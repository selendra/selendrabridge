//! A meter on the public fields that are thin proxies to the operator's RPC.
//!
//! `swapQuote`, `solanaBlockhash`, `solanaTokenBalance`, `solanaSignatureStatus`
//! and `solanaGateContext` each turn one anonymous GraphQL field into one or more
//! calls against the server-side (keyed) endpoint. Complexity pricing bounds how
//! many fit one request — at the default budget, still ~400 `swapQuote` aliases,
//! resolved concurrently — and the per-peer rate limit bounds requests, but
//! nothing bounded what the process as a whole sent upstream, and nothing let two
//! identical questions share one answer. Every caller was spending the operator's
//! provider quota, which every validator shares (audit 2026-09-16, LOW).
//!
//! [`Upstream`] adds both:
//! * a process-wide cap on concurrent upstream calls from these fields. A caller
//!   who cannot get a slot within [`UPSTREAM_WAIT`] gets `null` — every one of
//!   these fields is already nullable for "the RPC could not answer", so a
//!   flood degrades to unknowns instead of a burned provider quota;
//! * a short-lived answer cache for the pure reads, so repeated or aliased
//!   identical questions cost one call. TTLs are seconds: a quote or a balance a
//!   couple of seconds old is what a UI polling every few seconds sees anyway.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;

/// Concurrent upstream calls allowed across ALL requests.
pub const UPSTREAM_CONCURRENCY: usize = 16;
/// How long a field waits for a slot before answering `null`.
pub const UPSTREAM_WAIT: Duration = Duration::from_secs(2);
/// Entries kept before the cache is dropped and rebuilt — a cache, not a ledger.
const CACHE_MAX_ENTRIES: usize = 4096;
/// Keys longer than this are never cached (they are still metered): the key is
/// built from caller-supplied arguments, and memory must not be theirs to fill.
const CACHE_MAX_KEY: usize = 256;

#[derive(Clone)]
pub struct Upstream {
    permits: Arc<Semaphore>,
    wait: Duration,
    answers: Arc<Mutex<HashMap<String, (Instant, String)>>>,
    /// One lock per key being asked right now, so identical questions arriving
    /// together wait for the first answer instead of all going upstream — an
    /// aliased flood resolves concurrently, so a cache alone would let the
    /// first [`UPSTREAM_CONCURRENCY`] copies through.
    inflight: Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
}

impl Default for Upstream {
    fn default() -> Self {
        Self::new(UPSTREAM_CONCURRENCY, UPSTREAM_WAIT)
    }
}

impl Upstream {
    pub fn new(concurrency: usize, wait: Duration) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(concurrency)),
            wait,
            answers: Arc::new(Mutex::new(HashMap::new())),
            inflight: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Run `call` inside a slot. `None` when no slot frees up in time — `call`
    /// is then never polled, so nothing reaches the RPC.
    pub async fn metered<T>(&self, call: impl Future<Output = Option<T>>) -> Option<T> {
        let _slot = tokio::time::timeout(self.wait, self.permits.acquire()).await.ok()?.ok()?;
        call.await
    }

    /// [`metered`](Self::metered), answering from the cache when `key` was
    /// answered within its TTL. `ttl` picks the lifetime from the answer itself
    /// (`Duration::ZERO` = do not keep), so a settled status can be kept longer
    /// than a pending one. Failures (`None`) are never kept.
    pub async fn cached(
        &self,
        key: String,
        ttl: impl Fn(&str) -> Duration,
        call: impl Future<Output = Option<String>>,
    ) -> Option<String> {
        if let Some(hit) = self.lookup(&key) {
            return Some(hit);
        }
        if key.len() > CACHE_MAX_KEY {
            return self.metered(call).await;
        }
        let flight = {
            let mut inflight = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
            // A request dropped mid-call skips the cleanup below. Evicting an
            // idle entry only forgoes deduplication, never correctness.
            if inflight.len() >= CACHE_MAX_ENTRIES {
                inflight.retain(|_, f| Arc::strong_count(f) > 1);
            }
            inflight.entry(key.clone()).or_default().clone()
        };
        let answer = self.ask_once(&key, &flight, ttl, call).await;
        // Drop the lock entry once nobody else holds it (map + this handle).
        let mut inflight = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
        if inflight.get(&key).is_some_and(|f| Arc::strong_count(f) <= 2) {
            inflight.remove(&key);
        }
        answer
    }

    async fn ask_once(
        &self,
        key: &str,
        flight: &tokio::sync::Mutex<()>,
        ttl: impl Fn(&str) -> Duration,
        call: impl Future<Output = Option<String>>,
    ) -> Option<String> {
        let deadline = tokio::time::Instant::now() + self.wait;
        let _turn = tokio::time::timeout_at(deadline, flight.lock()).await.ok()?;
        // The caller ahead of us may have just answered this exact question.
        if let Some(hit) = self.lookup(key) {
            return Some(hit);
        }
        let _slot = tokio::time::timeout_at(deadline, self.permits.acquire()).await.ok()?.ok()?;
        let answer = call.await?;
        let keep = ttl(&answer);
        if !keep.is_zero() {
            let mut map = self.answers.lock().unwrap_or_else(|e| e.into_inner());
            if map.len() >= CACHE_MAX_ENTRIES {
                map.retain(|_, (expires, _)| *expires > Instant::now());
                if map.len() >= CACHE_MAX_ENTRIES {
                    map.clear();
                }
            }
            map.insert(key.to_owned(), (Instant::now() + keep, answer.clone()));
        }
        Some(answer)
    }

    fn lookup(&self, key: &str) -> Option<String> {
        let map = self.answers.lock().unwrap_or_else(|e| e.into_inner());
        map.get(key).filter(|(expires, _)| *expires > Instant::now()).map(|(_, v)| v.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn a_saturated_meter_answers_null_without_calling_upstream() {
        let up = Upstream::new(1, Duration::from_millis(50));
        let held = up.permits.clone().acquire_owned().await.unwrap();
        let calls = AtomicUsize::new(0);
        let got = up
            .metered(async {
                calls.fetch_add(1, Ordering::SeqCst);
                Some(1)
            })
            .await;
        assert_eq!(got, None);
        assert_eq!(calls.load(Ordering::SeqCst), 0, "nothing may reach the RPC without a slot");
        drop(held);
        assert_eq!(up.metered(async { Some(2) }).await, Some(2), "a free slot is used");
    }

    #[tokio::test]
    async fn failures_and_zero_ttl_answers_are_not_kept_and_long_keys_are_not_cached() {
        let up = Upstream::default();
        let calls = AtomicUsize::new(0);
        let ask = |v: Option<&'static str>| {
            calls.fetch_add(1, Ordering::SeqCst);
            async move { v.map(str::to_owned) }
        };
        let secs = |_: &str| Duration::from_secs(60);
        assert_eq!(up.cached("k".into(), secs, ask(None)).await, None);
        assert_eq!(up.cached("k".into(), secs, ask(Some("a"))).await.as_deref(), Some("a"));
        assert_eq!(up.cached("k".into(), secs, ask(Some("b"))).await.as_deref(), Some("a"), "kept");
        assert_eq!(up.cached("z".into(), |_| Duration::ZERO, ask(Some("c"))).await.as_deref(), Some("c"));
        assert_eq!(up.cached("z".into(), |_| Duration::ZERO, ask(Some("d"))).await.as_deref(), Some("d"));
        let long = "x".repeat(CACHE_MAX_KEY + 1);
        up.cached(long.clone(), secs, ask(Some("e"))).await;
        assert_eq!(up.cached(long, secs, ask(Some("f"))).await.as_deref(), Some("f"));
        assert!(up.answers.lock().unwrap().len() <= 2);
    }
}
