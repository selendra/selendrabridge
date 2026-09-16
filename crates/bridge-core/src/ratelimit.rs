//! Per-credential rate limiting for the bridge's HTTP write surfaces.
//!
//! ## Why (finding L-1)
//!
//! Neither the signature store nor the GraphQL API bounded request rate or body
//! size. The store's binding rules make a *forged* record impossible — an id must
//! be the keccak of its own params, and a signature must recover to its claimed
//! signer — but nothing requires the record to describe a transfer that ever
//! happened on a chain. A holder of a `Sign`-scoped token could therefore mint
//! arbitrary well-formed `(id, params, signature)` triples at line rate and grow
//! the `submissions` table without limit.
//!
//! That is not a fund-loss bug: the Gate still releases only against a real
//! validator quorum. It is an availability one, and it was the amplifier for the
//! keeper's work-queue problem — every junk row was another row the keeper carried
//! forever.
//!
//! ## The shape
//!
//! A token bucket per credential, keyed on the presented bearer token rather than
//! on a client address. That is the key that matters here: every writer is a
//! service holding a scoped token, they may sit behind the same NAT or ingress,
//! and the thing worth bounding is what one compromised or buggy credential can do
//! — not what one IP can. Requests with no credential share a single bucket, so an
//! unauthenticated deployment is bounded too.
//!
//! Deliberately in-process and approximate. It is a blast-radius bound, not a
//! billing meter: a horizontally-scaled store gets `replicas × rate`, which is
//! still a bound, and the alternative (shared state in Postgres) would put a write
//! on the path of every request in order to protect the database from writes.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use std::net::SocketAddr;

use axum::extract::connect_info::ConnectInfo;
use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use std::sync::Arc;

/// How many entries the bucket map may hold before it is swept.
///
/// The key is caller-controlled (an unknown bearer token is still a key), so the
/// map is an unbounded allocation unless something bounds it. Sweeping expired
/// buckets at this threshold keeps it proportional to the number of *live*
/// credentials rather than to the number of distinct strings ever presented.
const SWEEP_AT: usize = 4_096;

#[derive(Clone, Copy)]
struct Bucket {
    /// Tokens available, in whole requests, as of `last`.
    tokens: f64,
    last: Instant,
}

/// A token-bucket limiter shared by every request to the routes it guards.
///
/// `burst` is the bucket depth (how many requests may arrive back to back) and
/// `per_second` is the sustained refill. Cheap to clone — one `Arc`.
#[derive(Clone)]
pub struct RateLimit {
    inner: Arc<Inner>,
}

struct Inner {
    burst: f64,
    per_second: f64,
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl RateLimit {
    /// A limiter allowing `burst` requests back to back, refilling at
    /// `per_second`. Both must be positive; a zero rate would deny everything,
    /// which is a configuration mistake rather than a policy anyone wants.
    pub fn new(burst: u32, per_second: f64) -> RateLimit {
        RateLimit {
            inner: Arc::new(Inner {
                burst: f64::from(burst.max(1)),
                per_second: if per_second > 0.0 { per_second } else { 1.0 },
                buckets: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Consume one token for `key`. `false` means the caller is over its rate.
    ///
    /// Takes `now` so the refill arithmetic is testable without sleeping.
    pub fn check_at(&self, key: &str, now: Instant) -> bool {
        let inner = &self.inner;
        // A poisoned lock means another request panicked mid-update. Recovering
        // the guard is right here: the alternative is that one panic turns the
        // limiter into a permanent 500 on every write route.
        let mut buckets = inner.buckets.lock().unwrap_or_else(|e| e.into_inner());

        if buckets.len() >= SWEEP_AT {
            // Drop anything already refilled to full — it carries no state a new
            // entry would not reproduce.
            let (burst, rate) = (inner.burst, inner.per_second);
            buckets.retain(|_, b| {
                let refilled = b.tokens + now.saturating_duration_since(b.last).as_secs_f64() * rate;
                refilled < burst
            });
            // That alone does not bound the map: a bucket DRAINED by a request is
            // never full, so a caller who can mint fresh keys (an unauthenticated
            // service keys on something it does not control) would grow it without
            // limit and make every later request pay for the sweep. Evict the
            // least-recently-used half, which is the half closest to refilling
            // anyway (audit 2026-09-16, H-7).
            if buckets.len() >= SWEEP_AT {
                let mut times: Vec<Instant> = buckets.values().map(|b| b.last).collect();
                let cut = times.len() / 2;
                times.select_nth_unstable(cut);
                let cutoff = times[cut];
                buckets.retain(|_, b| b.last > cutoff);
            }
        }

        let bucket = buckets
            .entry(key.to_owned())
            .or_insert(Bucket { tokens: inner.burst, last: now });

        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * inner.per_second).min(inner.burst);
        bucket.last = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// [`check_at`](Self::check_at) against the current clock.
    pub fn check(&self, key: &str) -> bool {
        self.check_at(key, Instant::now())
    }

    /// Number of live buckets (for tests and startup logging).
    pub fn tracked(&self) -> usize {
        self.inner.buckets.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

/// The credential a request presents, or `""` when it presents none.
///
/// Keying on the token means one leaked or misbehaving credential is bounded
/// without penalising the others that share its network path.
fn credential(req: &Request) -> String {
    req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("")
        .to_owned()
}

/// The peer's IP address, or `""` when the server was not built with
/// [`axum::extract::connect_info::ConnectInfo`].
///
/// Keyed on the IP, not the socket, so a client cannot escape its bucket by
/// opening a new connection.
fn peer(req: &Request) -> String {
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip().to_string())
        .unwrap_or_default()
}

/// Middleware enforcing a [`RateLimit`] keyed on the PEER ADDRESS.
///
/// Use this on a surface with no authentication (audit 2026-09-16, H-7). Keying
/// on the bearer token there is worse than no limit at all: the key is then a
/// string the caller invents, so every request with a fresh random token lands on
/// a brand-new full bucket and the configured rate is never reached. [`enforce`]
/// is correct only where a scope check has already established that the token is
/// one of a known few.
///
/// Requires the server to be started with
/// `into_make_service_with_connect_info::<SocketAddr>()`; without it every peer
/// shares one bucket, which is a bound rather than a bypass.
pub async fn enforce_by_peer(
    State(limit): State<RateLimit>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if limit.check(&peer(&req)) {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::TOO_MANY_REQUESTS)
    }
}

/// Middleware enforcing a [`RateLimit`]. Wire it per route group:
///
/// ```ignore
/// .route_layer(middleware::from_fn_with_state(limit.clone(), enforce))
/// ```
pub async fn enforce(
    State(limit): State<RateLimit>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if limit.check(&credential(&req)) {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::TOO_MANY_REQUESTS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_burst_is_allowed_then_refused() {
        let rl = RateLimit::new(3, 1.0);
        let t = Instant::now();
        for i in 0..3 {
            assert!(rl.check_at("tok", t), "burst request {i} must pass");
        }
        assert!(!rl.check_at("tok", t), "the fourth must be refused");
    }

    #[test]
    fn tokens_refill_over_time() {
        let rl = RateLimit::new(2, 10.0); // 10/s
        let t = Instant::now();
        assert!(rl.check_at("tok", t));
        assert!(rl.check_at("tok", t));
        assert!(!rl.check_at("tok", t));
        // 100ms buys exactly one token back.
        assert!(rl.check_at("tok", t + Duration::from_millis(100)));
    }

    #[test]
    fn refill_is_capped_at_the_burst() {
        let rl = RateLimit::new(2, 100.0);
        let t = Instant::now();
        // A long idle period must not bank unlimited credit.
        for _ in 0..2 {
            assert!(rl.check_at("tok", t + Duration::from_secs(3600)));
        }
        assert!(!rl.check_at("tok", t + Duration::from_secs(3600)));
    }

    /// THE property: one credential exhausting its budget must not affect
    /// another. That is the whole reason the key is the token and not an address.
    #[test]
    fn credentials_are_limited_independently() {
        let rl = RateLimit::new(1, 0.001);
        let t = Instant::now();
        assert!(rl.check_at("validator", t));
        assert!(!rl.check_at("validator", t), "premise: this one is exhausted");
        assert!(rl.check_at("keeper", t), "an unrelated credential must be unaffected");
    }

    /// Unauthenticated callers share one bucket, so an open deployment is bounded
    /// rather than unbounded.
    #[test]
    fn anonymous_callers_share_a_bucket() {
        let rl = RateLimit::new(1, 0.001);
        let t = Instant::now();
        assert!(rl.check_at("", t));
        assert!(!rl.check_at("", t));
    }

    /// The key is caller-controlled, so the map has to be bounded by live
    /// credentials rather than by distinct strings ever seen.
    #[test]
    fn the_bucket_map_does_not_grow_without_bound() {
        let rl = RateLimit::new(1, 1000.0);
        let t = Instant::now();
        for i in 0..(SWEEP_AT + 64) {
            rl.check_at(&format!("tok-{i}"), t + Duration::from_secs(i as u64));
        }
        assert!(rl.tracked() < SWEEP_AT + 64, "expired buckets must be swept");
    }

    #[test]
    fn a_degenerate_configuration_still_lets_traffic_through() {
        let rl = RateLimit::new(0, 0.0); // clamped, not fatal
        assert!(rl.check_at("tok", Instant::now()));
    }
}
