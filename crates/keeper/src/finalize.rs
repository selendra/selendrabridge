//! The router finalize loop (audit 2026-10-02, M7-2) and the dust floor (M7-12).
//!
//! A swap-and-bridge is claimed INTO the destination `SwapRouter`; only
//! `SwapRouter.finalize` then swaps the stable on to the user. The keeper used to
//! stop at `Gate.claim`, leaving that to the user's browser — but the router's
//! stable rescue is only safe if every delivery is finalized (or deferred, which
//! books it into `owedStable`) inside the rescue's 48 h public notice. This loop
//! is what makes that hold.
//!
//! `finalize` is permissionless and idempotent: it proves delivery from the
//! Gate's `executed`/`cancelled` flags, a per-id `finalized` guard stops a
//! second settlement, and a caller who is not the receiver, owner or guardian
//! can only complete the real swap or leave it deferred — never hand the user
//! the stable instead. That last property is why the keeper refuses to finalize
//! through a router whose owner or guardian IS the keeper account.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::time::{Duration, Instant};

use alloy::primitives::{Address, B256, U256};
use alloy::providers::Provider;
use anyhow::Context;
use bridge_core::abi::{Gate, SwapRouter};
use bridge_core::backend::StoreBackend;
use bridge_core::store::SubmissionRecord;
use tracing::{debug, info, warn};

use super::{bytes_of, confirm, Submitter};

/// How often the queue is re-seeded from the store's history. The keeper's work
/// queue drops a transfer once it is claimed, so a claim made by anyone else (or
/// by this keeper before a restart) is only found this way.
pub const SEED_INTERVAL: Duration = Duration::from_secs(15 * 60);
/// First retry after a finalize that deferred or failed; doubles per attempt.
pub const BACKOFF_BASE: Duration = Duration::from_secs(5 * 60);
/// Backoff ceiling. A swap blocked for days (a delisted token) is still retried
/// a few times a day, and completes the moment it can.
pub const BACKOFF_MAX: Duration = Duration::from_secs(6 * 3600);
/// At most this many finalize attempts per tick, so a burst cannot starve claims.
pub const PER_TICK: usize = 4;
/// At most this many records loaded per seed.
pub const SEED_LOADS: usize = 200;

/// Backoff before attempt `attempts + 1` (attempts >= 1).
pub fn backoff_for(attempts: u32) -> Duration {
    let shift = attempts.saturating_sub(1).min(16);
    BACKOFF_BASE.saturating_mul(1u32 << shift).min(BACKOFF_MAX)
}

/// The configured router `rec` was delivered to, if any.
pub fn router_of(rec_receiver: &str, routers: &HashSet<Address>) -> Option<Address> {
    let addr = Address::from_str(rec_receiver).ok()?;
    routers.contains(&addr).then_some(addr)
}

/// Is `rec` below this target's configured claim floor? `Some((amount, floor))`
/// when it is. An unparseable amount is never "below" — the claim path reports
/// it on its own terms.
pub fn below_min_claim(cfg: &crate::config::ChainCfg, rec: &SubmissionRecord) -> Option<(u128, u128)> {
    let floor = cfg.min_claim_wire(&rec.debridge_id, rec.bridge_decimals?)?;
    let amount: u128 = U256::from_str(&rec.amount).ok()?.try_into().ok()?;
    (amount < floor).then_some((amount, floor))
}

struct Entry {
    rec: SubmissionRecord,
    router: Address,
    next_at: Instant,
    attempts: u32,
}

/// What one finalize attempt concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// `finalized(id)` is set: settled, by us or anyone.
    Done,
    /// Nothing this keeper should ever do for it; drop it with the reason.
    Drop(&'static str),
    /// The Gate has not executed it yet (the claim is still in flight).
    NotYetDelivered,
    /// Our finalize ran but the swap is blocked: the router deferred it (and
    /// booked the stable into `owedStable`). Retried with backoff.
    Deferred,
}

#[derive(Default)]
pub struct FinalizeQueue {
    entries: HashMap<String, Entry>,
    seeded_at: Option<Instant>,
}

impl FinalizeQueue {
    /// Queue `rec` for finalize through `router`. False if already queued.
    pub fn enqueue(&mut self, rec: &SubmissionRecord, router: Address, now: Instant) -> bool {
        if self.entries.contains_key(&rec.submission_id) {
            return false;
        }
        self.entries.insert(rec.submission_id.clone(), Entry { rec: rec.clone(), router, next_at: now, attempts: 0 });
        true
    }

    /// Up to `max` ids whose next attempt is due, soonest first.
    pub fn due(&self, now: Instant, max: usize) -> Vec<String> {
        let mut due: Vec<(&Instant, &String)> =
            self.entries.iter().filter(|(_, e)| e.next_at <= now).map(|(id, e)| (&e.next_at, id)).collect();
        due.sort();
        due.into_iter().take(max).map(|(_, id)| id.clone()).collect()
    }

    /// Record a non-final attempt and push the next one out.
    pub fn back_off(&mut self, id: &str, now: Instant) -> Option<Duration> {
        let e = self.entries.get_mut(id)?;
        e.attempts += 1;
        let wait = backoff_for(e.attempts);
        e.next_at = now + wait;
        Some(wait)
    }

    pub fn remove(&mut self, id: &str) {
        self.entries.remove(id);
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn seed_due(&self, now: Instant) -> bool {
        self.seeded_at.is_none_or(|t| now.duration_since(t) >= SEED_INTERVAL)
    }

    /// Re-seed from the store's newest history page: every transfer claimed on
    /// `chain_id` into one of `routers` whose finalize the indexer has not seen.
    /// File-backed stores keep no history; their work queue already hands back
    /// claimed records every tick, and the claim path enqueues those.
    pub async fn seed(
        &mut self,
        store: &StoreBackend,
        chain_id: u64,
        routers: &HashSet<Address>,
        target: &crate::config::ChainCfg,
        now: Instant,
    ) {
        self.seeded_at = Some(now);
        if routers.is_empty() || store.dir().is_some() {
            return;
        }
        let rows = match store.history().await {
            Ok(r) => r,
            Err(e) => {
                warn!(chain_id, error = %e, "finalize seed: history read failed; retrying next interval");
                return;
            }
        };
        let mut loads = 0;
        for row in rows {
            if loads >= SEED_LOADS {
                break;
            }
            if row.chain_id_to != chain_id
                || row.status != "claimed"
                || self.entries.contains_key(&row.submission_id)
                || row.swap_intent.as_ref().is_some_and(|s| s.finalize_tx.is_some())
            {
                continue;
            }
            let Some(router) = router_of(&row.receiver, routers) else { continue };
            loads += 1;
            match store.load(&row.submission_id).await {
                Ok(Some(rec)) if below_min_claim(target, &rec).is_none() => {
                    if self.enqueue(&rec, router, now) {
                        debug!(chain_id, submission_id = %rec.submission_id, %router, "finalize seed: queued");
                    }
                }
                Ok(_) => {}
                Err(e) => debug!(chain_id, submission_id = %row.submission_id, error = %e, "finalize seed: load failed"),
            }
        }
    }

    /// Run the due finalize attempts. Never fails the tick.
    pub async fn run<P: Provider + Clone>(
        &mut self,
        provider: P,
        gate: &Gate::GateInstance<P>,
        submitter: &Submitter,
        chain_id: u64,
    ) {
        let now = Instant::now();
        for id in self.due(now, PER_TICK) {
            let Some(e) = self.entries.get(&id) else { continue };
            let (router_addr, rec) = (e.router, e.rec.clone());
            let router = SwapRouter::new(router_addr, provider.clone());
            match finalize_one(gate, &router, &rec, submitter).await {
                Ok(Outcome::Done) => {
                    debug!(chain_id, submission_id = %id, "router delivery is finalized");
                    self.remove(&id);
                }
                Ok(Outcome::Drop(reason)) => {
                    warn!(chain_id, submission_id = %id, router = %router_addr, reason, "not finalizing this delivery");
                    self.remove(&id);
                }
                Ok(Outcome::NotYetDelivered) => {
                    self.back_off(&id, now);
                }
                Ok(Outcome::Deferred) => {
                    let wait = self.back_off(&id, now);
                    info!(
                        chain_id, submission_id = %id, retry_in_secs = wait.map(|w| w.as_secs()),
                        "finalize DEFERRED by the router (destination swap blocked right now); \
                         the stable is booked as owed and the swap will be retried"
                    );
                }
                Err(err) => {
                    let wait = self.back_off(&id, now);
                    warn!(
                        chain_id, submission_id = %id, error = %err, retry_in_secs = wait.map(|w| w.as_secs()),
                        "finalize failed; will retry"
                    );
                }
            }
        }
    }
}

/// One finalize attempt for a delivery into `router`. See [`Outcome`].
pub async fn finalize_one<P: Provider + Clone>(
    gate: &Gate::GateInstance<P>,
    router: &SwapRouter::SwapRouterInstance<P>,
    rec: &SubmissionRecord,
    submitter: &Submitter,
) -> anyhow::Result<Outcome> {
    let id = B256::from_str(&rec.submission_id).context("bad submission_id")?;
    if router.finalized(id).call().await? {
        return Ok(Outcome::Done);
    }
    // A cancelled transfer never delivered anything; `finalize` reverts
    // NotDelivered for it for ever.
    if gate.cancelled(id).call().await? {
        return Ok(Outcome::Drop("cancelled on the gate: nothing was delivered to the router"));
    }
    if !gate.executed(id).call().await? {
        return Ok(Outcome::NotYetDelivered);
    }
    // The router lets its owner/guardian take the stable fallback on the
    // user's behalf after the grace window. A keeper must never be that
    // caller: its retries would convert a blocked swap into a stable payout.
    let me = submitter.from;
    if router.owner().call().await? == me || router.guardian().call().await? == me {
        return Ok(Outcome::Drop(
            "the keeper account is this router's owner or guardian, so its finalize could hand the \
             user the stable fallback instead of their token; use a different keeper key",
        ));
    }
    let call = router.finalize(
        B256::from_str(&rec.debridge_id).context("bad debridge_id")?,
        U256::from_str(&rec.amount).context("bad amount")?,
        rec.bridge_decimals.context("record has no bridge_decimals")?,
        U256::from(rec.chain_id_from),
        U256::from(rec.nonce),
        bytes_of(&rec.receiver)?,
        bytes_of(&rec.auto_params)?,
        bytes_of(&rec.native_sender)?,
    );
    confirm(call, "finalize", &rec.submission_id, "FINALIZE sent (router)", submitter).await?;
    if router.finalized(id).call().await? {
        Ok(Outcome::Done)
    } else {
        Ok(Outcome::Deferred)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::Bytes;
    use alloy::providers::ProviderBuilder;
    use alloy::sol_types::SolValue;
    use alloy::transports::mock::Asserter;

    fn rec(id: u8, receiver: Address, amount: &str) -> SubmissionRecord {
        let mut r: SubmissionRecord = serde_json::from_value(serde_json::json!({
            "submission_id": format!("{:#x}", B256::repeat_byte(id)),
            "debridge_id": format!("{:#x}", B256::repeat_byte(0xAA)),
            "amount": amount,
            "chain_id_from": 1,
            "chain_id_to": 2,
            "nonce": id as u64,
            "receiver": format!("{receiver:#x}"),
            "auto_params": "0x",
            "native_sender": "0x",
            "signatures": [],
        }))
        .expect("record shape");
        r.bridge_decimals = Some(6);
        r
    }

    #[test]
    fn only_configured_routers_are_finalized() {
        let router = Address::repeat_byte(0x11);
        let routers: HashSet<Address> = [router].into();
        assert_eq!(router_of(&format!("{router:#x}"), &routers), Some(router));
        assert_eq!(router_of(&format!("{:#x}", Address::repeat_byte(0x22)), &routers), None, "a plain receiver");
        assert_eq!(router_of("0x1234", &routers), None, "not an address");
        assert_eq!(router_of(&format!("{:#x}", B256::repeat_byte(0x11)), &routers), None, "32-byte receiver");
    }

    #[test]
    fn the_queue_dedupes_and_backs_off_to_a_ceiling() {
        let t0 = Instant::now();
        let mut q = FinalizeQueue::default();
        let r = rec(1, Address::repeat_byte(0x11), "100");
        assert!(q.enqueue(&r, Address::repeat_byte(0x11), t0));
        assert!(!q.enqueue(&r, Address::repeat_byte(0x11), t0), "idempotent");
        assert_eq!(q.due(t0, PER_TICK), vec![r.submission_id.clone()]);

        assert_eq!(q.back_off(&r.submission_id, t0), Some(BACKOFF_BASE));
        assert!(q.due(t0, PER_TICK).is_empty(), "not due inside its backoff");
        assert_eq!(q.due(t0 + BACKOFF_BASE, PER_TICK).len(), 1);
        assert_eq!(q.back_off(&r.submission_id, t0), Some(BACKOFF_BASE * 2), "doubles");
        for _ in 0..40 {
            q.back_off(&r.submission_id, t0);
        }
        assert_eq!(q.back_off(&r.submission_id, t0), Some(BACKOFF_MAX), "capped");
        q.remove(&r.submission_id);
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn a_burst_is_spread_over_ticks() {
        let t0 = Instant::now();
        let mut q = FinalizeQueue::default();
        for i in 0..10 {
            q.enqueue(&rec(i, Address::repeat_byte(0x11), "1"), Address::repeat_byte(0x11), t0);
        }
        assert_eq!(q.due(t0, PER_TICK).len(), PER_TICK);
    }

    #[test]
    fn the_seed_runs_once_per_interval() {
        let t0 = Instant::now();
        let mut q = FinalizeQueue::default();
        assert!(q.seed_due(t0), "first tick seeds");
        q.seeded_at = Some(t0);
        assert!(!q.seed_due(t0 + Duration::from_secs(1)));
        assert!(q.seed_due(t0 + SEED_INTERVAL));
    }

    fn word<T: SolValue>(v: T) -> Bytes {
        Bytes::from(v.abi_encode())
    }

    fn submitter() -> Submitter {
        Submitter { lock: Default::default(), from: Address::repeat_byte(0xEE), role: "claim" }
    }

    /// Idempotent from the outside: an already-finalized delivery (by the
    /// user's browser, say) costs one read and sends nothing.
    #[tokio::test]
    async fn an_already_finalized_delivery_sends_nothing() {
        let a = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(a.clone());
        let gate = Gate::new(Address::repeat_byte(0x9), provider.clone());
        let router = SwapRouter::new(Address::repeat_byte(0x11), provider.clone());
        a.push_success(&word(true)); // finalized(id)
        let out = finalize_one(&gate, &router, &rec(1, Address::repeat_byte(0x11), "5"), &submitter()).await.unwrap();
        assert_eq!(out, Outcome::Done);
    }

    #[tokio::test]
    async fn a_cancelled_transfer_is_dropped_and_an_unexecuted_one_waits() {
        let a = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(a.clone());
        let gate = Gate::new(Address::repeat_byte(0x9), provider.clone());
        let router = SwapRouter::new(Address::repeat_byte(0x11), provider.clone());
        let r = rec(1, Address::repeat_byte(0x11), "5");

        a.push_success(&word(false)); // finalized
        a.push_success(&word(true)); // cancelled
        assert!(matches!(finalize_one(&gate, &router, &r, &submitter()).await.unwrap(), Outcome::Drop(_)));

        a.push_success(&word(false)); // finalized
        a.push_success(&word(false)); // cancelled
        a.push_success(&word(false)); // executed
        assert_eq!(finalize_one(&gate, &router, &r, &submitter()).await.unwrap(), Outcome::NotYetDelivered);
    }

    /// A keeper that is the router's owner (or guardian) would be entitled to
    /// the stable fallback, so it must not be the one retrying finalize.
    #[tokio::test]
    async fn the_keeper_never_finalizes_as_the_routers_owner_or_guardian() {
        let me = submitter().from;
        for (owner, guardian) in [(me, Address::ZERO), (Address::repeat_byte(1), me)] {
            let a = Asserter::new();
            let provider = ProviderBuilder::new().connect_mocked_client(a.clone());
            let gate = Gate::new(Address::repeat_byte(0x9), provider.clone());
            let router = SwapRouter::new(Address::repeat_byte(0x11), provider.clone());
            a.push_success(&word(false)); // finalized
            a.push_success(&word(false)); // cancelled
            a.push_success(&word(true)); // executed
            a.push_success(&word(owner));
            if owner != me {
                a.push_success(&word(guardian));
            }
            let out = finalize_one(&gate, &router, &rec(1, Address::repeat_byte(0x11), "5"), &submitter()).await.unwrap();
            assert!(matches!(out, Outcome::Drop(r) if r.contains("owner or guardian")), "{out:?}");
        }
    }

    #[test]
    fn dust_below_the_floor_is_recognised_and_default_is_off() {
        let did = format!("{:#x}", B256::repeat_byte(0xAA));
        let mut cfg: crate::config::ChainCfg = toml::from_str(
            "chain_id = 2\nrpc = \"http://x\"\ngate = \"0x0000000000000000000000000000000000000001\"\n",
        )
        .unwrap();
        let dust = rec(1, Address::repeat_byte(0x22), "999999");
        assert_eq!(below_min_claim(&cfg, &dust), None, "no floor configured: off");

        cfg.min_claim.insert(did, "1".into()); // 1 whole token = 1_000_000 at 6 dp
        assert_eq!(below_min_claim(&cfg, &dust), Some((999_999, 1_000_000)));
        assert_eq!(below_min_claim(&cfg, &rec(2, Address::repeat_byte(0x22), "1000000")), None, "at the floor claims");
        let mut other = rec(3, Address::repeat_byte(0x22), "1");
        other.debridge_id = format!("{:#x}", B256::repeat_byte(0xBB));
        assert_eq!(below_min_claim(&cfg, &other), None, "floors are per asset");
    }
}
