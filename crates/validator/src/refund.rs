//! Refund attestation loop — the off-chain half of the two-phase refund.
//!
//! A transfer can strand: the destination gate may have no liquidity for the
//! asset, the corridor may be de-listed after the funds were locked, or the
//! target chain may be down long enough that nobody ever claims. The locked
//! funds have to be recoverable, but a refund that merely waits out a timeout is
//! a double-spend — the transfer's claim signatures still exist, so a keeper can
//! deliver on the destination in the same window the source pays the refund.
//!
//! So the refund is ordered, and this loop is what enforces the ordering:
//!
//!   1. The transfer is unclaimed past the timeout, and the DESTINATION gate
//!      still reports `executed == false`. Attest a **cancel**.
//!   2. A keeper submits `cancel()` there, permanently burning the transfer —
//!      `claim()` can never succeed for it again.
//!   3. Only once the destination reports `cancelled == true` do we attest a
//!      **refund**.
//!
//! Step 3 is the load-bearing one. The source gate cannot read the destination,
//! so nothing on-chain stops a refund quorum from paying out early — the
//! guarantee is that this quorum never forms until the burn is an observed
//! on-chain fact. Which is the same trust assumption the bridge already makes
//! for `Sent`: validators attest to what they independently read on a chain.
//!
//! Every decision below is made from on-chain reads at a confirmed block. The
//! store's `refund_status`/timeout only *nominates* candidates; it never
//! authorises anything, so a wrong or manipulated timestamp there can at most
//! cause a wasted look.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::{Duration, Instant};

use alloy::eips::BlockNumberOrTag;
use alloy::primitives::{Address, B256};
use alloy::providers::{DynProvider, Provider};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use anyhow::Context;
use bridge_core::abi::Gate;
use bridge_core::backend::{RefundCursor, StoreBackend, MAX_REFUND_PAGES, REFUND_PAGE};
use bridge_core::signer::encode_signature;
use bridge_core::store::{SigKind, SignerSig, SubmissionRecord};
use tracing::{info, warn};

use crate::config::RefundConfig;
use crate::provider;

/// One chain this validator can independently read gate state from.
///
/// ## Every read is corroborated (audit round 6)
///
/// This used to hold ONE provider — the first healthy endpoint, the same one on
/// every validator — and the module docs called the refund path "already
/// second-sourced". It was not. The destination's `executed`/`cancelled` is the
/// single fact standing between a refund and a double-spend, and one endpoint
/// that answered `executed = false, cancelled = true` for a stuck transfer got
/// every validator to attest its refund while the claim signatures still existed.
///
/// Now every read goes to every endpoint, at ONE block number, and an answer is
/// used only when at least `min_agree` endpoints returned it AND they are a
/// strict majority of those that answered ([`provider::majority`]). Anything short of that
/// is an error: the candidate is skipped this tick and retried, loudly. A skipped
/// refund is late; a wrongly attested one is money gone.
struct GateReader {
    chain_id: u64,
    gate: Address,
    /// (redacted url, provider) for every endpoint that passed the chainId probe.
    endpoints: Vec<(String, DynProvider)>,
    block_confirmation: u64,
    /// How many endpoints must return the same answer. 2 whenever the chain is
    /// configured with a second endpoint or `[corroborate] require = true`;
    /// 1 only for a deliberately single-endpoint chain.
    min_agree: usize,
}

impl GateReader {
    async fn connect(
        chain_id: u64,
        gate: &str,
        endpoints: &[String],
        block_confirmation: u64,
        require: bool,
    ) -> anyhow::Result<Self> {
        let min_agree = provider::min_agree(endpoints.len(), require);
        let healthy = provider::connect_all_checked(endpoints, chain_id).await?;
        // Same rule as the transfer scanner: a chain configured with a second
        // endpoint does not start on one, because endpoints are probed only here
        // and it would then run single-source for the life of the process.
        anyhow::ensure!(
            healthy.len() >= min_agree,
            "{} healthy RPC endpoint(s) of {} configured; the refund path needs {min_agree} \
             to corroborate every read (audit H-4, round 6)",
            healthy.len(),
            endpoints.len()
        );
        if min_agree < 2 {
            warn!(
                chain_id,
                "refund loop: ONE RPC endpoint for this chain — every executed/cancelled read \
                 rests on it alone, and a lying endpoint can get a delivered transfer refunded. \
                 Add a second `rpcs` entry, or set [corroborate] require = true to refuse."
            );
        }
        Ok(GateReader {
            chain_id,
            gate: gate.parse().context("bad gate address")?,
            endpoints: healthy,
            block_confirmation,
            min_agree,
        })
    }

    /// Ask every endpoint the same question and return the [`provider::majority`] answer.
    async fn agreed<T, F, Fut>(&self, what: &str, read: F) -> anyhow::Result<T>
    where
        T: PartialEq + Clone + std::fmt::Debug,
        F: Fn(DynProvider) -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<T>>,
    {
        provider::read_agreed(&self.endpoints, self.min_agree, what, read, |answers| {
            warn!(
                chain_id = self.chain_id,
                what,
                answers = ?answers,
                "RPC ENDPOINTS DISAGREE about gate state — attesting NOTHING that depends on \
                 it (audit H-4). One endpoint is wrong about the chain: investigate."
            );
        })
        .await
    }

    /// The newest block we are willing to trust, as ONE number every endpoint is
    /// then asked about. Reading `executed` at the chain tip would let a reorg
    /// make a claimed transfer look unclaimed — and this loop would then attest a
    /// cancel for a transfer that was actually paid.
    ///
    /// The highest head a STRICT MAJORITY of the answering endpoints has
    /// reached ([`majority_floor`]), so no single endpoint can push the read past
    /// what the others have. With two endpoints that is the lower of the two
    /// heads, exactly as before. With three or more (audit round 7, L7-12) it is
    /// no longer the lowest: one endpoint reporting a stale or bogus LOW head
    /// used to drag every read back with it, and on the cancel leg that made the
    /// aged-block check fail for every candidate — one endpoint blocking all
    /// cancels. Now it is outvoted, while a head no majority has reached still
    /// cannot be used.
    ///
    /// A head that is too low only makes the read older, and older is the safe
    /// direction on both legs: `cancelled` only ever goes false→true, so an older
    /// read can only HIDE a burn (delaying a refund); and a cancel attested off a
    /// stale `executed = false` cannot be used, because `claim` and `cancel`
    /// share the gate's one `executed` flag and `cancel` reverts once it is set.
    async fn confirmed_block(&self) -> anyhow::Result<u64> {
        let mut heads: Vec<u64> = Vec::new();
        for (_, p) in &self.endpoints {
            if let Ok(h) = p.get_block_number().await {
                heads.push(h);
            }
        }
        anyhow::ensure!(
            heads.len() >= self.min_agree,
            "only {} of {} endpoints reported a head; need {}",
            heads.len(),
            self.endpoints.len(),
            self.min_agree
        );
        let latest = majority_floor(&heads).expect("min_agree >= 1");
        Ok(latest.saturating_sub(self.block_confirmation))
    }

    /// Destination-side view of a submission at a confirmed block.
    async fn destination_state(&self, id: B256) -> anyhow::Result<DestinationState> {
        let block = self.confirmed_block().await?;
        let gate_addr = self.gate;
        let (executed, cancelled) = self
            .agreed("destination executed/cancelled", |p| async move {
                let at = BlockNumberOrTag::Number(block).into();
                let gate = Gate::new(gate_addr, &p);
                Ok((
                    gate.executed(id).block(at).call().await?,
                    gate.cancelled(id).block(at).call().await?,
                ))
            })
            .await?;
        Ok(DestinationState { executed, cancelled })
    }

    /// Source-side view: who locked the funds (zero once refunded or if this gate
    /// never emitted the id at all), and whether it has already been paid back.
    async fn source_state(&self, id: B256) -> anyhow::Result<SourceState> {
        let block = self.confirmed_block().await?;
        let gate_addr = self.gate;
        let (sent_by, refunded) = self
            .agreed("source sentBy/refunded", |p| async move {
                let at = BlockNumberOrTag::Number(block).into();
                let gate = Gate::new(gate_addr, &p);
                Ok((
                    gate.sentBy(id).block(at).call().await?,
                    gate.refunded(id).block(at).call().await?,
                ))
            })
            .await?;
        Ok(SourceState { sent_by, refunded })
    }

    /// A block that is provably at least `timeout_secs` old, measured against the
    /// chain's OWN head timestamp rather than our wall clock (a validator with a
    /// skewed clock must not be able to attest early, and block timestamps are
    /// what the chain actually agrees on).
    ///
    /// Each endpoint locates one from the SAME confirmed head, and the newest
    /// block that a STRICT MAJORITY of them vouch is old enough is used
    /// ([`agreed_aged_block`]): every block at or before an endpoint's answer is
    /// old enough by that endpoint's account, and `None` vouches for nothing.
    /// Too NEW is the dangerous direction (a transfer would count as aged
    /// early), and no minority can push it there; too OLD only makes
    /// `was_sent_by_block` harder to satisfy.
    ///
    /// With two endpoints that is the OLDER answer, and `None` from either wins
    /// — the strict rule this always had. With three or more (audit round 7,
    /// L7-12) one endpoint answering `None`, or an absurdly old block, no
    /// longer blocks every cancel attestation: it is outvoted.
    ///
    /// `Ok(None)` means the chain has no block that old yet (a fresh dev chain),
    /// in which case nothing may be attested.
    async fn aged_block(&self, timeout_secs: i64) -> anyhow::Result<Option<u64>> {
        let head_num = self.confirmed_block().await?;
        let mut found: Vec<Option<u64>> = Vec::new();
        let mut failed: Vec<String> = Vec::new();
        for (url, p) in &self.endpoints {
            match aged_block_on(p, head_num, timeout_secs).await {
                Ok(v) => found.push(v),
                Err(e) => failed.push(format!("{url}: {e}")),
            }
        }
        anyhow::ensure!(
            found.len() >= self.min_agree,
            "locating an aged block: only {} of {} endpoints answered; need {} ({})",
            found.len(),
            self.endpoints.len(),
            self.min_agree,
            failed.join("; ")
        );
        Ok(agreed_aged_block(&found))
    }

    /// Was `id` already locked on this gate as of `block`?
    ///
    /// `sentBy` is written by `send` in the same transaction that locks the funds,
    /// so a non-zero value at a historical height is the chain's own statement
    /// that the deposit existed by then. Reading it at an aged block is therefore
    /// an *authenticated* age check — no timestamp from the store, no schema
    /// change, one `eth_call` per endpoint.
    async fn was_sent_by_block(&self, id: B256, block: u64) -> anyhow::Result<bool> {
        let gate_addr = self.gate;
        self.agreed("historical sentBy", |p| async move {
            let at = BlockNumberOrTag::Number(block).into();
            let gate = Gate::new(gate_addr, &p);
            Ok(gate.sentBy(id).block(at).call().await? != Address::ZERO)
        })
        .await
    }
}

/// A configured chain whose [`GateReader`] may not be connected yet (audit
/// round 7, L7-13). See `run` for why connecting is lazy.
struct LazyReader {
    chain_id: u64,
    gate: String,
    endpoints: Vec<String>,
    reader: Option<GateReader>,
}

impl LazyReader {
    fn new(chain_id: u64, gate: String, endpoints: Vec<String>) -> Self {
        LazyReader { chain_id, gate, endpoints, reader: None }
    }

    /// Try once to connect, if not connected yet. Never blocks beyond the one
    /// probe; a chain that is still short of healthy endpoints stays `None` and
    /// its candidates are skipped this tick.
    async fn ensure(&mut self, block_confirmation: u64, require: bool) {
        if self.reader.is_some() {
            return;
        }
        match GateReader::connect(self.chain_id, &self.gate, &self.endpoints, block_confirmation, require).await {
            Ok(r) => {
                info!(chain_id = self.chain_id, endpoints = r.endpoints.len(), "refund loop: chain connected");
                self.reader = Some(r);
            }
            Err(e) => warn!(
                chain_id = self.chain_id,
                error = %e,
                "refund loop: chain not readable yet — candidates touching it are skipped until it \
                 is (other chains proceed); retrying next tick"
            ),
        }
    }
}

/// What the refund loop can do with a chain id.
enum Reader<'a> {
    Ready(&'a GateReader),
    /// Configured, but not connected yet. Must NOT be treated as unreadable:
    /// an unreadable SOURCE opens the refund leg without its source-side
    /// checks (round 4, M-4), which is only right for a chain no reader exists
    /// for at all.
    NotReady,
    /// Not configured on this validator.
    NotConfigured,
}

fn lookup(readers: &BTreeMap<u64, LazyReader>, chain_id: u64) -> Reader<'_> {
    match readers.get(&chain_id) {
        None => Reader::NotConfigured,
        Some(LazyReader { reader: Some(r), .. }) => Reader::Ready(r),
        Some(_) => Reader::NotReady,
    }
}

/// [`GateReader::aged_block`] against one endpoint, from a given head.
///
/// Conservative by construction: any block old enough will do, so we step back
/// exponentially until the timestamp condition holds rather than binary-
/// searching for the newest such block. Overshooting only makes the effective
/// timeout longer, which is the safe direction. Typically one or two calls,
/// because block times are stable.
async fn aged_block_on(
    provider: &DynProvider,
    head_num: u64,
    timeout_secs: i64,
) -> anyhow::Result<Option<u64>> {
    let head = provider
        .get_block_by_number(BlockNumberOrTag::Number(head_num))
        .await?
        .context("confirmed head block vanished")?;
    let target = (head.header.timestamp as i64).saturating_sub(timeout_secs);

    // Start from a 12s/block estimate, then double until we are far enough
    // back. Bounded so a pathological chain cannot spin here.
    let mut step: u64 = ((timeout_secs.max(1) as u64) / 12).max(1);
    for _ in 0..24 {
        let Some(candidate) = head_num.checked_sub(step) else { return Ok(None) };
        let block = provider
            .get_block_by_number(BlockNumberOrTag::Number(candidate))
            .await?
            .context("candidate block vanished")?;
        if (block.header.timestamp as i64) <= target {
            return Ok(Some(candidate));
        }
        step = step.saturating_mul(2);
    }
    Ok(None)
}

/// The newest aged block a strict majority of the endpoints vouch for; `None`
/// when no majority vouches for any. See [`GateReader::aged_block`] for why.
/// `None < Some(_)` in `Option`'s order, which is exactly "vouches for nothing".
fn agreed_aged_block(found: &[Option<u64>]) -> Option<u64> {
    majority_floor(found).flatten()
}

// `majority_floor` moved to `provider` (audit round 7, M7-8): the scan loop's
// head now uses the same rule.
use crate::provider::majority_floor;

struct DestinationState {
    executed: bool,
    cancelled: bool,
}

struct SourceState {
    sent_by: Address,
    refunded: bool,
}

/// What this validator should do about one candidate, after reading both chains.
#[derive(Debug, PartialEq, Eq)]
enum Decision {
    /// Destination is unclaimed and past the timeout — attest the burn.
    AttestCancel,
    /// Destination is burned — attest the payout.
    AttestRefund,
    /// Nothing to do (delivered, already refunded, already attested by us, or a
    /// chain we don't watch). Carries a reason for the log.
    Skip(&'static str),
}

/// Has this validator already attested BOTH domains for this candidate?
///
/// If so [`decide`] returns some `Skip` for every possible chain state — with
/// both flags set, `AttestRefund` is guarded by `already_attested_refund` and
/// `AttestCancel` by `already_attested_cancel`, which is tested before
/// `aged_out` — so reading the two chains first can only confirm what is already
/// known. Skipping early is exactly equivalent and saves the 8-30 RPC calls
/// `handle_candidate` would spend to reach the same answer, on every tick, for
/// as long as the row stays in the queue (audit 2026-09-16, H-6).
///
/// Counts only attestations that RECOVER to this validator over their own
/// domain's digest — see [`attested_by`].
fn fully_attested_by_us(rec: &SubmissionRecord, id: B256, signer_addr: Address) -> bool {
    attested_by(&rec.cancel_signatures, id, SigKind::Cancel, signer_addr)
        && attested_by(&rec.refund_signatures, id, SigKind::Refund, signer_addr)
}

/// Does `sigs` hold a genuine `kind` attestation by `signer_addr` for `id`?
///
/// Decided by RECOVERING each signature over `kind`'s digest, never by the
/// store's `signer` label (audit 2026-09-16, LOW). The label is a string the
/// store hands back: a store — or anything between us and it — that puts our
/// address on a junk signature used to make this validator believe it had
/// already voted, so it never attested that transfer again and its refund quorum
/// was one short for good. Recovery is what the Gate will do with the bytes, so
/// it is the only answer to "have we voted" that means anything on-chain.
fn attested_by(sigs: &[SignerSig], id: B256, kind: SigKind, signer_addr: Address) -> bool {
    sigs.iter()
        .any(|s| matches!(bridge_core::store::verify_attestation(id, kind, s), Ok(a) if a == signer_addr))
}

/// The submissionId a candidate's OWN params hash to, or an error if the store
/// paired them with a different id.
///
/// Every routing decision in [`handle_candidate`] — which chain is the
/// destination, which is the source — comes from `chain_id_to`/`chain_id_from`,
/// while every read and the signature itself are keyed on `submission_id`.
/// Nothing tied the two together (audit 2026-09-16, LOW), so a record naming a
/// real id with a different corridor sent the `executed`/`cancelled` reads to a
/// gate that has never heard of the transfer and decided it from what that gate
/// said. The sig-store enforces this binding on write; this validator no longer
/// takes that on trust, exactly as it does not take the store's timeout.
fn bound_submission_id(rec: &SubmissionRecord) -> anyhow::Result<B256> {
    let claimed = B256::from_str(&rec.submission_id).context("bad submission_id")?;
    let computed = bridge_core::store::canonical_submission_id(rec)
        .map_err(|e| anyhow::anyhow!("candidate params do not form a submissionId: {e}"))?;
    anyhow::ensure!(
        computed == claimed,
        "candidate {claimed:#x} carries params that hash to {computed:#x}; refusing to route reads by them"
    );
    Ok(claimed)
}

/// Decide from on-chain facts alone. Split out from the I/O so the safety rules
/// are unit-testable.
///
/// `aged_out` is this validator's OWN answer to "has the unclaimed timeout
/// elapsed?", derived from `sentBy` at a historical block (see
/// [`GateReader::was_sent_by_block`]) — never from the store's `refund_status`.
///
/// ## Why the timeout has to be checked here (finding H-2)
///
/// The store only nominates candidates: `sweep_refund_eligible` flips
/// `refund_status` to `'eligible'` after `refund_timeout_secs`. This loop used to
/// treat "it is on the candidate list" as "the timeout has elapsed", so the
/// entire unclaimed-timeout rested on a database column — a value no validator
/// verified, and one the module docs wrongly described as unable to authorise
/// anything.
///
/// It authorised plenty: a wrong `created_at`, clock skew, a misconfigured sweep
/// interval, or write access to the DB nominates healthy in-flight transfers, and
/// within one poll interval the validators attest cancels for all of them.
/// `cancel` is irreversible and permanently forecloses the payout, so that turns
/// a DB fault into a fleet-wide forced-refund of everything in flight.
///
/// The destination check (`executed == false`) never stopped it, because a
/// transfer that is merely *in flight* has not been claimed yet either — that is
/// precisely the window an early cancel steals.
///
/// ## A source this validator cannot read (audit round 4, M-4)
///
/// `src` is `None` when there is no reader for `chain_id_from` — today that means
/// the source is Solana, which no EVM validator can read. The CANCEL leg is then
/// impossible here, because the age can only be established on the source, and
/// `aged_out` MUST be `false` for such a candidate (the caller guarantees it;
/// this function refuses regardless). The REFUND leg is different: it follows a
/// burn this validator observed on a destination it CAN read, at a confirmed
/// block, and the source-side checks it skips (`sentBy`, `refunded`) only guard
/// against a wasted attestation — the Solana program's `process_refund` refuses
/// `NotSent` and a spent record on-chain. Skipping refunds too, as this loop
/// used to (`return` on a missing source reader), left every stuck Solana→EVM
/// transfer unrefundable.
fn decide(
    src: Option<&SourceState>,
    dst: &DestinationState,
    aged_out: bool,
    already_attested_cancel: bool,
    already_attested_refund: bool,
) -> Decision {
    // The destination was DELIVERED. Never attest anything: a refund on top of a
    // claim is the double-spend this whole design exists to prevent.
    if dst.executed && !dst.cancelled {
        return Decision::Skip("delivered on destination");
    }
    match src {
        // Source has already paid it back.
        Some(src) if src.refunded || src.sent_by == Address::ZERO => {
            return Decision::Skip("already refunded, or not sent from this gate");
        }
        Some(_) => {}
        // No source reader: only the refund leg can proceed (see above).
        None if !dst.cancelled => {
            return Decision::Skip("source chain unreadable — cancel cannot be attested here");
        }
        None => {}
    }
    // A burn that is already on-chain is a settled fact — the refund leg does not
    // re-litigate the timeout, it only follows the destination.
    if dst.cancelled {
        return if already_attested_refund {
            Decision::Skip("refund already attested by us")
        } else {
            Decision::AttestRefund
        };
    }
    if already_attested_cancel {
        return Decision::Skip("cancel already attested by us");
    }
    // Burning a transfer the keeper may still be about to deliver is not ours to
    // do until the window we independently verified has actually passed.
    if !aged_out {
        return Decision::Skip("unclaimed timeout has not elapsed (verified on-chain)");
    }
    Decision::AttestCancel
}

/// What [`handle_candidate`] concluded, beyond any attestation it posted.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Done,
    /// The source gate, read at a confirmed block, has no `sentBy` for this id.
    NotSent,
}

/// First rest for a candidate the source gate says it never sent.
const NOT_SENT_REST: Duration = Duration::from_secs(10 * 60);
/// The longest rest: a mistaken memo can delay a refund by at most this.
const NOT_SENT_MAX_REST: Duration = Duration::from_secs(24 * 60 * 60);
/// Bound on the memo. Past it a not-sent row is simply re-read each tick, as
/// before H7-5 — the memo saves RPC, it is never what keeps the loop live.
const NOT_SENT_MAX_ENTRIES: usize = 100_000;

/// Candidates the source chain says were never sent, rested with a doubling
/// backoff (audit round 7, H7-5).
///
/// A row only the store has — no chain ever emitted it — stays a candidate for
/// as long as the store keeps serving it, and used to cost every validator a
/// source read plus the age search on every tick. "Not sent" is read at a
/// confirmed block, but it is a fact about NOW: a row naming a future nonce
/// becomes a real transfer if someone sends exactly it. So the memo rests a row
/// instead of dropping it, and the rest is capped at [`NOT_SENT_MAX_REST`].
#[derive(Default)]
struct NotSentMemo {
    /// id -> (do not re-read before, current rest)
    rows: std::collections::HashMap<B256, (Instant, Duration)>,
}

impl NotSentMemo {
    fn is_resting(&self, id: B256, now: Instant) -> bool {
        self.rows.get(&id).is_some_and(|(until, _)| now < *until)
    }

    fn rest(&mut self, id: B256, now: Instant) {
        let rest = match self.rows.get(&id) {
            Some((_, prev)) => (*prev * 2).min(NOT_SENT_MAX_REST),
            None if self.rows.len() >= NOT_SENT_MAX_ENTRIES => return,
            None => NOT_SENT_REST,
        };
        self.rows.insert(id, (now + rest, rest));
    }

    /// Forget rows whose rest ran out long ago, so the memo tracks the queue.
    fn prune(&mut self, now: Instant) {
        self.rows.retain(|_, (until, _)| now < *until + NOT_SENT_MAX_REST);
    }
}

/// Poll the store for stuck transfers and attest cancels/refunds for them.
pub async fn run(
    cfg: RefundConfig,
    sources: Vec<(u64, String, Vec<String>)>, // (chain_id, gate, endpoints)
    signer: PrivateKeySigner,
    sink: std::sync::Arc<StoreBackend>,
    // `[corroborate] require`: also demand two agreeing endpoints on a chain
    // configured with only one (which then never connects).
    require_corroboration: bool,
) -> anyhow::Result<()> {
    let signer_addr = signer.address();
    let retry = Duration::from_millis(cfg.poll_interval_ms.max(1000));

    // Every chain is CONFIGURED up front and CONNECTED lazily (audit round 7,
    // L7-13). A validator that cannot read a chain must not vote on transfers
    // touching it, so a bad endpoint is never papered over — but this used to
    // wait, forever, until every chain had connected, so one dead endpoint on
    // one chain stopped the refund loop for all of them. Now each tick retries
    // the chains that are not ready yet, and only candidates touching such a
    // chain are skipped (see `handle_candidate`); the rest proceed.
    let mut source_readers: BTreeMap<u64, LazyReader> = BTreeMap::new();
    for (chain_id, gate, endpoints) in &sources {
        source_readers.insert(*chain_id, LazyReader::new(*chain_id, gate.clone(), endpoints.clone()));
    }

    let mut dest_readers: BTreeMap<u64, LazyReader> = BTreeMap::new();
    for dest in &cfg.destinations {
        let endpoints = dest.endpoints()?;
        dest_readers.insert(dest.chain_id, LazyReader::new(dest.chain_id, dest.gate.clone(), endpoints));
    }

    let mut cursor = RefundCursor::default();
    let mut not_sent = NotSentMemo::default();

    info!(
        validator = %signer_addr,
        sources = source_readers.len(),
        destinations = dest_readers.len(),
        timeout_secs = cfg.timeout_secs,
        "refund attestation loop started"
    );

    loop {
        for r in source_readers.values_mut().chain(dest_readers.values_mut()) {
            r.ensure(cfg.block_confirmation, require_corroboration).await;
        }

        // Walk the queue a page at a time (audit 2026-09-16, H-6), resuming
        // where the previous tick stopped (H7-5). Unpaged, a queue grown past
        // the client's response cap returned an error on every tick forever; and
        // walked from the head each tick, rows that never leave the queue hid
        // every row behind them.
        let walk = cursor
            .walk(|limit, after| {
                let sink = &sink;
                async move { sink.refund_candidates(limit, after.as_deref()).await }
            })
            .await;
        let candidates = match walk {
            Ok(w) => {
                if w.truncated {
                    warn!(
                        pages = MAX_REFUND_PAGES,
                        page_size = REFUND_PAGE,
                        "refund queue exceeds one tick's walk; resuming from here next tick"
                    );
                }
                w.candidates
            }
            Err(e) => {
                warn!(error = %e, "fetching refund candidates failed; retrying");
                tokio::time::sleep(retry).await;
                continue;
            }
        };
        let now = Instant::now();
        not_sent.prune(now);

        for rec in candidates {
            // Cheap-skip before the 8-30 on-chain reads `handle_candidate` makes:
            // a candidate this validator has already attested in both domains has
            // nothing left for it to do, and re-deciding it costs the same RPC
            // budget as a fresh one.
            let id = match bound_submission_id(&rec) {
                Ok(id) => id,
                Err(e) => {
                    warn!(submission_id = %rec.submission_id, error = %e, "refund candidate refused");
                    continue;
                }
            };
            if fully_attested_by_us(&rec, id, signer_addr) {
                continue;
            }
            if not_sent.is_resting(id, now) {
                continue;
            }
            match handle_candidate(
                &rec,
                id,
                &source_readers,
                &dest_readers,
                &signer,
                signer_addr,
                &sink,
                cfg.timeout_secs,
            )
            .await
            {
                Ok(Outcome::NotSent) => not_sent.rest(id, now),
                Ok(Outcome::Done) => {}
                Err(e) => {
                    warn!(submission_id = %rec.submission_id, error = %e, "refund attestation failed");
                }
            }
        }

        tokio::time::sleep(Duration::from_millis(cfg.poll_interval_ms)).await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_candidate(
    rec: &SubmissionRecord,
    // Verified by `bound_submission_id`: the id `rec`'s params hash to.
    id: B256,
    source_readers: &BTreeMap<u64, LazyReader>,
    dest_readers: &BTreeMap<u64, LazyReader>,
    signer: &PrivateKeySigner,
    signer_addr: Address,
    sink: &StoreBackend,
    timeout_secs: i64,
) -> anyhow::Result<Outcome> {
    // The DESTINATION must be readable: whether a transfer was delivered is the
    // one fact no attestation may take from the store. A destination we cannot
    // read — or cannot read YET (L7-13) — is a corridor we do not vote on.
    let dst = match lookup(dest_readers, rec.chain_id_to) {
        Reader::Ready(r) => r,
        Reader::NotReady => {
            tracing::debug!(submission_id = %rec.submission_id, chain = rec.chain_id_to,
                            "destination not connected yet; skipping this tick");
            return Ok(Outcome::Done);
        }
        Reader::NotConfigured => return Ok(Outcome::Done),
    };
    // The SOURCE may be unreadable (round 4, M-4: a Solana source). Then only the
    // refund leg is possible — `decide` enforces that — and the age is never
    // claimed: `aged_out` stays false. A source that IS configured but not yet
    // connected is not "unreadable": skip the candidate until it connects, or
    // the refund leg would run without the source checks it always had.
    let src = match lookup(source_readers, rec.chain_id_from) {
        Reader::Ready(r) => Some(r),
        Reader::NotConfigured => None,
        Reader::NotReady => {
            tracing::debug!(submission_id = %rec.submission_id, chain = rec.chain_id_from,
                            "source not connected yet; skipping this tick");
            return Ok(Outcome::Done);
        }
    };

    let dst_state = dst.destination_state(id).await.context("reading destination gate")?;
    let src_state = match src {
        Some(s) => Some(s.source_state(id).await.context("reading source gate")?),
        None => None,
    };

    // H7-5: a source that says it never sent this, or already paid it back,
    // settles it before the age search below — the 10-30 reads that made every
    // junk row in the queue expensive on every tick. `decide` would skip it
    // anyway; this only skips the reads that cannot change that.
    if let Some(s) = &src_state {
        if s.sent_by == Address::ZERO && !s.refunded {
            tracing::debug!(submission_id = %rec.submission_id, "source gate never sent this; resting it");
            return Ok(Outcome::NotSent);
        }
        if s.refunded {
            return Ok(Outcome::Done);
        }
    }

    // H-2: establish the unclaimed timeout OURSELVES, from the source chain, and
    // never from the store's nomination. Only needed on the cancel leg — once the
    // destination is burned the refund follows an on-chain fact, not a timer — so
    // skip the reads when they cannot change the outcome.
    let aged_out = match (src, dst_state.cancelled) {
        (_, true) => true,
        (None, false) => false, // cannot be shown; `decide` skips the cancel anyway
        (Some(src), false) => {
            match src.aged_block(timeout_secs).await.context("locating an aged source block")? {
                Some(block) => src
                    .was_sent_by_block(id, block)
                    .await
                    .context("reading historical sentBy")?,
                // The chain has no block old enough yet: nothing can have aged out.
                None => false,
            }
        }
    };

    let decision = decide(
        src_state.as_ref(),
        &dst_state,
        aged_out,
        attested_by(&rec.cancel_signatures, id, SigKind::Cancel, signer_addr),
        attested_by(&rec.refund_signatures, id, SigKind::Refund, signer_addr),
    );

    let kind = match decision {
        Decision::Skip(reason) => {
            tracing::debug!(submission_id = %rec.submission_id, reason, "no attestation");
            return Ok(Outcome::Done);
        }
        Decision::AttestCancel => SigKind::Cancel,
        Decision::AttestRefund => SigKind::Refund,
    };

    let digest = kind.digest(id);
    let sig = signer.sign_message(digest.as_slice()).await?;
    let sig = SignerSig {
        signer: format!("{signer_addr:#x}"),
        signature: encode_signature(&sig),
    };

    sink.upsert_attestation(&rec.submission_id, kind, sig).await?;

    info!(
        submission_id = %rec.submission_id,
        kind = kind.as_str(),
        chain_from = rec.chain_id_from,
        chain_to = rec.chain_id_to,
        source_readable = src.is_some(),
        dest_chain = dst.chain_id,
        "ATTESTED"
    );
    Ok(Outcome::Done)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sender() -> Address {
        Address::repeat_byte(0x11)
    }

    fn src(refunded: bool) -> SourceState {
        SourceState { sent_by: sender(), refunded }
    }

    /// This validator verified, on-chain, that the unclaimed timeout has elapsed.
    const AGED: bool = true;

    #[test]
    fn never_attests_a_delivered_transfer() {
        // THE safety rule. A claimed transfer must never earn a cancel or refund
        // attestation, whatever the store says about timeouts.
        let dst = DestinationState { executed: true, cancelled: false };
        assert!(matches!(decide(Some(&src(false)), &dst, AGED, false, false), Decision::Skip(_)));
    }

    #[test]
    fn attests_cancel_when_destination_is_untouched_and_aged_out() {
        let dst = DestinationState { executed: false, cancelled: false };
        assert_eq!(decide(Some(&src(false)), &dst, AGED, false, false), Decision::AttestCancel);
    }

    /// THE H-2 rule. Appearing on the store's candidate list is not evidence of
    /// anything: the validator establishes the age itself against the source
    /// chain, and until that passes it will not burn a transfer the keeper may
    /// still be about to deliver.
    #[test]
    fn never_attests_a_cancel_before_the_timeout_it_verified_itself() {
        let untouched = DestinationState { executed: false, cancelled: false };
        assert_eq!(
            decide(Some(&src(false)), &untouched, false, false, false),
            Decision::Skip("unclaimed timeout has not elapsed (verified on-chain)"),
            "a store nomination alone must not authorise a burn"
        );
        // The same candidate becomes attestable once it has genuinely aged.
        assert_eq!(
            decide(Some(&src(false)), &untouched, AGED, false, false),
            Decision::AttestCancel
        );
    }

    /// The finding's actual attack: a DB that flags everything eligible the moment
    /// it is created must not be able to force a fleet-wide cancel of healthy
    /// in-flight transfers. Note the destination check never caught this — an
    /// in-flight transfer is unclaimed too, which is exactly the window a
    /// premature cancel steals.
    #[test]
    fn a_compromised_store_cannot_shorten_the_window() {
        let in_flight = DestinationState { executed: false, cancelled: false };
        for already_cancel in [false, true] {
            let d = decide(Some(&src(false)), &in_flight, false, already_cancel, false);
            assert!(
                matches!(d, Decision::Skip(_)),
                "a not-yet-aged transfer must never be cancelled, got {d:?}"
            );
        }
    }

    /// The refund leg follows an on-chain burn rather than a timer, so it does not
    /// re-check the age: by then the destination is provably foreclosed.
    #[test]
    fn a_burned_destination_still_earns_a_refund_without_an_age_check() {
        let burned = DestinationState { executed: true, cancelled: true };
        assert_eq!(decide(Some(&src(false)), &burned, false, true, false), Decision::AttestRefund);
    }

    #[test]
    fn attests_refund_only_after_the_burn_is_on_chain() {
        let untouched = DestinationState { executed: false, cancelled: false };
        assert_eq!(
            decide(Some(&src(false)), &untouched, AGED, true, false),
            Decision::Skip("cancel already attested by us")
        );

        let burned = DestinationState { executed: true, cancelled: true };
        assert_eq!(decide(Some(&src(false)), &burned, AGED, true, false), Decision::AttestRefund);
    }

    #[test]
    fn stops_once_the_source_has_paid_out() {
        let burned = DestinationState { executed: true, cancelled: true };
        assert!(matches!(decide(Some(&src(true)), &burned, AGED, true, true), Decision::Skip(_)));
    }

    #[test]
    fn refuses_a_submission_this_gate_never_sent() {
        // A quorum must not form for a transfer that was never locked here.
        let burned = DestinationState { executed: true, cancelled: true };
        let ghost = SourceState { sent_by: Address::ZERO, refunded: false };
        assert!(matches!(decide(Some(&ghost), &burned, AGED, false, false), Decision::Skip(_)));
    }

    /// Round 5, H-6. `handle_candidate` now skips a candidate this validator has
    /// attested in BOTH domains without reading either chain. That is only sound
    /// if `decide` could never have asked for work in that state — so assert it
    /// over every combination of chain facts, including the ones that cannot
    /// co-occur. If a future branch returns an `Attest*` with both flags set,
    /// this fails and the pre-filter must be revisited.
    #[test]
    fn both_attested_always_skips_whatever_the_chains_say() {
        for executed in [false, true] {
            for cancelled in [false, true] {
                for aged in [false, true] {
                    for refunded in [false, true] {
                        let dst = DestinationState { executed, cancelled };
                        for source in [Some(src(refunded)), None] {
                            let d = decide(source.as_ref(), &dst, aged, true, true);
                            assert!(
                                matches!(d, Decision::Skip(_)),
                                "executed={executed} cancelled={cancelled} aged={aged} \
                                 refunded={refunded} source={} produced {d:?}, so skipping \
                                 the on-chain reads would drop real work",
                                source.is_some()
                            );
                        }
                    }
                }
            }
        }
    }

    use alloy::signers::SignerSync;
    use alloy::primitives::U256;

    /// A candidate whose id genuinely binds its params.
    pub(super) fn bound_record() -> SubmissionRecord {
        let domain = B256::repeat_byte(0xD0);
        let token = Address::repeat_byte(0x33);
        let debridge_id = bridge_core::debridge_id(U256::from(1u64), token);
        let receiver = Address::repeat_byte(0xAB).to_vec();
        let id = bridge_core::submission_id(
            domain,
            debridge_id,
            6,
            U256::from(100u64),
            U256::from(1u64),
            U256::from(2u64),
            U256::from(7u64),
            &receiver,
        );
        SubmissionRecord {
            submission_id: format!("{id:#x}"),
            bridge_domain: format!("{domain:#x}"),
            debridge_id: format!("{debridge_id:#x}"),
            amount: "100".into(),
            bridge_decimals: Some(6),
            chain_id_from: 1,
            chain_id_to: 2,
            nonce: 7,
            receiver: format!("0x{}", hex::encode(&receiver)),
            auto_params: "0x".into(),
            native_sender: "0x".into(),
            token: format!("{token:#x}"),
            signatures: vec![],
            cancel_signatures: vec![],
            refund_signatures: vec![],
        }
    }

    fn attest(key: &PrivateKeySigner, id: B256, kind: SigKind) -> SignerSig {
        let sig = key.sign_message_sync(kind.digest(id).as_slice()).unwrap();
        SignerSig { signer: format!("{:#X}", key.address()), signature: encode_signature(&sig) }
    }

    /// The pre-filter itself: both domains genuinely signed by us.
    /// H7-5: a never-sent candidate is rested with a doubling backoff, capped,
    /// and comes back once its rest is over.
    #[test]
    fn a_never_sent_candidate_rests_and_comes_back() {
        let id = B256::repeat_byte(0x42);
        let t0 = Instant::now();
        let mut memo = NotSentMemo::default();
        assert!(!memo.is_resting(id, t0));
        memo.rest(id, t0);
        assert!(memo.is_resting(id, t0 + NOT_SENT_REST - Duration::from_secs(1)));
        assert!(!memo.is_resting(id, t0 + NOT_SENT_REST), "re-read once the rest is over");
        let t1 = t0 + NOT_SENT_REST;
        memo.rest(id, t1);
        assert!(memo.is_resting(id, t1 + NOT_SENT_REST), "the second rest is twice as long");
        assert!(!memo.is_resting(id, t1 + NOT_SENT_REST * 2));
        let mut t = t1;
        for _ in 0..20 {
            memo.rest(id, t);
            t += NOT_SENT_MAX_REST;
        }
        assert!(!memo.is_resting(id, t), "a rest never exceeds the cap");
        memo.prune(t + NOT_SENT_MAX_REST * 2);
        assert!(memo.rows.is_empty(), "long-expired rows are forgotten");
    }

    #[test]
    fn fully_attested_needs_both_domains() {
        let me = PrivateKeySigner::random();
        let other = PrivateKeySigner::random();
        let mut rec = bound_record();
        let id = bound_submission_id(&rec).unwrap();
        assert!(!fully_attested_by_us(&rec, id, me.address()));

        rec.cancel_signatures = vec![attest(&me, id, SigKind::Cancel)];
        assert!(!fully_attested_by_us(&rec, id, me.address()), "cancel alone is not done");

        rec.refund_signatures = vec![attest(&other, id, SigKind::Refund)];
        assert!(!fully_attested_by_us(&rec, id, me.address()), "another validator's refund is not ours");

        rec.refund_signatures.push(attest(&me, id, SigKind::Refund));
        assert!(fully_attested_by_us(&rec, id, me.address()));
    }

    /// THE regression (audit 2026-09-16, LOW). The dedupe used to trust the
    /// store's `signer` LABEL, so a junk signature filed under our address made
    /// this validator believe it had already voted — it never attested that
    /// transfer, and the refund quorum stayed one short forever.
    #[test]
    fn a_label_with_our_address_on_a_signature_we_did_not_make_is_not_our_vote() {
        let me = PrivateKeySigner::random();
        let other = PrivateKeySigner::random();
        let rec = bound_record();
        let id = bound_submission_id(&rec).unwrap();
        let mine = format!("{:#x}", me.address());

        // Someone else's genuine signature, relabelled as ours.
        let mut forged = attest(&other, id, SigKind::Cancel);
        forged.signer = mine.clone();
        assert!(!attested_by(&[forged], id, SigKind::Cancel, me.address()));

        // Garbage bytes under our label.
        let junk = SignerSig { signer: mine, signature: format!("0x{}", "00".repeat(65)) };
        assert!(!attested_by(&[junk], id, SigKind::Cancel, me.address()));

        // Our real transfer signature does not count as a cancel vote either.
        let wrong_domain = attest(&me, id, SigKind::Transfer);
        assert!(!attested_by(&[wrong_domain], id, SigKind::Cancel, me.address()));

        // And the real thing does.
        assert!(attested_by(&[attest(&me, id, SigKind::Cancel)], id, SigKind::Cancel, me.address()));
    }

    /// THE regression (audit 2026-09-16, LOW). Reads are routed by
    /// `chain_id_to`/`chain_id_from` but keyed on `submission_id`; a candidate
    /// whose corridor was swapped under a real id is refused before any read.
    #[test]
    fn a_candidate_whose_params_do_not_hash_to_its_id_is_refused() {
        let good = bound_record();
        assert!(bound_submission_id(&good).is_ok(), "premise: the fixture binds");

        let mut rerouted = good.clone();
        rerouted.chain_id_to = 99;
        assert!(bound_submission_id(&rerouted).is_err(), "a different destination must not be read");

        let mut resourced = good.clone();
        resourced.chain_id_from = 98;
        assert!(bound_submission_id(&resourced).is_err(), "a different source must not be read");

        let mut garbage = good;
        garbage.submission_id = "not-an-id".into();
        assert!(bound_submission_id(&garbage).is_err());
    }

    #[test]
    fn does_not_re_attest() {
        let burned = DestinationState { executed: true, cancelled: true };
        assert_eq!(
            decide(Some(&src(false)), &burned, AGED, true, true),
            Decision::Skip("refund already attested by us")
        );
    }

    // --- an unreadable source (round 4, M-4: Solana-origin transfers) --------

    /// THE M-4 fix. This validator can read the EVM destination but not the
    /// Solana source. It used to return before deciding anything, so a burned
    /// Solana->EVM transfer never collected refund attestations from the EVM
    /// validators and stayed stuck. A burn observed at a confirmed block is
    /// enough for the refund leg; the source gate enforces the rest on-chain.
    #[test]
    fn a_burn_on_a_readable_destination_earns_a_refund_even_without_a_source_reader() {
        let burned = DestinationState { executed: true, cancelled: true };
        assert_eq!(decide(None, &burned, false, false, false), Decision::AttestRefund);
        assert_eq!(
            decide(None, &burned, false, false, true),
            Decision::Skip("refund already attested by us")
        );
    }

    /// The cancel leg needs the age, and the age lives on the source. No reader
    /// => no cancel, however the candidate was nominated and even if the caller
    /// somehow passed `aged_out = true`.
    #[test]
    fn no_source_reader_never_yields_a_cancel() {
        let untouched = DestinationState { executed: false, cancelled: false };
        for aged in [false, true] {
            for already in [false, true] {
                assert_eq!(
                    decide(None, &untouched, aged, already, false),
                    Decision::Skip("source chain unreadable — cancel cannot be attested here")
                );
            }
        }
    }

    /// Delivered stays delivered, reader or not.
    #[test]
    fn a_delivered_transfer_is_never_attested_without_a_source_reader_either() {
        let delivered = DestinationState { executed: true, cancelled: false };
        assert!(matches!(decide(None, &delivered, true, false, false), Decision::Skip(_)));
    }
}

/// Audit round 6, HIGH #2: one destination endpoint used to decide, alone,
/// whether a transfer was burned — and so whether every validator attested its
/// refund while the claim signatures still existed.
#[cfg(test)]
mod round6_tests {
    use super::*;
    use crate::provider::majority;
    use alloy::providers::ProviderBuilder;
    use alloy_sol_types::SolCall;

    #[test]
    fn two_endpoints_must_both_agree() {
        assert_eq!(majority(&[("a", (false, true)), ("b", (false, true))], 2), Ok((false, true)));
        // THE finding: one endpoint claiming a burn the other does not see.
        let e = majority(&[("liar", (false, true)), ("honest", (false, false))], 2).unwrap_err();
        assert!(e.disagreement, "{e:?}");
        // One endpoint down is not agreement either — and not an accusation.
        let e = majority(&[("a", (false, true))], 2).unwrap_err();
        assert!(!e.disagreement, "{e:?}");
    }

    #[test]
    fn with_three_endpoints_one_liar_is_outvoted_either_way() {
        // Forging a burn fails...
        assert_eq!(
            majority(&[("liar", true), ("h1", false), ("h2", false)], 2),
            Ok(false)
        );
        // ...and so does stalling every refund by dissenting from a real one.
        assert_eq!(
            majority(&[("h1", true), ("liar", false), ("h2", true)], 2),
            Ok(true)
        );
        // Three different answers: nothing.
        assert!(majority(&[("a", 1), ("b", 2), ("c", 3)], 2).is_err());
        // Two of four is not a majority.
        assert!(majority(&[("a", 1), ("b", 1), ("c", 2), ("d", 2)], 2).is_err());
    }

    #[test]
    fn a_single_endpoint_chain_is_only_trusted_when_configured_so() {
        assert_eq!(majority(&[("only", true)], 1), Ok(true));
        assert!(majority::<bool>(&[], 1).is_err());
    }

    /// A liar can push the aged block BACK (harder to show the deposit existed
    /// by then), never forward.
    #[test]
    fn the_oldest_aged_block_wins() {
        // Two endpoints: unchanged — both must vouch, so the older answer.
        assert_eq!(agreed_aged_block(&[Some(900), Some(950)]), Some(900));
        assert_eq!(agreed_aged_block(&[Some(900), Some(1)]), Some(1));
        assert_eq!(agreed_aged_block(&[Some(900), None]), None, "no block old enough: nothing ages out");
        assert_eq!(agreed_aged_block(&[Some(900)]), Some(900));
    }

    /// Audit round 7, L7-12: with three endpoints one liar is outvoted in BOTH
    /// directions — it can neither block every cancel (`None`, or an absurdly
    /// old block) nor make a transfer count as aged early (a block too new).
    #[test]
    fn with_three_endpoints_one_liar_cannot_move_the_aged_block() {
        // "None wins outright" no longer holds for a lone None.
        assert_eq!(agreed_aged_block(&[Some(900), None, Some(900)]), Some(900));
        assert_eq!(agreed_aged_block(&[Some(900), Some(1), Some(900)]), Some(900));
        // The dangerous direction: a liar's too-new block is not used.
        assert_eq!(agreed_aged_block(&[Some(900), Some(10_000), Some(900)]), Some(900));
        // Two vouching for nothing is a majority: nothing ages out.
        assert_eq!(agreed_aged_block(&[Some(900), None, None]), None);
        // Honest-but-different answers: the newest a majority vouches for.
        assert_eq!(agreed_aged_block(&[Some(900), Some(800), Some(850)]), Some(850));
    }

    #[test]
    fn majority_floor_is_what_a_strict_majority_has_reached() {
        assert_eq!(majority_floor::<u64>(&[]), None);
        assert_eq!(majority_floor(&[7u64]), Some(7));
        assert_eq!(majority_floor(&[100u64, 5]), Some(5), "two: both must have reached it");
        assert_eq!(majority_floor(&[100u64, 5, 100]), Some(100), "a low liar is outvoted");
        assert_eq!(majority_floor(&[100u64, u64::MAX, 100]), Some(100), "a high liar is outvoted");
        assert_eq!(majority_floor(&[1u64, 2, 3, 4]), Some(2), "four: three must have reached it");
    }

    /// End to end: one endpoint reporting a stale head no longer drags the
    /// confirmed block (and so every read, and the aged-block search) back.
    #[tokio::test]
    async fn a_low_head_from_one_of_three_endpoints_is_outvoted() {
        let r = reader(&[stub(100, false, false).await, stub(1, false, false).await, stub(100, false, false).await]);
        assert_eq!(r.confirmed_block().await.unwrap(), 98);
        // Two endpoints keep the strict rule: the lower head.
        let r = reader(&[stub(100, false, false).await, stub(50, false, false).await]);
        assert_eq!(r.confirmed_block().await.unwrap(), 48);
    }

    // ---- L7-13: chains connect lazily, one at a time -------------------------

    #[tokio::test]
    async fn a_chain_with_a_dead_endpoint_is_not_ready_and_does_not_hold_up_others() {
        let mut half_dead = LazyReader::new(1, "0x6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a".into(),
                                            vec![stub(100, false, false).await, "http://127.0.0.1:1/".into()]);
        let mut healthy = LazyReader::new(1, "0x6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a".into(),
                                          vec![stub(100, false, false).await, stub(100, false, false).await]);
        half_dead.ensure(2, false).await;
        healthy.ensure(2, false).await;
        let map: BTreeMap<u64, LazyReader> = [(1, half_dead), (2, healthy)].into_iter().collect();
        assert!(matches!(lookup(&map, 1), Reader::NotReady), "two configured, one healthy: not read single-source");
        assert!(matches!(lookup(&map, 2), Reader::Ready(_)));
        assert!(matches!(lookup(&map, 3), Reader::NotConfigured));
    }

    /// A configured source that has not connected yet must NOT be taken for an
    /// unreadable one: that would attest a refund without the source checks.
    /// The sink is dead, so any attempt to attest shows up as an error.
    #[tokio::test]
    async fn a_not_yet_connected_source_skips_rather_than_attesting_without_source_checks() {
        let rec = super::tests::bound_record(); // 1 -> 2
        let id = bound_submission_id(&rec).unwrap();
        let burned = || async { reader(&[stub(100, false, true).await, stub(100, false, true).await]) };
        let mut dests = BTreeMap::new();
        let mut d = LazyReader::new(2, String::new(), vec![]);
        d.reader = Some(burned().await);
        dests.insert(2, d);
        let signer = PrivateKeySigner::random();
        let sink = StoreBackend::remote_for_role("http://127.0.0.1:1", "SIG_STORE_VALIDATOR_TOKEN");

        // Source configured, not connected: skipped, nothing attempted.
        let mut srcs = BTreeMap::new();
        srcs.insert(1, LazyReader::new(1, String::new(), vec![]));
        handle_candidate(&rec, id, &srcs, &dests, &signer, signer.address(), &sink, 60)
            .await
            .expect("a not-ready source is a skip, not an attestation attempt");

        // Contrast: with NO source configured the refund leg does proceed
        // (round 4, M-4) — and reaches the (dead) sink.
        let none = BTreeMap::new();
        assert!(handle_candidate(&rec, id, &none, &dests, &signer, signer.address(), &sink, 60)
            .await
            .is_err());

        // And a destination not connected yet is a skip too.
        let mut not_ready = BTreeMap::new();
        not_ready.insert(2, LazyReader::new(2, String::new(), vec![]));
        handle_candidate(&rec, id, &none, &not_ready, &signer, signer.address(), &sink, 60)
            .await
            .expect("a not-ready destination is a skip");
    }

    // ---- end to end, against stub JSON-RPC endpoints -----------------------

    /// A gate endpoint at `head` answering `executed`/`cancelled` with the given
    /// values for any id at any block.
    async fn stub(head: u64, executed: bool, cancelled: bool) -> String {
        use axum::{routing::post, Json, Router};
        let word = |b: bool| format!("0x{:064x}", b as u8);
        let app = Router::new().route(
            "/",
            post(move |Json(req): Json<serde_json::Value>| async move {
                let result = match req["method"].as_str() {
                    Some("eth_blockNumber") => serde_json::json!(format!("{head:#x}")),
                    Some("eth_chainId") => serde_json::json!("0x1"),
                    Some("eth_call") => {
                        let tx = &req["params"][0];
                        let input = tx["input"].as_str().or(tx["data"].as_str()).unwrap_or_default();
                        let sel = hex::decode(&input[2..10]).unwrap();
                        if sel == Gate::executedCall::SELECTOR {
                            serde_json::json!(word(executed))
                        } else if sel == Gate::cancelledCall::SELECTOR {
                            serde_json::json!(word(cancelled))
                        } else {
                            panic!("stub RPC: unexpected call {input}")
                        }
                    }
                    m => panic!("stub RPC: unexpected method {m:?}"),
                };
                Json(serde_json::json!({ "jsonrpc": "2.0", "id": req["id"], "result": result }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}/")
    }

    fn reader(urls: &[String]) -> GateReader {
        GateReader {
            chain_id: 1,
            gate: Address::repeat_byte(0x6A),
            endpoints: urls
                .iter()
                .map(|u| (u.clone(), ProviderBuilder::new().connect_http(u.parse().unwrap()).erased()))
                .collect(),
            block_confirmation: 2,
            min_agree: 2,
        }
    }

    /// THE attack. A stuck transfer; a compromised destination endpoint reports it
    /// burned. Before the fix this read came from that one endpoint, `decide`
    /// returned `AttestRefund`, and a refund quorum formed on the source while the
    /// transfer was still claimable. Now the read is refused.
    #[tokio::test]
    async fn a_lying_endpoint_cannot_fake_a_burn() {
        let liar = stub(100, false, true).await;
        let honest = stub(100, false, false).await;
        let r = reader(&[liar, honest]);
        let err = r.destination_state(B256::repeat_byte(7)).await.err().expect("must refuse");
        assert!(err.to_string().contains("no 2 endpoints agree"), "{err}");
    }

    #[tokio::test]
    async fn a_real_burn_seen_by_both_is_read() {
        let r = reader(&[stub(100, false, true).await, stub(105, false, true).await]);
        let d = r.destination_state(B256::repeat_byte(7)).await.unwrap();
        assert!(!d.executed && d.cancelled);
        assert_eq!(
            decide(None, &d, true, false, false),
            Decision::AttestRefund,
            "a genuine, corroborated burn must still be refundable"
        );
    }

    #[tokio::test]
    async fn three_endpoints_outvote_one_liar() {
        let r = reader(&[stub(100, false, true).await, stub(100, false, false).await, stub(100, false, false).await]);
        let d = r.destination_state(B256::repeat_byte(7)).await.unwrap();
        assert!(!d.cancelled, "two honest endpoints outvote the forged burn");
    }
}
