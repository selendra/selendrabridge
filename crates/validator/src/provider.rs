//! Multi-RPC failover (mirrors this repo's `ChainProvider` + `Web3Service`).
//!
//! Holds an ordered list of RPC endpoints. Every call tries the currently
//! active endpoint first, then rotates through the rest on error, sticking to
//! the first one that answers. A `chainId` guard at startup drops endpoints
//! that report the wrong chain (the classic "pointed at the wrong network" bug).
//!
//! ## H-4: rotating on ERROR is not enough (audit 2026-09-16)
//!
//! Failover answers "is this endpoint up?", never "is this endpoint honest?". A
//! `Sent` event is the validator's entire view of a deposit: it recomputes the
//! submissionId from the log and signs it. One endpoint that serves a fabricated
//! log therefore mints a quorum-valid signature for a deposit that never
//! happened — and the destination gate cannot tell, because every signature over
//! it is genuine. (This comment once said the refund path already
//! second-sourced. It did not — it read every gate fact from one endpoint — and
//! since audit round 6 it cross-checks each read across endpoints too; see
//! `refund::GateReader`.)
//!
//! So [`Failover::get_logs_corroborated`] fetches the window from the active
//! endpoint and then asks a DIFFERENT endpoint for the same explicit range, and
//! the two log sets must match exactly. See [`Corroboration`] for why this is
//! `eth_getLogs` and not a `sentBy` read.
//!
//! ## Round 6: the check could be switched off from the serving side
//!
//! The first version let the serving endpoint alone decide where a window ended
//! and promoted whichever peer disagreed with it. A lying serving endpoint made
//! every window "inconclusive" by reporting a head no honest peer had reached,
//! and the scan loop signed single-source after ten of those; a lying peer got
//! itself made the serving endpoint by disagreeing once. The window end is now
//! bounded by the checking peer's head too, a disagreement is settled by
//! majority or not at all ([`tally`]), and an inconclusive window is never
//! signed (`main.rs`).

use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::{Filter, Log};
use bridge_core::config::redact_url;
use tracing::warn;

struct Endpoint {
    /// The endpoint as it may appear in a log line: scheme + host only. Hosted
    /// RPC keys live in the path/query, and every `warn!` here used to print the
    /// full URL (audit 2026-09-09, "keyed RPC URLs logged"). The full URL is
    /// consumed by the provider at construction and kept nowhere else.
    url: String,
    provider: DynProvider,
}

pub struct Failover {
    endpoints: Vec<Endpoint>,
    active: usize,
}

/// The verdict of the H-4 second-source check on one scan window.
///
/// WHY `eth_getLogs` AND NOT `sentBy`. Confirming a candidate with
/// `gate.sentBy(id) != 0` on a second endpoint is the other half of the audit's
/// suggested fix, and it cannot be used here: `sentBy` is *cleared* on refund
/// (`Gate.sol:1315`), so it is only meaningful when read at the log's own block —
/// which is historical state, which public endpoints do not keep. During a
/// catch-up replay (mesh10 routinely replays thousands of blocks) every such read
/// would fail on a non-archive node and the scanner would wedge, permanently, on
/// a check meant to protect it. Log INDEXES are kept by every node, which is the
/// point of `eth_getLogs`, so comparing the two sets over one explicit range
/// answers the same question — "did this chain really emit this?" — with no
/// archive dependency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Corroboration {
    /// A strict majority of the endpoints that answered — at least one besides
    /// the serving endpoint — returned exactly the same logs for the same range.
    Agreed { url: String },
    /// No majority backs the served logs. Some endpoint is wrong about what the
    /// chain emitted; nothing in this window may be signed. The serving endpoint
    /// is demoted only if a majority outvoted it (see [`tally`]).
    Disagreed { served_by: String, checked_by: String, detail: String },
    /// No second opinion was obtainable — the peer lags this range, or erred.
    /// NOT the same as agreement: the caller must neither sign nor advance on
    /// it, however many times it repeats.
    Inconclusive { reason: String },
    /// Only one endpoint is configured, so there is nothing to compare against.
    /// The caller decides whether that is fatal (`[corroborate] require = true`).
    Unavailable,
}

/// A log's identity for cross-endpoint comparison: where it sits in the chain
/// and what it says. Two honest nodes serving the same range must produce the
/// same set of these.
///
/// `removed` is deliberately excluded — the caller filters orphaned logs, and a
/// transient difference in that flag between two nodes is lag, not dishonesty.
///
/// `address` is included (audit round 6): the filter pins it on both sides, so
/// honest nodes can never differ on it, and leaving it out meant two sets could
/// "agree" on a log neither attributed to the gate.
type LogKey = (
    u64,
    u64,
    Option<alloy::primitives::B256>,
    alloy::primitives::Address,
    Vec<alloy::primitives::B256>,
    Vec<u8>,
);

fn log_key(l: &Log) -> LogKey {
    (
        l.block_number.unwrap_or_default(),
        l.log_index.unwrap_or_default(),
        l.transaction_hash,
        l.address(),
        l.topics().to_vec(),
        l.data().data.to_vec(),
    )
}

/// Connect to the first endpoint that answers AND reports `expected_chain_id`.
///
/// Used by the refund loop, which needs a plain provider for `eth_call` reads of
/// gate state rather than the log-scanning surface [`Failover`] exposes. The
/// chainId guard matters more here than anywhere: attesting a refund on the
/// strength of a *different* chain's `executed` flag would be exactly the
/// mistake that lets a delivered transfer also be refunded.
pub async fn connect_checked(urls: &[String], expected_chain_id: u64) -> anyhow::Result<DynProvider> {
    probe(urls, expected_chain_id, true, None)
        .await
        .into_iter()
        .next()
        .map(|e| e.provider)
        .ok_or_else(|| anyhow::anyhow!("no healthy RPC endpoints for chain {expected_chain_id}"))
}

/// Every endpoint that answers AND reports `expected_chain_id`, in the order
/// given, each with its REDACTED url (safe to log). Errors if none survive.
///
/// For callers that must cross-check one read across endpoints rather than use
/// whichever answers first — the refund loop, whose `executed`/`cancelled` reads
/// decide whether a transfer may be paid back (audit round 6).
pub async fn connect_all_checked(
    urls: &[String],
    expected_chain_id: u64,
) -> anyhow::Result<Vec<(String, DynProvider)>> {
    let healthy = probe(urls, expected_chain_id, false, None).await;
    anyhow::ensure!(!healthy.is_empty(), "no healthy RPC endpoints for chain {expected_chain_id}");
    Ok(healthy.into_iter().map(|e| (e.url, e.provider)).collect())
}

/// Build a provider for every url that parses, and keep those whose
/// `eth_chainId` matches, in the order given. Endpoints that fail either check
/// are logged and dropped. `stop_at_first` returns as soon as one is healthy,
/// for callers that only ever use a single provider.
///
/// The chainId guard is the whole point and is why this is one function rather
/// than two: a silently-wrong-network endpoint reads plausible state for a
/// DIFFERENT chain, which is how a validator ends up attesting against gate
/// state it never actually saw.
async fn probe(
    urls: &[String],
    expected_chain_id: u64,
    stop_at_first: bool,
    call_check: Option<alloy::primitives::Address>,
) -> Vec<Endpoint> {
    let mut healthy = Vec::new();
    for full_url in urls {
        let url = redact_url(full_url);
        let provider = match full_url.parse() {
            Ok(parsed) => ProviderBuilder::new().connect_http(parsed).erased(),
            Err(e) => {
                warn!(%url, error = %e, "skipping unparseable RPC url");
                continue;
            }
        };
        match provider.get_chain_id().await {
            Ok(id) if id == expected_chain_id => {}
            Ok(id) => {
                warn!(%url, got = id, want = expected_chain_id, "skipping RPC: chainId mismatch");
                continue;
            }
            Err(e) => {
                warn!(%url, error = %e, "skipping RPC: unreachable");
                continue;
            }
        }
        // `eth_chainId` and `eth_getLogs` working does NOT mean `eth_call` does.
        // Found the hard way while wiring H-4's second endpoints (2026-09-25):
        // a free `drpc` key rejects `eth_call` on its gas limit and `1rpc.io`
        // gates it behind a paid plan, while both answer `eth_chainId` happily.
        // Such an endpoint entering the pool breaks whatever read lands on it —
        // the startup `bridgeDomain()` read, or the H-2 scale cross-check — and
        // the loop retries for ever against an endpoint that will never answer.
        // So every endpoint must prove it can serve a real contract read before
        // it is trusted with one.
        if let Some(gate) = call_check {
            if let Err(e) = probe_gate_call(&provider, gate).await {
                warn!(%url, error = %e, "skipping RPC: cannot serve eth_call against the gate");
                continue;
            }
        }
        healthy.push(Endpoint { url, provider });
        if stop_at_first {
            return healthy;
        }
    }
    healthy
}

/// One real contract read — `Gate.bridgeDomain()` — to prove this endpoint serves
/// `eth_call`. The VALUE is not checked here (the scan loop reads it properly and
/// has to handle a gate that predates the field); only that a 32-byte word came
/// back, which no gas-limit refusal or paid-plan gate can fake.
async fn probe_gate_call(
    provider: &DynProvider,
    gate: alloy::primitives::Address,
) -> anyhow::Result<()> {
    use alloy::rpc::types::TransactionRequest;
    // keccak("bridgeDomain()")[..4]
    const BRIDGE_DOMAIN: [u8; 4] = [0x76, 0xae, 0x5b, 0xc8];
    let req = TransactionRequest::default()
        .to(gate)
        .input(alloy::primitives::Bytes::from_static(&BRIDGE_DOMAIN).into());
    let out = provider.call(req).await?;
    anyhow::ensure!(out.len() == 32, "bridgeDomain() returned {} bytes, want 32", out.len());
    Ok(())
}

// The window arithmetic now lives in `bridge_core::scan`: the indexer needs the
// identical rule (audit 2026-09-16, M-7) and two copies of it would drift the
// way the two mirrored `Submission` structs did.
pub use bridge_core::scan::clamp_scan_window;

impl Failover {
    /// Connect to every URL, keep only those whose `eth_chainId` matches
    /// `expected_chain_id`. Errors if none survive.
    pub async fn connect(urls: &[String], expected_chain_id: u64) -> anyhow::Result<Self> {
        Self::connect_for_gate(urls, expected_chain_id, None).await
    }

    /// [`Failover::connect`], additionally requiring every endpoint to serve an
    /// `eth_call` against `gate` (see [`probe_gate_call`]). Preferred wherever the
    /// caller will do contract reads through these endpoints, which the scan loop
    /// does at startup and on every H-2 cross-check.
    pub async fn connect_for_gate(
        urls: &[String],
        expected_chain_id: u64,
        gate: Option<alloy::primitives::Address>,
    ) -> anyhow::Result<Self> {
        let endpoints = probe(urls, expected_chain_id, false, gate).await;
        anyhow::ensure!(
            !endpoints.is_empty(),
            "no healthy RPC endpoints for chain {expected_chain_id}"
        );
        Ok(Self { endpoints, active: 0 })
    }

    /// The active endpoint, REDACTED (scheme + host). Safe to log.
    pub fn active_url(&self) -> &str {
        &self.endpoints[self.active].url
    }

    /// How many endpoints survived the startup chainId probe. Below 2 there is
    /// no second source, and [`Corroboration::Unavailable`] is the only possible
    /// verdict.
    pub fn endpoint_count(&self) -> usize {
        self.endpoints.len()
    }

    /// Rotate the endpoint order by `offset`, so that different validators do not
    /// all read from the same endpoint first (audit H-4).
    ///
    /// With every validator preferring endpoint A, a single dishonest A is seen
    /// by the whole fleet at once and the corroboration below is the only thing
    /// standing in the way. Staggering means A is the SERVING endpoint for some
    /// validators and the CHECKING endpoint for others, so the same lie has to
    /// survive being compared against itself from both sides.
    pub fn stagger(&mut self, offset: usize) {
        let n = self.endpoints.len();
        if n > 1 {
            self.endpoints.rotate_left(offset % n);
        }
    }

    /// Make endpoint `to` the serving one, because a MAJORITY of the endpoints
    /// consulted outvoted the one that served (audit round 6: H-4 incomplete).
    ///
    /// The previous rule demoted the serving endpoint on ANY disagreement and
    /// promoted `active + 1` — which is exactly the peer that had just disagreed,
    /// since that peer is always asked first. With two endpoints a lying peer got
    /// itself made the serving endpoint by lying once. Two endpoints that disagree
    /// say only that ONE of them is wrong, never which; so a 1-vs-1 split promotes
    /// nobody, and when a majority does exist [`tally`] names a member of it
    /// other than the first dissenter.
    fn promote(&mut self, to: usize, why: &str) {
        if to == self.active {
            return;
        }
        let from = self.endpoints[self.active].url.clone();
        self.active = to;
        warn!(
            %from,
            to = %self.endpoints[to].url,
            reason = why,
            "DEMOTING an RPC endpoint a majority of endpoints outvoted about chain contents \
             (not an error — a disagreement)"
        );
    }

    /// Run an async provider op across endpoints, rotating on failure and
    /// pinning `active` to the first that succeeds.
    async fn with_failover<T, F, Fut>(&mut self, what: &str, mut op: F) -> anyhow::Result<T>
    where
        F: FnMut(DynProvider) -> Fut,
        Fut: std::future::Future<Output = Result<T, alloy::transports::TransportError>>,
    {
        let n = self.endpoints.len();
        let mut last_err = None;
        for attempt in 0..n {
            let idx = (self.active + attempt) % n;
            let provider = self.endpoints[idx].provider.clone();
            match op(provider).await {
                Ok(v) => {
                    if idx != self.active {
                        warn!(from = %self.endpoints[self.active].url, to = %self.endpoints[idx].url, "RPC failover");
                        self.active = idx;
                    }
                    return Ok(v);
                }
                Err(e) => {
                    warn!(url = %self.endpoints[idx].url, op = what, error = %e, "RPC call failed; rotating");
                    last_err = Some(e);
                }
            }
        }
        Err(anyhow::anyhow!(
            "all {n} RPC endpoints failed for {what}: {}",
            last_err.map(|e| e.to_string()).unwrap_or_default()
        ))
    }

    /// A clone of the currently-active provider, for one-off contract reads that
    /// do not warrant a dedicated failover wrapper (e.g. the startup read of
    /// `Gate.bridgeDomain()`). Callers own the retry: this hands back whichever
    /// endpoint is active right now and does not rotate on failure.
    pub fn active_provider(&self) -> DynProvider {
        self.endpoints[self.active].provider.clone()
    }

    pub async fn get_block_number(&mut self) -> anyhow::Result<u64> {
        self.with_failover("get_block_number", |p| async move { p.get_block_number().await })
            .await
    }

    /// `eth_getLogs` for `[from_block, to_block]` from endpoint `idx` and nowhere
    /// else — no failover, because WHICH endpoint answered is the whole point of
    /// the check this serves.
    async fn logs_from(
        &self,
        idx: usize,
        filter: &Filter,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<Log>, alloy::transports::TransportError> {
        let f = filter.clone().from_block(from_block).to_block(to_block);
        self.endpoints[idx].provider.get_logs(&f).await
    }
}

impl Failover {
    /// `eth_getLogs` for a window, checked against at least one OTHER endpoint
    /// before anything in it may be signed (H-4).
    ///
    /// Returns `Ok(None)` when the serving endpoint has nothing confirmed at
    /// `from_block` — nothing was scanned, nothing may advance. Otherwise the
    /// logs, the last block the window covers, and the [`Corroboration`] verdict.
    /// The logs are meaningful only under `Agreed` (and `Unavailable`, which the
    /// caller's `[corroborate] require` policy decides); under any other verdict
    /// they must not be signed and the cursor must not move.
    ///
    /// ## Who decides where the window ends (audit round 6)
    ///
    /// The window used to end at the SERVING endpoint's head minus
    /// `confirmations`, and a peer whose own confirmed head fell short of it was
    /// "lagging" — an inconclusive window, not a disagreement. So a lying serving
    /// endpoint only had to report a head ahead of every honest peer: every
    /// window came back inconclusive, and after `INCONCLUSIVE_LIMIT` of them the
    /// scan loop signed whatever that endpoint served, with no second source.
    ///
    /// The window now ends at the LOWER of the serving head and the checking
    /// peer's head. Inflating one's own head no longer pushes the window past what
    /// an honest peer can check; to move it, both endpoints would have to lie,
    /// which is the two-source bar this check exists to set. A head that is too
    /// LOW on either side only shortens the window — a delay, never a signature.
    ///
    /// ## Who is believed when they disagree
    ///
    /// The first peer (in stagger order) is asked; if it agrees, that is the
    /// answer. If it does not, every other peer that has the window confirmed is
    /// asked too and the answers are [`tally`]ed: the serving endpoint's logs are
    /// signed only if a strict majority of the endpoints that answered returned
    /// exactly them. With two endpoints a disagreement is therefore always a
    /// withheld window, never a signature and never a promotion.
    pub async fn get_logs_corroborated(
        &mut self,
        filter: &Filter,
        from_block: u64,
        to_block: u64,
        confirmations: u64,
    ) -> anyhow::Result<Option<(Vec<Log>, u64, Corroboration)>> {
        let n = self.endpoints.len();
        // The serving endpoint's head. Failover here is on ERROR only, as ever.
        let serving_head = self.get_block_number().await?;
        let s = self.active;
        let Some(serving_to) = clamp_scan_window(from_block, to_block, serving_head, confirmations)
        else {
            return Ok(None);
        };

        if n < 2 {
            let logs = self.logs_from(s, filter, from_block, serving_to).await?;
            return Ok(Some((logs, serving_to, Corroboration::Unavailable)));
        }

        // Every peer's head, in stagger order.
        let mut why: Vec<String> = Vec::new();
        let mut peers: Vec<(usize, u64)> = Vec::new();
        for step in 1..n {
            let idx = (s + step) % n;
            match self.endpoints[idx].provider.get_block_number().await {
                Ok(head) => peers.push((idx, head)),
                Err(e) => why.push(format!("{}: head unreadable: {e}", self.endpoints[idx].url)),
            }
        }

        // The window end: bounded by the serving head AND by the first peer that
        // has anything at `from_block` confirmed. See the doc comment above.
        let peer_heads: Vec<u64> = peers.iter().map(|&(_, head)| head).collect();
        let Some(scanned_to) = corroborated_window_end(from_block, serving_to, &peer_heads, confirmations)
        else {
            for &(idx, head) in &peers {
                why.push(format!(
                    "{}: at block {head}, has nothing confirmed from {from_block}",
                    self.endpoints[idx].url
                ));
            }
            return Ok(Some((
                Vec::new(),
                serving_to,
                Corroboration::Inconclusive { reason: why.join("; ") },
            )));
        };

        let served = match self.logs_from(s, filter, from_block, scanned_to).await {
            Ok(logs) => logs,
            Err(e) => {
                // An ERROR, not a disagreement: rotate as failover always has.
                // Serving confers no trust any more — whoever serves still needs
                // a second endpoint's agreement — so this rotation cannot be used
                // to get a signature, only to change who is asked first.
                let url = self.endpoints[s].url.clone();
                self.active = (s + 1) % n;
                anyhow::bail!("get_logs from serving endpoint {url} failed: {e}");
            }
        };
        let served_keys = log_set(&served);

        let mut answers: Vec<(usize, Vec<Log>)> = Vec::new();
        for &(idx, head) in &peers {
            if head.saturating_sub(confirmations) < scanned_to {
                why.push(format!(
                    "{}: at block {head}, has not confirmed {scanned_to}",
                    self.endpoints[idx].url
                ));
                continue;
            }
            match self.logs_from(idx, filter, from_block, scanned_to).await {
                Ok(logs) => {
                    let agrees = log_set(&logs) == served_keys;
                    answers.push((idx, logs));
                    // The common case: the first peer agrees and nobody has
                    // dissented. A third call would buy nothing.
                    if agrees && answers.len() == 1 {
                        break;
                    }
                }
                Err(e) => why.push(format!("{}: get_logs failed: {e}", self.endpoints[idx].url)),
            }
        }

        let verdict = match tally(&served, &answers, from_block, scanned_to) {
            Tally::NoAnswer => Corroboration::Inconclusive { reason: why.join("; ") },
            Tally::Agreed { by, dissenters } => {
                if dissenters > 0 {
                    warn!(
                        served_by = %self.endpoints[s].url,
                        checked_by = %self.endpoints[by].url,
                        dissenters,
                        from_block,
                        scanned_to,
                        "a MAJORITY of RPC endpoints agree on this range but {dissenters} \
                         disagreed — one of them is wrong about the chain (audit H-4)"
                    );
                }
                Corroboration::Agreed { url: self.endpoints[by].url.clone() }
            }
            Tally::Disagreed { first_dissenter, promote, detail } => {
                let served_by = self.endpoints[s].url.clone();
                let checked_by = self.endpoints[first_dissenter].url.clone();
                if let Some(to) = promote {
                    self.promote(to, &detail);
                }
                Corroboration::Disagreed { served_by, checked_by, detail }
            }
        };
        Ok(Some((served, scanned_to, verdict)))
    }
}

/// Where a corroborated window ends: at `serving_to` (already clamped to the
/// serving endpoint's confirmed head), further clamped to the confirmed head of
/// the first peer that has anything at `from_block` confirmed. `None` when no
/// peer does. Pure, because it is the half of H-4 that decides whether a lying
/// head can push the window past what an honest peer can check.
pub fn corroborated_window_end(
    from_block: u64,
    serving_to: u64,
    peer_heads: &[u64],
    confirmations: u64,
) -> Option<u64> {
    peer_heads
        .iter()
        .find_map(|&head| clamp_scan_window(from_block, serving_to, head, confirmations))
}

/// The set of log identities in `logs`, orphaned logs excluded: the caller drops
/// them anyway, and two nodes differing on `removed` mid-reorg is lag, not
/// dishonesty.
fn log_set(logs: &[Log]) -> std::collections::BTreeSet<LogKey> {
    logs.iter().filter(|l| !l.removed).map(log_key).collect()
}

/// The outcome of counting endpoints' answers for one window. Indices are into
/// the endpoint list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tally {
    /// No peer answered.
    NoAnswer,
    /// A strict majority of the endpoints that answered — the serving one
    /// included — returned exactly the served logs. `by` is one agreeing peer.
    Agreed { by: usize, dissenters: usize },
    /// No majority for the served logs. `promote` is set only when a strict
    /// majority returned one OTHER identical set, and names a member of that
    /// majority other than `first_dissenter`.
    Disagreed { first_dissenter: usize, promote: Option<usize>, detail: String },
}

/// Count the answers to one window. Pure, because this is the security decision:
/// everything around it is plumbing that decides which endpoints to ask.
///
/// `served` counts as one vote. The served logs win only with a STRICT majority
/// of everyone who answered, so a single peer's agreement suffices when nobody
/// dissents, and a 1-vs-1 split — the only possible disagreement with two
/// endpoints — is a withheld window with nobody promoted.
pub fn tally(served: &[Log], answers: &[(usize, Vec<Log>)], from_block: u64, scanned_to: u64) -> Tally {
    if answers.is_empty() {
        return Tally::NoAnswer;
    }
    let mine = log_set(served);
    let sets: Vec<(usize, std::collections::BTreeSet<LogKey>)> =
        answers.iter().map(|(idx, logs)| (*idx, log_set(logs))).collect();
    let total = sets.len() + 1;
    let for_served = 1 + sets.iter().filter(|(_, s)| *s == mine).count();
    if for_served * 2 > total {
        let by = sets.iter().find(|(_, s)| *s == mine).map(|(i, _)| *i).expect("majority > 1");
        return Tally::Agreed { by, dissenters: total - for_served };
    }
    let (first_dissenter, theirs) = sets
        .iter()
        .find(|(_, s)| *s != mine)
        .map(|(i, s)| (*i, s))
        .expect("no majority for the served set implies a dissent");
    // A strict majority behind one other set? It has >= 2 members (total >= 2),
    // so one of them is not the first dissenter: promote that one, never the peer
    // whose disagreement opened the count.
    let promote = sets.iter().find_map(|(_, candidate)| {
        let backers: Vec<usize> =
            sets.iter().filter(|(_, s)| s == candidate).map(|(i, _)| *i).collect();
        (*candidate != mine && backers.len() * 2 > total)
            .then(|| backers.into_iter().find(|&i| i != first_dissenter))
            .flatten()
    });
    let fabricated = mine.difference(theirs).count();
    let withheld = theirs.difference(&mine).count();
    Tally::Disagreed {
        first_dissenter,
        promote,
        detail: format!(
            "blocks {from_block}..={scanned_to}: {fabricated} log(s) only the serving endpoint \
             returned, {withheld} only the peer returned; {for_served} of {total} endpoints \
             back the served set"
        ),
    }
}

#[cfg(test)]
mod h4_tests {
    use super::*;
    use alloy::primitives::{Address, Bytes, B256, U256};

    /// A `Sent`-shaped log at `(block, index)` carrying `id` as topic1.
    fn sent(block: u64, index: u64, id: u8) -> Log {
        let mut l = Log::default();
        l.inner.address = Address::repeat_byte(0xAA);
        l.inner.data = alloy::primitives::LogData::new_unchecked(
            vec![B256::repeat_byte(0xF4), B256::repeat_byte(id)],
            Bytes::from(U256::from(1_000_000u64).to_be_bytes::<32>().to_vec()),
        );
        l.block_number = Some(block);
        l.log_index = Some(index);
        l.transaction_hash = Some(B256::repeat_byte(id));
        l
    }

    /// Two endpoints: `a` serves (index 0), `b` checks (index 1).
    fn verdict(a: &[Log], b: &[Log]) -> Tally {
        tally(a, &[(1, b.to_vec())], 100, 200)
    }

    /// The honest case, which must not be noisy: same range, same logs.
    #[test]
    fn two_honest_endpoints_agree() {
        let logs = vec![sent(101, 0, 1), sent(150, 3, 2)];
        assert!(matches!(verdict(&logs, &logs), Tally::Agreed { .. }));
        // Order must not matter — nothing guarantees two nodes return logs in the
        // same order, and treating that as a disagreement would be a permanent
        // self-inflicted outage.
        let reordered = vec![logs[1].clone(), logs[0].clone()];
        assert!(matches!(verdict(&logs, &reordered), Tally::Agreed { .. }));
    }

    /// THE FINDING. One endpoint serves a `Sent` the chain never emitted; the
    /// validator would recompute its id, sign it, and the signature would be
    /// indistinguishable from an honest one at the destination.
    #[test]
    fn a_fabricated_log_is_caught() {
        let honest = vec![sent(101, 0, 1)];
        let forged = vec![sent(101, 0, 1), sent(102, 0, 0xEE)];
        match verdict(&forged, &honest) {
            Tally::Disagreed { detail, first_dissenter, promote } => {
                assert!(detail.contains("1 log(s) only the serving"), "{detail}");
                assert_eq!(first_dissenter, 1);
                assert_eq!(promote, None, "a 1-vs-1 split cannot say who lied");
            }
            v => panic!("a fabricated log must be refused, got {v:?}"),
        }
    }

    /// The other direction: an endpoint HIDING a real transfer. Not theft, but it
    /// strands the transfer and stalls the scanner on the next nonce, and only
    /// this check can name the cause.
    #[test]
    fn a_withheld_log_is_caught_too() {
        let honest = vec![sent(101, 0, 1), sent(102, 0, 2)];
        let censoring = vec![sent(101, 0, 1)];
        match verdict(&censoring, &honest) {
            Tally::Disagreed { detail, .. } => {
                assert!(detail.contains("1 only the peer returned"), "{detail}");
            }
            v => panic!("a withheld log must be refused, got {v:?}"),
        }
    }

    /// Same position, different contents — the subtlest forgery: a real event's
    /// slot with someone else's submissionId or amount in it.
    #[test]
    fn a_tampered_payload_at_a_real_position_is_caught() {
        let honest = vec![sent(101, 0, 1)];
        let mut tampered = sent(101, 0, 1);
        tampered.inner.data = alloy::primitives::LogData::new_unchecked(
            tampered.topics().to_vec(),
            Bytes::from(U256::from(999_999_999u64).to_be_bytes::<32>().to_vec()),
        );
        assert!(
            matches!(verdict(&[tampered], &honest), Tally::Disagreed { .. }),
            "a different amount at the same log position must be refused"
        );
        // And a different topic1 (the submissionId itself).
        assert!(
            matches!(verdict(&[sent(101, 0, 0x77)], &honest), Tally::Disagreed { .. }),
            "a different submissionId at the same position must be refused"
        );
    }

    /// An empty range is the common case and must corroborate, not stall.
    #[test]
    fn an_empty_window_agrees() {
        assert!(matches!(verdict(&[], &[]), Tally::Agreed { .. }));
    }

    /// A log one node has marked orphaned and the other has not is mid-reorg lag.
    /// The caller drops `removed` logs anyway, so this must not read as a lie.
    #[test]
    fn an_orphaned_log_is_not_a_disagreement() {
        let honest = vec![sent(101, 0, 1)];
        let mut with_orphan = honest.clone();
        let mut orphan = sent(102, 0, 9);
        orphan.removed = true;
        with_orphan.push(orphan);
        assert!(matches!(verdict(&with_orphan, &honest), Tally::Agreed { .. }));
    }
}

/// Audit round 6: the two ways one endpoint could still get a forged `Sent`
/// signed after the first H-4 fix, pinned as tests.
#[cfg(test)]
mod round6_tests {
    use super::*;
    use alloy::primitives::{Address, Bytes, B256, U256};

    fn sent(block: u64, index: u64, id: u8) -> Log {
        let mut l = Log::default();
        l.inner.address = Address::repeat_byte(0xAA);
        l.inner.data = alloy::primitives::LogData::new_unchecked(
            vec![B256::repeat_byte(0xF4), B256::repeat_byte(id)],
            Bytes::from(U256::from(1_000_000u64).to_be_bytes::<32>().to_vec()),
        );
        l.block_number = Some(block);
        l.log_index = Some(index);
        l.transaction_hash = Some(B256::repeat_byte(id));
        l
    }

    /// Finding 1, the pure half. A serving endpoint reporting a head far past
    /// the real tip no longer pushes the window beyond what the peer confirms —
    /// which is what made every window "inconclusive" and let the scan loop
    /// fall back to signing single-source.
    #[test]
    fn an_inflated_serving_head_is_bounded_by_the_peer() {
        // Serving claims head 1_000_000 (so serving_to is the requested 5_000);
        // the honest peer is at 200 with 10 confirmations.
        assert_eq!(corroborated_window_end(100, 5_000, &[200], 10), Some(190));
        // A peer with nothing confirmed yet is skipped, not trusted.
        assert_eq!(corroborated_window_end(100, 5_000, &[50, 200], 10), Some(190));
        assert_eq!(corroborated_window_end(100, 5_000, &[50], 10), None);
        // A peer AHEAD of the serving endpoint cannot extend the window either.
        assert_eq!(corroborated_window_end(100, 150, &[9_999], 10), Some(150));
    }

    /// Finding 2. With two endpoints a disagreement cannot say who lied, so it
    /// must promote nobody — the old rule promoted the dissenting peer.
    #[test]
    fn a_one_vs_one_split_promotes_nobody() {
        let honest = vec![sent(101, 0, 1)];
        let forged = vec![sent(101, 0, 1), sent(102, 0, 0xEE)];
        for (served, peer) in [(&honest, &forged), (&forged, &honest)] {
            match tally(served, &[(1, peer.clone())], 100, 200) {
                Tally::Disagreed { promote: None, first_dissenter: 1, .. } => {}
                t => panic!("a 1-vs-1 split must withhold and promote nobody, got {t:?}"),
            }
        }
    }

    /// Three endpoints, the serving one lying: both peers outvote it, and the one
    /// promoted is the SECOND peer, never the one whose dissent opened the count.
    #[test]
    fn a_lying_server_is_outvoted_and_the_first_dissenter_is_not_promoted() {
        let honest = vec![sent(101, 0, 1)];
        let forged = vec![sent(101, 0, 1), sent(102, 0, 0xEE)];
        match tally(&forged, &[(1, honest.clone()), (2, honest.clone())], 100, 200) {
            Tally::Disagreed { first_dissenter: 1, promote: Some(2), detail } => {
                assert!(detail.contains("1 of 3 endpoints back the served set"), "{detail}");
            }
            t => panic!("{t:?}"),
        }
    }

    /// Three endpoints, one lying PEER: the serving endpoint and the other peer
    /// are a majority, so the window is signed and nobody is demoted.
    #[test]
    fn a_lying_peer_is_outvoted() {
        let honest = vec![sent(101, 0, 1)];
        let forged = vec![sent(101, 0, 1), sent(102, 0, 0xEE)];
        assert_eq!(
            tally(&honest, &[(1, forged), (2, honest.clone())], 100, 200),
            Tally::Agreed { by: 2, dissenters: 1 }
        );
    }

    /// No majority for anything: withhold, promote nobody.
    #[test]
    fn three_different_answers_promote_nobody() {
        let a = vec![sent(101, 0, 1)];
        let b = vec![sent(101, 0, 2)];
        let c = vec![sent(101, 0, 3)];
        assert!(matches!(
            tally(&a, &[(1, b), (2, c)], 100, 200),
            Tally::Disagreed { promote: None, .. }
        ));
    }

    /// Two against two is not a majority for the served set.
    #[test]
    fn a_tie_is_not_agreement() {
        let honest = vec![sent(101, 0, 1)];
        let forged = vec![sent(102, 0, 0xEE)];
        assert!(matches!(
            tally(&forged, &[(1, honest.clone()), (2, forged.clone()), (3, honest)], 100, 200),
            Tally::Disagreed { promote: None, .. }
        ));
    }

    #[test]
    fn no_answer_is_not_agreement() {
        assert_eq!(tally(&[sent(101, 0, 1)], &[], 100, 200), Tally::NoAnswer);
    }

    /// The emitting address is part of a log's identity now.
    #[test]
    fn a_different_emitter_is_a_disagreement() {
        let honest = vec![sent(101, 0, 1)];
        let mut elsewhere = sent(101, 0, 1);
        elsewhere.inner.address = Address::repeat_byte(0xBB);
        assert!(matches!(
            tally(&[elsewhere], &[(1, honest)], 100, 200),
            Tally::Disagreed { .. }
        ));
    }

    // ---- end to end, against two stub JSON-RPC endpoints -------------------

    /// A JSON-RPC endpoint that reports `head` and serves `logs` for any range.
    async fn stub(head: u64, logs: serde_json::Value) -> String {
        use axum::{routing::post, Json, Router};
        let app = Router::new().route(
            "/",
            post(move |Json(req): Json<serde_json::Value>| {
                let logs = logs.clone();
                async move {
                    let result = match req["method"].as_str() {
                        Some("eth_blockNumber") => serde_json::json!(format!("{head:#x}")),
                        Some("eth_getLogs") => logs,
                        m => panic!("stub RPC: unexpected method {m:?}"),
                    };
                    Json(serde_json::json!({ "jsonrpc": "2.0", "id": req["id"], "result": result }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}/")
    }

    fn rpc_log(block: u64, id: u8) -> serde_json::Value {
        serde_json::json!({
            "address": format!("{:#x}", Address::repeat_byte(0xAA)),
            "topics": [format!("{:#x}", B256::repeat_byte(0xF4)), format!("{:#x}", B256::repeat_byte(id))],
            "data": "0x",
            "blockNumber": format!("{block:#x}"),
            "blockHash": format!("{:#x}", B256::repeat_byte(0x01)),
            "transactionHash": format!("{:#x}", B256::repeat_byte(id)),
            "transactionIndex": "0x0",
            "logIndex": "0x0",
            "removed": false
        })
    }

    fn pool(urls: &[String]) -> Failover {
        Failover {
            endpoints: urls
                .iter()
                .map(|u| Endpoint {
                    url: u.clone(),
                    provider: ProviderBuilder::new().connect_http(u.parse().unwrap()).erased(),
                })
                .collect(),
            active: 0,
        }
    }

    /// Finding 1, end to end. The serving endpoint claims a head far past the
    /// real tip and serves a forged `Sent`. Before the fix the honest peer could
    /// never "confirm" that range, every window was inconclusive, and the scan
    /// loop signed the forgery after ten of them. Now the window ends where the
    /// peer can check it, and the forgery is a disagreement.
    #[tokio::test]
    async fn an_inflated_head_cannot_make_a_forgery_inconclusive() {
        let liar = stub(1_000_000, serde_json::json!([rpc_log(150, 0xEE)])).await;
        let honest = stub(200, serde_json::json!([])).await;
        let mut f = pool(&[liar.clone(), honest]);
        let filter = Filter::new();
        let (_, scanned_to, verdict) =
            f.get_logs_corroborated(&filter, 100, 5_000, 10).await.unwrap().unwrap();
        assert_eq!(scanned_to, 190, "the window must end at the PEER's confirmed head");
        assert!(matches!(verdict, Corroboration::Disagreed { .. }), "got {verdict:?}");
        assert_eq!(f.active_url(), liar, "1-vs-1: nobody is promoted");
    }

    /// Finding 2, end to end. A lying peer disagrees with an honest serving
    /// endpoint. It used to be promoted to serving endpoint on the spot.
    #[tokio::test]
    async fn a_lying_peer_is_not_promoted() {
        let honest = stub(200, serde_json::json!([])).await;
        let liar = stub(200, serde_json::json!([rpc_log(150, 0xEE)])).await;
        let mut f = pool(&[honest.clone(), liar]);
        let (_, _, verdict) =
            f.get_logs_corroborated(&Filter::new(), 100, 5_000, 10).await.unwrap().unwrap();
        assert!(matches!(verdict, Corroboration::Disagreed { .. }), "got {verdict:?}");
        assert_eq!(f.active_url(), honest, "the dissenting peer must not become the server");
    }

    /// And the honest case still agrees, over the same bounded window.
    #[tokio::test]
    async fn two_honest_endpoints_still_agree() {
        let a = stub(200, serde_json::json!([rpc_log(150, 1)])).await;
        let b = stub(210, serde_json::json!([rpc_log(150, 1)])).await;
        let mut f = pool(&[a, b]);
        let (logs, scanned_to, verdict) =
            f.get_logs_corroborated(&Filter::new(), 100, 5_000, 10).await.unwrap().unwrap();
        assert!(matches!(verdict, Corroboration::Agreed { .. }), "got {verdict:?}");
        assert_eq!(scanned_to, 190);
        assert_eq!(logs.len(), 1);
    }
}

#[cfg(test)]
mod stagger_tests {
    /// The ordering `Failover::stagger` produces, isolated from the endpoints it
    /// would rotate. H-4 asks that validators not all prefer the same endpoint.
    fn preferred(n: usize, last_byte: u8) -> usize {
        // Mirrors `stagger` + `active == 0`: rotate_left(k) puts index k first.
        (last_byte as usize) % n
    }

    #[test]
    fn validators_differ_when_there_are_three_endpoints() {
        // The two live mesh10 validators, by the last byte of their addresses.
        let (val1, val2) = (0xAAu8, 0xB8u8);
        assert_ne!(preferred(3, val1), preferred(3, val2), "3 endpoints: must differ");
    }

    /// The honest limit, recorded so nobody reads more into the stagger than it
    /// gives: with TWO endpoints two validators align whenever their offsets have
    /// the same parity, which is half the time and is the case on mesh10 today.
    /// Staggering cannot fix that — only a third endpoint can.
    #[test]
    fn two_endpoints_can_still_align_and_that_is_inherent() {
        let (val1, val2) = (0xAAu8, 0xB8u8);
        assert_eq!(
            preferred(2, val1),
            preferred(2, val2),
            "both even: they align, and no offset scheme avoids it at n=2"
        );
    }
}
