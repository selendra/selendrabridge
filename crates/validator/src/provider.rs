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
//! it is genuine. The refund path already second-sources (`refund.rs` reads
//! `sentBy` on chain before attesting); the transfer path did not.
//!
//! So [`Failover::get_logs_corroborated`] fetches the window from the active
//! endpoint and then asks a DIFFERENT endpoint for the same explicit range, and
//! the two log sets must match exactly. See [`Corroboration`] for why this is
//! `eth_getLogs` and not a `sentBy` read.

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
    /// A second endpoint returned exactly the same logs for the same range.
    Agreed { url: String },
    /// The two endpoints disagree. One of them is wrong about what the chain
    /// emitted; nothing in this window may be signed, and the endpoint that
    /// served it has been demoted.
    Disagreed { served_by: String, checked_by: String, detail: String },
    /// No second opinion was obtainable — the peer lags this range, or erred.
    /// NOT the same as agreement: the caller must not advance on it.
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
type LogKey = (u64, u64, Option<alloy::primitives::B256>, Vec<alloy::primitives::B256>, Vec<u8>);

fn log_key(l: &Log) -> LogKey {
    (
        l.block_number.unwrap_or_default(),
        l.log_index.unwrap_or_default(),
        l.transaction_hash,
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

    /// Move off the active endpoint after it DISAGREED (not merely errored).
    ///
    /// The audit is explicit that rotating only on error is half a defence: an
    /// endpoint that answers every call promptly and wrongly is never demoted by
    /// failover, which is exactly the endpoint that matters.
    fn demote_active(&mut self, why: &str) {
        if self.endpoints.len() < 2 {
            return;
        }
        let from = self.endpoints[self.active].url.clone();
        self.active = (self.active + 1) % self.endpoints.len();
        warn!(
            %from,
            to = %self.endpoints[self.active].url,
            reason = why,
            "DEMOTING an RPC endpoint that disagreed about chain contents (not an error — a disagreement)"
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

    /// `eth_getLogs` for `[from_block, to_block]`, with the window clamped to the
    /// head reported by the SAME endpoint that serves the logs. There is
    /// deliberately no unbounded `get_logs` here any more: the scan loop must not
    /// be able to pair a head from one endpoint with logs from another.
    ///
    /// ## Why (audit 2026-09-09, "failover can advance the cursor past unscanned blocks")
    ///
    /// The scan loop reads `latest` once, computes `to_block` from it, then calls
    /// `get_logs`. Those are two separate failover calls: `latest` may have come
    /// from endpoint A and, after a rotation, the logs from endpoint B. If B lags
    /// A — a different node behind the same load balancer, a replica still
    /// syncing — B simply returns no logs for blocks it has not seen yet, the
    /// call succeeds, and the loop persists `last_block = to_block`. Every `Sent`
    /// in the gap is skipped for good (and the nonce gap then pauses the
    /// validator on the NEXT event, blaming a missed nonce the RPC caused).
    ///
    /// So both reads happen against one provider inside one failover attempt:
    /// ask THIS endpoint for its head, clamp the window to its own confirmed
    /// depth, and only then fetch logs. The caller advances the cursor to the
    /// returned `scanned_to`, never to the `to_block` it asked for. If this
    /// endpoint has nothing confirmed at `from_block` yet, `Ok(None)`: nothing was
    /// scanned, nothing may advance.
    ///
    /// This costs one `eth_blockNumber` per window on top of the `eth_getLogs`
    /// (a cheap call, and the price of the two being coherent); the scan loop's
    /// cached-head optimisation still bounds the REQUESTED window, so catch-up
    /// throughput is otherwise unchanged.
    ///
    /// `filter` must carry the address/topic selection only; the block range is
    /// set here.
    pub async fn get_logs_confirmed(
        &mut self,
        filter: &Filter,
        from_block: u64,
        to_block: u64,
        confirmations: u64,
    ) -> anyhow::Result<Option<(Vec<Log>, u64)>> {
        let filter = filter.clone();
        self.with_failover("get_logs_confirmed", move |p| {
            let filter = filter.clone();
            async move {
                let head = p.get_block_number().await?;
                let Some(scanned_to) = clamp_scan_window(from_block, to_block, head, confirmations) else {
                    return Ok(None);
                };
                let f = filter.from_block(from_block).to_block(scanned_to);
                let logs = p.get_logs(&f).await?;
                Ok(Some((logs, scanned_to)))
            }
        })
        .await
    }
}

impl Failover {
    /// [`Failover::get_logs_confirmed`], then a SECOND opinion on the same range
    /// from a different endpoint (H-4).
    ///
    /// Returns `Ok(None)` for the same reason `get_logs_confirmed` does — the
    /// serving endpoint has nothing confirmed at `from_block` — and otherwise the
    /// logs, the block actually scanned, and the [`Corroboration`] verdict. The
    /// verdict is returned rather than enforced here: whether an unavailable
    /// second source is fatal is an operator policy (`[corroborate] require`), and
    /// this module has no business deciding it.
    ///
    /// Cost is one extra `eth_getLogs` per window, only when a second endpoint
    /// exists. The check runs over the range the FIRST endpoint actually served,
    /// so the two calls cannot be talking about different windows.
    pub async fn get_logs_corroborated(
        &mut self,
        filter: &Filter,
        from_block: u64,
        to_block: u64,
        confirmations: u64,
    ) -> anyhow::Result<Option<(Vec<Log>, u64, Corroboration)>> {
        let Some((logs, scanned_to)) =
            self.get_logs_confirmed(filter, from_block, to_block, confirmations).await?
        else {
            return Ok(None);
        };
        let verdict = self.second_opinion(filter, from_block, scanned_to, confirmations, &logs).await;
        if let Corroboration::Disagreed { ref detail, .. } = verdict {
            // Demote BEFORE returning, so the next tick reads from someone else
            // even though the caller is about to discard this window.
            self.demote_active(detail);
        }
        Ok(Some((logs, scanned_to, verdict)))
    }

    /// Ask endpoints other than the active one for `[from_block, scanned_to]` and
    /// compare the log sets, taking the FIRST definitive answer.
    ///
    /// Every other endpoint is tried, not just one, because a single unusable peer
    /// would otherwise make this check permanently inconclusive — and an
    /// inconclusive window does not advance the cursor, so one misconfigured peer
    /// would silently stop the validator. Public endpoints make that concrete: at
    /// the time of writing `1rpc.io` caps `eth_getLogs` at 50 blocks and a free
    /// `drpc` key at 10,000, so a peer can be healthy, honest, on the right chain,
    /// and still unable to answer the question being asked.
    async fn second_opinion(
        &self,
        filter: &Filter,
        from_block: u64,
        scanned_to: u64,
        confirmations: u64,
        served: &[Log],
    ) -> Corroboration {
        let n = self.endpoints.len();
        if n < 2 {
            return Corroboration::Unavailable;
        }
        let mut why: Vec<String> = Vec::new();
        for step in 1..n {
            let peer = &self.endpoints[(self.active + step) % n];
            // The peer must actually have this range confirmed. A lagging peer is
            // the single most likely cause of a mismatch and is NOT dishonesty, so
            // it must never be reported as one — that is the failure mode that
            // would turn this check into a self-inflicted outage.
            match peer.provider.get_block_number().await {
                Ok(head) if head.saturating_sub(confirmations) >= scanned_to => {}
                Ok(head) => {
                    why.push(format!("{}: at block {head}, has not confirmed {scanned_to}", peer.url));
                    continue;
                }
                Err(e) => {
                    why.push(format!("{}: head unreadable: {e}", peer.url));
                    continue;
                }
            }
            let f = filter.clone().from_block(from_block).to_block(scanned_to);
            match peer.provider.get_logs(&f).await {
                Ok(peer_logs) => {
                    return compare_log_sets(
                        served,
                        &peer_logs,
                        from_block,
                        scanned_to,
                        &self.endpoints[self.active].url,
                        &peer.url,
                    )
                }
                Err(e) => why.push(format!("{}: get_logs failed: {e}", peer.url)),
            }
        }
        Corroboration::Inconclusive { reason: why.join("; ") }
    }
}

/// The H-4 verdict for two endpoints' answers to the same `eth_getLogs` range.
///
/// Pure, because this is the security decision and it must be testable without a
/// chain: everything above it is plumbing that decides WHICH endpoints to ask.
pub fn compare_log_sets(
    served: &[Log],
    peer: &[Log],
    from_block: u64,
    scanned_to: u64,
    served_by: &str,
    checked_by: &str,
) -> Corroboration {
    use std::collections::BTreeSet;
    // Orphaned logs are excluded on both sides: the caller drops them anyway, and
    // two nodes differing on `removed` mid-reorg is lag, not dishonesty.
    let mine: BTreeSet<LogKey> = served.iter().filter(|l| !l.removed).map(log_key).collect();
    let theirs: BTreeSet<LogKey> = peer.iter().filter(|l| !l.removed).map(log_key).collect();
    if mine == theirs {
        return Corroboration::Agreed { url: checked_by.to_string() };
    }
    // Both directions matter. An extra log on the serving side is the forgery this
    // check exists for. A MISSING one means the serving endpoint is hiding real
    // transfers — which strands them and, because nonces must be sequential,
    // stalls the scanner on the next one regardless. Censorship rather than theft,
    // but still an endpoint lying about the chain, and the operator needs to know.
    let fabricated = mine.difference(&theirs).count();
    let withheld = theirs.difference(&mine).count();
    Corroboration::Disagreed {
        served_by: served_by.to_string(),
        checked_by: checked_by.to_string(),
        detail: format!(
            "blocks {from_block}..={scanned_to}: {fabricated} log(s) only the serving \
             endpoint returned, {withheld} only the peer returned"
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

    fn verdict(a: &[Log], b: &[Log]) -> Corroboration {
        compare_log_sets(a, b, 100, 200, "https://a.example", "https://b.example")
    }

    /// The honest case, which must not be noisy: same range, same logs.
    #[test]
    fn two_honest_endpoints_agree() {
        let logs = vec![sent(101, 0, 1), sent(150, 3, 2)];
        assert!(matches!(verdict(&logs, &logs), Corroboration::Agreed { .. }));
        // Order must not matter — nothing guarantees two nodes return logs in the
        // same order, and treating that as a disagreement would be a permanent
        // self-inflicted outage.
        let reordered = vec![logs[1].clone(), logs[0].clone()];
        assert!(matches!(verdict(&logs, &reordered), Corroboration::Agreed { .. }));
    }

    /// THE FINDING. One endpoint serves a `Sent` the chain never emitted; the
    /// validator would recompute its id, sign it, and the signature would be
    /// indistinguishable from an honest one at the destination.
    #[test]
    fn a_fabricated_log_is_caught() {
        let honest = vec![sent(101, 0, 1)];
        let forged = vec![sent(101, 0, 1), sent(102, 0, 0xEE)];
        match verdict(&forged, &honest) {
            Corroboration::Disagreed { detail, served_by, checked_by } => {
                assert!(detail.contains("1 log(s) only the serving"), "{detail}");
                assert_eq!(served_by, "https://a.example");
                assert_eq!(checked_by, "https://b.example");
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
            Corroboration::Disagreed { detail, .. } => {
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
            matches!(verdict(&[tampered], &honest), Corroboration::Disagreed { .. }),
            "a different amount at the same log position must be refused"
        );
        // And a different topic1 (the submissionId itself).
        assert!(
            matches!(verdict(&[sent(101, 0, 0x77)], &honest), Corroboration::Disagreed { .. }),
            "a different submissionId at the same position must be refused"
        );
    }

    /// An empty range is the common case and must corroborate, not stall.
    #[test]
    fn an_empty_window_agrees() {
        assert!(matches!(verdict(&[], &[]), Corroboration::Agreed { .. }));
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
        assert!(matches!(verdict(&with_orphan, &honest), Corroboration::Agreed { .. }));
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
