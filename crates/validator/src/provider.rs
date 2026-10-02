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
    /// Every endpoint's head at the last [`Failover::scan_head`], for the idle
    /// warning (M7-8): (redacted url, head or the error).
    last_heads: Vec<(String, Result<u64, String>)>,
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

/// Every endpoint that answers AND reports `expected_chain_id`, in the order
/// given, each with its REDACTED url (safe to log). Errors if none survive.
///
/// For callers that must cross-check one read across endpoints rather than use
/// whichever answers first — the refund loop, whose `executed`/`cancelled` reads
/// decide whether a transfer may be paid back (audit round 6), and the H-2
/// scale-peer reads (audit round 6, LOW; they used a first-healthy-only
/// `connect_checked`, now removed).
pub async fn connect_all_checked(
    urls: &[String],
    expected_chain_id: u64,
) -> anyhow::Result<Vec<(String, DynProvider)>> {
    let healthy = probe(urls, expected_chain_id, false, None).await;
    anyhow::ensure!(!healthy.is_empty(), "no healthy RPC endpoints for chain {expected_chain_id}");
    Ok(healthy.into_iter().map(|e| (e.url, e.provider)).collect())
}

/// How many endpoints must return the same answer for a cross-checked read: 2
/// whenever the chain is configured with a second endpoint (or `[corroborate]
/// require = true` is passed as `require`), 1 only for a deliberately
/// single-endpoint chain. One rule for the refund reads, the startup
/// `Gate.bridgeDomain()` read and the H-2 scale-peer reads (audit round 6, LOW).
pub fn min_agree(configured: usize, require: bool) -> usize {
    if configured >= 2 || require {
        2
    } else {
        1
    }
}

/// Why [`majority`] refused.
#[derive(Debug, PartialEq, Eq)]
pub struct NoMajority {
    pub reason: String,
    /// Endpoints ANSWERED and differed — as opposed to too few answering.
    pub disagreement: bool,
}

/// The answer at least `min_agree` endpoints returned, provided they are also a
/// STRICT majority of every endpoint that answered. Pure: this is the security
/// decision of every cross-checked point read (refund, bridgeDomain, scale).
///
/// With two endpoints that means both, identically. With three, two of them —
/// so one lying endpoint can neither forge an answer nor, by dissenting, stall
/// the read.
///
/// Moved here from `refund.rs` (audit round 6, LOW) so the startup reads that
/// used to be single-source apply the SAME rule rather than a second copy of it.
pub fn majority<T: PartialEq + Clone + std::fmt::Debug>(
    answers: &[(&str, T)],
    min_agree: usize,
) -> Result<T, NoMajority> {
    if answers.len() < min_agree {
        return Err(NoMajority {
            reason: format!("only {} endpoint(s) answered; need {min_agree}", answers.len()),
            disagreement: false,
        });
    }
    for (_, candidate) in answers {
        let backers = answers.iter().filter(|(_, v)| v == candidate).count();
        if backers >= min_agree && backers * 2 > answers.len() {
            return Ok(candidate.clone());
        }
    }
    Err(NoMajority {
        reason: format!("no {min_agree} endpoints agree, as a majority, among {answers:?}"),
        disagreement: true,
    })
}

/// The largest value that a STRICT MAJORITY of `values` are at or above — the
/// `(n/2 + 1)`-th largest. `None` only for an empty slice.
///
/// Used where a value is safe in one direction only (L7-12, M7-8): a minority
/// can neither raise the result above what a majority reported nor drag it
/// down. For one value it is that value; for two, the smaller (both must
/// vouch); for three, the median.
pub fn majority_floor<T: Ord + Copy>(values: &[T]) -> Option<T> {
    if values.is_empty() {
        return None;
    }
    let mut v = values.to_vec();
    v.sort_unstable_by(|a, b| b.cmp(a));
    Some(v[values.len() / 2])
}

/// How far (in blocks) the serving endpoint's head may trail the majority head
/// before [`Failover::scan_head`] stops asking it first (audit round 7, M7-8).
/// Generous on purpose: heads are read one after another, so honest endpoints
/// differ by a few blocks on a fast chain, and flapping between them would only
/// make the logs noisier. A stuck endpoint trails by far more.
pub const HEAD_LAG_ROTATE: u64 = 64;

/// Ask every endpoint the same question, sequentially. Returns the answers (by
/// redacted url) and the failures, for [`majority`] and the caller's log line.
pub async fn ask_all<T, F, Fut>(endpoints: &[(String, DynProvider)], read: F) -> (Vec<(String, T)>, Vec<String>)
where
    F: Fn(DynProvider) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    let mut answers = Vec::new();
    let mut failed = Vec::new();
    for (url, p) in endpoints {
        match read(p.clone()).await {
            Ok(v) => answers.push((url.clone(), v)),
            Err(e) => failed.push(format!("{url}: {e}")),
        }
    }
    (answers, failed)
}

/// [`ask_all`] then [`majority`]: `Ok` only on an agreed answer. On refusal the
/// error names what was read and every endpoint that failed; a DISAGREEMENT (as
/// opposed to too few answers) is also reported through `on_disagree` with the
/// answers, so each caller can log it loudly in its own terms.
pub async fn read_agreed<T, F, Fut>(
    endpoints: &[(String, DynProvider)],
    min_agree: usize,
    what: &str,
    read: F,
    on_disagree: impl FnOnce(&[(&str, T)]),
) -> anyhow::Result<T>
where
    T: PartialEq + Clone + std::fmt::Debug,
    F: Fn(DynProvider) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    let (answers, failed) = ask_all(endpoints, read).await;
    let answers: Vec<(&str, T)> = answers.iter().map(|(u, v)| (u.as_str(), v.clone())).collect();
    majority(&answers, min_agree).map_err(|e| {
        if e.disagreement {
            on_disagree(&answers);
        }
        anyhow::anyhow!(
            "{what}: {}{}",
            e.reason,
            if failed.is_empty() { String::new() } else { format!(" (failed: {})", failed.join("; ")) }
        )
    })
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
        Ok(Self { endpoints, active: 0, last_heads: Vec::new() })
    }

    /// Every endpoint's head at the last [`Failover::scan_head`], one line, for
    /// a log message. Urls are redacted.
    pub fn heads_summary(&self) -> String {
        if self.last_heads.is_empty() {
            return "no head read yet".into();
        }
        self.last_heads
            .iter()
            .map(|(u, h)| match h {
                Ok(h) => format!("{u}={h}"),
                Err(e) => format!("{u}=ERR({e})"),
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// The chain head the scan loop should work towards (audit round 7, M7-8).
    ///
    /// It used to be the ACTIVE endpoint's head alone. Failover rotates on
    /// ERROR, and a stuck or lagging endpoint answers happily with an old
    /// number — so the loop saw `confirmed < from_block`, slept, and asked the
    /// same endpoint again, for ever, without a word. With three endpoints each
    /// stuck one silently stopped about a third of the fleet.
    ///
    /// Now every endpoint is asked, and the head is the one a STRICT MAJORITY of
    /// those that answered has reached ([`majority_floor`]): a stuck endpoint
    /// cannot drag it down and an inflated one cannot push it up. When the
    /// active endpoint trails that head by more than [`HEAD_LAG_ROTATE`] (or
    /// cannot answer), the first endpoint in stagger order that HAS reached it
    /// becomes the serving one.
    ///
    /// This changes WHO IS ASKED FIRST, never what may be signed: serving confers
    /// no trust ([`Failover::get_logs_corroborated`] still bounds every window by
    /// a checking peer's head and needs a majority to agree on its logs), and the
    /// head only decides how far the next window may reach. With two endpoints
    /// the head is the lower of the two, as before — one stuck endpoint of two
    /// leaves nothing to corroborate against, which the scan loop's idle warning
    /// now reports instead of staying silent.
    pub async fn scan_head(&mut self) -> anyhow::Result<u64> {
        let n = self.endpoints.len();
        let mut heads: Vec<(usize, u64)> = Vec::new();
        let mut report = Vec::with_capacity(n);
        for (idx, ep) in self.endpoints.iter().enumerate() {
            match ep.provider.get_block_number().await {
                Ok(h) => {
                    heads.push((idx, h));
                    report.push((ep.url.clone(), Ok(h)));
                }
                Err(e) => report.push((ep.url.clone(), Err(e.to_string()))),
            }
        }
        self.last_heads = report;
        let values: Vec<u64> = heads.iter().map(|&(_, h)| h).collect();
        let Some(head) = majority_floor(&values) else {
            anyhow::bail!("all {n} RPC endpoints failed to report a head: {}", self.heads_summary());
        };
        let active_head = heads.iter().find(|&&(i, _)| i == self.active).map(|&(_, h)| h);
        if active_head.is_none_or(|h| h.saturating_add(HEAD_LAG_ROTATE) < head) {
            let to = (1..n)
                .map(|k| (self.active + k) % n)
                .find(|i| heads.iter().any(|&(j, h)| j == *i && h >= head));
            if let Some(to) = to {
                warn!(
                    from = %self.endpoints[self.active].url,
                    to = %self.endpoints[to].url,
                    active_head = ?active_head,
                    majority_head = head,
                    heads = %self.heads_summary(),
                    "serving RPC endpoint TRAILS the head a majority of endpoints report \
                     (stuck or lagging) — asking another first (audit round 7, M7-8)"
                );
                self.active = to;
            }
        }
        Ok(head)
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

    /// Every endpoint in the pool, (redacted url, provider), for one-off point
    /// reads that must be cross-checked with [`read_agreed`] rather than taken
    /// from whichever endpoint is active — e.g. the startup read of
    /// `Gate.bridgeDomain()` (audit round 6, LOW: it used to be single-source).
    pub fn all_providers(&self) -> Vec<(String, DynProvider)> {
        self.endpoints.iter().map(|e| (e.url.clone(), e.provider.clone())).collect()
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
        // M7-9 (audit round 7): a node never returns two logs at one (block,
        // logIndex). A served list that does is malformed on its face — no peer
        // need be asked — and processing it would replay the second copy into
        // the nonce check, which reads it as DUPLICATED_NONCE and pauses the
        // scanner persistently. Withhold the window and stop asking this
        // endpoint first: unlike a 1-vs-1 split, this is evidence about the
        // serving endpoint itself, and serving confers no trust on whoever is
        // asked next (they still need a majority to agree with them).
        let dups = duplicate_positions(&served);
        if dups > 0 {
            let served_by = self.endpoints[s].url.clone();
            self.active = (s + 1) % n;
            warn!(
                from = %served_by,
                to = %self.endpoints[self.active].url,
                duplicates = dups,
                "serving RPC returned the SAME log position more than once — withholding the \
                 window and asking another endpoint first (audit round 7, M7-9)"
            );
            return Ok(Some((
                served,
                scanned_to,
                Corroboration::Disagreed {
                    checked_by: served_by.clone(),
                    served_by,
                    detail: format!(
                        "blocks {from_block}..={scanned_to}: the serving endpoint returned {dups} \
                         log(s) at a (block, logIndex) it had already returned"
                    ),
                },
            )));
        }
        let served_keys = log_bag(&served);

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
                    let agrees = log_bag(&logs) == served_keys;
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

/// The MULTISET of log identities in `logs` (identity -> how many times it was
/// returned), orphaned logs excluded: the caller drops them anyway, and two
/// nodes differing on `removed` mid-reorg is lag, not dishonesty.
///
/// A multiset, not a set (audit round 7, M7-9): with a set, an endpoint that
/// returned a genuine log TWICE compared equal to its honest peers, the window
/// was Agreed, and the second copy then paused the scanner on DUPLICATED_NONCE.
type LogBag = std::collections::BTreeMap<LogKey, usize>;

fn log_bag(logs: &[Log]) -> LogBag {
    let mut bag = LogBag::new();
    for l in logs.iter().filter(|l| !l.removed) {
        *bag.entry(log_key(l)).or_default() += 1;
    }
    bag
}

/// How many entries of `a` (counted with multiplicity) `b` lacks.
fn bag_excess(a: &LogBag, b: &LogBag) -> usize {
    a.iter().map(|(k, &n)| n.saturating_sub(b.get(k).copied().unwrap_or(0))).sum()
}

/// How many non-orphaned logs in `logs` sit at a (block, logIndex) an earlier
/// one already occupies. Zero for anything an honest node returns.
pub fn duplicate_positions(logs: &[Log]) -> usize {
    let mut seen = std::collections::BTreeSet::new();
    logs.iter()
        .filter(|l| !l.removed)
        .filter(|l| !seen.insert((l.block_number, l.log_index)))
        .count()
}

/// Drop exact duplicate copies of a log from `logs` before it is processed
/// (audit round 7, M7-9; defence in depth behind the corroboration check,
/// and the only guard on a deliberately single-endpoint chain). Returns how
/// many copies were dropped.
///
/// Two DIFFERENT logs at one (block, logIndex) cannot both be real, and there
/// is no telling which one is: that is an `Err` and the window must be neither
/// signed nor advanced. Dropping an exact copy signs nothing new — the first
/// copy yields the identical signature — it only stops the second from
/// tripping a persisted DUPLICATED_NONCE stop on an anomaly that is not one.
pub fn dedupe_logs(logs: &mut Vec<Log>) -> Result<usize, String> {
    let mut seen: std::collections::BTreeMap<(Option<u64>, Option<u64>), LogKey> =
        std::collections::BTreeMap::new();
    let before = logs.len();
    let mut conflict = None;
    logs.retain(|l| {
        let pos = (l.block_number, l.log_index);
        let key = log_key(l);
        match seen.get(&pos) {
            None => {
                seen.insert(pos, key);
                true
            }
            Some(k) if *k == key => false,
            Some(_) => {
                conflict.get_or_insert(pos);
                true
            }
        }
    });
    if let Some((block, index)) = conflict {
        return Err(format!(
            "two DIFFERENT logs at block {block:?} logIndex {index:?} — at most one can be real"
        ));
    }
    Ok(before - logs.len())
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
    let mine = log_bag(served);
    let sets: Vec<(usize, LogBag)> = answers.iter().map(|(idx, logs)| (*idx, log_bag(logs))).collect();
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
    let fabricated = bag_excess(&mine, theirs);
    let withheld = bag_excess(theirs, &mine);
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
    pub(super) async fn stub(head: u64, logs: serde_json::Value) -> String {
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

    pub(super) fn rpc_log(block: u64, id: u8) -> serde_json::Value {
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

    pub(super) fn pool(urls: &[String]) -> Failover {
        Failover {
            endpoints: urls
                .iter()
                .map(|u| Endpoint {
                    url: u.clone(),
                    provider: ProviderBuilder::new().connect_http(u.parse().unwrap()).erased(),
                })
                .collect(),
            active: 0,
            last_heads: Vec::new(),
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

/// Audit round 6, LOW: the startup `Gate.bridgeDomain()` read and the H-2
/// scale-peer reads used ONE endpoint. They now share the refund path's
/// majority rule through [`read_agreed`].
#[cfg(test)]
mod agreed_read_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn endpoints(n: usize) -> Vec<(String, DynProvider)> {
        (0..n)
            .map(|i| {
                let p = DynProvider::new(ProviderBuilder::new().connect_http("http://127.0.0.1:1".parse().unwrap()));
                (format!("ep{i}"), p)
            })
            .collect()
    }

    /// Answer the i-th call with `script[i]` (`None` = transport failure).
    async fn run(script: &[Option<u8>], min_agree: usize) -> (anyhow::Result<u8>, bool) {
        let calls = AtomicUsize::new(0);
        let mut disagreed = false;
        let r = read_agreed(
            &endpoints(script.len()),
            min_agree,
            "test read",
            |_| {
                let v = script[calls.fetch_add(1, Ordering::SeqCst)];
                async move { v.ok_or_else(|| anyhow::anyhow!("refused")) }
            },
            |_| disagreed = true,
        )
        .await;
        (r, disagreed)
    }

    #[test]
    fn a_second_configured_endpoint_means_two_must_agree() {
        assert_eq!(min_agree(1, false), 1);
        assert_eq!(min_agree(2, false), 2);
        assert_eq!(min_agree(3, false), 2);
        assert_eq!(min_agree(1, true), 2);
    }

    #[tokio::test]
    async fn one_lying_endpoint_of_two_is_a_loud_refusal_not_an_answer() {
        let (r, disagreed) = run(&[Some(6), Some(18)], 2).await;
        assert!(r.is_err() && disagreed, "{r:?}");
    }

    #[tokio::test]
    async fn one_endpoint_down_of_two_is_a_quiet_refusal() {
        let (r, disagreed) = run(&[Some(6), None], 2).await;
        let e = r.unwrap_err().to_string();
        assert!(!disagreed && e.contains("ep1: refused"), "{e}");
    }

    #[tokio::test]
    async fn with_three_endpoints_one_liar_is_outvoted() {
        assert_eq!(run(&[Some(18), Some(6), Some(6)], 2).await.0.unwrap(), 6);
        assert_eq!(run(&[Some(6), Some(6)], 2).await.0.unwrap(), 6);
    }

    #[tokio::test]
    async fn a_single_endpoint_chain_reads_single_source_only_by_configuration() {
        assert_eq!(run(&[Some(6)], 1).await.0.unwrap(), 6);
        assert!(run(&[Some(6)], 2).await.0.is_err());
    }
}

/// Audit round 7: M7-8 (a stuck serving endpoint silently stopped a validator)
/// and M7-9 (a duplicated log tripped a persisted DUPLICATED_NONCE pause).
#[cfg(test)]
mod round7_tests {
    use super::round6_tests::{pool, rpc_log, stub};
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

    // ---- M7-8 -----------------------------------------------------------

    #[test]
    fn majority_floor_outvotes_one_stuck_head() {
        assert_eq!(majority_floor(&[50u64, 10_000, 10_000]), Some(10_000));
        assert_eq!(majority_floor(&[50u64, 10_000]), Some(50), "two endpoints: both must have reached it");
    }

    /// THE finding, end to end with three mock endpoints. The serving endpoint
    /// is stuck at block 50 and two honest ones are at 10_000. Before the fix
    /// the head came from the stuck one, `confirmed < from_block`, and the
    /// loop slept for ever without a word. Now the head is the majority's, the
    /// stuck endpoint stops being asked first, and the window is scanned and
    /// corroborated by the honest pair.
    #[tokio::test]
    async fn a_stuck_serving_endpoint_no_longer_stops_the_scan() {
        let stuck = stub(50, serde_json::json!([])).await;
        let a = stub(10_000, serde_json::json!([rpc_log(9_050, 1)])).await;
        let b = stub(10_000, serde_json::json!([rpc_log(9_050, 1)])).await;
        let mut f = pool(&[stuck.clone(), a.clone(), b]);
        assert_eq!(f.active_url(), stuck, "premise: the stuck endpoint serves");

        let head = f.scan_head().await.unwrap();
        assert_eq!(head, 10_000, "the stuck endpoint is outvoted");
        assert_eq!(f.active_url(), a, "the stuck endpoint is no longer asked first");
        assert!(f.heads_summary().contains("=50"), "{}", f.heads_summary());

        let (logs, scanned_to, verdict) =
            f.get_logs_corroborated(&Filter::new(), 9_000, 9_099, 10).await.unwrap().unwrap();
        assert!(matches!(verdict, Corroboration::Agreed { .. }), "got {verdict:?}");
        assert_eq!(scanned_to, 9_099);
        assert_eq!(logs.len(), 1);
    }

    /// A head that is merely a few blocks behind is not a reason to rotate,
    /// and an INFLATED head can neither drag the scan head up nor get itself
    /// asked first.
    #[tokio::test]
    async fn small_lag_does_not_rotate_and_an_inflated_head_is_outvoted() {
        let a = stub(9_990, serde_json::json!([])).await;
        let b = stub(10_000, serde_json::json!([])).await;
        let liar = stub(u64::MAX / 2, serde_json::json!([])).await;
        let mut f = pool(&[a.clone(), b, liar]);
        assert_eq!(f.scan_head().await.unwrap(), 10_000);
        assert_eq!(f.active_url(), a, "10 blocks behind is within HEAD_LAG_ROTATE");
    }

    /// Two endpoints, one stuck: no majority has reached the honest head, so
    /// the scan head stays low (there is nothing to corroborate against) —
    /// and the scan loop now says so through its idle warning.
    #[tokio::test]
    async fn two_endpoints_one_stuck_keeps_the_strict_rule() {
        let stuck = stub(50, serde_json::json!([])).await;
        let ok = stub(10_000, serde_json::json!([])).await;
        let mut f = pool(&[stuck, ok]);
        assert_eq!(f.scan_head().await.unwrap(), 50);
    }

    // ---- M7-9 -----------------------------------------------------------

    /// THE finding, pure half: the same genuine log returned twice used to
    /// compare EQUAL to the honest peer's answer (set semantics).
    #[test]
    fn a_duplicated_log_is_a_disagreement() {
        let honest = vec![sent(101, 0, 1)];
        let doubled = vec![sent(101, 0, 1), sent(101, 0, 1)];
        match tally(&doubled, &[(1, honest.clone())], 100, 200) {
            Tally::Disagreed { detail, .. } => assert!(detail.contains("1 log(s) only the serving"), "{detail}"),
            t => panic!("a duplicated log must not be Agreed, got {t:?}"),
        }
        // A duplicating PEER is a dissenter too, and with three endpoints it
        // is simply outvoted.
        assert_eq!(
            tally(&honest, &[(1, doubled), (2, honest.clone())], 100, 200),
            Tally::Agreed { by: 2, dissenters: 1 }
        );
    }

    #[test]
    fn duplicate_positions_are_counted() {
        assert_eq!(duplicate_positions(&[sent(101, 0, 1), sent(101, 1, 2)]), 0);
        assert_eq!(duplicate_positions(&[sent(101, 0, 1), sent(101, 0, 1)]), 1);
        assert_eq!(duplicate_positions(&[sent(101, 0, 1), sent(101, 0, 9)]), 1);
    }

    /// End to end: the serving endpoint returns a genuine log twice. Before,
    /// the window was Agreed and the copy paused the scanner. Now it is
    /// withheld, and the duplicating endpoint stops being asked first.
    #[tokio::test]
    async fn a_serving_endpoint_returning_a_log_twice_is_withheld_and_rotated() {
        let dup = stub(200, serde_json::json!([rpc_log(150, 1), rpc_log(150, 1)])).await;
        let honest = stub(200, serde_json::json!([rpc_log(150, 1)])).await;
        let mut f = pool(&[dup.clone(), honest.clone()]);
        let (_, _, verdict) =
            f.get_logs_corroborated(&Filter::new(), 100, 5_000, 10).await.unwrap().unwrap();
        assert!(matches!(verdict, Corroboration::Disagreed { .. }), "got {verdict:?}");
        assert_eq!(f.active_url(), honest, "the duplicating endpoint is no longer asked first");
        // With the honest one serving, the duplicating PEER dissents: a 1-vs-1
        // split, withheld — never signed, never paused.
        let (_, _, verdict) =
            f.get_logs_corroborated(&Filter::new(), 100, 5_000, 10).await.unwrap().unwrap();
        assert!(matches!(verdict, Corroboration::Disagreed { .. }), "got {verdict:?}");
    }

    #[test]
    fn dedupe_drops_exact_copies_and_refuses_conflicts() {
        let mut logs = vec![sent(101, 0, 1), sent(101, 0, 1), sent(102, 0, 2)];
        assert_eq!(dedupe_logs(&mut logs), Ok(1));
        assert_eq!(logs.len(), 2);
        let mut conflicting = vec![sent(101, 0, 1), sent(101, 0, 9)];
        assert!(dedupe_logs(&mut conflicting).is_err(), "two different logs at one position");
        let mut clean = vec![sent(101, 0, 1), sent(101, 1, 2)];
        assert_eq!(dedupe_logs(&mut clean), Ok(0));
    }
}
