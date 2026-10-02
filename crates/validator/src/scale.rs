//! The two ends of a transfer must agree on the scale its amount is in.
//!
//! ## Why this exists (audit 2026-09-16, H-2)
//!
//! Every transfer travels in a per-asset "bridge decimals" scale. `Gate.send`
//! divides the locked local amount by the SOURCE gate's registered scale, and
//! `Gate.claim` multiplies the wire amount by the DESTINATION gate's own
//! registered scale. Two gates that disagree by one digit therefore pay a power
//! of ten too much or too little on every claim of that asset. No attacker input
//! is needed: an ordinary user's 1 TST becomes 1,000 TST for whoever receives
//! it, and each gate is behaving exactly as configured.
//!
//! ## What changed when the scale went into the submissionId
//!
//! The design half of H-2 landed: the preimage carries the scale now, and
//! `Gate.claim` refuses a wire scale that is not its own registration. So the
//! drain this module was written to prevent is closed on-chain, in both
//! directions, without any validator's cooperation.
//!
//! This check is no longer the only thing standing in the way — but it is still
//! worth running, and it moved UP the stack rather than out of it. A mis-scaled
//! corridor now cannot settle at all: every transfer into it strands and has to
//! be walked back through cancel -> refund. Refusing to sign turns that into one
//! loud log line per corridor, at the first transfer, instead of a queue of
//! stuck users. It is an operational guard now, not the last line of defence.
//!
//! ## Why it still belongs HERE and not in the keeper
//!
//! `Gate.claim` is permissionless: anyone holding a validator quorum can submit
//! it. A check in the keeper would therefore stop only the honest submitter. The
//! signature is the last thing that can be withheld.
//!
//! ## What it reads
//!
//! * source scale — NOT read at all any more. It is a field of the `Sent` event,
//!   and since it is inside the submissionId it is the exact value this
//!   validator is about to sign over; reading the source gate's registration
//!   would only re-derive what the gate already put in the hash, at the cost of
//!   an RPC round-trip per corridor.
//! * EVM destination scale — `bridgeDecimalsFor(debridgeId)`, which resolves
//!   `tokenOf` and the token's decimals in one atomic call. A gate deployed
//!   before that function existed reverts on it, so the read FALLS BACK to the
//!   same two reads it performs (`tokenOf` then `bridgeDecimalsOf`), which every
//!   decimals-aware gate has. Found by replaying live mesh8 traffic: without the
//!   fallback this guard refused every transfer to a live pre-upgrade gate, and
//!   those gates are sealed, so upgrading them first means a 48 h timelock with
//!   the bridge stopped. The two reads cannot race: both registrations are
//!   write-once.
//! * Solana destination scale — the Solana gate's `["asset", debridgeId]`
//!   account. An EVM destination reader can never cover a Solana chain, so
//!   without this every EVM->Solana transfer was refused outright (also found on
//!   live traffic).
//!
//! Registrations are write-once, so a successful read is cached forever and the
//! steady-state cost is one pair of reads per corridor, not per transfer.
//! Failures are never cached — a transient RPC fault must not turn into a
//! permanent refusal.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Duration;

use alloy::primitives::{Address, B256};
use alloy::providers::DynProvider;
use base64::Engine as _;
use tokio::sync::Mutex;
use tracing::warn;

use bridge_core::abi::Gate;
use bridge_core::config::redact_url;

use crate::provider;

/// An EVM destination gate this validator can read well enough to vote on.
///
/// ## Connected lazily (audit round 7, L7-13)
///
/// The scan loop used to connect every destination up front and wait, forever,
/// until each had `min_agree` healthy endpoints — so one dead endpoint on one
/// peer chain stopped this source signing transfers to EVERY peer. Now the
/// endpoints are probed the first time a transfer to this chain needs them, and
/// re-probed on every later attempt until enough are healthy. Until then a read
/// is an `Err` — retryable, never `Unknown` — so a transfer to a not-yet-ready
/// destination is retried with the cursor rolled back, and nothing is withheld
/// for good. Corridors to ready destinations are unaffected.
pub struct Destination {
    pub chain_id: u64,
    pub gate: Address,
    /// The configured urls, probed by [`Destination::endpoints`].
    urls: Vec<String>,
    /// Every healthy endpoint for the peer chain, (redacted url, provider), once
    /// at least `min_agree` of them passed the probe. `None` until then.
    ///
    /// Audit round 6, LOW: this used to be ONE provider — `connect_checked`
    /// kept the first healthy endpoint — so a single lying destination RPC could
    /// report a wrong scale and stop this validator signing the corridor. Only
    /// liveness (claim enforces the scale on-chain since the scale went into the
    /// submissionId), but every other gate read is corroborated now, so this is
    /// too: the scale is taken only when [`provider::majority`] agrees.
    connected: Mutex<Option<Vec<(String, DynProvider)>>>,
    /// [`provider::min_agree`] for the peer's CONFIGURED endpoint count.
    pub min_agree: usize,
}

impl Destination {
    /// A destination that connects on first use.
    pub fn new(chain_id: u64, gate: Address, urls: Vec<String>) -> Self {
        let min_agree = provider::min_agree(urls.len(), false);
        Destination { chain_id, gate, urls, connected: Mutex::new(None), min_agree }
    }

    /// Already-connected endpoints (tests).
    #[cfg(test)]
    pub fn connected(chain_id: u64, gate: Address, endpoints: Vec<(String, DynProvider)>, min_agree: usize) -> Self {
        Destination { chain_id, gate, urls: vec![], connected: Mutex::new(Some(endpoints)), min_agree }
    }

    /// The healthy endpoints, probing them now if that has not succeeded yet.
    /// `Err` (retryable) while fewer than `min_agree` are healthy: a chain
    /// configured with a second endpoint is never read single-source.
    async fn endpoints(&self) -> anyhow::Result<Vec<(String, DynProvider)>> {
        let mut slot = self.connected.lock().await;
        if let Some(e) = slot.as_ref() {
            return Ok(e.clone());
        }
        let healthy = provider::connect_all_checked(&self.urls, self.chain_id)
            .await
            .map_err(|e| anyhow::anyhow!("destination {} not ready: {e}", self.chain_id))?;
        anyhow::ensure!(
            healthy.len() >= self.min_agree,
            "destination {} not ready: {} healthy RPC endpoint(s) of {} configured, need {} \
             to read its bridge decimals (audit round 6/L7-13); will retry",
            self.chain_id,
            healthy.len(),
            self.urls.len(),
            self.min_agree
        );
        *slot = Some(healthy.clone());
        Ok(healthy)
    }
}

/// A Solana gate program this validator can read, for EVM->Solana transfers.
pub struct SolanaDestination {
    pub chain_id: u64,
    pub program_id: [u8; 32],
    /// Every configured Solana JSON-RPC url (audit round 7, L7-11). Each is
    /// asked; see [`ScaleGuard::solana_destination_scale`] for the rule.
    pub rpcs: Vec<String>,
}

enum Peer {
    Evm(Destination),
    Solana(SolanaDestination),
}

/// What the two ends say about an asset's scale.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Both ends registered the same scale. Safe to sign.
    Agree(u8),
    /// They disagree: claiming this would pay `10^|src-dst|` off.
    Mismatch { source: u8, destination: u8 },
    /// Could not establish both ends. Withhold the signature — see the module
    /// note on failing closed. Carries a reason for the log.
    Unknown(&'static str),
}

pub struct ScaleGuard {
    peers: BTreeMap<u64, Peer>,
    /// `(chain_id_to, debridge_id) -> bridge decimals`, successful reads only.
    dest_cache: Mutex<HashMap<(u64, B256), u8>>,
    /// `token -> bridge decimals` on this scanner's own source gate.
    /// Chains we have already warned about, so an unconfigured peer does not
    /// print once per transfer.
    warned: Mutex<HashSet<u64>>,
    /// For the Solana reads. Bounded, because a destination RPC that accepts a
    /// connection and never answers must not wedge the source scan loop.
    http: reqwest::Client,
}

/// Largest Solana RPC response we will read. A `getAccountInfo` for a 130-byte
/// account is a few hundred bytes; anything near this is not that answer.
const MAX_SOLANA_RESPONSE: usize = 64 * 1024;

impl ScaleGuard {
    pub fn new(evm: Vec<Destination>, solana: Vec<SolanaDestination>) -> Self {
        let mut peers = BTreeMap::new();
        for d in evm {
            peers.insert(d.chain_id, Peer::Evm(d));
        }
        for d in solana {
            peers.insert(d.chain_id, Peer::Solana(d));
        }
        ScaleGuard {
            peers,
            dest_cache: Mutex::new(HashMap::new()),
            warned: Mutex::new(HashSet::new()),
            http: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(10))
                .timeout(Duration::from_secs(20))
                .build()
                .unwrap_or_default(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Do the two ends agree about `debridge_id`'s scale?
    ///
    /// `source_provider` is the endpoint this scanner is already reading logs
    /// from, so the source read costs no new connection.
    ///
    /// `Err` means a read failed in TRANSIT (rate limit, timeout, refused
    /// connection): we do not know yet. The caller must propagate it so the batch
    /// is retried with the cursor and nonces rolled back — the convention every
    /// other chain read in this codebase follows. Mapping it to `Unknown` instead
    /// withheld the signature and advanced past the transfer for good, so a
    /// single 429 on one validator could leave a legitimate transfer short of
    /// quorum forever; replaying live mesh8 traffic hit exactly that. `Unknown`
    /// is reserved for DEFINITIVE answers the chain itself gave.
    /// `source` is the `bridgeDecimals` the `Sent` event carries — the scale the
    /// submissionId commits to, and so the scale any claim of this transfer must
    /// present to the destination gate.
    pub async fn verdict(
        &self,
        source: u8,
        chain_id_to: u64,
        debridge_id: B256,
    ) -> anyhow::Result<Verdict> {
        let Some(peer) = self.peers.get(&chain_id_to) else {
            if self.warned.lock().await.insert(chain_id_to) {
                warn!(
                    chain_id_to,
                    "no [[destinations]] or [[solana_destinations]] entry for this peer — \
                     cannot verify that it agrees on the asset's bridge decimals, so transfers \
                     to it will NOT be signed (audit H-2). Add it to this validator's config."
                );
            }
            return Ok(Verdict::Unknown("destination chain not configured on this validator"));
        };

        let key = (chain_id_to, debridge_id);
        let cached = self.dest_cache.lock().await.get(&key).copied();
        let destination = match cached {
            Some(d) => d,
            None => {
                let read = match peer {
                    Peer::Evm(d) => self.evm_destination_scale(d, debridge_id).await?,
                    Peer::Solana(d) => self.solana_destination_scale(d, debridge_id).await?,
                };
                match read {
                    Some(d) => {
                        self.dest_cache.lock().await.insert(key, d);
                        d
                    }
                    None => {
                        return Ok(Verdict::Unknown("destination did not report bridge decimals"))
                    }
                }
            }
        };

        Ok(if source == destination {
            Verdict::Agree(source)
        } else {
            Verdict::Mismatch { source, destination }
        })
    }

    /// The destination scale, read from every endpoint of the peer and taken
    /// only on a [`provider::majority`] (audit round 6, LOW). A refusal is an
    /// `Err` — too few answers, or endpoints that answered and DIFFER — so the
    /// batch is retried with the cursor rolled back, the same posture as a
    /// transport fault: a lying endpoint delays signing, it never turns into a
    /// permanent withhold (`Unknown`) or, worse, a cached wrong scale.
    async fn evm_destination_scale(
        &self,
        dest: &Destination,
        debridge_id: B256,
    ) -> anyhow::Result<Option<u8>> {
        let endpoints = dest.endpoints().await?;
        provider::read_agreed(
            &endpoints,
            dest.min_agree,
            "destination bridge decimals",
            |p| evm_scale_on(dest, p, debridge_id),
            |answers| {
                warn!(
                    chain_id = dest.chain_id,
                    %debridge_id,
                    answers = ?answers,
                    "DESTINATION RPC ENDPOINTS DISAGREE about an asset's bridge decimals — not \
                     signing this source until they agree (audit H-4/H-2). One endpoint is wrong \
                     about the chain: investigate."
                );
            },
        )
        .await
    }
}

/// One endpoint's answer for [`ScaleGuard::evm_destination_scale`]: `Ok(None)`
/// when the chain definitively has no scale for the id, `Err` on transit faults.
async fn evm_scale_on(dest: &Destination, provider: DynProvider, debridge_id: B256) -> anyhow::Result<Option<u8>> {
    let gate = Gate::new(dest.gate, &provider);
    let primary: Option<String> = match gate.bridgeDecimalsFor(debridge_id).call().await {
        Ok(out) if out.set => return Ok(Some(out.bridgeDecimals)),
        Ok(_) => {
            // No corridor there yet. The transfer is already unclaimable until
            // one exists, so withholding costs nothing and the operator sees why.
            warn!(
                chain_id = dest.chain_id,
                %debridge_id,
                "destination gate has no corridor registered for this debridgeId"
            );
            return Ok(None);
        }
        // A gate older than `bridgeDecimalsFor` reverts on it; answer from the
        // two reads it is made of. A transport fault lands here too and is
        // then reported by those reads, so it is still retried, not withheld.
        Err(e) => Some(e.to_string()),
    };
    // Name BOTH reads when the fallback also fails in transit: otherwise a
    // 429 on `bridgeDecimalsFor` is logged as if only `tokenOf` had failed.
    let first = || primary.as_deref().map(|p| format!(" (bridgeDecimalsFor first: {p})")).unwrap_or_default();

    let local = match gate.tokenOf(debridge_id).call().await {
        Ok(t) => t,
        Err(e) if is_definitive(&e) => {
            warn!(chain_id = dest.chain_id, gate = %dest.gate, error = %e,
                  "destination gate does not answer tokenOf");
            return Ok(None);
        }
        Err(e) => {
            return Err(anyhow::anyhow!(
                "reading destination tokenOf on chain {}: {e}{}",
                dest.chain_id,
                first()
            ))
        }
    };
    if local == Address::ZERO {
        warn!(
            chain_id = dest.chain_id,
            %debridge_id,
            "destination gate has no corridor registered for this debridgeId"
        );
        return Ok(None);
    }
    match gate.bridgeDecimalsOf(local).call().await {
        Ok(out) if out.set => Ok(Some(out.bridgeDecimals)),
        Ok(_) => {
            warn!(
                chain_id = dest.chain_id,
                token = %local,
                "destination token has no bridge decimals registered"
            );
            Ok(None)
        }
        Err(e) if is_definitive(&e) => {
            warn!(chain_id = dest.chain_id, token = %local, error = %e,
                  "destination gate does not answer bridgeDecimalsOf");
            Ok(None)
        }
        Err(e) => Err(anyhow::anyhow!(
            "reading destination bridgeDecimalsOf on chain {}: {e}{}",
            dest.chain_id,
            first()
        )),
    }
}

/// One Solana endpoint's verdict on the `["asset", id]` account. Compared
/// across endpoints as a whole, rather than the raw account bytes, so endpoints
/// that agree on the scale agree even if they served different finalized slots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SolanaAnswer {
    /// `value: null` — no such account.
    Absent,
    /// An account exists but is not one this validator can vouch for.
    Unusable(&'static str),
    /// A current, program-owned record at this scale.
    Scale(u8),
}

/// The rule for combining several Solana endpoints' answers (audit round 7,
/// L7-11). Pure, so it is testable without a network.
///
/// * A scale is taken on a [`provider::majority`] — one lying or lagging
///   endpoint can neither forge one nor, by dissenting, stall the read.
/// * A NEGATIVE answer (`Absent`/`Unusable`) withholds the signature for good,
///   so it must be the majority AND unanimous among the endpoints that
///   answered. One endpoint answering `null` among several that see the account
///   is a disagreement — retried — not a verdict.
/// * Anything else is `Err`: too few answers, or no majority.
///
/// With one configured endpoint (`min_agree == 1`) this is exactly the old
/// single-source behaviour.
pub(crate) fn settle_solana(
    answers: &[(String, SolanaAnswer)],
    min_agree: usize,
) -> Result<SolanaAnswer, provider::NoMajority> {
    let refs: Vec<(&str, SolanaAnswer)> = answers.iter().map(|(u, a)| (u.as_str(), a.clone())).collect();
    let agreed = provider::majority(&refs, min_agree)?;
    if matches!(agreed, SolanaAnswer::Scale(_)) || answers.iter().all(|(_, a)| *a == agreed) {
        return Ok(agreed);
    }
    Err(provider::NoMajority {
        reason: format!(
            "a definitive \"no usable asset record\" must be unanimous, got {answers:?}"
        ),
        disagreement: true,
    })
}

impl ScaleGuard {
    async fn solana_destination_scale(
        &self,
        dest: &SolanaDestination,
        debridge_id: B256,
    ) -> anyhow::Result<Option<u8>> {
        let did: [u8; 32] = debridge_id.0;
        let Some((pda, _bump)) =
            swap_math::pda::find_program_address(&[b"asset", &did], &dest.program_id)
        else {
            warn!(chain_id = dest.chain_id, "no asset PDA derives for this debridgeId");
            return Ok(None);
        };
        let program_b58 = bs58::encode(dest.program_id).into_string();

        // Every endpoint, and the answers combined by `settle_solana`. Transport
        // faults (HTTP errors, rate limits, JSON-RPC errors, oversized bodies)
        // are not answers; what an account says is.
        let mut answers: Vec<(String, SolanaAnswer)> = Vec::new();
        let mut failed: Vec<String> = Vec::new();
        for url in &dest.rpcs {
            let shown = redact_url(url);
            match self.solana_account(url, &pda).await {
                Ok(None) => answers.push((shown, SolanaAnswer::Absent)),
                Ok(Some((owner, data))) => {
                    let a = match solana_asset_scale(owner == program_b58, &data, &did) {
                        Ok(d) => SolanaAnswer::Scale(d),
                        Err(why) => SolanaAnswer::Unusable(why),
                    };
                    answers.push((shown, a));
                }
                Err(e) => failed.push(format!("{shown}: {e}")),
            }
        }
        let min_agree = provider::min_agree(dest.rpcs.len(), false);
        match settle_solana(&answers, min_agree) {
            Ok(SolanaAnswer::Scale(d)) => Ok(Some(d)),
            Ok(SolanaAnswer::Absent) => {
                warn!(
                    chain_id = dest.chain_id,
                    %debridge_id,
                    "Solana gate has no asset registered for this debridgeId"
                );
                Ok(None)
            }
            Ok(SolanaAnswer::Unusable(why)) => {
                warn!(chain_id = dest.chain_id, %debridge_id, reason = why, "Solana asset account unusable");
                Ok(None)
            }
            Err(e) => {
                if e.disagreement {
                    warn!(
                        chain_id = dest.chain_id,
                        %debridge_id,
                        answers = ?answers,
                        "SOLANA RPC ENDPOINTS DISAGREE about an asset account — not signing this \
                         source until they agree (audit L7-11). One endpoint is wrong or lagging: \
                         investigate."
                    );
                }
                Err(anyhow::anyhow!(
                    "Solana destination {} asset scale: {}{}",
                    dest.chain_id,
                    e.reason,
                    if failed.is_empty() { String::new() } else { format!(" (failed: {})", failed.join("; ")) }
                ))
            }
        }
    }

    /// `getAccountInfo` at `finalized` against ONE endpoint: the account's owner
    /// (base58) and raw data, or `None` when it does not exist.
    async fn solana_account(
        &self,
        url: &str,
        address: &[u8; 32],
    ) -> anyhow::Result<Option<(String, Vec<u8>)>> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getAccountInfo",
            "params": [bs58::encode(address).into_string(), {"encoding": "base64", "commitment": "finalized"}],
        });
        // `without_url`: a hosted endpoint's url is its API key.
        let mut res = self.http.post(url).json(&body).send().await.map_err(|e| e.without_url())?;
        if !res.status().is_success() {
            anyhow::bail!("HTTP {}", res.status());
        }
        let bytes = read_capped(&mut res, MAX_SOLANA_RESPONSE).await?;
        let v: serde_json::Value = serde_json::from_slice(&bytes)?;
        if let Some(err) = v.get("error") {
            anyhow::bail!("getAccountInfo error: {err}");
        }
        let value = &v["result"]["value"];
        if value.is_null() {
            return Ok(None);
        }
        let owner = value["owner"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("account has no owner"))?
            .to_string();
        let b64 = value["data"][0]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("account data is not base64"))?;
        Ok(Some((owner, base64::engine::general_purpose::STANDARD.decode(b64)?)))
    }
}

/// Read a response body, refusing it as soon as it exceeds `cap` bytes (audit
/// round 7, L7-11). `res.bytes()` buffered the WHOLE body before the size check,
/// so an endpoint streaming an endless reply cost unbounded memory first.
async fn read_capped(res: &mut reqwest::Response, cap: usize) -> anyhow::Result<Vec<u8>> {
    if let Some(len) = res.content_length() {
        anyhow::ensure!(len <= cap as u64, "oversized getAccountInfo response ({len} bytes declared)");
    }
    let mut out = Vec::new();
    while let Some(chunk) = res.chunk().await.map_err(|e| e.without_url())? {
        anyhow::ensure!(
            out.len() + chunk.len() <= cap,
            "oversized getAccountInfo response (over {cap} bytes)"
        );
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Did the chain itself ANSWER (a revert, or a reply that is not this function's
/// shape), as opposed to the request failing in transit?
///
/// A revert is a fact about the contract and will not change on retry: withhold.
/// A 429, a timeout or a refused connection says nothing about the contract:
/// retry. Treating the second like the first is what permanently withheld a
/// legitimate live transfer's signature over one rate-limited request.
fn is_definitive(e: &alloy::contract::Error) -> bool {
    use alloy::contract::Error as E;
    if e.as_revert_data().is_some() {
        return true;
    }
    match e {
        E::ZeroData(..) | E::AbiError(_) | E::UnknownFunction(_) | E::UnknownSelector(_) => true,
        // Some nodes report a data-less revert only in the message.
        E::TransportError(_) => e.to_string().to_ascii_lowercase().contains("execution reverted"),
        _ => false,
    }
}

/// The scale a Solana `["asset", id]` account pays out at. Pure, so the rules
/// are testable against real captured account bytes.
///
/// Refuses (with a reason) anything that is not a current, program-owned record
/// for exactly this `debridge_id`:
/// * a foreign owner — only the gate program can have written the real record;
/// * a pre-decimals record (96/97 bytes). It decodes on the program at scale 0,
///   which is the right semantics for transfers made before decimals existed,
///   but comparing that 0 against a decimals-aware source would claim "these
///   agree" or "these differ" about a scale the record never had. Unknown is the
///   honest answer, and fail-closed;
/// * a record whose `debridge_id` differs from the one derived for — only seed
///   confusion could produce it;
/// * decimals that yield no bridge unit.
pub(crate) fn solana_asset_scale(
    owner_is_program: bool,
    data: &[u8],
    debridge_id: &[u8; 32],
) -> Result<u8, &'static str> {
    if !owner_is_program {
        return Err("asset account is not owned by the gate program");
    }
    if data.len() < 98 {
        return Err("pre-decimals asset record: scale cannot be compared");
    }
    let asset: bridge_solana::account::AssetAccount =
        bridge_solana::account::decode(data).ok_or("asset account does not decode")?;
    if &asset.debridge_id != debridge_id {
        return Err("asset record is for a different debridgeId");
    }
    if asset.bridge_unit().is_none() {
        return Err("asset decimals yield no bridge unit");
    }
    Ok(asset.bridge_decimals)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard() -> ScaleGuard {
        ScaleGuard::new(vec![], vec![])
    }

    fn dead_provider() -> DynProvider {
        DynProvider::new(
            alloy::providers::ProviderBuilder::new()
                .connect_http("http://127.0.0.1:1".parse().unwrap()),
        )
    }

    /// An unconfigured destination must withhold, not wave through: the whole
    /// point is that an unverifiable far end is exactly the dangerous case.
    #[tokio::test]
    async fn an_unconfigured_destination_is_unknown_not_agree() {
        let v = guard()
            .verdict(6, 1338, B256::repeat_byte(3))
            .await
            .expect("an unconfigured peer is a definitive answer, not a transport fault");
        assert!(matches!(v, Verdict::Unknown(_)), "got {v:?}");
    }

    /// It warns once per chain, not once per transfer — an unconfigured peer on a
    /// busy corridor would otherwise bury every other line in the log.
    #[tokio::test]
    async fn the_unconfigured_warning_is_once_per_chain() {
        let g = guard();
        assert!(g.warned.lock().await.is_empty());
        for _ in 0..3 {
            let _ = g.verdict(6, 1338, B256::ZERO).await;
        }
        assert_eq!(g.warned.lock().await.len(), 1);
    }

    /// A read that fails IN TRANSIT must surface as `Err` — retried with the
    /// cursor rolled back — never as `Unknown`, which withholds and moves on for
    /// good. Here the DESTINATION RPC refuses the connection outright. (The
    /// source is no longer read at all: its scale rides in the signed event.)
    #[tokio::test]
    async fn a_transport_failure_is_retryable_not_a_withhold() {
        let g = ScaleGuard::new(
            vec![Destination::connected(
                1338,
                Address::repeat_byte(4),
                vec![("dead".into(), dead_provider())],
                1,
            )],
            vec![],
        );
        let r = g
            .verdict(6, 1338, B256::ZERO)
            .await;
        assert!(r.is_err(), "a refused connection is not a verdict, got {r:?}");
    }

    #[test]
    fn a_disagreement_is_a_mismatch_and_agreement_is_not() {
        assert_eq!(
            Verdict::Mismatch { source: 6, destination: 3 },
            Verdict::Mismatch { source: 6, destination: 3 }
        );
        assert_ne!(Verdict::Agree(6), Verdict::Mismatch { source: 6, destination: 3 });
    }

    /// A configured Solana peer is a peer: it must not be reported as
    /// "not configured" — that was the EVM->Solana regression.
    #[tokio::test]
    async fn a_configured_solana_peer_is_not_unconfigured() {
        let g = ScaleGuard::new(
            vec![],
            vec![SolanaDestination { chain_id: 7565164, program_id: [9; 32], rpcs: vec!["http://127.0.0.1:1".into()] }],
        );
        let _ = g
            .verdict(6, 7565164, B256::ZERO)
            .await;
        assert!(
            g.warned.lock().await.is_empty(),
            "a Solana destination listed in config must reach the Solana reader"
        );
    }

    fn asset_bytes(did: [u8; 32], bridge: u8, local: u8, slack: usize) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&did);
        v.extend_from_slice(&[7u8; 32]); // mint
        v.extend_from_slice(&[8u8; 32]); // vault
        v.push(bridge);
        v.push(local);
        v.extend(std::iter::repeat_n(0u8, slack));
        v
    }

    #[test]
    fn solana_asset_scale_reads_a_current_record_with_or_without_slack() {
        let did = [3u8; 32];
        assert_eq!(solana_asset_scale(true, &asset_bytes(did, 6, 9, 0), &did), Ok(6));
        // the M-3 allocation: 98 + 32 bytes of slack
        assert_eq!(solana_asset_scale(true, &asset_bytes(did, 9, 9, 32), &did), Ok(9));
    }

    #[test]
    fn solana_asset_scale_refuses_what_it_cannot_vouch_for() {
        let did = [3u8; 32];
        let good = asset_bytes(did, 6, 9, 0);
        assert!(solana_asset_scale(false, &good, &did).is_err(), "foreign owner");
        assert!(solana_asset_scale(true, &good[..96], &did).is_err(), "legacy 96-byte record");
        assert!(solana_asset_scale(true, &good[..97], &did).is_err(), "legacy 97-byte account");
        assert!(solana_asset_scale(true, &good, &[4u8; 32]).is_err(), "wrong debridgeId");
        assert!(solana_asset_scale(true, &asset_bytes(did, 9, 6, 0), &did).is_err(), "bridge > local");
    }

    /// Pinned to REAL devnet state (captured 2026-09-17 from the live mesh8 gate
    /// program `Bvh4Jxh…`): the asset record the real Hoodi->Solana TST transfer
    /// `0x53aa76b3…` paid out through. Proves two things the synthetic fixtures
    /// cannot: that `swap_math`'s derivation lands on the account the program
    /// actually created, and that the decoder reads the scale from the bytes the
    /// program actually wrote.
    #[test]
    fn a_live_devnet_asset_record_derives_and_decodes() {
        let program: [u8; 32] = bs58::decode("Bvh4JxhWBCFXfc4iu8Cm9PCw86EAH4Yn39pHpzwnQFc1")
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap();
        let did: [u8; 32] =
            hex::decode("e34a1d65b23e939952a1177300f24c1e1f05d72014029d1aa50014c56f831cac")
                .unwrap()
                .try_into()
                .unwrap();
        let (pda, _) = swap_math::pda::find_program_address(&[b"asset", &did], &program).unwrap();
        assert_eq!(bs58::encode(pda).into_string(), "GeLamBdw5UPj3ggtiZzL5vZ3SixtrEuPUi2nRARYrLWk");

        let data = base64::engine::general_purpose::STANDARD
            .decode("40odZbI+k5lSoRdzAPJMHh8F1yAUAp0apQAUxW+DHKxurL23/bNu4A1eAkIk1L/hYdnvk4TSxxly8TH01AcyvNmj2TKLgFGm+jbiGojUCvH6cSk1PjGzBtIT8wQXmphGBgY=")
            .unwrap();
        assert_eq!(data.len(), 98);
        assert_eq!(solana_asset_scale(true, &data, &did), Ok(6));
    }

    // --- audit round 7, L7-11: several Solana RPCs, majority rule -------------

    fn a(answers: &[SolanaAnswer]) -> Vec<(String, SolanaAnswer)> {
        answers.iter().enumerate().map(|(i, x)| (format!("rpc{i}"), x.clone())).collect()
    }

    #[test]
    fn settle_solana_takes_a_majority_scale_and_only_a_unanimous_negative() {
        use SolanaAnswer::*;
        // One configured endpoint: the old single-source behaviour, unchanged.
        assert_eq!(settle_solana(&a(&[Absent]), 1), Ok(Absent));
        assert_eq!(settle_solana(&a(&[Scale(6)]), 1), Ok(Scale(6)));
        // Two: both, identically.
        assert_eq!(settle_solana(&a(&[Scale(6), Scale(6)]), 2), Ok(Scale(6)));
        assert_eq!(settle_solana(&a(&[Absent, Absent]), 2), Ok(Absent));
        // THE finding: one `null` beside an endpoint that sees the account is a
        // disagreement to retry, never a permanent withhold.
        let e = settle_solana(&a(&[Scale(6), Absent]), 2).unwrap_err();
        assert!(e.disagreement, "{e:?}");
        // Three: one liar is outvoted when it denies the account...
        assert_eq!(settle_solana(&a(&[Scale(6), Absent, Scale(6)]), 2), Ok(Scale(6)));
        // ...but a negative needs every answering endpoint, so one endpoint that
        // DOES see the record keeps the transfer retryable.
        assert!(settle_solana(&a(&[Absent, Absent, Scale(6)]), 2).is_err());
        assert!(settle_solana(&a(&[Unusable("x"), Unusable("x"), Absent]), 2).is_err());
        // Different scales, or too few answers: nothing.
        assert!(settle_solana(&a(&[Scale(6), Scale(9)]), 2).is_err());
        let e = settle_solana(&a(&[Scale(6)]), 2).unwrap_err();
        assert!(!e.disagreement, "one answer of two is not an accusation: {e:?}");
    }

    const PROGRAM: [u8; 32] = [9; 32];

    /// A Solana JSON-RPC stub. `account = Some(bytes)` serves a program-owned
    /// account, `None` serves `value: null`; `pad` bloats the body.
    async fn sol_stub(account: Option<Vec<u8>>, pad: usize) -> String {
        use axum::{routing::post, Json, Router};
        let owner = bs58::encode(PROGRAM).into_string();
        let app = Router::new().route(
            "/",
            post(move |Json(req): Json<serde_json::Value>| async move {
                assert_eq!(req["method"], "getAccountInfo");
                let value = match &account {
                    Some(d) => serde_json::json!({
                        "owner": owner,
                        "data": [base64::engine::general_purpose::STANDARD.encode(d), "base64"],
                    }),
                    None => serde_json::Value::Null,
                };
                Json(serde_json::json!({
                    "jsonrpc": "2.0", "id": req["id"],
                    "result": { "context": { "slot": 1 }, "value": value },
                    "pad": "x".repeat(pad),
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}/")
    }

    fn sol_guard(rpcs: Vec<String>) -> ScaleGuard {
        ScaleGuard::new(vec![], vec![SolanaDestination { chain_id: 7565164, program_id: PROGRAM, rpcs }])
    }

    const DID: [u8; 32] = [3; 32];

    #[tokio::test]
    async fn one_solana_rpc_answering_null_among_several_is_retried_not_withheld() {
        let rec = asset_bytes(DID, 6, 9, 0);
        let g = sol_guard(vec![sol_stub(Some(rec.clone()), 0).await, sol_stub(None, 0).await]);
        let r = g.verdict(6, 7565164, B256::from(DID)).await;
        assert!(r.is_err(), "a lone null must not become Unknown (a permanent withhold), got {r:?}");

        // The same null, outvoted by two endpoints that see the record.
        let g = sol_guard(vec![
            sol_stub(Some(rec.clone()), 0).await,
            sol_stub(None, 0).await,
            sol_stub(Some(rec), 0).await,
        ]);
        assert_eq!(g.verdict(6, 7565164, B256::from(DID)).await.unwrap(), Verdict::Agree(6));
    }

    #[tokio::test]
    async fn solana_rpcs_that_agree_are_read_and_a_unanimous_absence_is_unknown() {
        let rec = asset_bytes(DID, 6, 9, 0);
        let g = sol_guard(vec![sol_stub(Some(rec.clone()), 0).await, sol_stub(Some(rec), 0).await]);
        assert_eq!(g.verdict(9, 7565164, B256::from(DID)).await.unwrap(), Verdict::Mismatch { source: 9, destination: 6 });

        let g = sol_guard(vec![sol_stub(None, 0).await, sol_stub(None, 0).await]);
        let v = g.verdict(6, 7565164, B256::from(DID)).await.unwrap();
        assert!(matches!(v, Verdict::Unknown(_)), "every endpoint says no record: {v:?}");
    }

    /// The size cap holds while reading, not after buffering the whole body.
    #[tokio::test]
    async fn an_oversized_solana_response_is_refused() {
        let g = sol_guard(vec![sol_stub(Some(asset_bytes(DID, 6, 9, 0)), MAX_SOLANA_RESPONSE + 1).await]);
        let e = g.verdict(6, 7565164, B256::from(DID)).await.unwrap_err();
        assert!(e.to_string().contains("oversized"), "{e}");
    }

    // --- audit round 7, L7-13: destinations connect lazily -----------------

    /// An EVM gate stub on chain 1338 answering `bridgeDecimalsFor` with scale 6.
    async fn evm_stub(chain: u64) -> String {
        use alloy_sol_types::SolCall;
        use axum::{routing::post, Json, Router};
        let app = Router::new().route(
            "/",
            post(move |Json(req): Json<serde_json::Value>| async move {
                let result = match req["method"].as_str() {
                    Some("eth_chainId") => serde_json::json!(format!("{chain:#x}")),
                    Some("eth_call") => {
                        let tx = &req["params"][0];
                        let input = tx["input"].as_str().or(tx["data"].as_str()).unwrap_or_default();
                        let sel = hex::decode(&input[2..10]).unwrap();
                        assert_eq!(sel, Gate::bridgeDecimalsForCall::SELECTOR);
                        let ret = Gate::bridgeDecimalsForCall::abi_encode_returns(
                            &Gate::bridgeDecimalsForReturn {
                                set: true,
                                bridgeDecimals: 6,
                                localDecimals: 18,
                                localToken: Address::repeat_byte(1),
                            },
                        );
                        serde_json::json!(format!("0x{}", hex::encode(ret)))
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

    /// One peer with a dead endpoint no longer holds up the others: building the
    /// guard connects nothing, the dead peer's corridor is a RETRYABLE error (not
    /// `Unknown`, so its transfers are not skipped for good) and never a
    /// single-source read, while a healthy peer in the same guard is read.
    #[tokio::test]
    async fn a_dead_destination_endpoint_withholds_only_its_own_corridor_and_retryably() {
        let half_dead = evm_stub(1339).await;
        let g = ScaleGuard::new(
            vec![
                // configured with two, one dead: must not be read on one
                Destination::new(1339, Address::repeat_byte(4), vec![half_dead, "http://127.0.0.1:1".into()]),
                Destination::new(1338, Address::repeat_byte(4), vec![evm_stub(1338).await, evm_stub(1338).await]),
            ],
            vec![],
        );
        let r = g.verdict(6, 1339, B256::ZERO).await;
        assert!(r.is_err(), "a destination short of healthy endpoints is retried, got {r:?}");
        assert_eq!(g.verdict(6, 1338, B256::ZERO).await.unwrap(), Verdict::Agree(6));
    }
}

