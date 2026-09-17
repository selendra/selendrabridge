//! The two ends of a transfer must agree on the scale its amount is in.
//!
//! ## Why this exists (audit 2026-09-16, H-2)
//!
//! Every transfer travels in a per-asset "bridge decimals" scale. `Gate.send`
//! divides the locked local amount by the SOURCE gate's registered scale, and
//! `Gate.claim` multiplies the wire amount by the DESTINATION gate's own
//! registered scale. The submissionId commits to `debridgeId` and the amount —
//! but NOT to the scale (`contracts/src/BridgeHash.sol`).
//!
//! So two gates that disagree by one digit pay a power of ten too much or too
//! little on every claim of that asset. No attacker input is needed: an ordinary
//! user's 1 TST becomes 1,000 TST for whoever receives it, and the gate is
//! behaving exactly as configured. Both registrations are write-once, so it
//! cannot be corrected in place — only a new gate or a UUPS upgrade fixes it.
//!
//! ## Why the check has to be HERE
//!
//! `Gate.claim` is permissionless: anyone holding a validator quorum can submit
//! it. A check in the keeper would therefore stop only the honest submitter. The
//! signature is the last thing that can be withheld, so the validators are the
//! only component that can actually prevent the payout — which is why this runs
//! before signing, and why it fails CLOSED.
//!
//! ## What it reads
//!
//! * source scale — `bridgeDecimalsOf(token)` on the source gate, keyed on the
//!   `token` the `Sent` event carries. NOT `bridgeDecimalsFor(debridgeId)`: a
//!   gate never maps its own outgoing id, so that would answer "unregistered".
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

/// An EVM destination gate this validator can read well enough to vote on.
pub struct Destination {
    pub chain_id: u64,
    pub gate: Address,
    pub provider: DynProvider,
}

/// A Solana gate program this validator can read, for EVM->Solana transfers.
pub struct SolanaDestination {
    pub chain_id: u64,
    pub program_id: [u8; 32],
    pub rpc: String,
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
    source_cache: Mutex<HashMap<Address, u8>>,
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
            source_cache: Mutex::new(HashMap::new()),
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
    pub async fn verdict(
        &self,
        source_provider: &DynProvider,
        source_gate: Address,
        token: Address,
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

        let source = match self.source_scale(source_provider, source_gate, token).await? {
            Some(d) => d,
            None => return Ok(Verdict::Unknown("source gate did not report bridge decimals")),
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

    async fn source_scale(
        &self,
        provider: &DynProvider,
        gate: Address,
        token: Address,
    ) -> anyhow::Result<Option<u8>> {
        if let Some(d) = self.source_cache.lock().await.get(&token) {
            return Ok(Some(*d));
        }
        let out = match Gate::new(gate, provider).bridgeDecimalsOf(token).call().await {
            Ok(v) => v,
            Err(e) if is_definitive(&e) => {
                warn!(%gate, %token, error = %e, "source gate does not answer bridgeDecimalsOf");
                return Ok(None);
            }
            Err(e) => return Err(anyhow::anyhow!("reading source bridgeDecimalsOf on {gate}: {e}")),
        };
        // `set == false` on the source cannot happen for a token `send` accepted
        // (it converts through the same registration), so treat it as a lying or
        // wrong-address read rather than a corridor fact.
        if !out.set {
            warn!(%gate, %token, "source gate reports no bridge decimals for a token it just locked");
            return Ok(None);
        }
        self.source_cache.lock().await.insert(token, out.bridgeDecimals);
        Ok(Some(out.bridgeDecimals))
    }

    async fn evm_destination_scale(
        &self,
        dest: &Destination,
        debridge_id: B256,
    ) -> anyhow::Result<Option<u8>> {
        let gate = Gate::new(dest.gate, &dest.provider);
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
        // Transport faults (HTTP errors, rate limits, JSON-RPC errors) propagate
        // and are retried; what the account itself says is definitive.
        match self.solana_account(dest, &pda).await? {
            None => {
                warn!(
                    chain_id = dest.chain_id,
                    %debridge_id,
                    "Solana gate has no asset registered for this debridgeId"
                );
                Ok(None)
            }
            Some((owner, data)) => match solana_asset_scale(owner == program_b58, &data, &did) {
                Ok(d) => Ok(Some(d)),
                Err(why) => {
                    warn!(chain_id = dest.chain_id, %debridge_id, reason = why, "Solana asset account unusable");
                    Ok(None)
                }
            },
        }
    }

    /// `getAccountInfo` at `finalized`: the account's owner (base58) and raw data,
    /// or `None` when it does not exist.
    async fn solana_account(
        &self,
        dest: &SolanaDestination,
        address: &[u8; 32],
    ) -> anyhow::Result<Option<(String, Vec<u8>)>> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getAccountInfo",
            "params": [bs58::encode(address).into_string(), {"encoding": "base64", "commitment": "finalized"}],
        });
        let res = self.http.post(&dest.rpc).json(&body).send().await?;
        if !res.status().is_success() {
            anyhow::bail!("HTTP {}", res.status());
        }
        let bytes = res.bytes().await?;
        if bytes.len() > MAX_SOLANA_RESPONSE {
            anyhow::bail!("oversized getAccountInfo response ({} bytes)", bytes.len());
        }
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
            .verdict(&dead_provider(), Address::repeat_byte(1), Address::repeat_byte(2), 1338, B256::repeat_byte(3))
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
        let p = dead_provider();
        for _ in 0..3 {
            let _ = g.verdict(&p, Address::repeat_byte(1), Address::repeat_byte(2), 1338, B256::ZERO).await;
        }
        assert_eq!(g.warned.lock().await.len(), 1);
    }

    /// A read that fails IN TRANSIT must surface as `Err` — retried with the
    /// cursor rolled back — never as `Unknown`, which withholds and moves on for
    /// good. Here the source RPC refuses the connection outright.
    #[tokio::test]
    async fn a_transport_failure_is_retryable_not_a_withhold() {
        let g = ScaleGuard::new(
            vec![Destination { chain_id: 1338, gate: Address::repeat_byte(4), provider: dead_provider() }],
            vec![],
        );
        let r = g
            .verdict(&dead_provider(), Address::repeat_byte(1), Address::repeat_byte(2), 1338, B256::ZERO)
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
            vec![SolanaDestination { chain_id: 7565164, program_id: [9; 32], rpc: "http://127.0.0.1:1".into() }],
        );
        let _ = g
            .verdict(&dead_provider(), Address::repeat_byte(1), Address::repeat_byte(2), 7565164, B256::ZERO)
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
}

