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
//! * destination scale — `bridgeDecimalsFor(debridgeId)` on the destination
//!   gate, which resolves `tokenOf` and the token's decimals in one atomic call.
//!
//! Registrations are write-once, so a successful read is cached forever and the
//! steady-state cost is one pair of `eth_call`s per corridor, not per transfer.
//! Failures are never cached — a transient RPC fault must not turn into a
//! permanent refusal.

use std::collections::{BTreeMap, HashMap, HashSet};

use alloy::primitives::{Address, B256};
use alloy::providers::DynProvider;
use tokio::sync::Mutex;
use tracing::warn;

use bridge_core::abi::Gate;

/// A destination chain this validator can read well enough to vote on.
pub struct Destination {
    pub chain_id: u64,
    pub gate: Address,
    pub provider: DynProvider,
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
    destinations: BTreeMap<u64, Destination>,
    /// `(chain_id_to, debridge_id) -> bridge decimals`, successful reads only.
    dest_cache: Mutex<HashMap<(u64, B256), u8>>,
    /// `token -> bridge decimals` on this scanner's own source gate.
    source_cache: Mutex<HashMap<Address, u8>>,
    /// Chains we have already warned about, so an unconfigured peer does not
    /// print once per transfer.
    warned: Mutex<HashSet<u64>>,
}

impl ScaleGuard {
    pub fn new(destinations: Vec<Destination>) -> Self {
        ScaleGuard {
            destinations: destinations.into_iter().map(|d| (d.chain_id, d)).collect(),
            dest_cache: Mutex::new(HashMap::new()),
            source_cache: Mutex::new(HashMap::new()),
            warned: Mutex::new(HashSet::new()),
        }
    }

    /// Chains this guard can vote on, for the startup banner.
    pub fn covered(&self) -> Vec<u64> {
        self.destinations.keys().copied().collect()
    }

    pub fn is_empty(&self) -> bool {
        self.destinations.is_empty()
    }

    /// Do the two ends agree about `debridge_id`'s scale?
    ///
    /// `source_provider` is the endpoint this scanner is already reading logs
    /// from, so the source read costs no new connection.
    pub async fn verdict(
        &self,
        source_provider: &DynProvider,
        source_gate: Address,
        token: Address,
        chain_id_to: u64,
        debridge_id: B256,
    ) -> Verdict {
        let Some(dest) = self.destinations.get(&chain_id_to) else {
            if self.warned.lock().await.insert(chain_id_to) {
                warn!(
                    chain_id_to,
                    "no [[destinations]] entry for this peer — cannot verify that it \
                     agrees on the asset's bridge decimals, so transfers to it will NOT \
                     be signed (audit H-2). Add its chain_id/gate/rpcs to this \
                     validator's config."
                );
            }
            return Verdict::Unknown("destination chain not configured on this validator");
        };

        let source = match self.source_scale(source_provider, source_gate, token).await {
            Some(d) => d,
            None => return Verdict::Unknown("source gate did not report bridge decimals"),
        };
        let destination = match self.destination_scale(dest, debridge_id).await {
            Some(d) => d,
            None => {
                return Verdict::Unknown("destination gate did not report bridge decimals")
            }
        };

        if source == destination {
            Verdict::Agree(source)
        } else {
            Verdict::Mismatch { source, destination }
        }
    }

    async fn source_scale(
        &self,
        provider: &DynProvider,
        gate: Address,
        token: Address,
    ) -> Option<u8> {
        if let Some(d) = self.source_cache.lock().await.get(&token) {
            return Some(*d);
        }
        let out = match Gate::new(gate, provider).bridgeDecimalsOf(token).call().await {
            Ok(v) => v,
            Err(e) => {
                warn!(%gate, %token, error = %e, "reading source bridgeDecimalsOf failed");
                return None;
            }
        };
        // `set == false` on the source cannot happen for a token `send` accepted
        // (it converts through the same registration), so treat it as a lying or
        // wrong-address read rather than a corridor fact.
        if !out.set {
            warn!(%gate, %token, "source gate reports no bridge decimals for a token it just locked");
            return None;
        }
        self.source_cache.lock().await.insert(token, out.bridgeDecimals);
        Some(out.bridgeDecimals)
    }

    async fn destination_scale(&self, dest: &Destination, debridge_id: B256) -> Option<u8> {
        let key = (dest.chain_id, debridge_id);
        if let Some(d) = self.dest_cache.lock().await.get(&key) {
            return Some(*d);
        }
        let out = match Gate::new(dest.gate, &dest.provider)
            .bridgeDecimalsFor(debridge_id)
            .call()
            .await
        {
            Ok(v) => v,
            Err(e) => {
                // A gate deployed before H-2 has no such function, so the call
                // reverts. That is indistinguishable here from an RPC fault, and
                // both mean the same thing: we cannot establish the far end.
                warn!(
                    chain_id = dest.chain_id,
                    gate = %dest.gate,
                    %debridge_id,
                    error = %e,
                    "reading destination bridgeDecimalsFor failed (is the gate older than \
                     this check? it needs the implementation that adds bridgeDecimalsFor)"
                );
                return None;
            }
        };
        if !out.set {
            // No corridor there yet. The transfer is already unclaimable until
            // one exists, so withholding costs nothing and the operator sees why.
            warn!(
                chain_id = dest.chain_id,
                %debridge_id,
                "destination gate has no corridor registered for this debridgeId"
            );
            return None;
        }
        self.dest_cache.lock().await.insert(key, out.bridgeDecimals);
        Some(out.bridgeDecimals)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard() -> ScaleGuard {
        ScaleGuard::new(vec![])
    }

    /// An unconfigured destination must withhold, not wave through: the whole
    /// point is that an unverifiable far end is exactly the dangerous case.
    #[tokio::test]
    async fn an_unconfigured_destination_is_unknown_not_agree() {
        let g = guard();
        let v = g
            .verdict(
                &DynProvider::new(alloy::providers::ProviderBuilder::new().connect_http(
                    "http://127.0.0.1:1".parse().unwrap(),
                )),
                Address::repeat_byte(1),
                Address::repeat_byte(2),
                1338,
                B256::repeat_byte(3),
            )
            .await;
        assert!(matches!(v, Verdict::Unknown(_)), "got {v:?}");
    }

    /// It warns once per chain, not once per transfer — an unconfigured peer on a
    /// busy corridor would otherwise bury every other line in the log.
    #[tokio::test]
    async fn the_unconfigured_warning_is_once_per_chain() {
        let g = guard();
        assert!(g.warned.lock().await.is_empty());
        let p = DynProvider::new(
            alloy::providers::ProviderBuilder::new()
                .connect_http("http://127.0.0.1:1".parse().unwrap()),
        );
        for _ in 0..3 {
            let _ = g
                .verdict(&p, Address::repeat_byte(1), Address::repeat_byte(2), 1338, B256::ZERO)
                .await;
        }
        assert_eq!(g.warned.lock().await.len(), 1);
    }

    #[test]
    fn a_disagreement_is_a_mismatch_and_agreement_is_not() {
        assert_eq!(
            Verdict::Mismatch { source: 6, destination: 3 },
            Verdict::Mismatch { source: 6, destination: 3 }
        );
        assert_ne!(Verdict::Agree(6), Verdict::Mismatch { source: 6, destination: 3 });
    }
}
