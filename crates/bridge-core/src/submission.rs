//! The `Submission` — the off-chain mirror of a `Sent` event, plus the
//! independent recomputation of its `submissionId`.

use alloy_primitives::{B256, U256};

use crate::{submission_id, submission_id_with_auto, AutoParams};

/// All parameters of a single cross-chain transfer, as read from a `Sent` event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Submission {
    /// Deployment generation this transfer belongs to — the `bridgeDomain()` of
    /// the gate that emitted it. Read from the gate rather than configured, so a
    /// stale config can never make a validator sign for the wrong generation.
    pub bridge_domain: B256,
    pub debridge_id: B256,
    /// Wire scale `amount` is denominated in, as the SOURCE gate registered it
    /// (H-2). Inside the id, so recomputing with any other value produces an id
    /// the gate never minted — which is what a scale mis-registration now looks
    /// like everywhere, instead of a payout off by a power of ten.
    pub bridge_decimals: u8,
    pub amount: U256,
    pub chain_id_from: U256,
    pub chain_id_to: U256,
    pub nonce: U256,
    pub receiver: Vec<u8>,
    /// `None` for a plain transfer; `Some` when an execution payload is attached.
    pub auto: Option<AutoParams>,
}

impl Submission {
    /// Recompute the submissionId from these parameters (never trust the emitted one).
    pub fn compute_id(&self) -> B256 {
        match &self.auto {
            None => submission_id(
                self.bridge_domain,
                self.debridge_id,
                self.bridge_decimals,
                self.amount,
                self.chain_id_from,
                self.chain_id_to,
                self.nonce,
                &self.receiver,
            ),
            Some(auto) => submission_id_with_auto(
                self.bridge_domain,
                self.debridge_id,
                self.bridge_decimals,
                self.amount,
                self.chain_id_from,
                self.chain_id_to,
                self.nonce,
                &self.receiver,
                auto,
            ),
        }
    }
}

/// Build the independent `Submission` a validator recomputes an id from, out of
/// a decoded `Gate.Sent` event.
///
/// An `autoParams` blob that fails to decode yields `auto: None` — deliberately.
/// The resulting id is then the plain-transfer hash, which cannot match the
/// emitted one for a transfer that really carries a payload, so the caller's
/// id check refuses to sign it. Failing the comparison is the fail-closed
/// outcome; guessing at a payload we could not parse would not be.
#[cfg(feature = "abi")]
impl Submission {
    pub fn from_sent_event(ev: &crate::abi::Gate::Sent, bridge_domain: B256) -> Self {
        Submission {
            bridge_domain,
            debridge_id: ev.debridgeId,
            bridge_decimals: ev.bridgeDecimals,
            amount: ev.amount,
            chain_id_from: ev.chainIdFrom,
            chain_id_to: ev.chainIdTo,
            nonce: ev.nonce,
            receiver: ev.receiver.to_vec(),
            auto: crate::decode_auto_params(&ev.autoParams, &ev.nativeSender)
                .ok()
                .flatten(),
        }
    }
}
