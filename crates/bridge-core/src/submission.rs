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
/// `Err` when the event carries an `autoParams` blob that does not decode. It
/// used to be folded into `auto: None` (audit round 7, L7-2) — exactly what
/// [`crate::decode_auto_params`] says a caller must never do. That still failed
/// closed (the plain-transfer id cannot match a with-payload one), but the
/// validator answers an id MISMATCH by pausing its scanner, so one user able to
/// emit a payload our decoder rejects could halt every validator at once. The
/// caller now sees "undecodable" as its own outcome and decides: the validator
/// refuses to sign that one event and moves on.
#[cfg(feature = "abi")]
impl Submission {
    pub fn from_sent_event(
        ev: &crate::abi::Gate::Sent,
        bridge_domain: B256,
    ) -> Result<Self, alloy::sol_types::Error> {
        Ok(Submission {
            bridge_domain,
            debridge_id: ev.debridgeId,
            bridge_decimals: ev.bridgeDecimals,
            amount: ev.amount,
            chain_id_from: ev.chainIdFrom,
            chain_id_to: ev.chainIdTo,
            nonce: ev.nonce,
            receiver: ev.receiver.to_vec(),
            auto: crate::decode_auto_params(&ev.autoParams, &ev.nativeSender)?,
        })
    }
}

#[cfg(all(test, feature = "abi"))]
mod tests {
    use super::*;
    use crate::abi::Gate;
    use alloy::primitives::{Address, Bytes};

    fn sent(auto_params: Vec<u8>) -> Gate::Sent {
        Gate::Sent {
            submissionId: B256::repeat_byte(1),
            debridgeId: B256::repeat_byte(2),
            amount: U256::from(5u64),
            bridgeDecimals: 6,
            chainIdFrom: U256::from(1u64),
            chainIdTo: U256::from(2u64),
            receiver: Bytes::from(vec![0xAB; 20]),
            nonce: U256::from(3u64),
            autoParams: Bytes::from(auto_params),
            nativeSender: Bytes::from(vec![0xCD; 20]),
            token: Address::repeat_byte(9),
        }
    }

    /// L7-2: an undecodable payload is an ERROR, never a plain transfer.
    #[test]
    fn an_undecodable_auto_params_blob_is_an_error_not_a_plain_transfer() {
        let r = Submission::from_sent_event(&sent(vec![0xFF; 7]), B256::ZERO);
        assert!(r.is_err(), "garbage autoParams must not fold into auto: None, got {r:?}");
    }

    #[test]
    fn an_empty_blob_is_a_plain_transfer_and_a_valid_one_decodes() {
        let plain = Submission::from_sent_event(&sent(vec![]), B256::ZERO).unwrap();
        assert!(plain.auto.is_none());

        use alloy::sol_types::SolValue;
        let ap = crate::abi::AutoParamsTo {
            executionFee: U256::from(7u64),
            flags: U256::from(1u64),
            fallbackAddress: Bytes::from(vec![0x11; 20]),
            data: Bytes::from(vec![0x22; 4]),
        };
        let with = Submission::from_sent_event(&sent(ap.abi_encode()), B256::ZERO).unwrap();
        let auto = with.auto.expect("a valid blob decodes to a payload");
        assert_eq!(auto.execution_fee, U256::from(7u64));
        assert_eq!(auto.native_sender, vec![0xCD; 20]);
    }
}
