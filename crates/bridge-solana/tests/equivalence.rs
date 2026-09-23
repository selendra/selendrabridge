//! Cross-chain hash + signature equivalence (Phase 8, the Solana analogue of
//! bridge-core's Phase-3 lock).
//!
//! 1. The Solana-side `hash` reproduces every Solidity/Rust submissionId in the
//!    shared Foundry fixtures — including the 32-byte-receiver (Solana) and the
//!    auto-params cases. If this fails, no validator signature would verify on
//!    the Solana gate.
//! 2. The Solana-side `verify` recovers the exact EVM address that signed, and
//!    the threshold check accepts real validator signatures — so the same
//!    signatures the keeper submits to the EVM gate are valid on the Solana gate.

mod common;

use std::path::PathBuf;

use alloy_primitives::{Address, B256, U256};
use bridge_solana::hash::{self, AutoParams};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Fixtures {
    fixtures: Vec<Fixture>,
}

#[derive(Debug, Deserialize)]
struct Fixture {
    name: String,
    #[serde(rename = "bridgeDomain")]
    bridge_domain: String,
    #[serde(rename = "debridgeId")]
    debridge_id: String,
    #[serde(rename = "bridgeDecimals")]
    bridge_decimals: u8,
    amount: String,
    #[serde(rename = "chainIdFrom")]
    chain_id_from: u64,
    #[serde(rename = "chainIdTo")]
    chain_id_to: u64,
    nonce: u64,
    receiver: String,
    #[serde(rename = "hasAuto")]
    has_auto: bool,
    #[serde(rename = "executionFee")]
    execution_fee: String,
    flags: String,
    #[serde(rename = "fallbackAddress")]
    fallback_address: String,
    data: String,
    #[serde(rename = "nativeSender")]
    native_sender: String,
    #[serde(rename = "submissionId")]
    submission_id: String,
}

fn bytes(h: &str) -> Vec<u8> {
    let s = h.strip_prefix("0x").unwrap_or(h);
    if s.is_empty() {
        return Vec::new();
    }
    hex::decode(s).expect("hex")
}

fn word(dec: &str) -> [u8; 32] {
    U256::from_str_radix(dec, 10).expect("dec").to_be_bytes::<32>()
}

fn arr32(h: &str) -> [u8; 32] {
    h.parse::<B256>().expect("b256").0
}

fn fixtures_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/fixtures/submission_ids.json")
}

#[test]
fn solana_hash_matches_solidity_fixtures_and_bridge_core() {
    let raw = std::fs::read_to_string(fixtures_path()).unwrap_or_else(|e| {
        panic!("read fixtures ({e}); run: forge test --match-contract GenFixtures")
    });
    let parsed: Fixtures = serde_json::from_str(&raw).expect("fixtures json");
    assert!(parsed.fixtures.len() >= 3, "expected >= 3 fixtures");

    for f in &parsed.fixtures {
        let bridge_domain = arr32(&f.bridge_domain);
        let debridge_id = arr32(&f.debridge_id);
        let amount = word(&f.amount);
        let receiver = bytes(&f.receiver);

        // Solana-side (this crate, sha3 + [u8;32] packing).
        let sol_id = if f.has_auto {
            let auto = AutoParams {
                execution_fee: word(&f.execution_fee),
                flags: word(&f.flags),
                fallback_address: bytes(&f.fallback_address),
                data: bytes(&f.data),
                native_sender: bytes(&f.native_sender),
            };
            hash::submission_id_with_auto(
                &bridge_domain,
                &debridge_id,
                f.bridge_decimals,
                &amount,
                f.chain_id_from,
                f.chain_id_to,
                f.nonce,
                &receiver,
                &auto,
            )
        } else {
            hash::submission_id(
                &bridge_domain,
                &debridge_id,
                f.bridge_decimals,
                &amount,
                f.chain_id_from,
                f.chain_id_to,
                f.nonce,
                &receiver,
            )
        };

        // EVM-side reference (bridge-core, alloy U256).
        let core_id = if f.has_auto {
            bridge_core::submission_id_with_auto(
                bridge_domain.into(),
                debridge_id.into(),
                f.bridge_decimals,
                U256::from_str_radix(&f.amount, 10).unwrap(),
                U256::from(f.chain_id_from),
                U256::from(f.chain_id_to),
                U256::from(f.nonce),
                &receiver,
                &bridge_core::AutoParams {
                    execution_fee: U256::from_str_radix(&f.execution_fee, 10).unwrap(),
                    flags: U256::from_str_radix(&f.flags, 10).unwrap(),
                    fallback_address: bytes(&f.fallback_address),
                    data: bytes(&f.data),
                    native_sender: bytes(&f.native_sender),
                },
            )
        } else {
            bridge_core::submission_id(
                bridge_domain.into(),
                debridge_id.into(),
                f.bridge_decimals,
                U256::from_str_radix(&f.amount, 10).unwrap(),
                U256::from(f.chain_id_from),
                U256::from(f.chain_id_to),
                U256::from(f.nonce),
                &receiver,
            )
        };

        let expected = arr32(&f.submission_id);
        assert_eq!(sol_id, expected, "fixture '{}': solana != solidity", f.name);
        assert_eq!(sol_id, core_id.0, "fixture '{}': solana != bridge-core", f.name);
    }
}

#[test]
fn solana_debridge_id_matches_bridge_core() {
    let token: [u8; 20] = [0x11; 20];
    let sol = hash::debridge_id(1337, &token);
    let core = bridge_core::debridge_id(U256::from(1337u64), Address::from(token));
    assert_eq!(sol, core.0);
}

#[tokio::test]
async fn verify_recovers_and_accepts_real_validator_signatures() {
    use bridge_solana::verify::{eth_signed_digest, recover_evm_address, verify_threshold, VerifyError};

    let v = common::Validator::random();
    let id = [0x7u8; 32];
    let sig = v.sign(&id).await;

    // Recovery yields the exact EVM signer address.
    let digest = eth_signed_digest(&id);
    assert_eq!(recover_evm_address(&digest, &sig).unwrap(), v.address());

    // Threshold accepts a known validator, rejects an unknown signer.
    let addr = v.address();
    assert_eq!(verify_threshold(&id, &[sig.clone()], |a| *a == addr, 1).unwrap(), 1);
    assert_eq!(
        verify_threshold(&id, &[sig], |_| false, 1).unwrap_err(),
        VerifyError::NotEnoughSignatures { got: 0, want: 1 }
    );
}
