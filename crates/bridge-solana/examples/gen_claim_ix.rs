//! Generate the on-chain instruction bytes + real validator signatures for the
//! localnet EVM→Solana claim test (driven by `scripts/solana-localnet-e2e.sh`).
//!
//! Usage: `gen_claim_ix <receiver_token_pubkey_hex_32bytes>`
//! Prints a JSON blob the Node harness feeds to the deployed `solana-gate`.
//!
//! Everything is fixed except the receiver token account (only known once the
//! harness has created it on the cluster), which is passed in.

use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use bridge_solana::hash::{self, amount_word};
use bridge_solana::instruction::{ClaimArgs, GateInstruction, InitArgs};
use bridge_solana::verify::{eth_signed_digest, recover_evm_address};
use bridge_solana::SOLANA_CHAIN_ID;

const EVM_CHAIN_ID: u64 = 1337;
const AMOUNT: u64 = 1000;
/// The asset's wire scale — part of the submissionId since H-2, and what the
/// destination gate's own registration must equal for the claim to settle.
const BRIDGE_DECIMALS: u8 = 6;
/// Deployment generation for the localnet mesh. This same value initializes the
/// gate below AND goes into the submissionId, so the two cannot drift. A real
/// deployment must use a fresh value per generation, or a superseded
/// generation's attestations stay valid against the new gates.
const LOCALNET_BRIDGE_DOMAIN: [u8; 32] = [0xD0; 32];

fn validator(seed: u8) -> PrivateKeySigner {
    let mut key = [0u8; 32];
    key[31] = seed;
    PrivateKeySigner::from_bytes(&key.into()).expect("valid key")
}

async fn sign65(signer: &PrivateKeySigner, id: &[u8; 32]) -> Vec<u8> {
    let sig = signer.sign_message(id).await.expect("sign");
    bridge_core::signer::signature_bytes(&sig).to_vec()
}

#[tokio::main]
async fn main() {
    // args: <receiver_pubkey_hex> [num_sigs=2] [nonce=0]
    let arg = std::env::args().nth(1).expect("receiver pubkey hex arg");
    let receiver = hex::decode(arg.strip_prefix("0x").unwrap_or(&arg)).expect("hex");
    assert_eq!(receiver.len(), 32, "receiver must be a 32-byte pubkey");
    let num_sigs: usize = std::env::args().nth(2).map(|s| s.parse().unwrap()).unwrap_or(2);
    let nonce: u64 = std::env::args().nth(3).map(|s| s.parse().unwrap()).unwrap_or(0);

    // Three deterministic validators; the Solana gate is initialized with these.
    let vs = [validator(1), validator(2), validator(3)];
    let validators: Vec<[u8; 20]> = vs.iter().map(|v| v.address().into_array()).collect();

    let debridge_id = hash::debridge_id(EVM_CHAIN_ID, &[0xAB; 20]);
    let native_sender = vec![0xBE; 20];

    // The id the EVM gate emitted (chainFrom=EVM, chainTo=Solana), recomputed on chain.
    let id = hash::submission_id(
        &LOCALNET_BRIDGE_DOMAIN,
        &debridge_id,
        BRIDGE_DECIMALS,
        &amount_word(AMOUNT as u128),
        EVM_CHAIN_ID,
        SOLANA_CHAIN_ID,
        nonce,
        &receiver,
    );

    // `num_sigs` validators attest; sort ascending by signer as the gate requires.
    let mut sigs = Vec::new();
    for v in vs.iter().take(num_sigs) {
        sigs.push(sign65(v, &id).await);
    }
    let digest = eth_signed_digest(&id);
    sigs.sort_by_key(|s| recover_evm_address(&digest, s).unwrap());

    let init_ix = GateInstruction::Init(InitArgs {
        bridge_domain: LOCALNET_BRIDGE_DOMAIN,
        validators: validators.clone(),
        threshold: 2,
        chain_id: SOLANA_CHAIN_ID,
        // Capacities are fixed at init and size the config account (H-3 / L-3).
        // Headroom for a few validator rotations and destination chains.
        max_validators: 8,
        max_corridors: 8,
        guardian: [0u8; 32], // none appointed in this fixture
    })
    .to_bytes();

    let claim_ix = GateInstruction::Claim(ClaimArgs {
        debridge_id,
        amount: AMOUNT,
        bridge_decimals: BRIDGE_DECIMALS,
        chain_id_from: EVM_CHAIN_ID,
        nonce,
        receiver: receiver.clone(),
        auto: None,
        native_sender,
        signatures: sigs,
    })
    .to_bytes();

    let out = serde_json::json!({
        "amount": AMOUNT,
        "submission_id": format!("0x{}", hex::encode(id)),
        "debridge_id": format!("0x{}", hex::encode(debridge_id)),
        "validators": validators.iter().map(|v| format!("0x{}", hex::encode(v))).collect::<Vec<_>>(),
        "init_ix": format!("0x{}", hex::encode(init_ix)),
        "claim_ix": format!("0x{}", hex::encode(claim_ix)),
    });
    println!("{}", serde_json::to_string(&out).unwrap());
}
