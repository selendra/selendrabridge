//! End-to-end EVM ↔ Solana simulation, both directions, driven by real alloy
//! validator signatures.
//!
//! There is no Solana runtime in CI here, so this exercises the *exact* on-chain
//! verification path — [`SolanaGate`] (the program's brain) + the `verify`
//! (secp256k1_recover) and `hash` (keccak) logic a deployed program calls — plus
//! the off-chain relayer adapters, against real signatures produced the same way
//! the production validator produces them. It proves:
//!   * EVM → Solana: a threshold of validator sigs releases SPL on the Solana
//!     gate; replay is blocked; below-threshold and non-validator sigs are refused.
//!   * Solana → EVM: a Solana `send` emits a scannable log the validator parses
//!     and independently recomputes, and those signatures pass the EVM gate's
//!     verification rule.

mod common;

use alloy_primitives::{Address, U256};
use bridge_solana::gate::{GateError, Sent, SolanaGate};
use bridge_solana::instruction::GateInstruction;
use bridge_solana::relayer::{
    build_claim_instruction, parse_sent_log_line, sent_event_to_program_data_line, SentEvent,
};
use bridge_solana::verify::{eth_signed_digest, recover_evm_address, verify_threshold, VerifyError};
use bridge_solana::SOLANA_CHAIN_ID;
use common::Validator;

/// One deployment generation shared by the modelled EVM gate and Solana gate —
/// which is the point: an id only agrees across the two when the domain does.
const MESH_DOMAIN: [u8; 32] = [0xD0; 32];

const EVM_CHAIN_ID: u64 = 1337;

/// Sort signatures by recovered signer, strictly ascending — the order the gate
/// requires (both the Solana gate and Gate.sol).
fn sorted_sigs(id: &[u8; 32], sigs: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let digest = eth_signed_digest(id);
    let mut s = sigs;
    s.sort_by_key(|x| recover_evm_address(&digest, x).unwrap_or([0xff; 20]));
    s
}

/// The debridgeId of an EVM-native token on chain 1337 (same bytes on both sides).
fn evm_token_debridge_id(token: [u8; 20]) -> [u8; 32] {
    bridge_core::debridge_id(U256::from(EVM_CHAIN_ID), Address::from(token)).0
}

#[tokio::test]
async fn evm_to_solana_claim_release_replay_and_threshold() {
    // 3 independent validators; the Solana gate trusts the same EVM addresses.
    let vs = vec![Validator::random(), Validator::random(), Validator::random()];
    let addrs: Vec<[u8; 20]> = vs.iter().map(|v| v.address()).collect();
    let set = addrs.clone();

    let mut gate = SolanaGate::new(SOLANA_CHAIN_ID, MESH_DOMAIN, &addrs, 2);

    // Register the bridged asset and pre-fund the Solana vault (target-side liquidity).
    let token = [0xAB; 20];
    let debridge_id = evm_token_debridge_id(token);
    let spl_mint = [0x55; 32];
    gate.register_asset(debridge_id, spl_mint, 1_000_000);

    // --- EVM side: user sends 100 units to a 32-byte Solana token account -------
    let amount: u64 = 100_000;
    // The mesh's wire scale for this asset — inside the submissionId since H-2.
    const BRIDGE_DECIMALS: u8 = 6;
    let receiver: Vec<u8> = vec![0xCA; 32]; // Solana token account (32 bytes)
    let evm_sender: Vec<u8> = vec![0xBE; 20];
    let nonce = 0u64;

    // The id the EVM Gate.sol would emit (bridge-core == Solidity, proven by fixtures).
    let id = bridge_core::submission_id(
        MESH_DOMAIN.into(),
        debridge_id.into(),
        BRIDGE_DECIMALS,
        U256::from(amount),
        U256::from(EVM_CHAIN_ID),
        U256::from(SOLANA_CHAIN_ID),
        U256::from(nonce),
        &receiver,
    )
    .0;

    // The Solana gate must recompute the identical id.
    assert_eq!(
        gate.id_for(
            &debridge_id,
            amount,
            BRIDGE_DECIMALS,
            EVM_CHAIN_ID,
            SOLANA_CHAIN_ID,
            nonce,
            &receiver,
            None
        ),
        id,
        "solana gate recomputes a different submissionId than the EVM gate emitted"
    );

    let sent = Sent {
        submission_id: id,
        debridge_id,
        amount,
        bridge_decimals: BRIDGE_DECIMALS,
        chain_id_from: EVM_CHAIN_ID,
        chain_id_to: SOLANA_CHAIN_ID,
        receiver: receiver.clone(),
        nonce,
        native_sender: evm_sender,
        auto: None,
    };

    // Validators 0 and 1 attest (threshold 2 of 3).
    let sigs = sorted_sigs(&id, vec![vs[0].sign(&id).await, vs[1].sign(&id).await]);

    // Keeper's Borsh claim instruction round-trips and re-derives the same id.
    let ix_bytes = build_claim_instruction(&sent, sigs.clone()).unwrap();
    match GateInstruction::try_from_bytes(&ix_bytes).unwrap() {
        GateInstruction::Claim(args) => {
            let re = gate.id_for(
                &args.debridge_id,
                args.amount,
                args.bridge_decimals,
                args.chain_id_from,
                SOLANA_CHAIN_ID,
                args.nonce,
                &args.receiver,
                None,
            );
            assert_eq!(re, id, "decoded claim instruction re-derives a different id");
        }
        other => panic!("expected Claim, got {other:?}"),
    }

    // Claim releases the SPL to the receiver, exactly once.
    let vault_before = gate.vault_balance(&debridge_id);
    let claimed = gate
        .claim(debridge_id, amount, BRIDGE_DECIMALS, EVM_CHAIN_ID, nonce, receiver.clone(), None, &sigs)
        .expect("2-of-3 claim should succeed");
    assert_eq!(claimed.amount, amount);
    assert_eq!(gate.token_accounts.get(&[0xCA; 32]).copied(), Some(amount));
    assert_eq!(gate.vault_balance(&debridge_id), vault_before - amount);

    // Replay is blocked.
    assert_eq!(
        gate.claim(debridge_id, amount, BRIDGE_DECIMALS, EVM_CHAIN_ID, nonce, receiver.clone(), None, &sigs).unwrap_err(),
        GateError::AlreadyExecuted
    );

    // --- Below-threshold and non-validator safety (a second transfer) ----------
    let nonce2 = 1u64;
    let receiver2: Vec<u8> = vec![0xDD; 32];
    let id2 = gate.id_for(
        &debridge_id,
        amount,
        BRIDGE_DECIMALS,
        EVM_CHAIN_ID,
        SOLANA_CHAIN_ID,
        nonce2,
        &receiver2,
        None,
    );

    // Only one validator signs -> refused, nothing released.
    let one = sorted_sigs(&id2, vec![vs[0].sign(&id2).await]);
    assert!(matches!(
        gate.claim(debridge_id, amount, BRIDGE_DECIMALS, EVM_CHAIN_ID, nonce2, receiver2.clone(), None, &one).unwrap_err(),
        GateError::Verify(VerifyError::NotEnoughSignatures { got: 1, want: 2 })
    ));
    assert_eq!(gate.token_accounts.get(&[0xDD; 32]).copied(), None);

    // One validator + one outsider = still one valid signature -> refused.
    let outsider = Validator::random();
    let mixed = sorted_sigs(&id2, vec![vs[0].sign(&id2).await, outsider.sign(&id2).await]);
    assert!(matches!(
        gate.claim(debridge_id, amount, BRIDGE_DECIMALS, EVM_CHAIN_ID, nonce2, receiver2.clone(), None, &mixed).unwrap_err(),
        GateError::Verify(VerifyError::NotEnoughSignatures { got: 1, want: 2 })
    ));

    // Recovery: the second validator returns -> threshold met -> released.
    let two = sorted_sigs(&id2, vec![vs[0].sign(&id2).await, vs[1].sign(&id2).await]);
    gate
        .claim(debridge_id, amount, BRIDGE_DECIMALS, EVM_CHAIN_ID, nonce2, receiver2, None, &two)
        .expect("recovered 2-of-3 claim should succeed");
    assert_eq!(gate.token_accounts.get(&[0xDD; 32]).copied(), Some(amount));

    // Sanity: the whole set really is 3 distinct validators.
    assert_eq!(set.iter().collect::<std::collections::BTreeSet<_>>().len(), 3);
    println!(
        "EVM->Solana OK: 2-of-3 released {amount} to Solana acct; replay blocked; 1-of-3 refused"
    );
}

#[tokio::test]
async fn solana_to_evm_send_scan_and_evm_verification() {
    let vs = vec![Validator::random(), Validator::random(), Validator::random()];
    let addrs: Vec<[u8; 20]> = vs.iter().map(|v| v.address()).collect();
    let evm_validator_set = addrs.clone();
    let threshold = 2u32;

    // A Solana gate that also lets users send SPL out to EVM.
    let mut gate = SolanaGate::new(SOLANA_CHAIN_ID, MESH_DOMAIN, &addrs, threshold);
    let token = [0xAB; 20];
    let debridge_id = evm_token_debridge_id(token);
    gate.register_asset(debridge_id, [0x55; 32], 0);

    // --- Solana side: lock SPL, emit a Sent to a 20-byte EVM receiver ----------
    let amount: u64 = 42_000;
    const SOL_BRIDGE_DECIMALS: u8 = 9;
    let evm_receiver: Vec<u8> = vec![0xEE; 20];
    let solana_sender: Vec<u8> = vec![0x11; 32];
    let sent = gate
        .send(
            debridge_id,
            amount,
            SOL_BRIDGE_DECIMALS,
            EVM_CHAIN_ID,
            evm_receiver.clone(),
            solana_sender,
            None,
        )
        .expect("solana send");
    assert_eq!(sent.chain_id_from, SOLANA_CHAIN_ID);
    assert_eq!(sent.chain_id_to, EVM_CHAIN_ID);
    assert_eq!(gate.vault_balance(&debridge_id), amount, "SPL should be locked in the vault");

    // --- Validator's Solana source: find & parse the Sent among program logs ---
    // The program emits its Sent through `sol_log_data`, which the runtime prints
    // as a `Program data: <b64> <b64>` line. `[0x55; 32]` is the locked mint the
    // gate registered above — carried in the event as the asset identity (H5).
    let mint = [0x55u8; 32];
    let logs = [
        "Program log: instruction: Send".to_string(),
        sent_event_to_program_data_line(&SentEvent::from_sent(&sent, mint)),
        "Program consumed 4242 compute units".to_string(),
    ];
    let parsed = logs
        .iter()
        .find_map(|l| parse_sent_log_line(l))
        .expect("a BRIDGE_SENT line")
        .expect("parses");
    assert_eq!(parsed, sent, "log round-trip must be lossless");

    // Independent recompute (validator never trusts the emitted id): matches the
    // EVM formula for chainFrom=Solana, chainTo=EVM.
    let recomputed = bridge_core::submission_id(
        MESH_DOMAIN.into(),
        debridge_id.into(),
        SOL_BRIDGE_DECIMALS,
        U256::from(amount),
        U256::from(SOLANA_CHAIN_ID),
        U256::from(EVM_CHAIN_ID),
        U256::from(parsed.nonce),
        &evm_receiver,
    )
    .0;
    assert_eq!(recomputed, parsed.submission_id, "recomputed id != emitted id");

    // --- Validators sign; the EVM gate's verification rule must accept them -----
    let id = parsed.submission_id;
    let two = sorted_sigs(&id, vec![vs[0].sign(&id).await, vs[2].sign(&id).await]);

    // verify_threshold mirrors Gate.sol::_verifySignatures byte-for-byte, so this
    // passing means the EVM claim() would succeed (also covered by Claim.t.sol).
    let count = verify_threshold(&id, &two, |a| evm_validator_set.contains(a), threshold)
        .expect("EVM gate would accept 2-of-3");
    assert_eq!(count, 2);

    // One signature is below threshold -> the EVM claim would revert.
    let one = sorted_sigs(&id, vec![vs[0].sign(&id).await]);
    assert_eq!(
        verify_threshold(&id, &one, |a| evm_validator_set.contains(a), threshold).unwrap_err(),
        VerifyError::NotEnoughSignatures { got: 1, want: 2 }
    );

    println!("Solana->EVM OK: locked {amount} SPL; validator parsed+recomputed; 2-of-3 valid for EVM claim");
}
