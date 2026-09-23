//! Fixture generator + check for the browser's transaction encoding.
//!
//! The frontend builds its own Solana swap transaction by hand (no web3.js), for
//! the reason stated in `frontend/src/wallet/solana.ts`: every account that
//! decides where the money goes must be derived in the browser. Hand-rolled
//! encoding needs something to be checked against, so this test builds the SAME
//! transaction through `solana-sdk` and writes the bytes to
//! `contracts/fixtures/solana_swap_tx.json`, which
//! `frontend/e2e/unit/solana.spec.ts` then asserts against.
//!
//! Regenerate with:
//!     cargo test --manifest-path crates/solana-relayer/Cargo.toml --test swap_message_fixture

use std::str::FromStr;

use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::message::Message;
use solana_sdk::pubkey::Pubkey;
use solana_swap::SwapInstruction;

/// Fixed, meaningless-but-valid inputs: the point is byte equality, not realism.
const PROGRAM: &str = "E28r29Hyky3UqVBcdSvFk6qNedbRN8X2z4R8hYGDUk88";
const USER: &str = "EgZc1wGaqZXYn6jy7oSRe95qWmp2NM9SRxXJWjhxuGkC";
const MINT_IN: &str = "8T2cxAqp8mDNkdTTb5giew9eYgZ7NmHdEWz6kMeE7WFV";
const MINT_OUT: &str = "Bqt4xDpu6oEPgTgVLjZVQ56hFUGo2F4M8zFuK98NHe32";
const VAULT_IN: &str = "FtnmRC62mfLeW5PE2vRU2mFi5skpa36K7EnHqfaAXryk";
const VAULT_OUT: &str = "66UA92nBYZHQQ9Rb8rCMEKdeeNJq9CLwRcnWizqPFfDY";
const USER_IN: &str = "3DJhoSoK6qAvuwF3DBh7VRJEf4oroUwCDu598nruk2Tn";
const USER_OUT: &str = "C2kdxNXY43h5ss3TfrD6Q6AXjzZ1DJ1bd964xKb6pzBy";
const BLOCKHASH: &str = "11111111111111111111111111111111";
const AMOUNT_IN: u64 = 100_000_000;
const MIN_OUT: u64 = 31_289_307;

#[test]
fn write_browser_transaction_fixture() {
    let program = Pubkey::from_str(PROGRAM).unwrap();
    let user = Pubkey::from_str(USER).unwrap();
    let mint_in = Pubkey::from_str(MINT_IN).unwrap();
    let mint_out = Pubkey::from_str(MINT_OUT).unwrap();

    let (pool, _) = Pubkey::find_program_address(&[b"pool"], &program);
    let (rec_in, _) = Pubkey::find_program_address(&[b"token", mint_in.as_ref()], &program);
    let (rec_out, _) = Pubkey::find_program_address(&[b"token", mint_out.as_ref()], &program);
    let (authority, _) = Pubkey::find_program_address(&[b"vault_authority"], &program);

    let ix = Instruction {
        program_id: program,
        accounts: vec![
            AccountMeta::new_readonly(pool, false),
            AccountMeta::new_readonly(user, true),
            AccountMeta::new(rec_in, false),
            AccountMeta::new(rec_out, false),
            AccountMeta::new(Pubkey::from_str(USER_IN).unwrap(), false),
            AccountMeta::new(Pubkey::from_str(USER_OUT).unwrap(), false),
            AccountMeta::new(Pubkey::from_str(VAULT_IN).unwrap(), false),
            AccountMeta::new(Pubkey::from_str(VAULT_OUT).unwrap(), false),
            AccountMeta::new_readonly(mint_in, false),
            AccountMeta::new_readonly(mint_out, false),
            AccountMeta::new_readonly(authority, false),
            AccountMeta::new_readonly(spl_token_id(), false),
        ],
        data: SwapInstruction::Swap { amount_in: AMOUNT_IN, min_amount_out: MIN_OUT }.to_bytes(),
    };

    let mut msg = Message::new(&[ix.clone()], Some(&user));
    msg.recent_blockhash = solana_sdk::hash::Hash::from_str(BLOCKHASH).unwrap();
    let serialized = msg.serialize();

    let json = serde_json::json!({
        "program": PROGRAM, "user": USER,
        "mintIn": MINT_IN, "mintOut": MINT_OUT,
        "vaultIn": VAULT_IN, "vaultOut": VAULT_OUT,
        "userIn": USER_IN, "userOut": USER_OUT,
        "blockhash": BLOCKHASH,
        "amountIn": AMOUNT_IN.to_string(), "minAmountOut": MIN_OUT.to_string(),
        // The addresses the browser must derive for itself.
        "poolPda": pool.to_string(),
        "recordInPda": rec_in.to_string(),
        "recordOutPda": rec_out.to_string(),
        "vaultAuthority": authority.to_string(),
        // And the bytes it must produce.
        "instructionData": hex::encode(&ix.data),
        "message": hex::encode(&serialized),
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/fixtures/solana_swap_tx.json");
    std::fs::write(&path, serde_json::to_string_pretty(&json).unwrap()).expect("write fixture");
    println!("wrote {}", path.display());
}

/// The gate `send` the Bridge view builds — same purpose as the swap fixture:
/// the browser derives the `["sent", submissionId]` PDA from an id it computes
/// itself, so both the id and the instruction bytes need pinning against the
/// implementations that already agree (bridge-core's hash, solana-sdk's message).
#[test]
fn write_gate_send_fixture() {
    use bridge_solana::instruction::{GateInstruction, SendArgs};

    const GATE: &str = "HvGQTWChe6bMpSYGNavDhGcG8YrJkubJQCDmBrxNR133";
    const VAULT: &str = "33A9xPRuLjv8NBrp5XjjdU22yfXdNx6vGczW9XY3bpgb";
    const USER_TOKEN: &str = "3DJhoSoK6qAvuwF3DBh7VRJEf4oroUwCDu598nruk2Tn";
    // A 20-byte EVM receiver, the normal Solana -> EVM direction.
    const RECEIVER: &str = "addd30479698216b0c2ee967cbc115917eefe243";
    const DOMAIN: &str = "619244a655e7383c05da63e9d66080952fcfe4fc48b40c61f566996006848055";
    const DEBRIDGE_ID: &str = "4b7347216b2c2ce2879cf0086a2bd0ad84a4df90c1d0d1e665041ba0bc157454";
    const SOLANA_CHAIN: u64 = 7565164;
    const CHAIN_TO: u64 = 11155111;
    const NONCE: u64 = 3;
    // A 9-decimal mint bridged at 6 decimals: the instruction carries the MINT
    // amount, the submissionId hashes it divided by the bridge unit. A browser
    // that hashed the mint amount would derive a `sent` PDA the program refuses.
    const AMOUNT: u64 = 2_000_000_000;
    const BRIDGE_UNIT: u64 = 1_000;
    /// The wire scale the unit above implies, and — since H-2 — part of the id.
    const BRIDGE_DECIMALS: u8 = 6;

    let program = Pubkey::from_str(GATE).unwrap();
    let user = Pubkey::from_str(USER).unwrap();
    let receiver = hex::decode(RECEIVER).unwrap();
    let debridge_id: [u8; 32] = hex::decode(DEBRIDGE_ID).unwrap().try_into().unwrap();
    let domain: [u8; 32] = hex::decode(DOMAIN).unwrap().try_into().unwrap();

    // The id through the SHARED implementation — the one pinned to the Solidity
    // fixtures — so the browser's copy is checked against the real thing.
    let id = bridge_solana::hash::submission_id(
        &domain,
        &debridge_id,
        BRIDGE_DECIMALS,
        &bridge_solana::hash::amount_word((AMOUNT / BRIDGE_UNIT) as u128),
        SOLANA_CHAIN,
        CHAIN_TO,
        NONCE,
        &receiver,
    );

    let (config, _) = Pubkey::find_program_address(&[b"config"], &program);
    let (asset, _) = Pubkey::find_program_address(&[b"asset", &debridge_id], &program);
    let (sent, _) = Pubkey::find_program_address(&[b"sent", &id], &program);

    let ix = Instruction {
        program_id: program,
        accounts: vec![
            AccountMeta::new(config, false),
            AccountMeta::new_readonly(asset, false),
            AccountMeta::new(user, true),
            AccountMeta::new(Pubkey::from_str(USER_TOKEN).unwrap(), false),
            AccountMeta::new(Pubkey::from_str(VAULT).unwrap(), false),
            AccountMeta::new_readonly(spl_token_id(), false),
            AccountMeta::new(sent, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
        data: GateInstruction::Send(SendArgs {
            debridge_id,
            amount: AMOUNT,
            chain_id_to: CHAIN_TO,
            receiver: receiver.clone(),
            auto: None,
        })
        .to_bytes(),
    };

    let mut msg = Message::new(&[ix.clone()], Some(&user));
    msg.recent_blockhash = solana_sdk::hash::Hash::from_str(BLOCKHASH).unwrap();

    let json = serde_json::json!({
        "program": GATE, "user": USER, "userToken": USER_TOKEN, "vault": VAULT,
        "receiver": format!("0x{RECEIVER}"),
        "bridgeDomain": format!("0x{DOMAIN}"),
        "debridgeId": format!("0x{DEBRIDGE_ID}"),
        "solanaChainId": SOLANA_CHAIN, "chainIdTo": CHAIN_TO,
        "nonce": NONCE, "amount": AMOUNT.to_string(), "bridgeUnit": BRIDGE_UNIT.to_string(),
        "bridgeDecimals": BRIDGE_DECIMALS,
        "blockhash": BLOCKHASH,
        "submissionId": format!("0x{}", hex::encode(id)),
        "configPda": config.to_string(),
        "assetPda": asset.to_string(),
        "sentPda": sent.to_string(),
        "instructionData": hex::encode(&ix.data),
        "message": hex::encode(msg.serialize()),
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/fixtures/solana_gate_send_tx.json");
    std::fs::write(&path, serde_json::to_string_pretty(&json).unwrap()).expect("write fixture");
}

fn spl_token_id() -> Pubkey {
    Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap()
}
