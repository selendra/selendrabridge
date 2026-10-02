//! Audit round 7, LOW — regression tests for two findings in the native program.
//!
//! L7-3: `Config::store` overwrote only the new body, so a body that SHRANK (a
//!       validator removal, -20 bytes) left its old tail in the slack that every
//!       appended field relies on reading as zero. Fixed: the remainder of the
//!       account is zeroed on every store.
//! L7-4: Solana's 1232-byte packet limit caps how many 69-byte signatures one
//!       `claim`/`cancel`/`refund` can carry. Fixed: the threshold is capped at
//!       `MAX_THRESHOLD` (init + `set_threshold`), and the relayer sends exactly
//!       `threshold` signatures. The cap is MEASURED here against the relayer's
//!       transaction shape, so it cannot drift from the bytes it protects.
use borsh::BorshSerialize;
use solana_program::instruction::{AccountMeta, Instruction};
use solana_program::pubkey::Pubkey;
use solana_program_test::{processor, ProgramTest, ProgramTestContext};
use solana_sdk::account::Account;
use solana_sdk::compute_budget::ComputeBudgetInstruction;
use solana_sdk::hash::Hash;
use solana_sdk::signature::{Keypair, Signer};
use solana_sdk::transaction::{Transaction, TransactionError};

use solana_gate::{
    process_instruction, AutoParamsWire, CancelArgs, ClaimArgs, Config, GateInstruction, RefundArgs,
    MAX_THRESHOLD,
};

const PROGRAM_ID: Pubkey = Pubkey::new_from_array([7u8; 32]);
/// `GateError::ThresholdTooHigh`.
const THRESHOLD_TOO_HIGH: u32 = 29;
/// Solana's maximum serialized transaction size (`PACKET_DATA_SIZE`).
const PACKET_DATA_SIZE: usize = 1232;
/// The program's `CONFIG_SLACK`.
const CONFIG_SLACK: usize = 64;

fn pda(seeds: &[&[u8]]) -> Pubkey {
    Pubkey::find_program_address(seeds, &PROGRAM_ID).0
}
fn config_pda() -> Pubkey {
    pda(&[b"config"])
}

/// `config_space` as the program computes it, `sealed` + `setup_deadline` included.
fn config_space(validators: u32, corridors: u32) -> usize {
    32 + 32 + 32 + (4 + 20 * validators as usize) + 4 + 8 + 1 + 4 + 4 + (4 + 16 * corridors as usize) + 1 + 8
}

fn validator(i: u8) -> [u8; 20] {
    [i; 20]
}

/// A gate allocated the way `init` allocates one (capacity + slack), whose body
/// TAIL is deliberately non-zero: corridor nonces, `sealed = true` and a
/// non-zero `setup_deadline` — exactly the bytes a shrink used to strand.
fn gate(owner: &Keypair, validators: Vec<[u8; 20]>, threshold: u32) -> ProgramTest {
    let mut pt = ProgramTest::new("solana_gate", PROGRAM_ID, processor!(process_instruction));
    pt.add_account(
        owner.pubkey(),
        Account {
            lamports: 10_000_000_000,
            data: vec![],
            owner: solana_sdk::system_program::id(),
            executable: false,
            rent_epoch: 0,
        },
    );
    let cfg = Config {
        owner: owner.pubkey(),
        bridge_domain: [0xD0; 32],
        guardian: Pubkey::default(),
        validators,
        threshold,
        chain_id: 7565164,
        paused: false,
        max_validators: 12,
        max_corridors: 4,
        nonce_to: vec![(1337, 0xAAAA_AAAA_AAAA_AAAA), (1338, 0x5555_5555_5555_5555)],
        sealed: true,
        setup_deadline: 0x7777_7777_7777_7777,
    };
    let mut data = vec![0u8; config_space(12, 4) + CONFIG_SLACK];
    cfg.serialize(&mut &mut data[..]).unwrap();
    pt.add_account(
        config_pda(),
        Account { lamports: 10_000_000_000, data, owner: PROGRAM_ID, executable: false, rent_epoch: 0 },
    );
    pt
}

async fn exec(ctx: &mut ProgramTestContext, i: Instruction, extra: &[&Keypair]) -> Result<(), TransactionError> {
    let bh = ctx.get_new_latest_blockhash().await.unwrap_or(ctx.last_blockhash);
    let mut signers: Vec<&Keypair> = vec![&ctx.payer];
    signers.extend_from_slice(extra);
    let tx = Transaction::new_signed_with_payer(&[i], Some(&ctx.payer.pubkey()), &signers, bh);
    ctx.banks_client.process_transaction(tx).await.map_err(|e| match e {
        solana_program_test::BanksClientError::TransactionError(te) => te,
        other => panic!("unexpected banks error: {other:?}"),
    })
}

fn is_custom(err: &TransactionError, code: u32) -> bool {
    matches!(err, TransactionError::InstructionError(_, solana_sdk::instruction::InstructionError::Custom(c)) if *c == code)
}

fn owner_ix(owner: Pubkey, data: GateInstruction) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![AccountMeta::new(config_pda(), false), AccountMeta::new_readonly(owner, true)],
        data: borsh::to_vec(&data).unwrap(),
    }
}

async fn config_bytes(ctx: &mut ProgramTestContext) -> Vec<u8> {
    ctx.banks_client.get_account(config_pda()).await.unwrap().unwrap().data
}

// ---------------------------------------------------------------------------
// L7-3
// ---------------------------------------------------------------------------

/// A validator removal shrinks the body by 20 bytes. Every byte after the new
/// body must be zero afterwards — the old tail must not survive in the slack.
#[tokio::test]
async fn removing_a_validator_leaves_only_zeros_after_the_body() {
    let owner = Keypair::new();
    let mut ctx = gate(&owner, vec![validator(1), validator(2), validator(3)], 2).start_with_context().await;

    let before = config_bytes(&mut ctx).await;
    let old_len = borsh::to_vec(&<Config as borsh::BorshDeserialize>::deserialize(&mut &before[..]).unwrap())
        .unwrap()
        .len();

    exec(
        &mut ctx,
        owner_ix(owner.pubkey(), GateInstruction::SetValidator { validator: validator(3), active: false }),
        &[&owner],
    )
    .await
    .expect("removal is immediate and owner-only");

    let after = config_bytes(&mut ctx).await;
    let cfg = <Config as borsh::BorshDeserialize>::deserialize(&mut &after[..]).unwrap();
    assert_eq!(cfg.validators, vec![validator(1), validator(2)]);
    assert!(cfg.sealed && cfg.setup_deadline == 0x7777_7777_7777_7777, "the tail moved down intact");
    let body = borsh::to_vec(&cfg).unwrap().len();
    assert_eq!(body + 20, old_len, "the body shrank by one validator");

    let stale: Vec<usize> = after[body..].iter().enumerate().filter(|(_, b)| **b != 0).map(|(i, _)| body + i).collect();
    assert!(stale.is_empty(), "stale bytes left after the {body}-byte body at offsets {stale:?}");
}

/// The same guarantee from the other side: a field appended to `Config` reads
/// zero after a shrink. Simulated by decoding the first byte past the body as a
/// Borsh `bool` — the brick the finding describes (a stale `0x77` fails it).
#[tokio::test]
async fn a_field_appended_after_a_shrink_reads_zero() {
    let owner = Keypair::new();
    let mut ctx = gate(&owner, vec![validator(1), validator(2), validator(3)], 2).start_with_context().await;
    exec(
        &mut ctx,
        owner_ix(owner.pubkey(), GateInstruction::SetValidator { validator: validator(1), active: false }),
        &[&owner],
    )
    .await
    .unwrap();
    let after = config_bytes(&mut ctx).await;
    let cfg = <Config as borsh::BorshDeserialize>::deserialize(&mut &after[..]).unwrap();
    let body = borsh::to_vec(&cfg).unwrap().len();
    let appended = <(bool, i64) as borsh::BorshDeserialize>::deserialize(&mut &after[body..])
        .expect("an appended (bool, i64) must decode on an existing gate");
    assert_eq!(appended, (false, 0));
}

// ---------------------------------------------------------------------------
// L7-4 — program refuses an unclaimable threshold
// ---------------------------------------------------------------------------

/// With more validators than the cap, raising the threshold to the cap works
/// and one past it is refused with `ThresholdTooHigh` — the config untouched.
#[tokio::test]
async fn set_threshold_refuses_a_threshold_above_the_cap() {
    let owner = Keypair::new();
    let validators: Vec<[u8; 20]> = (1..=10).map(validator).collect();
    let mut ctx = gate(&owner, validators, 3).start_with_context().await;

    let err = exec(
        &mut ctx,
        owner_ix(owner.pubkey(), GateInstruction::SetThreshold { threshold: MAX_THRESHOLD + 1 }),
        &[&owner],
    )
    .await
    .expect_err("a threshold past the packet limit must be refused");
    assert!(is_custom(&err, THRESHOLD_TOO_HIGH), "got {err:?}");
    let cfg = <Config as borsh::BorshDeserialize>::deserialize(&mut &config_bytes(&mut ctx).await[..]).unwrap();
    assert_eq!(cfg.threshold, 3);

    exec(
        &mut ctx,
        owner_ix(owner.pubkey(), GateInstruction::SetThreshold { threshold: MAX_THRESHOLD }),
        &[&owner],
    )
    .await
    .expect("raising to exactly the cap is allowed (and instant)");
    let cfg = <Config as borsh::BorshDeserialize>::deserialize(&mut &config_bytes(&mut ctx).await[..]).unwrap();
    assert_eq!(cfg.threshold, MAX_THRESHOLD);
}

// ---------------------------------------------------------------------------
// L7-4 — the cap is measured, not guessed
// ---------------------------------------------------------------------------

fn sigs(n: u32) -> Vec<Vec<u8>> {
    (0..n).map(|i| vec![i as u8; 65]).collect()
}

/// Serialized size of the transaction the relayer sends: a legacy transaction,
/// `SetComputeUnitLimit` + the gate instruction, the payer as the only signer.
fn tx_size(accounts: Vec<AccountMeta>, data: GateInstruction) -> usize {
    let payer = Keypair::new();
    let mut accounts = accounts;
    // The relayer's account lists name the payer as a writable signer.
    for a in accounts.iter_mut() {
        if a.pubkey == PAYER_SLOT {
            *a = AccountMeta::new(payer.pubkey(), true);
        }
    }
    let gate = Instruction { program_id: PROGRAM_ID, accounts, data: borsh::to_vec(&data).unwrap() };
    let tx = Transaction::new_signed_with_payer(
        &[ComputeBudgetInstruction::set_compute_unit_limit(1_400_000), gate],
        Some(&payer.pubkey()),
        &[&payer],
        Hash::new_unique(),
    );
    bincode::serialize(&tx).unwrap().len()
}

fn u() -> Pubkey {
    Pubkey::new_unique()
}
/// Placeholder replaced by the fee payer in [`tx_size`] (not `Pubkey::default()`:
/// that is the system program's id).
const PAYER_SLOT: Pubkey = Pubkey::new_from_array([0xEE; 32]);
fn payer_slot() -> AccountMeta {
    AccountMeta::new(PAYER_SLOT, true)
}

/// `[config, asset, executed(w), payer(s,w), vault(w), receiver_token(w),
///   vault_authority, spl_token, system_program]` — as `target.rs::try_claim`.
fn claim_size(n: u32, auto: Option<AutoParamsWire>, native_sender: usize) -> usize {
    tx_size(
        vec![
            AccountMeta::new_readonly(u(), false),
            AccountMeta::new_readonly(u(), false),
            AccountMeta::new(u(), false),
            payer_slot(),
            AccountMeta::new(u(), false),
            AccountMeta::new(u(), false),
            AccountMeta::new_readonly(u(), false),
            AccountMeta::new_readonly(spl_token::id(), false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
        GateInstruction::Claim(ClaimArgs {
            debridge_id: [1; 32],
            amount: u64::MAX,
            bridge_decimals: 6,
            chain_id_from: u64::MAX,
            nonce: u64::MAX,
            receiver: vec![2; 32], // a claim receiver is always a 32-byte token account
            auto,
            native_sender: vec![3; native_sender],
            signatures: sigs(n),
        }),
    )
}

/// `[config, executed(w), payer(s,w), system_program]` — as `try_cancel`.
fn cancel_size(n: u32, auto: Option<AutoParamsWire>) -> usize {
    tx_size(
        vec![
            AccountMeta::new_readonly(u(), false),
            AccountMeta::new(u(), false),
            payer_slot(),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
        GateInstruction::Cancel(CancelArgs {
            debridge_id: [1; 32],
            amount: u64::MAX,
            bridge_decimals: 6,
            chain_id_from: u64::MAX,
            nonce: u64::MAX,
            receiver: vec![2; 32],
            auto,
            native_sender: vec![3; 32],
            signatures: sigs(n),
        }),
    )
}

/// `[config, asset, sent(w), refunded(w), payer(s,w), vault(w), source_token(w),
///   vault_authority, spl_token, system_program]` — as `refund_accounts`.
fn refund_size(n: u32, auto: Option<AutoParamsWire>) -> usize {
    tx_size(
        vec![
            AccountMeta::new_readonly(u(), false),
            AccountMeta::new_readonly(u(), false),
            AccountMeta::new(u(), false),
            AccountMeta::new(u(), false),
            payer_slot(),
            AccountMeta::new(u(), false),
            AccountMeta::new(u(), false),
            AccountMeta::new_readonly(u(), false),
            AccountMeta::new_readonly(spl_token::id(), false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
        GateInstruction::Refund(RefundArgs {
            debridge_id: [1; 32],
            amount: u64::MAX,
            bridge_decimals: 6,
            chain_id_to: u64::MAX,
            nonce: u64::MAX,
            receiver: vec![2; 32], // widest legal receiver
            auto,
            native_sender: vec![3; 32], // the Solana sender
            signatures: sigs(n),
        }),
    )
}

/// The largest signature count that still fits one packet.
fn max_fitting(size: impl Fn(u32) -> usize) -> u32 {
    (0..64).take_while(|n| size(*n) <= PACKET_DATA_SIZE).last().unwrap()
}

/// Every instruction shape without auto-params fits at `threshold = MAX_THRESHOLD`
/// — the relayer sends exactly `threshold` signatures — and the cap is TIGHT for
/// the binding shape (refund), so it was not chosen lower than it needs to be.
#[test]
fn every_recovery_and_claim_shape_fits_one_packet_at_the_cap() {
    let claim = claim_size(MAX_THRESHOLD, None, 32);
    let claim_evm = claim_size(MAX_THRESHOLD, None, 20);
    let cancel = cancel_size(MAX_THRESHOLD, None);
    let refund = refund_size(MAX_THRESHOLD, None);
    println!(
        "at MAX_THRESHOLD={MAX_THRESHOLD}: claim {claim} B (20-byte sender {claim_evm} B), cancel {cancel} B, refund {refund} B"
    );
    println!(
        "max signatures per packet: claim {} (20-byte sender {}), cancel {}, refund {}; per signature {} B",
        max_fitting(|n| claim_size(n, None, 32)),
        max_fitting(|n| claim_size(n, None, 20)),
        max_fitting(|n| cancel_size(n, None)),
        max_fitting(|n| refund_size(n, None)),
        claim_size(1, None, 32) - claim_size(0, None, 32),
    );
    for (name, size) in [("claim", claim), ("claim/evm-sender", claim_evm), ("cancel", cancel), ("refund", refund)] {
        assert!(size <= PACKET_DATA_SIZE, "{name} with {MAX_THRESHOLD} signatures is {size} B > {PACKET_DATA_SIZE}");
    }
    assert!(
        refund_size(MAX_THRESHOLD + 1, None) > PACKET_DATA_SIZE,
        "refund fits one more signature — MAX_THRESHOLD could be raised (re-measure and update its doc)"
    );
    // 69 bytes per signature: a 4-byte Borsh length + 65 bytes.
    assert_eq!(claim_size(1, None, 32) - claim_size(0, None, 32), 69);
}

/// Auto-params are carried verbatim (they are hashed into the id) and `Gate.sol`
/// does not bound their payload, so they eat into the same budget. Pinned so the
/// documented headroom stays true: an EMPTY auto block still fits a claim and a
/// refund at the cap.
#[test]
fn an_empty_auto_block_still_fits_at_the_cap() {
    let auto = Some(AutoParamsWire { execution_fee: u128::MAX, flags: u64::MAX, fallback_address: vec![], data: vec![] });
    let claim = claim_size(MAX_THRESHOLD, auto.clone(), 32);
    let cancel = cancel_size(MAX_THRESHOLD, auto.clone());
    let refund = refund_size(MAX_THRESHOLD, auto.clone());
    println!("empty auto at the cap: claim {claim} B, cancel {cancel} B, refund {refund} B");
    assert!(claim <= PACKET_DATA_SIZE && cancel <= PACKET_DATA_SIZE && refund <= PACKET_DATA_SIZE);
}

/// The host-side mirror must agree, or `gate-admin` pre-checks a different cap
/// than the program enforces.
#[test]
fn the_cap_is_mirrored_in_bridge_solana() {
    assert_eq!(bridge_solana::instruction::MAX_THRESHOLD, MAX_THRESHOLD);
}
