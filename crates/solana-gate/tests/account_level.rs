//! Account-level tests — the handlers actually EXECUTED, not just their pure
//! predicates asserted.
//!
//! `solana-program-test` runs `process_instruction` natively inside a real test
//! bank (no SBF toolchain needed), so rent, lamports, account ownership, PDA
//! derivation and Borsh (de)serialization behave as they do on-chain. The
//! `c1_tests` module in `lib.rs` covers the pure authorization *rules*; this file
//! covers the handlers that apply them.
//!
//! ## Scope, and two honest exclusions
//!
//! **`init` is not covered here.** `process_init` reads the BPF-loader `Program`
//! and `ProgramData` accounts to identify the upgrade authority. Installing a
//! `bpf_loader_upgradeable`-owned account at the program's own address defeats
//! `ProgramTest`'s builtin dispatch — the runtime then tries to load a real ELF
//! from the (fake) ProgramData and the instruction never reaches our code. Testing
//! it needs a genuine `cargo build-sbf` artifact. The authority rule itself is
//! covered by `c1_tests::init_requires_upgrade_authority`. Tests below therefore
//! seed the config account directly, exactly as a successful `init` would leave it.
//!
//! Everything else IS covered, including the SPL-backed paths: `solana-program-test`
//! bundles the SPL token program (`programs::spl_programs`), so `send`'s lock,
//! `claim`'s release and `refund`'s payout all execute for real here against
//! genuine token accounts.
//!
//! Executed below: `process_register_corridor`, `process_set_paused`,
//! `process_set_guardian`, `process_set_validator`, `process_set_threshold`,
//! `process_schedule_governance`, `process_cancel_scheduled_governance`,
//! `process_register_asset`, `process_send`, `process_claim`, `process_cancel`
//! and `process_refund` — i.e. the live paths for findings H-2, H-3, M-1, M-2,
//! M-6, L-3 and, from audit round 4, H-2 (governance timelock) and M-5
//! (pre-funded PDAs). `init`'s round-4 changes (M-5 path, validator-set
//! validation) share `create_pda_account` / `validate_validator_set` with the
//! handlers and predicates covered here.

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::instruction::{AccountMeta, Instruction};
use solana_program::pubkey::Pubkey;
use solana_program_test::{processor, ProgramTest, ProgramTestContext};
use solana_sdk::account::Account;
use solana_sdk::signature::{Keypair, Signer};
use solana_sdk::transaction::Transaction;

use solana_gate::{
    process_instruction, AssetConfig, CancelArgs, Config, GateInstruction, SendArgs,
};

const PROGRAM_ID: Pubkey = Pubkey::new_from_array([7u8; 32]);
const CHAIN_ID: u64 = 7565164; // Solana
const DEST_CHAIN: u64 = 1337;
/// Deployment generation shared by every gate these tests stand up. Non-zero,
/// because `init` refuses a zero domain.
const TEST_BRIDGE_DOMAIN: [u8; 32] = [0xD0; 32];

fn config_pda() -> Pubkey {
    Pubkey::find_program_address(&[b"config"], &PROGRAM_ID).0
}

/// Mirrors `config_space` in the program: the account is sized for the DECLARED
/// capacities, which is the H-3 fix.
///
/// Kept in sync BY HAND, so any field added to `Config` must be added here too —
/// a stale copy shows up as `AccountDataTooSmall` from whichever instruction
/// first reserializes the config, not as a compile error.
fn config_space(validators: u32, corridors: u32) -> usize {
    32                                  // owner
    + 32                                // bridge_domain
    + 32                                // guardian
    + (4 + 20 * validators as usize)    // validators
    + 4 + 8 + 1 + 4 + 4                 // threshold, chain_id, paused, caps
    + (4 + 16 * corridors as usize)     // nonce_to
}

/// A bank with the gate registered and its config PDA already initialized —
/// owner-gated instructions are then driven by `owner`, which is funded.
async fn setup(max_validators: u32, max_corridors: u32, guardian: Pubkey) -> (ProgramTestContext, Keypair) {
    setup_with_validators(max_validators, max_corridors, guardian, vec![[1u8; 20], [2u8; 20], [3u8; 20]], 2).await
}

/// As [`setup`], but with a caller-chosen validator set and threshold — needed by
/// the quorum tests, which must seed the addresses their real signatures recover
/// to rather than placeholder bytes.
async fn setup_with_validators(
    max_validators: u32,
    max_corridors: u32,
    guardian: Pubkey,
    validators: Vec<[u8; 20]>,
    threshold: u32,
) -> (ProgramTestContext, Keypair) {
    let owner = Keypair::new();
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

    // Exactly what a successful `init` leaves behind.
    let cfg = Config {
        owner: owner.pubkey(),
        bridge_domain: TEST_BRIDGE_DOMAIN,
        guardian,
        validators,
        threshold,
        chain_id: CHAIN_ID,
        paused: false,
        max_validators,
        max_corridors,
        nonce_to: Vec::new(),
        // H-5: a LIVE gate — wiring finished, setup phase closed. Anything that
        // pays out needs this, and a test that wanted the open phase says so.
        sealed: true,
        setup_deadline: 0,
    };
    let space = config_space(max_validators, max_corridors);
    let mut data = vec![0u8; space];
    cfg.serialize(&mut &mut data[..]).expect("config must fit the space it declares");

    pt.add_account(
        config_pda(),
        Account {
            lamports: 10_000_000_000,
            data,
            owner: PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        },
    );

    (pt.start_with_context().await, owner)
}

fn ix(data: GateInstruction, accounts: Vec<AccountMeta>) -> Instruction {
    Instruction { program_id: PROGRAM_ID, accounts, data: borsh::to_vec(&data).unwrap() }
}

async fn exec(
    ctx: &mut ProgramTestContext,
    instruction: Instruction,
    extra: &[&Keypair],
) -> Result<(), solana_sdk::transaction::TransactionError> {
    // A FRESH blockhash per call. Reusing `ctx.last_blockhash` for an identical
    // instruction produces a byte-identical transaction, which the bank
    // deduplicates and reports as success — making a replay test pass for the
    // wrong reason (it never reached the program at all). Taken before the
    // signer borrows so `ctx` is not aliased.
    let blockhash = ctx.get_new_latest_blockhash().await.unwrap_or(ctx.last_blockhash);
    let mut signers: Vec<&Keypair> = vec![&ctx.payer];
    signers.extend_from_slice(extra);
    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&ctx.payer.pubkey()),
        &signers,
        blockhash,
    );
    ctx.banks_client.process_transaction(tx).await.map_err(|e| match e {
        solana_program_test::BanksClientError::TransactionError(te) => te,
        other => panic!("unexpected banks error: {other:?}"),
    })
}

async fn read_config(ctx: &mut ProgramTestContext) -> Config {
    let acct = ctx.banks_client.get_account(config_pda()).await.unwrap().expect("config exists");
    assert_eq!(acct.owner, PROGRAM_ID, "config must stay program-owned");
    Config::deserialize(&mut &acct.data[..]).expect("config must deserialize")
}

fn register_corridor(who: Pubkey, chain_id_to: u64) -> Instruction {
    ix(
        GateInstruction::RegisterCorridor { chain_id_to },
        vec![AccountMeta::new(config_pda(), false), AccountMeta::new(who, true)],
    )
}

/// Six accounts so `send` clears `next_account_info`. The pause and corridor
/// guards both fire before any of them is dereferenced, which is what lets these
/// tests reach the guards without the SPL token program.
fn send_instruction(signer: Pubkey, chain_id_to: u64) -> Instruction {
    ix(
        GateInstruction::Send(SendArgs {
            debridge_id: [9u8; 32],
            amount: 1,
            chain_id_to,
            receiver: vec![0xAB; 20],
            auto: None,
        }),
        vec![
            AccountMeta::new(config_pda(), false),
            AccountMeta::new_readonly(Pubkey::new_unique(), false), // asset
            AccountMeta::new(signer, true),
            AccountMeta::new(Pubkey::new_unique(), false), // user_token
            AccountMeta::new(Pubkey::new_unique(), false), // vault
            AccountMeta::new_readonly(spl_token::id(), false),
            AccountMeta::new(Pubkey::new_unique(), false), // sent record (M-2)
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
    )
}

// ---------------------------------------------------------------------------
// H-3 — `send` cannot create a corridor; corridors are owner-gated and bounded
// ---------------------------------------------------------------------------

#[tokio::test]
async fn send_to_an_unregistered_corridor_is_refused_and_creates_nothing() {
    let (mut ctx, owner) = setup(8, 4, Pubkey::default()).await;

    // THE H-3 attack: `send` used to append a `(chain_id, nonce)` entry for any
    // destination a caller invented, growing the config until it no longer fit its
    // account — permanently bricking send AND governance, with no realloc path.
    let err = exec(&mut ctx, send_instruction(owner.pubkey(), 424242), &[&owner])
        .await
        .expect_err("an unregistered destination must be refused");
    assert!(format!("{err:?}").contains("Custom"), "got {err:?}");

    // The load-bearing assertion: no entry was created as a side effect.
    let cfg = read_config(&mut ctx).await;
    assert!(cfg.nonce_to.is_empty(), "send must never create a corridor, got {:?}", cfg.nonce_to);
}

#[tokio::test]
async fn corridor_registration_is_owner_gated() {
    let (mut ctx, _owner) = setup(8, 4, Pubkey::default()).await;

    let stranger = Keypair::new();
    let err = exec(&mut ctx, register_corridor(stranger.pubkey(), DEST_CHAIN), &[&stranger])
        .await
        .expect_err("only the owner may register a corridor");
    assert!(format!("{err:?}").contains("MissingRequiredSignature"), "got {err:?}");
    assert!(read_config(&mut ctx).await.nonce_to.is_empty());
}

#[tokio::test]
async fn corridor_registration_is_idempotent_and_never_resets_a_nonce() {
    let (mut ctx, owner) = setup(8, 4, Pubkey::default()).await;

    exec(&mut ctx, register_corridor(owner.pubkey(), DEST_CHAIN), &[&owner]).await.expect("first");
    exec(&mut ctx, register_corridor(owner.pubkey(), DEST_CHAIN), &[&owner]).await.expect("second");

    let cfg = read_config(&mut ctx).await;
    assert_eq!(cfg.nonce_to, vec![(DEST_CHAIN, 0)], "no duplicate entry, nonce untouched");
}

#[tokio::test]
async fn corridors_are_capacity_bounded() {
    // Room for exactly 2 corridors.
    let (mut ctx, owner) = setup(8, 2, Pubkey::default()).await;

    exec(&mut ctx, register_corridor(owner.pubkey(), 1), &[&owner]).await.expect("first fits");
    exec(&mut ctx, register_corridor(owner.pubkey(), 2), &[&owner]).await.expect("second fits");

    // The third must fail cleanly rather than overflow the account — this bound is
    // what makes the H-3 vector impossible even for the owner.
    let err = exec(&mut ctx, register_corridor(owner.pubkey(), 3), &[&owner])
        .await
        .expect_err("registering past max_corridors must fail");
    assert!(format!("{err:?}").contains("Custom"), "got {err:?}");

    let cfg = read_config(&mut ctx).await;
    assert_eq!(cfg.nonce_to.len(), 2, "state unchanged after the rejected registration");
}

// ---------------------------------------------------------------------------
// M-1 — the circuit breaker, executed rather than asserted
// ---------------------------------------------------------------------------

fn pause(who: Pubkey) -> Instruction {
    ix(
        GateInstruction::Pause,
        vec![AccountMeta::new(config_pda(), false), AccountMeta::new_readonly(who, true)],
    )
}

fn unpause(who: Pubkey) -> Instruction {
    ix(
        GateInstruction::Unpause,
        vec![AccountMeta::new(config_pda(), false), AccountMeta::new_readonly(who, true)],
    )
}

#[tokio::test]
async fn a_paused_gate_refuses_send() {
    let (mut ctx, owner) = setup(8, 4, Pubkey::default()).await;
    // Register the corridor first, so a later failure can only be the pause.
    exec(&mut ctx, register_corridor(owner.pubkey(), DEST_CHAIN), &[&owner]).await.unwrap();

    // Un-paused: the corridor guard passes and we get as far as the SPL asset
    // checks, which fail for a different reason — proving the send guard is not
    // what stopped us.
    let before = exec(&mut ctx, send_instruction(owner.pubkey(), DEST_CHAIN), &[&owner]).await;
    let before = format!("{:?}", before.expect_err("dummy SPL accounts must fail"));
    assert!(!before.contains("Custom(7)"), "should not be the Paused error yet: {before}");

    exec(&mut ctx, pause(owner.pubkey()), &[&owner]).await.expect("owner pause");
    assert!(read_config(&mut ctx).await.paused, "the flag must actually be persisted");

    // Paused: now it stops before any of that. `Config.paused` used to be dead
    // code — written false at init, never read, with no instruction to set it.
    let err = exec(&mut ctx, send_instruction(owner.pubkey(), DEST_CHAIN), &[&owner])
        .await
        .expect_err("a paused gate must refuse send");
    assert!(format!("{err:?}").contains("Custom"), "got {err:?}");
}

#[tokio::test]
async fn a_guardian_may_stop_the_gate_but_never_restart_it() {
    let guardian = Keypair::new();
    let (mut ctx, owner) = setup(8, 4, guardian.pubkey()).await;

    // Fund the guardian so signing is possible.
    let fund = solana_sdk::system_instruction::transfer(
        &ctx.payer.pubkey(),
        &guardian.pubkey(),
        1_000_000_000,
    );
    let tx = Transaction::new_signed_with_payer(
        &[fund],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer],
        ctx.last_blockhash,
    );
    ctx.banks_client.process_transaction(tx).await.unwrap();

    // The guardian is a low-trust STOP button: it may halt...
    exec(&mut ctx, pause(guardian.pubkey()), &[&guardian]).await.expect("guardian may pause");
    assert!(read_config(&mut ctx).await.paused);

    // ...but never resume, so a compromised guardian causes only a recoverable
    // liveness halt, never a restart of a gate the owner deliberately stopped.
    let err = exec(&mut ctx, unpause(guardian.pubkey()), &[&guardian])
        .await
        .expect_err("a guardian must not resume the gate");
    assert!(format!("{err:?}").contains("MissingRequiredSignature"), "got {err:?}");
    assert!(read_config(&mut ctx).await.paused, "still paused after the refused unpause");

    // The owner can.
    exec(&mut ctx, unpause(owner.pubkey()), &[&owner]).await.expect("owner may resume");
    assert!(!read_config(&mut ctx).await.paused);
}

#[tokio::test]
async fn a_stranger_can_neither_pause_nor_unpause() {
    let (mut ctx, _owner) = setup(8, 4, Pubkey::default()).await;
    let stranger = Keypair::new();
    let fund = solana_sdk::system_instruction::transfer(
        &ctx.payer.pubkey(),
        &stranger.pubkey(),
        1_000_000_000,
    );
    let tx = Transaction::new_signed_with_payer(
        &[fund],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer],
        ctx.last_blockhash,
    );
    ctx.banks_client.process_transaction(tx).await.unwrap();

    for instruction in [pause(stranger.pubkey()), unpause(stranger.pubkey())] {
        let err = exec(&mut ctx, instruction, &[&stranger]).await.expect_err("stranger refused");
        assert!(format!("{err:?}").contains("MissingRequiredSignature"), "got {err:?}");
    }
    assert!(!read_config(&mut ctx).await.paused);
}

// ---------------------------------------------------------------------------
// L-3 — the validator set cannot outgrow its account
// ---------------------------------------------------------------------------

#[tokio::test]
async fn validator_set_is_capped_at_the_declared_capacity() {
    // Room for 4; the seeded config holds 3.
    let (mut ctx, owner) = setup(4, 4, Pubkey::default()).await;

    // H-2 (round 4): an addition consumes a matured schedule, so each attempt is
    // scheduled and aged first — this test is about the CAPACITY rule, which
    // must still fire after the timelock is satisfied.
    for v in [4u8, 5] {
        exec(&mut ctx, schedule_governance(owner.pubkey(), add_validator_action_id(&[v; 20])), &[&owner])
            .await
            .expect("schedule");
    }
    advance_clock(&mut ctx, GOVERNANCE_DELAY).await;

    exec(&mut ctx, set_validator(owner.pubkey(), [4; 20], true), &[&owner]).await.expect("the 4th fits");
    assert_eq!(read_config(&mut ctx).await.validators.len(), 4);

    // The 5th must be refused explicitly rather than blowing up inside Borsh once
    // the buffer overflows — that opaque failure was finding L-3.
    let err = exec(&mut ctx, set_validator(owner.pubkey(), [5; 20], true), &[&owner])
        .await
        .expect_err("past capacity must fail");
    assert!(is_custom(&err, AT_CAPACITY), "expected AtCapacity, got {err:?}");
    assert_eq!(read_config(&mut ctx).await.validators.len(), 4, "state unchanged");
}

// ---------------------------------------------------------------------------
// H-2 (audit round 4) — governance timelock, executed through the real handlers
//
// `set_validator(active=true)` and a threshold DECREASE used to be instant, so a
// compromised owner key could add one attacker validator, set threshold 1 and
// drain every vault in a single block — while the EVM gate made the same key
// wait 48 hours in public view. Both legs share one validator set, so the EVM
// timelock was only ever as strong as this program's owner key.
// ---------------------------------------------------------------------------

use solana_gate::{add_validator_action_id, lower_threshold_action_id, GOVERNANCE_DELAY, GOVERNANCE_GRACE};
use solana_program::clock::Clock;

const GOVERNANCE_NOT_SCHEDULED: u32 = 17;
const GOVERNANCE_NOT_READY: u32 = 18;
const GOVERNANCE_EXPIRED: u32 = 19;
const AT_CAPACITY: u32 = 9;

fn gov_pda(action_id: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[b"gov", action_id], &PROGRAM_ID).0
}

fn schedule_governance(owner: Pubkey, action_id: [u8; 32]) -> Instruction {
    ix(
        GateInstruction::ScheduleGovernance { action_id },
        vec![
            AccountMeta::new_readonly(config_pda(), false),
            AccountMeta::new(owner, true),
            AccountMeta::new(gov_pda(&action_id), false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
    )
}

fn cancel_governance(who: Pubkey, action_id: [u8; 32]) -> Instruction {
    ix(
        GateInstruction::CancelScheduledGovernance { action_id },
        vec![
            AccountMeta::new_readonly(config_pda(), false),
            AccountMeta::new_readonly(who, true),
            AccountMeta::new(gov_pda(&action_id), false),
        ],
    )
}

/// `SetValidator` with the governance PDA attached (needed for an addition).
fn set_validator(owner: Pubkey, validator: [u8; 20], active: bool) -> Instruction {
    ix(
        GateInstruction::SetValidator { validator, active },
        vec![
            AccountMeta::new(config_pda(), false),
            AccountMeta::new_readonly(owner, true),
            AccountMeta::new(gov_pda(&add_validator_action_id(&validator)), false),
        ],
    )
}

/// `SetThreshold` with the governance PDA attached (needed for a decrease).
fn set_threshold(owner: Pubkey, threshold: u32) -> Instruction {
    ix(
        GateInstruction::SetThreshold { threshold },
        vec![
            AccountMeta::new(config_pda(), false),
            AccountMeta::new_readonly(owner, true),
            AccountMeta::new(gov_pda(&lower_threshold_action_id(threshold)), false),
        ],
    )
}

/// Move the CLUSTER clock forward by `secs`. The program reads `Clock::get()`,
/// which is what the bank agrees on — not the host's wall clock — so this is the
/// only way to age a schedule in a test.
async fn advance_clock(ctx: &mut ProgramTestContext, secs: i64) {
    let mut clock: Clock = ctx.banks_client.get_sysvar().await.expect("clock sysvar");
    clock.unix_timestamp += secs;
    ctx.set_sysvar(&clock);
}

async fn fund(ctx: &mut ProgramTestContext, who: Pubkey) {
    let fund = solana_sdk::system_instruction::transfer(&ctx.payer.pubkey(), &who, 1_000_000_000);
    let tx = Transaction::new_signed_with_payer(
        &[fund],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer],
        ctx.last_blockhash,
    );
    ctx.banks_client.process_transaction(tx).await.unwrap();
}

/// THE H-2 attack, refused: without a schedule an addition fails, and the set is
/// untouched. An owner key on its own can no longer grant signing power.
#[tokio::test]
async fn adding_a_validator_without_a_schedule_is_refused() {
    let (mut ctx, owner) = setup(8, 4, Pubkey::default()).await;
    let v = [0x44u8; 20];

    // With the governance account supplied but never scheduled…
    let err = exec(&mut ctx, set_validator(owner.pubkey(), v, true), &[&owner])
        .await
        .expect_err("an unscheduled addition must be refused");
    assert!(is_custom(&err, GOVERNANCE_NOT_SCHEDULED), "got {err:?}");

    // …and with the old two-account shape (no governance account at all).
    let legacy = ix(
        GateInstruction::SetValidator { validator: v, active: true },
        vec![AccountMeta::new(config_pda(), false), AccountMeta::new_readonly(owner.pubkey(), true)],
    );
    let err = exec(&mut ctx, legacy, &[&owner]).await.expect_err("no gov account");
    assert!(is_custom(&err, GOVERNANCE_NOT_SCHEDULED), "got {err:?}");

    assert_eq!(read_config(&mut ctx).await.validators.len(), 3, "set untouched");
}

/// The honest path: schedule, wait out the delay, execute — and the schedule is
/// BURNED by the execution, so it cannot be spent twice.
#[tokio::test]
async fn a_matured_schedule_admits_the_validator_exactly_once() {
    let (mut ctx, owner) = setup(8, 4, Pubkey::default()).await;
    let v = [0x44u8; 20];
    let action = add_validator_action_id(&v);

    exec(&mut ctx, schedule_governance(owner.pubkey(), action), &[&owner]).await.expect("schedule");
    let gov = ctx.banks_client.get_account(gov_pda(&action)).await.unwrap().expect("gov PDA created");
    assert_eq!(gov.owner, PROGRAM_ID, "schedule must be program-owned");

    advance_clock(&mut ctx, GOVERNANCE_DELAY).await;
    exec(&mut ctx, set_validator(owner.pubkey(), v, true), &[&owner]).await.expect("matured");
    let cfg = read_config(&mut ctx).await;
    assert!(cfg.validators.contains(&v), "validator admitted");
    assert_eq!(cfg.validators.len(), 4);

    // One approval, one change: remove it and try to re-add on the spent schedule.
    exec(&mut ctx, set_validator(owner.pubkey(), v, false), &[&owner]).await.expect("removal is instant");
    assert_eq!(read_config(&mut ctx).await.validators.len(), 3);
    let err = exec(&mut ctx, set_validator(owner.pubkey(), v, true), &[&owner])
        .await
        .expect_err("a consumed schedule must not authorise a second addition");
    assert!(is_custom(&err, GOVERNANCE_NOT_SCHEDULED), "got {err:?}");
}

/// One second short of the delay is still too early.
#[tokio::test]
async fn an_immature_schedule_is_refused() {
    let (mut ctx, owner) = setup(8, 4, Pubkey::default()).await;
    let v = [0x44u8; 20];
    exec(&mut ctx, schedule_governance(owner.pubkey(), add_validator_action_id(&v)), &[&owner])
        .await
        .expect("schedule");

    advance_clock(&mut ctx, GOVERNANCE_DELAY - 1).await;
    let err = exec(&mut ctx, set_validator(owner.pubkey(), v, true), &[&owner])
        .await
        .expect_err("47h59m59s is not 48h");
    assert!(is_custom(&err, GOVERNANCE_NOT_READY), "got {err:?}");
    assert_eq!(read_config(&mut ctx).await.validators.len(), 3);

    // The last second matters in both directions.
    advance_clock(&mut ctx, 1).await;
    exec(&mut ctx, set_validator(owner.pubkey(), v, true), &[&owner]).await.expect("now matured");
}

/// A matured schedule left lying around past the grace window is a banked
/// instant right for whoever holds the owner key later. It expires.
#[tokio::test]
async fn an_expired_schedule_is_refused_and_can_be_rescheduled() {
    let (mut ctx, owner) = setup(8, 4, Pubkey::default()).await;
    let v = [0x44u8; 20];
    let action = add_validator_action_id(&v);
    exec(&mut ctx, schedule_governance(owner.pubkey(), action), &[&owner]).await.expect("schedule");

    advance_clock(&mut ctx, GOVERNANCE_DELAY + GOVERNANCE_GRACE + 1).await;
    let err = exec(&mut ctx, set_validator(owner.pubkey(), v, true), &[&owner])
        .await
        .expect_err("a stale approval must not be spendable");
    assert!(is_custom(&err, GOVERNANCE_EXPIRED), "got {err:?}");
    assert_eq!(read_config(&mut ctx).await.validators.len(), 3);

    // Re-scheduling restarts the clock on the SAME PDA (no create_account brick).
    exec(&mut ctx, schedule_governance(owner.pubkey(), action), &[&owner]).await.expect("re-schedule");
    let err = exec(&mut ctx, set_validator(owner.pubkey(), v, true), &[&owner])
        .await
        .expect_err("fresh schedule is immature again");
    assert!(is_custom(&err, GOVERNANCE_NOT_READY), "got {err:?}");
    advance_clock(&mut ctx, GOVERNANCE_DELAY).await;
    exec(&mut ctx, set_validator(owner.pubkey(), v, true), &[&owner]).await.expect("matured again");
}

/// The guardian may cancel a pending grant of power (incident response), and a
/// stranger may not. Cancelling executes nothing, so the worst a compromised
/// guardian can do is delay.
#[tokio::test]
async fn the_guardian_may_cancel_a_scheduled_action_but_a_stranger_may_not() {
    let guardian = Keypair::new();
    let stranger = Keypair::new();
    let (mut ctx, owner) = setup(8, 4, guardian.pubkey()).await;
    fund(&mut ctx, guardian.pubkey()).await;
    fund(&mut ctx, stranger.pubkey()).await;

    let v = [0x44u8; 20];
    let action = add_validator_action_id(&v);
    exec(&mut ctx, schedule_governance(owner.pubkey(), action), &[&owner]).await.expect("schedule");

    let err = exec(&mut ctx, cancel_governance(stranger.pubkey(), action), &[&stranger])
        .await
        .expect_err("a stranger cannot cancel");
    assert!(format!("{err:?}").contains("MissingRequiredSignature"), "got {err:?}");

    exec(&mut ctx, cancel_governance(guardian.pubkey(), action), &[&guardian])
        .await
        .expect("guardian cancels");

    // The schedule is gone: even fully aged, the addition is refused.
    advance_clock(&mut ctx, GOVERNANCE_DELAY).await;
    let err = exec(&mut ctx, set_validator(owner.pubkey(), v, true), &[&owner])
        .await
        .expect_err("cancelled schedule authorises nothing");
    assert!(is_custom(&err, GOVERNANCE_NOT_SCHEDULED), "got {err:?}");

    // Only the owner may SCHEDULE — the guardian is a stop button, not a start one.
    let err = exec(&mut ctx, schedule_governance(guardian.pubkey(), action), &[&guardian])
        .await
        .expect_err("guardian cannot schedule");
    assert!(format!("{err:?}").contains("MissingRequiredSignature"), "got {err:?}");
}

/// A schedule authorises exactly one concrete change: approving validator A does
/// not admit validator B.
#[tokio::test]
async fn a_schedule_for_one_validator_does_not_admit_another() {
    let (mut ctx, owner) = setup(8, 4, Pubkey::default()).await;
    let (a, b) = ([0xAAu8; 20], [0xBBu8; 20]);
    exec(&mut ctx, schedule_governance(owner.pubkey(), add_validator_action_id(&a)), &[&owner])
        .await
        .expect("schedule A");
    advance_clock(&mut ctx, GOVERNANCE_DELAY).await;

    // Attempt to add B, pointing at A's (matured) schedule account.
    let cheat = ix(
        GateInstruction::SetValidator { validator: b, active: true },
        vec![
            AccountMeta::new(config_pda(), false),
            AccountMeta::new_readonly(owner.pubkey(), true),
            AccountMeta::new(gov_pda(&add_validator_action_id(&a)), false),
        ],
    );
    let err = exec(&mut ctx, cheat, &[&owner]).await.expect_err("wrong action's PDA");
    assert!(format!("{err:?}").contains("InvalidSeeds"), "got {err:?}");
    assert!(!read_config(&mut ctx).await.validators.contains(&b));
}

/// Threshold asymmetry: RAISING is instant (it makes the gate harder to move),
/// LOWERING waits — and the approval commits to the exact value.
#[tokio::test]
async fn raising_the_threshold_is_instant_but_lowering_it_waits() {
    // 3 validators, threshold 2.
    let (mut ctx, owner) = setup(8, 4, Pubkey::default()).await;

    // Raise 2 -> 3: no schedule needed, even with the legacy two-account shape.
    let raise = ix(
        GateInstruction::SetThreshold { threshold: 3 },
        vec![AccountMeta::new(config_pda(), false), AccountMeta::new_readonly(owner.pubkey(), true)],
    );
    exec(&mut ctx, raise, &[&owner]).await.expect("raising is instant");
    assert_eq!(read_config(&mut ctx).await.threshold, 3);

    // Lower 3 -> 1 without a schedule: refused.
    let err = exec(&mut ctx, set_threshold(owner.pubkey(), 1), &[&owner])
        .await
        .expect_err("an unscheduled decrease must be refused");
    assert!(is_custom(&err, GOVERNANCE_NOT_SCHEDULED), "got {err:?}");
    assert_eq!(read_config(&mut ctx).await.threshold, 3, "unchanged");

    // Schedule a decrease to 2, mature it, then try to spend it on 1.
    exec(&mut ctx, schedule_governance(owner.pubkey(), lower_threshold_action_id(2)), &[&owner])
        .await
        .expect("schedule t=2");
    advance_clock(&mut ctx, GOVERNANCE_DELAY).await;
    let cheat = ix(
        GateInstruction::SetThreshold { threshold: 1 },
        vec![
            AccountMeta::new(config_pda(), false),
            AccountMeta::new_readonly(owner.pubkey(), true),
            AccountMeta::new(gov_pda(&lower_threshold_action_id(2)), false),
        ],
    );
    let err = exec(&mut ctx, cheat, &[&owner]).await.expect_err("t=2 approval is not a t=1 approval");
    assert!(format!("{err:?}").contains("InvalidSeeds"), "got {err:?}");
    assert_eq!(read_config(&mut ctx).await.threshold, 3);

    // The exact scheduled value goes through.
    exec(&mut ctx, set_threshold(owner.pubkey(), 2), &[&owner]).await.expect("scheduled decrease");
    assert_eq!(read_config(&mut ctx).await.threshold, 2);
}

/// Removing a validator stays instant — the moment a key is known compromised is
/// the moment it must leave the set — with no governance account required.
#[tokio::test]
async fn removing_a_validator_is_instant() {
    let (mut ctx, owner) = setup(8, 4, Pubkey::default()).await;
    let remove = ix(
        GateInstruction::SetValidator { validator: [3u8; 20], active: false },
        vec![AccountMeta::new(config_pda(), false), AccountMeta::new_readonly(owner.pubkey(), true)],
    );
    exec(&mut ctx, remove, &[&owner]).await.expect("removal needs no schedule");
    let cfg = read_config(&mut ctx).await;
    assert_eq!(cfg.validators, vec![[1u8; 20], [2u8; 20]]);
}

/// M-5, for the governance PDA too: a squatter pre-funding `["gov", action_id]`
/// must not be able to block governance.
#[tokio::test]
async fn a_pre_funded_governance_pda_does_not_block_scheduling() {
    let (mut ctx, owner) = setup(8, 4, Pubkey::default()).await;
    let action = add_validator_action_id(&[0x44u8; 20]);
    ctx.set_account(
        &gov_pda(&action),
        &Account {
            lamports: 1,
            data: vec![],
            owner: solana_sdk::system_program::id(),
            executable: false,
            rent_epoch: 0,
        }
        .into(),
    );
    exec(&mut ctx, schedule_governance(owner.pubkey(), action), &[&owner])
        .await
        .expect("a pre-funded PDA must not brick scheduling");
    let gov = ctx.banks_client.get_account(gov_pda(&action)).await.unwrap().unwrap();
    assert_eq!(gov.owner, PROGRAM_ID);
}

// ---------------------------------------------------------------------------
// Wire compatibility: the program's `GateInstruction` and the host mirror in
// `bridge_solana::instruction` must decode each other's bytes. A relayer builds
// instructions from the mirror; if a variant is added to one and not the other,
// or in a different position, the transaction is well-formed and runs the WRONG
// handler.
// ---------------------------------------------------------------------------

#[test]
fn the_host_mirror_encodes_every_instruction_the_program_decodes() {
    use bridge_solana::instruction as host;

    let cases: Vec<(host::GateInstruction, &str)> = vec![
        (host::GateInstruction::SetValidator { validator: [7u8; 20], active: true }, "SetValidator"),
        (host::GateInstruction::SetThreshold { threshold: 2 }, "SetThreshold"),
        (host::GateInstruction::RegisterAsset { debridge_id: [9u8; 32], bridge_decimals: 6 }, "RegisterAsset"),
        (host::GateInstruction::RegisterCorridor { chain_id_to: 1337 }, "RegisterCorridor"),
        (host::GateInstruction::Pause, "Pause"),
        (host::GateInstruction::Unpause, "Unpause"),
        (host::GateInstruction::SetGuardian { guardian: [5u8; 32] }, "SetGuardian"),
        (host::GateInstruction::ScheduleGovernance { action_id: [0xA1; 32] }, "ScheduleGovernance"),
        (host::GateInstruction::CancelScheduledGovernance { action_id: [0xA2; 32] }, "CancelScheduledGovernance"),
        (host::GateInstruction::Seal, "Seal"),
    ];
    for (host_ix, name) in cases {
        let bytes = host_ix.to_bytes();
        let ours = GateInstruction::try_from_slice(&bytes)
            .unwrap_or_else(|e| panic!("{name}: program cannot decode the mirror's bytes: {e}"));
        // The variant NAME must match (a shifted discriminant would decode as a
        // different, well-formed instruction), and the byte round trip must be
        // identical (a payload field of the wrong width would not survive it).
        let variant = |d: &str| d.split(|c| c == ' ' || c == '(').next().unwrap().to_string();
        assert_eq!(
            variant(&format!("{ours:?}")),
            variant(&format!("{host_ix:?}")),
            "{name}: decoded to a different variant"
        );
        assert_eq!(borsh::to_vec(&ours).unwrap(), bytes, "{name}: re-encoding diverged");
    }

    // The two governance variants are the round-4 additions and must sit at
    // discriminants 12 and 13 — after Refund (11) — on BOTH sides.
    assert_eq!(host::GateInstruction::ScheduleGovernance { action_id: [0; 32] }.to_bytes()[0], 12);
    assert_eq!(host::GateInstruction::CancelScheduledGovernance { action_id: [0; 32] }.to_bytes()[0], 13);
    assert_eq!(borsh::to_vec(&GateInstruction::ScheduleGovernance { action_id: [0; 32] }).unwrap()[0], 12);
    assert_eq!(
        borsh::to_vec(&GateInstruction::CancelScheduledGovernance { action_id: [0; 32] }).unwrap()[0],
        13
    );
    // H-5's `Seal` is the round-5 addition and must sit at 14 on both sides.
    assert_eq!(host::GateInstruction::Seal.to_bytes()[0], 14);
    assert_eq!(borsh::to_vec(&GateInstruction::Seal).unwrap()[0], 14);

    // The asset action id is built independently on each side (Pubkey vs raw
    // bytes, `keccak::hashv` vs a concatenated buffer), so it can drift silently:
    // the schedule would land at one address and the consume would look at
    // another, and `register-asset` would be permanently unschedulable on a
    // sealed gate. Pin them against each other.
    let mint = Pubkey::new_unique();
    let vault = Pubkey::new_unique();
    assert_eq!(
        solana_gate::register_asset_action_id(&[0xC3; 32], &mint, &vault, 6),
        host::register_asset_action_id(&[0xC3; 32], &mint.to_bytes(), &vault.to_bytes(), 6),
        "the host mirror's registerAsset action id diverged from the program's"
    );
}

/// The host-side `SentRecord` mirror (read by the relayer's origin-proof check
/// and, since round 4, by its refund attester for the lock time) must be exactly
/// what `process_send` writes.
#[test]
fn the_sent_record_mirror_matches_the_program() {
    let ours = solana_gate::SentRecord {
        debridge_id: [1u8; 32],
        sender: Pubkey::new_from_array([2u8; 32]),
        source_token: Pubkey::new_from_array([3u8; 32]),
        mint: Pubkey::new_from_array([4u8; 32]),
        amount: 500,
        locked_at: 1_700_000_000,
    };
    let bytes = borsh::to_vec(&ours).unwrap();
    assert_eq!(bytes.len(), bridge_solana::relayer::SENT_RECORD_LEN, "SENT_RECORD_LEN drifted");
    let theirs = bridge_solana::relayer::SentRecord::try_from_slice(&bytes).expect("mirror decodes");
    assert_eq!(theirs.debridge_id, [1u8; 32]);
    assert_eq!(theirs.sender, [2u8; 32]);
    assert_eq!(theirs.source_token, [3u8; 32]);
    assert_eq!(theirs.mint, [4u8; 32]);
    assert_eq!(theirs.amount, 500);
    assert_eq!(theirs.locked_at, 1_700_000_000);
}

// ---------------------------------------------------------------------------
// M-2 — the destination-side burn, executed
//
// `cancel` moves no funds, so unlike `refund` it needs neither the asset registry
// nor the SPL token program — which makes it fully drivable here.
// ---------------------------------------------------------------------------

fn executed_pda(id: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[b"executed", id], &PROGRAM_ID).0
}

/// The wire scale every fixture in this file registers its asset at. Since H-2
/// it is part of the submissionId preimage, so the hand-rolled hashes below must
/// carry it too — that is what makes them a genuine independent reproduction of
/// the program's, rather than a copy that would agree with any bug.
const FIXTURE_BRIDGE_DECIMALS: u8 = 6;

/// Recompute the submissionId exactly as the program does, so the test can derive
/// the marker PDA the instruction will touch.
fn submission_id_for(args: &CancelArgs, chain_id_to: u64) -> [u8; 32] {
    use solana_program::keccak;
    fn be32(v: u64) -> [u8; 32] {
        let mut o = [0u8; 32];
        o[24..].copy_from_slice(&v.to_be_bytes());
        o
    }
    keccak::hashv(&[
        &be32(1), // SUBMISSION_PREFIX
        &TEST_BRIDGE_DOMAIN,
        &args.debridge_id,
        &be32(args.chain_id_from),
        &be32(chain_id_to),
        &[args.bridge_decimals],
        &be32(args.amount),
        &args.receiver,
        &be32(args.nonce),
    ])
    .to_bytes()
}

fn cancel_args(signatures: Vec<Vec<u8>>) -> CancelArgs {
    CancelArgs {
        debridge_id: [9u8; 32],
        amount: 100,
        bridge_decimals: FIXTURE_BRIDGE_DECIMALS,
        chain_id_from: DEST_CHAIN,
        nonce: 0,
        receiver: vec![0xAB; 32],
        auto: None,
        native_sender: vec![0x11; 20],
        signatures,
    }
}

fn cancel_instruction(args: CancelArgs, payer: Pubkey) -> (Instruction, [u8; 32]) {
    let id = submission_id_for(&args, CHAIN_ID);
    let instruction = ix(
        GateInstruction::Cancel(args),
        vec![
            AccountMeta::new_readonly(config_pda(), false),
            AccountMeta::new(executed_pda(&id), false),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
    );
    (instruction, id)
}

/// Without a validator quorum over the CANCEL digest, nothing is burned. This is
/// the guard that stops anyone simply erasing a healthy in-flight transfer.
#[tokio::test]
async fn cancel_without_a_quorum_is_refused_and_burns_nothing() {
    let (mut ctx, owner) = setup(8, 4, Pubkey::default()).await;

    let (instruction, id) = cancel_instruction(cancel_args(vec![]), owner.pubkey());
    let err = exec(&mut ctx, instruction, &[&owner])
        .await
        .expect_err("no signatures must not reach the threshold");
    assert!(format!("{err:?}").contains("Custom"), "got {err:?}");

    // Nothing was created, so the transfer stays claimable.
    let marker = ctx.banks_client.get_account(executed_pda(&id)).await.unwrap();
    assert!(marker.is_none(), "a refused cancel must leave no marker");
}

/// A transfer signature must not be replayable as a cancel. The two are signed
/// over different digests (`submissionId` vs `keccak(2 || submissionId)`), so a
/// transfer quorum recovers to the wrong addresses here and cannot reach the
/// threshold — the same domain separation `BridgeHash` enforces on the EVM side.
#[tokio::test]
async fn a_transfer_signature_cannot_be_replayed_as_a_cancel() {
    let (mut ctx, owner) = setup(8, 4, Pubkey::default()).await;

    // 65-byte structurally valid signatures that are not over the cancel digest.
    let junk = vec![vec![0x1bu8; 65], vec![0x1bu8; 65]];
    let (instruction, id) = cancel_instruction(cancel_args(junk), owner.pubkey());

    let err = exec(&mut ctx, instruction, &[&owner])
        .await
        .expect_err("signatures from the wrong domain must not authorise a burn");
    assert!(format!("{err:?}").contains("Custom"), "got {err:?}");
    assert!(ctx.banks_client.get_account(executed_pda(&id)).await.unwrap().is_none());
}

/// A paused gate refuses to burn as well as to send — cancel is irreversible and
/// forecloses the payout, so it is deliberately NOT exempt the way refund is.
#[tokio::test]
async fn a_paused_gate_refuses_cancel() {
    let (mut ctx, owner) = setup(8, 4, Pubkey::default()).await;
    exec(&mut ctx, pause(owner.pubkey()), &[&owner]).await.expect("pause");

    let (instruction, _) = cancel_instruction(cancel_args(vec![]), owner.pubkey());
    let err = exec(&mut ctx, instruction, &[&owner]).await.expect_err("paused");
    assert!(format!("{err:?}").contains("Custom"), "got {err:?}");
}

// ---------------------------------------------------------------------------
// M-2 — a REAL quorum actually burns the transfer
//
// The tests above prove `cancel` refuses. These prove it works, which is the
// half that matters for recovering stuck funds: without a working burn there is
// no precondition for a source-side refund, and an unclaimable EVM->Solana
// transfer stays locked forever.
// ---------------------------------------------------------------------------

/// A validator identity: a secp256k1 key plus the EVM address it recovers to.
struct Validator {
    secret: libsecp256k1::SecretKey,
    address: [u8; 20],
}

impl Validator {
    fn new(seed: u8) -> Validator {
        let secret = libsecp256k1::SecretKey::parse(&[seed; 32]).expect("valid scalar");
        let public = libsecp256k1::PublicKey::from_secret_key(&secret);
        // address = keccak(uncompressed pubkey without the 0x04 tag)[12..]
        let uncompressed = public.serialize();
        let hash = solana_program::keccak::hashv(&[&uncompressed[1..]]).to_bytes();
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);
        Validator { secret, address }
    }

    /// A 65-byte r||s||v signature over the EIP-191 digest of `message`, exactly
    /// as the EVM validators produce and `verify_threshold` expects.
    fn sign(&self, message: &[u8; 32]) -> Vec<u8> {
        let digest =
            solana_program::keccak::hashv(&[b"\x19Ethereum Signed Message:\n32", message])
                .to_bytes();
        let (sig, recid) =
            libsecp256k1::sign(&libsecp256k1::Message::parse(&digest), &self.secret);
        let mut out = sig.serialize().to_vec(); // r||s, 64 bytes
        out.push(recid.serialize() + 27); // v in {27, 28}
        out
    }
}

/// Signatures sorted ascending by signer address, as the gate requires (the
/// ordering is what de-duplicates signers on-chain).
fn quorum(validators: &[&Validator], message: &[u8; 32]) -> Vec<Vec<u8>> {
    let mut signed: Vec<([u8; 20], Vec<u8>)> =
        validators.iter().map(|v| (v.address, v.sign(message))).collect();
    signed.sort_by_key(|(addr, _)| *addr);
    signed.into_iter().map(|(_, sig)| sig).collect()
}

fn cancel_digest(id: &[u8; 32]) -> [u8; 32] {
    fn be32(v: u64) -> [u8; 32] {
        let mut o = [0u8; 32];
        o[24..].copy_from_slice(&v.to_be_bytes());
        o
    }
    solana_program::keccak::hashv(&[&be32(2), id]).to_bytes()
}

#[tokio::test]
async fn a_real_quorum_burns_the_transfer_and_the_burn_is_final() {
    let (v1, v2, v3) = (Validator::new(1), Validator::new(2), Validator::new(3));
    let (mut ctx, owner) = setup_with_validators(
        8,
        4,
        Pubkey::default(),
        vec![v1.address, v2.address, v3.address],
        2,
    )
    .await;

    let args = cancel_args(vec![]);
    let id = submission_id_for(&args, CHAIN_ID);
    let sigs = quorum(&[&v1, &v2], &cancel_digest(&id));

    let (instruction, id2) = cancel_instruction(cancel_args(sigs.clone()), owner.pubkey());
    assert_eq!(id, id2, "test and program must agree on the submissionId");

    exec(&mut ctx, instruction, &[&owner]).await.expect("a 2-of-3 quorum must burn it");

    // The marker exists, is program-owned, and says CANCELLED rather than CLAIMED
    // — a consumer must be able to tell "burned" from "delivered".
    let marker = ctx
        .banks_client
        .get_account(executed_pda(&id))
        .await
        .unwrap()
        .expect("the burn must leave a marker");
    assert_eq!(marker.owner, PROGRAM_ID, "marker must be program-owned");
    assert_eq!(marker.data, vec![2u8], "marker must record CANCELLED, not CLAIMED");

    // The burn is final: a second cancel cannot re-authorise another refund.
    let (again, _) = cancel_instruction(cancel_args(sigs), owner.pubkey());
    let err = exec(&mut ctx, again, &[&owner]).await.expect_err("re-cancel must fail");
    assert!(format!("{err:?}").contains("Custom"), "got {err:?}");
}

/// One signature against a threshold of two is not a quorum. Pins that the
/// threshold is actually enforced, rather than any signature passing.
#[tokio::test]
async fn a_sub_threshold_quorum_does_not_burn() {
    let (v1, v2, v3) = (Validator::new(1), Validator::new(2), Validator::new(3));
    let (mut ctx, owner) = setup_with_validators(
        8,
        4,
        Pubkey::default(),
        vec![v1.address, v2.address, v3.address],
        2,
    )
    .await;

    let id = submission_id_for(&cancel_args(vec![]), CHAIN_ID);
    let sigs = quorum(&[&v1], &cancel_digest(&id)); // only one

    let (instruction, _) = cancel_instruction(cancel_args(sigs), owner.pubkey());
    let err = exec(&mut ctx, instruction, &[&owner]).await.expect_err("1-of-3 < threshold 2");
    assert!(format!("{err:?}").contains("Custom"), "got {err:?}");
    assert!(ctx.banks_client.get_account(executed_pda(&id)).await.unwrap().is_none());
}

/// Outsiders cannot burn a transfer however many of them sign: `verify_threshold`
/// counts only configured validators.
#[tokio::test]
async fn signatures_from_non_validators_never_reach_the_threshold() {
    let (v1, v2, v3) = (Validator::new(1), Validator::new(2), Validator::new(3));
    let (outsider_a, outsider_b) = (Validator::new(9), Validator::new(10));
    let (mut ctx, owner) = setup_with_validators(
        8,
        4,
        Pubkey::default(),
        vec![v1.address, v2.address, v3.address],
        2,
    )
    .await;

    let id = submission_id_for(&cancel_args(vec![]), CHAIN_ID);
    let sigs = quorum(&[&outsider_a, &outsider_b], &cancel_digest(&id));

    let (instruction, _) = cancel_instruction(cancel_args(sigs), owner.pubkey());
    let err = exec(&mut ctx, instruction, &[&owner]).await.expect_err("outsiders are not a quorum");
    assert!(format!("{err:?}").contains("Custom"), "got {err:?}");
    assert!(ctx.banks_client.get_account(executed_pda(&id)).await.unwrap().is_none());
}

/// THE domain-separation property, with real signatures: a validator's TRANSFER
/// signature (over the raw submissionId) must not authorise a burn. Under a
/// shared digest this quorum would succeed and anyone able to read the signature
/// store could destroy healthy in-flight transfers.
#[tokio::test]
async fn a_genuine_transfer_quorum_cannot_burn_a_transfer() {
    let (v1, v2, v3) = (Validator::new(1), Validator::new(2), Validator::new(3));
    let (mut ctx, owner) = setup_with_validators(
        8,
        4,
        Pubkey::default(),
        vec![v1.address, v2.address, v3.address],
        2,
    )
    .await;

    let id = submission_id_for(&cancel_args(vec![]), CHAIN_ID);
    // Signed over the submissionId itself — a real, valid TRANSFER quorum.
    let transfer_quorum = quorum(&[&v1, &v2], &id);

    let (instruction, _) = cancel_instruction(cancel_args(transfer_quorum), owner.pubkey());
    let err = exec(&mut ctx, instruction, &[&owner])
        .await
        .expect_err("a transfer quorum must not authorise a burn");
    assert!(format!("{err:?}").contains("Custom"), "got {err:?}");
    assert!(
        ctx.banks_client.get_account(executed_pda(&id)).await.unwrap().is_none(),
        "nothing may be burned by a replayed transfer quorum"
    );
}

// ---------------------------------------------------------------------------
// The SPL-backed paths: claim (H-2) and refund (M-2)
//
// `solana-program-test` bundles the SPL token program, so these paths ARE
// reachable here — which closes the two gaps the header note used to describe.
// Accounts are pre-baked with `Pack` rather than built via CPI setup
// transactions; the bank cannot tell the difference and the tests stay short.
// ---------------------------------------------------------------------------

use solana_program::program_pack::Pack;
use solana_sdk::program_option::COption;

fn vault_authority() -> Pubkey {
    Pubkey::find_program_address(&[b"vault_authority"], &PROGRAM_ID).0
}

/// H-5(b): the record of which `debridgeId` a vault backs.
fn vault_binding_pda(vault: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"vault", vault.as_ref()], &PROGRAM_ID).0
}

fn asset_pda(debridge_id: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[b"asset", debridge_id], &PROGRAM_ID).0
}

fn sent_pda(id: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[b"sent", id], &PROGRAM_ID).0
}

fn refunded_pda(id: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[b"refunded", id], &PROGRAM_ID).0
}

fn mint_account() -> Account {
    mint_account_with_decimals(6)
}

fn mint_account_with_decimals(decimals: u8) -> Account {
    let mut data = vec![0u8; spl_token::state::Mint::LEN];
    spl_token::state::Mint {
        mint_authority: COption::None,
        supply: 1_000_000,
        decimals,
        is_initialized: true,
        freeze_authority: COption::None,
    }
    .pack_into_slice(&mut data);
    Account { lamports: 10_000_000, data, owner: spl_token::id(), executable: false, rent_epoch: 0 }
}

/// An initialized SPL token account. `delegate`/`close_authority` are settable so
/// the M-6 test can build the vault it must reject.
fn token_account(
    mint: Pubkey,
    owner: Pubkey,
    amount: u64,
    delegate: COption<Pubkey>,
    close_authority: COption<Pubkey>,
) -> Account {
    let mut data = vec![0u8; spl_token::state::Account::LEN];
    spl_token::state::Account {
        mint,
        owner,
        amount,
        delegate,
        state: spl_token::state::AccountState::Initialized,
        is_native: COption::None,
        delegated_amount: 0,
        close_authority,
    }
    .pack_into_slice(&mut data);
    Account { lamports: 10_000_000, data, owner: spl_token::id(), executable: false, rent_epoch: 0 }
}

fn spl_balance(account: &Account) -> u64 {
    spl_token::state::Account::unpack(&account.data).expect("an SPL token account").amount
}

/// A bank with a mint, a registered asset, a funded vault, and a user token
/// account — i.e. everything the SPL-backed instructions need.
struct AssetFixture {
    ctx: ProgramTestContext,
    owner: Keypair,
    mint: Pubkey,
    vault: Pubkey,
    user_token: Pubkey,
    debridge_id: [u8; 32],
}

async fn setup_with_asset(
    validators: Vec<[u8; 20]>,
    threshold: u32,
    vault_balance: u64,
    user_balance: u64,
) -> AssetFixture {
    setup_with_asset_decimals(validators, threshold, vault_balance, user_balance, 6, 6).await
}

/// [`setup_with_asset`] for a mint of `local_decimals` bridged at `bridge_decimals`.
async fn setup_with_asset_decimals(
    validators: Vec<[u8; 20]>,
    threshold: u32,
    vault_balance: u64,
    user_balance: u64,
    local_decimals: u8,
    bridge_decimals: u8,
) -> AssetFixture {
    let owner = Keypair::new();
    let mint = Pubkey::new_unique();
    let vault = Pubkey::new_unique();
    let user_token = Pubkey::new_unique();
    let debridge_id = [9u8; 32];

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
        bridge_domain: TEST_BRIDGE_DOMAIN,
        guardian: Pubkey::default(),
        validators,
        threshold,
        chain_id: CHAIN_ID,
        paused: false,
        max_validators: 8,
        max_corridors: 4,
        nonce_to: vec![(DEST_CHAIN, 0)], // corridor pre-registered
        sealed: true,  // H-5: claim releases nothing on an unsealed gate
        setup_deadline: 0,
    };
    let mut cfg_data = vec![0u8; config_space(8, 4)];
    cfg.serialize(&mut &mut cfg_data[..]).unwrap();
    pt.add_account(
        config_pda(),
        Account {
            lamports: 10_000_000_000,
            data: cfg_data,
            owner: PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        },
    );

    // The asset registry entry governance would have created.
    let asset = solana_gate::AssetConfig { debridge_id, mint, vault, bridge_decimals, local_decimals };
    let mut asset_data = vec![0u8; 32 + 32 + 32 + 2];
    asset.serialize(&mut &mut asset_data[..]).unwrap();
    pt.add_account(
        asset_pda(&debridge_id),
        Account {
            lamports: 10_000_000,
            data: asset_data,
            owner: PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        },
    );

    pt.add_account(mint, mint_account_with_decimals(local_decimals));
    pt.add_account(
        vault,
        token_account(mint, vault_authority(), vault_balance, COption::None, COption::None),
    );
    pt.add_account(
        user_token,
        token_account(mint, owner.pubkey(), user_balance, COption::None, COption::None),
    );

    AssetFixture { ctx: pt.start_with_context().await, owner, mint, vault, user_token, debridge_id }
}

/// THE H-2 test, finally executed rather than asserted.
///
/// A submissionId is public — it is in the source chain's `Sent` event and in the
/// signature store — so anyone can derive `["executed", id]` and transfer the
/// rent-exempt minimum to it BEFORE the keeper claims. Under the old guard
/// (`lamports() > 0`) and the old `create_account` call, that permanently blocked
/// the claim, and with no cancel/refund on this program the funds were stuck for
/// good. A claim must now sail straight past a pre-funded marker.
#[tokio::test]
async fn a_claim_succeeds_even_when_the_marker_pda_was_pre_funded_by_a_griefer() {
    let (v1, v2, v3) = (Validator::new(1), Validator::new(2), Validator::new(3));
    let mut fx =
        setup_with_asset(vec![v1.address, v2.address, v3.address], 2, 1_000, 0).await;

    // The claim releases to a token account whose ADDRESS is the signed receiver.
    let receiver_token = Pubkey::new_unique();
    fx.ctx.set_account(
        &receiver_token,
        &token_account(fx.mint, Pubkey::new_unique(), 0, COption::None, COption::None).into(),
    );

    let args = solana_gate::ClaimArgs {
        debridge_id: fx.debridge_id,
        amount: 250,
        bridge_decimals: FIXTURE_BRIDGE_DECIMALS,
        chain_id_from: DEST_CHAIN,
        nonce: 0,
        receiver: receiver_token.to_bytes().to_vec(),
        auto: None,
        native_sender: vec![0x11; 20],
        signatures: vec![],
    };
    let id = claim_submission_id(&args);

    // The griefing move: fund the marker PDA so `create_account` would fail and
    // the old `lamports() > 0` guard would report AlreadyExecuted.
    let griefed = Account {
        lamports: 1_000_000,
        data: vec![],
        owner: solana_sdk::system_program::id(),
        executable: false,
        rent_epoch: 0,
    };
    fx.ctx.set_account(&executed_pda(&id), &griefed.into());

    let sigs = quorum(&[&v1, &v2], &id); // transfer domain: the raw submissionId
    let instruction = ix(
        GateInstruction::Claim(solana_gate::ClaimArgs { signatures: sigs, ..args }),
        vec![
            AccountMeta::new_readonly(config_pda(), false),
            AccountMeta::new_readonly(asset_pda(&fx.debridge_id), false),
            AccountMeta::new(executed_pda(&id), false),
            AccountMeta::new(fx.owner.pubkey(), true),
            AccountMeta::new(fx.vault, false),
            AccountMeta::new(receiver_token, false),
            AccountMeta::new_readonly(vault_authority(), false),
            AccountMeta::new_readonly(spl_token::id(), false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
    );

    let owner = Keypair::from_bytes(&fx.owner.to_bytes()).unwrap();
    exec(&mut fx.ctx, instruction, &[&owner])
        .await
        .expect("a pre-funded marker must NOT block a legitimate claim");

    // Funds moved, and the marker now says CLAIMED.
    let recv = fx.ctx.banks_client.get_account(receiver_token).await.unwrap().unwrap();
    assert_eq!(spl_balance(&recv), 250, "the receiver must be paid");
    let marker = fx.ctx.banks_client.get_account(executed_pda(&id)).await.unwrap().unwrap();
    assert_eq!(marker.owner, PROGRAM_ID);
    assert_eq!(marker.data, vec![1u8], "marker must record CLAIMED");
}

/// Recompute a claim's submissionId (destination side: chain_id_to is ours).
fn claim_submission_id(args: &solana_gate::ClaimArgs) -> [u8; 32] {
    use solana_program::keccak;
    fn be32(v: u64) -> [u8; 32] {
        let mut o = [0u8; 32];
        o[24..].copy_from_slice(&v.to_be_bytes());
        o
    }
    keccak::hashv(&[
        &be32(1),
        &TEST_BRIDGE_DOMAIN,
        &args.debridge_id,
        &be32(args.chain_id_from),
        &be32(CHAIN_ID),
        &[args.bridge_decimals],
        &be32(args.amount),
        &args.receiver,
        &be32(args.nonce),
    ])
    .to_bytes()
}

/// Source-side submissionId (chain_id_from is ours).
fn send_submission_id(debridge_id: &[u8; 32], amount: u64, receiver: &[u8], nonce: u64) -> [u8; 32] {
    use solana_program::keccak;
    fn be32(v: u64) -> [u8; 32] {
        let mut o = [0u8; 32];
        o[24..].copy_from_slice(&v.to_be_bytes());
        o
    }
    keccak::hashv(&[
        &be32(1),
        &TEST_BRIDGE_DOMAIN,
        debridge_id,
        &be32(CHAIN_ID),
        &be32(DEST_CHAIN),
        &[FIXTURE_BRIDGE_DECIMALS],
        &be32(amount),
        receiver,
        &be32(nonce),
    ])
    .to_bytes()
}

fn refund_digest(id: &[u8; 32]) -> [u8; 32] {
    fn be32(v: u64) -> [u8; 32] {
        let mut o = [0u8; 32];
        o[24..].copy_from_slice(&v.to_be_bytes());
        o
    }
    solana_program::keccak::hashv(&[&be32(3), id]).to_bytes()
}

/// The whole point of M-2: funds locked by `send` can be recovered.
///
/// Before this existed, an EVM→Solana transfer that could not be claimed left the
/// source deposit locked forever — the Solana gate had no `cancel` to burn the
/// destination and no `refund` to pay anyone back. This drives the source half
/// end-to-end: lock, then repay, with a real validator quorum over the refund
/// digest.
#[tokio::test]
async fn refund_returns_locked_funds_to_the_account_that_sent_them() {
    let (v1, v2, v3) = (Validator::new(1), Validator::new(2), Validator::new(3));
    let mut fx =
        setup_with_asset(vec![v1.address, v2.address, v3.address], 2, 0, 500).await;
    let owner = Keypair::from_bytes(&fx.owner.to_bytes()).unwrap();

    let amount = 300u64;
    let receiver = vec![0xEEu8; 20];
    let id = send_submission_id(&fx.debridge_id, amount, &receiver, 0);

    // --- lock ---
    let send = ix(
        GateInstruction::Send(SendArgs {
            debridge_id: fx.debridge_id,
            amount,
            chain_id_to: DEST_CHAIN,
            receiver: receiver.clone(),
            auto: None,
        }),
        vec![
            AccountMeta::new(config_pda(), false),
            AccountMeta::new_readonly(asset_pda(&fx.debridge_id), false),
            AccountMeta::new(owner.pubkey(), true),
            AccountMeta::new(fx.user_token, false),
            AccountMeta::new(fx.vault, false),
            AccountMeta::new_readonly(spl_token::id(), false),
            AccountMeta::new(sent_pda(&id), false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
    );
    exec(&mut fx.ctx, send, &[&owner]).await.expect("send must lock the funds");

    let user = fx.ctx.banks_client.get_account(fx.user_token).await.unwrap().unwrap();
    let vault = fx.ctx.banks_client.get_account(fx.vault).await.unwrap().unwrap();
    assert_eq!(spl_balance(&user), 200, "user debited");
    assert_eq!(spl_balance(&vault), 300, "vault credited");

    // The origin proof exists — this is what `refund` will trust instead of calldata.
    let sent = fx.ctx.banks_client.get_account(sent_pda(&id)).await.unwrap().unwrap();
    assert_eq!(sent.owner, PROGRAM_ID, "sent record must be program-owned");
    // Round 4 (M-4/M-13): it carries the CLUSTER lock time, which is what a refund
    // attester ages the transfer against instead of the store's nomination.
    let record = solana_gate::SentRecord::deserialize(&mut &sent.data[..]).expect("decodes");
    let clock: Clock = fx.ctx.banks_client.get_sysvar().await.unwrap();
    assert_eq!(record.locked_at, clock.unix_timestamp, "locked_at must be the cluster clock");
    assert_eq!(record.amount, amount);
    assert_eq!(record.source_token, fx.user_token);

    // --- repay (the destination has been burned; validators attested a refund) ---
    let refund = ix(
        GateInstruction::Refund(solana_gate::RefundArgs {
            debridge_id: fx.debridge_id,
            amount,
            bridge_decimals: FIXTURE_BRIDGE_DECIMALS,
            chain_id_to: DEST_CHAIN,
            nonce: 0,
            receiver: receiver.clone(),
            auto: None,
            native_sender: owner.pubkey().to_bytes().to_vec(),
            signatures: quorum(&[&v1, &v2], &refund_digest(&id)),
        }),
        vec![
            AccountMeta::new_readonly(config_pda(), false),
            AccountMeta::new_readonly(asset_pda(&fx.debridge_id), false),
            AccountMeta::new(sent_pda(&id), false),
            AccountMeta::new(refunded_pda(&id), false),
            AccountMeta::new(owner.pubkey(), true),
            AccountMeta::new(fx.vault, false),
            AccountMeta::new(fx.user_token, false),
            AccountMeta::new_readonly(vault_authority(), false),
            AccountMeta::new_readonly(spl_token::id(), false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
    );
    exec(&mut fx.ctx, refund, &[&owner]).await.expect("a refund quorum must repay the sender");

    let user = fx.ctx.banks_client.get_account(fx.user_token).await.unwrap().unwrap();
    let vault = fx.ctx.banks_client.get_account(fx.vault).await.unwrap().unwrap();
    assert_eq!(spl_balance(&user), 500, "the sender must be made whole");
    assert_eq!(spl_balance(&vault), 0, "the vault must be drained by exactly the refund");

    // The origin proof is retired, so it can never authorise a second payout.
    let sent = fx.ctx.banks_client.get_account(sent_pda(&id)).await.unwrap().unwrap();
    assert!(sent.data.iter().all(|b| *b == 0), "sent record must be zeroed on payout");
    let marker = fx.ctx.banks_client.get_account(refunded_pda(&id)).await.unwrap().unwrap();
    assert_eq!(marker.owner, PROGRAM_ID, "refunded marker must exist");
}

/// A refund quorum is not a licence to drain the vault twice.
#[tokio::test]
async fn a_refund_cannot_be_replayed() {
    let (v1, v2, v3) = (Validator::new(1), Validator::new(2), Validator::new(3));
    let mut fx = setup_with_asset(vec![v1.address, v2.address, v3.address], 2, 0, 500).await;
    let owner = Keypair::from_bytes(&fx.owner.to_bytes()).unwrap();

    let amount = 300u64;
    let receiver = vec![0xEEu8; 20];
    let id = send_submission_id(&fx.debridge_id, amount, &receiver, 0);

    let send = ix(
        GateInstruction::Send(SendArgs {
            debridge_id: fx.debridge_id,
            amount,
            chain_id_to: DEST_CHAIN,
            receiver: receiver.clone(),
            auto: None,
        }),
        vec![
            AccountMeta::new(config_pda(), false),
            AccountMeta::new_readonly(asset_pda(&fx.debridge_id), false),
            AccountMeta::new(owner.pubkey(), true),
            AccountMeta::new(fx.user_token, false),
            AccountMeta::new(fx.vault, false),
            AccountMeta::new_readonly(spl_token::id(), false),
            AccountMeta::new(sent_pda(&id), false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
    );
    exec(&mut fx.ctx, send, &[&owner]).await.unwrap();

    let build_refund = |sigs: Vec<Vec<u8>>| {
        ix(
            GateInstruction::Refund(solana_gate::RefundArgs {
                debridge_id: fx.debridge_id,
                amount,
                bridge_decimals: FIXTURE_BRIDGE_DECIMALS,
                chain_id_to: DEST_CHAIN,
                nonce: 0,
                receiver: receiver.clone(),
                auto: None,
                native_sender: owner.pubkey().to_bytes().to_vec(),
                signatures: sigs,
            }),
            vec![
                AccountMeta::new_readonly(config_pda(), false),
                AccountMeta::new_readonly(asset_pda(&fx.debridge_id), false),
                AccountMeta::new(sent_pda(&id), false),
                AccountMeta::new(refunded_pda(&id), false),
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(fx.vault, false),
                AccountMeta::new(fx.user_token, false),
                AccountMeta::new_readonly(vault_authority(), false),
                AccountMeta::new_readonly(spl_token::id(), false),
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            ],
        )
    };
    let sigs = quorum(&[&v1, &v2], &refund_digest(&id));

    exec(&mut fx.ctx, build_refund(sigs.clone()), &[&owner]).await.expect("first refund");
    let err = exec(&mut fx.ctx, build_refund(sigs), &[&owner])
        .await
        .expect_err("a second refund must be refused");
    assert!(format!("{err:?}").contains("Custom"), "got {err:?}");

    let user = fx.ctx.banks_client.get_account(fx.user_token).await.unwrap().unwrap();
    assert_eq!(spl_balance(&user), 500, "the sender must not be paid twice");
}

/// M-6, executed: a vault carrying a `delegate` or `close_authority` must be
/// refused at registration.
///
/// Owning the vault proves the program CAN move it; it does not prove nobody else
/// can. A delegate transfers up to `delegated_amount` with no involvement from the
/// owner PDA, and a close authority sweeps the account — both entirely outside
/// this program, past every check it makes.
#[tokio::test]
async fn register_asset_refuses_a_vault_someone_else_can_move() {
    for (delegate, close_authority, label) in [
        (COption::Some(Pubkey::new_unique()), COption::None, "delegate"),
        (COption::None, COption::Some(Pubkey::new_unique()), "close authority"),
    ] {
        let owner = Keypair::new();
        let mint = Pubkey::new_unique();
        let vault = Pubkey::new_unique();
        let debridge_id = [42u8; 32];

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
            bridge_domain: TEST_BRIDGE_DOMAIN,
            guardian: Pubkey::default(),
            validators: vec![[1u8; 20]],
            threshold: 1,
            chain_id: CHAIN_ID,
            paused: false,
            max_validators: 8,
            max_corridors: 4,
            nonce_to: vec![],
            // H-5: registering an asset in ONE transaction is the setup phase,
            // which these tests are exercising.
            sealed: false,
            setup_deadline: i64::MAX,
        };
        let mut cfg_data = vec![0u8; config_space(8, 4)];
        cfg.serialize(&mut &mut cfg_data[..]).unwrap();
        pt.add_account(
            config_pda(),
            Account {
                lamports: 10_000_000_000,
                data: cfg_data,
                owner: PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
        );
        pt.add_account(mint, mint_account());
        // The vault is correctly owned by the vault-authority PDA and holds the
        // right mint — everything the old check looked at — but is reachable by
        // someone else.
        pt.add_account(
            vault,
            token_account(mint, vault_authority(), 0, delegate, close_authority),
        );

        let mut ctx = pt.start_with_context().await;
        let instruction = ix(
            GateInstruction::RegisterAsset { debridge_id, bridge_decimals: 6 },
            vec![
                AccountMeta::new_readonly(config_pda(), false),
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(asset_pda(&debridge_id), false),
                AccountMeta::new_readonly(mint, false),
                AccountMeta::new_readonly(vault, false),
                AccountMeta::new_readonly(spl_token::id(), false),
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                AccountMeta::new(vault_binding_pda(&vault), false),
            ],
        );

        let err = exec(&mut ctx, instruction, &[&owner])
            .await
            .expect_err("a vault reachable by someone else must be refused");
        assert!(format!("{err:?}").contains("InvalidAccountData"), "{label}: got {err:?}");
        assert!(
            ctx.banks_client.get_account(asset_pda(&debridge_id)).await.unwrap().is_none(),
            "{label}: nothing may be registered"
        );
    }
}

/// H-1, through the real handler: a registered corridor cannot be repointed.
///
/// `Gate.sol::setLocalToken` is write-once and documents why — a claim commits to
/// `debridgeId`, never to the local asset, so whoever can repoint the binding can
/// make the validators' EXISTING signatures release a different asset from a
/// different vault. The Solana registry re-serialized unconditionally, so an
/// owner (or a compromised owner key) had exactly that power.
#[tokio::test]
async fn a_registered_asset_cannot_be_repointed() {
    let owner = Keypair::new();
    let debridge_id = [42u8; 32];

    // The genuine binding, and the attacker's replacement.
    let real_mint = Pubkey::new_unique();
    let real_vault = Pubkey::new_unique();
    let evil_mint = Pubkey::new_unique();
    let evil_vault = Pubkey::new_unique();

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
        bridge_domain: TEST_BRIDGE_DOMAIN,
        guardian: Pubkey::default(),
        validators: vec![[1u8; 20]],
        threshold: 1,
        chain_id: CHAIN_ID,
        paused: false,
        max_validators: 8,
        max_corridors: 4,
        nonce_to: vec![],
        sealed: false,             // H-5: the setup phase, where this is instant
        setup_deadline: i64::MAX,
    };
    let mut cfg_data = vec![0u8; config_space(8, 4)];
    cfg.serialize(&mut &mut cfg_data[..]).unwrap();
    pt.add_account(
        config_pda(),
        Account {
            lamports: 10_000_000_000,
            data: cfg_data,
            owner: PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        },
    );
    for m in [real_mint, evil_mint] {
        pt.add_account(m, mint_account());
    }
    // Both vaults are individually well-formed: right authority, no delegate, no
    // close authority. The ONLY thing wrong with the second is that the corridor
    // is already bound — which is the whole point.
    pt.add_account(
        real_vault,
        token_account(real_mint, vault_authority(), 0, COption::None, COption::None),
    );
    pt.add_account(
        evil_vault,
        token_account(evil_mint, vault_authority(), 0, COption::None, COption::None),
    );

    let mut ctx = pt.start_with_context().await;

    let register = |mint: Pubkey, vault: Pubkey| {
        ix(
            GateInstruction::RegisterAsset { debridge_id, bridge_decimals: 6 },
            vec![
                AccountMeta::new_readonly(config_pda(), false),
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(asset_pda(&debridge_id), false),
                AccountMeta::new_readonly(mint, false),
                AccountMeta::new_readonly(vault, false),
                AccountMeta::new_readonly(spl_token::id(), false),
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                AccountMeta::new(vault_binding_pda(&vault), false),
            ],
        )
    };

    // 1. The genuine first registration succeeds.
    exec(&mut ctx, register(real_mint, real_vault), &[&owner])
        .await
        .expect("first registration must succeed");

    let stored = ctx.banks_client.get_account(asset_pda(&debridge_id)).await.unwrap().unwrap();
    let before = AssetConfig::deserialize(&mut &stored.data[..]).unwrap();
    assert_eq!(before.mint, real_mint);
    assert_eq!(before.vault, real_vault);

    // 2. THE ATTACK: repoint the same debridgeId at a different mint + vault.
    let err = exec(&mut ctx, register(evil_mint, evil_vault), &[&owner])
        .await
        .expect_err("a live binding must not be repointable");
    assert!(
        is_custom(&err, ASSET_ALREADY_REGISTERED),
        "expected AssetAlreadyRegistered, got {err:?}"
    );

    // 3. The original binding is untouched — in-flight signed claims still
    //    release the asset the validators actually attested.
    let stored = ctx.banks_client.get_account(asset_pda(&debridge_id)).await.unwrap().unwrap();
    let after = AssetConfig::deserialize(&mut &stored.data[..]).unwrap();
    assert_eq!(after.mint, real_mint, "the registered mint must survive the attempt");
    assert_eq!(after.vault, real_vault, "the registered vault must survive the attempt");

    // 4. Re-registering the IDENTICAL binding stays a no-op, so a deploy script
    //    that runs twice does not fail.
    exec(&mut ctx, register(real_mint, real_vault), &[&owner])
        .await
        .expect("idempotent re-registration must succeed");
}

/// M-5 (round 4), executed: a squatter pre-funding `["asset", debridge_id]` must
/// not be able to block registration.
///
/// A `debridge_id` is public well before governance registers it (it is a hash
/// of the source chain id and token), so an attacker could park one lamport on
/// every plausible asset PDA. `system_instruction::create_account` then fails
/// with "already in use" and the corridor can never be opened without redeploying
/// the program — the exact brick H-2 removed from the executed marker. Every PDA
/// now goes through the same transfer+allocate+assign path.
#[tokio::test]
async fn register_asset_succeeds_when_the_pda_was_pre_funded_by_a_griefer() {
    let owner = Keypair::new();
    let mint = Pubkey::new_unique();
    let vault = Pubkey::new_unique();
    let debridge_id = [42u8; 32];

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
        bridge_domain: TEST_BRIDGE_DOMAIN,
        guardian: Pubkey::default(),
        validators: vec![[1u8; 20]],
        threshold: 1,
        chain_id: CHAIN_ID,
        paused: false,
        max_validators: 8,
        max_corridors: 4,
        nonce_to: vec![],
        sealed: false,             // H-5: the setup phase, where this is instant
        setup_deadline: i64::MAX,
    };
    let mut cfg_data = vec![0u8; config_space(8, 4)];
    cfg.serialize(&mut &mut cfg_data[..]).unwrap();
    pt.add_account(
        config_pda(),
        Account { lamports: 10_000_000_000, data: cfg_data, owner: PROGRAM_ID, executable: false, rent_epoch: 0 },
    );
    pt.add_account(mint, mint_account());
    pt.add_account(vault, token_account(mint, vault_authority(), 0, COption::None, COption::None));
    // THE griefing move: one lamport, system-owned, no data.
    pt.add_account(
        asset_pda(&debridge_id),
        Account { lamports: 1, data: vec![], owner: solana_sdk::system_program::id(), executable: false, rent_epoch: 0 },
    );

    let mut ctx = pt.start_with_context().await;
    let instruction = ix(
        GateInstruction::RegisterAsset { debridge_id, bridge_decimals: 6 },
        vec![
            AccountMeta::new_readonly(config_pda(), false),
            AccountMeta::new(owner.pubkey(), true),
            AccountMeta::new(asset_pda(&debridge_id), false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(vault, false),
            AccountMeta::new_readonly(spl_token::id(), false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new(vault_binding_pda(&vault), false),
        ],
    );
    exec(&mut ctx, instruction, &[&owner])
        .await
        .expect("a pre-funded asset PDA must NOT block registration");

    let stored = ctx.banks_client.get_account(asset_pda(&debridge_id)).await.unwrap().unwrap();
    assert_eq!(stored.owner, PROGRAM_ID, "the program took ownership");
    let asset = AssetConfig::deserialize(&mut &stored.data[..]).unwrap();
    assert_eq!(asset.mint, mint);
    assert_eq!(asset.vault, vault);
    assert!(stored.lamports >= 1, "the squatter's lamport was absorbed, not refused");
}

// ---------------------------------------------------------------------------
// Signature-array length cap, executed.
//
// `secp256k1_recover` costs ~25k CU. `verify_threshold` used to loop over every
// signature supplied, so an array longer than the validator set was a compute
// bomb: the transaction ran out of budget before reaching quorum. The sig-store
// authenticates a signature against its CLAIMED signer — not against the
// validator set — so anyone with a `Sign`-scoped token can append junk from
// throwaway keys to a pending submission, and a relayer that forwards it makes
// the transfer permanently unclaimable.
//
// Worse, `claim`, `cancel` and `refund` share one verifier. Padding the array
// kills the payout AND both recovery paths together, which is the difference
// between a delayed transfer and a lost one.
//
// `Gate.sol` has carried the equivalent cap since `16ed706` (`TooManySignatures`).
// These tests prove the Solana gate now refuses the same shape, cheaply, through
// the real handler.
// ---------------------------------------------------------------------------

/// `ProgramError::Custom(n)` for a `GateError` — the discriminant is
/// `index + 1`. `TooManySignatures` is the 13th variant.
const TOO_MANY_SIGNATURES: u32 = 13;
/// H-1's error, appended last so every code above it stays stable.
const ASSET_ALREADY_REGISTERED: u32 = 15;

fn is_custom(err: &solana_sdk::transaction::TransactionError, code: u32) -> bool {
    matches!(
        err,
        solana_sdk::transaction::TransactionError::InstructionError(
            _,
            solana_sdk::instruction::InstructionError::Custom(c),
        ) if *c == code
    )
}

/// A three-validator gate padded with junk: refused on length, before any
/// recover, and nothing is burned.
#[tokio::test]
async fn a_padded_cancel_is_refused_on_length_and_burns_nothing() {
    // setup() seeds three validators, threshold 2.
    let (mut ctx, owner) = setup(8, 4, Pubkey::default()).await;

    // Four structurally valid 65-byte signatures against a 3-validator set.
    // An honest array can never be this long: signers must be distinct and
    // strictly ascending, so there are at most three of them.
    let padded = vec![vec![0x1bu8; 65]; 4];
    let (instruction, id) = cancel_instruction(cancel_args(padded), owner.pubkey());

    let err = exec(&mut ctx, instruction, &[&owner])
        .await
        .expect_err("more signatures than validators must be refused");
    assert!(
        is_custom(&err, TOO_MANY_SIGNATURES),
        "expected TooManySignatures, got {err:?}"
    );

    // The transfer is untouched, so an honest (unpadded) attempt still works.
    assert!(
        ctx.banks_client.get_account(executed_pda(&id)).await.unwrap().is_none(),
        "a refused cancel must leave no marker"
    );
}

/// The griefing volume that used to exhaust the compute budget. It must now cost
/// the gate a length comparison, not eight signature recoveries.
#[tokio::test]
async fn a_heavily_padded_array_never_reaches_the_recover_loop() {
    let (mut ctx, owner) = setup(8, 4, Pubkey::default()).await;

    // Eight recoveries ≈ 200k CU: the entire default budget.
    let padded = vec![vec![0x1bu8; 65]; 8];
    let (instruction, _) = cancel_instruction(cancel_args(padded), owner.pubkey());

    let err = exec(&mut ctx, instruction, &[&owner]).await.expect_err("must be refused");
    assert!(
        is_custom(&err, TOO_MANY_SIGNATURES),
        "a padded array must fail on the cap, not on compute exhaustion: {err:?}"
    );
}

/// The cap must not break an honest array. Exactly `validatorCount` signatures is
/// legal and has to reach the recover loop — where these placeholder bytes then
/// fail as BAD SIGNATURES, which is how we know the length check let them past.
#[tokio::test]
async fn an_array_within_the_validator_count_still_reaches_verification() {
    let (mut ctx, owner) = setup(8, 4, Pubkey::default()).await;

    for len in 1..=3usize {
        let (instruction, _) =
            cancel_instruction(cancel_args(vec![vec![0x1bu8; 65]; len]), owner.pubkey());
        let err = exec(&mut ctx, instruction, &[&owner]).await.expect_err("junk is still junk");
        assert!(
            !is_custom(&err, TOO_MANY_SIGNATURES),
            "{len} signatures must pass the length cap and fail on verification instead: {err:?}"
        );
    }
}


// ---------------------------------------------------------------------------
// Decimals normalisation, through the real handlers.
//
// A 9-decimal mint bridged at 6 bridge decimals: `send` locks the mint amount but
// hashes (and emits) it in bridge units, `refund` returns exactly what was
// locked, and `claim` of a bridge amount pays it out at 9 decimals. Before this,
// the raw amount crossed unchanged, so 1 TST from an 18-decimal EVM chain was
// claimable here as 10^12 TST.
// ---------------------------------------------------------------------------

const INEXACT_AMOUNT: u32 = 22;

fn send_ix(fx: &AssetFixture, signer: Pubkey, amount: u64, receiver: &[u8], id: &[u8; 32]) -> Instruction {
    ix(
        GateInstruction::Send(SendArgs {
            debridge_id: fx.debridge_id,
            amount,
            chain_id_to: DEST_CHAIN,
            receiver: receiver.to_vec(),
            auto: None,
        }),
        vec![
            AccountMeta::new(config_pda(), false),
            AccountMeta::new_readonly(asset_pda(&fx.debridge_id), false),
            AccountMeta::new(signer, true),
            AccountMeta::new(fx.user_token, false),
            AccountMeta::new(fx.vault, false),
            AccountMeta::new_readonly(spl_token::id(), false),
            AccountMeta::new(sent_pda(id), false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
    )
}

#[tokio::test]
async fn send_hashes_bridge_units_and_refund_returns_the_mint_amount() {
    let (v1, v2, v3) = (Validator::new(1), Validator::new(2), Validator::new(3));
    let mut fx = setup_with_asset_decimals(
        vec![v1.address, v2.address, v3.address],
        2,
        0,
        3_000_000_000, // 3.0 at 9 decimals
        9,
        6,
    )
    .await;
    let owner = Keypair::from_bytes(&fx.owner.to_bytes()).unwrap();
    let receiver = vec![0xEEu8; 20];

    // 2.25 tokens = 2_250_000_000 mint units = 2_250_000 bridge units. The sent
    // PDA is seeded by the id, so a program still hashing mint units would fail
    // this instruction with InvalidSeeds.
    let local = 2_250_000_000u64;
    let id = send_submission_id(&fx.debridge_id, 2_250_000, &receiver, 0);
    let send = send_ix(&fx, owner.pubkey(), local, &receiver, &id);
    exec(&mut fx.ctx, send, &[&owner])
        .await
        .expect("send must hash the bridge amount");

    let user = fx.ctx.banks_client.get_account(fx.user_token).await.unwrap().unwrap();
    assert_eq!(spl_balance(&user), 750_000_000, "the MINT amount is locked");
    let sent = fx.ctx.banks_client.get_account(sent_pda(&id)).await.unwrap().unwrap();
    let record = solana_gate::SentRecord::deserialize(&mut &sent.data[..]).unwrap();
    assert_eq!(record.amount, local, "the record keeps the mint amount for refund");

    let refund = ix(
        GateInstruction::Refund(solana_gate::RefundArgs {
            debridge_id: fx.debridge_id,
            amount: 2_250_000, // the id's (bridge) amount
            bridge_decimals: FIXTURE_BRIDGE_DECIMALS,
            chain_id_to: DEST_CHAIN,
            nonce: 0,
            receiver: receiver.clone(),
            auto: None,
            native_sender: owner.pubkey().to_bytes().to_vec(),
            signatures: quorum(&[&v1, &v2], &refund_digest(&id)),
        }),
        vec![
            AccountMeta::new_readonly(config_pda(), false),
            AccountMeta::new_readonly(asset_pda(&fx.debridge_id), false),
            AccountMeta::new(sent_pda(&id), false),
            AccountMeta::new(refunded_pda(&id), false),
            AccountMeta::new(owner.pubkey(), true),
            AccountMeta::new(fx.vault, false),
            AccountMeta::new(fx.user_token, false),
            AccountMeta::new_readonly(vault_authority(), false),
            AccountMeta::new_readonly(spl_token::id(), false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
    );
    exec(&mut fx.ctx, refund, &[&owner]).await.expect("refund");
    let user = fx.ctx.banks_client.get_account(fx.user_token).await.unwrap().unwrap();
    assert_eq!(spl_balance(&user), 3_000_000_000, "made whole in mint units");
}

#[tokio::test]
async fn send_refuses_precision_below_the_bridge_unit() {
    let (v1, v2, v3) = (Validator::new(1), Validator::new(2), Validator::new(3));
    let mut fx =
        setup_with_asset_decimals(vec![v1.address, v2.address, v3.address], 2, 0, 3_000_000_000, 9, 6).await;
    let owner = Keypair::from_bytes(&fx.owner.to_bytes()).unwrap();
    let receiver = vec![0xEEu8; 20];

    // One mint unit past a whole bridge unit: not representable on the wire.
    let id = send_submission_id(&fx.debridge_id, 2_250_000, &receiver, 0);
    let send = send_ix(&fx, owner.pubkey(), 2_250_000_001, &receiver, &id);
    let err = exec(&mut fx.ctx, send, &[&owner])
        .await
        .expect_err("an inexact amount must be refused");
    assert!(is_custom(&err, INEXACT_AMOUNT), "expected InexactAmount, got {err:?}");
    let user = fx.ctx.banks_client.get_account(fx.user_token).await.unwrap().unwrap();
    assert_eq!(spl_balance(&user), 3_000_000_000, "nothing locked");
}

#[tokio::test]
async fn claim_pays_a_bridge_amount_out_in_mint_units() {
    let (v1, v2, v3) = (Validator::new(1), Validator::new(2), Validator::new(3));
    let mut fx =
        setup_with_asset_decimals(vec![v1.address, v2.address, v3.address], 2, 5_000_000_000, 0, 9, 6).await;
    let receiver_token = Pubkey::new_unique();
    fx.ctx.set_account(
        &receiver_token,
        &token_account(fx.mint, Pubkey::new_unique(), 0, COption::None, COption::None).into(),
    );

    // 1.5 tokens from an EVM chain: 1_500_000 bridge units on the wire.
    let args = solana_gate::ClaimArgs {
        debridge_id: fx.debridge_id,
        amount: 1_500_000,
        bridge_decimals: FIXTURE_BRIDGE_DECIMALS,
        chain_id_from: DEST_CHAIN,
        nonce: 0,
        receiver: receiver_token.to_bytes().to_vec(),
        auto: None,
        native_sender: vec![0x11; 20],
        signatures: vec![],
    };
    let id = claim_submission_id(&args);
    let sigs = quorum(&[&v1, &v2], &id);
    let claim = ix(
        GateInstruction::Claim(solana_gate::ClaimArgs { signatures: sigs, ..args }),
        vec![
            AccountMeta::new_readonly(config_pda(), false),
            AccountMeta::new_readonly(asset_pda(&fx.debridge_id), false),
            AccountMeta::new(executed_pda(&id), false),
            AccountMeta::new(fx.owner.pubkey(), true),
            AccountMeta::new(fx.vault, false),
            AccountMeta::new(receiver_token, false),
            AccountMeta::new_readonly(vault_authority(), false),
            AccountMeta::new_readonly(spl_token::id(), false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
    );
    let owner = Keypair::from_bytes(&fx.owner.to_bytes()).unwrap();
    exec(&mut fx.ctx, claim, &[&owner]).await.expect("claim");

    let recv = fx.ctx.banks_client.get_account(receiver_token).await.unwrap().unwrap();
    assert_eq!(spl_balance(&recv), 1_500_000_000, "1.5 tokens at 9 decimals");
    let vault = fx.ctx.banks_client.get_account(fx.vault).await.unwrap().unwrap();
    assert_eq!(spl_balance(&vault), 3_500_000_000);
}

/// `GateError::BridgeScaleMismatch`, appended last — `Custom(n)` is variant `n - 1`, and
/// the enum, and the discriminant order is part of the on-chain ABI.
const BRIDGE_SCALE_MISMATCH: u32 = 25;
/// `GateError::NotEnoughSignatures` — the 5th variant, so `Custom(5)`.
const NOT_ENOUGH_SIGNATURES: u32 = 5;

/// H-2 ON SOLANA, the destination half. The asset registry here is what
/// `RegisterAsset` wrote; the claim carries what the SOURCE gate hashed. When
/// they differ, both doors are shut, and this walks both.
///
/// Registered at 6, the mesh at 9: a wire amount the source meant as 1.5 tokens
/// would have been paid out as 1500. Note there is no third option — the scale
/// that matches the signatures is refused by the registry, and the scale the
/// registry accepts hashes to an id nobody signed — so the transfer is stranded
/// rather than mis-paid, and stranded has the cancel -> refund path.
#[tokio::test]
async fn claim_refuses_a_wire_scale_this_gate_did_not_register() {
    let (v1, v2, v3) = (Validator::new(1), Validator::new(2), Validator::new(3));
    // 9-decimal mint registered at 6 — the fixture default.
    let mut fx =
        setup_with_asset_decimals(vec![v1.address, v2.address, v3.address], 2, 5_000_000_000, 0, 9, 6).await;
    let receiver_token = Pubkey::new_unique();
    fx.ctx.set_account(
        &receiver_token,
        &token_account(fx.mint, Pubkey::new_unique(), 0, COption::None, COption::None).into(),
    );
    let owner = Keypair::from_bytes(&fx.owner.to_bytes()).unwrap();

    let accounts = |id: &[u8; 32]| {
        vec![
            AccountMeta::new_readonly(config_pda(), false),
            AccountMeta::new_readonly(asset_pda(&fx.debridge_id), false),
            AccountMeta::new(executed_pda(id), false),
            AccountMeta::new(fx.owner.pubkey(), true),
            AccountMeta::new(fx.vault, false),
            AccountMeta::new(receiver_token, false),
            AccountMeta::new_readonly(vault_authority(), false),
            AccountMeta::new_readonly(spl_token::id(), false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ]
    };

    // 1) The honest keeper's claim: the SOURCE's scale, which is what the
    //    validators signed. The registry refuses it before any token moves.
    let signed = solana_gate::ClaimArgs {
        debridge_id: fx.debridge_id,
        amount: 1_500_000,
        bridge_decimals: 9,
        chain_id_from: DEST_CHAIN,
        nonce: 0,
        receiver: receiver_token.to_bytes().to_vec(),
        auto: None,
        native_sender: vec![0x11; 20],
        signatures: vec![],
    };
    let signed_id = claim_submission_id(&signed);
    let sigs = quorum(&[&v1, &v2], &signed_id);
    let err = exec(
        &mut fx.ctx,
        ix(
            GateInstruction::Claim(solana_gate::ClaimArgs { signatures: sigs, ..signed.clone() }),
            accounts(&signed_id),
        ),
        &[&owner],
    )
    .await
    .expect_err("a mis-scaled claim must be refused");
    assert!(is_custom(&err, BRIDGE_SCALE_MISMATCH), "expected BridgeScaleMismatch, got {err:?}");

    // 2) The same transfer restated at this gate's own scale — what an operator
    //    "fixing" the mismatch by hand would try. Now the id is a different hash,
    //    so the signatures are over some other transfer and the quorum fails.
    let restated = solana_gate::ClaimArgs { bridge_decimals: 6, ..signed };
    let restated_id = claim_submission_id(&restated);
    assert_ne!(restated_id, signed_id, "premise: the scale changes the id");
    let err = exec(
        &mut fx.ctx,
        ix(
            GateInstruction::Claim(solana_gate::ClaimArgs {
                // One signature, so the failure can only be "this is not a
                // validator's signature over THIS id" — not the ordering rule,
                // which a two-element array would trip first for the same reason.
                signatures: quorum(&[&v1], &signed_id),
                ..restated
            }),
            accounts(&restated_id),
        ),
        &[&owner],
    )
    .await
    .expect_err("signatures for another id must not verify");
    assert!(is_custom(&err, NOT_ENOUGH_SIGNATURES), "expected NotEnoughSignatures, got {err:?}");

    let recv = fx.ctx.banks_client.get_account(receiver_token).await.unwrap().unwrap();
    assert_eq!(spl_balance(&recv), 0, "not one unit moved");
    let vault = fx.ctx.banks_client.get_account(fx.vault).await.unwrap().unwrap();
    assert_eq!(spl_balance(&vault), 5_000_000_000, "the vault is untouched");
}

// ---------------------------------------------------------------------------
// H-5 (audit round 5), executed: `RegisterAsset` was instant and unilateral for
// ever, and bound neither the vault nor the scale to anything.
//
// The EVM gate already made the same action wait — `Gate.setLocalToken` behind
// `seal()` + `GOVERNANCE_DELAY` — and the registry is the whole of what stands
// between an owner key and the vaults. On Solana it stayed a one-transaction
// owner action, which bought two drains:
//
//   (a) a legitimate user's 1 TST send paid out as 1000 TST, for ever, because
//       the binding named a scale three digits below the mesh's; and
//   (b) a second, perfectly well-formed debridgeId bound to the LIVE, funded
//       vault, drained with honest validator signatures over an asset no
//       validator could tell apart.
//
// Nothing below needs a compromised key beyond the owner's, and nothing below
// was possible to see coming: no schedule, no notice, no guardian veto.
// ---------------------------------------------------------------------------

/// `GateError::NotSealed` — `Custom(26)`.
const NOT_SEALED: u32 = 26;
/// `GateError::AlreadySealed` — `Custom(27)`.
const ALREADY_SEALED: u32 = 27;
/// `GateError::VaultAssetMismatch` — `Custom(28)`.
const VAULT_ASSET_MISMATCH: u32 = 28;

fn seal_ix(owner: Pubkey) -> Instruction {
    ix(
        GateInstruction::Seal,
        vec![
            AccountMeta::new(config_pda(), false),
            AccountMeta::new_readonly(owner, true),
        ],
    )
}

/// `RegisterAsset` with BOTH trailing accounts attached, which is what
/// `gate-admin` sends: the vault binding (always read) and the governance
/// schedule (read only once the setup phase is over).
fn register_asset_ix(
    owner: Pubkey,
    debridge_id: [u8; 32],
    mint: Pubkey,
    vault: Pubkey,
    bridge_decimals: u8,
) -> Instruction {
    let action = solana_gate::register_asset_action_id(&debridge_id, &mint, &vault, bridge_decimals);
    ix(
        GateInstruction::RegisterAsset { debridge_id, bridge_decimals },
        vec![
            AccountMeta::new_readonly(config_pda(), false),
            AccountMeta::new(owner, true),
            AccountMeta::new(asset_pda(&debridge_id), false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(vault, false),
            AccountMeta::new_readonly(spl_token::id(), false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new(vault_binding_pda(&vault), false),
            AccountMeta::new(gov_pda(&action), false),
        ],
    )
}

/// Read the config, apply `f`, write it back. Used to put a fixture into the
/// pre-H-5 states that no instruction can produce any more — an unsealed live
/// gate, or one whose `setup_deadline` is the zero a pre-H-5 account decodes to.
async fn edit_config(ctx: &mut ProgramTestContext, f: impl FnOnce(&mut Config)) {
    let mut acct = ctx.banks_client.get_account(config_pda()).await.unwrap().unwrap();
    let mut cfg = Config::deserialize(&mut &acct.data[..]).expect("config decodes");
    f(&mut cfg);
    let mut data = vec![0u8; acct.data.len()];
    cfg.serialize(&mut &mut data[..]).expect("config still fits");
    acct.data = data;
    ctx.set_account(&config_pda(), &acct.into());
}

/// The M-1 half of H-5: an unsealed gate must not pay anything out.
///
/// Sealing was a runbook note that no fund-moving instruction consulted, so a
/// gate that was funded and never sealed kept one-transaction registration for
/// ever — which is drain (b) sitting there, waiting for the owner key. Refusing
/// the claim is what makes the step unskippable: an operator cannot run a bridge
/// that pays out without it.
#[tokio::test]
async fn claim_is_refused_until_the_gate_is_sealed() {
    let (v1, v2, v3) = (Validator::new(1), Validator::new(2), Validator::new(3));
    let mut fx = setup_with_asset(vec![v1.address, v2.address, v3.address], 2, 1_000, 0).await;
    let owner = Keypair::from_bytes(&fx.owner.to_bytes()).unwrap();

    let receiver_token = Pubkey::new_unique();
    fx.ctx.set_account(
        &receiver_token,
        &token_account(fx.mint, Pubkey::new_unique(), 0, COption::None, COption::None).into(),
    );

    // Back to the state the fixture would have been left in by `init` alone.
    edit_config(&mut fx.ctx, |c| c.sealed = false).await;

    let args = solana_gate::ClaimArgs {
        debridge_id: fx.debridge_id,
        amount: 250,
        bridge_decimals: FIXTURE_BRIDGE_DECIMALS,
        chain_id_from: DEST_CHAIN,
        nonce: 0,
        receiver: receiver_token.to_bytes().to_vec(),
        auto: None,
        native_sender: vec![0x11; 20],
        signatures: vec![],
    };
    let id = claim_submission_id(&args);
    let accounts = vec![
        AccountMeta::new_readonly(config_pda(), false),
        AccountMeta::new_readonly(asset_pda(&fx.debridge_id), false),
        AccountMeta::new(executed_pda(&id), false),
        AccountMeta::new(fx.owner.pubkey(), true),
        AccountMeta::new(fx.vault, false),
        AccountMeta::new(receiver_token, false),
        AccountMeta::new_readonly(vault_authority(), false),
        AccountMeta::new_readonly(spl_token::id(), false),
        AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
    ];
    let claim = |sigs: Vec<Vec<u8>>| {
        ix(
            GateInstruction::Claim(solana_gate::ClaimArgs { signatures: sigs, ..args.clone() }),
            accounts.clone(),
        )
    };

    // A fully valid, threshold-signed claim. The ONLY thing wrong is the gate.
    let err = exec(&mut fx.ctx, claim(quorum(&[&v1, &v2], &id)), &[&owner])
        .await
        .expect_err("an unsealed gate must release nothing");
    assert!(is_custom(&err, NOT_SEALED), "expected NotSealed, got {err:?}");
    let vault = fx.ctx.banks_client.get_account(fx.vault).await.unwrap().unwrap();
    assert_eq!(spl_balance(&vault), 1_000, "the vault is untouched");
    assert!(
        fx.ctx.banks_client.get_account(executed_pda(&id)).await.unwrap().is_none(),
        "and the transfer is not burned — it is claimable once the gate is sealed"
    );

    // Seal it, and the very same claim goes through.
    exec(&mut fx.ctx, seal_ix(fx.owner.pubkey()), &[&owner]).await.expect("owner may seal");
    exec(&mut fx.ctx, claim(quorum(&[&v1, &v2], &id)), &[&owner])
        .await
        .expect("the same claim must succeed once the registry is final");
    let recv = fx.ctx.banks_client.get_account(receiver_token).await.unwrap().unwrap();
    assert_eq!(spl_balance(&recv), 250, "paid out after sealing");

    // Irreversible, for the reason `Gate.seal` is: an owner who could un-seal
    // would hold the delay in name only.
    let err = exec(&mut fx.ctx, seal_ix(fx.owner.pubkey()), &[&owner])
        .await
        .expect_err("sealing twice must be refused");
    assert!(is_custom(&err, ALREADY_SEALED), "expected AlreadySealed, got {err:?}");
}

/// H-5(a), executed: past the setup phase an asset binding waits out the
/// timelock, and the matured approval is spendable on EXACTLY that binding.
///
/// The scale is the payload of the drain: registered three digits low, a 1 TST
/// send from the mesh pays 1000 TST out of the vault, repeatable until it is
/// empty, with every validator signature honest. So the action id has to commit
/// to the scale — which the second half of this test proves by trying to spend
/// the approval at a different one.
#[tokio::test]
async fn registering_an_asset_on_a_sealed_gate_needs_a_matured_schedule() {
    let (mut ctx, owner) = setup(8, 4, Pubkey::default()).await; // sealed: a live gate
    let mint = Pubkey::new_unique();
    let vault = Pubkey::new_unique();
    let debridge_id = [0x51u8; 32];
    ctx.set_account(&mint, &mint_account_with_decimals(9).into());
    ctx.set_account(
        &vault,
        &token_account(mint, vault_authority(), 0, COption::None, COption::None).into(),
    );

    // 1. The old behaviour: one transaction, no notice, done.
    let err = exec(&mut ctx, register_asset_ix(owner.pubkey(), debridge_id, mint, vault, 6), &[&owner])
        .await
        .expect_err("a sealed gate must not bind an asset instantly");
    assert!(is_custom(&err, GOVERNANCE_NOT_SCHEDULED), "expected GovernanceNotScheduled, got {err:?}");

    // 2. Scheduled, but the delay has not run. This is the window the finding
    //    removed entirely: 48 h in which anyone can read the pending action id
    //    off the chain and the guardian can cancel it.
    let action = solana_gate::register_asset_action_id(&debridge_id, &mint, &vault, 6);
    exec(&mut ctx, schedule_governance(owner.pubkey(), action), &[&owner]).await.expect("schedule");
    let err = exec(&mut ctx, register_asset_ix(owner.pubkey(), debridge_id, mint, vault, 6), &[&owner])
        .await
        .expect_err("an immature schedule must not be spendable");
    assert!(is_custom(&err, GOVERNANCE_NOT_READY), "expected GovernanceNotReady, got {err:?}");

    advance_clock(&mut ctx, GOVERNANCE_DELAY + 1).await;

    // 3. THE SUBSTITUTION: the approval matured for scale 6 — spend it at 3, the
    //    1000x payout. The id is over the scale too, so there is no schedule at
    //    that address at all.
    let err = exec(&mut ctx, register_asset_ix(owner.pubkey(), debridge_id, mint, vault, 3), &[&owner])
        .await
        .expect_err("an approval for one scale must not bind another");
    assert!(is_custom(&err, GOVERNANCE_NOT_SCHEDULED), "expected GovernanceNotScheduled, got {err:?}");

    // 4. The binding that was actually approved goes through.
    exec(&mut ctx, register_asset_ix(owner.pubkey(), debridge_id, mint, vault, 6), &[&owner])
        .await
        .expect("a matured schedule must bind exactly what it named");
    let stored = ctx.banks_client.get_account(asset_pda(&debridge_id)).await.unwrap().unwrap();
    let asset = AssetConfig::deserialize(&mut &stored.data[..]).unwrap();
    assert_eq!(asset.bridge_decimals, 6);
    assert_eq!(asset.vault, vault);

    // 5. One schedule, one binding. The approval is burned, so it cannot be
    //    replayed onto anything.
    let err = exec(&mut ctx, register_asset_ix(owner.pubkey(), [0x52u8; 32], mint, vault, 6), &[&owner])
        .await
        .expect_err("a consumed schedule must not authorise a second binding");
    assert!(is_custom(&err, GOVERNANCE_NOT_SCHEDULED), "expected GovernanceNotScheduled, got {err:?}");
}

/// H-5(b), executed: every debridgeId sharing a vault pays out in the same units.
///
/// The finding asks for one asset per vault, and this bridge cannot have that
/// rule: a `debridgeId` is `keccak(sourceChainId, sourceToken)`, so the same SPL
/// mint behind mesh10's three EVM chains is THREE ids against ONE vault, all
/// correct. The first half of this test is that fan-out — it is the regression
/// test for the naive rule, which would have let the Solana leg accept TST from
/// exactly one chain.
///
/// What IS checkable is the amplification, and it is what the drain uses:
/// `asset_write_allowed` blocks repointing an id that exists and says nothing
/// about a NEW one, so the owner binds a fresh, well-formed id to the live,
/// FUNDED vault at a scale three digits low — and the first honest transfer pays
/// 1000x out of it.
#[tokio::test]
async fn a_second_debridge_id_on_a_live_vault_cannot_change_the_mint_or_the_scale() {
    let (mut ctx, owner) = setup(8, 4, Pubkey::default()).await;
    edit_config(&mut ctx, |c| {
        c.sealed = false;
        c.setup_deadline = i64::MAX; // the setup phase, where this was instant
    })
    .await;

    let mint = Pubkey::new_unique();
    let vault = Pubkey::new_unique();
    ctx.set_account(&mint, &mint_account_with_decimals(9).into());
    // The real vault, with real liquidity in it.
    ctx.set_account(
        &vault,
        &token_account(mint, vault_authority(), 750_000_000, COption::None, COption::None).into(),
    );

    // 1. THE LEGITIMATE FAN-OUT: one asset, one vault, one id per source chain.
    //    All three must register.
    let from_chains = [[0xA0u8; 32], [0xA1u8; 32], [0xA2u8; 32]];
    for did in from_chains {
        exec(&mut ctx, register_asset_ix(owner.pubkey(), did, mint, vault, 6), &[&owner])
            .await
            .unwrap_or_else(|e| panic!("a source chain's own debridgeId must register: {e:?}"));
    }
    let binding = ctx.banks_client.get_account(vault_binding_pda(&vault)).await.unwrap().unwrap();
    assert_eq!(binding.owner, PROGRAM_ID);
    let bound = solana_gate::VaultBinding::deserialize(&mut &binding.data[..]).unwrap();
    assert_eq!(bound.mint, mint);
    assert_eq!(bound.bridge_decimals, 6, "the vault is committed to the units it holds");

    // 2. THE AMPLIFICATION: a fourth id on the same funded vault at scale 3. On a
    //    9-decimal mint that is a 10^6 multiplier on every claim.
    let err = exec(&mut ctx, register_asset_ix(owner.pubkey(), [0xE0u8; 32], mint, vault, 3), &[&owner])
        .await
        .expect_err("a mis-scaled id must not be bound to a live vault");
    assert!(is_custom(&err, VAULT_ASSET_MISMATCH), "expected VaultAssetMismatch, got {err:?}");
    assert!(
        ctx.banks_client.get_account(asset_pda(&[0xE0u8; 32])).await.unwrap().is_none(),
        "and no shadow asset record exists to claim against"
    );

    // 3. Nor can a different mint borrow this vault's liquidity — and this one is
    //    refused EARLIER, by the C1 check that the vault's own SPL `mint` field
    //    must equal the mint being registered. So `VaultBinding::mint` never gets
    //    to speak: it is recorded to make the commitment self-describing, not
    //    because this path could otherwise reach it.
    let other_mint = Pubkey::new_unique();
    ctx.set_account(&other_mint, &mint_account_with_decimals(9).into());
    let err = exec(&mut ctx, register_asset_ix(owner.pubkey(), [0xE1u8; 32], other_mint, vault, 6), &[&owner])
        .await
        .expect_err("a different mint must not share a committed vault");
    assert!(
        format!("{err:?}").contains("InvalidAccountData"),
        "expected the vault/mint check to refuse it first, got {err:?}"
    );

    // 4. A separate vault for the same mint at a DIFFERENT scale is still allowed:
    //    this commits a vault, not a mint. (Whether that is wise is the operator's
    //    call; the program only refuses to mix units inside one pot of funds.)
    let second_vault = Pubkey::new_unique();
    ctx.set_account(
        &second_vault,
        &token_account(mint, vault_authority(), 0, COption::None, COption::None).into(),
    );
    exec(&mut ctx, register_asset_ix(owner.pubkey(), [0xB0u8; 32], mint, second_vault, 3), &[&owner])
        .await
        .expect("a fresh vault carries its own commitment");

    // 5. And the fan-out is still the idempotent no-op deploy scripts re-run.
    exec(&mut ctx, register_asset_ix(owner.pubkey(), from_chains[0], mint, vault, 6), &[&owner])
        .await
        .expect("re-registering an identical binding must stay a no-op");
}

/// The upgrade path for a gate that is ALREADY live, which is the case that
/// decides whether this fix is deployable at all.
///
/// A gate registered by a pre-H-5 build has asset records and funded vaults but
/// no `["vault", vault]` bindings — so on the upgrade alone, drain (b) is still
/// open: the attacker's fresh debridgeId finds an unbound vault and takes it.
/// Closing it must not require a 48 h wait per asset, because that IS the window.
///
/// So re-running `register-asset` with the values already stored backfills the
/// binding and consumes no schedule: an identical write changes nothing the
/// timelock protects. That is the one-command migration, and this proves both
/// halves of it — the backfill lands, and the drain is shut afterwards.
#[tokio::test]
async fn re_registering_a_pre_h5_asset_backfills_its_vault_binding_with_no_schedule() {
    let (v1, v2) = (Validator::new(1), Validator::new(2));
    // The fixture writes the asset record directly, exactly as the old program
    // left it: no vault binding anywhere.
    let mut fx = setup_with_asset(vec![v1.address, v2.address], 2, 400_000, 0).await;
    let owner = Keypair::from_bytes(&fx.owner.to_bytes()).unwrap();
    // A pre-H-5 config decodes `setup_deadline` from its zero padding, so the
    // upgraded gate is on the DELAYED path from the first block. Fail-closed.
    edit_config(&mut fx.ctx, |c| c.setup_deadline = 0).await;
    assert!(
        fx.ctx.banks_client.get_account(vault_binding_pda(&fx.vault)).await.unwrap().is_none(),
        "premise: a pre-H-5 gate has no vault binding"
    );

    // 1. The drain, while the vault carries no commitment: a fresh debridgeId on
    //    the funded vault at a scale below the mesh's, which pays a power of ten
    //    out of it. It needs a schedule now (the gate is sealed), so it is at
    //    least visible — but it is still reachable, which is why the backfill
    //    matters, and why it must not itself cost 48 h.
    let evil = [0xE1u8; 32];
    let evil_scale = FIXTURE_BRIDGE_DECIMALS - 3;
    let action = solana_gate::register_asset_action_id(&evil, &fx.mint, &fx.vault, evil_scale);
    exec(&mut fx.ctx, schedule_governance(fx.owner.pubkey(), action), &[&owner]).await.unwrap();
    advance_clock(&mut fx.ctx, GOVERNANCE_DELAY + 1).await;

    // 2. THE MIGRATION: re-register the asset that is already there, byte for
    //    byte. No schedule of its own, and it writes the binding.
    exec(
        &mut fx.ctx,
        register_asset_ix(
            fx.owner.pubkey(),
            fx.debridge_id,
            fx.mint,
            fx.vault,
            FIXTURE_BRIDGE_DECIMALS,
        ),
        &[&owner],
    )
    .await
    .expect("an identical re-registration must need no schedule — it changes nothing");
    let binding = fx.ctx.banks_client.get_account(vault_binding_pda(&fx.vault)).await.unwrap().unwrap();
    let bound = solana_gate::VaultBinding::deserialize(&mut &binding.data[..]).unwrap();
    assert_eq!(bound.mint, fx.mint, "the binding was backfilled");
    assert_eq!(bound.bridge_decimals, FIXTURE_BRIDGE_DECIMALS);

    // 3. The attacker's approval is still matured and still unspent — and now
    //    lands on a vault whose units are pinned.
    let err = exec(
        &mut fx.ctx,
        register_asset_ix(fx.owner.pubkey(), evil, fx.mint, fx.vault, evil_scale),
        &[&owner],
    )
    .await
    .expect_err("the funded vault must refuse foreign units after the backfill");
    assert!(is_custom(&err, VAULT_ASSET_MISMATCH), "expected VaultAssetMismatch, got {err:?}");

    // The asset record and the liquidity are exactly as they were.
    let stored = fx.ctx.banks_client.get_account(asset_pda(&fx.debridge_id)).await.unwrap().unwrap();
    let asset = AssetConfig::deserialize(&mut &stored.data[..]).unwrap();
    assert_eq!(asset.vault, fx.vault);
    assert_eq!(asset.bridge_decimals, FIXTURE_BRIDGE_DECIMALS);
    let vault = fx.ctx.banks_client.get_account(fx.vault).await.unwrap().unwrap();
    assert_eq!(spl_balance(&vault), 400_000, "not one unit moved during the migration");
}
