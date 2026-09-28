//! Audit round 6, LOW — regression tests for two findings in the native program.
//!
//! LOW-A: `send` never checked `cfg.sealed`, so users could lock real tokens in
//!        an unsealed gate while one-transaction registration was still open.
//!        Fixed: `send` refuses with `NotSealed` (`Custom(26)`), as `claim` does.
//! LOW-B: the "identical re-run" of `RegisterAsset` that backfills the H-5(b)
//!        vault binding failed with `AssetAlreadyRegistered` on a legacy
//!        (pre-decimals, 96/97-byte) asset record, whose decimals decode as 0.
//!        Fixed: same id/mint/vault at IDENTITY scale upgrades the record and
//!        binds the vault; anything else is still refused.
use borsh::BorshSerialize;
use solana_program::instruction::{AccountMeta, Instruction};
use solana_program::program_pack::Pack;
use solana_program::pubkey::Pubkey;
use solana_program_test::{processor, ProgramTest, ProgramTestContext};
use solana_sdk::account::Account;
use solana_sdk::program_option::COption;
use solana_sdk::signature::{Keypair, Signer};
use solana_sdk::transaction::{Transaction, TransactionError};

use solana_gate::{process_instruction, Config, GateInstruction, SendArgs};

const PROGRAM_ID: Pubkey = Pubkey::new_from_array([7u8; 32]);
const CHAIN_ID: u64 = 7565164;
const DEST_CHAIN: u64 = 1337;
const TEST_BRIDGE_DOMAIN: [u8; 32] = [0xD0; 32];
const DECIMALS: u8 = 6;
/// `GateError::AssetAlreadyRegistered` (index 14, +1).
const ASSET_ALREADY_REGISTERED: u32 = 15;
/// `GateError::NotSealed`.
const NOT_SEALED: u32 = 26;

fn pda(seeds: &[&[u8]]) -> Pubkey {
    Pubkey::find_program_address(seeds, &PROGRAM_ID).0
}
fn config_pda() -> Pubkey { pda(&[b"config"]) }
fn asset_pda(id: &[u8; 32]) -> Pubkey { pda(&[b"asset", id]) }
fn sent_pda(id: &[u8; 32]) -> Pubkey { pda(&[b"sent", id]) }
fn vault_authority() -> Pubkey { pda(&[b"vault_authority"]) }
fn vault_binding_pda(v: &Pubkey) -> Pubkey { pda(&[b"vault", v.as_ref()]) }
fn gov_pda(a: &[u8; 32]) -> Pubkey { pda(&[b"gov", a]) }

fn config_space(validators: u32, corridors: u32) -> usize {
    32 + 32 + 32 + (4 + 20 * validators as usize) + 4 + 8 + 1 + 4 + 4 + (4 + 16 * corridors as usize)
}

fn mint_account(decimals: u8) -> Account {
    let mut data = vec![0u8; spl_token::state::Mint::LEN];
    spl_token::state::Mint {
        mint_authority: COption::None,
        supply: 1_000_000_000,
        decimals,
        is_initialized: true,
        freeze_authority: COption::None,
    }
    .pack_into_slice(&mut data);
    Account { lamports: 10_000_000, data, owner: spl_token::id(), executable: false, rent_epoch: 0 }
}

fn token_account(mint: Pubkey, owner: Pubkey, amount: u64) -> Account {
    let mut data = vec![0u8; spl_token::state::Account::LEN];
    spl_token::state::Account {
        mint,
        owner,
        amount,
        delegate: COption::None,
        state: spl_token::state::AccountState::Initialized,
        is_native: COption::None,
        delegated_amount: 0,
        close_authority: COption::None,
    }
    .pack_into_slice(&mut data);
    Account { lamports: 10_000_000, data, owner: spl_token::id(), executable: false, rent_epoch: 0 }
}

fn spl_balance(a: &Account) -> u64 {
    spl_token::state::Account::unpack(&a.data).unwrap().amount
}

fn ix(data: GateInstruction, accounts: Vec<AccountMeta>) -> Instruction {
    Instruction { program_id: PROGRAM_ID, accounts, data: borsh::to_vec(&data).unwrap() }
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

fn register_asset_ix(owner: Pubkey, id: [u8; 32], mint: Pubkey, vault: Pubkey, bridge_decimals: u8) -> Instruction {
    let action = solana_gate::register_asset_action_id(&id, &mint, &vault, bridge_decimals);
    ix(
        GateInstruction::RegisterAsset { debridge_id: id, bridge_decimals },
        vec![
            AccountMeta::new_readonly(config_pda(), false),
            AccountMeta::new(owner, true),
            AccountMeta::new(asset_pda(&id), false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(vault, false),
            AccountMeta::new_readonly(spl_token::id(), false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new(vault_binding_pda(&vault), false),
            AccountMeta::new(gov_pda(&action), false),
        ],
    )
}

fn send_submission_id(id: &[u8; 32], amount: u64, receiver: &[u8], nonce: u64) -> [u8; 32] {
    fn be32(v: u64) -> [u8; 32] {
        let mut o = [0u8; 32];
        o[24..].copy_from_slice(&v.to_be_bytes());
        o
    }
    solana_program::keccak::hashv(&[
        &be32(1), &TEST_BRIDGE_DOMAIN, id, &be32(CHAIN_ID), &be32(DEST_CHAIN),
        &[DECIMALS], &be32(amount), receiver, &be32(nonce),
    ])
    .to_bytes()
}

struct Fx {
    pt: ProgramTest,
    owner: Keypair,
    mint: Pubkey,
    vault: Pubkey,
    user_token: Pubkey,
    id: [u8; 32],
}

/// A gate config (corridor to DEST_CHAIN pre-registered), a 6-decimal mint, a
/// clean vault owned by the vault authority, and a funded user token account.
/// NO asset record — each test supplies (or registers) its own.
fn base(sealed: bool, setup_deadline: i64) -> Fx {
    let owner = Keypair::new();
    let (mint, vault, user_token) = (Pubkey::new_unique(), Pubkey::new_unique(), Pubkey::new_unique());
    let mut pt = ProgramTest::new("solana_gate", PROGRAM_ID, processor!(process_instruction));
    pt.add_account(
        owner.pubkey(),
        Account { lamports: 10_000_000_000, data: vec![], owner: solana_sdk::system_program::id(), executable: false, rent_epoch: 0 },
    );
    let cfg = Config {
        owner: owner.pubkey(),
        bridge_domain: TEST_BRIDGE_DOMAIN,
        guardian: Pubkey::default(),
        validators: vec![[1u8; 20], [2u8; 20], [3u8; 20]],
        threshold: 2,
        chain_id: CHAIN_ID,
        paused: false,
        max_validators: 8,
        max_corridors: 4,
        nonce_to: vec![(DEST_CHAIN, 0)],
        sealed,
        setup_deadline,
    };
    let mut data = vec![0u8; config_space(8, 4)];
    cfg.serialize(&mut &mut data[..]).unwrap();
    pt.add_account(config_pda(), Account { lamports: 10_000_000_000, data, owner: PROGRAM_ID, executable: false, rent_epoch: 0 });
    pt.add_account(mint, mint_account(DECIMALS));
    pt.add_account(vault, token_account(mint, vault_authority(), 0));
    pt.add_account(user_token, token_account(mint, owner.pubkey(), 5_000_000));
    Fx { pt, owner, mint, vault, user_token, id: [9u8; 32] }
}

fn send_ix(fx_owner: Pubkey, id: [u8; 32], user_token: Pubkey, vault: Pubkey, amount: u64, receiver: &[u8], nonce: u64) -> Instruction {
    let sid = send_submission_id(&id, amount, receiver, nonce);
    ix(
        GateInstruction::Send(SendArgs { debridge_id: id, amount, chain_id_to: DEST_CHAIN, receiver: receiver.to_vec(), auto: None }),
        vec![
            AccountMeta::new(config_pda(), false),
            AccountMeta::new_readonly(asset_pda(&id), false),
            AccountMeta::new(fx_owner, true),
            AccountMeta::new(user_token, false),
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(spl_token::id(), false),
            AccountMeta::new(sent_pda(&sid), false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
    )
}

fn seal_ix(owner: Pubkey) -> Instruction {
    ix(
        GateInstruction::Seal,
        vec![AccountMeta::new(config_pda(), false), AccountMeta::new_readonly(owner, true)],
    )
}

async fn read_config(ctx: &mut ProgramTestContext) -> Config {
    let a = ctx.banks_client.get_account(config_pda()).await.unwrap().unwrap();
    <Config as borsh::BorshDeserialize>::deserialize(&mut &a.data[..]).unwrap()
}

// ---------------------------------------------------------------------------
// LOW-A
// ---------------------------------------------------------------------------

/// Nothing enters an unsealed gate: the send is refused before any state moves,
/// and the very same send goes through once the owner seals.
#[tokio::test]
async fn send_is_refused_until_the_gate_is_sealed() {
    let fx = base(false, i64::MAX); // setup phase open
    let (owner, mint, vault, user_token, id) = (fx.owner, fx.mint, fx.vault, fx.user_token, fx.id);
    let mut ctx = fx.pt.start_with_context().await;
    exec(&mut ctx, register_asset_ix(owner.pubkey(), id, mint, vault, DECIMALS), &[&owner])
        .await
        .expect("setup-phase registration");

    let receiver = [0xEEu8; 20];
    let amount = 2_000_000u64;
    let sid = send_submission_id(&id, amount, &receiver, 0);
    let err = exec(&mut ctx, send_ix(owner.pubkey(), id, user_token, vault, amount, &receiver, 0), &[&owner])
        .await
        .expect_err("an unsealed gate must lock nothing");
    assert!(is_custom(&err, NOT_SEALED), "expected NotSealed, got {err:?}");
    let v = ctx.banks_client.get_account(vault).await.unwrap().unwrap();
    let u = ctx.banks_client.get_account(user_token).await.unwrap().unwrap();
    assert_eq!(spl_balance(&v), 0, "nothing locked");
    assert_eq!(spl_balance(&u), 5_000_000, "user untouched");
    assert!(ctx.banks_client.get_account(sent_pda(&sid)).await.unwrap().is_none(), "no sent record");
    assert_eq!(read_config(&mut ctx).await.nonce_to, vec![(DEST_CHAIN, 0)], "nonce not consumed");

    exec(&mut ctx, seal_ix(owner.pubkey()), &[&owner]).await.expect("owner seals");
    exec(&mut ctx, send_ix(owner.pubkey(), id, user_token, vault, amount, &receiver, 0), &[&owner])
        .await
        .expect("the same send once sealed");
    let v = ctx.banks_client.get_account(vault).await.unwrap().unwrap();
    assert_eq!(spl_balance(&v), amount);
    assert!(ctx.banks_client.get_account(sent_pda(&sid)).await.unwrap().is_some());
}

// ---------------------------------------------------------------------------
// LOW-B
// ---------------------------------------------------------------------------

/// Legacy `["asset", id]` account: body `debridge_id | mint | vault` (96 bytes),
/// in an account of `len` bytes (96, or the 97 the old program allocated).
fn legacy_asset(id: [u8; 32], mint: Pubkey, vault: Pubkey, len: usize) -> Account {
    let mut data = vec![0u8; len];
    data[..32].copy_from_slice(&id);
    data[32..64].copy_from_slice(mint.as_ref());
    data[64..96].copy_from_slice(vault.as_ref());
    // Rent-exempt for its OWN size only, as the old program left it: the upgrade
    // must top it up for the larger record.
    Account { lamports: 1_600_000, data, owner: PROGRAM_ID, executable: false, rent_epoch: 0 }
}

/// A LIVE legacy gate (sealed, no setup window), as a pre-decimals deploy is,
/// with a second clean vault of the same mint available.
async fn legacy_gate(len: usize) -> (ProgramTestContext, Keypair, Pubkey, Pubkey, Pubkey, Pubkey, [u8; 32]) {
    let mut fx = base(true, 0);
    fx.pt.add_account(asset_pda(&fx.id), legacy_asset(fx.id, fx.mint, fx.vault, len));
    let other_vault = Pubkey::new_unique();
    fx.pt.add_account(other_vault, token_account(fx.mint, vault_authority(), 0));
    let ctx = fx.pt.start_with_context().await;
    (ctx, fx.owner, fx.mint, fx.vault, other_vault, fx.user_token, fx.id)
}

#[tokio::test]
async fn a_legacy_asset_rerun_at_identity_scale_upgrades_it_and_binds_the_vault() {
    for len in [96usize, 97] {
        let (mut ctx, owner, mint, vault, _, user_token, id) = legacy_gate(len).await;
        let action = solana_gate::register_asset_action_id(&id, &mint, &vault, DECIMALS);

        exec(&mut ctx, register_asset_ix(owner.pubkey(), id, mint, vault, DECIMALS), &[&owner])
            .await
            .unwrap_or_else(|e| panic!("len {len}: the documented migration must succeed: {e:?}"));

        // The vault binding is backfilled at identity scale.
        let b = ctx.banks_client.get_account(vault_binding_pda(&vault)).await.unwrap().expect("binding");
        let bound = <solana_gate::VaultBinding as borsh::BorshDeserialize>::deserialize(&mut &b.data[..]).unwrap();
        assert_eq!(bound.mint, mint);
        assert_eq!(bound.bridge_decimals, DECIMALS);
        // The record is upgraded in place to the current layout, rent-exempt.
        let a = ctx.banks_client.get_account(asset_pda(&id)).await.unwrap().unwrap();
        assert!(a.data.len() > len, "record grown past the legacy size");
        let rent = ctx.banks_client.get_rent().await.unwrap();
        assert!(rent.is_exempt(a.lamports, a.data.len()), "topped up to rent exemption");
        let rec = <solana_gate::AssetConfig as borsh::BorshDeserialize>::deserialize(&mut &a.data[..]).unwrap();
        assert_eq!((rec.debridge_id, rec.mint, rec.vault), (id, mint, vault));
        assert_eq!((rec.bridge_decimals, rec.local_decimals), (DECIMALS, DECIMALS));
        // No schedule was needed, and none was consumed.
        assert!(ctx.banks_client.get_account(gov_pda(&action)).await.unwrap().is_none());

        // A second run is now an ordinary byte-for-byte no-op.
        exec(&mut ctx, register_asset_ix(owner.pubkey(), id, mint, vault, DECIMALS), &[&owner])
            .await
            .expect("identical re-run of the upgraded record");

        // And the asset still bridges 1:1, with the scale in the id.
        let receiver = [0xEEu8; 20];
        exec(&mut ctx, send_ix(owner.pubkey(), id, user_token, vault, 1_234_567, &receiver, 0), &[&owner])
            .await
            .expect("send on the upgraded asset");
        let v = ctx.banks_client.get_account(vault).await.unwrap().unwrap();
        assert_eq!(spl_balance(&v), 1_234_567);
    }
}

#[tokio::test]
async fn a_legacy_asset_is_not_rewritable_at_another_scale_or_vault() {
    for len in [96usize, 97] {
        // Non-identity scales: 0 (what the legacy record decodes to) and 3.
        for scale in [0u8, 3] {
            let (mut ctx, owner, mint, vault, _, _, id) = legacy_gate(len).await;
            let err = exec(&mut ctx, register_asset_ix(owner.pubkey(), id, mint, vault, scale), &[&owner])
                .await
                .expect_err("a non-identity scale is not the legacy re-run");
            assert!(is_custom(&err, ASSET_ALREADY_REGISTERED), "len {len} scale {scale}: {err:?}");
            assert!(ctx.banks_client.get_account(vault_binding_pda(&vault)).await.unwrap().is_none());
            let a = ctx.banks_client.get_account(asset_pda(&id)).await.unwrap().unwrap();
            assert_eq!(a.data.len(), len, "legacy record untouched");
        }
        // A different vault, even at identity scale, is a repoint.
        let (mut ctx, owner, mint, vault, other_vault, _, id) = legacy_gate(len).await;
        let err = exec(&mut ctx, register_asset_ix(owner.pubkey(), id, mint, other_vault, DECIMALS), &[&owner])
            .await
            .expect_err("a legacy record cannot be repointed at another vault");
        assert!(is_custom(&err, ASSET_ALREADY_REGISTERED), "len {len}: {err:?}");
        assert!(ctx.banks_client.get_account(vault_binding_pda(&other_vault)).await.unwrap().is_none());
        let a = ctx.banks_client.get_account(asset_pda(&id)).await.unwrap().unwrap();
        assert_eq!(a.data.len(), len);
        let _ = vault;
    }
}
