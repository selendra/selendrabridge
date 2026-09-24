//! `gate-admin` — the on-chain client for the Solana gate's governance
//! instructions.
//!
//! `scripts/testing/solana-onchain.sh` states the gap this fills: "driving
//! init/send/claim on-chain needs a client that…" — there wasn't one. The gate
//! could be built and deployed but never *configured*, so nothing downstream
//! (corridors, assets, the relayer) could be exercised against a real cluster.
//!
//! It lives in `solana-relayer` because that crate already carries the only
//! dependency set that can talk to Solana: `solana-client` pins `zeroize <1.4`,
//! which cannot coexist with alloy's `^1.5`, so no EVM-side crate can host it.
//!
//! Every subcommand is owner- or upgrade-authority-gated ON-CHAIN. This tool
//! only builds and signs transactions; it grants no authority of its own.
//!
//!   gate-admin (--rpc-env <VAR> | --rpc <url>) --keypair <path> --program <pubkey> <command>
//!
//!     `--rpc-env` names an environment variable holding the endpoint. Prefer it
//!     for a keyed provider URL: `--rpc` puts the key in `ps` and shell history.
//!
//!     init --chain-id N --threshold N --validator 0x.. [--validator 0x..]
//!          --bridge-domain <0x…32 bytes>
//!          [--max-validators N] [--max-corridors N] [--guardian <pubkey>]
//!     register-corridor --chain-id-to N
//!     register-asset --debridge-id 0x.. --mint <pubkey> --vault <pubkey> --bridge-decimals N
//!                    (N = the asset's mesh-wide bridge decimals; the SAME value every
//!                    EVM gate registered with setBridgeDecimals)
//!                    (past the setup phase this needs a matured schedule — see below)
//!     seal           end the setup phase: IRREVERSIBLE, and required before the
//!                    gate will claim anything
//!     set-threshold --threshold N            (a DECREASE needs a matured schedule)
//!     set-validator --validator 0x.. --active <bool>
//!                                            (an ADDITION needs a matured schedule)
//!     schedule-governance (--add-validator 0x.. | --lower-threshold N | --action-id 0x..
//!                          | --register-asset --debridge-id 0x.. --mint <pubkey>
//!                            --vault <pubkey> --bridge-decimals N)
//!     cancel-governance   (same selectors)
//!     governance-status   (same selectors)
//!     send --debridge-id 0x.. --amount N --chain-id-to N --receiver 0x..
//!          --from-token-account <pubkey>
//!     cancel --submission-id 0x.. --debridge-id 0x.. --wire-amount N --bridge-decimals N
//!            --chain-id-from N --nonce N
//!            --receiver 0x.. --native-sender 0x.. --signature 0x.. [--signature 0x..]
//!     refund --submission-id 0x.. --debridge-id 0x.. --wire-amount N --bridge-decimals N
//!            --chain-id-to N --nonce N --receiver 0x.. --native-sender 0x..
//!            [--to-token-account <pubkey>]   (default: the account `send` debited,
//!                                             read from the ["sent", id] record)
//!            --signature 0x.. [--signature 0x..]
//!     digest --submission-id 0x.. — print the cancel/refund digests to sign
//!     asset-status --debridge-id 0x.. — what the gate has bound for that id, and
//!                    what its vault is committed to (H-5). Read-only.
//!     show
//!
//! AMOUNTS: `send --amount` is in MINT units (the program scales it down).
//! `cancel`/`refund --wire-amount` is the WIRE amount, in the asset's bridge
//! decimals — the value hashed into the submissionId, i.e. the sig-store record's
//! `amount`. They differ whenever an asset's mint has more decimals than its
//! bridge decimals, so the two are deliberately different flags.
//!
//! `--bridge-decimals` is that same scale as a number, and is ALSO hashed into
//! the id (H-2). It is required rather than read from the asset registry on
//! purpose: a cancel is the recovery path for a transfer this gate cannot settle,
//! including one whose asset it never registered, so there may be nothing on
//! chain to read. Pass the sig-store record's `bridge_decimals`. A wrong value
//! simply produces an id no validator signed.
//!
//! `cancel`/`refund` take signatures as INPUT rather than signing themselves:
//! they are validator attestations over domain-separated digests, and a tool that
//! could mint them would be a tool that could burn or claw back any transfer.
//! Use `digest` to get the bytes, sign them with the validator keys wherever
//! those live, and pass the results back.
//!
//! ## Governance timelock (audit round 4, H-2)
//!
//! Adding a validator or LOWERING the threshold grants signing power, so the
//! program makes it wait: `schedule-governance` first, then 48 h later the
//! `set-validator` / `set-threshold` call consumes the schedule (and must land
//! within the 7-day grace window or be re-scheduled). Removing a validator and
//! RAISING the threshold are instant. `set-validator`/`set-threshold` print the
//! action id they need, so a refused call tells you what to schedule.
//!
//! ## The setup phase (audit round 5, H-5)
//!
//! Binding an asset decides which mint and vault back a `debridgeId` AND at what
//! wire scale, so past the setup phase it is power-granting too: a scale one digit
//! low pays a power of ten out of the vault on an ordinary user's transfer, and a
//! fresh `debridgeId` aimed at an already-funded vault drains it outright. So
//! `register-asset` is instant only while the gate is in its setup phase — before
//! `seal` and within `SETUP_WINDOW` of `init` — and behind the 48 h timelock after
//! that. `register-asset` prints the action id it needs, and
//! `schedule-governance --register-asset …` schedules exactly it.
//!
//! `claim` is refused until `seal` lands, so the wiring order is: init →
//! register-corridor → register-asset → **seal** → fund the vaults.
//!
//! A vault backs exactly ONE asset: a second `debridgeId` naming a vault already
//! recorded in `["vault", vault]` is refused (`Custom(28)`).
//!
//! The program UPGRADE authority cannot be timelocked by the program itself:
//! put it behind a Squads / SPL-Governance timelock before any production use.

use std::str::FromStr;

use bridge_solana::instruction::{
    add_validator_action_id, lower_threshold_action_id, register_asset_action_id, GateInstruction,
    GovernanceSchedule, InitArgs, GOVERNANCE_DELAY_SECS, GOVERNANCE_GRACE_SECS,
};
use borsh::BorshDeserialize as _;
use solana_relayer::gate::{
    decode_config_view, domain_id, hex20, hex32, ConfigTail, BPF_LOADER_UPGRADEABLE,
    CANCEL_PREFIX, REFUND_PREFIX, SPL_TOKEN,
};
use solana_relayer::target::refund_accounts;
use solana_client::rpc_client::RpcClient;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{read_keypair_file, Signer};
use solana_sdk::transaction::Transaction;

/// Parse a repeated `--signature 0x..` into 65-byte r||s||v arrays.
fn parse_sigs(args: &Args) -> anyhow::Result<Vec<Vec<u8>>> {
    let out: Vec<Vec<u8>> = args
        .all("--signature")
        .iter()
        .map(|s| {
            let h = s.strip_prefix("0x").unwrap_or(s);
            hex::decode(h).map_err(|_| anyhow::anyhow!("signature {s:?} is not hex"))
        })
        .collect::<Result<_, _>>()?;
    anyhow::ensure!(!out.is_empty(), "at least one --signature is required");
    for s in &out {
        anyhow::ensure!(s.len() == 65, "each signature must be 65 bytes, got {}", s.len());
    }
    Ok(out)
}

/// The governance action id a `schedule-governance` / `cancel-governance` /
/// `governance-status` call names: exactly one of `--add-validator 0x..`,
/// `--lower-threshold N` or a raw `--action-id 0x..`.
fn governance_action_id(args: &Args) -> anyhow::Result<[u8; 32]> {
    // H-5: the asset-binding action id is built from four values rather than one,
    // so it gets its own selector instead of another slot in the tuple below.
    if args.has("--register-asset") {
        return Ok(register_asset_action(args)?.0);
    }
    match (args.get("--add-validator"), args.get("--lower-threshold"), args.get("--action-id")) {
        (Some(v), None, None) => Ok(add_validator_action_id(&hex20(&v)?)),
        (None, Some(t), None) => Ok(lower_threshold_action_id(t.parse()?)),
        (None, None, Some(a)) => hex32(&a),
        _ => anyhow::bail!(
            "name exactly one action: --add-validator 0x.. | --lower-threshold N | \
             --action-id 0x.. | --register-asset (with --debridge-id/--mint/--vault/--bridge-decimals)"
        ),
    }
}

/// The four values an asset binding commits to, and the action id over them
/// (H-5). Shared by `register-asset` and the `--register-asset` governance
/// selector so the id a refused call prints is provably the one that schedules it.
fn register_asset_action(args: &Args) -> anyhow::Result<([u8; 32], [u8; 32], Pubkey, Pubkey, u8)> {
    let debridge_id = hex32(&args.req("--debridge-id")?)?;
    let mint = Pubkey::from_str(&args.req("--mint")?)?;
    let vault = Pubkey::from_str(&args.req("--vault")?)?;
    // Required, never defaulted: a wrong value scales every transfer of the asset
    // by a power of ten, and the binding is write-once.
    let bridge_decimals: u8 = args
        .req("--bridge-decimals")?
        .parse()
        .map_err(|e| anyhow::anyhow!("--bridge-decimals: {e}"))?;
    let action_id =
        register_asset_action_id(&debridge_id, &mint.to_bytes(), &vault.to_bytes(), bridge_decimals);
    Ok((action_id, debridge_id, mint, vault, bridge_decimals))
}

/// The H-5(b) vault-binding record: which `debridgeId` a vault backs.
fn vault_binding_pda(program_id: &Pubkey, vault: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"vault", vault.as_ref()], program_id).0
}

fn gov_pda(program_id: &Pubkey, action_id: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[b"gov", action_id], program_id).0
}

/// Minimal flag reader: `--name value`. Repeated flags collect.
struct Args(Vec<String>);
impl Args {
    fn get(&self, name: &str) -> Option<String> {
        self.0.iter().position(|a| a == name).and_then(|i| self.0.get(i + 1)).cloned()
    }
    fn all(&self, name: &str) -> Vec<String> {
        self.0
            .iter()
            .enumerate()
            .filter(|(_, a)| a.as_str() == name)
            .filter_map(|(i, _)| self.0.get(i + 1).cloned())
            .collect()
    }
    fn req(&self, name: &str) -> anyhow::Result<String> {
        self.get(name).ok_or_else(|| anyhow::anyhow!("missing required flag {name}"))
    }
    /// A bare flag with no value, e.g. `--register-asset`.
    fn has(&self, name: &str) -> bool {
        self.0.iter().any(|a| a == name)
    }
}

/// `anyhow`'s default `Error:` print goes straight to stderr, around the
/// subscriber the daemons install — and a transport failure inside it carries
/// the RPC URL, which on a keyed endpoint is the provider key (found in the
/// live mesh9 logs, 2026-09-21). So this scrubs the one line it prints.
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {}", log_scrub::scrub(&format!("{e:?}")));
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> anyhow::Result<()> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    // The command is the first bare token that is NOT a flag's value. Skipping
    // only `--`-prefixed tokens is not enough: `--rpc https://…` would make the
    // URL look like the command.
    let cmd = argv
        .iter()
        .enumerate()
        .find(|(i, a)| {
            !a.starts_with("--") && !argv.get(i.wrapping_sub(1)).is_some_and(|p| p.starts_with("--"))
        })
        .map(|(_, a)| a.clone())
        .ok_or_else(|| anyhow::anyhow!("no command; see the header of this file"))?;
    let args = Args(argv);

    let rpc_url = solana_relayer::cli::resolve_rpc(args.get("--rpc"), args.get("--rpc-env"), |v| {
        std::env::var(v).ok()
    })?;
    let program_id = Pubkey::from_str(&args.req("--program")?)?;
    let payer = read_keypair_file(args.req("--keypair")?)
        .map_err(|e| anyhow::anyhow!("reading keypair: {e}"))?;
    let rpc = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    let (config_pda, _) = Pubkey::find_program_address(&[b"config"], &program_id);
    let (vault_authority, _) = Pubkey::find_program_address(&[b"vault_authority"], &program_id);

    if cmd == "digest" {
        let id = hex32(&args.req("--submission-id")?)?;
        println!("submissionId : 0x{}", hex::encode(id));
        println!("cancelId     : 0x{}", hex::encode(domain_id(CANCEL_PREFIX, &id)));
        println!("refundId     : 0x{}", hex::encode(domain_id(REFUND_PREFIX, &id)));
        println!();
        println!("Validators sign the EIP-191 digest of the id above — the same");
        println!("`personal_sign` shape as the EVM side, so `cast wallet sign` works:");
        println!("  cast wallet sign --private-key <key> <cancelId|refundId>");
        return Ok(());
    }

    // H-5: what is actually on chain for an asset. A deploy that registered the
    // wrong `--bridge-decimals` produces a gate that signs and quotes normally and
    // then pays out a power of ten wrong (or, with the H-2 check, cannot settle at
    // all), so the read-back is worth a command of its own.
    if cmd == "asset-status" {
        use bridge_solana::account::{decode, AssetAccount, VaultBindingAccount};
        let debridge_id = hex32(&args.req("--debridge-id")?)?;
        let (asset_pda, _) = Pubkey::find_program_address(&[b"asset", &debridge_id], &program_id);
        println!("debridgeId : 0x{}", hex::encode(debridge_id));
        println!("asset PDA  : {asset_pda}");
        match rpc.get_account(&asset_pda) {
            Ok(acct) if acct.owner == program_id => {
                match decode::<AssetAccount>(&acct.data) {
                    Some(a) => {
                        let mint = Pubkey::new_from_array(a.mint);
                        let vault = Pubkey::new_from_array(a.vault);
                        println!("  mint           : {mint}");
                        println!("  vault          : {vault}");
                        println!("  bridge decimals: {}", a.bridge_decimals);
                        println!("  mint decimals  : {}", a.local_decimals);
                        println!(
                            "  bridge unit    : {}",
                            a.bridge_unit().map(|u| u.to_string()).unwrap_or_else(|| "OVERFLOW".into())
                        );
                        // The H-5(b) commitment. Every debridgeId sharing this
                        // vault must agree with it, and a gate registered before
                        // H-5 has none until `register-asset` is re-run.
                        let binding_pda = vault_binding_pda(&program_id, &vault);
                        println!("  vault binding  : {binding_pda}");
                        match rpc.get_account(&binding_pda) {
                            Ok(b) if b.owner == program_id => match decode::<VaultBindingAccount>(&b.data) {
                                Some(vb) => {
                                    println!(
                                        "    committed to : mint {} at scale {}",
                                        Pubkey::new_from_array(vb.mint),
                                        vb.bridge_decimals
                                    );
                                    if vb.mint != a.mint || vb.bridge_decimals != a.bridge_decimals {
                                        println!("    MISMATCH against the asset record above");
                                    }
                                }
                                None => println!("    UNREADABLE (layout drift?)"),
                            },
                            _ => println!(
                                "    NOT COMMITTED — a pre-H-5 registration. Re-run \
                                 `register-asset` with these exact values to backfill it \
                                 (no schedule needed: an identical write is a no-op)"
                            ),
                        }
                    }
                    None => println!("  UNREADABLE (layout drift between program and gate-admin?)"),
                }
            }
            Ok(_) => println!("  NOT REGISTERED (an account exists but the program does not own it)"),
            Err(_) => println!("  NOT REGISTERED"),
        }
        return Ok(());
    }

    if cmd == "governance-status" {
        let action_id = governance_action_id(&args)?;
        let pda = gov_pda(&program_id, &action_id);
        println!("action id : 0x{}", hex::encode(action_id));
        println!("gov PDA   : {pda}");
        match rpc.get_account(&pda) {
            Ok(acct) if acct.owner == program_id && acct.data.len() >= 8 => {
                let sched = GovernanceSchedule::deserialize(&mut &acct.data[..])?;
                if sched.ready_at == 0 {
                    println!("status    : NOT SCHEDULED (consumed or cancelled)");
                } else {
                    let now = rpc
                        .get_account(&solana_sdk::sysvar::clock::id())
                        .ok()
                        .and_then(|a| solana_sdk::account::from_account::<solana_sdk::clock::Clock, _>(&a))
                        .map(|c| c.unix_timestamp);
                    println!("ready_at  : {} (unix, cluster clock)", sched.ready_at);
                    println!("expires   : {}", sched.ready_at + GOVERNANCE_GRACE_SECS);
                    match now {
                        Some(now) if now < sched.ready_at => {
                            println!("status    : SCHEDULED, matures in {}s", sched.ready_at - now)
                        }
                        Some(now) if now > sched.ready_at + GOVERNANCE_GRACE_SECS => {
                            println!("status    : EXPIRED — re-run schedule-governance")
                        }
                        Some(_) => println!("status    : READY — execute set-validator / set-threshold now"),
                        None => println!("status    : scheduled (could not read the cluster clock)"),
                    }
                }
            }
            _ => println!("status    : NOT SCHEDULED"),
        }
        return Ok(());
    }

    if cmd == "show" {
        println!("program        : {program_id}");
        println!("config PDA     : {config_pda}");
        println!("vault authority: {vault_authority}");
        match rpc.get_account(&config_pda) {
            Ok(acct) => {
                println!("config account : {} bytes, owner {}", acct.data.len(), acct.owner);
                // Deserialized through the ONE mirrored layout (`gate::ConfigView`),
                // never sliced at hardcoded offsets. An earlier version read
                // `validators` from byte 64 and silently reported zeros for
                // everything once `bridge_domain` was inserted ahead of `guardian`
                // — a diagnostic that lies is worse than none. Sharing the struct
                // with the runner means drift now breaks both loudly, together.
                let mut cursor: &[u8] = &acct.data;
                match decode_config_view(&mut cursor) {
                    Ok(c) => {
                        let guardian = Pubkey::new_from_array(c.guardian);
                        println!("  owner        : {}", Pubkey::new_from_array(c.owner));
                        println!("  bridge domain: 0x{}", hex::encode(c.bridge_domain));
                        println!(
                            "  guardian     : {}",
                            if guardian == Pubkey::default() {
                                "none".to_string()
                            } else {
                                guardian.to_string()
                            }
                        );
                        println!("  validators   : {}", c.validators.len());
                        for v in &c.validators {
                            println!("    0x{}", hex::encode(v));
                        }
                        println!("  threshold    : {}", c.threshold);
                        println!("  chain_id     : {}", c.chain_id);
                        println!("  paused       : {}", c.paused);
                        // The capacity/corridor tail continues from the same
                        // cursor. Only `show` reads it, so it stays out of the
                        // hot-path struct — and if it ever drifts, the fields
                        // above still print.
                        match <ConfigTail as borsh::BorshDeserialize>::deserialize(&mut cursor) {
                            Ok(t) => {
                                println!(
                                    "  capacity     : {} validators, {} corridors",
                                    t.max_validators, t.max_corridors
                                );
                                println!("  corridors    : {}", t.nonce_to.len());
                                for (chain, nonce) in &t.nonce_to {
                                    println!("    -> chain {chain}  next nonce {nonce}");
                                }
                                // H-5. An unsealed gate cannot claim at all, and
                                // the runbook step that fixes it is one command,
                                // so say which state this is in plain words.
                                println!("  sealed       : {}", t.sealed);
                                if t.sealed {
                                    println!("    asset bindings are timelocked; claim is enabled");
                                } else if t.setup_deadline == 0 {
                                    // A deadline of 0 is not something an H-5 `init`
                                    // can produce (it always stores now + 7 days), so
                                    // these 9 bytes came from the account's rent
                                    // padding: the config was written by an older
                                    // program. Which of the two states that means
                                    // depends on the program deployed RIGHT NOW,
                                    // which this account cannot say — so say both
                                    // rather than assert the wrong one.
                                    println!(
                                        "    written by a pre-H-5 program (setup_deadline 0 is padding, not a date)"
                                    );
                                    println!(
                                        "    -> if the deployed program HAS H-5: bindings are timelocked and \
                                         CLAIM IS REFUSED until `seal`"
                                    );
                                    println!(
                                        "    -> if it does not: there is no seal rule at all, and \
                                         `register-asset` is still instant and unilateral"
                                    );
                                } else {
                                    println!(
                                        "    setup phase until {} — bindings are instant, and \
                                         CLAIM IS REFUSED until `seal`",
                                        t.setup_deadline
                                    );
                                }
                            }
                            Err(e) => println!("  capacity/corridors UNREADABLE: {e}"),
                        }
                    }
                    Err(e) => println!("  UNREADABLE: {e} (layout drift between program and gate-admin?)"),
                }
            }
            Err(_) => println!("config account : NOT INITIALIZED (run `init`)"),
        }
        return Ok(());
    }

    let (ix_data, accounts) = match cmd.as_str() {
        "init" => {
            let validators: Vec<[u8; 20]> =
                args.all("--validator").iter().map(|v| hex20(v)).collect::<Result<_, _>>()?;
            anyhow::ensure!(!validators.is_empty(), "init needs at least one --validator");
            let threshold: u32 = args.req("--threshold")?.parse()?;
            let chain_id: u64 = args.req("--chain-id")?.parse()?;
            // The program refuses it too; refusing here saves a doomed transaction.
            anyhow::ensure!(chain_id != 0, "--chain-id must be non-zero (it is bound into every submissionId)");
            let max_validators: u32 =
                args.get("--max-validators").unwrap_or_else(|| "8".into()).parse()?;
            let max_corridors: u32 =
                args.get("--max-corridors").unwrap_or_else(|| "8".into()).parse()?;
            // Required, with no default: a defaulted domain shared by every
            // deployment would be the same as having none.
            let bridge_domain = hex32(&args.req("--bridge-domain")?)?;
            let guardian = match args.get("--guardian") {
                Some(g) => Pubkey::from_str(&g)?.to_bytes(),
                None => [0u8; 32],
            };

            let loader = Pubkey::from_str(BPF_LOADER_UPGRADEABLE)?;
            let (program_data, _) =
                Pubkey::find_program_address(&[program_id.as_ref()], &loader);

            (
                GateInstruction::Init(InitArgs {
                    bridge_domain,
                    validators,
                    threshold,
                    chain_id,
                    max_validators,
                    max_corridors,
                    guardian,
                })
                .to_bytes(),
                vec![
                    AccountMeta::new(config_pda, false),
                    AccountMeta::new(payer.pubkey(), true),
                    AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                    AccountMeta::new_readonly(program_id, false),
                    AccountMeta::new_readonly(program_data, false),
                ],
            )
        }
        "register-corridor" => (
            GateInstruction::RegisterCorridor { chain_id_to: args.req("--chain-id-to")?.parse()? }
                .to_bytes(),
            vec![
                AccountMeta::new(config_pda, false),
                AccountMeta::new_readonly(payer.pubkey(), true),
            ],
        ),
        // H-5: instant during the setup phase, timelocked after `seal`. The gov
        // account is ALWAYS attached so one command works in both states, and the
        // action id is printed so a refused call tells you what to schedule.
        "register-asset" => {
            let (action_id, debridge_id, mint, vault, bridge_decimals) =
                register_asset_action(&args)?;
            let (asset_pda, _) =
                Pubkey::find_program_address(&[b"asset", &debridge_id], &program_id);
            println!("registerAsset action id: 0x{}", hex::encode(action_id));
            println!(
                "(past the setup phase this needs `schedule-governance --register-asset …` {}h earlier)",
                GOVERNANCE_DELAY_SECS / 3600
            );
            (
                GateInstruction::RegisterAsset { debridge_id, bridge_decimals }.to_bytes(),
                vec![
                    AccountMeta::new_readonly(config_pda, false),
                    AccountMeta::new(payer.pubkey(), true),
                    AccountMeta::new(asset_pda, false),
                    AccountMeta::new_readonly(mint, false),
                    AccountMeta::new_readonly(vault, false),
                    AccountMeta::new_readonly(Pubkey::from_str(SPL_TOKEN)?, false),
                    AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                    AccountMeta::new(vault_binding_pda(&program_id, &vault), false),
                    AccountMeta::new(gov_pda(&program_id, &action_id), false),
                ],
            )
        }
        // H-5: IRREVERSIBLE. Also the step that makes the gate able to claim.
        "seal" => {
            println!("sealing {program_id}: asset bindings become timelocked, claim becomes possible");
            println!("this cannot be undone — a gate that could un-seal would hold the delay in name only");
            (
                GateInstruction::Seal.to_bytes(),
                vec![
                    AccountMeta::new(config_pda, false),
                    AccountMeta::new_readonly(payer.pubkey(), true),
                ],
            )
        }
        // A DECREASE consumes `["gov", lower_threshold_action_id(t)]`; an increase
        // ignores the extra account. Always attached, so the same command works
        // in both directions, and the action id is printed for the schedule step.
        "set-threshold" => {
            let threshold: u32 = args.req("--threshold")?.parse()?;
            let action_id = lower_threshold_action_id(threshold);
            println!("lowerThreshold action id: 0x{}", hex::encode(action_id));
            println!(
                "(a DECREASE needs `schedule-governance --lower-threshold {threshold}` {}h earlier; an increase is instant)",
                GOVERNANCE_DELAY_SECS / 3600
            );
            (
                GateInstruction::SetThreshold { threshold }.to_bytes(),
                vec![
                    AccountMeta::new(config_pda, false),
                    AccountMeta::new_readonly(payer.pubkey(), true),
                    AccountMeta::new(gov_pda(&program_id, &action_id), false),
                ],
            )
        }
        // H-2 (round 4): queue a validator addition / threshold decrease.
        "schedule-governance" => {
            let action_id = governance_action_id(&args)?;
            println!("scheduling action 0x{}", hex::encode(action_id));
            println!(
                "matures {}h after this lands; execute within the following {}-day grace window",
                GOVERNANCE_DELAY_SECS / 3600,
                GOVERNANCE_GRACE_SECS / 86_400
            );
            (
                GateInstruction::ScheduleGovernance { action_id }.to_bytes(),
                vec![
                    AccountMeta::new_readonly(config_pda, false),
                    AccountMeta::new(payer.pubkey(), true),
                    AccountMeta::new(gov_pda(&program_id, &action_id), false),
                    AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                ],
            )
        }
        // Owner OR guardian.
        "cancel-governance" => {
            let action_id = governance_action_id(&args)?;
            println!("cancelling scheduled action 0x{}", hex::encode(action_id));
            (
                GateInstruction::CancelScheduledGovernance { action_id }.to_bytes(),
                vec![
                    AccountMeta::new_readonly(config_pda, false),
                    AccountMeta::new_readonly(payer.pubkey(), true),
                    AccountMeta::new(gov_pda(&program_id, &action_id), false),
                ],
            )
        }
        // Solana -> EVM. Locks the caller's SPL tokens into the registered vault
        // and emits the `Sent` event the relayer signs.
        //
        // The `["sent", submissionId]` record PDA has to be derived client-side,
        // which means recomputing the id exactly as the program does — same
        // fields, same order. `bridge_solana::hash` is the shared implementation
        // that Phase 3 locks against the Solidity fixtures, so this cannot drift
        // from either VM.
        "send" => {
            let debridge_id = hex32(&args.req("--debridge-id")?)?;
            let amount: u64 = args.req("--amount")?.parse()?;
            let chain_id_to: u64 = args.req("--chain-id-to")?.parse()?;
            let receiver = {
                let h = args.req("--receiver")?;
                let h = h.strip_prefix("0x").unwrap_or(&h).to_string();
                hex::decode(&h).map_err(|_| anyhow::anyhow!("--receiver is not hex"))?
            };
            anyhow::ensure!(
                receiver.len() == 20 || receiver.len() == 32,
                "receiver must be 20 bytes (EVM) or 32 (Solana), got {}",
                receiver.len()
            );
            let user_token = Pubkey::from_str(&args.req("--from-token-account")?)?;

            // chain_id and the per-corridor nonce come from the config; the
            // program uses exactly these to build the id.
            let cfg_acct = rpc.get_account(&config_pda)?;
            // Through the ONE mirrored layout (`gate::ConfigView` + `ConfigTail`),
            // never hand-sliced offsets — that is how `show` once reported zeros
            // after `bridge_domain` was inserted.
            let mut cursor: &[u8] = &cfg_acct.data;
            let view = decode_config_view(&mut cursor)?;
            let tail = ConfigTail::deserialize(&mut cursor)
                .map_err(|e| anyhow::anyhow!("config tail does not decode: {e}"))?;
            let bridge_domain = view.bridge_domain;
            let chain_id = view.chain_id;
            let nonce = tail
                .nonce_to
                .iter()
                .find(|(c, _)| *c == chain_id_to)
                .map(|(_, n)| *n)
                .ok_or_else(|| {
                    anyhow::anyhow!("corridor {chain_id_to} is not registered — run register-corridor")
                })?;

            // No auto-params here, so `native_sender` is NOT part of the hash —
            // it only enters via `keccak(nativeSender)` in the auto tail, exactly
            // as `BridgeHash.sol` defines it. Using the with-auto form here would
            // produce an id the gate never derives.
            let (asset_pda, _) =
                Pubkey::find_program_address(&[b"asset", &debridge_id], &program_id);
            let asset_acct = rpc.get_account(&asset_pda)?;
            let asset: bridge_solana::account::AssetAccount =
                bridge_solana::account::decode(&asset_acct.data)
                    .ok_or_else(|| anyhow::anyhow!("asset account is malformed"))?;
            let vault = Pubkey::new_from_array(asset.vault);
            // `--amount` is in the mint's decimals; the program hashes it in the
            // asset's bridge decimals, so the id must be built from that.
            let unit = asset
                .bridge_unit()
                .ok_or_else(|| anyhow::anyhow!("asset has invalid bridge decimals"))?;
            anyhow::ensure!(
                amount % unit == 0,
                "--amount {amount} is not a multiple of the bridge unit {unit} \
                 ({} mint decimals, {} bridge decimals)",
                asset.local_decimals,
                asset.bridge_decimals
            );
            let wire_amount = amount / unit;

            let id = bridge_solana::hash::submission_id(
                &bridge_domain,
                &debridge_id,
                asset.bridge_decimals,
                &bridge_solana::hash::amount_word(wire_amount as u128),
                chain_id,
                chain_id_to,
                nonce,
                &receiver,
            );
            let (sent_pda, _) = Pubkey::find_program_address(&[b"sent", &id], &program_id);

            println!("submissionId : 0x{}", hex::encode(id));
            println!("amount       : {amount} (mint units) = {wire_amount} on the wire");
            println!("nonce        : {nonce}  corridor {chain_id} -> {chain_id_to}");
            println!("vault        : {vault}");

            (
                GateInstruction::Send(bridge_solana::instruction::SendArgs {
                    debridge_id,
                    amount,
                    chain_id_to,
                    receiver,
                    auto: None,
                })
                .to_bytes(),
                vec![
                    AccountMeta::new(config_pda, false),
                    AccountMeta::new_readonly(asset_pda, false),
                    AccountMeta::new(payer.pubkey(), true),
                    AccountMeta::new(user_token, false),
                    AccountMeta::new(vault, false),
                    AccountMeta::new_readonly(Pubkey::from_str(SPL_TOKEN)?, false),
                    AccountMeta::new(sent_pda, false),
                    AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                ],
            )
        }
        // M-2, DESTINATION side: burn the transfer so it can never be claimed.
        // Moves no funds; it only unlocks the source-side refund.
        "cancel" => {
            let wire_amount =
                solana_relayer::cli::wire_amount_flag("cancel", args.get("--amount"), args.get("--wire-amount"))?;
            let a = bridge_solana::instruction::CancelArgs {
                debridge_id: hex32(&args.req("--debridge-id")?)?,
                amount: wire_amount,
                bridge_decimals: args.req("--bridge-decimals")?.parse()?,
                chain_id_from: args.req("--chain-id-from")?.parse()?,
                nonce: args.req("--nonce")?.parse()?,
                receiver: hex::decode(
                    args.req("--receiver")?.strip_prefix("0x").unwrap_or(&args.req("--receiver")?),
                )?,
                auto: None,
                native_sender: hex::decode(
                    args.req("--native-sender")?
                        .strip_prefix("0x")
                        .unwrap_or(&args.req("--native-sender")?),
                )?,
                signatures: parse_sigs(&args)?,
            };
            let id = hex32(&args.req("--submission-id")?)?;
            let (executed, _) = Pubkey::find_program_address(&[b"executed", &id], &program_id);
            println!("burning {} (executed PDA {})", hex::encode(id), executed);
            println!("wire amount  : {wire_amount} (bridge decimals, as hashed into the id)");
            (
                GateInstruction::Cancel(a).to_bytes(),
                vec![
                    AccountMeta::new_readonly(config_pda, false),
                    AccountMeta::new(executed, false),
                    AccountMeta::new(payer.pubkey(), true),
                    AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                ],
            )
        }
        // M-2, SOURCE side: return the locked funds once a refund quorum exists.
        // The gate cannot see the destination chain: what it checks is the
        // validators' refund signatures, which they only give after observing
        // the destination burn.
        "refund" => {
            let debridge_id = hex32(&args.req("--debridge-id")?)?;
            let wire_amount =
                solana_relayer::cli::wire_amount_flag("refund", args.get("--amount"), args.get("--wire-amount"))?;
            let a = bridge_solana::instruction::RefundArgs {
                debridge_id,
                amount: wire_amount,
                bridge_decimals: args.req("--bridge-decimals")?.parse()?,
                chain_id_to: args.req("--chain-id-to")?.parse()?,
                nonce: args.req("--nonce")?.parse()?,
                receiver: hex::decode(
                    args.req("--receiver")?.strip_prefix("0x").unwrap_or(&args.req("--receiver")?),
                )?,
                auto: None,
                native_sender: hex::decode(
                    args.req("--native-sender")?
                        .strip_prefix("0x")
                        .unwrap_or(&args.req("--native-sender")?),
                )?,
                signatures: parse_sigs(&args)?,
            };
            let id = hex32(&args.req("--submission-id")?)?;
            let (asset_pda, _) =
                Pubkey::find_program_address(&[b"asset", &debridge_id], &program_id);
            let (sent_pda, _) = Pubkey::find_program_address(&[b"sent", &id], &program_id);
            let (refunded_pda, _) =
                Pubkey::find_program_address(&[b"refunded", &id], &program_id);
            let asset_acct = rpc.get_account(&asset_pda)?;
            let vault = Pubkey::new_from_array(solana_relayer::gate::asset_vault(
                asset_acct.owner == program_id,
                &asset_acct.data,
                &debridge_id,
            )?);
            let unit = solana_relayer::gate::asset_bridge_unit(&asset_acct.data)
                .ok_or_else(|| anyhow::anyhow!("asset has invalid bridge decimals"))?;

            // The payout destination is the token account `send` debited, recorded
            // by the program in `["sent", id]` — so it can be read rather than
            // typed. An explicit `--to-token-account` still has to MATCH it, or the
            // program refuses; pass it only as a cross-check.
            let sent_acct = rpc
                .get_account(&sent_pda)
                .map_err(|_| anyhow::anyhow!("no [\"sent\", id] record: this gate never sent {}", hex::encode(id)))?;
            anyhow::ensure!(sent_acct.owner == program_id, "sent record is not program-owned");
            let record = bridge_solana::relayer::decode_sent_record(&sent_acct.data)
                .ok_or_else(|| anyhow::anyhow!("sent record does not decode (layout drift?)"))?;
            anyhow::ensure!(record.amount != 0, "sent record is zeroed: already refunded");
            let recorded_to = Pubkey::new_from_array(record.source_token);
            let to_token = match args.get("--to-token-account") {
                Some(t) => {
                    let t = Pubkey::from_str(&t)?;
                    anyhow::ensure!(t == recorded_to, "--to-token-account {t} != recorded {recorded_to}");
                    t
                }
                None => recorded_to,
            };
            solana_relayer::cli::check_refund_amount(wire_amount, unit, record.amount)?;
            println!(
                "refunding {} : {} MINT units (= wire amount {wire_amount} x bridge unit {unit}) from vault {vault} -> {to_token}",
                hex::encode(id),
                record.amount
            );
            println!("locked_at    : {} (cluster unix time)", record.locked_at);
            (
                GateInstruction::Refund(a).to_bytes(),
                refund_accounts(
                    config_pda,
                    asset_pda,
                    sent_pda,
                    refunded_pda,
                    payer.pubkey(),
                    vault,
                    to_token,
                    vault_authority,
                ),
            )
        }
        // An ADDITION consumes `["gov", add_validator_action_id(v)]`; a removal
        // is instant and ignores the extra account.
        "set-validator" => {
            let validator = hex20(&args.req("--validator")?)?;
            let active = args.get("--active").unwrap_or_else(|| "true".into()) == "true";
            let action_id = add_validator_action_id(&validator);
            println!("addValidator action id: 0x{}", hex::encode(action_id));
            if active {
                println!(
                    "(an ADDITION needs `schedule-governance --add-validator 0x{}` {}h earlier; removal is instant)",
                    hex::encode(validator),
                    GOVERNANCE_DELAY_SECS / 3600
                );
            }
            (
                GateInstruction::SetValidator { validator, active }.to_bytes(),
                vec![
                    AccountMeta::new(config_pda, false),
                    AccountMeta::new_readonly(payer.pubkey(), true),
                    AccountMeta::new(gov_pda(&program_id, &action_id), false),
                ],
            )
        }
        other => anyhow::bail!("unknown command {other:?}"),
    };

    let ix = Instruction { program_id, accounts, data: ix_data };
    let blockhash = rpc.get_latest_blockhash()?;
    let tx =
        Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer], blockhash);
    let sig = rpc.send_and_confirm_transaction(&tx)?;
    println!("{cmd} OK — tx {sig}");
    Ok(())
}

#[cfg(test)]
mod scrub_tests {
    /// The `Error:` line this binary prints is outside any subscriber, so it
    /// gets the scrub explicitly. Pins that a transport failure carrying a
    /// keyed RPC URL cannot reach stderr in the clear.
    #[test]
    fn the_error_line_cannot_carry_an_rpc_key() {
        let e = anyhow::anyhow!(
            "reading the gate: error sending request for url (https://solana-devnet.rpc.example/v2/alch_Ex4mpl3K3y-N0t-Re4l7): dns error"
        );
        let printed = format!("{}", log_scrub::scrub(&format!("{e:?}")));
        assert!(!printed.contains("alch_Ex4mpl3K3y-N0t-Re4l7"), "{printed}");
        assert!(printed.contains("https://solana-devnet.rpc.example/v2/<redacted>"), "{printed}");
        assert!(printed.contains("dns error"), "{printed}");
    }
}
