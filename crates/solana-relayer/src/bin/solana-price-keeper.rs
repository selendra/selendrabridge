//! `solana-price-keeper` — keeps the Solana swap pool's prices fresh.
//!
//! The Solana twin of `crates/price-keeper` (which serves the EVM `SwapPool`s).
//! Two binaries because solana-client and alloy cannot share one; ONE rule,
//! because both plan with `swap_math::refresh::plan`.
//!
//! The pool refuses a price older than `max_price_age` (`PoolState::
//! effective_max_price_age`, a day when unset), so without an oracle every
//! non-hub swap stops a day after the last `SetPrice`. For each configured mint
//! this loop re-asserts its static price before that happens, or walks the
//! on-chain price toward the configured one in capped steps. It discovers no
//! prices: a token with a real market needs a real feed.
//!
//!   solana-price-keeper /configs/solana-price-keeper.toml
//!
//! ```toml
//! rpc = "https://..."
//! program = "E28r29Hyky3UqVBcdSvFk6qNedbRN8X2z4R8hYGDUk88"
//! oracle_keypair = "/keys/payer.json"   # must be the pool's oracle
//! poll_interval_secs = 600
//! refresh_margin_secs = 21600
//! [[tokens]]
//! symbol = "WRAP"
//! mint = "Bqt4..."
//! price = "3180"                        # whole hub units
//! ```

use std::str::FromStr;
use std::time::Duration;

use serde::Deserialize;
use solana_client::rpc_client::RpcClient;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{read_keypair_file, Keypair, Signer};
use solana_sdk::transaction::Transaction;
use solana_swap::math::refresh::{due_in, parse_price, plan, Plan, PriceState};
use solana_swap::{math, Pool, SwapInstruction, TokenRec, POOL_SEED, TOKEN_SEED};
use tracing::{debug, error, info, warn};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    rpc: String,
    program: String,
    oracle_keypair: String,
    #[serde(default = "default_poll")]
    poll_interval_secs: u64,
    #[serde(default = "default_margin")]
    refresh_margin_secs: i64,
    tokens: Vec<TokenCfg>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenCfg {
    symbol: String,
    mint: String,
    price: String,
}

fn default_poll() -> u64 {
    600
}
fn default_margin() -> i64 {
    6 * 3600
}

/// A token ready to watch: its mint, token-record PDA and target price.
struct Watched {
    symbol: String,
    mint: Pubkey,
    record: Pubkey,
    target: u128,
}

impl Config {
    fn from_toml(raw: &str) -> anyhow::Result<Self> {
        let cfg: Config = toml::from_str(raw)?;
        if cfg.tokens.is_empty() {
            anyhow::bail!("config needs at least one [[tokens]] block");
        }
        if cfg.poll_interval_secs == 0 || cfg.refresh_margin_secs <= 0 {
            anyhow::bail!("poll_interval_secs and refresh_margin_secs must be > 0");
        }
        Pubkey::from_str(&cfg.program).map_err(|e| anyhow::anyhow!("program: {e}"))?;
        let mut seen = std::collections::BTreeSet::new();
        for t in &cfg.tokens {
            Pubkey::from_str(&t.mint).map_err(|e| anyhow::anyhow!("token {} mint: {e}", t.symbol))?;
            if !seen.insert(t.mint.clone()) {
                anyhow::bail!("duplicate mint {} in config", t.mint);
            }
            if parse_price(&t.price).is_none() {
                anyhow::bail!(
                    "token {}: price {:?} is not a positive decimal in whole hub units",
                    t.symbol,
                    t.price
                );
            }
        }
        Ok(cfg)
    }
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "solana_price_keeper=info".into()),
        )
        .init();

    let path = std::env::args().nth(1).unwrap_or_else(|| "solana-price-keeper.toml".into());
    let raw = std::fs::read_to_string(&path).map_err(|e| anyhow::anyhow!("reading {path}: {e}"))?;
    let cfg = Config::from_toml(&raw)?;
    let oracle = read_keypair_file(&cfg.oracle_keypair)
        .map_err(|e| anyhow::anyhow!("reading oracle keypair {}: {e}", cfg.oracle_keypair))?;
    let program = Pubkey::from_str(&cfg.program)?;
    let pool_pda = Pubkey::find_program_address(&[POOL_SEED], &program).0;
    let tokens: Vec<Watched> = cfg
        .tokens
        .iter()
        .map(|t| {
            let mint = Pubkey::from_str(&t.mint).expect("validated at load");
            Watched {
                symbol: t.symbol.clone(),
                mint,
                record: Pubkey::find_program_address(&[TOKEN_SEED, mint.as_ref()], &program).0,
                target: parse_price(&t.price).expect("validated at load"),
            }
        })
        .collect();
    let rpc = RpcClient::new_with_commitment(cfg.rpc.clone(), CommitmentConfig::confirmed());

    info!(
        oracle = %oracle.pubkey(),
        %program,
        tokens = tokens.len(),
        poll_secs = cfg.poll_interval_secs,
        margin_secs = cfg.refresh_margin_secs,
        "solana-price-keeper started (static prices — testnet/demo pools only)"
    );
    let poll = Duration::from_secs(cfg.poll_interval_secs);
    loop {
        let sleep = match tick(&rpc, &oracle, program, pool_pda, &tokens, cfg.refresh_margin_secs) {
            // Wake when a cooldown ends rather than a whole poll after it, with
            // slack for the gap between the cluster clock and ours.
            Ok(Some(secs)) if secs >= 0 => poll.min(Duration::from_secs(secs as u64 + 15)),
            Ok(_) => poll,
            Err(e) => {
                warn!(error = %e, "tick failed; retrying next poll");
                poll
            }
        };
        std::thread::sleep(sleep);
    }
}

fn tick(
    rpc: &RpcClient,
    oracle: &Keypair,
    program: Pubkey,
    pool_pda: Pubkey,
    tokens: &[Watched],
    margin: i64,
) -> anyhow::Result<Option<i64>> {
    let pool_acct = rpc.get_account(&pool_pda)?;
    // Refuse an account some other program owns: the PDA was derived from the
    // configured program id, so a mismatch means the config names the wrong one.
    if pool_acct.owner != program {
        anyhow::bail!("pool {pool_pda} is owned by {}, not {program}", pool_acct.owner);
    }
    let pool: Pool = math::decode(&pool_acct.data)
        .ok_or_else(|| anyhow::anyhow!("pool account {pool_pda} does not decode"))?;
    if pool.oracle != oracle.pubkey().to_bytes() {
        error!(
            pool_oracle = %Pubkey::new_from_array(pool.oracle),
            us = %oracle.pubkey(),
            "we are not this pool's oracle; nothing can be refreshed"
        );
        return Ok(None);
    }
    // The program judges freshness on the cluster clock, so plan on it too.
    let clock_acct = rpc.get_account(&solana_sdk::sysvar::clock::id())?;
    let now = solana_sdk::account::from_account::<solana_sdk::clock::Clock, _>(&clock_acct)
        .ok_or_else(|| anyhow::anyhow!("clock sysvar does not decode"))?
        .unix_timestamp;
    let mut soonest: Option<i64> = None;
    let (mut fresh, mut next_due): (usize, Option<i64>) = (0, None);

    for t in tokens {
        if t.mint.to_bytes() == pool.hub_mint {
            debug!(symbol = %t.symbol, "hub is pinned at 1.0 and never stale; skipping");
            continue;
        }
        let rec: TokenRec = match rpc.get_account(&t.record) {
            Ok(a) => math::decode(&a.data).ok_or_else(|| anyhow::anyhow!("{} record does not decode", t.symbol))?,
            Err(_) => {
                warn!(symbol = %t.symbol, mint = %t.mint, "token is not listed on this pool; skipping");
                continue;
            }
        };
        let state = PriceState {
            now,
            price: rec.price,
            price_set_at: rec.price_set_at,
            last_price_update: rec.last_price_update,
            max_age: Some(pool.effective_max_price_age()),
            min_update_interval: pool.min_price_update_interval,
            max_deviation_bps: pool.max_price_deviation_bps,
        };
        match plan(&state, t.target, margin) {
            Plan::Idle => {
                debug!(symbol = %t.symbol, age = now - rec.price_set_at, "fresh");
                fresh += 1;
                if let Some(d) = due_in(&state, margin) {
                    next_due = Some(next_due.map_or(d, |n| n.min(d)));
                }
            }
            Plan::Wait { until } => {
                info!(symbol = %t.symbol, wait_secs = until - now, "reprice due but in cooldown");
                soonest = Some(soonest.map_or(until - now, |s| s.min(until - now)));
            }
            Plan::Set { price, step } => {
                let ix = Instruction {
                    program_id: program,
                    accounts: vec![
                        AccountMeta::new_readonly(pool_pda, false),
                        AccountMeta::new_readonly(oracle.pubkey(), true),
                        AccountMeta::new(t.record, false),
                    ],
                    data: SwapInstruction::SetPrice { price }.to_bytes(),
                };
                let blockhash = rpc.get_latest_blockhash()?;
                let tx = Transaction::new_signed_with_payer(&[ix], Some(&oracle.pubkey()), &[oracle], blockhash);
                let sig = rpc.send_and_confirm_transaction(&tx)?;
                info!(
                    symbol = %t.symbol, from = rec.price, to = price, step,
                    age_was = now - rec.price_set_at, tx = %sig,
                    "price refreshed"
                );
            }
        }
    }
    if fresh > 0 {
        info!(fresh, next_refresh_in_secs = next_due, "prices fresh");
    }
    Ok(soonest)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: &str = r#"
        rpc = "http://127.0.0.1:8899"
        program = "E28r29Hyky3UqVBcdSvFk6qNedbRN8X2z4R8hYGDUk88"
        oracle_keypair = "/keys/payer.json"
        [[tokens]]
        symbol = "WRAP"
        mint = "Bqt4xDpu6oEPgTgVLjZVQ56hFUGo2F4M8zFuK98NHe32"
        price = "3180"
    "#;

    #[test]
    fn loads_with_defaults() {
        let c = Config::from_toml(OK).unwrap();
        assert_eq!((c.poll_interval_secs, c.refresh_margin_secs), (600, 21600));
    }

    #[test]
    fn rejects_bad_prices_mints_and_typos() {
        assert!(Config::from_toml(&OK.replace("\"3180\"", "\"0\"")).is_err());
        assert!(Config::from_toml(&OK.replace("Bqt4xDpu6", "not-a-key")).is_err());
        assert!(Config::from_toml(&OK.replace("poll_interval_secs", "x").replace("rpc =", "rpc_url =")).is_err());
    }

    /// The instruction bytes the loop sends must be the program's own SetPrice.
    #[test]
    fn set_price_instruction_matches_the_program_enum() {
        let bytes = SwapInstruction::SetPrice { price: 3180 * math::PRICE_ONE }.to_bytes();
        assert_eq!(bytes.len(), 1 + 16, "tag + u128");
    }
}
