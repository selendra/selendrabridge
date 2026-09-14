//! `price-keeper` — keeps EVM `SwapPool` prices fresh.
//!
//! A pool refuses any price older than `maxPriceAge` (a day by default), so with
//! no oracle running every WRAP-side swap and quote reverts `StalePrice` a day
//! after the last `setPrice` — which is exactly how the live testnet's swaps
//! went dark. This service is that oracle for a deployment whose prices are
//! STATIC: each token has a configured price, and the loop
//!
//! * re-asserts it before it would go stale (`refresh_margin_secs` early), and
//! * walks the on-chain price toward it in capped steps when the two differ
//!   (a config change), never breaking the pool's cooldown or step cap.
//!
//! It does not discover prices. Re-asserting a static figure defeats the point
//! of the staleness guard for a token with a real market — run a real feed for
//! those. The decision itself is `swap_math::refresh::plan`, shared with the
//! Solana refresher so both VMs follow one rule.

mod config;

use std::time::Duration;

use alloy::eips::BlockNumberOrTag;
use alloy::network::EthereumWallet;
use alloy::primitives::{Address, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use anyhow::Context;
use bridge_core::abi::SwapPool;
use bridge_core::config::redact_url;
use swap_math::refresh::{due_in, parse_price, plan, Plan, PriceState};
use tracing::{debug, error, info, warn};

use config::{Config, PoolCfg};

/// A setPrice that has not confirmed by now is abandoned for this tick; the next
/// tick re-reads the chain, so a late landing is simply observed as done.
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(180);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "price_keeper=info".into()),
        )
        .init();

    let cfg_path = std::env::args().nth(1).unwrap_or_else(|| "price-keeper.toml".into());
    let cfg = Config::load(&cfg_path)?;
    let signer = cfg.oracle.load("oracle").context("loading oracle signer")?;
    info!(
        oracle = %signer.address(),
        pools = cfg.pools.len(),
        poll_secs = cfg.poll_interval_secs,
        margin_secs = cfg.refresh_margin_secs,
        "price-keeper started (static prices — testnet/demo pools only)"
    );

    let mut tasks = tokio::task::JoinSet::new();
    for pool in cfg.pools.clone() {
        let signer = signer.clone();
        let (poll, margin) = (cfg.poll_interval_secs, cfg.refresh_margin_secs);
        tasks.spawn(async move { run_pool(pool, signer, poll, margin).await });
    }
    let total = tasks.len();
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(Ok(())) => warn!("a pool loop exited (other chains keep running)"),
            Ok(Err(e)) => error!(error = %e, "a pool loop failed (other chains keep running)"),
            Err(e) => error!(error = %e, "a pool task panicked (other chains keep running)"),
        }
    }
    anyhow::bail!("all {total} pool loops have exited");
}

/// One chain's loop. Only a permanent misconfiguration (wrong chain id, bad
/// address) returns; RPC trouble is logged and retried on the next tick.
async fn run_pool(cfg: PoolCfg, signer: PrivateKeySigner, poll_secs: u64, margin: i64) -> anyhow::Result<()> {
    let chain_id = cfg.chain_id;
    let pool_addr: Address = cfg.pool.parse().with_context(|| format!("chain {chain_id}: bad pool address"))?;
    let tokens = cfg
        .tokens
        .iter()
        .map(|t| {
            let addr: Address = t.address.parse().with_context(|| format!("chain {chain_id}: bad address for {}", t.symbol))?;
            // Already validated by Config::from_toml.
            let target = parse_price(&t.price).context("price validated at load")?;
            Ok((t.symbol.clone(), addr, target))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    // SimpleNonceManager for the reason the keeper uses it: a reverting estimate
    // must not advance a cached nonce and wedge every later send.
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer.clone()))
        .with_simple_nonce_management()
        .connect_http(cfg.rpc.parse().with_context(|| format!("chain {chain_id}: bad rpc url"))?);
    let poll = Duration::from_secs(poll_secs);

    loop {
        match provider.get_chain_id().await {
            Ok(id) if id == chain_id => break,
            Ok(id) => anyhow::bail!("RPC {} reports chainId {id}, config says {chain_id}", redact_url(&cfg.rpc)),
            Err(e) => {
                warn!(chain_id, error = %e, "get_chain_id failed; retrying");
                tokio::time::sleep(poll.min(Duration::from_secs(30))).await;
            }
        }
    }
    let pool = SwapPool::new(pool_addr, &provider);
    info!(chain_id, pool = %pool_addr, tokens = tokens.len(), "watching pool");

    loop {
        let sleep = match tick(chain_id, &provider, &pool, signer.address(), &tokens, margin).await {
            Ok(wait) => next_sleep(poll, wait),
            Err(e) => {
                warn!(chain_id, error = %e, "tick failed; retrying next poll");
                poll
            }
        };
        tokio::time::sleep(sleep).await;
    }
}

async fn tick<P: Provider>(
    chain_id: u64,
    provider: &P,
    pool: &SwapPool::SwapPoolInstance<&P>,
    me: Address,
    tokens: &[(String, Address, u128)],
    margin: i64,
) -> anyhow::Result<Option<i64>> {
    let oracle = pool.oracle().call().await?;
    if oracle != me {
        // Not fatal: ownership may hand the role over later. Loud, because until
        // then this pool will go stale exactly as if nothing were running.
        error!(chain_id, pool_oracle = %oracle, us = %me, "we are not this pool's oracle; nothing can be refreshed");
        return Ok(None);
    }
    let stable = pool.stable().call().await?;
    let max_age = to_i64(pool.maxPriceAge().call().await?)?;
    let min_interval = to_i64(pool.minPriceUpdateInterval().call().await?)?;
    let deviation = pool.maxPriceDeviationBps().call().await?;
    let head = provider
        .get_block_by_number(BlockNumberOrTag::Latest)
        .await?
        .context("no latest block")?;
    let now = head.header.timestamp as i64;
    let mut soonest: Option<i64> = None;
    // For the per-tick summary: how many tokens are fresh, and when the first of
    // them comes due. A healthy keeper otherwise logs nothing at info level.
    let (mut fresh, mut next_due): (usize, Option<i64>) = (0, None);

    for (symbol, token, target) in tokens {
        if *token == stable {
            debug!(chain_id, %symbol, "stable is pinned at 1.0 and never stale; skipping");
            continue;
        }
        let info = pool.tokens(*token).call().await?;
        if !info.listed {
            warn!(chain_id, %symbol, %token, "token is not listed on this pool; skipping");
            continue;
        }
        let price: u128 = info.price.try_into().context("on-chain price exceeds u128")?;
        let state = PriceState {
            now,
            price,
            price_set_at: to_i64(pool.priceSetAt(*token).call().await?)?,
            last_price_update: to_i64(pool.lastPriceUpdate(*token).call().await?)?,
            // Solidity: 0 disables the guard.
            max_age: (max_age > 0).then_some(max_age),
            min_update_interval: min_interval,
            max_deviation_bps: deviation,
        };
        match plan(&state, *target, margin) {
            Plan::Idle => {
                debug!(chain_id, %symbol, age = now - state.price_set_at, "fresh");
                fresh += 1;
                if let Some(d) = due_in(&state, margin) {
                    next_due = Some(next_due.map_or(d, |n| n.min(d)));
                }
            }
            Plan::Wait { until } => {
                info!(chain_id, %symbol, wait_secs = until - now, "reprice due but in cooldown");
                soonest = Some(soonest.map_or(until - now, |s| s.min(until - now)));
            }
            Plan::Set { price: next, step } => {
                let pending = pool.setPrice(*token, U256::from(next)).send().await?;
                let hash = *pending.tx_hash();
                let receipt = pending.with_timeout(Some(RECEIPT_TIMEOUT)).get_receipt().await?;
                if !receipt.status() {
                    anyhow::bail!("setPrice {symbol} reverted in {hash}");
                }
                info!(
                    chain_id, %symbol, from = price, to = next, step,
                    age_was = now - state.price_set_at, tx = %hash,
                    "price refreshed"
                );
            }
        }
    }
    if fresh > 0 {
        info!(chain_id, fresh, next_refresh_in_secs = next_due, "prices fresh");
    }
    Ok(soonest)
}

/// Sleep the poll interval — or less, when a cooldown ends sooner: a refresh
/// that is already due should not wait out a whole poll behind it. The slack
/// covers the gap between the chain's clock and ours.
fn next_sleep(poll: Duration, cooldown_left: Option<i64>) -> Duration {
    match cooldown_left {
        Some(secs) if secs >= 0 => poll.min(Duration::from_secs(secs as u64 + 15)),
        _ => poll,
    }
}

fn to_i64(v: U256) -> anyhow::Result<i64> {
    i64::try_from(v).map_err(|_| anyhow::anyhow!("on-chain value {v} does not fit i64"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wakes_for_a_cooldown_that_ends_before_the_next_poll() {
        let poll = Duration::from_secs(600);
        assert_eq!(next_sleep(poll, None), poll);
        assert_eq!(next_sleep(poll, Some(220)), Duration::from_secs(235));
        assert_eq!(next_sleep(poll, Some(3_600)), poll, "never sleeps longer than a poll");
        assert_eq!(next_sleep(poll, Some(-5)), poll);
    }
}
