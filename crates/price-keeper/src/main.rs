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

use std::collections::HashMap;
use std::time::Duration;

use alloy::eips::BlockNumberOrTag;
use alloy::network::EthereumWallet;
use alloy::primitives::{Address, B256, U256};
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
    let mut pending = PendingPrices::default();

    loop {
        let sleep = match tick(chain_id, &provider, &pool, signer.address(), &tokens, margin, &mut pending).await {
            Ok(report) => next_sleep(poll, report.soonest),
            Err(e) => {
                warn!(chain_id, error = %e, "tick failed; retrying next poll");
                poll
            }
        };
        tokio::time::sleep(sleep).await;
    }
}

/// What one tick did, for the loop's sleep and for tests.
#[derive(Debug, Default, PartialEq, Eq)]
struct TickReport {
    /// Seconds until the soonest cooldown ends, if a reprice is waiting on one.
    soonest: Option<i64>,
    fresh: usize,
    refreshed: usize,
    /// Tokens left alone because an earlier `setPrice` for them is still in flight.
    in_flight: usize,
    /// Tokens whose read or `setPrice` failed this tick.
    failed: usize,
}

/// One token's result, folded into [`TickReport`].
enum TokenOutcome {
    Skipped,
    Fresh { due_in: Option<i64> },
    Wait { secs: i64 },
    InFlight,
    Refreshed,
}

async fn tick<P: Provider>(
    chain_id: u64,
    provider: &P,
    pool: &SwapPool::SwapPoolInstance<&P>,
    me: Address,
    tokens: &[(String, Address, u128)],
    margin: i64,
    pending: &mut PendingPrices,
) -> anyhow::Result<TickReport> {
    let oracle = pool.oracle().call().await?;
    if oracle != me {
        // Not fatal: ownership may hand the role over later. Loud, because until
        // then this pool will go stale exactly as if nothing were running.
        error!(chain_id, pool_oracle = %oracle, us = %me, "we are not this pool's oracle; nothing can be refreshed");
        return Ok(TickReport::default());
    }
    let pool_state = PoolState {
        stable: pool.stable().call().await?,
        max_age: to_i64(pool.maxPriceAge().call().await?)?,
        min_interval: to_i64(pool.minPriceUpdateInterval().call().await?)?,
        deviation: pool.maxPriceDeviationBps().call().await?,
        now: provider
            .get_block_by_number(BlockNumberOrTag::Latest)
            .await?
            .context("no latest block")?
            .header
            .timestamp as i64,
    };
    let mut report = TickReport::default();
    // For the per-tick summary: when the first fresh token comes due. A healthy
    // keeper otherwise logs nothing at info level.
    let mut next_due: Option<i64> = None;

    // Each token is its own unit of work. They used to share one `?`, so the
    // first token whose read or `setPrice` failed ended the tick, and every
    // token after it in the list went unrefreshed for as long as that one kept
    // failing — a single delisted or misconfigured token let the rest of the
    // pool go stale (audit 2026-09-16, LOW).
    for (symbol, token, target) in tokens {
        match refresh_token(chain_id, provider, pool, &pool_state, symbol, *token, *target, margin, pending).await {
            Ok(TokenOutcome::Skipped) => {}
            Ok(TokenOutcome::Fresh { due_in }) => {
                report.fresh += 1;
                if let Some(d) = due_in {
                    next_due = Some(next_due.map_or(d, |n| n.min(d)));
                }
            }
            Ok(TokenOutcome::Wait { secs }) => {
                report.soonest = Some(report.soonest.map_or(secs, |s| s.min(secs)));
            }
            Ok(TokenOutcome::InFlight) => report.in_flight += 1,
            Ok(TokenOutcome::Refreshed) => report.refreshed += 1,
            Err(e) => {
                report.failed += 1;
                warn!(chain_id, %symbol, %token, error = %e, "token refresh failed; carrying on with the rest of the pool");
            }
        }
    }
    if report.fresh > 0 {
        info!(chain_id, fresh = report.fresh, next_refresh_in_secs = next_due, "prices fresh");
    }
    Ok(report)
}

/// The pool-wide parameters one tick reads once.
struct PoolState {
    stable: Address,
    max_age: i64,
    min_interval: i64,
    deviation: u16,
    now: i64,
}

#[allow(clippy::too_many_arguments)]
async fn refresh_token<P: Provider>(
    chain_id: u64,
    provider: &P,
    pool: &SwapPool::SwapPoolInstance<&P>,
    ps: &PoolState,
    symbol: &str,
    token: Address,
    target: u128,
    margin: i64,
    pending: &mut PendingPrices,
) -> anyhow::Result<TokenOutcome> {
    if token == ps.stable {
        debug!(chain_id, %symbol, "stable is pinned at 1.0 and never stale; skipping");
        return Ok(TokenOutcome::Skipped);
    }
    let info = pool.tokens(token).call().await?;
    if !info.listed {
        warn!(chain_id, %symbol, %token, "token is not listed on this pool; skipping");
        return Ok(TokenOutcome::Skipped);
    }
    let price: u128 = info.price.try_into().context("on-chain price exceeds u128")?;
    let now = ps.now;
    let state = PriceState {
        now,
        price,
        price_set_at: to_i64(pool.priceSetAt(token).call().await?)?,
        last_price_update: to_i64(pool.lastPriceUpdate(token).call().await?)?,
        // Solidity: 0 disables the guard.
        max_age: (ps.max_age > 0).then_some(ps.max_age),
        min_update_interval: ps.min_interval,
        max_deviation_bps: ps.deviation,
    };
    match plan(&state, target, margin) {
        Plan::Idle => {
            debug!(chain_id, %symbol, age = now - state.price_set_at, "fresh");
            Ok(TokenOutcome::Fresh { due_in: due_in(&state, margin) })
        }
        Plan::Wait { until } => {
            info!(chain_id, %symbol, wait_secs = until - now, "reprice due but in cooldown");
            Ok(TokenOutcome::Wait { secs: until - now })
        }
        Plan::Set { price: next, step } => {
            if !pending.may_submit(provider, chain_id, symbol, token).await {
                return Ok(TokenOutcome::InFlight);
            }
            let sent = pool.setPrice(token, U256::from(next)).send().await?;
            let hash = *sent.tx_hash();
            let receipt = match sent.with_timeout(Some(RECEIPT_TIMEOUT)).get_receipt().await {
                Ok(r) => r,
                // The watcher gave up, not the chain: remember the hash so the
                // next tick asks about it before sending a second `setPrice`.
                Err(alloy::providers::PendingTransactionError::TxWatcher(
                    alloy::providers::WatchTxError::Timeout,
                )) => {
                    pending.track(token, hash);
                    anyhow::bail!("no receipt for setPrice {symbol} ({hash}) within {}s; remembered", RECEIPT_TIMEOUT.as_secs());
                }
                Err(e) => return Err(anyhow::Error::from(e).context("await setPrice receipt")),
            };
            if !receipt.status() {
                anyhow::bail!("setPrice {symbol} reverted in {hash}");
            }
            info!(
                chain_id, %symbol, from = price, to = next, step,
                age_was = now - state.price_set_at, tx = %hash,
                "price refreshed"
            );
            Ok(TokenOutcome::Refreshed)
        }
    }
}

/// What became of a remembered `setPrice`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TxProbe {
    Mined,
    InMempool,
    Gone,
    Unknown,
}

/// `setPrice` hashes whose receipt did not arrive within [`RECEIPT_TIMEOUT`],
/// per token — the keeper's `PendingTxs`, carried over.
///
/// Without it a slow `setPrice` bailed the tick, the next tick re-read a chain
/// that had not seen it land, planned the same step and sent a SECOND one with
/// a fresh pending nonce. Whichever mined second then reverted on the pool's
/// update cooldown, paying gas for nothing, every time the network was slow.
#[derive(Default)]
struct PendingPrices(HashMap<Address, B256>);

impl PendingPrices {
    fn track(&mut self, token: Address, hash: B256) {
        self.0.insert(token, hash);
    }

    /// Apply a probe for `token`'s remembered tx: forget it unless it is still
    /// (or possibly still) in flight. Returns whether a new `setPrice` may go
    /// out. Fail-closed on `Unknown` — an RPC blip must not become a duplicate.
    ///
    /// A MINED tx, reverted or not, is forgotten and the send allowed: the plan
    /// was computed from state read this tick, so if the first one landed the
    /// plan would not have asked for another.
    fn apply(&mut self, token: Address, probe: TxProbe) -> bool {
        match probe {
            TxProbe::InMempool | TxProbe::Unknown => false,
            TxProbe::Mined | TxProbe::Gone => {
                self.0.remove(&token);
                true
            }
        }
    }

    async fn may_submit<P: Provider>(&mut self, provider: &P, chain_id: u64, symbol: &str, token: Address) -> bool {
        let Some(&hash) = self.0.get(&token) else { return true };
        let probe = match provider.get_transaction_receipt(hash).await {
            Ok(Some(_)) => TxProbe::Mined,
            Ok(None) => match provider.get_transaction_by_hash(hash).await {
                Ok(Some(_)) => TxProbe::InMempool,
                Ok(None) => TxProbe::Gone,
                Err(_) => TxProbe::Unknown,
            },
            Err(_) => TxProbe::Unknown,
        };
        let go = self.apply(token, probe);
        if go {
            info!(chain_id, %symbol, tx = %hash, ?probe, "earlier setPrice settled; planning afresh");
        } else {
            debug!(chain_id, %symbol, tx = %hash, ?probe, "earlier setPrice still in flight; not sending another");
        }
        go
    }
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
    use alloy::primitives::Bytes;
    use alloy::providers::ProviderBuilder;
    use alloy::sol_types::SolValue;
    use alloy::transports::mock::Asserter;

    const NOW: i64 = 1_000_000;
    const PRICE: u128 = 2_000_000_000_000_000_000;

    fn word<T: SolValue>(v: T) -> Bytes {
        Bytes::from(v.abi_encode())
    }

    /// Queue the pool-wide reads one tick makes, in order.
    fn pool_reads(a: &Asserter, me: Address) {
        a.push_success(&word(me)); // oracle
        a.push_success(&word(Address::repeat_byte(0x5)));
        a.push_success(&word(U256::from(86_400))); // maxPriceAge
        a.push_success(&word(U256::from(60))); // minPriceUpdateInterval
        a.push_success(&word(1_000u16)); // maxPriceDeviationBps
        let mut block = alloy::rpc::types::Block::<alloy::rpc::types::Transaction>::default();
        block.header.inner.timestamp = NOW as u64;
        a.push_success(&block);
    }

    /// Queue one listed token's reads, with its price last set `age` seconds ago.
    fn token_reads(a: &Asserter, age: i64) {
        a.push_success(&Bytes::from((true, U256::from(18), U256::from(PRICE), U256::from(1u64 << 40)).abi_encode()));
        a.push_success(&word(U256::from(NOW - age))); // priceSetAt
        a.push_success(&word(U256::from(NOW - age))); // lastPriceUpdate
    }

    /// Audit 2026-09-16 (LOW): one token's failure used to end the whole tick,
    /// so every token listed after it went unrefreshed for as long as it failed.
    #[tokio::test]
    async fn one_failing_token_does_not_starve_the_rest_of_the_pool() {
        let me = Address::repeat_byte(0xAA);
        let a = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(a.clone());
        let pool = SwapPool::new(Address::repeat_byte(0x9), &provider);
        pool_reads(&a, me);
        a.push_failure_msg("header not found"); // tokens(BAD)
        token_reads(&a, 10); // GOOD: fresh

        let tokens = [
            ("BAD".to_string(), Address::repeat_byte(0x1), PRICE),
            ("GOOD".to_string(), Address::repeat_byte(0x2), PRICE),
        ];
        let report = tick(1, &provider, &pool, me, &tokens, 3_600, &mut PendingPrices::default())
            .await
            .expect("a token's failure is not the pool's");
        assert_eq!(report.failed, 1);
        assert_eq!(report.fresh, 1, "the token after the failing one was still read");
    }

    /// The keeper's duplicate-tx rule, carried over: a `setPrice` whose receipt
    /// timed out is asked about before another is sent — and an unanswerable
    /// question means wait, not resend.
    #[tokio::test]
    async fn an_in_flight_set_price_is_not_sent_twice() {
        let me = Address::repeat_byte(0xAA);
        let token = Address::repeat_byte(0x2);
        let a = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(a.clone());
        let pool = SwapPool::new(Address::repeat_byte(0x9), &provider);
        pool_reads(&a, me);
        token_reads(&a, 90_000); // stale: the plan says Set
        a.push_failure_msg("rate limited"); // eth_getTransactionReceipt

        let mut pending = PendingPrices::default();
        pending.track(token, B256::repeat_byte(0x77));
        let tokens = [("TST".to_string(), token, PRICE)];
        let report = tick(1, &provider, &pool, me, &tokens, 3_600, &mut pending).await.unwrap();
        assert_eq!(report.in_flight, 1, "no second setPrice while the first may still land");
        assert_eq!((report.refreshed, report.failed), (0, 0), "nothing was sent: {report:?}");
        assert!(pending.0.contains_key(&token), "still remembered");
    }

    #[test]
    fn a_settled_or_vanished_set_price_is_forgotten() {
        let token = Address::repeat_byte(0x2);
        for (probe, go) in
            [(TxProbe::InMempool, false), (TxProbe::Unknown, false), (TxProbe::Mined, true), (TxProbe::Gone, true)]
        {
            let mut p = PendingPrices::default();
            p.track(token, B256::repeat_byte(1));
            assert_eq!(p.apply(token, probe), go, "{probe:?}");
            assert_eq!(p.0.contains_key(&token), !go, "{probe:?}");
        }
        assert!(PendingPrices::default().apply(token, TxProbe::Gone), "nothing remembered: go");
    }

    #[test]
    fn wakes_for_a_cooldown_that_ends_before_the_next_poll() {
        let poll = Duration::from_secs(600);
        assert_eq!(next_sleep(poll, None), poll);
        assert_eq!(next_sleep(poll, Some(220)), Duration::from_secs(235));
        assert_eq!(next_sleep(poll, Some(3_600)), poll, "never sleeps longer than a poll");
        assert_eq!(next_sleep(poll, Some(-5)), poll);
    }
}
