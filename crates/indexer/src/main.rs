//! indexer — read-only chain-event mirror into Postgres.
//!
//! Unlike the validator (scans + signs) and the keeper (scans + claims), this
//! process never signs or submits a transaction. It exists purely so every
//! swap and bridge transfer is visible in the database — including ones that
//! never got a single validator signature, which today are invisible (a row
//! only appears once `upsert_signature` runs). One independent poll loop per
//! configured chain:
//!
//!   * `Gate.Sent`             -> `observe_submission` (row exists immediately,
//!                                 even with zero signatures)
//!   * `Gate.Claimed`          -> `mark_claimed` (any keeper, not just ours)
//!   * `SwapPool.Swapped`      -> `record_swap` (same-chain swap history)
//!   * `SwapRouter.SwapBridged`         -> `record_swap_bridge_intent`
//!   * `SwapRouter.Finalized`/`FinalizeFallback` -> `record_finalized`
//!
//! A separate periodic sweep flags long-unclaimed transfers `refund_status =
//! 'eligible'` — informational only; no funds move. See the plan doc for the
//! follow-up validator-signed refund mechanism this groundwork feeds.

mod config;

use std::str::FromStr;
use std::time::Duration;

use alloy::primitives::{Address, B256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::{Filter, Log};
use alloy_sol_types::SolEvent;
use anyhow::Context;
use bridge_core::abi::{Gate, SwapPool, SwapRouter};
use bridge_core::store::SubmissionRecord;
use bridge_db::Db;
use config::{ChainCfg, Config};
use tracing::{info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Scrubbed writer: a transport error carries the URL it failed on, and on a
    // keyed endpoint that is the provider key (see `log_scrub`).
    log_scrub::init("indexer=info,bridge_db=info");

    let cfg_path = std::env::args().nth(1).unwrap_or_else(|| "indexer.toml".into());
    let cfg = Config::load(&cfg_path)?;
    let db = Db::connect(&cfg.resolved_database_url()?).await?;
    info!(chains = cfg.chains.len(), "indexer started");

    let refund_timeout = chrono::Duration::seconds(cfg.refund_timeout_secs);
    let sweep_interval = Duration::from_secs(cfg.sweep_interval_secs);
    let sweep_db = db.clone();
    tokio::spawn(async move {
        loop {
            match sweep_db.sweep_refund_eligible(refund_timeout).await {
                Ok(n) if n > 0 => info!(rows = n, "flagged refund-eligible"),
                Ok(_) => {}
                Err(e) => warn!(error = %e, "refund-eligibility sweep failed"),
            }
            tokio::time::sleep(sweep_interval).await;
        }
    });

    let mut tasks = tokio::task::JoinSet::new();
    for chain in cfg.chains {
        let db = db.clone();
        tasks.spawn(async move { run_chain(chain, db).await });
    }

    let total = tasks.len();
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(Ok(())) => warn!("a chain loop exited on its own (other chains keep running)"),
            Ok(Err(e)) => warn!(error = %e, "a chain loop failed (other chains keep running)"),
            Err(e) => warn!(error = %e, "a chain task panicked (other chains keep running)"),
        }
    }
    anyhow::bail!("all {total} chain loops have exited");
}

async fn run_chain(chain: ChainCfg, db: Db) -> anyhow::Result<()> {
    let gate: Option<Address> = chain.gate.as_deref().map(Address::from_str).transpose().context("bad gate address")?;
    let router: Option<Address> =
        chain.router.as_deref().map(Address::from_str).transpose().context("bad router address")?;
    let pool: Option<Address> = chain.pool.as_deref().map(Address::from_str).transpose().context("bad pool address")?;
    anyhow::ensure!(
        gate.is_some() || router.is_some() || pool.is_some(),
        "chain {} configures none of gate/router/pool — nothing to index",
        chain.chain_id
    );

    let retry = Duration::from_millis(chain.poll_interval_ms.max(1000));
    let mut cached_latest: Option<u64> = None;
    let catchup_ms = chain.catchup_poll_interval_ms.unwrap_or(chain.poll_interval_ms);
    let provider = ProviderBuilder::new().connect_http(chain.rpc.parse()?);

    loop {
        match provider.get_chain_id().await {
            Ok(id) if id == chain.chain_id => break,
            Ok(id) => anyhow::bail!("RPC chainId {id} != configured {} for {}", chain.chain_id, chain.rpc),
            Err(e) => {
                warn!(chain_id = chain.chain_id, error = %e, "get_chain_id failed; retrying");
                tokio::time::sleep(retry).await;
            }
        }
    }

    // Deployment generation of this chain's gate, read from the contract. The
    // indexer recomputes submissionIds through `observe_submission`, so a wrong
    // domain would make every observed transfer fail its id check. Zero when no
    // gate is configured, which is fine: `handle_gate_log` never runs then.
    let gate_domain: B256 = match gate {
        None => B256::ZERO,
        Some(addr) => loop {
            match Gate::new(addr, &provider).bridgeDomain().call().await {
                Ok(d) => break d,
                Err(e) => {
                    warn!(
                        chain_id = chain.chain_id,
                        gate = %addr,
                        error = %e,
                        "reading Gate.bridgeDomain() failed; retrying"
                    );
                    tokio::time::sleep(retry).await;
                }
            }
        },
    };

    let mut from_block = match db.get_cursor(chain.chain_id).await {
        Ok(Some(b)) => b + 1,
        Ok(None) => chain.start_block,
        Err(e) => {
            warn!(chain_id = chain.chain_id, error = %e, "reading cursor failed; starting from configured start_block");
            chain.start_block
        }
    };

    info!(
        chain_id = chain.chain_id,
        ?gate,
        ?router,
        ?pool,
        from_block,
        "chain loop started"
    );

    loop {
        // Re-read the head only once the scanner reaches what it last saw: a
        // cursor far behind gains nothing from asking for the tip between every
        // window, and that round trip is half of them. Mirrors the validator.
        if cached_latest.is_none_or(|l| from_block + chain.block_confirmation > l) {
            match provider.get_block_number().await {
                Ok(v) => cached_latest = Some(v),
                Err(e) => {
                    warn!(chain_id = chain.chain_id, error = %e, "get_block_number failed; retrying");
                    tokio::time::sleep(retry).await;
                    continue;
                }
            }
        }
        let latest = cached_latest.unwrap_or(0);
        let confirmed = latest.saturating_sub(chain.block_confirmation);

        if confirmed >= from_block {
            let to_block = confirmed.min(from_block + chain.max_block_range - 1);

            // Advance the cursor only if EVERY relevant scan durably handled all
            // its logs. If any scan fails, leave the cursor put and reprocess the
            // same range next tick — advancing past a failed range would drop
            // whatever events it held (history, a Claimed/Cancelled transition).
            let mut all_ok = true;
            if let Some(addr) = gate {
                let handler =
                    |db, cid, log| handle_gate_log(db, cid, log, gate_domain);
                if let Err(e) =
                    scan(&provider, &db, chain.chain_id, addr, from_block, to_block, handler).await
                {
                    warn!(chain_id = chain.chain_id, error = %e, "gate scan failed; will retry same range next tick");
                    all_ok = false;
                }
            }
            if let Some(addr) = router {
                if let Err(e) = scan(&provider, &db, chain.chain_id, addr, from_block, to_block, handle_router_log).await
                {
                    warn!(chain_id = chain.chain_id, error = %e, "router scan failed; will retry same range next tick");
                    all_ok = false;
                }
            }
            if let Some(addr) = pool {
                if let Err(e) = scan(&provider, &db, chain.chain_id, addr, from_block, to_block, handle_pool_log).await {
                    warn!(chain_id = chain.chain_id, error = %e, "pool scan failed; will retry same range next tick");
                    all_ok = false;
                }
            }

            if all_ok {
                if let Err(e) = db.set_cursor(chain.chain_id, to_block).await {
                    warn!(chain_id = chain.chain_id, error = %e, "failed to persist cursor");
                } else {
                    from_block = to_block + 1;
                    // Catch-up: a range capped by `max_block_range` means more
                    // confirmed history is already waiting, and sleeping a whole
                    // poll interval before reading it is what turns a few hours
                    // of downtime into a day of stale history. Read back-to-back
                    // while behind; the configured interval still paces the
                    // steady state. Mirrors the validator's scanner, which has
                    // the same arithmetic problem for the same reason.
                    if to_block < confirmed {
                        tokio::time::sleep(Duration::from_millis(catchup_ms)).await;
                        continue;
                    }
                }
            }
        }

        tokio::time::sleep(Duration::from_millis(chain.poll_interval_ms)).await;
    }
}

/// Fetch `[from_block, to_block]` logs for one address and hand each, in chain
/// order, to `handler`. A single bad log is logged and skipped, not fatal.
async fn scan<P, F, Fut>(
    provider: &P,
    db: &Db,
    chain_id: u64,
    address: Address,
    from_block: u64,
    to_block: u64,
    handler: F,
) -> anyhow::Result<()>
where
    P: Provider,
    F: Fn(Db, u64, Log) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<()>>,
{
    let filter = Filter::new().address(address).from_block(from_block).to_block(to_block);
    let mut logs = provider.get_logs(&filter).await.context("get_logs")?;
    logs.sort_by_key(|l| (l.block_number.unwrap_or(0), l.log_index.unwrap_or(0)));

    // An orphaned log means the reorg was deeper than `block_confirmation`, which
    // this scanner reads behind precisely to avoid. Mirroring it into history
    // would record a transfer the chain has retracted, so drop it and make the
    // misconfiguration visible — see the validator's copy of this guard.
    let before = logs.len();
    logs.retain(|l| !l.removed);
    if logs.len() != before {
        warn!(
            chain_id,
            dropped = before - logs.len(),
            "REORG DEEPER THAN block_confirmation — dropped orphaned logs; raise \
             block_confirmation for this chain"
        );
    }
    for log in logs {
        // Propagate handler failures instead of swallowing them. A transient
        // DB/store error must fail the whole batch so the caller leaves the
        // cursor where it is and reprocesses the range next tick — otherwise the
        // event (a Sent/Claimed/Cancelled row) would be dropped permanently. All
        // handler writes are idempotent upserts (ON CONFLICT / UPDATE), so
        // reprocessing already-handled logs in the range is safe.
        handler(db.clone(), chain_id, log)
            .await
            .with_context(|| format!("handling log in blocks [{from_block},{to_block}]"))?;
    }
    Ok(())
}

/// The log's transaction hash as `0x`-prefixed hex, or `""` if the RPC omitted
/// it. Every handler records one, so the fallback lives here rather than being
/// spelled out at each call site.
fn tx_hash(log: &Log) -> String {
    log.transaction_hash.map(|h| format!("{h:#x}")).unwrap_or_default()
}

async fn handle_gate_log(
    db: Db,
    chain_id: u64,
    log: Log,
    bridge_domain: B256,
) -> anyhow::Result<()> {
    if let Ok(decoded) = Gate::Sent::decode_log(&log.inner) {
        let ev = &decoded.data;
        // An event whose chainId/nonce overflows u64 is skipped rather than
        // aliased to u64::MAX (which would mis-key the history row). Skip, not
        // error: the scan cursor must still advance past a permanently-malformed
        // log, or it would re-read the same range forever.
        let Some(record) = SubmissionRecord::from_sent_event(ev, bridge_domain) else {
            warn!(
                chain_id,
                submission_id = %format!("{:#x}", ev.submissionId),
                "skipping Sent with chainId/nonce exceeding u64 (malformed/hostile source)"
            );
            return Ok(());
        };
        let id = record.submission_id.clone();
        db.observe_submission(record).await?;
        info!(chain_id, submission_id = %id, "observed Sent");
        return Ok(());
    }
    if let Ok(decoded) = Gate::Claimed::decode_log(&log.inner) {
        let ev = &decoded.data;
        let tx = tx_hash(&log);
        let id = format!("{:#x}", ev.submissionId);
        db.mark_claimed(&id, &tx).await?;
        info!(chain_id, submission_id = %id, %tx, "observed Claimed");
        return Ok(());
    }
    // Refund path. These are observed from the chain rather than taken on a
    // relayer's word, so the recorded lifecycle always reflects what actually
    // happened on-chain — which is what the UI and the validators' candidate
    // list both read.
    if let Ok(decoded) = Gate::Cancelled::decode_log(&log.inner) {
        let ev = &decoded.data;
        let tx = tx_hash(&log);
        let id = format!("{:#x}", ev.submissionId);
        db.mark_cancelled(&id, &tx).await?;
        info!(chain_id, submission_id = %id, %tx, "observed Cancelled (destination burned)");
        return Ok(());
    }
    if let Ok(decoded) = Gate::Refunded::decode_log(&log.inner) {
        let ev = &decoded.data;
        let tx = tx_hash(&log);
        let id = format!("{:#x}", ev.submissionId);
        db.mark_refunded(&id, &tx).await?;
        info!(chain_id, submission_id = %id, %tx, "observed Refunded (source repaid)");
    }
    Ok(())
}

async fn handle_pool_log(db: Db, chain_id: u64, log: Log) -> anyhow::Result<()> {
    let Ok(decoded) = SwapPool::Swapped::decode_log(&log.inner) else { return Ok(()) };
    let ev = &decoded.data;
    let tx_hash = tx_hash(&log);
    let log_index = log.log_index.unwrap_or(0) as i64;
    db.record_swap(
        chain_id,
        &tx_hash,
        log_index,
        &format!("{:#x}", ev.sender),
        &format!("{:#x}", ev.to),
        &format!("{:#x}", ev.tokenIn),
        &format!("{:#x}", ev.tokenOut),
        &ev.amountIn.to_string(),
        &ev.amountOut.to_string(),
        log.block_number.unwrap_or(0),
    )
    .await?;
    info!(chain_id, %tx_hash, "observed Swapped");
    Ok(())
}

async fn handle_router_log(db: Db, chain_id: u64, log: Log) -> anyhow::Result<()> {
    if let Ok(decoded) = SwapRouter::SwapBridged::decode_log(&log.inner) {
        let ev = &decoded.data;
        let id = format!("{:#x}", ev.submissionId);
        db.record_swap_bridge_intent(
            &id,
            &format!("{:#x}", ev.tokenIn),
            &ev.amountIn.to_string(),
            &ev.stableOut.to_string(),
            &format!("{:#x}", ev.finalToken),
            &format!("{:#x}", ev.finalReceiver),
        )
        .await?;
        info!(chain_id, submission_id = %id, "observed SwapBridged");
        return Ok(());
    }
    if let Ok(decoded) = SwapRouter::Finalized::decode_log(&log.inner) {
        let ev = &decoded.data;
        let id = format!("{:#x}", ev.submissionId);
        let tx = tx_hash(&log);
        db.record_finalized(&id, &tx, &ev.amountOut.to_string(), false).await?;
        info!(chain_id, submission_id = %id, "observed Finalized");
        return Ok(());
    }
    if let Ok(decoded) = SwapRouter::FinalizeDeferred::decode_log(&log.inner) {
        // Not a lifecycle transition — nothing settled — so no DB write. Logged
        // because a deferred delivery is otherwise indistinguishable from one
        // nobody has finalized yet, and an operator watching a stuck corridor
        // needs to see that the router is waiting on the pool rather than idle.
        let ev = &decoded.data;
        info!(
            chain_id,
            submission_id = %format!("{:#x}", ev.submissionId),
            final_token = %ev.finalToken,
            retry_after = %ev.retryAfter,
            "observed FinalizeDeferred (destination swap blocked; delivery still pending)"
        );
        return Ok(());
    }
    if let Ok(decoded) = SwapRouter::FinalizeFallback::decode_log(&log.inner) {
        let ev = &decoded.data;
        let id = format!("{:#x}", ev.submissionId);
        let tx = tx_hash(&log);
        db.record_finalized(&id, &tx, &ev.stableAmount.to_string(), true).await?;
        info!(chain_id, submission_id = %id, "observed FinalizeFallback");
    }
    Ok(())
}
