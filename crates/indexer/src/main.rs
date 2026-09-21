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
#[cfg(test)]
use alloy::primitives::U256;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::{Filter, Log};
use alloy_sol_types::SolEvent;
use anyhow::Context;
use bridge_core::abi::{Gate, SwapPool, SwapRouter};
use bridge_core::scan::clamp_scan_window;
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
            // How far the cursor may move: the LOWEST upper bound any scanner
            // actually read (audit 2026-09-16, M-7). `None` means some endpoint
            // had nothing confirmed at `from_block`, so nothing may advance.
            // Starts at `to_block` so a chain with no contracts configured — and
            // therefore no logs to miss — still makes progress.
            let mut scanned_to = Some(to_block);
            let window = Window { from_block, to_block, confirmations: chain.block_confirmation };
            let mut narrow = |limit: Option<u64>| {
                scanned_to = match (scanned_to, limit) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    _ => None,
                };
            };
            if let Some(addr) = gate {
                let handler =
                    |db, cid, log| handle_gate_log(db, cid, log, gate_domain);
                match scan(&provider, &db, chain.chain_id, addr, window, handler).await
                {
                    Ok(limit) => narrow(limit),
                    Err(e) => {
                        warn!(chain_id = chain.chain_id, error = %e, "gate scan failed; will retry same range next tick");
                        all_ok = false;
                    }
                }
            }
            if let Some(addr) = router {
                match scan(&provider, &db, chain.chain_id, addr, window, handle_router_log).await
                {
                    Ok(limit) => narrow(limit),
                    Err(e) => {
                        warn!(chain_id = chain.chain_id, error = %e, "router scan failed; will retry same range next tick");
                        all_ok = false;
                    }
                }
            }
            if let Some(addr) = pool {
                match scan(&provider, &db, chain.chain_id, addr, window, handle_pool_log).await {
                    Ok(limit) => narrow(limit),
                    Err(e) => {
                        warn!(chain_id = chain.chain_id, error = %e, "pool scan failed; will retry same range next tick");
                        all_ok = false;
                    }
                }
            }

            // A scanner served by a node that lags `from_block` read nothing —
            // which is indistinguishable from "no events here" in the response
            // itself. Advancing on it walked the cursor past blocks nobody read,
            // and nothing revisits them: the `Sent` in that window never reaches
            // history and `sweep_refund_eligible` can never flag it. Re-read the
            // same range next tick instead; `cached_latest` is dropped so the
            // head is re-fetched rather than trusted from the endpoint that was
            // ahead.
            let advance_to = if all_ok { scanned_to } else { None };
            if all_ok && scanned_to.is_none() {
                warn!(
                    chain_id = chain.chain_id,
                    from_block,
                    to_block,
                    "an RPC endpoint lags this range; not advancing the cursor (retrying next tick)"
                );
                cached_latest = None;
            }

            if let Some(to_block) = advance_to {
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

/// The block range one scan is asked for, and how deep it must stay behind the
/// serving endpoint's head. Grouped so the three scanners in a tick pass the
/// identical window by construction.
#[derive(Clone, Copy, Debug)]
struct Window {
    from_block: u64,
    to_block: u64,
    confirmations: u64,
}

/// Fetch logs for one address over `[from_block, to_block]` — clamped to what
/// the serving endpoint itself has confirmed — and hand each, in chain order, to
/// `handler`. A single bad log is logged and skipped, not fatal.
///
/// Returns the block the scan actually reached, which the caller uses as the
/// cursor bound; `None` means this endpoint has nothing confirmed at
/// `from_block` and read nothing at all.
///
/// ## Why the head is re-read here (audit 2026-09-16, M-7)
///
/// The loop's `cached_latest` and this `get_logs` are separate round trips, and
/// behind a hosted URL sits a POOL of nodes at differing heights. A node that
/// has not imported the range answers `Ok(vec![])` — success, no logs — which
/// the loop could not tell from "nothing happened in these blocks", so the
/// cursor moved past blocks nobody read. `block_confirmation` guards reorgs, not
/// a peer being behind. Asking the same provider for its head and clamping to it
/// makes the empty answer mean what it says. This is the rule the validator's
/// scanner already applies, shared from `bridge_core::scan` so the two cannot
/// drift.
async fn scan<P, F, Fut>(
    provider: &P,
    db: &Db,
    chain_id: u64,
    address: Address,
    window: Window,
    handler: F,
) -> anyhow::Result<Option<u64>>
where
    P: Provider,
    F: Fn(Db, u64, Log) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<()>>,
{
    let Window { from_block, to_block, confirmations } = window;
    let head = provider.get_block_number().await.context("get_block_number (scan window)")?;
    let Some(scanned_to) = clamp_scan_window(from_block, to_block, head, confirmations) else {
        return Ok(None);
    };
    let filter = Filter::new().address(address).from_block(from_block).to_block(scanned_to);
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
            .with_context(|| format!("handling log in blocks [{from_block},{scanned_to}]"))?;
    }
    Ok(Some(scanned_to))
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::transports::mock::Asserter;
    use tokio::sync::Mutex;

    /// `BRIDGE_TEST_DATABASE_URL`, or `None` with a note (CI has no Postgres —
    /// audit item 7 on the recommended-order list).
    fn live_db_url() -> Option<String> {
        match std::env::var("BRIDGE_TEST_DATABASE_URL") {
            Ok(u) if !u.is_empty() => Some(u),
            _ => {
                eprintln!("BRIDGE_TEST_DATABASE_URL unset — skipping live-Postgres test");
                None
            }
        }
    }

    /// Serialises the Postgres-backed tests in this crate.
    static LIVE_DB: Mutex<()> = Mutex::const_new(());

    async fn noop_handler(_db: Db, _chain_id: u64, _log: Log) -> anyhow::Result<()> {
        Ok(())
    }

    /// M-7. A node that has not imported the range answers `Ok(vec![])` —
    /// success, no logs — which used to look exactly like "nothing happened
    /// here" and moved the cursor past blocks nobody read.
    ///
    /// Both halves matter: the lagging endpoint must scan NOTHING (so the
    /// caller cannot advance), and a healthy-but-behind endpoint must scan only
    /// as far as IT has confirmed.
    #[tokio::test]
    async fn a_lagging_endpoint_scans_nothing_and_a_behind_one_only_what_it_confirmed() {
        let Some(url) = live_db_url() else { return };
        let _serial = LIVE_DB.lock().await;
        let db = Db::connect(&url).await.expect("connect to BRIDGE_TEST_DATABASE_URL");
        let addr = Address::repeat_byte(0x11);

        // (a) head 109, 10 confirmations => confirmed 99, below from_block 100.
        // Nothing may be read, and no `eth_getLogs` may even be attempted: the
        // asserter holds only the head reply, so a `get_logs` here panics.
        let a = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(a.clone());
        a.push_success(&U256::from(109u64));
        let reached = scan(&provider, &db, 1, addr, Window { from_block: 100, to_block: 199, confirmations: 10 }, noop_handler)
            .await
            .expect("a lagging endpoint is not an error");
        assert_eq!(reached, None, "a lagging endpoint must scan nothing");

        // (b) head 160 => confirmed 150: the window shrinks to 150, and the
        // cursor bound is what was read, not the 199 that was asked for.
        let a = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(a.clone());
        a.push_success(&U256::from(160u64));
        a.push_success(&Vec::<Log>::new());
        let reached = scan(&provider, &db, 1, addr, Window { from_block: 100, to_block: 199, confirmations: 10 }, noop_handler)
            .await
            .expect("scan");
        assert_eq!(reached, Some(150), "may only advance as far as this endpoint confirmed");
    }

    /// The cursor bound for a tick is the LOWEST of what each scanner read, and
    /// any scanner that read nothing (a lagging endpoint) pins the tick: gate,
    /// router and pool are three separate `eth_getLogs`, each of which may be
    /// served by a different node behind the same URL.
    #[test]
    fn one_lagging_scanner_holds_the_whole_tick_back() {
        // Mirrors the loop's `narrow` fold.
        fn advance_to(results: &[Option<u64>], requested_to: u64) -> Option<u64> {
            let mut acc = Some(requested_to);
            for r in results {
                acc = match (acc, r) {
                    (Some(a), Some(b)) => Some(a.min(*b)),
                    _ => None,
                };
            }
            acc
        }
        assert_eq!(advance_to(&[Some(199), Some(199), Some(199)], 199), Some(199));
        assert_eq!(advance_to(&[Some(199), Some(150), Some(199)], 199), Some(150), "lowest wins");
        assert_eq!(advance_to(&[Some(199), None, Some(199)], 199), None, "one lagging scanner pins it");
        assert_eq!(advance_to(&[], 199), Some(199), "no contracts configured: nothing to miss");
    }
}
