//! External-validator node.
//!
//! Phase 4 gave us the core loop: scan the source chain for `Sent`, recompute
//! `submissionId`, sign it (EIP-191 `eth_sign`) only if it matches, store it.
//!
//! Phase 6 hardens it into the real node:
//!   * multi-RPC failover with a chainId guard ([`provider::Failover`]),
//!   * a finality buffer (`block_confirmation`),
//!   * a resumable cursor persisted to disk ([`state::Runtime`]),
//!   * sequential-nonce enforcement — a missed or duplicated nonce *pauses* the
//!     scanner instead of silently signing,
//!   * an operator HTTP API (pause / resume / rescan / status).

mod api;
mod config;
mod provider;
mod refund;
mod scale;
mod state;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::{Address, B256};
use alloy::rpc::types::Filter;
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use alloy_sol_types::SolEvent;
use anyhow::Context;
use bridge_core::abi::Gate;
use bridge_core::allow::Allowlist;
use bridge_core::allow::AllowlistPolicy;
use bridge_core::backend::StoreBackend;
use bridge_core::signer::encode_signature;
use bridge_core::store::{SignerSig, SubmissionRecord};
use bridge_core::Submission;
use config::{Config, CorroboratePolicy, SourceChain};
use state::{NonceDecision, PauseReason, Runtime};
use tokio::sync::Mutex;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Scrubbed writer: a transport error carries the URL it failed on, and on a
    // keyed endpoint that is the provider key (see `log_scrub`).
    log_scrub::init("validator=info,bridge_core=info");

    let cfg_path = std::env::args().nth(1).unwrap_or_else(|| "validator.toml".into());
    let cfg = Config::load(&cfg_path)?;

    // Say so at startup: with this set, a store that serves an empty allowlist
    // halts signing rather than falling back to "allow everything" (M-5).
    if cfg.allowlist.required() {
        info!(
            pinned_tokens = cfg.allowlist.pinned_tokens.len(),
            pinned_chains = cfg.allowlist.pinned_chains.len(),
            "allowlist enforcement REQUIRED"
        );
    }

    let signer = cfg.signer.load("validator").context("loading validator signer")?;
    let signer_addr = signer.address();
    // One sink, shared across every per-source scan loop. L-5: read + sign only —
    // it cannot mark claimed or edit the allowlist.
    let sink = Arc::new(StoreBackend::from_config(&cfg.store, "SIG_STORE_VALIDATOR_TOKEN")?);

    info!(
        validator = %signer_addr,
        sources = cfg.sources.len(),
        sink = %sink.describe(),
        "validator started"
    );

    // Build a runtime per source up front so the operator API can address each by
    // chain_id, then spawn one scan loop per source sharing those runtimes.
    let mut runtimes: BTreeMap<u64, Arc<Mutex<Runtime>>> = BTreeMap::new();
    for source in &cfg.sources {
        let state_path = PathBuf::from(&source.state_file);
        // A corrupt state file is a hard error here (see `Runtime::load_or_init`):
        // it may hold a persisted safety stop, and coming up "fresh" would clear it.
        let runtime = Arc::new(Mutex::new(
            Runtime::load_or_init(&state_path, source.start_block)
                .with_context(|| format!("loading scanner state for chain {}", source.chain_id))?,
        ));
        runtimes.insert(source.chain_id, runtime);
    }
    let runtimes = Arc::new(runtimes);

    if let Some(api) = &cfg.api {
        let api_state = api::ApiState {
            sources: runtimes.clone(),
            validator: format!("{signer_addr:#x}"),
            token: api.resolved_token(),
            allow_unauthenticated: api.allow_unauthenticated,
        };
        let bind = api.bind.clone();
        tokio::spawn(async move {
            if let Err(e) = api::serve(&bind, api_state).await {
                warn!(error = %e, "operator API exited");
            }
        });
    }

    let mut tasks = tokio::task::JoinSet::new();

    // Refund attestations, if this validator is configured to verify destination
    // chains. Spawned alongside the scan loops and isolated the same way: a dead
    // refund loop must never stop the validator from signing live transfers.
    if let Some(refund_cfg) = cfg.refund.clone() {
        let sources: Vec<(u64, String, Vec<String>)> = cfg
            .sources
            .iter()
            .map(|s| Ok((s.chain_id, s.gate.clone(), s.endpoints()?)))
            .collect::<anyhow::Result<_>>()?;
        let signer = signer.clone();
        let sink = sink.clone();
        tasks.spawn(async move { refund::run(refund_cfg, sources, signer, sink).await });
    } else {
        info!("no [refund] block — this validator will not attest cancels or refunds");
    }

    // H-2: every scan loop needs to read the peer gates to confirm they agree on
    // an asset's scale before signing. Resolved once here so a misconfiguration
    // is a startup error rather than a per-transfer surprise.
    let scale_peers: Vec<(u64, String, Vec<String>)> = cfg
        .scale_destinations()
        .iter()
        .map(|d| Ok((d.chain_id, d.gate.clone(), d.endpoints()?)))
        .collect::<anyhow::Result<_>>()?;
    // Solana peers are separate: an EVM gate reader can never vouch for a Solana
    // payout, so without these every EVM->Solana transfer is refused.
    let solana_peers: Vec<(u64, [u8; 32], String)> = cfg
        .solana_destinations
        .iter()
        .map(|d| Ok((d.chain_id, d.program_key()?, d.rpc.clone())))
        .collect::<anyhow::Result<_>>()?;
    if scale_peers.is_empty() && solana_peers.is_empty() {
        warn!(
            "no [[destinations]], [refund.destinations] or [[solana_destinations]] — this \
             validator cannot verify that a peer agrees on an asset's bridge decimals, so it \
             will sign NOTHING. Add each peer (audit 2026-09-16, H-2)."
        );
    } else {
        info!(
            evm_peers = ?scale_peers.iter().map(|(c, _, _)| *c).collect::<Vec<_>>(),
            solana_peers = ?solana_peers.iter().map(|(c, _, _)| *c).collect::<Vec<_>>(),
            "bridge-decimals cross-check active for these destination chains"
        );
    }

    for source in cfg.sources {
        let signer = signer.clone();
        let sink = sink.clone();
        let runtime = runtimes.get(&source.chain_id).unwrap().clone();
        let peers = scale_peers.clone();
        let sol_peers = solana_peers.clone();
        let policy = cfg.allowlist.clone();
        let corroborate = cfg.corroborate.clone();
        tasks.spawn(async move {
            scan_source(
                source, signer, signer_addr, sink, runtime, peers, sol_peers, policy, corroborate,
            )
            .await
        });
    }

    // Isolate a dead source loop so one bad chain can't stop the validator from
    // signing transfers on the others. Only error out once every loop has exited.
    let total = tasks.len();
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(Ok(())) => warn!("a source scan loop exited on its own (other chains keep running)"),
            Ok(Err(e)) => warn!(error = %e, "a source scan loop failed (other chains keep running)"),
            Err(e) => warn!(error = %e, "a source task panicked (other chains keep running)"),
        }
    }
    anyhow::bail!("all {total} source scan loops have exited");
}

/// H-4: how many consecutive windows may end with no peer verdict before the
/// scanner stops waiting and falls back to the "no second source" policy.
///
/// At the shortest sensible poll interval this is minutes of patience, which
/// covers ordinary peer lag, and it bounds the damage from a peer that can never
/// answer to a loud warning rather than a stopped validator.
const INCONCLUSIVE_LIMIT: u32 = 10;

/// Scan one source chain forever: poll for `Sent`, verify, sign, store.
async fn scan_source(
    source: SourceChain,
    signer: PrivateKeySigner,
    signer_addr: Address,
    sink: Arc<StoreBackend>,
    runtime: Arc<Mutex<Runtime>>,
    scale_peers: Vec<(u64, String, Vec<String>)>,
    solana_peers: Vec<(u64, [u8; 32], String)>,
    policy: AllowlistPolicy,
    corroborate: CorroboratePolicy,
) -> anyhow::Result<()> {
    let gate: Address = source.gate.parse().context("bad gate address")?;
    let retry = Duration::from_millis(source.poll_interval_ms.max(1000));
    // Last observed chain head; see the refresh rule in the scan loop.
    let mut cached_latest: Option<u64> = None;
    // H-4: consecutive windows on which no peer could give a verdict. Bounded,
    // because an unverified window does not advance the cursor and a peer that can
    // NEVER answer would therefore stop this validator outright — a security check
    // that turns into a silent outage is the failure mode this repo has already
    // been bitten by (the H-2 cross-check withholding on an empty peer list,
    // 2026-09-24). Past the limit the policy for "no second source" applies.
    let mut inconclusive_streak: u32 = 0;
    // How fast we may read while behind. Defaults to the steady-state interval:
    // see `catchup_poll_interval_ms` for why aggression has to be opt-in.
    let catchup_ms = source.catchup_poll_interval_ms.unwrap_or(source.poll_interval_ms);

    // Multi-RPC failover, with a chainId guard per endpoint. Connecting can fail
    // if every endpoint is momentarily down/wrong-chain; retry rather than kill
    // this loop (and, with the isolation in main, never the sibling chains).
    let endpoints = source.endpoints()?;
    let mut failover = loop {
        match provider::Failover::connect_for_gate(&endpoints, source.chain_id, Some(gate)).await {
            Ok(mut f) => {
                // H-4: do not let the whole fleet prefer the same endpoint. The
                // offset comes from the validator's own address, so it is stable
                // across restarts (an endpoint order that reshuffled every boot
                // would make a real disagreement look like flapping) and differs
                // between validators without any coordination or extra config.
                f.stagger(signer_addr.as_slice()[19] as usize);
                break f;
            }
            Err(e) => {
                warn!(chain_id = source.chain_id, error = %e, "connecting RPC endpoints failed; retrying");
                tokio::time::sleep(retry).await;
            }
        }
    };
    // H-4: one endpoint means the `Sent` events this loop signs rest on a single
    // source's word. Say so at startup, once, with the fix in the message —
    // `[corroborate] require = true` turns it from a warning into a refusal.
    if failover.endpoint_count() < 2 {
        if corroborate.require {
            warn!(
                chain_id = source.chain_id,
                "[corroborate] require = true and only ONE healthy RPC endpoint: this loop will \
                 sign NOTHING until a second endpoint is reachable (audit H-4)"
            );
        } else {
            warn!(
                chain_id = source.chain_id,
                "only ONE healthy RPC endpoint: every signature rests on it alone, and a single \
                 endpoint serving a forged Sent mints a valid quorum (audit H-4). Add a second \
                 `rpcs` entry for this chain; set [corroborate] require = true to withhold instead."
            );
        }
    }

    // H-2: connect the peer gates this loop will cross-check against. Same retry
    // posture as the source connection — a peer that is momentarily down must not
    // kill the loop, and `connect_checked` verifies the chain id so a
    // wrong-chain endpoint cannot answer for a peer it is not.
    let scale_guard = {
        let mut dests = Vec::new();
        for (chain_id, gate_str, urls) in &scale_peers {
            let gate_addr: Address = gate_str
                .parse()
                .with_context(|| format!("bad gate address for destination {chain_id}"))?;
            let provider = loop {
                match provider::connect_checked(urls, *chain_id).await {
                    Ok(p) => break p,
                    Err(e) => {
                        warn!(chain_id, error = %e,
                              "connecting destination RPC for the bridge-decimals check failed; retrying");
                        tokio::time::sleep(retry).await;
                    }
                }
            };
            dests.push(scale::Destination { chain_id: *chain_id, gate: gate_addr, provider });
        }
        let solana = solana_peers
            .iter()
            .map(|(chain_id, program_id, rpc)| scale::SolanaDestination {
                chain_id: *chain_id,
                program_id: *program_id,
                rpc: rpc.clone(),
            })
            .collect();
        scale::ScaleGuard::new(dests, solana)
    };
    if scale_guard.is_empty() {
        warn!(
            chain_id = source.chain_id,
            "no verifiable destinations: this source will withhold every signature (H-2)"
        );
    }

    // The deployment generation, read FROM THE GATE rather than from config.
    //
    // Every submissionId is recomputed under this value, so a wrong one means
    // every recomputed id mismatches the emitted one and this validator signs
    // nothing — safe, but silent. Sourcing it from the contract removes the
    // possibility of that misconfiguration entirely, and costs one call at
    // startup. Retry rather than exit: a momentarily flaky RPC must not kill the
    // scan loop for this chain (and, per main's isolation, never its siblings).
    let bridge_domain: B256 = loop {
        match Gate::new(gate, failover.active_provider()).bridgeDomain().call().await {
            Ok(d) => break d,
            Err(e) => {
                warn!(
                    chain_id = source.chain_id,
                    gate = %gate,
                    error = %e,
                    "reading Gate.bridgeDomain() failed; retrying (is this gate pre-domain?)"
                );
                tokio::time::sleep(retry).await;
            }
        }
    };

    let resume_from = runtime.lock().await.next_block();
    info!(
        validator = %signer_addr,
        gate = %gate,
        bridge_domain = %bridge_domain,
        chain_id = source.chain_id,
        // Redacted to scheme+host by `Failover`: hosted RPC keys live in the path.
        rpc = %failover.active_url(),
        // BOTH counts, because they differ and the difference is what matters.
        // Reporting only the configured length made this line lie: an endpoint
        // dropped by the startup probe (wrong chain, unreachable, or unable to
        // serve `eth_call`) still counted, so an operator reading `endpoints = 3`
        // would believe H-4 corroboration had two peers to choose from when it
        // had one — or none. Caught on mesh10 the day the check shipped, where a
        // configured Hoodi endpoint 404s from inside the container.
        endpoints_configured = endpoints.len(),
        endpoints_healthy = failover.endpoint_count(),
        resume_from,
        "source scan loop started"
    );
    if failover.endpoint_count() < endpoints.len() {
        warn!(
            chain_id = source.chain_id,
            configured = endpoints.len(),
            healthy = failover.endpoint_count(),
            "some configured RPC endpoints were DROPPED at startup (see the `skipping RPC` lines \
             above for each reason). H-4 corroboration only has the healthy ones to work with."
        );
    }

    let sent_sig = Gate::Sent::SIGNATURE_HASH;

    loop {
        // Respect the pause flag (operator-set, or tripped by a nonce anomaly).
        {
            let rt = runtime.lock().await;
            if rt.paused() {
                let reason = rt.pause_reason().map(|r| r.as_str()).unwrap_or_default();
                drop(rt);
                warn!(chain_id = source.chain_id, %reason, "scanner PAUSED — not processing (resume via operator API)");
                tokio::time::sleep(Duration::from_millis(source.poll_interval_ms.max(1000))).await;
                continue;
            }
        }

        let from_block = runtime.lock().await.next_block();
        // The head is re-read only when the scanner has caught up to what it last
        // saw. A scanner a million blocks behind learns nothing from asking where
        // the tip is between every 100-block window — and that extra round trip
        // is half the round trips it makes, so skipping it doubles catch-up
        // throughput. Once current, this reduces to the old behaviour: every
        // tick reaches the cached head and re-reads it.
        if cached_latest.is_none_or(|l| from_block + source.block_confirmation > l) {
            // Transient RPC failures must not kill the loop (which, pre-fix, also
            // took down every sibling chain). Log, back off, and try again.
            match failover.get_block_number().await {
                Ok(v) => cached_latest = Some(v),
                Err(e) => {
                    warn!(chain_id = source.chain_id, error = %e, "get_block_number failed; retrying");
                    tokio::time::sleep(retry).await;
                    continue;
                }
            }
        }
        let latest = cached_latest.unwrap_or(0);
        let confirmed = latest.saturating_sub(source.block_confirmation);

        if confirmed >= from_block {
            let to_block = confirmed.min(from_block + source.max_block_range - 1);

            // Address/topic selection only — the block range is applied by
            // `get_logs_confirmed`, against the head of the endpoint that serves
            // the call. `cached_latest` above may have come from a DIFFERENT
            // endpoint (failover rotates between calls); a lagging node would
            // return no logs for blocks it has not seen, the call would succeed,
            // and the cursor would move past transfers nobody signed. So the
            // window is clamped per endpoint and the cursor only ever advances
            // to `scanned_to` — what was actually read — never to `to_block`.
            let filter = Filter::new().address(gate).event_signature(sent_sig);

            let (mut logs, scanned_to, verdict) = match failover
                .get_logs_corroborated(&filter, from_block, to_block, source.block_confirmation)
                .await
            {
                Ok(Some(v)) => v,
                Ok(None) => {
                    // The endpoint that answered has nothing confirmed at
                    // `from_block` yet: it lags the head we cached from another.
                    // Nothing was scanned, so nothing advances; re-read the head
                    // next tick rather than trusting the stale cache.
                    warn!(
                        chain_id = source.chain_id,
                        rpc = %failover.active_url(),
                        from_block,
                        cached_head = latest,
                        "serving RPC lags the cached head; not advancing the cursor"
                    );
                    cached_latest = None;
                    tokio::time::sleep(retry).await;
                    continue;
                }
                Err(e) => {
                    warn!(chain_id = source.chain_id, error = %e, "get_logs failed; retrying");
                    tokio::time::sleep(retry).await;
                    continue;
                }
            };
            // H-4: the window must survive a second endpoint before anything in it
            // is signed. A validator's whole view of a deposit is the `Sent` log,
            // so one endpoint that serves a fabricated one mints a signature the
            // destination gate cannot distinguish from an honest quorum.
            //
            // Every non-agreement leaves the cursor PUT. That is the point: this
            // range is unverified, and skipping it would strand the transfers in
            // it (and, because nonces must be sequential, stall on the next one
            // anyway). Re-reading is free and idempotent.
            match &verdict {
                provider::Corroboration::Agreed { .. } => {
                    inconclusive_streak = 0;
                }
                provider::Corroboration::Disagreed { served_by, checked_by, detail } => {
                    inconclusive_streak = 0;
                    // The endpoint has already been demoted inside the provider,
                    // so the retry below reads from someone else. This is the one
                    // log line in the system that means "an RPC endpoint lied".
                    warn!(
                        chain_id = source.chain_id,
                        %served_by,
                        %checked_by,
                        %detail,
                        from_block,
                        scanned_to,
                        "RPC ENDPOINTS DISAGREE about this range — signing NOTHING from it and \
                         demoting the endpoint that served it (audit H-4). If this persists, one \
                         endpoint is wrong about the chain: investigate before resuming."
                    );
                    tokio::time::sleep(retry).await;
                    continue;
                }
                provider::Corroboration::Inconclusive { reason } => {
                    inconclusive_streak = inconclusive_streak.saturating_add(1);
                    if inconclusive_streak < INCONCLUSIVE_LIMIT {
                        // Almost always a lagging peer, which is ordinary. Not an
                        // accusation, and not agreement either: wait for it.
                        warn!(
                            chain_id = source.chain_id,
                            %reason,
                            from_block,
                            scanned_to,
                            attempt = inconclusive_streak,
                            "no second opinion on this range yet; not advancing the cursor"
                        );
                        tokio::time::sleep(retry).await;
                        continue;
                    }
                    // Every peer has failed this range this many times running, so
                    // it is not transient lag — it is a peer that cannot answer at
                    // all (a `get_logs` range cap below `max_block_range` is the
                    // usual cause). Treat it as "no second source" and apply that
                    // policy, loudly, rather than staying stopped for ever on a
                    // configuration problem nothing else would report.
                    warn!(
                        chain_id = source.chain_id,
                        %reason,
                        from_block,
                        scanned_to,
                        attempts = inconclusive_streak,
                        "NO PEER CAN CORROBORATE this range after {INCONCLUSIVE_LIMIT} attempts — \
                         treating it as having no second source. Usual cause: a peer's eth_getLogs \
                         range cap is below this chain's max_block_range. Fix the peer list (audit H-4)."
                    );
                    if corroborate.require {
                        warn!(
                            chain_id = source.chain_id,
                            "WITHHOLDING: [corroborate] require = true (audit H-4)"
                        );
                        tokio::time::sleep(retry).await;
                        continue;
                    }
                }
                provider::Corroboration::Unavailable => {
                    if corroborate.require {
                        warn!(
                            chain_id = source.chain_id,
                            "WITHHOLDING: [corroborate] require = true and no second RPC endpoint \
                             for this chain (audit H-4)"
                        );
                        tokio::time::sleep(retry).await;
                        continue;
                    }
                }
            }

            // True when there is more ALREADY-CONFIRMED history waiting right now:
            // the window was capped by `max_block_range`, or shortened by a lagging
            // endpoint. See the catch-up note where this is consumed.
            let behind = scanned_to < confirmed;
            // Process in chain order so nonce sequencing is meaningful.
            logs.sort_by_key(|l| (l.block_number.unwrap_or(0), l.log_index.unwrap_or(0)));

            // A log the node has since orphaned. `block_confirmation` is the real
            // defence — we read well behind the head precisely so this cannot
            // happen — so seeing one means the reorg went DEEPER than the
            // configured buffer, which is a security parameter having been set too
            // low for this chain. Drop the event (never sign a transfer the chain
            // has retracted) and say so loudly: nothing else in the system would
            // ever mention it, and the operator needs to raise the buffer.
            let before = logs.len();
            logs.retain(|l| !l.removed);
            if logs.len() != before {
                warn!(
                    chain_id = source.chain_id,
                    dropped = before - logs.len(),
                    block_confirmation = source.block_confirmation,
                    "REORG DEEPER THAN block_confirmation — dropped orphaned logs. Raise \
                     block_confirmation for this chain; a transfer signed from an orphaned \
                     block would be attested against history that no longer exists."
                );
            }

            // Allowlist for this batch. In sig-store mode a fetch failure is
            // fail-closed (skip the batch) so we never sign a now-disallowed
            // transfer on a stale view; in file mode it is None (no enforcement).
            //
            // A SUCCESSFUL fetch can also be refused (audit 2026-09-16, M-5):
            // with `[allowlist] require = true` an empty served list is the
            // kill-switch being turned off by whoever controls the store, and a
            // list missing a locally pinned entry has been truncated. Both skip
            // the batch rather than sign on it.
            let allowlist = match sink.fetch_allowlist().await.map(|v| policy.check(v)) {
                Ok(Ok(a)) => a,
                Ok(Err(refusal)) => {
                    warn!(
                        chain_id = source.chain_id,
                        reason = %refusal,
                        "REFUSING to sign on the served allowlist; skipping batch"
                    );
                    tokio::time::sleep(retry).await;
                    continue;
                }
                Err(e) => {
                    warn!(chain_id = source.chain_id, error = %e, "allowlist fetch failed; skipping batch");
                    tokio::time::sleep(retry).await;
                    continue;
                }
            };

            // The nonce cursor and the block cursor must advance TOGETHER.
            //
            // `handle_log` advances the nonce cursor per event, as soon as that
            // event is durably stored, but `last_block` only advances once the
            // WHOLE batch is handled — so a mid-batch stop rescans events whose
            // nonces were already consumed. `check_nonce` reads those as
            // DUPLICATED and pauses the scanner on an anomaly that never
            // happened, a persisted stop only an operator can clear. One
            // transient sig-store error was enough to take a validator out of
            // quorum until someone noticed.
            //
            // So snapshot the nonce cursor here and roll it back below whenever
            // the block cursor stays put. The rollback also keeps a genuine
            // anomaly legible: without it, a MISSED_NONCE stop that the operator
            // resumes comes back as DUPLICATED_NONCE on the replay, hiding the
            // real reason behind an invented one.
            let nonces_before = runtime.lock().await.nonce_snapshot();

            let mut paused = false;
            let mut batch_failed = false;
            for log in &logs {
                match handle_log(
                    &signer,
                    signer_addr,
                    &sink,
                    &runtime,
                    log,
                    allowlist.as_ref(),
                    bridge_domain,
                    &scale_guard,
                )
                .await
                {
                    Ok(true) => {} // processed
                    Ok(false) => {
                        // a nonce anomaly paused the scanner; stop this batch
                        paused = true;
                        break;
                    }
                    Err(e) => {
                        // A sign/store failure must NOT lose the signature: stop the
                        // batch and leave the cursor put, so the range is rescanned
                        // next tick. Re-signing the range is idempotent (the store
                        // upserts), and the nonce rollback below puts the sequence
                        // back where the replay expects to find it.
                        warn!(chain_id = source.chain_id, error = %e, "failed handling log; will retry same range");
                        batch_failed = true;
                        break;
                    }
                }
            }

            let mut rt = runtime.lock().await;
            if paused || batch_failed {
                // This range will be rescanned, so put the nonce cursor back where
                // the block cursor still points. See `nonces_before` above.
                rt.restore_nonces(nonces_before);
            } else {
                // Advance the cursor only after the whole batch is durably handled,
                // and only as far as the serving endpoint actually scanned.
                rt.persist.last_block = scanned_to;
            }
            if let Err(e) = rt.save() {
                warn!(chain_id = source.chain_id, error = %e, "failed to persist scanner state");
            }

            // Catch-up: when the range was capped there is confirmed history
            // still unread, and sleeping a full poll interval before the next
            // window is what makes recovery take hours.
            //
            // The arithmetic is unforgiving on a fast chain. Monad produces ~3.3
            // blocks/s; a 100-block cap polled every 2s reads ~34/s, so it gains
            // only ~31 blocks/s on the head — a day of downtime then takes ~6
            // hours to work off, during which the validator signs nothing recent.
            // Reading back-to-back while behind turns that into minutes.
            //
            // A small floor remains so a fast-answering endpoint cannot be
            // hammered, and the configured interval still governs the steady
            // state — this path only runs when there is a real backlog.
            if behind && !paused && !batch_failed {
                tokio::time::sleep(Duration::from_millis(catchup_ms)).await;
                continue;
            }
        }

        tokio::time::sleep(Duration::from_millis(source.poll_interval_ms)).await;
    }
}

/// Returns `Ok(true)` if the event was processed (or harmlessly skipped),
/// `Ok(false)` if a nonce anomaly paused the scanner (caller should stop).
async fn handle_log(
    signer: &PrivateKeySigner,
    signer_addr: Address,
    sink: &StoreBackend,
    runtime: &Arc<Mutex<Runtime>>,
    log: &alloy::rpc::types::Log,
    allowlist: Option<&Allowlist>,
    bridge_domain: B256,
    scale: &scale::ScaleGuard,
) -> anyhow::Result<bool> {
    let decoded = Gate::Sent::decode_log(&log.inner).context("decode Sent")?;
    let ev = &decoded.data;

    let emitted_id: B256 = ev.submissionId;
    // Chain ids and the nonce MUST fit u64 (see `SubmissionRecord::from_sent_event`
    // for why an aliasing cast would break claim reconstruction). A real gate
    // never emits these; treat it as a malformed or hostile source and refuse to
    // sign — but skip, don't error, so a single bad log can't wedge the batch
    // (H3 retries errors forever).
    let Some(record) = SubmissionRecord::from_sent_event(ev, bridge_domain) else {
        warn!(
            submission_id = %emitted_id,
            chain_from = %ev.chainIdFrom,
            chain_to = %ev.chainIdTo,
            nonce = %ev.nonce,
            "Sent event has a chainId/nonce that exceeds u64 — refusing to sign (aliased value would mis-key the nonce and break claim reconstruction)"
        );
        return Ok(true); // skip this event; never sign an aliased transfer
    };
    let (chain_from, chain_to, nonce) = (record.chain_id_from, record.chain_id_to, record.nonce);

    // Sequential-nonce enforcement (mirrors NonceControllingService). The nonce
    // sequence is per (chain_from, chain_to): each source gate runs its own
    // nonceTo[chainIdTo], so distinct sources reach the same destination with
    // independent 0,1,2,… — a mesh corridor, not a duplicate.
    {
        let mut rt = runtime.lock().await;
        match rt.check_nonce(chain_from, chain_to, nonce) {
            NonceDecision::Accept => {}
            NonceDecision::Missed => {
                let expected = rt.last_nonce(chain_from, chain_to).map(|n| n + 1).unwrap_or(0);
                warn!(chain_from, chain_to, expected, got = nonce, "MISSED_NONCE — pausing scanner");
                rt.pause(PauseReason::MissedNonce { chain_from, chain_to, expected, got: nonce });
                let _ = rt.save();
                return Ok(false);
            }
            NonceDecision::Duplicated => {
                let last = rt.last_nonce(chain_from, chain_to).unwrap_or(0);
                warn!(chain_from, chain_to, last, got = nonce, "DUPLICATED_NONCE — pausing scanner");
                rt.pause(PauseReason::DuplicatedNonce { chain_from, chain_to, last, got: nonce });
                let _ = rt.save();
                return Ok(false);
            }
        }
    }

    // Independently recompute the submissionId; never sign one we can't reproduce.
    let computed_id = Submission::from_sent_event(ev, bridge_domain).compute_id();
    if computed_id != emitted_id {
        warn!(
            emitted = %emitted_id,
            computed = %computed_id,
            "submissionId MISMATCH — refusing to sign and pausing (bad/lying RPC?)"
        );
        let mut rt = runtime.lock().await;
        rt.pause(PauseReason::IdMismatch { submission_id: format!("{emitted_id:#x}") });
        let _ = rt.save();
        return Ok(false);
    }

    // Allowlist enforcement: refuse to attest a non-whitelisted token or chain
    // pair. We still consume the nonce (the transfer really happened on-chain) so
    // the sequence stays intact — we just withhold our signature, so it can never
    // reach threshold and be claimed.
    if let Some(allow) = allowlist {
        let debridge_hex = format!("{:#x}", ev.debridgeId);
        if !allow.token_allowed(&debridge_hex) || !allow.chain_allowed(chain_from, chain_to) {
            warn!(
                submission_id = %emitted_id,
                debridge_id = %debridge_hex,
                chain_from,
                chain_to,
                "BLOCKED by allowlist — withholding signature (nonce advanced)"
            );
            runtime.lock().await.accept_nonce(chain_from, chain_to, nonce);
            return Ok(true);
        }
    }

    // H-2: the submissionId now commits to the scale (`ev.bridgeDecimals` is in
    // the preimage), and `claim` refuses a scale that is not the destination's
    // own registration — so a mis-scaled corridor can no longer pay out wrong.
    // What it CAN still do is strand every transfer into it, unclaimable, to be
    // walked back through cancel -> refund. Refusing to sign turns that into one
    // warning at the first transfer instead of a queue of stuck users, so this
    // still runs and still fails CLOSED. The nonce is consumed either way (the
    // transfer really happened), so the sequence stays intact.
    // `?`: a read that failed in transit is not a verdict. Propagating it fails
    // the batch, which leaves the cursor put and rolls the nonces back, so the
    // transfer is re-examined next tick instead of being withheld for good.
    match scale.verdict(ev.bridgeDecimals, chain_to, ev.debridgeId).await? {
        scale::Verdict::Agree(_) => {}
        scale::Verdict::Mismatch { source, destination } => {
            warn!(
                submission_id = %emitted_id,
                debridge_id = %ev.debridgeId,
                chain_from,
                chain_to,
                source_bridge_decimals = source,
                destination_bridge_decimals = destination,
                "BRIDGE DECIMALS MISMATCH — the source signed this transfer at one \
                 scale and the destination would pay it at another, so the claim can \
                 never verify there. Withholding signature (nonce advanced); the \
                 transfer is recoverable through cancel -> refund. Both registrations \
                 are write-once: fixing the corridor needs a gate upgrade or a new \
                 mesh generation."
            );
            runtime.lock().await.accept_nonce(chain_from, chain_to, nonce);
            return Ok(true);
        }
        scale::Verdict::Unknown(why) => {
            warn!(
                submission_id = %emitted_id,
                debridge_id = %ev.debridgeId,
                chain_to,
                reason = why,
                "cannot verify the destination's bridge decimals — withholding signature \
                 (nonce advanced)"
            );
            runtime.lock().await.accept_nonce(chain_from, chain_to, nonce);
            return Ok(true);
        }
    }

    // EIP-191 eth_sign over the raw 32-byte submissionId.
    let sig = signer.sign_message(emitted_id.as_slice()).await?;
    let sig_hex = encode_signature(&sig);

    sink.upsert(record, SignerSig { signer: format!("{signer_addr:#x}"), signature: sig_hex })
        .await?;

    // Record the accepted nonce only after a successful sign+store.
    runtime.lock().await.accept_nonce(chain_from, chain_to, nonce);

    info!(
        submission_id = %emitted_id,
        nonce,
        chain_to,
        "SIGNED and stored"
    );
    Ok(true)
}
