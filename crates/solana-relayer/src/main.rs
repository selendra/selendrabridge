//! solana-relayer — the Solana leg's off-chain runner (finding M-3).
//!
//! Runs as its OWN process rather than inside `validator`, and has to: adding
//! `solana-client` to the validator fails to resolve, because Solana 1.18 pins
//! `ed25519-dalek 1.0.1 -> curve25519-dalek 3.2.1 -> zeroize <1.4` while alloy
//! requires `zeroize ^1.5`. The two dependency trees are mutually exclusive.
//! Splitting the process is the correct boundary anyway — it shares no chain
//! client with the EVM side, only the sig-store, which it reaches over HTTP.
//!
//! It performs the validator's job for Solana: scan the gate for `Sent`,
//! independently recompute the submissionId, sign it with the SAME secp256k1 key
//! the EVM validator uses, and store the signature.

use solana_relayer::gate::evm_address;
use solana_relayer::{config, evm, observer, refund, source, store, target};
use tracing::{info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Scrubbed writer: a transport error carries the URL it failed on, and on a
    // keyed endpoint that is the provider key (see `log_scrub`).
    log_scrub::init("solana_relayer=info");

    let (mode, path) = config::parse_args(std::env::args().skip(1))?;
    let cfg = config::Config::load(&path)?;
    // L7-14 (audit 2026-10-02): the Sign and Indexer credentials never share a
    // process. See `config::check_credentials`.
    config::check_credentials(mode, cfg.store.token().is_some(), cfg.store.indexer_token().is_some())?;
    if mode == config::Mode::ObserverOnly {
        return run_observer_only(cfg).await;
    }
    let key = cfg.signer.resolve()?;

    if cfg.store.token().is_none() {
        tracing::warn!(
            var = %cfg.store.token_env,
            "no sig-store token set — requests will be unauthenticated"
        );
    }
    // Each loop gets its own client (they run concurrently); one closure so the
    // url/token pair is read from one place.
    let sig_store = || store::Store::new(&cfg.store.url, cfg.store.token());

    let secret = libsecp256k1::SecretKey::parse(&key)
        .map_err(|_| anyhow::anyhow!("signer key is not a valid secp256k1 scalar"))?;
    let signer_address = evm_address(&secret);

    // The claim submitter, when configured. Spawned alongside the scanner and
    // isolated the same way the EVM validator isolates its loops: a dead
    // submitter must never stop this node from signing.
    let submitter = match cfg.target.as_ref() {
        Some(t) => Some(target::Submitter::new(&cfg.source, t, sig_store()?)?),
        None => {
            info!("no [target] block — this relayer signs but never delivers claims");
            None
        }
    };

    // Refund attester for both Solana corridors (EVM->Solana and, since audit
    // round 4, Solana->EVM). Without it a transfer that cannot be delivered is
    // burnable and refundable only by hand: the EVM validators cannot read
    // Solana, so nobody else votes on these corridors.
    let attester =
        refund::Attester::new(&cfg.source, cfg.refund.as_ref(), key, signer_address, sig_store()?)?;

    // The marker observer no longer runs in this process (L7-14): it is the
    // `--observer-only` mode of this same binary, in its own process/container
    // holding the Indexer token and nothing else.
    info!(
        "marker observer is not part of the signing process; run `solana-relayer --observer-only \
         <config>` separately with only SIG_STORE_INDEXER_TOKEN (audit 2026-10-02, L7-14)"
    );

    // H-2: the scanner cross-checks each EVM destination's bridge decimals before
    // signing, so it needs the same gate readers the refund attester uses. A peer
    // with no reader here is unverifiable and will not be signed for.
    let mut evm_gates = std::collections::BTreeMap::new();
    for reader_cfg in cfg.scale_readers() {
        evm_gates.insert(reader_cfg.chain_id, evm::GateReader::new(reader_cfg)?);
    }
    if evm_gates.is_empty() {
        warn!(
            "no [[evm_destinations]] (and no [[refund.evm]]) — this relayer cannot verify that an EVM destination \
             agrees on an asset's bridge decimals, so it will sign NOTHING (audit H-2)"
        );
    } else {
        info!(peers = ?evm_gates.keys().collect::<Vec<_>>(),
              "bridge-decimals cross-check active for these EVM destinations");
    }

    let scanner = source::Scanner::new(cfg.source, key, sig_store()?, evm_gates)?;
    info!(validator = %scanner.signer_address(), "solana-relayer started");

    // Each loop is isolated: a dead submitter or attester must never stop this
    // node signing transfers, which is its one irreplaceable job. The optional
    // loop is spawned as a task that never returns when absent, so one
    // `select!` covers every combination.
    let scan = tokio::spawn(scanner.run());
    let refunds = tokio::spawn(attester.run());
    let submit = spawn_optional(submitter.map(|s| s.run()));
    tokio::select! {
        r = scan => r??,
        r = submit => r??,
        r = refunds => r??,
    }
    Ok(())
}

/// `--observer-only`: the marker observer, the Solana gate's stand-in for the
/// EVM indexer. It reports observed claimed/cancelled/refunded markers to the
/// store on the Indexer-scoped token, and ONLY on that token — its reports are
/// authoritative. Without it a delivered EVM->Solana transfer stays `signed`
/// in the store forever and is flagged stuck by the indexer's sweep.
///
/// Runs ALONE (audit 2026-10-02, L7-14). It used to run inside the delivering
/// relayer, which therefore held both the Sign token (create a row) and the
/// Indexer token (mark it observed) — the two halves of round-4 M-4's
/// "pre-poison a future submissionId", recombined in one container. This mode
/// never resolves the signing key and refuses to start with the Sign token in
/// its environment ([`config::check_credentials`]).
async fn run_observer_only(cfg: config::Config) -> anyhow::Result<()> {
    let token = cfg.store.indexer_token().expect("check_credentials requires the indexer token here");
    info!(
        token = %cfg.store.indexer_token_source(),
        poll_ms = cfg.observer.poll_interval_ms,
        commitment = %cfg.observer.commitment,
        "observer-only mode: Solana terminal markers will be reported to the store; this process \
         holds no signing key and no Sign credential"
    );
    observer::Observer::new(&cfg.source, &cfg.observer, store::Store::new(&cfg.store.url, Some(token))?)?
        .run()
        .await
}

/// Spawn an optional loop; an absent one becomes a task that pends forever, so
/// the caller's `select!` needs no per-combination branch.
fn spawn_optional<F>(fut: Option<F>) -> tokio::task::JoinHandle<anyhow::Result<()>>
where
    F: std::future::Future<Output = anyhow::Result<()>> + Send + 'static,
{
    match fut {
        Some(f) => tokio::spawn(f),
        None => tokio::spawn(std::future::pending()),
    }
}
