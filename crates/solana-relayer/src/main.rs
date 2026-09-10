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
use solana_relayer::{config, observer, refund, source, store, target};
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "solana_relayer=info".into()),
        )
        .init();

    let path = std::env::args().nth(1).unwrap_or_else(|| "solana-relayer.toml".into());
    let cfg = config::Config::load(&path)?;
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
        Some(t) => Some(target::Submitter::new(&cfg.source, t, sig_store())?),
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
        refund::Attester::new(&cfg.source, cfg.refund.as_ref(), key, signer_address, sig_store())?;

    // The marker observer: the Solana gate's stand-in for the EVM indexer. It
    // reports observed claimed/cancelled/refunded markers to the store on the
    // Indexer-scoped token, and ONLY on that token — its reports are
    // authoritative, so it runs iff that credential resolves. Without it a
    // delivered EVM->Solana transfer stays `signed` in the store forever and is
    // flagged stuck by the indexer's sweep.
    let observer = match cfg.store.indexer_token() {
        Some(token) => {
            info!(
                token = %cfg.store.indexer_token_source(),
                poll_ms = cfg.observer.poll_interval_ms,
                commitment = %cfg.observer.commitment,
                "observer ACTIVE: Solana terminal markers will be reported to the store"
            );
            Some(observer::Observer::new(
                &cfg.source,
                &cfg.observer,
                store::Store::new(&cfg.store.url, Some(token)),
            )?)
        }
        None => {
            info!(
                token = %cfg.store.indexer_token_source(),
                "observer INACTIVE: no indexer token resolves — Solana claims/cancels/refunds \
                 will not reach the store's lifecycle from this process (set [store] \
                 indexer_token_env = \"SIG_STORE_INDEXER_TOKEN\" on the relayer that delivers)"
            );
            None
        }
    };

    let scanner = source::Scanner::new(cfg.source, key, sig_store())?;
    info!(validator = %scanner.signer_address(), "solana-relayer started");

    // Each loop is isolated: a dead submitter, attester or observer must never
    // stop this node signing transfers, which is its one irreplaceable job.
    // Every optional loop is spawned as a task that never returns when absent,
    // so one `select!` covers every combination.
    let scan = tokio::spawn(scanner.run());
    let refunds = tokio::spawn(attester.run());
    let submit = spawn_optional(submitter.map(|s| s.run()));
    let observe = spawn_optional(observer.map(|o| o.run()));
    tokio::select! {
        r = scan => r??,
        r = submit => r??,
        r = refunds => r??,
        r = observe => r??,
    }
    Ok(())
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
