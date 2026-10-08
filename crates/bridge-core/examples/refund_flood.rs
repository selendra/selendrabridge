//! Test tooling for scripts/testing/refund-starvation.sh (audit round 7, H7-5).
//!
//! Posts `count` well-formed submissions that no gate ever emitted — valid
//! id⇄params binding, valid token binding, a genuine transfer signature from
//! the key in `FLOOD_SIGNER_KEY` — to a sig-store. Nonces start at 10^9, far
//! past anything a test chain sends, so none of them is ever a real transfer.
//! This is exactly what a `Sign` credential could put in the refund queue.
//!
//!   FLOOD_SIGNER_KEY=0x.. cargo run -p bridge-core --features abi,http \
//!     --example refund_flood -- <store_url> <count> <chain_from> <chain_to> <token> <bridge_domain>
//!
//! The key is read from the environment, never from argv; so is the store's
//! bearer token, `FLOOD_STORE_TOKEN`, when the store wants one.

use std::str::FromStr;
use std::sync::Arc;

use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use alloy_primitives::{Address, B256, U256};
use bridge_core::remote::RemoteStore;
use bridge_core::store::{SigKind, SignerSig, SubmissionRecord};

const BRIDGE_DECIMALS: u8 = 18;
const CONCURRENCY: usize = 32;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    anyhow::ensure!(args.len() == 6, "usage: <store_url> <count> <chain_from> <chain_to> <token> <bridge_domain>");
    let store = Arc::new(RemoteStore::with_token(
        args[0].clone(),
        std::env::var("FLOOD_STORE_TOKEN").ok().filter(|t| !t.is_empty()),
    ));
    let count: u64 = args[1].parse()?;
    let from: u64 = args[2].parse()?;
    let to: u64 = args[3].parse()?;
    let token = Address::from_str(&args[4])?;
    let domain = B256::from_str(&args[5])?;
    let signer: PrivateKeySigner = std::env::var("FLOOD_SIGNER_KEY")?.parse()?;
    let signer = Arc::new(signer);

    let debridge_id = bridge_core::debridge_id(U256::from(from), token);
    let receiver = Address::repeat_byte(0xAB).to_vec();
    let sem = Arc::new(tokio::sync::Semaphore::new(CONCURRENCY));
    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..count {
        let nonce = 1_000_000_000 + i;
        let id = bridge_core::submission_id(
            domain,
            debridge_id,
            BRIDGE_DECIMALS,
            U256::from(1u64),
            U256::from(from),
            U256::from(to),
            U256::from(nonce),
            &receiver,
        );
        let rec = SubmissionRecord {
            submission_id: format!("{id:#x}"),
            bridge_domain: format!("{domain:#x}"),
            debridge_id: format!("{debridge_id:#x}"),
            amount: "1".into(),
            bridge_decimals: Some(BRIDGE_DECIMALS),
            chain_id_from: from,
            chain_id_to: to,
            nonce,
            receiver: format!("0x{}", hex::encode(&receiver)),
            auto_params: "0x".into(),
            native_sender: "0x".into(),
            token: format!("{token:#x}"),
            signatures: vec![],
            cancel_signatures: vec![],
            refund_signatures: vec![],
        };
        let sig = signer.sign_message_sync(SigKind::Transfer.digest(id).as_slice())?;
        let sig = SignerSig {
            signer: format!("{:#x}", signer.address()),
            signature: bridge_core::signer::encode_signature(&sig),
        };
        let permit = sem.clone().acquire_owned().await?;
        let store = store.clone();
        tasks.spawn(async move {
            let _permit = permit;
            store.upsert(rec, sig).await
        });
    }
    let mut ok = 0u64;
    while let Some(r) = tasks.join_next().await {
        r??;
        ok += 1;
    }
    println!("posted {ok} never-sent submissions ({from} -> {to})");
    Ok(())
}
