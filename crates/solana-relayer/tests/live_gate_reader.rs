//! Opt-in LIVE check of the Solana->EVM H-2 read against a real deployed gate.
//!
//! `GateReader::bridge_decimals_for` decides whether this relayer signs a
//! Solana->EVM transfer. Its fallback path (`tokenOf` + `bridgeDecimalsOf` for a
//! gate older than `bridgeDecimalsFor`) was added after replaying live mesh8
//! traffic showed every transfer to a pre-upgrade gate being refused. The unit
//! tests pin the ABI decoding against hand-built words; this runs the real code
//! against a real node and a real gate, which is the only way to learn whether
//! the two agree.
//!
//! IGNORED by default, and it FAILS rather than passes when its inputs are
//! missing: a live test that reports green without running is how
//! `bridge-db`'s Postgres suite went unverified (audit 2026-09-16). Run with:
//!
//! ```text
//! LIVE_EVM_RPC=https://… LIVE_CHAIN_ID=560048 LIVE_GATE=0x… \
//! LIVE_DEBRIDGE_ID=0x… LIVE_EXPECT_DECIMALS=6 \
//!   cargo test --test live_gate_reader -- --ignored --nocapture
//! ```
//!
//! `LIVE_EXPECT_DECIMALS` is the scale the gate should report for that
//! corridor. A corridor the gate does not map must come back `None`, which the
//! second test checks with an id nothing can have registered.

use solana_relayer::config::EvmReader;
use solana_relayer::evm::GateReader;

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is required for this live test"))
}

fn hex32(s: &str) -> [u8; 32] {
    let h = s.strip_prefix("0x").unwrap_or(s);
    let v = hex::decode(h).expect("hex");
    v.try_into().expect("32 bytes")
}

fn reader() -> GateReader {
    GateReader::new(&EvmReader {
        chain_id: env("LIVE_CHAIN_ID").parse().expect("LIVE_CHAIN_ID"),
        gate: env("LIVE_GATE"),
        rpc: Some(env("LIVE_EVM_RPC")),
        rpc_env: None,
        // A registration is write-once; a shallow buffer is plenty for a read.
        block_confirmation: 2,
    })
    .expect("reader")
}

#[tokio::test]
#[ignore = "live network; see module docs"]
async fn a_registered_corridor_reports_its_scale() {
    let want: u8 = env("LIVE_EXPECT_DECIMALS").parse().expect("LIVE_EXPECT_DECIMALS");
    let got = reader()
        .bridge_decimals_for(&hex32(&env("LIVE_DEBRIDGE_ID")))
        .await
        .expect("a transport failure here is not an answer; rerun");
    println!("bridge_decimals_for -> {got:?}");
    assert_eq!(got, Some(want));
}

#[tokio::test]
#[ignore = "live network; see module docs"]
async fn an_unmapped_corridor_is_none_not_an_error() {
    let got = reader()
        .bridge_decimals_for(&[0x5a; 32])
        .await
        .expect("an unmapped corridor is a definitive answer, not a transport fault");
    assert_eq!(got, None);
}
