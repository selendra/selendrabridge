//! Host-side mirrors of the gate program's ACCOUNT layouts.
//!
//! The program's own definitions live in `crates/solana-gate`, which cannot be
//! linked here (or by `graphql-api`): its `solana-program` dependency pins
//! `zeroize <1.4`, and alloy needs `^1.5`. So an off-chain reader that wants to
//! know a corridor's nonce or an asset's vault has to decode the bytes itself.
//!
//! A second declaration is a drift risk — the gate's two `Sent` definitions
//! already drifted once, and both sides kept compiling. What keeps this one
//! honest is `tests/account_layout.rs`, which decodes a REAL account captured
//! from the deployed devnet gate and asserts the values it produces are the ones
//! that gate actually holds. A layout change that broke this would fail there,
//! not silently in production.

use borsh::{BorshDeserialize, BorshSerialize};

/// A 32-byte Solana key, as plain bytes so this crate stays free of
/// `solana-program`.
pub type Key = [u8; 32];

/// The gate's `["config"]` account.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct ConfigAccount {
    pub owner: Key,
    /// The deployment generation, hashed into every submissionId.
    pub bridge_domain: [u8; 32],
    pub guardian: Key,
    pub validators: Vec<[u8; 20]>,
    pub threshold: u32,
    pub chain_id: u64,
    pub paused: bool,
    pub max_validators: u32,
    pub max_corridors: u32,
    /// `(chain_id_to, next_nonce)` per governance-registered corridor.
    pub nonce_to: Vec<(u64, u64)>,
    /// H-5: is the asset registry final? An unsealed gate releases nothing, and a
    /// new asset binding on it needs no timelock. Appended to the program's
    /// `Config`, so an account written before H-5 supplies these from its rent
    /// padding — `false` and `0`, which is the fail-closed reading of both.
    pub sealed: bool,
    /// H-5: when the instant-registration phase ends by itself. ZERO MEANS
    /// EXPIRED, not "no deadline".
    pub setup_deadline: i64,
}

impl ConfigAccount {
    /// The next nonce for a destination chain, or `None` when that corridor is
    /// not registered — which is also the program's answer: `send` refuses a
    /// destination governance never approved.
    pub fn nonce(&self, chain_id_to: u64) -> Option<u64> {
        self.nonce_to.iter().find(|(c, _)| *c == chain_id_to).map(|(_, n)| *n)
    }
}

/// The gate's `["asset", debridge_id]` registry entry.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct AssetAccount {
    pub debridge_id: [u8; 32],
    pub mint: Key,
    pub vault: Key,
    /// The asset's mesh-wide bridge decimals: every transfer amount travels in
    /// these (see `solana_gate::AssetConfig`).
    pub bridge_decimals: u8,
    /// The mint's own decimals, cached at registration.
    pub local_decimals: u8,
}

impl AssetAccount {
    /// `10^(local - bridge)`: the smallest mint amount that crosses the bridge.
    pub fn bridge_unit(&self) -> Option<u64> {
        10u64.checked_pow(self.local_decimals.checked_sub(self.bridge_decimals)? as u32)
    }
}

/// The gate's `["vault", vault]` commitment: what a vault's liquidity is (H-5).
///
/// One vault legitimately backs one asset arriving from several source chains, so
/// this pins what they must agree on rather than naming a single `debridgeId`.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct VaultBindingAccount {
    pub mint: Key,
    pub bridge_decimals: u8,
}

/// Decode an account whose trailing bytes are rent padding.
///
/// `try_from_slice` refuses trailing data and every one of these accounts is
/// sized with slack, so the strict form reads a good record as corrupt.
pub fn decode<T: BorshDeserialize>(data: &[u8]) -> Option<T> {
    T::deserialize(&mut &data[..]).ok()
}
