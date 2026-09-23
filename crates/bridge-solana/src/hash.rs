//! The sacred submissionId hash — the Solana-side reproduction.
//!
//! This MUST match, byte-for-byte, `BridgeHash.sol` and `bridge_core`'s
//! `submission_id`. A Solana gate program computes it with the runtime's
//! `keccak` syscall over the same big-endian, `abi.encodePacked`-style layout;
//! here we do it with `sha3::Keccak256`, which produces identical bytes. The
//! cross-chain equivalence test locks this against the shared Foundry fixtures.
//!
//! Every EVM word (`uint256`/`bytes32`) is 32 bytes big-endian. Chain ids and
//! nonces comfortably fit `u64`; `amount` and the auto-params fees can be a full
//! 256-bit word, so those come in already widened to `[u8; 32]`.

use sha3::{Digest, Keccak256};

/// Domain-separating prefix, matching `BridgeHash.SUBMISSION_PREFIX`.
pub const SUBMISSION_PREFIX: u64 = 1;

/// keccak256 of `bytes` (Solana: the `keccak` syscall).
pub fn keccak(bytes: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(bytes);
    h.finalize().into()
}

/// A `u64` as a 32-byte big-endian EVM word.
fn be32(v: u64) -> [u8; 32] {
    let mut o = [0u8; 32];
    o[24..].copy_from_slice(&v.to_be_bytes());
    o
}

/// Optional execution payload attached to a transfer (mirrors `AutoParams`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AutoParams {
    pub execution_fee: [u8; 32],
    pub flags: [u8; 32],
    pub fallback_address: Vec<u8>,
    pub data: Vec<u8>,
    /// Packed source-chain sender (20 bytes for an EVM address, 32 for Solana).
    pub native_sender: Vec<u8>,
}

/// `debridgeId = keccak256(abi.encodePacked(uint256 nativeChainId, address nativeToken))`.
///
/// `native_token` is the 20-byte EVM token address for an EVM-native asset. (An
/// SPL-native asset would register its own debridgeId; the id is just an opaque
/// 32-byte asset key on this chain.)
pub fn debridge_id(native_chain_id: u64, native_token: &[u8; 20]) -> [u8; 32] {
    let mut p = Vec::with_capacity(32 + 20);
    p.extend_from_slice(&be32(native_chain_id));
    p.extend_from_slice(native_token);
    keccak(&p)
}

/// The 9-field packed base of every submissionId, unhashed (matches
/// `BridgeHash.packedSubmission`).
///
/// `bridge_domain` is the deployment generation, and must equal the domain the
/// EVM gates were initialized with. Without it an attestation from a superseded
/// deployment stays valid against a redeployed one.
///
/// `bridge_decimals` is the wire scale `amount` is denominated in (H-2), as the
/// gate that minted the id had the asset registered. A single byte, and the
/// reason a scale mis-registration on either end now produces two ids that never
/// meet instead of a payout off by a power of ten.
#[allow(clippy::too_many_arguments)]
fn packed_submission(
    bridge_domain: &[u8; 32],
    debridge_id: &[u8; 32],
    bridge_decimals: u8,
    amount: &[u8; 32],
    chain_id_from: u64,
    chain_id_to: u64,
    nonce: u64,
    receiver: &[u8],
) -> Vec<u8> {
    let mut p = Vec::with_capacity(32 * 7 + 1 + receiver.len());
    p.extend_from_slice(&be32(SUBMISSION_PREFIX));
    p.extend_from_slice(bridge_domain);
    p.extend_from_slice(debridge_id);
    p.extend_from_slice(&be32(chain_id_from));
    p.extend_from_slice(&be32(chain_id_to));
    p.push(bridge_decimals);
    p.extend_from_slice(amount);
    p.extend_from_slice(receiver);
    p.extend_from_slice(&be32(nonce));
    p
}

/// submissionId for a transfer WITHOUT an execution payload.
#[allow(clippy::too_many_arguments)]
pub fn submission_id(
    bridge_domain: &[u8; 32],
    debridge_id: &[u8; 32],
    bridge_decimals: u8,
    amount: &[u8; 32],
    chain_id_from: u64,
    chain_id_to: u64,
    nonce: u64,
    receiver: &[u8],
) -> [u8; 32] {
    keccak(&packed_submission(
        bridge_domain,
        debridge_id,
        bridge_decimals,
        amount,
        chain_id_from,
        chain_id_to,
        nonce,
        receiver,
    ))
}

/// submissionId for a transfer WITH an execution payload.
#[allow(clippy::too_many_arguments)]
pub fn submission_id_with_auto(
    bridge_domain: &[u8; 32],
    debridge_id: &[u8; 32],
    bridge_decimals: u8,
    amount: &[u8; 32],
    chain_id_from: u64,
    chain_id_to: u64,
    nonce: u64,
    receiver: &[u8],
    auto: &AutoParams,
) -> [u8; 32] {
    let mut p = packed_submission(
        bridge_domain,
        debridge_id,
        bridge_decimals,
        amount,
        chain_id_from,
        chain_id_to,
        nonce,
        receiver,
    );
    p.extend_from_slice(&auto.execution_fee);
    p.extend_from_slice(&auto.flags);
    p.extend_from_slice(&keccak(&auto.fallback_address));
    p.extend_from_slice(&keccak(&auto.data));
    p.extend_from_slice(&keccak(&auto.native_sender));
    keccak(&p)
}

/// Widen a `u64` token amount to the 32-byte word the hash expects.
pub fn amount_word(amount: u128) -> [u8; 32] {
    let mut o = [0u8; 32];
    o[16..].copy_from_slice(&amount.to_be_bytes());
    o
}
