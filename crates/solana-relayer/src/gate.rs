//! The Solana gate's wire surface, shared by every binary in this crate.
//!
//! This crate cannot depend on `solana-gate` (it pins an older `solana-program`
//! than `solana-client` resolves) or on `bridge-core` (alloy's `zeroize ^1.5`
//! cannot coexist with solana-client's `<1.4`), so the gate's account layout and
//! its keccak digest domains are mirrored here. They are mirrored ONCE: the
//! relayer, its claim submitter and `gate-admin` all read the same config
//! account and sign the same digests, and three private copies is exactly how
//! the `bridge_domain` insertion silently broke two of them.

use tracing::warn;

/// `BridgeHash` domain prefixes. A transfer signature must never authorise a
/// burn, nor a cancel a payout, so each digest lives in its own keccak domain —
/// mirrored byte-for-byte from `solana-gate` and `BridgeHash.sol`.
pub const CANCEL_PREFIX: u64 = 2;
pub const REFUND_PREFIX: u64 = 3;

/// Marker bytes the gate writes into the `["executed", id]` PDA.
pub const MARKER_CLAIMED: u8 = 1;
pub const MARKER_CANCELLED: u8 = 2;

/// A `u64` left-padded into a 32-byte big-endian word, as Solidity's
/// `abi.encodePacked(uint256(x))` produces.
fn be32(v: u64) -> [u8; 32] {
    let mut o = [0u8; 32];
    o[24..].copy_from_slice(&v.to_be_bytes());
    o
}

/// `keccak(prefix ‖ submissionId)` — the digest a validator signs for a
/// cancel/refund attestation.
pub fn domain_id(prefix: u64, submission_id: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&be32(prefix));
    buf.extend_from_slice(submission_id);
    bridge_solana::hash::keccak(&buf)
}

/// A Borsh mirror of `solana_gate::Config`, in the program's field order, up to
/// and including `paused`.
///
/// It is a STRUCT, deliberately, and not a set of byte offsets. An earlier
/// version sliced `validators` from byte 64 on the assumption that `guardian`
/// followed `owner` directly. When `bridge_domain` was inserted between them
/// every offset shifted by 32, and the decoder began reading the validator count
/// out of the middle of `guardian` — which on a real config is the default
/// pubkey, so it decoded as "zero validators, threshold zero" and errored
/// nowhere. The claim submitter then filtered away every signature it had.
///
/// It is a PREFIX, also deliberately: the account continues with capacity fields
/// and the corridor nonce map, which the hot paths do not need and which may
/// grow. Readers that want them deserialize [`ConfigTail`] from the same cursor.
///
/// Field ORDER is the wire format — keep it identical to the program's struct.
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshDeserialize)]
pub struct ConfigView {
    pub owner: [u8; 32],
    pub bridge_domain: [u8; 32],
    pub guardian: [u8; 32],
    pub validators: Vec<[u8; 20]>,
    pub threshold: u32,
    pub chain_id: u64,
    pub paused: bool,
}

/// The rest of `solana_gate::Config`, after [`ConfigView`]. Read only by
/// `gate-admin show`, which reports capacity and corridor state.
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshDeserialize)]
pub struct ConfigTail {
    pub max_validators: u32,
    pub max_corridors: u32,
    pub nonce_to: Vec<(u64, u64)>,
    /// H-5: is the asset registry final? Until it is, `claim` releases nothing
    /// and a new binding needs no timelock. Appended to the program's `Config`,
    /// so a gate deployed before H-5 reads the zero padding past its stored body
    /// — `false`, `0` — which is the fail-closed reading in both cases.
    pub sealed: bool,
    /// H-5: when the instant-registration phase ends on its own. ZERO MEANS
    /// EXPIRED, not "no deadline".
    pub setup_deadline: i64,
}

/// Decode the leading fields of the gate's `Config` account, returning the
/// cursor positioned at [`ConfigTail`].
///
/// `deserialize`, not `try_from_slice`: the account is SIZED for its
/// `max_validators`/`max_corridors` capacity, so real data is followed by unused
/// padding that `try_from_slice` would reject as "not all bytes read".
pub fn decode_config_view<'a>(data: &mut &'a [u8]) -> anyhow::Result<ConfigView> {
    <ConfigView as borsh::BorshDeserialize>::deserialize(data)
        .map_err(|e| anyhow::anyhow!("config account does not match the expected layout: {e}"))
}

/// The subset of the on-chain `Config` the submit paths need: who may sign, and
/// how many signatures constitute a quorum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateConfig {
    pub validators: Vec<[u8; 20]>,
    pub threshold: u32,
}

/// Decode the gate's `Config` account into the quorum parameters.
pub fn decode_gate_config(data: &[u8]) -> anyhow::Result<GateConfig> {
    let view = decode_config_view(&mut &data[..])?;

    // An initialized gate ALWAYS has at least one validator — `init` refuses an
    // empty set. So decoding to none is never a real gate state; it is layout
    // drift, and it is the specific failure that must not pass silently, because
    // an empty validator set filters every signature away and is indistinguishable
    // from "nobody has signed yet".
    if view.validators.is_empty() {
        anyhow::bail!(
            "config decoded with an EMPTY validator set — the account layout has drifted \
             from this decoder; refusing to run with a filter that drops every signature"
        );
    }
    Ok(GateConfig { validators: view.validators, threshold: view.threshold })
}

/// The SPL token program id, hardcoded to avoid pulling `spl-token` in.
pub const SPL_TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

/// The BPF upgradeable loader — `init` proves the caller is the program's
/// upgrade authority, which means reading the loader's ProgramData account.
pub const BPF_LOADER_UPGRADEABLE: &str = "BPFLoaderUpgradeab1e11111111111111111111111";

/// Compute units to request for an instruction against a gate with `validators`
/// registered signers.
///
/// ~25k CU per `secp256k1_recover`, plus headroom for keccak, Borsh
/// deserialization, marker creation and the SPL transfer. Clamped to Solana's
/// 1.4M per-transaction maximum; requesting more is rejected outright.
pub fn compute_budget_for(validators: usize) -> u32 {
    const PER_SIGNATURE: u32 = 30_000;
    const OVERHEAD: u32 = 120_000;
    const MAX: u32 = 1_400_000;
    OVERHEAD.saturating_add(PER_SIGNATURE.saturating_mul(validators as u32)).min(MAX)
}

/// Parse a commitment level by name, defaulting to `processed` for anything
/// unrecognized (the config layer is what enforces `finalized` where it matters).
pub fn commitment(name: &str) -> solana_sdk::commitment_config::CommitmentConfig {
    use solana_sdk::commitment_config::CommitmentConfig;
    match name {
        "finalized" => CommitmentConfig::finalized(),
        "confirmed" => CommitmentConfig::confirmed(),
        other => {
            if other != "processed" {
                warn!(commitment = other, "unrecognized commitment level; using `processed`");
            }
            CommitmentConfig::processed()
        }
    }
}

// --- hex helpers ----------------------------------------------------------

/// Decode `0x`-optional hex. An empty string is an empty byte string, not an error.
pub fn hex_bytes(s: &str) -> anyhow::Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.is_empty() {
        return Ok(Vec::new());
    }
    Ok(hex::decode(s)?)
}

/// Decode `0x`-optional hex that must be exactly 32 bytes (a submissionId or a
/// debridgeId).
pub fn hex32(s: &str) -> anyhow::Result<[u8; 32]> {
    hex_bytes(s)?.try_into().map_err(|_| anyhow::anyhow!("expected 32 bytes, got {s:?}"))
}

/// Decode `0x`-optional hex that must be exactly 20 bytes (an EVM address).
pub fn hex20(s: &str) -> anyhow::Result<[u8; 20]> {
    hex_bytes(s)?.try_into().map_err(|_| anyhow::anyhow!("expected 20 bytes, got {s:?}"))
}

// --- signing --------------------------------------------------------------

/// 65-byte `r||s||v` EIP-191 signature over `digest32`, matching what the EVM
/// validator produces and what `Gate._verifySignatures` accepts.
///
/// One definition for the transfer, cancel and refund domains alike — they
/// differ only in which digest is handed in, and a divergent encoding here would
/// recover to a different address and be silently dropped as "not a validator".
pub fn sign(secret: &libsecp256k1::SecretKey, digest32: &[u8; 32]) -> String {
    let digest = bridge_solana::verify::eth_signed_digest(digest32);
    let (sig, recid) = libsecp256k1::sign(&libsecp256k1::Message::parse(&digest), secret);
    let mut out = sig.serialize().to_vec();
    out.push(recid.serialize() + 27);
    format!("0x{}", hex::encode(out))
}

/// The 20-byte EVM address of a secp256k1 public key —
/// `keccak(uncompressed_pubkey[1..])[12..]`.
pub fn address_of(public: &libsecp256k1::PublicKey) -> [u8; 20] {
    let hash = bridge_solana::hash::keccak(&public.serialize()[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

/// This signer's EVM address, `0x`-prefixed — the `signer` field the sig-store
/// records a signature under.
pub fn evm_address(secret: &libsecp256k1::SecretKey) -> String {
    let public = libsecp256k1::PublicKey::from_secret_key(secret);
    format!("0x{}", hex::encode(address_of(&public)))
}

/// Recover the EVM address a signature belongs to, over an already-EIP-191
/// digest. `None` for anything that will not recover — such a signature could
/// only pad the array toward the gate's length cap (finding H-1).
pub fn recovered_address(digest: &[u8; 32], sig65: &[u8]) -> Option<[u8; 20]> {
    if sig65.len() != 65 {
        return None;
    }
    let recid = libsecp256k1::RecoveryId::parse(sig65[64].checked_sub(27)?).ok()?;
    let sig = libsecp256k1::Signature::parse_standard_slice(&sig65[..64]).ok()?;
    let public = libsecp256k1::recover(&libsecp256k1::Message::parse(digest), &sig, &recid).ok()?;
    Some(address_of(&public))
}

/// Size of the pre-decimals `["asset", id]` body: `debridge_id + mint + vault`.
/// Mirrors `solana_gate::LEGACY_ASSET_CONFIG_LEN`; the program still accepts
/// such a record (at 96 or 97 bytes) and so must every client that reads one.
const LEGACY_ASSET_LEN: usize = 32 * 3;

/// The vault an `["asset", debridge_id]` record binds, decoded through the shared
/// Borsh mirror (`bridge_solana::account::AssetAccount`) rather than sliced at
/// hardcoded byte offsets — the pattern that silently broke the config reads when
/// `bridge_domain` was inserted.
///
/// Also refuses what the old `data[64..96]` slice accepted: an account the
/// program does not own, and a record for a different `debridge_id`. The program
/// re-checks the binding on-chain; this stops the submitter from paying fees to
/// learn it.
pub fn asset_vault(
    owner_is_program: bool,
    data: &[u8],
    debridge_id: &[u8; 32],
) -> anyhow::Result<[u8; 32]> {
    anyhow::ensure!(owner_is_program, "asset account is not owned by the gate program");
    let (recorded_id, vault) = if data.len() == LEGACY_ASSET_LEN || data.len() == LEGACY_ASSET_LEN + 1 {
        #[derive(borsh::BorshDeserialize)]
        struct Legacy {
            debridge_id: [u8; 32],
            _mint: [u8; 32],
            vault: [u8; 32],
        }
        let l: Legacy = bridge_solana::account::decode(&data[..LEGACY_ASSET_LEN])
            .ok_or_else(|| anyhow::anyhow!("legacy asset account does not decode"))?;
        (l.debridge_id, l.vault)
    } else {
        let a: bridge_solana::account::AssetAccount = bridge_solana::account::decode(data)
            .ok_or_else(|| anyhow::anyhow!("asset account does not decode ({} bytes)", data.len()))?;
        (a.debridge_id, a.vault)
    };
    anyhow::ensure!(
        &recorded_id == debridge_id,
        "asset account records debridge_id 0x{}, not the requested 0x{}",
        hex::encode(recorded_id),
        hex::encode(debridge_id)
    );
    Ok(vault)
}

/// `10^(local - bridge)` for an `["asset", id]` record: the mint units per wire
/// unit. `1` for a legacy record, exactly as the program reads one; `None` when
/// the record does not decode or its decimals are invalid.
pub fn asset_bridge_unit(data: &[u8]) -> Option<u64> {
    if data.len() == LEGACY_ASSET_LEN || data.len() == LEGACY_ASSET_LEN + 1 {
        return Some(1);
    }
    bridge_solana::account::decode::<bridge_solana::account::AssetAccount>(data)?.bridge_unit()
}

#[cfg(test)]
mod tests {
    use super::{asset_bridge_unit, asset_vault};

    #[test]
    fn asset_bridge_unit_matches_the_program() {
        let mut data = asset_bytes([1; 32], [2; 32], [3; 32], &[6, 9]);
        data.resize(130, 0);
        assert_eq!(asset_bridge_unit(&data), Some(1_000));
        assert_eq!(asset_bridge_unit(&data[..96]), Some(1), "legacy bridged 1:1");
        assert_eq!(asset_bridge_unit(&asset_bytes([1; 32], [2; 32], [3; 32], &[9, 6])), None);
    }

    fn asset_bytes(id: [u8; 32], mint: [u8; 32], vault: [u8; 32], tail: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&id);
        v.extend_from_slice(&mint);
        v.extend_from_slice(&vault);
        v.extend_from_slice(tail);
        v
    }

    /// The current layout, with the program's slack, decodes to its vault.
    #[test]
    fn asset_vault_reads_the_current_layout() {
        let mut data = asset_bytes([1; 32], [2; 32], [3; 32], &[6, 9]);
        data.resize(98 + 32, 0);
        assert_eq!(asset_vault(true, &data, &[1; 32]).unwrap(), [3; 32]);
    }

    /// Records written before the decimals fields (96 or 97 bytes) are still live
    /// on-chain and the program still honours them.
    #[test]
    fn asset_vault_reads_legacy_records() {
        for tail in [&[][..], &[0u8][..]] {
            let data = asset_bytes([1; 32], [2; 32], [3; 32], tail);
            assert_eq!(asset_vault(true, &data, &[1; 32]).unwrap(), [3; 32]);
        }
    }

    /// The hardcoded `data[64..96]` slice accepted the first two of these.
    #[test]
    fn asset_vault_refuses_what_the_offset_slice_accepted() {
        let data = asset_bytes([1; 32], [2; 32], [3; 32], &[6, 6]);
        assert!(asset_vault(false, &data, &[1; 32]).is_err(), "foreign owner");
        assert!(asset_vault(true, &data, &[9; 32]).is_err(), "another asset's record");
        assert!(asset_vault(true, &data[..97 - 20], &[1; 32]).is_err(), "truncated");
    }

    use super::*;

    /// Pinned against `BridgeHash.getCancelId`/`getRefundId` ground truth — the
    /// same constants `solana-gate`'s own suite asserts. If these drift, this
    /// validator signs digests no gate will ever accept and refunds silently
    /// never reach quorum.
    #[test]
    fn digests_match_bridgehash_ground_truth() {
        let id = [0x11u8; 32];
        assert_eq!(
            hex::encode(domain_id(CANCEL_PREFIX, &id)),
            "5f53d5916a01e246eeb5fd7d9e96634532fe35b576656d6244780290984a5eee"
        );
        assert_eq!(
            hex::encode(domain_id(REFUND_PREFIX, &id)),
            "3457405ce2152b6317347888618027bd5912e3026e48a5654384dbcb99a45b6e"
        );
    }

    /// The three domains must be three different messages, or a signature that
    /// only ever meant "burn this" could authorise a payout.
    #[test]
    fn the_domains_are_separated() {
        let id = [0x11u8; 32];
        let c = domain_id(CANCEL_PREFIX, &id);
        let r = domain_id(REFUND_PREFIX, &id);
        assert_ne!(c, r);
        assert_ne!(c, id, "a transfer signature must not authorise a burn");
        assert_ne!(r, id, "a transfer signature must not authorise a payout");
    }

    /// A signature this crate produces must recover to the address it reports —
    /// the property every quorum filter depends on, across both binaries.
    #[test]
    fn a_signature_recovers_to_the_reported_address() {
        let secret = libsecp256k1::SecretKey::parse(&[7u8; 32]).unwrap();
        let digest = domain_id(CANCEL_PREFIX, &[0x22u8; 32]);
        let sig = hex_bytes(&sign(&secret, &digest)).unwrap();

        let eip191 = bridge_solana::verify::eth_signed_digest(&digest);
        let recovered = recovered_address(&eip191, &sig).expect("recovers");
        assert_eq!(format!("0x{}", hex::encode(recovered)), evm_address(&secret));
    }

    #[test]
    fn hex_helpers_accept_both_prefixed_and_bare() {
        assert_eq!(hex32(&format!("0x{}", "11".repeat(32))).unwrap(), [0x11u8; 32]);
        assert_eq!(hex32(&"11".repeat(32)).unwrap(), [0x11u8; 32]);
        assert!(hex32("0x1234").is_err(), "a short id must not be accepted");
        assert_eq!(hex_bytes("0x").unwrap(), Vec::<u8>::new());
    }

    /// The layout guard: a config whose bytes stop before `paused` must ERROR,
    /// not decode to plausible zeros. This is the shape of the drift that made
    /// the submitter report "zero validators" while looking healthy.
    #[test]
    fn a_truncated_config_is_an_error_not_zeros() {
        let mut bytes = vec![0u8; 96]; // owner ‖ bridge_domain ‖ guardian only
        bytes.extend_from_slice(&1u32.to_le_bytes()); // claims one validator...
        assert!(decode_gate_config(&bytes).is_err(), "truncated config must not decode");
    }

    /// An initialized gate always has validators, so an empty set is drift, not
    /// state — and it must be loud, because it silently filters every signature.
    #[test]
    fn an_empty_validator_set_is_rejected() {
        let mut bytes = vec![0u8; 96];
        bytes.extend_from_slice(&0u32.to_le_bytes()); // validators: []
        bytes.extend_from_slice(&2u32.to_le_bytes()); // threshold
        bytes.extend_from_slice(&7u64.to_le_bytes()); // chain_id
        bytes.push(0); // paused
        let err = decode_gate_config(&bytes).unwrap_err().to_string();
        assert!(err.contains("EMPTY validator set"), "got: {err}");
    }

    #[test]
    fn compute_budget_scales_and_is_clamped() {
        assert!(compute_budget_for(3) > compute_budget_for(1));
        assert_eq!(compute_budget_for(1000), 1_400_000, "must not exceed Solana's per-tx max");
    }
}
