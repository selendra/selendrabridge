//! The Solana gate program's brain: the send/claim state machine, host-testable.
//!
//! The deployable native program (../../crates/solana-gate) is a thin
//! entrypoint that deserializes a [`crate::instruction::GateInstruction`] and
//! calls these methods against on-chain account state (a PDA config, an SPL
//! vault, the receiver's token account). Here the same transitions run against
//! in-memory maps, so the exact logic that guards funds on-chain is unit-tested
//! and driven end-to-end by real validator signatures (see `tests/e2e.rs`).
//!
//! It mirrors `Gate.sol`: `send` locks + emits, `claim` verifies a threshold of
//! distinct validator signatures and releases exactly once (replay-safe).

use std::collections::{BTreeMap, BTreeSet};

use crate::hash::{self, amount_word, AutoParams};
#[cfg(feature = "recover")]
use crate::verify::verify_threshold;
use crate::verify::VerifyError;

/// 20-byte EVM validator address.
pub type Address = [u8; 20];
/// 32-byte word: debridgeId, submissionId, or a Solana pubkey / token account.
pub type Bytes32 = [u8; 32];

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GateError {
    #[error("amount must be non-zero")]
    ZeroAmount,
    #[error("receiver width must be 20 (EVM) or 32 (Solana), got {0}")]
    BadReceiver(usize),
    #[error("submissionId already executed (replay)")]
    AlreadyExecuted,
    #[error("no local token registered for this debridgeId")]
    UnknownAsset,
    #[error("gate vault has insufficient liquidity: have {have}, need {need}")]
    InsufficientLiquidity { have: u64, need: u64 },
    #[error(transparent)]
    Verify(#[from] VerifyError),
}

/// A `Sent` event — the off-chain mirror of a source-side transfer, identical in
/// shape to the EVM `Sent` (so one validator recompute path serves both VMs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sent {
    pub submission_id: Bytes32,
    pub debridge_id: Bytes32,
    pub amount: u64,
    /// Wire scale `amount` is denominated in — inside the id (H-2).
    pub bridge_decimals: u8,
    pub chain_id_from: u64,
    pub chain_id_to: u64,
    pub receiver: Vec<u8>,
    pub nonce: u64,
    pub native_sender: Vec<u8>,
    pub auto: Option<AutoParams>,
}

/// A `Claimed` event — funds released on this chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claimed {
    pub submission_id: Bytes32,
    pub debridge_id: Bytes32,
    pub receiver: Bytes32,
    pub amount: u64,
}

/// In-memory model of a deployed Solana gate's account state.
#[derive(Clone, Debug)]
pub struct SolanaGate {
    /// This gate's chain id (Solana). `chainIdTo` for incoming, `chainIdFrom` for outgoing.
    pub chain_id: u64,
    /// Deployment generation, folded into every submissionId. Must match the EVM
    /// gates of the same mesh or no id agrees across chains.
    pub bridge_domain: Bytes32,
    /// Active validator set — the same EVM addresses the EVM gate trusts.
    validators: BTreeSet<Address>,
    /// Signatures required to release funds.
    pub threshold: u32,
    /// Source-side per-target-chain monotonic nonce.
    nonce_to: BTreeMap<u64, u64>,
    /// Replay guard: a submissionId may execute at most once.
    // Only read by `claim`, which needs the `recover` feature.
    #[cfg_attr(not(feature = "recover"), allow(dead_code))]
    executed: BTreeSet<Bytes32>,
    /// Asset registry: which local SPL mint backs a debridgeId here.
    token_of: BTreeMap<Bytes32, Bytes32>,
    /// Pre-funded liquidity the gate vault holds per debridgeId (SPL vault balance).
    vault: BTreeMap<Bytes32, u64>,
    /// Modeled SPL token accounts: recipient pubkey -> balance (claim credits here).
    pub token_accounts: BTreeMap<Bytes32, u64>,
}

impl SolanaGate {
    pub fn new(
        chain_id: u64,
        bridge_domain: Bytes32,
        validators: &[Address],
        threshold: u32,
    ) -> Self {
        assert!(threshold > 0, "threshold must be > 0");
        assert!(
            threshold as usize <= validators.len(),
            "threshold must be <= validator count"
        );
        Self {
            chain_id,
            bridge_domain,
            validators: validators.iter().copied().collect(),
            threshold,
            nonce_to: BTreeMap::new(),
            executed: BTreeSet::new(),
            token_of: BTreeMap::new(),
            vault: BTreeMap::new(),
            token_accounts: BTreeMap::new(),
        }
    }

    /// Register the local SPL mint backing a debridgeId and (for the target side)
    /// pre-fund the vault with releasable liquidity.
    pub fn register_asset(&mut self, debridge_id: Bytes32, local_mint: Bytes32, prefund: u64) {
        self.token_of.insert(debridge_id, local_mint);
        *self.vault.entry(debridge_id).or_insert(0) += prefund;
    }

    pub fn is_validator(&self, a: &Address) -> bool {
        self.validators.contains(a)
    }

    pub fn nonce_to(&self, chain_id_to: u64) -> u64 {
        self.nonce_to.get(&chain_id_to).copied().unwrap_or(0)
    }

    pub fn vault_balance(&self, debridge_id: &Bytes32) -> u64 {
        self.vault.get(debridge_id).copied().unwrap_or(0)
    }

    // -- source side: lock + emit ------------------------------------------

    /// Lock `amount` of the asset and produce a `Sent` for the validators.
    /// `receiver` is a 20-byte EVM address for Solana→EVM.
    #[allow(clippy::too_many_arguments)]
    pub fn send(
        &mut self,
        debridge_id: Bytes32,
        amount: u64,
        bridge_decimals: u8,
        chain_id_to: u64,
        receiver: Vec<u8>,
        native_sender: Vec<u8>,
        auto: Option<AutoParams>,
    ) -> Result<Sent, GateError> {
        if amount == 0 {
            return Err(GateError::ZeroAmount);
        }
        if receiver.len() != 20 && receiver.len() != 32 {
            return Err(GateError::BadReceiver(receiver.len()));
        }

        let nonce = self.nonce_to(chain_id_to);
        let submission_id = self.id_for(
            &debridge_id,
            amount,
            bridge_decimals,
            self.chain_id,
            chain_id_to,
            nonce,
            &receiver,
            auto.as_ref(),
        );

        // effects before "interaction": reserve the nonce, then lock into the vault.
        self.nonce_to.insert(chain_id_to, nonce + 1);
        *self.vault.entry(debridge_id).or_insert(0) += amount;

        Ok(Sent {
            submission_id,
            debridge_id,
            amount,
            bridge_decimals,
            chain_id_from: self.chain_id,
            chain_id_to,
            receiver,
            nonce,
            native_sender,
            auto,
        })
    }

    // -- target side: verify + execute (replay-safe) -----------------------

    /// Verify a threshold of validator signatures and release funds once.
    /// `receiver` is a 32-byte Solana token account for EVM→Solana.
    #[allow(clippy::too_many_arguments)]
    /// Requires the `recover` feature: verifying a quorum means recovering
    /// signer addresses, which needs k256 (see the note in Cargo.toml).
    #[cfg(feature = "recover")]
    pub fn claim(
        &mut self,
        debridge_id: Bytes32,
        amount: u64,
        bridge_decimals: u8,
        chain_id_from: u64,
        nonce: u64,
        receiver: Vec<u8>,
        auto: Option<AutoParams>,
        signatures: &[Vec<u8>],
    ) -> Result<Claimed, GateError> {
        let submission_id = self.id_for(
            &debridge_id,
            amount,
            bridge_decimals,
            chain_id_from,
            self.chain_id,
            nonce,
            &receiver,
            auto.as_ref(),
        );

        if self.executed.contains(&submission_id) {
            return Err(GateError::AlreadyExecuted);
        }

        // Same signatures, same order rule as Gate.sol::_verifySignatures.
        let validators = &self.validators;
        verify_threshold(
            &submission_id,
            signatures,
            |a| validators.contains(a),
            self.threshold,
        )?;

        // effects before interaction
        self.executed.insert(submission_id);

        if !self.token_of.contains_key(&debridge_id) {
            return Err(GateError::UnknownAsset);
        }
        let have = self.vault_balance(&debridge_id);
        if have < amount {
            return Err(GateError::InsufficientLiquidity { have, need: amount });
        }
        let to = to_pubkey(&receiver)?;
        *self.vault.get_mut(&debridge_id).unwrap() -= amount;
        *self.token_accounts.entry(to).or_insert(0) += amount;

        Ok(Claimed {
            submission_id,
            debridge_id,
            receiver: to,
            amount,
        })
    }

    /// Recompute a submissionId without executing (id equivalence checks).
    #[allow(clippy::too_many_arguments)]
    pub fn id_for(
        &self,
        debridge_id: &Bytes32,
        amount: u64,
        bridge_decimals: u8,
        chain_id_from: u64,
        chain_id_to: u64,
        nonce: u64,
        receiver: &[u8],
        auto: Option<&AutoParams>,
    ) -> Bytes32 {
        let amt = amount_word(amount as u128);
        match auto {
            None => hash::submission_id(
                &self.bridge_domain,
                debridge_id,
                bridge_decimals,
                &amt,
                chain_id_from,
                chain_id_to,
                nonce,
                receiver,
            ),
            Some(a) => hash::submission_id_with_auto(
                &self.bridge_domain,
                debridge_id,
                bridge_decimals,
                &amt,
                chain_id_from,
                chain_id_to,
                nonce,
                receiver,
                a,
            ),
        }
    }
}

/// Read a 32-byte Solana pubkey/token account from `receiver`.
// Only used by `claim`, which needs the `recover` feature.
#[cfg_attr(not(feature = "recover"), allow(dead_code))]
fn to_pubkey(receiver: &[u8]) -> Result<Bytes32, GateError> {
    if receiver.len() != 32 {
        return Err(GateError::BadReceiver(receiver.len()));
    }
    let mut p = [0u8; 32];
    p.copy_from_slice(receiver);
    Ok(p)
}
