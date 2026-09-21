//! Allowlists — which tokens and which source→target chain pairs may bridge.
//!
//! These types are the on-wire shape shared by the Postgres-backed `sig-store`
//! (server) and the `RemoteStore` HTTP client the validator/keeper use to fetch
//! the lists. The DB (`bridge-db`) is the source of truth; everyone else mirrors
//! it into an in-memory [`Allowlist`] for fast membership checks.
//!
//! ## Semantics: the allowlist is OPT-IN
//!
//! An *empty* token list means "no token restriction configured" — every token
//! is allowed. The first row you add flips it to deny-by-default: only listed
//! tokens pass. The chain list behaves the same way, independently. This keeps
//! every existing end-to-end script working until an operator deliberately seeds
//! the lists, then enforcement turns on with no code change.
//!
//! The sharp edge is the way back out, which is why `bridge_db` refuses to
//! delete the LAST row of either list. Pruning row by row would otherwise cross
//! from deny-by-default to allow-everything the moment the final row went — no
//! error, no log, and both enforcement points (the validator before it signs,
//! the keeper before it claims) turned off at once, since they build their view
//! from the same fetch. Turning enforcement off stays possible; it just has to
//! be done to the table, not stumbled into one DELETE at a time.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// One whitelisted ERC-20, keyed by `(chain_id, token)`. `debridge_id` is the
/// `keccak256(chainId, token)` the Gate emits in `Sent` — precomputed so the
/// validator/keeper can match an event by a single hash lookup.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AllowedToken {
    pub chain_id: u64,
    /// `0x`-prefixed token address (lowercased).
    pub token: String,
    /// `0x`-prefixed `keccak256(abi.encodePacked(chain_id, token))` (lowercased).
    pub debridge_id: String,
    #[serde(default)]
    pub symbol: Option<String>,
}

/// One whitelisted directed chain pair: transfers from `chain_id_from` to
/// `chain_id_to` are permitted.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AllowedChain {
    pub chain_id_from: u64,
    pub chain_id_to: u64,
}

/// Request body to add a token to the allowlist; the `debridge_id` is derived
/// server-side so a caller can't pin a token onto the wrong hash.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddTokenRequest {
    pub chain_id: u64,
    pub token: String,
    #[serde(default)]
    pub symbol: Option<String>,
}

/// Request body to mark a submission claimed (keeper → sig-store).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimedRequest {
    /// `0x`-prefixed claim transaction hash on the target chain.
    pub claim_tx: String,
}

/// Request body for an OBSERVED destination cancel (observer → sig-store,
/// `POST /submissions/:id/observed/cancelled`, `Indexer` scope).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObservedCancelledRequest {
    /// The destination-chain cancel tx (EVM hash, or the Solana signature /
    /// marker address when no signature is available).
    pub cancel_tx: String,
}

/// Request body for an OBSERVED source refund (observer → sig-store,
/// `POST /submissions/:id/observed/refunded`, `Indexer` scope).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObservedRefundedRequest {
    pub refund_tx: String,
}

/// Request body to post a cancel/refund attestation (validator → sig-store).
/// The signature is verified against `kind`'s own digest server-side, so a
/// mislabelled or replayed signature is rejected rather than miscounted.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationRequest {
    /// `cancel` | `refund`.
    pub kind: String,
    pub signer: String,
    pub signature: String,
}


/// A submission as it appears in the transaction-history view: the transfer
/// parameters plus its lifecycle status and timing. Distinct from
/// [`crate::store::SubmissionRecord`] (which carries the raw signatures the
/// keeper needs) so history queries stay cheap and read-only.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubmissionHistory {
    pub submission_id: String,
    pub debridge_id: String,
    pub amount: String,
    pub chain_id_from: u64,
    pub chain_id_to: u64,
    pub nonce: u64,
    pub receiver: String,
    /// `signed` once the transfer has been observed (regardless of signature
    /// count — see the indexer, which inserts on `Sent` before any validator has
    /// acted) or at least one validator has attested; `claimed` after a keeper
    /// executes `claim()` on the target chain.
    pub status: String,
    /// Target-chain claim tx hash, once claimed.
    pub claim_tx: Option<String>,
    pub signature_count: i64,
    /// RFC-3339 timestamps.
    pub created_at: String,
    pub updated_at: String,
    /// True once this transfer has entered the refund lifecycle at all — i.e.
    /// `refund_status != "none"`. A nomination, not an authorisation.
    #[serde(default)]
    pub stuck: bool,
    /// Refund lifecycle: `none` | `eligible` | `cancelled` | `refunded`.
    ///
    /// `eligible` — past the timeout and still unclaimed, so validators may
    /// attest a cancel. `cancelled` — burned on the destination chain, which is
    /// what unlocks refund attestations. `refunded` — funds returned on the
    /// source chain. Cleared back to `none` if a stuck transfer is claimed after
    /// all.
    #[serde(default = "default_refund_status")]
    pub refund_status: String,
    /// Source-chain `Gate.refund` tx hash, once refunded.
    #[serde(default)]
    pub refund_tx: Option<String>,
    /// Destination-chain `Gate.cancel` tx hash, once burned.
    #[serde(default)]
    pub cancel_tx: Option<String>,
    /// The source-chain ERC-20 that was locked (needed to build `Gate.refund`).
    #[serde(default)]
    pub token: Option<String>,
    /// How many validators have attested the destination cancel.
    #[serde(default)]
    pub cancel_signature_count: i64,
    /// How many validators have attested the source refund.
    #[serde(default)]
    pub refund_signature_count: i64,
    /// If this transfer was a `SwapRouter.swapAndBridge` (swap-then-bridge) rather
    /// than a plain bridge send, its swap intent/outcome.
    #[serde(default)]
    pub swap_intent: Option<SwapBridgeInfo>,
    /// The keeper's OWN report of the claim tx it submitted (M-1, audit
    /// 2026-09-09). Advisory only: `status`/`claim_tx` above come from the
    /// indexer's on-chain observation, and no queue reads this field. Useful to
    /// spot a keeper that believes it claimed something the chain never saw.
    #[serde(default)]
    pub keeper_claim_tx: Option<String>,
}

fn default_refund_status() -> String {
    "none".to_string()
}

/// One same-chain swap (`SwapPool.Swapped`), mirrored into the DB by the indexer.
/// Same-chain swaps are atomic (revert on failure), so unlike a bridge transfer
/// there is no "stuck" state to track here — only completed swaps are ever emitted.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SwapRecord {
    pub chain_id: u64,
    /// `0x`-prefixed transaction hash.
    pub tx_hash: String,
    pub log_index: i64,
    pub sender: String,
    pub receiver: String,
    pub token_in: String,
    pub token_out: String,
    /// decimal strings (uint256)
    pub amount_in: String,
    pub amount_out: String,
    pub block_number: u64,
    /// RFC-3339 timestamp.
    pub created_at: String,
}

/// The swap intent (source leg) and outcome (destination leg) of a
/// `SwapRouter.swapAndBridge` transfer, keyed by the bridge `submissionId`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SwapBridgeInfo {
    pub token_in: String,
    pub amount_in: String,
    pub stable_out: String,
    pub final_token: String,
    pub final_receiver: String,
    /// Set once the destination leg has run (`Finalized`/`FinalizeFallback`).
    pub finalize_tx: Option<String>,
    pub finalize_amount_out: Option<String>,
    /// True if the destination swap failed and the router fell back to
    /// delivering the stable itself (`FinalizeFallback`).
    pub finalize_fallback: Option<bool>,
    pub finalized_at: Option<String>,
}

/// In-memory mirror of the allowlists, built from the fetched rows for O(1)
/// membership checks on the hot path (validator signing / keeper claiming).
#[derive(Clone, Debug, Default)]
pub struct Allowlist {
    /// Allowed `debridge_id`s (lowercased `0x`-hex).
    debridge_ids: HashSet<String>,
    /// Allowed `(chain_id_from, chain_id_to)` pairs.
    chains: HashSet<(u64, u64)>,
}

impl Allowlist {
    /// Build from the lists fetched from the store.
    pub fn from_parts(tokens: &[AllowedToken], chains: &[AllowedChain]) -> Self {
        Allowlist {
            debridge_ids: tokens.iter().map(|t| t.debridge_id.to_ascii_lowercase()).collect(),
            chains: chains.iter().map(|c| (c.chain_id_from, c.chain_id_to)).collect(),
        }
    }

    /// Opt-in semantics: an empty token list allows everything; otherwise only
    /// listed `debridge_id`s pass. `debridge_id` is matched case-insensitively.
    pub fn token_allowed(&self, debridge_id: &str) -> bool {
        self.debridge_ids.is_empty() || self.debridge_ids.contains(&debridge_id.to_ascii_lowercase())
    }

    /// Opt-in semantics: an empty chain list allows every pair; otherwise only
    /// listed `(from, to)` pairs pass.
    pub fn chain_allowed(&self, from: u64, to: u64) -> bool {
        self.chains.is_empty() || self.chains.contains(&(from, to))
    }

    /// True when neither list has an entry — "allow everything".
    pub fn is_empty(&self) -> bool {
        self.debridge_ids.is_empty() && self.chains.is_empty()
    }

    fn has_token(&self, debridge_id: &str) -> bool {
        self.debridge_ids.contains(&debridge_id.to_ascii_lowercase())
    }

    fn has_chain(&self, from: u64, to: u64) -> bool {
        self.chains.contains(&(from, to))
    }
}

/// What the store served when asked for the allowlists.
///
/// The three cases used to collapse into `Option<Allowlist>`, and that is what
/// M-5 was: an empty list and a present one were both `Some`, and the empty one
/// means "allow everything". The store is explicitly untrusted (threat model
/// (b)), so whoever controls it could answer `200 []` and switch off the one
/// content-level control standing between a malicious corridor and validator
/// signatures — silently, at every validator and the keeper at once, with no
/// error anywhere because nothing had failed.
#[derive(Clone, Debug)]
pub enum AllowlistView {
    /// No central allowlist exists at all: the legacy file-backed store keeps
    /// none, so there is nothing to enforce and nothing to switch off.
    NotConfigured,
    /// The store served at least one entry.
    Enforcing(Allowlist),
    /// The store served both lists empty — "allow everything".
    Empty,
}

/// Why a node refuses to act on the allowlist it was served.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AllowlistRefusal {
    #[error(
        "the store served an EMPTY allowlist while `[allowlist] require = true`: that means \
         ALLOW EVERYTHING, so it is indistinguishable from the kill-switch being turned off \
         by whoever controls the store. Refusing until it serves entries again (add one back, \
         or set `require = false` to opt out deliberately)."
    )]
    Empty,
    #[error(
        "`[allowlist] require = true` but this store keeps no central allowlist (file-backed \
         store). Point `[store] url` at a sig-store, or set `require = false`."
    )]
    NotConfigured,
    #[error(
        "the store's allowlist is missing pinned entry {0} — the local config says it must be \
         there, so the served list has been truncated or replaced. Refusing to act on it."
    )]
    MissingPin(String),
}

/// The locally-configured expectations an allowlist must meet before this node
/// will act on it.
///
/// `require` alone closes the kill-switch hole. The pins go further and are what
/// the audit asked for: a corridor this operator KNOWS is live, written down
/// locally, so a store that quietly drops entries (rather than emptying the
/// list) is caught too. Pinning implies `require`: pinning entries while still
/// accepting an empty list would be a contradiction.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowlistPolicy {
    /// Refuse to sign/claim when the store serves an empty or absent allowlist.
    #[serde(default)]
    pub require: bool,
    /// `debridge_id`s that must appear in the served token list.
    #[serde(default)]
    pub pinned_tokens: Vec<String>,
    /// `(chain_id_from, chain_id_to)` pairs that must appear in the served chain list.
    #[serde(default)]
    pub pinned_chains: Vec<(u64, u64)>,
}

impl AllowlistPolicy {
    /// True when this node insists on an enforced allowlist.
    pub fn required(&self) -> bool {
        self.require || !self.pinned_tokens.is_empty() || !self.pinned_chains.is_empty()
    }

    /// Apply the policy to what the store served.
    ///
    /// `Ok(None)` means "no enforcement" and is the legacy default: an operator
    /// who has not opted in keeps exactly the behaviour they had. `Ok(Some(l))`
    /// means enforce against `l`. `Err` means the node must not act at all this
    /// tick — the served list cannot be trusted, and signing on it anyway is the
    /// failure M-5 describes.
    pub fn check(&self, view: AllowlistView) -> Result<Option<Allowlist>, AllowlistRefusal> {
        match view {
            AllowlistView::NotConfigured => {
                if self.required() {
                    return Err(AllowlistRefusal::NotConfigured);
                }
                Ok(None)
            }
            AllowlistView::Empty => {
                if self.required() {
                    return Err(AllowlistRefusal::Empty);
                }
                Ok(None)
            }
            AllowlistView::Enforcing(list) => {
                for t in &self.pinned_tokens {
                    if !list.has_token(t) {
                        return Err(AllowlistRefusal::MissingPin(t.to_ascii_lowercase()));
                    }
                }
                for (from, to) in &self.pinned_chains {
                    if !list.has_chain(*from, *to) {
                        return Err(AllowlistRefusal::MissingPin(format!("chain pair {from}->{to}")));
                    }
                }
                Ok(Some(list))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "0xaa000000000000000000000000000000000000000000000000000000000000aa";

    fn listed() -> Allowlist {
        Allowlist::from_parts(
            &[AllowedToken {
                chain_id: 1,
                token: "0x1111111111111111111111111111111111111111".into(),
                debridge_id: TOKEN.into(),
                symbol: None,
            }],
            &[AllowedChain { chain_id_from: 1, chain_id_to: 2 }],
        )
    }

    /// M-5. The store is untrusted by design, and `200 []` is not an error — so
    /// the one content-level control between a malicious corridor and a
    /// signature used to switch itself off silently, at every validator and the
    /// keeper at once. An operator who has said the allowlist matters must not
    /// be able to lose it that quietly.
    #[test]
    fn an_empty_served_allowlist_is_refused_when_the_operator_requires_one() {
        let required = AllowlistPolicy { require: true, ..Default::default() };
        assert_eq!(required.check(AllowlistView::Empty).unwrap_err(), AllowlistRefusal::Empty);
        // ...and a store that keeps no allowlist at all is the same hole by
        // another route: point the node at a sig-store, or opt out on purpose.
        assert_eq!(required.check(AllowlistView::NotConfigured).unwrap_err(), AllowlistRefusal::NotConfigured);
        // A populated list is what it asked for.
        assert!(matches!(required.check(AllowlistView::Enforcing(listed())), Ok(Some(_))));
    }

    /// The default must stay exactly as it was: an operator who never opted in
    /// keeps the opt-in semantics, empty list included. Fixing M-5 by making
    /// every empty allowlist fatal would have halted every mesh on upgrade.
    #[test]
    fn the_legacy_default_is_unchanged() {
        let legacy = AllowlistPolicy::default();
        assert!(!legacy.required());
        assert!(matches!(legacy.check(AllowlistView::Empty), Ok(None)), "empty still allows everything");
        assert!(matches!(legacy.check(AllowlistView::NotConfigured), Ok(None)), "file mode still enforces nothing");
        assert!(matches!(legacy.check(AllowlistView::Enforcing(listed())), Ok(Some(_))));
    }

    /// Emptying the list is the loud way to disable enforcement; quietly
    /// dropping entries from it is the quiet one, and `require` alone does not
    /// catch that. A pin is the operator's own copy of a corridor they know is
    /// live.
    #[test]
    fn a_served_list_missing_a_pinned_entry_is_refused() {
        let pinned = AllowlistPolicy { pinned_tokens: vec![TOKEN.to_uppercase()], ..Default::default() };
        // Pinning implies requiring: otherwise the pin would be checked only
        // when the store felt like serving entries at all.
        assert!(pinned.required());
        assert_eq!(pinned.check(AllowlistView::Empty).unwrap_err(), AllowlistRefusal::Empty);
        // Present (case-insensitively, as everywhere else): fine.
        assert!(matches!(pinned.check(AllowlistView::Enforcing(listed())), Ok(Some(_))));

        // Dropped from the served list: refused, and the message names it.
        let other = "0xbb00000000000000000000000000000000000000000000000000000000000000";
        let missing = AllowlistPolicy { pinned_tokens: vec![other.into()], ..Default::default() };
        assert_eq!(missing.check(AllowlistView::Enforcing(listed())).unwrap_err(), AllowlistRefusal::MissingPin(other.into()));

        let chains = AllowlistPolicy { pinned_chains: vec![(9, 9)], ..Default::default() };
        assert!(matches!(chains.check(AllowlistView::Enforcing(listed())), Err(AllowlistRefusal::MissingPin(_))));
        let live = AllowlistPolicy { pinned_chains: vec![(1, 2)], ..Default::default() };
        assert!(matches!(live.check(AllowlistView::Enforcing(listed())), Ok(Some(_))));
    }

    /// The view the backend builds must distinguish the two cases the fix rests
    /// on — a list with entries, and one without.
    #[test]
    fn an_allowlist_knows_whether_it_is_empty() {
        assert!(Allowlist::default().is_empty());
        assert!(!listed().is_empty());
        // Chains alone still count as enforcement.
        let chains_only = Allowlist::from_parts(&[], &[AllowedChain { chain_id_from: 1, chain_id_to: 2 }]);
        assert!(!chains_only.is_empty());
    }
}
