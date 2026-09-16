//! The sig-store wire contract.
//!
//! This duplicates `bridge_core::store::SubmissionRecord` on purpose. That crate
//! depends unconditionally on `alloy-primitives` (it backs the core hashing), and
//! alloy's `zeroize ^1.5` cannot coexist with `solana-client`'s `<1.4` pin — so
//! this process cannot link it at all. What crosses the boundary here is a JSON
//! wire format, not shared logic, and the server re-derives and re-verifies
//! everything it accepts. The real protocol logic still comes from
//! `bridge-solana`, which IS shared.
//!
//! Field names must stay byte-identical to `SubmissionRecord`'s serde names.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// Page size for walking [`Store::refund_candidates`]. Mirrors
/// `bridge_core::backend::REFUND_PAGE`, which this crate cannot import (see the
/// dependency note in Cargo.toml); keep the two in step.
pub const REFUND_PAGE: u64 = 500;

/// Pages walked per tick before deferring the remainder to the next one.
/// Mirrors `bridge_core::backend::MAX_REFUND_PAGES`.
pub const MAX_REFUND_PAGES: u64 = 20;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignerSig {
    pub signer: String,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubmissionRecord {
    pub submission_id: String,
    /// `0x`-prefixed 32-byte deployment domain, read from the gate's `["config"]`
    /// PDA. NOT optional and NOT defaultable here: the store parses it strictly
    /// and rejects the whole submission if it is empty, which is the point — a
    /// record with no domain belongs to no generation and must never be signed
    /// for. Omitting it from this struct is what silently killed the entire
    /// Solana -> EVM direction, since the store's own field IS `#[serde(default)]`
    /// and so accepted the missing key, then failed on the empty value.
    pub bridge_domain: String,
    pub debridge_id: String,
    /// decimal string (uint256 on the EVM side)
    pub amount: String,
    pub chain_id_from: u64,
    pub chain_id_to: u64,
    pub nonce: u64,
    pub receiver: String,
    pub auto_params: String,
    pub native_sender: String,
    #[serde(default)]
    pub token: String,
    pub signatures: Vec<SignerSig>,
    #[serde(default)]
    pub cancel_signatures: Vec<SignerSig>,
    #[serde(default)]
    pub refund_signatures: Vec<SignerSig>,
}

/// Minimal HTTP client for the sig-store, carrying the validator-scoped bearer
/// token (finding L-5: this process signs, so `Sign` is the only scope it needs).
pub struct Store {
    base: String,
    client: reqwest::Client,
}

impl Store {
    pub fn new(base: &str, token: Option<String>) -> Self {
        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(token) = token.as_deref().filter(|t| !t.is_empty()) {
            if let Ok(mut v) = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")) {
                v.set_sensitive(true);
                headers.insert(reqwest::header::AUTHORIZATION, v);
            }
        }
        Store {
            base: base.trim_end_matches('/').to_string(),
            client: reqwest::Client::builder().default_headers(headers).build().unwrap_or_default(),
        }
    }

    /// POST a record plus this validator's signature. The server enforces the
    /// id⇄params binding and signature authenticity, so a bug here cannot poison
    /// the store — it can only get us rejected.
    pub async fn upsert(&self, record: &SubmissionRecord) -> anyhow::Result<()> {
        let res =
            self.client.post(format!("{}/submissions", self.base)).json(record).send().await?;
        if !res.status().is_success() {
            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            anyhow::bail!("sig-store rejected the submission ({status}): {body}");
        }
        Ok(())
    }
}

impl Store {
    /// Submissions the store has flagged as stuck. Candidates only — the caller
    /// MUST still verify both ends on-chain before signing anything, which is
    /// exactly what `refund::Attester` does.
    /// Paged: the queue is unbounded and the store is untrusted, so an unpaged
    /// fetch can be grown until it fails on every tick (audit 2026-09-16, H-6).
    /// Callers walk pages — see [`REFUND_PAGE`].
    pub async fn refund_candidates(
        &self,
        limit: u64,
        offset: u64,
    ) -> anyhow::Result<Vec<SubmissionRecord>> {
        let res = self
            .client
            .get(format!("{}/refund-candidates?limit={limit}&offset={offset}", self.base))
            .send()
            .await?;
        if !res.status().is_success() {
            anyhow::bail!("sig-store refund-candidates failed ({})", res.status());
        }
        Ok(res.json().await?)
    }

    /// Deposit one cancel/refund attestation. The server re-derives the digest
    /// for `kind` specifically, so a transfer signature posted as a cancel
    /// recovers to the wrong address and is refused — the three quorums stay
    /// independent.
    pub async fn post_attestation(
        &self,
        submission_id: &str,
        kind: &str,
        signer: &str,
        signature: &str,
    ) -> anyhow::Result<()> {
        let body = serde_json::json!({ "kind": kind, "signer": signer, "signature": signature });
        let res = self
            .client
            .post(format!("{}/submissions/{submission_id}/attestations", self.base))
            .json(&body)
            .send()
            .await?;
        if !res.status().is_success() {
            let status = res.status();
            let text = res.text().await.unwrap_or_default();
            anyhow::bail!("sig-store rejected the {kind} attestation ({status}): {text}");
        }
        Ok(())
    }

    /// Every record the store holds. The keeper half filters these down to the
    /// ones bound for Solana.
    pub async fn list(&self) -> anyhow::Result<Vec<SubmissionRecord>> {
        let res = self.client.get(format!("{}/submissions", self.base)).send().await?;
        if !res.status().is_success() {
            anyhow::bail!("sig-store list failed ({})", res.status());
        }
        Ok(res.json().await?)
    }

    /// The store's target-side work queue for `chain_id_to`: transfers it still
    /// believes may need a claim or a cancel there (`status <> 'claimed'`, not
    /// cancelled/refunded). Filtered server-side on the lifecycle the indexer —
    /// and, for Solana, the observer — maintains.
    pub async fn pending_claims(&self, chain_id_to: u64) -> anyhow::Result<Vec<SubmissionRecord>> {
        self.get_json(&format!("/submissions?pending=claims&chain_id_to={chain_id_to}")).await
    }

    /// The store's source-side work queue for `chain_id_from`: transfers with a
    /// refund attestation that are not yet recorded as repaid.
    pub async fn pending_refunds(&self, chain_id_from: u64) -> anyhow::Result<Vec<SubmissionRecord>> {
        self.get_json(&format!("/submissions?pending=refunds&chain_id_from={chain_id_from}")).await
    }
}

/// A terminal state an observer saw on-chain, and the store route that records
/// it. The store treats the report as AUTHORITATIVE (it runs the same `mark_*`
/// the EVM indexer does), which is why it is accepted only from the
/// `Indexer`-scoped credential — never from the validator token this process
/// otherwise carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Terminal {
    /// Destination delivered it: `["executed", id]` holds `MARKER_CLAIMED`.
    Claimed,
    /// Destination burned it: `["executed", id]` holds `MARKER_CANCELLED`.
    Cancelled,
    /// Source repaid it: `["refunded", id]` exists.
    Refunded,
}

impl Terminal {
    /// The route suffix and the body field the store reads for this state.
    pub fn route(self) -> &'static str {
        match self {
            Terminal::Claimed => "claimed",
            Terminal::Cancelled => "cancelled",
            Terminal::Refunded => "refunded",
        }
    }

    pub fn tx_field(self) -> &'static str {
        match self {
            Terminal::Claimed => "claim_tx",
            Terminal::Cancelled => "cancel_tx",
            Terminal::Refunded => "refund_tx",
        }
    }
}

impl Store {
    /// Report an OBSERVED terminal state: `POST /submissions/:id/observed/<state>`
    /// with the tx (a Solana signature, or the marker address when the
    /// signature could not be fetched cheaply) under the field the store expects.
    ///
    /// Must be sent from a client built with the indexer token; the store answers
    /// 401 to anything else, and this returns that as an error so the caller
    /// retries on the next tick rather than marking the id reported.
    pub async fn report_observed(&self, submission_id: &str, what: Terminal, tx: &str) -> anyhow::Result<()> {
        let id = submission_id.strip_prefix("0x").unwrap_or(submission_id);
        let body = serde_json::json!({ what.tx_field(): tx });
        let res = self
            .client
            .post(format!("{}/submissions/{id}/observed/{}", self.base, what.route()))
            .json(&body)
            .send()
            .await?;
        if !res.status().is_success() {
            let status = res.status();
            let text = res.text().await.unwrap_or_default();
            anyhow::bail!("sig-store rejected the observed-{} report ({status}): {text}", what.route());
        }
        Ok(())
    }
}

/// One whitelisted asset, as the sig-store serves it at `/allowed/tokens`.
///
/// Another hand-maintained mirror of a `bridge_core::allow` type, for the same
/// unavoidable reason as [`SubmissionRecord`]: this crate cannot link
/// bridge-core at all. Only the fields this side actually reads are declared;
/// unknown ones are ignored by serde, so the server may add fields freely.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AllowedToken {
    /// `0x`-prefixed `keccak256(abi.encodePacked(chain_id, token))`, lowercased.
    pub debridge_id: String,
}

/// One whitelisted directed chain pair, as served at `/allowed/chains`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AllowedChain {
    pub chain_id_from: u64,
    pub chain_id_to: u64,
}

/// Which assets and corridors this relayer will attest.
///
/// ## Semantics must match `bridge_core::allow::Allowlist` exactly
///
/// The lists are **opt-in**: an empty list means "no restriction configured" and
/// allows everything; the first row flips that list to deny-by-default. The two
/// lists are independent. Diverging from the EVM side here would be worse than
/// having no check at all — operators would face a control that means one thing
/// on one leg and something else on the other.
#[derive(Clone, Debug, Default)]
pub struct Allowlist {
    debridge_ids: HashSet<String>,
    chains: HashSet<(u64, u64)>,
}

impl Allowlist {
    pub fn from_parts(tokens: &[AllowedToken], chains: &[AllowedChain]) -> Self {
        Allowlist {
            debridge_ids: tokens.iter().map(|t| t.debridge_id.to_ascii_lowercase()).collect(),
            chains: chains.iter().map(|c| (c.chain_id_from, c.chain_id_to)).collect(),
        }
    }

    /// Empty list => everything allowed; otherwise only listed ids, matched
    /// case-insensitively (the store lowercases, we format with `hex::encode`,
    /// but a hand-seeded row could be mixed case).
    pub fn token_allowed(&self, debridge_id: &str) -> bool {
        self.debridge_ids.is_empty()
            || self.debridge_ids.contains(&debridge_id.to_ascii_lowercase())
    }

    /// Empty list => every pair allowed; otherwise only listed `(from, to)`.
    pub fn chain_allowed(&self, from: u64, to: u64) -> bool {
        self.chains.is_empty() || self.chains.contains(&(from, to))
    }
}

impl Store {
    /// The current allowlists, refetched per tick so an operator's change applies
    /// without restarting every relayer in the fleet.
    ///
    /// Both lists are read at the `Read` scope, which the validator-scoped token
    /// this process already carries includes.
    pub async fn allowlist(&self) -> anyhow::Result<Allowlist> {
        let tokens: Vec<AllowedToken> = self.get_json("/allowed/tokens").await?;
        let chains: Vec<AllowedChain> = self.get_json("/allowed/chains").await?;
        Ok(Allowlist::from_parts(&tokens, &chains))
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        let res = self.client.get(format!("{}{path}", self.base)).send().await?;
        if !res.status().is_success() {
            anyhow::bail!("sig-store {path} failed ({})", res.status());
        }
        Ok(res.json().await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_record() -> SubmissionRecord {
        SubmissionRecord {
            submission_id: format!("0x{}", "11".repeat(32)),
            bridge_domain: format!("0x{}", "22".repeat(32)),
            debridge_id: format!("0x{}", "33".repeat(32)),
            amount: "1000000".into(),
            chain_id_from: 7_565_164,
            chain_id_to: 11_155_111,
            nonce: 0,
            receiver: format!("0x{}", "44".repeat(20)),
            auto_params: "0x".into(),
            native_sender: format!("0x{}", "55".repeat(32)),
            token: String::new(),
            signatures: vec![],
            cancel_signatures: vec![],
            refund_signatures: vec![],
        }
    }

    /// THE REGRESSION. This struct is a hand-maintained duplicate of
    /// `bridge_core::store::SubmissionRecord` (the crates cannot link: alloy needs
    /// `zeroize ^1.5`, solana-client pins `<1.4`). When `bridge_domain` was added
    /// to the canonical record it was NOT added here, and because the canonical
    /// field is `#[serde(default)]` the store happily accepted the missing key —
    /// then rejected the empty value with `malformed field: bridge_domain`, and
    /// every Solana-origin transfer failed to store. Nothing in either crate's
    /// tests noticed, because neither can see the other's struct.
    ///
    /// So the wire format is pinned HERE, as an explicit key list.
    #[test]
    fn the_wire_format_carries_every_field_the_store_requires() {
        let json = serde_json::to_value(a_record()).expect("serializes");
        let obj = json.as_object().expect("an object");

        // Exactly the serde names `bridge_core::store::SubmissionRecord` reads.
        for key in [
            "submission_id",
            "bridge_domain",
            "debridge_id",
            "amount",
            "chain_id_from",
            "chain_id_to",
            "nonce",
            "receiver",
            "auto_params",
            "native_sender",
            "token",
            "signatures",
            "cancel_signatures",
            "refund_signatures",
        ] {
            assert!(obj.contains_key(key), "the store requires `{key}`, and it is not on the wire");
        }
    }

    // --- allowlist ----------------------------------------------------------

    fn tok(id: &str) -> AllowedToken {
        AllowedToken { debridge_id: id.into() }
    }

    /// Opt-in semantics, and they MUST match `bridge_core::allow::Allowlist`.
    /// An empty list allowing everything is what keeps a fleet that has never
    /// seeded the lists working; the first row is what turns enforcement on.
    #[test]
    fn an_empty_allowlist_permits_everything() {
        let a = Allowlist::from_parts(&[], &[]);
        assert!(a.token_allowed("0xdeadbeef"));
        assert!(a.chain_allowed(7_565_164, 11_155_111));
    }

    /// The first row flips that list to deny-by-default. This is the behaviour
    /// an operator relies on when they de-list a token during an incident.
    #[test]
    fn one_token_row_denies_every_other_token() {
        let a = Allowlist::from_parts(&[tok("0xaa")], &[]);
        assert!(a.token_allowed("0xaa"));
        assert!(!a.token_allowed("0xbb"));
        // The chain list is independent and still empty, so it allows all pairs.
        assert!(a.chain_allowed(1, 2));
    }

    #[test]
    fn one_chain_row_denies_every_other_pair() {
        let a = Allowlist::from_parts(&[], &[AllowedChain { chain_id_from: 1, chain_id_to: 2 }]);
        assert!(a.chain_allowed(1, 2));
        assert!(!a.chain_allowed(2, 1), "the pair is DIRECTED");
        assert!(!a.chain_allowed(1, 3));
    }

    /// We format ids with `hex::encode` (lowercase) and the store lowercases its
    /// rows, but a hand-seeded row could be mixed case. Matching case-sensitively
    /// would silently de-list a token that IS listed.
    #[test]
    fn debridge_ids_match_case_insensitively() {
        let a = Allowlist::from_parts(&[tok("0xAaBbCc")], &[]);
        assert!(a.token_allowed("0xaabbcc"));
        assert!(a.token_allowed("0xAABBCC"));
    }

    /// The wire shape the sig-store actually serves at `/allowed/*`. Pinned for
    /// the same reason as the submission record above: this crate cannot link
    /// bridge-core, so nothing else would catch a rename.
    #[test]
    fn the_allowlist_wire_format_matches_the_sig_store() {
        let tokens: Vec<AllowedToken> = serde_json::from_str(
            r#"[{"chain_id":1,"token":"0xabc","debridge_id":"0xdef","symbol":"TST"}]"#,
        )
        .expect("extra fields are ignored, debridge_id is read");
        assert_eq!(tokens[0].debridge_id, "0xdef");

        let chains: Vec<AllowedChain> =
            serde_json::from_str(r#"[{"chain_id_from":7565164,"chain_id_to":11155111}]"#)
                .expect("parses the served shape");
        assert_eq!(chains[0].chain_id_from, 7_565_164);
        assert_eq!(chains[0].chain_id_to, 11_155_111);
    }

    /// The observed-report wire shape, pinned the same way: route suffix and body
    /// field must match `sig-store`'s `/observed/*` handlers and their request
    /// types (`ClaimedRequest { claim_tx }`, `ObservedCancelledRequest
    /// { cancel_tx }`, `ObservedRefundedRequest { refund_tx }`).
    #[test]
    fn the_observed_report_wire_format_matches_the_sig_store() {
        assert_eq!((Terminal::Claimed.route(), Terminal::Claimed.tx_field()), ("claimed", "claim_tx"));
        assert_eq!((Terminal::Cancelled.route(), Terminal::Cancelled.tx_field()), ("cancelled", "cancel_tx"));
        assert_eq!((Terminal::Refunded.route(), Terminal::Refunded.tx_field()), ("refunded", "refund_tx"));
    }

    /// The store parses `bridge_domain` with `B256::from_str`, which accepts only
    /// `0x` + 64 hex. An empty string — the value a missing field defaults to —
    /// is the exact failure that took the Solana leg down, so pin the shape.
    #[test]
    fn bridge_domain_is_sent_as_an_0x_prefixed_32_byte_hex_string() {
        let json = serde_json::to_value(a_record()).expect("serializes");
        let d = json["bridge_domain"].as_str().expect("a string");
        assert!(d.starts_with("0x"), "must be 0x-prefixed, got {d}");
        assert_eq!(d.len(), 66, "must be 0x + 64 hex chars, got {} in {d}", d.len());
        assert!(d[2..].chars().all(|c| c.is_ascii_hexdigit()), "must be hex: {d}");
        assert_ne!(d, "0x", "an empty domain is rejected by the store, not defaulted");
    }
}
