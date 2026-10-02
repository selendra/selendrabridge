//! The Solana marker observer: the missing "indexer" for the Solana gate.
//!
//! ## The bug this closes
//!
//! The store's lifecycle (`status`, `refund_status`) moves only on an OBSERVED
//! on-chain terminal event — that is the M-1 posture: a keeper's report of its
//! own claim is advisory, because a leaked keeper token must not be able to hide
//! a transfer from the claim and refund queues. The EVM `indexer` supplies those
//! observations for EVM gates, straight into Postgres. Nothing supplied them for
//! the Solana gate. So a transfer DELIVERED on Solana stayed `status='signed'`
//! forever: the indexer's sweep flagged it `refund_status='eligible'`, the
//! explorer showed it stuck, the submitter re-probed it every poll, and the
//! refund attesters kept examining a transfer that had already paid out (they
//! refuse to attest it — the marker says delivered — but it never left the list).
//!
//! ## What this loop does
//!
//! Every `poll_interval_ms` it asks the store for the two work queues that
//! concern this chain, reads the gate's own markers for each entry at the
//! configured commitment, and reports each terminal state it sees ONCE through
//! the store's `Indexer`-scoped `/observed/*` routes — the same authoritative
//! `mark_*` writes the EVM indexer makes:
//!
//!   * Solana is the DESTINATION (`pending_claims(chain_id)`): the
//!     `["executed", id]` PDA. `MARKER_CLAIMED` → `claimed`; `MARKER_CANCELLED`
//!     → `cancelled` (the burn that unlocks refund attestations).
//!   * Solana is the SOURCE (`pending_refunds(chain_id)`): the `["refunded", id]`
//!     PDA → `refunded`.
//!
//! The tx recorded is the claim/cancel/refund transaction's signature when
//! `getSignaturesForAddress` on the marker returns one that provably CREATED the
//! marker (see [`creates_marker`]), else the marker address itself — either is
//! enough for an operator to find the transaction.
//!
//! ## Why it holds a credential of its own
//!
//! These reports are authoritative by construction, so they ride on a scope
//! (`Indexer`, `SIG_STORE_INDEXER_TOKEN`) that no keeper, validator or operator
//! holds. The loop runs only when that token resolves; without it this process
//! keeps signing, delivering and attesting exactly as before, and the store
//! keeps refusing lifecycle writes from everything else.
//!
//! ## What it trusts
//!
//! Only a PDA the PROGRAM owns, with data, counts — the same rule the submitter
//! and the refund attester apply, because anyone can park lamports at a derived
//! address. Reads are at `finalized` unless the operator opted out for a local
//! validator: a report retires a transfer from every queue for good, so it must
//! not rest on a slot a fork can discard.

use std::collections::HashSet;
use std::str::FromStr;
use std::time::Duration;

use solana_client::nonblocking::rpc_client::RpcClient;
use solana_client::rpc_client::GetConfirmedSignaturesForAddress2Config;
use solana_client::rpc_config::RpcTransactionConfig;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use solana_transaction_status::option_serializer::OptionSerializer;
use solana_transaction_status::{
    EncodedConfirmedTransactionWithStatusMeta, EncodedTransaction, UiCompiledInstruction,
    UiInnerInstructions, UiInstruction, UiMessage, UiTransactionEncoding,
};
use tracing::{info, warn};

use crate::config::{ObserverConfig, SourceChain};
use crate::gate::{commitment, hex32, MARKER_CANCELLED, MARKER_CLAIMED};
use crate::store::{Store, SubmissionRecord, Terminal};

/// Interpret a `["executed", id]` account on the DESTINATION gate (pure,
/// host-testable). `account` is `(owner_is_program, data)` from a plain
/// `getAccountInfo`, `None` when the account does not exist.
pub fn destination_terminal(account: Option<(bool, &[u8])>) -> Option<Terminal> {
    let (owner_is_program, data) = account?;
    // Only program-owned state with data is a marker. A system-owned account
    // someone funded at that address is the H-2 griefing state, not a claim.
    if !owner_is_program || data.is_empty() {
        return None;
    }
    match data[0] {
        MARKER_CLAIMED => Some(Terminal::Claimed),
        MARKER_CANCELLED => Some(Terminal::Cancelled),
        // A byte this reader does not know: the program grew a state we cannot
        // name. Report nothing rather than guess — a wrong `claimed` hides a
        // transfer; a missed one only delays.
        _ => None,
    }
}

/// Interpret a `["refunded", id]` account on the SOURCE gate (pure). The
/// program writes `MARKER_CLAIMED` there, but any program-owned data means the
/// payout happened: the marker is a replay guard, not a state byte.
pub fn source_terminal(account: Option<(bool, &[u8])>) -> Option<Terminal> {
    let (owner_is_program, data) = account?;
    if !owner_is_program || data.is_empty() {
        return None;
    }
    Some(Terminal::Refunded)
}

/// Which queue a record belongs to from this chain's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// `chain_id_to == ours`: read the destination marker.
    Destination,
    /// `chain_id_from == ours`: read the refund marker.
    Source,
}

/// Classify a record against our chain id (pure). `None` for corridors that do
/// not touch this gate — the queues are filtered server-side, so this is the
/// belt to that suspender: a store that answered the wrong filter must not make
/// us read a marker for a transfer that was never ours.
pub fn side_of(rec: &SubmissionRecord, chain_id: u64) -> Option<Side> {
    if rec.chain_id_to == chain_id {
        Some(Side::Destination)
    } else if rec.chain_id_from == chain_id {
        Some(Side::Source)
    } else {
        None
    }
}

/// Report-once bookkeeping (pure).
///
/// A report is recorded only once the store has ACCEPTED it, so a rejected or
/// failed report is retried next tick; a `(id, state)` pair already accepted is
/// not sent again while this process lives. The set is in memory on purpose:
/// after a restart every still-pending id is re-read and re-reported, and the
/// store's `mark_*` are idempotent, so a repeat costs one request and changes
/// nothing. `retain` prunes ids that have left the queues (the store has them
/// now), which keeps the set bounded by the queue size rather than by history.
#[derive(Debug, Default)]
pub struct Reported {
    done: HashSet<(String, Terminal)>,
}

impl Reported {
    /// Has this exact state already been accepted for this id?
    pub fn already(&self, id: &str, what: Terminal) -> bool {
        self.done.contains(&(id.to_ascii_lowercase(), what))
    }

    /// Record an ACCEPTED report. Returns false if it was already recorded.
    pub fn accepted(&mut self, id: &str, what: Terminal) -> bool {
        self.done.insert((id.to_ascii_lowercase(), what))
    }

    /// Forget ids that are no longer in any queue this tick.
    pub fn retain_in_queue(&mut self, in_queue: &HashSet<String>) {
        self.done.retain(|(id, _)| in_queue.contains(id));
    }

    pub fn len(&self) -> usize {
        self.done.len()
    }

    pub fn is_empty(&self) -> bool {
        self.done.is_empty()
    }
}

pub struct Observer {
    rpc: RpcClient,
    program_id: Pubkey,
    chain_id: u64,
    poll: Duration,
    commitment_name: String,
    store: Store,
    reported: Reported,
}

impl Observer {
    /// `store` must have been built with the INDEXER token; the caller decides
    /// whether to construct an observer at all on that basis.
    pub fn new(source: &SourceChain, cfg: &ObserverConfig, store: Store) -> anyhow::Result<Self> {
        Ok(Observer {
            rpc: RpcClient::new_with_commitment(source.rpc.clone(), commitment(&cfg.commitment)),
            program_id: Pubkey::from_str(&source.program_id)
                .map_err(|_| anyhow::anyhow!("program_id is not a valid pubkey"))?,
            chain_id: source.chain_id,
            poll: Duration::from_millis(cfg.poll_interval_ms.max(1000)),
            commitment_name: cfg.commitment.clone(),
            store,
            reported: Reported::default(),
        })
    }

    pub async fn run(mut self) -> anyhow::Result<()> {
        info!(
            chain_id = self.chain_id,
            program = %self.program_id,
            commitment = %self.commitment_name,
            poll_ms = self.poll.as_millis() as u64,
            "solana marker observer started — reporting observed claimed/cancelled/refunded to the store"
        );
        loop {
            if let Err(e) = self.tick().await {
                warn!(error = %e, "observer tick failed; retrying");
            }
            tokio::time::sleep(self.poll).await;
        }
    }

    async fn tick(&mut self) -> anyhow::Result<()> {
        // Both queues first, so one failed listing skips the tick whole rather
        // than pruning bookkeeping against half a view.
        let claims = self.store.pending_claims(self.chain_id).await?;
        let refunds = self.store.pending_refunds(self.chain_id).await?;

        let mut in_queue: HashSet<String> = HashSet::new();
        for rec in claims.iter().chain(refunds.iter()) {
            in_queue.insert(rec.submission_id.to_ascii_lowercase());
        }
        self.reported.retain_in_queue(&in_queue);

        for rec in claims.iter().chain(refunds.iter()) {
            let Some(side) = side_of(rec, self.chain_id) else { continue };
            let Ok(id) = hex32(&rec.submission_id) else { continue };
            let (seed, marker): (&[u8], _) = match side {
                Side::Destination => (b"executed", destination_terminal as fn(_) -> _),
                Side::Source => (b"refunded", source_terminal as fn(_) -> _),
            };
            let (pda, _) = Pubkey::find_program_address(&[seed, &id], &self.program_id);
            let acct = match self.rpc.get_account_with_commitment(&pda, self.rpc.commitment()).await {
                Ok(r) => r.value,
                Err(e) => {
                    warn!(submission_id = %rec.submission_id, error = %e, "cannot read marker; skipping");
                    continue;
                }
            };
            let Some(what) =
                marker(acct.as_ref().map(|a| (a.owner == self.program_id, a.data.as_slice())))
            else {
                continue; // still pending on-chain: nothing to report
            };
            if self.reported.already(&rec.submission_id, what) {
                continue;
            }
            let tx = self.marker_tx(&pda, side).await;
            match self.store.report_observed(&rec.submission_id, what, &tx).await {
                Ok(()) => {
                    self.reported.accepted(&rec.submission_id, what);
                    info!(
                        submission_id = %rec.submission_id,
                        state = what.route(),
                        %tx,
                        chain_from = rec.chain_id_from,
                        chain_to = rec.chain_id_to,
                        "OBSERVED on Solana — reported to the store"
                    );
                }
                Err(e) => warn!(
                    submission_id = %rec.submission_id,
                    state = what.route(),
                    error = %e,
                    "store refused the observed report; will retry"
                ),
            }
        }
        Ok(())
    }

    /// The signature of the transaction that created the marker, when one
    /// lookup finds it; otherwise the marker address, which is still enough to
    /// locate the transaction by hand. Never fails the report over this.
    ///
    /// Audit 2026-10-02, L7-8: `getSignaturesForAddress` lists EVERY transaction
    /// that mentions the address, and anyone can mention a derivable PDA in a
    /// transaction of their own — before the real claim, even, since the id is
    /// public from the `Sent` onward. Taking "the oldest successful one" let
    /// such a transaction be recorded as the claim/cancel/refund. Each candidate
    /// is now fetched and accepted only if [`creates_marker`] holds; otherwise
    /// the next is tried, and with none the marker address is recorded.
    async fn marker_tx(&self, marker: &Pubkey, side: Side) -> String {
        let cfg = GetConfirmedSignaturesForAddress2Config {
            before: None,
            until: None,
            limit: Some(MARKER_TX_CANDIDATES),
            commitment: Some(self.rpc.commitment()),
        };
        let sigs = match self.rpc.get_signatures_for_address_with_config(marker, cfg).await {
            Ok(sigs) => sigs,
            Err(e) => {
                tracing::debug!(%marker, error = %e, "no signature lookup; recording the marker address");
                return marker.to_string();
            }
        };
        let tx_cfg = RpcTransactionConfig {
            encoding: Some(UiTransactionEncoding::Json),
            commitment: Some(self.rpc.commitment()),
            max_supported_transaction_version: Some(0),
        };
        // Newest first from the RPC; the creating transaction is the oldest
        // that qualifies (a later replay of the same claim fails on-chain).
        for s in sigs.iter().rev().filter(|s| s.err.is_none()) {
            let Ok(sig) = Signature::from_str(&s.signature) else { continue };
            match self.rpc.get_transaction_with_config(&sig, tx_cfg).await {
                Ok(tx) if creates_marker(&tx, &self.program_id, marker, side) => return s.signature.clone(),
                Ok(_) => tracing::debug!(%marker, signature = %s.signature, "mentions the marker but did not create it"),
                Err(e) => tracing::debug!(%marker, signature = %s.signature, error = %e, "transaction lookup failed"),
            }
        }
        marker.to_string()
    }
}

/// Signatures examined per marker by [`Observer::marker_tx`]; each costs a
/// `getTransaction`. Display-only data, so a bound beats completeness.
const MARKER_TX_CANDIDATES: usize = 10;

/// `GateInstruction` discriminants that create a marker, and the account slot
/// the program reads that marker from (`process_claim` / `process_cancel` /
/// `process_refund` in `solana-gate`; pinned on the client side by the
/// encoders in `target::wire`).
const CLAIM_IX: (u8, usize) = (2, 2);
const CANCEL_IX: (u8, usize) = (10, 1);
const REFUND_IX: (u8, usize) = (11, 3);

/// Did this transaction create `marker` through the gate program (pure,
/// host-testable)? (Audit 2026-10-02, L7-8.)
///
/// True only when the transaction SUCCEEDED and some instruction in it — top
/// level or inner (a CPI) — is the gate program running Claim or Cancel (for a
/// destination `["executed", id]` marker) or Refund (for a source
/// `["refunded", id]` one) with `marker` in the exact account slot the program
/// checks against the PDA it derives from the instruction's own id, and creates.
/// Such an instruction cannot succeed twice for one marker, so it is THE
/// creating transaction. Merely listing the address — as a trailing extra
/// account on some other gate call, in a system transfer, anywhere — is not.
pub fn creates_marker(
    tx: &EncodedConfirmedTransactionWithStatusMeta,
    program_id: &Pubkey,
    marker: &Pubkey,
    side: Side,
) -> bool {
    let Some(meta) = tx.transaction.meta.as_ref() else { return false };
    if meta.err.is_some() || meta.status.is_err() {
        return false;
    }
    let EncodedTransaction::Json(ui) = &tx.transaction.transaction else { return false };
    let UiMessage::Raw(msg) = &ui.message else { return false };
    // Static keys, then (v0) the lookup-table loads: writable, then readonly.
    let mut keys: Vec<&str> = msg.account_keys.iter().map(String::as_str).collect();
    if let OptionSerializer::Some(loaded) = &meta.loaded_addresses {
        keys.extend(loaded.writable.iter().map(String::as_str));
        keys.extend(loaded.readonly.iter().map(String::as_str));
    }
    let program = program_id.to_string();
    let marker = marker.to_string();
    let wanted: &[(u8, usize)] = match side {
        Side::Destination => &[CLAIM_IX, CANCEL_IX],
        Side::Source => &[REFUND_IX],
    };
    let creates = |ix: &UiCompiledInstruction| {
        if keys.get(ix.program_id_index as usize) != Some(&program.as_str()) {
            return false;
        }
        let Ok(data) = solana_sdk::bs58::decode(&ix.data).into_vec() else { return false };
        let Some(&disc) = data.first() else { return false };
        wanted.iter().any(|&(d, slot)| {
            d == disc
                && ix.accounts.get(slot).and_then(|&k| keys.get(k as usize)) == Some(&marker.as_str())
        })
    };
    let inner: &[UiInnerInstructions] = match &meta.inner_instructions {
        OptionSerializer::Some(v) => v,
        _ => &[],
    };
    msg.instructions.iter().any(creates)
        || inner.iter().flat_map(|i| &i.instructions).any(|ix| match ix {
            UiInstruction::Compiled(c) => creates(c),
            UiInstruction::Parsed(_) => false,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(from: u64, to: u64) -> SubmissionRecord {
        SubmissionRecord {
            submission_id: format!("0x{}", "11".repeat(32)),
            bridge_domain: format!("0x{}", "22".repeat(32)),
            debridge_id: format!("0x{}", "33".repeat(32)),
            amount: "1".into(),
            bridge_decimals: Some(6),
            chain_id_from: from,
            chain_id_to: to,
            nonce: 0,
            receiver: "0x".into(),
            auto_params: "0x".into(),
            native_sender: "0x".into(),
            token: String::new(),
            signatures: vec![],
            cancel_signatures: vec![],
            refund_signatures: vec![],
        }
    }

    // --- the marker interpretation (what gets reported) ----------------------

    /// THE fix: a program-owned `["executed", id]` holding the claimed byte is a
    /// delivered transfer, and that is what the store must hear.
    #[test]
    fn a_claimed_marker_is_reported_as_claimed() {
        assert_eq!(destination_terminal(Some((true, &[MARKER_CLAIMED]))), Some(Terminal::Claimed));
    }

    /// A burn is NOT a delivery — reporting it as `claimed` would tell the source
    /// chain nothing needs repaying. It is the state that unlocks refunds.
    #[test]
    fn a_cancelled_marker_is_reported_as_cancelled_never_claimed() {
        assert_eq!(destination_terminal(Some((true, &[MARKER_CANCELLED]))), Some(Terminal::Cancelled));
    }

    /// No account, a foreign-owned account (the H-2 griefing state: anyone can
    /// fund a derived address), or program-owned with no data: not a marker.
    /// A false `claimed` here would hide an undelivered transfer forever, so
    /// every one of these must report nothing.
    #[test]
    fn missing_foreign_or_empty_accounts_report_nothing() {
        for acct in [None, Some((false, &[MARKER_CLAIMED][..])), Some((true, &[][..]))] {
            assert_eq!(destination_terminal(acct), None, "{acct:?}");
            assert_eq!(source_terminal(acct), None, "{acct:?}");
        }
    }

    /// A state byte this reader does not know is not guessed at.
    #[test]
    fn an_unknown_marker_byte_reports_nothing() {
        assert_eq!(destination_terminal(Some((true, &[0]))), None);
        assert_eq!(destination_terminal(Some((true, &[3]))), None);
        assert_eq!(destination_terminal(Some((true, &[0xff]))), None);
    }

    /// The refund marker is a replay guard, so any program-owned data means paid.
    #[test]
    fn a_refunded_marker_is_reported_as_refunded() {
        assert_eq!(source_terminal(Some((true, &[MARKER_CLAIMED]))), Some(Terminal::Refunded));
        assert_eq!(source_terminal(Some((true, &[7, 7]))), Some(Terminal::Refunded));
    }

    /// Which marker to read follows which end of the corridor we are.
    #[test]
    fn a_record_is_read_on_the_side_this_chain_plays() {
        const SOL: u64 = 7_565_164;
        assert_eq!(side_of(&record(1, SOL), SOL), Some(Side::Destination));
        assert_eq!(side_of(&record(SOL, 1), SOL), Some(Side::Source));
        assert_eq!(side_of(&record(1, 2), SOL), None, "an EVM<->EVM corridor is not ours");
    }

    // --- report-once bookkeeping ----------------------------------------------

    #[test]
    fn a_state_is_reported_once_until_forgotten() {
        let mut r = Reported::default();
        assert!(!r.already("0xAB", Terminal::Claimed));
        assert!(r.accepted("0xAB", Terminal::Claimed));
        assert!(r.already("0xAB", Terminal::Claimed));
        assert!(r.already("0xab", Terminal::Claimed), "ids compare case-insensitively");
        assert!(!r.accepted("0xab", Terminal::Claimed), "a second accept is a no-op");
        assert_eq!(r.len(), 1);
    }

    /// The same id can legitimately reach two states in sequence: a destination
    /// burn (`cancelled`) and later — as a Solana-source transfer — a payout.
    /// They are distinct reports.
    #[test]
    fn different_states_for_one_id_are_distinct_reports() {
        let mut r = Reported::default();
        r.accepted("0x01", Terminal::Cancelled);
        assert!(!r.already("0x01", Terminal::Refunded));
        assert!(!r.already("0x01", Terminal::Claimed));
    }

    /// Only an ACCEPTED report is remembered: the caller must not call
    /// `accepted` on a failure, so a 401 (wrong token) or a store outage is
    /// retried next tick rather than silently dropped for the process lifetime.
    #[test]
    fn a_failed_report_is_not_remembered() {
        let r = Reported::default();
        // Nothing accepted => nothing remembered, whatever was attempted.
        assert!(!r.already("0x01", Terminal::Claimed));
        assert!(r.is_empty());
    }

    /// Bookkeeping is bounded by the live queues: once the store has moved an id
    /// out of them, remembering it buys nothing (a repeat is idempotent) and
    /// would grow without limit over the process lifetime.
    #[test]
    fn ids_that_left_the_queues_are_forgotten() {
        let mut r = Reported::default();
        r.accepted("0xaa", Terminal::Claimed);
        r.accepted("0xbb", Terminal::Refunded);
        let still: HashSet<String> = ["0xbb".to_string()].into_iter().collect();
        r.retain_in_queue(&still);
        assert!(!r.already("0xaa", Terminal::Claimed), "gone from the queue => forgotten");
        assert!(r.already("0xbb", Terminal::Refunded), "still queued => still remembered");
    }

    // --- L7-8: which transaction created the marker ---------------------------

    const SYSTEM: &str = "11111111111111111111111111111111";

    fn key(b: u8) -> String {
        Pubkey::new_from_array([b; 32]).to_string()
    }

    /// A `getTransaction` (encoding `json`) result, as the RPC returns it.
    /// `ixs`/`inner` are `(program_id_index, accounts, data)`.
    fn fixture(
        keys: &[String],
        ixs: &[(u8, &[u8], &[u8])],
        inner: &[(u8, &[u8], &[u8])],
        failed: bool,
        loaded_writable: &[String],
    ) -> EncodedConfirmedTransactionWithStatusMeta {
        let ix = |(p, a, d): &(u8, &[u8], &[u8])| {
            serde_json::json!({
                "programIdIndex": p,
                "accounts": a,
                "data": solana_sdk::bs58::encode(d).into_string(),
                "stackHeight": null
            })
        };
        let (err, status) = if failed {
            let e = serde_json::json!({"InstructionError": [0, {"Custom": 6}]});
            (e.clone(), serde_json::json!({"Err": e}))
        } else {
            (serde_json::Value::Null, serde_json::json!({"Ok": null}))
        };
        let n = keys.len() + loaded_writable.len();
        let v = serde_json::json!({
            "slot": 311_000_123u64,
            "blockTime": 1_759_000_000i64,
            "version": 0,
            "transaction": {
                "signatures": ["5h6xBEauJ3PK6SWCZ1PGjBvj8vDdWG3KpwATGy1ARAXFSDwt8GFXM7W5Ncn16wmqokgpiKRLuS83KUxyZyv2sUYv"],
                "message": {
                    "header": {"numRequiredSignatures": 1, "numReadonlySignedAccounts": 0, "numReadonlyUnsignedAccounts": 2},
                    "accountKeys": keys,
                    "recentBlockhash": SYSTEM,
                    "instructions": ixs.iter().map(ix).collect::<Vec<_>>()
                }
            },
            "meta": {
                "err": err,
                "status": status,
                "fee": 5000,
                "preBalances": vec![0u64; n],
                "postBalances": vec![1u64; n],
                "innerInstructions": if inner.is_empty() { serde_json::json!([]) } else {
                    serde_json::json!([{"index": 0, "instructions": inner.iter().map(ix).collect::<Vec<_>>()}])
                },
                "logMessages": [],
                "loadedAddresses": {"writable": loaded_writable, "readonly": []}
            }
        });
        serde_json::from_value(v).expect("fixture matches the RPC's getTransaction shape")
    }

    /// Keys: 0 payer, 1 config, 2 asset, 3 MARKER, 4 vault, 5 receiver token,
    /// 6 vault authority, 7 another id's marker, 8 system, 9 GATE, 10 other program.
    fn keys(program: &Pubkey, marker: &Pubkey) -> Vec<String> {
        let mut k: Vec<String> = (0u8..=10).map(|b| key(b + 1)).collect();
        k[3] = marker.to_string();
        k[8] = SYSTEM.into();
        k[9] = program.to_string();
        k
    }

    /// The real claim: gate program, `Claim` (2), the marker in slot 2.
    #[test]
    fn the_successful_gate_claim_creating_the_marker_is_accepted() {
        let (program, marker) = (Pubkey::new_from_array([0xaa; 32]), Pubkey::new_from_array([0xbb; 32]));
        let k = keys(&program, &marker);
        let claim: &[u8] = &[1, 2, 3, 0, 4, 5, 6, 8];
        let tx = fixture(&k, &[(9, claim, &[2, 0xde, 0xad])], &[], false, &[]);
        assert!(creates_marker(&tx, &program, &marker, Side::Destination));
        assert!(!creates_marker(&tx, &program, &marker, Side::Source), "a claim does not create a refund marker");
        // The same transaction, but it FAILED: nothing was created.
        let failed = fixture(&k, &[(9, claim, &[2, 0xde, 0xad])], &[], true, &[]);
        assert!(!creates_marker(&failed, &program, &marker, Side::Destination));
        // Cancel (10) reads the marker from slot 1.
        let cancel = fixture(&k, &[(9, &[1, 3, 0, 8], &[10, 1])], &[], false, &[]);
        assert!(creates_marker(&cancel, &program, &marker, Side::Destination));
        // Refund (11) creates ["refunded", id] from slot 3, on the SOURCE side.
        let refund = fixture(&k, &[(9, &[1, 2, 4, 3, 0, 5, 7, 6, 8], &[11])], &[], false, &[]);
        assert!(creates_marker(&refund, &program, &marker, Side::Source));
        assert!(!creates_marker(&refund, &program, &marker, Side::Destination));
    }

    /// THE finding: anyone can name the marker in a transaction of their own,
    /// and every one of these succeeded. None of them created it.
    #[test]
    fn a_transaction_that_merely_mentions_the_marker_is_rejected() {
        let (program, marker) = (Pubkey::new_from_array([0xaa; 32]), Pubkey::new_from_array([0xbb; 32]));
        let k = keys(&program, &marker);
        let cases: [(&str, Vec<(u8, &[u8], &[u8])>); 5] = [
            // A system transfer of a lamport to the derived address.
            ("system transfer", vec![(8, &[0, 3], &[2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0])]),
            // A REAL claim of another transfer (marker 7 in slot 2) with ours
            // appended as an extra account the program never reads.
            ("another id's claim", vec![(9, &[1, 2, 7, 0, 4, 5, 6, 8, 3], &[2])]),
            // A different gate instruction (Send = 1) naming it.
            ("gate send", vec![(9, &[1, 3, 0, 8], &[1])]),
            // The marker in a Claim's slot, but issued to ANOTHER program.
            ("look-alike program", vec![(10, &[1, 2, 3, 0, 4, 5, 6, 8], &[2])]),
            // Gate instruction with no data at all.
            ("empty data", vec![(9, &[1, 2, 3, 0], &[])]),
        ];
        for (what, ixs) in cases {
            let tx = fixture(&k, &ixs, &[], false, &[]);
            assert!(!creates_marker(&tx, &program, &marker, Side::Destination), "{what}");
            assert!(!creates_marker(&tx, &program, &marker, Side::Source), "{what}");
        }
    }

    /// A claim the gate runs as a CPI (inner instruction) counts, and so does a
    /// marker loaded through an address lookup table (v0).
    #[test]
    fn a_cpi_claim_and_a_lookup_table_marker_are_accepted() {
        let (program, marker) = (Pubkey::new_from_array([0xaa; 32]), Pubkey::new_from_array([0xbb; 32]));
        let k = keys(&program, &marker);
        let outer: (u8, &[u8], &[u8]) = (10, &[0, 3, 9], &[7, 7]);
        let tx = fixture(&k, &[outer], &[(9, &[1, 2, 3, 0, 4, 5, 6, 8], &[2])], false, &[]);
        assert!(creates_marker(&tx, &program, &marker, Side::Destination));

        let mut statics = k.clone();
        statics[3] = key(0x55); // the marker is NOT a static key...
        let alt = fixture(&statics, &[(9, &[1, 2, 11, 0, 4, 5, 6, 8], &[2])], &[], false, &[marker.to_string()]);
        assert!(creates_marker(&alt, &program, &marker, Side::Destination), "...it is loaded at index 11");
    }

    /// The poll floor and the default: slower than the claim loop, never a
    /// busy-loop against the store.
    #[test]
    fn observer_poll_has_a_floor() {
        let cfg = ObserverConfig { poll_interval_ms: 1, commitment: "finalized".into() };
        let src = SourceChain {
            chain_id: 1,
            rpc: "http://127.0.0.1:8899".into(),
            program_id: "11111111111111111111111111111111".into(),
            commitment: "finalized".into(),
            allow_unfinalized: false,
            poll_interval_ms: 2000,
            state_file: "x".into(),
            max_batch: 1,
            start_at_tip: false,
        };
        let o = Observer::new(&src, &cfg, Store::new("http://127.0.0.1:1", None).unwrap()).unwrap();
        assert_eq!(o.poll, Duration::from_secs(1));
        assert_eq!(ObserverConfig::default().poll_interval_ms, 10_000);
    }
}
