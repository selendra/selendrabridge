//! Refund attestation for transfers that touch Solana at EITHER end.
//!
//! The two-phase refund needs someone to vouch, from on-chain facts, that a
//! stuck transfer may be burned and then repaid. `crates/validator`'s refund
//! loop does that for corridors whose both ends are EVM chains. This attester
//! covers the two corridors that have a Solana end:
//!
//!   * **EVM → Solana** (Solana is the DESTINATION). The burn/no-burn facts are
//!     read from the Solana `["executed", id]` marker. The AGE — "has this been
//!     unclaimed for the timeout?" — is read from the EVM SOURCE gate: `sentBy(id)`
//!     at a block that is provably `timeout_secs` old by that chain's own clock,
//!     exactly as `validator/src/refund.rs` does (its H-2 fix). Audit round 4
//!     (M-13) found this attester taking the age from the store's
//!     `refund_candidates()` nomination instead, which let anyone who could flip
//!     `refund_status` get validators to burn a fresh, deliverable transfer.
//!   * **Solana → EVM** (Solana is the SOURCE). Round 4's M-4: nothing attested
//!     these at all — the EVM validator skips a source it cannot read, and this
//!     process handled only Solana destinations — so a stuck Solana→EVM transfer
//!     was unrefundable. Now the burn facts come from the EVM DESTINATION gate
//!     (`executed`/`cancelled` at a confirmed block, over raw JSON-RPC in
//!     [`crate::evm`]) and the age from the Solana `["sent", id]` record's
//!     `locked_at`, measured against the cluster's Clock sysvar.
//!
//! ## The rules that never bend
//!
//!   * A transfer DELIVERED on its destination earns nothing. A refund on top of
//!     a claim is the double-spend the whole design exists to prevent.
//!   * A CANCEL is attested only once THIS process has shown, on-chain, that the
//!     transfer is older than the timeout. If it cannot show that — no reader for
//!     the source chain, no `[refund]` block, the chain too young — it does not
//!     vote. The store's word is never evidence.
//!   * A REFUND follows an observed burn, not a timer, so it needs no age check.
//!
//! Every read is at the commitment / confirmation depth the operator configured
//! for signing, because a rolled-back "not executed" would let us attest a burn
//! for a transfer that was in fact paid.

use std::collections::{BTreeMap, HashSet};
use std::str::FromStr;
use std::sync::Mutex;
use std::time::Duration;

use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use tracing::{info, warn};

use crate::config::{RefundConfig, SourceChain};
use crate::evm::GateReader;
use crate::gate::{
    commitment, domain_id, hex32, sign, CANCEL_PREFIX, MARKER_CANCELLED, REFUND_PREFIX,
};
use crate::store::{
    SignerSig, Store, SubmissionRecord, MAX_REFUND_PAGES, REFUND_PAGE,
};

/// What a DESTINATION gate says about a submission (either VM).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DestinationState {
    /// The submission is spent there, one way or the other.
    pub executed: bool,
    /// …and it was BURNED rather than delivered.
    pub cancelled: bool,
}

/// What a SOURCE gate says about a submission (either VM).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceState {
    /// The gate really locked funds for this id (Solana: a live `["sent", id]`
    /// record; EVM: `sentBy != 0`).
    pub sent: bool,
    /// Already paid back (Solana: the record was zeroed; EVM: `refunded`).
    pub refunded: bool,
}

/// What to do about one candidate.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    /// Destination is untouched and the transfer is provably aged — attest the burn.
    AttestCancel,
    /// Destination is burned — attest the payout.
    AttestRefund,
    Skip(&'static str),
}

/// Decide from on-chain facts alone. Split from the I/O so the safety rules are
/// unit-testable, exactly as the EVM loop does it.
///
/// * `src` is `None` when this process has no reader for the source chain. The
///   source-side checks guard against WASTED attestations, not against loss (the
///   source gate itself refuses `NotSent`/`AlreadyRefunded`), so a missing reader
///   does not block the refund leg — but it does block the cancel leg, through
///   `aged_out`.
/// * `aged_out` is this process's OWN on-chain answer to "has the unclaimed
///   timeout elapsed?": `Some(true)`/`Some(false)` when it could be established,
///   `None` when it could not. `None` never yields a cancel. This is M-13.
pub fn decide(
    src: Option<&SourceState>,
    dst: &DestinationState,
    aged_out: Option<bool>,
    already_attested_cancel: bool,
    already_attested_refund: bool,
) -> Decision {
    // THE safety rule. A delivered transfer must never earn a cancel or refund
    // attestation, whatever the store says about timeouts.
    if dst.executed && !dst.cancelled {
        return Decision::Skip("delivered on destination");
    }
    if let Some(src) = src {
        if src.refunded || !src.sent {
            return Decision::Skip("already refunded, or not sent from that gate");
        }
    }
    // A burn already on-chain is a settled fact — the refund leg follows the
    // destination, it does not re-litigate the timeout.
    if dst.cancelled {
        return if already_attested_refund {
            Decision::Skip("refund already attested by us")
        } else {
            Decision::AttestRefund
        };
    }
    if already_attested_cancel {
        return Decision::Skip("cancel already attested by us");
    }
    match aged_out {
        None => Decision::Skip("unclaimed timeout cannot be verified on-chain; not attesting"),
        Some(false) => Decision::Skip("unclaimed timeout has not elapsed (verified on-chain)"),
        Some(true) => Decision::AttestCancel,
    }
}

/// Pure Solana age rule (host-testable): has a transfer locked at cluster time
/// `locked_at` been unclaimed for `timeout_secs`, as of cluster time `now`?
///
/// Both timestamps come from the chain — `locked_at` from the `["sent", id]`
/// record `process_send` wrote, `now` from the Clock sysvar — never from this
/// host's wall clock, so a skewed validator cannot attest early.
pub fn solana_aged_out(locked_at: i64, now: i64, timeout_secs: i64) -> bool {
    // A record with no lock time (pre-round-4 layout, or a zeroed field) can
    // never be shown aged: fail closed.
    locked_at > 0 && now.saturating_sub(locked_at) >= timeout_secs
}

/// The Solana source record, decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SolanaSourceRecord {
    pub state: SourceState,
    /// `locked_at` from the record; 0 when there is no live record.
    pub locked_at: i64,
}

/// Interpret a `["sent", id]` account (pure, host-testable). `owner_is_program`
/// and `data` come from a plain `getAccountInfo`.
pub fn solana_source_record(account: Option<(bool, &[u8])>) -> SolanaSourceRecord {
    use bridge_solana::relayer::decode_sent_record;

    let not_sent = SolanaSourceRecord { state: SourceState { sent: false, refunded: false }, locked_at: 0 };
    let Some((owner_is_program, data)) = account else { return not_sent };
    // Only a PDA the PROGRAM owns counts: anyone can park an account there.
    if !owner_is_program {
        return not_sent;
    }
    // Both the current and the pre-round-4 layout; the latter has no lock time,
    // so it decodes with `locked_at == 0` and can never be shown aged.
    let Some(rec) = decode_sent_record(data) else { return not_sent };
    // `process_refund` zeroes the record on payout.
    if rec.amount == 0 && rec.debridge_id == [0u8; 32] {
        return SolanaSourceRecord { state: SourceState { sent: true, refunded: true }, locked_at: 0 };
    }
    SolanaSourceRecord { state: SourceState { sent: true, refunded: false }, locked_at: rec.locked_at }
}

/// The submissionId a candidate's OWN params hash to, or an error if the store
/// paired them with a different id (audit 2026-10-02, L7-7 — the port of the
/// validator's round-5 `bound_submission_id`).
///
/// Every routing decision in [`Attester::tick`] — is Solana the destination or
/// the source, and which EVM gate is the far end — comes from
/// `chain_id_to`/`chain_id_from`, while every read and the signature itself are
/// keyed on `submission_id`. Nothing tied the two together here, so a record
/// naming a real id with a different corridor sent the `executed`/`cancelled`
/// reads to a gate that has never heard of the transfer, and the attester
/// decided it from what THAT gate said (a never-seen id reads "untouched" — the
/// cancel leg's precondition). The sig-store enforces the binding on write; this
/// process no longer takes that on trust.
///
/// The recompute is the store's `canonical_submission_id` rule over the
/// record's OWN `bridge_domain` (the gate-domain check belongs to the
/// submitters): the plain hash for an empty `auto_params`, otherwise the
/// with-auto hash over the decoded `abi.encode(AutoParamsTo)` blob and
/// `native_sender`. Anything that does not decode is refused, never folded to
/// "no auto" — the two are different ids.
pub fn bound_submission_id(rec: &SubmissionRecord) -> anyhow::Result<[u8; 32]> {
    use bridge_solana::hash::{amount_word, submission_id, submission_id_with_auto};
    use bridge_solana::relayer::{decode_evm_auto_params, wire_to_auto};
    use crate::gate::hex_bytes;

    let claimed = hex32(&rec.submission_id).map_err(|_| anyhow::anyhow!("bad submission_id"))?;
    let domain = hex32(&rec.bridge_domain).map_err(|_| anyhow::anyhow!("bad bridge_domain"))?;
    let debridge_id = hex32(&rec.debridge_id).map_err(|_| anyhow::anyhow!("bad debridge_id"))?;
    // A Solana leg moves a u64; a u128 covers every amount that can name one.
    let amount: u128 =
        rec.amount.parse().map_err(|_| anyhow::anyhow!("amount does not fit a Solana-leg transfer"))?;
    let decimals = rec.bridge_decimals.ok_or_else(|| anyhow::anyhow!("record has no bridge_decimals"))?;
    let receiver = hex_bytes(&rec.receiver).map_err(|_| anyhow::anyhow!("bad receiver"))?;
    let native_sender = hex_bytes(&rec.native_sender).map_err(|_| anyhow::anyhow!("bad native_sender"))?;
    let blob = hex_bytes(&rec.auto_params).map_err(|_| anyhow::anyhow!("bad auto_params"))?;
    let auto = decode_evm_auto_params(&blob).map_err(|e| anyhow::anyhow!("auto_params: {e}"))?;

    let word = amount_word(amount);
    let computed = match &auto {
        None => submission_id(
            &domain, &debridge_id, decimals, &word, rec.chain_id_from, rec.chain_id_to, rec.nonce,
            &receiver,
        ),
        Some(w) => submission_id_with_auto(
            &domain, &debridge_id, decimals, &word, rec.chain_id_from, rec.chain_id_to, rec.nonce,
            &receiver, &wire_to_auto(w, &native_sender),
        ),
    };
    anyhow::ensure!(
        computed == claimed,
        "candidate 0x{} carries params that hash to 0x{}; refusing to route reads by them",
        hex::encode(claimed),
        hex::encode(computed)
    );
    Ok(claimed)
}

/// Does `sigs` hold a genuine attestation by `me` over `digest_input` (the
/// pre-EIP-191 domain digest, e.g. `domain_id(CANCEL_PREFIX, id)`)?
///
/// Decided by RECOVERING each signature, never by the store's `signer` label
/// (audit 2026-10-02, L7-7 — the validator's round-5 fix). A store that puts
/// our address on a junk signature used to make this attester believe it had
/// already voted, so it never attested that transfer again and the quorum was
/// one short for good. Recovery is what the gate does with the bytes, so it is
/// the only meaningful answer to "have we voted".
pub fn attested_by(sigs: &[SignerSig], digest_input: &[u8; 32], me: &[u8; 20]) -> bool {
    let digest = bridge_solana::verify::eth_signed_digest(digest_input);
    sigs.iter().any(|s| {
        crate::gate::hex_bytes(&s.signature)
            .ok()
            .and_then(|b| crate::gate::recovered_address(&digest, &b))
            .is_some_and(|a| &a == me)
    })
}

/// Read the Solana destination marker for a submission.
async fn solana_destination_state(
    rpc: &RpcClient,
    program_id: &Pubkey,
    id: &[u8; 32],
) -> anyhow::Result<DestinationState> {
    let (executed, _) = Pubkey::find_program_address(&[b"executed", id], program_id);
    let acct = rpc.get_account_with_commitment(&executed, rpc.commitment()).await?.value;
    Ok(match acct {
        // Only a PDA the PROGRAM owns counts. An account someone else parked at
        // that address proves nothing about this gate's state.
        Some(a) if a.owner == *program_id && !a.data.is_empty() => DestinationState {
            executed: true,
            cancelled: a.data[0] == MARKER_CANCELLED,
        },
        _ => DestinationState::default(),
    })
}

/// Read the Solana `["sent", id]` origin record.
async fn solana_source_state(
    rpc: &RpcClient,
    program_id: &Pubkey,
    id: &[u8; 32],
) -> anyhow::Result<SolanaSourceRecord> {
    let (sent, _) = Pubkey::find_program_address(&[b"sent", id], program_id);
    let acct = rpc.get_account_with_commitment(&sent, rpc.commitment()).await?.value;
    Ok(solana_source_record(acct.as_ref().map(|a| (a.owner == *program_id, a.data.as_slice()))))
}

/// The cluster's own notion of now, from the Clock sysvar at the signing
/// commitment.
async fn solana_now(rpc: &RpcClient) -> anyhow::Result<i64> {
    let acct = rpc
        .get_account_with_commitment(&solana_sdk::sysvar::clock::id(), rpc.commitment())
        .await?
        .value
        .ok_or_else(|| anyhow::anyhow!("clock sysvar missing"))?;
    let clock: solana_sdk::clock::Clock = solana_sdk::account::from_account(&acct)
        .ok_or_else(|| anyhow::anyhow!("clock sysvar does not decode"))?;
    Ok(clock.unix_timestamp)
}

pub struct Attester {
    rpc: RpcClient,
    program_id: Pubkey,
    chain_id: u64,
    secret: libsecp256k1::SecretKey,
    signer_address: String,
    /// The address `secret` signs as — what our own attestations recover to.
    me: [u8; 20],
    poll: Duration,
    store: Store,
    /// `None` => no `[refund]` block: refunds only, never cancels.
    timeout_secs: Option<i64>,
    evm: BTreeMap<u64, GateReader>,
    /// Corridors already warned about (no reader / no timeout), so the log says
    /// it once per submission rather than every poll.
    warned: Mutex<HashSet<String>>,
}

impl Attester {
    pub fn new(
        cfg: &SourceChain,
        refund: Option<&RefundConfig>,
        secret_key: [u8; 32],
        signer_address: String,
        store: Store,
    ) -> anyhow::Result<Self> {
        let mut evm = BTreeMap::new();
        if let Some(r) = refund {
            for e in &r.evm {
                evm.insert(e.chain_id, GateReader::new(e)?);
            }
        }
        let secret = libsecp256k1::SecretKey::parse(&secret_key)
            .map_err(|_| anyhow::anyhow!("signer key is not a valid secp256k1 scalar"))?;
        let me = crate::gate::address_of(&libsecp256k1::PublicKey::from_secret_key(&secret));
        Ok(Attester {
            // Refund decisions release real funds, so read them at the same
            // commitment the scanner signs at — a rolled-back "not executed"
            // would let us attest a burn for a transfer that was in fact paid.
            rpc: RpcClient::new_with_commitment(cfg.rpc.clone(), commitment(&cfg.commitment)),
            program_id: Pubkey::from_str(&cfg.program_id)
                .map_err(|_| anyhow::anyhow!("program_id is not a valid pubkey"))?,
            chain_id: cfg.chain_id,
            secret,
            me,
            signer_address,
            poll: Duration::from_millis(cfg.poll_interval_ms.max(1000)),
            store,
            timeout_secs: refund.map(|r| r.timeout_secs),
            evm,
            warned: Mutex::new(HashSet::new()),
        })
    }

    pub async fn run(self) -> anyhow::Result<()> {
        info!(
            validator = %self.signer_address,
            chain_id = self.chain_id,
            evm_readers = self.evm.len(),
            timeout_secs = ?self.timeout_secs,
            "solana refund attester started"
        );
        if self.timeout_secs.is_none() {
            warn!(
                "no [refund] block — this attester will vote REFUND for observed burns but \
                 NEVER cancel: a cancel needs an on-chain age proof (timeout_secs + an EVM \
                 reader for the source or destination gate)"
            );
        }
        loop {
            if let Err(e) = self.tick().await {
                warn!(error = %e, "refund attestation tick failed; retrying");
            }
            tokio::time::sleep(self.poll).await;
        }
    }

    fn warn_once(&self, key: String, msg: &str) {
        let mut seen = self.warned.lock().unwrap_or_else(|p| p.into_inner());
        if seen.insert(key.clone()) {
            warn!(submission_id = %key, "{msg}");
        }
    }

    async fn tick(&self) -> anyhow::Result<()> {
        // Walk the queue a page at a time (audit 2026-09-16, H-6); a short page
        // is the end of it.
        let mut candidates: Vec<SubmissionRecord> = Vec::new();
        for p in 0..MAX_REFUND_PAGES {
            let page = self.store.refund_candidates(REFUND_PAGE, p * REFUND_PAGE).await?;
            let short = (page.len() as u64) < REFUND_PAGE;
            candidates.extend(page);
            if short {
                break;
            }
        }

        for rec in candidates {
            // L7-7: the corridor below routes every read, so it must be the one
            // the id actually commits to.
            let id = match bound_submission_id(&rec) {
                Ok(id) => id,
                Err(e) => {
                    warn!(submission_id = %rec.submission_id, error = %e, "refund candidate refused");
                    continue;
                }
            };

            let facts = if rec.chain_id_to == self.chain_id {
                self.evm_to_solana_facts(&rec.submission_id, &id, rec.chain_id_from).await
            } else if rec.chain_id_from == self.chain_id {
                self.solana_to_evm_facts(&rec.submission_id, &id, rec.chain_id_to).await
            } else {
                continue; // an EVM<->EVM corridor; the EVM validators own it
            };
            let Some((src, dst, aged_out)) = (match facts {
                Ok(f) => f,
                Err(e) => {
                    // Never guess. An unreadable chain means no vote.
                    warn!(submission_id = %rec.submission_id, error = %e, "cannot read chain state; not attesting");
                    continue;
                }
            }) else {
                continue;
            };

            let decision = decide(
                src.as_ref(),
                &dst,
                aged_out,
                attested_by(&rec.cancel_signatures, &domain_id(CANCEL_PREFIX, &id), &self.me),
                attested_by(&rec.refund_signatures, &domain_id(REFUND_PREFIX, &id), &self.me),
            );

            let (kind, prefix) = match decision {
                Decision::AttestCancel => ("cancel", CANCEL_PREFIX),
                Decision::AttestRefund => ("refund", REFUND_PREFIX),
                Decision::Skip(reason) => {
                    tracing::debug!(submission_id = %rec.submission_id, reason, "no attestation");
                    continue;
                }
            };

            let signature = sign(&self.secret, &domain_id(prefix, &id));
            match self
                .store
                .post_attestation(&rec.submission_id, kind, &self.signer_address, &signature)
                .await
            {
                Ok(()) => info!(
                    submission_id = %rec.submission_id,
                    kind,
                    chain_from = rec.chain_id_from,
                    chain_to = rec.chain_id_to,
                    "ATTESTED"
                ),
                Err(e) => warn!(submission_id = %rec.submission_id, kind, error = %e, "attestation rejected"),
            }
        }
        Ok(())
    }

    /// Solana is the DESTINATION. Burn facts from the Solana marker; age (and the
    /// wasted-work guards) from the EVM source gate when we have a reader for it.
    async fn evm_to_solana_facts(
        &self,
        sid: &str,
        id: &[u8; 32],
        chain_id_from: u64,
    ) -> anyhow::Result<Option<(Option<SourceState>, DestinationState, Option<bool>)>> {
        let dst = solana_destination_state(&self.rpc, &self.program_id, id).await?;
        let (src, aged_out) = match (self.timeout_secs, self.evm.get(&chain_id_from)) {
            (Some(timeout), Some(reader)) => {
                let s = reader.source_state(id).await?;
                let aged = if dst.cancelled { None } else { Some(reader.aged_out(id, timeout).await?) };
                (Some(SourceState { sent: s.sent, refunded: s.refunded }), aged)
            }
            _ => {
                if !dst.cancelled {
                    self.warn_once(
                        sid.to_string(),
                        &format!(
                            "EVM->Solana candidate from chain {chain_id_from}: no [[refund.evm]] reader \
                             (or no [refund].timeout_secs) for the SOURCE gate, so its age cannot be \
                             verified on-chain — cancel will NOT be attested (M-13)"
                        ),
                    );
                }
                (None, None)
            }
        };
        Ok(Some((src, dst, aged_out)))
    }

    /// Solana is the SOURCE (M-4). Burn facts from the EVM destination gate —
    /// without a reader for it we cannot see the destination at all and must not
    /// vote — age from the Solana `["sent", id]` record against the cluster clock.
    async fn solana_to_evm_facts(
        &self,
        sid: &str,
        id: &[u8; 32],
        chain_id_to: u64,
    ) -> anyhow::Result<Option<(Option<SourceState>, DestinationState, Option<bool>)>> {
        let Some(reader) = self.evm.get(&chain_id_to) else {
            self.warn_once(
                sid.to_string(),
                &format!(
                    "Solana->EVM candidate to chain {chain_id_to}: no [[refund.evm]] reader for the \
                     DESTINATION gate, so neither cancel nor refund can be attested by this process"
                ),
            );
            return Ok(None);
        };
        let d = reader.destination_state(id).await?;
        let dst = DestinationState { executed: d.executed, cancelled: d.cancelled };
        let src = solana_source_state(&self.rpc, &self.program_id, id).await?;
        let aged_out = match self.timeout_secs {
            Some(timeout) if !dst.cancelled && src.state.sent && !src.state.refunded => {
                Some(solana_aged_out(src.locked_at, solana_now(&self.rpc).await?, timeout))
            }
            Some(_) => None,
            None => None,
        };
        Ok(Some((Some(src.state), dst, aged_out)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn delivered() -> DestinationState {
        DestinationState { executed: true, cancelled: false }
    }
    fn burned() -> DestinationState {
        DestinationState { executed: true, cancelled: true }
    }
    fn untouched() -> DestinationState {
        DestinationState::default()
    }
    fn live_source() -> SourceState {
        SourceState { sent: true, refunded: false }
    }
    /// This process verified, on-chain, that the timeout has elapsed.
    const AGED: Option<bool> = Some(true);
    const FRESH: Option<bool> = Some(false);
    const UNKNOWN: Option<bool> = None;

    /// THE rule. A delivered transfer must never earn either attestation — a
    /// refund on top of a claim is the double-spend the two-phase design exists
    /// to prevent, and no timeout or store state may override an on-chain payout.
    #[test]
    fn a_delivered_transfer_is_never_attested() {
        for (c, r) in [(false, false), (true, false), (false, true), (true, true)] {
            for aged in [AGED, FRESH, UNKNOWN] {
                assert_eq!(
                    decide(Some(&live_source()), &delivered(), aged, c, r),
                    Decision::Skip("delivered on destination")
                );
                assert_eq!(decide(None, &delivered(), aged, c, r), Decision::Skip("delivered on destination"));
            }
        }
    }

    #[test]
    fn an_untouched_destination_earns_a_cancel_once_aged_on_chain() {
        assert_eq!(decide(Some(&live_source()), &untouched(), AGED, false, false), Decision::AttestCancel);
        assert_eq!(decide(None, &untouched(), AGED, false, false), Decision::AttestCancel);
    }

    /// THE M-13 rule. Appearing on the store's candidate list is not evidence of
    /// anything: until THIS process has established the age on-chain, it will not
    /// burn a transfer the keeper may still be about to deliver.
    #[test]
    fn a_store_nomination_alone_never_authorises_a_cancel() {
        assert_eq!(
            decide(Some(&live_source()), &untouched(), FRESH, false, false),
            Decision::Skip("unclaimed timeout has not elapsed (verified on-chain)")
        );
        // The same candidate becomes attestable once it has genuinely aged.
        assert_eq!(decide(Some(&live_source()), &untouched(), AGED, false, false), Decision::AttestCancel);
    }

    /// No reader for the source chain => the age is unknowable => no cancel. A
    /// process that cannot verify does not vote, whatever the store says.
    #[test]
    fn an_unverifiable_age_never_authorises_a_cancel() {
        assert_eq!(
            decide(None, &untouched(), UNKNOWN, false, false),
            Decision::Skip("unclaimed timeout cannot be verified on-chain; not attesting")
        );
        assert_eq!(
            decide(Some(&live_source()), &untouched(), UNKNOWN, false, false),
            Decision::Skip("unclaimed timeout cannot be verified on-chain; not attesting")
        );
    }

    /// The finding's actual attack: a DB that flags everything eligible the
    /// moment it is created must not be able to force a fleet-wide cancel of
    /// healthy in-flight transfers.
    #[test]
    fn a_compromised_store_cannot_shorten_the_window() {
        for already_cancel in [false, true] {
            for aged in [FRESH, UNKNOWN] {
                let d = decide(Some(&live_source()), &untouched(), aged, already_cancel, false);
                assert!(matches!(d, Decision::Skip(_)), "a not-yet-aged transfer must never be cancelled, got {d:?}");
            }
        }
    }

    /// Refund follows an on-chain burn rather than a timer, so it does not
    /// re-check the age — and it does not need a source reader either: the source
    /// gate itself refuses `NotSent`/`AlreadyRefunded`, so the worst case without
    /// one is a wasted attestation. This is what lets the EVM validators and this
    /// process each vote REFUND for a Solana->EVM burn (M-4).
    #[test]
    fn a_burned_destination_earns_a_refund_without_an_age_check_or_source_reader() {
        assert_eq!(decide(Some(&live_source()), &burned(), FRESH, true, false), Decision::AttestRefund);
        assert_eq!(decide(None, &burned(), UNKNOWN, false, false), Decision::AttestRefund);
    }

    #[test]
    fn refund_requires_the_burn_to_be_on_chain_first() {
        assert_eq!(
            decide(Some(&live_source()), &untouched(), AGED, true, false),
            Decision::Skip("cancel already attested by us")
        );
        assert_eq!(decide(Some(&live_source()), &burned(), AGED, true, false), Decision::AttestRefund);
    }

    #[test]
    fn we_do_not_re_attest_our_own_vote() {
        assert_eq!(
            decide(Some(&live_source()), &untouched(), AGED, true, false),
            Decision::Skip("cancel already attested by us")
        );
        assert_eq!(
            decide(Some(&live_source()), &burned(), AGED, false, true),
            Decision::Skip("refund already attested by us")
        );
    }

    /// Source-side guards, when a reader exists: already repaid, or never locked
    /// there at all (a forged candidate), earn nothing.
    #[test]
    fn a_refunded_or_never_sent_source_earns_nothing() {
        let repaid = SourceState { sent: true, refunded: true };
        let ghost = SourceState { sent: false, refunded: false };
        for src in [repaid, ghost] {
            for dst in [untouched(), burned()] {
                assert!(matches!(decide(Some(&src), &dst, AGED, false, false), Decision::Skip(_)));
            }
        }
    }

    /// A marker PDA owned by anyone but the program proves nothing — treating it
    /// as state would let a squatter fake "delivered" and block a legitimate
    /// refund forever.
    #[test]
    fn only_a_program_owned_marker_counts() {
        let foreign = DestinationState::default();
        assert!(!foreign.executed, "a non-program-owned account is not state");
        assert_eq!(decide(Some(&live_source()), &foreign, AGED, false, false), Decision::AttestCancel);
    }

    // --- L7-7: id binding and recovered-address dedupe ----------------------

    fn word(v: u64) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&v.to_be_bytes());
        w
    }

    /// `abi.encode(AutoParamsTo{fee, flags, fallback, data})`, by hand.
    fn auto_blob(fee: u64, flags: u64, fallback: &[u8], data: &[u8]) -> Vec<u8> {
        let padded = |b: &[u8]| b.len().div_ceil(32) * 32;
        let mut out = Vec::new();
        out.extend_from_slice(&word(0x20));
        out.extend_from_slice(&word(fee));
        out.extend_from_slice(&word(flags));
        out.extend_from_slice(&word(0x80));
        out.extend_from_slice(&word(0x80 + 32 + padded(fallback) as u64));
        for b in [fallback, data] {
            out.extend_from_slice(&word(b.len() as u64));
            let mut p = b.to_vec();
            p.resize(padded(b), 0);
            out.extend_from_slice(&p);
        }
        out
    }

    /// A record whose id really is the hash of its own params, EVM -> Solana.
    fn bound_record(auto_params: &[u8]) -> SubmissionRecord {
        use bridge_solana::hash::{amount_word, submission_id, submission_id_with_auto};
        let domain = [0xd0u8; 32];
        let debridge = [0x0du8; 32];
        let receiver = [0x5au8; 32];
        let native_sender = [0x77u8; 20];
        let (from, to, nonce, amount, dec) = (11155111u64, 7_565_164u64, 42u64, 1_000_000u64, 6u8);
        let id = match bridge_solana::relayer::decode_evm_auto_params(auto_params).unwrap() {
            None => submission_id(&domain, &debridge, dec, &amount_word(amount as u128), from, to, nonce, &receiver),
            Some(w) => submission_id_with_auto(
                &domain, &debridge, dec, &amount_word(amount as u128), from, to, nonce, &receiver,
                &bridge_solana::relayer::wire_to_auto(&w, &native_sender),
            ),
        };
        SubmissionRecord {
            submission_id: format!("0x{}", hex::encode(id)),
            bridge_domain: format!("0x{}", hex::encode(domain)),
            debridge_id: format!("0x{}", hex::encode(debridge)),
            amount: amount.to_string(),
            bridge_decimals: Some(dec),
            chain_id_from: from,
            chain_id_to: to,
            nonce,
            receiver: format!("0x{}", hex::encode(receiver)),
            auto_params: format!("0x{}", hex::encode(auto_params)),
            native_sender: format!("0x{}", hex::encode(native_sender)),
            token: String::new(),
            signatures: vec![],
            cancel_signatures: vec![],
            refund_signatures: vec![],
        }
    }

    /// L7-7. A record's corridor routes every read, so it must be the corridor
    /// its id commits to. A real id re-paired with another destination or source
    /// (the reads would go to a gate that never heard of it and read
    /// "untouched") is refused, as is anything that does not hash at all.
    #[test]
    fn a_candidate_whose_params_do_not_hash_to_its_id_is_refused() {
        for blob in [Vec::new(), auto_blob(5, 1, &[0xfa; 20], b"payload")] {
            let good = bound_record(&blob);
            assert_eq!(
                bound_submission_id(&good).expect("premise: the fixture binds"),
                hex32(&good.submission_id).unwrap()
            );
            let rerouted = SubmissionRecord { chain_id_to: 84532, ..good.clone() };
            assert!(bound_submission_id(&rerouted).is_err(), "a different destination must not be read");
            let resourced = SubmissionRecord { chain_id_from: 1, ..good.clone() };
            assert!(bound_submission_id(&resourced).is_err(), "a different source must not be read");
            let other_domain = SubmissionRecord { bridge_domain: format!("0x{}", "11".repeat(32)), ..good.clone() };
            assert!(bound_submission_id(&other_domain).is_err());
            let no_scale = SubmissionRecord { bridge_decimals: None, ..good.clone() };
            assert!(bound_submission_id(&no_scale).is_err(), "no scale, no id");
        }
        // With-auto params dropped (or swapped for "none") are a different id.
        let with_auto = bound_record(&auto_blob(5, 1, &[0xfa; 20], b"payload"));
        assert!(bound_submission_id(&SubmissionRecord { auto_params: "0x".into(), ..with_auto.clone() }).is_err());
        assert!(bound_submission_id(&SubmissionRecord { auto_params: "0xdead".into(), ..with_auto }).is_err());
        let garbage = SubmissionRecord { submission_id: "0xnothex".into(), ..bound_record(&[]) };
        assert!(bound_submission_id(&garbage).is_err());
    }

    /// L7-7. "Have we already voted?" is answered by recovering the signature
    /// over the right domain, never by the store's `signer` label.
    #[test]
    fn our_vote_is_recognised_by_recovery_not_by_label() {
        let secret = libsecp256k1::SecretKey::parse(&[0x42u8; 32]).unwrap();
        let me = crate::gate::address_of(&libsecp256k1::PublicKey::from_secret_key(&secret));
        let my_label = crate::gate::evm_address(&secret);
        let id = [0x99u8; 32];
        let cancel = domain_id(CANCEL_PREFIX, &id);
        let refund = domain_id(REFUND_PREFIX, &id);

        // Genuine: our signature over the cancel digest.
        let real = SignerSig { signer: my_label.clone(), signature: sign(&secret, &cancel) };
        assert!(attested_by(std::slice::from_ref(&real), &cancel, &me));
        // It is NOT a refund vote: the domains are distinct.
        assert!(!attested_by(std::slice::from_ref(&real), &refund, &me));
        // Our label on junk, or on someone else's signature: not our vote — this
        // is what used to silence the attester for good.
        let other = libsecp256k1::SecretKey::parse(&[0x43u8; 32]).unwrap();
        let forged = [
            SignerSig { signer: my_label.clone(), signature: format!("0x{}", "00".repeat(65)) },
            SignerSig { signer: my_label.clone(), signature: sign(&other, &cancel) },
            SignerSig { signer: my_label.clone(), signature: "not hex".into() },
        ];
        assert!(!attested_by(&forged, &cancel, &me));
        // Our genuine signature under someone else's label still counts: the
        // label is not what the gate reads.
        let relabelled = SignerSig { signer: "0xsomebody".into(), signature: sign(&secret, &cancel) };
        assert!(attested_by(&[relabelled], &cancel, &me));
    }

    // --- the Solana age rule (M-4 / M-13) -----------------------------------

    #[test]
    fn solana_age_is_measured_in_cluster_time() {
        let locked = 1_700_000_000;
        assert!(!solana_aged_out(locked, locked + 3599, 3600), "one second short is short");
        assert!(solana_aged_out(locked, locked + 3600, 3600));
        assert!(solana_aged_out(locked, locked + 999_999, 3600));
        // A clock that appears to run backwards (or a record from the future)
        // is never "aged".
        assert!(!solana_aged_out(locked, locked - 1, 3600));
    }

    /// A record with no lock time — the pre-round-4 layout, or a zeroed field —
    /// cannot be shown aged. Fail closed rather than treat 0 as "1970, so
    /// ancient".
    #[test]
    fn a_record_without_a_lock_time_is_never_aged() {
        assert!(!solana_aged_out(0, 1_700_000_000, 3600));
        assert!(!solana_aged_out(-5, 1_700_000_000, 3600));
    }

    // --- the ["sent", id] record interpretation -----------------------------

    fn record_bytes(amount: u64, locked_at: i64) -> Vec<u8> {
        use borsh::BorshSerialize;
        let rec = bridge_solana::relayer::SentRecord {
            debridge_id: if amount == 0 { [0u8; 32] } else { [9u8; 32] },
            sender: [1u8; 32],
            source_token: [2u8; 32],
            mint: [3u8; 32],
            amount,
            locked_at,
        };
        let mut out = Vec::new();
        rec.serialize(&mut out).unwrap();
        out
    }

    #[test]
    fn a_live_sent_record_is_sent_and_carries_its_lock_time() {
        let data = record_bytes(500, 1_700_000_000);
        let r = solana_source_record(Some((true, &data)));
        assert_eq!(r.state, SourceState { sent: true, refunded: false });
        assert_eq!(r.locked_at, 1_700_000_000);
    }

    /// `process_refund` zeroes the record on payout: that is "refunded", and it
    /// must not be mistaken for "never sent" (which would be a forged candidate)
    /// nor for a live record.
    #[test]
    fn a_zeroed_sent_record_is_refunded() {
        let zeroed = vec![0u8; bridge_solana::relayer::SENT_RECORD_LEN];
        let r = solana_source_record(Some((true, &zeroed)));
        assert_eq!(r.state, SourceState { sent: true, refunded: true });
        assert_eq!(r.locked_at, 0);
    }

    /// A record from before the upgrade proves the lock but not WHEN: it is
    /// `sent`, and its age can never be shown, so it earns a refund (after an
    /// observed burn) but never a cancel from this process.
    #[test]
    fn a_legacy_record_is_sent_but_never_aged() {
        let data = record_bytes(500, 1_700_000_000);
        let legacy = &data[..bridge_solana::relayer::LEGACY_SENT_RECORD_LEN];
        let r = solana_source_record(Some((true, legacy)));
        assert_eq!(r.state, SourceState { sent: true, refunded: false });
        assert_eq!(r.locked_at, 0);
        assert!(!solana_aged_out(r.locked_at, i64::MAX, 1), "unknown lock time is never aged");
    }

    /// No account, a foreign-owned account, or a wrong-sized one: this gate never
    /// sent it. Only program-owned state of a known layout is evidence.
    #[test]
    fn missing_foreign_or_malformed_records_are_not_sent() {
        let data = record_bytes(500, 1_700_000_000);
        for account in [None, Some((false, data.as_slice())), Some((true, &data[..data.len() - 9]))] {
            let r = solana_source_record(account);
            assert_eq!(r.state, SourceState { sent: false, refunded: false });
            assert_eq!(r.locked_at, 0);
        }
    }
}
