//! The Solana source scanner: the missing runner from finding M-3.
//!
//! Does exactly what the EVM validator's `scan_source` does, against a different
//! VM: poll for the gate's transactions, decode each `Sent` event, INDEPENDENTLY
//! recompute the submissionId, sign it only if it matches, and store the
//! signature. It signs with the same secp256k1 key the validator uses on the EVM
//! side, so one validator set attests for both chains.
//!
//! The three safety rules carried over from the EVM scanner:
//!   * **finality** — read only at `finalized`, so a fork cannot discard a `Sent`
//!     after the destination has paid out (enforced in [`crate::config`]);
//!   * **never sign what you cannot reproduce** — a mismatch between the emitted
//!     and recomputed id means a lying RPC or a divergent program. It is never
//!     signed; since audit round 6 (LOW) it is QUARANTINED — logged at ERROR,
//!     persisted beside the cursor, and scanned past — rather than a hard stop
//!     that wedged the scanner on that transaction forever (see
//!     [`Scanner::process_line`]). The one exception is an event from a NEWER
//!     program version, which still halts: that is systemic, not per-event;
//!   * **the allowlist gates signing, not just claiming** — see below.
//!
//! ## Why the allowlist has to be enforced HERE
//!
//! This scanner used to sign every `Sent` it could authenticate, leaving the
//! allowlist to the EVM keeper's pre-claim check. That made the control
//! asymmetric in a way nothing surfaced: on an EVM→EVM corridor a de-listed
//! token never reaches quorum, because each validator withholds its signature;
//! on Solana→EVM it reached quorum anyway, and `Gate.claim` is `external` with
//! no access control and no notion of an off-chain list — it checks validator
//! signatures and `tokenOf[debridgeId] != 0`, nothing more. The signatures are
//! public (the GraphQL API serves the raw 65 bytes so a user can self-claim), so
//! *anyone* could complete a transfer the operator had just de-listed. The
//! keeper's check only ever bound the keeper.
//!
//! Not a fund-loss bug — the gate still releases only registered assets against
//! a real quorum — but an operational kill-switch that silently did nothing in
//! one direction, which is worse than no kill-switch, because it is reached for
//! during an incident. Withholding the signature is the only thing that actually
//! stops the transfer, so it happens here.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::str::FromStr;
use std::time::Duration;

use tokio::sync::Mutex;

use anyhow::Context as _;
use bridge_solana::account::{self, AssetAccount};
use bridge_solana::gate::Sent;
use bridge_solana::hash::{amount_word, submission_id, submission_id_with_auto};
use bridge_solana::relayer::{
    gate_program_data_lines, parse_sent_event_line, verify_sent_record, SentEvent, PROGRAM_DATA_PREFIX,
    SENT_EVENT_VERSION,
};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_client::rpc_client::GetConfirmedSignaturesForAddress2Config;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use solana_transaction_status::UiTransactionEncoding;
use tracing::{error, info, warn};

use crate::config::SourceChain;
use crate::evm::GateReader;
use crate::gate::{commitment, decode_config_view, evm_address, sign};
use crate::state::Cursor;
use crate::store::{Allowlist, SignerSig, Store, SubmissionRecord};

/// One entry from `getSignaturesForAddress`.
type SignatureEntry = solana_client::rpc_response::RpcConfirmedTransactionStatusWithSignature;

/// Pagination depth for [`Scanner::collect_since_cursor`]. 100 pages × the
/// default 100-signature batch = 10k transactions of backlog before an operator
/// has to intervene.
const MAX_PAGES: usize = 100;

/// What to do after reading one page of signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PageAction {
    /// The page reached the cursor (or the start of history): the collected range
    /// is contiguous and safe to process.
    Complete,
    /// The page was full, so older signatures above the cursor remain unread.
    KeepWalking,
    /// Full pages all the way to [`MAX_PAGES`] — the backlog is deeper than we
    /// will walk. Fail rather than process a range with a hole under it.
    TooDeep,
}

/// Whether a walk must reach the start of its range before the range is usable:
/// always with a cursor, and — unless the operator explicitly chose
/// `start_at_tip` — without one too, so a lost or never-written cursor replays
/// history instead of silently skipping it.
fn walks_to_start(has_cursor: bool, start_at_tip: bool) -> bool {
    has_cursor || !start_at_tip
}

/// The pagination rule, extracted so the thing that actually went wrong is
/// testable without an RPC.
///
/// The bug this encodes: a page that comes back FULL is the RPC saying "I hit
/// `limit` before I hit `until`" — i.e. there is more history between this page
/// and the cursor. Treating a full page as the end of the range is what silently
/// skipped events.
fn next_page_action(
    page_len: usize,
    max_batch: usize,
    walk_to_start: bool,
    page_index: usize,
) -> PageAction {
    if page_len < max_batch {
        return PageAction::Complete; // reached `until`, or ran out of history
    }
    if !walk_to_start {
        return PageAction::Complete; // no cursor AND `start_at_tip`: the operator's choice
    }
    if page_index + 1 >= MAX_PAGES {
        return PageAction::TooDeep;
    }
    PageAction::KeepWalking
}

/// Why a decoded event can never be signed by this scanner, or `Ok` if the
/// event-intrinsic checks pass (pure; the RPC-backed origin proof comes later).
///
/// Both checks are PERMANENT properties of the event: re-reading the same
/// transaction yields the same answer. That is what makes them quarantine
/// material rather than retry material (audit round 6, LOW).
fn signable(sent: &Sent, bridge_domain: &[u8; 32], chain_id: u64) -> Result<(), String> {
    // Never sign an id we cannot reproduce ourselves.
    let computed = recompute(sent, bridge_domain);
    if computed != sent.submission_id {
        return Err(format!(
            "submissionId MISMATCH: emitted {} computed {} — refusing to sign",
            hex::encode(sent.submission_id),
            hex::encode(computed)
        ));
    }
    // The gate binds its own chain id into the hash; if it disagrees with our
    // config we are pointed at the wrong program or the wrong cluster. (A
    // config-wide mismatch is refused at startup — `load_bridge_domain` checks
    // the gate's own `chain_id` — so reaching this is a per-event anomaly.)
    if sent.chain_id_from != chain_id {
        return Err(format!(
            "event chain_id_from {} != configured {} — refusing to sign",
            sent.chain_id_from, chain_id
        ));
    }
    Ok(())
}

/// The version byte of a tagged `Program data:` payload, read WITHOUT decoding
/// the rest — so it is available even when a future layout no longer
/// deserializes as today's `SentEvent`. `version` is the struct's first field.
fn payload_version(line: &str) -> Option<u8> {
    use base64::Engine as _;
    let rest = line.trim().strip_prefix(PROGRAM_DATA_PREFIX)?;
    let payload = rest.split_whitespace().nth(1)?;
    base64::engine::general_purpose::STANDARD.decode(payload).ok()?.first().copied()
}

/// Recompute a submissionId from a decoded event, exactly as the program did.
///
/// This is THE check: we sign the id we derived, never the one we were handed.
fn recompute(sent: &Sent, bridge_domain: &[u8; 32]) -> [u8; 32] {
    match sent.auto.as_ref() {
        None => submission_id(
            bridge_domain,
            &sent.debridge_id,
            sent.bridge_decimals,
            &amount_word(sent.amount as u128),
            sent.chain_id_from,
            sent.chain_id_to,
            sent.nonce,
            &sent.receiver,
        ),
        Some(auto) => submission_id_with_auto(
            bridge_domain,
            &sent.debridge_id,
            sent.bridge_decimals,
            &amount_word(sent.amount as u128),
            sent.chain_id_from,
            sent.chain_id_to,
            sent.nonce,
            &sent.receiver,
            auto,
        ),
    }
}

/// Whether the allowlist permits attesting this transfer.
///
/// Split out from the I/O so the opt-in semantics are unit-testable, exactly as
/// the refund loop splits `decide` from its chain reads.
///
/// `None` means enforcement is off — reserved for the case where no allowlist
/// could be established at all. It is deliberately NOT what a failed fetch
/// produces: see the fail-closed skip in `tick`.
fn allowlist_permits(
    allowlist: Option<&Allowlist>,
    debridge_id: &str,
    chain_from: u64,
    chain_to: u64,
) -> bool {
    match allowlist {
        None => true,
        Some(a) => a.token_allowed(debridge_id) && a.chain_allowed(chain_from, chain_to),
    }
}

pub struct Scanner {
    rpc: RpcClient,
    program_id: Pubkey,
    /// Deployment generation, read from the gate's `["config"]` PDA at startup
    /// rather than configured — same reasoning as the EVM validator. Signing
    /// under a stale domain would produce ids the gate never derives.
    bridge_domain: [u8; 32],
    cfg: SourceChain,
    secret: libsecp256k1::SecretKey,
    signer_address: String,
    store: Store,
    cursor: Cursor,
    /// Refetched every tick, so an operator de-listing a token takes effect
    /// across the fleet without restarting anything.
    allowlist: Option<Allowlist>,
    /// EVM destination gates this scanner can read, for the H-2 bridge-decimals
    /// cross-check. A peer with no reader cannot be verified, so transfers to it
    /// are not signed — see [`Scanner::scale_agrees`].
    evm_gates: BTreeMap<u64, GateReader>,
    /// `(chain_id_to, debridge_id) -> destination scale`. Registrations are
    /// write-once, so a successful read is good forever; failures are never
    /// cached, or one RPC fault would become a permanent refusal.
    scale_cache: Mutex<HashMap<(u64, [u8; 32]), u8>>,
    /// Chains already warned about, so an unconfigured peer does not log once
    /// per transfer.
    scale_warned: Mutex<HashSet<u64>>,
}

impl Scanner {
    pub fn new(
        cfg: SourceChain,
        secret_key: [u8; 32],
        store: Store,
        evm_gates: BTreeMap<u64, GateReader>,
    ) -> anyhow::Result<Self> {
        let commitment = commitment(&cfg.commitment);
        let secret = libsecp256k1::SecretKey::parse(&secret_key)
            .map_err(|_| anyhow::anyhow!("signer key is not a valid secp256k1 scalar"))?;
        let signer_address = evm_address(&secret);
        let cursor = Cursor::load_or_init(&cfg.state_file)?;
        Ok(Scanner {
            rpc: RpcClient::new_with_commitment(cfg.rpc.clone(), commitment),
            program_id: Pubkey::from_str(&cfg.program_id)
                .map_err(|_| anyhow::anyhow!("program_id is not a valid pubkey"))?,
            bridge_domain: [0u8; 32],
            evm_gates,
            scale_cache: Mutex::new(HashMap::new()),
            scale_warned: Mutex::new(HashSet::new()),
            cfg,
            secret,
            signer_address,
            store,
            cursor,
            allowlist: None,
        })
    }

    pub fn signer_address(&self) -> &str {
        &self.signer_address
    }

    /// Read `bridge_domain` out of the gate's `["config"]` PDA.
    ///
    /// DESERIALIZED, not sliced at a byte offset. An earlier version took bytes
    /// 32..64 on the assumption that `bridge_domain` follows `owner` directly —
    /// the same assumption that broke the claim submitter when a field was
    /// inserted, silently yielding a plausible-looking 32 bytes from the wrong
    /// place. Signing under a wrong domain produces ids no gate ever derives, so
    /// the failure would be total and completely silent. [`crate::gate::ConfigView`] is the
    /// single mirrored layout; a drift there is now an error everywhere at once.
    async fn load_bridge_domain(&mut self) -> anyhow::Result<()> {
        let (config_pda, _) = Pubkey::find_program_address(&[b"config"], &self.program_id);
        let account = self
            .rpc
            .get_account(&config_pda)
            .await
            .with_context(|| format!("reading gate config PDA {config_pda}"))?;
        anyhow::ensure!(
            account.owner == self.program_id,
            "config PDA {config_pda} is owned by {}, not the gate program",
            account.owner
        );
        let view = decode_config_view(&mut &account.data[..])
            .with_context(|| format!("decoding gate config PDA {config_pda}"))?;
        // Audit round 6, LOW: a wrong `[source].chain_id` used to surface as a
        // per-event `chain_id_from` refusal that wedged the scanner. Events are
        // now quarantined and scanned PAST instead — so a config-wide mismatch
        // must be refused here, up front, or every transfer would be skipped
        // (loudly, but irrecoverably once the cursor moved). The gate stamps
        // `chain_id_from` from this very field.
        anyhow::ensure!(
            view.chain_id == self.cfg.chain_id,
            "gate config PDA {config_pda} carries chain_id {} but [source].chain_id is {} — \
             wrong program, wrong cluster, or wrong config; refusing to scan",
            view.chain_id,
            self.cfg.chain_id
        );
        let domain = view.bridge_domain;
        anyhow::ensure!(
            domain != [0u8; 32],
            "gate reports a zero bridge_domain — it predates the deployment-domain fix and \
             its attestations would be replayable across deployments"
        );
        self.bridge_domain = domain;
        Ok(())
    }

    /// Poll forever. Transient RPC failures back off and retry rather than kill
    /// the loop; a batch that fails to store leaves the cursor put so the same
    /// range is re-scanned (the store's upsert is idempotent).
    pub async fn run(mut self) -> anyhow::Result<()> {
        let retry = Duration::from_millis(self.cfg.poll_interval_ms.max(500));

        // Before signing anything, learn which deployment generation this gate
        // belongs to. Retried rather than fatal so a cold RPC doesn't kill the
        // process, but the loop below is never entered with a zero domain.
        while let Err(e) = self.load_bridge_domain().await {
            warn!(error = %e, program = %self.program_id, "reading the gate's bridge_domain failed; retrying");
            tokio::time::sleep(retry).await;
        }

        info!(
            validator = %self.signer_address,
            program = %self.program_id,
            bridge_domain = %hex::encode(self.bridge_domain),
            commitment = %self.cfg.commitment,
            resume_after = ?self.cursor.last_signature,
            "solana source scanner started"
        );

        loop {
            match self.tick().await {
                Ok(n) if n > 0 => info!(processed = n, "handled Sent events"),
                Ok(_) => {}
                Err(e) => warn!(error = %e, "scan tick failed; retrying"),
            }
            tokio::time::sleep(retry).await;
        }
    }

    /// Every signature newer than the cursor, oldest-first.
    ///
    /// **This has to paginate.** `getSignaturesForAddress` walks BACKWARDS from
    /// the tip (or from `before`) and stops at `until` *or* at `limit`, whichever
    /// comes first — so a single call on a backlog larger than `limit` returns the
    /// NEWEST `limit` signatures and silently omits the older ones sitting right
    /// above the cursor. Processing that page and advancing the cursor to its
    /// newest entry would skip the omitted range **permanently**: those `Sent`
    /// events would never be signed, and the transfers behind them would never
    /// reach quorum. That is H-3's "cursor advanced past unhandled logs", one
    /// layer down.
    ///
    /// So we walk back page by page until a page reaches the cursor, and only
    /// then hand the caller a contiguous range. If the backlog is deeper than
    /// `max_batch * MAX_PAGES` we return an error and leave the cursor put: the
    /// next tick retries the same range. Falling behind is recoverable; a hole is
    /// not.
    async fn collect_since_cursor(&self) -> anyhow::Result<Vec<SignatureEntry>> {
        let until = self
            .cursor
            .last_signature
            .as_deref()
            .and_then(|s| Signature::from_str(s).ok());

        let mut newest_first: Vec<SignatureEntry> = Vec::new();
        let mut before: Option<Signature> = None;

        for page in 0..MAX_PAGES {
            let sigs = self
                .rpc
                .get_signatures_for_address_with_config(
                    &self.program_id,
                    GetConfirmedSignaturesForAddress2Config {
                        before,
                        until,
                        limit: Some(self.cfg.max_batch),
                        commitment: Some(self.rpc.commitment()),
                    },
                )
                .await?;

            let walk = walks_to_start(until.is_some(), self.cfg.start_at_tip);
            let action = next_page_action(sigs.len(), self.cfg.max_batch, walk, page);
            let oldest = sigs.last().map(|s| s.signature.clone());
            newest_first.extend(sigs);

            match action {
                PageAction::Complete => {
                    if until.is_none() && !newest_first.is_empty() {
                        if self.cfg.start_at_tip {
                            warn!(
                                "no cursor and [source].start_at_tip = true — starting from the \
                                 current tip; nothing older will ever be signed by this relayer"
                            );
                        } else {
                            warn!(
                                transactions = newest_first.len(),
                                "no cursor — replaying the program's full history (signing is \
                                 idempotent). Set [source].start_at_tip = true only if older \
                                 transfers are known to be settled"
                            );
                        }
                    }
                    return Ok(newest_first.into_iter().rev().collect());
                }
                PageAction::TooDeep if until.is_none() => anyhow::bail!(
                    "no cursor at {} and the program's history exceeds {} signatures; refusing \
                     to guess where to start — restore the state file, or set \
                     [source].start_at_tip = true if every older transfer is known to be settled",
                    self.cfg.state_file,
                    MAX_PAGES * self.cfg.max_batch
                ),
                PageAction::TooDeep => anyhow::bail!(
                    "backlog exceeds {} signatures without reaching the cursor; refusing to \
                     advance past unscanned history — raise max_batch or investigate the stall",
                    MAX_PAGES * self.cfg.max_batch
                ),
                PageAction::KeepWalking => {}
            }

            before = match oldest.as_deref().and_then(|s| Signature::from_str(s).ok()) {
                Some(s) => Some(s),
                None => anyhow::bail!("RPC returned an unparseable signature while paginating"),
            };
        }
        unreachable!("the loop returns or bails on its last iteration")
    }

    async fn tick(&mut self) -> anyhow::Result<usize> {
        // Allowlist for this tick, refetched so a de-listing propagates without a
        // restart. FAIL-CLOSED, mirroring the EVM validator: a fetch failure ends
        // the tick with the cursor untouched, so we never sign against a stale
        // view of what is permitted. Falling behind is recoverable; signing a
        // transfer the operator has just de-listed is not — the signature is
        // public the moment it lands, and anyone can then claim on it.
        self.allowlist = Some(
            self.store
                .allowlist()
                .await
                .context("fetching the allowlist; skipping tick rather than signing on a stale view")?,
        );

        // Oldest-first, so the nonce sequence and the cursor advance monotonically.
        let entries = self.collect_since_cursor().await?;
        if entries.is_empty() {
            return Ok(0);
        }

        let mut handled = 0usize;
        for entry in &entries {
            if entry.err.is_some() {
                // A failed tx emitted no committed event, but it still counts as
                // scanned — the cursor must move past it or the next tick re-reads
                // the same range forever.
                self.cursor.last_signature = Some(entry.signature.clone());
                self.cursor.save(&self.cfg.state_file)?;
                continue;
            }
            let signature = Signature::from_str(&entry.signature)?;
            let tx = self
                .rpc
                .get_transaction_with_config(
                    &signature,
                    solana_client::rpc_config::RpcTransactionConfig {
                        encoding: Some(UiTransactionEncoding::Json),
                        commitment: Some(self.rpc.commitment()),
                        max_supported_transaction_version: Some(0),
                    },
                )
                .await?;

            let logs = tx
                .transaction
                .meta
                .as_ref()
                .and_then(|m| Option::<Vec<String>>::from(m.log_messages.clone()))
                .unwrap_or_default();

            // ATTRIBUTION FIRST. A transaction's logs are the concatenation of
            // every program that ran in it, and `getSignaturesForAddress` returns
            // transactions that merely MENTION the gate. Parsing all of them would
            // let any program in the transaction dictate what this validator
            // signs. Keep only the lines the gate itself emitted.
            let gate = self.program_id.to_string();
            for line in gate_program_data_lines(&logs, &gate) {
                if self.process_line(line, &entry.signature).await? {
                    handled += 1;
                }
            }

            // Advance only after the whole transaction is durably handled.
            self.cursor.last_signature = Some(entry.signature.clone());
            self.cursor.save(&self.cfg.state_file)?;
        }
        Ok(handled)
    }

    /// Handle one gate-attributed log line from transaction `tx`. `Ok(true)`
    /// means an event was signed and stored; `Ok(false)` means there was nothing
    /// to sign (not our event, withheld, or quarantined); `Err` is transient and
    /// leaves the cursor put so the whole transaction is re-read next tick.
    ///
    /// Audit round 6, LOW — undecodable events used to wedge the scanner. A bad
    /// version, a submissionId that does not reproduce, or a foreign
    /// `chain_id_from` each `bail!`ed with the cursor pinned, so every later
    /// tick re-read the same transaction and failed the same way: ONE bad event
    /// stopped this validator attesting for every Solana transfer after it.
    ///
    /// Now they are QUARANTINED: never signed (those refusals are the point, and
    /// `handle` still re-checks as a backstop), logged at ERROR with the tx and
    /// reason, persisted in the cursor file, and scanned past. The security
    /// cost is bounded to the event itself: it was never going to be signed, so
    /// skipping it withholds exactly one attestation — and a transfer that
    /// cannot reach quorum is what the cancel/refund path exists for. Nothing
    /// here weakens the `["sent", id]` origin proof; quarantine happens only on
    /// the path that REFUSES to sign.
    ///
    /// Why persisted, not just logged: the cursor alone would claim these
    /// transactions were handled. The list beside it is the durable record an
    /// operator (or the refund tooling) can audit after the log has rotated.
    ///
    /// The exception is an event from a NEWER program version. That is not a
    /// bad event but an upgraded gate ahead of this relayer — every subsequent
    /// event would be skipped too, irrecoverably once the cursor moved. It
    /// still halts, loudly, and resumes cleanly once the relayer is upgraded.
    /// (An OLDER version — e.g. replaying pre-upgrade history — is quarantined.)
    async fn process_line(&mut self, line: &str, tx: &str) -> anyhow::Result<bool> {
        let ahead = |v: u8| {
            anyhow::anyhow!(
                "BRIDGE_SENT in tx {tx} is event version {v}, newer than this relayer's \
                 {SENT_EVENT_VERSION} — the gate program was upgraded; upgrade the relayer. \
                 Halting rather than scanning past events it cannot read"
            )
        };
        let event = match parse_sent_event_line(line) {
            None => return Ok(false), // not our event
            Some(Ok(event)) => event,
            Some(Err(e)) => {
                if let Some(v) = payload_version(line).filter(|v| *v > SENT_EVENT_VERSION) {
                    return Err(ahead(v));
                }
                self.quarantine(tx, &format!("malformed BRIDGE_SENT: {e}"))?;
                return Ok(false);
            }
        };
        if event.version > SENT_EVENT_VERSION {
            return Err(ahead(event.version));
        }
        let sent = match event.to_sent() {
            Ok(sent) => sent,
            Err(e) => {
                self.quarantine(tx, &format!("undecodable BRIDGE_SENT: {e}"))?;
                return Ok(false);
            }
        };
        if let Err(reason) = signable(&sent, &self.bridge_domain, self.cfg.chain_id) {
            self.quarantine(tx, &reason)?;
            return Ok(false);
        }
        self.handle(&event, &sent, tx).await
    }

    /// Record a never-signable event and move on (see [`Self::process_line`]).
    /// Logged once per `(tx, reason)`; a transient failure later in the same
    /// transaction re-reads it without a duplicate entry or line.
    fn quarantine(&mut self, tx: &str, reason: &str) -> anyhow::Result<()> {
        if self.cursor.quarantine(tx, reason) {
            error!(
                tx,
                reason,
                state_file = %self.cfg.state_file,
                "QUARANTINED gate event — NOT signed, scanning past it. This transfer will not \
                 reach quorum from this validator; route it to cancel/refund"
            );
            self.cursor.save(&self.cfg.state_file)?;
        }
        Ok(())
    }

    /// Verify and sign one event. `Ok(false)` means the event was rejected as
    /// unauthentic and skipped; `Ok(true)` means it was signed and stored.
    async fn handle(&self, event: &SentEvent, sent: &Sent, tx: &str) -> anyhow::Result<bool> {
        // Backstop: `process_line` quarantines these before we get here, but the
        // function that signs keeps its own refusal to sign an id it cannot
        // reproduce, or one from a foreign chain.
        if let Err(reason) = signable(sent, &self.bridge_domain, self.cfg.chain_id) {
            anyhow::bail!("tx {tx}: {reason}");
        }

        // THE origin proof. Recomputing the id proves only that whoever wrote the
        // log hashed their own fields correctly — an attacker does that trivially.
        // The gate's `["sent", submissionId]` PDA is program state only
        // `process_send` can write, so it is the thing that actually distinguishes
        // "the gate locked these funds" from "someone printed a convincing line".
        let asset = match self.asset_for(&event.debridge_id, tx).await? {
            Some(a) => a,
            None => {
                warn!(
                    tx,
                    submission_id = %format!("0x{}", hex::encode(sent.submission_id)),
                    debridge_id = %format!("0x{}", hex::encode(sent.debridge_id)),
                    "REJECTED unauthentic BRIDGE_SENT — no usable [\"asset\"] registration \
                     for its debridgeId; refusing to sign (possible forged event)"
                );
                return Ok(false);
            }
        };
        if !self.origin_proof_holds(event, sent, tx, &asset).await? {
            return Ok(false);
        }

        // H-2 (audit 2026-09-16): the submissionId does not commit to the scale
        // the amount is in. This gate divides by its own registered bridge
        // decimals and the destination multiplies by ITS own, so two ends that
        // disagree pay a power of ten wrong on an ordinary transfer. `Gate.claim`
        // is permissionless and these signatures are public, so withholding is
        // the only thing that stops it — the same reasoning as the allowlist.
        if !self.scale_agrees(sent, &asset).await? {
            return Ok(false);
        }

        // Allowlist gate. Withhold the signature so the transfer can never reach
        // quorum — the only thing that actually stops it, since `Gate.claim` is
        // permissionless and the collected signatures are public. Skip rather
        // than error: the transfer really happened on-chain and there is nothing
        // to retry, so the cursor moves past it exactly as the EVM validator
        // consumes the nonce of a blocked transfer.
        let debridge_hex = format!("0x{}", hex::encode(sent.debridge_id));
        if !allowlist_permits(
            self.allowlist.as_ref(),
            &debridge_hex,
            sent.chain_id_from,
            sent.chain_id_to,
        ) {
            warn!(
                submission_id = %format!("0x{}", hex::encode(sent.submission_id)),
                debridge_id = %debridge_hex,
                chain_from = sent.chain_id_from,
                chain_to = sent.chain_id_to,
                "BLOCKED by allowlist — withholding signature"
            );
            return Ok(false);
        }

        let record = SubmissionRecord {
            submission_id: format!("0x{}", hex::encode(sent.submission_id)),
            // The SAME domain this scanner recomputed the id under, so the store
            // re-derives the identical id. Reading it from `self` (which loaded it
            // from the chain) rather than from config means a relayer can never
            // attest under a domain the gate does not actually carry.
            bridge_domain: format!("0x{}", hex::encode(self.bridge_domain)),
            debridge_id: format!("0x{}", hex::encode(sent.debridge_id)),
            amount: sent.amount.to_string(),
            // The scale the program hashed into the id (H-2), read off the same
            // event this scanner recomputed from — never from config.
            bridge_decimals: Some(sent.bridge_decimals),
            chain_id_from: sent.chain_id_from,
            chain_id_to: sent.chain_id_to,
            nonce: sent.nonce,
            receiver: format!("0x{}", hex::encode(&sent.receiver)),
            // Solana auto-params ride in the id, not as EVM-encoded bytes; the
            // store treats an empty string as "no payload".
            auto_params: "0x".to_string(),
            native_sender: format!("0x{}", hex::encode(&sent.native_sender)),
            // `token` is the EVM-side ERC-20 for the refund relayer. A Solana
            // transfer's asset is the SPL mint, which does not hash to the same
            // debridgeId formula, so it is deliberately left empty rather than
            // filled with something the store would reject.
            token: String::new(),
            signatures: vec![SignerSig {
                signer: self.signer_address.clone(),
                signature: sign(&self.secret, &sent.submission_id),
            }],
            cancel_signatures: vec![],
            refund_signatures: vec![],
        };

        self.store.upsert(&record).await?;
        info!(
            submission_id = %record.submission_id,
            nonce = sent.nonce,
            chain_to = sent.chain_id_to,
            "SIGNED and stored"
        );
        Ok(true)
    }

    /// The asset's `10^(local-bridge)` scale, from the gate's own
    /// `["asset", debridgeId]` registration.
    ///
    /// `Ok(None)` means the account is absent, foreign-owned, undecodable, or
    /// carries decimals that cannot produce a unit — none of which a genuine
    /// `send` could have produced, since `process_send` loads this very account.
    /// An RPC fault is an `Err`, so the caller retries rather than mistaking a
    /// lookup failure for a forgery.
    async fn asset_for(
        &self,
        debridge_id: &[u8; 32],
        tx: &str,
    ) -> anyhow::Result<Option<AssetAccount>> {
        let (pda, _bump) =
            Pubkey::find_program_address(&[b"asset", debridge_id], &self.program_id);
        let account = self
            .rpc
            .get_account_with_commitment(&pda, self.rpc.commitment())
            .await
            .with_context(|| format!("reading [\"asset\"] PDA {pda} for tx {tx}"))?
            .value;
        let Some(account) = account else { return Ok(None) };
        if account.owner != self.program_id {
            return Ok(None);
        }
        Ok(account::decode::<AssetAccount>(&account.data))
    }

    /// Do this gate and the EVM destination agree about the asset's scale?
    ///
    /// H-2 (audit 2026-09-16). Solana `send` hashed `local / bridge_unit`; the
    /// EVM `claim` will pay `amount * 10^(localDecimals - bridgeDecimals)` using
    /// the DESTINATION's own registration. Nothing in the submissionId ties the
    /// two together, so a peer registered one digit off pays a power of ten wrong
    /// — with no attacker input at all.
    ///
    /// Fails CLOSED: a destination we cannot read is exactly the case we cannot
    /// clear. Returns `Ok(false)` to withhold (the transfer really happened, so
    /// the cursor moves past it), and only propagates `Err` for faults worth
    /// retrying the whole tick over.
    async fn scale_agrees(&self, sent: &Sent, asset: &AssetAccount) -> anyhow::Result<bool> {
        let chain_to = sent.chain_id_to;
        let Some(reader) = self.evm_gates.get(&chain_to) else {
            if self.scale_warned.lock().await.insert(chain_to) {
                warn!(
                    chain_to,
                    "no [[refund.evm]] reader for this destination — cannot verify it agrees \
                     on the asset's bridge decimals, so transfers to it will NOT be signed \
                     (audit H-2). Add its chain_id/gate/rpc to this relayer's config."
                );
            }
            return Ok(false);
        };

        let key = (chain_to, sent.debridge_id);
        let cached = self.scale_cache.lock().await.get(&key).copied();
        let destination = match cached {
            Some(d) => d,
            None => match reader.bridge_decimals_for(&sent.debridge_id).await {
                Ok(Some(d)) => {
                    self.scale_cache.lock().await.insert(key, d);
                    d
                }
                Ok(None) => {
                    warn!(
                        chain_to,
                        debridge_id = %hex::encode(sent.debridge_id),
                        "destination gate has no corridor for this debridgeId — withholding \
                         signature"
                    );
                    return Ok(false);
                }
                // In transit, not an answer: propagate so the tick retries with
                // the cursor unmoved, exactly as `origin_proof_holds` treats an
                // unreadable record. Withholding here dropped a legitimate
                // transfer's signature for good over one rate-limited request.
                Err(e) => {
                    return Err(e.context(format!(
                        "reading chain {chain_to}'s bridge decimals for the H-2 check"
                    )))
                }
            },
        };

        if destination == asset.bridge_decimals {
            return Ok(true);
        }
        warn!(
            submission_id = %format!("0x{}", hex::encode(sent.submission_id)),
            debridge_id = %format!("0x{}", hex::encode(sent.debridge_id)),
            chain_to,
            source_bridge_decimals = asset.bridge_decimals,
            destination_bridge_decimals = destination,
            "BRIDGE DECIMALS MISMATCH — the two gates disagree about this asset's scale, so \
             a claim would pay out a power of ten wrong. Withholding signature. Both \
             registrations are write-once: fixing this needs a gate upgrade or a new mesh \
             generation."
        );
        Ok(false)
    }

    /// Read the gate's `["sent", submissionId]` record and check it corroborates
    /// the event.
    ///
    /// The two failure modes are deliberately NOT treated alike:
    ///
    ///   * **unauthentic** (no record, foreign-owned, disagrees) — this is not our
    ///     event. Warn loudly and skip. It must not abort the tick: a forged event
    ///     is cheap to emit, so failing the batch would let anyone wedge the
    ///     scanner permanently by spamming them — turning a foiled theft into a
    ///     denial of service on every real transfer behind it.
    ///   * **unreadable** (RPC error) — we do not KNOW. Propagate, so the cursor
    ///     stays put and the tick retries. Never sign on a failed lookup.
    async fn origin_proof_holds(
        &self,
        event: &SentEvent,
        sent: &Sent,
        tx: &str,
        asset: &AssetAccount,
    ) -> anyhow::Result<bool> {
        let (pda, _bump) = Pubkey::find_program_address(
            &[b"sent", &sent.submission_id],
            &self.program_id,
        );
        let account = self
            .rpc
            .get_account_with_commitment(&pda, self.rpc.commitment())
            .await
            .with_context(|| format!("reading [\"sent\"] PDA {pda} for tx {tx}"))?
            .value;

        let view = account
            .as_ref()
            .map(|a| (a.owner == self.program_id, a.data.as_slice()));

        // The record's amount is in the MINT's decimals and the event's is in the
        // asset's bridge decimals, so corroborating one against the other needs
        // the asset's scale. Same split of failure modes as the record itself: an
        // RPC fault is "we do not know" and propagates; anything else means this
        // event does not describe a registered asset, so it is not ours.
        let Some(bridge_unit) = asset.bridge_unit() else {
            warn!(
                tx,
                submission_id = %hex::encode(sent.submission_id),
                debridge_id = %hex::encode(event.debridge_id),
                "asset registration has decimals that produce no usable bridge unit — \
                 refusing to sign"
            );
            return Ok(false);
        };

        match verify_sent_record(view, event, bridge_unit) {
            Ok(_) => Ok(true),
            Err(e) => {
                warn!(
                    tx,
                    submission_id = %hex::encode(sent.submission_id),
                    sent_pda = %pda,
                    amount = sent.amount,
                    chain_to = sent.chain_id_to,
                    error = %e,
                    "REJECTED unauthentic BRIDGE_SENT — no matching on-chain origin \
                     proof; refusing to sign (possible forged event)"
                );
                Ok(false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    /// Any non-zero domain: these tests assert recompute is SELF-consistent and
    /// detects tampering, neither of which depends on the specific value.
    const TEST_DOMAIN: [u8; 32] = [0xD0; 32];

    use super::*;
    use bridge_solana::relayer::{sent_event_to_program_data_line, SentEvent};
    use crate::store::{AllowedChain, AllowedToken};

    // --- allowlist enforcement ----------------------------------------------
    //
    // THE FINDING these pin: this scanner signed every authentic `Sent`,
    // regardless of the allowlist, leaving the check to the EVM keeper. But
    // `Gate.claim` is `external` with no access control and no notion of the
    // off-chain list, and the collected signatures are served publicly by the
    // GraphQL API — so a quorum reached here is claimable by anyone, and the
    // keeper's check bound only the keeper. On EVM→EVM the same de-listing DOES
    // stop the transfer, because each validator withholds. The asymmetry was
    // silent, which is what made it dangerous: an operator reaching for the
    // kill-switch mid-incident would believe it had fired.

    const SOL: u64 = 7_565_164;
    const SEPOLIA: u64 = 11_155_111;

    fn allowing(tokens: &[&str], chains: &[(u64, u64)]) -> Allowlist {
        Allowlist::from_parts(
            &tokens.iter().map(|t| AllowedToken { debridge_id: (*t).into() }).collect::<Vec<_>>(),
            &chains
                .iter()
                .map(|(f, t)| AllowedChain { chain_id_from: *f, chain_id_to: *t })
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn a_delisted_token_is_not_attested() {
        let list = allowing(&["0xaa"], &[]);
        assert!(
            !allowlist_permits(Some(&list), "0xbb", SOL, SEPOLIA),
            "a token absent from a non-empty list must never be signed for"
        );
    }

    #[test]
    fn a_delisted_corridor_is_not_attested() {
        let list = allowing(&[], &[(SEPOLIA, SOL)]);
        assert!(
            !allowlist_permits(Some(&list), "0xaa", SOL, SEPOLIA),
            "the pair is directed: allowing EVM->Solana must not allow Solana->EVM"
        );
    }

    #[test]
    fn an_allowed_transfer_is_attested() {
        let list = allowing(&["0xaa"], &[(SOL, SEPOLIA)]);
        assert!(allowlist_permits(Some(&list), "0xAA", SOL, SEPOLIA));
    }

    /// Both lists must pass, not either. A listed token on an unlisted corridor
    /// is still blocked.
    #[test]
    fn both_lists_must_pass() {
        let list = allowing(&["0xaa"], &[(SEPOLIA, SOL)]);
        assert!(!allowlist_permits(Some(&list), "0xaa", SOL, SEPOLIA));
    }

    /// Opt-in: a fleet that has never seeded the lists keeps working, exactly as
    /// on the EVM side. Enforcement turns on with the first row, not with a
    /// deploy.
    #[test]
    fn an_empty_allowlist_still_permits_everything() {
        let list = allowing(&[], &[]);
        assert!(allowlist_permits(Some(&list), "0xanything", SOL, SEPOLIA));
    }

    /// `None` means "no allowlist established", which after this change can only
    /// happen before the first successful fetch — `tick` fails closed rather
    /// than proceeding with `None` on a fetch error.
    #[test]
    fn no_allowlist_means_no_enforcement() {
        assert!(allowlist_permits(None, "0xanything", SOL, SEPOLIA));
    }

    fn sample() -> Sent {
        let mut s = Sent {
            bridge_decimals: 9,
            submission_id: [0u8; 32],
            debridge_id: [0x22; 32],
            amount: 42_000,
            chain_id_from: 7565164,
            chain_id_to: 1337,
            receiver: vec![0xEE; 20],
            nonce: 7,
            native_sender: vec![0x33; 32],
            auto: None,
        };
        s.submission_id = recompute(&s, &TEST_DOMAIN);
        s
    }

    /// The scanner must derive the same id the program did — otherwise every
    /// signature it produces is for a submission no gate will ever recognise.
    #[test]
    fn recompute_round_trips_through_the_real_log_framing() {
        let sent = sample();
        let line = sent_event_to_program_data_line(&SentEvent::from_sent(&sent, [0x55; 32]));
        let parsed = parse_sent_event_line(&line)
            .expect("our line")
            .expect("decodes")
            .to_sent()
            .expect("converts");
        assert_eq!(recompute(&parsed, &TEST_DOMAIN), sent.submission_id, "id must survive the round trip");
    }

    /// C-1, at the layer the scanner actually reads.
    ///
    /// `getSignaturesForAddress(gate)` returns transactions that merely MENTION
    /// the gate, and their logs carry every program's output. The scanner used to
    /// parse all of them, so a forged `BRIDGE_SENT` from an attacker's program was
    /// indistinguishable from a real one — it recomputes, its `chain_id_from` is
    /// whatever the attacker wrote, and the validator signed it. That signature,
    /// times threshold, releases real liquidity on the EVM destination.
    ///
    /// The scanner now selects lines by emitting program before parsing.
    #[test]
    fn a_forged_event_from_another_program_never_reaches_the_parser() {
        const GATE: &str = "GateProg11111111111111111111111111111111111";
        const EVIL: &str = "EvilProg11111111111111111111111111111111111";

        // The attacker's payload: a real corridor, an enormous amount, their own
        // receiver — and a correctly recomputed id, because they hash their own
        // fields honestly. Nothing downstream can tell it apart.
        let mut forged = sample();
        forged.amount = 1_000_000_000_000;
        forged.receiver = vec![0xAA; 20]; // the attacker's EVM address
        forged.submission_id = recompute(&forged, &TEST_DOMAIN);

        let line = sent_event_to_program_data_line(&SentEvent::from_sent(&forged, [0x55; 32]));
        let logs: Vec<String> = vec![
            format!("Program {EVIL} invoke [1]"),
            line.clone(),
            format!("Program {EVIL} success"),
        ];

        // Pre-fix behaviour: the line parses, and recompute agrees with it.
        let decoded = parse_sent_event_line(&line).unwrap().unwrap().to_sent().unwrap();
        assert_eq!(recompute(&decoded, &TEST_DOMAIN), decoded.submission_id, "the forgery is self-consistent");

        // Post-fix: it is never attributed to the gate, so it is never parsed.
        assert!(
            gate_program_data_lines(&logs, GATE).is_empty(),
            "a foreign program's forged Sent must never reach the signing path"
        );
    }

    /// A tampered event must not reproduce its claimed id — this is the check that
    /// stops a lying RPC getting a signature over params nobody sent.
    #[test]
    fn a_tampered_event_fails_recomputation() {
        let mut sent = sample();
        sent.amount += 1; // the classic: inflate the payout
        assert_ne!(recompute(&sent, &TEST_DOMAIN), sent.submission_id, "tampering must be detectable");
    }

    /// THE cursor bug, stated as a rule.
    ///
    /// `getSignaturesForAddress` walks backwards from the tip and stops at
    /// `until` OR `limit`. A full page therefore means "I hit the limit first" —
    /// there is unread history between this page and the cursor. The scanner used
    /// to process that page and set the cursor to its newest entry, which skipped
    /// the unread range permanently: those `Sent` events were never signed, so
    /// their transfers could never reach quorum.
    #[test]
    fn a_full_page_means_there_is_more_history_below_it() {
        // Backlog deeper than one page, cursor present -> must keep walking.
        assert_eq!(
            next_page_action(100, 100, true, 0),
            PageAction::KeepWalking,
            "a full page must never be treated as the end of the range"
        );
        // Short page -> the walk reached the cursor; the range is contiguous.
        assert_eq!(next_page_action(37, 100, true, 0), PageAction::Complete);
        assert_eq!(next_page_action(0, 100, true, 3), PageAction::Complete);
    }

    /// A missing cursor used to mean "start at the tip", silently: a wiped state
    /// volume skipped every transfer sent since the last save, for good. It now
    /// walks history like any other backlog unless the operator opted out.
    #[test]
    fn a_missing_cursor_walks_history_unless_start_at_tip_is_explicit() {
        assert_eq!(
            next_page_action(100, 100, walks_to_start(false, false), 0),
            PageAction::KeepWalking,
            "no cursor, no opt-out: a full page means older history to replay"
        );
        assert_eq!(next_page_action(100, 100, walks_to_start(false, false), MAX_PAGES - 1), PageAction::TooDeep);
        assert_eq!(next_page_action(100, 100, walks_to_start(false, true), 0), PageAction::Complete);
        // A cursor always walks to itself, whatever `start_at_tip` says.
        assert_eq!(next_page_action(100, 100, walks_to_start(true, true), 0), PageAction::KeepWalking);
    }

    /// Falling too far behind must fail loudly and leave the cursor put. Silently
    /// processing a range with a hole under it is the failure mode we are fixing;
    /// re-reading the same range next tick is merely slow.
    #[test]
    fn an_unwalkable_backlog_fails_instead_of_skipping() {
        assert_eq!(next_page_action(100, 100, true, MAX_PAGES - 1), PageAction::TooDeep);
        // Still walkable one page earlier.
        assert_eq!(next_page_action(100, 100, true, MAX_PAGES - 2), PageAction::KeepWalking);
    }

    /// The signature must recover to the address we claim, or the store rejects it.
    #[test]
    fn signature_recovers_to_the_claimed_signer() {
        let secret = libsecp256k1::SecretKey::parse(&[7u8; 32]).unwrap();
        let id = [0x11u8; 32];
        let sig_hex = sign(&secret, &id);
        let raw = hex::decode(sig_hex.trim_start_matches("0x")).unwrap();

        let digest = bridge_solana::verify::eth_signed_digest(&id);
        let recovered = libsecp256k1::recover(
            &libsecp256k1::Message::parse(&digest),
            &libsecp256k1::Signature::parse_standard_slice(&raw[..64]).unwrap(),
            &libsecp256k1::RecoveryId::parse(raw[64] - 27).unwrap(),
        )
        .unwrap();
        let hash = bridge_solana::hash::keccak(&recovered.serialize()[1..]);
        assert_eq!(format!("0x{}", hex::encode(&hash[12..])), evm_address(&secret));
    }
}

#[cfg(test)]
mod quarantine_tests {
    //! Audit round 6, LOW: an unsignable gate event used to `bail!` with the
    //! cursor pinned, wedging the scanner on that transaction forever. It must
    //! now be refused (never signed), recorded, and scanned past — while an
    //! event from a NEWER program version still halts, and a transient fault on
    //! a good event still leaves the cursor put.
    use super::*;
    use bridge_solana::relayer::{sent_event_to_program_data_line, SentEvent, SENT_EVENT_VERSION};

    const DOMAIN: [u8; 32] = [0xD0; 32];

    fn scanner(name: &str) -> Scanner {
        let dir = std::env::temp_dir().join(format!("sr-quarantine-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = SourceChain {
            chain_id: 7_565_164,
            rpc: "http://127.0.0.1:1".into(), // unreachable: proves no RPC is reached
            program_id: "11111111111111111111111111111111".into(),
            commitment: "confirmed".into(),
            allow_unfinalized: true,
            poll_interval_ms: 2000,
            state_file: dir.join("cursor.json").to_string_lossy().into_owned(),
            max_batch: 100,
            start_at_tip: false,
        };
        let mut s = Scanner::new(cfg, [0x42; 32], Store::new("http://127.0.0.1:1", None).unwrap(), BTreeMap::new())
            .unwrap();
        s.bridge_domain = DOMAIN;
        s
    }

    fn good() -> Sent {
        let mut s = Sent {
            bridge_decimals: 9,
            submission_id: [0; 32],
            debridge_id: [0x22; 32],
            amount: 42_000,
            chain_id_from: 7_565_164,
            chain_id_to: 1337,
            receiver: vec![0xEE; 20],
            nonce: 7,
            native_sender: vec![0x33; 32],
            auto: None,
        };
        s.submission_id = recompute(&s, &DOMAIN);
        s
    }

    /// The event is refused, recorded (in memory AND in the state file), and the
    /// line reports "nothing signed" instead of an error — so `tick` advances.
    async fn assert_quarantined(sc: &mut Scanner, line: &str, reason_has: &str) {
        let signed = sc.process_line(line, "TX1").await.expect("quarantined, not a hard error");
        assert!(!signed, "an unsignable event must never be signed");
        assert_eq!(sc.cursor.quarantined.len(), 1);
        assert_eq!(sc.cursor.quarantined[0].tx, "TX1");
        assert!(sc.cursor.quarantined[0].reason.contains(reason_has), "{:?}", sc.cursor.quarantined);
        let on_disk = crate::state::Cursor::load_or_init(&sc.cfg.state_file).unwrap();
        assert_eq!(on_disk.quarantined, sc.cursor.quarantined, "persisted beside the cursor");

        // A re-read of the same transaction (e.g. after a transient failure
        // later in it) neither duplicates the entry nor errors.
        assert!(!sc.process_line(line, "TX1").await.unwrap());
        assert_eq!(sc.cursor.quarantined.len(), 1);
    }

    #[tokio::test]
    async fn an_id_mismatch_is_quarantined_not_wedging() {
        let mut sc = scanner("id");
        let mut s = good();
        s.submission_id[0] ^= 1;
        let line = sent_event_to_program_data_line(&SentEvent::from_sent(&s, [0x55; 32]));
        assert_quarantined(&mut sc, &line, "MISMATCH").await;
    }

    #[tokio::test]
    async fn a_foreign_chain_id_from_is_quarantined_not_wedging() {
        let mut sc = scanner("chain");
        let mut s = good();
        s.chain_id_from = 999;
        s.submission_id = recompute(&s, &DOMAIN); // self-consistent, wrong chain
        let line = sent_event_to_program_data_line(&SentEvent::from_sent(&s, [0x55; 32]));
        assert_quarantined(&mut sc, &line, "chain_id_from").await;
    }

    #[tokio::test]
    async fn an_older_event_version_is_quarantined_not_wedging() {
        let mut sc = scanner("old");
        let mut ev = SentEvent::from_sent(&good(), [0x55; 32]);
        ev.version = SENT_EVENT_VERSION - 1; // e.g. replaying pre-upgrade history
        assert_quarantined(&mut sc, &sent_event_to_program_data_line(&ev), "version").await;
    }

    #[tokio::test]
    async fn a_garbage_payload_is_quarantined_not_wedging() {
        use base64::Engine as _;
        let mut sc = scanner("garbage");
        let b64 = base64::engine::general_purpose::STANDARD;
        // Our tag, a payload claiming the CURRENT version, then truncated.
        let line = format!(
            "{PROGRAM_DATA_PREFIX} {} {}",
            b64.encode(bridge_solana::relayer::SENT_EVENT_TAG),
            b64.encode([SENT_EVENT_VERSION, 1, 2, 3])
        );
        assert_quarantined(&mut sc, &line, "malformed").await;
    }

    /// A NEWER version is an upgraded program, not a bad event: scanning past it
    /// would skip every transfer until the relayer is upgraded. It halts —
    /// whether or not the new layout still decodes as today's struct.
    #[tokio::test]
    async fn a_newer_event_version_still_halts() {
        use base64::Engine as _;
        let mut sc = scanner("newer");
        let mut ev = SentEvent::from_sent(&good(), [0x55; 32]);
        ev.version = SENT_EVENT_VERSION + 1;
        let err = sc.process_line(&sent_event_to_program_data_line(&ev), "TX1").await.unwrap_err();
        assert!(err.to_string().contains("upgrade the relayer"), "{err}");

        let b64 = base64::engine::general_purpose::STANDARD;
        let line = format!(
            "{PROGRAM_DATA_PREFIX} {} {}",
            b64.encode(bridge_solana::relayer::SENT_EVENT_TAG),
            b64.encode([SENT_EVENT_VERSION + 1, 9, 9])
        );
        assert!(sc.process_line(&line, "TX2").await.is_err(), "undecodable newer layout halts too");
        assert!(sc.cursor.quarantined.is_empty(), "a halt is not a quarantine");
    }

    /// A GOOD event proceeds to the RPC-backed origin proof; an RPC fault there
    /// is transient and must still propagate (cursor pinned, retried), never be
    /// mistaken for quarantine material.
    #[tokio::test]
    async fn a_good_event_with_an_rpc_fault_is_retried_not_quarantined() {
        let mut sc = scanner("good");
        let line = sent_event_to_program_data_line(&SentEvent::from_sent(&good(), [0x55; 32]));
        assert!(sc.process_line(&line, "TX1").await.is_err(), "unreachable RPC is an error");
        assert!(sc.cursor.quarantined.is_empty());
    }

    #[test]
    fn signable_names_each_refusal() {
        assert!(signable(&good(), &DOMAIN, 7_565_164).is_ok());
        assert!(signable(&good(), &[0xD1; 32], 7_565_164).unwrap_err().contains("MISMATCH"));
        assert!(signable(&good(), &DOMAIN, 1).unwrap_err().contains("chain_id_from"));
    }
}
