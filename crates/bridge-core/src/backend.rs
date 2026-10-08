//! One read/write view over the shared signature store, for every service.
//!
//! The store has exactly two backings — a file-per-id directory (local dev) and
//! the HTTP `sig-store` service (Phase 7) — and the validator, the keeper and
//! the GraphQL API each need a slightly different slice of the same operations
//! over them. They each grew their own near-identical enum for that, three
//! copies of the same eight `match self` arms, which is how one of them ends up
//! quietly missing a case.
//!
//! ## Why one type does not widen anyone's authority
//!
//! Least privilege here is enforced by the CREDENTIAL, not by which methods a
//! Rust type happens to expose: the sig-store checks a per-service bearer token
//! against a required scope on every route (see `auth::Scope`). A reader token
//! calling [`StoreBackend::mark_claimed`] gets a 401 regardless of what compiles.
//! So each service builds its backend with [`StoreBackend::remote_for_role`] and
//! its OWN variable, and that is what actually bounds it.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::allow::AllowlistView;
use crate::remote::RemoteStore;
use crate::store::{self, SigKind, SignerSig, SubmissionRecord};

/// Page size for walking [`StoreBackend::refund_candidates`].
///
/// Small enough that one page stays far inside `RemoteStore`'s response cap even
/// if every row carries the maximum signature set, so a refund loop can always
/// make progress no matter how large the queue has grown.
pub const REFUND_PAGE: u64 = 500;

/// Stop walking after this many pages in one tick.
///
/// A queue longer than `REFUND_PAGE * MAX_REFUND_PAGES` is a symptom, not a
/// workload: the loop covers what it can this tick and resumes next tick rather
/// than spending unbounded time and RPC budget before its first attestation.
pub const MAX_REFUND_PAGES: u64 = 20;

/// Where a refund loop's walk of the candidate queue resumes (audit round 7,
/// H7-5).
///
/// A walk used to restart at the head of the queue every tick and stop after
/// `REFUND_PAGE * MAX_REFUND_PAGES` rows, so whatever sat in the first 10,000
/// rows was all any loop ever examined — and anything that never leaves the
/// queue (a row no chain emitted) could hold that head for good. The cursor
/// carries the last id a tick reached into the next one and wraps to the head
/// once a walk reaches the end, so every row is examined within
/// `ceil(len / (REFUND_PAGE * MAX_REFUND_PAGES))` ticks however the queue is
/// filled.
///
/// Kept in memory: a restart begins one walk at the head, which costs a pass,
/// not progress.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RefundCursor {
    after: Option<String>,
}

/// What one tick of [`RefundCursor::walk`] produced.
#[derive(Debug)]
pub struct RefundWalk {
    pub candidates: Vec<SubmissionRecord>,
    /// The walk stopped at `MAX_REFUND_PAGES` with more queue left; the next
    /// tick resumes there.
    pub truncated: bool,
}

impl RefundCursor {
    /// Walk up to [`MAX_REFUND_PAGES`] pages from where the last tick stopped.
    /// `fetch(limit, after)` reads one page. On an error the cursor is left
    /// where it was, so the failed page is retried next tick.
    pub async fn walk<F, Fut, E>(&mut self, mut fetch: F) -> Result<RefundWalk, E>
    where
        F: FnMut(u64, Option<String>) -> Fut,
        Fut: std::future::Future<Output = Result<Vec<SubmissionRecord>, E>>,
    {
        let mut candidates = Vec::new();
        for _ in 0..MAX_REFUND_PAGES {
            let page = fetch(REFUND_PAGE, self.after.clone()).await?;
            let short = (page.len() as u64) < REFUND_PAGE;
            if let Some(last) = page.last() {
                self.after = Some(last.submission_id.clone());
            }
            candidates.extend(page);
            if short {
                // The end of the queue: the next tick starts again at the head.
                self.after = None;
                return Ok(RefundWalk { candidates, truncated: false });
            }
        }
        Ok(RefundWalk { candidates, truncated: true })
    }
}

pub enum StoreBackend {
    /// File-per-id directory. The lock serializes the read-modify-write inside
    /// `store::upsert_signature`, so two concurrent upserts for one id cannot
    /// read the same record and each write back only its own signature.
    File { dir: PathBuf, write_lock: Mutex<()> },
    /// The HTTP sig-store; it owns the trust-boundary validation server-side.
    Remote(RemoteStore),
}

impl StoreBackend {
    /// A directory-backed store, creating the directory if needed.
    pub fn file(dir: impl Into<PathBuf>) -> Result<Self, store::StoreError> {
        let dir = dir.into();
        store::ensure_dir(&dir)?;
        Ok(StoreBackend::File { dir, write_lock: Mutex::new(()) })
    }

    /// An HTTP store presenting the narrowest credential the caller has.
    ///
    /// `role_env` is the service's OWN variable — `SIG_STORE_VALIDATOR_TOKEN`,
    /// `SIG_STORE_KEEPER_TOKEN`, `SIG_STORE_READER_TOKEN` — and is what bounds
    /// what this backend can actually do. See the module note.
    pub fn remote_for_role(url: impl Into<String>, role_env: &str) -> Self {
        StoreBackend::Remote(RemoteStore::for_role(url, role_env))
    }

    /// Build from a `[store]` config block: `url` selects the HTTP service and
    /// wins over `dir`.
    pub fn from_config(cfg: &StoreConfig, role_env: &str) -> anyhow::Result<Self> {
        if let Some(url) = &cfg.url {
            Ok(Self::remote_for_role(url.clone(), role_env))
        } else if let Some(dir) = &cfg.dir {
            Ok(Self::file(dir)?)
        } else {
            anyhow::bail!("[store] needs either `dir` or `url`")
        }
    }

    /// Human-readable backing, for the startup log line.
    pub fn describe(&self) -> String {
        match self {
            StoreBackend::File { dir, .. } => format!("file://{}", dir.display()),
            StoreBackend::Remote(_) => "http(sig-store)".into(),
        }
    }

    /// Upsert a record and merge in one signature, returning the merged record.
    ///
    /// The dir backing runs the local trust boundary (`store::upsert_signature`);
    /// the remote backing defers to the sig-store service, which enforces the
    /// same checks. Either way an unverifiable record or signature is rejected.
    pub async fn upsert(
        &self,
        record: SubmissionRecord,
        sig: SignerSig,
    ) -> anyhow::Result<SubmissionRecord> {
        match self {
            StoreBackend::File { dir, write_lock } => {
                let _guard = lock(write_lock);
                Ok(store::upsert_signature(dir, record, sig)?)
            }
            StoreBackend::Remote(remote) => Ok(remote.upsert(record, sig).await?),
        }
    }

    /// Merge a cancel/refund attestation into an already-stored submission.
    pub async fn upsert_attestation(
        &self,
        submission_id: &str,
        kind: SigKind,
        sig: SignerSig,
    ) -> anyhow::Result<SubmissionRecord> {
        match self {
            StoreBackend::File { dir, write_lock } => {
                let _guard = lock(write_lock);
                Ok(store::upsert_attestation(dir, submission_id, kind, sig)?)
            }
            StoreBackend::Remote(remote) => {
                Ok(remote.upsert_attestation(submission_id, kind, sig).await?)
            }
        }
    }

    pub async fn load(&self, submission_id: &str) -> anyhow::Result<Option<SubmissionRecord>> {
        match self {
            StoreBackend::File { dir, .. } => Ok(store::load(dir, submission_id)?),
            StoreBackend::Remote(remote) => Ok(remote.load(submission_id).await?),
        }
    }

    pub async fn load_all(&self) -> anyhow::Result<Vec<SubmissionRecord>> {
        match self {
            StoreBackend::File { dir, .. } => Ok(store::load_all(dir)?),
            StoreBackend::Remote(remote) => Ok(remote.load_all().await?),
        }
    }

    /// The keeper's work queue for claims/cancels on one destination chain.
    ///
    /// In file mode there is no server-side lifecycle, so every stored record is
    /// offered and the caller's own on-chain checks do all the filtering — the
    /// pre-existing behaviour, kept for the dev path.
    pub async fn pending_claims(&self, chain_id_to: u64) -> anyhow::Result<Vec<SubmissionRecord>> {
        match self {
            StoreBackend::File { dir, .. } => Ok(store::load_all(dir)?),
            StoreBackend::Remote(remote) => Ok(remote.pending_claims(chain_id_to).await?),
        }
    }

    /// The keeper's work queue for refunds on one source chain. File mode as above.
    pub async fn pending_refunds(
        &self,
        chain_id_from: u64,
    ) -> anyhow::Result<Vec<SubmissionRecord>> {
        match self {
            StoreBackend::File { dir, .. } => Ok(store::load_all(dir)?),
            StoreBackend::Remote(remote) => Ok(remote.pending_refunds(chain_id_from).await?),
        }
    }

    /// One page of the submissions a refund loop should examine, starting after
    /// the `submission_id` `after` (keyset, audit round 7, H7-5), or at the head
    /// of the queue for `None`.
    ///
    /// In file mode there is no server-side lifecycle, so every stored record is
    /// offered and the caller's own on-chain checks do all the filtering; the
    /// records are ordered by id and the page applied client-side so both modes
    /// present the same interface.
    ///
    /// Callers must WALK the pages (see [`REFUND_PAGE`]): the queue is unbounded
    /// and served by a component the design treats as untrusted, so a single
    /// unpaged fetch can be made to exceed the response cap forever (audit
    /// 2026-09-16, H-6). Use [`RefundCursor`] to do it.
    pub async fn refund_candidates(
        &self,
        limit: u64,
        after: Option<&str>,
    ) -> anyhow::Result<Vec<SubmissionRecord>> {
        match self {
            StoreBackend::File { dir, .. } => {
                let mut all = store::load_all(dir)?;
                for r in &mut all {
                    r.submission_id = r.submission_id.to_ascii_lowercase();
                }
                all.sort_by(|a, b| a.submission_id.cmp(&b.submission_id));
                let after = after.map(str::to_ascii_lowercase);
                Ok(all
                    .into_iter()
                    .filter(|r| after.as_deref().is_none_or(|a| r.submission_id.as_str() > a))
                    .take(limit as usize)
                    .collect())
            }
            StoreBackend::Remote(remote) => {
                Ok(remote.refund_candidates(limit, after).await?)
            }
        }
    }

    /// What the store currently serves for the allowlists. Refetched per tick by
    /// its callers, so an operator's change applies without a restart.
    ///
    /// Returns the three cases apart (audit 2026-09-16, M-5): an EMPTY list from
    /// the store is not the same fact as there being no central allowlist, even
    /// though both end up meaning "allow everything" by default. The caller
    /// applies its [`AllowlistPolicy`] to decide which of them it will act on.
    pub async fn fetch_allowlist(&self) -> anyhow::Result<AllowlistView> {
        match self {
            StoreBackend::File { .. } => Ok(AllowlistView::NotConfigured),
            StoreBackend::Remote(remote) => {
                let list = remote.allowlist().await?;
                Ok(if list.is_empty() { AllowlistView::Empty } else { AllowlistView::Enforcing(list) })
            }
        }
    }

    /// Record a successful claim back to the store (a no-op in file mode, which
    /// keeps no lifecycle).
    pub async fn mark_claimed(&self, submission_id: &str, claim_tx: &str) -> anyhow::Result<()> {
        match self {
            StoreBackend::File { .. } => Ok(()),
            StoreBackend::Remote(remote) => Ok(remote.mark_claimed(submission_id, claim_tx).await?),
        }
    }

    /// The transaction-history view.
    ///
    /// Only the sig-store keeps a lifecycle, so the file backing has nothing to
    /// report and says so rather than returning a misleading empty list.
    pub async fn history(&self) -> anyhow::Result<Vec<crate::allow::SubmissionHistory>> {
        match self {
            StoreBackend::File { .. } => anyhow::bail!(
                "transaction history needs the sig-store — start with `--store-url`; \
                 a file-backed store keeps signatures only, not a lifecycle"
            ),
            StoreBackend::Remote(remote) => Ok(remote.history().await?),
        }
    }

    /// Same-chain swap history, newest first, optionally scoped to one chain.
    pub async fn swaps(
        &self,
        chain_id: Option<u64>,
        limit: u64,
    ) -> anyhow::Result<Vec<crate::allow::SwapRecord>> {
        match self {
            StoreBackend::File { .. } => anyhow::bail!(
                "swap history needs the sig-store — start with `--store-url`; \
                 a file-backed store keeps signatures only"
            ),
            StoreBackend::Remote(remote) => Ok(remote.swaps(chain_id, limit).await?),
        }
    }

    /// The directory this backend writes to, if it is file-backed.
    pub fn dir(&self) -> Option<&Path> {
        match self {
            StoreBackend::File { dir, .. } => Some(dir),
            StoreBackend::Remote(_) => None,
        }
    }
}

/// Take the write lock, ignoring poisoning.
///
/// A panic inside `upsert_signature` cannot leave the STORE inconsistent — it
/// writes each record with a single `fs::write` — so a poisoned lock carries no
/// information worth propagating, and refusing to serve every later request over
/// it would turn one failed upsert into a dead process.
fn lock(m: &Mutex<()>) -> std::sync::MutexGuard<'_, ()> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A `[store]` config block: a local directory (`dir`) or the HTTP sig-store
/// (`url`). `url` wins when both are set.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreConfig {
    #[serde(default)]
    pub dir: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(n: usize) -> SubmissionRecord {
        SubmissionRecord {
            submission_id: format!("0x{n:064x}"),
            bridge_domain: String::new(),
            debridge_id: String::new(),
            amount: "0".into(),
            bridge_decimals: None,
            chain_id_from: 0,
            chain_id_to: 0,
            nonce: 0,
            receiver: String::new(),
            auto_params: String::new(),
            native_sender: String::new(),
            token: String::new(),
            signatures: vec![],
            cancel_signatures: vec![],
            refund_signatures: vec![],
        }
    }

    /// A store serving `len` rows by keyset, like `/refund-candidates?after=`.
    fn queue(len: usize) -> Vec<SubmissionRecord> {
        (0..len).map(rec).collect()
    }

    async fn page(q: &[SubmissionRecord], limit: u64, after: Option<String>) -> Result<Vec<SubmissionRecord>, ()> {
        Ok(q.iter()
            .filter(|r| after.as_deref().is_none_or(|a| r.submission_id.as_str() > a))
            .take(limit as usize)
            .cloned()
            .collect())
    }

    /// H7-5: with more queue than one tick walks, the next tick resumes where
    /// this one stopped, the walk wraps at the end, and every row is reached.
    #[tokio::test]
    async fn every_row_is_reached_however_long_the_queue_is() {
        let per_tick = (REFUND_PAGE * MAX_REFUND_PAGES) as usize;
        let q = queue(per_tick * 2 + 7);
        let mut cursor = RefundCursor::default();

        let t1 = cursor.walk(|l, a| page(&q, l, a)).await.unwrap();
        assert!(t1.truncated);
        assert_eq!(t1.candidates.len(), per_tick);
        assert_eq!(t1.candidates[0].submission_id, q[0].submission_id);

        let t2 = cursor.walk(|l, a| page(&q, l, a)).await.unwrap();
        assert_eq!(t2.candidates[0].submission_id, q[per_tick].submission_id, "resumes, not restarts");

        let t3 = cursor.walk(|l, a| page(&q, l, a)).await.unwrap();
        assert!(!t3.truncated);
        assert_eq!(t3.candidates.len(), 7, "the tail behind 2x a tick's worth is reached");

        let t4 = cursor.walk(|l, a| page(&q, l, a)).await.unwrap();
        assert_eq!(t4.candidates[0].submission_id, q[0].submission_id, "and the walk wraps to the head");
    }

    #[tokio::test]
    async fn a_failed_page_is_retried_from_the_same_place() {
        let q = queue((REFUND_PAGE * MAX_REFUND_PAGES) as usize + 1);
        let mut cursor = RefundCursor::default();
        cursor.walk(|l, a| page(&q, l, a)).await.unwrap();
        let before = cursor.clone();
        let failed: Result<RefundWalk, ()> = cursor.walk(|_, _| async { Err(()) }).await;
        assert!(failed.is_err());
        assert_eq!(cursor, before);
    }

    #[tokio::test]
    async fn file_mode_pages_by_id() {
        let dir = std::env::temp_dir().join(format!("refund-cursor-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for r in queue(5) {
            std::fs::write(dir.join(format!("{}.json", r.submission_id)), serde_json::to_string(&r).unwrap()).unwrap();
        }
        let b = StoreBackend::File { dir: dir.clone(), write_lock: Mutex::new(()) };
        let first = b.refund_candidates(2, None).await.unwrap();
        let rest = b.refund_candidates(10, Some(&first[1].submission_id)).await.unwrap();
        std::fs::remove_dir_all(&dir).ok();
        let ids: Vec<_> = first.iter().chain(&rest).map(|r| r.submission_id.clone()).collect();
        assert_eq!(ids, queue(5).into_iter().map(|r| r.submission_id).collect::<Vec<_>>());
    }
}
