//! Bearer-token authentication for the bridge's HTTP surfaces (the signature
//! store, the validator's operator API).
//!
//! ## Why scopes (finding L-5)
//!
//! There used to be exactly one secret, `SIG_STORE_TOKEN`, shared by every
//! validator, the keeper and the GraphQL API. Holding it granted every route. So
//! compromising ANY one component — including the read-only GraphQL service, the
//! most exposed of them — granted the ability to write signatures, mark transfers
//! claimed, and rewrite the allowlist that is itself a security control.
//!
//! That blast radius is what made finding H-1 reachable: a single leaked token
//! let an attacker deposit junk signatures and permanently deny the claim path.
//!
//! Tokens now carry [`Scope`]s and each route group demands the narrowest one
//! that lets it work:
//!
//! | Scope     | Grants                                                   | Held by         |
//! |-----------|----------------------------------------------------------|-----------------|
//! | `Read`    | read submissions, history, refund candidates             | everyone        |
//! | `Sign`    | POST signatures and cancel/refund attestations           | validators      |
//! | `Relay`   | annotate a submission with a claim tx (ADVISORY, M-1)    | keeper          |
//! | `Indexer` | report an OBSERVED on-chain terminal state (authoritative)| Solana observer |
//! | `Admin`   | add/remove allowlist entries                             | operators       |
//!
//! A scope is a *capability*, not a role: one token may carry several. `Admin`
//! does NOT imply the others — the operator token can edit the allowlist and
//! nothing else — and no scope implies `Indexer`. The legacy `SIG_STORE_TOKEN`
//! is still accepted and carries all five, so existing deployments keep working
//! — but it logs a warning, because it reinstates exactly the blast radius above.
//!
//! ## Why `Indexer` is its own scope
//!
//! The lifecycle columns (`status`, `refund_status`) gate every work queue, so
//! whoever can write them can hide a transfer from the keeper and the refund
//! path for good (audit 2026-09-09, M-1). The EVM indexer writes them from
//! events it read itself, directly into Postgres. The Solana gate has no EVM
//! indexer: its `["executed", id]` / `["refunded", id]` markers are observed by
//! the Solana relayer's observer loop and reported over HTTP. That report is
//! authoritative by construction, so it must not ride on the `Relay` token every
//! keeper holds (which stays advisory) — it gets a credential only the observer
//! is handed, and a leak of it is a leak of exactly one capability.

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// A capability a token may carry. Deliberately fine-grained: the point is that
/// the GraphQL API can be given `Read` alone, so leaking its credential cannot
/// write anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scope {
    /// Read submissions, history and refund candidates.
    Read,
    /// Write transfer signatures and cancel/refund attestations (validators).
    Sign,
    /// Record a claim tx against a submission (the keeper). Advisory only.
    Relay,
    /// Report an on-chain terminal state this caller OBSERVED (claimed /
    /// cancelled / refunded). Authoritative: moves the lifecycle, exactly as the
    /// EVM indexer's direct database write does. Held by the Solana observer.
    Indexer,
    /// Mutate the allowlists — itself a security control, hence its own scope.
    Admin,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Read => "read",
            Scope::Sign => "sign",
            Scope::Relay => "relay",
            Scope::Indexer => "indexer",
            Scope::Admin => "admin",
        }
    }

    /// Everything — what the legacy single token carries.
    pub fn all() -> HashSet<Scope> {
        [Scope::Read, Scope::Sign, Scope::Relay, Scope::Indexer, Scope::Admin].into_iter().collect()
    }
}

/// The configured token set. Cheap to clone (one `Arc`).
///
/// `disabled()` is the dev-only mode in which every request is allowed; it is
/// reported loudly by the caller rather than silently assumed.
#[derive(Clone, Default)]
pub struct Auth {
    tokens: Arc<HashMap<String, HashSet<Scope>>>,
    enforced: bool,
}

impl Auth {
    /// Unauthenticated: every request passes. Dev only.
    pub fn disabled() -> Auth {
        Auth { tokens: Arc::new(HashMap::new()), enforced: false }
    }

    /// Build from (token, scopes) pairs. Empty tokens are ignored so an unset
    /// environment variable cannot accidentally authenticate an empty header.
    ///
    /// A token appearing more than once accumulates the union of its scopes,
    /// which is what lets one operator token be handed several capabilities.
    pub fn new(entries: impl IntoIterator<Item = (String, HashSet<Scope>)>) -> Auth {
        let mut tokens: HashMap<String, HashSet<Scope>> = HashMap::new();
        for (token, scopes) in entries {
            if token.is_empty() {
                continue;
            }
            tokens.entry(token).or_default().extend(scopes);
        }
        let enforced = !tokens.is_empty();
        Auth { tokens: Arc::new(tokens), enforced }
    }

    pub fn is_enforced(&self) -> bool {
        self.enforced
    }

    /// Number of distinct tokens configured (for startup logging).
    pub fn token_count(&self) -> usize {
        self.tokens.len()
    }

    /// Does `presented` carry `scope`?
    ///
    /// Compared in constant time against every configured token. We deliberately
    /// do NOT short-circuit on the first match: returning early would make the
    /// response time depend on which token was presented, leaking information
    /// about the token set's ordering.
    pub fn grants(&self, presented: &str, scope: Scope) -> bool {
        if !self.enforced {
            return true;
        }
        let mut granted = false;
        for (token, scopes) in self.tokens.iter() {
            let matches = ct_eq(presented.as_bytes(), token.as_bytes());
            granted |= matches && scopes.contains(&scope);
        }
        granted
    }
}

/// Extract the bearer token from a request, or `""` when absent/malformed.
fn bearer(req: &Request) -> &str {
    req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("")
}

/// Middleware demanding a specific [`Scope`].
///
/// Wire it per route group:
/// ```ignore
/// .route_layer(middleware::from_fn_with_state((auth.clone(), Scope::Sign), require_scope))
/// ```
pub async fn require_scope(
    State((auth, scope)): State<(Auth, Scope)>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if auth.grants(bearer(&req), scope) {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

/// Back-compat single-secret gate, still used by the validator's operator API
/// (which has exactly one privilege level: halt this validator).
pub async fn require_auth(
    State(expected): State<Arc<String>>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if ct_eq(bearer(&req).as_bytes(), expected.as_bytes()) {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

/// Length-checked constant-time byte comparison (avoids leaking the token via
/// early-exit timing on the compare itself).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth() -> Auth {
        Auth::new([
            ("val-token".to_string(), [Scope::Read, Scope::Sign].into_iter().collect()),
            ("keeper-token".to_string(), [Scope::Read, Scope::Relay].into_iter().collect()),
            ("reader-token".to_string(), [Scope::Read].into_iter().collect()),
            ("indexer-token".to_string(), [Scope::Read, Scope::Indexer].into_iter().collect()),
            ("admin-token".to_string(), [Scope::Read, Scope::Admin].into_iter().collect()),
        ])
    }

    const ALL: [Scope; 5] = [Scope::Read, Scope::Sign, Scope::Relay, Scope::Indexer, Scope::Admin];

    #[test]
    fn ct_eq_is_correct() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(ct_eq(b"", b""));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab")); // length mismatch
        assert!(!ct_eq(b"", b"x"));
    }

    // THE L-5 property: a leaked read-only credential must not be able to write.
    // Under the old single shared token, the GraphQL API's secret was the
    // validators' secret was the keeper's secret.
    #[test]
    fn a_read_token_cannot_write() {
        let a = auth();
        assert!(a.grants("reader-token", Scope::Read));
        assert!(!a.grants("reader-token", Scope::Sign), "read-only must not sign");
        assert!(!a.grants("reader-token", Scope::Relay), "read-only must not mark claimed");
        assert!(!a.grants("reader-token", Scope::Admin), "read-only must not touch allowlists");
        assert!(!a.grants("reader-token", Scope::Indexer), "read-only must not move the lifecycle");
    }

    /// The observer's authoritative report is a capability of its own: neither
    /// the keeper's advisory `Relay` nor the operator's `Admin` implies it, and
    /// it implies neither of them. A leaked keeper token still cannot hide a
    /// transfer (M-1), and a leaked observer token cannot sign or edit the
    /// allowlist.
    #[test]
    fn indexer_is_not_implied_by_any_other_scope_and_implies_none() {
        let a = auth();
        for t in ["val-token", "keeper-token", "reader-token", "admin-token"] {
            assert!(!a.grants(t, Scope::Indexer), "{t} must not carry Indexer");
        }
        assert!(a.grants("indexer-token", Scope::Indexer));
        assert!(a.grants("indexer-token", Scope::Read));
        for s in [Scope::Sign, Scope::Relay, Scope::Admin] {
            assert!(!a.grants("indexer-token", s), "the observer must not carry {}", s.as_str());
        }
    }

    // Each component gets its own capability and nothing more.
    #[test]
    fn scopes_are_not_interchangeable() {
        let a = auth();
        assert!(a.grants("val-token", Scope::Sign));
        assert!(!a.grants("val-token", Scope::Relay), "a validator must not mark claimed");
        assert!(!a.grants("val-token", Scope::Admin), "a validator must not edit the allowlist");

        assert!(a.grants("keeper-token", Scope::Relay));
        assert!(!a.grants("keeper-token", Scope::Sign), "the keeper must not deposit signatures");
    }

    #[test]
    fn unknown_and_empty_tokens_are_refused() {
        let a = auth();
        for t in ["", "nope", "val-token "] {
            for s in ALL {
                assert!(!a.grants(t, s), "token {t:?} must not grant {}", s.as_str());
            }
        }
    }

    // An unset env var must not become a valid empty credential.
    #[test]
    fn empty_configured_tokens_are_dropped() {
        let a = Auth::new([(String::new(), Scope::all())]);
        assert!(!a.is_enforced(), "no usable token => no enforcement to claim");
        assert_eq!(a.token_count(), 0);
    }

    // The legacy single secret still works, carrying every scope.
    #[test]
    fn legacy_single_token_carries_all_scopes() {
        let a = Auth::new([("legacy".to_string(), Scope::all())]);
        assert_eq!(Scope::all().len(), ALL.len(), "`all()` must list every scope");
        for s in ALL {
            assert!(a.grants("legacy", s));
        }
    }

    // Dev mode: no tokens configured at all => open. Explicit, not accidental.
    #[test]
    fn disabled_auth_allows_everything() {
        let a = Auth::disabled();
        assert!(!a.is_enforced());
        assert!(a.grants("", Scope::Admin));
    }

    // One token may hold several capabilities (an operator key, say).
    #[test]
    fn duplicate_entries_union_their_scopes() {
        let a = Auth::new([
            ("op".to_string(), [Scope::Read].into_iter().collect()),
            ("op".to_string(), [Scope::Admin].into_iter().collect()),
        ]);
        assert!(a.grants("op", Scope::Read));
        assert!(a.grants("op", Scope::Admin));
        assert!(!a.grants("op", Scope::Sign));
    }
}
