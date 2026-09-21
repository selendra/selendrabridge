use bridge_core::allow::AllowlistPolicy;
use bridge_core::backend::StoreConfig;
use bridge_core::config::ensure_unique;
use bridge_core::signer::SignerConfig;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Legacy single-source form: `[source]`. Folded into `sources` on load.
    #[serde(default)]
    pub source: Option<SourceChain>,
    /// Multi-source form: one `[[sources]]` block per chain to watch, so a single
    /// validator process can sign transfers originating on B *and* C.
    #[serde(default)]
    pub sources: Vec<SourceChain>,
    /// How this node holds its signing key (raw dev key, env var, or — for
    /// production — an encrypted keystore). See [`SignerConfig`].
    pub signer: SignerConfig,
    pub store: StoreConfig,
    /// Optional operator HTTP API (pause/resume/rescan/status).
    #[serde(default)]
    pub api: Option<Api>,
    /// Optional refund attestation loop. Absent => this validator never attests
    /// cancels or refunds, and stuck transfers stay stuck (safe default: a
    /// validator that cannot see the destination chain must not vote on whether
    /// a transfer was delivered).
    #[serde(default)]
    pub refund: Option<RefundConfig>,
    /// Peer chains this validator can read gate state from, for the H-2
    /// bridge-decimals cross-check (audit 2026-09-16).
    ///
    /// The submissionId does not commit to the scale an amount is in, so a
    /// destination gate registered one digit off pays a power of ten wrong on an
    /// ordinary transfer. `claim` is permissionless, so a validator withholding
    /// its signature is the only thing that still prevents it — and to decide
    /// that, the validator must be able to read the destination gate.
    ///
    /// A peer with no entry here CANNOT be verified, so transfers to it are not
    /// signed. Left empty, this validator falls back to `refund.destinations`,
    /// which carries the same (chain_id, gate, rpcs) shape — so a deployment
    /// that already attests refunds gets the check without new configuration.
    #[serde(default)]
    pub destinations: Vec<RefundChain>,
    /// Solana gate programs this validator reads for the same H-2 check on
    /// EVM->Solana transfers. `[[destinations]]` can only describe an EVM gate,
    /// so without an entry here every transfer to Solana is refused — the check
    /// fails closed, and an EVM reader can never vouch for a Solana payout.
    #[serde(default)]
    pub solana_destinations: Vec<SolanaDestinationChain>,
    /// What this validator expects of the allowlist the store serves (audit
    /// 2026-09-16, M-5). Absent => the legacy default: enforce whatever the
    /// store says, and accept an empty list as "allow everything".
    #[serde(default)]
    pub allowlist: AllowlistPolicy,
}

/// One Solana gate program the H-2 check can read.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SolanaDestinationChain {
    pub chain_id: u64,
    /// The gate program id, base58.
    pub program_id: String,
    /// Solana JSON-RPC URL.
    pub rpc: String,
}

impl SolanaDestinationChain {
    /// The program id as the 32 raw bytes PDA derivation hashes.
    pub fn program_key(&self) -> anyhow::Result<[u8; 32]> {
        let raw = bs58::decode(self.program_id.trim())
            .into_vec()
            .map_err(|e| anyhow::anyhow!("solana destination {}: program_id is not base58: {e}", self.chain_id))?;
        raw.try_into().map_err(|v: Vec<u8>| {
            anyhow::anyhow!(
                "solana destination {}: program_id decodes to {} bytes, expected 32",
                self.chain_id,
                v.len()
            )
        })
    }
}

impl Config {
    /// Peer chains usable for the H-2 check: the dedicated list when given, else
    /// the refund loop's destinations, which are the same thing by another name.
    pub fn scale_destinations(&self) -> &[RefundChain] {
        if !self.destinations.is_empty() {
            return &self.destinations;
        }
        match self.refund.as_ref() {
            Some(r) => &r.destinations,
            None => &[],
        }
    }
}

/// Drives the two-phase refund attestation loop.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefundConfig {
    /// **ENFORCED HERE — finding H-2.** How long a transfer must sit unclaimed
    /// before this validator will attest a cancel.
    ///
    /// This used to be advisory, with the real gate being the indexer's
    /// eligibility sweep flipping `refund_status = 'eligible'` in Postgres. That
    /// put the entire unclaimed-timeout on a database column no validator
    /// verified: a wrong `created_at`, clock skew, or DB write access nominated
    /// healthy in-flight transfers, and the validators attested cancels for them
    /// within one poll interval — irreversibly foreclosing payouts the keeper was
    /// still about to deliver.
    ///
    /// The loop now establishes the age itself, from the source chain, by reading
    /// `sentBy(id)` at a block whose own timestamp is at least this many seconds
    /// behind the chain head. The store still nominates candidates; it no longer
    /// decides when one is old enough. Set it to match the indexer's
    /// `refund_timeout_secs` so the two agree on the intended window — but the
    /// value here is the one that binds.
    #[serde(default = "default_refund_timeout")]
    pub timeout_secs: i64,
    #[serde(default = "default_refund_interval")]
    pub poll_interval_ms: u64,
    /// **Finality buffer — SECURITY CRITICAL.** `executed`/`cancelled`/`sentBy`
    /// are read at `latest - block_confirmation`. A refund on the source chain is
    /// irreversible once it pays out, and it is authorised solely on having read
    /// `cancelled == true` on the destination. If that read is at the chain tip
    /// (buffer 0) and the destination later reorgs the `cancel` away, the
    /// original claim signatures become live again → the transfer is paid on the
    /// destination AND refunded on the source (a double-spend of bridge
    /// liquidity). This MUST exceed the destination chain's maximum reorg depth
    /// (its finality). `Config::load` refuses to start with a 0 buffer unless
    /// `allow_zero_confirmation` is set (only safe on instant-finality dev chains
    /// such as anvil).
    #[serde(default)]
    pub block_confirmation: u64,
    /// Opt out of the non-zero `block_confirmation` requirement. ONLY for
    /// instant-finality local chains (anvil) that never reorg. Never set this
    /// against a real network.
    #[serde(default)]
    pub allow_zero_confirmation: bool,
    /// Every destination chain this validator can independently verify. A
    /// transfer bound for a chain not listed here is never attested.
    #[serde(default)]
    pub destinations: Vec<RefundChain>,
}

/// One chain the refund loop can read gate state from.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefundChain {
    pub chain_id: u64,
    #[serde(default)]
    pub rpc: Option<String>,
    #[serde(default)]
    pub rpcs: Vec<String>,
    pub gate: String,
}

impl RefundChain {
    pub fn endpoints(&self) -> anyhow::Result<Vec<String>> {
        endpoints(&self.rpc, &self.rpcs, &format!("refund destination {}", self.chain_id))
    }
}

/// Resolve the `rpc` / `rpcs` pair either block accepts into one ordered,
/// deduplicated, non-empty endpoint list. `what` names the block in the error.
///
/// The single-`rpc` form is back-compat; when both are given the singular one
/// leads, so an operator adding `rpcs` for failover keeps their existing primary.
fn endpoints(rpc: &Option<String>, rpcs: &[String], what: &str) -> anyhow::Result<Vec<String>> {
    let mut out = rpcs.to_vec();
    if let Some(rpc) = rpc {
        if !out.iter().any(|u| u == rpc) {
            out.insert(0, rpc.clone());
        }
    }
    anyhow::ensure!(!out.is_empty(), "{what} has no RPC endpoints (set `rpc` or `rpcs`)");
    Ok(out)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceChain {
    pub chain_id: u64,
    /// Single RPC (back-compat). Prefer `rpcs` for failover.
    #[serde(default)]
    pub rpc: Option<String>,
    /// Ordered list of RPC endpoints; the validator fails over to the next on error.
    #[serde(default)]
    pub rpcs: Vec<String>,
    pub gate: String,
    #[serde(default)]
    pub start_block: u64,
    /// **Finality buffer — SECURITY CRITICAL.** Only process up to
    /// `latest - block_confirmation`. Signing a `Sent` event at the chain tip lets
    /// a source reorg erase the deposit *after* validators have signed and the
    /// keeper has released destination liquidity — a double-spend of bridge funds.
    /// This MUST exceed the source chain's maximum reorg depth. `Config::load`
    /// refuses to start with a 0 buffer unless `allow_zero_confirmation` is set.
    #[serde(default)]
    pub block_confirmation: u64,
    /// Opt out of the non-zero `block_confirmation` requirement. ONLY for
    /// instant-finality local chains (anvil) that never reorg. Never set this
    /// against a real network. Mirrors `RefundConfig.allow_zero_confirmation`.
    #[serde(default)]
    pub allow_zero_confirmation: bool,
    #[serde(default = "default_interval")]
    pub poll_interval_ms: u64,
    /// Delay between windows while CATCHING UP — i.e. when the last range was
    /// capped by `max_block_range` and confirmed history is still unread.
    ///
    /// Defaults to `poll_interval_ms`, which is the conservative choice: how
    /// fast a scanner may read is a property of the ENDPOINT, not of the
    /// backlog. Reading back-to-back is what clears a fast chain's gap in
    /// minutes instead of hours, but on a shared rate-limited endpoint it also
    /// starves every other consumer of the same key — the API's pool reads and
    /// the indexer included — which shows up as 429s, not as slowness. So lower
    /// it only for an endpoint you know can take it (your own node, or a public
    /// RPC with a generous cap).
    #[serde(default)]
    pub catchup_poll_interval_ms: Option<u64>,
    #[serde(default = "default_range")]
    pub max_block_range: u64,
    /// Where to persist the resumable cursor + per-chain nonce state.
    #[serde(default = "default_state_file")]
    pub state_file: String,
}

impl SourceChain {
    /// Resolve the configured endpoints into a non-empty ordered list.
    pub fn endpoints(&self) -> anyhow::Result<Vec<String>> {
        endpoints(&self.rpc, &self.rpcs, &format!("source chain {}", self.chain_id))
    }
}

/// `deny_unknown_fields` (audit 2026-09-16, LOW): without it a misspelt or
/// unsupported key here — `token_env` was the one seen in practice, the name
/// every other block in this repo uses — parsed cleanly and was dropped, so the
/// operator believed the halt button was guarded by a token that was never read.
/// The API then fails closed (control routes unmounted), which is safe but reads
/// as an outage with no config error to explain it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Api {
    /// e.g. "127.0.0.1:9090"
    pub bind: String,
    /// Bearer token guarding pause/resume/rescan. Falls back to `token_env`, then
    /// to the `VALIDATOR_API_TOKEN` env var. Unset on all means the control routes
    /// are not served at all unless `allow_unauthenticated` says otherwise.
    #[serde(default)]
    pub token: Option<String>,
    /// Name of the environment variable holding the bearer token, so the secret
    /// need not sit in the config file. When set it is authoritative: a named
    /// variable that is unset or empty resolves to NO token (control routes
    /// unmounted) rather than silently falling back to `VALIDATOR_API_TOKEN`.
    #[serde(default)]
    pub token_env: Option<String>,
    /// Serve pause/resume/rescan with NO authentication when no token is set.
    /// Dev only — those routes can halt this validator out of quorum.
    #[serde(default)]
    pub allow_unauthenticated: bool,
}

impl Api {
    /// The configured token; else the variable `token_env` names; else (only when
    /// `token_env` is absent) the `VALIDATOR_API_TOKEN` env var.
    pub fn resolved_token(&self) -> Option<String> {
        self.resolve_token_with(|k| std::env::var(k).ok())
    }

    fn resolve_token_with(&self, env: impl Fn(&str) -> Option<String>) -> Option<String> {
        if let Some(t) = self.token.clone().filter(|t| !t.is_empty()) {
            return Some(t);
        }
        let var = self.token_env.as_deref().unwrap_or("VALIDATOR_API_TOKEN");
        env(var).filter(|t| !t.is_empty())
    }
}

fn default_interval() -> u64 {
    1000
}
fn default_range() -> u64 {
    1000
}
fn default_state_file() -> String {
    "validator-state.json".into()
}
fn default_refund_timeout() -> i64 {
    3600
}
fn default_refund_interval() -> u64 {
    15_000
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading config {path}: {e}"))?;
        Self::from_toml(&raw)
    }

    /// Parse + validate a config from a TOML string. Split out from [`load`] so the
    /// fail-closed checks below can be unit-tested without touching the filesystem.
    pub fn from_toml(raw: &str) -> anyhow::Result<Self> {
        let mut cfg: Config = toml::from_str(raw)?;

        // Backward compatibility: a single `[source]` is a one-element list.
        if let Some(s) = cfg.source.take() {
            cfg.sources.insert(0, s);
        }
        if cfg.sources.is_empty() {
            anyhow::bail!("config needs at least one [[sources]] block (or a legacy [source])");
        }

        // Each source must be a distinct chain and own a distinct state file,
        // otherwise two scan loops would clobber each other's cursor.
        ensure_unique(&cfg.sources, |s| s.chain_id, "source chain_id")?;
        ensure_unique(&cfg.sources, |s| s.state_file.as_str(), "source state_file")?;

        // SECURITY: signing a `Sent` event at the source chain tip lets a reorg
        // erase the deposit *after* the keeper has already released destination
        // liquidity — a double-spend of bridge funds. Refuse a 0 finality buffer
        // unless the operator explicitly opts out for an instant-finality dev
        // chain. (Mirrors the refund reader's guard below; before this check the
        // shipped `allow_zero_confirmation` on `[source]` was silently ignored.)
        for s in &cfg.sources {
            if s.block_confirmation == 0 && !s.allow_zero_confirmation {
                anyhow::bail!(
                    "source chain_id {} has block_confirmation = 0 — the validator would sign \
                     Sent events at the chain tip, so a source reorg could erase a deposit after \
                     the destination was paid (double-spend). Set block_confirmation to exceed \
                     the source chain's finality depth, or set allow_zero_confirmation = true \
                     ONLY for an instant-finality dev chain (e.g. anvil).",
                    s.chain_id
                );
            }
        }

        // H-2 peers: each chain may be described once across both lists, and a
        // Solana program id must actually be a 32-byte key. Caught here rather
        // than as a refusal on the first transfer to that chain.
        {
            let mut seen = std::collections::HashSet::new();
            for id in cfg.destinations.iter().map(|d| d.chain_id)
                .chain(cfg.solana_destinations.iter().map(|d| d.chain_id))
            {
                if !seen.insert(id) {
                    anyhow::bail!(
                        "destination chain_id {id} is listed more than once across \
                         [[destinations]] and [[solana_destinations]]"
                    );
                }
            }
            for d in &cfg.solana_destinations {
                d.program_key()?;
                if d.rpc.trim().is_empty() {
                    anyhow::bail!("solana destination {}: rpc is empty", d.chain_id);
                }
            }
        }

        if let Some(api) = &cfg.api {
            if api.token.as_deref().is_some_and(|t| !t.is_empty()) && api.token_env.is_some() {
                anyhow::bail!("[api] sets both `token` and `token_env`; keep one");
            }
            if api.token_env.as_deref().is_some_and(|v| v.trim().is_empty()) {
                anyhow::bail!("[api] token_env is empty; name the variable holding the token");
            }
        }

        // A refund block with no destinations can never attest anything; that is
        // almost certainly a misconfiguration rather than an intent to disable.
        if let Some(refund) = &cfg.refund {
            if refund.destinations.is_empty() {
                anyhow::bail!(
                    "[refund] has no [[refund.destinations]]; remove the block to disable \
                     refund attestation, or list the destination chains to verify"
                );
            }
            ensure_unique(&refund.destinations, |d| d.chain_id, "refund destination chain_id")?;

            // SECURITY: a source-chain refund is irreversible and is authorised
            // only on a destination `cancelled` read. Reading at the chain tip
            // lets a destination reorg re-enable the original claim after the
            // refund is signed → double-spend. Refuse to start at buffer 0 unless
            // the operator explicitly opts out for an instant-finality dev chain.
            if refund.block_confirmation == 0 && !refund.allow_zero_confirmation {
                anyhow::bail!(
                    "[refund] block_confirmation is 0 — refund attestations would read the \
                     destination at the chain tip, so a reorg could enable a double-spend. \
                     Set block_confirmation to exceed the destination chain's finality depth, \
                     or set allow_zero_confirmation = true ONLY for an instant-finality dev \
                     chain (e.g. anvil)."
                );
            }

            // SECURITY (H-2): `timeout_secs` is the age gate the refund loop
            // enforces ITSELF, on-chain, before attesting a cancel — a transfer
            // younger than this is still the keeper's to deliver. Zero or negative
            // would make every unclaimed transfer immediately cancellable, which is
            // a censorship primitive against in-flight transfers; fail closed
            // exactly as `block_confirmation` does (audit 2026-09-09).
            if refund.timeout_secs <= 0 {
                anyhow::bail!(
                    "[refund] timeout_secs = {} — must be > 0. This is the on-chain age gate \
                     that stops validators cancelling a transfer the keeper is still about to \
                     deliver; 0 or negative would disable it and let every fresh transfer be \
                     burned on the destination immediately.",
                    refund.timeout_secs
                );
            }

            // Liveness: the refund loop still takes its CANDIDATES from the store's
            // `refund_candidates` (which the indexer's eligibility sweep populates)
            // and only then re-derives the age on-chain. The local file store has
            // no lifecycle, so `refund_candidates` there is "every record ever
            // signed": harmless for safety (the on-chain checks still bind) but
            // it would make every validator re-read gate state for the whole
            // history on every poll. Require the HTTP store for the refund path.
            if cfg.store.url.is_none() {
                anyhow::bail!(
                    "[refund] requires an HTTP [store] (url = \"http://sig-store…\"): the file \
                     store keeps no lifecycle, so refund candidates there would be every \
                     record ever signed, re-verified on-chain on every poll."
                );
            }
        }

        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A minimal single-source config with an explicit finality buffer; each test
    // tweaks the `[source]` block to exercise the fail-closed rule.
    fn cfg(source_body: &str) -> String {
        format!(
            "[source]\n\
             chain_id = 1337\n\
             rpcs = [\"http://localhost:8545\"]\n\
             gate = \"0x0000000000000000000000000000000000000001\"\n\
             {source_body}\n\
             [signer]\n\
             private_key = \"0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d\"\n\
             [store]\n\
             dir = \"./sigs\"\n"
        )
    }

    // --- H-2 bridge-decimals cross-check coverage (audit 2026-09-16) ---------

    const PEER: &str = "chain_id = 1338\n\
         rpcs = [\"http://localhost:8546\"]\n\
         gate = \"0x0000000000000000000000000000000000000002\"\n";

    /// The dedicated list is what the check uses when it is given.
    #[test]
    fn scale_destinations_prefers_the_dedicated_list() {
        let toml = format!("{}[[destinations]]\n{PEER}", cfg("block_confirmation = 12"));
        let c = Config::from_toml(&toml).expect("loads");
        let d = c.scale_destinations();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].chain_id, 1338);
    }

    /// An existing deployment already lists its peers under `[refund.destinations]`
    /// — the same (chain_id, gate, rpcs) shape. Falling back to it means the H-2
    /// check turns on without anyone editing a config, which matters because the
    /// check fails CLOSED: no peers means no signatures.
    #[test]
    fn scale_destinations_falls_back_to_the_refund_block() {
        let c = Config::from_toml(&refund_cfg("")).expect("loads");
        assert!(c.destinations.is_empty(), "premise: no dedicated list");
        assert_eq!(c.scale_destinations().len(), c.refund.as_ref().unwrap().destinations.len());
        assert!(!c.scale_destinations().is_empty(), "the refund peers are used");
    }

    /// EVM->Solana: a Solana gate is described by its program id, and must load.
    #[test]
    fn a_solana_destination_loads_with_a_real_program_id() {
        let toml = format!(
            "{}[[solana_destinations]]\nchain_id = 7565164\n\
             program_id = \"Bvh4JxhWBCFXfc4iu8Cm9PCw86EAH4Yn39pHpzwnQFc1\"\n\
             rpc = \"https://api.devnet.solana.com\"\n",
            cfg("block_confirmation = 12")
        );
        let c = Config::from_toml(&toml).expect("loads");
        assert_eq!(c.solana_destinations.len(), 1);
        assert_eq!(c.solana_destinations[0].program_key().unwrap().len(), 32);
    }

    /// A malformed program id is a startup error, not a refusal on the first
    /// transfer to Solana hours later.
    #[test]
    fn a_bad_solana_program_id_is_refused_at_startup() {
        for bad in ["not-base58-0OIl", "11111111111111111111111111111111111111111111111111"] {
            let toml = format!(
                "{}[[solana_destinations]]\nchain_id = 7565164\nprogram_id = \"{bad}\"\n\
                 rpc = \"https://api.devnet.solana.com\"\n",
                cfg("block_confirmation = 12")
            );
            assert!(Config::from_toml(&toml).is_err(), "{bad} must be refused");
        }
    }

    /// One chain, one description: an id listed as both an EVM and a Solana peer
    /// would make which reader answers depend on insertion order.
    #[test]
    fn a_chain_listed_as_both_evm_and_solana_is_refused() {
        let toml = format!(
            "{}[[destinations]]\n{PEER}[[solana_destinations]]\nchain_id = 1338\n\
             program_id = \"Bvh4JxhWBCFXfc4iu8Cm9PCw86EAH4Yn39pHpzwnQFc1\"\n\
             rpc = \"https://api.devnet.solana.com\"\n",
            cfg("block_confirmation = 12")
        );
        let err = Config::from_toml(&toml).unwrap_err().to_string();
        assert!(err.contains("more than once"), "got: {err}");
    }

    /// Neither configured => empty, and the caller withholds every signature.
    /// Asserted so the fail-closed default cannot be silently inverted later.
    #[test]
    fn scale_destinations_is_empty_when_nothing_is_configured() {
        let c = Config::from_toml(&cfg("block_confirmation = 12")).expect("loads");
        assert!(c.scale_destinations().is_empty());
    }

    #[test]
    fn source_zero_confirmation_is_rejected_by_default() {
        // Omitted block_confirmation defaults to 0 -> must fail closed.
        let err = Config::from_toml(&cfg("")).unwrap_err().to_string();
        assert!(err.contains("block_confirmation = 0"), "got: {err}");

        // Explicit 0 without the opt-in -> must fail closed.
        let err = Config::from_toml(&cfg("block_confirmation = 0"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("block_confirmation = 0"), "got: {err}");
    }

    #[test]
    fn source_zero_confirmation_opt_in_is_honored() {
        // The opt-in must actually be read (the H1 bug: it was silently dropped).
        let c = Config::from_toml(&cfg("block_confirmation = 0\nallow_zero_confirmation = true"))
            .expect("opt-in should load");
        assert!(c.sources[0].allow_zero_confirmation);
        assert_eq!(c.sources[0].block_confirmation, 0);
    }

    #[test]
    fn source_nonzero_confirmation_is_accepted() {
        let c = Config::from_toml(&cfg("block_confirmation = 12")).expect("nonzero should load");
        assert_eq!(c.sources[0].block_confirmation, 12);
        assert!(!c.sources[0].allow_zero_confirmation);
    }

    /// A refund block for the H-2 tests: HTTP store, one destination, a sane
    /// finality buffer; `refund_body` is appended to the `[refund]` table.
    fn refund_cfg(refund_body: &str) -> String {
        format!(
            "[source]\n\
             chain_id = 1337\n\
             rpcs = [\"http://localhost:8545\"]\n\
             gate = \"0x0000000000000000000000000000000000000001\"\n\
             block_confirmation = 3\n\
             [signer]\n\
             private_key = \"0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d\"\n\
             [store]\n\
             url = \"http://sig-store:8080\"\n\
             [refund]\n\
             block_confirmation = 3\n\
             {refund_body}\n\
             [[refund.destinations]]\n\
             chain_id = 1338\n\
             rpcs = [\"http://localhost:8546\"]\n\
             gate = \"0x0000000000000000000000000000000000000002\"\n"
        )
    }

    /// Audit 2026-09-09: a zero or negative `timeout_secs` silently disabled the
    /// on-chain age gate (H-2), making every fresh transfer cancellable at once.
    #[test]
    fn refund_timeout_must_be_positive() {
        for bad in ["timeout_secs = 0", "timeout_secs = -1", "timeout_secs = -3600"] {
            let err = Config::from_toml(&refund_cfg(bad)).unwrap_err().to_string();
            assert!(err.contains("timeout_secs"), "{bad}: got {err}");
        }
        let c = Config::from_toml(&refund_cfg("timeout_secs = 1")).expect("1s is a legal gate");
        assert_eq!(c.refund.unwrap().timeout_secs, 1);
        // The default is positive and therefore fine.
        let c = Config::from_toml(&refund_cfg("")).expect("default should load");
        assert_eq!(c.refund.unwrap().timeout_secs, 3600);
    }

    #[test]
    fn misspelled_field_is_rejected_not_ignored() {
        // deny_unknown_fields: a typo like `allow_zero_confirmations` (trailing s)
        // must be an error, not a silently-ignored no-op that leaves buffer 0.
        let err = Config::from_toml(&cfg(
            "block_confirmation = 0\nallow_zero_confirmations = true",
        ))
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("allow_zero_confirmations") || err.contains("unknown field"),
            "got: {err}"
        );
    }

    /// THE regression (audit 2026-09-16, LOW). `token_env` used to parse and be
    /// dropped, because `[api]` had no `deny_unknown_fields`; the token named
    /// there was never read. It is now honoured.
    #[test]
    fn api_token_env_is_read_not_dropped() {
        let raw = cfg("block_confirmation = 2\n")
            + "[api]\nbind = \"127.0.0.1:9090\"\ntoken_env = \"MY_API_TOKEN\"\n";
        let c = Config::from_toml(&raw).unwrap();
        let api = c.api.unwrap();
        let env = |k: &str| (k == "MY_API_TOKEN").then(|| "from-env".to_string());
        assert_eq!(api.resolve_token_with(env).as_deref(), Some("from-env"));
        // Named and unset: no token, and NOT a silent fallback to the default var.
        let only_default = |k: &str| (k == "VALIDATOR_API_TOKEN").then(|| "other".to_string());
        assert_eq!(api.resolve_token_with(only_default), None);
    }

    #[test]
    fn api_without_token_env_keeps_the_default_variable() {
        let raw = cfg("block_confirmation = 2\n") + "[api]\nbind = \"127.0.0.1:9090\"\n";
        let api = Config::from_toml(&raw).unwrap().api.unwrap();
        let env = |k: &str| (k == "VALIDATOR_API_TOKEN").then(|| "dflt".to_string());
        assert_eq!(api.resolve_token_with(env).as_deref(), Some("dflt"));
        let inline = Config::from_toml(&(cfg("block_confirmation = 2\n")
            + "[api]\nbind = \"127.0.0.1:9090\"\ntoken = \"inline\"\n"))
        .unwrap()
        .api
        .unwrap();
        assert_eq!(inline.resolve_token_with(env).as_deref(), Some("inline"));
    }

    #[test]
    fn api_rejects_unknown_keys_and_ambiguous_tokens() {
        let base = cfg("block_confirmation = 2\n") + "[api]\nbind = \"127.0.0.1:9090\"\n";
        let typo = format!("{base}allow_unauthenticted = true\n");
        assert!(Config::from_toml(&typo).is_err(), "a misspelt key must not parse");
        let both = format!("{base}token = \"a\"\ntoken_env = \"B\"\n");
        assert!(Config::from_toml(&both).is_err());
        let empty = format!("{base}token_env = \" \"\n");
        assert!(Config::from_toml(&empty).is_err());
    }

    /// Adding `deny_unknown_fields` must not break a config anyone ships: every
    /// tracked validator config in the repo still parses its `[api]` block.
    #[test]
    fn tracked_validator_configs_still_parse() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
        for rel in [
            "docker/configs/val1.toml",
            "docker/configs/val2.toml",
            "docker/configs/val3.toml",
            "docker/production/validator/configs/validator.toml.example",
        ] {
            let raw = std::fs::read_to_string(format!("{root}/{rel}")).unwrap_or_else(|e| panic!("{rel}: {e}"));
            // Only the TOML shape is under test here; environment-dependent
            // validation (keys, RPCs) is not.
            if let Err(e) = toml::from_str::<Config>(&raw) {
                panic!("{rel} no longer parses: {e}");
            }
        }
    }
}
