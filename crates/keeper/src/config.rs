use bridge_core::allow::AllowlistPolicy;
use bridge_core::backend::StoreConfig;
use bridge_core::config::ensure_unique;
use bridge_core::signer::SignerConfig;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Legacy single-target form: `[target]`. Folded into `targets` on load.
    #[serde(default)]
    pub target: Option<ChainCfg>,
    /// Multi-target form: one `[[targets]]` block per destination chain the
    /// keeper should deliver claims to (e.g. chainB *and* chainC).
    #[serde(default)]
    pub targets: Vec<ChainCfg>,
    /// How the keeper holds the funded gas-payer key that signs `claim()` txs
    /// (raw dev key, env var, or an encrypted keystore). See [`SignerConfig`].
    pub keeper: SignerConfig,
    pub store: StoreConfig,
    /// Source chains this keeper can submit `refund()` to. Refunds execute on the
    /// chain the funds were locked on, which is the *source* of a transfer — so
    /// they need their own blocks, separate from the claim targets. Empty (the
    /// default) means this keeper never submits refunds.
    #[serde(default)]
    pub sources: Vec<ChainCfg>,
    /// What this keeper expects of the allowlist the store serves (audit
    /// 2026-09-16, M-5). Absent => the legacy default. The keeper is the second
    /// enforcement gate after the validators, so an operator running with
    /// `require = true` should set it in both.
    #[serde(default)]
    pub allowlist: AllowlistPolicy,
}

/// One chain the keeper submits transactions to.
///
/// A `[[targets]]` block (claims + cancels, on the destination) and a
/// `[[sources]]` block (refunds, on the chain the funds were locked on) take
/// exactly the same settings — only the loop that consumes them differs — so
/// they share one type rather than two that must be kept in step.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainCfg {
    pub chain_id: u64,
    pub rpc: String,
    pub gate: String,
    #[serde(default = "default_interval")]
    pub poll_interval_ms: u64,
}

fn default_interval() -> u64 {
    1000
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading config {path}: {e}"))?;
        Self::from_toml(&raw)
    }

    /// Parse + validate from a TOML string. Split out from [`load`] so the checks
    /// below are unit-testable without touching the filesystem.
    pub fn from_toml(raw: &str) -> anyhow::Result<Self> {
        let mut cfg: Config = toml::from_str(raw)?;

        // Backward compatibility: a single `[target]` is just a one-element list.
        if let Some(t) = cfg.target.take() {
            cfg.targets.insert(0, t);
        }
        if cfg.targets.is_empty() {
            anyhow::bail!("config needs at least one [[targets]] block (or a legacy [target])");
        }

        // Guard against two blocks claiming the same chain: two loops on one chain
        // would submit from the same account and contend on its nonce.
        ensure_unique(&cfg.targets, |t| t.chain_id, "target chain_id")?;
        ensure_unique(&cfg.sources, |s| s.chain_id, "source chain_id")?;

        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(body: &str) -> String {
        format!(
            "{body}\n\
             [keeper]\n\
             private_key = \"0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a\"\n\
             [store]\n\
             url = \"http://127.0.0.1:8080\"\n"
        )
    }

    const TARGET: &str = "[target]\n\
                          chain_id = 1338\n\
                          rpc = \"http://127.0.0.1:8546\"\n\
                          gate = \"0x0000000000000000000000000000000000000001\"\n";

    #[test]
    fn legacy_target_block_loads() {
        let c = Config::from_toml(&cfg(TARGET)).expect("should load");
        assert_eq!(c.targets.len(), 1);
        assert_eq!(c.targets[0].chain_id, 1338);
    }

    // M-4: a misspelled key must be an ERROR, not a silently-ignored no-op. The
    // validator got `deny_unknown_fields` in the H1 work; the keeper did not, so a
    // typo here used to fall back to a default (or drop a whole refund source)
    // with no signal at all.
    #[test]
    fn misspelled_field_is_rejected_not_ignored() {
        let err = Config::from_toml(&cfg(&format!("{TARGET}poll_interval_msec = 500\n")))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("poll_interval_msec") || err.contains("unknown field"),
            "got: {err}"
        );
    }

    // The costliest typo: `[[source]]` instead of `[[sources]]` silently produced
    // a keeper that never submits a single refund.
    #[test]
    fn misspelled_sources_table_is_rejected() {
        let body = format!(
            "{TARGET}\n[[source]]\n\
             chain_id = 1337\n\
             rpc = \"http://127.0.0.1:8545\"\n\
             gate = \"0x0000000000000000000000000000000000000002\"\n"
        );
        let err = Config::from_toml(&cfg(&body)).unwrap_err().to_string();
        assert!(err.contains("source") || err.contains("unknown field"), "got: {err}");
    }

    #[test]
    fn duplicate_target_chain_is_rejected() {
        let body = format!("{TARGET}\n[[targets]]\n\
             chain_id = 1338\n\
             rpc = \"http://127.0.0.1:8546\"\n\
             gate = \"0x0000000000000000000000000000000000000003\"\n");
        let err = Config::from_toml(&cfg(&body)).unwrap_err().to_string();
        assert!(err.contains("duplicate target chain_id"), "got: {err}");
    }

    #[test]
    fn no_target_at_all_is_rejected() {
        let err = Config::from_toml(&cfg("")).unwrap_err().to_string();
        assert!(err.contains("at least one"), "got: {err}");
    }
}
