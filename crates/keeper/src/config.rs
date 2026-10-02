use bridge_core::allow::AllowlistPolicy;
use bridge_core::backend::StoreConfig;
use bridge_core::config::ensure_unique;
use bridge_core::signer::SignerConfig;
use serde::Deserialize;
use std::collections::BTreeMap;

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
    /// `[[targets]]` only: the SwapRouters on this chain whose deliveries this
    /// keeper `finalize`s after claiming them (audit 2026-10-02, M7-2).
    ///
    /// A swap-and-bridge is claimed INTO the destination router, and only
    /// `SwapRouter.finalize` swaps it on to the user. The router's stable rescue
    /// is safe only if every such delivery is finalized (or deferred) within the
    /// rescue's 48 h notice — and nothing did that except the user's browser.
    /// Listed explicitly rather than guessed from `autoParams`, because a
    /// finalize is a call into the receiver contract at the keeper's expense.
    #[serde(default)]
    pub routers: Vec<String>,
    /// `[[targets]]` only: skip claiming transfers smaller than this, per asset
    /// (audit 2026-10-02, M7-12). Off by default.
    ///
    /// Keyed by `debridge_id` (`0x` + 64 hex); the value is in WHOLE tokens
    /// ("0.5", "10"), scaled by each transfer's own wire scale
    /// (`bridge_decimals`). A transfer below it is not claimed (or finalized) by
    /// this keeper — it is logged once and left to its sender, who can claim it
    /// themselves, or to the cancel/refund path. A 1-unit send from a cheap chain
    /// otherwise makes the keeper pay a full claim at the destination's prices.
    #[serde(default)]
    pub min_claim: BTreeMap<String, String>,
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

        for t in &cfg.targets {
            for r in &t.routers {
                parse_router(r).map_err(|e| anyhow::anyhow!("target {}: routers: {e}", t.chain_id))?;
            }
            for (id, min) in &t.min_claim {
                parse_debridge_id(id).map_err(|e| anyhow::anyhow!("target {}: min_claim: {e}", t.chain_id))?;
                parse_whole(min)
                    .ok_or_else(|| anyhow::anyhow!("target {}: min_claim {id} = {min:?} is not a decimal amount", t.chain_id))?;
            }
        }
        // The two keys only mean something on a claim target; on a refund
        // source they would be silently ignored, which is the M-4 failure mode.
        for s in &cfg.sources {
            if !s.routers.is_empty() || !s.min_claim.is_empty() {
                anyhow::bail!("source {}: `routers` and `min_claim` belong on a [[targets]] block", s.chain_id);
            }
        }

        Ok(cfg)
    }
}

impl ChainCfg {
    /// The configured routers, parsed (validated at load).
    pub fn router_addresses(&self) -> Vec<alloy_primitives::Address> {
        self.routers.iter().filter_map(|r| parse_router(r).ok()).collect()
    }

    /// The smallest wire amount this keeper will claim for `debridge_id` at
    /// `bridge_decimals`, or `None` when no minimum is configured for it.
    pub fn min_claim_wire(&self, debridge_id: &str, bridge_decimals: u8) -> Option<u128> {
        let key = debridge_id.to_ascii_lowercase();
        let (_, v) = self.min_claim.iter().find(|(k, _)| k.to_ascii_lowercase() == key)?;
        let (whole, frac) = parse_whole(v)?;
        scale(&whole, &frac, bridge_decimals)
    }
}

fn parse_router(s: &str) -> Result<alloy_primitives::Address, String> {
    s.parse::<alloy_primitives::Address>().map_err(|e| format!("{s:?} is not an address: {e}"))
}

fn parse_debridge_id(s: &str) -> Result<(), String> {
    let hex = s.strip_prefix("0x").ok_or_else(|| format!("{s:?} must be 0x-prefixed"))?;
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{s:?} is not a 32-byte debridge_id"));
    }
    Ok(())
}

/// "12.5" -> ("12", "5"). Digits only, at most one dot, not empty.
fn parse_whole(s: &str) -> Option<(String, String)> {
    let s = s.trim();
    let (w, f) = s.split_once('.').unwrap_or((s, ""));
    if (w.is_empty() && f.is_empty()) || !w.bytes().all(|b| b.is_ascii_digit()) || !f.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((w.to_owned(), f.to_owned()))
}

/// Whole units -> wire units at `decimals`, rounding a finer fraction UP so the
/// configured minimum is never undercut. `None` on overflow.
fn scale(whole: &str, frac: &str, decimals: u8) -> Option<u128> {
    let d = decimals as usize;
    let unit = 10u128.checked_pow(decimals as u32)?;
    let w: u128 = if whole.is_empty() { 0 } else { whole.parse().ok()? };
    let (kept, rest) = if frac.len() > d { frac.split_at(d) } else { (frac, "") };
    let mut f: u128 = if kept.is_empty() { 0 } else { kept.parse().ok()? };
    f = f.checked_mul(10u128.checked_pow((d - kept.len()) as u32)?)?;
    let round_up = rest.bytes().any(|b| b != b'0') as u128;
    w.checked_mul(unit)?.checked_add(f)?.checked_add(round_up)
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

    const DID: &str = "0x00000000000000000000000000000000000000000000000000000000000000aa";

    #[test]
    fn routers_and_min_claim_load_and_validate() {
        let body = format!(
            "{TARGET}routers = [\"0x00000000000000000000000000000000000000Ab\"]\n\
             [target.min_claim]\n\"{DID}\" = \"2.5\"\n"
        );
        let c = Config::from_toml(&cfg(&body)).expect("loads");
        let t = &c.targets[0];
        assert_eq!(t.router_addresses().len(), 1);
        assert_eq!(t.min_claim_wire(DID, 6), Some(2_500_000));
        assert_eq!(t.min_claim_wire(&DID.to_uppercase().replace("0X", "0x"), 6), Some(2_500_000), "case-insensitive");
        assert_eq!(t.min_claim_wire(DID, 0), Some(3), "a finer fraction rounds UP, never undercutting the floor");
        assert_eq!(t.min_claim_wire(DID, 18), Some(2_500_000_000_000_000_000));
        let other = "0x00000000000000000000000000000000000000000000000000000000000000bb";
        assert_eq!(t.min_claim_wire(other, 6), None, "no minimum for an unlisted asset: default off");
    }

    #[test]
    fn a_bad_min_claim_or_router_is_rejected() {
        for body in [
            format!("{TARGET}[target.min_claim]\n\"0x1234\" = \"1\"\n"),
            format!("{TARGET}[target.min_claim]\n\"{DID}\" = \"1e6\"\n"),
            format!("{TARGET}[target.min_claim]\n\"{DID}\" = \"-1\"\n"),
            format!("{TARGET}routers = [\"0xnotanaddress\"]\n"),
        ] {
            assert!(Config::from_toml(&cfg(&body)).is_err(), "{body}");
        }
    }

    #[test]
    fn routers_on_a_source_are_rejected_not_ignored() {
        let body = format!(
            "{TARGET}\n[[sources]]\n\
             chain_id = 1337\n\
             rpc = \"http://127.0.0.1:8545\"\n\
             gate = \"0x0000000000000000000000000000000000000002\"\n\
             routers = [\"0x00000000000000000000000000000000000000Ab\"]\n"
        );
        let err = Config::from_toml(&cfg(&body)).unwrap_err().to_string();
        assert!(err.contains("[[targets]]"), "{err}");
    }

    #[test]
    fn no_target_at_all_is_rejected() {
        let err = Config::from_toml(&cfg("")).unwrap_err().to_string();
        assert!(err.contains("at least one"), "got: {err}");
    }
}
