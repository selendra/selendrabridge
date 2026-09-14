use bridge_core::config::ensure_unique;
use bridge_core::signer::SignerConfig;
use serde::Deserialize;

/// `price-keeper.toml`.
///
/// ```toml
/// poll_interval_secs = 600
/// refresh_margin_secs = 21600   # reprice this long before maxPriceAge expires it
///
/// [oracle]                       # the pool's `oracle` key (SignerConfig)
/// private_key_env = "PRICE_ORACLE_KEY"
///
/// [[pools]]
/// chain_id = 11155111
/// rpc = "https://..."
/// pool = "0x..."
/// [[pools.tokens]]
/// symbol = "WRAP"
/// address = "0x..."
/// price = "3180"                 # whole hub units; the pool is kept at this price
/// ```
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub oracle: SignerConfig,
    #[serde(default = "default_poll")]
    pub poll_interval_secs: u64,
    #[serde(default = "default_margin")]
    pub refresh_margin_secs: i64,
    pub pools: Vec<PoolCfg>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolCfg {
    pub chain_id: u64,
    pub rpc: String,
    pub pool: String,
    pub tokens: Vec<TokenCfg>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenCfg {
    pub symbol: String,
    pub address: String,
    /// Target price in whole hub units ("3180", "0.5"). A static price: this
    /// service keeps the pool AT it, it does not discover it.
    pub price: String,
}

fn default_poll() -> u64 {
    600
}

/// Six hours: a day-long max age then gets refreshed at 18h, leaving room for a
/// stalled RPC or several missed polls before swaps stop.
fn default_margin() -> i64 {
    6 * 3600
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading config {path}: {e}"))?;
        Self::from_toml(&raw)
    }

    pub fn from_toml(raw: &str) -> anyhow::Result<Self> {
        let cfg: Config = toml::from_str(raw)?;
        if cfg.pools.is_empty() {
            anyhow::bail!("config needs at least one [[pools]] block");
        }
        if cfg.poll_interval_secs == 0 {
            anyhow::bail!("poll_interval_secs must be > 0");
        }
        if cfg.refresh_margin_secs <= 0 {
            anyhow::bail!("refresh_margin_secs must be > 0");
        }
        // One loop per chain, all sending from the oracle account: two blocks on
        // one chain would race each other's nonces.
        ensure_unique(&cfg.pools, |p| p.chain_id, "pool chain_id")?;
        for p in &cfg.pools {
            if p.tokens.is_empty() {
                anyhow::bail!("pool on chain {} lists no tokens", p.chain_id);
            }
            ensure_unique(&p.tokens, |t| t.address.to_ascii_lowercase(), "token address")?;
            for t in &p.tokens {
                if swap_math::refresh::parse_price(&t.price).is_none() {
                    anyhow::bail!(
                        "chain {} token {}: price {:?} is not a positive decimal in whole hub units",
                        p.chain_id,
                        t.symbol,
                        t.price
                    );
                }
            }
        }
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a";

    fn cfg(extra: &str, price: &str) -> String {
        format!(
            "{extra}\n[oracle]\nprivate_key = \"{KEY}\"\n\
             [[pools]]\nchain_id = 1337\nrpc = \"http://127.0.0.1:8545\"\n\
             pool = \"0x0000000000000000000000000000000000000001\"\n\
             [[pools.tokens]]\nsymbol = \"WRAP\"\n\
             address = \"0x0000000000000000000000000000000000000002\"\nprice = \"{price}\"\n"
        )
    }

    #[test]
    fn loads_with_defaults() {
        let c = Config::from_toml(&cfg("", "3180")).unwrap();
        assert_eq!(c.poll_interval_secs, 600);
        assert_eq!(c.refresh_margin_secs, 21600);
        assert_eq!(c.pools[0].tokens[0].symbol, "WRAP");
    }

    #[test]
    fn rejects_a_price_it_cannot_scale() {
        for bad in ["0", "-1", "3e3", ""] {
            let err = Config::from_toml(&cfg("", bad)).err().map(|e| e.to_string()).unwrap_or_default();
            assert!(err.contains("whole hub units"), "{bad:?}: {err}");
        }
    }

    #[test]
    fn rejects_unknown_fields() {
        assert!(Config::from_toml(&cfg("poll_interval = 5", "1")).is_err());
    }

    #[test]
    fn rejects_two_pools_on_one_chain() {
        let one = cfg("", "1");
        let pool = &one[one.find("[[pools]]").unwrap()..];
        let err = Config::from_toml(&format!("{one}{pool}")).err().unwrap().to_string();
        assert!(err.contains("chain_id"), "{err}");
    }
}
