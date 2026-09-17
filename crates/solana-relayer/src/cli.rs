//! Pure argument handling shared by `gate-admin` and `swap-admin`, split out so
//! the rules an incident operator depends on are unit-tested rather than
//! discovered mid-incident.

/// The RPC endpoint for an admin tool: `--rpc <url>` or `--rpc-env <VAR>`.
///
/// A keyed provider URL passed as `--rpc` sits in the process table (`ps`), in
/// shell history, and in any CI log that echoes the command. `--rpc-env` names a
/// variable instead, so the key never touches argv. Exactly one is required, and
/// an error names the VARIABLE, never its value.
pub fn resolve_rpc(
    rpc: Option<String>,
    rpc_env: Option<String>,
    lookup: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<String> {
    match (rpc, rpc_env) {
        (Some(_), Some(_)) => anyhow::bail!("pass --rpc or --rpc-env, not both"),
        (Some(url), None) => Ok(url),
        (None, Some(var)) => lookup(&var)
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("--rpc-env {var}: that environment variable is unset or empty")),
        (None, None) => anyhow::bail!(
            "missing RPC endpoint: --rpc-env <VAR> (preferred for a keyed URL) or --rpc <url>"
        ),
    }
}

/// The amount a `cancel`/`refund` must be given: the WIRE amount, in the asset's
/// bridge decimals — the value the submissionId hashes.
///
/// `send --amount` takes MINT units, and these two commands used to take a flag
/// of the same name meaning something else. Passing the local amount out of habit
/// builds an id the validators never signed, which fails closed but costs an
/// operator the incident's scarcest resource. So the flag is `--wire-amount`, and
/// the old spelling is refused with the reason rather than reinterpreted.
pub fn wire_amount_flag(cmd: &str, amount: Option<String>, wire_amount: Option<String>) -> anyhow::Result<u64> {
    if amount.is_some() {
        anyhow::bail!(
            "`{cmd}` takes --wire-amount (the amount in the asset's BRIDGE decimals, as signed \
             in the submissionId), not --amount (which `send` reads in MINT units). \
             Use the `amount` field of the sig-store record."
        );
    }
    let raw = wire_amount.ok_or_else(|| anyhow::anyhow!("missing required flag --wire-amount"))?;
    raw.parse().map_err(|e| anyhow::anyhow!("--wire-amount {raw:?}: {e}"))
}

/// Cross-check a refund's `--wire-amount` against the program's own `["sent", id]`
/// record, which stores what `send` debited in MINT units.
///
/// `bridge_unit` is `10^(local - bridge)` from the asset record (`1` for a legacy
/// asset). A mismatch means the id being refunded is not the one that was sent;
/// the program would refuse it anyway, so say which number is wrong up front.
pub fn check_refund_amount(wire_amount: u64, bridge_unit: u64, recorded_local: u64) -> anyhow::Result<()> {
    match wire_amount.checked_mul(bridge_unit) {
        Some(local) if local == recorded_local => Ok(()),
        _ => anyhow::bail!(
            "--wire-amount {wire_amount} × bridge unit {bridge_unit} != the {recorded_local} mint units \
             this gate recorded at send — the WIRE amount is {}",
            recorded_local.checked_div(bridge_unit).unwrap_or(0)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_env_resolves_without_the_url_on_argv() {
        let lookup = |v: &str| (v == "SOL_RPC").then(|| "https://rpc.example/secret-key".to_string());
        assert_eq!(resolve_rpc(None, Some("SOL_RPC".into()), lookup).unwrap(), "https://rpc.example/secret-key");
    }

    #[test]
    fn an_unset_rpc_env_names_the_variable_not_a_value() {
        let err = resolve_rpc(None, Some("SOL_RPC".into()), |_| None).unwrap_err().to_string();
        assert!(err.contains("SOL_RPC"));
        let err = resolve_rpc(None, Some("SOL_RPC".into()), |_| Some("  ".into())).unwrap_err();
        assert!(err.to_string().contains("unset or empty"));
    }

    #[test]
    fn rpc_and_rpc_env_are_exclusive_and_one_is_required() {
        assert!(resolve_rpc(Some("http://a".into()), Some("V".into()), |_| Some("http://b".into())).is_err());
        assert!(resolve_rpc(None, None, |_| None).is_err());
        assert_eq!(resolve_rpc(Some("http://a".into()), None, |_| None).unwrap(), "http://a");
    }

    /// The incident-tool trap: `--amount` meant MINT units on `send` and WIRE
    /// units on `cancel`/`refund`. The ambiguous spelling is now refused.
    #[test]
    fn cancel_and_refund_refuse_the_ambiguous_amount_flag() {
        let err = wire_amount_flag("refund", Some("5000".into()), None).unwrap_err().to_string();
        assert!(err.contains("--wire-amount") && err.contains("MINT"), "{err}");
        assert!(wire_amount_flag("cancel", Some("5".into()), Some("5".into())).is_err());
        assert_eq!(wire_amount_flag("cancel", None, Some("5".into())).unwrap(), 5);
        assert!(wire_amount_flag("cancel", None, None).is_err());
    }

    #[test]
    fn a_refund_amount_is_checked_against_the_recorded_debit() {
        // 6 bridge decimals on a 9-decimal mint: unit 1000.
        check_refund_amount(5, 1_000, 5_000).unwrap();
        // The local amount passed as the wire amount: named, with the right value.
        let err = check_refund_amount(5_000, 1_000, 5_000).unwrap_err().to_string();
        assert!(err.contains("WIRE amount is 5"), "{err}");
        assert!(check_refund_amount(u64::MAX, 1_000, 5_000).is_err(), "overflow is a mismatch");
        check_refund_amount(7, 1, 7).unwrap(); // legacy asset
    }
}
