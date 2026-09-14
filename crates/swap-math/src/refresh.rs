//! When — and to what — a price refresher should reprice a pool token.
//!
//! Both pools refuse a price older than their max age (`SwapPool.maxPriceAge`,
//! `PoolState::max_price_age`), so a pool with no oracle stops quoting a day
//! after its last `setPrice`. The EVM and Solana refreshers are two processes —
//! alloy and solana-client cannot share a binary — but the decision they make is
//! one function, here, so the two cannot drift into different rules.
//!
//! The on-chain guards this plans around are identical on both VMs:
//!
//! * **cooldown** — after the first reprice, another must wait
//!   `min_update_interval` seconds from `last_price_update`;
//! * **step cap** — every update may move the price by at most
//!   `max_deviation_bps` of the current price;
//! * **staleness** — swaps refuse a price older than `max_age`.
//!
//! A call that breaks a guard reverts and still costs gas, so the planner never
//! proposes one: it waits out a cooldown and walks a distant target in capped
//! steps instead.

use crate::{mul_div_floor, BPS_DENOM, PRICE_ONE};

/// A token's on-chain pricing state plus the pool's guards, as read just now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PriceState {
    /// Chain time (seconds). Use the chain's clock, not the host's: the guards
    /// compare against it.
    pub now: i64,
    pub price: u128,
    /// When the current price was established.
    pub price_set_at: i64,
    /// When the oracle last repriced; `0` = never (the cooldown is skipped).
    pub last_price_update: i64,
    /// The staleness bound; `None` when the pool enforces none (EVM `maxPriceAge == 0`).
    pub max_age: Option<i64>,
    pub min_update_interval: i64,
    pub max_deviation_bps: u16,
}

/// What to do about one token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plan {
    /// The price is at target and not yet due for a refresh.
    Idle,
    /// Something needs doing, but the cooldown forbids it until `until`.
    Wait { until: i64 },
    /// Send `setPrice(price)`. `step` is true when this is a capped step toward a
    /// target further away than one update may move.
    Set { price: u128, step: bool },
}

/// Decide what to send for a token whose price should be `target`.
///
/// `margin` is how long before the price would go stale to refresh it: large
/// enough to absorb a slow RPC, a missed poll or a congested chain.
pub fn plan(s: &PriceState, target: u128, margin: i64) -> Plan {
    let moving = s.price != target;
    let due = match s.max_age {
        Some(max_age) => s.now.saturating_sub(s.price_set_at) >= max_age.saturating_sub(margin).max(0),
        None => false,
    };
    if !moving && !due {
        return Plan::Idle;
    }
    if s.last_price_update != 0 {
        let until = s.last_price_update.saturating_add(s.min_update_interval);
        if s.now < until {
            return Plan::Wait { until };
        }
    }
    let cap = mul_div_floor(s.price, s.max_deviation_bps as u128, BPS_DENOM as u128).unwrap_or(0);
    let (next, step) = if s.price.abs_diff(target) <= cap {
        (target, false)
    } else if target > s.price {
        (s.price.saturating_add(cap), true)
    } else {
        (s.price.saturating_sub(cap), true)
    };
    // A zero cap cannot move the price at all; re-asserting it is still a valid
    // refresh when one is due, and pointless otherwise.
    if next == s.price && !due {
        return Plan::Idle;
    }
    Plan::Set { price: next, step }
}

/// Seconds until [`plan`] would call this price due for a refresh (0 = now),
/// or `None` when the pool enforces no age. For logging a healthy keeper's
/// schedule; the decision itself is always [`plan`].
pub fn due_in(s: &PriceState, margin: i64) -> Option<i64> {
    let max_age = s.max_age?;
    let due_at = s.price_set_at.saturating_add(max_age.saturating_sub(margin).max(0));
    Some(due_at.saturating_sub(s.now).max(0))
}

/// Parse a price in WHOLE hub units ("3180", "0.5") into the pools' PRICE_ONE
/// (1e18) fixed point — the same scaling the deploy script applies at listing.
/// `None` for anything malformed, zero, over 18 decimals, or out of range.
pub fn parse_price(s: &str) -> Option<u128> {
    let s = s.trim();
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    if whole.is_empty() && frac.is_empty() {
        return None;
    }
    if !whole.bytes().all(|b| b.is_ascii_digit()) || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if frac.len() > 18 {
        return None;
    }
    let whole: u128 = if whole.is_empty() { 0 } else { whole.parse().ok()? };
    let frac_scaled: u128 = if frac.is_empty() {
        0
    } else {
        frac.parse::<u128>().ok()?.checked_mul(10u128.pow(18 - frac.len() as u32))?
    };
    let v = whole.checked_mul(PRICE_ONE)?.checked_add(frac_scaled)?;
    (v > 0).then_some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86_400;
    const HOUR: i64 = 3_600;

    fn state(price: u128) -> PriceState {
        PriceState {
            now: 10 * DAY,
            price,
            price_set_at: 10 * DAY - HOUR,
            last_price_update: 10 * DAY - HOUR,
            max_age: Some(DAY),
            min_update_interval: HOUR,
            max_deviation_bps: 1_000,
        }
    }

    #[test]
    fn a_fresh_price_at_target_is_left_alone() {
        assert_eq!(plan(&state(3180), 3180, 6 * HOUR), Plan::Idle);
    }

    #[test]
    fn refreshes_inside_the_margin_before_it_goes_stale() {
        let mut s = state(3180);
        s.price_set_at = s.now - (DAY - 6 * HOUR); // exactly at the margin
        s.last_price_update = s.price_set_at;
        assert_eq!(plan(&s, 3180, 6 * HOUR), Plan::Set { price: 3180, step: false });
        s.price_set_at += 1;
        assert_eq!(plan(&s, 3180, 6 * HOUR), Plan::Idle, "one second earlier is not due");
    }

    /// The live failure this exists for: a price days past its max age.
    #[test]
    fn an_already_stale_price_is_reasserted() {
        let mut s = state(3180);
        s.price_set_at = s.now - 4 * DAY;
        s.last_price_update = s.price_set_at;
        assert_eq!(plan(&s, 3180, 6 * HOUR), Plan::Set { price: 3180, step: false });
    }

    #[test]
    fn never_refreshes_through_a_cooldown() {
        let mut s = state(3180);
        s.price_set_at = s.now - 4 * DAY; // due
        s.last_price_update = s.now - 60; // but repriced a minute ago
        assert_eq!(plan(&s, 3180, 6 * HOUR), Plan::Wait { until: s.now - 60 + HOUR });
    }

    #[test]
    fn the_first_reprice_after_listing_skips_the_cooldown() {
        let mut s = state(3180);
        s.price_set_at = s.now - 4 * DAY;
        s.last_price_update = 0;
        assert!(matches!(plan(&s, 3180, 6 * HOUR), Plan::Set { .. }));
    }

    #[test]
    fn a_distant_target_is_walked_in_capped_steps() {
        let s = state(1000 * PRICE_ONE);
        assert_eq!(plan(&s, 2000 * PRICE_ONE, 0), Plan::Set { price: 1100 * PRICE_ONE, step: true });
        assert_eq!(plan(&s, 500 * PRICE_ONE, 0), Plan::Set { price: 900 * PRICE_ONE, step: true });
        // Within one step: land exactly on target.
        assert_eq!(plan(&s, 1050 * PRICE_ONE, 0), Plan::Set { price: 1050 * PRICE_ONE, step: false });
    }

    #[test]
    fn a_step_never_exceeds_the_on_chain_cap() {
        for (price, target) in [(3180u128, 1u128), (1, 3180), (7, 9), (PRICE_ONE, u128::MAX / 2)] {
            let s = state(price);
            if let Plan::Set { price: next, .. } = plan(&s, target, 0) {
                let cap = mul_div_floor(price, 1_000, 10_000).unwrap();
                assert!(next.abs_diff(price) <= cap, "{price} -> {next} breaks cap {cap}");
            }
        }
    }

    #[test]
    fn a_pool_without_a_staleness_guard_only_moves_toward_target() {
        let mut s = state(3180);
        s.max_age = None;
        s.price_set_at = 0;
        assert_eq!(plan(&s, 3180, 6 * HOUR), Plan::Idle);
    }

    #[test]
    fn a_zero_cap_refreshes_but_does_not_pretend_to_move() {
        let mut s = state(5);
        s.max_deviation_bps = 1_000; // 10% of 5 floors to 0
        assert_eq!(plan(&s, 9, 6 * HOUR), Plan::Idle, "cannot move, not due");
        s.price_set_at = s.now - 2 * DAY;
        s.last_price_update = s.price_set_at;
        assert_eq!(plan(&s, 9, 6 * HOUR), Plan::Set { price: 5, step: true });
    }

    #[test]
    fn due_in_counts_down_to_the_same_moment_plan_refreshes() {
        let mut s = state(3180);
        s.price_set_at = s.now - HOUR;
        assert_eq!(due_in(&s, 6 * HOUR), Some(DAY - 6 * HOUR - HOUR));
        s.price_set_at = s.now - (DAY - 6 * HOUR);
        s.last_price_update = s.price_set_at;
        assert_eq!(due_in(&s, 6 * HOUR), Some(0));
        assert!(matches!(plan(&s, 3180, 6 * HOUR), Plan::Set { .. }), "due_in 0 <=> plan refreshes");
        s.max_age = None;
        assert_eq!(due_in(&s, 6 * HOUR), None);
    }

    #[test]
    fn parses_whole_hub_units_into_price_one() {
        assert_eq!(parse_price("3180"), Some(3180 * PRICE_ONE));
        assert_eq!(parse_price("1"), Some(PRICE_ONE));
        assert_eq!(parse_price("0.5"), Some(PRICE_ONE / 2));
        assert_eq!(parse_price(".25"), Some(PRICE_ONE / 4));
        assert_eq!(parse_price("2."), Some(2 * PRICE_ONE));
        assert_eq!(parse_price("0.000000000000000001"), Some(1));
        for bad in ["", ".", "0", "0.0", "-1", "1e3", "abc", "1.2.3", "0.0000000000000000001"] {
            assert_eq!(parse_price(bad), None, "{bad:?}");
        }
    }
}
