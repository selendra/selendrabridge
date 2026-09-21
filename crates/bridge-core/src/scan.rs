//! Block-window arithmetic shared by every log scanner in the mesh.
//!
//! Lives here rather than in one scanner because the validator and the indexer
//! read the SAME chains through the same hosted providers and hit the same
//! hazard: behind one URL is a pool of nodes at differing heights, so the head
//! one call reports is not the head the next call is served from. A scanner
//! that trusts the first and scans with the second walks past blocks nobody
//! read. The validator learned this in round 4; the indexer had its own copy of
//! the bug until the 2026-09-16 audit's M-7.

/// The last block a scan window may safely extend to on ONE endpoint, given the
/// head THAT endpoint reports.
///
/// `None` means the endpoint has nothing confirmed at or past `from_block` — a
/// node lagging behind whichever endpoint we last read the head from — and the
/// caller must not scan (or advance the cursor) on it at all this tick.
/// Otherwise the window is the requested `to_block`, clamped to what this
/// endpoint has actually finalised. Pure, so it is unit-tested directly.
pub fn clamp_scan_window(from_block: u64, to_block: u64, endpoint_head: u64, confirmations: u64) -> Option<u64> {
    let confirmed = endpoint_head.saturating_sub(confirmations);
    if confirmed < from_block {
        return None;
    }
    Some(to_block.min(confirmed))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pre-fix behaviour was `to_block` regardless of what the serving node
    /// knew. Every case here is one a scanner got wrong or right for the wrong
    /// reason.
    #[test]
    fn scan_window_is_clamped_to_the_serving_endpoints_head() {
        // Endpoint is at/ahead of the cached head: the requested window stands.
        assert_eq!(clamp_scan_window(100, 199, 210, 10), Some(199));
        assert_eq!(clamp_scan_window(100, 199, 209, 10), Some(199));
        // Endpoint lags: the window shrinks to what IT has confirmed.
        assert_eq!(clamp_scan_window(100, 199, 160, 10), Some(150));
        // Endpoint has nothing confirmed at from_block yet: do not scan at all.
        assert_eq!(clamp_scan_window(100, 199, 109, 10), None);
        assert_eq!(clamp_scan_window(100, 199, 5, 10), None, "saturating, not wrapping");
        // Exactly one block available.
        assert_eq!(clamp_scan_window(100, 199, 110, 10), Some(100));
        // Zero confirmations (dev chains) clamp to the head itself.
        assert_eq!(clamp_scan_window(100, 199, 150, 0), Some(150));
    }
}
