Gate (UUPS; storage from __gap, slots 0-20 unchanged):
- M-1 replacing/removing a set guardian after setup is timelocked and
  cancellable by the current guardian; raw scheduleGovernance(bytes32) is
  removed in favour of typed schedule* calls that emit decoded params;
  codeless tokens refused at schedule time; action ids versioned (v2).
- M-2 per-token minSendAmount; autoParams capped at 4096 bytes in send

Swap (SwapPool/SwapRouter are not upgradeable: redeploy):
- M-1 stable rescue is debited by every settlement since its notice
  (stableSettledOut); keeper gains a SwapRouter.finalize loop.
- M-2 one setPrice may move the price by at most min(maxDeviation, fee);
  deploy defaults new pools to 30 bps; keepers step by that cap.
- M-3 setPrice(token, expectedOld, newPrice) compare-and-set; the
  price-keeper sends the price it planned from.
- M-4 keeper per-target min_claim dust floor (default off).

Validator / sig-store:
- M-1 scan head is the strict-majority head; rotate off a lagging
  endpoint; idle-scan warning.
- M-2 logs compared as multisets; duplicate positions are a disagreement.
- M-3 a required allowlist with either dimension empty is refused.
- M-4 per-validator Sign tokens (SIG_STORE_VALIDATOR_TOKENS), each its own
  rate-limit bucket and identity; generator issues one per holder; batch
  retries skip already-stored upserts.

API / frontend:
- M-1 --trusted-proxy client-IP keying; nginx overwrites XFF/X-Real-IP and
  adds limit_req; production subnet pinned.
- M-2 pool reads go through the cached upstream; bridgeDecimals is costed;
  negative scale results briefly cached.
- M-3 quotes keyed to the exact amount; no submit without a slippage floor;
  leg 2 quoted in destination-local units.
