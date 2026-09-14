import { useCallback, useEffect, useRef, useState } from "react";

/** Debounce a rapidly-changing value (e.g. an amount input driving a quote). */
export function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const id = setTimeout(() => setV(value), ms);
    return () => clearTimeout(id);
  }, [value, ms]);
  return v;
}

export interface PollResult<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  /** Manually re-run the fetch now. */
  refetch: () => void;
}

/**
 * Poll an async fetcher on an interval, keeping the last good data on error.
 * `deps` re-arms the poll (e.g. a filter change). The tab is polite: it skips
 * refetches while the document is hidden.
 */
export function usePoll<T>(fn: () => Promise<T>, deps: unknown[], intervalMs = 4000): PollResult<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const fnRef = useRef(fn);
  fnRef.current = fn;
  // Monotonic generation. Every run() bumps it and captures its own value; only
  // the newest run may write state. Without this, a slow request (or one from a
  // previous deps-arming) could resolve after a fresher one and clobber current
  // data with stale results — a flicker or a wrong-filter view.
  const genRef = useRef(0);
  // When the outstanding request of the CURRENT arming started (null = none).
  const inFlightRef = useRef<number | null>(null);

  const run = useCallback(async () => {
    const myGen = ++genRef.current;
    inFlightRef.current = Date.now();
    try {
      const d = await fnRef.current();
      if (genRef.current !== myGen) return; // superseded by a newer run
      setData(d);
      setError(null);
    } catch (e) {
      if (genRef.current !== myGen) return;
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      // Only the newest run clears loading (interval ticks don't re-raise it, so
      // the spinner shows on the initial arming, not on every background poll).
      if (genRef.current === myGen) {
        setLoading(false);
        inFlightRef.current = null;
      }
    }
  }, []);

  useEffect(() => {
    setLoading(true);
    inFlightRef.current = null;
    // A request that never settles (no fetch timeout) must not stall polling
    // forever: past this age a tick supersedes it after all.
    const stuckMs = Math.max(30_000, 3 * intervalMs);
    const id = setInterval(() => {
      // A tick must not supersede a request for the SAME deps that is merely
      // slow: when the backend takes longer than `intervalMs`, every response
      // would be discarded by the next tick and `data` would never arrive —
      // which is exactly how the Swap view sat on "No pool on this chain" while
      // the API answered in 13s against a 10s poll.
      const since = inFlightRef.current;
      if (document.visibilityState !== "hidden" && (since === null || Date.now() - since > stuckMs)) run();
    }, intervalMs);
    run();
    return () => {
      // Re-arming (deps changed) or unmount supersedes any in-flight request:
      // bumping the generation makes an older resolve a no-op.
      genRef.current++;
      clearInterval(id);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return { data, error, loading, refetch: run };
}
