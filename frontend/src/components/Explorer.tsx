import { useEffect, useMemo, useState } from "react";
import { Dropdown, type DropdownOption } from "./Dropdown";
import { StatusBadge, RefundBadge } from "./StatusBadge";
import { Glyph, Refresh, ArrowRight, Search } from "./icons";
import { chainViz, formatWireAmount, shortHex, wireAmountTitle } from "../data/format";
import { fetchHistory, fetchStats, fetchSubmissions, fetchSwapHistory } from "../api/client";
import { usePoll } from "../api/hooks";
import type {
  Chain,
  HistoryEntry,
  Stats,
  Submission,
  SubmissionFilter,
  SwapHistoryEntry,
} from "../api/types";
import { SubmissionDetail } from "./SubmissionDetail";

interface ExplorerProps {
  chains: Chain[];
  initialFilter?: SubmissionFilter;
}

/*
 * No wallet, and no `decimals()` reads: every amount this view renders now
 * arrives with its own scale from the API (M-11/M-12). The explorer used to
 * read ERC-20 decimals per chain over RPC and apply them to amounts that were
 * in a different scale entirely — the reads were both wrong and, on a non-EVM
 * chain, impossible.
 */

const ANY = "any";

function ChainCell({ chains, id }: { chains: Chain[]; id: number }) {
  const name = chains.find((c) => c.chainId === id)?.name ?? `Chain ${id}`;
  const v = chainViz(id, name);
  return (
    <span className="chaincell">
      <Glyph gradient={v.gradient} size={18} />
      {name}
    </span>
  );
}

export function Explorer({ chains, initialFilter }: ExplorerProps) {
  const [from, setFrom] = useState<string>(
    initialFilter?.chainIdFrom != null ? String(initialFilter.chainIdFrom) : ANY
  );
  const [to, setTo] = useState<string>(
    initialFilter?.chainIdTo != null ? String(initialFilter.chainIdTo) : ANY
  );
  const [readyOnly, setReadyOnly] = useState<boolean>(initialFilter?.ready ?? false);
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [tab, setTab] = useState<"bridge" | "swaps">("bridge");

  // Keep in sync if the parent hands us a new corridor (e.g. "Review" click).
  useEffect(() => {
    setFrom(initialFilter?.chainIdFrom != null ? String(initialFilter.chainIdFrom) : ANY);
    setTo(initialFilter?.chainIdTo != null ? String(initialFilter.chainIdTo) : ANY);
    setReadyOnly(initialFilter?.ready ?? false);
  }, [initialFilter]);

  const filter: SubmissionFilter = useMemo(
    () => ({
      chainIdFrom: from === ANY ? undefined : Number(from),
      chainIdTo: to === ANY ? undefined : Number(to),
      ready: readyOnly ? true : undefined,
    }),
    [from, to, readyOnly]
  );

  const stats = usePoll<Stats>(() => fetchStats(), [], 5000);
  const subs = usePoll<Submission[]>(() => fetchSubmissions(filter), [from, to, readyOnly], 5000);

  // Best-effort: the DB-backed history/swap views only exist when graphql-api
  // was started with --store-url. Swallow failures into an empty list instead of
  // surfacing an error, so an unconfigured deployment looks exactly as it did
  // before this feature existed — the Stuck badge and Swaps tab just stay empty.
  const history = usePoll<HistoryEntry[]>(
    () => fetchHistory(filter).catch(() => []),
    [from, to, readyOnly],
    5000
  );
  const stuckBySubmission = useMemo(() => {
    const m = new Map<string, HistoryEntry>();
    for (const h of history.data ?? []) if (h.refundStatus !== "none") m.set(h.submissionId, h);
    return m;
  }, [history.data]);

  const swapChainId = from === ANY ? undefined : Number(from);
  const swaps = usePoll<SwapHistoryEntry[]>(
    // No `.catch(() => [])` here: a failing query used to render as "no swaps
    // recorded yet", which is what an API too old to serve the per-token scale
    // fields looks like. An error must say so — an empty tab is a claim about
    // the chain, not about the backend.
    () => (tab === "swaps" ? fetchSwapHistory(swapChainId, 100) : Promise.resolve([])),
    [tab, swapChainId],
    5000
  );

  const chainOptions: DropdownOption[] = [
    { value: ANY, label: "Any chain", glyph: <span className="dot-any" /> },
    ...chains.map((c) => {
      const v = chainViz(c.chainId, c.name);
      return { value: String(c.chainId), label: c.name, glyph: <Glyph gradient={v.gradient} size={20} /> };
    }),
  ];

  const rows = useMemo(() => {
    const list = subs.data ?? [];
    const q = search.trim().toLowerCase();
    if (!q) return list;
    return list.filter(
      (s) => s.submissionId.toLowerCase().includes(q) || s.receiver.toLowerCase().includes(q)
    );
  }, [subs.data, search]);

  const s = stats.data;

  return (
    <section className="explorer">
      <div className="explorer__head">
        <div>
          <h1 className="explorer__title">Explorer</h1>
          <p className="explorer__sub">
            Live view of the signature store — what validators have signed, straight from the backend.
          </p>
        </div>
        <button
          type="button"
          className="ghost-btn"
          onClick={() => (stats.refetch(), subs.refetch(), history.refetch(), swaps.refetch())}
        >
          <Refresh size={16} /> Refresh
        </button>
      </div>

      <div className="stat-grid">
        <Stat label="Total transfers" value={s ? s.total : "—"} />
        <Stat label="With signatures" value={s ? s.signed : "—"} />
        <Stat label="Ready to claim" value={s ? s.ready : "—"} accent="ready" />
        <Stat label="Threshold" value={s?.threshold != null ? `${s.threshold}-of-N` : "—"} />
      </div>

      <div className="tabs">
        <button
          type="button"
          className={`tab${tab === "bridge" ? " tab--active" : ""}`}
          onClick={() => setTab("bridge")}
        >
          Bridge transfers
        </button>
        <button
          type="button"
          className={`tab${tab === "swaps" ? " tab--active" : ""}`}
          onClick={() => setTab("swaps")}
        >
          Same-chain swaps
        </button>
      </div>

      {tab === "bridge" && (
        <>
          <div className="filters">
            <label className="filters__field">
              <span>From</span>
              <Dropdown variant="chain" value={from} options={chainOptions} onChange={setFrom} />
            </label>
            <ArrowRight size={16} className="filters__arrow" />
            <label className="filters__field">
              <span>To</span>
              <Dropdown variant="chain" value={to} options={chainOptions} onChange={setTo} />
            </label>
            <button
              type="button"
              className={`chip-toggle${readyOnly ? " chip-toggle--on" : ""}`}
              onClick={() => setReadyOnly((v) => !v)}
            >
              Ready only
            </button>
            <div className="search">
              <Search size={16} />
              <input
                value={search}
                placeholder="Search id or receiver…"
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
          </div>

          {subs.error && (
            <div className="notice notice--error">
              Couldn’t reach the backend: {subs.error}. Is <code>graphql-api</code> running on :8088?
            </div>
          )}

          <div className="table-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>Route</th>
                  <th>Amount</th>
                  <th className="tbl__num">Nonce</th>
                  <th className="tbl__num">Signatures</th>
                  <th>Status</th>
                  <th>Submission ID</th>
                  <th aria-label="open" />
                </tr>
              </thead>
              <tbody>
                {rows.map((sub) => (
                  <tr key={sub.submissionId} className="tbl__row" onClick={() => setSelected(sub.submissionId)}>
                    <td>
                      <span className="route-cell">
                        <ChainCell chains={chains} id={sub.chainIdFrom} />
                        <ArrowRight size={13} className="route-cell__arrow" />
                        <ChainCell chains={chains} id={sub.chainIdTo} />
                      </span>
                    </td>
                    <td
                      className={"tbl__amount" + (sub.bridgeDecimals == null ? " tbl__amount--raw" : "")}
                      title={wireAmountTitle(sub.amount, sub.bridgeDecimals)}
                      data-testid="submission-amount"
                    >
                      {formatWireAmount(sub.amount, sub.bridgeDecimals)}
                    </td>
                    <td className="tbl__num">{sub.nonce}</td>
                    <td className="tbl__num">
                      <span className="sig-count">
                        {sub.signatureCount}
                        {s?.threshold != null && <span className="sig-count__of"> / {s.threshold}</span>}
                      </span>
                    </td>
                    <td>
                      <StatusBadge status={sub.status} />
                      {stuckBySubmission.has(sub.submissionId) && (
                        <RefundBadge refundStatus={stuckBySubmission.get(sub.submissionId)!.refundStatus} />
                      )}
                    </td>
                    <td className="tbl__mono">{shortHex(sub.submissionId, 10, 6)}</td>
                    <td className="tbl__open">
                      <ArrowRight size={15} />
                    </td>
                  </tr>
                ))}
                {rows.length === 0 && !subs.loading && (
                  <tr>
                    <td colSpan={7} className="tbl__empty">
                      {subs.error ? "No data (backend unreachable)." : "No transfers match these filters."}
                    </td>
                  </tr>
                )}
                {rows.length === 0 && subs.loading && (
                  <tr>
                    <td colSpan={7} className="tbl__empty">
                      Loading…
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </>
      )}

      {tab === "swaps" && (
        <div className="table-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>Chain</th>
                <th>Sender</th>
                <th>Swap</th>
                <th>Amount in</th>
                <th>Amount out</th>
                <th>Tx</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {(swaps.data ?? []).map((sw, i) => (
                <tr key={`${sw.txHash}-${i}`}>
                  <td><ChainCell chains={chains} id={sw.chainId} /></td>
                  <td className="tbl__mono">{shortHex(sw.sender, 8, 6)}</td>
                  <td className="tbl__mono">
                    {shortHex(sw.tokenIn, 6, 4)} <ArrowRight size={11} className="route-cell__arrow" />{" "}
                    {shortHex(sw.tokenOut, 6, 4)}
                  </td>
                  {/* A swap crosses two tokens, so each amount is scaled by its
                      OWN token. The chain's default-token decimals used to
                      scale both, which is right only when the pool happens to
                      trade that token against another of equal width. */}
                  <td
                    className={"tbl__amount" + (sw.amountInDecimals == null ? " tbl__amount--raw" : "")}
                    title={wireAmountTitle(sw.amountIn, sw.amountInDecimals, "this token's decimals")}
                    data-testid="swap-amount-in"
                  >
                    {formatWireAmount(sw.amountIn, sw.amountInDecimals)}
                  </td>
                  <td
                    className={"tbl__amount" + (sw.amountOutDecimals == null ? " tbl__amount--raw" : "")}
                    title={wireAmountTitle(sw.amountOut, sw.amountOutDecimals, "this token's decimals")}
                    data-testid="swap-amount-out"
                  >
                    {formatWireAmount(sw.amountOut, sw.amountOutDecimals)}
                  </td>
                  <td className="tbl__mono">{shortHex(sw.txHash, 8, 6)}</td>
                  <td>{new Date(sw.createdAt).toLocaleString()}</td>
                </tr>
              ))}
              {(swaps.data ?? []).length === 0 && (
                <tr>
                  <td colSpan={7} className="tbl__empty">
                    {swaps.loading
                      ? "Loading…"
                      : swaps.error
                        ? `Couldn’t load swaps: ${swaps.error}`
                        : "No same-chain swaps recorded yet."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {selected && (
        <SubmissionDetail submissionId={selected} chains={chains} onClose={() => setSelected(null)} />
      )}
    </section>
  );
}

function Stat({ label, value, accent }: { label: string; value: string | number; accent?: "ready" }) {
  return (
    <div className={`stat${accent ? ` stat--${accent}` : ""}`}>
      <div className="stat__value">{value}</div>
      <div className="stat__label">{label}</div>
    </div>
  );
}
