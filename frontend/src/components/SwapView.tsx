import { useCallback, useEffect, useMemo, useState } from "react";
import { Dropdown, type DropdownOption } from "./Dropdown";
import { TxBanner, type TxState } from "./TxBanner";
import { ArrowDown, Glyph, Help, Refresh } from "./icons";
import { chainViz, formatUnits, formatUnitsRaw, parseUnits, shortHex, tokenGradient } from "../data/format";
import {
  fetchSolanaBlockhash,
  fetchSolanaSignatureStatus,
  fetchSolanaTokenBalance,
  fetchSwapPool,
  fetchSwapQuote,
} from "../api/client";
import { usePoll, useDebounced } from "../api/hooks";
import { errMsg, readAllowance, readBalance, sendApprove, sendSwap, waitReceipt } from "../wallet/eth";
import type { Chain, PoolToken, SwapPoolInfo } from "../api/types";
import type { WalletState } from "../wallet/useWallet";
import type { SolanaWalletState } from "../wallet/useSolanaWallet";
import {
  associatedTokenAddress,
  buildSwapInstruction,
  createAtaInstruction,
  serializeMessage,
} from "../wallet/solana";

const eq = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();

const SLIPPAGE_OPTS = [10, 50, 100]; // bps: 0.1%, 0.5%, 1%

interface Props {
  chains: Chain[];
  wallet: WalletState;
  /** The Solana wallet, used when the selected pool lives on Solana. */
  solana: SolanaWalletState;
}

/** A pool address that is not `0x…` is a Solana program id — the same rule the
 *  API uses to tell the two VMs apart, so the UI needs no extra flag. */
const isSolanaPool = (address: string | undefined) => !!address && !address.startsWith("0x");

export function SwapView({ chains, wallet, solana }: Props) {
  // Which chain's pool we're swapping on. Prefer the connected wallet chain.
  const [chainId, setChainId] = useState<number | null>(null);
  useEffect(() => {
    if (chainId != null) return;
    if (wallet.chainId && chains.some((c) => c.chainId === wallet.chainId)) setChainId(wallet.chainId);
    else if (chains.length) setChainId(chains[0].chainId);
  }, [chains, wallet.chainId, chainId]);

  const poolQ = usePoll<SwapPoolInfo | null>(
    () => (chainId != null ? fetchSwapPool(chainId) : Promise.resolve(null)),
    [chainId],
    10000
  );
  const pool = poolQ.data;
  const tokens = useMemo(() => pool?.tokens ?? [], [pool]);

  const [tokenIn, setTokenIn] = useState("");
  const [tokenOut, setTokenOut] = useState("");
  const [amount, setAmount] = useState("");
  const [slippageBps, setSlippageBps] = useState(50);
  const [tx, setTx] = useState<TxState>({ kind: "idle" });

  // (Re)initialise the token pair whenever the pool identity changes.
  useEffect(() => {
    if (!tokens.length) return;
    const has = (a: string) => tokens.some((t) => eq(t.token, a));
    const first = tokens[0].token;
    if (!has(tokenIn)) setTokenIn(first);
    const inAddr = has(tokenIn) ? tokenIn : first;
    if (!has(tokenOut) || eq(tokenOut, inAddr)) {
      setTokenOut((tokens.find((t) => !eq(t.token, inAddr)) ?? tokens[0]).token);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pool?.address, tokens.length]);

  const tin = tokens.find((t) => eq(t.token, tokenIn));
  const tout = tokens.find((t) => eq(t.token, tokenOut));
  const amountBase = tin ? parseUnits(amount, tin.decimals) : 0n;

  // --- live quote (debounced) -------------------------------------------
  const debouncedAmt = useDebounced(amountBase.toString(), 300);
  const [quote, setQuote] = useState<string | null>(null);
  const [quoting, setQuoting] = useState(false);
  useEffect(() => {
    if (chainId == null || !tin || !tout || eq(tokenIn, tokenOut) || BigInt(debouncedAmt) <= 0n) {
      setQuote(null);
      setQuoting(false);
      return;
    }
    let alive = true;
    setQuoting(true);
    fetchSwapQuote(chainId, tokenIn, tokenOut, debouncedAmt)
      .then((q) => alive && setQuote(q))
      .catch(() => alive && setQuote(null))
      .finally(() => alive && setQuoting(false));
    return () => {
      alive = false;
    };
  }, [chainId, tokenIn, tokenOut, debouncedAmt, tin, tout]);

  const quoteBase = quote ? BigInt(quote) : 0n;
  const minOut = (quoteBase * BigInt(10000 - slippageBps)) / 10000n;
  const reserveOut = tout ? BigInt(tout.reserve) : 0n;
  const exceedsLock = quoteBase > reserveOut;

  const solanaMode = isSolanaPool(pool?.address);
  const account = solanaMode ? solana.address : wallet.address;

  // --- on-chain balance + allowance (only when on the pool's chain) ------
  // A Solana pool has no chain to switch to: the wallet is bound to its cluster,
  // so "right chain" is simply "connected".
  const onRightChain = solanaMode ? solana.address != null : wallet.chainId === chainId;
  const [balance, setBalance] = useState<bigint | null>(null);
  const [allowance, setAllowance] = useState<bigint | null>(null);

  const refreshOnchain = useCallback(async () => {
    if (solanaMode) {
      // SPL: the balance lives in the owner's associated token account, which
      // the browser derives; there is no allowance — the signer authorises the
      // transfer directly.
      setAllowance(null);
      if (!solana.address || !tin || chainId == null) {
        setBalance(null);
        return;
      }
      try {
        const ata = await associatedTokenAddress(solana.address, tin.token);
        const raw = await fetchSolanaTokenBalance(chainId, ata);
        setBalance(raw != null ? BigInt(raw) : null);
      } catch {
        setBalance(null);
      }
      return;
    }
    if (!wallet.address || !onRightChain || !tin || !pool) {
      setBalance(null);
      setAllowance(null);
      return;
    }
    try {
      const [b, a] = await Promise.all([
        readBalance(wallet.request, tin.token, wallet.address),
        readAllowance(wallet.request, tin.token, wallet.address, pool.address),
      ]);
      setBalance(b);
      setAllowance(a);
    } catch {
      setBalance(null);
      setAllowance(null);
    }
  }, [wallet.address, wallet.request, onRightChain, tin, pool]);

  useEffect(() => {
    refreshOnchain();
  }, [refreshOnchain]);

  // No approve step on Solana: an SPL transfer is authorised by the signer.
  const needsApprove = !solanaMode && allowance != null && amountBase > 0n && allowance < amountBase;
  const insufficient = balance != null && amountBase > balance;
  const busy = tx.kind === "pending";

  // --- actions -----------------------------------------------------------
  const doApprove = async () => {
    if (!pool || !tin || !wallet.address || chainId == null) return;
    setTx({ kind: "pending", label: `Approving ${tin.symbol || "token"}…` });
    try {
      const hash = await sendApprove(wallet.request, wallet.address, tin.token, pool.address, amountBase, chainId);
      setTx({ kind: "pending", label: "Confirming approval…", hash });
      await waitReceipt(wallet.request, hash);
      // Same lagging-node hazard as BridgeView.doApprove: wait, bounded, until a
      // read actually shows the new allowance before the refresh.
      for (let i = 0; i < 15; i++) {
        const a = await readAllowance(wallet.request, tin.token, wallet.address, pool.address).catch(() => 0n);
        if (a >= amountBase) break;
        await new Promise((r) => setTimeout(r, 1000));
      }
      await refreshOnchain();
      setTx({ kind: "idle" });
    } catch (e) {
      setTx({ kind: "error", message: errMsg(e) });
    }
  };

  const doSwap = async () => {
    if (!pool || !tin || !tout || !wallet.address || chainId == null) return;
    setTx({ kind: "pending", label: "Swapping…" });
    try {
      const hash = await sendSwap(
        wallet.request,
        wallet.address,
        pool.address,
        tin.token,
        tout.token,
        amountBase,
        minOut,
        wallet.address,
        chainId
      );
      setTx({ kind: "pending", label: "Confirming swap…", hash });
      const r = await waitReceipt(wallet.request, hash);
      if (!r.success) throw new Error("Swap reverted on-chain");
      setTx({ kind: "done", label: `Swapped for ${formatUnits(quoteBase, tout.decimals)} ${tout.symbol}`, hash });
      setAmount("");
      setQuote(null);
      await Promise.all([refreshOnchain(), poolQ.refetch()]);
    } catch (e) {
      setTx({ kind: "error", message: errMsg(e) });
    }
  };

  /**
   * The Solana swap. Every account that decides where the output lands — the
   * user's associated token accounts and the pool's PDAs — is derived HERE, in
   * the browser (`wallet/solana.ts`). The API contributes only a blockhash and
   * the pool's vaults, neither of which can misdirect funds: a wrong vault is
   * refused by the program, which pins it in its own token record.
   */
  const doSwapSolana = async () => {
    if (!pool || !tin || !tout || !solana.address || chainId == null) return;
    if (!tin.vault || !tout.vault) {
      setTx({ kind: "error", message: "Pool vaults unavailable — try again in a moment" });
      return;
    }
    setTx({ kind: "pending", label: "Building transaction…" });
    try {
      const [userIn, userOut, blockhash] = await Promise.all([
        associatedTokenAddress(solana.address, tin.token),
        associatedTokenAddress(solana.address, tout.token),
        fetchSolanaBlockhash(chainId),
      ]);
      if (!blockhash) throw new Error("No recent blockhash from the API");

      const swapIx = await buildSwapInstruction({
        programId: pool.address,
        user: solana.address,
        mintIn: tin.token,
        mintOut: tout.token,
        vaultIn: tin.vault,
        vaultOut: tout.vault,
        userIn,
        userOut,
        amountIn: amountBase,
        minAmountOut: minOut,
      });
      // Create the destination account first, idempotently: a user who has
      // never held the output mint has no account for it, and an SPL transfer
      // into a missing account fails rather than creating one.
      const message = serializeMessage(solana.address, blockhash, [
        createAtaInstruction(solana.address, userOut, solana.address, tout.token),
        swapIx,
      ]);

      setTx({ kind: "pending", label: "Confirm in your wallet…" });
      const signature = await solana.signAndSend(message);
      setTx({ kind: "pending", label: "Confirming swap…", hash: signature });

      // Poll the cluster through the API until it settles either way.
      let status = "pending";
      for (let i = 0; i < 40 && status !== "confirmed" && status !== "finalized"; i++) {
        await new Promise((r) => setTimeout(r, 1500));
        status = (await fetchSolanaSignatureStatus(chainId, signature)) ?? "pending";
        if (status === "failed") throw new Error("Swap failed on-chain");
      }
      setTx({
        kind: "done",
        label: `Swapped for ${formatUnits(quoteBase, tout.decimals)} ${tout.symbol}`,
        hash: signature,
      });
      setAmount("");
      setQuote(null);
      await Promise.all([refreshOnchain(), poolQ.refetch()]);
    } catch (e) {
      setTx({ kind: "error", message: errMsg(e) });
    }
  };

  const flip = () => {
    setTokenIn(tokenOut);
    setTokenOut(tokenIn);
    setAmount("");
    setQuote(null);
    setTx({ kind: "idle" });
  };

  // --- primary button state ---------------------------------------------
  const chainName = chains.find((c) => c.chainId === chainId)?.name ?? `chain ${chainId}`;
  let button: { label: string; onClick?: () => void; disabled?: boolean };
  if (solanaMode && !solana.available)
    button = { label: "Install Phantom", disabled: true };
  else if (!account)
    button = solanaMode
      ? { label: "Connect Phantom", onClick: () => solana.connect() }
      : { label: "Connect Wallet", onClick: () => wallet.connect() };
  else if (!solanaMode && chainId != null && !onRightChain)
    button = { label: `Switch to ${chainName}`, onClick: () => wallet.switchChain(chainId) };
  else if (!pool) button = { label: "No pool on this chain", disabled: true };
  else if (amountBase <= 0n) button = { label: "Enter an amount", disabled: true };
  else if (insufficient) button = { label: `Insufficient ${tin?.symbol ?? "balance"}`, disabled: true };
  else if (quoting) button = { label: "Fetching quote…", disabled: true };
  else if (!quote || quoteBase <= 0n) button = { label: "No quote available", disabled: true };
  else if (exceedsLock) button = { label: "Exceeds pool lock", disabled: true };
  else if (needsApprove) button = { label: `Approve ${tin?.symbol ?? "token"}`, onClick: doApprove };
  else button = { label: "Swap", onClick: solanaMode ? doSwapSolana : doSwap };
  if (busy) button = { label: tx.label, disabled: true };

  const outStr = tout && quoteBase > 0n ? formatUnits(quoteBase, tout.decimals) : "0";
  const rate =
    tin && tout && amountBase > 0n && quoteBase > 0n
      ? (Number(formatUnitsRaw(quoteBase, tout.decimals)) / Number(formatUnitsRaw(amountBase, tin.decimals))).toLocaleString(
          undefined,
          { maximumSignificantDigits: 6 }
        )
      : null;

  return (
    <section className="card">
      <div className="card__head">
        <div>
          <h2 className="card__title">Swap</h2>
          <p className="card__subtitle">Same-chain, pegged-price pool · {chainName}</p>
        </div>
        <div className="card__tools">
          <Dropdown
            variant="chain"
            value={String(chainId ?? "")}
            options={chains.map((c) => {
              const v = chainViz(c.chainId, c.name);
              return { value: String(c.chainId), label: c.name, glyph: <Glyph gradient={v.gradient} size={20} /> };
            })}
            onChange={(v) => {
              setChainId(Number(v));
              setAmount("");
              setQuote(null);
              setTx({ kind: "idle" });
            }}
          />
          <button
            type="button"
            className="icon-btn"
            aria-label="Refresh pool"
            onClick={() => {
              poolQ.refetch();
              refreshOnchain();
            }}
          >
            <Refresh size={18} />
          </button>
        </div>
      </div>

      <div className="swap-box">
        <TokenRow
          label="You pay"
          tokens={tokens}
          selected={tokenIn}
          onSelect={setTokenIn}
          amount={amount}
          editable
          onAmount={setAmount}
          balance={balance != null && tin ? formatUnitsRaw(balance, tin.decimals) : null}
          onMax={balance != null && tin ? () => setAmount(formatUnitsRaw(balance, tin.decimals)) : undefined}
        />

        <button type="button" className="swap-arrow" aria-label="Flip tokens" onClick={flip}>
          <ArrowDown size={18} />
        </button>

        <TokenRow
          label="You receive"
          tokens={tokens}
          selected={tokenOut}
          onSelect={setTokenOut}
          amount={quoting ? "…" : outStr}
          editable={false}
          note={
            tout
              ? `Pool lock: ${formatUnits(tout.reserve, tout.decimals)} ${tout.symbol}`
              : undefined
          }
        />
      </div>

      <dl className="summary">
        <div className="summary__row">
          <dt>
            Rate <Help size={14} />
          </dt>
          <dd>
            {rate && tin && tout ? `1 ${tin.symbol} ≈ ${rate} ${tout.symbol}` : "—"}
          </dd>
        </div>
        <div className="summary__row">
          <dt>
            Min received ({(slippageBps / 100).toFixed(2)}% slippage) <Help size={14} />
          </dt>
          <dd>{tout && quoteBase > 0n ? `${formatUnits(minOut, tout.decimals)} ${tout.symbol}` : "—"}</dd>
        </div>
        <div className="summary__row">
          <dt>Max slippage</dt>
          <dd className="slippage">
            {SLIPPAGE_OPTS.map((bps) => (
              <button
                key={bps}
                type="button"
                className={`slippage__opt${slippageBps === bps ? " slippage__opt--on" : ""}`}
                onClick={() => setSlippageBps(bps)}
              >
                {bps / 100}%
              </button>
            ))}
          </dd>
        </div>
        {pool && (
          <div className="summary__row">
            <dt>Pool</dt>
            <dd className="mono-sm">{shortHex(pool.address, 8, 6)}</dd>
          </div>
        )}
      </dl>

      {exceedsLock && tout && (
        <div className="notice notice--warn">
          Output ({formatUnits(quoteBase, tout.decimals)} {tout.symbol}) exceeds the pool's locked reserve for{" "}
          {tout.symbol}. Reduce the amount.
        </div>
      )}

      <TxBanner tx={tx} />

      <button type="button" className="review-btn" disabled={button.disabled || !button.onClick} onClick={button.onClick}>
        {button.label}
      </button>
    </section>
  );
}

// --- one from/to row ------------------------------------------------------

interface TokenRowProps {
  label: string;
  tokens: PoolToken[];
  selected: string;
  onSelect: (addr: string) => void;
  amount: string;
  editable: boolean;
  onAmount?: (v: string) => void;
  onMax?: () => void;
  balance?: string | null;
  note?: string;
}

function TokenRow(props: TokenRowProps) {
  const { tokens, selected, editable } = props;
  const options: DropdownOption[] = tokens.map((t) => ({
    value: t.token,
    label: t.symbol || shortHex(t.token, 6, 4),
    sub: t.isStable ? "stablecoin" : shortHex(t.token, 6, 4),
    glyph: <Glyph gradient={tokenGradient(t.token)} size={22} />,
  }));

  return (
    <div className="amount-row">
      <div className="amount-row__top">
        <span className="amount-row__label">{props.label}</span>
        <Dropdown variant="token" value={selected} options={options} onChange={props.onSelect} />
      </div>
      <div className="amount-row__bottom">
        <div className="amount-row__value">
          {editable ? (
            <input
              className="amount-row__input"
              inputMode="decimal"
              value={props.amount}
              placeholder="0"
              style={{ width: `${Math.max(1, props.amount.length)}ch` }}
              onChange={(e) => {
                const v = e.target.value;
                if (v === "" || /^\d*\.?\d*$/.test(v)) props.onAmount?.(v);
              }}
            />
          ) : (
            <span className="amount-row__input amount-row__input--readonly">{props.amount || "0"}</span>
          )}
        </div>
        <div className="amount-row__meta">
          {props.onMax && (
            <button type="button" className="max-btn" onClick={props.onMax}>
              Max
            </button>
          )}
          {props.balance != null && <span className="amount-row__bal">Bal: {props.balance}</span>}
          {props.note && <span className="amount-row__bal">{props.note}</span>}
        </div>
      </div>
    </div>
  );
}
