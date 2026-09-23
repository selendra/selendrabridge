import { useCallback, useEffect, useMemo, useState } from "react";
import { Dropdown, type DropdownOption } from "./Dropdown";
import { TxBanner, type TxState } from "./TxBanner";
import { Glyph } from "./icons";
import { chainViz, formatUnits, parseUnits, shortHex, tokenGradient } from "../data/format";
import {
  fetchSolanaBlockhash,
  fetchSolanaGateContext,
  fetchSolanaSignatureStatus,
  fetchSolanaTokenBalance,
} from "../api/client";
import { hexToBytes } from "../wallet/keccak";
import { associatedTokenAddress, buildGateSendInstruction, serializeMessage } from "../wallet/solana";
import { errMsg, readBridgeDecimalsFor, rpcRequest } from "../wallet/eth";
import type { Chain } from "../api/types";
import type { SolanaWalletState } from "../wallet/useSolanaWallet";

/**
 * Bridging OUT of Solana.
 *
 * A sibling of the EVM form rather than a branch inside it: that form's source
 * chain IS the connected EVM wallet's chain, an assumption threaded through its
 * balance reads, approvals and chain-switch prompts. Bending it around a source
 * with no EVM wallet at all would put the tested EVM path at risk to serve a
 * flow that shares almost none of it.
 *
 * What the two DO share is the rule that matters: the instruction is built here,
 * in the browser. The receiver, amount and destination go into the bytes this
 * component hashes into the submissionId — the API supplies only the corridor's
 * nonce, the deployment domain and the registered vault, none of which can send
 * the funds anywhere else (a wrong one just fails on-chain).
 */

interface Props {
  /** The Solana chain's registry entry (its mints live in `tokens`). */
  solanaChain: Chain;
  /** Every chain, for the destination picker. */
  chains: Chain[];
  wallet: SolanaWalletState;
}

export function SolanaBridgePanel({ solanaChain, chains, wallet }: Props) {
  const destinations = useMemo(
    () => chains.filter((c) => c.chainId !== solanaChain.chainId),
    [chains, solanaChain.chainId]
  );
  const [toChainId, setToChainId] = useState<number | null>(null);
  useEffect(() => {
    if (toChainId == null && destinations.length) setToChainId(destinations[0].chainId);
  }, [destinations, toChainId]);

  const tokens = solanaChain.tokens ?? [];
  const [symbol, setSymbol] = useState<string>("");
  useEffect(() => {
    if (!symbol && tokens.length) setSymbol(tokens[0].symbol);
  }, [tokens, symbol]);
  const mint = tokens.find((t) => t.symbol === symbol)?.address ?? "";

  const [amount, setAmount] = useState("");
  const [receiver, setReceiver] = useState("");
  const [tx, setTx] = useState<TxState>({ kind: "idle" });

  // The corridor's live parameters. Fetched per (asset, destination) because the
  // nonce advances with every send — a stale one produces a submissionId the
  // program will not derive.
  const [ctx, setCtx] = useState<Awaited<ReturnType<typeof fetchSolanaGateContext>>>(null);
  useEffect(() => {
    let alive = true;
    if (!symbol || toChainId == null) {
      setCtx(null);
      return;
    }
    fetchSolanaGateContext(solanaChain.chainId, symbol, toChainId)
      .then((c) => alive && setCtx(c))
      .catch(() => alive && setCtx(null));
    return () => {
      alive = false;
    };
  }, [solanaChain.chainId, symbol, toChainId, tx.kind]);

  const decimals = ctx?.decimals ?? 0;
  const amountBase = ctx ? parseUnits(amount, decimals) : 0n;
  // Amounts cross the bridge in the asset's bridge decimals; the program refuses
  // a mint amount that isn't a whole multiple of the unit between the two.
  const bridgeUnit = ctx && ctx.decimals >= ctx.bridgeDecimals ? 10n ** BigInt(ctx.decimals - ctx.bridgeDecimals) : null;
  const inexact = bridgeUnit != null && amountBase > 0n && amountBase % bridgeUnit !== 0n;

  // H-2 (audit T-7): the destination EVM gate must agree on the asset's scale.
  // The Solana program divides the locked amount by ITS registered bridge
  // decimals; the EVM gate multiplies the wire amount by ITS OWN. The
  // submissionId commits to neither, so two ends one digit apart pay out a power
  // of ten wrong — and both registrations are write-once. The relayer refuses to
  // sign such a transfer, but a user should not be able to lock funds into one in
  // the first place, exactly as the EVM form already refuses.
  //
  // Keyed on PRIMITIVES only: `ctx` is refetched after every send (the nonce
  // moves), and depending on the object would re-run and flash "Checking…".
  const toReg = destinations.find((c) => c.chainId === toChainId);
  const destGate = toReg?.gate ?? "";
  const destRpcUrl = toReg?.rpcUrl ?? "";
  const destIsEvm = destGate.startsWith("0x");
  const corridorId = ctx?.debridgeId ?? "";
  const destScaleKey = `${toChainId ?? "?"}:${destGate.toLowerCase()}:${corridorId.toLowerCase()}`;
  const [destBridgeDecimals, setDestBridgeDecimals] = useState<number | null>(null);
  const [destReadFor, setDestReadFor] = useState<string | null>(null);
  const destScaleStale = destReadFor !== destScaleKey;
  useEffect(() => {
    let alive = true;
    // Invalidate first: until the read lands, "unknown" must not look like agreement.
    setDestReadFor(null);
    setDestBridgeDecimals(null);
    if (!corridorId || toChainId == null) return;
    // The id the Solana send hashes (`ctx.debridgeId`) is the peer-derived one the
    // destination gate maps, so it is exactly the corridor to ask about.
    const read: Promise<number | null> =
      destIsEvm && destRpcUrl
        ? readBridgeDecimalsFor(rpcRequest(destRpcUrl), destGate, corridorId)
        : Promise.resolve(null); // not an EVM gate we can read: unknown, fails closed
    read
      .catch(() => null)
      .then((d) => {
        if (!alive) return;
        setDestBridgeDecimals(d);
        setDestReadFor(destScaleKey);
      });
    return () => {
      alive = false;
    };
  }, [destScaleKey, corridorId, toChainId, destIsEvm, destGate, destRpcUrl]);
  const srcBridgeDecimals = ctx?.bridgeDecimals ?? null;
  const scaleMismatch =
    !destScaleStale && destBridgeDecimals != null && srcBridgeDecimals != null && destBridgeDecimals !== srcBridgeDecimals;
  // A destination registered one digit SHORT of the source pays ten times too much.
  const scaleSkew = scaleMismatch ? (srcBridgeDecimals as number) - (destBridgeDecimals as number) : 0;
  const toName = toReg?.name ?? "the destination";

  const [balance, setBalance] = useState<bigint | null>(null);
  const refreshBalance = useCallback(async () => {
    if (!wallet.address || !mint) {
      setBalance(null);
      return;
    }
    try {
      const ata = await associatedTokenAddress(wallet.address, mint);
      const raw = await fetchSolanaTokenBalance(solanaChain.chainId, ata);
      setBalance(raw != null ? BigInt(raw) : null);
    } catch {
      setBalance(null);
    }
  }, [wallet.address, mint, solanaChain.chainId]);
  useEffect(() => {
    refreshBalance();
  }, [refreshBalance, tx.kind]);

  // The destination is an EVM chain, so the receiver is a 20-byte address.
  const receiverOk = /^0x[0-9a-fA-F]{40}$/.test(receiver.trim());
  const insufficient = balance != null && amountBase > balance;
  const busy = tx.kind === "pending";

  const doSend = async () => {
    if (!ctx || !mint || toChainId == null || !wallet.address) return;
    setTx({ kind: "pending", label: "Building transaction…" });
    try {
      const [userToken, blockhash] = await Promise.all([
        associatedTokenAddress(wallet.address, mint),
        fetchSolanaBlockhash(solanaChain.chainId),
      ]);
      if (!blockhash) throw new Error("No recent blockhash from the API");

      const { instruction, submissionId } = await buildGateSendInstruction({
        programId: ctx.programId,
        user: wallet.address,
        userTokenAccount: userToken,
        vault: ctx.vault,
        debridgeId: ctx.debridgeId,
        bridgeDomain: ctx.bridgeDomain,
        solanaChainId: BigInt(ctx.chainId),
        chainIdTo: BigInt(toChainId),
        nonce: BigInt(ctx.nonce),
        amount: amountBase,
        bridgeUnit: bridgeUnit ?? 1n,
        // The gate's own registered scale, from the same `gateContext` the unit
        // above came from — it is inside the submissionId (H-2).
        bridgeDecimals: ctx.bridgeDecimals,
        receiver: hexToBytes(receiver.trim()),
      });

      setTx({ kind: "pending", label: "Confirm in your wallet…" });
      const signature = await wallet.signAndSend(
        serializeMessage(wallet.address, blockhash, [instruction])
      );
      setTx({ kind: "pending", label: "Confirming on Solana…", hash: signature });

      let status = "pending";
      for (let i = 0; i < 40 && status !== "confirmed" && status !== "finalized"; i++) {
        await new Promise((r) => setTimeout(r, 1500));
        status = (await fetchSolanaSignatureStatus(solanaChain.chainId, signature)) ?? "pending";
        if (status === "failed") throw new Error("Send failed on-chain");
      }
      // Running out of polls is NOT confirmation: a transaction that dropped
      // (expired blockhash, never landed) looks exactly like this.
      if (status !== "confirmed" && status !== "finalized") {
        throw new Error(
          `Not confirmed yet (status: ${status}) — check ${shortHex(signature, 8, 8)} in an explorer before retrying`
        );
      }
      // Locked, not delivered: the validators still have to sign and a keeper
      // still has to claim on the destination. Say so rather than imply arrival.
      setTx({
        kind: "done",
        label: `Locked ${amount} ${symbol} — ${shortHex(submissionId, 10, 6)} is now awaiting validators`,
        hash: signature,
      });
      setAmount("");
    } catch (e) {
      setTx({ kind: "error", message: errMsg(e) });
    }
  };

  const destOptions: DropdownOption[] = destinations.map((c) => {
    const viz = chainViz(c.chainId, c.name);
    return {
      value: String(c.chainId),
      label: c.name,
      sub: `chain ${c.chainId}`,
      glyph: <Glyph gradient={viz.gradient} size={22} />,
    };
  });
  const tokenOptions: DropdownOption[] = tokens.map((t) => ({
    value: t.symbol,
    label: t.symbol,
    sub: shortHex(t.address, 6, 4),
    glyph: <Glyph gradient={tokenGradient(t.address)} size={22} />,
  }));

  let button: { label: string; onClick?: () => void; disabled?: boolean };
  if (!wallet.available) button = { label: "Install Phantom", disabled: true };
  else if (!wallet.address) button = { label: "Connect Phantom", onClick: () => wallet.connect() };
  else if (!tokens.length) button = { label: "No bridgeable mint configured", disabled: true };
  else if (toChainId == null) button = { label: "Pick a destination", disabled: true };
  else if (!ctx) button = { label: "Corridor unavailable", disabled: true };
  else if (ctx.paused) button = { label: "Gate is paused", disabled: true };
  else if (!receiverOk) button = { label: "Enter the destination address", disabled: true };
  else if (amountBase <= 0n) button = { label: "Enter an amount", disabled: true };
  else if (bridgeUnit == null) button = { label: "Corridor misconfigured (bridge decimals)", disabled: true };
  // H-2 fails closed: an unread or unreadable destination scale blocks the send
  // just as a mismatch does.
  else if (destScaleStale) button = { label: "Checking destination decimals…", disabled: true };
  else if (destBridgeDecimals == null)
    button = { label: `Can't confirm how ${toName} scales this asset`, disabled: true };
  else if (scaleMismatch) button = { label: "Bridge decimals mismatch — refusing to send", disabled: true };
  else if (inexact)
    button = { label: `Too precise — this asset bridges at most ${ctx.bridgeDecimals} decimals`, disabled: true };
  else if (insufficient) button = { label: `Insufficient ${symbol}`, disabled: true };
  else button = { label: "Bridge from Solana", onClick: doSend };
  if (busy) button = { label: tx.label, disabled: true };

  return (
    <div className="solana-bridge">
      <div className="amount-row">
        <div className="amount-row__side">
          <span className="amount-row__label">You send</span>
          <Dropdown options={tokenOptions} value={symbol} onChange={setSymbol} variant="token" />
        </div>
        <div className="amount-row__side">
          <input
            className="amount-row__field"
            inputMode="decimal"
            placeholder="0.0"
            value={amount}
            onChange={(e) => setAmount(e.target.value)}
            aria-label="Amount"
          />
          {balance != null && (
            <span className="amount-row__bal">Bal: {formatUnits(balance, decimals)}</span>
          )}
        </div>
      </div>

      <div className="amount-row">
        <div className="amount-row__side">
          <span className="amount-row__label">To chain</span>
          <Dropdown
            options={destOptions}
            value={toChainId == null ? "" : String(toChainId)}
            onChange={(v) => setToChainId(Number(v))}
          />
        </div>
        <div className="amount-row__side">
          <input
            className="amount-row__field"
            placeholder="0x… destination address"
            value={receiver}
            onChange={(e) => setReceiver(e.target.value)}
            aria-label="Receiver"
          />
        </div>
      </div>

      <div className="summary">
        <div className="summary__row">
          <span>Gate</span>
          <span>{ctx ? shortHex(ctx.programId, 6, 4) : "—"}</span>
        </div>
        <div className="summary__row">
          <span>Corridor nonce</span>
          <span>{ctx ? ctx.nonce : "—"}</span>
        </div>
      </div>

      {/* H-2: say what disagrees and that it cannot be fixed after the fact. */}
      {scaleMismatch && (
        <div className="notice notice--warn" data-testid="bridge-decimals-mismatch">
          {solanaChain.name} bridges this asset at {srcBridgeDecimals} decimals, but {toName}'s Gate is registered at{" "}
          {destBridgeDecimals}. The transfer id does not commit to that scale, so a claim on {toName} would pay out{" "}
          10<sup>{Math.abs(scaleSkew)}</sup> times too {scaleSkew > 0 ? "much" : "little"} and nothing on-chain would
          catch it. Both registrations are write-once — report this to the operator instead of sending.
        </div>
      )}
      {ctx && !destScaleStale && destBridgeDecimals == null && (
        <div className="notice notice--warn" data-testid="bridge-decimals-unknown">
          Couldn't read the bridge decimals {toName}'s Gate has registered for this asset, so there is no way to tell
          whether it would pay out the right amount. Refusing to send is deliberate.
        </div>
      )}

      <TxBanner tx={tx} />
      <button className="review-btn" onClick={button.onClick} disabled={button.disabled || !button.onClick}>
        {button.label}
      </button>
    </div>
  );
}
