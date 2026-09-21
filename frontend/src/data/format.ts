// Presentation helpers + unit math. The backend only knows chain id/name/rpc,
// so the gradient/short-code per chain are supplied here (curated palette, or
// derived deterministically for unknown ids). No fake token registry, no fake
// USD prices — token metadata now comes live from the swap pool.

import type { Chain } from "../api/types";

/** deBridge's chain id for Solana — the value the gates hash into a submissionId. */
export const SOLANA_CHAIN_ID = 7565164;

const CHAIN_PALETTE: Record<number, { gradient: [string, string]; short: string }> = {
  [SOLANA_CHAIN_ID]: { gradient: ["#9945FF", "#14F195"], short: "SOL" },
  1: { gradient: ["#8FA6F3", "#3C55DE"], short: "ETH" },
  8453: { gradient: ["#4C8CFB", "#0052FF"], short: "BASE" },
  42161: { gradient: ["#3AC6F2", "#2D77E8"], short: "ARB" },
  10: { gradient: ["#FF6E6E", "#FF0420"], short: "OP" },
  137: { gradient: ["#A879F7", "#7B3FE4"], short: "POLY" },
  1337: { gradient: ["#7C5CFF", "#3AA0FF"], short: "A" },
  1338: { gradient: ["#00C2A8", "#14C8E6"], short: "B" },
  1339: { gradient: ["#F7A34B", "#F25C05"], short: "C" },
};

export interface ChainViz {
  gradient: [string, string];
  short: string;
}

/** Deterministic pastel gradient for an id/string we have no palette entry for. */
function derivedGradient(seed: number): [string, string] {
  const h = (seed * 2654435761) % 360;
  return [`hsl(${h} 75% 62%)`, `hsl(${(h + 40) % 360} 75% 48%)`];
}

export function chainViz(chainId: number, name?: string): ChainViz {
  const hit = CHAIN_PALETTE[chainId];
  if (hit) return hit;
  const short =
    (name ?? String(chainId)).replace(/[^A-Za-z0-9]/g, "").slice(0, 4).toUpperCase() || String(chainId);
  return { gradient: derivedGradient(chainId), short };
}

/** Stable gradient for a token, derived from its address (no registry needed). */
export function tokenGradient(address: string): [string, string] {
  let acc = 0;
  const s = address.toLowerCase();
  for (let i = 2; i < s.length; i += 4) acc = (acc + parseInt(s.slice(i, i + 4) || "0", 16)) % 100000;
  return derivedGradient(acc + 7);
}

// --- unit math -----------------------------------------------------------

/** Parse a human decimal string into base units (bigint). Invalid => 0n. */
export function parseUnits(value: string, decimals: number): bigint {
  const s = value.trim();
  if (!s || !/^\d*\.?\d*$/.test(s)) return 0n;
  const [wholeRaw, fracRaw = ""] = s.split(".");
  const whole = wholeRaw || "0";
  const frac = (fracRaw + "0".repeat(decimals)).slice(0, decimals);
  try {
    return BigInt((whole + frac).replace(/^0+(?=\d)/, "") || "0");
  } catch {
    return 0n;
  }
}

/** Format base units as a grouped, trimmed decimal for DISPLAY (e.g. 1,234.56). */
export function formatUnits(raw: string | bigint, decimals = 18, maxFrac = 6): string {
  let s = typeof raw === "bigint" ? raw.toString() : raw.trim();
  let neg = false;
  if (s.startsWith("-")) {
    neg = true;
    s = s.slice(1);
  }
  if (!/^\d+$/.test(s)) return String(raw);
  s = s.padStart(decimals + 1, "0");
  const whole = s.slice(0, s.length - decimals).replace(/^0+(?=\d)/, "");
  let frac = decimals ? s.slice(s.length - decimals) : "";
  frac = frac.slice(0, maxFrac).replace(/0+$/, "");
  let grouped: string;
  try {
    grouped = BigInt(whole).toLocaleString("en-US");
  } catch {
    grouped = whole;
  }
  return (neg ? "-" : "") + (frac ? `${grouped}.${frac}` : grouped);
}

/** Format base units as a plain decimal for an INPUT field (no grouping, full). */
export function formatUnitsRaw(raw: bigint, decimals: number): string {
  const neg = raw < 0n;
  const s = (neg ? -raw : raw).toString().padStart(decimals + 1, "0");
  const whole = s.slice(0, s.length - decimals);
  const frac = decimals ? s.slice(s.length - decimals).replace(/0+$/, "") : "";
  return (neg ? "-" : "") + (frac ? `${whole}.${frac}` : whole);
}

/**
 * A transfer `amount` rendered at the scale it is actually in (M-11).
 *
 * `amount` is a WIRE amount: the asset's bridge decimals, which are mesh-wide
 * and usually NOT the source token's own. The explorer used to fall back to the
 * ERC-20's local decimals, then to 18, whenever the API served
 * `bridgeDecimals: null` — which `scripts/run.sh` guaranteed, because it never
 * emits `bridge_decimals` into the registry. At 6 bridge / 18 local decimals a
 * 1,000-token transfer rendered as `0`, and an operator diagnosing a stuck
 * transfer read a number that was a trillion times too small.
 *
 * With no scale from the API there is no honest way to place the point, so the
 * raw integer is shown and labelled — see [`wireAmountTitle`]. A wrong number
 * looks just as authoritative as a right one; an unformatted one does not.
 */
export function formatWireAmount(amount: string, bridgeDecimals: number | null | undefined): string {
  if (bridgeDecimals == null) return amount;
  return formatUnits(amount, bridgeDecimals);
}

/**
 * Tooltip for [`formatWireAmount`], explaining an unscaled figure.
 *
 * `scaleName` names WHICH decimals these are, because the explorer shows two
 * different kinds side by side: a transfer's `amount` is in the asset's
 * mesh-wide bridge decimals, while a pool swap's `amountIn`/`amountOut` are in
 * each token's own local decimals. Saying "bridge decimals" on a swap row would
 * be a different wrong answer to the same question.
 */
export function wireAmountTitle(
  amount: string,
  decimals: number | null | undefined,
  scaleName = "this asset's bridge decimals"
): string {
  return decimals == null
    ? `Raw amount — ${scaleName} are unknown to the API, so the decimal point cannot be placed. ${amount} base units.`
    : `${amount} base units at ${decimals} decimals (${scaleName})`;
}

/** Middle-truncate a hex string: 0x1234…abcd. */
export function shortHex(hex: string, lead = 6, tail = 4): string {
  if (!hex || hex.length <= lead + tail + 2) return hex;
  return `${hex.slice(0, lead)}…${hex.slice(-tail)}`;
}

/** True for a well-formed 0x-prefixed 20-byte EVM address. */
export function isAddress(v: string): boolean {
  return /^0x[0-9a-fA-F]{40}$/.test(v.trim());
}

/**
 * True for a well-formed base58 Solana account key (32 bytes).
 *
 * Base58 excludes 0, O, I and l precisely so visually similar characters cannot
 * be confused, and an encoded 32-byte key lands in 32–44 characters.
 */
export function isSolanaAccount(v: string): boolean {
  return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(v.trim());
}

/**
 * Whether a registry entry is a non-EVM chain — today, Solana — decided by the
 * REGISTRY, not by a chain id baked into the bundle. The API routes on the
 * gate's address form: an EVM gate is `0x…`, a Solana gate is its base58
 * program id. A row with neither url nor gate (the older "listed, not polled"
 * form) is Solana too.
 */
export function isNonEvmChain(c: Pick<Chain, "gate" | "rpcUrl">): boolean {
  return c.gate ? !c.gate.startsWith("0x") : !c.rpcUrl;
}

/**
 * Validate a bridge receiver for the destination chain (finding L-4).
 *
 * The two VMs want different things, and getting it wrong is expensive:
 *
 *  - **EVM destinations** take a 20-byte address.
 *  - **Solana destinations** take a 32-byte key that must be the recipient's
 *    **SPL associated token account**, NOT their wallet address. The gate
 *    releases funds to the account whose address the validators signed, so a
 *    wallet pubkey produces a transfer that can never be claimed. It is now
 *    recoverable — the Solana gate finally has cancel/refund — but it still
 *    costs the user the round trip, and nothing upstream used to say so.
 *
 * The destination's VM comes from its registry entry (`isNonEvmChain`). It used
 * to be `chainId === SOLANA_CHAIN_ID`, so a Solana gate registered under any
 * other id (a local validator, a devnet mesh) was validated as EVM: a base58
 * token account was refused and a 20-byte address ACCEPTED — a receiver the
 * Solana gate can never release to (audit round 5, LOW).
 *
 * Returns `null` when valid, or a message explaining what is wrong.
 */
export function receiverProblem(
  receiver: string,
  destination: Pick<Chain, "gate" | "rpcUrl"> | null
): string | null {
  const v = receiver.trim();
  if (!v) return "Enter a receiver";

  if (destination && isNonEvmChain(destination)) {
    if (isAddress(v)) {
      return "That is an EVM address. A Solana destination needs a base58 account key.";
    }
    if (!isSolanaAccount(v)) return "Enter a valid Solana account key (base58)";
    return null;
  }

  if (isSolanaAccount(v) && !isAddress(v)) {
    return "That looks like a Solana key. This destination needs a 0x EVM address.";
  }
  if (!isAddress(v)) return "Enter a valid 0x address";
  return null;
}
