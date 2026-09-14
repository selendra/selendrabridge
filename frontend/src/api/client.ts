// Tiny GraphQL client. Talks to the backend same-origin via the Vite dev proxy
// (/graphql and /health -> 127.0.0.1:8088, see vite.config.ts). In a production
// build, serve the SPA behind the same origin as graphql-api, or set VITE_API.

import type {
  Chain,
  HistoryEntry,
  HistoryFilter,
  Stats,
  Submission,
  SubmissionFilter,
  SwapHistoryEntry,
  SwapPoolInfo,
} from "./types";

// `import.meta.env` is injected by Vite. Guard the whole access so this module
// can also be imported outside a Vite build (the test runner does exactly that
// to exercise the query builders directly).
const API_BASE = import.meta.env?.VITE_API ?? "";

export async function gql<T>(query: string, variables?: Record<string, unknown>): Promise<T> {
  const res = await fetch(`${API_BASE}/graphql`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ query, variables }),
  });
  if (!res.ok) throw new Error(`backend HTTP ${res.status}`);
  const json = (await res.json()) as { data?: T; errors?: { message: string }[] };
  if (json.errors && json.errors.length) throw new Error(json.errors[0].message);
  if (!json.data) throw new Error("empty GraphQL response");
  return json.data;
}

/**
 * Guard a number that is about to be spliced into a GraphQL document as a
 * literal.
 *
 * `chainId`/`limit` are `u64` arguments with no convenient variable scalar name,
 * so they are inlined rather than bound. That is only safe while they really are
 * integers: TypeScript's `number` is a compile-time claim, and these values
 * originate from backend JSON and wallet responses. A non-integer would be
 * interpolated verbatim into the query text — closing the argument list and
 * appending arbitrary selections. Enforce the claim at the boundary instead of
 * documenting it.
 *
 * Its three callers are `async` on purpose. A `Promise`-returning function that
 * throws SYNCHRONOUSLY sidesteps every `.catch()` its callers attach, so a
 * rejected argument would crash a render instead of being handled like any other
 * failed fetch. `async` turns the throw into a rejection.
 */
function intLiteral(name: string, v: number): string {
  if (!Number.isSafeInteger(v) || v < 0) throw new Error(`${name} must be a non-negative integer`);
  return String(v);
}

export async function health(): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/health`);
    return res.ok;
  } catch {
    return false;
  }
}

// --- bridge / signature store -------------------------------------------

export function fetchChains(): Promise<Chain[]> {
  return gql<{ chains: Chain[] }>(
    `{ chains { chainId name rpcUrl gate token tokens { symbol address bridgeDecimals } router } }`,
  ).then((d) => d.chains);
}

export function fetchStats(): Promise<Stats> {
  return gql<{ stats: Stats }>(
    `{ stats { total signed ready threshold routes { chainIdFrom chainIdTo count } } }`
  ).then((d) => d.stats);
}

export function fetchSubmissions(filter?: SubmissionFilter): Promise<Submission[]> {
  return gql<{ submissions: Submission[] }>(
    `query Subs($filter: SubmissionFilter) {
       submissions(filter: $filter) {
         submissionId debridgeId amount bridgeDecimals chainIdFrom chainIdTo nonce receiver
         nativeSender signatureCount meetsThreshold status
         signatures { signer }
       }
     }`,
    { filter }
  ).then((d) => d.submissions);
}

export function fetchSubmission(submissionId: string): Promise<Submission | null> {
  return gql<{ submission: Submission | null }>(
    `query Sub($id: String!) {
       submission(submissionId: $id) {
         submissionId debridgeId amount bridgeDecimals chainIdFrom chainIdTo nonce receiver
         nativeSender autoParams signatureCount meetsThreshold status
         signatures { signer signature }
       }
     }`,
    { id: submissionId }
  ).then((d) => d.submission);
}

// --- transaction history (served via the sig-store's read scope) ---------

export function fetchHistory(filter?: HistoryFilter): Promise<HistoryEntry[]> {
  return gql<{ history: HistoryEntry[] }>(
    `query Hist($filter: HistoryFilter) {
       history(filter: $filter) {
         submissionId debridgeId amount bridgeDecimals chainIdFrom chainIdTo nonce receiver
         status claimTx signatureCount createdAt updatedAt
         stuck refundStatus refundTx cancelTx token
         cancelSignatureCount refundSignatureCount
         swapIntent {
           tokenIn amountIn stableOut finalToken finalReceiver
           finalizeTx finalizeAmountOut finalizeFallback finalizedAt
         }
       }
     }`,
    { filter }
  ).then((d) => d.history);
}

export async function fetchSwapHistory(chainId?: number, limit?: number): Promise<SwapHistoryEntry[]> {
  // chainId/limit are u64 args (not InputObject fields), which — like
  // swapQuote's chainId — don't have a convenient GraphQL variable scalar
  // name, so inline them as integer literals rather than variables. See
  // `intLiteral`: the integer-ness is enforced, not assumed.
  const args = [
    chainId != null ? `chainId: ${intLiteral("chainId", chainId)}` : null,
    limit != null ? `limit: ${intLiteral("limit", limit)}` : null,
  ]
    .filter(Boolean)
    .join(", ");
  return gql<{ swapHistory: SwapHistoryEntry[] }>(
    `{ swapHistory(${args}) {
         chainId txHash sender receiver tokenIn tokenOut amountIn amountOut
         blockNumber createdAt
       } }`
  ).then((d) => d.swapHistory);
}

// --- swap (same-chain SwapPool) -----------------------------------------
// chainId is inlined as an integer literal (it's a validated number, not free
// text) to sidestep the u64 GraphQL scalar name; string args use variables.

export async function fetchSwapPool(chainId: number): Promise<SwapPoolInfo | null> {
  return gql<{ swapPool: SwapPoolInfo | null }>(
    `{ swapPool(chainId: ${intLiteral("chainId", chainId)}) {
         chainId address stable
         tokens { token symbol decimals price reserve maxSwapUsd isStable vault }
       } }`
  ).then((d) => d.swapPool);
}

/** A recent blockhash for a Solana pool's cluster (the one thing the browser
 *  cannot derive; everything else in the transaction is built locally). */
export async function fetchSolanaBlockhash(chainId: number): Promise<string | null> {
  return gql<{ solanaBlockhash: string | null }>(
    `{ solanaBlockhash(chainId: ${intLiteral("chainId", chainId)}) }`
  ).then((d) => d.solanaBlockhash);
}

export interface SolanaGateContext {
  programId: string;
  bridgeDomain: string;
  chainId: number;
  nonce: number;
  debridgeId: string;
  vault: string;
  /** The mint's decimals — what the user types the amount in. */
  decimals: number;
  /** The asset's bridge decimals; amounts must be multiples of 10^(decimals - bridgeDecimals). */
  bridgeDecimals: number;
  paused: boolean;
}

/** What the browser needs to build a `send` out of Solana. None of it decides
 *  where the funds go — see `SolanaBridgePanel`. */
export async function fetchSolanaGateContext(
  chainId: number,
  symbol: string,
  chainIdTo: number
): Promise<SolanaGateContext | null> {
  return gql<{ solanaGateContext: SolanaGateContext | null }>(
    `query Q($sym: String!) {
       solanaGateContext(chainId: ${intLiteral("chainId", chainId)}, symbol: $sym, chainIdTo: ${intLiteral(
         "chainIdTo",
         chainIdTo
       )}) { programId bridgeDomain chainId nonce debridgeId vault decimals bridgeDecimals paused }
     }`,
    { sym: symbol }
  ).then((d) => d.solanaGateContext);
}

/** SPL balance of a token account the CALLER derived. */
export async function fetchSolanaTokenBalance(chainId: number, account: string): Promise<string | null> {
  return gql<{ solanaTokenBalance: string | null }>(
    `query Q($acct: String!) {
       solanaTokenBalance(chainId: ${intLiteral("chainId", chainId)}, account: $acct)
     }`,
    { acct: account }
  ).then((d) => d.solanaTokenBalance);
}

/** `pending` | `processed` | `confirmed` | `finalized` | `failed`. */
export async function fetchSolanaSignatureStatus(
  chainId: number,
  signature: string
): Promise<string | null> {
  return gql<{ solanaSignatureStatus: string | null }>(
    `query Q($sig: String!) {
       solanaSignatureStatus(chainId: ${intLiteral("chainId", chainId)}, signature: $sig)
     }`,
    { sig: signature }
  ).then((d) => d.solanaSignatureStatus);
}

export async function fetchSwapQuote(
  chainId: number,
  tokenIn: string,
  tokenOut: string,
  amountIn: string
): Promise<string | null> {
  return gql<{ swapQuote: string | null }>(
    `query Q($in: String!, $out: String!, $amt: String!) {
       swapQuote(chainId: ${intLiteral("chainId", chainId)}, tokenIn: $in, tokenOut: $out, amountIn: $amt)
     }`,
    { in: tokenIn, out: tokenOut, amt: amountIn }
  ).then((d) => d.swapQuote);
}
