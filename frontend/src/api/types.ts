// Wire types mirroring the graphql-api schema (crates/graphql-api/src/schema.rs).

export type SubmissionStatus = "PENDING" | "READY" | "EXECUTED" | "CANCELLED" | "UNKNOWN";

export interface TokenRef {
  symbol: string;
  address: string;
  /** The asset's mesh-wide bridge decimals; null when the registry doesn't say. */
  bridgeDecimals?: number | null;
}

export interface Chain {
  chainId: number;
  name: string;
  rpcUrl: string | null;
  gate: string | null;
  /** Default/primary bridgeable token (back-compat; `tokens[0]` supersedes). */
  token: string | null;
  /** All bridgeable tokens on this chain, for the token picker. May be empty. */
  tokens: TokenRef[];
  /** Deployed SwapRouter on this chain, for cross-chain swap. Null if unset. */
  router: string | null;
}

export interface SignatureRef {
  signer: string;
  signature?: string;
}

export interface Submission {
  submissionId: string;
  debridgeId?: string;
  /** Wire amount: in the asset's BRIDGE decimals (`bridgeDecimals`), not the
   *  source token's own decimals. */
  amount: string;
  /** Decimals `amount` is expressed in; null when the API cannot resolve the asset. */
  bridgeDecimals?: number | null;
  chainIdFrom: number;
  chainIdTo: number;
  nonce: number;
  receiver: string;
  nativeSender?: string;
  autoParams?: string;
  signatureCount: number;
  meetsThreshold: boolean | null;
  status: SubmissionStatus;
  signatures: SignatureRef[];
}

export interface RouteCount {
  chainIdFrom: number;
  chainIdTo: number;
  count: number;
}

export interface Stats {
  total: number;
  signed: number;
  ready: number;
  threshold: number | null;
  routes: RouteCount[];
}

export interface SubmissionFilter {
  chainIdFrom?: number;
  chainIdTo?: number;
  minSignatures?: number;
  ready?: boolean;
}

// --- swap (same-chain SwapPool read view) --------------------------------

export interface PoolToken {
  token: string; // 0x address (lowercase), or a base58 mint on Solana
  /** The pool's vault for this token — Solana only; null on EVM. */
  vault?: string | null;
  symbol: string;
  decimals: number;
  price: string; // 1e18-scaled USD, decimal string
  reserve: string; // base units, decimal string — this is the swap lock
  maxSwapUsd: string; // reserve*price/10^decimals, 1e18-scaled, decimal string
  isStable: boolean;
}

export interface SwapPoolInfo {
  chainId: number;
  address: string; // SwapPool contract — approve/swap target
  stable: string;
  tokens: PoolToken[];
}

// --- transaction history (served via the sig-store's read scope) ---------

/** The swap intent (and destination outcome) of a swap-then-bridge transfer. */
export interface SwapIntent {
  tokenIn: string;
  amountIn: string;
  stableOut: string;
  finalToken: string;
  finalReceiver: string;
  finalizeTx: string | null;
  finalizeAmountOut: string | null;
  finalizeFallback: boolean | null;
  finalizedAt: string | null;
}

/**
 * A row from the DB-backed `history` query: every bridge transfer the indexer
 * has observed, including ones stuck at zero signatures (which `submissions`
 * can never show — that view only exists once a validator has signed).
 */
export interface HistoryEntry {
  submissionId: string;
  debridgeId: string;
  /** Wire amount, in `bridgeDecimals` (see {@link Submission.amount}). */
  amount: string;
  bridgeDecimals?: number | null;
  chainIdFrom: number;
  chainIdTo: number;
  nonce: number;
  receiver: string;
  status: string; // 'signed' | 'claimed' (DB lifecycle, not the live-checked SubmissionStatus)
  claimTx: string | null;
  signatureCount: number;
  createdAt: string;
  updatedAt: string;
  /** True once this transfer has entered the refund lifecycle at all. */
  stuck: boolean;
  /**
   * 'none' | 'eligible' | 'cancelled' | 'refunded'.
   *
   * 'cancelled' means the transfer was burned on the destination chain so the
   * source could repay it — the funds did NOT arrive; they went back.
   */
  refundStatus: string;
  /** Source-chain Gate.refund tx hash. */
  refundTx: string | null;
  /** Destination-chain Gate.cancel tx hash. */
  cancelTx: string | null;
  /** The source-chain ERC-20 that was locked. */
  token: string | null;
  /** Validators attesting the destination burn. */
  cancelSignatureCount: number;
  /** Validators attesting the source payout. */
  refundSignatureCount: number;
  swapIntent: SwapIntent | null;
}

export interface HistoryFilter {
  chainIdFrom?: number;
  chainIdTo?: number;
  stuckOnly?: boolean;
  submissionId?: string;
}

/** A completed same-chain swap (SwapPool.Swapped), mirrored by the indexer. */
export interface SwapHistoryEntry {
  chainId: number;
  txHash: string;
  sender: string;
  receiver: string;
  tokenIn: string;
  tokenOut: string;
  amountIn: string;
  amountOut: string;
  /** Decimals of `tokenIn`/`tokenOut` respectively — a swap crosses two tokens,
   *  so the two amounts are in DIFFERENT scales and neither is "the chain's".
   *  Null when the API could not read that token; show the raw integer then. */
  amountInDecimals: number | null;
  amountOutDecimals: number | null;
  blockNumber: number;
  createdAt: string;
}
