// Minimal, dependency-free Solana encoding for the ONE transaction this app
// sends: a swap against `crates/solana-swap`.
//
// Same posture as `wallet/eth.ts`: no web3.js. Not for its own sake — because
// everything that decides where the money goes must be computed HERE. A
// destination account taken on trust from a server is a destination that can be
// swapped for someone else's, and the wallet's confirmation dialog shows an
// address the user has no way to check. So the ATAs, the pool PDAs and the
// instruction bytes are all derived in the browser; the API supplies only a
// recent blockhash, which cannot be abused.
//
// Everything here is byte-level and covered by `e2e/unit/solana.spec.ts`, whose
// expected values come from the on-chain program and the deployed accounts.

import { bytesToHex, hexToBytes, submissionId } from "./keccak";

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function b58encode(bytes: Uint8Array): string {
  // Starts EMPTY, not [0]: a leading zero digit would append a spurious '1' to
  // an all-zero key, which the leading-zero loop below already accounts for.
  const digits: number[] = [];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      carry += digits[i] << 8;
      digits[i] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = "";
  for (const b of bytes) {
    if (b !== 0) break;
    out += "1";
  }
  for (let i = digits.length - 1; i >= 0; i--) out += B58[digits[i]];
  return out || "1";
}

export function b58decode(s: string): Uint8Array {
  // Also empty for the same reason, mirrored: `[0]` here yields 33 bytes for a
  // 32-byte zero key, which silently lengthens a blockhash by one byte.
  const bytes: number[] = [];
  for (const ch of s) {
    const v = B58.indexOf(ch);
    if (v < 0) throw new Error(`bad base58 character: ${ch}`);
    let carry = v;
    for (let i = 0; i < bytes.length; i++) {
      carry += bytes[i] * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  let zeros = 0;
  for (const ch of s) {
    if (ch !== "1") break;
    zeros++;
  }
  return new Uint8Array([...new Array(zeros).fill(0), ...bytes.reverse()]);
}

// ---------------------------------------------------------------------------
// Program-derived addresses
// ---------------------------------------------------------------------------

const P = (1n << 255n) - 19n;
// d = -121665/121666 (mod p), the Edwards curve constant.
const D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;

function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let r = 1n;
  let b = ((base % m) + m) % m;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return r;
}

/**
 * Is this 32-byte value a valid Ed25519 point — i.e. could a private key exist
 * for it? A program-derived address must NOT be one, which is the whole reason
 * the bump loop exists.
 *
 * Decompresses y and asks whether x² = (y²-1)/(d·y²+1) has a square root mod p.
 */
export function isOnCurve(key: Uint8Array): boolean {
  if (key.length !== 32) return false;
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(key[i]);
  const sign = y >> 255n;
  y &= (1n << 255n) - 1n;
  if (y >= P) return false;

  const y2 = (y * y) % P;
  const u = (y2 - 1n + P) % P;
  const v = (D * y2 + 1n) % P;
  // x = u·v³·(u·v⁷)^((p-5)/8), the standard RFC 8032 recovery.
  const v3 = (((v * v) % P) * v) % P;
  const v7 = (((v3 * v3) % P) * v) % P;
  let x = (((u * v3) % P) * modPow((u * v7) % P, (P - 5n) / 8n, P)) % P;
  const vxx = (((v * x) % P) * x) % P;
  if (vxx !== u % P) {
    if (vxx === (P - (u % P)) % P) {
      // x = x · 2^((p-1)/4) recovers the other root; if that fails, no root
      // exists and the value is off the curve.
      x = (x * modPow(2n, (P - 1n) / 4n, P)) % P;
      if ((((v * x) % P) * x) % P !== u % P) return false;
    } else {
      return false;
    }
  }
  if (x === 0n && sign === 1n) return false;
  return true;
}

async function sha256(parts: Uint8Array[]): Promise<Uint8Array> {
  let len = 0;
  for (const p of parts) len += p.length;
  const buf = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    buf.set(p, off);
    off += p.length;
  }
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
}

const PDA_MARKER = new TextEncoder().encode("ProgramDerivedAddress");

/** `findProgramAddress`: the first bump, counting down from 255, that lands off the curve. */
export async function findProgramAddress(
  seeds: Uint8Array[],
  programId: Uint8Array
): Promise<{ address: Uint8Array; bump: number }> {
  for (let bump = 255; bump >= 0; bump--) {
    const candidate = await sha256([...seeds, new Uint8Array([bump]), programId, PDA_MARKER]);
    if (!isOnCurve(candidate)) return { address: candidate, bump };
  }
  throw new Error("no program address found for these seeds");
}

export const TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
export const ASSOCIATED_TOKEN_PROGRAM_ID = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
export const SYSTEM_PROGRAM_ID = "11111111111111111111111111111111";

const enc = new TextEncoder();

/** The pool account for a swap program (`["pool"]`). */
export async function poolAddress(programId: string): Promise<string> {
  const { address } = await findProgramAddress([enc.encode("pool")], b58decode(programId));
  return b58encode(address);
}

/** One listed mint's record (`["token", mint]`). */
export async function tokenRecordAddress(programId: string, mint: string): Promise<string> {
  const { address } = await findProgramAddress(
    [enc.encode("token"), b58decode(mint)],
    b58decode(programId)
  );
  return b58encode(address);
}

/** The authority that owns every pool vault (`["vault_authority"]`). */
export async function vaultAuthority(programId: string): Promise<string> {
  const { address } = await findProgramAddress([enc.encode("vault_authority")], b58decode(programId));
  return b58encode(address);
}

/** The canonical associated token account for an owner + mint. */
export async function associatedTokenAddress(owner: string, mint: string): Promise<string> {
  const { address } = await findProgramAddress(
    [b58decode(owner), b58decode(TOKEN_PROGRAM_ID), b58decode(mint)],
    b58decode(ASSOCIATED_TOKEN_PROGRAM_ID)
  );
  return b58encode(address);
}

// ---------------------------------------------------------------------------
// Instructions
// ---------------------------------------------------------------------------

export interface AccountMeta {
  pubkey: string;
  isSigner: boolean;
  isWritable: boolean;
}
export interface Instruction {
  programId: string;
  keys: AccountMeta[];
  data: Uint8Array;
}

function u64le(v: bigint): Uint8Array {
  if (v < 0n || v > 0xffffffffffffffffn) throw new Error(`u64 out of range: ${v}`);
  const out = new Uint8Array(8);
  let x = v;
  for (let i = 0; i < 8; i++) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

/**
 * `SwapInstruction::Swap { amount_in, min_amount_out }` — Borsh: the enum's
 * variant index (5) then two little-endian u64s. The variant index is position
 * in the enum, so a variant inserted ABOVE Swap in the program would change it;
 * `e2e/unit/solana.spec.ts` pins the bytes.
 */
export function encodeSwapData(amountIn: bigint, minAmountOut: bigint): Uint8Array {
  return new Uint8Array([5, ...u64le(amountIn), ...u64le(minAmountOut)]);
}

/** The `createAssociatedTokenAccount` instruction (idempotent variant, tag 1). */
export function createAtaInstruction(
  payer: string,
  ata: string,
  owner: string,
  mint: string
): Instruction {
  return {
    programId: ASSOCIATED_TOKEN_PROGRAM_ID,
    keys: [
      { pubkey: payer, isSigner: true, isWritable: true },
      { pubkey: ata, isSigner: false, isWritable: true },
      { pubkey: owner, isSigner: false, isWritable: false },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
    ],
    data: new Uint8Array([1]),
  };
}

/**
 * The swap instruction, with accounts in the exact order `process_swap` reads
 * them. Every address here is derived locally — see the file header for why.
 */
export async function buildSwapInstruction(args: {
  programId: string;
  user: string;
  mintIn: string;
  mintOut: string;
  vaultIn: string;
  vaultOut: string;
  userIn: string;
  userOut: string;
  amountIn: bigint;
  minAmountOut: bigint;
}): Promise<Instruction> {
  const [pool, recIn, recOut, authority] = await Promise.all([
    poolAddress(args.programId),
    tokenRecordAddress(args.programId, args.mintIn),
    tokenRecordAddress(args.programId, args.mintOut),
    vaultAuthority(args.programId),
  ]);
  return {
    programId: args.programId,
    keys: [
      { pubkey: pool, isSigner: false, isWritable: false },
      { pubkey: args.user, isSigner: true, isWritable: false },
      { pubkey: recIn, isSigner: false, isWritable: true },
      { pubkey: recOut, isSigner: false, isWritable: true },
      { pubkey: args.userIn, isSigner: false, isWritable: true },
      { pubkey: args.userOut, isSigner: false, isWritable: true },
      { pubkey: args.vaultIn, isSigner: false, isWritable: true },
      { pubkey: args.vaultOut, isSigner: false, isWritable: true },
      { pubkey: args.mintIn, isSigner: false, isWritable: false },
      { pubkey: args.mintOut, isSigner: false, isWritable: false },
      { pubkey: authority, isSigner: false, isWritable: false },
      { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
    ],
    data: encodeSwapData(args.amountIn, args.minAmountOut),
  };
}

// ---------------------------------------------------------------------------
// The bridge gate: locking SPL on Solana to send it to an EVM chain
// ---------------------------------------------------------------------------

export const GATE_CONFIG_SEED = "config";
export const GATE_ASSET_SEED = "asset";
export const GATE_SENT_SEED = "sent";

/** The gate's config account (`["config"]`). */
export async function gateConfigAddress(programId: string): Promise<string> {
  const { address } = await findProgramAddress([enc.encode(GATE_CONFIG_SEED)], b58decode(programId));
  return b58encode(address);
}

/** The registry entry binding a debridgeId to its mint + vault. */
export async function gateAssetAddress(programId: string, debridgeId: string): Promise<string> {
  const { address } = await findProgramAddress(
    [enc.encode(GATE_ASSET_SEED), hexToBytes(debridgeId)],
    b58decode(programId)
  );
  return b58encode(address);
}

/** The `["sent", submissionId]` record a later refund uses as its origin proof. */
export async function gateSentAddress(programId: string, submissionIdBytes: Uint8Array): Promise<string> {
  const { address } = await findProgramAddress(
    [enc.encode(GATE_SENT_SEED), submissionIdBytes],
    b58decode(programId)
  );
  return b58encode(address);
}

/** Borsh `Vec<u8>`: a 4-byte little-endian length, then the bytes. */
function borshBytes(b: Uint8Array): number[] {
  const len = new Uint8Array(4);
  new DataView(len.buffer).setUint32(0, b.length, true);
  return [...len, ...b];
}

/**
 * `GateInstruction::Send { debridge_id, amount, chain_id_to, receiver, auto }`
 * — Borsh, variant index 1 (Init is 0).
 *
 * `auto` is always `None` here: an execution payload changes the submissionId
 * (it hashes a longer preimage), and this app does not offer one.
 */
export function encodeGateSendData(args: {
  debridgeId: string;
  amount: bigint;
  chainIdTo: bigint;
  receiver: Uint8Array;
}): Uint8Array {
  if (args.chainIdTo > 0xffffffffffffffffn) throw new Error("chainIdTo out of range");
  return new Uint8Array([
    1,
    ...hexToBytes(args.debridgeId),
    ...u64le(args.amount),
    ...u64le(args.chainIdTo),
    ...borshBytes(args.receiver),
    0, // Option::None
  ]);
}

/**
 * The gate `send` instruction: lock SPL into the registered vault and emit the
 * `Sent` event the relayers sign.
 *
 * The `["sent", id]` PDA depends on the submissionId, so the browser computes
 * that id itself (`wallet/keccak.ts`) from the SAME inputs it puts in the
 * instruction. The nonce and bridge domain come from the API — but they only
 * decide whether the id matches the one the program derives, never where the
 * funds go: the receiver is in the data this function builds.
 */
export async function buildGateSendInstruction(args: {
  programId: string;
  user: string;
  userTokenAccount: string;
  vault: string;
  debridgeId: string;
  bridgeDomain: string;
  solanaChainId: bigint;
  chainIdTo: bigint;
  nonce: bigint;
  /** MINT amount to lock (the mint's decimals) — what the instruction carries. */
  amount: bigint;
  /**
   * `10^(mintDecimals - bridgeDecimals)`. The program hashes `amount / bridgeUnit`
   * (the asset's bridge-decimals amount every other chain sees), so the id — and
   * the `sent` PDA it seeds — must be built from that, not from `amount`.
   */
  bridgeUnit: bigint;
  /**
   * The asset's bridge decimals, as the Solana gate's own registry has them.
   * Hashed into the id (H-2), so it must be the SAME value the program will
   * read from the asset account — a mismatch makes the `sent` PDA wrong and the
   * send fails rather than locking funds under an id nobody can settle.
   */
  bridgeDecimals: number;
  receiver: Uint8Array;
}): Promise<{ instruction: Instruction; submissionId: string }> {
  if (args.bridgeUnit <= 0n) throw new Error("bridge unit must be positive");
  if (args.amount % args.bridgeUnit !== 0n) {
    throw new Error(`amount must be a whole multiple of ${args.bridgeUnit} (the asset's bridge unit)`);
  }
  const id = submissionId({
    bridgeDomain: args.bridgeDomain,
    debridgeId: args.debridgeId,
    bridgeDecimals: args.bridgeDecimals,
    amount: args.amount / args.bridgeUnit,
    chainIdFrom: args.solanaChainId,
    chainIdTo: args.chainIdTo,
    nonce: args.nonce,
    receiver: args.receiver,
  });
  const [config, asset, sent] = await Promise.all([
    gateConfigAddress(args.programId),
    gateAssetAddress(args.programId, args.debridgeId),
    gateSentAddress(args.programId, id),
  ]);
  return {
    submissionId: bytesToHex(id),
    instruction: {
      programId: args.programId,
      keys: [
        { pubkey: config, isSigner: false, isWritable: true },
        { pubkey: asset, isSigner: false, isWritable: false },
        { pubkey: args.user, isSigner: true, isWritable: true },
        { pubkey: args.userTokenAccount, isSigner: false, isWritable: true },
        { pubkey: args.vault, isSigner: false, isWritable: true },
        { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
        { pubkey: sent, isSigner: false, isWritable: true },
        { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
      ],
      data: encodeGateSendData(args),
    },
  };
}

// ---------------------------------------------------------------------------
// Legacy transaction message
// ---------------------------------------------------------------------------

/** compact-u16 (shortvec) length prefix. */
function shortVec(n: number): number[] {
  const out: number[] = [];
  let v = n;
  for (;;) {
    if (v < 0x80) {
      out.push(v);
      return out;
    }
    out.push((v & 0x7f) | 0x80);
    v >>= 7;
  }
}

/**
 * Serialize a legacy message: header, account keys, blockhash, instructions.
 *
 * Account ordering is the consensus rule, not a preference — signers first,
 * then writable non-signers, then read-only, with the fee payer at index 0.
 * Getting it wrong produces a transaction the runtime rejects rather than one
 * that misbehaves, which is the failure mode you want here.
 */
export function serializeMessage(
  feePayer: string,
  blockhash: string,
  instructions: Instruction[]
): Uint8Array {
  const metas = new Map<string, AccountMeta>();
  const note = (m: AccountMeta) => {
    const prev = metas.get(m.pubkey);
    if (prev) {
      prev.isSigner ||= m.isSigner;
      prev.isWritable ||= m.isWritable;
    } else {
      metas.set(m.pubkey, { ...m });
    }
  };
  note({ pubkey: feePayer, isSigner: true, isWritable: true });
  for (const ix of instructions) {
    for (const k of ix.keys) note(k);
    // A program id is always a read-only, non-signer account.
    note({ pubkey: ix.programId, isSigner: false, isWritable: false });
  }

  const all = [...metas.values()];
  const rank = (m: AccountMeta) =>
    m.pubkey === feePayer ? 0 : m.isSigner && m.isWritable ? 1 : m.isSigner ? 2 : m.isWritable ? 3 : 4;
  // Within a category, BY PUBKEY — solana-sdk compiles its key list through a
  // BTreeMap, so an order based on first appearance produces a different (and
  // rejected) message even though every account is present.
  const cmp = (a: string, b: string) => {
    const x = b58decode(a);
    const y = b58decode(b);
    for (let i = 0; i < 32; i++) {
      if (x[i] !== y[i]) return x[i] - y[i];
    }
    return 0;
  };
  all.sort((a, b) => rank(a) - rank(b) || cmp(a.pubkey, b.pubkey));

  const numSigners = all.filter((m) => m.isSigner).length;
  const numReadonlySigned = all.filter((m) => m.isSigner && !m.isWritable).length;
  const numReadonlyUnsigned = all.filter((m) => !m.isSigner && !m.isWritable).length;
  const index = (key: string) => all.findIndex((m) => m.pubkey === key);

  const bytes: number[] = [numSigners, numReadonlySigned, numReadonlyUnsigned];
  bytes.push(...shortVec(all.length));
  for (const m of all) bytes.push(...b58decode(m.pubkey));
  bytes.push(...b58decode(blockhash));
  bytes.push(...shortVec(instructions.length));
  for (const ix of instructions) {
    bytes.push(index(ix.programId));
    bytes.push(...shortVec(ix.keys.length));
    for (const k of ix.keys) bytes.push(index(k.pubkey));
    bytes.push(...shortVec(ix.data.length));
    bytes.push(...ix.data);
  }
  return new Uint8Array(bytes);
}

/**
 * A signed-transaction envelope with an empty signature slot, which is what a
 * wallet expects to be handed for signing.
 */
export function serializeUnsignedTransaction(message: Uint8Array, numSigners: number): Uint8Array {
  const sigs: number[] = [...shortVec(numSigners)];
  for (let i = 0; i < numSigners; i++) sigs.push(...new Array(64).fill(0));
  return new Uint8Array([...sigs, ...message]);
}
