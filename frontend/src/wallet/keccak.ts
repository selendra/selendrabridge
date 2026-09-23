// Keccak-256, because the browser has to compute a submissionId.
//
// `crypto.subtle` offers SHA-3 nowhere and Keccak (the pre-NIST padding) never,
// and the id is the one value the whole bridge agrees on — Solidity, Rust and
// the Solana program all hash the same bytes. Computing it here rather than
// asking the API for it is what keeps the destination of a transfer decided in
// the browser: the receiver is INSIDE the hash, so an id handed over by a server
// could commit to a different one.
//
// `e2e/unit/keccak.spec.ts` checks this against `contracts/fixtures/submission_ids.json`
// — the same sacred vectors the Solidity and Rust implementations are pinned to.

const RC: bigint[] = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
const ROT = [
  [0, 36, 3, 41, 18],
  [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
];
const MASK = (1n << 64n) - 1n;

const rotl = (x: bigint, n: number) =>
  n === 0 ? x : ((x << BigInt(n)) | (x >> BigInt(64 - n))) & MASK;

function keccakF(a: bigint[][]): void {
  for (let round = 0; round < 24; round++) {
    // θ
    const c = [0n, 0n, 0n, 0n, 0n];
    for (let x = 0; x < 5; x++) c[x] = a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4];
    for (let x = 0; x < 5; x++) {
      const d = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1);
      for (let y = 0; y < 5; y++) a[x][y] ^= d;
    }
    // ρ and π
    const b: bigint[][] = [[], [], [], [], []];
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        b[y][(2 * x + 3 * y) % 5] = rotl(a[x][y], ROT[x][y]);
      }
    }
    // χ
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        a[x][y] = b[x][y] ^ (~b[(x + 1) % 5][y] & MASK & b[(x + 2) % 5][y]);
      }
    }
    // ι
    a[0][0] ^= RC[round];
  }
}

/** Keccak-256 (Ethereum's, i.e. the 0x01 pad — NOT SHA3-256's 0x06). */
export function keccak256(input: Uint8Array): Uint8Array {
  const RATE = 136; // 1088 bits
  const a: bigint[][] = Array.from({ length: 5 }, () => new Array<bigint>(5).fill(0n));

  const padded = new Uint8Array(Math.ceil((input.length + 1) / RATE) * RATE);
  padded.set(input);
  padded[input.length] = 0x01;
  padded[padded.length - 1] |= 0x80;

  for (let off = 0; off < padded.length; off += RATE) {
    for (let i = 0; i < RATE / 8; i++) {
      let lane = 0n;
      for (let j = 7; j >= 0; j--) lane = (lane << 8n) | BigInt(padded[off + i * 8 + j]);
      a[i % 5][(i / 5) | 0] ^= lane;
    }
    keccakF(a);
  }

  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    let lane = a[i % 5][(i / 5) | 0];
    for (let j = 0; j < 8; j++) {
      out[i * 8 + j] = Number(lane & 0xffn);
      lane >>= 8n;
    }
  }
  return out;
}

/** A big-endian 32-byte word, the width every field in the packing uses. */
export function word32(v: bigint): Uint8Array {
  if (v < 0n) throw new Error("negative word");
  const out = new Uint8Array(32);
  let x = v;
  for (let i = 31; i >= 0 && x > 0n; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  if (x > 0n) throw new Error("value exceeds 32 bytes");
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  const h = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  if (h.length % 2) throw new Error(`odd-length hex: ${hex}`);
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToHex(b: Uint8Array): string {
  return "0x" + Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

/**
 * The asset id: `keccak256(abi.encodePacked(nativeChainId, nativeToken))` —
 * byte-identical to `BridgeHash.getDebridgeId` and `bridge_core::debridge_id`.
 *
 * `encodePacked`, not `encode`: a 32-byte chain id followed by the RAW 20-byte
 * token, so the preimage is 52 bytes, not 64. A padded token would hash to an id
 * no gate has ever registered.
 *
 * The id is derived from the asset's NATIVE (source) chain and token — the same
 * id on both ends of a corridor, which is what makes it the right key to ask a
 * destination gate what scale it will pay that asset out in (H-2).
 */
export function debridgeId(nativeChainId: bigint, nativeToken: string): string {
  const token = hexToBytes(nativeToken);
  if (token.length !== 20) throw new Error(`bad token address: ${nativeToken}`);
  const packed = new Uint8Array(52);
  packed.set(word32(nativeChainId), 0);
  packed.set(token, 32);
  return bytesToHex(keccak256(packed));
}

/** deBridge's prefix for a transfer id, as `BridgeHash.SUBMISSION_PREFIX`. */
const SUBMISSION_PREFIX = 1n;

/**
 * The submissionId for a transfer without an execution payload — byte-identical
 * to `BridgeHash.getSubmissionId` and `bridge_core::submission_id`.
 *
 * Field order is the contract's and is load-bearing: the receiver is packed at
 * its natural width (20 bytes for EVM, 32 for Solana) BETWEEN amount and nonce,
 * not padded to a word like the numbers around it.
 *
 * `bridgeDecimals` is the wire scale `amount` is denominated in (H-2), packed as
 * ONE raw byte — `abi.encodePacked(uint8)`, not a word — between chainIdTo and
 * amount. It is in the preimage because `amount` is a bare integer whose meaning
 * depends entirely on it: without the scale, a gate registered one digit off
 * computes the same id and pays out a power of ten too much.
 */
export function submissionId(args: {
  bridgeDomain: string;
  debridgeId: string;
  bridgeDecimals: number;
  amount: bigint;
  chainIdFrom: bigint;
  chainIdTo: bigint;
  nonce: bigint;
  receiver: Uint8Array;
}): Uint8Array {
  if (!Number.isInteger(args.bridgeDecimals) || args.bridgeDecimals < 0 || args.bridgeDecimals > 255) {
    throw new Error(`bridgeDecimals must be a byte: ${args.bridgeDecimals}`);
  }
  const parts = [
    word32(SUBMISSION_PREFIX),
    hexToBytes(args.bridgeDomain),
    hexToBytes(args.debridgeId),
    word32(args.chainIdFrom),
    word32(args.chainIdTo),
    Uint8Array.of(args.bridgeDecimals),
    word32(args.amount),
    args.receiver,
    word32(args.nonce),
  ];
  let len = 0;
  for (const p of parts) len += p.length;
  const packed = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    packed.set(p, off);
    off += p.length;
  }
  return keccak256(packed);
}
