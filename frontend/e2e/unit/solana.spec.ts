import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { hexToBytes } from "../../src/wallet/keccak";
import {
  associatedTokenAddress,
  buildGateSendInstruction,
  b58decode,
  b58encode,
  buildSwapInstruction,
  encodeSwapData,
  isOnCurve,
  poolAddress,
  serializeMessage,
  tokenRecordAddress,
  vaultAuthority,
} from "../../src/wallet/solana";

/**
 * The browser builds its own Solana swap transaction — no web3.js — so that
 * every account deciding where the money goes is derived locally rather than
 * taken from a server. Hand-rolled encoding has to be pinned to something, and
 * the something is `solana-sdk` itself: `contracts/fixtures/solana_swap_tx.json`
 * is written by `crates/solana-relayer/tests/swap_message_fixture.rs`, which
 * builds the SAME transaction through the real SDK.
 *
 * A failure here means the UI would produce a transaction the runtime rejects —
 * or, worse for the PDA cases, one that points at the wrong accounts.
 */
const fx = JSON.parse(
  readFileSync(fileURLToPath(new URL("../../../contracts/fixtures/solana_swap_tx.json", import.meta.url)), "utf8")
);

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

test("base58 round-trips, including leading zeros", () => {
  for (const key of [fx.program, fx.user, fx.mintIn, "11111111111111111111111111111111"]) {
    expect(b58encode(b58decode(key))).toBe(key);
  }
  expect(b58decode(fx.program)).toHaveLength(32);
});

test("on-curve detection separates wallets from program addresses", () => {
  // A wallet pubkey IS a curve point; a PDA is chosen precisely because it is not.
  expect(isOnCurve(b58decode(fx.user))).toBe(true);
  expect(isOnCurve(b58decode(fx.poolPda))).toBe(false);
  expect(isOnCurve(b58decode(fx.vaultAuthority))).toBe(false);
});

test("PDA derivation matches solana-sdk", async () => {
  expect(await poolAddress(fx.program)).toBe(fx.poolPda);
  expect(await vaultAuthority(fx.program)).toBe(fx.vaultAuthority);
  expect(await tokenRecordAddress(fx.program, fx.mintIn)).toBe(fx.recordInPda);
  expect(await tokenRecordAddress(fx.program, fx.mintOut)).toBe(fx.recordOutPda);
});

test("the associated token account is derived, never trusted from the API", async () => {
  // These are the real ATAs of the fixture's owner — the accounts a swap pays
  // out to. Deriving them locally is the whole reason this module exists.
  expect(await associatedTokenAddress(fx.user, fx.mintIn)).toBe(fx.userIn);
  expect(await associatedTokenAddress(fx.user, fx.mintOut)).toBe(fx.userOut);
});

test("swap instruction data is the program's Borsh encoding", () => {
  const data = encodeSwapData(BigInt(fx.amountIn), BigInt(fx.minAmountOut));
  expect(hex(data)).toBe(fx.instructionData);
  // Variant 5 = SwapInstruction::Swap; a variant inserted above it in the
  // program would silently change this byte.
  expect(data[0]).toBe(5);
});

test("the serialized message is byte-identical to the SDK's", async () => {
  const ix = await buildSwapInstruction({
    programId: fx.program,
    user: fx.user,
    mintIn: fx.mintIn,
    mintOut: fx.mintOut,
    vaultIn: fx.vaultIn,
    vaultOut: fx.vaultOut,
    userIn: fx.userIn,
    userOut: fx.userOut,
    amountIn: BigInt(fx.amountIn),
    minAmountOut: BigInt(fx.minAmountOut),
  });
  const msg = serializeMessage(fx.user, fx.blockhash, [ix]);
  expect(hex(msg)).toBe(fx.message);
});

test("u64 encoding refuses what it cannot represent", () => {
  expect(() => encodeSwapData(-1n, 0n)).toThrow();
  expect(() => encodeSwapData(2n ** 64n, 0n)).toThrow();
});

/**
 * The gate `send` — bridging OUT of Solana.
 *
 * Pinned the same way as the swap, and for a sharper reason: the
 * `["sent", submissionId]` account depends on an id the browser computes with
 * its own keccak. If that id were off by a bit, the PDA would not match the one
 * the program derives and the transfer would simply fail — so the id is checked
 * against `bridge_solana::hash`, which is itself pinned to the Solidity fixtures.
 */
const gfx = JSON.parse(
  readFileSync(
    fileURLToPath(new URL("../../../contracts/fixtures/solana_gate_send_tx.json", import.meta.url)),
    "utf8"
  )
);

test("the submissionId the browser computes matches the shared implementation", async () => {
  const { submissionId: id } = await buildGateSendInstruction({
    programId: gfx.program,
    user: gfx.user,
    userTokenAccount: gfx.userToken,
    vault: gfx.vault,
    debridgeId: gfx.debridgeId,
    bridgeDomain: gfx.bridgeDomain,
    solanaChainId: BigInt(gfx.solanaChainId),
    chainIdTo: BigInt(gfx.chainIdTo),
    nonce: BigInt(gfx.nonce),
    amount: BigInt(gfx.amount),
    bridgeUnit: BigInt(gfx.bridgeUnit),
    bridgeDecimals: gfx.bridgeDecimals,
    receiver: hexToBytes(gfx.receiver),
  });
  expect(id).toBe(gfx.submissionId);
});

test("the gate send transaction is byte-identical to the SDK's", async () => {
  const { instruction } = await buildGateSendInstruction({
    programId: gfx.program,
    user: gfx.user,
    userTokenAccount: gfx.userToken,
    vault: gfx.vault,
    debridgeId: gfx.debridgeId,
    bridgeDomain: gfx.bridgeDomain,
    solanaChainId: BigInt(gfx.solanaChainId),
    chainIdTo: BigInt(gfx.chainIdTo),
    nonce: BigInt(gfx.nonce),
    amount: BigInt(gfx.amount),
    bridgeUnit: BigInt(gfx.bridgeUnit),
    bridgeDecimals: gfx.bridgeDecimals,
    receiver: hexToBytes(gfx.receiver),
  });
  expect(hex(instruction.data)).toBe(gfx.instructionData);
  // And the accounts it derived, including the id-dependent one.
  expect(instruction.keys[0].pubkey).toBe(gfx.configPda);
  expect(instruction.keys[1].pubkey).toBe(gfx.assetPda);
  expect(instruction.keys[6].pubkey).toBe(gfx.sentPda);

  const msg = serializeMessage(gfx.user, gfx.blockhash, [instruction]);
  expect(hex(msg)).toBe(gfx.message);
});
