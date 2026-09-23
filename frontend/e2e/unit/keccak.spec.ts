import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { bytesToHex, debridgeId, hexToBytes, keccak256, submissionId } from "../../src/wallet/keccak";

/**
 * The submissionId is the one value the whole bridge agrees on: Solidity, Rust
 * and the Solana program hash the same bytes, and a browser that computes it
 * differently would build a transfer nobody can claim.
 *
 * These are the SAME fixtures the Solidity and Rust implementations are pinned
 * to (`contracts/fixtures/submission_ids.json`, written by GenFixtures.t.sol).
 */
const fx = JSON.parse(
  readFileSync(fileURLToPath(new URL("../../../contracts/fixtures/submission_ids.json", import.meta.url)), "utf8")
);

test("keccak256 matches the known empty-input digest", () => {
  expect(bytesToHex(keccak256(new Uint8Array()))).toBe(
    "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
  );
  expect(bytesToHex(keccak256(new TextEncoder().encode("abc")))).toBe(
    "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
  );
});

/**
 * The asset id the browser derives to ask a DESTINATION gate what scale it would
 * pay an asset out in (H-2). A wrong id there is not a visible failure: the gate
 * answers "not registered", the UI refuses every transfer of that asset, and the
 * mismatch it exists to catch is never actually checked.
 *
 * Golden value from `cast keccak $(cast abi-encode --packed 'f(uint256,address)'
 * 1337 0xaa…aa)`, i.e. exactly `BridgeHash.getDebridgeId(1337, 0xaa…aa)`.
 */
test("debridgeId packs a 32-byte chain id and the RAW 20-byte token", () => {
  expect(debridgeId(1337n, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")).toBe(
    "0xd663e6c160b55911e4e4c0e0dc08ae44f1493be27a4356da0f44e1960f0eba54"
  );
  // The token is NOT word-padded: padding it would hash to an id no gate maps.
  expect(debridgeId(1337n, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")).not.toBe(
    bytesToHex(keccak256(hexToBytes("0x" + (1337).toString(16).padStart(64, "0") + "aa".repeat(20).padStart(64, "0"))))
  );
  expect(() => debridgeId(1337n, "0x1234")).toThrow(/bad token address/);
});

test("submissionId matches every Solidity fixture without an auto payload", () => {
  const cases = fx.fixtures.filter((f: { hasAuto: boolean }) => !f.hasAuto);
  expect(cases.length).toBeGreaterThan(0);
  for (const f of cases) {
    const got = submissionId({
      bridgeDomain: f.bridgeDomain,
      debridgeId: f.debridgeId,
      bridgeDecimals: f.bridgeDecimals,
      amount: BigInt(f.amount),
      chainIdFrom: BigInt(f.chainIdFrom),
      chainIdTo: BigInt(f.chainIdTo),
      nonce: BigInt(f.nonce),
      receiver: hexToBytes(f.receiver),
    });
    expect(bytesToHex(got), `fixture ${f.name}`).toBe(f.submissionId);
  }
});

test("a 32-byte Solana receiver hashes at its own width, not padded", () => {
  // `long-receiver` is the fixture with a 32-byte (Solana) receiver — the case
  // that would silently break if the receiver were word-padded like the numbers.
  const f = fx.fixtures.find((x: { name: string }) => x.name === "long-receiver");
  expect(hexToBytes(f.receiver)).toHaveLength(32);
  expect(
    bytesToHex(
      submissionId({
        bridgeDomain: f.bridgeDomain,
        debridgeId: f.debridgeId,
        bridgeDecimals: f.bridgeDecimals,
        amount: BigInt(f.amount),
        chainIdFrom: BigInt(f.chainIdFrom),
        chainIdTo: BigInt(f.chainIdTo),
        nonce: BigInt(f.nonce),
        receiver: hexToBytes(f.receiver),
      })
    )
  ).toBe(f.submissionId);
});

/**
 * H-2 at the hash layer, in the browser. `scale-separated` repeats `no-auto`
 * field for field at a different `bridgeDecimals`, so an implementation that
 * dropped the scale byte would produce one id for both — and a wallet would
 * happily sign a transfer the destination reads at a scale nobody agreed to.
 */
test("the wire scale changes the submissionId", () => {
  const plain = fx.fixtures.find((x: { name: string }) => x.name === "no-auto");
  const rescaled = fx.fixtures.find((x: { name: string }) => x.name === "scale-separated");
  expect(rescaled.bridgeDecimals).not.toBe(plain.bridgeDecimals);
  expect(rescaled.amount).toBe(plain.amount);
  expect(rescaled.bridgeDomain).toBe(plain.bridgeDomain);

  const id = (f: { bridgeDomain: string; debridgeId: string; bridgeDecimals: number; amount: string; chainIdFrom: number; chainIdTo: number; nonce: number; receiver: string }) =>
    bytesToHex(
      submissionId({
        bridgeDomain: f.bridgeDomain,
        debridgeId: f.debridgeId,
        bridgeDecimals: f.bridgeDecimals,
        amount: BigInt(f.amount),
        chainIdFrom: BigInt(f.chainIdFrom),
        chainIdTo: BigInt(f.chainIdTo),
        nonce: BigInt(f.nonce),
        receiver: hexToBytes(f.receiver),
      })
    );
  expect(id(plain)).toBe(plain.submissionId);
  expect(id(rescaled)).toBe(rescaled.submissionId);
  expect(id(rescaled)).not.toBe(id(plain));
});
