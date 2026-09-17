import { test, expect } from "@playwright/test";
import {
  SOLANA_CHAIN_ID,
  chainViz,
  formatUnits,
  formatUnitsRaw,
  isAddress,
  isSolanaAccount,
  parseUnits,
  receiverProblem,
  isNonEvmChain,
  shortHex,
  tokenGradient,
} from "../../src/data/format";

/**
 * `src/data/format.ts` — every exported function.
 *
 * `parseUnits` is the one that matters most: it converts what the user typed
 * into the base-unit integer that goes into `Gate.send` calldata. Everything
 * else here is presentation.
 */

test.describe("parseUnits", () => {
  test("scales by the token's decimals", () => {
    expect(parseUnits("1", 18)).toBe(10n ** 18n);
    expect(parseUnits("1.5", 18)).toBe(1_500_000_000_000_000_000n);
    expect(parseUnits("100", 6)).toBe(100_000_000n);
    expect(parseUnits("0.000001", 6)).toBe(1n);
  });

  test("handles a zero-decimal token", () => {
    expect(parseUnits("7", 0)).toBe(7n);
    expect(parseUnits("7.9", 0)).toBe(7n);
  });

  test("truncates beyond the token's precision rather than rounding up", () => {
    // Rounding up would encode more than the user has; truncation cannot.
    expect(parseUnits("1.9999999", 6)).toBe(1_999_999n);
  });

  test("rejects anything that is not a plain decimal", () => {
    for (const bad of ["", "abc", "-1", "1e18", "1.2.3", "0x10", " 1,5 ", "١٢٣"]) {
      expect(parseUnits(bad, 18), bad).toBe(0n);
    }
  });

  test("accepts the partial input an amount field produces mid-typing", () => {
    expect(parseUnits(".", 18)).toBe(0n);
    expect(parseUnits("0.", 18)).toBe(0n);
    expect(parseUnits(".5", 18)).toBe(500_000_000_000_000_000n);
    expect(parseUnits(" 2.5 ", 18)).toBe(2_500_000_000_000_000_000n);
  });

  test("keeps full precision on large amounts (no float rounding)", () => {
    expect(parseUnits("123456789.123456789012345678", 18)).toBe(
      123456789123456789012345678n
    );
  });

  test("round-trips with formatUnitsRaw", () => {
    for (const [v, d] of [
      ["1", 18],
      ["0.5", 6],
      ["123456.789", 9],
      ["0", 18],
    ] as const) {
      expect(formatUnitsRaw(parseUnits(v, d), d)).toBe(String(Number(v)));
    }
  });
});

test.describe("formatUnits", () => {
  test("groups the whole part and trims trailing fraction zeros", () => {
    expect(formatUnits(1_234_560_000_000_000_000_000n, 18)).toBe("1,234.56");
    expect(formatUnits("1000000000000000000", 18)).toBe("1");
    expect(formatUnits(0n, 18)).toBe("0");
  });

  test("caps the displayed fraction", () => {
    expect(formatUnits(1_123_456_789_012_345_678n, 18, 4)).toBe("1.1234");
  });

  test("handles amounts smaller than one unit", () => {
    expect(formatUnits(1n, 18)).toBe("0");
    expect(formatUnits(1_000_000_000_000n, 18)).toBe("0.000001");
  });

  test("handles negatives and zero decimals", () => {
    expect(formatUnits(-1_500_000n, 6)).toBe("-1.5");
    expect(formatUnits(42n, 0)).toBe("42");
  });

  test("returns non-numeric input untouched instead of NaN", () => {
    expect(formatUnits("pending", 18)).toBe("pending");
  });
});

test.describe("formatUnitsRaw", () => {
  test("is ungrouped and full precision — it feeds an input field", () => {
    expect(formatUnitsRaw(1_234_560_000_000_000_000_000n, 18)).toBe("1234.56");
    expect(formatUnitsRaw(1n, 18)).toBe("0.000000000000000001");
    expect(formatUnitsRaw(0n, 18)).toBe("0");
    expect(formatUnitsRaw(-2_500_000n, 6)).toBe("-2.5");
  });
});

test.describe("address + receiver validation", () => {
  test("isAddress accepts only a 20-byte 0x hex string", () => {
    expect(isAddress("0x" + "a".repeat(40))).toBe(true);
    expect(isAddress("0x" + "A".repeat(40))).toBe(true);
    expect(isAddress(" 0x" + "a".repeat(40) + " ")).toBe(true);
    expect(isAddress("0x" + "a".repeat(39))).toBe(false);
    expect(isAddress("0x" + "a".repeat(41))).toBe(false);
    expect(isAddress("a".repeat(40))).toBe(false);
    expect(isAddress("0x" + "g".repeat(40))).toBe(false);
    expect(isAddress("")).toBe(false);
  });

  test("isSolanaAccount accepts base58 keys and rejects the ambiguous alphabet", () => {
    expect(isSolanaAccount("SysvarC1ock11111111111111111111111111111111")).toBe(true);
    expect(isSolanaAccount("11111111111111111111111111111111")).toBe(true);
    // 0, O, I and l are excluded from base58 on purpose.
    expect(isSolanaAccount("0".repeat(32))).toBe(false);
    expect(isSolanaAccount("O".repeat(32))).toBe(false);
    expect(isSolanaAccount("l".repeat(32))).toBe(false);
    expect(isSolanaAccount("1".repeat(31))).toBe(false);
    expect(isSolanaAccount("1".repeat(45))).toBe(false);
  });

  const EVM_DEST = { gate: "0x" + "b".repeat(40), rpcUrl: "http://127.0.0.1:8546" };
  const SOLANA_DEST = { gate: "HvGQTWChe6bMpSYGNavDhGcG8YrJkubJQCDmBrxNR133", rpcUrl: null };

  test("an EVM destination demands an EVM address", () => {
    expect(receiverProblem("0x" + "a".repeat(40), EVM_DEST)).toBeNull();
    expect(receiverProblem("", EVM_DEST)).toMatch(/Enter a receiver/);
    expect(receiverProblem("nonsense", EVM_DEST)).toMatch(/valid 0x address/);
  });

  test("a Solana key typed into an EVM destination is named, not just rejected", () => {
    const problem = receiverProblem("SysvarC1ock11111111111111111111111111111111", EVM_DEST);
    expect(problem).toMatch(/Solana key/);
  });

  test("a Solana destination demands a base58 token account", () => {
    expect(receiverProblem("SysvarC1ock11111111111111111111111111111111", SOLANA_DEST)).toBeNull();
    expect(receiverProblem("!!!!", SOLANA_DEST)).toMatch(/base58/);
  });

  test("an EVM address typed into a Solana destination is named", () => {
    // Funds released to a 20-byte value on Solana are unrecoverable without a
    // round trip, so this has to be caught before signing, not after.
    const problem = receiverProblem("0x" + "a".repeat(40), SOLANA_DEST);
    expect(problem).toMatch(/EVM address/);
  });

  test("the destination's VM comes from its registry row, not a chain id", () => {
    // A base58 gate is a Solana program whatever id it is registered under.
    expect(isNonEvmChain(SOLANA_DEST)).toBe(true);
    expect(isNonEvmChain(EVM_DEST)).toBe(false);
    // The older "listed, not polled" row: no gate, no url.
    expect(isNonEvmChain({ gate: null, rpcUrl: null })).toBe(true);
    // An unknown destination is validated as EVM, as before.
    expect(receiverProblem("0x" + "a".repeat(40), null)).toBeNull();
  });

  test("SOLANA_CHAIN_ID is deBridge's value, hashed into every submissionId", () => {
    expect(SOLANA_CHAIN_ID).toBe(7565164);
  });
});

test.describe("presentation helpers", () => {
  test("shortHex middle-truncates only when it saves space", () => {
    expect(shortHex("0x1234567890abcdef1234")).toBe("0x1234…1234");
    expect(shortHex("0x1234")).toBe("0x1234");
    expect(shortHex("0x12345678", 4, 2)).toBe("0x12…78");
    expect(shortHex("")).toBe("");
  });

  test("chainViz uses the curated palette where one exists", () => {
    expect(chainViz(1).short).toBe("ETH");
    expect(chainViz(SOLANA_CHAIN_ID).short).toBe("SOL");
    expect(chainViz(1337).gradient).toHaveLength(2);
  });

  test("chainViz derives a stable label for unknown chains", () => {
    const a = chainViz(99999, "My Test Chain");
    const b = chainViz(99999, "My Test Chain");
    expect(a).toEqual(b);
    expect(a.short).toBe("MYTE");
    // No name: fall back to the id (clipped to the 4-char pill) rather than
    // rendering an empty badge.
    expect(chainViz(424242).short).toBe("4242");
    expect(chainViz(42).short).toBe("42");
  });

  test("tokenGradient is deterministic per address and case-insensitive", () => {
    const lower = tokenGradient("0xabcdef0123456789abcdef0123456789abcdef01");
    const upper = tokenGradient("0xABCDEF0123456789ABCDEF0123456789ABCDEF01");
    expect(lower).toEqual(upper);
    expect(lower).toHaveLength(2);
  });
});
