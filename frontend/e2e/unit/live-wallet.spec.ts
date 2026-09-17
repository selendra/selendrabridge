import { test, expect } from "@playwright/test";
import { runCastWithKey, scrubSecret } from "../fixtures/live-wallet";

/**
 * The live suite signs with a real testnet key, passed to `cast` on its command
 * line (cast has no environment variable for it). A failing `execFile` reports
 * the full command — key included — and that error travels into the page and
 * Playwright's output. These pin that it cannot.
 */

// Anvil's first dev key: public, never funded anywhere real.
const KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

test("scrubs the key with and without its 0x prefix", () => {
  const bare = KEY.slice(2);
  const text = `Command failed: cast send 0x1 --private-key ${KEY}\nkey was ${bare}`;
  const out = scrubSecret(text, KEY);
  expect(out).not.toContain(bare);
  expect(out).toContain("<redacted>");
  expect(out).toContain("Command failed: cast send 0x1");
});

test("a failing cast never surfaces the key, and carries none of the original error's fields", async () => {
  const leaky = async () => {
    const e = new Error(`Command failed: cast send 0xabc 0x --private-key ${KEY} --async`) as Error & {
      cmd: string;
      stdout: string;
      stderr: string;
    };
    e.cmd = `cast send 0xabc 0x --private-key ${KEY} --async`;
    e.stdout = "";
    e.stderr = `Error: server returned an error response: insufficient funds (signer ${KEY.slice(2)})`;
    throw e;
  };

  const err = (await runCastWithKey(["send", "0xabc", "0x", "--private-key", KEY], KEY, {}, leaky).catch(
    (e: unknown) => e
  )) as Error & Record<string, unknown>;

  expect(err).toBeInstanceOf(Error);
  expect(err.message).not.toContain(KEY.slice(2));
  // The useful part of the diagnosis survives.
  expect(err.message).toContain("insufficient funds");
  // Nothing else from the original error rides along to be printed.
  expect(err.cmd).toBeUndefined();
  expect(err.stderr).toBeUndefined();
  expect(JSON.stringify(err, Object.getOwnPropertyNames(err))).not.toContain(KEY.slice(2));
});

test("a successful cast is passed through untouched", async () => {
  const ok = async () => ({ stdout: "0x" + "ab".repeat(32) + "\n" });
  const { stdout } = await runCastWithKey(["send"], KEY, {}, ok);
  expect(stdout.trim()).toBe("0x" + "ab".repeat(32));
});
