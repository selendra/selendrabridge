import { test, expect, startApp, connectWallet, gotoView } from "../fixtures/app";
import { driftChain, sentTransactions, walletCalls, ACCOUNT } from "../fixtures/wallet";
import { GATE_A, GATE_B, TOKEN_18, TOKEN_6 } from "../fixtures/backend";

/**
 * BridgeView, direct mode: the lock-and-emit path.
 *
 * Every assertion that matters here is about the CALLDATA, not the pixels — the
 * UI's job is to turn a typed amount and address into the right bytes on the
 * right chain, and that is the part a user cannot check.
 */

const BAL = 1000n * 10n ** 18n;
// bridgeUnit(token) = 1: the token is already at its bridge decimals.
const DEC_18 = { "313ce567": "12", "70a08231": BAL.toString(16), "dd62ed3e": "0", "4e3ff796": "1" };
const APPROVED = { ...DEC_18, dd62ed3e: (2n ** 255n).toString(16) };

const SENT_TOPIC0 = "0x8c7ee7a778ddf9672e509e70cf61fd826a6275ae6dd14c5e474b13898a1f2bbb";
const word = (v: bigint | number) => BigInt(v).toString(16).padStart(64, "0");
/** What a real gate's `send` leaves in the receipt — the only proof funds locked. */
const SENT_LOG = {
  address: GATE_A,
  topics: [SENT_TOPIC0, "0x" + "11".repeat(32), "0x" + "22".repeat(32)],
  data: "0x" + word(10n ** 18n) + word(0) + word(0) + word(0) + word(0),
};

const primaryButton = (page: import("@playwright/test").Page) => page.locator(".review-btn");
const field = (page: import("@playwright/test").Page, label: string) =>
  page.locator(".field").filter({ hasText: label }).locator("input");
// `hasText` with a string is case-insensitive, so "Token (ERC-20" would also
// match "Final token (ERC-20 on …". A regex keeps the two fields distinct.
const tokenField = (page: import("@playwright/test").Page) =>
  page.locator(".field").filter({ hasText: /Token \(ERC-20/ }).locator("input");

async function openBridge(
  page: import("@playwright/test").Page,
  calls: Record<string, string> = APPROVED,
  extra: Record<string, unknown> = {}
) {
  await startApp(page, { wallet: { chainId: 1337, calls, receiptLogs: [SENT_LOG], ...extra } });
  await connectWallet(page);
  await gotoView(page, "Bridge");
  await expect(page.getByRole("heading", { name: "Bridge" })).toBeVisible();
}

test.describe("form state", () => {
  test("prefills the gate and primary token from the registry for the connected chain", async ({ page }) => {
    await openBridge(page);
    await expect(field(page, "Gate contract")).toHaveValue(GATE_A);
    await expect(tokenField(page)).toHaveValue(TOKEN_18);
  });

  test("re-targets the gate to the new chain when the wallet switches", async ({ page }) => {
    await openBridge(page);
    await expect(field(page, "Gate contract")).toHaveValue(GATE_A);
    await page.evaluate(() =>
      (window as unknown as { ethereum: { request(a: unknown): Promise<unknown> } }).ethereum.request({
        method: "wallet_switchEthereumChain",
        params: [{ chainId: "0x53a" }],
      })
    );
    await expect(page.locator(".bridge-route__node").first()).toContainText("Chain B");
    // Chain A's gate address means nothing on chain B.
    await expect(field(page, "Gate contract")).toHaveValue(GATE_B);
  });

  test("defaults the receiver to the connected account", async ({ page }) => {
    await openBridge(page);
    await expect(field(page, "Receiver")).toHaveValue(ACCOUNT);
  });

  test("defaults the destination to a chain that is not the source", async ({ page }) => {
    await openBridge(page);
    await expect(page.locator(".bridge-route").locator(".dd__label")).toHaveText("Chain B");
  });

  test("shows the source chain as the connected wallet's chain", async ({ page }) => {
    await openBridge(page);
    await expect(page.locator(".bridge-route__node").first()).toContainText("Chain A");
  });

  test("only accepts decimal input in the amount field", async ({ page }) => {
    await openBridge(page);
    const amount = page.locator(".field").filter({ hasText: "Amount" }).locator("input");
    await amount.fill("12.5");
    await expect(amount).toHaveValue("12.5");
    await amount.fill("");
    await amount.pressSequentially("abc");
    await expect(amount).toHaveValue("");
  });

  test("Max fills the full balance at the token's real decimals", async ({ page }) => {
    await openBridge(page);
    await page.getByRole("button", { name: /^Max/ }).click();
    // decimals() returns 0x12 = 18, so 1000 * 10^18 renders as "1000".
    await expect(page.locator(".field").filter({ hasText: "Amount" }).locator("input")).toHaveValue("1000");
  });
});

test.describe("validation gates the primary button", () => {
  test("refuses a malformed token address", async ({ page }) => {
    await openBridge(page);
    await tokenField(page).fill("0x123");
    await expect(primaryButton(page)).toHaveText("Enter a token address");
    await expect(primaryButton(page)).toBeDisabled();
  });

  test("refuses a malformed gate address", async ({ page }) => {
    await openBridge(page);
    await field(page, "Gate contract").fill("nope");
    await expect(primaryButton(page)).toHaveText("Enter the Gate address");
  });

  test("names the problem when a Solana key is typed for an EVM destination", async ({ page }) => {
    await openBridge(page);
    await field(page, "Receiver").fill("SysvarC1ock11111111111111111111111111111111");
    await expect(primaryButton(page)).toContainText("Solana key");
  });

  test("refuses an empty amount", async ({ page }) => {
    await openBridge(page);
    await expect(primaryButton(page)).toHaveText("Enter an amount");
  });

  test("refuses more than the balance", async ({ page }) => {
    await openBridge(page);
    await page.locator(".field").filter({ hasText: "Amount" }).locator("input").fill("100000");
    await expect(primaryButton(page)).toHaveText("Insufficient balance");
  });
});

test.describe("approve → bridge", () => {
  test("asks for an approval first when the allowance is short", async ({ page }) => {
    await openBridge(page, DEC_18); // allowance 0
    await page.locator(".field").filter({ hasText: "Amount" }).locator("input").fill("10");
    await expect(primaryButton(page)).toHaveText("Approve token");

    await primaryButton(page).click();

    await expect
      .poll(async () => (await sentTransactions(page)).length, { timeout: 10_000 })
      .toBe(1);
    const [tx] = await sentTransactions(page);
    expect(tx.to.toLowerCase()).toBe(TOKEN_18);
    expect(tx.data.slice(0, 10)).toBe("0x095ea7b3"); // approve
    // The spender is the gate, and the amount is exactly what was typed.
    expect(tx.data.slice(10, 74)).toBe(GATE_A.slice(2).padStart(64, "0"));
    expect(BigInt("0x" + tx.data.slice(74, 138))).toBe(10n * 10n ** 18n);
  });

  test("sends the bridge transaction with the exact typed amount and receiver", async ({ page }) => {
    await openBridge(page);
    const receiver = "0x" + "ee".repeat(20);
    await field(page, "Receiver").fill(receiver);
    await page.locator(".field").filter({ hasText: "Amount" }).locator("input").fill("2.5");
    await expect(primaryButton(page)).toHaveText("Bridge");

    await primaryButton(page).click();
    await expect(page.locator(".txbar--done")).toContainText(/Locked/, { timeout: 15_000 });

    const [tx] = await sentTransactions(page);
    expect(tx.to.toLowerCase()).toBe(GATE_A);
    expect(tx.data.slice(0, 10)).toBe("0x565443e9"); // send(...)

    const words = tx.data.slice(10).match(/.{64}/g)!;
    expect(words[0]).toBe(TOKEN_18.slice(2).padStart(64, "0"));
    expect(BigInt("0x" + words[1])).toBe(2_500_000_000_000_000_000n); // 2.5 @ 18dp
    expect(BigInt("0x" + words[2])).toBe(1338n); // chainIdTo
    const offReceiver = Number(BigInt("0x" + words[3])) / 32;
    expect(BigInt("0x" + words[offReceiver])).toBe(20n);
    expect(words[offReceiver + 1].slice(0, 40)).toBe(receiver.slice(2));
  });

  test("clears the amount and reports success after a mined send", async ({ page }) => {
    await openBridge(page);
    await page.locator(".field").filter({ hasText: "Amount" }).locator("input").fill("1");
    await primaryButton(page).click();
    await expect(page.locator(".txbar--done")).toContainText(/Locked/, { timeout: 15_000 });
    await expect(page.locator(".field").filter({ hasText: "Amount" }).locator("input")).toHaveValue("");
  });

  test("offers a jump to the Explorer for the corridor just used", async ({ page }) => {
    await openBridge(page);
    await page.locator(".field").filter({ hasText: "Amount" }).locator("input").fill("1");
    await primaryButton(page).click();
    const review = page.getByRole("button", { name: /Track this transfer/ });
    await expect(review).toBeVisible({ timeout: 15_000 });
    await review.click();
    await expect(page.getByRole("heading", { name: "Explorer" })).toBeVisible();
  });

  test("reports a mined revert as an error rather than success", async ({ page }) => {
    await openBridge(page, APPROVED, { receiptStatus: "0x0" });
    await page.locator(".field").filter({ hasText: "Amount" }).locator("input").fill("1");
    await primaryButton(page).click();
    await expect(page.locator(".txbar--error")).toContainText(/reverted/i, { timeout: 15_000 });
  });

  test("a mined send with no Sent event from the gate is an error, not a lock", async ({ page }) => {
    // What a send to a wrong/stale gate address looks like: a call to an address
    // with no code succeeds, emits nothing, and locks nothing.
    await openBridge(page, APPROVED, { receiptLogs: [] });
    await page.locator(".field").filter({ hasText: "Amount" }).locator("input").fill("1");
    await primaryButton(page).click();
    await expect(page.locator(".txbar--error")).toContainText(/no Sent event/, { timeout: 15_000 });
    await expect(page.locator(".txbar--done")).toHaveCount(0);
  });

  test("reports a wallet rejection in plain language", async ({ page }) => {
    await openBridge(page, APPROVED, { rejectSend: true });
    await page.locator(".field").filter({ hasText: "Amount" }).locator("input").fill("1");
    await primaryButton(page).click();
    await expect(page.locator(".txbar--error")).toContainText("Rejected in wallet", { timeout: 15_000 });
  });
});

test.describe("bridge decimals", () => {
  // An 18-decimal token bridged at 6 decimals: the gate's unit is 10^12.
  const UNIT_1E12 = { ...APPROVED, "4e3ff796": (10n ** 12n).toString(16) };

  test("refuses precision the bridge cannot carry, before any transaction", async ({ page }) => {
    await openBridge(page, UNIT_1E12);
    await page.locator(".field").filter({ hasText: "Amount" }).locator("input").fill("1.0000001");
    await expect(primaryButton(page)).toHaveText("Too precise — this asset bridges at most 6 decimals");
    await expect(primaryButton(page)).toBeDisabled();
    expect(await sentTransactions(page)).toHaveLength(0);
  });

  test("accepts an amount that is a whole number of bridge units", async ({ page }) => {
    await openBridge(page, UNIT_1E12);
    await page.locator(".field").filter({ hasText: "Amount" }).locator("input").fill("1.000001");
    await expect(primaryButton(page)).toHaveText("Bridge");
  });

  test("Max rounds the balance down to a whole bridge unit", async ({ page }) => {
    const dusty = 1000n * 10n ** 18n + 123n; // 1000 TST and 123 wei of dust
    await openBridge(page, { ...UNIT_1E12, "70a08231": dusty.toString(16) });
    await page.getByRole("button", { name: /^Max/ }).click();
    await expect(page.locator(".field").filter({ hasText: "Amount" }).locator("input")).toHaveValue("1000");
    await expect(primaryButton(page)).toHaveText("Bridge");
  });

  test("says so when the gate cannot bridge the token at all", async ({ page }) => {
    // bridgeUnit(token) reverting reads back as 0 from the mock.
    await openBridge(page, { ...APPROVED, "4e3ff796": "0" });
    await page.locator(".field").filter({ hasText: "Amount" }).locator("input").fill("1");
    await expect(primaryButton(page)).toHaveText("This token isn't bridgeable through this Gate");
  });
});

test.describe("token switching", () => {
  /**
   * The regression: `decimals` is read asynchronously and used to scale the
   * amount. Holding the PREVIOUS token's value while a new read is in flight
   * lets a submit encode 10^(oldDec-newDec) times the intended amount — from an
   * 18-decimal token to a 6-decimal one, a million-fold overpayment.
   */
  test("will not submit while the token's decimals are still being read", async ({ page }) => {
    await openBridge(page);
    await page.locator(".field").filter({ hasText: "Amount" }).locator("input").fill("10");
    await expect(primaryButton(page)).toHaveText("Bridge");

    // Stall the next eth_call so the read cannot complete.
    await page.evaluate(() => {
      const p = (window as unknown as {
        ethereum: { request: (a: { method: string }) => Promise<unknown> };
      }).ethereum;
      const original = p.request.bind(p);
      p.request = async (args: { method: string }) => {
        if (args.method === "eth_call") return new Promise(() => {}); // never resolves
        return original(args);
      };
    });

    await tokenField(page).fill(TOKEN_6);

    // No trustworthy decimals => the button must refuse, not encode with stale ones.
    await expect(primaryButton(page)).toHaveText("Reading token…");
    await expect(primaryButton(page)).toBeDisabled();
  });

  test("re-reads balance and allowance for the newly selected token", async ({ page }) => {
    await openBridge(page);
    const before = (await walletCalls(page)).filter((c) => c.method === "eth_call").length;
    await tokenField(page).fill(TOKEN_6);
    await expect
      .poll(async () => (await walletCalls(page)).filter((c) => c.method === "eth_call").length)
      .toBeGreaterThan(before);
  });

  test("the token dropdown does not claim a selection the form does not hold", async ({ page }) => {
    await openBridge(page);
    // A custom address that is in neither registry entry.
    await tokenField(page).fill("0x" + "9".repeat(40));
    await expect(page.locator(".token-picker .dd__label")).toHaveText("Custom address");
  });

  test("picking a registry token from the dropdown fills the address field", async ({ page }) => {
    await openBridge(page);
    await page.locator(".token-picker .dd__trigger").click();
    await page.getByRole("option", { name: /USDC/ }).click();
    await expect(tokenField(page)).toHaveValue(TOKEN_6);
  });
});

test.describe("chain-id binding", () => {
  /**
   * The UI's `chainId` comes from a `chainChanged` event and can lag the wallet.
   * Contract addresses are not chain-scoped, so a write that lands on the wrong
   * chain silently targets a different contract. Both writes must refuse.
   */
  test("refuses to send when the wallet has drifted to another chain", async ({ page }) => {
    await openBridge(page);
    await page.locator(".field").filter({ hasText: "Amount" }).locator("input").fill("1");
    await expect(primaryButton(page)).toHaveText("Bridge");

    // The wallet moves; the UI never hears about it.
    await driftChain(page, 999);
    await primaryButton(page).click();

    await expect(page.locator(".txbar--error")).toContainText(/chain 999/i, { timeout: 15_000 });
    expect(await sentTransactions(page)).toHaveLength(0);
  });

  test("refuses to approve when the wallet has drifted to another chain", async ({ page }) => {
    await openBridge(page, DEC_18);
    await page.locator(".field").filter({ hasText: "Amount" }).locator("input").fill("1");
    await expect(primaryButton(page)).toHaveText("Approve token");

    await driftChain(page, 999);
    await primaryButton(page).click();

    await expect(page.locator(".txbar--error")).toContainText(/Switch networks/i, { timeout: 15_000 });
    expect(await sentTransactions(page)).toHaveLength(0);
  });

  test("stamps the intended chain id into the transaction it does send", async ({ page }) => {
    await openBridge(page);
    await page.locator(".field").filter({ hasText: "Amount" }).locator("input").fill("1");
    await primaryButton(page).click();
    await expect
      .poll(async () => (await sentTransactions(page)).length, { timeout: 15_000 })
      .toBe(1);
    expect((await sentTransactions(page))[0].chainId).toBe("0x539"); // 1337
  });
});
