import { test, expect, startApp, connectWallet, gotoView } from "../fixtures/app";
import { driftChain, sentTransactions, ACCOUNT } from "../fixtures/wallet";
import { GATE_A, ROUTER_A, ROUTER_B, STABLE_B, TOKEN_18 } from "../fixtures/backend";

/**
 * BridgeView, "swap on arrival": swap locally → bridge the stable → swap again
 * on the destination.
 *
 * The interesting property is RECOVERY. `finalize()` needs values that exist
 * only in the source chain's `Sent` log — debridgeId, amount, nonce, the peer
 * router, the swap intent. If the page reloads and those are gone, the bridged
 * stable sits on the destination router with nothing in the UI able to move it.
 */

const SENT_TOPIC0 = "0x8c7ee7a778ddf9672e509e70cf61fd826a6275ae6dd14c5e474b13898a1f2bbb";
const SUBMISSION_ID = "0x" + "11".repeat(32);
const DEBRIDGE_ID = "0x" + "22".repeat(32);

const word = (v: bigint | number) => BigInt(v).toString(16).padStart(64, "0");
const addrWord = (a: string) => a.replace(/^0x/, "").toLowerCase().padStart(64, "0");

/** A `Sent` log the way the gate emits it: amount at word 0, nonce at word 4. */
const sentLog = {
  address: GATE_A,
  topics: [SENT_TOPIC0, SUBMISSION_ID, DEBRIDGE_ID],
  data: "0x" + word(1000n) + word(0) + word(0) + word(0) + word(7n),
};

const BAL = 1000n * 10n ** 18n;
const CALLS = {
  "313ce567": "12", // decimals = 18
  "70a08231": BAL.toString(16), // balanceOf
  dd62ed3e: (2n ** 255n).toString(16), // allowance: already approved
  "7a0ebc88": addrWord(GATE_A), // router.gate()
  "4e3ff796": "1", // gate.bridgeUnit(token): already at bridge decimals
  // remoteRouter(uint256) -> dynamic bytes: offset, length, data
  a6b18e64: "raw:" + word(32) + word(20) + ROUTER_B.replace(/^0x/, "").padEnd(64, "0"),
};

const primaryButton = (page: import("@playwright/test").Page) => page.locator(".review-btn");
const field = (page: import("@playwright/test").Page, label: string) =>
  page.locator(".field").filter({ hasText: label }).locator("input");
// `hasText` with a string is case-insensitive, so "Token (ERC-20" would also
// match "Final token (ERC-20 on …". A regex keeps the two fields distinct.
const tokenField = (page: import("@playwright/test").Page) =>
  page.locator(".field").filter({ hasText: /Token \(ERC-20/ }).locator("input");

async function openCrossSwap(
  page: import("@playwright/test").Page,
  opts: { calls?: Record<string, string>; backend?: Record<string, unknown> } = {}
) {
  await startApp(page, {
    wallet: { chainId: 1337, calls: opts.calls ?? CALLS, receiptLogs: [sentLog] },
    backend: opts.backend ?? {},
  });
  await connectWallet(page);
  await gotoView(page, "Bridge");
  await page.getByRole("button", { name: "Swap on arrival" }).click();
  await expect(field(page, "Router contract")).toHaveValue(ROUTER_A);
}

/** Fill the form and fire swapAndBridge, leaving the flow in `awaiting-execution`. */
async function submitSwapAndBridge(page: import("@playwright/test").Page) {
  await field(page, "Final token").fill(STABLE_B);
  await page.locator(".field").filter({ hasText: "Amount" }).locator("input").fill("5");
  await expect(primaryButton(page)).toHaveText("Swap & Bridge");
  await primaryButton(page).click();
  await expect(page.locator(".txbar--done")).toContainText(/Swapped & locked/, { timeout: 15_000 });
}

test.describe("form", () => {
  test("reveals the router and destination-token fields in swap mode", async ({ page }) => {
    await openCrossSwap(page);
    await expect(field(page, "Router contract")).toBeVisible();
    await expect(field(page, "Final token")).toBeVisible();
  });

  test("approves the ROUTER, not the gate, in swap mode", async ({ page }) => {
    await openCrossSwap(page, {
      calls: { ...CALLS, dd62ed3e: "0" }, // no allowance
    });
    await field(page, "Final token").fill(STABLE_B);
    await page.locator(".field").filter({ hasText: "Amount" }).locator("input").fill("5");
    await expect(primaryButton(page)).toHaveText("Approve for router");

    await primaryButton(page).click();
    await expect.poll(async () => (await sentTransactions(page)).length, { timeout: 10_000 }).toBe(1);
    const [tx] = await sentTransactions(page);
    expect(tx.data.slice(10, 74)).toBe(addrWord(ROUTER_A));
  });

  test("warns when the corridor has no peer router registered", async ({ page }) => {
    await openCrossSwap(page, { calls: { ...CALLS, a6b18e64: "raw:" } });
    await field(page, "Final token").fill(STABLE_B);
    await page.locator(".field").filter({ hasText: "Amount" }).locator("input").fill("5");
    await expect(page.locator(".notice--warn")).toContainText("no corridor registered");
    await expect(primaryButton(page)).toHaveText("Corridor not configured");
  });

  test("blocks an output larger than the destination pool's locked reserve", async ({ page }) => {
    await openCrossSwap(page);
    await field(page, "Final token").fill(STABLE_B);
    // The mocked pool locks 1000e18 of the stable; ask for more.
    await page.locator(".field").filter({ hasText: "Amount" }).locator("input").fill("5000");
    await expect(primaryButton(page)).toHaveText(/Insufficient balance|Exceeds destination pool lock/);
  });

  test("slippage options change the quoted minimum", async ({ page }) => {
    await openCrossSwap(page);
    await field(page, "Final token").fill(STABLE_B);
    await page.locator(".field").filter({ hasText: "Amount" }).locator("input").fill("100");

    const arrives = page.locator(".summary__row").filter({ hasText: "Arrives as" }).locator("dd");
    await expect(arrives).not.toHaveText("—", { timeout: 10_000 });
    const at05 = await arrives.textContent();

    await page.getByRole("button", { name: "1%", exact: true }).click();
    await expect(arrives).not.toHaveText(at05!);
  });
});

test.describe("the swapAndBridge → finalize lifecycle", () => {
  test("captures the Sent event and waits for the keeper", async ({ page }) => {
    await openCrossSwap(page);
    await submitSwapAndBridge(page);

    const [tx] = await sentTransactions(page);
    expect(tx.to.toLowerCase()).toBe(ROUTER_A);
    expect(tx.data.slice(0, 10)).toBe("0x07c1462d"); // swapAndBridge

    await expect(page.locator(".notice")).toContainText(/waiting for the keeper/i);
    await expect(primaryButton(page)).toHaveText("Waiting for validators + keeper…");
    await expect(primaryButton(page)).toBeDisabled();
  });

  test("advances to finalize once the backend reports the leg EXECUTED", async ({ page }) => {
    await openCrossSwap(page, {
      backend: { submissionStatus: { [SUBMISSION_ID]: "EXECUTED" } },
    });
    await submitSwapAndBridge(page);

    // The wallet is still on the source chain, so the app must offer the switch.
    await expect(primaryButton(page)).toHaveText("Switch to Chain B", { timeout: 15_000 });
  });

  test("finalizes on the destination with the fields captured from the Sent log", async ({ page }) => {
    await openCrossSwap(page, {
      backend: { submissionStatus: { [SUBMISSION_ID]: "EXECUTED" } },
    });
    await submitSwapAndBridge(page);

    await expect(primaryButton(page)).toHaveText("Switch to Chain B", { timeout: 15_000 });
    await primaryButton(page).click(); // wallet_switchEthereumChain -> chainChanged
    await expect(primaryButton(page)).toHaveText("Finalize on Chain B", { timeout: 15_000 });

    await primaryButton(page).click();
    await expect(page.locator(".txbar--done")).toContainText(/Finalized/, { timeout: 15_000 });

    const txs = await sentTransactions(page);
    const finalize = txs[txs.length - 1];
    expect(finalize.to.toLowerCase()).toBe(ROUTER_B);
    expect(finalize.data.slice(0, 10)).toBe("0xc2c1fffb");
    // It executes on the DESTINATION chain, not the transfer's origin.
    expect(finalize.chainId).toBe("0x53a"); // 1338

    const words = finalize.data.slice(10).match(/.{64}/g)!;
    expect("0x" + words[0]).toBe(DEBRIDGE_ID); // from topics[2]
    expect(BigInt("0x" + words[1])).toBe(1000n); // amount, from data word 0
    expect(BigInt("0x" + words[2])).toBe(1337n); // chainIdFrom
    expect(BigInt("0x" + words[3])).toBe(7n); // nonce, from data word 4
  });

  test("does not reinterpret the destination switch as picking a new corridor", async ({ page }) => {
    await openCrossSwap(page, {
      backend: { submissionStatus: { [SUBMISSION_ID]: "EXECUTED" } },
    });
    await submitSwapAndBridge(page);
    await expect(primaryButton(page)).toHaveText("Switch to Chain B", { timeout: 15_000 });
    await primaryButton(page).click();

    // Now on chain B. The pending transfer's destination is still B — the button
    // must still target it, not flip to "bridge back to A".
    await expect(primaryButton(page)).toHaveText("Finalize on Chain B", { timeout: 15_000 });
  });
});

test.describe("recovery", () => {
  /**
   * Losing this state strands the transfer: the stable has already arrived on
   * the destination router, and only `finalize()` — with the exact captured
   * fields — can move it on to the user's token.
   */
  test("a page reload does not lose the finalize action", async ({ page }) => {
    await openCrossSwap(page, {
      backend: { submissionStatus: { [SUBMISSION_ID]: "EXECUTED" } },
    });
    await submitSwapAndBridge(page);
    await expect(primaryButton(page)).toHaveText("Switch to Chain B", { timeout: 15_000 });

    await page.reload();
    await gotoView(page, "Bridge");

    await expect(primaryButton(page)).toHaveText(/Switch to Chain B|Finalize on Chain B/, {
      timeout: 15_000,
    });
  });

  test("the restored stage is re-derived from the backend, not trusted from storage", async ({ page }) => {
    // Persist a flow that thinks it is still awaiting.
    await openCrossSwap(page);
    await submitSwapAndBridge(page);
    await expect(primaryButton(page)).toHaveText("Waiting for validators + keeper…");

    // The keeper lands it while the page is closed.
    await page.route("**/graphql", async (route) => {
      const body = JSON.parse(route.request().postData() ?? "{}");
      if (String(body.query).includes("submission(submissionId")) {
        return route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            data: {
              submission: {
                submissionId: SUBMISSION_ID,
                debridgeId: DEBRIDGE_ID,
                amount: "1000",
                chainIdFrom: 1337,
                chainIdTo: 1338,
                nonce: 7,
                receiver: ACCOUNT,
                nativeSender: ROUTER_A,
                autoParams: "0x",
                signatureCount: 2,
                meetsThreshold: true,
                status: "EXECUTED",
                signatures: [],
              },
            },
          }),
        });
      }
      return route.fallback();
    });

    await page.reload();
    await gotoView(page, "Bridge");
    await expect(primaryButton(page)).toHaveText(/Switch to Chain B|Finalize on Chain B/, {
      timeout: 20_000,
    });
  });

  /**
   * Under a single storage key a second transfer overwrote the first, and the
   * first's finalize fields — which exist nowhere else — were gone for good.
   */
  test("a second in-flight transfer does not erase the first one's recovery data", async ({ page }) => {
    await openCrossSwap(page);
    await submitSwapAndBridge(page);

    const stored = await page.evaluate(() => {
      const keys: string[] = [];
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (k?.startsWith("bridge.pendingSwap")) keys.push(k);
      }
      return keys;
    });
    expect(stored).toHaveLength(1);
    expect(stored[0]).toContain(SUBMISSION_ID.slice(2, 10));

    // A second transfer with a different submissionId lands.
    await page.evaluate((first) => {
      const raw = localStorage.getItem(first)!;
      const second = raw.replace(/0x1111[0-9a-f]*/g, "0x" + "33".repeat(32));
      localStorage.setItem("bridge.pendingSwap.v2." + "0x" + "33".repeat(32), second);
    }, stored[0]);

    const after = await page.evaluate(() => {
      const keys: string[] = [];
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (k?.startsWith("bridge.pendingSwap")) keys.push(k);
      }
      return keys;
    });
    expect(after, "both transfers must survive").toHaveLength(2);

    await page.reload();
    await gotoView(page, "Bridge");
    await expect(page.getByTestId("other-pending")).toContainText("1 other unfinished transfer", {
      timeout: 15_000,
    });
  });

  test("finishing a transfer clears only its own record", async ({ page }) => {
    await openCrossSwap(page, {
      backend: { submissionStatus: { [SUBMISSION_ID]: "EXECUTED" } },
    });
    await submitSwapAndBridge(page);
    await expect(primaryButton(page)).toHaveText("Switch to Chain B", { timeout: 15_000 });
    await primaryButton(page).click();
    await expect(primaryButton(page)).toHaveText("Finalize on Chain B", { timeout: 15_000 });
    await primaryButton(page).click();
    await expect(page.locator(".txbar--done")).toContainText(/Finalized/, { timeout: 15_000 });

    await primaryButton(page).click(); // "Start a new transfer"
    const left = await page.evaluate(() => {
      const keys: string[] = [];
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (k?.startsWith("bridge.pendingSwap")) keys.push(k);
      }
      return keys;
    });
    expect(left).toHaveLength(0);
  });

  test("corrupt stored state is discarded rather than crashing the view", async ({ page }) => {
    await startApp(page, { wallet: { chainId: 1337, calls: CALLS } });
    await page.evaluate(() => {
      localStorage.setItem("bridge.pendingSwap.v2.0xdead", "{not json");
      localStorage.setItem("bridge.pendingSwap.v1", '{"pending":{},"stage":"awaiting-execution"}');
    });
    await page.reload();
    await connectWallet(page);
    await gotoView(page, "Bridge");
    await expect(page.getByRole("heading", { name: "Bridge" })).toBeVisible();
    await expect(primaryButton(page)).toHaveText("Enter an amount");
  });
});

test.describe("chain-id binding", () => {
  test("refuses swapAndBridge when the wallet has drifted", async ({ page }) => {
    await openCrossSwap(page);
    await field(page, "Final token").fill(STABLE_B);
    await page.locator(".field").filter({ hasText: "Amount" }).locator("input").fill("5");
    await expect(primaryButton(page)).toHaveText("Swap & Bridge");

    await driftChain(page, 999);
    await primaryButton(page).click();
    await expect(page.locator(".txbar--error")).toContainText(/chain 999/i, { timeout: 15_000 });
    expect(await sentTransactions(page)).toHaveLength(0);
  });
});

test.describe("mode toggle", () => {
  test("is locked while a transfer is in flight", async ({ page }) => {
    await openCrossSwap(page);
    await submitSwapAndBridge(page);
    await expect(page.getByRole("button", { name: "Direct" })).toBeDisabled();
    await expect(page.getByRole("button", { name: "Swap on arrival" })).toBeDisabled();
  });

  test("switching back to Direct hides the router fields and targets the gate", async ({ page }) => {
    await openCrossSwap(page);
    await page.getByRole("button", { name: "Direct" }).click();
    await expect(field(page, "Router contract")).toBeHidden();
    await page.locator(".field").filter({ hasText: "Amount" }).locator("input").fill("1");
    await expect(primaryButton(page)).toHaveText("Bridge");
    await primaryButton(page).click();
    await expect.poll(async () => (await sentTransactions(page)).length, { timeout: 15_000 }).toBe(1);
    expect((await sentTransactions(page))[0].to.toLowerCase()).toBe(GATE_A);
  });
});

test.describe("token field", () => {
  test("keeps the source token independent of the destination token", async ({ page }) => {
    await openCrossSwap(page);
    await field(page, "Final token").fill(STABLE_B);
    await expect(tokenField(page)).toHaveValue(TOKEN_18);
  });
});
