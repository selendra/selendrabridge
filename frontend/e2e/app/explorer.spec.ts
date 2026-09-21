import { test, expect, startApp, gotoView } from "../fixtures/app";
import { CHAINS } from "../fixtures/backend";

/** Explorer: stats, filters, both tabs, and the submission detail drawer. */

const SUB_A = "0x" + "aa".repeat(32);
const SUB_B = "0x" + "bb".repeat(32);

const submissions = [
  {
    submissionId: SUB_A,
    debridgeId: "0x" + "11".repeat(32),
    amount: "1500000000000000000",
    // An 18/18 asset: the API says so rather than leaving the view to guess.
    bridgeDecimals: 18,
    chainIdFrom: 1337,
    chainIdTo: 1338,
    nonce: 1,
    receiver: "0x" + "ee".repeat(20),
    nativeSender: "0x" + "ff".repeat(20),
    signatureCount: 2,
    meetsThreshold: true,
    status: "READY",
    signatures: [{ signer: "0x" + "01".repeat(20) }, { signer: "0x" + "02".repeat(20) }],
  },
  {
    submissionId: SUB_B,
    debridgeId: "0x" + "22".repeat(32),
    amount: "500000000000000000",
    bridgeDecimals: 18,
    chainIdFrom: 1338,
    chainIdTo: 1337,
    nonce: 2,
    receiver: "0x" + "cc".repeat(20),
    nativeSender: "0x" + "dd".repeat(20),
    signatureCount: 1,
    meetsThreshold: false,
    status: "PENDING",
    signatures: [{ signer: "0x" + "01".repeat(20) }],
  },
];

const stats = { total: 2, signed: 2, ready: 1, threshold: 2, routes: [] };

const swapHistory = [
  {
    chainId: 1337,
    txHash: "0x" + "99".repeat(32),
    sender: "0x" + "70".repeat(20),
    receiver: "0x" + "71".repeat(20),
    tokenIn: "0x" + "aa".repeat(20),
    tokenOut: "0x" + "bb".repeat(20),
    amountIn: "1000000000000000000",
    amountOut: "990000000000000000",
    amountInDecimals: 18,
    amountOutDecimals: 18,
    blockNumber: 12,
    createdAt: "2026-08-01T10:00:00Z",
  },
];

async function openExplorer(page: import("@playwright/test").Page, backend = {}) {
  const world = await startApp(page, { backend: { submissions, stats, ...backend } });
  await gotoView(page, "Explorer");
  await expect(page.getByRole("heading", { name: "Explorer" })).toBeVisible();
  return world;
}

test("shows the store's headline counters", async ({ page }) => {
  await openExplorer(page);
  const grid = page.locator(".stat-grid");
  await expect(grid).toContainText("Total transfers");
  await expect(grid.locator(".stat").filter({ hasText: "Ready to claim" })).toContainText("1");
  await expect(grid.locator(".stat").filter({ hasText: "Threshold" })).toContainText("2-of-N");
});

test("lists every submission with its route, amount, nonce and signature count", async ({ page }) => {
  await openExplorer(page);
  await expect(page.locator(".tbl__row")).toHaveCount(2);

  const first = page.locator(".tbl__row").first();
  await expect(first).toContainText("Chain A");
  await expect(first).toContainText("Chain B");
  await expect(first.locator(".tbl__amount")).toHaveText("1.5");
  await expect(first.locator(".sig-count")).toContainText("2 / 2");
});

/**
 * Seen on the live testnet: the explorer's per-chain decimals lookup sent an EVM
 * `decimals()` eth_call to EVERY registry chain with an rpcUrl — including Solana,
 * whose token is a base58 mint and whose RPC does not speak eth_call. It could
 * only ever fail back to 18, after a request to that endpoint.
 */
test("never sends an EVM decimals() call to a non-EVM chain's RPC", async ({ page }) => {
  const SOLANA_RPC = "http://127.0.0.1:8899";
  const hits: string[] = [];
  await page.route(`${SOLANA_RPC}/**`, (route) => {
    hits.push(route.request().postData() ?? "");
    return route.fulfill({ status: 200, contentType: "application/json", body: '{"jsonrpc":"2.0","id":1,"result":"0x"}' });
  });
  await openExplorer(page, {
    chains: [
      ...CHAINS,
      {
        chainId: 7565164,
        name: "Solana Devnet",
        rpcUrl: SOLANA_RPC,
        gate: "Bvh4JxhWBCFXfc4iu8Cm9PCw86EAH4Yn39pHpzwnQFc1",
        token: "8T2cxAqp8mDNkdTTb5giew9eYgZ7NmHdEWz6kMeE7WFV",
        tokens: [{ symbol: "TST", address: "8T2cxAqp8mDNkdTTb5giew9eYgZ7NmHdEWz6kMeE7WFV" }],
        router: null,
      },
    ],
  });
  await expect(page.locator(".tbl__row").first()).toBeVisible();
  await page.waitForTimeout(1_500); // give the decimals lookup time to (not) fire
  expect(hits.filter((b) => b.includes("eth_call"))).toHaveLength(0);
});

test("formats an amount in the bridge decimals the API reports, not the token's", async ({ page }) => {
  // 2.5 at 6 bridge decimals. Formatted with the source token's 18 decimals it
  // would read as 0.0000000000025.
  await openExplorer(page, {
    submissions: [{ ...submissions[0], amount: "2500000", bridgeDecimals: 6 }],
  });
  await expect(page.locator(".tbl__row").first().locator(".tbl__amount")).toHaveText("2.5");
});

/**
 * M-11. `amount` is a WIRE amount. When the API cannot name its scale
 * (`bridgeDecimals: null` — which `scripts/run.sh` guarantees, since it never
 * emits `bridge_decimals`), the explorer used to format it with the source
 * ERC-20's own decimals, then with 18. A 1,000-token transfer at 6 bridge / 18
 * local decimals rendered as `0`: an operator diagnosing a stuck transfer read
 * a number a trillion times too small, with nothing to say it was a guess.
 */
test("shows raw units rather than a wrong amount when the API cannot name the scale", async ({ page }) => {
  // 1,000 tokens at 6 bridge decimals, on a chain whose token has 18.
  await openExplorer(page, {
    submissions: [{ ...submissions[0], amount: "1000000000", bridgeDecimals: null }],
  });
  const cell = page.locator(".tbl__row").first().locator('[data-testid="submission-amount"]');
  // Not "0", and not 1000 either — nothing here can honestly place the point.
  await expect(cell).toHaveText("1000000000");
  await expect(cell).toHaveClass(/tbl__amount--raw/);
  await expect(cell).toHaveAttribute("title", /bridge decimals are unknown/i);
});

test("the detail drawer marks an unscaled amount too", async ({ page }) => {
  await openExplorer(page, {
    submissions: [{ ...submissions[0], amount: "1000000000", bridgeDecimals: null }],
    submissionStatus: { [SUB_A.toLowerCase()]: "READY" },
  });
  await page.locator(".tbl__row").first().click();
  await expect(page.locator('[data-testid="detail-amount"]')).toHaveText("1000");
  await expect(page.locator(".drawer")).toContainText("(raw units)");
});

test("renders the lifecycle status per row", async ({ page }) => {
  await openExplorer(page);
  await expect(page.locator(".tbl__row").first()).toContainText(/Ready/i);
  await expect(page.locator(".tbl__row").last()).toContainText(/Pending/i);
});

test("filters by source chain", async ({ page }) => {
  const { backend } = await openExplorer(page);
  await page.locator(".filters__field").first().locator(".dd__trigger").click();
  await page.getByRole("option", { name: "Chain A" }).click();
  await expect
    .poll(() => backend.queries.some((q) => q.includes("submissions(filter")))
    .toBe(true);
  await expect(page.locator(".filters__field").first().locator(".dd__label")).toHaveText("Chain A");
});

test("filters by destination chain", async ({ page }) => {
  await openExplorer(page);
  await page.locator(".filters__field").nth(1).locator(".dd__trigger").click();
  await page.getByRole("option", { name: "Chain B" }).click();
  await expect(page.locator(".filters__field").nth(1).locator(".dd__label")).toHaveText("Chain B");
});

test("toggles the ready-only filter", async ({ page }) => {
  await openExplorer(page);
  const chip = page.getByRole("button", { name: "Ready only" });
  await chip.click();
  await expect(chip).toHaveClass(/chip-toggle--on/);
  await chip.click();
  await expect(chip).not.toHaveClass(/chip-toggle--on/);
});

test("searches by submission id, client-side", async ({ page }) => {
  await openExplorer(page);
  await page.getByPlaceholder("Search id or receiver…").fill("aaaaaa");
  await expect(page.locator(".tbl__row")).toHaveCount(1);
  await expect(page.locator(".tbl__row")).toContainText("0x" + "aa".repeat(4));
});

test("searches by receiver", async ({ page }) => {
  await openExplorer(page);
  await page.getByPlaceholder("Search id or receiver…").fill("cccccc");
  await expect(page.locator(".tbl__row")).toHaveCount(1);
});

test("says so when nothing matches", async ({ page }) => {
  await openExplorer(page);
  await page.getByPlaceholder("Search id or receiver…").fill("no-such-thing");
  await expect(page.locator(".tbl__empty")).toContainText("No transfers match these filters");
});

test("refresh re-queries the backend", async ({ page }) => {
  const { backend } = await openExplorer(page);
  const before = backend.queries.length;
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect.poll(() => backend.queries.length).toBeGreaterThan(before);
});

test("switches to the same-chain swaps tab", async ({ page }) => {
  await openExplorer(page, { swapHistory });
  await page.getByRole("button", { name: "Same-chain swaps" }).click();
  await expect(page.locator(".tbl")).toContainText("Amount in");
  await expect(page.locator(".tbl tbody tr").first()).toContainText("Chain A");
});

/** A backend too old to serve `amountInDecimals`/`amountOutDecimals` answers the
 *  swaps query with a GraphQL error. That used to be swallowed into `[]`, so the
 *  tab said "No same-chain swaps recorded yet" — a claim about the CHAIN, made on
 *  the strength of a failed request. The deployment order (API before UI) is a
 *  real constraint, so getting it wrong has to be legible. */
test("an API error in the swaps tab is reported, not shown as an empty chain", async ({ page }) => {
  await openExplorer(page, {
    swapHistoryError: 'Unknown field "amountInDecimals" on type "SwapHistoryEntry".',
  });
  await page.getByRole("button", { name: "Same-chain swaps" }).click();
  const empty = page.locator(".tbl__empty");
  await expect(empty).toContainText("Couldn’t load swaps");
  await expect(empty).toContainText("amountInDecimals");
  await expect(empty).not.toContainText("No same-chain swaps recorded yet");
});

test("the swaps tab bounds its query with integer literals", async ({ page }) => {
  const { backend } = await openExplorer(page, { swapHistory });
  await page.getByRole("button", { name: "Same-chain swaps" }).click();
  await expect.poll(() => backend.queries.some((q) => q.includes("swapHistory("))).toBe(true);
  for (const q of backend.queries.filter((q) => q.includes("swapHistory("))) {
    // Only `chainId: <digits>` and `limit: <digits>` may appear.
    expect(q).toMatch(/swapHistory\((chainId: \d+(, )?)?(limit: \d+)?\)/);
  }
});

/**
 * The same class as M-11, one level down: a swap crosses TWO tokens, so
 * `amountIn` and `amountOut` are in different scales. Both used to be formatted
 * with `decimalsByChain[sw.chainId]` — the chain's DEFAULT token's decimals —
 * which is right only when the pool happens to trade that token against another
 * of equal width. A 1 WETH -> 3,180 USDC trade (18 in, 6 out) showed the output
 * as 0.00000000000000318.
 */
test("scales each side of a swap by its own token, not the chain's default", async ({ page }) => {
  await openExplorer(page, {
    swapHistory: [
      {
        ...swapHistory[0],
        amountIn: "1000000000000000000", // 1 WETH, 18dp
        amountInDecimals: 18,
        amountOut: "3180000000", // 3,180 USDC, 6dp
        amountOutDecimals: 6,
      },
    ],
  });
  await page.getByRole("button", { name: "Same-chain swaps" }).click();
  await expect(page.locator('[data-testid="swap-amount-in"]')).toHaveText("1");
  await expect(page.locator('[data-testid="swap-amount-out"]')).toHaveText("3,180");
});

test("a swap whose token decimals the API could not read shows raw units", async ({ page }) => {
  await openExplorer(page, {
    swapHistory: [
      { ...swapHistory[0], amountOut: "3180000000", amountOutDecimals: null },
    ],
  });
  await page.getByRole("button", { name: "Same-chain swaps" }).click();
  const out = page.locator('[data-testid="swap-amount-out"]');
  await expect(out).toHaveText("3180000000");
  await expect(out).toHaveClass(/tbl__amount--raw/);
  await expect(out).toHaveAttribute("title", /this token's decimals are unknown/i);
});

test("an empty swaps tab says so rather than showing a blank table", async ({ page }) => {
  await openExplorer(page);
  await page.getByRole("button", { name: "Same-chain swaps" }).click();
  await expect(page.locator(".tbl__empty")).toContainText("No same-chain swaps recorded yet");
});

test.describe("submission detail", () => {
  test("opens a drawer with the full transfer record", async ({ page }) => {
    await openExplorer(page, { submissionStatus: { [SUB_A]: "READY" } });
    await page.locator(".tbl__row").first().click();

    const drawer = page.getByRole("dialog", { name: "Submission detail" });
    await expect(drawer).toBeVisible();
    await expect(drawer).toContainText("Chain A");
    await expect(drawer).toContainText("Chain B");
    await expect(drawer.locator(".detail__row").filter({ hasText: "Nonce" })).toContainText("1");
  });

  test("closes on the close button", async ({ page }) => {
    await openExplorer(page, { submissionStatus: { [SUB_A]: "READY" } });
    await page.locator(".tbl__row").first().click();
    await page.getByRole("button", { name: "Close" }).click();
    await expect(page.getByRole("dialog")).toBeHidden();
  });

  test("closes on Escape", async ({ page }) => {
    await openExplorer(page, { submissionStatus: { [SUB_A]: "READY" } });
    await page.locator(".tbl__row").first().click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(page.getByRole("dialog")).toBeHidden();
  });

  test("closes on a scrim click", async ({ page }) => {
    await openExplorer(page, { submissionStatus: { [SUB_A]: "READY" } });
    await page.locator(".tbl__row").first().click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await page.locator(".drawer-scrim").click({ position: { x: 5, y: 5 } });
    await expect(page.getByRole("dialog")).toBeHidden();
  });

  test("shows a threshold-met badge when the quorum exists", async ({ page }) => {
    await openExplorer(page, { submissionStatus: { [SUB_A]: "READY" } });
    await page.locator(".tbl__row").first().click();
    await expect(page.locator(".sig-count__badge")).toContainText("threshold met");
  });

  /** An empty drawer is indistinguishable from one still loading — say what
   *  happened instead. */
  test("reports an unknown submission instead of rendering a blank drawer", async ({ page }) => {
    // No `submissionStatus` entry => the API returns null.
    await openExplorer(page);
    await page.locator(".tbl__row").first().click();
    const drawer = page.getByRole("dialog", { name: "Submission detail" });
    await expect(drawer).toBeVisible();
    await expect(drawer).toContainText(/no record of this submission/i);
  });
});

test("surfaces a backend failure rather than showing an empty table as if it were data", async ({ page }) => {
  await startApp(page, { backend: {} });
  await page.route("**/graphql", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ errors: [{ message: "connection refused" }] }),
    })
  );
  await gotoView(page, "Explorer");
  await expect(page.locator(".notice--error")).toContainText("connection refused", {
    timeout: 15_000,
  });
});
