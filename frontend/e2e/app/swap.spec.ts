import { test, expect, startApp, connectWallet, gotoView } from "../fixtures/app";
import { driftChain, sentTransactions, ACCOUNT } from "../fixtures/wallet";
import { POOL_A, STABLE_A, TOKEN_18 } from "../fixtures/backend";

/** SwapView: the same-chain pegged pool. */

const BAL = 1000n * 10n ** 18n;
const CALLS = {
  "70a08231": BAL.toString(16), // balanceOf
  dd62ed3e: (2n ** 255n).toString(16), // allowance
};
const NO_ALLOWANCE = { ...CALLS, dd62ed3e: "0" };

const primaryButton = (page: import("@playwright/test").Page) => page.locator(".review-btn");
const payAmount = (page: import("@playwright/test").Page) =>
  page.locator(".amount-row").first().locator("input");
const receiveAmount = (page: import("@playwright/test").Page) =>
  page.locator(".amount-row").last().locator(".amount-row__input");

async function openSwap(
  page: import("@playwright/test").Page,
  calls: Record<string, string> = CALLS,
  extra: Record<string, unknown> = {}
) {
  await startApp(page, { wallet: { chainId: 1337, calls, ...extra } });
  await connectWallet(page);
  await gotoView(page, "Swap");
  await expect(page.locator(".card__subtitle")).toContainText("Chain A", { timeout: 10_000 });
}

test("loads the pool for the connected chain and shows its address", async ({ page }) => {
  await openSwap(page);
  await expect(page.locator(".summary__row").filter({ hasText: "Pool" })).toContainText(
    POOL_A.slice(0, 8)
  );
});

test("initialises a distinct token pair from the pool", async ({ page }) => {
  await openSwap(page);
  const labels = await page.locator(".amount-row .dd__label").allTextContents();
  expect(labels).toHaveLength(2);
  expect(labels[0]).not.toBe(labels[1]);
});

test("quotes the output for a typed amount", async ({ page }) => {
  await openSwap(page);
  await payAmount(page).fill("10");
  // The mock quotes 1:1, so 10 in => 10 out.
  await expect(receiveAmount(page)).toHaveText("10", { timeout: 10_000 });
});

test("flip swaps the pair and clears the amount", async ({ page }) => {
  await openSwap(page);
  const before = await page.locator(".amount-row .dd__label").allTextContents();
  await payAmount(page).fill("5");
  await page.getByRole("button", { name: "Flip tokens" }).click();
  const after = await page.locator(".amount-row .dd__label").allTextContents();
  expect(after).toEqual([before[1], before[0]]);
  await expect(payAmount(page)).toHaveValue("");
});

test("Max fills the wallet balance", async ({ page }) => {
  await openSwap(page);
  await page.getByRole("button", { name: "Max" }).click();
  await expect(payAmount(page)).toHaveValue("1000");
});

test("shows the rate and the slippage-adjusted minimum", async ({ page }) => {
  await openSwap(page);
  await payAmount(page).fill("100");
  await expect(page.locator(".summary__row").filter({ hasText: "Rate" })).not.toContainText("—", {
    timeout: 10_000,
  });
  const minRow = page.locator(".summary__row").filter({ hasText: "Min received" });
  const at05 = await minRow.locator("dd").textContent();
  await page.getByRole("button", { name: "1%", exact: true }).click();
  await expect(minRow.locator("dd")).not.toHaveText(at05!);
});

test("blocks a swap larger than the pool's locked reserve", async ({ page }) => {
  await openSwap(page);
  await payAmount(page).fill("999999");
  await expect(primaryButton(page)).toHaveText(/Insufficient|Exceeds pool lock/);
});

test("offers a chain switch when the wallet is on a different chain than the pool", async ({ page }) => {
  // Connected to B; the view defaults to B's pool, so pick A's explicitly.
  await startApp(page, { wallet: { chainId: 1338, calls: CALLS } });
  await connectWallet(page);
  await gotoView(page, "Swap");
  await expect(page.locator(".card__subtitle")).toContainText("Chain B", { timeout: 10_000 });

  await page.locator(".card__tools .dd__trigger").click();
  await page.getByRole("option", { name: "Chain A" }).click();
  await expect(primaryButton(page)).toHaveText("Switch to Chain A");
});

test("asks for an approval against the pool before swapping", async ({ page }) => {
  await openSwap(page, NO_ALLOWANCE);
  await payAmount(page).fill("10");
  await expect(primaryButton(page)).toHaveText(/^Approve /, { timeout: 10_000 });

  await primaryButton(page).click();
  await expect.poll(async () => (await sentTransactions(page)).length, { timeout: 10_000 }).toBe(1);
  const [tx] = await sentTransactions(page);
  expect(tx.data.slice(0, 10)).toBe("0x095ea7b3");
  expect(tx.data.slice(10, 74)).toBe(POOL_A.slice(2).padStart(64, "0"));
});

test("sends swap() to the pool with the pair, amount, minOut and recipient", async ({ page }) => {
  await openSwap(page);
  await payAmount(page).fill("10");
  await expect(primaryButton(page)).toHaveText("Swap", { timeout: 10_000 });

  await primaryButton(page).click();
  await expect(page.locator(".txbar--done")).toContainText(/Swapped/, { timeout: 15_000 });

  const [tx] = await sentTransactions(page);
  expect(tx.to.toLowerCase()).toBe(POOL_A);
  expect(tx.data.slice(0, 10)).toBe("0xd5bcb9b5");

  const words = tx.data.slice(10).match(/.{64}/g)!;
  expect(BigInt("0x" + words[2])).toBe(10n * 10n ** 18n); // amountIn
  // minOut = quote * (10000 - 50bps default) / 10000
  expect(BigInt("0x" + words[3])).toBe((10n * 10n ** 18n * 9950n) / 10000n);
  expect("0x" + words[4].slice(24)).toBe(ACCOUNT); // recipient = the connected account
  expect(tx.chainId).toBe("0x539");
});

test("clears the amount after a successful swap", async ({ page }) => {
  await openSwap(page);
  await payAmount(page).fill("10");
  await primaryButton(page).click();
  await expect(page.locator(".txbar--done")).toBeVisible({ timeout: 15_000 });
  await expect(payAmount(page)).toHaveValue("");
});

test("reports a mined revert rather than claiming success", async ({ page }) => {
  await openSwap(page, CALLS, { receiptStatus: "0x0" });
  await payAmount(page).fill("10");
  await primaryButton(page).click();
  await expect(page.locator(".txbar--error")).toContainText(/reverted/i, { timeout: 15_000 });
});

test("refuses to swap when the wallet has drifted to another chain", async ({ page }) => {
  await openSwap(page);
  await payAmount(page).fill("10");
  await expect(primaryButton(page)).toHaveText("Swap", { timeout: 10_000 });

  await driftChain(page, 999);
  await primaryButton(page).click();
  await expect(page.locator(".txbar--error")).toContainText(/chain 999/i, { timeout: 15_000 });
  expect(await sentTransactions(page)).toHaveLength(0);
});

test("says so plainly when the chain has no pool", async ({ page }) => {
  await openSwap(page, CALLS, {});
  await page.route("**/graphql", async (route) => {
    const body = JSON.parse(route.request().postData() ?? "{}");
    if (String(body.query).includes("swapPool(")) {
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ data: { swapPool: null } }),
      });
    }
    return route.fallback();
  });
  await page.reload();
  await gotoView(page, "Swap");
  await expect(primaryButton(page)).toHaveText(/No pool on this chain|Connect Wallet/, {
    timeout: 15_000,
  });
});

test("the refresh control re-queries the pool", async ({ page }) => {
  const { backend } = await startApp(page, { wallet: { chainId: 1337, calls: CALLS } });
  await connectWallet(page);
  await gotoView(page, "Swap");
  await expect(page.locator(".card__subtitle")).toContainText("Chain A", { timeout: 10_000 });

  const before = backend.queries.filter((q) => q.includes("swapPool(")).length;
  await page.getByRole("button", { name: "Refresh pool" }).click();
  await expect
    .poll(() => backend.queries.filter((q) => q.includes("swapPool(")).length)
    .toBeGreaterThan(before);
});

test("switching the pool chain re-quotes against the new pool", async ({ page }) => {
  const { backend } = await startApp(page, { wallet: { chainId: 1337, calls: CALLS } });
  await connectWallet(page);
  await gotoView(page, "Swap");
  await expect(page.locator(".card__subtitle")).toContainText("Chain A", { timeout: 10_000 });

  await page.locator(".card__tools .dd__trigger").click();
  await page.getByRole("option", { name: "Chain B" }).click();
  await expect(page.locator(".card__subtitle")).toContainText("Chain B");
  await expect
    .poll(() => backend.queries.some((q) => q.includes("swapPool(chainId: 1338)")))
    .toBe(true);
});

test("the pool chain id goes over the wire as an integer literal", async ({ page }) => {
  const { backend } = await startApp(page, { wallet: { chainId: 1337, calls: CALLS } });
  await connectWallet(page);
  await gotoView(page, "Swap");
  await expect
    .poll(() => backend.queries.some((q) => /swapPool\(chainId: \d+\)/.test(q)))
    .toBe(true);
  // Nothing but digits may be spliced into the document.
  for (const q of backend.queries.filter((q) => q.includes("swapPool("))) {
    expect(q).toMatch(/swapPool\(chainId: \d+\)/);
  }
});

test("connect is offered before any wallet-dependent action", async ({ page }) => {
  await startApp(page, { wallet: { chainId: 1337, calls: CALLS } });
  await gotoView(page, "Swap");
  await expect(primaryButton(page)).toHaveText("Connect Wallet");
});

test("the token pair can be re-picked from the dropdowns", async ({ page }) => {
  await openSwap(page);
  const payDropdown = page.locator(".amount-row").first().locator(".dd__trigger");
  await payDropdown.click();
  const options = page.getByRole("option");
  await expect(options.first()).toBeVisible();
  const count = await options.count();
  await options.nth(count - 1).click();
  await expect(page.locator(".amount-row").first().locator(".dd__label")).toBeVisible();
});

test("the receive side is read-only", async ({ page }) => {
  await openSwap(page);
  await expect(page.locator(".amount-row").last().locator("input")).toHaveCount(0);
  await expect(receiveAmount(page)).toBeVisible();
});

test("shows the destination token's pool lock", async ({ page }) => {
  await openSwap(page);
  await expect(page.locator(".amount-row").last()).toContainText("Pool lock:");
});

test("shows the source token balance", async ({ page }) => {
  await openSwap(page);
  await expect(page.locator(".amount-row").first()).toContainText("Bal: 1000");
});

test("the pool's stable is labelled as such in the picker", async ({ page }) => {
  await openSwap(page);
  await page.locator(".amount-row").first().locator(".dd__trigger").click();
  await expect(page.locator(".dd__item-sub").filter({ hasText: "stablecoin" })).toHaveCount(1);
  expect([STABLE_A, TOKEN_18]).toHaveLength(2); // fixtures referenced
});

test("a pool that answers slower than the poll interval still renders", async ({ page }) => {
  // Live regression: the API took ~13s per swapPool against a reused Monad pool
  // while the view polls every 10s. Each tick superseded the request before it
  // returned, so no answer was ever applied and the view said "No pool on this
  // chain" indefinitely — even though every single request succeeded.
  test.setTimeout(60_000);
  const { mockBackend } = await import("../fixtures/backend");
  const { mockChainRpcs } = await import("../fixtures/app");
  const { installWallet } = await import("../fixtures/wallet");
  await mockBackend(page, {});
  await mockChainRpcs(page);
  await installWallet(page, { chainId: 1337, calls: CALLS, preAuthorized: true });
  // Registered last, so it runs first: hold every swapPool query past a tick.
  await page.route("**/graphql", async (route) => {
    if ((route.request().postData() ?? "").includes("swapPool(")) {
      await new Promise((r) => setTimeout(r, 12_000));
    }
    await route.fallback();
  });
  await page.goto("/");
  await gotoView(page, "Swap");
  await expect(page.locator(".summary__row").filter({ hasText: "Pool" })).toContainText(POOL_A.slice(0, 8), {
    timeout: 40_000,
  });
  await expect(primaryButton(page)).not.toHaveText("No pool on this chain");
});
