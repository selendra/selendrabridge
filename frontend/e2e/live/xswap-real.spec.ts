import { test, expect, type Page } from "@playwright/test";
import { erc20Balance, installLiveWallets, liveEnv, type LiveEnv } from "../fixtures/live-wallet";

/**
 * Cross-chain swap ("Swap on arrival") against a REAL mesh: swapAndBridge on the
 * source router, validators sign, the keeper claims the stable to the destination
 * router, and the browser calls finalize() there — paying out the final token.
 *
 * Needs SwapRouters deployed and wired (`chains[].router` in the registry). The
 * route is derived from the registry: the first two EVM chains that both carry a
 * router and a pool, sending the first non-stable token and asking for the same
 * symbol back. Env as for bridge-real (LIVE_EVM_KEY, LIVE_RPCS, LIVE_API, LIVE_APP).
 */

const API = process.env.LIVE_API ?? "http://127.0.0.1:8088";
const APP = process.env.LIVE_APP ?? "http://127.0.0.1:5173";

type Token = { symbol: string; address: string };
type Chain = { chainId: number; name: string; gate: string; router: string | null; tokens: Token[] };

async function gql<T>(query: string): Promise<T> {
  const res = await fetch(`${API}/graphql`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ query }),
  });
  const body = await res.json();
  expect(body.errors, `query failed: ${query}`).toBeUndefined();
  return body.data as T;
}

let env: LiveEnv | null = null;
test.beforeAll(async () => {
  env = await liveEnv();
});

test.use({ baseURL: APP });

async function pick(page: Page, scope: ReturnType<Page["locator"]>, name: string) {
  await scope.locator(".dd__trigger").click();
  await page.getByRole("option", { name: new RegExp(name) }).first().click();
}

test("cross-chain swap: Swap on arrival delivers the final token on the destination", async ({ page }) => {
  test.skip(!env, "LIVE_EVM_KEY / LIVE_RPCS not set — real-wallet suite skipped");
  test.setTimeout(25 * 60_000);

  const { chains } = await gql<{ chains: Chain[] }>(
    "{ chains { chainId name gate router tokens { symbol address } } }"
  );
  const routed = chains.filter((c) => c.router && /^0x[0-9a-fA-F]{40}$/.test(c.gate));
  test.skip(routed.length < 2, "fewer than two chains with a SwapRouter");
  const [from, to] = routed;
  const { swapPool } = await gql<{ swapPool: { stable: string } | null }>(
    `{ swapPool(chainId: ${from.chainId}) { stable } }`
  );
  expect(swapPool, `no pool on ${from.name}`).not.toBeNull();
  const tokenIn = from.tokens.find((t) => t.address.toLowerCase() !== swapPool!.stable.toLowerCase())!;
  const tokenOut = to.tokens.find((t) => t.symbol === tokenIn.symbol)!;
  expect(tokenIn && tokenOut, "no matching non-stable token on both chains").toBeTruthy();

  const rpcTo = env!.rpcs[String(to.chainId)];
  const before = await erc20Balance(rpcTo, tokenOut.address, env!.evmAddress);

  await installLiveWallets(page, env!, from.chainId);
  await page.goto("/");
  await page.locator(".nav__links").getByRole("button", { name: "Bridge", exact: true }).click();
  const btn = page.locator(".review-btn");
  await expect(btn).toHaveText("Connect Wallet", { timeout: 20_000 });
  await btn.click();

  await page.getByRole("button", { name: "Swap on arrival" }).click();
  await pick(page, page.locator(".bridge-route"), to.name);
  await pick(page, page.locator(".token-picker"), tokenIn.symbol);
  await page.locator("label.field", { hasText: "Final token" }).locator("input").fill(tokenOut.address);
  await page.locator(".field", { hasText: "Amount" }).locator("input.field__input").fill("0.02");
  await page.locator("label.field", { hasText: "Final receiver" }).locator("input").fill(env!.evmAddress);

  // Approve if asked, then Swap & Bridge.
  await expect(btn).toHaveText(/Approve for router|Swap & Bridge/, { timeout: 60_000 });
  if ((await btn.textContent())?.includes("Approve")) {
    await btn.click();
    await expect(btn).toHaveText("Swap & Bridge", { timeout: 180_000 });
  }
  await btn.click();

  // Validators sign, the keeper claims to the destination router.
  await expect(btn).toHaveText(/Waiting for validators|Switch to|Finalize on/, { timeout: 180_000 });
  await expect(btn).toHaveText(new RegExp(`Switch to ${to.name}|Finalize on ${to.name}`), { timeout: 20 * 60_000 });
  if ((await btn.textContent())?.startsWith("Switch to")) {
    await btn.click();
    await expect(btn).toHaveText(`Finalize on ${to.name}`, { timeout: 30_000 });
  }
  await btn.click();
  await expect(btn).toHaveText("Start a new transfer", { timeout: 180_000 });

  // The receiver got the FINAL token, not the carrier stable.
  await expect
    .poll(async () => (await erc20Balance(rpcTo, tokenOut.address, env!.evmAddress)) - before, {
      timeout: 60_000,
    })
    .toBeGreaterThan(0n);
});
