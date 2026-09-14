import { test, expect, type Page } from "@playwright/test";
import { randomBytes } from "node:crypto";
import {
  erc20Balance,
  installLiveWallets,
  liveEnv,
  splBalance,
  switchLiveChain,
  type LiveEnv,
} from "../fixtures/live-wallet";

/**
 * Real transfers THROUGH THE UI on a live mesh — signed, broadcast, attested,
 * claimed. `testnet.spec.ts` checks that the UI renders what the API returns;
 * this file checks that what the UI SENDS actually bridges.
 *
 * Opt-in: needs LIVE_EVM_KEY + LIVE_RPCS (and LIVE_SOLANA_KEYPAIR +
 * LIVE_SOLANA_RPC for the Solana legs) — see `fixtures/live-wallet.ts`. It
 * spends testnet gas, so it never runs by accident.
 *
 * Chains are picked from the registry by env (LIVE_SRC / LIVE_DST, default the
 * first two EVM chains); amounts are raw base units because the bridge carries
 * no decimals normalisation between chains.
 */

const API = process.env.LIVE_API ?? "http://127.0.0.1:5173";
const APP = process.env.LIVE_APP ?? "http://127.0.0.1:5173";
const SOLANA_CHAIN_ID = 7565164;
/** How long a leg may take end to end: confirmations + quorum + keeper claim. */
const ARRIVAL_MS = Number(process.env.LIVE_ARRIVAL_MS ?? 15 * 60_000);

type Chain = { chainId: number; name: string; gate: string | null; tokens: { symbol: string; address: string }[] };

async function gql<T>(query: string, variables?: Record<string, unknown>): Promise<T> {
  const res = await fetch(`${API}/graphql`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ query, variables }),
  });
  const body = (await res.json()) as { data: T; errors?: { message: string }[] };
  expect(body.errors, JSON.stringify(body.errors)).toBeUndefined();
  return body.data;
}

const registry = () =>
  gql<{ chains: Chain[] }>("{ chains { chainId name gate tokens { symbol address } } }").then((d) => d.chains);

async function waitFor<T>(what: string, fn: () => Promise<T | null>, timeoutMs = ARRIVAL_MS): Promise<T> {
  const start = Date.now();
  for (;;) {
    const v = await fn().catch(() => null);
    if (v != null) return v;
    if (Date.now() - start > timeoutMs) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 10_000));
  }
}

const tst = (c: Chain) => c.tokens.find((t) => t.symbol === "TST")?.address ?? c.tokens[0].address;
const freshEvmAddress = () => "0x" + randomBytes(20).toString("hex");

let env: LiveEnv | null = null;
let chains: Chain[] = [];
let src: Chain;
let dst: Chain;

test.describe.configure({ mode: "serial" });
test.use({ baseURL: APP });

test.beforeAll(async () => {
  env = await liveEnv();
  if (!env) return;
  chains = await registry();
  const evm = chains.filter((c) => c.gate?.startsWith("0x"));
  src = evm.find((c) => c.chainId === Number(process.env.LIVE_SRC)) ?? evm[0];
  dst = evm.find((c) => c.chainId === Number(process.env.LIVE_DST)) ?? evm.find((c) => c !== src)!;
});

test.beforeEach(() => {
  test.skip(!env, "LIVE_EVM_KEY / LIVE_RPCS not set — real-wallet suite skipped");
});

async function openBridge(page: Page, chainId: number) {
  await installLiveWallets(page, env!, chainId);
  await page.goto("/");
  await page.locator(".nav__links").getByRole("button", { name: "Bridge", exact: true }).click();
  await expect(page.locator(".status")).toHaveText(/Backend live/, { timeout: 20_000 });
  const connect = page.locator(".card").getByRole("button", { name: "Connect Wallet" });
  if (await connect.isVisible()) await connect.click();
}

/** Fill the EVM form and drive approve → bridge through the real wallet. */
async function bridgeFromEvm(page: Page, to: Chain | { chainId: number; name: string }, amount: string, receiver: string) {
  await page.locator(".bridge-route .dd__trigger").click();
  await page.getByRole("option", { name: to.name }).click();
  const inputs = page.locator(".fields .field__input");
  // Amount is the only non-mono input; the receiver is the last one.
  await page.locator(".fields input[inputmode=decimal]").fill(amount);
  await inputs.last().fill(receiver);

  const button = page.locator(".review-btn");
  await expect(button).not.toHaveText(/Reading token/, { timeout: 30_000 });
  if (/Approve/.test((await button.textContent()) ?? "")) {
    await button.click();
    await expect(button).toHaveText("Bridge", { timeout: 180_000 });
  }
  await expect(button).toHaveText("Bridge");
  await button.click();
  const outcome = page.locator(".txbar--done, .txbar--error");
  await expect(outcome).toBeVisible({ timeout: 180_000 });
  await expect(outcome, "the send must lock, not error").toHaveClass(/txbar--done/);
  await expect(outcome).toContainText("Locked");
}

test("the bridge form re-targets the Gate when the wallet changes chain", async ({ page }) => {
  await openBridge(page, src.chainId);
  const gateInput = page.locator(".field").filter({ hasText: "Gate contract" }).locator("input");
  await expect(gateInput).toHaveValue(new RegExp(src.gate!, "i"), { timeout: 20_000 });

  await switchLiveChain(page, dst.chainId);
  await expect(page.locator(".bridge-route__node").first()).toContainText(dst.name);
  // Sending to the PREVIOUS chain's gate address on this chain calls whatever
  // (if anything) lives at that address here.
  await expect(gateInput).toHaveValue(new RegExp(dst.gate!, "i"), { timeout: 10_000 });
});

test("EVM → EVM: a transfer sent from the UI arrives on the destination", async ({ page }) => {
  test.setTimeout(ARRIVAL_MS + 5 * 60_000);
  const receiver = freshEvmAddress();
  const amount = "0.25";
  await openBridge(page, src.chainId);
  await bridgeFromEvm(page, dst, amount, receiver);

  const arrived = await waitFor(`${amount} TST at ${receiver} on ${dst.name}`, async () => {
    const b = await erc20Balance(env!.rpcs[String(dst.chainId)], tst(dst), receiver);
    return b > 0n ? b : null;
  });
  expect(arrived).toBe(250000000000000000n);

  // And the API reports it as executed, from live chain state.
  const status = await waitFor(
    `submission for ${receiver} to read EXECUTED`,
    async () => {
      const { submissions } = await gql<{ submissions: { receiver: string; status: string }[] }>(
        "{ submissions { receiver status } }"
      );
      const mine = submissions.find((s) => s.receiver.toLowerCase() === receiver.toLowerCase());
      return mine?.status === "EXECUTED" ? mine.status : null;
    },
    120_000
  );
  expect(status).toBe("EXECUTED");
  await page.locator(".nav__links").getByRole("button", { name: "Explorer", exact: true }).click();
  await expect(page.locator(".tbl__row").first()).toBeVisible({ timeout: 30_000 });
});

test("EVM → Solana: a transfer sent from the UI lands in the SPL token account", async ({ page }) => {
  test.setTimeout(ARRIVAL_MS + 5 * 60_000);
  const account = process.env.LIVE_SOLANA_TOKEN_ACCOUNT;
  test.skip(!account || !env!.solanaRpc, "LIVE_SOLANA_TOKEN_ACCOUNT / LIVE_SOLANA_RPC not set");
  const sol = chains.find((c) => c.chainId === SOLANA_CHAIN_ID);
  test.skip(!sol, "no Solana chain in the registry");

  const before = (await splBalance(env!.solanaRpc!, account!)) ?? 0n;
  await openBridge(page, src.chainId);
  // 1_000_000 raw = 0.000000000001 of an 18-dec token = 1 whole 6-dec SPL token.
  await bridgeFromEvm(page, sol!, "0.000000000001", account!);

  const after = await waitFor(`SPL balance of ${account} to rise`, async () => {
    const b = await splBalance(env!.solanaRpc!, account!);
    return b != null && b > before ? b : null;
  });
  expect(after - before).toBe(1_000_000n);
});

test("Solana → EVM: a send built in the browser arrives on the EVM chain", async ({ page }) => {
  test.setTimeout(ARRIVAL_MS + 5 * 60_000);
  test.skip(!env!.solanaSecret || !env!.solanaRpc, "LIVE_SOLANA_KEYPAIR / LIVE_SOLANA_RPC not set");
  const receiver = freshEvmAddress();
  await openBridge(page, src.chainId);
  await page.getByRole("tab", { name: /From Solana/ }).click();
  await page.locator(".solana-bridge").getByRole("button", { name: "Connect Phantom" }).click();

  const panel = page.locator(".solana-bridge");
  await panel.locator(".amount-row").nth(1).locator(".dd__trigger").click();
  await page.getByRole("option", { name: dst.name }).click();
  await panel.getByLabel("Amount").fill("1");
  await panel.getByLabel("Receiver").fill(receiver);
  await expect(panel.locator(".review-btn")).toHaveText("Bridge from Solana", { timeout: 30_000 });
  await panel.locator(".review-btn").click();
  await expect(panel).toContainText(/awaiting validators/, { timeout: 120_000 });

  const arrived = await waitFor(`Solana-origin TST at ${receiver} on ${dst.name}`, async () => {
    const b = await erc20Balance(env!.rpcs[String(dst.chainId)], tst(dst), receiver);
    return b > 0n ? b : null;
  });
  expect(arrived).toBe(1_000_000n);
});

test("same-chain swap: a swap sent from the UI pays out the quoted token", async ({ page }) => {
  test.setTimeout(6 * 60_000);
  const chain = dst;
  const pool = await gql<{ swapPool: { tokens: { token: string; symbol: string }[] } | null }>(
    `{ swapPool(chainId: ${chain.chainId}) { tokens { token symbol } } }`
  );
  test.skip(!pool.swapPool || pool.swapPool.tokens.length < 2, `no swap pool on ${chain.name}`);
  const out = pool.swapPool!.tokens[1];
  const rpcUrl = env!.rpcs[String(chain.chainId)];
  const before = await erc20Balance(rpcUrl, out.token, env!.evmAddress);

  await installLiveWallets(page, env!, chain.chainId);
  await page.goto("/");
  await page.locator(".nav").getByRole("button", { name: "Connect Wallet" }).first().click();
  await page.locator(".card__tools .dd__trigger").click();
  await page.getByRole("option", { name: chain.name }).click();
  await page.locator(".amount-row").first().locator("input").fill("1");

  const button = page.locator(".review-btn");
  await expect(button).toHaveText(/^(Approve|Swap$)/, { timeout: 60_000 });
  if (/Approve/.test((await button.textContent()) ?? "")) {
    await button.click();
    await expect(button).toHaveText("Swap", { timeout: 180_000 });
  }
  await button.click();
  const outcome = page.locator(".txbar--done, .txbar--error");
  await expect(outcome).toBeVisible({ timeout: 180_000 });
  await expect(outcome, "the swap must succeed").toHaveClass(/txbar--done/);

  const after = await erc20Balance(rpcUrl, out.token, env!.evmAddress);
  expect(after, `${out.symbol} balance must rise after the swap`).toBeGreaterThan(before);
});
