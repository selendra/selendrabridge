import { test, expect, startApp, gotoView } from "../fixtures/app";
import { installSolanaWallet, signedMessages, SOLANA_ACCOUNT } from "../fixtures/solana-wallet";
import { b58decode } from "../../src/wallet/solana";

/**
 * Bridging OUT of Solana, from the Bridge view.
 *
 * The EVM form's source chain is the connected EVM wallet's chain, so this flow
 * lives in its own panel behind a source switch. What is asserted here is that
 * the switch appears only when the mesh has a non-EVM chain, that the panel uses
 * the Solana wallet, and that the transaction it hands over carries the gate's
 * `send` — the bytes of which are pinned in `e2e/unit/solana.spec.ts`.
 */

const SOL_CHAIN = 7565164;
const TST = "8T2cxAqp8mDNkdTTb5giew9eYgZ7NmHdEWz6kMeE7WFV";
const GATE = "HvGQTWChe6bMpSYGNavDhGcG8YrJkubJQCDmBrxNR133";
const VAULT = "33A9xPRuLjv8NBrp5XjjdU22yfXdNx6vGczW9XY3bpgb";
const RECEIVER = "0xaddd30479698216B0C2eE967cBC115917EeFE243";

const CHAINS = [
  {
    chainId: 11155111,
    name: "Ethereum Sepolia",
    rpcUrl: "http://127.0.0.1:8545",
    gate: "0x1111111111111111111111111111111111111111",
    token: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    tokens: [{ symbol: "TST", address: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }],
    router: null as unknown as string,
  },
  {
    chainId: SOL_CHAIN,
    name: "Solana Devnet",
    rpcUrl: null as unknown as string,
    gate: null as unknown as string,
    token: TST,
    tokens: [{ symbol: "TST", address: TST }],
    router: null as unknown as string,
  },
];

const primaryButton = (page: import("@playwright/test").Page) => page.locator(".review-btn");

async function openSolanaBridge(page: import("@playwright/test").Page, wallet = {}) {
  await installSolanaWallet(page, wallet);
  await startApp(page, { backend: { chains: CHAINS }, wallet: null });
  await gotoView(page, "Bridge");
  await page.getByRole("tab", { name: /From Solana/ }).click();
}

test("the source switch appears only when the mesh has a non-EVM chain", async ({ page }) => {
  await installSolanaWallet(page);
  // EVM-only registry: no switch at all.
  await startApp(page, { backend: { chains: [CHAINS[0]] }, wallet: null });
  await gotoView(page, "Bridge");
  await expect(page.getByRole("tab", { name: /From Solana/ })).toHaveCount(0);
});

test("the Solana panel asks for Phantom", async ({ page }) => {
  await openSolanaBridge(page);
  await expect(primaryButton(page)).toHaveText("Connect Phantom");
});

test("shows the corridor the gate actually reports", async ({ page }) => {
  await openSolanaBridge(page);
  await primaryButton(page).click();
  await expect(page.locator(".summary__row").filter({ hasText: "Corridor nonce" })).toContainText("3", {
    timeout: 10_000,
  });
});

test("hands the wallet a gate send carrying the typed receiver", async ({ page }) => {
  await openSolanaBridge(page);
  await primaryButton(page).click();
  await page.getByLabel("Amount").fill("2");
  await page.getByLabel("Receiver").fill(RECEIVER);
  await expect(primaryButton(page)).toHaveText("Bridge from Solana", { timeout: 10_000 });
  await primaryButton(page).click();

  await expect.poll(async () => (await signedMessages(page)).length, { timeout: 15_000 }).toBe(1);
  const hex = Buffer.from(b58decode((await signedMessages(page))[0])).toString("hex");

  // Variant 1 = GateInstruction::Send, then the debridgeId.
  expect(hex).toContain("014b7347216b2c2ce2879cf0086a2bd0ad84a4df90c1d0d1e665041ba0bc157454");
  // The receiver the USER typed is in the instruction data — that is the field
  // that decides where the transfer lands, and it is built in the browser.
  expect(hex).toContain(RECEIVER.slice(2).toLowerCase());
  // …together with the gate, its vault, and the signer.
  for (const key of [GATE, VAULT, SOLANA_ACCOUNT]) {
    expect(hex).toContain(Buffer.from(b58decode(key)).toString("hex"));
  }
});

test("a mint bridged at fewer decimals refuses precision below its bridge unit", async ({ page }) => {
  // A 9-decimal mint bridged at 6 decimals.
  await installSolanaWallet(page);
  await startApp(page, {
    backend: {
      chains: CHAINS,
      solanaGateContext: {
        programId: GATE,
        bridgeDomain: "0x619244a655e7383c05da63e9d66080952fcfe4fc48b40c61f566996006848055",
        chainId: 7565164,
        nonce: 3,
        debridgeId: "0x4b7347216b2c2ce2879cf0086a2bd0ad84a4df90c1d0d1e665041ba0bc157454",
        vault: VAULT,
        decimals: 9,
        bridgeDecimals: 6,
        paused: false,
      },
    },
    wallet: null,
  });
  await gotoView(page, "Bridge");
  await page.getByRole("tab", { name: /From Solana/ }).click();
  await primaryButton(page).click();
  await page.getByLabel("Receiver").fill(RECEIVER);
  await page.getByLabel("Amount").fill("2.0000001");
  await expect(primaryButton(page)).toHaveText("Too precise — this asset bridges at most 6 decimals", {
    timeout: 10_000,
  });
  await page.getByLabel("Amount").fill("2.000001");
  await expect(primaryButton(page)).toHaveText("Bridge from Solana");
});

test("says the transfer is locked and awaiting validators, not delivered", async ({ page }) => {
  await openSolanaBridge(page);
  await primaryButton(page).click();
  await page.getByLabel("Amount").fill("2");
  await page.getByLabel("Receiver").fill(RECEIVER);
  await primaryButton(page).click();
  await expect(page.locator(".txbar--done")).toContainText(/awaiting validators/i, { timeout: 20_000 });
});
