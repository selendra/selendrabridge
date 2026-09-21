import { test as base, expect, type Page } from "@playwright/test";
import { mockBackend, type BackendMock, type BackendOptions } from "./backend";
import { installWallet, type WalletSetup } from "./wallet";

/**
 * One place to stand the app up: mocked backend, mocked wallet, mocked chain
 * RPCs. Individual tests only say what is DIFFERENT about their world.
 */

export { expect };

/**
 * The chains' own RPCs, which the app reads DIRECTLY (not through the wallet):
 * since H-2, the Bridge view asks the DESTINATION gate what scale it would pay
 * an asset out in. (The Explorer no longer reads any token decimals over RPC —
 * since M-11/M-12 every amount arrives from the API with its own scale.)
 * Served here so tests don't depend on a live anvil.
 */
export interface ChainRpcSetup {
  /** `decimals()` for tokens read over a registry RPC. */
  decimals?: number;
  /**
   * `bridgeDecimalsFor(bytes32)` on the destination gate — the far end of the
   * H-2 scale check. Defaults to `decimals` (i.e. agreeing with a source gate
   * whose `bridgeUnit` is 1). `null` answers like a gate that has no such
   * corridor registered (`set == false`).
   */
  bridgeDecimals?: number | null;
  /**
   * Answer as a PRE-H-2 gate: `bridgeDecimalsFor` is an unknown selector there,
   * so the call returns empty data and the reader must fall back to
   * `tokenOf` + `bridgeUnit` + `decimals`.
   */
  legacyGate?: boolean;
  /** `bridgeUnit(address)` on that gate, for the pre-H-2 fallback path. */
  bridgeUnit?: bigint;
  /** What `tokenOf(bytes32)` maps the asset to on that gate (fallback path). */
  gateToken?: string;
}

export async function mockChainRpcs(page: Page, setup: ChainRpcSetup = {}): Promise<void> {
  const decimals = setup.decimals ?? 18;
  const token = setup.gateToken ?? "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const word = (v: bigint | number) => BigInt(v).toString(16).padStart(64, "0");

  for (const url of ["**/127.0.0.1:8545/**", "**/127.0.0.1:8546/**"]) {
    await page.route(url, (route) => {
      const body = JSON.parse(route.request().postData() ?? "{}") as {
        id?: number;
        params?: [{ data?: string }];
      };
      const data = body.params?.[0]?.data ?? "";
      const reply = (result: string) =>
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ jsonrpc: "2.0", id: body.id ?? 1, result }),
        });

      switch (data.slice(2, 10)) {
        // Gate.bridgeDecimalsFor(bytes32) -> (set, bridgeDecimals, localDecimals, localToken)
        case "93b06e9d": {
          if (setup.legacyGate) return reply("0x");
          const bd = setup.bridgeDecimals === undefined ? decimals : setup.bridgeDecimals;
          if (bd === null) return reply("0x" + word(0).repeat(4));
          return reply("0x" + word(1) + word(bd) + word(decimals) + word(BigInt(token)));
        }
        case "bae667bc": // Gate.tokenOf(bytes32)
          return reply("0x" + word(BigInt(token)));
        case "4e3ff796": // Gate.bridgeUnit(address)
          return reply("0x" + word(setup.bridgeUnit ?? 1n));
        default: // decimals(), and anything else a read path asks for
          return reply("0x" + word(decimals));
      }
    });
  }
}

export interface AppWorld {
  backend: BackendMock;
}

export async function startApp(
  page: Page,
  opts: { backend?: BackendOptions; wallet?: WalletSetup | null; chainRpc?: ChainRpcSetup } = {}
): Promise<AppWorld> {
  const backend = await mockBackend(page, opts.backend ?? {});
  await mockChainRpcs(page, opts.chainRpc ?? {});
  if (opts.wallet !== null) await installWallet(page, opts.wallet ?? {});
  await page.goto("/");
  await expect(page.getByRole("button", { name: "Bridge", exact: true })).toBeVisible();
  return { backend };
}

/** Connect the injected wallet through the navbar and wait for the chip. */
export async function connectWallet(page: Page): Promise<void> {
  await page.getByRole("button", { name: "Connect Wallet" }).first().click();
  await expect(page.locator(".wallet-chip")).toBeVisible();
}

export async function gotoView(page: Page, view: "Bridge" | "Swap" | "Explorer"): Promise<void> {
  await page.locator(".nav__links").getByRole("button", { name: view, exact: true }).click();
}

/** Pick an option out of a `Dropdown` by its visible label. */
export async function chooseFromDropdown(
  page: Page,
  trigger: ReturnType<Page["locator"]>,
  label: string
): Promise<void> {
  await trigger.click();
  await page.getByRole("option", { name: label, exact: false }).first().click();
}

export const test = base;
