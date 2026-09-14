import { execFile } from "node:child_process";
import { createPrivateKey, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { promisify } from "node:util";
import type { Page } from "@playwright/test";

/**
 * REAL wallets for the live suite — they sign and broadcast on actual testnets.
 *
 * The mocked `wallet.ts` proves what the UI asks a wallet to do; this one proves
 * that what it asks for actually WORKS on-chain: that the calldata is accepted by
 * the deployed gate, that the receipt the UI waits on arrives, and that the
 * transfer the UI reports as locked is the one the validators then sign.
 *
 * The page gets a thin EIP-1193 / Phantom shim; every read is forwarded to the
 * chain's RPC from Node, and every write is signed in Node — by `cast` for EVM
 * and by node:crypto's ed25519 for Solana — so no key ever enters the page.
 *
 * Configured ONLY from the environment, so no key or keyed RPC url is committed:
 *
 *   LIVE_EVM_KEY          0x-prefixed private key of the funded test account
 *   LIVE_RPCS             JSON object {"<chainId>": "<rpc url>", ...}
 *   LIVE_SOLANA_KEYPAIR   path to a solana-keygen JSON keypair (optional)
 *   LIVE_SOLANA_RPC       Solana RPC url (optional, with the keypair)
 */

const run = promisify(execFile);

export interface LiveEnv {
  evmKey: string;
  evmAddress: string;
  rpcs: Record<string, string>;
  solanaSecret: Uint8Array | null;
  solanaAddress: string | null;
  solanaRpc: string | null;
}

/** Null when the live wallet isn't configured, so specs can skip cleanly. */
export async function liveEnv(): Promise<LiveEnv | null> {
  const evmKey = process.env.LIVE_EVM_KEY;
  const rpcsRaw = process.env.LIVE_RPCS;
  if (!evmKey || !rpcsRaw) return null;
  const rpcs = JSON.parse(rpcsRaw) as Record<string, string>;
  const { stdout } = await run("cast", ["wallet", "address", "--private-key", evmKey]);
  let solanaSecret: Uint8Array | null = null;
  let solanaAddress: string | null = null;
  const kp = process.env.LIVE_SOLANA_KEYPAIR;
  if (kp) {
    solanaSecret = Uint8Array.from(JSON.parse(readFileSync(kp, "utf8")) as number[]);
    solanaAddress = b58encode(solanaSecret.slice(32, 64));
  }
  return {
    evmKey,
    evmAddress: stdout.trim(),
    rpcs,
    solanaSecret,
    solanaAddress,
    solanaRpc: process.env.LIVE_SOLANA_RPC ?? null,
  };
}

// --- base58 (Node side; the page has its own) ------------------------------

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function b58encode(bytes: Uint8Array): string {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let s = "";
  while (n > 0n) {
    s = B58[Number(n % 58n)] + s;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    s = "1" + s;
  }
  return s;
}

export function b58decode(s: string): Uint8Array {
  let n = 0n;
  for (const c of s) {
    const i = B58.indexOf(c);
    if (i < 0) throw new Error(`bad base58 character ${c}`);
    n = n * 58n + BigInt(i);
  }
  const out: number[] = [];
  while (n > 0n) {
    out.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  for (const c of s) {
    if (c !== "1") break;
    out.unshift(0);
  }
  return Uint8Array.from(out);
}

// --- RPC -------------------------------------------------------------------

export async function rpc<T>(url: string, method: string, params: unknown[]): Promise<T> {
  for (let attempt = 0; ; attempt++) {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
    // Hosted free tiers rate-limit bursts; back off instead of failing the flow.
    if (res.status === 429 && attempt < 5) {
      await new Promise((r) => setTimeout(r, 1000 * (attempt + 1)));
      continue;
    }
    const body = (await res.json()) as { result?: T; error?: { code: number; message: string; data?: unknown } };
    if (body.error) {
      const err = new Error(body.error.message) as Error & { code: number; data?: unknown };
      err.code = body.error.code;
      err.data = body.error.data;
      throw err;
    }
    return body.result as T;
  }
}

/** ERC-20 balance through the RPC, for asserting what actually arrived. */
export async function erc20Balance(url: string, token: string, owner: string): Promise<bigint> {
  const data = "0x70a08231" + owner.replace(/^0x/, "").toLowerCase().padStart(64, "0");
  const r = await rpc<string>(url, "eth_call", [{ to: token, data }, "latest"]);
  return BigInt(r === "0x" ? 0 : r);
}

/** SPL token account balance (base units) — null when the account doesn't exist. */
export async function splBalance(url: string, account: string): Promise<bigint | null> {
  try {
    const r = await rpc<{ value: { amount: string } }>(url, "getTokenAccountBalance", [account]);
    return BigInt(r.value.amount);
  } catch {
    return null;
  }
}

// --- install ---------------------------------------------------------------

/**
 * Inject both wallets. `chainId` is the EVM chain the wallet starts on; the app
 * may switch it with `wallet_switchEthereumChain` like a real MetaMask.
 */
export async function installLiveWallets(page: Page, env: LiveEnv, chainId: number): Promise<void> {
  await page.exposeFunction("__liveEvmRpc", async (cid: number, method: string, params: unknown[]) => {
    const url = env.rpcs[String(cid)];
    if (!url) throw new Error(`no RPC for chain ${cid} in LIVE_RPCS`);
    return rpc(url, method, params);
  });

  await page.exposeFunction(
    "__liveEvmSend",
    async (cid: number, tx: { to: string; data?: string; value?: string }) => {
      const url = env.rpcs[String(cid)];
      if (!url) throw new Error(`no RPC for chain ${cid} in LIVE_RPCS`);
      const args = ["send", tx.to, tx.data ?? "0x", "--rpc-url", url, "--private-key", env.evmKey, "--async"];
      if (tx.value && BigInt(tx.value) > 0n) args.push("--value", BigInt(tx.value).toString());
      const { stdout } = await run("cast", args, { timeout: 120_000 });
      const hash = stdout.trim().split(/\s+/).pop() ?? "";
      if (!/^0x[0-9a-fA-F]{64}$/.test(hash)) throw new Error(`cast send gave no hash: ${stdout}`);
      return hash;
    }
  );

  if (env.solanaSecret && env.solanaRpc) {
    const secret = env.solanaSecret;
    const url = env.solanaRpc;
    // PKCS#8 wrapper for a raw 32-byte ed25519 seed.
    const pkcs8 = Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      Buffer.from(secret.slice(0, 32)),
    ]);
    const key = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
    await page.exposeFunction("__liveSolanaSignAndSend", async (messageB58: string) => {
      const message = b58decode(messageB58);
      const signature = sign(null, message, key);
      // Wire format: compact-u16 signature count (1), the signature, the message.
      const wire = Buffer.concat([Buffer.from([1]), signature, Buffer.from(message)]);
      await rpc<string>(url, "sendTransaction", [
        wire.toString("base64"),
        { encoding: "base64", preflightCommitment: "confirmed" },
      ]);
      return b58encode(signature);
    });
  }

  await page.addInitScript(
    (cfg: { account: string; chainId: number; solana: string | null }) => {
      type Fn = (...a: unknown[]) => Promise<unknown>;
      const w = window as unknown as Record<string, Fn> & { ethereum: unknown; phantom: unknown };
      let chainId = cfg.chainId;
      let authorized = sessionStorage.getItem("__live_wallet_authorized") === "1";
      const listeners: Record<string, ((...a: unknown[]) => void)[]> = {};
      const hex = (n: number) => "0x" + n.toString(16);

      const provider = {
        isMetaMask: true,
        on(ev: string, h: (...a: unknown[]) => void) {
          (listeners[ev] ??= []).push(h);
        },
        removeListener(ev: string, h: (...a: unknown[]) => void) {
          listeners[ev] = (listeners[ev] ?? []).filter((x) => x !== h);
        },
        async request({ method, params = [] }: { method: string; params?: unknown[] }) {
          switch (method) {
            case "eth_accounts":
              return authorized ? [cfg.account] : [];
            case "eth_requestAccounts":
              authorized = true;
              sessionStorage.setItem("__live_wallet_authorized", "1");
              return [cfg.account];
            case "eth_chainId":
              return hex(chainId);
            case "wallet_switchEthereumChain": {
              chainId = parseInt((params[0] as { chainId: string }).chainId, 16);
              sessionStorage.setItem("__live_wallet_chain", String(chainId));
              (listeners.chainChanged ?? []).forEach((h) => h(hex(chainId)));
              return null;
            }
            case "eth_sendTransaction": {
              const tx = params[0] as { to: string; data?: string; value?: string; chainId?: string };
              if (tx.chainId && parseInt(tx.chainId, 16) !== chainId) {
                throw new Error(`tx built for chain ${parseInt(tx.chainId, 16)}, wallet is on ${chainId}`);
              }
              return w.__liveEvmSend(chainId, tx);
            }
            default:
              return w.__liveEvmRpc(chainId, method, params);
          }
        },
      };
      const saved = sessionStorage.getItem("__live_wallet_chain");
      if (saved) chainId = Number(saved);
      w.ethereum = provider;
      const announce = () =>
        window.dispatchEvent(
          new CustomEvent("eip6963:announceProvider", {
            detail: {
              info: { uuid: "live-wallet", name: "MetaMask", icon: "data:image/svg+xml,", rdns: "io.metamask" },
              provider,
            },
          })
        );
      window.addEventListener("eip6963:requestProvider", announce);
      announce();

      if (cfg.solana) {
        const account = cfg.solana;
        w.phantom = {
          solana: {
            isPhantom: true,
            publicKey: null as unknown,
            async connect(opts?: { onlyIfTrusted?: boolean }) {
              if (opts?.onlyIfTrusted) throw new Error("not trusted");
              this.publicKey = { toString: () => account };
              return { publicKey: this.publicKey };
            },
            async disconnect() {
              this.publicKey = null;
            },
            async request(args: { method: string; params?: { message?: string } }) {
              if (args.method !== "signAndSendTransaction") throw new Error(`unexpected ${args.method}`);
              const signature = await w.__liveSolanaSignAndSend(args.params?.message ?? "");
              return { signature };
            },
            on() {},
            removeListener() {},
          },
        };
      }
    },
    { account: env.evmAddress, chainId, solana: env.solanaAddress }
  );
}

/** Switch the injected EVM wallet to another chain, as the user would in MetaMask. */
export async function switchLiveChain(page: Page, chainId: number): Promise<void> {
  await page.evaluate(
    (id) =>
      (window as unknown as { ethereum: { request(a: unknown): Promise<unknown> } }).ethereum.request({
        method: "wallet_switchEthereumChain",
        params: [{ chainId: "0x" + id.toString(16) }],
      }),
    chainId
  );
}
