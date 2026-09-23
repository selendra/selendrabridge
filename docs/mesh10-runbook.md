# mesh10 deploy runbook

The H-2 fix changes the submissionId format, so it cannot go onto mesh9 — its
gates are sealed and hold the old format. mesh10 is a fresh generation.

Everything below is **staged and verified locally**; the only thing missing is
permission to send real transactions. The sandbox refused the deploy with
`[Real-World Transactions]`, so the commands are written out rather than run.

## What is already done

| | |
| --- | --- |
| Fresh key material | `.mesh10-keys/` (gitignored, mode 0600) |
| Deploy config | `config/testnet10.deploy.local.json` |
| Solana program rebuilt | `crates/solana-gate/target/deploy/solana_gate.so`, 244,744 bytes, SBF target |
| `gate-admin` / `swap-admin` rebuilt | `crates/solana-relayer/target/release/` |
| Dry run | passes |

### New identities

| Role | Value |
| --- | --- |
| `bridgeDomain` | `0x49fe3aa153c84e32d996497b29c46ec4472b628b9524242f145f05a015a94051` |
| validator 1 | `0x3C42f23C68c38C827dd25359ddbfC404919995Aa` |
| validator 2 | `0x7270b593Eb45E408060E4D3714B9f433a5a469B8` |
| keeper | `0x5808931A1364acc9bCa44F68f0ebEef5155312c8` |
| Solana relayer payer | `EYXn9qSrJosHg7mhTCF79cRXVVhawRYrn5TFUjdHnSRg` |
| deployer / gate owner | `0xaddd30479698216B0C2eE967cBC115917EeFE243` (unchanged, as supplied) |

Threshold stays 2-of-2. RPCs are **public endpoints** — mesh10 never touches the
leaked Alchemy key (H-3).

## Step 1 — deploy the EVM leg

```bash
bash scripts/deploy-from-json.sh config/testnet10.deploy.local.json
```

No `--allow-local-profile-on-chain`: Sepolia, Hoodi and Monad are all already on
the script's `DEV_CHAIN_IDS` allowlist, so the flag is not needed and passing it
only disables a real check.

Writes `config/deployments/testnet-mesh10.json` and patches
`config/testnet10.bridge.local.json`.

Deployer gas at time of staging: Sepolia 0.107 ETH, Hoodi 1.44 ETH, Monad
4.45 MON. **Sepolia is the thin one** — a full gate + 2 tokens + pool + router is
roughly 11M gas; fine at 1–5 gwei, tight if it spikes.

## Step 2 — fund the keeper

The keeper sends every `claim`/`cancel`/`refund`, so it needs gas on all three
EVM chains. The validators do **not** — they only sign off-chain.

```bash
KEEPER=0x5808931A1364acc9bCa44F68f0ebEef5155312c8
cast send $KEEPER --value 0.02ether --rpc-url https://ethereum-sepolia-rpc.publicnode.com  --private-key $DEPLOYER_KEY
cast send $KEEPER --value 0.3ether  --rpc-url https://ethereum-hoodi-rpc.publicnode.com    --private-key $DEPLOYER_KEY
cast send $KEEPER --value 1ether    --rpc-url https://testnet-rpc.monad.xyz                --private-key $DEPLOYER_KEY
```

## Step 3 — the Solana leg

Not staged, and it needs one thing only you can provide.

`solana.payer_keypair` is used as **both** the deploy payer and the gate owner —
the Solana program has no ownership-transfer instruction, so whoever signs `init`
owns it permanently. That must be your key, not the relayer's; the two being the
same account is exactly audit finding T-8.

Materialising your key from the mnemonic was refused by the sandbox
(`[Credential Materialization]`). Run it yourself:

```bash
solana-keygen recover -o .mesh10-keys/owner.json --force 'prompt://'
# paste the 12 words, then an empty line for the passphrase
```

Then edit `config/testnet10.deploy.local.json`:

```jsonc
"solana": {
  "enabled": true,                                  // currently false
  "payer_keypair": ".mesh10-keys/owner.json",       // owner + deploy payer
  "gate_admin_bin": "crates/solana-relayer/target/release/gate-admin",
  "program": { "deploy": true },                    // new id: the ["config"] PDA
                                                    // carries bridgeDomain and is
                                                    // set once at init
  "assets": [ { "vault": null }, … ]                // see below
}
```

**The mesh9 vaults are unusable.** A vault is an SPL account owned by the gate
program's `["vault_authority"]` PDA, and a new program id means a new PDA. For
the staged program keypair that address is
`DMEGibzP7jR7h6yeQadXM8WoLWnr3ek5iwTPy8htkKyM`, but the deploy script generates
its own id unless you pin one — so derive it **after** the program deploys:

```bash
solana find-program-derived-address <NEW_PROGRAM_ID> string:vault_authority
spl-token create-account <MINT> --owner <THAT_PDA> --fee-payer .mesh10-keys/owner.json
```

and put the resulting accounts in `solana.assets[].vault`. The SPL mints
themselves can be reused from mesh9; the swap program can too (it is same-chain
only and carries no submissionIds).

The relayer containers get `EYXn9qSrJosHg7mhTCF79cRXVVhawRYrn5TFUjdHnSRg` as
their fee payer, separate from the owner — that is the T-8 fix.

## Step 4 — stack, then cut over

```bash
bash scripts/bridge-from-json.sh config/testnet10.bridge.local.json --compose
cd docker/testnet-mesh10 && cp .env.example .env   # fill in the tokens
docker compose up -d --build
```

Bring mesh10 up on a spare port first, prove a transfer, **then** retire mesh9:

```bash
cd docker/testnet-mesh9 && docker compose down -v
```

mesh9 was left running deliberately. You asked to replace it entirely, but
mesh10 does not exist yet — tearing it down now would leave nothing serving.
Its 17 transfers are all settled (16 claimed, 1 cancelled + refunded), so
nothing strands whenever you do pull it.

## What was verified locally instead

A full local mesh on the **new contracts** — real Gates with the new id format,
the real backend, the real UI:

- `scripts/run.sh scripts/mesh10-local.config` — 2 anvil chains, sig-store,
  2 validators, keeper, indexer, graphql-api, frontend
- a 25 TST transfer: 2 validator signatures → keeper `claim` → delivered
- the API serving `bridgeDecimals: 18` from the **signed record**, not a chain read
- 9/9 live UI tests, plus `EVM → EVM: a transfer sent from the UI arrives on the
  destination` — a real browser-driven, wallet-signed transfer
- the rebuilt SBF artifact deploying into a live `solana-test-validator`

Not covered locally: EVM↔Solana legs (no local Solana mesh wired up) and the
same-chain swap UI test (the local pool lists one token).
