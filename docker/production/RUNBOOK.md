# Runbook — running each element

One page per stack: what it does, what it needs, how to start it, what a healthy
start looks like, how to prove it works, and what the failures actually look
like when they happen.

Every log line quoted below was observed from these stacks running against live
testnets — none of it is illustrative.

For the deployment as a whole — topology, which machine gets which secret,
bring-up order — read [`README.md`](./README.md) first. This document assumes
you have already read it and are now standing in front of one machine.

## Contents

- [§0 Common to every stack](#0-common-to-every-stack)
- [§1 store — Postgres + sig-store + TLS](#1-store)
- [§2 indexer](#2-indexer)
- [§3 validator](#3-validator)
- [§4 keeper](#4-keeper)
- [§5 api — GraphQL + frontend](#5-api)
- [§6 solana-relayer](#6-solana-relayer)
- [§7 Cross-cutting operations](#7-cross-cutting-operations)

---

## 0. Common to every stack

Every directory works the same way, so these apply everywhere and are not
repeated below.

### The three files you fill in

| File | What it is | Permissions |
| --- | --- | --- |
| `.env` | secrets + image tags. Never committed. | `chmod 600` |
| `configs/*` | the process's TOML or JSON, copied from `*.example` | readable |
| `secrets/*` | keystores and keypairs (validator, keeper, solana-relayer only) | see §0.4 |

### Image selection

Each stack reads an image variable from `.env`:

```bash
BRIDGE_IMAGE=registry.example.com/selendra/bridge:abc1234   # store, indexer, validator, keeper, api
FRONTEND_IMAGE=registry.example.com/selendra/bridge-frontend:abc1234   # api only
RELAYER_IMAGE=registry.example.com/selendra/bridge-relayer:abc1234     # solana-relayer only
BRIDGE_PULL_POLICY=missing    # `missing` pulls if absent; `always` when tracking a moving tag
```

Pin an immutable tag or a digest. A validator fleet split across two binary
versions is a bad way to spend an afternoon — and after the allowlist change it
is worse than cosmetic, since an older relayer does not enforce the allowlist at
all.

Leave the defaults and each stack builds from the repo instead, which requires
the full source tree on that machine.

### Standard commands

```bash
docker compose up -d                  # start
docker compose ps                     # state + health
docker compose logs -f <service>      # follow
docker compose logs <service> --since 10m
docker compose restart <service>      # restart, keeping config
docker compose up -d --force-recreate # re-read .env / compose changes
docker compose down                   # stop, KEEP volumes
docker compose down -v                # stop and DESTROY volumes — see §7.3
```

### The secret-permission rule

Applies to `validator/`, `keeper/` and `solana-relayer/` — the three stacks with
a `secrets/` directory.

Docker compose bind-mounts file-secrets with the **host** file's ownership, and
**ignores** the `uid`/`gid`/`mode` long-syntax fields outside swarm mode (tested;
they are silently dropped). The images run as **uid 10001**, so a keystore left
at your-user:0600 is unreadable inside the container. The only symptom is a
restart loop:

```
Error: loading validator signer

Caused by:
    0: reading keystore_password_file /run/secrets/keystore_password
    1: Permission denied (os error 13)
```

Two correct shapes. `./preflight.sh` accepts either and rejects everything else:

```bash
# A — strictest, needs root once
sudo chown 10001:10001 secrets/*
chmod 600 secrets/*

# B — no root needed. The 0700 directory keeps other host users out; the file
#     must be world-readable so uid 10001 can read it through the bind mount,
#     which does not re-check directory traversal.
chmod 700 secrets
chmod 644 secrets/*
```

**Run `./preflight.sh` before every `up`** on those three stacks. It also catches
an unfilled `.env` and a world-readable one.

---

## 1. store

**Postgres + sig-store + Caddy.** Machine 1.

### What it does

The rendezvous point every other process talks to. Validators POST signatures
here; the keeper GETs merged records; the indexer writes history; the API reads
it. Nothing coordinates any other way — there is no peer-to-peer layer anywhere
in this system.

It is **not** an authority. `Db::upsert_signature` re-derives every
`submissionId` from its own parameters and ecrecovers every signature before
storing it, parameters are immutable after first insert, and the Gate verifies
the whole quorum again on-chain. Whoever runs this machine can **censor** —
withhold signatures, stall transfers, which the two-phase refund recovers from.
They cannot **forge**.

### What breaks without it

Everything. Validators cannot deposit signatures, the keeper has nothing to
read, the UI has no backend.

### Start it

```bash
cd store
cp .env.example .env
for v in POSTGRES_PASSWORD SIG_STORE_VALIDATOR_TOKEN SIG_STORE_KEEPER_TOKEN \
         SIG_STORE_READER_TOKEN SIG_STORE_ADMIN_TOKEN; do
  echo "$v=$(openssl rand -hex 32)"
done                     # paste into .env
# then set SIG_STORE_DOMAIN, ACME_EMAIL, OPERATOR_CIDRS
chmod 600 .env
docker compose up -d
```

### Healthy

```
NAME                SERVICE     STATUS
store-postgres-1    postgres    Up 13 seconds (healthy)
store-sig-store-1   sig-store   Up 8 seconds (healthy)
```

Plus `caddy` as `Up` — it has no healthcheck of its own; confirm it separately
with the `curl` below. (The two rows above are from a test run on a host with no
public DNS, so Caddy was not started there; everything else in this document was
observed with it in the picture or is independent of it.)

Both healthchecks must go green. `sig-store` will not start until Postgres is
healthy (`depends_on: service_healthy`), and it runs the schema migration on
first boot.

### Verify

```bash
curl -fsS https://sig-store.example.com/health          # 200, no auth needed
```

Then prove the scopes are actually enforced — this is the security design, so
check it rather than assume it:

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://sig-store.example.com/submissions
# 401 — no token

curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $SIG_STORE_READER_TOKEN" \
     https://sig-store.example.com/submissions
# 200 — read scope

curl -s -o /dev/null -w '%{http_code}\n' -X POST \
     -H "Authorization: Bearer $SIG_STORE_READER_TOKEN" \
     -H 'content-type: application/json' -d '{}' \
     https://sig-store.example.com/allowed/tokens
# 401 — reader cannot write the allowlist

curl -s -o /dev/null -w '%{http_code}\n' -X POST \
     -H "Authorization: Bearer $SIG_STORE_KEEPER_TOKEN" \
     -H 'content-type: application/json' -d '{}' \
     https://sig-store.example.com/submissions
# 401 — the keeper cannot deposit signatures
```

All four must come back as shown. If any returns something else, a token is
wired to the wrong variable.

### Failures

| Symptom | Cause | Fix |
| --- | --- | --- |
| `sig-store` restarting, `DATABASE_URL` errors | password mismatch between the two services | both read `POSTGRES_PASSWORD` from the same `.env`; recreate both |
| Caddy cannot get a certificate | DNS not pointing here, or 80/443 blocked | ACME needs inbound 80; check `docker compose logs caddy` |
| Everyone gets 403 | `OPERATOR_CIDRS` too narrow, or Caddy is behind a load balancer | see §7 of the README — `remote_ip` sees the balancer, not the client |
| A startup warning about all scopes | `SIG_STORE_TOKEN` is set | unset it; use the four scoped tokens |

### Do not

- Publish the Postgres port. It is deliberately absent from the compose file.
- Put `SIG_STORE_ADMIN_TOKEN` on any machine. Generate it here, keep it offline,
  use it from an operator workstation.

---

## 2. indexer

Machine 1, co-located with the store.

### What it does

Read-only against every chain. Never signs, never sends a transaction. It exists
so every transfer is visible in the database **including those with zero
validator signatures**, which are invisible to the signature-store view by
construction.

It is also the **sole writer of `refund_status`**, and the sole writer of the
`cancelled`/`refunded` lifecycle — which it sets only from observed on-chain
events. The sig-store deliberately exposes no HTTP route for those states,
because a forged "refunded" would hide a stuck transfer from every relayer.

### What breaks without it

Transaction history, stuck detection, and **the entire refund path**. The
validators' refund loop only ever sees candidates the store has nominated, and
`sweep_refund_eligible` is called from the indexer and nowhere else. Without it,
stranded transfers stay stranded silently — nothing errors.

### Why it shares the store's machine

It is the only component besides sig-store that needs a Postgres credential.
Moving it elsewhere means shipping that credential off-host **and** exposing the
database port. It still runs as its own stack — own compose file, own restart,
own logs — so it is operated separately; it just shares the host.

### Start it

```bash
cd indexer
cp .env.example .env                              # DATABASE_URL, same password as store/.env
cp configs/indexer.toml.example configs/indexer.toml   # one [[chains]] per chain
chmod 600 .env
docker compose up -d
```

It attaches to the `bridge-core` network the store stack created, so `postgres`
resolves without a published port. **Start the store first** or the network will
not exist.

### Verify

```bash
docker compose ps                    # Up, not restarting
docker compose logs indexer --since 5m
```

Then confirm it is actually writing, through the store's read scope:

```bash
curl -s -H "Authorization: Bearer $SIG_STORE_READER_TOKEN" \
     https://sig-store.example.com/history | jq 'length'
```

That count should grow as transfers happen. It includes transfers with zero
signatures, which is the whole reason this process exists.

### Failures

| Symptom | Cause | Fix |
| --- | --- | --- |
| `network bridge-core declared as external, but could not be found` | the store stack is not up | start `store/` first |
| Connection refused to `postgres` | not on the shared network | check the `networks:` block was not edited |
| Refunds never become eligible | this process is not running, or `refund_timeout_secs` is longer than you think | check `docker compose ps`; the value is in seconds |

### Tuning

`refund_timeout_secs` nominates candidates. It does **not** authorise anything —
each validator establishes the age itself, on-chain, before attesting a cancel.
Set it to match the validators' `[refund] timeout_secs` so the two agree on
intent. Hours in production, comfortably above real claim latency on your
slowest corridor.

---

## 3. validator

Machines 2..N — **one per independent operator**, on hardware that operator
controls.

### What it does

The only process holding signing authority, and the only one whose output the
Gate will accept. Per source chain it runs an independent scan loop: fetch `Sent`
logs up to `latest - block_confirmation`, check the nonce is sequential for that
corridor, **independently recompute the `submissionId`** under the
`bridgeDomain` it reads from the gate itself, check the allowlist, sign, store.

### The thing that actually makes the threshold real

Three validators reading the same chain through the **same RPC provider** are not
three independent observers — they are one observer signing three times, and a
provider that serves a wrong log makes all three sign it. The threshold then
counts signatures, not independent confirmations.

Every operator must use their own endpoints. This is the single highest-value
line in this document.

### Start it

```bash
cd validator
cp .env.example .env                                     # token + operator API token
cp configs/validator.toml.example configs/validator.toml # your chains, YOUR rpcs
# create the keystore — see secrets/README.md
chmod 600 .env
./preflight.sh && docker compose up -d
docker compose logs -f validator
```

### Healthy

In this order:

```
INFO bridge_core::signer: loaded signer from encrypted keystore role="validator"
     signer=0x7099… keystore=/run/secrets/validator_keystore
INFO validator: validator started validator=0x7099… sources=1 sink=http(sig-store)
INFO validator::api: operator API listening bind=0.0.0.0:9090
INFO validator::api: operator API auth enabled: bearer token required for pause/resume/rescan
INFO validator: source scan loop started validator=0x7099… gate=0x6170…
     bridge_domain=0x619244a6… chain_id=11155111 rpc=https://… endpoints=1
     resume_from=11581995
```

Three things to read there:

- **`sink=http(sig-store)`** — it is using the remote store, not a local
  directory. If this says `file://…` your `[store]` block has `dir` set.
- **`bridge_domain`** — read from the gate, not from config. It must be
  identical across every validator and every gate in the mesh, including the
  Solana one. A mismatch means ids never line up and nothing is ever claimed —
  silently.
- **one `source scan loop started` per configured chain.**

If you omitted `[refund]` you will also see, correctly:

```
INFO validator: no [refund] block — this validator will not attest cancels or refunds
```

That is a safe default, not a degraded one: a node that cannot independently
read the destination chain must not have an opinion on whether a transfer was
delivered.

### Working

```
INFO validator: SIGNED and stored submission_id=0x6cf1b32c… nonce=6 chain_to=7565164
```

Or, when the allowlist blocks it:

```
WARN validator: BLOCKED by allowlist — withholding signature (nonce advanced)
     submission_id=0x6cf1b32c… debridge_id=0x87daa69d… chain_from=11155111 chain_to=7565164
```

That is correct behaviour. The signature is withheld so the transfer can never
reach threshold; the nonce is still consumed because the transfer really
happened on-chain and the per-corridor sequence must stay intact.

### Verify from outside

The ground truth for "is my validator participating" is whose addresses appear
in the store:

```bash
curl -s -H "Authorization: Bearer $SIG_STORE_READER_TOKEN" \
     https://sig-store.example.com/submissions \
  | jq -r '.[-5:][] | "\(.submission_id) \(.signatures | map(.signer) | join(" "))"'
```

A validator that is running, unpaused and caught up but whose address never
appears is **not reaching the store** — check its token and `[store] url` before
suspecting the scanner.

### Operator API

Bound to host loopback only. Reach it over SSH.

```bash
curl -s http://127.0.0.1:9090/status | jq          # open, no token
curl -s -X POST -H "Authorization: Bearer $VALIDATOR_API_TOKEN" \
     http://127.0.0.1:9090/pause
curl -s -X POST -H "Authorization: Bearer $VALIDATOR_API_TOKEN" \
     http://127.0.0.1:9090/resume
curl -s -X POST -H "Authorization: Bearer $VALIDATOR_API_TOKEN" \
     -H 'content-type: application/json' -d '{"from_block": 11582100}' \
     http://127.0.0.1:9090/rescan
```

`/status` returns the cursor, the pause state and reason, and the per-corridor
nonce map. `/pause`, `/resume` and `/rescan` take the bearer token and accept an
optional `/{chain_id}` suffix.

### A pause is a real safety stop

The scanner pauses itself on a nonce gap, a nonce replay, or a `submissionId`
mismatch — each meaning an RPC lied or events were missed.

**The pause survives a restart.** It is serialized to `state_file`, and the
process logs the reason on the way back up. Restarting is not a way to clear it
and must not be used as one. Diagnose the cause, then `/resume`.

### Failures

| Symptom | Cause | Fix |
| --- | --- | --- |
| `Permission denied (os error 13)` on a secret | uid 10001 cannot read it | §0.4, or run `./preflight.sh` |
| `block_confirmation = 0` refusal at startup | fail-closed guard | set it above the chain's reorg depth |
| `unknown field` at startup | a typo in the TOML | `deny_unknown_fields` is deliberate; fix the key |
| Signs nothing, no errors | wrong `bridge_domain` (wrong gate), or the allowlist blocks everything | compare the logged domain against another validator's |
| `allowlist fetch failed; skipping batch` | store unreachable | fail-closed by design; fix connectivity |
| Comes up paused | a real anomaly, persisted | read `pause_reason` from `/status` |

### Tuning

`catchup_poll_interval_ms` is optional and applies **only while behind**. It
defaults to `poll_interval_ms`, deliberately. Reading back-to-back clears a fast
chain's backlog in minutes instead of hours, but on a shared rate-limited
endpoint it starves every other consumer of the same key — including the API's
pool reads — and the symptom is 429s in unrelated services, not slowness here.
Lower it only for an endpoint you know can take it.

---

## 4. keeper

Machine 5. Permissionless — anyone can run one.

### What it does

Holds a funded gas-payer key and **no other authority**. Every transaction it
sends is re-verified on-chain by `Gate._verifySignatures` before anything moves,
so a hostile keeper can waste its own gas, delay delivery, or reorder ready
transfers — it cannot move funds the validators did not already authorise.

That is why **running more than one is safe** and is the normal way to get
redundancy: each submit path re-reads on-chain state first, so the loser of a
race sees `executed == true` and does nothing.

### Two lists, and mixing them up is the classic mistake

```
[[targets]]   where transfers are DELIVERED.  Claims and cancels run here.
[[sources]]   where funds were LOCKED.        Refunds run here.
```

A keeper with no `[[sources]]` **never submits a refund**, and nothing warns you
at runtime — the transfers simply sit in the candidate list. For a full mesh
every chain usually appears in both lists.

### Start it

```bash
cd keeper
cp .env.example .env
cp configs/keeper.toml.example configs/keeper.toml
chmod 600 .env
./preflight.sh && docker compose up -d
```

### Healthy

```
INFO bridge_core::signer: loaded signer from encrypted keystore role="keeper" signer=0x15d3…
INFO keeper: keeper started keeper=0x15d3… targets=1 sources=1 source=http(sig-store)
INFO keeper: source refund loop started keeper=0x15d3… gate=0x6170… chain_id=11155111
     threshold=2 validator_count=2
INFO keeper: target loop started keeper=0x15d3… gate=0x09aC… chain_id=560048
     threshold=2 validator_count=2
```

`threshold` and `validator_count` are read from the gate. If they do not match
what you deployed, this keeper is pointed at the wrong contract.

You get one `target loop started` per `[[targets]]` and one
`source refund loop started` per `[[sources]]`. Count them.

### The signal that the cross-machine link is broken

```
WARN keeper: allowlist fetch failed; skipping tick
```

every poll interval. Fail-closed by design — it will not claim against a stale
allowlist. Check the store URL and the keeper token.

### Failures

| Symptom | Cause | Fix |
| --- | --- | --- |
| `claim failed` every tick | out of gas on that chain | fund the keeper address |
| Nothing is ever claimed, no errors | quorum not reached | check `signatureCount` vs threshold in the API |
| Refunds never submitted | no `[[sources]]` block | add one per source chain |
| Startup warning about one chain in both lists | expected for a bidirectional corridor | harmless; split the roles if it is busy |

### Keep it funded

A hot wallet. Monitor the balance on every chain in both lists, and keep no more
than a few days of gas on it.

---

## 5. api

Machine 6. The only machine exposed to the open internet.

### What it does

Serves the SPA and the GraphQL read API. nginx proxies `/graphql` and `/health`
to `graphql-api` over the stack's private network, so the browser talks to the
backend same-origin and there is no CORS configuration anywhere.

### Deliberately the least privileged

- It holds `SIG_STORE_READER_TOKEN` and nothing else. Read scope: no signature
  deposits, no mark-claimed, no allowlist writes.
- `graphql-api` holds **no database credential**. It reads history through the
  sig-store's read scope. Do not hand it a `DATABASE_URL` even when running it by
  hand.
- Mutations are off. `--allow-mutations` would expose `submitSignature`. Leave
  it off.

### Start it

```bash
cd api
cp .env.example .env
cp configs/chains.json.example configs/chains.json
chmod 600 .env
docker compose up -d
```

### The repeatable flags

`--gate` and `--swap` may each appear many times, which compose cannot template
from a single value, so they are word-split by a shell:

```bash
GRAPHQL_GATES=--gate 1=https://rpc,0xGate1 --gate 56=https://rpc2,0xGate56
GRAPHQL_SWAPS=--swap 1=https://rpc,0xPool1,18000000,1000
```

Space-separated, no quotes inside the value. A Solana entry is recognised by its
base58 (non-`0x`) address.

### Healthy

```
NAME                  SERVICE       STATUS
api-graphql-api-1     graphql-api   Up 30 seconds (healthy)
api-frontend-1        frontend      Up 20 seconds
```

Plus `caddy` as `Up`. (Same caveat as §1: the rows above come from a run without
public DNS, so Caddy was not started. The Caddyfile itself passes
`caddy validate`.)

`frontend` will not start until `graphql-api` is healthy.

### Verify

```bash
curl -s -o /dev/null -w 'HTTP %{http_code}\n' https://bridge.example.com/     # 200
curl -s https://bridge.example.com/health                                     # ok
```

Then the two reads that exercise different paths:

```bash
# reads the REMOTE store with the read token
curl -s -X POST https://bridge.example.com/graphql -H 'content-type: application/json' \
  -d '{"query":"{ stats { total } submissions { submissionId signatureCount meetsThreshold } }"}'

# a LIVE on-chain read — this is what proves the --gate/--swap wiring works
curl -s -X POST https://bridge.example.com/graphql -H 'content-type: application/json' \
  -d '{"query":"{ pools(chainId: 1) { token symbol decimals reserve price isStable } }"}'
```

A real response to the second looks like:

```json
{"data":{"pools":[{"token":"0xf66247c6…","symbol":"TST","decimals":18,
"reserve":"1000000000000000000000000","price":"1000000000000000000","isStable":true}]}}
```

### Failures

| Symptom | Cause | Fix |
| --- | --- | --- |
| `pools` returns `null` | no `--swap` for that chain | add it to `GRAPHQL_SWAPS` |
| 502 from nginx after recreating the API | stale DNS | already handled — the config uses a variable upstream and a resolver |
| Empty token lists that come and go | RPC rate limiting (429s) | lower `GRAPHQL_MAX_BLOCK_RANGE`, or check whether a scanner's catch-up is eating the budget |
| `stats` errors | reader token wrong, or store unreachable | check `SIG_STORE_URL` and the token |

---

## 6. solana-relayer

Beside each `validator/` (sign-only) and beside the `keeper/` (deliver-too).
Only if your mesh includes Solana.

### What it is

The Solana leg's validator. A **separate binary and image** — `solana-client`
pins `zeroize <1.4` and alloy needs `^1.5`, so it cannot share a binary with the
EVM services.

It shares the **same secp256k1 signing key** as the EVM validator beside it (one
validator set attests for both VMs) and the same store and token.

### Two shapes

**Sign-only** — the validator role. One per operator:

```bash
cd solana-relayer
cp .env.example .env                                          # token + THE SAME key
cp configs/solana-relayer.toml.example configs/solana-relayer.toml
chmod 600 .env
./preflight.sh && docker compose up -d
```

**Deliver-too** — adds the EVM→Solana keeper role. Run **one** for the whole
mesh, on the keeper machine:

```bash
cp configs/solana-relayer.deliver.toml.example configs/solana-relayer.toml
# fund a Solana payer keypair into secrets/payer.json
./preflight.sh
docker compose -f docker-compose.yml -f docker-compose.deliver.yml up -d
```

### Healthy — sign-only

```
INFO solana_relayer: no [target] block — this relayer signs but never delivers claims
INFO solana_relayer: solana-relayer started validator=0x364f…
INFO solana_relayer::refund: solana refund attester started (destination-side)
     validator=0x364f… chain_id=7565164
INFO solana_relayer::source: solana source scanner started validator=0x364f…
     program=HvGQ… bridge_domain=619244a6… commitment=finalized resume_after=None
INFO solana_relayer::source: no cursor — replaying the program's full history (signing is idempotent). …
```

On first start (or after the state volume is lost) the relayer walks the
program's whole history and signs anything not yet signed — a lost cursor no
longer skips transfers. A history deeper than 10,000 signatures stops the
relayer with an error: restore the state file, or set
`[source].start_at_tip = true` only if every older transfer is known settled.

The `bridge_domain` here must equal the one your EVM validators log. On a live
mesh it does — same value across both VMs.

The refund attester starts **unconditionally**, unlike the EVM validator where
omitting `[refund]` disables it. It has to: the EVM validators cannot read
Solana, so without it nobody votes on whether an undeliverable EVM→Solana
transfer may be burned.

### Healthy — deliver-too

Additionally:

```
INFO solana_relayer::target: solana claim submitter started payer=EgZc1wGa… program=HvGQ…
INFO solana_relayer::target: gate requires 2 signatures; THIS process contributes 1 —
     2 relayers must run, each with a distinct validator key, or Solana-origin
     transfers never reach quorum threshold=2 validators=2
```

That last line is your check that enough relayers exist. One per validator
operator, exactly as on the EVM side.

### Working

```
INFO solana_relayer::source: SIGNED and stored submission_id=0x229f590d… nonce=0 chain_to=11155111
```

Blocked by the allowlist:

```
WARN solana_relayer::source: BLOCKED by allowlist — withholding signature
     submission_id=0x229f590d… debridge_id=0x4b734721… chain_from=7565164 chain_to=11155111
```

Store unreachable — fail-closed:

```
WARN solana_relayer::source: scan tick failed; retrying
     error=fetching the allowlist; skipping tick rather than signing on a stale view
```

It recovers on its own when the store returns; no restart needed.

### Two things that are weaker here

**No keystore.** `[signer]` accepts only `private_key` / `private_key_env`, so
the validator key lives in `.env` as an environment variable. Keep it at `0600`
and treat the host accordingly. Never put `private_key` inline in the TOML —
that file is mounted into the container. `preflight.sh` rejects it.

**No operator API.** There is no `/status`, `/pause`, `/resume` or `/rescan`. To
rewind the cursor, stop the container and edit the state file on the
`solana-relayer-state` volume. `down -v` deletes the cursor, so the relayer
replays the program's history on the next start (see above) — it does not jump
to the tip unless `[source].start_at_tip = true`.

### Failures

| Symptom | Cause | Fix |
| --- | --- | --- |
| Refuses to start over commitment | `commitment` weaker than `finalized` | correct only on a local test validator |
| `backlog exceeds … signatures` | fell too far behind | raise `max_batch`, or investigate the stall — it refuses to skip history |
| Signs nothing, no errors | wrong `program_id`, or everything is allowlist-blocked | compare `bridge_domain` against the EVM validators |
| `scan tick failed … stale view` repeating | store unreachable | fail-closed; fix connectivity |

---

## 7. Cross-cutting operations

### 7.1 Upgrading a binary

Roll validators **one at a time** and confirm each is signing again before
moving on. With threshold T of N you can lose N−T without stopping delivery, so
one at a time is always safe.

```bash
# edit BRIDGE_IMAGE (or RELAYER_IMAGE) in .env, then
docker compose pull
docker compose up -d --force-recreate
docker compose logs -f validator      # wait for "source scan loop started"
```

State lives on named volumes and survives a recreate. Never `down -v` to
upgrade.

### 7.2 Changing the allowlist

Two allowlists, both enforced at signing (validator and solana-relayer) and
again at claiming (keeper). Changes take effect **without a restart** — every
process refetches per tick.

```bash
curl -X POST -H "Authorization: Bearer $SIG_STORE_ADMIN_TOKEN" \
     -H 'content-type: application/json' \
     -d '{"chain_id":1,"token":"0xToken","symbol":"TST"}' \
     https://sig-store.example.com/allowed/tokens

curl -X POST -H "Authorization: Bearer $SIG_STORE_ADMIN_TOKEN" \
     -H 'content-type: application/json' \
     -d '{"chain_id_from":1,"chain_id_to":56}' \
     https://sig-store.example.com/allowed/chains
```

**Opt-in semantics.** An empty list allows everything; the first row flips that
list to deny-by-default. The two lists are independent. `bridge_db` refuses to
delete the last row of either, because pruning row by row would otherwise cross
back to allow-everything with no error and no log.

**Understand what de-listing does and does not do.** It stops *new* signatures.
It does **not** retract signatures already collected: the store is append-only,
`Gate.claim` is permissionless, and the signatures are public. Anything already
at quorum stays claimable. De-listing is a forward-looking policy control, not
an incident kill-switch. The kill-switch is `Gate.pause()` — on-chain, callable
by owner or guardian, and it halts `send` and `claim` for that whole chain.

### 7.3 Volumes, and which ones matter

| Volume | Stack | Losing it means |
| --- | --- | --- |
| `pgdata` | store | all history, allowlists, refund lifecycle. **Back this up.** |
| `validator-state` | validator | rescan from `start_block`, and a pause an operator has not yet cleared |
| `solana-relayer-state` | solana-relayer | rescan from the program's current signature history |
| `caddy-data` | store, api | certificates; they re-issue, subject to ACME rate limits |

`docker compose down -v` destroys them. Use plain `down` unless you mean it.

Never point two hosts at shared storage for a validator's state file.

### 7.4 When something is wrong, check in this order

1. **The store is reachable** — `curl https://sig-store.example.com/health`.
2. **Who is signing** — the signer addresses in `/submissions`. This answers
   "are my validators connected" better than any local log.
3. **Each validator's `/status`** over SSH — cursor moving? paused, with a
   reason?
4. **The keeper's logs** — `allowlist fetch failed` means the link is down;
   `claim failed` usually means gas.
5. **Only then** the chain RPCs.

Most cross-machine problems are a wrong token or a wrong `[store] url`, and step
2 distinguishes those from a scanner problem in one command.
