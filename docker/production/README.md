# Production deployment — one stack per machine

Six compose stacks, meant to run on **different hosts**. Each directory is
self-contained: copy it to its machine, fill in its `.env`, `docker compose up -d`.

This is the distributed counterpart to the single-host `docker-compose.yml` at
the repo root (local development) and `docker/testnet-mesh5/` (a generated
testnet stack). Nothing here is generated — these are hand-written templates,
because a production topology is not something a script should guess at.

Read [`docs/architecture.md`](../../docs/architecture.md) §4.2–4.8 and
[`docs/operations.md`](../../docs/operations.md) §5 first. This README assumes
you know what each process does.

**Standing in front of one machine?** [`RUNBOOK.md`](./RUNBOOK.md) is the
per-element reference: what each stack does, the exact commands, what a healthy
start looks like line by line, how to verify it, and what the failures actually
look like. This README is the deployment as a whole; that one is the machine in
front of you.

---

## 1. The topology

```
                        ┌──────────────────────────────────────┐
   machine 1            │  store/         Postgres             │
   (the hub)            │                 sig-store            │
                        │                 caddy  :443 ─────────┼──┐
                        │  indexer/       indexer              │  │
                        └──────────────────────────────────────┘  │
                                                                  │  HTTPS
   machine 2  ┌─ validator/ ── validator (operator A) ────────────►│  + bearer
   machine 3  ├─ validator/ ── validator (operator B) ────────────►│    token
   machine 4  └─ validator/ ── validator (operator C) ───────────►│
                                                                  │
   machine 5     keeper/ ───── keeper ───────────────────────────►│
                                  └──► Gate.claim() on-chain      │
                                                                  │
   machine 2..4  solana-relayer/ sign-only, per validator ───────►│
   machine 5     solana-relayer/ + [target], with the keeper ────►│
                                  └──► gate claim on Solana       │
                                                                  │
   machine 6     api/ ───────── graphql-api + frontend + caddy ──►┘
                                  ▲
                                  └── the public internet
```

The Solana leg is a **separate binary and image**, not a config variant of the
EVM validator: `solana-client` pins `zeroize <1.4` and alloy needs `^1.5`, so the
two dependency trees cannot share a binary. It runs *beside* the EVM stacks on
the same machines, sharing their signing key and their store — see §3.6.

**Validators never talk to each other.** There is no peer list to configure, no
gossip port to open, no consensus round between them. Every arrow above points
at the store, and that is the whole of the coordination. Adding validators means
adding machines that each point at the same URL — nothing on the existing hosts
changes.

**The store is a rendezvous point, not an authority.** It re-derives every
`submissionId` from its own parameters and ecrecovers every signature before
storing it, and `Gate._verifySignatures` verifies the quorum again on-chain at
claim time. Whoever runs machine 1 can **censor** — withhold signatures, stall
transfers, which the two-phase refund exists to recover from. They cannot
**forge**. That property is what makes a central hub an acceptable design here.

---

## 2. Which machine gets which secret

This table is the security design. Nothing else in this directory matters as
much as getting it right.

| Machine | Holds | Explicitly does NOT hold |
| --- | --- | --- |
| 1 store | Postgres password, all four scoped tokens | any chain signing key |
| 1 indexer | Postgres password | any token, any signing key |
| 2..4 validator | its own **signing key**, its OWN `SIG_STORE_VALIDATOR_TOKEN` (one entry of the store's `SIG_STORE_VALIDATOR_TOKENS`) | Postgres, keeper key, admin token |
| 5 keeper | its own **funded gas key**, `SIG_STORE_KEEPER_TOKEN` | Postgres, any validator key, sign scope |
| 2..4 solana-relayer | the **same secp256k1 key** as the EVM validator beside it, `SIG_STORE_VALIDATOR_TOKEN` | Postgres, a Solana payer keypair |
| 5 solana-relayer | a **funded Solana payer keypair**, a validator key, `SIG_STORE_VALIDATOR_TOKEN` | Postgres, admin token |
| 6 api | `SIG_STORE_READER_TOKEN` | Postgres, every other token, every key |

`SIG_STORE_ADMIN_TOKEN` is generated on machine 1 and then belongs **nowhere**.
Keep it offline and use it from an operator workstation for allowlist changes.
Allowlist management is itself a security control; it is not a service
credential.

Never set `SIG_STORE_TOKEN` anywhere. It is the legacy all-scopes secret and
grants read + sign + relay + admin to whoever holds it; the sig-store logs a
warning at startup when it is set.

---

## 3. Bring-up order

Machine 1 must be reachable before the others do anything useful, but nothing
breaks if you start out of order — validators retry their store writes, and the
keeper skips a tick rather than submitting against a stale allowlist.

### 3.1 Build the image once

Every machine should run a byte-identical binary. Build once and push:

```bash
# from the repo root, on a build host
TAG=$(git rev-parse --short HEAD)
docker build -t registry.example.com/selendra/bridge:$TAG .
docker build -t registry.example.com/selendra/bridge-frontend:$TAG \
             -f docker/Dockerfile.frontend .
# The Solana relayer needs its OWN image: solana-client pins zeroize <1.4 while
# alloy needs ^1.5, so it cannot share a binary — or a cargo workspace — with
# the EVM services.
docker build -t registry.example.com/selendra/bridge-relayer:$TAG \
             -f docker/Dockerfile.relayer .
docker push registry.example.com/selendra/bridge:$TAG
docker push registry.example.com/selendra/bridge-frontend:$TAG
docker push registry.example.com/selendra/bridge-relayer:$TAG
```

Then set `BRIDGE_IMAGE` (plus `FRONTEND_IMAGE` on machine 6 and `RELAYER_IMAGE` wherever the Solana leg runs) to that exact tag in
each `.env`. Pin a digest or an immutable tag, not `latest` — a validator fleet
silently split across two binary versions is a bad way to spend an afternoon.

If you skip the registry, each stack falls back to building from the repo, which
requires the full source tree on every machine.

### 3.2 Machine 1 — the store

```bash
scp -r docker/production/store  machine1:~/bridge-store
scp -r docker/production/indexer machine1:~/bridge-indexer

ssh machine1
cd ~/bridge-store
cp .env.example .env
# generate five independent secrets
for v in POSTGRES_PASSWORD SIG_STORE_KEEPER_TOKEN \
         SIG_STORE_READER_TOKEN SIG_STORE_ADMIN_TOKEN SIG_STORE_INDEXER_TOKEN; do
  echo "$v=$(openssl rand -hex 32)"
done
# ONE Sign token per validator machine / Solana relayer (audit M7-11); hand
# each operator only their own, as SIG_STORE_VALIDATOR_TOKEN in their .env.
echo "SIG_STORE_VALIDATOR_TOKENS=$(for op in op-a op-b op-c; do
  printf '%s:%s,' "$op" "$(openssl rand -hex 32)"; done | sed 's/,$//')"   # paste into .env, then set SIG_STORE_DOMAIN / ACME_EMAIL / OPERATOR_CIDRS
chmod 600 .env
docker compose up -d
curl -fsS https://sig-store.example.com/health    # from an allowlisted IP
```

`OPERATOR_CIDRS` must list every other machine's egress IP. It is a second,
independent control alongside the bearer tokens: the token proves *which role*
is calling, the allowlist bounds *who can try at all*, so a leaked token is not
immediately usable from the open internet.

Then the indexer, on the same host:

```bash
cd ~/bridge-indexer
cp .env.example .env          # DATABASE_URL uses the password from store/.env
cp configs/indexer.toml.example configs/indexer.toml   # one [[chains]] per chain
chmod 600 .env
docker compose up -d
```

The indexer is co-located deliberately — it is the only component besides
sig-store needing a Postgres credential, and moving it off-host means shipping
that credential over the network *and* exposing the database port. Its compose
file documents the remote alternative if you must.

Do not skip it. It is the **sole writer of `refund_status`**, so without it the
refund candidate list never populates and stranded transfers stay stranded.

### 3.3 Machines 2..4 — one validator per operator

Each operator does this independently, on their own hardware, with their own
key and their own RPC endpoints:

```bash
cd ~/bridge-validator
cp .env.example .env                                     # SIG_STORE_VALIDATOR_TOKEN
cp configs/validator.toml.example configs/validator.toml # your chains, YOUR rpcs
# create the keystore — see secrets/README.md
chmod 600 .env
./preflight.sh && docker compose up -d
docker compose logs -f validator      # expect "source scan loop started" per chain
```

**Run `./preflight.sh`.** Docker compose bind-mounts file-secrets with the host
file's ownership and **ignores** the `uid`/`gid`/`mode` long syntax outside swarm
mode. The image runs as uid 10001, so a keystore left at your-user:0600 is
unreadable in the container and the only symptom is a restart loop logging
`Permission denied (os error 13)`. preflight checks for it and prints the two
correct shapes (`chown 10001` + 0600, or a 0700 `secrets/` dir + 0644 files).

A healthy start logs, in order: `loaded signer from encrypted keystore`, then
`validator started … sink=http(sig-store)` — confirming it is using the REMOTE
store, not a local directory — then one `source scan loop started` per chain,
each showing the `bridge_domain` it read from that gate.

**The threshold is only as real as the independence behind it.** Three
validators reading the same chain through the same RPC provider are not three
independent observers — they are one observer signing three times, and a
provider serving a wrong log makes all three sign it. Different keys on the same
endpoint buys you nothing. Give each operator their own provider, and run your
own node where the corridor's value justifies it.

`block_confirmation` is per-operator, not a fleet constant. Operators on slower
or less-trusted endpoints should sit further from the tip; nobody has to agree,
and a more conservative validator simply signs later.

### 3.4 Machine 5 — the keeper

```bash
cd ~/bridge-keeper
cp .env.example .env                                 # SIG_STORE_KEEPER_TOKEN
cp configs/keeper.toml.example configs/keeper.toml   # [[targets]] AND [[sources]]
chmod 600 .env
./preflight.sh && docker compose up -d
```

Same keystore-permission rule as the validator; `./preflight.sh` covers it. A
healthy start logs `keeper started … source=http(sig-store)` followed by one
`target loop started` / `source refund loop started` per chain, each reporting
the `threshold` and `validator_count` it read from that gate. If the store is
unreachable or the token is wrong you get `allowlist fetch failed; skipping
tick` every poll — fail-closed, and the clearest signal that the cross-machine
link is broken.

Two mistakes to avoid here:

- **`[[targets]]` and `[[sources]]` are different lists.** Claims and cancels run
  on the destination; refunds run where funds were locked. A keeper with no
  `[[sources]]` never submits a refund and nothing warns you at runtime — the
  transfers just sit in the candidate list.
- **Fund the key on every listed chain.** A claim loop out of gas logs
  `claim failed` each tick and delivers nothing. Monitor the balance; keep no
  more than a few days of gas on a hot wallet.

Running a second keeper is safe and is the normal way to get redundancy: each
submit path re-reads on-chain state first, so the loser of a race sees
`executed == true` and does nothing.

### 3.5 Machine 6 — the public surface

```bash
cd ~/bridge-api
cp .env.example .env                                # SIG_STORE_READER_TOKEN only
cp configs/chains.json.example configs/chains.json
chmod 600 .env
docker compose up -d
```

`GRAPHQL_GATES` and `GRAPHQL_SWAPS` hold repeatable `--gate` / `--swap` flags,
word-split by a shell because compose cannot template a repeated flag from one
variable. Space-separated, no quotes inside the value.

This box is the most exposed and the least privileged: read scope only, no
database credential, mutations off. Keep it that way.

### 3.6 The Solana leg — `solana-relayer/`

Only if your mesh includes Solana. It is a **separate binary and image** from the
EVM validator, not a config variant, and it runs *beside* the EVM stacks rather
than on a machine of its own.

**What it shares with the EVM validator:** the secp256k1 signing key — the same
key, so one validator set signs for both VMs — and the sig-store with
`SIG_STORE_VALIDATOR_TOKEN`. Its `[store] token_env` defaults to that variable
because this process does exactly what a validator does: it signs.

**What differs**, all deliberate:

| | EVM `validator/` | `solana-relayer/` |
| --- | --- | --- |
| Sources | `[[sources]]`, repeatable | `[source]`, exactly one |
| Finality | `block_confirmation` (blocks) | `commitment = "finalized"` |
| Cursor | last block number | last **transaction signature** |
| Key custody | encrypted keystore | **env var only — no keystore** |
| Refunds | `[refund]`; omit ⇒ never attests | **always on**, no config block |
| Operator API | `/status` `/pause` `/resume` `/rescan` | none |
| Keeper role | separate `keeper/` machine | optional `[target]`, same process |

Two deployment shapes, and you should be deliberate about which you run.

**Sign-only — the validator role.** One per operator, on the same machine as
that operator's `validator/` stack, using the same key:

```bash
cd ~/bridge-solana-relayer
cp .env.example .env                                          # token + THE SAME key
cp configs/solana-relayer.toml.example configs/solana-relayer.toml
chmod 600 .env
./preflight.sh && docker compose up -d
```

Expect `no [target] block — this relayer signs but never delivers claims`,
then `solana refund attester started`, then `solana source scanner started`
reporting the `bridge_domain` it read from the gate program. That domain must be
**identical** to the one your EVM validators log — it is the same value across
every gate in the mesh, and a mismatch means the ids will never line up.

**Deliver-too — adds the EVM→Solana keeper role.** Run exactly **one** of these
for the whole mesh, on the keeper machine:

```bash
cp configs/solana-relayer.deliver.toml.example configs/solana-relayer.toml
# fund a Solana payer keypair into secrets/payer.json — see secrets/README.md
./preflight.sh
docker compose -f docker-compose.yml -f docker-compose.deliver.yml up -d
```

It logs `solana claim submitter started payer=…` and then, usefully, how many
signatures it contributes against the gate's threshold:

```
gate requires 2 signatures; THIS process contributes 1 — 2 relayers must run,
each with a distinct validator key, or Solana-origin transfers never reach quorum
```

That is the check that you have enough relayers. One relayer per validator
operator, exactly as on the EVM side.

**Key custody is weaker here, and you should know it.** `solana-relayer`'s
`[signer]` accepts only `private_key` and `private_key_env` — there is no
encrypted-keystore option, so nothing corresponds to the `validator/` and
`keeper/` stacks' `/run/secrets` keystore. Use `private_key_env` so the key at
least stays off the container filesystem, keep `.env` at 0600, and treat that
host accordingly. Never put `private_key` inline in the TOML: that file is
mounted into the container and is far easier to leak than an env var. preflight
rejects an inline key.

**The relayer enforces the allowlist**, exactly as the EVM validator does: it
withholds its signature for a de-listed token or corridor, and fails closed
(skips the tick) if the allowlist cannot be fetched. That matters because
`Gate.claim` is permissionless and the collected signatures are public — the
keeper's pre-claim check only ever bound the keeper, so withholding the
signature is the only thing that actually stops a Solana→EVM transfer.

---

---

## 4. Verifying the fleet actually works together

From an allowlisted host:

```bash
# 1. the store is up and reachable
curl -fsS https://sig-store.example.com/health

# 2. WHO IS ACTUALLY PARTICIPATING — the ground truth
curl -fsS -H "Authorization: Bearer $SIG_STORE_READER_TOKEN" \
     https://sig-store.example.com/submissions \
  | jq -r '.[-5:][] | "\(.submission_id) \(.signatures | map(.signer) | join(" "))"'
```

The signer addresses in that output are the answer to "are my validators
connected?". A validator that is running, unpaused and caught up but whose
address never appears is **not reaching the store** — check its token and its
`[store] url` before suspecting the scanner.

Then, per validator host, over SSH:

```bash
curl -fsS http://127.0.0.1:9090/status | jq
```

`paused: true` with a reason is a **real safety stop that survived a restart** —
a nonce gap, a nonce replay, or a `submissionId` mismatch, each meaning an RPC
lied or events were missed. Restarting does not clear it and must not be used to
try. Diagnose, then:

```bash
curl -fsS -X POST -H "Authorization: Bearer $VALIDATOR_API_TOKEN" \
     http://127.0.0.1:9090/resume
```

### 4.1 A first signature will be withheld until the allowlist is populated

A brand-new store has empty allowlists, and both the validator and the keeper
enforce them. The validator logs, per transfer:

```
BLOCKED by allowlist — withholding signature (nonce advanced)
```

That is correct behaviour, not a misconfiguration: the signature is withheld so
the transfer can never reach threshold, while the nonce is still consumed
because the transfer really did happen on-chain and the per-corridor sequence
must stay intact. Populate the allowlist from an operator workstation with the
admin token — the one credential that lives on no machine in this fleet:

```bash
curl -X POST -H "Authorization: Bearer $SIG_STORE_ADMIN_TOKEN"      -H 'content-type: application/json'      -d '{"chain_id":1,"token":"0xToken","symbol":"TST"}'      https://sig-store.example.com/allowed/tokens

curl -X POST -H "Authorization: Bearer $SIG_STORE_ADMIN_TOKEN"      -H 'content-type: application/json'      -d '{"chain_id_from":1,"chain_id_to":56}'      https://sig-store.example.com/allowed/chains
```

Both take effect without a restart — validators and keepers refetch per tick.
To re-attest transfers that were blocked before the allowlist existed, rewind
one validator at a time:

```bash
curl -X POST -H "Authorization: Bearer $VALIDATOR_API_TOKEN"      -H 'content-type: application/json'      -d '{"from_block": 11582100}' http://127.0.0.1:9090/rescan
```

### 4.2 The end-to-end check

Send a small transfer on a real corridor and watch it appear in `/submissions`
with `threshold` signatures, then land on the destination. The API machine sees
the same thing through GraphQL, which is the check that the read path works too:

```bash
curl -s -X POST https://bridge.example.com/graphql   -H 'content-type: application/json'   -d '{"query":"{ stats { total } submissions { submissionId signatureCount meetsThreshold } }"}'
```

`meetsThreshold: false` with a `signatureCount` below your threshold means some
validators are not signing — check each one's `/status` and its logs for
`BLOCKED by allowlist` or a pause reason.

---

## 5. What was verified before this was committed

These stacks were run against live testnets as five separate compose projects on
isolated Docker networks, reaching each other only over a host IP — the same
code path as separate machines. Confirmed working:

- store: Postgres unpublished, sig-store healthy, scoped tokens enforced over
  the network (reader `GET /submissions` 200; reader `POST /allowed/tokens` 401;
  keeper `POST /submissions` 401; admin allowlist write 200; `/health` open)
- validator: loaded an encrypted keystore, read `bridgeDomain` off a live gate,
  scanned real Sepolia history, **signed a real `Sent` event and posted it to
  the remote store**
- validator operator API: `/status` open on host loopback, `/pause` 401 without
  the token and 200 with it, unreachable from the LAN interface
- keeper: authenticated to the remote store and read `threshold` /
  `validator_count` from two live gates, with no allowlist-fetch failures
- api: SPA served, `/graphql` and `/health` proxied same-origin, `chains` from
  the mounted registry, `stats`/`submissions` read back the validator's
  signature through the remote store, and `pools(chainId:)` performed a live
  on-chain SwapPool read — which is what proves the repeatable `--gate`/`--swap`
  flag wiring works
- solana-relayer, sign-only: logged `no [target] block …`, started the refund
  attester unconditionally, read the same `bridge_domain` off the devnet gate
  program that the Sepolia gate reports, and **signed real devnet `Sent` events
  into the remote store**
- solana-relayer, deliver mode: mounted the payer keypair from
  `/run/secrets/solana_payer`, started the claim submitter, resumed from its
  persisted signature cursor, and reported `gate requires 2 signatures; THIS
  process contributes 1`
- solana-relayer allowlist enforcement, tested against live devnet in both
  directions: with one unrelated row seeded (deny-by-default), three real `Sent`
  events that the previous build had **signed and stored** were instead logged
  `BLOCKED by allowlist — withholding signature` and the store stayed empty;
  after allowlisting the real asset and corridor the same three signed normally.
  Stopping the sig-store produced `scan tick failed … skipping tick rather than
  signing on a stale view` and no signatures, and the loop recovered on its own
  when the store returned.
- both preflight scripts: verified they reject the real uid-10001 permission
  failure, an unfilled `.env`, and a world-readable one
- both Caddyfiles pass `caddy validate`

Not exercised, because this host has no public DNS: ACME certificate issuance
and the `remote_ip` allowlist under real traffic.

---

## 6. Changing the fleet

**Adding a validator.** Stand up another `validator/` machine pointing at the
same store URL, add its egress IP to `OPERATOR_CIDRS` on machine 1, and add its
address to the gates' on-chain validator set. Nothing on the existing validators
changes; they have no peer list. The keeper picks up the new signer within 60
seconds — `GateView` re-reads `threshold`, `validatorCount` and membership on
that interval, so a set change needs no restart.

**Removing one.** Remove it from the on-chain validator set first, then stop the
machine. The keeper drops its signatures from the quorum count automatically
(signatures from non-members are filtered before counting, so a removed
validator's leftovers can never inflate the count or overflow the array).

**Redeploying the gates.** Rotate `bridgeDomain` on every gate in the mesh, and
keep it identical across them. It is hashed into every `submissionId` precisely
so a previous generation's quorum signatures cannot be replayed against a fresh
gate on the same chain pair — which also restarts `nonceTo` at 0. Validators
read it from the contract, so they need no config change, but they **do** need
their `state_file` cursors reset to the new gates' deploy blocks.

---

## 7. Known gaps to close before real value flows

Documented rather than hidden, because you should decide about them
deliberately. (The Solana allowlist gap that used to be listed here is fixed —
the relayer now withholds its signature; see §3.6.)

**One shared validator token.** `crates/sig-store/src/main.rs` exposes a single
`--validator-token`, so every validator presents the same credential. `Auth` is
already a `HashMap<String, HashSet<Scope>>` and supports many tokens per scope —
making the flag repeatable gives each operator a separately revocable one.

Until then, be precise about what a leak of it buys an attacker. It does **not**
let them forge signatures: the store ecrecovers every signature, and the Gate
counts only keys in the on-chain validator set. It does let them write to the
store unattributably and spam it, and it means revoking one operator's access
requires rotating the token for everyone.

**Solana relayer key custody.** No encrypted-keystore option; the validator key
lives in `.env` as an environment variable. See §3.6.

**Caddy behind a load balancer.** `remote_ip` in `store/Caddyfile` sees the
balancer, not the client, so the IP allowlist matches everyone. Put Caddy on a
public IP directly, or switch to `client_ip` with a `trusted_proxies` block for
the balancer's ranges.

---

## 8. Files

```
README.md    this file — the deployment as a whole
RUNBOOK.md   per-element: run, verify, and troubleshoot one stack
store/       docker-compose.yml  Caddyfile  .env.example
indexer/     docker-compose.yml  .env.example  configs/indexer.toml.example
validator/   docker-compose.yml  .env.example  preflight.sh
             configs/validator.toml.example    secrets/README.md
keeper/      docker-compose.yml  .env.example  preflight.sh
             configs/keeper.toml.example       secrets/README.md
api/         docker-compose.yml  Caddyfile  .env.example  configs/chains.json.example
solana-relayer/
             docker-compose.yml  docker-compose.deliver.yml
             .env.example  preflight.sh  secrets/README.md
             configs/solana-relayer.toml.example          (sign-only)
             configs/solana-relayer.deliver.toml.example  (+ [target])
```

Every `.env`, every real `configs/*` and everything under `secrets/` is
gitignored. The `.example` files are the only ones tracked — keep it that way,
and treat any machine holding a filled-in copy as secret material.
