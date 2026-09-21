#!/usr/bin/env bash
# run.sh — one-command launcher for the whole bridge + swap stack, driven by a
# config file (scripts/run.config by default).
#
# Brings up, per the config:
#   * N chains (local anvil, or your own RPCs) — 2, 3, 4, …
#   * Gate + token on each, wired full-mesh for bidirectional bridging between
#     every pair of chains, + an optional SwapPool on one chain
#   * Postgres + sig-store + M validators (threshold) + keeper
#   * optional indexer (history + refund eligibility) and the two-phase refund path
#   * graphql-api (backend) + the React frontend (vite)
#
# Usage:
#   bash scripts/run.sh [config-file]     # default: scripts/run.config
#   bash scripts/stop.sh [config-file]    # tear it all down
#
# Re-running is idempotent: it stops the previous run first.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACTS="$ROOT/contracts"
FRONTEND="$ROOT/frontend"
CONFIG="${1:-$ROOT/scripts/run.config}"

[[ -f "$CONFIG" ]] || { echo "config file not found: $CONFIG" >&2; exit 1; }

# M-8 (audit 2026-09-16): this config is BASH — it carries arrays (`CHAINS`,
# `PUBLIC_RPCS`, `CONFIRMATIONS`), so sourcing it is the format, not an
# oversight, and everything in it runs as you. The JSON-driven launcher is
# scripts/bridge-from-json.sh; use that when the config is data you did not
# write. What this checks is the thing that actually goes wrong: a config file
# somewhere another user can write, which turns `run.sh` into their shell. Same
# ownership rule as `scripts/testing/_rundir.sh:rundir_trusted`, inline because
# run.sh does not depend on the test helpers.
config_trusted() { # $1 file
  local f="$1" d owner mode
  [[ ! -L "$f" ]] || { echo "ERROR: $f is a symlink — refusing to source it" >&2; return 1; }
  d="$(cd "$(dirname -- "$f")" && pwd)"
  for target in "$f" "$d"; do
    owner="$(stat -c %u -- "$target")"; mode="$(stat -c %a -- "$target")"
    [[ "$owner" == "$(id -u)" || "$owner" == 0 ]] \
      || { echo "ERROR: $target is owned by uid $owner, not you — refusing to source $f" >&2; return 1; }
    (( (8#$mode & 8#022) == 0 )) \
      || { echo "ERROR: $target is group/world-writable (mode $mode) — anyone who can write it runs code as you; refusing to source $f" >&2; return 1; }
  done
}
config_trusted "$CONFIG" || exit 1
# shellcheck disable=SC1090
source "$CONFIG"

# --- resolve toolchain onto PATH (auto-detect newest nvm node if unset) ---
if [[ -z "${NODE_BIN:-}" ]]; then
  NODE_BIN="$(ls -d "$HOME"/.nvm/versions/node/*/bin 2>/dev/null | sort -V | tail -1 || true)"
fi
export PATH="${NODE_BIN:+$NODE_BIN:}${FOUNDRY_BIN:-}:${CARGO_BIN:-}:$PATH"

# Not /tmp (M-11, audit round 4): the run dir holds validator/keeper private keys
# in the generated TOMLs, the sig-store tokens and the Postgres password, and
# `systemd-tmpfiles-clean` sweeps /tmp daily — which also loses the validator
# cursors. Everything written here is created 0600 under a 0700 directory.
RUN_DIR="${RUN_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/selendra-bridge/run}"
umask 077
mkdir -p "$RUN_DIR" "$RUN_DIR/pids"
chmod 700 "$RUN_DIR"
ADDR_ENV="$RUN_DIR/addresses.env"     # generated deploy addresses (for the summary + reruns)
REG_JSON="$RUN_DIR/chains.json"       # generated registry the frontend reads via graphql
TOKENS_ENV="$RUN_DIR/tokens.env"      # sig-store tokens + Postgres password, 0600

STORE_URL="http://$BIND_HOST:$STORE_PORT"
GQL_BIND="$BIND_HOST:$GQL_PORT"

say()  { printf '\n\033[1;36m=== %s ===\033[0m\n' "$*"; }
info() { printf '  %s\n' "$*"; }
warn() { printf '\033[1;33m  ! %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

# Long-lived service, detached so it survives this shell.
#
# The pid is recorded by the process ITSELF (`$$` inside the setsid'd shell,
# which then execs into the service), so the file names the real service pid
# even when setsid had to fork. `stop.sh` kills exactly these process groups and
# nothing else — no more `pkill -f vite` (audit round 4, LOW).
# M-8 (audit 2026-09-16): takes ARGV, never a command string. It used to be
# `bash -c "exec $1"` with $1 built from config values, so a host/port/name
# carrying `$(…)` ran as the operator during expansion — the config file is
# presented as pure data and is partly rewritten by deploy-from-json.sh.
# The -c script below is a FIXED literal; every datum arrives as a positional.
#
#   spawn <logfile> -- <command> [args...]
spawn() {
  local log="$1"; shift
  [[ "${1:-}" == "--" ]] || die "spawn: expected -- before the command (internal error)"
  shift
  local name="${log%.log}"
  local pidfile="$RUN_DIR/pids/$name.pid"
  # Recorded for stop.sh's `ours()`, which only ever TOKENISES this to match
  # /proc/<pid>/cmdline. It is never executed.
  printf '%s\n' "$*" > "$RUN_DIR/pids/$name.cmd"
  setsid bash -c 'echo $$ > "$1"; shift; exec "$@"' _ "$pidfile" "$@" \
    >"$RUN_DIR/$log" 2>&1 </dev/null & disown || true
}
need()  { command -v "$1" >/dev/null 2>&1 || die "'$1' not found on PATH (needed for: $2)"; }
rand_token() { openssl rand -hex 32 2>/dev/null || head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
# Read one KEY from a previous run's tokens file (empty if absent).
prev_token() { [[ -f "$TOKENS_ENV" ]] && sed -n "s/^$1=//p" "$TOKENS_ENV" | head -1 || true; }

(( BASH_VERSINFO[0] >= 4 )) || die "bash 4+ required (found $BASH_VERSION); the ASSETS map needs associative arrays"

# back-compat: an old single DEPLOY flag seeds all three sub-flags if the new
# ones aren't set.
if [[ -n "${DEPLOY:-}" ]]; then
  DEPLOY_TOKENS="${DEPLOY_TOKENS:-$DEPLOY}"; DEPLOY_BRIDGE="${DEPLOY_BRIDGE:-$DEPLOY}"; DEPLOY_SWAP="${DEPLOY_SWAP:-$DEPLOY}"
fi
DEPLOY_TOKENS="${DEPLOY_TOKENS:-true}"; DEPLOY_BRIDGE="${DEPLOY_BRIDGE:-true}"; DEPLOY_SWAP="${DEPLOY_SWAP:-true}"

# ---------------------------------------------------------------------------
# parse CHAINS -> CID CNAME CRPC CGATE   (gate optional 4th field)
# ---------------------------------------------------------------------------
CID=() CNAME=() CRPC=() CGATE=() CIMPL=()
declare -A CIDX                                   # chain_id -> array index
for entry in "${CHAINS[@]}"; do
  IFS='|' read -r cid cname crpc cgate <<<"$entry"
  cid="${cid// /}"; cname="$(echo "$cname" | sed 's/^ *//;s/ *$//')"; crpc="${crpc// /}"; cgate="${cgate// /}"
  [[ -n "$cid" && -n "$crpc" ]] || die "bad CHAINS entry: '$entry' (need chain_id|name|rpc)"
  CIDX[$cid]=${#CID[@]}
  CID+=("$cid"); CNAME+=("${cname:-chain $cid}"); CRPC+=("$crpc"); CGATE+=("$cgate")
done

# Browser-facing RPC per chain (H-4, audit round 4). The registry the GraphQL API
# serves to every anonymous client used to carry the SAME url the services use —
# and on a hosted provider that url IS the API key. The API now serves only
# `public_rpc_url` (as `rpcUrl`, or null), never `rpc_url`.
#
#   PUBLIC_RPCS[chain_id]="https://…"   keyless endpoint safe to hand to browsers
#
# Unset: a loopback/anvil url is its own public url (nothing to leak); anything
# else gets NO public url — the UI falls back to the wallet's provider for its
# reads — and a warning, so a live chain is never served a key by accident.
declare -A PUBLIC_RPCS 2>/dev/null || true
is_local_rpc() { [[ "$1" =~ ^https?://(127\.0\.0\.1|localhost|\[::1\]|0\.0\.0\.0)(:[0-9]+)?(/.*)?$ ]]; }
public_rpc_for() {  # $1 chain_id, $2 private rpc -> echoes the public url or nothing
  local cid="$1" rpc="$2"
  if [[ -n "${PUBLIC_RPCS[$cid]:-}" ]]; then echo "${PUBLIC_RPCS[$cid]}"; return; fi
  if is_local_rpc "$rpc"; then echo "$rpc"; return; fi
  warn "chain $cid: no PUBLIC_RPCS[$cid] configured — the UI gets rpcUrl=null for it (the private endpoint is never served)"
}

# Destinations `send` may target beyond the EVM mesh itself (M-3: `send` reverts
# UnsupportedChain for anything the owner has not listed). The Solana gate lives
# in its own config, so its chain id goes here. Idempotent, instant, reversible.
#   EXTRA_SUPPORTED_CHAINS=(7565164)
# `+x` first: run.sh runs under `set -u`.
[[ -n "${EXTRA_SUPPORTED_CHAINS+x}" ]] || EXTRA_SUPPORTED_CHAINS=()

# seal() after wiring (H-1). Irreversible: from then on a NEW corridor needs
# scheduleGovernance + 48h, which is what stops an owner key from draining the
# gate through a fake corridor. `false` keeps the setup phase open — for a
# throwaway anvil mesh you keep adding assets to, never for a gate that holds
# anyone else's funds.
SEAL_GATES="${SEAL_GATES:-true}"

# Per-chain finality buffer. A confirmation COUNT means a different wall-clock
# delay on every chain — 6 blocks is 12s on a 2s chain and 1.5s on Arbitrum's
# ~0.25s blocks — so a mesh of mixed-cadence chains cannot honestly share one
# number. `CONFIRMATIONS[chain_id]` overrides `SOURCE_BLOCK_CONFIRMATION` for
# that chain; unset chains keep the global value, so existing configs are
# unaffected.
declare -A CONFIRMATIONS 2>/dev/null || true
conf_for() {
  local cid="$1"
  echo "${CONFIRMATIONS[$cid]:-$SOURCE_BLOCK_CONFIRMATION}"
}

# How far back scanners start. A fresh anvil begins at block 0, so 0 is right
# locally — but on a live chain it means re-scanning the ENTIRE history before
# reaching anything this deployment did. Sepolia is past 11.4M blocks; at any
# sane range-per-poll that never finishes, and it burns the RPC quota trying.
#
#   START_BLOCKS[chain_id]  explicit height for one chain (e.g. its deploy block)
#   START_BLOCK             "head" to begin at each chain's current tip, or a
#                           literal height applied to every chain
#
# Default: 0 for local anvil, "head" for anything else — fail toward "sees new
# events" rather than "silently busy for hours".
declare -A START_BLOCKS 2>/dev/null || true
: "${START_BLOCK:=$([[ "$LOCAL_ANVIL" == "true" ]] && echo 0 || echo head)}"
start_block_for() {
  local cid="$1" rpc="$2"
  if [[ -n "${START_BLOCKS[$cid]:-}" ]]; then echo "${START_BLOCKS[$cid]}"; return; fi
  if [[ "$START_BLOCK" == "head" ]]; then
    cast block-number --rpc-url "$rpc" 2>/dev/null || echo 0
  else
    echo "$START_BLOCK"
  fi
}

# Blocks per `eth_getLogs` call. Hosted RPCs cap this and REJECT anything wider
# rather than truncating — Alchemy's free tier allows 10 — so an over-wide range
# is a hard failure loop, not a slow scan. 1000 suits a local node.
: "${MAX_BLOCK_RANGE:=1000}"

# How often each scanner polls. 300ms suits an instant-mining anvil, and is
# absurd on a real chain: with a 10-block window on 12s slots it re-requests the
# same range ~40 times per new block, across every validator AND the indexer AND
# every chain. On a shared hosted key that is what exhausts the per-second
# compute budget and turns every scan into a 429.
#
# Rule of thumb: poll no faster than the chain produces the window you ask for.
: "${POLL_INTERVAL_MS:=300}"
: "${INDEXER_POLL_INTERVAL_MS:=$((POLL_INTERVAL_MS > 500 ? POLL_INTERVAL_MS : 500))}"
N=${#CID[@]}
(( N >= 2 )) || die "CHAINS needs at least 2 chains (got $N)"
SWAP_CHAIN="${SWAP_CHAIN:-${CID[0]}}"

# ---------------------------------------------------------------------------
# parse ASSETS -> ATOKEN["<sym>|<chain_id>"] = token ; ACHAINS["<sym>"]="c1 c2"
# ---------------------------------------------------------------------------
ASYMS=()
declare -A ATOKEN ACHAINS
for entry in "${ASSETS[@]:-}"; do
  [[ -z "$entry" ]] && continue
  IFS='|' read -r sym rest <<<"$entry"
  sym="${sym// /}"; [[ -n "$sym" ]] || die "bad ASSETS entry (empty symbol): '$entry'"
  ASYMS+=("$sym")
  IFS='|' read -ra pairs <<<"$rest"
  for pv in "${pairs[@]}"; do
    pv="${pv// /}"; [[ -z "$pv" ]] && continue
    cid="${pv%%:*}"; tok="${pv#*:}"
    [[ -n "${CIDX[$cid]+x}" ]] || die "asset $sym lists chain $cid, which is not in CHAINS"
    ATOKEN["$sym|$cid"]="$tok"
    ACHAINS[$sym]="${ACHAINS[$sym]:-} $cid"
  done
  [[ -n "${ACHAINS[$sym]:-}" ]] || die "asset $sym has no chains"
done
(( ${#ASYMS[@]} >= 1 )) || die "ASSETS needs at least one asset"

# ---------------------------------------------------------------------------
# 0. preflight
# ---------------------------------------------------------------------------
say "preflight"
need cargo "building the Rust services"
need node  "the frontend"; need npm "the frontend"
if [[ "$LOCAL_ANVIL" == "true" || "$DEPLOY_TOKENS" == "true" || "$DEPLOY_BRIDGE" == "true" || "$DEPLOY_SWAP" == "true" ]]; then
  need anvil "local chains / deploys"; need cast "chain ops"; need forge "contract deploys"
else
  need cast "chain reads"
fi
[[ "$PG_DOCKER" == "true" ]] && need docker "the Postgres-backed sig-store"
info "config: $CONFIG"
info "chains: $N  ($(IFS=,; echo "${CID[*]}"))"
info "assets: ${ASYMS[*]}"
info "deploy: tokens=$DEPLOY_TOKENS bridge=$DEPLOY_BRIDGE swap=$DEPLOY_SWAP"
info "validators: ${#VALIDATOR_KEYS[@]}  threshold: $THRESHOLD"
info "features: swap=$ENABLE_SWAP indexer=$ENABLE_INDEXER refund=$ENABLE_REFUND"

# derive validator addresses from their keys
VALIDATOR_ADDRS=()
for k in "${VALIDATOR_KEYS[@]}"; do VALIDATOR_ADDRS+=("$(cast wallet address --private-key "$k")"); done
DEPLOYER_ADDR="$(cast wallet address --private-key "$DEPLOYER_KEY")"
(( THRESHOLD >= 1 && THRESHOLD <= ${#VALIDATOR_KEYS[@]} )) || die "THRESHOLD must be 1..${#VALIDATOR_KEYS[@]}"

# index of the swap chain within the arrays
swap_idx=-1
for i in "${!CID[@]}"; do [[ "${CID[$i]}" == "$SWAP_CHAIN" ]] && swap_idx=$i; done
[[ "$ENABLE_SWAP" != "true" || $swap_idx -ge 0 ]] || die "SWAP_CHAIN=$SWAP_CHAIN is not in CHAINS"

# ---------------------------------------------------------------------------
# 1. stop any previous run
# ---------------------------------------------------------------------------
say "stopping any previous run"
bash "$ROOT/scripts/stop.sh" "$CONFIG" >/dev/null 2>&1 || true
sleep 1

# ---------------------------------------------------------------------------
# 2. build the Rust services we need
# ---------------------------------------------------------------------------
say "building rust services"
BUILD_PKGS=(-p sig-store -p validator -p keeper -p graphql-api)
[[ "$ENABLE_INDEXER" == "true" ]] && BUILD_PKGS+=(-p indexer)
( cd "$ROOT" && cargo build "${BUILD_PKGS[@]}" ) || die "cargo build failed"

# ---------------------------------------------------------------------------
# 3. chains (local anvil or external)
# ---------------------------------------------------------------------------
if [[ "$LOCAL_ANVIL" == "true" ]]; then
  # ANVIL_BLOCK_TIME: keep the chains PRODUCING blocks, not merely accepting txs.
  #
  # A default anvil mines only when a transaction arrives, so an idle chain's head
  # timestamp is frozen. Anything that measures elapsed time in block timestamps
  # then never advances — most visibly the refund path: the validator establishes
  # the unclaimed timeout itself by walking back to a block `REFUND_TIMEOUT_SECS`
  # older than the head (it will not take the store's word for it), and on a
  # frozen chain no such block ever exists, so a stranded transfer is never
  # cancelled however long you wait. One second is imperceptible for a demo and
  # makes the local mesh behave like a real chain.
  say "booting $N anvil chain(s)"
  for i in "${!CID[@]}"; do
    port="${CRPC[$i]##*:}"
    spawn "anvil-${CID[$i]}.log" -- anvil --chain-id "${CID[$i]}" --port "$port" --host 127.0.0.1 --silent --block-time "${ANVIL_BLOCK_TIME:-1}"
    info "${CNAME[$i]} (${CID[$i]}) on :$port"
  done
fi
for i in "${!CID[@]}"; do
  ok=false
  for _ in $(seq 1 60); do cast chain-id --rpc-url "${CRPC[$i]}" >/dev/null 2>&1 && { ok=true; break; }; sleep 0.25; done
  $ok || die "RPC not reachable: ${CRPC[$i]}"
  got="$(cast chain-id --rpc-url "${CRPC[$i]}")"
  [[ "$got" == "${CID[$i]}" ]] || die "RPC ${CRPC[$i]} reports chainId $got, config says ${CID[$i]}"
done

# ---------------------------------------------------------------------------
# 4. deploy tokens / bridge / swap (each independent) + wire the mesh
# ---------------------------------------------------------------------------
deployed_to() { grep deployedTo | grep -oE '0x[0-9a-fA-F]{40}' | head -1; }
csend() { cast send "$1" "$2" "${@:3}" >/dev/null; }
vlist="[$(IFS=,; echo "${VALIDATOR_ADDRS[*]}")]"      # "[0xV1,0xV2,...]"
MINT=1000000000000000000000000                        # 1,000,000e18
SWAP_POOL=""
need_forge=false
[[ "$DEPLOY_TOKENS" == "true" || "$DEPLOY_BRIDGE" == "true" || "$DEPLOY_SWAP" == "true" ]] && need_forge=true
if $need_forge; then ( cd "$CONTRACTS" && forge build >/dev/null ) || die "forge build failed"; fi
fc() { ( cd "$CONTRACTS" && forge create "$1" --rpc-url "$2" --private-key "$DEPLOYER_KEY" --broadcast --json "${@:3}" 2>/dev/null ) | deployed_to; }

# --- 4a. tokens: resolve every asset's per-chain token address ---
say "resolving asset tokens (deploy_tokens=$DEPLOY_TOKENS)"
for sym in "${ASYMS[@]}"; do
  for cid in ${ACHAINS[$sym]}; do
    i=${CIDX[$cid]}; tok="${ATOKEN[$sym|$cid]}"
    if [[ "$tok" == "auto" ]]; then
      [[ "$DEPLOY_TOKENS" == "true" ]] || die "asset $sym on chain $cid is 'auto' but DEPLOY_TOKENS=false — give a 0x address"
      addr=$(fc src/TestToken.sol:TestToken "${CRPC[$i]}" --constructor-args "$sym" "$sym")
      [[ "$addr" =~ ^0x ]] || die "token deploy failed: $sym on chain $cid"
      ATOKEN["$sym|$cid"]="$addr"
    elif [[ ! "$tok" =~ ^0x[0-9a-fA-F]{40}$ ]]; then
      die "asset $sym on chain $cid: '$tok' is neither 'auto' nor a 0x address"
    fi
    info "$sym @ $cid = ${ATOKEN[$sym|$cid]}"
  done
done

# --- 4b. bridge: deploy Gates, then register + fund every asset's mesh ---
#
# The Gate is UUPS, so "deploying a gate" is two contracts: an implementation
# (never initialized, holds no state) and an ERC1967 proxy that IS the gate. The
# proxy address is what every config, validator and keeper must point at; the
# implementation address is an internal detail that changes on every upgrade.
#
# `initialize` runs INSIDE the proxy's constructor via the initdata below, so
# there is no window in which an uninitialized proxy exists on-chain for someone
# else to claim ownership of.
if [[ "$DEPLOY_BRIDGE" == "true" ]]; then
  # Every gate in one mesh shares one domain, and a NEW deployment needs a NEW
  # one — that is the whole mechanism that stops the previous deployment's
  # validator signatures from being replayed against these fresh gates. Derived
  # from the validator set + threshold + a per-run salt so two runs never collide.
  if [[ -z "${BRIDGE_DOMAIN:-}" ]]; then
    BRIDGE_DOMAIN=$(cast keccak "$(printf 'selendra-bridge|%s|%s|%s' \
      "$vlist" "$THRESHOLD" "$(date +%s)-$$")")
    info "generated BRIDGE_DOMAIN=$BRIDGE_DOMAIN (set it in the config to pin one)"
  fi
  [[ "$BRIDGE_DOMAIN" =~ ^0x[0-9a-fA-F]{64}$ ]] || die "BRIDGE_DOMAIN must be 0x + 64 hex chars"
  [[ "$BRIDGE_DOMAIN" =~ ^0x0{64}$ ]] && die "BRIDGE_DOMAIN must not be zero"

  say "deploying Gates (validators=${#VALIDATOR_ADDRS[@]}, threshold=$THRESHOLD, domain=${BRIDGE_DOMAIN:0:12}…)"
  initdata=$(cast calldata "initialize(address[],uint256,bytes32)" "$vlist" "$THRESHOLD" "$BRIDGE_DOMAIN")
  for i in "${!CID[@]}"; do
    impl=$(fc src/Gate.sol:Gate "${CRPC[$i]}")
    [[ "$impl" =~ ^0x ]] || die "gate implementation deploy failed on chain ${CID[$i]}"
    CGATE[$i]=$(fc src/GateProxy.sol:GateProxy "${CRPC[$i]}" --constructor-args "$impl" "$initdata")
    [[ "${CGATE[$i]}" =~ ^0x ]] || die "gate proxy deploy failed on chain ${CID[$i]}"
    CIMPL[$i]="$impl"
    info "${CNAME[$i]} gate=${CGATE[$i]} (implementation $impl)"
  done
else
  for i in "${!CID[@]}"; do
    [[ "${CGATE[$i]}" =~ ^0x ]] || die "DEPLOY_BRIDGE=false but chain ${CID[$i]} has no gate in CHAINS"
  done
fi

# --- gate wiring helpers (audit round 4: H-1 seal, M-3 supportedChain) --------
#
# Order per gate, before any liquidity: setSupportedChain for every peer ->
# setLocalToken for every inbound corridor -> seal(). Every step is idempotent
# (read first, send only what is missing), so re-running is safe.
gate_owner()     { cast call "$1" "owner()(address)" --rpc-url "$2" 2>/dev/null || echo ""; }
gate_owned_by_us() { [[ "$(gate_owner "$1" "$2" | tr 'A-F' 'a-f')" == "${DEPLOYER_ADDR,,}" ]]; }
gate_sealed()    { [[ "$(cast call "$1" "isSealed()(bool)" --rpc-url "$2" 2>/dev/null || echo false)" == "true" ]]; }
chain_supported() { [[ "$(cast call "$1" "supportedChain(uint256)(bool)" "$3" --rpc-url "$2" 2>/dev/null || echo false)" == "true" ]]; }
peers_of() {  # $1 array index -> every chain id this gate may `send` to
  local i="$1" j x
  for j in "${!CID[@]}"; do [[ "$j" == "$i" ]] || echo "${CID[$j]}"; done
  for x in "${EXTRA_SUPPORTED_CHAINS[@]:-}"; do [[ -n "$x" ]] && echo "$x"; done
}
# Register a token's bridge decimals on a gate (decimals normalisation). Every
# transfer travels in ONE per-asset decimals value that every gate must agree
# on; `send` and `setLocalToken` both revert for a token without it. Write-once:
# an existing, matching registration is skipped; a different one is fatal.
ensure_bridge_decimals() {  # gate rpc token bridgeDecimals label
  local gate="$1" rpc="$2" tok="$3" want="$4" label="$5" isset cur
  read -r isset cur _ <<<"$(cast call "$gate" "bridgeDecimalsOf(address)(bool,uint8,uint8)" "$tok" --rpc-url "$rpc" 2>/dev/null | tr '\n' ' ')"
  if [[ "$isset" == "true" ]]; then
    [[ "$cur" == "$want" ]] || die "$label: gate $gate has bridge decimals $cur, the mesh needs $want (write-once — redeploy the gate)"
    return
  fi
  gate_sealed "$gate" "$rpc" && die "$label: gate $gate is SEALED — bridge decimals now need governance:
    cast send $gate 'scheduleGovernance(bytes32)' \$(cast call $gate 'setBridgeDecimalsActionId(address,uint8)(bytes32)' $tok $want --rpc-url $rpc) --rpc-url $rpc --private-key <owner>
    # wait GOVERNANCE_DELAY, then: cast send $gate 'setBridgeDecimals(address,uint8)' $tok $want ..."
  csend "$gate" "setBridgeDecimals(address,uint8)" "$tok" "$want" --rpc-url "$rpc" --private-key "$DEPLOYER_KEY"
  info "$label: bridge decimals $want"
}

# Register an inbound corridor. setLocalToken is WRITE-ONCE (finding M-5): a
# registered corridor cannot be repointed, because in-flight claims bind only the
# debridgeId and would then release the new asset — so an existing mapping is
# skipped, not re-sent. On a SEALED gate the owner can no longer register
# instantly; print exactly what governance must do instead of a bare revert.
register_corridor() {  # gate rpc debridgeId localToken label
  local gate="$1" rpc="$2" did="$3" tok="$4" label="$5" cur aid
  cur=$(cast call "$gate" "tokenOf(bytes32)(address)" "$did" --rpc-url "$rpc" 2>/dev/null || echo "")
  if [[ -n "${cur:-}" && ! "${cur:-}" =~ ^0x0{40}$ ]]; then info "$label already registered ($cur)"; return; fi
  if gate_sealed "$gate" "$rpc"; then
    aid=$(cast call "$gate" "setLocalTokenActionId(bytes32,address)(bytes32)" "$did" "$tok" --rpc-url "$rpc")
    die "$label: gate $gate is SEALED — a new corridor needs governance (H-1):
    cast send $gate 'scheduleGovernance(bytes32)' $aid --rpc-url $rpc --private-key <owner>
    # wait GOVERNANCE_DELAY (48h), then within SCHEDULE_GRACE (7d):
    cast send $gate 'setLocalToken(bytes32,address)' $did $tok --rpc-url $rpc --private-key <owner>
  (or SEAL_GATES=false on a throwaway mesh, and redeploy)"
  fi
  csend "$gate" "setLocalToken(bytes32,address)" "$did" "$tok" --rpc-url "$rpc" --private-key "$DEPLOYER_KEY"
  info "$label -> $tok"
}

# --- 4b-i. destinations: every gate lists every peer it may send to (M-3) ---
say "listing destinations (setSupportedChain)"
for i in "${!CID[@]}"; do
  for peer in $(peers_of "$i"); do
    chain_supported "${CGATE[$i]}" "${CRPC[$i]}" "$peer" && continue
    if gate_owned_by_us "${CGATE[$i]}" "${CRPC[$i]}"; then
      csend "${CGATE[$i]}" "setSupportedChain(uint256,bool)" "$peer" true --rpc-url "${CRPC[$i]}" --private-key "$DEPLOYER_KEY"
      info "${CNAME[$i]}: send -> chain $peer enabled"
    else
      warn "${CNAME[$i]}: chain $peer is not a supported destination and the deployer is not the gate owner ($(gate_owner "${CGATE[$i]}" "${CRPC[$i]}")) — the owner must call setSupportedChain($peer, true)"
    fi
  done
done

# Wire when anything fresh was deployed (extra liquidity is harmless on a test
# chain). Skip entirely for a pure existing stack.
if [[ "$DEPLOY_BRIDGE" == "true" || "$DEPLOY_TOKENS" == "true" ]]; then
  say "wiring asset meshes (liquidity + setLocalToken)"
  for sym in "${ASYMS[@]}"; do
    read -ra chs <<<"${ACHAINS[$sym]}"
    (( ${#chs[@]} >= 2 )) || { info "$sym is on <2 chains — spendable only, not bridgeable"; }
    # The asset's bridge decimals: BRIDGE_DECIMALS_<SYM> if set, else the lowest
    # decimals it has on any chain here (so every claim scales up exactly). A
    # corridor to a chain outside CHAINS (e.g. a 6-decimal SPL mint) must be
    # covered by setting BRIDGE_DECIMALS_<SYM> to that lower value.
    bd_var="BRIDGE_DECIMALS_${sym}"; bdec="${!bd_var:-}"
    if [[ -z "$bdec" ]]; then
      for cid in "${chs[@]}"; do
        d=$(cast call "${ATOKEN[$sym|$cid]}" "decimals()(uint8)" --rpc-url "${CRPC[${CIDX[$cid]}]}" | awk '{print $1}')
        [[ -z "$bdec" ]] || (( d < bdec )) && bdec="$d"
      done
    fi
    info "$sym bridges at $bdec decimals"
    for cid in "${chs[@]}"; do
      i=${CIDX[$cid]}; tok="${ATOKEN[$sym|$cid]}"
      ensure_bridge_decimals "${CGATE[$i]}" "${CRPC[$i]}" "$tok" "$bdec" "$sym on chain $cid"
      # account0 spendable + gate payout liquidity of this token on this chain
      csend "$tok" "mint(address,uint256)" "$DEPLOYER_ADDR"  "$MINT" --rpc-url "${CRPC[$i]}" --private-key "$DEPLOYER_KEY"
      csend "$tok" "mint(address,uint256)" "${CGATE[$i]}"    "$MINT" --rpc-url "${CRPC[$i]}" --private-key "$DEPLOYER_KEY"
      # register this asset inbound from every OTHER chain it lives on
      for ocid in "${chs[@]}"; do
        [[ "$ocid" == "$cid" ]] && continue
        otok="${ATOKEN[$sym|$ocid]}"
        pad=$(printf '%064x' "$ocid"); did=$(cast keccak "0x${pad}${otok#0x}")
        register_corridor "${CGATE[$i]}" "${CRPC[$i]}" "$did" "$tok" "corridor $sym <- chain $ocid on chain $cid"
      done
    done
  done
fi

# --- 4b-ii. return paths for corridors this script does NOT manage ---
#
# The loop above wires only the chains in CHAINS — i.e. the EVM mesh. A corridor
# whose far side lives elsewhere (the Solana gate, which has its own config and
# its own toolchain) therefore has no `tokenOf` mapping on the EVM side, and a
# claim arriving from it reverts `UnknownAsset`.
#
# That failed SILENTLY and cost real debugging time: the keeper treats
# `tokenOf == 0` as a stranded transfer and declines to retry, so the only
# symptom was a fully-signed transfer parked at READY with nothing in any log.
# (The keeper now reports it once at WARN — see `ClaimOutcome::Stranded` — but
# the corridor still has to be registered, and registering it here means a
# redeploy cannot forget.)
#
# Entries are "chain_id | debridgeId | local_token":
#   chain_id     an EVM chain from CHAINS, whose gate gets the mapping
#   debridgeId   the asset id the FAR side emits (keccak(origin_chain, origin_token))
#   local_token  the ERC-20 this gate releases for it
#
# Write-once, like the mesh wiring above, so re-running is safe.
# `+x` first: run.sh runs under `set -u`, and a bare ${#arr[@]} on an array no
# config happens to define is an unbound-variable abort.
if [[ -n "${EXTRA_LOCAL_TOKENS+x}" && ${#EXTRA_LOCAL_TOKENS[@]} -gt 0 ]]; then
  say "registering return paths for externally-managed corridors"
  for entry in "${EXTRA_LOCAL_TOKENS[@]}"; do
    IFS='|' read -r xcid xdid xtok <<<"$entry"
    xcid="${xcid// /}"; xdid="${xdid// /}"; xtok="${xtok// /}"
    [[ -n "$xcid" && -n "$xdid" && -n "$xtok" ]] || die "bad EXTRA_LOCAL_TOKENS entry: '$entry'"
    [[ -n "${CIDX[$xcid]:-}" ]] || die "EXTRA_LOCAL_TOKENS names chain $xcid, which is not in CHAINS"
    [[ "$xdid" =~ ^0x[0-9a-fA-F]{64}$ ]] || die "EXTRA_LOCAL_TOKENS debridgeId must be 0x + 64 hex: '$xdid'"
    i=${CIDX[$xcid]}
    [[ "$(cast call "${CGATE[$i]}" "bridgeDecimalsOf(address)(bool,uint8,uint8)" "$xtok" --rpc-url "${CRPC[$i]}" 2>/dev/null | head -1)" == "true" ]] \
      || die "EXTRA_LOCAL_TOKENS: $xtok has no bridge decimals on chain $xcid's gate — it must be an asset this mesh wires (set BRIDGE_DECIMALS_<SYM> for its lowest-decimals chain)"
    register_corridor "${CGATE[$i]}" "${CRPC[$i]}" "$xdid" "$xtok" "chain $xcid: ${xdid:0:12}…"
  done
fi

# --- 4b-iii. seal (H-1) — the LAST wiring step, before anything is funded ---
#
# From here on every new corridor is scheduleGovernance + 48h. That is the
# property that stops a stolen owner key from registering a worthless token as
# the asset behind a real corridor and draining the pot in one block.
if [[ "$SEAL_GATES" == "true" ]]; then
  say "sealing gates (new corridors now need governance + 48h)"
  for i in "${!CID[@]}"; do
    if gate_sealed "${CGATE[$i]}" "${CRPC[$i]}"; then info "${CNAME[$i]}: already sealed"; continue; fi
    if gate_owned_by_us "${CGATE[$i]}" "${CRPC[$i]}"; then
      csend "${CGATE[$i]}" "seal()" --rpc-url "${CRPC[$i]}" --private-key "$DEPLOYER_KEY"
      info "${CNAME[$i]}: sealed"
    else
      warn "${CNAME[$i]}: gate is UNSEALED and the deployer is not its owner — the owner must call seal() before funding it"
    fi
  done
else
  warn "SEAL_GATES=false: gates stay in the setup phase (setLocalToken instant). Dev only."
  warn "  NOTE (M-1): since the 2026-09-21 contracts, \`claim\` REVERTS on an unsealed gate, so a"
  warn "  mesh left this way will sign transfers it can never pay out. The setup phase also"
  warn "  expires on its own 7 days after deploy."
fi

# --- 4b-iv. assert the wiring, so a half-configured mesh never comes up ------
say "verifying gate wiring"
for i in "${!CID[@]}"; do
  for peer in $(peers_of "$i"); do
    chain_supported "${CGATE[$i]}" "${CRPC[$i]}" "$peer" \
      || die "${CNAME[$i]} gate ${CGATE[$i]}: supportedChain($peer) is false — send towards it would revert UnsupportedChain"
  done
  if [[ "$SEAL_GATES" == "true" ]] && gate_owned_by_us "${CGATE[$i]}" "${CRPC[$i]}"; then
    gate_sealed "${CGATE[$i]}" "${CRPC[$i]}" || die "${CNAME[$i]} gate ${CGATE[$i]} is not sealed"
  fi
  info "${CNAME[$i]}: peers ok, sealed=$(gate_sealed "${CGATE[$i]}" "${CRPC[$i]}" && echo true || echo false)"
done

# --- 4c. swap: same-chain SwapPool for the Swap view ---
if [[ "$ENABLE_SWAP" == "true" ]]; then
  if [[ "$DEPLOY_SWAP" == "true" ]]; then
    say "deploying SwapPool on ${CNAME[$swap_idx]}"
    if ( cd "$CONTRACTS" && forge script script/DeploySwap.s.sol:DeploySwap \
           --rpc-url "${CRPC[$swap_idx]}" --private-key "$DEPLOYER_KEY" --broadcast >"$RUN_DIR/swap-deploy.log" 2>&1 ); then
      source "$CONTRACTS/fixtures/swap-deploy.env"   # SWAP_POOL, STABLE, WETH, TT
      for pair in "$WETH:10000000000000000000" "$TT:250000000000000000000000" "$STABLE:5000000000"; do
        cast send "${pair%%:*}" "mint(address,uint256)" "$DEPLOYER_ADDR" "${pair##*:}" \
          --rpc-url "${CRPC[$swap_idx]}" --private-key "$DEPLOYER_KEY" >/dev/null 2>&1 || true
      done
      info "SwapPool=$SWAP_POOL (stable=$STABLE WETH=$WETH TT=$TT)"
    else
      info "!! swap deploy failed — Swap view will be empty (see $RUN_DIR/swap-deploy.log)"
      ENABLE_SWAP=false
    fi
  else
    SWAP_POOL="${SWAP_POOL_ADDR:-}"
    [[ "$SWAP_POOL" =~ ^0x ]] || { info "DEPLOY_SWAP=false and no SWAP_POOL_ADDR — Swap view off"; ENABLE_SWAP=false; }
  fi
fi
cd "$ROOT"

# Per-chain PRIMARY token = the first listed asset that exists on that chain.
# (The Gate bridges all assets; the demo UI surfaces this one per chain.)
CTOKEN=()
for i in "${!CID[@]}"; do
  primary=""
  for sym in "${ASYMS[@]}"; do
    t="${ATOKEN[$sym|${CID[$i]}]:-}"
    [[ -n "$t" ]] && { primary="$t"; break; }
  done
  CTOKEN[$i]="$primary"
done

# persist addresses for the summary / debugging
: > "$ADDR_ENV"
for i in "${!CID[@]}"; do
  echo "CHAIN_${CID[$i]}_GATE=${CGATE[$i]}" >> "$ADDR_ENV"
  [[ -n "${CIMPL[$i]:-}" ]] && echo "CHAIN_${CID[$i]}_GATE_IMPL=${CIMPL[$i]}" >> "$ADDR_ENV"
done
echo "BRIDGE_DOMAIN=${BRIDGE_DOMAIN:-}" >> "$ADDR_ENV"
for sym in "${ASYMS[@]}"; do
  for cid in ${ACHAINS[$sym]}; do echo "TOKEN_${sym}_${cid}=${ATOKEN[$sym|$cid]}" >> "$ADDR_ENV"; done
done
echo "SWAP_POOL=${SWAP_POOL:-}" >> "$ADDR_ENV"

# reusable TOML fragments over all chains
emit_sources() {  # $1 = keyword: "sources" (validator) / "targets"/"sources" (keeper)
  for i in "${!CID[@]}"; do
    echo "[[$1]]"
    echo "chain_id = ${CID[$i]}"
    echo "rpc = \"${CRPC[$i]}\""
    echo "gate = \"${CGATE[$i]}\""
    echo "poll_interval_ms = 300"
    echo
  done
}

# ---------------------------------------------------------------------------
# 5. Postgres
# ---------------------------------------------------------------------------
if [[ "$PG_DOCKER" == "true" ]]; then
  say "starting Postgres ($PG_NAME on :$PG_PORT)"
  docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
  # Named volume so bridge history OUTLIVES the container. `stop.sh` removes the
  # container (it holds a port), and without a volume that erased everything:
  # transfer records, refund state, signatures, indexer cursors. On a throwaway
  # anvil that is harmless — the chain resets too. On a LIVE chain it is not: the
  # chain remembers and the bridge forgets, and the signatures do not come back,
  # because validators resume from file-based cursors and never re-sign blocks
  # they already scanned. An in-flight refund is stranded by a restart.
  #
  # `bash scripts/stop.sh <config> --wipe` deletes the volume when a clean slate
  # is actually what you want.
  docker volume create "${PG_NAME}-data" >/dev/null 2>&1 || true
  # M-10 (audit round 4): the port used to be published on every interface with
  # `bridge:bridge` — a `-p` publish bypasses ufw, so signatures, refund state
  # and allowlists were writable by anyone who could reach the host. Loopback
  # only, and a random password: from PG_PASSWORD in the config if set, else the
  # one this run dir already generated (it must match the volume's), else fresh.
  PG_PASSWORD="${PG_PASSWORD:-$(prev_token PG_PASSWORD)}"
  [[ -n "$PG_PASSWORD" ]] || PG_PASSWORD="$(rand_token)"
  # M-8: the password goes in through a 0600 --env-file, not on the command
  # line. Every argv on this host is world-readable via /proc/*/cmdline, which
  # this script already avoids for RPC keys and store tokens.
  PG_ENV="$RUN_DIR/postgres.env"
  ( umask 077; printf 'POSTGRES_USER=bridge\nPOSTGRES_DB=bridge\nPOSTGRES_PASSWORD=%s\n' "$PG_PASSWORD" > "$PG_ENV" )
  docker run -d --name "$PG_NAME" \
    --env-file "$PG_ENV" \
    -v "${PG_NAME}-data:/var/lib/postgresql/data" \
    -p "127.0.0.1:${PG_PORT}:5432" postgres:16-alpine >/dev/null || die "failed to start Postgres container"
  ok=false
  for _ in $(seq 1 60); do docker exec "$PG_NAME" pg_isready -U bridge -d bridge >/dev/null 2>&1 && { ok=true; break; }; sleep 0.5; done
  $ok || die "Postgres did not become ready"
  # POSTGRES_PASSWORD only applies when the volume is first initialised. A volume
  # from an earlier run (or from before this change, when the password was
  # `bridge`) keeps its old one, so set it explicitly over the container's local
  # socket (trust auth) — no more "password authentication failed" on upgrade.
  # M-8: the statement arrives on STDIN, so the password is in NO argv — not
  # psql's, not docker's (`docker exec -e PGPW=…` would put it back on the host
  # command line). The literal is quoted by doubling any `'`, which is all
  # standard_conforming_strings needs, so a password of `x'; ALTER USER bridge
  # SUPERUSER; --` can no longer close the literal and run its own statement.
  pg_literal() { printf "'%s'" "${1//\'/\'\'}"; }
  printf 'ALTER USER bridge WITH PASSWORD %s;\n' "$(pg_literal "$PG_PASSWORD")" \
    | docker exec -i "$PG_NAME" psql -q -U bridge -d bridge -f - >/dev/null 2>&1 \
    || warn "could not set the Postgres password on the existing volume"
  DATABASE_URL="postgres://bridge:${PG_PASSWORD}@127.0.0.1:${PG_PORT}/bridge?sslmode=disable"
  info "Postgres ready on 127.0.0.1:$PG_PORT (password in $TOKENS_ENV)"
else
  [[ -n "${DATABASE_URL:-}" ]] || die "PG_DOCKER=false needs DATABASE_URL in the config"
fi

# ---------------------------------------------------------------------------
# 6. sig-store
#
# SCOPED AUTH (finding L-5). Without tokens the store starts UNAUTHENTICATED and
# says so in its log: signatures, claim status and the allowlist all become
# world-writable to anything that can reach the port. docker-compose has wired
# these since the L-5 fix; this launcher did not, so the everyday path — and the
# live testnet deployment — ran wide open.
#
# One random token per role per run, so a leak from one component cannot act as
# another. Override any of them in the config to pin a value across restarts.
# ---------------------------------------------------------------------------
export SIG_STORE_VALIDATOR_TOKEN="${SIG_STORE_VALIDATOR_TOKEN:-$(rand_token)}"
export SIG_STORE_KEEPER_TOKEN="${SIG_STORE_KEEPER_TOKEN:-$(rand_token)}"
export SIG_STORE_READER_TOKEN="${SIG_STORE_READER_TOKEN:-$(rand_token)}"
export SIG_STORE_ADMIN_TOKEN="${SIG_STORE_ADMIN_TOKEN:-$(rand_token)}"
# Written before anything reads it (umask 077 is process-wide, see the top).
{
  echo "SIG_STORE_VALIDATOR_TOKEN=$SIG_STORE_VALIDATOR_TOKEN"
  echo "SIG_STORE_KEEPER_TOKEN=$SIG_STORE_KEEPER_TOKEN"
  echo "SIG_STORE_READER_TOKEN=$SIG_STORE_READER_TOKEN"
  echo "SIG_STORE_ADMIN_TOKEN=$SIG_STORE_ADMIN_TOKEN"
  [[ -n "${PG_PASSWORD:-}" ]] && echo "PG_PASSWORD=$PG_PASSWORD"
} > "$TOKENS_ENV"
chmod 600 "$TOKENS_ENV"

say "starting sig-store ($STORE_URL)"
SIG_STORE_BIND="$BIND_HOST:$STORE_PORT" DATABASE_URL="$DATABASE_URL" \
  spawn sig-store.log -- "$ROOT/target/debug/sig-store"
ok=false
for _ in $(seq 1 60); do curl -s "$STORE_URL/health" | grep -q ok && { ok=true; break; }; sleep 0.25; done
$ok || die "sig-store did not come up (see $RUN_DIR/sig-store.log)"
info "sig-store healthy"
info "auth: scoped tokens generated (admin token in $TOKENS_ENV)"

# ---------------------------------------------------------------------------
# 7. validators — watch ALL chains as sources; refund to ALL as destinations
# ---------------------------------------------------------------------------
say "starting ${#VALIDATOR_KEYS[@]} validator(s), each watching all $N chains"
# Scan cursors (`validator-*-<chain>.json`) survive in the run dir on purpose:
# on a LIVE chain a lost cursor means re-scanning from `start_block`. On a local
# anvil the opposite holds — the chain was just re-created from block 0, so a
# cursor from the previous run points PAST every block that will exist for a
# long while, and the validators sit silently waiting for it: nothing is ever
# signed, while the refund loop (which reads the chain directly) still works.
# That is exactly what the durable run dir (M-11) made reproducible on every
# re-run, so throwaway chains get throwaway cursors.
if [[ "$LOCAL_ANVIL" == "true" ]]; then
  stale=$(find "$RUN_DIR" -maxdepth 1 -name 'validator-*-*.json' -print -delete | wc -l)
  (( stale == 0 )) || info "LOCAL_ANVIL: dropped $stale scan cursor(s) from the previous run (the chains restarted at block 0)"
fi
vi=0
for key in "${VALIDATOR_KEYS[@]}"; do
  vi=$((vi+1))
  cfg="$RUN_DIR/validator-$vi.toml"
  {
    for i in "${!CID[@]}"; do
      echo "[[sources]]"
      echo "chain_id = ${CID[$i]}"
      echo "rpcs = [\"${CRPC[$i]}\"]"
      echo "gate = \"${CGATE[$i]}\""
      echo "start_block = $(start_block_for "${CID[$i]}" "${CRPC[$i]}")"
      echo "block_confirmation = $(conf_for "${CID[$i]}")"
      echo "allow_zero_confirmation = $SOURCE_ALLOW_ZERO_CONFIRMATION"
      echo "poll_interval_ms = $POLL_INTERVAL_MS"
      echo "max_block_range = $MAX_BLOCK_RANGE"
      echo "state_file = \"$RUN_DIR/validator-$vi-${CID[$i]}.json\""
      echo
    done
    echo "[signer]"
    echo "private_key = \"$key\""
    echo
    echo "[store]"
    echo "url = \"$STORE_URL\""
    # H-2 (audit 2026-09-16): a validator must be able to read each peer gate to
    # confirm it agrees on an asset's bridge decimals, or a destination
    # registered one digit off pays a power of ten wrong and nothing on-chain
    # catches it. Emitted UNCONDITIONALLY — unlike [refund], which an operator
    # may legitimately disable — because without it the validator signs nothing.
    for i in "${!CID[@]}"; do
      echo
      echo "[[destinations]]"
      echo "chain_id = ${CID[$i]}"
      echo "rpcs = [\"${CRPC[$i]}\"]"
      echo "gate = \"${CGATE[$i]}\""
    done
    if [[ "$ENABLE_REFUND" == "true" ]]; then
      echo
      echo "[refund]"
      echo "timeout_secs = $REFUND_TIMEOUT_SECS"
      echo "poll_interval_ms = 2000"
      echo "block_confirmation = $REFUND_BLOCK_CONFIRMATION"
      echo "allow_zero_confirmation = $REFUND_ALLOW_ZERO_CONFIRMATION"
      for i in "${!CID[@]}"; do
        echo
        echo "[[refund.destinations]]"
        echo "chain_id = ${CID[$i]}"
        echo "rpcs = [\"${CRPC[$i]}\"]"
        echo "gate = \"${CGATE[$i]}\""
      done
    fi
  } > "$cfg"
  spawn "validator-$vi.log" -- "$ROOT/target/debug/validator" "$cfg"
done

# ---------------------------------------------------------------------------
# 8. keeper — claims on ALL chains; refunds on ALL sources if enabled
# ---------------------------------------------------------------------------
say "starting keeper (targets = all $N chains)"
kcfg="$RUN_DIR/keeper.toml"
{
  emit_sources targets
  echo "[keeper]"
  echo "private_key = \"$KEEPER_KEY\""
  echo
  echo "[store]"
  echo "url = \"$STORE_URL\""
  if [[ "$ENABLE_REFUND" == "true" ]]; then
    echo
    emit_sources sources
  fi
} > "$kcfg"
spawn keeper.log -- "$ROOT/target/debug/keeper" "$kcfg"

# ---------------------------------------------------------------------------
# 9. indexer (history + refund eligibility) over ALL chains
# ---------------------------------------------------------------------------
if [[ "$ENABLE_INDEXER" == "true" ]]; then
  say "starting indexer"
  icfg="$RUN_DIR/indexer.toml"
  {
    echo "database_url = \"$DATABASE_URL\""
    echo "refund_timeout_secs = $REFUND_TIMEOUT_SECS"
    echo "sweep_interval_secs = $SWEEP_INTERVAL_SECS"
    for i in "${!CID[@]}"; do
      echo
      echo "[[chains]]"
      echo "chain_id = ${CID[$i]}"
      echo "rpc = \"${CRPC[$i]}\""
      echo "gate = \"${CGATE[$i]}\""
      [[ "$ENABLE_SWAP" == "true" && $i == "$swap_idx" && -n "${SWAP_POOL:-}" ]] && echo "pool = \"$SWAP_POOL\""
      echo "start_block = $(start_block_for "${CID[$i]}" "${CRPC[$i]}")"
      echo "block_confirmation = $(conf_for "${CID[$i]}")"
      # M-7: the indexer fails closed on a 0 buffer, so carry the same
      # instant-finality opt-in the validator config already uses.
      echo "allow_zero_confirmation = $SOURCE_ALLOW_ZERO_CONFIRMATION"
      echo "poll_interval_ms = $INDEXER_POLL_INTERVAL_MS"
      echo "max_block_range = $MAX_BLOCK_RANGE"
    done
  } > "$icfg"
  spawn indexer.log -- "$ROOT/target/debug/indexer" "$icfg"
fi

# ---------------------------------------------------------------------------
# 10. graphql-api (backend) — registry + gates for ALL chains
# ---------------------------------------------------------------------------
say "starting graphql-api ($GQL_BIND)"
# The pool's token list is discovered by replaying its TokenListed logs, so its
# scan floor must be AT OR BEFORE the pool's deployment — always. That is a
# different requirement from the scanners' floor, which is "this deployment's
# history onward" and legitimately moves forward over time. Deriving one from the
# other silently empties the token list the moment they diverge: the scan starts
# after the listings, finds nothing, and the Swap view renders a pool with zero
# tokens. Hence its own knob, defaulting to the chain's floor.
: "${SWAP_FROM_BLOCK:=$(start_block_for "$SWAP_CHAIN" "${CRPC[$swap_idx]}")}"
# M-8 (audit 2026-09-16): built with jq, never by pasting values between literal
# quotes. A chain name, symbol or url containing a `"` used to close the string
# and rewrite the registry the API and the UI both trust — and `--argjson` for
# the numbers means a non-numeric chain_id/block fails here rather than being
# emitted as bare JSON garbage.
{
  for i in "${!CID[@]}"; do
    # per-chain token list from ASSETS (symbol + address), for the UI's picker
    toks="$(
      for sym in "${ASYMS[@]}"; do
        t="${ATOKEN[$sym|${CID[$i]}]:-}"
        [[ -n "$t" ]] || continue
        jq -n --arg symbol "$sym" --arg address "$t" '{$symbol, $address}'
      done | jq -s '.'
    )"
    # `rpc_url` is what the API itself calls (server-side, may carry a key);
    # `public_rpc_url` is the only one it ever serves to a browser (H-4).
    pub="$(public_rpc_for "${CID[$i]}" "${CRPC[$i]}")"
    args=(--argjson chain_id "${CID[$i]}" --arg name "${CNAME[$i]}"
          --arg rpc_url "${CRPC[$i]}" --arg gate "${CGATE[$i]}"
          --arg token "${CTOKEN[$i]}" --argjson tokens "$toks")
    filter='{$chain_id, $name, $rpc_url, $gate, $token, $tokens}'
    [[ -n "$pub" ]] && { args+=(--arg public_rpc_url "$pub"); filter+=' + {$public_rpc_url}'; }
    # The swap pool rides in the registry too (`swap_pool`, read over this
    # entry's rpc_url), so no RPC url has to go on the API's command line.
    if [[ "$ENABLE_SWAP" == "true" && $i == "$swap_idx" && -n "${SWAP_POOL:-}" ]]; then
      args+=(--arg pool "$SWAP_POOL" --argjson from_block "$SWAP_FROM_BLOCK"
             --argjson max_block_range "$MAX_BLOCK_RANGE")
      filter+=' + {swap_pool: {address: $pool, $from_block, $max_block_range}}'
    fi
    jq -n "${args[@]}" "$filter"
  done
} | jq -s '.' > "$REG_JSON"

# No `--gate` / `--swap` flags: the API folds every registry chain's gate and
# `swap_pool` into its maps itself, so the keyed RPC urls stay in the 0600
# chains.json instead of on a world-readable command line (/proc/*/cmdline).
GQL_ARGS=(--bind "$GQL_BIND" --store-url "$STORE_URL" --threshold "$THRESHOLD"
          --chains-file "$REG_JSON" --allow-mutations)
# No --db-url: graphql-api reads the indexer's history through the sig-store's
# Read scope, on the reader token it already holds. It is the only service meant
# to face the internet, so it gets no database credential of its own.

export GRAPHQL_MAX_BLOCK_RANGE="$MAX_BLOCK_RANGE"
spawn graphql-api.log -- "$ROOT/target/debug/graphql-api" "${GQL_ARGS[@]}"
ok=false
for _ in $(seq 1 60); do curl -s "http://$GQL_BIND/health" >/dev/null 2>&1 && { ok=true; break; }; sleep 0.25; done
$ok || die "graphql-api did not come up (see $RUN_DIR/graphql-api.log)"
info "graphql-api healthy"

# ---------------------------------------------------------------------------
# 11. frontend (vite dev server)
# ---------------------------------------------------------------------------
say "starting frontend (vite on :$WEB_PORT)"
# From the lockfile, with the same command CI and docker/Dockerfile.frontend
# use. The repo tracks only frontend/bun.lock — `npm install` ignores it and
# resolves a fresh tree, so a launcher could run dependency versions nothing in
# CI ever built or tested (audit round 5, LOW; the round-4 fix never reached
# the launchers).
if [[ ! -d "$FRONTEND/node_modules" ]]; then
  export PATH="$PATH:$HOME/.bun/bin"
  command -v bun >/dev/null 2>&1 || die "bun not found: the frontend installs from frontend/bun.lock (bun install --frozen-lockfile), as CI does — https://bun.sh"
  ( cd "$FRONTEND" && bun install --frozen-lockfile ) || die "bun install --frozen-lockfile failed (frontend/bun.lock out of date with package.json?)"
fi
( cd "$FRONTEND" && VITE_PROXY_TARGET="http://$BIND_HOST:$GQL_PORT" \
    spawn web.log -- npx vite --host "$WEB_HOST" --port "$WEB_PORT" --strictPort )
for _ in $(seq 1 80); do curl -s "http://127.0.0.1:$WEB_PORT/" >/dev/null 2>&1 && break; sleep 0.3; done

# ---------------------------------------------------------------------------
# 12. summary
# ---------------------------------------------------------------------------
say "stack is up  ($N chains, ${#ASYMS[@]} asset(s), full-mesh bridging)"
printf '  %-12s %s\n' "frontend"  "http://$WEB_HOST:$WEB_PORT"
printf '  %-12s %s\n' "graphql"   "http://$GQL_BIND  (POST /graphql, GraphiQL at /)"
printf '  %-12s %s\n' "sig-store" "$STORE_URL"
for i in "${!CID[@]}"; do
  # list the assets bridgeable on this chain
  toks=""
  for sym in "${ASYMS[@]}"; do
    t="${ATOKEN[$sym|${CID[$i]}]:-}"; [[ -n "$t" ]] && toks+="$sym "
  done
  # never echo a keyed url: a terminal scrollback is a log too
  shown="${CRPC[$i]}"; is_local_rpc "$shown" || shown="${PUBLIC_RPCS[${CID[$i]}]:-<private rpc, see $CONFIG>}"
  printf '  %-12s %s\n' "${CNAME[$i]}" "$shown   gate ${CGATE[$i]}"
  printf '  %-12s   assets: %s\n' "" "${toks:-none}"
done
echo
echo "  MetaMask: add each network above, then import the deployer to move funds:"
echo "    address $DEPLOYER_ADDR   (key: DEPLOYER_KEY in $CONFIG — not printed)"
echo
echo "  logs:  $RUN_DIR/*.log     addresses: $ADDR_ENV     secrets: $TOKENS_ENV"
echo "  stop:  bash scripts/stop.sh $([ "$CONFIG" = "$ROOT/scripts/run.config" ] || echo "$CONFIG")"
