#!/usr/bin/env bash
# Deploy a Gate the way a Gate actually deploys now. Sourced by the suites here.
#
# WHY THIS EXISTS. Every script in this directory used to do:
#
#     forge create src/Gate.sol:Gate --constructor-args "[$V1,$V2]" "$THRESHOLD"
#
# That stopped working when Gate became UUPS. A gate is now TWO contracts:
#
#   * the implementation — no constructor args, never initialized, holds no state;
#   * a `GateProxy` (ERC1967) whose constructor delegatecalls
#     `initialize(address[],uint256,bytes32)`. THE PROXY IS THE GATE — its
#     address is what configs, validators and keepers must point at.
#
# The old form now fails outright ("Constructor argument count mismatch: expected
# 0 but got 2"). Twelve scripts carried their own copy of it, so the fix lives
# here once instead of twelve times.
#
# The third initialize argument is `bridgeDomain`: the deployment generation that
# is mixed into every submissionId, so signatures from a previous deployment
# cannot be replayed against a fresh gate. Every gate in ONE mesh must share it,
# or the two sides compute different ids for the same transfer and nothing
# claims.
#
# So the domain is fixed HERE, at source time, once per script run. It cannot be
# established inside `deploy_gate`: callers invoke it as `GATE=$(deploy_gate …)`,
# and an assignment made in that subshell dies with it — the second gate would
# silently get a different domain. Setting it at source time means every
# subshell inherits the same value.
#
# Usage:
#   source "$(dirname "${BASH_SOURCE[0]}")/_deploy_gate.sh"
#   GATE_A=$(deploy_gate "$RPC_A" "$KEY0" "[$V1,$V2]" 2)   # both gates share
#   GATE_B=$(deploy_gate "$RPC_B" "$KEY0" "[$V1,$V2]" 2)   # $BRIDGE_DOMAIN
#
# Pass a 5th argument only to deploy a gate deliberately OUTSIDE this mesh.
#
# Destinations (M-3, audit round 4): `send` reverts UnsupportedChain unless the
# owner has listed the destination chain. The suites here bridge between the
# local anvil ids 1337/1338/1339 (plus 9999, which db-e2e.sh uses to prove the
# validator allowlist blocks a chain the GATE accepts, and the Solana test id),
# so every gate lists all of them — override with GATE_PEER_CHAINS="a b c".
# `deploy_gate` returns a gate in its SETUP PHASE: registration is instant, and
# `claim` reverts with NotSealed (M-1, audit 2026-09-16). Every suite must
# therefore call `seal_gate rpc key gate` as its LAST wiring step — after
# set_bridge_decimals and setLocalToken, before any send/claim — which is the
# order production uses (run.sh, deploy-from-json.sh). Suites that never claim
# seal anyway: an unsealed destination makes a "claim reverts" assertion pass
# for the wrong reason. `set_bridge_decimals rpc key gate token` must run for
# every token a gate will send or map, before setLocalToken / send / seal.
#
# The setup phase also EXPIRES on its own (SETUP_WINDOW after deploy), so a gate
# left unsealed does not keep one-block registration forever. That window is far
# longer than any suite here runs.

_GATE_CONTRACTS="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../contracts" && pwd)"

# Pull the created address out of `forge create --json`. Matching the
# "deployedTo" KEY rather than the first 40-hex run in the blob matters: the
# JSON also carries "deployer" and a 64-hex tx hash.
_deployed_to() { sed -n 's/.*"deployedTo": *"\([^"]*\)".*/\1/p' | head -1; }

_forge_create() {  # rpc key target [extra args...] -> address
  local rpc=$1 key=$2 target=$3; shift 3
  ( cd "$_GATE_CONTRACTS" && forge create "$target" \
      --rpc-url "$rpc" --private-key "$key" --broadcast --json "$@" ) | _deployed_to
}

# One domain per script run, shared by every gate it deploys. Distinct across
# runs: reusing a domain is exactly what lets an old deployment's signatures
# replay against a fresh gate.
: "${BRIDGE_DOMAIN:=$(cast keccak "selendra-bridge-test|$(date +%s%N)-$$-$RANDOM")}"
export BRIDGE_DOMAIN

deploy_gate() {  # rpc key validators threshold [domain] -> echoes the PROXY address
  local rpc=$1 key=$2 vlist=$3 thr=$4 domain=${5:-$BRIDGE_DOMAIN}

  [[ "$domain" =~ ^0x[0-9a-fA-F]{64}$ ]] || { echo "deploy_gate: bad domain '$domain'" >&2; return 1; }

  local impl initdata proxy
  impl=$(_forge_create "$rpc" "$key" src/Gate.sol:Gate)
  [[ "$impl" =~ ^0x[0-9a-fA-F]{40}$ ]] || { echo "deploy_gate: implementation deploy failed on $rpc" >&2; return 1; }

  initdata=$(cast calldata "initialize(address[],uint256,bytes32)" "$vlist" "$thr" "$domain")
  proxy=$(_forge_create "$rpc" "$key" src/GateProxy.sol:GateProxy --constructor-args "$impl" "$initdata")
  [[ "$proxy" =~ ^0x[0-9a-fA-F]{40}$ ]] || { echo "deploy_gate: proxy deploy failed on $rpc" >&2; return 1; }

  local peer
  for peer in ${GATE_PEER_CHAINS:-1337 1338 1339 31337 9999 7565164}; do
    cast send "$proxy" "setSupportedChain(uint256,bool)" "$peer" true \
      --rpc-url "$rpc" --private-key "$key" >/dev/null 2>&1 \
      || { echo "deploy_gate: setSupportedChain($peer) failed on $rpc" >&2; return 1; }
  done

  printf '%s' "$proxy"
}

# Bridge decimals: a gate refuses `setLocalToken(id, token)` and `send(token, …)`
# with BridgeDecimalsUnset until the owner registers the token's bridge decimals.
# The suites register the IDENTITY (bridgeDecimals = the token's own decimals), so
# no amount, submissionId or assertion changes. Write-once, and instant only while
# the gate is unsealed — so call this BEFORE setLocalToken / send / seal_gate.
# Every gate in a mesh must register the same value for the same asset.
set_bridge_decimals() {  # rpc key gate token [decimals] — defaults to token.decimals()
  local rpc=$1 key=$2 gate=$3 token=$4 dec=${5:-}
  if [[ -z "$dec" ]]; then
    dec=$(cast call "$token" "decimals()(uint8)" --rpc-url "$rpc") \
      || { echo "set_bridge_decimals: decimals() failed for $token on $rpc" >&2; return 1; }
  fi
  cast send "$gate" "setBridgeDecimals(address,uint8)" "$token" "$dec" \
    --rpc-url "$rpc" --private-key "$key" >/dev/null \
    || { echo "set_bridge_decimals: setBridgeDecimals($token,$dec) failed on $gate ($rpc)" >&2; return 1; }
}

seal_gate() {  # rpc key gate — irreversible; setLocalToken then needs scheduleGovernance + 48h
  cast send "$3" "seal()" --rpc-url "$1" --private-key "$2" >/dev/null
}
