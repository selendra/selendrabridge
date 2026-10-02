#!/usr/bin/env bash
# rotate-keys.sh — move the live EVM roles off the hot deployer key (audit T-5).
#
#   bash scripts/rotate-keys.sh <chains.json> status
#   bash scripts/rotate-keys.sh <chains.json> handover --keystore K [--password-file F]
#        --new-oracle ADDR --new-owner ADDR [--guardian ADDR] [--execute]
#   bash scripts/rotate-keys.sh <chains.json> accept   --keystore K [--password-file F] [--execute]
#
# <chains.json> is a generation's runtime chain list, e.g.
# docker/testnet-mesh10/configs/chains.json. Non-EVM entries (Solana) are skipped.
#
# Contracts covered, per chain: the gate, the swap pool (`swap_pool`) and the
# SwapRouter (`router`, or `swap_router`; a bare address or {"address": ...}).
# The pool and router are optional; a chain with no router recorded gets a
# WARNING, because a router left on the hot key is not moved by this script
# (audit L7-9: its owner sets remoteRouter instantly and so decides where
# every future swap-and-bridge's stable lands on the destination).
#
# T-5: the price-keeper signed with the key that is owner() of every gate and
# pool, so that one container held governance (scheduleUpgrade,
# scheduleGovernance, transferOwnership, seal, ...). And no gate had a guardian,
# so nobody but that same key could cancel a scheduled upgrade: the 48 h timelock
# was defended only by the key it is meant to defend against.
#
# Order, which matters:
#   1. handover (signed by the CURRENT owner)
#        pool.setOracle(new-oracle)      the price-keeper's only role
#        gate/pool/router.setGuardian(guardian)  optional, but see above; do it
#                                        here, while the hot key can still send it
#        gate/pool/router.transferOwnership(new-owner)  step 1 of 2; nothing moves yet
#   2. put the NEW ORACLE key in price-keeper.toml and restart price-keeper.
#      Between 1 and 2 the keeper logs "we are not this pool's oracle" — prices
#      go stale for at most one poll, they are not moved.
#   3. accept (signed by the NEW owner, from its cold wallet/keystore)
#        gate/pool/router.acceptOwnership()
#   4. status — every owner/oracle/guardian must be off the old key.
#
# Without --execute, handover/accept only print the calls they would send.
# Keys are taken from an encrypted keystore only, never argv (audit round 6).
set -euo pipefail
umask 077

die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null || die "$1 not found${2:+ ($2)}"; }
need cast; need jq

(( $# >= 2 )) || die "usage: $0 <chains.json> status|handover|accept [options]"
CHAINS="$1"; MODE="$2"; shift 2
[[ -f "$CHAINS" ]] || die "no such file: $CHAINS"

KEYSTORE="" PASSFILE="" NEW_ORACLE="" NEW_OWNER="" GUARDIAN="" EXECUTE=0
while (( $# )); do
  case "$1" in
    --keystore)      KEYSTORE="$2"; shift 2 ;;
    --password-file) PASSFILE="$2"; shift 2 ;;
    --new-oracle)    NEW_ORACLE="$2"; shift 2 ;;
    --new-owner)     NEW_OWNER="$2"; shift 2 ;;
    --guardian)      GUARDIAN="$2"; shift 2 ;;
    --execute)       EXECUTE=1; shift ;;
    *) die "unknown option: $1" ;;
  esac
done

is_addr() { [[ "$1" =~ ^0x[0-9a-fA-F]{40}$ ]] && [[ ! "$1" =~ ^0x0{40}$ ]]; }
lc() { tr '[:upper:]' '[:lower:]' <<<"$1"; }

# chain_id US rpc US gate US pool US router — EVM entries only (a 0x-address
# gate). Fields are split on the ASCII unit separator, not a tab: tab is IFS
# whitespace, so `read` would collapse an empty pool and shift the router into
# its place.
US=$'\x1f'
addr_of() { printf '%s' '(if type == "object" then (.address // "") else (. // "") end)'; }
mapfile -t ROWS < <(jq -r "
  .[]
  | select((.gate // \"\") | test(\"^0x[0-9a-fA-F]{40}\$\"))
  | [ (.chain_id | tostring), (.rpc_url // .public_rpc_url), .gate,
      ((.swap_pool // \"\") | $(addr_of)),
      ((.router // .swap_router // \"\") | $(addr_of)) ]
  | join(\"\u001f\")" "$CHAINS")
(( ${#ROWS[@]} )) || die "no EVM chains in $CHAINS"

row() { IFS="$US" read -r cid rpc gate pool router <<<"$1"; }

# Every chain must name its router or say loudly that it does not.
for r in "${ROWS[@]}"; do
  row "$r"
  if [[ -z "$router" ]]; then
    printf 'WARNING: chain %s has no router recorded in %s — if a SwapRouter is deployed there it is\n' "$cid" "$CHAINS" >&2
    printf '         NOT covered by this script and stays on its current owner. Add "router": "0x…".\n' >&2
  elif ! is_addr "$router"; then
    die "chain $cid: router '$router' is not a non-zero 0x address"
  fi
done

AUTH=()
signer() {
  [[ -n "$KEYSTORE" ]] || die "--keystore is required for $MODE"
  [[ -f "$KEYSTORE" ]] || die "keystore not found: $KEYSTORE"
  AUTH=(--keystore "$KEYSTORE")
  [[ -n "$PASSFILE" ]] && AUTH+=(--password-file "$PASSFILE")
  SIGNER="$(cast wallet address "${AUTH[@]}")" || die "keystore does not decrypt"
  echo "signer: $SIGNER"
}

call() { cast call --rpc-url "$1" "$2" "${@:3}" 2>/dev/null || echo "?"; }

# send <rpc> <to> <sig> [args...] — prints, and sends only with --execute.
send() {
  local rpc="$1" to="$2"; shift 2
  printf '  %s %s\n' "$to" "$*"
  (( EXECUTE )) || return 0
  cast send --rpc-url "$rpc" "${AUTH[@]}" "$to" "$@" >/dev/null \
    || die "send failed: $to $*"
}

status() {
  local r d dcid drouter remote
  for r in "${ROWS[@]}"; do
    row "$r"
    echo "== chain $cid"
    echo "  gate $gate  owner=$(call "$rpc" "$gate" 'owner()(address)')  pending=$(call "$rpc" "$gate" 'pendingOwner()(address)')  guardian=$(call "$rpc" "$gate" 'guardian()(address)')"
    [[ -n "$pool" ]] && echo "  pool $pool  owner=$(call "$rpc" "$pool" 'owner()(address)')  pending=$(call "$rpc" "$pool" 'pendingOwner()(address)')  oracle=$(call "$rpc" "$pool" 'oracle()(address)')  guardian=$(call "$rpc" "$pool" 'guardian()(address)')"
    if [[ -z "$router" ]]; then
      echo "  router (none recorded — NOT checked)"
      continue
    fi
    echo "  router $router  owner=$(call "$rpc" "$router" 'owner()(address)')  pending=$(call "$rpc" "$router" 'pendingOwner()(address)')  guardian=$(call "$rpc" "$router" 'guardian()(address)')"
    # remoteRouter(peer) must be the router this file records for that peer;
    # anything else is where the owner key is sending swap-and-bridge stable.
    for d in "${ROWS[@]}"; do
      IFS="$US" read -r dcid _ _ _ drouter <<<"$d"
      [[ "$dcid" != "$cid" ]] || continue
      remote="$(call "$rpc" "$router" 'remoteRouter(uint256)(bytes)' "$dcid")"
      if [[ -z "$drouter" ]]; then
        echo "    remoteRouter($dcid)=$remote  (peer has no router recorded)"
      elif [[ "$(lc "$remote")" == "$(lc "$drouter")" ]]; then
        echo "    remoteRouter($dcid)=$remote  ok"
      else
        echo "    remoteRouter($dcid)=$remote  MISMATCH: expected $drouter"
      fi
    done
  done
}

handover() {
  is_addr "$NEW_ORACLE" || die "--new-oracle must be a non-zero address"
  is_addr "$NEW_OWNER"  || die "--new-owner must be a non-zero address"
  [[ -z "$GUARDIAN" ]] || is_addr "$GUARDIAN" || die "--guardian must be a non-zero address"
  signer
  local s; s="$(lc "$SIGNER")"
  # The whole point is to get OFF this key: refuse to hand a role back to it.
  for a in "$NEW_ORACLE" "$NEW_OWNER" ${GUARDIAN:+"$GUARDIAN"}; do
    [[ "$(lc "$a")" != "$s" ]] || die "$a is the current owner key — that is what T-5 moves away from"
  done
  [[ "$(lc "$NEW_ORACLE")" != "$(lc "$NEW_OWNER")" ]] \
    || die "the oracle is a hot key in a running container; it must not also be the owner"
  [[ -z "$GUARDIAN" || "$(lc "$GUARDIAN")" != "$(lc "$NEW_ORACLE")" ]] \
    || die "the guardian must not be the hot oracle key"

  local r c
  # Check every chain before sending anything, so a wrong signer or a
  # contract already handed over stops the run before it is half done.
  for r in "${ROWS[@]}"; do
    row "$r"
    for c in "$gate" ${pool:+"$pool"} ${router:+"$router"}; do
      [[ "$(lc "$(call "$rpc" "$c" 'owner()(address)')")" == "$s" ]] \
        || die "chain $cid: $c is not owned by the signer $SIGNER"
    done
  done
  for r in "${ROWS[@]}"; do
    row "$r"
    echo "== chain $cid"
    [[ -n "$pool" ]] && send "$rpc" "$pool" 'setOracle(address)' "$NEW_ORACLE"
    if [[ -n "$GUARDIAN" ]]; then
      for c in "$gate" ${pool:+"$pool"} ${router:+"$router"}; do
        send "$rpc" "$c" 'setGuardian(address)' "$GUARDIAN"
      done
    fi
    for c in "$gate" ${pool:+"$pool"} ${router:+"$router"}; do
      send "$rpc" "$c" 'transferOwnership(address)' "$NEW_OWNER"
    done
    [[ -n "$router" ]] || echo "  WARNING: no router recorded for chain $cid — a SwapRouter there is NOT handed over"
  done
  (( EXECUTE )) || { echo "(dry run — pass --execute to send)"; return; }
  echo
  echo "next: put the key for $NEW_ORACLE in price-keeper.toml [oracle], restart price-keeper,"
  echo "      then run 'accept' with the new owner's keystore."
}

accept() {
  signer
  local s; s="$(lc "$SIGNER")"
  local r c
  for r in "${ROWS[@]}"; do
    row "$r"
    for c in "$gate" ${pool:+"$pool"} ${router:+"$router"}; do
      [[ "$(lc "$(call "$rpc" "$c" 'pendingOwner()(address)')")" == "$s" ]] \
        || die "chain $cid: $c has no pending handover to $SIGNER (run 'handover' first)"
    done
  done
  for r in "${ROWS[@]}"; do
    row "$r"
    echo "== chain $cid"
    for c in "$gate" ${pool:+"$pool"} ${router:+"$router"}; do
      send "$rpc" "$c" 'acceptOwnership()'
    done
    [[ -n "$router" ]] || echo "  WARNING: no router recorded for chain $cid — a SwapRouter there is NOT accepted"
  done
  (( EXECUTE )) || echo "(dry run — pass --execute to send)"
}

case "$MODE" in
  status)   status ;;
  handover) handover ;;
  accept)   accept ;;
  *) die "mode must be status, handover or accept" ;;
esac
if [[ "$MODE" != status ]] && (( EXECUTE )); then echo; status; fi
