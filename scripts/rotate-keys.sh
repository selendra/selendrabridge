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
# T-5: the price-keeper signed with the key that is owner() of every gate and
# pool, so that one container held governance (scheduleUpgrade,
# scheduleGovernance, transferOwnership, seal, ...). And no gate had a guardian,
# so nobody but that same key could cancel a scheduled upgrade: the 48 h timelock
# was defended only by the key it is meant to defend against.
#
# Order, which matters:
#   1. handover (signed by the CURRENT owner)
#        pool.setOracle(new-oracle)      the price-keeper's only role
#        gate/pool.setGuardian(guardian) optional, but see above; do it here,
#                                        while the hot key can still send it
#        gate/pool.transferOwnership(new-owner)   step 1 of 2; nothing moves yet
#   2. put the NEW ORACLE key in price-keeper.toml and restart price-keeper.
#      Between 1 and 2 the keeper logs "we are not this pool's oracle" — prices
#      go stale for at most one poll, they are not moved.
#   3. accept (signed by the NEW owner, from its cold wallet/keystore)
#        gate/pool.acceptOwnership()
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

# chain_id \t rpc \t gate \t pool  — EVM entries only (a 0x-address gate).
mapfile -t ROWS < <(jq -r '.[]
  | select((.gate // "") | test("^0x[0-9a-fA-F]{40}$"))
  | [.chain_id, (.rpc_url // .public_rpc_url), .gate, (.swap_pool.address // "")] | @tsv' "$CHAINS")
(( ${#ROWS[@]} )) || die "no EVM chains in $CHAINS"

AUTH=()
signer() {
  [[ -n "$KEYSTORE" ]] || die "--keystore is required for $MODE"
  [[ -f "$KEYSTORE" ]] || die "keystore not found: $KEYSTORE"
  AUTH=(--keystore "$KEYSTORE")
  [[ -n "$PASSFILE" ]] && AUTH+=(--password-file "$PASSFILE")
  SIGNER="$(cast wallet address "${AUTH[@]}")" || die "keystore does not decrypt"
  echo "signer: $SIGNER"
}

call() { cast call --rpc-url "$1" "$2" "$3" 2>/dev/null || echo "?"; }

# send <rpc> <to> <sig> [args...] — prints, and sends only with --execute.
send() {
  local rpc="$1" to="$2"; shift 2
  printf '  %s %s\n' "$to" "$*"
  (( EXECUTE )) || return 0
  cast send --rpc-url "$rpc" "${AUTH[@]}" "$to" "$@" >/dev/null \
    || die "send failed: $to $*"
}

status() {
  for row in "${ROWS[@]}"; do
    IFS=$'\t' read -r cid rpc gate pool <<<"$row"
    echo "== chain $cid"
    echo "  gate $gate  owner=$(call "$rpc" "$gate" 'owner()(address)')  pending=$(call "$rpc" "$gate" 'pendingOwner()(address)')  guardian=$(call "$rpc" "$gate" 'guardian()(address)')"
    [[ -n "$pool" ]] && echo "  pool $pool  owner=$(call "$rpc" "$pool" 'owner()(address)')  pending=$(call "$rpc" "$pool" 'pendingOwner()(address)')  oracle=$(call "$rpc" "$pool" 'oracle()(address)')  guardian=$(call "$rpc" "$pool" 'guardian()(address)')"
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

  for row in "${ROWS[@]}"; do
    IFS=$'\t' read -r cid rpc gate pool <<<"$row"
    echo "== chain $cid"
    for c in "$gate" ${pool:+"$pool"}; do
      [[ "$(lc "$(call "$rpc" "$c" 'owner()(address)')")" == "$s" ]] \
        || die "chain $cid: $c is not owned by the signer $SIGNER"
    done
    [[ -n "$pool" ]] && send "$rpc" "$pool" 'setOracle(address)' "$NEW_ORACLE"
    if [[ -n "$GUARDIAN" ]]; then
      send "$rpc" "$gate" 'setGuardian(address)' "$GUARDIAN"
      [[ -n "$pool" ]] && send "$rpc" "$pool" 'setGuardian(address)' "$GUARDIAN"
    fi
    send "$rpc" "$gate" 'transferOwnership(address)' "$NEW_OWNER"
    [[ -n "$pool" ]] && send "$rpc" "$pool" 'transferOwnership(address)' "$NEW_OWNER"
  done
  (( EXECUTE )) || { echo "(dry run — pass --execute to send)"; return; }
  echo
  echo "next: put the key for $NEW_ORACLE in price-keeper.toml [oracle], restart price-keeper,"
  echo "      then run 'accept' with the new owner's keystore."
}

accept() {
  signer
  local s; s="$(lc "$SIGNER")"
  for row in "${ROWS[@]}"; do
    IFS=$'\t' read -r cid rpc gate pool <<<"$row"
    echo "== chain $cid"
    for c in "$gate" ${pool:+"$pool"}; do
      [[ "$(lc "$(call "$rpc" "$c" 'pendingOwner()(address)')")" == "$s" ]] \
        || die "chain $cid: $c has no pending handover to $SIGNER (run 'handover' first)"
      send "$rpc" "$c" 'acceptOwnership()'
    done
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
