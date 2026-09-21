#!/usr/bin/env bash
# Regression test for M-8 (audit 2026-09-16): the launchers must treat config
# values as DATA — never as shell code, never as raw JSON. Offline, no services.
#
#   bash scripts/testing/registry-escaping.sh
#
# Two sinks, both reproduced here against the real code lifted from the scripts:
#
#   1. `spawn` used to be `bash -c "exec $1"` with $1 assembled from config
#      values, so `.sig_store.bind` = `127.0.0.1:8080 $(cmd)` ran `cmd` as the
#      operator while bash expanded the string.
#   2. `run.sh` used to build chains.json by pasting values between literal
#      quotes, so a chain name containing a `"` rewrote the registry that the
#      API and the UI both trust.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
command -v jq >/dev/null || { echo "jq is required"; exit 1; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
fail=0
check() { if eval "$2"; then printf '  ok   %s\n' "$1"; else printf '  FAIL %s\n' "$1"; fail=1; fi; }

# --- 1. spawn takes argv, so a config value is never parsed as code -----------

# The real post-fix body, lifted from scripts/bridge-from-json.sh.
RUN_DIR="$WORK/run"; mkdir -p "$RUN_DIR"
PIDS="$WORK/pids.tsv"; : > "$PIDS"
die() { echo "$*" >&2; return 1; }
spawn() {
  local log="$1" display="$2" pattern="$3"; shift 3
  [[ "${1:-}" == "--" ]] || die "spawn: expected -- before the command (internal error)"
  shift
  setsid "$@" >"$RUN_DIR/$log" 2>&1 </dev/null &
  local pid=$!
  disown || true
  printf '%s\t%s\t%s\n' "$pid" "$display" "$pattern" >> "$PIDS"
}

HOSTILE="127.0.0.1:8080 \$(touch $WORK/PWNED)"
spawn sig-store.log sig-store "x" -- /bin/true --bind "$HOSTILE"
sleep 0.5
check "a \$(…) in a bind is passed as one argument, not run" '[[ ! -e "$WORK/PWNED" ]]'

# The same value through the OLD body must run it — otherwise this test proves
# nothing about the fix.
old_spawn() { setsid bash -c "exec $1" >/dev/null 2>&1 & disown || true; }
old_spawn "/bin/true --bind 127.0.0.1:8080 \$(touch $WORK/OLD_PWNED)"
sleep 0.5
check "(control) the old bash -c body DOES run it" '[[ -e "$WORK/OLD_PWNED" ]]'

# --- 2. the registry survives a value that used to break out ------------------

# A chain name carrying a quote, a brace and a newline: the shape that used to
# terminate the JSON string and inject a sibling key.
NAME='Anvil "A" }, {"chain_id": 99, "gate": "0xdead
evil'
SYM='T"ST'

# Run run.sh's REAL generator, not a copy of it — extracted between its own
# markers so this test fails if that block regresses.
sed -n '/^# M-8 (audit 2026-09-16): built with jq/,/^} | jq -s/p' "$ROOT/scripts/run.sh" \
  > "$WORK/gen.sh"
grep -q 'jq -n "\${args\[@\]}"' "$WORK/gen.sh" \
  || { echo "  FAIL could not extract the generator from run.sh"; exit 1; }

# These are the inputs run.sh's generator reads; shellcheck cannot see the use
# because the generator arrives via `source` below.
# shellcheck disable=SC2034
{
REG_JSON="$WORK/chains.json"
CID=(1337); CNAME=("$NAME"); CRPC=("http://127.0.0.1:8545"); CGATE=("0xgate"); CTOKEN=("0xtok")
ASYMS=("$SYM"); declare -A ATOKEN=(["$SYM|1337"]="0xaaa")
ENABLE_SWAP=false; swap_idx=-1; SWAP_POOL=""; SWAP_FROM_BLOCK=0; MAX_BLOCK_RANGE=500
}
public_rpc_for() { echo "http://127.0.0.1:8545"; }
# shellcheck disable=SC1090
source "$WORK/gen.sh"

check "the generated registry is valid JSON" 'jq -e . "$WORK/chains.json" >/dev/null'
check "it holds exactly one chain (no injected sibling)" '[[ "$(jq -r "length" "$WORK/chains.json")" == 1 ]]'
check "the hostile name round-trips byte for byte" \
  '[[ "$(jq -r ".[0].name" "$WORK/chains.json")" == "$NAME" ]]'
check "the hostile symbol round-trips byte for byte" \
  '[[ "$(jq -r ".[0].tokens[0].symbol" "$WORK/chains.json")" == "$SYM" ]]'
check "no chain_id 99 was smuggled in" '[[ -z "$(jq -r ".[] | select(.chain_id == 99) | .chain_id" "$WORK/chains.json")" ]]'

# The OLD hand-built form, for contrast: it must produce something broken.
old_line="  {\"chain_id\": 1337, \"name\": \"$NAME\", \"gate\": \"0xgate\"}"
printf '[\n%s\n]\n' "$old_line" > "$WORK/old-chains.json"
check "(control) the old hand-built form is corrupt" \
  '! jq -e . "$WORK/old-chains.json" >/dev/null 2>&1 || [[ "$(jq -r "length" "$WORK/old-chains.json" 2>/dev/null)" != 1 ]]'

# --- 3. a non-numeric chain_id fails closed ----------------------------------
check "a non-numeric chain_id is refused, not emitted raw" \
  '! jq -n --argjson chain_id "not-a-number" "{\$chain_id}" >/dev/null 2>&1'

echo
if (( fail )); then echo FAILED; exit 1; fi
echo "registry escaping clean"
