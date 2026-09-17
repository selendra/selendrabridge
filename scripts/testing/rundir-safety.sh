#!/usr/bin/env bash
# Regression test for _rundir.sh (audit round 5, LOW): the test scripts used to
# `source` addresses.env / tokens.env from fixed /tmp paths, so a file planted
# there by another local user ran as code. Offline, no services.
#
#   bash scripts/testing/rundir-safety.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=_rundir.sh
source "$ROOT/scripts/testing/_rundir.sh"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
fail=0
check() { if eval "$2"; then printf '  ok   %s\n' "$1"; else printf '  FAIL %s\n' "$1"; fail=1; fi; }

mkdir -m 700 "$WORK/good"
printf '%s\n' '# comment' 'CHAIN_1337_GATE=0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512' 'SWAP_POOL=' \
  'BRIDGE_DOMAIN=0xabc' > "$WORK/good/addresses.env"
check "a plain file from a private dir loads" \
  '( load_env_file "$WORK/good/addresses.env" 2>/dev/null && [[ "$CHAIN_1337_GATE" == 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512 && -z "$SWAP_POOL" ]] )'

printf '%s\n' 'TOKEN_TST_1337=0x1' "PWNED=\$(touch $WORK/executed)" > "$WORK/good/evil.env"
check "a command substitution is refused, not run" \
  '! ( load_env_file "$WORK/good/evil.env" 2>/dev/null ) && [[ ! -e "$WORK/executed" ]]'
printf '%s\n' 'A=1; touch '"$WORK/executed2" > "$WORK/good/evil2.env"
check "a trailing command is refused, not run" \
  '! ( load_env_file "$WORK/good/evil2.env" 2>/dev/null ) && [[ ! -e "$WORK/executed2" ]]'
printf 'path=/x\n' > "$WORK/good/lower.env"
check "a key that is not [A-Z_][A-Z0-9_]* is refused" '! ( load_env_file "$WORK/good/lower.env" 2>/dev/null )'

mkdir -m 777 "$WORK/shared"; cp "$WORK/good/addresses.env" "$WORK/shared/"
check "a world-writable run dir is refused" '! ( load_env_file "$WORK/shared/addresses.env" 2>/dev/null )'
ln -s "$WORK/good" "$WORK/link"
check "a symlinked run dir is refused" '! rundir_trusted "$WORK/link" 2>/dev/null'
if [[ "$(stat -c %u /)" != "$(id -u)" ]]; then
  check "a dir owned by another user is refused" '! rundir_trusted / 2>/dev/null'
fi

echo
(( fail )) && { echo FAILED; exit 1; }
echo "all passed"
