#!/usr/bin/env bash
# Start N solana-relayer instances, one per validator key.
#
# WHY N AND NOT ONE: Solana `Sent` events are signed ONLY by relayers — the EVM
# validators never scan Solana — so a gate with threshold T needs at least T
# relayers, each holding a DISTINCT validator key. Run fewer and Solana-origin
# transfers stall at fewer signatures than the quorum, silently.
#
#   bash scripts/testing/solana-relayers.sh <config> [<config> ...]
#
# Each config needs its own `state_file` and its own `private_key_env`. Tokens
# come from $RUN_DIR/tokens.env (written by scripts/run.sh).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
# Run-dir files are PARSED, not sourced, and only from a dir this user owns
# (audit round 5, LOW: the old fixed /tmp default could be pre-created by any
# local user). See _rundir.sh.
source "$ROOT/scripts/testing/_rundir.sh"
RUN_DIR="${RUN_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/selendra-bridge/run}"
BIN="$ROOT/crates/solana-relayer/target/debug/solana-relayer"

[[ -x "$BIN" ]] || {
  echo "building solana-relayer..."
  cargo build --manifest-path crates/solana-relayer/Cargo.toml --bin solana-relayer
}

# Scoped sig-store credential (finding L-5): a relayer signs, so `Sign` is all
# it needs.
if [[ -f "$RUN_DIR/tokens.env" ]]; then
  load_env_file "$RUN_DIR/tokens.env" || exit 1
fi

# Detached so the instances outlive this shell, exactly as scripts/run.sh spawns
# its services.
spawn() { setsid bash -c "exec $1" >"$2" 2>&1 </dev/null & disown || true; }

i=0
for cfg in "$@"; do
  i=$((i + 1))
  [[ -f "$cfg" ]] || { echo "no such config: $cfg" >&2; exit 1; }
  log="$RUN_DIR/solana-relayer-$i.log"
  spawn "$BIN $cfg" "$log"
  echo "  relayer $i: $cfg -> $log"
done

sleep 6
running=$(pgrep -fc "solana-relayer /" 2>/dev/null || echo 0)
echo "  $running relayer process(es) up"
