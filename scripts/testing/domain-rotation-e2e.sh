#!/usr/bin/env bash
# End-to-end proof of audit finding M-6 (audit 2026-09-16): a bridgeDomain
# rotation must NOT turn into a per-tick revert loop in the keeper.
#
# THE BUG. `Gate.claim` rebuilds the submissionId from calldata under its OWN
# `bridgeDomain`. The keeper used to hand the stored id + params to the gate on
# trust, so after a redeploy (which rotates the domain — H-3) every unclaimed
# pre-rotation row reverted `NotEnoughSignatures` at estimateGas, every tick,
# forever, logged only as "claim failed". The fix (crates/keeper/src/main.rs:
# `agrees_with_gate` / `gate_submission_id`) reads `bridgeDomain()` once per gate,
# re-derives the id, and reports a record that does not re-derive ONCE, as
# UNCLAIMABLE, naming the rotation — without touching the chain again.
#
# Topology: Postgres (Docker) + Postgres-backed sig-store, two anvils, validator
# threshold 1, one keeper. Everything on its own ports, so it does not collide
# with db-e2e.sh or with a Docker testnet on the same host.
#
#   CHECK 1  baseline: a D1 transfer is claimed by the keeper (the harness works).
#   CHECK 2  keeper stopped; a second D1 transfer reaches quorum in the store but
#            is NOT executed on the D1 destination gate.
#   CHECK 3  "rotation": a fresh destination gate under domain D2, keeper restarted
#            against it. For the stranded D1 record the keeper must
#              a. not claim it (`executed(id)` false on the D2 gate),
#              b. warn about the domain rotation exactly ONCE for it,
#              c. never spin: no "claim failed", keeper nonce unchanged, and no
#                 eth_estimateGas / eth_sendRawTransaction reaching the chain
#                 over ~OBSERVE_SECS of ticks.
#   CHECK 4  positive control: a transfer through a D2 source gate IS claimed by
#            the SAME keeper process (the check blocks the stale domain only).
#
# Run from anywhere:  bash scripts/testing/domain-rotation-e2e.sh
set -euo pipefail
export PATH="$HOME/.foundry/bin:$HOME/.cargo/bin:$PATH"

# Two domains, fixed up front. D1 is exported as BRIDGE_DOMAIN so every
# deploy_gate call without a 5th arg lands in the D1 mesh.
D1=$(cast keccak "selendra-bridge-test|m6-D1|$(date +%s%N)-$$-$RANDOM")
D2=$(cast keccak "selendra-bridge-test|m6-D2|$(date +%s%N)-$$-$RANDOM")
export BRIDGE_DOMAIN=$D1
source "$(dirname "${BASH_SOURCE[0]}")/_deploy_gate.sh"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTRACTS="$ROOT/contracts"
LOGS="$ROOT/.e2e-logs"
mkdir -p "$LOGS"
rm -f "$LOGS"/m6-*.json "$LOGS"/m6-*.log "$LOGS"/m6-*.toml

PG_NAME=bridge-pg-m6
PG_PORT=5436
DATABASE_URL="postgres://bridge:bridge@127.0.0.1:${PG_PORT}/bridge?sslmode=disable"

# anvil default accounts: [0] deployer/sender, [1] validator, [4] keeper, [6] receiver
ACC0=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
KEY0=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
V1=0x70997970C51812dc3A010C7d01b50e0d17dc79C8; V1K=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
KEEPER=0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65
KEEPER_KEY=0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a
RECEIVER=0x976EA74026E726554dB657fA54763abd0C3a0aa9

SRC_PORT=18645
DST_PORT=18646
SRC_RPC=http://127.0.0.1:$SRC_PORT
DST_RPC=http://127.0.0.1:$DST_PORT
SRC_CHAIN=1337
DST_CHAIN=1338
STORE_BIND=127.0.0.1:18680
STORE_URL=http://$STORE_BIND
AMOUNT=100000000000000000000   # 100e18
POLL_MS=300
OBSERVE_SECS=${OBSERVE_SECS:-10}   # ~30 keeper ticks at POLL_MS

declare -a PIDS=()
track() { PIDS+=("$1"); }
KEEPER_PID=""
cleanup() {
  echo "--- cleaning up ---"
  # Only what THIS script started — never a pattern kill, which would take down
  # any other anvil on the host.
  for p in "${PIDS[@]:-}" "${KEEPER_PID:-}"; do [[ -n "${p:-}" ]] && kill "$p" 2>/dev/null || true; done
  docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

for port in $SRC_PORT $DST_PORT ${STORE_BIND##*:} $PG_PORT; do
  if ss -ltn "sport = :$port" | grep -q LISTEN; then
    echo "❌ port $port is already in use; refusing to start"; exit 1
  fi
done

deployed_to() { grep deployedTo | grep -oE '0x[0-9a-fA-F]{40}' | head -1; }
bal() { cast call "$1" "balanceOf(address)(uint256)" "$2" --rpc-url "$3" | awk '{print $1}'; }
debridge_id() { local chain=$1 token=$2; cast keccak "0x$(printf '%064x' "$chain")${token#0x}"; }
executed() { cast call "$1" "executed(bytes32)(bool)" "$2" --rpc-url "$DST_RPC"; }
fail() {
  echo "❌ FAIL: $1"
  echo "--- validator.log (tail) ---"; tail -15 "$LOGS/m6-validator.log" 2>/dev/null || true
  echo "--- keeper1.log (tail) ---";   tail -10 "$LOGS/m6-keeper1.log" 2>/dev/null || true
  echo "--- keeper2.log (tail) ---";   tail -25 "$LOGS/m6-keeper2.log" 2>/dev/null || true
  exit 1
}

# --- sig-store JSON helpers ---------------------------------------------------
sub_ids() { # all submission ids in the store, one per line
  curl -fsS "$STORE_URL/submissions" | python3 -c "import sys,json;[print(r['submission_id'].lower()) for r in json.load(sys.stdin)]"
}
sub_field() { # $1=submission_id $2=field -> value (lists -> length), or NONE
  curl -fsS "$STORE_URL/submissions" | python3 -c "
import sys,json
m=[r for r in json.load(sys.stdin) if r['submission_id'].lower()=='${1,,}']
v=m[0].get('$2') if m else None
print('NONE' if v is None else (len(v) if isinstance(v,list) else v))"
}
keeper_claimtx() { # $1=submission_id -> keeper's reported claim tx, or NONE
  curl -fsS "$STORE_URL/history" | python3 -c "
import sys,json
m=[r for r in json.load(sys.stdin) if r.get('submission_id','').lower()=='${1,,}']
print((m[0].get('keeper_claim_tx') or m[0].get('claim_tx') or 'NONE') if m else 'NONE')"
}
wait_new_id() { # $1=file of ids known before -> echoes the one new id
  for i in $(seq 1 80); do
    local n; n=$(sub_ids | grep -vxFf "$1" | head -1 || true)
    [[ -n "$n" ]] && { echo "$n"; return 0; }
    sleep 0.25
  done; return 1
}
wait_signed() { # $1=submission_id -> 0 once it carries >= 1 signature (threshold 1)
  for i in $(seq 1 80); do [[ "$(sub_field "$1" signatures)" =~ ^[1-9] ]] && return 0; sleep 0.25; done; return 1
}
wait_executed() { # $1=gate $2=submission_id
  for i in $(seq 1 80); do [[ "$(executed "$1" "$2")" == true ]] && return 0; sleep 0.25; done; return 1
}
# anvil logs every RPC method it serves, one per line.
rpc_count() { grep -c "$1" "$LOGS/m6-anvil-dst.log" || true; }

echo "=== building binaries ==="
( cd "$ROOT" && cargo build -p validator -p keeper -p sig-store >/dev/null 2>&1 ) || fail "cargo build failed"

echo "=== starting Postgres in Docker ($PG_NAME on 127.0.0.1:$PG_PORT) ==="
docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
# Loopback-only publish (M-9): a bare -p bypasses the host firewall.
docker run -d --name "$PG_NAME" \
  -e POSTGRES_USER=bridge -e POSTGRES_PASSWORD=bridge -e POSTGRES_DB=bridge \
  -p 127.0.0.1:${PG_PORT}:5432 postgres:16-alpine >/dev/null
for i in $(seq 1 60); do
  docker exec "$PG_NAME" pg_isready -U bridge -d bridge >/dev/null 2>&1 && break
  sleep 0.5
  [[ $i == 60 ]] && fail "Postgres did not become ready"
done
echo "✅ Postgres ready"

echo "=== starting anvil chains (:$SRC_PORT, :$DST_PORT) ==="
anvil --chain-id $SRC_CHAIN --port $SRC_PORT >"$LOGS/m6-anvil-src.log" 2>&1 & track $!
anvil --chain-id $DST_CHAIN --port $DST_PORT >"$LOGS/m6-anvil-dst.log" 2>&1 & track $!
for url in $SRC_RPC $DST_RPC; do
  for i in $(seq 1 50); do cast chain-id --rpc-url "$url" >/dev/null 2>&1 && break; sleep 0.2; done
done

cd "$CONTRACTS"
forge build >/dev/null 2>&1 || fail "forge build failed"
echo "=== deploying the D1 mesh (1 validator, threshold 1) ==="
TOKEN=$(    forge create src/TestToken.sol:TestToken --rpc-url "$SRC_RPC" --private-key $KEY0 --broadcast --json --constructor-args Good GOOD 2>/dev/null | deployed_to)
TOKEN_DST=$(forge create src/TestToken.sol:TestToken --rpc-url "$DST_RPC" --private-key $KEY0 --broadcast --json --constructor-args Good GOOD 2>/dev/null | deployed_to)
GATE_SRC=$(deploy_gate "$SRC_RPC" "$KEY0" "[$V1]" 1)
GATE_DST=$(deploy_gate "$DST_RPC" "$KEY0" "[$V1]" 1)
DID=$(debridge_id $SRC_CHAIN "$TOKEN")
echo "  D1=$D1"
echo "  src: token=$TOKEN gate=$GATE_SRC"
echo "  dst: token=$TOKEN_DST gate=$GATE_DST"

FUND=3000000000000000000000   # 3000e18
cast send "$TOKEN" "mint(address,uint256)" $ACC0 $FUND --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null

wire_source() { # gate — decimals, allowance, seal
  set_bridge_decimals "$SRC_RPC" "$KEY0" "$1" "$TOKEN" 18
  cast send "$TOKEN" "approve(address,uint256)" "$1" $FUND --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null
  seal_gate "$SRC_RPC" "$KEY0" "$1"
}
wire_dest() { # gate — decimals, liquidity, corridor, seal (sealing LAST, as production does)
  set_bridge_decimals "$DST_RPC" "$KEY0" "$1" "$TOKEN_DST" 18
  cast send "$TOKEN_DST" "mint(address,uint256)" "$1" 1000000000000000000000 --rpc-url $DST_RPC --private-key $KEY0 >/dev/null
  cast send "$1" "setLocalToken(bytes32,address)" "$DID" "$TOKEN_DST" --rpc-url $DST_RPC --private-key $KEY0 >/dev/null
  seal_gate "$DST_RPC" "$KEY0" "$1"
}
wire_source "$GATE_SRC"
wire_dest "$GATE_DST"
[[ "$(cast call "$GATE_DST" 'bridgeDomain()(bytes32)' --rpc-url $DST_RPC)" == "$D1" ]] || fail "D1 dest gate does not report D1"

echo "=== starting Postgres-backed sig-store ($STORE_URL) ==="
# --allow-unauthenticated: local test on loopback. Comment kept ABOVE the env
# prefix — after a `\` it would swallow the continuation.
SIG_STORE_BIND=$STORE_BIND DATABASE_URL="$DATABASE_URL" \
  "$ROOT/target/debug/sig-store" --allow-unauthenticated >"$LOGS/m6-sig-store.log" 2>&1 & track $!
for i in $(seq 1 60); do curl -s "$STORE_URL/health" >/dev/null 2>&1 && break; sleep 0.25; done
curl -s "$STORE_URL/health" | grep -q ok || fail "sig-store did not come up"
SIG_STORE="$STORE_URL" bash "$ROOT/scripts/testing/allowlist.sh" add-token $SRC_CHAIN "$TOKEN" GOOD >/dev/null
curl -fsS -X POST "$STORE_URL/allowed/chains" -H 'content-type: application/json' \
  -d "{\"chain_id_from\":$SRC_CHAIN,\"chain_id_to\":$DST_CHAIN}" >/dev/null
echo "✅ sig-store healthy, token + corridor allowlisted"

write_validator_cfg() { # name source-gate dest-gate
  cat > "$LOGS/m6-$1.toml" <<EOF
[source]
chain_id = $SRC_CHAIN
rpcs = ["$SRC_RPC"]
gate = "$2"
start_block = 0
block_confirmation = 0
allow_zero_confirmation = true   # anvil is instant-final
poll_interval_ms = $POLL_MS
max_block_range = 1000
state_file = "$LOGS/m6-$1-state.json"

[signer]
private_key = "$V1K"

[store]
url = "$STORE_URL"

[[destinations]]
chain_id = $DST_CHAIN
rpcs = ["$DST_RPC"]
gate = "$3"
EOF
}
write_keeper_cfg() { # name dest-gate
  cat > "$LOGS/m6-$1.toml" <<EOF
[target]
chain_id = $DST_CHAIN
rpc = "$DST_RPC"
gate = "$2"
poll_interval_ms = $POLL_MS

[keeper]
private_key = "$KEEPER_KEY"

[store]
url = "$STORE_URL"
EOF
}
start_keeper() { # name
  "$ROOT/target/debug/keeper" "$LOGS/m6-$1.toml" >"$LOGS/m6-$1.log" 2>&1 & KEEPER_PID=$!
}
stop_keeper() {
  kill "$KEEPER_PID" 2>/dev/null || true; wait "$KEEPER_PID" 2>/dev/null || true; KEEPER_PID=""
}

write_validator_cfg validator  "$GATE_SRC" "$GATE_DST"
write_keeper_cfg    keeper1    "$GATE_DST"
echo "=== starting validator + keeper (D1) ==="
"$ROOT/target/debug/validator" "$LOGS/m6-validator.toml" >"$LOGS/m6-validator.log" 2>&1 & track $!
start_keeper keeper1
sleep 1

send() { # gate
  cast send "$1" "send(address,uint256,uint256,bytes,bytes)" \
    "$TOKEN" $AMOUNT $DST_CHAIN "$RECEIVER" "0x" --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null
}
KNOWN="$LOGS/m6-known-ids.txt"; : > "$KNOWN"

echo
echo "########## CHECK 1: baseline — a D1 transfer is claimed ##########"
send "$GATE_SRC"
SID1=$(wait_new_id "$KNOWN") || fail "validator never wrote the first transfer to the store"
echo "$SID1" >> "$KNOWN"
wait_executed "$GATE_DST" "$SID1" || fail "baseline transfer $SID1 was never claimed on the D1 gate"
for i in $(seq 1 40); do [[ "$(keeper_claimtx "$SID1")" == 0x* ]] && break; sleep 0.25; done
echo "  id=$SID1 executed=$(executed "$GATE_DST" "$SID1") keeper_claim_tx=$(keeper_claimtx "$SID1") receiver=$(bal "$TOKEN_DST" "$RECEIVER" "$DST_RPC")"
[[ "$(bal "$TOKEN_DST" "$RECEIVER" "$DST_RPC")" == "$AMOUNT" ]] || fail "receiver not paid by the baseline claim"
echo "✅ baseline D1 transfer claimed by the keeper"

echo
echo "########## CHECK 2: keeper down — a D1 transfer reaches quorum, unclaimed ##########"
stop_keeper
send "$GATE_SRC"
SID2=$(wait_new_id "$KNOWN") || fail "validator never wrote the second transfer to the store"
echo "$SID2" >> "$KNOWN"
wait_signed "$SID2" || fail "second transfer never reached quorum in the store"
sleep 1
REC_DOMAIN=$(sub_field "$SID2" bridge_domain)
echo "  id=$SID2 sigs=$(sub_field "$SID2" signatures) record.bridge_domain=$REC_DOMAIN executed(D1 gate)=$(executed "$GATE_DST" "$SID2")"
[[ "${REC_DOMAIN,,}" == "${D1,,}" ]]            || fail "stored record does not carry D1"
[[ "$(executed "$GATE_DST" "$SID2")" == false ]] || fail "second transfer was claimed although the keeper is down"
echo "✅ second transfer signed under D1, NOT claimed"

echo
echo "########## CHECK 3: rotate to D2 — keeper must strand the D1 record, once, quietly ##########"
GATE_DST2=$(deploy_gate "$DST_RPC" "$KEY0" "[$V1]" 1 "$D2")
wire_dest "$GATE_DST2"
DST2_DOMAIN=$(cast call "$GATE_DST2" 'bridgeDomain()(bytes32)' --rpc-url $DST_RPC)
echo "  D2=$D2"
echo "  new dest gate=$GATE_DST2 bridgeDomain=$DST2_DOMAIN"
[[ "$DST2_DOMAIN" == "$D2" && "$D2" != "$D1" ]] || fail "rotated gate does not carry a distinct D2"

NONCE_BEFORE=$(cast nonce "$KEEPER" --rpc-url $DST_RPC)
write_keeper_cfg keeper2 "$GATE_DST2"
start_keeper keeper2
# Wait for the keeper to connect, then snapshot the chain-side counters so the
# window covers ONLY steady-state ticks.
for i in $(seq 1 60); do grep -q "DIFFERENT bridgeDomain" "$LOGS/m6-keeper2.log" && break; sleep 0.25; done
EST_BEFORE=$(rpc_count eth_estimateGas)
RAW_BEFORE=$(rpc_count eth_sendRawTransaction)
echo "  observing the keeper for ${OBSERVE_SECS}s (~$(( OBSERVE_SECS * 1000 / POLL_MS )) ticks)…"
sleep "$OBSERVE_SECS"
NONCE_AFTER=$(cast nonce "$KEEPER" --rpc-url $DST_RPC)
EST_AFTER=$(rpc_count eth_estimateGas)
RAW_AFTER=$(rpc_count eth_sendRawTransaction)

WARN_SID2=$(grep "DIFFERENT bridgeDomain" "$LOGS/m6-keeper2.log" | grep -ci "$SID2" || true)
WARN_TOTAL=$(grep -c "DIFFERENT bridgeDomain" "$LOGS/m6-keeper2.log" || true)
WARN_IDS=$(grep "DIFFERENT bridgeDomain" "$LOGS/m6-keeper2.log" | grep -oiE '0x[0-9a-f]{64}' | sort -u | grep -civxF -e "${DID,,}" || true)
FAILED_SID2=$(grep "claim failed" "$LOGS/m6-keeper2.log" | grep -ci "$SID2" || true)
FAILED_ALL=$(grep -c "claim failed" "$LOGS/m6-keeper2.log" || true)
REVERTS=$(grep -ciE "NotEnoughSignatures|revert" "$LOGS/m6-keeper2.log" || true)
EXEC2=$(executed "$GATE_DST2" "$SID2")

echo "  executed(SID2) on D2 gate           = $EXEC2"
echo "  domain-rotation warns for SID2      = $WARN_SID2"
echo "  domain-rotation warns total         = $WARN_TOTAL (distinct ids: $WARN_IDS — every D1 row still in the queue)"
echo "  'claim failed' lines (SID2 / all)   = $FAILED_SID2 / $FAILED_ALL"
echo "  revert mentions in keeper log       = $REVERTS"
echo "  keeper nonce on dest                = $NONCE_BEFORE -> $NONCE_AFTER"
echo "  dest eth_estimateGas in window      = $(( EST_AFTER - EST_BEFORE ))"
echo "  dest eth_sendRawTransaction in window = $(( RAW_AFTER - RAW_BEFORE ))"
echo "  the warn:"; grep "DIFFERENT bridgeDomain" "$LOGS/m6-keeper2.log" | grep -i "$SID2" | sed -e 's/\x1b\[[0-9;]*m//g' -e 's/^/    /' || true

[[ "$EXEC2" == false ]]                     || fail "the D1 record was EXECUTED on the D2 gate"
[[ "$WARN_SID2" == 1 ]]                     || fail "expected exactly one domain-rotation warn for $SID2, got $WARN_SID2"
[[ "$WARN_TOTAL" == "$WARN_IDS" ]]          || fail "domain-rotation warn repeated for some record ($WARN_TOTAL lines, $WARN_IDS ids)"
[[ "$FAILED_ALL" == 0 ]]                    || fail "keeper is retrying a claim the D2 gate can never accept ($FAILED_ALL 'claim failed')"
[[ "$REVERTS" == 0 ]]                       || fail "keeper log shows reverts ($REVERTS)"
[[ "$NONCE_AFTER" == "$NONCE_BEFORE" ]]     || fail "keeper nonce moved $NONCE_BEFORE -> $NONCE_AFTER"
[[ "$EST_AFTER" == "$EST_BEFORE" ]]         || fail "keeper kept estimating claims against the D2 gate ($(( EST_AFTER - EST_BEFORE )) eth_estimateGas)"
[[ "$RAW_AFTER" == "$RAW_BEFORE" ]]         || fail "keeper broadcast $(( RAW_AFTER - RAW_BEFORE )) tx to the D2 chain"
echo "✅ D1 record stranded: not claimed, one warn naming the rotation, zero chain traffic, nonce flat"

echo
echo "########## CHECK 4: positive control — a D2 transfer is claimed by the SAME keeper ##########"
GATE_SRC2=$(deploy_gate "$SRC_RPC" "$KEY0" "[$V1]" 1 "$D2")
wire_source "$GATE_SRC2"
write_validator_cfg validator2 "$GATE_SRC2" "$GATE_DST2"
"$ROOT/target/debug/validator" "$LOGS/m6-validator2.toml" >"$LOGS/m6-validator2.log" 2>&1 & track $!
PAID_BEFORE=$(bal "$TOKEN_DST" "$RECEIVER" "$DST_RPC")
send "$GATE_SRC2"
SID3=$(wait_new_id "$KNOWN") || fail "D2 validator never wrote the third transfer to the store"
echo "$SID3" >> "$KNOWN"
wait_executed "$GATE_DST2" "$SID3" || fail "D2 transfer $SID3 was not claimed by the running keeper"
PAID_AFTER=$(bal "$TOKEN_DST" "$RECEIVER" "$DST_RPC")
echo "  id=$SID3 record.bridge_domain=$(sub_field "$SID3" bridge_domain) executed(D2 gate)=$(executed "$GATE_DST2" "$SID3")"
echo "  receiver $PAID_BEFORE -> $PAID_AFTER; keeper pid still $KEEPER_PID"
[[ "$(python3 -c "print($PAID_AFTER-$PAID_BEFORE)")" == "$AMOUNT" ]] || fail "receiver not paid by the D2 claim"
kill -0 "$KEEPER_PID" 2>/dev/null || fail "keeper process died"
[[ "$(executed "$GATE_DST2" "$SID2")" == false ]] || fail "SID2 became executed on the D2 gate"
[[ "$(grep "DIFFERENT bridgeDomain" "$LOGS/m6-keeper2.log" | grep -ci "$SID2" || true)" == 1 ]] \
  || fail "domain-rotation warn for SID2 repeated after the positive control"
echo "✅ same keeper claims D2 transfers; the D1 record stays stranded, warned once"

echo
echo "================= M-6 DOMAIN-ROTATION E2E RESULT ================="
echo "✅ a bridgeDomain rotation strands pre-rotation records ONCE, loudly, and without"
echo "   a per-tick revert loop; post-rotation transfers claim normally."
echo "================================================================="
