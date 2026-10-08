#!/usr/bin/env bash
# H7-5 (audit round 7): junk rows must not starve a genuine refund.
#
# The refund queue used to be walked from its head every tick and cut off at
# 10,000 rows, and the eligibility sweep nominated every aged unclaimed row,
# whoever wrote it. So 10,000 rows no chain ever emitted — posted with a Sign
# credential — sat in front of every genuine stuck transfer created after them,
# for good.
#
# This floods the queue BEFORE a real transfer strands, with two kinds of junk,
# each larger than one tick's walk (REFUND_PAGE * MAX_REFUND_PAGES = 10,000):
#
#   A. 10,500 never-sent rows on the INDEXED source chain. Fixed by the
#      `sent_observed_at` vouch: the indexer never saw their Sent, so the sweep
#      never nominates them.
#   B. 10,500 never-sent rows from a source no indexer reads (where Solana
#      transfers come from) to a destination no validator reads. They ARE
#      served, and never leave; fixed by the keyset cursor, which resumes where
#      the previous tick stopped instead of re-reading the same head.
#
# Then a genuine transfer strands (unfunded, unregistered destination) and the
# REAL indexer + validator + keeper must cancel and refund it, with no error in
# any log. Two validators, threshold 2; the junk is signed by validator 1's own
# key, which is all H7-3 leaves an attacker: ONE stolen validator key. (At
# threshold 1 that key is the whole quorum and junk is a claimable transfer —
# there is nothing left to defend.)
#
# BIN_DIR overrides where the service binaries come from, so the same scenario
# can be run against a pre-fix build (it should time out at the refund).
#
# Run from anywhere:  bash scripts/testing/refund-starvation.sh
set -euo pipefail

export PATH="$HOME/.foundry/bin:$HOME/.cargo/bin:$PATH"
source "$(dirname "${BASH_SOURCE[0]}")/_deploy_gate.sh"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTRACTS="$ROOT/contracts"
LOGS="$ROOT/.refund-starvation-logs"
BIN_DIR="${BIN_DIR:-$ROOT/target/debug}"
rm -rf "$LOGS"; mkdir -p "$LOGS"

PG_NAME=bridge-pg-starve
PG_PORT=5437
DATABASE_URL="postgres://bridge:bridge@127.0.0.1:${PG_PORT}/bridge?sslmode=disable"

# anvil default accounts: [0] deployer/sender, [1] [3] validators, [2] keeper
ACC0=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
KEY0=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
V1=0x70997970C51812dc3A010C7d01b50e0d17dc79C8;  V1K=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
V2=0x90F79bf6EB2c4f870365E785982E1f101E93b906;  V2K=0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6
KEEPER_KEY=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
RECEIVER=0x976EA74026E726554dB657fA54763abd0C3a0aa9

SRC_RPC=http://127.0.0.1:8555
DST_RPC=http://127.0.0.1:8556
SRC_CHAIN=1337
DST_CHAIN=1338
# Junk B's corridor: no indexer reads 424242, no validator reads 424243.
GHOST_FROM=424242
GHOST_TO=424243
STORE_URL=http://127.0.0.1:8097
AMOUNT=100000000000000000000      # 100e18
JUNK=10500

declare -a PIDS=()
track() { PIDS+=("$1"); }
cleanup() {
  echo "--- cleaning up ---"
  for p in "${PIDS[@]:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null || true; done
  docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

bal() { cast call "$1" "balanceOf(address)(uint256)" "$2" --rpc-url "$3" | awk '{print $1}'; }
psql_q() { docker exec "$PG_NAME" psql -U bridge -d bridge -tAc "$1"; }
fail() {
  echo "❌ FAIL: $1"
  for l in indexer validator validator2 keeper sig-store; do
    echo "--- $l.log (tail) ---"; tail -20 "$LOGS/$l.log" 2>/dev/null || true
  done
  exit 1
}

echo "=== building ==="
( cd "$ROOT" && cargo build -p validator -p keeper -p sig-store -p indexer >/dev/null 2>&1 \
  && cargo build -p bridge-core --features abi,http --example refund_flood >/dev/null 2>&1 )
FLOOD="$ROOT/target/debug/examples/refund_flood"
echo "  services from $BIN_DIR"

echo "=== starting anvil chains ==="
# --block-time 1: the validator measures the timeout in block timestamps.
anvil --chain-id $SRC_CHAIN --port 8555 --block-time 1 >"$LOGS/anvil-src.log" 2>&1 & track $!
anvil --chain-id $DST_CHAIN --port 8556 --block-time 1 >"$LOGS/anvil-dst.log" 2>&1 & track $!
for url in $SRC_RPC $DST_RPC; do
  for _ in $(seq 1 50); do cast chain-id --rpc-url "$url" >/dev/null 2>&1 && break; sleep 0.2; done
done

cd "$CONTRACTS"
forge build >/dev/null
echo "=== deploying (2 validators, threshold 2) ==="
TOKEN_SRC=$(_forge_create "$SRC_RPC" "$KEY0" src/TestToken.sol:TestToken --constructor-args Test TST)
GATE_SRC=$(deploy_gate "$SRC_RPC" "$KEY0" "[$V1,$V2]" 2)
# Destination: no liquidity, no asset registration — every claim reverts.
GATE_DST=$(deploy_gate "$DST_RPC" "$KEY0" "[$V1,$V2]" 2)
BRIDGE_DEC=18
set_bridge_decimals "$SRC_RPC" "$KEY0" "$GATE_SRC" "$TOKEN_SRC" "$BRIDGE_DEC"
seal_gate "$SRC_RPC" "$KEY0" "$GATE_SRC"
seal_gate "$DST_RPC" "$KEY0" "$GATE_DST"
DOMAIN=$(cast call "$GATE_SRC" "bridgeDomain()(bytes32)" --rpc-url $SRC_RPC)
echo "  src gate=$GATE_SRC dst gate=$GATE_DST domain=$DOMAIN"
cast send "$TOKEN_SRC" "mint(address,uint256)" $ACC0 $AMOUNT --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null
cast send "$TOKEN_SRC" "approve(address,uint256)" "$GATE_SRC" $AMOUNT --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null

echo "=== Postgres + sig-store + indexer ==="
docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
docker run -d --name "$PG_NAME" \
  -e POSTGRES_USER=bridge -e POSTGRES_PASSWORD=bridge -e POSTGRES_DB=bridge \
  -p 127.0.0.1:${PG_PORT}:5432 postgres:16-alpine >/dev/null
for i in $(seq 1 60); do
  docker exec "$PG_NAME" pg_isready -U bridge -d bridge >/dev/null 2>&1 && break
  sleep 0.5; [[ $i == 60 ]] && fail "Postgres did not become ready"
done
sleep 1
# The flood needs the write limiter out of the way; the limiter is not H7-5's fix.
SIG_STORE_BIND=127.0.0.1:8097 DATABASE_URL="$DATABASE_URL" \
  SIG_STORE_RATE_PER_SECOND=100000 SIG_STORE_RATE_BURST=100000 \
  "$BIN_DIR/sig-store" --allow-unauthenticated >"$LOGS/sig-store.log" 2>&1 & track $!
for _ in $(seq 1 60); do curl -s "$STORE_URL/health" >/dev/null 2>&1 && break; sleep 0.25; done
curl -s "$STORE_URL/health" | grep -q ok || fail "sig-store did not come up"

cat > "$LOGS/indexer.toml" <<EOF
database_url = "$DATABASE_URL"
refund_timeout_secs = 5
sweep_interval_secs = 2

[[chains]]
chain_id = $SRC_CHAIN
rpc = "$SRC_RPC"
gate = "$GATE_SRC"
start_block = 0
block_confirmation = 0
allow_zero_confirmation = true
poll_interval_ms = 500
max_block_range = 1000

[[chains]]
chain_id = $DST_CHAIN
rpc = "$DST_RPC"
gate = "$GATE_DST"
start_block = 0
block_confirmation = 0
allow_zero_confirmation = true
poll_interval_ms = 500
max_block_range = 1000
EOF
"$BIN_DIR/indexer" "$LOGS/indexer.toml" >"$LOGS/indexer.log" 2>&1 & track $!
for _ in $(seq 1 60); do
  [[ "$(psql_q "SELECT count(*) FROM indexer_cursors WHERE chain_id=$SRC_CHAIN" 2>/dev/null)" == "1" ]] && break
  sleep 0.5
done
[[ "$(psql_q "SELECT count(*) FROM indexer_cursors WHERE chain_id=$SRC_CHAIN")" == "1" ]] || fail "indexer never saved a cursor"

echo
echo "########## flooding the refund queue ##########"
export FLOOD_SIGNER_KEY=$V1K
"$FLOOD" "$STORE_URL" $JUNK $SRC_CHAIN $DST_CHAIN "$TOKEN_SRC" "$DOMAIN"   || fail "flood A"
"$FLOOD" "$STORE_URL" $JUNK $GHOST_FROM $GHOST_TO "$TOKEN_SRC" "$DOMAIN"   || fail "flood B"
unset FLOOD_SIGNER_KEY
# Let the sweep age them all past the 5s timeout before the real transfer.
sleep 8
ELIG_A=$(psql_q "SELECT count(*) FROM submissions WHERE chain_id_from=$SRC_CHAIN AND nonce>=1000000000 AND refund_status='eligible'")
ELIG_B=$(psql_q "SELECT count(*) FROM submissions WHERE chain_id_from=$GHOST_FROM AND refund_status='eligible'")
echo "  junk A (indexed source) nominated: $ELIG_A / $JUNK"
echo "  junk B (unindexed source) nominated: $ELIG_B / $JUNK"

write_validator() { # $1=name $2=key
cat > "$LOGS/$1.toml" <<EOF
[source]
chain_id = $SRC_CHAIN
rpcs = ["$SRC_RPC"]
gate = "$GATE_SRC"
start_block = 0
block_confirmation = 0
allow_zero_confirmation = true
poll_interval_ms = 300
max_block_range = 1000
state_file = "$LOGS/$1-state.json"

[signer]
private_key = "$2"

[store]
url = "$STORE_URL"

[refund]
timeout_secs = 5
poll_interval_ms = 1000
block_confirmation = 0
allow_zero_confirmation = true

[[refund.destinations]]
chain_id = $DST_CHAIN
rpcs = ["$DST_RPC"]
gate = "$GATE_DST"
EOF
}
write_validator validator "$V1K"
write_validator validator2 "$V2K"

cat > "$LOGS/keeper.toml" <<EOF
[keeper]
private_key = "$KEEPER_KEY"

[store]
url = "$STORE_URL"

[[targets]]
chain_id = $DST_CHAIN
rpc = "$DST_RPC"
gate = "$GATE_DST"
poll_interval_ms = 300

[[sources]]
chain_id = $SRC_CHAIN
rpc = "$SRC_RPC"
gate = "$GATE_SRC"
poll_interval_ms = 300
EOF

echo
echo "########## a genuine transfer strands behind the junk ##########"
BAL_BEFORE=$(bal "$TOKEN_SRC" $ACC0 $SRC_RPC)
cast send "$GATE_SRC" "send(address,uint256,uint256,bytes,bytes)" \
  "$TOKEN_SRC" $AMOUNT $DST_CHAIN "$RECEIVER" "0x" \
  --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null
SUB=$(cast call "$GATE_SRC" "computeSubmissionId(bytes32,uint256,uint8,uint256,uint256,uint256,bytes,bytes,bytes)(bytes32)" \
  "$(cast keccak "$(cast abi-encode --packed "f(uint256,address)" $SRC_CHAIN "$TOKEN_SRC")")" \
  "$AMOUNT" "$BRIDGE_DEC" "$SRC_CHAIN" "$DST_CHAIN" 0 \
  "$(cast abi-encode --packed "f(address)" "$RECEIVER")" "0x" "0x" --rpc-url $SRC_RPC)
echo "  submissionId=$SUB"

"$BIN_DIR/validator" "$LOGS/validator.toml"  >"$LOGS/validator.log"  2>&1 & track $!
"$BIN_DIR/validator" "$LOGS/validator2.toml" >"$LOGS/validator2.log" 2>&1 & track $!
"$BIN_DIR/keeper"    "$LOGS/keeper.toml"    >"$LOGS/keeper.log" 2>&1 & track $!

echo "  waiting for the relayers to cancel and refund it ..."
START=$(date +%s)
REFUNDED=0
for _ in $(seq 1 180); do
  [[ "$(bal "$TOKEN_SRC" $ACC0 $SRC_RPC)" == "$BAL_BEFORE" ]] && { REFUNDED=1; break; }
  sleep 1
done
TOOK=$(( $(date +%s) - START ))
[[ "$REFUNDED" == "1" ]] || fail "the genuine stuck transfer was never refunded (starved behind the junk)"
echo "  refunded after ${TOOK}s"

CANCELLED=$(cast call "$GATE_DST" "cancelled(bytes32)(bool)" "$SUB" --rpc-url $DST_RPC)
SRC_REFUNDED=$(cast call "$GATE_SRC" "refunded(bytes32)(bool)" "$SUB" --rpc-url $SRC_RPC)
[[ "$CANCELLED" == "true" ]]    || fail "destination not cancelled"
[[ "$SRC_REFUNDED" == "true" ]] || fail "source refunded flag not set"

FINAL=""
for _ in $(seq 1 30); do
  FINAL=$(psql_q "SELECT refund_status FROM submissions WHERE submission_id='${SUB,,}'")
  [[ "$FINAL" == "refunded" ]] && break
  sleep 1
done

echo
echo "########## assertions ##########"
PASS=0
check() { if eval "$2"; then echo "  ✅ $1"; PASS=$((PASS+1)); else fail "$1"; fi; }
ELIG_A=$(psql_q "SELECT count(*) FROM submissions WHERE chain_id_from=$SRC_CHAIN AND nonce>=1000000000 AND refund_status<>'none'")
UNOBS_A=$(psql_q "SELECT count(*) FROM submissions WHERE chain_id_from=$SRC_CHAIN AND nonce>=1000000000 AND sent_observed_at IS NULL")
check "junk A: none of $JUNK never-sent rows on the indexed source was nominated" '[[ "$ELIG_A" == "0" && "$UNOBS_A" == "$JUNK" ]]'
check "junk B: all $JUNK unindexed-source rows are queued (the cursor has to get past them)" '[[ "$ELIG_B" == "$JUNK" ]]'
check "the real transfer was observed by the indexer" '[[ -n "$(psql_q "SELECT 1 FROM submissions WHERE submission_id='"'"'${SUB,,}'"'"' AND sent_observed_at IS NOT NULL")" ]]'
check "the validator walked past one tick's worth (cursor resumed)" 'grep -q "resuming from here next tick" "$LOGS/validator.log"'
for v in validator validator2; do
  check "$v attested the cancel and the refund" '[[ $(grep -c "ATTESTED" "$LOGS/$v.log") -ge 2 ]]'
done
check "DB lifecycle reached refunded" '[[ "$FINAL" == "refunded" ]]'
for l in indexer validator validator2 keeper sig-store; do
  check "$l.log has no ERROR or panic" '! grep -qE "ERROR|panicked" "$LOGS/$l.log"'
done
check "no validator refused or failed a candidate" '! grep -qE "refund attestation failed|refund candidate refused|fetching refund candidates failed" "$LOGS"/validator*.log'
check "the keeper never tried to claim the junk (one key is below threshold)" '! grep -q UNCLAIMABLE "$LOGS/keeper.log"'

echo
echo "================= H7-5 STARVATION RESULT ================="
echo "✅ $PASS checks: a genuine stuck transfer queued behind $((JUNK*2)) junk rows was"
echo "   cancelled and refunded by the relayers in ${TOOK}s, with no error logged"
echo "=========================================================="
