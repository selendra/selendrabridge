#!/usr/bin/env bash
# H7-4 (audit round 7) — a refunded swap-and-bridge reaches the USER, end to
# end over two local anvil chains and the real keeper binary.
#
#   @chain A  routerA.swapAndBridge(WETH -> stable -> Gate.send): the gate's
#             `sentBy` is routerA, so the gate refunds into routerA.
#   @chain B  the transfer is cancelled (validator cancel attestation), which
#             makes it refundable on A.
#   keeper    reads the refund quorum from a file store and, because routerA is
#             in its source's `routers`, refunds through
#             routerA.refundAndForward — the stable goes to the user in the same
#             transaction instead of resting in the router.
#
# Asserts: the user is repaid exactly the stable bridged; routerA holds none;
# the router's refund record is consumed; a second forward reverts.
#
# Signatures are produced with `cast wallet sign` (single validator,
# threshold 1), as in xswap.sh / refund-e2e.sh.
#
# Run from anywhere:  bash scripts/testing/xswap-refund.sh
set -euo pipefail

export PATH="$HOME/.foundry/bin:$HOME/.cargo/bin:$PATH"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTRACTS="$ROOT/contracts"
LOGS="$ROOT/.xswap-refund-logs"
STORE="$LOGS/store"
rm -rf "$LOGS"; mkdir -p "$STORE"

ACC0=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
KEY0=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
VALIDATOR=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
VALIDATOR_KEY=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
USER=0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
USER_KEY=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
FINAL_RECEIVER=0x90F79bf6EB2c4f870365E785982E1f101E93b906
# The keeper is neither the routers' owner nor their guardian.
KEEPER_KEY=0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a

SRC_RPC=http://127.0.0.1:8545
DST_RPC=http://127.0.0.1:8546
CHAIN_A=1337
CHAIN_B=1338
AMOUNT_IN=1000000000000000000       # 1 WETH
WETH_PRICE=3180000000000000000000
TT_PRICE=2000000000000000000
STABLE_BRIDGE_DEC=6

FAIL=0
check() { if [[ "$2" == "$3" ]]; then echo "  ✅ $1: $2"; else echo "  ❌ $1: got $2 want $3"; FAIL=1; fi; }
num() { awk '{print $1}'; }

KEEPER_PID=""
cleanup() {
  [[ -n "$KEEPER_PID" ]] && kill "$KEEPER_PID" 2>/dev/null || true
  kill ${ANVIL1_PID:-} ${ANVIL2_PID:-} 2>/dev/null || true
}
trap cleanup EXIT

echo "=== building contracts + keeper ==="
(cd "$CONTRACTS" && forge build >/dev/null)
cargo build -q -p keeper --manifest-path "$ROOT/Cargo.toml"
KEEPER_BIN="$ROOT/target/debug/keeper"

pkill -f "anvil --chain-id" 2>/dev/null || true
sleep 1
anvil --chain-id $CHAIN_A --port 8545 >"$LOGS/anvil-a.log" 2>&1 & ANVIL1_PID=$!
anvil --chain-id $CHAIN_B --port 8546 >"$LOGS/anvil-b.log" 2>&1 & ANVIL2_PID=$!
for url in $SRC_RPC $DST_RPC; do
  for _ in $(seq 1 50); do cast chain-id --rpc-url "$url" >/dev/null 2>&1 && break; sleep 0.2; done
done

echo "=== deploy + wire A <-> B ==="
cd "$CONTRACTS"
deploy() { # rpc price symbol log
  VALIDATOR=$VALIDATOR ALT_PRICE=$2 ALT_SYMBOL=$3 \
    forge script script/DeployXSwap.s.sol:DeployXSwap --rpc-url "$1" --private-key $KEY0 --broadcast \
    >"$LOGS/$4" 2>&1 || { echo "!! deploy failed ($4)"; tail -30 "$LOGS/$4"; exit 1; }
}
deploy "$SRC_RPC" $WETH_PRICE WETH deploy-a.log
source "$CONTRACTS/fixtures/xswap-$CHAIN_A.env"
STABLE_A=$STABLE; WETH=$ALT; POOL_A=$POOL; GATE_A=$GATE; ROUTER_A=$ROUTER
deploy "$DST_RPC" $TT_PRICE TT deploy-b.log
source "$CONTRACTS/fixtures/xswap-$CHAIN_B.env"
STABLE_B=$STABLE; TT=$ALT; GATE_B=$GATE; ROUTER_B=$ROUTER
wire() { # rpc gate router stable peerChain peerStable peerRouter log
  forge script script/DeployXSwap.s.sol:DeployXSwap \
    --sig "wire(address,address,address,uint256,address,address)" "$2" "$3" "$4" "$5" "$6" "$7" \
    --rpc-url "$1" --private-key $KEY0 --broadcast >"$LOGS/$8" 2>&1 \
    || { echo "!! wire failed ($8)"; tail -30 "$LOGS/$8"; exit 1; }
}
wire "$SRC_RPC" "$GATE_A" "$ROUTER_A" "$STABLE_A" $CHAIN_B "$STABLE_B" "$ROUTER_B" wire-a.log
wire "$DST_RPC" "$GATE_B" "$ROUTER_B" "$STABLE_B" $CHAIN_A "$STABLE_A" "$ROUTER_A" wire-b.log
PREFIX=$(printf '%064x' $CHAIN_A)
DEBRIDGE_ID=$(cast keccak "0x${PREFIX}${STABLE_A#0x}")

echo "=== chain A: swapAndBridge 1 WETH -> TT@B ==="
cast send "$WETH" "mint(address,uint256)" "$USER" $AMOUNT_IN --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null
cast send "$WETH" "approve(address,uint256)" "$ROUTER_A" $AMOUNT_IN --rpc-url $SRC_RPC --private-key $USER_KEY >/dev/null
STABLE_OUT=$(cast call "$POOL_A" "quote(address,address,uint256)(uint256)" "$WETH" "$STABLE_A" $AMOUNT_IN --rpc-url $SRC_RPC | num)
cast send "$ROUTER_A" "swapAndBridge(address,uint256,uint256,uint256,address,address,uint256)" \
  "$WETH" $AMOUNT_IN 0 $CHAIN_B "$TT" "$FINAL_RECEIVER" 0 --rpc-url $SRC_RPC --private-key $USER_KEY >/dev/null
USER_BEFORE=$(cast call "$STABLE_A" "balanceOf(address)(uint256)" "$USER" --rpc-url $SRC_RPC | num)

NONCE=0
INTENT=$(cast abi-encode "f(address,address,uint256)" "$TT" "$FINAL_RECEIVER" 0)
AUTOPARAMS=$(cast abi-encode "f((uint256,uint256,bytes,bytes))" "(0,0,$FINAL_RECEIVER,$INTENT)")
SUB_ID=$(cast call "$GATE_A" \
  "computeSubmissionId(bytes32,uint256,uint8,uint256,uint256,uint256,bytes,bytes,bytes)(bytes32)" \
  "$DEBRIDGE_ID" $STABLE_OUT $STABLE_BRIDGE_DEC $CHAIN_A $CHAIN_B $NONCE "$ROUTER_B" "$AUTOPARAMS" "$ROUTER_A" \
  --rpc-url $SRC_RPC)
check "gateA.sentBy is the router" "$(cast call "$GATE_A" 'sentBy(bytes32)(address)' "$SUB_ID" --rpc-url $SRC_RPC)" "$ROUTER_A"
check "routerA.refundOf names the user" \
  "$(cast call "$ROUTER_A" 'refundOf(bytes32)(address,uint256)' "$SUB_ID" --rpc-url $SRC_RPC | head -1)" "$USER"

echo "=== chain B: cancel the transfer ==="
# BridgeHash: cancelId = keccak(uint256(2) ++ id), refundId = keccak(uint256(3) ++ id)
CANCEL_ID=$(cast keccak "$(cast abi-encode --packed "f(uint256,bytes32)" 2 "$SUB_ID")")
REFUND_ID=$(cast keccak "$(cast abi-encode --packed "f(uint256,bytes32)" 3 "$SUB_ID")")
CANCEL_SIG=$(cast wallet sign --private-key $VALIDATOR_KEY "$CANCEL_ID")
cast send "$GATE_B" "cancel(bytes32,uint256,uint8,uint256,uint256,bytes,bytes,bytes,bytes[])" \
  "$DEBRIDGE_ID" $STABLE_OUT $STABLE_BRIDGE_DEC $CHAIN_A $NONCE "$ROUTER_B" "$AUTOPARAMS" "$ROUTER_A" "[$CANCEL_SIG]" \
  --rpc-url $DST_RPC --private-key $KEY0 >"$LOGS/cancel.log" 2>&1 \
  || { echo "  ❌ cancel reverted"; tail -20 "$LOGS/cancel.log"; exit 1; }
check "gateB.cancelled[id]" "$(cast call "$GATE_B" 'cancelled(bytes32)(bool)' "$SUB_ID" --rpc-url $DST_RPC)" "true"

echo "=== store: the record with its refund quorum ==="
REFUND_SIG=$(cast wallet sign --private-key $VALIDATOR_KEY "$REFUND_ID")
DOMAIN=$(cast call "$GATE_A" 'bridgeDomain()(bytes32)' --rpc-url $SRC_RPC)
jq -n --arg id "$SUB_ID" --arg dom "$DOMAIN" --arg did "$DEBRIDGE_ID" --arg amt "$STABLE_OUT" \
  --arg rx "$(tr 'A-F' 'a-f' <<<"$ROUTER_B")" --arg ap "$AUTOPARAMS" --arg ns "$(tr 'A-F' 'a-f' <<<"$ROUTER_A")" \
  --arg tok "$STABLE_A" --arg v "$VALIDATOR" --arg sig "$REFUND_SIG" \
  --argjson a $CHAIN_A --argjson b $CHAIN_B --argjson dec $STABLE_BRIDGE_DEC \
  '{submission_id:$id, bridge_domain:$dom, debridge_id:$did, amount:$amt, bridge_decimals:$dec,
    chain_id_from:$a, chain_id_to:$b, nonce:0, receiver:$rx, auto_params:$ap, native_sender:$ns,
    token:$tok, signatures:[], cancel_signatures:[], refund_signatures:[{signer:$v, signature:$sig}]}' \
  >"$STORE/${SUB_ID#0x}.json"

echo "=== keeper: refund through the router ==="
cat >"$LOGS/keeper.toml" <<EOF
[[targets]]
chain_id = $CHAIN_B
rpc = "$DST_RPC"
gate = "$GATE_B"
poll_interval_ms = 500

[[sources]]
chain_id = $CHAIN_A
rpc = "$SRC_RPC"
gate = "$GATE_A"
poll_interval_ms = 500
routers = ["$ROUTER_A"]

[keeper]
private_key = "$KEEPER_KEY"

[store]
dir = "$STORE"
EOF
"$KEEPER_BIN" "$LOGS/keeper.toml" >"$LOGS/keeper.log" 2>&1 & KEEPER_PID=$!
for _ in $(seq 1 60); do
  [[ "$(cast call "$GATE_A" 'refunded(bytes32)(bool)' "$SUB_ID" --rpc-url $SRC_RPC)" == "true" ]] && break
  sleep 0.5
done
sleep 1

echo "=== assertions ==="
check "gateA.refunded[id]" "$(cast call "$GATE_A" 'refunded(bytes32)(bool)' "$SUB_ID" --rpc-url $SRC_RPC)" "true"
USER_AFTER=$(cast call "$STABLE_A" "balanceOf(address)(uint256)" "$USER" --rpc-url $SRC_RPC | num)
check "user repaid the stable bridged" "$((USER_AFTER - USER_BEFORE))" "$STABLE_OUT"
check "routerA holds no stable" "$(cast call "$STABLE_A" 'balanceOf(address)(uint256)' "$ROUTER_A" --rpc-url $SRC_RPC | num)" "0"
check "routerA.refundOf consumed" \
  "$(cast call "$ROUTER_A" 'refundOf(bytes32)(address,uint256)' "$SUB_ID" --rpc-url $SRC_RPC | head -1)" \
  "0x0000000000000000000000000000000000000000"
check "keeper used refundAndForward" "$(grep -c 'refundAndForward' "$LOGS/keeper.log" || true)" "1"
if cast send "$ROUTER_A" 'forwardRefund(bytes32)' "$SUB_ID" --rpc-url $SRC_RPC --private-key $KEY0 >/dev/null 2>&1; then
  check "a second forward reverts" "succeeded" "reverted"
else
  check "a second forward reverts" "reverted" "reverted"
fi

echo
if [[ "$FAIL" == "0" ]]; then
  echo "✅ H7-4 PASS: the refunded swap-and-bridge paid $STABLE_OUT stable back to the user"
else
  echo "❌ FAIL — see $LOGS/ (keeper.log)"
  exit 1
fi
