#!/usr/bin/env bash
# Solana leg — the checks that need the REAL target, not a host simulation.
#
# `scripts/testing/solana-e2e.sh` proves the protocol logic (hash equivalence,
# threshold rules, both directions) on the host, and the account-level suite in
# `crates/solana-gate/tests/` runs the actual handlers in a solana-program-test
# bank. Both compile for the host, so three things stay unverified until the SBF
# target is involved:
#
#   1. the SBF build — a stack frame over 4 KB is a hard error here and a silent
#      pass natively;
#   2. the deployed artifact loading into a real validator;
#   3. compute-unit cost — secp256k1_recover is ~25k CU per signature, so a
#      5-of-7 quorum spends ~175k against a 200k default budget.
#
# Everything runs in Docker; no host Solana toolchain is needed.
#
#   bash scripts/testing/solana-onchain.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

IMAGE="${IMAGE:-bridge-solana-tools}"
CONTAINER=bridge-solana-validator
SO=crates/solana-gate/target/deploy/solana_gate.so

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== [1/3] toolchain image =="
if docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "   $IMAGE present"
else
  docker build -f docker/Dockerfile.solana -t "$IMAGE" .
fi

echo
echo "== [2/3] cargo-build-sbf — the real BPF target =="
# platform-tools is baked into the image (checksum-verified at image build), so
# this compiles straight away instead of downloading the toolchain first.
# Runs as the CALLER's uid, not root (audit round 5, LOW): the image carries a
# verified platform-tools install readable by any uid, so the artifacts belong to
# whoever ran this and nothing in the container runs privileged. The image's own
# cache is read-only to this uid; the SDK's optional `criterion` (C test
# framework) fetch then prints a harmless "mkdir ... Permission denied" after
# the build — the Rust program does not use it.
docker run --rm --user "$(id -u):$(id -g)" -v "$ROOT:/work" -w /work "$IMAGE" \
  cargo-build-sbf --manifest-path crates/solana-gate/Cargo.toml
[[ -f "$SO" ]] || { echo "FAIL: no artifact at $SO"; exit 1; }
echo "   built $(du -h "$SO" | cut -f1) -> $SO"

echo
echo "== [3/3] deploy into a live validator =="
cleanup
docker run -d --name "$CONTAINER" -v "$ROOT:/work" -w /work "$IMAGE" \
  solana-test-validator --reset --quiet --ledger /tmp/ledger >/dev/null

printf "   waiting for RPC"
for _ in $(seq 1 90); do
  if docker exec "$CONTAINER" solana --url http://127.0.0.1:8899 cluster-version >/dev/null 2>&1; then
    printf " — up\n"; break
  fi
  printf "."; sleep 1
done
docker exec "$CONTAINER" solana --url http://127.0.0.1:8899 cluster-version

# `solana program deploy` rejects a malformed or oversized ELF, so this is the
# artifact-loads check.
docker exec "$CONTAINER" sh -c '
  set -e
  solana config set --url http://127.0.0.1:8899 >/dev/null
  [ -f ~/.config/solana/id.json ] || solana-keygen new --no-bip39-passphrase -s -o ~/.config/solana/id.json >/dev/null
  for i in 1 2 3; do solana airdrop 10 >/dev/null 2>&1 && break || sleep 2; done
  solana program deploy /work/crates/solana-gate/target/deploy/solana_gate.so
'

echo
echo "================= RESULT ================="
echo "PASS: compiles for the real SBF target (stack + syscall limits)"
echo "PASS: the artifact deploys into a live validator"
echo
echo "NOT covered here: driving init/send/claim on-chain needs a client that"
echo "builds Borsh instructions. That logic is covered natively by"
echo "crates/solana-gate/tests/account_level.rs."
echo "=========================================="
