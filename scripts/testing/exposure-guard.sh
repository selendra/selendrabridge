#!/usr/bin/env bash
# Guard against re-publishing a service on every interface (audit 2026-09-16,
# M-9 and M-15). Offline, no services, no docker — it reads the tree.
#
#   bash scripts/testing/exposure-guard.sh
#
# Two rules, both learned the hard way:
#
#   1. A docker `-p`/`ports:` publish without an explicit `127.0.0.1:` binds
#      0.0.0.0 AND writes its own DNAT rule, which bypasses ufw/firewalld. The
#      round-4 fix reached the launchers but not five test harnesses, one of
#      them the live-testnet bring-up whose database holds real signatures.
#   2. The root compose stack must not serve GraphiQL/introspection: its own
#      header tells operators to swap in their real chains, so whatever it does
#      by default is what ends up facing the internet.
#
# The live stack under docker/testnet-mesh9/ is exempt: it is operated, not
# shipped as an example, and it is not this repo's advice to anyone.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

fail=0
bad() { printf '  FAIL %s\n' "$*"; fail=1; }
ok()  { printf '  ok   %s\n' "$*"; }

# --- 1. docker -p publishes in scripts ---------------------------------------
#
# Matches `-p <something>:<port>` where <something> is not a loopback address.
# Both real invocations and the commands our headers tell operators to run:
# a copy-pasted example is advice, and publishes just as widely.
# Prose that merely QUOTES a bad pattern (this file, and the comments
# explaining the fix) is not a publish; a commented-out `docker run` is, because
# a header telling an operator what to run is advice they will paste.
# `|| true` on the WHOLE pipeline: under `set -o pipefail` any grep that
# filters everything out exits 1 and would abort the script before it reports.
hits="$( { grep -rnE -- '-p[[:space:]]+"?\$?\{?[A-Za-z0-9_]*\}?[0-9]*:[0-9]+' scripts/ \
        | grep -vE -- '-p[[:space:]]+"?127\.0\.0\.1:' \
        | grep -vE 'mkdir|exposure-guard\.sh' \
        | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#' \
        | grep -E 'docker run|^[^:]+:[0-9]+:[^#]' ; } || true )"
if [[ -n "$hits" ]]; then
  bad "docker publish without 127.0.0.1:"
  printf '       %s\n' "$hits"
else
  ok "every docker publish in scripts/ is loopback-pinned"
fi

# --- 2. compose port publishes ------------------------------------------------
compose_hits=""
# Scope: the example/dev stacks this repo ships as advice. docker/production/*
# is exempt — its caddy publishes 80/443 on purpose, because terminating TLS for
# the public API is that container's whole job.
for f in docker-compose.yml docker-compose.dev.yml; do
  [[ -f "$f" ]] || continue
  # `ports: ["8545:8545"]` and the long form `- "8545:8545"`; a published port
  # is loopback-safe only when it names 127.0.0.1 explicitly.
  while IFS= read -r line; do
    compose_hits+="$f: $line"$'\n'
  done < <(grep -nE '^[[:space:]]*(ports:[[:space:]]*\[|-)[[:space:]]*"?[0-9]+:[0-9]+"?' "$f" || true)
  true
done
if [[ -n "$compose_hits" ]]; then
  bad "compose publishes a port on every interface:"
  printf '       %s\n' "$compose_hits"
else
  ok "every compose port publish is loopback-pinned"
fi

# --- 3. the root stack must not serve GraphiQL / introspection ----------------
if grep -q -- '"--production"' docker-compose.yml; then
  ok "root compose runs graphql-api with --production"
else
  bad "root compose does not pass --production: GraphiQL + introspection are on"
fi

echo
if (( fail )); then echo FAILED; exit 1; fi
echo "exposure guard clean"
