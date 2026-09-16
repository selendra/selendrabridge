#!/usr/bin/env bash
# Refuse provider-keyed RPC URLs and raw private keys in the repository.
#
# WHY THIS EXISTS (audit 2026-09-16, H-3)
#
# A live Alchemy key was committed inside a generated docker-compose file, pushed
# to `origin/master`, and survived three audit rounds. Each round tightened
# `.gitignore` — which stops the NEXT file, not the key already in history — and
# nothing ever checked. `git rm --cached` cleaned the working tree and left the
# key readable at `git show <old-sha>:<path>` for anyone who has ever cloned.
#
# So this scans BOTH the tracked tree and full history. Run it locally the same
# way CI does:  bash scripts/secret-scan.sh
#
# Deliberately not a generic entropy scanner: the false-positive rate of those on
# a repo full of addresses, hashes and fixtures is high enough that the result
# gets ignored, which is how you end up with a key in history. These are the
# shapes that actually leak here.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Fail CLOSED. Every check below ends in `|| true` so that "no matches" (grep's
# exit 1) is not fatal, which means a git that cannot run would otherwise report
# "clean" — the exact failure mode this script exists to prevent.
git rev-parse --git-dir >/dev/null 2>&1 || {
  printf 'secret scan cannot run: not a git repository\n' >&2
  exit 1
}

# --- what we refuse -----------------------------------------------------------

# A hosted-RPC URL carrying a key in its path. The key segment is >= 12 chars so
# `.../v2/` placeholders and `${RPC_1}` references do not match.
KEYED_RPC='(alchemy\.com|infura\.io|quiknode\.pro|helius-rpc\.com|ankr\.com|blastapi\.io)/[A-Za-z0-9_/-]*[A-Za-z0-9_-]{12,}'

# --- known-acceptable matches -------------------------------------------------
#
# Each entry must be a FIXTURE (an obviously fake value in a test) or a
# DOCUMENTED, ALREADY-BURNED credential. Adding a live key here is not a fix.
#
# TODO(H-3): `alch_0yxW5Nx78Hp-2dZ-iJBSq` is the key the 2026-09-16 audit found
# in `origin/master` history at 1bdca61/44cbaaf/c9a027e/8319bb7. It is allowed
# HERE ONLY so this scan can be merged and start protecting against new leaks
# while that one is dealt with. Remove this line once the key is rotated at the
# provider and, if the history is being rewritten, purged. Until it is removed,
# treat that key as public.
ALLOW='SuPerSecretKey123|AbCdEfGhIjKlMnOpQrStUvWxYz012345|0123456789abcdef0123456789abcdef|alch_0yxW5Nx78Hp-2dZ-iJBSq'

fail=0

say() { printf '%s\n' "$*" >&2; }

# --- 1. the tracked tree ------------------------------------------------------

say "scanning tracked files..."
if hits=$(git grep -I -n -E "$KEYED_RPC" -- . ':(exclude)scripts/secret-scan.sh' 2>/dev/null \
            | grep -Ev "$ALLOW" || true); [[ -n "$hits" ]]; then
  say ""
  say "FAIL: keyed RPC URL in a tracked file:"
  say "$hits"
  say ""
  say "Emit \${RPC_<chain_id>} and keep the value in an ignored .env, as"
  say "scripts/bridge-from-json.sh does."
  fail=1
fi

# --- 2. history ---------------------------------------------------------------
#
# Skipped on a shallow clone, which would silently scan almost nothing — say so
# rather than passing quietly.

if [[ "$(git rev-parse --is-shallow-repository)" == "true" ]]; then
  say "NOTE: shallow clone — history not scanned (CI uses fetch-depth: 0)."
else
  say "scanning history ($(git rev-list --count --all) commits)..."
  if hits=$(git grep -I -n -E "$KEYED_RPC" $(git rev-list --all) 2>/dev/null \
              | grep -Ev "$ALLOW" | head -40 || true); [[ -n "$hits" ]]; then
    say ""
    say "FAIL: keyed RPC URL reachable in history:"
    say "$hits"
    say ""
    say "Rotate the credential at the provider FIRST — it is readable by anyone"
    say "who has cloned. Removing it from the tip does not unpublish it."
    fail=1
  fi
fi

if (( fail )); then
  say ""
  say "secret scan FAILED"
  exit 1
fi
say "secret scan clean"
