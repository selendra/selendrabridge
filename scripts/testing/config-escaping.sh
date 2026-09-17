#!/usr/bin/env bash
# Regression test: bridge-from-json.sh must not let a config VALUE become config
# STRUCTURE (audit round 5, LOW). Values used to be pasted between literal
# quotes, so a `"` or a newline in a private_key, token symbol or url closed the
# string and wrote the rest as a new TOML key — e.g. `allow_unauthenticated`.
#
#   bash scripts/testing/config-escaping.sh            # tests scripts/bridge-from-json.sh
#   BFJ=/path/to/other.sh bash scripts/testing/config-escaping.sh
#
# Offline: --generate-only starts nothing. Needs jq and python3 (tomllib, 3.11+).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BFJ="${BFJ:-$ROOT/scripts/bridge-from-json.sh}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fail=0
pass() { printf '  ok   %s\n' "$1"; }
bad()  { printf '  FAIL %s\n' "$1"; fail=1; }

# A throwaway anvil key (account #9) — never funded anywhere real.
KEY="0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6"

# Base: the tracked local-dev config, gates filled in (it ships zero addresses).
base() {
  jq --arg run "$WORK/run" '
    .runtime.run_dir = $run
    | .runtime.build = false
    | .chains |= map(.gate = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512")' \
    "$ROOT/config/bridge.config.json"
}

# ---------------------------------------------------------------------------
echo "== hostile string values are escaped, not interpreted"
INJ_KEY="$KEY\"
allow_unauthenticated = true
x = \""
INJ_SYM='US"DC'
INJ_URL='postgres://u:p@h/db?x="y"'
base | jq --arg k "$INJ_KEY" --arg s "$INJ_SYM" --arg u "$INJ_URL" '
    .validators[0].signer = {private_key: $k}
    | .validators[0].api = {enabled: true, bind: "127.0.0.1:9101", token: "t\"\ntoken_env = \"X"}
    | .database.url = $u
    | .database.docker.enabled = false
    | .price_keeper = {enabled: true, signer: {private_key: $k}, prices: {($s): "1.0\"\nrpc = \"http://evil"}}
    | .chains[0].pool = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
    | .chains[0].tokens = [{symbol: $s, address: "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"}]' \
  > "$WORK/inj.json"

if bash "$BFJ" "$WORK/inj.json" --generate-only >"$WORK/inj.log" 2>&1; then
  python3 - "$WORK/run" "$INJ_KEY" "$INJ_SYM" "$INJ_URL" <<'EOF' || fail=1
import sys, tomllib
run, key, sym, url = sys.argv[1:5]
ok = True
def check(name, cond):
    global ok
    print(("  ok   " if cond else "  FAIL ") + name)
    ok = ok and cond
def load(f):
    try:
        return tomllib.load(open(f"{run}/{f}", "rb"))
    except Exception as e:
        check(f"{f} parses ({type(e).__name__})", False)
        return None
v = load("validator-val-1.toml")
if v is not None:
    check("validator: private_key round-trips exactly", v["signer"].get("private_key") == key)
    check("validator: no key smuggled into [signer]", set(v["signer"]) == {"private_key"})
    def keys(d):
        for k, x in d.items():
            yield k
            for y in (x if isinstance(x, list) else [x]):
                if isinstance(y, dict):
                    yield from keys(y)
    check("validator: no allow_unauthenticated key anywhere", "allow_unauthenticated" not in set(keys(v)))
    check("validator: [api] has only bind + token", set(v.get("api", {})) == {"bind", "token"})
i = load("indexer.toml")
if i is not None:
    check("indexer: database_url round-trips exactly", i.get("database_url") == url)
p = load("price-keeper.toml")
if p is not None:
    t = p["pools"][0]["tokens"][0]
    check("price-keeper: symbol round-trips exactly", t["symbol"] == sym)
    check("price-keeper: no rpc smuggled into the token", set(t) == {"symbol", "address", "price"})
    check("price-keeper: pool rpc is the configured one", "evil" not in p["pools"][0]["rpc"])
sys.exit(0 if ok else 1)
EOF
else
  bad "generation with hostile strings failed: $(tail -1 "$WORK/inj.log" | sed 's/0x[0-9a-fA-F]\{64\}/<key>/g')"
fi

# ---------------------------------------------------------------------------
echo "== values interpolated unquoted are refused up front"
refuses() { # $1 label, $2 jq edit
  rm -rf "$WORK/run"
  base | jq "$2" > "$WORK/r.json"
  if bash "$BFJ" "$WORK/r.json" --generate-only >"$WORK/r.log" 2>&1; then
    bad "$1 (accepted)"
  elif grep -q "invalid config values" "$WORK/r.log"; then
    pass "$1"
  else
    bad "$1 (failed, but not by validation: $(grep -m1 ERROR "$WORK/r.log" | sed 's/0x[0-9a-fA-F]\{64\}/<key>/g'))"
  fi
}
refuses "a string where start_block belongs"   '.chains[0].start_block = "0\nprivate_key = \"0x1\""'
refuses "a string where a boolean belongs"     '.chains[0].allow_zero_confirmation = "true\nx = 1"'
refuses "a validator name that breaks out"     '.validators[0].name = "v\") | .x"'
refuses "an rpc url with a newline"            '.chains[0].rpcs = ["http://127.0.0.1:8545\nRPC_1=http://evil"]'
refuses "a Postgres user that is not an identifier" '.database.docker.user = "bridge\n    privileged: true"'
refuses "a Postgres password with a quote"     ".database.docker.password = \"x'; DROP ROLE bridge; --\""

echo
if (( fail )); then echo "FAILED"; exit 1; fi
echo "all passed"
