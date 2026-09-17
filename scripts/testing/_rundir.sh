#!/usr/bin/env bash
# Run-directory helpers for the scripts in this directory. Sourced, never run.
#
# WHY (audit round 5, LOW). These scripts used fixed paths under /tmp —
# /tmp/bridge-run, /tmp/bridge-gen5, /tmp/deploy.json — and then SOURCED files
# from them. /tmp is shared: any local user can create /tmp/bridge-run first,
# drop an `addresses.env` in it, and have it executed as whoever runs the test
# next (with that user's keys in the environment). A fixed log path is also a
# symlink target: `>"$LOG/api.log"` follows a planted link and truncates
# whatever it points at.
#
#   bridge_state_dir NAME  -> a private per-user dir (0700) for state that must
#                             outlive the script (logs, addresses, cursors).
#   rundir_trusted DIR     -> succeeds only if DIR is a real directory (not a
#                             symlink) owned by this user and not writable by
#                             group/other. Call it before reading anything from
#                             a dir given by RUN_DIR / a config file.
#   load_env_file FILE     -> assigns KEY=VALUE lines WITHOUT executing them.
#                             Only [A-Z_][A-Z0-9_]* keys and values free of shell
#                             metacharacters are taken; anything else is refused
#                             by name. Replaces `source addresses.env`.

bridge_state_dir() { # $1 name
  local d="${XDG_STATE_HOME:-$HOME/.local/state}/selendra-bridge/$1"
  mkdir -p "$d" && chmod 700 "$d" && printf '%s' "$d"
}

rundir_trusted() { # $1 dir
  local d="$1" owner mode
  [[ -d "$d" && ! -L "$d" ]] || { echo "ERROR: $d is not a directory (or is a symlink)" >&2; return 1; }
  owner="$(stat -c %u -- "$d")" mode="$(stat -c %a -- "$d")"
  [[ "$owner" == "$(id -u)" ]] || { echo "ERROR: $d is owned by uid $owner, not you — refusing to read from it" >&2; return 1; }
  (( (8#$mode & 8#022) == 0 )) || { echo "ERROR: $d is group/world-writable (mode $mode) — refusing to read from it" >&2; return 1; }
}

load_env_file() { # $1 file; exports each accepted KEY
  local f="$1" line key val n=0
  [[ -f "$f" && ! -L "$f" ]] || { echo "ERROR: $f is not a regular file" >&2; return 1; }
  rundir_trusted "$(dirname -- "$f")" || return 1
  while IFS= read -r line || [[ -n "$line" ]]; do
    n=$((n + 1))
    [[ -z "$line" || "$line" == \#* ]] && continue
    if [[ "$line" =~ ^([A-Z_][A-Z0-9_]*)=([A-Za-z0-9._:/@+=~-]*)$ ]]; then
      key="${BASH_REMATCH[1]}" val="${BASH_REMATCH[2]}"
      printf -v "$key" '%s' "$val"
      export "${key?}"
    else
      echo "ERROR: $f:$n is not a plain KEY=VALUE line — refusing to load it" >&2
      return 1
    fi
  done < "$f"
}
