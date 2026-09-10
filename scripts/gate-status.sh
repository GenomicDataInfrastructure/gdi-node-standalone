#!/usr/bin/env bash
#
# Decide whether `ci-local.sh all` may short-circuit, and say why.
#
# Split out of ci-local.sh so the decision is testable on its own (see
# scripts/tests/test_gate_status.py) rather than only reachable by running a whole gate.
# This is the logic that decides whether to skip every leg the gate would otherwise run.
#
# Also useful directly when a gate re-runs and you want to know what invalidated it:
#
#     scripts/gate-status.sh          # -> FRESH ... | STALE: <reason>
#
# Exit 0 = fresh (safe to short-circuit), 1 = stale (run everything). Every failure mode
# returns STALE: missing, unreadable, malformed, mismatched, expired and clock-skewed
# markers alike. A needless full run costs minutes, and a wrong skip is a false green in
# the gate most of CI delegates to.
#
# Overrides exist for testing; defaults are what the gate uses:
#   --marker PATH   marker file            (default: $PWD/target/.gate-ok)
#   --key KEY       expected content key   (default: scripts/gate-key.sh .)
#   --now EPOCH     current unix time      (default: date +%s)
# Env: GATE_FORCE=1 always reports STALE; GATE_TTL_HOURS bounds marker age (default 24).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
marker="" key="" now=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --marker) marker="$2"; shift 2 ;;
    --key)    key="$2";    shift 2 ;;
    --now)    now="$2";    shift 2 ;;
    *) printf 'gate-status: unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done
marker="${marker:-$PWD/target/.gate-ok}"
now="${now:-$(date +%s)}"
ttl="${GATE_TTL_HOURS:-24}"

stale() { printf 'STALE: %s\n' "$1"; exit 1; }

[[ "${GATE_FORCE:-0}" == "1" ]] && stale "GATE_FORCE=1"
[[ -f "$marker" ]] || stale "no marker at $marker; no green run on record"
[[ -s "$marker" ]] || stale "marker is empty"

saved_key="" saved_ts=""
read -r saved_key saved_ts _ < "$marker" 2>/dev/null || stale "marker is unreadable"
[[ -n "$saved_key" && -n "$saved_ts" ]] || stale "marker is malformed, want '<key> <epoch>'"
[[ "$saved_ts" =~ ^[0-9]+$ ]] || stale "marker timestamp is not an integer: '$saved_ts'"

key="${key:-$("$here/gate-key.sh" .)}"
[[ "$saved_key" == "$key" ]] || stale "tree or toolchain changed since the last green run"

# Guard both directions: a marker from the future means the clock moved, and trusting it
# could extend a skip far past the TTL.
(( now >= saved_ts )) || stale "marker timestamp is in the future (clock skew)"
age_h=$(( (now - saved_ts) / 3600 ))
(( age_h < ttl )) || stale "last green run was ${age_h}h ago, past the ${ttl}h TTL"

printf 'FRESH: green %sh ago, inputs unchanged\n' "$age_h"
