#!/usr/bin/env bash
#
# Decide whether a finished `ci-local.sh all` may record its green run, and say why not.
#
# The counterpart to gate-status.sh, which decides whether to skip: this one decides
# whether the run earned the marker that authorises the next skip. It is a separate
# script so the decision is testable on its own (scripts/tests/test_gate_record.py)
# instead of only reachable by running a whole gate.
#
# The rule: record only when the tree is byte-identical to what the legs actually tested.
# `all` is meant to be run in the background while you keep working, so the tree can
# legitimately change mid-run. Hashing the tree after the legs would stamp the marker
# with a tree that was never compiled: an edit landing mid-run would be certified by a
# green that tested the tree as it stood when the legs started, and the next `all` would
# short-circuit on "inputs unchanged" over code nothing ever built. That is a false green
# in the gate most of CI delegates to.
#
# A changed tree is not a failure: the legs really did pass for the tree they saw. It is
# simply unrecordable, so we say so and exit 0, leaving the next `all` to run in full.
#
#     scripts/gate-record.sh --key-before <KEY>     # -> RECORDED <key> | NOT RECORDED: ...
#
# Overrides exist for testing; defaults are what the gate uses:
#   --key-before KEY  the tree key sampled before the legs ran (required)
#   --key-now KEY     the tree key now          (default: scripts/gate-key.sh .)
#   --marker PATH     marker file               (default: $PWD/target/.gate-ok)
#   --now EPOCH       current unix time         (default: date +%s)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
key_before="" key_now="" marker="" now=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --key-before) key_before="$2"; shift 2 ;;
    --key-now)    key_now="$2";    shift 2 ;;
    --marker)     marker="$2";     shift 2 ;;
    --now)        now="$2";        shift 2 ;;
    *) printf 'gate-record: unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done

[[ -n "$key_before" ]] || { printf 'gate-record: --key-before is required\n' >&2; exit 2; }
key_now="${key_now:-$("$here/gate-key.sh" .)}"
marker="${marker:-$PWD/target/.gate-ok}"
now="${now:-$(date +%s)}"

if [[ "$key_before" != "$key_now" ]]; then
  printf 'NOT RECORDED: the tree changed while the gate was running, so this green covers\n'
  printf '  a tree that no longer exists. The next all runs in full.\n'
  exit 0
fi

mkdir -p "$(dirname "$marker")"
printf '%s %s\n' "$key_now" "$now" > "$marker"
printf 'RECORDED %s\n' "$key_now"
