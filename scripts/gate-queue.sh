#!/usr/bin/env bash
# scripts/gate-queue.sh — run a command while holding the machine-wide gate slot.
#
# Several checkouts or worktrees on one machine let `ci-local.sh all` runs overlap, and
# concurrent gates do not share a machine, they thrash it. Three equal gates under
# processor-sharing all finish at ~3T; queued FIFO they finish at T, 2T and 3T. Same
# total work, earlier verdicts, and the wait is visible in the log instead of being spent
# inside a long "still compiling".
#
# The slot is a `flock` on one file shared by every checkout on the machine, the main
# checkout and all `.worktrees/*` alike, because the contention is the CPU and not the
# tree. `ci-local.sh` re-execs itself through this wrapper for its heavy targets. The
# fast tiers (`quick`, `lint`, the pre-commit hook) never queue.
#
# Not `nice`: CFS weights make a niced gate starve beside any nice-0 bulk load. Nice 10
# is weight 110 against nice 0's 1024, so a handful of nice-0 test workers crowd a niced
# gate out almost entirely. One slot is the fix.
#
# The lock is a file descriptor, inherited by everything the command spawns. An orphaned
# `cargo` left behind when the wrapper is killed keeps the slot, correctly, because it is
# still burning the CPU, and so would a leg that leaves a daemon running (`all` leaves
# none). The waiter names the holder so a stuck slot is diagnosable.
#
# Usage:
#   scripts/gate-queue.sh --lock <file> [--label <text>] -- <command> [args...]
#
# Env, read:
#   GATE_QUEUE_HEARTBEAT   seconds between "still queued" lines while waiting (default 60),
#                          so a log reader can tell queued from hung.
# Env, set for the command:
#   GATE_QUEUE_WAIT        seconds spent waiting for the slot; 0 when it was free.
set -euo pipefail

usage() {
  printf 'usage: %s --lock <file> [--label <text>] -- <command> [args...]\n' "${0##*/}" >&2
  exit 2
}

lock='' label=''
while (( $# )); do
  case "$1" in
    --lock)  [[ $# -ge 2 ]] || usage; lock="$2"; shift 2 ;;
    --label) [[ $# -ge 2 ]] || usage; label="$2"; shift 2 ;;
    --)      shift; break ;;
    *)       usage ;;
  esac
done
[[ -n "$lock" && $# -ge 1 ]] || usage

# A missing util-linux must never block a gate: run unqueued and say why.
if ! command -v flock >/dev/null 2>&1; then
  printf 'gate-queue: flock (util-linux) not found; running unqueued\n' >&2
  GATE_QUEUE_WAIT=0 exec "$@"
fi

mkdir -p "$(dirname "$lock")"
exec {fd}>>"$lock"
wait=0
if ! flock -n "$fd"; then
  holder="$(tail -n 1 "$lock" 2>/dev/null || true)"
  holder_pid="${holder#pid=}"; holder_pid="${holder_pid%% *}"
  if [[ "$holder_pid" =~ ^[0-9]+$ ]] && ! kill -0 "$holder_pid" 2>/dev/null; then
    holder+=" (that process is gone; a child of it still holds the descriptor)"
  fi
  printf '==> gate queue: slot held by %s; waiting. GATE_QUEUE=0 runs unqueued\n' \
    "${holder:-an unknown holder}"
  t0=$SECONDS
  heartbeat="${GATE_QUEUE_HEARTBEAT:-60}"
  # Clamped to >= 1: `flock -w 0` is a non-blocking try, so a heartbeat of 0, or junk,
  # turns the wait into a busy loop printing "still queued" as fast as the shell can.
  [[ "$heartbeat" =~ ^[0-9]+$ && "$heartbeat" -ge 1 ]] || heartbeat=1
  until flock -w "$heartbeat" "$fd"; do
    printf '    still queued after %ds\n' "$((SECONDS - t0))"
  done
  wait=$((SECONDS - t0))
  printf '    queued %ds; starting\n' "$wait"
fi
# Name the holder for the next waiter. Truncating the file does not touch the lock,
# which lives on the descriptor, not the content.
printf 'pid=%s label=%s since=%s\n' "$$" "${label:-$PWD}" "$(date +%s)" > "$lock"
GATE_QUEUE_WAIT="$wait" exec "$@"
