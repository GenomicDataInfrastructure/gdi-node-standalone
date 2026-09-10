#!/usr/bin/env bash
#
# Crash-loop / restart soak for gdi-node-standalone.
#
# Boots the node over a persistent inbox + data_dir, drives dataset churn (drop, then
# delete), and SIGKILLs the node at randomised moments during ingest and delete. A real
# `kill -9` unwinds nothing and runs no Drop, unlike an in-process panic. The node
# restarts each cycle, so the boot-time reap + hydrate must recover from whichever torn
# window the kill landed in: the PostRename one, dir committed and status not, or the
# PostStatusPurge one, status purged and dir not.
#
# Convergence invariants asserted after a final clean boot:
#   * a kept dataset (dropped, never deleted) ends served (visible/hidden) with its dir;
#   * a deleted dataset ends 410 Gone (tombstoned), its data_dir/{id}/ erased and no
#     .deleting/{id} marker left behind, so no un-erased data survives a crash
#     mid-erasure;
#   * no orphan working dir survives under data_dir/.incoming/ (boot reap);
#   * every dataset dir on disk has a status-index entry (store consistency).
#
# Advisory long-runner. Tunables: SOAK_CYCLES (default 8). Uses target/release binaries,
# building them if absent. No Docker, S3 or keys.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

PORT="${SOAK_PORT:-8892}"
MGMT_PORT="${SOAK_MGMT_PORT:-8893}"
BASE="http://127.0.0.1:${PORT}"
MGMT_BASE="http://127.0.0.1:${MGMT_PORT}"
CYCLES="${SOAK_CYCLES:-8}"

command -v curl >/dev/null 2>&1 || { echo "FAIL: curl not found" >&2; exit 127; }

TOOL="${TOOL:-$ROOT/target/release/gdi-dataset-tool}"
NODE="${NODE:-$ROOT/target/release/gdi-node-standalone}"
if [ ! -x "$TOOL" ] || [ ! -x "$NODE" ]; then
  echo "==> building release binaries"
  cargo build --release --locked --bins -p gdi-node-standalone -p gdi-dataset-tool
fi

WORK="$(mktemp -d)"
NODE_PID=""
cleanup() {
  if [ -n "$NODE_PID" ]; then kill -9 "$NODE_PID" 2>/dev/null || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT

DATA="$WORK/data"; INBOX="$WORK/inbox"; BUILDROOT="$WORK/build"
mkdir -p "$DATA" "$INBOX" "$BUILDROOT"

cat > "$WORK/node.toml" <<EOF
[service]
listen = "127.0.0.1:${PORT}"
management_addr = "127.0.0.1:${MGMT_PORT}"
base_url = "${BASE}"
data_dir = "${DATA}"
inbox = "${INBOX}"
rescan_interval_seconds = 2

[catalogs]
gdi-aggregated = "Genome of Europe Aggregated Data"

[beacon]
id = "org.gdi.soak.beacon"
name = "GDI crash-soak beacon"
EOF

# Build two distinct datasets once (country code is part of the id).
build_ds() {  # build_ds <cc> -> echoes the dataset id, leaves staging under $BUILDROOT/<cc>
  local cc="$1"
  local out="$BUILDROOT/$cc"
  mkdir -p "$out"
  "$TOOL" build "$ROOT/crates/gdi-dataset-tool/tests/fixtures/covid-package.yaml" \
    --cc "$cc" --output "$out" >/dev/null
  basename "$(find "$out" -mindepth 1 -maxdepth 1 -type d | head -n1)"
}
echo "==> building two fixture datasets"
KEEP_ID="$(build_ds FI)"    # dropped, never deleted -> must end served
DEL_ID="$(build_ds LV)"     # dropped, then deleted  -> must end erased
echo "    keep=$KEEP_ID  delete=$DEL_ID"

drop_ds() {  # drop_ds <cc> <id> [state]
  local cc="$1" id="$2" state="${3:-visible}"
  local src; src="$(find "$BUILDROOT/$cc" -mindepth 1 -maxdepth 1 -type d | head -n1)"
  # Copy (the staging is consumed on ingest; keep the pristine build for re-drops).
  cp -a "$src" "$INBOX/$id"
  printf '{"state":"%s"}' "$state" > "$INBOX/${id}.state.json"
}

boot() {
  "$NODE" --config "$WORK/node.toml" > "$WORK/node.$1.log" 2>&1 &
  NODE_PID=$!
  local ok=""
  for _ in $(seq 1 60); do curl -fsS "${MGMT_BASE}/health/ready" >/dev/null 2>&1 && { ok=1; break; }; sleep 0.5; done
  [ -n "$ok" ] || { echo "FAIL: node not ready (cycle $1)" >&2; tail -20 "$WORK/node.$1.log" >&2; exit 1; }
}

# Deterministic churn with randomised kill timing: the jitter is derived from the cycle
# number, so the run is reproducible. Drop both early, tombstone DEL_ID mid-run.
for c in $(seq 1 "$CYCLES"); do
  boot "$c"
  if [ "$c" -eq 1 ]; then drop_ds FI "$KEEP_ID"; drop_ds LV "$DEL_ID"; fi
  if [ "$c" -eq $(( CYCLES / 2 )) ]; then
    # force=true: delete even if it already reached Visible (reconcile_deleted refuses a
    # live Visible dataset otherwise).
    printf '{"state":"deleted","force":true}' > "$INBOX/${DEL_ID}.state.json"
  fi
  # Jitter 100..900ms so the SIGKILL lands in varying phases of ingest/delete.
  ms=$(( 100 + (c * 137) % 800 ))
  sleep "$(awk "BEGIN{print $ms/1000}")"
  kill -9 "$NODE_PID" 2>/dev/null || true
  wait "$NODE_PID" 2>/dev/null || true
  NODE_PID=""
  printf '  cycle %s/%s: killed after %sms\n' "$c" "$CYCLES" "$ms"
done

# Final clean boot; let reap + hydrate + rescans settle, then assert convergence.
echo "==> final boot; waiting for convergence"
boot final

state_of() { curl -s -o /dev/null -w '%{http_code}' "${MGMT_BASE}/datasets/$1/state"; }
body_of()  { curl -s "${MGMT_BASE}/datasets/$1/state"; }

converged=""
for _ in $(seq 1 40); do
  ks="$(body_of "$KEEP_ID")"; dc="$(state_of "$DEL_ID")"
  if echo "$ks" | grep -qE '"state":"(visible|hidden)"' && [ "$dc" = "410" ]; then converged=1; break; fi
  sleep 0.5
done

fail=0
if [ -z "$converged" ]; then
  echo "FAIL: did not converge; keep=$(body_of "$KEEP_ID") del_http=$(state_of "$DEL_ID")" >&2; fail=1
fi
# The kept dataset is served and present on disk.
[ -d "$DATA/$KEEP_ID" ] || { echo "FAIL: kept dataset dir missing: $DATA/$KEEP_ID" >&2; fail=1; }
# The deleted dataset is fully erased: 410 Gone, no dir, no lingering intent marker.
#
# 410, not 404. The node distinguishes a tombstone, meaning the id existed, was erased and
# is refused while the operator's `deleted` sidecar stands, from an id it never ingested,
# which stays 404. Conflating the two makes `deploy --wait` poll out its whole timeout
# against an id the node has permanently refused. 410 is also the stronger assertion here:
# this scenario drops a `deleted` sidecar, so a 404 would mean the tombstone was lost, the
# id forgotten rather than refused.
[ "$(state_of "$DEL_ID")" = "410" ] || { echo "FAIL: deleted dataset not tombstoned (want 410 Gone): $(state_of "$DEL_ID") $(body_of "$DEL_ID")" >&2; fail=1; }
[ ! -d "$DATA/$DEL_ID" ] || { echo "FAIL: un-erased data survives for deleted dataset: $DATA/$DEL_ID" >&2; fail=1; }
[ ! -e "$DATA/.deleting/$DEL_ID" ] || { echo "FAIL: a .deleting intent marker was left behind for $DEL_ID" >&2; fail=1; }
# No orphan working dir survived the boot reap.
if [ -d "$DATA/.incoming" ] && [ -n "$(find "$DATA/.incoming" -mindepth 1 2>/dev/null)" ]; then
  echo "FAIL: orphan working dir under .incoming survived a boot reap" >&2; fail=1
fi
# Store consistency: every on-disk dataset dir has a status-index entry.
if [ -f "$DATA/.status.json" ]; then
  for d in "$DATA"/*/; do
    [ -d "$d" ] || continue
    id="$(basename "$d")"
    grep -q "\"$id\"" "$DATA/.status.json" || { echo "FAIL: on-disk dataset $id has no .status.json entry" >&2; fail=1; }
  done
fi

if [ "$fail" -ne 0 ]; then echo "CRASH-LOOP SOAK: FAILED" >&2; exit 1; fi
echo "CRASH-LOOP SOAK: PASS ($CYCLES kill/restart cycles; kept=$KEEP_ID served, deleted=$DEL_ID erased)"
