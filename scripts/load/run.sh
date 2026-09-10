#!/usr/bin/env bash
#
# Advisory HTTP load harness for gdi-node-standalone, driven by `oha`.
#
# Boots the service over the COVID fixture (plaintext inbox ingest, no Docker, no S3,
# no keys), then drives the live beacon with `oha`:
#
#   1. baseline: concurrency below `[service].max_concurrent_requests`. Asserts all-2xx
#      and reports throughput and p99 latency.
#   2. saturation: concurrency well above the limit. Asserts the load-shed arm trips
#      (>=1 `503`). This is the one back-pressure path that is not testable in process:
#      a `tower::oneshot` queues on the permit instead of shedding, and `Overloaded` is
#      not constructible, so the in-repo middleware test covers 408 but not 503.
#   3. best-effort: captures one shed body under load and checks it is a
#      `beaconErrorResponse` envelope. Timing-dependent, so it is non-fatal.
#
# Advisory: throughput and latency numbers vary with the runner and gate nothing. The
# hard assertions are structural: baseline all-2xx, saturation sheds a 503.
# `.github/workflows/scheduled.yml` invokes it.
#
# Usage: scripts/load/run.sh, from the repo root. Requires `oha` (`cargo install oha`)
# on PATH. Uses `target/release` binaries, building them if absent; override NODE / TOOL
# to point at pre-built binaries, debug ones for instance.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

PORT="${LOAD_PORT:-8870}"
MGMT_PORT="${LOAD_MGMT_PORT:-8871}"
BASE="http://127.0.0.1:${PORT}"
MGMT_BASE="http://127.0.0.1:${MGMT_PORT}"
MAX_CONCURRENT="${LOAD_MAX_CONCURRENT:-4}"
BASE_CONC="${LOAD_BASE_CONC:-2}"
SAT_CONC="${LOAD_SAT_CONC:-64}"
BASE_DURATION="${LOAD_BASE_DURATION:-10s}"
SAT_DURATION="${LOAD_SAT_DURATION:-10s}"

command -v oha >/dev/null 2>&1 || {
  echo "FAIL: oha not found on PATH; install it with: cargo install oha --locked" >&2
  exit 127
}
command -v python3 >/dev/null 2>&1 || {
  echo "FAIL: python3 not found on PATH; the harness parses oha JSON output with python3" >&2
  exit 127
}

TOOL="${TOOL:-$ROOT/target/release/gdi-dataset-tool}"
NODE="${NODE:-$ROOT/target/release/gdi-node-standalone}"
if [ ! -x "$TOOL" ] || [ ! -x "$NODE" ]; then
  echo "==> building release binaries"
  cargo build --release --locked --bins -p gdi-node-standalone -p gdi-dataset-tool
fi

WORK="$(mktemp -d)"
NODE_PID=""
cleanup() {
  [ -n "$NODE_PID" ] && kill "$NODE_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

DATA="$WORK/data"
INBOX="$WORK/inbox"
BUILDROOT="$WORK/build"
mkdir -p "$DATA" "$INBOX" "$BUILDROOT"

# 1. Build the COVID dataset (catalog `gdi-aggregated`): plaintext staging, lite-
#    ingestible. Same fixture scripts/e2e/run.sh builds from.
echo "==> building the COVID fixture dataset"
"$TOOL" build "$ROOT/crates/gdi-dataset-tool/tests/fixtures/covid-package.yaml" \
  --cc EE --output "$BUILDROOT"
STAGING="$(find "$BUILDROOT" -mindepth 1 -maxdepth 1 -type d | head -n1)"
[ -n "$STAGING" ] || { echo "FAIL: no staging dir produced under $BUILDROOT" >&2; exit 1; }
DATASET_ID="$(basename "$STAGING")"

# 2. Drop the staging dir + a `visible` sidecar into the inbox.
mv "$STAGING" "$INBOX/$DATASET_ID"
printf '{"state":"visible"}' > "$INBOX/${DATASET_ID}.state.json"

# 3. Minimal node config with a low concurrency limit, so the saturation pass sheds.
cat > "$WORK/node.toml" <<EOF
[service]
listen = "127.0.0.1:${PORT}"
management_addr = "127.0.0.1:${MGMT_PORT}"
base_url = "${BASE}"
data_dir = "${DATA}"
inbox = "${INBOX}"
max_concurrent_requests = ${MAX_CONCURRENT}

[catalogs]
gdi-aggregated = "Genome of Europe Aggregated Data"

[beacon]
id = "org.gdi.load.beacon"
name = "GDI load-test beacon"
# Serve on the combined /beacon/v2 prefix this harness probes. Without these the node
# uses its split default, with aggregated at /aggregated/beacon/v2, so every probe below
# would 404 and the load test would never run.
aggregated_base_path = "/beacon/v2"
sensitive_base_path = "/beacon/v2"
EOF

echo "==> booting the node (max_concurrent_requests=${MAX_CONCURRENT})"
"$NODE" --config "$WORK/node.toml" > "$WORK/node.log" 2>&1 &
NODE_PID=$!
for _ in $(seq 1 60); do
  curl -fsS "${MGMT_BASE}/health/ready" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS "${MGMT_BASE}/health/ready" >/dev/null || {
  echo "FAIL: node did not become ready" >&2; tail -20 "$WORK/node.log" >&2; exit 1
}

# The readiness poll above hits the management port; the load below hits the main service
# port, which can bind slightly later. Wait on a real main-port endpoint, the beacon
# service-info: an unauthenticated GET with no dataset dependency.
MAIN_READY_URL="${BASE}/beacon/v2/service-info"
for _ in $(seq 1 60); do
  curl -fsS "$MAIN_READY_URL" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS "$MAIN_READY_URL" >/dev/null || {
  echo "FAIL: main listener never accepted at $MAIN_READY_URL" >&2; tail -20 "$WORK/node.log" >&2; exit 1
}

# A representative hit query, the COVID chr3 T>C site, as a GET.
QUERY="${BASE}/beacon/v2/g_variants?referenceName=3&start=45823239&referenceBases=T&alternateBases=C&assemblyId=GRCh38&requestedGranularity=record"

# Both assertions live in scripts/load/checks.py rather than in inline heredocs, so they
# can be unit-tested. They must fail closed when oha reports no status codes at all.
CHECKS="$(dirname "$0")/checks.py"

# --- 1. Baseline: concurrency under the limit -> all 2xx -----------------------
echo "==> baseline load (c=${BASE_CONC}, ${BASE_DURATION})"
oha --no-tui --output-format json -c "${BASE_CONC}" -z "${BASE_DURATION}" "$QUERY" > "$WORK/baseline.json"
python3 "$CHECKS" baseline "$WORK/baseline.json"

# --- 2. Saturation: concurrency over the limit -> the load-shed arm trips ------
echo "==> saturation load (c=${SAT_CONC}, ${SAT_DURATION})"
oha --no-tui --output-format json -c "${SAT_CONC}" -z "${SAT_DURATION}" "$QUERY" > "$WORK/sat.json"
python3 "$CHECKS" saturation "$WORK/sat.json"

# --- 3. Best-effort: a shed body is a beaconErrorResponse envelope -------------
echo "==> best-effort: 503 body shape"
oha --no-tui -c "${SAT_CONC}" -z 5s "$QUERY" >/dev/null 2>&1 &
BURST=$!
shed_body=""
for _ in $(seq 1 80); do
  resp="$(curl -s -w '\n%{http_code}' "$QUERY" 2>/dev/null || true)"
  code="$(printf '%s' "$resp" | tail -n1)"
  if [ "$code" = "503" ]; then
    shed_body="$(printf '%s' "$resp" | sed '$d')"
    break
  fi
done
wait "$BURST" 2>/dev/null || true
if [ -n "$shed_body" ]; then
  printf '%s' "$shed_body" | python3 -c \
    'import json,sys; b=json.load(sys.stdin); assert b["error"]["errorCode"]==503, b; print("  OK: 503 body is a beaconErrorResponse envelope")'
else
  echo "  no 503 captured by curl this run; the saturation pass already confirmed the shed" >&2
fi

echo "==> load harness OK"
