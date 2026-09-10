#!/usr/bin/env bash
#
# Endurance / leak soak for gdi-node-standalone.
#
# Boots the node over the COVID fixture (plaintext inbox, no Docker, no S3, no keys, the
# same boot as scripts/load/run.sh), drives repeated request bursts, and samples the node
# process's resident memory, open file descriptors and thread count each round. A leak
# shows a sustained upward RSS/fd trend; a healthy process fills its caches during warmup
# then plateaus. `scripts/soak/checks.py` distinguishes the two.
#
# Advisory long-runner. The hard assertions are structural: fds and threads must not grow
# past a small tolerance, and RSS must plateau rather than keep climbing after warmup.
# Tunables:
#   SOAK_ROUNDS       rounds of drive+sample (default 30)
#   SOAK_ROUND_SECS   oha drive seconds per round (default 2)
#   SOAK_WARMUP       leading rounds excluded from the trend baseline (default 5)
#   SOAK_CONC         oha concurrency per round (default 8)
#   SOAK_PACKAGE      package.yaml to build the soaked dataset from (default: COVID fixture)
#   SOAK_QUERY        path+query appended to the base URL (default: the COVID site below)
#   SOAK_PROBE_MATCH  string the probe response must contain; required with SOAK_QUERY
# Uses target/release binaries, building them if absent. Requires oha + python3.
#
# What the default profile does NOT cover. It drives one single-position query at 8
# clients against a one-variant fixture: a page of one row. `docs/deployment.md`'s
# resource baseline reports a very different regime: 32 clients pulling 1000-row pages,
# where RSS climbs for about a minute to roughly 1 GiB and keeps ~920 MiB after the load
# stops. The trend check here is sound, but at the default load it plateaus within a few
# MiB and would stay green through all of that. To drive the advertised regime, build the
# realistic sample and page a chr21 window that fills a 1000-row page:
#
#   SOAK_PACKAGE=crates/test-util/tests/fixtures/sample/gdi-sample.package.yaml \
#   SOAK_QUERY='/beacon/v2/g_variants?referenceName=21&start=5030000&end=5130000&assemblyId=GRCh38&requestedGranularity=record&limit=1000' \
#   SOAK_PROBE_MATCH='"alleleCount"' SOAK_CONC=32 SOAK_ROUND_SECS=10 SOAK_ROUNDS=12 \
#     scripts/soak/leak.sh
#
# Neither profile is in `ci-local.sh all`: this is a long-runner, run on purpose.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

PORT="${SOAK_PORT:-8890}"
MGMT_PORT="${SOAK_MGMT_PORT:-8891}"
BASE="http://127.0.0.1:${PORT}"
MGMT_BASE="http://127.0.0.1:${MGMT_PORT}"
SOAK_ROUNDS="${SOAK_ROUNDS:-30}"
SOAK_ROUND_SECS="${SOAK_ROUND_SECS:-2}"
SOAK_WARMUP="${SOAK_WARMUP:-5}"
SOAK_CONC="${SOAK_CONC:-8}"
SOAK_PACKAGE="${SOAK_PACKAGE:-$ROOT/crates/gdi-dataset-tool/tests/fixtures/covid-package.yaml}"
# A probe that cannot fail is worse than no probe: with the query overridden, the default
# `alleleCount":618` names a variant the new dataset does not contain, so the run would
# stop. But a laxer default would let an override soak a 0-result path and call the
# resulting flat trend a leak verdict. Require the pair to move together.
if [ -n "${SOAK_QUERY:-}" ] && [ -z "${SOAK_PROBE_MATCH:-}" ]; then
  echo "FAIL: SOAK_QUERY is set but SOAK_PROBE_MATCH is not. The probe asserts the soaked" >&2
  echo "      query returns rows; with a new query the default assertion names a variant" >&2
  echo "      the new dataset does not have. Set both (see the header)." >&2
  exit 2
fi
SOAK_PROBE_MATCH="${SOAK_PROBE_MATCH:-\"alleleCount\":618}"

command -v oha >/dev/null 2>&1 || { echo "FAIL: oha not found; install it with: cargo install oha --locked" >&2; exit 127; }
command -v python3 >/dev/null 2>&1 || { echo "FAIL: python3 not found" >&2; exit 127; }

TOOL="${TOOL:-$ROOT/target/release/gdi-dataset-tool}"
NODE="${NODE:-$ROOT/target/release/gdi-node-standalone}"
if [ ! -x "$TOOL" ] || [ ! -x "$NODE" ]; then
  echo "==> building release binaries"
  cargo build --release --locked --bins -p gdi-node-standalone -p gdi-dataset-tool
fi

WORK="$(mktemp -d)"
NODE_PID=""
cleanup() {
  if [ -n "$NODE_PID" ]; then kill "$NODE_PID" 2>/dev/null || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT

DATA="$WORK/data"; INBOX="$WORK/inbox"; BUILDROOT="$WORK/build"
mkdir -p "$DATA" "$INBOX" "$BUILDROOT"

echo "==> building the soak dataset from $(basename "$SOAK_PACKAGE")"
"$TOOL" build "$SOAK_PACKAGE" --cc EE --output "$BUILDROOT"
STAGING="$(find "$BUILDROOT" -mindepth 1 -maxdepth 1 -type d | head -n1)"
[ -n "$STAGING" ] || { echo "FAIL: no staging dir produced" >&2; exit 1; }
DATASET_ID="$(basename "$STAGING")"
mv "$STAGING" "$INBOX/$DATASET_ID"
printf '{"state":"visible"}' > "$INBOX/${DATASET_ID}.state.json"

cat > "$WORK/node.toml" <<EOF
[service]
listen = "127.0.0.1:${PORT}"
management_addr = "127.0.0.1:${MGMT_PORT}"
base_url = "${BASE}"
data_dir = "${DATA}"
inbox = "${INBOX}"

[catalogs]
gdi-aggregated = "Genome of Europe Aggregated Data"

[beacon]
id = "org.gdi.soak.beacon"
name = "GDI soak beacon"
# Serve on the combined /beacon/v2 prefix this harness probes. Without these the node
# stays on its split default and every g_variants sample 404s, so the soak would measure
# RSS against a beacon it never reached.
aggregated_base_path = "/beacon/v2"
sensitive_base_path = "/beacon/v2"
EOF

echo "==> booting the node"
"$NODE" --config "$WORK/node.toml" > "$WORK/node.log" 2>&1 &
NODE_PID=$!
for _ in $(seq 1 60); do curl -fsS "${MGMT_BASE}/health/ready" >/dev/null 2>&1 && break; sleep 1; done
curl -fsS "${MGMT_BASE}/health/ready" >/dev/null || { echo "FAIL: node not ready" >&2; tail -20 "$WORK/node.log" >&2; exit 1; }
for _ in $(seq 1 60); do curl -fsS "${BASE}/beacon/v2/service-info" >/dev/null 2>&1 && break; sleep 1; done
# Fail closed if the beacon plane never came up. Otherwise the soak measures its RSS, fd
# and thread trends against a beacon it never reached.
curl -fsS "${BASE}/beacon/v2/service-info" >/dev/null || { echo "FAIL: beacon plane never accepted at ${BASE}/beacon/v2/service-info" >&2; tail -20 "$WORK/node.log" >&2; exit 1; }

# `start` is the 0-based Beacon coordinate: 1-based VCF POS 45823240 minus 1. Both numbers
# appear in this repo, 45823240 in prose naming the site and 45823239 in every query, so
# it is easy to write the 1-based one here and soak a miss path instead.
QUERY="${BASE}${SOAK_QUERY:-/beacon/v2/g_variants?referenceName=3&start=45823239&referenceBases=T&alternateBases=C&assemblyId=GRCh38}"

# Check one response before soaking on it. `oha`'s exit status is discarded below and no
# body is inspected there. A soak that drives a 0-result path still moves RSS and fds, so
# its trend looks plausible while exercising a fraction of the response-assembly code.
PROBE="$(curl -fsS "${QUERY}&requestedGranularity=record" || true)"
printf '%s' "$PROBE" | grep -qF "$SOAK_PROBE_MATCH" || {
  echo "FAIL: the soak query returns no ${SOAK_PROBE_MATCH}." >&2
  echo "      Check the 0-based \`start\` in QUERY above. Response was:" >&2
  printf '      %s\n' "${PROBE:-<empty>}" >&2
  exit 1
}
echo "==> soak query verified: response contains ${SOAK_PROBE_MATCH}"

SAMPLES="$WORK/samples.tsv"
printf 'round\trss_kb\tfds\tthreads\n' > "$SAMPLES"
echo "==> soak: ${SOAK_ROUNDS} rounds x ${SOAK_ROUND_SECS}s (warmup ${SOAK_WARMUP})"
for r in $(seq 1 "$SOAK_ROUNDS"); do
  oha --no-tui -c "$SOAK_CONC" -z "${SOAK_ROUND_SECS}s" "$QUERY" >/dev/null 2>&1 || true
  # Sample the node process straight from /proc (same host process).
  rss="$(awk '/^VmRSS:/{print $2}' "/proc/${NODE_PID}/status" 2>/dev/null || echo 0)"
  fds="$(find "/proc/${NODE_PID}/fd" -mindepth 1 2>/dev/null | wc -l | tr -d ' ')"
  threads="$(awk '/^Threads:/{print $2}' "/proc/${NODE_PID}/status" 2>/dev/null || echo 0)"
  printf '%s\t%s\t%s\t%s\n' "$r" "${rss:-0}" "${fds:-0}" "${threads:-0}" >> "$SAMPLES"
  printf '  round %2s/%s  rss=%sKB fds=%s threads=%s\n' "$r" "$SOAK_ROUNDS" "$rss" "$fds" "$threads"
done

# Fail closed if the node died mid-soak. `oha` above is non-fatal, since a shed request is
# not a leak, and the /proc reads fall back to 0 once the process is gone, so a crash
# leaves an all-zeros series that every trend check passes. checks.py rejects a degenerate
# series too; catching it here names the cause and shows the log.
kill -0 "$NODE_PID" 2>/dev/null || {
  echo "FAIL: the node process exited during the soak. The samples above are not a leak" >&2
  echo "      trend, they are a dead process. Last 30 log lines:" >&2
  tail -30 "$WORK/node.log" >&2
  exit 1
}

echo "==> analysing the RSS / fd / thread trend"
python3 "$ROOT/scripts/soak/checks.py" "$SAMPLES" "$SOAK_WARMUP"
