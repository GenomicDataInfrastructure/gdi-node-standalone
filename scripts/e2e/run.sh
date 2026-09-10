#!/usr/bin/env bash
# Compose-based end-to-end smoke test against the Compose stack.
#
# It brings up the Compose stack and exercises the lite profile end-to-end, which is the
# wiring the unit and golden suites cannot pin:
#
#   1. build + pack a tiny fixture dataset with `gdi-dataset-tool`;
#   2. drop the staging dir + an {id}.state.json{"state":"visible"} sidecar into
#      the inbox volume;
#   3. poll `GET /datasets/{id}/state` until it reaches `visible`;
#   4. POST a Beacon `g_variants` query and assert the COVID
#      `frequencyInPopulations` (Total alleleCount 618 / alleleNumber 8000);
#   5. crawl `/fairdp` (Accept: text/turtle) and assert it harvests (the dataset
#      is reachable from the FDP root);
#   6. a publish -> unpublish round-trip via the state sidecar (visible -> hidden ->
#      visible), asserted through `GET /datasets/{id}/state`;
#   7. an operator override (`dataset hide`) that must survive a container restart. It is
#      the other authority, and the only state a re-ingest cannot rebuild. Its loss presents
#      as a clean recovery in which every withheld dataset serves again, so the restart is
#      the assertion that tells those two apart.
#
# The full stack (Garage/minio + OpenBao + PME + S3 upload) is exercised by
# scripts/e2e/run-full.sh, kept separate so the lite gate stays fast and needs no secrets
# and no S3 backend.
#
# Requirements: docker (+ compose v2), cargo (to run gdi-dataset-tool + discover
# the dataset id), ss (iproute2, for the busy-port preflight). Honours $COMPOSE (default
# "docker compose").
#
# Host ports (GDI_HOST_PORT_PUBLIC/GDI_HOST_PORT_MANAGEMENT) and the compose project name
# (GDI_E2E_PROJECT_SUFFIX, appended) are overridable, so this leg can run beside a dev
# stack, or beside another e2e run, instead of racing it for the same port. See
# docs/deployment.md's "Overriding the dev-stack host ports" table.
#
# Exit non-zero on the first failed assertion (set -e); always tears the stack
# down on exit.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

COMPOSE="${COMPOSE:-docker compose}"
COMPOSE_FILE="docker-compose.minimal.yml"
PROJECT="gdi-node-standalone-e2e${GDI_E2E_PROJECT_SUFFIX:-}"
HOST_PORT_PUBLIC="${GDI_HOST_PORT_PUBLIC:-8080}"
HOST_PORT_MANAGEMENT="${GDI_HOST_PORT_MANAGEMENT:-9090}"
export GDI_HOST_PORT_PUBLIC="$HOST_PORT_PUBLIC" GDI_HOST_PORT_MANAGEMENT="$HOST_PORT_MANAGEMENT"
BASE_URL="${BASE_URL:-http://localhost:$HOST_PORT_PUBLIC}"
# Health, readiness and the dataset-state oracle live on the separate management listener
# (`[service].management_addr`, mapped by the compose file), not on the public BASE_URL.
MGMT_URL="${MGMT_URL:-http://localhost:$HOST_PORT_MANAGEMENT}"
AGG_BASE_PATH="/beacon/v2"
TIMEOUT_SECS="${TIMEOUT_SECS:-120}"

compose() { $COMPOSE -p "$PROJECT" -f "$COMPOSE_FILE" "$@"; }

log()  { echo "[e2e] $*"; }
fail() { echo "[e2e] FAIL: $*" >&2; exit 1; }

# Preflight: this smoke builds images + boots a Compose stack, so fail fast (and
# actionably) if Docker or Compose v2 is missing rather than deep inside `compose up`.
command -v docker >/dev/null 2>&1 \
    || fail "docker not found on PATH: this smoke needs Docker with Compose v2"
$COMPOSE version >/dev/null 2>&1 \
    || fail "'$COMPOSE' is not usable: this smoke needs Docker Compose v2, set \$COMPOSE to a working command"

# Preflight: the host ports docker-compose.minimal.yml publishes for this project, from the
# GDI_HOST_PORT_PUBLIC/GDI_HOST_PORT_MANAGEMENT variables above, so this checks what
# `compose up` is about to bind. `compose up` does not ask whether another stack already
# holds a port: it either fails deep inside `up` with a raw "address already in use", or,
# if the port belongs to a container Docker is not tracking under this project, appears to
# succeed while talking to someone else's service. It runs before `trap cleanup EXIT` below,
# so a preflight failure does not also print "tearing down the stack" for a stack this run
# never started.
E2E_PORTS=("$HOST_PORT_PUBLIC" "$HOST_PORT_MANAGEMENT")
e2e_port_holder() {  # e2e_port_holder <port> -> holding container name(s), or empty
    docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null \
        | awk -v p=":$1->" '$0 ~ p {print $1}' | tr '\n' ' '
}
command -v ss >/dev/null 2>&1 || fail "ss not found on PATH: install iproute2, needed to check for busy host ports before compose up"
# One process per port, no pipeline: under `set -o pipefail` the `grep -q` of a
# `ss | awk | grep -q` pipeline exits at its first match, SIGPIPEs `awk`, and the pipeline
# returns 141, so a busy port reads as free. A failing `ss` is fatal for the same reason:
# silencing it would report "no ports busy".
listening="$(ss -ltn)" || fail "ss -ltn failed, so whether the e2e ports are free is unknown"
e2e_busy=()
for p in "${E2E_PORTS[@]}"; do
    if awk -v p=":${p}" '$4 ~ p"$" {found=1} END {exit !found}' <<<"$listening"; then
        e2e_busy+=("$p")
    fi
done
if [ "${#e2e_busy[@]}" -gt 0 ]; then
    for p in "${e2e_busy[@]}"; do
        holder="$(e2e_port_holder "$p")"
        log "port :$p is already bound${holder:+ (holder: $holder)}"
    done
    fail "cannot start: host port(s) ${e2e_busy[*]} already bound; stop the stack holding them and re-run"
fi

cleanup() {
    local rc=$?
    # On a non-zero exit, dump every service's logs before teardown: the containers are
    # gone after `compose down`, so this is the only window in which assertion paths that
    # print no logs inline can be diagnosed.
    if [ "$rc" -ne 0 ]; then
        log "failed with exit $rc; dumping compose logs before teardown"
        compose logs --no-color --tail=200 >&2 2>/dev/null || true
    fi
    log "tearing down the stack"
    compose down -v --remove-orphans >/dev/null 2>&1 || true
    [ -n "${WORK:-}" ] && rm -rf "$WORK" || true
}
trap cleanup EXIT

WORK="$(mktemp -d)"
BUILD_OUT="$WORK/build"
mkdir -p "$BUILD_OUT"

# --- 1. Build a tiny fixture dataset staging dir with the real tool -----------
FIXTURE="crates/gdi-dataset-tool/tests/fixtures/covid-package.yaml"
[ -f "$FIXTURE" ] || fail "missing fixture $FIXTURE"

log "building the COVID fixture staging dir with gdi-dataset-tool"
cargo run --quiet --locked -p gdi-dataset-tool -- build \
    "$FIXTURE" --cc EE -o "$BUILD_OUT"

STAGING="$(find "$BUILD_OUT" -mindepth 1 -maxdepth 1 -type d | head -n1)"
[ -n "$STAGING" ] || fail "no staging dir produced under $BUILD_OUT"
DATASET_ID="$(basename "$STAGING")"
log "dataset id: $DATASET_ID"
case "$DATASET_ID" in
    GDI-EE-UTARTU-*) : ;;
    *) fail "unexpected dataset id $DATASET_ID (expected GDI-EE-UTARTU-*)" ;;
esac

# --- 2. Bring up the minimal stack -------------------------------------------
# Provenance. docker-compose.minimal.yml's `build.args` read these two from the
# environment, defaulting to empty, so without them the image reports git_sha "unknown",
# which is the gap the assertion after readiness below exists to catch.
# Assigned, then exported: `export X="$(cmd)"` returns export's status, not cmd's, so the
# combined form would ship an empty sha silently (SC2155). Under `set -e` the split form
# aborts the run instead.
GITHUB_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD)"
SOURCE_DATE_EPOCH="$(git -C "$REPO_ROOT" log -1 --format=%ct)"
export GITHUB_SHA SOURCE_DATE_EPOCH
log "bringing up the minimal stack (build + up; git_sha=${GITHUB_SHA:0:12})"
compose up -d --build

# Wait for liveness, then readiness.
wait_http() {
    local url="$1" want="$2" deadline=$(( $(date +%s) + TIMEOUT_SECS ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if curl -fsS -o /dev/null -w '%{http_code}' "$url" 2>/dev/null | grep -q "$want"; then
            return 0
        fi
        sleep 2
    done
    return 1
}
log "waiting for /health/live"
wait_http "$MGMT_URL/health/live" 200 || { compose logs gdi-node-standalone; fail "service never became live"; }
log "waiting for /health/ready"
wait_http "$MGMT_URL/health/ready" 200 || { compose logs gdi-node-standalone; fail "service never became ready"; }

# The provenance args exported above must have reached the image: a compose file whose
# `build.args` drift from what this script exports would ship "unknown" with every other
# assertion in this smoke still green.
VERSION_BODY="$(curl -fsS "$MGMT_URL/version")" || fail "GET /version failed"
REPORTED_SHA="$(echo "$VERSION_BODY" | grep -o '"git_sha":"[^"]*"' | cut -d'"' -f4)"
[ -n "$REPORTED_SHA" ] || { echo "$VERSION_BODY"; fail "GET /version has no git_sha field"; }
[ "$REPORTED_SHA" != "unknown" ] \
    || { echo "$VERSION_BODY"; fail "GET /version reports git_sha=unknown: the compose build did not receive GITHUB_SHA"; }
log "confirmed: /version reports git_sha=$REPORTED_SHA (not unknown)"

# --- 3. Drop the staging dir + a visible sidecar into the inbox volume --------
# The inbox is a named volume mounted at /var/lib/gdi-node-standalone/inbox in the
# container; copy the staging dir + sidecar in via `docker cp` to the running
# container (atomic-enough for the watcher; the service ignores partial dirs until
# the sidecar/scan settles).
CID="$(compose ps -q gdi-node-standalone)"
[ -n "$CID" ] || fail "could not resolve the service container id"

log "dropping the staging dir into the inbox"
docker cp "$STAGING" "$CID:/var/lib/gdi-node-standalone/inbox/$DATASET_ID"
# The {id}.state.json sidecar declares the desired published visibility.
echo '{"state":"visible"}' > "$WORK/$DATASET_ID.state.json"
docker cp "$WORK/$DATASET_ID.state.json" "$CID:/var/lib/gdi-node-standalone/inbox/$DATASET_ID.state.json"

# --- 4. Poll /datasets/{id}/state until visible -------------------------------
state_of() {
    curl -fsS "$MGMT_URL/datasets/$DATASET_ID/state" 2>/dev/null \
        | grep -o '"state":"[a-z]*"' | head -n1 | cut -d'"' -f4
}
log "polling /datasets/$DATASET_ID/state for 'visible'"
deadline=$(( $(date +%s) + TIMEOUT_SECS ))
got=""
while [ "$(date +%s)" -lt "$deadline" ]; do
    got="$(state_of || true)"
    [ "$got" = "visible" ] && break
    [ "$got" = "error" ] && { compose logs gdi-node-standalone; fail "dataset entered error state"; }
    sleep 2
done
[ "$got" = "visible" ] || { compose logs gdi-node-standalone; fail "dataset did not reach visible (last: '${got:-none}')"; }
log "dataset is visible"

# --- 5. Beacon g_variants query: assert the COVID frequencies -----------------
log "querying g_variants for the COVID chr3:45823240 T>C site"
QUERY='{"query":{"requestParameters":{"referenceName":"3","start":[45823239],"referenceBases":"T","alternateBases":"C","assemblyId":"GRCh38","requestedGranularity":"RECORD"}}}'
RESP="$(curl -fsS -X POST "$BASE_URL$AGG_BASE_PATH/g_variants" \
    -H 'content-type: application/json' -d "$QUERY")"

echo "$RESP" | grep -q '"frequencyInPopulations"' \
    || { echo "$RESP"; fail "response has no frequencyInPopulations"; }
# Assert the COVID fixture's Total allele count and allele number.
echo "$RESP" | grep -q '"alleleCount":618' \
    || { echo "$RESP"; fail "expected Total alleleCount 618 not found"; }
echo "$RESP" | grep -q '"alleleNumber":8000' \
    || { echo "$RESP"; fail "expected Total alleleNumber 8000 not found"; }
log "g_variants frequencies asserted (Total AC=618 AN=8000)"

# --- 6. FDP harvest: the dataset is reachable from /fairdp --------------------
log "crawling /fairdp (Accept: text/turtle)"
ROOT_TTL="$(curl -fsS -H 'Accept: text/turtle' "$BASE_URL/fairdp")"
echo "$ROOT_TTL" | grep -qi 'ldp:contains\|http://www.w3.org/ns/ldp#contains' \
    || { echo "$ROOT_TTL"; fail "FDP root has no ldp:contains (no catalog reachable)"; }
# The dataset record must dereference and conform (carry a dct:identifier / type).
DS_TTL="$(curl -fsS -H 'Accept: text/turtle' "$BASE_URL/fairdp/dataset/$DATASET_ID")"
echo "$DS_TTL" | grep -qi "$DATASET_ID" \
    || { echo "$DS_TTL"; fail "FDP dataset record does not mention the dataset id"; }
log "FDP harvests: root -> catalog -> dataset reachable"

# --- 7. publish -> unpublish round-trip via the state sidecar -----------------
log "round-trip: unpublish (hidden) then re-publish (visible)"
echo '{"state":"hidden"}' > "$WORK/$DATASET_ID.state.json"
docker cp "$WORK/$DATASET_ID.state.json" "$CID:/var/lib/gdi-node-standalone/inbox/$DATASET_ID.state.json"
# Nudge a rescan (the watcher fires on the cp; allow it to settle), then poll.
deadline=$(( $(date +%s) + 60 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    [ "$(state_of || true)" = "hidden" ] && break
    sleep 2
done
[ "$(state_of || true)" = "hidden" ] || fail "dataset did not transition to hidden"
log "unpublished (hidden)"

echo '{"state":"visible"}' > "$WORK/$DATASET_ID.state.json"
docker cp "$WORK/$DATASET_ID.state.json" "$CID:/var/lib/gdi-node-standalone/inbox/$DATASET_ID.state.json"
deadline=$(( $(date +%s) + 60 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    [ "$(state_of || true)" = "visible" ] && break
    sleep 2
done
[ "$(state_of || true)" = "visible" ] || fail "dataset did not transition back to visible"
log "re-published (visible)"

# Physical deletion is implemented: reconcile_deleted -> delete_dataset
# (crates/gdi-node-standalone/src/ingest_runtime.rs) evicts the cache, purges the status
# entry and removes the dataset dir, covered by the inbox_deleted_tombstone and
# s3_reconcile integration tests. This smoke exercises the publish -> unpublish ->
# re-publish round-trip only; a delete leg could be added here.

# --- 8. Operator override survives a container restart -----------------------
# Step 7 exercised the source state, a sidecar the provider controls. This is the other
# authority: an operator withhold, which lives in the override store and must outlive the
# process. It is the only state a re-ingest cannot rebuild, and losing it presents as a
# clean success in which every withheld dataset is served again, which is why
# deploy/kubernetes/base/pvc.yaml gives the override store its own claim.
#
# Unit tests cover the store, and the compose stack defaults override_dir under data_dir, so
# it rides the `datasets` volume. Whether a withhold survives `compose restart` is wiring,
# and wiring is what this leg is for.
log "operator override: hiding $DATASET_ID via the CLI"
# `exec` bypasses the image ENTRYPOINT, so name the binary and config explicitly. The
# runtime image is distroless and has no shell, so this must be the binary, never `sh -c`.
compose exec -T gdi-node-standalone \
    /gdi-node-standalone --config /etc/gdi-node-standalone/node.toml \
    dataset hide "$DATASET_ID" --reason "e2e: operator override persistence check" \
    || fail "dataset hide failed"

deadline=$(( $(date +%s) + 60 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    [ "$(state_of || true)" = "hidden" ] && break
    sleep 2
done
# Assert positively: `!= "visible"` would also pass on an empty or failed `state_of`, that
# is on a node that had stopped answering, which cannot tell "withheld" from "broken".
[ "$(state_of || true)" = "hidden" ] || fail "operator hide did not withhold the dataset (state: $(state_of || true))"
log "withheld by operator override (state: $(state_of || true))"

# The disclosure property, not just the status field: the Beacon must stop answering.
HIDDEN_RESP="$(curl -fsS -X POST "$BASE_URL$AGG_BASE_PATH/g_variants" \
    -H 'content-type: application/json' -d "$QUERY" || true)"
# Check the envelope first: `curl ... || true` makes HIDDEN_RESP empty on any failure, and
# an empty body trivially satisfies the "no frequencies" grep below, so a node that stopped
# serving would read as correct withholding.
echo "$HIDDEN_RESP" | grep -q '"beaconId"' \
    || { echo "$HIDDEN_RESP"; fail "no beacon envelope while hidden: the node stopped answering, so the withholding check would pass vacuously"; }
echo "$HIDDEN_RESP" | grep -q '"alleleCount":618' \
    && { echo "$HIDDEN_RESP"; fail "a withheld dataset still discloses its frequencies"; }
log "beacon withholds the frequencies while hidden"

log "restarting the container; the override must survive the process"
compose restart gdi-node-standalone >/dev/null \
    || fail "compose restart failed"
wait_http "$MGMT_URL/health/ready" 200 \
    || { compose logs gdi-node-standalone; fail "node never became ready after restart"; }

# The assertion. A lost override store looks like a healthy node here, because the dataset
# simply reappears, so this is the one check that tells them apart.
[ "$(state_of || true)" = "hidden" ] \
    || fail "the operator override did not survive the restart: $DATASET_ID is $(state_of || true), expected hidden"
AFTER_RESP="$(curl -fsS -X POST "$BASE_URL$AGG_BASE_PATH/g_variants" \
    -H 'content-type: application/json' -d "$QUERY" || true)"
echo "$AFTER_RESP" | grep -q '"beaconId"' \
    || { echo "$AFTER_RESP"; fail "no beacon envelope after the restart: the node stopped answering, so the withholding check would pass vacuously"; }
echo "$AFTER_RESP" | grep -q '"alleleCount":618' \
    && { echo "$AFTER_RESP"; fail "withheld dataset discloses again after a restart"; }
log "override survived the restart; still withheld"

# Lift it, so the run leaves the stack in the state step 7 left it in.
compose exec -T gdi-node-standalone \
    /gdi-node-standalone --config /etc/gdi-node-standalone/node.toml \
    dataset unhide "$DATASET_ID" --reason "e2e: restoring the state step 7 left" \
    || fail "dataset unhide failed"
deadline=$(( $(date +%s) + 60 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    [ "$(state_of || true)" = "visible" ] && break
    sleep 2
done
[ "$(state_of || true)" = "visible" ] || fail "lifting the override did not restore the dataset"
log "override lifted; dataset visible again"

log "PASS: lite end-to-end smoke (build -> inbox -> visible -> g_variants -> FDP -> round-trip -> operator override across restart)"
