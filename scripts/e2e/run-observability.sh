#!/usr/bin/env bash
# Observability pipeline smoke: a metric the node emits must reach Prometheus.
#
# Two guards cover the observability stack, and both are static text checks:
#   * scripts/check-dashboard-metrics.py proves every `gdi_*` series the dashboard charts
#     resolves to a literal in metrics.rs, and that every Loki panel selects on a label
#     Alloy is configured to emit.
#   * `ci-local.sh promtool` proves the alert rules and Prometheus config parse.
# Neither runs anything, so neither can tell whether the node serves /metrics in the Compose
# stack, whether Prometheus's scrape target resolves, or whether a sample ever lands. A
# scrape config pointing at the wrong port, a management listener bound to the wrong
# interface, or a renamed Compose service leaves both guards green and the dashboards
# permanently empty, and an empty panel is indistinguishable from a quiet node.
#
# Scope: node + Prometheus only, not the whole observability overlay (Loki, Tempo, Grafana,
# Alloy, Alertmanager, blackbox). This asserts the one link the static guards cannot, emit
# to scrape to queryable, without paying for six more images.
#
# Requirements: docker (+ compose v2), curl, ss (iproute2, for the busy-port preflight). No
# cargo, no fixture, no dataset: the node emits process/build metrics from boot, so this
# needs no ingest.
#
# Host ports (GDI_HOST_PORT_PUBLIC/GDI_HOST_PORT_MANAGEMENT/GDI_HOST_PORT_PROMETHEUS) and
# the compose project name (GDI_E2E_PROJECT_SUFFIX, appended) are overridable, so this leg
# can run beside a dev stack, or beside another e2e run, instead of racing it for the same
# port. See docs/deployment.md's "Overriding the dev-stack host ports" table.
#
# Run: ./scripts/e2e/run-observability.sh   (or `ci-local.sh e2e-observability`)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

COMPOSE="${COMPOSE:-docker compose}"
PROJECT="gdi-node-standalone-e2e-obs${GDI_E2E_PROJECT_SUFFIX:-}"
# The minimal stack plus the overlay, one of the two combinations the overlay's own header
# documents. Minimal rather than the full stack because this asserts the metrics pipeline,
# which needs no S3, no Vault and no secrets provisioning; pulling those in would make a
# metrics test depend on the crypto path it is not testing.
#
# The overlay rebuilds the node with FEATURES=full,otel and points OTLP at `alloy`, which
# this run does not start. Export is fire-and-forget, so a missing collector must not affect
# readiness; if it ever does, this leg fails.
COMPOSE_FILES=(-f docker-compose.minimal.yml -f docker-compose.observability.yml)
HOST_PORT_PUBLIC="${GDI_HOST_PORT_PUBLIC:-8080}"
HOST_PORT_MANAGEMENT="${GDI_HOST_PORT_MANAGEMENT:-9090}"
HOST_PORT_PROMETHEUS="${GDI_HOST_PORT_PROMETHEUS:-9089}"
export GDI_HOST_PORT_PUBLIC="$HOST_PORT_PUBLIC" GDI_HOST_PORT_MANAGEMENT="$HOST_PORT_MANAGEMENT" \
    GDI_HOST_PORT_PROMETHEUS="$HOST_PORT_PROMETHEUS"
# Host port for Prometheus, published on loopback by the overlay (container port 9090).
PROM_URL="${PROM_URL:-http://localhost:$HOST_PORT_PROMETHEUS}"
MGMT_URL="${MGMT_URL:-http://localhost:$HOST_PORT_MANAGEMENT}"
TIMEOUT_SECS="${TIMEOUT_SECS:-180}"

compose() { $COMPOSE -p "$PROJECT" "${COMPOSE_FILES[@]}" "$@"; }

log()  { echo "[obs] $*"; }
fail() { echo "[obs] FAIL: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 \
    || fail "docker not found on PATH: this smoke needs Docker with Compose v2"
command -v curl >/dev/null 2>&1 || fail "curl not found on PATH"
$COMPOSE version >/dev/null 2>&1 \
    || fail "'$COMPOSE' is not usable: this smoke needs Docker Compose v2, set \$COMPOSE to a working command"

# Preflight: the host ports this project's compose combination publishes. Those are the node
# (docker-compose.minimal.yml) and the overlay's own Prometheus (docker-compose.
# observability.yml, host GDI_HOST_PORT_PROMETHEUS to container :9090). They are the same
# variables as above, so this checks what `compose up` is about to bind, which `compose up`
# itself does not check. It runs before `trap cleanup EXIT` below, so a preflight failure
# does not also print "tearing down" for a stack that never started.
E2E_PORTS=("$HOST_PORT_PUBLIC" "$HOST_PORT_MANAGEMENT" "$HOST_PORT_PROMETHEUS")
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
    if [ "$rc" -ne 0 ]; then
        log "failed with exit $rc; dumping logs before teardown"
        compose logs --no-color --tail=120 >&2 2>/dev/null || true
    fi
    log "tearing down"
    compose down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Poll on the status code, never the body: `/health/live` returns 200 with an empty body
# (health.rs: `StatusCode::OK.into_response()`), so any body match, even `grep -q '.'`, can
# never succeed and the wait would only time out against a healthy node.
wait_http() {  # wait_http <url> <expected-status> <label>
    local url="$1" want="$2" label="$3"
    local deadline=$(( $(date +%s) + TIMEOUT_SECS ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        [ "$(curl -sS -o /dev/null -w '%{http_code}' "$url" 2>/dev/null)" = "$want" ] && return 0
        sleep 3
    done
    fail "$label never returned $want within ${TIMEOUT_SECS}s ($url)"
}

# --- 1. Bring up the node and Prometheus ---------------------------------------
# Naming both services keeps Loki/Tempo/Grafana/Alloy/Alertmanager out of the run;
# Compose still starts whatever they depend on.
# Provenance. docker-compose.minimal.yml's `build.args` read these from the environment,
# defaulting to empty, and without them the image reports git_sha "unknown".
# Assigned, then exported: `export X="$(cmd)"` returns export's status, not the command's,
# so the combined form ships an empty sha silently (SC2155). Under `set -e` the split form
# aborts the run instead.
GITHUB_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD)"
SOURCE_DATE_EPOCH="$(git -C "$REPO_ROOT" log -1 --format=%ct)"
export GITHUB_SHA SOURCE_DATE_EPOCH
log "bringing up gdi-node-standalone + prometheus (git_sha=${GITHUB_SHA:0:12})"
compose up -d --build gdi-node-standalone prometheus

log "waiting for the node to become live"
wait_http "$MGMT_URL/health/live" 200 "node liveness"

# --- 2. The node actually serves /metrics on the management plane ---------------
# First link in the chain, and the cheapest to get wrong: /metrics lives on the separate
# management listener, not on the public port.
log "asserting the node serves /metrics"
METRICS="$(curl -fsS "$MGMT_URL/metrics" || true)"
printf '%s' "$METRICS" | grep -q '^gdi_' \
    || { printf '%s\n' "${METRICS:0:400}"; fail "/metrics served no gdi_* series"; }
# Name one series concretely, so "served something" cannot pass for "served the node's
# metrics".
SERIES="$(printf '%s' "$METRICS" | grep -oE '^gdi_[a-z0-9_]+' | sort -u | head -n1)"
[ -n "$SERIES" ] || fail "could not extract a gdi_* series name from /metrics"
log "node exposes $(printf '%s' "$METRICS" | grep -cE '^gdi_[a-z0-9_]+' ) gdi_* sample lines (e.g. $SERIES)"

# --- 2b. Every alert rule keys on a metric the node actually exports ------------
# `check-dashboard-metrics.py` proves each alerted metric is declared in metrics.rs, and
# `promtool check rules` proves the PromQL parses. Neither can see whether a series is ever
# emitted, and a `> 0` alert over a never-emitted series is dead. This is the first check
# that looks at a real scrape.
#
# The sampler ticks every SAMPLE_INTERVAL (10s) and sleeps first, so a scrape taken before
# ~10s legitimately lacks a dozen gauges. Re-scrape here rather than reusing $METRICS from
# step 2, which is taken as soon as the node is live.
log "waiting for a sampler tick, then re-scraping for the alert-presence check"
sleep 12
ALERT_SCRAPE="$(mktemp)"
curl -fsS "$MGMT_URL/metrics" > "$ALERT_SCRAPE" || fail "could not re-scrape /metrics"

# This overlay boots a lite node (no S3, no Vault, no PME, see the header), so the subsystem
# series below are correctly absent. Each is named with its reason, and the check fails if
# any of them turns out to be present, so the list cannot rot into a silent hole.
python3 "$REPO_ROOT/scripts/check-alert-metric-presence.py" \
    --rules "$REPO_ROOT/compose/observability/rules/gdi-node-standalone.yml" \
    --scrape "$ALERT_SCRAPE" \
    --expect-absent 'gdi_s3_channel_orphaned=lite node: no S3 channel configured' \
    --expect-absent 'gdi_s3_deleted_sidecar_ignored_total=lite node: no S3 channel configured' \
    --expect-absent 'gdi_s3_download_errors_total=lite node: no S3 channel configured' \
    --expect-absent 'gdi_s3_poll_errors_total=lite node: no S3 channel configured' \
    --expect-absent 'gdi_s3_poll_last_success_timestamp_seconds=lite node: no S3 channel configured' \
    --expect-absent 'gdi_s3_removal_skipped_total=lite node: no S3 channel configured' \
    --expect-absent 'gdi_s3_status_writeback_disabled=lite node: no S3 channel configured' \
    --expect-absent 'gdi_vault_token_ttl_seconds=lite node: no Vault configured' \
    --expect-absent 'gdi_vault_token_file_age_seconds=lite node: no Vault configured' \
    --expect-absent 'gdi_pme_master_key_mismatch=lite node: PME not configured' \
    --expect-absent 'gdi_datasets_at_rest=lite node: PME-only series, PME not configured' \
    || fail "an alert rule keys on a metric the node never exports"
rm -f "$ALERT_SCRAPE"
log "every in-scope alerted metric is exported by the running node"

# --- 3. Prometheus is up and its scrape target resolves -------------------------
log "waiting for prometheus to be ready"
wait_http "$PROM_URL/-/ready" 200 "prometheus readiness"

# `up == 1` for the node's job is the pipeline assertion: the target resolved, the
# connection succeeded, and the scrape parsed. A misconfigured port or a renamed Compose
# service shows here as up==0 while every static guard stays green.
log "asserting prometheus scrapes job=gdi-node-standalone successfully"
deadline=$(( $(date +%s) + TIMEOUT_SECS ))
UP=""
while [ "$(date +%s)" -lt "$deadline" ]; do
    UP="$(curl -fsS --get "$PROM_URL/api/v1/query" \
        --data-urlencode 'query=up{job="gdi-node-standalone"}' 2>/dev/null || true)"
    printf '%s' "$UP" | grep -q '"value":\[[0-9.]*,"1"\]' && break
    sleep 3
done
printf '%s' "$UP" | grep -q '"value":\[[0-9.]*,"1"\]' || {
    printf '%s\n' "$UP"
    log "scrape targets as prometheus sees them:"
    curl -fsS "$PROM_URL/api/v1/targets" 2>/dev/null | head -c 1200 >&2 || true
    fail "prometheus is not successfully scraping job=gdi-node-standalone (up != 1)"
}
log "prometheus scrape target is up"

# --- 4. A gdi_* sample the node emitted is queryable in Prometheus ---------------
# The end of the chain. Step 2 proved the node emits it; this proves it survived the
# scrape and is retrievable by the same name the dashboard guard checks statically.
log "asserting $SERIES is queryable in prometheus"
deadline=$(( $(date +%s) + TIMEOUT_SECS ))
RESULT=""
while [ "$(date +%s)" -lt "$deadline" ]; do
    RESULT="$(curl -fsS --get "$PROM_URL/api/v1/query" \
        --data-urlencode "query=$SERIES" 2>/dev/null || true)"
    # A successful but empty result is the failure mode here, so require a sample.
    printf '%s' "$RESULT" | grep -q '"result":\[{' && break
    sleep 3
done
printf '%s' "$RESULT" | grep -q '"result":\[{' || {
    printf '%s\n' "$RESULT"
    fail "$SERIES is not queryable in prometheus: the query returned an empty result"
}
log "$SERIES is queryable; emit -> scrape -> store verified end to end"

log "PASS: observability pipeline (node /metrics -> prometheus scrape -> queryable)"
