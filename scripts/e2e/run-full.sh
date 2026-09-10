#!/usr/bin/env bash
# Compose-based end-to-end smoke test for the full stack.
#
# Brings up the full dev stack (service + Garage [default] / minio + OpenBao
# [default] / Vault), provisions the S3 creds + the Transit at-rest key via
# compose/setup.sh and mints the node crypt4gh identity into Vault via the
# gdi-node-standalone `identity init` subcommand, then:
#
#   1. build + pack the COVID fixture into an encrypted {id}.tar.c4gh with the tool
#      (recipient = the node's published recipient);
#   2. upload it to the S3 bucket with `gdi-dataset-tool upload`, then `publish`;
#   3. the service decrypts + ingests + PME-encrypts at rest, then publishes;
#   4. poll /datasets/{id}/state to visible;
#   5. the same Beacon g_variants query asserts the COVID frequencies, read back
#      through the PME decryption path, which proves at-rest encryption round-trips.
#
# Run with S3_BACKEND=minio to use minio instead of Garage (the default), and
# EXTRA_PROFILES="--profile vault" to use HashiCorp Vault instead of OpenBao.
#
# Host ports (GDI_HOST_PORT_PUBLIC/GDI_HOST_PORT_MANAGEMENT/GDI_HOST_PORT_OPENBAO/
# GDI_HOST_PORT_GARAGE/GDI_HOST_PORT_MINIO) and the compose project name
# (GDI_E2E_PROJECT_SUFFIX, appended) are overridable, so this leg can run beside a dev
# stack, or beside another e2e run, instead of racing it for the same port. See
# docs/deployment.md's "Overriding the dev-stack host ports" table.
#
# Requirements: docker (+ compose v2), cargo, jq, ss (iproute2, for the busy-port
# preflight).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

COMPOSE="${COMPOSE:-docker compose}"
COMPOSE_FILE="docker-compose.yml"
PROJECT="gdi-node-standalone-e2e-full${GDI_E2E_PROJECT_SUFFIX:-}"
HOST_PORT_PUBLIC="${GDI_HOST_PORT_PUBLIC:-8080}"
HOST_PORT_MANAGEMENT="${GDI_HOST_PORT_MANAGEMENT:-9090}"
HOST_PORT_OPENBAO="${GDI_HOST_PORT_OPENBAO:-8200}"
HOST_PORT_GARAGE="${GDI_HOST_PORT_GARAGE:-3900}"
HOST_PORT_GARAGE_ADMIN="${GDI_HOST_PORT_GARAGE_ADMIN:-3903}"
HOST_PORT_MINIO="${GDI_HOST_PORT_MINIO:-9000}"
HOST_PORT_MINIO_CONSOLE="${GDI_HOST_PORT_MINIO_CONSOLE:-9001}"
export GDI_HOST_PORT_PUBLIC="$HOST_PORT_PUBLIC" GDI_HOST_PORT_MANAGEMENT="$HOST_PORT_MANAGEMENT" \
    GDI_HOST_PORT_OPENBAO="$HOST_PORT_OPENBAO" GDI_HOST_PORT_GARAGE="$HOST_PORT_GARAGE" \
    GDI_HOST_PORT_GARAGE_ADMIN="$HOST_PORT_GARAGE_ADMIN" GDI_HOST_PORT_MINIO="$HOST_PORT_MINIO" \
    GDI_HOST_PORT_MINIO_CONSOLE="$HOST_PORT_MINIO_CONSOLE"
BASE_URL="${BASE_URL:-http://localhost:$HOST_PORT_PUBLIC}"
# Health/readiness/dataset-state live on the separate management listener
# (`[service].management_addr`, mapped by docker-compose.yml), not BASE_URL.
MGMT_URL="${MGMT_URL:-http://localhost:$HOST_PORT_MANAGEMENT}"
AGG_BASE_PATH="/beacon/v2"
TIMEOUT_SECS="${TIMEOUT_SECS:-180}"
S3_BACKEND="${S3_BACKEND:-garage}"
EXTRA_PROFILES="${EXTRA_PROFILES:-}"   # e.g. "--profile vault --profile minio"
# The well-known dev S3 credentials docker-compose.yml ships for Garage/minio. Defined
# once here, then reused by the tool config written below and by the GDI_TEST_* exports.
S3_DEV_KEY="GK0123456789abcdef01234567" # gitleaks:allow - documented dev credential
S3_DEV_SECRET="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" # gitleaks:allow - documented dev credential

compose() { $COMPOSE -p "$PROJECT" -f "$COMPOSE_FILE" $EXTRA_PROFILES "$@"; }
log()  { echo "[e2e-full] $*"; }
fail() { echo "[e2e-full] FAIL: $*" >&2; exit 1; }

# Preflight: this smoke builds images + boots a Compose stack, so fail fast (and
# actionably) if Docker or Compose v2 is missing rather than deep inside `compose up`.
command -v docker >/dev/null 2>&1 \
    || fail "docker not found on PATH: this smoke needs Docker with Compose v2"
$COMPOSE version >/dev/null 2>&1 \
    || fail "'$COMPOSE' is not usable: this smoke needs Docker Compose v2, set \$COMPOSE to a working command"

# Preflight: the host ports this project's compose combination publishes. Those are the
# node (docker-compose.yml), the secrets backend (OpenBao/Vault, loopback, default :8200)
# and the S3 backend with its admin/console port (Garage, default :3900 and :3903; minio,
# default :9000 and :9001, with S3_BACKEND=minio). They are the same GDI_HOST_PORT_*
# variables exported above, so this checks what `compose up` is about to bind, which
# `compose up` itself does not check. It runs before `trap cleanup EXIT` below, so a
# preflight failure does not also print "tearing down" for a stack that never started.
case "$S3_BACKEND" in
    minio) E2E_S3_PORTS=("$HOST_PORT_MINIO" "$HOST_PORT_MINIO_CONSOLE") ;;
    *)     E2E_S3_PORTS=("$HOST_PORT_GARAGE" "$HOST_PORT_GARAGE_ADMIN") ;;
esac
E2E_PORTS=("$HOST_PORT_PUBLIC" "$HOST_PORT_MANAGEMENT" "$HOST_PORT_OPENBAO" "${E2E_S3_PORTS[@]}")
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
    # On a non-zero exit, dump the stack's logs before teardown: the containers are gone
    # after `compose down`, so this is the only window in which failure paths that print no
    # logs inline can be diagnosed.
    if [ "$rc" -ne 0 ]; then
        log "failed with exit $rc; dumping compose logs before teardown"
        compose --profile garage --profile openbao --profile setup --profile minio --profile vault logs --no-color --tail=200 >&2 2>/dev/null || true
    fi
    log "tearing down the full stack"
    compose --profile garage --profile openbao --profile setup --profile minio --profile vault down -v --remove-orphans >/dev/null 2>&1 || true
    [ -n "${WORK:-}" ] && rm -rf "$WORK" || true
}
trap cleanup EXIT

WORK="$(mktemp -d)"

# The node runs against a copy of the shipped config, which this harness owns and rewrites
# in step 9b to exercise the SIGHUP bucket reload. Editing `compose/node.full.toml` in place
# would mutate a tracked file, and would leave it mutated if the run died between the edit
# and the restore.
# SOURCE: docker-compose.yml's ${GDI_NODE_CONFIG:-…} mount, whose default is that file.
NODE_CONFIG="$WORK/node.toml"
cp "$REPO_ROOT/compose/node.full.toml" "$NODE_CONFIG"
export GDI_NODE_CONFIG="$NODE_CONFIG"

# --- 1. Bring up the backends first (build the image too) ----------------------
# A missing required Vault secret is a permanent startup error: the node refuses to serve
# with half-configured secrets. So Vault has to be provisioned before the service starts.
# Bring up the secrets + S3 backends (and build the service image), then provision, then
# start the service. The service container restarts on failure in the meantime, which is
# expected and harmless.
# Backend selection. Naming a profiled service in `up` activates it regardless of
# COMPOSE_PROFILES; the `<backend>-setup` sidecar bootstraps the bucket/key. minio
# reuses node.full.toml with its S3 endpoint/region overridden via the
# GDI_NODE__S3__BUCKETS__0__ env overlay, plus its profile active.
case "$S3_BACKEND" in
    minio)
        BACKEND_SVCS="minio minio-setup"
        export GDI_S3_ENDPOINT="http://minio:9000" GDI_S3_REGION="us-east-1"
        EXTRA_PROFILES="$EXTRA_PROFILES --profile minio"
        ;;
    *)
        BACKEND_SVCS="garage garage-setup"
        ;;
esac
# Provenance. docker-compose.yml's `build.args` for gdi-node-standalone read these from
# the environment, defaulting to empty, and without them the image reports git_sha
# "unknown".
# Assigned, then exported: `export X="$(cmd)"` returns export's status, not the command's,
# so the combined form ships an empty sha silently (SC2155). Under `set -e` the split form
# aborts the run instead.
GITHUB_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD)"
SOURCE_DATE_EPOCH="$(git -C "$REPO_ROOT" log -1 --format=%ct)"
export GITHUB_SHA SOURCE_DATE_EPOCH
log "bringing up the backends (S3_BACKEND=$S3_BACKEND $EXTRA_PROFILES; git_sha=${GITHUB_SHA:0:12})"
# $BACKEND_SVCS intentionally word-splits into the two backend service names.
compose up -d --build openbao $BACKEND_SVCS
# Build the service image without starting it.
compose build gdi-node-standalone

# --- 2. Provision S3 creds + Transit key (before the service starts) -----------
# Initialize and unseal the secrets backend before anything writes to it: a healthy backend
# is not enough, it must also be initialized and hold `dev-root-token` before the node
# authenticates against it. Nothing else pulls this in, because `up -d openbao` starts only
# openbao's own dependencies and the `setup` service declares no depends_on.
# `secrets-init` carries the openbao/vault profile, which $EXTRA_PROFILES already selects.
log "initializing + unsealing the secrets backend (secrets-init)"
compose --profile openbao run --rm secrets-init || fail "secrets-init failed"

log "running the dev setup script (S3 creds + Transit key)"
compose --profile setup run --rm \
    -e S3_BACKEND="$S3_BACKEND" \
    setup || fail "setup script failed"

# --- 2b. Mint the node crypt4gh identity straight into Vault (in memory) -------
# The service binary mints the keypair and writes it to Vault KV directly, never to disk.
# --ensure makes a re-run a no-op rather than an error.
log "minting the node crypt4gh identity into Vault (identity init)"
compose run --rm gdi-node-standalone identity init --ensure || fail "identity init failed"

# --- 3. Start the service; it now loads its identity + Transit key from Vault ---
log "starting the service (loads identity + PME Transit key from Vault)"
compose up -d gdi-node-standalone

log "waiting for the service to come live with the provisioned secrets"
deadline=$(( $(date +%s) + TIMEOUT_SECS ))
until curl -fsS -o /dev/null "$MGMT_URL/health/live" 2>/dev/null; do
    [ "$(date +%s)" -lt "$deadline" ] || { compose logs gdi-node-standalone; fail "service never came live"; }
    sleep 3
done

# Confirm from the logs that the PME wiring is active, meaning the at-rest Transit key is
# in use. The two needles below gate the smoke, so each names the `tracing` call that emits
# it: a log-message rename then trips here against a source pointer rather than as a bare
# failure.
# SOURCE: crates/gdi-node-standalone/src/bootstrap.rs (tracing::info! "PME active: parquet payload encrypted at rest ...")
PME_ACTIVE_LOG="PME active"
# SOURCE: crates/gdi-node-standalone/src/identities.rs (tracing::info! "loaded crypt4gh node identities from Vault")
IDENTITY_LOADED_LOG="loaded crypt4gh node identities from Vault"
# Retry rather than grep once: `/health/live` answering does not mean `docker compose logs`
# has caught up. "PME active" is emitted during bootstrap, before the listener binds, so a
# single grep can run against a log stream the daemon has not flushed yet.
#
# Capture, then match from a here-string, never `compose logs … | grep -q`. Under the
# `set -o pipefail` this script runs with, `grep -q` exits at the first match, the compose
# CLI dies of SIGPIPE writing the rest, the pipeline reports 141, and a needle that is in
# the log reads as absent. scripts/tests/test_run_full_wait_log.py runs this function
# against a 5 MB log with the needle on its first line.
#
# Stdout only (no `2>&1`): a `docker compose` warning on stderr must not masquerade as the
# needle or obscure it. Real stderr still reaches the terminal; it is just not compared.
wait_log() {  # wait_log <needle> <what>
    local needle="$1" what="$2" logs
    local deadline=$(( $(date +%s) + 60 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        logs="$(compose logs gdi-node-standalone)" || true
        if grep -qF -- "$needle" <<<"$logs"; then return 0; fi
        sleep 2
    done
    # `|| true`: without it, a failing `compose logs` (torn-down project, dead dockerd)
    # aborts the script under `set -e` before the `fail` line that names the cause.
    compose logs gdi-node-standalone 2>&1 | tail -40 || true
    fail "$what"
}
wait_log "$PME_ACTIVE_LOG" "service did not report PME active: the Transit key wiring is broken"
log "confirmed: PME at-rest active (Vault-minted DEK via Transit)"
wait_log "$IDENTITY_LOADED_LOG" "service did not report loading its crypt4gh identity from Vault"
log "confirmed: node crypt4gh identity loaded from Vault"

log "full stack is up with secrets provisioned (PME at-rest key active)"

# --- 4. Build the tool + a profile pointing at the live stack (host ports) ------
log "building gdi-dataset-tool"
cargo build --quiet --locked -p gdi-dataset-tool || fail "tool build failed"
TOOL="$REPO_ROOT/target/debug/gdi-dataset-tool"
case "$S3_BACKEND" in
    minio) S3_ENDPOINT="http://localhost:$HOST_PORT_MINIO"; S3_REGION="us-east-1" ;;
    *)     S3_ENDPOINT="http://localhost:$HOST_PORT_GARAGE"; S3_REGION="garage" ;;
esac
CFG="$WORK/tool.toml"
# The tool's config dir, isolated to this run. Without it the harness would read the
# developer's real ~/.config/gdi, where `package` pins the node's published recipient at
# `recipients/localhost_<port>.<hash>.pub` on first fetch. Every run of this harness mints a
# fresh node identity into a fresh OpenBao, so a later run would fetch a key that differs
# from that pin and `package` would fail closed, since a changed recipient is
# indistinguishable from a MITM. Only `keys pin-recipient --force` replaces such a pin;
# `package --force` overwrites the output file alone.
export GDI_CONFIG_DIR="$WORK/gdi-config"
# No `[tool]` section: `default_profile` is a root-level key, root-level keys must appear
# before any `[section]` header, and the loader rejects unknown keys outright (see
# docs/gdi-dataset-tool.md).
#
# The `prefix` must equal the node's: writer and reader address one keyspace, and a prefix
# on one side only is a silent desync where upload writes what the node never lists. It is
# read from the node's own config rather than restated here, so the two cannot drift.
# Scoped to the first [[s3.buckets]] block rather than the first `prefix =` line anywhere,
# since a `prefix` key in an earlier section would otherwise win.
S3_PREFIX="$(awk '/^\[\[s3\.buckets\]\]/{inblk=1; next} /^\[/{inblk=0} inblk && /^prefix = /{gsub(/^prefix = "|"$/, ""); print; exit}' compose/node.full.toml)"
[ -n "$S3_PREFIX" ] || fail "compose/node.full.toml declares no [[s3.buckets]].prefix: \
this harness derives the tool profile's prefix from it, and step 8b asserts the confinement"
# `e2e_root` is the same bucket with no prefix. It makes the prefix falsifiable: a prefix
# that did nothing would leave every assertion below green, and step 8b uses this profile to
# tell those apart.
cat > "$CFG" <<EOF
default_profile = "e2e"
[profiles.e2e]
service_url = "$BASE_URL"
management_url = "$MGMT_URL"
[profiles.e2e.s3]
endpoint = "$S3_ENDPOINT"
region = "$S3_REGION"
bucket = "gdi-datasets"
prefix = "$S3_PREFIX"
path_style = true
allow_http = true
access_key_id = "$S3_DEV_KEY"
secret_access_key = "$S3_DEV_SECRET"
[profiles.e2e_root]
service_url = "$BASE_URL"
management_url = "$MGMT_URL"
[profiles.e2e_root.s3]
endpoint = "$S3_ENDPOINT"
region = "$S3_REGION"
bucket = "gdi-datasets"
path_style = true
allow_http = true
access_key_id = "$S3_DEV_KEY"
secret_access_key = "$S3_DEV_SECRET"
EOF

# --- 5. The node must be S3-ready before it can ingest from the bucket ----------
log "waiting for the node to become S3-ready"
deadline=$(( $(date +%s) + TIMEOUT_SECS ))
until curl -fsS -o /dev/null "$MGMT_URL/health/ready" 2>/dev/null; do
    [ "$(date +%s)" -lt "$deadline" ] || { compose logs gdi-node-standalone; fail "node never became S3-ready"; }
    sleep 3
done

# --- 6. Build + pack the COVID fixture, encrypted to the node's published recipient
# (auto-fetched from {service_url}/.well-known/c4gh-recipient via the profile). The
# `package` default output is {datasetId}.tar.c4gh in the cwd, so run it in $WORK.
log "packaging the COVID fixture (encrypted to the node recipient)"
PKG_DIR="$WORK/pkg"; mkdir -p "$PKG_DIR"
( cd "$PKG_DIR" && "$TOOL" --config "$CFG" package \
    "$REPO_ROOT/crates/gdi-dataset-tool/tests/fixtures/covid-package.yaml" \
    --cc EE --force ) || fail "package (build+pack) failed"
PKG="$(find "$PKG_DIR" -name '*.tar.c4gh' | head -n1)"
[ -n "$PKG" ] || fail "no .tar.c4gh produced"
DATASET_ID="$(basename "$PKG" .tar.c4gh)"
log "packed $DATASET_ID"

# --- 7. Upload to S3 + publish; the node decrypts -> ingests -> PME-encrypts ----
log "uploading + publishing $DATASET_ID"
"$TOOL" --config "$CFG" upload "$PKG" || fail "upload failed"
"$TOOL" --config "$CFG" publish "$DATASET_ID" || fail "publish failed"

# --- 8. Poll the dataset state to visible --------------------------------------
log "waiting for $DATASET_ID to reach visible (decrypt -> ingest -> PME-encrypt -> publish)"
deadline=$(( $(date +%s) + TIMEOUT_SECS ))
until curl -fsS "$MGMT_URL/datasets/$DATASET_ID/state" 2>/dev/null | grep -q '"state":"visible"'; do
    [ "$(date +%s)" -lt "$deadline" ] || { compose logs gdi-node-standalone; fail "$DATASET_ID never became visible"; }
    sleep 3
done
log "visible (ingested + PME-encrypted at rest)"

# --- 8b. The channel really is confined to the bucket prefix --------------------
# Everything above ran through the prefix, since both the node config and the tool profile
# carry it, so reaching `visible` proves writer and reader agree on the keyspace. It does
# not prove the prefix does anything: an ignored `prefix` key would produce the same green
# run.
#
# Listing the bucket root tells those apart. `list` prints "{id}\t{visibility}" per dataset,
# so the id is an exact field rather than a substring: the root listing must not report this
# dataset, while the prefixed listing must.
log "asserting the channel is confined to the '$S3_PREFIX' prefix"
listed_ids() {  # listed_ids <profile>
    "$TOOL" --config "$CFG" --profile "$1" list 2>/dev/null | cut -f1
}
# Captured, then matched from a here-string: `… | grep -q` would let grep exit on the first
# match, SIGPIPE the tool, and fail the pipeline under `pipefail`, which is a false failure
# on the path that is working.
PREFIXED_IDS="$(listed_ids e2e)" || fail "listing the prefixed channel failed"
ROOT_IDS="$(listed_ids e2e_root)" || fail "listing the bucket root failed"
grep -qxF "$DATASET_ID" <<<"$PREFIXED_IDS" \
    || fail "the prefixed listing does not report $DATASET_ID: writer and reader disagree \
on the prefix, yet the node served it"
# `if`, not `&&`: a trailing `A && fail …` whose A correctly finds nothing returns 1 as
# the last command of the script's flow, and `set -e` would abort the run as a failure.
if grep -qxF "$DATASET_ID" <<<"$ROOT_IDS"; then
    fail "$DATASET_ID is listed at the bucket root: the prefix was not applied to the \
uploaded objects"
fi
log "confirmed: the package lives under $S3_PREFIX and the bucket root reports nothing"

# --- 9. Beacon g_variants reads back through the PME decryption path ------------
# The COVID fixture's real numbers (chr3:45823240 T>C, Total AC=618, AN=8000) must come
# back through the at-rest decryption, which proves the PME round-trip.
log "querying g_variants for the COVID chr3:45823240 T>C site"
QUERY='{"query":{"requestParameters":{"referenceName":"3","start":[45823239],"referenceBases":"T","alternateBases":"C","assemblyId":"GRCh38","requestedGranularity":"RECORD"}}}'
RESP="$(curl -fsS -X POST "$BASE_URL$AGG_BASE_PATH/g_variants" \
    -H 'content-type: application/json' -d "$QUERY")" || fail "g_variants query failed"
echo "$RESP" | grep -q '"frequencyInPopulations"' \
    || { echo "$RESP"; fail "response has no frequencyInPopulations"; }
echo "$RESP" | grep -q '"alleleCount":618' \
    || { echo "$RESP"; fail "expected Total alleleCount 618 not found"; }
echo "$RESP" | grep -q '"alleleNumber":8000' \
    || { echo "$RESP"; fail "expected Total alleleNumber 8000 not found"; }
log "g_variants frequencies asserted (Total AC=618 AN=8000), read back through PME"

# --- 9b. Add, modify and remove a bucket by SIGHUP, with no restart -------------
# The three cases are not symmetric: add and modify apply live, remove only warns. Each is
# asserted by an observable effect rather than by the log line alone, because a log line
# proves the code ran and not that the monitor did anything.
RELOAD_BUCKET="gdi-reloaded"
RELOAD_CHANNEL="reloaded"
log "provisioning $RELOAD_BUCKET for the SIGHUP bucket-reload smoke"
( export S3_BUCKET="$RELOAD_BUCKET"; compose run --rm "${S3_BACKEND}-setup" ) \
    || fail "could not provision the $RELOAD_BUCKET bucket"

# The node reads its config from a mount; the endpoint here is the IN-COMPOSE one.
case "$S3_BACKEND" in
    minio) NODE_S3_ENDPOINT="http://minio:9000"; NODE_S3_REGION="us-east-1" ;;
    *)     NODE_S3_ENDPOINT="http://garage:3900"; NODE_S3_REGION="garage" ;;
esac
append_reload_bucket() {  # append_reload_bucket <secret>
    cat >> "$NODE_CONFIG" <<EOF

[[s3.buckets]]
name = "$RELOAD_CHANNEL"
endpoint = "$NODE_S3_ENDPOINT"
bucket = "$RELOAD_BUCKET"
region = "$NODE_S3_REGION"
access_key_id = "$S3_DEV_KEY"
secret_access_key = "$1"
path_style = true
allow_http = true
marker_poll_interval = 15
full_poll_interval = 60
EOF
}
# Truncate back to the config as booted, so each case starts from a known file.
reset_node_config() { cp "$REPO_ROOT/compose/node.full.toml" "$NODE_CONFIG"; }

# Apply a `sed` expression to $NODE_CONFIG, preserving its inode.
#
# docker-compose bind-mounts this file, not its directory, at
# /etc/gdi-node-standalone/node.toml, and Docker resolves a file mount to the host inode
# when the container starts. `sed -i` writes a temp file and renames it over the target, so
# the host path gets a new inode and the container keeps reading the original one until it
# restarts. A leg that edits and then reloads would see the node re-read pre-edit bytes and
# report them as applied. Redirecting over the path truncates and rewrites the same inode,
# which the mount does follow.
edit_node_config() {  # edit_node_config <sed-expression>
    local tmp="$WORK/node.toml.edit"
    sed "$1" "$NODE_CONFIG" > "$tmp" || fail "editing $NODE_CONFIG failed: $1"
    cat "$tmp" > "$NODE_CONFIG" || fail "rewriting $NODE_CONFIG failed"
    rm -f "$tmp"
}

# `kill -s` targets PID 1 in the container, so no exec into the container is needed.
# SIGUSR1 afterwards wakes every monitor, so the assertion lands on the next poll instead of
# waiting out marker_poll_interval.
sighup() { compose kill -s SIGHUP gdi-node-standalone >/dev/null 2>&1 || fail "SIGHUP failed"; }
sigusr1() { compose kill -s SIGUSR1 gdi-node-standalone >/dev/null 2>&1 || fail "SIGUSR1 failed"; }

# Poll the readiness document for one bucket's health. A bucket that is down does not 503
# the node; it reports ready and degraded, so the per-bucket value is the signal.
bucket_health() {  # bucket_health <channel>
    curl -fsS "$MGMT_URL/health/ready" 2>/dev/null \
        | jq -r --arg c "$1" '.subsystems.s3_buckets[$c] // "absent"'
}
await_bucket_health() {  # await_bucket_health <channel> <want> <what>
    local deadline=$(( $(date +%s) + 90 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        [ "$(bucket_health "$1")" = "$2" ] && return 0
        sigusr1
        sleep 3
    done
    curl -fsS "$MGMT_URL/health/ready" | jq . >&2 || true
    compose logs --tail=60 gdi-node-standalone >&2
    fail "$3"
}

# Add: a channel that did not exist at boot must come up and reach ok.
log "adding a [[s3.buckets]] entry and reloading with SIGHUP"
append_reload_bucket "$S3_DEV_SECRET"
sighup
wait_log "config reload added this bucket" "SIGHUP did not report adding the new bucket"
await_bucket_health "$RELOAD_CHANNEL" "ok" \
    "the bucket added by SIGHUP never became healthy: the reload did not start its monitor"
log "confirmed: a bucket added by SIGHUP polls without a restart"

# Modify: rewrite the same entry with a wrong secret. The channel going unhealthy is what
# proves the monitor restarted with the new credential, which is the rotated-credential
# case. A monitor that kept running would stay ok on its boot-time client, and a log line
# alone cannot tell those apart.
log "rotating that bucket's credential to a bad one and reloading"
reset_node_config
append_reload_bucket "0000000000000000000000000000000000000000000000000000000000000000"
sighup
wait_log "restarting its monitor" "SIGHUP did not report restarting the modified bucket"
await_bucket_health "$RELOAD_CHANNEL" "unavailable" \
    "the bucket stayed healthy after its credential changed: the monitor kept its old \
client, so a rotated credential would never take effect"
log "confirmed: a modified bucket restarts its monitor with the new credential"

# Remove: warns and changes nothing. The dataset served from the original bucket must
# still be visible afterwards: removal must not evict, and must not disturb another
# channel.
log "removing the entry and reloading (must warn, not evict)"
reset_node_config
sighup
wait_log "bucket removal is restart-only" "SIGHUP did not warn about the removed bucket"
curl -fsS "$MGMT_URL/datasets/$DATASET_ID/state" 2>/dev/null | grep -q '"state":"visible"' \
    || fail "$DATASET_ID stopped being visible after a bucket-removal reload: removal must \
change nothing until a restart"
log "confirmed: removal warns, evicts nothing, and leaves other channels serving"

# Identity change: re-pointing a channel's keyspace is restart-only, like removal. Changing
# `prefix`, `bucket` or `endpoint` live on a channel that owns datasets would retire its
# monitor and start the replacement against a keyspace that legitimately lists nothing,
# which the reconcile cannot tell from "the provider deleted everything". It would evict
# every dataset the channel owns and delete it from data_dir while /health/ready still
# reported the channel `ok`.
#
# Run against the primary channel, the only one here that owns a dataset. The earlier cases
# run against `reloaded`, which owns none, so none of them can catch this.
log "re-pointing the primary channel's prefix (must be refused as restart-only)"
reset_node_config
edit_node_config "s|^prefix = \"$S3_PREFIX\"|prefix = \"gdi-node-storage-moved/\"|"
grep -q '^prefix = "gdi-node-storage-moved/"' "$NODE_CONFIG" \
    || fail "could not re-point the primary prefix in $NODE_CONFIG"
sighup
# The log line is the deterministic half: a build that applies the re-point live says
# "restarting its monitor" here instead, immediately and every time.
wait_log "restart-only: applying it live would" \
    "SIGHUP did not refuse the keyspace re-point as restart-only: the monitor was re-pointed"
# ...and the property: force a poll and the dataset must still be served.
sigusr1
sleep 5
curl -fsS "$MGMT_URL/datasets/$DATASET_ID/state" 2>/dev/null | grep -q '"state":"visible"' \
    || fail "$DATASET_ID stopped being visible after its channel's prefix was changed: the \
keyspace re-point was applied live and evicted the channel's datasets"
log "confirmed: a keyspace re-point is refused, and no dataset is evicted"
reset_node_config
sighup

# Vault-credentialled add: a bucket whose credential lives only in Vault must come up on a
# reload, without a restart. `[vault].s3_path` is read at boot, keyed by the buckets the
# boot config declared, so a reload that did not re-read it would leave a bucket added later
# with no credential: it would fall back to inline keys the deployment forbids and, with
# none, build an anonymous client that 403s forever while the node sits `degraded`.
#
# This is the one leg with a real secret store behind it, because no in-process test can
# reach a Vault.
log "writing the reloaded channel's credential into Vault only"
VAULT_ADDR_HOST="http://localhost:$HOST_PORT_OPENBAO"
VAULT_TOKEN_E2E="${VAULT_TOKEN:-dev-root-token}"
# The KV v2 API path is <mount>/data/<path>. The mount is `secret` and the path is
# `gdi-node-standalone/s3-credentials`, read from compose/setup.sh's KV_MOUNT/S3_PATH, which
# is what wrote this secret. The node's `[vault].s3_path` names only the path half, so
# composing the URL from it alone addresses a mount that does not exist.
VAULT_KV_URL="$VAULT_ADDR_HOST/v1/${KV_MOUNT:-secret}/data/${S3_PATH:-gdi-node-standalone/s3-credentials}"
# Read-merge-write rather than PATCH: `primary`'s credentials must survive, and a plain POST
# of the merged object works on any KV v2 without depending on patch support or capability.
existing="$(curl -fsS -H "X-Vault-Token: $VAULT_TOKEN_E2E" "$VAULT_KV_URL")" \
    || fail "could not read the existing S3 credentials from Vault at $VAULT_KV_URL"
merged="$(echo "$existing" | jq -c \
    --arg k "${RELOAD_CHANNEL}_access_key_id" --arg kv "$S3_DEV_KEY" \
    --arg s "${RELOAD_CHANNEL}_secret_access_key" --arg sv "$S3_DEV_SECRET" \
    '{data: (.data.data + {($k): $kv, ($s): $sv})}')" \
    || fail "could not merge the $RELOAD_CHANNEL credential into the existing secret"
curl -fsS -X POST \
    -H "X-Vault-Token: $VAULT_TOKEN_E2E" \
    -H "Content-Type: application/json" \
    -d "$merged" "$VAULT_KV_URL" >/dev/null \
    || fail "could not write the $RELOAD_CHANNEL credential into Vault"

# The entry carries no inline credentials: Vault is the only source.
reset_node_config
cat >> "$NODE_CONFIG" <<EOF

[[s3.buckets]]
name = "$RELOAD_CHANNEL"
endpoint = "$NODE_S3_ENDPOINT"
bucket = "$RELOAD_BUCKET"
region = "$NODE_S3_REGION"
path_style = true
allow_http = true
marker_poll_interval = 15
full_poll_interval = 60
EOF
sighup
wait_log "re-read the per-bucket S3 credentials" \
    "the reload did not re-read [vault].s3_path: a Vault-credentialled add cannot work"
await_bucket_health "$RELOAD_CHANNEL" "ok" \
    "the Vault-credentialled bucket added by SIGHUP never became healthy: its credential \
was not read from Vault, so the channel was refused or polled anonymously"
log "confirmed: a bucket credentialled only in Vault onboards without a restart"
reset_node_config
sighup

# --- 9c. The management plane honours an inbound x-request-id -----------------
# Both planes are asserted together, because the difference between them is the property:
# an assertion that the management plane echoes would still pass if the public plane began
# echoing too, and an unauthenticated caller choosing the correlation id on every audit line
# is the failure that matters.
CALLER_ID="e2e-$(date +%s)-correlation"
log "asserting the management plane echoes x-request-id and the public plane does not"
for path in "/version" "/datasets/$DATASET_ID/state"; do
    echoed="$(curl -fsS -D - -o /dev/null -H "x-request-id: $CALLER_ID" "$MGMT_URL$path" \
        | tr -d '\r' | awk 'tolower($1) == "x-request-id:" { print $2 }')"
    [ "$echoed" = "$CALLER_ID" ] \
        || fail "management $path returned x-request-id '$echoed', expected the caller's \
'$CALLER_ID': an orchestrator cannot correlate across the boundary"
done
# The public plane must mint instead: a non-empty id that is not the one sent.
public_id="$(curl -fsS -D - -o /dev/null -H "x-request-id: $CALLER_ID" \
    "$BASE_URL$AGG_BASE_PATH/service-info" | tr -d '\r' \
    | awk 'tolower($1) == "x-request-id:" { print $2 }')"
[ -n "$public_id" ] || fail "the public plane returned no x-request-id at all"
[ "$public_id" != "$CALLER_ID" ] \
    || fail "the public plane echoed a caller-supplied x-request-id: an unauthenticated \
caller would then choose the correlation id on every audit line and error body"
log "confirmed: management echoes the caller's id, public mints its own"

# --- 9d. GET /datasets, opt-in ------------------------------------------------
# The flag is off in the shipped config, so the route must be absent now. Asserting that
# first is what makes the second half meaningful: turning a flag on and seeing a 200 proves
# nothing if the route was there all along.
log "asserting GET /datasets is absent while the flag is off"
off_status="$(curl -s -o /dev/null -w '%{http_code}' "$MGMT_URL/datasets")"
[ "$off_status" = "404" ] \
    || fail "GET /datasets answered $off_status with expose_dataset_list unset; it must be \
absent (404), which is indistinguishable from a node too old to serve it"

log "enabling expose_dataset_list and restarting the node"
# Inserted into the existing [service] table: a second `[service]` header would be a
# duplicate-table TOML error, not an override.
edit_node_config '/^\[service\]/a expose_dataset_list = true'
grep -q '^expose_dataset_list = true' "$NODE_CONFIG" \
    || fail "could not enable expose_dataset_list in $NODE_CONFIG"
# A restart, not a SIGHUP: the flag decides whether a route is mounted, which happens once
# at router-build time. The reloadable subset is narrow, covering the buckets of step 9b and
# nothing else, so a restart is the way to exercise this.
compose restart gdi-node-standalone >/dev/null 2>&1 || fail "could not restart the node"
deadline=$(( $(date +%s) + TIMEOUT_SECS ))
until curl -fsS -o /dev/null "$MGMT_URL/health/live" 2>/dev/null; do
    [ "$(date +%s)" -lt "$deadline" ] || { compose logs --tail=40 gdi-node-standalone; fail "the node did not come back after enabling expose_dataset_list"; }
    sleep 2
done

listing="$(curl -fsS "$MGMT_URL/datasets")" \
    || fail "GET /datasets failed with expose_dataset_list = true"
echo "$listing" | jq -e --arg id "$DATASET_ID" 'any(.[]; .id == $id and .state == "visible")' >/dev/null \
    || { echo "$listing"; fail "GET /datasets did not report $DATASET_ID as visible"; }
# The route and the CLI must render the same rows. `dataset list --format json` runs inside
# the container and reads the node's data_dir, so this compares both surfaces against one
# node's real state.
# Absolute path: the runtime image is distroless with the binary at the filesystem root, and
# `compose exec` runs its argv directly, so it uses neither the ENTRYPOINT nor a PATH entry
# that would resolve a bare name.
# SOURCE: Dockerfile's `ENTRYPOINT ["/gdi-node-standalone"]`
# Stdout only (no `2>&1`): the capture is fed straight to `jq -S .` below, and any stderr
# line merged into it would break the byte comparison against the route's JSON. Real stderr
# still reaches the terminal; it is just not compared.
cli_listing="$(compose exec -T gdi-node-standalone \
    /gdi-node-standalone dataset list --format json)" \
    || fail "the in-container dataset list CLI failed"
[ "$(echo "$listing" | jq -S .)" = "$(echo "$cli_listing" | jq -S .)" ] \
    || { echo "route: $listing"; echo "cli: $cli_listing"; \
         fail "GET /datasets and 'dataset list --format json' disagree: they must render \
the same rows from the same collector"; }
log "confirmed: absent while off, serves the inventory when on, and agrees with the CLI"

# --- 9e. GET /stats/queries, opt-in --------------------------------------------
# Same off-first shape as step 9d, for the same reason. What this leg adds beyond the unit
# and integration suites is the part only a real process can show: `startedAt` survives a
# SIGHUP and does not survive a restart. A collector's delta algorithm treats a changed
# `startedAt` as "counters restarted from zero", so a node that reset its counters on a
# reload while keeping the stamp would silently lose traffic, and one that changed the stamp
# on a reload would make the next poll re-count everything as new.
log "asserting GET /stats/queries is absent while the flag is off"
stats_off_status="$(curl -s -o /dev/null -w '%{http_code}' "$MGMT_URL/stats/queries")"
[ "$stats_off_status" = "404" ] \
    || fail "GET /stats/queries answered $stats_off_status with [stats] unset; it must be \
absent (404), which is indistinguishable from a node too old to serve it"

log "enabling [stats] and restarting the node"
# Appended as a new table at the end of the file, which ends inside [vault]. A `[stats]`
# header closes whatever preceded it, so this needs no anchor the way an in-table key would.
printf '\n[stats]\nenabled = true\n' >> "$NODE_CONFIG"
compose restart gdi-node-standalone >/dev/null 2>&1 || fail "could not restart the node"
deadline=$(( $(date +%s) + TIMEOUT_SECS ))
until curl -fsS "$MGMT_URL/datasets/$DATASET_ID/state" 2>/dev/null | grep -q '"state":"visible"'; do
    [ "$(date +%s)" -lt "$deadline" ] || { compose logs --tail=40 gdi-node-standalone; fail "$DATASET_ID did not return to visible after enabling [stats]"; }
    sleep 2
done

# Fresh boot: the counters start empty, which is what makes the increments below evidence.
stats="$(curl -fsS "$MGMT_URL/stats/queries")" || fail "GET /stats/queries failed with [stats] enabled"
echo "$stats" | jq -e --arg id "$DATASET_ID" '.schemaVersion == 1 and (.datasets[$id] // null) == null' >/dev/null \
    || { echo "$stats"; fail "a just-restarted node must report no counters for $DATASET_ID"; }
BOOT_STAMP="$(echo "$stats" | jq -r .startedAt)"

# One of each counted source, through the PUBLIC plane.
curl -fsS -X POST "$BASE_URL$AGG_BASE_PATH/g_variants" -H 'content-type: application/json' \
    -d "$QUERY" >/dev/null || fail "the g_variants query for the stats leg failed"
curl -fsS "$BASE_URL$AGG_BASE_PATH/datasets" >/dev/null || fail "the /datasets listing for the stats leg failed"
curl -fsS -H 'accept: text/turtle' "$BASE_URL/fairdp/dataset/$DATASET_ID" >/dev/null \
    || fail "the FDP dataset read for the stats leg failed"

stats="$(curl -fsS "$MGMT_URL/stats/queries")" || fail "GET /stats/queries failed after the queries"
echo "$stats" | jq -e --arg id "$DATASET_ID" \
    '.datasets[$id] | .consulted == 1 and .hit == 1 and .listed == 1 and .fairdpReads == 1' >/dev/null \
    || { echo "$stats"; fail "the four counters did not each record exactly one event for \
$DATASET_ID (the query MATCHES this dataset, so consulted and hit must both be 1)"; }
log "counters recorded a Beacon query, a listing and an FDP read"

# A SIGHUP must leave both the boot identity and the accumulated counts alone. The `sleep`
# bounds the signal handler: the reload is asynchronous and this asserts that nothing
# changed, so there is no state transition to poll for. It cannot pass vacuously, because
# the restart case below asserts that the same stamp does change.
sighup
sleep 2
stats="$(curl -fsS "$MGMT_URL/stats/queries")" || fail "GET /stats/queries failed after SIGHUP"
[ "$(echo "$stats" | jq -r .startedAt)" = "$BOOT_STAMP" ] \
    || { echo "$stats"; fail "startedAt changed on SIGHUP: a reload is not a new boot epoch, \
and a poller reading it as one re-counts every dataset's whole history"; }
echo "$stats" | jq -e --arg id "$DATASET_ID" '.datasets[$id].consulted == 1' >/dev/null \
    || { echo "$stats"; fail "a SIGHUP reset the counters"; }

# A restart must do the opposite: new stamp, counters back to zero.
compose restart gdi-node-standalone >/dev/null 2>&1 || fail "could not restart the node"
deadline=$(( $(date +%s) + TIMEOUT_SECS ))
until curl -fsS -o /dev/null "$MGMT_URL/stats/queries" 2>/dev/null; do
    [ "$(date +%s)" -lt "$deadline" ] || { compose logs --tail=40 gdi-node-standalone; fail "the node did not come back after the stats restart"; }
    sleep 2
done
stats="$(curl -fsS "$MGMT_URL/stats/queries")" || fail "GET /stats/queries failed after the restart"
[ "$(echo "$stats" | jq -r .startedAt)" != "$BOOT_STAMP" ] \
    || { echo "$stats"; fail "startedAt survived a restart: the counters reset with the \
process, so a stamp that does not change hides the reset from every poller"; }
echo "$stats" | jq -e --arg id "$DATASET_ID" '(.datasets[$id] // null) == null' >/dev/null \
    || { echo "$stats"; fail "counters survived a restart, but they are in-memory only"; }
log "confirmed: absent while off, counts per dataset, stable across SIGHUP, reset across restart"

# --- 9f. POST /reload, opt-in --------------------------------------------------
# Asserted by an observable effect rather than by "the endpoint answered 200": a new catalog
# is in the SIGHUP-reloadable subset and the FDP serves `/fairdp/catalog/{id}` from that
# snapshot, so a 404 turning into a 200 with no restart is the reload being visible.
RELOAD_CATALOG="e2e-reload-check"
log "asserting POST /reload is absent while [control] is off"
reload_off_status="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$MGMT_URL/reload")"
[ "$reload_off_status" = "404" ] \
    || fail "POST /reload answered $reload_off_status with [control] unset; it must be absent (404)"

log "enabling [control] and restarting the node"
# A short window so the rate-limit assertion below does not stall the run; the default is 10.
printf '\n[control]\nenabled = true\nmin_interval_seconds = 2\n' >> "$NODE_CONFIG"
compose restart gdi-node-standalone >/dev/null 2>&1 || fail "could not restart the node"
deadline=$(( $(date +%s) + TIMEOUT_SECS ))
until curl -fsS -o /dev/null "$MGMT_URL/health/live" 2>/dev/null; do
    [ "$(date +%s)" -lt "$deadline" ] || { compose logs --tail=40 gdi-node-standalone; fail "the node did not come back after enabling [control]"; }
    sleep 2
done

# The catalog must not resolve yet, or the 200 below would prove nothing.
before="$(curl -s -o /dev/null -w '%{http_code}' "$BASE_URL/fairdp/catalog/$RELOAD_CATALOG")"
[ "$before" = "404" ] \
    || fail "/fairdp/catalog/$RELOAD_CATALOG answered $before before the catalog was added"

# Insert into the existing [catalogs] table: a second header would be a duplicate-table
# error. Use `edit_node_config`, never `sed -i`, because this leg reloads instead of
# restarting, so the edit has to reach the container through the existing file mount.
edit_node_config "/^\[catalogs\]/a $RELOAD_CATALOG = \"E2E Reload Check\""
grep -q "^$RELOAD_CATALOG = " "$NODE_CONFIG" || fail "could not add $RELOAD_CATALOG to $NODE_CONFIG"

reload_body="$(curl -fsS -X POST "$MGMT_URL/reload")" || fail "POST /reload failed with [control] enabled"
echo "$reload_body" | jq -e '.applied == true' >/dev/null \
    || { echo "$reload_body"; fail "POST /reload did not report the config as applied"; }

# The assertion: applied without a restart.
after="$(curl -s -o /dev/null -w '%{http_code}' "$BASE_URL/fairdp/catalog/$RELOAD_CATALOG")"
[ "$after" = "200" ] \
    || fail "/fairdp/catalog/$RELOAD_CATALOG answered $after after POST /reload: the endpoint \
returned applied:true but nothing was reloaded"
log "confirmed: a config change applied over HTTP, with no restart and no pods/exec"

# Rate-limited: the very next call is inside the window.
rl_status="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$MGMT_URL/reload")"
[ "$rl_status" = "429" ] \
    || fail "a second POST /reload inside min_interval_seconds answered $rl_status, expected 429"

# A broken file must be refused and the running config kept, which is what makes this
# endpoint safe to expose.
sleep 3
printf '\nthis is not valid toml\n' >> "$NODE_CONFIG"
reject_body="$(curl -fsS -X POST "$MGMT_URL/reload")" || fail "POST /reload failed on a broken config"
echo "$reject_body" | jq -e '.applied == false and .reason == "unparsable"' >/dev/null \
    || { echo "$reject_body"; fail "POST /reload did not report the broken config as unparsable"; }
still="$(curl -s -o /dev/null -w '%{http_code}' "$BASE_URL/fairdp/catalog/$RELOAD_CATALOG")"
[ "$still" = "200" ] \
    || fail "the node dropped its running config ($still) after refusing a bad reload"
log "confirmed: rate-limited, and a bad config is refused with a reason, not applied"

# Leave the file valid: later legs (and any re-run) read it.
edit_node_config '/^this is not valid toml$/d'

# --- 9g. POST /reconcile and POST /log-level -------------------------------------
# `/reconcile` is asserted by the effect an operator cares about: a withhold applied without
# waiting out the periodic reconcile. `dataset hide` writes the suppression file and does not
# signal the node, so this endpoint is what applies it promptly. `hide` rather than
# `take-down`, because this leg has to put the dataset back for the legs after it.
sleep 3
log "hiding $DATASET_ID (writes the override; the CLI cannot signal the node)"
compose exec -T gdi-node-standalone \
    /gdi-node-standalone dataset hide "$DATASET_ID" --reason "e2e reconcile check" \
    >/dev/null 2>&1 || fail "dataset hide failed"

# It must still be serving, because nothing has applied the override yet. That is what
# makes the assertion after /reconcile mean something.
curl -fsS "$MGMT_URL/datasets/$DATASET_ID/state" 2>/dev/null | grep -q '"state":"visible"' \
    || fail "$DATASET_ID stopped being visible before /reconcile: something else applied the \
take-down, so this leg cannot prove the endpoint did"

reconcile_body="$(curl -fsS -X POST "$MGMT_URL/reconcile")" || fail "POST /reconcile failed"
echo "$reconcile_body" | jq -e '.started == true' >/dev/null \
    || { echo "$reconcile_body"; fail "POST /reconcile did not report the pass as started"; }
# 202 means started, so poll for the effect rather than assuming it landed synchronously.
deadline=$(( $(date +%s) + 60 ))
until curl -fsS "$MGMT_URL/datasets/$DATASET_ID/state" 2>/dev/null | grep -q '"state":"hidden"'; do
    [ "$(date +%s)" -lt "$deadline" ] || fail "the withhold was not applied within 60s of \
POST /reconcile: the endpoint answered 202 but ran no reconcile"
    sleep 2
done
log "confirmed: a withhold applied on demand, without waiting out the reconcile interval"

# Restore visibility so the remaining legs see the dataset they expect.
compose exec -T gdi-node-standalone \
    /gdi-node-standalone dataset unhide "$DATASET_ID" --reason "e2e: restore for later legs" \
    >/dev/null 2>&1 || fail "dataset unhide failed"
sleep 3
curl -fsS -X POST "$MGMT_URL/reconcile" >/dev/null || fail "POST /reconcile (restore) failed"
deadline=$(( $(date +%s) + 60 ))
until curl -fsS "$MGMT_URL/datasets/$DATASET_ID/state" 2>/dev/null | grep -q '"state":"visible"'; do
    [ "$(date +%s)" -lt "$deadline" ] || fail "$DATASET_ID did not return to visible"
    sleep 2
done

# `/log-level` flips the real subscriber, which no in-process test can reach because the
# test binary installs no global subscriber. Both directions are checked, plus the revert
# countdown that only the on direction may advertise.
sleep 3
on_body="$(curl -fsS -X POST "$MGMT_URL/log-level")" || fail "POST /log-level (on) failed"
echo "$on_body" | jq -e '.verbose == true and .reverts_in_seconds > 0' >/dev/null \
    || { echo "$on_body"; fail "POST /log-level did not turn diagnostic logging on with a \
bounded revert window"; }
sleep 3
off_body="$(curl -fsS -X POST "$MGMT_URL/log-level")" || fail "POST /log-level (off) failed"
echo "$off_body" | jq -e '.verbose == false and (has("reverts_in_seconds") | not)' >/dev/null \
    || { echo "$off_body"; fail "POST /log-level did not turn diagnostic logging back off, or \
advertised a revert window on the off direction"; }
log "confirmed: log level flips both ways against a real subscriber, with an auto-revert window"

# --- 9h. Traceparent trust is split by source ------------------------------------
# Without an otel build and a collector, what this can assert is that the binary accepts and
# reads the key. `[service]` is deny_unknown_fields, so a binary lacking the key fails to
# boot with it set, and the node coming back up is the discriminator. The boot warning
# naming it proves the value reached the code rather than being parsed and dropped.
#
# Not asserted here: that an ingest span parents under the sidecar's traceparent. That needs
# `--features full,otel` plus an OTLP collector in the stack, neither of which this harness
# has; the flag's effect is covered by the unit tests over `s3_inbound_traceparent`.
log "enabling trust_sidecar_traceparent and restarting the node"
edit_node_config '/^\[service\]/a trust_sidecar_traceparent = true'
grep -q '^trust_sidecar_traceparent = true' "$NODE_CONFIG" \
    || fail "could not enable trust_sidecar_traceparent in $NODE_CONFIG"
compose restart gdi-node-standalone >/dev/null 2>&1 || fail "could not restart the node"
deadline=$(( $(date +%s) + TIMEOUT_SECS ))
until curl -fsS -o /dev/null "$MGMT_URL/health/live" 2>/dev/null; do
    [ "$(date +%s)" -lt "$deadline" ] || { compose logs --tail=40 gdi-node-standalone; fail "the node did not come back with trust_sidecar_traceparent set: the key was rejected (deny_unknown_fields), so this binary does not have it"; }
    sleep 2
done
# The boot advisory fires because this stack configures no otlp_endpoint, and it names the
# flag that is set, so the value was read rather than merely accepted by the parser.
# The needle is the JSON field, not `key=value`: LOG_FORMAT defaults to json here, so a
# text-format needle would match nothing while the node behaves correctly.
wait_log '"trust_sidecar_traceparent":true' \
    "the node did not report reading trust_sidecar_traceparent at boot"
log "confirmed: the sidecar trust flag is accepted and read, independently of the header flag"

# --- 10. The three real-endpoint smokes, against this stack ---------------------
# `crates/gdi-node-standalone/tests/it` carries three `#[ignore]`d smokes that exercise the
# real SigV4/ranged-GET stack and the real KV-v2 + Transit engine, rather than the InMemory
# store and the wiremock Vault the gate uses. They need `GDI_TEST_*` pointing at live
# backends, which this stack is the only place in the repo to provide.
#
# GDI_TEST_REQUIRED makes a missing endpoint variable fatal rather than silent: with it set,
# a smoke whose variable is absent panics instead of early-returning green (see
# `test_util::endpoint_env`). It distinguishes "no backend here, skip" from "the runner
# booted one, so a skip is a lie".
log "running the three real-endpoint smokes against the live stack"

# An isolated bucket, not the node's `gdi-datasets`: the S3 smoke seeds its own package
# and `_status/` objects, and the running node reconciles + writes status into whatever it
# monitors. Sharing one bucket would race the node for those keys. Both setup sidecars take
# S3_BUCKET by Compose interpolation, so a one-off `run` mints it; they are idempotent.
SMOKE_BUCKET="gdi-smoke"
log "provisioning the isolated smoke bucket $SMOKE_BUCKET"
# Subshell, not `S3_BUCKET=... compose ...`: `compose` is a shell function, and a variable
# prefix on a function call leaks the assignment into the caller in bash.
( export S3_BUCKET="$SMOKE_BUCKET"; compose run --rm "${S3_BACKEND}-setup" ) \
    || fail "could not provision the $SMOKE_BUCKET bucket"

# Region matters for Garage: it validates its `s3_region` inside the SigV4 signature, so a
# default region fails to authenticate. minio ignores it.
export GDI_TEST_REQUIRED=1
export GDI_TEST_S3_ENDPOINT="$S3_ENDPOINT" GDI_TEST_S3_REGION="$S3_REGION"
export GDI_TEST_S3_BUCKET="$SMOKE_BUCKET"
export GDI_TEST_S3_KEY="$S3_DEV_KEY"
export GDI_TEST_S3_SECRET="$S3_DEV_SECRET"
export GDI_TEST_VAULT_ADDR="$VAULT_ADDR_HOST"
export GDI_TEST_VAULT_TOKEN="${VAULT_TOKEN:-dev-root-token}"
# Both are deployment-specific and both differ from the tests' hand-rolled-dev defaults
# ("gdi-at-rest" / "gdi/c4gh"); these are what compose/setup.sh and `identity init` created.
# SOURCE: compose/setup.sh TRANSIT_KEY, compose/node.full.toml [vault].kv_path
export GDI_TEST_TRANSIT_KEY="gdi-node-standalone-at-rest"
export GDI_TEST_VAULT_KV_PATH="gdi-node-standalone/c4gh-identities"

# One test per invocation: the names are unique, and a per-smoke exit code says which
# backend contract broke instead of one opaque failure. `full` = s3 + vault + pme, the three
# features these are gated behind; they share one compiled `it` binary. `-p` matters because
# core and beacon also have a `tests/it/main.rs`, so a bare `--test it` runs three binaries
# and `--features full` becomes ambiguous across them.
#
# Asserting "1 passed" catches a name filter that matches nothing: libtest then exits 0 with
# "0 passed; 0 failed". If one of these smokes is renamed, this fails here instead of quietly
# stopping covering it.
for smoke in real_endpoint_round_trip \
             real_vault_kv_and_transit_round_trip \
             real_openbao_pme_round_trip; do
    log "smoke: $smoke"
    # Stdout only (no `2>&1`): libtest prints the "test result: …" summary on stdout, while
    # cargo's build progress and warnings go to stderr and must not enter the string this
    # grep matches. Real stderr still reaches the terminal as the subprocess produces it.
    out="$(cargo test --locked -p gdi-node-standalone --features full --test it -- \
        --ignored --nocapture "$smoke")" \
        || { echo "$out" >&2; fail "real-endpoint smoke failed: $smoke"; }
    echo "$out" | grep -q "test result: ok. 1 passed" \
        || { echo "$out" >&2; fail "$smoke did not run exactly one test: it was renamed or filtered out"; }
done
log "all three real-endpoint smokes passed against the live stack"

log "PASS: full stack e2e (package -> upload -> PME ingest -> visible -> Beacon read-back)"
