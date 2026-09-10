#!/bin/sh
# Garage bucket bootstrap for the full Compose stack (the Garage analogue of the
# `minio-setup` container). Garage ships no shell in its image and needs an
# explicit cluster layout before it serves S3, so this one-shot runs in an
# `alpine/curl` sidecar and drives Garage's admin API (port 3903) over HTTP:
#
#   1. wait for the admin API to answer;
#   2. assign + apply a single-node cluster layout (idempotent: skipped once a
#      layout version exists);
#   3. create the bucket (tolerating "already exists");
#   4. import the fixed dev access key (idempotent) — Garage requires a
#      `GK`+24-hex id and a 64-hex secret, which is exactly the dev-cred format
#      compose/setup.sh writes to Vault, so one credential pair works against
#      both Garage and minio;
#   5. grant the key read+write+owner on the bucket.
#
# The whole script is idempotent, so re-running `docker compose up` is safe.
#
# Admin API version: Garage v2.x serves the admin API at /v2/<Operation> (the
# named-operation scheme; the older /v1/ verb-style endpoints are gone). This
# script targets the v2 API to match `dxflrs/garage:v2.x` in docker-compose.yml.
# Bump both together if the image major changes.
#
# Inputs (env, with dev defaults matching docker-compose.yml / compose/garage.toml):
#   GARAGE_ADMIN_ADDR    admin API base URL     (default http://garage:3903)
#   GARAGE_ADMIN_TOKEN   admin bearer token     (default dev-admin-token)
#   S3_BUCKET            bucket name            (default gdi-datasets)
#   S3_ACCESS_KEY        GK+24-hex access key   (default the dev key)
#   S3_SECRET_KEY        64-hex secret key      (default the dev secret)
#   GARAGE_ZONE          layout zone label      (default dev)
#   GARAGE_CAPACITY_BYTES node capacity in bytes (default 1000000000 = 1G)
#   GARAGE_KEY_NAME      human label for the key (default dev-key)

set -eu

ADMIN="${GARAGE_ADMIN_ADDR:-http://garage:3903}"
TOKEN="${GARAGE_ADMIN_TOKEN:-dev-admin-token}"
BUCKET="${S3_BUCKET:-gdi-datasets}"
AK="${S3_ACCESS_KEY:-GK0123456789abcdef01234567}"
SK="${S3_SECRET_KEY:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"
ZONE="${GARAGE_ZONE:-dev}"
CAP="${GARAGE_CAPACITY_BYTES:-1000000000}"
KEY_NAME="${GARAGE_KEY_NAME:-dev-key}"

log() { echo "[garage-setup] $*"; }

# api METHOD PATH [JSON_BODY] — print the response body.
api() {
    _m="$1"; _p="$2"; _b="${3:-}"
    if [ -n "$_b" ]; then
        curl -sS -X "$_m" -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" -d "$_b" "$ADMIN$_p"
    else
        curl -sS -X "$_m" -H "Authorization: Bearer $TOKEN" "$ADMIN$_p"
    fi
}

# api_code METHOD PATH [JSON_BODY] — print only the HTTP status code (no body).
api_code() {
    _m="$1"; _p="$2"; _b="${3:-}"
    if [ -n "$_b" ]; then
        curl -sS -o /dev/null -w '%{http_code}' -X "$_m" \
            -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
            -d "$_b" "$ADMIN$_p"
    else
        curl -sS -o /dev/null -w '%{http_code}' -X "$_m" \
            -H "Authorization: Bearer $TOKEN" "$ADMIN$_p"
    fi
}

# Extract the first value of a string JSON field whose value is lowercase hex.
hexfield() { grep -o "\"$1\"[[:space:]]*:[[:space:]]*\"[0-9a-f]*\"" | head -1 | sed 's/.*"\([0-9a-f]*\)"$/\1/'; }

# --- 1. Wait for the admin API (v2 GetClusterStatus answers 200) ---------------
log "waiting for the Garage admin API at $ADMIN"
i=0
until [ "$(api_code GET /v2/GetClusterStatus 2>/dev/null || echo 000)" = "200" ]; do
    i=$((i + 1))
    [ "$i" -gt 60 ] && { log "ERROR: admin API not ready after 60s"; exit 1; }
    sleep 1
done

# GetClusterStatus reports `layoutVersion` plus `nodes[].id`; the first hex `id` is
# this single node's id.
STATUS="$(api GET /v2/GetClusterStatus)"
NODE="$(printf '%s' "$STATUS" | hexfield id)"
LAYV="$(printf '%s' "$STATUS" | grep -o '"layoutVersion"[[:space:]]*:[[:space:]]*[0-9]*' | head -1 | sed 's/.*:[[:space:]]*//')"
[ -n "$NODE" ] || { log "ERROR: could not read node id from /v2/GetClusterStatus"; exit 1; }
log "node=$NODE layoutVersion=${LAYV:-0}"

# --- 2. Assign + apply the cluster layout (idempotent) ------------------------
# UpdateClusterLayout stages the role; ApplyClusterLayout commits it as the next
# version. On a fresh cluster (layoutVersion 0) the applied version is 1.
if [ "${LAYV:-0}" = "0" ]; then
    log "staging + applying single-node layout (zone=$ZONE capacity=$CAP bytes)"
    # Check the HTTP status (like CreateBucket/ImportKey/AllowBucketKey below): the `api`
    # helper uses `curl -sS` without `-f`, so a 4xx/5xx (transient error, bad $CAP, or a
    # future admin-API schema change) would otherwise be swallowed and falsely logged as
    # "layout applied", leaving a non-functional S3 backend.
    CODE="$(api_code POST /v2/UpdateClusterLayout \
        "{\"roles\":[{\"id\":\"$NODE\",\"zone\":\"$ZONE\",\"capacity\":$CAP,\"tags\":[]}]}")"
    [ "$CODE" = "200" ] || { log "ERROR: UpdateClusterLayout returned HTTP $CODE"; exit 1; }
    CODE="$(api_code POST /v2/ApplyClusterLayout '{"version":1}')"
    [ "$CODE" = "200" ] || { log "ERROR: ApplyClusterLayout returned HTTP $CODE"; exit 1; }
    log "layout applied (version 1)"
else
    log "layout already applied (version $LAYV) — skipping"
fi

# --- 3. Create the bucket (tolerate already-exists) ---------------------------
# Resolve the bucket id from GetBucketInfo after create, so a re-run whose create
# returns a non-2xx (already-exists) still proceeds as long as the bucket is there.
log "ensuring bucket '$BUCKET' exists"
CODE="$(api_code POST /v2/CreateBucket "{\"globalAlias\":\"$BUCKET\"}")"
case "$CODE" in
    200) log "bucket created" ;;
    *)   log "CreateBucket returned HTTP $CODE (already exists?) — verifying" ;;
esac
BID="$(api GET "/v2/GetBucketInfo?globalAlias=$BUCKET" | hexfield id)"
[ -n "$BID" ] || { log "ERROR: could not resolve bucket id for '$BUCKET' (create HTTP $CODE)"; exit 1; }

# --- 4. Import the fixed dev key (idempotent) ---------------------------------
log "importing access key $AK (idempotent)"
CODE="$(api_code POST /v2/ImportKey "{\"accessKeyId\":\"$AK\",\"secretAccessKey\":\"$SK\",\"name\":\"$KEY_NAME\"}")"
case "$CODE" in
    200) log "key imported" ;;
    400) log "ERROR: key rejected — Garage needs a GK+24-hex id and a 64-hex secret"; exit 1 ;;
    *)   log "ImportKey returned HTTP $CODE (already present?) — continuing" ;;
esac

# --- 5. Grant the key read+write+owner on the bucket --------------------------
# AllowBucketKey is the functional check: if the key import truly failed this errors.
log "granting read+write+owner on '$BUCKET' to $AK"
CODE="$(api_code POST /v2/AllowBucketKey \
    "{\"bucketId\":\"$BID\",\"accessKeyId\":\"$AK\",\"permissions\":{\"read\":true,\"write\":true,\"owner\":true}}")"
[ "$CODE" = "200" ] || { log "ERROR: AllowBucketKey returned HTTP $CODE"; exit 1; }

log "done: layout applied, bucket '$BUCKET' ready, key $AK granted"
