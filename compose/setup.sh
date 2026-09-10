#!/bin/sh
# Dev setup script for the full Compose stack: provisions the S3 credentials + the
# Transit key.
#
# Provisions, against the selected secrets backend (OpenBao by default, HashiCorp
# Vault behind --profile vault — both speak the same KV v2 + Transit API, so
# this script runs unchanged against either):
#   1. the KV v2 secret holding the per-bucket S3 credentials, at $KV_MOUNT/$S3_PATH
#      — keys `${BUCKET_LOGICAL}_access_key_id` / `${BUCKET_LOGICAL}_secret_access_key`;
#   2. the Transit aes256-gcm96 key $TRANSIT_KEY under the $TRANSIT_MOUNT mount
#      (the at-rest PME master key);
# and creates the S3 bucket on the selected S3 backend (Garage by default, minio
# behind --profile minio).
#
# The node crypt4gh identity is not provisioned here — it is minted straight into
# Vault by `gdi-node-standalone identity init` (generated in memory, never on disk). Run
# `docker compose run --rm gdi-node-standalone identity init` after this script.
#
# Inputs (env, with dev defaults matching compose/node.full.toml):
#   VAULT_ADDR         secrets backend HTTP address      (default http://openbao:8200)
#   VAULT_TOKEN        dev root token                    (default dev-root-token)
#   KV_MOUNT           KV v2 mount for the secrets        (default secret)
#   S3_PATH            S3-creds KV path                  (gdi-node-standalone/s3-credentials)
#   TRANSIT_MOUNT/TRANSIT_KEY  transit mount + key       (transit / gdi-node-standalone-at-rest)
#   BUCKET_LOGICAL     the [[s3.buckets]].name           (default primary)
#   S3_BUCKET          the actual bucket name            (default gdi-datasets)
#   S3_BACKEND         garage | minio                    (default garage)
#   S3_ACCESS_KEY/S3_SECRET_KEY  bucket creds to provision (default dev values)
#
# Requires only POSIX sh + curl (both in the openbao/vault and a busybox image).

set -eu

VAULT_ADDR="${VAULT_ADDR:-http://openbao:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-dev-root-token}"
KV_MOUNT="${KV_MOUNT:-secret}"
S3_PATH="${S3_PATH:-gdi-node-standalone/s3-credentials}"
TRANSIT_MOUNT="${TRANSIT_MOUNT:-transit}"
TRANSIT_KEY="${TRANSIT_KEY:-gdi-node-standalone-at-rest}"
BUCKET_LOGICAL="${BUCKET_LOGICAL:-primary}"
S3_BUCKET="${S3_BUCKET:-gdi-datasets}"
S3_BACKEND="${S3_BACKEND:-garage}"
# The dev creds use Garage's key format (GK + 24 hex id, 64 hex secret) so the same
# pair is accepted by both Garage (`key import`) and minio (root creds).
S3_ACCESS_KEY="${S3_ACCESS_KEY:-GK0123456789abcdef01234567}"
S3_SECRET_KEY="${S3_SECRET_KEY:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"

log() { echo "[setup] $*"; }

# --- Wait for the secrets backend to be ready ---------------------------------
log "waiting for the secrets backend at $VAULT_ADDR"
# `?standbyok=true` and nothing else. Adding `sealedcode=200&uninitcode=200` makes the
# backend answer 200 while sealed or uninitialized, so this loop would exit as soon as the
# process was listening and the very next write would get `503 sealed`. Under the normal
# compose stack OpenBao boots already unsealed (`seal "static"`) and that race is rarely
# lost, but through the chaos overlay's toxiproxy hop it is lost every time.
#
# Bare `/v1/sys/health` returns 200 only when initialized and unsealed and active, and
# `standbyok=true` widens that to a standby replica — which is exactly "can accept the
# writes below". A setup script must wait for write-capable, not for "responding".
i=0
until curl -fsS "$VAULT_ADDR/v1/sys/health?standbyok=true" >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -gt 60 ]; then
        log "ERROR: secrets backend not unsealed/ready after 60s at $VAULT_ADDR"
        log "       (a listening but sealed backend looks like this; check its logs)"
        exit 1
    fi
    sleep 1
done
log "secrets backend is up and unsealed"

vault_api() {
    # vault_api METHOD PATH [JSON_BODY]
    _method="$1"; _path="$2"; _body="${3:-}"
    if [ -n "$_body" ]; then
        curl -fsS -X "$_method" \
            -H "X-Vault-Token: $VAULT_TOKEN" \
            -H "Content-Type: application/json" \
            -d "$_body" \
            "$VAULT_ADDR/v1/$_path"
    else
        curl -fsS -X "$_method" \
            -H "X-Vault-Token: $VAULT_TOKEN" \
            "$VAULT_ADDR/v1/$_path"
    fi
}

# Enable a secrets engine, ignoring "already enabled" (dev servers pre-enable the
# default KV at `secret/`; transit is not pre-enabled).
enable_engine() {
    _mount="$1"; _type="$2"
    if vault_api POST "sys/mounts/$_mount" "{\"type\":\"$_type\"}" >/dev/null 2>&1; then
        log "enabled $_type engine at $_mount/"
    else
        log "$_type engine at $_mount/ already enabled (or pre-mounted) — continuing"
    fi
}

# --- 1. KV v2 secret: per-bucket S3 credentials -------------------------------
# (The node crypt4gh identity is minted separately by `gdi-node-standalone identity init`.)
enable_engine "$KV_MOUNT" "kv-v2"

log "writing the per-bucket S3 credentials to $KV_MOUNT/$S3_PATH"
vault_api POST "$KV_MOUNT/data/$S3_PATH" \
    "{\"data\":{\"${BUCKET_LOGICAL}_access_key_id\":\"$S3_ACCESS_KEY\",\"${BUCKET_LOGICAL}_secret_access_key\":\"$S3_SECRET_KEY\"}}" >/dev/null

# --- 2. Transit at-rest master key --------------------------------------------
enable_engine "$TRANSIT_MOUNT" "transit"
log "creating the Transit aes256-gcm96 key $TRANSIT_MOUNT/$TRANSIT_KEY"
vault_api POST "$TRANSIT_MOUNT/keys/$TRANSIT_KEY" '{"type":"aes256-gcm96"}' >/dev/null

# --- 3. S3 bucket creation is handled by a dedicated container ----------------
# The bucket + access-key bootstrap for each backend runs in its own one-shot
# Compose service (the `garage` profile's garage-setup via the admin API, the
# `minio` profile's minio-setup via mc), not here — this script only provisions
# the secrets backend so it can run unchanged against OpenBao or Vault.
case "$S3_BACKEND" in
    garage) log "S3 bucket is bootstrapped by the garage-setup container (admin API)" ;;
    minio)  log "S3 bucket is bootstrapped by the minio-setup container (mc)" ;;
    *)      log "unknown S3_BACKEND=$S3_BACKEND; ensure the bucket exists out of band" ;;
esac

log "done: S3 creds + Transit key provisioned (run identity init for the node key)"
