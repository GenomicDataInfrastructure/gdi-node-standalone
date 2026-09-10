#!/bin/sh
# Dev secrets-backend bootstrap: generate the static seal key, then initialize the
# backend and mint a stable fixed-id token.
#
# Two modes:
#   --genkey   write $KEYS_DIR/unseal.key if absent (OpenBao static seal); must run
#              before the OpenBao server starts.
#   (default)  wait for the backend, initialize if needed, unseal if needed
#              (Shamir only), and mint $DEV_TOKEN_ID.
#
# Idempotent: safe to re-run on every `up`.
#
# Runs unchanged against OpenBao and HashiCorp Vault, which speak the same
# sys/init, sys/unseal and auth/token/create API. The one difference is the seal:
# OpenBao auto-unseals via `seal "static"` (so init returns no keys and the
# backend is immediately usable), while Vault uses a 1-of-1 Shamir key that must
# be stored and replayed after every restart. $SECRETS_BACKEND selects the branch.
#
# Requires only POSIX sh + curl (the alpine/curl sidecar image).

set -eu

VAULT_ADDR="${VAULT_ADDR:-http://openbao:8200}"
SECRETS_BACKEND="${SECRETS_BACKEND:-openbao}"
KEYS_DIR="${KEYS_DIR:-/keys}"
DEV_TOKEN_ID="${DEV_TOKEN_ID:-dev-root-token}"

log() { echo "[secrets-init] $*"; }
die() { echo "[secrets-init] ERROR: $*" >&2; exit 1; }

genkey() {
    if [ -s "$KEYS_DIR/unseal.key" ]; then
        log "static seal key already present — keeping it"
        return 0
    fi
    # 32 raw bytes, base64-encoded. The seal rejects anything that does not decode to
    # exactly 32 bytes (AES-256-GCM-96).
    head -c 32 /dev/urandom | base64 | tr -d '\n' > "$KEYS_DIR/unseal.key"
    chmod 0644 "$KEYS_DIR/unseal.key"
    log "generated a new static seal key"
}

if [ "${1:-}" = "--genkey" ]; then
    genkey
    exit 0
fi

# --- wait for the listener (bounded; a stuck backend must be diagnosable) ------
log "waiting for the secrets backend at $VAULT_ADDR"
i=0
until curl -fsS "$VAULT_ADDR/v1/sys/seal-status" >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -gt 60 ] && die "secrets backend not reachable after 60s"
    sleep 1
done
log "listener is up"

seal_status_field() {
    # seal_status_field FIELD -> prints the JSON boolean as `true`/`false`
    curl -fsS "$VAULT_ADDR/v1/sys/seal-status" \
        | tr ',' '\n' | grep "\"$1\"" | head -1 | grep -o 'true\|false'
}

# --- initialize (once) --------------------------------------------------------
if [ "$(seal_status_field initialized)" = "false" ]; then
    if [ "$SECRETS_BACKEND" = "openbao" ]; then
        # Static seal: no unseal keys are produced and the backend self-unseals.
        body='{"recovery_shares":0,"recovery_threshold":0}'
    else
        # Shamir: one share, one threshold; the key must be kept to unseal later.
        body='{"secret_shares":1,"secret_threshold":1}'
    fi
    resp="$(curl -fsS -X PUT -d "$body" "$VAULT_ADDR/v1/sys/init")" \
        || die "init failed"
    printf '%s' "$resp" \
        | sed -n 's/.*"root_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        > "$KEYS_DIR/root-token"
    [ -s "$KEYS_DIR/root-token" ] || die "init returned no root token"
    chmod 0600 "$KEYS_DIR/root-token"
    if [ "$SECRETS_BACKEND" != "openbao" ]; then
        printf '%s' "$resp" \
            | sed -n 's/.*"keys"[[:space:]]*:[[:space:]]*\["\([^"]*\)".*/\1/p' \
            > "$KEYS_DIR/unseal-key"
        [ -s "$KEYS_DIR/unseal-key" ] || die "shamir init returned no unseal key"
        chmod 0600 "$KEYS_DIR/unseal-key"
    fi
    log "backend initialized"
else
    log "backend already initialized — continuing"
fi

# --- unseal (Shamir profile only; the static seal self-unseals) ---------------
if [ "$(seal_status_field sealed)" = "true" ]; then
    [ "$SECRETS_BACKEND" = "openbao" ] && \
        die "openbao is sealed despite the static seal — check the seal key file"
    [ -s "$KEYS_DIR/unseal-key" ] || \
        die "backend is sealed and no unseal key is stored; run scripts/dev-reset.sh"
    curl -fsS -X PUT \
        -d "{\"key\":\"$(cat "$KEYS_DIR/unseal-key")\"}" \
        "$VAULT_ADDR/v1/sys/unseal" >/dev/null || die "unseal failed"
    [ "$(seal_status_field sealed)" = "false" ] || die "still sealed after unseal"
    log "backend unsealed"
fi

# --- mint the stable dev token ------------------------------------------------
# Everything downstream (compose/node.full.toml, compose/setup.sh, the node's
# GDI_NODE__VAULT__TOKEN) hard-codes this id, so minting it here means a real
# `operator init` changes nothing for them. Only root may choose a token id.
#
# Probe the fixed id first: on a re-run there is no root token in this process's
# memory, and re-minting an existing id fails with "cannot create a token with a
# duplicate ID". Both of those are expected steady-state conditions, not errors.
if curl -fsS -o /dev/null -H "X-Vault-Token: $DEV_TOKEN_ID" \
        "$VAULT_ADDR/v1/auth/token/lookup-self" 2>/dev/null; then
    log "dev token '$DEV_TOKEN_ID' already valid — nothing to do"
else
    [ -s "$KEYS_DIR/root-token" ] || die "no stored root token; run scripts/dev-reset.sh"
    out="$(curl -sS -X POST -H "X-Vault-Token: $(cat "$KEYS_DIR/root-token")" \
        -d "{\"id\":\"$DEV_TOKEN_ID\",\"policies\":[\"root\"],\"no_parent\":true}" \
        "$VAULT_ADDR/v1/auth/token/create")" || die "token create request failed"
    case "$out" in
        *'"client_token"'*) log "minted dev token '$DEV_TOKEN_ID'" ;;
        *'duplicate ID'*)   log "dev token '$DEV_TOKEN_ID' exists — continuing" ;;
        *)                  die "token create failed: $out" ;;
    esac
fi

log "done: backend initialized, unsealed, and '$DEV_TOKEN_ID' is usable"
