# OpenBao config for the dev stack — persistent, auto-unsealing.
#
# Storage is a file backend on a named volume, so the node crypt4gh identity and the
# Transit master key survive restarts. `server -dev` keeps them in memory and loses them.
#
# `seal "static"` auto-unseals from a key file, so the backend boots already
# unsealed and there is no unseal key to persist or re-supply. HashiCorp Vault
# has no static-seal equivalent, which is why compose/vault.hcl uses Shamir and
# compose/secrets-init.sh branches on the backend.
#
# The storage path is /openbao/file because the image pre-creates it with the
# right ownership for its non-root user — a named volume mounted there needs no
# chown sidecar. compose/vault.hcl uses /vault/file for the same reason. Those
# paths must differ (per-image conventions); this is not a duplicated invariant.
#
# Dev only: TLS is disabled and the seal key sits beside the data. Never use
# this shape for anything you need.

disable_mlock = true
ui            = true

storage "file" {
  path = "/openbao/file"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

seal "static" {
  current_key_id = "gdi-dev-1"
  current_key    = "file:///openbao/secrets/unseal.key"
}
