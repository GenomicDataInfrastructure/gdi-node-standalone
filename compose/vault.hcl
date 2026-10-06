# HashiCorp Vault config for the dev stack: persistent, Shamir-sealed.
#
# The sibling compose/openbao.hcl uses `seal "static"` to auto-unseal. Vault has no
# static-seal equivalent, so this profile keeps a 1-of-1 Shamir key that
# compose/secrets-init.sh persists and replays on every start. That asymmetry is one
# branch in one script, not two mechanisms.
#
# The storage path is /vault/file because the image pre-creates it with the right
# ownership for its non-root user; openbao.hcl uses /openbao/file for the same reason.
# The two paths must differ, so this is not a duplicated invariant.
#
# Do not pass `-config=` on the command line for this image.
# The entrypoint already adds `-config=/vault/config`, so naming this file again loads
# it twice and the second listener fails with
#   "Error initializing listener of type tcp: listen tcp4 0.0.0.0:8200: bind:
#    address already in use"
# so the compose service runs a bare `server`. OpenBao's entrypoint does the same, but
# it tolerates the duplicate, which is why its service can keep `-config=`.
#
# Behaviour of this profile, as observed on openbao/openbao:2.6.4 and hashicorp/vault:2.1.1:
#   * after `sys/init` it is still sealed (the static seal auto-unseals; Shamir does not)
#   * after a container restart it comes back sealed and must be unsealed again —
#     this is the case the seal-aware healthcheck exists to catch
#   * `vault status` exits 0 unsealed / 2 sealed, matching `bao status`
#   * the image ships /bin/vault, plus /usr/bin/wget and /usr/bin/nc but no curl.
#     `vault status` is still the healthcheck probe, because it is the only one of
#     the three that reports seal state — a sealed server still accepts TCP.
#
# Dev only: TLS is disabled. Never use this shape for anything you need.

disable_mlock = true
ui            = true

storage "file" {
  path = "/vault/file"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}
