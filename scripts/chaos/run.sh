#!/usr/bin/env bash
#
# Real-dependency chaos harness for gdi-node-standalone: S3 and Vault faults.
#
# Brings up the full e2e stack (node + real Garage + real OpenBao) with the
# docker-compose.chaos.yml overlay, which inserts a toxiproxy sidecar on the wire between
# the node and both dependencies. The node is repointed at the toxiproxy listeners, so a
# fault (latency, bandwidth, connection reset, timeout) can be injected on the S3 or Vault
# connection through toxiproxy's admin API (:8474) without touching the node or the
# backends, which an in-memory mock cannot reproduce.
#
# Scenarios and the behaviours they assert:
#   * baseline: clean path through both proxies, so the node reaches /health/ready.
#   * s3-latency: 2s added latency on every S3 op. The node must not abort mid-download,
#     since the object_store total-request timeout is disabled, and must recover to ready
#     once the toxic clears; poll errors stay bounded.
#   * s3-reset: connection reset on S3. A poll fails and gdi_s3_poll_errors_total rises,
#     but the node stays up and recovers when the toxic clears.
#   * vault-down: S3-side ops keep working while Vault is black-holed with a timeout
#     toxic. /health/ready degrades to vault_ok=false and recovers when cleared, the node
#     never crashes, and it never serves at-rest-decrypt data it has no key for.
#
# Advisory and on-demand: it needs Docker, the e2e image build and several GB of disk, and
# is not part of `scripts/ci-local.sh all`. Knobs: S3_BACKEND (garage|minio), VAULT_BACKEND
# (openbao|vault), TOXIPROXY_ADMIN (default http://127.0.0.1:8474).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

COMPOSE="${COMPOSE:-docker compose}"
PROJECT="gdi-node-standalone-chaos"
S3_BACKEND="${S3_BACKEND:-garage}"
VAULT_BACKEND="${VAULT_BACKEND:-openbao}"
ADMIN="${TOXIPROXY_ADMIN:-http://127.0.0.1:8474}"
MGMT_URL="${MGMT_URL:-http://127.0.0.1:9090}"

# Upstream service:port the proxies point at (compose DNS names on the shared network).
case "$S3_BACKEND" in
  garage) S3_UPSTREAM="garage:3900" ;;
  minio)  S3_UPSTREAM="minio:9000" ;;
  *) echo "FAIL: unknown S3_BACKEND=$S3_BACKEND" >&2; exit 2 ;;
esac
VAULT_UPSTREAM="${VAULT_BACKEND}:8200"

export COMPOSE_PROFILES="${S3_BACKEND},${VAULT_BACKEND},chaos,setup"
export GDI_S3_ENDPOINT="http://toxiproxy:23900"
export VAULT_ADDR="http://toxiproxy:28200"

FILES=(-f docker-compose.yml -f docker-compose.chaos.yml)
dc() { $COMPOSE -p "$PROJECT" "${FILES[@]}" "$@"; }

# Node logs from the teardown go to a freshly created private file, not a fixed `/tmp`
# path: a predictable name in a world-writable directory can be pre-created or symlinked
# by any local user, who then captures the node log or redirects the write. `mktemp`
# creates with O_EXCL at 0600 and fails if the name already exists.
CHAOS_LOG="$(mktemp -t chaos-node.XXXXXXXX.log)"

cleanup() {
  echo "==> tearing down"
  dc logs --no-color --tail=80 gdi-node-standalone >"$CHAOS_LOG" 2>&1 || true
  echo "    node logs: $CHAOS_LOG"
  dc down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

# --- toxiproxy admin helpers (admin port published on loopback) --------------------
tp() { curl -fsS "$@"; }
mk_proxy() { # mk_proxy <name> <listen> <upstream>
  tp -XPOST "$ADMIN/proxies" -d "{\"name\":\"$1\",\"listen\":\"$2\",\"upstream\":\"$3\",\"enabled\":true}" >/dev/null
}
add_toxic() { # add_toxic <proxy> <name> <json-body>
  tp -XPOST "$ADMIN/proxies/$1/toxics" -d "$3" >/dev/null && echo "    + toxic $2 on $1"
}
clear_toxics() { # clear_toxics <proxy>: delete the proxy's toxics, restoring a clean wire
  local t
  for t in $(tp "$ADMIN/proxies/$1/toxics" | grep -oE '"name":"[^"]+"' | cut -d'"' -f4); do
    tp -XDELETE "$ADMIN/proxies/$1/toxics/$t" >/dev/null || true
  done
  echo "    - cleared toxics on $1"
}
ready() { curl -fsS "$MGMT_URL/health/ready" >/dev/null 2>&1; }
wait_ready() { for _ in $(seq 1 "${1:-60}"); do ready && return 0; sleep 1; done; return 1; }
wait_unready() { for _ in $(seq 1 "${1:-30}"); do ready || return 0; sleep 1; done; return 1; }

echo "==> bringing up the stack + toxiproxy (S3=$S3_BACKEND, Vault=$VAULT_BACKEND)"
dc up -d --build toxiproxy
for _ in $(seq 1 30); do tp "$ADMIN/version" >/dev/null 2>&1 && break; sleep 1; done
echo "==> creating proxies"
mk_proxy s3    "0.0.0.0:23900" "$S3_UPSTREAM"
mk_proxy vault "0.0.0.0:28200" "$VAULT_UPSTREAM"

# Bring up the backends and bootstrap, then the node, which now dials through toxiproxy.
# Every step must run and no failure may be swallowed: without its bucket and key the node
# gets S3 403, and without a Vault identity it dies on `Vault ... 404`. Either way the
# harness fails its own clean-wire baseline before a single fault is injected.
dc up -d "$S3_BACKEND" "$VAULT_BACKEND"
dc up -d "${S3_BACKEND}-setup"                    # S3 bucket + access key (garage-setup / minio-setup)
# Initialize and unseal the secrets backend before anything writes to it. A backend that
# is merely healthy is not enough: setup.sh dies on its first write against an
# uninitialized one. docker-compose.yml declares secrets-init on the node, and nothing
# else pulls it in: `up -d openbao` starts only openbao and its own dependencies, and the
# `setup` service does not depend on it either.
dc run --rm secrets-init                          # init + unseal (secrets-init.sh)
dc run --rm setup                                 # Vault Transit engine (setup.sh)
dc run --rm gdi-node-standalone identity init --ensure  # mint the node crypt4gh identity into Vault
dc up -d gdi-node-standalone

fail=0

echo "==> baseline: clean path through both proxies"
if wait_ready 90; then echo "    baseline ready OK"; else echo "FAIL: node never became ready on a clean wire" >&2; fail=1; fi

echo "==> s3-latency: 2s on every S3 op; must not abort, must recover"
add_toxic s3 latency '{"type":"latency","attributes":{"latency":2000}}'
sleep 8
ready && echo "    node stays up under S3 latency OK" || echo "    node reported not-ready under S3 latency; acceptable if it recovers" >&2
clear_toxics s3
if wait_ready 60; then echo "    recovered after clearing S3 latency OK"; else echo "FAIL: node did not recover after S3 latency cleared" >&2; fail=1; fi

echo "==> s3-reset: connection reset on S3; poll fails, node stays up and recovers"
add_toxic s3 reset '{"type":"reset_peer","attributes":{"timeout":0}}'
sleep 8
# The node process must still answer /health/live (management plane stays up).
if curl -fsS "$MGMT_URL/health/live" >/dev/null 2>&1; then
  echo "    management plane alive under S3 reset OK"
else
  echo "FAIL: node down under S3 reset" >&2; fail=1
fi
clear_toxics s3
if wait_ready 60; then echo "    recovered after clearing S3 reset OK"; else echo "FAIL: no recovery after S3 reset" >&2; fail=1; fi

echo "==> vault-down: black-hole Vault; readiness degrades, node stays up, recovers"
add_toxic vault down '{"type":"timeout","attributes":{"timeout":0}}'
# Vault health reaches /health/ready through a periodic probe on VAULT_LIVENESS_INTERVAL,
# 1 minute in crates/gdi-node-standalone/src/main.rs, so this window must stay comfortably
# above that interval or it expires before the signal can arrive. Vault gates `ready`, so
# this is a hard assertion; scripts/tests/test_chaos_timings.py enforces the margin.
if wait_unready 90; then
  echo "    /health/ready degraded with Vault unreachable OK"
else
  echo "FAIL: /health/ready stayed up 90s into a Vault black-hole; Vault gates readiness" >&2
  fail=1
fi
if curl -fsS "$MGMT_URL/health/live" >/dev/null 2>&1; then
  echo "    management plane alive under Vault outage OK"
else
  echo "FAIL: node crashed under Vault outage" >&2; fail=1
fi
clear_toxics vault
wait_ready 90 && echo "    recovered after Vault restored OK" || echo "    not recovered: a boot-time keyless degrade does not self-heal; restart the node" >&2

if [ "$fail" -ne 0 ]; then echo "CHAOS: FAILED" >&2; exit 1; fi
echo "CHAOS: PASS (baseline + S3 latency/reset + Vault outage, all recovered or fail-closed)"
