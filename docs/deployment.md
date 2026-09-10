# Deployment

How to install and run `gdi-node-standalone`: platforms, binaries, deployment shapes and
sizing. Day-2 operation — health, metrics, incidents, key rotation, disaster recovery — is
in [operating.md](operating.md), starting with its §0 bring-up checklist. For a first local
run, use the [README](../README.md) quickstart.

For Kubernetes, [`deploy/kubernetes/`](../deploy/kubernetes/README.md) is a worked example
Kustomize base. Adapt it rather than apply it unchanged; no image is published yet. It
encodes the container contract described below: non-root uid `65532`, which needs an init
container to take ownership of each fresh PVC (`fsGroup` alone does not — see
[operating.md §18](operating.md#18-upgrades-version-skew-and-rollback)); port `8080` for the
public plane, and port `9090` on a separate management Service restricted by a
`NetworkPolicy`, which restricts anything only on a CNI that enforces it. The Ingress in
front of the public plane is yours to supply. See the prerequisites in the example's README.

## Binaries and platforms

The service is a single binary, built in two flavours:

- **`gnu` (glibc) — recommended.** Serves markedly more Beacon throughput than the static
  `musl` build under concurrent load, and its glibc floor is guarded at ≤ 2.28, which covers
  RHEL/Rocky/Alma 8+ and Debian 10+. Dynamically linked against the host glibc, present on
  every mainstream Linux but not on Alpine.
- **`musl` (fully static) — fallback.** Use on Alpine/musl, or anywhere a zero-dependency
  static binary is required: no glibc, no shared libraries, no interpreter. Slower under
  load, but runs anywhere.

Prefer `gnu`. Reach for `musl` only when the gnu binary will not start.

No release has been cut, so there is no `v*` tag: the Releases page is empty, the GHCR
image does not exist, and the download commands below do not resolve. Build from source
until a tag exists — it is the only working install path:

```bash
cargo build --release --features full -p gdi-node-standalone
```

For the static musl fallback, add the target and a C toolchain (`apt install musl-tools`)
and pass `--target x86_64-unknown-linux-musl`.

`cargo install` works too, but only from the checkout. Nothing here is published to a
registry, so `cargo install gdi-node-standalone` fails with *"could not find
`gdi-node-standalone` in registry"*, and the repo root is a virtual workspace manifest, so
`cargo install --path .` fails as well (*"found a virtual manifest"*). Point `--path` at
the crate:

```bash
cargo install --path crates/gdi-dataset-tool
cargo install --path crates/gdi-node-standalone                  # lite
cargo install --path crates/gdi-node-standalone --features full  # + S3 / Vault / PME
```

Each `cargo install --path …` builds the whole arrow/parquet/noodles/crypt4gh tree from
source in its own temporary target directory, sharing nothing with the others. Add
`--target-dir target`, or set `CARGO_TARGET_DIR` for the session, to share the work. Cargo
prints no progress when its output is piped or redirected, so a silent terminal is normal.

Once a release exists, download a prebuilt, signed, checksummed binary from the
[Releases page](https://github.com/GenomicDataInfrastructure/gdi-node-standalone/releases).
The per-target service assets are named
`gdi-node-standalone-<tag>-{x86_64,aarch64}-unknown-linux-{gnu,musl}`; fetch one plus the
checksums and the SBOM, then verify — see
[operating.md §20](operating.md#20-verifying-release-artifacts--the-container-image) for the
full provenance and SBOM verification.

```bash
# The service binary, x86_64 glibc. This pattern matches exactly that one asset, not the
# aarch64 build or the gdi-dataset-tool CLI. Swap 'x86_64' for 'aarch64', or 'gnu' for
# 'musl', to fetch a different single asset.
gh release download <tag> --repo GenomicDataInfrastructure/gdi-node-standalone \
  --pattern 'gdi-node-standalone-*-x86_64-unknown-linux-gnu' --pattern SHA256SUMS --pattern '*.cdx.json'
sha256sum -c SHA256SUMS --ignore-missing
```

## Bare metal

A container is not required. Copy the one binary, drop a `node.toml` — start from
[`node.quickstart.toml`](../node.quickstart.toml), or from the annotated
[`node.example.toml`](../node.example.toml) for the full per-knob reference — and start it.
`check-config` runs the full preflight without binding a listener and lists every
`<SET ME: …>` placeholder still to fill. Four things to get right off-cluster, where there
is no Kubernetes to enforce them:

- **Firewall the management plane if you widen it.** `[service].management_addr` defaults to
  `127.0.0.1:9090`, loopback only, so out of the box nothing off-host can reach it. It
  serves `/metrics` plus the unauthenticated dataset-state oracle
  (`GET /datasets/{id}/state`, which reveals `hidden` and `error` ids). Anything probing or
  scraping it from another host or network namespace — a kubelet liveness probe, a
  Prometheus scraper, `docker -p` — cannot see it until you widen the bind to
  `"0.0.0.0:9090"`, and the moment you do, you own the exposure: gate it with a
  `NetworkPolicy` or a host firewall. The binary emits a startup INFO line on a wildcard
  bind (`event.action = "config.posture"`), not a WARN, because a widened bind is a
  documented deployment rather than a misconfiguration. Treat it as an action item all the
  same.
- **Rate-limit the public beacon at your ingress.** The aggregated Beacon plane is
  unauthenticated, so the node has no client identity to meter against and ships no rate
  limiter. An in-process one would be the wrong place for it: it would be per-replica, so
  three replicas would silently allow three times the intended rate; it would be blind to
  `X-Forwarded-For` unless told to trust it; and a mis-tuned limit throttling a federated
  aggregator looks exactly like a node fault. Put the budget where shared state and a real
  client identity exist — your ingress, reverse proxy or WAF. A per-source-IP allowance in
  the low tens of requests per second is generous for an aggregator while raising the cost
  of the two things request volume buys an attacker: bulk extraction of the
  allele-frequency matrix, and the repeated sampling a timing side-channel needs. It makes
  both slower rather than infeasible, and it is not a membership-inference control — see the
  accepted residual risk in [threat-model.md](threat-model.md). Bounding *work per request*
  is a separate, in-node concern, already covered by the beacon's page-size ceiling and
  range-span cap.

  **Also set a per-source connection limit, which is a different directive.** A rate limiter
  counts requests, and the cheapest denial of the public plane makes none: hold idle TCP
  sockets until the per-plane connection cap is reached. Ordinary clients then get
  connection resets, no rate counter moves, and the only signal is
  `gdi_http_connections_rejected_total{plane="public"}` climbing (see
  [api.md](api.md#standards-conformance-and-known-deltas)). Use `limit_conn` (nginx) or
  `maxConnectionsPerSource` and its equivalents (Traefik, HAProxy, Envoy) alongside the
  per-IP rate limit; neither substitutes for the other.
- **Never commit secrets, and know which source wins.** The S3 and Vault profiles need
  secrets the install notes do not copy: `[[s3.buckets]]` `access_key_id` and
  `secret_access_key`, and the `[vault]` token or `secret_id`. Environment variables
  override the file and Vault overrides both, with one trap — see
  [Which S3 credential is actually in force](#which-s3-credential-is-actually-in-force).

  Off-cluster, prefer a non-git `node.toml` at mode `0640` owned `root:<service-user>` over
  env. It is the bare-metal analogue of a mounted Kubernetes Secret, since a process
  environment is visible in `/proc/<pid>/environ` and through `docker inspect`. Then make
  sure no stale `GDI_NODE__S3__BUCKETS__*` variables survive in the service environment, or
  they will silently win over the value you edited. For the no-Vault case,
  [operating.md §11](operating.md#11-running-without-vault-the-s3-profile) lists where each
  secret then comes from.

  **In a cluster that ranking inverts.** The file holding the secret is a mounted Secret
  the platform provides, not a `node.toml` an operator edits. Take Vault first
  (`[vault].s3_path` for the S3 credentials, `[vault].kv_path` for the crypt4gh identity),
  then a `…_file` form where one exists (`[vault].token_file` is the one that does), and
  inline env last. With a Vault Agent writing that token file the node holds no static
  secret at all, only a path — see [Authenticating the node](#authenticating-the-node).
- **`data_dir` must be an absolute path.** The preflight rejects a relative one, which would
  otherwise root the data tree under the process working directory.

**Upgrade in place and rollback.** Stop the process, install the new binary, run
`check-config` against the new config, then start. Rollback reinstalls the prior binary
*and* its matching `node.toml` together, because a newer config key
`deny_unknown_fields`-kills the older binary (see
[operating.md §18](operating.md#18-upgrades-version-skew-and-rollback)). A serialized
stop-then-start never overlaps two processes on the one data volume, which is the
single-writer invariant.

## Container image

> **No image has been published yet.** No `v*` tag exists, so nothing has ever been pushed
> to GHCR and the `docker pull` below fails with not-found. Build your own from the shipped
> `Dockerfile` — see [Building your own image](#building-your-own-image) — until the first
> tag ships. This section is the procedure that becomes live with that release.

Tagged releases will publish a container image to GHCR, packaged from the same released
`gnu` (glibc) binary onto a minimal `distroless/cc` base. There is no recompile: the binary
is byte-identical to the bare-metal download.

```bash
docker pull ghcr.io/genomicdatainfrastructure/gdi-node-standalone:<tag>
docker run --rm -v "$PWD/node.toml:/etc/gdi-node-standalone/node.toml:ro" \
  -p 8080:8080 -p 9090:9090 \
  ghcr.io/genomicdatainfrastructure/gdi-node-standalone:<tag> --config /etc/gdi-node-standalone/node.toml
```

`-p 9090:9090` only reaches the management plane if your `node.toml` sets
`[service] management_addr = "0.0.0.0:9090"`. It defaults to `127.0.0.1:9090`, loopback
*inside* the container, and `node.quickstart.toml` does not override it, so the published
port refuses connections until you widen the bind. The shipped
[`compose/node.minimal.toml`](../compose/node.minimal.toml),
[`compose/node.s3.toml`](../compose/node.s3.toml) and
[`compose/node.full.toml`](../compose/node.full.toml) all set it; read the management-plane
note above before exposing it beyond the host.

The image will ship a `HEALTHCHECK` that runs `gdi-node-standalone healthcheck`, which
probes `/health/ready` on the loopback management port. It will be `linux/amd64` only; on
`arm64`, run the bare-metal `aarch64` binary.

**Licensing of the image layers.** Every Rust dependency is permissive or public-domain,
no copyleft, enforced by `cargo deny check` in the `supply-chain` leg of
`./scripts/ci-local.sh` against an exhaustive allow-list. That covers the dependency graph,
not the image. An image also carries its base layer, under that layer's own upstream
licence: the service image builds on `distroless/cc`, whose glibc is LGPL-2.1-or-later, and
`Dockerfile.ops` on Alpine, whose busybox is GPL-2.0. Both are unmodified upstream layers
redistributed under their own terms, and neither is linked into the Rust binary, which
stays permissive either way. The CycloneDX SBOM from `./scripts/ci-local.sh sbom` comes
from `cargo cyclonedx` and so inventories the Rust graph only. Scan the image itself
(Trivy, syft) for an OS-level inventory. `THIRD-PARTY-LICENSES.md`, the per-crate
attribution bundle, is copied into the image.

### Building your own image

The `Dockerfile` compiles from source and takes the Cargo feature set as a build argument.
`FEATURES` defaults to `full` (S3 + Vault + PME). Add `otel` to compile in the optional OTLP
export seam — traces, and the opt-in metrics push — which is what a deployment wants if it
exports at all: `[service].otlp_endpoint`, `otlp_metrics_interval_seconds` and both
`traceparent`-trust flags are inert without it, and the feature cannot be turned on later
without rebuilding. A `full,otel` build exports over `https://` directly to an authenticated
intake, so no collector is needed in front of it.

Two header mechanisms exist, read by different layers. Pick one per deployment rather than
setting both:

| Variable | Read by | Shape |
| --- | --- | --- |
| `GDI_NODE__SERVICE__OTLP_HEADERS__AUTHORIZATION` | the node, as an env overlay onto `[service].otlp_headers` | the header value verbatim: `ApiKey <key>` |
| `OTEL_EXPORTER_OTLP_HEADERS` | the OpenTelemetry SDK's own exporter, before the node sees it | the whole comma-separated header list, values URL-encoded per the OTel specification: `Authorization=ApiKey%20<key>` |

The second is what `deploy/kubernetes/components/push-telemetry` uses, because it comes from
a Secret as one opaque string. The first keeps the credential in the node's own config
surface, so `check-config` reports it. Mind the encoding difference: a `%20` written into
the node-side variable is sent literally.

Pass the provenance arguments too, or `/version` and `gdi_build_info` report `unknown`:

```bash
docker build \
  --build-arg FEATURES=full,otel \
  --build-arg GITHUB_SHA="$(git rev-parse HEAD)" \
  --build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" \
  -t <registry>/gdi-node-standalone:<tag> .
docker push <registry>/gdi-node-standalone:<tag>
```

**With `otel` compiled in, trace volume is partly chosen by callers.** The management plane
opens and exports a span only when the caller supplies an `x-request-id`, so anything that
can reach that port can turn a free poll into an exported span; and a package's
`{id}.state.json` can mark its `traceparent` not-sampled (`-00`), which suppresses that
ingest's spans entirely. The first is how an orchestrator asks to be correlated and the
second is standard W3C sampling, but size the collector for traffic you do not fully
control. `otel` is a diagnostic build, never required to serve.

Deployments that pin by digest — recommended, since a tag is mutable — read it back from the
push output, or with `docker inspect --format '{{index .RepoDigests 0}}' <image>`.

## Deployment shapes

| Shape | When | Config |
| --- | --- | --- |
| **Minimal** (inbox-only, plaintext at rest) | a local end-to-end trial run | `compose/node.minimal.toml` via `docker compose -f docker-compose.minimal.yml up -d --build`: the container form of the [README's Quickstart 1](../README.md#quickstart-1--see-it-work). Its inbox is inside the container — see [Feeding the minimal stack's inbox](#feeding-the-minimal-stacks-inbox) |
| **S3** (S3 ingest, disk key, no Vault or PME) | the common networked public-data node | `compose/node.s3.toml` via `COMPOSE_PROFILES=garage docker compose -f docker-compose.yml -f docker-compose.s3.yml up -d`. Mint the node identity first (below), or the `keyinit` one-shot exits 1 and the stack does not start. [`node.quickstart.toml`](../node.quickstart.toml) is the bare-metal counterpart — the same S3-plus-disk-key posture, though it keeps the default split beacon prefixes where `compose/node.s3.toml` mounts one combined `/beacon/v2`; check `check-config`'s registration URLs against whichever you deploy. The same file, with no profile, runs against a bucket of your own: [Running against your own backends](#running-against-your-own-backends) |
| **Full dev** (S3 + Vault/OpenBao + at-rest PME) | exercising the full secrets path | `compose/node.full.toml` via `docker-compose.yml`. `up -d` alone is not enough; provision the secrets first (below) |

**On Kubernetes, S3 is the supported ingest channel.** The three shapes above are the
bare-metal and Compose ones; [`deploy/kubernetes/`](../deploy/kubernetes/README.md) is the
cluster form of the S3 shape. A provider uploads, the node polls, and nothing has to reach
into the pod — which matters because the runtime image is distroless: `kubectl cp` into it
fails (`exec: "tar": executable file not found`), and the dataset tool's inbox verbs only
know local directories. A node with no object store can still run the inbox shape there via
the `inbox` component, which adds an inbox volume and an ops sidecar carrying the two
binaries. The trade-offs it asks you to accept — plaintext at rest, operator-performed
drops, `pods/exec` as the install path — are in that README's "Getting a dataset in on
Kubernetes".

**Mint the node identity before the S3 stack.** It mounts the key from
`compose/keys/node.c4gh`, which is gitignored and therefore absent in a fresh checkout. A
`keyinit` one-shot installs it for the node's uid and exits 1 if the file is missing, so the
stack refuses to start rather than come up keyless. Both the one-shot and the
`./compose/keys` bind live in `docker-compose.s3.yml`; the full-dev stack has neither,
because its identity is not a file at all — `compose/node.full.toml` carries no `[keys]`
block and sources the identity from Vault (`[vault].kv_path`), which is what the two extra
steps below provision:

```bash
gdi-node-standalone --config compose/node.s3.toml identity init \
    --file compose/keys/node.c4gh
```

`--file` is required here because the path the config names (`/keys/node.c4gh`) is the
in-container one. `scripts/dev-reset.sh` keeps this key unless you pass `--keys`.

**The full dev stack needs two more steps after `up -d`**, because its identity and S3
credentials live in the secrets backend rather than on disk. Without them the node
crash-loops on `Vault secret load failed: vault returned status 404`:

```bash
docker compose up -d
docker compose run --rm setup       # enable KV v2 + Transit, write the S3 creds and master key
docker compose run --rm gdi-node-standalone identity init --ensure   # node key -> Vault KV
docker compose up -d gdi-node-standalone
```

`setup` is idempotent and `identity init --ensure` refuses to clobber a live identity, so
both are safe to re-run. When it is up, `/health/ready` reports `vault: ok` and
`at_rest: ok`.

The S3 profile is the production-shaped path: it serves public aggregated data, so
volume-level at-rest encryption is the appropriate baseline and there is no secret-wrapping
key to manage. Run the shipped `full` binary with `[vault]` omitted, which leaves the Vault
and PME subsystems dormant, or build a smaller `--features s3` binary. The full dev stack
(Garage + OpenBao + PME) is a dev convenience for exercising the encrypted-at-rest path end
to end, not a production recipe. See the [`compose/`](../compose/) stacks.

The bundled OpenBao in that stack is persistent: it uses file storage on a named volume and
auto-unseals via a static seal, so the node crypt4gh identity and the Transit master key
survive `docker compose down`/`up`, `stop`/`start`, a host reboot and `--force-recreate`.
The HashiCorp Vault profile is persistent too, but has no static-seal equivalent, so it
keeps a stored 1-of-1 Shamir key and comes back sealed after a restart until the
`secrets-init` one-shot replays that key.

To start genuinely clean, run `scripts/dev-reset.sh --yes`. It destroys the secrets and data
volumes together, because removing only one leaves live data outliving the key that can read
it. Preview with `--dry-run`; the hand-minted `compose/keys/node.c4gh` is kept unless you
pass `--keys`.

> The dev secrets backend is dev-only: no TLS, and a root-policy token with a fixed id.
> Durable is not the same as production-shaped.

**Keep `[[s3.buckets]].allow_http = false` (the default) on every real bucket.** It permits
a plaintext `http://` endpoint and exists for the loopback dev backends the `compose/`
configs point at. Over a network it puts the package bytes in the clear and, with no
producer-authenticity check and a length-only download verify, lets an on-path attacker
substitute a same-length body. The preflight only warns, and only when the deployment
declares itself production — `[beacon].environment = "prod"` or
`[beacon.configuration].production_status = "PROD"` — *and* the endpoint is non-loopback, so
a dev config carrying `allow_http = true` will start anywhere. Check the value yourself
before the config leaves your machine.

**Multiple providers.** One node fronts many providers by repeating `[[s3.buckets]]`, one
bucket per provider, because the trust boundary is the bucket. The shipped configs show a
single bucket; the annotated [`node.example.toml`](../node.example.toml) documents the
multi-bucket shape inline — the per-bucket credential env indices
`GDI_NODE__S3__BUCKETS__<i>__…` against the Vault `{name}_access_key_id` keys, and the
per-channel health and metric labels. Two operational consequences before you add the second
bucket: the ingest pool is node-wide, so `ingest_concurrency` is shared across all
providers; and one unreachable bucket delays the whole node's cold start by up to
`[service].startup_reconcile_timeout_seconds` (default `30`), after which it serves with
`ready: true, degraded: true`. See
[operating.md §1](operating.md#1-health-and-readiness-endpoints).

### Feeding the minimal stack's inbox

The minimal stack's inbox is a named volume inside the container, so the tool's
`deploy --inbox` / `publish --inbox`, which need a host-side directory, do not apply. Build
the staging directory on the host and copy it in. Keep `--build` on the first `up`:
`gdi-node-standalone:latest` is a tag this build produces locally, never one pulled from a
registry, and that first build compiles the arrow/parquet/noodles tree from source.

```bash
GITHUB_SHA=$(git rev-parse HEAD) SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) \
  docker compose -f docker-compose.minimal.yml up -d --build
until curl -fsS http://localhost:9090/health/ready; do sleep 2; done   # management plane

# Build the bundled sample. Start from an empty build/: each run mints a new id and nothing
# prunes the directory, so a leftover makes $DATASET_ID below more than one line.
rm -rf build
gdi-dataset-tool build crates/gdi-dataset-tool/tests/fixtures/covid-package.yaml --cc EE -o build
DATASET_ID=$(ls build)
CID=$(docker compose -f docker-compose.minimal.yml ps -q gdi-node-standalone)

# `docker cp` keeps the host uid, so land the copy under a dot-prefixed name (the scanner
# ignores those), chown it to the node's uid, then rename it into place. Ingesting a
# host-owned directory leaves the node unable to remove it afterwards.
docker cp "build/$DATASET_ID" "$CID:/var/lib/gdi-node-standalone/inbox/.$DATASET_ID.tmp"
docker run --rm --volumes-from "$CID" --user 0 busybox:1.38.0 sh -c \
  "chown -R 65532:65532 /var/lib/gdi-node-standalone/inbox/.$DATASET_ID.tmp && \
   mv /var/lib/gdi-node-standalone/inbox/.$DATASET_ID.tmp /var/lib/gdi-node-standalone/inbox/$DATASET_ID"

# The visibility sidecar, copied in separately. A dataset whose sidecar has not arrived yet
# is `hidden`, so wait for `visible` and bail only on `error`. Written to a temp dir, not
# the checkout: a stray file in the tree makes the gate's key check report NOT RECORDED.
sidecar="$(mktemp -d)/$DATASET_ID.state.json"
echo '{"state":"visible"}' > "$sidecar"
docker cp "$sidecar" "$CID:/var/lib/gdi-node-standalone/inbox/$DATASET_ID.state.json"
for _ in $(seq 1 60); do
  S=$(curl -fsS "http://localhost:9090/datasets/$DATASET_ID/state" || echo '{}')
  jq -e '.state=="visible"' <<<"$S" >/dev/null && break
  jq -e '.state=="error"' <<<"$S" >/dev/null && { echo "dataset ingestion failed: $S"; break; }
  sleep 2
done

# `compose/node.minimal.toml` mounts the Beacon at the combined `/beacon/v2` prefix:
curl -X POST http://localhost:8080/beacon/v2/g_variants -H 'content-type: application/json' \
  -d '{"query":{"requestParameters":{"referenceName":"3","start":[45823239],"referenceBases":"T","alternateBases":"C","assemblyId":"GRCh38","requestedGranularity":"RECORD"}}}'
```

Without `GITHUB_SHA`/`SOURCE_DATE_EPOCH` the image builds and runs, but `/version` and
`gdi_build_info` report `git_sha unknown`.

### Overriding the dev-stack host ports

Every host port every `docker-compose*.yml` publishes is a
`${GDI_HOST_PORT_<NAME>:-<default>}` interpolation, so an operator, or a second stack, can
shift the whole thing sideways with one exported variable per port while the defaults stay
what this doc and the README quickstart promise. This is what lets
[`scripts/e2e/run.sh`](../scripts/e2e/run.sh), `run-observability.sh` and `run-full.sh` run
beside a developer's own dev stack, or beside each other. `GDI_E2E_PROJECT_SUFFIX` is
appended to each script's own compose project name so two runs can coexist.

| Variable | Default | Service | Compose file(s) |
| --- | --- | --- | --- |
| `GDI_HOST_PORT_PUBLIC` | 8080 | node public plane (Beacon/FDP) | `docker-compose.yml`, `docker-compose.minimal.yml` |
| `GDI_HOST_PORT_MANAGEMENT` | 9090 | node management plane (health/metrics/oracle), loopback | `docker-compose.yml`, `docker-compose.minimal.yml` |
| `GDI_HOST_PORT_OPENBAO` | 8200 | secrets backend (OpenBao or Vault — alternatives, same host port), loopback | `docker-compose.yml` |
| `GDI_HOST_PORT_GARAGE` | 3900 | Garage S3 API, loopback | `docker-compose.yml` |
| `GDI_HOST_PORT_GARAGE_ADMIN` | 3903 | Garage admin API, loopback | `docker-compose.yml` |
| `GDI_HOST_PORT_MINIO` | 9000 | minio S3 API (deprecated backend), loopback | `docker-compose.yml` |
| `GDI_HOST_PORT_MINIO_CONSOLE` | 9001 | minio console UI, loopback | `docker-compose.yml` |
| `GDI_HOST_PORT_PROMETHEUS` | 9089 | Prometheus UI/API, loopback | `docker-compose.observability.yml` |
| `GDI_HOST_PORT_ALERTMANAGER` | 9093 | Alertmanager UI, loopback | `docker-compose.observability.yml` |
| `GDI_HOST_PORT_BLACKBOX` | 9115 | blackbox-exporter, loopback | `docker-compose.observability.yml` |
| `GDI_HOST_PORT_LOKI` | 3100 | Loki query API, loopback | `docker-compose.observability.yml` |
| `GDI_HOST_PORT_TEMPO` | 3200 | Tempo query API (Grafana datasource), loopback | `docker-compose.observability.yml` |
| `GDI_HOST_PORT_TEMPO_OTLP` | 4319 | Tempo's own OTLP/gRPC receiver (host-shifted; the node sends to Alloy, not here), loopback | `docker-compose.observability.yml` |
| `GDI_HOST_PORT_ALLOY` | 12345 | Alloy UI, loopback | `docker-compose.observability.yml` |
| `GDI_HOST_PORT_ALLOY_OTLP_GRPC` | 4317 | Alloy's OTLP/gRPC receiver, loopback | `docker-compose.observability.yml` |
| `GDI_HOST_PORT_ALLOY_OTLP_HTTP` | 4318 | Alloy's OTLP/HTTP receiver (the node's `GDI_NODE__SERVICE__OTLP_ENDPOINT` target), loopback | `docker-compose.observability.yml` |
| `GDI_HOST_PORT_GRAFANA` | 3000 | Grafana UI (anonymous Admin, dev only), loopback | `docker-compose.observability.yml` |
| `GDI_HOST_PORT_TOXIPROXY` | 8474 | toxiproxy admin API, loopback | `docker-compose.chaos.yml` |
| `GDI_E2E_PROJECT_SUFFIX` | *(empty)* | appended to each e2e script's own `-p` compose project name | n/a — read by `scripts/e2e/*.sh`, not a compose file |

`docker-compose.s3.yml` and `docker-compose.external.yml` publish no ports of their own;
they layer onto the ports above via `docker-compose.yml`.

### Sharing a bucket with something that is not a data source

Sometimes the bucket is not yours alone: an institution hands out a prefix rather than a
bucket, one bucket hosts a test node beside a production one, or the same bucket holds your
own backups. **`[[s3.buckets]].prefix` confines the channel to one key prefix.** The
listing, the packages, the `.state.json` and `.metadata.json` sidecars, `_sync_marker.json`
and the `_status/` writebacks all resolve under it, and the node issues no request outside
it.

Set it together with a prefix-scoped credential: grant `…/<prefix>*` plus `ListBucket`
conditioned on the same prefix. The two are one control. The credential is what actually
denies the rest of the bucket, and the prefix is what keeps the node from needing it, since
an unconfined node's root listing fails `AccessDenied` against such a credential and takes
the channel down. Confining the node without narrowing the credential leaves the node
holding access it no longer uses; narrowing the credential without confining the node breaks
it.

**Adopting a prefix on a bucket that already holds datasets needs a restart, not a
`SIGHUP`.** `prefix` decides which objects the channel can see, so changing it live would
point the monitor at a keyspace that legitimately lists nothing — indistinguishable to the
reconcile from the provider having deleted everything, which evicts the datasets and deletes
them from `data_dir`. The node therefore refuses to apply the change on a reload: it logs a
loud WARN, keeps polling the old keyspace, and waits for you to restart. Move the objects
under the prefix first, then set it and restart.

The writer must carry the same prefix: `gdi-dataset-tool`'s profile has the same key,
`[profiles.<name>.s3].prefix`. Reader and writer address one keyspace, so a prefix set on
one side only presents as uploads the node never lists, or as a `list` that reports an empty
bucket the node is happily serving from. A prefix that would not survive S3 key
normalization unchanged — a leading `/`, `//`, a `.` or `..` segment, or a character outside
the accepted set — is rejected at boot rather than silently rewritten.

This is not a way to put two providers in one bucket. See the next section: a prefix is not
a trust boundary, because everyone with PUT on the bucket can still write anywhere in it. It
is for keeping the node *out* of data that is not its own.

### One provider per bucket — a bucket is a trust domain

**An S3 bucket is a single trust domain, not a multi-tenant surface.** Everyone holding PUT
access to a bucket is trusted with every dataset in it, not just their own. The reason is
the visibility sidecar: `{id}.state.json` is plain, unsigned JSON dropped beside the package
(see [package-format.md](package-format.md#overlay-sidecars)), and nothing binds it to
whoever produced the package it names. Any writer who can PUT into the bucket can therefore
flip any other writer's dataset between `visible` and `hidden`, without the package, its
writer key, or any node credential.

**`writer_policy = "enforce"` does not close this.** It recovers the crypt4gh writer key of
the `{id}.tar.c4gh` package and checks it against the channel's allow-list, so it governs
who may *publish a package*. The sidecar carries no crypt4gh envelope and hence no writer
identity, so there is nothing for an allow-list to check, and visibility remains
unauthenticated within the bucket under every policy value.

So give each provider its own bucket, and credentials for that bucket only. That is what
makes the per-bucket allow-lists, health and metrics mean what they appear to mean.

Signing the sidecar is not implemented. An attacker holding bucket write can also delete the
package outright, overwrite `_sync_marker.json`, or flood the bucket past `MAX_BUCKET_OBJECTS`
until reconcile fails closed — but every one of those is an availability action. Flipping
another writer's withheld dataset to `visible` is a disclosure, and it is the one capability
the sidecar adds that the alternatives do not substitute for. On a node with
`writer_policy = "enforce"` and an allow-list holding only the legitimate provider's
fingerprint, an attacker's own package is refused (`writer-rejected`,
`gdi_ingest_writer_unknown_total`) while a bare `{id}.state.json` for that provider's
withheld dataset publishes it to the public plane within one poll interval.

Signatures would close a confidentiality gap, at the cost of a key to manage. Credential
separation per bucket removes the attacker outright, whereas signing only narrows one route
for an attacker you have already admitted to the trust domain. That reasoning holds only if
you do give each provider its own bucket. If you do not, then within that bucket you have
an unauthenticated publish primitive, and no value of `writer_policy` changes it.

Provenance will not help you reconstruct such a flip either: the victim dataset still
reports the legitimate writer's fingerprint, because the package was never touched. The only
record tying the flip to the sidecar is the `sidecar-state-change` entry in the audit log
([operating.md §21](operating.md#21-audit-log)). If you run one bucket for more than one
provider despite the above, that event is your sole evidence, so a sidecar transition to
visible also emits an alarm line (`event.action = "dataset.sidecar.release"`,
`tags: ["Alert"]` under `LOG_FORMAT=ecs`; see
[operating.md §15](operating.md#15-logs-and-log-configuration)). The withhold direction is
not tagged, because failing closed is the safe direction.

Read it as detection, not prevention. The node cannot tell a legitimate publication from a
hostile one — that is what the missing writer identity costs — so it alarms on every
release, one line per publication, and you correlate those against your own record of
intended publications. What would prevent the flip is a signed sidecar the node verifies
against the same per-channel fingerprint allow-list `writer_policy` uses, which is a
wire-contract change rather than a config one.

## Running against your own backends

The node is endpoint-agnostic: `[vault]` takes any address, namespace and auth method, and
`[[s3.buckets]]` takes any endpoint, region, addressing style and credentials.

For a container stack that runs only the node against your infrastructure, layer
[`docker-compose.external.yml`](../docker-compose.external.yml) over the base file, with
[`.env.external.example`](../.env.external.example) copied to `.env.external` as the
template. It is an override rather than a stack of its own — on its own it does not even
parse, because it defaults no credential — and the env file must be passed explicitly,
since the committed `.env` selects the bundled backends:

```bash
cp .env.external.example .env.external   # then fill it in
docker compose --env-file .env.external \
  -f docker-compose.yml -f docker-compose.external.yml up -d
```

`--env-file` replaces `.env` rather than adding to it, which is the point: `.env` sets
`COMPOSE_PROFILES=garage,openbao`, and inheriting that would start the very backends this
shape exists to avoid. It starts no bundled backend and defaults no credential.

**Disk key instead of a secrets backend.** When the node's identity is a file rather than
a Vault entry, use the S3 override: [`docker-compose.s3.yml`](../docker-compose.s3.yml) as
in the S3 row above, with no profile so no Garage starts, and every S3 fact supplied by
variable. `GDI_NODE_CONFIG` mounts a `node.toml` of your own, for when
`compose/node.s3.toml`'s `allow_http = true` and `path_style = true` do not fit your
endpoint. Mint the identity into `compose/keys/node.c4gh` first, exactly as for the S3 row:

```bash
export S3_ACCESS_KEY=… S3_SECRET_KEY=…           # in the shell, never in a file
COMPOSE_PROFILES= GDI_S3_ENDPOINT=https://s3.example.org GDI_S3_REGION=eu-central-1 \
  GDI_S3_BUCKET=my-bucket GDI_NODE_CONFIG=/absolute/path/node.toml \
  docker compose -f docker-compose.yml -f docker-compose.s3.yml up -d
```

Unlike the external override, this file keeps the dev credentials as defaults so the Garage
quickstart stays one command. A forgotten export therefore shows up as the S3 subsystem
failing in `/health/ready` rather than at `up`. It never shows as the dev key working
against your bucket.

### What to create in your secrets backend

Vault and OpenBao speak the identical KV v2 + Transit API, so one setup serves either.
[`compose/setup.sh`](../compose/setup.sh) is the executable reference for all but one row
below: it creates the KV mount, writes the S3 credentials, and enables the Transit mount and
key. The node identity path is not its job — that is minted separately by
`gdi-node-standalone identity init`, as the full-dev recipe above shows and the row itself
notes.

| Thing | Config key | Notes |
| --- | --- | --- |
| KV v2 mount | `[vault].kv_mount` (default `secret`) | Can be an existing mount in a shared Vault |
| Node identity path | `[vault].kv_path` | Holds `c4gh-<epoch-millis>` fields; minted by `identity init` |
| S3 credentials path | `[vault].s3_path` | Keys are `{channel}_access_key_id` and `{channel}_secret_access_key`, where `{channel}` is each `[[s3.buckets]].name` |
| Transit mount | `[vault].transit_mount` (default `transit`) | Only for at-rest PME |
| Transit key | `[vault].transit_key` | `aes256-gcm96`. Its presence is the PME switch |

### Least-privilege policy

The serving node reads KV and calls Transit. It needs no KV write capability: the write
paths belong to the operator-run provisioning commands, which should hold a separate
credential.

```hcl
# Serving policy — what the running node needs, and nothing more.
# Substitute your own mounts/paths if they differ from the defaults.
path "secret/data/gdi-node-standalone/c4gh-identities" { capabilities = ["read"] }
path "secret/data/gdi-node-standalone/s3-credentials"  { capabilities = ["read"] }
path "transit/datakey/plaintext/gdi-node-standalone-at-rest" { capabilities = ["update"] }
path "transit/decrypt/gdi-node-standalone-at-rest"           { capabilities = ["update"] }
```

```hcl
# Provisioning policy — for `identity init` / `identity rotate` only.
# `read` is required, not optional: both commands read the path before writing it.
# Do not give this to the serving node.
path "secret/data/gdi-node-standalone/c4gh-identities" { capabilities = ["read", "create", "update"] }
```

**`read` is not optional here.** `identity init` issues a KV read first, to refuse
overwriting an existing identity, and `identity rotate` reads to merge additively. Vault
answers a policy without `read` with `403`, which the client classifies as transient, since
a `403` normally means a lapsed token, so the command aborts with
`cannot reach Vault to check for an existing identity` — a message that sends the operator
to network reachability and token TTLs when the fault is the missing capability. Granting
`create` alone does not produce a safer init; it produces an init that cannot run.

Neither `identity init` (`cas = 0`) nor `identity rotate` (an additive cas-merge) ever
deletes or overwrites a key, so the irreplaceable identity is protected by the commands
themselves. You can drop `update` from an init-only credential, but not `read`.

### Authenticating the node

Supply exactly one method.

**AppRole** — the norm for a long-running node; the client renews and re-authenticates.

```bash
vault write auth/approle/role/gdi-node-standalone \
    token_policies="gdi-node-standalone-serving" \
    token_ttl=1h token_max_ttl=24h
vault read  auth/approle/role/gdi-node-standalone/role-id          # -> [vault].role_id
vault write -f auth/approle/role/gdi-node-standalone/secret-id     # -> GDI_NODE__VAULT__SECRET_ID
```

**Agent sidecar (`[vault].token_file`)** — the credential-free shape, and the recommended
one where you can run an agent. A Vault Agent or Secrets Operator authenticates by whatever
method your server supports (Kubernetes, JWT/OIDC, AWS IAM, TLS cert), renews continuously,
and writes the current token to a file, ideally on an in-memory volume. The node reads that
file and re-reads it when the mtime changes, so no static credential is stored anywhere and
the node implements none of those auth methods itself.

Because the agent owns renewal, the node performs none: `VaultRenewalFailing` and
`VaultTokenLeaseTooShort` are both structurally unable to fire in this mode. Alert on
`gdi_vault_token_file_age_seconds` (`VaultTokenFileStale`) instead — see
[operating.md §8](operating.md#8-vault-token-health), which tabulates which signal watches
which auth mode.

**Static token** — simplest, but it lapses at its own TTL and the node does not renew it.
Supply one whose TTL outlives the process.

### Which S3 credential is actually in force

`GDI_NODE__S3__BUCKETS__<i>__ACCESS_KEY_ID` and `…__SECRET_ACCESS_KEY` override the config
file, and Vault overrides both — but only when `[vault].s3_path` is set. A `[vault]` block
present for the node identity or Transit alone supplies no S3 credentials, so a stale
environment variable silently wins over the value you just edited in the file.

The node reports the answer at startup, once per bucket:

```
INFO s3 channel target and credential source channel=primary source=vault keyspace=gdi-primary/staging
```

`keyspace` is the `bucket/prefix` this channel can see, the same shape `check-config`
prints, so the two sides compare by eye. It is not called `target`: that is the tracing
field the audit stream is routed on, and an event field of the same name emits a duplicate
JSON key.

`source` is `vault` (an `s3_path` override), `config`, or `anonymous` (no credentials, so
requests are unsigned). `config` covers both the TOML literal and the env overlay, because
the env value is merged into the config during load, so by the time the node reads a bucket
the two are indistinguishable. That is why this trap bites: the line tells you Vault is not
in play, and from there you check your environment before your file.

### Private CA

There is no CA-bundle config knob. The binary merges the bundled Mozilla roots on top of the
host's platform trust store, so a publicly-trusted certificate needs nothing. For an
internal PKI, install your CA into the container's trust store; for the distroless image,
add it to `/etc/ssl/certs/ca-certificates.crt` in a derived image. A dedicated knob is
deferred until a deployment needs it.

## Registering with a Beacon network

A Beacon network — the GDI allele-frequency network, whose aggregator is the EGA
`beacon-network-facade` — is given the node's **aggregated** beacon base URL, the mount
`[beacon].aggregated_base_path` serves, for example
`https://beacon.example.org/aggregated/beacon/v2`. It reads the node's identity from
`GET {prefix}/info`. Two of the fields it reads are optional in the Beacon schema and unset
by default here. Treat both as required when you register: at least one aggregator
implementation has been observed to handle a member that omits them badly, degrading the
network's member listing rather than that member's entry alone. Queries still aggregate, so
the symptom is easy to miss and hard to attribute back to your node. **Set both before you
register:**

```toml
[beacon]
# The human-facing entry point for this beacon (a portal or landing page). Emitted as
# `alternativeUrl`; the network shows it as the member's link.
alternative_url = "https://gdi.example.org/beacon"

[beacon.organization]
# Absolute URL of the organization's logo. Emitted as `organization.logoUrl`; the network
# shows it next to the member name.
logo_url = "https://gdi.example.org/assets/logo.svg"
```

Both are plain strings the node emits verbatim — it never fetches them — and omits entirely
when unset, so the failure above is invisible in the node's own logs. The rest of what a
registry reads is already required or defaulted: `[beacon].id`, `[beacon].name`,
`[beacon].environment`, `[beacon.organization].id` and `.name`, and `welcomeUrl`
(`[service].base_url`). See [api.md](api.md) for the full `/info` shape, and
[`node.example.toml`](../node.example.toml) for the annotated `[beacon]` block.

**Register the aggregated prefix, and only a split mount's.** With the default split layout
(`aggregated_base_path` ≠ `sensitive_base_path`) the aggregated mount advertises
`genomicVariant` and `dataset` only, which is what the allele-frequency network should hold.
Setting the two paths equal collapses them into one combined mount, whose
`GET {prefix}/map` also advertises `individual` and whose `/individuals` answers an empty
`200`, because this node serves no individual-level data. That advertisement invites an
individual-level registration, and the portal's collector keeps only `dataset` result sets
with `resultsCount > 0` and then intersects them with the catalogue, so a node registered
there drops out of every portal search carrying a Beacon facet. Register a combined mount in
an individual-level network only if the node really serves individuals.

## Compatibility

The declared support set. No prebuilt artifacts are published yet, so build the row you
need from source. `scripts/ci-local.sh` (see [`CONTRIBUTING.md`](../CONTRIBUTING.md))
build-verifies the Linux rows with its `cross` and `cross-arm` legs; both live in the
`release` target rather than `all`, so treat a row as verified once you have run it
yourself.

| Dimension | Supported / tested |
| --- | --- |
| **Rust toolchain** (build) | MSRV **1.96** — a ratchet, raised only when a dependency or a feature requires it, never lowered. Newer stable toolchains build too. |
| **Service binary** | Linux `x86_64` and `aarch64`, both `gnu` (glibc) and `musl` (static); the release matrix builds all four. Build-verify them locally with `ci-local.sh cross` (x86_64) and `cross-arm` (aarch64). |
| **`gdi-dataset-tool` binary** | Linux `x86_64` (`gnu` + static `musl`); macOS `aarch64` (Apple silicon only); Windows `x86_64-msvc`. No prebuilt aarch64-Linux tool binary — build from source with `cargo build --release -p gdi-dataset-tool`. |
| **Container image** | `linux/amd64` only (distroless `cc-debian13`). On `arm64`, run the bare-metal `aarch64` binary. |
| **glibc floor** | Guarded at ≤ 2.28 → RHEL/Rocky/Alma 8+, Debian 10+. Alpine and musl via the static `musl` build. |
| **Object store (S3 API)** | Garage, Ceph RGW, MinIO — S3-compatible, path- or virtual-host style. |
| **Secrets backend** | HashiCorp Vault or OpenBao (KV v2 + Transit; API v1). |
| **Public API contracts** | GA4GH Beacon v2.2.0; FAIR Data Point / DCAT-AP. |

## Resource baseline

Size a node from its configured ceilings, not from the size of its data. Disk follows the
ingest caps. RAM follows the **query** path: the ingest path streams, so its footprint is
flat and independent of package size, while a query holds a page of rows and a decoded
parquet row group.

| Resource | Baseline | Driver |
| --- | --- | --- |
| **CPU** | ~1–2 vCPU serving-only. During ingest budget ~1 core per ingest worker, so ~5–6 vCPU at the default `[service].ingest_concurrency` of `4`. | VCF→parquet, zstd and crypt4gh are CPU-bound. Broad Beacon queries add to it. |
| **RAM** | The retained pages plus the decode working set, which are separate terms — see below. Provision `max_total_query_bytes + scan_pool_cap × max_parquet_row_group_bytes`: 16 GiB at the shipped defaults. | Query path. |
| **Disk** | `ingest_concurrency × 4 × max_package_bytes`, plus ~25 % headroom, on `data_dir`. At the shipped values (4 workers, 16 GiB per package) that is 4 × 4 × 16 = 256 GiB peak, ≈ 320 GiB with headroom. Size from 4×, not 3×; `.incoming/` self-cleans to zero afterwards. | Ingest scratch. |
| **Override store** | Kilobytes: one small JSON per suppressed or corrected dataset. Size is irrelevant, durability is not — it is the only state re-ingest cannot rebuild, so put `override_dir` on separately-backed storage rather than sizing for it. | Operator intent (see [operating.md §17](operating.md#17-disaster-recovery)). |

**Measured, for scale** (release build, one 6-core Linux host, 2026-09; inputs generated
by `scripts/gen-sample-vcf.py generate --synthetic-sites N`, the realistic
twelve-population sites-only export shape). The table above is what the caps *permit*;
this is what a node *does*:

| Sites | VCF (BGZF) | `build` (peak RSS) | Parquet in `data_dir` | Ingest | Idle RSS |
| --- | --- | --- | --- | --- | --- |
| 1 M | 463 MB | about a minute (136 MB) | 103 MB, 323 files (~9 B per row) | under a minute | 13 MiB |
| 10 M | 4.6 GB | about ten minutes (674 MB) | 992 MB, 323 files (~8 B per row) | minutes | 13 MiB |
| 30 M | 13.9 GB | tens of minutes (712 MB) | 2.96 GB, 323 files (~8 B per row) | minutes | 13 MiB |

Sizes are the stable part, and both re-measured rows land on the printed figure: 1 M gave
463,945,598 B of VCF and 103,141,618 B across 323 Parquet files (8.58 B per row); 10 M
gave 4,631,875,101 B and 992,166,908 B across 323 files (8.25 B per row). The 30 M row is
not re-measured, but 360 M rows at ~8.2 B is 2.95 GB, which is the figure shown. Build
peak RSS is the softest number here. The 10 M build measured 674 MB against the 624 MB
recorded earlier, so treat it as ±10 % between runs rather than a constant. Idle RSS is
flat: it does not move with the number of sites, nor with the number of datasets in
`data_dir`. Fourteen fresh starts over 1, 2 and 4 datasets all read 12.5–13.0 MiB. The
durations are from a shared host with other work running; your hardware will differ.

**What concurrent paging costs, and why one number will not do it.** Query memory is the
term that decides a memory limit, and it depends on how long the load runs, so a single
figure is only as good as its window. Measured on one 1 M-variant dataset, `POST
/g_variants` over `chr1:1,000,000-9,000,000` (1833 matching rows) at `RECORD`
granularity, lite release build, one 6-core host:

| Load | Peak RSS |
| --- | --- |
| 1 client, `limit=1000`, 20 s | 43 MiB |
| 8 clients, `limit=1000`, 20 s | 118 MiB |
| 32 clients, `limit=10` / `limit=100`, 20 s | 90 MiB / 104 MiB |
| 32 clients, `limit=1000`, 20 s | 264–286 MiB (two runs) |
| 32 clients, `limit=1000`, 120 s | 1103 MiB |
| 32 clients, `limit=1000`, 180 s | plateaus at 0.96–1.05 GiB, peak 1182 MiB |
| 64 clients, `limit=1000`, 20 s | 444 MiB, and shedding begins |

Two things follow. **It plateaus, but not quickly**: RSS climbs for about a minute and
then oscillates around 1 GiB. A burst test that stops at 20 s reports a quarter of the
steady-state cost. **It does not come back**: 120 s after the load stopped, RSS was still
920 MiB and flat, so a node that has served one busy minute keeps that resident. Size the
container limit for the plateau, not for the idle figure above.

**More datasets cost throughput, not memory.** A `g_variants` range query fans out over
every visible dataset, but `[service].query_concurrency` (default: follows
`ingest_concurrency`, so 4) bounds how many of those scans run at once, and each
concurrent scan is what retains rows. Measured at 4 clients, where nothing sheds, over
1, 2, 4 and 8 identical 1 M-variant datasets:

| Visible datasets | Peak RSS | over idle | per dataset | Throughput | p99 |
| --- | --- | --- | --- | --- | --- |
| 1 | 102 MiB | 87 MiB | 87 MiB | 53.2 rps | 0.15 s |
| 2 | 180 MiB | 165 MiB | 82 MiB | 26.8 rps | 0.28 s |
| 4 | 348 MiB | 332 MiB | 83 MiB | 12.9 rps | 0.52 s |
| 8 | 354 MiB | 339 MiB | 42 MiB | 6.1 rps | 1.29 s |

Memory grows by about 85 MiB per dataset up to the scan-pool width and then stops: the
eighth dataset adds nothing, because only four scans run at a time. Throughput falls
roughly as `1/n` instead, and latency rises with it. Held at 8 datasets for three minutes
the node settles at 396 MiB and stays there, which is a real plateau rather than a ramp.

At a realistic concurrency the same growth shows up as refusal rather than latency. At 32
clients over the same datasets, peak RSS went 269 → 537 → 877 → 1022 MiB while the share
of requests shed with `503` went 0 % → 82 % → 87 % → 97 %, and p99 went 1.2 s → 5.4 s. A
memory curve that flattens under that load means work is being refused, not that the cost
levelled off. At rest the cost is small: hydrating eight datasets instead of four moved
idle RSS from about 13 MiB to about 15 MiB.

Shedding also does not wait for `[service].max_concurrent_requests` to be exceeded by
client count: 64 clients shed against one dataset, and 32 clients shed as soon as a second
dataset is visible. Treat that limit as a backstop, not as the point where 503s start.
`scripts/soak/leak.sh` checks that RSS plateaus rather than climbing, but it drives a
single-position query at 8 clients, far below this regime, and it is not part of
`ci-local.sh all`.

**The retained page is the first memory term, and it is bounded.** A query retains its page,
not its match set: the scan applies the floor and the page window while folding, so
granularity barely changes the cost and `pagination.skip` does not accumulate. The bound is

```
datasets matched × max_page_limit × populations × ≈450 B
```

`skip` and `limit` apply **per dataset** ([api.md](api.md)), so a node serving *N* visible
datasets retains *N* windows rather than one. At the shipped `[beacon].max_page_limit` of
`1000` and the 512-population cap that is ≈ 220 MiB per matched dataset. Multiply by the
concurrency you admit: `max_concurrent_requests × 220 MiB` is 3.4 GiB at 16 and 13.8 GiB at
the shipped `[service].max_concurrent_requests` of `64`, which is above the 8 GiB
`[service].max_total_query_bytes`. A 512-population node at the shipped defaults therefore
sheds `503`s under that load unless you lower `max_concurrent_requests` or `max_page_limit`.
`deploy/kubernetes/` ships `max_concurrent_requests = 16`, a 3.4 GiB retained burst inside
the 8 GiB budget.

`max_total_query_bytes` is the process-wide ceiling on rows held across all in-flight
queries. Each scan's retention sink charges it as rows accumulate and sheds with a `503` the
moment the total is reached, so retained rows cannot exceed it. `[service].max_query_bytes`
is the same idea per request. How close they come to binding depends entirely on the page
size: at the default `[beacon].default_page_limit` of `10` a request retains tens of MiB and
the per-request cap is orders of magnitude above it, while at `max_page_limit = 1000`
against a 512-population dataset a request retains ≈ 220 MiB, so the process-wide ceiling is
reached by about 37 concurrent requests — fewer than the shipped `max_concurrent_requests`.

**The decode working set is the second term, and it is not bounded by either budget.** To
produce any rows, each admitted scan must first materialise a parquet row group, and that
allocation is live before a single row is charged. The scan pool admits
`query_concurrency × 4 + 16` concurrent scans, 32 at the defaults, so the floor under a
saturated pool is `scan_pool_cap × max_parquet_row_group_bytes`, and it sits **on top of**
`max_total_query_bytes` rather than inside it.

At the shipped defaults that is 32 × 256 MiB = 8 GiB, exactly `max_total_query_bytes`, so a
stock node boots silent. Raise `[service].max_parquet_row_group_bytes` (default
`268435456`) or `query_concurrency` past that and the node says so once at boot:

```
WARN beacon query memory: a saturated scan pool (32) decodes up to 17179869184 bytes of
parquet row groups at once, which exceeds [service].max_total_query_bytes (8589934592).
```

Treat that as a real sizing prompt: the failure mode for the decode term is an OOM kill, not
a shed request. Provision for the sum, or lower one of the two knobs.

That sum, 16 GiB at the defaults (8 GiB retained plus the 8 GiB decode floor), is the worst
case the node *permits*, and it is what a memory **limit** must be sized from. A memory
**request** is a scheduling reservation for the peak the configuration actually reaches, so
`deploy/kubernetes/` requests `12Gi`: the 8 GiB decode floor, which any saturated scan pool
reaches, plus the 3.4 GiB retained burst its `max_concurrent_requests = 16` admits. That is
also why that example ships no memory limit — see the comments on `resources` in
[`deploy/kubernetes/base/deployment.yaml`](../deploy/kubernetes/base/deployment.yaml).

**`ingest_concurrency` silently sets the query fan-out too.** `[service].query_concurrency`
is the per-query Beacon scan fan-out cap, and when unset it falls back to
`ingest_concurrency`, so raising ingest throughput from 4 to 8 also doubles the scan fan-out
and with it the peak memory and blocking-pool pressure of the read path. The two coincide
only while the knob is unset. Set `query_concurrency` explicitly whenever you tune
`ingest_concurrency`, or the CPU row above and the query terms stop being independent.
`gdi_query_concurrency` reports whichever value is in force.

**Populations, not disk size, are what a page costs.** A page holds `limit` variant groups
and each group carries one row per population, so the retained page is `limit × populations`
and the `POPULATION` column compresses well enough that disk size predicts it badly. At the
default page a high-population dataset costs little more than a low-population one; at
`limit = 1000` the population count is the multiplier, and a dataset at the 512-population
cap is the worst case a single dataset can impose. The response bytes grow with the page
too, and they are what the client must hold: a 1000-row page runs from about a megabyte at
six populations to tens of megabytes at the cap.

**The page limit is the memory knob, and the shipped cap is 1000 because the portal asks for
1000.** The GDI User Portal's position-range search sends `pagination.limit: 1000` and does
not page — it reads one `resultSet` and stops — so a GDI node must serve a 1000-row page or
every range search it answers is silently truncated to the cap. `default_page_limit` is
still `10`, so only a client that asks for a big page pays for one. Lower `max_page_limit`
to 100 if your node is memory-constrained and serves no portal, accepting that a portal
range search against it truncates; the clamp is visible either way, since the effective
limit is echoed in `meta.receivedRequestSummary.pagination`.

**One shape still scales with the match set: a block split across several files.** When one
block's populations come from several source VCFs — a per-population split, a supported
packaging shape — those files cover the same loci, so their `POS` spans overlap and no file
ordering makes the concatenation ascending. The scan cannot stream them: it buffers and
sorts the whole block before folding. That arm costs roughly `size_of::<AlleleRow>()` plus
three string allocations per matching row, about 300 B, and neither granularity nor `limit`
bounds it, because the buffer is built to order the rows at all, before anything decides
what to keep. It is bounded and shed rather than fatal: the buffer is charged against
`max_query_bytes` and credited back per block, so only the largest block's buffer is ever
resident, and a block that does not fit returns `400 query too large` with the node healthy.
If your packages split a block across files, size from the block's matching rows, and note
that lowering `max_query_bytes` converts the risk from memory into refused queries rather
than removing it.

Serving is stateless apart from the `data_dir` volume and the operator-override store, so
read replicas scale horizontally — S3 is the source of truth for dataset *content* — while
the single-writer ingest path is `Recreate`/RWO.

> **Every serving replica must see the override store.** Suppressions and metadata
> corrections are evaluated per process, from that process's own `override_dir`. S3 is not
> the source of truth for them, and re-ingest cannot rebuild them, since it restores each
> dataset to the source-resolved state an override exists to countermand. A replica that
> cannot read the store serves every withheld dataset, silently, because at startup an
> absent store is indistinguishable from one that never existed. A store that vanishes under
> an already-running replica is caught, because that reload keeps its last-good set; a
> replica that never saw the store has nothing to keep.
>
> Under the default (`<data_dir>/overrides/`) the store rides along with `data_dir`, so
> replicas inherit it only if they share that volume.
> [operating.md §17](operating.md#17-disaster-recovery) recommends relocating `override_dir`
> onto separately-backed storage. If you do, mount that volume into every serving pod,
> read-only. Serving only reads `suppressions/` and `overlays/`, and `reingest/` markers are
> matched on their stamp rather than consumed, so nothing on the serving path writes into
> `override_dir`. The operator CLI keeps a separate read-write mount. See
> [deploy/kubernetes/README.md](../deploy/kubernetes/README.md), which sizes the volume
> `ReadOnlyMany` on the serving replicas for that reason.
>
> Set `[service].require_override_store = true` on all of them so a replica that loses the
> mount refuses to serve instead of quietly disclosing, and watch the `OverrideStoreAbsent`
> alert.
