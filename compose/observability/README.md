# Observability overlay (optional)

A self-contained local observability stack for `gdi-node-standalone`, layered onto an
existing Compose stack with a second `-f`. It changes nothing by default: without
`-f docker-compose.observability.yml` the node runs unchanged. The overlay only *adds* —
it scrapes the management-plane metrics the node already exposes (`:9090` — `/metrics`,
`/health/live`, `/health/ready`) and adds logs and traces on top.

## What it adds

| Service | Image | Role |
| --- | --- | --- |
| **prometheus** | `prom/prometheus` | Scrapes five jobs — the node's `/metrics`, the blackbox probes, Alloy, Tempo and itself; evaluates the docs/operating.md §3 alert rules. |
| **alertmanager** | `prom/alertmanager` | Routes firing alerts to a dev "devnull" receiver (UI only, no notifications). |
| **blackbox-exporter** | `prom/blackbox-exporter` | Synthetic HTTP probes of `/health/ready`, `/health/live`, `/fairdp`. |
| **loki** | `grafana/loki` | Stores container logs. |
| **tempo** | `grafana/tempo` | Stores traces. |
| **alloy** | `grafana/alloy` | Single telemetry agent: OTLP receiver (traces → Tempo) + Docker-log collector (logs → Loki). |
| **grafana** | `grafana/grafana` | Dashboards + datasources, auto-provisioned. |

Every image is **pinned by digest** (tag **and** `@sha256:` — the tag is for the reader,
the digest is what Docker resolves) for reproducibility. The tags live in
`docker-compose.observability.yml`; see its `image:` lines. To move one, resolve the new
digest with `docker buildx imagetools inspect <image:tag>` and change both.

The overlay also **overrides the `gdi-node-standalone` service** to rebuild the image
with the `full,otel` feature set (`build.args.FEATURES=full,otel`) and points it
at Alloy (`GDI_NODE__SERVICE__OTLP_ENDPOINT=http://alloy:4318`), so traces flow
node → Alloy → Tempo. A rebuild is required — pass `--build`. It also sets the node's
`LOG_FORMAT=ecs` (the base compose defaults to `json`): Alloy derives the `service` stream
label from each line's own `service.name`, so a dev stack and a cluster shipping to an
ECS-consuming backend share one service identity.

Retention is bounded so a stack left running does not grow without limit: Prometheus
3d, Tempo 3d, Loki 3d (`--storage.tsdb.retention.time`, `tempo.yml`'s
`block_retention`, `loki-config.yml`'s `retention_period` — all 72 h, so a trace's log
lines do not outlive the trace). Alloy keeps its tail positions
on the `alloy-data` volume, so a restart resumes rather than re-ships.

## Run it

Full stack (Garage + OpenBao + the node, plus observability):

```bash
docker compose -f docker-compose.yml \
               -f docker-compose.observability.yml up -d --build
```

Minimal stack (node only, plus observability):

```bash
docker compose -f docker-compose.minimal.yml \
               -f docker-compose.observability.yml up -d --build
```

Tear down (all volumes are kept):

```bash
docker compose -f docker-compose.yml \
               -f docker-compose.observability.yml down
```

**Do not add `-v`.** `docker compose down -v` drops *every* named volume in the merged
project — including `datasets` and `inbox`, the node's only durable state — not just the
observability ones. To drop only the latter, remove them by name afterwards:

```bash
# `gdi-node-standalone_` is the Compose project-name prefix. Compose derives it from the
# checkout directory (lowercased) unless COMPOSE_PROJECT_NAME is set, so a differently
# named checkout has e.g. `myclone_prometheus-data` — the hardcoded names below would
# then match nothing (or, worse, another project's volumes). Set the prefix to match:
proj="${COMPOSE_PROJECT_NAME:-gdi-node-standalone}"   # or: basename "$PWD" | tr 'A-Z' 'a-z'
docker volume rm "${proj}_prometheus-data" "${proj}_loki-data" \
                 "${proj}_tempo-data" "${proj}_grafana-data" "${proj}_alloy-data"
```

To confirm the prefix rather than assume it, list the project's volumes first with
`docker volume ls | grep -E '_(prometheus|loki|tempo|grafana|alloy)-data$'`. `alloy-data`
holds Alloy's tail positions: leave it and a restarted stack resumes where the old one
stopped instead of re-shipping every container log from the beginning.

## URLs (localhost)

| UI | URL | Notes |
| --- | --- | --- |
| Grafana | http://localhost:3000 | Anonymous **Admin** in dev (no login). Dashboards + Explore. |
| Prometheus | http://localhost:9089 | Host `9089` → container `9090` (the node holds host `:9090`). |
| Alertmanager | http://localhost:9093 | Firing alerts; no real notifications in dev. |
| Alloy | http://localhost:12345 | Telemetry-agent UI (component graph, health). |
| Tempo | via Grafana | Queried through the Tempo datasource (not a standalone UI). |
| Loki | via Grafana | The dashboard's log panel, or Explore for ad-hoc LogQL. |

Every port above is published on `127.0.0.1` only. Keep it that way: on Linux, Docker
installs its own iptables DNAT rules and a published port is **not** filtered by `ufw` or
`firewalld`, so dropping the loopback prefix puts an anonymous-Admin Grafana and a
lifecycle-enabled Prometheus on your LAN.

These are the defaults; every one is overridable with a `GDI_HOST_PORT_*` variable — see
[deployment.md's host-port table](../../docs/deployment.md#overriding-the-dev-stack-host-ports).

The **gdi-node-standalone** dashboard auto-loads in Grafana over every curated `gdi_*`
series, grouped into rows in the order an operator asks the questions: **Status** (ready,
probes, keyless / master-key latches, build, uptime, datasets by state and at-rest form,
disk, store scrub), **Serving** (HTTP / Beacon / FDP rate, error ratio and latency, in-flight
vs capacity, rejections, readiness by subsystem as a state timeline), **Ingest pipeline**,
**Sources** (S3 buckets and inbox), **Secrets** (Vault), **Governance and integrity**,
**Process**, and one Loki panel showing the node's own logs
(`{service="gdi-node-standalone"}`, rendered as `logger message` with the ECS document one
click away). That panel doubles as a liveness check on the
Alloy → Loki pipeline: if it is empty, the pipeline is broken, not the node quiet. Alloy
discovers every container on the Docker host, so a host running several stacks sees their
infra containers (`garage`, `postgres`, …) in Loki too — select on `service` to keep to the
node. A **Node** variable (`instance`) scopes every panel when one Prometheus scrapes
several nodes.

Every panel that backs an alert names it in its title, and
`scripts/check-dashboard-metrics.py` holds the JSON to that: no overlapping panels, one
unit per axis, a stat tile that shows the latest value rather than every sample, an
alert-named panel that charts the alert's own series, threshold steps on every panel that
colours by thresholds (declared or, for `stat`/`gauge`, implied), and a neutral base step
on every tile that sets a `noValue` — Grafana paints that text with the base step, so a
green base would read absent data as "OK".

Select logs on **`service`** (the Compose service name). `job` is `docker-logs` on every
container, so it discriminates nothing; and `container` is `<project>-<service>-<n>`
(e.g. `gdi-node-standalone-gdi-node-standalone-1`), which moves with `COMPOSE_PROJECT_NAME`.

## Requirements & notes

- **Docker socket mount for log collection.** Alloy mounts
  `/var/run/docker.sock:/var/run/docker.sock:ro` so `discovery.docker` /
  `loki.source.docker` can enumerate and tail container logs. Without it, traces
  and metrics still work but no container logs are shipped to Loki.
- **Dev only.** Grafana runs with anonymous Admin and no login form; Loki/Tempo
  use single-binary filesystem storage with no replication. Do not expose this
  overlay publicly.
- **The `otel` feature.** The base `Dockerfile` exposes a `FEATURES` ARG
  (default `full`); the overlay sets it to `full,otel`. The first `up --build`
  after enabling the overlay recompiles the image.
- **Alert rules mirror docs/operating.md §3** — see `rules/gdi-node-standalone.yml`. Every
  rule has a `promtool test rules` case under `rules/tests/` (a firing input, and for the
  guarded ones a non-firing one); `scripts/ci-local.sh promtool` runs them with the same
  pinned image the overlay evaluates them with.
