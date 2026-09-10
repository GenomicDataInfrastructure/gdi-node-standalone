# gdi-node-standalone documentation

Start at the top-level [README](../README.md) for the project overview and the local
quickstart. This folder holds the deeper guides, grouped by audience:

| Doc | For | What it covers |
| --- | --- | --- |
| [gdi-dataset-tool.md](gdi-dataset-tool.md) | data providers | The `gdi-dataset-tool` CLI: every command, `package.yaml` authoring, S3 / inbox / air-gapped workflows, and provider key management. |
| [operating.md](operating.md) | operators | Day-2 runbook: bring-up, health & metrics, alerts, incident recovery, key rotation, disaster recovery, upgrades, audit log. |
| [deployment.md](deployment.md) | operators | Installing and running the node for real: bare-metal & container, the S3-profile and dev stacks, the compatibility matrix, and resource sizing. |
| [api.md](api.md) | integrators | The HTTP contract: Beacon + FAIR Data Point + management endpoints, CORS, the resilience envelope, and standards-conformance notes. |
| [package-format.md](package-format.md) | integrators | The normative `.tar.c4gh` package format: archive layout, `manifest.json` schema, overlay sidecars, and the node↔package versioning policy. |
| [architecture.md](architecture.md) | contributors | How the system is built: crate map, ingest→overlay→query data flow, trust boundaries, cryptographic architecture, and the disclosure-control model and its limits. |
| [threat-model.md](threat-model.md) | contributors | Disclosure-control (k-anonymity) threat model: what the single-variant differencing gate defends, the residual multi-variant and cross-dataset limits, and which mitigations help. |
| [testing.md](testing.md) | contributors | The test strategy: the test tiers and where each lives, the shared-fixture API, and how to run the suite. |

## Machine-readable schemas

Six JSON Schema (draft 2020-12) files, generated from the Rust models and held to them by a
freshness guard. They are the authoritative type contract: `package-format.md` is the
human-readable summary, and on any conflict the schema wins. Validate or code-generate
against these rather than against the prose.

| Schema | Describes |
| --- | --- |
| [manifest.schema.json](manifest.schema.json) | `manifest.json` — the package's first member: the metadata a consumer reads without touching the payload. |
| [metadata-overlay.schema.json](metadata-overlay.schema.json) | The `{id}.metadata.json` sidecar, which corrects a published dataset's metadata out-of-band without repacking it. |
| [state-sidecar.schema.json](state-sidecar.schema.json) | The `{id}.state.json` sidecar carrying a dataset's intended visibility (`visible` / `hidden` / `deleted`). |
| [status-writeback.schema.json](status-writeback.schema.json) | `_status/{id}.json` — what the node publishes back about each dataset (state, the `.tar.c4gh` ETag the result is for, any error). `gdi-dataset-tool status` reads it to detect staleness. |
| [query-stats.schema.json](query-stats.schema.json) | The `GET /stats/queries` response — per-dataset usage counters since the node booted. Served over HTTP rather than written to object storage. |
| [catalogs.schema.json](catalogs.schema.json) | The `GET /catalogs` response — the configured catalogs (id and title) as plain JSON, for an integrating system that needs the ids a package's `metadata.catalog` may name without reading the FDP root's RDF. Served over HTTP. |

The configuration reference lives in the annotated
[`node.example.toml`](../node.example.toml) (service) and
[`tool.example.toml`](../tool.example.toml) (provider tool) at the repo root. Contributor
build, test and release guidance is in [`CONTRIBUTING.md`](../CONTRIBUTING.md).
