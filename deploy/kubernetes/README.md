# Kubernetes example

A worked Kustomize base for `gdi-node-standalone`. **This is an example to adapt, not a
turnkey production deployment** — it encodes the container contract correctly, but the
sizing, storage classes, ingress, namespace labels and secret delivery are all yours.

It lives in this repo, next to the `Dockerfile`, because it encodes *this binary's*
contract: the non-root uid, the port split, the volume semantics, and the single-writer
constraint. Those change with the binary, so they belong beside it.

Where an operator still has to supply something, it says so.

## Layout

```
deploy/kubernetes/
├── kustomization.yaml            # a one-line alias for base/ — keeps `apply -k deploy/kubernetes` working
├── base/                         # the manifests + node.toml: the scrape-based shape
├── components/                   # the optional shapes, as kustomize components (composable)
│   ├── inbox/                    #   fourth volume + the `ops` sidecar (no-S3 nodes)
│   └── push-telemetry/           #   OTLP export instead of a scraper
└── overlays/                     # what you apply: base + components, and nothing else
    ├── inbox/
    ├── inbox-push/               #   both components at once
    └── push-telemetry/
```

```bash
kubectl kustomize .                          # render locally — needs no cluster
kubectl apply -k .                           # the plain shape, once the placeholders are filled
kubectl apply -k overlays/push-telemetry     # + OTLP export
kubectl apply -k overlays/inbox              # + the local inbox and its ops sidecar
```

The base lives in its own subdirectory for one reason: kustomize refuses a resource that
is an *ancestor* of the overlay loading it, and (by default) a file outside the overlay's
own directory. An overlay inside the base tree — one with `resources: [../]` — therefore
cannot render at all. The root `kustomization.yaml` must stay a pure alias (`resources:
[base]`): anything listed there is unreachable from every overlay.

The optional shapes are **components** (`kind: Component`) so they *stack*: an overlay
lists the ones it wants and adds its own patches. An overlay that instead names the base
itself and keeps its patch in its own directory cannot be layered into an operator's own
overlay — kustomize's load restrictor refuses a patch file from a sibling directory, and
applying the shipped overlay *instead* would revert their ConfigMap and drop their extra
volume. Write your own the same way `overlays/inbox-push/` does: `resources:
[../../base]` plus the components you want.

> **Do not point `kubectl kustomize` (or `apply -k`) at a directory under `components/`.**
> Kustomize renders a Component root as an empty document stream and exits **0** — no
> error, nothing applied, and no way to tell that from a manifest set that renders nothing.
> Apply an overlay.

(`kubectl apply --dry-run=client -k .` still contacts the API server to fetch the OpenAPI
schema, so it fails with `connection refused` when no cluster is reachable — including
with `--validate=false`, which only skips a different check and still resolves resource
kinds against the server. `kubectl kustomize` is the only offline render.)

`scripts/tests/k8s/test_k8s_manifests.py` renders every root above with `kubectl
kustomize` and asserts the invariants below; `scripts/ci-local.sh k8s-manifests` runs it.

## Before you apply

- **No image is published.** Build from source and push to your own registry, then set the
  image — in **two** places that must agree (the node container and the `overrides-init`
  init container), so use `kustomize edit set image
  gdi-node-standalone=<registry>/<image>:<tag>` or the `images:` transformer in your own
  overlay rather than editing `base/deployment.yaml` by hand. The `inbox` component needs
  a second image, built from `Dockerfile.ops`. See
  [`docs/deployment.md`](../../docs/deployment.md).
- **Fill every `<SET ME: …>`** in `base/node.toml` — including the `[fairdp]` block, which
  is **required in full** once present (`title`, `issued`, `license`, `theme`,
  `applicable_legislation`, and both the publisher and HDAB agents with their contact
  points). A partial block is rejected at preflight, and at one replica under `Recreate`
  that is a crash-loop rather than a failed apply. Delete the whole block for a
  Beacon-only node.
- **Gate the apply with `check-config`, from your workstation.** The in-pod spelling works
  only once the pod runs — i.e. never in the cases where you need it:
  ```bash
  # in the pod, once it is Running (the path must be absolute: distroless has no shell and
  # nothing on PATH to resolve a bare name)
  kubectl exec deploy/gdi-node-standalone -- \
    /gdi-node-standalone --config /etc/gdi-node-standalone/node.toml check-config

  # before the apply, which is the one that catches a crash-loop config:
  kubectl kustomize . | \
    python3 -c 'import sys,yaml; print([d for d in yaml.safe_load_all(sys.stdin) if d and d["kind"]=="ConfigMap"][0]["data"]["node.toml"])' > /tmp/node.toml
  docker run --rm -v /tmp/node.toml:/etc/gdi-node-standalone/node.toml:ro \
    <your-image> --config /etc/gdi-node-standalone/node.toml check-config
  ```
  It lists every `<SET ME: …>` still to fill and runs the whole preflight without binding
  a listener.
- **First boot needs the override store to exist.** `require_override_store = true` is set
  here, and boot creates nothing, so the very first start on a fresh volume refuses with
  *"the operator-override store is not intact"*. The `overrides-init` init container runs
  `overrides init` (plain, never `--yes`) on every start: a no-op once the store is there,
  and a refusal when this node's used marker says the store has held overrides, which is
  the lost-volume case where the answer is `overrides import`
  ([operating.md §0](../../docs/operating.md#0-quickstart-first-production-bring-up) and
  [§17](../../docs/operating.md#17-disaster-recovery)).
- **`fsGroup` does not make the volumes writable — the init container does.** See the table
  below. If your namespace enforces the `restricted` Pod Security standard, that container
  is rejected: do the `chown` storage-side and delete it.
- **Decide `[beacon].min_allele_count` before you apply.** It ships as `0` here, which
  means small-count suppression is off: singleton allele counts are served verbatim on
  an unauthenticated plane. That is deliberate — the floor is a disclosure-policy decision
  these manifests must not make for you, and the quickstart and compose profiles pick `10`
  only because they are throwaway dev stacks. Set a floor (e.g. `min_allele_count = 10`)
  unless your DPIA concludes aggregate allele frequencies are non-identifying for this
  dataset. The node logs a startup `WARN` in every environment while it is `0`. See the
  notes in `base/node.toml`, `node.example.toml` and
  [`docs/threat-model.md`](../../docs/threat-model.md).
- **`[beacon].id` follows a convention the node checks.**
  `<cc>.<institution>.<af-beacon|sl-beacon>.<staging|production>[.<extra>]`, with the last
  segment agreeing with `environment`. A value that does not match still boots, but WARNs
  on every start.
- **Both Beacon-network fields are filled.** `[beacon].alternative_url` and
  `[beacon.organization].logo_url` are optional in the Beacon schema but should be treated
  as required by the GDI allele-frequency network's registry: omitting either has been
  observed to degrade the shared member listing, not just your own entry. Nothing in this
  node reports that, so it is on you to set them.
- **Deliver the Vault credential out of band.** `base/secret.example.yaml` holds
  placeholders and is excluded from `base/kustomization.yaml`, so a stray `apply -k` cannot
  create a Secret containing the literal string `<SET ME: …>`.
- **Filling the placeholders is necessary, not sufficient.** This config carries no
  `[vault]` or `[[s3.buckets]]` section at all — add them from
  [`docs/deployment.md`](../../docs/deployment.md) ("Running against your own backends"),
  or apply `overlays/inbox`, or the node has no source to ingest from. A node with neither
  channel now says so at `WARN` on every boot; it still reports `ready: true`, because it
  serves whatever its data dir already holds.
- **Check `resources`.** `requests` are shipped (a serving floor, so the pod is not
  BestEffort and first-evicted); **no limits are**, because a limit has to be sized from the
  node's own ceilings (the 8 GiB retained-row budget *plus* the 8 GiB decode floor = 16 GiB
  here) with headroom that is deployment-specific — not from the request. They will look
  large next to the ~15 MiB an idle node measures: that is expected — the **query** path is
  what consumes memory, in two terms, and `requests.memory: 12Gi` covers their sum. The
  retained page costs ≈220 MiB per matched dataset per request at the shipped
  `max_page_limit` of 1000 and the 512-population cap (a tenth of that at
  `max_page_limit = 100`), so
  `max_concurrent_requests = 16` admits a 3.4 GiB burst; on top of it sits the parquet decode
  working set, `(query_concurrency x 4 + 16) x max_parquet_row_group_bytes` = 8 GiB at the
  defaults this config inherits — the floor the node's own boot check compares against
  `max_total_query_bytes` (8 GiB here). A request reservation is not a description of steady
  state. On a small dev cluster a 2-CPU / 12Gi request may not schedule at all; lower them
  together with the node.toml knobs they are computed from, using
  [`docs/deployment.md`](../../docs/deployment.md) ("Resource baseline").

## The choices that matter

| Choice | Why |
| --- | --- |
| `strategy: Recreate` | The ingest path is single-writer against one data volume, and `RollingUpdate` would briefly run two. This, with the node's own `<data_dir>/.lock`, is what enforces it. `ReadWriteOnce` does not: it is node-scoped, meaning read-write by pods on one node, so it admits a second pod co-scheduled there. |
| The `fix-permissions` init container | The node must own its data dir, because it tightens the root to `0700` so a shared-volume co-tenant cannot read the decrypted store. `fsGroup` does not confer ownership: it does `chown -1:65532` plus setgid, so the owner stays `root`, and only the owner may `chmod`. This holds on a PV and on an `emptyDir` alike. `fsGroup: 65532` is kept for group access; the init container is what satisfies the rule. |
| The `overrides-init` init container | Boot creates nothing in the override store, so a first boot under `require_override_store = true` refuses. Plain `overrides init` is a no-op afterwards and still refuses the lost-volume shape. |
| The `data` claim at `320Gi` | Sized from the configured caps rather than from measured load: `ingest_concurrency × 4 × max_package_bytes` plus 25 % headroom at the shipped defaults (docs/deployment.md "Resource baseline"; a test derives the floor from the same two caps). **Applying this base over a cluster with a smaller claim asks Kubernetes to expand it in place.** That works under a StorageClass with `allowVolumeExpansion: true` and is an apply-time error under one without. Note that `storageclass.example.yaml` is not that class: it exists for the override-store claim and this `data` claim names no `storageClassName` at all, so expansion here depends on your cluster's default class. In that case grow the claim by hand or keep your own size in an overlay patch. |
| A **separate** `overrides` PVC | The operator-override store is the only state re-ingest cannot rebuild. Its loss looks like a *successful* recovery in which every withheld dataset is served again ([operating.md §17](../../docs/operating.md#17-disaster-recovery)). |
| `require_override_store = true` | With the store on its own volume, a lost mount must refuse to serve rather than silently lift every suppression. |
| `management_addr = "0.0.0.0:9090"` | Kubelet probes come from another network namespace and cannot reach loopback inside the container. |
| `configMapGenerator` (hashed ConfigMap name) | `kubectl rollout undo` reverts the pod template and nothing else, so a ConfigMap edited in place cannot be rolled back with the image. The content hash puts the config *in* the template. The cost: the applied object is `gdi-node-standalone-config-<hash>` — address it by label, not by name. |
| `terminationGracePeriodSeconds: 75` | The node drains its public plane, stops the management listener (hard-coded 2s), then awaits in-flight **ingest** — so shutdown can take `preStop sleep + 2 x shutdown_drain_seconds + 2s management stop` = 67s at the shipped drain of 30, which 75 covers with 8s of slack. Kubernetes' 30s default is below that and SIGKILLs the pod mid-drain. That accounting starts when the node starts serving. The handlers are armed before the first listener binds, so a SIGTERM delivered from that point on is buffered and honoured at the serve loop's first poll: a pod terminated mid-boot exits after the *remaining* startup — the work the `startupProbe` here budgets at `5s x 60` = 5 minutes — plus an empty drain, or at SIGKILL when the grace period ends. Earlier still, during config and secret load and the disk-cache re-hydrate, a signal is immediately fatal; see [operating.md §14](../../docs/operating.md#14-graceful-shutdown-and-signals). |
| `preStop: sleep: 5` | Endpoint removal is eventually consistent; without the pause a rollout still routes a few requests to a listener that has stopped accepting. The **native** sleep action, not `exec: ["sleep", …]` — the image is distroless and has no `sleep` to exec. **Requires Kubernetes >= 1.30**: the `sleep` preStop action (`PodLifecycleSleepAction`) is beta and enabled by default only from that version (GA at 1.34); a cluster whose API server does not know it **prunes it silently** rather than rejecting the apply, so the grace-period accounting in the row above loses this term and in-flight requests are cut off at the next stage instead. Verify before relying on it — `kubectl version` (server minor >= 30) — and after every apply: `kubectl get deploy gdi-node-standalone -o yaml` should show the `sleep` hook under `lifecycle.preStop`; an absent hook post-apply, not an error, is the symptom of a server that pruned it. Fall back to an image that has a shell if your cluster is older. |
| `readinessProbe.initialDelaySeconds: 2` | Readiness runs only after the startup probe has succeeded, so a longer delay re-pays a cold start that is already over — and at one replica under `Recreate` it is added directly to every restart outage. |
| `automountServiceAccountToken: false` | The node never calls the Kubernetes API — Vault auth here is AppRole or an agent-written token file, never the `kubernetes` auth method — so a projected token is only ever escalation surface. |
| `NetworkPolicy` | **Not optional — and only as strong as the CNI.** Widening the management bind exposes the unauthenticated dataset-state oracle (`GET /datasets/{id}/state`, revealing hidden/errored ids). The policy is what contains it — and it *admits* the monitoring namespace, because a policy that admits nobody gives you the exposure and no metrics. `NetworkPolicy` objects are accepted by every API server but **enforced only by a CNI that implements them** (Calico, Cilium, Antrea, …) — not kindnet (kind's default) or flannel alone — so on a non-enforcing CNI this object applies cleanly and does **nothing**: the management plane stays reachable cluster-wide, silently. Verify: identify the CNI running in `kube-system`, or apply a scratch deny-all policy in a throwaway namespace and confirm a cross-namespace `curl` is actually blocked. |
| Two Services | Lets an Ingress select the public plane without ever exposing `:9090`. |

**Three startup `WARN`s are expected from the example as shipped**, and none is a
misconfiguration — each is a trade this base makes on purpose, or a decision it leaves to
you:

* **`min_allele_count = 0`**, the disclosure decision above;
* **ingest writer authentication is off** — no `[ingest]` block here, so a package that
  decrypts to this node's key is published with its writer key recorded but unverified
  (provenance `recovered`). Configure `[ingest]` if your providers are meant to be
  authenticated;
* **`no ingest channel configured`** — means exactly what it says: add `[[s3.buckets]]`
  or the inbox component.

The **wildcard management bind** is also logged, but at `INFO`, not `WARN` — binding the
pod interface is the documented deployment here, so the NetworkPolicy above, not a WARN,
is what contains it.

## Getting a dataset in on Kubernetes

**S3 is the supported channel.** A provider uploads a `.tar.c4gh`, the node polls its
buckets, and nothing has to reach into the pod. Configure `[[s3.buckets]]` (and `[vault]`
if the credentials live there) per
[`docs/deployment.md`](../../docs/deployment.md) — that is the whole story, and the rest of
this section does not apply.

For a node with **no object store** — the keyless, plaintext-at-rest posture — apply
`overlays/inbox`. It adds a fourth PVC at `/var/lib/gdi-node-standalone/inbox`, points the
node at it with `GDI_NODE__SERVICE__INBOX` (an env overlay, so the path is not a second
copy inside the config), and adds an **`ops` sidecar**: an Alpine image built from
[`Dockerfile.ops`](../../Dockerfile.ops) carrying the two static binaries and running
`sleep infinity`, as the node's uid, sharing the inbox volume.

The sidecar exists because there is otherwise no way in:

* `kubectl cp` into the node container fails — `exec: "tar": executable file not found in
  $PATH`. The runtime image is distroless.
* `gdi-dataset-tool deploy --inbox` from a workstation only knows local directories;
  `--management-url` covers `--wait`, not the drop.
* A helper pod can only mount the ReadWriteOnce inbox at all if the scheduler happens to
  place it on the node already holding the claim; the reliable form of that route is to
  scale the node to zero first — an outage per drop.

The sidecar shares the pod's network namespace, so the node's management plane — bound
`0.0.0.0:9090` and reachable from nowhere else — is on **loopback** from here. Pass it as
`--management-url`: it is what the lifecycle verbs consult for the dataset-state oracle,
and `delete` **refuses** rather than guessing when it has none.

```bash
POD=$(kubectl get pod -l app.kubernetes.io/name=gdi-node-standalone -o name | head -1)
INBOX=/var/lib/gdi-node-standalone/inbox
MGMT=http://127.0.0.1:9090

# 1. Copy the build staging directory into the sidecar's scratch space — not straight into
#    the inbox: `kubectl cp` is a streaming tar extract, so the node's watcher would see a
#    half-copied dir. The directory must be named exactly its datasetId.
kubectl cp <staging-dir> "${POD#pod/}:/tmp/<datasetId>" -c ops

# 2. Install it atomically (the tool stages a dot-prefixed dir and renames):
kubectl exec "$POD" -c ops -- gdi-dataset-tool deploy /tmp/<datasetId> \
  --inbox "$INBOX" --management-url "$MGMT" --wait

# 3. Make it visible, and the rest of the lifecycle:
kubectl exec "$POD" -c ops -- gdi-dataset-tool publish <datasetId> --inbox "$INBOX" --management-url "$MGMT"
kubectl exec "$POD" -c ops -- gdi-dataset-tool unpublish <datasetId> --inbox "$INBOX" --management-url "$MGMT"
kubectl exec "$POD" -c ops -- gdi-dataset-tool delete <datasetId> --inbox "$INBOX" --management-url "$MGMT"

# The node's own operator verbs run the same way — the lock-free ones are safe against the
# serving node (operating.md §0b). Here the binary IS on PATH, unlike in the node container:
kubectl exec "$POD" -c ops -- gdi-node-standalone \
  --config /etc/gdi-node-standalone/node.toml dataset hide <datasetId> --reason "..."
kubectl exec "$POD" -c ops -- gdi-node-standalone \
  --config /etc/gdi-node-standalone/node.toml overrides export -o /tmp/overrides.json
```

Say it plainly before you choose this shape:

* **Plaintext at rest.** Nothing is encrypted to a node identity here; the staging material
  sits on the inbox volume until ingest moves it, and rejected drops linger under
  `.rejected/`.
* **Operator-performed drops.** There is no provider self-service: every install is a
  `kubectl cp` + `kubectl exec` by someone holding `pods/exec` on this namespace — which is
  also a shell next to the decrypted store, so treat that RBAC as data access.
* **Back up the override-store volume.** It is the only state a re-ingest cannot rebuild,
  and in this shape you are the one writing it. See
  [operating.md §17](../../docs/operating.md#17-disaster-recovery).

## Telemetry: two shapes

The base is the **scrape-based** shape: a Prometheus scrapes `/metrics` on the management
plane (`base/servicemonitor.yaml`, applied by you if the Operator's CRDs exist — it is
not in the kustomization, since its CRDs would fail everyone else's `apply
-k`) and the NetworkPolicy admits that scraper; the alert rules under
`compose/observability/rules/` are the PromQL for it (each with a `promtool test rules`
case). With prometheus-operator v0.93.1 the shipped ServiceMonitor and
NetworkPolicy need no edit, but **your `Prometheus` CR needs
`serviceMonitorNamespaceSelector: {}`** when it lives in another namespace than the node —
the operator's default is its own namespace, so it would never select this ServiceMonitor
and no target would appear. That file's header has the detail.

The **push-based** shape is `components/push-telemetry` (apply `overlays/push-telemetry`),
for a cluster whose observability is an OTLP intake (Elastic APM, an OpenTelemetry
collector, Grafana Cloud) and nothing that scrapes: the node exports traces *and* metrics
itself (`[service].otlp_metrics_interval_seconds`;
[operating.md §16](../../docs/operating.md#16-distributed-tracing-optional)). It adds four
environment variables — the intake URL, the push interval, the metrics temporality
(`delta` for Elastic), and the credential header from a Secret — and changes nothing else.
Two things bite before it works, and both look like network problems:

* **The pod does not start until the Secret exists** (`CreateContainerConfigError`): the
  `secretKeyRef` is not `optional`, unlike the base's Vault one. Create it from
  `components/push-telemetry/secret.example.yaml` first.
* **A placeholder or malformed endpoint crash-loops after two `WARN`s.** The exporter is
  constructed before the placeholder preflight rejects the value, so you see `OTLP exporter
  setup failed … invalid URI` twice and only then `service.otlp_endpoint must be a valid
  URL`. That is the `<SET ME: …>` still in place (or an unbracketed IPv6 literal), not the
  intake being unreachable — an unreachable intake logs one `OTLP export failing` line per
  outage and keeps serving.

Exported spans and pushed metrics carry **dataset ids**, hidden and errored ones included
(`path` attributes, `ingest_job{dataset}`, `gdi_dataset_state{dataset}`). Those ids already
travel to the same backend in the audit log; exporting them to a third-party intake is a
governance choice, and the place to make it is a collector-side `attributes` processor.
See [operating.md §16](../../docs/operating.md#16-distributed-tracing-optional).

Pick one per cluster. Both at once works but double-counts every series.

## Scaling beyond one replica

Serving is stateless apart from the volumes, so read replicas scale — but:

- the ingest path is **single-writer**, and the `data` PVC being `ReadWriteOnce` is not
  what enforces that. RWO is node-scoped — "mountable read-write by pods on one node" —
  so two pods co-scheduled on one node can both mount it read-write. The guarantee comes
  from the node's exclusive lock on `<data_dir>/.lock` (a second process fails fast) plus
  `strategy: Recreate` (the rollout never runs two). RWO keeps the claim on one node;
  it does not keep it to one pod;
- **every** serving replica must see the override store — but **read-only** is enough. The
  node never writes to it: suppressions and overlays are re-read declaratively, and
  `reingest/` markers are matched on their `requested_at` stamp rather than consumed. So
  the store would want `ReadOnlyMany` on the serving replicas, **not** `ReadWriteMany`,
  with the operator CLI writing it through a separate read-write mount. That is a property
  of the multi-replica shape below, not a change to make here: in this single-replica base
  both claims are `ReadWriteOnce`, and the guardrail asserts exactly that.

> **`ReadWriteMany` is not required, and the guardrail below rejects it.**
> The blocker is topology, not correctness: `.status.json`, the durable overlay
> and the modified high-water mark all live under `data_dir`, so N replicas need N data
> volumes — a **StatefulSet**, not this Deployment, each replica reconciling from S3
> itself. Until you make that change, run one replica.

## Guardrail

`scripts/tests/k8s/test_k8s_manifests.py` pins the invariants above. It is a **structural**
test, not a schema validator: `kubectl apply` already rejects malformed YAML, whereas a
dropped `NetworkPolicy` or a `Recreate` flipped to `RollingUpdate` is valid YAML, valid
Kubernetes, and a live incident. The one thing it does *execute* is `kubectl kustomize`
over every root above, because whether an overlay builds — or whether two components still
compose — is not a structural property: a check that pins the expected strings passes just
as happily on an overlay kustomize refuses to build. Without `kubectl` those render tests
skip, and the `k8s-manifests` gate leg says so in its summary.

`base/node.toml` is additionally held to the same contract as the repo's other shipped
templates (`crates/gdi-node-standalone/tests/it/config_examples.rs`): it must parse, must
refuse preflight while a `<SET ME: …>` stands, and must preflight cleanly once the hints
are substituted — so "these placeholders are usable values" is checked rather than hoped.
