# gdi-node-standalone operator runbook

Day-2 operations for running a `gdi-node-standalone` node unattended. This is the
operator doc; the provider docs (creating and shipping packages) are the `README.md`
quickstart and `gdi-dataset-tool.md`.

> ### If you read nothing else
>
> Four defaults are safe for the shipped posture and wrong for most real ones. Decide
> each one rather than inheriting it.
>
> 1. **Disclosure suppression ships off.** [§0 bring-up](#0-quickstart-first-production-bring-up)
>    covers setting a floor; [threat-model.md](threat-model.md) explains what a floor does
>    and does not buy. It does not stop membership inference.
> 2. **Back up the node identity before you need it.** Lose it and no package decrypts.
>    [§17 disaster recovery](#17-disaster-recovery).
> 3. **The management plane is loopback-bound**, so `/health/*` and `/metrics` are not
>    reachable from another host until you say so. A Prometheus target configured from the
>    wrong assumption looks like a dead node. [§1](#1-health-and-readiness-endpoints).
> 4. **A provider cannot see ingest failures by default.** Their tooling reads the
>    management plane (loopback) or an opt-in `_status/` writeback; with neither, a
>    rejected package is silent to them.
>    [§12 dataset lifecycle](#12-dataset-lifecycle-and-state-transitions).

## Where things live

| Concern | Home |
| --- | --- |
| Kubernetes manifests | [`deploy/kubernetes/`](../deploy/kubernetes/README.md): a worked Kustomize example (base plus an inbox and a push-telemetry component). Adapt it; it is not turnkey. The container contract it encodes is in `deployment.md` |
| Local quickstart | `README.md` (bare binaries, keyless inbox); its Docker Compose form is in `deployment.md` |
| Provider reference (`gdi-dataset-tool`) | `gdi-dataset-tool.md` |
| Config reference | the annotated [`node.example.toml`](../node.example.toml), one self-documenting entry per knob. Copy it to your own `node.toml`; it is not a shipped runtime file |
| Day-2 operations | this file |

The node serves two separate listeners. The public `[service].listen` carries only the
read paths (Beacon, FDP, `/.well-known/c4gh-recipient`). `/health/*`, `/metrics` and
`GET /datasets/{id}/state` live only on `[service].management_addr`, never on the public
listener or Ingress; reach them in-cluster from the kubelet, a cluster Prometheus or
scrape sidecar, the orchestrator on the ClusterIP, or a co-located tool on loopback. The
management bind is a hard startup requirement: the node exits rather than run
unprobeable.

## Table of contents

- [0. Quickstart: first production bring-up](#0-quickstart-first-production-bring-up)
- [0b. Operator commands (CLI)](#0b-operator-commands-cli)
- [1. Health and readiness endpoints](#1-health-and-readiness-endpoints)
- [2. Reading the metrics](#2-reading-the-metrics)
- [3. Alert thresholds (quick reference)](#3-alert-thresholds-quick-reference)
- [4. Clearing a dataset stuck in `error`](#4-clearing-a-dataset-stuck-in-error)
- [5. Forcing a re-ingest](#5-forcing-a-re-ingest)
- [6. Detecting a wedged ingest pool](#6-detecting-a-wedged-ingest-pool)
- [7. Low-disk alerting](#7-low-disk-alerting)
- [8. Vault token health](#8-vault-token-health)
- [9. Rotating a node crypt4gh identity](#9-rotating-a-node-crypt4gh-identity)
- [10. Rotating / revoking a Vault Transit (at-rest) key](#10-rotating--revoking-a-vault-transit-at-rest-key)
- [11. Running without Vault (the S3 profile)](#11-running-without-vault-the-s3-profile)
- [12. Dataset lifecycle and state transitions](#12-dataset-lifecycle-and-state-transitions)
- [13. Correcting dataset metadata](#13-correcting-dataset-metadata)
- [14. Graceful shutdown and signals](#14-graceful-shutdown-and-signals)
- [15. Logs and log configuration](#15-logs-and-log-configuration)
- [16. Distributed tracing (optional)](#16-distributed-tracing-optional)
- [17. Disaster recovery](#17-disaster-recovery)
- [18. Upgrades, version skew, and rollback](#18-upgrades-version-skew-and-rollback)
- [19. HTTP surface (endpoint reference)](#19-http-surface-endpoint-reference)
- [20. Verifying release artifacts + the container image](#20-verifying-release-artifacts--the-container-image)
- [21. Audit log](#21-audit-log)
- [22. One dataset's queries cost far more than its neighbours](#22-one-datasets-queries-cost-far-more-than-its-neighbours)

---

## 0. Quickstart: first production bring-up

New node, first boot: the day-one path. Install choices (bare-metal, container, the S3
profile) are in [deployment.md](deployment.md); this is what to do once it is running.

1. **Config.** Copy [`node.quickstart.toml`](../node.quickstart.toml) to your own
   `node.toml` and replace its `<SET ME: …>` values. It is the common public-data posture:
   S3 ingest plus `[keys]`, no `[vault]`. The annotated
   [`node.example.toml`](../node.example.toml) is the full per-knob reference. Add
   `[vault]` and `[vault].transit_key` there only if you want a secrets backend or at-rest
   PME.
2. **Mint the node identity**: the crypt4gh key that decrypts inbound `.tar.c4gh`
   packages. The node mints its own, so the provider's `gdi-dataset-tool` is not needed.
   ```bash
   gdi-node-standalone --config node.toml identity init --ensure
   ```
   It writes wherever the config says the node reads the key from: with `[vault]`, into
   Vault KV; otherwise into the first `[keys].identities` entry, plus its recipient at
   `<path>.pub`. `--ensure` makes a re-run a no-op, so this line is safe in a bring-up
   script. A keyless, plaintext-only node skips this step (delete `[keys]`). Back the key
   up: it is the one irreplaceable node secret. See §9 for rotation and for the `--file`
   and `--from` variants.
3. **Preflight**: a full config check that needs no listener and no network. It exits
   non-zero on any problem.
   ```bash
   gdi-node-standalone --config node.toml check-config
   ```
4. **Initialise the operator-override store.** First boot only, and only when
   `require_override_store = true`. Boot creates nothing there: a check that materialises
   what it then tests cannot tell "never used" from "the volume was lost". So a node that
   sets the flag before it has ever recorded an override refuses to serve on its first
   start:
   ```text
   invalid config: service.require_override_store is set but the operator-override store is
   not intact: the root is absent, is not a directory, or one of its `suppressions/` and
   `overlays/` directories is missing or unreadable
   ```
   ```bash
   gdi-node-standalone --config node.toml overrides init
   ```
   Plain `init`, never `--yes`. It is a no-op on an intact store, so it is safe in a
   bring-up script or as the init container `deploy/kubernetes` runs on every start. It
   refuses when this node's used-marker says the store has held overrides: that shape is a
   lost volume, and the answer is `overrides import` from the §17 backup.
5. **Start it**, then confirm readiness on the management plane (`:9090`, not the public
   `:8080`):
   ```bash
   until curl -fsS http://localhost:9090/health/ready; do sleep 2; done
   ```
   On a multi-bucket node this can take up to
   `[service].startup_reconcile_timeout_seconds` (default 30) if a provider bucket is
   unreachable, because the startup reconcile waits for every bucket before serving. Check
   `degraded` in the response: `ready: true, degraded: true` means the node came up but a
   provider is dark (§1).
6. **Confirm metrics** on the same plane: `curl -s http://localhost:9090/metrics | head`.
7. **Present the first dataset.** A provider packages a `.tar.c4gh` with
   `gdi-dataset-tool` and installs it over S3 or the inbox (see the
   [provider guide](gdi-dataset-tool.md)). Watch it reach `visible` via
   `GET :9090/datasets/{id}/state`, then query the public beacon on `:8080`.
8. **Work through the rest of this runbook**: the metrics to watch (§2), alert
   thresholds (§3), and the incident, rotation and disaster-recovery procedures below.

---

## 0b. Operator commands (CLI)

The binary is both the node and the operator toolbox: running it with no command serves,
and running it with a command does that one thing and exits. Commands are grouped noun-verb
(`identity ...`, `dataset ...`, `channel ...`); node-level actions are bare verbs. At most one
command per invocation, and a command's flags apply only to it. Mixing commands, or
passing another command's flag, is a usage error. `gdi-node-standalone --help` prints the
full grammar.

The `dataset`, `channel` and `overrides` groups and `doctor` are **lock-free** — they never
take the data-dir writer lock, so they are safe to run **while the node is serving**. That
includes `overrides export`, so a backup needs no outage. `verify` and the `identity` group
are offline/Vault operations.

| Command | What it does |
|---|---|
| `serve` (default) | Run the node. |
| `check-config` | Load + preflight the config, print a redacted effective-config summary, exit. A pre-deploy gate. |
| `healthcheck` | Probe `/health/ready` on loopback; exit 0/non-zero. The container `HEALTHCHECK`. |
| `doctor [--format text\|json] [--strict]` | Read-only posture report (config, keys, k-anon floor, writer-policy, override-store durability, subsystems, registry). Exits non-zero on a hard config failure, or on any `WARN` under `--strict`. |
| `verify [--full] [--digest] [--concurrency N]` | Offline store scrub (see §17). |
| `overrides export [-o\|--output PATH]` | Write the operator-override store to a readable JSON bundle (stdout unless `-o`). Fails rather than emitting an empty bundle when the store cannot be read (see §17). |
| `overrides import <BUNDLE> [--force]` | Restore a bundle. Refuses a store that already holds overrides unless `--force`. It never deletes, so it cannot make a withhold disappear, but `--force` overwrites a same-named entry, so a stale bundle can replace an in-force `take-down` with a weaker `hide` (see §17). |
| `overrides init [--yes]` | Create an empty operator-override store when it is absent. A no-op on an intact store, so it is safe to run unattended on every start, as [`deploy/kubernetes`](../deploy/kubernetes/README.md) does. Only a node that sets `require_override_store` before it has ever recorded an override needs it. It refuses without `--yes` when this node's used-marker says the store has held overrides, whether the store is now absent or present-and-empty: that shape is a lost volume, and the answer is `overrides import` (§17). `--yes` creates the store and attests it as empty, clearing the marker so the node boots. |
| `overrides prune-reingest [--all] [--dry-run]` | Remove reingest-request markers this node can no longer act on. Processing keeps a marker so a shared store fans out to every replica (§5), so markers accumulate, one per dataset. Removes only markers whose dataset the node has no trace of; `--all` withdraws every pending request, which another replica may not have observed yet. |
| `dataset list [filters] [--format text\|json]` | Read-only listing of the status index (id, state, channel, provenance, suppressed), with any operator override composed into `state`, so `--state hidden` finds a withhold and a masked declared state is reported as `source_state`. Filters: `--state` (repeatable), `--errors`, `--channel`, `--provenance`, `--unverified`, `--writer <fp-substr>`, `--id <substr>`, `--suppressed` (every withheld row: an active operator override, or a dataset of an orphaned channel, which carries no `suppressed` mode). |
| `dataset unhide <id> --reason <text>` (alias `dataset show`) | Lift an operator-authored withhold on `id`, if any. It never force-serves a dataset the source marked hidden. Works for both inbox and bucket-owned datasets. `--reason` is required and recorded in a durable lift record (`<override_dir>/lifted/`, naming what was lifted and why); like every operator reason it stays out of the log stream. |
| `dataset hide <id> --reason <text>` | Withhold `id` from disclosure. The underlying data is untouched and the withhold is reversible via `dataset unhide`. An id this node has no record of is still accepted, since a shared override store and a pre-emptive withhold are both normal, but the command says so, so a typo is not read as a completed withhold. Same for `take-down` and `correct`. |
| `dataset take-down <id> --reason <text> (--yes \| --dry-run)` | Withhold `id` and mark it for eviction. Irreversible from the node's perspective. `--dry-run` previews without writing; `--yes` confirms and applies. Giving neither is refused rather than defaulted, as on `identity retire`. |
| `dataset reingest <id>` | Retry ingest for `id` after fixing its cause: for an inbox dataset, moves its quarantined artifact from `inbox/.rejected/` back; otherwise (a bucket-owned or not-yet-seen id) queues a node-side reingest-request marker that clears `id`'s recorded signature, defeating the S3 reconcile's same-ETag short-circuit. Works for both channels. See §5. Over HTTP, `POST /datasets/{id}/reingest` applies the same clear in-process and starts the pass (`[control].enabled`). |
| `dataset purge-rejected [--older-than <dur>] [--dry-run]` | Erase `inbox/.rejected/` quarantine entries on demand: a GDPR and disk-pressure lever independent of the automatic `rejected_retention_hours` GC. Without `--older-than`, every entry is purged; with it (an integer + `s`/`m`/`h`/`d`/`w`, e.g. `72h` or `7d`), only entries older than that are. `--dry-run` lists what would be purged and removes nothing. Requires `[service].inbox`. |
| `dataset correct <id> (--field k=v... \| --patch <path>) [--reason <text>]` | Author (or refresh) a node-local metadata-overlay override for `id`, applied through the existing overlay engine. Works for a bucket-owned dataset with no bucket write, and takes precedence over any bucket/inbox `{id}.metadata.json` sidecar. `--reason` records the justification in the `metadata_overlay_set` audit line. See §13. |
| `dataset correct <id> --reset` | Remove `id`'s node-local metadata-overlay override, reverting to the package baseline (or resuming a source sidecar, if one is present) on the node's next reconcile. |
| `channel list [--format text\|json]` | Read-only listing of every configured channel (each `[[s3.buckets]]` name, plus `inbox` if configured) with its current suppression state. `--format json` for scripting, like `dataset list` / `doctor`. |
| `channel unhide <name> --reason <text>` (alias `channel show`) | Lift an operator-authored withhold on channel `name`, if any, and resume its ingest. `--reason` is required and recorded in a durable lift record (`<override_dir>/lifted/`), never the log stream. |
| `channel hide <name> --reason <text>` | Withhold every dataset of channel `name` from disclosure and pause its ingest (no further poll or download). This is the "this provider is compromised, stop now" lever. Reversible via `channel unhide`. |
| `channel take-down <name> --reason <text> (--yes \| --dry-run)` | Withhold every dataset of channel `name`, mark each for eviction, and pause its ingest. Irreversible from the node's perspective. `--dry-run` previews without writing; `--yes` confirms and applies. Giving neither is refused. |
| `identity init [--ensure] [--force] [--from <PATH>] [--file <PATH>]` | Mint (or import) the node crypt4gh identity, into Vault if `[vault]` is set, else into the key file at the first `[keys].identities` entry (`--file` names it explicitly). Works on any build. See §9. |
| `identity list` | Read-only inspection of the node identity, on any build and either posture: with `[vault]` it reads Vault KV; without it, it lists the `[keys].identities` files with path, role (the first entry is the published recipient), public-key fingerprint and file mode. It applies the loader's rules, including `[service].strict_key_perms`, so it doubles as a preflight: a non-zero exit means the node would refuse to start. Never prints key material. See §9. |
| `identity {rotate,retire,backup,restore}` | The rest of the node crypt4gh identity lifecycle (Vault builds only; for the file posture see §9's "Rotating a file-backed identity"). See §9. |
| `config dump-defaults` | Print the generated default configuration as TOML: what this node does if you set nothing. It reads no config file and touches no data dir, so it works on a box with nothing deployed yet. It is a reference, not a runnable config, because deployment-specific fields print as their empty defaults. Diff it against yours to see what you have overridden. |
| `pme reseal --yes` | Rewrite `<data_dir>/.pme-sentinel.json` against the currently configured Transit key, clearing a latched at-rest mismatch once the recovery or re-key is complete. It re-proves the store first and refuses if the configured key still cannot read it, so it cannot silence a genuine mismatch. Refused without `--yes`. PME builds only. See §10 and §17. |
| `version` | Print the version line (crate version, git SHA, `gdi_metadata_version`, build epoch) and exit. This is the subcommand spelling of `--version` / `-V`. |

`dataset unhide`/`hide`/`take-down` write an operator suppression override
(`<override_dir>/suppressions/{id}.json`), applied on `SIGUSR1` or the next reconcile
pass, for both inbox and bucket-owned datasets. `channel unhide`/`hide`/`take-down`
write the channel-granularity sibling
(`<override_dir>/suppressions/channel-{name}.json`): every dataset whose `channel`
equals `name` is withheld or evicted the same way, and the channel's ingest is paused.
A bucket's `BucketMonitor` stops polling, downloading and ingesting entirely while
suppressed, and the inbox scanner skips its whole scan while `channel-inbox.json` is
present. `name` must be a channel the config knows about: a configured
`[[s3.buckets]].name`, or `inbox` with `[service].inbox` set. `channel list` shows what
is configured. Where both an id-level and a channel-level override apply to one dataset,
the most restrictive wins (§12).

`dataset correct`/`--reset` write (or remove) a sibling node-local metadata-overlay
override (`<override_dir>/overlays/{id}.json`), applied the same way and through the same
overlay engine as a bucket or inbox `{id}.metadata.json` sidecar (§13). `dataset
reingest` works for both channels: an inbox id restores its quarantined artifact; a
bucket-owned or not-yet-seen id instead writes a one-shot `<override_dir>/reingest/{id}`
marker, applied on `SIGUSR1` or the next reconcile. The node clears the id's recorded S3
`ETag` signature and reconciles it, so a package that errored on a node-side cause, such
as a catalog you have since added, retries with no provider re-upload. See §5. `dataset
list` and `doctor` reflect all channels. `dataset purge-rejected` is the one command that
does not go through the override store: it acts directly on `[service].inbox`'s
`.rejected/` quarantine directory, in-process, before the CLI exits.

> **Multi-tenant plaintext inbox is unsupported.** The plaintext-staging-dir inbox path
> validates a drop in place and then copies it into the store by path. On a keyless node
> (no crypt4gh or PME identity) whose inbox directory is writable by more than its owner,
> a co-tenant can swap a just-validated file for a symlink to another tenant's plaintext
> parquet between validation and the copy. Run the inbox single-tenant (owner-only,
> `0700`), or use crypt4gh/PME: encrypted `.tar.c4gh` drops are staged into a private
> `.incoming/<rand>/` (`0700`) before validation and are immune. The node warns at boot
> when it detects a keyless node with a group- or other-writable inbox.

> **Take-down scope.** A `channel take-down` withholds an id only while the id is
> presented on that channel. Re-presenting the same id on a different monitored channel
> (a second bucket, or the inbox) is a distinct publication that the channel entry does
> not cover, because the trust boundary is the channel, not the id. For "this id,
> everywhere and permanently", use the id-level `dataset take-down <id>`, whose
> `{id}.json` `Remove` matches regardless of channel. The node does not auto-write
> per-member id markers on a channel take-down: the member set is unbounded and
> time-varying, so doing so would grow the override store without limit.

> **Back the override store up. It is the one part of the data volume re-ingest cannot
> rebuild.** Everything these commands write lands under `override_dir` (default
> `<data_dir>/overrides/`), and re-ingesting from the bucket restores each dataset to its
> source-resolved state, which is what the override countermands. Losing the store across
> a restart un-hides every withheld dataset and reverts every correction, silently: an
> absent store is indistinguishable from one that never existed. Put it on
> separately-backed storage and set `[service].require_override_store = true`. Losing it
> under a running node is caught: the reload keeps its last-good set and raises
> `gdi_override_store_absent`. That cannot survive the restart.
>
> With `require_override_store = true` the node refuses to start unless the store is
> intact: the root and both loader subdirectories, `suppressions/` and `overlays/`. It
> creates none of them; any `dataset hide`, `channel take-down` or `dataset correct` does.
> Mount the separately-backed volume at `<override_dir>` before the node boots.
>
> After a store-volume loss, restore with `overrides import` from the
> [§17](#17-disaster-recovery) backup, never with a file-level tool that can recreate
> directories without their contents. Do not run `overrides init --yes`: an empty store is
> the re-disclosure the flag exists to prevent. [§17](#17-disaster-recovery) covers the
> used-marker that tells an emptied store from a fresh one, and the backup procedure.

**Seeing an override.** `GET /datasets/{id}/state` (§19) adds a `suppression: {mode, at}`
object while a suppression override is active. It carries no `reason`: that free text is
kept off this oracle. §12 names the three places it is available instead: the override
file, the `dataset_suppressed` audit line, and `dataset list`'s `REASON` column.
`overlay_applied_at` and `overlay_error` report the current metadata-overlay outcome from
either a node-local override or a source sidecar, without distinguishing which. `dataset
list --suppressed`, and the plain `SUPPRESSED` column, list every overridden id.

`dataset list`, `doctor`, `channel list` and `channel unhide` fail loudly rather than
printing an empty list when the override store cannot be read: an empty list is
indistinguishable from "no withholds exist". Treat a read failure here as a
disclosure-control incident, not a reporting glitch.
`gdi_datasets_suppressed{mode}` and `gdi_suppression_load_degraded` (§2) are the
fleet-wide view for suppression, and `gdi_channel_suppressed{channel}` (§2) is the same
for a whole channel. See §12 for how a suppression override composes with the
source-driven state, and §13 for the metadata-overlay override.

**Compromise response.** `channel hide`/`take-down` is the immediate incident lever: stop
serving and ingesting now. It complements rather than replaces durably distrusting a
compromised provider's writer key. Clear
`[[s3.buckets]].allowed_writer_fingerprints` (or
`[ingest].inbox_allowed_writer_fingerprints`) under `writer_policy = "enforce"`, so a
re-onboarded or rotated key cannot resume publishing without an explicit operator
decision. §14 covers reloading that allow-list without a restart.

---

## 1. Health and readiness endpoints

Two management-plane probes (`crates/gdi-node-standalone/src/health.rs`):

### `GET /health/live`

Liveness. A reachable handler is the signal: it returns `200` whenever the management
listener is up. Wire it to the kubelet liveness probe. The binary also ships a
`healthcheck` subcommand (`gdi-node-standalone healthcheck`) that probes `/health/ready`
on the loopback management port and exits `0`/`1`. It is the container image's
`HEALTHCHECK` and works for any non-Kubernetes supervisor too.

**Mind the pre-bind startup window.** The management listener binds only after secret
load and cache hydrate complete, so until then both probes get connection-refused rather
than a `503`. The store self-test runs after the bind, with the listener already
reporting `200`-live and `503`-not-ready. On a populated PME node that self-test decrypts
a bounded sample, so readiness can stay `503` for a while. Guard it with a `startupProbe`
on `/health/ready` and a generous `failureThreshold`, so the kubelet holds the liveness
check until the node is up instead of SIGKILLing one that is still hydrating:

```yaml
startupProbe:
  httpGet: { path: /health/ready, port: 9090 }
  periodSeconds: 5
  failureThreshold: 60        # covers secret load plus the store self-test on a populated node
livenessProbe:
  httpGet: { path: /health/live, port: 9090 }
```

### `GET /health/ready`

Readiness. Returns a small JSON document, with `200` when ready and `503` when not:

```json
{
  "ready": true,
  "degraded": false,
  "subsystems": {
    "s3": "ok",
    "s3_buckets": { "provider-a": "ok" },
    "vault": "ok",
    "at_rest": "ok",
    "key_material": "ok",
    "initial_reconcile": "done"
  }
}
```

`at_rest` reports the PME master-key path and reads `not-configured` unless
`[vault].transit_key` is set. It latches `mismatch` when the key can no longer decrypt
this node's data (§10, §17), and `unverifiable` when the check could not be completed
from local state: an unreadable or unparseable sentinel, or one naming an unknown
scheme. The first means "recover the key", the second means "inspect the sentinel, then
`pme reseal --yes`". Both gate `ready`. A node with no S3 bucket omits `s3_buckets` and
reports `s3: not-configured`. The same six components (`overall`, `initial_reconcile`,
`s3`, `vault`, `at_rest`, `key_material`) are the label set of the `gdi_health_ready`
gauge (§2), sampled from this body.

**`degraded` means the node is serving a partial view.** It is `true` whenever any
configured subsystem reads `unavailable`, including per-bucket S3, which does not gate
`ready`. So `ready` alone cannot tell you the node is half-blind.

What half-blind means depends on timing. A bucket the node never reached (a fresh start)
has its datasets absent, and a Beacon query returns a clean "no match". A bucket
reached earlier and now unreachable keeps serving its datasets at their last-known
visibility, because the reconcile fails open so a transient blip does not drop a live
provider. A source-side retraction issued during that outage is not observed, and the
dataset keeps being served until the bucket returns: served-and-stale, not absent.
`degraded` flags both cases in one field a probe already reads.

To bound how long a dark bucket may serve stale visibility, set
`[service].max_visibility_staleness_seconds` (default `86400`, 24 h). Past it, the
datasets of a channel whose last successful reconcile is older are withheld from the
public plane (Beacon and FDP) until it returns. Set `0` to disable the bound, and a dark
bucket serves its last-known visibility indefinitely. This gates the public plane only:
the management state oracle still reports the dataset's stored state, so
`GET /datasets/<id>/state` can read `visible` while the public plane serves nothing.

- `ready: true,  degraded: false` — serving everything.
- `ready: true,  degraded: true`  — serving, but at least one provider is dark.
- `ready: false, degraded: *`     — not in rotation.

`degraded` is not the complement of `ready`; a not-ready node is usually degraded too.
The startup reconcile still being `pending` is progress, not degradation, and does not
raise the flag. The field is always present, so a missing one means version skew rather
than "not degraded".

The ready predicate, all of which must hold:

- `initial_reconcile` is `done`: the startup listing and the per-dataset `.state.json`
  fetch are both complete, so visibility is correct from the first served request.
  Reported as `done | pending`.
- Every configured subsystem except S3 is healthy. S3 is reported but does not gate; see
  the S3 note below. Each subsystem reports `ok | not-configured | unavailable`.
  - **`vault`**: a dependency only if `[vault]` is configured, otherwise
    `not-configured`. It reads `ok` when connected with a usable token. If Vault is
    unreachable at startup the node boots degraded-keyless: this subsystem and
    `key_material` read `unavailable`, `/health/ready` stays `503`, encrypted-package
    ingest is skipped, and `gdi_keyless_degraded` latches to `1`. That does not self-heal,
    because identities load once at startup, so restart the node once Vault is reachable.
    A Vault outage after a healthy boot is different: cached DEKs keep serving and ingest
    retries transiently (§8).
  - **`key_material`**: the node crypt4gh identity or identities loaded, and under
    S3 with Vault the per-bucket S3 credentials. The keyless/plaintext mode (no
    identities and no Vault) is valid and reports `ok`; it does not fail readiness.
    At startup the node also runs a store-readability self-test. It opens and decrypts
    a bounded sample of re-hydrated datasets' parquet footers through the loaded
    decryptor, and flips this subsystem to `unavailable` only if every sampled dataset
    is unreadable, which means a global wrong or rotated crypt4gh or PME key. The node
    then reports not-ready instead of serving `error` per query, while a single corrupt
    dataset does not `503` the whole node. A fresh node with no data is a no-op.
    Sampling keeps the readiness-gating boot path off an O(datasets) × Vault-RTT cost.
    The full store is checked off-path by a detached sweep that publishes
    `gdi_store_scrub_failed` (§2), and on demand by the offline `verify` subcommand.

    **Two tiers.** Every dataset is checked for readability on each pass. A rotating
    slice of 4 is additionally re-hashed against its `parquet-digests.json` sidecar,
    which catches silent data-page bit-rot behind an intact footer without the exclusive
    lock offline `verify --digest` needs (§17). Every dataset is digest-verified in turn,
    so a 100-dataset node cycles in about 25 sweeps. Row validation is offline only, as
    `verify --full --digest`. The first sweep after a start skips the digest slice and
    does not advance the rotation cursor, so a restart pays no whole-file re-hashes on
    its first tick; readability still covers every dataset on every boot.

    **Detection is bounded by the sweep interval.** The detached sweep runs every
    `[service].rescan_interval_seconds` (default `600`), so a dataset that becomes
    unreadable keeps being served for up to that long. Within that window
    `GET /datasets/{id}/state` still answers `visible`, `/fairdp/dataset/{id}` still
    serves its metadata, and both provider recovery paths are refused: `deploy` says
    "already live" and `delete` hits the visible-guard. The next sweep quarantines the
    dataset and releases both. Lower `rescan_interval_seconds` if that window matters.
    Running `verify` does not shorten it, because it needs the exclusive data-dir lock
    (§17).

**S3 bucket health is not part of the ready predicate.** With per-provider buckets, one
bucket going unhealthy (an unreachable endpoint, bad credentials, a slow or timed-out
startup reconcile) must degrade only that bucket's datasets. A `503` would drop every
other provider from rotation. The probe reports it as detail instead:

- **`s3`** (aggregate): `not-configured` when there is no `[[s3.buckets]]`, otherwise a
  rollup that reads `ok` only when every bucket is healthy and `unavailable` if any is
  degraded. Informational; it does not gate `ready`.
- **`s3_buckets`** (object, present only when buckets are configured): per-channel health
  keyed by channel, the bucket `name`, each `ok | unavailable`. This shows which provider
  bucket is degraded.

A degraded bucket therefore leaves `ready: true`, flips `s3` and its `s3_buckets` entry
to `unavailable`, and raises `degraded: true`. Page on
`gdi_health_ready{component="s3"} == 0` or the per-bucket `gdi_s3_poll_errors_total`, not
on `component="overall"`, which stays `1`.

> **A bucket that is dead from boot delays readiness for the whole node.** The startup
> reconcile waits for every bucket to finish or time out before `initial_reconcile` flips
> to `done`, which is what makes visibility correct from the first served request. One
> unreachable provider therefore holds the node at `503`, healthy buckets included, for up
> to `[service].startup_reconcile_timeout_seconds` (default 30). It is bounded, never a
> wedge: the bucket is then marked unhealthy and the node comes up `ready: true, degraded:
> true`, serving every other provider. A bucket that goes bad after boot does not re-gate
> readiness, since `initial_reconcile` is a latch; that case is a metrics alert. Size a
> `startupProbe` above this timeout, not below it.

> **If every bucket fails and the store is empty, the node never becomes ready.**
> `initial_reconcile` flips to `done` only once at least one bucket has been listed, or
> datasets were re-hydrated from disk, because a node with no data and no reachable source
> has nothing correct to serve. It self-heals the moment any bucket polls successfully, no
> restart needed. On a single-bucket node whose bucket is down at boot this presents as a
> crash loop: readiness never goes green, a Kubernetes `startupProbe` exhausts its
> `failureThreshold`, and the kubelet SIGKILLs the container. Diagnose it from
> `gdi_s3_poll_errors_total{channel}` and the startup `WARN`, not from the restart count.

A subsystem reporting `not-configured` is never a readiness failure.

> **A wedged ingest pool does not fail readiness.** Nothing about the ingest queue feeds
> this probe, and the read path is unaffected by a stuck ingest, so a wedge surfaces as a
> metrics alert (§6) rather than a `503`. Do not add ingest state to your readiness
> gating.

Size the Kubernetes deployment's `terminationGracePeriodSeconds` from the drain accounting
in [§14](#14-graceful-shutdown-and-signals): `[service].shutdown_drain_seconds` is spent
twice, not once, plus the fixed preStop and management-stop terms.

---

## 2. Reading the metrics

Metrics are served on the management-plane listener (`[service].management_addr`),
alongside the health probes and the dataset-state oracle. It is a separate listener from
the public `listen`; the preflight refuses to start if `management_addr` is empty or
equals `listen`, and the bind is a hard startup requirement. Bind the pod interface for a
cluster Prometheus or kubelet. The public Ingress never routes the management plane, so
`/metrics` and the hidden-dataset oracle stay in-cluster.

Exposition is Prometheus / OpenMetrics text at `GET /metrics` on `management_addr`. It is
read-only: there is no admin or control surface here. No label is ever derived from
request content or client identity: no per-dataset-id labels, no variant, region, query,
IP or Origin. Labels are bounded, content-free, operator-known sets only. Per-dataset
usage counts live on the flag-gated management stats route (`GET /stats/queries`,
`[stats].enabled`; see [api.md](api.md)), never in `/metrics`. Metrics are scraped into
monitoring systems whose access is cheap to grant, so a dataset-id label would put an
enumeration of every id, hidden ones included, far beyond this plane.

The complete curated series (from `crates/gdi-node-standalone/src/metrics.rs`):

<!-- metric-names:start -->
| Metric | Type | Labels | What it tells you |
| --- | --- | --- | --- |
| `gdi_uptime_seconds` | gauge | — | Process uptime |
| `gdi_build_info` | gauge | `version`, `git_sha` | Constant `1` carrying the build version + git commit (see [§18](#18-upgrades-version-skew-and-rollback) for how `git_sha` is resolved and when it reads `unknown`) |
| `gdi_dataset_state` | gauge | `state` ∈ `visible\|hidden\|processing\|error` | Datasets per state (`error` includes datasets not in the cache) |
| `gdi_datasets_suppressed` | gauge | `mode` ∈ `hide\|remove` | Dataset count by operator-suppression override mode, over the full `<override_dir>/suppressions/*.json` store and independent of cache membership. Recomputed by the periodic sampler (about every 10 s), so it is correct within one tick of boot, and also on every apply, reload or `SIGUSR1` |
| `gdi_suppression_load_degraded` | gauge | — | Count of `<override_dir>/suppressions/*.json` files that failed to parse on the last load and were fail-closed to `hide` (`0` on a clean load); a sustained non-zero value means an operator should find and fix the offending file(s) (§21) |
| `gdi_override_store_absent` | gauge | — | `1` when the whole override-store root has gone while `require_override_store` is set: the node is serving from its last known-good in-memory set, no new `dataset hide`/`correct` can take effect, and a restart would refuse to serve. It is the only signal for that state, because `gdi_datasets_suppressed` keeps reporting the retained counts and nothing failed to parse, so `gdi_suppression_load_degraded` stays `0`. Restore the store from backup ([§17](#17-disaster-recovery)) |
| `gdi_channel_suppressed` | gauge (0/1) | `channel` (a bucket name, or `inbox`) | Whether a whole channel is under an active operator channel-suppression override (`channel hide`/`take-down`): every dataset of it withheld, its ingest paused. Set on every `BucketMonitor` poll-loop wake, including the `SIGUSR1`-triggered one, and by the periodic sampler (about every 10 s). The sampler is what covers `inbox`, which has no per-channel loop, and boot ordering |
| `gdi_s3_channel_orphaned` | gauge (0/1) | `channel` | Whether the channel is orphaned: the status index still owns datasets for it but no `[[s3.buckets]]` entry declares it. Its datasets are withheld from boot (withheld, not erased) and nothing polls its bucket, so a provider deleting their package has no effect. Set at boot; cleared live when a config reload re-adds the bucket. Resolve it: re-add the entry, or erase with `channel take-down <name>`. The series exists only while a channel is orphaned (the label set is unknowable at seed time) |
| `gdi_catalog_orphaned` | gauge (0/1) | `catalog` | Whether visible datasets still declare a `[catalogs]` entry that has been removed. They keep being served on both planes; what they lose is discoverability. `/fairdp` lists one catalog per configured entry, so those datasets fall out of the root's `ldp:contains` and cannot be reached by crawling. Unlike `gdi_s3_channel_orphaned` nothing is withheld: a catalog is a grouping, so the dataset still reconciles through its own channel and the provider's retraction still works. Every configured catalog is set to `0` at boot and on each reload; an orphan's own label cannot be seeded. Resolve it: re-add the entry, or take the datasets down if retraction was the intent (drives the **Catalog orphaned** alert) |
| `gdi_s3_keyspace_mismatch` | gauge (0/1) | `channel` | Whether the channel's removal processing is refused by the keyspace gate: the configured `endpoint`/`bucket`/`prefix` is not the keyspace its on-disk datasets were ingested from (recorded in `data_dir/.keyspace-{channel}.json`), or that witness file is unreadable, and datasets are missing from the new keyspace's listing. Serving and additions continue; evictions (including legitimate provider retractions) do not, so resolve it: revert the keyspace change, finish migrating the data, or erase the channel's datasets (`take-down`), after which the new keyspace is adopted automatically. Set on every removal-processing pass, in both directions |
| `gdi_config_reload_failed_total` | counter | — | `SIGHUP` config-reload attempts that failed validation (unparsable TOML, or the reloaded file failed the same preflight boot runs) and were discarded; the node kept its previous `[catalogs]` and `[ingest]` writer-allow-list subset. `0` under normal operation. A clean reload, or one that only warned about an ignored restart-only field, does not increment this (§14) |
| `gdi_disk_free_bytes` | gauge | `volume` (= the `data_dir` path) | Free bytes on the data volume |
| `gdi_disk_sample_failed` | gauge | — | `1` when the last `statvfs` failed, `0` when it succeeded. Health companion of `gdi_disk_free_bytes`: the exporter has no idle timeout, so an unset gauge keeps rendering its last healthy value and `LowDisk` would evaluate a frozen number |
| `gdi_ingest_queue_depth` | gauge | — | Ingest jobs queued, not yet picked up |
| `gdi_ingest_inflight` | gauge | — | Ingest jobs currently being processed by a worker |
| `gdi_ingest_inflight_oldest_age_seconds` | gauge | — | Seconds the oldest in-flight ingest (queued or being processed) has been held; `0` when nothing is in flight. The stuck-ingest signal (§3, §6.1): one ingest that never finishes raises it without bound, while a steady stream of short overlapping ingests cannot |
| `gdi_ingest_transient_backoff` | gauge | — | Distinct sources currently in a transient-failure backoff window. A persistently-failing backend (Vault or S3) keeps a source here; it clears on that source's first successful ingest |
| `gdi_ingest_concurrency` | gauge | — | Configured ingest worker capacity (`ingest_concurrency`, set once at startup). It is the node-wide ceiling shared across the inbox and every `[[s3.buckets]]` provider, so a slow package on one provider consumes a slot the others then contend for. Pair with `gdi_ingest_inflight` for a deployment-independent saturation signal |
| `gdi_query_concurrency` | gauge | — | Configured Beacon query scan fan-out capacity (`[service].query_concurrency`, else `ingest_concurrency`): the capacity line for `gdi_beacon_scan_blocking_inflight`. It is a separate gauge because the knob decouples the read path's cap from ingest; the two coincide only while it is unset |
| `gdi_ingest_last_progress_timestamp_seconds` | gauge | — | Unix time of the last ingest progress event |
| `gdi_beacon_scan_blocking_inflight` | gauge | — | Beacon `g_variants` per-dataset parquet scans currently running on tokio's shared `spawn_blocking` pool (512 threads), including scans detached by a request timeout. The read-path counterpart of `gdi_ingest_inflight`: the query fan-out is not capped across concurrent requests, so sustained high values mean queries are consuming the pool ingest also uses. See `IngestPoolStarvedByQueries`. Sampled from a dedicated sampler thread, so it reports even under full pool saturation |
| `gdi_ingest_total` | counter | `outcome` ∈ `success\|transient\|permanent\|timeout\|refused_pool_pressure\|cancelled` (plus a sanitized `error_class` on permanent; `cancelled` is a shutdown-interrupted ingest, see §14) | Ingest outcomes; `refused_pool_pressure` is an ingest deferred because the shared blocking pool was saturated (backpressure, retried) |
| `gdi_ingest_duration_seconds` | histogram | — | Ingest wall-clock duration |
| `gdi_s3_poll_last_success_timestamp_seconds` | gauge | `channel` | Unix time of a channel's last successful poll |
| `gdi_s3_poll_errors_total` | counter | `channel` | S3 poll errors per channel |
| `gdi_s3_status_writeback_disabled` | gauge (0/1) | `channel` | Set to `1` when writeback was disabled after an `AccessDenied` |
| `gdi_s3_download_bytes` | histogram | — | Bytes streamed per successful S3 package download (the pre-ingest network-fetch leg) |
| `gdi_s3_download_duration_seconds` | histogram | — | Wall-clock duration of a successful S3 package download |
| `gdi_s3_download_errors_total` | counter | `channel` | S3 package download failures per channel, the fetch leg after a successful listing. A bucket that lists fine but whose packages fail to download shows healthy poll-success while datasets never appear (drives the **S3 download errors** alert) |
| `gdi_overlay_apply_failed_total` | counter | `channel`, `reason` ∈ `fetch\|parse\|validate` | Dataset metadata-overlay apply failures. A persistently broken governance overlay keeps serving last-good metadata (drives the **Overlay apply failing** alert). Labelled `channel`, so it covers the inbox as well as buckets |
| `gdi_state_sidecar_rejected_total` | counter | `channel`, `reason` ∈ `unreadable\|unrecognized` | A `{id}.state.json` visibility sidecar was rejected and the dataset failed safe to `hidden`: it was withdrawn from the public plane because the sidecar could not be read, not because anyone chose to hide it (drives the **State sidecar rejected** alert). Pair it with the `state_sidecar_error` field on `GET /datasets/{id}/state` to find the id |
| `gdi_s3_removal_skipped_total` | counter | `channel` | Times the reconcile skipped its mass-eviction pass because a collapsed listing would have wiped a majority of owned datasets. Served data was retained and nothing deleted; check the bucket and endpoint (drives the **Mass removal skipped** alert) |
| `gdi_s3_deleted_sidecar_ignored_total` | counter | `channel` | An orchestrator wrote a `deleted` `.state.json` on an S3 bucket, where deletion means removing the `.tar.c4gh` object. The sidecar was ignored and the dataset kept hidden. The emit-site WARN log names the object to delete and is the actionable signal, so this counter is a trend aggregate rather than a paging condition |
| `gdi_inbox_scan_last_success_timestamp_seconds` | gauge | — | Unix time of the last successful inbox scan |
| `gdi_inbox_quarantine_evicted_total` | counter | — | Quarantine entries evicted by the `inbox/.rejected` count cap (`rejected_max_count`) |
| `gdi_store_scrub_failed` | gauge | — | Datasets that failed the last detached store sweep (§1 describes its two tiers). A failure about the data quarantines the dataset rather than merely counting it. A failure the node cannot attribute to the data, where the directory or its parquet could not be read (EACCES, EIO, ESTALE, EMFILE), is counted and logged but leaves the dataset served, so a transient volume fault does not take a healthy dataset out of service |
| `gdi_store_scrub_last_run_timestamp_seconds` | gauge | — | Unix time the last full store-readability sweep completed |
| `gdi_datasets_at_rest` | gauge | `form` | Dataset stores by at-rest form (`plaintext` = `PAR1`, `encrypted` = PME `PARE`, `indeterminate` = neither, meaning no readable parquet or a directory the node could not read). Emitted only when PME is configured. Enabling PME does not migrate existing datasets, so `plaintext > 0` is the standing version of the `doctor` at-rest warning. Each form is counted rather than derived by subtraction, so a deleted or truncated store cannot inflate the encrypted figure. `indeterminate > 0` needs no alert of its own, because such a dataset also fails the scrub sweep and raises `gdi_store_scrub_failed`; it covers both a store with no readable parquet, which is quarantined, and one that merely could not be read, which is not |
| `gdi_manifest_reload_skipped_total` | counter | — | Datasets skipped on a cache reload due to an unreadable/corrupt `manifest.json` (a published dataset silently dropping out of serving until fixed). A missing manifest mid-ingest is benign and is not counted (drives the **Manifest reload skipped** alert) |
| `gdi_inbox_watcher_restarts_total` | counter | — | Inbox filesystem-watcher restarts (flaky/dead watcher) |
| `gdi_background_task_panics_total` | counter | — | Recovered background daemon-loop panics (inbox watcher / rescan / S3 monitor, caught + restarted) |
| `gdi_ingest_provenance_absent_total` | counter | `reason` | Published packages carrying no recoverable crypt4gh writer key. `reason="plaintext"` is expected on every inbox staging-dir drop; `reason="recovery_failed"` is anomalous and alerts |
| `gdi_ingest_writer_unknown_total` | counter | `channel` | Artifacts the channel cannot vouch for under a non-`off` `[ingest].writer_policy`: a writer key not on its allow-list, an unparseable header, or an unidentified plaintext staging-dir drop, which carries no writer key and so can never be allow-listed. `warn`: published; `enforce`: quarantined. The allow-list-discovery signal |
| `gdi_beacon_merged_blocks_total` | counter | — | Blocks a Beacon scan had to buffer and sort whole because several source VCFs cover the same positions in them (a per-population split package). This is the one query shape whose peak memory neither `granularity` nor `limit` bounds, and it is a property of how the provider built the package, not of the request. A steadily rising count on a node whose queries feel expensive names the cause; [§22](#22-one-datasets-queries-cost-far-more-than-its-neighbours) says what to do about it |
| `gdi_vault_token_ttl_seconds` | gauge | — | The token's **full lease duration**, re-stamped on every successful login/renew (`0` for a static/non-lease token). It is a step value rather than a live countdown of seconds-until-expiry, and never decreases on its own. To detect a lapsing token, alert on `gdi_vault_reauth_total{outcome="failed"}` (see §8), not on this. |
| `gdi_vault_renewal_failures_total` | counter | — | Vault token renewal failures. A rising value is not by itself a fault: a renewable token cannot be renewed past `token_max_ttl`, so reaching that ceiling always fails one renewal and then re-logs in successfully. Useful for dashboards and correlation; do not page on it |
| `gdi_vault_reauth_total` | counter | `outcome` ∈ `recovered\|failed` | What the fallback re-login did after a renewal failed. `recovered` = routine `token_max_ttl` rollover, the node holds a fresh token and never stopped working. `failed` = the re-login failed too, so the credential is genuinely unusable and the node runs on borrowed time until its current token lapses (drives the **Vault renewal failing** alert) |
| `gdi_vault_token_file_age_seconds` | gauge | — | Age of `[vault].token_file` (`now - mtime`). The freshness signal when an **external agent** owns renewal: in that mode the node never renews, so `gdi_vault_renewal_failures_total` cannot rise and `gdi_vault_token_ttl_seconds` stays `0`, so a climbing age is the only evidence the agent has died. Absent unless `token_file` is set |
| `gdi_vault_token_file_reloads_total` | counter | — | Successful reads of `[vault].token_file`: one at startup, plus one per detected rotation. Flat while the age gauge climbs ⇒ the agent stopped rotating |
| `gdi_vault_token_file_read_errors_total` | counter | — | Failed reads of `[vault].token_file` (missing, unreadable, or empty). Distinguishes "the agent wrote garbage" from "the agent stopped writing", which the age gauge alone cannot |
| `gdi_pme_master_key_mismatch` | gauge (0/1) | — | `1` when the configured Transit master key can no longer unwrap a DEK this node wrote: the key was replaced, or the secrets backend was reset, so PME parquet at rest is undecryptable. Checked once at startup against `<data_dir>/.pme-sentinel.json` and latched for the life of the process; a transient check failure leaves it `0`. A restart alone does not clear it, because the check re-runs against the same sentinel and re-latches. Once the store is readable under the current key again (§10 step 4 / §17), clear it with `gdi-node-standalone pme reseal --yes`, then restart. Absent unless `[vault].transit_key` is set |
| `gdi_keyless_degraded` | gauge (0/1) | — | `1` while the node runs keyless-degraded (`[vault]` set but unreachable at startup); encrypted-package ingest skipped, latched until a restart with Vault reachable |
| `gdi_vault_call_duration_seconds` | histogram | `operation` ∈ `kv_read\|kv_write\|transit_datakey\|transit_decrypt` | Vault KV/Transit call latency on the **data** path (PME key fetch / crypt4gh unwrap), distinct from the token-lifecycle metrics above |
| `gdi_vault_call_errors_total` | counter | `operation` ∈ `kv_read\|kv_write\|transit_datakey\|transit_decrypt` | Vault KV/Transit call failures on the data path (pairs with the duration histogram; drives the **Vault call errors** alert) |
| `gdi_health_ready` | gauge (0/1) | `component` ∈ `overall\|initial_reconcile\|s3\|vault\|at_rest\|key_material` | The node's readiness self-report — `1` ready / `0` not (a not-configured component reports `1`); sampled from the same `readiness_body` the readiness probe uses, so it cannot disagree. `component="overall"` is the aggregate (drives the **Node not ready** alert) |
| `gdi_beacon_requests_total` | counter | `entry_type` ∈ `genomicVariant\|dataset\|individual`, `status_class` ∈ `2xx\|4xx\|5xx` | Beacon request volume (no query params) |
| `gdi_beacon_request_duration_seconds` | histogram | same content-free labels | Beacon latency |
| `gdi_beacon_query_total` | counter | `entry_type` ∈ `genomicVariant\|dataset\|individual`, `granularity` ∈ `boolean\|count\|record\|n/a`, `exists` ∈ `true\|false` | Answered Beacon queries: hit or miss (`exists`) at the granted disclosure level (`granularity`). The semantic complement to the transport-level `gdi_beacon_requests_total` (still no query params) |
| `gdi_beacon_query_rejected_total` | counter | `entry_type` ∈ `genomicVariant\|dataset\|individual`, `code` ∈ `400\|413\|500\|other` (all four are seeded per entry type, so a scrape always shows them; only `400`/`500` are reached in practice) | Beacon queries rejected before or within the scan (client error `400`, malformed or too-broad/`max_query_rows`; scan error `500`). Page-able per code, which the transport-level `status_class` only lumps into `4xx`/`5xx`. (Too-broad queries return `400`, matching the pre-scan span cap; the body-size `413` is a resilience-layer rejection counted under `gdi_http_requests_rejected_total{reason="body_too_large"}`, not here.) |
| `gdi_fairdp_requests_total` | counter | `resource_type` ∈ `root\|catalog\|dataset\|distribution`, `status_class` ∈ `2xx\|4xx\|5xx` | FAIR Data Point request volume by resource kind (the FDP serving plane, mirror of the beacon metric) |
| `gdi_fairdp_request_duration_seconds` | histogram | `resource_type`, `status_class` | FDP request latency |
| `gdi_fairdp_serialization_failures_total` | counter | — | FDP RDF serialization produced empty output (the internal-invariant `500` branch) |
| `gdi_http_requests_rejected_total` | counter | `reason` ∈ `overloaded\|timeout\|body_too_large\|uri_too_large\|internal` | Requests rejected by a resilience layer (load-shed `503` / timeout `408` / body-cap `413` / URI-cap `414`): the load and attack signals the per-route beacon metric never sees |
| `gdi_http_requests_total` | counter | `plane` ∈ `public\|management`, `status_class` ∈ `1xx\|2xx\|3xx\|4xx\|5xx\|other` | Every completed request on both listeners. On the public plane it covers every route, including the Beacon informational surface (`/service-info`, `/configuration`, `/entry_types`, `/map`, `/info`, `/`) and `/.well-known/c4gh-recipient`, which the per-entry-type `gdi_beacon_requests_total` does not see. On the management plane it is the probe, scrape and oracle traffic |
| `gdi_http_request_duration_seconds` | histogram | `plane` ∈ `public\|management` | Whole-node request latency by plane, complementing the per-entry-type beacon and FDP histograms. Lowest buckets 0.25 ms and 1 ms, so a sub-millisecond request is not rendered as an interpolated 2.5 ms |
| `gdi_http_inflight` | gauge | — | In-flight public-plane HTTP requests (serving-path saturation; pair with `gdi_http_max_concurrent_requests` for utilization) |
| `gdi_http_max_concurrent_requests` | gauge | — | The configured `max_concurrent_requests` capacity line (constant) |
| `gdi_http_connections_rejected_total` | counter | `plane` ∈ `public\|management` | Connections dropped at accept because the plane's connection cap (2048) was full. This sits below every request metric, since a dropped connection never becomes a request. On `management` it also sits below the health-probe exemption, so a saturated management listener starves the kubelet's `/health/*` and gets a correctly-serving node SIGKILLed |
| `gdi_process_cpu_seconds` | gauge | — | Cumulative process CPU time (user plus system) in fractional seconds, from Linux `/proc/self/stat`. Monotonic within a process life, so `rate()` it for cores in use. It is a gauge rather than a counter because the exporter's counters are whole integers, which rounds a lightly loaded node's `rate()` to `0` |
| `gdi_process_resident_memory_bytes` | gauge | — | Process RSS (Linux `/proc/self/status`); node_exporter-independent memory signal |
| `gdi_process_open_fds` | gauge | — | Process open file descriptors (`/proc/self/fd`) |
| `gdi_process_threads` | gauge | — | Process thread count (`/proc/self/status`) |
| `gdi_inbox_rejected_packages` | gauge | — | Permanently-rejected packages parked in the inbox `.rejected/` quarantine (standing backlog, inbox nodes only) |
| `gdi_inbox_keyless_packages` | gauge | — | Encrypted (`.tar.c4gh`) packages sitting in the inbox that this node holds no crypt4gh identity for. The node skips them so they survive until a keyed run, which means no error, no quarantine and no dataset state appears; the only other signal is an `INFO` line invisible at `GDI_LOG=warn`. Reads `0` on a keyed node and on an empty inbox, so `> 0` means packages are waiting for a key this node does not have (inbox nodes only) |
| `gdi_decrypt_failures_total` | counter | — | crypt4gh / PME decrypt failures |
<!-- metric-names:end -->

Notes that affect alerting:

- A periodic sampler (every 10 s) refreshes `gdi_dataset_state`,
  `gdi_disk_free_bytes`, `gdi_uptime_seconds`, the `gdi_process_*` gauges,
  `gdi_inbox_rejected_packages`, and `gdi_health_ready`, so a scrape always reads
  fresh-enough values.
  The `gdi_process_*` gauges are Linux-only (read from `/proc/self/*`).
- `gdi_ingest_queue_depth`, `gdi_ingest_inflight`, `gdi_ingest_inflight_oldest_age_seconds`,
  `gdi_ingest_last_progress_timestamp_seconds`, `gdi_decrypt_failures_total`,
  `gdi_fairdp_serialization_failures_total`, all five
  `gdi_http_requests_rejected_total{reason}` series, every `gdi_beacon_query_rejected_total`
  cell (`entry_type` × `code`), the `2xx`/`5xx` cells of `gdi_beacon_requests_total` per
  entry type, and `gdi_beacon_merged_blocks_total` are seeded at startup, so they render
  from the first scrape with no missing-series gap before the first event. The `2xx` and
  `5xx` cells of `gdi_fairdp_requests_total` are seeded per resource type when `[fairdp]`
  is configured.
  The per-channel series are seeded too, from the configured `[[s3.buckets]]` names: the
  `gdi_s3_*{channel}` counters and the `gdi_s3_status_writeback_disabled{channel}` latch at
  `0`, and `gdi_s3_poll_last_success_timestamp_seconds{channel}` at boot time. A bucket
  that has never once polled successfully, an endpoint dead from boot, would otherwise
  emit no series at all, and `S3PollerWedged`, a `time() - <gauge>` staleness rule, would
  sit at no-data for exactly the bucket it exists to catch. Seeding it to boot rather than
  `0` starts its staleness clock at startup without looking stale on every cold boot. The
  remaining per-label series (`{state}`, the other `{status_class}` values) appear as each
  label is first observed.
- The `error_class` and `version` values are bounded, path-free, and safe to alert or
  group on.

**Scraping into Elastic (Elastic Agent or Metricbeat).** The exposition is standard
Prometheus / OpenMetrics text, so nothing in the node changes to land it in
Elasticsearch: point Elastic's own Prometheus integration at the management-plane
`/metrics`. Where no scraper can reach the node, the `otel` build can instead push the
same series as OTLP metrics (`[service].otlp_metrics_interval_seconds`, §16) straight to
an APM intake. The names are the same either way.

- **Elastic Agent**: add the Prometheus Metrics integration, choose "Collect Prometheus
  metrics" with the Collector metricset, host `http://<node>:9090`, metrics path
  `/metrics`, and a `period` matched to your alert windows (§3).
- **Standalone Metricbeat**: the equivalent `prometheus` module:

  ```yaml
  - module: prometheus
    metricsets: ["collector"]
    period: 30s
    hosts: ["<node>:9090"]            # the management_addr, not the public listen
    metrics_path: /metrics
  ```

Scrape the management plane (`[service].management_addr`), never the public `listen`, and
keep the scraper in-cluster, because the management plane is not Ingress-routed. It
defaults to `127.0.0.1:9090`, loopback only, so a scraper in another pod, host or network
namespace gets connection-refused until you widen the bind to `"0.0.0.0:9090"`. That then
needs a `NetworkPolicy` or firewall in front of it, because this plane is
unauthenticated. A dead scrape target here is almost always that bind, not a dead node.

Histograms (`gdi_*_seconds`, `gdi_*_bytes`) arrive as their `_bucket`, `_sum` and
`_count` series. All labels are content-free and safe to index, and the `gdi_process_*`
gauges are Linux-only. The §3 thresholds are the reference regardless of backend;
translate the PromQL to your Kibana alerting rules. For logs alongside these metrics,
`LOG_FORMAT=ecs` (§15) lands ECS-shaped lines in the same Elasticsearch with no ingest
pipeline.

**Signal notes.** `gdi_ingest_total`'s optional `error_class` label appears only on
`outcome="permanent"` rows, as a closed sanitized enum; do not expect it on `success` or
`transient`. `gdi_dataset_state` carries only the four real states
(`visible|hidden|processing|error`); `ready` is a `/health/ready` probe outcome, not a
dataset state. Of those four, `processing` is always 0: the gauge is sampled from the
metadata cache, and no code path inserts a cache entry in that state. In-flight ingests
are counted by `gdi_ingest_inflight`, and `processing` is written only into the S3
`_status/{id}.json` writeback. Do not alert on it; §3's stuck-ingest row names the series
that moves.

---

## 3. Alert thresholds (quick reference)

Tune the windows and margins to your scrape interval and dataset sizes. This is a
backend-agnostic catalog of the shipped alerts: what each one watches, and its severity.
The exact PromQL expressions, thresholds, windows and margins live in
`compose/observability/rules/gdi-node-standalone.yml`, where each rule also carries a
`summary:`. Translate those to your own alerting backend rather than copying values from
here.

| Symptom | What fires it (the exact expression lives in the rules file) | Severity |
| --- | --- | --- |
| **No metrics at all** (`NodeMetricsAbsent`) | `absent(gdi_build_info)` for 10m: nothing is scraping the node. Read it first: while it fires, every other row in this table is blind, so a quiet dashboard means "no data", not "no problem". | critical |
| **Encrypted packages on a keyless node** (`InboxKeylessPackages`) | `gdi_inbox_keyless_packages > 0` for 30m: `.tar.c4gh` drops are accumulating on a node with no crypt4gh identity, so nothing will ever ingest them. The node skips them so they survive for a later keyed run, which is why the condition is otherwise silent: no error, no quarantine, no dataset state. Either this node's identity config is missing or failed, or a provider is dropping into the wrong node. | warning |
| **Wedged ingest pool** (`WedgedIngestPool`) | a non-empty `gdi_ingest_queue_depth` while `gdi_ingest_inflight` is 0: the pool stopped draining, with no worker processing. A long single ingest keeps `inflight >= 1` and is caught by **Ingest timed out**, not here; a worker stuck inside a job likewise. | critical |
| **Ingest timed out** (`IngestTimeout`) | a job exceeded `ingest_timeout_seconds` (`gdi_ingest_total{outcome="timeout"}`; see §6). | warning (restart to clear) |
| **Ingest retry churn** (`IngestRetryChurn`) | persistent transient retries (`gdi_ingest_total{outcome="transient"}`): a backend dependency is degraded; see §6.1. | warning |
| **Ingest source backoff** (`IngestSourceBackoff`) | one source stuck in a transient-failure backoff window (`gdi_ingest_transient_backoff > 0` sustained): a backend is persistently failing that one source, where the rate signal above covers all of them. See §6.1. | warning |
| **Dataset stuck `processing`** (`DatasetStuckProcessing`) | the oldest in-flight ingest has been held for >30m (`gdi_ingest_inflight_oldest_age_seconds > 1800`, which is what the shipped rule watches; see §6.1). Identify the id from `_status/{id}.json` or the ingest logs, not from `gdi_dataset_state{state="processing"}`: see the signal note in §2, that bucket is structurally always 0. | warning |
| **Ingest pool saturated** (`IngestPoolSaturated`) | every worker busy: `gdi_ingest_inflight` at `gdi_ingest_concurrency` (raise `ingest_concurrency` or investigate slow ingests; not necessarily wedged). | warning |
| **Ingest pool starved by queries** (`IngestPoolStarvedByQueries`) | Beacon scans sustained at `gdi_beacon_scan_blocking_inflight >= 2x gdi_query_concurrency` for >5m: the query fan-out shares tokio's blocking pool with ingest and can starve it while async `/health` stays green. The threshold scales to the emitted capacity gauge, so it is reachable on a small node. A visibility signal only; the node reserves no ingest headroom. Shed query load or scale out; see §6.1. | warning |
| **Low disk** (`LowDisk`) | `gdi_disk_free_bytes` below your margin (size it ≥ peak ingest scratch + headroom; see §7 and the §6 peak-scratch formula). | critical (grow *before* a wedge) |
| **Disk sample failing** (`DiskSampleFailed`) | `gdi_disk_sample_failed > 0`: `statvfs` on `data_dir` is erroring, so `gdi_disk_free_bytes` is stale and `LowDisk` cannot fire. Check the mount. | warning |
| **Vault token lease too short** (`VaultTokenLeaseTooShort`) | `gdi_vault_token_ttl_seconds` below your token-TTL margin. This gauge is the full lease, re-stamped on each renew, and never counts down, so it fires only on a token issued with a lease shorter than the margin, a token-policy misconfiguration, never on an expiry. The lapsing-token signal is `gdi_vault_reauth_total{outcome="failed"}` (below). | critical |
| **Vault renewal failing** (`VaultRenewalFailing`) | `gdi_vault_reauth_total{outcome="failed"}` rising: a token renewal failed and the fallback re-login failed too, so the credential is unusable. Not keyed on `gdi_vault_renewal_failures_total`: a renewal failure alone is routine `token_max_ttl` rollover and would page daily on a healthy node. | critical |
| **Vault token file stale** (`VaultTokenFileStale`) | `gdi_vault_token_file_age_seconds` above your agent's refresh interval (shipped rule: >1 h for 5 m). This is the only credential-health signal under `[vault].token_file`; `VaultRenewalFailing` and `VaultTokenLeaseTooShort` cannot fire in that mode. Investigate the agent sidecar, not the node. | critical |
| **Vault token file unreadable** (`VaultTokenFileUnreadable`) | `gdi_vault_token_file_read_errors_total` rising: the file is missing, empty, or unreadable (a vanished mount, or a half-written rotation). | critical |
| **At-rest master-key mismatch** (`PmeMasterKeyMismatch`) | `gdi_pme_master_key_mismatch > 0`: the Transit key cannot decrypt this node's data. The node reports `at_rest: mismatch` and `ready: false`, so it leaves the rotation while staying diagnosable. A damaged sentinel reports `at_rest: unverifiable` instead and does not raise this alert. Recovery is §17's "If the Transit key is genuinely lost", or §10 step 4 after a planned key revocation. Either way the final step is `pme reseal`, because the sentinel outlives the recovery. | critical |
| **Vault call errors** (`VaultCallErrors`) | `gdi_vault_call_errors_total` on the *data* path; keep the `{operation}` ∈ `kv_read\|kv_write\|transit_datakey\|transit_decrypt` (PME key fetch / crypt4gh unwrap, distinct from token-lifecycle renewal). | warning |
| **Node keyless-degraded** (`KeylessDegraded`) | `gdi_keyless_degraded` latched to 1 (Vault unreachable at startup; encrypted-package ingest is skipped). It does not self-heal: restart once Vault is reachable. | critical |
| **Datasets in `error`** (`DatasetsInError`) | any dataset in the `error` state (`gdi_dataset_state{state="error"}`). | info |
| **S3 poller wedged** (`S3PollerWedged`) | `gdi_s3_poll_last_success_timestamp_seconds{channel}` has not advanced within ~2× `full_poll_interval`. | warning |
| **S3 poll errors** (`S3PollErrors`) | `gdi_s3_poll_errors_total` rising. | warning |
| **S3 download errors** (`S3DownloadErrors`) | `gdi_s3_download_errors_total`: a bucket lists fine but its packages fail to download (datasets never appear while poll-success stays healthy). | warning |
| **Overlay apply failing** (`OverlayApplyFailing`) | `gdi_overlay_apply_failed_total`: a broken governance overlay keeps serving last-good metadata silently; `{reason}` ∈ `fetch\|parse\|validate`. Labelled `{channel}`, so it covers an inbox-only node. | warning |
| **State sidecar rejected** (`StateSidecarRejected`) | `gdi_state_sidecar_rejected_total`: a `{id}.state.json` could not be read (`{reason}` ∈ `unreadable\|unrecognized`) and the dataset failed safe to `hidden`. It was withdrawn from the public plane by a bad sidecar write rather than by anyone's decision. Find the id via `state_sidecar_error` on `GET /datasets/{id}/state`. | warning |
| **Mass removal skipped** (`MassRemovalSkipped`) | `gdi_s3_removal_skipped_total`: the collapse guard suppressed a mass eviction. Served data was retained and nothing deleted; check the bucket and endpoint. | warning |
| **Deleted sidecar ignored** (`DeletedSidecarIgnored`) | `gdi_s3_deleted_sidecar_ignored_total`: a `{id}.state.json` carrying `deleted` was seen and ignored. That spelling is the inbox delete verb and is not a delete on S3: remove the `{id}.tar.c4gh` object instead. The WARN log names the key. | info |
| **Manifest reload skipped** (`ManifestReloadSkipped`) | `gdi_manifest_reload_skipped_total`: a published dataset dropped from serving on a cache reload because its `manifest.json` was unreadable or corrupt. A missing manifest mid-ingest is benign and is not counted. | warning |
| **Inbox scan wedged** (`InboxScanWedged`) | `gdi_inbox_scan_last_success_timestamp_seconds` has not advanced within ~2× `rescan_interval_seconds` (only if an inbox is configured). | warning |
| **Inbox watcher flapping** (`InboxWatcherFlapping`) | `gdi_inbox_watcher_restarts_total` rising. | warning |
| **Status writeback disabled** (`StatusWritebackDisabled`) | `gdi_s3_status_writeback_disabled` set: writeback disabled for a bucket after an `AccessDenied`. | warning |
| **Decrypt failures** (`DecryptFailures`) | `gdi_decrypt_failures_total` rising. | warning |
| **Background task panic** (`BackgroundPanics`) | `gdi_background_task_panics_total`: a daemon loop (inbox watcher, rescan or S3 monitor) panicked and was restarted. | warning |
| **Provenance recovery failed** (`ProvenanceRecoveryFailed`) | `gdi_ingest_provenance_absent_total{reason="recovery_failed"}`: a `.tar.c4gh` published but its header yielded no writer key, so the package's provenance is unknown. | warning |
| **Writer key not allow-listed** (`WriterKeyNotAllowed`) | `gdi_ingest_writer_unknown_total`: a package from a writer not allow-listed for its channel reached ingest (`warn`: published; `enforce`: quarantined as `writer-rejected`). | warning |
| **Synthetic probe down** (`SyntheticProbeDown`) | the blackbox `blackbox-http` probe of `/health/ready` (`probe_success`) is down: the data plane is down or draining (the `for:` window rides out a normal initial reconcile / SIGTERM drain). | critical |
| **Node not ready** (`HealthNotReady`) | `gdi_health_ready{component="overall"}` reports not-ready — the node's own self-report, native from `/metrics`, so no blackbox probe is needed. The `{component}` ∈ `overall\|initial_reconcile\|s3\|vault\|at_rest\|key_material` label says which subsystem is unready. | critical |
| **Beacon serving errors** (`BeaconServingErrors`) | a sustained 5xx *ratio* on `gdi_beacon_requests_total{status_class="5xx"}` vs total, guarded by a min request rate (so a single transient 5xx or an idle node never pages). | warning |
| **FDP serving errors** (`FdpServingErrors`) | the FDP mirror of **Beacon serving errors**: the 5xx *ratio* on `gdi_fairdp_requests_total`, guarded by a min request rate. | critical |
| **FDP serialization failures** (`FdpSerializationFailures`) | `gdi_fairdp_serialization_failures_total`: the empty-output `500` branch fired (a serializer regression). | warning |
| **HTTP requests rejected** (`HttpRequestsRejected`) | `gdi_http_requests_rejected_total`; keep the `{reason}` ∈ `overloaded\|timeout\|body_too_large\|uri_too_large\|internal`: the load-shed `503`, timeout `408`, body-cap `413` and URI-cap `414` rejections the per-route beacon metric never sees, plus `internal`, a caught handler panic. Dropping `internal` from a hand-built panel or alert discards the most page-worthy of the five. | warning |
| **HTTP serving plane saturated** (`HttpInflightSaturated`) | `gdi_http_inflight` nearing the `gdi_http_max_concurrent_requests` cap (raise the limit or scale reads before load-shed `503`s). | warning |
| **Connections rejected at accept** (`HttpConnectionsRejected`) | `gdi_http_connections_rejected_total{plane}`: the plane's 2048-connection cap was reached, so connections were dropped before becoming requests, invisible to every request metric and unlogged. On `plane="management"` this sits below the health-probe exemption: kubelet probes are starved at accept and the pod is SIGKILLed while serving public traffic correctly. Look for a client leaking connections or a misbehaving scraper. | warning |
| **Store scrub stale** (`StoreScrubStale`) | `time() - gdi_store_scrub_last_run_timestamp_seconds > 6h`: the store-readability sweep has not completed in over six hours, so corruption detection is blind. Distinct from the row below: that one is a sweep that ran and found a bad dataset, this one is a sweep that is not running at all. | warning |
| **Store scrub failed** (`StoreScrubFailed`) | `gdi_store_scrub_failed`: a dataset failed the detached store-readability sweep. The cause is on-disk parquet corruption, a wrong or rotated key, or an unreadable data volume. The boot self-test only samples. A sustained non-zero value with no dataset in `Error` means the failures are transient, counted but not quarantined, which points at the volume rather than the data. | info |
| **Datasets plaintext at rest** (`DatasetsPlaintextAtRest`) | `gdi_datasets_at_rest{form="plaintext"}`: PME is configured but datasets remain unencrypted on disk. Enabling PME does not migrate what is already there. Re-ingest them (delete + re-add, or re-upload from S3); `verify --digest` shows the form per dataset. Expected to fire from the moment PME is switched on until the last dataset is migrated. | warning |
| **Datasets indeterminate at rest** (`DatasetsIndeterminateAtRest`) | `gdi_datasets_at_rest{form="indeterminate"}`: a served dataset directory holds no readable `allele-freq.*.parquet` (deleted, truncated or unreadable), so its at-rest form is unknown and it is not known to be encrypted. Run `verify`, which fails on it at footer depth and names the dataset. This is not a faster signal than `gdi_store_scrub_failed` but a more specific one: that gauge is a bare count of datasets failing verification for any reason. | warning |
| **Suppression store degraded** (`SuppressionStoreDegraded`) | `gdi_suppression_load_degraded`: an operator `<override_dir>/suppressions/*.json` file failed to parse on the last load and was fail-closed to `hide` (never `remove`); the dataset stays withheld either way, but the file needs fixing. | warning |
| **Override store absent** (`OverrideStoreAbsent`) | `gdi_override_store_absent`: the whole override-store root is gone while `require_override_store` is set. Nothing is re-disclosed (the last in-memory set is held), but the store is the one part of the data volume re-ingest cannot rebuild, no new `hide`/`correct` takes effect, and a restart will refuse to serve. Restore it from backup ([§17](#17-disaster-recovery)). | critical |
| **S3 channel orphaned** (`S3ChannelOrphaned`) | `gdi_s3_channel_orphaned{channel}`: the channel's `[[s3.buckets]]` entry was removed while it still owns datasets. They are withheld from boot, and the provider's own deletion can never take effect because nothing polls. Either finish the offboarding (`channel take-down <name>`) or re-add the entry. Neither state should stand. | warning |
| **Catalog orphaned** (`CatalogOrphaned`) | `gdi_catalog_orphaned{catalog}`: visible datasets declare a `[catalogs]` entry that no longer exists. They are still served, but they have dropped out of the FDP root's `ldp:contains`, so nothing reaches them by crawling. Either an operator removed the catalog believing it retracted the data, which it does not (use a take-down), or a config slip de-listed a live provider, in which case re-add the entry. | warning |
| **S3 keyspace mismatch** (`S3KeyspaceMismatch`) | `gdi_s3_keyspace_mismatch{channel}`: the channel's configured keyspace is not the one its datasets were ingested from, or the witness is unreadable, and datasets are missing at the new keyspace, so removal processing is refused. Either a config mistake to revert or a migration to finish. While it stands, provider retractions are not applied either. Do not leave it standing. | warning |
| **Channel suppressed** (`ChannelSuppressed`) | `gdi_channel_suppressed{channel}`: a whole channel (bucket or `inbox`) is under an active operator suppression override (`channel hide`/`take-down`), so every dataset of it is withheld and its ingest paused. Operator-actionable either way: confirm it is intentional (an active incident response), or lift it with `channel unhide --reason <text>`. | info |
| **Config reload failed** (`ConfigReloadFailed`) | `gdi_config_reload_failed_total` rising: a `SIGHUP` config reload failed validation (bad TOML, or the same preflight boot runs) and was discarded; the node kept serving its previous `[catalogs]`/`[ingest]` writer allow-list (§14). Check the paired WARN log line for the reason, fix the file, and resend `SIGHUP`. | warning |
| **Inbox quarantine backlog** (`InboxQuarantineBacklog`) | `gdi_inbox_rejected_packages`: rejected packages parked in `.rejected/` awaiting manual clearing (distinct from the permanent-error *rate*). | info |
| **Target down** (`TargetDown`) | the scrape `up` series for the `gdi-node-standalone` + `blackbox-http` jobs is down: a scrape-up backstop, because the `time() - <gauge>` staleness rows go to no-data rather than stale when `/metrics` is down, so a hard node-down is invisible to them. | critical |
| **Observability target down** (`ObservabilityTargetDown`) | the scrape `up` series for the `alloy`, `tempo` or `prometheus` job is down for 5m. Dev overlay only: cluster observability is central, so this can fire only under `docker-compose.observability.yml`. Delete it with the compose stack. | warning |
| **Watchdog (dead-man's switch)** (`Watchdog`) | an always-firing heartbeat (`vector(1)`); route it to an external monitor that pages when it stops arriving (i.e. Prometheus / Alertmanager / the pipeline is down). | n/a (heartbeat) |

The shipped Prometheus rule names, from
`compose/observability/rules/gdi-node-standalone.yml` and kept in sync with the table
above by `scripts/check-dashboard-metrics.py`:

<!-- alert-rule-names:start -->
`NodeMetricsAbsent`, `WedgedIngestPool`, `IngestTimeout`, `IngestRetryChurn`, `IngestSourceBackoff`, `DatasetStuckProcessing`, `IngestPoolSaturated`, `IngestPoolStarvedByQueries`, `LowDisk`, `DiskSampleFailed`, `VaultTokenLeaseTooShort`, `VaultRenewalFailing`, `VaultTokenFileStale`, `VaultTokenFileUnreadable`, `VaultCallErrors`, `DatasetsInError`, `S3PollerWedged`, `S3PollErrors`, `S3DownloadErrors`, `OverlayApplyFailing`, `StateSidecarRejected`, `MassRemovalSkipped`, `DeletedSidecarIgnored`, `ManifestReloadSkipped`, `InboxScanWedged`, `InboxWatcherFlapping`, `StatusWritebackDisabled`, `DecryptFailures`, `BackgroundPanics`, `ProvenanceRecoveryFailed`, `WriterKeyNotAllowed`, `SyntheticProbeDown`, `HealthNotReady`, `BeaconServingErrors`, `HttpRequestsRejected`, `HttpInflightSaturated`, `HttpConnectionsRejected`, `FdpServingErrors`, `FdpSerializationFailures`, `StoreScrubFailed`, `StoreScrubStale`, `DatasetsPlaintextAtRest`, `DatasetsIndeterminateAtRest`, `SuppressionStoreDegraded`, `ChannelSuppressed`, `S3ChannelOrphaned`, `CatalogOrphaned`, `S3KeyspaceMismatch`, `ConfigReloadFailed`, `InboxQuarantineBacklog`, `InboxKeylessPackages`, `PmeMasterKeyMismatch`, `KeylessDegraded`, `TargetDown`, `ObservabilityTargetDown`, `Watchdog`, `OverrideStoreAbsent`
<!-- alert-rule-names:end -->

> `gdi_ingest_queue_depth` alone cannot tell busy from wedged. A non-empty queue with no
> `gdi_ingest_inflight` is the wedge signal (see **Wedged ingest pool**), and
> `gdi_ingest_last_progress_timestamp_seconds` shows liveness within a running job.

**Inbox metrics are conditional.** `gdi_inbox_scan_last_success_timestamp_seconds` and
`gdi_inbox_watcher_restarts_total` carry meaningful values only when an inbox is
configured. On a pure-S3 node they never advance, so alert on them conditionally.

---

## 4. Clearing a dataset stuck in `error`

A dataset enters `error` only on a permanent data or validation failure: a bad manifest,
an unsafe archive, a decompression-bomb parquet, or none of the node's identities
decrypting an available package. A transient infrastructure failure (Vault unreachable, a
full disk, a partial that slipped through) leaves the dataset `processing` and retries on
the next reconcile. It never becomes `error`.

`error` persists across restarts, recorded in `datasets/.status.json`, but how it clears
depends on the class.

The node-side classes (`invalid-config`, `unknown-catalog`, `decrypt-failed`,
`writer-rejected`, `scrub-failed`, `internal-error`) are drained at every startup. Fix
the node (add the catalog, add the fingerprint to the writer allow-list, restore the
Vault identity) and restart, or apply the fix without a restart via `dataset reingest
<id>` ([§5](#5-forcing-a-re-ingest)). For a bucket (S3) id that is enough: the durable
object is still there, so the drained id is re-ingested from the unchanged source with no
provider re-upload, and steps 3-4 below are wasted work. For an inbox id it is not: a
permanent error moves the artifact to `inbox/.rejected/`, so the drain leaves no
source behind and the restart merely makes the id absent (`404`). Restore it with
`dataset reingest <id>`, which lifts the quarantined artifact back into the inbox. Once
the `[service].rejected_retention_hours` GC (default `168` h, see the `.rejected/`
callout below) has reaped that entry, step 4 (`deploy --replace`) is the only route left.

The data-fault classes (`invalid-manifest`, `invalid-parquet-schema`, `unsafe-archive`)
are kept across restarts and clear only when the source signature changes. Those are what
steps 3-4 address.

**Symptom → cause → fix.**

1. **Symptom.** `gdi_dataset_state{state="error"} > 0`, or `GET
   /datasets/{id}/state` returns:

   ```json
   {"id": "GDI-EE-EXAMPLE-...", "state": "error",
    "error_message": "invalid-manifest",
    "channel": "inbox"}
   ```

   The `error_message` here is the **closed, sanitized class** (one of
   `invalid-config`, `invalid-manifest`, `invalid-parquet-schema`, `unsafe-archive`,
   `unknown-catalog`, `decrypt-failed`, `query-too-large`, `resource-exhausted`,
   `writer-rejected`, `scrub-failed`, `internal-error` — the full published set, pinned by
   `ErrorClass::ALL` in `crates/core/src/error.rs`). It carries no filesystem paths, no
   Vault or S3 hostnames, and no `internal`-section values.

2. **Find the full cause chain.** The complete `anyhow` cause chain is in the structured
   JSON log on stderr, keyed by the request's `X-Request-Id`. The public plane mints the
   id server-side and ignores any inbound one; the management plane adopts a
   caller-supplied id of 1-128 visible-ASCII bytes, so your orchestrator's id is the one
   to grep for. Both planes echo it in the `X-Request-Id` response header on traced
   routes; `/health/live`, `/health/ready` and `/metrics` sit outside that layer and carry
   no id. It is a span field, so it appears under `span` in each JSON line, on the
   innermost enclosing span rather than at the top level: correlate by `span.request_id`
   to read the un-sanitized chain.

   ```bash
   # in your log store (example: jq over shipped NDJSON)
   jq 'select(.span.request_id == "<the X-Request-Id>")' node.log
   # LOG_FORMAT=ecs lifts it to the ECS field; see the §15 table:
   jq 'select(."http.request.id" == "<the X-Request-Id>")' node.log
   ```

3. **Fix the package** (data-fault classes only). Re-build it with the provider tool so
   the underlying defect (schema, archive layout, parquet) is corrected. A genuine data
   change is a new dataset with a new id, but an `error`ed id never went live, so
   re-present the same id with the corrected package.

4. **Re-present with `--replace`.** Routing depends on the channel reported by
   `GET /datasets/{id}/state`:
   - **S3 channel** → `gdi-dataset-tool upload --replace` (re-uploads the package
     and bumps the marker).
   - **inbox channel** → `gdi-dataset-tool deploy --replace` (re-drops into the
     inbox).

   `--replace` retries an `error`ed id with a fixed package. It does not overwrite a live
   (`visible` or `hidden`) dataset: the node ignores a changed source for a live id. An
   ignored re-drop into the inbox is moved to `inbox/.rejected/{id}/` with a non-error
   reason, so you can see it had no effect. A changed dataset needs a new id.

> Inbox `.rejected/` housekeeping: rejected and ignored artifacts can hold plaintext,
> genotype-derived data. A `.tar.c4gh` drop is quarantined as a single file named for the
> id, with no extension (`inbox/.rejected/{id}`); a plaintext staging dir is quarantined as
> a directory. Match on the id rather than assuming either shape. They are garbage-collected after
> `[service].rejected_retention_hours` (default `168`, seven days) on each startup and
> full scan. Clear them sooner with `dataset purge-rejected [--older-than <dur>]
> [--dry-run]` (§0b) if the volume is tight or the data is sensitive. It applies
> immediately, with no restart or signal.

---

## 5. Forcing a re-ingest

The node's ingest triggers are the S3 reconcile, the inbox scan and watcher, and the
startup reconcile, all feeding one shared queue. Re-ingesting one dataset means clearing
its recorded signature and then making the node reconcile. With `[control].enabled` both
halves are one HTTP call: `POST /datasets/{id}/reingest` applies the clear in-process and
starts the pass (see [api.md](api.md); `404` for an id the node has never seen, `409` when
there is nothing to retry). Without it, the clear is the CLI's queued marker below and the
pass is `POST /reconcile`, the blanket equivalent of `SIGUSR1`, which takes no dataset id.

- **An `error`ed or absent id whose cause was fixed node-side**, such as a missing catalog
  you have since added to `[catalogs]` or a now-present writer allow-list entry, with the
  source package unchanged → `dataset reingest <id>` (§0b). For a bucket dataset this
  clears the id's recorded ETag signature, so the S3 reconcile's same-ETag short-circuit
  no longer pins it, and no provider re-upload is needed. Lock-free, applied on `SIGUSR1`
  or the node's next reconcile.
- **An S3 dataset whose cause needs a corrected package** → `upload --replace`. It
  changes the `.tar.c4gh` ETag, so the signature differs and the id is re-queued.
- **An inbox dataset whose cause needs a corrected package** → `deploy --replace`, which
  re-drops atomically as `*.partial` then `rename`. Or `dataset reingest <id>` if the
  already-corrected original artifact is still quarantined under `inbox/.rejected/{id}`.
- **Converting an existing dataset's at-rest form**: plaintext to PME after enabling
  `[vault].transit_key`, or a re-key after a Transit rotation → re-ingest from S3, the
  source of truth. A fresh ingest re-mints the DEK and rewrites the file under the current
  setting. A re-mint happens only on a new ingest, meaning an `error`ed or absent id,
  where `upload --replace` (S3) or `deploy --replace` (inbox) suffices. For a live
  dataset, see the callout below and §10 step 2.
- **A restart** re-queues anything whose source signature differs from
  `datasets/.status.json`, and re-queues an interrupted in-flight ingest, since
  `processing` is never persisted.

> **Inbox uid contract for host-side drops.** When a permanent-error inbox artifact is
> quarantined, the node moves the staging directory into `inbox/.rejected/{id}/`. Moving a
> directory needs write permission on the directory itself, so a host-side drop deposited
> by a different uid than the node runs as fails with `Permission denied`, and the node
> cannot quarantine it. `dataset purge-rejected` cannot later delete what was never moved
> in either. The node backs that id off and re-attempts on a widening interval, so a
> failed quarantine does not hot-loop the scan. The fix is on the drop side: deposit
> inbox artifacts as the node's uid, or make the inbox setgid and group-writable so the
> node can move them. A single-tenant, node-owned inbox satisfies this, and is the
> recommended posture (see the keyless-inbox warning above).

> A live (`visible` or `hidden`) dataset is immutable, and a changed source is ignored and
> logged (S3) or quarantined to `.rejected/` (inbox). You cannot force-re-ingest a live id
> in place. To re-ingest or re-key one, delete it first and then re-add it: remove the
> object for S3, or publish a `deleted` sidecar for inbox. The `delete` tooling refuses a
> `visible` dataset, so `unpublish` it to `hidden` first or pass `--force`. Delete purges
> the dataset's status entry, so re-presenting the same id afterwards is a fresh ingest
> that re-derives the parquet and re-mints the DEK. The id `404`s in the gap between
> delete and re-add. A real data change is a new id, not a re-ingest of the old one.

---

## 6. Detecting a wedged ingest pool

This is the single-replica failure mode: a full disk or an oversized dataset pins all
`ingest_concurrency` workers, so the queue stops draining. Readiness stays green, because
the read path is unaffected, so this is an alert rather than a probe failure.

**Symptom → cause → fix.**

1. **Symptom.** `gdi_ingest_queue_depth > 0` while
   `gdi_ingest_last_progress_timestamp_seconds` does not advance for several minutes,
   with `gdi_ingest_inflight` typically pinned at `ingest_concurrency`. That timestamp is
   bumped on every outcome, a permanent `error` included, so a frozen timestamp means no
   progress at all rather than merely no successes.

2. **Cause.** Almost always disk pressure, so cross-check `gdi_disk_free_bytes` (§7).
   Otherwise one pathological package. Peak scratch is about
   `ingest_concurrency × (largest .tar.c4gh + its extracted tree)` on `data_dir`.

3. **Fix.**
   - If disk-bound, grow the PVC (§7) and the wedged jobs make progress: disk-full is
     classed transient and retries.
   - If one oversized or crafted package is the culprit, it should hit the decompression
     and size caps and fail fast as a permanent `error` with the matching `error_class`
     (`unsafe-archive` for the package cap). Those caps are
     `max_parquet_decompressed_bytes` (default 4 GiB), `max_parquet_row_group_bytes`
     (default 256 MiB), `max_parquet_file_bytes`, and the whole-package
     `max_package_bytes` (default 16 GiB). The package cap is enforced on the decrypted
     archive as it streams to disk, so an over-cap package is refused before extraction.
     An S3 package whose encrypted `.tar.c4gh` object already exceeds it is refused at
     listing time, before any download into `.incoming/`, so one over-cap upload cannot
     fill the data volume. If the package is merely large, raise `ingest_concurrency`
     headroom or the caps.
   - As a last resort, restart. In-flight ingest is abandoned safely and re-queues on
     startup, because atomic rename means no half-written dataset goes live.

4. **Per-job timeout safety net.** A single ingest that blocks indefinitely (a hung Vault
   mint, a stuck `fsync` on a degraded volume, a pathological decode) does not pin its
   worker forever. After `[service].ingest_timeout_seconds` (default `3600`) the worker is
   freed so the queue keeps draining, and `gdi_ingest_total{outcome="timeout"}` increments;
   alert on any increase. The blocking task cannot be cancelled, so the timed-out thread
   runs to completion in the background and the dataset is left in flight, neither retried
   nor quarantined, so no second ingest can race it. A merely slow ingest that finishes
   there is picked up by the periodic full reload and served without a restart. Recovery
   for a genuinely hung one is a restart, which reaps the `.incoming/` work dir and
   re-scans. Size `ingest_timeout_seconds` above the wall-clock of your largest expected
   ingest, and set it to `0` only if you accept the wedge risk for very large datasets.

### 6.1 Clearing a dataset stuck in `processing`

A dataset shows `processing` while an ingest holds its in-flight guard. Unlike `error`
(§4), `processing` is not terminal: the node is either working on it, or retrying it
after a transient failure. A transient ingest error clears the guard and re-enqueues on
the next reconcile, recording no permanent error. A dataset that stays `processing` for a
sustained window is stuck, not progressing.

1. **Detect.** The `DatasetStuckProcessing` alert watches
   `gdi_ingest_inflight_oldest_age_seconds > 1800`, the age of the longest-held in-flight
   guard, which is where this state lives. The metadata cache never holds `processing`, so
   read the id from `_status/{id}.json` or the ingest logs rather than from the gauge.
   When a retrying backend is the cause, it usually fires alongside `IngestRetryChurn`
   (`increase(gdi_ingest_total{outcome="transient"}[1h])`, the rate of transient failures)
   or `IngestSourceBackoff` (`gdi_ingest_transient_backoff > 0`, one source stuck).
   Per-source retries are paced with capped exponential backoff: the first failure retries
   immediately so a blip is not penalised, and repeats escalate to a 10-minute ceiling.
   `gdi_ingest_transient_backoff` counts the sources currently in a backoff window.

2. **Cause.** A transient dependency is failing for that dataset:
   - the PME **Vault DEK mint** is failing (Vault unreachable or token denied;
     cross-check `gdi_vault_*`), or
   - the data volume is **disk-full or slow** (cross-check `gdi_disk_free_bytes`,
     §7), or
   - a single job is **hung** and was timed out (the per-job timeout safety net
     above / `IngestTimeout`), so it is left in-flight pending a restart.

3. **Fix.** Repair the dependency (Vault back up, disk grown) and the dataset
   self-heals on the next reconcile. No manual state edit is needed, and none is
   possible: `processing` is node-owned, not a sidecar state. If the cause was a hung
   or timed-out job, restart to reap the in-flight thread and re-queue. If the source
   itself is the problem, a package the node can never ingest, remove it: drop the
   inbox artifact, fix and re-present it with a changed signature, or for S3 replace
   or remove the object. It then leaves `processing` on the next scan.

---

## 7. Low-disk alerting

Alert proactively, so the volume is grown before a full disk wedges ingestion (§6).

- **Signal:** `gdi_disk_free_bytes{volume="<data_dir>"}` below your margin for several
  minutes. The `volume` label is the `data_dir` path, an operator-known mount rather than
  request data. Sampled every 10 s.
- **Sizing the margin:** set it at or above peak ingest scratch plus headroom. Peak
  scratch is `ingest_concurrency × 4 × largest .tar.c4gh` on `data_dir`; the 4× covers
  the package, its extracted tree and the conversion intermediates
  ([deployment.md](deployment.md) sizes it). Worked example: `ingest_concurrency = 4` and
  a largest package of 16 GiB (`max_package_bytes`) gives 64 GiB of scratch per in-flight
  ingest and about 256 GiB at four workers; add roughly 25 % headroom and alert below
  about 320 GiB.
- **Why a metric, not a probe:** disk is not a configured subsystem, so it cannot flip
  `/health/ready`.
- **What consumes the volume:** published datasets (`datasets/{id}/`), the status index
  (`datasets/.status.json`), atomic-publish staging and ingest scratch
  (`datasets/.incoming/…`), and the inbox including `inbox/.rejected/` if configured. All
  on the one data volume.
- **Fix:** grow the PVC. Reclaim space by clearing `inbox/.rejected/` sooner; it is
  plaintext, retained 168 h by default. `datasets/.incoming/*` working dirs are reaped on
  every startup, so a restart clears any stranded scratch.

---

## 8. Vault token health

Relevant only when `[vault]` is configured. AppRole renewal fails quietly, and
steady-state readiness will not catch a lapsing token, so alert on metrics. The client
renews a renewable token at about two-thirds of its lease and re-authenticates if renewal
fails.

**Which signal watches which auth mode.** The three modes fail differently, and two of
the alerts cannot fire in some of them, so pick the right one rather than reading a green
board as a healthy credential:

| Auth mode | Renewed by | The signal that matters |
| --- | --- | --- |
| `token` (static) | nobody; it lapses at its own TTL | Neither TTL alert can fire, because the gauge is `0`. Supply a token whose TTL outlives the process; there is no in-node warning. |
| `role_id` + `secret_id` (AppRole) | the node | `VaultRenewalFailing`. `VaultTokenLeaseTooShort` fires only if the granted lease is itself shorter than the margin. |
| `token_file` (agent sidecar) | an external agent, not the node | `VaultTokenFileStale` and `VaultTokenFileUnreadable`. `VaultRenewalFailing` cannot fire, because the node performs no renewals, and `VaultTokenLeaseTooShort` cannot fire, because the TTL gauge stays `0`. |

**Recovering a stale token file.** `VaultTokenFileStale` means the agent stopped
refreshing, so investigate the sidecar, not the node. The node re-reads the file on the
next Vault call after its mtime changes, so once the agent is healthy the node recovers
with no restart. `VaultTokenFileUnreadable` means the file is missing, empty or
unreadable: check the mount and whether the agent was mid-rotation. Both are `critical`.

**Mount points are configurable.** This runbook assumes the defaults. Two of them can
point at an existing mount in a shared Vault: `[vault].kv_mount`, the KV v2 mount holding
the identity and the S3 credentials (default `secret`), and `[vault].transit_mount`, the
at-rest PME Transit mount (default `transit`). `[vault].s3_path` is the KV path holding
the per-bucket S3 credentials, keyed by each bucket's `name`.
`[vault].role_id` + `secret_id` select the AppRole, and
`[vault].connect_timeout_seconds` (default `10`; `0` = unbounded) bounds a connect to a
black-holed endpoint so an unreachable Vault fails fast instead of pinning a
blocking-pool thread. Substitute your own mounts throughout §§8–11.

- **Signals:**
  - `gdi_vault_reauth_total{outcome="failed"}` incrementing. A renewal failed and the
    re-login that follows it failed too, so the token is no longer being re-stamped and
    its last lease will expire. Alert on this, not on the TTL gauge and not on the
    renewal counter.
  - `gdi_vault_renewal_failures_total` on its own is expected to rise. A renewable token
    cannot be renewed past `token_max_ttl`, so every rollover produces one failed renewal
    followed by a successful re-login. At `token_ttl=1h` and `token_max_ttl=24h` that is
    one increment per day on a healthy node. Watch it next to `{outcome="recovered"}`;
    page on neither.
  - `gdi_vault_token_ttl_seconds` is the token's full lease duration, re-stamped on each
    successful renew. It is a step value that never counts down; `0` means a static or
    non-lease token, expected for `[vault].token`. Do not alert on it trending toward
    zero: a healthy token holds its step value, and a lapsing one stops being re-stamped
    rather than ticking down.
- **Symptom → cause → fix.**
  1. **Symptom.** `increase(gdi_vault_reauth_total{outcome="failed"}[15m]) > 0`: a renew
     failed and re-auth could not recover it, so the lease will lapse. Steady-state token
     renewal does not touch `/health/ready`, because the `vault` subsystem stays `ok`
     while cached DEKs keep serving (§1), so a lapsing token is visible only in these
     metrics, never as a `503`. Alert on `gdi_vault_reauth_total{outcome="failed"}`, not the
     readiness probe, the TTL gauge or the renewal counter.
  2. **Cause.** A revoked/expired AppRole `secret_id`, a Vault outage, a policy
     change, or a too-short lease.
  3. **Fix.** Restore Vault reachability, or re-issue the AppRole `secret_id`, supplied
     out-of-band via a mounted Secret or env var and never stored in Vault itself. An
     out-of-band token revocation needs no operator action: the next authenticated
     request meets the `403`, re-authenticates once (single-flighted, so a burst performs
     one login) and retries. AppRole re-exchanges the `role_id` and `secret_id`;
     `[vault].token_file` re-reads the file. A static `[vault].token` cannot self-heal,
     because there is nothing to re-mint, so supply a fresh token and restart. A second
     `403` after re-auth is a policy problem rather than a stale credential, and is left
     as a transient error. Serving is unaffected during a brief Vault outage, because
     unwrapped DEKs are cached.

---

## 9. Rotating a node crypt4gh identity

The node holds one or more crypt4gh identities, from `[keys].identities` (a file list) or
from Vault `[vault].kv_path`, which takes precedence. They are tried in order when
decrypting, and one is the node's published recipient, served at
`/.well-known/c4gh-recipient`.

- **`[keys].identities`**: the first listed is the recipient.
- **Vault**: one PEM per field, each named `c4gh-<epoch-millis>`. The newest is the
  recipient and the rest are decrypt-only, where newest means the greatest parsed millis,
  not the lexicographically greatest field name; see the selection rules below.
  `identity init` mints the first, or imports one with `--from <pem>`, and `identity
  rotate` adds a newer one.

### The Vault KV identity-set layout (for a consumer that shares the key)

An integrating system that reads the same `[vault].kv_path` secret to decrypt a package,
to reach its non-public `files` and `internal` sections, consumes the layout below and
must apply the same selection rules the node's loader and `identity init`/`identity
rotate` enforce. Getting one wrong fails silently: each naive shortcut parses and opens
something, then fails on a specific package.

- **Layout.** The secret is a flat map of `c4gh-<epoch-millis>` to an unencrypted
  crypt4gh-v1 secret-key PEM, one field per identity. The millis component is zero-padded
  to a fixed width, so conforming field names sort chronologically as plain strings. Rely
  on the parsed-integer rule below, not on that.
- **The published recipient is the greatest parsed millis.** Parse the millis out of each
  `c4gh-<millis>` field and take the numeric maximum, not the lexicographically greatest
  map key. A non-conforming field name such as a hand-added `node-prev` sorts after
  `c4gh-` as a raw string and would hijack the recipient slot under a key-max.
- **Non-conforming fields are decrypt-only.** A field whose name is not `c4gh-<millis>`
  is retained as a fallback key for decryption and is never promoted to the published
  recipient.
- **No conforming identity means fail closed.** A secret that has fields but no
  `c4gh-<millis>` identity is an error. Do not promote a fallback to recipient.
- **Decrypt by trying every identity, newest first.** A package opens only with the key it
  was wrapped to, so after a rotation an older package opens with a non-recipient
  fallback rather than the published key. A reader must try the whole set, recipient
  first, then the retained fallbacks. A "decrypt with the published recipient" shortcut
  breaks on the first package that predates the current rotation.

These rules are the contract. The node, `gdi-dataset-tool` (rekey and retire) and any
integrating system that shares the key all implement it.

> **Inspecting and idempotent init.** `gdi-node-standalone identity list` prints the
> current Vault identity state: the fields, and which is the published recipient. It is
> read-only, so it is safe at any time. `identity init --ensure` treats an
> already-provisioned identity as success (exit `0`) instead of erroring, so a re-run of a
> bring-up script is a no-op rather than a failure.

> **Node identity keys must be unencrypted crypt4gh-v1 keys.** The loader accepts only the
> plain `c4gh-v1` secret-key format (`kdf` and `cipher` both `none`), as produced by the
> node's own `identity init` in either posture, or by `crypt4gh-keygen --nocrypt`. A
> passphrase-protected key or an OpenSSH-format identity is rejected at startup with an
> explicit error. Node key material is therefore stored unencrypted at rest, on disk or in
> Vault: protect it with file permissions and volume or at-rest encryption, not an in-file
> passphrase. `identity init` writes the key `0600`, and the node refuses to start on a
> group- or other-readable key under `[service].strict_key_perms` (the default).

### The file-backed identity (no `[vault]`)

A node without `[vault]` keeps its identity in the files at `[keys].identities`, the first
of which is the published recipient. The node mints it itself. `gdi-dataset-tool` is the
provider's CLI, a different actor and usually a different organisation, and is not needed
to operate a node:

```bash
# Mint into the first [keys].identities entry (writes <path> 0600 + <path>.pub).
gdi-node-standalone --config node.toml identity init --ensure

# …or name the key file explicitly / import an existing one:
gdi-node-standalone --config node.toml identity init --file keys/node.c4gh
gdi-node-standalone --config node.toml identity init --from /secure/existing.c4gh
```

Create-only, like the Vault form: an existing key is never silently replaced. `--force`
replaces it, first copying the old key to a `.bak-<epoch>` sibling. Keep that backup until
every package wrapped to the old key has been re-keyed (routine rotation, below), because
nothing else can open them.

Inspect what is configured at any time. This is read-only, works on any build, and applies
the loader's own rules, so a non-zero exit means the node would not start:

```bash
gdi-node-standalone --config node.toml identity list
# node crypt4gh identities (2 configured in [keys].identities, tried in order; …):
#   [0] PUBLISHED RECIPIENT  /keys/node.c4gh
#       fingerprint: sha256:f3920f42…
#   [1] decrypt-only         /keys/node-2026.c4gh
#       fingerprint: sha256:55db4d8a…
```

#### Rotating a file-backed identity

There is no `identity rotate` for the file posture. Rotation there is one mint plus one
config edit, and the config is the operator's file: under Ansible, Kustomize or Helm a
node that rewrote `node.toml` in place would either be reverted on the next converge or
cause silent drift. The node mints the key and you place it:

```bash
# 1. Mint the new key alongside the current one (create-only; never touches the old key).
gdi-node-standalone --config node.toml identity init --file keys/node-$(date +%Y%m%d).c4gh

# 2. Edit [keys].identities: put the new file first, and keep the old one after it.
#    identities = ["keys/node-20260721.c4gh", "keys/node.c4gh"]

# 3. Verify before restarting: the new key must be [0], the old one still present.
gdi-node-standalone --config node.toml identity list

# 4. Restart. Identities load once at startup; there is no SIGHUP reload for [keys].
```

Dropping the old key from the list is the one irreversible mistake here: every package
still wrapped to it becomes unreadable, and the loss surfaces only on a later ingest or a
store rebuild. Keep it until the re-key window closes (below), then remove it and restart.

#### Backing up a file-backed identity

There is no `identity backup` for this posture either, because the key is a file: copy
it. `identity backup` exists for Vault because the key lives in Vault KV and has to be
exported to become a file at all.

```bash
install -m 0600 keys/node.c4gh /secure/offline/node-$(date +%F).c4gh
```

Treat that copy as the node's most sensitive artifact: it decrypts every ingested package
and, under PME, all at-rest parquet. It belongs with the other non-rederivable state in
§17's disaster-recovery inventory; losing it is unrecoverable.

crypt4gh headers are re-encryptable: a package's recipients can be changed by rewriting
only the header, with no payload re-encryption.

> **The node does not rewrite packages.** It has read-only S3 access and consumes inbox
> drops on ingest. Re-wrapping a package's header is done by whoever owns the package and
> its bucket, the provider or orchestrator, who writes a whole new object because S3
> objects are immutable. The node's only role is to accept old and new identities during
> the re-key window, then drop the old one.

### Routine rotation

1. **Add the new identity so it becomes the published recipient**, keeping the old
   one for decryption:
   - **Vault:** run `gdi-node-standalone identity rotate`. It mints a fresh keypair and
     adds it under a field that sorts after the current newest (so it becomes the
     recipient) via a check-and-set, without deleting any existing key.
   - **`[keys].identities`:** prepend the new identity file as the **first** entry,
     keep the old **after** it.

   Restart the node so the new set loads. It now publishes the new recipient and can
   still decrypt anything wrapped to either.
2. Confirm `/.well-known/c4gh-recipient` serves the new public key and
   `/health/ready` reports `key_material: ok`.
3. **Re-wrap existing packages' headers to the new recipient** (package owner's job)
   with `gdi-dataset-tool rekey`. It decrypts each package's session key with the
   provider's identities, then re-wraps it to the new node recipient, plus the
   provider's own recipient so the provider can still decrypt. The package is written
   back with the new (same-length-class) header and the body unchanged, so there is no
   payload re-encryption. Per package:

   ```bash
   # In place (requires --force); the new node recipient comes from the active
   # profile (or pass --recipient <new-node.pub> for an offline recipient file).
   gdi-dataset-tool rekey <id>.tar.c4gh --force

   # Or write a new object and upload it (S3 objects are immutable). `upload` derives the
   # dataset id from the file name, which must be exactly {id}.tar.c4gh, so write the
   # re-keyed package to a separate directory rather than decorating its stem.
   mkdir -p rekeyed
   gdi-dataset-tool rekey <id>.tar.c4gh -o rekeyed/<id>.tar.c4gh --recipient new-node.pub
   gdi-dataset-tool upload rekeyed/<id>.tar.c4gh --replace
   ```

   > **On a `writer_policy = enforce` node, pass `--as <your-provider-key>`.** A plain
   > `rekey` re-signs the header with a fresh ephemeral writer key, so the recovered writer
   > fingerprint changes and an `enforce` node rejects every rekeyed package as
   > `error/writer-rejected`, fleet-wide, with fingerprints unknowable in advance. `--as`
   > re-signs as your own provider key, the one that authored the original package, so the
   > fingerprint stays the one already on the channel's `allowed_writer_fingerprints`:
   > ```bash
   > gdi-dataset-tool rekey <id>.tar.c4gh --as ~/.config/gdi/keys/provider.c4gh --force
   > ```
   > Pass `-v` to see which writer key was used. `rekey` announces the fingerprint and
   > warns when it mints an ephemeral one, but both go to stderr at verbose level only; at
   > default verbosity it reports the recipients alone, so a plain re-key looks identical
   > to an `--as` one. On a `warn` or `off` node the plain form is fine, because the
   > ephemeral writer is not gated. Full flag reference:
   > [`rekey`](gdi-dataset-tool.md#rekey) in the provider tool doc.
4. Once every package has been re-wrapped, retire the old identity rather than
   hand-editing Vault.
   - **Vault:** preview with `gdi-node-standalone identity retire --dry-run`, then apply with
     `gdi-node-standalone identity retire --yes`. This destructive op refuses without one
     of those two flags; there is no bare form. It removes the oldest retained
     (decrypt-only) key via a check-and-set, refuses to drop the published recipient or
     the sole remaining key, and emits an `identity_retired` audit line. It retires one
     key per invocation, so run it again to prune the next-oldest.
     > **A quarantined package blocks the retire until you deal with it.** The openability
     > guard sweeps `inbox/.rejected/`, and an entry it cannot probe makes the retire
     > demand `--force`. A directory-form quarantine entry, whose recipient key it cannot
     > read, is one such entry. The message names both ways out: clear the entries with
     > `dataset purge-rejected`, or retire with `--force` and accept the orphaning below.
     >
     > **`--force` bypasses the openability guard. Do not use it routinely.** Retire
     > normally refuses when it would leave a package that no surviving key can open, i.e.
     > an orphaned, permanently undecryptable package. `--force` retires anyway and orphans
     > those packages. It exists for a key already known compromised or lost, where you
     > accept the orphaning. Otherwise `rekey` every package to a surviving key first (step
     > 3), then retire without `--force`. The guard's bucket scan uses the same
     > Vault-backed S3 credentials serve-time uses (`[vault].s3_path`), so a scan failure
     > is a real problem to fix, not a reason to force past it.
   - **`[keys].identities`:** remove the old key file's entry from the list and
     restart.

   **Restart the running node for a retirement to take effect.** Identities load once at
   startup and there is no runtime reload path, so a retired key stays live in memory, and
   usable for decryption, on the running process until it is restarted. `identity retire`
   changes Vault, not the running node. The same holds for `identity rotate`: the live
   node keeps publishing the previous recipient until restarted. Retirement and revocation
   latency is bounded by when you restart, not by the command.

   Retention is bounded by the re-key window, not permanent. See §17 for keeping the
   identity backup in step with retirements.

### Compromise variant

The same procedure, run urgently, to cut off future access to the store. Any ciphertext an
attacker already copied while holding the compromised key stays exposed: re-wrapping the
header does not help for bytes already taken, and the only cure there is provider-side
re-encryption from plaintext. On the public aggregated tier the data is served publicly
anyway, so this residual is accepted; it must be closed before the sensitive tier.

---

## 10. Rotating / revoking a Vault Transit (at-rest) key

Applies only when PME is enabled: the build includes the `pme` feature and
`[vault].transit_key` is configured. With PME off this section is moot, but `SIGHUP` is
still not a no-op: on every unix build it re-parses the config file and reloads
`[catalogs]` and the `[ingest]` writer-key allow-list (§14). Only the DEK-cache flush is
skipped.

Each PME parquet file stores a self-describing `key_metadata` carrying its wrapped
DEK (`vault:vN:…`). The unwrapped DEK is held in a `zeroize`-backed in-process
cache (default TTL 1 hour), single-flighted on miss, so steady-state reads never
call Vault.

### Routine rotation (not revocation)

A **key-version bump** only:

1. `vault write -f transit/keys/<key>/rotate` (or the OpenBao equivalent).
2. Done. New ingests wrap their DEK under the new version, and older PME files keep
   their version stamp and still read, because Vault keeps unwrapping the old version.
   Forward-only: no re-ingest, no cache flush needed.

> Rotation is not revocation. A version bump alone does not stop an already-written
> file's old-version DEK from being unwrapped.

### Revoking a compromised key version (five steps, in order)

1. **Bump the Transit key** (rotate, as above) so new wraps use a fresh version.
2. **Re-ingest every PME dataset** so each file's DEK is re-minted under the new version.
   S3 is the source of truth, so re-ingest from the bucket. A re-mint happens only on a
   new ingest, and published datasets are live and therefore immutable, so a bare
   `upload --replace` or re-drop is ignored for them (see the §5 callout). Delete each
   dataset, then re-add it. For S3, remove the object (`unpublish` a `visible` one first,
   or pass `--force`) and re-`upload`. For an inbox-only node, publish a `deleted`
   sidecar, then re-drop the package. Each dataset `404`s in the gap between its delete
   and re-add, so stage this per dataset, or in a maintenance window, if continuous
   availability matters.
3. **Raise `min_decryption_version`** past the retired version so Vault refuses to
   unwrap any old-version DEK:

   ```bash
   vault write transit/keys/<key>/config min_decryption_version=<new-min>
   ```

   Do this only after step 2 completes for every dataset. Raising it first makes the
   not-yet-re-keyed files unreadable.
4. **Reseal the at-rest sentinel.** `<data_dir>/.pme-sentinel.json` was wrapped at the
   *retired* version, so step 3 makes Vault refuse to unwrap it by policy (a 400, which the
   node classifies permanent). On the next boot that latches `gdi_pme_master_key_mismatch`
   and `ready: false`, on a node whose datasets are all correctly re-keyed. Run:

   ```bash
   gdi-node-standalone pme reseal --yes
   ```

   > **`reseal` refuses over a sentinel scheme this build does not know.** It rewrites the
   > node's at-rest key binding, and doing that blind would downgrade state written by a
   > newer binary. The refusal names the fix: run the newer binary. There is no override
   > flag. Every other `reseal` failure, such as a damaged sentinel or a Transit key that
   > cannot unwrap it, is the ordinary case this step is for.

   `reseal` verifies the current key can still read a real `PARE` dataset before rewriting
   the sentinel, and refuses if it cannot, so this step cannot mask an incomplete step 2.
   Skipping it turns a successful revocation into a serving outage.
5. **Flush the in-process DEK cache** so no cached plaintext DEK keeps serving
   until its TTL:
   - send **`SIGHUP`** to the process (`kill -HUP <pid>` /
     `kubectl exec ... -- kill -HUP 1`), or
   - **`POST /reload`** on the management plane: the same handler, so it flushes the cache
     too (opt-in via `[control].enabled`; see [api.md](api.md)). Use it when you cannot
     `kubectl exec`, which is the common case, since revoking a key is when you need the
     flush and can least afford the pod restart below. It flushes whether or not the config
     changed, and whether or not the candidate config was accepted.
   - **restart** the pod.

   `SIGHUP` drops every cached DEK at once, bounding revocation latency to the signal
   rather than the cache TTL.

**Residual:** data an attacker already copied and decrypted while the key was valid cannot
be un-disclosed, the same caveat as on the crypt4gh side. Accepted for the public
aggregated tier; a precondition to close before the sensitive tier.

### Scripting the bulk re-ingest (verify-driven)

There is no built-in "re-key everything" command: the node exposes no mutation endpoint,
so bulk orchestration belongs to the operator or back-office layer. The offline `verify`
subcommand makes a loop straightforward, because after a key change every affected PME
dataset fails to read and is printed as `FAIL  <id>  <detail>`.

> **Stop the node first.** `verify` takes the data-dir writer lock, so against a running
> node it refuses and prints nothing to stdout; the error goes to stderr and the exit is
> non-zero. An empty work-list is then indistinguishable from "everything is healthy", and
> step 3's re-verify is satisfied by the same empty output, so the procedure can appear to
> succeed while verifying nothing, immediately before you raise `min_decryption_version`
> and make the not-yet-rebuilt files permanently unreadable. Run it against a stopped node,
> or a copy of its `data_dir`. The `set -euo pipefail` and the non-empty guard below turn
> that silent no-op into a loud failure.

```bash
# bash, not sh: `pipefail` is not POSIX and dash exits on it immediately.
set -euo pipefail

# 1. Discover what to rebuild (the datasets that no longer decrypt). Review the list
#    first: the steps below delete published datasets and each id 404s while it rebuilds.
#    Stop the node first: a running node holds the writer lock and `verify` refuses.
#
#    `verify` exits non-zero exactly when it finds FAILs, i.e. whenever there is work to
#    do, so capture its status rather than letting it trip `set -e`.
rc=0
gdi-node-standalone verify > verify.out || rc=$?
awk '/^FAIL/ { print $2 }' verify.out > to-rebuild.txt
# An empty list is not "all healthy" unless verify actually ran: a running node, or any
# other lock holder, yields an empty file. Refuse to proceed on empty, so step 3's
# "expect zero FAILs" cannot be satisfied by a verify that never ran.
[ -s to-rebuild.txt ] || { echo "no FAIL rows in verify.out (verify exit $rc); did verify run? stop the node first"; exit 1; }

# 2. Per id (S3 node shown): delete, wait until the node has evicted and purged the id,
#    then re-present the same archived package. The wait is required: re-uploading
#    before the purge looks like a changed source on a live id and is silently ignored,
#    not rebuilt (see §5). S3 deletion removes the only bucket copy, so hold the source
#    packages in $ARCHIVE.
while read -r id; do
  gdi-dataset-tool delete --force "$id"
  until ! gdi-dataset-tool list | grep -qw "$id"; do sleep 5; done   # confirm eviction
  gdi-dataset-tool upload "$ARCHIVE/$id.tar.c4gh"                     # fresh ingest re-mints the DEK
done < to-rebuild.txt

# 3. Re-verify; expect zero FAILs.
gdi-node-standalone verify
```

For an inbox node, swap the `delete` for publishing a `{"state":"deleted"}` sidecar (or
`delete --force`), and the `upload` for `deploy`; the same evict-before-re-present rule
applies. Treat this as a skeleton, not a turnkey script: it is destructive, each id is
unavailable until its re-ingest completes, the `list` match is illustrative, and it
assumes the source packages are archived. Stage it in a maintenance window, or one id at a
time, if availability matters. A large estate belongs in the back-office layer, not this
loop.

---

## 11. Running without Vault (the S3 profile)

A common deployment monitors an S3 bucket (Ceph with Rook, Garage, MinIO) but runs
without a secrets backend and without at-rest PME, serving public aggregated data. This is
the S3 profile. There is no separate download for it: run the shipped `full` binary with
no `[vault]` block, which leaves the Vault and PME subsystems dormant, or build a smaller
`--features s3` binary. Start from [`node.quickstart.toml`](../node.quickstart.toml),
which is this shape: `[[s3.buckets]]` plus `[keys]`, no `[vault]`. See
[`node.example.toml`](../node.example.toml) for the full knob reference.

**Where the secrets live (no Vault to hold them).**

- **S3 credentials.** With no `[vault]`, the inline `[[s3.buckets]]` `access_key_id` and
  `secret_access_key` are the source; nothing overrides them. Do not commit real keys.
  Supply them out-of-band, preferring an env var or a mounted file over an inline literal:
  `GDI_NODE__S3__BUCKETS__0__ACCESS_KEY_ID` and `…__SECRET_ACCESS_KEY`, where env always
  wins over the file. A process environment is readable via `/proc/<pid>/environ`,
  `docker inspect` and pod specs; a mounted Secret file is not. On Kubernetes also enable
  etcd Secret encryption-at-rest (§17). If the bucket is public-read, omit both
  credentials and the node reads anonymously, holding no S3 secret at all.
- **The node crypt4gh identity.** Comes from `[keys].identities` local key files instead
  of `[vault].kv_path`. Supply them as mounted Secrets, and set
  `[service].strict_key_perms = true` to refuse start on a group- or other-readable key.
  Rotation is file-based: prepend the new identity file as the first `[keys].identities`
  entry, so it becomes the published recipient, keep the old one after it for the re-key
  window, then restart. `gdi-node-standalone identity rotate` is Vault-only: it writes to
  `[vault].kv_path` and errors without a `[vault]` block, so it does not apply here. §9
  covers both modes.

**At-rest encryption.** No Vault means no `[vault].transit_key`, so PME is off and the
payload's at-rest protection is volume-level only: an encrypted PVC or StorageClass,
LUKS/dm-crypt, or node full-disk encryption. For public aggregated data that is the right
baseline, since PME's extra app-level layer exists to keep a secret-wrapping key off the
data volume. Dataset packages in the S3 bucket remain crypt4gh-encrypted either way,
independently of Vault.

**Readiness.** The Vault subsystem reports `not-configured` rather than `unavailable`,
and the keyless mode reports `ok`. Neither fails readiness (§1). The `gdi_vault_*` metrics
(§2) stay at zero, and the Vault-token and Vault-renewal alerts (§3, §8) do not apply.

**Disaster recovery (§17) is simpler.** There is no Transit master key to lose. The only
irreplaceable secret is the node identity in the `[keys]` files. Back those up
out-of-band: lose them and you must re-key and re-publish the recipient, as with the Vault
`kv_path` identity.

---

## 12. Dataset lifecycle and state transitions

A lookup map of how a dataset moves through the node; the procedures live in the
cross-referenced sections. The four served states are the canonical `DatasetState` from
`crates/core/src/state.rs`: `visible`, `hidden`, `error`, `processing`. The `deleted`
tombstone is an operator command rather than a served state: a deleted dataset is removed
and then `404`s. `ready` is not a dataset state; it is a readiness-probe outcome.

| State | Persisted? | Served as | Set by |
| --- | --- | --- | --- |
| `processing` | No (ephemeral; never written to `.status.json`) | id + state only | queued from reconcile / inbox scan / startup |
| `visible` | Yes (`datasets/.status.json`) | full public metadata; listed in catalogs/collections | operator `{id}.state.json` sidecar = `visible` |
| `hidden` | Yes | id + state only; excluded from listings | sidecar = `hidden`, **or the default** when ingest succeeds with no/unrecognized sidecar |
| `error` | Yes (with sanitized `error_message`) | id + state + closed-class message | a **permanent** ingest failure; not held in the cache |
| `deleted` (a tombstone, not a `DatasetState`) | n/a, removed | becomes `404` | operator `{"state":"deleted"}` sidecar (inbox) / object removal (S3) |

| From → To | Trigger | Where |
| --- | --- | --- |
| (none) → `processing` | queued / being ingested (incl. transient-retry wait) | [§5](#5-forcing-a-re-ingest), [§6](#6-detecting-a-wedged-ingest-pool) |
| `processing` → `visible` | successful ingest + sidecar `visible` | [§13](#publishing--changing-visibility) |
| `processing` → `hidden` | successful ingest + sidecar `hidden`, **or no governing sidecar** (default), which is why a fresh dataset is invisible until you publish it | [§13](#publishing--changing-visibility) |
| `processing` → `error` | a **permanent** data/validation failure (bad manifest, unsafe archive, bomb parquet, no identity decrypts) | [§4](#4-clearing-a-dataset-stuck-in-error) |
| `processing` → `processing` (re-queue) | a **transient** infra failure (Vault unreachable, disk full); never becomes `error` and self-heals on the next reconcile | [§6](#6-detecting-a-wedged-ingest-pool) |
| `visible` ↔ `hidden` | operator flips `{id}.state.json` | [§13](#publishing--changing-visibility) |
| `error` → `processing` | **data-fault** classes (`invalid-manifest`, `invalid-parquet-schema`, `unsafe-archive`): re-present the same id with a corrected package so the source signature changes (`--replace`); these clear only on a changed signature. The node-side classes drain at startup instead (or on `dataset reingest <id>`), an inbox id additionally needing its quarantined artifact restored | [§4](#4-clearing-a-dataset-stuck-in-error), [§5](#5-forcing-a-re-ingest) |
| any → removed (then `404`) | `deleted` tombstone (inbox) / object removal (S3); a bucket-owned id ignores an inbox `deleted`, and a `visible` dataset is refused without `force` | delete semantics |
| restart (hydrate) | absent-from-index → `hidden` (never `visible` without a sidecar); `error` ids have no dir and are skipped; `processing` is never persisted, so an interrupted ingest re-queues | [§17](#17-disaster-recovery) |

**An operator suppression override always takes precedence over the source.** Everything
in the table above is driven by the source: the inbox or bucket sidecar, and the ingest
outcome. A `dataset hide`/`take-down`/`show` override
(`<override_dir>/suppressions/{id}.json`, §0b) sits above all of it and applies on either
channel.

- **`hide`** forces the served state to `hidden` whatever the source sidecar says. Local
  data is untouched and it is reversible via `dataset unhide`.
- **`remove`** forces `hidden` immediately, then erases `data_dir/{id}` on the node's next
  apply (`SIGUSR1` or the periodic reconcile), after which the id `404`s. The ingest gate
  also refuses to re-ingest a `remove`-suppressed id, so a still-present source package
  cannot silently re-materialise it. `dataset unhide` lifts the override by removing the
  override file only; it does not touch the status index or the S3
  `last_seen_signature`. Re-ingest on lift still works, because the earlier erase already
  purged the whole status entry, `last_seen_signature` included: once the override is
  gone, the next poll sees the still-present bucket package as new and re-ingests it. A
  `hide` erased nothing, so lifting it lets the next reconcile restore the id to its
  source-resolved state.
- **`channel hide`/`take-down`/`show`** (§0b) is the same override at channel granularity
  (`<override_dir>/suppressions/channel-{name}.json`). Every dataset whose `channel`
  equals `name` gets the same `hide` or `remove` treatment, and the channel's ingest is
  paused: a bucket's poll loop stops entirely and the inbox scanner skips its scan. A
  compromised provider therefore cannot push new packages while suppressed. Where an
  id-level and a channel-level override both apply to one dataset, the most restrictive
  wins: `remove` beats `hide` beats serve.
- The override is node-local and read-only against the source. It never writes to a
  provider's bucket, and it does not survive `data_dir` loss (§17): the files live under
  `<override_dir>` (default `<data_dir>/overrides/`).
- It is applied on `SIGUSR1`, by `POST /reconcile` (opt-in, see [api.md](api.md)), and by
  the periodic full reload, so it lags a just-written file by at most one reconcile
  interval if nothing triggers a pass. The CLI does not signal the node; it prints how to
  (§0b). The override file is authoritative the instant it lands; only its application to
  the running node can lag.
- **Visibility.** `GET /datasets/{id}/state` shows `suppression: {mode, at}` while active
  (§19), but not the justification: that is free text which in practice names people, and
  this plane is unauthenticated. Read it from the override file or the `REASON` column of
  `dataset list`; it is not in the `dataset_suppressed` audit event either (§21).
  `dataset list --suppressed` and the `SUPPRESSED` column list every overridden id.
  `gdi_datasets_suppressed{mode}` is the fleet-wide count, and
  `gdi_suppression_load_degraded` flags a broken override file (§2, §21).

**Remove an S3 dataset with the tool or a `hidden` flip, not out-of-band bucket surgery.**
On the S3 channel the node reconciles a package deletion only on a sync-marker change. A
periodic safety-net poll does not evict on a package absence while `_sync_marker.json` is
unchanged: an absent package under an unchanged marker is more likely a truncated listing
than an intended delete. The tool's `delete` bumps the marker and evicts promptly.
A manual `aws s3 rm` of the `{id}.tar.c4gh` does not bump it, so the node keeps serving its
local copy until the marker next changes or the node restarts. To stop serving immediately
without deleting the package, set the dataset `hidden` via `{id}.state.json`; visibility
flips are not marker-gated. Startup always reconciles removals, so a delete performed while
the node was down is applied at boot.

**Why is my dataset stuck?** Stuck `error` →
[§4](#4-clearing-a-dataset-stuck-in-error). Stuck `processing` →
[§6](#6-detecting-a-wedged-ingest-pool). Ingested but not appearing publicly: it defaulted
to `hidden`, so publish a `visible` sidecar
([§13](#publishing--changing-visibility)).

---

## 13. Correcting dataset metadata

The encrypted package and its data are immutable: a data change is always a new dataset
with a new id. The public metadata fields (title, description, license and so on) can be
corrected in place without touching the package, by dropping a `{id}.metadata.json`
overlay sidecar beside the package in the inbox or S3 bucket.

### What to drop

Create a plain JSON object containing only the fields you want to change. It is a field
patch, not a replacement of the metadata section:

```json
{
  "title": {"en": "Corrected title"},
  "license": "http://publications.europa.eu/resource/authority/licence/CC_BY_4_0"
}
```

For an inbox dataset, drop it atomically into the inbox alongside the package:

```bash
cp /tmp/GDI-EE-EXAMPLE-20260409143052837.metadata.json inbox/GDI-EE-EXAMPLE-20260409143052837.metadata.json.partial
mv inbox/GDI-EE-EXAMPLE-20260409143052837.metadata.json.partial inbox/GDI-EE-EXAMPLE-20260409143052837.metadata.json
```

For an S3 dataset, upload it to the same bucket and key prefix as the package:

```bash
aws s3 cp GDI-EE-EXAMPLE-20260409143052837.metadata.json \
    s3://<bucket>/GDI-EE-EXAMPLE-20260409143052837.metadata.json
```

The node reconciles the sidecar on its next scan or poll cycle, as it does for
`{id}.state.json`.

### Editable fields

Every field of the public `metadata` section is patchable except four protected ones:

| Protected (cannot patch) | Reason |
| --- | --- |
| `datasetId` | the id is the package's identity |
| `catalog` | determines the catalog the dataset is listed under |
| `numberOfRecords` | provider-computed and verified against the beacon parquet at ingest; a manifest whose count disagrees with the data is rejected |
| `populations` | re-derived from the beacon parquet at ingest, like `numberOfRecords`; the served strata are a property of the data, not of the metadata |

All other public metadata fields are editable, including: `title`, `description`,
`accessRights`, `applicableLegislation`, `license`, `creator`, `healthCategory`,
`keywords`, `numberOfUniqueIndividuals`, `conformsTo`, `type`, `legalBasis`,
`isReferencedBy`, `otherIdentifier`, `contactPoint`.

A sidecar containing a protected field name or an unrecognised key is invalid and ignored
in its entirety; the parser rejects it with `deny_unknown_fields`. Check the logs for the
warning, fix the sidecar, and the next reconcile picks up the corrected version.

**Localised fields.** `title` and `description` are localisation maps. When you patch one,
supply all languages at once: the entire map replaces the package baseline. Partial
per-language patching, such as correcting only `"en"` while keeping the package's `"fi"`,
is not supported.

### Effect on timestamps

- **`dct:modified`** advances to the time the node applied the overlay, and is reported in
  the FDP dataset record and the portal's Modified column. The applied timestamp is
  persisted in `datasets/{id}/.metadata.overlay.json` and survives restarts, so the
  original application time is preserved rather than re-stamped on every restart. It is
  also monotonic: a durable high-water mark (`datasets/{id}/.metadata.modified`) records
  the latest applied time and is retained across a revert, so `dct:modified` never moves
  backward. A backward timestamp can make an incremental harvester skip a genuine change.
- **`dct:issued`** never changes. It records the dataset's original creation time, from
  the `datasetId` timestamp, and is unaffected by metadata edits.

### Reverting an overlay

Remove the sidecar. The node detects the removal on its next reconcile and reverts the
dataset to its package-baseline metadata:

- **Inbox**: delete the file from the inbox directory.
- **S3**: delete the object from the bucket.

After the revert the served metadata is the package baseline again, but `dct:modified`
does not move backward: it stays at the last applied time, the retained high-water mark,
because the revert is itself a change to the served record. `dct:issued` is unchanged.

### Invalid overlays

If the merged result fails gdi-metadata model validation (a required field nulled out, a
wrong controlled-vocabulary value) the overlay is ignored and the dataset keeps serving
its last-good metadata. No quarantine, no `error` state. Check the structured log for the
`WARN` line identifying the validation failure, fix the sidecar and re-drop it.

### Operator-mediated only

There is no `gdi-dataset-tool` command for metadata overlays: write the JSON directly and
place it alongside the package. There is no node-wide "change one field across all
datasets" operation; overlays are always per-dataset.

### Node-local override: for a bucket dataset, or without touching the source

Everything above describes the source-authored `{id}.metadata.json` sidecar dropped in the
inbox or the bucket. The node is read-only against a provider's bucket, so that path does
not help when you need to correct a bucket-owned dataset's metadata and either cannot or
should not write to the bucket. `dataset correct` closes that gap with a node-local
override, applied through the same overlay engine: the same field-patch shape,
`deny_unknown_fields`, the four protected fields, the monotone `dct:modified` high-water
mark, gdi-metadata validation, and the "invalid means ignored, keep last-good" contract
above.

```bash
gdi-node-standalone dataset correct GDI-EE-EXAMPLE-20260409143052837 \
  --field title.en="Corrected title" \
  --field license=http://publications.europa.eu/resource/authority/licence/CC_BY_4_0
# or, from a patch file:
gdi-node-standalone dataset correct GDI-EE-EXAMPLE-20260409143052837 --patch correction.json
```

`--field KEY=VALUE` is repeatable. A dotted `KEY` sets a nested or localised field
(`title.en=...`, `title.fi=...`); supply every language you want present, as with the
sidecar. `VALUE` is parsed as JSON when it parses cleanly, so `--field
numberOfUniqueIndividuals=42` becomes a number and `--field
keywords='["covid","variant"]'` becomes an array; otherwise it is taken as a bare string,
so a plain IRI needs no quoting. `--field` and `--patch` are mutually exclusive. A
protected field (`datasetId`, `catalog`, `numberOfRecords`, `populations`) or an unknown
key is rejected before anything is written, under the same `deny_unknown_fields`
allow-list as the sidecar.

This writes (or refreshes) `<override_dir>/overlays/{id}.json`, the sibling store to
`<override_dir>/suppressions/{id}.json` (§12), read at boot, on `SIGUSR1`, and on every
reconcile pass. Revert with:

```bash
gdi-node-standalone dataset correct GDI-EE-EXAMPLE-20260409143052837 --reset
```

which removes the override file; the dataset reverts to the package baseline (or
resumes a source `{id}.metadata.json`, if one is present) on the node's next
reconcile. The `dct:modified` high-water mark is unaffected by `--reset`, for the same
reason a sidecar revert does not move it backward (see Effect on timestamps, above).

**Precedence: operator beats source.** While a node-local override exists for an id, the
node ignores that id's bucket or inbox `{id}.metadata.json` sidecar entirely. It is
neither applied on top of the override nor treated as a reason to revert it, mirroring how
a `dataset hide`/`take-down` suppression override wins over the source's `{id}.state.json`
(§12). Remove the override with `--reset` to let the source sidecar resume governing.

The same actor caveat applies as for suppression overrides (§12): the audit actor is the
file-writer, not an authenticated identity.

### Publishing / changing visibility

Visibility is not one of the metadata fields above. It is governed by a separate
`{id}.state.json` sidecar, dropped beside the package in the inbox, or uploaded to the
same bucket and key prefix for an S3 dataset, exactly like the metadata overlay. A
freshly-ingested dataset is `hidden` by default. Publish it, and later hide, unpublish or
tombstone it, by writing this sidecar. In the inbox, drop it atomically: `*.partial`,
then `rename`, as in the metadata example above. Accepted `state` values:

| `state` value | Effect |
| --- | --- |
| `visible` | published: full public metadata, listed in catalogs/collections |
| `hidden` | served as id + state only, excluded from listings |
| `deleted` | tombstone: the dataset is removed and then `404`s (inbox; for S3 remove the object instead) |

**Fail-safe to `hidden`.** A `state` value outside the set above is treated as `hidden`,
never `visible`, including on an already-visible dataset. A typo while trying to hide
something can only under-expose, never accidentally publish. The node logs a grep-able
`WARN`: `unrecognized state sidecar value; failing safe to hidden`.

A sidecar that could not be read or parsed at all fails safe the same way. The node logs
`WARN unreadable state sidecar; failing safe to hidden (a half-written retraction must not
leave a dataset published)`, counts it in
`gdi_state_sidecar_rejected_total{reason="unreadable"}` (§2, and the **State sidecar
rejected** alert in §3), and withdraws the dataset from the public plane. The condition
may be transient (a partial write caught mid-scan, a disk blip) and the next scan
re-reads the file, but until a well-formed sidecar is read the dataset stays hidden: a
sidecar an operator was midway through writing is likelier to be a retraction than a
publication. The symptom of a persistently unreadable sidecar is therefore a missing
dataset, not a lingering one. Fix the file, or replace it with a well-formed
`{"state":"visible"}`, and it returns on the next scan; meanwhile
`GET /datasets/{id}/state` carries the reason in `state_sidecar_error`. The S3 channel
behaves identically for a bucket sidecar.

An accepted inbox flip emits a `dataset_state_change` audit line carrying the `channel`
and new `state` ([§21](#21-audit-log)), so visibility changes are accountable alongside
ingest outcomes.

> **This sidecar is the source's opinion, not the last word.** An operator suppression
> override (`dataset hide`/`take-down`,
> [§12](#12-dataset-lifecycle-and-state-transitions)) sits above it and wins regardless of
> what it says. That is the node-local mechanism for withholding a dataset the source
> still marks `visible`, and it needs no bucket write access. Flipping the sidecar back
> does nothing while an override is active; lift the override with `dataset unhide`.

> **FDP catalog and root `metadataModified` on hide.** The `fdp-o:metadataModified` of a
> catalog, and of the root, is the latest change across its visible datasets, derived
> without a wall clock so it stays restart-stable. Hiding or removing the latest-modified
> dataset can therefore lower that timestamp. It is harmless: the catalog's membership
> triples (`dcat:dataset`, `ldp:contains`) change at the same moment, so a harvester still
> sees the update, and a per-dataset `dct:modified` only ever moves forward (see
> [§13 timestamps](#effect-on-timestamps)).

> **Hiding or unpublishing the node's last dataset does not retract it from a portal
> harvest.** The GDI User Portal's FDP harvester treats an empty-but-healthy crawl, with
> every dataset now `hidden` or removed, the same as a failed crawl, so it never runs the
> delete branch. The portal keeps listing the stale entry, whose `access_url` now answers
> `exists:false`. This is consumer-side behaviour: nothing the node emits changes it, and
> `gdi-dataset-tool unpublish` succeeds regardless. A node with two or more datasets is
> unaffected, because hiding one of several still yields a non-empty crawl, which the
> harvester retracts normally. To retract a node's only dataset from an affected portal,
> ask the portal operator to clear the source rather than waiting on the next harvest.

---

## 14. Graceful shutdown and signals

| Signal | Effect |
| --- | --- |
| **SIGTERM / SIGINT** | Graceful shutdown: flip `/health/ready` to `503` to drain, stop accepting new connections, drain in-flight HTTP requests, flush logs, exit. The handler is armed after the secret load and the disk cache re-hydrate, before the first listener binds, so a signal arriving from that point on is buffered and honoured once the node starts serving. Earlier than that the signal keeps its default disposition and the process dies at once; see the grace accounting below. |
| **SIGHUP** | Not a shutdown. Re-read external state: re-parse the config file and, on success, reload `[catalogs]` and the `[ingest]` writer-key allow-list, start a monitor for any added `[[s3.buckets]]` entry, restart one whose credentials or connection behaviour changed, then flush the PME DEK cache (§10). Removal, and any change to `endpoint`, `bucket`, `prefix` or `name`, re-points the keyspace and stays restart-only; see below. The flush is a no-op when PME is inactive. |
| **SIGUSR1** | Not a shutdown. Reload and enforce the operator suppression store (§12) and the node-local metadata-overlay override store (§13), process every pending `dataset reingest <id>` marker (§5), run an immediate inbox rescan, and wake every S3 bucket monitor to reconcile now. A corrective fix (a fresh `dataset hide`/`take-down`/`show`/`correct` override, a queued `dataset reingest`, a restored package) therefore takes effect on both channels without waiting out `rescan_interval_seconds` or the S3 poll interval, and without a restart. It is a blanket trigger and takes no dataset id; the per-id path is the queued marker this handler drains, or `POST /datasets/{id}/reingest`. Every step is idempotent and a no-op on a node with no inbox, no buckets, no overrides and no queued reingest markers. |
| **SIGUSR2** | Not a shutdown. Toggle diagnostic logging: raise the node's own crates (`gdi_node_standalone*`) to `debug` on top of the boot `GDI_LOG` or `RUST_LOG` level, and back again on the next `SIGUSR2`. Trace a live issue, such as a wedged ingest, without a restart. The applied filter is echoed on the log line; the audit-target OTLP exclusion is unaffected. |

> **Removing a `[catalogs]` entry is not a retraction, and it is not free.** The reload
> accepts it, but `/fairdp` lists one catalog per configured entry, so any visible dataset
> still naming the removed one drops out of the FDP root's `ldp:contains` and out of
> `fdp-o:metadataModified`. Those datasets keep being served, by the Beacon and at
> `/fairdp/dataset/{id}` for anyone who already holds the URI. What they lose is
> discovery by crawling, which is the one thing a FAIR Data Point exists to provide.
>
> The node says so: a WARN naming each catalog and its dataset count, plus
> `gdi_catalog_orphaned{catalog}` and the **Catalog orphaned** alert, evaluated at boot and
> after every applied reload. Nothing is withheld. Re-add the entry to restore discovery;
> if retraction was the intent, use `dataset take-down`.

**When you cannot send a signal.** Under Kubernetes `kill -HUP 1` means
`kubectl exec … kill -HUP 1`, and many clusters withhold `pods/exec` RBAC. That leaves a
pod restart, which at one replica is a public Beacon outage. Three management-plane
endpoints run the same work as the three signals (see [api.md](api.md)), all opt-in via
`[control].enabled` and rate-limited:

| Endpoint | Signal | What it adds over the signal |
| --- | --- | --- |
| `POST /reload` | `SIGHUP` | tells you whether the config was **applied or refused**, and why |
| `POST /reconcile` | `SIGUSR1` | reachable without `pods/exec`; answers `202` and runs asynchronously |
| `POST /log-level` | `SIGUSR2` | **auto-reverts** after `[control].log_level_revert_seconds`, so `debug` cannot be left on |

Everything below about what each does applies unchanged to both triggers. The CLI one-shots
(`dataset hide`/`take-down`/`correct`, `dataset reingest`) do not signal the node
themselves; they print how to apply the write, because a separate CLI process cannot safely
find the serving node's PID and the shipped image is distroless.

**Config reload without a restart (`SIGHUP`).** Only a narrow subset of `node.toml` reloads
live. Everything else stays fixed for the process lifetime and needs a restart.

- **Reloadable:** `[catalogs]` (add, rename or remove a catalog), the `[ingest]`
  writer-key allow-list (`writer_policy`, `inbox_allowed_writer_fingerprints` and each
  `[[s3.buckets]].allowed_writer_fingerprints`), an added `[[s3.buckets]]` entry (see the
  Vault caveat below), and a change to an existing entry's credentials or connection
  behaviour. So you can clear an `unknown-catalog` ingest error, onboard a provider,
  rotate a bucket's key, or onboard a whole new provider bucket, without restarting.
- **Adding a bucket, or changing how it connects.** A newly-configured `[[s3.buckets]]`
  entry starts a monitor. An entry whose credentials, `region`, `path_style`, `allow_http`,
  poll intervals or `write_status` changed restarts that channel's monitor. That is what
  makes a rotated S3 credential apply: the monitor holds its client from boot, so an
  add-only reload would keep using the old key while the config on disk looked applied. A
  restarted monitor evicts nothing: it addresses the same objects with a new client, and
  its datasets keep serving throughout. The new or restarted channel does not re-run the
  startup reconcile barrier, since the node is already serving and must not be held up. It
  reports unhealthy under `s3_buckets.<name>` until its first poll succeeds.
- **Adding a bucket whose credential comes from Vault works live.** The reload re-reads
  `[vault].s3_path` for the new bucket set before applying it, so a bucket added with its
  credential already under that path onboards on `SIGHUP` or `POST /reload`. If the
  credential is missing, the node refuses to start that channel rather than bringing up one
  that would poll anonymously, fail every request and leave the node permanently
  `degraded`. Against a public bucket such a channel would instead succeed with no
  authentication at all. It says
  what to do: add `<name>_access_key_id` and `<name>_secret_access_key` under
  `[vault].s3_path`, then reload again. A restart does not help; it re-reads the same Vault
  path and finds the same nothing. A bucket whose credentials are inline in the file is
  unaffected and starts live.
- **Changing which objects a bucket addresses is restart-only:** `endpoint`, `bucket`,
  `prefix` and `name`. These decide the channel's keyspace, and applying one live is data
  loss. The replacement monitor lists a keyspace that legitimately contains nothing, which
  the reconcile cannot distinguish from "the provider deleted everything", so it evicts
  every dataset the channel owns and deletes it from `data_dir` while `/health/ready` still
  reports the channel `ok`. A change to any of them therefore logs a WARN naming the channel
  and changes nothing: the monitor keeps polling the old keyspace and its datasets stay
  served until you restart. To adopt a prefix on a bucket that already holds datasets,
  restart the node (see
  [deployment.md](deployment.md#sharing-a-bucket-with-something-that-is-not-a-data-source)).
  A wrong credential fails loudly and evicts nothing; a wrong prefix succeeds and returns
  an empty listing, silent on both sides, because the provider's upload succeeded and so
  did the node's poll. The node does not look outside its own keyspace. What it does log
  is the one desync it can see from inside it, as a once-per-key WARN saying the key
  "sits below the keyspace": a dataset key such as `provider-a/GDI-….tar.c4gh` under a
  node prefix of `provider-a/`, or an unprefixed node seeing a writer's prefixed key. The
  other direction, node prefixed and writer not, is reported on the writer's side:
  `gdi-dataset-tool list` probes the whole bucket when its own listing comes back empty.
  Either way, compare `gdi-node-standalone doctor` here against `gdi-dataset-tool doctor`
  on the writer. Both print `bucket/prefix`, and they must agree.
- **Removing a bucket is restart-only.** A removed entry logs a WARN naming the channel and
  changes nothing: the monitor keeps polling the old descriptor and its datasets keep
  serving until you restart. A vanished bucket is indistinguishable from a total mass
  removal and collides with the cross-poll removal-confirmation guard, and offboarding is
  planned and rare, so a restart is proportionate. Renaming is a removal plus an addition,
  where the new name starts and the old one keeps running, so restart after a rename. A removed
  bucket keeps its `allowed_writer_fingerprints` until the restart, for the same reason its
  monitor keeps polling: the channel is still live, and an empty allow-list under
  `writer_policy = "enforce"` admits nothing, so dropping the list would quarantine every
  package published to that bucket.
- **Restart-only (everything else)**, notably the listeners (`listen`, `management_addr`),
  identities, `[keys]`, `[vault]`, `data_dir`, and `[beacon].min_allele_count`. The
  k-anonymity floor is never live-reloadable: a live lowering would re-expose counts a
  stricter floor already suppressed, and the effective floor is baked into each manifest at
  ingest time rather than applied retroactively.
- **Validate-then-swap, fail-safe.** On `SIGHUP` the node re-parses the config file and
  runs the same startup preflight `check-config` and boot use. On success it swaps in the
  new `[catalogs]` and allow-list, re-checking `[ingest].allow_any_writer_ack` against the
  reloaded `writer_policy` and allow-lists, so a reload that would leave `enforce` pointed
  at a newly emptied, unacknowledged allow-list is rejected rather than applied. On failure
  (unparsable TOML, or a preflight rejection) the node keeps its old `[catalogs]` and
  allow-list, logs a WARN, and counts `gdi_config_reload_failed_total` (§2, §3). It never
  crashes a serving node over a bad reload. If the reloaded file also changed a
  restart-only field, that change is warned about and left un-applied, but the warning does
  not name the field: it reports only that something outside the reloadable subset differs.
  Diff the reloaded `node.toml` against the copy in place at boot to find it.
- **Effective within one ingest job, or one FDP root or catalog request.** The swap itself
  is instant, but a request already in flight when `SIGHUP` arrives may still see the old
  subset.

**Readiness drains first.** On SIGTERM or SIGINT the node sets `/health/ready` to `503`
(`{"ready":false,"draining":true,…}`) before the drain begins, so a readiness-gated load
balancer or Kubernetes Service stops routing new requests to this pod while in-flight ones
finish. Liveness (`/health/live`) stays `200`, so the kubelet does not SIGKILL a
still-draining pod. Endpoint removal is eventually consistent, so add a small `preStop`
sleep to let routing propagate before the listener stops. Without it a rolling deploy can
still send a few requests to a pod that has stopped accepting, producing
connection-refused blips:

```yaml
lifecycle:
  preStop:
    sleep: { seconds: 5 }               # ≥ one readiness probe period, so the endpoint
                                        # withdrawal has propagated before the listener stops
readinessProbe:
  httpGet: { path: /health/ready, port: 9090 }
  periodSeconds: 2
```

**Use the native `sleep` action, not `exec: { command: ["sleep", "5"] }`.** The exec form
runs inside the container, and the shipped image is distroless, with no shell and no
`sleep` binary, so it fails with `executable file not found` and the kubelet proceeds
straight to SIGTERM: a hook that looks present in the manifest and does nothing. The native
`PodLifecycleSleepAction` is performed by the kubelet and needs nothing in the image.
`deploy/kubernetes/base/deployment.yaml` ships it at 5 s. An API server too old to know the
field prunes it on `apply` silently rather than failing, so confirm with
`kubectl explain pod.spec.containers.lifecycle.preStop` before relying on it.

**Drain budget: `shutdown_drain_seconds` is spent twice.** Shutdown runs three bounded
phases back to back:

| # | Phase | Bound |
| --- | --- | --- |
| 1 | Public listener drains in-flight connections | `[service].shutdown_drain_seconds` |
| 2 | Management listener is stopped | **2 s, hard-coded** |
| 3 | In-flight **ingest** is awaited before the data-dir lock is released | `shutdown_drain_seconds` **again** |

so the ceiling is `2 × shutdown_drain_seconds + 2 s`, plus process exit. The startup
preflight rejects `request_timeout_seconds > shutdown_drain_seconds`, which bounds phase 1;
it says nothing about phase 3.

Size the grace period as `terminationGracePeriodSeconds ≥ preStop 5 s + public drain
(≤ shutdown_drain_seconds) + management stop 2 s + ingest quiesce
(≤ shutdown_drain_seconds)`, which is 67 s at the shipped drain of 30;
`deploy/kubernetes/base/deployment.yaml` ships 75. A grace of 35 SIGKILLs a node
mid-backfill. A node that sets a larger drain must raise the grace with it; dataset or
population count does not enter. When the ingest quiesce does not finish in its budget the
log carries `ingest still in flight after the drain budget`.

> **Teardown after `service.drained` is bounded and logged.** Both drains end at
> `service.drained`. The process then awaits in-flight ingest (phase 3, bounded by
> `shutdown_drain_seconds`), logs `service.stopped` with `teardown_ms`, flushes telemetry,
> releases the data-dir lock and exits, without waiting for detached background work.
> `teardown_ms` covers the quiesce up to the log call, not the telemetry flush that follows
> it: the log is written first so a hung OTLP flush cannot swallow it. A node that fails
> mid-serve logs the cause and exits 1, with no `service.stopped` and no `teardown_ms`.
>
> **That accounting starts when the node starts serving.** The SIGTERM and SIGINT handlers
> are armed after the secret load and the disk cache hydrate, before the first listener
> binds, so a signal delivered from that point on is buffered: the node finishes booting,
> then runs the phases above on an empty drain, because nothing has been served yet. A
> signal arriving earlier takes SIGTERM's default disposition and kills the process at
> once. The offline `verify` path returns before the arming line and must stay
> Ctrl-C-interruptible.
>
> Shutdown latency during boot is therefore the remaining startup plus the accounting
> above: both listener binds, the store self-test, the ingest runtime and S3 monitor start,
> and the initial reconcile gate. All of it sits inside the 5-minute budget the manifest's
> `startupProbe` sets at `periodSeconds: 5` × `failureThreshold: 60` in
> `deploy/kubernetes/base/deployment.yaml`. A pod terminated mid-boot exits once that work
> finishes and the empty drain runs, or at SIGKILL when the grace period ends. Neither
> risks data: nothing is served during startup and the store is crash-safe, so an abandoned
> boot re-does itself on the next one. Leave `terminationGracePeriodSeconds` at 75; sizing
> it for a worst-case boot would delay every normal termination to buy nothing.

**In-flight ingest is awaited, then abandoned.** Shutdown stops ingest workers from pulling
new jobs; the heavy steps run under `spawn_blocking` so they do not block connection
draining. Phase 3 gives whatever is still running a bounded window to finish. Anything
still in flight when that window closes is abandoned safely: the atomic-rename store means
a half-written dataset never goes visible, `processing` is never persisted, and the source
artifact is left where it was, so the job re-queues on the next startup. A cancelled ingest
counts as `gdi_ingest_total{outcome="cancelled"}`, not `transient`, so a rolling restart
cannot trip the `IngestRetryChurn` alert.

**Startup reaps orphaned working dirs.** Before reconciling, the service garbage-collects
any leftover `datasets/.incoming/*` working dirs. They are incomplete by construction,
never published and never read, so a SIGTERM or crash mid-ingest cannot accumulate scratch
on an RWO PVC.

---

## 15. Logs and log configuration

The node logs to stderr as single-line JSON (NDJSON) by default. That is the form a log
pipeline ingests, and what the `jq` recipes elsewhere in this doc assume. Logging is not a
config-file knob; two environment variables tune it.

- **Level: `GDI_LOG` overrides `RUST_LOG`; default `info`.** A set, valid `GDI_LOG` wins,
  so a deployment can set the node's level without disturbing a `RUST_LOG` that co-located
  tooling reads. It takes the standard `tracing` `EnvFilter` syntax, for example
  `GDI_LOG=info,gdi_node_standalone=debug`. Because it wins, a stray or leftover `GDI_LOG`
  silently no-ops any `RUST_LOG` you set: if a `RUST_LOG` change is not taking effect,
  check the environment for an unintended `GDI_LOG`. Whatever the spec, the `object_store`
  crate's retry loop, two INFO lines per S3 call, is capped at `warn` unless the spec
  names `object_store` itself, so `GDI_LOG=info,object_store=debug` is honoured. The cap is
  applied like the audit floor, so a `SIGUSR2` toggle keeps it.
- **A refused start is one line, and it is an alarm.** When the serving process cannot
  start (an unreadable config, an override store that is not intact, an identity that will
  not load, a bind failure) it exits 1 after writing one structured line in the configured
  format. Under `json` or `ecs` that line carries `level: ERROR` / `log.level: error`,
  `message` (the reason), `error` / `error.message` (the full cause chain),
  `event.action: "startup"`, `event.outcome: "failure"` and `tags: ["Alert"]`. No metric
  rule can see this class, because the process is gone before `/metrics` exists, so route
  it from the log store: `tags: Alert` is the selector and the line carries why. Under
  `LOG_FORMAT=text` it is one human line, `ERROR startup: <cause chain>`, with none of
  those fields including `tags`. An alarm-routed deployment must therefore run `json` or
  `ecs`; a node left on `text` emits a refused start that no `tags: Alert` rule can match.
  One-shot subcommands such as `check-config` and `doctor` keep a plain `Error:` report,
  because they talk to a terminal.
- **Runtime toggle: `SIGUSR2`.** Send `SIGUSR2` (`kill -USR2 <pid>`, or
  `kubectl exec … -- kill -USR2 1`) to raise the node's own crates
  (`gdi_node_standalone*`) to `debug` on top of the boot level, and again to toggle back.
  No restart, which would drop in-flight ingests and force a full re-reconcile. It is a
  signal rather than an env var because a running process cannot have its environment
  changed from outside. The applied filter is echoed on the
  `SIGUSR2: toggled diagnostic logging` line. The audit-target trace exclusion is
  independent of the level and is never affected.
- **Format: `LOG_FORMAT=json|text|ecs`; default `json`.** `text` is the human-readable
  single-line form for local runs; leave it `json`, or unset, in production for structured
  ingestion. `ecs` emits Elastic Common Schema field names (`@timestamp`, `log.level`,
  `message`, `service.name`, `service.environment`, event and span fields under `labels.*`,
  and with `otel` also `trace.id` and `span.id`) so logs land in Elasticsearch and Kibana
  with no ingest pipeline. Panic lines follow the same schema.

  `service.environment` is `[beacon].environment` (`dev`, `test`, `staging` or `prod`) and
  is emitted only in `ecs` mode. It also travels on the OTLP trace resource as
  `deployment.environment`. That resource carries `service.instance.id` too: the hostname,
  which is the pod name on Kubernetes unless `OTEL_RESOURCE_ATTRIBUTES` names one. So two
  replicas' pushed series stay distinguishable. A dead collector is announced by one
  `otlp.export` WARN per outage plus a recovery INFO, never per batch. The default `json`
  and `text` forms omit service-identity fields; supply the environment via a collector
  label there if you need it. The dev observability overlay
  (`docker-compose.observability.yml`) sets `LOG_FORMAT=ecs` for the node, and its Alloy
  takes the `service` stream label from each line's own `service.name`, so a dev query and
  a cluster query select the same thing.

  **`ecs` renames fields the rest of this runbook selects on.** Every recipe below is
  written for the default `json` shape. Under `LOG_FORMAT=ecs` translate as follows, or
  the selector silently matches nothing:

  | `json` (default) | `ecs` | note |
  |---|---|---|
  | `timestamp` | `@timestamp` | |
  | `level` | `log.level` | **case differs**: `json` emits `ERROR`, `ecs` emits `warn`/`error` lowercase |
  | `target` | `log.logger` | this is the one §21 routes the audit stream on |
  | `span.<field>` | `labels.<field>` | e.g. `span.dataset` → `labels.dataset` (`json` emits only the innermost span, never an ancestor list) |
  | `span.request_id` / `span.method` / `span.path` | `http.request.id` / `http.request.method` / `url.path` | the request span's fields, lifted to ECS's HTTP fields on every line inside it |
  | `status` / `latency_us` *(access log)* | `http.response.status_code` / `event.duration` | the latter in nanoseconds |
  | *(event fields)* | `labels.<field>` | e.g. `event` → `labels.event` |
  | `event.action` | same name, top level | on every line that records an event (ECS core field) |
  | `alert: true` | `tags: ["Alert"]` | lifted, top level; see "Alarm lines" below |
  | `event.action` / `event.outcome` | same names, top level | lifted with it (ECS core fields) |

  `ecs` additionally emits `ecs.version`, `service.name`, `service.version`,
  `service.environment`, and with `otel` lifts `trace.id`/`span.id` out of `labels.*`.
  The exact envelope is pinned by `logging.rs::ecs_schema_is_pinned`.

  **`labels.*` are keyword by convention, but some carry numbers or booleans**
  (`labels.count`, `labels.num_results`, `labels.exists`, `labels.found`, `labels.status`
  and others). Elasticsearch's dynamic mapping types a field from the first document it
  sees and then rejects a later document whose value does not fit, dropping that line
  silently. Map `labels` explicitly in the index template rather than relying on dynamic
  mapping; a `flattened` field is simplest and never conflicts. This is an ingest-side
  mapping concern, not a log-shape change: the emitted bytes are unchanged.

  **Alarm lines: `tags: ["Alert"]`.** The `Alert` tag is reserved for events that must
  reach a person, and an Elastic-only deployment can route on nothing else: one Kibana rule
  over `tags:Alert`, grouped by `service.name`, with `event.action` in the ticket subject.
  A call site that needs a human says `alert = true`, and the ECS layer turns that into
  `tags: ["Alert"]` at the top level beside the `event.action` and `event.outcome` the site
  names. `json` and `text` keep the three as plain fields: `"alert":true`,
  `"event.action":"…"`. The refused-start line (`event.action = "startup"`, emitted by the
  fatal path rather than a tracing site) is tagged the same way, in `json` and `ecs`.
  `LOG_FORMAT=text` renders it as one human line with no `tags` field, so it is unroutable
  by this rule; see the refused-start bullet above. The tagged conditions, and what the
  person holding the ticket should do:

  | `event.action` | condition | what to do |
  |---|---|---|
  | `startup` | the node refused to start; `error` carries the reason chain | fix the config / store / credential it names |
  | `vault.token.reauth` | a Vault token renewal failed **and** the re-authentication that follows it failed too, so the credential is unusable and the node runs on borrowed time until its current token lapses | check Vault reachability and the AppRole / agent |
  | `vault.token.probe` | the token-liveness probe failed; Vault is marked not-ready and `/health/ready` degrades. Tagged once per excursion (the probe runs every minute and repeats are DEBUG); an untagged INFO line with `event.outcome = "success"` marks the recovery | same |
  | `vault.secret.load` | the crypt4gh identity secret could not be loaded, or holds no keys, so the node is keyless and decrypts nothing | restore the secret at `[vault].kv_path`, then restart (identities load once at startup; SIGHUP does not reload them) |
  | `task.panic` | a background task panicked and was restarted after backoff (`gdi_background_task_panics_total`) | a defect: keep the panic line, report it |
  | `ingest.panic` | an ingest task panicked; the dataset is recorded in permanent error | same, then re-ingest the dataset after the fix |
  | `http.panic` | a request handler panicked (the client got a 500) | a defect |
  | `store.scrub.quarantine` | the store scrub quarantined a dataset that failed its integrity check | verify the payload; re-ingest |
  | `ingest.reject.cleanup` | a writer-rejected payload could not be removed; the intent marker is kept so the next scrub retries | free the path (permissions, a full volume) |
  | `suppression.store.read` | the suppression store directory is unreadable; the last-good set is kept | fix the volume / permissions |
  | `disk.sample` | `statvfs` failed, so `gdi_disk_free_bytes` is stale | check that the data volume is still mounted |
  | `dataset.sidecar.release` | a `{id}.state.json` sidecar flipped a dataset to visible. Sidecars carry no writer identity, so anything that can write the channel can publish anything in it, including a dataset another party withheld ([deployment.md](deployment.md)) | confirm the publication was intended. One line per publication is expected: the node cannot tell a legitimate publish from a hostile one, so correlate it against your own record of intended publishes rather than reading it as a fault |

  Every row carries `event.outcome = "failure"` except `dataset.sidecar.release`, whose
  outcome is `"success"`: a successful action that needs a person to confirm it, not a
  fault. Conditions a metric rule detects better (low disk, a wedged pool, readiness,
  token TTL) are not tagged. They are §3's rules, translated on the Kibana side.

Every public-plane request emits one INFO access-log line (`message: "request completed"`,
`event.action: "http.request"`) carrying the response `status` and `latency_us` in
microseconds, inside the request's `http_request` span, so it also carries `method`, `path`
and `request_id`. Under `ecs` those five travel as ECS's own HTTP fields:
`http.request.method`, `url.path` and `http.request.id` on every line inside the span, and
`http.response.status_code` plus `event.duration` in nanoseconds on the access-log line.
The management plane (health, readiness, `/metrics`, dataset-state) is not
access-logged, which keeps probe and scrape traffic out of the logs. It is still metered:
see `gdi_http_requests_total{plane="management"}` in §2.

**`event.action` is the machine key for "what happened".** Every line that records an
event carries it in dotted ECS form: `service.start`, `service.listen`, `dataset.ingest`,
`dataset.state.change`, `s3.bucket.configure`, `config.reload.signal`, `config.posture` and
so on. `message` is prose for a person and may be reworded. Audit lines carry
`event.action` beside their `event` name (`event = "beacon_query"`,
`event.action = "beacon.query"`): `event` is the compliance vocabulary the §21 catalogue
enumerates, `event.action` is what a Kibana or Loki rule selects on, and the two never
disagree. The first line a serving node writes is `service starting` (`service.start`) with
`version`, `git_sha` and the compiled `features`, before any I/O; `service configured`
follows once the config is resolved. One-shot subcommands such as `dataset list`, `doctor`
and `overrides …` emit neither, because they are not starting a service.

Route the `audit` target into its own retention- or WORM-managed stream (§21), and
correlate a failed request by its server-side `request_id` with `jq` over the NDJSON (the
§4 recipe).

**The log collector must not apply back-pressure to the writer.** The node writes each log
and audit line synchronously to stderr, so an `audit` record is on the wire before the
emitting request returns and no buffered line is lost on SIGKILL. The cost is that if
whatever drains the process's stderr (the container runtime's log driver, journald, a
Fluent Bit or Alloy sidecar) stalls and lets the OS pipe buffer fill, the next write
blocks the emitting worker thread until the reader catches up. Every standard driver either
drops (`docker` and `containerd` `json-file`/`local` with a `max-size`, journald
`RateLimit`) or buffers generously and never stalls the writer, so this does not normally
occur, but do not pipe the node's stderr into a slow or unbuffered synchronous consumer.

If a deployment cannot guarantee a non-blocking collector and prefers liveness over log
durability, split the streams. Keep the `audit` target synchronous, ideally to a local
file, which never suffers pipe back-pressure. Route the remaining operational logs
through a lossy non-blocking writer that drops rather than blocks. The `audit` target is
not low-volume, because the public-plane access log rides it too, one
`event = "http_request"` line per completed public request, so the split reduces the
synchronous write volume little; its benefit is the local-file sink, which cannot be
back-pressured at all. Size the `"target":"audit"` retention stream (§21) for full public
request volume.

---

## 16. Distributed tracing (optional)

The node can export its `tracing` spans as **OpenTelemetry (OTLP) traces**, the
per-request span waterfall (HTTP handler → ingest → query), and, opt-in, push its
`/metrics` series as **OTLP metrics** to the same endpoint. Both are **off by default**;
for local viewing use the observability Compose overlay (see
[`compose/observability/`](../compose/observability/README.md)).

**Enabling it needs two things:**

1. **Build with the `otel` feature** (`cargo build --features full,otel`). `otel` is
   not in `full` by default, so a plain `full` binary exports nothing; a non-`otel`
   build parses-but-ignores the settings below and warns once.
2. **Set `[service].otlp_endpoint`** (or `GDI_NODE__SERVICE__OTLP_ENDPOINT`) to a
   collector, e.g. `http://alloy:4318`, or **directly to an OTLP intake** such as
   Elastic APM, e.g. `https://apm.example.org`. Unset ⇒ no export.

**Transport.** OTLP over HTTP with protobuf. An `https://` endpoint works in any build
carrying the `tls` group (`full,otel`) and is verified against the OS CA bundle of the host
or image; the `distroless/cc` base the shipped `Dockerfile` builds on carries one.
`SSL_CERT_FILE` is not consulted, so a private CA
goes into `/etc/ssl/certs/ca-certificates.crt`. An untrusted certificate fails closed: the
export is dropped and logged, and the node keeps serving. A `lite,otel` build has no TLS
and speaks `http://` only.

Related `[service]` keys:

- **`otlp_headers`** (name→value; prefer the `GDI_NODE__SERVICE__OTLP_HEADERS__<NAME>`
  env overlay so a token stays out of the config file): attaches an auth header to
  every export, e.g. `Authorization = "ApiKey <key>"` for an Elastic APM intake. Send
  it over `https://`; over plaintext `http://` to a non-loopback endpoint in prod,
  preflight warns that the secret travels in cleartext.
- **`otlp_metrics_interval_seconds`** (default unset, meaning off; `0` is rejected): push
  every series `/metrics` serves as OTLP metrics to `…/v1/metrics` once per interval, for a
  store with no Prometheus scraper of its own. `/metrics` keeps serving and stays the
  source of truth: the push is a second recorder fanned out beside the Prometheus one, so a
  series added anywhere in the node crosses over by construction. Names travel verbatim
  (`gdi_ingest_total`, not `gdi_ingest`), labels become attributes one-to-one with nothing
  added, so the §2 privacy posture holds, histograms use the same bucket table, and a
  counter's `absolute()` becomes a delta on the monotonic OTLP sum. Temporality is
  cumulative, and the final collection is pushed at shutdown. `check-config` prints the
  effective state as `otlp_metrics`.
- **`otlp_trace_sample_ratio`** (default unset, meaning `1.0`, every request): the
  fraction of new traces exported, `0.0` to `1.0`, and parent-based. A request arriving
  with a trusted `traceparent` follows its parent's decision, so a sampled upstream trace
  is never cut off at this node. Only the exported spans are sampled; every log line
  still carries its trace id, so a Loki-to-Tempo pivot from an unsampled request finds no
  trace. At the
  public request rates §15 sizes the audit stream for, `1.0` is one span per request to the
  intake, and this is the knob that turns it down. A value outside the range is rejected at
  preflight.
- **`trust_inbound_traceparent`** (default `false`): when `true`, adopt a valid W3C
  `traceparent` HTTP header as the span's parent, so a query crossing a trusted hop shows as
  one trace. It covers both listeners, including the internet-facing public one, so enable
  it only behind a trusted ingress that sets and sanitizes the header.
- **`trust_sidecar_traceparent`** (default `false`): the same for a `traceparent` carried
  in an S3 handoff sidecar (`{id}.state.json`), parenting that package's `ingest_job` span
  under the orchestrator's trace. It is independent of the flag above, because writing the
  sidecar requires bucket write credentials whereas sending a header only requires reaching
  the port. An orchestrator that wants its publishes correlated end to end can turn this one
  on and leave the other off, which is the recommended posture.

**What is exported.** Work spans only, named and shaped by the OpenTelemetry conventions
so a trace backend's own views apply:

- **Request spans**: one per completed request on either plane, exported under the name
  `METHOD route-template` (`POST /beacon/v2/g_variants`, `GET /fairdp/dataset/{id}`; the
  template, never an id), kind `server`, with `http.route`, the final
  `http.response.status_code`, and the OTel error status on a 5xx (so TraceQL's
  `{ status = error }` and Grafana's "Errors" filter find them). In the logs the same span
  is still `http_request` (public) / `mgmt_request` (management, and only when the caller
  supplied an `x-request-id` or a trusted `traceparent`).
  - Beacon queries carry a `beacon_scan{mode, datasets}` child around the fan-out, with one
    `scan_dataset{dataset}` child per dataset scanned, which is the part of a request
    that costs anything. FDP reads carry an `fdp_render{resource}` child.
- **`ingest_job{dataset, channel}`** with its `decrypt`/`extract`/`check_layout`/
  `validate_manifest`/`validate_parquet`/`store` children, an `ingest_finish` child for the
  write-back / cache / sidecar tail, and an `outcome` (`success`/`error`/`panic`) recorded on
  the job span with the OTel error status on the latter two.
- **Dependency spans** under whichever of the above is running: `vault_call{operation}`
  (every KV/Transit call), `s3_poll{channel}` (each listing pass, with the
  `s3_download{channel, dataset}` and `overlay_apply{channel, dataset}` work of that pass
  under it).

Every attribute on these spans is an operator-known field, and the tracing bridge's
`code.*`, `thread.*`, `busy_ns` and `idle_ns` boilerplate is switched off. The supervision
spans the background loops run under (`daemon{task, instance}`, and the per-iteration
`daemon{task}` around every guarded tick) are not exported. They exist to stamp `task` and
`instance` on log lines; exported, they produce either a one-span root trace per tick, or a
parent that never closes and collects a child per tick for the life of the process. A work
span created inside one, such as an `ingest_job` with no sidecar `traceparent`, is
therefore its own root. Under `LOG_FORMAT=ecs` the lines an `ingest_job` emits carry that
job's `trace.id` and `span.id`, as the lines inside a request span do on both planes.

**Spans and pushed metrics carry dataset ids, hidden and errored ones included.** The span
name is the route template, but the `path` attribute is the concrete path
(`/datasets/GDI-EE-…/state`), `ingest_job` and `ingest_finish` carry `dataset = <id>`, and
`gdi_dataset_state` is labelled by id. Those ids are surrogates, not personal data, and
they already travel to the same backend in the audit log and in metric labels. But a
deployment exporting to a third-party intake is telling that vendor which unpublished
dataset ids exist. That is a governance choice, and the place to make it is the collector:
an `attributes` processor that deletes or hashes `dataset` and `path`, in the pipeline in
front of the exporter. The node does not hash them, because that would break the
log-to-trace correlation this section exists for.

**Privacy: content-free by construction.** Trace export applies the same discipline as
`/metrics` (§2). The `audit` tracing target is the only site that could carry queried
coordinates when `[audit].query_detail` is on (§21), and it is excluded from exported
spans in the export layer, so a trace backend can never become a who-queried-what store.
Spans carry only administrative metadata; the `trace.id` and `span.id` in
`LOG_FORMAT=ecs` logs (§15) link a trace to its log lines.

---

## 17. Disaster recovery

Almost everything is reconstructible. A few small things are not.

### Reconstructible: the data volume

The published datasets, the status index and all scratch live on the one data volume, and
S3 is the source of truth. A lost data volume re-populates by re-ingesting from the
buckets: provision a fresh PVC, start the node, and the startup reconcile re-downloads and
re-ingests every package. For an inbox-only node the operator re-drops the packages,
because the inbox is a drop zone rather than a durable store. Keep your package archive.

No backup of the published `datasets/{id}/` directories or `.status.json` is required.

**Not everything on that volume is reconstructible.** Re-ingest restores each dataset to
its source-resolved state, which is the state an operator override exists to countermand.
The override store (`override_dir`, default `<data_dir>/overrides/`) therefore does not
survive this procedure even though it sits on the same volume; see the next section.
`<inbox>/.rejected/` is likewise unbacked, because a quarantined package has no upstream
copy at all.

The two stores fail in opposite directions, which is why only one of them needs you. A lost
`.status.json` is safe: an id absent from the index hydrates as `hidden`, never `visible`.
A lost override store is not: an absent store is indistinguishable from "no overrides were
ever recorded", so on a restart it reads as the empty set and every withhold is lifted.

On a running node that is caught, regardless of `require_override_store`. A reload that
finds the store absent while the process still holds overrides keeps its last known-good
set, logs an error and raises `gdi_override_store_absent` rather than adopting the empty
set. That covers a detached PVC, an unmounted export or a mount-path typo, but it cannot
cover a store destroyed while the node was down: after a restart there is no in-memory set
to compare against, and the store is the only record of itself. That case is what
`[service].require_override_store` and the backup below exist for.

> **`require_override_store` catches an absent store; the used-marker catches an empty
> one.** The flag refuses to serve only when the store root is missing: unmounted, or at
> a wrong path. A freshly re-provisioned volume is an empty directory, which passes that
> structural check. The node closes the gap with one durable bit,
> `data_dir/.override-store-used.json`, recording that this node's store has held at least
> one override. It lives on the data volume so it survives the loss the store cannot
> witness, the override volume being replaced wholesale, which is why putting
> `override_dir` on separate storage is what makes the marker work.
>
> An empty store is therefore no longer ambiguous. Empty with the marker means the
> overrides are gone: with `require_override_store` set the node refuses to boot, and
> without it logs a WARN naming the recovery. Empty without the marker is a fresh node and
> boots normally. A running node applies the same test on every reload: a store found empty
> under the marker, while the node is withholding or has `require_override_store` set,
> keeps its last known-good set, logs an error and raises `gdi_override_store_absent`,
> exactly as an absent store does. A `dataset unhide` of the last override clears the
> marker first, so a store the CLI emptied is adopted normally.
>
> Recover with `overrides import`. Only when the store was emptied intentionally, attest
> that with `overrides init --yes`. Do not automate `overrides init --yes`: attesting is the
> assertion the marker exists to demand.
>
> Not losing the volume beats detecting that you lost it, so start with the storage layer:
>
> 1. **Keep the volume from being destroyed.** Give the override PVC a
>    `reclaimPolicy: Retain` StorageClass, or a statically provisioned PV with
>    `persistentVolumeReclaimPolicy: Retain`, so deleting the PVC, pod or namespace keeps
>    the volume and recovery re-binds the same bytes rather than a fresh empty one. See
>    `deploy/kubernetes/base/storageclass.example.yaml`. The default StorageClass is
>    typically `Delete`, which is the case this warning is about.
> 2. **Restore before you serve.** After any override-volume loss, `overrides import` the
>    last backup before the node accepts traffic. `require_override_store` is a seatbelt
>    for the unmounted case, not a guarantee against the empty-remount case.

### Backing up and restoring the override store

Because it is the one part of the data volume re-ingest cannot rebuild, back it up
independently of the volume:

```bash
gdi-node-standalone --config <path> overrides export -o overrides-$(date +%F).json
```

The bundle is plain JSON, one object per loader directory (`suppressions/`, `overlays/`),
each entry stored parsed, so you can read, diff and review it before trusting it. It is not
a tar, because a recovery artifact you cannot inspect is one you cannot verify. `reingest/`
markers are excluded: they are transient and carry no intent worth preserving.

Lift records are in the bundle (v2). `<override_dir>/lifted/` is the durable home of every
`unhide` justification (§21) and its only off-volume copy, so `export` captures it under a
separate `history` key and `import` rewrites it. Restoring it does not reinstate anything
as active: the node never reads `lifted/`, so a restored history changes nothing served. A
`v1` bundle from an older build carries no history.

Export fails rather than emitting an empty bundle when the store cannot be read, and names
any file that is not valid JSON. A backup that silently captured nothing is worse than no
backup, because it looks like one.

To restore into a rebuilt node:

```bash
gdi-node-standalone --config <path> overrides import overrides-<DATE>.json
```

Import refuses if the target store already holds overrides: the recovery case is a node
believed to have lost its state, and merging into a populated store leaves the in-force set
ambiguous. Use `--force` to proceed; it overwrites same-named entries and keeps any extras.
It never deletes, so no withhold in force today can disappear from the store, but "never
deletes" is not "never weakens". A same-named entry is overwritten, so a stale bundle whose
entry for a dataset is a `hide` replaces a `take-down` (`remove`) authored since that
backup: the dataset stays withheld, but the eviction, a consent-withdrawal erasure, is
undone. Diff the bundle against `overrides export` before a `--force` restore, and re-issue
any `dataset take-down` that post-dates the backup.

> **A non-zero exit does not mean nothing was restored.** `import` pre-flights every entry
> body before writing anything, then installs the whole bundle. If any body would be
> refused at apply time it installs it anyway, names it on stdout as `! {entry}: {reason}`,
> and then exits non-zero. Read the count and the audit line, emitted first: they are the
> truth about what landed. Leaving a bad entry out is the disclosure direction: an absent
> suppression serves the dataset, and an absent overlay republishes the metadata it was
> redacting. Installed, a malformed suppression is read fail-closed as `hide` and a
> malformed overlay keeps its precedence claim, so last-good stays served. Do not re-run
> with `--force` on the strength of the exit code; the restore already succeeded. Fix the
> named entries, re-drop those, then reload.

A running node picks the restored set up on its next reload (`SIGUSR1`, or the override
reconcile timer); a stopped node loads it at boot. Set
`[service].require_override_store = true` afterwards so a future loss is loud rather
than silent; see the `gdi_override_store_absent` gauge.

### Verifying the store after a restore / disk incident

The offline **`verify`** subcommand scrubs every published dataset against the
loaded key material and exits non-zero if any fail, so it slots into a restore
runbook. It binds no listener and starts no ingest:

> **Not a cron job on a live node.** `verify` takes the exclusive data-dir lock, so it
> requires stopping the node or pointing it at a copy of the data dir. At §7's sizing
> neither is a routine scheduled task. For unattended checking, the node's own detached
> sweep covers readability continuously and digests a rotating slice (§2,
> `gdi_store_scrub_failed`). `verify --digest` is that same hash-only check, on demand and
> over every dataset at once. `verify --full --digest` is the deep one: it is the only
> thing that re-validates the stored rows, nothing on a live node runs it, and it stays an
> operator-run action.

```bash
gdi-node-standalone verify                       # footer readability of every dataset
gdi-node-standalone verify --full                # + full parquet schema/value validation
gdi-node-standalone verify --digest              # at-rest content-digest check (hash-only)
gdi-node-standalone verify --full --digest       # both: row validation and the digest sidecar
gdi-node-standalone verify --digest --concurrency 8
```

The depth tiers are independent rather than a ladder. `--full` adds full parquet
validation for plaintext stores; PME stores stay footer-only, because offline full-decode
of `PARE` is not supported. `--digest` verifies the per-parquet `parquet-digests.json`
sidecar written at ingest, for plaintext stores. `--digest` is hash-only and does not imply
`--full`, so pass both flags for the deepest offline check, which is what a restore runbook
wants. PME files carry AEAD tamper detection, so a PME store is skipped at these tiers and
reported as a pass (`PME: footer-only`).

There is no "unverified" status. Every plaintext store gets a sidecar at ingest, so a
missing one is anomalous (a deleted sidecar, tampering or corruption) and fails closed
with `FAIL … digest: no parquet-digests.json sidecar on a plaintext store …` and a non-zero
exit. Do not dismiss that failure as the PME case. `--concurrency` bounds per-dataset
parallelism, and with it the concurrent Vault DEK unwraps, which are single-flighted per
key rather than serialised process-wide. Against a Vault shared with a live node, prefer a
small concurrency and avoid running during heavy ingest.

### Irreplaceable: back these up out-of-band

The only state that **cannot** be reconstructed:

1. **The node crypt4gh identity / identities.** A node whose identity is lost
   **cannot decrypt** its existing `.tar.c4gh` packages (and a re-keyed store
   wrapped to a lost recipient is unrecoverable).
2. **The Vault Transit master key** (when PME is enabled). Lost ⇒ no PME-encrypted
   parquet at rest can ever be decrypted.
3. **The operator-override store**: `override_dir` (default `<data_dir>/overrides/`),
   holding `suppressions/` (dataset and channel takedowns) and `overlays/` (metadata
   corrections). Lose it and every withheld dataset is served again and every correction
   reverts to its source value. The free-text `reason` recorded with each suppression,
   the operator's justification for withholding, exists nowhere else on disk, because the
   audit trail is emitted to stderr rather than to a file. `reingest/` markers under the
   same root are transient and need no backup.

   > **Keep personal data out of `--reason`.** A withholding justification is where a name
   > or a personal identity code gets typed. The text is not written to the audit log
   > stream: `dataset_suppressed` and `channel_suppressed` carry only `dataset` or
   > `channel`, `mode` and `actor`. That free text therefore never reaches the cluster
   > log aggregator, its indices or its backups, none of which are governed by this
   > store's retention policy. `dataset correct --reason` is the exception: a correction reason
   > states the metadata change rather than anything about a subject, and it has nowhere
   > else to live.
   >
   > The suppression file is the record, and it is backed up out-of-band, so the text
   > travels with those backups. Write a case or ticket reference and keep the identity in
   > the system that already holds it.

Items 1 and 2 are the more severe: lose them and the data is permanently undecryptable.
Item 3 is the more likely, because it is the only one the default layout places on the
disposable data volume, and the only one whose loss presents as a clean, successful
recovery.

#### Backing up the operator-override store

There is no bespoke tool. Unlike the node identity, which lives in Vault KV and is raw key
material needing crypt4gh encryption before it can touch disk, the override store is a
directory of small, non-secret JSON files. Standard filesystem tooling covers it, and a
periodic export would go stale after every operator action.

Prefer relocation over export: point `[service].override_dir` at storage backed up
independently of the data volume, so the store is not destroyed by the recovery procedure
above. If you run more than one serving replica, that volume must be mounted into every one
of them. Suppressions are evaluated per process from its own `override_dir`, so a replica
that cannot read the store serves every withheld dataset (see
[deployment.md](deployment.md#resource-baseline)).

> **Copy before you re-point.** Changing `override_dir` moves nothing: editing this value
> on a node with existing overrides abandons every one of them at the old location. Copy
> the directory to the new location first, then change the config, then restart.
>
> A running node refuses to adopt an absent new location while it still holds overrides; it
> keeps its last-good set and raises `gdi_override_store_absent`. That is a backstop, not a
> licence. A new location that exists and is empty is indistinguishable from a store with
> nothing in it and is adopted as such, and the restart this procedure ends with clears the
> in-memory set the guard compares against.

Then set `[service].require_override_store = true`. The config is mounted from a ConfigMap
or Secret rather than the data volume, so it is the only thing that survives the incident
and can still testify the store was supposed to be there. With it set:

* the node refuses to start if the store root is absent, rather than serving with every
  withhold silently lifted;
* a store deleted under a running node no longer empties the in-memory set at the next
  reconcile: the last known-good set is kept and the failure is logged at `error`.

Operator subcommands (`dataset unhide`/`hide`/`take-down`, `channel …`) still run while the
node refuses to serve, so a store can be rebuilt in place.

#### Backing up the node crypt4gh identity (Vault)

There is a built-in backup/restore pair. The backup is itself crypt4gh-encrypted to an
operator's recipient, so the blob is useless without the operator's secret. Store the two
separately.

```bash
# 0. The operator needs a crypt4gh keypair (generate once with any crypt4gh tool).
#    Keep operator.sec offline; hand identity backup only operator.pub.
# 1. Export. Run with a Vault credential that can read the identity KV path.
#    Pass --recipient more than once to encrypt the same blob to several operator
#    keys; any one of those secrets can then restore it (see the redundancy note below):
gdi-node-standalone identity backup \
    --recipient operatorA.pub --recipient operatorB.pub \
    --out node-identity.c4gh
# 2. Verify the backup is restorable, on the offline machine that holds operator.sec.
#    Decrypt and parse only; touches neither Vault nor the live identity:
gdi-node-standalone identity restore --in node-identity.c4gh --identity operatorA.sec --dry-run
# 3. Restore onto a fresh node. Create-only (cas=0), refuses to clobber a live
#    identity; needs a write-capable Vault credential:
gdi-node-standalone identity restore --in node-identity.c4gh --identity operatorA.sec
```

`identity backup` captures the whole KV map, every `c4gh-*` field including rotated keys.
In the no-Vault mode the identity is a mounted key file: back that file up directly, with
no tooling.

**Refresh the backup after every `identity rotate`.** A backup is a point-in-time
snapshot, and a rotation adds a published key an older backup does not contain, so an
unrefreshed backup can no longer recover data ingested after the rotation. `identity
rotate` prints a stderr warning to this effect. Re-run `--dry-run` to confirm the refreshed
blob. When you wind the re-key window down, prune superseded keys rather than hand-editing
Vault: preview with `--dry-run`, then apply
`gdi-node-standalone identity retire --yes` ([§9](#9-rotating-a-node-crypt4gh-identity)).
It refuses to drop the published or sole key and writes via check-and-set.

**The operator secret becomes the irreplaceable one; give it its own custody plan.** The
blob is useless without `operator.sec`, so losing that loses the backup. Back the blob up
to multiple operator keys with repeated `--recipient`, so one lost operator key is
survivable, and hold `operator.sec` under your own escrow: split custody, an offline HSM,
sealed media. `identity backup` implements no m-of-n threshold; the recipients are a plain
disjunction, and any one secret restores.

#### The Vault Transit master key: the Vault operator's responsibility

The Transit master key never leaves Vault, so there is no node tooling to export it. Its
durability is the Vault operator's job: cluster snapshots, HA, Vault's own DR. Do not make
the key `exportable` just to back it up; that weakens the at-rest guarantee.

**Detection.** A replaced or reset key is caught at startup by the at-rest sentinel
(`<data_dir>/.pme-sentinel.json`). The node logs one error, reports `at_rest: mismatch`
with `ready: false`, and raises `PmeMasterKeyMismatch`.

**If the Transit key is genuinely lost**, with no Vault snapshot to restore it from, the
existing PME parquet at rest is permanently undecryptable. The datasets are not
necessarily lost, though, because S3 is the source of truth. Provision a new Transit key: a lost
key cannot be rotated, so §10's rotation and revocation steps do not apply. Then re-ingest
every dataset from the bucket so each file's DEK is re-minted under the new key. Published
datasets are immutable, so re-ingest here means delete-then-re-add per the §5 callout, not
a bare `upload --replace`; §10's "Scripting the bulk re-ingest" gives a `verify`-driven
loop. Any dataset whose source `.tar.c4gh` is also gone from S3, and not held in an
archive, is unrecoverable.

**Finally, reseal the sentinel.** The sentinel is written once, when absent, and lives on
the data volume beside the data it vouches for, so it survives both the incident and this
recovery. After the re-ingest above every dataset is decryptable under the new key but the
old sentinel is not, and the node would keep latching `at_rest: mismatch` and
`ready: false` on every boot over a healthy store. Clear it with:

```bash
gdi-node-standalone pme reseal --yes
```

It re-proves the store first, footer-decrypting a real `PARE` dataset through the same
retriever the query path uses, and refuses if the configured key still cannot read the
store, so it cannot silence a genuine mismatch. It emits a `pme_sentinel_resealed` audit
line naming the mount, the key and the dataset it verified against. Restart the node
afterwards to clear the latched gauge. The node does not do this for itself: a guard that
clears itself in the scenario it exists to flag is not a guard.

Also enable Kubernetes Secret encryption-at-rest, so the mounted identity, S3 credentials
and Vault token are not plaintext in etcd, and keep the Vault bootstrap credential (a
static token or an AppRole `secret_id`) supplied out-of-band. It is not stored in Vault
itself.

---

## 18. Upgrades, version skew, and rollback

### Binary-swap ordering

The node is stateless apart from its data volume, so a rolling image or binary swap is
safe. Confirm the running build with `GET /version`, which reports `service_version`,
`gdi_metadata_version`, `git_sha` and `build_epoch`, or with the
`gdi_build_info{version,git_sha}` gauge. `service_version` and `gdi_metadata_version` do
not move for a hotfix rebuild of the same crate version; to tell two such builds apart use
`git_sha`, from the `gdi_build_info{git_sha}` label or the `/version` fields.

**How the two provenance values are resolved.** `git_sha` is `GITHUB_SHA` when set at
build time, else the repository's `HEAD` via `git rev-parse`, so a plain `cargo build` in a
checkout reports a real commit rather than `unknown`. It reads `unknown` only when
`GITHUB_SHA` is unset and no repository is reachable, which is the case inside the
container image: `.dockerignore` excludes `.git`, so an image built from the `Dockerfile`'s
builder stage reports `unknown` unless you pass the values in. Either way the value is
abbreviated to 12 hex characters, so it stays one width whoever built it, and remains a
prefix of a full-length SHA such as the image's `org.opencontainers.image.revision` label.
`build_epoch` is `SOURCE_DATE_EPOCH` when set, else the `HEAD` commit's committer epoch. It
is commit-stable, so a from-source rebuild of the same commit reproduces it.

To stamp your own image build, pass both as `--build-arg` (the `Dockerfile` declares
`GITHUB_SHA` and `SOURCE_DATE_EPOCH`; the shipped `Dockerfile` does not use them, because it
packages a binary the release job already stamped):

```bash
docker build --build-arg GITHUB_SHA="$(git rev-parse HEAD)" \
             --build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" .
```

`GDI_GIT_SHA` is the rustc-env variable the build script *emits*, not an input, so
setting it has no effect.

> **`git_sha` names a commit, not a tree.** It is taken from `HEAD`, so a build made with
> uncommitted changes reports the commit it was based on and carries no marker saying so.
> When you need certainty that a running binary matches a commit, build from a clean
> checkout, or compare the release artifact's `SHA256SUMS` entry, which is a property of
> the bytes rather than of the repository state.

Rely on the SIGTERM readiness drain and `preStop`
([§14](#14-graceful-shutdown-and-signals)) so in-flight requests drain before the old
process exits. An interrupted ingest is never persisted as `processing`, so it re-queues on
the new build.

**Single-writer invariant.** A `data_dir` has exactly one writer, enforced at boot by an
exclusive advisory lock on `<data_dir>/.lock`, held for the process lifetime and released
on exit. A second process that starts on the same `data_dir` fails fast with a descriptive
error rather than corrupting the first, so a boot cannot reap `datasets/.incoming/*` out
from under a peer, and two processes cannot race on `datasets/.status.json`.

For rolling swaps this means the old process must fully exit before the new one starts: a
naive `RollingUpdate` with `maxSurge ≥ 1` over a shared RWX volume crash-loops the surge
pod every rollout, because the old process still holds the lock. Use an RWO PVC with the
`Recreate` strategy, or `RollingUpdate` with `maxSurge: 0`. This is required, not merely
advisable, and is consistent with the single-replica framing in
[§6](#6-detecting-a-wedged-ingest-pool) and the RWO PVC in
[§14](#14-graceful-shutdown-and-signals). The only skew that then occurs is sequential,
the new binary reading state the old one wrote, which the on-disk compatibility section
below covers.

**The `data_dir` volume must be owned by the node's run uid.** At boot the node tightens
the data-dir root to owner-only, so a shared-volume co-tenant cannot traverse into the
decrypted store. A directory that is already `0o700` needs no `chmod` and is left
untouched, but the node still checks it is the owner and refuses by name if not. An
owner-only directory owned by somebody else is one an unprivileged uid can neither read
nor write, so booting on it would only move the failure to the first write. A node running as
root is exempt, because root bypasses the kernel's DAC checks. A group- or
other-accessible directory the node does not own cannot be tightened either, and it refuses
with an ownership-named error there too.

A named volume works out of the box, because the image pre-creates it owned by the run uid.
A raw root-owned `tmpfs`, a fresh `emptyDir` or a PV does not. `fsGroup` does not satisfy
this: it performs `chown -1:<gid>` plus setgid, so the owner stays root, and only the owner
may `chmod`, so the node's own tightening fails with `EPERM` and it refuses. `chown` the
volume to the run uid instead. On Kubernetes that means a root init container, which
`deploy/kubernetes` ships, a storage class that sets ownership, or a pre-provisioned PV.
This requirement is distinct from the RWO access mode.

To scale reads, do not share the volume: give each replica its own independent data volume,
each reconciling from the shared bucket, since S3 is the source of truth. They share no
`data_dir`.

> **`data_dir` must be block storage, and the node cannot check this for you.**
>
> Single-writer is enforced by an advisory `flock` on `data_dir/.lock`. That is sufficient
> on a local or block-backed filesystem (ext4, xfs, an RWO PVC), where a second process is
> refused with `WouldBlock`. If a filesystem does not support locking at all, the node
> refuses to start rather than proceeding unlocked.
>
> It is **worthless on NFS/RWX**. The Linux NFS client emulates `flock` with POSIX locks,
> and under `local_lock=all` (or `local_lock=flock`, or an NFSv3 server with no working
> lock daemon) the lock succeeds *locally on each client* and provides no cross-host
> exclusion. Two pods on two hosts then each believe they are the single writer and both
> run the atomic-publish and erase paths against one tree.
>
> There is no probe that distinguishes "I hold a cluster-wide lock" from "I hold a lock
> only my own kernel knows about", so **the node cannot detect this and will not warn**.
> Putting `data_dir` on an RWX/NFS volume is unsupported.

### On-disk compatibility

vN+1 can read vN's `data_dir`, and with one caveat vN can read vN+1's, because the two
persisted node-owned artifacts (`datasets/.status.json` and
`datasets/{id}/manifest.json`) are tolerant-parsed: unknown additive fields are ignored on
read. A removed or renamed required field would still fail to parse, and that failure is
whole-file. `.status.json` is loaded as a single parse and the caller propagates the error,
so one unparseable entry refuses the boot rather than degrading one dataset. The entire
dataset inventory is then unavailable until `.status.json` is hand-edited or deleted, and
deleting it loses every channel attribution and every recorded `error`. Additive changes
are therefore safe to roll back across; narrowing or renaming `state` or `channel` is not.

The caveat is the durable metadata overlay, `.metadata.overlay.json`. It is
`deny_unknown_fields`, so an overlay a newer node wrote with a new field fails to parse
under an older node. That is treated as "no overlay", so the dataset reverts to its
baseline metadata; it does not crash or block hydration. Re-applying the overlay on the
older node, as a `{id}.metadata.json` with only known fields, restores it. In all cases S3
remains the source of truth, so the ultimate rollback recovery is re-ingest
([§17](#17-disaster-recovery)). Newer overlay edits are not promised to survive a
downgrade.

### Config compatibility on rollback

The on-disk story above is about data; `node.toml` takes the opposite stance. The config is
parsed with `deny_unknown_fields`, so a downgrade boots and then dies with
`unknown field <name>` the instant the newer config carries a key the older binary does not
know. A config addition is a one-way ratchet the older binary cannot ignore. So when you
roll the image back, revert the config alongside it, and run `check-config` against the
target (older) binary as the pre-rollback dry run: it executes the live boot's preflight
without binding a listener, catching the `unknown field` before the rollout does.

> **"Revert it alongside" needs a mechanism, and `kubectl rollout undo` is not one.** `undo`
> reverts the pod template, and a ConfigMap edited in place has no history to revert to.
> `deploy/kubernetes` therefore generates the ConfigMap with a `configMapGenerator` and a
> hashed name: the name lands in the pod template, so the config is part of what `undo`
> reverts, and re-applying the previous manifests rolls both together. The general form,
> for any deployment shape: roll back by re-applying the previous manifests, image and
> config in one revision, not by reverting the image alone.
>
> `undo` also warns `resource … was previously managed with 'kubectl apply'. Rolling back
> will not update the last-applied-configuration annotation`. The pods are right, the
> recorded intent is stale, and the next `apply` of the old manifests re-syncs it.

`check-config` validates config content (shape, enums, cross-field contradictions) plus
one filesystem check: `service.data_dir` and `service.inbox` are rejected if they exist but
are not directories, because a file where a directory belongs is a typo the node can
otherwise only report as a confusing mid-boot failure. A green check does not guarantee the
node will start. The `[keys]` files existing, `data_dir` being writable, the public and
management ports being bindable, and Vault being reachable are checked only at boot, so a
passing check can still crash on startup.

### Tolerant-parse policy

- Persisted node-owned data (`.status.json`, `manifest.json`) is forward-compatible:
  additive unknown fields are ignored on read, so an older node tolerates a newer node's
  writes.
- The one opposite is `MetadataOverlay`, which is operator input. There
  `deny_unknown_fields` is the editable allow-list: a typo'd or protected key must fail
  loudly rather than be silently dropped.
- There is no `schema_version` or envelope field on `.status.json`. It is a transparent map
  keyed by dataset id, and S3 is the source of truth; adding such a field to a transparent
  map would itself be the breaking change this policy avoids.

---

## 19. HTTP surface (endpoint reference)

The full endpoint reference lives in [api.md](api.md): the public and management route
tables, CORS scoping, the resilience envelope, and standards conformance. The
two-listener security boundary, keeping the management plane off the public Ingress, is an
operational invariant covered above under [Where things live](#where-things-live).

---

## 20. Verifying release artifacts + the container image

> **`v1.0.0-rc.1` is the current release.** Being a candidate, it has no `:latest` image
> tag, so use the exact tag in the commands below.

Each release publishes, alongside the per-platform binaries: one `SHA256SUMS`, a keyless
SLSA build-provenance attestation via GitHub OIDC, needing no signing-key secrets, and a
CycloneDX SBOM per shipped binary (`gdi-node-standalone`, `gdi-dataset-tool`) rather than
one for the whole release. Verify before deploying.

**Checksums.** Download `SHA256SUMS` next to the artifact(s) and check:

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

**Build provenance (binaries).** Confirm the artifact was built by this repo's
release workflow (not re-uploaded), using the GitHub CLI:

```bash
gh attestation verify <artifact> --repo GenomicDataInfrastructure/gdi-node-standalone
```

**Container image.** The image (`ghcr.io/genomicdatainfrastructure/gdi-node-standalone`)
carries its own provenance attestation; verify it by digest:

```bash
gh attestation verify oci://ghcr.io/genomicdatainfrastructure/gdi-node-standalone:<tag> \
    --repo GenomicDataInfrastructure/gdi-node-standalone
```

**SBOM.** One CycloneDX SBOM per binary, attached to the Release as
`gdi-node-standalone.cdx.json` and `gdi-dataset-tool.cdx.json`, is the dependency inventory
for vulnerability scanning. The binaries are not `cargo-auditable`-embedded, so the SBOM
sidecar is the only mechanism. Feed the one matching what you deployed to your scanner, for
example `grype sbom:./gdi-node-standalone.cdx.json`.

### Image tagging and architecture caveats

- **`:latest` tracks stable releases only.** A `v0.x` pre-release tag publishes the
  immutable `:<tag>` image but does not move `:latest`. Pin a specific `:<tag>` in
  production regardless.
- **The image, once published, will be `linux/amd64` only.** It is built from the x86_64
  `gnu` (glibc) binary on `distroless/cc`. An arm64 host should run the released
  `aarch64-unknown-linux-gnu` binary on bare metal, or on your own `distroless/cc` base
  image; pulling the image on arm64 fails with a no-matching-manifest error. A
  manifest-list multi-arch image is a future upgrade.

---

## 21. Audit log

The node emits one structured **`audit`**-target log line per answered Beacon
data-discovery query (`entry_type` ∈ `genomicVariant` / `dataset` / `individual`), for
accountability ("was the node probed, how, and how much"). It is configured under
`[audit]`:

- **`enabled` (default `true`)**: emit the per-query line.
- **`query_detail` (default `false`)**: also log the queried coordinates and filters.

**Every line is tagged by `event`, and every line emitted from
`crates/gdi-node-standalone/src/audit.rs` also by `actor`.** Each `audit` line carries a
machine-filterable `event` from the catalogue below. The catalogue covers the `audit.rs`
emit sites only. The public-plane access log is also emitted on the `audit` target, with
`event = "http_request"`, carrying `status` and `latency_us` but no `actor`, because the
principal class is not known at the layer that emits it. It is the only per-request record
for resilience-layer rejections (408, 413, 414, 500, 503), which never produce a
`beacon_query` line, so do not filter it out of audit retention.

<!-- audit-event-names:start -->
`beacon_query`, `beacon_query_rejected`, `channel_suppressed`, `channel_unsuppressed`, `config_reloaded`, `dataset_inventory_read`, `dataset_state_change`, `dataset_state_read`, `dataset_suppressed`, `dataset_unsuppressed`, `fairdp_read`, `http_request`, `identity_backed_up`, `identity_initialized`, `identity_listed`, `identity_restored`, `identity_retired`, `identity_rotated`, `ingest_provenance`, `ingest_provenance_absent`, `keyless_degraded`, `log_level_changed`, `metadata_overlay_applied`, `metadata_overlay_cleared`, `metadata_overlay_set`, `override_store_reloaded`, `overrides_imported`, `plaintext_drop_not_allowed`, `pme_at_rest_unverifiable`, `pme_cache_flushed`, `pme_master_key_mismatch`, `pme_sentinel_resealed`, `purge_rejected`, `query_stats_read`, `reconcile_requested`, `reingest_refused`, `reingest_requested`, `writer_key_not_allowed`
<!-- audit-event-names:end -->

...and an **`actor`** naming
the process class that produced it: `beacon-client` (a public discovery caller),
`fairdp-client` (a FAIR Data Point / RDF harvester), `management-client` (a
`GET /datasets/{id}/state` read), `system` (the background reconcile / ingest
pipeline), or `operator` (an identity-lifecycle CLI action, or a `dataset
hide|take-down|show` suppression-override write; see the `dataset_suppressed` and
`dataset_unsuppressed` entries below for that actor's caveat). The `actor` names an
automated process outright rather than leaving it inferred from a missing `request_id`,
so a pipeline can split or alert on principal class directly.

**Private by default.** With `query_detail = false`, a line records only the query
shape: the entry type, the served `granularity`, `exists`, and the true result
`num_results`. It never records which variant was asked. Each line is emitted inside the
per-request span, so it carries the **`request_id`**: join it to the
fronting proxy's access log to attribute the client IP (and to the authenticated
subject once an auth layer is added). Enable `query_detail` only where the local
DPIA permits recording queried coordinates.

**Where that `request_id` comes from differs by plane, and an auditor needs to know.** On
the public plane it is always server-minted, and an inbound one is stripped, so an
unauthenticated caller cannot choose the correlation id on its own audit lines. On the
management plane a caller-supplied `x-request-id` is adopted when it is 1-128 bytes of
visible ASCII, so an orchestrator can follow one request across the boundary. That plane
has no authentication, its controls being the listener bind and a `NetworkPolicy`, so treat
`request_id` on a management-plane line as an untrusted correlation hint the caller chose,
not an identifier the node vouches for. It is still unforgeable as a link to the node's own
log lines for that request; it is not evidence about who made it.

**Answered and rejected queries are both tagged.** An answered line carries
**`event = "beacon_query"`**. A query rejected before or within the scan carries
**`event = "beacon_query_rejected"`** with the HTTP `code` (malformed, unknown or
ambiguous `assemblyId`, and too-broad are all `400`; a scan error is `500`) and a
path-free `reason` naming the offending field. A probe of malformed queries is therefore
accountable too, not just answered ones. Filter the whole stream on `"target":"audit"`,
then classify within it on the structured `event` field.

**`assembly` on a query line is the assembly searched, not the one requested.** A query that
omits `assemblyId` is answered under the node's default and told so on the wire
(`meta.assumedAssemblyId`, see [api.md](api.md)); the audit line records the resolved value
with no flag distinguishing it from an assembly the client actually sent.

**The management plane's read events are off by default** (`[audit].management_reads`,
default `false`). `GET /datasets` carries `event = "dataset_inventory_read"`, with `route`
naming which inventory was pulled, `/datasets` or `/datasets/suppressed`, since the two
disclose different sets. `GET /stats/queries` carries `event = "query_stats_read"`, and
`GET /datasets/{id}/state` carries `event = "dataset_state_read"`. The node emits all three
only when `[audit].management_reads` is set.

They default off because an orchestrator polls these routes per dataset per tick to
reconcile, which is not a disclosure to a data consumer. At 100 datasets on a 60 s cadence
that is roughly 144,000 synchronous, WORM-retained lines a day, burying the disclosures the
trail exists for. The management plane's request volume stays visible on
`gdi_http_requests_total{plane="management"}` regardless. Turn `management_reads` on where
a DPIA wants the management-read trail recorded despite the volume; the inventory and stats
ids still follow only under `query_detail`, and the public-plane disclosure trail
(`beacon_query`, `fairdp_read`) is audited independently of this knob.

**FAIR Data Point reads are tagged too.** A read of the RDF discovery surface
(`/fairdp` root / catalog / dataset / distribution) carries **`event = "fairdp_read"`**
with `resource` (the kind), the target `id`, and the served `count`. It is the FDP mirror
of `beacon_query`, so a harvester enumerating the catalog over RDF leaves the same trail a
beacon `datasets` enumeration does (never the metadata contents).

**Mutations, not just reads.** The same `audit` target also records node
*mutations*, so the trail is not query-only. A controlled-access node that audited
only discovery would leave who published what, what was rejected and which keys
changed unaccountable:

- **`event = "dataset_state_change"`**: a dataset changed serving state. Fields:
  `dataset` (id), `channel`, `state`, and a path-free `cause`.

  **`state` here is not the lowercase `visible|hidden|processing|error` vocabulary the
  rest of this runbook and `/datasets/{id}/state` use.** It is a mixed set, because some
  emit sites pass a literal and one Debug-formats the enum. Match on these exact strings:

  | `state` | `cause` | Emitted when |
  |---|---|---|
  | `error` | the closed error class (`unsafe-archive`, `decrypt-failed`, …) | a permanent ingest failure |
  | `rejected` | `immutable-redrop` | a changed re-upload under a live id was quarantined |
  | `Visible` / `Hidden` | `sidecar-state-change` | a `{id}.state.json` flipped visibility, from a bucket or the inbox (Debug-formatted, hence the capital). The `Visible` direction also emits an alarm line (`dataset.sidecar.release`, §15): a sidecar carries no writer identity, so a publication it drives is confirmed by a person, not just recorded |
  | `Deleted` | `package-removed` | the source object vanished from the bucket |
  | `Deleted` | `tombstone-delete` | an inbox `{"state":"deleted"}` tombstone |
  | `Deleted` | `operator-suppress-remove` | a `Remove` suppression's actual erasure (`actor = "system"`, the node performing it, distinct from the `dataset_suppressed` line below, which is the CLI recording the operator's intent) |
  | `OverlayApplied` / `OverlayReverted` | `metadata-overlay` | a metadata overlay was applied or reverted |

  A consumer that lowercases before comparing is safe against the casing split; one that
  matches the runbook's four-state vocabulary literally will silently miss every row
  except `error`.
- **`event = "dataset_suppressed"`**: `dataset hide` or `dataset take-down` wrote or
  refreshed an operator suppression override file
  (`<override_dir>/suppressions/{id}.json`). Fields: `dataset` (id) and `mode` (`hide` or
  `remove`). The operator-supplied `--reason` is absent: it is free text that in practice
  names a data subject, and this stream renders to stderr, into the cluster log aggregator
  and its backups, outside the retention policy that governs the override file. The
  override file remains the durable record of why; `dataset` and `mode` correlate this line
  to it. `channel_suppressed` omits it on the same grounds. `metadata_overlay_set` does
  carry a `reason`, because `dataset correct --reason` has no other durable home. The actor
  is the file-writer, not an authenticated identity: `actor = "operator"` means the process
  that ran this CLI command with filesystem access to `override_dir`, whose trust equals
  config-file-write trust, since there is no authentication on this path (§12, §13). The
  line is emitted by the CLI when the file write succeeds, whether or not the running node
  is up or ever applies it; the durable file is authoritative regardless.
- **`event = "dataset_unsuppressed"`**: `dataset unhide` (alias `dataset show`) removed an
  operator suppression override file, if one was present. A no-op removal, where the id
  carried no override, is audited too, mirroring `dataset_state_read`'s recording of a
  miss. Field: `dataset` (id). The operator's mandatory `--reason` is not a field, under
  the same rule as `dataset_suppressed`: reasons are free text about data subjects and stay
  off the log stream. It lives in the durable lift record the verb writes to
  `<override_dir>/lifted/{id}.*.json`, carrying the scope, the lifted mode and its
  authoring time, the reason, and when. That record is written only when an override was
  actually lifted, so a probing no-op leaves an audit line and no record. This line
  correlates one-to-one with its record by id, as `dataset_suppressed` does with its
  override file. Same file-writer `actor` caveat as `dataset_suppressed`.
- **`event = "purge_rejected"`**: `dataset purge-rejected` erased `inbox/.rejected/`
  quarantine entries on demand (§0b, §4). Fields: `count` (entries actually removed) and
  `older_than_secs` (the `--older-than` threshold, if given). One line per invocation, not
  per entry, unlike the automatic `rejected_retention_hours` GC, whose per-id removals go
  through `dataset_state_change` with `cause = "rejected-expired"` or
  `"rejected-overflow"` and `actor = "system"`. Emitted only for a real run, including a
  harmless `count = 0`; a `--dry-run` preview removes nothing and emits no line. Same
  file-writer `actor` caveat as `dataset_suppressed`.
- **`event = "override_store_reloaded"`**: a suppression-store reload, from `SIGUSR1` or a
  periodic reconcile, adopted an out-of-band change to the withhold set, such as a
  suppression file added, removed or mode-changed outside `dataset hide`/`show`/`take-down`,
  such as a direct `rm`, a hand-written file or a restore. `actor = "system"`, the node
  reconciling disk rather than an operator command. Fields: `added` (comma-joined `id=mode`
  or `channel:<name>=mode` for a new or escalated withhold) and `removed` (the ids or
  channels whose withhold vanished). Emitted only when the set changed; a no-op reload
  writes nothing. This makes an insider or co-tenant filesystem write to the override store
  visible in the audit stream, which would otherwise carry no trace of it. It does not
  authenticate the change; the store is still unsigned.
- **`event = "identity_rotated"`**: `identity rotate` added a new node crypt4gh
  key. Fields: `field` (the new published key field) and `retained` (key count).
- **`event = "identity_retired"`**: `identity retire` removed the oldest retained
  (decrypt-only) crypt4gh key (the inverse of `identity_rotated`; see §9). It carries
  no key material.
- **`event = "identity_initialized"`**: `identity init` minted (or, with `--from`,
  imported) the node's crypt4gh key. Fields: `field` (the new key field) and `imported`
  (imported vs freshly minted). It carries no key material.
- **`event = "identity_backed_up"`**: `identity backup` exported the node identity
  KV map to operator recipients (see §17). Fields: `fields` (identity fields exported)
  and `recipients` (operator keys the blob was encrypted to). It carries no key
  material, paths, or destination.
- **`event = "identity_restored"`**: `identity restore` re-created the node identity
  KV map on a fresh node from an operator backup (the inverse of `identity_backed_up`;
  see §17). Carries no key material.
- **`event = "identity_listed"`**: `identity list` read the node identity inventory
  (which key fields exist, which is the published recipient). A read, not a mutation: the
  identity-plane counterpart to `dataset_state_read`, so an inventory read is not silent.
  Field: `fields` (count). No key material or fingerprints.
- **`event = "pme_master_key_mismatch"`**: the configured at-rest master key no longer
  unwraps the sentinel this node wrote, so existing PME data is undecryptable. Emitted at
  boot, with `actor = system` and a key-material-free `detail`. Pair it with any later
  `pme_sentinel_resealed`: that event is the deliberate overwriting of key provenance, and
  this is the incident that prompted it.
- **`event = "pme_at_rest_unverifiable"`**: the at-rest key check could not be completed
  from local state, because the sentinel is unreadable, unparseable, or names a scheme
  this build does not know. It is a separate event from `pme_master_key_mismatch`, which
  says the key is wrong; this one says the node could not tell. Readiness names them apart too,
  `at_rest: "unverifiable"` here and `at_rest: "mismatch"` for a real key incident, but the
  probe forgets on restart and this audit stream does not, which is what makes a later
  `pme_sentinel_resealed` legible. Emitted at boot with `actor = system` and a
  key-material-free `detail`. It matters most for a restored data volume whose Transit key
  was replaced, which presents as a local fault rather than a mismatch. For a damaged
  sentinel the operator path is `pme reseal`; for an unknown scheme it is not, because the
  sentinel came from a newer binary and `reseal` refuses.
- **`event = "reconcile_requested"`**: a reconcile pass started, reloading suppressions
  and metadata overlays, draining queued reingest markers, rescanning the inbox and waking
  every bucket monitor. `trigger` names which path started it: `sigusr1` (an operator with shell
  access) or `http` (`POST /reconcile`, on a management plane that authenticates nothing).
  Emitted from inside the shared pass, before the work, so the record survives a pass that
  fails partway. Actor `system`: on the HTTP trigger the node cannot attribute the request
  to a person.
- **`event = "reingest_requested"`** and **`event = "reingest_refused"`**: `POST
  /datasets/{id}/reingest` cleared one dataset's recorded source signature and started the
  reconcile pass (`reingest_requested`, with the `dataset`), or refused to
  (`reingest_refused`, with the `dataset` and a `reason`: `unknown` for an id this node has
  never seen, the `404`, or `not_retriable` for an entry clearing would not change, the
  `409`). The refusals are recorded on the same terms as `dataset_state_read`'s miss: the
  route answers the existence question for any id, on a plane that authenticates nothing,
  and before the pacing window.
- **`event = "log_level_changed"`**: runtime diagnostic logging was turned on or off,
  carrying the resulting `verbose` state and the applied `filter`. `trigger` is `sigusr2`,
  `http` (`POST /log-level`), or `auto-revert` when the diagnostic window elapsed on its
  own. Both edges are recorded: an auditor asking how long this node was logging every
  request in detail needs the close as well as the open. Actor `system`.
- **`event = "pme_cache_flushed"`**: the PME DEK cache was flushed, propagating a
  Vault-side key revocation (a bumped Transit `min_decryption_version`) into the running
  node. It is governance-critical, because it proves when a revocation reached a node,
  and carries no key material. It has two triggers, named in the `trigger` field:
  `sighup` (an operator with shell access) and `http` (`POST /reload`, meaning anyone who
  can reach the management listener, which authenticates nothing). The actor is therefore
  `system`, the node applying the revocation, not `operator`, which would assert an
  attribution the node cannot make. Same decomposition as `config_reloaded`.
- **`event = "pme_sentinel_resealed"`**: an operator ran `pme reseal`, rewriting
  `<data_dir>/.pme-sentinel.json` against the currently configured Transit key (§10 step 4,
  §17). This is the single point at which the evidence of an at-rest master-key change is
  overwritten, so it is governance-critical. It carries the `operator` actor, the
  `transit_mount` and `transit_key` it resealed against, and `probed_dataset`: the stored
  dataset proved readable under the current key first, empty when the store held no
  encrypted dataset to prove against. Never key material.
- **`event = "ingest_provenance"`**: records the crypt4gh writer public-key provenance of
  an ingested package, meaning which key sealed it, for controlled-access accountability.
  Emitted per ingested package alongside its `dataset_state_change`. The writer key is
  proof of possession, not an authenticated identity: anyone holding the node's public
  recipient key can author a package under a fresh writer key of their own. Under the
  shipped default `[ingest].writer_policy = "off"` nothing gates on it, so treat it as an
  accountability record rather than a claim of origin. Only `writer_policy = "enforce"`
  gates ingest on the channel's trusted-writer allow-list
  (`[ingest].inbox_allowed_writer_fingerprints` or
  `[[s3.buckets]].allowed_writer_fingerprints`; see the `writer_key_not_allowed` entry
  below, and §14 for the SIGHUP reload). `warn` is discovery only: it publishes regardless
  and merely counts and audits. Even under `enforce` the allow-list proves only that the
  sealer held an allow-listed key. The same fingerprints are persisted in
  `datasets/.status.json` and served by `GET /datasets/{id}/state`, so the record outlives
  log rotation.
- **`event = "ingest_provenance_absent"`**: the sibling of the above, emitted when a
  published package carried no recoverable writer key. The closed-class `reason` is
  `plaintext` for an inbox staging directory, which has no crypt4gh envelope and is
  expected on every drop, or `recovery_failed` for a `.tar.c4gh` whose body decrypted but
  whose header yielded no writer key. The second is anomalous: it is emitted at `warn` and
  alerted via `gdi_ingest_provenance_absent_total{reason="recovery_failed"}`. Every
  successful ingest
  emits exactly one of `ingest_provenance` or `ingest_provenance_absent`, so the absence of
  both is itself a signal.
- **`event = "writer_key_not_allowed"`**: a package whose crypt4gh writer key is not in
  its channel's allow-list (`[ingest].inbox_allowed_writer_fingerprints` for the inbox,
  `[[s3.buckets]].allowed_writer_fingerprints` per bucket) reached ingest under a non-`off`
  `writer_policy`. `decision` is `quarantined` (`enforce`: not published, a permanent
  `writer-rejected` error) or `published_warn` (`warn`: published anyway, recorded for
  allow-list discovery). Carries the offending public fingerprints, never key material.
- **`event = "plaintext_drop_not_allowed"`**: a plaintext staging-dir drop, which has no
  crypt4gh envelope and hence no writer key, reached a channel under a non-`off`
  `writer_policy`. It can never appear on an allow-list, so `enforce` quarantines it
  (`decision = "quarantined"`, a permanent `writer-rejected` error) and `warn` publishes it
  (`decision = "published_warn"`) so you can find every plaintext producer before switching
  to `enforce`. Gating it stops the staging-dir path from bypassing the allow-list
  `enforce` requires. A node that legitimately ingests plaintext is keyless, and `enforce`
  on a keyless node is refused at preflight.
- **`event = "keyless_degraded"`**: stamped once (with the `system` actor) when the
  node boots **degraded-keyless** (`[vault]` set but unreachable at startup);
  encrypted-package ingest is skipped until a restart with Vault reachable (see §8 and
  `gdi_keyless_degraded` in §2).

These mutation events are gated on `enabled` only; `query_detail` does not apply, because
there is no query content. They never carry manifest contents or key material. A transient
"left for the next reconcile" outcome is not a state change, since there is no terminal
state yet; it surfaces in the metrics and logs instead.

**A management-plane read is audited only with `[audit].management_reads`.** Beyond the
public Beacon queries above, the node can emit `event = "dataset_state_read"` on
`GET /datasets/{id}/state`, the hidden-dataset state oracle
([api.md](api.md#management-plane)), on hit or miss, so probing it is accountable. It
defaults off, because the orchestrator's own reconciliation poll would otherwise dominate
the stream. Fields when on: `found` (whether the id is known), `state` (the served state,
omitted on a miss), and `channel`. Gated on `[audit].enabled` and
`[audit].management_reads`.

It carries a `request_id` in its span when the caller supplied one: the management plane
adopts an inbound `x-request-id` of 1-128 visible-ASCII bytes, and the audit line is emitted
inside the span that id names. Read that field as an untrusted correlation hint, not as an
identifier the node vouches for: this plane has no authentication, so anyone who can reach
it chooses the value that appears here. The public plane does the opposite, stripping and
re-minting, because there the caller is the internet. With no inbound id the node mints its
own, and dataset id plus timestamp remain a correlation of last resort.

The lines are ordinary NDJSON on stderr, because the node owns no audit storage. Route and
retain them in your log pipeline: filter on the concrete `"target":"audit"` field in each
line, into a dedicated, retention- or WORM-managed stream. Under `LOG_FORMAT=ecs` that
field is named `log.logger`, not `target`, so a rule written against `"target":"audit"`
matches nothing there and the compliance stream stays silently empty (see the §15 rename
table). The event name is `labels.event` in `ecs`. A rising
`gdi_background_task_panics_total` is unrelated; it counts recovered daemon-loop panics
(§2).

### 21.1 The audit trail has two producers: collect both

**A collector attached to the server container captures only half the catalogue.** The
node's audit trail is emitted by whichever process performs the action, and the operator
commands are separate, short-lived processes: usually a `docker exec` or `kubectl exec` into
the container, or the binary run straight from a shell. Their audit lines go to that
process's stderr and are gone when it exits. Nothing forwards them to the running server,
and the server logs nothing about them.

These events are emitted only by the CLI, never by the serving process:

| `event` | Emitted by |
| --- | --- |
| `dataset_suppressed`, `dataset_unsuppressed` | `dataset hide` / `dataset take-down` / `dataset unhide` |
| `channel_suppressed`, `channel_unsuppressed` | `channel hide` / `channel take-down` / `channel unhide` |
| `metadata_overlay_set`, `metadata_overlay_cleared` | `dataset correct` / `dataset correct --reset` |
| `overrides_imported` | `overrides import` |
| `identity_initialized`, `identity_rotated`, `identity_retired`, `identity_backed_up`, `identity_restored`, `identity_listed` | the `identity` subcommands |
| `pme_sentinel_resealed` | `pme reseal` |
| `purge_rejected` | `dataset purge-rejected` |

That set is the take-down, disclosure-correction and key-custody record: the part an
auditor is most likely to ask for, and the part most likely to be missing. A take-down
performed by `docker exec … dataset take-down DATASET_ID --yes` leaves no trace in the
server's log stream. The only server-side evidence is the effect, a
`dataset_state_change` on the next reconcile, not the who, when or why.

**Capture it at the call site.** The CLI writes the audit line to stderr in the same format
the server uses (`LOG_FORMAT` applies), so append it to the same collected file, or pipe it
into the same agent:

```bash
# Container: tee the operator command's stderr into the collected stream.
docker exec gdi-node sh -c \
  'gdi-node-standalone --config /etc/gdi/node.toml dataset hide DATASET_ID --reason TICKET-123 2>&1 | tee -a /proc/1/fd/2'

# Kubernetes: same idea; /proc/1/fd/2 is the PID-1 stderr the log agent already tails.
kubectl exec deploy/gdi-node -- sh -c \
  'gdi-node-standalone --config /etc/gdi/node.toml dataset hide DATASET_ID --reason TICKET-123 2>&1 | tee -a /proc/1/fd/2'

# Host shell: append to a file the agent tails, and keep the exit code (tee would mask it).
gdi-node-standalone --config /etc/gdi/node.toml dataset hide DATASET_ID --reason TICKET-123 \
  2> >(tee -a /var/log/gdi/audit-cli.log >&2)
```

Wrap this in the operator wrapper script your runbook already uses, rather than trusting
each operator to remember the redirect. An unforwarded take-down leaves no trace, and
nothing reports its absence.

Everything in §21.2 applies to both producers unchanged: the CLI lines carry the same
`target: "audit"` / `log.logger: "audit"` key and the same closed `event` set, so one
routing rule covers them once they reach the agent.

### 21.2 Separating the audit stream from operational logs

**Why this matters.** The node writes the audit trail and every operational log line to the
same stderr stream, so it stays a 12-factor process and owns no audit storage. Building an
audit file into the node would mean owning rotation, permissions, fsync, a writable mount
under the read-only root filesystem, and a disk-full policy in which dropping a compliance
record silently would be worse than keeping it. The cost is that, undirected, the audit
trail lands in the same store as `DEBUG` chatter, with the same retention window and the
same read access. An audit trail wants the opposite: long, often multi-year retention, read
access limited to auditors, and ideally append-only or WORM storage.

**The node's half is done.** Every audit line is self-identifying, by `"target": "audit"`
(or `log.logger":"audit"` under `LOG_FORMAT=ecs`) plus a closed `event` from the catalogue
above, so the separation is a routing rule in your log agent, applied where the retention
and access policy already live. You need nothing from the node beyond what it emits.

**Recipe for Grafana Alloy**, the agent the `docker-compose.observability.yml` overlay
ships. The shipped `compose/observability/alloy/config.alloy` tails containers straight
into Loki: `loki.source.docker` then `loki.write`. Insert one processing stage between them
that promotes a low-cardinality `audit` label, so the trail becomes a selectable stream:

```river
// Point the existing docker source at this stage instead of straight at loki.write:
//   loki.source.docker "containers" { ... forward_to = [loki.process.audit_split.receiver] }

loki.process "audit_split" {
  forward_to = [loki.write.default.receiver]

  // Pull the tracing target out of the node's JSON line. Under LOG_FORMAT=ecs the
  // field is `log.logger`, not `target`. Change the right-hand side to match, or the
  // audit stream stays silently empty.
  stage.json {
    expressions = { logtarget = "target" }
  }

  // Derive a two-valued label so `{audit="true"}` selects the compliance trail while
  // cardinality stays at 2. Promoting `logtarget` directly would mint one stream per
  // module path, a Loki anti-pattern.
  stage.template {
    source   = "audit"
    template = "{{ if eq .logtarget \"audit\" }}true{{ else }}false{{ end }}"
  }

  stage.labels {
    values = { audit = "audit" }
  }
}
```

The label only makes the stream addressable. The separation happens at the store, where
retention and access are configured, and that part is deployment-specific:

- **Loki**: apply a longer per-stream retention rule to `{audit="true"}` than to the rest,
  and restrict who may query that stream. For true immutability, ship the same lines to an
  object store with a bucket WORM or retention lock.
- **Splunk, Elastic, Fluent Bit, Vector**: filter on the same `target == "audit"` field and
  route to a dedicated index or pipeline with its own retention and RBAC. The match key is
  identical; only the agent syntax differs.

The observability overlay is a local stack, a single Loki with no retention configured, so
treat the snippet as the shape to carry into your production pipeline, not a turnkey
compliance setup. The match key (`target` or `log.logger` equal to `"audit"`) does not
change between environments: the node guarantees it and floors it, so no `GDI_LOG`
directive can silence the audit target (§15).

---

## 22. One dataset's queries cost far more than its neighbours

**Symptom.** One dataset's `g_variants` queries peak far higher than another dataset of
similar row count and disk size, or get refused with `400 query too large` while the others
answer fine. Two details separate this from ordinary big-dataset behaviour:

* Lowering `requestedGranularity` to `count` or `boolean` does not make it cheaper.
* Lowering the client's `pagination.limit` does not either.

Everywhere else on this node those two knobs bound the cost, so when neither bites, the
cost is not the answer being built. It is the read.

**Cause.** That dataset stores more than one parquet file in a single position block. The
node normally streams a block row by row, holding one variant group at a time, because rows
arrive in ascending `(POS, REF, ALT)`. It cannot when a block holds several files whose
`POS` spans overlap, which is what a per-population split produces: several source VCFs
carrying different populations over the same loci. Such a block must be read, buffered and
sorted in full before it can be folded, so the peak tracks the block's matching rows rather
than the requested page. For the same 1.6 M rows and the same answer, one file per block
peaks at 17 MiB and eight files at 462 MiB.

**Confirm it** by counting files per block in the dataset's directory. The block is the
third dot-separated component of the filename:

```bash
# Counts files per chr+block. `-printf '%f'` matters: the fields are counted from the file
# name, and a data_dir whose path contains a dot would otherwise shift them.
find "$DATA_DIR/$DATASET_ID" -name 'allele-freq.*.parquet' -printf '%f\n' \
  | awk -F. '{print $2"."$3}' | sort | uniq -c | sort -rn | head
```

A count of `1` on every line is the streaming shape:

```text
      1 chr1.0
```

Any line with a count above `1` names a block that will be merged in memory, and the
largest such count is what to size for; here, eight files in one block:

```text
      8 chr1.0
```

**The node also says so on its own.** Every block it has to buffer whole increments
`gdi_beacon_merged_blocks_total` (§2) and logs one `debug` line carrying that block's file
count, so a node whose queries feel expensive can be diagnosed from the metric before anyone
runs the `find` above; a flat zero rules this cause out. The counter is unlabelled, because
a `dataset` label on a public-query metric would key Prometheus series by data.

**And so does the build.** `gdi-dataset-tool build`, and `package`, prints a note when two
or more of a package's source VCFs write into the same position block, naming how many
blocks are affected and the worst one. That is the last moment the layout is still a
choice; after the package ships, the cost is the operator's and the fix is another build.

**What to do.** Nothing is wrong with the dataset and the node serves it correctly, so the
choice is where to absorb the cost:

* **Size for it.** Size memory on the worst block's matching rows rather than on the page
  size; the count above names that block.
  [deployment.md](deployment.md#resource-baseline) covers the rest of the memory budget.
* **Cap it and accept refusals.** `[service].max_query_bytes` converts the exposure from
  memory growth into a clean `400` for the queries that would exceed it, and the node stays
  healthy. The buffer is charged and credited per block, so only the largest block's buffer
  is ever resident, and the ceiling overshoots by about one file's rows because the charge
  lands after each file is read.
* **Ask the provider to repackage.** A package split by position, one VCF per region,
  instead of by population, puts one file in each block and restores streaming. This is the
  only option that removes the cost rather than relocating it.

A k-way merge across the block's files would stream this shape too. The node does not
implement one, so a per-population split package always pays the buffer.
