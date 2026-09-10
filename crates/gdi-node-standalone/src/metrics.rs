//! Prometheus text-exposition instrumentation.
//!
//! One instrumentation layer with two sinks: the hook points across the service emit a
//! `metrics::counter!`, `gauge!` or `histogram!` alongside their `tracing` event, so there
//! is no parallel bookkeeping. This module owns the metric-name constants every hook point
//! references, the `PrometheusRecorder` install, the periodic gauge sampler, and the
//! `/metrics` route ([`metrics_router`]) mounted on the management-plane listener
//! (`[service].management_addr`), a separate listener from the public `listen`, alongside
//! the health probes and the dataset-state oracle.
//!
//! Privacy invariants, enforced by construction here:
//! * `/metrics` lives only on the management plane, never the public `listen`, so the
//!   operational series stay in-cluster behind the bind address and a `NetworkPolicy`. The
//!   recorder is a no-op when [`install_recorder`] cannot install.
//! * No label is derived from request content or client identity. Every label key this
//!   module passes to `gauge!`, `counter!` or `histogram!` is listed in the machine-readable
//!   line below, which `module_header_names_exactly_the_label_keys_the_module_emits` binds
//!   to the code in both directions. Each is a bounded, content-free, operator-known set:
//!   `channel`, `catalog` and `volume` are operator-named; `state` is the four
//!   [`DatasetState`](gdi_node_standalone_core::state::DatasetState) values; `outcome` is
//!   `success|transient|permanent|timeout|refused_pool_pressure|cancelled` on the ingest
//!   series and `recovered|failed` on `gdi_vault_reauth_total`; `error_class` is the
//!   sanitised closed class beside a `permanent` ingest outcome, emitted from
//!   `ingest_runtime` and `s3` rather than here; `entry_type` is
//!   `genomicVariant|dataset|individual`; `status_class` is `1xx|2xx|3xx|4xx|5xx|other`;
//!   `granularity` is `boolean|count|record|n/a`; `exists` is `true|false`; `code` is
//!   `400|413|500|other`; `plane` is `public|management`; `mode` is the suppression modes;
//!   `form` the at-rest forms; `component` the readiness components; `operation` the Vault
//!   call kinds; `reason` the per-series closed reject-reason sets; `resource_type` the FDP
//!   resource kinds; and `version` and `git_sha` the build stamp. Never a variant, region,
//!   assembly, filter, query string, token, IP address or `Origin`, and never a
//!   per-dataset-id label.
//!
//! label keys: `catalog`, `channel`, `code`, `component`, `entry_type`, `error_class`, `exists`, `form`, `git_sha`, `granularity`, `mode`, `operation`, `outcome`, `plane`, `reason`, `resource_type`, `state`, `status_class`, `version`, `volume`

use std::sync::Arc;
use std::time::Duration;

use gdi_node_standalone_core::suppression::SuppressMode;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tracing::warn;

use crate::state::AppState;

// ---- Metric names (the curated series) ----

/// Process uptime in seconds (gauge, sampled on scrape via the periodic task).
pub const UPTIME_SECONDS: &str = "gdi_uptime_seconds";
/// Build version info (gauge, constant `1` carrying a `version` label).
pub const BUILD_INFO: &str = "gdi_build_info";

/// Dataset count by state (gauge; label `state` ∈ visible|hidden|processing|error).
pub const DATASET_STATE: &str = "gdi_dataset_state";
/// Free bytes on the data volume (gauge; label `volume`).
pub const DISK_FREE_BYTES: &str = "gdi_disk_free_bytes";
/// Health of the [`DISK_FREE_BYTES`] sample: `1` when the last `statvfs` failed, `0` when it
/// succeeded (gauge).
///
/// The exporter is a registry rendered on demand with no idle timeout, so a gauge that stops
/// being set keeps rendering its last value: a failed sample reads as healthy rather than as
/// a gap. Without this companion the `LowDisk` alert evaluates a frozen number after a volume
/// detaches. Seeded `0` at recorder install, because an unseeded series never trips a `> 0`
/// alert reliably.
pub const DISK_SAMPLE_FAILED: &str = "gdi_disk_sample_failed";

/// Dataset count by operator-suppression override mode (gauge; label `mode` ∈
/// `hide|remove`). Reflects the whole `<override_dir>/suppressions/*.json` store's mode
/// breakdown (`SuppressionSet::counts_by_mode`), independent of whether an id happens to be
/// cached when a `Remove` completes its erase. Set on every re-apply of the suppression set
/// to the cache — the periodic full reload and `SIGUSR1` — and resampled every
/// periodic-sampler tick (`sample_suppressions`). The resample is what makes the gauge
/// correct within one tick of boot, since `enforce_suppressions` runs before the recorder
/// installs and `AppState::new` loads the set without going through the event-driven
/// setter.
pub const DATASETS_SUPPRESSED: &str = "gdi_datasets_suppressed";
/// Count of `<override_dir>/suppressions/*.json` entries that failed to parse on the last
/// load and were fail-closed to `hide` (gauge; node-wide). `0` on a clean load. Set on every
/// `SIGUSR1` reload
/// ([`AppState::reload_suppressions`](crate::state::AppState::reload_suppressions)) and
/// resampled every periodic-sampler tick (`sample_suppressions`). The resample is what
/// covers boot: `AppState::new` loads the suppression set inline without calling
/// `reload_suppressions`, so otherwise the gauge would not reflect a broken override file
/// already on disk. A sustained non-zero value means an operator should find and fix the
/// offending override files; see `docs/operating.md` §21.
pub const SUPPRESSION_LOAD_DEGRADED: &str = "gdi_suppression_load_degraded";
/// Whether the operator-override store is unusable — absent, or present but unreadable
/// (gauge 0/1; node-wide). `1` means the node is serving from its last known-good in-memory
/// override set: every reload is skipped so a stale but safe set is kept rather than
/// silently lifting every withhold, and no new `dataset hide` or `correct` takes effect
/// until the store is restored.
///
/// This is the only signal for that state. `gdi_datasets_suppressed` keeps reporting the
/// retained counts, because the sampler reads the live set rather than the disk, and
/// `gdi_suppression_load_degraded` stays `0` because nothing failed to parse. Resampled
/// every periodic-sampler tick, which makes it correct regardless of when a reload last ran.
/// See `docs/operating.md` §3 for the `OverrideStoreAbsent` alert and §17 for why the store
/// cannot be rebuilt.
pub const OVERRIDE_STORE_ABSENT: &str = "gdi_override_store_absent";
/// Whether a channel — an S3 bucket's configured `name`, or `inbox` — is under an active
/// operator channel-suppression override (gauge 0/1; label `channel`). It is the "stop this
/// provider now" lever: every dataset of the channel is withheld and its ingest paused, by
/// `BucketMonitor::run`'s in-loop pause and the inbox scanner's early return. Set from two
/// paths, mirroring [`DATASETS_SUPPRESSED`] and [`SUPPRESSION_LOAD_DEGRADED`]: event-driven
/// on every `BucketMonitor` wake, including a `SIGUSR1`-triggered one, and by the periodic
/// sampler (`sample_channel_suppressions`) for every configured channel. The sampler is the
/// only path for the `inbox` channel, which no per-channel loop watches, and it is what
/// makes the gauge correct regardless of boot ordering.
pub const CHANNEL_SUPPRESSED: &str = "gdi_channel_suppressed";
/// Whether a channel is orphaned (`1`): the status index still owns datasets for it but no
/// `[[s3.buckets]]` entry declares it, so nothing polls it, a departed provider's retraction
/// can never take effect, and its datasets are withheld by the hydrate projection
/// (`AppState::channel_is_orphaned`). Operator-actionable while 1: re-add the
/// `[[s3.buckets]]` entry to resume serving, or erase with `channel take-down <name>`. Set
/// at boot, and cleared live if a config reload re-adds the bucket. Not seeded to 0 per
/// channel: an orphan is by definition absent from the config, so the label set is unknowable
/// at seed time, and the alert is `> 0`, which tolerates an absent series.
pub const S3_CHANNEL_ORPHANED: &str = "gdi_s3_channel_orphaned";
/// Whether a `[catalogs]` entry has been removed while visible datasets still declare it
/// (`1`), with the datasets orphaned from FDP discovery.
///
/// `/fairdp` lists one catalog per configured entry, so those datasets drop out of the
/// root's `ldp:contains` and out of every crawl path while staying `visible` and served by
/// the Beacon. They are de-listed from the one interface a FAIR Data Point exists to
/// provide, and without this gauge nothing else says so.
///
/// The catalog counterpart of [`S3_CHANNEL_ORPHANED`] in signalling only: the datasets are
/// not withheld. That sibling withholds because an orphaned bucket is never polled again, so
/// the provider's retraction stops working. A catalog is a discovery grouping, the dataset
/// still reconciles through its own channel, and deletion still takes effect, so pulling
/// live public data off the air over a config typo would buy nothing.
///
/// Operator-actionable while 1: re-add the `[catalogs]` entry to restore discovery, or
/// retract the datasets with a take-down.
///
/// Every configured catalog is set to `0` at boot and on each reload, so a healthy node
/// carries the full baseline and re-adding an entry stands the alert down. An orphan's label
/// cannot be seeded, being absent from the config, so the alert is a `> 0` threshold, which
/// tolerates a series that only appears when the condition does.
pub const CATALOG_ORPHANED: &str = "gdi_catalog_orphaned";
/// Whether the keyspace gate is currently refusing a bucket channel's removal processing
/// (`1`). The configured endpoint, bucket or prefix is not the keyspace its on-disk datasets
/// were ingested from, or the witness file is unreadable, and datasets are missing from the
/// new keyspace's listing. Serving and additions continue; evictions do not.
/// Operator-actionable while 1: revert the keyspace change, finish the migration, or erase
/// the channel's datasets with `take-down`. See the `removals_authorized` doc in `s3.rs`.
pub const S3_KEYSPACE_MISMATCH: &str = "gdi_s3_keyspace_mismatch";
/// `SIGHUP` config-reload attempts that failed validation and were discarded, so the running
/// node kept its previous `[catalogs]` and `[ingest]` writer-allow-list subset (counter).
/// `0` under normal operation; each increment means a reload did not take effect, because
/// the TOML was unparsable or the reloaded file failed the same preflight boot runs, and the
/// paired warning names the reason. Never increments on a clean reload, nor on a reload that
/// only changed a restart-only field, which warns while the reload itself succeeds.
pub const CONFIG_RELOAD_FAILED_TOTAL: &str = "gdi_config_reload_failed_total";

/// This process's resident set size in bytes (gauge; Linux `/proc/self/status` `VmRSS`). A
/// memory signal that needs no separate exporter, and paired with [`PROCESS_OPEN_FDS`] and
/// [`PROCESS_THREADS`] it catches a memory, descriptor or thread leak before the process
/// OOMs or hits `EMFILE`.
pub const PROCESS_RESIDENT_MEMORY_BYTES: &str = "gdi_process_resident_memory_bytes";
/// This process's open file-descriptor count (gauge; entries under `/proc/self/fd`).
pub const PROCESS_OPEN_FDS: &str = "gdi_process_open_fds";
/// This process's thread count (gauge; Linux `/proc/self/status` `Threads`).
pub const PROCESS_THREADS: &str = "gdi_process_threads";
/// Cumulative CPU time (user + system) this process has consumed, in fractional seconds
/// (gauge; Linux `/proc/self/stat` `utime`+`stime` ÷ `CLK_TCK`). The CPU leg the
/// RSS/fd/thread gauges miss: `rate(gdi_process_cpu_seconds[5m])` is the per-core
/// utilization, so a busy-loop or pathological regex pinning a core becomes visible
/// instead of silent.
///
/// A gauge, not a counter, and without the `_total` suffix: the `metrics` facade's counters
/// are `u64`, so as a counter this would carry whole seconds, and a node using a fraction of
/// a core would tick once every few minutes with `rate()` reading `0` for most windows. The
/// kernel tally is monotonic within a process life, so `rate()` over this gauge gives the
/// same utilization a float counter would, and a restart resets it to ~0 as a counter
/// would.
pub const PROCESS_CPU_SECONDS: &str = "gdi_process_cpu_seconds";

/// In-queue ingest jobs not yet picked up (gauge).
pub const INGEST_QUEUE_DEPTH: &str = "gdi_ingest_queue_depth";
/// Ingest jobs currently being processed by a worker (gauge).
pub const INGEST_INFLIGHT: &str = "gdi_ingest_inflight";
/// Age in seconds of the oldest ingest currently in flight, queued or being processed, and
/// `0` when none is (gauge). Sampled from the runtime's in-flight markers
/// (`AppState::ingest_inflight`) by the periodic sampler. This is the stuck-ingest signal
/// `DatasetStuckProcessing` fires on: a marker that never releases — a hung job, or a
/// timed-out one whose detached task never ends — raises it without bound, whereas the
/// [`INGEST_INFLIGHT`] count sits at 1 just as well under a steady stream of short,
/// overlapping ingests.
pub const INGEST_INFLIGHT_OLDEST_AGE_SECONDS: &str = "gdi_ingest_inflight_oldest_age_seconds";
/// Distinct sources currently in a transient-failure backoff window (gauge). Rises when a
/// backend such as Vault or S3 keeps a source failing across reconciles, so a sustained
/// non-zero value is a persistently failing backend an operator should investigate. The
/// per-failure `outcome="transient"` counter is a rate and cannot distinguish that from many
/// one-off blips. Cleared per source on the first successful ingest.
pub const INGEST_TRANSIENT_BACKOFF: &str = "gdi_ingest_transient_backoff";
/// Configured ingest worker capacity (gauge; constant, set once at startup to the
/// resolved `ingest_concurrency`). Paired with [`INGEST_INFLIGHT`] for a
/// deployment-independent saturation signal (`inflight >= concurrency`).
pub const INGEST_CONCURRENCY: &str = "gdi_ingest_concurrency";
/// Configured Beacon query scan fan-out capacity (`query_concurrency`, else
/// `ingest_concurrency`) — the capacity line for `gdi_beacon_scan_blocking_inflight`.
///
/// A separate gauge from [`INGEST_CONCURRENCY`] because `[service].query_concurrency`
/// decouples the two: an alert on scan saturation must compare against the query cap, and
/// the two values coincide only while that knob is unset.
pub const QUERY_CONCURRENCY: &str = "gdi_query_concurrency";
/// Unix seconds of the last ingest progress event (gauge). It distinguishes a busy pool
/// from a wedged one: a queue above 0 with this not advancing means wedged.
pub const INGEST_LAST_PROGRESS_TIMESTAMP_SECONDS: &str =
    "gdi_ingest_last_progress_timestamp_seconds";
/// Ingest outcomes (counter; label `outcome` ∈
/// `success|transient|permanent|timeout|refused_pool_pressure|cancelled`, plus a
/// sanitized closed-class `error_class` on a permanent error). `refused_pool_pressure`
/// counts an ingest deferred because the shared blocking pool was saturated
/// (backpressure); `cancelled` an ingest cut short by shutdown (a rolling restart
/// mid-backfill is routine, so it is not folded into `transient`).
pub const INGEST_TOTAL: &str = "gdi_ingest_total";
/// Ingest wall-clock duration (histogram, seconds).
pub const INGEST_DURATION_SECONDS: &str = "gdi_ingest_duration_seconds";

/// Published packages that carried no recoverable crypt4gh writer key (counter; closed
/// `reason` label). `plaintext` is expected on every inbox staging-dir drop, which has no
/// envelope. `recovery_failed` is anomalous — the body decrypted but the header yielded no
/// writer key — and is the alertable series.
pub const INGEST_PROVENANCE_ABSENT_TOTAL: &str = "gdi_ingest_provenance_absent_total";
/// `reason` label: the plaintext staging-dir path carries no crypt4gh header at all.
pub const PROVENANCE_ABSENT_PLAINTEXT: &str = "plaintext";
/// `reason` label: a `.tar.c4gh` whose header would not yield a writer key. Anomalous.
pub const PROVENANCE_ABSENT_RECOVERY_FAILED: &str = "recovery_failed";

/// Packages whose crypt4gh writer key is not allow-listed for their channel under a
/// non-`off` `[ingest].writer_policy` (counter; `channel` label). Fires in both `warn`,
/// where the package is published anyway, and `enforce`, where it is quarantined, so it is
/// the discovery signal for building a per-channel allow-list. Pairs with the
/// `datasets --unverified` listing.
pub const INGEST_WRITER_UNKNOWN_TOTAL: &str = "gdi_ingest_writer_unknown_total";

/// Blocks a Beacon scan had to buffer and sort whole because several source VCFs
/// contributed overlapping `POS` spans to them, which a per-population split package
/// produces (counter, no labels).
///
/// The one query shape whose peak memory neither `granularity` nor `limit` bounds: splitting
/// the same rows across several files costs more than an order of magnitude more memory than
/// one file. It is a property of how the provider built the package rather than of the
/// request, so the node cannot fix it at query time and the operator has no other way to see
/// it. Unlabelled: a `dataset` label would key a public-query metric by data.
pub const BEACON_MERGED_BLOCKS_TOTAL: &str = "gdi_beacon_merged_blocks_total";

/// Unix seconds of a bucket's last successful S3 poll (gauge; label `channel`).
pub const S3_POLL_LAST_SUCCESS_TIMESTAMP_SECONDS: &str =
    "gdi_s3_poll_last_success_timestamp_seconds";
/// S3 poll errors per channel (counter; label `channel`).
pub const S3_POLL_ERRORS_TOTAL: &str = "gdi_s3_poll_errors_total";
/// Whether status writeback was disabled after an `AccessDenied` (gauge 0/1; label
/// `channel`).
pub const S3_STATUS_WRITEBACK_DISABLED: &str = "gdi_s3_status_writeback_disabled";
/// Bytes streamed per successful S3 package download (histogram). The network-fetch
/// leg runs before the ingest timer, so without this the fetch slice of RED is
/// invisible.
pub const S3_DOWNLOAD_BYTES: &str = "gdi_s3_download_bytes";
/// Wall-clock duration of a successful S3 package download (histogram, seconds).
pub const S3_DOWNLOAD_DURATION_SECONDS: &str = "gdi_s3_download_duration_seconds";
/// Count of S3 package download failures per bucket: the fetch leg after a successful
/// listing. Distinct from `gdi_s3_poll_errors_total`, the listing leg. A bucket that lists
/// fine but whose packages always fail to download would otherwise show healthy S3 and
/// advancing poll-success while datasets never appear.
pub const S3_DOWNLOAD_ERRORS_TOTAL: &str = "gdi_s3_download_errors_total";
/// Count of dataset metadata-overlay apply failures per `channel` and `reason`
/// (`fetch` | `parse` | `validate`, a bounded closed set). Each overlay failure keeps
/// last-good and only `warn!`s, so a persistently broken governance overlay silently
/// serves stale metadata; this makes it alertable.
///
/// Emitted from the inbox path as well as the S3 one, following the convention
/// [`INGEST_WRITER_UNKNOWN_TOTAL`] uses. From the S3 path alone, an inbox-only node, the
/// recommended default, would produce no series at all for a rejected overlay, and
/// `OverlayApplyFailing` could not fire there.
pub const OVERLAY_APPLY_FAILED_TOTAL: &str = "gdi_overlay_apply_failed_total";
/// Count of visibility sidecar (`{id}.state.json`) rejections per `channel` and `reason`
/// (`unreadable` | `unrecognized`, a bounded closed set).
///
/// The state-sidecar counterpart of [`OVERLAY_APPLY_FAILED_TOTAL`]. The metadata overlay
/// governs descriptive fields; the visibility sidecar governs disclosure, so a rejection
/// needs a metric an alert can fire on rather than a log line alone.
///
/// It matters because a rejected sidecar fails safe to `hidden` rather than keeping the last
/// state: the outcome is a live dataset dropping off the public plane because a write was
/// truncated, which is an availability event with no other machine-readable trace.
pub const STATE_SIDECAR_REJECTED_TOTAL: &str = "gdi_state_sidecar_rejected_total";
/// Count of times the S3 reconcile skipped its mass-eviction pass per bucket because the
/// listing collapsed to zero packages while the channel still owned datasets: a fail-safe
/// against a broken or hostile listing wiping served data. A non-zero value means served
/// datasets were retained despite an empty listing, so check the bucket and endpoint. It
/// does not mean anything was deleted.
pub const S3_REMOVAL_SKIPPED_TOTAL: &str = "gdi_s3_removal_skipped_total";

/// Count of `{id}.state.json` sidecars carrying `state: deleted` seen on an S3 bucket
/// (counter, per bucket). On S3, `deleted` is not a delete verb: deletion is removing the
/// `{id}.tar.c4gh` object, and a `deleted` sidecar is ignored while the dataset is kept
/// hidden. A non-zero value means an orchestrator used the inbox delete verb on an S3
/// channel and its intended deletion did not take effect, so the object should be removed
/// instead. It does not mean anything was deleted.
pub const S3_DELETED_SIDECAR_IGNORED_TOTAL: &str = "gdi_s3_deleted_sidecar_ignored_total";

/// Unix seconds of the last successful inbox scan (gauge).
pub const INBOX_SCAN_LAST_SUCCESS_TIMESTAMP_SECONDS: &str =
    "gdi_inbox_scan_last_success_timestamp_seconds";
/// Quarantine entries evicted by the `inbox/.rejected/` count cap (counter). A non-zero
/// value means a producer dropped more distinct bad packages than `rejected_max_count`
/// within the retention window.
pub const INBOX_QUARANTINE_EVICTED_TOTAL: &str = "gdi_inbox_quarantine_evicted_total";
/// Datasets that failed the last detached store-readability sweep (gauge). The startup
/// self-test samples a bounded subset and gates readiness only when all of them fail; this
/// gauge surfaces the full background sweep without gating serving.
pub const STORE_SCRUB_FAILED: &str = "gdi_store_scrub_failed";
/// Unix seconds the last full store-readability sweep completed (gauge).
pub const STORE_SCRUB_LAST_RUN_TIMESTAMP_SECONDS: &str =
    "gdi_store_scrub_last_run_timestamp_seconds";
/// Dataset stores by at-rest form (gauge), labelled
/// `form="plaintext"|"encrypted"|"indeterminate"`.
///
/// Emitted only when PME is configured (`[vault].transit_key`), mirroring `doctor`'s gate:
/// on a node that never enabled PME every store is plaintext, so the series would be a
/// permanent non-finding and any alert on it would fire forever. Under PME the interesting
/// states are covered: a half-migrated store reports `plaintext > 0` alongside
/// `encrypted > 0`, and the worse case — PME switched on, nothing re-ingested yet — reports
/// `plaintext > 0` with `encrypted == 0`. Enabling PME does not migrate existing datasets,
/// so without this the drift is invisible between manual `doctor` runs.
///
/// `indeterminate` is a dataset directory with no readable `allele-freq.*.parquet`. It is a
/// separate series rather than part of `encrypted`: deriving `encrypted` as
/// `total - plaintext` folds it in, so a deleted or truncated parquet would raise the
/// at-rest-encryption figure.
///
/// It carries its own `DatasetsIndeterminateAtRest` alert, because `gdi_store_scrub_failed`
/// does not say what failed. Timing is not the difference: an indeterminate store fails at
/// footer depth, since [`crate::scrub::scrub_dataset`] classifies `AtRestForm::Indeterminate`
/// before the `ScrubDepth::Footer` early return, and the readability tier runs footer depth
/// over every dataset on every pass, so such a store is quarantined by the first sweep after
/// it appears, inside the same `rescan_interval_seconds` window in which this tally is
/// recomputed. What this gauge adds is the form: `gdi_store_scrub_failed` counts datasets
/// failing verification for any reason, while this one says the at-rest form is unknown and
/// the data is not known to be encrypted, which is the finding a PME deployment must act
/// on.
pub const DATASETS_AT_REST: &str = "gdi_datasets_at_rest";
/// Inbox filesystem-watcher restarts (counter).
pub const INBOX_WATCHER_RESTARTS_TOTAL: &str = "gdi_inbox_watcher_restarts_total";
/// Background daemon-task panics caught and recovered (counter). A rising value means a
/// supervised loop — inbox watcher, periodic rescan, S3 monitor — panicked and was
/// restarted; the correlated warning names the task.
pub const BACKGROUND_TASK_PANICS_TOTAL: &str = "gdi_background_task_panics_total";
/// Permanently-rejected packages parked under `{inbox}/.rejected/` awaiting operator action
/// (gauge; inbox nodes only). The standing backlog, distinct from the
/// `gdi_ingest_total{outcome="permanent"}` rate, so a pile-up of stuck datasets is alertable
/// even after the failure events scrolled out of the counter window.
pub const INBOX_REJECTED_PACKAGES: &str = "gdi_inbox_rejected_packages";

/// Encrypted packages sitting in the inbox that this node holds no key for.
pub const INBOX_KEYLESS_PACKAGES: &str = "gdi_inbox_keyless_packages";

/// Vault token TTL (the lease) as of the last login or renew, in seconds (gauge; `0` for a
/// static, non-lease token). A step value that resets to the full lease on each renew, not a
/// live countdown of remaining seconds.
pub const VAULT_TOKEN_TTL_SECONDS: &str = "gdi_vault_token_ttl_seconds";
/// Vault token renewal failures (counter) — the `AppRole` renewal fails quietly.
///
/// A rising value is not by itself a fault. A renewable token cannot be renewed past its
/// `token_max_ttl`, so reaching that ceiling always produces one failed renewal followed by
/// a successful re-login, which is intended behaviour on a healthy node. Alerting on this
/// counter alone therefore pages roughly once per `token_max_ttl` for a node that is working
/// perfectly. Use [`VAULT_REAUTH_TOTAL`] `{outcome="failed"}` for the fault signal, and keep
/// this one for dashboards and correlation.
pub const VAULT_RENEWAL_FAILURES_TOTAL: &str = "gdi_vault_renewal_failures_total";
/// Outcome of the re-login the node falls back to when a token renewal fails (counter,
/// `outcome` ∈ `recovered` | `failed`).
///
/// This is the signal [`VAULT_RENEWAL_FAILURES_TOTAL`] cannot carry. A failed renewal has
/// two different meanings depending on what happens next:
///
/// * `recovered` — re-login succeeded. A routine `token_max_ttl` rollover: the node holds a
///   fresh token and never stopped working. Expected, periodic, not actionable.
/// * `failed` — re-login also failed. The credential is broken (a revoked `AppRole`, a wrong
///   `secret_id`, an unreachable Vault) and the node is running on borrowed time until its
///   current token lapses. Actionable, and what `VaultRenewalFailing` pages on.
///
/// Splitting them is what lets that alert keep `severity: critical` without crying wolf: an
/// alert that fires on routine operation is the one operators learn to silence.
pub const VAULT_REAUTH_TOTAL: &str = "gdi_vault_reauth_total";
/// Age of the `[vault].token_file` in seconds (gauge; `now - mtime`).
///
/// The freshness signal for the agent-sidecar shape. With `token_file` the node does not
/// renew — an external agent rewrites the file — so [`VAULT_RENEWAL_FAILURES_TOTAL`] can
/// never increment and [`VAULT_TOKEN_TTL_SECONDS`] stays `0`. A climbing age is the only
/// evidence that the agent has stopped refreshing. Absent unless `token_file` is
/// configured.
pub const VAULT_TOKEN_FILE_AGE_SECONDS: &str = "gdi_vault_token_file_age_seconds";
/// Successful reads of the `[vault].token_file` (counter): one at startup, plus one per
/// detected rotation.
pub const VAULT_TOKEN_FILE_RELOADS_TOTAL: &str = "gdi_vault_token_file_reloads_total";
/// Failed reads of the `[vault].token_file` (counter) — missing, unreadable, or empty.
/// Distinguishes "the agent wrote garbage" from "the agent stopped writing", which the
/// age gauge alone cannot.
pub const VAULT_TOKEN_FILE_READ_ERRORS_TOTAL: &str = "gdi_vault_token_file_read_errors_total";
/// Vault KV and Transit call latency during serving (histogram, seconds; label `operation` ∈
/// `kv_read|kv_write|transit_datakey|transit_decrypt`). The token lifecycle gauges miss
/// this: a Vault cluster slow to answer each PME key fetch or crypt4gh unwrap shows only as
/// an ingest or request slowdown, not as Vault latency.
pub const VAULT_CALL_DURATION_SECONDS: &str = "gdi_vault_call_duration_seconds";
/// Vault KV/Transit call failures during serving (counter; same `operation` label) —
/// distinguishes a Vault dependency fault from a data-path fault.
pub const VAULT_CALL_ERRORS_TOTAL: &str = "gdi_vault_call_errors_total";
/// The bounded, statically-known `operation` label set of [`VAULT_CALL_ERRORS_TOTAL`] and
/// the matching duration histogram. Enumerated so `seed_always_present` can seed every
/// operation to `0`, giving `increase()>0` alerts a baseline that fires on the first failure
/// of any operation. Kept in sync with the `operation` argument passed to
/// [`record_vault_call`] at the Vault client call sites.
#[cfg(feature = "vault")]
pub const VAULT_OPERATIONS: [&str; 4] =
    ["kv_read", "kv_write", "transit_datakey", "transit_decrypt"];

/// Set to `1` when the configured Transit master key can no longer unwrap a DEK this
/// node previously wrote (gauge; node-wide) — the key was replaced, or the secrets
/// backend was reset. Existing PME parquet at rest is undecryptable.
///
/// Distinct from [`KEYLESS_DEGRADED`], which is the crypt4gh identity, a different key, and
/// from [`VAULT_CALL_ERRORS_TOTAL`], since Vault here is reachable and answering. Latched for
/// the process lifetime, because the condition is a key incident an operator must resolve
/// rather than a transient; a transient check failure leaves this at `0`. Absent unless
/// `[vault].transit_key` is set.
pub const PME_MASTER_KEY_MISMATCH: &str = "gdi_pme_master_key_mismatch";

/// Set to `1` while the node runs in degraded keyless mode because `[vault]` was configured
/// but Vault was unreachable at startup (gauge; node-wide). In that state encrypted-package
/// ingest is skipped and `/health/ready` stays `503`. Latched for the process lifetime,
/// because identities load once at startup and the node does not self-heal; a restart with
/// Vault reachable clears it. `0` whenever key material loaded, and in the valid keyless or
/// no-Vault mode.
pub const KEYLESS_DEGRADED: &str = "gdi_keyless_degraded";

/// Per-subsystem readiness as a gauge (`1` ready, `0` not ready; label `component` ∈
/// `overall|initial_reconcile|s3|vault|at_rest|key_material`). Exposes `/health/ready` to
/// Prometheus, so an operator can alert on `gdi_health_ready{component="overall"} == 0`, or
/// drill into which subsystem, instead of scraping the probe JSON. A not-configured
/// subsystem reports ready (`1`) and never blocks readiness. Sampled.
pub const HEALTH_READY: &str = "gdi_health_ready";
/// The bounded `component` label values of [`HEALTH_READY`] (used for seeding).
pub const HEALTH_READY_COMPONENTS: [&str; 6] = [
    "overall",
    "initial_reconcile",
    "s3",
    "vault",
    // The at-rest (PME) master key. It gates readiness, so leaving it out would let a
    // master-key mismatch drive `overall` to 0 with no component series naming the
    // subsystem.
    "at_rest",
    "key_material",
];

/// Beacon requests (counter; labels `entry_type` ∈ `genomicVariant|dataset|individual` and
/// `status_class` ∈ `2xx|4xx|5xx`, and no query parameters).
pub const BEACON_REQUESTS_TOTAL: &str = "gdi_beacon_requests_total";
/// The bounded `entry_type` label set of the Beacon series (used for seeding).
pub const BEACON_ENTRY_TYPES: [&str; 3] = ["genomicVariant", "dataset", "individual"];
/// The bounded `code` label set of [`BEACON_QUERY_REJECTED_TOTAL`] (used for seeding).
/// [`record_beacon_query_rejected`] maps every status onto exactly these values, and
/// `beacon_rejection_codes_are_all_seeded` binds the two.
pub const BEACON_REJECT_CODES: [&str; 4] = ["400", "413", "500", "other"];
/// The two `status_class` cells seeded on the request counters: the class every healthy
/// request lands in, and the one the serving-error ratio alerts put in the numerator. A
/// fresh node then renders a flat zero for both instead of no series at all.
const SEEDED_STATUS_CLASSES: [&str; 2] = ["2xx", "5xx"];
/// The bounded `resource_type` label set of the FDP series (used for seeding).
pub const FAIRDP_RESOURCE_TYPES: [&str; 4] = ["root", "catalog", "dataset", "distribution"];
/// Beacon request duration (histogram, seconds; same content-free labels).
pub const BEACON_REQUEST_DURATION_SECONDS: &str = "gdi_beacon_request_duration_seconds";
/// Whole-node request rate, errors and duration, by plane (counter; labels `plane` ∈
/// `public|management` and `status_class` ∈ `1xx|2xx|3xx|4xx|5xx|other`). On the public plane
/// it complements the per-entry-type [`BEACON_REQUESTS_TOTAL`] by covering the routes that
/// one does not: the Beacon informational surface (`/service-info`, `/configuration`,
/// `/entry_types`, `/map`, `/info`, `/`) and `/.well-known/c4gh-recipient`. Emitted from the
/// public plane's `TraceLayer` `on_response` and the management plane's outermost
/// middleware, so it sees the final status of every completed request, including
/// resilience-layer rejections. Both planes are metered, so the probe and scrape traffic on
/// the management port is visible too.
pub const HTTP_REQUESTS_TOTAL: &str = "gdi_http_requests_total";
/// Whole-node request duration (histogram, seconds; label `plane` ∈ `public|management`).
pub const HTTP_REQUEST_DURATION_SECONDS: &str = "gdi_http_request_duration_seconds";
/// Answered beacon queries by semantic outcome (counter; labels `entry_type` ∈
/// `genomicVariant|dataset|individual`, `granularity` ∈ `boolean|count|record|n/a`, `exists`
/// ∈ `true|false`). The hit/miss and disclosure-level view the transport-level
/// [`BEACON_REQUESTS_TOTAL`] cannot give, since that sees only the HTTP status. Recorded at
/// the handler beside the audit line, so it covers exactly the queries that reached a
/// handler, and unlike the audit line it is independent of the `[audit]` toggle. The labels
/// are a bounded closed set: never query parameters or dataset ids.
pub const BEACON_QUERY_TOTAL: &str = "gdi_beacon_query_total";
/// Rejected or errored beacon queries by HTTP `code` (counter; labels `entry_type`, `code`
/// ∈ `400|413|500|other`). Surfaces the in-scan `500` rate and the malformed-client `400`
/// rate as distinct, page-able series, which the undifferentiated `status_class` bucket of
/// [`BEACON_REQUESTS_TOTAL`] cannot separate.
pub const BEACON_QUERY_REJECTED_TOTAL: &str = "gdi_beacon_query_rejected_total";
/// Beacon `g_variants` per-dataset parquet scans currently running on tokio's shared
/// `spawn_blocking` pool (gauge; sampled). The read-path counterpart of the bounded
/// [`INGEST_INFLIGHT`]: the query fan-out is not capped across concurrent requests, and a
/// scan detached by a request timeout keeps running because `spawn_blocking` is not
/// cancellable, so this can accumulate toward tokio's blocking-pool ceiling and starve
/// ingest, which shares the pool, while the async `/health` probes stay green. This gauge
/// makes that contention visible (see `IngestPoolStarvedByQueries`), and it is sampled by
/// the periodic task on a dedicated thread, so it still reports when the pool is saturated.
/// Reserving ingest headroom is out of scope here.
pub const BEACON_SCAN_BLOCKING_INFLIGHT: &str = "gdi_beacon_scan_blocking_inflight";

/// HTTP requests rejected by a resilience layer before, or instead of, reaching a handler
/// (counter; label `reason` ∈
/// `overloaded|timeout|body_too_large|uri_too_large|internal`). These are the load and
/// attack signals the per-entry-type [`BEACON_REQUESTS_TOTAL`] cannot see: a load-shed `503`
/// never reaches a route, and a request-timeout `408` cancels the handler future before the
/// per-route metric records it. `reason` is a bounded, content-free closed set: never a
/// path, query or client identity.
pub const HTTP_REQUESTS_REJECTED_TOTAL: &str = "gdi_http_requests_rejected_total";
/// `reason` label: concurrency-limit load-shed (`503`).
pub const REJECT_REASON_OVERLOADED: &str = "overloaded";
/// `reason` label: per-request timeout (`408`).
pub const REJECT_REASON_TIMEOUT: &str = "timeout";
/// `reason` label: request body exceeded the configured cap (`413`).
pub const REJECT_REASON_BODY_TOO_LARGE: &str = "body_too_large";
/// `reason` label: the request target, path plus query, exceeded the cap (`414`). The
/// GET-side mirror of `body_too_large`, since a body cap does not bound a long URI.
pub const REJECT_REASON_URI_TOO_LARGE: &str = "uri_too_large";
/// `reason` label: an internal `500` from a caught handler panic or an unexpected tower
/// layer error. These unwind past, or never reach, the per-entry-type request metric, and
/// `rejection_reason` maps `500` to `None`, so without an explicit count at the source they
/// would be metric-invisible and a panic-rate alert impossible.
pub const REJECT_REASON_INTERNAL: &str = "internal";

/// Public-plane HTTP requests currently being served (gauge). Paired with
/// [`HTTP_MAX_CONCURRENT_REQUESTS`] this is the serving-path saturation signal: it shows the
/// approach to the concurrency limit, whereas
/// [`HTTP_REQUESTS_REJECTED_TOTAL`]`{reason="overloaded"}` fires only after the limit is
/// hit. Held by an RAII [`InFlightGuard`], so it decrements even when a request future is
/// cancelled by a client disconnect.
pub const HTTP_IN_FLIGHT: &str = "gdi_http_inflight";
/// The configured public-plane concurrency limit (gauge; constant, set once at startup to
/// `max_concurrent_requests`). The capacity line for [`HTTP_IN_FLIGHT`]:
/// `gdi_http_inflight / gdi_http_max_concurrent_requests` is the utilization fraction an
/// operator right-sizes the limit against.
pub const HTTP_MAX_CONCURRENT_REQUESTS: &str = "gdi_http_max_concurrent_requests";

/// Connections dropped at accept because the plane's connection semaphore was full
/// (counter; label `plane` ∈ `public|management`).
///
/// This is the layer below every request-level signal. A dropped connection never becomes a
/// request, so [`HTTP_REQUESTS_REJECTED_TOTAL`] cannot see it, and the drop is not logged
/// per connection because a flood would amplify the log. Without this counter the cap is
/// unobservable on either plane.
///
/// It matters most on the management plane, where the semaphore sits below the health-probe
/// exemption `build_management_router` constructs: a leaking scraper or sidecar that
/// saturates the management port starves `/health/live` and `/health/ready` at accept, and
/// after `failureThreshold` the kubelet SIGKILLs a node that is serving public traffic
/// correctly — the eviction the split stack exists to prevent. `plane` is a bounded,
/// content-free closed set: never a peer address.
pub const HTTP_CONNECTIONS_REJECTED_TOTAL: &str = "gdi_http_connections_rejected_total";
/// `plane` label: the public serving listener (`service.listen`).
pub const PLANE_PUBLIC: &str = "public";
/// `plane` label: the management listener (`service.management_addr`).
pub const PLANE_MANAGEMENT: &str = "management";

/// FAIR Data Point requests (counter; labels `resource_type` ∈
/// `root|catalog|dataset|distribution` and `status_class` ∈ `2xx|4xx|5xx`). The FDP is the
/// other public serving plane, so it mirrors the beacon pattern rather than being a metrics
/// blind spot.
pub const FAIRDP_REQUESTS_TOTAL: &str = "gdi_fairdp_requests_total";
/// FAIR Data Point request duration (histogram, seconds; the same `resource_type` and
/// `status_class` labels).
pub const FAIRDP_REQUEST_DURATION_SECONDS: &str = "gdi_fairdp_request_duration_seconds";
/// FDP RDF serialization failures (counter): the empty-output branch of `render` that
/// returns a `500`. A dedicated series, so an internal serializer regression is page-able
/// rather than lost in the undifferentiated `status_class="5xx"` bucket.
pub const FAIRDP_SERIALIZATION_FAILURES_TOTAL: &str = "gdi_fairdp_serialization_failures_total";

/// crypt4gh / PME decrypt failures (counter).
pub const DECRYPT_FAILURES_TOTAL: &str = "gdi_decrypt_failures_total";

/// Dataset directories skipped on a cache reload because their `manifest.json` was present
/// but unreadable or corrupt (counter). Each is a published dataset dropping out of the
/// beacon, the FDP and the listing until it is fixed, a data-availability regression an
/// operator should be able to alert on. A missing manifest mid-ingest is benign and not
/// counted here.
pub const MANIFEST_RELOAD_SKIPPED_TOTAL: &str = "gdi_manifest_reload_skipped_total";

/// How often the periodic sampler refreshes the scrape-time gauges (dataset states,
/// disk-free, uptime). Far below any scrape interval, so a scrape reads fresh values without
/// the sampler being a load source.
const SAMPLE_INTERVAL: Duration = Duration::from_secs(10);

/// A handle to the installed Prometheus recorder, used by the `/metrics` route to
/// render the current text exposition. Cheaply cloneable (`PrometheusHandle` is an
/// `Arc` internally).
#[derive(Clone)]
pub struct MetricsHandle {
    handle: PrometheusHandle,
}

impl MetricsHandle {
    /// Render the current Prometheus text exposition (format `0.0.4`; the `/metrics`
    /// handler serves it as `text/plain; version=0.0.4`, not `OpenMetrics`).
    #[must_use]
    pub fn render(&self) -> String {
        self.handle.render()
    }

    /// Drain the histogram sample accumulators into their distributions, and expire idle
    /// series. `metrics-exporter-prometheus` folds recorded histogram samples into the
    /// rendered distribution only on a render — a `/metrics` scrape — or this upkeep; until
    /// then each observation is retained as a heap node in a lock-free `AtomicBucket`. A node
    /// serving traffic while nothing scrapes `/metrics` would otherwise grow that accumulator
    /// without bound. The periodic sampler calls this each tick, so memory stays bounded
    /// regardless of scrape cadence.
    pub fn run_upkeep(&self) {
        self.handle.run_upkeep();
    }
}

/// Fixed second and byte buckets per histogram: the one table both sinks bucket from, the
/// Prometheus recorder below and, with the `otel` feature, the OTLP mirror
/// (`metrics_otel`), so a quantile reads the same on `/metrics` and in an OTLP store. Order
/// is irrelevant, since each entry configures a distinct metric.
pub const HISTOGRAM_BUCKETS: &[(&str, &[f64])] = &[
    (
        INGEST_DURATION_SECONDS,
        &[0.1, 0.5, 1.0, 5.0, 15.0, 60.0, 300.0, 900.0],
    ),
    (
        BEACON_REQUEST_DURATION_SECONDS,
        &[0.00025, 0.001, 0.005, 0.025, 0.1, 0.5, 1.0, 5.0, 15.0],
    ),
    (
        FAIRDP_REQUEST_DURATION_SECONDS,
        &[0.00025, 0.001, 0.005, 0.025, 0.1, 0.5, 1.0, 5.0, 15.0],
    ),
    (
        HTTP_REQUEST_DURATION_SECONDS,
        &[0.00025, 0.001, 0.005, 0.025, 0.1, 0.5, 1.0, 5.0, 15.0],
    ),
    // Genomic packages are large and slow to fetch, so these bounds are much wider than the
    // request histograms: seconds to minutes, and megabytes to gigabytes.
    (
        S3_DOWNLOAD_DURATION_SECONDS,
        &[0.5, 2.0, 10.0, 30.0, 120.0, 300.0, 900.0, 1800.0],
    ),
    (
        S3_DOWNLOAD_BYTES,
        &[1e6, 1e7, 1e8, 5e8, 1e9, 5e9, 1e10, 5e10],
    ),
    // A Vault call is normally single-digit milliseconds, but a struggling Vault can take
    // seconds, so these bounds match the request histograms.
    (
        VAULT_CALL_DURATION_SECONDS,
        &[0.00025, 0.001, 0.005, 0.025, 0.1, 0.5, 1.0, 5.0],
    ),
];
// The two sub-millisecond bounds on the request-shaped tables above matter: a served
// request is well under a millisecond, so with a 5 ms floor every sample lands in the first
// bucket and `histogram_quantile` interpolates linearly inside `[0, 5 ms]`, giving a
// constant p50 and p99 that do not move with load until a request is genuinely slow. They
// cost two extra series per label set.

/// The OTLP mirror the recorder fans out to when the `otel` feature is compiled in and
/// `[service].otlp_metrics_interval_seconds` is set; `logging::TelemetryGuard::otel_mirror`
/// hands it over. Without the feature the type is uninhabited, so the only value a caller
/// can pass is `None`, and the call site reads the same in both builds.
#[cfg(feature = "otel")]
pub type OtelMirror = Arc<crate::metrics_otel::OtelRecorder>;
/// See the `otel` definition: uninhabited, so `Option<OtelMirror>` is always `None`.
#[cfg(not(feature = "otel"))]
pub type OtelMirror = std::convert::Infallible;

/// Install the global Prometheus recorder and describe + seed the curated series.
///
/// `metrics::set_global_recorder` can be called once per process, so this returns `None`,
/// logging a warning, if a recorder is already installed. The histograms get fixed second
/// buckets ([`HISTOGRAM_BUCKETS`]), so a scrape yields useful quantiles without the recorder
/// guessing.
///
/// With `mirror` set, every series is also driven into the OTLP mirror through a fan-out
/// recorder (`metrics_otel::Fanout`); `/metrics` renders exactly as without it.
///
/// Returns the [`MetricsHandle`] the `/metrics` route renders from, or `None` when
/// a recorder could not be installed.
#[must_use]
pub fn install_recorder(mirror: Option<OtelMirror>) -> Option<MetricsHandle> {
    // Applied in one pass, so a single bad bucket set disables metrics wholesale.
    let mut builder = PrometheusBuilder::new();
    for &(metric, buckets) in HISTOGRAM_BUCKETS {
        builder = match builder.set_buckets_for_metric(
            metrics_exporter_prometheus::Matcher::Full(metric.to_owned()),
            buckets,
        ) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "could not configure Prometheus histogram buckets; metrics disabled");
                return None;
            }
        };
    }

    let recorder = builder.build_recorder();
    let handle = recorder.handle();

    // `SetRecorderError<R>` carries the rejected recorder back, so the two arms would have
    // different error types; the message is all that is needed.
    let installed: Result<(), String> = match mirror {
        #[cfg(feature = "otel")]
        Some(otel) => {
            metrics::set_global_recorder(crate::metrics_otel::Fanout::new(recorder, otel))
                .map_err(|e| e.to_string())
        }
        #[cfg(not(feature = "otel"))]
        Some(never) => match never {},
        None => metrics::set_global_recorder(recorder).map_err(|e| e.to_string()),
    };
    if let Err(e) = installed {
        warn!(error = %e, "a metrics recorder is already installed; metrics disabled");
        return None;
    }

    describe_series();
    seed_always_present();
    Some(MetricsHandle { handle })
}

/// Seed the gauges and counters that should be visible from the first scrape even before
/// any event touches them. The Prometheus exporter renders a series only after it has been
/// emitted at least once, so an operator graphing `gdi_ingest_queue_depth` would otherwise
/// see a gap until the first job.
///
/// The rule behind every seed below: an alert of the form `> 0` or `increase(...) > 0` cannot
/// fire on a series that springs into existence at `1`, so an alert-backing series is seeded
/// to `0`. A unix-timestamp gauge is seeded to boot time instead, because `time() - 0` reads
/// as decades stale on every cold boot.
///
/// Only node-wide series with no dynamic label belong here; the per-label ones
/// (`{channel}`, `{state}`, `{entry_type}`) are seeded from config in
/// [`seed_s3_channel_series`] and [`seed_channel_series`], or appear as their labels are
/// first observed.
fn seed_always_present() {
    metrics::gauge!(INGEST_QUEUE_DEPTH).set(0.0);
    metrics::gauge!(INGEST_INFLIGHT).set(0.0);
    metrics::gauge!(INGEST_INFLIGHT_OLDEST_AGE_SECONDS).set(0.0);
    // Operator suppression overrides: both mode series and the degraded-load gauge, so an
    // operator can confirm the feature is wired on a node with nothing suppressed.
    for mode in [SuppressMode::Hide, SuppressMode::Remove] {
        metrics::gauge!(DATASETS_SUPPRESSED, "mode" => mode.as_str()).set(0.0);
    }
    metrics::gauge!(SUPPRESSION_LOAD_DEGRADED).set(0.0);
    // The health companion of a gauge whose source can fail, so `LowDisk` has a baseline.
    metrics::gauge!(DISK_SAMPLE_FAILED).set(0.0);
    // A node whose override store is intact publishes the baseline `OverrideStoreAbsent`
    // keys on: a missing series and a healthy one are indistinguishable to an alert.
    metrics::gauge!(OVERRIDE_STORE_ABSENT).set(0.0);
    // `ConfigReloadFailed` keys on `increase()>0`.
    metrics::counter!(CONFIG_RELOAD_FAILED_TOTAL).increment(0);
    metrics::gauge!(INGEST_TRANSIENT_BACKOFF).set(0.0);
    metrics::gauge!(BEACON_SCAN_BLOCKING_INFLIGHT).set(0.0);
    // Boot time, not epoch 0: `time() - last_progress` must read ~0 on a freshly-booted
    // node. The gauge is stamped again at each job pickup and completion, so it tracks the
    // time of the last ingest activity.
    metrics::gauge!(INGEST_LAST_PROGRESS_TIMESTAMP_SECONDS).set(unix_now_seconds());
    metrics::counter!(DECRYPT_FAILURES_TOTAL).increment(0);
    metrics::counter!(FAIRDP_SERIALIZATION_FAILURES_TOTAL).increment(0);
    metrics::counter!(MANIFEST_RELOAD_SKIPPED_TOTAL).increment(0);
    metrics::counter!(INBOX_QUARANTINE_EVICTED_TOTAL).increment(0);
    // Both provenance-absent reasons; `recovery_failed` is the one
    // `ProvenanceRecoveryFailed` keys on.
    for reason in [
        PROVENANCE_ABSENT_PLAINTEXT,
        PROVENANCE_ABSENT_RECOVERY_FAILED,
    ] {
        metrics::counter!(INGEST_PROVENANCE_ABSENT_TOTAL, "reason" => reason).increment(0);
    }
    // Sibling inbox-only counter, behind `InboxWatcherFlapping`.
    metrics::counter!(INBOX_WATCHER_RESTARTS_TOTAL).increment(0);
    // A background-task panic is rare and alert-worthy (`BackgroundPanics`).
    metrics::counter!(BACKGROUND_TASK_PANICS_TOTAL).increment(0);
    metrics::gauge!(STORE_SCRUB_FAILED).set(0.0);
    // The completion-time sibling, seeded to process start. Unseeded, the series would not
    // exist until the first sweep finished, and a node whose sweep never completed would look
    // like one whose sweep is healthy. Boot time makes "never completed" visibly stale after
    // one sweep interval, exactly as a sweep that stopped completing does.
    metrics::gauge!(STORE_SCRUB_LAST_RUN_TIMESTAMP_SECONDS).set(unix_now_seconds());
    // Node-wide degraded-mode latch. The boot path flips it to 1 right after install when
    // the node booted keyless-degraded.
    metrics::gauge!(KEYLESS_DEGRADED).set(0.0);
    // The rejection reasons are a bounded, node-wide closed set, so seed every one.
    // `internal`, the panic and 500 reason, is the most alert-worthy of them.
    for reason in [
        REJECT_REASON_OVERLOADED,
        REJECT_REASON_TIMEOUT,
        REJECT_REASON_BODY_TOO_LARGE,
        REJECT_REASON_URI_TOO_LARGE,
        REJECT_REASON_INTERNAL,
    ] {
        metrics::counter!(HTTP_REQUESTS_REJECTED_TOTAL, "reason" => reason).increment(0);
    }
    // The serving-path saturation gauge is node-wide.
    metrics::gauge!(HTTP_IN_FLIGHT).set(0.0);
    // Both planes exist for the whole process life, so both get a baseline.
    for plane in [PLANE_PUBLIC, PLANE_MANAGEMENT] {
        metrics::counter!(HTTP_CONNECTIONS_REJECTED_TOTAL, "plane" => plane).increment(0);
    }
    // Readiness is node-wide with a bounded `component` set. `0` means not ready; the
    // sampler flips each to its real value within one sample interval.
    for component in HEALTH_READY_COMPONENTS {
        metrics::gauge!(HEALTH_READY, "component" => component).set(0.0);
    }
    // Ingest outcomes are a bounded closed set; seed the ones `IngestTimeout` and
    // `IngestRetryChurn` key on. `permanent` carries an extra `error_class` label, covered by
    // the dataset-state alerts, and `refused_pool_pressure` is graph-only, so neither is
    // seeded here.
    for outcome in ["success", "transient", "timeout"] {
        metrics::counter!(INGEST_TOTAL, "outcome" => outcome).increment(0);
    }
    // Beacon serving-plane baselines: the `2xx` and `5xx` cells of the request counter per
    // entry type, every rejection cell (entry type by code), and the label-free split-block
    // counter. A node nobody has queried then renders a flat zero on the serving panels.
    for entry_type in BEACON_ENTRY_TYPES {
        for class in SEEDED_STATUS_CLASSES {
            metrics::counter!(
                BEACON_REQUESTS_TOTAL,
                "entry_type" => entry_type,
                "status_class" => class,
            )
            .increment(0);
        }
        for code in BEACON_REJECT_CODES {
            metrics::counter!(
                BEACON_QUERY_REJECTED_TOTAL,
                "entry_type" => entry_type,
                "code" => code,
            )
            .increment(0);
        }
    }
    metrics::counter!(BEACON_MERGED_BLOCKS_TOTAL).increment(0);
    // Vault series exist only in a `vault` build: the renewal-failure counter and every
    // `operation` of the call-error counter.
    #[cfg(feature = "vault")]
    {
        metrics::counter!(VAULT_RENEWAL_FAILURES_TOTAL).increment(0);
        // Both re-auth outcomes, not only `failed`: `recovered` needs a baseline so a
        // dashboard shows the routine max-TTL rollovers as a flat line rather than nothing.
        for outcome in VAULT_REAUTH_OUTCOMES {
            metrics::counter!(VAULT_REAUTH_TOTAL, "outcome" => outcome).increment(0);
        }
        // Behind `VaultTokenFileUnreadable`.
        metrics::counter!(VAULT_TOKEN_FILE_READ_ERRORS_TOTAL).increment(0);
        for operation in VAULT_OPERATIONS {
            metrics::counter!(VAULT_CALL_ERRORS_TOTAL, "operation" => operation).increment(0);
        }
    }
}

/// HELP text for the S3 bucket-monitor series (poll, download, overlay). Split out of
/// [`describe_series`] to keep each function's line count within the lint bound.
fn describe_s3_series() {
    use metrics::{Unit, describe_counter, describe_gauge, describe_histogram};

    describe_gauge!(
        S3_POLL_LAST_SUCCESS_TIMESTAMP_SECONDS,
        Unit::Seconds,
        "Unix time of a bucket's last successful poll"
    );
    describe_counter!(S3_POLL_ERRORS_TOTAL, "S3 poll errors per bucket");
    describe_counter!(
        S3_DOWNLOAD_ERRORS_TOTAL,
        "S3 package download failures per bucket (fetch leg, after a successful listing)"
    );
    describe_counter!(
        OVERLAY_APPLY_FAILED_TOTAL,
        "Dataset metadata-overlay apply failures per channel and reason (fetch|parse|validate)"
    );
    describe_counter!(
        STATE_SIDECAR_REJECTED_TOTAL,
        "Visibility sidecar rejections per channel and reason (unreadable|unrecognized)"
    );
    describe_counter!(
        S3_REMOVAL_SKIPPED_TOTAL,
        "S3 reconcile Removed-pass skips per bucket (collapsed listing; served data retained)"
    );
    describe_counter!(
        S3_DELETED_SIDECAR_IGNORED_TOTAL,
        "`deleted` .state.json sidecars ignored on an S3 bucket per bucket (delete on S3 = remove the object)"
    );
    describe_gauge!(
        S3_STATUS_WRITEBACK_DISABLED,
        "Whether status writeback was disabled for a bucket (1) or not (0)"
    );
    describe_histogram!(
        S3_DOWNLOAD_BYTES,
        Unit::Bytes,
        "Bytes streamed per successful S3 package download"
    );
    describe_histogram!(
        S3_DOWNLOAD_DURATION_SECONDS,
        Unit::Seconds,
        "Wall-clock duration of a successful S3 package download"
    );
}

/// Register the human-readable HELP text for the curated series, in one place; the hook
/// points only emit values. A counter, gauge or histogram whose label set is dynamic is
/// described by base name.
fn describe_series() {
    use metrics::{Unit, describe_counter, describe_gauge, describe_histogram};

    describe_gauge!(UPTIME_SECONDS, Unit::Seconds, "Process uptime in seconds");
    describe_gauge!(
        BUILD_INFO,
        "Build version info (constant 1 carrying version + git_sha labels)"
    );
    describe_gauge!(DATASET_STATE, "Number of datasets in each state");
    describe_gauge!(
        DISK_FREE_BYTES,
        Unit::Bytes,
        "Free bytes on the data volume"
    );
    describe_gauge!(
        DISK_SAMPLE_FAILED,
        "1 when the last statvfs of the data volume failed (gdi_disk_free_bytes is then stale), 0 when it succeeded"
    );
    describe_process_series();
    describe_gauge!(INGEST_QUEUE_DEPTH, "Ingest jobs queued, not yet picked up");
    describe_gauge!(INGEST_INFLIGHT, "Ingest jobs currently being processed");
    describe_gauge!(
        INGEST_INFLIGHT_OLDEST_AGE_SECONDS,
        "Seconds the oldest in-flight ingest (queued or processing) has been held; 0 when none"
    );
    describe_gauge!(
        INGEST_TRANSIENT_BACKOFF,
        "Distinct sources currently in a transient-failure backoff window"
    );
    describe_gauge!(
        BEACON_SCAN_BLOCKING_INFLIGHT,
        "Beacon g_variants parquet scans currently running on the shared blocking pool"
    );
    describe_gauge!(
        INGEST_CONCURRENCY,
        "Configured ingest worker capacity (ingest_concurrency)"
    );
    describe_gauge!(
        QUERY_CONCURRENCY,
        "Configured Beacon query scan fan-out capacity (query_concurrency, else ingest_concurrency)"
    );
    describe_gauge!(
        INGEST_LAST_PROGRESS_TIMESTAMP_SECONDS,
        Unit::Seconds,
        "Unix time of the last ingest progress event"
    );
    describe_counter!(INGEST_TOTAL, "Ingest outcomes by outcome class");
    describe_histogram!(
        INGEST_DURATION_SECONDS,
        Unit::Seconds,
        "Ingest wall-clock duration"
    );
    describe_s3_series();
    describe_gauge!(
        INBOX_SCAN_LAST_SUCCESS_TIMESTAMP_SECONDS,
        Unit::Seconds,
        "Unix time of the last successful inbox scan"
    );
    describe_counter!(
        INBOX_WATCHER_RESTARTS_TOTAL,
        "Inbox filesystem-watcher restarts"
    );
    describe_counter!(
        INBOX_QUARANTINE_EVICTED_TOTAL,
        "Quarantine entries evicted by the inbox/.rejected count cap"
    );
    describe_counter!(
        INGEST_PROVENANCE_ABSENT_TOTAL,
        "Published packages carrying no recoverable crypt4gh writer key, by reason"
    );
    describe_counter!(
        INGEST_WRITER_UNKNOWN_TOTAL,
        "Packages whose writer key is not allow-listed for their channel, by channel"
    );
    describe_gauge!(
        STORE_SCRUB_FAILED,
        "Datasets that failed the last detached store-readability sweep"
    );
    describe_gauge!(
        STORE_SCRUB_LAST_RUN_TIMESTAMP_SECONDS,
        Unit::Seconds,
        "Unix time the last full store-readability sweep completed"
    );
    describe_gauge!(
        DATASETS_AT_REST,
        "Dataset stores by at-rest form (plaintext PAR1 vs PME-encrypted PARE); PME builds only"
    );
    describe_counter!(
        BACKGROUND_TASK_PANICS_TOTAL,
        "Background daemon-task panics caught + restarted"
    );
    describe_counter!(
        BEACON_MERGED_BLOCKS_TOTAL,
        "Blocks a Beacon scan buffered whole (per-population split package)"
    );
    describe_inbox_series();
    describe_vault_series();
    describe_serving_plane_series();
    describe_suppression_series();
}

/// The `/proc/self` process gauges. Split out of [`describe_series`] to keep each function
/// under the line cap, and called once from it.
fn describe_process_series() {
    use metrics::{Unit, describe_gauge};

    describe_gauge!(
        PROCESS_RESIDENT_MEMORY_BYTES,
        Unit::Bytes,
        "Process resident set size (RSS)"
    );
    describe_gauge!(PROCESS_OPEN_FDS, "Process open file descriptors");
    describe_gauge!(PROCESS_THREADS, "Process thread count");
    describe_gauge!(
        PROCESS_CPU_SECONDS,
        Unit::Seconds,
        "Cumulative process CPU time (user + system) in fractional seconds; monotonic within a process life, so rate() it"
    );
}

/// The inbox backlog gauges. Split out of [`describe_series`] to keep each function under
/// the line cap, and called once from it.
fn describe_inbox_series() {
    use metrics::describe_gauge;

    describe_gauge!(
        INBOX_REJECTED_PACKAGES,
        "Permanently-rejected packages parked in the inbox .rejected quarantine"
    );
    describe_gauge!(
        INBOX_KEYLESS_PACKAGES,
        "Encrypted inbox packages this node holds no crypt4gh identity for"
    );
}

/// Register the HELP text for the override and reload series: dataset suppression, channel
/// suppression, and `SIGHUP` config reload. Split out of [`describe_series`] to keep each
/// function under the line cap, and called once from it.
fn describe_suppression_series() {
    use metrics::{describe_counter, describe_gauge};

    describe_gauge!(
        DATASETS_SUPPRESSED,
        "Dataset count by operator-suppression override mode (hide|remove)"
    );
    describe_gauge!(
        SUPPRESSION_LOAD_DEGRADED,
        "Suppression-override files that failed to parse on the last load and were fail-closed to hide"
    );
    describe_gauge!(
        OVERRIDE_STORE_ABSENT,
        "Whether the operator-override store root is absent while require_override_store is set"
    );
    describe_gauge!(
        CHANNEL_SUPPRESSED,
        "Whether a channel (bucket or inbox) is under an active operator channel-suppression override"
    );
    describe_gauge!(
        S3_CHANNEL_ORPHANED,
        "Whether a channel still owns datasets but is no longer declared in [[s3.buckets]]: withheld from boot, nothing polls it"
    );
    describe_gauge!(
        CATALOG_ORPHANED,
        "Whether visible datasets still declare a [catalogs] entry that has been removed; they stay served but are unreachable by crawling the FDP"
    );
    describe_gauge!(
        S3_KEYSPACE_MISMATCH,
        "Whether a bucket channel's removal processing is refused because its configured keyspace is not the one its datasets were ingested from"
    );
    describe_counter!(
        CONFIG_RELOAD_FAILED_TOTAL,
        "SIGHUP config-reload attempts that failed validation and kept the running config"
    );
}

/// Register the HELP text for the Vault and secret-plane series. Split out of
/// [`describe_series`] to keep each function under the line cap, and called once from it.
fn describe_vault_series() {
    use metrics::{Unit, describe_counter, describe_gauge};

    describe_gauge!(
        VAULT_TOKEN_TTL_SECONDS,
        Unit::Seconds,
        "Vault token TTL (lease) at last login/renew in seconds; resets on renew, not a live countdown"
    );
    describe_counter!(VAULT_RENEWAL_FAILURES_TOTAL, "Vault token renewal failures");
    describe_counter!(
        VAULT_REAUTH_TOTAL,
        "Re-login outcome after a failed Vault token renewal (recovered|failed)"
    );
    describe_gauge!(
        VAULT_TOKEN_FILE_AGE_SECONDS,
        Unit::Seconds,
        "Age of [vault].token_file; the freshness signal when an external agent owns renewal"
    );
    describe_counter!(
        VAULT_TOKEN_FILE_RELOADS_TOTAL,
        "Successful [vault].token_file reads (startup + each detected rotation)"
    );
    describe_counter!(
        VAULT_TOKEN_FILE_READ_ERRORS_TOTAL,
        "Failed [vault].token_file reads (missing, unreadable, or empty)"
    );
    describe_gauge!(
        PME_MASTER_KEY_MISMATCH,
        "1 when the at-rest Transit master key cannot decrypt this node's data (replaced key or reset backend); latched until restart"
    );
    describe_gauge!(
        KEYLESS_DEGRADED,
        "1 while the node runs keyless-degraded (Vault configured but unreachable at startup); latched until restart"
    );
}

/// Register the HELP text for the public serving-plane series: beacon, HTTP resilience, FDP
/// and decrypt. Split out of [`describe_series`] to keep each function under the line cap,
/// and called once from it.
fn describe_serving_plane_series() {
    use metrics::{Unit, describe_counter, describe_gauge, describe_histogram};

    describe_counter!(
        BEACON_REQUESTS_TOTAL,
        "Beacon requests by entry type and status class"
    );
    describe_histogram!(
        BEACON_REQUEST_DURATION_SECONDS,
        Unit::Seconds,
        "Beacon request duration"
    );
    describe_counter!(
        HTTP_REQUESTS_TOTAL,
        "All completed requests by plane (public|management) and status class (covers informational + well-known routes)"
    );
    describe_histogram!(
        HTTP_REQUEST_DURATION_SECONDS,
        Unit::Seconds,
        "Request duration by plane (public|management)"
    );
    describe_counter!(
        BEACON_QUERY_TOTAL,
        "Answered beacon queries by entry type, granularity, and hit/miss (exists)"
    );
    describe_counter!(
        BEACON_QUERY_REJECTED_TOTAL,
        "Rejected/errored beacon queries by entry type and HTTP code"
    );
    describe_counter!(
        HTTP_REQUESTS_REJECTED_TOTAL,
        "HTTP requests rejected by a resilience layer (load-shed/timeout/body-cap), by reason"
    );
    describe_gauge!(
        HTTP_IN_FLIGHT,
        "Public-plane HTTP requests currently in flight"
    );
    describe_gauge!(
        HTTP_MAX_CONCURRENT_REQUESTS,
        "Configured public-plane concurrency limit (max_concurrent_requests)"
    );
    describe_counter!(
        HTTP_CONNECTIONS_REJECTED_TOTAL,
        "Connections dropped at accept because the plane's connection cap was full, by plane"
    );
    describe_counter!(
        FAIRDP_REQUESTS_TOTAL,
        "FAIR Data Point requests by resource type and status class"
    );
    describe_histogram!(
        FAIRDP_REQUEST_DURATION_SECONDS,
        Unit::Seconds,
        "FAIR Data Point request duration by resource type"
    );
    describe_counter!(
        FAIRDP_SERIALIZATION_FAILURES_TOTAL,
        "FDP RDF serialization failures (empty-output 500s)"
    );
    describe_counter!(DECRYPT_FAILURES_TOTAL, "crypt4gh / PME decrypt failures");
    describe_counter!(
        MANIFEST_RELOAD_SKIPPED_TOTAL,
        "Datasets skipped on reload due to an unreadable/corrupt manifest.json"
    );
    describe_gauge!(
        HEALTH_READY,
        "Per-subsystem readiness (1 ready / 0 not), by component"
    );
    describe_histogram!(
        VAULT_CALL_DURATION_SECONDS,
        Unit::Seconds,
        "Vault KV/Transit call latency, by operation"
    );
    describe_counter!(
        VAULT_CALL_ERRORS_TOTAL,
        "Vault KV/Transit call failures, by operation"
    );
}

/// Count a published package that carried no recoverable crypt4gh writer key.
///
/// `reason` must be one of the closed-class label constants
/// ([`PROVENANCE_ABSENT_PLAINTEXT`], [`PROVENANCE_ABSENT_RECOVERY_FAILED`]); `&'static str`
/// keeps the label cardinality bounded by construction. Not labelled by fingerprint, which
/// would be unbounded cardinality.
pub fn ingest_provenance_absent(reason: &'static str) {
    metrics::counter!(INGEST_PROVENANCE_ABSENT_TOTAL, "reason" => reason).increment(1);
}

/// Count a package whose writer key is not allow-listed for `channel` (warn or enforce).
pub fn ingest_writer_unknown(channel: &str) {
    metrics::counter!(INGEST_WRITER_UNKNOWN_TOTAL, "channel" => channel.to_owned()).increment(1);
}

/// Count one block a Beacon scan had to buffer and sort whole.
///
/// `files` is how many source files contributed to it. It is not a label, because an
/// unbounded per-package value would key cardinality on provider data, so it travels in the
/// log beside the increment rather than in Prometheus.
pub fn beacon_merged_block(files: usize) {
    metrics::counter!(BEACON_MERGED_BLOCKS_TOTAL).increment(1);
    tracing::debug!(
        files,
        "block buffered whole: several source files cover the same positions"
    );
}

/// Record the build-version info series once: a constant `1` carrying `version` and
/// `git_sha` labels. Content-free, since both are compile-time constants — the crate version
/// and the injected commit, `unknown` for a plain build — rather than request data, so a
/// release tag and a from-source build of the same crate version are distinguishable at
/// runtime.
pub fn record_build_info() {
    metrics::gauge!(
        BUILD_INFO,
        "version" => env!("CARGO_PKG_VERSION"),
        "git_sha" => gdi_build_info::GIT_SHA,
    )
    .set(1.0);
}

// ---- Hook-point helpers (one place per series; call sites stay one line) ----

/// Count one inbox-watcher restart / failure (a flaky or dead watcher signal).
pub fn inbox_watcher_restart() {
    metrics::counter!(INBOX_WATCHER_RESTARTS_TOTAL).increment(1);
}

/// Count one caught and recovered background daemon-task panic. Label-free: the task name
/// and cause are in the correlated warning.
pub fn background_task_panic() {
    metrics::counter!(BACKGROUND_TASK_PANICS_TOTAL).increment(1);
}

/// Count one quarantine entry evicted by the `inbox/.rejected/` count cap
/// (`gdi_inbox_quarantine_evicted_total`).
pub fn inbox_quarantine_evicted() {
    metrics::counter!(INBOX_QUARANTINE_EVICTED_TOTAL).increment(1);
}

/// Record a completed full store-readability sweep: how many datasets `failed`
/// (`gdi_store_scrub_failed`) and the completion time
/// (`gdi_store_scrub_last_run_timestamp_seconds`).
#[expect(
    clippy::cast_precision_loss,
    reason = "dataset counts are far below f64's exact-integer range"
)]
pub fn record_store_scrub(failed: usize) {
    metrics::gauge!(STORE_SCRUB_FAILED).set(failed as f64);
    metrics::gauge!(STORE_SCRUB_LAST_RUN_TIMESTAMP_SECONDS).set(unix_now_seconds());
}

/// Record the at-rest composition of the store (`gdi_datasets_at_rest{form}`).
///
/// All three label values are always set, so each exists as a `0` series from the first
/// scrape rather than appearing only once a dataset lands in it; an absent series and a zero
/// one are otherwise indistinguishable to an alert. Call only when PME is configured; see
/// [`DATASETS_AT_REST`] for why the series is absent on a non-PME node.
///
/// `encrypted` is counted, never derived as `total - plaintext`. That subtraction folds
/// every store with no readable parquet into the encrypted bucket, so a deleted or truncated
/// dataset would raise the at-rest-encryption number instead of lowering it. `indeterminate`
/// is that third bucket, and it needs no alert of its own: the scrub sweep quarantines such
/// a dataset and `gdi_store_scrub_failed` fires for it.
///
/// `f64::from` rather than `as`: a `u32` converts losslessly, so no precision waiver is
/// needed.
pub fn record_at_rest(plaintext: u32, encrypted: u32, indeterminate: u32) {
    metrics::gauge!(DATASETS_AT_REST, "form" => "plaintext").set(f64::from(plaintext));
    metrics::gauge!(DATASETS_AT_REST, "form" => "encrypted").set(f64::from(encrypted));
    metrics::gauge!(DATASETS_AT_REST, "form" => "indeterminate").set(f64::from(indeterminate));
}

/// Record a channel's successful poll (`gdi_s3_poll_last_success_timestamp_seconds{channel}`).
/// `channel` is the operator-configured logical name, not user data.
pub fn s3_poll_success(channel: &str) {
    metrics::gauge!(S3_POLL_LAST_SUCCESS_TIMESTAMP_SECONDS, "channel" => channel.to_owned())
        .set(unix_now_seconds());
}

/// Count one channel poll error (`gdi_s3_poll_errors_total{channel}`).
pub fn s3_poll_error(channel: &str) {
    metrics::counter!(S3_POLL_ERRORS_TOTAL, "channel" => channel.to_owned()).increment(1);
}

/// Count one S3 package download failure (`gdi_s3_download_errors_total{channel}`), the
/// fetch leg after a successful listing. `channel` is the operator-configured logical name,
/// not user data.
pub fn s3_download_error(channel: &str) {
    metrics::counter!(S3_DOWNLOAD_ERRORS_TOTAL, "channel" => channel.to_owned()).increment(1);
}

/// Seed every per-channel error counter to `0` for the configured S3 channels.
///
/// `seed_always_present` states the seeding rule; the `{channel}` label set is known only
/// from config, which is why these are seeded here instead. The four `increase()>0` bucket
/// alerts — `S3PollErrors`, `S3DownloadErrors`, `OverlayApplyFailing`, `MassRemovalSkipped` —
/// need the baseline. `channel` values are operator-configured logical names, not user data,
/// so cardinality is bounded by the config.
///
/// [`S3_POLL_LAST_SUCCESS_TIMESTAMP_SECONDS`] is seeded to boot time rather than `0`.
/// `S3PollerWedged` is a `time() - <gauge>` staleness expression, so it evaluates to no data
/// for a bucket whose endpoint is dead from boot, the one bucket it exists to catch, while a
/// `0` seed would make it fire on every cold boot. The staleness clock therefore starts at
/// boot and only runs if no poll ever succeeds, as
/// `INGEST_LAST_PROGRESS_TIMESTAMP_SECONDS` does.
pub fn seed_s3_channel_series(channel_names: &[&str]) {
    for channel in channel_names {
        metrics::gauge!(S3_POLL_LAST_SUCCESS_TIMESTAMP_SECONDS, "channel" => (*channel).to_owned())
            .set(unix_now_seconds());
        metrics::counter!(S3_POLL_ERRORS_TOTAL, "channel" => (*channel).to_owned()).increment(0);
        metrics::counter!(S3_DOWNLOAD_ERRORS_TOTAL, "channel" => (*channel).to_owned())
            .increment(0);
        metrics::counter!(S3_REMOVAL_SKIPPED_TOTAL, "channel" => (*channel).to_owned())
            .increment(0);
        // Seeded like its three siblings above.
        metrics::counter!(S3_DELETED_SIDECAR_IGNORED_TOTAL, "channel" => (*channel).to_owned())
            .increment(0);
        // The writeback latch is a 0/1 gauge over the same `{channel}` label set. Only the
        // first `AccessDenied` sets it, so without a baseline a panel or a `== 1` rule over a
        // healthy channel shows the same nothing as one over a channel whose writeback died.
        metrics::gauge!(S3_STATUS_WRITEBACK_DISABLED, "channel" => (*channel).to_owned()).set(0.0);
    }
}

/// Seed [`CHANNEL_SUPPRESSED`] to `0` for every configured channel: bucket names, plus
/// `inbox` when configured.
///
/// Same reason as [`seed_s3_channel_series`]: the `{channel}` label set comes from config.
/// Called from the boot path beside `seed_s3_channel_series` and, for a bucket a config
/// reload adds, from the reload's add arm, so a live-added channel gets the same baseline a
/// boot-time one does. The plain `> 0` threshold this gauge uses cannot tolerate a series
/// that appears only with the first suppression, and a seeded `0` lets an operator confirm
/// the feature is wired on a node with nothing suppressed.
pub fn seed_channel_series(channel_names: &[&str]) {
    for channel in channel_names {
        metrics::gauge!(CHANNEL_SUPPRESSED, "channel" => (*channel).to_owned()).set(0.0);
        // Same `{channel}` label set, same reason: `WriterKeyNotAllowed` keys on
        // `increase(gdi_ingest_writer_unknown_total[..]) > 0`, so on a node where exactly one
        // un-allow-listed package is ever dropped the alert needs this baseline to fire.
        metrics::counter!(INGEST_WRITER_UNKNOWN_TOTAL, "channel" => (*channel).to_owned())
            .increment(0);
        // Same reasoning, and the same `> 0` alert shape. Seeded for every channel for
        // label-set uniformity; only bucket channels ever set it to 1, since `inbox` has no
        // keyspace to mismatch.
        metrics::gauge!(S3_KEYSPACE_MISMATCH, "channel" => (*channel).to_owned()).set(0.0);
        // Seeded per channel rather than per bucket, inbox included: `OverlayApplyFailing`
        // uses `increase(...) > 0` and cannot fire for a never-seeded channel.
        for reason in OVERLAY_APPLY_REASONS {
            metrics::counter!(
                OVERLAY_APPLY_FAILED_TOTAL,
                "channel" => (*channel).to_owned(),
                "reason" => reason,
            )
            .increment(0);
        }
        // Same shape, same alert form, same seeding requirement.
        for reason in StateSidecarRejectReason::ALL {
            metrics::counter!(
                STATE_SIDECAR_REJECTED_TOTAL,
                "channel" => (*channel).to_owned(),
                "reason" => reason.as_str(),
            )
            .increment(0);
        }
    }
    // The node-local override feed is always present, so it is seeded here rather than
    // passed in with the configured channels. Only the overlay counter: it is not an ingest
    // channel, so the suppression, writer-policy and keyspace series above would be
    // meaningless for it, and a seeded-but-impossible series is misleading.
    for reason in OVERLAY_APPLY_REASONS {
        metrics::counter!(
            OVERLAY_APPLY_FAILED_TOTAL,
            "channel" => LOCAL_OVERRIDE_CHANNEL,
            "reason" => reason,
        )
        .increment(0);
    }
}

/// Seed [`INBOX_SCAN_LAST_SUCCESS_TIMESTAMP_SECONDS`] to process start, only when an inbox
/// is configured.
///
/// Mirrors [`STORE_SCRUB_LAST_RUN_TIMESTAMP_SECONDS`]'s seeding. `InboxScanWedged` is
/// `time() - gdi_inbox_scan_last_success_timestamp_seconds > …`, which cannot fire on an
/// absent series, and only a successful scan writes the gauge — so an inbox unreadable from
/// boot (the wrong mode after a volume remount, a vanished mount, a mistyped path) is the
/// wedged-from-birth case the alert could not see. Boot time rather than 0, for the reason
/// given at the scrub gauge.
///
/// Conditional on `[service].inbox` being set: seeding it unconditionally would make
/// `InboxScanWedged` fire on every node that has no inbox.
pub fn seed_inbox_series() {
    metrics::gauge!(INBOX_SCAN_LAST_SUCCESS_TIMESTAMP_SECONDS).set(unix_now_seconds());
}

/// Seed the `2xx` and `5xx` cells of [`FAIRDP_REQUESTS_TOTAL`] for every resource type, only
/// when `[fairdp]` is configured, mirroring [`seed_inbox_series`]: the FDP router is not
/// mounted otherwise, and a seeded-but-impossible series is misleading. On a node nobody has
/// crawled, the FDP panels then read a flat zero rather than nothing.
pub fn seed_fairdp_series() {
    for resource_type in FAIRDP_RESOURCE_TYPES {
        for class in SEEDED_STATUS_CLASSES {
            metrics::counter!(
                FAIRDP_REQUESTS_TOTAL,
                "resource_type" => resource_type,
                "status_class" => class,
            )
            .increment(0);
        }
    }
}

/// The bounded, statically-known `reason` label set of [`OVERLAY_APPLY_FAILED_TOTAL`].
/// Enumerated so [`seed_channel_series`] can seed every reason to `0`. Kept in sync with
/// the `reason` argument passed to [`overlay_apply_failed`] at the overlay call sites.
pub const OVERLAY_APPLY_REASONS: [&str; 3] = ["fetch", "parse", "validate"];

/// Why a `{id}.state.json` visibility sidecar was rejected: the closed `reason` label set of
/// [`STATE_SIDECAR_REJECTED_TOTAL`], seeded to `0` per channel by [`seed_channel_series`].
/// An enum rather than a `&'static str` matched against an array by convention, so the type
/// is the set and a rejection site cannot spell a value the seeder and the alert do not
/// know.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateSidecarRejectReason {
    /// The file could not be fetched or parsed at all (torn write, oversized, I/O fault).
    Unreadable,
    /// It parsed, but its `state` names no served visibility.
    Unrecognized,
}

impl StateSidecarRejectReason {
    /// Every variant, in label order — what the seeder and its test iterate.
    pub const ALL: [Self; 2] = [Self::Unreadable, Self::Unrecognized];

    /// The `reason` label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unreadable => "unreadable",
            Self::Unrecognized => "unrecognized",
        }
    }
}

/// The `channel` label value for the node-local operator override feed
/// (`[service].override_dir`/`overlays/`) — the third overlay source, alongside the inbox
/// and each S3 bucket.
///
/// It is not an ingest channel, since no packages arrive through it, so it takes no part in
/// the suppression and writer-policy series. It can reject an overlay, though: an unparseable
/// entry in the override store holds precedence and keeps the node serving last-good
/// metadata. An operator has to be able to see that, which is why these rejections are
/// counted under their own channel rather than folded into `inbox`.
pub const LOCAL_OVERRIDE_CHANNEL: &str = "local-override";

/// Count one metadata-overlay apply failure
/// (`gdi_overlay_apply_failed_total{channel,reason}`). `reason` is a bounded closed set
/// (`fetch` | `parse` | `validate`), so label cardinality stays fixed.
///
/// Not called directly from the overlay call sites: `AppState::note_overlay_error` calls it,
/// so recording the per-id oracle field and incrementing this counter are one act, and the
/// two surfaces cannot drift apart.
pub fn overlay_apply_failed(channel: &str, reason: &'static str) {
    metrics::counter!(OVERLAY_APPLY_FAILED_TOTAL, "channel" => channel.to_owned(), "reason" => reason)
        .increment(1);
}

/// Count one visibility-sidecar rejection
/// (`gdi_state_sidecar_rejected_total{channel,reason}`). `reason` is the closed
/// [`StateSidecarRejectReason`] set, so label cardinality stays fixed by type.
///
/// Like [`overlay_apply_failed`], reached through `AppState::note_state_sidecar_error`
/// rather than called at the rejection sites, so the counter and the `state_sidecar_error`
/// oracle field cannot diverge.
pub fn state_sidecar_rejected(channel: &str, reason: StateSidecarRejectReason) {
    metrics::counter!(STATE_SIDECAR_REJECTED_TOTAL, "channel" => channel.to_owned(), "reason" => reason.as_str())
        .increment(1);
}

/// Count one skipped S3 removal pass (`gdi_s3_removal_skipped_total{channel}`): a collapsed
/// listing whose mass eviction was suppressed to protect served data.
pub fn s3_removal_skipped(channel: &str) {
    metrics::counter!(S3_REMOVAL_SKIPPED_TOTAL, "channel" => channel.to_owned()).increment(1);
}

/// Count one `deleted` `.state.json` sidecar ignored on an S3 bucket
/// (`gdi_s3_deleted_sidecar_ignored_total{channel}`): the orchestrator used the inbox delete
/// verb on an S3 channel, where deletion means removing the object.
pub fn s3_deleted_sidecar_ignored(channel: &str) {
    metrics::counter!(S3_DELETED_SIDECAR_IGNORED_TOTAL, "channel" => channel.to_owned())
        .increment(1);
}

/// Record one completed S3 package download: bytes streamed and wall-clock seconds
/// (`gdi_s3_download_bytes`, `gdi_s3_download_duration_seconds`). The fetch leg runs before
/// the ingest timer, so this is the otherwise-invisible network slice. Content-free, with no
/// per-request labels.
pub fn record_s3_download(bytes: u64, elapsed_seconds: f64) {
    #[expect(
        clippy::cast_precision_loss,
        reason = "byte counts up to ~exabytes lose no meaningful precision as f64 histogram samples"
    )]
    metrics::histogram!(S3_DOWNLOAD_BYTES).record(bytes as f64);
    metrics::histogram!(S3_DOWNLOAD_DURATION_SECONDS).record(elapsed_seconds);
}

/// Set whether status writeback is disabled for a bucket (`1`) or not (`0`)
/// (`gdi_s3_status_writeback_disabled{channel}`).
pub fn s3_writeback_disabled(channel: &str, disabled: bool) {
    metrics::gauge!(S3_STATUS_WRITEBACK_DISABLED, "channel" => channel.to_owned())
        .set(f64::from(u8::from(disabled)));
}

/// Set whether `channel`, a bucket name or `inbox`, is under an active operator
/// channel-suppression override (`1`) or not (`0`); see [`CHANNEL_SUPPRESSED`]. Called from
/// `BucketMonitor::run`'s pause check, immediately and event-driven, and from the periodic
/// sampler (`sample_channel_suppressions`), which is the only path for `inbox` and the one
/// that is correct regardless of boot ordering.
pub fn channel_suppressed(channel: &str, suppressed: bool) {
    metrics::gauge!(CHANNEL_SUPPRESSED, "channel" => channel.to_owned())
        .set(f64::from(u8::from(suppressed)));
}

/// Set whether `channel` is orphaned; see [`S3_CHANNEL_ORPHANED`]. Set at boot for each
/// channel `AppState::orphaned_channels` reports, and cleared by the config-reload add arm
/// when a reload re-declares the bucket.
pub fn s3_channel_orphaned(channel: &str, orphaned: bool) {
    metrics::gauge!(S3_CHANNEL_ORPHANED, "channel" => channel.to_owned())
        .set(f64::from(u8::from(orphaned)));
}

/// Set whether `catalog` is orphaned; see [`CATALOG_ORPHANED`]. Set at boot and re-evaluated
/// on every config reload, which is also what clears it when the `[catalogs]` entry comes
/// back.
pub fn catalog_orphaned(catalog: &str, orphaned: bool) {
    metrics::gauge!(CATALOG_ORPHANED, "catalog" => catalog.to_owned())
        .set(f64::from(u8::from(orphaned)));
}

/// Set whether `channel`'s removal processing is refused by the keyspace gate; see
/// [`S3_KEYSPACE_MISMATCH`]. Called from `BucketMonitor::removals_authorized` on every
/// removal-processing pass, in both directions, so a resolved mismatch clears without a
/// restart.
pub fn s3_keyspace_mismatch(channel: &str, mismatched: bool) {
    metrics::gauge!(S3_KEYSPACE_MISMATCH, "channel" => channel.to_owned())
        .set(f64::from(u8::from(mismatched)));
}

/// Set the Vault token TTL (lease) at the last login or renew, in seconds
/// (`gdi_vault_token_ttl_seconds`). A step value that resets on renew, not a live countdown
/// of remaining seconds.
pub fn vault_token_ttl(seconds: f64) {
    metrics::gauge!(VAULT_TOKEN_TTL_SECONDS).set(seconds);
}

/// Count one Vault token renewal failure (`gdi_vault_renewal_failures_total`).
pub fn vault_renewal_failure() {
    metrics::counter!(VAULT_RENEWAL_FAILURES_TOTAL).increment(1);
}

/// The bounded `outcome` label set of [`VAULT_REAUTH_TOTAL`], seeded to `0` at recorder
/// install so `increase()` over the `failed` series works from the first occurrence rather
/// than the second.
pub const VAULT_REAUTH_OUTCOMES: [&str; 2] = ["recovered", "failed"];

/// Record the outcome of the re-login that follows a failed token renewal
/// (`gdi_vault_reauth_total{outcome}`). `recovered` means the node holds a fresh token;
/// `failed` means the credential is broken. See [`VAULT_REAUTH_TOTAL`].
pub fn vault_reauth(outcome: &'static str) {
    metrics::counter!(VAULT_REAUTH_TOTAL, "outcome" => outcome).increment(1);
}

/// Publish the Vault token file's age in seconds (`gdi_vault_token_file_age_seconds`).
pub fn vault_token_file_age(seconds: f64) {
    metrics::gauge!(VAULT_TOKEN_FILE_AGE_SECONDS).set(seconds);
}

/// Count one successful Vault token-file read (`gdi_vault_token_file_reloads_total`).
pub fn vault_token_file_reload() {
    metrics::counter!(VAULT_TOKEN_FILE_RELOADS_TOTAL).increment(1);
}

/// Count one failed Vault token-file read (`gdi_vault_token_file_read_errors_total`).
pub fn vault_token_file_read_error() {
    metrics::counter!(VAULT_TOKEN_FILE_READ_ERRORS_TOTAL).increment(1);
}

/// Set the keyless-degraded latch (`gdi_keyless_degraded`): `1` when the node booted in
/// degraded keyless mode, with `[vault]` configured but unreachable at startup, else `0`.
/// Set once at startup; the node does not self-heal in place.
pub fn keyless_degraded(degraded: bool) {
    metrics::gauge!(KEYLESS_DEGRADED).set(f64::from(u8::from(degraded)));
}

/// Publish the at-rest master-key mismatch latch (`gdi_pme_master_key_mismatch`).
pub fn pme_master_key_mismatch(mismatched: bool) {
    metrics::gauge!(PME_MASTER_KEY_MISMATCH).set(f64::from(u8::from(mismatched)));
}

/// Map an HTTP status code to its bounded, content-free status class label
/// (`1xx|2xx|3xx|4xx|5xx|other`). Never the exact code: the class is what an operator alerts
/// on, and it keeps cardinality small.
#[must_use]
pub fn status_class(status: u16) -> &'static str {
    match status / 100 {
        1 => "1xx",
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        _ => "other",
    }
}

/// Record one beacon request: bump `gdi_beacon_requests_total{entry_type, status_class}` and
/// observe `gdi_beacon_request_duration_seconds` with the same labels. Both labels are
/// bounded, content-free sets: `entry_type` is one of `genomicVariant|dataset|individual`,
/// the GA4GH entity name rather than the route or the query, and `status_class` is the
/// response class. No query parameter, filter, variant or client identity ever becomes a
/// label.
pub fn record_beacon_request(entry_type: &'static str, status: u16, elapsed_seconds: f64) {
    let class = status_class(status);
    metrics::counter!(
        BEACON_REQUESTS_TOTAL,
        "entry_type" => entry_type,
        "status_class" => class,
    )
    .increment(1);
    metrics::histogram!(
        BEACON_REQUEST_DURATION_SECONDS,
        "entry_type" => entry_type,
        "status_class" => class,
    )
    .record(elapsed_seconds);
}

/// Record one completed request on either plane into the whole-node series
/// (`gdi_http_requests_total{plane,status_class}` and
/// `gdi_http_request_duration_seconds{plane}`). `plane` is [`PLANE_PUBLIC`] or
/// [`PLANE_MANAGEMENT`], and `status` is bucketed to a `status_class`. On the public plane
/// this covers every route, including the informational and well-known endpoints the
/// per-entry-type beacon metric does not, with no route, query or client label.
pub fn record_http_request(plane: &'static str, status: u16, elapsed_seconds: f64) {
    metrics::counter!(
        HTTP_REQUESTS_TOTAL,
        "plane" => plane,
        "status_class" => status_class(status),
    )
    .increment(1);
    metrics::histogram!(HTTP_REQUEST_DURATION_SECONDS, "plane" => plane).record(elapsed_seconds);
}

/// Record an answered beacon query's semantic outcome: the hit/miss and disclosure-level
/// counter ([`BEACON_QUERY_TOTAL`]). `entry_type` is the route entry type — `genomicVariant`,
/// `dataset` or `individual` — matching [`BEACON_REQUESTS_TOTAL`]. Always emitted,
/// independently of `[audit]`, and every label is a bounded closed set.
///
/// The per-query result count is not metered here. `audit::beacon_query` records it exactly,
/// per query, as `BeaconQueryAudit::num_results` alongside the dataset ids and pagination,
/// which answers the disclosure-volume and floor-tuning questions better than fixed
/// histogram buckets would.
pub fn record_beacon_query(entry_type: &'static str, granularity: &str, exists: bool) {
    let granularity = match granularity {
        "boolean" => "boolean",
        "count" => "count",
        "record" => "record",
        _ => "n/a",
    };
    let exists = if exists { "true" } else { "false" };
    metrics::counter!(
        BEACON_QUERY_TOTAL,
        "entry_type" => entry_type,
        "granularity" => granularity,
        "exists" => exists,
    )
    .increment(1);
}

/// Record a rejected or errored beacon query by HTTP `code`
/// ([`BEACON_QUERY_REJECTED_TOTAL`]): `400` for an envelope or coordinate reject, `413` for
/// a query that is too broad, `500` for an internal scan failure, and `other` defensively.
/// The page-able per-code signal the undifferentiated `status_class` bucket lumps together.
/// Always emitted, with a bounded label set.
pub fn record_beacon_query_rejected(entry_type: &'static str, code: u16) {
    let code = match code {
        400 => "400",
        413 => "413",
        500 => "500",
        _ => "other",
    };
    metrics::counter!(
        BEACON_QUERY_REJECTED_TOTAL,
        "entry_type" => entry_type,
        "code" => code,
    )
    .increment(1);
}

/// Record one FAIR Data Point request: bump
/// `gdi_fairdp_requests_total{resource_type,status_class}` and observe
/// `gdi_fairdp_request_duration_seconds` with the same labels. Both labels are bounded,
/// content-free sets: `resource_type` ∈ `root|catalog|dataset|distribution`, and
/// `status_class` is the response class. No path, resource id or `Accept` value ever becomes
/// a label.
pub fn record_fairdp_request(resource_type: &'static str, status: u16, elapsed_seconds: f64) {
    let class = status_class(status);
    metrics::counter!(
        FAIRDP_REQUESTS_TOTAL,
        "resource_type" => resource_type,
        "status_class" => class,
    )
    .increment(1);
    metrics::histogram!(
        FAIRDP_REQUEST_DURATION_SECONDS,
        "resource_type" => resource_type,
        "status_class" => class,
    )
    .record(elapsed_seconds);
}

/// Record one Vault KV or Transit call's latency, and on failure its error, by `operation`
/// (`kv_read|kv_write|transit_datakey|transit_decrypt`). Called from the Vault client, and
/// compiled only with the `vault` feature.
#[cfg(feature = "vault")]
pub fn record_vault_call(operation: &'static str, elapsed_seconds: f64, failed: bool) {
    metrics::histogram!(VAULT_CALL_DURATION_SECONDS, "operation" => operation)
        .record(elapsed_seconds);
    if failed {
        metrics::counter!(VAULT_CALL_ERRORS_TOTAL, "operation" => operation).increment(1);
    }
}

/// Count one FDP RDF serialization failure (the empty-output `500` branch of
/// `fairdp_http::render`).
pub fn fairdp_serialization_failure() {
    metrics::counter!(FAIRDP_SERIALIZATION_FAILURES_TOTAL).increment(1);
}

/// Count `count` datasets skipped on a cache reload for an unreadable or corrupt
/// `manifest.json` (`gdi_manifest_reload_skipped_total`). Called at the reload seam, so the
/// metric name stays owned by this module and core stays metrics-free.
pub fn manifest_reload_skipped(count: u64) {
    metrics::counter!(MANIFEST_RELOAD_SKIPPED_TOTAL).increment(count);
}

/// Set `gdi_datasets_suppressed{mode}` from the operator override store's mode
/// breakdown (`hide` count, `remove` count — see
/// [`SuppressionSet::counts_by_mode`](gdi_node_standalone_core::suppression::SuppressionSet::counts_by_mode)).
/// Called both event-driven, every time the suppression set is (re)applied to the cache
/// (see
/// [`AppState::apply_suppressions_to_cache`](crate::state::AppState::apply_suppressions_to_cache)),
/// and from every periodic sampler tick (`sample_suppressions`), which is what makes the
/// gauge correct within one tick of boot independent of install ordering.
pub fn datasets_suppressed(hide: u64, remove: u64) {
    #[expect(
        clippy::cast_precision_loss,
        reason = "suppression-override counts are tiny — exact in f64"
    )]
    {
        metrics::gauge!(DATASETS_SUPPRESSED, "mode" => SuppressMode::Hide.as_str())
            .set(hide as f64);
        metrics::gauge!(DATASETS_SUPPRESSED, "mode" => SuppressMode::Remove.as_str())
            .set(remove as f64);
    }
}

/// Set `gdi_suppression_load_degraded` — the count of `<override_dir>/suppressions/*.json`
/// entries that were fail-closed to `hide` on the last store load (`0` on a clean load).
/// Called from
/// [`AppState::reload_suppressions`](crate::state::AppState::reload_suppressions) on
/// every `SIGUSR1` reload (`reload_suppressions` is never called at boot — the initial
/// load happens inline in `AppState::new`), and from every periodic-sampler tick
/// (`sample_suppressions`), which is what makes this gauge correct at boot.
pub fn suppression_load_degraded(count: u64) {
    #[expect(
        clippy::cast_precision_loss,
        reason = "degraded-file counts are tiny — exact in f64"
    )]
    metrics::gauge!(SUPPRESSION_LOAD_DEGRADED).set(count as f64);
}

/// Which independent check is reporting the operator-override store lost.
///
/// `gdi_override_store_absent` has three writers applying three different predicates, and a
/// gauge `.set()` is last-writer-wins. Without per-source latching, a healthy `overlays/`
/// reload would write the gauge back to zero moments after `reload_suppressions` raised it
/// for an unreadable `suppressions/`, and the unreadable condition would never be
/// observable: the periodic sampler repairs it only when `require_override_store` is set or
/// the latch has already fired, and the latch is fed by a set that loads empty when
/// unreadable.
///
/// Each source therefore latches its own slot and the gauge publishes the OR: no writer can
/// clear a condition it does not observe.
#[derive(Debug, Clone, Copy)]
pub enum OverrideStoreAlarm {
    /// [`AppState::reload_suppressions`](crate::state::AppState::reload_suppressions) — the
    /// `suppressions/` half is unreadable, or absent while `require_override_store` is set.
    Suppressions,
    /// [`AppState::reload_local_overlays`](crate::state::AppState::reload_local_overlays) —
    /// the `overlays/` half, same predicate.
    Overlays,
    /// The periodic sampler's presence check over the store root (`store_loss_signal`).
    /// This is the only path that sees a store already gone at boot, as with
    /// `suppression_load_degraded`: the initial set is loaded inline in `AppState::new`
    /// without going through either reload.
    Presence,
}

/// Latched state of each [`OverrideStoreAlarm`] source, OR'd into the published gauge.
static ALARM_SUPPRESSIONS: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static ALARM_OVERLAYS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static ALARM_PRESENCE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Record `source`'s verdict and republish `gdi_override_store_absent` as the OR over all
/// three sources: the node is serving from a last known-good set if any of them says so.
///
/// Each source clears only its own slot, so a healthy `overlays/` reload cannot silence an
/// unreadable `suppressions/`.
pub fn override_store_absent(source: OverrideStoreAlarm, absent: bool) {
    use std::sync::atomic::Ordering::Relaxed;
    match source {
        OverrideStoreAlarm::Suppressions => ALARM_SUPPRESSIONS.store(absent, Relaxed),
        OverrideStoreAlarm::Overlays => ALARM_OVERLAYS.store(absent, Relaxed),
        OverrideStoreAlarm::Presence => ALARM_PRESENCE.store(absent, Relaxed),
    }
    let any = ALARM_SUPPRESSIONS.load(Relaxed)
        || ALARM_OVERLAYS.load(Relaxed)
        || ALARM_PRESENCE.load(Relaxed);
    metrics::gauge!(OVERRIDE_STORE_ABSENT).set(f64::from(u8::from(any)));
}

/// Count one failed `SIGHUP` config-reload attempt (unparsable TOML, or a preflight
/// rejection) — the running node kept its previous `[catalogs]`/`[ingest]`-writer-
/// allow-list subset. Called from
/// [`AppState::reload_config_from`](crate::state::AppState::reload_config_from) on each failure;
/// never called on a successful reload, even one that also warned about an ignored
/// restart-only field. See [`CONFIG_RELOAD_FAILED_TOTAL`].
pub fn config_reload_failed() {
    metrics::counter!(CONFIG_RELOAD_FAILED_TOTAL).increment(1);
}

/// Count one HTTP request rejected by a resilience layer, labelled by its bounded
/// `reason` (`overloaded|timeout|body_too_large|uri_too_large|internal` — one of the
/// `REJECT_REASON_*` constants). The label is content-free: no path, query, or client
/// identity.
pub fn record_request_rejected(reason: &'static str) {
    metrics::counter!(HTTP_REQUESTS_REJECTED_TOTAL, "reason" => reason).increment(1);
}

/// Count one connection dropped at accept because `plane`'s connection cap was full
/// (one of the `PLANE_*` constants). A counter rather than a log line: it carries no
/// per-connection detail, so it cannot be amplified by the very flood it reports.
pub fn record_connection_rejected(plane: &'static str) {
    metrics::counter!(HTTP_CONNECTIONS_REJECTED_TOTAL, "plane" => plane).increment(1);
}

/// Record the public-plane concurrency limit once at startup — the constant
/// capacity line ([`HTTP_MAX_CONCURRENT_REQUESTS`]) for the [`HTTP_IN_FLIGHT`]
/// saturation gauge. Mirrors [`INGEST_CONCURRENCY`] for the ingest pool.
pub fn record_http_max_concurrent(limit: usize) {
    #[expect(
        clippy::cast_precision_loss,
        reason = "concurrency-limit gauge tolerates f64 imprecision far above any real limit"
    )]
    metrics::gauge!(HTTP_MAX_CONCURRENT_REQUESTS).set(limit as f64);
}

/// RAII guard holding the [`HTTP_IN_FLIGHT`] gauge incremented for the lifetime of
/// one in-flight request. It decrements on `Drop` rather than after the handler's
/// `.await`, so the count stays correct even when axum drops the request future
/// mid-flight (client disconnect / shutdown drain) — a post-`.await` decrement
/// would leak and the gauge would ratchet up forever.
#[must_use = "the gauge is only held up while the guard is alive; drop it when the request ends"]
pub struct InFlightGuard(());

impl InFlightGuard {
    /// Increment [`HTTP_IN_FLIGHT`] and return a guard that decrements it on drop.
    pub fn enter() -> Self {
        metrics::gauge!(HTTP_IN_FLIGHT).increment(1.0);
        Self(())
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        metrics::gauge!(HTTP_IN_FLIGHT).decrement(1.0);
    }
}

/// Current Unix time in (fractional) seconds, used for the `*_last_*_seconds`
/// gauges and the `last_progress` timestamp.
#[must_use]
pub fn unix_now_seconds() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

/// Spawn the periodic gauge sampler: refresh the scrape-time gauges that are
/// cheaper to sample than to track on every transition — the four
/// `gdi_dataset_state` counts (recomputed from the cache + status index), the data
/// volume's `gdi_disk_free_bytes`, and `gdi_uptime_seconds`. Spawned only when
/// metrics are enabled.
pub fn spawn_sampler(state: AppState, handle: MetricsHandle) {
    let started = std::time::Instant::now();
    // A dedicated OS thread rather than `tokio::spawn`: `sample_once` is entirely synchronous
    // and issues blocking fs syscalls (`statvfs` on the data volume, `/proc/self/*`
    // reads, `read_dir` of the inbox quarantine). On a stalled data volume (e.g. an
    // unreachable NFS mount) those block in uninterruptible D-state for the mount
    // timeout, which on a shared async worker would park a reactor thread and stall
    // request handling. Its own thread keeps that off the reactor entirely; the thread
    // is detached and ends when the process exits.
    let spawned = std::thread::Builder::new()
        .name("gdi-metrics-sampler".to_owned())
        .spawn(move || {
            loop {
                std::thread::sleep(SAMPLE_INTERVAL);
                // Drain the histogram sample accumulators before the gauge refresh, so a
                // `sample_once` panic can never skip it. Their lock-free buckets are
                // emptied only on a `/metrics` render or this upkeep — a node whose
                // `/metrics` is never scraped would otherwise retain one heap node per
                // histogram observation forever (unbounded RSS under sustained traffic).
                // Isolated on its own so a panic here cannot freeze the gauge refresh below.
                if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle.run_upkeep()))
                    .is_err()
                {
                    warn!("metrics upkeep iteration panicked; continuing");
                    background_task_panic();
                }
                // Isolate a panicking sub-sampler (a malformed `/proc` read, an
                // arithmetic edge) so one bad iteration cannot permanently freeze every
                // scrape-time gauge for the process lifetime — the OS-thread analogue of
                // the tokio `guarded()` loops.
                if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    sample_once(&state, started);
                }))
                .is_err()
                {
                    warn!("metrics sampler iteration panicked; continuing");
                    background_task_panic();
                }
            }
        });
    if let Err(e) = spawned {
        warn!(error = %e, "failed to start the metrics sampler thread; scrape-time gauges will not refresh");
    }
}

/// Take one sample of the scrape-time gauges. Separated from [`spawn_sampler`] so a
/// test can drive a single deterministic refresh.
pub fn sample_once(state: &AppState, started: std::time::Instant) {
    // The order below is a contract, bound by
    // `readiness_is_sampled_before_anything_that_can_stall`. This runs on one OS thread, so
    // the first sampler that blocks freezes every gauge behind it at its last value, and a
    // frozen `gdi_health_ready` reads 1, so a wedged node scrapes as healthy. Everything
    // reading only in-memory state therefore runs before anything that touches a filesystem.
    //
    // Phase 1, pure in-memory. Readiness comes first: it is the one gauge whose staleness is
    // indistinguishable from health, so it must be written before anything that can block.
    crate::health::record_readiness_metrics(state);
    metrics::gauge!(UPTIME_SECONDS).set(started.elapsed().as_secs_f64());
    sample_dataset_states(state);
    sample_suppressions(state);
    sample_channel_suppressions(state);
    sample_query_scan_blocking(state);
    sample_ingest_inflight_age(state);

    // Phase 2, everything that touches a filesystem. Ordered last, and each one is a
    // candidate to hang: see `sample_override_store_presence` for the worst case.
    sample_process();
    sample_override_store_presence(state);
    sample_disk_free(&state.config.service.data_dir);
    sample_inbox_rejected(state.config.service.inbox.as_deref());
    sample_inbox_keyless(
        state.config.service.inbox.as_deref(),
        state.identities.is_enabled(),
    );
    sample_vault_token_file_age(state);
}

/// The filesystem half of the override-store gauges: does the store root still exist?
///
/// In phase 2 because it is the sampler most likely to hang.
/// [`gdi_node_standalone_core::override_store::is_present`] stats the root and every loader
/// directory under it, and [`operating.md` §17] recommends relocating `override_dir` onto
/// separately-backed storage, which is the kind of network volume that hangs rather than
/// errors. Run before [`crate::health::record_readiness_metrics`], a wedged override mount
/// would block the sampler thread and leave `gdi_health_ready` scraping its last value, `1`,
/// for the life of the process.
///
/// [`operating.md` §17]: ../../../docs/operating.md
fn sample_override_store_presence(state: &AppState) {
    let set = state
        .suppressions
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let root = state.config.service.override_dir_resolved();
    // Both halves of the store, not just suppressions. Asking "does this node hold
    // overrides?" of the suppression set alone would answer no on a node whose overrides are
    // all metadata overlays, never latch `ever_held`, and produce no signal when its store
    // was destroyed. Losing the overlay set re-publishes the source metadata each override
    // was redacting, which is the discrimination this signal exists to make.
    let holds_suppressions = !set.is_empty() || set.degraded() > 0;
    let holds_overlays = {
        let overlays = state
            .local_overlays
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        overlays.ids().next().is_some() || overlays.degraded() > 0
    };
    let holds_overrides = holds_suppressions || holds_overlays;
    // Drop the suppressions read guard before touching the filesystem. `is_present` stats
    // the store root and every loader dir under it, the call this function exists to keep off
    // the readiness path because it can block forever on a hung mount. Held across that call,
    // the guard would block every writer to `state.suppressions` too, so an operator's
    // `SIGHUP` suppression reload would wedge behind the metrics sampler.
    drop(set);
    override_store_absent(
        OverrideStoreAlarm::Presence,
        store_loss_signal(
            state.config.service.require_override_store,
            note_and_read_ever_held(holds_overrides),
            gdi_node_standalone_core::override_store::is_present(&root),
        ),
    );
}

/// Sample the age of `[vault].token_file` (`gdi_vault_token_file_age_seconds`).
///
/// Publishing the gauge only from `VaultClient::ensure_token` is not enough: that runs on a
/// Vault call, and the one periodic Vault call, the liveness probe, is
/// `#[cfg(feature = "pme")]` and spawns only when PME is active. On a `[vault]`-without-PME
/// node (identities or S3 credentials read once at boot, no `transit_key`) the gauge would be
/// written once during startup and never again, sitting at roughly 0 for the life of the
/// process, so `VaultTokenFileStale` could never fire.
/// `deploy/kubernetes/base/secret.example.yaml` tells operators this gauge is their signal,
/// since `VaultRenewalFailing` and `VaultTokenLeaseTooShort` are inert in this mode.
///
/// Sampling here makes freshness independent of whether anything talks to Vault, and of the
/// `pme` feature. One `stat` per tick.
fn sample_vault_token_file_age(state: &AppState) {
    let Some(path) = state
        .config
        .vault
        .as_ref()
        .and_then(|v| v.token_file.as_deref())
    else {
        return;
    };
    match std::fs::metadata(path).and_then(|m| m.modified()) {
        Ok(mtime) => {
            // A clock skew making the file "newer than now" reports 0 rather than a wild value.
            vault_token_file_age(mtime.elapsed().map_or(0.0, |d| d.as_secs_f64()));
        }
        // Missing / unreadable: count it rather than freezing the gauge silently. This is the
        // same event `read_token_file` reports, and what `VaultTokenFileUnreadable` alerts on.
        Err(_) => vault_token_file_read_error(),
    }
}

/// Sample how many Beacon `g_variants` parquet scans are running on the shared
/// `spawn_blocking` pool, including scans detached by a request timeout. Sampled from the
/// dedicated sampler thread rather than emitted event-driven, so it still reports under full
/// pool saturation, the condition it measures, when a queued scan closure never gets a
/// thread to run on. See [`BEACON_SCAN_BLOCKING_INFLIGHT`].
fn sample_query_scan_blocking(state: &AppState) {
    let running = state
        .query_scan_blocking
        .load(std::sync::atomic::Ordering::Relaxed);
    #[expect(
        clippy::cast_precision_loss,
        reason = "scan-inflight gauge tolerates f64 imprecision far above the blocking-pool ceiling"
    )]
    metrics::gauge!(BEACON_SCAN_BLOCKING_INFLIGHT).set(running as f64);
}

/// Sample the age of the oldest in-flight ingest marker into
/// [`INGEST_INFLIGHT_OLDEST_AGE_SECONDS`]. In-memory only (phase 1 of `sample_once`).
fn sample_ingest_inflight_age(state: &AppState) {
    let oldest = oldest_inflight_age(&state.ingest_inflight, std::time::Instant::now());
    metrics::gauge!(INGEST_INFLIGHT_OLDEST_AGE_SECONDS).set(oldest.as_secs_f64());
}

/// Age at `now` of the oldest marker in `inflight`; zero when there is none. Saturating:
/// a marker stamped after `now` was taken (the sampler races the scanner) reads as zero,
/// not as a panic.
fn oldest_inflight_age(
    inflight: &std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>,
    now: std::time::Instant,
) -> Duration {
    inflight
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .values()
        .map(|started| now.saturating_duration_since(*started))
        .max()
        .unwrap_or_default()
}

/// Sample the inbox quarantine backlog: how many permanently-rejected packages are
/// parked under `{inbox}/.rejected/`. No-op on a pure-S3 node (no inbox). A missing
/// `.rejected/` dir (no rejections yet) reads as `0`, so the gauge is present from the
/// first sample on any inbox node.
fn sample_inbox_rejected(inbox: Option<&std::path::Path>) {
    let Some(inbox) = inbox else { return };
    // Single-sourced with the GC and `dataset purge-rejected` through
    // `ingest_runtime::read_rejected_entries`, the one definition of "a quarantine entry",
    // so the gauge cannot disagree with what eviction and purge count.
    //
    // Both quarantine shapes count. `quarantine` renames the artifact wholesale, so an inbox
    // `{id}.tar.c4gh` package lands as a regular file at `.rejected/{id}` rather than as a
    // staging directory. An `is_dir()` filter would pin this gauge at `0` on the documented
    // production ingress and leave `InboxQuarantineBacklog` unable to fire.
    let count = crate::ingest_runtime::read_rejected_entries(&inbox.join(".rejected")).len();
    #[expect(
        clippy::cast_precision_loss,
        reason = "quarantine-backlog gauge tolerates f64 imprecision far above any real count"
    )]
    metrics::gauge!(INBOX_REJECTED_PACKAGES).set(count as f64);
}

/// Sample encrypted inbox packages this node cannot decrypt.
///
/// A `.tar.c4gh` dropped on a node with no crypt4gh identity is skipped rather than
/// rejected, so it survives until a keyed run. The skip carries no dataset state (the id was
/// never ingested) and no quarantine, so without this gauge its only surface is one `INFO`
/// line per scan. At `GDI_LOG=warn` a provider could drop packages indefinitely with nothing
/// to show for it, and raising the log level does not help: the drop is standing, so it
/// re-logs every scan.
///
/// A gauge is the right shape for a standing condition — it reads `0` on a keyed node and
/// on an empty inbox, so `> 0` means exactly "packages are waiting for a key this node does
/// not have". No-op on a pure-S3 node.
fn sample_inbox_keyless(inbox: Option<&std::path::Path>, identities_enabled: bool) {
    // A `read_dir` failure is a fault, not "no packages waiting": the gauge still reads 0
    // (an absent series and a healthy zero are indistinguishable to an alert), but the
    // failure is said out loud — once, until a sample succeeds again, since this runs on a
    // timer and an unreadable inbox stays that way until someone acts.
    static UNREADABLE_WARNED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    let Some(inbox) = inbox else { return };
    // A keyed node always reports 0 rather than not reporting: an absent series and a
    // healthy zero are indistinguishable to an alert, and this one must be able to say
    // "healthy" out loud.
    let count = if identities_enabled {
        0
    } else {
        match std::fs::read_dir(inbox) {
            Ok(entries) => {
                UNREADABLE_WARNED.store(false, std::sync::atomic::Ordering::Relaxed);
                entries
                    .filter_map(Result::ok)
                    .filter(|e| {
                        e.file_name().to_str().is_some_and(|n| {
                            n.ends_with(gdi_node_standalone_core::s3_layout::TAR_C4GH_SUFFIX)
                        })
                    })
                    .count()
            }
            Err(e) => {
                if !UNREADABLE_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    tracing::warn!(
                        inbox = %inbox.display(),
                        error = %e,
                        "the inbox could not be read while sampling keyless packages; \
                         gdi_inbox_keyless_packages reports 0 for a directory nobody can see \
                         into (warned once until a sample succeeds)"
                    );
                }
                0
            }
        }
    };
    #[expect(
        clippy::cast_precision_loss,
        reason = "keyless-backlog gauge tolerates f64 imprecision far above any real count"
    )]
    metrics::gauge!(INBOX_KEYLESS_PACKAGES).set(count as f64);
}

/// Sample this process's resident memory, open-fd count, and thread count from
/// `/proc/self/*`. Best-effort and Linux-only: on a platform without `/proc`, or on
/// any read/parse failure, the gauge is simply not refreshed this tick (no panic).
fn sample_process() {
    let rss_kb = proc_status_field("VmRSS:");
    let threads = proc_status_field("Threads:");
    let open_fds = open_fd_count();
    #[expect(
        clippy::cast_precision_loss,
        reason = "process gauges tolerate f64 imprecision far above any real RSS/fd/thread count"
    )]
    {
        if let Some(rss_kb) = rss_kb {
            metrics::gauge!(PROCESS_RESIDENT_MEMORY_BYTES).set(rss_kb.saturating_mul(1024) as f64);
        }
        if let Some(threads) = threads {
            metrics::gauge!(PROCESS_THREADS).set(threads as f64);
        }
        if let Some(open_fds) = open_fds {
            metrics::gauge!(PROCESS_OPEN_FDS).set(open_fds as f64);
        }
    }
    // The kernel's cumulative tally is set rather than incremented, so the series is
    // monotonic within the process and resets cleanly to roughly 0 on restart. `rate()`
    // reads it as it would a float counter, with no double-counting across ticks.
    if let Some(cpu_seconds) = proc_self_cpu_seconds() {
        metrics::gauge!(PROCESS_CPU_SECONDS).set(cpu_seconds);
    }
}

/// Cumulative CPU time (user + system) this process has used, in fractional seconds,
/// from `/proc/self/stat` (`utime` + `stime` clock ticks ÷ the kernel `CLK_TCK`).
///
/// `comm` (field 2) can itself contain `)` and spaces, so the stable fields are
/// parsed from after the last `)`: in that whitespace-split tail, `utime` is
/// index 11 and `stime` index 12 (fields 14/15 counting from `pid`). Fractional, so
/// the gauge moves every sampler tick on a lightly loaded node (whole seconds left
/// its `rate()` at `0` for most windows). `None` off Linux or on any read/parse
/// failure (the gauge is simply not refreshed this tick).
fn proc_self_cpu_seconds() -> Option<f64> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let tail = stat.rsplit_once(')')?.1;
    let fields: Vec<&str> = tail.split_whitespace().collect();
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    let ticks_per_second = rustix::param::clock_ticks_per_second();
    if ticks_per_second == 0 {
        return None;
    }
    #[expect(
        clippy::cast_precision_loss,
        reason = "clock ticks over a process lifetime are far below f64's exact-integer range"
    )]
    Some(utime.saturating_add(stime) as f64 / ticks_per_second as f64)
}

/// Parse the first integer on a `/proc/self/status` line with the given `prefix`
/// (e.g. `"VmRSS:"` → `1234` from `VmRSS:\t  1234 kB`). `None` off Linux or on any
/// missing-line / parse failure.
fn proc_status_field(prefix: &str) -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix(prefix))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse().ok())
}

/// Count this process's open file descriptors (entries under `/proc/self/fd`),
/// subtracting the directory handle `read_dir` itself holds open while counting.
/// `None` off Linux.
fn open_fd_count() -> Option<u64> {
    let count = std::fs::read_dir("/proc/self/fd").ok()?.count() as u64;
    Some(count.saturating_sub(1))
}

/// Recompute the `gdi_dataset_state{state}` gauges from the live cache (visible /
/// hidden / processing) plus the persistent status index (`error` datasets are not
/// in the cache — a failed ingest leaves no `datasets/{id}/`). Aggregate counts by
/// state only; never a per-id label (which would leak hidden-dataset ids).
fn sample_dataset_states(state: &AppState) {
    use gdi_node_standalone_core::state::DatasetState;

    // Count cached datasets by state without deep-cloning the whole registry every tick
    // (this runs on a 10s background timer).
    //
    // `error` is the union of the two stores, not either alone. `quarantine_scrub_failure`
    // sets an already-cached dataset to `Error` in the cache and updates the status index
    // only when an entry already exists, so a dataset quarantined without a status entry
    // would be counted in no bucket at all: it leaves `visible` or `hidden` and never
    // arrives in `error`. Union by id, since the common case has it in both.
    let [visible, hidden, processing, _cached_error] = state.cache.count_by_state();
    let mut error_ids: std::collections::HashSet<String> = state
        .cache
        .ids_in_state(DatasetState::Error)
        .into_iter()
        .collect();
    {
        let status = state
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (id, entry) in status.entries() {
            if entry.state == DatasetState::Error {
                error_ids.insert(id.clone());
            }
        }
    }
    let error = error_ids.len();

    // Dataset counts are tiny, so `usize -> f64` is exact for any realistic registry.
    #[expect(
        clippy::cast_precision_loss,
        reason = "dataset counts are tiny — exact in f64"
    )]
    let counts = [
        ("visible", visible as f64),
        ("hidden", hidden as f64),
        ("processing", processing as f64),
        ("error", error as f64),
    ];
    for (label, value) in counts {
        metrics::gauge!(DATASET_STATE, "state" => label).set(value);
    }
}

/// Whether the absent-override-store gauge should report a loss.
///
/// Keyed on whether the store matters, not on the operator having set a flag. Gated on
/// `require_override_store` alone, which defaults to false, the detector would be disabled
/// on the nodes that lose a store silently: one holding real withholds without the assertion
/// set would have them all lifted with no signal anywhere. A node that genuinely holds no
/// overrides and asserts nothing still reports nothing.
fn store_loss_signal(required: bool, has_or_had_overrides: bool, present_on_disk: bool) -> bool {
    !present_on_disk && (required || has_or_had_overrides)
}

/// Whether this process has ever observed a non-empty operator-override set.
///
/// `holds_overrides` is derived from the live in-memory set, which is loaded from the store
/// being checked, so the moment a destroyed store loads as empty that argument goes false and
/// the node becomes indistinguishable from one that genuinely holds no overrides. The latch
/// keeps the discrimination the signal exists to make.
///
/// Latched here rather than inside the predicate, so the predicate stays a pure function of
/// its arguments and its unit tests stay order-independent.
///
/// Its bound: it detects a store destroyed while the node was running. It cannot detect
/// one destroyed while the node was down, because after a restart there is no in-process
/// memory and the store is the only record of itself. That case is detectable only through
/// `service.require_override_store`, whose config is mounted from outside the volume and so
/// survives the incident.
static EVER_HELD_OVERRIDES: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Record that a non-empty override set was observed, and report the latch.
fn note_and_read_ever_held(holds_overrides: bool) -> bool {
    if holds_overrides {
        EVER_HELD_OVERRIDES.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    EVER_HELD_OVERRIDES.load(std::sync::atomic::Ordering::Relaxed)
}

/// Recompute `gdi_datasets_suppressed{mode}` and `gdi_suppression_load_degraded` from the
/// live `state.suppressions` set, independent of when an event-driven `.set()` call last ran.
///
/// This closes a boot-ordering gap. `enforce_suppressions().await` runs before the Prometheus
/// recorder is installed, so its `datasets_suppressed` call has no recorder to record into,
/// and `AppState::new` loads the suppression set inline via `suppression::load` without
/// calling [`AppState::reload_suppressions`](crate::state::AppState::reload_suppressions),
/// the only other caller of `suppression_load_degraded`. Without this resample, a node that
/// restarts with an already-broken `suppressions/*.json` file would read a false `0` on both
/// gauges, and never trip the degraded-store alert, until the first `SIGUSR1` or periodic
/// full reload up to `rescan_interval_seconds` later. Run every sampler tick (~10s), so both
/// gauges are correct within one tick of boot regardless of install ordering.
fn sample_suppressions(state: &AppState) {
    let set = state
        .suppressions
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (hide, remove) = set.counts_by_mode();
    datasets_suppressed(hide as u64, remove as u64);
    suppression_load_degraded(set.degraded() as u64);
    // The store-presence gauge is not computed here, because it stats the disk: see
    // `sample_override_store_presence`, which runs in phase 2. The two gauges above read the
    // live in-memory set, so they look healthy while the disk behind them is gone. The
    // presence gauge catches that, and keeping it in phase 2 keeps it from stalling this
    // function.
}

/// Refresh [`CHANNEL_SUPPRESSED`] for every configured channel (bucket names, plus `inbox`
/// when configured) from the live `state.suppressions` set.
///
/// This is the only path covering two cases `BucketMonitor::run`'s event-driven set cannot:
/// the `inbox` channel, which no per-channel poll loop watches (the scanner's pause check
/// lives in `ingest_runtime::scan_once`, which does not touch this metric), and a channel
/// already suppressed before the recorder installs. Run every sampler tick (~10s), so both
/// gaps close within one tick regardless of install ordering or which channels have a
/// running monitor.
fn sample_channel_suppressions(state: &AppState) {
    let set = state
        .suppressions
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(s3) = state.config.s3.as_ref() {
        for bucket in &s3.buckets {
            channel_suppressed(&bucket.name, set.channel_get(&bucket.name).is_some());
        }
    }
    if state.config.service.inbox.is_some() {
        channel_suppressed("inbox", set.channel_get("inbox").is_some());
    }
}

/// Sample the data volume's free bytes (available to non-root) via a `statvfs` and
/// set `gdi_disk_free_bytes{volume}`. The `volume` label is the data-dir path — an
/// operator-known mount, not request data.
///
/// Always publishes [`DISK_SAMPLE_FAILED`] alongside, in both arms. A `statvfs` failure is
/// not a missing data point: this exporter is a registry rendered on demand with no idle
/// timeout, so leaving the gauge unset keeps its last healthy value rendering forever and
/// `LowDisk` silently evaluates a frozen number. The companion series is what makes the
/// failure observable.
fn sample_disk_free(data_dir: &std::path::Path) {
    match rustix::fs::statvfs(data_dir) {
        Ok(st) => {
            metrics::gauge!(DISK_SAMPLE_FAILED).set(0.0);
            // Available blocks to an unprivileged process × the fragment size.
            let free = st.f_bavail.saturating_mul(st.f_frsize);
            let volume = data_dir.to_string_lossy().into_owned();
            // A byte count beyond 2^52 loses precision in f64 (≈4 PB) — irrelevant
            // for a free-bytes gauge whose alert thresholds are far coarser.
            #[expect(
                clippy::cast_precision_loss,
                reason = "free-bytes gauge tolerates f64 imprecision above ~4 PB"
            )]
            let free = free as f64;
            metrics::gauge!(DISK_FREE_BYTES, "volume" => volume).set(free);
        }
        Err(e) => {
            metrics::gauge!(DISK_SAMPLE_FAILED).set(1.0);
            // `warn!`, not `debug!`: the default level is `info`, so a `debug!` here would
            // hide the one in-process trace of a detached data volume.
            tracing::warn!(
                alert = true,
                event.action = "disk.sample",
                event.outcome = "failure",
                path = %data_dir.display(),
                error = %e,
                "statvfs failed; gdi_disk_free_bytes is now stale"
            );
        }
    }
}

/// The `/metrics` route, rendering Prometheus exposition from `handle`.
///
/// Mounted on the management-plane listener, never the public `listen`, so the operational
/// series (request volumes, hot datasets, error rates) stay in-cluster, reached by the
/// management listener's binding plus a `NetworkPolicy` rather than the public Ingress.
/// Returns a state-agnostic `Router<AppState>` so it merges into the management router; the
/// handler ignores the state and renders from the captured `handle`.
pub fn metrics_router(handle: Arc<MetricsHandle>) -> axum::Router<crate::state::AppState> {
    use axum::routing::get;

    axum::Router::new().route(
        "/metrics",
        get(move || {
            let handle = Arc::clone(&handle);
            async move {
                (
                    [(
                        axum::http::header::CONTENT_TYPE,
                        "text/plain; version=0.0.4; charset=utf-8",
                    )],
                    handle.render(),
                )
            }
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stuck-ingest gauge reads the oldest marker, and zero when there is none, which
    /// lets one hung ingest raise it while a stream of short ones cannot.
    #[test]
    fn oldest_inflight_age_is_the_oldest_marker_and_zero_when_idle() {
        let now = std::time::Instant::now();
        let inflight = std::sync::Mutex::new(std::collections::HashMap::new());
        assert_eq!(oldest_inflight_age(&inflight, now), Duration::ZERO);

        let earlier = |secs| now.checked_sub(Duration::from_secs(secs)).expect("recent");
        inflight
            .lock()
            .expect("unpoisoned")
            .insert("GDI-2".to_owned(), earlier(5));
        inflight
            .lock()
            .expect("unpoisoned")
            .insert("GDI-1".to_owned(), earlier(90));
        inflight
            .lock()
            .expect("unpoisoned")
            .insert("GDI-3".to_owned(), earlier(1));
        assert_eq!(oldest_inflight_age(&inflight, now), Duration::from_secs(90));

        // A marker stamped after `now` was read (the sampler racing the scanner) reads
        // as zero, not as a panic.
        inflight.lock().expect("unpoisoned").clear();
        inflight
            .lock()
            .expect("unpoisoned")
            .insert("GDI-4".to_owned(), now + Duration::from_secs(1));
        assert_eq!(oldest_inflight_age(&inflight, now), Duration::ZERO);
    }

    #[test]
    fn build_info_env_is_wired() {
        // The shared `gdi-build-info` crate's build.rs injects these (at minimum
        // "unknown"); a missing var would fail to compile via `env!` inside that
        // crate, so this guards that the provenance is still wired through.
        assert!(!gdi_build_info::GIT_SHA.is_empty());
        assert!(!gdi_build_info::BUILD_EPOCH.is_empty());
    }

    #[test]
    fn status_class_buckets_by_hundreds() {
        assert_eq!(status_class(100), "1xx");
        assert_eq!(status_class(199), "1xx");
        assert_eq!(status_class(200), "2xx");
        assert_eq!(status_class(302), "3xx");
        assert_eq!(status_class(404), "4xx");
        assert_eq!(status_class(503), "5xx");
        assert_eq!(status_class(599), "5xx");
        // Out-of-band codes collapse to the catch-all bucket (bounded cardinality).
        assert_eq!(status_class(600), "other");
        assert_eq!(status_class(700), "other");
        assert_eq!(status_class(0), "other");
    }

    /// The `/proc/self/*` process-stat parsers return live, positive values for the
    /// running test process. Linux-only (the gauges are best-effort elsewhere).
    #[cfg(target_os = "linux")]
    #[test]
    fn proc_self_stats_are_readable_and_positive() {
        let rss_kb = proc_status_field("VmRSS:").expect("VmRSS present on Linux");
        assert!(rss_kb > 0, "a running process has non-zero RSS");
        let threads = proc_status_field("Threads:").expect("Threads present on Linux");
        assert!(threads >= 1, "a running process has at least one thread");
        let fds = open_fd_count().expect("/proc/self/fd readable on Linux");
        assert!(fds >= 1, "a running process has at least one open fd");
        // A missing field returns None rather than panicking.
        assert_eq!(proc_status_field("NotAField:"), None);
    }

    /// Cumulative CPU seconds parses from `/proc/self/stat` for the running test
    /// process. May legitimately be tiny (a fast test uses well under a second of CPU),
    /// so assert only that it parses, is finite and is plausible — the `)`-in-`comm`
    /// split is the part that would silently misparse.
    #[cfg(target_os = "linux")]
    #[test]
    fn proc_self_cpu_seconds_parses() {
        let secs = proc_self_cpu_seconds().expect("/proc/self/stat readable on Linux");
        assert!(
            secs.is_finite() && (0.0..86_400.0).contains(&secs),
            "implausible CPU seconds for a test process: {secs}"
        );
    }

    /// The in-flight guard increments on construction and decrements on drop. With
    /// no recorder installed in this unit-test process the gauge calls are no-ops,
    /// so this exercises the RAII shape (construct + drop without panicking) — the
    /// real increment/decrement balance is covered by the metrics integration test.
    #[test]
    fn in_flight_guard_constructs_and_drops() {
        let g = InFlightGuard::enter();
        drop(g);
    }

    /// Assert `render` carries a line for `metric` with exactly `labels`, valued `0`.
    /// Label order in the exporter's output is not part of the contract, so match on the
    /// metric name, every `k="v"` pair, and the trailing value.
    fn assert_seeded_zero(render: &str, metric: &str, labels: &[(&str, &str)]) {
        let hit = render.lines().any(|line| {
            line.starts_with(metric)
                && line.ends_with(" 0")
                && labels
                    .iter()
                    .all(|(k, v)| line.contains(&format!("{k}=\"{v}\"")))
        });
        assert!(
            hit,
            "expected a seeded-to-zero series `{metric}` with labels {labels:?}, got:\n{render}"
        );
    }

    /// Every per-channel error counter must exist at `0` from the first scrape.
    ///
    /// `increase(counter[15m]) > 0` needs two samples in the range, so the four
    /// `increase()>0` bucket alerts (`S3PollErrors`, `S3DownloadErrors`,
    /// `OverlayApplyFailing`, `MassRemovalSkipped`) would miss a bucket's first isolated
    /// error without this baseline. `gdi_s3_poll_last_success_timestamp_seconds` is seeded to
    /// boot time instead; see `poll_last_success_gauge_is_seeded_to_boot_time` below.
    #[test]
    fn per_channel_error_counters_are_seeded_to_zero() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || seed_s3_channel_series(&["alpha", "beta"]));
        let render = handle.render();

        for bucket in ["alpha", "beta"] {
            for metric in [
                S3_POLL_ERRORS_TOTAL,
                S3_DOWNLOAD_ERRORS_TOTAL,
                S3_REMOVAL_SKIPPED_TOTAL,
                // The fourth `gdi_s3_*{channel}` counter: without a seed its series is
                // absent until the first ignore rather than starting at 0.
                S3_DELETED_SIDECAR_IGNORED_TOTAL,
            ] {
                assert_seeded_zero(&render, metric, &[("channel", bucket)]);
            }
            // The writeback latch shares the label set: only the first AccessDenied sets
            // it, so without a seed a healthy bucket has no series at all.
            assert_seeded_zero(
                &render,
                S3_STATUS_WRITEBACK_DISABLED,
                &[("channel", bucket)],
            );
        }
        // `gdi_overlay_apply_failed_total` is not asserted here: `seed_channel_series`
        // seeds it so the inbox gets it too, and
        // `channel_series_are_seeded_to_exact_zero` covers it.
        assert!(
            !render.contains(OVERLAY_APPLY_FAILED_TOTAL),
            "the overlay counter must not be seeded per S3 channel: it is a shared channel \
             series, and seeding it here would leave an inbox-only node without it:\n{render}"
        );
    }

    /// `seed_always_present` must seed `gdi_datasets_suppressed{mode="hide"}`,
    /// `gdi_datasets_suppressed{mode="remove"}`, and `gdi_suppression_load_degraded` to an
    /// exact `0` at recorder install, with no suppression activity at all. This is the
    /// isolated counterpart to the shared-recorder presence check
    /// `suppression_gauges_are_seeded_to_zero` in
    /// `crates/gdi-node-standalone/tests/it/metrics_endpoint.rs`. That `it` test shares the
    /// global recorder with the rest of the binary, so another test's suppression activity
    /// can move these gauges off `0` concurrently and it can assert presence only. This test
    /// uses its own local recorder (`metrics::with_local_recorder`), so it neither races nor
    /// is raced, and can assert the `0` value `seed_always_present` promises.
    #[test]
    fn suppression_gauges_are_seeded_to_exact_zero() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, seed_always_present);
        let render = handle.render();

        for mode in [SuppressMode::Hide, SuppressMode::Remove] {
            assert_seeded_zero(&render, DATASETS_SUPPRESSED, &[("mode", mode.as_str())]);
        }
        assert_seeded_zero(&render, SUPPRESSION_LOAD_DEGRADED, &[]);
        assert_seeded_zero(&render, OVERRIDE_STORE_ABSENT, &[]);
        assert_seeded_zero(&render, CONFIG_RELOAD_FAILED_TOTAL, &[]);
    }

    /// The scrub completion-time gauge is seeded to boot time, not zero.
    ///
    /// Unseeded, the series would not exist until the first sweep finished, and an alert on
    /// `time() - gdi_store_scrub_last_run_timestamp_seconds` cannot fire on an absent series,
    /// so a node whose sweep never completed would read like one whose sweep is healthy.
    ///
    /// Seeding it to `0` like its `gdi_store_scrub_failed` sibling would be wrong: for a
    /// unix-timestamp gauge that is an age of about 56 years, firing the staleness alert on
    /// every boot, which is how an operator learns to ignore it.
    #[test]
    fn the_scrub_completion_gauge_is_seeded_to_boot_time_not_zero() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, seed_always_present);
        let render = handle.render();

        let line = render
            .lines()
            .find(|l| l.starts_with(STORE_SCRUB_LAST_RUN_TIMESTAMP_SECONDS) && !l.starts_with('#'))
            .unwrap_or_else(|| {
                panic!("{STORE_SCRUB_LAST_RUN_TIMESTAMP_SECONDS} must exist from the first scrape:\n{render}")
            });
        let value: f64 = line
            .rsplit(' ')
            .next()
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| panic!("unparseable gauge line: {line}"));

        // Plausibly "now": past 2023-11 and not in the future. A 0 seed would be ~56 years
        // stale and is what this pins against.
        assert!(
            value > 1_700_000_000.0,
            "seeded to {value}, which reads as a decades-stale sweep — that fires the \
             staleness alert on every boot"
        );
        assert!(
            value <= unix_now_seconds() + 1.0,
            "seeded into the future: {value}"
        );
    }

    /// `override_store_absent` is the only signal that a node is serving from its last
    /// known-good in-memory override set because the store on disk has gone. Nothing
    /// else moves: `gdi_datasets_suppressed` keeps reporting the retained counts, because
    /// the sampler reads the live set rather than the disk, and
    /// `gdi_suppression_load_degraded` stays `0` because nothing failed to *parse*.
    ///
    /// The gauge must fire for a node that held withholds and lost its store, even with
    /// `require_override_store` unset. That is the default, and so the configuration most
    /// likely to lose a store without noticing.
    #[test]
    fn store_loss_signal_does_not_depend_on_the_operator_setting_a_flag() {
        // Real overrides, no assertion, store gone: the case keying on the flag alone misses.
        assert!(store_loss_signal(false, true, false));
        // Asserted and gone: reported, as before.
        assert!(store_loss_signal(true, false, false));
        // Present: never a loss, however configured.
        assert!(!store_loss_signal(true, true, true));
        assert!(!store_loss_signal(false, false, true));
        // Genuinely no overrides and nothing asserted: not a loss, so a fresh node stays quiet.
        assert!(!store_loss_signal(false, false, false));
    }

    /// The case the live set structurally cannot report: the store held overrides, was
    /// destroyed, and the next load reads empty, so `holds_overrides` is false by the time
    /// anyone asks. The `ever_held` latch is the only thing that still remembers.
    ///
    /// This drives the latch itself rather than passing `true` for `has_or_had_overrides` by
    /// hand, which would pass unchanged with the latch deleted. Safe to mutate the
    /// process-global here: no other unit test in this module calls `sample_once` or
    /// `sample_override_store_presence` (the integration suite that does runs in a separate
    /// binary), and the latch only ever moves false -> true.
    #[test]
    fn the_ever_held_latch_remembers_a_store_that_has_since_read_empty() {
        // A node that has never seen an override: no memory, so no loss to report.
        assert!(
            !note_and_read_ever_held(false),
            "the latch must start clear, or every fresh node reports a phantom store loss"
        );
        assert!(!store_loss_signal(
            false,
            note_and_read_ever_held(false),
            false
        ));

        // The store is observed holding overrides. The latch closes.
        assert!(note_and_read_ever_held(true));

        // The store is destroyed: the next load reads empty, so `holds_overrides` is now
        // false, and the signal must still fire on the latch's memory alone.
        assert!(
            note_and_read_ever_held(false),
            "the latch must not re-open when the set reads empty; that empty read is the \
             incident"
        );
        assert!(
            store_loss_signal(false, note_and_read_ever_held(false), false),
            "a store destroyed after holding overrides must still signal a loss on a \
             default node (require_override_store unset)"
        );
    }

    #[test]
    fn override_store_absent_gauge_flips_and_clears() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            seed_always_present();
            override_store_absent(OverrideStoreAlarm::Suppressions, true);
        });
        assert!(
            handle
                .render()
                .contains(&format!("{OVERRIDE_STORE_ABSENT} 1")),
            "a vanished required store must raise the gauge"
        );

        metrics::with_local_recorder(&recorder, || {
            override_store_absent(OverrideStoreAlarm::Suppressions, false);
        });
        assert!(
            handle
                .render()
                .contains(&format!("{OVERRIDE_STORE_ABSENT} 0")),
            "a restored store must clear it again"
        );
    }

    /// One source must not clear another's alarm.
    ///
    /// `main` calls `reload_suppressions` and then `reload_local_overlays` two lines later.
    /// Were both to write this one gauge with `.set()`, an unreadable `suppressions/` would
    /// raise the alarm and a healthy `overlays/` would clear it microseconds afterwards. The
    /// periodic sampler repairs that only when `require_override_store` is set or the
    /// `ever_held` latch has already fired, and that latch is fed by a set which loads empty
    /// when unreadable, so on the default posture nothing would raise it at all.
    #[test]
    fn a_healthy_half_of_the_store_cannot_clear_the_other_halfs_alarm() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            seed_always_present();
            // Reset every slot: these are process-global latches and another test in this
            // binary may have set one.
            override_store_absent(OverrideStoreAlarm::Suppressions, false);
            override_store_absent(OverrideStoreAlarm::Overlays, false);
            override_store_absent(OverrideStoreAlarm::Presence, false);

            // suppressions/ is unreadable...
            override_store_absent(OverrideStoreAlarm::Suppressions, true);
            // ...and overlays/ is fine, which is the exact sequence main.rs produces.
            override_store_absent(OverrideStoreAlarm::Overlays, false);
        });
        assert!(
            handle
                .render()
                .contains(&format!("{OVERRIDE_STORE_ABSENT} 1")),
            "a healthy overlays/ reload must not clear the unreadable-suppressions alarm"
        );

        // Only when the raising source itself clears does the gauge fall.
        metrics::with_local_recorder(&recorder, || {
            override_store_absent(OverrideStoreAlarm::Suppressions, false);
        });
        assert!(
            handle
                .render()
                .contains(&format!("{OVERRIDE_STORE_ABSENT} 0")),
            "and it must still clear once the source that raised it recovers"
        );
    }

    /// `sample_once` runs on one OS thread, so the first sampler that blocks freezes every
    /// gauge behind it at its last value, and a frozen `gdi_health_ready` reads `1`, so a
    /// wedged node scrapes as healthy. The function therefore samples all in-memory gauges,
    /// readiness first, before anything that touches a filesystem.
    ///
    /// That is an invariant about the order of the source, so this test reads the source. A
    /// comment stating the rule is not enough: operators are told to put the override store
    /// on separate, often networked, storage, so a sampler that stats it belongs in phase 2
    /// however the in-memory group is worded.
    #[test]
    fn readiness_is_sampled_before_anything_that_can_stall() {
        /// Every sampler in `sample_once`'s phase 2. Each one performs filesystem I/O and
        /// can therefore block indefinitely on a hung mount.
        const FS_SAMPLERS: [&str; 6] = [
            "sample_process",
            "sample_override_store_presence",
            "sample_disk_free",
            "sample_inbox_rejected",
            // Reads the inbox directory to count encrypted drops on a keyless node, so it
            // blocks on a hung inbox mount exactly like its quarantine sibling above.
            "sample_inbox_keyless",
            "sample_vault_token_file_age",
        ];
        /// Every sampler in phase 1. These read only in-memory state, so they may precede
        /// the readiness gauges. Listed for the same reason as the protected-field list in
        /// `apply_overlay`: to make a new sampler a decision rather than an omission.
        const IN_MEMORY_SAMPLERS: [&str; 5] = [
            "sample_dataset_states",
            "sample_suppressions",
            "sample_channel_suppressions",
            "sample_query_scan_blocking",
            "sample_ingest_inflight_age",
        ];
        const READINESS: &str = "record_readiness_metrics";

        let src = include_str!("metrics.rs");
        let start = src
            .find("pub fn sample_once(")
            .expect("sample_once must exist; this guard is named after it");
        // The body ends at the first line-start `}` after the signature.
        let end = start
            + src[start..]
                .find("\n}\n")
                .expect("sample_once must have a body");
        // Strip `//` comments: the phase-1 comment names the phase-2 samplers, so a raw
        // substring search would match prose that sits above the call it is ordering
        // against.
        let body: String = src[start..end]
            .lines()
            .map(|l| l.split_once("//").map_or(l, |(code, _)| code))
            .collect::<Vec<_>>()
            .join("\n");

        // Match call syntax, not the bare name, for the same reason.
        let call = |name: &str| body.find(&format!("{name}("));
        let ready_at = call(READINESS).expect("sample_once must record the readiness gauges");

        // Completeness, derived from the body. `FS_SAMPLERS` alone covers a sampler being
        // renamed or removed, but says nothing about one being added, and a new filesystem
        // sampler appended to phase 2 would simply be absent from the list, leaving the
        // guard to check four of five and report success. Extract every `sample_*` call the
        // body makes and require each to be classified into one phase or the other, so a new
        // one fails here until someone decides which it is.
        let mut rest = body.as_str();
        while let Some(i) = rest.find("sample_") {
            let tail = &rest[i..];
            let name_len = tail
                .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .unwrap_or(tail.len());
            let name = &tail[..name_len];
            if tail[name_len..].starts_with('(') && name != "sample_once" {
                assert!(
                    FS_SAMPLERS.contains(&name) || IN_MEMORY_SAMPLERS.contains(&name),
                    "`{name}` is called from sample_once but appears in neither \
                     FS_SAMPLERS nor IN_MEMORY_SAMPLERS. Classify it: anything touching a \
                     filesystem must be ordered after {READINESS} and listed in \
                     FS_SAMPLERS; a pure in-memory read belongs in IN_MEMORY_SAMPLERS."
                );
            }
            rest = &rest[i + name_len..];
        }
        for sampler in FS_SAMPLERS {
            // A renamed sampler would otherwise drop out of the check silently and leave
            // this guard asserting less every time the code moves.
            let at = call(sampler).unwrap_or_else(|| {
                panic!(
                    "{sampler} is no longer called from sample_once — either it was renamed \
                     (update FS_SAMPLERS) or removed, and this guard is now checking less \
                     than it claims"
                )
            });
            assert!(
                ready_at < at,
                "{READINESS} must be sampled before {sampler}, which touches the \
                 filesystem and can block forever on a hung mount. As ordered, a wedged \
                 volume freezes gdi_health_ready at its last value (1 = ready) for the \
                 life of the process."
            );
        }
    }

    /// `config_reload_failed` increments the counter: the `SIGHUP` reload handler counts a
    /// failed reload attempt so `ConfigReloadFailed`
    /// (`increase(gdi_config_reload_failed_total[15m]) > 0`) can fire.
    #[test]
    fn config_reload_failed_increments_the_counter() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            seed_always_present();
            config_reload_failed();
            config_reload_failed();
        });
        let render = handle.render();
        assert!(
            render
                .lines()
                .any(|l| l.starts_with(CONFIG_RELOAD_FAILED_TOTAL) && l.ends_with(" 2")),
            "two failed reloads must read 2:\n{render}"
        );
    }

    /// All three at-rest forms must render as their own series, and `encrypted` must be a
    /// counted form rather than `total - plaintext`, which would over-report a store with a
    /// deleted parquet.
    ///
    /// The alert `DatasetsIndeterminateAtRest` selects `form="indeterminate"`, so the label
    /// value is a wire contract between this emitter and the rules file. A rename here would
    /// leave the alert matching nothing, which `promtool` cannot detect: it checks syntax,
    /// not whether any series will ever satisfy the selector.
    #[test]
    fn at_rest_renders_three_counted_forms_including_indeterminate() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            seed_always_present();
            // 1 plaintext, 1 encrypted, 2 with no readable parquet.
            record_at_rest(1, 1, 2);
        });
        let render = handle.render();
        for (form, want) in [
            ("plaintext", "1"),
            ("encrypted", "1"),
            ("indeterminate", "2"),
        ] {
            let series = format!("{DATASETS_AT_REST}{{form=\"{form}\"}} {want}");
            assert!(
                render.lines().any(|l| l == series),
                "expected `{series}` in:\n{render}"
            );
        }
    }

    /// The poll-success timestamp gauge is seeded to boot time, never to `0`.
    ///
    /// Left unseeded, a bucket that has never polled successfully (endpoint dead from boot)
    /// has no `gdi_s3_poll_last_success_timestamp_seconds{channel}` series at all, so
    /// `S3PollerWedged`, a `time() - <gauge>` staleness expression, evaluates to no data and
    /// never fires for the bucket it exists to catch.
    ///
    /// Seeding to boot time creates the series without the false positive a `0` seed would
    /// cause: `time() - 0` is stale on every cold boot, whereas `time() - boot` starts at 0
    /// and grows only if no poll ever succeeds, which is the alert condition. Same rationale
    /// as `INGEST_LAST_PROGRESS_TIMESTAMP_SECONDS` in `seed_always_present`.
    #[test]
    fn poll_last_success_gauge_is_seeded_to_boot_time() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let before = unix_now_seconds();
        metrics::with_local_recorder(&recorder, || seed_s3_channel_series(&["alpha"]));
        let render = handle.render();

        let value = render
            .lines()
            .find(|line| {
                line.starts_with(S3_POLL_LAST_SUCCESS_TIMESTAMP_SECONDS) && line.contains("channel=\"alpha\"")
            })
            .and_then(|line| line.rsplit(' ').next())
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or_else(|| {
                panic!(
                    "a never-polled bucket must still have a {S3_POLL_LAST_SUCCESS_TIMESTAMP_SECONDS} \
                     series, or S3PollerWedged is no-data for exactly the bucket it must \
                     catch; got:\n{render}"
                )
            });

        assert!(
            value >= before,
            "must be seeded to boot time, not 0 (a 0 seed makes S3PollerWedged fire on \
             every cold boot); got {value}"
        );
    }

    /// No configured buckets (a `lite` node, or `[s3]` absent) seeds nothing.
    #[test]
    fn seeding_no_buckets_emits_no_series() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || seed_s3_channel_series(&[]));
        assert!(!handle.render().contains("gdi_s3_poll_errors_total"));
    }

    /// `gdi_channel_suppressed{channel}` must be seeded to an exact `0` for every
    /// configured channel name (bucket names plus `inbox`), the isolated counterpart to the
    /// bucket-series seeding tests above. The `{channel}` label set is likewise
    /// config-dependent, so `seed_always_present` cannot know it.
    #[test]
    fn channel_series_are_seeded_to_exact_zero() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            seed_channel_series(&["primary", "inbox"]);
        });
        let render = handle.render();
        for channel in ["primary", "inbox"] {
            assert_seeded_zero(&render, CHANNEL_SUPPRESSED, &[("channel", channel)]);
            // The two sidecar-rejection counters, seeded for every channel. The inbox case
            // is the one that matters: bucket-labelled and bucket-seeded, the overlay
            // counter would leave an inbox-only node with no series to alert on.
            for reason in OVERLAY_APPLY_REASONS {
                assert_seeded_zero(
                    &render,
                    OVERLAY_APPLY_FAILED_TOTAL,
                    &[("channel", channel), ("reason", reason)],
                );
            }
            for reason in StateSidecarRejectReason::ALL {
                assert_seeded_zero(
                    &render,
                    STATE_SIDECAR_REJECTED_TOTAL,
                    &[("channel", channel), ("reason", reason.as_str())],
                );
            }
        }
    }

    /// No configured channels (no `[s3.buckets]`, no `[service].inbox`) seeds no
    /// per-channel series — except the node-local override feed, which always exists.
    #[test]
    fn seeding_no_channels_emits_no_series() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || seed_channel_series(&[]));
        let render = handle.render();
        assert!(!render.contains(CHANNEL_SUPPRESSED));
        // The override store is not configured per channel, so its overlay-rejection series
        // is seeded unconditionally — an operator can have a degraded override store on a
        // node with no inbox and no bucket at all.
        assert!(
            render.lines().any(|l| {
                l.starts_with(OVERLAY_APPLY_FAILED_TOTAL)
                    && l.contains("channel=\"local-override\"")
                    && l.ends_with(" 0")
            }),
            "the local-override overlay series is always seeded:\n{render}"
        );
    }

    /// A failed renewal is only a fault when the re-login that follows it also fails, and
    /// the two outcomes must be separable.
    ///
    /// A renewable token cannot be renewed past `token_max_ttl`, so reaching that ceiling
    /// always fails one renewal and then re-logs in successfully. Keyed on
    /// `gdi_vault_renewal_failures_total` alone, `VaultRenewalFailing` would page `critical`
    /// on a healthy node once per `token_max_ttl`, which at the documented `token_ttl=1h`
    /// and `token_max_ttl=24h` is daily. This counter lets the alert keep `critical` and
    /// lose the false positives.
    #[test]
    fn vault_reauth_outcomes_are_separable_and_both_seeded() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            for outcome in VAULT_REAUTH_OUTCOMES {
                metrics::counter!(VAULT_REAUTH_TOTAL, "outcome" => outcome).increment(0);
            }
            // The routine max-TTL rollover: renewal failed, re-login worked.
            vault_reauth("recovered");
        });
        let render = handle.render();
        assert!(
            render.lines().any(|l| {
                l.starts_with(VAULT_REAUTH_TOTAL)
                    && l.contains("outcome=\"recovered\"")
                    && l.ends_with(" 1")
            }),
            "the routine rollover must be counted as recovered:\n{render}"
        );
        assert!(
            render.lines().any(|l| {
                l.starts_with(VAULT_REAUTH_TOTAL)
                    && l.contains("outcome=\"failed\"")
                    && l.ends_with(" 0")
            }),
            "the fault series must be seeded at 0 and must not move for a recovered \
             rollover; the two outcomes are separate:\n{render}"
        );
    }

    /// `channel_suppressed` sets the gauge to `1`/`0` per channel independently.
    #[test]
    fn channel_suppressed_setter_toggles_the_gauge() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            seed_channel_series(&["primary", "inbox"]);
            channel_suppressed("primary", true);
        });
        let render = handle.render();
        assert!(
            render.lines().any(|l| l.starts_with(CHANNEL_SUPPRESSED)
                && l.contains("channel=\"primary\"")
                && l.ends_with(" 1")),
            "suppressed channel must read 1:\n{render}"
        );
        assert_seeded_zero(&render, CHANNEL_SUPPRESSED, &[("channel", "inbox")]);
    }

    /// The keyless-backlog gauge counts encrypted drops a keyless node cannot ingest, and
    /// reads a real zero once keys exist.
    ///
    /// The skip itself is correct: a `.tar.c4gh` on a node with no identity is left for a
    /// later keyed run rather than failed. It carries no dataset state and no quarantine,
    /// so without this gauge its only trace is an `INFO` line the common `GDI_LOG=warn`
    /// posture drops, and a provider could drop packages indefinitely into a misconfigured
    /// node with nothing to show for it.
    #[test]
    fn inbox_keyless_gauge_counts_undecryptable_drops_and_zeroes_when_keyed() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("GDI-EE-UTARTU-20260409143052837.tar.c4gh"),
            b"enc",
        )
        .expect("write package");
        std::fs::write(
            tmp.path().join("GDI-EE-UTARTU-20260409143052838.tar.c4gh"),
            b"enc",
        )
        .expect("write package");
        // Neither of these is an encrypted package: a plaintext staging dir, which a
        // keyless node can ingest, and a state sidecar. Counting them would make the gauge
        // fire on a healthy keyless inbox.
        std::fs::create_dir(tmp.path().join("GDI-EE-UTARTU-20260409143052839"))
            .expect("create staging dir");
        std::fs::write(
            tmp.path()
                .join("GDI-EE-UTARTU-20260409143052839.state.json"),
            b"{}",
        )
        .expect("write sidecar");

        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            sample_inbox_keyless(Some(tmp.path()), false);
        });
        let render = handle.render();
        assert!(
            render
                .lines()
                .any(|l| l.starts_with(INBOX_KEYLESS_PACKAGES) && l.ends_with(" 2")),
            "only the two .tar.c4gh drops count, not the staging dir or the sidecar:\n{render}"
        );

        // A keyed node reports 0 rather than not reporting: an absent series and a healthy
        // zero are indistinguishable to an alert, and this one must be able to say
        // "healthy" out loud while the same packages are still on disk.
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            sample_inbox_keyless(Some(tmp.path()), true);
        });
        let render = handle.render();
        assert!(
            render
                .lines()
                .any(|l| l.starts_with(INBOX_KEYLESS_PACKAGES) && l.ends_with(" 0")),
            "a keyed node must emit an explicit 0, not omit the series:\n{render}"
        );
    }

    /// The quarantine backlog gauge counts both shapes: a rejected `.tar.c4gh` package,
    /// which `ingest_runtime::quarantine` renames wholesale into `.rejected/{id}` as a
    /// regular file, and the staging-dir case that lands as a directory.
    ///
    /// The encrypted `.tar.c4gh` drop is the documented production ingress, so a sampler
    /// that counts directories only pins `gdi_inbox_rejected_packages` at `0` on the
    /// intended topology and makes `InboxQuarantineBacklog` structurally dead.
    #[test]
    fn inbox_rejected_gauge_counts_quarantined_packages_not_only_dirs() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let rejected = tmp.path().join(".rejected");
        std::fs::create_dir_all(&rejected).expect("create .rejected");
        // A quarantined `.tar.c4gh` package: a file named for the dataset id.
        std::fs::write(rejected.join("GDI-EE-UTARTU-20260409143052837"), b"pkg")
            .expect("write package");
        // A quarantined staging dir. Both are quarantine entries.
        std::fs::create_dir(rejected.join("GDI-EE-UTARTU-20260409143052838"))
            .expect("create staging dir");

        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || sample_inbox_rejected(Some(tmp.path())));
        let render = handle.render();

        assert!(
            render
                .lines()
                .any(|l| l.starts_with(INBOX_REJECTED_PACKAGES) && l.ends_with(" 2")),
            "both the quarantined package file and the staging dir must count:\n{render}"
        );
    }

    /// A gauge whose source can fail must publish its own health, because a failed sample
    /// is not a missing data point. The exporter is a registry rendered on demand with no
    /// idle timeout, so a gauge that stops being set keeps rendering its last value forever.
    /// Without a companion series, a `statvfs` failure is indistinguishable from a healthy
    /// volume at every scrape, and `LowDisk`, the only `severity: critical` threshold alert
    /// on a sampled gauge, evaluates a frozen number.
    #[test]
    fn disk_sample_publishes_health_on_failure() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            sample_disk_free(std::path::Path::new("/nonexistent-gdi-audit-volume"));
        });
        let render = handle.render();

        assert!(
            render
                .lines()
                .any(|l| l.starts_with(DISK_SAMPLE_FAILED) && l.ends_with(" 1")),
            "a failed statvfs must publish gdi_disk_sample_failed=1:\n{render}"
        );
    }

    /// The healthy arm must publish `0`, not merely omit the series — an alert cannot
    /// distinguish a missing series from a healthy one.
    #[test]
    fn disk_sample_publishes_health_on_success() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || sample_disk_free(tmp.path()));
        let render = handle.render();

        assert!(
            render
                .lines()
                .any(|l| l.starts_with(DISK_SAMPLE_FAILED) && l.ends_with(" 0")),
            "a successful statvfs must publish gdi_disk_sample_failed=0:\n{render}"
        );
    }

    /// Seeded at install for the same reason every other health gauge is: an unseeded
    /// series never trips a `> 0` alert reliably, because Prometheus cannot tell "never
    /// failed" from "not scraped".
    #[test]
    fn disk_sample_health_is_seeded_to_zero() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, seed_always_present);
        assert_seeded_zero(&handle.render(), DISK_SAMPLE_FAILED, &[]);
    }

    /// An inbox the keyless sampler cannot read is a fault, not a healthy zero. Publishing
    /// `0` on a `read_dir` failure would say "no packages waiting" about an inbox nobody can
    /// see into. The failure is warned instead, once until a sample succeeds again, since
    /// the sampler runs on a timer and the inbox stays unreadable until someone acts.
    #[test]
    fn keyless_sampler_warns_once_while_the_inbox_cannot_be_read() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let inbox = tmp.path().join("gone");
        let logs = test_util::capture_json_logs(|| {
            sample_inbox_keyless(Some(&inbox), false);
            sample_inbox_keyless(Some(&inbox), false);
        })
        .1;
        assert_eq!(
            logs.matches("inbox could not be read").count(),
            1,
            "two failed samples warn once, not once per tick: {logs}"
        );
        // A successful sample re-arms the latch, so a later outage is news again.
        std::fs::create_dir_all(&inbox).expect("inbox");
        sample_inbox_keyless(Some(&inbox), false);
        std::fs::remove_dir_all(&inbox).expect("remove");
        let logs = test_util::capture_json_logs(|| sample_inbox_keyless(Some(&inbox), false)).1;
        assert_eq!(
            logs.matches("inbox could not be read").count(),
            1,
            "after a good sample the next failure warns again: {logs}"
        );
    }

    /// Every curated series must carry `# HELP` text: one `describe_*` per
    /// `pub const NAME: &str = "gdi_…"`. Nothing else binds the two lists, so without this a
    /// seeded, alerted, runbook-documented series can render a `# TYPE` line and no
    /// `# HELP` line.
    #[test]
    fn every_declared_metric_is_described() {
        const SRC: &str = include_str!("metrics.rs");
        let production = SRC.split("\n#[cfg(test)]").next().unwrap_or(SRC);

        let mut declared: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for (idx, _) in production.match_indices("pub const ") {
            let rest = &production[idx + "pub const ".len()..];
            let Some(colon) = rest.find(':') else {
                continue;
            };
            let ident = &rest[..colon];
            let Some(after) = rest[colon + 1..].trim_start().strip_prefix("&str") else {
                continue;
            };
            let Some(after) = after.trim_start().strip_prefix('=') else {
                continue;
            };
            if after.trim_start().starts_with("\"gdi_") {
                declared.insert(ident.to_owned());
            }
        }
        assert!(
            declared.len() >= 70,
            "parsed only {} metric consts — the parser broke and this guard would pass by \
             checking nothing: {declared:?}",
            declared.len()
        );

        let mut described: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for macro_name in [
            "describe_gauge!(",
            "describe_counter!(",
            "describe_histogram!(",
        ] {
            for (idx, _) in production.match_indices(macro_name) {
                let body = production[idx + macro_name.len()..].trim_start();
                let ident: String = body
                    .chars()
                    .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
                    .collect();
                described.insert(ident);
            }
        }
        let missing: Vec<&String> = declared.difference(&described).collect();
        assert!(
            missing.is_empty(),
            "declared series with no describe_* (they render with no HELP line): {missing:?}"
        );
    }

    /// Every `code` [`record_beacon_query_rejected`] can emit is seeded at install, so the
    /// first rejection of any kind is a real `increase()` rather than a series born at 1,
    /// and the mapper cannot grow a code the seed does not know about. The 2xx/5xx request
    /// cells and the split-block counter ride on the same seed.
    #[test]
    fn beacon_rejection_codes_are_all_seeded() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, seed_always_present);
        let seeded = handle.render();
        for entry_type in BEACON_ENTRY_TYPES {
            for code in BEACON_REJECT_CODES {
                assert_seeded_zero(
                    &seeded,
                    BEACON_QUERY_REJECTED_TOTAL,
                    &[("entry_type", entry_type), ("code", code)],
                );
            }
            for class in SEEDED_STATUS_CLASSES {
                assert_seeded_zero(
                    &seeded,
                    BEACON_REQUESTS_TOTAL,
                    &[("entry_type", entry_type), ("status_class", class)],
                );
            }
        }
        assert_seeded_zero(&seeded, BEACON_MERGED_BLOCKS_TOTAL, &[]);

        // Recording every status the mapper distinguishes (plus one it folds to `other`)
        // must create no series the seed did not already render.
        let count = |render: &str| {
            render
                .lines()
                .filter(|l| l.starts_with(BEACON_QUERY_REJECTED_TOTAL))
                .count()
        };
        let before = count(&seeded);
        metrics::with_local_recorder(&recorder, || {
            for code in [400, 413, 500, 418] {
                record_beacon_query_rejected("genomicVariant", code);
            }
        });
        let after = handle.render();
        assert_eq!(
            before,
            count(&after),
            "a rejection code escaped the seeded set — add it to BEACON_REJECT_CODES:\n{after}"
        );
    }

    /// The FDP request counter is seeded per resource type x `2xx`/`5xx` by the
    /// config-conditional `seed_fairdp_series` (only when `[fairdp]` is mounted), so a
    /// node nobody has crawled renders a flat zero rather than nothing.
    #[test]
    fn fairdp_request_counter_is_seeded_per_resource_type() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, seed_fairdp_series);
        let render = handle.render();
        for resource_type in FAIRDP_RESOURCE_TYPES {
            for class in SEEDED_STATUS_CLASSES {
                assert_seeded_zero(
                    &render,
                    FAIRDP_REQUESTS_TOTAL,
                    &[("resource_type", resource_type), ("status_class", class)],
                );
            }
        }
    }

    /// Every `.rs` under `dir`, recursively.
    fn source_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read src dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                source_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    /// The module header's privacy invariant lists the label keys this crate emits, and a
    /// privacy claim nobody can check is one nobody re-checks when a label that matters
    /// lands. The header carries one machine-readable `label keys:` line, bound here to the
    /// keys actually passed to `gauge!`, `counter!` and `histogram!` in every source file of
    /// this crate. The claim is crate-wide, so the check must be too: bound to `metrics.rs`
    /// alone it would miss `error_class` in `ingest_runtime.rs` and `s3.rs`, and the next
    /// `"object_key" => key` beside one of those would ship a dataset id as a label.
    ///
    /// Each file's test-gated modules are cut out by `test_util::production_text`, which is
    /// brace-matched and string- and comment-aware, since a file may hold several with
    /// production code between them as `s3.rs` does. Test-only labels (`k` in
    /// `metrics_otel`) are therefore not counted, and no production emit site is skipped.
    #[test]
    fn module_header_names_exactly_the_label_keys_the_module_emits() {
        const SRC: &str = include_str!("metrics.rs");

        let mut files = Vec::new();
        source_files(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut files,
        );
        files.sort();
        assert!(
            files.len() >= 20,
            "found only {} source files under src/ — the walk broke",
            files.len()
        );

        let mut emitted: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for file in &files {
            let text = std::fs::read_to_string(file).expect("read source file");
            let production = test_util::production_text(&text);
            let production = production.as_str();
            for macro_name in ["gauge!(", "counter!(", "histogram!("] {
                for (idx, _) in production.match_indices(macro_name) {
                    let body = &production[idx + macro_name.len()..];
                    // The balanced argument list of this invocation.
                    let mut depth = 1usize;
                    let mut end = 0usize;
                    for (i, ch) in body.char_indices() {
                        match ch {
                            '(' => depth += 1,
                            ')' => {
                                depth -= 1;
                                if depth == 0 {
                                    end = i;
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                    let args = &body[..end];
                    // Every `"key" =>` inside it is a label key.
                    let mut rest = args;
                    while let Some(open) = rest.find('"') {
                        let after = &rest[open + 1..];
                        let Some(close) = after.find('"') else { break };
                        let key = &after[..close];
                        let tail = after[close + 1..].trim_start();
                        if tail.starts_with("=>")
                            && !key.is_empty()
                            && key.chars().all(|c| c.is_ascii_lowercase() || c == '_')
                        {
                            emitted.insert(key.to_owned());
                        }
                        rest = &after[close + 1..];
                    }
                }
            }
        }
        assert!(
            emitted.contains("error_class"),
            "`error_class` is emitted from ingest_runtime.rs/s3.rs; the cross-file scan \
             has stopped seeing other files: {emitted:?}"
        );
        assert!(
            emitted.len() >= 15,
            "parsed only {} label keys from the macro invocations; the parser broke and \
             this guard would pass by checking nothing: {emitted:?}",
            emitted.len()
        );

        let header_line = SRC
            .lines()
            .find(|l| l.starts_with("//! label keys:"))
            .expect("the module header carries a `//! label keys:` line");
        let declared: std::collections::BTreeSet<String> = header_line
            .split('`')
            .skip(1)
            .step_by(2)
            .map(str::to_owned)
            .collect();
        assert_eq!(
            declared, emitted,
            "the header's `label keys:` line must name exactly the keys this module passes \
             to gauge!/counter!/histogram!"
        );
    }
}
