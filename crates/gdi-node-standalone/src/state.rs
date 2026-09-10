//! Shared, cheaply-cloneable service state.
//!
//! [`AppState`] bundles the in-memory metadata cache, the persistent status index and the
//! loaded service configuration behind cheap clones (`Arc` / handle), so it is shared across
//! the ingest workers, the inbox watcher and the HTTP handlers.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use gdi_node_standalone_core::{
    cache::MetadataCache,
    cache::StatusEntry,
    cache::StatusIndex,
    cache::StatusWrite,
    config::{Reloadable, ServiceConfig},
    model::ManifestMetadata,
    overlay_override::{self, LocalOverlaySet},
    overlay_store, override_store,
    parquet_io::{DatasetDecryptor, DatasetEncryptor},
    query_stats::QueryStats,
    reingest_request,
    state::DatasetState,
    suppression::{self, SuppressMode, SuppressionSet},
};

use crate::control_http::ReloadRejection;
use crate::health::Readiness;
use crate::identities::NodeIdentities;
use crate::metrics::OverrideStoreAlarm;

/// What a re-ingest request finds for an id. Both `POST /datasets/{id}/reingest` and the
/// marker drain act on this one classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReingestVerdict {
    /// No status entry: never seen, or already erased, so there is nothing to clear.
    Unknown,
    /// An entry exists but clearing its signature would change nothing: an inbox-owned
    /// id (the inbox gate never consults the signature), a live id (already served), or
    /// an errored id whose signature was never recorded.
    NotRetriable,
    /// A bucket-owned `error` entry with a recorded signature: clearing it makes the
    /// next reconcile present the unchanged package to ingest again.
    Retriable,
}

/// The pure half of the verdict, over one status entry.
fn classify_reingest(entry: Option<&StatusEntry>) -> ReingestVerdict {
    let Some(entry) = entry else {
        return ReingestVerdict::Unknown;
    };
    if entry.channel == "inbox"
        || entry.last_seen_signature.is_none()
        || entry.state != DatasetState::Error
    {
        return ReingestVerdict::NotRetriable;
    }
    ReingestVerdict::Retriable
}

/// The ingest runtime's in-flight markers: dataset id → the instant it was marked.
/// See [`AppState::ingest_inflight`].
pub type IngestInflight = Arc<Mutex<HashMap<String, Instant>>>;

/// The shared service state.
///
/// Cloning is cheap: [`MetadataCache`] is an `Arc` handle, and the status index, config and
/// identities are wrapped in `Arc`. The status index sits behind a synchronous
/// [`std::sync::Mutex`], locked only for short read/modify/persist sections, so no guard is
/// held across an `.await`.
#[derive(Clone)]
pub struct AppState {
    /// In-memory dataset cache (the query-time source of truth).
    pub cache: MetadataCache,
    /// Persistent `datasets/.status.json` index (provenance, signatures, errors).
    pub status: Arc<Mutex<StatusIndex>>,
    /// Serializes status-index writes so a persist's blocking fsync runs outside the
    /// [`status`](Self::status) lock, which the management plane also takes. The guarded
    /// `u64` is the sequence of the last snapshot durably written: a persist whose sequence
    /// is not strictly greater is skipped, so a serialize/write reordering cannot regress
    /// `.status.json` to an older snapshot. See
    /// [`persist_status_index`](Self::persist_status_index).
    pub persist_lock: Arc<Mutex<u64>>,
    /// Monotonic sequence assigned to each status snapshot while the
    /// [`status`](Self::status) lock is held, so sequence order equals serialize order.
    /// Paired with [`persist_lock`](Self::persist_lock) to reject a stale, out-of-order
    /// durable write.
    pub persist_seq: Arc<AtomicU64>,
    /// The loaded, preflighted service configuration.
    pub config: Arc<ServiceConfig>,
    /// Ids observed deleted from their source bucket while mid-ingest.
    ///
    /// The S3 reconcile records an id here when its `.tar.c4gh` vanishes from the bucket
    /// during that id's ingest. `ingest_runtime::on_success` consumes the mark and publishes
    /// the finished dataset Hidden instead of the captured `Visible`, so a package deleted
    /// mid-ingest is never briefly served; the next reconcile then evicts it.
    /// `ingest_runtime::finish_job` clears the mark on every terminal outcome, not only the
    /// success arm that consumes it, which bounds the set by the number of concurrent
    /// ingests.
    pub removal_requested: Arc<Mutex<HashSet<String>>>,
    /// Ids whose source package was seen deleted during ingest, published Hidden, and which
    /// the owning bucket monitor must still confirm and evict.
    ///
    /// The in-flight guard excludes a mid-ingest id from the monitor's `absent` set, so the
    /// racing poll records no removal streak, and `plan_removals` ignores a fresh absence
    /// with `prior_streak == 0` on a timer-only pass. The dataset stays withheld either way,
    /// but without this it could sit on disk until an unrelated marker bump or a restart,
    /// which matters for a source-side erasure. This carries the streak the racing poll could
    /// not record across to the monitor that can act on it.
    pub removal_seeds: Arc<Mutex<HashSet<String>>>,
    /// Why the last operator metadata-overlay (`{id}.metadata.json`) apply attempt was
    /// rejected, per dataset. The reason is a closed set: `fetch` | `parse` | `validate`.
    ///
    /// Set when an overlay is dropped (last-good metadata kept), cleared when one applies or
    /// reverts. Transient and in-memory; a re-present re-derives it. Surfaced on
    /// `GET /datasets/{id}/state` as `overlay_error` so the orchestrator can tell a
    /// silently-dropped correction from an applied one.
    pub overlay_errors: Arc<Mutex<HashMap<String, String>>>,
    /// Why the last visibility sidecar (`{id}.state.json`) was rejected, per dataset. The
    /// reason is a closed set: `unreadable` | `unrecognized`.
    ///
    /// The state-sidecar counterpart of [`Self::overlay_errors`], and the more consequential
    /// of the two: an unparseable sidecar fails the dataset safe to `hidden`, so a truncated
    /// write withdraws a live dataset. Without a machine-readable surface no alert can fire
    /// on that. Transient and in-memory; cleared when a sidecar for the id parses cleanly, or
    /// when the id is re-ingested or erased.
    pub state_sidecar_errors: Arc<Mutex<HashMap<String, String>>>,
    /// Ids whose most recent changed re-drop under a live (immutable) id was ignored, mapped
    /// to the RFC3339 time it was observed.
    ///
    /// A live dataset is immutable, so a corrected re-upload under the same id is quarantined
    /// (inbox) or dropped (S3) with the live entry left `visible` and `error_message: null`,
    /// which is no signal at all to the provider. Surfaced on `GET /datasets/{id}/state` as
    /// `superseded_redrop` so `deploy --wait`, `status` and a back-office can tell a
    /// silently-ignored correction from a landed one, and so a same-millisecond id collision
    /// discarding a second dataset is visible. Transient and in-memory; cleared when the id
    /// is re-ingested or erased.
    pub superseded_redrops: Arc<Mutex<HashMap<String, String>>>,
    /// Operator suppression overrides (`[service].override_dir`/`suppressions/`), loaded at
    /// boot and re-read on SIGUSR1 by [`Self::reload_suppressions`]. Behind an `RwLock`
    /// rather than the `status` `Mutex`: it is read on every
    /// [`Self::apply_suppressions_to_cache`] pass and written only on a reload, so the common
    /// case is many concurrent readers and one occasional writer.
    pub suppressions: Arc<RwLock<SuppressionSet>>,
    /// Node-local operator metadata-overlay overrides (`[service].override_dir`/
    /// `overlays/`), loaded at boot and re-read on SIGUSR1 by
    /// [`Self::reload_local_overlays`]. They feed the overlay engine
    /// ([`gdi_node_standalone_core::overlay_store`]) and take precedence over a bucket or
    /// inbox `{id}.metadata.json` sidecar for the same id: while an id has a node-local
    /// override, `ingest_runtime::reconcile_overlay`/`reconcile_overlay_reverts` and
    /// `s3::BucketMonitor::apply_overlay_change` skip the source-authored sidecar entirely
    /// (see [`Self::local_overlay_present`]). Same `RwLock` rationale as
    /// [`suppressions`](Self::suppressions).
    pub local_overlays: Arc<RwLock<LocalOverlaySet>>,
    /// The `SIGHUP`-reloadable config subset: `[catalogs]` plus the `[ingest]` writer-key
    /// allow-list. A small `Arc<RwLock<Arc<Reloadable>>>` cell rather than the whole `config`
    /// `Arc`, so everything else stays on the immutable boot [`config`](Self::config) and is
    /// restart-only for free. A reader clones the inner `Arc` under a brief read lock via
    /// [`Self::reloadable`], then reads the clone lock-free; [`Self::reload_config_from`]
    /// swaps the whole inner `Arc` under the write lock, so a reader racing the swap observes
    /// a complete old-or-new snapshot. std `RwLock`, not `arc-swap`: this is read at
    /// FDP-request and ingest-job frequency, not on the beacon hot path, which reads only
    /// boot-immutable fields.
    pub reloadable: Arc<RwLock<Arc<Reloadable>>>,
    /// Wakes every S3 bucket monitor's poll loop to run an immediate reconcile. Fired on
    /// `SIGUSR1` after a suppression reload, so a just-authored override reaches S3-owned
    /// datasets without waiting out the bucket's poll interval. Best-effort:
    /// [`tokio::sync::Notify::notify_waiters`] wakes only the monitors currently parked in
    /// their `select!`, and the periodic full poll remains the safety net for one that was
    /// mid-reconcile.
    pub reconcile_trigger: Arc<tokio::sync::Notify>,
    /// The `requested_at` stamp of the last reingest marker this process acted on, per
    /// dataset id. See [`Self::process_reingest_requests`].
    ///
    /// Per-process and in-memory, not persisted and not in the override store: the marker is
    /// shared state, but "have I acted on it" is not. A restart re-reconciles every dataset
    /// anyway, so re-applying a still-present marker once per boot costs nothing the boot
    /// does not already do.
    pub reingest_applied: Arc<Mutex<HashMap<String, String>>>,
    /// Per-source exponential backoff for ids whose last ingest hit a transient error, one
    /// that is not quarantined and retries. Paces re-ingest so a fast reconcile trigger
    /// cannot hot-loop a persistently-failing backend; cleared per id on the first success.
    /// See [`crate::ingest_backoff`].
    pub retry_backoff: Arc<crate::ingest_backoff::RetryBackoff>,
    /// Count of Beacon `g_variants` per-dataset parquet scans currently running on tokio's
    /// shared `spawn_blocking` pool. Incremented inside the blocking closure, so a scan
    /// detached by a request timeout is still counted until it finishes; `spawn_blocking` is
    /// not cancellable. Sampled into the `gdi_beacon_scan_blocking_inflight` gauge by the
    /// periodic sampler, which runs on a dedicated thread and so reports even when the pool
    /// is saturated. Ingest is bounded by `ingest_concurrency` + `DETACHED_HEADROOM` but the
    /// query fan-out is not, so scan accumulation can starve ingest on the shared pool while
    /// the async health probes stay green. This gauge only reports that; it does not refuse
    /// scans to reserve ingest headroom.
    pub query_scan_blocking: Arc<AtomicUsize>,
    /// Start instant of every ingest currently in flight, queued or being processed, keyed by
    /// dataset id. This is also the ingest runtime's dedup marker: inserted when an id is
    /// enqueued, removed when its outcome has been applied, or for a timed-out job when its
    /// detached blocking task ends. It lives here rather than inside the runtime so the
    /// periodic sampler can read the oldest age into
    /// `gdi_ingest_inflight_oldest_age_seconds`, the stuck-ingest signal: one marker that
    /// never releases raises it without bound, a stream of short overlapping ingests cannot.
    pub ingest_inflight: IngestInflight,
    /// The process-wide retained-scan-row byte budget (`[service].max_total_query_bytes`),
    /// shared by every in-flight `g_variants` query.
    ///
    /// The per-request `max_query_bytes` ceiling cannot express an aggregate: with
    /// `max_concurrent_requests` defaulting to 64, that alone allows 64 independent full
    /// allowances. A query whose rows would push the process past this budget is shed with
    /// `503` rather than admitted and allocated.
    pub query_memory_budget: Arc<crate::beacon_http::QueryMemoryBudget>,
    /// Rotating cursor into `cache.ids()` for the sweep's digest tier.
    ///
    /// The readability sweep checks every dataset every pass, but a digest check rehashes
    /// whole files, so it is spread across passes instead: each sweep verifies the next slice
    /// and the cursor advances, giving every dataset periodic at-rest verification at bounded
    /// per-pass cost.
    pub digest_scrub_cursor: Arc<AtomicUsize>,
    /// Ids currently carrying a `deleted` tombstone sidecar in the inbox.
    ///
    /// A derived cache of what the inbox scan already computes, never the source of truth:
    /// the sidecar on disk is the durable record and this is rebuilt from it on every scan,
    /// startup included. The tombstone is the erasure record and the only thing suppressing
    /// re-ingest of a package still sitting in the inbox, so an in-memory authority could
    /// un-erase a dataset across a crash.
    ///
    /// The state oracle uses it to distinguish "deleted" from "never ingested", which a bare
    /// `404` conflates, leaving `deploy --wait` to poll out its whole timeout.
    pub tombstoned: Arc<RwLock<HashSet<String>>>,
    /// The node's crypt4gh identities (zeroize-backed; empty when keyless). Tried
    /// in order to decrypt `.tar.c4gh`; the first is the published recipient.
    pub identities: Arc<NodeIdentities>,
    /// The shared per-subsystem readiness view backing `/health/ready`
    /// (cheaply-cloneable atomic flags). Subsystems write their health; the probe
    /// reads a snapshot. See [`crate::health`].
    pub readiness: Readiness,
    /// The `POST /reload` action, installed by `main` at boot once the ingest runtime and
    /// bucket-monitor set it reloads exist; the management router is built before them. Holds
    /// the endpoint's rate-limit clock too. Empty on a node that never installed one, such as
    /// the CLI one-shots, which the route reports as `503` rather than as a failed reload.
    pub reload_hook: Arc<crate::control_http::ReloadHook>,
    /// The `POST /reconcile` action, the `SIGUSR1` pass, installed by `main` beside
    /// [`reload_hook`](Self::reload_hook) for the same reason and with the same `503` before
    /// it exists.
    pub reconcile_hook: Arc<crate::control_http::ReconcileHook>,
    /// The `POST /log-level` auto-revert window. Needs nothing from `main`: the level lives
    /// in [`crate::logging`], so this holds only the generation counter that keeps a
    /// scheduled revert from overriding a later decision.
    pub log_level_window: Arc<crate::control_http::LogLevelWindow>,
    /// Per-dataset query counters backing the management plane's `GET /stats/queries`,
    /// recording only when `[stats].enabled`. Written by the Beacon and FDP answer paths,
    /// all synchronous, so its `Mutex` is never held across an `.await`; read only when the
    /// endpoint is polled. The boot stamp the snapshot carries comes from
    /// [`readiness`](Self::readiness), so the node has one process-start fact, not two.
    pub query_stats: Arc<QueryStats>,
    /// The PME runtime: the Vault-minting DEK source plus cached key retriever, set only
    /// when PME is active (compiled `pme` feature and a configured `[vault].transit_key`).
    /// `None` means plaintext writes and reads.
    #[cfg(feature = "pme")]
    pub pme: Option<Arc<crate::pme::PmeRuntime>>,
}

/// What a successful reload applied, and whether the file also carried something it could not.
///
/// `restart_required` tells the operator whether the edit took effect. Restart-only edits are
/// the common case (every opt-in flag, and every `endpoint`/`bucket`/`prefix` change), so a
/// flat `applied: true` would mislead.
#[derive(Debug, Clone)]
pub struct AppliedReload {
    /// The config that was validated and whose reloadable subset was swapped in.
    pub config: ServiceConfig,
    /// Whether the same file also changed a setting outside the reloadable subset, which was
    /// therefore not applied.
    pub restart_required: bool,
}

/// What asked for a config reload.
///
/// Recorded on every reload log line, so an operator reading one is not sent hunting for a
/// signal nobody sent. One reload implementation, two triggers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadTrigger {
    /// `SIGHUP`.
    Signal,
    /// `POST /reload` on the management plane.
    Http,
}

impl ReloadTrigger {
    /// The stable log-field value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Signal => "sighup",
            Self::Http => "http",
        }
    }
}

/// Whether `channel` is orphaned: the status index may still own datasets for it, but the
/// declared channel set [`Reloadable::channels`] does not name it.
///
/// The single statement of the rule; every surface composes it from here. A running node
/// answers from the live snapshot ([`AppState::channel_is_orphaned`], read by the hydrate
/// projection and the management routes); a one-shot CLI answers from
/// `Reloadable::from_config` over the file it read. The local inbox is excluded by name: it
/// never appears in `[[s3.buckets]]`, and without the exclusion every inbox dataset on a node
/// whose `[service].inbox` was later unset would be withheld.
#[must_use]
pub fn channel_is_orphaned(reloadable: &Reloadable, channel: &str) -> bool {
    channel != crate::health::INBOX_CHANNEL && !reloadable.channels.contains(channel)
}

/// Who authored the metadata overlay being adopted.
///
/// Single-sources the two facts that must agree about one apply: the audit `actor` and the
/// `dataset_state_change` provenance tag. Chosen independently at each apply site they drift,
/// and a mismatch attributes a provider's sidecar broadening `access_rights` to the node's
/// administrator. Adding a variant here forces both answers at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlaySource {
    /// `dataset correct`: a node-local override the operator authored.
    OperatorOverride,
    /// A provider-authored `{id}.metadata.json` dropped in the inbox.
    InboxSidecar,
    /// A provider-authored `{id}.metadata.json` object in an S3 bucket.
    Bucket,
}

impl OverlaySource {
    /// The audit principal class: only the node-local override is an operator action; the
    /// other two are the background reconcile applying what a data provider published.
    #[must_use]
    pub const fn actor(self) -> &'static str {
        match self {
            Self::OperatorOverride => crate::audit::ACTOR_OPERATOR,
            Self::InboxSidecar | Self::Bucket => crate::audit::ACTOR_SYSTEM,
        }
    }

    /// The `dataset_state_change` reason tag.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::OperatorOverride => "operator-metadata-overlay",
            Self::InboxSidecar | Self::Bucket => "metadata-overlay",
        }
    }
}

impl AppState {
    /// The visible datasets to serve, with the visibility-staleness gate applied.
    ///
    /// When `[service].max_visibility_staleness_seconds > 0`, a dataset whose owning channel's
    /// last successful reconcile is older than the bound is withheld: its bucket has gone dark
    /// and may be serving a visibility a source-side retraction has since changed. A bound of
    /// `0` disables the gate and returns the cache's visible set unchanged. This is the single
    /// serve-time gate every visible-dataset serving path (Beacon and FDP) routes through, so
    /// the two cannot diverge.
    #[must_use]
    pub fn fresh_visible_datasets(
        &self,
    ) -> Vec<Arc<gdi_node_standalone_core::cache::DatasetEntry>> {
        let visible = self.cache.visible_datasets();
        let bound = self.config.service.max_visibility_staleness_seconds;
        // Two short-circuits, both before the status mutex: the disabled bound, and the
        // steady state where the gate is on but nothing is dark. `any_channel_stale` answers
        // the second from the per-channel reconcile map, one entry per bucket, instead of
        // building the O(datasets) channel map below.
        if bound == 0 || !self.readiness.any_channel_stale(bound) {
            return visible;
        }
        // The served `DatasetEntry` does not carry its owning channel; that lives in the
        // status index. Resolve each id's channel under the status lock, release it, then
        // apply the staleness gate, so the status lock is never held across the reconcile-map
        // lock `channel_stale` takes.
        let channels: std::collections::HashMap<String, String> = {
            let status = self
                .status
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            visible
                .iter()
                .filter_map(|d| status.get(&d.id).map(|e| (d.id.clone(), e.channel.clone())))
                .collect()
        };
        visible
            .into_iter()
            .filter(|d| {
                channels
                    .get(&d.id)
                    // Through `public_visibility_stale`, not an inlined `channel_stale`, so
                    // this set, the single-resource FDP path and the management oracle share
                    // one definition of "withheld for staleness".
                    .is_none_or(|ch| !self.public_visibility_stale(d.state, ch))
            })
            .collect()
    }

    /// The owning channel of `id` from the status index, or `None` when it has no entry.
    ///
    /// Lets a single-entry serving path reach the same staleness gate the whole-set path
    /// applies, without cloning the visible set to find one dataset.
    #[must_use]
    pub fn channel_of(&self, id: &str) -> Option<String> {
        self.status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(id)
            .map(|e| e.channel.clone())
    }

    /// Whether this dataset must be withheld from the public plane right now: the
    /// single-entry form of the [`Self::fresh_visible_datasets`] gate.
    ///
    /// `/fairdp/dataset/{id}` and `/fairdp/distribution/{id}` route here rather than checking
    /// `state == Visible` alone. Without it a harvester holding an id from an earlier crawl
    /// could re-harvest the full DCAT record of a dataset every other surface withholds.
    #[must_use]
    pub fn withheld_from_public(&self, id: &str, state: DatasetState) -> bool {
        // Short-circuit on the disabled bound before touching the status index, mirroring
        // `fresh_visible_datasets`. `public_visibility_stale` returns `false` anyway, but only
        // after taking the `status` mutex and cloning a channel `String` on every
        // single-resource FDP request.
        let bound = self.config.service.max_visibility_staleness_seconds;
        if bound == 0 || !self.readiness.any_channel_stale(bound) {
            return false;
        }
        // No status entry means no channel to age out, which is how
        // `fresh_visible_datasets` treats it too (`is_none_or`).
        self.channel_of(id)
            .is_some_and(|ch| self.public_visibility_stale(state, &ch))
    }

    /// Whether a `Visible` dataset on `channel` is currently withheld from the public plane
    /// by the visibility-staleness gate, so the management state oracle can report it instead
    /// of answering a bare `visible` while the public plane serves nothing.
    ///
    /// The gate withholds a visible dataset whose owning channel reconciled and then went
    /// dark past `[service].max_visibility_staleness_seconds`. This is the same condition
    /// [`Self::fresh_visible_datasets`] applies at serve time, read from the same boot config,
    /// so the oracle and the served set cannot disagree. `false` for a disabled bound (`0`),
    /// a non-`Visible` state, or a channel that is not stale.
    #[must_use]
    pub fn public_visibility_stale(&self, state: DatasetState, channel: &str) -> bool {
        let bound = self.config.service.max_visibility_staleness_seconds;
        state == DatasetState::Visible && self.readiness.channel_stale(channel, bound)
    }

    /// Build an [`AppState`] from a config, a (loaded) status index, and the
    /// node's crypt4gh identities. PME is left inactive (use
    /// `AppState::with_pme` to attach a configured PME runtime).
    #[must_use]
    pub fn new(config: ServiceConfig, status: StatusIndex, identities: NodeIdentities) -> Self {
        let suppressions = suppression::load(&suppression::suppressions_subdir(
            &config.service.override_dir_resolved(),
        ));
        let local_overlays = overlay_override::load(&overlay_override::overlays_subdir(
            &config.service.override_dir_resolved(),
        ));
        // The boot snapshot of the reloadable subset, extracted before `config` moves into
        // its own `Arc` below; `SIGHUP` swaps this cell independently.
        let reloadable = Reloadable::from_config(&config);
        // Read before `config` moves into its own `Arc` below, for the same reason.
        let max_total_query_bytes = config.service.max_total_query_bytes;
        let stats_enabled = config.stats.enabled;
        Self {
            cache: MetadataCache::new(),
            status: Arc::new(Mutex::new(status)),
            persist_lock: Arc::new(Mutex::new(0)),
            // Sequences start at 1 so the first snapshot (seq 1) is strictly greater than
            // the initial last-written sentinel (0) and is always written.
            persist_seq: Arc::new(AtomicU64::new(1)),
            config: Arc::new(config),
            removal_requested: Arc::new(Mutex::new(HashSet::new())),
            removal_seeds: Arc::new(Mutex::new(HashSet::new())),
            overlay_errors: Arc::new(Mutex::new(HashMap::new())),
            state_sidecar_errors: Arc::new(Mutex::new(HashMap::new())),
            superseded_redrops: Arc::new(Mutex::new(HashMap::new())),
            suppressions: Arc::new(RwLock::new(suppressions)),
            local_overlays: Arc::new(RwLock::new(local_overlays)),
            reloadable: Arc::new(RwLock::new(Arc::new(reloadable))),
            reconcile_trigger: Arc::new(tokio::sync::Notify::new()),
            reingest_applied: Arc::new(Mutex::new(HashMap::new())),
            retry_backoff: Arc::new(crate::ingest_backoff::RetryBackoff::new()),
            query_scan_blocking: Arc::new(AtomicUsize::new(0)),
            ingest_inflight: Arc::new(Mutex::new(HashMap::new())),
            query_memory_budget: Arc::new(crate::beacon_http::QueryMemoryBudget::new(
                max_total_query_bytes,
            )),
            digest_scrub_cursor: Arc::new(AtomicUsize::new(0)),
            tombstoned: Arc::new(RwLock::new(HashSet::new())),
            identities: Arc::new(identities),
            readiness: Readiness::new(),
            reload_hook: Arc::new(crate::control_http::ReloadHook::new()),
            reconcile_hook: Arc::new(crate::control_http::ReconcileHook::new()),
            log_level_window: Arc::new(crate::control_http::LogLevelWindow::new()),
            query_stats: Arc::new(QueryStats::new(stats_enabled)),
            #[cfg(feature = "pme")]
            pme: None,
        }
    }

    /// Serialize the status snapshot and durably write `.status.json`.
    ///
    /// The status guard is dropped before the blocking fsync, so the mutex the management
    /// plane also takes is never held across the write. A monotonic sequence is assigned
    /// while the status lock is held, so sequence order equals serialize order; the durable
    /// write then runs under [`persist_lock`](Self::persist_lock), which holds the
    /// last-written sequence and drops any snapshot whose sequence is not strictly greater.
    /// That keeps a serialize/write reordering from regressing the durable index, which after
    /// a crash could re-disclose a concurrently-hidden dataset from a stale sidecar seed.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InternalError`](gdi_node_standalone_core::error::CoreError) if
    /// serialization fails, or [`CoreError::Io`](gdi_node_standalone_core::error::CoreError)
    /// if the durable write fails. A skipped stale write is `Ok(())`.
    pub fn persist_status_index(
        &self,
        status: std::sync::MutexGuard<'_, StatusIndex>,
    ) -> gdi_node_standalone_core::error::CoreResult<()> {
        let path = self.config.service.data_dir.join(".status.json");
        // Assign the sequence under the status lock so sequence order equals serialize order.
        let seq = self.persist_seq.fetch_add(1, Ordering::SeqCst);
        let bytes = status.serialize_persisted();
        drop(status); // release the status lock before the unbounded write + fsync
        let bytes = bytes?;
        let mut last_written = self
            .persist_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if seq <= *last_written {
            // A newer snapshot already reached disk; writing this older one would regress the
            // durable index. The in-memory state is already correct.
            return Ok(());
        }
        gdi_node_standalone_core::util::write_durable_atomic_private(&path, &bytes)
            .map_err(gdi_node_standalone_core::error::CoreError::Io)?;
        *last_written = seq;
        Ok(())
    }

    /// Record that `id`'s source package was observed deleted while it was mid-ingest.
    /// Consumed once by [`Self::take_removal_requested`] in `on_success`.
    pub fn note_removal_requested(&self, id: &str) {
        self.removal_requested
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id.to_owned());
    }

    /// Whether `id` is currently held under a store-scrub quarantine.
    ///
    /// Read by the scrub sweep to decide which datasets to re-verify at full depth: a
    /// quarantine is lifted only by a passing scrub, never by a restart, so the sweep has to
    /// find the quarantined set. Matches on the class as well as the state, because an
    /// `Error` from ingest is a different verdict with a different remedy, a corrected
    /// package, and must not be re-verified as at-rest rot.
    #[must_use]
    pub fn is_scrub_quarantined(&self, id: &str) -> bool {
        self.status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(id)
            .is_some_and(|e| {
                e.state == DatasetState::Error
                    && e.error_message
                        == Some(gdi_node_standalone_core::error::ErrorClass::ScrubFailed)
            })
    }

    /// Take (and clear) the "deleted while mid-ingest" mark for `id`: `true` if the source
    /// was observed deleted during this ingest, so the caller must publish the finished
    /// dataset Hidden rather than Visible.
    pub fn take_removal_requested(&self, id: &str) -> bool {
        self.removal_requested
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(id)
    }

    /// Seed a removal confirmation for `id`, so the owning monitor's next full poll advances
    /// it instead of ignoring a fresh absence. See [`Self::removal_seeds`].
    pub fn seed_removal_confirmation(&self, id: &str) {
        self.removal_seeds
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id.to_owned());
    }

    /// Take (and clear) the seeded removal confirmations owned by `channel`.
    ///
    /// The drain must be per-channel. `pending_removals` is per-monitor and `plan_removals`
    /// rebuilds it from that monitor's own `absent` set, so a foreign monitor that consumed
    /// the seed would discard it, the owning monitor would never see it, and the retracted
    /// dataset would never be evicted.
    ///
    /// Ownership comes from the status index, the same source `plan_removals` keys on. A seed
    /// for an id with no status entry is left in place rather than discarded: it cannot be
    /// attributed yet, and dropping it would be the same silent loss.
    pub fn drain_removal_seeds_for(&self, channel: &str) -> HashSet<String> {
        // Never nests the two locks: snapshot, resolve, then remove.
        let all: Vec<String> = {
            let guard = self
                .removal_seeds
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.iter().cloned().collect()
        };
        if all.is_empty() {
            return HashSet::new();
        }
        let mine: HashSet<String> = {
            let status = self
                .status
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            all.into_iter()
                .filter(|id| status.get(id).is_some_and(|e| e.channel == channel))
                .collect()
        };
        let mut guard = self
            .removal_seeds
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for id in &mine {
            guard.remove(id);
        }
        mine
    }

    /// Record that `id`'s last metadata-overlay attempt was rejected for `reason`.
    ///
    /// Sets both surfaces a rejection must have: the per-id `overlay_error` field on
    /// `GET /datasets/{id}/state`, and the
    /// [`OVERLAY_APPLY_FAILED_TOTAL`](crate::metrics::OVERLAY_APPLY_FAILED_TOTAL) counter for
    /// `channel`. Taking `channel` as a parameter rather than emitting at each call site is
    /// what keeps them together: there is no way to record the error and miss the metric, and
    /// without the metric `OverlayApplyFailing` cannot fire on an inbox-only node.
    pub fn note_overlay_error(&self, id: &str, channel: &str, reason: &'static str) {
        self.overlay_errors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id.to_owned(), reason.to_owned());
        crate::metrics::overlay_apply_failed(channel, reason);
    }

    /// Clear any recorded overlay-reject for `id`: an overlay applied or reverted cleanly.
    pub fn clear_overlay_error(&self, id: &str) {
        self.overlay_errors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(id);
    }

    /// Record that `id`'s visibility sidecar (`{id}.state.json`) was rejected for `reason`
    /// (`unreadable` | `unrecognized`), and that the node failed the dataset safe to
    /// `hidden`.
    ///
    /// Sets both surfaces at once, for the same reason [`Self::note_overlay_error`] does: the
    /// `state_sidecar_error` field on `GET /datasets/{id}/state`, and the
    /// [`STATE_SIDECAR_REJECTED_TOTAL`](crate::metrics::STATE_SIDECAR_REJECTED_TOTAL) counter
    /// for `channel`.
    pub fn note_state_sidecar_error(
        &self,
        id: &str,
        channel: &str,
        reason: crate::metrics::StateSidecarRejectReason,
    ) {
        self.state_sidecar_errors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id.to_owned(), reason.as_str().to_owned());
        crate::metrics::state_sidecar_rejected(channel, reason);
    }

    /// Clear any recorded state-sidecar reject for `id`: a sidecar parsed cleanly.
    pub fn clear_state_sidecar_error(&self, id: &str) {
        self.state_sidecar_errors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(id);
    }

    /// The recorded state-sidecar reject reason for `id`, if its last sidecar was rejected.
    #[must_use]
    pub fn state_sidecar_error(&self, id: &str) -> Option<String> {
        self.state_sidecar_errors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(id)
            .cloned()
    }

    /// Record that a changed re-drop under the live (immutable) `id` was ignored. Surfaced
    /// as `superseded_redrop` on `GET /datasets/{id}/state`.
    pub fn note_superseded_redrop(&self, id: &str) {
        self.superseded_redrops
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id.to_owned(), gdi_node_standalone_core::util::now_rfc3339());
    }

    /// Clear any recorded superseded-re-drop marker for `id`: the id was re-ingested or
    /// erased, so a prior "your correction was ignored" signal is now stale.
    pub fn clear_superseded_redrop(&self, id: &str) {
        self.superseded_redrops
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(id);
    }

    /// When `id`'s most recent changed re-drop was ignored as immutable, if any.
    #[must_use]
    pub fn superseded_redrop_at(&self, id: &str) -> Option<String> {
        self.superseded_redrops
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(id)
            .cloned()
    }

    /// The last overlay-reject reason for `id`, if its most recent overlay attempt failed.
    #[must_use]
    pub fn overlay_error(&self, id: &str) -> Option<String> {
        self.overlay_errors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(id)
            .cloned()
    }

    /// Update the cached entry's metadata and `metadata_modified` in place, preserving state
    /// and config, and audit the change.
    ///
    /// The shared cache-update and audit contract for "an overlay applied or reverted", used
    /// by the sidecar-driven reconcile in [`crate::ingest_runtime`] and `crate::s3` and by
    /// the node-local operator-overlay enforce ([`Self::enforce_local_overlays`]). Authored
    /// once so the sites cannot diverge on what counts as an audited overlay change.
    ///
    /// `reason` is the caller's own audit cause string, distinct per site
    /// (`"metadata-overlay"` for a source sidecar, `"operator-metadata-overlay"` for a
    /// node-local override), so the audit trail keeps telling the two apart.
    ///
    /// Changes only the served metadata, not the dataset's visibility state, so no status
    /// index write is needed.
    pub fn apply_overlay_outcome(
        &self,
        id: &str,
        metadata: ManifestMetadata,
        modified: Option<String>,
        reason: &str,
        channel: Option<&str>,
    ) {
        let applied = modified.is_some();
        // An overlay applied or reverted cleanly, so any prior reject no longer stands. Clear
        // unconditionally: correct even when `set_metadata` reports no change, as on an
        // idempotent re-apply of an already-good overlay.
        self.clear_overlay_error(id);
        if self.cache.set_metadata(id, metadata, modified) {
            tracing::info!(dataset = %id, applied, reason, "metadata overlay reconciled");
            // An explicit channel wins, since the S3 monitor knows its bucket without a
            // lookup; otherwise resolve it from the status index.
            let channel = match channel {
                Some(ch) => ch.to_owned(),
                None => self
                    .status
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(id)
                    .map_or_else(|| "inbox".to_owned(), |e| e.channel.clone()),
            };
            crate::audit::dataset_state_change(
                &self.config.audit,
                id,
                &channel,
                if applied {
                    "OverlayApplied"
                } else {
                    "OverlayReverted"
                },
                reason,
            );
        }
    }

    /// Adopt a successfully applied metadata overlay: emit the correction audit line, log the
    /// merged result's non-fatal advisories, then project the merged metadata into the served
    /// cache.
    ///
    /// The single path every apply site takes (`enforce_local_overlays`, the inbox
    /// `reconcile_overlay`, the S3 `apply_overlay_change`). Taking the `Applied` result whole
    /// and doing both steps here means a new apply site cannot adopt an overlay without
    /// auditing it.
    ///
    /// `channel` lets a caller that already knows the owning channel skip the status-index
    /// lookup; `None` resolves it.
    pub fn adopt_applied_overlay(
        &self,
        id: &str,
        applied: gdi_node_standalone_core::overlay_store::Applied,
        source: OverlaySource,
        channel: Option<&str>,
    ) {
        // Before `apply_overlay_outcome` consumes the rest: the diff is the only surviving
        // record of what the correction replaced.
        crate::audit::metadata_overlay_applied(
            &self.config.audit,
            id,
            &applied.change,
            source.actor(),
        );
        // The advisories reach the operator here, on the one funnel every overlay channel
        // (inbox, S3, node-local enforce) takes, mirroring the ingest path. Warnings only:
        // `Applied` carries no notes. The strings are validator-authored constants, never
        // provider text.
        for warning in &applied.warnings {
            tracing::warn!(
                dataset = %id,
                warning = %warning,
                "metadata overlay advisory at apply"
            );
        }
        self.apply_overlay_outcome(
            id,
            applied.metadata,
            Some(applied.applied_at),
            source.reason(),
            channel,
        );
    }

    /// Whether a node-local operator metadata-overlay override exists for `id`.
    ///
    /// The operator-over-source precedence check every source-driven overlay reconcile site
    /// (`ingest_runtime::reconcile_overlay`/`reconcile_overlay_reverts`,
    /// `s3::BucketMonitor::apply_overlay_change`) consults before touching an id's overlay.
    /// While it is `true` the source's `{id}.metadata.json` sidecar is skipped entirely,
    /// neither applied nor treated as a reason to revert, so the node-local override alone
    /// governs that id's served metadata.
    #[must_use]
    pub fn local_overlay_present(&self, id: &str) -> bool {
        self.local_overlays
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(id)
    }

    /// A cheap, consistent snapshot of the `SIGHUP`-reloadable config subset (`[catalogs]`
    /// plus the `[ingest]` writer-key allow-list): clone the inner `Arc` under a brief read
    /// lock, then read the clone lock-free. Every read site calls this once per request or
    /// job and never holds the lock itself, so the `SIGHUP` write-lock swap is never blocked
    /// behind a slow reader.
    #[must_use]
    pub fn reloadable(&self) -> Arc<Reloadable> {
        Arc::clone(
            &self
                .reloadable
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Re-parse `config_path`, validate it exactly like boot ([`crate::preflight::run`]) and,
    /// on success, swap the reloadable cell to the freshly extracted subset
    /// ([`Reloadable::from_config`]).
    ///
    /// The whole freshly-parsed file is validated, not just the reloadable subset, so a
    /// reload that would leave `enforce` pointed at a newly-empty, unacknowledged writer
    /// allow-list is rejected. On rejection the old subset is kept and
    /// [`crate::metrics::config_reload_failed`] counts: a serving node must never crash, or
    /// start rejecting every writer, over a bad `SIGHUP`.
    ///
    /// A change outside the reloadable subset (a listener, `[vault]`, `min_allele_count`, a
    /// bucket's endpoint or credentials, a bucket added, removed or renamed) is warned about
    /// and not applied ([`ServiceConfig::changed_outside_reloadable_subset`]); the operator
    /// must restart.
    ///
    /// Returns the accepted config so the caller can apply the parts outside this cell, today
    /// the bucket-monitor reload. That keeps both halves of one `SIGHUP` on the same bytes.
    /// `trigger` only names the cause in the logs. Synchronous, and run inline on the
    /// signal-handler task.
    ///
    /// # Errors
    ///
    /// [`ReloadRejection::Unparsable`] when the file cannot be read or parsed,
    /// [`ReloadRejection::Invalid`] when it fails the same validation boot runs. The running
    /// config is kept in both cases.
    pub fn reload_config_from(
        &self,
        config_path: &std::path::Path,
        trigger: ReloadTrigger,
    ) -> Result<AppliedReload, ReloadRejection> {
        let trigger = trigger.as_str();
        let new_config = match ServiceConfig::load(Some(config_path)) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    config = %config_path.display(),
                    trigger,
                    error = %e,
                    "config reload: failed to parse the config file; keeping the running config"
                );
                crate::metrics::config_reload_failed();
                return Err(ReloadRejection::Unparsable);
            }
        };
        if let Err(e) = crate::preflight::run_with(&new_config, false) {
            tracing::warn!(
                config = %config_path.display(),
                trigger,
                error = %e,
                "config reload: the reloaded config failed startup validation; keeping the \
                 running config"
            );
            crate::metrics::config_reload_failed();
            return Err(ReloadRejection::Invalid);
        }
        let restart_required = self.config.changed_outside_reloadable_subset(&new_config);
        if restart_required {
            tracing::warn!(
                config = %config_path.display(),
                trigger,
                "config reload: the reloaded file also changes a restart-only setting, one \
                 outside the reloadable subset of [catalogs] plus the [ingest] writer \
                 allow-list, such as [beacon].min_allele_count, a listener addr, [vault] or \
                 [[s3.buckets]]; that change was not applied. Restart the node to pick it up"
            );
        }
        let catalog_count = new_config.catalogs.len();
        let writer_policy = new_config.ingest.writer_policy;
        let inbox_allowlist_size = new_config.ingest.inbox_allowed_writer_fingerprints.len();
        // A channel the reloaded file no longer declares keeps its allow-list: bucket removal
        // is restart-only, so that monitor is still polling and ingesting, and an empty
        // allow-list under `writer_policy = "enforce"` would quarantine every package
        // published there as `writer-rejected`.
        let previous = self.reloadable();
        *self
            .reloadable
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Arc::new(Reloadable::from_config(&new_config).retaining_removed_channels(&previous));
        tracing::info!(
            config = %config_path.display(),
            trigger,
            catalogs = catalog_count,
            "config reload: applied [catalogs] + the [ingest] writer allow-list"
        );
        // A durable record of the publication-auth posture change: the `info!` above is
        // droppable by GDI_LOG, so also emit an audit-floored record.
        crate::audit::config_reloaded(
            &self.config.audit,
            trigger,
            writer_policy,
            inbox_allowlist_size,
            catalog_count,
        );
        Ok(AppliedReload {
            config: new_config,
            restart_required,
        })
    }

    /// Re-read the node-local operator metadata-overlay store from disk on `SIGUSR1` and on
    /// the periodic reload. Not called at boot; the initial load happens inline in
    /// [`AppState::new`]. Does not touch the cache: pair it with
    /// [`Self::enforce_local_overlays`] to project the freshly-loaded set onto served
    /// metadata.
    ///
    /// Clears a stale `overlay_error` for any id whose override just disappeared from disk,
    /// as after `dataset correct <id> --reset`. If that id's last apply failed validation,
    /// `enforce_local_overlays` set `overlay_error` without writing a durable overlay, and
    /// nothing else would ever clear it. This is the one place that observes an override
    /// going away, on every channel.
    pub fn reload_local_overlays(&self) {
        let root = self.config.service.override_dir_resolved();
        // See `reload_suppressions`: a required-but-absent root is a destroyed store, and
        // adopting its empty set would revert every operator correction to the source
        // metadata. A correction is often a redaction, so that is a disclosure, not just a
        // config regression. `holding_now` covers the default posture, where the store is not
        // required.
        let dir = overlay_override::overlays_subdir(&root);
        if !override_store::loader_dir_present(&dir) {
            // Absent path only; see the suppression twin for why the lock is not taken on
            // every reload.
            let holding_now = self.serving_overlays_now();
            if self.config.service.require_override_store || holding_now {
                tracing::error!(
                    override_dir = %dir.display(),
                    require_override_store = self.config.service.require_override_store,
                    holding_now,
                    "operator-override overlays/ is absent while this node is serving \
                     corrections (or service.require_override_store is set); keeping the last \
                     loaded overlay set rather than reverting every correction. Restore the \
                     store from backup"
                );
                crate::metrics::override_store_absent(OverrideStoreAlarm::Overlays, true);
                return;
            }
        }
        // The emptied-under-the-marker arm; see `reload_suppressions` for the argument. An
        // empty set drops every precedence claim and the next reconcile re-publishes what
        // each correction was redacting.
        if crate::override_marker::marker_path(&self.config).exists()
            && !override_store::is_populated(&root)
        {
            let holding_now = self.serving_overlays_now();
            if self.config.service.require_override_store || holding_now {
                tracing::error!(
                    override_dir = %dir.display(),
                    require_override_store = self.config.service.require_override_store,
                    holding_now,
                    "operator-override store is empty while this node's used marker records \
                     that it has held overrides, and this node is serving corrections (or \
                     service.require_override_store is set); keeping the last loaded overlay \
                     set rather than reverting every correction. Restore the store from \
                     backup (`overrides import`), or attest the emptied store with \
                     `overrides init --yes`"
                );
                crate::metrics::override_store_absent(OverrideStoreAlarm::Overlays, true);
                return;
            }
        }
        let set = overlay_override::load(&dir);
        // Same split as `reload_suppressions`. Adopting an empty set drops every id's
        // operator-over-source precedence claim at once, and `reconcile_overlay_reverts` then
        // re-publishes the source metadata each override was redacting.
        if set.unreadable() {
            tracing::error!(
                override_dir = %dir.display(),
                "operator-override overlays/ is unreadable, not absent; keeping the last \
                 loaded overlay set rather than reverting every correction. Fix the mount or \
                 permissions"
            );
            crate::metrics::override_store_absent(OverrideStoreAlarm::Overlays, true);
            return;
        }
        crate::metrics::override_store_absent(OverrideStoreAlarm::Overlays, false);
        let mut guard = self
            .local_overlays
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for id in guard.ids() {
            if !set.contains(id) {
                self.clear_overlay_error(id);
            }
        }
        // An id that was degraded and now parses is healthy again, so drop its marker.
        // Scoped to ids leaving the degraded set, so this never clears an unrelated overlay
        // error such as a `fetch` or `validate` reject recorded by the apply path.
        let repaired: Vec<String> = guard
            .degraded_ids()
            .filter(|id| !set.degraded_ids().any(|d| d == *id))
            .map(str::to_owned)
            .collect();
        for id in &repaired {
            self.clear_overlay_error(id);
        }
        // A present-but-unparseable override holds precedence, so the node keeps serving
        // last-good rather than reverting to source. The operator still has to see that the
        // store is degraded, or the oracle an auditor consults reads healthy while it is
        // broken.
        for id in set.degraded_ids() {
            self.note_overlay_error(id, crate::metrics::LOCAL_OVERRIDE_CHANNEL, "parse");
        }
        *guard = set;
    }

    /// Project the current node-local overlay set onto served metadata through the overlay
    /// engine (`overlay_store::apply`), at boot, on `SIGUSR1` and on the periodic full
    /// reload. Mirrors [`Self::enforce_suppressions`]'s wiring without the erase half; a
    /// metadata correction has no destructive completion to finish.
    ///
    /// For every id with a node-local override: a dataset not yet in the cache is skipped and
    /// self-heals next pass, since a metadata overlay needs a published baseline manifest to
    /// merge over. Otherwise the patch is merged over the package baseline and re-validated,
    /// exactly as a source `{id}.metadata.json` sidecar is. On success the served metadata
    /// updates and `overlay_error` clears; on failure the last-good metadata is kept and
    /// `overlay_error` is set, the same invalid-is-ignored contract a source overlay gets.
    ///
    /// Runs inline rather than on `spawn_blocking`: the node-local override set is bounded by
    /// operator actions, not by the number of cached datasets, and this shares the reactor
    /// context `reconcile_overlay` already runs in. Idempotent; safe to call on every reload.
    pub fn enforce_local_overlays(&self) {
        // Record the degraded (present-but-unparseable) overrides first, so the boot pass
        // reports them too. `reload_local_overlays` notes them, but the initial load happens
        // inline in `AppState::new`, which has no `self` to call `note_overlay_error` on, and
        // the loop below iterates `ids()`, which excludes the degraded set. This method runs
        // on all three paths (boot, SIGUSR1, periodic full reload), and re-noting an
        // already-recorded id is idempotent.
        let (ids, degraded): (Vec<String>, Vec<String>) = {
            let guard = self
                .local_overlays
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (
                guard.ids().map(ToOwned::to_owned).collect(),
                guard.degraded_ids().map(ToOwned::to_owned).collect(),
            )
        };
        for id in &degraded {
            self.note_overlay_error(id, crate::metrics::LOCAL_OVERRIDE_CHANNEL, "parse");
        }
        let data_dir = self.config.service.data_dir.clone();
        for id in ids {
            if self.cache.get(&id).is_none() {
                tracing::info!(
                    dataset = %id,
                    "skipped: node-local metadata override for a not-yet-ingested dataset; will retry"
                );
                continue;
            }
            // Re-read the patch under the lock right before applying it: the set may have
            // changed, or the entry been removed, between the id snapshot above and here on
            // a concurrent reload.
            let patch = {
                let set = self
                    .local_overlays
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match set.get(&id) {
                    Some(p) => p.clone(),
                    None => continue,
                }
            };
            match overlay_store::apply(&data_dir, &id, &patch) {
                Ok(applied) => {
                    self.adopt_applied_overlay(&id, applied, OverlaySource::OperatorOverride, None);
                }
                Err(e) => {
                    tracing::warn!(
                        dataset = %id,
                        error = %e,
                        "ignored: node-local metadata override failed validation (keeps last-good)"
                    );
                    self.note_overlay_error(
                        &id,
                        crate::metrics::LOCAL_OVERRIDE_CHANNEL,
                        "validate",
                    );
                }
            }
        }
    }

    /// Re-read the operator suppression store from disk on `SIGUSR1`. Not called at boot:
    /// the initial load happens inline in [`AppState::new`], so the
    /// `suppression_load_degraded` gauge is not set there and the periodic metrics sampler
    /// covers the gap (see [`crate::metrics::sample_once`]).
    ///
    /// Never errors. [`suppression::load`] is fail-closed: a missing dir is empty, and an
    /// unparseable `{id}.json` still suppresses that filename-id as `Hide`. A non-zero
    /// [`SuppressionSet::degraded`] count means some override file failed to parse and its
    /// dataset was fail-closed; it is logged so an operator can find and fix it.
    ///
    /// Does not touch the cache: pair with [`Self::apply_suppressions_to_cache`] to project
    /// the freshly-loaded set onto served state.
    pub fn reload_suppressions(&self) {
        let root = self.config.service.override_dir_resolved();
        // A store that vanishes under a running node is a destroyed store, not an empty one.
        // `suppression::load` cannot tell the two apart, so adopting its result would lift
        // every withhold, `Remove` take-downs written to satisfy an erasure request included.
        // Keep the last known-good set instead; the boot path refuses to start outright.
        //
        // `require_override_store` alone is not enough: it defaults to `false`, so on the
        // shipped posture a detached volume or a mount-path typo would adopt the empty set.
        // `holding_now` closes that with no new state and cannot cause a false refusal: when
        // the in-memory set is empty, refusing to adopt an empty set and adopting it are the
        // same outcome.
        //
        // A store destroyed while the node was down is not covered: after a restart there is
        // no in-memory set to compare against. That case is `require_override_store`'s.
        let dir = suppression::suppressions_subdir(&root);
        if !override_store::loader_dir_present(&dir) {
            // Read the live set only on the absent path: the common case must not pay a lock
            // acquisition per reload, and the filesystem call above can block indefinitely on
            // a hung network mount.
            let holding_now = self.holding_suppressions_now();
            if self.config.service.require_override_store || holding_now {
                tracing::error!(
                    override_dir = %dir.display(),
                    require_override_store = self.config.service.require_override_store,
                    holding_now,
                    "operator-override suppressions/ is absent while this node is withholding \
                     datasets (or service.require_override_store is set); keeping the last \
                     loaded suppression set rather than lifting every withhold. Restore the \
                     store from backup"
                );
                crate::metrics::override_store_absent(OverrideStoreAlarm::Suppressions, true);
                return;
            }
        }
        // The runtime twin of the boot assertion (`override_marker::sync_and_assert`): the
        // loader directory is present but the store is empty while the data volume's used
        // marker records that it has held overrides. That is the structure-only restore
        // shape, every file gone and the tree intact, which the absent arm cannot see. The
        // marker distinguishes it from a legitimate emptying: a CLI lift of the last override
        // clears the marker (`override_marker::sync_after_removal`), so that case falls
        // through to the normal adopt below. Same gate, message family and gauge as the
        // absent arm.
        //
        // `is_populated` is whole-store: the marker is one bit for both loader directories,
        // so an empty `suppressions/` beside a populated `overlays/` is legitimately empty
        // and must adopt.
        if crate::override_marker::marker_path(&self.config).exists()
            && !override_store::is_populated(&root)
        {
            let holding_now = self.holding_suppressions_now();
            if self.config.service.require_override_store || holding_now {
                tracing::error!(
                    override_dir = %dir.display(),
                    require_override_store = self.config.service.require_override_store,
                    holding_now,
                    "operator-override store is empty while this node's used marker records \
                     that it has held overrides, and this node is withholding datasets (or \
                     service.require_override_store is set); keeping the last loaded \
                     suppression set rather than lifting every withhold. Restore the store \
                     from backup (`overrides import`), or attest the emptied store with \
                     `overrides init --yes`"
                );
                crate::metrics::override_store_absent(OverrideStoreAlarm::Suppressions, true);
                return;
            }
        }
        let set = suppression::load(&dir);
        // Unreadable is not absent, and unlike absence it is not ambiguous: an EACCES or an
        // EIO on a network volume would otherwise read as an empty set and lift every
        // withhold. Keep the last-good set unconditionally.
        if set.unreadable() {
            tracing::error!(
                override_dir = %dir.display(),
                "operator-override suppressions/ is unreadable, not absent; keeping the last \
                 loaded suppression set rather than lifting every withhold. Fix the mount or \
                 permissions"
            );
            crate::metrics::override_store_absent(OverrideStoreAlarm::Suppressions, true);
            return;
        }
        crate::metrics::override_store_absent(OverrideStoreAlarm::Suppressions, false);
        if set.degraded() > 0 {
            tracing::warn!(
                degraded = set.degraded(),
                "suppression store reload: some override files failed to parse and were \
                 fail-closed to hide"
            );
        }
        // Set unconditionally (not only when > 0) so a since-fixed override file also
        // clears a non-zero gauge back to 0.
        crate::metrics::suppression_load_degraded(set.degraded() as u64);
        // Audit any out-of-band change to the withhold set. The per-write audit fires in the
        // CLI writer process, so a direct `rm` or a hand-written file leaves no trail: diff
        // what the node held against what it just loaded and record the net change. Under the
        // write lock, so a concurrent reload cannot interleave and drop a diff.
        {
            let mut guard = self
                .suppressions
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let old = Self::suppression_snapshot(&guard);
            let new = Self::suppression_snapshot(&set);
            let (added, removed) = Self::suppression_reload_diff(&old, &new);
            crate::audit::override_store_reloaded(&self.config.audit, &added, &removed);
            *guard = set;
        }
    }

    /// Whether this node holds at least one suppression right now: a non-empty or degraded
    /// in-memory set. This is the `holding_now` half of the reload guards. When the in-memory
    /// set is empty, refusing to adopt an empty set and adopting it are the same outcome, so
    /// keying a guard on this cannot cause a false refusal.
    fn holding_suppressions_now(&self) -> bool {
        let guard = self
            .suppressions
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        !guard.is_empty() || guard.degraded() > 0
    }

    /// Overlay twin of [`Self::holding_suppressions_now`].
    fn serving_overlays_now(&self) -> bool {
        let guard = self
            .local_overlays
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.ids().next().is_some() || guard.degraded() > 0
    }

    /// Catalogs that visible datasets still declare but `[catalogs]` no longer configures,
    /// as `(catalog, dataset count)`: the datasets orphaned from FDP discovery.
    ///
    /// `/fairdp` builds one listing per configured catalog and groups visible datasets by
    /// `metadata.catalog`, so a dataset naming a removed catalog lands in a group nobody
    /// iterates. It drops out of the root's `ldp:contains`, out of `fdp-o:metadataModified`
    /// and out of every crawl path, while remaining `visible`, served by the Beacon and
    /// resolvable at `/fairdp/dataset/{id}` by anyone who knows the URI.
    ///
    /// Read-only: this is not the catalog analogue of the orphan-channel withhold
    /// ([`Self::channel_is_orphaned`]). An orphaned bucket is never polled again, so the
    /// provider's retraction verb stops working and serving on becomes unsafe. A catalog is
    /// only a discovery grouping: the dataset still reconciles through its own channel and
    /// deletion still takes effect, so withholding would pull live public data off the air
    /// over a config typo and buy no safety. Take-down stays the verb that retracts.
    ///
    /// Counted from the cache rather than the status index, because this is about what is
    /// served and discoverable, so an errored, status-only id is correctly absent.
    #[must_use]
    pub fn orphaned_catalogs(&self) -> Vec<(String, usize)> {
        let configured = &self.reloadable().catalogs;
        let mut orphaned: BTreeMap<String, usize> = BTreeMap::new();
        for entry in self.cache.visible_datasets() {
            let catalog = entry.metadata.catalog.as_str();
            if configured.contains_key(catalog) {
                continue;
            }
            *orphaned.entry(catalog.to_owned()).or_default() += 1;
        }
        orphaned.into_iter().collect()
    }

    /// A scope-qualified `key -> mode` snapshot of a suppression set, for diffing a reload.
    /// Dataset ids key as themselves; channel scopes key as `channel:<name>` so the two never
    /// collide in the diff.
    fn suppression_snapshot(set: &suppression::SuppressionSet) -> BTreeMap<String, &'static str> {
        let mut m = BTreeMap::new();
        for id in set.ids() {
            if let Some(s) = set.get(id) {
                m.insert(id.to_owned(), s.mode.as_str());
            }
        }
        for ch in set.channel_names() {
            if let Some(s) = set.channel_get(ch) {
                m.insert(format!("channel:{ch}"), s.mode.as_str());
            }
        }
        m
    }

    /// Diff two suppression snapshots into `(added, removed)` audit descriptors. `added`
    /// carries `key=mode` for a new or mode-changed withhold; `removed` carries the bare
    /// `key` of a withhold that vanished. Both are sorted, the snapshots being `BTreeMap`s,
    /// so a reload's audit line is deterministic.
    fn suppression_reload_diff(
        old: &BTreeMap<String, &'static str>,
        new: &BTreeMap<String, &'static str>,
    ) -> (Vec<String>, Vec<String>) {
        let added = new
            .iter()
            .filter(|(k, mode)| old.get(*k) != Some(*mode))
            .map(|(k, mode)| format!("{k}={mode}"))
            .collect();
        let removed = old
            .keys()
            .filter(|k| !new.contains_key(*k))
            .map(String::clone)
            .collect();
        (added, removed)
    }

    /// The orphaned channels, ones the status index still owns datasets for but the live
    /// configuration does not declare, as `(channel, dataset count)` pairs for the boot
    /// warning and the `gdi_s3_channel_orphaned` gauge.
    ///
    /// An orphan is a channel removed from config before a restart: no monitor is built for
    /// it, so nothing polls its bucket and the provider's retraction verb, deleting the
    /// package, can never take effect. The staleness bound cannot carry the withhold alone,
    /// because an orphan never reconciles and its staleness age is measured from process
    /// start, which every restart resets.
    ///
    /// This method only reports; the withhold is applied by
    /// [`Self::hydrate_cache_from_disk`]'s projection on every walk, through
    /// [`Self::channel_is_orphaned`]. Counted from the status index, the operator-facing
    /// inventory, so a status-only errored dataset is counted although it has nothing cached
    /// to hide. The withhold is cache-only, so re-declaring the bucket restores serving on
    /// the next hydrate; `channel take-down` remains the verb that erases.
    #[must_use]
    pub fn orphaned_channels(&self) -> Vec<(String, usize)> {
        let reloadable = self.reloadable();
        let status = self
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut orphaned: BTreeMap<String, usize> = BTreeMap::new();
        for entry in status.entries().values() {
            if !channel_is_orphaned(&reloadable, &entry.channel) {
                continue;
            }
            *orphaned.entry(entry.channel.clone()).or_default() += 1;
        }
        orphaned.into_iter().collect()
    }

    /// Whether `channel` is orphaned under the live configuration: [`channel_is_orphaned`]
    /// over the current reloadable snapshot, so a bucket a reload added is declared here the
    /// moment the reload lands, exactly as it is for the hydrate projection.
    #[must_use]
    pub fn channel_is_orphaned(&self, channel: &str) -> bool {
        channel_is_orphaned(&self.reloadable(), channel)
    }

    /// Project the current suppression set onto the in-memory cache: the withhold direction
    /// only, cache state only, never touching `data_dir` or the status index.
    ///
    /// * `Some(Hide)` and `Some(Remove)` both force the cached entry to
    ///   [`DatasetState::Hidden`], the immediate withhold. `Remove` is completed to
    ///   evict-and-erase by [`Self::enforce_suppressions`], which calls this first and then
    ///   [`Self::erase_dataset`], so a `Remove` this method hid still has its
    ///   `data_dir/{id}/` and status entry until the erase runs.
    /// * `None`, including a just-lifted suppression, is a no-op. Restoring a lifted
    ///   suppression's source-resolved state is the next reconcile's job; it re-derives that
    ///   state from the channel's sidecar or listing.
    ///
    /// Idempotent; safe to call after every reload. Snapshots the ids to hide under the
    /// suppression and status locks, releases the suppression lock, then re-takes the status
    /// lock once per id.
    ///
    /// Per id rather than across the loop, because this runs on the SIGUSR1 path and one
    /// wide critical section would block every publish, poll and `/datasets/{id}/state` for
    /// the length of the whole store. The lock order is `suppressions -> status -> cache`,
    /// the same order `erase_dataset` takes, so the two cannot deadlock.
    pub fn apply_suppressions_to_cache(&self) {
        let to_hide: Vec<String> = {
            let set = self
                .suppressions
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let status = self
                .status
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // `gdi_datasets_suppressed{mode}` reflects the override store's mode breakdown,
            // not cache membership, so it stays correct for a `Remove` whose erase evicts the
            // id from `self.cache` before the next pass could re-tally it.
            let (hide, remove) = set.counts_by_mode();
            crate::metrics::datasets_suppressed(hide as u64, remove as u64);
            self.cache
                .ids()
                .into_iter()
                .filter(|id| {
                    let channel = status.get(id).map_or("unknown", |e| e.channel.as_str());
                    set.effective(id, channel).is_some()
                })
                .collect()
        };
        for id in to_hide {
            let status = self
                .status
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let _ = self
                .cache
                .set_state(StatusWrite::held(&status), &id, DatasetState::Hidden);
        }
    }

    /// Enforce the current suppression set on the running node: force every Hide- or
    /// Remove-suppressed cached dataset to [`DatasetState::Hidden`] via
    /// [`Self::apply_suppressions_to_cache`], then erase every `Remove`-suppressed dataset
    /// via [`Self::erase_dataset`] so it becomes `404` with `data_dir/{id}/` gone, completing
    /// [`SuppressMode::Remove`]'s evict-and-erase contract.
    ///
    /// Run after every cache hydrate (boot, the periodic full reload, the SIGUSR1 reload),
    /// because
    /// [`hydrate_from_disk`](crate::state::AppState::hydrate_cache_from_disk) seeds
    /// visibility from the status index, which a `Hide` never touches, so a bare hydrate
    /// would re-disclose a hidden-by-suppression dataset until the next enforce. Idempotent.
    ///
    /// The erase is what makes a `Remove` stick: the ingest gate refuses to re-ingest a
    /// suppressed id, so the still-present source package cannot re-materialise it.
    ///
    /// The cache walk alone would miss a `Remove`-suppressed id that is on disk but not
    /// cached, such as one `hydrate` skipped for a corrupt `manifest.json`. So this also
    /// cross-checks `data_dir/{id}/` directly for every [`SuppressionSet::remove_ids`] entry
    /// and every status-tracked id of a channel-level `Remove` (see
    /// [`SuppressionSet::channel_get`]: the store names only the channel), and erases any
    /// that exist on disk. `remove_ids()` only grows, so that cross-check runs its `is_dir()`
    /// stats on `spawn_blocking` with no lock held.
    ///
    /// The channel cross-check reaches only status-tracked ids; there is no id-to-channel
    /// mapping on disk. `dataset take-down <id>` names the id directly and is the tool for a
    /// crash-window orphan.
    pub async fn enforce_suppressions(&self) {
        self.apply_suppressions_to_cache();
        // Snapshot the (id, channel) pairs whose effective mode is `Remove` via the cache
        // walk, releasing both locks before the disk cross-check below: no std guard is held
        // across an `.await`, and none across a blocking syscall.
        let mut erase: std::collections::BTreeMap<String, String> = {
            let set = self
                .suppressions
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let status = self
                .status
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.cache
                .ids()
                .into_iter()
                .filter_map(|id| {
                    let channel = status.get(&id).map_or("unknown", |e| e.channel.as_str());
                    (set.effective(&id, channel) == Some(SuppressMode::Remove))
                        .then(|| (id, channel.to_owned()))
                })
                .collect()
        };
        // Catch a `Remove`-suppressed id the cache walk missed because it is not cached but
        // whose data still lives on disk. `remove_ids()` only grows, so snapshot the
        // candidate ids under both locks briefly, run the `is_dir()` checks on
        // `spawn_blocking` with no lock held, then re-take `status` briefly to resolve
        // channels for the subset that exists.
        //
        // Two sources feed `candidates`, unioned:
        // * id-level `Remove` entries (`remove_ids()`), which need no status entry, so they
        //   catch a crash window where the status entry was purged but `data_dir/{id}/`
        //   remains.
        // * a channel-level `Remove`'s member ids. The store names only the channel, so
        //   membership is resolved via the status index: any status-tracked id of that
        //   channel, cached or not.
        let candidates: Vec<String> = {
            let set = self
                .suppressions
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let status = self
                .status
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let by_id = set.remove_ids().map(ToOwned::to_owned);
            let by_channel = status
                .entries()
                .iter()
                .filter(|(_, entry)| {
                    set.channel_get(&entry.channel).map(|s| s.mode) == Some(SuppressMode::Remove)
                })
                .map(|(id, _)| id.clone());
            by_id
                .chain(by_channel)
                .filter(|id| !erase.contains_key(id))
                .collect::<std::collections::BTreeSet<String>>()
                .into_iter()
                .collect()
        };
        if !candidates.is_empty() {
            let data_dir = self.config.service.data_dir.clone();
            let on_disk: Vec<String> = tokio::task::spawn_blocking(move || {
                candidates
                    .into_iter()
                    .filter(|id| data_dir.join(id).is_dir())
                    .collect()
            })
            .await
            .unwrap_or_default();
            if !on_disk.is_empty() {
                let status = self
                    .status
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                for id in on_disk {
                    let channel = status
                        .get(&id)
                        .map_or("unknown", |e| e.channel.as_str())
                        .to_owned();
                    erase.insert(id, channel);
                }
            }
        }
        let to_erase: Vec<(String, String)> = erase.into_iter().collect();
        let erased: std::collections::BTreeSet<String> =
            to_erase.iter().map(|(id, _)| id.clone()).collect();
        for (id, channel) in to_erase {
            // The operator `Remove` is the erasure path: audit it under its own reason
            // before the erase, as the S3 and inbox delete sites audit theirs.
            crate::audit::dataset_state_change(
                &self.config.audit,
                &id,
                &channel,
                "Deleted",
                "operator-suppress-remove",
            );
            self.erase_dataset(&id, &channel).await;
        }
        // An id-level `Remove` for an id that was never ingested has no cache entry, no
        // status entry and nothing under `data_dir`, so neither walk above reaches it, yet
        // its drop may still sit in the inbox. A take-down is an erasure request, so sweep
        // the inbox for every id-level `Remove` that did not just go through
        // `erase_dataset`. Idempotent and cheap, so it runs every pass. Channel-level
        // take-downs are not covered: their members are enumerated from the status index,
        // and a never-ingested drop has no entry to enumerate.
        let never_ingested: Vec<String> = {
            let set = self
                .suppressions
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            set.remove_ids()
                .filter(|id| !erased.contains(*id))
                .map(ToOwned::to_owned)
                .collect()
        };
        for id in never_ingested {
            self.erase_inbox_artifacts(&id).await;
        }
    }

    /// Re-read both operator override stores from disk ([`Self::reload_suppressions`],
    /// [`Self::reload_local_overlays`]), project them onto the running node
    /// ([`Self::enforce_suppressions`], [`Self::enforce_local_overlays`]), then process any
    /// pending reingest-request markers ([`Self::process_reingest_requests`]). Both stores
    /// are reloaded before either is enforced, the same sequence
    /// [`crate::ingest_runtime::IngestRuntime::full_reload`] runs, minus its cache re-hydrate
    /// and inbox scan.
    ///
    /// This is the body of the periodic override-reconcile timer, which `main.rs` spawns only
    /// when no inbox is configured. `full_reload` carries the same duty on an
    /// inbox-configured node, so any node has exactly one periodic reload-and-enforce path
    /// per store. Without this, a node whose datasets are entirely S3-bucket-owned would
    /// never re-read an override written against a live node, except at boot or on a
    /// `SIGUSR1` that a `distroless` image cannot deliver.
    ///
    /// The disk reads run off the async reactor via `spawn_blocking`.
    pub async fn reload_and_enforce_overrides(&self) {
        let state = self.clone();
        let _ = tokio::task::spawn_blocking(move || state.reload_suppressions()).await;
        let state = self.clone();
        let _ = tokio::task::spawn_blocking(move || state.reload_local_overlays()).await;
        self.enforce_suppressions().await;
        self.enforce_local_overlays();
        // The targeted bucket retry, on the same periodic path as suppressions and overlays.
        // A bucket-only node never runs `IngestRuntime::full_reload`, so this is its only
        // durable fallback for a `dataset reingest <id>` marker when `SIGUSR1` is never
        // delivered.
        self.process_reingest_requests().await;
    }

    /// Process every pending reingest-request marker (`<override_dir>/reingest/{id}`) written
    /// by `dataset reingest <id>` for a dataset it could not restore from `inbox/.rejected/`:
    /// in practice a bucket-owned or not-yet-seen id pinned by the S3 reconcile's same-ETag
    /// short-circuit.
    ///
    /// For every marker whose `requested_at` differs from the last stamp this process acted
    /// on ([`Self::reingest_applied`]), clear the recorded `last_seen_signature` so the
    /// still-present source package no longer looks unchanged to `s3::apply_package`, then
    /// wake every S3 bucket monitor ([`Self::reconcile_trigger`]) so the unpinned id is
    /// retried without waiting out the bucket's poll interval.
    ///
    /// The marker is not removed. Deleting it would make the request a single-consumer queue:
    /// with several nodes against one override store, whichever polled first would consume it
    /// for all of them. Comparing a stamp per process lets every node observe every request
    /// once and leaves the override store read-only to the serving path.
    ///
    /// Idempotent and cheap with no pending markers. Runs on `SIGUSR1` and on the periodic
    /// override-reconcile. The `read_dir` listing runs off the reactor via `spawn_blocking`.
    pub async fn process_reingest_requests(&self) {
        let dir = reingest_request::requests_subdir(&self.config.service.override_dir_resolved());
        let requests = tokio::task::spawn_blocking(move || reingest_request::list_requests(&dir))
            .await
            .unwrap_or_default();
        if requests.is_empty() {
            return;
        }
        // Act only on the ones whose stamp differs from the last this process handled, and
        // record the stamp before clearing anything: the record means "observed", not
        // "succeeded". Re-running a clear is harmless, but a marker that re-fires every pass
        // would notify the reconcile trigger forever.
        let fresh: Vec<String> = {
            let mut applied = self
                .reingest_applied
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut fresh = Vec::new();
            for req in requests {
                if applied
                    .insert(req.id.clone(), req.requested_at.clone())
                    .is_none_or(|seen| seen != req.requested_at)
                {
                    fresh.push(req.id);
                }
            }
            fresh
        };
        if fresh.is_empty() {
            return;
        }
        for id in &fresh {
            self.clear_reingest_signature(id);
        }
        self.reconcile_trigger.notify_waiters();
    }

    /// Clear `id`'s recorded `last_seen_signature` in the status index, so the next reconcile
    /// no longer sees the still-present source package as unchanged and re-ingests it. This
    /// is how [`Self::process_reingest_requests`] defeats the S3 reconcile's same-ETag
    /// short-circuit for a targeted `dataset reingest <id>`.
    ///
    /// A no-op when `id` has no status entry or no recorded signature. Also a no-op for an
    /// `inbox`-channel entry, whose ingest gate never consults the signature, and for a
    /// bucket entry that is not [`DatasetState::Error`]: a live id is already served, and
    /// clearing its signature would only trigger the immutable-re-drop warning and a
    /// redundant `record_signature` write on the next reconcile.
    ///
    /// Returns the verdict it acted on. [`ReingestVerdict::Retriable`] means the signature
    /// was cleared; the other two mean nothing was touched.
    pub(crate) fn clear_reingest_signature(&self, id: &str) -> ReingestVerdict {
        let mut status = self
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let verdict = classify_reingest(status.get(id));
        if verdict != ReingestVerdict::Retriable {
            return verdict;
        }
        let Some(entry) = status.get(id) else {
            return ReingestVerdict::Unknown;
        };
        let next = StatusEntry {
            last_seen_signature: None,
            ..entry.clone()
        };
        status.insert(id.to_owned(), next);
        if let Err(e) = self.persist_status_index(status) {
            tracing::warn!(
                dataset = %id,
                error = %e,
                "failed to persist status index after clearing reingest signature"
            );
        }
        ReingestVerdict::Retriable
    }

    /// The verdict for `id` without changing anything: what `POST /datasets/{id}/reingest`
    /// answers `404`/`409` from, before it consumes the pacing window. The guard is taken
    /// and dropped here, never held across an `.await`.
    pub(crate) fn reingest_verdict(&self, id: &str) -> ReingestVerdict {
        let status = self
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        classify_reingest(status.get(id))
    }

    /// Erase a dataset from the node: evict the cache entry, purge the status entry and
    /// remove `data_dir/{id}/`.
    ///
    /// The one crash-safe erasure shared by the S3 removed path (`crate::s3::apply_removed`),
    /// the inbox tombstone path
    /// ([`crate::ingest_runtime`]`::IngestRuntime::delete_dataset`) and the operator `Remove`
    /// suppression ([`Self::enforce_suppressions`]), so the ordering invariant is authored
    /// once.
    ///
    /// Ordering, the re-disclosure and crash-safety contract:
    /// 1. Write-ahead a `.deleting/{id}` intent marker before the status purge, so a crash
    ///    in the torn window (status purged, dir not yet removed) is finished by the next
    ///    boot's [`reap_deleting`](gdi_node_standalone_core::util::reap_deleting).
    ///    Best-effort: losing it forfeits the crash-safety net, not the erase.
    /// 2. Evict the cache entry and purge the status entry together under the status lock,
    ///    so a concurrent full reload cannot observe one write without the other. The
    ///    reload's disk walk runs lock-free and is not serialised against this; what stops
    ///    it re-inserting the still-on-disk dataset is the `.deleting` marker from step 1,
    ///    which `cache::apply_scan` checks before every insert.
    /// 3. Remove the possibly multi-GB dataset dir off the reactor via `tokio::fs`. The std
    ///    status lock is dropped first and never held across the `.await`.
    /// 4. Erase the inbox-side copies (`erase_inbox_artifacts`) while the marker still
    ///    stands, so a crash between step 3 and this is finished by `reap_deleting`'s inbox
    ///    arm rather than leaving the drop behind.
    /// 5. Clear the intent marker once the dir is gone. The inbox sweep is best-effort and
    ///    does not hold the marker: a persistently unremovable inbox file must not pin a
    ///    marker that a later boot would replay against a re-added live dataset.
    ///
    /// Callers own the audit line; the reason differs per site (`package-removed`,
    /// `tombstone-delete`, `operator-suppress-remove`). Idempotent: an absent cache or status
    /// entry and a missing dir are all no-ops.
    ///
    /// `channel` is the dataset's owning channel (an S3 bucket's configured `name`, or
    /// `inbox`), carried only as `warn!` context on an I/O failure and never used to decide
    /// anything here.
    pub async fn erase_dataset(&self, id: &str, channel: &str) {
        let data_dir = &self.config.service.data_dir;
        // Write-ahead the erasure intent (crash-safety net; see step 1).
        if let Err(e) = gdi_node_standalone_core::util::mark_deleting(data_dir, id) {
            tracing::warn!(dataset = %id, channel = %channel, error = %e, "could not record deletion intent; proceeding without the crash-safety net");
        }
        // Evict and purge together under the status lock (step 2). `persist_status_index`
        // consumes the guard and drops it before its fsync.
        {
            let mut status = self
                .status
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let _ = self.cache.remove(StatusWrite::held(&status), id);
            status.remove(id);
            if let Err(e) = self.persist_status_index(status) {
                tracing::warn!(dataset = %id, channel = %channel, error = %e, "failed to persist status index on erase");
            }
        }
        // Drop any transient-failure backoff for a removed dataset, on every erase path, so
        // its entry never lingers in the backoff map or gauge.
        self.retry_backoff.clear(id);
        // An erased id is no longer live, so a "your re-drop was ignored" marker for it is
        // stale: the take-down half of the take-down and re-add recourse.
        self.clear_superseded_redrop(id);
        // Test-only fault point: a crash here, with the status purged and the dir still
        // present, is the erasure window the intent marker makes recoverable.
        let _ = gdi_node_standalone_core::faults::guard(
            gdi_node_standalone_core::faults::FaultPoint::PostStatusPurge,
            id,
        );
        // Remove the dataset dir off the reactor: unbounded blocking I/O (step 3).
        let dir = data_dir.join(id);
        let removed = tokio::fs::remove_dir_all(&dir).await;
        // `data_dir/{id}` is not the only copy of the subject's data this node holds (step
        // 4). Swept while the intent marker still stands, so a crash between the dir removal
        // and this is finished by `reap_deleting`'s inbox arm at the next boot.
        self.erase_inbox_artifacts(id).await;
        // Clear the intent marker only if the removal succeeded (step 5). A failed
        // `remove_dir_all` must keep the marker so the next boot's `reap_deleting` retries
        // the erasure; dropping it here would strand un-erased data.
        if let Err(e) = gdi_node_standalone_core::util::clear_deleting_marker(data_dir, id, removed)
        {
            tracing::warn!(dataset = %id, channel = %channel, error = %e, "could not remove dataset dir on erase; keeping the deletion-intent marker so the next boot retries the erasure");
        }
    }

    /// Erase every inbox-side copy of `id`: the drop, an in-flight `.partial`, the provider's
    /// metadata sidecar, the staging dir and the quarantine entry. The list lives in
    /// `util::inbox_artifact_paths`. Never the `deleted` tombstone, which is the provider's
    /// retraction record.
    ///
    /// Reachable from [`Self::erase_dataset`], whose callers are all genuine erasures, and
    /// from [`Self::enforce_suppressions`] for an id-level `Remove` of an id that was never
    /// ingested, whose only copy is the inbox drop. Not reachable from `hide`, which is
    /// reversible: destroying the provider's drop would make lifting it impossible without a
    /// re-drop.
    ///
    /// A successful ingest consumes its source, so most datasets leave nothing behind. An
    /// unconsumed drop does, and nothing GCs those: `rejected_retention_hours` reaps only
    /// `.rejected/`, so an erasure that skipped them would leave the subject's data on the
    /// node's volume.
    ///
    /// Best-effort and non-fatal: the dataset itself is already erased and a failure here
    /// must not mask that. Each removal is logged so the operator can see what an erasure
    /// reached.
    async fn erase_inbox_artifacts(&self, id: &str) {
        let Some(inbox) = self.config.service.inbox.as_ref() else {
            return;
        };
        // The id is already validated everywhere it enters, but this joins it onto a path,
        // so re-assert rather than inherit the assumption: a `..` here would delete outside
        // the inbox.
        if !gdi_node_standalone_core::id::is_valid_dataset_id(id) {
            tracing::warn!(dataset = %id, "refusing to erase inbox artifacts for a malformed id");
            return;
        }
        // The shapes and the removal live in core (`util::sweep_inbox_artifacts`), shared
        // with the boot-time replay so the two cannot reach different sets. Off the
        // reactor: a handful of stats and up to as many removals of possibly large trees.
        let inbox = inbox.clone();
        let owned = id.to_owned();
        let swept = match tokio::task::spawn_blocking(move || {
            gdi_node_standalone_core::util::sweep_inbox_artifacts(&inbox, &owned)
        })
        .await
        {
            Ok(swept) => swept,
            // A join failure, from the runtime shutting down mid-erase, is not "nothing to
            // sweep". This arm is terminal: `erase_dataset` clears the intent marker once the
            // dir is removed, so a lost sweep is never retried. Log it at the level the
            // per-path failure below uses.
            Err(e) => {
                tracing::warn!(
                    dataset = %id,
                    error = %e,
                    "the inbox-side erasure sweep was lost; inbox copies of an erased \
                     dataset may remain. Re-run `dataset take-down` or remove them by hand"
                );
                Vec::new()
            }
        };
        for (path, removed) in swept {
            match removed {
                Ok(()) => tracing::info!(
                    dataset = %id,
                    path = %path.display(),
                    "erased an inbox-side copy of an erased dataset"
                ),
                Err(e) => tracing::warn!(
                    dataset = %id,
                    path = %path.display(),
                    error = %e,
                    "could not erase an inbox-side copy; it still holds data for an erased dataset"
                ),
            }
        }
    }

    /// Re-hydrate the in-memory metadata cache from the persisted dataset directories under
    /// `[service].data_dir`, seeding each entry's state from the loaded status index.
    ///
    /// The cache is purely in-memory, so without this the Beacon and FDP query paths would be
    /// empty after every restart. Called at startup before the inbox scan and S3 reconcile,
    /// so their sidecar reads can update existing entries, and again on the periodic
    /// full-reload safety net.
    ///
    /// The current suppression set and the orphan predicate ([`Self::channel_is_orphaned`],
    /// over the live reloadable channel set) are passed into the core walk, so a suppressed
    /// or orphaned id is seeded [`DatasetState::Hidden`] in place rather than by a later step
    /// the next walk would undo. The periodic caller must therefore call
    /// [`Self::reload_suppressions`] first, so a just-authored `hide` is already in the set
    /// the seed consults.
    ///
    /// Returns the whole [`HydrateStats`](gdi_node_standalone_core::cache::HydrateStats), not
    /// just `loaded`. `skipped` counts dataset directories whose `manifest.json` is present
    /// but unreadable or corrupt; `verify` enumerates the cache, so a skipped dataset is one
    /// it never scrubs.
    pub fn hydrate_cache_from_disk(&self) -> gdi_node_standalone_core::cache::HydrateStats {
        // Walk the disk with no lock held. This is the expensive half, a `read_dir` plus a
        // manifest read, JSON parse and overlay merge per dataset, and holding the status
        // mutex across it would block the request path for the whole reload: the
        // management-plane state oracle takes that mutex on every call.
        let scan = gdi_node_standalone_core::cache::scan_disk(&self.config.service.data_dir);
        // Take the suppression read lock before the status lock, the same
        // suppressions-then-status order `apply_suppressions_to_cache` and
        // `enforce_suppressions` hold, so a concurrent enforce cannot deadlock against this
        // hydrate. Passed into the projection so a suppressed id is seeded `Hidden` in place.
        let hydrated = {
            let suppressions = self
                .suppressions
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let status = self
                .status
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // `apply_scan` skips any id with a live deletion-intent marker, which keeps an
            // erase that began during the walk from being undone by it.
            //
            // The orphan rule rides inside the projection, over the live channel set. The
            // withhold lives in neither the status index, which keeps the source-declared
            // `Visible`, nor the suppression set, so a projection that did not ask would
            // re-serve a departed provider's datasets on every walk. Snapshotted once,
            // outside the per-dataset loop.
            let reloadable = self.reloadable();
            gdi_node_standalone_core::cache::apply_scan(
                &scan,
                &self.config.service.data_dir,
                StatusWrite::held(&status),
                &status,
                &self.cache,
                &suppressions,
                &|channel| channel_is_orphaned(&reloadable, channel),
            )
        };
        // A skipped dataset (present but unreadable or corrupt manifest) is a published
        // dataset dropping out of serving. Core warns per dataset; this surfaces the
        // aggregate as a page-able metric, since core stays metrics-free.
        if hydrated.skipped > 0 {
            crate::metrics::manifest_reload_skipped(hydrated.skipped as u64);
        }
        if hydrated.evicted > 0 {
            // A stale cache entry cleared by the authoritative-reconcile net: a dataset whose
            // dir is gone. Expected to be 0; a non-zero value means a removal ghost was
            // caught here rather than served until restart.
            tracing::info!(
                evicted = hydrated.evicted,
                "full reload evicted stale cache entries (datasets no longer on disk)"
            );
        }
        hydrated
    }

    /// Attach a configured PME runtime (the Vault-minting DEK source + cached key
    /// retriever), consuming and returning `self` for the builder-style wiring in
    /// `main`. Only meaningful under the `pme` feature.
    #[cfg(feature = "pme")]
    #[must_use]
    pub fn with_pme(mut self, pme: Option<Arc<crate::pme::PmeRuntime>>) -> Self {
        self.pme = pme;
        self
    }

    /// The PME read context for the query path: a cached Vault-backed key
    /// retriever when PME is active, else the plaintext context. A `PARE` file
    /// decrypts through the retriever; a `PAR1` file (or any no-PME build) reads
    /// plaintext; the mixed store reads either.
    #[must_use]
    pub fn dataset_decryptor(&self) -> DatasetDecryptor {
        #[cfg(feature = "pme")]
        {
            if let Some(pme) = &self.pme {
                return DatasetDecryptor::with_retriever(pme.retriever());
            }
        }
        DatasetDecryptor::plaintext()
    }

    /// The PME write context for the ingest store: a Vault-minting encryptor when
    /// PME is active, else the plaintext context (an ordinary `fs::copy` store).
    #[must_use]
    pub fn dataset_encryptor(&self) -> DatasetEncryptor {
        #[cfg(feature = "pme")]
        {
            if let Some(pme) = &self.pme {
                return DatasetEncryptor::with_minter(pme.minter());
            }
        }
        DatasetEncryptor::plaintext()
    }

    /// Whether at-rest encryption is configured (`[vault].transit_key`) but the PME runtime
    /// is not active, as when Vault was unreachable at boot and the node degraded keyless.
    ///
    /// In that state [`dataset_encryptor`](Self::dataset_encryptor) returns the plaintext
    /// context, so ingesting a plaintext staging dir would write parquet unencrypted at
    /// rest, and permanently: datasets are immutable and no later reconcile re-encrypts
    /// them. Callers must fail closed and park the ingest. Always `false` on a build without
    /// the `pme` feature.
    #[must_use]
    pub fn at_rest_encryption_required_but_inactive(&self) -> bool {
        #[cfg(feature = "pme")]
        {
            if self.config.has_transit_key() && self.pme.is_none() {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state_in(dir: &std::path::Path) -> AppState {
        state_with(dir, "")
    }

    /// `state_in` plus extra `[service]` lines, so a test can pin the config value it is
    /// actually about instead of inheriting whatever the default happens to be.
    fn state_with(dir: &std::path::Path, extra_service: &str) -> AppState {
        let toml = format!(
            r#"
[service]
base_url = "https://x.example"
data_dir = "{}"
{extra_service}

[beacon]
id = "org.x.beacon"
name = "X"
"#,
            dir.display()
        );
        let config = gdi_node_standalone_core::config::ServiceConfig::from_toml_str(&toml)
            .expect("minimal config must parse");
        AppState::new(
            config,
            gdi_node_standalone_core::cache::StatusIndex::new(),
            crate::identities::NodeIdentities::empty(),
        )
    }

    #[test]
    fn public_visibility_stale_tracks_the_serve_time_gate_for_the_oracle() {
        // A bare `visible` from the state oracle would be wrong for a dataset the staleness
        // gate is withholding: the operator is told "served" while collections are 0. The
        // oracle consults this predicate so the two agree.
        let dir = tempfile::tempdir().expect("tempdir");
        let toml = format!(
            "[service]\nbase_url=\"https://x.example\"\ndata_dir=\"{}\"\n\
             max_visibility_staleness_seconds=30\n[beacon]\nid=\"o.x\"\nname=\"X\"\n",
            dir.path().display()
        );
        let config = gdi_node_standalone_core::config::ServiceConfig::from_toml_str(&toml)
            .expect("config parses");
        let state = AppState::new(
            config,
            gdi_node_standalone_core::cache::StatusIndex::new(),
            crate::identities::NodeIdentities::empty(),
        );

        // A bucket that reconciled and then went dark (a 2020 stamp is stale under any bound).
        state
            .readiness
            .record_reconcile_at("provider-a", None, "2020-01-01T00:00:00Z".to_owned());

        assert!(
            state.public_visibility_stale(DatasetState::Visible, "provider-a"),
            "a visible dataset on a dark bucket must read as staleness-withheld"
        );
        // A non-visible state is never staleness-withheld (it isn't on the public plane).
        assert!(!state.public_visibility_stale(DatasetState::Hidden, "provider-a"));
        // A fresh reconcile is not stale.
        state.readiness.record_reconcile("provider-a", None);
        assert!(!state.public_visibility_stale(DatasetState::Visible, "provider-a"));
        // A channel that never reconciled (the inbox) is never stale.
        assert!(!state.public_visibility_stale(DatasetState::Visible, "inbox"));
    }

    /// A minimally valid cached entry, for tests that need ids in the serving cache.
    fn cached_entry(
        id: &str,
        state: DatasetState,
    ) -> gdi_node_standalone_core::cache::DatasetEntry {
        use gdi_node_standalone_core::model;
        gdi_node_standalone_core::cache::DatasetEntry {
            id: id.to_owned(),
            metadata: model::ManifestMetadata {
                dataset_id: id.to_owned(),
                catalog: "gdi-aggregated".to_owned(),
                title: model::LocalizedText::Plain("Sample".to_owned()),
                description: None,
                access_rights: "PUBLIC".to_owned(),
                applicable_legislation: vec![],
                license: "https://example.org/license".to_owned(),
                creator: vec![],
                health_category: vec![],
                keywords: None,
                number_of_unique_individuals: None,
                conforms_to: None,
                type_: None,
                legal_basis: None,
                is_referenced_by: None,
                other_identifier: None,
                contact_point: None,
                number_of_records: Some(1),
                populations: None,
            },
            config: model::ManifestConfig {
                mode: model::DatasetMode::Aggregated,
                block_range: 10_000_000,
                af_source: None,
                af_source_reference: None,
                min_allele_count: 0,
                hide_lower_counts: None,
                assembly: model::Assembly {
                    reference: "GRCh38".to_owned(),
                },
                manifest_version: 1,
                generated_by: "test".to_owned(),
            },
            state,
            metadata_modified: None,
        }
    }

    fn status_entry(channel: &str) -> StatusEntry {
        StatusEntry {
            state: DatasetState::Visible,
            error_message: None,
            channel: channel.to_owned(),
            last_seen_signature: None,
            provenance: gdi_node_standalone_core::cache::DatasetProvenance::Unknown,
        }
    }

    /// `AppState` over a config declaring one bucket, `kept`, rooted at `dir`.
    fn state_with_bucket_kept(dir: &std::path::Path) -> AppState {
        let toml = format!(
            r#"
[service]
base_url = "https://x.example"
data_dir = "{}"

[beacon]
id = "org.x.beacon"
name = "X"

[[s3.buckets]]
name = "kept"
endpoint = "https://s3.example.org"
bucket = "b-kept"
"#,
            dir.display()
        );
        let config = gdi_node_standalone_core::config::ServiceConfig::from_toml_str(&toml)
            .expect("config must parse");
        AppState::new(
            config,
            gdi_node_standalone_core::cache::StatusIndex::new(),
            crate::identities::NodeIdentities::empty(),
        )
    }

    /// A channel whose `[[s3.buckets]]` entry was removed must have its datasets projected
    /// `Hidden` by the hydrate, while a configured channel and the inbox are untouched and a
    /// status-only orphan id is reported without panicking.
    ///
    /// The mechanism is the immediate withhold, not the staleness bound: an orphan's
    /// staleness age measures from process start, so a restart would re-open a serving
    /// window each boot.
    #[test]
    fn hydrate_withholds_only_the_undeclared_channels() {
        const KEPT: &str = "GDI-EE-UTARTU-20260409143052901";
        const GONE_A: &str = "GDI-EE-UTARTU-20260409143052902";
        const GONE_ERRORED: &str = "GDI-EE-UTARTU-20260409143052903";
        const INBOXED: &str = "GDI-EE-UTARTU-20260409143052904";

        let dir = tempfile::tempdir().expect("tempdir");
        let state = state_with_bucket_kept(dir.path());
        {
            let mut status = state
                .status
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            status.insert(KEPT.to_owned(), status_entry("kept"));
            status.insert(GONE_A.to_owned(), status_entry("gone"));
            // Status-only: an errored ingest published nothing, but the channel still owns it.
            status.insert(GONE_ERRORED.to_owned(), status_entry("gone"));
            status.insert(
                INBOXED.to_owned(),
                status_entry(crate::health::INBOX_CHANNEL),
            );
        }
        for id in [KEPT, GONE_A, INBOXED] {
            write_dataset_dir(dir.path(), id);
        }

        let hydrated = state.hydrate_cache_from_disk();
        assert_eq!(
            hydrated.loaded, 3,
            "precondition: every published dir was projected"
        );

        assert_eq!(
            state.orphaned_channels(),
            vec![("gone".to_owned(), 2)],
            "the departed channel is reported once, with both its datasets counted \
             (the uncached errored one included)"
        );
        assert_eq!(
            state.cache.get(GONE_A).map(|e| e.state),
            Some(DatasetState::Hidden),
            "the orphan channel's dataset is withheld by the projection itself"
        );
        assert_eq!(
            state.cache.get(KEPT).map(|e| e.state),
            Some(DatasetState::Visible),
            "a channel the config declares is untouched"
        );
        assert_eq!(
            state.cache.get(INBOXED).map(|e| e.state),
            Some(DatasetState::Visible),
            "the inbox never appears in [[s3.buckets]] and must never be withheld by this"
        );

        // Idempotent: a second walk reports the same and changes nothing.
        state.hydrate_cache_from_disk();
        assert_eq!(state.orphaned_channels(), vec![("gone".to_owned(), 2)]);
        assert_eq!(
            state.cache.get(GONE_A).map(|e| e.state),
            Some(DatasetState::Hidden)
        );
    }

    /// `Reloadable::channels` is the declared channel set the orphan rule reads: every
    /// `[[s3.buckets]].name`, plus `inbox` when `[service].inbox` is set. A bucket a reload
    /// removes is carried forward, because removal is restart-only and its monitor is still
    /// polling, so withholding would flap against that monitor's reconcile.
    #[test]
    fn reloadable_channels_name_every_bucket_and_the_inbox_and_survive_a_removal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let toml = format!(
            r#"
[service]
base_url = "https://x.example"
data_dir = "{}"
inbox = "{}"

[beacon]
id = "org.x.beacon"
name = "X"

[[s3.buckets]]
name = "b1"
endpoint = "https://s3.example.org"
bucket = "b-1"
"#,
            dir.path().display(),
            dir.path().join("inbox").display()
        );
        let config = gdi_node_standalone_core::config::ServiceConfig::from_toml_str(&toml)
            .expect("config must parse");
        let reloadable = Reloadable::from_config(&config);
        assert_eq!(
            reloadable.channels,
            ["b1".to_owned(), "inbox".to_owned()].into_iter().collect()
        );
        assert!(!channel_is_orphaned(&reloadable, "b1"));
        assert!(!channel_is_orphaned(&reloadable, "inbox"));
        assert!(channel_is_orphaned(&reloadable, "departed"));

        // A reload that no longer names `b1` keeps it declared until the restart.
        let mut without = Reloadable::default();
        without.channels.insert("b2".to_owned());
        let merged = without.retaining_removed_channels(&reloadable);
        assert!(
            !channel_is_orphaned(&merged, "b1"),
            "a removed bucket's monitor is still polling; its datasets must not read as orphaned"
        );
        assert!(!channel_is_orphaned(&merged, "b2"));

        // With no `[service].inbox`, the inbox is never orphaned: it is excluded by name.
        let bare = Reloadable::default();
        assert!(!channel_is_orphaned(&bare, "inbox"));
        assert!(channel_is_orphaned(&bare, "b1"));
    }

    /// A minimally valid published dataset directory under `data_dir`, so the hydrate walk
    /// produces a candidate for `id` that the projection has to decide a state for.
    fn write_dataset_dir(data_dir: &std::path::Path, id: &str) {
        use gdi_node_standalone_core::model;
        let entry = cached_entry(id, DatasetState::Hidden);
        let dir = data_dir.join(id);
        std::fs::create_dir_all(&dir).expect("dataset dir");
        let manifest = model::Manifest {
            payload: None,
            metadata: entry.metadata,
            files: Vec::new(),
            internal: model::Internal::default(),
            config: entry.config,
        };
        let bytes = serde_json::to_vec(&manifest).expect("manifest json");
        gdi_node_standalone_core::util::write_durable_atomic_private(
            &dir.join("manifest.json"),
            &bytes,
        )
        .expect("manifest write");
    }

    /// The orphan withhold must survive a rescan. `hydrate_cache_from_disk` recomputes every
    /// cached state from the status index, which still records the orphan's dataset as
    /// `Visible`, since the withhold is cache-only and the override store has no record of
    /// it. A projection that did not apply the orphan rule itself would return the departed
    /// provider's data to the public plane one `rescan_interval_seconds` tick after boot.
    #[test]
    fn hydrate_keeps_an_orphan_channel_withheld() {
        const GONE: &str = "GDI-EE-UTARTU-20260409143052905";

        let dir = tempfile::tempdir().expect("tempdir");
        let state = state_in(dir.path());
        write_dataset_dir(dir.path(), GONE);
        {
            let mut status = state
                .status
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            status.insert(GONE.to_owned(), status_entry("gone"));
        }
        // What a boot finds: a served entry for a channel no `[[s3.buckets]]` declares.
        state.cache.insert(
            StatusWrite::unshared(),
            cached_entry(GONE, DatasetState::Visible),
        );

        // The boot hydrate.
        let hydrated = state.hydrate_cache_from_disk();
        assert_eq!(
            hydrated.loaded, 1,
            "precondition: the walk projected the dataset"
        );
        assert_eq!(state.orphaned_channels(), vec![("gone".to_owned(), 1)]);
        assert_eq!(
            state.cache.get(GONE).map(|e| e.state),
            Some(DatasetState::Hidden),
            "withheld at boot"
        );

        // The periodic rescan.
        state.hydrate_cache_from_disk();
        assert_eq!(
            state.cache.get(GONE).map(|e| e.state),
            Some(DatasetState::Hidden),
            "a rescan must not undo the orphan withhold: the status index still says \
             Visible and the override store has no record, so only a projection that \
             applies the rule itself keeps a departed provider's data off the air"
        );
    }

    /// A boot config declaring `buckets`, for [`write_config`]. A real file, so a reload can
    /// re-read it.
    #[cfg(feature = "s3")]
    fn bucket_config_toml(dir: &std::path::Path, buckets: &[&str]) -> String {
        let mut toml = format!(
            r#"
[service]
base_url = "https://x.example"
data_dir = "{}"

[beacon]
id = "org.x.beacon"
name = "X"
"#,
            dir.display()
        );
        for name in buckets {
            use std::fmt::Write as _;
            write!(
                toml,
                "\n[[s3.buckets]]\nname = \"{name}\"\nendpoint = \"https://s3.example.org\"\nbucket = \"b-{name}\"\n"
            )
            .expect("writing to a String cannot fail");
        }
        toml
    }

    /// A bucket the reload re-declares is configured again, and the next hydrate must serve
    /// its datasets: the orphan rule reads the live channel set, not the boot config, or a
    /// reload-added bucket's datasets stay withheld until a restart while the reload's own
    /// log line says the monitor started.
    #[cfg(feature = "s3")]
    #[test]
    fn a_reload_that_re_declares_a_bucket_lifts_the_orphan_withhold_on_the_next_hydrate() {
        const GONE: &str = "GDI-EE-UTARTU-20260409143052906";

        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = write_config(dir.path(), &bucket_config_toml(dir.path(), &[]));
        let state = state_from_file(&config_path);
        write_dataset_dir(dir.path(), GONE);
        {
            let mut status = state
                .status
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            status.insert(GONE.to_owned(), status_entry("gone"));
        }
        state.hydrate_cache_from_disk();
        assert_eq!(
            state.cache.get(GONE).map(|e| e.state),
            Some(DatasetState::Hidden),
            "precondition: orphaned at boot"
        );

        // The operator re-declares the bucket and reloads.
        write_config(dir.path(), &bucket_config_toml(dir.path(), &["gone"]));
        state
            .reload_config_from(&config_path, ReloadTrigger::Signal)
            .expect("the reloaded file passes preflight");
        state.hydrate_cache_from_disk();
        assert_eq!(
            state.cache.get(GONE).map(|e| e.state),
            Some(DatasetState::Visible),
            "a re-declared bucket is not orphaned: the hydrate must read the live channel set"
        );
    }

    #[test]
    fn suppression_reload_diff_reports_adds_removes_and_mode_changes() {
        // A direct `rm` or a hand-written suppression file bypasses the CLI's per-write
        // audit, so the node's reload diff is the only record of what changed. It must catch
        // a new withhold, a lifted one and a mode change.
        let old: BTreeMap<String, &'static str> = [
            ("GDI-EE-UTARTU-keep".to_owned(), "hide"),
            ("GDI-EE-UTARTU-lift".to_owned(), "hide"),
            ("GDI-EE-UTARTU-escalate".to_owned(), "hide"),
        ]
        .into_iter()
        .collect();
        let new: BTreeMap<String, &'static str> = [
            ("GDI-EE-UTARTU-keep".to_owned(), "hide"), // unchanged
            ("GDI-EE-UTARTU-escalate".to_owned(), "remove"), // mode changed
            ("GDI-EE-UTARTU-forged".to_owned(), "hide"), // forged/added out-of-band
        ]
        .into_iter()
        .collect();

        let (added, removed) = AppState::suppression_reload_diff(&old, &new);
        // A new withhold and a mode change both surface in `added` with the new mode; the
        // deleted withhold surfaces in `removed`; an unchanged one appears in neither.
        assert_eq!(
            added,
            vec![
                "GDI-EE-UTARTU-escalate=remove".to_owned(),
                "GDI-EE-UTARTU-forged=hide".to_owned(),
            ]
        );
        assert_eq!(removed, vec!["GDI-EE-UTARTU-lift".to_owned()]);

        // An identical snapshot is a no-op (nothing to audit).
        let (a2, r2) = AppState::suppression_reload_diff(&new, &new);
        assert!(a2.is_empty() && r2.is_empty());
    }

    #[test]
    fn public_visibility_stale_is_off_when_the_bound_is_zero() {
        // An explicit 0 disables the gate, so the oracle must never report staleness on a
        // node that has opted out. Set explicitly rather than relying on the default: a test
        // that reads its precondition from a default stops testing what it names the moment
        // that default moves.
        let dir = tempfile::tempdir().expect("tempdir");
        let state = state_with(dir.path(), "max_visibility_staleness_seconds = 0");
        state
            .readiness
            .record_reconcile_at("provider-a", None, "2020-01-01T00:00:00Z".to_owned());
        assert!(!state.public_visibility_stale(DatasetState::Visible, "provider-a"));
    }

    /// The shipped default withholds a dataset whose channel went dark:
    /// `max_visibility_staleness_seconds` defaults to 24 h.
    #[test]
    fn public_visibility_stale_is_on_by_default_for_a_long_dark_channel() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = state_in(dir.path()); // no explicit bound => the 86400 default
        state
            .readiness
            .record_reconcile_at("provider-a", None, "2020-01-01T00:00:00Z".to_owned());
        assert!(
            state.public_visibility_stale(DatasetState::Visible, "provider-a"),
            "a channel dark since 2020 is well past the 24 h default; leaving it visible \
             serves a dataset whose retraction the node could not have observed"
        );
    }

    #[test]
    fn persist_skips_a_stale_out_of_order_snapshot() {
        // A snapshot whose sequence is not strictly greater than the last durably written
        // one must be skipped, so a serialize/write reordering cannot regress
        // `.status.json` to an older snapshot.
        let dir = tempfile::tempdir().expect("tempdir");
        let state = state_in(dir.path());
        let status_path = dir.path().join(".status.json");

        // Simulate a newer snapshot (seq 5) already durably written.
        *state
            .persist_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = 5;
        // A fresh AppState assigns seq 1 to this snapshot (1 <= 5): it must be skipped.
        {
            let status = state
                .status
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state
                .persist_status_index(status)
                .expect("a skipped stale write is Ok");
        }
        assert!(
            !status_path.exists(),
            "a stale (out-of-order) snapshot must not be written"
        );

        // A strictly-newer snapshot is written.
        *state
            .persist_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = 0;
        {
            let status = state
                .status
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state
                .persist_status_index(status)
                .expect("a newer snapshot persists");
        }
        assert!(
            status_path.exists(),
            "a strictly-newer snapshot must be written"
        );
    }

    /// An erasure must also remove the node's inbox-side copies, not just `data_dir/{id}`.
    ///
    /// A successful ingest consumes its source, so most datasets leave nothing behind. An
    /// unconsumed drop does, and nothing GCs those: `rejected_retention_hours` reaps only
    /// `.rejected/`. Every shape is asserted, because they are removed by different calls
    /// (`remove_file` versus `remove_dir_all`).
    ///
    /// The one inbox-side file about `id` that must survive is a `deleted`
    /// `{id}.state.json`. It is the provider's tombstone, so an erasure that deleted it would
    /// re-open ingest for the id being erased.
    #[tokio::test]
    async fn erasing_a_dataset_also_erases_its_inbox_side_copies() {
        let dir = tempfile::tempdir().expect("tempdir");
        let inbox = dir.path().join("inbox");
        std::fs::create_dir_all(inbox.join(".rejected")).expect("create inbox");
        let state = state_with(dir.path(), &format!("inbox = \"{}\"", inbox.display()));
        let id = "GDI-EE-UTARTU-20260409143052837";

        let drop_file = inbox.join(format!("{id}.tar.c4gh"));
        let partial = inbox.join(format!("{id}.tar.c4gh.partial"));
        let overlay = inbox.join(format!("{id}.metadata.json"));
        let tombstone = inbox.join(format!("{id}.state.json"));
        let staging = inbox.join(id);
        let rejected = inbox.join(".rejected").join(id);
        std::fs::write(&drop_file, b"ciphertext").expect("write an unconsumed drop");
        std::fs::write(&partial, b"cipher").expect("write an in-flight drop");
        std::fs::write(&overlay, b"{}").expect("write a metadata sidecar");
        std::fs::write(&tombstone, br#"{"state":"deleted"}"#).expect("write the tombstone");
        std::fs::create_dir_all(&staging).expect("create a staging dir");
        std::fs::write(staging.join("manifest.json"), b"{}").expect("write a staged manifest");
        std::fs::create_dir_all(&rejected).expect("create a quarantine entry");

        state.erase_dataset(id, "inbox").await;

        assert!(
            !drop_file.exists(),
            "an erasure left the unconsumed .tar.c4gh drop on the volume"
        );
        assert!(
            !partial.exists(),
            "an erasure left an in-flight .partial drop on the volume"
        );
        assert!(
            !overlay.exists(),
            "an erasure left the provider's metadata sidecar on the volume"
        );
        assert!(
            !staging.exists(),
            "an erasure left the plaintext staging dir on the volume"
        );
        assert!(
            !rejected.exists(),
            "an erasure left the quarantined copy on the volume"
        );
        assert!(
            tombstone.exists(),
            "the `deleted` tombstone is the provider's retraction record and must survive"
        );
    }

    /// The inbox cleanup joins the dataset id onto a path, so it re-asserts the id is valid
    /// rather than inheriting that assumption from its callers. A `..` id must delete nothing.
    #[tokio::test]
    async fn erase_refuses_inbox_cleanup_for_a_malformed_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let inbox = dir.path().join("inbox");
        std::fs::create_dir_all(&inbox).expect("create inbox");
        let state = state_with(dir.path(), &format!("inbox = \"{}\"", inbox.display()));

        // A file outside the inbox that a traversing id would reach.
        let outside = dir.path().join("outside.txt");
        std::fs::write(&outside, b"must survive").expect("write the sentinel");

        state.erase_inbox_artifacts("../outside.txt").await;

        assert!(
            outside.exists(),
            "a malformed id escaped the inbox and deleted outside it"
        );
    }

    #[tokio::test]
    async fn enforce_suppressions_erases_a_remove_suppressed_dir_thats_not_cached() {
        // Erasure completeness: a `Remove`-suppressed id whose `data_dir/{id}/` exists on
        // disk but is not in the cache, because `hydrate` skipped a corrupt
        // `manifest.json`, must still be erased. Walking only the cache would leave that
        // data on disk indefinitely.
        let dir = tempfile::tempdir().expect("tempdir");
        let state = state_in(dir.path());
        let id = "GDI-EE-UTARTU-20260409143052837";

        // On disk, but never entered into the cache or the status index.
        let ds_dir = dir.path().join(id);
        std::fs::create_dir_all(&ds_dir).expect("create dataset dir");
        std::fs::write(ds_dir.join("manifest.json"), b"not valid json")
            .expect("write a stand-in for a corrupt manifest");
        assert!(state.cache.get(id).is_none(), "must not be cached");
        assert!(
            state
                .status
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(id)
                .is_none(),
            "must have no status entry"
        );

        // Write a `Remove` suppression for it directly to the override store, then load
        // it the same way `SIGUSR1`/the periodic reload would.
        let sub = suppression::suppressions_subdir(&state.config.service.override_dir_resolved());
        suppression::write_file(
            &sub,
            id,
            &suppression::Suppression {
                mode: SuppressMode::Remove,
                reason: "erasure".to_owned(),
                at: String::new(),
            },
        )
        .expect("write suppression file");
        state.reload_suppressions();

        state.enforce_suppressions().await;

        assert!(
            !ds_dir.exists(),
            "an on-disk-but-uncached Remove-suppressed dataset must be erased"
        );
    }

    /// Whether `id` currently has a loaded withhold, without a poisoning `unwrap`.
    fn suppressed(state: &AppState, id: &str) -> bool {
        state
            .suppressions
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(id)
            .is_some()
    }

    #[test]
    fn reload_keeps_withholds_when_the_suppressions_subdir_is_destroyed() {
        // A destroyed store must not read as an empty one. `suppression::load` reads
        // `root/suppressions/`, so a guard that checked only the store root would pass when
        // that subdirectory alone is deleted, load the empty set and lift every withhold on
        // the next SIGUSR1. `require_override_store` exists so this cannot happen silently.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = state_in(dir.path());
        {
            let cfg = std::sync::Arc::get_mut(&mut state.config)
                .expect("sole owner of the config at test setup");
            cfg.service.require_override_store = true;
        }
        let root = state.config.service.override_dir_resolved();
        let sub = suppression::suppressions_subdir(&root);
        std::fs::create_dir_all(&sub).expect("create suppressions subdir");

        let id = "GDI-EE-UTARTU-20260409143052900";
        suppression::write_file(
            &sub,
            id,
            &suppression::Suppression {
                mode: SuppressMode::Hide,
                reason: "take-down".to_owned(),
                at: String::new(),
            },
        )
        .expect("write suppression file");
        state.reload_suppressions();
        assert!(
            suppressed(&state, id),
            "precondition: the withhold is loaded"
        );

        // The store is destroyed beneath a surviving root.
        std::fs::remove_dir_all(&sub).expect("destroy suppressions subdir");
        state.reload_suppressions();

        assert!(
            suppressed(&state, id),
            "a destroyed store must keep the last known withholds, not lift them"
        );
    }

    #[tokio::test]
    async fn enforce_suppressions_erases_a_channel_remove_suppressed_dir_thats_not_cached() {
        // The channel analogue of the case above: a `channel take-down` implies every member
        // id, but the store names only the channel, so the erasure cross-check must resolve
        // membership via the status index rather than the cache, which this id never enters.
        let dir = tempfile::tempdir().expect("tempdir");
        let state = state_in(dir.path());
        let id = "GDI-EE-UTARTU-20260409143052900";
        let channel = "primary";

        let ds_dir = dir.path().join(id);
        std::fs::create_dir_all(&ds_dir).expect("create dataset dir");
        std::fs::write(ds_dir.join("manifest.json"), b"not valid json")
            .expect("write a stand-in for a corrupt manifest");
        assert!(state.cache.get(id).is_none(), "must not be cached");

        // A status entry exists (so channel membership is resolvable) but the id is not
        // cached; mirrors a corrupt-manifest hydrate skip after a restart.
        {
            let mut status = state
                .status
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            status.insert(
                id.to_owned(),
                gdi_node_standalone_core::cache::StatusEntry {
                    state: DatasetState::Visible,
                    error_message: None,
                    channel: channel.to_owned(),
                    last_seen_signature: None,
                    provenance: gdi_node_standalone_core::cache::DatasetProvenance::Unknown,
                },
            );
        }

        // Only a channel-level Remove, with no id-level suppression file.
        let sub = suppression::suppressions_subdir(&state.config.service.override_dir_resolved());
        suppression::write_channel_file(
            &sub,
            channel,
            &suppression::Suppression {
                mode: SuppressMode::Remove,
                reason: "provider compromised".to_owned(),
                at: String::new(),
            },
        )
        .expect("write channel suppression file");
        state.reload_suppressions();

        state.enforce_suppressions().await;

        assert!(
            !ds_dir.exists(),
            "an on-disk-but-uncached member of a Remove-suppressed channel must be erased"
        );
        assert!(
            state
                .status
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(id)
                .is_none(),
            "the status entry must be purged by the erase"
        );
    }

    #[cfg(feature = "pme")]
    #[test]
    fn at_rest_required_but_inactive_when_transit_key_set_without_pme() {
        // A node with [vault].transit_key configured but PME inactive, as when Vault is down
        // at boot, must report at-rest encryption as required-but-inactive so the ingest
        // path fails closed instead of writing plaintext at rest.
        let dir = tempfile::tempdir().expect("tempdir");

        // No [vault] block at all -> not required.
        assert!(!state_in(dir.path()).at_rest_encryption_required_but_inactive());

        // [vault].transit_key set, but AppState::new leaves PME inactive (pme = None).
        let toml = format!(
            r#"
[service]
base_url = "https://x.example"
data_dir = "{}"

[beacon]
id = "org.x.beacon"
name = "X"

[vault]
address = "https://vault.example"
kv_path = "node/id"
transit_key = "at-rest"
"#,
            dir.path().display()
        );
        let config = gdi_node_standalone_core::config::ServiceConfig::from_toml_str(&toml)
            .expect("config with transit_key must parse");
        let state = AppState::new(
            config,
            gdi_node_standalone_core::cache::StatusIndex::new(),
            crate::identities::NodeIdentities::empty(),
        );
        assert!(
            state.at_rest_encryption_required_but_inactive(),
            "transit_key configured + PME inactive must be required-but-inactive"
        );
    }

    /// Write `toml` to `<dir>/config.toml`, returning its path: the file
    /// [`AppState::reload_config_from`] under test re-parses.
    fn write_config(dir: &std::path::Path, toml: &str) -> std::path::PathBuf {
        let path = dir.join("config.toml");
        std::fs::write(&path, toml).expect("write config.toml");
        path
    }

    /// Build an [`AppState`] whose boot config is loaded from a real file on disk, so
    /// [`AppState::reload_config_from`] is exercised as `SIGHUP` uses it: re-parsing the
    /// same path the node booted from.
    fn state_from_file(config_path: &std::path::Path) -> AppState {
        let config = gdi_node_standalone_core::config::ServiceConfig::load(Some(config_path))
            .expect("initial config loads");
        AppState::new(
            config,
            gdi_node_standalone_core::cache::StatusIndex::new(),
            crate::identities::NodeIdentities::empty(),
        )
    }

    /// The happy path: a `SIGHUP` reload picks up a newly added catalog and a newly added
    /// writer fingerprint on the next read, while a restart-only field
    /// (`min_allele_count`) edited in the same file is warned about and left unchanged.
    #[test]
    fn reload_config_applies_new_catalog_and_fingerprint_but_ignores_restart_only_edits() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = write_config(
            dir.path(),
            &format!(
                r#"
[service]
base_url = "https://x.example"
data_dir = "{}"

[catalogs]
gdi-aggregated = "GoE"

[beacon]
id = "org.x.beacon"
name = "X"
min_allele_count = 5

[ingest]
inbox_allowed_writer_fingerprints = ["sha256:orig"]
"#,
                dir.path().display()
            ),
        );
        let state = state_from_file(&config_path);
        assert_eq!(
            state.reloadable().catalogs.len(),
            1,
            "boot snapshot has one catalog"
        );

        // Rewrite the same file: add a catalog, add a writer fingerprint, and lower the
        // restart-only k-anonymity floor to 0. The reload must apply the first two live and
        // leave the third at its boot value.
        std::fs::write(
            &config_path,
            format!(
                r#"
[service]
base_url = "https://x.example"
data_dir = "{}"

[catalogs]
gdi-aggregated = "GoE"
synthetic-data = "Synthetic"

[beacon]
id = "org.x.beacon"
name = "X"
min_allele_count = 0

[ingest]
inbox_allowed_writer_fingerprints = ["sha256:orig", "sha256:new"]
"#,
                dir.path().display()
            ),
        )
        .expect("rewrite config.toml");

        state
            .reload_config_from(&config_path, ReloadTrigger::Signal)
            .expect("a valid config must reload");

        let reloadable = state.reloadable();
        assert!(
            reloadable.catalogs.contains_key("synthetic-data"),
            "a catalog added by SIGHUP must be served without a restart: {:?}",
            reloadable.catalogs
        );
        assert_eq!(
            reloadable.writer_allowlist_for("inbox"),
            ["sha256:orig", "sha256:new"],
            "a writer fingerprint added by SIGHUP must be honored without a restart"
        );
        assert_eq!(
            state.config.beacon.min_allele_count, 5,
            "min_allele_count is restart-only: a live-lowered value in the reloaded file \
             must not take effect"
        );
    }

    /// Malformed input: a `SIGHUP` reload from unparsable TOML must keep the old reloadable
    /// subset, count [`crate::metrics::CONFIG_RELOAD_FAILED_TOTAL`] and, by returning
    /// normally, never panic the serving node.
    #[test]
    fn reload_config_keeps_old_config_on_malformed_toml_and_counts_the_failure() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = write_config(
            dir.path(),
            &format!(
                r#"
[service]
base_url = "https://x.example"
data_dir = "{}"

[catalogs]
gdi-aggregated = "GoE"

[beacon]
id = "org.x.beacon"
name = "X"
"#,
                dir.path().display()
            ),
        );
        let state = state_from_file(&config_path);

        std::fs::write(&config_path, "this is not { valid toml").expect("write malformed toml");

        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let outcome = metrics::with_local_recorder(&recorder, || {
            state.reload_config_from(&config_path, ReloadTrigger::Signal)
        });

        // The closed-set reason is what `POST /reload` puts on the wire, so the two failure
        // modes must stay distinguishable here: an operator reading `unparsable` goes to the
        // TOML, one reading `invalid` goes to the values.
        assert_eq!(outcome.err(), Some(ReloadRejection::Unparsable));
        assert_eq!(
            state.reloadable().catalogs.len(),
            1,
            "a malformed reload must keep the old reloadable subset"
        );
        let render = handle.render();
        assert!(
            render.lines().any(
                |l| l.starts_with(crate::metrics::CONFIG_RELOAD_FAILED_TOTAL) && l.ends_with(" 1")
            ),
            "a failed reload must count gdi_config_reload_failed_total: {render}"
        );
    }

    /// A well-formed but invalid reload: a `SIGHUP` reload that fails the same startup
    /// preflight boot runs, here `enforce` with a newly-emptied and unacknowledged inbox
    /// allow-list, must also keep the old subset and count the failure.
    #[test]
    fn reload_config_keeps_old_config_on_a_preflight_rejection_and_counts_the_failure() {
        let dir = tempfile::tempdir().expect("tempdir");
        let inbox = dir.path().join("inbox");
        let config_path = write_config(
            dir.path(),
            &format!(
                r#"
[service]
base_url = "https://x.example"
data_dir = "{}"
inbox = "{}"

[catalogs]
gdi-aggregated = "GoE"

[beacon]
id = "org.x.beacon"
name = "X"

[ingest]
inbox_allowed_writer_fingerprints = ["sha256:orig"]
"#,
                dir.path().display(),
                inbox.display()
            ),
        );
        let state = state_from_file(&config_path);
        assert_eq!(
            state.reloadable().writer_policy,
            gdi_node_standalone_core::config::WriterPolicy::Off
        );

        // Parses fine but fails preflight: `enforce` with an empty inbox allow-list and no
        // `allow_any_writer_ack` would silently reject every encrypted package.
        std::fs::write(
            &config_path,
            format!(
                r#"
[service]
base_url = "https://x.example"
data_dir = "{}"
inbox = "{}"

[catalogs]
gdi-aggregated = "GoE"

[beacon]
id = "org.x.beacon"
name = "X"

[ingest]
writer_policy = "enforce"
"#,
                dir.path().display(),
                inbox.display()
            ),
        )
        .expect("rewrite config.toml");

        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let outcome = metrics::with_local_recorder(&recorder, || {
            state.reload_config_from(&config_path, ReloadTrigger::Signal)
        });

        // A file that parsed but failed validation is `invalid`, not `unparsable`, the
        // distinction the wire contract promises.
        assert_eq!(outcome.err(), Some(ReloadRejection::Invalid));
        assert_eq!(
            state.reloadable().writer_policy,
            gdi_node_standalone_core::config::WriterPolicy::Off,
            "a preflight-rejected reload must keep the old writer_policy"
        );
        let render = handle.render();
        assert!(
            render.lines().any(
                |l| l.starts_with(crate::metrics::CONFIG_RELOAD_FAILED_TOTAL) && l.ends_with(" 1")
            ),
            "a preflight-rejected reload must count gdi_config_reload_failed_total: {render}"
        );
    }

    /// Concurrency: a reader racing the `SIGHUP` swap must always observe a complete
    /// `Reloadable` snapshot, never a torn mix of one config's catalogs with another's
    /// writer fingerprints. The cell is a single `Arc` swapped under one write lock, so this
    /// holds structurally; the test catches a refactor that split the cell into per-field
    /// locks.
    #[test]
    fn reloadable_swap_is_torn_read_free_under_concurrent_readers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = state_in(dir.path());

        let mut reloadable_a = Reloadable::default();
        reloadable_a
            .catalogs
            .insert("cat-a".to_owned(), "A".to_owned());
        reloadable_a.inbox_allowed_writer_fingerprints = vec!["sha256:a".to_owned()];

        let mut reloadable_b = Reloadable::default();
        reloadable_b
            .catalogs
            .insert("cat-b".to_owned(), "B".to_owned());
        reloadable_b.inbox_allowed_writer_fingerprints = vec!["sha256:b".to_owned()];

        // Prime the cell to `reloadable_a` before spawning the reader. The boot
        // `Reloadable::default()` is neither the `A` nor the `B` snapshot, so a reader
        // started against it would trip the `is_a || is_b` assertion below.
        *state
            .reloadable
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(reloadable_a.clone());

        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reader_state = state.clone();
        let reader_stop = Arc::clone(&stop);
        let reader = std::thread::spawn(move || {
            let mut observations = 0usize;
            // Observe at least once before checking `stop`: under contention the writer can
            // finish all its swaps before this thread is first scheduled, leaving
            // `observations == 0` and failing the check below. Every observation still races
            // the swaps.
            loop {
                let snapshot = reader_state.reloadable();
                let is_a = snapshot.catalogs.contains_key("cat-a")
                    && snapshot.inbox_allowed_writer_fingerprints == ["sha256:a"];
                let is_b = snapshot.catalogs.contains_key("cat-b")
                    && snapshot.inbox_allowed_writer_fingerprints == ["sha256:b"];
                assert!(
                    is_a || is_b,
                    "a reader must observe a complete old-or-new snapshot, never a torn \
                     mix: {:?} / {:?}",
                    snapshot.catalogs,
                    snapshot.inbox_allowed_writer_fingerprints
                );
                observations += 1;
                if reader_stop.load(Ordering::Relaxed) {
                    break;
                }
            }
            observations
        });

        for i in 0..2000 {
            let next = if i % 2 == 0 {
                reloadable_a.clone()
            } else {
                reloadable_b.clone()
            };
            *state
                .reloadable
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(next);
        }
        stop.store(true, Ordering::Relaxed);
        let observations = reader.join().expect("reader thread must not panic");
        assert!(
            observations > 0,
            "the reader thread must have observed at least one snapshot"
        );
    }

    /// A seed must survive a drain by a monitor that does not own it.
    ///
    /// `pending_removals` is per-monitor and `plan_removals` rebuilds it from that monitor's
    /// own `absent` set, so a foreign monitor discards the seed. A global drain would also
    /// have removed it from the shared set, so the owning monitor would never see it and the
    /// retracted dataset would never be evicted.
    #[test]
    fn a_removal_seed_is_not_consumed_by_a_monitor_that_does_not_own_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = write_config(dir.path(), "");
        let state = state_from_file(&config_path);
        {
            let mut status = state
                .status
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            status.insert(
                "ds-1".to_owned(),
                gdi_node_standalone_core::cache::StatusEntry {
                    state: gdi_node_standalone_core::state::DatasetState::Visible,
                    error_message: None,
                    channel: "bucket-a".to_owned(),
                    last_seen_signature: None,
                    provenance: gdi_node_standalone_core::cache::DatasetProvenance::Unknown,
                },
            );
        }
        state.seed_removal_confirmation("ds-1");

        assert!(
            state.drain_removal_seeds_for("bucket-b").is_empty(),
            "a monitor that does not own the id must not consume its seed"
        );
        assert_eq!(
            state.drain_removal_seeds_for("bucket-a"),
            std::iter::once("ds-1".to_owned()).collect::<HashSet<String>>(),
            "the owning monitor must still receive the seed after the foreign drain"
        );
        assert!(
            state.drain_removal_seeds_for("bucket-a").is_empty(),
            "the seed is consumed once, by its owner"
        );
    }

    /// A visible dataset whose `[catalogs]` entry has been removed is reported as orphaned,
    /// and is not withheld.
    ///
    /// Both halves matter. Without the report, removing a catalog silently de-lists live
    /// data from FDP discovery: `/fairdp` lists one catalog per configured entry, so the
    /// dataset falls out of the root's `ldp:contains` while still being served. Without the
    /// second half, a config typo would pull public data off the air, which is why this is
    /// not the catalog analogue of the orphan-channel withhold (`channel_is_orphaned`).
    #[test]
    fn a_removed_catalog_is_reported_but_its_datasets_keep_serving() {
        const KEPT: &str = "GDI-EE-UTARTU-20260409143052901";
        const ORPHANED: &str = "GDI-EE-UTARTU-20260409143052902";
        const HIDDEN: &str = "GDI-EE-UTARTU-20260409143052903";

        let dir = tempfile::tempdir().expect("tempdir");
        // Only `gdi-aggregated` is configured; `retired-catalog` has been removed.
        let state = state_with(
            dir.path(),
            "\n[catalogs]\ngdi-aggregated = \"Aggregated\"\n",
        );

        let mut kept = cached_entry(KEPT, DatasetState::Visible);
        kept.metadata.catalog = "gdi-aggregated".to_owned();
        state.cache.insert(StatusWrite::unshared(), kept);

        let mut orphan = cached_entry(ORPHANED, DatasetState::Visible);
        orphan.metadata.catalog = "retired-catalog".to_owned();
        state.cache.insert(StatusWrite::unshared(), orphan);

        // Hidden datasets are not discoverable in the first place, so a hidden one under a
        // removed catalog has lost nothing and must not raise the alarm.
        let mut hidden = cached_entry(HIDDEN, DatasetState::Hidden);
        hidden.metadata.catalog = "retired-catalog".to_owned();
        state.cache.insert(StatusWrite::unshared(), hidden);

        assert_eq!(
            state.orphaned_catalogs(),
            vec![("retired-catalog".to_owned(), 1)],
            "only the visible dataset under the removed catalog counts"
        );

        // Reporting must not have changed what is served.
        assert_eq!(
            state.cache.get(ORPHANED).map(|e| e.state),
            Some(DatasetState::Visible),
            "an orphaned catalog must not withhold its datasets: a catalog is a discovery \
             grouping, the dataset still reconciles through its own channel, and the \
             provider's retraction still works, so withholding would take live public data \
             off the air over a config typo and buy nothing"
        );
        assert_eq!(
            state.cache.get(KEPT).map(|e| e.state),
            Some(DatasetState::Visible)
        );
    }

    /// A node whose catalogs all still exist reports nothing: the check must not fire on the
    /// healthy shape, or the alert it drives is noise from the first boot.
    #[test]
    fn configured_catalogs_are_not_reported_as_orphaned() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = state_with(
            dir.path(),
            "\n[catalogs]\ngdi-aggregated = \"Aggregated\"\n",
        );
        state.cache.insert(
            StatusWrite::unshared(),
            cached_entry("GDI-EE-UTARTU-20260409143052901", DatasetState::Visible),
        );
        assert!(
            state.orphaned_catalogs().is_empty(),
            "the default fixture declares gdi-aggregated, which is configured"
        );
    }

    /// Recording an overlay rejection sets both surfaces from one call: the per-id oracle
    /// field and the per-channel counter.
    ///
    /// Set separately, a call site can emit the field and miss the counter, and a node that
    /// only ever hits that site emits no `gdi_overlay_apply_failed_total` series at all, so
    /// `OverlayApplyFailing` cannot fire there.
    #[test]
    fn recording_an_overlay_error_sets_the_field_and_the_counter_together() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = state_in(dir.path());
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();

        metrics::with_local_recorder(&recorder, || {
            state.note_overlay_error("GDI-EE-UTARTU-20260409143052837", "inbox", "parse");
        });

        assert_eq!(
            state
                .overlay_error("GDI-EE-UTARTU-20260409143052837")
                .as_deref(),
            Some("parse"),
            "the oracle field must carry the reason"
        );
        let render = handle.render();
        assert!(
            render.lines().any(|l| {
                l.starts_with(crate::metrics::OVERLAY_APPLY_FAILED_TOTAL)
                    && l.contains("channel=\"inbox\"")
                    && l.contains("reason=\"parse\"")
                    && l.ends_with(" 1")
            }),
            "the inbox channel must emit the counter, or OverlayApplyFailing cannot fire \
             on an inbox-only node:\n{render}"
        );
    }

    /// The visibility sidecar gets the same treatment, and it is the more consequential of
    /// the two: a rejected `{id}.state.json` fails the dataset safe to `hidden`, so a
    /// truncated write withdraws a live dataset.
    #[test]
    fn recording_a_state_sidecar_rejection_sets_the_field_and_the_counter_together() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = state_in(dir.path());
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();

        metrics::with_local_recorder(&recorder, || {
            state.note_state_sidecar_error(
                "GDI-EE-UTARTU-20260409143052837",
                "inbox",
                crate::metrics::StateSidecarRejectReason::Unreadable,
            );
        });

        assert_eq!(
            state
                .state_sidecar_error("GDI-EE-UTARTU-20260409143052837")
                .as_deref(),
            Some("unreadable"),
            "the oracle field must say why the dataset is hidden"
        );
        let render = handle.render();
        assert!(
            render.lines().any(|l| {
                l.starts_with(crate::metrics::STATE_SIDECAR_REJECTED_TOTAL)
                    && l.contains("channel=\"inbox\"")
                    && l.contains("reason=\"unreadable\"")
                    && l.ends_with(" 1")
            }),
            "a rejected visibility sidecar must be countable:\n{render}"
        );

        // A sidecar that later parses clears the marker, so the field reports the current
        // state of the id rather than accumulating every rejection it ever had.
        state.clear_state_sidecar_error("GDI-EE-UTARTU-20260409143052837");
        assert!(
            state
                .state_sidecar_error("GDI-EE-UTARTU-20260409143052837")
                .is_none(),
            "a clean sidecar must clear the marker"
        );
    }
}
