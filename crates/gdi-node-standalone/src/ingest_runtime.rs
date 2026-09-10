//! The inbox-driven ingestion runtime: a single shared job queue drained by a
//! bounded worker pool, an inbox scanner that decides what to (re-)ingest, and the
//! declarative reconcile of `{id}.state.json` sidecars.
//!
//! * One `tokio::mpsc` queue feeds `ingest_concurrency` worker tasks; each heavy
//!   [`gdi_node_standalone_core::ingest::ingest_staging_dir`] call runs under
//!   `spawn_blocking` with explicit `JoinError::is_panic` handling so a panicking
//!   ingest becomes a permanent dataset `error`, never a crash.
//! * Jobs are deduplicated by `datasetId` via the shared in-flight markers
//!   ([`AppState::ingest_inflight`]), which also stamp when each id was marked so the
//!   sampler can report the oldest one's age.
//! * [`IngestRuntime::scan_once`] enumerates the inbox and enqueues work; it is
//!   `pub` so tests can drive it directly without depending on watcher timing.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use gdi_node_standalone_core::cache::{
    DELETED_SIDECAR_STATE, DatasetEntry, DatasetProvenance, StatusEntry, StatusWrite,
};
use gdi_node_standalone_core::config::AuditConfig;
use gdi_node_standalone_core::error::WriterUnknownKind;
use gdi_node_standalone_core::error::{CoreError, CoreResult};
use gdi_node_standalone_core::extract::ExtractBounds;
use gdi_node_standalone_core::id::is_valid_dataset_id;
use gdi_node_standalone_core::ingest::{
    IngestOk, WriterAdmission, WriterProvenance, ingest_staging_dir_with_bounds,
    ingest_tar_c4gh_with_bounds, writer_admission,
};
use gdi_node_standalone_core::s3_layout::{StateSidecar, is_data_file_name};
use gdi_node_standalone_core::state::DatasetState;
use gdi_node_standalone_core::validate_parquet::ParquetCaps;
use sha2::{Digest as _, Sha256};
use tokio::sync::{Mutex as TokioMutex, mpsc};
use tokio::task::JoinSet;
use tracing::{Instrument as _, debug, info, warn};

use crate::metrics;
use crate::state::{AppState, IngestInflight};

/// Bound on the in-memory job queue. Far above any realistic single-scan backlog;
/// dedup keeps duplicates out, so this only bounds a genuine flood.
const QUEUE_CAPACITY: usize = 4096;

/// How many detached (timed-out but still-running) ingest blocking tasks are tolerated on
/// top of the `ingest_concurrency` active ones before new ingests are refused. Bounds
/// ingest's share of tokio's shared blocking pool (default 512, shared with the public
/// Beacon read path) well below saturation, so accumulated hangs cannot starve serving.
/// New ingests resume once detached tasks finish.
const DETACHED_HEADROOM: usize = 16;

/// Decrements the running-ingest-blocking-task counter when the `spawn_blocking` closure
/// it is moved into finishes, whether the task was awaited to completion or detached on
/// timeout. It lives inside the closure so a detached task still decrements the count when
/// it eventually completes.
struct BlockingGuard(Arc<AtomicUsize>);

impl Drop for BlockingGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Sole owner of one dataset's in-flight dedup marker, releasing it on drop.
///
/// The only code that removes an id from the in-flight set. The marker keeps a dataset
/// already being ingested from being picked up again by a concurrent scan or reconcile;
/// leaking one silently skips that dataset on every future pass until the process restarts.
/// It is a guard rather than a `remove` call at each site so the release survives a panic on
/// the async path. Exactly one guard owns a given marker at a time, and [`Self::transfer`]
/// hands it on without releasing.
///
/// The guard covers the marker from the moment a worker picks a job up. Before that, the
/// scanner's error paths release it with explicit `clear_inflight` calls, and the success
/// path keeps the marker alive across the queue hand-off. A panic in the scanner between
/// marking and enqueueing still leaks it.
struct InflightGuard {
    inflight: IngestInflight,
    /// `None` once the marker has been transferred to another owner.
    id: Option<String>,
}

impl InflightGuard {
    fn new(inflight: IngestInflight, id: String) -> Self {
        Self {
            inflight,
            id: Some(id),
        }
    }

    /// Give up ownership without releasing, returning the id, because another owner (the
    /// timed-out-job supervisor) now holds the marker. Dropping this guard afterwards is a
    /// no-op, so the marker is never released twice nor prematurely.
    fn transfer(&mut self) -> Option<String> {
        self.id.take()
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            lock(&self.inflight).remove(&id);
        }
    }
}

/// RAII cleanup for one in-flight job in [`worker_loop`]: on drop it restores the `active`
/// count and the `INGEST_INFLIGHT` gauge, and releases the in-flight dedup marker for the id
/// unless it was transferred. Drop also runs on an async-path panic unwind, so a panic in
/// `process_job`'s outcome application cannot leak the marker or latch the saturation gauge.
struct WorkerJobGuard {
    active: Arc<AtomicUsize>,
    /// Owns the dedup marker. Transferred (not dropped) for a timed-out job whose detached
    /// blocking task still owns it ([`JobDisposition::RetainInflight`]).
    marker: InflightGuard,
}

impl Drop for WorkerJobGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
        ::metrics::gauge!(metrics::INGEST_INFLIGHT).decrement(1.0);
        // `self.marker` drops here and releases, unless it was transferred.
    }
}

/// One queued ingest job: an artifact to publish under its id, how it must be
/// ingested, and the channel-specific post-processing.
#[derive(Debug, Clone)]
pub(crate) struct Job {
    /// The dataset id (the inbox entry's name, sans extension == the dataset id).
    id: String,
    /// The artifact + ingest method (a staging dir, or an encrypted package).
    source: JobSource,
    /// The content-hash signature recorded as last-seen on success.
    signature: String,
    /// The owning channel recorded in the status index (`inbox` or a bucket name).
    channel: String,
    /// How the job's outcome is applied (inbox quarantine vs S3 in-place).
    kind: JobKind,
}

/// How a queued job's artifact is ingested.
#[derive(Debug, Clone)]
enum JobSource {
    /// A plaintext staging directory (ingested via `ingest_staging_dir`).
    StagingDir(PathBuf),
    /// An encrypted `.tar.c4gh` package, ingested via `ingest_tar_c4gh_with_bounds`. The
    /// service always passes the operator-configured extract bounds; the defaults-only
    /// `ingest_tar_c4gh` wrapper is test-only.
    TarC4gh(PathBuf),
}

impl JobSource {
    /// The path of this artifact (the thing consumed/quarantined/cleaned up).
    fn path(&self) -> &Path {
        match self {
            Self::StagingDir(p) | Self::TarC4gh(p) => p,
        }
    }
}

/// Channel-specific post-processing of a job's outcome.
///
/// The inbox owns its artifacts: consume on success, quarantine to `.rejected/` on a
/// permanent error, read the local `{id}.state.json` sidecar for the published visibility.
/// An S3 job's artifact is a transient download under `.incoming/`, deleted on every outcome
/// because S3 retains the durable package; a permanent error is recorded in `.status.json`
/// with no quarantine move and clears on a changed `ETag`. Its published visibility comes
/// from the bucket's `{id}.state.json` sidecar.
#[derive(Debug, Clone)]
enum JobKind {
    /// An inbox drop: consume on success, quarantine on permanent error, derive
    /// the published state from the local sidecar.
    Inbox,
    /// An S3 download: the artifact is a transient download deleted on every outcome; a
    /// permanent error is recorded without a `.rejected` move, since S3 retains the durable
    /// package. Published visibility is re-read from the sidecar at publish, not captured
    /// before the download. See [`on_success`].
    #[cfg(feature = "s3")]
    S3 {
        /// The bucket handle, used to re-read `{id}.state.json` at publish time. Capturing
        /// the visibility before the download would ignore an operator unpublish issued
        /// mid-ingest until the next full poll. Cheap to carry (`Arc<dyn ObjectStore>`).
        store: crate::s3::Store,
        /// The `{id}.state.json` object key, if the listing carried one (`None` => the
        /// dataset has no sidecar => `Hidden`, the fail-safe default).
        sidecar_key: Option<object_store::path::Path>,
        /// Optional inbound W3C `traceparent` from the `.state.json` sidecar. The
        /// `ingest_job` span is parented under it when the node trusts inbound trace
        /// context, correlating the ingest with the orchestrator's publish trace. Read only
        /// by the otel span-parenting path, so it is inert without the `otel` feature.
        #[cfg_attr(
            not(feature = "otel"),
            expect(
                dead_code,
                reason = "read only by the otel ingest_job span-parenting path"
            )
        )]
        traceparent: Option<String>,
    },
}

/// The S3-specific inputs to [`IngestRuntime::enqueue_s3_tar_c4gh`], bundled so the call
/// stays within the argument limit and the publish-time re-read inputs travel together.
#[cfg(feature = "s3")]
pub(crate) struct S3Enqueue {
    /// The bucket handle, used to re-read `{id}.state.json` at publish time.
    pub(crate) store: crate::s3::Store,
    /// The `{id}.state.json` object key, if the listing carried one.
    pub(crate) sidecar_key: Option<object_store::path::Path>,
    /// Optional inbound W3C `traceparent` from the sidecar.
    pub(crate) traceparent: Option<String>,
}

/// A cheaply-cloneable handle over the running ingestion runtime.
///
/// Holds the queue sender + the dedup set so [`IngestRuntime::scan_once`] can
/// enqueue. Workers run as detached tasks; dropping the runtime closes the queue,
/// which lets the workers finish their drain and exit.
#[derive(Clone)]
pub struct IngestRuntime {
    state: AppState,
    tx: mpsc::Sender<Job>,
    inflight: IngestInflight,
    /// Count of jobs a worker is *actively processing* right now (incremented
    /// when a worker picks a job off the queue, decremented when it finishes). Mirrors the
    /// `INGEST_INFLIGHT` gauge with an in-process value. Bounded by `ingest_concurrency`,
    /// one increment per busy worker, unlike [`Self::inflight`] which also counts
    /// queued-but-not-yet-started ids.
    active: Arc<AtomicUsize>,
    /// Count of ingest blocking tasks currently running on tokio's shared blocking pool:
    /// active workers plus any detached, timed-out ingest whose `spawn_blocking` task cannot
    /// be cancelled and is still writing `datasets/{id}/`. Exposed via
    /// [`Self::inflight_blocking_count`] so the shutdown path can wait for writers to
    /// quiesce before the data-dir lock drops.
    blocking: Arc<AtomicUsize>,
    /// De-dup for the "orphaned state sidecar" log: id → the sidecar `state` value last
    /// logged for it. Logging only when the id is new or its sidecar state changed keeps a
    /// standing orphan from re-logging on every scan and burying real events. Entries are
    /// dropped once the id is no longer orphaned.
    orphan_sidecars_logged: Arc<Mutex<HashMap<String, String>>>,
    /// De-dup for the "ignored inbox entry" logs, on the same grounds as
    /// [`Self::orphan_sidecars_logged`]: an entry the scan cannot use would be re-logged on
    /// every pass, and the watcher scans far more often than `rescan_interval_seconds`
    /// suggests. A large drop of unusable entries floods the same stderr the audit stream
    /// rides on, which must never be back-pressured. Logging only when an entry is newly
    /// ignored collapses that to once per entry; the set is pruned to what the last readable
    /// scan saw, so a removed-and-re-added entry logs again and the set stays bounded by the
    /// inbox.
    ignored_entries_logged: Arc<Mutex<HashSet<String>>>,
}

impl IngestRuntime {
    /// Start the runtime: spawn `ingest_concurrency` workers draining a shared
    /// queue, and return the handle used to enqueue scans.
    #[must_use]
    pub fn start(state: AppState) -> Self {
        let (tx, rx) = mpsc::channel::<Job>(QUEUE_CAPACITY);
        // The markers live on the state (not here) so the metrics sampler can read the
        // oldest one's age; the runtime is their only writer.
        let inflight = Arc::clone(&state.ingest_inflight);
        let active: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        // Ingest blocking tasks running on tokio's shared blocking pool: active plus
        // detached, since a timed-out ingest keeps running (`spawn_blocking` is not
        // cancellable). Bounds pool occupancy so hangs cannot starve the Beacon read path.
        let blocking: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        // A single receiver shared across N workers (the "single shared queue").
        let shared_rx = Arc::new(TokioMutex::new(rx));

        let concurrency = state.config.service.ingest_concurrency.max(1);
        // Publish the resolved worker capacity as a constant gauge, so the
        // saturation alert (`inflight >= concurrency`) is deployment-independent.
        ::metrics::gauge!(metrics::INGEST_CONCURRENCY)
            .set(f64::from(u32::try_from(concurrency).unwrap_or(u32::MAX)));
        // The read path's fan-out cap, published separately: `[service].query_concurrency`
        // decouples it from ingest, so the scan-saturation alert must compare against this
        // one. The two coincide only while that knob is unset.
        let query_cap = state.config.service.query_concurrency().max(1);
        ::metrics::gauge!(metrics::QUERY_CONCURRENCY)
            .set(f64::from(u32::try_from(query_cap).unwrap_or(u32::MAX)));

        // Supervise the worker pool. `process_job` turns a panic in the blocking pipeline
        // into a permanent error, but a panic on a worker's async path would end that worker
        // silently and shrink the pool until ingest wedges, with no signal. The supervisor
        // restarts a worker that ended by panic so the pool stays at `concurrency`. A clean
        // exit, the queue closed on shutdown, is not restarted: a replacement would
        // re-observe the closed queue and spin.
        {
            let shared_rx = Arc::clone(&shared_rx);
            let inflight = Arc::clone(&inflight);
            let active = Arc::clone(&active);
            let blocking = Arc::clone(&blocking);
            let state = state.clone();
            tokio::spawn(async move {
                let spawn_worker = |set: &mut JoinSet<()>| {
                    set.spawn(worker_loop(
                        Arc::clone(&shared_rx),
                        Arc::clone(&inflight),
                        Arc::clone(&active),
                        Arc::clone(&blocking),
                        state.clone(),
                    ));
                };
                let mut set = JoinSet::new();
                for _ in 0..concurrency {
                    spawn_worker(&mut set);
                }
                while let Some(res) = set.join_next().await {
                    match res {
                        Err(e) if e.is_panic() => {
                            warn!(
                                "ingest worker panicked on its async path; restarting it to keep the pool at capacity"
                            );
                            spawn_worker(&mut set);
                        }
                        // Clean exit or cancellation at teardown: do not restart.
                        Ok(()) | Err(_) => {}
                    }
                }
            });
        }

        // `create_private_dir` applies 0o700 only to components it creates, so a `.rejected/`
        // made by an operator's `mkdir` keeps its mode and can sit world-readable beside a
        // 0o700 store, holding plaintext staging dirs and allele-frequency parquet for
        // `rejected_retention_hours`. Tighten it at startup, as the data-dir root is.
        if let Some(inbox) = state.config.service.inbox.as_deref() {
            tighten_rejected_dir(inbox);
        }

        Self {
            state,
            tx,
            inflight,
            active,
            blocking,
            orphan_sidecars_logged: Arc::new(Mutex::new(HashMap::new())),
            ignored_entries_logged: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Whether an orphaned-sidecar log line should fire for `id` at sidecar `state`: `true`
    /// only when this id has not been logged, or its sidecar `state` changed since it was,
    /// so a standing orphan is logged once per change rather than once per scan.
    fn orphan_sidecar_should_log(&self, id: &str, state: &str) -> bool {
        let mut logged = self
            .orphan_sidecars_logged
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        orphan_should_log(&mut logged, id, state)
    }

    /// Drop `id` from the orphaned-sidecar log-dedup set: it was found in the cache, so a
    /// later orphaning logs once again and the set stays bounded to currently-orphaned ids.
    fn orphan_sidecar_resolved(&self, id: &str) {
        self.orphan_sidecars_logged
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(id);
    }

    /// The number of ingest blocking tasks currently running on tokio's blocking pool:
    /// active workers plus any detached, timed-out ingest whose `spawn_blocking` task cannot
    /// be cancelled and is still writing `datasets/{id}/`. The shutdown path polls this to
    /// let writers quiesce before the data-dir lock is released, so the single-writer flock
    /// outlives the common-case writers.
    #[must_use]
    pub fn inflight_blocking_count(&self) -> usize {
        self.blocking.load(Ordering::Relaxed)
    }

    /// The periodic safety-net full reload and inbox rescan: re-hydrate the in-memory cache
    /// from the persisted `datasets/{id}/` directories, repairing anything the cache lost,
    /// then run an inbox scan. The hydration is `read_dir` plus manifest parsing, so it runs
    /// off the async reactor via `spawn_blocking`.
    ///
    /// Idempotent: hydration replaces entries in place, and the subsequent inbox scan or S3
    /// reconcile re-apply current sidecar visibility.
    ///
    /// This is the durable fallback for operator overrides. The `dataset
    /// hide`/`take-down`/`show` CLI does not signal the node, so this periodic pass is what
    /// applies an override written against a live node within one poll.
    pub async fn full_reload(&self) {
        // Re-read the suppression store from disk before the re-hydrate, so the hydrate walk
        // seeds a suppressed id `Hidden` in place and never flashes it `Visible`: `hydrate`
        // seeds visibility from the status index, which a `Hide` never touches. Re-reading
        // rather than re-applying is what covers a node that was down when the operator acted
        // and a missed SIGUSR1. The walk is blocking I/O, so it runs via `spawn_blocking`.
        let state = self.state.clone();
        let _ = tokio::task::spawn_blocking(move || state.reload_suppressions()).await;
        // Re-read the node-local metadata-overlay override store too, for the same reason:
        // an operator `dataset correct`/`--reset` written while the node was down, or a
        // missed `SIGUSR1`, must self-heal within one poll. `overlay_override::load` is the
        // same bounded blocking walk as `suppression::load`, so it is spawn-blocked too.
        let state = self.state.clone();
        let _ = tokio::task::spawn_blocking(move || state.reload_local_overlays()).await;
        let state = self.state.clone();
        let loaded = tokio::task::spawn_blocking(move || state.hydrate_cache_from_disk())
            .await
            .unwrap_or_default()
            .loaded;
        debug!(loaded, "periodic full reload re-hydrated the dataset cache");
        // Enforce again after the walk: `apply_suppressions_to_cache` refreshes the
        // suppression gauges, and a `Remove` is completed here from the seeded `Hidden` to a
        // full evict-and-erase, which the seed alone does not do.
        self.state.enforce_suppressions().await;
        // Project the freshly-reloaded node-local overlay set onto served metadata before
        // the inbox scan, so `reconcile_overlay`'s precedence check sees the current
        // override set and does not race a stale one.
        self.state.enforce_local_overlays();
        // Targeted bucket retry: process any pending reingest-request markers (clear
        // `last_seen_signature` and wake the S3 monitors) before the inbox scan, mirroring
        // the SIGUSR1 handler's ordering.
        self.state.process_reingest_requests().await;
        self.scan_once().await;
    }

    /// Scan the inbox once: enumerate artifacts, decide what to (re-)ingest per the
    /// same-source / immutability rules, enqueue ingest jobs, reconcile state
    /// sidecars, and GC stale `inbox/.rejected/` entries.
    ///
    /// Safe to call repeatedly (idempotent): an id already queued/in-flight is not
    /// re-enqueued, and an unchanged signature for a live id is a no-op.
    ///
    /// Channel suppression pauses the whole scan: while the `inbox` channel carries an
    /// active `channel-inbox.json` override, this returns immediately, with no enumeration,
    /// GC, or sidecar/overlay reconcile. It is the analogue of `BucketMonitor::run`'s in-loop
    /// pause. `consider_artifact`'s per-id `effective()` gate already refuses to (re-)ingest
    /// any inbox id once the channel entry is populated; skipping the disk walk as well
    /// costs only a suppression-set read-lock check and denies a misbehaving drop directory
    /// any further scanning attention while paused.
    pub async fn scan_once(&self) {
        let Some(inbox) = self.state.config.service.inbox.clone() else {
            return;
        };
        if self
            .state
            .suppressions
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .channel_get("inbox")
            .is_some()
        {
            debug!("inbox channel administratively suppressed; skipping the scan entirely");
            return;
        }
        // The blocking enumeration + signature hashing runs off the async runtime.
        let inbox2 = inbox.clone();
        let ignored_logged = Arc::clone(&self.ignored_entries_logged);
        let scan = tokio::task::spawn_blocking(move || scan_inbox(&inbox2, &ignored_logged)).await;
        let scan = match scan {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "inbox scan task failed");
                return;
            }
        };

        self.gc_rejected(&inbox).await;

        // A `deleted` sidecar present at scan time is a tombstone: while it is there the id
        // stays inbox-owned and any re-dropped package of the same id is suppressed. Collect
        // the tombstoned ids up front so package consideration below can skip them.
        //
        // An unreadable sidecar for an id the cache does not hold also holds the tombstone,
        // which is the erasure record and the only thing suppressing re-ingest of a package
        // still in the inbox, so a torn write must not release it. The cost is that a damaged
        // sidecar for a never-ingested id blocks its ingest until it is repaired or removed.
        let tombstoned: HashSet<&str> = scan
            .sidecars
            .iter()
            .filter(|s| {
                s.state == DELETED_SIDECAR_STATE
                    || (s.unreadable.is_some() && self.state.cache.get(&s.id).is_none())
            })
            .map(|s| s.id.as_str())
            .collect();

        // Publish the set so the state oracle can answer `410 Gone` for a tombstoned id
        // rather than the `404` that also means "never ingested". Rebuilt wholesale from the
        // sidecars on disk every scan, so a sidecar the operator removes drops out on the
        // next pass and the disk stays authoritative. Only on a scan that read the inbox: an
        // unreadable one returns `readable: false` with empty vectors, and republishing from
        // those would turn a `410 Gone` into a `404` for the whole outage.
        if scan.readable {
            let mut published = self
                .state
                .tombstoned
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *published = tombstoned.iter().map(|id| (*id).to_owned()).collect();
        }

        // Fail closed for at-rest coverage: if [vault].transit_key is configured but PME is
        // inactive, a plaintext staging dir would be written unencrypted at rest and stay
        // that way, since datasets are immutable. Park such staging dirs in the inbox until
        // PME activates instead of defeating the configured at-rest protection.
        let park_plaintext_staging = self.state.at_rest_encryption_required_but_inactive();
        for staging in &scan.staging_dirs {
            if tombstoned.contains(staging.id.as_str()) {
                info!(dataset = %staging.id, "suppressed: re-dropped package for a deleted-tombstoned id (remove the sidecar to release it)");
                continue;
            }
            if park_plaintext_staging {
                warn!(
                    dataset = %staging.id,
                    "skipped plaintext staging dir: at-rest encryption is configured \
                     ([vault].transit_key) but PME is inactive, so ingesting now would write \
                     parquet unencrypted at rest, permanently. Left in the inbox for a later \
                     scan once PME activates; resolve the Vault connection and restart."
                );
                continue;
            }
            self.consider_artifact(
                &inbox,
                staging.id.clone(),
                JobSource::StagingDir(staging.path.clone()),
            )
            .await;
        }
        for c4gh in &scan.c4gh {
            if tombstoned.contains(c4gh.id.as_str()) {
                info!(dataset = %c4gh.id, "suppressed: re-dropped package for a deleted-tombstoned id (remove the sidecar to release it)");
                continue;
            }
            if !self.state.identities.is_enabled() {
                // Keyless node: nothing can decrypt a .tar.c4gh, so skip rather than error.
                // The package stays in the inbox for a later keyed run.
                info!(
                    artifact = %c4gh.path.display(),
                    "skipped encrypted package (see `artifact`): no crypt4gh identities configured (keyless node)"
                );
                continue;
            }
            self.consider_artifact(
                &inbox,
                c4gh.id.clone(),
                JobSource::TarC4gh(c4gh.path.clone()),
            )
            .await;
        }
        for sidecar in &scan.sidecars {
            self.reconcile_sidecar(sidecar).await;
        }

        // Reconcile operator metadata overlays: apply present ones, revert removed ones.
        let present: HashSet<String> = scan.overlays.iter().map(|a| a.id.clone()).collect();
        for art in &scan.overlays {
            self.reconcile_overlay(art);
        }
        // Revert only on a scan that read the inbox. An unreadable inbox (lost mount,
        // permissions) yields an empty result, and treating that as "the operator removed
        // every sidecar" would revert every inbox-owned correction at once. The S3 side
        // gates removals on a marker change for the same reason.
        if scan.readable {
            self.reconcile_overlay_reverts(&present);
        }

        stamp_inbox_scan_success(&scan);
    }

    /// Decide and act on a single inbox artifact (a staging dir or a `.tar.c4gh`).
    ///
    /// The content-hash signature is computed lazily, only after the cheap dispositions have
    /// failed to short-circuit the artifact: the caller already filtered tombstoned and
    /// keyless drops, and the in-flight dedup below returns before hashing. A suppressed,
    /// keyless or already-queued multi-GB package is never hashed just to be discarded.
    async fn consider_artifact(&self, inbox: &Path, id: String, source: JobSource) {
        // Operator-suppression gate: a suppressed dataset is never (re-)ingested from the
        // inbox, whatever its mode. This blocks a pre-emptively-suppressed id before it
        // lands, and it is what makes a `Remove` eviction stick; otherwise the reconcile
        // that erased the dataset would immediately re-ingest the still-present inbox
        // package. The drop stays in place, since the suppression file is the control;
        // removing the suppression releases it on the next scan.
        if self
            .state
            .suppressions
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .effective(&id, "inbox")
            .is_some()
        {
            debug!(dataset = %id, "skipped: dataset is operator-suppressed; not ingesting");
            return;
        }

        // Whether the id is currently live, meaning visible or hidden in the cache.
        let live = self
            .state
            .cache
            .get(&id)
            .is_some_and(|e| matches!(e.state, DatasetState::Visible | DatasetState::Hidden));

        if live {
            // A re-drop for an id that is both live and still marked in-flight is a slow
            // ingest that crossed `ingest_timeout_seconds`, not a genuine immutable re-drop.
            // The worker was freed via `RetainInflight` while the detached blocking task ran
            // to completion and wrote `datasets/{id}/`, which the periodic full reload then
            // re-hydrated into the cache without ever running `on_success`. Quarantining the
            // source here would audit a rejection for an ingest that succeeded, so leave the
            // drop in place; a restart's inbox reap resolves it.
            if self.is_inflight(&id) {
                debug!(
                    dataset = %id,
                    "in-flight re-drop for a live id (ingest completed after timeout); leaving in place, not quarantining"
                );
                return;
            }
            // A re-presentation for an immutable id: hash to compare against last-seen.
            let sig = match signature_of_source_offloaded(&source).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(dataset = %id, error = %e, "could not signature inbox re-drop; left for retry");
                    return;
                }
            };
            let last_seen = {
                let status = lock(&self.state.status);
                status.get(&id).and_then(|e| e.last_seen_signature.clone())
            };
            if last_seen.as_deref() == Some(sig.as_str()) {
                // Unchanged: pure no-op (no log spam).
                return;
            }
            // Changed source for a live id: ignore, quarantine and log once. Also flag it on
            // the state oracle so a provider polling `/datasets/<id>/state` sees their
            // correction was dropped rather than `visible` or `null`.
            warn!(dataset = %id, "ignored: dataset is immutable; quarantining inbox re-drop");
            self.state.note_superseded_redrop(&id);
            // Quarantining an immutable dataset's re-drop is a policy rejection that
            // `record_permanent_error` never sees, so audit it here: id and a path-free cause
            // only, never the artifact contents.
            crate::audit::dataset_state_change(
                &self.state.config.audit,
                &id,
                "inbox",
                "rejected",
                "immutable-redrop",
            );
            // Quarantine first, then record the signature as last-seen. The recorded
            // signature is what makes a future identical re-drop a silent no-op above, so
            // persisting it only after the artifact has moved to `.rejected/` means a crash
            // between the two leaves the drop to be re-detected and re-quarantined rather
            // than ignored forever. A quarantine failure only warrants a log here: the
            // signature recorded below stops the re-loop whether or not the move landed.
            if let Err(e) = quarantine(inbox, &id, source.path()) {
                warn!(dataset = %id, error = %e, "could not quarantine an immutable re-drop; recording its signature to avoid re-processing");
            }
            self.record_signature(&id, &sig);
            return;
        }

        // A source whose last ingest hit a transient error is in a backoff window, e.g. Vault
        // down during a PME mint. Skip re-enqueuing it until the window elapses, so a fast
        // reconcile cannot hot-loop a persistently-failing backend. The window is cleared on
        // the first successful ingest (`on_success`).
        if self
            .state
            .retry_backoff
            .is_backing_off(&id, std::time::Instant::now())
        {
            debug!(dataset = %id, "ingest is in a transient-failure backoff window; leaving for a later reconcile");
            return;
        }

        // Absent or error: enqueue ingest, deduped by id. Claim the in-flight marker before
        // hashing so an already-queued id never re-hashes a possibly multi-GB artifact only
        // to be deduped away.
        if !self.try_mark_inflight(&id) {
            debug!(dataset = %id, "ingest already queued/in-flight; skipping");
            return;
        }
        let sig = match signature_of_source_offloaded(&source).await {
            Ok(s) => s,
            Err(e) => {
                // Could not signature: release the in-flight guard so a later scan retries.
                self.clear_inflight(&id);
                warn!(dataset = %id, error = %e, "could not signature inbox artifact; left for retry");
                return;
            }
        };
        let job = Job {
            id: id.clone(),
            source,
            signature: sig,
            channel: "inbox".to_owned(),
            kind: JobKind::Inbox,
        };
        if let Err(e) = self.tx.send(job).await {
            // Queue closed (shutting down): release the in-flight marker.
            self.clear_inflight(&id);
            warn!(dataset = %id, error = %e, "failed to enqueue ingest job");
        } else {
            // Enqueued: one more job waiting to be picked up; the worker decrements on
            // dequeue. Content-free gauge, with no dataset-id label.
            ::metrics::gauge!(metrics::INGEST_QUEUE_DEPTH).increment(1.0);
        }
    }

    /// Enqueue an externally-prepared `.tar.c4gh` ingest (the S3 channel).
    ///
    /// The S3 monitor downloads a bucket's `.tar.c4gh` to a transient path under
    /// `data_dir/.incoming/`, then calls this to feed it through the same bounded worker pool
    /// the inbox uses, so the per-`datasetId` dedup spans both channels. `channel` is the
    /// owning bucket's `name`, `signature` the source `ETag` recorded as last-seen on
    /// success. Published visibility is not passed in: `store` and `sidecar_key` let
    /// [`on_success`] re-read `{id}.state.json` at publish, so an unpublish issued during the
    /// download is honoured.
    ///
    /// Returns `false` (and cleans up the download) if the id is already
    /// queued/in-flight (deduped) or the queue is closed; `true` once enqueued.
    #[cfg(feature = "s3")]
    pub(crate) async fn enqueue_s3_tar_c4gh(
        &self,
        id: String,
        download: PathBuf,
        signature: String,
        channel: String,
        s3: S3Enqueue,
    ) -> bool {
        let S3Enqueue {
            store,
            sidecar_key,
            traceparent,
        } = s3;
        // Same transient-failure backoff as the inbox reconcile: a source whose last ingest
        // transient-failed records no ETag, so the poller re-presents it. Skipping it until
        // the window elapses keeps an S3 poll from hot-looping an expensive re-ingest. The
        // download is discarded and the next eligible poll retries.
        if self
            .state
            .retry_backoff
            .is_backing_off(&id, std::time::Instant::now())
        {
            debug!(dataset = %id, "S3 ingest is in a transient-failure backoff window; skipping this poll");
            let _ = std::fs::remove_file(&download);
            return false;
        }
        if !self.try_mark_inflight(&id) {
            debug!(dataset = %id, "ingest already queued/in-flight; skipping S3 enqueue");
            let _ = std::fs::remove_file(&download);
            return false;
        }
        let job = Job {
            id: id.clone(),
            source: JobSource::TarC4gh(download),
            signature,
            channel,
            kind: JobKind::S3 {
                store,
                sidecar_key,
                traceparent,
            },
        };
        let path = job.source.path().to_path_buf();
        if let Err(e) = self.tx.send(job).await {
            self.clear_inflight(&id);
            let _ = std::fs::remove_file(&path);
            warn!(dataset = %id, error = %e, "failed to enqueue S3 ingest job");
            return false;
        }
        ::metrics::gauge!(metrics::INGEST_QUEUE_DEPTH).increment(1.0);
        true
    }

    /// Whether an id is currently queued/in-flight (the cross-channel claim probe).
    #[cfg(feature = "s3")]
    #[must_use]
    pub(crate) fn is_id_inflight(&self, id: &str) -> bool {
        self.is_inflight(id)
    }

    /// Test-support hook: claim the in-flight guard for `id`, as the private
    /// `try_mark_inflight` does, so a test can reproduce the live-and-in-flight state a
    /// timed-out-but-completed ingest leaves behind. Returns whether the claim was newly
    /// made. Not part of the public API.
    #[doc(hidden)]
    #[must_use]
    pub fn test_mark_inflight(&self, id: &str) -> bool {
        self.try_mark_inflight(id)
    }

    /// Test-support probe: whether `id` is currently claimed in-flight, so a test can wait
    /// for a supervised, timed-out ingest to finish and release its marker. Not part of the
    /// public API.
    #[doc(hidden)]
    #[must_use]
    pub fn is_inflight_for_test(&self, id: &str) -> bool {
        self.is_inflight(id)
    }

    /// Test-support hook: release the in-flight guard for `id`, as the private
    /// `clear_inflight` does, so a test can move an id out of the live-and-in-flight state
    /// after asserting the in-flight-only behaviour. Not part of the public API.
    #[doc(hidden)]
    pub fn test_clear_inflight(&self, id: &str) {
        self.clear_inflight(id);
    }

    /// Test-support probe: the number of claimed ids, queued or being ingested. Bounded by
    /// the number of distinct enqueued ids, not by `ingest_concurrency`, and reaches 0 only
    /// at quiescence, so a test can poll it to `0` to drain deterministically. Not part of
    /// the public API; for the bounded-pool ceiling use [`Self::test_active_count`].
    #[doc(hidden)]
    #[must_use]
    pub fn test_inflight_count(&self) -> usize {
        lock(&self.inflight).len()
    }

    /// Test-support probe: the number of jobs a worker is actively processing right now.
    /// Bounded by `ingest_concurrency`, one increment per busy worker, so only an
    /// unbounded-spawn defect could exceed it. Not part of the public API.
    #[doc(hidden)]
    #[must_use]
    pub fn test_active_count(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    /// Reconcile a `{id}.state.json` sidecar.
    ///
    /// For a cached id: update its visibility (`visible` or `hidden`). `deleted` is a
    /// tombstone (see [`Self::reconcile_deleted`]) and is handled even for an id absent from
    /// the cache, since its job is to purge the index and suppress re-ingest. A
    /// non-`deleted` sidecar for an unknown id that is not in flight is ignored and logged.
    async fn reconcile_sidecar(&self, sidecar: &SidecarArtifact) {
        let id = &sidecar.id;
        // Skip ids still being ingested: the worker reads the sidecar on success.
        if self.is_inflight(id) {
            return;
        }
        // `deleted` is sidecar-only vocabulary, never a served state. Handle it before the
        // cache lookup, since it must still purge the index and act as a tombstone for an id
        // that is not, or no longer, in the cache.
        if sidecar.state == DELETED_SIDECAR_STATE {
            self.reconcile_deleted(id, sidecar.force).await;
            return;
        }
        if self.state.cache.get(id).is_none() {
            // Unreadable, for an id this node does not serve: `scan_once` holds it as a
            // tombstone, so re-ingest stays suppressed and the state oracle answers `410`.
            // Record it where the oracle field and `gdi_state_sidecar_rejected_total` read,
            // so a damaged erasure record is visible. The warning is deduped per id like the
            // orphan line below: the file stands until someone acts on it, and the scan runs
            // on every watcher wake.
            if let Some(reason) = &sidecar.unreadable {
                if self.orphan_sidecar_should_log(id, "unreadable") {
                    warn!(
                        dataset = %id,
                        reason = %reason,
                        "unreadable state sidecar for an id this node does not serve; holding \
                         it as a tombstone (re-ingest suppressed, the state oracle answers 410) \
                         until the file is repaired or removed"
                    );
                }
                self.state.note_state_sidecar_error(
                    id,
                    crate::health::INBOX_CHANNEL,
                    crate::metrics::StateSidecarRejectReason::Unreadable,
                );
                return;
            }
            // Log once per sidecar-per-change, not once per scan: a standing orphaned
            // sidecar would otherwise re-log on every reconcile and flood the log.
            if self.orphan_sidecar_should_log(id, &sidecar.state) {
                info!(dataset = %id, state = %sidecar.state, "ignored: state sidecar for an unknown dataset id");
            }
            return;
        }
        // The id is known now: clear any orphan-dedup entry so a later orphaning re-logs.
        self.orphan_sidecar_resolved(id);
        // Operator suppression outranks the source, and the most restrictive wins. The
        // sidecar carries the source's declared visibility, which does not change when an
        // operator suppresses the id, so applying it unconditionally would re-disclose a
        // `hide`/`take-down` on every reconcile pass and undo what
        // `AppState::enforce_suppressions` enforced. Mirrors the gate in
        // `consider_artifact`, which guards the ingest side of this channel.
        if self
            .state
            .suppressions
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .effective(id, "inbox")
            .is_some()
        {
            debug!(dataset = %id, "ignored: state sidecar for an operator-suppressed dataset");
            return;
        }
        // Channel ownership applies in the disclosing direction as well as the destructive
        // one: an inbox `{id}.state.json` must not publish a bucket-owned dataset the
        // provider set hidden. Same rule and same helper as the delete path, which refuses
        // to act on another channel's id.
        if let Some(channel) = self.foreign_owner(id) {
            info!(dataset = %id, channel = %channel, "ignored: state sidecar targets a bucket-owned id (set its visibility at its source)");
            return;
        }
        // A file that could not be parsed is the same hazard as an unrecognised value and
        // gets the same answer. It sits after the in-flight, deleted, unknown-id,
        // suppression and foreign-owner guards above, so failing safe cannot itself become a
        // way to hide someone else's dataset or resurrect a tombstoned one.
        if let Some(reason) = &sidecar.unreadable {
            warn!(
                dataset = %id,
                reason = %reason,
                "unreadable state sidecar; failing safe to hidden (a half-written retraction \
                 must not leave a dataset published)"
            );
            self.state.note_state_sidecar_error(
                id,
                crate::health::INBOX_CHANNEL,
                crate::metrics::StateSidecarRejectReason::Unreadable,
            );
            self.set_state_and_persist(id, DatasetState::Hidden);
            return;
        }
        if let Some(state) = DatasetState::from_visibility_str(&sidecar.state) {
            self.state.clear_state_sidecar_error(id);
            self.set_state_and_persist(id, state);
        } else {
            // Fail safe to `Hidden` rather than keeping the last good value: an unrecognised
            // state value is treated as hidden, never visible, so a typo can only
            // under-expose. Keeping the last good value would leave an already-visible id
            // public. Matches the S3 path, which maps an unrecognised bucket sidecar to
            // `Hidden`.
            warn!(dataset = %id, value = %sidecar.state, "unrecognized state sidecar value; failing safe to hidden");
            self.state.note_state_sidecar_error(
                id,
                crate::health::INBOX_CHANNEL,
                crate::metrics::StateSidecarRejectReason::Unrecognized,
            );
            self.set_state_and_persist(id, DatasetState::Hidden);
        }
    }

    /// The channel owning `id` when it is not the inbox, so an inbox sidecar must not act.
    ///
    /// An id owned by a bucket has its source of truth in that bucket, so an inbox sidecar
    /// may govern neither its deletion nor its visibility. `None` means the inbox may act:
    /// either it owns the id, or nothing does yet.
    fn foreign_owner(&self, id: &str) -> Option<String> {
        let owner = {
            let status = lock(&self.state.status);
            status.get(id).map(|e| e.channel.clone())
        };
        owner.filter(|channel| channel != "inbox")
    }

    /// Reconcile a `{"state":"deleted"}` tombstone sidecar (inbox-only vocabulary).
    ///
    /// Mirrors the S3 removed path: the service removes `datasets/{id}/`, evicts the cache
    /// entry, and purges the id from `datasets/.status.json`, so `GET /datasets/{id}/state`
    /// then 404s. The `deleted` sidecar stays in the inbox as a tombstone; the operator
    /// removes it to release the id, and the scan suppresses re-ingest while it remains.
    ///
    /// Guards:
    /// * a sidecar targeting a bucket-owned id (status `channel != inbox`) is ignored and
    ///   logged, since its source of truth is the bucket;
    /// * a sidecar for a currently visible dataset is refused unless `force`, so a
    ///   hand-written sidecar cannot destroy a live, publicly-served dataset.
    async fn reconcile_deleted(&self, id: &str, force: bool) {
        // Bucket-owned ids are governed by their bucket sidecar, not the inbox.
        if let Some(channel) = self.foreign_owner(id) {
            info!(dataset = %id, channel = %channel, "ignored: deleted sidecar targets a bucket-owned id (delete it at its source)");
            return;
        }

        // Refuse deleting a live, publicly-served dataset unless force is set.
        let visible = self
            .state
            .cache
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Visible);
        if visible && !force {
            info!(dataset = %id, "refused: unpublish before delete, or set force");
            return;
        }

        // Already erased: the tombstone is standing, not newly observed. The `deleted`
        // sidecar stays in the inbox as the ownership signal that keeps a re-dropped package
        // suppressed, so this path is re-entered on every scan for as long as the operator
        // leaves it there. Without this guard each pass would re-run the erase and re-emit
        // the `tombstone-delete` audit event for a dataset that is already gone, flooding
        // the audit stream. A log line, an audit event or an index write fires on a
        // transition, not on every reconcile pass that re-observes an unchanged value, as
        // `Cache::set_state_if_changed` requires for state writes.
        let known = self.state.cache.get(id).is_some() || {
            let status = lock(&self.state.status);
            status.get(id).is_some()
        };
        if !known {
            return;
        }

        self.delete_dataset(id).await;
    }

    /// Remove an inbox-owned dataset: delete `datasets/{id}/`, evict the cache entry, and
    /// purge the status index. Uses the shared crash-safe erasure
    /// ([`AppState::erase_dataset`]) that the S3 removed path and the operator `Remove`
    /// suppression also use. The caller leaves the `deleted` sidecar in place as a tombstone.
    async fn delete_dataset(&self, id: &str) {
        info!(dataset = %id, "deleted: removing local dataset (evicting cache, purging status)");
        // Drop any transient-failure backoff for this id: the source is gone, so its entry
        // must not linger in the map or in the `gdi_ingest_transient_backoff` gauge.
        self.state.retry_backoff.clear(id);
        // Mutation audit trail: an explicit operator deletion via a `.deleted` tombstone,
        // the erasure path. Read the channel before the erase purges the status entry.
        let channel = {
            let status = lock(&self.state.status);
            status
                .get(id)
                .map_or_else(|| "inbox".to_owned(), |e| e.channel.clone())
        };
        crate::audit::dataset_state_change(
            &self.state.config.audit,
            id,
            &channel,
            "Deleted",
            "tombstone-delete",
        );
        // The evict, purge and dir-remove, with its crash-safety ordering, lives once on
        // `AppState` so this path, the S3 removed path and operator `Remove` cannot drift.
        self.state.erase_dataset(id, &channel).await;
    }

    /// Set a cached dataset's state and persist the status index.
    ///
    /// On an actual transition this also logs and emits a `dataset_state_change` audit line,
    /// giving the inbox sidecar path parity with the S3 sidecar path (`apply_state_change`);
    /// an inbox publish would otherwise leave no log and no audit record.
    ///
    /// The transition test is [`MetadataCache::set_state_if_changed`], not `set_state`: the
    /// latter returns `true` for any present id, so gating on it would re-emit the audit line
    /// on every reconcile pass for an unchanged sidecar.
    ///
    /// [`MetadataCache::set_state_if_changed`]: gdi_node_standalone_core::cache::MetadataCache::set_state_if_changed
    fn set_state_and_persist(&self, id: &str, new_state: DatasetState) {
        // Hold the status lock across both the cache write and the status write so a
        // concurrent reload cannot interleave and clobber the cache back to the stale
        // snapshot state, which for a visible-to-hidden flip would briefly re-expose a
        // just-hidden dataset on the public plane. The reload's disk walk is lock-free, but
        // the half that writes the cache (`cache::apply_scan`) runs under this lock and
        // recomputes state from the status index as it stands then, so it sees this flip.
        let mut status = lock(&self.state.status);
        if !self
            .state
            .cache
            .set_state_if_changed(StatusWrite::held(&status), id, new_state)
        {
            return; // absent, or already in this state: not a transition
        }
        if let Some(e) = status.get(id).cloned() {
            status.insert(
                id.to_owned(),
                StatusEntry {
                    state: new_state,
                    ..e
                },
            );
        }
        persist(status, &self.state); // consumes + drops the status guard
        info!(
            event.action = "dataset.state.change",
            dataset = %id,
            state = %new_state,
            "state changed from inbox sidecar"
        );
        crate::audit::sidecar_state_change(&self.state.config.audit, id, "inbox", new_state);
    }

    /// Reconcile a `{id}.metadata.json` operator overlay sidecar.
    ///
    /// Skips ids that are currently in-flight, which are picked up on the next scan, and any
    /// id carrying a node-local operator override ([`AppState::local_overlay_present`]):
    /// operator input outranks the source, so [`AppState::enforce_local_overlays`] governs
    /// that id's overlay and this sidecar is ignored while the override stands. An id not
    /// yet in the cache is logged and retried on the next scan. Unreadable or structurally
    /// invalid files are warned about and left in place rather than quarantined, since they
    /// are declarative sidecars, and the dataset keeps its last-good metadata.
    fn reconcile_overlay(&self, art: &OverlayArtifact) {
        let id = &art.id;
        let _span =
            tracing::info_span!("overlay_apply", channel = "inbox", dataset = %id).entered();
        if self.is_inflight(id) {
            return; // ingest in progress; pick the overlay up next scan
        }
        if self.state.local_overlay_present(id) {
            debug!(dataset = %id, "skipped: node-local metadata override takes precedence over the inbox sidecar");
            return;
        }
        if self.state.cache.get(id).is_none() {
            info!(dataset = %id, "skipped: metadata overlay for a not-yet-ingested dataset; will retry");
            return;
        }
        // Ownership, the same rule the revert path applies. Without it a `{id}.metadata.json`
        // dropped into the local inbox would rewrite the served DCAT governance fields
        // (`accessRights`, `license`, legal basis) of a bucket-owned dataset. The two would
        // then fight: the owning bucket's next poll sees no sidecar in its listing and
        // reverts, the next inbox scan re-applies, and the record and its `dct:modified` flap
        // every cycle. If that bucket has no running monitor nothing reverts at all and the
        // foreign override stands permanently.
        let owning_channel = {
            let status = lock(&self.state.status);
            status.get(id).map(|e| e.channel.clone())
        };
        if !inbox_may_revert_overlay(owning_channel.as_deref()) {
            debug!(
                dataset = %id,
                channel = owning_channel.as_deref().unwrap_or("unknown"),
                "skipped: inbox overlay for a bucket-owned dataset; its own channel governs it"
            );
            return;
        }
        let raw = match read_control_file(&art.path) {
            Ok(r) => r,
            Err(e) => {
                warn!(dataset = %id, error = %e, "ignored: unreadable or oversized metadata overlay (keeps last-good)");
                self.state
                    .note_overlay_error(id, crate::health::INBOX_CHANNEL, "fetch");
                return;
            }
        };
        let patch: gdi_node_standalone_core::model::MetadataOverlay = match serde_json::from_slice(
            &raw,
        ) {
            Ok(p) => p,
            Err(e) => {
                warn!(dataset = %id, error = %e, "ignored: invalid metadata overlay (keeps last-good)");
                self.state
                    .note_overlay_error(id, crate::health::INBOX_CHANNEL, "parse");
                return;
            }
        };
        let data_dir = &self.state.config.service.data_dir;
        match gdi_node_standalone_core::overlay_store::apply(data_dir, id, &patch) {
            Ok(applied) => {
                self.state.adopt_applied_overlay(
                    id,
                    applied,
                    crate::state::OverlaySource::InboxSidecar,
                    None,
                );
            }
            Err(e) => {
                warn!(dataset = %id, error = %e, "ignored: metadata overlay failed validation (keeps last-good)");
                self.state
                    .note_overlay_error(id, crate::health::INBOX_CHANNEL, "validate");
            }
        }
    }

    /// For each cached dataset whose durable overlay exists on disk but whose
    /// `{id}.metadata.json` is no longer present in the inbox scan, revert the
    /// overlay and restore the baseline metadata.
    ///
    /// Run this even when `present` is empty, so a removed sidecar is detected on the scan
    /// immediately after deletion.
    fn reconcile_overlay_reverts(&self, present: &HashSet<String>) {
        let data_dir = &self.state.config.service.data_dir;
        for id in self.state.cache.ids() {
            if present.contains(&id) {
                continue;
            }
            // A node-local operator override governs this id's overlay lifecycle, and
            // operator input outranks the source. Do not revert just because the source
            // sidecar is absent; only removing the override with `dataset correct <id>
            // --reset` lets this revert path resume.
            if self.state.local_overlay_present(&id) {
                continue;
            }
            // Revert only inbox-owned overlays. A bucket-owned id's overlay is governed by
            // its bucket poll; reverting it on every inbox scan would flap its served
            // metadata (see `inbox_may_revert_overlay`).
            let channel = {
                let status = lock(&self.state.status);
                status.get(&id).map(|e| e.channel.clone())
            };
            if !inbox_may_revert_overlay(channel.as_deref()) {
                continue;
            }
            if gdi_node_standalone_core::overlay_store::read_durable(data_dir, &id).is_some() {
                match gdi_node_standalone_core::overlay_store::revert(data_dir, &id) {
                    Ok((baseline, modified)) => {
                        // `modified` is the retained high-water mark, so a revert never
                        // moves the dataset's `dct:modified` backward.
                        self.state.apply_overlay_outcome(
                            &id,
                            baseline,
                            modified,
                            "metadata-overlay",
                            None,
                        );
                    }
                    Err(e) => {
                        warn!(dataset = %id, error = %e, "metadata overlay revert failed");
                    }
                }
            }
        }
    }

    /// GC `inbox/.rejected/{id}/` entries older than `rejected_retention_hours`.
    async fn gc_rejected(&self, inbox: &Path) {
        let retention = Duration::from_secs(
            self.state
                .config
                .service
                .rejected_retention_hours
                .saturating_mul(3600),
        );
        let max_count = self.state.config.service.rejected_max_count;
        let rejected = inbox.join(".rejected");
        let audit = self.state.config.audit.clone();
        let inbox_root = inbox.to_path_buf();
        let _ = tokio::task::spawn_blocking(move || {
            gc_rejected_dir(&rejected, retention, max_count, &audit);
            // The inbox root's own staging leftovers, under the same bound.
            gc_abandoned_staging(&inbox_root, retention, &audit);
        })
        .await;
    }

    /// Record a new last-seen signature for an id (without touching its state).
    fn record_signature(&self, id: &str, sig: &str) {
        let mut status = lock(&self.state.status);
        let entry = status.get(id).cloned();
        let next = match entry {
            Some(e) => StatusEntry {
                last_seen_signature: Some(sig.to_owned()),
                ..e
            },
            None => StatusEntry {
                state: DatasetState::Hidden,
                error_message: None,
                channel: "inbox".to_owned(),
                last_seen_signature: Some(sig.to_owned()),
                // A signature-only bookkeeping row: no successful ingest has recorded a
                // package header for this id yet.
                provenance: DatasetProvenance::Unknown,
            },
        };
        status.insert(id.to_owned(), next);
        persist(status, &self.state);
    }

    /// Try to mark an id in-flight, stamping when; returns `false` (and keeps the
    /// original stamp) if it already was.
    fn try_mark_inflight(&self, id: &str) -> bool {
        match lock(&self.inflight).entry(id.to_owned()) {
            std::collections::hash_map::Entry::Occupied(_) => false,
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(Instant::now());
                true
            }
        }
    }

    /// Clear an id's in-flight marker.
    fn clear_inflight(&self, id: &str) {
        lock(&self.inflight).remove(id);
    }

    /// Whether an id is currently queued/in-flight.
    fn is_inflight(&self, id: &str) -> bool {
        lock(&self.inflight).contains_key(id)
    }
}

/// Whether an inbox scan may revert the durable overlay of a dataset with the given
/// owning `channel` (from the status index).
///
/// Only inbox-owned datasets are reverted here: `channel == "inbox"`, or an absent channel
/// (`None`), which counts as inbox. A bucket-owned id (`channel != "inbox"`) is governed by
/// its bucket poll, which re-applies its overlay every cycle; reverting it on every inbox
/// scan would make its served metadata flap and would let a non-owning channel clobber
/// another channel's overlay. Mirrors the channel guard on
/// [`IngestRuntime::reconcile_deleted`].
fn inbox_may_revert_overlay(channel: Option<&str>) -> bool {
    !matches!(channel, Some(c) if c != "inbox")
}

/// The worker drain loop: pull one job at a time from the shared queue and process
/// it. Exits when the queue is closed and drained.
async fn worker_loop(
    rx: Arc<TokioMutex<mpsc::Receiver<Job>>>,
    inflight: IngestInflight,
    active: Arc<AtomicUsize>,
    blocking: Arc<AtomicUsize>,
    state: AppState,
) {
    loop {
        // Hold the receiver lock only for the recv, never across the heavy work.
        let job = {
            let mut guard = rx.lock().await;
            guard.recv().await
        };
        let Some(job) = job else {
            break; // queue closed and drained
        };
        // Picked up off the queue and into a worker: queue depth down one, inflight up one,
        // both content-free gauges. Stamp `last_progress` here too, since a pickup is pool
        // progress; the gauge then tracks last activity rather than only completion, which
        // keeps it meaningful for a single long-running job.
        ::metrics::gauge!(metrics::INGEST_QUEUE_DEPTH).decrement(1.0);
        ::metrics::gauge!(metrics::INGEST_INFLIGHT).increment(1.0);
        ::metrics::gauge!(metrics::INGEST_LAST_PROGRESS_TIMESTAMP_SECONDS)
            .set(metrics::unix_now_seconds());
        active.fetch_add(1, Ordering::Relaxed);
        // RAII cleanup: restore `active` and the inflight gauge and release the in-flight
        // dedup marker even if `process_job`'s async path panics, which would otherwise
        // leave the id marked forever and the gauge latched. The default is to release the
        // marker; a timeout disarms it.
        let mut job_guard = WorkerJobGuard {
            active: Arc::clone(&active),
            marker: InflightGuard::new(Arc::clone(&inflight), job.id.clone()),
        };
        let disposition = process_job(&state, &job, &blocking, &inflight).await;
        // A timed-out job's non-cancellable blocking task is still running detached and
        // still owns the marker; keep it so no second, concurrent ingest of the same dataset
        // is started. Every other disposition releases the marker on drop.
        if matches!(disposition, JobDisposition::RetainInflight) {
            // The supervisor spawned in `process_job` constructed its own guard for this id,
            // so hand the marker over rather than releasing it here.
            job_guard.marker.transfer();
        }
        drop(job_guard);
    }
}

/// Whether `worker_loop` should release a job's in-flight guard once `process_job`
/// returns.
#[derive(Debug)]
enum JobDisposition {
    /// The job reached a terminal outcome (success, permanent error or transient backend
    /// failure); release the guard so a later reconcile can re-enqueue.
    Release,
    /// The job timed out and its non-cancellable blocking task is still running; keep the
    /// guard so no second, concurrent ingest of the same dataset is started.
    RetainInflight,
}

/// The `traceparent` to parent an `ingest_job` span under: the value the S3 handoff sidecar
/// carried, and only when the job is an S3 job and the node trusts that source
/// (`[service].trust_sidecar_traceparent`).
///
/// The gate is not `trust_inbound_traceparent`, which governs HTTP headers on the public and
/// management listeners; an orchestrator correlating its publishes must not have to trust the
/// internet-facing Beacon's headers. Only compiled in an otel build.
#[cfg(all(feature = "s3", feature = "otel"))]
fn s3_inbound_traceparent(state: &AppState, job: &Job) -> Option<String> {
    match &job.kind {
        JobKind::S3 { traceparent, .. } if state.config.service.trust_sidecar_traceparent => {
            traceparent.clone()
        }
        _ => None,
    }
}

/// Process one ingest job: run the heavy pipeline under `spawn_blocking` with
/// panic handling, then apply the outcome (publish/consume or quarantine/error).
#[expect(
    clippy::too_many_lines,
    reason = "one ingest pipeline whose steps share a single spawn_blocking closure"
)]
async fn process_job(
    state: &AppState,
    job: &Job,
    blocking: &Arc<AtomicUsize>,
    inflight: &IngestInflight,
) -> JobDisposition {
    // Refuse a new ingest when too many ingest blocking tasks, active plus detached, already
    // occupy tokio's shared blocking pool, so accumulated timed-out hangs cannot starve the
    // public Beacon read path that shares it. The cap is
    // `ingest_concurrency + DETACHED_HEADROOM`, so only detached-hang buildup past the
    // headroom trips it. A refused job is released rather than quarantined: the source stays
    // and a later reconcile retries once the pool drains.
    let pool_cap = state
        .config
        .service
        .ingest_concurrency
        .max(1)
        .saturating_add(DETACHED_HEADROOM);
    if blocking.load(Ordering::Relaxed) >= pool_cap {
        ::metrics::counter!(metrics::INGEST_TOTAL, "outcome" => "refused_pool_pressure")
            .increment(1);
        warn!(
            dataset = %job.id,
            channel = %job.channel,
            running = blocking.load(Ordering::Relaxed),
            cap = pool_cap,
            "refusing ingest: too many concurrent/detached ingest tasks occupy the shared blocking \
             pool; leaving for the next reconcile"
        );
        // A non-publishing terminal disposition, so the S3 download is dropped like every
        // other one; otherwise a sustained pool-pressure loop orphans a full package copy per
        // refusal on the served-data volume, since `reap_incoming` only runs at boot. A no-op
        // for inbox jobs, whose source is the durable drop.
        drop_transient_download(job);
        return JobDisposition::Release;
    }

    let started = std::time::Instant::now();
    let caps = parquet_caps(state);
    let bounds = extract_bounds(state);
    // Catalog validation reads the SIGHUP-reloadable snapshot, not the immutable boot
    // config, so a catalog added by a live reload is honoured by the next ingest job.
    let catalogs = state.reloadable().catalogs.clone();
    // Capture the SIGHUP-reloadable writer policy and this channel's allow-list snapshot so
    // the store-time gate uses the same live values `note_unknown_writer_on_publish` reads: a
    // warn-to-enforce flip or an added fingerprint applies to the next ingest without a
    // restart. They are moved into the blocking closure, where the gate borrows them.
    let writer_policy = state.reloadable().writer_policy;
    let writer_allowlist: Vec<String> = state
        .reloadable()
        .writer_allowlist_for(&job.channel)
        .to_vec();
    let data_dir = state.config.service.data_dir.clone();
    let source = job.source.clone();
    // The identities are shared behind an `Arc`; the blocking closure takes a cheap clone of
    // the handle so it stays `'static` and `Send`.
    let identities = state.identities.clone();
    // The PME write context: a Vault-minting encryptor when PME is active (compiled in and
    // `[vault].transit_key` set), else plaintext. Cheaply cloneable.
    let encryptor = state.dataset_encryptor();

    // Correlate the whole pipeline. `spawn_blocking` does not carry the spawning task's
    // span, so without a span entered on the blocking thread the core pipeline's stage spans
    // are orphan roots with no dataset id, indistinguishable across concurrent ingests, and
    // every ingest log line lacks span context. Entering one `ingest_job` span inside the
    // closure nests the stages under it and gives log lines `dataset` and `channel`, plus
    // `trace_id` and `span_id` under otel.
    let job_id = job.id.clone();
    let channel = job.channel.clone();
    // The inbound `traceparent` from an S3 handoff, captured by move into the blocking
    // closure. Only meaningful in an otel build.
    #[cfg(all(feature = "s3", feature = "otel"))]
    let inbound_parent = s3_inbound_traceparent(state, job);
    // The guard lives inside the blocking closure, so the running count is decremented when
    // the task finishes, whether this worker awaited it or it was detached on timeout and
    // completed later in the background.
    blocking.fetch_add(1, Ordering::Relaxed);
    let run_guard = BlockingGuard(Arc::clone(blocking));
    // Minted here, on the async side, and entered on the blocking thread below. The same
    // span then also wraps `finish_job` after the await, so the outcome lines carry the job's
    // `trace.id` and `span.id` like the stage lines do.
    let job_span = tracing::info_span!(
        "ingest_job",
        dataset = %job_id,
        channel = %channel,
        // Recorded by `record_job_outcome` once the result is known: success, error or
        // panic, plus the OTel error status on the latter two.
        outcome = tracing::field::Empty,
        otel.status_code = tracing::field::Empty,
        // Recorded by `record_span_ids` in otel builds so every line inside carries
        // `trace.id` and `span.id`; `Empty` is omitted from the JSON line.
        trace_id = tracing::field::Empty,
        span_id = tracing::field::Empty,
    );
    // Nest under the orchestrator's inbound trace context before entering, so the otel layer
    // sees the parent when it processes this span.
    #[cfg(all(feature = "s3", feature = "otel"))]
    if let Some(tp) = &inbound_parent {
        crate::app::adopt_traceparent(&job_span, tp);
    }
    crate::app::record_span_ids(&job_span);
    let span = job_span.clone();
    let handle = tokio::task::spawn_blocking(move || {
        let _run_guard = run_guard;
        let _span = span.entered();
        // The drop directory name, or the S3 key basename, is the published dataset id by
        // contract. Assert the manifest's own `datasetId` matches it, so the per-`datasetId`
        // dedup and immutability the runtime keys on `job.id` cannot be defeated by a
        // manifest declaring a different id under a mismatched name.
        let expected_id = Some(job_id.as_str());
        // The store-time writer gate. `StagingDir` carries no key (`Plaintext`), which
        // `enforce` rejects like any unidentified drop; the `.tar.c4gh` path recovers the key
        // inside `ingest_tar_c4gh_with_bounds` and gates on it before the rename.
        let gate = gdi_node_standalone_core::ingest::WriterGate {
            policy: writer_policy,
            channel: &channel,
            allowlist: &writer_allowlist,
        };
        match source {
            JobSource::StagingDir(staging) => ingest_staging_dir_with_bounds(
                &staging,
                &data_dir,
                &caps,
                &catalogs,
                &encryptor,
                &bounds,
                expected_id,
                &gate,
                &gdi_node_standalone_core::ingest::WriterProvenance::Plaintext,
            ),
            JobSource::TarC4gh(pkg) => ingest_tar_c4gh_with_bounds(
                &pkg,
                identities.secrets(),
                &data_dir,
                &caps,
                &catalogs,
                &encryptor,
                &bounds,
                expected_id,
                &gate,
            ),
        }
    });

    // Bound the blocking ingest by `ingest_timeout_seconds` so one hung job cannot
    // permanently occupy a worker; enough hung jobs would otherwise wedge all ingest until a
    // restart. `0` disables the bound.
    let timeout_secs = state.config.service.ingest_timeout_seconds;
    let mut handle = handle;
    let result = match await_with_timeout(&job.id, &job.channel, timeout_secs, started, &mut handle)
        .await
    {
        Ok(join_result) => join_result,
        Err(disposition) => {
            // The blocking task is still running and cannot be cancelled. Hand it to a
            // supervisor that applies the same outcome handling once it finishes, so the
            // store-time writer-key gate's verdict is still acted on and the in-flight marker
            // is released when the work is genuinely over. Dropping the handle here would
            // wedge the id in the in-flight set until restart.
            let state = state.clone();
            let job = job.clone();
            let inflight = Arc::clone(inflight);
            let job_span = job_span.clone();
            tokio::spawn(async move {
                // RAII, constructed before the awaits: a panic in `finish_job`'s outcome
                // application must still release the marker, or the dataset is silently
                // skipped by every future scan until the process restarts.
                let _marker = InflightGuard::new(inflight, job.id.clone());
                let result = handle.await;
                record_job_outcome(&job_span, &result);
                finish_job(&state, &job, result)
                    .instrument(tracing::info_span!(parent: &job_span, "ingest_finish"))
                    // Re-enter the job span too, so it ends after its finish child rather
                    // than at the blocking half's last exit.
                    .instrument(job_span.clone())
                    .await;
                debug!(dataset = %job.id, "supervised timed-out ingest finished; in-flight marker released");
            });
            return disposition;
        }
    };

    // Record the ingest duration and a progress timestamp regardless of outcome; a permanent
    // error is still progress, since the pool is not wedged. Both are content-free.
    ::metrics::histogram!(metrics::INGEST_DURATION_SECONDS).record(started.elapsed().as_secs_f64());
    ::metrics::gauge!(metrics::INGEST_LAST_PROGRESS_TIMESTAMP_SECONDS)
        .set(metrics::unix_now_seconds());

    record_job_outcome(&job_span, &result);
    // `ingest_finish`: the write-back, cache and sidecar tail of the job, which accounts for
    // a large share of the job's wall time and needs its own span.
    finish_job(state, job, result)
        .instrument(tracing::info_span!(parent: &job_span, "ingest_finish"))
        // Re-enter the job span too, so it ends after its finish child rather than at the
        // blocking half's last exit; a span ends at its last exit, not at its drop.
        .instrument(job_span.clone())
        .await;
    // Every non-timeout outcome is terminal for this attempt: release the in-flight guard so
    // a later reconcile can act.
    JobDisposition::Release
}

/// Await the in-flight ingest `fut`, bounded by `timeout_secs` (`0` = unbounded).
///
/// On elapse the worker is freed but the dataset is left in-flight: `spawn_blocking` cannot
/// be cancelled, so the task is detached and runs to completion in the background. Freeing
/// the worker keeps the queue draining. The source is not quarantined, since the detached
/// task still owns it, and the in-flight guard is not released, so a later reconcile cannot
/// start a second, racing ingest. Recovery for a genuinely hung ingest is an operator
/// restart. On elapse this records the timeout metrics, warns, and returns
/// `Err(JobDisposition::RetainInflight)` for the caller to early-return; otherwise it returns
/// `Ok(join_result)` for the caller to classify.
///
/// Extracted from [`process_job`] so the timeout branch is unit-testable with an injected
/// never-completing future, which makes `timeout` elapse on the first poll.
async fn await_with_timeout(
    id: &str,
    channel: &str,
    timeout_secs: u64,
    started: std::time::Instant,
    handle: &mut tokio::task::JoinHandle<CoreResult<IngestOk>>,
) -> Result<Result<CoreResult<IngestOk>, tokio::task::JoinError>, JobDisposition> {
    if timeout_secs == 0 {
        return Ok(handle.await);
    }
    // `&mut handle`: `JoinHandle` is `Unpin`, so the timeout can poll it without consuming
    // it. Ownership has to stay here, because dropping the handle detaches a task that
    // `spawn_blocking` cannot cancel and abandons a result the caller still has to act on.
    match tokio::time::timeout(Duration::from_secs(timeout_secs), &mut *handle).await {
        Ok(join_result) => Ok(join_result),
        Err(_elapsed) => {
            ::metrics::histogram!(metrics::INGEST_DURATION_SECONDS)
                .record(started.elapsed().as_secs_f64());
            ::metrics::gauge!(metrics::INGEST_LAST_PROGRESS_TIMESTAMP_SECONDS)
                .set(metrics::unix_now_seconds());
            ::metrics::counter!(metrics::INGEST_TOTAL, "outcome" => "timeout").increment(1);
            warn!(
                dataset = %id,
                channel = %channel,
                timeout_seconds = timeout_secs,
                "ingest exceeded ingest_timeout_seconds; freed the worker and handed the \
                 still-running blocking task to a supervisor, which keeps the in-flight \
                 marker until the task finishes"
            );
            Err(JobDisposition::RetainInflight)
        }
    }
}

/// Emit the "writer the channel cannot vouch for" metric and audit line, shared by the
/// discovery path (`warn`, on a successful publish) and the store-time enforce-reject path.
/// `enforced` distinguishes the two in the audit.
fn emit_writer_unknown(state: &AppState, job: &Job, kind: &WriterUnknownKind, enforced: bool) {
    metrics::ingest_writer_unknown(&job.channel);
    match kind {
        WriterUnknownKind::PlaintextDrop => {
            crate::audit::plaintext_drop_not_allowed(
                &state.config.audit,
                &job.id,
                &job.channel,
                enforced,
            );
        }
        WriterUnknownKind::UntrustedKey(fingerprints) => {
            crate::audit::writer_key_not_allowed(
                &state.config.audit,
                &job.id,
                &job.channel,
                fingerprints,
                enforced,
            );
        }
    }
}

/// On a successful publish, if the channel cannot vouch for the writer, count and audit it:
/// the `warn`-mode allow-list-discovery trail.
///
/// A no-op under `off`, which audits nothing, and effectively a no-op under `enforce` too,
/// since the store-time gate rejects an unadmitted writer before the rename. Reading the same
/// reloadable policy and allow-list the gate used keeps the two decisions in step.
fn note_unknown_writer_on_publish(state: &AppState, job: &Job, provenance: &WriterProvenance) {
    use gdi_node_standalone_core::config::WriterPolicy;
    let reloadable = state.reloadable();
    if reloadable.writer_policy == WriterPolicy::Off {
        return;
    }
    let allowlist = reloadable.writer_allowlist_for(&job.channel);
    if let WriterAdmission::Unknown(kind) = writer_admission(allowlist, provenance) {
        emit_writer_unknown(state, job, &kind, false);
    }
}

/// Apply a successful ingest: determine the published visibility from the local inbox
/// sidecar or the S3 sidecar re-read at publish, insert into the cache, update and persist
/// the status index, and clean up the source artifact.
#[expect(
    clippy::too_many_lines,
    reason = "one atomic publish sequence whose steps must stay together under one lock"
)]
async fn on_success(state: &AppState, job: &Job, ok: IngestOk) {
    // A successful ingest clears any transient-failure backoff window for this id, and updates
    // the `gdi_ingest_transient_backoff` gauge so a recovered backend drops out of it.
    state.retry_backoff.clear(&job.id);
    // A landed ingest supersedes any prior "your re-drop was ignored" marker: the id is
    // fresh again, so a stale marker on the oracle would mislead.
    state.clear_superseded_redrop(&job.id);
    // The effective query-time k-anon floor is the max of the node and dataset floors, as in
    // `beacon::query`. Captured before `ok.config` is moved into the cache below.
    let effective_floor = state
        .config
        .beacon
        .min_allele_count
        .max(ok.config.min_allele_count);
    // Determine the published state: for the inbox, read its local sidecar, defaulting to
    // hidden; for S3, re-read the bucket sidecar now at publish rather than before the
    // download.
    let desired = match &job.kind {
        JobKind::Inbox => state
            .config
            .service
            .inbox
            .as_ref()
            .and_then(|inbox| read_sidecar_state(inbox, &ok.id))
            .unwrap_or(DatasetState::Hidden),
        #[cfg(feature = "s3")]
        JobKind::S3 {
            store, sidecar_key, ..
        } => {
            resolve_published_state(state, store, &job.channel, &ok.id, sidecar_key.as_ref()).await
        }
    };
    // If the source package was observed deleted from the bucket while this ingest was in
    // flight, do not honour the captured `Visible`: a reconcile that raced the deletion
    // recorded the removal, since the in-flight guard keeps `apply_removed` from evicting an
    // id that is not yet published. Publish `Hidden` so the finished dataset is never briefly
    // served.
    //
    // The retention half is closed below by `seed_removal_confirmation`, which
    // `s3::BucketMonitor` consumes through `drain_removal_seeds_for`. The in-flight guard
    // excludes this id from `absent`, so the racing poll recorded no removal streak, and
    // without the seed a retracted dataset would be withheld but retained on disk until an
    // unrelated marker bump or a restart.
    let desired = if state.take_removal_requested(&ok.id) {
        warn!(
            dataset = %ok.id,
            channel = %job.channel,
            "source package was deleted during ingest; publishing Hidden instead of Visible \
             (the next reconcile will evict it)"
        );
        // Seed the confirmation the racing poll could not record. Publishing Hidden closes
        // the served-deleted window; this closes the retention window, so a source-side
        // erasure does not leave the dataset on disk until an unrelated marker bump or a
        // restart.
        state.seed_removal_confirmation(&ok.id);
        DatasetState::Hidden
    } else {
        desired
    };

    // Project the writer provenance and write its sidecar before the re-ask below. It is
    // filesystem I/O and does not depend on the published visibility, and leaving it between
    // the re-ask and the publish would make those two non-atomic. The sidecar is the durable
    // copy next to the data, so a lost `.status.json` does not take an inbox dataset's
    // provenance with it; its source package is already consumed, so the header lives
    // nowhere else.
    let provenance: DatasetProvenance = (&ok.writer_provenance).into();
    let dataset_dir = state.config.service.data_dir.join(&ok.id);
    if let Err(e) =
        gdi_node_standalone_core::cache::write_provenance_sidecar(&dataset_dir, &provenance)
    {
        warn!(
            dataset = %ok.id,
            error = %e,
            "failed to write provenance sidecar; provenance lives only in the status index until the next write"
        );
    }

    // Operator authority, re-asked at the publish moment and held across the publish.
    // `consider_artifact` gated suppression when the artifact was accepted, but the ingest
    // that follows can run for minutes: a `dataset hide` or take-down issued in that window
    // finds this id not yet in the cache, so publishing the source's captured `Visible` here
    // would undo the operator, and for a `Remove` it would re-materialise erased data.
    // Releasing the guard before the insert below leaves a window in which the enforce path
    // erases `data_dir/{id}` while this function inserts a `Visible` cache entry over the
    // erased directory.
    //
    // Lock order: suppressions, then status, then cache, as `erase_dataset` and
    // `writeback_owned` take it, so a concurrent enforce cannot deadlock. Insert the cache
    // entry and the status entry together under the status lock so a concurrent reload cannot
    // re-seed the cache from a snapshot that predates this publish.
    let desired = {
        let set = state
            .suppressions
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let allowed = set.publishable_state(&ok.id, &job.channel, desired);
        if allowed != desired {
            warn!(
                dataset = %ok.id,
                channel = %job.channel,
                "operator suppression landed while this ingest was in flight; publishing \
                 Hidden instead of the source's declared state"
            );
        }
        let mut status = lock(&state.status);
        state.cache.insert(
            StatusWrite::held(&status),
            DatasetEntry {
                id: ok.id.clone(),
                metadata: ok.metadata,
                config: ok.config,
                state: allowed,
                metadata_modified: None,
            },
        );
        status.insert(
            ok.id.clone(),
            StatusEntry {
                state: allowed,
                error_message: None,
                channel: job.channel.clone(),
                last_seen_signature: Some(job.signature.clone()),
                // The audit line below records the same fact, but a log rotates; the status
                // index and the sidecar written above are the durable records.
                provenance,
            },
        );
        persist(status, state);
        allowed
    };

    // Clean up the source artifact; the canonical copy now lives in `data_dir`. The inbox
    // consumes its drop, S3 deletes the transient download. `tokio::fs` offloads to the
    // blocking pool so removing a potentially multi-GB staging tree does not block the
    // reactor worker that ran this.
    let consumed = match &job.source {
        JobSource::StagingDir(p) => tokio::fs::remove_dir_all(p).await,
        JobSource::TarC4gh(p) => tokio::fs::remove_file(p).await,
    };
    if let Err(e) = consumed {
        warn!(dataset = %ok.id, error = %e, "failed to clean up source artifact after publish");
    }
    info!(
        event.action = "dataset.ingest",
        dataset = %ok.id,
        channel = %job.channel,
        state = %desired,
        "ingested dataset"
    );

    // Mutation audit trail: a dataset reached a published terminal state.
    crate::audit::dataset_state_change(
        &state.config.audit,
        &ok.id,
        &job.channel,
        desired.as_str(),
        "ingested",
    );
    // Provenance: record the crypt4gh writer keys recovered from the published package's
    // header. This is not a signature; the writer key is proof-of-possession only (see
    // `WriterProvenance`), so the record is accountability, not authentication. Every
    // successful ingest emits one audit line: a recovered key, or a typed reason for its
    // absence. The metric is emitted independently of `[audit].enabled`, so disabling the
    // audit trail cannot also blind the alert.
    crate::audit::ingest_provenance(
        &state.config.audit,
        &ok.id,
        &job.channel,
        &ok.writer_provenance,
    );
    match &ok.writer_provenance {
        WriterProvenance::Recovered(_) => {}
        WriterProvenance::Plaintext => {
            crate::metrics::ingest_provenance_absent(crate::metrics::PROVENANCE_ABSENT_PLAINTEXT);
        }
        WriterProvenance::Unrecoverable(_) => {
            crate::metrics::ingest_provenance_absent(
                crate::metrics::PROVENANCE_ABSENT_RECOVERY_FAILED,
            );
        }
    }

    // An AF-only dataset (no AC/AN counts) is entirely withheld at query time under a
    // positive k-anon floor, since `beacon::query`'s `row_survives` fail-closes an AF-only
    // row. Warn the operator now rather than leave them to discover empty query results. The
    // check runs only for a positive floor and a dataset actually served, and the scan is
    // offloaded to a blocking task because parquet I/O must not run on the reactor.
    if desired == DatasetState::Visible && effective_floor > 0 {
        let dir = state.config.service.data_dir.join(&ok.id);
        let caps = state.config.service.parquet_caps();
        // The stored dataset is `PARE` under PME, so the scan needs the same key material the
        // query path reads with; without it the check cannot run on a PME node.
        let decryptor = state.dataset_decryptor();
        match tokio::task::spawn_blocking(move || {
            gdi_node_standalone_core::validate_parquet::dir_af_only(&dir, &caps, &decryptor)
        })
        .await
        {
            Ok(Ok(true)) => warn!(
                dataset = %ok.id,
                floor = effective_floor,
                "dataset is AF-only (no AC/AN counts): every variant is suppressed by the k-anonymity floor, so it will serve no query results"
            ),
            Ok(Ok(false)) => {}
            Ok(Err(e)) => warn!(dataset = %ok.id, error = %e, "AF-only ingest check failed"),
            Err(e) => warn!(dataset = %ok.id, error = %e, "AF-only ingest check task panicked"),
        }
    }
}

/// Apply a permanent error: record the sanitized closed-class error in the status index, then
/// for an inbox job move the artifact to `inbox/.rejected/{id}/`, or for an S3 job delete the
/// transient download. S3 retains the durable package, so the error stays recorded and clears
/// on a changed `ETag` with no `.rejected` move.
fn on_permanent_error(state: &AppState, job: &Job, err: &CoreError) {
    let class = err.class();
    let class_str = class.as_str();
    // Log both the closed `error_class`, the sanitized public class, and the full `error`
    // cause chain, which is the operator-facing detail the runbook has operators look up by
    // `X-Request-Id`. The full chain goes only to this structured log; the public
    // `error_message` and the metrics stay the sanitized closed class.
    warn!(dataset = %job.id, channel = %job.channel, error_class = %class_str, error = %err, "permanent ingest error");

    // Mutation audit trail: a dataset reached the `error` terminal state. The `cause`
    // is the sanitized closed error class (path-free), never the full cause chain.
    crate::audit::dataset_state_change(
        &state.config.audit,
        &job.id,
        &job.channel,
        "error",
        class_str,
    );

    // Outcome counter, labelled by the closed, sanitized `error_class` enum: the same
    // path-free, bounded set the public two-channel error model uses, never content-derived.
    // A decrypt failure also bumps the dedicated decrypt counter.
    ::metrics::counter!(
        metrics::INGEST_TOTAL,
        "outcome" => "permanent",
        "error_class" => class_str.to_owned(),
    )
    .increment(1);
    if err.class() == gdi_node_standalone_core::error::ErrorClass::DecryptFailed {
        ::metrics::counter!(metrics::DECRYPT_FAILURES_TOTAL).increment(1);
    }

    // An `error` dataset has no manifest, so it is not inserted into the in-memory cache,
    // which only holds successfully-ingested datasets. The error state lives in the status
    // index and the state endpoint reads it from there. Any prior live entry for this id is
    // left alone: a live dataset is immutable, and an error on a re-presentation never
    // overwrites it.

    {
        let mut status = lock(&state.status);
        // Preserve a previously-recorded channel, else stamp this job's channel.
        let channel = status
            .get(&job.id)
            .map_or_else(|| job.channel.clone(), |e| e.channel.clone());
        // Preserve any previously-recorded writer provenance for the same reason the channel
        // is preserved: a failed re-presentation must not erase what the last successful
        // ingest recorded about who wrote the package. This job's package never published, so
        // it contributes no provenance; `Unknown` when there is nothing to inherit.
        let provenance = status
            .get(&job.id)
            .map_or(DatasetProvenance::Unknown, |e| e.provenance.clone());
        status.insert(
            job.id.clone(),
            StatusEntry {
                state: DatasetState::Error,
                error_message: Some(class),
                channel,
                last_seen_signature: Some(job.signature.clone()),
                provenance,
            },
        );
        persist(status, state);
    }

    match &job.kind {
        JobKind::Inbox => {
            if let Some(inbox) = state.config.service.inbox.clone()
                && quarantine(&inbox, &job.id, job.source.path()).is_err()
            {
                // The source could not be moved out of the scan path, commonly a staging dir
                // owned by another uid. The non-live scan path has no signature
                // short-circuit, so it would re-enqueue this errored id on every scan. Back
                // it off so the scan path's `is_backing_off` gate skips it and re-attempts
                // trickle; a later scan still retries in case the operator fixes the
                // permissions. `record_failure` grows the window exponentially.
                state
                    .retry_backoff
                    .record_failure(&job.id, std::time::Instant::now());
            }
        }
        #[cfg(feature = "s3")]
        JobKind::S3 { .. } => drop_transient_download(job),
    }
}

/// Resolve an S3 dataset's published visibility by re-reading `{id}.state.json` at publish
/// time, rather than trusting a value captured before the download; an operator `unpublish`
/// issued in that window would otherwise be ignored until the next full poll.
///
/// A `None` sidecar key means `Hidden`, and `fetch_state_from_store` fail-safes to `Hidden` on
/// any fetch, parse or oversize failure, so a transient S3 hiccup at the publish instant
/// publishes `Hidden` and self-heals on the next reconcile rather than disclosing under
/// uncertainty. There is no captured fallback: the re-read is the only source of published
/// state, so it cannot go stale.
#[cfg(feature = "s3")]
async fn resolve_published_state(
    state: &AppState,
    store: &crate::s3::Store,
    channel: &str,
    id: &str,
    sidecar_key: Option<&object_store::path::Path>,
) -> DatasetState {
    match sidecar_key {
        Some(key) => {
            let verdict = crate::s3::fetch_state_from_store(store, channel, id, key).await;
            // Record here rather than inside the fetch, so the counter and the per-id
            // `state_sidecar_error` field are set by the one call that sets both.
            match verdict.rejected {
                Some(reason) => state.note_state_sidecar_error(id, channel, reason),
                None => state.clear_state_sidecar_error(id),
            }
            verdict.state
        }
        None => DatasetState::Hidden,
    }
}

/// Best-effort cleanup of a writer-rejected package's payload dir at `data_dir/{id}/`.
///
/// The store-time gate refuses a rejected `enforce` package before `store_atomically` renames
/// it into place, so usually no dir exists here and this is a no-op. It stays as
/// defence-in-depth: if any path ever stores a payload and only then rejects it, leaving the
/// dir would let `hydrate_from_disk` re-admit it as `Hidden`, which an unsigned
/// `{id}.state.json` `visible` sidecar could promote to served, defeating
/// `writer_policy = enforce`.
///
/// Guarded by "no live cache entry", since a prior successful ingest of the same id owns its
/// dir and its data is immutable. Uses the same crash-safe erasure protocol as an operator
/// delete (`mark_deleting`, `remove_dir_all`, `clear_deleting_marker`), so an interrupted or
/// failed removal keeps its intent marker and the next boot's `reap_deleting` completes it.
async fn remove_rejected_payload(state: &AppState, id: &str) {
    if state.cache.get(id).is_some() {
        // A successfully-ingested dataset is serving this id; its dir is not this job's.
        return;
    }
    let data_dir = &state.config.service.data_dir;
    let dir = data_dir.join(id);
    if !dir.exists() {
        // A pre-store failure, such as decrypt or validation, never created the dir.
        return;
    }
    if let Err(e) = gdi_node_standalone_core::util::mark_deleting(data_dir, id) {
        warn!(dataset = %id, error = %e, "could not record removal intent for a rejected payload; proceeding without the crash-safety net");
    }
    let removed = tokio::fs::remove_dir_all(&dir).await;
    if let Err(e) = gdi_node_standalone_core::util::clear_deleting_marker(data_dir, id, removed) {
        warn!(alert = true, event.action = "ingest.reject.cleanup", event.outcome = "failure", dataset = %id, error = %e, "could not remove a writer-rejected dataset payload; keeping the intent marker so the next boot completes the removal");
    }
}

/// The status-index row a scrub quarantine records, synthesizing one when none exists.
///
/// Written unconditionally, because this row is the quarantine's only durable record: an
/// insert conditional on an existing row would leave a cached id with no row quarantined in
/// memory only, while the warning and the audit line fired regardless.
///
/// A cached dataset with no index row is an anomaly, so the channel is unknown here.
/// `"unknown"` is the placeholder `apply_suppressions_to_cache` uses and is not a real bucket
/// name: `writeback_owned` filters on channel equality, so a synthesized row cannot publish a
/// status object for a dataset whose owner is unknown.
fn quarantined_status_row(existing: Option<StatusEntry>) -> StatusEntry {
    let error_message = Some(gdi_node_standalone_core::error::ErrorClass::ScrubFailed);
    match existing {
        Some(e) => StatusEntry {
            state: DatasetState::Error,
            error_message,
            ..e
        },
        None => StatusEntry {
            state: DatasetState::Error,
            error_message,
            channel: "unknown".to_owned(),
            last_seen_signature: None,
            provenance: gdi_node_standalone_core::cache::DatasetProvenance::Unknown,
        },
    }
}

/// Lift a scrub quarantine after a later scrub passed, restoring the dataset to `Hidden` with
/// its error cleared. Returns `true` if a quarantine was lifted.
///
/// This is the counterpart of `quarantine_scrub_failure` and the only measured way out of a
/// quarantine, so `ScrubFailed` is not node-retriable: clearing the row at boot would re-serve
/// data the node has proven corrupt, on assumption rather than measurement.
///
/// Restores to `Hidden` rather than the pre-quarantine state, which is not recorded. That is
/// the fail-safe direction, and it self-corrects on a bucket channel: the next reconcile's
/// `apply_state_change` resolves the real visibility from the channel's sidecar through the
/// suppression gate, usually within one poll. The inbox channel has no such resolver, so a
/// recovered dataset stays withheld until an operator re-presents it, rather than being
/// re-served on a guess.
pub(crate) fn clear_scrub_quarantine(state: &AppState, id: &str) -> bool {
    let mut status = lock(&state.status);
    // Only lift what this function is for. Another writer may have moved the dataset on, by
    // an erase, a re-ingest or an operator suppression, between the scrub and this lock.
    let still_quarantined = status.get(id).is_some_and(|e| {
        e.state == DatasetState::Error
            && e.error_message == Some(gdi_node_standalone_core::error::ErrorClass::ScrubFailed)
    });
    if !still_quarantined {
        return false;
    }
    if !state
        .cache
        .set_state(StatusWrite::held(&status), id, DatasetState::Hidden)
    {
        return false; // not cached: nothing to restore
    }
    if let Some(existing) = status.get(id).cloned() {
        status.insert(
            id.to_owned(),
            StatusEntry {
                state: DatasetState::Hidden,
                error_message: None,
                ..existing
            },
        );
    }
    persist(status, state); // consumes + drops the status guard
    warn!(
        dataset = %id,
        "store scrub: a previously quarantined dataset passed re-verification; quarantine \
         lifted and the dataset restored as hidden. A bucket channel resolves its real \
         visibility on the next reconcile; an inbox dataset stays hidden until re-presented"
    );
    crate::audit::dataset_state_change(
        &state.config.audit,
        id,
        "scrub",
        "Hidden",
        "scrub-quarantine-lifted",
    );
    true
}

/// Quarantine an already-served dataset that failed a runtime store scrub: mark it `Error` in
/// both the live cache and the persisted status index, under the status lock so a concurrent
/// `hydrate_from_disk` cannot clobber it back, so `visible_datasets()` stops returning it.
///
/// Unlike a delete, the data dir is left in place for operator investigation and `verify
/// --digest`. Metering a scrub failure alone would leave a corrupt or unreadable dataset
/// `visible` and returning a 500 on every query.
pub(crate) fn quarantine_scrub_failure(state: &AppState, id: &str, detail: &str) {
    let mut status = lock(&state.status);
    let cached = state
        .cache
        .set_state(StatusWrite::held(&status), id, DatasetState::Error);
    // Not cached covers two situations and only one means "nothing to quarantine". An id
    // whose directory is gone was evicted or erased, and resurrecting a status row for it
    // would republish a dataset the node removed. An id whose directory is still there but
    // which never reached the cache is the opposite case, most often because of the very
    // fault being quarantined: an unparseable stored `manifest.json`, which
    // `cache::apply_scan` skips on every reload. Returning early on that one leaves the
    // dataset unserved while `GET /datasets/{id}/state` still answers `visible`. The sweep
    // only scrubs directories it found on disk, so the directory test separates the two.
    if !cached && !state.config.service.data_dir.join(id).is_dir() {
        return;
    }
    let row = quarantined_status_row(status.get(id).cloned());
    status.insert(id.to_owned(), row);
    persist(status, state); // consumes + drops the status guard
    warn!(alert = true, event.action = "store.scrub.quarantine", event.outcome = "failure", dataset = %id, detail = %detail, "store scrub: quarantined a dataset that failed its integrity check (Error; no longer served)");
    crate::audit::dataset_state_change(
        &state.config.audit,
        id,
        "scrub",
        "Error",
        "scrub-quarantine",
    );
}

/// Record a successful inbox scan. On a keyless node without S3 the watcher and rescan are
/// the only ingestion-detection path, so a dead watcher or stalled rescan would silently stop
/// pickups.
///
/// Takes the whole [`ScanResult`] rather than being an inline `gauge!` at the call site, so
/// the one place that claims a successful scan is the place holding the evidence. Stamped
/// only when the inbox was read: an unreadable inbox yields empty vectors, and treating that
/// as a success would report health on the one failure mode that stops all ingestion and
/// re-stamp every rescan tick, so `InboxScanWedged` could never fire. Same `readable`
/// distinction `reconcile_overlay_reverts` honours.
fn stamp_inbox_scan_success(scan: &ScanResult) {
    if !scan.readable {
        return;
    }
    ::metrics::gauge!(metrics::INBOX_SCAN_LAST_SUCCESS_TIMESTAMP_SECONDS)
        .set(metrics::unix_now_seconds());
}

/// The result of enumerating the inbox once.
struct ScanResult {
    staging_dirs: Vec<StagingArtifact>,
    sidecars: Vec<SidecarArtifact>,
    c4gh: Vec<C4ghArtifact>,
    overlays: Vec<OverlayArtifact>,
    /// Whether the inbox was read. `false` means `read_dir` failed, so the empty vectors
    /// above mean "could not look", not "nothing is there". Any caller acting on absence must
    /// honour the distinction (see `reconcile_overlay_reverts`).
    readable: bool,
}

/// A recognized staging directory, meaning a dir containing `manifest.json`. The content
/// signature is hashed lazily in `consider_artifact`, after the cheap dispositions, so a
/// suppressed or already-queued drop is never hashed.
struct StagingArtifact {
    id: String,
    path: PathBuf,
}

/// A recognized `{id}.tar.c4gh` encrypted package. The content signature is hashed lazily in
/// `consider_artifact`, after the cheap dispositions, so a keyless, suppressed or
/// already-queued package is never hashed.
struct C4ghArtifact {
    id: String,
    path: PathBuf,
}

/// A recognized `{id}.state.json` sidecar.
struct SidecarArtifact {
    id: String,
    state: String,
    /// The `deleted` force flag (see [`StateSidecar::force`]); irrelevant for
    /// `visible`/`hidden`.
    force: bool,
    /// `Some(reason)` when the file could not be parsed at all: truncated, wrong types, or
    /// not JSON. Distinct from an unrecognised `state` value, which parses fine. The reason
    /// is carried through so `reconcile_sidecar` applies the same fail-safe rule to both.
    /// `state` is empty here.
    unreadable: Option<String>,
}

/// A recognized `{id}.metadata.json` operator overlay sidecar.
struct OverlayArtifact {
    id: String,
    path: PathBuf,
}

/// Whether `dir` holds at least one `allele-freq.*.parquet` data file, which distinguishes a
/// complete staging dir from a half-copied one with a manifest but no parquet yet. A
/// `read_dir` failure reports `false`, treating the dir as incomplete and retrying rather than
/// enqueuing a dir that cannot be inspected.
fn staging_has_parquet(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries
        .filter_map(Result::ok)
        .any(|e| e.file_name().to_str().is_some_and(is_data_file_name))
}

/// Release an S3 job's transient `.incoming/` download.
///
/// The durable package lives in the bucket, so the local copy is scratch: every terminal
/// disposition that will not publish it must drop it, or a retry loop orphans one full
/// package per attempt on the served-data volume. A no-op for inbox jobs, whose source
/// artifact is the durable copy and is handled by `quarantine`.
fn drop_transient_download(job: &Job) {
    #[cfg(feature = "s3")]
    if matches!(job.kind, JobKind::S3 { .. }) {
        let _ = std::fs::remove_file(job.source.path());
    }
    #[cfg(not(feature = "s3"))]
    let _ = job;
}

/// Enumerate the inbox: classify entries into typed artifacts. `consider_artifact` hashes
/// signatures lazily, after the cheap dispositions. Ignores dot-prefixed entries such as
/// `.rejected/` and `*.partial` names; any unrecognized entry is ignored and logged.
fn scan_inbox(inbox: &Path, ignored_logged: &Mutex<HashSet<String>>) -> ScanResult {
    // Entries this pass could not use. Collected so the log-dedup set below can be pruned to
    // what is still there; a name that leaves and returns is worth logging again.
    let mut ignored_this_scan: HashSet<String> = HashSet::new();
    let mut staging_dirs = Vec::new();
    let mut sidecars = Vec::new();
    let mut c4gh = Vec::new();
    let mut overlays = Vec::new();

    let entries = match std::fs::read_dir(inbox) {
        Ok(e) => e,
        Err(e) => {
            warn!(inbox = %inbox.display(), error = %e, "cannot read inbox");
            return ScanResult {
                staging_dirs,
                sidecars,
                c4gh,
                overlays,
                readable: false,
            };
        }
    };

    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // Ignore dot-prefixed entries and *.partial names.
        if name.starts_with('.') || name.ends_with(".partial") {
            continue;
        }
        let is_dir = entry.file_type().is_ok_and(|t| t.is_dir());

        if is_dir {
            if let Some(a) =
                classify_staging_dir(name, &path, &mut ignored_this_scan, ignored_logged)
            {
                staging_dirs.push(a);
            }
            continue;
        }

        // A regular file.
        if let Some(id) = name.strip_suffix(".state.json") {
            if !is_valid_dataset_id(id) {
                if note_ignored(&mut ignored_this_scan, ignored_logged, name) {
                    info!(entry = %name, "ignored: state sidecar name is not a valid dataset id");
                }
                continue;
            }
            match read_sidecar(&path) {
                Ok(s) => sidecars.push(SidecarArtifact {
                    id: id.to_owned(),
                    state: s.state,
                    force: s.force,
                    unreadable: None,
                }),
                // Carried through rather than dropped. Dropping it would keep the artifact
                // from reaching `reconcile_sidecar`, so an operator's half-written retraction
                // would leave an already-visible dataset public with only a warning. It fails
                // safe where an unrecognised value does.
                Err(reason) => sidecars.push(SidecarArtifact {
                    id: id.to_owned(),
                    state: String::new(),
                    force: false,
                    unreadable: Some(reason),
                }),
            }
            continue;
        }
        if let Some(id) = name.strip_suffix(".tar.c4gh") {
            if !is_valid_dataset_id(id) {
                if note_ignored(&mut ignored_this_scan, ignored_logged, name) {
                    info!(entry = %name, "ignored: .tar.c4gh name is not a valid dataset id");
                }
                continue;
            }
            // The signature is computed lazily in `consider_artifact`, after the cheap
            // tombstone, keyless and in-flight dispositions, so a keyless, suppressed or
            // already-queued multi-GB package is never hashed just to be discarded.
            c4gh.push(C4ghArtifact {
                id: id.to_owned(),
                path: path.clone(),
            });
            continue;
        }
        if let Some(id) = name.strip_suffix(gdi_node_standalone_core::overlay_store::OVERLAY_SUFFIX)
        {
            if !is_valid_dataset_id(id) {
                if note_ignored(&mut ignored_this_scan, ignored_logged, name) {
                    info!(entry = %name, "ignored: metadata overlay name is not a valid dataset id");
                }
                continue;
            }
            overlays.push(OverlayArtifact {
                id: id.to_owned(),
                path: path.clone(),
            });
            continue;
        }
        if note_ignored(&mut ignored_this_scan, ignored_logged, name) {
            info!(entry = %name, "ignored: unrecognized inbox entry");
        }
    }

    // Prune the log-dedup set to what this pass saw. Only on a readable scan: an unreadable
    // inbox yields an empty set, and clearing on that would re-log everything on return.
    ignored_logged
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .retain(|name| ignored_this_scan.contains(name));

    ScanResult {
        staging_dirs,
        sidecars,
        c4gh,
        overlays,
        readable: true,
    }
}

/// Classify one directory entry of the inbox: a staging drop, or a logged non-drop.
///
/// Records every ignored name in `seen_this_scan`, which drives the dedup-set prune at the
/// end of the scan, and logs it at most once per appearance via [`ignored_should_log`].
fn classify_staging_dir(
    name: &str,
    path: &Path,
    seen_this_scan: &mut HashSet<String>,
    ignored_logged: &Mutex<HashSet<String>>,
) -> Option<StagingArtifact> {
    // A staging dir is a directory containing manifest.json.
    if !path.join("manifest.json").is_file() {
        seen_this_scan.insert(name.to_owned());
        if ignored_should_log(ignored_logged, name) {
            info!(entry = %name, "ignored: directory without a manifest.json");
        }
        return None;
    }
    if !is_valid_dataset_id(name) {
        // A manifest-bearing dir whose name is not a valid dataset id is a hand-assembled
        // drop that would silently lose data: the inbox derives the id from the directory
        // name, as S3 does from the object key, not from the manifest. Warn rather than info,
        // and state the contract and the fix. `deploy build/<id>` names the dir correctly.
        seen_this_scan.insert(name.to_owned());
        if ignored_should_log(ignored_logged, name) {
            warn!(
                entry = %name,
                "ignored: an inbox staging dir must be named EXACTLY its datasetId (the \
                 inbox derives the id from the dir name, not the manifest). Rename \
                 inbox/{name} to inbox/<datasetId>, or drop it with `gdi-dataset-tool \
                 deploy` which names it for you."
            );
        }
        return None;
    }
    // Incomplete-on-first-sight backstop, since drops must be atomic: a manifest present with
    // no parquet yet is a half-copied drop. Skip it this scan, self-healing once the parquet
    // lands, rather than enqueuing an ingest that would fail the layout check as a permanent
    // error and land in `.rejected/`.
    //
    // Not dedup-gated: this state resolves on its own, so the line repeating is the signal
    // that it has not. The ignores above are standing facts that sit until an operator acts.
    if !staging_has_parquet(path) {
        info!(entry = %name, "skipped: staging dir has a manifest but no parquet yet (incomplete drop); will retry next scan");
        return None;
    }
    // The signature is computed lazily in `consider_artifact`, after the cheap tombstone and
    // in-flight dispositions, so a suppressed or already-queued drop is never hashed just to
    // be discarded.
    Some(StagingArtifact {
        id: name.to_owned(),
        path: path.to_path_buf(),
    })
}

/// Tighten a pre-existing `inbox/.rejected/` to owner-only (`0o700`) when any group or other
/// bit is set, the same predicate `main` applies to the data-dir root. Best effort: a chmod
/// needs ownership, and a quarantine the node cannot tighten is reported rather than fatal,
/// since the inbox is an operator-provisioned ingress and refusing to start over its
/// subdirectory would trade a disclosure posture for an outage. An absent directory is fine;
/// the first quarantine creates it owner-only.
#[cfg(unix)]
fn tighten_rejected_dir(inbox: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let rejected = inbox.join(".rejected");
    let needs_tightening = match std::fs::metadata(&rejected) {
        Ok(meta) if meta.is_dir() => meta.permissions().mode() & 0o077 != 0,
        _ => false,
    };
    if !needs_tightening {
        return;
    }
    match std::fs::set_permissions(&rejected, std::fs::Permissions::from_mode(0o700)) {
        Ok(()) => info!(
            path = %rejected.display(),
            "tightened a pre-existing inbox/.rejected to owner-only (it holds plaintext quarantine)"
        ),
        Err(e) => warn!(
            path = %rejected.display(),
            error = %e,
            "could not tighten inbox/.rejected to owner-only; it holds plaintext quarantine; \
             chown it to the node's uid, or chmod 0700 by hand"
        ),
    }
}

/// No-op off Unix: there is no mode to tighten.
#[cfg(not(unix))]
fn tighten_rejected_dir(_inbox: &Path) {}

/// Record `name` as ignored by this scan and say whether its line should fire. Every
/// `ignored:` site in [`scan_inbox`] goes through this pairing, so a new site cannot forget
/// either half and re-log on every scan.
fn note_ignored(
    ignored_this_scan: &mut HashSet<String>,
    ignored_logged: &Mutex<HashSet<String>>,
    name: &str,
) -> bool {
    ignored_this_scan.insert(name.to_owned());
    ignored_should_log(ignored_logged, name)
}

/// Whether an "ignored inbox entry" line should fire for `name`: only the first time the
/// entry is seen in this state. Standing junk in the inbox is a one-line fact, not a per-scan
/// event. See [`IngestRuntime::ignored_entries_logged`].
fn ignored_should_log(logged: &Mutex<HashSet<String>>, name: &str) -> bool {
    logged
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(name.to_owned())
}

/// Compute the content-hash signature for an inbox artifact, dispatching on its kind. Called
/// lazily from `consider_artifact` once the cheap dispositions have not short-circuited the
/// artifact, so a suppressed, keyless or already-queued package is never hashed.
fn signature_of_source(source: &JobSource) -> CoreResult<String> {
    match source {
        JobSource::StagingDir(p) => signature_of_staging(p),
        JobSource::TarC4gh(p) => signature_of_file(p),
    }
}

/// Compute [`signature_of_source`] on the blocking pool.
///
/// Signing a `.tar.c4gh` streams the whole encrypted package through SHA-256, and signing a
/// staging dir hashes every file. That blocking CPU and I/O must not run on the async
/// reactor, so `consider_artifact` offloads through this wrapper.
async fn signature_of_source_offloaded(source: &JobSource) -> CoreResult<String> {
    let source = source.clone();
    match tokio::task::spawn_blocking(move || signature_of_source(&source)).await {
        Ok(res) => res,
        Err(join_err) => Err(CoreError::InternalError {
            detail: format!("signature task failed to join: {join_err}"),
        }),
    }
}

/// Compute a deterministic content-hash signature of a staging dir: sha256 over the
/// `manifest.json` bytes plus, for every regular file under the dir sorted by relative name,
/// its name, size and streamed content. Cheap and stable, and detects any payload or manifest
/// change.
fn signature_of_staging(staging: &Path) -> CoreResult<String> {
    let mut hasher = Sha256::new();

    // 1. manifest.json bytes, capped. This runs at scan time, before the ingest job's
    //    `check_manifest_size` gate, and the staging dir is provider-writable, so a bare
    //    `fs::read` would let a multi-GiB `manifest.json` OOM the node on every scan. Bytes
    //    for a manifest within the cap are identical, so the signature contract is unchanged;
    //    an oversized one errors here and would be rejected downstream anyway.
    let manifest = gdi_node_standalone_core::ingest::read_manifest_bytes(staging)?;
    hasher.update(b"manifest:");
    hasher.update((manifest.len() as u64).to_le_bytes());
    hasher.update(&manifest);

    // 2. Sorted (relative name, size, content) of every regular file, recursively. Streaming
    //    the content rather than just name and size means a same-name, same-size,
    //    different-bytes re-drop produces a different signature, so the runtime re-ingests
    //    and re-validates it instead of treating it as an unchanged re-presentation. Mirrors
    //    `signature_of_file`'s content hash; the staging tree is small.
    let mut files: Vec<(String, u64)> = Vec::new();
    collect_files(staging, staging, &mut files)?;
    files.sort();
    for (name, size) in files {
        hasher.update(b"file:");
        hasher.update(name.as_bytes());
        hasher.update(b":");
        hasher.update(size.to_le_bytes());
        hasher.update(b":content:");
        let mut f = std::fs::File::open(staging.join(&name))?;
        std::io::copy(&mut f, &mut hasher)?;
    }

    Ok(finalize_signature(hasher))
}

/// Compute a deterministic content-hash signature of a single file: sha256 over
/// its bytes, streamed in chunks (constant memory regardless of package size).
/// Used for `.tar.c4gh` packages so a byte-identical re-drop is a true no-op and
/// any real change is detected.
fn signature_of_file(path: &Path) -> CoreResult<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(finalize_signature(hasher))
}

/// Finalize a SHA-256 hasher into the canonical `sha256:<64-hex>` signature string shared by
/// [`signature_of_staging`] and [`signature_of_file`].
fn finalize_signature(hasher: Sha256) -> String {
    use std::fmt::Write as _;
    let mut hex = String::with_capacity(71);
    hex.push_str("sha256:");
    for b in hasher.finalize() {
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

/// Recursively collect `(relative-path, size)` of regular files under `dir`.
fn collect_files(root: &Path, dir: &Path, out: &mut Vec<(String, u64)>) -> CoreResult<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            collect_files(root, &path, out)?;
        } else if ft.is_file() {
            let rel = path.strip_prefix(root).map_or_else(
                |_| path.to_string_lossy().into_owned(),
                |p| p.to_string_lossy().into_owned(),
            );
            let size = entry.metadata().map_or(0, |m| m.len());
            out.push((rel, size));
        }
    }
    Ok(())
}

/// Hard cap on a per-dataset control object (`{id}.state.json` visibility sidecar or
/// `{id}.metadata.json` operator overlay) read fully into memory during reconcile.
pub(crate) use gdi_node_standalone_core::s3_layout::MAX_CONTROL_OBJECT_BYTES;

/// Read a small control file (`{id}.state.json` or `{id}.metadata.json`) into memory with a
/// hard [`MAX_CONTROL_OBJECT_BYTES`] cap, so a hostile oversized file in the inbox cannot OOM
/// the process on reconcile. Reads at most `cap + 1` bytes, bounding heap regardless of the
/// on-disk size and with no stat/read TOCTOU, and errors if that limit is reached. Callers
/// treat the error as "unreadable" and fail safe.
fn read_control_file(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    let mut buf = Vec::new();
    let limit = MAX_CONTROL_OBJECT_BYTES.saturating_add(1);
    std::fs::File::open(path)?
        .take(limit)
        .read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_CONTROL_OBJECT_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "control file {} exceeds the {MAX_CONTROL_OBJECT_BYTES}-byte cap",
                path.display()
            ),
        ));
    }
    Ok(buf)
}

/// Read and parse a `{id}.state.json` sidecar file, returning a concrete reason on failure,
/// I/O or JSON parse, so the caller can log one warning keyed on the dataset id like the
/// bad-value path does, rather than a filename-keyed line a by-id log filter would miss.
fn read_sidecar(path: &Path) -> Result<StateSidecar, String> {
    let raw = read_control_file(path).map_err(|e| format!("unreadable: {e}"))?;
    serde_json::from_slice::<StateSidecar>(&raw).map_err(|e| format!("invalid JSON: {e}"))
}

/// Read the desired [`DatasetState`] from `inbox/{id}.state.json`, if present and it names a
/// served visibility (`visible` or `hidden`).
fn read_sidecar_state(inbox: &Path, id: &str) -> Option<DatasetState> {
    let sidecar = read_sidecar(&inbox.join(format!("{id}.state.json"))).ok()?;
    DatasetState::from_visibility_str(&sidecar.state)
}

/// Move a permanent-error inbox `artifact` (a staging dir or a `.tar.c4gh`) to
/// `inbox/.rejected/{id}/`, replacing any prior one, and report failure so the caller can
/// back off.
///
/// A bare `rename(2)` fails for a `.rejected/` on a different filesystem (`EXDEV`), where a
/// copy-then-unlink fallback works, and for a staging dir deposited by another uid (`EPERM`,
/// since renaming a directory needs write access on it to update `..`). The `EPERM` case
/// cannot be moved at all and the fallback's source-removal fails too, so the error is
/// reported and `on_permanent_error` backs the id off instead of re-attempting on every scan.
/// The uid contract for host-side inbox drops is documented in `docs/operating.md`.
///
/// # Errors
///
/// Propagates the `create_dir_all` / `rename` / copy / source-removal [`std::io::Error`].
fn quarantine(inbox: &Path, id: &str, artifact: &Path) -> std::io::Result<()> {
    let rejected = inbox.join(".rejected");
    // Owner-only, not the umask default. The node creates this directory and it holds
    // rejected artifacts (plaintext staging dirs, VCF headers, allele-frequency parquet) for
    // `rejected_retention_hours`, 7 days by default. The served store next door is 0o700 and
    // 0o600, so a world-readable quarantine beside it would leak what the store protects. The
    // inbox itself keeps its operator-provisioned permissions, since it is an ingress others
    // drop into; this subdirectory belongs to the node.
    gdi_node_standalone_core::util::create_private_dir(&rejected)?;
    let dest = rejected.join(id);
    let _ = std::fs::remove_dir_all(&dest);
    let _ = std::fs::remove_file(&dest);
    match std::fs::rename(artifact, &dest) {
        Ok(()) => Ok(()),
        Err(rename_err) => {
            // Fall back to copy-then-unlink (handles a cross-device `.rejected`). For a
            // foreign-uid staging dir the copy succeeds but the source-removal fails, so
            // undo the copy to avoid a duplicate under `.rejected/` and surface the error.
            copy_path_recursive(artifact, &dest).map_err(|copy_err| {
                warn!(dataset = %id, rename_error = %rename_err, copy_error = %copy_err, "cannot move artifact to inbox/.rejected (rename and copy both failed)");
                copy_err
            })?;
            let is_dir = artifact.is_dir();
            match remove_rejected_entry(artifact, is_dir) {
                Ok(()) => Ok(()),
                Err(rm_err) => {
                    let _ = std::fs::remove_dir_all(&dest);
                    let _ = std::fs::remove_file(&dest);
                    warn!(dataset = %id, error = %rm_err, "cannot move artifact to inbox/.rejected: copied, but the source could not be removed, commonly a staging dir owned by another uid");
                    Err(rm_err)
                }
            }
        }
    }
}

/// The orphaned-sidecar log-dedup decision: record `state` for `id` and return whether to
/// log, which is `true` only when `id` is new to `logged` or its `state` changed. Pure, so
/// the "once per sidecar-per-change" rule is testable without an [`IngestRuntime`].
fn orphan_should_log(logged: &mut HashMap<String, String>, id: &str, state: &str) -> bool {
    if logged.get(id).map(String::as_str) == Some(state) {
        return false;
    }
    logged.insert(id.to_owned(), state.to_owned());
    true
}

/// Deepest directory nesting [`copy_path_recursive`] will descend before refusing.
///
/// A quarantined artifact is a rejected inbox package: a manifest, a metadata sidecar and a
/// flat set of parquet files. Nothing legitimate is more than a couple of levels deep, so
/// this is far above any real package and far below a stack-exhausting walk.
const MAX_QUARANTINE_COPY_DEPTH: usize = 32;

/// Recursively copy `src` (a file or a directory tree) to `dst`. Used by [`quarantine`] as
/// a cross-device fallback for `rename(2)`.
///
/// The tree it walks is provider-controlled: the artifact being quarantined is the one ingest
/// just rejected, and `check_staging_dir` rejects a symlink in a staging dir, so this fallback
/// runs on hostile input. Three properties keep it symlink-safe:
///
/// * the walk classifies with [`std::fs::symlink_metadata`], which does not follow, and
///   refuses any symlink, so a member like `escape -> /` cannot make the node copy an
///   arbitrary node-readable tree into the inbox;
/// * every destination file is created with `O_CREAT|O_EXCL` via `create_private_file_new`
///   rather than `fs::copy`, so a pre-planted destination symlink cannot be written through.
///   `fs::copy` opens the destination `O_WRONLY|O_CREAT|O_TRUNC` and follows one, which would
///   let a forged `.status.json` or suppression override be written as the node uid;
/// * the recursion is depth-bounded by [`MAX_QUARANTINE_COPY_DEPTH`].
///
/// One residual remains: the `.rejected` root itself is opened by path, so a fully hostile
/// inbox could swap a component between the check and the open. Bounding that needs
/// `openat`-based traversal. The inbox is documented single-tenant, and these three properties
/// close the paths reachable without winning that race.
///
/// # Errors
///
/// Propagates any `std::fs` error encountered creating dirs or copying files, and returns
/// [`std::io::ErrorKind::InvalidData`] for a symlink member, a non-regular member (device,
/// fifo, socket), or a tree deeper than [`MAX_QUARANTINE_COPY_DEPTH`].
fn copy_path_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    copy_path_recursive_bounded(src, dst, 0)
}

/// The depth-tracking body of [`copy_path_recursive`].
fn copy_path_recursive_bounded(src: &Path, dst: &Path, depth: usize) -> std::io::Result<()> {
    if depth > MAX_QUARANTINE_COPY_DEPTH {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("quarantine copy exceeded {MAX_QUARANTINE_COPY_DEPTH} levels of nesting"),
        ));
    }
    // `symlink_metadata`, not `Path::is_dir` or `is_file`, which follow symlinks.
    let file_type = std::fs::symlink_metadata(src)?.file_type();
    if file_type.is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "quarantine copy refuses a symlink member",
        ));
    }
    if file_type.is_dir() {
        // Owner-only, like the `.rejected` root: a quarantine holds plaintext.
        gdi_node_standalone_core::util::create_private_dir(dst)?;
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            copy_path_recursive_bounded(&entry.path(), &dst.join(entry.file_name()), depth + 1)?;
        }
        return Ok(());
    }
    if !file_type.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "quarantine copy refuses a non-regular member",
        ));
    }
    if let Some(parent) = dst.parent() {
        gdi_node_standalone_core::util::create_private_dir(parent)?;
    }
    let mut reader = std::fs::File::open(src)?;
    let mut writer = gdi_node_standalone_core::util::create_private_file_new(dst)?;
    std::io::copy(&mut reader, &mut writer).map(|_| ())
}

/// Remove one `inbox/.rejected/` entry, a dir or a file, reporting failure.
///
/// The background GC discards the result and retries on the next sweep, but `dataset
/// purge-rejected` must count what was actually unlinked rather than what was enumerated,
/// since an operator runs it to satisfy a deletion request.
///
/// # Errors
///
/// Propagates the underlying `remove_dir_all` / `remove_file` [`std::io::Error`], most often
/// `PermissionDenied` for an entry owned by another uid.
pub(crate) fn remove_rejected_entry(path: &Path, is_dir: bool) -> std::io::Result<()> {
    if is_dir {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    }
}

/// One `inbox/.rejected/{id}` entry as read from disk: a direct child of `.rejected/`, never
/// recursed into, named by the dataset id it quarantines, either a staging directory or a
/// `.tar.c4gh` file, with its filesystem mtime.
///
/// Shared between the automatic GC ([`gc_rejected_dir`]) and the on-demand `dataset
/// purge-rejected` CLI ([`crate::dataset_cmd::purge_rejected`]) so both judge what counts as
/// an entry, and how old it is, identically.
pub(crate) struct RejectedEntry {
    /// The entry's full path, always a direct child of the `.rejected/` dir passed to
    /// [`read_rejected_entries`] and never traversed from user input. The filename component
    /// is the dataset id it quarantines.
    pub(crate) path: PathBuf,
    /// Whether the entry is a staging directory (`true`) or a `.tar.c4gh` file (`false`).
    pub(crate) is_dir: bool,
    /// The entry's filesystem modification time, used as its age. Falls back to
    /// `SystemTime::now()` where `metadata().modified()` is unavailable.
    pub(crate) modified: SystemTime,
}

/// Read every direct child of `rejected`, an `inbox/.rejected/` dir, as a [`RejectedEntry`].
/// Never recurses, so it cannot walk outside `rejected` itself. An unreadable directory,
/// usually one that does not exist because nothing has been rejected yet, yields an empty list
/// rather than an error. Per-entry `read_dir` and `metadata` errors are skipped, matching the
/// rest of this GC's best-effort posture.
pub(crate) fn read_rejected_entries(rejected: &Path) -> Vec<RejectedEntry> {
    let Ok(entries) = std::fs::read_dir(rejected) else {
        return Vec::new();
    };
    let now = SystemTime::now();
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            let meta = entry.metadata().ok()?;
            let is_dir = meta.is_dir();
            let modified = meta.modified().unwrap_or(now);
            Some(RejectedEntry {
                path,
                is_dir,
                modified,
            })
        })
        .collect()
}

/// Emit the `dataset_state_change` audit line for a GC'd `inbox/.rejected/{id}` entry, whose
/// name is the dataset id. `cause` distinguishes age expiry from count-cap overflow. Never
/// any package contents: the id and a path-free cause only.
fn audit_rejected_gc(audit: &AuditConfig, path: &Path, cause: &str) {
    let id = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    crate::audit::dataset_state_change(audit, id, "inbox", "deleted", cause);
}

/// Age out abandoned inbox staging artifacts (`*.partial`, `.{id}.partial`).
///
/// `deploy`, and the documented hand-drop procedure, stages a package under a `.partial` name
/// and renames it into place, so a partially-written file is never ingested. The scanner skips
/// those names permanently, so without this sweep an interrupted copy strands the staging file
/// on the shared data volume, where no scan, GC, boot reap, `purge-rejected` or `doctor`
/// accounts for it and the operator sees only ENOSPC.
///
/// Reuses the `rejected_retention_hours` bound rather than introducing a second retention
/// policy, and runs node-side so it covers hand-drops. `retention == 0` means "retain
/// forever", matching `gc_rejected_dir`.
fn gc_abandoned_staging(inbox: &Path, retention: Duration, audit: &AuditConfig) {
    if retention.is_zero() {
        return;
    }
    let Ok(entries) = std::fs::read_dir(inbox) else {
        return;
    };
    let now = SystemTime::now();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        // Exactly the names the scanner skips as "still being written".
        if !name.ends_with(".partial") {
            continue;
        }
        let path = entry.path();
        let Ok(modified) = entry.metadata().and_then(|m| m.modified()) else {
            continue;
        };
        let age = now.duration_since(modified).unwrap_or(Duration::ZERO);
        if age <= retention {
            continue;
        }
        warn!(
            path = %path.display(),
            age_secs = age.as_secs(),
            "removing an abandoned inbox staging artifact (interrupted deploy or hand-drop)"
        );
        audit_rejected_gc(audit, &path, "staging-abandoned");
        // A `.{id}.partial` staging dir as well as a `*.partial` file.
        let _ = if entry.file_type().is_ok_and(|t| t.is_dir()) {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
    }
}

/// GC `inbox/.rejected/{id}/` entries: first by age, evicting anything older than
/// `retention`, then by count, evicting the oldest survivors down to `max_count`. A `0` cap
/// disables the count pass. Age alone is not a bound, since a producer dropping many distinct
/// bad packages within the window can fill the shared volume. Each eviction is audited.
/// Best-effort: per-entry errors are ignored.
fn gc_rejected_dir(rejected: &Path, retention: Duration, max_count: usize, audit: &AuditConfig) {
    let now = SystemTime::now();
    // Age pass; survivors carry their mtime for the count-cap pass.
    let mut survivors: Vec<(SystemTime, PathBuf, bool)> = Vec::new();
    for entry in read_rejected_entries(rejected) {
        let age = now.duration_since(entry.modified).unwrap_or(Duration::ZERO);
        // `retention == 0` means "retain forever", matching `rejected_max_count`, where `0`
        // disables the count cap. Age-based eviction is skipped and the count cap below still
        // bounds the quarantine. Otherwise a `0` would purge everything and destroy the
        // forensic record the operator meant to keep.
        if !retention.is_zero() && age > retention {
            audit_rejected_gc(audit, &entry.path, "rejected-expired");
            let _ = remove_rejected_entry(&entry.path, entry.is_dir); // GC: retried next sweep
        } else {
            survivors.push((entry.modified, entry.path, entry.is_dir));
        }
    }
    // Count cap: evict the oldest survivors beyond `max_count`.
    if max_count > 0 && survivors.len() > max_count {
        survivors.sort_by_key(|(modified, _, _)| *modified); // oldest first
        let evict = survivors.len() - max_count;
        for (_, path, is_dir) in survivors.into_iter().take(evict) {
            warn!(
                path = %path.display(),
                max_count,
                "inbox/.rejected over the count cap; evicting oldest quarantine entry"
            );
            crate::metrics::inbox_quarantine_evicted();
            audit_rejected_gc(audit, &path, "rejected-overflow");
            let _ = remove_rejected_entry(&path, is_dir); // GC: retried next sweep
        }
    }
}

/// Build the [`ParquetCaps`] from the service config. Single-sourced on
/// [`ServiceSection::parquet_caps`](gdi_node_standalone_core::config::ServiceSection::parquet_caps)
/// so the ingest and query paths cannot drift from each other or from the tool.
fn parquet_caps(state: &AppState) -> ParquetCaps {
    state.config.service.parquet_caps()
}

/// Build the operator-configured archive and staging [`ExtractBounds`] from `[service]`
/// config: the analogue of [`parquet_caps`] for the `.tar.c4gh` and staging-dir path, holding
/// the decrypted-package byte cap and the member and size extraction bounds.
fn extract_bounds(state: &AppState) -> ExtractBounds {
    let s = &state.config.service;
    ExtractBounds {
        max_members: s.max_package_members,
        max_total_bytes: s.max_package_bytes,
    }
}

/// Persist the status index atomically to `data_dir/.status.json`, logging any failure. A
/// persistence error is non-fatal: the index re-derives on the next scan.
///
/// Delegates to [`AppState::persist_status_index`], which serializes under the status lock,
/// drops the guard before the blocking write and fsync so the shared status mutex is never
/// held across the write, and skips an out-of-order write so a reordering cannot regress the
/// index.
fn persist(
    status: std::sync::MutexGuard<'_, gdi_node_standalone_core::cache::StatusIndex>,
    state: &AppState,
) {
    if let Err(e) = state.persist_status_index(status) {
        warn!(error = %e, "failed to persist status index");
    }
}

/// Lock a `std::sync::Mutex`, recovering from poisoning rather than propagating it: the
/// protected data is a plain map or set and stays safe to use after a panic.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod inbox_scan_gauge_tests {
    use metrics_exporter_prometheus::PrometheusBuilder;

    use super::*;

    fn scan(readable: bool) -> ScanResult {
        ScanResult {
            staging_dirs: Vec::new(),
            sidecars: Vec::new(),
            c4gh: Vec::new(),
            overlays: Vec::new(),
            readable,
        }
    }

    /// `gdi_inbox_scan_last_success_timestamp_seconds` is consumed by `InboxScanWedged` as
    /// `time() - gauge > 1200`, and its name claims the last successful scan.
    ///
    /// An unreadable inbox, from a lost mount or a chown that drops the node's `r-x`, makes
    /// `scan_inbox` return `readable: false` with empty vectors, which stops all ingestion on
    /// an inbox-only node. Stamping the gauge there would report success on the one failure
    /// mode the alert exists to catch, and re-stamp it every rescan tick so the alert could
    /// never fire.
    #[test]
    fn unreadable_scan_does_not_stamp_last_success() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        ::metrics::with_local_recorder(&recorder, || stamp_inbox_scan_success(&scan(false)));

        assert!(
            !handle
                .render()
                .contains(metrics::INBOX_SCAN_LAST_SUCCESS_TIMESTAMP_SECONDS),
            "a scan that could not read the inbox must not claim a successful scan:\n{}",
            handle.render()
        );
    }

    /// The complement: a scan that did read the inbox must stamp, or the alert would fire on
    /// every healthy node.
    #[test]
    fn readable_scan_stamps_last_success() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        ::metrics::with_local_recorder(&recorder, || stamp_inbox_scan_success(&scan(true)));

        assert!(
            handle
                .render()
                .contains(metrics::INBOX_SCAN_LAST_SUCCESS_TIMESTAMP_SECONDS),
            "a successful scan must stamp the gauge:\n{}",
            handle.render()
        );
    }
}

#[cfg(test)]
mod timeout_tests {
    use super::*;

    /// A handle that never resolves, standing in for a hung ingest.
    fn never_handle() -> tokio::task::JoinHandle<CoreResult<IngestOk>> {
        tokio::spawn(std::future::pending::<CoreResult<IngestOk>>())
    }

    /// A handle that resolves immediately to a permanent ingest error, standing in for a job
    /// that finished within the timeout.
    fn ready_err_handle() -> tokio::task::JoinHandle<CoreResult<IngestOk>> {
        tokio::spawn(std::future::ready(Err(CoreError::InternalError {
            detail: "done".to_owned(),
        })))
    }

    #[tokio::test]
    async fn elapsed_timeout_frees_worker_but_retains_inflight() {
        // 1s bound, but the wrapped future never completes, so the timeout fires at once. A
        // timed-out ingest must free the worker yet retain the in-flight guard, so a later
        // reconcile cannot start a second, racing ingest.
        let outcome = await_with_timeout(
            "GDI-EE-UTARTU-20260409143052837",
            "inbox",
            1,
            std::time::Instant::now(),
            &mut never_handle(),
        )
        .await;
        std::assert_matches!(
            outcome,
            Err(JobDisposition::RetainInflight),
            "a timed-out ingest must return RetainInflight"
        );
    }

    #[tokio::test]
    async fn completion_within_timeout_passes_the_join_result_through() {
        // A job that finishes before the 1s bound passes its join result through as `Ok`
        // for the caller to classify, not as `RetainInflight`.
        let outcome = await_with_timeout(
            "id",
            "inbox",
            1,
            std::time::Instant::now(),
            &mut ready_err_handle(),
        )
        .await;
        std::assert_matches!(
            outcome,
            Ok(Ok(Err(_))),
            "a job finishing within the timeout passes its join result through"
        );
    }

    #[tokio::test]
    async fn zero_timeout_is_unbounded() {
        // `0` disables the bound entirely: the result passes through unconditionally.
        let outcome = await_with_timeout(
            "id",
            "inbox",
            0,
            std::time::Instant::now(),
            &mut ready_err_handle(),
        )
        .await;
        std::assert_matches!(outcome, Ok(Ok(Err(_))));
    }
}

#[cfg(test)]
mod signature_tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;

    #[test]
    fn inbox_reverts_only_its_own_overlays() {
        // An inbox scan reverts only inbox-owned overlays. A bucket-owned id
        // (channel != "inbox") is governed by its bucket poll; reverting it on every inbox
        // scan would flap its served metadata and would let a non-owning channel clobber
        // another channel's overlay. An absent channel counts as inbox.
        assert!(inbox_may_revert_overlay(Some("inbox")));
        assert!(inbox_may_revert_overlay(None));
        assert!(!inbox_may_revert_overlay(Some("s3:provider-bucket")));
        assert!(!inbox_may_revert_overlay(Some("s3")));
    }

    /// A size-preserving content edit, with the same file names and sizes but different
    /// bytes, must change the staging-dir re-drop signature, so a rebuilt-but-same-size
    /// parquet is re-ingested rather than skipped as an unchanged re-presentation.
    #[test]
    fn staging_signature_detects_size_preserving_content_edit() {
        let tmp = tempfile::tempdir().unwrap();
        let build = |name: &str, parquet: &[u8]| {
            let dir = tmp.path().join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("manifest.json"), b"{}").unwrap();
            // Same file name and same length in both dirs, different bytes.
            std::fs::write(dir.join("allele-freq.chr3.0.br0.deadbeef.parquet"), parquet).unwrap();
            signature_of_staging(&dir).unwrap()
        };
        let sig_a = build("a", b"AAAA");
        let sig_b = build("b", b"BBBB");
        assert_ne!(
            sig_a, sig_b,
            "a same-name, same-size, different-bytes re-drop must change the signature"
        );
    }

    /// The AF-completeness scan is keyed to the `allele-freq.*.parquet` name prefix, not any
    /// `*.parquet`. A future individual-level tier shipping `genotypes.*` or `individuals.*`
    /// parquet in the same dataset dir must not be mistaken for aggregated allele-frequency
    /// data by this gate.
    #[test]
    fn staging_has_parquet_matches_only_the_allele_freq_prefix() {
        let tmp = tempfile::tempdir().unwrap();

        // A non-`allele-freq.` parquet, such as a future record-level file, is not counted.
        let other = tmp.path().join("other");
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(other.join("genotypes.chr1.parquet"), b"x").unwrap();
        assert!(
            !staging_has_parquet(&other),
            "a non-allele-freq parquet must not be seen as allele-frequency data"
        );

        // An `allele-freq.*.parquet` file is counted.
        let agg = tmp.path().join("agg");
        std::fs::create_dir_all(&agg).unwrap();
        std::fs::write(agg.join("allele-freq.chr1.0.br0.deadbeef.parquet"), b"x").unwrap();
        assert!(
            staging_has_parquet(&agg),
            "an allele-freq.*.parquet file must be detected"
        );
    }

    /// Abandoned staging artifacts must age out, and only when genuinely abandoned.
    ///
    /// The scanner skips `*.partial` permanently, which is correct for atomicity, so without
    /// this sweep an interrupted multi-GB deploy strands a file on the shared data volume
    /// that no scan, GC, boot reap, `purge-rejected` or `doctor` accounts for.
    #[test]
    fn gc_abandoned_staging_removes_only_stale_partials() {
        let tmp = tempfile::tempdir().unwrap();
        let inbox = tmp.path();
        let audit = AuditConfig::default();

        let mk = |name: &str, dir: bool| {
            let p = inbox.join(name);
            if dir {
                std::fs::create_dir_all(p.join("inner")).unwrap();
            } else {
                std::fs::write(&p, b"x").unwrap();
            }
            p
        };
        let stale_file = mk("GDI-EE-UTARTU-20260409143052837.tar.c4gh.partial", false);
        let stale_dir = mk(".GDI-EE-UTARTU-20260409143052838.partial", true);
        // Neither of these is a staging artifact and neither may be touched.
        let live = mk("GDI-EE-UTARTU-20260409143052839.tar.c4gh", false);
        let rejected = mk(".rejected", true);

        // A 1 ns retention makes every existing entry "abandoned" without mtime surgery.
        gc_abandoned_staging(inbox, Duration::from_nanos(1), &audit);
        assert!(
            !stale_file.exists(),
            "a stale *.partial file must be removed"
        );
        assert!(
            !stale_dir.exists(),
            "a stale dot-prefixed .partial staging dir must be removed too (deploy_dir)"
        );
        assert!(live.is_file(), "a real package must never be touched");
        assert!(
            rejected.is_dir(),
            "the quarantine dir is not a staging artifact"
        );

        // A partial younger than the bound is an upload in progress; removing it would
        // corrupt a live deploy, which is why the scanner skips these names.
        let fresh = mk("GDI-EE-UTARTU-20260409143052840.tar.c4gh.partial", false);
        gc_abandoned_staging(inbox, Duration::from_hours(1), &audit);
        assert!(
            fresh.is_file(),
            "an in-progress upload must survive the sweep"
        );

        // `retention == 0` means retain forever, matching `gc_rejected_dir`.
        gc_abandoned_staging(inbox, Duration::ZERO, &audit);
        assert!(fresh.is_file(), "retention 0 must retain forever");
    }

    #[test]
    fn gc_rejected_dir_zero_retention_retains_forever() {
        // `retention == 0` means retain forever, matching `rejected_max_count`, where `0`
        // disables the cap. It must not purge the quarantine; only the count cap bounds it.
        let tmp = tempfile::tempdir().unwrap();
        let rejected = tmp.path().join(".rejected");
        std::fs::create_dir_all(&rejected).unwrap();
        let ancient = rejected.join("ancient");
        let f = std::fs::File::create(&ancient).unwrap();
        // An epoch-old mtime that any positive retention would evict.
        f.set_modified(std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1))
            .unwrap();

        // retention = 0 (retain forever), count cap = 0 (disabled): nothing is evicted.
        gc_rejected_dir(&rejected, Duration::ZERO, 0, &AuditConfig::default());
        assert!(
            ancient.exists(),
            "a 0 (retain-forever) retention must not purge the quarantine"
        );
    }

    #[test]
    fn gc_rejected_dir_count_cap_evicts_oldest() {
        // Capture the `audit`-target tracing emitted synchronously while `f` runs.
        fn capture_audit(f: impl FnOnce()) -> String {
            test_util::capture_json_logs(f).1
        }

        // A long retention, so age never evicts, and a count cap of 2: the two newest of
        // three quarantined entries survive and the oldest is evicted. That is the cross-id
        // flood bound age-based retention alone does not provide. Uses file entries, which
        // the GC handles identically to dirs, for reliable mtimes.
        let tmp = tempfile::tempdir().unwrap();
        let rejected = tmp.path().join(".rejected");
        std::fs::create_dir_all(&rejected).unwrap();
        for (i, name) in ["old", "mid", "new"].iter().enumerate() {
            let path = rejected.join(name);
            let f = std::fs::File::create(&path).unwrap();
            // Distinct, increasing mtimes so "oldest" is unambiguous.
            let mtime = std::time::SystemTime::UNIX_EPOCH
                + Duration::from_secs(1_000_000 + u64::try_from(i).unwrap() * 60);
            f.set_modified(mtime).unwrap();
        }
        // Retention longer than any real file age, so only the count cap evicts; the
        // epoch-era mtimes above are ancient relative to wall-clock `now`.
        let retention = Duration::from_secs(9_999_999_999);
        let audit = AuditConfig::default();
        let logs = capture_audit(|| gc_rejected_dir(&rejected, retention, 2, &audit));
        assert!(!rejected.join("old").exists(), "oldest must be evicted");
        assert!(rejected.join("mid").exists(), "newer survivor kept");
        assert!(rejected.join("new").exists(), "newest survivor kept");
        // The eviction left an audit trail: a "deleted" state change for the evicted id.
        assert!(
            logs.contains("dataset_state_change") && logs.contains("rejected-overflow"),
            "GC eviction audited: {logs}"
        );
        assert!(logs.contains("\"old\""), "evicted id recorded: {logs}");

        // A cap of 0 disables the count cap, so both survivors stay under long retention.
        gc_rejected_dir(&rejected, retention, 0, &audit);
        assert!(rejected.join("mid").exists());
        assert!(rejected.join("new").exists());
    }
}

#[cfg(test)]
mod quarantine_tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;

    #[test]
    fn a_scrub_quarantine_is_recorded_even_when_no_status_row_exists() {
        use gdi_node_standalone_core::cache::DatasetProvenance;
        use gdi_node_standalone_core::error::ErrorClass;

        // The row is the quarantine's only durable record: for a cached id with no row, an
        // insert conditional on an existing row would leave the quarantine memory-only while
        // the warning and the `dataset_state_change` audit line fired anyway.
        let synthesized = quarantined_status_row(None);
        assert_eq!(synthesized.state, DatasetState::Error);
        assert_eq!(synthesized.error_message, Some(ErrorClass::ScrubFailed));
        assert_eq!(
            synthesized.channel, "unknown",
            "a synthesized row must not claim a real channel: `writeback_owned` filters on \
             channel equality, so claiming one would publish a status object for a dataset \
             whose owner is unknown"
        );

        // An existing row keeps everything that identifies the dataset's origin; only the
        // state and the error class move.
        let existing = StatusEntry {
            state: DatasetState::Visible,
            error_message: None,
            channel: "primary".to_owned(),
            last_seen_signature: Some("etag-1".to_owned()),
            provenance: DatasetProvenance::Plaintext,
        };
        let quarantined = quarantined_status_row(Some(existing));
        assert_eq!(quarantined.state, DatasetState::Error);
        assert_eq!(quarantined.error_message, Some(ErrorClass::ScrubFailed));
        assert_eq!(quarantined.channel, "primary");
        assert_eq!(quarantined.last_seen_signature.as_deref(), Some("etag-1"));
        assert_eq!(quarantined.provenance, DatasetProvenance::Plaintext);
    }

    #[test]
    fn quarantine_moves_a_staging_dir_and_reports_ok() {
        let tmp = tempfile::tempdir().unwrap();
        let inbox = tmp.path();
        let id = "GDI-EE-UTARTU-20260409143052837";
        let staging = inbox.join(id);
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("manifest.json"), b"{}").unwrap();

        quarantine(inbox, id, &staging).expect("a movable staging dir quarantines");

        assert!(
            !staging.exists(),
            "the source must be moved out of the scan path"
        );
        let dest = inbox.join(".rejected").join(id);
        assert!(
            dest.join("manifest.json").is_file(),
            "the artifact must land under inbox/.rejected/{{id}}/"
        );
    }

    #[test]
    fn quarantine_reports_failure_it_cannot_swallow() {
        // A hot loop that re-quarantines every scan is bounded by a backoff only if the
        // caller can see the failure. Force one deterministically: put a regular file where
        // `.rejected/` must be a directory, so the move cannot land. `quarantine` must return
        // `Err` rather than swallow it, so `on_permanent_error` can back the id off.
        let tmp = tempfile::tempdir().unwrap();
        let inbox = tmp.path();
        std::fs::write(inbox.join(".rejected"), b"not a dir").unwrap();
        let id = "GDI-EE-UTARTU-20260409143052838";
        let staging = inbox.join(id);
        std::fs::create_dir_all(&staging).unwrap();

        assert!(
            quarantine(inbox, id, &staging).is_err(),
            "a quarantine that cannot land must report failure, not swallow it"
        );
    }

    #[test]
    fn orphan_sidecar_logs_once_per_change_not_once_per_scan() {
        // A standing orphaned sidecar would otherwise re-log on every scan. Log only when
        // the id is new or its sidecar state changed.
        let mut logged = HashMap::new();
        let id = "GDI-EE-UTARTU-20260409143052837";
        assert!(
            orphan_should_log(&mut logged, id, "visible"),
            "first sight logs"
        );
        assert!(
            !orphan_should_log(&mut logged, id, "visible"),
            "an unchanged orphan on the next scan must not re-log"
        );
        assert!(
            orphan_should_log(&mut logged, id, "hidden"),
            "a changed sidecar state re-logs once"
        );
        assert!(
            !orphan_should_log(&mut logged, id, "hidden"),
            "then goes quiet again"
        );
        // A different orphan logs independently.
        assert!(orphan_should_log(
            &mut logged,
            "GDI-EE-UTARTU-20260409143052838",
            "visible"
        ));
    }

    #[test]
    fn copy_path_recursive_copies_a_dir_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("a.txt"), b"a").unwrap();
        std::fs::write(src.join("sub/b.txt"), b"b").unwrap();
        let dst = tmp.path().join("dst");

        copy_path_recursive(&src, &dst).unwrap();

        assert_eq!(std::fs::read(dst.join("a.txt")).unwrap(), b"a");
        assert_eq!(std::fs::read(dst.join("sub/b.txt")).unwrap(), b"b");
    }

    #[cfg(unix)]
    #[test]
    fn copy_path_recursive_refuses_a_symlink_instead_of_following_it() {
        // The quarantine fallback runs on a drop the ingest path rejected, often rejected by
        // `check_staging_dir` for containing a symlink, so following one here would read
        // through the exact link the node just refused into a destination the dropper can
        // read.
        //
        // The contract is to refuse, not to skip. Failing the copy is safe because this runs
        // only after `rename(2)`, and the error reaches `on_permanent_error`, which backs the
        // id off rather than re-scanning forever. Skipping would produce a silently
        // incomplete quarantine that reported success.
        let tmp = tempfile::tempdir().unwrap();
        let secret = tmp.path().join("secret.txt");
        std::fs::write(&secret, b"token").unwrap();

        let src = tmp.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("real.txt"), b"ok").unwrap();
        std::os::unix::fs::symlink(&secret, src.join("leak")).unwrap();

        let dst = tmp.path().join("dst");
        let err = copy_path_recursive(&src, &dst)
            .expect_err("a symlink member must be refused, never followed");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{err}");

        // The security property, independent of how it is signalled: the pointed-at bytes
        // must not be reproduced anywhere the dropper can read.
        assert!(
            !dst.join("leak").exists(),
            "the symlink target must not be copied into the quarantine"
        );
    }

    /// Exercise the depth bound: an unbounded recursion on a hostile tree is a
    /// stack-exhaustion primitive.
    #[test]
    fn copy_path_recursive_refuses_a_tree_deeper_than_the_bound() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        let mut deep = src.clone();
        for _ in 0..=MAX_QUARANTINE_COPY_DEPTH {
            deep = deep.join("d");
        }
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("f.txt"), b"too deep").unwrap();

        let err = copy_path_recursive(&src, &tmp.path().join("dst"))
            .expect_err("a tree past the depth bound must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{err}");
        // `InvalidData` is also what the symlink and non-regular arms return, so pin the
        // reason too; otherwise this test could pass for the wrong refusal.
        assert!(
            err.to_string().contains("nesting"),
            "expected the depth refusal, got: {err}"
        );
    }
}

#[cfg(test)]
mod control_object_tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;

    #[test]
    fn read_control_file_accepts_small_and_rejects_oversized() {
        // A control file at or under the cap reads fine; one over it is rejected as
        // `InvalidData`, which callers map to "unreadable" and fail safe on. The read is
        // bounded, so an oversized file never buffers past cap + 1 bytes.
        let dir = tempfile::tempdir().unwrap();

        let small = dir.path().join("small.state.json");
        std::fs::write(&small, br#"{"state":"visible"}"#).unwrap();
        assert_eq!(
            read_control_file(&small).unwrap(),
            br#"{"state":"visible"}"#.to_vec()
        );

        let cap = usize::try_from(MAX_CONTROL_OBJECT_BYTES).unwrap();

        // Exactly at the cap is still accepted.
        let at_cap = dir.path().join("at_cap.json");
        std::fs::write(&at_cap, vec![b'x'; cap]).unwrap();
        assert_eq!(
            u64::try_from(read_control_file(&at_cap).unwrap().len()).unwrap(),
            MAX_CONTROL_OBJECT_BYTES
        );

        // One byte over the cap is rejected without buffering the whole file.
        let over = dir.path().join("over.metadata.json");
        std::fs::write(&over, vec![b'x'; cap + 4096]).unwrap();
        let err = read_control_file(&over).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}

/// Record how the blocking half of an ingest ended onto its `ingest_job` span, before
/// `finish_job` applies it: `success`, `error` for any core error, or `panic` when the task
/// did not return, with the OpenTelemetry error status on the latter two. The metric and the
/// outcome lines carry the error class.
fn record_job_outcome(
    span: &tracing::Span,
    result: &Result<CoreResult<IngestOk>, tokio::task::JoinError>,
) {
    let outcome = match result {
        Ok(Ok(_)) => "success",
        Ok(Err(_)) => "error",
        Err(_) => "panic",
    };
    span.record("outcome", outcome);
    if outcome != "success" {
        span.record("otel.status_code", "ERROR");
    }
}

/// Apply an ingest attempt's outcome: publish, quarantine, back off, or record a permanent
/// error.
///
/// Shared by the normal path and by the supervisor that adopts a timed-out job's still
/// running task, so a slow ingest faces the same gates as a fast one, in particular the
/// store-time writer-key allow-list gate that `store_atomically` applies before it renames
/// the payload into `data_dir/{id}/`.
async fn finish_job(
    state: &AppState,
    job: &Job,
    result: Result<CoreResult<IngestOk>, tokio::task::JoinError>,
) {
    match result {
        // A valid, decrypted package still faces the writer-key allow-list before it
        // publishes: under `enforce`, a package from a producer not trusted for this channel
        // is quarantined as a permanent `writer-rejected` error, not served. The store-time
        // gate rejects an unadmitted `enforce` package before the rename, so a successful
        // ingest here was stored, either admitted or under `warn`/`off`. Under `warn` an
        // unknown writer is still published; count and audit it so an operator can see who
        // published before flipping to `enforce`.
        Ok(Ok(ok)) => {
            note_unknown_writer_on_publish(state, job, &ok.writer_provenance);
            ::metrics::counter!(metrics::INGEST_TOTAL, "outcome" => "success").increment(1);
            on_success(state, job, ok).await;
        }
        // An `enforce` package whose writer the channel cannot vouch for is rejected by the
        // store-time gate before the rename, so nothing is published and no hydrate or
        // reconcile race can re-admit it. Emit the enforce metric and audit, record the
        // permanent error, and run the payload cleanup, which is a no-op on the common path
        // and covers only a crash in the narrow window before the rename.
        Ok(Err(CoreError::WriterRejected { kind, detail })) => {
            emit_writer_unknown(state, job, &kind, true);
            on_permanent_error(state, job, &CoreError::WriterRejected { kind, detail });
            remove_rejected_payload(state, &job.id).await;
        }
        // A transient backend failure, such as Vault being unreachable while minting a PME
        // data key, is not quarantined and records no permanent `error`: the signature is
        // left unrecorded and the in-flight guard clears, so the next reconcile re-enqueues
        // the dataset once the backend returns.
        Ok(Err(core_err)) if core_err.is_transient() => {
            ::metrics::counter!(metrics::INGEST_TOTAL, "outcome" => "transient").increment(1);
            // Pace the retry: record a transient failure so the next reconcile applies capped
            // exponential backoff instead of re-ingesting on every tick. Cleared on the first
            // successful ingest. The rising `attempts` count surfaces a persistently-failing
            // backend to the operator.
            let attempts = state
                .retry_backoff
                .record_failure(&job.id, std::time::Instant::now());
            warn!(
                dataset = %job.id,
                channel = %job.channel,
                error = %core_err,
                attempts,
                "transient ingest error; backing off before the next reconcile"
            );
            // Release the transient download, as the permanent path does. This branch
            // retries, and each retry re-downloads, so keeping the copy would orphan a full
            // package per attempt on the volume the served datasets live on. The durable
            // object stays in the bucket and the next reconcile fetches it again.
            drop_transient_download(job);
        }
        Ok(Err(core_err)) => on_permanent_error(state, job, &core_err),
        // A cancelled blocking ingest says nothing about the data or the backend: only
        // runtime shutdown cancels one. Treating it as a permanent error would quarantine the
        // artifact into `.rejected/` and mark the dataset `error`, so an ordinary restart
        // mid-backfill would destroy every in-flight drop. The artifact is left in place and
        // re-queues on the next startup instead. The `transient` label would be wrong too:
        // `IngestRetryChurn` reads it as a degraded backend dependency. No retry-backoff
        // failure is recorded either, since backoff paces a source that failed and this one
        // never ran.
        Err(join_err) if !join_err.is_panic() => {
            ::metrics::counter!(metrics::INGEST_TOTAL, "outcome" => "cancelled").increment(1);
            info!(
                dataset = %job.id,
                channel = %job.channel,
                "ingest cancelled by shutdown; the source artifact is left in place and re-queues on the next startup"
            );
            // Same reasoning as the transient arm: the durable copy is the bucket object, so
            // the local `.incoming/` scratch is dropped and re-fetched by the next reconcile.
            // A no-op for inbox jobs, whose staging dir is the durable copy and must stay
            // where the next startup scan will find it.
            drop_transient_download(job);
        }
        Err(join_err) => {
            // A panic inside the blocking ingest must become a permanent error,
            // never propagate and crash the worker.
            debug_assert!(
                join_err.is_panic(),
                "the cancelled arm above must have taken every non-panic JoinError"
            );
            warn!(
                alert = true,
                event.action = "ingest.panic",
                event.outcome = "failure",
                dataset = %job.id,
                "ingest task panicked; recording permanent error"
            );
            on_permanent_error(
                state,
                job,
                &CoreError::InternalError {
                    detail: "ingest task panicked".to_owned(),
                },
            );
        }
    }

    // Removal-mark lifecycle. `on_success` above consumes the mark by publishing `Hidden`
    // instead of the captured `Visible`, so this is a no-op on that arm. Every other terminal
    // outcome would leave the mark behind, and `note_removal_requested` fires exactly when
    // the source vanished mid-ingest, which predicts the download then fails. The set would
    // grow without bound, keyed by provider-chosen ids, and a later clean re-upload of the
    // same id would publish `Hidden` and log a misleading "deleted during ingest".
    //
    // Clearing at the single point every outcome passes through makes the mark job-scoped, so
    // it cannot outlive the attempt it describes on any arm, including one added later.
    state.take_removal_requested(&job.id);
}

#[cfg(test)]
mod ignored_entry_log_dedup_tests {
    use super::*;

    /// Every `ignored:` line the scan emits goes through the dedup set, including a
    /// badly-named `.state.json` or `.tar.c4gh`. A standing junk entry of any kind is a
    /// one-line fact, and a per-scan line under the watcher's cadence is the flood the set
    /// exists to stop.
    #[test]
    fn a_misnamed_sidecar_or_package_registers_in_the_dedup_set() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let inbox = tmp.path();
        for name in ["not-an-id.state.json", "not-an-id.tar.c4gh", "noise.txt"] {
            std::fs::write(inbox.join(name), b"x").expect("inbox entry");
        }
        let logged = Mutex::new(HashSet::new());

        let scan = scan_inbox(inbox, &logged);
        assert!(scan.readable);
        assert!(scan.sidecars.is_empty() && scan.c4gh.is_empty());

        let seen = logged.lock().expect("dedup set");
        for name in ["not-an-id.state.json", "not-an-id.tar.c4gh", "noise.txt"] {
            assert!(
                seen.contains(name),
                "{name} must be registered so its line fires once, not once per scan: {seen:?}"
            );
        }
    }

    /// A standing junk entry is a one-line fact, not a per-scan event.
    ///
    /// The watcher scans far more often than `rescan_interval_seconds` implies, so a line
    /// emitted per entry per scan is unbounded, on the same stderr the audit stream rides.
    #[test]
    fn an_entry_logs_once_until_it_leaves_and_returns() {
        let logged = Mutex::new(HashSet::new());

        // First sight logs; every repeat within the same standing set is silent.
        assert!(ignored_should_log(&logged, "noise.txt"));
        assert!(!ignored_should_log(&logged, "noise.txt"));
        assert!(!ignored_should_log(&logged, "noise.txt"));

        // A different entry is a different fact and logs on its own.
        assert!(ignored_should_log(&logged, "other.txt"));

        // The scan prunes to what it saw. `other.txt` is gone from the inbox, so it leaves
        // the set, and a later reappearance is news again. That bounds the set by the inbox
        // rather than by uptime.
        let still_present: HashSet<String> = ["noise.txt".to_owned()].into_iter().collect();
        logged
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|name| still_present.contains(name));

        assert!(
            !ignored_should_log(&logged, "noise.txt"),
            "an entry that is still there must stay silent"
        );
        assert!(
            ignored_should_log(&logged, "other.txt"),
            "an entry that left and came back is worth one new line"
        );
    }
}

#[cfg(test)]
mod shutdown_cancellation_tests {
    use super::*;

    /// A minimal `AppState` whose inbox and data dir are both real directories.
    fn state_for(data_dir: &Path, inbox: &Path) -> AppState {
        let toml = format!(
            "[service]\nbase_url=\"https://x.example\"\ndata_dir=\"{}\"\ninbox=\"{}\"\n\
             [beacon]\nid=\"o.x\"\nname=\"X\"\n[catalogs]\ngdi-aggregated=\"Agg\"\n",
            data_dir.display(),
            inbox.display()
        );
        let config = gdi_node_standalone_core::config::ServiceConfig::from_toml_str(&toml)
            .expect("the fixture config must parse");
        AppState::new(
            config,
            gdi_node_standalone_core::cache::StatusIndex::new(),
            crate::identities::NodeIdentities::empty(),
        )
    }

    /// A genuinely cancelled `JoinError`, the kind runtime shutdown produces.
    ///
    /// Constructed by aborting a live task: `JoinError` has no public constructor, and a
    /// hand-rolled stand-in would not prove the arm this test guards is selected by the real
    /// `is_panic()` discriminant.
    async fn cancelled_join_error() -> tokio::task::JoinError {
        let handle = tokio::spawn(std::future::pending::<()>());
        handle.abort();
        let err = handle
            .await
            .expect_err("an aborted task must resolve to a JoinError");
        assert!(
            !err.is_panic() && err.is_cancelled(),
            "this fixture must produce a cancelled JoinError, not a panicking one"
        );
        err
    }

    /// Shutdown must not destroy an in-flight drop.
    ///
    /// A cancelled `JoinError` must not reach `on_permanent_error`: that would quarantine
    /// every in-flight staging dir into `inbox/.rejected/`, mark each dataset `error`, and
    /// let `rejected_retention_hours` delete them, all for a panic that never happened. The
    /// shutdown log line and the operating docs promise that in-flight ingest re-queues on
    /// the next startup, which holds only while this test passes.
    #[tokio::test]
    async fn a_shutdown_cancelled_ingest_leaves_the_artifact_for_the_next_startup() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().join("data");
        let inbox = tmp.path().join("inbox");
        std::fs::create_dir_all(&data_dir).expect("data dir");
        std::fs::create_dir_all(&inbox).expect("inbox");

        let id = "GDI-EE-UTARTU-20260409143052837";
        let staging = inbox.join(id);
        std::fs::create_dir_all(&staging).expect("staging dir");
        std::fs::write(
            staging.join("manifest.json"),
            test_util::stored_manifest_json(id),
        )
        .expect("manifest");

        let state = state_for(&data_dir, &inbox);
        let job = Job {
            id: id.to_owned(),
            source: JobSource::StagingDir(staging.clone()),
            signature: "sig-1".to_owned(),
            channel: "inbox".to_owned(),
            kind: JobKind::Inbox,
        };

        finish_job(&state, &job, Err(cancelled_join_error().await)).await;

        assert!(
            staging.is_dir(),
            "the staging dir must stay in the inbox so the next startup scan re-queues it"
        );
        assert!(
            !inbox.join(".rejected").join(id).exists(),
            "a cancellation is not attributable to the data and must not quarantine"
        );
        let status = lock(&state.status);
        assert!(
            status
                .get(id)
                .is_none_or(|e| e.state != DatasetState::Error),
            "a cancelled ingest must not record a permanent `error` state"
        );
    }

    /// The other arm still works: a real panic is a permanent error.
    ///
    /// Without it, "never quarantine on a `JoinError`" would re-queue a package that panics
    /// the ingest worker on every startup.
    #[tokio::test]
    async fn a_panicking_ingest_is_still_quarantined_as_a_permanent_error() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().join("data");
        let inbox = tmp.path().join("inbox");
        std::fs::create_dir_all(&data_dir).expect("data dir");
        std::fs::create_dir_all(&inbox).expect("inbox");

        let id = "GDI-EE-UTARTU-20260409143052838";
        let staging = inbox.join(id);
        std::fs::create_dir_all(&staging).expect("staging dir");
        std::fs::write(
            staging.join("manifest.json"),
            test_util::stored_manifest_json(id),
        )
        .expect("manifest");

        let panicked = tokio::spawn(async { panic!("ingest blew up") })
            .await
            .expect_err("a panicking task must resolve to a JoinError");
        assert!(panicked.is_panic(), "this fixture must produce a panic");

        let state = state_for(&data_dir, &inbox);
        let job = Job {
            id: id.to_owned(),
            source: JobSource::StagingDir(staging.clone()),
            signature: "sig-2".to_owned(),
            channel: "inbox".to_owned(),
            kind: JobKind::Inbox,
        };

        finish_job(&state, &job, Err(panicked)).await;

        assert!(
            !staging.exists(),
            "a panicking package must be moved out of the scan path, not retried forever"
        );
        assert!(
            inbox.join(".rejected").join(id).is_dir(),
            "a panic is attributable to the artifact and must quarantine"
        );
    }
}
