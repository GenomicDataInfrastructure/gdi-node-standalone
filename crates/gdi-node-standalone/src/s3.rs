//! S3 bucket monitoring (compiled only under the `s3` feature).
//!
//! Each configured `[[s3.buckets]]` is monitored independently by a
//! [`BucketMonitor`]: a cheap `_sync_marker.json` `HeadObject` poll
//! (`marker_poll_interval`) plus an unconditional full reconcile
//! (`full_poll_interval`) as the safety net for out-of-band additions and changes. The full
//! poll does not start a fresh removal on its own; see `plan_removals`. A full reconcile
//! lists the flat bucket root, builds `datasetId -> (tar.c4gh ETag, state.json state)`
//! (ignoring `_status/*` and any unknown per-id object), diffs it against the local cache
//! and status index, and applies New / Re-presented / Removed / State-changed per the spec,
//! reusing the inbox channel's same-source and immutability rules, channel provenance, and
//! cross-channel first-claim. New and eligible re-presented packages are downloaded (async,
//! streamed to `data_dir/.incoming/`) and fed through the same bounded worker pool the inbox
//! uses. With `write_status` enabled the node publishes its ingest result to
//! `_status/{id}.json` (sanitized, best-effort, never bumps the marker).
//!
//! The reconcile/ingest/writeback logic is written against
//! `Arc<dyn object_store::ObjectStore>`, so tests drive it with
//! `object_store::memory::InMemory`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use futures::stream::{self, StreamExt as _};
use gdi_node_standalone_core::cache::{
    DELETED_SIDECAR_STATE, DatasetProvenance, StatusEntry, StatusWrite,
};
use gdi_node_standalone_core::config::{KeyspaceWitness, S3Bucket, ServiceConfig};
use gdi_node_standalone_core::error::ErrorClass;
use gdi_node_standalone_core::id::is_valid_dataset_id;
use gdi_node_standalone_core::model::{ManifestMetadata, MetadataOverlay};
use gdi_node_standalone_core::overlay_store::{self as overlay, OVERLAY_SUFFIX};
use gdi_node_standalone_core::state::DatasetState;
// The S3 object-name contract is defined once in `core::s3_layout` so the tool
// (writer) and this service (reader) cannot drift; imported here to keep the
// local call sites stable.
use gdi_node_standalone_core::s3_layout::{
    MARKER_KEY, STATE_SUFFIX, STATUS_PREFIX, STATUS_SCHEMA_VERSION, StateSidecar, StatusWriteback,
    TAR_C4GH_SUFFIX,
};
use gdi_node_standalone_core::util::{now_rfc3339, rand_suffix};
use object_store::path::Path as ObjPath;
use object_store::{ObjectStore, ObjectStoreExt, PutPayload};
use tokio::io::AsyncWriteExt as _;
use tracing::{debug, info, warn};

use crate::ingest_runtime::IngestRuntime;
use crate::metrics;
use crate::state::AppState;

/// A cheaply-cloneable handle wrapping the object store, used by tests and the
/// monitor. `dyn ObjectStore` so `InMemory` and `AmazonS3` share one code path.
pub type Store = Arc<dyn ObjectStore>;

/// Whether the S3 monitoring feature is compiled into this binary. Always `true`
/// in this module (it exists only under `#[cfg(feature = "s3")]`).
#[must_use]
pub const fn compiled() -> bool {
    true
}

/// Build an `Arc<dyn ObjectStore>` for one configured bucket: the bounded client, and the
/// default choice.
///
/// Endpoint-agnostic (custom `endpoint` + `path_style` + `allow_http`), so Ceph+Rook,
/// Garage and minio are one code path differing only by config. Inline credentials are used
/// when present, as the no-Vault fallback; Vault's `s3_path` takes precedence.
/// `object_store` installs no TLS provider of its own and honours the process-default `ring`
/// provider installed at startup.
///
/// Every request is bounded by a per-request timeout and a small retry budget, because every
/// S3 request this node makes is small apart from the package body. An endpoint that accepts
/// the TCP connection and then never answers would otherwise hang the awaiting task forever,
/// the bucket poll loop included. The package body is the sole exception:
/// [`build_package_object_store`].
///
/// # Errors
///
/// Returns an error when required fields are missing (`endpoint`/`bucket`) or the
/// builder rejects the configuration.
pub fn build_object_store(bucket: &S3Bucket) -> Result<Store> {
    gdi_node_standalone_core::s3_conn::build_metadata_object_store(&conn_params(bucket)?)
        .with_context(|| format!("building S3 client for channel '{}'", bucket.name))
}

/// Build the unbounded object store for `bucket`: the package-body client, used by exactly
/// one call site, `BucketMonitor::download_package`.
///
/// Same connection contract as [`build_object_store`] (they share `conn_params`, so
/// endpoint, credentials and addressing cannot drift between the two), but with no
/// per-request timeout: a multi-GB `.tar.c4gh` download is legitimately slow and must never
/// be cut off mid-body.
///
/// Do not use it for a metadata request. It carries the longer name so that a caller
/// reaching for "the S3 client" gets the bounded [`build_object_store`] instead.
///
/// # Errors
///
/// As [`build_object_store`].
pub fn build_package_object_store(bucket: &S3Bucket) -> Result<Store> {
    gdi_node_standalone_core::s3_conn::build_object_store(&conn_params(bucket)?).with_context(
        || {
            format!(
                "building S3 package-body client for channel '{}'",
                bucket.name
            )
        },
    )
}

/// Maps a `[[s3.buckets]]` entry to core's connection params, so the metadata store and the
/// package store address the same bucket with the same credentials and addressing. They may
/// differ only in timeout and retry.
fn conn_params(bucket: &S3Bucket) -> Result<gdi_node_standalone_core::s3_conn::S3ConnParams<'_>> {
    let endpoint = bucket
        .endpoint
        .as_deref()
        .with_context(|| format!("s3 channel '{}' is missing an endpoint", bucket.name))?;
    let bucket_name = bucket
        .bucket
        .as_deref()
        .with_context(|| format!("s3 channel '{}' is missing a bucket name", bucket.name))?;

    // The endpoint/region/path-style/signing config is centralized in `core::s3_conn` so
    // the service and the tool cannot drift.
    Ok(gdi_node_standalone_core::s3_conn::S3ConnParams {
        endpoint,
        bucket: bucket_name,
        // Both stores carry it, so the package body is fetched from the same keyspace
        // the listing found it in. `preflight` has already rejected a prefix that would
        // not survive `Path` normalization intact.
        prefix: &bucket.prefix,
        region: bucket.region.as_deref(),
        path_style: bucket.path_style,
        allow_http: bucket.allow_http,
        access_key_id: bucket.access_key_id.as_deref(),
        secret_access_key: bucket.secret_access_key.as_deref(),
    })
}

/// The reconciled bucket listing: `datasetId -> (tar.c4gh ETag, sidecar key)`.
///
/// The sidecar key, not its content, is captured during listing; readiness and reconcile
/// fetch the body separately, since a `ListObjectsV2` returns only keys and `ETags`.
#[derive(Debug, Default)]
struct Listing {
    /// id -> the `.tar.c4gh` object's change-token + size (see [`PackageMeta`]).
    packages: BTreeMap<String, PackageMeta>,
    /// id -> the `.state.json` object key (present iff a sidecar exists).
    sidecars: BTreeMap<String, ObjPath>,
    /// id -> the `.metadata.json` object key (present iff an operator overlay exists).
    overlays: BTreeMap<String, ObjPath>,
}

/// The listing facts about one `{id}.tar.c4gh` object: its opaque change-token and
/// its (encrypted, on-storage) size, both captured from the `ListObjectsV2` metadata.
#[derive(Debug, Clone)]
struct PackageMeta {
    /// The object's `ETag` (or last-modified fallback): the opaque change-token used
    /// as the dataset's `last_seen_signature`.
    ///
    /// This `ETag`, not a content hash, is the documented S3 change-detection contract (see
    /// `docs/package-format.md` "Package change detection"). It is upload-method dependent: a
    /// multipart re-upload of identical bytes yields a different `ETag`, so a producer that
    /// means "no change" must re-upload the same way. A served dataset is immutable in any
    /// case, so a re-presented package is ignored rather than re-ingested.
    etag: String,
    /// The encrypted object's size in bytes (`ObjectMeta::size`), used to reject an
    /// oversize package *before* it is streamed into `.incoming/`.
    size: u64,
}

// The published-status object written under `_status/{id}.json` (sanitized) is the shared
// `s3_layout::StatusWriteback`: the service serializes it here and the tool deserializes the
// same struct, so the wire field names cannot drift.

/// A per-bucket monitor: the object store, the bucket config, shared app state,
/// the ingest runtime, and the writeback-disabled latch.
#[derive(Clone)]
pub struct BucketMonitor {
    /// The metadata store: bounded (per-request timeout plus a small retry budget). Every
    /// S3 operation this monitor performs goes through it except the package body: listings,
    /// the marker `HeadObject`, the small `.state.json` and overlay `GET`s, and the `_status`
    /// writeback `PUT`. These are the requests the poll loop awaits, so an endpoint that
    /// accepts the connection then stalls must surface as a retryable error rather than
    /// wedge the loop forever.
    ///
    /// It is the default store so that a new metadata call site reaching for `self.store`
    /// inherits the bound; the unbounded client is reachable only via the explicitly-named
    /// [`Self::package_store`].
    store: Store,
    /// The package-body store: unbounded (no request timeout), used by exactly one call
    /// site, [`Self::download_package`]. A multi-GB `.tar.c4gh` download is legitimately
    /// slow and must never be cut off mid-body. Never use it for a metadata request: that
    /// wedges the poll loop.
    package_store: Store,
    /// Latches [`Self::note_nested_dataset_key`] to one warning per channel, since the
    /// offending keys are re-listed on every poll. It covers the one prefix-desync
    /// direction the channel's own listing can see: objects below the keyspace it polls.
    /// Objects elsewhere in the bucket would need a request outside the prefix, which
    /// `[[s3.buckets]].prefix` promises the node never issues.
    nested_key_warned: Arc<AtomicBool>,
    bucket: Arc<S3Bucket>,
    state: AppState,
    runtime: IngestRuntime,
    /// Set once on the first `_status/*` `AccessDenied`; disables writeback and warns once
    /// for this bucket.
    writeback_disabled: Arc<AtomicBool>,
    /// Ids this monitor has enqueued for ingest and is still waiting on. An in-flight id is
    /// not yet in the status index (that entry is written by `on_success`), so
    /// `apply_removed` cannot tell from the index that a mid-ingest id belongs to this
    /// channel. On each reconcile, an id here whose package has vanished from the listing is
    /// recorded via [`AppState::note_removal_requested`], and ids that have finished
    /// ingesting are pruned. Shared across clones of this monitor.
    ingesting: Arc<Mutex<HashSet<String>>>,
    /// Per-id consecutive-absence streaks for the cross-poll mass-removal confirmation (see
    /// [`plan_removals`]). An owned id whose removal is suspected as part of a mass removal
    /// accrues a streak here across reconcile passes and is evicted once it reaches
    /// [`CONFIRM_REMOVAL_POLLS`]; an id that reappears drops out. In-memory only: a restart
    /// re-confirms from the persisted status index.
    pending_removals: Arc<Mutex<HashMap<String, PendingRemoval>>>,
    /// Raised by [`Self::retire`] when a `SIGHUP` reload has replaced this channel's
    /// descriptor: [`Self::run`] returns cleanly at its next wake, and the supervisor, which
    /// shares the same flag, stops rather than restarting it.
    ///
    /// Retirement is cooperative rather than an abort. `enqueue_s3_tar_c4gh` marks an id
    /// in-flight and then `.await`s a bounded `send`; a task aborted between those two
    /// leaves the id marked forever, so that dataset would never ingest again until a
    /// restart. Returning between polls has no such window.
    retire: Arc<RetireSignal>,
}

/// The retirement flag and its wakeup, shared by a monitor and its supervisor.
///
/// Both halves are needed: the `Notify` makes a retired monitor return at once instead of
/// after up to a whole `marker_poll_interval`, and the supervisor reads the `AtomicBool` to
/// tell retirement apart from the unexpected return it must restart from.
#[derive(Default)]
pub struct RetireSignal {
    retired: AtomicBool,
    wake: tokio::sync::Notify,
}

impl RetireSignal {
    /// Whether this monitor has been retired by a config reload.
    #[must_use]
    pub fn is_retired(&self) -> bool {
        self.retired.load(Ordering::SeqCst)
    }

    /// Retire the monitor: it returns at its next wake and is not restarted.
    ///
    /// `notify_one` rather than `notify_waiters` so a monitor that is mid-reconcile, and so
    /// not yet awaiting, still gets the permit and returns on its next loop turn instead of
    /// missing the notification and running until the poll interval elapses.
    pub fn retire(&self) {
        self.retired.store(true, Ordering::SeqCst);
        self.wake.notify_one();
    }
}

/// Removes its path on drop unless [`Self::keep`]-ed, so a mid-stream download failure does
/// not orphan a partial `*.download.tar.c4gh` under `.incoming/` until the next restart's
/// `reap_incoming`. The removal is a single `unlink`, cheap enough to do synchronously on
/// drop even on the reactor.
struct RemoveOnDrop(Option<PathBuf>);

impl RemoveOnDrop {
    /// Disarm the guard on the success path: take the path so `drop` is a no-op.
    fn keep(mut self) {
        self.0 = None;
    }
}

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// Single-poll mass-eviction floor for the collapse guard (see [`is_suspect_mass_removal`]).
const MASS_REMOVAL_FLOOR: usize = 3;

/// Maximum number of objects a single reconcile scans from the bucket root before failing
/// the poll closed. The bucket is provider-controlled, and in a shared-bucket deployment a
/// co-tenant can create objects, so an unbounded listing is an attacker-influenced memory
/// cost. A real node carries a few objects per dataset, so this sits far above any
/// legitimate bucket while bounding a flood to a failed poll, which reads as unhealthy,
/// rather than an OOM of the shared process.
// Single-sourced in `core::s3_layout` so the service (reader) and tool (writer) share one
// ceiling; aliased here to keep the local doc links and call sites unchanged.
const MAX_BUCKET_OBJECTS: usize = gdi_node_standalone_core::s3_layout::MAX_BUCKET_OBJECTS;

/// Whether a Removed pass evicting `absent` of `total` owned datasets in a single poll is
/// suspect, meaning a truncated or empty listing rather than a real unpublish.
///
/// Fires when at least [`MASS_REMOVAL_FLOOR`] datasets and more than half the channel's
/// owned set vanish at once. Removing one or a few datasets, including the last one in a
/// small bucket, always proceeds: over a single poll that case cannot be told from a listing
/// glitch, so the unpublish takes effect on the poll that observes it.
fn is_suspect_mass_removal(absent: usize, total: usize) -> bool {
    absent >= MASS_REMOVAL_FLOOR && absent * 2 > total
}

/// How an S3 `{id}.state.json` sidecar's `state` string is interpreted, keeping the
/// operator-visible cases distinct so the reconcile logs/meters them differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BucketSidecarState {
    /// `visible` — serve publicly.
    Visible,
    /// `hidden` — retain but exclude from listings.
    Hidden,
    /// `deleted`: the inbox delete verb, which is not a delete on S3, where deletion means
    /// removing the `{id}.tar.c4gh` object. Recorded distinctly so it is surfaced with a
    /// warning and a metric rather than swallowed as an unrecognized typo, then falls back
    /// to `hidden`.
    DeletedIgnored,
    /// Any other value, a typo or a future keyword; falls back to `hidden`.
    Unrecognized,
}

/// Classify an S3 sidecar `state` string. `visible`/`hidden` route through
/// [`DatasetState::from_visibility_str`] (single source of those two spellings);
/// `deleted` ([`DELETED_SIDECAR_STATE`]) is called out distinctly from a generic typo.
fn classify_bucket_sidecar_state(state: &str) -> BucketSidecarState {
    match DatasetState::from_visibility_str(state) {
        Some(DatasetState::Visible) => BucketSidecarState::Visible,
        // `from_visibility_str` yields only `Visible`/`Hidden`.
        Some(_) => BucketSidecarState::Hidden,
        None if state == DELETED_SIDECAR_STATE => BucketSidecarState::DeletedIgnored,
        None => BucketSidecarState::Unrecognized,
    }
}

/// Consecutive reconcile passes an owned id must remain absent, once its removal is
/// suspected as part of a mass removal, before it is evicted. At `2`, a suspected mass
/// removal is confirmed on the second pass that still sees it gone, and a one-poll listing
/// glitch clears on the next pass without ever reaching it.
const CONFIRM_REMOVAL_POLLS: u32 = 2;

/// The observed state of the `_sync_marker.json` change-token.
///
/// A definite absence and an indeterminate `HeadObject` failure are separate states, so the
/// loop can fail safe: an indeterminate observation never opens the removal gate and never
/// overwrites the baseline. Collapsing the two would let a transient failure flip
/// `marker_changed` against a known token and then overwrite the good baseline.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Marker {
    /// A definite change-token (`ETag`, else last-modified).
    Token(String),
    /// The marker is definitely absent (`NotFound`).
    Absent,
    /// The observation is indeterminate: a transient non-`NotFound` `HeadObject` error, or
    /// an incomplete response. Neither present nor confirmed absent.
    Unknown,
}

impl Marker {
    /// Classify a `HeadObject` result into the three states.
    fn classify(result: Result<object_store::ObjectMeta, object_store::Error>) -> Self {
        match result {
            Ok(meta) => Self::Token(
                meta.e_tag
                    .unwrap_or_else(|| meta.last_modified.to_rfc3339()),
            ),
            Err(object_store::Error::NotFound { .. }) => Self::Absent,
            Err(_) => Self::Unknown,
        }
    }

    /// Whether this observation opens the removal gate relative to `baseline`.
    ///
    /// Only a definite observation (`Token` or `Absent`) that differs from the last known
    /// baseline does. An `Unknown` observation never opens the gate, which stops a transient
    /// `HeadObject` failure or an incomplete 200 listing from triggering absence-eviction.
    /// Against an `Unknown` baseline, which only comes from a failed boot read, any definite
    /// observation counts as a change, so a real mutation during the outage is not missed.
    /// The bias is toward reconciling, never toward serving retracted data.
    fn opens_removal_gate(&self, baseline: &Marker) -> bool {
        match self {
            Marker::Unknown => false,
            definite => definite != baseline,
        }
    }

    /// Whether this is a definite observation worth adopting as the new baseline. An
    /// `Unknown` must not overwrite a good baseline, or the next real token re-flips the
    /// gate.
    fn is_known(&self) -> bool {
        !matches!(self, Marker::Unknown)
    }

    /// The change-token to record in the reconcile ACK, or `None` for `Absent` and
    /// `Unknown`.
    fn ack_token(&self) -> Option<String> {
        match self {
            Marker::Token(t) => Some(t.clone()),
            Marker::Absent | Marker::Unknown => None,
        }
    }
}

/// Whether a poll tick should run a reconcile pass: an operator trigger, a marker change, or
/// the due full-poll interval. Extracted so a test can pin its independence from
/// `marker_changed`: an `Unknown` marker forces `marker_changed = false`, and a due full poll
/// must still reconcile, since a missed reconcile keeps serving retracted data.
const fn should_reconcile(triggered: bool, marker_changed: bool, due_full: bool) -> bool {
    triggered || marker_changed || due_full
}

/// Decide which owned-absent ids to evict this reconcile, and the updated per-id
/// consecutive-absence streaks, applying cross-poll confirmation to a suspected mass
/// removal: a majority of a channel's datasets vanishing at once is not evicted on the first
/// sighting, it must persist across [`CONFIRM_REMOVAL_POLLS`] passes. A legitimate bulk
/// unpublish is therefore applied rather than wedged forever, while a truncated listing that
/// clears next poll never evicts.
///
/// * `absent` — owned ids currently missing from the listing.
/// * `owned_total` — the channel's owned dataset count, the mass-removal denominator.
/// * `prior` — each id's streak from the previous pass.
/// * `process_removals` — `true` on a marker-triggered reconcile, which may start a
///   confirmation and evicts a normal small removal immediately; `false` on the timer-only
///   full-poll safety net, which only advances an already-pending confirmation and never
///   acts on a fresh absence. Advancing on the full poll lets a single bulk-delete marker
///   bump confirm without waiting for a second marker change.
///
/// Returns `(evict, next_streaks)`. Ids absent this pass but not evicted carry a streak in
/// `next_streaks`; ids no longer absent, whether a resolved glitch or an eviction, are
/// dropped.
fn plan_removals(
    absent: &std::collections::BTreeSet<String>,
    owned_total: usize,
    prior: &HashMap<String, PendingRemoval>,
    process_removals: bool,
    now: Instant,
    min_separation: Duration,
) -> (Vec<String>, HashMap<String, PendingRemoval>) {
    let suspect = is_suspect_mass_removal(absent.len(), owned_total);
    let mut evict = Vec::new();
    let mut next = HashMap::new();
    for id in absent {
        let prior_entry = prior.get(id);
        let prior_streak = prior_entry.map_or(0, |p| p.streak);
        // A confirmation may only advance on an observation separated in time from the one
        // that raised it: the guard's safety rests on a truncated listing clearing by the
        // next poll, and a second look at the same instant is the same observation counted
        // twice. Without this, anything able to drive reconciles back to back collapses the
        // window and turns a transient glitch into a confirmed eviction in one request.
        let separated =
            prior_entry.is_none_or(|p| now.duration_since(p.last_advanced) >= min_separation);
        let confirm =
            |streak: u32, evict: &mut Vec<String>, next: &mut HashMap<String, PendingRemoval>| {
                if !separated {
                    // Hold the existing confirmation unchanged, including its clock, so a
                    // burst of passes neither advances nor resets it.
                    if let Some(p) = prior_entry {
                        next.insert(id.clone(), *p);
                    }
                    return;
                }
                if streak >= CONFIRM_REMOVAL_POLLS {
                    evict.push(id.clone());
                } else {
                    next.insert(
                        id.clone(),
                        PendingRemoval {
                            streak,
                            last_advanced: now,
                        },
                    );
                }
            };
        if process_removals && !suspect {
            // A normal small unpublish: evict immediately (drop any stale streak).
            evict.push(id.clone());
        } else if process_removals {
            // A marker-triggered suspected mass removal: confirm across polls.
            confirm(prior_streak + 1, &mut evict, &mut next);
        } else if prior_streak > 0 {
            // Timer-only full poll: advance only an already-pending confirmation. A fresh
            // absence with no prior streak is ignored rather than acted on.
            confirm(prior_streak + 1, &mut evict, &mut next);
        }
    }
    evict.sort();
    (evict, next)
}

/// The dataset id inside a listing key that the id validator rejected only because the key
/// sits below this channel's keyspace: `Some("GDI-EE-…")` for `provider-a/GDI-EE-…`, `None`
/// for a genuinely malformed name.
///
/// `rejected` is the key minus its extension, what `strip_suffix(TAR_C4GH_SUFFIX)` left, and
/// is only asked once `is_valid_dataset_id` has said no. Splitting on the last `/` separates
/// the two reasons a name can be rejected: junk is junk at any depth, but a valid id under a
/// path segment is a correctly-named package in the wrong keyspace.
fn nested_dataset_id(rejected: &str) -> Option<&str> {
    let (parent, last) = rejected.rsplit_once('/')?;
    // A leading `/` gives an empty parent: a malformed key, not a nested one.
    (!parent.is_empty() && is_valid_dataset_id(last)).then_some(last)
}

/// One id's pending mass-removal confirmation: how many separated observations have seen it
/// absent, and when the last of those was counted.
///
/// The clock matters as much as the count. `CONFIRM_REMOVAL_POLLS` counts observations, and
/// an observation is only independent if time passed since the last one. Otherwise a caller
/// able to drive reconciles in a burst satisfies the count without the delay that makes it
/// mean anything.
#[derive(Debug, Clone, Copy)]
struct PendingRemoval {
    /// Consecutive separated passes that saw this id absent.
    streak: u32,
    /// When `streak` was last incremented.
    last_advanced: Instant,
}

impl BucketMonitor {
    /// Build a monitor over a freshly-built object store for `bucket`.
    ///
    /// # Errors
    ///
    /// Propagates [`build_object_store`] failures (missing endpoint/bucket, etc.).
    pub fn new(bucket: S3Bucket, state: AppState, runtime: IngestRuntime) -> Result<Self> {
        // Two clients over the same bucket: a bounded one for the metadata requests the
        // poll loop awaits, and an unbounded one for the package body, which must be free to
        // stream for as long as a multi-GB download takes. Both come from `conn_params`, so
        // they cannot address different buckets.
        let store = build_object_store(&bucket)?;
        let package_store = build_package_object_store(&bucket)?;
        Ok(Self::with_stores(
            store,
            package_store,
            bucket,
            state,
            runtime,
        ))
    }

    /// Build a monitor over an explicit object store (the test seam: `InMemory`).
    ///
    /// The one store backs both the metadata and package paths, since an in-memory store
    /// has no timeouts to distinguish. Use [`Self::with_stores`] to separate them.
    #[must_use]
    pub fn with_store(
        store: Store,
        bucket: S3Bucket,
        state: AppState,
        runtime: IngestRuntime,
    ) -> Self {
        Self::with_stores(store.clone(), store, bucket, state, runtime)
    }

    /// Build a monitor over explicit metadata + package object stores.
    #[must_use]
    pub fn with_stores(
        store: Store,
        package_store: Store,
        bucket: S3Bucket,
        state: AppState,
        runtime: IngestRuntime,
    ) -> Self {
        Self {
            store,
            package_store,
            nested_key_warned: Arc::new(AtomicBool::new(false)),
            bucket: Arc::new(bucket),
            state,
            runtime,
            writeback_disabled: Arc::new(AtomicBool::new(false)),
            ingesting: Arc::new(Mutex::new(HashSet::new())),
            pending_removals: Arc::new(Mutex::new(HashMap::new())),
            retire: Arc::new(RetireSignal::default()),
        }
    }

    /// The retirement signal this monitor and its supervisor share.
    ///
    /// Handed to the supervisor at spawn and kept by the reload so a later `SIGHUP` can
    /// stand this channel down before starting its replacement.
    #[must_use]
    pub fn retire_signal(&self) -> Arc<RetireSignal> {
        Arc::clone(&self.retire)
    }

    /// The owning channel name (the bucket's logical `name`).
    #[must_use]
    pub fn channel(&self) -> &str {
        &self.bucket.name
    }

    /// The descriptor this monitor was built from. A `SIGHUP` reload diffs the freshly-loaded
    /// entry against it to decide whether this channel needs restarting. It is the effective
    /// descriptor after overrides, not the file's.
    #[must_use]
    pub fn descriptor(&self) -> &S3Bucket {
        &self.bucket
    }

    /// Whether this monitor's channel currently carries an active channel-level suppression
    /// (`channel-{name}.json`), the pre-poll pause gate: a channel-suppressed bucket stops
    /// polling, downloading and ingesting entirely, not merely the per-id ingest decision
    /// that `apply_package`'s
    /// [`effective()`][gdi_node_standalone_core::suppression::SuppressionSet::effective]
    /// check already gates once the channel entry is populated. Read-lock only; never held
    /// across an `.await`.
    fn channel_suppressed(&self) -> bool {
        self.state
            .suppressions
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .channel_get(self.channel())
            .is_some()
    }

    /// A handle to this monitor's in-flight (`ingesting`) set, shared by clones.
    ///
    /// Used by the reload swap: a monitor being replaced hands its in-flight set to its
    /// successor via [`Self::adopt_ingesting`], so an id still ingesting under the retired
    /// monitor stays visible to the replacement's `apply_removed`. Without the carry the
    /// successor starts with an empty set, and a package deleted at source during that ingest
    /// is published `Visible` and served until the next full reconcile.
    #[must_use]
    pub fn ingesting_handle(&self) -> Arc<Mutex<HashSet<String>>> {
        Arc::clone(&self.ingesting)
    }

    /// Adopt the in-flight set of the monitor this one replaces on reload, in place of the
    /// fresh one [`Self::with_stores`] created. Call it before the monitor is spawned or
    /// cloned, so every clone shares the carried set. The retired monitor's still-running
    /// ingest tasks prune and record through the same `Arc`, so they and this monitor's poll
    /// loop observe one set rather than two.
    pub fn adopt_ingesting(&mut self, handle: Arc<Mutex<HashSet<String>>>) {
        self.ingesting = handle;
    }

    /// Test-support hook: mark `id` as one this monitor is ingesting, as the download and
    /// enqueue path does, so a test can reproduce the deleted-while-in-flight state without
    /// racing a real ingest. Not part of the public API.
    #[doc(hidden)]
    pub fn test_mark_ingesting(&self, id: &str) {
        self.ingesting_lock().insert(id.to_owned());
    }

    /// Run the poll loop until the queue closes: marker `HeadObject` every
    /// `marker_poll_interval`, plus an unconditional full reconcile every
    /// `full_poll_interval`. A marker `ETag` change triggers a full reconcile.
    ///
    /// Channel suppression pauses this loop entirely: while this monitor's channel carries
    /// an active channel-level suppression override, no `HeadObject`, list, download or
    /// ingest call is made at all, so a compromised provider gets no further node contact
    /// until `channel unhide` lifts it. The suppression is re-read on every wake, whether a
    /// marker-poll tick, an operator `SIGUSR1` trigger or the periodic full-poll interval, so
    /// lifting it resumes on the next tick even without a delivered signal.
    ///
    /// Cancellation-safe: it only sleeps and awaits store calls, holding no lock across
    /// `.await`.
    pub async fn run(self) {
        // A channel suppressed from the first tick must not issue even the seed HeadObject
        // calls below, for parity with the in-loop pause.
        let suppressed_at_boot = self.channel_suppressed();
        if suppressed_at_boot {
            metrics::channel_suppressed(self.channel(), true);
            info!(
                channel = self.channel(),
                "channel administratively suppressed at startup; monitor starts paused \
                 (no poll/download/ingest) until `channel unhide` lifts it"
            );
        } else {
            // Seed the per-bucket writeback-disabled gauge at 0 for a write_status bucket so
            // the series is present, and visibly false, before any AccessDenied flips it. A
            // read-only bucket never writes back, so it stays unseeded.
            if self.bucket.write_status {
                metrics::s3_writeback_disabled(self.channel(), self.writeback_disabled());
            }
        }

        let marker_period = Duration::from_secs(self.bucket.marker_poll_interval.max(1));
        let full_period = Duration::from_secs(self.bucket.full_poll_interval.max(1));

        // Monotonic. This is the safety net that catches a marker bump the node missed, so
        // the wall clock must not disarm it: a backward step from an NTP correction or a
        // manual set would otherwise read as "not due yet" and postpone the sweep until the
        // clock caught back up.
        let mut last_full = std::time::Instant::now();
        // The startup reconcile has already run for readiness unless the channel was
        // suppressed at boot, in which case no startup reconcile ran either. Seed the marker
        // so the first loop iteration does not immediately re-reconcile on an unchanged one.
        // A boot-suppressed channel seeds `Unknown`, against which any definite observation
        // counts as a change, so the first read after the suppression lifts reconciles.
        let mut last_marker: Marker = if suppressed_at_boot {
            Marker::Unknown
        } else {
            self.head_marker().await
        };
        let mut monitor_paused = suppressed_at_boot;

        loop {
            // Wake on the marker poll interval or an operator `SIGUSR1` reconcile trigger,
            // whichever comes first. Cancellation-safe: whichever branch loses is a bare
            // timer or `Notify` future, dropped with nothing held across it.
            let triggered = tokio::select! {
                () = tokio::time::sleep(marker_period) => false,
                () = self.state.reconcile_trigger.notified() => true,
                () = self.retire.wake.notified() => true,
            };

            // A reload has replaced this channel's descriptor. Return between polls, with
            // nothing in flight from this task, and let the supervisor stand down through the
            // same flag so the replacement monitor is the only one on this channel. Checked
            // after the wake, not only before the sleep, so a retirement raised mid-reconcile
            // is acted on at once.
            if self.retire.is_retired() {
                info!(
                    channel = self.channel(),
                    "channel descriptor changed by a config reload; this monitor is standing \
                     down for its replacement"
                );
                return;
            }

            // Skip HeadObject, list, download and ingest entirely while the channel is
            // suppressed, rather than only gating the per-id ingest decision that
            // `apply_package`'s `effective()` check already covers. Logged on transition, not
            // every tick, so a long suppression window does not spam; the gauge is still
            // refreshed every tick so it never goes stale.
            let suppressed = self.channel_suppressed();
            metrics::channel_suppressed(self.channel(), suppressed);
            if suppressed {
                if !monitor_paused {
                    info!(
                        channel = self.channel(),
                        "channel administratively suppressed; pausing poll/download/ingest \
                         until `channel unhide` lifts it"
                    );
                    monitor_paused = true;
                }
                continue;
            }
            if monitor_paused {
                info!(
                    channel = self.channel(),
                    "channel suppression lifted; resuming poll/download/ingest"
                );
                monitor_paused = false;
            }

            let due_full = last_full.elapsed() >= full_period;
            let marker = self.head_marker().await;
            // Only a definite change opens the removal gate; an `Unknown` from a transient
            // failure is never a change. A due full poll still reconciles below regardless,
            // so an `Unknown` never suppresses a needed reconcile either.
            let marker_changed = marker.opens_removal_gate(&last_marker);

            if should_reconcile(triggered, marker_changed, due_full) {
                if triggered {
                    debug!(
                        channel = self.channel(),
                        "operator reconcile trigger; reconciling"
                    );
                } else if marker_changed {
                    debug!(channel = self.channel(), "marker changed; reconciling");
                } else {
                    debug!(channel = self.channel(), "full-poll interval; reconciling");
                }
                // Only a marker change processes fresh package-absence removals. A real
                // delete bumps the marker, so an absence seen on a timer-only sweep or an
                // operator trigger is a truncated listing that would otherwise wipe a small
                // bucket. An operator `Remove` eviction runs separately via
                // `AppState::enforce_suppressions`, never through this removal path.
                //
                // On success, record the marker reconciled on so an orchestrator can confirm
                // its `_sync_marker.json` bump was observed. Consume it only on success: it
                // is the sole authorisation for removal processing, so consuming one whose
                // reconcile applied nothing drops a retraction permanently, since
                // `marker_changed` never comes back and the later full poll runs with
                // removals gated off. Leaving it unconsumed retries on the next tick.
                if self.reconcile_with(marker_changed).await {
                    self.state
                        .readiness
                        .record_reconcile(self.channel(), marker.ack_token());
                    // Adopt only a definite observation as the new baseline; an `Unknown`
                    // must not overwrite the last-good token, or the next real token
                    // re-flips the gate.
                    if marker.is_known() {
                        last_marker = marker;
                    }
                }
                last_full = std::time::Instant::now();
            }
        }
    }

    /// `HeadObject` the marker, classified into [`Marker`]. A definite absence (`Absent`) and
    /// a transient failure (`Unknown`) stay distinct: only a definite change opens the removal
    /// gate, so an indeterminate read cannot trigger a spurious eviction. The full poll still
    /// reconciles regardless, and reconcile remains the source of truth.
    async fn head_marker(&self) -> Marker {
        let result = self.store.head(&ObjPath::from(MARKER_KEY)).await;
        if let Err(e) = &result
            && !matches!(e, object_store::Error::NotFound { .. })
        {
            warn!(
                channel = self.channel(),
                error = %e,
                "marker HeadObject failed; the observation is indeterminate and does not \
                 count as a change"
            );
        }
        Marker::classify(result)
    }

    /// Run one full reconcile pass: list, diff, apply (New / Re-presented / Removed /
    /// State-changed), then writeback. Best-effort: a listing failure is logged and retried
    /// next cycle.
    pub async fn reconcile(&self) {
        let _ = self.reconcile_with(true).await;
    }

    /// Like [`Self::reconcile`], but `process_removals` gates the Removed pass.
    ///
    /// The `run()` poll loop passes `marker_changed`. A timer-only sweep with an unchanged
    /// marker passes `false`, so a truncated listing cannot evict a dataset whose package is
    /// absent only because the listing was incomplete; a genuine delete bumps the sync marker
    /// and arrives here as a marker-triggered `true`. Startup readiness and tests use
    /// [`Self::reconcile`], which passes `true`, so a real delete followed by an explicit
    /// reconcile still evicts in one poll.
    pub async fn reconcile_with(&self, process_removals: bool) -> bool {
        // One `s3_poll{channel}` span per pass, so a slow or failing listing is visible in a
        // trace. Every `s3_download` and `overlay_apply` of the pass nests under it.
        let span = tracing::info_span!("s3_poll", channel = self.channel());
        tracing::Instrument::instrument(self.reconcile_pass(process_removals), span).await
    }

    /// The body of [`Self::reconcile_with`], split out so the poll span can wrap it.
    async fn reconcile_pass(&self, process_removals: bool) -> bool {
        let listing = match self.list().await {
            Ok(l) => l,
            Err(e) => {
                warn!(channel = self.channel(), error = %e, "S3 listing failed (transient)");
                // A failed poll marks S3 unhealthy for `/health/ready`, since the bucket is
                // a configured dependency, and bumps the per-bucket poll-error counter. It
                // recovers on the next good poll.
                self.state
                    .readiness
                    .set_channel_health(self.channel(), false);
                metrics::s3_poll_error(self.channel());
                return false;
            }
        };
        // The keyspace gate is asked once per pass and its answer handed to the apply, as an
        // input distinct from the timer-only `process_removals` that `plan_removals` reads as
        // "advance a pending confirmation".
        let gate_authorized = self.removals_authorized(&listing).await;
        self.apply_gated(&listing, process_removals, gate_authorized)
            .await;
        self.writeback_owned().await;
        // A successful reconcile (listing + apply) marks S3 healthy for readiness and
        // stamps the last-success timestamp so a silently-wedged poller is visible.
        self.state
            .readiness
            .set_channel_health(self.channel(), true);
        // A successful poll also establishes data visibility, so a node whose startup
        // reconciles all failed, leaving `initial_reconcile` pending, becomes ready now.
        // Idempotent: a no-op once already marked done.
        self.state.readiness.mark_initial_reconcile_done();
        metrics::s3_poll_success(self.channel());
        true
    }

    /// Warn, at most once per channel, that a node-shaped object sits one or more path
    /// segments below the keyspace this channel polls.
    ///
    /// This is the half of the prefix-desync mistake the channel's own listing can see: the
    /// writer prefixed one level deeper than the node polls. Both sides are otherwise silent,
    /// since the writer reports success while the node answers `404` for that id forever. The
    /// reverse direction would need a listing outside the prefix, which
    /// `[[s3.buckets]].prefix` promises the node never issues; comparing the keyspace each
    /// `doctor` command prints is how that one is found.
    ///
    /// A warning, never a refusal, and latched once: a bucket shared with a second node on a
    /// different prefix is a supported topology, and a co-tenant's keys must not stop this
    /// channel serving.
    fn note_nested_dataset_key(&self, key: &str, rejected_id: &str) {
        let Some(nested) = nested_dataset_id(rejected_id) else {
            return;
        };
        if self.nested_key_warned.swap(true, Ordering::SeqCst) {
            return;
        }
        let polling = match self.bucket.prefix.trim_end_matches('/') {
            "" => "the bucket root".to_owned(),
            p => format!("{p}/"),
        };
        warn!(
            channel = self.channel(),
            key,
            dataset = nested,
            polling = %polling,
            "ignored: a valid dataset id sits below the keyspace this channel polls, so it \
             will never be ingested and the id answers 404, while the writer's upload, \
             publish and list all report success. The prefix is set on the writer but not \
             on this channel, or set one level deeper. Compare `gdi-node-standalone doctor` \
             here against `gdi-dataset-tool doctor` on the writer: the two must print the \
             same bucket and prefix. Warned once per channel"
        );
    }

    /// List the flat bucket root into a [`Listing`]: classify `{id}.tar.c4gh` and
    /// `{id}.state.json`, and ignore `_status/*`, the marker, and any unknown per-id object
    /// under the additive-object rule.
    ///
    /// # Errors
    ///
    /// Returns the object-store error on a listing failure, or a generic error if the
    /// bucket lists more than [`MAX_BUCKET_OBJECTS`] objects (fail closed rather than
    /// accumulate an attacker-influenced, unbounded working set).
    async fn list(&self) -> Result<Listing, object_store::Error> {
        // Stream the listing and fold each object into `listing` directly, with no
        // intermediate `Vec<ObjectMeta>` holding every key at once. The object count is
        // capped so a provider or co-tenant flooding the bucket fails the poll instead of
        // OOM-ing the shared process.
        let mut listing = Listing::default();
        let mut stream = self.store.list(None);
        let mut scanned: usize = 0;

        while let Some(meta) = stream.next().await {
            let meta = meta?;
            scanned += 1;
            if scanned > MAX_BUCKET_OBJECTS {
                return Err(object_store::Error::Generic {
                    store: "s3",
                    source: format!(
                        "bucket lists more than {MAX_BUCKET_OBJECTS} objects; refusing to \
                         reconcile an unbounded listing"
                    )
                    .into(),
                });
            }
            let key = meta.location.as_ref();
            // Ignore the node's own status namespace and the marker.
            if key.starts_with(STATUS_PREFIX) || key == MARKER_KEY {
                continue;
            }
            if let Some(id) = key.strip_suffix(TAR_C4GH_SUFFIX) {
                if !is_valid_dataset_id(id) {
                    // A rejected name that is a valid id one path segment down is not junk,
                    // it is a correctly-built package dropped in the wrong keyspace.
                    self.note_nested_dataset_key(key, id);
                    debug!(
                        channel = self.channel(),
                        key, "ignored: .tar.c4gh name is not a valid dataset id"
                    );
                    continue;
                }
                let etag = meta
                    .e_tag
                    .clone()
                    .unwrap_or_else(|| meta.last_modified.to_rfc3339());
                listing.packages.insert(
                    id.to_owned(),
                    PackageMeta {
                        etag,
                        size: meta.size,
                    },
                );
            } else if let Some(id) = key.strip_suffix(STATE_SUFFIX) {
                if !is_valid_dataset_id(id) {
                    // Same signal from the sidecar half: a writer that prefixed its packages
                    // prefixed their sidecars too, and whichever the listing reaches first is
                    // enough. The latch keeps it to one line either way.
                    self.note_nested_dataset_key(key, id);
                    debug!(
                        channel = self.channel(),
                        key, "ignored: .state.json name is not a valid dataset id"
                    );
                    continue;
                }
                listing
                    .sidecars
                    .insert(id.to_owned(), meta.location.clone());
            } else if let Some(id) = key.strip_suffix(OVERLAY_SUFFIX) {
                if !is_valid_dataset_id(id) {
                    debug!(
                        channel = self.channel(),
                        key, "ignored: .metadata.json name is not a valid dataset id"
                    );
                    continue;
                }
                listing
                    .overlays
                    .insert(id.to_owned(), meta.location.clone());
            } else {
                // An unknown per-id object is additive: logged and ignored, never an error.
                debug!(
                    channel = self.channel(),
                    key, "ignored: unrecognized bucket object"
                );
            }
        }
        Ok(listing)
    }

    /// Read the optional W3C `traceparent` from a `{id}.state.json`. Best-effort: any fetch
    /// or parse failure, including an oversized control object, yields `None` and the ingest
    /// span gets a fresh root. Costs one extra GET of a small control object on the rare
    /// new-package path.
    #[expect(
        clippy::disallowed_methods,
        reason = "the advertised size is checked against MAX_CONTROL_OBJECT_BYTES immediately below"
    )]
    async fn fetch_sidecar_traceparent(&self, key: &ObjPath) -> Option<String> {
        let result = self.store.get(key).await.ok()?;
        if result.meta.size > crate::ingest_runtime::MAX_CONTROL_OBJECT_BYTES {
            return None;
        }
        let bytes = result.bytes().await.ok()?;
        serde_json::from_slice::<StateSidecar>(&bytes)
            .ok()
            .and_then(|s| s.traceparent)
    }

    /// Fetch a bucket sidecar's served visibility, delegating to the free
    /// [`fetch_state_from_store`], which is shared with the publish-time re-read and
    /// documents the fail-safe behaviour: a missing, oversized, failed or unrecognized
    /// sidecar defaults to `hidden`.
    async fn fetch_state(&self, id: &str, key: &ObjPath) -> DatasetState {
        let verdict = fetch_state_from_store(&self.store, self.channel(), id, key).await;
        match verdict.rejected {
            Some(reason) => self
                .state
                .note_state_sidecar_error(id, self.channel(), reason),
            None => self.state.clear_state_sidecar_error(id),
        }
        verdict.state
    }

    /// `data_dir/.keyspace-{channel}.json`, the [`KeyspaceWitness`]'s home. Dot-prefixed so
    /// it cannot collide with a dataset directory, as with `.status.json` and the PME
    /// sentinel, and kept beside the datasets it vouches for so a restore that brings back
    /// the data brings back the witness.
    fn keyspace_witness_path(&self) -> std::path::PathBuf {
        self.state
            .config
            .service
            .data_dir
            .join(format!(".keyspace-{}.json", self.channel()))
    }

    /// Persist `witness` durably (atomic + fsync), returning whether it is now on disk.
    ///
    /// The caller refuses removals on `false`: an adoption that could not be recorded has
    /// not happened, and authorizing on the strength of a witness that is not there would
    /// make a read-only or full `data_dir` re-enter the first-observation arm on every boot
    /// and authorize unconditionally, including the boot after a re-point. The failure
    /// direction stays safe: an absent or stale witness can only refuse removals, never
    /// authorize ones the current witness would not, and the next pass retries the write.
    async fn write_keyspace_witness(&self, witness: &KeyspaceWitness) -> bool {
        let path = self.keyspace_witness_path();
        let bytes = match serde_json::to_vec_pretty(witness) {
            Ok(b) => b,
            Err(e) => {
                warn!(channel = self.channel(), error = %e, "serializing keyspace witness");
                return false;
            }
        };
        let write_path = path.clone();
        let result = tokio::task::spawn_blocking(move || {
            gdi_node_standalone_core::util::write_durable_atomic_private(&write_path, &bytes)
        })
        .await;
        let failure = match result {
            Ok(Ok(())) => None,
            Ok(Err(e)) => Some(e.to_string()),
            Err(e) => Some(e.to_string()),
        };
        if let Some(error) = failure {
            warn!(
                channel = self.channel(),
                path = %path.display(),
                error,
                "writing keyspace witness failed; removals are refused until it can be \
                 recorded, retried next pass, because nothing on disk vouches for this \
                 keyspace"
            );
            return false;
        }
        true
    }

    /// Whether the Removed pass may run against `listing`: the keyspace gate.
    ///
    /// The persisted [`KeyspaceWitness`] records the keyspace this channel's on-disk datasets
    /// were ingested from. The live reload refuses to re-point a running monitor because an
    /// empty keyspace cannot be told from a mass deletion; this applies the same rule to a
    /// restart. Four outcomes:
    ///
    /// * **Match** — authorized, the steady state; nothing is rewritten.
    /// * **Absent** — first observation, from a fresh channel or a first boot without a
    ///   witness on disk. The current config is adopted and removals are authorized, but only
    ///   once the witness reaches disk. Trust on first observation leaves that first boot
    ///   unprotected and every boot after it protected. A witness that cannot be written, on
    ///   a read-only or full `data_dir`, refuses instead with the mismatch gauge raised, or
    ///   this arm would re-authorize on every boot including the one after a re-point.
    /// * **Mismatch, nothing missing** — every dataset the channel owns is present in the new
    ///   keyspace's listing, so the data moved with the keyspace: adopt and authorize.
    ///   Adopting here cannot evict anything. A channel whose datasets were all erased with
    ///   `take-down` adopts vacuously, so that erasure verb doubles as the "abandon the old
    ///   keyspace" step.
    /// * **Mismatch, something missing** — the destructive case the gate exists for, refused.
    ///   Additions from the new keyspace still ingest, since only removals are gated. The
    ///   warning names both keyspaces and the ways out, and
    ///   `gdi_s3_keyspace_mismatch{channel}` holds 1 until one of them happens.
    ///
    /// An unreadable or unparseable witness also refuses, failing closed. Only the destructive
    /// pass is gated, so serving is unaffected, and deleting the corrupt file recovers through
    /// the absent arm.
    async fn removals_authorized(&self, listing: &Listing) -> bool {
        let configured = self.bucket.keyspace_witness();
        let path = self.keyspace_witness_path();
        let read_path = path.clone();
        let recorded: Result<Option<KeyspaceWitness>, String> =
            match tokio::task::spawn_blocking(move || match std::fs::read(&read_path) {
                Ok(bytes) => serde_json::from_slice::<KeyspaceWitness>(&bytes)
                    .map(Some)
                    .map_err(|e| e.to_string()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e.to_string()),
            })
            .await
            {
                Ok(r) => r,
                // A cancelled or panicked blocking task: refuse this pass, retried next.
                Err(e) => Err(e.to_string()),
            };

        match recorded {
            Ok(Some(witness)) if witness == configured => {
                metrics::s3_keyspace_mismatch(self.channel(), false);
                true
            }
            Ok(None) => {
                info!(
                    channel = self.channel(),
                    "no keyspace witness recorded for this channel; adopting the \
                     configured keyspace (first observation)"
                );
                let recorded = self.write_keyspace_witness(&configured).await;
                metrics::s3_keyspace_mismatch(self.channel(), !recorded);
                recorded
            }
            Ok(Some(witness)) => {
                // Mismatch. Safe to adopt only if nothing the channel owns is missing from
                // the new keyspace's listing, using the same owned-set filter
                // `apply_removed` uses for its eviction candidates.
                let missing: usize = {
                    let status = self.status_lock();
                    status
                        .entries()
                        .iter()
                        .filter(|(id, entry)| {
                            entry.channel == self.channel()
                                && !self.runtime.is_id_inflight(id)
                                && !listing.packages.contains_key(*id)
                        })
                        .count()
                };
                if missing == 0 {
                    info!(
                        channel = self.channel(),
                        from_endpoint = %witness.endpoint,
                        from_bucket = %witness.bucket,
                        from_prefix = %witness.prefix,
                        "keyspace changed and every owned dataset is present at the new \
                         keyspace; adopting it (removals re-enabled)"
                    );
                    let recorded = self.write_keyspace_witness(&configured).await;
                    metrics::s3_keyspace_mismatch(self.channel(), !recorded);
                    recorded
                } else {
                    warn!(
                        channel = self.channel(),
                        recorded_endpoint = %witness.endpoint,
                        recorded_bucket = %witness.bucket,
                        recorded_prefix = %witness.prefix,
                        configured_endpoint = %configured.endpoint,
                        configured_bucket = %configured.bucket,
                        configured_prefix = %configured.prefix,
                        missing,
                        "this channel's configured keyspace is not the one its datasets \
                         were ingested from, and {missing} of them are absent from the \
                         new keyspace's listing; refusing to process removals, because an \
                         eviction here would be the mass deletion the live reload refuses \
                         to risk. Additions still ingest. To resolve: revert the endpoint, \
                         bucket or prefix change; or finish migrating the data so nothing \
                         is missing; or erase the channel's datasets with `dataset \
                         take-down` or `channel take-down`, after which the new keyspace \
                         is adopted automatically"
                    );
                    metrics::s3_keyspace_mismatch(self.channel(), true);
                    false
                }
            }
            Err(e) => {
                warn!(
                    channel = self.channel(),
                    path = %path.display(),
                    error = %e,
                    "keyspace witness unreadable; refusing to process removals until it \
                     is restored or deleted (a deleted witness is re-adopted from the \
                     running config)"
                );
                metrics::s3_keyspace_mismatch(self.channel(), true);
                false
            }
        }
    }

    /// Apply the listing diff against the local cache and status index.
    ///
    /// `gate_authorized` is the keyspace gate's answer for this listing, asked once by the
    /// caller ([`Self::removals_authorized`]): removals may only be processed when the
    /// listing came from the keyspace the channel's on-disk datasets were ingested from.
    /// Without it a restart would apply an endpoint, bucket or prefix change that the live
    /// reload refuses as data-destroying, since boot cannot tell an empty new keyspace from a
    /// mass deletion. Additions still apply either way. The refusal is a separate input to
    /// the Removed pass rather than being folded into `process_removals`, whose `false` means
    /// "timer-only: advance a pending confirmation" and would still evict under a refused
    /// gate.
    ///
    /// The gate also reaches `apply_package`, for the visibility flip of an already-live id
    /// from the listing's sidecar, which is neither an addition nor a removal. Otherwise a
    /// refused keyspace still carrying some of the channel's packages would rewrite their
    /// visibility from its sidecars.
    async fn apply_gated(&self, listing: &Listing, process_removals: bool, gate_authorized: bool) {
        // Removed: ids this channel owns whose package is gone from the listing.
        self.apply_removed(
            listing,
            process_removals && gate_authorized,
            !gate_authorized,
        )
        .await;

        for (id, pkg) in &listing.packages {
            self.apply_package(id, &pkg.etag, listing, gate_authorized)
                .await;
        }

        // Overlay apply and revert pass: the union of ids with an overlay object in the
        // bucket and ids whose durable overlay may need reverting after a deletion.
        let mut overlay_ids: std::collections::BTreeSet<String> =
            listing.overlays.keys().cloned().collect();
        // Offload the durable-overlay disk probes, one per cached dataset, to the blocking
        // pool rather than doing synchronous `std::fs` reads on the async reactor. A join
        // failure yields an empty set and the overlay reconcile is retried next pass.
        let ids = self.state.cache.ids();
        let data_dir = self.state.config.service.data_dir.clone();
        let with_durable = tokio::task::spawn_blocking(move || {
            ids.into_iter()
                .filter(|id| overlay::read_durable(&data_dir, id).is_some())
                .collect::<Vec<String>>()
        })
        .await
        .unwrap_or_default();
        overlay_ids.extend(with_durable);
        for id in &overlay_ids {
            // Only the channel that owns the id's package reconciles its overlay.
            // `with_durable` is drawn from the node-global cache, which spans every bucket,
            // so without this gate a non-owning bucket would find an id it does not own, see
            // no overlay object in its own listing, and revert the owning bucket's durable
            // overlay on every poll, flapping the published DCAT and FDP metadata between
            // overlaid and baseline. Ownership is keyed on the package's channel; an id with
            // no package yet is owned by nobody, so its overlay is deferred until ingest.
            if self.owning_channel(id).as_deref() != Some(self.channel()) {
                continue;
            }
            self.apply_overlay_change(id, listing).await;
        }
    }

    /// Handle Removed: for every id this channel owns in the status index whose `.tar.c4gh`
    /// is absent from the listing, evict the cache, purge the status entry, and delete the
    /// local dataset dir. An id this channel does not own is left alone, since another
    /// channel may own it. An in-flight id is skipped: it has no package yet and must not be
    /// evicted while ingesting.
    async fn apply_removed(&self, listing: &Listing, process_removals: bool, gate_refused: bool) {
        // For each id this monitor is still ingesting, a package that has vanished from the
        // listing was deleted mid-ingest. Record it so `on_success` publishes the finished
        // dataset Hidden instead of Visible: the in-flight guard below keeps such an id out
        // of the eviction set, so it would otherwise be served until the next reconcile. Ids
        // that have finished ingesting are pruned.
        {
            let mut ingesting = self.ingesting_lock();
            ingesting.retain(|id| {
                if !self.runtime.is_id_inflight(id) {
                    return false; // ingest finished; stop tracking
                }
                if !listing.packages.contains_key(id) {
                    self.state.note_removal_requested(id);
                }
                true
            });
        }
        // A refused keyspace gate is not a timer-only pass: `plan_removals` reads
        // `process_removals = false` as "advance an already-pending confirmation", so a
        // suspected mass removal confirmed on the previous pass would be evicted on the pass
        // the gate refused. Under refusal the pending set is held unchanged, neither started,
        // advanced nor cleared, and nothing is evicted; the gate's own warning names the way
        // out.
        if gate_refused {
            return;
        }
        // The owned datasets currently absent from the listing, and the channel's owned
        // total, the mass-removal denominator. Computed on both a marker-triggered pass and
        // the timer-only full poll, because the full poll advances an in-progress cross-poll
        // removal confirmation (see `plan_removals`).
        let (absent, owned_total): (std::collections::BTreeSet<String>, usize) = {
            let status = self.status_lock();
            let owned = || {
                status.entries().iter().filter(|(id, entry)| {
                    entry.channel == self.channel() && !self.runtime.is_id_inflight(id)
                })
            };
            let absent = owned()
                .filter(|(id, _)| !listing.packages.contains_key(*id))
                .map(|(id, _)| id.clone())
                .collect();
            (absent, owned().count())
        };
        // Collapse guard with cross-poll confirmation. A Removed pass evicts the cache,
        // purges the status entry and deletes the local dir, so a truncated or empty listing
        // that dropped many packages could wipe served data. A suspected mass removal, a
        // majority of the channel gone at once per `is_suspect_mass_removal`, is therefore
        // not evicted on first sight: it must persist across `CONFIRM_REMOVAL_POLLS`
        // reconciles. A real bulk delete is applied within a poll or two, while a one-poll
        // listing glitch clears and never evicts. A marker-triggered `process_removals` gates
        // whether a fresh absence may start a confirmation; an already-pending confirmation
        // also advances on the full poll, so a single bulk-delete marker bump does not stall
        // waiting for a second marker change.
        let suspect = is_suspect_mass_removal(absent.len(), owned_total);
        let owned_absent = {
            let mut pending = self.pending_removals_lock();
            // Fold in any confirmation seeded by an ingest that finished after its source
            // package was deleted. That id was excluded from `absent` while in flight, so the
            // racing poll recorded no streak, and a timer-only pass ignores a fresh absence
            // with `prior_streak == 0`, leaving a retracted dataset on disk indefinitely.
            // Seeding at 1 puts it on the normal confirm-across-polls path, so it still has
            // to be observed absent again before anything is deleted.
            let now = Instant::now();
            let seeded = self.state.drain_removal_seeds_for(self.channel());
            for id in &seeded {
                pending.entry(id.clone()).or_insert(PendingRemoval {
                    streak: 1,
                    last_advanced: now,
                });
            }
            // A confirmation advances only on an observation separated by at least one
            // marker poll, the cadence at which independent listings arrive. See
            // `PendingRemoval`: this stops a burst of operator-triggered reconciles from
            // satisfying the count without the delay that gives it meaning.
            let min_separation = Duration::from_secs(self.bucket.marker_poll_interval.max(1));
            let (evict, next) = plan_removals(
                &absent,
                owned_total,
                &pending,
                process_removals,
                now,
                min_separation,
            );
            *pending = next;
            // Carry forward a seed the plan could not evaluate. `plan_removals` rebuilds
            // `next` from `absent`, and an id still in flight is excluded from `absent`, so a
            // seed drained in the narrow window at the tail of `on_success` would be folded
            // in above and then dropped by this assignment. The drain has already removed it
            // from the seed set, so no later pass would see it again until a restart, and a
            // source-side erasure would leave the dataset on disk until an unrelated marker
            // bump.
            //
            // Only for ids that are still in flight: anything else `plan_removals` evaluated,
            // and its verdict stands.
            for id in seeded {
                if !pending.contains_key(&id) && self.runtime.is_id_inflight(&id) {
                    pending.insert(
                        id,
                        PendingRemoval {
                            streak: 1,
                            last_advanced: now,
                        },
                    );
                }
            }
            evict
        };
        if suspect && process_removals && owned_absent.is_empty() {
            // A suspected mass removal is being confirmed rather than applied this pass.
            // Surface it so an operator sees a deferred bulk removal rather than a silent
            // skip; the per-id eviction is logged below once confirmed.
            crate::metrics::s3_removal_skipped(self.channel());
            warn!(
                channel = self.channel(),
                absent = absent.len(),
                owned_total,
                confirm_polls = CONFIRM_REMOVAL_POLLS,
                "S3 reconcile sees a suspected mass removal, a majority of the channel gone \
                 at once; confirming across polls before evicting, so a listing glitch \
                 clears and a real bulk unpublish is applied once confirmed"
            );
        }
        for id in owned_absent {
            info!(channel = self.channel(), dataset = %id, "removed: package gone from bucket; evicting");
            // Mutation audit trail: an irreversible deletion. The `.tar.c4gh` disappeared
            // from the bucket, so the cache is evicted, the status purged and the local
            // dataset dir deleted. This is the erasure and unpublish path, so it must leave
            // a record.
            crate::audit::dataset_state_change(
                &self.state.config.audit,
                &id,
                self.channel(),
                "Deleted",
                "package-removed",
            );
            // The evict, purge and dir-remove, with its crash-safety ordering, lives once on
            // `AppState` so this path, the inbox tombstone path and operator `Remove` cannot
            // drift apart.
            self.state.erase_dataset(&id, self.channel()).await;
            // Best-effort delete tombstone on a write_status bucket.
            self.writeback_deleted(&id).await;
        }
    }

    /// Handle one present `{id}.tar.c4gh` (New / Re-presented / State-changed).
    async fn apply_package(&self, id: &str, etag: &str, listing: &Listing, gate_authorized: bool) {
        // Operator-suppression gate, both pre-emptive and anti-undo: a suppressed id is
        // neither ingested nor state-flipped, so the bucket sidecar cannot un-hide an
        // operator override. This blocks a pre-emptively-suppressed id before it lands and
        // makes a `Remove` eviction stick, since otherwise this reconcile would re-ingest the
        // still-present bucket package and undo the erase. The operator override wins over
        // the source; lifting the suppression releases the id on the next reconcile, either
        // through `ingest_new` if absent or `apply_state_change` if live.
        if self
            .state
            .suppressions
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .effective(id, self.channel())
            .is_some()
        {
            debug!(
                channel = self.channel(),
                dataset = id,
                "skipped: dataset is operator-suppressed; not ingesting or flipping state"
            );
            return;
        }

        // Cross-channel ownership: the first channel to claim an id owns it, and any other
        // channel presenting the same id is skipped with a warning while the owner holds it.
        if let Some(owner) = self.owning_channel(id) {
            if owner != self.channel() {
                warn!(channel = self.channel(), dataset = id, owner = %owner, "skipped: dataset id is owned by another channel");
                return;
            }
        } else if self.runtime.is_id_inflight(id) {
            // An id mid-ingest from another channel has no status entry yet: defer.
            debug!(
                channel = self.channel(),
                dataset = id,
                "id is being ingested elsewhere; deferring claim"
            );
            return;
        }

        let live = self
            .state
            .cache
            .get(id)
            .is_some_and(|e| matches!(e.state, DatasetState::Visible | DatasetState::Hidden));
        let last_seen = self.last_seen_signature(id);

        if live {
            // Re-presented for a live, and therefore immutable, id. A visible/hidden flip is
            // still applied with no re-download; a changed ETag is logged and ignored.
            //
            // Under a refused keyspace gate the flip is not applied: the sidecar comes from
            // the listing the gate declined to trust, so a `visible` there would publish the
            // dataset on that keyspace's word, and an absent sidecar would pull a served
            // dataset off the air. The last-known state is kept, as the last-known data is,
            // and the signature bookkeeping below is unaffected. The boot-time `states` loop
            // in `reconcile_for_readiness` applies the same rule.
            if !gate_authorized {
                debug!(
                    channel = self.channel(),
                    dataset = id,
                    "keyspace gate refused this listing; keeping the last-known visibility"
                );
                return;
            }
            if last_seen.as_deref() != Some(etag) {
                warn!(
                    channel = self.channel(),
                    dataset = id,
                    "ignored: dataset is immutable; re-presented package not re-ingested"
                );
                // Flag it on the state oracle: a changed re-presentation of a live id is
                // dropped, and a provider polling the oracle would otherwise see only
                // `visible` or `null`. Mirrors the inbox path.
                self.state.note_superseded_redrop(id);
                self.record_signature(id, etag);
            }
            self.apply_state_change(id, listing).await;
            return;
        }

        // Absent or error: a New id, or an error-recovery once the ETag changes.
        if last_seen.as_deref() == Some(etag) && !self.is_lost(id) {
            // Unchanged signature for a known id: nothing to do. A recorded error stays
            // recorded until its ETag changes, so a known-bad package is not re-downloaded on
            // every poll.
            return;
        }
        self.ingest_new(id, etag, listing).await;
    }

    /// Whether `id` is lost: absent from the cache with no error recorded for it.
    ///
    /// `hydrate_from_disk` drops a dataset whose `manifest.json` is unreadable and runs once
    /// per process. Nothing else brings it back on a bucket-only node, because the
    /// unchanged-signature early return in `apply_package` reads a seen `ETag` as "nothing to
    /// do".
    ///
    /// Lost is distinct from known-bad: a recorded error means the package was read and
    /// rejected, and retrying it every poll would re-download a package that fails again. No
    /// entry and no error means the node does not have it while the bucket does.
    fn is_lost(&self, id: &str) -> bool {
        if self.state.cache.get(id).is_some() {
            return false;
        }
        let status = self.status_lock();
        !status
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Error)
    }

    /// Download and enqueue a New or eligible re-presented package, after fetching its
    /// `.state.json` content for the published visibility.
    async fn ingest_new(&self, id: &str, etag: &str, listing: &Listing) {
        // Skip if already queued or in flight; dedups across channels and poll races.
        if self.runtime.is_id_inflight(id) {
            return;
        }
        // Reject an oversize package before downloading it. The encrypted `.tar.c4gh` size
        // is already known from the listing, so a package over the configured cap is refused
        // here rather than streamed in full into `.incoming/`, where a careless or hostile
        // provider could exhaust the data volume. The cap, `max_package_bytes`, bounds the
        // decrypted archive at extract time; crypt4gh ciphertext is never smaller than its
        // plaintext, so an encrypted object already over the cap would also fail extraction,
        // which makes this a conservative pre-filter. The full decrypted staging-byte bound
        // still applies after a within-cap download.
        if let Some(pkg) = listing.packages.get(id) {
            let cap = self.state.config.service.max_package_bytes;
            if pkg.size > cap {
                self.reject_oversize_package(id, etag, pkg.size, cap);
                return;
            }
        }
        // Do not resolve the published visibility here, ahead of a download that may take
        // minutes. Carry the sidecar key and re-read it at publish time, so an unpublish
        // issued mid-ingest is honoured. The traceparent is read now, since the ingest span
        // is parented as the download starts, and it is correlation metadata rather than a
        // security decision.
        let sidecar_key = listing.sidecars.get(id).cloned();
        let traceparent = match &sidecar_key {
            Some(key) => self.fetch_sidecar_traceparent(key).await,
            None => None,
        };
        // The transient-failure backoff, consulted before spending a download. The ingest
        // path's own check runs after the fetch and discards the bytes, which suits an ingest
        // that failed but not a package that never downloads: a bucket that lists fine and
        // always fails to GET would otherwise be re-fetched in full on every poll.
        if self
            .state
            .retry_backoff
            .is_backing_off(id, std::time::Instant::now())
        {
            debug!(
                channel = self.channel(),
                dataset = id,
                "download is in a transient-failure backoff window; skipping this poll"
            );
            return;
        }
        let download = match self.download_package(id).await {
            Ok(p) => p,
            Err(e) => {
                // Transient download failure: stay pending, retry next reconcile. Counted
                // per bucket, since the listing succeeded and advanced poll-success, which
                // makes "lists fine but downloads fail" otherwise invisible.
                crate::metrics::s3_download_error(self.channel());
                // Record it against the same backoff the ingest path uses, so a
                // persistently-failing download is paced by the capped-exponential window
                // instead of hot-looping. Cleared by the first success.
                let attempts = self
                    .state
                    .retry_backoff
                    .record_failure(id, std::time::Instant::now());
                warn!(channel = self.channel(), dataset = id, error = %e, attempts, "S3 package download failed (transient)");
                return;
            }
        };
        // Publish a `processing` writeback for the upload about to be ingested.
        self.writeback_processing(id, etag).await;
        let enqueued = self
            .runtime
            .enqueue_s3_tar_c4gh(
                id.to_owned(),
                download,
                etag.to_owned(),
                self.channel().to_owned(),
                crate::ingest_runtime::S3Enqueue {
                    store: self.store.clone(),
                    sidecar_key,
                    traceparent,
                },
            )
            .await;
        if enqueued {
            // Track that this monitor is ingesting `id`, so a later reconcile that sees its
            // package vanish mid-ingest can record the deletion; the id is not yet in the
            // status index. Pruned when the ingest finishes (see `apply_removed`).
            self.ingesting_lock().insert(id.to_owned());
            info!(
                channel = self.channel(),
                dataset = id,
                "enqueued S3 package for ingest"
            );
        }
    }

    /// Record an oversize `.tar.c4gh` as a permanent `unsafe-archive` error without
    /// downloading it: the encrypted object already exceeds `max_package_bytes`, so it is
    /// refused before it can fill `.incoming/`. Mirrors the ingest worker's
    /// `on_permanent_error` recording, with a path-free audit line, the permanent-outcome
    /// metric and an `Error` status entry keyed to this `ETag`, so the rejection is
    /// observable and is not re-evaluated every poll. A changed `ETag` clears it, as it does
    /// any other recorded error.
    fn reject_oversize_package(&self, id: &str, etag: &str, size: u64, cap: u64) {
        let class = ErrorClass::UnsafeArchive;
        let class_str = class.as_str();
        warn!(
            channel = self.channel(),
            dataset = id,
            size,
            cap,
            error_class = class_str,
            "rejected: package exceeds max_package_bytes; not downloaded"
        );
        // Mutation audit trail carrying the path-free sanitized class, mirroring the worker.
        crate::audit::dataset_state_change(
            &self.state.config.audit,
            id,
            self.channel(),
            "error",
            class_str,
        );
        // Permanent ingest outcome, labelled with the same closed `error_class` the
        // extract-time size-cap violation uses, so an operator sees one `unsafe-archive`
        // class whether a package is refused here or at extraction. Matches the emission in
        // `ingest_runtime::on_permanent_error`.
        ::metrics::counter!(
            metrics::INGEST_TOTAL,
            "outcome" => "permanent",
            "error_class" => class_str.to_owned(),
        )
        .increment(1);
        // Record the `Error` state keyed to this upload's `ETag`, preserving any
        // previously-recorded channel, so the next reconcile does not re-evaluate the same
        // package and the published `_status/{id}.json` reflects the rejection.
        let mut status = self.status_lock();
        let channel = status
            .get(id)
            .map_or_else(|| self.channel().to_owned(), |e| e.channel.clone());
        // Preserve any previously-recorded writer provenance, as `channel` is preserved: a
        // failed re-presentation must not erase what the last successful ingest recorded
        // about who wrote the package. `Unknown` when there is no prior ingest to inherit
        // from.
        let provenance = status
            .get(id)
            .map_or(DatasetProvenance::Unknown, |e| e.provenance.clone());
        status.insert(
            id.to_owned(),
            StatusEntry {
                state: DatasetState::Error,
                error_message: Some(class),
                channel,
                last_seen_signature: Some(etag.to_owned()),
                provenance,
            },
        );
        self.persist(status);
    }

    /// State-changed: re-fetch the sidecar and flip visible or hidden in the cache and
    /// status index, with no re-download. Any other value is logged, ignored, and treated as
    /// hidden.
    async fn apply_state_change(&self, id: &str, listing: &Listing) {
        // The state being transitioned from, captured before the async sidecar GET below.
        // `desired` is resolved from a point-in-time sidecar read, so if a concurrent
        // authoritative writer such as an operator hide, a delete tombstone or a hydrate
        // re-seed changes the state during the GET, applying the stale `desired` would
        // clobber it and re-disclose a just-hidden dataset on the public plane.
        let before = self.state.cache.get(id).map(|e| e.state);
        // Resolve the desired visibility with an async S3 GET before taking the status lock:
        // it is a std `Mutex` and must never be held across an `.await`.
        let desired = match listing.sidecars.get(id) {
            Some(key) => self.fetch_state(id, key).await,
            // No sidecar present means hidden, the fail-safe default.
            None => DatasetState::Hidden,
        };
        // Re-ask operator authority at the moment of publish, as every other
        // suppression-versus-reconcile seam does. `apply_package`'s gate is not sufficient on
        // its own, because it runs before the awaited sidecar GET above. A `dataset hide`
        // landing inside that window is missed by the gate, and the compare-and-swap below
        // compares cache state, which a suppression need not move: for an id already Hidden
        // whose sidecar now says Visible, the swap passes and `set_state(id, Visible)`
        // re-exposes a dataset the operator just took down. The suppression set is keyed on
        // operator intent rather than on a state transition, so it catches that.
        //
        // Lock order: suppressions before status, the invariant
        // `AppState::hydrate_cache_from_disk` states and `apply_suppressions_to_cache`
        // documents in full; inverting it deadlocks the node. Both guards are acquired here,
        // in that order, and no `.await` occurs while either is live.
        let suppressions = self
            .state
            .suppressions
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let desired = suppressions.publishable_state(id, self.channel(), desired);
        // Apply the cache write and the status write under a single lock hold, so a
        // concurrent reload cannot interleave between them and clobber the cache back to the
        // stale snapshot state, which for a visible-to-hidden flip would briefly re-expose a
        // just-hidden dataset on the public plane. The reload's disk walk is lock-free, but
        // the half that writes the cache, `cache::apply_scan`, runs under this lock, and the
        // compare-and-swap below re-reads the cache while holding it, so a reload landing
        // during the sidecar GET is caught rather than merged. No `.await` occurs while the
        // guard is held.
        let mut status = self.status_lock();
        // Compare-and-swap precondition: if the cache state moved since `before` was read,
        // a concurrent authoritative write raced the sidecar GET, so drop this stale flip and
        // let the next reconcile re-read the sidecar. The read is consistent because the
        // status lock held here serializes every authoritative writer, which the compiler
        // enforces: `MetadataCache::set_state` takes a `StatusWrite` proof-of-lock, minted
        // from the held guard via `StatusWrite::held`, so a writer that skips the lock does
        // not compile.
        if self.state.cache.get(id).map(|e| e.state) != before {
            return;
        }
        if !self
            .state
            .cache
            .set_state(StatusWrite::held(&status), id, desired)
        {
            return;
        }
        if let Some(e) = status.get(id).cloned()
            && e.state != desired
        {
            status.insert(
                id.to_owned(),
                StatusEntry {
                    state: desired,
                    ..e
                },
            );
            self.persist(status);
            info!(
                event.action = "dataset.state.change",
                channel = self.channel(),
                dataset = id,
                state = %desired,
                "state changed from bucket sidecar"
            );
            // Mutation audit trail: a visibility transition driven by the bucket
            // `.state.json` sidecar. It is governance-relevant, so it must leave a record,
            // and a release additionally raises an alarm because the sidecar carries no
            // writer identity.
            crate::audit::sidecar_state_change(
                &self.state.config.audit,
                id,
                self.channel(),
                desired,
            );
        }
    }

    /// Fetch, parse, and apply or revert a `{id}.metadata.json` overlay from the bucket.
    /// Cache-only: it does not write `_status/{id}.json` or the `.status.json` index. The
    /// node never writes `{id}.metadata.json` back, since it is operator-owned.
    ///
    /// * `Some(key)` — fetches the body, parses it as [`MetadataOverlay`], merges and
    ///   validates it over the baseline, and updates the cache on success. A parse or fetch
    ///   error is warned and the last-good overlay is kept, with no cache mutation.
    /// * `None` — if a durable overlay file exists on disk, reverts to baseline.
    ///
    /// A node-local operator override ([`AppState::local_overlay_present`]) skips both
    /// branches: the bucket sidecar is never applied over it, and its durable overlay is
    /// never reverted just because the bucket carries no `{id}.metadata.json`. While the
    /// override stands, `AppState::enforce_local_overlays` alone governs that id's overlay,
    /// so no bucket write is needed to make this branch stand aside.
    async fn apply_overlay_change(&self, id: &str, listing: &Listing) {
        let span = tracing::info_span!("overlay_apply", channel = self.channel(), dataset = id);
        tracing::Instrument::instrument(self.apply_overlay_change_inner(id, listing), span).await;
    }

    /// The body of [`Self::apply_overlay_change`], split out so the overlay span can wrap it.
    #[expect(
        clippy::disallowed_methods,
        reason = "the advertised size is checked against MAX_CONTROL_OBJECT_BYTES in the arm above"
    )]
    async fn apply_overlay_change_inner(&self, id: &str, listing: &Listing) {
        if self.state.local_overlay_present(id) {
            debug!(
                channel = self.channel(),
                dataset = id,
                "skipped: node-local metadata override takes precedence over the bucket sidecar"
            );
            return;
        }
        let data_dir = &self.state.config.service.data_dir;
        if let Some(key) = listing.overlays.get(id) {
            let bytes = match self.store.get(key).await {
                // Reject an oversized overlay object by its GET-reported size before
                // buffering the body, since a multi-GB `<id>.metadata.json` would otherwise
                // OOM the process. The last-good metadata is kept.
                Ok(r) if r.meta.size > crate::ingest_runtime::MAX_CONTROL_OBJECT_BYTES => {
                    warn!(
                        channel = self.channel(),
                        dataset = id,
                        size = r.meta.size,
                        cap = crate::ingest_runtime::MAX_CONTROL_OBJECT_BYTES,
                        "rejected: .metadata.json exceeds the control-object size cap (keeps last-good)"
                    );
                    self.state.note_overlay_error(id, self.channel(), "fetch");
                    return;
                }
                Ok(r) => match r.bytes().await {
                    Ok(b) => b,
                    Err(e) => {
                        warn!(channel = self.channel(), dataset = id, error = %e, "fetching .metadata.json body failed (keeps last-good)");
                        self.state.note_overlay_error(id, self.channel(), "fetch");
                        return;
                    }
                },
                Err(e) => {
                    warn!(channel = self.channel(), dataset = id, error = %e, "fetching .metadata.json failed (keeps last-good)");
                    self.state.note_overlay_error(id, self.channel(), "fetch");
                    return;
                }
            };
            let patch: MetadataOverlay = match serde_json::from_slice(&bytes) {
                Ok(p) => p,
                Err(e) => {
                    warn!(channel = self.channel(), dataset = id, error = %e, "ignored: invalid .metadata.json (keeps last-good)");
                    self.state.note_overlay_error(id, self.channel(), "parse");
                    return;
                }
            };
            // Offload the baseline read, validation and durable write to the blocking pool:
            // `overlay::apply` does synchronous `std::fs` I/O that must not run on the async
            // reactor, as with the durable-probe offload in `reconcile`.
            let data_dir_owned = data_dir.clone();
            let id_owned = id.to_owned();
            let applied = tokio::task::spawn_blocking(move || {
                overlay::apply(&data_dir_owned, &id_owned, &patch)
            })
            .await;
            match applied {
                Ok(Ok(applied)) => {
                    // Through the shared funnel, so this channel emits the same correction
                    // audit line as the inbox and operator paths.
                    self.state.adopt_applied_overlay(
                        id,
                        applied,
                        crate::state::OverlaySource::Bucket,
                        Some(self.channel()),
                    );
                }
                Ok(Err(e)) => {
                    warn!(channel = self.channel(), dataset = id, error = %e, "ignored: .metadata.json failed validation (keeps last-good)");
                    self.state
                        .note_overlay_error(id, self.channel(), "validate");
                }
                Err(e) => {
                    warn!(channel = self.channel(), dataset = id, error = %e, "overlay apply task failed (keeps last-good)");
                    self.state
                        .note_overlay_error(id, self.channel(), "validate");
                }
            }
        } else {
            // No overlay object: revert if a durable one is present on disk. The presence
            // probe and the revert are synchronous `std::fs` calls, so run them off the
            // async reactor.
            let data_dir_owned = data_dir.clone();
            let id_owned = id.to_owned();
            let reverted = tokio::task::spawn_blocking(move || {
                overlay::read_durable(&data_dir_owned, &id_owned)
                    .is_some()
                    .then(|| overlay::revert(&data_dir_owned, &id_owned))
            })
            .await;
            match reverted {
                // `modified` is the retained high-water mark, so a revert never moves the
                // dataset's `dct:modified` backward.
                Ok(Some(Ok((baseline, modified)))) => {
                    self.set_overlay_in_cache(id, baseline, modified);
                }
                Ok(Some(Err(e))) => {
                    warn!(channel = self.channel(), dataset = id, error = %e, "overlay revert failed");
                }
                Ok(None) => {} // no durable overlay present, nothing to revert
                Err(e) => {
                    warn!(channel = self.channel(), dataset = id, error = %e, "overlay revert task failed");
                }
            }
        }
    }

    /// Patch `entry.metadata` and `entry.metadata_modified` in the cache for `id`.
    ///
    /// Cache-only: visibility state, the `.status.json` index and the `_status/{id}.json`
    /// writeback are untouched, because an overlay change is metadata-only and must not
    /// disturb the ingest and state machinery.
    fn set_overlay_in_cache(&self, id: &str, metadata: ManifestMetadata, modified: Option<String>) {
        let applied = modified.is_some();
        // An overlay applied or reverted cleanly clears any prior reject.
        self.state.clear_overlay_error(id);
        // Atomic in-place edit (see `MetadataCache::set_metadata`): a get, clone and insert
        // here could clobber a concurrent `set_state` flip and re-disclose a hidden id.
        if self.state.cache.set_metadata(id, metadata, modified) {
            // Mutation audit trail: an operator `{id}.metadata.json` overlay changed the
            // served governance fields such as licence, legal basis and access rights. Gated
            // on the changed flag so the idempotent per-poll reconcile does not flood the
            // trail, matching the visibility and delete paths.
            crate::audit::dataset_state_change(
                &self.state.config.audit,
                id,
                self.channel(),
                if applied {
                    "OverlayApplied"
                } else {
                    "OverlayReverted"
                },
                "metadata-overlay",
            );
        }
    }

    /// Download the bucket's `{id}.tar.c4gh` to a transient path under
    /// `data_dir/.incoming/`, streaming the body in constant memory.
    ///
    /// # Errors
    ///
    /// Returns an error on any store or filesystem failure. The caller classifies these as
    /// transient.
    async fn download_package(&self, id: &str) -> Result<PathBuf> {
        // The network leg before the ingest timer, as its own `s3_download{channel}` span.
        let span = tracing::info_span!("s3_download", channel = self.channel(), dataset = id);
        tracing::Instrument::instrument(self.download_package_inner(id), span).await
    }

    /// The body of [`Self::download_package`], split out so the download span can wrap it.
    async fn download_package_inner(&self, id: &str) -> Result<PathBuf> {
        let key = ObjPath::from(format!("{id}{TAR_C4GH_SUFFIX}"));
        let incoming = self.state.config.service.data_dir.join(".incoming");
        // Owner-only: the transient encrypted download lands here on the shared data volume.
        // A cheap mkdir, so the std helper runs on the reactor rather than a private
        // `tokio::fs` variant.
        gdi_node_standalone_core::util::create_private_dir(&incoming)
            .with_context(|| format!("creating {}", incoming.display()))?;
        // Test-only fault point, a no-op unless the `fault-injection` feature is built. A
        // disk-full at the download stage is transient and the poll retries, which is
        // distinct from an `ENOSPC` during the ingest store.
        gdi_node_standalone_core::faults::guard(
            gdi_node_standalone_core::faults::FaultPoint::S3Download,
            id,
        )?;
        let dest = incoming.join(format!("{id}.{}.download.tar.c4gh", rand_suffix()));
        // Any `?` below drops this guard, which unlinks the partial `dest`; otherwise a
        // failed download leaks one partial per poll until the next restart's
        // `reap_incoming`. Disarmed via `keep()` on success only.
        let cleanup = RemoveOnDrop(Some(dest.clone()));

        // Time the network-fetch leg: it runs before the ingest timer, so the fetch slice
        // would otherwise be unmeasured. Recorded only on success below.
        let started = std::time::Instant::now();
        // The one site that may use the unbounded client: a multi-GB `.tar.c4gh` body is
        // legitimately slow and must never be cut off by a request timeout. Every other S3
        // call in this module goes through the bounded `self.store`.
        let result = self
            .package_store
            .get(&key)
            .await
            .with_context(|| format!("GET {key}"))?;
        // The object's authoritative byte length from the GET response metadata, captured
        // before `into_stream` consumes `result`. A `0` means the backend reported no size,
        // so the check is skipped rather than rejecting a legitimately-streamed body.
        let expected_size = result.meta.size;
        let mut stream = result.into_stream();
        #[expect(
            clippy::disallowed_methods,
            reason = "the body is crypt4gh ciphertext, not secret; write it to the \
                      `RemoveOnDrop`-guarded partial under `.incoming/`"
        )]
        let mut file = tokio::fs::File::create(&dest)
            .await
            .with_context(|| format!("creating {}", dest.display()))?;
        // Hard running cap, independent of the listing-reported size. The pre-download
        // filter trusts the listing, but a backend that under-reports a size, or growth
        // between the listing and the GET, would otherwise stream an unbounded body onto
        // shared data volume before any extract-time bound applies. Abort the moment the
        // streamed bytes exceed `max_package_bytes`; the still-armed `cleanup` guard unlinks
        // the partial. `max_package_bytes` is preflight-floored to at least 1, but the
        // `cap > 0` test keeps the guard robust.
        let cap = self.state.config.service.max_package_bytes;
        let mut written: u64 = 0;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.with_context(|| format!("streaming {key}"))?;
            written += chunk.len() as u64;
            if cap > 0 && written > cap {
                anyhow::bail!(
                    "download of {key} exceeded the {cap}-byte package cap (streamed at least {written} bytes); aborting"
                );
            }
            file.write_all(&chunk).await.context("writing download")?;
        }
        file.flush().await.context("flushing download")?;
        // Verify the streamed length against the object's reported size. A transfer cut
        // mid-body would otherwise write a partial `.tar.c4gh` that crypt4gh AEAD rejects as
        // a permanent `DecryptFailed`, turning a transient network truncation into a sticky
        // error that never self-heals until the ETag changes. Failing here surfaces it as a
        // transient error the caller retries on the next poll, with the still-armed `cleanup`
        // guard unlinking the partial. Length is the portable check; a multipart `ETag` is
        // not a content digest, so a body digest would be best-effort at most.
        if expected_size != 0 && written != expected_size {
            anyhow::bail!(
                "truncated download of {key}: wrote {written} bytes, expected {expected_size}"
            );
        }
        crate::metrics::record_s3_download(written, started.elapsed().as_secs_f64());
        cleanup.keep();
        Ok(dest)
    }

    // ---- readiness ----

    /// Run the startup full reconcile for readiness: list, fetch every present dataset's
    /// `.state.json` content with bounded concurrency, load already-ingested metadata, and
    /// start the ingest of new or changed packages in the background.
    ///
    /// Returns once the listing and the bounded sidecar fetch complete. It does not wait for
    /// the background ingest, so a large first load never stalls the readiness probe.
    ///
    /// A channel already suppressed at boot skips this entirely, with no list, download or
    /// fetch, mirroring [`Self::run`]'s in-loop pause. The bucket is marked healthy so an
    /// operator-paused channel does not block `/health/ready`: a pause is a non-error state,
    /// not a poll failure.
    pub async fn reconcile_for_readiness(&self) {
        if self.channel_suppressed() {
            info!(
                channel = self.channel(),
                "channel administratively suppressed; skipping the startup reconcile (no \
                 poll/download/ingest) until `channel unhide` lifts it"
            );
            metrics::channel_suppressed(self.channel(), true);
            self.state
                .readiness
                .set_channel_health(self.channel(), true);
            return;
        }
        let listing = match self.list().await {
            Ok(l) => l,
            Err(e) => {
                warn!(channel = self.channel(), error = %e, "startup S3 listing failed (transient); will retry");
                // S3 stays unhealthy for readiness until a poll succeeds: a startup listing
                // failure must not let the probe report S3 `ok`.
                self.state
                    .readiness
                    .set_channel_health(self.channel(), false);
                metrics::s3_poll_error(self.channel());
                return;
            }
        };

        // Bounded-concurrency fetch of each present dataset's sidecar content, so a node
        // with many datasets becomes ready promptly without a visible-to-hidden flap as
        // sidecars arrive. The fetched value is applied to already-loaded datasets; new ids
        // carry it into their ingest job below.
        let cap = self.state.config.service.ingest_concurrency.max(1);
        let states: HashMap<String, DatasetState> = stream::iter(listing.sidecars.iter())
            .map(|(id, key)| async move { (id.clone(), self.fetch_state(id, key).await) })
            .buffer_unordered(cap)
            .collect()
            .await;

        // The keyspace gate, asked before any visibility is written. A keyspace whose
        // listing is missing owned datasets is a re-point rather than a migration, so its
        // sidecars are not trusted either: one asserting a more visible state would otherwise
        // promote a dataset the gate just declined to trust the listing about. The last-known
        // state is kept, as the last-known data is.
        let gate_authorized = self.removals_authorized(&listing).await;
        if !gate_authorized {
            info!(
                channel = self.channel(),
                "keyspace gate refused this listing; keeping every dataset's last-known \
                 visibility (no startup state flips from an untrusted keyspace)"
            );
        }

        // Apply the fetched visibility to any dataset already loaded from disk, through the
        // same operator-authority gate every other publish seam uses. Writing visibility
        // straight into the cache would let a bucket sidecar re-publish an operator `Hide` on
        // every restart, on the public Beacon and FDP planes, while the suppression file,
        // `gdi_datasets_suppressed` and `_status/{id}.json` all still read "withheld".
        //
        // Lock order: suppressions before status before cache. See `writeback_owned` for the
        // three-thread deadlock the reverse order produces. Ownership is read off the status
        // guard already held rather than through `owning_channel`, which takes that same
        // non-reentrant mutex.
        if gate_authorized {
            let suppressions = self
                .state
                .suppressions
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let status_guard = self.status_lock();
            for (id, &desired) in &states {
                if self.state.cache.get(id).is_none() {
                    continue;
                }
                // Cross-channel ownership, as `apply_package` enforces: a bare
                // `{id}.state.json` dropped in another bucket must not flip a dataset this
                // channel does not own.
                if status_guard
                    .get(id)
                    .is_some_and(|e| e.channel != self.channel())
                {
                    warn!(
                        channel = self.channel(),
                        dataset = id,
                        "skipped startup state flip: dataset id is owned by another channel"
                    );
                    continue;
                }
                let published = suppressions.publishable_state(id, self.channel(), desired);
                let _ = self
                    .state
                    .cache
                    .set_state(StatusWrite::held(&status_guard), id, published);
            }
        }

        // Then run the normal diff: background ingest of new or changed packages, removed
        // eviction, live state flips. It re-fetches sidecars, but the bounded fetch above is
        // what gates readiness. Startup processes removals, catching deletes that happened
        // while the node was down; the periodic loop's marker gating applies only to timer
        // sweeps.
        self.apply_gated(&listing, true, gate_authorized).await;
        self.writeback_owned().await;
        // The startup listing and bounded sidecar fetch succeeded, so S3 is healthy for
        // `/health/ready`.
        self.state
            .readiness
            .set_channel_health(self.channel(), true);
        metrics::s3_poll_success(self.channel());
    }

    /// Run every bucket's startup reconcile concurrently, each under a hard per-bucket
    /// `timeout`, so one unreachable or slow provider bucket cannot block the node from
    /// binding.
    ///
    /// A bucket that exceeds `timeout` is logged, marked unhealthy for `/health/ready`,
    /// metered as a poll error, and skipped; it recovers on its normal poll cadence. At most
    /// `concurrency` reconciles run at once, floored to 1, in a sliding window, so the next
    /// bucket starts as soon as one finishes.
    pub async fn reconcile_all_for_readiness(
        monitors: &[Self],
        timeout: Duration,
        concurrency: usize,
    ) {
        stream::iter(monitors)
            .for_each_concurrent(concurrency.max(1), |monitor| async move {
                if tokio::time::timeout(timeout, monitor.reconcile_for_readiness())
                    .await
                    .is_err()
                {
                    warn!(
                        channel = monitor.channel(),
                        timeout_seconds = timeout.as_secs(),
                        "startup S3 reconcile timed out; marking bucket unhealthy and \
                         proceeding (it retries on its normal poll cadence)"
                    );
                    monitor
                        .state
                        .readiness
                        .set_channel_health(monitor.channel(), false);
                    metrics::s3_poll_error(monitor.channel());
                }
            })
            .await;
    }

    // ---- status writeback (_status/{id}.json) ----

    /// Whether status writeback is active for this bucket: `write_status` is configured and
    /// an earlier `AccessDenied` has not latched it off (see [`Self::put_status`]). Every
    /// `writeback_*` method opens with this gate.
    fn writeback_enabled(&self) -> bool {
        self.bucket.write_status && !self.writeback_disabled()
    }

    /// Publish the current status of every id this channel owns to `_status/`, as an
    /// idempotent overwrite. Best-effort: a denial disables writeback for the bucket after
    /// the first failure.
    async fn writeback_owned(&self) {
        if !self.writeback_enabled() {
            return;
        }
        // Resolve both locks up front and carry plain owned data into the loop: `put_status`
        // is awaited below, and a std guard must not be held across an await point.
        //
        // Operator authority is re-asked at the moment of publish, as every other
        // suppression-versus-reconcile seam does. `apply_suppressions_to_cache` is
        // cache-state-only, so `StatusEntry.state` stays `Visible` for a hidden dataset;
        // serialising it out without consulting the suppression set would tell a provider
        // polling `_status/{id}.json` that the node still serves a dataset the operator took
        // down.
        let owned: Vec<(String, StatusEntry, DatasetState)> = {
            // Lock order: suppressions before status, the invariant
            // `AppState::hydrate_cache_from_disk` states and every site obeys. Inverting it
            // here deadlocks:
            //
            //   T1 hydrate       holds suppressions.read(), waits on status
            //   T2 here          holds status,              waits on suppressions.read()
            //   T3 SIGUSR1       waits on suppressions.write()
            //
            // std's futex `RwLock` refuses a new reader while a writer waits, so T2's read
            // blocks behind T3, which blocks behind T1, which blocks behind T2. The status
            // mutex is then held forever: every ingest publish, every bucket poll,
            // `/datasets/{id}/state` and every status persist hang until the process is
            // restarted.
            let suppressions = self
                .state
                .suppressions
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let status = self.status_lock();
            status
                .entries()
                .iter()
                .filter(|(_, e)| e.channel == self.channel())
                .map(|(id, e)| {
                    let published = suppressions.publishable_state(id, &e.channel, e.state);
                    (id.clone(), e.clone(), published)
                })
                .collect()
        };
        for (id, entry, published) in owned {
            let obj = StatusWriteback {
                schema_version: STATUS_SCHEMA_VERSION,
                id: id.clone(),
                state: published.as_str().to_owned(),
                error_message: entry.error_message.map(|c| c.as_str().to_owned()),
                source_signature: entry.last_seen_signature.clone(),
                updated_at: now_rfc3339(),
            };
            self.put_status(&id, &obj).await;
        }
    }

    /// Write a `processing` status object for `id`, the upload identified by `etag`, before
    /// its ingest. Best-effort.
    async fn writeback_processing(&self, id: &str, etag: &str) {
        if !self.writeback_enabled() {
            return;
        }
        let obj = StatusWriteback {
            schema_version: STATUS_SCHEMA_VERSION,
            id: id.to_owned(),
            state: DatasetState::Processing.as_str().to_owned(),
            error_message: None,
            source_signature: Some(etag.to_owned()),
            updated_at: now_rfc3339(),
        };
        self.put_status(id, &obj).await;
    }

    /// Write a `{"state":"deleted"}` tombstone status object for `id`. Best-effort.
    async fn writeback_deleted(&self, id: &str) {
        if !self.writeback_enabled() {
            return;
        }
        let obj = StatusWriteback {
            schema_version: STATUS_SCHEMA_VERSION,
            id: id.to_owned(),
            state: DELETED_SIDECAR_STATE.to_owned(),
            error_message: None,
            source_signature: None,
            updated_at: now_rfc3339(),
        };
        self.put_status(id, &obj).await;
    }

    /// PUT one `_status/{id}.json` object as an idempotent overwrite. On the first
    /// permission error, disable writeback for the bucket, warn once, and set the
    /// `gdi_s3_status_writeback_disabled{channel}` flag. It never fails an ingest and never
    /// bumps the marker.
    async fn put_status(&self, id: &str, obj: &StatusWriteback) {
        let key = ObjPath::from(format!("{STATUS_PREFIX}{id}.json"));
        let body = match serde_json::to_vec(obj) {
            Ok(b) => b,
            Err(e) => {
                warn!(channel = self.channel(), dataset = id, error = %e, "serializing status object failed");
                return;
            }
        };
        match self.store.put(&key, PutPayload::from(body)).await {
            Ok(_) => debug!(
                channel = self.channel(),
                dataset = id,
                "status writeback ok"
            ),
            Err(
                object_store::Error::PermissionDenied { .. }
                | object_store::Error::Unauthenticated { .. },
            ) => {
                if !self.writeback_disabled.swap(true, Ordering::Relaxed) {
                    warn!(
                        channel = self.channel(),
                        "status writeback denied; disabling writeback for this bucket (grant _status/* PutObject to re-enable)"
                    );
                    // Latch the per-bucket writeback-disabled gauge so an operator sees the
                    // degradation. The label is the operator-facing bucket name, no data.
                    metrics::s3_writeback_disabled(self.channel(), true);
                }
            }
            Err(e) => {
                // Transient PUT failure: best-effort, retried on the next reconcile.
                debug!(channel = self.channel(), dataset = id, error = %e, "status writeback failed (transient)");
            }
        }
    }

    /// Whether writeback has been disabled for this bucket (the
    /// `gdi_s3_status_writeback_disabled{channel}` metric source).
    #[must_use]
    pub fn writeback_disabled(&self) -> bool {
        self.writeback_disabled.load(Ordering::Relaxed)
    }

    // ---- status-index helpers ----

    /// The channel currently recorded as owning `id`, from the status index.
    fn owning_channel(&self, id: &str) -> Option<String> {
        self.status_lock().get(id).map(|e| e.channel.clone())
    }

    /// The last-seen signature recorded for `id`: the S3 `ETag` change-token.
    fn last_seen_signature(&self, id: &str) -> Option<String> {
        self.status_lock()
            .get(id)
            .and_then(|e| e.last_seen_signature.clone())
    }

    /// Record a new last-seen signature for `id` without touching its state.
    fn record_signature(&self, id: &str, etag: &str) {
        let mut status = self.status_lock();
        let next = match status.get(id).cloned() {
            Some(e) => StatusEntry {
                last_seen_signature: Some(etag.to_owned()),
                ..e
            },
            None => StatusEntry {
                state: DatasetState::Hidden,
                error_message: None,
                channel: self.channel().to_owned(),
                last_seen_signature: Some(etag.to_owned()),
                // A signature-only bookkeeping row: no successful ingest has recorded a
                // package header for this id yet.
                provenance: DatasetProvenance::Unknown,
            },
        };
        status.insert(id.to_owned(), next);
        self.persist(status);
    }

    fn status_lock(
        &self,
    ) -> std::sync::MutexGuard<'_, gdi_node_standalone_core::cache::StatusIndex> {
        self.state
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Lock this monitor's in-ingest tracking set.
    fn ingesting_lock(&self) -> std::sync::MutexGuard<'_, HashSet<String>> {
        self.ingesting
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Lock this monitor's cross-poll mass-removal confirmation streaks.
    fn pending_removals_lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, PendingRemoval>> {
        self.pending_removals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Persist the status index via [`AppState::persist_status_index`], which serializes
    /// under the status lock, drops it before the fsync, and skips an out-of-order write so
    /// a reordering cannot regress the durable index.
    fn persist(
        &self,
        status: std::sync::MutexGuard<'_, gdi_node_standalone_core::cache::StatusIndex>,
    ) {
        if let Err(e) = self.state.persist_status_index(status) {
            warn!(channel = self.channel(), error = %e, "failed to persist status index");
        }
    }
}

/// The outcome of reading a `{id}.state.json`: the visibility to serve, and why it was
/// rejected if it was.
///
/// The reason is returned rather than recorded here because this is a free function with no
/// `AppState` handle, and recording a rejection sets two surfaces at once, the counter and
/// the per-id oracle field, via `AppState::note_state_sidecar_error`. Handing the reason back
/// to callers that do hold `AppState` keeps those two from drifting.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SidecarVerdict {
    /// The visibility to serve. `Hidden` for every rejection, the fail-safe default.
    pub state: DatasetState,
    /// `Some(reason)` when a sidecar was present but rejected. `None` when it parsed
    /// cleanly, or when there was simply no sidecar to read.
    pub rejected: Option<crate::metrics::StateSidecarRejectReason>,
}

impl SidecarVerdict {
    /// A clean read of `state`, with nothing to report.
    const fn ok(state: DatasetState) -> Self {
        Self {
            state,
            rejected: None,
        }
    }

    /// A rejected sidecar: always `Hidden`, tagged with `reason`.
    const fn rejected(reason: crate::metrics::StateSidecarRejectReason) -> Self {
        Self {
            state: DatasetState::Hidden,
            rejected: Some(reason),
        }
    }
}

/// Fetch and parse a `{id}.state.json` body into a served visibility, off any `Store` handle
/// rather than only a live `BucketMonitor`, so the S3 publish path can re-read it at publish
/// time instead of trusting a value captured before the download. A sidecar that is missing,
/// oversized, unparseable or unfetchable defaults to `Hidden`.
#[expect(
    clippy::disallowed_methods,
    reason = "the advertised size is checked against MAX_CONTROL_OBJECT_BYTES in the arm below"
)]
pub(crate) async fn fetch_state_from_store(
    store: &Store,
    channel: &str,
    id: &str,
    key: &ObjPath,
) -> SidecarVerdict {
    match store.get(key).await {
        // Reject an oversized control object by its GET-reported size before buffering the
        // body, so a multi-GB `<id>.state.json` cannot OOM the process.
        Ok(result) if result.meta.size > crate::ingest_runtime::MAX_CONTROL_OBJECT_BYTES => {
            warn!(
                channel = channel,
                dataset = id,
                size = result.meta.size,
                cap = crate::ingest_runtime::MAX_CONTROL_OBJECT_BYTES,
                "rejected: .state.json exceeds the control-object size cap; defaulting hidden"
            );
            SidecarVerdict::rejected(crate::metrics::StateSidecarRejectReason::Unreadable)
        }
        Ok(result) => {
            let etag = result.meta.e_tag.clone();
            match result.bytes().await {
                Ok(bytes) => match serde_json::from_slice::<StateSidecar>(&bytes) {
                    Ok(sidecar) => match classify_bucket_sidecar_state(&sidecar.state) {
                        BucketSidecarState::Visible => SidecarVerdict::ok(DatasetState::Visible),
                        BucketSidecarState::Hidden => SidecarVerdict::ok(DatasetState::Hidden),
                        BucketSidecarState::DeletedIgnored => {
                            // On S3, `deleted` is not a delete verb: deletion means removing
                            // the object. Rather than folding it into `hidden` like a typo,
                            // surface it with a warning and a metric so an orchestrator that
                            // reused the inbox delete verb on an S3 channel learns its
                            // deletion did not take effect, and keep the dataset hidden. The
                            // metric counts every poll; the warning fires once per sidecar
                            // version.
                            crate::metrics::s3_deleted_sidecar_ignored(channel);
                            if deleted_sidecar_newly_seen(channel, id, etag.as_deref()) {
                                warn!(
                                    channel = channel,
                                    dataset = id,
                                    "ignored: a `deleted` .state.json is not a delete on \
                                     S3; delete the {id}.tar.c4gh object to remove the \
                                     dataset. Keeping it hidden"
                                );
                            } else {
                                debug!(
                                    channel = channel,
                                    dataset = id,
                                    "still ignoring the `deleted` .state.json (unchanged since the warning)"
                                );
                            }
                            // It has its own counter, `s3_deleted_sidecar_ignored`, and is a
                            // recognised value used wrongly rather than a malformed one, so
                            // it is not also a state-sidecar rejection. Double-counting would
                            // make the rejection series mean two different things.
                            SidecarVerdict::ok(DatasetState::Hidden)
                        }
                        BucketSidecarState::Unrecognized => {
                            info!(
                                channel = channel,
                                dataset = id,
                                value = sidecar.state.as_str(),
                                "ignored: unrecognized bucket sidecar state; defaulting hidden"
                            );
                            SidecarVerdict::rejected(
                                crate::metrics::StateSidecarRejectReason::Unrecognized,
                            )
                        }
                    },
                    Err(e) => {
                        warn!(channel = channel, dataset = id, error = %e, "ignored: unparseable .state.json; defaulting hidden");
                        SidecarVerdict::rejected(
                            crate::metrics::StateSidecarRejectReason::Unreadable,
                        )
                    }
                },
                Err(e) => {
                    warn!(channel = channel, dataset = id, error = %e, "fetching .state.json body failed; defaulting hidden");
                    SidecarVerdict::rejected(crate::metrics::StateSidecarRejectReason::Unreadable)
                }
            }
        }
        // Absence is not a rejection: no sidecar means `hidden`.
        Err(object_store::Error::NotFound { .. }) => SidecarVerdict::ok(DatasetState::Hidden),
        Err(e) => {
            warn!(channel = channel, dataset = id, error = %e, "fetching .state.json failed; defaulting hidden");
            SidecarVerdict::rejected(crate::metrics::StateSidecarRejectReason::Unreadable)
        }
    }
}

/// `(channel, id)` → the `ETag` of the `deleted` sidecar last warned about.
type WarnedDeletedSidecars = Mutex<HashMap<(String, String), Option<String>>>;

/// The `deleted` sidecars already warned about, so a persistent misuse, where the object
/// stays until the provider deletes it, warns once per sidecar version rather than once per
/// poll. Bounded by the number of such sidecars; the metric beside it still counts every
/// poll.
static DELETED_SIDECAR_WARNED: std::sync::LazyLock<WarnedDeletedSidecars> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// Whether this `(channel, id, etag)` `deleted` sidecar has not been warned about yet, or
/// its `ETag` has moved since, recording it as seen.
fn deleted_sidecar_newly_seen(channel: &str, id: &str, etag: Option<&str>) -> bool {
    let mut warned = DELETED_SIDECAR_WARNED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let key = (channel.to_owned(), id.to_owned());
    match warned.get(&key) {
        Some(previous) if previous.as_deref() == etag => false,
        _ => {
            warned.insert(key, etag.map(str::to_owned));
            true
        }
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

    use super::*;
    use std::path::Path;

    fn set(ids: &[&str]) -> std::collections::BTreeSet<String> {
        ids.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn marker_classify_transient_error_is_unknown_not_absent() {
        // A definite `NotFound` is `Absent`; any other error is `Unknown` and is never
        // conflated with absence.
        assert_eq!(
            Marker::classify(Err(object_store::Error::NotFound {
                path: MARKER_KEY.to_owned(),
                source: "gone".into(),
            })),
            Marker::Absent
        );
        assert_eq!(
            Marker::classify(Err(object_store::Error::Generic {
                store: "s3",
                source: "connection reset".into(),
            })),
            Marker::Unknown
        );
    }

    #[test]
    fn marker_gate_ignores_a_transient_head_failure() {
        // Against a known baseline, only a definite change opens the removal gate.
        let base = Marker::Token("e1".to_owned());
        assert!(
            !Marker::Unknown.opens_removal_gate(&base),
            "a transient HEAD failure must not open the removal gate"
        );
        assert!(
            !Marker::Token("e1".to_owned()).opens_removal_gate(&base),
            "unchanged token"
        );
        assert!(
            Marker::Token("e2".to_owned()).opens_removal_gate(&base),
            "a real bump"
        );
        assert!(Marker::Absent.opens_removal_gate(&base), "a real deletion");
        // Fail-safe against an `Unknown` baseline from a failed boot read: any definite
        // observation counts as a change, so a real mutation during the outage is not missed,
        // while an `Unknown` observation still never opens the gate.
        assert!(Marker::Token("e1".to_owned()).opens_removal_gate(&Marker::Unknown));
        assert!(Marker::Absent.opens_removal_gate(&Marker::Unknown));
        assert!(!Marker::Unknown.opens_removal_gate(&Marker::Unknown));
    }

    #[test]
    fn marker_baseline_preserved_across_transient() {
        // Only a definite observation is adopted as the baseline, via `run()`'s `is_known`
        // gate; an `Unknown` must not overwrite a good token.
        assert!(!Marker::Unknown.is_known());
        assert!(Marker::Token("e1".to_owned()).is_known());
        assert!(Marker::Absent.is_known());
    }

    #[test]
    fn due_full_reconcile_survives_an_unknown_marker() {
        // An `Unknown` marker forces `marker_changed = false`, yet a due full poll or an
        // operator trigger must still reconcile, since a missed reconcile would keep serving
        // retracted data.
        assert!(
            should_reconcile(false, false, true),
            "a due full poll reconciles"
        );
        assert!(
            should_reconcile(true, false, false),
            "an operator trigger reconciles"
        );
        assert!(
            should_reconcile(false, true, false),
            "a real marker change reconciles"
        );
        assert!(
            !should_reconcile(false, false, false),
            "nothing due and no change: no reconcile"
        );
    }

    #[test]
    fn bucket_sidecar_state_distinguishes_deleted_from_a_typo() {
        assert_eq!(
            classify_bucket_sidecar_state("visible"),
            BucketSidecarState::Visible
        );
        assert_eq!(
            classify_bucket_sidecar_state("hidden"),
            BucketSidecarState::Hidden
        );
        // `deleted` is not an S3 delete verb: it is called out distinctly so it can be
        // surfaced, never folded into the generic typo path.
        assert_eq!(
            classify_bucket_sidecar_state("deleted"),
            BucketSidecarState::DeletedIgnored
        );
        assert_eq!(
            classify_bucket_sidecar_state("delete"),
            BucketSidecarState::Unrecognized
        );
        assert_eq!(
            classify_bucket_sidecar_state("hiddne"),
            BucketSidecarState::Unrecognized
        );
    }

    /// A pending confirmation, as a prior pass would have left it `separated` ago.
    fn pending(ids: &[&str], streak: u32, separated: Duration) -> HashMap<String, PendingRemoval> {
        let last_advanced = Instant::now()
            .checked_sub(separated)
            .expect("test clock does not underflow");
        ids.iter()
            .map(|id| {
                (
                    (*id).to_owned(),
                    PendingRemoval {
                        streak,
                        last_advanced,
                    },
                )
            })
            .collect()
    }

    /// One marker poll: the minimum separation between two real observations.
    const POLL: Duration = Duration::from_secs(30);
    /// Comfortably longer than [`POLL`]: a genuinely separated observation.
    const LATER: Duration = Duration::from_mins(2);

    #[test]
    fn plan_removals_evicts_a_normal_small_removal_immediately() {
        // A few of many gone on a marker-triggered pass: evict now, no confirmation.
        let (evict, next) =
            plan_removals(&set(&["a"]), 4, &HashMap::new(), true, Instant::now(), POLL);
        assert_eq!(evict, vec!["a".to_owned()]);
        assert!(next.is_empty());
    }

    #[test]
    fn plan_removals_defers_a_suspected_mass_removal_for_confirmation() {
        // A majority gone at once on a marker pass: start a streak rather than evicting.
        let (evict, next) = plan_removals(
            &set(&["a", "b", "c"]),
            4,
            &HashMap::new(),
            true,
            Instant::now(),
            POLL,
        );
        assert!(
            evict.is_empty(),
            "a suspected mass removal must not evict on the first pass"
        );
        assert_eq!(next.get("a").map(|p| p.streak), Some(1));
        assert_eq!(next.get("c").map(|p| p.streak), Some(1));
    }

    #[test]
    fn plan_removals_evicts_a_mass_removal_once_confirmed() {
        // The same absence persists into a second separated marker pass, so it is confirmed
        // and evicted.
        let prior = pending(&["a", "b", "c"], 1, LATER);
        let (mut evict, next) = plan_removals(
            &set(&["a", "b", "c"]),
            4,
            &prior,
            true,
            Instant::now(),
            POLL,
        );
        evict.sort();
        assert_eq!(evict, vec!["a".to_owned(), "b".to_owned(), "c".to_owned()]);
        assert!(next.is_empty());
    }

    /// A second pass that arrives without time separation does not confirm anything.
    ///
    /// `CONFIRM_REMOVAL_POLLS` counts observations, and an observation only means something
    /// if the listing had a chance to change between them: "a truncated listing clears by the
    /// next poll" is a claim about elapsed time, not about how many times someone asked.
    /// Without the separation check, anything able to drive reconciles back to back collapses
    /// a poll-interval window into two immediate calls.
    #[test]
    fn plan_removals_ignores_an_unseparated_second_pass() {
        let prior = pending(&["a", "b", "c"], 1, Duration::from_secs(1));
        let (evict, next) = plan_removals(
            &set(&["a", "b", "c"]),
            4,
            &prior,
            true,
            Instant::now(),
            POLL,
        );
        assert!(
            evict.is_empty(),
            "a burst of passes must not confirm a mass removal"
        );
        assert_eq!(
            next.get("a").map(|p| p.streak),
            Some(1),
            "the pending confirmation is held unchanged, neither advanced nor reset"
        );

        // Once the separation has elapsed, the same state confirms.
        let prior = pending(&["a", "b", "c"], 1, LATER);
        let (evict, _) = plan_removals(
            &set(&["a", "b", "c"]),
            4,
            &prior,
            true,
            Instant::now(),
            POLL,
        );
        assert_eq!(
            evict.len(),
            3,
            "the delay is the only thing that was missing"
        );
    }

    #[test]
    fn plan_removals_full_poll_advances_an_existing_confirmation() {
        // The timer-only safety net, `process_removals = false`, still advances and evicts an
        // already-pending confirmation, so a single bulk-delete marker bump does not wedge
        // waiting for a second marker change that never comes.
        let prior = pending(&["a", "b", "c"], 1, LATER);
        let (evict, next) = plan_removals(
            &set(&["a", "b", "c"]),
            4,
            &prior,
            false,
            Instant::now(),
            POLL,
        );
        assert_eq!(
            evict.len(),
            3,
            "an existing confirmation is advanced by the full poll"
        );
        assert!(next.is_empty());
    }

    #[test]
    fn plan_removals_full_poll_never_starts_a_fresh_confirmation() {
        // A timer-only sweep must not act on a fresh package absence, which may be a
        // truncated listing; only a marker-triggered pass may start a confirmation.
        let (evict, next) = plan_removals(
            &set(&["a", "b", "c"]),
            4,
            &HashMap::new(),
            false,
            Instant::now(),
            POLL,
        );
        assert!(evict.is_empty());
        assert!(next.is_empty());
    }

    #[test]
    fn plan_removals_clears_a_confirmation_when_the_glitch_resolves() {
        // `b` was pending but is present again this pass, so its streak is dropped and a
        // transient listing glitch never evicts.
        let prior = pending(&["a", "b"], 1, LATER);
        let (evict, next) = plan_removals(&set(&["a"]), 4, &prior, false, Instant::now(), POLL);
        assert_eq!(evict, vec!["a".to_owned()]); // a confirmed (1 -> 2)
        assert!(
            !next.contains_key("b"),
            "a resolved glitch clears its streak"
        );
    }

    #[test]
    fn suspect_mass_removal_flags_only_a_large_majority() {
        // A normal unpublish of one or a few of many proceeds.
        assert!(!is_suspect_mass_removal(1, 10));
        assert!(!is_suspect_mass_removal(2, 10));
        // Removing the last dataset of a small bucket is a legitimate single-poll unpublish
        // and is not suspect.
        assert!(!is_suspect_mass_removal(1, 1));
        assert!(!is_suspect_mass_removal(2, 2));
        // A majority of a large owned set vanishing at once is suspect.
        assert!(is_suspect_mass_removal(6, 10));
        assert!(is_suspect_mass_removal(3, 5));
        // An empty bucket has nothing to remove, so it is not suspect.
        assert!(!is_suspect_mass_removal(0, 0));
    }

    #[test]
    fn remove_on_drop_unlinks_partial_unless_kept() {
        let dir = tempfile::tempdir().unwrap();

        // Dropped without `keep()`, as on a mid-stream download failure: the partial is
        // unlinked, so a failing poll does not orphan a `*.download` until restart.
        let partial = dir.path().join("dataset.abc.download.tar.c4gh");
        std::fs::write(&partial, b"partial bytes").unwrap();
        drop(RemoveOnDrop(Some(partial.clone())));
        assert!(!partial.exists(), "guard must unlink the partial on drop");

        // `keep()` on the success path preserves the completed download.
        let complete = dir.path().join("dataset.def.download.tar.c4gh");
        std::fs::write(&complete, b"complete bytes").unwrap();
        RemoveOnDrop(Some(complete.clone())).keep();
        assert!(complete.exists(), "keep() must preserve the file");
    }

    /// Build an `AppState` for the overlay-precedence test below: a `Visible` dataset under
    /// `channel`, with a durable `manifest.json` on disk, since `overlay::apply` and
    /// `overlay::revert` read the baseline from disk rather than from the cache.
    fn state_for_overlay_precedence_test(
        data_dir: &Path,
        override_dir: &Path,
        id: &str,
        catalog: &str,
        channel: &str,
    ) -> AppState {
        std::fs::create_dir_all(data_dir.join(id)).unwrap();
        let toml = format!(
            r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"
override_dir = "{}"

[catalogs]
{catalog} = "Genome of Europe Aggregated Data"

[beacon]
id = "org.test.beacon"
name = "Test Beacon"
"#,
            data_dir.display(),
            override_dir.display(),
        );
        let config = gdi_node_standalone_core::config::ServiceConfig::from_toml_str(&toml).unwrap();
        config.preflight().unwrap();

        let manifest = gdi_node_standalone_core::model::Manifest {
            payload: None,
            metadata: ManifestMetadata {
                dataset_id: id.to_owned(),
                catalog: catalog.to_owned(),
                title: gdi_node_standalone_core::model::LocalizedText::Plain(
                    "Baseline title".to_owned(),
                ),
                description: None,
                access_rights:
                    "http://publications.europa.eu/resource/authority/access-right/PUBLIC"
                        .to_owned(),
                applicable_legislation: vec![
                    "http://data.europa.eu/eli/reg/2018/1725/oj".to_owned(),
                ],
                license: "https://creativecommons.org/licenses/by/4.0/".to_owned(),
                creator: vec![gdi_node_standalone_core::model::Agent {
                    name: "University of Tartu".to_owned(),
                }],
                health_category: vec![
                    "http://data.gdi.eu/core/p2/HealthCategoryHumanGenomic".to_owned(),
                ],
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
            files: Vec::new(),
            internal: gdi_node_standalone_core::model::Internal::default(),
            config: gdi_node_standalone_core::model::ManifestConfig {
                mode: gdi_node_standalone_core::model::DatasetMode::Aggregated,
                block_range: 10_000_000,
                af_source: None,
                af_source_reference: None,
                min_allele_count: 0,
                hide_lower_counts: None,
                assembly: gdi_node_standalone_core::model::Assembly {
                    reference: "GRCh38".to_owned(),
                },
                manifest_version: 1,
                generated_by: "test".to_owned(),
            },
        };
        std::fs::write(
            data_dir.join(id).join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();

        let mut index = gdi_node_standalone_core::cache::StatusIndex::new();
        index.insert(
            id.to_owned(),
            StatusEntry {
                state: DatasetState::Visible,
                error_message: None,
                channel: channel.to_owned(),
                last_seen_signature: None,
                provenance: DatasetProvenance::Unknown,
            },
        );
        let state = AppState::new(config, index, crate::identities::NodeIdentities::empty());
        state.cache.insert(
            gdi_node_standalone_core::cache::StatusWrite::unshared(),
            gdi_node_standalone_core::cache::DatasetEntry {
                id: id.to_owned(),
                metadata: manifest.metadata,
                config: manifest.config,
                state: DatasetState::Visible,
                metadata_modified: None,
            },
        );
        state
    }

    /// `apply_overlay_change` skips an id entirely, never fetching or applying the bucket's
    /// own `{id}.metadata.json`, when a node-local operator override exists for it, even
    /// though a valid bucket sidecar object is present in the listing and the store. The
    /// bucket sidecar must not reclaim an id the operator has corrected node-locally.
    #[tokio::test]
    async fn apply_overlay_change_skips_an_id_with_a_node_local_override() {
        use object_store::memory::InMemory;
        use object_store::path::Path as ObjPath;

        const ID: &str = "GDI-EE-UTARTU-20260409143052837";
        const CATALOG: &str = "gdi-aggregated";
        const BUCKET: &str = "bucket-a";

        let tmp = tempfile::tempdir().unwrap();
        let state = state_for_overlay_precedence_test(
            &tmp.path().join("data"),
            &tmp.path().join("overrides"),
            ID,
            CATALOG,
            BUCKET,
        );
        let runtime = IngestRuntime::start(state.clone());

        // A valid bucket sidecar in the store and listing: without the skip it would apply
        // and change the served title.
        let store: Store = Arc::new(InMemory::new());
        let sidecar_key = ObjPath::from(format!("{ID}.metadata.json"));
        store
            .put(
                &sidecar_key,
                PutPayload::from(br#"{"title":"From the bucket sidecar"}"#.to_vec()),
            )
            .await
            .unwrap();
        let mut overlays = BTreeMap::new();
        overlays.insert(ID.to_owned(), sidecar_key);
        let listing = Listing {
            overlays,
            ..Listing::default()
        };

        let bucket = S3Bucket {
            name: BUCKET.to_owned(),
            ..S3Bucket::default()
        };
        let monitor = BucketMonitor::with_store(store, bucket, state.clone(), runtime);

        // Seed a node-local override for the same id, then reload it into `state`.
        let overlay_dir = gdi_node_standalone_core::overlay_override::overlays_subdir(
            &state.config.service.override_dir_resolved(),
        );
        let patch: MetadataOverlay =
            serde_json::from_str(r#"{"title":"Operator-authored title"}"#).unwrap();
        gdi_node_standalone_core::overlay_override::write_file(&overlay_dir, ID, &patch).unwrap();
        state.reload_local_overlays();

        monitor.apply_overlay_change(ID, &listing).await;

        assert_eq!(
            state.cache.get(ID).unwrap().metadata.title,
            gdi_node_standalone_core::model::LocalizedText::Plain("Baseline title".to_owned()),
            "a node-local override must make apply_overlay_change skip the bucket \
             sidecar entirely; the served title must still be the baseline, not the \
             bucket sidecar's patch"
        );
        assert!(
            state.overlay_error(ID).is_none(),
            "a skip is not a rejection, so no overlay_error should be recorded"
        );
    }
}

/// Which source supplies a bucket's effective S3 credentials.
///
/// Returns `"vault"` for a `[vault].s3_path` override, `"config"` for the resolved
/// `[[s3.buckets]]` values, whether they came from the TOML literal or the
/// `GDI_NODE__S3__BUCKETS__<i>__…` env overlay, or `"anonymous"` when there are no
/// credentials at all and the client skips request signing.
///
/// `"config"` does not distinguish file from env: figment merges the env overlay into the
/// config struct during load, so the provenance is gone by the time this sees a bucket. It
/// therefore reports whether Vault is in play without claiming which non-Vault source won.
///
/// A bucket with only one of the credential pair reports `"config"` rather than
/// `"anonymous"`: that is a misconfiguration the connector rejects as `HalfCredentials`, not
/// an intent to run unauthenticated.
#[must_use]
pub fn credential_source(
    bucket: &S3Bucket,
    overrides: &BTreeMap<String, (String, String)>,
) -> &'static str {
    if overrides.contains_key(&bucket.name) {
        "vault"
    } else if bucket.access_key_id.is_some() || bucket.secret_access_key.is_some() {
        "config"
    } else {
        "anonymous"
    }
}

/// Log the effective credential source for every configured bucket, once at startup.
///
/// This is the diagnostic for the precedence trap: Vault overrides the config values only
/// when `[vault].s3_path` is set. A `[vault]` block present for the node identity or Transit
/// alone supplies no S3 credentials, so a stale env var stays in force. Without this line the
/// only way to learn which credential is live is to watch a request fail.
///
/// It names the source, never a key.
pub fn log_credential_sources(
    config: &ServiceConfig,
    overrides: &BTreeMap<String, (String, String)>,
) {
    let buckets = config
        .s3
        .as_ref()
        .map_or(&[][..], |s3| s3.buckets.as_slice());
    for bucket in buckets {
        info!(
            channel = %bucket.name,
            source = credential_source(bucket, overrides),
            // The prefix decides which objects this channel can see. Without it on an
            // operational surface, a prefix set on the node and not on the writer, or the
            // reverse, presents as "the bucket is empty" with nothing naming the cause.
            // Logged as `bucket/prefix`, the same shape `check-config` prints and
            // `gdi-dataset-tool`'s `target_label` renders, so the two sides compare by eye.
            //
            // The field is named `keyspace`, not `target`. `target` is the tracing target,
            // the field an operator routes the compliance stream on, and an event field of
            // the same name shadows it: the default `LOG_FORMAT=json` writer then emits both
            // and produces a duplicate `target` key. Duplicate object names are undefined in
            // RFC 8259, and some log pipelines reject the document. No event field may be
            // named `target`; `scripts/tests/test_no_event_field_shadows_target.py` pins
            // this.
            keyspace = %format_args!(
                "{}{}",
                bucket.bucket.as_deref().unwrap_or("<unset>"),
                if bucket.prefix.is_empty() {
                    String::new()
                } else {
                    format!("/{}", bucket.prefix.trim_end_matches('/'))
                }
            ),
            "s3 channel target and credential source"
        );
    }
}

#[cfg(test)]
mod nested_key_tests {
    use super::*;

    /// A correctly-named package one path segment below the keyspace this channel polls: the
    /// prefix-desync direction the channel's own listing can see.
    #[test]
    fn a_valid_id_below_our_keyspace_is_recognised_as_a_desync() {
        // What `strip_suffix(TAR_C4GH_SUFFIX)` leaves for `provider-a/GDI-….tar.c4gh`.
        assert_eq!(
            nested_dataset_id("provider-a/GDI-EE-UTARTU-20260409143052837"),
            Some("GDI-EE-UTARTU-20260409143052837"),
            "a writer-side prefix over a valid id is the mistake this exists to name"
        );
        // Deeper nesting is the same mistake.
        assert_eq!(
            nested_dataset_id("a/b/c/GDI-EE-UTARTU-20260409143052837"),
            Some("GDI-EE-UTARTU-20260409143052837")
        );
    }

    /// Junk stays junk. Splitting on the last `/` separates "a valid id in the wrong place"
    /// from "not a dataset id at all". Folding the two together would turn every co-tenant
    /// object in a shared bucket into a false desync warning, and a shared bucket is a
    /// supported topology.
    #[test]
    fn malformed_names_are_not_mistaken_for_a_desync() {
        assert_eq!(nested_dataset_id("provider-a/not-a-dataset-id"), None);
        assert_eq!(nested_dataset_id("backups/2026-08-25/dump"), None);
        // No path segment at all: a plain malformed name at the channel's own root.
        assert_eq!(nested_dataset_id("GDI-EE-BAD"), None);
        // A leading slash leaves an empty parent: malformed, not nested.
        assert_eq!(
            nested_dataset_id("/GDI-EE-UTARTU-20260409143052837"),
            None,
            "an empty parent segment is a malformed key, not a keyspace mismatch"
        );
    }
}

#[cfg(test)]
mod credential_source_tests {
    use super::*;
    use gdi_node_standalone_core::config::S3Bucket;
    use std::collections::BTreeMap;

    fn bucket(name: &str) -> S3Bucket {
        S3Bucket {
            name: name.to_owned(),
            access_key_id: Some("inline-access".to_owned()),
            secret_access_key: Some("inline-secret".to_owned()),
            ..S3Bucket::default()
        }
    }

    #[test]
    fn credential_source_names_where_each_bucket_gets_its_keys() {
        let mut overrides = BTreeMap::new();
        overrides.insert("vaulted".to_owned(), ("a".to_owned(), "s".to_owned()));

        // A Vault override wins over the bucket's own inline values.
        assert_eq!(credential_source(&bucket("vaulted"), &overrides), "vault");
        // Inline or env credentials with no Vault override for this bucket.
        assert_eq!(credential_source(&bucket("plain"), &overrides), "config");
        // Neither: a legitimately public bucket, where the client skips signing.
        let anon = S3Bucket {
            name: "anon".to_owned(),
            access_key_id: None,
            secret_access_key: None,
            ..S3Bucket::default()
        };
        assert_eq!(credential_source(&anon, &overrides), "anonymous");
    }

    #[test]
    fn a_half_populated_bucket_still_reports_config_not_anonymous() {
        // Exactly one of the pair set is a misconfiguration the S3 connector rejects as
        // `HalfCredentials`. It must not read as `anonymous`, which would suggest the
        // operator meant to run unauthenticated.
        let half = S3Bucket {
            name: "half".to_owned(),
            access_key_id: Some("only-access".to_owned()),
            secret_access_key: None,
            ..S3Bucket::default()
        };
        assert_eq!(credential_source(&half, &BTreeMap::new()), "config");
    }
}
