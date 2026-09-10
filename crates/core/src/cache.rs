//! In-memory metadata cache and persistent status index.
//!
//! The state vocabulary these stores record — [`DatasetState`] — is declared in
//! [`crate::state`], not here: it is the node's public contract, and keeping it out of this
//! module is what lets a caller name a state without depending on the machinery.
//!
//! Two distinct stores collaborate:
//!
//! * [`MetadataCache`] — a cheaply-cloneable, in-memory handle holding every
//!   ingested dataset's metadata + config (assembly + `blockRange` for query
//!   planning) + current [`DatasetState`]. It answers Beacon/FDP queries without
//!   touching the filesystem (the service is the sole writer of `datasets/{id}/`
//!   and updates the cache directly from the ingest/reconcile paths).
//! * [`StatusIndex`] — the service-owned, on-disk `datasets/.status.json` mapping
//!   `id -> {state, error_message, channel, last_seen_signature, provenance}`.
//!   It records only what the service must remember and cannot re-derive on restart:
//!   `error` datasets (a failed ingest leaves no `datasets/{id}/`), each id's owning
//!   channel (source), each source's last-seen signature, and the writer-key
//!   [`DatasetProvenance`] recovered from the package header (which the package itself,
//!   once consumed, no longer supplies).
//!
//! `processing` is ephemeral and never persisted: an ingest interrupted by a restart
//! re-queues. [`StatusIndex::store`] drops `processing` entries.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult, ErrorClass};
use crate::model::{ManifestConfig, ManifestMetadata};
use crate::state::DatasetState;

/// The operator tombstone `.state.json` value (`deleted`): an imperative delete command,
/// not a [`DatasetState`], since a deleted dataset is removed and then `404`s. Spelled here
/// once, so the inbox reconcile's sidecar checks and the S3 tombstone writeback cannot
/// drift.
pub const DELETED_SIDECAR_STATE: &str = "deleted";

/// The crypt4gh writer-key provenance recorded for a dataset in the status index: the
/// durable, closed-class form of [`crate::ingest::WriterProvenance`].
///
/// This is proof of possession, not identity. Anyone holding the node's public recipient
/// key can author a package under a fresh writer key, so a recovered fingerprint is not an
/// authenticated producer identity and nothing gates on it. It is persisted rather than
/// only logged, so the record outlives log rotation and a restart and a later producer-key
/// mismatch is answerable from the node itself.
///
/// The four states are exhaustive and mutually exclusive, so the "no fingerprint" cases
/// cannot collapse into one another: a plaintext drop, an unreadable header and a
/// not-yet-ingested bookkeeping row stay distinct on disk and in the API. The node-local
/// detail of why a header would not parse stays in the WARN audit log, neither persisted
/// nor served, mirroring the sanitized `error_message` posture.
///
/// Serialized internally-tagged on `kind` (`recovered` / `plaintext` / `recovery_failed` /
/// `unknown`), so `jq '.[] | select(.provenance.kind == "recovery_failed")'` and the
/// `datasets` subcommand filter on one stable field.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DatasetProvenance {
    /// The package header yielded crypt4gh writer-key fingerprint(s) (`sha256:<hex>`).
    /// Never empty — [`crate::ingest::WriterProvenance::Recovered`] cannot be empty.
    Recovered {
        /// De-duplicated writer-key fingerprints, first-seen order.
        fingerprints: Vec<String>,
    },
    /// The plaintext staging-dir path: no crypt4gh envelope exists, so no writer key can.
    /// Expected and unremarkable for an inbox drop.
    Plaintext,
    /// A `.tar.c4gh` that published (its body decrypted) but whose header yielded no
    /// writer key. Anomalous; the node-local reason is in the WARN audit log, not here.
    RecoveryFailed,
    /// No successful ingest has recorded provenance for this id — e.g. a status row created
    /// by a signature-only reconcile, or a failed ingest with no prior success. Also the
    /// [`Default`], so a status-index entry that predates or omits the field degrades to
    /// this honest "we don't know" rather than failing the whole index load.
    #[default]
    Unknown,
}

impl DatasetProvenance {
    /// The recovered writer-key fingerprints, or an empty slice for the other variants.
    #[must_use]
    pub fn fingerprints(&self) -> &[String] {
        match self {
            Self::Recovered { fingerprints } => fingerprints,
            Self::Plaintext | Self::RecoveryFailed | Self::Unknown => &[],
        }
    }

    /// The `kind` tag as its stable lowercase wire string (for filtering and display).
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Recovered { .. } => "recovered",
            Self::Plaintext => "plaintext",
            Self::RecoveryFailed => "recovery_failed",
            Self::Unknown => "unknown",
        }
    }

    /// Every valid `kind` string, for CLI filter validation and help text.
    pub const KINDS: [&'static str; 4] = ["recovered", "plaintext", "recovery_failed", "unknown"];
}

impl From<&crate::ingest::WriterProvenance> for DatasetProvenance {
    /// Project the ingest-time result onto the durable, closed-class record, dropping the
    /// `Unrecoverable` detail string. That string lives in the WARN log, never on disk.
    fn from(provenance: &crate::ingest::WriterProvenance) -> Self {
        use crate::ingest::WriterProvenance as W;
        match provenance {
            W::Recovered(fingerprints) => Self::Recovered {
                fingerprints: fingerprints.clone(),
            },
            W::Plaintext => Self::Plaintext,
            W::Unrecoverable(_) => Self::RecoveryFailed,
        }
    }
}

/// The per-dataset provenance sidecar filename, written into `datasets/{id}/` at publish.
///
/// The status index (`.status.json`) is the fast, queryable copy; this sidecar is the
/// durable copy beside the data. An inbox dataset's source `.tar.c4gh` is consumed on
/// success, so without the sidecar its writer-key provenance would live only in the index
/// and be irreplaceable if that index were lost. With it, provenance is reconstructible
/// from the dataset directory: see [`StatusIndex::backfill_provenance_from_sidecars`].
pub const PROVENANCE_SIDECAR_FILE: &str = "provenance.json";

/// Durably write `provenance` to `dir/provenance.json` (tmp + fsync + rename).
///
/// # Errors
///
/// [`CoreError::InternalError`] if serialization fails, or [`CoreError::Io`] on write.
pub fn write_provenance_sidecar(dir: &Path, provenance: &DatasetProvenance) -> CoreResult<()> {
    let json = serde_json::to_vec_pretty(provenance).map_err(|e| CoreError::InternalError {
        detail: format!("serializing dataset provenance: {e}"),
    })?;
    crate::util::write_durable_atomic_private(&dir.join(PROVENANCE_SIDECAR_FILE), &json)
        .map_err(CoreError::Io)
}

/// Read `dir/provenance.json`, or `None` when it is absent or unreadable/corrupt.
///
/// Best-effort: a missing or garbled sidecar is a recovery signal, never fatal — the
/// caller falls back to [`DatasetProvenance::Unknown`].
#[must_use]
pub(crate) fn read_provenance_sidecar(dir: &Path) -> Option<DatasetProvenance> {
    let raw = std::fs::read(dir.join(PROVENANCE_SIDECAR_FILE)).ok()?;
    serde_json::from_slice(&raw).ok()
}

/// One entry of the persistent status index (`datasets/.status.json`).
///
/// The JSON keys are `snake_case` to match the on-disk shape exactly:
/// `state` / `error_message` / `channel` / `last_seen_signature` / `provenance`.
/// `error_message` is present only on an `error` entry (omitted otherwise);
/// `last_seen_signature` is the S3 `ETag` or inbox content hash used to detect same-source
/// re-presentations; `provenance` is the writer-key provenance ([`DatasetProvenance`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusEntry {
    /// The service's last-known state. Never `processing` on disk (see
    /// [`StatusIndex::store`]).
    pub state: DatasetState,
    /// Sanitized, closed-class public error class; present only on `error`.
    ///
    /// Typed as [`ErrorClass`] rather than a `String` so a raw literal cannot be written
    /// here and escape the published taxonomy. Persisted as the stable
    /// [`ErrorClass::as_str`] string.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::error::deserialize_lenient_error_class"
    )]
    pub error_message: Option<ErrorClass>,
    /// Owning channel: an S3 bucket's configured `name`, or `inbox` for a local
    /// drop. The dataset's recorded source.
    pub channel: String,
    /// S3 `ETag` (opaque, quoted) or an inbox package's content hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_signature: Option<String>,
    /// The crypt4gh writer-key provenance recorded at ingest (see [`DatasetProvenance`]).
    ///
    /// Every entry the node writes carries an explicit provenance. `#[serde(default)]` is
    /// defence in depth, not legacy support: a hand-edited or truncated entry that omits
    /// the field degrades to [`DatasetProvenance::Unknown`] rather than failing the whole
    /// index load, which would resurrect every `error` marker and drop every channel. It
    /// never maps a written entry to `Unknown`, so the plaintext and recovery-failed
    /// distinction cannot collapse.
    #[serde(default)]
    pub provenance: DatasetProvenance,
}

/// The persistent status index — a `BTreeMap<id, StatusEntry>` serialized to
/// `datasets/.status.json`, written atomically (temp + `rename`).
///
/// Parsing is tolerant of unknown fields (forward-compatible with future
/// additive fields); a missing file loads as an empty index.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StatusIndex {
    entries: BTreeMap<String, StatusEntry>,
}

impl StatusIndex {
    /// Create an empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrow the entries map.
    #[must_use]
    pub fn entries(&self) -> &BTreeMap<String, StatusEntry> {
        &self.entries
    }

    /// Look up one entry by id.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&StatusEntry> {
        self.entries.get(id)
    }

    /// Insert or replace an entry.
    pub fn insert(&mut self, id: String, entry: StatusEntry) {
        self.entries.insert(id, entry);
    }

    /// Remove an entry by id, returning it if present.
    pub fn remove(&mut self, id: &str) -> Option<StatusEntry> {
        self.entries.remove(id)
    }

    /// Restore `Unknown` provenance from each dataset's on-disk `provenance.json` sidecar.
    ///
    /// For every entry whose provenance is [`DatasetProvenance::Unknown`], read the sidecar
    /// under `data_dir/{id}/` and adopt its value when the sidecar records something
    /// concrete. Returns the number of entries upgraded — the caller persists the index
    /// when that is non-zero. This is what makes the writer provenance survive a lost or
    /// partially-rebuilt `.status.json`: the durable copy lives next to the data.
    ///
    /// It never creates an entry for a directory the index has no row for. Channel and
    /// served state are not in the dataset directory, and a synthesized entry with a
    /// placeholder channel would block an S3 bucket's first-claim re-adoption of the id.
    /// Recreating missing rows is the reconcile path's job.
    pub fn backfill_provenance_from_sidecars(&mut self, data_dir: &Path) -> usize {
        let mut upgraded = 0;
        for (id, entry) in &mut self.entries {
            if entry.provenance != DatasetProvenance::Unknown {
                continue;
            }
            let Some(recovered) = read_provenance_sidecar(&data_dir.join(id)) else {
                continue;
            };
            if recovered == DatasetProvenance::Unknown {
                continue;
            }
            entry.provenance = recovered;
            upgraded += 1;
        }
        upgraded
    }

    /// Remove every `error` entry whose class is node-retriable, meaning a config, key or
    /// infrastructure fault a restart may have fixed, and return the removed ids sorted.
    ///
    /// Called once at startup, before the first reconcile. A cleared entry then looks never
    /// seen to the reconcile and is re-ingested from its source, so an operator who fixed
    /// the node's config or key material and restarted no longer has a dataset permanently
    /// branded by the fixed fault. Data-fault errors (`invalid-manifest`,
    /// `invalid-parquet-schema`, `unsafe-archive`) are kept: those need a corrected
    /// package, and re-attempting them every restart is wasted work. Idempotent within a
    /// boot, since a dataset that fails the same way is re-recorded as `error` and not
    /// retried until the next restart. An unrecognized `error_message` string is kept.
    pub fn drain_retriable_errors(&mut self) -> Vec<String> {
        let mut drained: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, entry)| {
                entry.state == DatasetState::Error
                    && entry
                        .error_message
                        .is_some_and(crate::error::ErrorClass::is_node_retriable)
            })
            .map(|(id, _)| id.clone())
            .collect();
        drained.sort();
        for id in &drained {
            self.entries.remove(id);
        }
        drained
    }

    /// Load the index from `path`. A missing file yields an empty index.
    ///
    /// Unknown fields in the JSON are ignored (forward-compatible).
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Io`] if the file exists but cannot be read, or
    /// [`CoreError::InvalidConfig`] if its contents are not valid index JSON.
    pub fn load(path: &Path) -> CoreResult<Self> {
        let raw = match std::fs::read(path) {
            Ok(raw) => raw,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Self::new()),
            Err(err) => return Err(CoreError::Io(err)),
        };
        serde_json::from_slice(&raw).map_err(|err| CoreError::InvalidConfig {
            detail: format!("datasets/.status.json is not valid: {err}"),
        })
    }

    /// Atomically write the index to `path`, **excluding `processing` entries**
    /// (which are ephemeral and never persisted).
    ///
    /// Writes a sibling temp file then `rename`s it over `path`, so a reader never
    /// observes a half-written index. The temp file lives in the same directory as
    /// `path` so the `rename` stays on one filesystem.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Io`] on any filesystem failure, or
    /// [`CoreError::InternalError`] if serialization fails.
    pub fn store(&self, path: &Path) -> CoreResult<()> {
        let json = self.serialize_persisted()?;
        // tmp, fsync, rename, dir fsync: a power loss just after `store` must not truncate
        // or lose the index. It holds state that cannot be re-derived (error markers,
        // channel, last_seen_signature), and losing it resurrects or forgets a dataset.
        crate::util::write_durable_atomic_private(path, &json).map_err(CoreError::Io)
    }

    /// Serialize the persistable entries (excluding ephemeral `Processing` entries) to
    /// pretty JSON bytes — the read-only half of [`Self::store`].
    ///
    /// Split out so a caller holding the index lock can produce the bytes under the lock and
    /// then write and fsync them outside it. The fsync is unbounded on slow storage and must
    /// not be held across the shared status mutex the management plane also locks.
    ///
    /// # Errors
    ///
    /// [`CoreError::InternalError`] if serialization fails.
    pub fn serialize_persisted(&self) -> CoreResult<Vec<u8>> {
        let persisted: BTreeMap<&String, &StatusEntry> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.state != DatasetState::Processing)
            .collect();
        serde_json::to_vec_pretty(&persisted).map_err(|err| CoreError::InternalError {
            detail: format!("serializing status index: {err}"),
        })
    }
}

/// A fully-ingested dataset held in the in-memory cache.
///
/// `config` carries the assembly and `blockRange` needed for query planning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetEntry {
    /// The dataset ID.
    pub id: String,
    /// FDP-public metadata (already merged with any operator overlay).
    pub metadata: ManifestMetadata,
    /// Processing config (assembly + `blockRange`).
    pub config: ManifestConfig,
    /// Current served state.
    pub state: DatasetState,
    /// Overrides `dct:modified` (xsd:dateTime). `Some` when an operator metadata
    /// overlay has been applied (the node-stamped apply time); `None` keeps the
    /// id-derived creation time. See [`crate::overlay_store`].
    pub metadata_modified: Option<String>,
}

/// Proof that the authoritative status-index lock is held while the caller mutates a
/// dataset's visibility.
///
/// The service's single `Mutex<StatusIndex>` serializes every authoritative writer of
/// dataset visibility. This token makes that rule a type: the four visibility mutators
/// ([`MetadataCache::insert`], [`MetadataCache::remove`], [`MetadataCache::set_state`] and
/// [`MetadataCache::set_state_if_changed`]) each take a `StatusWrite`, and the only way to
/// name one is a mint below, so omitting the lock is a compile error. The type is
/// `#[non_exhaustive]` with a private field, so no downstream crate can forge one with a
/// struct literal.
///
/// The bulk entry points [`hydrate_from_disk`] and [`apply_scan`] take the proof too. Both
/// are `pub` and mutate visibility through this module's private `*_inner` bypasses, so
/// without it a downstream caller could re-seed every dataset's state with no lock held.
///
/// # What it does not prove
///
/// [`StatusWrite::held`] borrows a `&MutexGuard<'_, StatusIndex>`, and the type system
/// cannot tell the canonical status mutex from a second `Mutex<StatusIndex>`: they are the
/// same type. Binding the proof to one mutex instance would mean wrapping the canonical
/// lock in a core newtype and routing every locker through it. What the token does give is
/// that a new visibility write cannot be added without *a* held status guard, checked by
/// the compiler, and that every mint is a single greppable call.
///
/// A caller that omits the proof does not compile:
///
/// ```compile_fail
/// let cache = gdi_node_standalone_core::cache::MetadataCache::new();
/// // `remove` now takes a `StatusWrite` proof first — this call is missing it.
/// let _ = cache.remove("GDI-EE-UTARTU-1");
/// ```
///
/// With the proof it compiles:
///
/// ```
/// use gdi_node_standalone_core::cache::{MetadataCache, StatusWrite};
/// let cache = MetadataCache::new();
/// let _ = cache.remove(StatusWrite::unshared(), "GDI-EE-UTARTU-1");
/// ```
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct StatusWrite<'a> {
    /// Ties the proof's lifetime to the guard it was minted from (via [`StatusWrite::held`]),
    /// so a proof cannot outlive the lock it stands for. Zero-sized.
    _lock: std::marker::PhantomData<&'a StatusIndex>,
}

impl<'a> StatusWrite<'a> {
    /// Mint the proof from a held status-index guard: the production path.
    ///
    /// Borrows the guard for `'a`, so the proof cannot outlive the critical section. The
    /// guard's contents are never read; only that it is held matters.
    #[must_use]
    pub fn held(guard: &'a std::sync::MutexGuard<'_, StatusIndex>) -> Self {
        let _ = guard;
        Self {
            _lock: std::marker::PhantomData,
        }
    }

    /// Mint a proof for a context where the status index is not yet shared across threads:
    /// construction before the application state is published to any task, and tests.
    ///
    /// There is no lock to hold because there is no other observer to race, and the caller
    /// asserts that. The name is chosen so a use outside construction or tests stands out.
    /// Production visibility writes hold the real guard and use [`StatusWrite::held`].
    #[must_use]
    pub fn unshared() -> Self {
        Self {
            _lock: std::marker::PhantomData,
        }
    }
}

/// A cheaply-cloneable handle over the shared in-memory dataset cache.
///
/// Cloning shares the same underlying map (an `Arc`), so handles in different
/// tasks observe each other's writes. Backed by a synchronous
/// [`std::sync::RwLock`] so the ingest runtime can call these from
/// `spawn_blocking` / sync contexts cheaply (no guard is held across an `.await`).
#[derive(Debug, Clone, Default)]
pub struct MetadataCache {
    // Entries are stored behind `Arc` so the per-request `visible_datasets()` hot path hands
    // out refcount bumps instead of deep-cloning every visible entry's metadata. In-place
    // mutators use `Arc::make_mut`, which copies only if a reader still holds a clone.
    // `get` and `remove` return an owned `DatasetEntry` for their cold callers.
    inner: Arc<RwLock<HashMap<String, Arc<DatasetEntry>>>>,
}

impl MetadataCache {
    /// Create an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a dataset entry (keyed by [`DatasetEntry::id`]).
    ///
    /// This sets the entry's served state, and a `Visible` entry becomes discoverable at
    /// once, so it is a visibility mutator and takes a [`StatusWrite`] proof of lock. The
    /// status mutex serializes it against every other authoritative writer. `_proof` is
    /// never read; holding the lock is what it stands for.
    pub fn insert(&self, _proof: StatusWrite<'_>, entry: DatasetEntry) {
        self.insert_inner(entry);
    }

    /// The unguarded body of [`Self::insert`], for [`apply_scan`], which takes the proof at
    /// its own public entry. Private, so nothing outside this module can flip visibility
    /// without the token. Mirrors [`Self::set_state_if_changed_inner`].
    fn insert_inner(&self, entry: DatasetEntry) {
        let mut guard = self.write_lock();
        guard.insert(entry.id.clone(), Arc::new(entry));
    }

    /// Look up a dataset by id, cloning the entry out so the lock is released
    /// before the caller uses it.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<DatasetEntry> {
        self.read_lock().get(id).map(|e| e.as_ref().clone())
    }

    /// Return every [`DatasetState::Visible`] dataset as a cheap [`Arc`] clone (a
    /// refcount bump, not a deep copy of each entry's metadata).
    #[must_use]
    pub fn visible_datasets(&self) -> Vec<Arc<DatasetEntry>> {
        self.read_lock()
            .values()
            .filter(|entry| entry.state == DatasetState::Visible)
            .cloned()
            .collect()
    }

    /// Count cached datasets by state without cloning any entry, for the metrics sampler.
    /// Returns `[visible, hidden, processing, error]`. A failed ingest leaves no cache
    /// entry, but a runtime scrub quarantine can set an already-cached dataset to `Error`
    /// in place, so the error slot can be non-zero until the next reload remaps that stale
    /// `Error` to `Hidden`.
    #[must_use]
    pub fn count_by_state(&self) -> [usize; 4] {
        let mut counts = [0usize; 4];
        for entry in self.read_lock().values() {
            let idx = match entry.state {
                DatasetState::Visible => 0,
                DatasetState::Hidden => 1,
                DatasetState::Processing => 2,
                DatasetState::Error => 3,
            };
            counts[idx] += 1;
        }
        counts
    }

    /// The ids of every cached dataset currently in `state`.
    ///
    /// Exists for the metrics sampler's `error` bucket, which must union the cache with the
    /// status index rather than read either alone. A runtime scrub quarantine sets an
    /// already-cached dataset to `Error` here and updates the status index only when an
    /// entry already exists, so a quarantined dataset can be `Error` in the cache and
    /// absent from the index. Counting the two separately would double-count the overlap.
    #[must_use]
    pub fn ids_in_state(&self, state: DatasetState) -> Vec<String> {
        self.read_lock()
            .values()
            .filter(|e| e.state == state)
            .map(|e| e.id.clone())
            .collect()
    }

    /// The ids of every cached dataset, in any state, cloning only the `String` keys rather
    /// than whole entries, for the reconcile, self-test and boot callers that need ids.
    #[must_use]
    pub fn ids(&self) -> Vec<String> {
        self.read_lock().values().map(|e| e.id.clone()).collect()
    }

    /// Whether the cached entry for `id` carries a metadata-overlay stamp more recent than
    /// `stamp`, meaning an overlay landed in the cache after `stamp` was read off disk.
    ///
    /// Exists so [`apply_scan`] can tell a current scan from one an operator overlaid while
    /// it was walking the disk, without cloning the entry or re-reading the overlay files
    /// under the lock. Compares by age rather than lexically: the two stamps can differ in
    /// subsecond precision, which a string compare would order wrongly.
    ///
    /// `false` when the id is not cached (nothing to preserve) or when the cached entry has
    /// no stamp at all.
    #[must_use]
    pub fn metadata_is_newer_than(&self, id: &str, stamp: Option<&str>) -> bool {
        let guard = self.read_lock();
        let Some(cached) = guard.get(id).and_then(|e| e.metadata_modified.as_deref()) else {
            return false;
        };
        match stamp {
            // The scan saw no overlay at all, the cache has one: the cache is ahead.
            None => true,
            Some(scanned) if scanned == cached => false,
            Some(scanned) => {
                match (
                    crate::util::rfc3339_age_seconds(cached),
                    crate::util::rfc3339_age_seconds(scanned),
                ) {
                    // Smaller age = more recent.
                    (Some(cached_age), Some(scanned_age)) => cached_age < scanned_age,
                    // An unparseable stamp on either side: prefer the scan (the disk is the
                    // durable record), matching how the overlay store fails open on its own
                    // formatting rather than withholding.
                    _ => false,
                }
            }
        }
    }

    /// Set the state of an existing dataset, reporting whether the value moved.
    ///
    /// Returns `true` only on a real transition: `false` both when the id is absent and
    /// when it already held `state`. Use this, not [`set_state`](Self::set_state), to gate
    /// a log line, an audit event or a status-index write. Those must fire on a transition,
    /// not on every reconcile pass that re-observes an unchanged value; `set_state`'s
    /// `bool` answers the different question of whether the id was present, and reading it
    /// as a change check emits `dataset_state_change` for every idle dataset on every pass.
    ///
    /// `_proof` is proof of lock, not data: see [`StatusWrite`].
    #[must_use]
    pub fn set_state_if_changed(
        &self,
        _proof: StatusWrite<'_>,
        id: &str,
        state: DatasetState,
    ) -> bool {
        self.set_state_if_changed_inner(id, state)
    }

    /// The unguarded body of [`Self::set_state_if_changed`].
    ///
    /// Private: it is the one door that does not demand proof of the status lock, and it
    /// exists for [`apply_scan`], which takes the proof at its own public entry. Everything
    /// outside this module goes through the public, guard-taking form.
    fn set_state_if_changed_inner(&self, id: &str, state: DatasetState) -> bool {
        let mut guard = self.write_lock();
        match guard.get_mut(id) {
            Some(entry) if entry.state != state => {
                Arc::make_mut(entry).state = state;
                true
            }
            _ => false,
        }
    }

    /// Set the state of an existing dataset. Returns `true` if the id was present.
    ///
    /// The returned `bool` is an existence check, not a change check: it is `true` for a
    /// present id even when `state` equals the value already stored. To gate a log, an
    /// audit event or a persist on a real transition, use
    /// [`set_state_if_changed`](Self::set_state_if_changed) instead.
    ///
    /// `_proof` is never read. It exists so a caller cannot mutate a dataset's visibility
    /// without holding the status-index mutex, which is what serializes every authoritative
    /// writer; a writer that holds no lock reads a value it believes is serialized and can
    /// re-publish an operator-suppressed dataset. See [`StatusWrite`] for what the token
    /// does and does not guarantee.
    ///
    /// Lock order is `suppressions -> status -> cache`. Take the suppression read guard
    /// first if you need one; `erase_dataset` and `writeback_owned` document the
    /// three-thread deadlock the reverse order produces.
    #[must_use]
    pub fn set_state(&self, _proof: StatusWrite<'_>, id: &str, state: DatasetState) -> bool {
        let mut guard = self.write_lock();
        if let Some(entry) = guard.get_mut(id) {
            Arc::make_mut(entry).state = state;
            true
        } else {
            false
        }
    }

    /// Replace an existing dataset's FDP metadata + `dct:modified` override in
    /// place (an operator metadata-overlay apply/revert). Returns `true` if the id
    /// was present.
    ///
    /// Like [`Self::set_state`], this mutates the live entry under the write lock
    /// rather than the get/clone/mutate/insert dance: a concurrent `set_state`
    /// (e.g. a state flip to `Hidden`) can therefore never be lost to a stale
    /// full-entry write-back, which would briefly re-disclose a hidden dataset.
    #[must_use]
    pub fn set_metadata(
        &self,
        id: &str,
        metadata: ManifestMetadata,
        metadata_modified: Option<String>,
    ) -> bool {
        let mut guard = self.write_lock();
        if let Some(entry) = guard.get_mut(id) {
            let entry = Arc::make_mut(entry);
            entry.metadata = metadata;
            entry.metadata_modified = metadata_modified;
            true
        } else {
            false
        }
    }

    /// Remove a dataset by id, returning the removed entry if present.
    ///
    /// Dropping an entry takes it out of [`Self::visible_datasets`], so this is a visibility
    /// mutator and takes a [`StatusWrite`] proof of lock like [`Self::set_state`]. `_proof`
    /// is never read.
    #[must_use]
    pub fn remove(&self, _proof: StatusWrite<'_>, id: &str) -> Option<DatasetEntry> {
        self.remove_inner(id)
    }

    /// The unguarded body of [`Self::remove`], for [`apply_scan`]'s authoritative eviction.
    /// Private, mirroring [`Self::insert_inner`] and [`Self::set_state_if_changed_inner`].
    fn remove_inner(&self, id: &str) -> Option<DatasetEntry> {
        self.write_lock().remove(id).map(Arc::unwrap_or_clone)
    }

    /// Number of cached datasets (any state).
    #[must_use]
    pub fn len(&self) -> usize {
        self.read_lock().len()
    }

    /// Whether the cache holds no datasets.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.read_lock().is_empty()
    }

    fn read_lock(&self) -> std::sync::RwLockReadGuard<'_, HashMap<String, Arc<DatasetEntry>>> {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write_lock(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<String, Arc<DatasetEntry>>> {
        self.inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Re-hydrate the in-memory [`MetadataCache`] from the persisted dataset directories, at
/// startup and as the periodic full-reload safety net.
///
/// The cache lives only in memory, and the Beacon and FDP query paths serve exclusively
/// from it, so after a restart they would be empty until each dataset's source is
/// re-presented. This walks `data_dir` for each `{id}/manifest.json` whose `{id}` is a
/// valid dataset ID, parses the stored manifest, and inserts a [`DatasetEntry`] seeded with
/// the last-known state from `status`.
///
/// State seeding. Visibility comes from the persisted [`StatusIndex`], which already
/// reflects the last sidecar reconcile. The caller then re-runs the inbox scan and S3
/// reconcile, which re-read the channel `{id}.state.json` sidecars and apply any change an
/// operator made while the node was down. An id absent from the index defaults to
/// [`DatasetState::Hidden`], never publicly visible without an explicit sidecar. An `error`
/// dataset normally has no `{id}/` directory and is skipped, but a directory recorded
/// `error` that does have a present, valid `manifest.json` is recovered and served
/// `Hidden`: the manifest only exists after the publish rename, so it proves the store
/// committed and the `error` is stale.
///
/// Suppression-aware seeding. Any id the operator has suppressed
/// ([`SuppressionSet::effective`](crate::suppression::SuppressionSet::effective) is `Some`)
/// is seeded [`DatasetState::Hidden`] in place, overriding the status-index visibility, so
/// it is never observably `Visible`, not even between this walk and the caller's later
/// `enforce_suppressions`. A `Hide` never persists, so without this a re-hydrate would
/// re-disclose it; a `Remove` is seeded `Hidden` here and completed to a full erase by
/// enforce.
///
/// Idempotent: re-running replaces entries in place. A missing `data_dir`, a
/// non-dataset-id entry, a directory without a `manifest.json` (a dataset mid-ingest, whose
/// manifest is written last via temp and rename), and an unparseable manifest are all
/// skipped rather than failing the whole reload.
///
/// Authoritative reconcile. After loading, any cache entry whose dataset directory is no
/// longer present on disk is evicted. Without it an insert-only reload can leave a
/// permanent ghost: a removal clears the cache and purges the status index, but a reload
/// running concurrently re-inserts the still-on-disk id from the stale status snapshot and
/// nothing else ever evicts it, re-disclosing a removed dataset until restart. Eviction
/// keys on directory presence, recorded for every valid dataset-id directory before the
/// manifest is read, so a dataset mid-ingest or with a temporarily unreadable manifest is
/// not evicted. It runs only when `data_dir` was enumerable, so a transient filesystem
/// outage cannot wipe the served set.
///
/// Returns a [`HydrateStats`] with the datasets loaded, the number skipped for a non-benign
/// reason, and the number evicted as stale. A missing manifest is benign and is not counted
/// as skipped.
///
/// Lock poisoning is not a panic path: every lock helper in this module recovers with
/// `PoisonError::into_inner`, so a thread that panicked mid-update degrades to a
/// possibly-torn map rather than taking the process down.
#[must_use]
pub fn hydrate_from_disk(
    data_dir: &Path,
    proof: StatusWrite<'_>,
    status: &StatusIndex,
    cache: &MetadataCache,
    suppressions: &crate::suppression::SuppressionSet,
    orphaned: &dyn Fn(&str) -> bool,
) -> HydrateStats {
    apply_scan(
        &scan_disk(data_dir),
        data_dir,
        proof,
        status,
        cache,
        suppressions,
        orphaned,
    )
}

/// One dataset read off disk by [`scan_disk`], before any decision about how to serve it.
///
/// Carries no `state`: that depends on the status index and the suppression set, which
/// [`apply_scan`] evaluates under their locks. Keeping the decision out of the scan is what
/// the split is for.
#[derive(Debug, Clone)]
pub struct ScannedDataset {
    id: String,
    metadata: ManifestMetadata,
    config: ManifestConfig,
    metadata_modified: Option<String>,
}

/// The result of one lock-free pass over `data_dir`.
#[derive(Debug, Default, Clone)]
pub struct DiskScan {
    datasets: Vec<ScannedDataset>,
    /// Every valid dataset-id directory seen, including ones whose manifest was missing or
    /// unreadable, so a mid-ingest directory is never evicted.
    present_ids: HashSet<String>,
    skipped: usize,
    /// Whether `data_dir` was enumerable at all. A fresh node has no directory yet and must
    /// not read as every dataset having disappeared.
    enumerable: bool,
}

/// Read every dataset directory under `data_dir`, without touching the status index, the
/// suppression set or the cache.
///
/// This is the expensive half of a reload: a `read_dir`, then per dataset a `manifest.json`
/// read, a JSON parse, and an overlay merge that reads more files. Holding the status mutex
/// across it would block the request path for a full disk walk on every reload, and stall
/// the management-plane state oracle, which takes that mutex on every call, once per rescan
/// tick. With the I/O split out, the locks cover only [`apply_scan`]'s in-memory work.
///
/// Deciding `state` later, under the lock, also reads the status index as it is when the
/// entry is inserted rather than as it was when the walk began.
#[must_use]
pub fn scan_disk(data_dir: &Path) -> DiskScan {
    let Ok(entries) = std::fs::read_dir(data_dir) else {
        // No data dir yet, so a fresh node: nothing to load, and not an empty disk.
        return DiskScan::default();
    };
    let mut scan = DiskScan {
        enumerable: true,
        ..DiskScan::default()
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(id) = name.to_str() else { continue };
        // Only real dataset directories: skip `.status.json`, `.incoming/`, `.deleting/`,
        // temp dirs, and anything not matching the dataset-ID pattern.
        if !crate::id::is_valid_dataset_id(id) {
            continue;
        }
        if !entry.path().is_dir() {
            continue;
        }
        // The directory exists, so this id must not be evicted whatever happens with its
        // manifest below. Recorded before the read, so a mid-ingest or unreadable-manifest
        // directory still counts as present.
        scan.present_ids.insert(id.to_owned());
        let manifest_path = entry.path().join("manifest.json");
        let raw = match std::fs::read(&manifest_path) {
            Ok(raw) => raw,
            // A missing manifest is benign and common: mid-ingest, the manifest is written
            // last via temp and rename, so skip it silently. A present but unreadable
            // manifest is a published dataset dropping out of serving with no other signal,
            // so warn and count it.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                tracing::warn!(
                    dataset = %id,
                    error = %e,
                    "manifest.json unreadable on reload; dataset dropped from serving until fixed"
                );
                scan.skipped += 1;
                continue;
            }
        };
        let manifest = match serde_json::from_slice::<crate::model::Manifest>(&raw) {
            Ok(manifest) => manifest,
            // A corrupt, half-written or schema-drifted manifest is skipped rather than
            // failing the reload, but counted and warned: it drops the dataset out of
            // Beacon, FDP and listing until fixed.
            Err(e) => {
                tracing::warn!(
                    dataset = %id,
                    error = %e,
                    "manifest.json failed to parse on reload; dataset dropped from serving until fixed"
                );
                scan.skipped += 1;
                continue;
            }
        };
        let (metadata, metadata_modified) =
            crate::overlay_store::merged_for_hydrate(data_dir, id, manifest.metadata);
        scan.datasets.push(ScannedDataset {
            id: id.to_owned(),
            metadata,
            config: manifest.config,
            metadata_modified,
        });
    }
    scan
}

/// Project a [`scan_disk`] result onto the cache, deciding each dataset's served state from
/// the current status index and suppression set.
///
/// In-memory apart from two cheap `stat`s per candidate, so the caller can hold the status
/// lock across it without stalling the request path.
///
/// Skips any id with a live deletion-intent marker ([`crate::util::is_deleting`]). That
/// marker is written before the status purge and cleared only after the directory removal
/// succeeds, so it spans the window in which an erase is in flight and the directory may
/// still be readable. Without the check, a walk that began before an erase could re-insert
/// the dataset afterwards and re-serve data that was just erased. Because the walk is
/// lock-free, this guard is what replaces the ordering a lock held across the walk gave.
///
/// # Metadata freshness
///
/// `state` is recomputed here from the current status index, so a publish that lands
/// between the scan and this call is respected. `metadata` is whatever the scan read, but
/// an overlay that landed during the scan is detected rather than projected away:
/// [`MetadataCache::metadata_is_newer_than`] compares the cached overlay stamp against the
/// one the scan read, and a newer cached stamp keeps the cache's metadata while this pass
/// still updates `state`. That closes the window without moving the overlay read back under
/// the lock, which is what the split exists to avoid.
///
/// # The orphan input
///
/// `orphaned` answers whether a channel is one the running configuration no longer
/// declares, whose datasets are withheld. The rule lives with the caller, since `core`
/// carries no channel set, and is asked here, inside the projection, because that withhold
/// lives in neither the status index, which keeps the source-declared state, nor the
/// suppression set. A projection that did not ask would re-serve a departed provider's
/// datasets on every walk while every management surface still answered `hidden`.
pub fn apply_scan(
    scan: &DiskScan,
    data_dir: &Path,
    // Proof that the status lock is held, demanded at this public entry so the private
    // `*_inner` writes below cannot be reached from another crate without it. `status` is
    // the index to read from; the proof is what makes writing legitimate.
    _proof: StatusWrite<'_>,
    status: &StatusIndex,
    cache: &MetadataCache,
    suppressions: &crate::suppression::SuppressionSet,
    orphaned: &dyn Fn(&str) -> bool,
) -> HydrateStats {
    if !scan.enumerable {
        return HydrateStats::default();
    }
    let mut loaded = 0;
    for scanned in &scan.datasets {
        let id = scanned.id.as_str();
        if crate::util::is_deleting(data_dir, id) {
            continue;
        }
        let status_entry = status.get(id);
        // The last-known served state; absent means Hidden, never visible without a
        // governing sidecar.
        //
        // A recorded `Error` is not early-skipped. Such an id normally has no published
        // directory, because the failure precedes the atomic store, so the scan never
        // produces a candidate for it. But a crash in the torn window after the publish
        // rename and before the status write can leave a complete, valid directory under an
        // `Error` entry. A present, valid manifest.json exists only after the rename, so it
        // proves the store committed and the `Error` is stale: recover the dataset, served
        // Hidden as the fail-safe default, instead of skipping it forever.
        let recorded = status_entry.map_or(DatasetState::Hidden, |entry| entry.state);
        // The owning channel of this id (default `"unknown"`, matching the enforce path),
        // needed to evaluate an operator suppression.
        let channel = status_entry.map_or("unknown", |entry| entry.channel.as_str());
        // Seed `Hidden`, so the dataset is never observably `Visible`, when any of these
        // holds. Any other recorded state is authoritative.
        //  - an operator suppression (`Hide` or `Remove`) withholds this id. A `Hide` never
        //    persists to the status index, where the entry stays `Visible`, so seeding
        //    `Hidden` here closes the window before the caller's `enforce_suppressions`
        //    runs after the whole walk. A `Remove` is seeded `Hidden` and then completed to
        //    a full erase by `enforce_suppressions`.
        //  - the owning channel is orphaned: withheld, not erased, until the configuration
        //    declares it again.
        //  - the store recorded `Error` and the class predates the publish, so the marker
        //    is stale.
        //
        // That last recovery must be class-aware. Its evidence is that a present, valid
        // manifest.json proves the store committed, which holds only for a class raised
        // before the atomic publish, where a complete directory is the surprising thing.
        // `ScrubFailed` is the opposite: it marks an already-published dataset, so a
        // complete directory and a valid manifest are present by construction and prove
        // nothing about the parquet the sweep found corrupt. Recovering it would demote the
        // quarantine to `Hidden`, which counts as live for `apply_package`, and the
        // untouched bucket sidecar would flip it back to `Visible`, re-serving bit-rotted
        // data with `error_message: scrub-failed` still on the row.
        //
        // The same class test covers a restart: `ScrubFailed` is not node-retriable, so
        // `StatusIndex::drain_retriable_errors` keeps the row and the boot hydrate reaches
        // this branch with the class intact. A quarantine is lifted by the sweep
        // re-verifying and passing, which is also what heals a restored Transit key, never
        // by a restart.
        let recovering_stale_ingest_error = recorded == DatasetState::Error
            && !matches!(
                status_entry.and_then(|entry| entry.error_message),
                Some(crate::error::ErrorClass::ScrubFailed)
            );
        let state = if suppressions.effective(id, channel).is_some()
            || orphaned(channel)
            || recovering_stale_ingest_error
        {
            DatasetState::Hidden
        } else {
            recorded
        };
        // An operator overlay that landed while the scan was walking the disk is newer than
        // what the scan read, so re-seeding metadata here would project it away until the
        // next reload. Keep the cache's metadata in that case and update only `state`,
        // which this pass is authoritative for.
        if cache.metadata_is_newer_than(id, scanned.metadata_modified.as_deref()) {
            // The transition bool is irrelevant here: this pass is not an audit event. The
            // unguarded inner form is safe because the proof of lock was demanded at this
            // function's public entry, so every caller has already minted one.
            let _ = cache.set_state_if_changed_inner(id, state);
            loaded += 1;
            continue;
        }
        cache.insert_inner(DatasetEntry {
            id: scanned.id.clone(),
            metadata: scanned.metadata.clone(),
            config: scanned.config.clone(),
            state,
            metadata_modified: scanned.metadata_modified.clone(),
        });
        loaded += 1;
    }
    // Authoritative reconcile: evict any cache entry whose dataset directory is gone from
    // disk, which a concurrent reload could otherwise leave as a permanent ghost.
    // `data_dir` was enumerable, or the early return above fired, so an empty `present_ids`
    // legitimately means there are no datasets on disk.
    let mut evicted = 0;
    for id in cache.ids() {
        if scan.present_ids.contains(&id) {
            continue;
        }
        // A cache id not seen in the walk is usually a gone directory, but a transient
        // per-entry `read_dir` or `is_dir` error can also omit a still-present directory
        // from `present_ids`, and evicting on that would drop a live dataset from serving
        // until the next reload. Evict only when an explicit stat confirms the directory is
        // absent. An ambiguous stat error leaves the entry in place for this pass.
        let dir = data_dir.join(&id);
        if let Err(e) = std::fs::symlink_metadata(&dir)
            && e.kind() == std::io::ErrorKind::NotFound
            && cache.remove_inner(&id).is_some()
        {
            evicted += 1;
            tracing::info!(
                dataset = %id,
                "reload evicted a cache entry whose dataset directory is gone from disk"
            );
        }
    }
    HydrateStats {
        loaded,
        skipped: scan.skipped,
        evicted,
    }
}

/// Outcome of a [`hydrate_from_disk`] pass.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct HydrateStats {
    /// Datasets successfully loaded into the cache.
    pub loaded: usize,
    /// Dataset directories skipped for a non-benign reason: a present but unreadable or
    /// corrupt `manifest.json`. Each such skip is a published dataset dropping out of
    /// Beacon, FDP and listing until fixed, so the caller surfaces it with a warning and
    /// `gdi_manifest_reload_skipped_total`. A missing manifest is benign and not counted.
    pub skipped: usize,
    /// Cache entries evicted because their dataset directory is no longer present on disk.
    /// This is the authoritative-reconcile safety net that clears a stale ghost entry a
    /// removal could otherwise leave in the cache (see [`hydrate_from_disk`]). Normally 0.
    pub evicted: usize,
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

    #[test]
    fn ids_in_state_sees_a_dataset_quarantined_in_place() {
        // A scrub quarantine sets an already-cached dataset to `Error` in the cache and
        // touches the status index only when an entry already exists. A metrics sampler
        // reading the status index alone would leave such a dataset counted visible or
        // hidden and never in error, so it would vanish from the gauge exactly when it
        // became unservable.
        let cache = MetadataCache::new();
        cache.insert(
            StatusWrite::unshared(),
            entry("ds-visible", DatasetState::Visible),
        );
        cache.insert(
            StatusWrite::unshared(),
            entry("ds-doomed", DatasetState::Visible),
        );
        assert!(cache.ids_in_state(DatasetState::Error).is_empty());

        // The visibility setters demand proof the status lock is held; a test takes it
        // exactly as production does.
        let status_mutex = std::sync::Mutex::new(StatusIndex::new());
        let status = status_mutex.lock().expect("status lock");
        assert!(cache.set_state(StatusWrite::held(&status), "ds-doomed", DatasetState::Error));
        assert_eq!(
            cache.ids_in_state(DatasetState::Error),
            vec!["ds-doomed".to_owned()],
            "an in-place quarantine must be visible to the sampler"
        );
        // And the other states are unaffected.
        assert_eq!(
            cache.ids_in_state(DatasetState::Visible),
            vec!["ds-visible".to_owned()]
        );
    }

    use super::*;
    use crate::model::{Assembly, DatasetMode, Internal, Manifest};
    use crate::suppression::{self, SuppressMode, Suppression, SuppressionSet};

    fn err_entry(class: ErrorClass) -> StatusEntry {
        StatusEntry {
            state: DatasetState::Error,
            error_message: Some(class),
            channel: "handoff".to_owned(),
            last_seen_signature: Some("etag".to_owned()),
            provenance: DatasetProvenance::Unknown,
        }
    }

    #[test]
    fn error_message_is_a_typed_class_persisted_as_its_public_string() {
        // The field is typed so a raw literal cannot reach a live state oracle without
        // passing through `ErrorClass`, where it would be invisible to the taxonomy golden
        // test and absent from the published API docs. A raw string is a compile error.
        let json = serde_json::to_value(err_entry(ErrorClass::ScrubFailed)).unwrap();
        assert_eq!(json["error_message"], serde_json::json!("scrub-failed"));
    }

    #[test]
    fn an_unrecognized_persisted_error_class_is_dropped_without_failing_the_load() {
        // `StatusIndex::load` is a strict `serde_json::from_slice` over the whole file, so
        // one unparseable entry would drop every channel and resurrect every error marker.
        // A hand-edited index, or one written by a newer node that knows a class this build
        // does not, must degrade that one entry and keep the load intact.
        let raw = r#"{"state":"error","error_message":"not-a-real-class","channel":"inbox"}"#;
        let entry: StatusEntry = serde_json::from_str(raw).unwrap();
        // The entry and its `error` state survive; only the unknown class is dropped, so
        // it carries no retriable claim and `drain_retriable_errors` leaves it alone.
        assert_eq!(entry.state, DatasetState::Error);
        assert_eq!(entry.error_message, None);
    }

    #[test]
    fn drain_retriable_errors_removes_node_faults_and_keeps_data_faults() {
        let mut index = StatusIndex::new();
        // Node-side faults a restart may have fixed: drained, so the next reconcile
        // re-ingests them.
        index.insert(
            "GDI-EE-UTARTU-1".to_owned(),
            err_entry(ErrorClass::UnknownCatalog),
        );
        index.insert(
            "GDI-EE-UTARTU-2".to_owned(),
            err_entry(ErrorClass::InternalError),
        );
        index.insert(
            "GDI-EE-UTARTU-3".to_owned(),
            err_entry(ErrorClass::DecryptFailed),
        );
        // Data faults need a corrected package, not a restart, so they must be kept.
        index.insert(
            "GDI-EE-UTARTU-4".to_owned(),
            err_entry(ErrorClass::InvalidManifest),
        );
        index.insert(
            "GDI-EE-UTARTU-5".to_owned(),
            err_entry(ErrorClass::UnsafeArchive),
        );
        // A store-scrub quarantine is a verdict about the bytes already on disk, so a
        // restart cannot change it and must not clear it. Draining the row would let the
        // dataset come back with no recorded error and the first reconcile re-serve data
        // the node had already proven corrupt. The quarantine is lifted by the sweep
        // re-verifying and passing, which also heals a restored Transit key without a
        // restart.
        index.insert(
            "GDI-EE-UTARTU-7".to_owned(),
            err_entry(ErrorClass::ScrubFailed),
        );
        // A visible dataset must never be touched.
        index.insert(
            "GDI-EE-UTARTU-6".to_owned(),
            StatusEntry {
                state: DatasetState::Visible,
                error_message: None,
                channel: "handoff".to_owned(),
                last_seen_signature: Some("etag".to_owned()),
                provenance: DatasetProvenance::Unknown,
            },
        );

        let mut drained = index.drain_retriable_errors();
        drained.sort();
        assert_eq!(
            drained,
            vec![
                "GDI-EE-UTARTU-1".to_owned(),
                "GDI-EE-UTARTU-2".to_owned(),
                "GDI-EE-UTARTU-3".to_owned()
            ]
        );
        // Drained entries are gone; data-fault errors and the visible entry remain.
        assert!(index.get("GDI-EE-UTARTU-1").is_none());
        assert_eq!(
            index.get("GDI-EE-UTARTU-4").unwrap().state,
            DatasetState::Error
        );
        assert_eq!(
            index.get("GDI-EE-UTARTU-5").unwrap().state,
            DatasetState::Error
        );
        assert_eq!(
            index.get("GDI-EE-UTARTU-6").unwrap().state,
            DatasetState::Visible
        );
        // A scrub quarantine must survive the restart intact, class and all, so
        // `apply_scan` can keep the dataset withheld until a scrub passes.
        let quarantined = index
            .get("GDI-EE-UTARTU-7")
            .expect("quarantine must survive");
        assert_eq!(quarantined.state, DatasetState::Error);
        assert_eq!(quarantined.error_message, Some(ErrorClass::ScrubFailed));
    }

    #[test]
    fn drain_retriable_errors_ignores_an_unknown_error_string() {
        // An error_message that is not a known class is kept: only faults positively
        // identified as node-retriable are cleared.
        let mut index = StatusIndex::new();
        let unknown: StatusEntry = serde_json::from_str(
            r#"{"state":"error","error_message":"mystery-future-class","channel":"handoff"}"#,
        )
        .unwrap();
        index.insert("GDI-EE-UTARTU-1".to_owned(), unknown);
        assert!(index.drain_retriable_errors().is_empty());
        assert_eq!(
            index.get("GDI-EE-UTARTU-1").unwrap().state,
            DatasetState::Error
        );
    }

    /// A `datasets/.status.json` example: one visible and one error entry.
    const STATUS_JSON: &str = r#"{
  "GDI-EE-UTARTU-20260409143052837": {
    "state": "visible",
    "channel": "primary",
    "last_seen_signature": "\"3f8a9c1e74b2d05f\""
  },
  "GDI-EE-UTARTU-20260411093000123": {
    "state": "error",
    "error_message": "invalid-manifest",
    "channel": "inbox",
    "last_seen_signature": "sha256:9c1e74b2d05f8a3c6b1e4f0a7d2c9e581a3b5c7d9e0f2a4b6c8d0e1f3a5b7c9d"
  }
}"#;

    fn sample_metadata(id: &str) -> ManifestMetadata {
        ManifestMetadata {
            dataset_id: id.to_owned(),
            catalog: "gdi-aggregated".to_owned(),
            title: crate::model::LocalizedText::Plain("Sample".to_owned()),
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
        }
    }

    fn sample_config() -> ManifestConfig {
        ManifestConfig {
            mode: DatasetMode::Aggregated,
            block_range: 10_000_000,
            af_source: None,
            af_source_reference: None,
            min_allele_count: 0,
            hide_lower_counts: None,
            assembly: Assembly {
                reference: "GRCh38".to_owned(),
            },
            manifest_version: 1,
            generated_by: "test".to_owned(),
        }
    }

    fn entry(id: &str, state: DatasetState) -> DatasetEntry {
        DatasetEntry {
            id: id.to_owned(),
            metadata: sample_metadata(id),
            config: sample_config(),
            state,
            metadata_modified: None,
        }
    }

    /// Write a minimally valid dataset directory that `scan_disk` will pick up.
    fn write_dataset_dir(data_dir: &std::path::Path, id: &str) {
        let dir = data_dir.join(id);
        std::fs::create_dir_all(&dir).unwrap();
        let manifest = crate::model::Manifest {
            payload: None,
            metadata: sample_metadata(id),
            files: Vec::new(),
            internal: crate::model::Internal::default(),
            config: sample_config(),
        };
        std::fs::write(
            dir.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
    }

    /// The race the scan and apply split has to keep closed.
    ///
    /// A walk holding the status mutex would order an erase strictly against it. The walk is
    /// lock-free instead, so an erase can land in the middle of one: the status entry is
    /// purged and the directory removed while a candidate for that id is already sitting in
    /// the scan result. Re-inserting it would re-serve data that was just erased, and leave
    /// a ghost until the next reload.
    ///
    /// The deletion-intent marker closes it: written before the status purge and cleared
    /// only after the removal succeeds, so it spans the whole window.
    #[test]
    fn apply_scan_does_not_resurrect_a_dataset_erased_during_the_walk() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        write_dataset_dir(data_dir, "GDI-EE-UTARTU-20260409143052837");
        let id = "GDI-EE-UTARTU-20260409143052837";

        // A walk that observed the dataset while it was still present.
        let scan = scan_disk(data_dir);
        assert_eq!(scan.datasets.len(), 1, "precondition: the walk saw it");

        // ...and an erase that begins after the walk: intent marker, then status purge.
        crate::util::mark_deleting(data_dir, id).unwrap();
        let status = StatusIndex::new();

        let cache = MetadataCache::new();
        let applied = apply_scan(
            &scan,
            data_dir,
            StatusWrite::unshared(),
            &status,
            &cache,
            &crate::suppression::SuppressionSet::default(),
            &|_| false,
        );

        assert_eq!(applied.loaded, 0, "an erasing dataset must not be loaded");
        assert!(
            cache.get(id).is_none(),
            "re-inserting a dataset whose erasure is in flight re-serves erased data"
        );
    }

    /// The same scan with no erase in flight must still load normally, or the guard above
    /// would be indistinguishable from a broken apply.
    #[test]
    fn apply_scan_loads_a_dataset_that_is_not_being_erased() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let id = "GDI-EE-UTARTU-20260409143052837";
        write_dataset_dir(data_dir, id);

        let scan = scan_disk(data_dir);
        let cache = MetadataCache::new();
        let applied = apply_scan(
            &scan,
            data_dir,
            StatusWrite::unshared(),
            &StatusIndex::new(),
            &cache,
            &crate::suppression::SuppressionSet::default(),
            &|_| false,
        );

        assert_eq!(applied.loaded, 1);
        assert_eq!(
            cache.get(id).map(|e| e.state),
            Some(DatasetState::Hidden),
            "no status entry seeds Hidden: never observably Visible without a sidecar"
        );
    }

    /// An overlay applied while the scan was walking must survive the apply.
    ///
    /// The scan reads metadata off disk with no lock held, so an operator `dataset correct`
    /// can land in between. Re-seeding from the scan would project that overlay away until
    /// the next reload, silently reverting a correction.
    #[test]
    fn apply_scan_keeps_an_overlay_applied_during_the_walk() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let id = "GDI-EE-UTARTU-20260409143052837";
        write_dataset_dir(data_dir, id);

        // A walk that saw the dataset with no overlay.
        let scan = scan_disk(data_dir);
        assert!(scan.datasets[0].metadata_modified.is_none());

        // ...then an operator overlay lands in the cache, stamped now.
        let cache = MetadataCache::new();
        let mut seeded = entry(id, DatasetState::Visible);
        seeded.metadata_modified = Some(crate::util::now_rfc3339());
        let corrected_title =
            crate::model::LocalizedText::Plain("corrected by the operator".to_owned());
        seeded.metadata.title.clone_from(&corrected_title);
        cache.insert(StatusWrite::unshared(), seeded);

        apply_scan(
            &scan,
            data_dir,
            StatusWrite::unshared(),
            &StatusIndex::new(),
            &cache,
            &crate::suppression::SuppressionSet::default(),
            &|_| false,
        );

        assert_eq!(
            cache.get(id).map(|e| e.metadata.title),
            Some(corrected_title),
            "a reload must not revert an overlay that landed while it was walking"
        );
    }

    /// A scan that did read the overlay must still be applied, or a restart would never
    /// load overlays at all.
    #[test]
    fn apply_scan_still_seeds_metadata_when_the_cache_has_no_overlay() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let id = "GDI-EE-UTARTU-20260409143052837";
        write_dataset_dir(data_dir, id);

        let scan = scan_disk(data_dir);
        let cache = MetadataCache::new();
        // Cached, but with no overlay stamp.
        cache.insert(StatusWrite::unshared(), entry(id, DatasetState::Hidden));

        apply_scan(
            &scan,
            data_dir,
            StatusWrite::unshared(),
            &StatusIndex::new(),
            &cache,
            &crate::suppression::SuppressionSet::default(),
            &|_| false,
        );

        assert_eq!(
            cache.get(id).map(|e| e.metadata.title),
            Some(sample_metadata(id).title),
            "with no overlay in the cache the scan is authoritative"
        );
    }

    /// A missing `data_dir` must read as a fresh node, not as every dataset having
    /// disappeared, or the eviction pass clears the whole cache on a transient mount
    /// failure.
    #[test]
    fn a_missing_data_dir_evicts_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let absent = tmp.path().join("not-created");
        let cache = MetadataCache::new();
        cache.insert(
            StatusWrite::unshared(),
            entry("GDI-EE-UTARTU-20260409143052837", DatasetState::Visible),
        );

        let scan = scan_disk(&absent);
        let applied = apply_scan(
            &scan,
            &absent,
            StatusWrite::unshared(),
            &StatusIndex::new(),
            &cache,
            &crate::suppression::SuppressionSet::default(),
            &|_| false,
        );

        assert_eq!(applied.evicted, 0);
        assert!(
            cache.get("GDI-EE-UTARTU-20260409143052837").is_some(),
            "an unreadable data dir must not be read as an empty one"
        );
    }

    #[test]
    fn count_by_state_tallies_each_state() {
        // Each state must land in its own slot: a stubbed array or a dropped increment
        // fails here.
        let cache = MetadataCache::new();
        cache.insert(
            StatusWrite::unshared(),
            entry("GDI-EE-UTARTU-1", DatasetState::Visible),
        );
        cache.insert(
            StatusWrite::unshared(),
            entry("GDI-EE-UTARTU-2", DatasetState::Visible),
        );
        cache.insert(
            StatusWrite::unshared(),
            entry("GDI-EE-UTARTU-3", DatasetState::Hidden),
        );
        cache.insert(
            StatusWrite::unshared(),
            entry("GDI-EE-UTARTU-4", DatasetState::Error),
        );
        // Order is [visible, hidden, processing, error].
        assert_eq!(cache.count_by_state(), [2, 1, 0, 1]);
    }

    #[test]
    fn status_index_parses_spec_example() {
        let index: StatusIndex = serde_json::from_str(STATUS_JSON).unwrap();
        assert_eq!(index.entries().len(), 2);

        let visible = index.get("GDI-EE-UTARTU-20260409143052837").unwrap();
        assert_eq!(visible.state, DatasetState::Visible);
        assert_eq!(visible.channel, "primary");
        assert_eq!(visible.error_message, None);
        assert_eq!(
            visible.last_seen_signature.as_deref(),
            Some("\"3f8a9c1e74b2d05f\"")
        );

        let errored = index.get("GDI-EE-UTARTU-20260411093000123").unwrap();
        assert_eq!(errored.state, DatasetState::Error);
        assert_eq!(errored.channel, "inbox");
        assert_eq!(errored.error_message, Some(ErrorClass::InvalidManifest));
    }

    #[test]
    fn visible_entry_omits_error_message_in_json() {
        let index: StatusIndex = serde_json::from_str(STATUS_JSON).unwrap();
        let visible = index.get("GDI-EE-UTARTU-20260409143052837").unwrap();
        let value = serde_json::to_value(visible).unwrap();
        let obj = value.as_object().unwrap();
        // error_message is omitted (not null) when None.
        assert!(!obj.contains_key("error_message"));
        // The exact snake_case keys are present.
        assert!(obj.contains_key("state"));
        assert!(obj.contains_key("channel"));
        assert!(obj.contains_key("last_seen_signature"));
    }

    #[test]
    fn status_index_round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".status.json");

        let index: StatusIndex = serde_json::from_str(STATUS_JSON).unwrap();
        index.store(&path).unwrap();
        let reloaded = StatusIndex::load(&path).unwrap();
        assert_eq!(index, reloaded);
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    #[serial_test::serial(faults)]
    fn store_fault_keeps_prior_index_and_converges_on_retry() {
        // A durable-write failure during a status-index persist must leave the previous
        // on-disk index intact, since it holds state that cannot be re-derived (error
        // markers, channel, last_seen_signature), and must not be fatal: once the fault
        // clears, a retry persists the new index. Arm on the unique tempdir path so no
        // sibling test's write can match.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".status.json");
        let arm_key = path.to_string_lossy().into_owned();

        // Persist a first, non-empty index (the last-good).
        let v1: StatusIndex = serde_json::from_str(STATUS_JSON).unwrap();
        v1.store(&path).unwrap();
        assert_eq!(StatusIndex::load(&path).unwrap(), v1);

        // Arm the durable-write fault, then try to persist a different, empty index: the
        // write must fail with an I/O error.
        let v2 = StatusIndex::new();
        assert_ne!(v2, v1);
        {
            let _g =
                crate::faults::arm_enospc(crate::faults::FaultPoint::DurableWrite, &arm_key, 1);
            let err = v2.store(&path).unwrap_err();
            std::assert_matches!(err, CoreError::Io(_), "got {err:?}");
        }
        // The prior index is untouched on disk (never truncated to empty or torn).
        assert_eq!(
            StatusIndex::load(&path).unwrap(),
            v1,
            "a failed status persist must keep the prior index"
        );

        // The fault has cleared (guard dropped): a retry persists the new index.
        v2.store(&path).unwrap();
        assert_eq!(
            StatusIndex::load(&path).unwrap(),
            v2,
            "a retry after the fault clears must converge to the new index"
        );
    }

    #[test]
    fn load_missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let index = StatusIndex::load(&dir.path().join("absent.json")).unwrap();
        assert!(index.entries().is_empty());
    }

    #[test]
    fn load_propagates_a_non_notfound_read_error() {
        // Only a NotFound may yield an empty index; any other read error must propagate as
        // `CoreError::Io`. Otherwise a present but unreadable `.status.json` loads as an
        // empty index, discarding error markers, owning channel and last_seen_signature.
        // Pointing `load` at a directory makes `std::fs::read` fail with EISDIR, whose kind
        // is not NotFound, so a match guard that swallowed it would be caught here.
        let dir = tempfile::tempdir().unwrap();
        let as_dir = dir.path().join("status-as-dir");
        std::fs::create_dir(&as_dir).unwrap();
        let err = StatusIndex::load(&as_dir).unwrap_err();
        std::assert_matches!(
            err,
            CoreError::Io(_),
            "a non-NotFound read error must propagate as CoreError::Io, got {err:?}"
        );
    }

    #[test]
    fn store_skips_processing_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".status.json");

        let mut index = StatusIndex::new();
        index.insert(
            "GDI-EE-UTARTU-1".to_owned(),
            StatusEntry {
                state: DatasetState::Visible,
                error_message: None,
                channel: "inbox".to_owned(),
                last_seen_signature: Some("sig".to_owned()),
                provenance: DatasetProvenance::Unknown,
            },
        );
        index.insert(
            "GDI-EE-UTARTU-2".to_owned(),
            StatusEntry {
                state: DatasetState::Processing,
                error_message: None,
                channel: "inbox".to_owned(),
                last_seen_signature: None,
                provenance: DatasetProvenance::Unknown,
            },
        );
        index.store(&path).unwrap();

        let reloaded = StatusIndex::load(&path).unwrap();
        // Processing entry is not persisted.
        assert_eq!(reloaded.entries().len(), 1);
        assert!(reloaded.get("GDI-EE-UTARTU-1").is_some());
        assert!(reloaded.get("GDI-EE-UTARTU-2").is_none());
    }

    #[test]
    fn status_index_remove_returns_entry_and_drops_it() {
        // `StatusIndex::remove` must both return the removed entry and delete it. A body
        // that only returned `None` would leave the entry in the index, and in the
        // persisted bytes, while claiming nothing was there.
        let mut index = StatusIndex::new();
        let entry = StatusEntry {
            state: DatasetState::Visible,
            error_message: None,
            channel: "inbox".to_owned(),
            last_seen_signature: Some("sig".to_owned()),
            provenance: DatasetProvenance::Unknown,
        };
        index.insert("GDI-EE-UTARTU-1".to_owned(), entry.clone());

        let removed = index
            .remove("GDI-EE-UTARTU-1")
            .expect("remove must return the entry that was present");
        assert_eq!(removed, entry, "the returned entry must be the one removed");
        assert!(
            index.get("GDI-EE-UTARTU-1").is_none(),
            "the id must no longer be present after remove"
        );

        // A re-serialized/persisted index omits the removed id.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".status.json");
        index.store(&path).unwrap();
        let reloaded = StatusIndex::load(&path).unwrap();
        assert!(
            reloaded.get("GDI-EE-UTARTU-1").is_none(),
            "the persisted index must not contain the removed id"
        );
    }

    #[test]
    fn serialize_persisted_excludes_processing_and_matches_store_bytes() {
        // `serialize_persisted`, run under the status lock, must produce exactly the bytes
        // `store` writes to disk outside it, and must exclude ephemeral `Processing`
        // entries.
        let mut index = StatusIndex::new();
        index.insert(
            "GDI-EE-UTARTU-1".to_owned(),
            StatusEntry {
                state: DatasetState::Visible,
                error_message: None,
                channel: "inbox".to_owned(),
                last_seen_signature: Some("sig".to_owned()),
                provenance: DatasetProvenance::Unknown,
            },
        );
        index.insert(
            "GDI-EE-UTARTU-2".to_owned(),
            StatusEntry {
                state: DatasetState::Processing,
                error_message: None,
                channel: "inbox".to_owned(),
                last_seen_signature: None,
                provenance: DatasetProvenance::Unknown,
            },
        );

        let bytes = index.serialize_persisted().unwrap();
        let parsed: BTreeMap<String, StatusEntry> = serde_json::from_slice(&bytes).unwrap();
        assert!(parsed.contains_key("GDI-EE-UTARTU-1"));
        assert!(
            !parsed.contains_key("GDI-EE-UTARTU-2"),
            "Processing entry must be excluded from the serialized bytes"
        );

        // The two halves of the split agree: store() writes exactly serialize_persisted().
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".status.json");
        index.store(&path).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }

    #[test]
    fn status_index_tolerates_unknown_fields() {
        let json = r#"{
  "GDI-EE-UTARTU-1": {
    "state": "hidden",
    "channel": "inbox",
    "some_future_field": "tolerated"
  }
}"#;
        let index: StatusIndex = serde_json::from_str(json).unwrap();
        let e = index.get("GDI-EE-UTARTU-1").unwrap();
        assert_eq!(e.state, DatasetState::Hidden);
        assert_eq!(e.last_seen_signature, None);
        // A missing `provenance` degrades one entry to `Unknown`, not a whole-index load
        // failure (defence-in-depth `#[serde(default)]`).
        assert_eq!(e.provenance, DatasetProvenance::Unknown);
    }

    #[test]
    fn status_index_with_future_entry_field_still_loads_from_disk() {
        // The on-disk `load` path, not just `from_str`, tolerates a future additive
        // per-entry field, so a newer node's `.status.json` still loads under an older node.
        // Only additive unknown fields: a removed required field still fails to parse.
        let json = r#"{
  "GDI-EE-UTARTU-1": {
    "state": "visible",
    "channel": "inbox",
    "ingested_at": "2027-01-01T00:00:00Z"
  }
}"#;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".status.json");
        std::fs::write(&path, json).unwrap();

        let index = StatusIndex::load(&path).unwrap();
        assert_eq!(index.entries().len(), 1);
        let e = index.get("GDI-EE-UTARTU-1").unwrap();
        assert_eq!(e.state, DatasetState::Visible);
    }

    #[test]
    fn cache_insert_get_and_visible_filter() {
        let cache = MetadataCache::new();
        assert!(cache.is_empty());

        cache.insert(
            StatusWrite::unshared(),
            entry("GDI-EE-UTARTU-1", DatasetState::Visible),
        );
        cache.insert(
            StatusWrite::unshared(),
            entry("GDI-EE-UTARTU-2", DatasetState::Hidden),
        );
        cache.insert(
            StatusWrite::unshared(),
            entry("GDI-EE-UTARTU-3", DatasetState::Error),
        );
        assert_eq!(cache.len(), 3);

        let got = cache.get("GDI-EE-UTARTU-1").unwrap();
        assert_eq!(got.id, "GDI-EE-UTARTU-1");
        assert_eq!(got.config.assembly.reference, "GRCh38");
        assert_eq!(got.config.block_range, 10_000_000);
        assert!(cache.get("missing").is_none());

        let visible = cache.visible_datasets();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].id, "GDI-EE-UTARTU-1");
    }

    #[test]
    fn cache_set_state_mutates() {
        let cache = MetadataCache::new();
        cache.insert(
            StatusWrite::unshared(),
            entry("GDI-EE-UTARTU-1", DatasetState::Hidden),
        );
        assert!(cache.visible_datasets().is_empty());

        let status_mutex = std::sync::Mutex::new(StatusIndex::new());
        let status = status_mutex.lock().expect("status lock");
        assert!(cache.set_state(
            StatusWrite::held(&status),
            "GDI-EE-UTARTU-1",
            DatasetState::Visible
        ));
        assert_eq!(cache.visible_datasets().len(), 1);

        // Unknown id -> false, no change.
        assert!(!cache.set_state(StatusWrite::held(&status), "missing", DatasetState::Visible));
    }

    #[test]
    fn set_state_if_changed_reports_a_real_transition_not_mere_presence() {
        let cache = MetadataCache::new();
        cache.insert(
            StatusWrite::unshared(),
            entry("GDI-EE-UTARTU-1", DatasetState::Hidden),
        );
        let status_mutex = std::sync::Mutex::new(StatusIndex::new());
        let status = status_mutex.lock().expect("status lock");

        // A genuine move.
        assert!(cache.set_state_if_changed(
            StatusWrite::held(&status),
            "GDI-EE-UTARTU-1",
            DatasetState::Visible
        ));

        // The same value again is not a transition. `set_state` answers whether the id was
        // present, so a caller that logs or audits on its result re-emits on every
        // reconcile pass for an idle dataset, flooding the `dataset_state_change` stream.
        assert!(!cache.set_state_if_changed(
            StatusWrite::held(&status),
            "GDI-EE-UTARTU-1",
            DatasetState::Visible
        ));
        assert!(
            cache.set_state(
                StatusWrite::held(&status),
                "GDI-EE-UTARTU-1",
                DatasetState::Visible
            ),
            "contrast: set_state still reports true for an unchanged but PRESENT id"
        );

        // Absent id is not a transition either.
        assert!(!cache.set_state_if_changed(
            StatusWrite::held(&status),
            "missing",
            DatasetState::Visible
        ));

        // A move back is a transition again.
        assert!(cache.set_state_if_changed(
            StatusWrite::held(&status),
            "GDI-EE-UTARTU-1",
            DatasetState::Hidden
        ));
        assert!(cache.visible_datasets().is_empty());
    }

    #[test]
    fn cache_set_metadata_edits_metadata_in_place_without_touching_state() {
        let cache = MetadataCache::new();
        cache.insert(
            StatusWrite::unshared(),
            entry("GDI-EE-UTARTU-1", DatasetState::Hidden),
        );

        // Apply an overlay: new metadata + a node-stamped `dct:modified`.
        assert!(cache.set_metadata(
            "GDI-EE-UTARTU-1",
            sample_metadata("GDI-EE-UTARTU-1"),
            Some("2026-04-09T14:30:52.837Z".to_owned()),
        ));

        let got = cache.get("GDI-EE-UTARTU-1").unwrap();
        assert_eq!(
            got.metadata_modified.as_deref(),
            Some("2026-04-09T14:30:52.837Z")
        );
        // The visibility state is untouched: an overlay apply edits metadata in place and
        // so cannot clobber a concurrent state flip, which would re-disclose a hidden
        // dataset through a lost update.
        assert_eq!(got.state, DatasetState::Hidden);

        // Unknown id -> false, no insert.
        assert!(!cache.set_metadata("missing", sample_metadata("missing"), None));
        assert!(cache.get("missing").is_none());
    }

    #[test]
    fn cache_remove() {
        let cache = MetadataCache::new();
        cache.insert(
            StatusWrite::unshared(),
            entry("GDI-EE-UTARTU-1", DatasetState::Visible),
        );
        let removed = cache
            .remove(StatusWrite::unshared(), "GDI-EE-UTARTU-1")
            .unwrap();
        assert_eq!(removed.id, "GDI-EE-UTARTU-1");
        assert!(cache.is_empty());
        assert!(
            cache
                .remove(StatusWrite::unshared(), "GDI-EE-UTARTU-1")
                .is_none()
        );
    }

    #[test]
    fn visibility_mutators_require_a_statuswrite_proof() {
        // Every door that changes what `visible_datasets()` returns — insert, remove,
        // set_state, set_state_if_changed — takes a `StatusWrite`. The only ways to mint one
        // are `held(&guard)`, proving the status lock is held, and `unshared()`, for
        // construction and tests where the index is not yet shared. The `compile_fail`
        // doctest on the type pins that a caller omitting the proof does not compile; this
        // test pins the positive half, that both mints reach the mutators.
        let cache = MetadataCache::new();

        // `unshared()` — the construction/test mint.
        cache.insert(
            StatusWrite::unshared(),
            entry("GDI-EE-UTARTU-1", DatasetState::Visible),
        );
        assert_eq!(cache.visible_datasets().len(), 1);

        // `held(&guard)` — the production mint, from an actual held status guard.
        let status_mutex = std::sync::Mutex::new(StatusIndex::new());
        let status = status_mutex.lock().expect("status lock");
        assert!(cache.set_state(
            StatusWrite::held(&status),
            "GDI-EE-UTARTU-1",
            DatasetState::Hidden
        ));
        assert!(cache.visible_datasets().is_empty());
        assert!(
            cache
                .remove(StatusWrite::held(&status), "GDI-EE-UTARTU-1")
                .is_some()
        );
        assert!(cache.is_empty());
    }

    #[test]
    fn cache_handle_is_shared_on_clone() {
        let cache = MetadataCache::new();
        let clone = cache.clone();
        cache.insert(
            StatusWrite::unshared(),
            entry("GDI-EE-UTARTU-1", DatasetState::Visible),
        );
        // The clone observes the original's write (shared Arc).
        assert!(clone.get("GDI-EE-UTARTU-1").is_some());
    }

    /// Write a `{id}/manifest.json` under `data_dir` for a manifest in `state`.
    fn write_published(data_dir: &Path, id: &str) {
        let dir = data_dir.join(id);
        std::fs::create_dir_all(&dir).unwrap();
        let manifest = Manifest {
            payload: None,
            metadata: sample_metadata(id),
            files: Vec::new(),
            internal: Internal::default(),
            config: sample_config(),
        };
        std::fs::write(
            dir.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn hydrate_rebuilds_cache_from_disk_with_index_state() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path();

        // Three published datasets on disk: one visible, one hidden.
        let vis = "GDI-EE-UTARTU-20260409143052837";
        let hid = "GDI-EE-UTARTU-20260409143052838";
        write_published(data_dir, vis);
        write_published(data_dir, hid);

        // A status index recording their last-known states. A third id is recorded
        // `error` with no directory (a failed ingest leaves none).
        let mut status = StatusIndex::new();
        status.insert(
            vis.to_owned(),
            StatusEntry {
                state: DatasetState::Visible,
                error_message: None,
                channel: "inbox".to_owned(),
                last_seen_signature: Some("sig".to_owned()),
                provenance: DatasetProvenance::Unknown,
            },
        );
        status.insert(
            hid.to_owned(),
            StatusEntry {
                state: DatasetState::Hidden,
                error_message: None,
                channel: "inbox".to_owned(),
                last_seen_signature: Some("sig".to_owned()),
                provenance: DatasetProvenance::Unknown,
            },
        );
        status.insert(
            "GDI-EE-UTARTU-20260409143052999".to_owned(),
            StatusEntry {
                state: DatasetState::Error,
                error_message: Some(ErrorClass::InvalidManifest),
                channel: "inbox".to_owned(),
                last_seen_signature: Some("sig".to_owned()),
                provenance: DatasetProvenance::Unknown,
            },
        );

        let cache = MetadataCache::new();
        let loaded = hydrate_from_disk(
            data_dir,
            StatusWrite::unshared(),
            &status,
            &cache,
            &SuppressionSet::default(),
            &|_| false,
        )
        .loaded;

        // Both on-disk datasets loaded; the error id (no dir) is not.
        assert_eq!(loaded, 2);
        assert_eq!(cache.len(), 2);

        // State is seeded from the index: the visible one is served, the hidden one
        // is cached-but-not-visible.
        let visible = cache.visible_datasets();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].id, vis);
        assert_eq!(cache.get(hid).unwrap().state, DatasetState::Hidden);

        // The metadata + config round-tripped from the stored manifest.
        let e = cache.get(vis).unwrap();
        assert_eq!(e.metadata.dataset_id, vis);
        assert_eq!(e.config.assembly.reference, "GRCh38");
        assert_eq!(e.config.block_range, 10_000_000);
    }

    #[test]
    fn hydrate_seeds_a_hide_suppressed_id_hidden_never_visible() {
        // A `hide`-suppressed dataset leaves the status index recording it `Visible`,
        // because a Hide never persists to `.status.json`. A suppression-blind hydrate
        // would re-seed it `Visible` and leave it disclosed until the caller's
        // `enforce_suppressions` re-hid it after the whole walk returned, reopening that
        // window on every rescan. The hydrate must seed it `Hidden` in place.
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path();
        let id = "GDI-EE-UTARTU-20260409143052837";
        write_published(data_dir, id);
        let mut status = StatusIndex::new();
        status.insert(
            id.to_owned(),
            StatusEntry {
                state: DatasetState::Visible,
                error_message: None,
                channel: "inbox".to_owned(),
                last_seen_signature: Some("sig".to_owned()),
                provenance: DatasetProvenance::Unknown,
            },
        );

        // The operator suppression store withholds this id as `Hide`.
        let sup_dir = data_dir.join("suppressions");
        suppression::write_file(
            &sup_dir,
            id,
            &Suppression {
                mode: SuppressMode::Hide,
                reason: "embargo".to_owned(),
                at: String::new(),
            },
        )
        .unwrap();
        let suppressions = suppression::load(&sup_dir);

        let cache = MetadataCache::new();
        let hydrated = hydrate_from_disk(
            data_dir,
            StatusWrite::unshared(),
            &status,
            &cache,
            &suppressions,
            &|_| false,
        );

        // Loaded, but seeded Hidden by hydrate itself: never a Visible-then-Hidden flash.
        assert_eq!(hydrated.loaded, 1);
        assert_eq!(cache.get(id).unwrap().state, DatasetState::Hidden);
        // And it never appears in the served (Visible) set.
        assert!(cache.visible_datasets().is_empty());
    }

    #[test]
    fn hydrate_recovers_a_completed_dir_recorded_error() {
        // A crash after the atomic publish rename but before the status write can leave a
        // complete, valid dataset directory under an `Error` status entry. A present, valid
        // manifest.json exists only after that rename, so it proves the store committed and
        // the `Error` is stale. Hydrate must recover such a directory, served Hidden as the
        // fail-safe default, instead of wedging a completed dataset into a permanent
        // unservable error.
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path();
        let id = "GDI-EE-UTARTU-20260409143052901";
        write_published(data_dir, id);

        let mut status = StatusIndex::new();
        status.insert(
            id.to_owned(),
            StatusEntry {
                state: DatasetState::Error,
                error_message: Some(ErrorClass::InternalError),
                channel: "inbox".to_owned(),
                last_seen_signature: Some("sig".to_owned()),
                provenance: DatasetProvenance::Unknown,
            },
        );

        let cache = MetadataCache::new();
        let hydrated = hydrate_from_disk(
            data_dir,
            StatusWrite::unshared(),
            &status,
            &cache,
            &SuppressionSet::default(),
            &|_| false,
        );
        assert_eq!(
            hydrated.loaded, 1,
            "a present, valid dir under a stale Error must be recovered, not skipped"
        );
        let entry = cache
            .get(id)
            .expect("the recovered dataset must be in the cache");
        assert_eq!(
            entry.state,
            DatasetState::Hidden,
            "recovered as Hidden (fail-safe); a governing sidecar promotes it to Visible"
        );
    }

    #[test]
    fn hydrate_evicts_cache_entry_whose_dir_is_gone() {
        // An insert-only reload leaves a permanent ghost: a cache entry for a dataset whose
        // directory has been deleted, which keeps re-disclosing a removed dataset on the
        // public plane until the process restarts. The authoritative-reconcile eviction
        // must clear it, and remove it from the served visible set, while retaining every
        // dataset still present on disk.
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path();

        let present = "GDI-EE-UTARTU-20260409143052837";
        let ghost = "GDI-EE-UTARTU-20260409143052840";
        write_published(data_dir, present);
        // `ghost` has no directory on disk but is still in the cache, and, simulating the
        // race, its stale `Visible` status entry survives too.

        let mut status = StatusIndex::new();
        for id in [present, ghost] {
            status.insert(
                id.to_owned(),
                StatusEntry {
                    state: DatasetState::Visible,
                    error_message: None,
                    channel: "inbox".to_owned(),
                    last_seen_signature: Some("sig".to_owned()),
                    provenance: DatasetProvenance::Unknown,
                },
            );
        }

        let cache = MetadataCache::new();
        cache.insert(
            StatusWrite::unshared(),
            entry(present, DatasetState::Visible),
        );
        cache.insert(StatusWrite::unshared(), entry(ghost, DatasetState::Visible));
        assert_eq!(cache.len(), 2);

        let hydrated = hydrate_from_disk(
            data_dir,
            StatusWrite::unshared(),
            &status,
            &cache,
            &SuppressionSet::default(),
            &|_| false,
        );

        assert_eq!(hydrated.evicted, 1, "the dir-less ghost is evicted");
        assert!(cache.get(ghost).is_none(), "ghost is no longer cached");
        assert!(cache.get(present).is_some(), "on-disk dataset is retained");
        let visible = cache.visible_datasets();
        assert_eq!(visible.len(), 1, "only the on-disk dataset is served");
        assert_eq!(visible[0].id, present);
    }

    #[test]
    fn hydrate_does_not_evict_a_dir_with_an_unwritten_manifest() {
        // A dataset mid-ingest: its directory exists but `manifest.json` is not yet
        // written, since it is written last via temp and rename. Reload must treat it as a
        // benign skip, neither loaded nor evicted, because the directory is present and so
        // it is not a ghost.
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path();

        let ingesting = "GDI-EE-UTARTU-20260409143052841";
        std::fs::create_dir_all(data_dir.join(ingesting)).unwrap(); // dir, no manifest yet

        let cache = MetadataCache::new();
        cache.insert(
            StatusWrite::unshared(),
            entry(ingesting, DatasetState::Visible),
        );

        let hydrated = hydrate_from_disk(
            data_dir,
            StatusWrite::unshared(),
            &StatusIndex::new(),
            &cache,
            &SuppressionSet::default(),
            &|_| false,
        );

        assert_eq!(hydrated.evicted, 0, "a present directory is never a ghost");
        assert_eq!(hydrated.loaded, 0, "no manifest yet -> not (re)loaded");
        assert!(
            cache.get(ingesting).is_some(),
            "the mid-ingest entry is retained because its directory is present"
        );
    }

    #[test]
    fn hydrate_skips_a_corrupt_manifest_without_aborting_the_reload() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path();

        // Two good published datasets...
        let good_a = "GDI-EE-UTARTU-20260409143052837";
        let good_b = "GDI-EE-UTARTU-20260409143052838";
        write_published(data_dir, good_a);
        write_published(data_dir, good_b);

        // ...and a third with a valid id but a truncated or garbage manifest.json. It must
        // be skipped at the serde parse branch, not panic or abort the whole reload.
        // Syntactically valid JSON that fails the schema hits the same branch.
        let corrupt = "GDI-EE-UTARTU-20260409143052839";
        let corrupt_dir = data_dir.join(corrupt);
        std::fs::create_dir_all(&corrupt_dir).unwrap();
        std::fs::write(corrupt_dir.join("manifest.json"), b"{\"metadata\": {tru").unwrap();

        let mut status = StatusIndex::new();
        for id in [good_a, good_b, corrupt] {
            status.insert(
                id.to_owned(),
                StatusEntry {
                    state: DatasetState::Hidden,
                    error_message: None,
                    channel: "inbox".to_owned(),
                    last_seen_signature: Some("sig".to_owned()),
                    provenance: DatasetProvenance::Unknown,
                },
            );
        }

        let cache = MetadataCache::new();
        let hydrated = hydrate_from_disk(
            data_dir,
            StatusWrite::unshared(),
            &status,
            &cache,
            &SuppressionSet::default(),
            &|_| false,
        );

        // Only the two good datasets load; the corrupt one is skipped and counted, so an
        // operator can see and alert on a dataset dropping out of serving.
        assert_eq!(
            hydrated.loaded, 2,
            "corrupt manifest must not abort the reload"
        );
        assert_eq!(
            hydrated.skipped, 1,
            "the corrupt manifest must be counted as a non-benign skip"
        );
        assert_eq!(cache.len(), 2);
        assert!(cache.get(good_a).is_some());
        assert!(cache.get(good_b).is_some());
        assert!(
            cache.get(corrupt).is_none(),
            "corrupt dataset must not be cached"
        );
    }

    #[test]
    fn hydrate_defaults_to_hidden_when_index_has_no_entry() {
        // A published directory whose id is absent from the status index must not be
        // served: no governing sidecar means hidden, never visible by accident.
        let dir = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-20260409143052840";
        write_published(dir.path(), id);

        let cache = MetadataCache::new();
        let loaded = hydrate_from_disk(
            dir.path(),
            StatusWrite::unshared(),
            &StatusIndex::new(),
            &cache,
            &SuppressionSet::default(),
            &|_| false,
        )
        .loaded;

        assert_eq!(loaded, 1);
        assert_eq!(cache.get(id).unwrap().state, DatasetState::Hidden);
        assert!(cache.visible_datasets().is_empty());
    }

    #[test]
    fn hydrate_skips_non_dataset_entries_and_missing_manifests() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path();

        // A valid published dataset.
        let id = "GDI-EE-UTARTU-20260409143052841";
        write_published(data_dir, id);
        // Service-owned non-dataset entries that must be ignored.
        std::fs::write(data_dir.join(".status.json"), b"{}").unwrap();
        std::fs::create_dir_all(data_dir.join(".incoming")).unwrap();
        std::fs::create_dir_all(data_dir.join("not-a-dataset-id")).unwrap();
        // A dataset-id directory with no manifest, interrupted mid-ingest, is skipped.
        std::fs::create_dir_all(data_dir.join("GDI-EE-UTARTU-20260409143052842")).unwrap();

        let cache = MetadataCache::new();
        let loaded = hydrate_from_disk(
            data_dir,
            StatusWrite::unshared(),
            &StatusIndex::new(),
            &cache,
            &SuppressionSet::default(),
            &|_| false,
        )
        .loaded;

        assert_eq!(loaded, 1);
        assert!(cache.get(id).is_some());
    }

    #[test]
    fn hydrate_missing_data_dir_is_empty_not_error() {
        let dir = tempfile::tempdir().unwrap();
        let cache = MetadataCache::new();
        let loaded = hydrate_from_disk(
            &dir.path().join("absent"),
            StatusWrite::unshared(),
            &StatusIndex::new(),
            &cache,
            &SuppressionSet::default(),
            &|_| false,
        )
        .loaded;
        assert_eq!(loaded, 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn provenance_is_internally_tagged_and_the_four_kinds_are_distinct_on_disk() {
        // The three "no fingerprint" cases must not collapse into one another. Each must
        // serialize to a distinct `kind` tag and round-trip unchanged.
        for (provenance, expected_kind) in [
            (
                DatasetProvenance::Recovered {
                    fingerprints: vec!["sha256:aa".to_owned()],
                },
                "recovered",
            ),
            (DatasetProvenance::Plaintext, "plaintext"),
            (DatasetProvenance::RecoveryFailed, "recovery_failed"),
            (DatasetProvenance::Unknown, "unknown"),
        ] {
            let json: serde_json::Value = serde_json::to_value(&provenance).unwrap();
            assert_eq!(
                json["kind"], expected_kind,
                "kind() and the wire tag must agree for {provenance:?}"
            );
            assert_eq!(provenance.kind(), expected_kind);
            let back: DatasetProvenance = serde_json::from_value(json).unwrap();
            assert_eq!(
                back, provenance,
                "round-trip must preserve the exact variant"
            );
        }
    }

    #[test]
    fn recorded_provenance_survives_a_store_load_cycle() {
        // Provenance is persisted rather than only logged so a recovered fingerprint and an
        // anomalous `recovery_failed` both survive a restart, and an operator can still say
        // who wrote a dataset, and which are unverified, months later.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".status.json");

        let mut index = StatusIndex::new();
        index.insert(
            "GDI-EE-UTARTU-1".to_owned(),
            StatusEntry {
                state: DatasetState::Visible,
                error_message: None,
                channel: "inbox".to_owned(),
                last_seen_signature: None,
                provenance: DatasetProvenance::Recovered {
                    fingerprints: vec!["sha256:aa".to_owned(), "sha256:bb".to_owned()],
                },
            },
        );
        index.insert(
            "GDI-EE-UTARTU-2".to_owned(),
            StatusEntry {
                state: DatasetState::Error,
                error_message: Some(ErrorClass::InvalidManifest),
                channel: "bkt".to_owned(),
                last_seen_signature: None,
                provenance: DatasetProvenance::RecoveryFailed,
            },
        );
        index.store(&path).unwrap();

        let loaded = StatusIndex::load(&path).unwrap();
        assert_eq!(
            loaded.get("GDI-EE-UTARTU-1").unwrap().provenance,
            DatasetProvenance::Recovered {
                fingerprints: vec!["sha256:aa".to_owned(), "sha256:bb".to_owned()],
            },
            "a recovered fingerprint survives restart; the record outlives log rotation"
        );
        assert_eq!(
            loaded.get("GDI-EE-UTARTU-2").unwrap().provenance,
            DatasetProvenance::RecoveryFailed,
            "the anomalous case stays distinct from plaintext/unknown after a reload"
        );
    }

    #[test]
    fn dataset_provenance_projects_from_writer_provenance_dropping_the_detail() {
        use crate::ingest::WriterProvenance;
        assert_eq!(
            DatasetProvenance::from(&WriterProvenance::Recovered(vec!["sha256:aa".to_owned()])),
            DatasetProvenance::Recovered {
                fingerprints: vec!["sha256:aa".to_owned()]
            }
        );
        assert_eq!(
            DatasetProvenance::from(&WriterProvenance::Plaintext),
            DatasetProvenance::Plaintext
        );
        // The node-local detail string is discarded from the durable form.
        assert_eq!(
            DatasetProvenance::from(&WriterProvenance::Unrecoverable("bad magic".to_owned())),
            DatasetProvenance::RecoveryFailed
        );
    }

    #[test]
    fn provenance_sidecar_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let prov = DatasetProvenance::Recovered {
            fingerprints: vec!["sha256:aa".to_owned()],
        };
        write_provenance_sidecar(dir.path(), &prov).unwrap();
        assert_eq!(read_provenance_sidecar(dir.path()), Some(prov));
        // A directory with no sidecar reads as None (never fatal).
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(read_provenance_sidecar(empty.path()), None);
    }

    #[test]
    fn backfill_restores_unknown_provenance_from_the_sidecar() {
        // Simulate a lost/partial index: the entry exists (state + channel survived) but
        // its provenance is Unknown, while the data dir still carries the sidecar.
        let data_dir = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-1";
        std::fs::create_dir_all(data_dir.path().join(id)).unwrap();
        write_provenance_sidecar(
            &data_dir.path().join(id),
            &DatasetProvenance::Recovered {
                fingerprints: vec!["sha256:bb".to_owned()],
            },
        )
        .unwrap();

        let mut index = StatusIndex::new();
        index.insert(
            id.to_owned(),
            StatusEntry {
                state: DatasetState::Visible,
                error_message: None,
                channel: "inbox".to_owned(),
                last_seen_signature: None,
                provenance: DatasetProvenance::Unknown,
            },
        );

        assert_eq!(index.backfill_provenance_from_sidecars(data_dir.path()), 1);
        assert_eq!(
            index.get(id).unwrap().provenance,
            DatasetProvenance::Recovered {
                fingerprints: vec!["sha256:bb".to_owned()]
            }
        );
        // Idempotent: a second pass upgrades nothing (the entry is no longer Unknown).
        assert_eq!(index.backfill_provenance_from_sidecars(data_dir.path()), 0);
    }

    #[test]
    fn backfill_never_overwrites_concrete_provenance_or_invents_entries() {
        let data_dir = tempfile::tempdir().unwrap();
        let id = "GDI-EE-UTARTU-1";
        std::fs::create_dir_all(data_dir.path().join(id)).unwrap();
        // The sidecar says plaintext but the index already recorded a real writer key, so
        // the index wins: backfill only fills `Unknown`, it never downgrades.
        write_provenance_sidecar(&data_dir.path().join(id), &DatasetProvenance::Plaintext).unwrap();

        let mut index = StatusIndex::new();
        index.insert(
            id.to_owned(),
            StatusEntry {
                state: DatasetState::Visible,
                error_message: None,
                channel: "inbox".to_owned(),
                last_seen_signature: None,
                provenance: DatasetProvenance::Recovered {
                    fingerprints: vec!["sha256:cc".to_owned()],
                },
            },
        );
        assert_eq!(index.backfill_provenance_from_sidecars(data_dir.path()), 0);
        // A sidecar with no matching index row creates nothing: channel and state are
        // unknown, and synthesizing a row would break S3 first-claim re-adoption.
        std::fs::create_dir_all(data_dir.path().join("GDI-FI-THL-2")).unwrap();
        write_provenance_sidecar(
            &data_dir.path().join("GDI-FI-THL-2"),
            &DatasetProvenance::Plaintext,
        )
        .unwrap();
        assert_eq!(index.backfill_provenance_from_sidecars(data_dir.path()), 0);
        assert!(index.get("GDI-FI-THL-2").is_none());
    }

    #[test]
    fn a_status_index_survives_a_version_downgrade_across_additive_fields() {
        // The rollback contract. Rolling an image back one version reads a `.status.json` a
        // newer binary wrote, so additive changes must be tolerated: an older parser meets a
        // field it has never heard of and must ignore it. `StatusIndex::load` is one
        // `from_slice` over the whole file and the caller propagates the error, so a parse
        // failure is not one degraded dataset but a node that refuses to boot with its
        // entire inventory unavailable.
        let from_a_newer_node = r#"{
              "GDI-EE-UTARTU-1": {
                "state": "visible",
                "channel": "primary",
                "last_seen_signature": "etag-1",
                "someFutureField": {"nested": [1, 2, 3]},
                "anotherOne": "additive"
              }
            }"#;
        let index: StatusIndex = serde_json::from_str(from_a_newer_node)
            .expect("an additive field must not fail the load");
        let entry = index.get("GDI-EE-UTARTU-1").expect("the entry survives");
        assert_eq!(entry.state, DatasetState::Visible);
        assert_eq!(entry.channel, "primary");
        assert_eq!(entry.last_seen_signature.as_deref(), Some("etag-1"));

        // The other half of the contract: a missing required field fails the whole file,
        // not just its own entry. That is what renaming `state` or `channel` would do to an
        // older binary, and why such a rename needs a migration rather than a rollback.
        let missing_required = r#"{
              "GDI-EE-UTARTU-1": {"channel": "primary"},
              "GDI-EE-UTARTU-2": {"state": "visible", "channel": "primary"}
            }"#;
        let err = serde_json::from_str::<StatusIndex>(missing_required)
            .expect_err("a missing required field must fail");
        assert!(
            err.to_string().contains("state"),
            "the error must name the field so an operator can act on it: {err}"
        );
    }
}
