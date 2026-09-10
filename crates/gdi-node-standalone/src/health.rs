//! Health probes and the readiness model.
//!
//! Two management-plane probes, served to the cluster rather than the public ingress:
//!
//! * `GET /health/live` answers whether the process is up. Always `200`, because a reachable
//!   handler is itself the liveness signal.
//! * `GET /health/ready` reports readiness as a small JSON document with an overall `ready`
//!   flag and a per-subsystem view (`s3`, `vault`, `at_rest`, `key_material`,
//!   `initial_reconcile`). A subsystem reads `ok`, `not-configured` or `unavailable`;
//!   `at_rest` also `mismatch` or `unverifiable`, and `initial_reconcile` reads `done` or
//!   `pending`. `200` when ready, `503` when not.
//!
//! The ready predicate:
//!
//! * no shutdown signal has arrived, so the node is not draining.
//! * Vault is healthy when `[vault]` is configured. A not-configured subsystem is never a
//!   failure.
//! * the at-rest (PME) master key still unwraps this node's sentinel, when
//!   `[vault].transit_key` is set.
//! * key material loaded: the node identities and, under S3 with Vault, the per-bucket S3
//!   credentials. An empty identity set with no Vault is the valid keyless mode and reads
//!   `ok`.
//! * the initial reconcile (the startup listing and the per-dataset `.state.json` fetch) is
//!   done, so visibility is correct from the first served request. `main` sets it once the
//!   pre-bind S3 reconcile loop completes, or immediately on a node with no S3 monitoring.
//!
//! S3 bucket health is not part of the gate. With per-provider buckets, one provider's bucket
//! going unhealthy degrades only that bucket's datasets, and a `503` would take every other
//! provider out of rotation with it. Per-bucket health is reported as `s3_buckets` detail,
//! with an aggregate `s3` rollup, and each bucket's poll errors are metered, but the node
//! stays ready as long as it is itself up.
//!
//! A wedged ingest pool does not fail readiness either: the read path is unaffected and the
//! wedge is a metrics alert, so nothing about the ingest queue feeds the probe.
//!
//! The per-subsystem health lives in [`Readiness`], a cheaply cloneable `Arc`-backed set of
//! atomic flags shared through [`crate::state::AppState`]. The subsystems write their state
//! (the S3 monitor on each reconcile; `main` for Vault, key material and the
//! initial-reconcile latch) and the probe reads a snapshot, holding no lock across an
//! `.await`.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use gdi_node_standalone_core::GDI_METADATA_VERSION;
use serde::Serialize;

use crate::state::AppState;

/// The channel name of the local filesystem inbox.
///
/// The one channel that never reconciles, and so the only one the visibility staleness bound
/// may exempt. It is named rather than inferred from absence from `channel_health`, which
/// would also exempt every departed provider (see `Readiness::is_reconciling_channel`).
pub const INBOX_CHANNEL: &str = "inbox";

/// The per-subsystem runtime health, shared through [`AppState`].
///
/// Cheaply cloneable, being one `Arc` over the flags. The flags carry a subsystem's health;
/// whether a subsystem is a dependency at all is decided from the config (`has_s3_buckets`
/// and `has_vault`) when the snapshot is taken, so a not-configured subsystem reads
/// `not-configured` whatever its flag says.
#[derive(Debug, Clone, Default)]
pub struct Readiness {
    inner: Arc<Flags>,
}

/// One bucket's last successful reconcile acknowledgement, serialized under `s3_markers`.
#[derive(Debug, Clone, Serialize)]
pub struct ChannelReconcile {
    /// The marker change-token (`_sync_marker.json` `ETag`, or its last-modified fallback)
    /// the node reconciled on. `None` when the marker was absent that pass.
    pub observed_marker: Option<String>,
    /// When that reconcile completed (`xsd:dateTime`, node clock).
    pub last_reconcile_at: String,
}

/// The atomic flags backing [`Readiness`].
#[derive(Debug)]
struct Flags {
    /// When this process started (`xsd:dateTime`, node clock).
    ///
    /// The staleness baseline for a channel with no reconcile record. `channel_reconcile`
    /// lives only in memory and is written solely by the poll loop after a successful
    /// reconcile, never by the startup reconcile, so every restart empties it. Anchoring to
    /// process start makes `max_visibility_staleness_seconds` survive a restart: a channel
    /// that has not reconciled since boot becomes stale once uptime exceeds the bound.
    /// Without that baseline a bucket that went dark before a restart would serve its whole
    /// visible set, retracted datasets included, with no bound at all.
    started_at: String,
    /// Whether data visibility has been established, so `/health/ready` may report ready.
    /// Starts `false`. `main` sets it after the pre-bind reconcile when there is no S3 to
    /// reconcile, when the node re-hydrated datasets from disk, or when at least one bucket's
    /// startup reconcile succeeded. A fresh S3 node whose every bucket failed at boot stays
    /// `false` until the first successful poll sets it.
    initial_reconcile_done: AtomicBool,
    /// Per-bucket S3 health, keyed by channel (the bucket `name`): `true` after that
    /// bucket's reconcile succeeds, `false` after it fails. A bucket appears here once its
    /// first reconcile runs. Consulted only when `[[s3.buckets]]` is configured, and unlike
    /// the other flags it does not gate overall readiness, since a single provider bucket
    /// outage must not take the whole node out of rotation. It is surfaced as per-bucket
    /// detail on `/health/ready`.
    ///
    /// The key set has a second job: it is the roster of channels the poll loop is expected
    /// to reconcile, which `is_reconciling_channel` and `any_channel_stale` read to decide
    /// who the visibility-staleness bound applies to. That is a serving gate rather than a
    /// readiness one, and it means a channel missing from this map is exempt from staleness,
    /// which is why `register_configured_channels` seeds every configured bucket at boot
    /// before any monitor is built.
    channel_health: Mutex<BTreeMap<String, bool>>,
    /// Per-bucket reconcile acknowledgement: the marker change-token the node last
    /// successfully reconciled on, and when. An orchestrator that bumps `_sync_marker.json`
    /// and then `HEAD`s it can poll here until `observed_marker` equals the marker's new
    /// `ETag`, which is a bounded read-side ack that its handoff has been seen rather than a
    /// blind timeout. Keyed by channel, updated after each successful reconcile.
    channel_reconcile: Mutex<BTreeMap<String, ChannelReconcile>>,
    /// Whether the Vault client is connected with a usable token. Consulted only when
    /// `[vault]` is configured; a transient startup failure leaves it `false`, which renders
    /// as `unavailable`.
    vault_ok: AtomicBool,
    /// The at-rest (PME) key verdict, as an [`AtRestHealth`] discriminant. Consulted only
    /// when `[vault].transit_key` is set, and it does not self-heal: a replaced or reset
    /// master key is an incident an operator must resolve.
    ///
    /// Three verdicts share this slot, and the two failures demand different operator
    /// actions. `Mismatch` means the master key no longer unwraps this node's data, so the
    /// key has to be recovered or the data is gone. `Unverifiable` means the check could not
    /// be completed from local state, so an operator inspects the sentinel and then runs
    /// `pme reseal`. A bool would render both as `at_rest: "unavailable"` and leave the probe
    /// unable to tell a key incident from a damaged sentinel.
    at_rest: AtomicU8,
    /// Whether the configured key material loaded: the node identities and, under S3 with
    /// Vault, the per-bucket S3 credentials. `true` also covers the valid keyless mode, with
    /// no identities and no Vault; `false` only when a configured load failed.
    key_material_ok: AtomicBool,
    /// Set once when a shutdown signal (`SIGTERM` or `SIGINT`) arrives, before the drain
    /// begins. It flips `/health/ready` to `503` so an orchestrator stops routing new traffic
    /// to this instance while in-flight requests drain, closing the endpoint-removal race
    /// that otherwise causes connection-refused blips on a rolling deploy. One-way: never
    /// reset, because the process is on its way out.
    shutting_down: AtomicBool,
}

/// Hand-written because `started_at` must be the moment the process came up, which a derived
/// `String` default cannot express. Every other field keeps its derived default, and adding
/// one here without a value is a compile error.
impl Default for Flags {
    fn default() -> Self {
        Self {
            started_at: gdi_node_standalone_core::util::now_rfc3339(),
            initial_reconcile_done: AtomicBool::default(),
            channel_health: Mutex::default(),
            channel_reconcile: Mutex::default(),
            vault_ok: AtomicBool::default(),
            at_rest: AtomicU8::new(AtRestHealth::Ok as u8),
            key_material_ok: AtomicBool::default(),
            shutting_down: AtomicBool::default(),
        }
    }
}

impl Readiness {
    /// A fresh readiness view: nothing is ready yet (initial reconcile pending, all
    /// subsystem flags `false`). `main` sets the flags as startup progresses.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// When this process started (RFC3339, node clock).
    ///
    /// It is the staleness baseline for a channel that has never reconciled, and the boot
    /// identity `GET /stats/queries` publishes as `startedAt`, so both surfaces answer "since
    /// when?" with the same instant. It is process start, never config-reload time, because a
    /// poller keys reset detection on it.
    #[must_use]
    pub fn started_at(&self) -> &str {
        &self.inner.started_at
    }

    /// Mark the initial reconcile (startup listing + per-dataset `.state.json`
    /// fetch) as complete. Idempotent.
    pub fn mark_initial_reconcile_done(&self) {
        self.inner
            .initial_reconcile_done
            .store(true, Ordering::Release);
    }

    /// Register every configured bucket as unhealthy, before any monitor is built.
    ///
    /// The per-bucket map is otherwise populated only by [`Self::set_channel_health`], which
    /// `BucketMonitor` calls, so a bucket whose client fails to build would never register
    /// and would vanish from `/health/ready`. `all_channels_ok()` is `.values().all(..)` over
    /// registered channels and is vacuously `true`, so the node would report ready while that
    /// provider's data was never polled.
    ///
    /// Seeding the key set from the config makes the registered channels a property of what
    /// the operator asked for rather than of which monitors happened to start, so an
    /// early-return on the construction path cannot make a configured bucket disappear. Each
    /// entry flips to `true` on its first successful reconcile.
    pub fn register_configured_channels<'a>(&self, channels: impl IntoIterator<Item = &'a str>) {
        let mut map = self
            .inner
            .channel_health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for channel in channels {
            // `or_insert`, not `insert`: a monitor that has already reported must not be
            // reset to unhealthy by a later call.
            map.entry(channel.to_owned()).or_insert(false);
        }
    }

    /// Record one bucket's S3 health, `true` for a successful reconcile and `false` for a
    /// failure, keyed by its channel. Called by each bucket monitor.
    pub fn set_channel_health(&self, channel: &str, ok: bool) {
        self.inner
            .channel_health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(channel.to_owned(), ok);
    }

    /// Record a successful reconcile's acknowledgement for `channel`: the `observed_marker`
    /// it reconciled on, and the current time. Surfaced under `s3_markers` on
    /// `/health/ready`.
    pub fn record_reconcile(&self, channel: &str, observed_marker: Option<String>) {
        self.record_reconcile_at(
            channel,
            observed_marker,
            gdi_node_standalone_core::util::now_rfc3339(),
        );
    }

    /// As [`record_reconcile`](Self::record_reconcile) but with an explicit RFC3339 stamp.
    ///
    /// Production uses the wall clock through `record_reconcile`; this seam lets a test
    /// inject a backdated reconcile to exercise the staleness gate without reaching into
    /// private fields or sleeping.
    pub fn record_reconcile_at(&self, channel: &str, observed_marker: Option<String>, at: String) {
        self.inner
            .channel_reconcile
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                channel.to_owned(),
                ChannelReconcile {
                    observed_marker,
                    last_reconcile_at: at,
                },
            );
    }

    /// A snapshot of every bucket's last reconcile ACK, keyed by channel. Drives the
    /// per-bucket `s3_markers` detail on `/health/ready`.
    #[must_use]
    pub fn channel_reconcile_snapshot(&self) -> BTreeMap<String, ChannelReconcile> {
        self.inner
            .channel_reconcile
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Whether any channel is currently stale past `max_secs`.
    ///
    /// The cheap precondition for the visibility-staleness gate. The gate paths otherwise
    /// resolve a dataset's owning channel through the status index, and the set-based path
    /// (`fresh_visible_datasets`) builds an id-to-channel map over every visible dataset,
    /// under the status mutex, on every request: `O(datasets)` work with two string
    /// allocations each, serialized across all in-flight requests, only to discover in the
    /// steady state that nothing is stale.
    ///
    /// This answers the same question from the reconcile map, which is keyed by channel and
    /// holds one entry per bucket, so the common case costs `O(buckets)` and never touches
    /// the status mutex. That is what makes the gate affordable as a default.
    #[must_use]
    pub fn any_channel_stale(&self, max_secs: u64) -> bool {
        if max_secs == 0 {
            return false;
        }
        let cap = i64::try_from(max_secs).unwrap_or(i64::MAX);
        let older = |ts: &str| {
            gdi_node_standalone_core::util::rfc3339_age_seconds(ts).is_some_and(|age| age > cap)
        };
        // Held only long enough to read, and released before `channel_health` is taken below.
        // No site in this file nests the two locks, and none may: reading one while holding
        // the other would be half of a deadlock that wedges the readiness probe. Snapshot
        // instead, as this function does.
        //
        // The key set is cloned only when it will be used. `None` here means already stale,
        // so the commonest early return costs no allocation.
        let recorded: Option<std::collections::BTreeSet<String>> = {
            let guard = self
                .inner
                .channel_reconcile
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if guard.values().any(|rec| older(&rec.last_reconcile_at)) {
                None
            } else {
                Some(guard.keys().cloned().collect())
            }
        };
        let Some(recorded) = recorded else {
            return true;
        };
        // A channel with no reconcile record uses the same uptime baseline `channel_stale`
        // does, or this fast path would disable the gate it guards. `channel_reconcile` is
        // in-memory and written only by the poll loop after a successful reconcile, so a
        // restart empties it and an `any()` over the empty map answers `false`;
        // `fresh_visible_datasets` would then return the whole visible set without ever
        // consulting `channel_stale`. `channel_health` is the channel roster here, because
        // the startup reconcile populates it.
        if !older(&self.inner.started_at) {
            return false;
        }
        let health = self
            .inner
            .channel_health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        health.keys().any(|ch| !recorded.contains(ch))
    }

    /// Whether `channel` is one the poll loop is expected to reconcile: every channel except
    /// the local inbox, decided by name. A pure check that takes no lock.
    ///
    /// Absence from `channel_health` is not the test. That map is seeded from the current
    /// config, so a provider whose `[[s3.buckets]]` entry has been deleted is absent from it
    /// too, and inferring the inbox's exemption from absence would exempt a departed provider
    /// from the staleness bound as well. The bound defaults to 86 400 seconds and ships on,
    /// so that exemption would be a disclosure rather than a no-op.
    ///
    /// A channel absent from the config is instead treated as reconciling but dark:
    /// [`Self::channel_stale`] measures it from `started_at` if asked, and the hydrate
    /// projection withholds its datasets as orphaned from boot, which is the lever that
    /// fires, since `any_channel_stale` consults only channels the current config seeds.
    /// `channel take-down` remains the immediate lever and accepts an unconfigured channel
    /// name.
    fn is_reconciling_channel(channel: &str) -> bool {
        channel != INBOX_CHANNEL
    }

    /// Whether `channel`'s last successful reconcile is older than `max_secs`, the
    /// visibility-staleness bound. `max_secs == 0` disables the gate and always answers
    /// `false`.
    ///
    /// With no reconcile record the answer depends on whether the channel is one that should
    /// be reconciling, which `is_reconciling_channel` decides by name.
    ///
    /// * A bucket channel with no record measures from process start (`started_at`).
    ///   `channel_reconcile` is written only by the poll loop after a successful reconcile, so
    ///   every restart empties it, and answering `false` there would let a bucket that went
    ///   dark before the restart serve retracted datasets indefinitely.
    /// * Any other channel answers `false`. The local inbox has no poll loop and never gets a
    ///   record, so applying the uptime baseline to it would withhold every inbox dataset
    ///   once uptime passed the bound, on a channel that cannot go dark in this sense.
    ///
    /// An unparseable timestamp counts as not stale, failing open on the node's own clock and
    /// format rather than on the provider, so a formatting bug cannot black out a live
    /// provider.
    #[must_use]
    pub fn channel_stale(&self, channel: &str, max_secs: u64) -> bool {
        if max_secs == 0 {
            return false;
        }
        let last = {
            let guard = self
                .inner
                .channel_reconcile
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match guard.get(channel) {
                Some(rec) => rec.last_reconcile_at.clone(),
                // Not a channel that reconciles at all, so no baseline applies. Checked
                // before the `started_at` fallback below, which is meaningful only for a
                // bucket that was supposed to be polling.
                None if !Self::is_reconciling_channel(channel) => return false,
                // No record: this channel has not successfully reconciled since the process
                // started, which is not evidence of freshness. `channel_reconcile` is
                // in-memory and the startup reconcile never writes it, so a restart empties
                // it for every channel, including one that had already gone dark. Measuring
                // from boot holds the bound from the last moment this node could have known
                // anything about the channel.
                None => self.inner.started_at.clone(),
            }
        };
        // Compare in `i64`, so a negative age from clock skew is never stale, and a
        // `max_secs` beyond `i64::MAX` clamps to never stale. An unparseable timestamp fails
        // open, so a formatting bug on the node's own clock cannot black out a provider.
        gdi_node_standalone_core::util::rfc3339_age_seconds(&last)
            .is_some_and(|age| age > i64::try_from(max_secs).unwrap_or(i64::MAX))
    }

    /// Record the current Vault health (connected with a usable token → `true`).
    pub fn set_vault_ok(&self, ok: bool) {
        self.inner.vault_ok.store(ok, Ordering::Release);
    }

    /// Record the at-rest (PME) key verdict. Only consulted when `[vault].transit_key`
    /// is set.
    pub fn set_at_rest(&self, health: AtRestHealth) {
        self.inner.at_rest.store(health as u8, Ordering::Release);
    }

    /// Record whether the configured key material loaded (or the valid keyless
    /// mode, which is `true`).
    pub fn set_key_material_ok(&self, ok: bool) {
        self.inner.key_material_ok.store(ok, Ordering::Release);
    }

    /// Mark the node as shutting down, flipping `/health/ready` to `503` so the
    /// orchestrator drains traffic before the listener stops. Call it before the
    /// graceful-drain wait. One-way and idempotent.
    pub fn begin_shutdown(&self) {
        self.inner.shutting_down.store(true, Ordering::Release);
    }

    /// Whether a shutdown signal has been received (the node is draining).
    #[must_use]
    pub fn is_shutting_down(&self) -> bool {
        self.inner.shutting_down.load(Ordering::Acquire)
    }

    fn initial_reconcile_done(&self) -> bool {
        self.inner.initial_reconcile_done.load(Ordering::Acquire)
    }

    /// A snapshot of every bucket's health, keyed by channel. Drives the per-bucket
    /// `s3_buckets` detail on `/health/ready`. Public so integration tests can assert
    /// the per-bucket readiness flip on an injected poll failure and its recovery.
    #[must_use]
    pub fn channel_health_snapshot(&self) -> BTreeMap<String, bool> {
        self.inner
            .channel_health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Whether every registered bucket is currently healthy, vacuously `true` before any
    /// bucket has reported. Drives the aggregate `s3` rollup, which signals that some bucket
    /// is degraded without gating overall readiness.
    #[must_use]
    pub fn all_channels_ok(&self) -> bool {
        self.inner
            .channel_health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .all(|&ok| ok)
    }

    /// Whether at least one registered bucket is currently healthy; `false` before any
    /// bucket has reported. It separates a fresh S3 node that established visibility with
    /// some bucket at boot from one that is fully blind. A blind node must not report
    /// `initial_reconcile: done`, or it would answer `exists:false` for datasets it will hold
    /// once S3 recovers.
    #[must_use]
    pub fn any_bucket_ok(&self) -> bool {
        self.inner
            .channel_health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .any(|&ok| ok)
    }

    fn vault_ok(&self) -> bool {
        self.inner.vault_ok.load(Ordering::Acquire)
    }

    /// The recorded at-rest verdict, ignoring whether PME is configured; the render decides
    /// that, as it does for `vault`.
    #[must_use]
    pub fn at_rest(&self) -> AtRestHealth {
        AtRestHealth::from_u8(self.inner.at_rest.load(Ordering::Acquire))
    }

    fn key_material_ok(&self) -> bool {
        self.inner.key_material_ok.load(Ordering::Acquire)
    }
}

/// The at-rest (PME) master-key verdict, as reported by `/health/ready`.
///
/// Separate from the private `SubsystemHealth`, because the two failure states are not
/// interchangeable and an operator's next step differs:
///
/// * `mismatch`: the configured Transit key cannot decrypt data this node wrote, because it
///   was replaced or the backend was reset. Existing PME data at rest is undecryptable, and
///   the fix is to recover the key. `pme reseal` refuses, because the mismatch is real.
/// * `unverifiable`: the check could not be completed from local state, because the sentinel
///   is unreadable, unparseable, or names a scheme this build does not know. It says nothing
///   about the key. The fix is to inspect the sentinel and then run `pme reseal --yes`, or to
///   deploy a newer binary when the scheme is the problem.
///
/// Both are readiness failures, so a single boolean would render both as `"unavailable"` and
/// leave `/health/ready`, the surface an operator reads first, unable to tell them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AtRestHealth {
    /// The configured master key unwrapped the sentinel.
    Ok,
    /// PME is not a dependency, because `[vault].transit_key` is unset. Never a readiness
    /// failure.
    NotConfigured,
    /// The master key could not unwrap the sentinel. A key incident.
    Mismatch,
    /// The check could not be completed from local state. Not a statement about the key.
    Unverifiable,
}

impl AtRestHealth {
    /// `ok` and `not-configured` are ready; both failure verdicts are not.
    const fn is_ready(self) -> bool {
        matches!(self, Self::Ok | Self::NotConfigured)
    }

    /// Decode a stored discriminant, defaulting to [`Self::Unverifiable`].
    ///
    /// The default is the cautious one: an unrecognised byte means this code and the writer
    /// disagree, which must not read as `ok`.
    const fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Ok,
            1 => Self::NotConfigured,
            2 => Self::Mismatch,
            _ => Self::Unverifiable,
        }
    }
}

/// The health of one configured-or-not subsystem, as reported by `/health/ready`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum SubsystemHealth {
    /// Configured and healthy.
    Ok,
    /// Not a dependency of this node, because its config section is absent or its feature is
    /// off. Never a readiness failure.
    NotConfigured,
    /// Configured but not currently healthy: unreachable, token lapsed, or load failed. A
    /// readiness failure.
    Unavailable,
}

impl SubsystemHealth {
    /// `ok` and `not-configured` are ready; `unavailable` is not. See the module docs for
    /// why `not-configured` is never a failure.
    fn is_ready(self) -> bool {
        !matches!(self, Self::Unavailable)
    }

    /// Derive a configured subsystem's health from its `ok` flag, or
    /// `not-configured` when it is not a dependency.
    fn from_configured(configured: bool, ok: bool) -> Self {
        if !configured {
            Self::NotConfigured
        } else if ok {
            Self::Ok
        } else {
            Self::Unavailable
        }
    }
}

/// The progress of the startup reconcile, reported as its own (non-subsystem)
/// readiness gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ReconcileProgress {
    /// The startup listing + per-dataset `.state.json` fetch are complete.
    Done,
    /// Not yet complete, so the node cannot serve correct visibility.
    Pending,
}

/// The per-subsystem readiness view serialized under `subsystems`.
#[derive(Debug, Clone, Serialize)]
struct Subsystems {
    /// Aggregate S3 rollup, `ok` only when every configured bucket is healthy.
    /// Informational: it does not gate overall readiness. See `s3_buckets` for per-bucket
    /// detail.
    s3: SubsystemHealth,
    /// S3 health per channel, keyed by channel name. Present only when `[[s3.buckets]]`
    /// is configured. A degraded channel reads `unavailable` here but never fails overall
    /// `ready`, because one provider's outage must not remove the node.
    #[serde(skip_serializing_if = "Option::is_none")]
    s3_buckets: Option<BTreeMap<String, SubsystemHealth>>,
    /// The Vault KV/Transit client (`[vault]`).
    vault: SubsystemHealth,
    /// Whether the at-rest (PME) master key still unwraps this node's data.
    /// `not-configured` unless `[vault].transit_key` is set. Separate from `vault`, because a
    /// mismatch is not an availability fault (Vault is reachable and answering) and reporting
    /// it there would point triage at connectivity.
    at_rest: AtRestHealth,
    /// The node's crypt4gh key material (and S3+Vault credentials).
    key_material: SubsystemHealth,
    /// The startup reconcile gate (listing + per-dataset `.state.json` fetch).
    initial_reconcile: ReconcileProgress,
}

/// The `/health/ready` response document.
#[derive(Debug, Clone, Serialize)]
struct ReadyBody {
    /// Overall readiness: Vault healthy when configured, key material healthy, the initial
    /// reconcile done, and not draining for shutdown. Configured S3 bucket health does not
    /// gate this flag (see the module docs).
    ready: bool,
    /// `true` when any configured subsystem reads `unavailable`, including one that does not
    /// gate `ready`, such as per-bucket S3 through the `s3` rollup.
    ///
    /// This is the "serving a partial view" signal. A degraded provider bucket leaves
    /// `ready: true`, so `ready` alone cannot tell an operator that the node is half-blind
    /// and an unreachable bucket's datasets are absent from what it serves. `degraded`
    /// surfaces that in a field a probe already reads, rather than making every consumer walk
    /// `subsystems.s3_buckets`.
    ///
    /// `ready: true` with `degraded: true` means serving while at least one provider is dark.
    /// It is not the complement of `ready`: a not-ready node is usually degraded too, and a
    /// startup reconcile still `pending` is progress rather than degradation, so it does not
    /// set this flag.
    ///
    /// Always serialized, so a consumer that keys on it can treat a missing field as version
    /// skew rather than as "not degraded".
    degraded: bool,
    /// `true` once a shutdown signal was received: the node is draining and reports not
    /// ready, so the orchestrator stops routing new traffic. Omitted from the JSON while the
    /// node is not draining.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    draining: bool,
    /// The per-subsystem detail.
    subsystems: Subsystems,
    /// Per-bucket reconcile acknowledgement: the marker each bucket last reconciled on, and
    /// when. Present only when `[[s3.buckets]]` is configured and at least one bucket has
    /// reconciled. Lets an orchestrator confirm its `_sync_marker.json` bump was observed.
    #[serde(skip_serializing_if = "Option::is_none")]
    s3_markers: Option<BTreeMap<String, ChannelReconcile>>,
}

/// `GET /health/live`: liveness. A reachable handler is the signal, so this is always
/// `200`.
pub(crate) async fn live() -> Response {
    StatusCode::OK.into_response()
}

/// The `GET /version` response document (build/version info).
#[derive(Debug, Clone, Serialize)]
struct VersionBody {
    /// The running service binary version (`CARGO_PKG_VERSION`).
    service_version: &'static str,
    /// The pinned gdi-metadata model version this build emits / validates against.
    gdi_metadata_version: &'static str,
    /// The git commit this binary was built from, abbreviated to 12 hex characters. See
    /// [`gdi_build_info::GIT_SHA`] for how it is resolved and when it reads `unknown`. It
    /// distinguishes a release tag from a from-source build of the same crate version.
    git_sha: &'static str,
    /// The build epoch in Unix seconds. See [`gdi_build_info::BUILD_EPOCH`].
    build_epoch: &'static str,
}

/// `GET /version`: build and version info. Always `200`, independent of readiness.
///
/// Lets an operator confirm which build is live, and which gdi-metadata model version it
/// emits, without a shell in the container or a request to the public data plane. These are
/// the same constants `--version` prints. Carries no secrets and no per-request state, and
/// is served on the management plane.
pub(crate) async fn version() -> Response {
    Json(VersionBody {
        service_version: env!("CARGO_PKG_VERSION"),
        gdi_metadata_version: GDI_METADATA_VERSION,
        git_sha: gdi_build_info::GIT_SHA,
        build_epoch: gdi_build_info::BUILD_EPOCH,
    })
    .into_response()
}

/// `GET /health/ready`: readiness with per-subsystem detail.
///
/// `200` with `{"ready": true, ...}` once the initial reconcile is done and the configured
/// Vault and key material are healthy, `503` with `{"ready": false, ...}` otherwise. A
/// not-configured subsystem is never a failure, per-bucket S3 health is reported as
/// `s3_buckets` detail without gating readiness, and a wedged ingest pool is not consulted
/// (see the module docs).
pub(crate) async fn ready(State(state): State<AppState>) -> Response {
    let body = readiness_body(&state);
    let status = if body.ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(body)).into_response()
}

/// Build the `/health/ready` document from the config (what is configured) and the
/// shared [`Readiness`] flags (each subsystem's current health).
fn readiness_body(state: &AppState) -> ReadyBody {
    let cfg = &state.config;
    let r = &state.readiness;

    let configured = cfg.has_s3_buckets();
    // Aggregate rollup: `ok` only when every configured bucket is healthy. Informational.
    let s3 = SubsystemHealth::from_configured(configured, r.all_channels_ok());
    // Per-bucket detail, only when S3 is a dependency.
    let s3_buckets: Option<BTreeMap<String, SubsystemHealth>> = configured.then(|| {
        r.channel_health_snapshot()
            .into_iter()
            .map(|(name, ok)| (name, SubsystemHealth::from_configured(true, ok)))
            .collect()
    });
    let vault = SubsystemHealth::from_configured(cfg.has_vault(), r.vault_ok());
    // PME is switched on by [vault].transit_key; without it this is not a dependency.
    let at_rest = if cfg.has_transit_key() {
        r.at_rest()
    } else {
        AtRestHealth::NotConfigured
    };
    // Key material is always a dependency, but the valid keyless mode reports `ok`, set by
    // `main`, so a keyless node never fails here.
    let key_material = if r.key_material_ok() {
        SubsystemHealth::Ok
    } else {
        SubsystemHealth::Unavailable
    };
    let initial_reconcile = if r.initial_reconcile_done() {
        ReconcileProgress::Done
    } else {
        ReconcileProgress::Pending
    };

    // A draining node reports not-ready whatever its subsystem health, so the orchestrator
    // removes it from rotation before the listener stops accepting. Per-bucket S3 health is
    // not part of the gate: one unhealthy provider bucket degrades only that bucket's
    // datasets, and a 503 would drop every other provider with it. The degraded bucket
    // surfaces as `s3_buckets` detail and in the aggregate `s3` rollup instead.
    let draining = r.is_shutting_down();
    let ready = !draining
        && vault.is_ready()
        && at_rest.is_ready()
        && key_material.is_ready()
        && matches!(initial_reconcile, ReconcileProgress::Done);

    // Serving a partial view: any configured subsystem unavailable, including the ones that
    // do not gate `ready`. Derived from the same `s3` rollup the probe reports, so a degraded
    // bucket cannot be visible in `s3_buckets` yet missing from this flag. The initial
    // reconcile is startup progress rather than degradation, so it is excluded.
    let degraded =
        !s3.is_ready() || !vault.is_ready() || !at_rest.is_ready() || !key_material.is_ready();

    // Per-bucket reconcile acknowledgement, only when S3 is a dependency and something has
    // reconciled. An empty map is omitted, so the field appears only once it is useful.
    let s3_markers = configured
        .then(|| r.channel_reconcile_snapshot())
        .filter(|m| !m.is_empty());

    ReadyBody {
        ready,
        degraded,
        draining,
        subsystems: Subsystems {
            s3,
            s3_buckets,
            vault,
            at_rest,
            key_material,
            initial_reconcile,
        },
        s3_markers,
    }
}

/// Sample `/health/ready` into the [`crate::metrics::HEALTH_READY`] gauge: one series per
/// subsystem, `1` for ready and `0` for not, plus an `overall` rollup. Reuses
/// [`readiness_body`], so the gauge cannot disagree with the probe. Called from the periodic
/// metrics sampler.
pub(crate) fn record_readiness_metrics(state: &AppState) {
    let body = readiness_body(state);
    let s = &body.subsystems;
    // Exhaustiveness guard. There is no `..` rest pattern, so a subsystem added to
    // `Subsystems` fails to compile here until it is metered or explicitly declined. A
    // hand-written list can omit a readiness-gating subsystem, leaving `overall` at 0 with
    // nothing to say why.
    let Subsystems {
        s3,
        // Per-bucket detail is not a component: it is keyed by an operator-chosen bucket
        // name, `gdi_s3_*{channel}` already carries per-channel health, and folding it in
        // would put unbounded label cardinality on this gauge.
        s3_buckets: _,
        vault,
        at_rest,
        key_material,
        initial_reconcile,
    } = s;
    let components = [
        ("overall", body.ready),
        (
            "initial_reconcile",
            matches!(initial_reconcile, ReconcileProgress::Done),
        ),
        ("s3", s3.is_ready()),
        ("vault", vault.is_ready()),
        ("at_rest", at_rest.is_ready()),
        ("key_material", key_material.is_ready()),
    ];
    for (component, ready) in components {
        ::metrics::gauge!(crate::metrics::HEALTH_READY, "component" => component)
            .set(f64::from(u8::from(ready)));
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;

    #[test]
    fn subsystem_health_not_configured_is_ready() {
        assert!(SubsystemHealth::NotConfigured.is_ready());
        assert!(SubsystemHealth::Ok.is_ready());
        assert!(!SubsystemHealth::Unavailable.is_ready());
    }

    #[test]
    fn from_configured_maps_states() {
        assert_eq!(
            SubsystemHealth::from_configured(false, false),
            SubsystemHealth::NotConfigured
        );
        assert_eq!(
            SubsystemHealth::from_configured(false, true),
            SubsystemHealth::NotConfigured
        );
        assert_eq!(
            SubsystemHealth::from_configured(true, true),
            SubsystemHealth::Ok
        );
        assert_eq!(
            SubsystemHealth::from_configured(true, false),
            SubsystemHealth::Unavailable
        );
    }

    #[test]
    fn readiness_flags_round_trip() {
        let r = Readiness::new();
        assert!(!r.initial_reconcile_done());
        assert!(!r.vault_ok());
        assert!(!r.key_material_ok());

        r.mark_initial_reconcile_done();
        r.set_vault_ok(true);
        r.set_key_material_ok(true);
        assert!(r.initial_reconcile_done());
        assert!(r.vault_ok());
        assert!(r.key_material_ok());

        // A clone shares the same flags.
        let clone = r.clone();
        r.set_vault_ok(false);
        assert!(!clone.vault_ok());
    }

    #[test]
    fn at_rest_verdict_round_trips_and_is_shared_by_clones() {
        let r = Readiness::new();
        // Starts `Ok`, which only matters once PME is configured, since the render otherwise
        // reports `not-configured`. `main` sets the real verdict once the sentinel is
        // checked.
        assert_eq!(r.at_rest(), AtRestHealth::Ok);

        let clone = r.clone();
        r.set_at_rest(AtRestHealth::Mismatch);
        assert_eq!(
            clone.at_rest(),
            AtRestHealth::Mismatch,
            "clones must share the slot: main sets it on one handle, the probe reads another"
        );
    }

    /// The two failure verdicts stay distinguishable, and both fail readiness.
    ///
    /// A single boolean would render a replaced master key and an unreadable sentinel alike
    /// as `at_rest: "unavailable"`, leaving the probe an operator reads first unable to tell
    /// "recover the key" from "inspect the sentinel". A refactor that collapses them fails
    /// here.
    #[test]
    fn a_key_mismatch_and_an_unverifiable_check_are_not_the_same_verdict() {
        let mismatch = serde_json::to_value(AtRestHealth::Mismatch).unwrap();
        let unverifiable = serde_json::to_value(AtRestHealth::Unverifiable).unwrap();
        assert_eq!(mismatch, "mismatch");
        assert_eq!(unverifiable, "unverifiable");
        assert_ne!(
            mismatch, unverifiable,
            "the two at-rest failures demand different operator actions and must not \
             render as one string"
        );
        assert!(!AtRestHealth::Mismatch.is_ready());
        assert!(!AtRestHealth::Unverifiable.is_ready());
        assert!(AtRestHealth::Ok.is_ready());
        assert!(AtRestHealth::NotConfigured.is_ready());
        // An unrecognised discriminant reads as the cautious verdict, never as `ok`.
        assert_eq!(AtRestHealth::from_u8(99), AtRestHealth::Unverifiable);
    }

    #[test]
    fn reconcile_ack_records_marker_and_time_per_channel() {
        let r = Readiness::new();
        // Unseen buckets have no ack until their first successful reconcile.
        assert!(r.channel_reconcile_snapshot().is_empty());

        r.record_reconcile("provider-a", Some("etag-abc".to_owned()));
        r.record_reconcile("provider-b", None); // marker absent that pass

        let snap = r.channel_reconcile_snapshot();
        let a = snap.get("provider-a").expect("provider-a ack recorded");
        assert_eq!(a.observed_marker.as_deref(), Some("etag-abc"));
        assert!(
            !a.last_reconcile_at.is_empty(),
            "the ack must stamp a reconcile time"
        );
        assert_eq!(
            snap.get("provider-b")
                .and_then(|b| b.observed_marker.clone()),
            None,
            "an absent marker is recorded as None, not omitted"
        );
    }

    #[test]
    fn a_channel_that_never_reconciled_since_boot_goes_stale_on_uptime() {
        // The restart case. `channel_reconcile` is in-memory and only the poll loop writes
        // it, so after a restart no channel has a record, including one that was already
        // dark. Answering "not stale" there would let a bucket serve a retracted dataset
        // indefinitely while `/health/ready` reported ready.
        //
        // Constructed directly rather than through a production seam: this is the one fact a
        // test needs to move and no caller should.
        let booted_long_ago = Readiness {
            inner: Arc::new(Flags {
                started_at: "2020-01-01T00:00:00Z".to_owned(),
                ..Flags::default()
            }),
        };
        // `bucket-a` has to be a channel the poll loop is expected to reconcile, meaning one
        // the startup reconcile registered. Otherwise this would assert the uptime baseline
        // for a channel that never reconciles at all (see
        // `the_inbox_is_never_stale_however_long_the_node_has_been_up`).
        booted_long_ago.set_channel_health("bucket-a", true);
        assert!(
            booted_long_ago.channel_stale("bucket-a", 60),
            "a known S3 bucket with no reconcile record on a node up since 2020 must be \
             stale: no record means 'not seen since boot', the opposite of fresh"
        );
        // The off switch, which is all this can be: `max_secs == 0` returns before any state
        // is read, so it says nothing about the baseline above.
        assert!(!booted_long_ago.channel_stale("bucket-a", 0));
        // The real control, with the gate enabled: identical state and a bound the uptime
        // cannot exceed, so an implementation that answered `true` unconditionally after the
        // `max_secs == 0` early return is caught here rather than by the line above.
        assert!(
            !booted_long_ago.channel_stale("bucket-a", u64::MAX),
            "the uptime baseline must be compared against the bound, not treated as stale \
             on sight"
        );
        // A channel that has reconciled recently is unaffected by an old boot time.
        booted_long_ago.record_reconcile("bucket-a", Some("e1".to_owned()));
        assert!(
            !booted_long_ago.channel_stale("bucket-a", 60),
            "a fresh reconcile must win over the boot baseline"
        );
    }

    /// The local inbox is never withheld by the staleness gate.
    ///
    /// It has no poll loop, so it never gets a `channel_reconcile` record. Applying the
    /// boot baseline to every record-less channel would withhold every inbox dataset once
    /// uptime passed the bound, on a channel that cannot be reached-then-dark.
    #[test]
    fn the_inbox_is_never_stale_however_long_the_node_has_been_up() {
        let booted_long_ago = Readiness {
            inner: std::sync::Arc::new(Flags {
                started_at: "2020-01-01T00:00:00Z".to_owned(),
                ..Flags::default()
            }),
        };
        assert!(
            !booted_long_ago.channel_stale("inbox", 60),
            "the inbox never reconciles, so the uptime baseline must not apply to it"
        );
        assert!(
            !booted_long_ago.any_channel_stale(60),
            "an inbox-only node must not trip the fast path either"
        );
        // Control: a channel the startup reconcile did reach, with no poll record, still
        // measures from boot. Otherwise this test would pass by disabling the gate.
        booted_long_ago.set_channel_health("bucket-a", true);
        assert!(
            booted_long_ago.channel_stale("bucket-a", 60),
            "a known S3 bucket with no reconcile record must still be stale from boot"
        );
    }

    /// A departed provider goes stale rather than inheriting the inbox's exemption.
    ///
    /// Inferring the exemption from absence in `channel_health`, whose keys come from the
    /// current config, would make deleting a `[[s3.buckets]]` entry, the documented
    /// offboarding step, exempt that channel and leave it permanently fresh. Its datasets are
    /// re-hydrated from `data_dir` on every boot whatever the channel, so a departed provider
    /// would keep being published with `ready: true, degraded: false` and no
    /// `gdi_s3_*{channel=...}` series left to notice.
    #[test]
    fn a_channel_no_longer_in_the_config_goes_stale_rather_than_serving_forever() {
        let booted_long_ago = Readiness {
            inner: std::sync::Arc::new(Flags {
                started_at: "2020-01-01T00:00:00Z".to_owned(),
                ..Flags::default()
            }),
        };
        // The per-channel verdict does not depend on the channel being in the config.
        assert!(
            booted_long_ago.channel_stale("departed-provider", 60),
            "a channel that can never reconcile again must not read as permanently fresh"
        );
        // The fast path reads a roster, so boot registers every channel the status index
        // still owns datasets for, not only the configured ones. Without that seeding
        // `fresh_visible_datasets` short-circuits on an empty roster and returns the whole
        // visible set without consulting the per-channel verdict above.
        booted_long_ago.register_configured_channels(["departed-provider"]);
        assert!(
            booted_long_ago.any_channel_stale(60),
            "the fast path must see a registered departed channel, or the gate never runs"
        );
        // The inbox keeps its exemption, as the one channel this may not withhold, and boot
        // never registers it.
        assert!(!booted_long_ago.channel_stale(INBOX_CHANNEL, 60));
    }

    /// `fresh_visible_datasets` calls `any_channel_stale` as a fast path and returns the
    /// whole visible set when it answers `false`, so `channel_stale`'s boot baseline is
    /// reachable only if this one agrees. Iterating the reconcile map instead would answer
    /// `false` after every restart, because that map is in-memory and written only by the
    /// poll loop, disabling the gate in exactly the window it covers.
    #[test]
    fn the_fast_path_does_not_disable_the_gate_after_a_restart() {
        let booted_long_ago = Readiness {
            inner: std::sync::Arc::new(Flags {
                started_at: "2020-01-01T00:00:00Z".to_owned(),
                ..Flags::default()
            }),
        };
        // A bucket the startup reconcile reached, with no poll-loop record yet: the
        // post-restart state.
        booted_long_ago.set_channel_health("bucket-a", true);
        assert!(
            booted_long_ago.any_channel_stale(60),
            "a channel with no reconcile record since a long-ago boot must not be reported \
             fresh; the per-channel gate is never consulted when this returns false"
        );
        // The off switch. It cannot serve as the control: `max_secs == 0` returns before any
        // channel state is consulted, so an implementation that answered `true` for
        // everything else still passes it.
        assert!(!booted_long_ago.any_channel_stale(0));
        // The real control, with the gate enabled: identical state and a bound the uptime
        // cannot exceed.
        assert!(
            !booted_long_ago.any_channel_stale(u64::MAX),
            "with the gate on and a bound nothing can exceed, no channel is stale — this \
             is what discriminates a fast path that always answers true"
        );
        let fresh_boot = Readiness::default();
        fresh_boot.set_channel_health("bucket-a", true);
        assert!(
            !fresh_boot.any_channel_stale(3600),
            "a node that booted moments ago is within the bound and must stay on the fast path"
        );
    }

    #[test]
    fn channel_stale_gates_only_a_reached_then_dark_bucket() {
        let r = Readiness::new();
        // An unknown channel is measured against process start rather than treated as
        // fresh. On a just-constructed `Readiness` the uptime is near zero, so it is under
        // any realistic bound and reads not-stale. The uptime-past-the-bound case is covered
        // by `a_channel_that_never_reconciled_since_boot_goes_stale_on_uptime` below.
        assert!(!r.channel_stale("bucket-a", 60));
        // A fresh reconcile is not stale.
        r.record_reconcile("bucket-a", Some("e1".to_owned()));
        assert!(!r.channel_stale("bucket-a", 60));
        // Bound 0 disables the gate entirely.
        assert!(!r.channel_stale("bucket-a", 0));

        // A reconcile stamped long in the past is stale under any modern bound.
        r.inner.channel_reconcile.lock().unwrap().insert(
            "bucket-a".to_owned(),
            ChannelReconcile {
                observed_marker: Some("e1".to_owned()),
                last_reconcile_at: "2020-01-01T00:00:00Z".to_owned(),
            },
        );
        assert!(
            r.channel_stale("bucket-a", 60),
            "a 2020 reconcile is stale under a 60s bound"
        );
        // Bound 0 still disables the gate even for that stale record.
        assert!(!r.channel_stale("bucket-a", 0));
        // A future timestamp from clock skew reads as not stale, failing open on the node's
        // own clock.
        r.inner.channel_reconcile.lock().unwrap().insert(
            "bucket-a".to_owned(),
            ChannelReconcile {
                observed_marker: Some("e1".to_owned()),
                last_reconcile_at: "2999-01-01T00:00:00Z".to_owned(),
            },
        );
        assert!(!r.channel_stale("bucket-a", 60));
    }

    #[test]
    fn bucket_health_is_tracked_per_channel() {
        let r = Readiness::new();
        // Unseen buckets are absent until their first poll registers them.
        assert!(r.channel_health_snapshot().is_empty());

        r.set_channel_health("provider-a", true);
        r.set_channel_health("provider-b", false);
        let snap = r.channel_health_snapshot();
        assert_eq!(snap.get("provider-a").copied(), Some(true));
        assert_eq!(snap.get("provider-b").copied(), Some(false));

        // The aggregate is "every registered bucket healthy", so one bad bucket makes it
        // false.
        assert!(!r.all_channels_ok());
        r.set_channel_health("provider-b", true);
        assert!(r.all_channels_ok());

        // Clones share the per-bucket state (each S3 monitor holds a clone).
        let clone = r.clone();
        r.set_channel_health("provider-a", false);
        assert_eq!(
            clone.channel_health_snapshot().get("provider-a").copied(),
            Some(false)
        );
    }

    #[test]
    fn a_configured_bucket_that_never_starts_a_monitor_reports_unhealthy_not_absent() {
        // `set_channel_health` is called only by a `BucketMonitor`, so a bucket whose S3
        // client fails to build never registers, and `all_channels_ok()`, an `.all(..)` over
        // registered channels, would stay vacuously true while that provider's data was
        // never polled or served.
        let r = Readiness::new();
        r.register_configured_channels(["provider-a", "provider-b"]);

        // Both configured channels are visible on the probe immediately, before any poll.
        let snap = r.channel_health_snapshot();
        assert_eq!(snap.get("provider-a").copied(), Some(false));
        assert_eq!(snap.get("provider-b").copied(), Some(false));
        assert!(
            !r.all_channels_ok(),
            "a configured-but-unstarted bucket must make the s3 rollup unhealthy, not vacuously ok"
        );

        // Only the bucket that reconciles flips; the failed one stays visible and bad.
        r.set_channel_health("provider-a", true);
        assert!(!r.all_channels_ok());
        assert_eq!(
            r.channel_health_snapshot().get("provider-b").copied(),
            Some(false),
            "the bucket whose client never built must remain registered as unhealthy"
        );

        // Re-registering, on a later call or a reload, must not clobber a healthy report.
        r.register_configured_channels(["provider-a", "provider-b"]);
        assert_eq!(
            r.channel_health_snapshot().get("provider-a").copied(),
            Some(true),
            "seeding must not reset a bucket that has already reported healthy"
        );
    }

    #[test]
    fn any_bucket_ok_distinguishes_a_blind_node_from_a_partially_healthy_one() {
        let r = Readiness::new();
        // A fresh node with no bucket reports yet is blind, because nothing reconciled.
        assert!(!r.any_bucket_ok());
        // Every configured bucket failing its startup reconcile leaves the node blind.
        r.set_channel_health("provider-a", false);
        r.set_channel_health("provider-b", false);
        assert!(!r.any_bucket_ok());
        // One bucket succeeding establishes visibility, even while another stays degraded.
        r.set_channel_health("provider-b", true);
        assert!(r.any_bucket_ok());
    }

    #[test]
    fn begin_shutdown_flips_the_draining_flag() {
        let r = Readiness::new();
        assert!(!r.is_shutting_down(), "not draining on a fresh node");
        // A clone observes the flip: the signal handler holds a clone, not `state`.
        let clone = r.clone();
        r.begin_shutdown();
        assert!(r.is_shutting_down());
        assert!(clone.is_shutting_down(), "draining is shared across clones");
    }

    #[test]
    fn health_serializes_in_kebab_case() {
        let v = serde_json::to_value(SubsystemHealth::NotConfigured).unwrap();
        assert_eq!(v, serde_json::Value::String("not-configured".to_owned()));
        let v = serde_json::to_value(ReconcileProgress::Pending).unwrap();
        assert_eq!(v, serde_json::Value::String("pending".to_owned()));
    }
}

#[cfg(test)]
mod readiness_metric_components_tests {

    /// The `gdi_health_ready{component}` label set is enumerated in two places in
    /// `docs/operating.md`, and nothing else ties either to the code. `at_rest` is the
    /// component that reports a master-key mismatch, so an alert row that omits it is the
    /// drift an operator would feel first.
    ///
    /// This reads the doc as data, so a component added to `HEALTH_READY_COMPONENTS` without
    /// updating both doc sites fails here.
    #[test]
    fn every_readiness_component_is_named_in_the_runbook() {
        let doc = include_str!("../../../docs/operating.md");
        // The two enumerations are pipe-separated alternations inside a table cell.
        let rows: Vec<&str> = doc
            .lines()
            // `∈` marks an enumeration of the label set, as opposed to prose citing a single
            // value such as `component="s3"`. Without it this matches a sentence and reports
            // every other component as omitted.
            .filter(|l| l.contains("gdi_health_ready") && l.contains('∈'))
            .collect();
        assert!(
            rows.len() >= 2,
            "expected at least two doc sites enumerating the component label; found {}. \
             The doc shape changed and this guard would be checking nothing.",
            rows.len()
        );
        for row in rows {
            for c in crate::metrics::HEALTH_READY_COMPONENTS {
                assert!(
                    row.contains(c),
                    "docs/operating.md enumerates the gdi_health_ready components but omits \
                     {c:?} in: {row}"
                );
            }
        }
    }

    /// Every subsystem `/health/ready` reports must have a `gdi_health_ready{component}`
    /// series.
    ///
    /// A hand-written list drifts from the struct it mirrors. If `at_rest` were missing, a
    /// PME master-key mismatch would drive `overall` to 0 with no component series saying
    /// which subsystem was unhappy, even though the struct carries it, the probe reports it
    /// and it gates readiness.
    #[test]
    fn every_readiness_subsystem_has_a_metric_component() {
        for want in [
            "overall",
            "initial_reconcile",
            "s3",
            "vault",
            "key_material",
            "at_rest",
        ] {
            assert!(
                crate::metrics::HEALTH_READY_COMPONENTS.contains(&want),
                "gdi_health_ready has no `{want}` component; \
                 HEALTH_READY_COMPONENTS = {:?}",
                crate::metrics::HEALTH_READY_COMPONENTS
            );
        }
    }
}
