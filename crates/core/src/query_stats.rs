//! Per-dataset query counters for the management-plane `GET /stats/queries` endpoint.
//!
//! Answers "does anyone use this dataset?" without standing up a log pipeline. The
//! aggregate Prometheus series are content-free, never carrying a per-dataset-id label,
//! and the per-dataset attribution that does exist is locked inside the compliance audit
//! stream.
//!
//! Four counters per dataset, all since boot, in memory, and monotonic within a boot. See
//! [`DatasetQueryStats`]. `startedAt` on the snapshot is the boot identity a consumer
//! needs to detect a reset: it is the node's process start, not a config-reload stamp, so
//! a poller differencing two snapshots can tell "counters advanced" from "the node
//! restarted and started over".
//!
//! This is a management-plane disclosure, not a metrics one. Per-dataset counts name ids,
//! including hidden ones, so they live only on the flag-gated management route
//! (`[stats].enabled`, default off), next to the state oracle that discloses the same
//! class of fact. They never appear in `/metrics`, whose labels stay content-free.
//!
//! The recording side ([`QueryStats`]) is a plain `Mutex<BTreeMap>`: every call site is a
//! synchronous function on the answer path, so the guard cannot be held across an
//! `.await`, and the critical section is a handful of integer adds.

use std::collections::BTreeMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// The `schemaVersion` stamped on every `GET /stats/queries` response.
pub const QUERY_STATS_SCHEMA_VERSION: u32 = 1;

/// One dataset's usage counters, all counted since the node process started.
///
/// Monotonic within a boot: a consumer differencing two snapshots with the same
/// `startedAt` may treat `current - previous` as the traffic between them, and a negative
/// difference as a bug rather than a reset.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct DatasetQueryStats {
    /// How often this dataset was in the selection set of an answered `g_variants` query,
    /// at any granularity. This is the same set the audit line records as its
    /// `dataset_ids`. A query rejected before dataset resolution carries no attribution and
    /// is not counted.
    pub consulted: u64,
    /// How often this dataset itself matched, meaning `exists = true` for this dataset
    /// rather than for the query as a whole. At `boolean` and `count` granularity the
    /// per-dataset outcome never reaches the wire, so this is the only place it is visible.
    pub hit: u64,
    /// How often this dataset appeared in the served page of a Beacon `/datasets` response.
    /// A dataset beyond the requested page was not listed, so it is not counted.
    pub listed: u64,
    /// How often this dataset's FAIR Data Point record was read, at `/fairdp/dataset/{id}`
    /// or `/fairdp/distribution/{id}`. Catalog-level reads are catalog-keyed, not
    /// dataset-keyed, and are not counted.
    pub fairdp_reads: u64,
}

/// A point-in-time snapshot of every dataset's counters: the `GET /stats/queries` body.
///
/// `startedAt` is the boot identity: it changes exactly when the process restarted and the
/// counters therefore restarted from zero. Entries for erased datasets persist until
/// restart, at four integers per dataset served this boot.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct QueryStatsSnapshot {
    /// Discriminator for the response shape; `1` today.
    pub schema_version: u32,
    /// When the node process started (RFC3339, node clock), not when its config was last
    /// reloaded. A consumer keys reset detection on this, so a reload must not change it.
    pub started_at: String,
    /// When this snapshot was taken (RFC3339, node clock).
    pub as_of: String,
    /// Counters keyed by dataset id, including ids that are currently hidden. This is the
    /// same disclosure class as the management plane's per-dataset state oracle.
    pub datasets: BTreeMap<String, DatasetQueryStats>,
}

/// One dataset's outcome in a single answered `g_variants` query.
///
/// Both granularity paths produce this, so `consulted` and `hit` derive from one value and
/// cannot disagree. The query-wide `responseSummary.exists` is an OR across datasets, so
/// attributing it per dataset would count a miss beside a hit as a hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetOutcome {
    /// The consulted dataset's id.
    pub id: String,
    /// Whether this dataset itself matched.
    pub hit: bool,
}

/// The in-memory per-dataset counters behind `GET /stats/queries`.
///
/// Recording is a no-op when the feature is disabled, so a call site cannot forget the
/// flag: the flag is read once, here, and every recorder short-circuits on it. That also
/// means a node that never opted in pays neither the lock nor the map.
#[derive(Debug)]
pub struct QueryStats {
    /// `[stats].enabled` — read once at construction.
    enabled: bool,
    /// The counters. A `Mutex`, not an `RwLock`: writes happen on every answered query and
    /// reads only when the endpoint is polled.
    datasets: Mutex<BTreeMap<String, DatasetQueryStats>>,
}

impl QueryStats {
    /// A registry that records only when `enabled`.
    #[must_use]
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            datasets: Mutex::new(BTreeMap::new()),
        }
    }

    /// Add one to `counter` for each named dataset, under one short critical section.
    ///
    /// The single lock-taking site: every recorder funnels through it, so "the guard is
    /// never held across an `.await`" is a property of one function, and so is the disabled
    /// short-circuit. A poisoned lock is recovered rather than propagated, because usage
    /// counters must never be the reason a query path fails.
    fn bump<'a>(
        &self,
        ids: impl IntoIterator<Item = &'a str>,
        counter: impl Fn(&mut DatasetQueryStats) -> &mut u64,
    ) {
        if !self.enabled {
            return;
        }
        let mut guard = self
            .datasets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for id in ids {
            let entry = guard.entry(id.to_owned()).or_default();
            let slot = counter(entry);
            *slot = slot.saturating_add(1);
        }
    }

    /// Record one answered `g_variants` query: every outcome's dataset was `consulted`, and
    /// those that matched were also `hit`.
    ///
    /// `consulted` is bumped first, so a snapshot taken between the two passes still
    /// satisfies `hit <= consulted`, the one relation a consumer may assume.
    pub fn record_query(&self, outcomes: &[DatasetOutcome]) {
        self.bump(outcomes.iter().map(|o| o.id.as_str()), |e| &mut e.consulted);
        self.bump(
            outcomes.iter().filter(|o| o.hit).map(|o| o.id.as_str()),
            |e| &mut e.hit,
        );
    }

    /// Record the served page of one Beacon `/datasets` response.
    pub fn record_listing(&self, ids: &[String]) {
        self.bump(ids.iter().map(String::as_str), |e| &mut e.listed);
    }

    /// Record one FAIR Data Point dataset/distribution read.
    pub fn record_fairdp_read(&self, id: &str) {
        self.bump(std::iter::once(id), |e| &mut e.fairdp_reads);
    }

    /// The current counters, stamped with the caller-supplied process-start time.
    ///
    /// `started_at` is passed in rather than captured here, so the node has one
    /// process-start fact (the readiness view's) rather than two that could disagree.
    #[must_use]
    pub fn snapshot(&self, started_at: &str) -> QueryStatsSnapshot {
        let datasets = self
            .datasets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        QueryStatsSnapshot {
            schema_version: QUERY_STATS_SCHEMA_VERSION,
            started_at: started_at.to_owned(),
            as_of: crate::util::now_rfc3339(),
            datasets,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DatasetOutcome, QueryStats};

    const A: &str = "GDI-EE-UTARTU-1";
    const B: &str = "GDI-EE-UTARTU-2";

    fn outcome(id: &str, hit: bool) -> DatasetOutcome {
        DatasetOutcome {
            id: id.to_owned(),
            hit,
        }
    }

    /// One query over two datasets where only one matched: both are `consulted`, only the
    /// matching one is `hit`.
    ///
    /// An implementation that attributed the query-wide `exists` to every consulted dataset
    /// passes every single-dataset test and fails here. The `boolean`/`count` path invites
    /// that mistake, because only the OR-ed answer reaches the wire.
    #[test]
    fn a_hit_is_attributed_to_the_dataset_that_matched_not_the_query() {
        let stats = QueryStats::new(true);
        stats.record_query(&[outcome(A, true), outcome(B, false)]);

        let snap = stats.snapshot("2026-08-10T00:00:00Z");
        assert_eq!(snap.datasets[A].consulted, 1);
        assert_eq!(snap.datasets[A].hit, 1);
        assert_eq!(snap.datasets[B].consulted, 1, "B was consulted");
        assert_eq!(
            snap.datasets[B].hit, 0,
            "B did not match, so it is not a hit"
        );
    }

    /// Counters accumulate across queries, and the three sources are independent.
    #[test]
    fn the_four_counters_accumulate_independently() {
        let stats = QueryStats::new(true);
        stats.record_query(&[outcome(A, true)]);
        stats.record_query(&[outcome(A, false)]);
        stats.record_listing(&[A.to_owned(), B.to_owned()]);
        stats.record_fairdp_read(A);
        stats.record_fairdp_read(A);

        let snap = stats.snapshot("2026-08-10T00:00:00Z");
        let a = snap.datasets[A];
        assert_eq!((a.consulted, a.hit, a.listed, a.fairdp_reads), (2, 1, 1, 2));
        let b = snap.datasets[B];
        assert_eq!((b.consulted, b.hit, b.listed, b.fairdp_reads), (0, 0, 1, 0));
    }

    /// With the feature off nothing is recorded at all, rather than recorded but unserved.
    ///
    /// Asserted per recorder rather than once: a short-circuit reaching only two of the
    /// three call paths would still pass a test that issues a query alone.
    #[test]
    fn a_disabled_registry_records_nothing_from_any_source() {
        let stats = QueryStats::new(false);
        stats.record_query(&[outcome(A, true)]);
        stats.record_listing(&[A.to_owned()]);
        stats.record_fairdp_read(A);

        assert!(
            stats.snapshot("2026-08-10T00:00:00Z").datasets.is_empty(),
            "a node that did not opt in must not pay the map either"
        );
    }

    /// The snapshot carries the caller's process-start stamp verbatim, the boot identity a
    /// poller keys reset detection on, plus the current schema version.
    #[test]
    fn the_snapshot_echoes_the_supplied_boot_stamp() {
        let stats = QueryStats::new(true);
        let snap = stats.snapshot("2026-08-10T09:00:00Z");
        assert_eq!(snap.started_at, "2026-08-10T09:00:00Z");
        assert_eq!(snap.schema_version, super::QUERY_STATS_SCHEMA_VERSION);
        assert!(
            snap.as_of.ends_with('Z'),
            "as_of is RFC3339 UTC: {}",
            snap.as_of
        );
    }
}
