//! The management-plane per-dataset query-statistics endpoint.
//!
//! `GET /stats/queries` reports how much each dataset is used, so answering that needs
//! `curl` on the management port rather than a log pipeline over the audit stream. Mounted
//! only when `[stats].enabled` is set; otherwise the route does not exist and the plane
//! answers `404`, indistinguishable from a node too old to serve it.
//!
//! The counters are keyed by dataset id, hidden ids included, so they disclose as much as
//! `GET /datasets/{id}/state` and belong on the management plane only. The same data must
//! never become a `/metrics` label: a scrape target is cheap to grant, so a dataset-id
//! label would carry the enumeration well beyond this plane.
//!
//! The body is
//! [`QueryStatsSnapshot`](gdi_node_standalone_core::query_stats::QueryStatsSnapshot),
//! published as `docs/query-stats.schema.json`:
//!
//! ```json
//! {
//!   "schemaVersion": 1,
//!   "startedAt": "2026-08-07T09:00:00Z",
//!   "asOf": "2026-08-07T12:34:56Z",
//!   "datasets": {
//!     "GDI-EE-EXAMPLE-1751234567890": {"consulted": 152, "hit": 37, "listed": 12, "fairdpReads": 9}
//!   }
//! }
//! ```

use axum::Json;
use axum::extract::State;
use axum::response::{IntoResponse as _, Response};

use crate::state::AppState;

/// `GET /stats/queries` — every dataset's usage counters since this process started.
///
/// Always `200` when mounted; an empty `datasets` map is the answer for a node that has
/// served no query yet. Counters live in memory and reset on restart, so `startedAt` is part
/// of the contract: a poller differencing two snapshots needs it to tell a restart from a
/// quiet interval.
pub(crate) async fn query_stats(State(state): State<AppState>) -> Response {
    // The readiness view owns the node's only process-start stamp, so the two cannot
    // disagree.
    let snapshot = state.query_stats.snapshot(state.readiness.started_at());
    // Keyed by dataset id, hidden ones included, so this discloses the inventory as
    // `GET /datasets` does, and is audited on the same terms.
    let ids: Vec<String> = snapshot.datasets.keys().cloned().collect();
    crate::audit::query_stats_read(&state.config.audit, snapshot.datasets.len(), &ids);
    Json(snapshot).into_response()
}
