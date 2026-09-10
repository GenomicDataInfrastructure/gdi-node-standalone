//! The management-plane catalog listing (`GET /catalogs`).
//!
//! Plain JSON for an integrating system: the `[catalogs]` table, without parsing the FDP
//! root's JSON-LD. A manifest's `metadata.catalog` must name one of these ids for this node
//! to accept the package. The table comes from the same reloadable snapshot as `/fairdp`, so
//! a catalog added by `SIGHUP` or `POST /reload` appears on both at once. Always mounted and
//! never audited, because the same table is already public on the FDP root; the id-keyed
//! `/datasets` and `/stats/queries` are not.
//!
//! The body is [`CatalogList`], published as `docs/catalogs.schema.json`:
//!
//! ```json
//! {"catalogs": [{"id": "gdi-aggregated", "title": "Genome of Europe Aggregated Data"}]}
//! ```

use axum::Json;
use axum::extract::State;
use axum::response::{IntoResponse as _, Response};
use gdi_node_standalone_core::catalogs::CatalogList;

use crate::state::AppState;

/// `GET /catalogs` — every configured catalog, sorted by id; always `200`.
pub(crate) async fn catalogs(State(state): State<AppState>) -> Response {
    // The same reloadable snapshot `/fairdp` reads, so the two surfaces cannot list
    // different catalogs.
    let reloadable = state.reloadable();
    Json(CatalogList::from_config(&reloadable.catalogs)).into_response()
}
