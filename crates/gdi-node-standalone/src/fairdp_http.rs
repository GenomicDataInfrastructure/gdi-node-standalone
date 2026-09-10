//! FAIR Data Point HTTP handlers for the service binary.
//!
//! The `fairdp` crate stays a pure, axum-free library (model -> `oxrdf::Graph` ->
//! Turtle/JSON-LD). This module is the thin axum glue that builds an [`FdpContext`]
//! from [`AppState`], selects the visible datasets, calls the library's graph
//! builders, and content-negotiates the serialization.
//!
//! The resource hierarchy served here:
//!
//! * `GET /fairdp` — the FDP root over all configured catalogs, each with its
//!   visible datasets;
//! * `GET /fairdp/catalog/{id}` — one configured catalog (404 if not configured);
//! * `GET /fairdp/dataset/{id}` — one visible dataset (404 otherwise);
//! * `GET /fairdp/distribution/{id}` — that dataset's distribution (404 unless
//!   visible).
//!
//! `/fairdp/profile/{service|catalog}` has no route: the `dct:conformsTo` marker IRIs
//! are opaque and non-dereferenceable, so they 404.
//!
//! FDP is optional (the beacon is required): with no `[fairdp]` config every route
//! here returns 404.

use axum::extract::{Path, State};
use axum::http::header::{ACCEPT, CONTENT_TYPE, VARY};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use gdi_node_standalone_core::cache::DatasetEntry;
use gdi_node_standalone_core::config::{FairdpConfig, ServiceConfig};
use gdi_node_standalone_core::state::DatasetState;
use gdi_node_standalone_fairdp::{
    CatalogListing, FdpContext, catalog_graph, dataset_graph, distribution_graph, fdp_root_graph,
    serialize_jsonld, serialize_turtle,
};
use oxrdf::Graph;

use crate::id_guard::{is_safe_catalog_name, is_safe_dataset_id};
use crate::state::AppState;

/// The Turtle content type the harvester asks for and the node renders (the primary
/// format).
const TURTLE: &str = "text/turtle";
/// The JSON-LD content type for the secondary (default) format.
const JSON_LD: &str = "application/ld+json";

/// The negotiated RDF serialization for one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    /// `text/turtle` (primary; the harvester's `Accept`).
    Turtle,
    /// `application/ld+json` (secondary; the default when no specific RDF type is
    /// requested).
    JsonLd,
}

/// Pick the response [`Format`] from the request's `Accept` header.
///
/// Turtle wins when `text/turtle` (or its `application/x-turtle` alias) is present
/// anywhere in the header; anything else falls back to JSON-LD, the spec's default
/// "when no specific RDF type is requested". Exact q-value ordering is not honoured.
/// Turtle is preferred whenever it is offered, matching the harvester's single-type
/// `Accept: text/turtle`.
fn negotiate(headers: &HeaderMap) -> Format {
    let accept = headers
        .get(ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    if accept.contains("text/turtle") || accept.contains("application/x-turtle") {
        Format::Turtle
    } else {
        Format::JsonLd
    }
}

/// Serialize `graph` in the negotiated `format` and render it as a `200` with the
/// matching `Content-Type`.
///
/// Two conditions are internal-invariant violations, rendered as a logged and counted
/// `500` rather than a `200` a harvester would mistake for an empty-but-valid resource:
///
/// * A zero-triple graph. Every FDP builder emits at least the resource's own
///   `rdf:type`, so an empty graph means a builder regression. The check reads the
///   graph, not the body, because the serializers disagree about what an empty graph
///   looks like: oxttl omits the `@prefix` prologue when no triple is written, so Turtle
///   yields `""`, while oxjsonld always emits its `{"@context":…,"@graph":[]}` envelope.
/// * An empty body. The serializers return an empty string only when RDF serialization
///   fails.
fn render(graph: &Graph, format: Format, resource: &'static str) -> Response {
    // The serialisation leg gets its own child span, so a slow Turtle or JSON-LD render
    // is visible in the trace instead of folded into the request span.
    let _span = tracing::info_span!("fdp_render", resource).entered();
    let (content_type, body) = match format {
        Format::Turtle => (format!("{TURTLE}; charset=utf-8"), serialize_turtle(graph)),
        Format::JsonLd => (format!("{JSON_LD}; charset=utf-8"), serialize_jsonld(graph)),
    };
    if graph.is_empty() || body.is_empty() {
        // `triples` separates the two causes in the log: 0 is a builder regression,
        // non-zero is a serializer failure.
        tracing::error!(
            ?format,
            triples = graph.len(),
            "FDP RDF render produced no servable document; returning 500"
        );
        // A dedicated counter, not just the 5xx bucket, so a serializer regression on
        // this internal-invariant path is page-able.
        crate::metrics::fairdp_serialization_failure();
        return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
    }
    // The body is content-negotiated on `Accept`, so advertise `Vary: Accept`: a shared
    // cache must key on it rather than serve one format to a client that asked for the
    // other.
    (
        StatusCode::OK,
        [(CONTENT_TYPE, content_type), (VARY, "accept".to_owned())],
        body,
    )
        .into_response()
}

/// The plain `404 Not Found` returned when FDP is unconfigured or a resource is absent
/// or hidden. FDP is not Beacon, so it does not use the `beaconErrorResponse` envelope;
/// a bare status plus text is the LDP-appropriate response.
///
/// The shared resilience-layer errors (load-shed `503`, request-timeout `408`,
/// URI-cap `414`, caught-panic `500`) answer in this same dialect under `/fairdp`:
/// those layers run outside the routed mounts, so `crate::app`'s
/// `render_synthesized_errors` decides the dialect from the request path.
fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found").into_response()
}

/// The FDP mount's unmatched-path fallback: an unknown path under `/fairdp`, including
/// the unrouted `/fairdp/profile/{service|catalog}` conformsTo markers, answers like a
/// real FDP miss with [`not_found`]'s bare `text/plain`, not the Beacon envelope.
pub(crate) async fn not_found_fallback() -> Response {
    not_found()
}

/// Build the [`FdpContext`] from the (present) `[fairdp]` config and the service's
/// `base_url` + beacon `aggregated_base_path`.
fn context<'a>(config: &'a ServiceConfig, fairdp: &'a FairdpConfig) -> FdpContext<'a> {
    FdpContext::new(
        &config.service.base_url,
        &config.beacon.aggregated_base_path,
        fairdp,
    )
}

/// `GET /fairdp` — the FDP root over all configured catalogs.
///
/// Lists every configured catalog (stable URIs, even empty ones) with its visible
/// datasets; the library derives the data-stable `metadataModified`.
pub(crate) async fn root(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let config = &state.config;
    // FDP is optional: a node without `[fairdp]` serves no FDP (404 everywhere).
    let Some(fairdp) = config.fairdp.as_ref() else {
        return not_found();
    };
    let ctx = context(config, fairdp);
    // The served catalog list reads the SIGHUP-reloadable snapshot, not the immutable
    // boot config, so a catalog added by a live reload appears here (and at
    // `/fairdp/catalog/{id}`) without a restart. Kept alive for the whole handler:
    // `listings` below borrows from it.
    let reloadable = state.reloadable();

    // Cloned once; references into it back the per-catalog listings for this request.
    let visible = state.fresh_visible_datasets();
    // Bucket visible datasets by catalog in one pass, O(datasets), instead of rescanning
    // every visible dataset once per configured catalog, O(catalogs × datasets).
    let mut by_catalog: std::collections::BTreeMap<&str, Vec<&DatasetEntry>> =
        std::collections::BTreeMap::new();
    for d in &visible {
        by_catalog
            .entry(d.metadata.catalog.as_str())
            .or_default()
            .push(d.as_ref());
    }
    // One CatalogListing per configured catalog, each carrying its visible datasets
    // (empty when no dataset declares that catalog).
    let listings: Vec<CatalogListing> = reloadable
        .catalogs
        .iter()
        .map(|(id, title)| CatalogListing {
            id,
            title,
            visible_datasets: by_catalog.get(id.as_str()).cloned().unwrap_or_default(),
        })
        .collect();

    let graph = fdp_root_graph(&listings, &ctx);
    crate::audit::fairdp_read(&config.audit, "root", "", visible.len());
    render(&graph, negotiate(&headers), "root")
}

/// `GET /fairdp/catalog/{id}` — one configured catalog with its visible datasets.
///
/// `404` when `{id}` is not a configured catalog (its title is the `[catalogs]`
/// display value).
pub(crate) async fn catalog(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let config = &state.config;
    // Boundary validation: reject a traversal-shaped / NUL / overlong catalog name
    // before any lookup (defence in depth).
    if !is_safe_catalog_name(&id) {
        return not_found();
    }
    // FDP is optional: a node without `[fairdp]` serves no FDP (404 everywhere).
    let Some(fairdp) = config.fairdp.as_ref() else {
        return not_found();
    };
    // Which ids count as configured catalogs reads the SIGHUP-reloadable snapshot; see
    // the `root` handler above.
    let reloadable = state.reloadable();
    let Some(title) = reloadable.catalogs.get(&id) else {
        return not_found();
    };
    let ctx = context(config, fairdp);

    let visible = state.fresh_visible_datasets();
    let datasets: Vec<&DatasetEntry> = visible
        .iter()
        .filter(|d| d.metadata.catalog == id)
        .map(AsRef::as_ref)
        .collect();

    let graph = catalog_graph(&id, title, &datasets, &ctx);
    crate::audit::fairdp_read(&config.audit, "catalog", &id, datasets.len());
    render(&graph, negotiate(&headers), "catalog")
}

/// The shared body of the two single-visible-dataset FDP resources
/// (`/fairdp/dataset/{id}` and `/fairdp/distribution/{id}`): boundary-validate `id`,
/// require FDP to be configured and the dataset to be currently visible, then render
/// `build`'s graph under `kind`, the audit label. `404` for a bad id, unconfigured FDP,
/// or an absent, hidden or errored dataset. The two resources differ only in the graph
/// builder and the audit `kind`.
fn single_visible_resource(
    state: &AppState,
    id: &str,
    headers: &HeaderMap,
    kind: &'static str,
    build: impl FnOnce(&DatasetEntry, &FdpContext<'_>) -> Graph,
) -> Response {
    let config = &state.config;
    // Boundary validation: reject a traversal-shaped / NUL / overlong id before any
    // lookup (defence in depth).
    if !is_safe_dataset_id(id) {
        return not_found();
    }
    // FDP is optional: a node without `[fairdp]` serves no FDP (404 everywhere).
    let Some(fairdp) = config.fairdp.as_ref() else {
        return not_found();
    };
    let Some(entry) = visible_entry(state, id) else {
        return not_found();
    };
    let ctx = context(config, fairdp);
    let graph = build(&entry, &ctx);
    crate::audit::fairdp_read(&config.audit, kind, id, 1);
    // `fairdpReads` is counted in the shared body of both single-dataset resources so a
    // third one cannot omit it. The catalog handler does not count: a catalog-keyed read
    // attributed to every dataset it contains would inflate the impact number a provider
    // reads as demand for their dataset. A no-op unless `[stats].enabled`.
    state.query_stats.record_fairdp_read(id);
    render(&graph, negotiate(headers), kind)
}

/// `GET /fairdp/dataset/{id}` — one visible dataset record.
///
/// `404` when the id is absent, hidden, or in error. The FDP only exposes visible
/// datasets.
pub(crate) async fn dataset(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    single_visible_resource(&state, &id, &headers, "dataset", dataset_graph)
}

/// `GET /fairdp/distribution/{id}` — the distribution record for a visible dataset
/// (its own dereferenceable graph; `404` unless the dataset is visible).
pub(crate) async fn distribution(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    single_visible_resource(&state, &id, &headers, "distribution", distribution_graph)
}

/// Fetch a single dataset by id, only if it is currently visible, returning a deep
/// clone of the single [`DatasetEntry`]. Cheaper than cloning the whole visible set,
/// unlike `visible_datasets`, which only bumps each entry's Arc refcount.
fn visible_entry(state: &AppState, id: &str) -> Option<DatasetEntry> {
    // O(1) single-entry lookup plus visibility check, rather than cloning the whole
    // visible-dataset set per request just to `find` one. `state == Visible` is not the
    // serving gate on its own, so this applies the same predicate as
    // `AppState::fresh_visible_datasets` to a single entry; otherwise these handlers
    // would serve a dataset every other visible-dataset path withholds.
    state
        .cache
        .get(id)
        .filter(|d| d.state == DatasetState::Visible)
        .filter(|d| !state.withheld_from_public(&d.id, d.state))
}

#[cfg(test)]
mod tests {
    use super::{Format, render};
    use axum::http::StatusCode;
    use oxrdf::Graph;

    /// A zero-triple graph must never be served as a `200`, in either format.
    ///
    /// Every FDP builder emits at least the resource's own `rdf:type`, so an empty graph
    /// is an internal-invariant violation, not a legitimate empty resource. A body-only
    /// check would miss it: oxjsonld always emits its `{"@context":…,"@graph":[]}`
    /// envelope, so on the format `negotiate` defaults to, a zero-triple graph would
    /// render as a `200` a harvester ingests as "this catalog is empty".
    #[test]
    fn an_empty_graph_is_a_500_in_both_formats() {
        for format in [Format::JsonLd, Format::Turtle] {
            let response = render(&Graph::new(), format, "root");
            assert_eq!(
                response.status(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "a zero-triple graph must render as 500, not 200, in {format:?}"
            );
        }
    }
}
