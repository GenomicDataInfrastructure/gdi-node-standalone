//! Harvester-style BFS crawl over the live FAIR Data Point, mirroring the
//! `ckanext-fairdatapoint` harvester (the authoritative pySHACL/ckanext crawl
//! lives in the conformance harness).
//!
//! The harvester discovers datasets by crawling the FDP — not via any custom API —
//! fetching every resource as Turtle (`Accept: text/turtle`) and doing a
//! breadth-first walk that follows only `ldp:contains`: root -> catalogs ->
//! datasets. A dataset's distribution is not an `ldp:contains` child; it is
//! linked by `dcat:distribution` and dereferenced separately as its own graph
//! (the harvester's tested path).
//!
//! This test starts the router, crawls it exactly that way, classifies reached
//! nodes by `rdf:type`, and asserts:
//!
//! * the crawl reaches the visible COVID dataset and its distribution;
//! * the distribution's own graph carries `dcat:accessService` -> a
//!   `dcat:DataService` with the lowercase `dcat:endpointURL`;
//! * a hidden dataset is never reached.
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::collections::{BTreeSet, VecDeque};
use std::path::Path;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use gdi_node_standalone::app::build_router;
use gdi_node_standalone::identities::NodeIdentities;
use gdi_node_standalone::state::AppState;
use gdi_node_standalone_core::cache::StatusIndex;
use gdi_node_standalone_core::config::ServiceConfig;
use gdi_node_standalone_core::state::DatasetState;
use oxrdf::{NamedOrBlankNode, Term, Triple};
use tower::ServiceExt as _; // for `oneshot`

use crate::fixtures::ingest_covid_fdp;

const BASE_URL: &str = "https://test.example.org";
const VISIBLE_ID: &str = "GDI-EE-UTARTU-20260409143052837";
const HIDDEN_ID: &str = "GDI-EE-UTARTU-20260409143052999";
const CATALOG: &str = "gdi-aggregated";

// RDF IRIs the crawl turns on.
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const LDP_CONTAINS: &str = "http://www.w3.org/ns/ldp#contains";
const DCAT_DISTRIBUTION: &str = "http://www.w3.org/ns/dcat#distribution";
const DCAT_ACCESS_SERVICE: &str = "http://www.w3.org/ns/dcat#accessService";
const DCAT_ENDPOINT_URL: &str = "http://www.w3.org/ns/dcat#endpointURL";
const TYPE_FAIR_DATA_POINT: &str = "https://w3id.org/fdp/fdp-o#FAIRDataPoint";
const TYPE_CATALOG: &str = "http://www.w3.org/ns/dcat#Catalog";
const TYPE_DATASET: &str = "http://www.w3.org/ns/dcat#Dataset";
const TYPE_DISTRIBUTION: &str = "http://www.w3.org/ns/dcat#Distribution";
const TYPE_DATA_SERVICE: &str = "http://www.w3.org/ns/dcat#DataService";

/// A service config with `[fairdp]` and the `gdi-aggregated` catalog.
fn test_config(data_dir: &Path) -> ServiceConfig {
    let toml = format!(
        r#"
[service]
base_url = "{BASE_URL}"
data_dir = "{}"

[catalogs]
{CATALOG} = "Genome of Europe Aggregated Data"

[beacon]
aggregated_base_path = "/beacon/v2"
id = "org.test.beacon"
name = "Test Beacon"
environment = "test"

[beacon.organization]
id = "ee.ut.gdi"
name = "University of Tartu"

[fairdp]
title = "GDI Estonia FAIR Data Point"
issued = "2026-01-01T00:00:00Z"
license = "https://creativecommons.org/licenses/by/4.0/"
theme = ["http://publications.europa.eu/resource/authority/data-theme/HEAL"]
applicable_legislation = ["http://data.europa.eu/eli/reg/2025/327/oj"]

[fairdp.publisher]
name = "University of Tartu"
[fairdp.publisher.contact_point]
fn = "GDI Estonia"
has_email = "mailto:gdi@example.org"

[fairdp.hdab]
name = "Estonian HDAB"
[fairdp.hdab.contact_point]
fn = "Estonian HDAB"
has_email = "mailto:hdab@example.org"
"#,
        data_dir.display(),
    );
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    cfg.preflight().unwrap();
    cfg
}

/// Build an `AppState`: one visible + one hidden COVID dataset in `gdi-aggregated`.
fn state_with_fdp() -> (AppState, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let visible = ingest_covid_fdp(tmp.path(), &data_dir, VISIBLE_ID, DatasetState::Visible);
    let hidden = ingest_covid_fdp(tmp.path(), &data_dir, HIDDEN_ID, DatasetState::Hidden);
    let config = test_config(&data_dir);
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
    state.cache.insert(
        gdi_node_standalone_core::cache::StatusWrite::unshared(),
        visible,
    );
    state.cache.insert(
        gdi_node_standalone_core::cache::StatusWrite::unshared(),
        hidden,
    );
    (state, tmp)
}

/// Map an absolute resource IRI under `BASE_URL` to its request path (the harvester
/// dereferences absolute IRIs; in-process we strip the base to a path).
fn iri_to_path(iri: &str) -> Option<String> {
    iri.strip_prefix(BASE_URL).map(ToOwned::to_owned)
}

/// Fetch one resource as Turtle and parse it into a flat list of triples.
///
/// Returns `None` on a non-200 (e.g. a `/profile/` marker IRI that 404s, or a
/// hidden resource) — exactly what a crawler sees when a link does not dereference.
async fn fetch_turtle(router: &Router, path: &str) -> Option<Vec<Triple>> {
    let req = Request::builder()
        .method("GET")
        .uri(path)
        .header("accept", "text/turtle")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    if resp.status() != StatusCode::OK {
        return None;
    }
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let mut triples = Vec::new();
    for triple in oxttl::TurtleParser::new().for_slice(&bytes) {
        triples.push(triple.unwrap());
    }
    Some(triples)
}

/// The IRI string of a subject, if it is a named node (skip blank nodes).
fn subject_iri(subject: &NamedOrBlankNode) -> Option<&str> {
    match subject {
        NamedOrBlankNode::NamedNode(n) => Some(n.as_str()),
        NamedOrBlankNode::BlankNode(_) => None,
    }
}

/// The IRI string of an object term, if it is a named node.
fn object_iri(term: &Term) -> Option<&str> {
    match term {
        Term::NamedNode(n) => Some(n.as_str()),
        _ => None,
    }
}

/// Collect the object IRIs of `(subject, predicate, *)` triples in `graph`, keeping
/// only those whose subject is the named node `subject_filter`.
fn objects_of(graph: &[Triple], subject_filter: &str, predicate: &str) -> Vec<String> {
    graph
        .iter()
        .filter(|t| {
            subject_iri(&t.subject) == Some(subject_filter) && t.predicate.as_str() == predicate
        })
        .filter_map(|t| object_iri(&t.object).map(ToOwned::to_owned))
        .collect()
}

/// The set of `rdf:type` IRIs asserted on any subject in `graph`.
fn types_in(graph: &[Triple]) -> BTreeSet<String> {
    graph
        .iter()
        .filter(|t| t.predicate.as_str() == RDF_TYPE)
        .filter_map(|t| object_iri(&t.object).map(ToOwned::to_owned))
        .collect()
}

/// Whether the distribution `dist` in `graph` reaches an inline `dcat:DataService`
/// (a blank node) via `dcat:accessService`, and that service carries a lowercase
/// `dcat:endpointURL` — exactly what the harvester copies recursively.
fn has_inline_data_service_with_endpoint(graph: &[Triple], dist: &str) -> bool {
    // The blank-node objects the distribution links via dcat:accessService.
    let services: BTreeSet<&str> = graph
        .iter()
        .filter(|t| {
            subject_iri(&t.subject) == Some(dist) && t.predicate.as_str() == DCAT_ACCESS_SERVICE
        })
        .filter_map(|t| match &t.object {
            Term::BlankNode(b) => Some(b.as_str()),
            _ => None,
        })
        .collect();
    // At least one must be typed dcat:DataService and carry a lowercase endpointURL.
    services.iter().any(|svc| {
        let is_service = graph.iter().any(|t| {
            matches!(&t.subject, NamedOrBlankNode::BlankNode(b) if b.as_str() == *svc)
                && t.predicate.as_str() == RDF_TYPE
                && object_iri(&t.object) == Some(TYPE_DATA_SERVICE)
        });
        let has_endpoint = graph.iter().any(|t| {
            matches!(&t.subject, NamedOrBlankNode::BlankNode(b) if b.as_str() == *svc)
                && t.predicate.as_str() == DCAT_ENDPOINT_URL
        });
        is_service && has_endpoint
    })
}

#[tokio::test]
async fn harvester_bfs_crawl_reaches_visible_dataset_and_distribution() {
    let (state, _tmp) = state_with_fdp();
    let router = build_router(state);

    // Seed the BFS at the FDP root.
    let root = fetch_turtle(&router, "/fairdp")
        .await
        .expect("the FDP root must dereference");

    // The root must be typed fdp-o:FAIRDataPoint.
    assert!(
        types_in(&root).contains(TYPE_FAIR_DATA_POINT),
        "root is not typed fdp-o:FAIRDataPoint"
    );
    let root_iri = format!("{BASE_URL}/fairdp");

    // A breadth-first walk following `ldp:contains` only. Track the node types reached and
    // the IRIs of any dataset/distribution we touch.
    let mut queue: VecDeque<String> = VecDeque::new();
    let mut visited: BTreeSet<String> = BTreeSet::new();
    let mut reached_datasets: BTreeSet<String> = BTreeSet::new();
    let mut reached_distributions: BTreeSet<String> = BTreeSet::new();
    let mut reached_catalogs: BTreeSet<String> = BTreeSet::new();

    // The root graph is already fetched; enqueue its ldp:contains targets.
    for target in objects_of(&root, &root_iri, LDP_CONTAINS) {
        queue.push_back(target);
    }

    while let Some(iri) = queue.pop_front() {
        if !visited.insert(iri.clone()) {
            continue;
        }
        let Some(path) = iri_to_path(&iri) else {
            continue;
        };
        let Some(graph) = fetch_turtle(&router, &path).await else {
            // A non-dereferenceable link (e.g. a hidden resource or a /profile/
            // marker): the harvester skips it.
            continue;
        };
        let types = types_in(&graph);

        if types.contains(TYPE_CATALOG) {
            reached_catalogs.insert(iri.clone());
        }
        if types.contains(TYPE_DATASET) {
            reached_datasets.insert(iri.clone());

            // A dataset's distribution is not an `ldp:contains` child, so dereference it
            // separately via dcat:distribution (the harvester's tested path).
            for dist_iri in objects_of(&graph, &iri, DCAT_DISTRIBUTION) {
                let Some(dist_path) = iri_to_path(&dist_iri) else {
                    continue;
                };
                if let Some(dist_graph) = fetch_turtle(&router, &dist_path).await {
                    let dist_types = types_in(&dist_graph);
                    assert!(
                        dist_types.contains(TYPE_DISTRIBUTION),
                        "the dereferenced distribution {dist_iri} is not a dcat:Distribution"
                    );
                    // Its own graph carries the inline DataService (reached via
                    // dcat:accessService) with the lowercase endpointURL.
                    assert!(
                        has_inline_data_service_with_endpoint(&dist_graph, &dist_iri),
                        "distribution {dist_iri} lacks an inline dcat:DataService with dcat:endpointURL"
                    );
                    reached_distributions.insert(dist_iri);
                }
            }
        }

        // Continue the BFS through ldp:contains only.
        for target in objects_of(&graph, &iri, LDP_CONTAINS) {
            queue.push_back(target);
        }
    }

    // The visible dataset and its distribution were reached.
    let visible_dataset_iri = format!("{BASE_URL}/fairdp/dataset/{VISIBLE_ID}");
    let visible_dist_iri = format!("{BASE_URL}/fairdp/distribution/{VISIBLE_ID}");
    assert!(
        reached_catalogs.contains(&format!("{BASE_URL}/fairdp/catalog/{CATALOG}")),
        "crawl did not reach the catalog; reached {reached_catalogs:?}"
    );
    assert!(
        reached_datasets.contains(&visible_dataset_iri),
        "crawl did not reach the visible dataset; reached {reached_datasets:?}"
    );
    assert!(
        reached_distributions.contains(&visible_dist_iri),
        "crawl did not reach the visible distribution; reached {reached_distributions:?}"
    );

    // The hidden dataset was never reached (not under ldp:contains; would 404 even
    // if a stale link pointed at it).
    let hidden_dataset_iri = format!("{BASE_URL}/fairdp/dataset/{HIDDEN_ID}");
    let hidden_dist_iri = format!("{BASE_URL}/fairdp/distribution/{HIDDEN_ID}");
    assert!(
        !reached_datasets.contains(&hidden_dataset_iri),
        "crawl wrongly reached the hidden dataset"
    );
    assert!(
        !reached_distributions.contains(&hidden_dist_iri),
        "crawl wrongly reached the hidden distribution"
    );
}

/// Harvest-contract guard: the GDI User Portal harvester (`ckanext-fairdatapoint`)
/// follows `ldp:contains` only and does not follow Hydra pagination, so the catalog has to
/// enumerate every visible dataset's membership in a single Turtle response served
/// on a bare `Accept: text/turtle` GET. A paginated or truncated catalog listing would
/// silently stop the datasets beyond the first page from being harvested.
#[tokio::test]
async fn catalog_lists_all_visible_datasets_in_one_turtle_response() {
    const ID_A: &str = "GDI-EE-UTARTU-20260409143052837";
    const ID_B: &str = "GDI-EE-UTARTU-20260409143052838";

    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let a = ingest_covid_fdp(tmp.path(), &data_dir, ID_A, DatasetState::Visible);
    let b = ingest_covid_fdp(tmp.path(), &data_dir, ID_B, DatasetState::Visible);
    let config = test_config(&data_dir);
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
    state
        .cache
        .insert(gdi_node_standalone_core::cache::StatusWrite::unshared(), a);
    state
        .cache
        .insert(gdi_node_standalone_core::cache::StatusWrite::unshared(), b);
    let router = build_router(state);

    // The catalog returns 200 and Turtle on a bare `Accept: text/turtle` GET
    // (`fetch_turtle` returns `None` on any non-200).
    let catalog_path = format!("/fairdp/catalog/{CATALOG}");
    let graph = fetch_turtle(&router, &catalog_path)
        .await
        .expect("catalog must dereference to 200 Turtle for the harvester");

    // Both visible datasets are `ldp:contains` members in the single response, with no paging.
    let catalog_iri = format!("{BASE_URL}/fairdp/catalog/{CATALOG}");
    let members = objects_of(&graph, &catalog_iri, LDP_CONTAINS);
    for id in [ID_A, ID_B] {
        let dataset_iri = format!("{BASE_URL}/fairdp/dataset/{id}");
        assert!(
            members.contains(&dataset_iri),
            "catalog ldp:contains must list {dataset_iri} in one response; got {members:?}"
        );
    }
}
