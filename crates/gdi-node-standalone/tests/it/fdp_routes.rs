//! Integration tests for the FAIR Data Point HTTP surface mounted in the service
//! binary: the four LDP resources (`/fairdp`, `/fairdp/catalog/{id}`,
//! `/fairdp/dataset/{id}`, `/fairdp/distribution/{id}`), their Turtle/JSON-LD
//! content negotiation, the visibility filtering (hidden datasets are absent), and
//! the FDP-is-optional gate (no `[fairdp]` gives a 404). Driven in-process via
//! `tower::ServiceExt::oneshot` against a router built from a real `AppState`, as
//! `beacon_query.rs` is.
//!
//! The harvester-style BFS crawl over the live FDP is a separate test
//! (`fdp_crawl.rs`).
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::path::Path;

use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode};
use gdi_node_standalone::app::build_router;
use gdi_node_standalone::identities::NodeIdentities;
use gdi_node_standalone::state::AppState;
use gdi_node_standalone_core::cache::{DatasetProvenance, StatusEntry, StatusIndex};
use gdi_node_standalone_core::config::ServiceConfig;
use gdi_node_standalone_core::state::DatasetState;
use tower::ServiceExt as _; // for `oneshot`

use crate::fixtures::ingest_covid_fdp;

const VISIBLE_ID: &str = "GDI-EE-UTARTU-20260409143052837";
const HIDDEN_ID: &str = "GDI-EE-UTARTU-20260409143052999";
const CATALOG: &str = "gdi-aggregated";

/// A service config with a complete `[fairdp]` block and the `gdi-aggregated`
/// catalog. With `fairdp = false` the `[fairdp]` block is omitted (FDP disabled).
fn test_config(data_dir: &Path, fairdp: bool) -> ServiceConfig {
    let fairdp_block = if fairdp {
        r#"
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
"#
    } else {
        ""
    };
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
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
{fairdp_block}
"#,
        data_dir.display(),
    );
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    cfg.preflight().unwrap();
    cfg
}

/// Build an `AppState`: one visible COVID dataset in `gdi-aggregated`, one hidden
/// COVID dataset (must never appear in the FDP). `fairdp` toggles the `[fairdp]`
/// config so the no-FDP gate can be exercised.
fn state_with_fdp(fairdp: bool) -> (AppState, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();

    let visible = ingest_covid_fdp(tmp.path(), &data_dir, VISIBLE_ID, DatasetState::Visible);
    let hidden = ingest_covid_fdp(tmp.path(), &data_dir, HIDDEN_ID, DatasetState::Hidden);

    let config = test_config(&data_dir, fairdp);
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

/// Issue a `GET` for `uri` with an optional `Accept` header.
async fn get(state: AppState, uri: &str, accept: Option<&str>) -> (StatusCode, String, String) {
    let router = build_router(state);
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(a) = accept {
        builder = builder.header("accept", a);
    }
    let req = builder.body(Body::empty()).unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let body = String::from_utf8(bytes.to_vec()).unwrap();
    (status, content_type, body)
}

#[test]
fn fairdp_read_emits_audit_line() {
    use tracing_subscriber::layer::SubscriberExt as _;

    // Keep the thread-local capture reliable under the parallel harness. The FDP handlers are
    // synchronous, so the audit line is emitted on the request thread.
    crate::fixtures::ensure_capture_safe_tracing();

    let (state, _tmp) = state_with_fdp(true);
    let router = build_router(state);

    let writer = test_util::CaptureWriter::new();
    let make = {
        let w = writer.clone();
        move || w.clone()
    };
    let subscriber = tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().json().with_writer(make));

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    tracing::subscriber::with_default(subscriber, || {
        rt.block_on(async {
            // The FDP root (catalog listing): a harvest surface that must leave a trail, and
            // the FDP mirror of the beacon `datasets` enumeration.
            let req = Request::builder()
                .method("GET")
                .uri("/fairdp")
                .body(Body::empty())
                .unwrap();
            assert_eq!(
                router.clone().oneshot(req).await.unwrap().status(),
                StatusCode::OK
            );

            // A single visible dataset record.
            let req = Request::builder()
                .method("GET")
                .uri(format!("/fairdp/dataset/{VISIBLE_ID}"))
                .body(Body::empty())
                .unwrap();
            assert_eq!(
                router.clone().oneshot(req).await.unwrap().status(),
                StatusCode::OK
            );
        });
    });

    let out = writer.contents();
    assert!(
        out.contains("fairdp_read"),
        "fairdp audit event present: {out}"
    );
    assert!(
        out.contains("\"resource\":\"root\""),
        "root read tagged: {out}"
    );
    assert!(
        out.contains("\"resource\":\"dataset\""),
        "dataset read tagged: {out}"
    );
    assert!(out.contains("fairdp-client"), "fairdp actor present: {out}");
}

#[tokio::test]
async fn root_as_turtle_lists_catalog() {
    let (state, _tmp) = state_with_fdp(true);
    let (status, content_type, body) = get(state, "/fairdp", Some("text/turtle")).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        content_type.starts_with("text/turtle"),
        "content-type was {content_type}"
    );
    // FDP root triples: it is a FAIRDataPoint and ldp:contains the catalog.
    assert!(
        body.contains("fdp-o:FAIRDataPoint") || body.contains("FAIRDataPoint"),
        "root must be typed fdp-o:FAIRDataPoint; body:\n{body}"
    );
    assert!(
        body.contains(&format!("/fairdp/catalog/{CATALOG}")),
        "root must ldp:contain the catalog; body:\n{body}"
    );
}

#[tokio::test]
async fn fdp_responses_advertise_vary_accept() {
    // The FDP body is content-negotiated on `Accept` (Turtle vs JSON-LD), so the
    // response must carry `Vary: accept` for shared-cache correctness.
    let (state, _tmp) = state_with_fdp(true);
    let router = build_router(state);
    let req = Request::builder()
        .method("GET")
        .uri("/fairdp")
        .header("accept", "text/turtle")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let vary = resp
        .headers()
        .get("vary")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        vary.eq_ignore_ascii_case("accept"),
        "FDP responses must send `Vary: accept`; got {vary:?}"
    );
}

/// Collect every string carried under `key` (`@id` or `@type`) anywhere in a JSON-LD
/// document, handling the string, array-of-string and array-of-`{"@id": …}` forms. This lets a
/// test bind assertions to the `@id` and `@type` slots structurally, rather than
/// substring-matching serialized bytes that change with whitespace and key order.
fn collect_ld_strings(v: &serde_json::Value, key: &str, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Object(map) => {
            if let Some(found) = map.get(key) {
                match found {
                    serde_json::Value::String(s) => out.push(s.clone()),
                    serde_json::Value::Array(arr) => {
                        for e in arr {
                            if let Some(s) = e.as_str() {
                                out.push(s.to_owned());
                            } else if let Some(s) = e.get("@id").and_then(serde_json::Value::as_str)
                            {
                                out.push(s.to_owned());
                            }
                        }
                    }
                    _ => {}
                }
            }
            for child in map.values() {
                collect_ld_strings(child, key, out);
            }
        }
        serde_json::Value::Array(arr) => {
            for e in arr {
                collect_ld_strings(e, key, out);
            }
        }
        _ => {}
    }
}

#[tokio::test]
async fn root_as_jsonld_default() {
    // Types may be expressed by the JSON-LD `@type` keyword or by the expanded `rdf:type`
    // predicate, which this serializer uses, so collect both.
    const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";

    let (state, _tmp) = state_with_fdp(true);
    // application/ld+json explicitly.
    let (status, content_type, body) = get(state, "/fairdp", Some("application/ld+json")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        content_type.starts_with("application/ld+json"),
        "content-type was {content_type}"
    );
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();

    // The JSON-LD root must carry the same semantics the Turtle root asserts: a node typed
    // fdp-o:FAIRDataPoint that navigates to the configured catalog. Bind to the type and @id
    // slots rather than substringing the serialized body.
    let mut types = Vec::new();
    collect_ld_strings(&v, "@type", &mut types);
    collect_ld_strings(&v, RDF_TYPE, &mut types);
    assert!(
        types.iter().any(|t| t.ends_with("FAIRDataPoint")),
        "JSON-LD root must contain a node typed fdp-o:FAIRDataPoint; types={types:?}\nbody:\n{body}"
    );

    let mut ids = Vec::new();
    collect_ld_strings(&v, "@id", &mut ids);
    let catalog_path = format!("/fairdp/catalog/{CATALOG}");
    assert!(
        ids.iter().any(|id| id.contains(&catalog_path)),
        "JSON-LD root must reference the catalog {catalog_path}; @ids={ids:?}\nbody:\n{body}"
    );
}

#[tokio::test]
async fn root_no_accept_defaults_to_jsonld() {
    let (state, _tmp) = state_with_fdp(true);
    let (status, content_type, _body) = get(state, "/fairdp", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        content_type.starts_with("application/ld+json"),
        "no Accept must default to JSON-LD; got {content_type}"
    );
}

#[tokio::test]
async fn root_accept_star_defaults_to_jsonld() {
    let (state, _tmp) = state_with_fdp(true);
    let (status, content_type, _body) = get(state, "/fairdp", Some("*/*")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        content_type.starts_with("application/ld+json"),
        "*/* must default to JSON-LD; got {content_type}"
    );
}

#[tokio::test]
async fn catalog_lists_visible_dataset() {
    let (state, _tmp) = state_with_fdp(true);
    let (status, content_type, body) = get(
        state,
        &format!("/fairdp/catalog/{CATALOG}"),
        Some("text/turtle"),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(content_type.starts_with("text/turtle"));
    assert!(body.contains("dcat:Catalog"), "catalog type; body:\n{body}");
    // The visible dataset appears under the membership predicates.
    assert!(
        body.contains(&format!("/fairdp/dataset/{VISIBLE_ID}")),
        "visible dataset must be a member; body:\n{body}"
    );
    // The hidden dataset must not be listed.
    assert!(
        !body.contains(HIDDEN_ID),
        "hidden dataset must not appear in the catalog; body:\n{body}"
    );
}

#[tokio::test]
async fn unknown_catalog_is_404() {
    let (state, _tmp) = state_with_fdp(true);
    let (status, _ct, _body) = get(state, "/fairdp/catalog/no-such-catalog", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn visible_dataset_is_served() {
    let (state, _tmp) = state_with_fdp(true);
    let (status, content_type, body) = get(
        state,
        &format!("/fairdp/dataset/{VISIBLE_ID}"),
        Some("text/turtle"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(content_type.starts_with("text/turtle"));
    assert!(body.contains("dcat:Dataset"), "dataset type; body:\n{body}");
    assert!(
        body.contains(&format!("/fairdp/distribution/{VISIBLE_ID}")),
        "dataset must link its distribution; body:\n{body}"
    );
}

#[tokio::test]
async fn hidden_dataset_is_404() {
    let (state, _tmp) = state_with_fdp(true);
    let (status, _ct, _body) = get(state, &format!("/fairdp/dataset/{HIDDEN_ID}"), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn unknown_dataset_is_404() {
    let (state, _tmp) = state_with_fdp(true);
    let (status, _ct, _body) =
        get(state, "/fairdp/dataset/GDI-XX-XXX-00000000000000000", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn visible_distribution_is_served() {
    let (state, _tmp) = state_with_fdp(true);
    let (status, content_type, body) = get(
        state,
        &format!("/fairdp/distribution/{VISIBLE_ID}"),
        Some("text/turtle"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(content_type.starts_with("text/turtle"));
    assert!(
        body.contains("dcat:Distribution"),
        "distribution type; body:\n{body}"
    );
    // Its own graph carries the inline DataService with the lowercase endpointURL.
    assert!(
        body.contains("dcat:accessService"),
        "distribution must carry dcat:accessService; body:\n{body}"
    );
}

#[tokio::test]
async fn hidden_distribution_is_404() {
    let (state, _tmp) = state_with_fdp(true);
    let (status, _ct, _body) = get(state, &format!("/fairdp/distribution/{HIDDEN_ID}"), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn profile_service_is_404() {
    let (state, _tmp) = state_with_fdp(true);
    // The conformsTo marker IRIs are opaque and not served.
    let (status, _ct, _body) = get(state, "/fairdp/profile/service", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn profile_catalog_is_404() {
    let (state, _tmp) = state_with_fdp(true);
    let (status, _ct, _body) = get(state, "/fairdp/profile/catalog", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn no_fairdp_config_root_is_404() {
    let (state, _tmp) = state_with_fdp(false);
    let (status, _ct, _body) = get(state, "/fairdp", Some("text/turtle")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn no_fairdp_config_catalog_is_404() {
    let (state, _tmp) = state_with_fdp(false);
    let (status, _ct, _body) = get(state, &format!("/fairdp/catalog/{CATALOG}"), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---- CORS scoping (FDP is a public browser endpoint; the sensitive mount is not) ----

/// Issue a `GET` for `uri` with optional headers, returning status + response
/// headers (so the CORS header can be asserted). Mirrors `health_state.rs`'s
/// header-bearing harness.
async fn get_headers(
    state: AppState,
    uri: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, HeaderMap) {
    let router = build_router(state);
    let mut builder = Request::builder().method("GET").uri(uri);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let req = builder.body(Body::empty()).unwrap();
    let resp = router.oneshot(req).await.unwrap();
    (resp.status(), resp.headers().clone())
}

/// A service config with distinct aggregated and sensitive beacon prefixes, so the sensitive
/// mount is its own sub-router without the public CORS layer, plus a complete `[fairdp]`
/// block. The default `test_config` uses the combined `/beacon/v2` for both prefixes, which
/// would merge the two mounts.
fn split_mount_config(data_dir: &Path) -> ServiceConfig {
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"

[catalogs]
{CATALOG} = "Genome of Europe Aggregated Data"

[beacon]
aggregated_base_path = "/beacon/aggregated/v2"
sensitive_base_path = "/beacon/sensitive/v2"
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

#[tokio::test]
async fn fairdp_carries_wildcard_cors() {
    let (state, _tmp) = state_with_fdp(true);
    // The FDP is a public, browser-consumed endpoint, so wildcard CORS.
    let (status, headers) = get_headers(
        state,
        "/fairdp",
        &[("origin", "https://userportal.example.org")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("*"),
        "/fairdp must carry wildcard CORS"
    );
}

#[tokio::test]
async fn sensitive_beacon_mount_has_no_wildcard_cors() {
    // Build a split-mount node so the sensitive beacon is its own sub-router; it merges with
    // the aggregated mount only when the prefixes are equal.
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let config = split_mount_config(&data_dir);
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());

    // The aggregated mount carries the wildcard...
    let (_status, agg_headers) = get_headers(
        state.clone(),
        "/beacon/aggregated/v2/info",
        &[("origin", "https://userportal.example.org")],
    )
    .await;
    assert_eq!(
        agg_headers
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("*"),
        "aggregated mount must carry wildcard CORS"
    );

    // ...the sensitive mount does not.
    let (_status, sens_headers) = get_headers(
        state,
        "/beacon/sensitive/v2/info",
        &[("origin", "https://userportal.example.org")],
    )
    .await;
    assert!(
        !sens_headers.contains_key("access-control-allow-origin"),
        "sensitive beacon mount must not carry wildcard CORS"
    );
}

// ---- overlay end-to-end: FDP HTTP serves the overlaid dataset ----

/// Build a service config with both an `[fairdp]` block and an `inbox` pointing at the given
/// temp dir. `test_config` omits the inbox, so this helper extends it inline.
fn test_config_with_inbox(data_dir: &Path, inbox: &Path) -> ServiceConfig {
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{data_dir}"
inbox = "{inbox}"
ingest_concurrency = 1
rescan_interval_seconds = 3600

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
        data_dir = data_dir.display(),
        inbox = inbox.display(),
    );
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    cfg.preflight().unwrap();
    cfg
}

/// End-to-end proof that the FDP HTTP route serves overlaid metadata.
///
/// Chain: ingest a visible dataset, drop `{id}.metadata.json`, reconcile via
/// `IngestRuntime::scan_once`, then `GET /fairdp/dataset/{id}`. The Turtle response carries
/// the corrected title and an advanced `dct:modified` that differs from `dct:issued`.
#[tokio::test]
async fn fdp_serves_overlaid_dataset() {
    use gdi_node_standalone::ingest_runtime::IngestRuntime;

    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&inbox).unwrap();

    // Step 1: ingest a visible dataset so both disk and in-memory cache are live.
    let entry = ingest_covid_fdp(tmp.path(), &data_dir, VISIBLE_ID, DatasetState::Visible);
    let config = test_config_with_inbox(&data_dir, &inbox);
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
    state.cache.insert(
        gdi_node_standalone_core::cache::StatusWrite::unshared(),
        entry,
    );

    // Optional pre-overlay baseline: the original title must be present before
    // the overlay is applied, and the corrected one must be absent.
    let (status_pre, _ct_pre, body_pre) = get(
        state.clone(),
        &format!("/fairdp/dataset/{VISIBLE_ID}"),
        Some("text/turtle"),
    )
    .await;
    assert_eq!(status_pre, StatusCode::OK);
    assert!(
        body_pre.contains("COVID monogenic AFs"),
        "pre-overlay body must carry the baseline title:\n{body_pre}"
    );
    assert!(
        !body_pre.contains("Corrected via overlay"),
        "pre-overlay body must not carry the corrected title:\n{body_pre}"
    );

    // Step 2: drop the metadata sidecar. A description is required, because the baseline
    // manifest has `description: None` and a title-only patch would fail overlay validation.
    std::fs::write(
        inbox.join(format!("{VISIBLE_ID}.metadata.json")),
        br#"{"title":"Corrected via overlay","description":"corrected"}"#,
    )
    .unwrap();

    // Step 3: reconcile, so the runtime reads the inbox and updates the cache.
    let runtime = IngestRuntime::start(state.clone());
    runtime.scan_once().await;

    // Step 4: GET the dataset from the FDP HTTP layer.
    let (status, ct, body) = get(
        state.clone(),
        &format!("/fairdp/dataset/{VISIBLE_ID}"),
        Some("text/turtle"),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "overlaid dataset must be 200 OK");
    assert!(
        ct.starts_with("text/turtle"),
        "content-type must be text/turtle; got {ct}"
    );

    // The corrected title must appear in the served Turtle.
    assert!(
        body.contains("Corrected via overlay"),
        "FDP must serve the overlaid title:\n{body}"
    );

    // Both dct:issued and dct:modified must be present and must differ: the overlay advances
    // modified while issued stays id-derived.
    // VISIBLE_ID = "GDI-EE-UTARTU-20260409143052837" gives "2026-04-09T14:30:52.837Z".
    let issued_value = "2026-04-09T14:30:52.837Z";
    assert!(
        body.contains(issued_value),
        "dct:issued must carry the id-derived creation time:\n{body}"
    );
    // dct:modified must be present (the overlay stamps it) and must not equal
    // dct:issued (the overlay advances the timestamp).
    assert!(
        body.contains("dct:modified"),
        "dct:modified predicate must appear in the Turtle:\n{body}"
    );
    // The overlay-stamped modified is not the id-derived creation time. Count occurrences of
    // the issued value: two if modified equals issued, one when modified has advanced.
    let occurrence_count = body.matches(issued_value).count();
    assert_eq!(
        occurrence_count, 1,
        "dct:issued and dct:modified must differ; the id-derived datetime appears \
         {occurrence_count} times (expected 1 for issued only):\n{body}"
    );
}

// ---- traversal-id rejection (no panic, no path use) ----

#[tokio::test]
async fn fairdp_traversal_id_is_rejected_no_panic() {
    let (state, _tmp) = state_with_fdp(true);
    // A traversal-shaped id on any id-bearing FDP resource is rejected at the boundary with
    // a 400 or a 404, never reaches the filesystem, and never panics.
    let bad_ids = [
        "..%2Fetc",
        "../x",
        "%2e%2e%2fpasswd",
        "GDI-EE-UTARTU-1%2F..%2Fx",
    ];
    let resources = ["dataset", "catalog", "distribution"];
    for resource in resources {
        for bad in bad_ids {
            let uri = format!("/fairdp/{resource}/{bad}");
            let (status, _h) = get_headers(state.clone(), &uri, &[]).await;
            assert!(
                status == StatusCode::BAD_REQUEST || status == StatusCode::NOT_FOUND,
                "traversal id {bad:?} on /fairdp/{resource} must be 400/404, got {status}"
            );
        }
    }
}

// ---- visibility staleness: the single serve-time gate, applied to every path ----

/// Build a node whose one visible dataset belongs to a channel that reconciled long ago, with
/// the staleness bound switched on.
///
/// `[service].max_visibility_staleness_seconds` withholds a visible dataset whose owning
/// channel has gone dark, because the bucket may be serving a visibility a source-side
/// retraction has since changed. Every serve path must consult the same gate.
fn state_with_stale_channel(bound_secs: u64, reconciled_at: &str) -> (AppState, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let visible = ingest_covid_fdp(tmp.path(), &data_dir, VISIBLE_ID, DatasetState::Visible);

    let mut config = test_config(&data_dir, true);
    config.service.max_visibility_staleness_seconds = bound_secs;

    let mut status = StatusIndex::new();
    status.insert(
        VISIBLE_ID.to_owned(),
        StatusEntry {
            state: DatasetState::Visible,
            error_message: None,
            channel: "provider-a".to_owned(),
            last_seen_signature: Some("sig".to_owned()),
            provenance: DatasetProvenance::Unknown,
        },
    );

    let state = AppState::new(config, status, NodeIdentities::empty());
    state.cache.insert(
        gdi_node_standalone_core::cache::StatusWrite::unshared(),
        visible,
    );
    state
        .readiness
        .record_reconcile_at("provider-a", None, reconciled_at.to_owned());
    (state, tmp)
}

/// A reconcile stamp far enough in the past to be stale under any sane bound.
const LONG_AGO: &str = "2020-01-01T00:00:00Z";

#[tokio::test]
async fn a_stale_channel_withholds_the_dataset_from_every_fdp_path() {
    // Bound 300 s, last reconcile 3600 s ago, so withheld.
    let (state, _tmp) = state_with_stale_channel(300, LONG_AGO);

    // The set-based paths: the withheld dataset is listed nowhere.
    let (_s, _ct, root) = get(state.clone(), "/fairdp", Some("text/turtle")).await;
    assert!(
        !root.contains(VISIBLE_ID),
        "the FDP root must omit a dataset withheld by the staleness gate"
    );
    let (_s, _ct, catalog) = get(state.clone(), &format!("/fairdp/catalog/{CATALOG}"), None).await;
    assert!(
        !catalog.contains(VISIBLE_ID),
        "the FDP catalog must omit it too"
    );

    // ...and the single-resource dereferences. Without the gate they serve the full DCAT
    // record of a withdrawn dataset to any harvester that captured the id from an earlier
    // crawl.
    let (status, _ct, _b) = get(
        state.clone(),
        &format!("/fairdp/dataset/{VISIBLE_ID}"),
        Some("text/turtle"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "/fairdp/dataset/{{id}} must not dereference a dataset the catalog withholds"
    );
    let (status, _ct, _b) = get(
        state,
        &format!("/fairdp/distribution/{VISIBLE_ID}"),
        Some("text/turtle"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "/fairdp/distribution/{{id}} shares the same handler and must behave identically"
    );
}

#[tokio::test]
async fn a_fresh_channel_still_serves_every_fdp_path() {
    // The control: same wiring, reconciled 10 s ago against a 300 s bound, so served. Without
    // this the test above would also pass if the gate 404'd everything.
    let (state, _tmp) =
        state_with_stale_channel(300, &gdi_node_standalone_core::util::now_rfc3339());
    let (status, _ct, _b) = get(
        state.clone(),
        &format!("/fairdp/dataset/{VISIBLE_ID}"),
        Some("text/turtle"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_s, _ct, catalog) = get(state, &format!("/fairdp/catalog/{CATALOG}"), None).await;
    assert!(catalog.contains(VISIBLE_ID));
}

#[tokio::test]
async fn the_gate_is_inert_when_the_bound_is_disabled() {
    // Bound 0, the shipped default, is availability-first: an ancient reconcile withholds
    // nothing, so behaviour changes when the knob is enabled, not when the node is upgraded.
    let (state, _tmp) = state_with_stale_channel(0, LONG_AGO);
    let (status, _ct, _b) = get(
        state,
        &format!("/fairdp/dataset/{VISIBLE_ID}"),
        Some("text/turtle"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn the_catalog_plane_forbids_intermediary_caching() {
    // The FAIR-DP counterpart to `beacon_query::wiring`'s check. This plane enumerates
    // datasets, so a copy retained by a forward proxy or browser cache re-advertises a dataset
    // after a `channel take-down`, a suppression, a `{id}.state.json` tombstone or the
    // visibility-staleness bound has stopped the node from serving it. The withhold machinery
    // cannot reach one hop upstream of itself, and without an explicit directive a cache may
    // heuristically retain a `200` (RFC 9111 §4.2.2).
    let (state, _tmp) = state_with_fdp(true);
    let router = build_router(state);
    for path in ["/fairdp", &format!("/fairdp/dataset/{VISIBLE_ID}")] {
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .header("accept", "text/turtle")
            .body(Body::empty())
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        // The header layer is outermost and stamps a 404 too, so without this check a wrong
        // path would satisfy the assertion below while proving nothing.
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "{path} did not serve, so the cache-control assertion below is vacuous"
        );
        let cc = resp
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok());
        assert_eq!(
            cc,
            Some("no-store"),
            "{path} must forbid intermediary caching; got {cc:?}"
        );
    }
}
