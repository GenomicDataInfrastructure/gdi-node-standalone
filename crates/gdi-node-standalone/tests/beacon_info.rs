//! Golden tests for the Beacon informational endpoints on the combined mount:
//! `/info` (also `/`), `/service-info`, `/configuration`, `/entry_types`, `/map`,
//! and `/filtering_terms`.
//!
//! Each endpoint is driven in-process via `tower::ServiceExt::oneshot` against a
//! router built from a real `AppState` with a fixed `[beacon]` /
//! `[beacon.organization]` config (every optional field populated), so the
//! snapshotted JSON bodies are stable. The snapshots pin the wire shape the Beacon
//! Network aggregator enrols a node from:
//!
//! * `/service-info` is the bare GA4GH `ServiceInfo` (no `{meta,response}`);
//! * the others are wrapped in the Beacon v2 `{meta,response}` envelope;
//! * `/map` omits `singleEntryUrl` for `genomicVariant` (no `GET /g_variants/{id}`);
//! * the combined mount lists all three entry types (genomicVariant + dataset +
//!   individual) in `/entry_types`, `/configuration.entryTypes`, and `/map`;
//! * `/configuration` carries the `securityAttributes` (`securityLevels: [PUBLIC]`);
//! * `/filtering_terms` is an empty list.
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use gdi_node_standalone::app::build_router;
use gdi_node_standalone::identities::NodeIdentities;
use gdi_node_standalone::state::AppState;
use gdi_node_standalone_core::cache::StatusIndex;
use gdi_node_standalone_core::config::ServiceConfig;
use serde_json::Value;
use tower::ServiceExt as _; // for `oneshot`

/// A fixed service config with every optional `[beacon]`/`[beacon.organization]`
/// field set, so the informational snapshots exercise the full key set and stay
/// stable across runs.
fn fixed_config() -> ServiceConfig {
    let toml = r#"
[service]
base_url = "https://beacon.example.org"
data_dir = "/tmp/gdi-node-standalone-info-test"

[catalogs]
gdi-aggregated = "Genome of Europe Aggregated Data"

[beacon]
# Combined mount (aggregated == sensitive) so a single `/beacon/v2` endpoint
# advertises all three entry types (genomicVariant, dataset, individual); this test
# exercises the combined layout rather than the split default.
aggregated_base_path = "/beacon/v2"
sensitive_base_path = "/beacon/v2"
id = "org.example.beacon"
name = "Example GDI Beacon"
api_version = "v2.2.0"
environment = "test"
documentation_url = "https://beacon.example.org/docs"
description = "An example aggregated allele-frequency beacon."
version = "1.2.3"
alternative_url = "https://alt.example.org/beacon"
created_at = "2026-01-01T00:00:00Z"
updated_at = "2026-06-16T00:00:00Z"

[beacon.organization]
id = "org.example"
name = "Example Organization"
welcome_url = "https://example.org"
contact_url = "mailto:beacon@example.org"
description = "The example organization."
logo_url = "https://example.org/logo.png"
"#;
    ServiceConfig::from_toml_str(toml).unwrap()
}

/// Build an `AppState` with the fixed config (no datasets — info endpoints need none).
fn fixed_state() -> AppState {
    AppState::new(fixed_config(), StatusIndex::new(), NodeIdentities::empty())
}

/// Drive a `GET` against `uri` and return its `200` JSON body.
async fn get_json(uri: &str) -> Value {
    let router = build_router(fixed_state());
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "{uri} should be 200");
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn info_golden() {
    let v = get_json("/beacon/v2/info").await;
    insta::assert_json_snapshot!("info", v);
}

#[tokio::test]
async fn root_matches_info() {
    // `/` and `/info` serve identical BeaconInfo. Under axum nesting, the nested
    // `/` route is served at the prefix root *without* a trailing slash.
    let root = get_json("/beacon/v2").await;
    let info = get_json("/beacon/v2/info").await;
    assert_eq!(root, info);
}

#[tokio::test]
async fn service_info_golden() {
    let v = get_json("/beacon/v2/service-info").await;
    // The bare GA4GH ServiceInfo is not wrapped in `{meta, response}`.
    assert!(v.get("meta").is_none(), "service-info must be bare");
    assert!(v.get("response").is_none());
    insta::assert_json_snapshot!("service_info", v);
}

#[tokio::test]
async fn map_golden() {
    let v = get_json("/beacon/v2/map").await;
    // genomicVariant omits singleEntryUrl (no GET /g_variants/{id}).
    let gv = &v["response"]["endpointSets"]["genomicVariant"];
    assert!(
        gv.get("singleEntryUrl").is_none(),
        "genomicVariant omits singleEntryUrl"
    );
    insta::assert_json_snapshot!("map", v);
}

#[tokio::test]
async fn entry_types_golden() {
    let v = get_json("/beacon/v2/entry_types").await;
    // The combined mount lists all three entry types.
    let types = &v["response"]["entryTypes"];
    assert!(types.get("genomicVariant").is_some());
    assert!(types.get("dataset").is_some());
    assert!(types.get("individual").is_some());
    insta::assert_json_snapshot!("entry_types", v);
}

#[tokio::test]
async fn configuration_golden() {
    let v = get_json("/beacon/v2/configuration").await;
    // All three entryTypes on the combined mount + the securityAttributes.
    let types = &v["response"]["entryTypes"];
    assert!(types.get("genomicVariant").is_some());
    assert!(types.get("dataset").is_some());
    assert!(types.get("individual").is_some());
    assert_eq!(
        v["response"]["securityAttributes"]["securityLevels"][0], "PUBLIC",
        "securityLevels is [PUBLIC]"
    );
    insta::assert_json_snapshot!("configuration", v);
}

#[tokio::test]
async fn filtering_terms_golden() {
    let v = get_json("/beacon/v2/filtering_terms").await;
    assert_eq!(
        v["response"]["filteringTerms"].as_array().unwrap().len(),
        0,
        "filtering_terms is empty"
    );
    insta::assert_json_snapshot!("filtering_terms", v);
}
