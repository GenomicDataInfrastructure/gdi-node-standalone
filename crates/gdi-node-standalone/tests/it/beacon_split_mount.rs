//! Split-mount integration test: distinct `aggregated_base_path` and
//! `sensitive_base_path` yield two beacons, each with the full informational set
//! scoped to its entry types.
//!
//! Driven in-process via `tower::ServiceExt::oneshot` against a router built from a
//! real `AppState`. With `aggregated_base_path = /beacon/aggregated/v2` and
//! `sensitive_base_path = /beacon/sensitive/v2`:
//!
//! * `/entry_types` under the aggregated prefix lists `genomicVariant` and `dataset`, not
//!   `individual`; under the sensitive prefix it lists `individual` only;
//! * `/map` rootUrls use the right per-entry-type prefix;
//! * the `g_variants` query route is under the aggregated prefix; `individuals`
//!   under the sensitive prefix (each 404s under the wrong prefix).
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use gdi_node_standalone::app::build_router;
use gdi_node_standalone::identities::NodeIdentities;
use gdi_node_standalone::state::AppState;
use gdi_node_standalone_core::cache::StatusIndex;
use gdi_node_standalone_core::config::ServiceConfig;
use serde_json::{Value, json};
use tower::ServiceExt as _; // for `oneshot`

const AGG: &str = "/beacon/aggregated/v2";
const SENS: &str = "/beacon/sensitive/v2";

/// A service config with distinct aggregated + sensitive mount prefixes.
fn split_config() -> ServiceConfig {
    let toml = format!(
        r#"
[service]
base_url = "https://beacon.example.org"
data_dir = "/tmp/gdi-node-standalone-split-test"

[beacon]
aggregated_base_path = "{AGG}"
sensitive_base_path = "{SENS}"
id = "org.example.beacon"
name = "Example GDI Beacon"
environment = "test"

[beacon.organization]
id = "org.example"
name = "Example Organization"
"#
    );
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    cfg.preflight().unwrap();
    cfg
}

fn split_state() -> AppState {
    AppState::new(split_config(), StatusIndex::new(), NodeIdentities::empty())
}

/// Drive a `GET` and return `(status, json_body)`.
async fn get(uri: &str) -> (StatusCode, Value) {
    let router = build_router(split_state());
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

/// Drive a `POST` of `body` and return its status.
async fn post_status(uri: &str, body: Value) -> StatusCode {
    let router = build_router(split_state());
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    router.oneshot(req).await.unwrap().status()
}

#[tokio::test]
async fn entry_types_are_scoped_per_prefix() {
    let (status, agg) = get(&format!("{AGG}/entry_types")).await;
    assert_eq!(status, StatusCode::OK);
    let agg_types = &agg["response"]["entryTypes"];
    assert!(agg_types.get("genomicVariant").is_some());
    assert!(agg_types.get("dataset").is_some());
    assert!(
        agg_types.get("individual").is_none(),
        "aggregated prefix must NOT list individual"
    );

    let (status, sens) = get(&format!("{SENS}/entry_types")).await;
    assert_eq!(status, StatusCode::OK);
    let sens_types = &sens["response"]["entryTypes"];
    assert!(
        sens_types.get("individual").is_some(),
        "sensitive prefix lists individual"
    );
    assert!(sens_types.get("genomicVariant").is_none());
    assert!(sens_types.get("dataset").is_none());
}

#[tokio::test]
async fn configuration_entry_types_are_scoped_per_prefix() {
    let (_, agg) = get(&format!("{AGG}/configuration")).await;
    let agg_types = &agg["response"]["entryTypes"];
    assert!(agg_types.get("genomicVariant").is_some());
    assert!(agg_types.get("individual").is_none());

    let (_, sens) = get(&format!("{SENS}/configuration")).await;
    let sens_types = &sens["response"]["entryTypes"];
    assert!(sens_types.get("individual").is_some());
    assert!(sens_types.get("genomicVariant").is_none());
}

#[tokio::test]
async fn map_root_urls_use_the_right_prefix() {
    let (_, agg) = get(&format!("{AGG}/map")).await;
    let agg_sets = &agg["response"]["endpointSets"];
    assert_eq!(
        agg_sets["genomicVariant"]["rootUrl"],
        format!("https://beacon.example.org{AGG}/g_variants")
    );
    assert_eq!(
        agg_sets["dataset"]["rootUrl"],
        format!("https://beacon.example.org{AGG}/datasets")
    );
    assert!(
        agg_sets.get("individual").is_none(),
        "aggregated /map omits individual"
    );

    let (_, sens) = get(&format!("{SENS}/map")).await;
    let sens_sets = &sens["response"]["endpointSets"];
    assert_eq!(
        sens_sets["individual"]["rootUrl"],
        format!("https://beacon.example.org{SENS}/individuals")
    );
    assert!(sens_sets.get("genomicVariant").is_none());
}

#[tokio::test]
async fn query_routes_live_under_their_own_prefix() {
    // g_variants under aggregated → 200 (empty query → empty resultSets); under
    // sensitive → 404 (not mounted there).
    assert_eq!(
        post_status(&format!("{AGG}/g_variants"), json!({})).await,
        StatusCode::OK
    );
    assert_eq!(
        post_status(&format!("{SENS}/g_variants"), json!({})).await,
        StatusCode::NOT_FOUND
    );

    // individuals under sensitive → 200; under aggregated → 404.
    assert_eq!(
        post_status(&format!("{SENS}/individuals"), json!({})).await,
        StatusCode::OK
    );
    assert_eq!(
        post_status(&format!("{AGG}/individuals"), json!({})).await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn both_prefixes_serve_the_shared_informational_endpoints() {
    // `/info` and `/service-info` are identical on both mounts.
    let (_, agg_info) = get(&format!("{AGG}/info")).await;
    let (_, sens_info) = get(&format!("{SENS}/info")).await;
    assert_eq!(agg_info, sens_info, "info is the same on both mounts");

    let (agg_si, agg_si_body) = get(&format!("{AGG}/service-info")).await;
    let (sens_si, sens_si_body) = get(&format!("{SENS}/service-info")).await;
    assert_eq!(agg_si, StatusCode::OK);
    assert_eq!(sens_si, StatusCode::OK);
    assert_eq!(agg_si_body, sens_si_body);

    // `/filtering_terms` is empty on both.
    let (_, agg_ft) = get(&format!("{AGG}/filtering_terms")).await;
    let (_, sens_ft) = get(&format!("{SENS}/filtering_terms")).await;
    assert_eq!(
        agg_ft["response"]["filteringTerms"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        sens_ft["response"]["filteringTerms"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
}

const DEFAULT_AGG: &str = "/aggregated/beacon/v2";
const DEFAULT_SENS: &str = "/sensitive/beacon/v2";

/// A config that omits both `*_base_path` keys, so the built-in defaults apply.
fn default_paths_config() -> ServiceConfig {
    let toml = r#"
[service]
base_url = "https://beacon.example.org"
data_dir = "/tmp/gdi-node-standalone-default-paths-test"

[beacon]
id = "org.example.beacon"
name = "Example GDI Beacon"
environment = "test"

[beacon.organization]
id = "org.example"
name = "Example Organization"
"#;
    let cfg = ServiceConfig::from_toml_str(toml).unwrap();
    cfg.preflight().unwrap();
    cfg
}

/// With no `*_base_path` configured, the defaults mount a split beacon at the
/// symmetric prefixes `/aggregated/beacon/v2` and `/sensitive/beacon/v2`, rather than a
/// combined `/beacon/v2`. This guards how the default values compose into mounts; the other
/// tests here pin explicit paths, and only this one exercises the shipped defaults.
#[tokio::test]
async fn default_config_serves_split_symmetric_prefixes() {
    let build = || {
        build_router(AppState::new(
            default_paths_config(),
            StatusIndex::new(),
            NodeIdentities::empty(),
        ))
    };

    // Aggregated default prefix serves the shared `/service-info`.
    let resp = build()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("{DEFAULT_AGG}/service-info"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "aggregated default prefix must serve /service-info"
    );

    // Sensitive default prefix serves the individuals placeholder.
    let resp = build()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("{DEFAULT_SENS}/individuals"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&json!({})).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "sensitive default prefix must serve /individuals"
    );

    // There is no combined `/beacon/v2` mount under the defaults.
    let resp = build()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/beacon/v2/service-info")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "the former combined /beacon/v2 mount must not be served by default"
    );
}
