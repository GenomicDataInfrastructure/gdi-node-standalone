//! The two planes treat an inbound `x-request-id` differently.
//!
//! The management plane honours a caller's id, so an orchestrator can follow one request
//! across the boundary. The public plane ignores it, because an unauthenticated caller
//! choosing the correlation id on every audit line and error body is worse than no
//! correlation at all.
//!
//! Both halves are asserted in one file, because what matters is the difference between them.
//! A test that only proved the management plane echoes would still pass if the public plane
//! started echoing too.
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use gdi_node_standalone::app::{build_management_router, build_router};
use gdi_node_standalone::identities::NodeIdentities;
use gdi_node_standalone::state::AppState;
use gdi_node_standalone_core::cache::StatusIndex;
use gdi_node_standalone_core::config::ServiceConfig;
use tower::ServiceExt as _;

const CALLER_ID: &str = "orchestrator-7f3a9c21";

fn state(data_dir: &std::path::Path) -> AppState {
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"

[catalogs]
gdi-aggregated = "GoE"

[beacon]
id = "org.test.beacon"
name = "Test Beacon"
"#,
        data_dir.display(),
    );
    let config = ServiceConfig::from_toml_str(&toml).unwrap();
    config.preflight().unwrap();
    AppState::new(config, StatusIndex::new(), NodeIdentities::empty())
}

/// The response's `x-request-id`, which is the correlation surface a caller reads.
///
/// The status is asserted to be `expect_status` rather than merely "not 404": these layers
/// wrap the whole router including its fallback, so a mistyped URI would still come back
/// carrying an id and every assertion below would pass while testing nothing.
async fn request_id_for(
    router: axum::Router,
    uri: &str,
    inbound: Option<&str>,
    expect_status: StatusCode,
) -> Option<String> {
    let mut req = Request::builder().uri(uri);
    if let Some(id) = inbound {
        req = req.header("x-request-id", id);
    }
    let resp = router
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        expect_status,
        "{uri} answered unexpectedly; this test asserts nothing if the request never \
         reached the route it names"
    );
    resp.headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(std::borrow::ToOwned::to_owned)
}

/// The management plane returns the caller's own id — on every route it serves.
///
/// Both routes, not one: the id comes from a plane-wide layer, and a route mounted outside
/// that layer (as `/datasets/{id}/state` could be) is exactly what one-route coverage would
/// miss.
#[tokio::test]
async fn the_management_plane_echoes_a_caller_supplied_request_id() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();

    // `/version` answers 200 and the dataset-state route answers 404 for an id this node
    // does not hold. Both are handler responses, which makes this a route test rather than a
    // fallback test.
    for (uri, status) in [
        ("/version", StatusCode::OK),
        (
            "/datasets/GDI-EE-UTARTU-20260409143052837/state",
            StatusCode::NOT_FOUND,
        ),
    ] {
        let router = build_management_router(state(&data_dir), None);
        assert_eq!(
            request_id_for(router, uri, Some(CALLER_ID), status)
                .await
                .as_deref(),
            Some(CALLER_ID),
            "the management plane must echo the caller's x-request-id on {uri}"
        );
    }
}

/// With no inbound id the management plane still returns one — a minted, non-empty id.
///
/// Without this, "echoes the caller's id" is satisfiable by a plane that only ever sets the
/// header when asked, leaving an unlabelled request with nothing to correlate on at all.
#[tokio::test]
async fn the_management_plane_mints_an_id_when_the_caller_sends_none() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();

    let minted = request_id_for(
        build_management_router(state(&data_dir), None),
        "/version",
        None,
        StatusCode::OK,
    )
    .await
    .expect("the management plane must always answer with an x-request-id");
    assert!(!minted.is_empty(), "a minted id must not be empty");
    assert_ne!(minted, CALLER_ID);
}

/// An unusable inbound id is dropped for a minted one, neither adopted nor fatal.
///
/// Over-long and non-graphic values are the two shapes that would otherwise be copied into a
/// response header and every log line the request emits. The request still succeeds: failing
/// an operator's `/version` over a malformed correlation id is a worse trade than losing the
/// correlation.
#[tokio::test]
async fn the_management_plane_drops_an_unusable_inbound_id() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();

    for (label, id) in [
        ("over-long", "x".repeat(129)),
        ("empty", String::new()),
        ("contains a space", "two words".to_owned()),
        ("non-ascii", "ident-\u{00e9}".to_owned()),
    ] {
        let router = build_management_router(state(&data_dir), None);
        let returned = request_id_for(router, "/version", Some(&id), StatusCode::OK).await;
        let returned = returned.expect("the request must still succeed and carry an id");
        assert_ne!(
            returned, id,
            "an {label} inbound id must be replaced by a minted one, not echoed"
        );
        assert!(
            !returned.is_empty(),
            "the replacement for an {label} id must be a real id"
        );
    }

    // The boundary itself: exactly at the cap is still accepted, so the bound rejects only
    // what it means to. A test that checked only the over-long case would pass with the cap
    // set to any value at all, including one that rejects every real id.
    let at_cap = "y".repeat(128);
    let router = build_management_router(state(&data_dir), None);
    assert_eq!(
        request_id_for(router, "/version", Some(&at_cap), StatusCode::OK)
            .await
            .as_deref(),
        Some(at_cap.as_str()),
        "an id exactly at the cap must be honoured"
    );
}

/// The public plane ignores an inbound id.
#[tokio::test]
async fn the_public_plane_still_ignores_an_inbound_request_id() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();

    let returned = request_id_for(
        build_router(state(&data_dir)),
        // The beacon routes are mounted under `[beacon].aggregated_base_path`, whose
        // default this URI spells out; the bare `/service-info` is a 404.
        "/aggregated/beacon/v2/service-info",
        Some(CALLER_ID),
        StatusCode::OK,
    )
    .await
    .expect("the public plane mints its own id");
    assert_ne!(
        returned, CALLER_ID,
        "the public plane must NOT adopt a caller-supplied x-request-id: an unauthenticated \
         caller would then choose the correlation id on every audit line and error body"
    );
    assert!(!returned.is_empty());
}
