//! The public plane's three `404` dialects, and the root index that names the services.
//!
//! The dialect follows the surface, and nothing else asserts a fallback body: the CORS test
//! next door asserts headers only, and every FDP `404` test discards its body.
//!
//!   * Under a beacon prefix: the Beacon envelope, which is what a federated client pointed
//!     at the mount parses. The message says what happened, and the error `meta` carries an
//!     empty `returnedSchemas`, since no route matched and so no entity was interpreted.
//!   * Under `/fairdp`: the bare `text/plain` `not found` a real FDP miss returns.
//!   * Anywhere else: a neutral JSON body, so `requestId` is still injected, naming the
//!     public services so a mistyped prefix answers with where the real ones are.
//!   * `GET /`: the same service directory as a `200`, the one place a human can land.
//!
//! The directory names the aggregated beacon prefix and `/fairdp` when configured, never the
//! sensitive prefix: the listing exists for the mistyped-FDP case, and the sensitive mount is
//! not a browser-discoverable surface.
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode};
use gdi_node_standalone::app::build_router;
use gdi_node_standalone::identities::NodeIdentities;
use gdi_node_standalone::state::AppState;
use gdi_node_standalone_core::cache::StatusIndex;
use gdi_node_standalone_core::config::ServiceConfig;
use tower::ServiceExt as _; // for `oneshot`

const AGGREGATED: &str = "/aggregated/beacon/v2";
const SENSITIVE: &str = "/sensitive/beacon/v2";
const COMBINED: &str = "/beacon/v2";

/// Which beacon layout the node under test mounts.
#[derive(Clone, Copy)]
enum Layout {
    /// Distinct prefixes: an aggregated and a sensitive beacon.
    Split,
    /// Equal prefixes: one combined beacon.
    Combined,
}

/// A lite `AppState` with the given beacon layout and, optionally, a `[fairdp]` block.
fn state(layout: Layout, fairdp: bool) -> (AppState, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let (agg, sens) = match layout {
        Layout::Split => (AGGREGATED, SENSITIVE),
        Layout::Combined => (COMBINED, COMBINED),
    };
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
gdi-aggregated = "Genome of Europe Aggregated Data"

[beacon]
aggregated_base_path = "{agg}"
sensitive_base_path = "{sens}"
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
    let config = ServiceConfig::from_toml_str(&toml).unwrap();
    config.preflight().unwrap();
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
    (state, tmp)
}

/// `GET uri` (with an `Origin`, so CORS can be asserted): status, headers, raw body.
async fn get(state: AppState, uri: &str) -> (StatusCode, HeaderMap, String) {
    let req = Request::builder()
        .uri(uri)
        .header("origin", "https://userportal.example.org")
        .body(Body::empty())
        .unwrap();
    let resp = build_router(state).oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, headers, String::from_utf8(bytes.to_vec()).unwrap())
}

fn content_type(headers: &HeaderMap) -> &str {
    headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Parse a JSON body, failing with the body in the message.
fn json(body: &str) -> serde_json::Value {
    serde_json::from_str(body).unwrap_or_else(|e| panic!("body is not JSON ({e}): {body}"))
}

// ---- anywhere else: the neutral JSON 404 -------------------------------------------

/// A mistyped top-level prefix gets a neutral JSON `404` rather than a Beacon envelope. It
/// names the public services and still carries the correlation id.
#[tokio::test]
async fn an_unknown_top_level_path_gets_a_neutral_json_404() {
    let (state, _tmp) = state(Layout::Split, true);
    let (status, headers, body) = get(state, "/fairdb").await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        content_type(&headers).starts_with("application/json"),
        "the neutral 404 must stay JSON so `requestId` is injected; got {:?}",
        content_type(&headers)
    );
    let v = json(&body);
    assert_eq!(v["status"], 404, "body: {body}");
    assert!(
        v["message"].as_str().is_some_and(|m| !m.is_empty()),
        "the neutral 404 must say what happened; body: {body}"
    );
    assert_eq!(v["services"]["beacon"], AGGREGATED, "body: {body}");
    assert_eq!(v["services"]["fairdp"], "/fairdp", "body: {body}");
    assert!(
        v.get("meta").is_none() && v.get("error").is_none(),
        "a top-level miss is not a Beacon error: no `meta`, no `error`; body: {body}"
    );
    assert!(
        !body.contains(SENSITIVE),
        "the sensitive prefix is never listed; body: {body}"
    );

    // The same id on the header and in the body, so a client can quote one.
    let id = header(&headers, "x-request-id").expect("x-request-id header");
    assert_eq!(v["requestId"], id, "body: {body}");

    // The public CORS policy, hand-stamped on the fallback.
    assert_eq!(header(&headers, "access-control-allow-origin"), Some("*"));
}

/// The directory names only what is served: no `[fairdp]`, no `fairdp` entry.
#[tokio::test]
async fn the_neutral_404_omits_fairdp_when_it_is_not_configured() {
    let (state, _tmp) = state(Layout::Split, false);
    let (status, _headers, body) = get(state, "/fairdb").await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    let v = json(&body);
    assert_eq!(v["services"]["beacon"], AGGREGATED, "body: {body}");
    assert!(
        v["services"].get("fairdp").is_none(),
        "an unconfigured FDP must not be advertised; body: {body}"
    );
}

/// A combined mount lists its one prefix as the beacon.
#[tokio::test]
async fn the_neutral_404_names_the_combined_prefix() {
    let (state, _tmp) = state(Layout::Combined, false);
    let (_status, _headers, body) = get(state, "/nope").await;
    assert_eq!(json(&body)["services"]["beacon"], COMBINED, "body: {body}");
}

// ---- GET /: the root index -----------------------------------------------------------

/// `GET /` is a `200` service directory carrying the same `services` object as the neutral
/// `404`, so the two cannot disagree about what the node serves.
#[tokio::test]
async fn the_root_index_lists_the_same_services_as_the_neutral_404() {
    let (state, _tmp) = state(Layout::Split, true);
    let (status, headers, body) = get(state.clone(), "/").await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(
        content_type(&headers).starts_with("application/json"),
        "got {:?}",
        content_type(&headers)
    );
    let index = json(&body);
    assert_eq!(index["services"]["beacon"], AGGREGATED, "body: {body}");
    assert_eq!(index["services"]["fairdp"], "/fairdp", "body: {body}");
    assert!(
        !body.contains(SENSITIVE),
        "the sensitive prefix is never listed; body: {body}"
    );
    // A public, browser-readable discovery document carries the public CORS policy.
    assert_eq!(header(&headers, "access-control-allow-origin"), Some("*"));

    let (_status, _headers, miss) = get(state, "/fairdb").await;
    assert_eq!(
        index["services"],
        json(&miss)["services"],
        "the root index and the neutral 404 must name the same services"
    );
}

/// Without `[fairdp]` the index names the beacon alone.
#[tokio::test]
async fn the_root_index_omits_fairdp_when_it_is_not_configured() {
    let (state, _tmp) = state(Layout::Split, false);
    let (status, _headers, body) = get(state, "/").await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let v = json(&body);
    assert_eq!(v["services"]["beacon"], AGGREGATED, "body: {body}");
    assert!(v["services"].get("fairdp").is_none(), "body: {body}");
}

// ---- under a beacon prefix: the Beacon envelope ---------------------------------------

/// An unknown path under a beacon mount answers in the Beacon envelope, with a message that
/// says so and an empty `returnedSchemas`.
///
/// Empty is the assertion that matters. The field says the request "has been interpreted for
/// the indicated entity", and a path that matched no route was interpreted as no entity at
/// all, so naming the mount's primary entry type would assert something the node did not do.
/// The field stays present because the vendored `beaconResponseMeta` lists it as required;
/// present-and-empty is the conformant way to say "none", and `ListOfSchemas` sets no
/// `minItems`.
///
/// The dialect must follow the mount on every layout, which is what a federated client
/// pointed at a prefix depends on. Hence the per-mount cases.
#[tokio::test]
async fn an_unknown_path_under_a_beacon_prefix_keeps_the_beacon_envelope() {
    let cases: [(Layout, &str); 7] = [
        (Layout::Split, "/aggregated/beacon/v2/nope"),
        // The nest root with a trailing slash; `{prefix}` itself is the Beacon root, a real
        // route. The documented rule is "decided from the path at a segment boundary", and
        // `{prefix}/` is under the prefix, so `Router::nest` hands it to the outer fallback,
        // which must still answer in this mount's dialect. A federated client that appends a
        // slash must not get a body it cannot parse.
        (Layout::Split, "/aggregated/beacon/v2/"),
        (Layout::Split, "/sensitive/beacon/v2/"),
        (Layout::Combined, "/beacon/v2/"),
        // Any depth, not just one segment.
        (Layout::Split, "/aggregated/beacon/v2/g_variants/extra"),
        (Layout::Split, "/sensitive/beacon/v2/nope"),
        (Layout::Combined, "/beacon/v2/nope"),
    ];
    for (layout, uri) in cases {
        let (state, _tmp) = state(layout, false);
        let (status, headers, body) = get(state, uri).await;

        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}: body: {body}");
        assert!(
            content_type(&headers).starts_with("application/json"),
            "{uri}: got {:?}",
            content_type(&headers)
        );
        let v = json(&body);
        assert_eq!(
            v["meta"]["beaconId"], "org.test.beacon",
            "{uri}: body: {body}"
        );
        assert_eq!(v["error"]["errorCode"], 404, "{uri}: body: {body}");
        let message = v["error"]["errorMessage"].as_str().unwrap_or_default();
        assert!(
            message.contains("Beacon") && message != "not found",
            "{uri}: the beacon-mount 404 must say no Beacon endpoint matched, not a bare \
             `not found`; got {message:?}"
        );
        let schemas = v["meta"]["returnedSchemas"]
            .as_array()
            .unwrap_or_else(|| panic!("{uri}: returnedSchemas must be present; body: {body}"));
        assert!(
            schemas.is_empty(),
            "{uri}: a route miss interpreted the request as NO entity, so it must name no \
             schema; body: {body}"
        );
        assert!(
            v["requestId"].as_str().is_some_and(|id| !id.is_empty()),
            "{uri}: body: {body}"
        );
    }
}

// ---- under /fairdp: the bare text 404 ------------------------------------------------

/// An unknown path under `/fairdp` answers like a real FDP miss: bare `text/plain`
/// `not found`, correlation id on the header, the FDP mount's CORS.
#[tokio::test]
async fn an_unknown_path_under_fairdp_is_a_bare_text_404() {
    for (fairdp, uri) in [
        (true, "/fairdp/profile/service"),
        (true, "/fairdp/nope/deeper"),
        // The FDP routes are always mounted (inert without `[fairdp]`), so the dialect
        // does not depend on the block being present.
        (false, "/fairdp/nope"),
    ] {
        let (state, _tmp) = state(Layout::Split, fairdp);
        let (status, headers, body) = get(state, uri).await;

        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}: body: {body}");
        assert!(
            content_type(&headers).starts_with("text/plain"),
            "{uri}: FDP is not Beacon — a bare text 404, got {:?} with body {body}",
            content_type(&headers)
        );
        assert_eq!(body, "not found", "{uri}");
        assert!(
            header(&headers, "x-request-id").is_some_and(|id| !id.is_empty()),
            "{uri}: the correlation header is plane-wide"
        );
        assert_eq!(
            header(&headers, "access-control-allow-origin"),
            Some("*"),
            "{uri}: the FDP mount's CORS layer must cover its fallback too"
        );
    }
}

// ---- the one trailing-slash exception: the FDP root ----------------------------------

/// `GET /fairdp/` answers `308 Permanent Redirect` to `/fairdp`.
///
/// Without the redirect, a harvest source URL written with the slash gets the FDP-dialect
/// `404` above, which `ckanext-fairdatapoint` reads as an empty FDP: the harvest completes
/// successfully with zero datasets and no error. `308` rather than `307`, because the move is
/// permanent and the method must be preserved.
///
/// The redirect is present whether or not `[fairdp]` is configured, like the FDP routes
/// themselves, so it cannot become a probe for the block's presence.
#[tokio::test]
async fn the_fdp_root_with_a_trailing_slash_redirects_to_the_fdp_root() {
    for fairdp in [true, false] {
        let (state, _tmp) = state(Layout::Split, fairdp);
        let (status, headers, body) = get(state, "/fairdp/").await;

        assert_eq!(
            status,
            StatusCode::PERMANENT_REDIRECT,
            "fairdp={fairdp}: body: {body}"
        );
        assert_eq!(
            header(&headers, "location"),
            Some("/fairdp"),
            "fairdp={fairdp}: the redirect must point at the FDP root"
        );
        assert_eq!(
            header(&headers, "access-control-allow-origin"),
            Some("*"),
            "fairdp={fairdp}: a browser client cannot follow a redirect that drops CORS"
        );
        assert!(
            header(&headers, "x-request-id").is_some_and(|id| !id.is_empty()),
            "fairdp={fairdp}: the correlation header is plane-wide"
        );
    }
}

/// That redirect is the only exception: every other trailing-slash path keeps the documented
/// "a trailing slash is not a route" `404`.
///
/// Tolerating one spelling of one root is a bounded concession to a harvester source URL.
/// Widening it to `/fairdp/dataset/{id}/` or to the beacon mounts would give every resource
/// IRI two spellings, which an LDP client's containment graph must not have.
#[tokio::test]
async fn every_other_trailing_slash_path_still_404s() {
    for uri in [
        "/fairdp/catalog/gdi-aggregated/",
        "/fairdp/dataset/GDI-EE-UTARTU-20260409143052837/",
        "/fairdp/distribution/GDI-EE-UTARTU-20260409143052837/",
        "/fairdp/profile/service/",
        // The beacon mounts keep the rule too; their dialect is pinned next door.
        "/aggregated/beacon/v2/",
        "/sensitive/beacon/v2/",
        // And the origin root's other registered path.
        "/.well-known/c4gh-recipient/",
    ] {
        let (state, _tmp) = state(Layout::Split, true);
        let (status, headers, body) = get(state, uri).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}: body: {body}");
        assert!(
            header(&headers, "location").is_none(),
            "{uri}: only the FDP root's trailing-slash form redirects"
        );
    }
}
