//! The unmatched-path fallback 404 (`app::public_not_found`) — the CORS site that no
//! other test drives.
//!
//! The routed 404s elsewhere (an unknown FDP catalog, a hidden distribution) are handler
//! 404s: they are produced by a matched route and so pass through that mount's
//! `CorsLayer`. This one is different — it is the top-level fallback for a path that
//! matches no route at all (a mistyped Beacon base path), and it is synthesized outside
//! the layer, so it stamps the public CORS policy by hand. That makes it one of the three
//! places `Access-Control-Allow-Origin` can leave the node, and the only one nothing else
//! exercises.
//!
//! It carries the same policy the routed planes do: the wildcard by default, and, under a
//! restricted `[service].cors_allowed_origins`, an echoed allowed origin with nothing at all
//! for a disallowed one.
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use gdi_node_standalone::app::build_router;
use gdi_node_standalone::identities::NodeIdentities;
use gdi_node_standalone::state::AppState;
use gdi_node_standalone_core::cache::StatusIndex;
use gdi_node_standalone_core::config::ServiceConfig;
use tower::ServiceExt as _; // for `oneshot`

/// A path that matches no route, so it lands on the top-level fallback.
const UNROUTED: &str = "/beacon/v2/g_variants";

/// A lite `AppState` whose public plane applies `cors` (a TOML fragment, possibly empty).
fn state_with_cors(cors: &str) -> (AppState, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"
{cors}

[catalogs]
gdi-aggregated = "Genome of Europe Aggregated Data"

[beacon]
aggregated_base_path = "/aggregated/beacon/v2"
sensitive_base_path = "/sensitive/beacon/v2"
id = "org.test.beacon"
name = "Test Beacon"
environment = "test"

[beacon.organization]
id = "ee.ut.gdi"
name = "University of Tartu"
"#,
        data_dir.display(),
    );
    let config = ServiceConfig::from_toml_str(&toml).unwrap();
    config.preflight().unwrap();
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
    (state, tmp)
}

/// `GET UNROUTED` with an optional `Origin`, returning the 404's headers.
async fn fallback_headers(cors: &str, origin: Option<&str>) -> axum::http::HeaderMap {
    let (state, _tmp) = state_with_cors(cors);
    let mut req = Request::builder().uri(UNROUTED);
    if let Some(o) = origin {
        req = req.header("origin", o);
    }
    let resp = build_router(state)
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "{UNROUTED} must fall through to the top-level fallback"
    );
    resp.headers().clone()
}

/// Default (no `cors_allowed_origins`): the fallback carries the wildcard, so a browser
/// client that mistyped the base path can still read the envelope and its correlation id.
#[tokio::test]
async fn fallback_404_carries_the_wildcard_by_default() {
    let headers = fallback_headers("", Some("https://anything.example")).await;
    assert_eq!(
        headers
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("*"),
        "the default policy is the wildcard, on the fallback too"
    );
    assert!(
        headers
            .get("access-control-expose-headers")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("x-request-id")),
        "the fallback must expose x-request-id cross-origin"
    );
}

/// Restricted: the fallback honours the allow-list exactly as the routed planes do —
/// echoing a listed origin (Vary-marked) and refusing every other one. A hardcoded `*` here
/// would hand a readable error envelope to an origin the node is configured to refuse.
#[tokio::test]
async fn fallback_404_honours_a_restricted_allow_list() {
    const CORS: &str = r#"cors_allowed_origins = ["https://portal.example.org"]"#;

    let allowed = fallback_headers(CORS, Some("https://portal.example.org")).await;
    assert_eq!(
        allowed
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("https://portal.example.org"),
        "an allowed origin is echoed on the fallback, never `*`"
    );
    assert!(
        allowed
            .get("vary")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.to_ascii_lowercase().contains("origin")),
        "an echoed origin must be Vary-marked"
    );

    let denied = fallback_headers(CORS, Some("https://evil.example")).await;
    assert!(
        denied.get("access-control-allow-origin").is_none(),
        "a disallowed origin gets no Allow-Origin on the fallback either"
    );

    // A request with no `Origin` at all is not a CORS request: nothing to echo, so the
    // restricted policy sends no Allow-Origin (the wildcard branch is the only one that
    // can answer without one).
    let no_origin = fallback_headers(CORS, None).await;
    assert!(
        no_origin.get("access-control-allow-origin").is_none(),
        "a restricted policy has no origin to echo when the request carries none"
    );
}
