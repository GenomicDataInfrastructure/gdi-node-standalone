//! Resilience-layer behaviour, driven by wrapping the production layer stack
//! (`app::apply_resilience_layers`) around a test-only router via `oneshot`: a panicking
//! handler gives 500 and the process survives, an over-budget handler gives 408, and an
//! over-long request target gives 414. The production router has no panicking or blocking
//! route to drive these layers, hence the extracted seam.
//!
//! A synthesized error answers in the dialect of the surface the request was for, the same
//! three dialects the unmatched-path 404 uses (`not_found_shapes.rs`): the
//! `beaconErrorResponse` envelope under a beacon prefix (the harness config mounts the
//! aggregated beacon at `/beacon/v2`, the sensitive one at its default), bare `text/plain`
//! under `/fairdp`, and a neutral JSON body anywhere else. The layers render from the request
//! path, because they run outside the routed mounts and see no route. A handler-produced
//! error is never re-rendered.
//!
//! The load-shed 503 envelope is not covered here. `ServiceExt::oneshot` awaits readiness, so
//! a second over-limit request queues on the concurrency permit rather than being shed, and
//! `tower`'s `Overloaded` error is not externally constructible. That path is exercised
//! against a running server under real concurrency.
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse as _;
use axum::routing::get;
use gdi_node_standalone::app::apply_resilience_layers;
use gdi_node_standalone_core::config::ServiceConfig;
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt as _; // for `oneshot`

/// A minimal valid config Arc; `max_concurrent`/`timeout_s` tune the layers under
/// test. (No `AppState` needed — `apply_resilience_layers` takes the config Arc.)
fn cfg_arc(max_concurrent: usize, timeout_s: u64) -> Arc<ServiceConfig> {
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "/tmp/gdi-node-standalone-mw-test"
max_concurrent_requests = {max_concurrent}
request_timeout_seconds = {timeout_s}

[catalogs]
gdi-aggregated = "Genome of Europe Aggregated Data"

[beacon]
aggregated_base_path = "/beacon/v2"
id = "org.test.beacon"
name = "Test Beacon"
environment = "test"

[beacon.organization]
id = "ee.ut.gdi"
name = "University of Tartu"
"#
    );
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    cfg.preflight().unwrap();
    Arc::new(cfg)
}

async fn json_body(body: Body) -> Value {
    let bytes = to_bytes(body, usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// A handler that always panics (drives `CatchPanicLayer`). The concrete return
/// type — which the `panic!` diverges to — is required for axum's `Handler` impl.
async fn panicking_handler() -> &'static str {
    panic!("boom in handler")
}

/// A handler that overruns a 1 s request budget (drives `TimeoutLayer`); see
/// `over_budget_handler_yields_408` for why real time, not a paused clock.
async fn slow_handler() -> &'static str {
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    "late"
}

/// A request target over the 8 KiB cap (drives the 414 layer), under `prefix`.
fn over_long_uri(prefix: &str) -> String {
    format!("{prefix}/{}", "x".repeat(9000))
}

/// `GET uri` with an `Origin` (so the CORS stamp can be asserted): status, the
/// `content-type`, the `x-request-id`, the `access-control-allow-origin`, the raw body.
async fn fetch(
    router: Router,
    uri: &str,
) -> (StatusCode, String, Option<String>, Option<String>, String) {
    let req = Request::builder()
        .uri(uri)
        .header("origin", "https://userportal.example.org")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let header = |name: &str| {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let content_type = header("content-type").unwrap_or_default();
    let request_id = header("x-request-id");
    let acao = header("access-control-allow-origin");
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let body = String::from_utf8(bytes.to_vec()).unwrap();
    (status, content_type, request_id, acao, body)
}

/// Under `/fairdp` every synthesized error is the FDP's own dialect: bare `text/plain`, like
/// its handler-level 404 and 500, never the Beacon envelope. The correlation header and the
/// public CORS stamp, a status-keyed plane-wide layer, still apply.
#[tokio::test]
async fn fdp_resilience_errors_are_bare_text() {
    let router = apply_resilience_layers(
        Router::new()
            .route("/fairdp/panic", get(panicking_handler))
            .route("/fairdp/slow", get(slow_handler)),
        cfg_arc(64, 1),
    );
    for (uri, status, text) in [
        (
            "/fairdp/panic".to_owned(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal error",
        ),
        (
            "/fairdp/slow".to_owned(),
            StatusCode::REQUEST_TIMEOUT,
            "request timed out",
        ),
        (
            over_long_uri("/fairdp/catalog"),
            StatusCode::URI_TOO_LONG,
            "request target exceeds the maximum length",
        ),
    ] {
        let (got, content_type, request_id, acao, body) = fetch(router.clone(), &uri).await;
        let label = &uri[..uri.len().min(40)];
        assert_eq!(got, status, "{label}: body {body}");
        assert!(
            content_type.starts_with("text/plain"),
            "{label}: FDP is not Beacon — a bare text body, got {content_type:?} with {body}"
        );
        assert_eq!(body, text, "{label}");
        assert!(
            request_id.is_some_and(|id| !id.is_empty()),
            "{label}: the correlation header is plane-wide"
        );
        assert_eq!(
            acao.as_deref(),
            Some("*"),
            "{label}: the CORS stamp is status-keyed"
        );
    }
}

/// Outside every mount — the root, the well-known path, a mistyped prefix — a synthesized
/// error is the same neutral JSON shape as the unmatched-path 404: `status`, `message`,
/// and the injected `requestId`; no Beacon `meta`, no `error` block.
#[tokio::test]
async fn root_level_resilience_errors_are_neutral_json() {
    let router = apply_resilience_layers(
        Router::new()
            .route("/panic", get(panicking_handler))
            .route("/slow", get(slow_handler)),
        cfg_arc(64, 1),
    );
    for (uri, status, text) in [
        (
            "/panic".to_owned(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal error",
        ),
        (
            "/slow".to_owned(),
            StatusCode::REQUEST_TIMEOUT,
            "request timed out",
        ),
        (
            over_long_uri("/nope"),
            StatusCode::URI_TOO_LONG,
            "request target exceeds the maximum length",
        ),
    ] {
        let (got, content_type, request_id, _acao, body) = fetch(router.clone(), &uri).await;
        let label = &uri[..uri.len().min(40)];
        assert_eq!(got, status, "{label}: body {body}");
        assert!(
            content_type.starts_with("application/json"),
            "{label}: neutral errors stay JSON so requestId is injected; got {content_type:?}"
        );
        let v: Value = serde_json::from_str(&body)
            .unwrap_or_else(|e| panic!("{label}: body is not JSON ({e}): {body}"));
        assert_eq!(v["status"], status.as_u16(), "{label}: {body}");
        assert_eq!(v["message"], text, "{label}: {body}");
        assert!(
            v.get("meta").is_none() && v.get("error").is_none(),
            "{label}: not a Beacon envelope outside the beacon mounts: {body}"
        );
        assert_eq!(
            v["requestId"].as_str().map(str::to_owned),
            request_id,
            "{label}: the body id matches the header: {body}"
        );
    }
}

/// Under the sensitive mount the envelope's error `meta` names that mount's own entry type,
/// `individual`, not the aggregated mount's `genomicVariant`.
#[tokio::test]
async fn sensitive_mount_resilience_errors_name_the_individual_entry_type() {
    let router = apply_resilience_layers(
        Router::new().route("/sensitive/beacon/v2/panic", get(panicking_handler)),
        cfg_arc(64, 30),
    );
    let (status, _ct, _id, _acao, body) = fetch(router, "/sensitive/beacon/v2/panic").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["error"]["errorCode"], 500, "{body}");
    assert_eq!(
        v["meta"]["returnedSchemas"][0]["entityType"], "individual",
        "the sensitive mount's envelope names its own entry type: {body}"
    );
}

/// Only synthesized errors are rendered per dialect. A handler's own error response, whether
/// the FDP's text 500, a beacon handler's typed envelope, or anything else a route returns,
/// passes through untouched whatever its status.
#[tokio::test]
async fn handler_produced_errors_are_never_re_rendered() {
    let router = apply_resilience_layers(
        Router::new()
            .route(
                "/fairdp/handler-500",
                get(|| async {
                    (StatusCode::INTERNAL_SERVER_ERROR, "handler says no").into_response()
                }),
            )
            .route(
                "/beacon/v2/handler-500",
                get(|| async {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        axum::Json(serde_json::json!({"custom": true})),
                    )
                        .into_response()
                }),
            ),
        cfg_arc(64, 30),
    );

    let (status, _ct, _id, _acao, body) = fetch(router.clone(), "/fairdp/handler-500").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        body, "handler says no",
        "a handler's text 500 is not re-rendered"
    );

    let (status, _ct, _id, _acao, body) = fetch(router, "/beacon/v2/handler-500").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        v["custom"], true,
        "a handler's JSON 500 keeps its own body: {body}"
    );
    assert!(
        v.get("meta").is_none(),
        "a handler's JSON 500 is not wrapped in the envelope: {body}"
    );
}

#[tokio::test]
async fn panicking_handler_yields_500_beacon_envelope_and_survives() {
    let router = apply_resilience_layers(
        Router::new()
            .route("/beacon/v2/panic", get(panicking_handler))
            .route("/ok", get(|| async { "ok" })),
        cfg_arc(64, 30),
    );

    let req = Request::builder()
        .uri("/beacon/v2/panic")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let v = json_body(resp.into_body()).await;
    assert_eq!(v["error"]["errorCode"].as_u64(), Some(500));
    assert!(v["error"]["errorMessage"].is_string());
    assert!(
        v["meta"]["returnedSchemas"].is_array(),
        "the 500 carries the beaconErrorResponse meta envelope: {v}"
    );

    // The caught panic did not kill the process: the same router still serves.
    let req2 = Request::builder().uri("/ok").body(Body::empty()).unwrap();
    let resp2 = router.oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
}

#[tokio::test]
async fn resilience_errors_carry_wildcard_cors_for_cross_origin_browsers() {
    // A resilience-layer error, here the panic 500, is synthesized outside the per-route
    // `public_cors`, so without a plane-wide stamp a cross-origin browser gets an opaque
    // network error. The 500 carries the wildcard `Access-Control-Allow-Origin: *` and
    // exposes `x-request-id`, so browser clients can read the envelope and the correlation
    // id.
    let router = apply_resilience_layers(
        Router::new().route("/panic", get(panicking_handler)),
        cfg_arc(64, 30),
    );
    let req = Request::builder()
        .uri("/panic")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let headers = resp.headers();
    assert_eq!(
        headers
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("*"),
        "a resilience-layer error must carry wildcard CORS for cross-origin browsers"
    );
    assert!(
        headers
            .get("access-control-expose-headers")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("x-request-id")),
        "the resilience error must expose x-request-id cross-origin"
    );
    assert!(
        headers.get("x-request-id").is_some(),
        "the correlation id header is present on the error"
    );
}

#[tokio::test]
async fn error_body_carries_request_id_matching_header() {
    // A JSON error envelope, here the caught-panic 500, carries a `requestId` equal to the
    // `x-request-id` response header, so a client can quote one id.
    let router = apply_resilience_layers(
        Router::new().route("/beacon/v2/panic", get(panicking_handler)),
        cfg_arc(64, 30),
    );
    let req = Request::builder()
        .uri("/beacon/v2/panic")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let header_id = resp
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let v = json_body(resp.into_body()).await;

    let body_id = v["requestId"].as_str().map(str::to_owned);
    assert!(
        body_id.as_deref().is_some_and(|s| !s.is_empty()),
        "error body carries a requestId: {v}"
    );
    assert_eq!(
        body_id, header_id,
        "body requestId matches the x-request-id header: {v}"
    );
    // The envelope is still a conformant beaconErrorResponse.
    assert_eq!(v["error"]["errorCode"].as_u64(), Some(500));
    assert!(v["meta"]["returnedSchemas"].is_array(), "{v}");
}

#[tokio::test]
async fn inbound_request_id_is_stripped_not_echoed() {
    // `SetRequestIdLayer` keeps a client-supplied `X-Request-Id`, so without the strip layer
    // an unauthenticated caller controls the correlation id on the response header and in the
    // error body, and can collide or forge audit entries. Send a forged id and require a
    // fresh server-minted one instead.
    let router = apply_resilience_layers(
        Router::new().route("/panic", get(panicking_handler)),
        cfg_arc(64, 30),
    );
    let forged = "attacker-chosen-request-id-0001";
    let req = Request::builder()
        .uri("/panic")
        .header("x-request-id", forged)
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();

    let header_id = resp
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    assert_ne!(
        header_id, forged,
        "the inbound X-Request-Id must be ignored, not echoed on the response header"
    );
    // `MakeRequestUuid` mints a 36-char UUID.
    assert_eq!(
        header_id.len(),
        36,
        "a fresh UUID was minted: {header_id:?}"
    );

    let v = json_body(resp.into_body()).await;
    assert_eq!(
        v["requestId"].as_str(),
        Some(header_id.as_str()),
        "the error body carries the SAME fresh id, not the forged one: {v}"
    );
}

#[tokio::test]
async fn success_body_is_not_rewritten() {
    // A 2xx JSON body must pass through untouched (no `requestId` injected).
    let router = apply_resilience_layers(
        Router::new().route(
            "/ok",
            get(|| async { axum::Json(serde_json::json!({"ok": true})) }),
        ),
        cfg_arc(64, 30),
    );
    let req = Request::builder().uri("/ok").body(Body::empty()).unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = json_body(resp.into_body()).await;
    assert!(
        v.get("requestId").is_none(),
        "success bodies are never rewritten: {v}"
    );
    assert_eq!(v["ok"], true);
}

#[tokio::test]
async fn over_budget_handler_yields_408() {
    // The config expresses the timeout in whole seconds with a 1 s minimum, so the budget is
    // 1 s and the handler sleeps 1.2 s. The request then exceeds the budget on real time
    // while the test costs little more than the sleep.
    //
    // `tokio::time::pause` is not used. `tower-http`'s `TimeoutLayer` drives the timeout via
    // a `tokio::time::sleep` inside a `Timeout` future that the tower `Service` polls, and
    // `oneshot` drives that future synchronously in the same reactor. Pending timers are not
    // flushed after `advance` without a yield, so the 408 does not fire reliably under a
    // paused clock here.
    let router = apply_resilience_layers(
        Router::new().route("/beacon/v2/slow", get(slow_handler)),
        cfg_arc(64, 1),
    );
    let req = Request::builder()
        .uri("/beacon/v2/slow")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);
    // A synthesized error, as opposed to a handler-produced one, also carries a `requestId`
    // matching the header, so body injection covers the timeout, load-shed and body-cap
    // envelopes and not just handler errors.
    let header_id = resp
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    // The 408 carries the beaconErrorResponse envelope rather than a bare body, matching the
    // 500, 503 and 414 paths a federated aggregator parses.
    let v = json_body(resp.into_body()).await;
    assert_eq!(v["error"]["errorCode"].as_u64(), Some(408));
    assert!(v["error"]["errorMessage"].is_string());
    assert!(
        v["meta"]["returnedSchemas"].is_array(),
        "the 408 carries the beaconErrorResponse meta envelope: {v}"
    );
    assert_eq!(
        v["requestId"].as_str().map(str::to_owned),
        header_id,
        "the synthesized 408 body carries the requestId, matching the header: {v}"
    );
}

#[tokio::test]
async fn non_json_error_body_is_not_rewritten() {
    // A non-JSON error body passes through byte for byte, gated on the content type, so the
    // middleware never mangles a plain-text payload. The `x-request-id` header is still
    // present for correlation.
    let router = apply_resilience_layers(
        Router::new().route(
            "/plain-error",
            get(|| async { (StatusCode::BAD_REQUEST, "plain text error").into_response() }),
        ),
        cfg_arc(64, 30),
    );
    let req = Request::builder()
        .uri("/plain-error")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(
        resp.headers().get("x-request-id").is_some(),
        "the correlation header is still set on a non-JSON error"
    );
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert_eq!(
        &bytes[..],
        b"plain text error",
        "a non-JSON error body must be passed through unchanged"
    );
}

/// A config Arc whose public plane restricts CORS to `origins` (a TOML array literal).
fn cfg_arc_cors(origins: &str) -> Arc<ServiceConfig> {
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "/tmp/gdi-node-standalone-mw-test"
cors_allowed_origins = {origins}

[catalogs]
gdi-aggregated = "Genome of Europe Aggregated Data"

[beacon]
aggregated_base_path = "/beacon/v2"
id = "org.test.beacon"
name = "Test Beacon"
environment = "test"

[beacon.organization]
id = "ee.ut.gdi"
name = "University of Tartu"
"#
    );
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    cfg.preflight().unwrap();
    Arc::new(cfg)
}

/// Under a restricted `[service].cors_allowed_origins`, a resilience-layer error carries the
/// same policy the data planes do: echo an allowed origin, and send no `Allow-Origin` at all
/// to a disallowed one. The panic 500 used here is synthesized outside the routed
/// `CorsLayer`, so a hardcoded `*` stamp would hand every origin a readable error envelope on
/// a restricted node. The sibling test above pins the unrestricted default.
#[tokio::test]
async fn resilience_errors_honour_restricted_cors_policy() {
    let router = apply_resilience_layers(
        Router::new().route("/panic", get(panicking_handler)),
        cfg_arc_cors(r#"["https://portal.example.org"]"#),
    );

    // An allowed origin is echoed verbatim, never `*`, and marked `Vary: origin` so a shared
    // cache cannot hand one origin's Allow-Origin to another.
    let req = Request::builder()
        .uri("/panic")
        .header("origin", "https://portal.example.org")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let headers = resp.headers();
    assert_eq!(
        headers
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("https://portal.example.org"),
        "an allowed origin must be echoed on the error envelope, not `*`"
    );
    assert!(
        headers
            .get("vary")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.to_ascii_lowercase().contains("origin")),
        "an echoed origin must be Vary-marked"
    );

    // A disallowed origin gets no Allow-Origin, so the browser cannot read the envelope.
    let req = Request::builder()
        .uri("/panic")
        .header("origin", "https://evil.example")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        resp.headers().get("access-control-allow-origin").is_none(),
        "a disallowed origin must not receive a wildcard (or any) Allow-Origin"
    );
}
