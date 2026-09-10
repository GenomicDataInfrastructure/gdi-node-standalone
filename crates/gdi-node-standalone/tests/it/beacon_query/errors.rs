//! HTTP-level error rendering: an oversized or malformed request renders as a
//! `beaconErrorResponse` envelope (400, 413, 414 or 415) rather than axum's default
//! plain-text rejection, because a federated aggregator parses the error body.
use super::*;

#[tokio::test]
async fn oversized_request_target_is_414() {
    // The GET-side mirror of the body cap: an over-long request target is rejected with 414
    // as a beaconErrorResponse envelope, symmetric with `oversized_body_is_413`.
    let (state, _tmp) = state_with_covid();
    let router = build_router(state);

    let big = "x".repeat(9000); // > MAX_REQUEST_TARGET_BYTES (8 KiB)
    let uri = format!("/beacon/v2/g_variants?referenceName=3&padding={big}");
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::URI_TOO_LONG);
    // The 414 is correlatable like every other response: the rejection sits inside the
    // request-id and trace layers, so it carries the server-generated id and is
    // access-logged.
    assert!(
        resp.headers().get("x-request-id").is_some(),
        "414 must carry an x-request-id header for correlation"
    );
    let v = body_json(resp.into_body()).await;
    assert_eq!(
        v["error"]["errorCode"].as_u64(),
        Some(414),
        "414 must be a beaconErrorResponse: {v}"
    );
}

#[tokio::test]
async fn malformed_get_query_string_is_400_beacon_envelope() {
    // A GET query string with invalid percent-encoding makes axum's `Query` extractor
    // reject. The `BeaconQuery` wrapper renders that as a beaconErrorResponse 400 rather than
    // axum's plain-text rejection, keeping the GET error surface in the same envelope as the
    // POST `BeaconJson` path.
    let (state, _tmp) = state_with_covid();
    let router = build_router(state);

    // `%zz` is not valid percent-encoding → serde_urlencoded fails → 400.
    let req = Request::builder()
        .method("GET")
        .uri("/beacon/v2/g_variants?referenceName=%zz")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v = body_json(resp.into_body()).await;
    assert_eq!(
        v["error"]["errorCode"].as_u64(),
        Some(400),
        "a malformed GET query must be a beaconErrorResponse: {v}"
    );
    assert!(
        v["meta"]["returnedSchemas"].is_array(),
        "the 400 carries the beaconErrorResponse meta envelope: {v}"
    );
}

#[tokio::test]
async fn malformed_request_envelope_is_400() {
    // A misplaced envelope must be a 400, not a misleading empty-query 200: the spec
    // nests variant params under `query.requestParameters`. A bare top-level
    // `requestParameters` (no `query` wrapper) and a non-object `query` are rejected;
    // a genuinely empty query is still a 200.
    async fn status_of(state: &AppState, body: serde_json::Value) -> StatusCode {
        let req = Request::builder()
            .method("POST")
            .uri("/beacon/v2/g_variants")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        build_router(state.clone())
            .oneshot(req)
            .await
            .unwrap()
            .status()
    }

    let (state, _tmp) = state_with_covid();

    // Misplaced: requestParameters at the top level, no `query` wrapper → 400.
    assert_eq!(
        status_of(&state, serde_json::json!({
            "requestParameters": { "assemblyId": "GRCh38", "referenceName": "3", "start": [45_823_239] }
        })).await,
        StatusCode::BAD_REQUEST,
        "bare top-level requestParameters must be 400"
    );
    // `query` present but not an object → 400.
    assert_eq!(
        status_of(&state, serde_json::json!({ "query": "oops" })).await,
        StatusCode::BAD_REQUEST,
        "non-object query must be 400"
    );
    // Genuinely empty query shapes stay 200.
    assert_eq!(
        status_of(&state, serde_json::json!({})).await,
        StatusCode::OK
    );
    assert_eq!(
        status_of(&state, serde_json::json!({ "query": {} })).await,
        StatusCode::OK
    );
    assert_eq!(
        status_of(
            &state,
            serde_json::json!({ "query": { "requestParameters": {} } })
        )
        .await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn top_level_filters_selector_is_rejected_like_a_nested_one() {
    // A `filters` selector is unsupported, since this beacon advertises no filtering terms,
    // so it is a 400 whether it sits in its canonical `query.filters` slot or is misplaced at
    // the top level as a sibling of `query`. Dropping a misplaced one would return an
    // unnarrowed 200 the caller believes was filtered.
    async fn status_of(state: &AppState, body: serde_json::Value) -> StatusCode {
        let req = Request::builder()
            .method("POST")
            .uri("/beacon/v2/g_variants")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        build_router(state.clone())
            .oneshot(req)
            .await
            .unwrap()
            .status()
    }

    let (state, _tmp) = state_with_covid();

    // Canonical placement (inside `query`) → 400 (baseline).
    assert_eq!(
        status_of(
            &state,
            serde_json::json!({
                "query": { "requestParameters": {}, "filters": [{ "id": "NCIT:C20197" }] }
            })
        )
        .await,
        StatusCode::BAD_REQUEST,
        "a nested filters selector must be 400"
    );
    // Misplaced at the top level (sibling of `query`) → still 400, not a silent 200.
    assert_eq!(
        status_of(
            &state,
            serde_json::json!({
                "query": { "requestParameters": {} },
                "filters": [{ "id": "NCIT:C20197" }]
            })
        )
        .await,
        StatusCode::BAD_REQUEST,
        "a top-level filters selector must also be 400, not silently ignored"
    );
}

#[tokio::test]
async fn oversized_body_is_413() {
    let (state, _tmp) = state_with_covid();
    let router = build_router(state);

    // max_request_body_bytes = 2048; build a body larger than that.
    let big = "x".repeat(8192);
    let body = serde_json::json!({
        "query": { "requestParameters": { "referenceName": "3", "padding": big } }
    });
    let req = Request::builder()
        .method("POST")
        .uri("/beacon/v2/g_variants")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    // The 413 on a beacon mount must be a `beaconErrorResponse` envelope (a
    // federated aggregator parses the error body), not axum's bare-text rejection.
    let v = body_json(resp.into_body()).await;
    assert_eq!(
        v["error"]["errorCode"].as_u64(),
        Some(413),
        "413 must be a beaconErrorResponse: {v}"
    );
}

#[tokio::test]
async fn malformed_json_body_is_beacon_error_envelope() {
    let (state, _tmp) = state_with_covid();
    let router = build_router(state);

    // Syntactically invalid JSON body must render a beaconErrorResponse (400), not
    // axum's default plain-text rejection — a federated aggregator parses the body.
    let req = Request::builder()
        .method("POST")
        .uri("/beacon/v2/g_variants")
        .header("content-type", "application/json")
        .body(Body::from("{ this is not valid json"))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v = body_json(resp.into_body()).await;
    assert_eq!(
        v["error"]["errorCode"].as_u64(),
        Some(400),
        "malformed JSON must be a beaconErrorResponse: {v}"
    );
    assert!(
        v["meta"]["beaconId"].is_string(),
        "envelope carries meta: {v}"
    );
}

#[tokio::test]
async fn wrong_content_type_is_beacon_error_envelope() {
    let (state, _tmp) = state_with_covid();
    let router = build_router(state);

    // A non-JSON Content-Type must render a beaconErrorResponse (415), not axum's
    // default plain-text 415.
    let req = Request::builder()
        .method("POST")
        .uri("/beacon/v2/g_variants")
        .header("content-type", "text/plain")
        .body(Body::from("{}"))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let v = body_json(resp.into_body()).await;
    assert_eq!(
        v["error"]["errorCode"].as_u64(),
        Some(415),
        "wrong Content-Type must be a beaconErrorResponse: {v}"
    );
}

/// Assembly policy case (c): a recognised assembly this node holds no dataset for is answered
/// `200` with `exists: false`, not `400`.
///
/// A 400 would buy no signal. A federating aggregator turns a member's 400 into the same
/// `{"exists": false}` stub it would build from a 200, while costing the node every `GRCh37`
/// query. "No data for that assembly" is `exists: false` in Beacon semantics. The guarantee
/// that matters, never searching a dataset under a foreign assembly, is kept by selecting no
/// dataset here, and is pinned by `a_multi_assembly_node_searches_only_the_matching_dataset`.
#[tokio::test]
async fn recognised_assembly_with_no_dataset_answers_exists_false() {
    let (state, _tmp) = state_with_covid();
    let router = build_router(state);
    let req = Request::builder()
        .method("POST")
        .uri("/beacon/v2/g_variants")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&wrong_assembly_body()).unwrap(),
        ))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp.into_body()).await;
    assert_eq!(
        body["responseSummary"]["exists"], false,
        "a GRCh37 query against a GRCh38-only node is a miss, not an error: {body}"
    );
    assert_eq!(
        body["responseSummary"]["numTotalResults"].as_u64(),
        Some(0),
        "the miss counts zero results: {body}"
    );
    // No dataset was searched, so none may report a hit. This says nothing about
    // consultation: the default `includeResultsetResponses: HIT` omits a consulted-but-missed
    // dataset entirely. It is still falsifiable, because `wrong_assembly_body()` targets the
    // COVID fixture's known hit, so a cross-assembly search produces a resultSet even at
    // that include level.
    assert!(
        body["response"]["resultSets"]
            .as_array()
            .is_none_or(Vec::is_empty),
        "no dataset may report a hit for a foreign assembly: {body}"
    );
}

/// Assembly policy case (d): a name `normalize_assembly` cannot resolve is a `400`. An
/// unresolvable name is a client error rather than a miss, and answering `exists: false`
/// would hide a mistyped assembly.
#[tokio::test]
async fn unrecognised_assembly_is_still_rejected() {
    let (state, _tmp) = state_with_covid();
    let router = build_router(state);
    let mut body = wrong_assembly_body();
    body["query"]["requestParameters"]["assemblyId"] = serde_json::json!("hg99");
    let req = Request::builder()
        .method("POST")
        .uri("/beacon/v2/g_variants")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v = body_json(resp.into_body()).await;
    assert_eq!(
        v["error"]["errorMessage"].as_str(),
        Some("unknown assemblyId"),
        "an unresolvable assemblyId is a 400: {v}"
    );
}

/// Assembly policy case (b): with several assemblies served, an omitted `assemblyId` cannot
/// be defaulted, so it is a `400` that says "ambiguous" and lists what this node serves, which
/// lets the client retry with one of them. Case (a), the single-assembly node that defaults,
/// is in `results.rs`.
#[tokio::test]
async fn absent_assembly_on_a_multi_assembly_node_is_ambiguous() {
    let (state, _tmp) = state_with_two_assemblies();
    let router = build_router(state);
    let req = Request::builder()
        .method("POST")
        .uri("/beacon/v2/g_variants")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&no_assembly_body()).unwrap()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp.into_body()).await;
    let msg = body["error"]["errorMessage"].as_str().unwrap_or_default();
    assert!(
        msg.contains("ambiguous"),
        "the reject must say the request is ambiguous: {msg}"
    );
    assert!(
        msg.contains("GRCh37") && msg.contains("GRCh38"),
        "the reject must list every assembly this node serves: {msg}"
    );
}
