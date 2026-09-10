//! Integration tests for the sensitive-beacon `individuals` placeholder, driven
//! in-process via `tower::ServiceExt::oneshot` against a router built from a real
//! `AppState`.
//!
//! The placeholder serves no data. It validates the Beacon v2 request envelope the way
//! `g_variants` does and returns a schema-valid zero result honouring
//! `requestedGranularity`. These tests assert:
//!
//! * a valid `record`-granularity POST → 200 with empty `resultSets`;
//! * `boolean` → `responseSummary.exists: false`; `count` → `numTotalResults: 0`;
//! * `testMode: true` → accepted as a no-op (still serves only zeros);
//! * `includeResultsetResponses: "WRONG"` → 400, while `ALL`, `HIT`, `MISS` and `NONE`
//!   → 200;
//! * a bearer `Authorization` header is accepted and ignored (still 200);
//! * `GET` also works;
//! * it serves only zeros (never a non-zero count or a non-empty resultSet).
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

const PREFIX: &str = "/beacon/v2";

/// A combined-mount config so `/beacon/v2/individuals` is served on one endpoint.
/// The default layout is split (`/aggregated/beacon/v2` + `/sensitive/beacon/v2`), so this
/// sets both prefixes equal explicitly to exercise the combined mount.
fn config() -> ServiceConfig {
    let toml = r#"
[service]
base_url = "https://beacon.example.org"
data_dir = "/tmp/gdi-node-standalone-individuals-test"

[beacon]
aggregated_base_path = "/beacon/v2"
sensitive_base_path = "/beacon/v2"
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

fn state() -> AppState {
    AppState::new(config(), StatusIndex::new(), NodeIdentities::empty())
}

/// POST `body` to `/individuals` (optionally with a bearer header); return
/// `(status, json)`.
async fn post(body: Value, bearer: Option<&str>) -> (StatusCode, Value) {
    let router = build_router(state());
    let mut builder = Request::builder()
        .method("POST")
        .uri(format!("{PREFIX}/individuals"))
        .header("content-type", "application/json");
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let req = builder
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json = serde_json::from_slice(&bytes).unwrap();
    (status, json)
}

/// A valid `individuals` request body for the given granularity.
///
/// `requestedGranularity` rides inside `query.requestParameters` — the same place
/// the shared `g_variants` parser reads it from.
fn body_for(granularity: &str) -> Value {
    json!({ "query": { "requestParameters": { "requestedGranularity": granularity } } })
}

/// Assert the response carries no non-zero count and no non-empty resultSet.
/// The `/individuals` disclosure contract: the endpoint answers, and answers with
/// nothing.
///
/// Every check is unconditional. Wrapping one in `if let Some(..)` would make an absent or
/// retyped `numTotalResults`, or a `resultSets` that stopped being an array, silently skip
/// the check instead of failing it. This helper is the only body assertion four of these
/// tests have.
fn assert_serves_only_zeros(v: &Value) {
    assert_eq!(
        v["responseSummary"]["exists"], false,
        "exists must be false: {v}"
    );
    let granularity = v["meta"]["returnedGranularity"]
        .as_str()
        .unwrap_or_else(|| panic!("meta.returnedGranularity must be present: {v}"));

    // The disclosure ladder: each granularity may carry strictly less than the one below it,
    // and carrying more is a leak. Both directions are asserted, because absence is as much
    // part of the contract as the zero. A boolean answer that shipped a count, or a count
    // answer that shipped records, would satisfy any "is it zero?" check while disclosing
    // more than the client asked for.
    let (wants_count, wants_sets) = match granularity {
        "boolean" => (false, false),
        "count" => (true, false),
        "record" => (true, true),
        other => panic!("unexpected returnedGranularity {other:?}: {v}"),
    };

    let count = &v["responseSummary"]["numTotalResults"];
    if wants_count {
        let n = count
            .as_u64()
            .unwrap_or_else(|| panic!("numTotalResults must be present and a number: {v}"));
        assert_eq!(n, 0, "numTotalResults must be zero: {v}");
    } else {
        assert!(
            count.is_null(),
            "a {granularity}-granularity response must not carry numTotalResults: {v}"
        );
    }

    let sets = &v["response"]["resultSets"];
    if wants_sets {
        let arr = sets
            .as_array()
            .unwrap_or_else(|| panic!("a record-granularity response must carry resultSets: {v}"));
        assert!(arr.is_empty(), "resultSets must be empty: {v}");
    } else {
        assert!(
            sets.is_null(),
            "a {granularity}-granularity response must not carry resultSets at all: {v}"
        );
    }
}

#[tokio::test]
async fn record_granularity_returns_empty_result_sets() {
    let (status, v) = post(body_for("record"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["response"]["resultSets"].as_array().unwrap().len(), 0);
    assert_eq!(v["responseSummary"]["numTotalResults"].as_u64().unwrap(), 0);
    // meta names the individual schema and echoes the granularity.
    assert_eq!(v["meta"]["returnedGranularity"], "record");
    assert_eq!(v["meta"]["returnedSchemas"][0]["entityType"], "individual");
    assert_serves_only_zeros(&v);
}

#[tokio::test]
async fn boolean_granularity_returns_exists_false() {
    let (status, v) = post(body_for("boolean"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["responseSummary"]["exists"], false);
    // boolean granularity carries no resultSets member.
    assert!(v["response"].is_null(), "boolean omits the response member");
    assert_eq!(v["meta"]["returnedGranularity"], "boolean");
    assert_serves_only_zeros(&v);
}

#[tokio::test]
async fn count_granularity_returns_zero() {
    let (status, v) = post(body_for("count"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["responseSummary"]["numTotalResults"].as_u64().unwrap(), 0);
    assert_eq!(v["responseSummary"]["exists"], false);
    assert_eq!(v["meta"]["returnedGranularity"], "count");
    assert_serves_only_zeros(&v);
}

#[tokio::test]
async fn test_mode_true_is_accepted_as_no_op() {
    // Beacon v2 requires a beacon to respond to a `testMode` request. The shared envelope
    // validator, the same path `g_variants` uses, accepts `testMode: true` as a no-op, and
    // the placeholder still serves only zeros.
    let body = json!({ "query": { "requestParameters": { "testMode": true } } });
    let (status, v) = post(body, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_serves_only_zeros(&v);
    // A non-boolean testMode is still a 400 (input validation, not a mode rejection).
    let bad = json!({ "query": { "requestParameters": { "testMode": "maybe" } } });
    let (status, _) = post(bad, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn include_resultset_responses_enum() {
    // A value outside `ALL`, `HIT`, `MISS`, `NONE` gives a 400.
    let bad = json!({
        "query": { "requestParameters": { "includeResultsetResponses": "WRONG" } }
    });
    let (status, _) = post(bad, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // All four enum values → 200, serving only zeros.
    for value in ["ALL", "HIT", "MISS", "NONE"] {
        let body = json!({
            "query": { "requestParameters": { "includeResultsetResponses": value } }
        });
        let (status, v) = post(body, None).await;
        assert_eq!(status, StatusCode::OK, "{value} must be accepted");
        assert_serves_only_zeros(&v);
    }
}

#[tokio::test]
async fn bearer_header_is_accepted_and_ignored() {
    // A bearer token is accepted and ignored — still a 200 zero result.
    let (status, v) = post(body_for("record"), Some("a-real-looking-token")).await;
    assert_eq!(status, StatusCode::OK);
    assert_serves_only_zeros(&v);
}

#[tokio::test]
async fn structurally_valid_filters_are_accepted_and_match_nothing() {
    // Any structurally-valid `filters` is accepted without a semantic check and
    // matches nothing (zero result).
    let body = json!({
        "query": {
            "requestParameters": {},
            "filters": [ { "id": "NCIT:C20197" } ]
        }
    });
    let (status, v) = post(body, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_serves_only_zeros(&v);
}

#[tokio::test]
async fn submitted_filters_are_accepted_but_never_reflected_into_the_summary() {
    // This is the only endpoint that could echo `filters`: `g_variants` rejects a non-empty
    // one with a 400, so nothing reaches its summary. Reflecting them would let a client
    // dictate the field's contents, and the vendored `beaconReceivedRequestSummary` types it
    // as `Filters` with `items: {"type": "string"}`, so the ontology-filter object real
    // Beacon v2 clients send would produce a response failing the node's own schema
    // conformance. `filters` is optional in that schema, so omitting it conforms.
    //
    // The request is still accepted, and still answered with zeros.
    for filters in [
        json!([ { "id": "NCIT:C20197" } ]), // the real client shape: objects
        json!(["BTO:0000199"]),             // the vendored shape: CURIE strings
        json!([42, null, true]),            // junk that would break the schema outright
    ] {
        let body = json!({
            "query": { "requestParameters": {}, "filters": filters }
        });
        let (status, v) = post(body, None).await;
        assert_eq!(status, StatusCode::OK, "filters stay accepted: {filters}");
        assert_serves_only_zeros(&v);
        assert!(
            v["meta"]["receivedRequestSummary"].get("filters").is_none(),
            "submitted filters must not be reflected into receivedRequestSummary; got {}",
            v["meta"]["receivedRequestSummary"]
        );
    }
}

#[tokio::test]
async fn get_also_works() {
    let router = build_router(state());
    let req = Request::builder()
        .method("GET")
        .uri(format!("{PREFIX}/individuals?requestedGranularity=record"))
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["response"]["resultSets"].as_array().unwrap().len(), 0);
    assert_serves_only_zeros(&v);
}

#[test]
fn get_testmode_true_is_recorded_in_the_individuals_audit() {
    use tracing_subscriber::layer::SubscriberExt as _;

    // A GET `?testMode=true` arrives as a JSON string, so the sensitive-plane audit records
    // `test_mode=true` through `request::testmode_flag`, as `g_variants` and `datasets` do. A
    // bare `Value::as_bool` would misreport it as false. The placeholder audits synchronously
    // on the request thread, so the `with_default` thread-local capture is reliable under the
    // parallel harness.
    crate::fixtures::ensure_capture_safe_tracing();

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
            let router = build_router(state());
            let req = Request::builder()
                .method("GET")
                .uri(format!(
                    "{PREFIX}/individuals?requestedGranularity=record&testMode=true"
                ))
                .body(Body::empty())
                .unwrap();
            let resp = router.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        });
    });

    let out = writer.contents();
    assert!(
        out.contains("\"entry_type\":\"individual\""),
        "an individuals audit line must be emitted: {out}"
    );
    assert!(
        out.contains("\"test_mode\":true"),
        "GET ?testMode=true must record test_mode=true in the individuals audit: {out}"
    );
}

/// `receivedRequestSummary` carries the same key set on `/individuals` as on `/g_variants`,
/// and the same echoed values for `includeResultsetResponses` and `testMode`.
///
/// This endpoint is the only one whose summary is hand-built as raw JSON in
/// `individuals_zero`, rather than the typed `ReceivedRequestSummary` every other path
/// serializes. A field added to that struct reaches `g_variants`, `datasets` and the error
/// paths automatically, and reaches this endpoint only if someone adds it. Such an omission
/// fails nothing on its own: the vendored summary schema makes these fields optional and
/// constrains only their types, so the `/map` conformance crawl validates the response either
/// way.
///
/// Comparing the two key sets is what makes an omission fail.
#[tokio::test]
async fn individuals_summary_key_set_matches_g_variants() {
    async fn summary_of(endpoint: &str, include: &str) -> Value {
        let router = build_router(state());
        let body = json!({
            "query": {
                "requestParameters": {},
                "includeResultsetResponses": include,
                "testMode": true,
                "requestedGranularity": "record"
            }
        });
        let req = Request::builder()
            .method("POST")
            .uri(format!("{PREFIX}/{endpoint}"))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{endpoint} must answer 200");
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        v["meta"]["receivedRequestSummary"].clone()
    }

    fn keys(v: &Value) -> Vec<String> {
        let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
        k.sort();
        k
    }

    let individuals = summary_of("individuals", "MISS").await;
    let g_variants = summary_of("g_variants", "MISS").await;

    assert_eq!(
        keys(&individuals),
        keys(&g_variants),
        "individuals summary {individuals} must carry the same keys as g_variants \
         {g_variants}"
    );
    assert_eq!(
        individuals["includeResultsetResponses"],
        json!("MISS"),
        "individuals must echo the applied shaping, not omit it: {individuals}"
    );
    assert_eq!(
        g_variants["includeResultsetResponses"],
        json!("MISS"),
        "g_variants must echo the applied shaping: {g_variants}"
    );

    // Values, not just keys. A hard-coded field is present but wrong, and a key-set
    // comparison alone passes it: `testMode: false` echoed for a request that sent `true`
    // carries the key all the same.
    for field in ["includeResultsetResponses", "testMode"] {
        assert_eq!(
            individuals[field], g_variants[field],
            "individuals must echo the same {field} as g_variants for the same request; \
             individuals={individuals} g_variants={g_variants}"
        );
    }
    assert_eq!(
        individuals["testMode"],
        json!(true),
        "the submitted testMode must be echoed, not fixed to the default: {individuals}"
    );
}
