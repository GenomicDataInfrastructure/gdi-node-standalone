//! `g_variants` response shaping: record-level frequencies, GET≡POST metamorphic
//! equivalence, granularity (record/count/boolean, including the configured
//! default), envelope-sibling fields (`testMode`, `requestedGranularity`), and
//! `includeResultsetResponses`.
use super::*;
use test_util::covid;

#[tokio::test]
async fn post_g_variants_returns_frequencies() {
    let (state, _tmp) = state_with_covid();
    let router = build_router(state);

    let body = serde_json::json!({
        "query": {
            "requestParameters": {
                "referenceName": "3",
                "start": [45_823_239],
                "referenceBases": "T",
                "alternateBases": "C",
                "assemblyId": "GRCh38",
                "requestedGranularity": "RECORD"
            }
        }
    });
    let req = Request::builder()
        .method("POST")
        .uri("/beacon/v2/g_variants")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let v = body_json(resp.into_body()).await;
    let result_sets = v["response"]["resultSets"].as_array().unwrap();
    assert_eq!(result_sets.len(), 1, "one resultSet for the single dataset");
    assert_eq!(result_sets[0]["id"], DATASET_ID);

    let freqs = result_sets[0]["results"][0]["frequencyInPopulations"][0]["frequencies"]
        .as_array()
        .unwrap();

    // FI_M with alleleFrequency ≈ 0.085.
    let fi_m = freqs
        .iter()
        .find(|f| f["population"] == "FI_M")
        .expect("FI_M frequency present");
    let fi_m_af = fi_m["alleleFrequency"].as_f64().unwrap();
    assert!(
        (fi_m_af - covid::FI_M_AF).abs() < 1e-3,
        "FI_M alleleFrequency {fi_m_af} not ≈ 0.085"
    );

    // Total with alleleCount == 618.
    let total = freqs
        .iter()
        .find(|f| f["population"] == "Total")
        .expect("Total frequency present");
    assert_eq!(total["alleleCount"].as_u64().unwrap(), covid::TOTAL_AC);
}

#[tokio::test]
async fn g_variants_honours_dataset_ids_scope() {
    // The chr3:45823240 T>C site hits the single COVID dataset. Scoping the query to a
    // different dataset id must not return that hit. If `datasetIds` were ignored, the node
    // would scan every visible dataset and a dataset-scoped existence query would affirm the
    // variant "in" a dataset that does not hold it.
    // POST a boolean g_variants for the COVID site with the given `datasetIds` (Null omits
    // the field), returning `responseSummary.exists`.
    async fn exists(router: &axum::Router, dataset_ids: serde_json::Value) -> bool {
        let mut query = serde_json::json!({
            "requestParameters": {
                "referenceName": "3",
                "start": [45_823_239],
                "referenceBases": "T",
                "alternateBases": "C",
                "assemblyId": "GRCh38"
            },
            "requestedGranularity": "boolean"
        });
        if !dataset_ids.is_null() {
            query["datasetIds"] = dataset_ids;
        }
        let body = serde_json::json!({ "query": query });
        let req = Request::builder()
            .method("POST")
            .uri("/beacon/v2/g_variants")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        body_json(resp.into_body()).await["responseSummary"]["exists"]
            .as_bool()
            .unwrap()
    }

    let (state, _tmp) = state_with_covid();
    let router = build_router(state);

    // Absent datasetIds scans all visible datasets, so a hit.
    assert!(
        exists(&router, serde_json::Value::Null).await,
        "absent datasetIds scans all datasets"
    );
    // Scoped to the dataset that holds the variant, so a hit.
    assert!(
        exists(&router, serde_json::json!([DATASET_ID])).await,
        "a query scoped to the holding dataset hits"
    );
    // Scoped to a different dataset, so a miss.
    assert!(
        !exists(
            &router,
            serde_json::json!(["GDI-EE-UTARTU-00000000000000000"])
        )
        .await,
        "an out-of-scope dataset-scoped query must not affirm the variant"
    );

    // A scope that was submitted but resolves to no usable id selects nothing. It must not
    // fall back to "all visible datasets". Each of these parses to an empty `Vec`, which the
    // handler must still distinguish from an absent field, or the query widens back to every
    // dataset and re-creates the false affirmation above. A `boolean` query is the sharpest
    // case: at that granularity `shape_for_granularity` drops the per-dataset resultSets, so
    // the client sees only the OR-ed `exists` and cannot tell which dataset produced the hit.
    for (label, ids) in [
        ("empty array", serde_json::json!([])),
        ("all-null elements", serde_json::json!([null])),
        ("non-string elements", serde_json::json!([7])),
        ("blank string", serde_json::json!("")),
        ("wrong-typed value", serde_json::json!(true)),
    ] {
        assert!(
            !exists(&router, ids).await,
            "{label}: a submitted datasetIds scope resolving to no id must select no dataset, \
             not every visible one"
        );
    }
}

#[tokio::test]
#[expect(
    clippy::similar_names,
    reason = "post_/get_ prefixed pairs are the clearest naming for the GET≡POST comparison"
)]
async fn get_g_variants_matches_equivalent_post() {
    // Metamorphic: the GET query-param form of g_variants must hit the same site as the
    // typed POST body and return the same responseSummary and frequencyInPopulations. POST
    // and GET differ in meta.receivedRequestSummary, so the comparison is scoped to those two
    // subtrees.
    let (state, _tmp) = state_with_covid();
    let router = build_router(state);

    let body = serde_json::json!({
        "query": {
            "requestParameters": {
                "referenceName": "3",
                "start": [45_823_239],
                "referenceBases": "T",
                "alternateBases": "C",
                "assemblyId": "GRCh38",
                "requestedGranularity": "RECORD"
            }
        }
    });
    let post_req = Request::builder()
        .method("POST")
        .uri("/beacon/v2/g_variants")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let post_resp = router.clone().oneshot(post_req).await.unwrap();
    assert_eq!(post_resp.status(), StatusCode::OK);
    let post_v = body_json(post_resp.into_body()).await;

    let get_req = Request::builder()
        .method("GET")
        .uri(
            "/beacon/v2/g_variants?referenceName=3&start=45823239\
             &referenceBases=T&alternateBases=C&assemblyId=GRCh38&requestedGranularity=RECORD",
        )
        .body(Body::empty())
        .unwrap();
    let get_resp = router.oneshot(get_req).await.unwrap();
    assert_eq!(get_resp.status(), StatusCode::OK, "GET g_variants must HIT");
    let get_v = body_json(get_resp.into_body()).await;

    // The GET is itself a real hit, not an empty or zero path.
    assert_eq!(get_v["responseSummary"]["exists"], true);
    assert_eq!(
        get_v["responseSummary"]["numTotalResults"].as_u64(),
        Some(1)
    );
    let get_rs = get_v["response"]["resultSets"].as_array().unwrap();
    assert_eq!(get_rs.len(), 1);
    assert_eq!(get_rs[0]["id"], DATASET_ID);

    // Metamorphic equivalence on the two scoped subtrees only.
    assert_eq!(
        get_v["responseSummary"], post_v["responseSummary"],
        "GET/POST responseSummary must be identical"
    );
    let post_freq = &post_v["response"]["resultSets"][0]["results"][0]["frequencyInPopulations"];
    let get_freq = &get_v["response"]["resultSets"][0]["results"][0]["frequencyInPopulations"];
    assert_eq!(
        get_freq, post_freq,
        "GET/POST frequencyInPopulations must be identical"
    );

    // Concrete-value guard so the test fails loudly if the fixture frequencies change.
    let freqs = get_freq[0]["frequencies"].as_array().unwrap();
    let fi_m_af = freqs
        .iter()
        .find(|f| f["population"] == "FI_M")
        .expect("FI_M frequency present")["alleleFrequency"]
        .as_f64()
        .unwrap();
    assert!((fi_m_af - covid::FI_M_AF).abs() < 1e-3, "FI_M af {fi_m_af}");
    let total_ac = freqs
        .iter()
        .find(|f| f["population"] == "Total")
        .expect("Total frequency present")["alleleCount"]
        .as_u64()
        .unwrap();
    assert_eq!(total_ac, covid::TOTAL_AC);
}

#[tokio::test]
async fn g_variants_count_drops_record_body_and_sets_returned_granularity() {
    let (state, _tmp) = state_with_covid();
    let router = build_router(state);

    // A `count`-granularity request for the known chr3:45823240 T>C site. The request is a
    // disclosure ceiling: the node serves the count alone, not the record-level
    // per-population frequency body.
    let body = serde_json::json!({
        "query": {
            "requestParameters": {
                "referenceName": "3",
                "start": [45_823_239],
                "referenceBases": "T",
                "alternateBases": "C",
                "assemblyId": "GRCh38",
                "requestedGranularity": "count"
            }
        }
    });
    let req = Request::builder()
        .method("POST")
        .uri("/beacon/v2/g_variants")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let v = body_json(resp.into_body()).await;
    // `meta` echoes the request's granularity and reports it as what was served.
    assert_eq!(
        v["meta"]["receivedRequestSummary"]["requestedGranularity"], "count",
        "receivedRequestSummary echoes the requested granularity"
    );
    assert_eq!(
        v["meta"]["returnedGranularity"], "count",
        "returnedGranularity reflects what was actually served (no longer hardcoded record)"
    );
    // count keeps exists + numTotalResults ...
    assert_eq!(v["responseSummary"]["exists"], true);
    assert_eq!(v["responseSummary"]["numTotalResults"].as_u64(), Some(1));
    // ... but the record-level frequency body is gone.
    assert!(
        v.get("response").is_none(),
        "count must NOT serve the record-level resultSets / frequencyInPopulations body"
    );
}

/// The aggregate (`boolean` and `count`) path must answer what the record path counts.
///
/// `boolean` and `count` are served by a streaming fold that never retains rows, while
/// `record` materialises and groups them. Two implementations answering one question can
/// drift, and the drift would be a wrong `numTotalResults` served as fact to a federated
/// aggregator rather than a visible failure. So the same query is asked at all three
/// granularities and the answers must agree.
#[tokio::test]
async fn granularities_agree_on_exists_and_count() {
    async fn ask(router: &axum::Router, granularity: &str) -> (bool, Option<u64>) {
        let body = serde_json::json!({
            "query": {
                "requestParameters": {
                    "referenceName": "3",
                    "start": [45_823_000],
                    "end": [45_824_000],
                    "assemblyId": "GRCh38"
                },
                "requestedGranularity": granularity
            }
        });
        let req = Request::builder()
            .method("POST")
            .uri("/beacon/v2/g_variants")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "{granularity} must answer 200"
        );
        let v = body_json(resp.into_body()).await;
        (
            v["responseSummary"]["exists"].as_bool().unwrap(),
            v["responseSummary"]["numTotalResults"].as_u64(),
        )
    }

    let (state, _tmp) = state_with_covid();
    let router = build_router(state);

    let (record_exists, record_count) = ask(&router, "RECORD").await;
    let (count_exists, count_count) = ask(&router, "count").await;
    let (bool_exists, _) = ask(&router, "boolean").await;

    assert!(
        record_exists,
        "fixture must actually match, or this test proves nothing"
    );
    assert!(
        record_count.is_some_and(|c| c > 0),
        "fixture must yield a non-zero count, got {record_count:?}"
    );
    assert_eq!(
        count_count, record_count,
        "count granularity must report the same numTotalResults as record"
    );
    assert_eq!(
        count_exists, record_exists,
        "count granularity must agree with record on exists"
    );
    assert_eq!(
        bool_exists, record_exists,
        "boolean granularity must agree with record on exists"
    );
}

/// Like [`state_with_covid`] but with an explicit
/// `[beacon.configuration].default_granularity`, to drive the config-default path.
fn state_with_covid_default_granularity(
    default_granularity: &str,
) -> (AppState, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let staging = build_covid_staging_named_goe(tmp.path(), DATASET_ID);
    let mut catalogs = std::collections::BTreeMap::new();
    catalogs.insert(
        CATALOG.to_owned(),
        "Genome of Europe Aggregated Data".to_owned(),
    );
    let ok = ingest_staging_dir(
        &staging,
        &data_dir,
        &ParquetCaps::default(),
        &catalogs,
        &DatasetEncryptor::plaintext(),
    )
    .unwrap();

    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"
max_request_body_bytes = 2048

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

[beacon.configuration]
default_granularity = "{default_granularity}"
"#,
        data_dir.display(),
    );
    let config = ServiceConfig::from_toml_str(&toml).unwrap();
    config.preflight().unwrap();
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
    state.cache.insert(
        gdi_node_standalone_core::cache::StatusWrite::unshared(),
        DatasetEntry {
            id: ok.id,
            metadata: ok.metadata,
            config: ok.config,
            state: DatasetState::Visible,
            metadata_modified: None,
        },
    );
    (state, tmp)
}

#[tokio::test]
async fn g_variants_applies_configured_default_granularity_when_unspecified() {
    // Pins the config-default granularity path through `to_beacon_params`: a node configured
    // `[beacon.configuration].default_granularity = "count"` serves a query that omits
    // requestedGranularity at count, dropping the record body, rather than at the hardcoded
    // "record". Preflight validates the config field; this drives the adapter that reads it.
    let (state, _tmp) = state_with_covid_default_granularity("count");
    let router = build_router(state);

    let body = serde_json::json!({
        "query": {
            "requestParameters": {
                "referenceName": "3",
                "start": [45_823_239],
                "referenceBases": "T",
                "alternateBases": "C",
                "assemblyId": "GRCh38"
                // No requestedGranularity, so the configured default applies.
            }
        }
    });
    let req = Request::builder()
        .method("POST")
        .uri("/beacon/v2/g_variants")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp.into_body()).await;
    assert_eq!(
        v["meta"]["returnedGranularity"], "count",
        "the configured default_granularity must be applied when the request omits it"
    );
    assert!(
        v.get("response").is_none(),
        "a count default must drop the record-level frequency body"
    );
}

#[tokio::test]
async fn g_variants_boolean_discloses_only_exists() {
    let (state, _tmp) = state_with_covid();
    let router = build_router(state);

    // A `boolean`-granularity request for the matching site: the node discloses only whether
    // a match exists, with no record body and no count.
    let body = serde_json::json!({
        "query": {
            "requestParameters": {
                "referenceName": "3",
                "start": [45_823_239],
                "referenceBases": "T",
                "alternateBases": "C",
                "assemblyId": "GRCh38",
                "requestedGranularity": "boolean"
            }
        }
    });
    let req = Request::builder()
        .method("POST")
        .uri("/beacon/v2/g_variants")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let v = body_json(resp.into_body()).await;
    assert_eq!(v["meta"]["returnedGranularity"], "boolean");
    assert_eq!(v["responseSummary"]["exists"], true);
    assert!(
        v["responseSummary"].get("numTotalResults").is_none(),
        "boolean must withhold the count"
    );
    assert!(
        v.get("response").is_none(),
        "boolean must NOT serve a record-level body"
    );
}

#[tokio::test]
async fn g_variants_honours_envelope_fields_at_query_sibling_level() {
    // The Beacon v2 schema and the GDI User Portal place includeResultsetResponses,
    // requestedGranularity, testMode and pagination as siblings of requestParameters under
    // `query`. Beacon v2 requires testMode:true there to be answered and echoed; this
    // all-public aggregate beacon has no sensitive data to withhold, so it is a no-op.
    // requestedGranularity there must be echoed too.

    // testMode:true at query.* answers 200 normally, and is echoed.
    let (state, _tmp) = state_with_covid();
    let router = build_router(state);
    let body = serde_json::json!({
        "query": {
            "requestParameters": {
                "referenceName": "3",
                "start": [45_823_239],
                "referenceBases": "T",
                "alternateBases": "C",
                "assemblyId": "GRCh38"
            },
            "testMode": true
        }
    });
    let req = Request::builder()
        .method("POST")
        .uri("/beacon/v2/g_variants")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "testMode:true must be answered (Beacon MUST), not rejected"
    );
    let v = body_json(resp.into_body()).await;
    assert_eq!(
        v["meta"]["receivedRequestSummary"]["testMode"], true,
        "testMode:true must be echoed in receivedRequestSummary"
    );

    // requestedGranularity at query.* is echoed in receivedRequestSummary.
    let (state, _tmp) = state_with_covid();
    let router = build_router(state);
    let body = serde_json::json!({
        "query": {
            "requestParameters": {
                "referenceName": "3",
                "start": [45_823_239],
                "referenceBases": "T",
                "alternateBases": "C",
                "assemblyId": "GRCh38"
            },
            "requestedGranularity": "count"
        }
    });
    let req = Request::builder()
        .method("POST")
        .uri("/beacon/v2/g_variants")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp.into_body()).await;
    assert_eq!(
        v["meta"]["receivedRequestSummary"]["requestedGranularity"], "count",
        "granularity at query.* must be echoed"
    );
}

/// HTTP-level coverage of `apply_include_resultset_responses`'s `MISS` case through the
/// router. The shaping logic is unit-tested in the `beacon` crate; this asserts the service
/// wires `includeResultsetResponses` through to the response.
#[tokio::test]
async fn include_miss_returns_empty_result_sets() {
    let (state, _tmp) = state_with_covid();
    let router = build_router(state);

    let resp = router
        .oneshot(g_variants_with_include("MISS"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let v = body_json(resp.into_body()).await;
    // MISS keeps only the `exists:false` misses. The fixture's one dataset is a hit, so it is
    // dropped and `resultSets` comes back empty, with the `response` member still present.
    let result_sets = v["response"]["resultSets"].as_array().unwrap();
    assert!(
        result_sets.is_empty(),
        "MISS drops the only dataset (a hit)"
    );
    // responseSummary still reports the true match.
    assert_eq!(v["responseSummary"]["exists"], true);
    assert_eq!(v["responseSummary"]["numTotalResults"].as_u64().unwrap(), 1);
}

#[tokio::test]
async fn a_node_holding_no_datasets_still_answers_exists_false() {
    // With nothing to serve, "I do not hold this variant" is true, not a false negative.
    // Rejecting here would make an empty node indistinguishable from a misconfigured one.
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let state = AppState::new(
        test_config(&data_dir),
        StatusIndex::new(),
        NodeIdentities::empty(),
    );
    let router = build_router(state);
    // Both an assembly it does not serve and no assembly at all. With nothing visible there
    // is no served set to default from and nothing ambiguous, so neither is a 400, and
    // neither may claim an assembly the node does not have.
    for body in [wrong_assembly_body(), no_assembly_body()] {
        let req = Request::builder()
            .method("POST")
            .uri("/beacon/v2/g_variants")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "request: {body}");
        let v = body_json(resp.into_body()).await;
        assert_eq!(v["responseSummary"]["exists"], false, "request: {body}");
        assert!(
            v["meta"]["receivedRequestSummary"]["assumedAssemblyId"].is_null(),
            "an empty node has no assembly to assume: {v}"
        );
    }
}

/// With exactly one assembly among the visible datasets, a variant query that omits
/// `assemblyId` is answered with that assembly rather than rejected, and the assumed value is
/// echoed so the client can see what was searched.
///
/// This is the GDI User Portal's default search: its Java client omits the key when the user
/// selected no assembly. A `400` here is turned by the network facade into a silent
/// `exists:false` stub, so the node would contribute nothing to any default portal search.
#[tokio::test]
async fn absent_assembly_defaults_to_the_single_served_assembly() {
    let (state, _tmp) = state_with_covid();
    let router = build_router(state);
    let req = Request::builder()
        .method("POST")
        .uri("/beacon/v2/g_variants")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&no_assembly_body()).unwrap()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "an assembly-less query on a single-assembly node must be answered"
    );
    let v = body_json(resp.into_body()).await;
    assert_eq!(
        v["responseSummary"]["exists"], true,
        "the COVID site is a hit under the assumed assembly: {v}"
    );
    assert_eq!(
        v["response"]["resultSets"][0]["id"].as_str(),
        Some(DATASET_ID),
        "the single visible dataset answers: {v}"
    );
    assert_eq!(
        v["meta"]["receivedRequestSummary"]["assumedAssemblyId"].as_str(),
        Some("GRCh38"),
        "the assumed assembly must be echoed so the client can see what was searched: {v}"
    );
}

/// A query that names its assembly is not echoed as assumed. The echo means "the node filled
/// this in", so emitting it unconditionally would make it meaningless.
#[tokio::test]
async fn a_named_assembly_is_not_echoed_as_assumed() {
    let (state, _tmp) = state_with_covid();
    let router = build_router(state);
    let resp = router
        .oneshot(g_variants_with_include("HIT"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp.into_body()).await;
    assert!(
        v["meta"]["receivedRequestSummary"]["assumedAssemblyId"].is_null(),
        "assumedAssemblyId must be absent when the client supplied one: {v}"
    );
}

/// A dataset is only ever searched under its own assembly. On a node serving two, a `GRCh38`
/// query consults the `GRCh38` dataset and no other. Asserted under
/// `includeResultsetResponses: ALL`, which reports every consulted dataset whether it hit or
/// missed, so a cross-assembly scan shows up here even when it matches nothing.
#[tokio::test]
async fn a_multi_assembly_node_searches_only_the_matching_dataset() {
    let (state, _tmp) = state_with_two_assemblies();
    let router = build_router(state);
    let body = serde_json::json!({
        "query": {
            "requestParameters": {
                "referenceName": "3",
                "start": [45_823_239],
                "referenceBases": "T",
                "alternateBases": "C",
                "assemblyId": "GRCh38"
            },
            "includeResultsetResponses": "ALL"
        }
    });
    let req = Request::builder()
        .method("POST")
        .uri("/beacon/v2/g_variants")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp.into_body()).await;
    let ids: Vec<&str> = v["response"]["resultSets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|rs| rs["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        vec![DATASET_ID],
        "only the GRCh38 dataset may be consulted for a GRCh38 query: {v}"
    );
}

/// `pagination.limit` is clamped to `[beacon].max_page_limit`, 1000 by default, and
/// `meta.receivedRequestSummary.pagination` reports the effective limit. A client that asked
/// for more can then see it was capped, instead of reading a short page as "no more rows".
/// `limit: 0`, the Beacon unbounded sentinel, reports the cap too.
#[tokio::test]
async fn over_cap_pagination_limit_is_echoed_as_the_effective_limit() {
    for requested in [5000, 0] {
        let (state, _tmp) = state_with_covid();
        let router = build_router(state);
        let body = serde_json::json!({
            "query": {
                "requestParameters": {
                    "referenceName": "3",
                    "start": [45_000_000],
                    "end": [46_000_000],
                    "assemblyId": "GRCh38"
                },
                "pagination": { "skip": 0, "limit": requested }
            }
        });
        let req = Request::builder()
            .method("POST")
            .uri("/beacon/v2/g_variants")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp.into_body()).await;
        assert_eq!(
            v["meta"]["receivedRequestSummary"]["pagination"]["limit"].as_u64(),
            Some(1000),
            "a requested limit of {requested} must be echoed as the effective 1000: {v}"
        );
    }
}

/// The GDI User Portal's 1000-row range page is served whole, not clamped.
///
/// Its position-range search sends `pagination.limit: 1000` and never pages: it reads one
/// resultSet and stops. So any shipped `[beacon].max_page_limit` below 1000 truncates every
/// range result to the cap, with nothing but the echoed limit to say so. The shipped default
/// is 1000 for that reason, and its cost is documented under "Resource baseline" in
/// `docs/deployment.md`. The echo test above would stay green against any cap, so this is
/// what holds the default in place.
#[tokio::test]
async fn the_portals_thousand_row_range_page_is_not_clamped_at_the_shipped_default() {
    let (state, _tmp) = state_with_covid();
    let router = build_router(state);
    let body = serde_json::json!({
        "query": {
            "requestParameters": {
                "referenceName": "3",
                "start": [45_000_000],
                "end": [46_000_000],
                "assemblyId": "GRCh38"
            },
            "pagination": { "skip": 0, "limit": 1000 }
        }
    });
    let req = Request::builder()
        .method("POST")
        .uri("/beacon/v2/g_variants")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp.into_body()).await;
    assert_eq!(
        v["meta"]["receivedRequestSummary"]["pagination"]["limit"].as_u64(),
        Some(1000),
        "the portal asks for 1000 rows and does not page: the shipped cap must serve them \
         whole, not clamp: {v}"
    );
}
