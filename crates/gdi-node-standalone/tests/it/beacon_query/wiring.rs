//! Cross-cutting HTTP wiring: CORS preflight, security headers, deterministic
//! resultSet ordering, and the synchronous-handler audit-log trails.
use super::*;

/// A cross-origin CORS preflight for the JSON query path succeeds and advertises the `POST`
/// method and the `content-type` request header. Without both, a browser client cannot send a
/// cross-origin `POST` query despite the wildcard origin. The CORS layer answers the
/// preflight, so no ingested data is needed.
#[tokio::test]
async fn cors_preflight_allows_cross_origin_post_json() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let state = AppState::new(
        test_config(&data_dir),
        StatusIndex::new(),
        NodeIdentities::empty(),
    );
    let router = build_router(state);

    let req = Request::builder()
        .method("OPTIONS")
        .uri("/beacon/v2/g_variants")
        .header("origin", "https://client.example.org")
        .header("access-control-request-method", "POST")
        .header("access-control-request-headers", "content-type")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();

    assert!(
        resp.status().is_success(),
        "preflight status: {}",
        resp.status()
    );
    let h = resp.headers();
    assert_eq!(
        h.get("access-control-allow-origin").unwrap(),
        "*",
        "wildcard origin"
    );
    let methods = h
        .get("access-control-allow-methods")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        methods.contains("POST"),
        "allow-methods missing POST: {methods}"
    );
    let allow_headers = h
        .get("access-control-allow-headers")
        .unwrap()
        .to_str()
        .unwrap()
        .to_ascii_lowercase();
    assert!(
        allow_headers.contains("content-type"),
        "allow-headers missing content-type: {allow_headers}"
    );
}

#[tokio::test]
async fn public_responses_carry_nosniff_header() {
    // Every public-plane response carries `X-Content-Type-Options: nosniff`.
    let (state, _tmp) = state_with_covid();
    let router = build_router(state);
    let req = Request::builder()
        .method("GET")
        .uri("/beacon/v2/service-info")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.headers()
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff"),
        "public responses must carry nosniff"
    );
}

#[tokio::test]
async fn public_responses_forbid_intermediary_caching() {
    // Every withhold this node has (a channel take-down, the suppression store, a
    // `{id}.state.json` tombstone, the visibility-staleness bound) stops the node serving a
    // dataset. None of them reach a copy already held by a forward proxy or browser cache.
    // Without an explicit directive a cache may heuristically retain a `200`
    // (RFC 9111 §4.2.2), so a correct incident response can leave the pre-takedown answer
    // served by an intermediary indefinitely.
    //
    // The FAIR-DP half, the plane that enumerates datasets and where a stale copy
    // re-advertises a retracted one, is covered by `fdp_routes.rs`, which has a state with
    // `[fairdp]` configured. Here those routes are present but inert.
    let (state, _tmp) = state_with_covid();
    let router = build_router(state);
    for path in ["/beacon/v2/service-info", "/beacon/v2/datasets"] {
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .body(Body::empty())
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        // The header layer is outermost, so it stamps a 404 too, and a mistyped or removed
        // route would satisfy the assertion below while testing nothing. `assert_eq!(OK)`
        // rather than `assert_ne!(NOT_FOUND)`, which a 400, 500 or 503 would also satisfy,
        // letting the route degrade to an error and leave this green.
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::OK,
            "{path} did not serve, so the cache-control assertion below is vacuous"
        );
        let cc = resp
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok());
        assert_eq!(
            cc,
            Some("no-store"),
            "{path} must forbid intermediary caching; got {cc:?}. `no-cache` is not \
             sufficient: it permits storage and only forces revalidation, leaving the \
             withheld body on disk in the intermediary."
        );
    }
}

#[tokio::test]
async fn g_variants_result_sets_are_ordered_by_dataset_id() {
    // Two visible datasets that both match the query, ingested and inserted in descending-id
    // order. The concurrent per-dataset scan completes in nondeterministic order, so an
    // id-sorted response shows the scan re-sorts by id rather than echoing insertion or
    // completion order.
    const ID_HI: &str = "GDI-EE-UTARTU-20260409143052899";
    const ID_LO: &str = "GDI-EE-UTARTU-20260409143052801";

    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let mut catalogs = std::collections::BTreeMap::new();
    catalogs.insert(
        CATALOG.to_owned(),
        "Genome of Europe Aggregated Data".to_owned(),
    );

    let config = test_config(&data_dir);
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());

    for id in [ID_HI, ID_LO] {
        let staging = build_covid_staging_named_goe(tmp.path(), id);
        let ok = ingest_staging_dir(
            &staging,
            &data_dir,
            &ParquetCaps::default(),
            &catalogs,
            &DatasetEncryptor::plaintext(),
        )
        .unwrap();
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
    }

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
    let ids: Vec<&str> = result_sets
        .iter()
        .map(|rs| rs["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        vec![ID_LO, ID_HI],
        "resultSets must be deterministically ordered by dataset id"
    );
}

/// The synchronous-handler audit paths leave their trails end to end: the datasets listing
/// emits its enriched `beacon query` line carrying `elapsed_us`, and a malformed `g_variants`
/// query emits its `beacon_query_rejected` line.
///
/// Both audit on the request thread, without `spawn_blocking`. On-thread emission is not
/// sufficient under the parallel harness, because sibling tests hitting the `audit` callsite
/// with no subscriber poison its process-global `tracing` interest, so
/// `ensure_capture_safe_tracing` installs a permissive global default first. The `g_variants`
/// answered-line field content, meaning assembly and dataset ids, runs through
/// `spawn_blocking` and is covered by the `audit.rs` unit tests.
#[test]
fn audit_log_records_dataset_listing_and_rejected_query() {
    use tracing_subscriber::layer::SubscriberExt as _;

    // Keep the thread-local capture below reliable under the parallel harness. The helper's
    // docs describe the `tracing` global-interest-cache race it defends against.
    crate::fixtures::ensure_capture_safe_tracing();

    let (state, _tmp) = state_with_covid();
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
            // Answered query on a fully-synchronous handler: the datasets listing
            // audits on the request thread, so the line is reliably captured.
            let req = Request::builder()
                .method("GET")
                .uri("/beacon/v2/datasets")
                .body(Body::empty())
                .unwrap();
            let resp = router.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);

            // Malformed query (unsupported `geneId` parameter) → 400 reject.
            let bad = serde_json::json!({
                "query": { "requestParameters": { "geneId": "BRCA1" } }
            });
            let req = Request::builder()
                .method("POST")
                .uri("/beacon/v2/g_variants")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&bad).unwrap()))
                .unwrap();
            let resp = router.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        });
    });

    let out = writer.contents();
    // The enriched answered line is emitted end-to-end (operational detail present).
    assert!(
        out.contains("\"entry_type\":\"dataset\""),
        "datasets audit line: {out}"
    );
    assert!(out.contains("elapsed_us"), "elapsed logged: {out}");
    // ...and it names the datasets it served. Passing `dataset_ids: &[]` here would leave
    // the one audited endpoint whose job is to enumerate datasets reporting that it touched
    // none, making a listing indistinguishable afterwards from a request that returned
    // nothing.
    assert!(
        out.contains(DATASET_ID),
        "the datasets audit line must name the served page: {out}"
    );
    assert!(
        out.contains("\"datasets_scanned\":1"),
        "the served page is one dataset here: {out}"
    );
    // The rejected query leaves a trail too.
    assert!(
        out.contains("beacon_query_rejected"),
        "reject audit line: {out}"
    );
    assert!(out.contains("\"code\":400"), "reject code logged: {out}");
}

/// A variant query that classifies cleanly but resolves no assembly on a node serving several
/// is rejected with a `400`, and leaves an audit trail. The reject fires before any
/// `spawn_blocking` scan, so the `with_default` thread-local subscriber captures it reliably
/// under the parallel harness, as it does for the malformed-query reject above.
///
/// The same body against a single-assembly node is answered with the assumed assembly, which
/// `absent_assembly_defaults_to_the_single_served_assembly` covers, so the audited reject is
/// the ambiguous case.
#[test]
fn variant_query_without_assembly_is_audited() {
    use tracing_subscriber::layer::SubscriberExt as _;

    // Keep the thread-local capture reliable under the parallel harness.
    crate::fixtures::ensure_capture_safe_tracing();

    let (state, _tmp) = state_with_two_assemblies();
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
            // A well-formed Sequence query (referenceName + start + ref/alt bases) with no
            // assemblyId: `"3"` resolves a chromosome but not an assembly, and this
            // node serves two, so the handler's ambiguity guard rejects it with a 400.
            let body = no_assembly_body();
            let req = Request::builder()
                .method("POST")
                .uri("/beacon/v2/g_variants")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap();
            let resp = router.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        });
    });

    let out = writer.contents();
    assert!(
        out.contains("beacon_query_rejected"),
        "no-assembly reject now audited: {out}"
    );
    assert!(out.contains("\"code\":400"), "reject code logged: {out}");
    assert!(out.contains("ambiguous"), "reject reason logged: {out}");
}
