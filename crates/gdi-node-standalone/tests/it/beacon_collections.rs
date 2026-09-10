//! Integration test for the aggregated Beacon `datasets` collections endpoint
//! (`beaconCollectionsResponse`), driven in-process via `tower::ServiceExt::oneshot`
//! against a router built from a real `AppState`.
//!
//! The COVID reference VCF is converted + ingested into a temp data dir and
//! inserted into the in-memory cache as `Visible`; a second, hidden dataset is also
//! inserted. A `POST {aggregated_base_path}/datasets` then:
//!
//! * returns `200` with the `beaconCollectionsResponse` envelope;
//! * `response.collections[0].id == datasetId` and `name == the title`;
//! * the hidden dataset is excluded (one collection, `numTotalResults == 1`);
//! * a `GET` of the same route behaves identically.

#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::path::{Path, PathBuf};

use axum::body::Body;

use crate::fixtures::body_json;
use axum::http::{Request, StatusCode};
use gdi_node_standalone::app::build_router;
use gdi_node_standalone::identities::NodeIdentities;
use gdi_node_standalone::state::AppState;
use gdi_node_standalone_core::cache::{DatasetEntry, StatusIndex};
use gdi_node_standalone_core::config::ServiceConfig;
use gdi_node_standalone_core::convert::{ConvertOptions, convert_vcf};
use gdi_node_standalone_core::ingest::ingest_staging_dir;
use gdi_node_standalone_core::model::{
    Agent, Assembly, DatasetMode, LocalizedText, Manifest, ManifestConfig, ManifestMetadata,
};
use gdi_node_standalone_core::parquet_io::DatasetEncryptor;
use gdi_node_standalone_core::state::DatasetState;
use gdi_node_standalone_core::validate_parquet::ParquetCaps;
use serde_json::Value;
use tower::ServiceExt as _; // for `oneshot`

const DATASET_ID: &str = "GDI-EE-UTARTU-20260409143052837";
const HIDDEN_ID: &str = "GDI-EE-UTARTU-20260411093000123";
const CATALOG: &str = "gdi-aggregated";
const TITLE: &str = "COVID monogenic AFs";

/// A representative valid manifest for the COVID dataset.
fn manifest_for(id: &str, number_of_records: u64) -> Manifest {
    Manifest {
        payload: None,
        metadata: ManifestMetadata {
            dataset_id: id.to_owned(),
            catalog: CATALOG.to_owned(),
            title: LocalizedText::Plain(TITLE.to_owned()),
            description: Some(LocalizedText::Plain("COVID monogenic AF panel.".to_owned())),
            access_rights: "http://publications.europa.eu/resource/authority/access-right/PUBLIC"
                .to_owned(),
            applicable_legislation: vec!["http://data.europa.eu/eli/reg/2018/1725/oj".to_owned()],
            license: "https://creativecommons.org/licenses/by/4.0/".to_owned(),
            creator: vec![Agent {
                name: "University of Tartu".to_owned(),
            }],
            health_category: vec![
                "http://data.gdi.eu/core/p2/HealthCategoryHumanGenomic".to_owned(),
            ],
            keywords: None,
            number_of_unique_individuals: None,
            conforms_to: None,
            type_: None,
            legal_basis: None,
            is_referenced_by: None,
            other_identifier: None,
            contact_point: None,
            number_of_records: Some(number_of_records),
            populations: None,
        },
        files: Vec::new(),
        internal: gdi_node_standalone_core::model::Internal::default(),
        config: ManifestConfig {
            mode: DatasetMode::Aggregated,
            block_range: 10_000_000,
            af_source: Some("The Genome of Europe".to_owned()),
            af_source_reference: Some("https://genomeofeurope.eu/".to_owned()),
            min_allele_count: 0,
            hide_lower_counts: None,
            assembly: Assembly {
                reference: "GRCh38".to_owned(),
            },
            manifest_version: 1,
            generated_by: "test".to_owned(),
        },
    }
}

/// Convert the COVID VCF into a staging dir under `parent`, write a manifest, and
/// return `(staging_dir, number_of_records)`.
fn build_staging_dir(parent: &Path, id: &str) -> (PathBuf, u64) {
    let staging = parent.join(format!("staging-{id}"));
    std::fs::create_dir_all(&staging).unwrap();
    let vcf = test_util::covid_vcf_path();
    let out = convert_vcf(
        &vcf,
        &staging,
        &ConvertOptions {
            assembly: "GRCh38".to_owned(),
            block_range: 10_000_000,
            min_allele_count: 0,
        },
    )
    .unwrap();
    let manifest = manifest_for(id, out.number_of_records);
    std::fs::write(
        staging.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    (staging, out.number_of_records)
}

/// Build a service config matching the test data dir.
fn test_config(data_dir: &Path) -> ServiceConfig {
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"

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
"#,
        data_dir.display(),
    );
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    cfg.preflight().unwrap();
    cfg
}

/// Build an `AppState` with the COVID dataset ingested + visible, plus a second
/// hidden dataset in the cache.
fn state_with_visible_and_hidden() -> (AppState, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();

    let (staging, _records) = build_staging_dir(tmp.path(), DATASET_ID);
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

    let config = test_config(&data_dir);
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());

    // The visible COVID dataset.
    let visible_metadata = ok.metadata.clone();
    let visible_config = ok.config.clone();
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
    // A second, hidden dataset (same metadata shape, different id): excluded.
    let mut hidden_metadata = visible_metadata;
    HIDDEN_ID.clone_into(&mut hidden_metadata.dataset_id);
    state.cache.insert(
        gdi_node_standalone_core::cache::StatusWrite::unshared(),
        DatasetEntry {
            id: HIDDEN_ID.to_owned(),
            metadata: hidden_metadata,
            config: visible_config,
            state: DatasetState::Hidden,
            metadata_modified: None,
        },
    );

    (state, tmp)
}

/// Assert the collections-response invariants over a parsed body: one collection
/// (the visible dataset), excluding the hidden one.
fn assert_one_visible_collection(v: &Value) {
    // beaconCollectionsResponse envelope: meta + responseSummary + response.collections.
    assert!(v["meta"].is_object(), "carries meta");
    assert_eq!(
        v["meta"]["returnedSchemas"][0]["entityType"], "dataset",
        "meta names the dataset schema"
    );
    let collections = v["response"]["collections"].as_array().unwrap();
    assert_eq!(collections.len(), 1, "hidden dataset is excluded");
    assert_eq!(collections[0]["id"], DATASET_ID);
    assert_eq!(collections[0]["name"], TITLE);
    // responseSummary reports the true visible count.
    assert_eq!(v["responseSummary"]["exists"], true);
    assert_eq!(v["responseSummary"]["numTotalResults"].as_u64().unwrap(), 1);
}

#[tokio::test]
async fn post_datasets_returns_visible_collection_excludes_hidden() {
    let (state, _tmp) = state_with_visible_and_hidden();
    let router = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/beacon/v2/datasets")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({})).unwrap(),
        ))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let v = body_json(resp.into_body()).await;
    assert_one_visible_collection(&v);
}

#[tokio::test]
async fn get_datasets_behaves_like_post() {
    let (state, _tmp) = state_with_visible_and_hidden();
    let router = build_router(state);

    let req = Request::builder()
        .method("GET")
        .uri("/beacon/v2/datasets")
        .body(Body::empty())
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let v = body_json(resp.into_body()).await;
    assert_one_visible_collection(&v);
}

/// A 400 on `/datasets` must name the `dataset` schema in its error meta, not the
/// request-agnostic `genomicVariant` default. This covers the HTTP wiring: the service
/// threads the literal `"dataset"` entry-type string into `reject_datasets`. That the string
/// resolves to the `dataset` schema URL and entityType is unit-tested in
/// `crates/beacon/tests/it/response_meta.rs`, and the reject conditions themselves (`geneId`
/// and submitted `filters`) in `crates/beacon/src/request.rs`.
#[tokio::test]
async fn datasets_error_meta_names_the_dataset_entry_type() {
    let (state, _tmp) = state_with_visible_and_hidden();
    let router = build_router(state);
    let req = Request::builder()
        .method("POST")
        .uri("/beacon/v2/datasets")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({
                "query": { "requestParameters": { "geneId": "BRCA1" } }
            }))
            .unwrap(),
        ))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v = crate::fixtures::body_json(resp.into_body()).await;
    assert_eq!(v["error"]["errorCode"], 400);
    assert_eq!(
        v["meta"]["returnedSchemas"][0]["entityType"], "dataset",
        "datasets error meta must name the dataset entry type, got {}",
        v["meta"]["returnedSchemas"]
    );
}

/// `/datasets` is public registry metadata with no disclosure ceiling to lower, so it
/// always serves `record`. But `receivedRequestSummary.requestedGranularity` echoes what the
/// client asked for: hard-coding `"record"` misreports a `boolean` or `count` request.
#[tokio::test]
async fn post_datasets_echoes_requested_granularity_but_serves_record() {
    let (state, _tmp) = state_with_visible_and_hidden();
    let router = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/beacon/v2/datasets")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({
                "query": { "requestParameters": {}, "requestedGranularity": "boolean" }
            }))
            .unwrap(),
        ))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp.into_body()).await;
    assert_eq!(
        v["meta"]["receivedRequestSummary"]["requestedGranularity"], "boolean",
        "receivedRequestSummary must echo the client's requestedGranularity: {v}"
    );
    assert_eq!(
        v["meta"]["returnedGranularity"], "record",
        "the public dataset listing is always served at record granularity: {v}"
    );
    // The listing is still fully served (not downgraded for boolean/count).
    assert_one_visible_collection(&v);
}

/// `/datasets` must apply the same envelope validation its sibling entry types do.
///
/// `docs/api.md` states unconditionally that an unknown `requestedGranularity`, a non-boolean
/// `testMode` and an out-of-enum `includeResultsetResponses` are each a `400`. `g_variants`
/// and `/individuals` reach those checks through `check_envelope`, which takes a
/// `NormalizedQuery` only a variant query produces, so `/datasets` has to run them itself.
/// Otherwise a client that typo'd its granularity gets a `200` whose
/// `receivedRequestSummary` claims it asked for `"record"`.
#[tokio::test]
async fn datasets_rejects_the_same_envelope_values_its_siblings_do() {
    for (query, what) in [
        ("requestedGranularity=bolean", "an unknown granularity"),
        ("testMode=maybe", "a non-boolean testMode"),
        (
            "includeResultsetResponses=all",
            "an out-of-enum includeResultsetResponses",
        ),
    ] {
        let (state, _tmp) = state_with_visible_and_hidden();
        let router = build_router(state);
        let req = Request::builder()
            .method("GET")
            .uri(format!("/beacon/v2/datasets?{query}"))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "{what} must be a 400 on /datasets exactly as on g_variants"
        );
    }

    // The control: valid envelope values still serve, so the check rejects the bad values
    // rather than the parameters themselves.
    let (state, _tmp) = state_with_visible_and_hidden();
    let router = build_router(state);
    let req = Request::builder()
        .method("GET")
        .uri("/beacon/v2/datasets?requestedGranularity=count&testMode=true")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
