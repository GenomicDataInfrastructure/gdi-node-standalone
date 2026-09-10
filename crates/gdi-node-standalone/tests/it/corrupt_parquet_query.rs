//! A Visible dataset whose stored parquet is overwritten with garbage must make
//! `g_variants` return a `500` `beaconErrorResponse` (no allele rows leaked) and
//! the process must survive — the scan failure is an `Err`, never a panic.
//!
//! Reachable on default features (plaintext): the query path opens the data file
//! via `read_matching_rows`, whose `ParquetRecordBatchReaderBuilder::try_new`
//! returns `Err` on garbage -> `CoreError::InvalidParquet` -> `scan_selected_datasets`
//! maps `Ok(Err(_))` to a `500` envelope.
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::path::{Path, PathBuf};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use gdi_node_standalone::app::build_router;
use gdi_node_standalone::identities::NodeIdentities;
use gdi_node_standalone::state::AppState;
use gdi_node_standalone_core::cache::{DatasetEntry, StatusIndex};
use gdi_node_standalone_core::config::ServiceConfig;
use gdi_node_standalone_core::ingest::ingest_staging_dir;
use gdi_node_standalone_core::parquet_io::DatasetEncryptor;
use gdi_node_standalone_core::state::DatasetState;
use gdi_node_standalone_core::validate_parquet::ParquetCaps;
use test_util::covid;
use tower::ServiceExt as _;

use crate::fixtures::{body_json, build_covid_staging_named_goe};

const DATASET_ID: &str = "GDI-EE-UTARTU-20260409143052837";
const CATALOG: &str = "gdi-aggregated";

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

/// Like `beacon_query::state_with_covid`, but also returns the published
/// dataset dir so the test can find + garble its stored parquet.
fn state_with_covid() -> (AppState, tempfile::TempDir, PathBuf) {
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

    let dataset_dir = data_dir.join(&ok.id);
    let config = test_config(&data_dir);
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
    (state, tmp, dataset_dir)
}

#[tokio::test]
async fn corrupt_stored_parquet_yields_500_beacon_error_no_rows() {
    let (state, _tmp, dataset_dir) = state_with_covid();

    // Overwrite the chr3 block-4 stored parquet (read-only after ingest) with
    // garbage so the query-time reader open fails.
    let file = std::fs::read_dir(&dataset_dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("allele-freq.chr3.4.") && n.ends_with(".parquet"))
        })
        .expect("published chr3 block-4 parquet present");
    // The stored parquet is read-only after ingest; make it writable to overwrite.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    std::fs::write(&file, b"not a parquet file at all, just garbage bytes").unwrap();

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
    assert_eq!(
        resp.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "a corrupt stored parquet must yield a 500"
    );

    let v = body_json(resp.into_body()).await;
    // beaconErrorResponse envelope: meta + error.errorCode == 500.
    assert!(
        v["meta"].is_object(),
        "500 carries the beacon meta envelope"
    );
    assert_eq!(v["error"]["errorCode"].as_u64(), Some(500));
    assert!(v["error"]["errorMessage"].is_string());

    // Fail-closed: no allele data leaked through the error path. Scrub the random
    // `requestId` first — its hex digits can coincidentally contain the count's
    // decimal digits and false-positive the numeric scan below (a flaky-test bug).
    let text = crate::fixtures::error_body_without_request_id(&v);
    assert!(
        v.get("response").is_none(),
        "no resultSets/response body on the error path: {v}"
    );
    assert!(
        !text.contains("frequencyInPopulations"),
        "no frequencies may leak: {text}"
    );
    assert!(
        !text.contains("FI_M"),
        "no per-population row may leak: {text}"
    );
    assert!(
        !text.contains(&covid::TOTAL_AC.to_string()),
        "no Total alleleCount may leak: {text}"
    );
    // Reaching here proves the process survived (no panic escaped the scan).
}
