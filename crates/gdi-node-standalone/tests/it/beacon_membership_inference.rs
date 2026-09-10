//! Membership-inference equivalence. Three `g_variants` queries produce the same observable
//! wire shape at every granularity: one whose variant is present but fully suppressed by the
//! `min_allele_count` floor, one whose variant is genuinely absent from an existing dataset,
//! and one against a chromosome no dataset matches. Otherwise a client can tell "suppressed"
//! from "absent" and infer membership of a privacy-sensitive aggregate beacon.
//!
//! The COVID fixture holds exactly one variant (chr3:45823240 T>C, Total AC=618),
//! so a `[beacon].min_allele_count` above 618 suppresses the whole group, which
//! `assemble` then drops — collapsing scenario (1) into (2)/(3).
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::path::Path;

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
use serde_json::Value;
use tower::ServiceExt as _; // for `oneshot`

use crate::fixtures::{body_json, build_covid_staging_named_goe};

const DATASET_ID: &str = "GDI-EE-UTARTU-20260409143052837";
const CATALOG: &str = "gdi-aggregated";

/// Service config with an explicit `[beacon].min_allele_count` serving floor.
fn config_with_floor(data_dir: &Path, floor: u32) -> ServiceConfig {
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
min_allele_count = {floor}

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

/// An `AppState` with the COVID dataset ingested + visible and the node serving
/// floor set to `floor`. Returns the `TempDir` so the data dir outlives queries.
fn state_with_floor(floor: u32) -> (AppState, tempfile::TempDir) {
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

    let config = config_with_floor(&data_dir, floor);
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

/// Issue one `g_variants` POST against a fresh router built from a clone of `state`.
async fn query(
    state: AppState,
    reference_name: &str,
    start: i64,
    granularity: &str,
) -> (StatusCode, Value) {
    let router = build_router(state);
    let body = serde_json::json!({
        "query": {
            "requestParameters": {
                "referenceName": reference_name,
                "start": [start],
                "referenceBases": "T",
                "alternateBases": "C",
                "assemblyId": "GRCh38",
                "requestedGranularity": granularity
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
    let status = resp.status();
    (status, body_json(resp.into_body()).await)
}

/// The membership-observable projection of a response: everything a client can see
/// that could distinguish "suppressed" from "absent".
fn observable(status: StatusCode, v: &Value) -> Value {
    serde_json::json!({
        "status": status.as_u16(),
        "exists": v["responseSummary"]["exists"],
        "hasNumTotalResults": v["responseSummary"].get("numTotalResults").is_some(),
        "numTotalResults": v["responseSummary"].get("numTotalResults").cloned(),
        "hasResponseMember": v.get("response").is_some(),
        "returnedGranularity": v["meta"]["returnedGranularity"],
    })
}

/// For one granularity, the three negative scenarios must be wire-indistinguishable.
async fn assert_three_scenarios_equivalent(granularity: &str) {
    // One node with the floor high enough to suppress the only COVID variant.
    let (state, _tmp) = state_with_floor(1000);

    // (1) present-but-fully-suppressed: the real variant, floored away.
    let (s1, v1) = query(state.clone(), "3", 45_823_239, granularity).await;
    let o1 = observable(s1, &v1);
    // (2) genuinely absent variant in the same existing dataset (chr3:1, no row).
    let (s2, v2) = query(state.clone(), "3", 1, granularity).await;
    let o2 = observable(s2, &v2);
    // (3) a chromosome with no matching dataset (no chr7 data ingested).
    let (s3, v3) = query(state.clone(), "7", 1, granularity).await;
    let o3 = observable(s3, &v3);

    assert_eq!(
        o1, o2,
        "[{granularity}] suppressed vs absent differ:\n{o1}\nvs\n{o2}"
    );
    assert_eq!(
        o1, o3,
        "[{granularity}] suppressed vs no-dataset differ:\n{o1}\nvs\n{o3}"
    );

    // Sanity: all three are negatives (exists:false) at HTTP 200.
    assert_eq!(o1["status"], 200);
    assert_eq!(o1["exists"], false, "all three must report no match");
    assert_eq!(o1["returnedGranularity"], granularity);
}

#[tokio::test]
async fn membership_inference_boolean_is_indistinguishable() {
    assert_three_scenarios_equivalent("boolean").await;
}

#[tokio::test]
async fn membership_inference_count_is_indistinguishable() {
    assert_three_scenarios_equivalent("count").await;
}

#[tokio::test]
async fn membership_inference_record_is_indistinguishable() {
    assert_three_scenarios_equivalent("record").await;
}
