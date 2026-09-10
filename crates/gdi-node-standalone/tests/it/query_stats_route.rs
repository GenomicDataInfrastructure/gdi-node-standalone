//! `GET /stats/queries` on the management plane, behind an opt-in flag.
//!
//! The counters are recorded on the public plane, by the Beacon and FDP answers, and read on
//! the management one, so every test here drives both routers off a single shared
//! `AppState`. That is also the only way to show the two halves are wired to the same
//! registry.
//!
//! The case that carries the feature is [`hit_is_the_datasets_own_match_not_the_querys`]: two
//! datasets, one query, one match. The rest is bookkeeping a single-dataset test would
//! confirm just as well.
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::path::Path;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use gdi_node_standalone::app::{build_management_router, build_router};
use gdi_node_standalone::identities::NodeIdentities;
use gdi_node_standalone::state::AppState;
use gdi_node_standalone_core::cache::{DatasetEntry, StatusIndex};
use gdi_node_standalone_core::config::ServiceConfig;
use gdi_node_standalone_core::convert::{ConvertOptions, convert_vcf};
use gdi_node_standalone_core::ingest::ingest_staging_dir;
use gdi_node_standalone_core::parquet_io::DatasetEncryptor;
use gdi_node_standalone_core::query_stats::QueryStatsSnapshot;
use gdi_node_standalone_core::state::DatasetState;
use gdi_node_standalone_core::validate_parquet::ParquetCaps;
use tower::ServiceExt as _; // for `oneshot`

use crate::fixtures::manifest_for_goe;

/// Serves the COVID variants under its own (permissive) floor.
const OPEN_ID: &str = "GDI-EE-UTARTU-20260409143052837";
/// The same COVID data behind a floor high enough to suppress every cell, so it is
/// consulted by the same queries and matches none of them.
const SUPPRESSED_ID: &str = "GDI-EE-UTARTU-20260409143052838";
const CATALOG: &str = "gdi-aggregated";
const AGG_BASE_PATH: &str = "/beacon/v2";

/// A floor no COVID cell can clear, so the dataset carrying it answers `exists:false` at
/// every granularity while still being scanned.
const SUPPRESSING_FLOOR: u32 = 1_000_000;

fn test_config(data_dir: &Path, stats_enabled: bool) -> ServiceConfig {
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"

[stats]
enabled = {stats_enabled}

[catalogs]
{CATALOG} = "Genome of Europe Aggregated Data"

[beacon]
aggregated_base_path = "{AGG_BASE_PATH}"
id = "org.test.beacon"
name = "Test Beacon"
environment = "test"

[beacon.organization]
id = "ee.ut.gdi"
name = "University of Tartu"

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
"#,
        data_dir.display(),
    );
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    cfg.preflight().unwrap();
    cfg
}

/// Convert and ingest the COVID VCF as `id`, with `min_allele_count` in its manifest set to
/// `floor`, the per-dataset half of `effective_floor`.
///
/// Local rather than in `fixtures`, because every shared builder there fixes the floor at `0`
/// and this suite needs two datasets that differ only in what they may disclose.
fn ingest_covid_with_floor(parent: &Path, data_dir: &Path, id: &str, floor: u32) -> DatasetEntry {
    let staging = parent.join(format!("staging-{id}"));
    std::fs::create_dir_all(&staging).unwrap();
    let out = convert_vcf(
        &test_util::covid_vcf_path(),
        &staging,
        &ConvertOptions {
            assembly: "GRCh38".into(),
            block_range: 10_000_000,
            min_allele_count: 0,
        },
    )
    .unwrap();
    let mut manifest = manifest_for_goe(id, out.number_of_records);
    manifest.config.min_allele_count = floor;
    std::fs::write(
        staging.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let mut catalogs = std::collections::BTreeMap::new();
    catalogs.insert(
        CATALOG.to_owned(),
        "Genome of Europe Aggregated Data".to_owned(),
    );
    let ok = ingest_staging_dir(
        &staging,
        data_dir,
        &ParquetCaps::default(),
        &catalogs,
        &DatasetEncryptor::plaintext(),
    )
    .unwrap();
    DatasetEntry {
        id: ok.id,
        metadata: ok.metadata,
        config: ok.config,
        state: DatasetState::Visible,
        metadata_modified: None,
    }
}

/// An `AppState` serving both datasets, visible, in one catalog.
fn state_with_two_datasets(stats_enabled: bool) -> (AppState, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();

    let open = ingest_covid_with_floor(tmp.path(), &data_dir, OPEN_ID, 0);
    let suppressed =
        ingest_covid_with_floor(tmp.path(), &data_dir, SUPPRESSED_ID, SUPPRESSING_FLOOR);

    let config = test_config(&data_dir, stats_enabled);
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
    state.cache.insert(
        gdi_node_standalone_core::cache::StatusWrite::unshared(),
        open,
    );
    state.cache.insert(
        gdi_node_standalone_core::cache::StatusWrite::unshared(),
        suppressed,
    );
    (state, tmp)
}

/// Drive one request through the public router and return its status.
async fn public(state: &AppState, request: Request<Body>) -> StatusCode {
    build_router(state.clone())
        .oneshot(request)
        .await
        .unwrap()
        .status()
}

/// A COVID `g_variants` POST at `granularity` for the known chr3:45823240 T>C site.
fn covid_query(granularity: &str) -> Request<Body> {
    let body = serde_json::json!({
        "query": {
            "requestParameters": {
                "referenceName": "3",
                "start": [45_823_239],
                "referenceBases": "T",
                "alternateBases": "C",
                "assemblyId": "GRCh38",
                "requestedGranularity": granularity
            }
        }
    });
    Request::builder()
        .method("POST")
        .uri(format!("{AGG_BASE_PATH}/g_variants"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

/// `GET` on the management plane.
async fn management(state: &AppState, uri: &str) -> (StatusCode, String) {
    let resp = build_management_router(state.clone(), None)
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// The parsed `/stats/queries` document, parsed into the shipped wire type.
///
/// A consumer-side convenience, not a schema bind. A round-trip through the same struct that
/// produced the body cannot notice a field the published `docs/query-stats.schema.json` no
/// longer carries, or a rename applied to both sides at once. The `test-schema` gate leg
/// (`ci-local.sh test-schema`) is what binds the struct to the published schema.
async fn stats(state: &AppState) -> QueryStatsSnapshot {
    let (status, body) = management(state, "/stats/queries").await;
    assert_eq!(status, StatusCode::OK, "stats route: {body}");
    serde_json::from_str(&body).unwrap()
}

/// A query consults both datasets; only the one that could disclose a cell is a hit.
///
/// This holds at every granularity, and `boolean` and `count` are where it is easy to get
/// wrong. There the per-dataset resultSets never reach the wire, only the OR-ed
/// `responseSummary.exists` does, so an implementation that attributes the query's answer to
/// each consulted dataset looks correct on `record` and doubles `hit` here.
#[tokio::test]
async fn hit_is_the_datasets_own_match_not_the_querys() {
    for granularity in ["RECORD", "COUNT", "BOOLEAN"] {
        let (state, _tmp) = state_with_two_datasets(true);
        assert_eq!(
            public(&state, covid_query(granularity)).await,
            StatusCode::OK
        );

        let snap = stats(&state).await;
        let open = snap.datasets[OPEN_ID];
        let suppressed = snap.datasets[SUPPRESSED_ID];
        assert_eq!(
            (open.consulted, open.hit),
            (1, 1),
            "{granularity}: the permissive dataset was consulted and matched"
        );
        assert_eq!(
            (suppressed.consulted, suppressed.hit),
            (1, 0),
            "{granularity}: the suppressed dataset was consulted but disclosed nothing, so \
             it is not a hit"
        );
    }
}

/// A query that matches nothing still counts as a consultation of every dataset it scanned.
///
/// `consulted` answers "was this dataset asked about", which is the question a provider is
/// really asking; conflating it with `hit` would make an unused-but-queried dataset
/// indistinguishable from one nobody ever asked for.
#[tokio::test]
async fn a_miss_is_consulted_but_not_hit() {
    let (state, _tmp) = state_with_two_datasets(true);
    let body = serde_json::json!({
        "query": {
            "requestParameters": {
                "referenceName": "3",
                "start": [1],
                "referenceBases": "A",
                "alternateBases": "G",
                "assemblyId": "GRCh38",
                "requestedGranularity": "RECORD"
            }
        }
    });
    let request = Request::builder()
        .method("POST")
        .uri(format!("{AGG_BASE_PATH}/g_variants"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    assert_eq!(public(&state, request).await, StatusCode::OK);

    let snap = stats(&state).await;
    for id in [OPEN_ID, SUPPRESSED_ID] {
        assert_eq!(snap.datasets[id].consulted, 1, "{id} was consulted");
        assert_eq!(snap.datasets[id].hit, 0, "{id} matched nothing");
    }
}

/// `listed` counts the served page, not the visible set.
///
/// With `limit=1` the second dataset is visible and counted in `numTotalResults`, but not
/// listed. A paging-blind implementation loses that distinction, and with it the meaning of
/// the number: how often somebody saw this dataset in a listing.
#[tokio::test]
async fn a_listing_counts_only_the_page_it_served() {
    let (state, _tmp) = state_with_two_datasets(true);
    let request = Request::builder()
        .uri(format!("{AGG_BASE_PATH}/datasets?skip=0&limit=1"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(public(&state, request).await, StatusCode::OK);

    let snap = stats(&state).await;
    // Ordered by id, so the first page is the lower id.
    assert_eq!(snap.datasets[OPEN_ID].listed, 1);
    assert_eq!(
        snap.datasets.get(SUPPRESSED_ID).map(|d| d.listed),
        None,
        "a dataset beyond the served page must not be counted as listed"
    );
}

/// An FDP dataset read counts for that dataset; a catalog read counts for nobody.
///
/// A catalog read is catalog-keyed: attributing it to every dataset the catalog contains
/// would inflate each provider's number by traffic that never asked about their dataset.
#[tokio::test]
async fn an_fdp_dataset_read_counts_and_a_catalog_read_does_not() {
    let (state, _tmp) = state_with_two_datasets(true);
    for uri in [
        format!("/fairdp/dataset/{OPEN_ID}"),
        format!("/fairdp/distribution/{OPEN_ID}"),
        format!("/fairdp/catalog/{CATALOG}"),
    ] {
        let request = Request::builder().uri(&uri).body(Body::empty()).unwrap();
        assert_eq!(public(&state, request).await, StatusCode::OK, "GET {uri}");
    }

    let snap = stats(&state).await;
    assert_eq!(
        snap.datasets[OPEN_ID].fairdp_reads, 2,
        "the dataset and distribution reads count, the catalog read does not"
    );
    assert_eq!(
        snap.datasets.get(SUPPRESSED_ID),
        None,
        "the catalog read must not be attributed to the datasets it contains"
    );
}

/// With the flag off the route is absent, and nothing is counted either.
///
/// The `/version` control is what makes the `404` meaningful. Without it, a router that
/// failed to build at all would pass this test.
#[tokio::test]
async fn the_route_is_absent_and_nothing_is_recorded_when_the_flag_is_off() {
    let (state, _tmp) = state_with_two_datasets(false);
    assert_eq!(public(&state, covid_query("RECORD")).await, StatusCode::OK);

    let (status, _) = management(&state, "/stats/queries").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "off means absent, not forbidden: a 403 would confirm the flag exists"
    );
    let (version_status, _) = management(&state, "/version").await;
    assert_eq!(
        version_status,
        StatusCode::OK,
        "the rest of the management plane is unaffected"
    );
    assert!(
        state
            .query_stats
            .snapshot("2026-08-10T00:00:00Z")
            .datasets
            .is_empty(),
        "a node that did not opt in must not accumulate the counters either"
    );
}

/// The published `startedAt` is the node's single process-start stamp, not a second one taken
/// when the counters were created.
///
/// A poller keys reset detection on this value, so it must move only when the process does.
#[tokio::test]
async fn the_boot_stamp_is_the_readiness_views_process_start() {
    let (state, _tmp) = state_with_two_datasets(true);
    let snap = stats(&state).await;
    assert_eq!(snap.started_at, state.readiness.started_at());
    assert_eq!(snap.schema_version, 1);
    assert!(
        snap.datasets.is_empty(),
        "a node that has answered nothing reports an empty map, not an error"
    );
}
