//! Integration test for the HTTP layer: the aggregated Beacon
//! `g_variants` query mounted in the service binary, driven in-process via
//! `tower::ServiceExt::oneshot` against a router built from a real `AppState`.
//!
//! The COVID reference VCF is converted and ingested into a temp data dir and inserted into
//! the in-memory cache as `Visible`, then:
//!
//! * a `record`-granularity `g_variants` POST for the known chr3:45823240 T>C site returns
//!   `200` and the real `frequencyInPopulations`, with the `FI_M` entry at
//!   `alleleFrequency ≈ 0.085` and the `Total` entry at `alleleCount == 618`;
//! * an oversized body is rejected with `413`;
//! * a malformed envelope is rejected with `400` rendered as a `beaconErrorResponse`. The
//!   geneId rejection and unsupported-filters logic are unit-tested in
//!   `crates/beacon/src/request.rs`;
//! * `GET /service-info` returns the bare GA4GH `ServiceInfo`, with no `{meta, response}`.
//!
//! The submodules split the suite by concern:
//!   * [`errors`] — 400, 413, 414 and 415 rejection rendering: malformed body, oversized
//!     body or target, wrong content-type, misplaced envelope.
//!   * [`misc`] — the bare `service-info` response and the store scrub check on the same
//!     ingested COVID fixture.
//!   * [`results`] — `g_variants` response shaping: record frequencies, GET and POST
//!     agreement, granularity, `includeResultsetResponses`, envelope-sibling fields.
//!   * [`wiring`] — CORS, response headers, resultSet ordering, and audit-log wiring.
//!
//! This file holds what those submodules share: the imports, the dataset id and catalog, and
//! the `test_config`, `state_with_covid` and `g_variants_with_include` helpers.
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
use tower::ServiceExt as _; // for `oneshot`

use crate::fixtures::{body_json, build_covid_staging_named_goe};

mod errors;
mod misc;
mod results;
mod wiring;

const DATASET_ID: &str = "GDI-EE-UTARTU-20260409143052837";
/// A second dataset id, used only by the assembly-policy tests that need a node whose visible
/// datasets declare two assemblies. See [`state_with_two_assemblies`].
const DATASET_ID_GRCH37: &str = "GDI-EE-UTARTU-20260409143052771";
const CATALOG: &str = "gdi-aggregated";

/// Build a service config with a small `max_request_body_bytes` so the 413 case is
/// easy to trigger.
fn test_config(data_dir: &Path) -> ServiceConfig {
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
"#,
        data_dir.display(),
    );
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    cfg.preflight().unwrap();
    cfg
}

/// Build an `AppState` with the COVID dataset ingested and visible in the cache.
///
/// `pub(crate)` because `api_doc_routes` needs a node that serves a variant, to check
/// `docs/api.md`'s `variation` example against live output. Every other caller is in this
/// module tree.
pub(crate) fn state_with_covid() -> (AppState, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();

    // Build a staging dir and ingest it directly (deterministic, no runtime poll).
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
    (state, tmp)
}

/// Convert + ingest the COVID fixture as `id` declaring `assembly`, and return the
/// ingested entry, `Visible`, ready for the cache.
fn ingest_covid_as(
    parent: &Path,
    data_dir: &Path,
    id: &str,
    assembly: &str,
) -> gdi_node_standalone_core::cache::DatasetEntry {
    let staging = crate::fixtures::build_covid_staging_named_goe_on(parent, id, assembly);
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

/// Build an `AppState` serving two assemblies: the COVID dataset ingested twice, once
/// declaring `GRCh38` ([`DATASET_ID`]) and once `GRCh37` ([`DATASET_ID_GRCH37`]).
///
/// The node's served-assembly set is derived from the visible datasets, so this is the only
/// shape in which an omitted `assemblyId` is ambiguous.
fn state_with_two_assemblies() -> (AppState, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();

    let config = test_config(&data_dir);
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
    for (id, assembly) in [(DATASET_ID, "GRCh38"), (DATASET_ID_GRCH37, "GRCh37")] {
        state.cache.insert(
            gdi_node_standalone_core::cache::StatusWrite::unshared(),
            ingest_covid_as(tmp.path(), &data_dir, id, assembly),
        );
    }
    (state, tmp)
}

/// Build a `g_variants` POST for the known chr3:45823240 T>C site with a given
/// `includeResultsetResponses` value.
fn g_variants_with_include(include: &str) -> Request<Body> {
    let body = serde_json::json!({
        "query": {
            "requestParameters": {
                "referenceName": "3",
                "start": [45_823_239],
                "referenceBases": "T",
                "alternateBases": "C",
                "assemblyId": "GRCh38",
                "requestedGranularity": "RECORD",
                "includeResultsetResponses": include
            }
        }
    });
    Request::builder()
        .method("POST")
        .uri("/beacon/v2/g_variants")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

/// The GDI User Portal's default variant search: a well-formed Sequence query with no
/// `assemblyId`, because its client omits the key when the user selected no assembly.
fn no_assembly_body() -> serde_json::Value {
    serde_json::json!({
        "query": { "requestParameters": {
            "referenceName": "3",
            "start": [45_823_239],
            "referenceBases": "T",
            "alternateBases": "C"
        } }
    })
}

/// A well-formed variant query naming an assembly the node does not serve.
fn wrong_assembly_body() -> serde_json::Value {
    serde_json::json!({
        "query": { "requestParameters": {
            "referenceName": "3",
            "start": [45_823_239],
            "referenceBases": "T",
            "alternateBases": "C",
            "assemblyId": "GRCh37"
        } }
    })
}
