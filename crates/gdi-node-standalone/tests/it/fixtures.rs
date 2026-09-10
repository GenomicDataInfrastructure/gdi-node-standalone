//! Shared manifest and staging fixtures for the `it` integration-test binary.
//!
//! Three manifest factories cover the suites: [`manifest_for`] for standard ingest,
//! [`manifest_for_goe`] for the Genome-of-Europe Beacon, and [`manifest_for_fdp`] for the
//! FAIR Data Point. They differ in `af_source` and applicable legislation; each factory's
//! own doc says how.
//!
//! The staging-dir builders all convert the bundled COVID VCF and differ only in the
//! staging subdirectory layout and in which manifest factory they call.
//!
//! A fixture that only one suite uses stays in that suite.

#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use axum::body::{Body, to_bytes};
use gdi_node_standalone::ingest_runtime::IngestRuntime;
use gdi_node_standalone_core::cache::DatasetEntry;
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

/// The inbox-ingest `ServiceConfig` the ingest-shaped suites all build: a data dir, an
/// inbox, one catalog, and the test beacon identity. Loaded from TOML and preflighted,
/// exactly as the service does at boot.
///
/// `preflight()` runs here rather than in the caller. A config that does not preflight is
/// not one the service would ever run, so a fixture that skipped it would test a shape
/// production cannot reach.
pub(crate) fn inbox_config(data_dir: &Path, inbox: &Path, catalog: &str) -> ServiceConfig {
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"
inbox = "{}"
ingest_concurrency = 2
rescan_interval_seconds = 3600

[catalogs]
{catalog} = "Genome of Europe Aggregated Data"

[beacon]
id = "org.test.beacon"
name = "Test Beacon"
"#,
        data_dir.display(),
        inbox.display(),
    );
    let cfg = ServiceConfig::from_toml_str(&toml).expect("fixture config parses");
    cfg.preflight().expect("fixture config preflights");
    cfg
}

/// Write a crypt4gh secret key to `path` with owner-only (`0o600`) permissions.
///
/// The node's key-permission preflight rejects a world-readable identity file, so a test
/// that wrote one with default permissions would fail for an unrelated reason. Kept here so
/// the suites that stage identities cannot drift on the mode.
pub(crate) fn write_identity(path: &Path, sk: &gdi_node_standalone_core::crypt4gh::SecretKey) {
    std::fs::write(
        path,
        gdi_node_standalone_core::crypt4gh::serialize_secret_key(sk),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

/// Poll `cond` until it returns `true` or `timeout` elapses; panics on timeout.
///
/// Bounded rather than a fixed `sleep`, so a suite neither races a slow machine nor pays a
/// fixed cost on a fast one.
///
/// Not an `async fn`: it is a plain fn returning a future, so that `#[track_caller]` works.
/// On an `async fn` the attribute is accepted, but the body runs inside the generated
/// future's `poll`, so a panic reports this file's line and the caller's is lost. A test
/// that awaits two conditions would then fail with the same message at every call site.
/// Capturing `Location::caller()` before entering the async block names the awaiting line.
#[track_caller]
pub(crate) fn poll_until<F: FnMut() -> bool>(
    timeout: std::time::Duration,
    mut cond: F,
) -> impl std::future::Future<Output = ()> {
    let caller = std::panic::Location::caller();
    async move {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if cond() {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "condition not met within {timeout:?}, awaited at {caller}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    }
}

/// Wait until the ingest runtime is quiescent: nothing queued or running, and every
/// in-flight guard cleared.
///
/// `on_success` publishes a dataset to the cache before it consumes the source artifact,
/// and `worker_loop` clears the job's in-flight guard only after `process_job` returns, so
/// `poll_until(Visible)` can return while the source is still present and the guard still
/// set. Tests that assert on post-publish side effects (source consumed, `.incoming/`
/// cleaned, or a reconcile's `apply_removed` eviction, which excludes in-flight ids) must
/// drain here first. `poll_until(Visible)` means published, not settled.
pub(crate) async fn await_ingest_quiescent(runtime: &IngestRuntime) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while runtime.test_inflight_count() != 0 {
        assert!(
            Instant::now() < deadline,
            "ingest runtime did not reach quiescence within 20s"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Read an `axum` response/request [`Body`] fully and parse it as JSON. The shared
/// helper behind the `body_json` several HTTP suites use to assert on a response.
pub(crate) async fn body_json(body: Body) -> Value {
    let bytes = to_bytes(body, usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// A minimal aggregated [`ManifestMetadata`] fixture (`PUBLIC`, one record, no optional
/// fields) keyed only by dataset id: the shape the health and metrics cache-seeding suites
/// need.
pub(crate) fn sample_metadata(id: &str) -> ManifestMetadata {
    ManifestMetadata {
        dataset_id: id.to_owned(),
        catalog: "gdi-aggregated".to_owned(),
        title: LocalizedText::Plain("Sample".to_owned()),
        description: None,
        access_rights: "PUBLIC".to_owned(),
        applicable_legislation: vec![],
        license: "https://example.org/license".to_owned(),
        creator: vec![],
        health_category: vec![],
        keywords: None,
        number_of_unique_individuals: None,
        conforms_to: None,
        type_: None,
        legal_basis: None,
        is_referenced_by: None,
        other_identifier: None,
        contact_point: None,
        number_of_records: Some(1),
        populations: None,
    }
}

// ---------------------------------------------------------------------------
// Manifest factories
// ---------------------------------------------------------------------------

/// Standard ingest manifest fixture.
///
/// Uses `af_source: None`, applicable legislation 2018/1725/oj, and
/// `HealthCategoryHumanGenomic`. Pass the catalog string the test scenario requires
/// (most use `"gdi-aggregated"`).
pub(crate) fn manifest_for(id: &str, catalog: &str, number_of_records: u64) -> Manifest {
    Manifest {
        payload: None,
        metadata: ManifestMetadata {
            dataset_id: id.to_owned(),
            catalog: catalog.to_owned(),
            title: LocalizedText::Plain("COVID monogenic AFs".to_owned()),
            description: Some(LocalizedText::Plain(
                "Aggregated allele frequencies for the dataset.".to_owned(),
            )),
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
            af_source: None,
            af_source_reference: None,
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

/// Genome-of-Europe Beacon manifest fixture.
///
/// Identical to [`manifest_for`] except `af_source` and `af_source_reference`
/// are populated with the `GoE` values and catalog is fixed to `"gdi-aggregated"`.
pub(crate) fn manifest_for_goe(id: &str, number_of_records: u64) -> Manifest {
    Manifest {
        payload: None,
        metadata: ManifestMetadata {
            dataset_id: id.to_owned(),
            catalog: "gdi-aggregated".to_owned(),
            title: LocalizedText::Plain("COVID monogenic AFs".to_owned()),
            description: Some(LocalizedText::Plain(
                "Aggregated allele frequencies for the dataset.".to_owned(),
            )),
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

/// FAIR Data Point manifest fixture.
///
/// Uses applicable legislation 2025/327/oj and the same `HealthCategoryHumanGenomic` URI
/// the other two factories use; only the applicable legislation differs. `af_source` is
/// populated and the catalog is fixed to `"gdi-aggregated"`.
pub(crate) fn manifest_for_fdp(id: &str, number_of_records: u64) -> Manifest {
    Manifest {
        payload: None,
        metadata: ManifestMetadata {
            dataset_id: id.to_owned(),
            catalog: "gdi-aggregated".to_owned(),
            title: LocalizedText::Plain("COVID monogenic AFs".to_owned()),
            description: Some(LocalizedText::Plain(
                "Aggregated allele frequencies for the dataset.".to_owned(),
            )),
            access_rights: "http://publications.europa.eu/resource/authority/access-right/PUBLIC"
                .to_owned(),
            applicable_legislation: vec!["http://data.europa.eu/eli/reg/2025/327/oj".to_owned()],
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

// ---------------------------------------------------------------------------
// COVID VCF path
// ---------------------------------------------------------------------------

fn covid_vcf() -> PathBuf {
    test_util::covid_vcf_path()
}

fn default_convert_options() -> ConvertOptions {
    ConvertOptions {
        assembly: "GRCh38".to_owned(),
        block_range: 10_000_000,
        min_allele_count: 0,
    }
}

// ---------------------------------------------------------------------------
// Staging-dir builders
// ---------------------------------------------------------------------------

/// Build a COVID staging dir under `parent/{id}` (converting the COVID VCF),
/// write a [`manifest_for`] manifest with the given `catalog`, and return the
/// staging dir path.
///
/// Used by inbox suites that vary the catalog per test case.
pub(crate) fn build_covid_staging_dir(parent: &Path, id: &str, catalog: &str) -> PathBuf {
    let staging = parent.join(id);
    std::fs::create_dir_all(&staging).unwrap();
    let out = convert_vcf(&covid_vcf(), &staging, &default_convert_options()).unwrap();
    std::fs::write(
        staging.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest_for(id, catalog, out.number_of_records)).unwrap(),
    )
    .unwrap();
    staging
}

/// Atomically place a built COVID staging dir into `inbox/{id}`.
///
/// Builds under a hidden temp dir inside `inbox`, then `rename`s atomically
/// into place — matches the production operator pattern.
pub(crate) fn place_covid_staging_into_inbox(inbox: &Path, id: &str, catalog: &str) {
    let tmp_parent = inbox.join(format!(".tmp-build-{id}"));
    std::fs::create_dir_all(&tmp_parent).unwrap();
    let built = build_covid_staging_dir(&tmp_parent, id, catalog);
    std::fs::rename(&built, inbox.join(id)).unwrap();
    std::fs::remove_dir_all(&tmp_parent).unwrap();
}

/// Build a COVID staging dir under `parent/{id}` with the `"gdi-aggregated"`
/// catalog hard-coded (via [`manifest_for`]).
///
/// Used by suites that always target the `GoE` catalog (PME round-trip,
/// tar.c4gh, back-pressure).
pub(crate) fn build_covid_staging_goe(parent: &Path, id: &str) -> PathBuf {
    build_covid_staging_dir(parent, id, "gdi-aggregated")
}

/// Build a COVID staging dir under `parent/staging-{id}` (named staging
/// variant) using [`manifest_for_goe`].
///
/// Used by suites whose staging subdirectory is `staging-{id}` rather than
/// just `{id}` (beacon query variants, corrupt-parquet, membership-inference).
pub(crate) fn build_covid_staging_named_goe(parent: &Path, id: &str) -> PathBuf {
    build_covid_staging_named_goe_on(parent, id, "GRCh38")
}

/// [`build_covid_staging_named_goe`] with the declared `assembly` (`GRCh37` or `GRCh38`).
/// The conversion and the manifest are given the same label, so the staging dir is
/// self-consistent.
///
/// Used by the assembly-policy suite, which needs a node whose visible datasets do not all
/// share one assembly. The COVID fixture's coordinates are `GRCh38`, so a `GRCh37` copy is a
/// label-only variant. The tests that use it assert which datasets are selected, never a
/// coordinate, which is the property the assembly guardrail governs.
pub(crate) fn build_covid_staging_named_goe_on(parent: &Path, id: &str, assembly: &str) -> PathBuf {
    let staging = parent.join(format!("staging-{id}"));
    std::fs::create_dir_all(&staging).unwrap();
    let mut opts = default_convert_options();
    assembly.clone_into(&mut opts.assembly);
    let out = convert_vcf(&covid_vcf(), &staging, &opts).unwrap();
    let mut manifest = manifest_for_goe(id, out.number_of_records);
    assembly.clone_into(&mut manifest.config.assembly.reference);
    std::fs::write(
        staging.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    staging
}

// ---------------------------------------------------------------------------
// Full ingest helper (FDP variant)
// ---------------------------------------------------------------------------

/// Convert + ingest the COVID VCF for `id` into `data_dir` using the FDP
/// manifest variant ([`manifest_for_fdp`]), inserting it into the
/// `"gdi-aggregated"` catalog, and return a [`DatasetEntry`] in the requested
/// `state`.
///
/// Used by `fdp_routes` and `fdp_crawl`.
pub(crate) fn ingest_covid_fdp(
    parent: &Path,
    data_dir: &Path,
    id: &str,
    state: DatasetState,
) -> DatasetEntry {
    let staging = parent.join(format!("staging-{id}"));
    std::fs::create_dir_all(&staging).unwrap();
    let out = convert_vcf(&covid_vcf(), &staging, &default_convert_options()).unwrap();
    std::fs::write(
        staging.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest_for_fdp(id, out.number_of_records)).unwrap(),
    )
    .unwrap();
    let mut catalogs = BTreeMap::new();
    catalogs.insert(
        "gdi-aggregated".to_owned(),
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
        state,
        metadata_modified: None,
    }
}

/// Make thread-local `tracing` capture (`with_default`) reliable under the parallel `it`
/// harness. Call it before any test that asserts on captured log output.
///
/// `tracing` caches per-callsite interest process-globally. When sibling tests exercise the
/// same callsite on threads with no subscriber installed, that callsite can be cached as
/// uninterested, and a concurrent test's `with_default` capture then drops the event even
/// though it was emitted on its own thread. The capture passes single-threaded and fails
/// under parallel load.
///
/// Installing one permissive, discarding global default subscriber for the whole test binary
/// keeps every callsite interested, so dispatch always reaches the current thread-local
/// subscriber while unrelated tests' events fall through to the sink. Idempotent via `Once`:
/// the first caller wins and a later `set_global_default` error is ignored.
pub(crate) fn ensure_capture_safe_tracing() {
    use std::sync::Once;

    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let sink = tracing_subscriber::fmt()
            .with_writer(std::io::sink)
            .with_max_level(tracing::level_filters::LevelFilter::TRACE)
            .finish();
        let _ = tracing::subscriber::set_global_default(sink);
    });
}

// ---------------------------------------------------------------------------
// Error-body leak-scan helper
// ---------------------------------------------------------------------------

/// Serialize a beacon error `Value` for a "no allele count leaked" substring scan
/// with the volatile top-level `requestId` removed.
///
/// A fail-closed `4xx` or `500` `beaconErrorResponse` carries a random top-level `requestId`
/// UUID, injected by `add_request_id_to_error_body`. Its hex digits can coincidentally
/// contain an allele count's decimal digits: the COVID `TOTAL_AC` (`618`) appears inside
/// `080c2451-3115-48db-96e2-74961848517c`. A whole-body `body.contains("618")` scan then
/// reports a leak where no row ever left the node. Every other field in these error bodies
/// is deterministic, so scrubbing only the requestId keeps the scan reliable while still
/// covering the whole data-bearing body.
pub(crate) fn error_body_without_request_id(v: &serde_json::Value) -> String {
    let mut v = v.clone();
    if let Some(map) = v.as_object_mut() {
        map.remove("requestId");
    }
    serde_json::to_string(&v).unwrap()
}

#[test]
fn error_body_scrub_defeats_request_id_count_collision() {
    // A requestId whose digits contain TOTAL_AC (618): the collision class the scrub exists
    // for.
    let ac = test_util::covid::TOTAL_AC.to_string();
    let colliding = "080c2451-3115-48db-96e2-74961848517c";
    assert!(
        colliding.contains(&ac),
        "fixture requestId must collide with {ac}"
    );

    let err = serde_json::json!({
        "error": { "errorCode": 500, "errorMessage": "internal error scanning a dataset" },
        "meta": { "apiVersion": "v2.2.0" },
        "requestId": colliding,
    });
    // The unscrubbed body contains the count via the requestId. This is the false positive
    // a whole-body substring scan trips on.
    assert!(
        serde_json::to_string(&err).unwrap().contains(&ac),
        "sanity: the raw body false-positives on the count before scrubbing"
    );
    // Scrubbing the requestId removes the false positive: the count no longer
    // appears anywhere in the (data-bearing) body.
    let scrubbed = error_body_without_request_id(&err);
    assert!(
        !scrubbed.contains(&ac),
        "requestId must be scrubbed before the count scan: {scrubbed}"
    );

    // A real leak, the count in a data-bearing field, is still caught.
    let leaky = serde_json::json!({
        "error": { "errorCode": 500, "errorMessage": "x" },
        "response": { "resultSets": [{ "ac": test_util::covid::TOTAL_AC }] },
        "requestId": "00000000-0000-0000-0000-000000000000",
    });
    assert!(
        error_body_without_request_id(&leaky).contains(&ac),
        "a genuine count leak in the data body must still be caught"
    );
}
