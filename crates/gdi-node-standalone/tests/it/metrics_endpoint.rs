//! Integration tests for the metrics surface: the curated Prometheus
//! series and the privacy invariants.
//!
//! `metrics::set_global_recorder` may be installed only once per process, so every
//! recorder-dependent assertion shares a single install (a process-wide
//! `OnceLock<MetricsHandle>`) and the tests run `#[serial]` so the shared global metric
//! registry is never raced. Counters are cumulative across the tests in this one binary, so
//! assertions check presence or a monotone increase, never an absolute reset-to-zero value.
//!
//! These exercise the lite (keyless, no S3, no Vault) build; the metrics surface itself is
//! not gated on the networked features.
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::path::Path;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use gdi_node_standalone::app::build_router;
use gdi_node_standalone::identities::NodeIdentities;
use gdi_node_standalone::ingest_runtime::IngestRuntime;
use gdi_node_standalone::metrics::{self, MetricsHandle};
use gdi_node_standalone::state::AppState;
use gdi_node_standalone_core::cache::{DatasetEntry, DatasetProvenance, StatusEntry, StatusIndex};
use gdi_node_standalone_core::config::ServiceConfig;
use gdi_node_standalone_core::convert::{ConvertOptions, convert_vcf};
use gdi_node_standalone_core::model::{
    Agent, Assembly, DatasetMode, LocalizedText, Manifest, ManifestConfig, ManifestMetadata,
};
use gdi_node_standalone_core::state::DatasetState;
use gdi_node_standalone_core::suppression::{
    SuppressMode, Suppression, suppressions_subdir, write_file as write_suppression_file,
};
use metrics_exporter_prometheus::PrometheusBuilder;
use serial_test::serial;
use tower::ServiceExt as _; // for `oneshot`

const VISIBLE_ID: &str = "GDI-EE-UTARTU-20260409143052837";
const HIDDEN_ID: &str = "GDI-EE-UTARTU-20260410120000000";
const ERROR_ID: &str = "GDI-EE-UTARTU-20260411093000123";

/// Install the global Prometheus recorder exactly once for this test binary and
/// return its render handle. Panics if a recorder is already installed by something
/// other than this helper (it should not be, in this binary).
fn handle() -> &'static MetricsHandle {
    static HANDLE: OnceLock<MetricsHandle> = OnceLock::new();
    HANDLE.get_or_init(|| {
        metrics::install_recorder(None).expect("recorder installs once per process")
    })
}

fn lite_config(data_dir: &std::path::Path) -> ServiceConfig {
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"

[catalogs]
gdi-aggregated = "Genome of Europe Aggregated Data"

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

use crate::fixtures::sample_metadata;

/// A config whose assembly matches the `GRCh38` `g_variants` query below, so the query
/// selects the dataset and scans it. The cache entries have no on-disk dataset dir, so the
/// scan finds no parquet and the answer is a valid empty `200`, which is all these tests
/// need.
///
/// It must not be a different assembly: a query naming an assembly the node does not serve
/// is a `400`, because a silent `exists:false` there would be a false negative.
fn sample_config() -> ManifestConfig {
    ManifestConfig {
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
    }
}

fn entry(id: &str, state: DatasetState) -> DatasetEntry {
    DatasetEntry {
        id: id.to_owned(),
        metadata: sample_metadata(id),
        config: sample_config(),
        state,
        metadata_modified: None,
    }
}

/// A lite `AppState` with one visible + one hidden cache entry and one error entry
/// in the status index (error datasets are not cached).
fn lite_state() -> (AppState, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();

    let mut status = StatusIndex::new();
    status.insert(
        ERROR_ID.to_owned(),
        StatusEntry {
            state: DatasetState::Error,
            error_message: Some(gdi_node_standalone_core::error::ErrorClass::InvalidManifest),
            channel: "inbox".to_owned(),
            last_seen_signature: None,
            provenance: DatasetProvenance::Unknown,
        },
    );

    let config = lite_config(&data_dir);
    let state = AppState::new(config, status, NodeIdentities::empty());
    state.cache.insert(
        gdi_node_standalone_core::cache::StatusWrite::unshared(),
        entry(VISIBLE_ID, DatasetState::Visible),
    );
    state.cache.insert(
        gdi_node_standalone_core::cache::StatusWrite::unshared(),
        entry(HIDDEN_ID, DatasetState::Hidden),
    );
    state.readiness.mark_initial_reconcile_done();
    state.readiness.set_key_material_ok(true);
    (state, tmp)
}

/// A lite `AppState` with a tiny `max_request_body_bytes`, so a normal beacon POST body
/// trips the body-cap `413` and drives the rejection counter.
fn lite_state_tiny_body() -> (AppState, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"
max_request_body_bytes = 16

[catalogs]
gdi-aggregated = "Genome of Europe Aggregated Data"

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
    let state = AppState::new(cfg, StatusIndex::new(), NodeIdentities::empty());
    state.readiness.mark_initial_reconcile_done();
    state.readiness.set_key_material_ok(true);
    (state, tmp)
}

async fn body_string(body: Body) -> String {
    let bytes = to_bytes(body, usize::MAX).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// `gdi_ingest_last_progress_timestamp_seconds` is seeded to a real wall-clock instant at
/// install, not epoch `0`. Seeded to `0`, `time() - last_progress` is around 1.7e9 on a cold
/// node, so the `WedgedIngestPool` alert, which pairs it with `queue_depth`, would false-fire
/// on every cold start with a backlog until the first job completed.
#[tokio::test]
async fn ingest_last_progress_seeded_to_wall_clock_not_epoch() {
    let h = handle();
    let text = h.render();
    let val = gauge_value(&text, "gdi_ingest_last_progress_timestamp_seconds", &[]);
    assert!(
        val > 1_700_000_000.0,
        "last_progress must be seeded to a recent unix instant (not epoch 0), got {val}"
    );
}

/// `gdi_ingest_inflight_oldest_age_seconds` is seeded `0` at install, so an idle node
/// reads 0 rather than absent and `DatasetStuckProcessing` (`> 1800`) evaluates from the
/// first scrape instead of reading "no data" until the first ingest.
#[tokio::test]
async fn ingest_inflight_oldest_age_seeded_to_zero() {
    let h = handle();
    let text = h.render();
    // Present, then zero. `gauge_value` returns `0.0` for an absent series too, so a value
    // assertion alone would be satisfied by the very failure this guards: the seed deleted
    // and the series absent until the first ingest.
    assert!(
        series_present(&text, "gdi_ingest_inflight_oldest_age_seconds", &[]),
        "the in-flight age gauge must be seeded at install, not absent until the first ingest"
    );
    let val = gauge_value(&text, "gdi_ingest_inflight_oldest_age_seconds", &[]);
    assert!(val.abs() < f64::EPSILON, "idle node must read 0, got {val}");
}

/// The S3 download-error and sidecar-rejection counters render under their documented names
/// and bounded labels. The failure paths that call them are exercised by the `s3_reconcile`
/// suite; this pins the metric contract, its name and label set, so a rename or a
/// cardinality-blowing label change is caught. Unique label values keep it independent of any
/// concurrently running test sharing the process recorder.
///
/// `gdi_overlay_apply_failed_total` is asserted on `channel`. The counter is emitted from
/// the inbox path as well as the S3 one; an S3-only label set would leave an inbox-only
/// node with no series at all, so `OverlayApplyFailing` could never fire there.
#[tokio::test]
async fn s3_download_and_overlay_failure_counters_emit() {
    let h = handle();
    metrics::s3_download_error("ctest-bkt");
    metrics::overlay_apply_failed("ctest-bkt", "parse");
    metrics::state_sidecar_rejected("ctest-bkt", metrics::StateSidecarRejectReason::Unreadable);
    metrics::manifest_reload_skipped(2);
    metrics::s3_removal_skipped("ctest-bkt");
    let text = h.render();
    assert!(
        line_with_value_at_least(
            &text,
            "gdi_s3_download_errors_total",
            &["channel=\"ctest-bkt\""],
            1.0,
        ),
        "s3 download error counter missing/unlabelled: {text}"
    );
    assert!(
        line_with_value_at_least(
            &text,
            "gdi_overlay_apply_failed_total",
            &["channel=\"ctest-bkt\"", "reason=\"parse\""],
            1.0,
        ),
        "overlay apply failed counter missing/unlabelled: {text}"
    );
    assert!(
        line_with_value_at_least(
            &text,
            "gdi_state_sidecar_rejected_total",
            &["channel=\"ctest-bkt\"", "reason=\"unreadable\""],
            1.0,
        ),
        "state sidecar rejection counter missing/unlabelled: {text}"
    );
    assert!(
        line_with_value_at_least(&text, "gdi_manifest_reload_skipped_total", &[], 2.0),
        "manifest reload skipped counter missing: {text}"
    );
    assert!(
        line_with_value_at_least(
            &text,
            "gdi_s3_removal_skipped_total",
            &["channel=\"ctest-bkt\""],
            1.0,
        ),
        "s3 removal skipped counter missing/unlabelled: {text}"
    );
}

/// A `g_variants` POST that validates and runs (no matching dataset gives an empty `200`),
/// for the `chr3` site. Used to show that no content-derived label leaks.
fn g_variants_chr3() -> Request<Body> {
    let body = serde_json::json!({
        "query": {
            "requestParameters": {
                "referenceName": "3",
                "start": "45823240",
                "referenceBases": "T",
                "alternateBases": "C",
                "assemblyId": "GRCh38",
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

/// A `g_variants` POST with a `geneId` parameter — rejected with `400` (the path is
/// not supported), so it bumps the `status_class="4xx"` beacon counter.
fn g_variants_gene_id() -> Request<Body> {
    let body = serde_json::json!({
        "query": { "requestParameters": { "referenceName": "3", "geneId": "BRCA1" } }
    });
    Request::builder()
        .method("POST")
        .uri("/beacon/v2/g_variants")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

#[tokio::test]
#[serial]
async fn beacon_query_semantic_metrics_recorded() {
    let h = handle();
    let (state, _tmp) = lite_state();
    let router = build_router(state);

    // Read before the stimulus and assert the delta. The registry is process-global and
    // cumulative, so a bare presence check would be satisfied by any earlier test in the
    // same process rather than by this request.
    let before_q = series_value(&h.render(), "gdi_beacon_query_total", &["exists=\"false\""]);
    let before_rej = series_value(
        &h.render(),
        "gdi_beacon_query_rejected_total",
        &["code=\"400\""],
    );

    // An answered g_variants (GRCh38 query against a GRCh37 dataset gives an empty 200 with
    // exists=false) and a malformed one (geneId gives a 400) drive the semantic and reject
    // series.
    let ok = router.clone().oneshot(g_variants_chr3()).await.unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
    let bad = router.oneshot(g_variants_gene_id()).await.unwrap();
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);

    let text = h.render();

    // Hit/miss + disclosure-level counter (the query matched no dataset → exists=false).
    let after_q = series_value(&text, "gdi_beacon_query_total", &["exists=\"false\""]);
    assert!(
        after_q > before_q,
        "this request must move gdi_beacon_query_total{{exists=\"false\"}} \
         ({before_q} -> {after_q}): {text}"
    );
    // The per-query result count is not a metric: it lives in the audit trail
    // (`BeaconQueryAudit::num_results`), exact rather than bucketed. Its absence is asserted
    // so it cannot drift back in as a wide histogram nothing observes.
    assert!(
        !text.contains("gdi_beacon_query_results"),
        "beacon_query_results was removed; result magnitude belongs in the audit trail: {text}"
    );
    // Rejected-by-code counter: the geneId 400 leaves a per-code series (the `code`
    // label is unique to this metric — the transport counter uses `status_class`).
    let after_rej = series_value(&text, "gdi_beacon_query_rejected_total", &["code=\"400\""]);
    assert!(
        after_rej > before_rej,
        "the geneId 400 must move gdi_beacon_query_rejected_total{{code=\"400\"}} \
         ({before_rej} -> {after_rej}): {text}"
    );
}

#[tokio::test]
#[serial]
async fn metrics_endpoint_serves_curated_series_with_no_content_labels() {
    let h = handle();
    let (state, _tmp) = lite_state();

    // Sample the gauges once so dataset-state + uptime appear in the render.
    metrics::sample_once(&state, std::time::Instant::now());
    metrics::record_build_info();

    // A 2xx g_variants and a 4xx g_variants so the beacon counter has both classes.
    let router = build_router(state.clone());
    let ok = router.clone().oneshot(g_variants_chr3()).await.unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
    let bad = router.oneshot(g_variants_gene_id()).await.unwrap();
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);

    let text = h.render();

    // The curated series are present.
    assert!(text.contains("gdi_dataset_state"), "dataset_state missing");
    assert!(
        text.contains("gdi_ingest_queue_depth"),
        "ingest_queue_depth missing"
    );
    assert!(
        text.contains("gdi_beacon_requests_total"),
        "beacon_requests_total missing"
    );
    // Whole public-plane RED (covers the informational + well-known routes the
    // per-entry-type beacon metric never saw) — emitted from the access-log on_response,
    // so any completed public request populates it with a bounded `plane` label.
    assert!(
        text.contains("gdi_http_requests_total") && text.contains("plane=\"public\""),
        "whole public-plane RED series missing: {text}"
    );
    assert!(
        text.contains("gdi_disk_free_bytes"),
        "disk_free_bytes missing"
    );
    assert!(text.contains("gdi_build_info"), "build_info missing");
    // Readiness is exposed as a gauge (sampled): overall is ready in the lite state
    // (reconcile done + key material ok; s3/vault not configured).
    assert!(
        text.contains("gdi_health_ready") && text.contains("component=\"overall\""),
        "health_ready gauge missing: {text}"
    );

    // No content-derived label leaked: the chr3 query must not add a `chr`, `referenceName`,
    // `variant`, `assembly`, `start`, or `alternateBases` label.
    for forbidden in [
        "chr3",
        "referenceName",
        "reference_name=",
        "variant=",
        "assembly=",
        "assemblyId",
        "alternateBases",
        "start=",
        "GRCh38",
        "BRCA1",
    ] {
        assert!(
            !text.contains(forbidden),
            "metrics text leaked a content-derived token: {forbidden}\n--- render ---\n{text}"
        );
    }

    // The only labels on the beacon series are entry_type + status_class.
    assert!(
        text.contains("entry_type=\"genomicVariant\""),
        "beacon entry_type label missing"
    );
}

#[tokio::test]
#[serial]
async fn beacon_request_counter_tracks_status_class() {
    let _h = handle();
    let (state, _tmp) = lite_state();
    let router = build_router(state);

    // A 2xx then a 4xx — both must increment the corresponding status_class.
    let ok = router.clone().oneshot(g_variants_chr3()).await.unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
    let bad = router.oneshot(g_variants_gene_id()).await.unwrap();
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);

    let text = handle().render();
    assert!(
        line_with_value_at_least(
            &text,
            "gdi_beacon_requests_total",
            &["entry_type=\"genomicVariant\"", "status_class=\"2xx\""],
            1.0,
        ),
        "g_variants 2xx counter not incremented\n{text}"
    );
    assert!(
        line_with_value_at_least(
            &text,
            "gdi_beacon_requests_total",
            &["entry_type=\"genomicVariant\"", "status_class=\"4xx\""],
            1.0,
        ),
        "g_variants 4xx counter not incremented\n{text}"
    );
}

#[tokio::test]
#[serial]
async fn resilience_layer_rejection_increments_rejected_counter() {
    let _h = handle();
    let (state, _tmp) = lite_state_tiny_body();
    let router = build_router(state);

    // A beacon POST whose body exceeds `max_request_body_bytes = 16` → the body-cap
    // layer renders a 413 (preserved by `BeaconJson` as a beaconErrorResponse), which
    // the outermost `meter_rejections` layer counts.
    let body = serde_json::json!({
        "query": { "requestParameters": { "referenceName": "3" } }
    });
    let req = Request::builder()
        .method("POST")
        .uri("/beacon/v2/g_variants")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let text = handle().render();
    assert!(
        line_with_value_at_least(
            &text,
            "gdi_http_requests_rejected_total",
            &["reason=\"body_too_large\""],
            1.0,
        ),
        "body-cap rejection not counted on gdi_http_requests_rejected_total\n{text}"
    );
    // The other reasons are seeded at recorder install, so they render from the first
    // scrape even though this process never load-shed or timed out.
    assert!(
        text.contains("reason=\"overloaded\"")
            && text.contains("reason=\"timeout\"")
            && text.contains("reason=\"uri_too_large\""),
        "seeded rejection reasons missing from render\n{text}"
    );
    // Newly seeded alert-backing counters must also render from the first scrape so
    // their `increase()>0` alerts (BackgroundPanics, InboxWatcherFlapping, IngestTimeout,
    // IngestRetryChurn) have a 0 baseline even though this process never hit them.
    assert!(
        text.contains("gdi_background_task_panics_total")
            && text.contains("gdi_inbox_watcher_restarts_total"),
        "seeded background/inbox counters missing from render\n{text}"
    );
    assert!(
        text.contains("outcome=\"timeout\"") && text.contains("outcome=\"transient\""),
        "seeded ingest outcomes missing from render\n{text}"
    );
}

#[tokio::test]
#[serial]
async fn fairdp_plane_is_instrumented() {
    let _h = handle();
    let (state, _tmp) = lite_state();
    let router = build_router(state);

    // FDP is unconfigured in the lite state, so `/fairdp` 404s, but the request still flows
    // through the FDP metric layer and the counter records it.
    let req = Request::builder()
        .method("GET")
        .uri("/fairdp")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let text = handle().render();
    assert!(
        line_with_value_at_least(
            &text,
            "gdi_fairdp_requests_total",
            &["resource_type=\"root\"", "status_class=\"4xx\""],
            1.0,
        ),
        "FDP request not counted with resource_type=root\n{text}"
    );

    // A sub-resource keeps its own label. The FDP router is nested at `/fairdp`, so
    // the metric layer sees the path with that prefix stripped; a label derivation that
    // still matched `/fairdp/catalog/` would quietly meter every catalog fetch as `root`
    // and nothing above would notice.
    let (state, _tmp) = lite_state();
    let req = Request::builder()
        .method("GET")
        .uri("/fairdp/catalog/gdi-aggregated")
        .body(Body::empty())
        .unwrap();
    let resp = build_router(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let text = handle().render();
    assert!(
        line_with_value_at_least(
            &text,
            "gdi_fairdp_requests_total",
            &["resource_type=\"catalog\"", "status_class=\"4xx\""],
            1.0,
        ),
        "FDP catalog request not counted with resource_type=catalog\n{text}"
    );
    // The serialization-failure counter is seeded at install, so it renders from the
    // first scrape even though no serializer failure occurred.
    assert!(
        text.contains("gdi_fairdp_serialization_failures_total"),
        "gdi_fairdp_serialization_failures_total missing (not seeded)\n{text}"
    );
}

#[tokio::test]
#[serial]
async fn dataset_state_gauge_reflects_counts() {
    let _h = handle();
    let (state, _tmp) = lite_state();
    metrics::sample_once(&state, std::time::Instant::now());

    let text = handle().render();
    // `lite_state()` holds exactly 1 visible, 1 hidden (cache) and 1 error (status index).
    // `sample_once` sets the gauge rather than incrementing it, so the counts from the call
    // above are what render, and `#[serial]` keeps another test from interleaving. The
    // values are compared as a range rather than for float equality: counts are whole
    // numbers, so 1 is [1, 2).
    assert!(
        line_with_value_at_least(&text, "gdi_dataset_state", &["state=\"visible\""], 1.0)
            && gauge_value(&text, "gdi_dataset_state", &["state=\"visible\""]) < 2.0,
        "visible count must be exactly 1\n{text}"
    );
    assert!(
        line_with_value_at_least(&text, "gdi_dataset_state", &["state=\"hidden\""], 1.0)
            && gauge_value(&text, "gdi_dataset_state", &["state=\"hidden\""]) < 2.0,
        "hidden count must be exactly 1\n{text}"
    );
    assert!(
        line_with_value_at_least(&text, "gdi_dataset_state", &["state=\"error\""], 1.0)
            && gauge_value(&text, "gdi_dataset_state", &["state=\"error\""]) < 2.0,
        "error count must be exactly 1\n{text}"
    );
}

// `/metrics` is absent from the public plane. That assertion lives in
// `health_state::management_routes_absent_from_public_plane`, which iterates the whole
// management route list, so it is not repeated here.

#[tokio::test]
#[serial]
async fn metrics_route_serves_prometheus_text() {
    let h = handle();
    let (state, _tmp) = lite_state();
    // Drive the real `/metrics` route via `metrics_router`, not `h.render()`
    // directly), so the route wiring + content-type are exercised end-to-end.
    let router = metrics::metrics_router(std::sync::Arc::new(h.clone())).with_state(state);
    let req = Request::builder()
        .uri("/metrics")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    assert!(
        ct.starts_with("text/plain"),
        "metrics content-type must be Prometheus text/plain; got {ct}"
    );
    let text = body_string(resp.into_body()).await;
    // `gdi_decrypt_failures_total` is seeded at recorder install (via
    // `seed_always_present`) with `increment(0)` so it appears in every render
    // from the very first scrape, regardless of test ordering.
    assert!(
        text.contains("gdi_decrypt_failures_total"),
        "the /metrics route did not render Prometheus text (gdi_decrypt_failures_total missing):\n{text}"
    );
}

/// `gdi_datasets_suppressed{mode}` (both `hide` and `remove`) and
/// `gdi_suppression_load_degraded` must render from the very first scrape — seeded at
/// recorder install (`seed_always_present`), mirroring the other alert-backing
/// gauges/counters seeded above. Without this an unseeded `gdi_suppression_load_degraded`
/// would never satisfy a `> 0` alert reliably (no baseline sample to compare against), and
/// an operator graphing `gdi_datasets_suppressed{mode="remove"}` on a node with nothing
/// suppressed would see a gap instead of a `0`.
///
/// Checks presence only, not an absolute-zero value. This uses the shared `handle()`
/// recorder described in the module doc, and `gdi_datasets_suppressed{mode}` is a plain
/// `.set()` that a concurrent test in this binary can legitimately move off `0`, so asserting
/// `< 1.0` here would race. Presence is what "seeded" has to guarantee anyway: the Prometheus
/// exporter renders a series only once it has been emitted, so a seeded series is never
/// absent.
///
/// The isolated-zero-value case, seeded to a known `0` with no prior suppression activity,
/// is covered by `suppression_gauges_are_seeded_to_exact_zero` in
/// `crates/gdi-node-standalone/src/metrics.rs`'s own `#[cfg(test)]` module, on its own local
/// recorder.
#[tokio::test]
#[serial]
async fn suppression_gauges_are_seeded_to_zero() {
    let h = handle();
    let text = h.render();
    assert!(
        series_present(&text, "gdi_datasets_suppressed", &["mode=\"hide\""]),
        "gdi_datasets_suppressed{{mode=\"hide\"}} must be seeded (present) from the first \
         scrape\n{text}"
    );
    assert!(
        series_present(&text, "gdi_datasets_suppressed", &["mode=\"remove\""]),
        "gdi_datasets_suppressed{{mode=\"remove\"}} must be seeded (present) from the \
         first scrape\n{text}"
    );
    assert!(
        text.contains("gdi_suppression_load_degraded"),
        "gdi_suppression_load_degraded must be seeded (present) from the first scrape\n{text}"
    );
}

/// `gdi_datasets_suppressed{mode}` and `gdi_suppression_load_degraded` are correct after a
/// single periodic [`metrics::sample_once`] tick, even when neither
/// [`AppState::reload_suppressions`](gdi_node_standalone::state::AppState::reload_suppressions)
/// nor `apply_suppressions_to_cache` and `enforce_suppressions` has run against the recorder.
///
/// That is the real boot sequence: `enforce_suppressions().await` runs before the Prometheus
/// recorder installs, so its `.set()` calls have no recorder to write into, and
/// `AppState::new` loads the suppression set inline via `suppression::load` without calling
/// `reload_suppressions`, the only other setter of the degraded gauge. Without suppression
/// sampling inside `sample_once`, both gauges sit falsely at `0` for up to
/// `rescan_interval_seconds` after a restart with an already-broken override store, which
/// silences the `SuppressionStoreDegraded` alert for that window.
///
/// Uses an isolated local recorder (`with_local_recorder`) rather than the shared `handle()`,
/// so it neither races nor is raced by the other tests in this binary and needs no
/// `#[serial]`.
#[test]
fn suppression_gauges_recompute_from_periodic_sampler_without_any_reload() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let override_dir = tmp.path().join("overrides");
    std::fs::create_dir_all(&data_dir).unwrap();

    // Two live overrides (one `hide`, one `remove`) plus one corrupt file, which fails
    // closed to `hide` and counts as `degraded`. All three are written before
    // `AppState::new`, so `suppression::load` picks them up on construction: the shape of a
    // restart with an already-broken `suppressions/*.json` on disk.
    let sub = suppressions_subdir(&override_dir);
    write_suppression_file(
        &sub,
        "GDI-EE-UTARTU-20260409143052001",
        &Suppression {
            mode: SuppressMode::Hide,
            reason: "t".into(),
            at: String::new(),
        },
    )
    .unwrap();
    write_suppression_file(
        &sub,
        "GDI-EE-UTARTU-20260409143052002",
        &Suppression {
            mode: SuppressMode::Remove,
            reason: "t".into(),
            at: String::new(),
        },
    )
    .unwrap();
    std::fs::write(
        sub.join("GDI-EE-UTARTU-20260409143052003.json"),
        b"{ not valid json",
    )
    .unwrap();

    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"
override_dir = "{}"

[catalogs]
gdi-aggregated = "Genome of Europe Aggregated Data"

[beacon]
id = "org.test.boot-staleness"
name = "Test Beacon"
"#,
        data_dir.display(),
        override_dir.display(),
    );
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    cfg.preflight().unwrap();

    // Mirrors real boot: `AppState::new` loads the suppression set inline. Nothing here
    // calls `reload_suppressions`, `apply_suppressions_to_cache` or `enforce_suppressions`;
    // only the periodic sampler runs.
    let state = AppState::new(cfg, StatusIndex::new(), NodeIdentities::empty());

    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    // The leading `::` names the external `metrics` crate, not the local
    // `gdi_node_standalone::metrics` module that the `use ... metrics::{self, ..}` above
    // binds to the bare identifier.
    ::metrics::with_local_recorder(&recorder, || {
        metrics::sample_once(&state, std::time::Instant::now());
    });
    let text = handle.render();

    assert!(
        line_with_value_at_least(&text, "gdi_datasets_suppressed", &["mode=\"hide\""], 2.0),
        "hide count must include BOTH the explicit hide override and the corrupt \
         fail-closed-to-hide entry (2 total), got:\n{text}"
    );
    assert!(
        line_with_value_at_least(&text, "gdi_datasets_suppressed", &["mode=\"remove\""], 1.0),
        "remove count must reflect the store loaded at AppState::new, got:\n{text}"
    );
    assert!(
        line_with_value_at_least(&text, "gdi_suppression_load_degraded", &[], 1.0),
        "degraded count must reflect the unparseable file loaded at AppState::new boot \
         time, even though reload_suppressions was never called, got:\n{text}"
    );
}

// ---- helpers for the ingest-error metrics test ----

/// Build a valid staging dir for `id` under `parent`, converting the COVID VCF.
/// Returns the staging dir path (`parent/{id}`).
fn build_unknown_catalog_staging_dir(parent: &Path, id: &str) -> std::path::PathBuf {
    let staging = parent.join(id);
    std::fs::create_dir_all(&staging).unwrap();
    let vcf = test_util::covid_vcf_path();
    convert_vcf(
        &vcf,
        &staging,
        &ConvertOptions {
            assembly: "GRCh38".to_owned(),
            block_range: 10_000_000,
            min_allele_count: 0,
        },
    )
    .unwrap();
    // Write a manifest that references a catalog not in the node config.
    let manifest = Manifest {
        payload: None,
        metadata: ManifestMetadata {
            dataset_id: id.to_owned(),
            catalog: "not-a-configured-catalog".to_owned(),
            title: LocalizedText::Plain("Test".to_owned()),
            description: None,
            access_rights: "PUBLIC".to_owned(),
            applicable_legislation: vec![],
            license: "https://example.org/license".to_owned(),
            creator: vec![Agent {
                name: "Test".to_owned(),
            }],
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
        },
        files: vec![],
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
    };
    std::fs::write(
        staging.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    staging
}

fn inbox_config_goe(data_dir: &Path, inbox: &Path) -> ServiceConfig {
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"
inbox = "{}"
ingest_concurrency = 2
rescan_interval_seconds = 3600

[catalogs]
gdi-aggregated = "Genome of Europe Aggregated Data"

[beacon]
id = "org.test.beacon"
name = "Test Beacon"
"#,
        data_dir.display(),
        inbox.display(),
    );
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    cfg.preflight().unwrap();
    cfg
}

async fn poll_until_error(state: &AppState, id: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        if state
            .status
            .lock()
            .unwrap()
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Error)
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "error state not recorded within {timeout:?}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// PME ingest-metrics privacy: drive a package to a permanent ingest error through
/// the real `IngestRuntime` path and assert:
///
/// (a) `gdi_ingest_total{outcome="permanent",error_class=<class>}` is present with
///     value >= 1;
/// (b) `gdi_decrypt_failures_total` is present in the render (seeded at install);
/// (c) the rendered text contains no dataset id, file path, or raw error message.
#[tokio::test]
#[serial]
async fn ingest_permanent_error_metrics_are_private() {
    let h = handle();

    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&inbox).unwrap();

    // Use a distinct id that will not collide with any other test.
    let id = "GDI-EE-UTARTU-20260412000000001";

    // Build a staging dir with an unknown catalog under a temp location and
    // move it atomically into the inbox (mirrors the inbox_ingest.rs pattern).
    let tmp_build = tmp.path().join("build");
    std::fs::create_dir_all(&tmp_build).unwrap();
    let staging = build_unknown_catalog_staging_dir(&tmp_build, id);
    std::fs::rename(&staging, inbox.join(id)).unwrap();

    let config = inbox_config_goe(&data_dir, &inbox);
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
    let runtime = IngestRuntime::start(state.clone());

    runtime.scan_once().await;
    poll_until_error(&state, id, Duration::from_secs(15)).await;

    // Sample the gauges so dataset-state labels appear.
    metrics::sample_once(&state, std::time::Instant::now());
    let text = h.render();

    // (a) The permanent-error ingest counter is present with value >= 1.
    assert!(
        line_with_value_at_least(
            &text,
            "gdi_ingest_total",
            &["outcome=\"permanent\"", "error_class=\"unknown-catalog\""],
            1.0,
        ),
        "gdi_ingest_total{{outcome=\"permanent\",error_class=\"unknown-catalog\"}} not found\n{text}"
    );

    // (b) gdi_decrypt_failures_total is present (seeded at recorder install).
    assert!(
        text.contains("gdi_decrypt_failures_total"),
        "gdi_decrypt_failures_total missing from render\n{text}"
    );

    // (c) No dataset id or raw internal error detail leaked into the rendered text. Mirrors
    //     the forbidden-token loop in
    //     `metrics_endpoint_serves_curated_series_with_no_content_labels`. The
    //     `gdi_disk_free_bytes{volume}` label carries the data-dir path, which the operator
    //     already knows and is not content-derived, so it is not forbidden here; only the
    //     dataset id and the raw catalog name are checked.
    for forbidden in [id, "not-a-configured-catalog"] {
        assert!(
            !text.contains(forbidden),
            "metrics text leaked a private token: {forbidden:?}\n--- render ---\n{text}"
        );
    }
}

/// Parse the value of a Prometheus sample line whose name + label substrings all
/// match, returning `0.0` if not found.
fn gauge_value(text: &str, name: &str, labels: &[&str]) -> f64 {
    for line in text.lines() {
        if line.starts_with('#') || !line.starts_with(name) {
            continue;
        }
        if labels.iter().all(|l| line.contains(l))
            && let Some(value) = line.rsplit_once(' ').map(|(_, v)| v)
            && let Ok(v) = value.trim().parse::<f64>()
        {
            return v;
        }
    }
    0.0
}

/// Whether a matching sample line exists with a value ≥ `min`.
fn line_with_value_at_least(text: &str, name: &str, labels: &[&str], min: f64) -> bool {
    gauge_value(text, name, labels) >= min
}

/// Whether a sample line for `name` with all of `labels` exists at all.
///
/// [`gauge_value`] defaults to `0.0`, which is indistinguishable from a present `0`-valued
/// series, so this is the primitive for a "was this series ever emitted" assertion.
fn series_present(text: &str, name: &str, labels: &[&str]) -> bool {
    text.lines().any(|line| {
        !line.starts_with('#') && line.starts_with(name) && labels.iter().all(|l| line.contains(l))
    })
}

/// The summed value of every series matching `name` + `labels` in a rendered exposition,
/// or 0.0 when none match.
///
/// The registry behind `handle()` is process-global and cumulative, so a bare
/// `text.contains("gdi_beacon_query_total")` is satisfied by any earlier test in the same
/// process, including one whose code path has nothing to do with the assertion. Under nextest
/// each test is its own process; under a plain `cargo test` the tests share one registry and a
/// presence check stops testing the stimulus it names. Reading the value lets a test assert
/// its own delta, which holds whatever ran before it.
///
/// [`gauge_value`] returns the first matching series, which is right for a single-series
/// gauge. A counter is routinely split across label sets the filter does not pin, such as
/// `entry_type`, and picking one arbitrarily would compare a series the stimulus never
/// touched. This sums every match.
fn series_value(text: &str, name: &str, labels: &[&str]) -> f64 {
    text.lines()
        .filter(|line| {
            !line.starts_with('#')
                && line.starts_with(name)
                && labels.iter().all(|l| line.contains(l))
        })
        .filter_map(|line| {
            line.rsplit_once(' ')
                .and_then(|(_, v)| v.trim().parse::<f64>().ok())
        })
        .sum()
}
