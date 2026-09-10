//! Integration tests for the operational surface served by the service
//! binary: the health probes (`/health/live`, `/health/ready` with per-subsystem
//! detail), the management-plane dataset-state endpoint
//! (`GET /datasets/{id}/state` — channel, sanitized error, `404` for unknown,
//! `400`/`404` for a traversal-shaped id), and the scoped wildcard CORS (only the
//! public browser endpoints carry `Access-Control-Allow-Origin: *`).
//!
//! Driven in-process via `tower::ServiceExt::oneshot` against a router built from a
//! real `AppState`, like `fdp_routes.rs` and `beacon_query.rs`. These exercise the lite
//! (keyless, no S3, no Vault) build: every networked subsystem reads `not-configured` and
//! `key_material` reads `ok`, which is the valid keyless mode.
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use gdi_node_standalone::app::{build_management_router, build_router};
#[cfg(feature = "pme")]
use gdi_node_standalone::health::AtRestHealth;
use gdi_node_standalone::identities::NodeIdentities;
use gdi_node_standalone::state::AppState;
use gdi_node_standalone_core::cache::{DatasetEntry, DatasetProvenance, StatusEntry, StatusIndex};
use gdi_node_standalone_core::catalogs::CatalogList;
use gdi_node_standalone_core::config::ServiceConfig;
use gdi_node_standalone_core::model::{Assembly, DatasetMode, ManifestConfig};
use gdi_node_standalone_core::state::DatasetState;
use gdi_node_standalone_core::suppression::{
    SuppressMode, Suppression, suppressions_subdir, write_channel_file, write_file,
};
use tower::ServiceExt as _; // for `oneshot`

const VISIBLE_ID: &str = "GDI-EE-UTARTU-20260409143052837";
const ERROR_ID: &str = "GDI-EE-UTARTU-20260411093000123";

/// Minimal valid service config (no FDP, no S3, no Vault) for the lite probes.
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

/// A minimal config with one configured (anonymous) S3 bucket, so `has_s3_buckets()`
/// is true and `/health/ready` reports the per-bucket S3 detail. Only built under the
/// `s3` feature (the `[[s3.buckets]]` config type is s3-gated).
#[cfg(feature = "s3")]
fn s3_config(data_dir: &std::path::Path) -> ServiceConfig {
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

[[s3.buckets]]
name = "provider-a"
endpoint = "https://s3.example.org"
bucket = "provider-a-data"
"#,
        data_dir.display(),
    );
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    cfg.preflight().unwrap();
    cfg
}

use crate::fixtures::sample_metadata;

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

/// Build a lite `AppState` with a visible dataset (channel `inbox`) and an `error`
/// dataset (status-index only, channel `inbox`, sanitized message).
fn lite_state() -> (AppState, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();

    let mut status = StatusIndex::new();
    status.insert(
        VISIBLE_ID.to_owned(),
        StatusEntry {
            state: DatasetState::Visible,
            error_message: None,
            channel: "inbox".to_owned(),
            last_seen_signature: Some("sig".to_owned()),
            provenance: DatasetProvenance::Unknown,
        },
    );
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
    // A keyless lite node serves visibility from the cache; the visible dataset is
    // in both the cache (state) and the status index (channel).
    state.cache.insert(
        gdi_node_standalone_core::cache::StatusWrite::unshared(),
        DatasetEntry {
            id: VISIBLE_ID.to_owned(),
            metadata: sample_metadata(VISIBLE_ID),
            config: sample_config(),
            state: DatasetState::Visible,
            metadata_modified: None,
        },
    );
    // Mark readiness as fully ready (initial reconcile done) — a lite node has no
    // S3/Vault, so this models a node that has finished its startup scan.
    state.readiness.mark_initial_reconcile_done();
    state.readiness.set_key_material_ok(true);
    (state, tmp)
}

/// Issue a `GET` against the management-plane router (health + dataset-state), which is a
/// separate listener from the public plane. No metrics handle is supplied, so `/metrics` is
/// absent here.
async fn get(
    state: AppState,
    uri: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, axum::http::HeaderMap, String) {
    oneshot_get(build_management_router(state, None), uri, headers).await
}

/// Issue a `GET` against the public-plane router (beacon + FDP + well-known).
async fn get_public(
    state: AppState,
    uri: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, axum::http::HeaderMap, String) {
    oneshot_get(build_router(state), uri, headers).await
}

/// Drive one `GET` through `router` via `oneshot`, returning status + headers + body.
async fn oneshot_get(
    router: axum::Router,
    uri: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, axum::http::HeaderMap, String) {
    let mut builder = Request::builder().method("GET").uri(uri);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let req = builder.body(Body::empty()).unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let resp_headers = resp.headers().clone();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let body = String::from_utf8(bytes.to_vec()).unwrap();
    (status, resp_headers, body)
}

// ---- health ----

/// Liveness is 200 in every state, including the states where readiness is 503.
///
/// A healthy node is the one state where the two probes agree, so it cannot tell them
/// apart. Each state below is one where `/health/ready` is asserted to be 503 elsewhere in
/// this file, which makes the contrast real: same state, opposite verdicts.
///
/// Conflating the two is the classic orchestrator outage: a liveness probe that follows
/// readiness kills a draining or still-reconciling pod and restarts it in a loop, instead of
/// merely pulling it from rotation.
#[tokio::test]
async fn health_live_is_always_200() {
    // Healthy.
    let (state, _tmp) = lite_state();
    let (status, _h, _body) = get(state, "/health/live", &[]).await;
    assert_eq!(status, StatusCode::OK, "a ready node is live");

    // Draining: /health/ready is 503 here (health_ready_is_503_while_draining).
    let (state, _tmp) = lite_state();
    state.readiness.begin_shutdown();
    let (status, _h, _body) = get(state, "/health/live", &[]).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a draining node is still LIVE — a liveness probe that followed readiness would \
         kill the pod mid-drain instead of pulling it from rotation"
    );

    // Startup reconcile not finished: 503 on ready
    // (health_ready_is_503_before_initial_reconcile).
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let state = AppState::new(
        lite_config(&data_dir),
        StatusIndex::new(),
        NodeIdentities::empty(),
    );
    let (status, _h, _body) = get(state, "/health/live", &[]).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a node still completing its initial reconcile is live; killing it here would \
         restart the scan from the beginning, forever"
    );

    // Key material not ok — the subsystem fault that makes a node fail readiness.
    let (state, _tmp) = lite_state();
    state.readiness.set_key_material_ok(false);
    let (status, _h, _body) = get(state, "/health/live", &[]).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a node with a key-material fault is live: the process is running and must be \
         left alone for an operator to inspect"
    );
}

#[tokio::test]
async fn version_route_reports_build_info() {
    let (state, _tmp) = lite_state();
    let (status, _h, body) = get(state, "/version", &[]).await;
    assert_eq!(status, StatusCode::OK, "body:\n{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        v["service_version"],
        env!("CARGO_PKG_VERSION"),
        "body:\n{body}"
    );
    assert_eq!(
        v["gdi_metadata_version"],
        gdi_node_standalone_core::GDI_METADATA_VERSION,
        "body:\n{body}"
    );
}

/// `/catalogs` serves the `[catalogs]` table as plain JSON: the ids an integrating system
/// names in `metadata.catalog`. It reads the same reloadable snapshot as the FDP root, which
/// the second half proves. A catalog swapped in the way `SIGHUP` does appears without a
/// restart.
#[tokio::test]
async fn catalogs_route_lists_the_reloadable_catalog_table() {
    let (state, _tmp) = lite_state();
    let (status, _h, body) = get(state.clone(), "/catalogs", &[]).await;
    assert_eq!(status, StatusCode::OK, "body:\n{body}");
    let listed: CatalogList = serde_json::from_str(&body).unwrap();
    assert_eq!(
        listed,
        CatalogList::from_config(&state.reloadable().catalogs),
        "body:\n{body}"
    );
    let ids: Vec<&str> = listed.catalogs.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids, ["gdi-aggregated"], "body:\n{body}");
    assert_eq!(
        listed.catalogs[0].title, "Genome of Europe Aggregated Data",
        "the title is the `[catalogs]` display value, not the id echoed back"
    );

    // Swap the reloadable snapshot exactly as a reload does; the route follows it.
    let mut reloaded = (*state.reloadable()).clone();
    reloaded
        .catalogs
        .insert("added-by-reload".to_owned(), "Added By Reload".to_owned());
    *state.reloadable.write().unwrap() = std::sync::Arc::new(reloaded);
    let (status, _h, body) = get(state, "/catalogs", &[]).await;
    assert_eq!(status, StatusCode::OK, "body:\n{body}");
    let listed: CatalogList = serde_json::from_str(&body).unwrap();
    let ids: Vec<&str> = listed.catalogs.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(
        ids,
        ["added-by-reload", "gdi-aggregated"],
        "a reloaded catalog is listed, in id order, with no restart: body:\n{body}"
    );
}

#[tokio::test]
async fn health_ready_lite_is_200_with_subsystem_detail() {
    let (state, _tmp) = lite_state();
    let (status, _h, body) = get(state, "/health/ready", &[]).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "lite node must be ready; body:\n{body}"
    );

    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["ready"], serde_json::Value::Bool(true));
    let sub = &v["subsystems"];
    // No S3 / no Vault => not-configured; keyless => key_material ok; reconcile done.
    assert_eq!(sub["s3"], "not-configured", "body:\n{body}");
    assert_eq!(sub["vault"], "not-configured", "body:\n{body}");
    assert_eq!(sub["key_material"], "ok", "body:\n{body}");
    assert_eq!(sub["initial_reconcile"], "done", "body:\n{body}");
}

/// A config whose `[vault].transit_key` is set, so PME (and therefore the `at_rest`
/// subsystem) is a real dependency. Vault-gated: the `[vault]` config type is
/// feature-gated, and `transit_key` additionally requires the `pme` feature at runtime.
#[cfg(feature = "pme")]
fn pme_config(data_dir: &std::path::Path) -> ServiceConfig {
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

[vault]
address = "https://vault.example.org"
token = "hvs.TEST"
kv_path = "gdi/c4gh"
transit_key = "gdi-at-rest"
"#,
        data_dir.display(),
    );
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    cfg.preflight().unwrap();
    cfg
}

/// An unverifiable at-rest check must be distinguishable from a key mismatch on the probe.
///
/// Both are readiness failures, but they are not interchangeable: `mismatch` means the
/// Transit key cannot decrypt this node's data (recover the key; `pme reseal` refuses),
/// while `unverifiable` says nothing about the key at all (inspect the sentinel, then
/// reseal).
#[cfg(feature = "pme")]
#[tokio::test]
async fn an_unverifiable_at_rest_check_is_reported_distinctly_from_a_mismatch() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let state = AppState::new(
        pme_config(&data_dir),
        StatusIndex::new(),
        NodeIdentities::empty(),
    );
    state.readiness.mark_initial_reconcile_done();
    state.readiness.set_key_material_ok(true);
    state.readiness.set_vault_ok(true);

    state.readiness.set_at_rest(AtRestHealth::Unverifiable);
    let (status, _h, body) = get(state, "/health/ready", &[]).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "a check that could not be completed must not serve; body:\n{body}"
    );
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["subsystems"]["at_rest"], "unverifiable", "body:\n{body}");
    assert_ne!(
        v["subsystems"]["at_rest"], "mismatch",
        "an unverifiable check must NOT be reported as a key mismatch: it says nothing \
         about the key, and it would send the operator to disaster recovery"
    );
    assert_eq!(v["subsystems"]["vault"], "ok", "body:\n{body}");
}

/// An at-rest master-key mismatch must take the node out of rotation.
///
/// The node reports degraded with `ready: false`, but the process keeps running so an
/// operator can exec in and run the recovery subcommands. Serving on would mean answering
/// Beacon queries while every PME-backed read 500s, which hands callers a changed answer
/// set.
#[cfg(feature = "pme")]
#[tokio::test]
async fn at_rest_mismatch_takes_the_node_out_of_rotation() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let state = AppState::new(
        pme_config(&data_dir),
        StatusIndex::new(),
        NodeIdentities::empty(),
    );
    state.readiness.mark_initial_reconcile_done();
    state.readiness.set_key_material_ok(true);
    state.readiness.set_vault_ok(true);

    // Sentinel verified: everything else being healthy, the node serves.
    state.readiness.set_at_rest(AtRestHealth::Ok);
    let (status, _h, body) = get(state.clone(), "/health/ready", &[]).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "baseline must be ready; body:\n{body}"
    );
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["subsystems"]["at_rest"], "ok", "body:\n{body}");

    // Sentinel mismatch: the master key no longer unwraps this node's data.
    state.readiness.set_at_rest(AtRestHealth::Mismatch);
    let (status, _h, body) = get(state, "/health/ready", &[]).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "an unreadable at-rest store must 503: serving would answer queries while every \
         PME-backed read 500s. body:\n{body}"
    );
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["ready"], serde_json::Value::Bool(false), "body:\n{body}");
    assert_eq!(
        v["degraded"],
        serde_json::Value::Bool(true),
        "body:\n{body}"
    );
    // Named, not just "unavailable". A replaced master key and an unreadable sentinel are
    // both readiness failures, and the operator's next step differs: "recover the key" here,
    // "inspect the sentinel, then reseal" for the other.
    assert_eq!(v["subsystems"]["at_rest"], "mismatch", "body:\n{body}");
    // Not reported against vault: Vault is reachable and answering, so pointing triage at
    // connectivity would mislead.
    assert_eq!(v["subsystems"]["vault"], "ok", "body:\n{body}");
}

/// A node without PME is unaffected: `at_rest` is not a dependency there.
#[tokio::test]
async fn at_rest_is_not_configured_on_a_non_pme_node() {
    let (state, _tmp) = lite_state();
    let (status, _h, body) = get(state, "/health/ready", &[]).await;
    assert_eq!(status, StatusCode::OK, "body:\n{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        v["subsystems"]["at_rest"], "not-configured",
        "a node with no transit_key must not gain a new failure mode; body:\n{body}"
    );
}

#[tokio::test]
async fn health_ready_is_503_while_draining() {
    // A ready node that has received a shutdown signal reports not-ready, so the
    // orchestrator removes it from rotation before the listener stops.
    let (state, _tmp) = lite_state();
    state.readiness.begin_shutdown();
    let (status, _h, body) = get(state, "/health/ready", &[]).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "draining node must be not-ready; body:\n{body}"
    );
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["ready"], serde_json::Value::Bool(false));
    assert_eq!(
        v["draining"],
        serde_json::Value::Bool(true),
        "body:\n{body}"
    );
    // It is the drain, not a fault: the subsystems themselves are still healthy.
    assert_eq!(v["subsystems"]["key_material"], "ok", "body:\n{body}");
}

#[tokio::test]
async fn health_ready_is_503_before_initial_reconcile() {
    // A fresh state whose startup reconcile has not finished (the default for a
    // node that has just bound but not completed its scan): readiness is `pending`.
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let config = lite_config(&data_dir);
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
    state.readiness.set_key_material_ok(true);
    // Leave the initial reconcile unmarked.

    let (status, _h, body) = get(state, "/health/ready", &[]).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "not ready before reconcile; body:\n{body}"
    );
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["ready"], serde_json::Value::Bool(false));
    assert_eq!(v["subsystems"]["initial_reconcile"], "pending");
}

#[cfg(feature = "s3")]
#[tokio::test]
async fn unhealthy_bucket_does_not_block_node_readiness() {
    // With per-provider buckets, one unhealthy bucket must not take the whole node out of
    // rotation. Node readiness is decoupled from per-bucket reachability; the degraded
    // bucket is surfaced as per-bucket detail, not a 503.
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let config = s3_config(&data_dir);
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
    state.readiness.mark_initial_reconcile_done();
    state.readiness.set_key_material_ok(true);
    // The bucket's poll has failed — it is registered unhealthy.
    state.readiness.set_channel_health("provider-a", false);

    let (status, _h, body) = get(state, "/health/ready", &[]).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an unhealthy bucket must NOT 503 the node; body:\n{body}"
    );
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["ready"], serde_json::Value::Bool(true), "body:\n{body}");
    // The degraded bucket is visible as per-bucket detail; the aggregate rolls it up.
    assert_eq!(
        v["subsystems"]["s3_buckets"]["provider-a"], "unavailable",
        "per-bucket detail must name the degraded bucket; body:\n{body}"
    );
    assert_eq!(
        v["subsystems"]["s3"], "unavailable",
        "aggregate rollup reflects the degraded bucket; body:\n{body}"
    );
}

#[cfg(feature = "s3")]
#[tokio::test]
async fn ready_node_with_degraded_bucket_reports_degraded() {
    // A degraded provider bucket leaves the node ready, because it must keep serving every
    // other provider, but `ready: true` alone cannot tell an operator the node is serving a
    // partial view. `degraded` is that signal: it is `true` whenever any configured
    // subsystem reads `unavailable`, so a consumer sees "serving, but half-blind" without
    // parsing the per-bucket detail.
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let config = s3_config(&data_dir);
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
    state.readiness.mark_initial_reconcile_done();
    state.readiness.set_key_material_ok(true);
    state.readiness.set_channel_health("provider-a", false);

    let (status, _h, body) = get(state, "/health/ready", &[]).await;
    assert_eq!(status, StatusCode::OK, "body:\n{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["ready"], serde_json::Value::Bool(true), "body:\n{body}");
    assert_eq!(
        v["degraded"],
        serde_json::Value::Bool(true),
        "a ready node serving a partial view must report degraded; body:\n{body}"
    );
}

#[cfg(feature = "s3")]
#[tokio::test]
async fn ready_node_with_all_buckets_healthy_is_not_degraded() {
    // The complement: every configured subsystem healthy => `degraded: false`, so the
    // flag actually discriminates (a constant `true` would pass the test above).
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let config = s3_config(&data_dir);
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
    state.readiness.mark_initial_reconcile_done();
    state.readiness.set_key_material_ok(true);
    state.readiness.set_channel_health("provider-a", true);

    let (status, _h, body) = get(state, "/health/ready", &[]).await;
    assert_eq!(status, StatusCode::OK, "body:\n{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["ready"], serde_json::Value::Bool(true), "body:\n{body}");
    assert_eq!(
        v["degraded"],
        serde_json::Value::Bool(false),
        "a fully-healthy node must not report degraded; body:\n{body}"
    );
}

#[tokio::test]
async fn not_ready_node_is_also_degraded() {
    // `degraded` tracks "some configured subsystem is unavailable", which a node that is
    // not ready (key material failed to load) also is. The two flags are not exclusive.
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let config = lite_config(&data_dir);
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
    state.readiness.mark_initial_reconcile_done();
    state.readiness.set_key_material_ok(false);

    let (status, _h, body) = get(state, "/health/ready", &[]).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "body:\n{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["ready"], serde_json::Value::Bool(false), "body:\n{body}");
    assert_eq!(
        v["degraded"],
        serde_json::Value::Bool(true),
        "unavailable key_material is a degradation; body:\n{body}"
    );
}

// ---- dataset state endpoint ----

#[tokio::test]
async fn dataset_state_visible_inbox() {
    let (state, _tmp) = lite_state();
    let (status, headers, body) = get(state, &format!("/datasets/{VISIBLE_ID}/state"), &[]).await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["id"], VISIBLE_ID);
    assert_eq!(v["state"], "visible");
    assert_eq!(v["channel"], "inbox");
    assert!(
        v.get("error_message").is_none() || v["error_message"].is_null(),
        "visible must not carry error_message; body:\n{body}"
    );
    assert!(
        v.get("source_state").is_none(),
        "unsuppressed: source_state is OMITTED, not emitted equal; body:\n{body}"
    );
    // Management-plane: no wildcard CORS.
    assert!(
        !headers.contains_key("access-control-allow-origin"),
        "state endpoint must not carry wildcard CORS"
    );
}

#[tokio::test]
async fn dataset_state_shows_suppression_override() {
    // A dataset carrying an active operator suppression override surfaces `suppression.mode`
    // and `at`, so an orchestrator or an operator can tell "hidden by the source sidecar"
    // from "withheld by an operator override" without shelling into the node.
    //
    // The justification is absent: it is mandatory operator free text that in practice names
    // people, and this plane is unauthenticated. Its absence is asserted below, because "the
    // mode is present" would pass just as well with the reason beside it.
    let (state, _tmp) = lite_state();
    let sub = suppressions_subdir(&state.config.service.override_dir_resolved());
    write_file(
        &sub,
        VISIBLE_ID,
        &Suppression {
            mode: SuppressMode::Hide,
            reason: "embargo pending DPO review".to_owned(),
            at: "2026-07-11T00:00:00Z".to_owned(),
        },
    )
    .unwrap();
    state.reload_suppressions();

    let (status, _h, body) = get(state, &format!("/datasets/{VISIBLE_ID}/state"), &[]).await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["suppression"]["mode"], "hide", "body:\n{body}");
    assert_eq!(
        v["suppression"]["at"], "2026-07-11T00:00:00Z",
        "body:\n{body}"
    );
    // Only the store was reloaded above; the cache still says `visible`, which is the
    // reload-to-apply window. The oracle composes rather than trusting the cache raw, so the
    // body cannot say "visible" beside an active withhold; the masked declared state
    // moves to `source_state`.
    assert_eq!(
        v["state"], "hidden",
        "an active override must compose into the state, not sit contradicted beside it:\n{body}"
    );
    assert_eq!(v["source_state"], "visible", "body:\n{body}");
    assert!(
        v["suppression"].get("reason").is_none(),
        "the operator's justification must not be served on this plane; body:\n{body}"
    );
    assert!(
        !body.contains("embargo pending DPO review"),
        "no part of the justification may reach the wire; body:\n{body}"
    );
}

/// A dataset withheld by a whole-channel take-down reports that too.
///
/// A channel-level override withholds every dataset on that channel. Looking the id up alone
/// would answer `suppression: null` and tell an operator asking "is this suppressed?" no
/// about a dataset the node is actively withholding.
#[tokio::test]
async fn dataset_state_shows_a_channel_level_suppression() {
    let (state, _tmp) = lite_state();
    let sub = suppressions_subdir(&state.config.service.override_dir_resolved());
    write_channel_file(
        &sub,
        "inbox",
        &Suppression {
            mode: SuppressMode::Hide,
            reason: "provider agreement suspended".to_owned(),
            at: "2026-07-21T00:00:00Z".to_owned(),
        },
    )
    .unwrap();
    state.reload_suppressions();

    let (status, _h, body) = get(state, &format!("/datasets/{VISIBLE_ID}/state"), &[]).await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        v["suppression"]["mode"], "hide",
        "a channel take-down withholds this id, so it must not report null:\n{body}"
    );
    assert!(
        !body.contains("provider agreement suspended"),
        "a CHANNEL suppression's justification is the same free text as a per-dataset one, \
         and must not reach this plane either; body:\n{body}"
    );
}

#[tokio::test]
async fn dataset_state_omits_suppression_when_unsuppressed() {
    // The common case: no override file written — `reload_suppressions` loads an empty
    // set, because the dir is missing, and the field is absent rather than `null`, matching the
    // `overlay_error`/`overlay_applied_at` `skip_serializing_if` precedent.
    let (state, _tmp) = lite_state();
    state.reload_suppressions();
    let (status, _h, body) = get(state, &format!("/datasets/{VISIBLE_ID}/state"), &[]).await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(
        v.get("suppression").is_none(),
        "suppression must be omitted, not null, when unsuppressed; body:\n{body}"
    );
}

#[tokio::test]
async fn dataset_state_serves_through_the_trace_layer_with_a_traceparent() {
    // `/datasets/{id}/state` is traced only when the caller supplies a `traceparent`, so a
    // span can nest under the orchestrator's trace. The traced path serves the request
    // identically: the trace layer does not alter the response.
    let (state, _tmp) = lite_state();
    let traceparent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
    let (status, _headers, body) = get(
        state,
        &format!("/datasets/{VISIBLE_ID}/state"),
        &[("traceparent", traceparent)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "traced state request must still 200"
    );
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["id"], VISIBLE_ID);
    assert_eq!(v["state"], "visible");
}

/// The index-only arm composes the override too, and keeps the error class.
///
/// An errored dataset is the concrete case: its ingest failed, so nothing is cached and
/// `apply_suppressions_to_cache`, which withholds by mutating the cache, can never reach it.
/// Serving the index state raw would answer `state: "error"` with `suppression: {mode:
/// "hide"}` attached, a body that contradicts itself and disagrees with what `dataset list`
/// reports for the same id.
///
/// All three fields are asserted together because each guards a different property: `state`
/// the composition, `source_state` that the mask is explained, and `error_message` that
/// composing did not swallow the class an operator triages by.
#[tokio::test]
async fn dataset_state_composes_a_suppression_on_an_index_only_error_dataset() {
    let (state, _tmp) = lite_state();
    let sub = suppressions_subdir(&state.config.service.override_dir_resolved());
    write_file(
        &sub,
        ERROR_ID,
        &Suppression {
            mode: SuppressMode::Hide,
            reason: "withheld pending investigation".to_owned(),
            at: "2026-08-12T00:00:00Z".to_owned(),
        },
    )
    .unwrap();
    state.reload_suppressions();
    // The cache apply runs as it would on SIGUSR1, and is a no-op here: ERROR_ID is not in
    // the cache, so only the handler's own composition can make the answer effective.
    state.apply_suppressions_to_cache();

    let (status, _h, body) = get(state, &format!("/datasets/{ERROR_ID}/state"), &[]).await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["state"], "hidden", "the withhold wins:\n{body}");
    assert_eq!(v["source_state"], "error", "the mask is explained:\n{body}");
    assert_eq!(
        v["error_message"], "invalid-manifest",
        "withholding a broken dataset does not repair it — the class survives:\n{body}"
    );
    assert_eq!(v["suppression"]["mode"], "hide", "body:\n{body}");
    assert!(
        !body.contains("withheld pending investigation"),
        "the justification stays off this plane:\n{body}"
    );
}

#[tokio::test]
async fn dataset_state_error_carries_sanitized_message() {
    let (state, _tmp) = lite_state();
    let (status, _h, body) = get(state, &format!("/datasets/{ERROR_ID}/state"), &[]).await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["state"], "error");
    assert_eq!(v["channel"], "inbox");
    // `error_message` is a closed vocabulary a client can match exhaustively, never free
    // text, so the served value is one of the published classes.
    assert_eq!(v["error_message"], "invalid-manifest");
    assert!(
        gdi_node_standalone_core::error::ErrorClass::ALL
            .iter()
            .any(|c| c.as_str() == v["error_message"].as_str().unwrap()),
        "error_message must be a published ErrorClass string"
    );
}

#[tokio::test]
async fn dataset_state_unknown_id_is_404() {
    let (state, _tmp) = lite_state();
    let (status, _h, _body) = get(state, "/datasets/GDI-XX-XXX-00000000000000000/state", &[]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn dataset_state_traversal_id_is_rejected_no_panic() {
    let (state, _tmp) = lite_state();
    // A traversal-shaped id must be rejected at the boundary (400/404), never used.
    for bad in ["..%2Fetc", "GDI-EE-UTARTU-1%2F..%2Fsecret", "not_an_id"] {
        let (status, _h, _body) = get(state.clone(), &format!("/datasets/{bad}/state"), &[]).await;
        assert!(
            status == StatusCode::BAD_REQUEST || status == StatusCode::NOT_FOUND,
            "traversal id {bad:?} must be 400/404, got {status}"
        );
    }
}

// ---- CORS scoping ----

#[tokio::test]
async fn beacon_aggregated_carries_wildcard_cors() {
    let (state, _tmp) = lite_state();
    // The aggregated beacon mount (a public browser endpoint) carries the wildcard.
    let (status, headers, _body) = get_public(
        state,
        "/beacon/v2/g_variants",
        &[("origin", "https://userportal.example.org")],
    )
    .await;
    // 200 (empty query) — the point is the CORS header, not the body.
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("*"),
        "aggregated beacon must carry wildcard CORS"
    );
}

#[tokio::test]
async fn wellknown_recipient_has_no_wildcard_cors() {
    let (state, _tmp) = lite_state();
    let (_status, headers, _body) = get_public(
        state,
        "/.well-known/c4gh-recipient",
        &[("origin", "https://userportal.example.org")],
    )
    .await;
    assert!(
        !headers.contains_key("access-control-allow-origin"),
        "well-known recipient must not carry wildcard CORS"
    );
}

// ---- trust boundary: management routes are not on the public plane ----

#[tokio::test]
async fn management_routes_absent_from_public_plane() {
    // The whole point of the separate management listener: the public router serves
    // beacon/FDP only. The health probes and the hidden-dataset state oracle must
    // 404 there, so a misconfigured public Ingress can never expose them.
    let (state, _tmp) = lite_state();
    for uri in [
        "/health/live",
        "/health/ready",
        "/version",
        "/catalogs",
        &format!("/datasets/{VISIBLE_ID}/state"),
        "/metrics",
    ] {
        let (status, _h, _body) = get_public(state.clone(), uri, &[]).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{uri} must not be served on the public plane"
        );
    }
}

/// The opt-in management surfaces are absent from the public plane too, asserted with every
/// one of them switched on.
///
/// Separate from the test above because the flags decide what is mounted. With them off, the
/// default `lite_state` posture, these paths 404 on both planes because the route is not
/// mounted anywhere, so adding them to that list would pass vacuously.
///
/// These five are the highest-consequence paths to leave unbound. Two enumerate every dataset
/// the node holds, hidden ones included; three are unauthenticated actions that make the node
/// do something.
#[tokio::test]
async fn opt_in_management_routes_are_absent_from_the_public_plane() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"
expose_dataset_list = true

[stats]
enabled = true

[control]
enabled = true

[catalogs]
gdi-aggregated = "GoE"

[beacon]
id = "org.test.beacon"
name = "Test Beacon"
"#,
        data_dir.display(),
    );
    let config = ServiceConfig::from_toml_str(&toml).unwrap();
    config.preflight().unwrap();
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());

    // Derived from `app.rs` rather than restated: every route the router mounts behind an
    // `if cfg.<flag>` block. A new opt-in route joins this guard by existing.
    let gated = crate::route_inventory::all_flag_gated_paths();
    assert!(
        gated.len() >= 6,
        "parsed only {} flag-gated routes from app.rs — the parser broke and this guard \
         would pass by checking nothing",
        gated.len()
    );

    // A gated path may carry a placeholder (`/datasets/{id}/reingest`); braces are not URI
    // characters, so the probe substitutes a concrete segment the one way every
    // route-shaped guard does.
    let concrete = crate::route_inventory::concretize;

    // Mounted on the management plane, which is what stops this passing vacuously. A method
    // no route allows distinguishes "registered" (405) from "absent" (404). A new flag whose
    // routes are missing fails at this loop, meaning the config above has not turned the new
    // surface on.
    for uri in gated.iter().map(|path| concrete(path)) {
        let resp = build_management_router(state.clone(), None)
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(&uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "{uri} must be mounted on the management plane with its flag on, or this test \
             proves nothing about the public one"
        );
    }

    // ...and absent from the public one.
    for uri in gated.iter().map(|path| concrete(path)) {
        let (status, _h, _body) = get_public(state.clone(), &uri, &[]).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{uri} must NOT be served on the public plane: a misconfigured public Ingress \
             would otherwise expose the hidden-dataset inventory, the per-dataset usage \
             counters, or an unauthenticated reload/reconcile/log-level action"
        );
    }
}

#[tokio::test]
async fn health_has_no_wildcard_cors() {
    let (state, _tmp) = lite_state();
    let (_status, headers, _body) = get(
        state,
        "/health/live",
        &[("origin", "https://userportal.example.org")],
    )
    .await;
    assert!(
        !headers.contains_key("access-control-allow-origin"),
        "health probe must not carry wildcard CORS"
    );
}
