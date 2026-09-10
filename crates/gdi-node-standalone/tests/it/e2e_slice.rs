//! Capstone end-to-end test.
//!
//! Exercises the whole architecture through both inbox channels, using the real tool
//! commands, the real service ingest runtime, and an in-process HTTP query:
//!
//! * (A) staging-dir path: `gdi-dataset-tool build` produces a `build/{id}/`
//!   staging dir; it is moved atomically into the service inbox alongside a
//!   `{id}.state.json{"state":"visible"}` sidecar; one inbox `scan_once` + the
//!   worker drain ingests it; the cache is polled (bounded, no fixed sleep) until
//!   the dataset is `Visible`; then a `g_variants` POST for the COVID chr3 T>C
//!   site returns the expected `frequencyInPopulations`.
//! * (B) `.tar.c4gh` path: a node keypair is generated, its secret written to
//!   a `[keys].identities` file and its public key to a recipient file;
//!   `gdi-dataset-tool package --recipient <node.pub>` produces an encrypted
//!   `{id}.tar.c4gh`; it is dropped into the inbox with a sidecar; the runtime
//!   decrypts + ingests it; the same `g_variants` POST returns the same
//!   frequencies; and `GET /.well-known/c4gh-recipient` publishes the node
//!   recipient (parseable back to the node's public key).
//!
//! `gdi-dataset-tool package` auto-generates a provider keypair under
//! `$GDI_CONFIG_DIR` (a process-global env var), so path (B) is `#[serial(env)]`.
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::path::{Path, PathBuf};
use std::time::Duration;

use axum::body::{Body, to_bytes};

use crate::fixtures::{body_json, poll_until};
use axum::http::{Request, StatusCode};
use clap::Parser as _;
use gdi_dataset_tool::cli::Cli;
use gdi_node_standalone::app::build_router;
use gdi_node_standalone::identities::NodeIdentities;
use gdi_node_standalone::ingest_runtime::IngestRuntime;
use gdi_node_standalone::state::AppState;
use gdi_node_standalone_core::cache::StatusIndex;
use gdi_node_standalone_core::config::ServiceConfig;
use gdi_node_standalone_core::crypt4gh::{
    generate_keypair, parse_public_key, serialize_public_key, serialize_secret_key,
};
use gdi_node_standalone_core::state::DatasetState;
use serde_json::Value;
use serial_test::serial;
use test_util::covid;
use tower::ServiceExt as _; // for `oneshot`

const CATALOG: &str = "gdi-aggregated";
const AGG_BASE_PATH: &str = "/beacon/v2";

/// Return the single subdirectory of `out` (the `<datasetId>/` staging dir).
fn single_subdir(out: &Path) -> PathBuf {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(out)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    assert_eq!(
        dirs.len(),
        1,
        "expected exactly one staging dir under {}",
        out.display()
    );
    dirs.remove(0)
}

/// Run `gdi-dataset-tool build --cc EE` for the COVID fixture into `out`, returning
/// the produced `<out>/<datasetId>/` staging dir. The package is materialized into a
/// sibling `covid-pkg` dir under `out`'s parent temp dir.
fn run_build(out: &Path) -> PathBuf {
    let pkg_dir = out
        .parent()
        .expect("out must have a parent temp dir")
        .join("covid-pkg");
    let cli = Cli::try_parse_from([
        "gdi-dataset-tool",
        "build",
        test_util::write_covid_package(&pkg_dir).to_str().unwrap(),
        "--cc",
        "EE",
        "-o",
        out.to_str().unwrap(),
    ])
    .unwrap();
    gdi_dataset_tool::run(cli).expect("tool build succeeds");
    single_subdir(out)
}

/// A minimal valid service config: one catalog, the aggregated beacon mount, and an
/// optional `[keys].identities` entry for the encrypted-package path.
fn test_config(data_dir: &Path, inbox: &Path, identity: Option<&Path>) -> ServiceConfig {
    let keys_section = identity.map_or_else(String::new, |p| {
        format!("\n[keys]\nidentities = [\"{}\"]\n", p.display())
    });
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{data}"
inbox = "{inbox}"
ingest_concurrency = 2
rescan_interval_seconds = 3600

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
{keys_section}"#,
        data = data_dir.display(),
        inbox = inbox.display(),
    );
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    cfg.preflight().unwrap();
    cfg
}

/// Build a `g_variants` POST for the known COVID chr3:45823240 T>C site.
fn covid_g_variants_request() -> Request<Body> {
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
    Request::builder()
        .method("POST")
        .uri(format!("{AGG_BASE_PATH}/g_variants"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

/// Assert the `g_variants` response for `id` carries the expected COVID
/// frequencies: `FI_M` at `alleleFrequency ≈ 0.085` and `Total` at
/// `alleleCount == 618` / `alleleNumber == 8000`.
fn assert_covid_frequencies(v: &Value, id: &str) {
    let result_sets = v["response"]["resultSets"].as_array().unwrap();
    assert_eq!(result_sets.len(), 1, "one resultSet for the single dataset");
    assert_eq!(result_sets[0]["id"], id);

    let freqs = result_sets[0]["results"][0]["frequencyInPopulations"][0]["frequencies"]
        .as_array()
        .unwrap();

    let fi_m = freqs
        .iter()
        .find(|f| f["population"] == "FI_M")
        .expect("FI_M frequency present");
    let fi_m_af = fi_m["alleleFrequency"].as_f64().unwrap();
    assert!(
        (fi_m_af - covid::FI_M_AF).abs() < 1e-3,
        "FI_M alleleFrequency {fi_m_af} not ≈ 0.085"
    );

    let total = freqs
        .iter()
        .find(|f| f["population"] == "Total")
        .expect("Total frequency present");
    assert_eq!(total["alleleCount"].as_u64().unwrap(), covid::TOTAL_AC);
    assert_eq!(total["alleleNumber"].as_u64().unwrap(), covid::TOTAL_AN);
}

/// (A) staging-dir path: build → inbox → ingest → query.
#[tokio::test]
async fn build_staging_inbox_ingest_query_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    let build_out = tmp.path().join("build");
    for d in [&data_dir, &inbox, &build_out] {
        std::fs::create_dir_all(d).unwrap();
    }

    // 1. Run the real tool `build` over the COVID fixture.
    let staging = run_build(&build_out);
    let id = staging.file_name().unwrap().to_str().unwrap().to_owned();
    assert!(
        id.starts_with("GDI-EE-UTARTU-"),
        "datasetId encodes cc=EE: {id}"
    );

    // 2. Atomically place the staging dir + a {"state":"visible"} sidecar into the
    //    inbox (rename within the same tempdir is atomic).
    std::fs::rename(&staging, inbox.join(&id)).unwrap();
    std::fs::write(
        inbox.join(format!("{id}.state.json")),
        br#"{"state":"visible"}"#,
    )
    .unwrap();

    // 3. Start the service runtime, scan once, drain the workers, poll until Visible.
    let config = test_config(&data_dir, &inbox, None);
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
    let runtime = IngestRuntime::start(state.clone());
    runtime.scan_once().await;
    poll_until(Duration::from_secs(10), || {
        state
            .cache
            .get(&id)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;
    crate::fixtures::await_ingest_quiescent(&runtime).await;

    // The staging dir was consumed; the dataset published with a parquet.
    assert!(!inbox.join(&id).exists(), "the staging dir is consumed");
    assert!(data_dir.join(&id).join("manifest.json").is_file());

    // 4. Query g_variants and assert the COVID frequencies.
    let router = build_router(state);
    let resp = router.oneshot(covid_g_variants_request()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp.into_body()).await;
    assert_covid_frequencies(&v, &id);
}

/// (B) `.tar.c4gh` path: package (encrypted to the node) → inbox → decrypt +
/// ingest → query, plus the published recipient.
#[tokio::test]
#[serial(env)]
async fn package_c4gh_inbox_ingest_query_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    let build_out = tmp.path().join("build");
    let keys = tmp.path().join("keys");
    for d in [&data_dir, &inbox, &build_out, &keys] {
        std::fs::create_dir_all(d).unwrap();
    }

    // `package` auto-generates a provider keypair under $GDI_CONFIG_DIR.
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("config"));

    // 1. Generate the node keypair: secret -> identity file, public -> recipient file.
    let (node_sk, node_pk) = generate_keypair();
    let identity_file = keys.join("node.c4gh");
    std::fs::write(&identity_file, serialize_secret_key(&node_sk)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&identity_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let recipient_file = keys.join("node.c4gh.pub");
    std::fs::write(&recipient_file, serialize_public_key(&node_pk)).unwrap();

    // 2. Run the real tool `package --recipient <node.pub>`. The datasetId encodes a
    //    fresh timestamp at build time, so discover it from the staging dir under
    //    `--build-out` rather than guessing — then name the inbox artifact +
    //    sidecar to match (the runtime keys ingestion off the `{id}.tar.c4gh` name).
    //    `--keep` retains the staging dir for that ID discovery (`package` deletes
    //    it by default).
    let staged_pkg = tmp.path().join("staged.tar.c4gh");
    let package = test_util::write_covid_package(&tmp.path().join("covid-pkg"));
    let cli = Cli::try_parse_from([
        "gdi-dataset-tool",
        "package",
        package.to_str().unwrap(),
        "--cc",
        "EE",
        "--build-out",
        build_out.to_str().unwrap(),
        "--recipient",
        recipient_file.to_str().unwrap(),
        "-o",
        staged_pkg.to_str().unwrap(),
        "--keep",
    ])
    .unwrap();
    gdi_dataset_tool::run(cli).expect("tool package succeeds");
    assert!(staged_pkg.is_file(), "the encrypted package is written");

    let id = single_subdir(&build_out)
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(
        id.starts_with("GDI-EE-UTARTU-"),
        "datasetId encodes cc=EE: {id}"
    );

    // 3. Drop {id}.tar.c4gh + a {"state":"visible"} sidecar into the inbox; configure
    //    the service with the node identity; scan, drain, poll.
    let pkg = inbox.join(format!("{id}.tar.c4gh"));
    std::fs::rename(&staged_pkg, &pkg).unwrap();
    std::fs::write(
        inbox.join(format!("{id}.state.json")),
        br#"{"state":"visible"}"#,
    )
    .unwrap();
    let config = test_config(&data_dir, &inbox, Some(&identity_file));
    let identities = NodeIdentities::load(&config).unwrap();
    assert!(identities.is_enabled(), "the node has a loaded identity");
    let state = AppState::new(config, StatusIndex::new(), identities);
    let runtime = IngestRuntime::start(state.clone());
    runtime.scan_once().await;
    poll_until(Duration::from_secs(15), || {
        state
            .cache
            .get(&id)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;

    // The package is published (Visible) one step before the worker consumes the
    // source; drain to quiescence before asserting on that consumption.
    crate::fixtures::await_ingest_quiescent(&runtime).await;
    // The package was consumed (decrypted + ingested); the dataset is published.
    assert!(!pkg.exists(), "the .tar.c4gh is consumed on success");
    assert!(data_dir.join(&id).join("manifest.json").is_file());

    // 4. Query g_variants and assert the same COVID frequencies.
    let router = build_router(state);
    let resp = router
        .clone()
        .oneshot(covid_g_variants_request())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp.into_body()).await;
    assert_covid_frequencies(&v, &id);

    // 5. The node recipient is published and parses back to the node public key.
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/.well-known/c4gh-recipient")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let pem = String::from_utf8(
        to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    let parsed = parse_public_key(&pem).expect("the published recipient parses");
    assert_eq!(
        parsed.as_bytes(),
        node_pk.as_bytes(),
        "the published recipient is the node's public key"
    );
}
