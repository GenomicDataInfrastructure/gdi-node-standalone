//! Integration test for the encrypted `.tar.c4gh` inbox path.
//!
//! Generates a node crypt4gh keypair, writes the secret to a temp identity file
//! and configures `[keys].identities = [that path]`, builds a COVID `.tar.c4gh`
//! encrypted to the node recipient (a real staging dir → uncompressed TAR →
//! `crypt4gh::encrypt`), drops `{id}.tar.c4gh` + `{id}.state.json` into the inbox,
//! runs the runtime's `scan_once`, and polls the cache until the dataset is
//! `Visible` — asserting the package was consumed and metadata loaded. It also
//! builds the router and asserts `GET /.well-known/c4gh-recipient` returns a
//! parseable recipient, and that a package encrypted to a different recipient
//! lands in `inbox/.rejected/{id}/` as a permanent `decrypt-failed` error.
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
#![expect(
    clippy::similar_names,
    reason = "node/other sk/pk are the standard, clearest crypto naming"
)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use gdi_node_standalone::app::build_router;
use gdi_node_standalone::identities::NodeIdentities;
use gdi_node_standalone::ingest_runtime::IngestRuntime;
use gdi_node_standalone::state::AppState;
use gdi_node_standalone_core::cache::StatusIndex;
use gdi_node_standalone_core::config::ServiceConfig;
use gdi_node_standalone_core::crypt4gh::{PublicKey, encrypt, generate_keypair, parse_public_key};
use gdi_node_standalone_core::state::DatasetState;
use tower::ServiceExt as _; // for `oneshot`

use crate::fixtures::{build_covid_staging_goe, poll_until, write_identity};

const CATALOG: &str = "gdi-aggregated";

/// Pack a staging dir into an uncompressed TAR (manifest first, then the parquet),
/// then crypt4gh-encrypt it to `recipient`, writing `{id}.tar.c4gh` under `dest`
/// and returning its path. The plaintext staging dir is removed afterward.
fn build_tar_c4gh(work: &Path, dest: &Path, id: &str, recipient: &PublicKey) -> PathBuf {
    let staging = build_covid_staging_goe(work, id);

    // Uncompressed TAR in the spec member order.
    let tar_path = work.join(format!("{id}.tar"));
    {
        let file = std::fs::File::create(&tar_path).unwrap();
        let mut builder = tar::Builder::new(file);
        builder
            .append_path_with_name(staging.join("manifest.json"), "manifest.json")
            .unwrap();
        for entry in std::fs::read_dir(&staging).unwrap() {
            let p = entry.unwrap().path();
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            if name.starts_with("allele-freq.") && name.ends_with(".parquet") {
                builder.append_path_with_name(&p, &name).unwrap();
            }
        }
        builder.into_inner().unwrap().sync_all().unwrap();
    }
    std::fs::remove_dir_all(&staging).unwrap();

    // Encrypt to the recipient.
    let pkg = dest.join(format!("{id}.tar.c4gh"));
    let (sender_sk, _sender_pk) = generate_keypair();
    let mut reader = std::fs::File::open(&tar_path).unwrap();
    let mut writer = std::fs::File::create(&pkg).unwrap();
    encrypt(
        &mut reader,
        &mut writer,
        std::slice::from_ref(recipient),
        &sender_sk,
    )
    .unwrap();
    writer.sync_all().unwrap();
    pkg
}

/// A minimal valid service config with one catalog + a `[keys].identities` list.
fn test_config(data_dir: &Path, inbox: &Path, identity: &Path) -> ServiceConfig {
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"
inbox = "{}"
ingest_concurrency = 2
rescan_interval_seconds = 3600

[catalogs]
{CATALOG} = "Genome of Europe Aggregated Data"

[beacon]
id = "org.test.beacon"
name = "Test Beacon"

[keys]
identities = ["{}"]
"#,
        data_dir.display(),
        inbox.display(),
        identity.display(),
    );
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    cfg.preflight().unwrap();
    cfg
}

/// Write the node secret key to `path` as the unencrypted crypt4gh PEM, `0600`.

#[tokio::test]
async fn ingests_tar_c4gh_from_inbox_and_publishes_recipient() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    let keys = tmp.path().join("keys");
    let work = tmp.path().join("work");
    for d in [&data_dir, &inbox, &keys, &work] {
        std::fs::create_dir_all(d).unwrap();
    }

    // Node identity.
    let (node_sk, node_pk) = generate_keypair();
    let identity_file = keys.join("node.c4gh");
    write_identity(&identity_file, &node_sk);

    let id = "GDI-EE-UTARTU-20260409143052837";
    // Build {id}.tar.c4gh encrypted to the node recipient, drop into the inbox.
    build_tar_c4gh(&work, &inbox, id, &node_pk);
    std::fs::write(
        inbox.join(format!("{id}.state.json")),
        br#"{"state":"visible"}"#,
    )
    .unwrap();

    let config = test_config(&data_dir, &inbox, &identity_file);
    let identities = NodeIdentities::load(&config).unwrap();
    assert!(identities.is_enabled(), "the node has an identity");
    let state = AppState::new(config, StatusIndex::new(), identities);
    let runtime = IngestRuntime::start(state.clone());

    runtime.scan_once().await;

    // Poll until the dataset is Visible.
    poll_until(Duration::from_secs(15), || {
        state
            .cache
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;

    let entry = state.cache.get(id).unwrap();
    assert_eq!(entry.state, DatasetState::Visible);
    assert_eq!(entry.metadata.dataset_id, id);
    assert_eq!(entry.config.assembly.reference, "GRCh38");

    // The published dataset has a manifest + parquet.
    let published = data_dir.join(id);
    assert!(published.join("manifest.json").is_file());
    let has_parquet = std::fs::read_dir(&published)
        .unwrap()
        .filter_map(Result::ok)
        .any(|e| e.file_name().to_string_lossy().ends_with(".parquet"));
    assert!(has_parquet, "a parquet must be published");

    // The dataset is published (Visible) one step before the worker consumes the
    // source and clears its in-flight guard; drain to quiescence before asserting.
    crate::fixtures::await_ingest_quiescent(&runtime).await;
    // The .tar.c4gh package was consumed (deleted); the sidecar persists.
    assert!(
        !inbox.join(format!("{id}.tar.c4gh")).exists(),
        "the package must be consumed on success"
    );
    assert!(
        inbox.join(format!("{id}.state.json")).exists(),
        "the sidecar must persist"
    );

    // The status index recorded the inbox channel + a signature, no error.
    {
        let status = state.status.lock().unwrap();
        let e = status.get(id).expect("status entry recorded");
        assert_eq!(e.channel, "inbox");
        assert!(e.last_seen_signature.is_some());
        assert_eq!(e.error_message, None);
    }

    // GET /.well-known/c4gh-recipient returns the node's recipient (parseable).
    let router = build_router(state.clone());
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
    let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let pem = String::from_utf8(body.to_vec()).unwrap();
    let parsed = parse_public_key(&pem).expect("the recipient parses");
    assert_eq!(
        parsed.as_bytes(),
        node_pk.as_bytes(),
        "the published recipient is the first identity's public key"
    );
}

#[tokio::test]
async fn wrong_recipient_tar_c4gh_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    let keys = tmp.path().join("keys");
    let work = tmp.path().join("work");
    for d in [&data_dir, &inbox, &keys, &work] {
        std::fs::create_dir_all(d).unwrap();
    }

    // The node holds one identity; the package is encrypted to a different one.
    let (node_sk, _node_pk) = generate_keypair();
    let identity_file = keys.join("node.c4gh");
    write_identity(&identity_file, &node_sk);
    let (_other_sk, other_pk) = generate_keypair();

    let id = "GDI-EE-UTARTU-20260409143052901";
    build_tar_c4gh(&work, &inbox, id, &other_pk);

    let config = test_config(&data_dir, &inbox, &identity_file);
    let identities = NodeIdentities::load(&config).unwrap();
    let state = AppState::new(config, StatusIndex::new(), identities);
    let runtime = IngestRuntime::start(state.clone());

    runtime.scan_once().await;

    // Poll until the status index records the permanent error.
    poll_until(Duration::from_secs(15), || {
        let status = state.status.lock().unwrap();
        status
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Error)
    })
    .await;

    // The artifact was moved to inbox/.rejected/{id} (a file, not re-scanned).
    let rejected = inbox.join(".rejected").join(id);
    assert!(
        rejected.exists(),
        "a permanent-error package must move to inbox/.rejected/{{id}}"
    );
    assert!(
        !inbox.join(format!("{id}.tar.c4gh")).exists(),
        "the original package must be moved out of the scan path"
    );

    {
        let status = state.status.lock().unwrap();
        let e = status.get(id).expect("status entry recorded");
        assert_eq!(e.state, DatasetState::Error);
        assert_eq!(
            e.error_message,
            Some(gdi_node_standalone_core::error::ErrorClass::DecryptFailed)
        );
    }

    // The dataset is not visible.
    assert!(
        state
            .cache
            .get(id)
            .is_none_or(|e| e.state != DatasetState::Visible)
    );
}
