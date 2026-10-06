//! Integration test: malformed parquet on the ingest path.
//!
//! A parquet with a malformed embedded `ARROW:schema` must not crash the worker. Run
//! through the inbox runtime (`scan_once` → `spawn_blocking`), the dataset must end in a
//! permanent `error`, the process must keep running, and the staging dir must move to
//! `inbox/.rejected/{id}/`. (`arrow-ipc` 59 panicked on this file, which exercised the
//! `catch_unwind` and `JoinError::is_panic` guards; 60 returns a parse error first.)
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::path::Path;
use std::time::Duration;

use gdi_node_standalone::identities::NodeIdentities;
use gdi_node_standalone::ingest_runtime::IngestRuntime;
use gdi_node_standalone::state::AppState;
use gdi_node_standalone_core::cache::StatusIndex;
use gdi_node_standalone_core::state::DatasetState;

use crate::fixtures::{manifest_for, poll_until};

const CATALOG: &str = "gdi-aggregated";
const ID: &str = "GDI-EE-UTARTU-20260409143052837";

/// Crafted parquet with a malformed embedded Arrow schema (shared with core's tests).
fn malformed_parquet() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../core/tests/fixtures/malformed/arrow_schema_panic.parquet")
}

#[tokio::test]
async fn a_malformed_parquet_ingest_becomes_a_permanent_error_not_a_crash() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    for d in [&data_dir, &inbox] {
        std::fs::create_dir_all(d).unwrap();
    }

    // A valid manifest plus the malformed parquet under a canonical data-file name, so
    // the layout check passes and per-file validation runs.
    let staging = inbox.join(ID);
    std::fs::create_dir_all(&staging).unwrap();
    std::fs::write(
        staging.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest_for(ID, "gdi-aggregated", 1)).unwrap(),
    )
    .unwrap();
    std::fs::copy(
        malformed_parquet(),
        staging.join("allele-freq.chr1.0.br10000000.0123456789abcdef.parquet"),
    )
    .unwrap();

    let config = crate::fixtures::inbox_config(&data_dir, &inbox, CATALOG);
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
    let runtime = IngestRuntime::start(state.clone());

    // Run the scan; it must return normally despite the malformed schema.
    runtime.scan_once().await;

    // The dataset reaches a permanent `error` in the status index.
    poll_until(Duration::from_secs(15), || {
        let status = state.status.lock().unwrap();
        status
            .get(ID)
            .is_some_and(|e| e.state == DatasetState::Error)
    })
    .await;

    {
        let status = state.status.lock().unwrap();
        let e = status.get(ID).expect("status entry recorded");
        assert_eq!(e.state, DatasetState::Error);
        // error_message is the sanitized error class: no path, no id.
        assert_eq!(
            e.error_message,
            Some(gdi_node_standalone_core::error::ErrorClass::InvalidParquetSchema),
            "the malformed schema must surface as the sanitized class"
        );
        // Path-freeness is structural: the field is typed, so the only strings it can
        // render are the compile-time class constants, which the taxonomy golden test
        // asserts are path-free. The rendered value is re-asserted here so the intent
        // survives if the field ever widens.
        let msg = e
            .error_message
            .map(gdi_node_standalone_core::error::ErrorClass::as_str);
        assert!(
            msg.is_some_and(|m| !m.contains('/') && !m.contains(ID)),
            "error_message must be path-free and not echo the id: {msg:?}"
        );
    }

    // The artifact was quarantined; it is not published and not left to re-scan.
    assert!(
        inbox.join(".rejected").join(ID).exists(),
        "a permanent-error staging dir must move to inbox/.rejected/{{id}}"
    );
    assert!(
        !staging.exists(),
        "the original staging dir must be moved out of the scan path"
    );
    assert!(
        !data_dir.join(ID).exists(),
        "a panicking ingest must not publish the dataset"
    );
    assert!(
        state
            .cache
            .get(ID)
            .is_none_or(|e| e.state != DatasetState::Visible),
        "the dataset must never become visible"
    );

    // The runtime is still alive after containing the panic: a second scan over an
    // empty inbox completes normally.
    runtime.scan_once().await;
}
