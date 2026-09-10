//! The in-memory metadata cache the Beacon and FDP query paths serve from is re-hydrated
//! from the persisted `datasets/{id}/` directories on restart.
//!
//! Inbox artifacts are consumed on ingest, so if the only `cache.insert` were on a fresh
//! ingest, every already-ingested dataset would vanish from Beacon queries and FDP catalog
//! listings after a restart, while `/health` and `GET /datasets/{id}/state`, served from the
//! persisted status index, went on looking healthy.
//!
//! This test ingests through the real runtime, simulates a restart by building a fresh
//! `AppState` over the same data dir and a reloaded `.status.json`, runs the startup
//! hydration, and asserts the datasets are served again with their visibility preserved.
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::time::Duration;

use gdi_node_standalone::identities::NodeIdentities;
use gdi_node_standalone::ingest_runtime::IngestRuntime;
use gdi_node_standalone::state::AppState;
use gdi_node_standalone_core::cache::StatusIndex;
use gdi_node_standalone_core::state::DatasetState;

use crate::fixtures::{place_covid_staging_into_inbox, poll_until};

#[tokio::test]
async fn datasets_survive_a_restart_via_cache_rehydration() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&inbox).unwrap();

    let visible_id = "GDI-EE-UTARTU-20260409143052837";
    let hidden_id = "GDI-EE-UTARTU-20260409143052838";

    // One dataset published visible (a `{"state":"visible"}` sidecar), one left at
    // the default hidden (no sidecar).
    place_covid_staging_into_inbox(&inbox, visible_id, "gdi-aggregated");
    std::fs::write(
        inbox.join(format!("{visible_id}.state.json")),
        br#"{"state":"visible"}"#,
    )
    .unwrap();
    place_covid_staging_into_inbox(&inbox, hidden_id, "gdi-aggregated");

    // ---- First run: ingest both. ----
    {
        let config = crate::fixtures::inbox_config(&data_dir, &inbox, "gdi-aggregated");
        let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
        let runtime = IngestRuntime::start(state.clone());
        runtime.scan_once().await;

        poll_until(Duration::from_secs(10), || {
            state
                .cache
                .get(visible_id)
                .is_some_and(|e| e.state == DatasetState::Visible)
                && state.cache.get(hidden_id).is_some()
        })
        .await;
        // Drain to quiescence: the inbox staging dirs are consumed one step after the
        // datasets are published, so the consumed assertions below can race the worker.
        crate::fixtures::await_ingest_quiescent(&runtime).await;

        // Both dataset dirs are on disk; the inbox staging dirs were consumed.
        assert!(data_dir.join(visible_id).join("manifest.json").is_file());
        assert!(data_dir.join(hidden_id).join("manifest.json").is_file());
        assert!(!inbox.join(visible_id).exists());
        assert!(!inbox.join(hidden_id).exists());
    }

    // ---- Simulate a restart: nothing in memory survives. Reload the persisted
    // status index from disk and build a fresh AppState over the same data dir,
    // exactly as `main` does on boot. ----
    let config = crate::fixtures::inbox_config(&data_dir, &inbox, "gdi-aggregated");
    let status = StatusIndex::load(&data_dir.join(".status.json")).unwrap();
    let state = AppState::new(config, status, NodeIdentities::empty());

    // The fresh cache starts empty: without hydration the query path would serve nothing.
    assert!(
        state.cache.is_empty(),
        "a fresh AppState's cache is empty before hydration"
    );

    // The startup hydration `main` runs before the inbox scan / S3 reconcile.
    let loaded = state.hydrate_cache_from_disk();

    // Both datasets are back in the served cache, with visibility preserved.
    assert_eq!(
        loaded.loaded, 2,
        "both persisted datasets must be re-hydrated"
    );
    assert_eq!(
        loaded.skipped, 0,
        "and neither was skipped for an unreadable manifest"
    );
    assert_eq!(state.cache.len(), 2);

    let visible = state.cache.visible_datasets();
    assert_eq!(
        visible.len(),
        1,
        "the visible dataset must be served after restart"
    );
    assert_eq!(visible[0].id, visible_id);
    assert_eq!(visible[0].config.assembly.reference, "GRCh38");

    // The hidden dataset is cached (so a sidecar flip to visible would publish it)
    // but not served.
    let hidden = state.cache.get(hidden_id).unwrap();
    assert_eq!(hidden.state, DatasetState::Hidden);
}
