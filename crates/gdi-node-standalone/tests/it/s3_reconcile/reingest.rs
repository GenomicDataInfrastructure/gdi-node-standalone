//! Targeted bucket reingest.
//!
//! `dataset reingest <id>` on a bucket dataset queues a reingest-request marker; the
//! fixture's `test_config` sets no `[service].inbox`, so the CLI always takes that path. The
//! node's marker processing clears the id's recorded `last_seen_signature`, so the S3
//! reconcile's same-ETag short-circuit ("unchanged signature for an absent or errored id:
//! nothing to do") no longer pins it, and the still-present package re-ingests on the next
//! reconcile with the same `ETag`.

use gdi_node_standalone_core::cache::{DatasetProvenance, StatusEntry};
use gdi_node_standalone_core::reingest_request::requests_subdir;

use super::*;

/// End-to-end: an `Error` bucket dataset pinned by an unchanged `ETag` never retries on its
/// own. `dataset reingest <id>` plus the node's marker processing clears the pin, and the same
/// package re-ingests to `Visible` on the next reconcile.
#[tokio::test]
async fn bucket_reingest_marker_defeats_the_same_etag_short_circuit_and_re_ingests() {
    let rig = Rig::standard();
    let id = "GDI-EE-UTARTU-20260409143052901";
    let etag = rig.seed_package(id, Some("visible")).await;

    // A permanent error recorded against this object, from a node-side cause that has since
    // been fixed, such as a catalog added to the node config. Seeded directly, as
    // `operator_flows.rs`'s inbox reingest test does: what is under test is the
    // signature-clear mechanism, not how an `unknown-catalog` error gets recorded. That is
    // `errors.rs`'s `writeback_publishes_error_status_object`.
    {
        let mut status = rig.state.status.lock().unwrap();
        status.insert(
            id.to_owned(),
            StatusEntry {
                state: DatasetState::Error,
                error_message: Some(gdi_node_standalone_core::error::ErrorClass::UnknownCatalog),
                channel: "primary".to_owned(),
                last_seen_signature: Some(etag.clone()),
                provenance: DatasetProvenance::Unknown,
            },
        );
    }

    // Baseline: the same-ETag short-circuit pins it, so a reconcile is a no-op.
    rig.monitor.reconcile().await;
    assert_eq!(
        rig.status_state(id),
        Some(DatasetState::Error),
        "unchanged signature for an errored id must stay pinned"
    );
    assert!(rig.state.cache.get(id).is_none());

    // `dataset reingest <id>`: no inbox is configured in this fixture, so the CLI takes the
    // bucket-marker path unconditionally.
    assert!(rig.state.config.service.inbox.is_none());
    gdi_node_standalone::dataset_cmd::reingest(&rig.state.config, id).unwrap();
    let dir = requests_subdir(&rig.state.config.service.override_dir_resolved());
    assert!(
        dir.join(format!("{id}.json")).is_file(),
        "reingest must queue a marker"
    );

    // The node's marker processing, driven directly: the SIGUSR1 and periodic path.
    rig.state.process_reingest_requests().await;
    assert!(
        dir.join(format!("{id}.json")).exists(),
        "the marker SURVIVES processing: deleting it would consume the request on behalf \
         of every other node reading the same override store"
    );
    assert_eq!(
        rig.state
            .status
            .lock()
            .unwrap()
            .get(id)
            .unwrap()
            .last_seen_signature,
        None,
        "the recorded signature must be cleared"
    );
    // Idempotent: processing again with no marker left must be a safe no-op.
    rig.state.process_reingest_requests().await;

    // The same package, with the same ETag and never re-uploaded, now re-ingests.
    rig.monitor.reconcile().await;
    rig.await_ingest_quiescent().await;
    poll_until(Duration::from_secs(15), || {
        rig.state
            .cache
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;
    assert_eq!(rig.status_state(id), Some(DatasetState::Visible));
}
