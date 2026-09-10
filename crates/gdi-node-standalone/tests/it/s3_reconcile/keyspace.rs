//! The keyspace-witness removal gate: a restart must not apply the endpoint, bucket or prefix
//! change that a live reload refuses as data-destroying.
//!
//! The witness, `data_dir/.keyspace-{channel}.json`, records the keyspace the channel's
//! datasets were ingested from, and `BucketMonitor::removals_authorized` compares it against
//! the configured keyspace before any Removed pass. These tests drive the same monitor type
//! over the same state through a restart, meaning a second monitor over the same `AppState`
//! and data dir, as boot builds, with a re-pointed bucket config.

use super::*;

/// Re-pointing the channel at an empty keyspace and restarting does not evict.
///
/// One dataset, below `MASS_REMOVAL_FLOOR`, so an ungated pass would evict it immediately at
/// boot with `/health/ready` green throughout. The witness gate refuses the Removed pass, the
/// dataset stays served, and the status entry stays intact.
#[tokio::test]
async fn a_keyspace_repoint_does_not_evict_at_the_next_reconcile() {
    let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    let rig = Rig::new(Arc::clone(&store), bucket_cfg("primary", false));
    let id = "GDI-EE-UTARTU-20260409143052881";
    rig.seed_package(id, Some("visible")).await;

    // First reconcile: witness absent -> adopted from the running config (first
    // observation), dataset ingests and serves.
    rig.monitor.reconcile().await;
    rig.await_visible(id).await;
    assert!(
        rig.data_dir.join(".keyspace-primary.json").is_file(),
        "the first reconcile records the keyspace witness"
    );

    // "Restart" against a re-pointed config: same state, same data dir, but the
    // channel now addresses a different prefix — whose listing is empty (a fresh
    // InMemory), exactly what a mis-pointed keyspace serves.
    let repointed = S3Bucket {
        prefix: "probe-empty-keyspace/".to_owned(),
        ..bucket_cfg("primary", false)
    };
    let empty: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    let rebooted =
        BucketMonitor::with_store(empty, repointed, rig.state.clone(), rig.runtime.clone());
    rebooted.reconcile().await;

    assert!(
        rig.state.cache.get(id).is_some(),
        "the dataset must survive a reconcile against the re-pointed (empty) keyspace"
    );
    assert_eq!(
        rig.status_state(id),
        Some(DatasetState::Visible),
        "and its status entry must be untouched"
    );
}

/// A re-point whose new keyspace holds every owned dataset is a completed migration:
/// adopted automatically, and removals work again — including against the new keyspace.
#[tokio::test]
async fn a_repoint_with_all_data_present_adopts_and_removals_resume() {
    let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    let rig = Rig::new(Arc::clone(&store), bucket_cfg("primary", false));
    let id = "GDI-EE-UTARTU-20260409143052882";
    rig.seed_package(id, Some("visible")).await;
    rig.monitor.reconcile().await;
    rig.await_visible(id).await;

    // The migrated keyspace: a different configured identity, with the bucket name changed,
    // same store contents — every owned id is present in its listing.
    let migrated = S3Bucket {
        bucket: Some("migrated".to_owned()),
        ..bucket_cfg("primary", false)
    };
    let rebooted = BucketMonitor::with_store(
        Arc::clone(&store),
        migrated,
        rig.state.clone(),
        rig.runtime.clone(),
    );
    // Adoption pass: mismatch, nothing missing -> witness rewritten, nothing evicted.
    rebooted.reconcile().await;
    assert!(
        rig.state.cache.get(id).is_some(),
        "adoption must not evict anything (nothing was missing)"
    );

    // The gate is open again: a genuine deletion at the adopted keyspace evicts normally.
    rig.store
        .delete(&ObjPath::from(format!("{id}.tar.c4gh")))
        .await
        .unwrap();
    rebooted.reconcile().await;
    assert!(
        rig.state.cache.get(id).is_none(),
        "a real deletion after adoption must evict — the gate must not wedge removals"
    );
}

/// A real deletion at an unchanged keyspace still evicts — the boot-catches-deletes
/// feature the gate must not break (the witness matches, so the pass is authorized).
#[tokio::test]
async fn a_real_deletion_at_an_unchanged_keyspace_still_evicts() {
    let rig = Rig::standard();
    let id = "GDI-EE-UTARTU-20260409143052883";
    rig.seed_package(id, Some("visible")).await;
    rig.monitor.reconcile().await;
    rig.await_visible(id).await;

    rig.store
        .delete(&ObjPath::from(format!("{id}.tar.c4gh")))
        .await
        .unwrap();
    rig.store
        .delete(&ObjPath::from(format!("{id}.state.json")))
        .await
        .unwrap();
    rig.monitor.reconcile().await;
    assert!(
        rig.state.cache.get(id).is_none(),
        "a legitimate provider deletion must still evict when the keyspace is unchanged"
    );
}

/// An unreadable witness refuses removals (fail closed) — and only removals: the
/// dataset keeps serving, and a deleted witness recovers via the first-observation arm.
#[tokio::test]
async fn an_unreadable_witness_refuses_removals_but_not_serving() {
    let rig = Rig::standard();
    let id = "GDI-EE-UTARTU-20260409143052884";
    rig.seed_package(id, Some("visible")).await;
    rig.monitor.reconcile().await;
    rig.await_visible(id).await;

    // Corrupt the witness, then delete the package: the Removed pass must refuse.
    std::fs::write(rig.data_dir.join(".keyspace-primary.json"), b"not json").unwrap();
    rig.store
        .delete(&ObjPath::from(format!("{id}.tar.c4gh")))
        .await
        .unwrap();
    rig.monitor.reconcile().await;
    assert!(
        rig.state.cache.get(id).is_some(),
        "an unverifiable witness must fail closed: no evictions"
    );

    // Deleting the corrupt witness is the documented recovery: the next pass adopts the
    // running config (first observation) and the pending real deletion applies.
    std::fs::remove_file(rig.data_dir.join(".keyspace-primary.json")).unwrap();
    rig.monitor.reconcile().await;
    assert!(
        rig.state.cache.get(id).is_none(),
        "after recovery the legitimate deletion must apply"
    );
}

/// The gate is consulted before the startup visibility flips. A re-point to a keyspace the
/// gate refuses, because its listing is missing owned datasets, does not promote a dataset on
/// the strength of that keyspace's sidecar. The last-known state is kept, as the last-known
/// data is.
#[tokio::test]
async fn a_refused_gate_keeps_the_last_known_visibility_at_boot() {
    let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    let rig = Rig::new(Arc::clone(&store), bucket_cfg("primary", false));
    let id = "GDI-EE-UTARTU-20260409143052885";
    rig.seed_package(id, Some("hidden")).await;
    rig.monitor.reconcile().await;
    poll_until(Duration::from_secs(20), || {
        rig.state
            .cache
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Hidden)
    })
    .await;
    rig.await_ingest_quiescent().await;

    // "Restart" re-pointed at a keyspace that carries a `visible` sidecar for the id but not
    // its package: a mismatch with something missing, the destructive case the gate refuses.
    // The sidecar is the only thing there.
    let elsewhere: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    put(
        &elsewhere,
        &format!("{id}.state.json"),
        br#"{"state":"visible"}"#.to_vec(),
    )
    .await;
    let repointed = S3Bucket {
        bucket: Some("other".to_owned()),
        ..bucket_cfg("primary", false)
    };
    let rebooted =
        BucketMonitor::with_store(elsewhere, repointed, rig.state.clone(), rig.runtime.clone());
    rebooted.reconcile_for_readiness().await;

    assert_eq!(
        rig.state.cache.get(id).map(|e| e.state),
        Some(DatasetState::Hidden),
        "a keyspace the gate refuses must not flip visibility either — last-known wins"
    );
    assert!(
        rig.state.cache.get(id).is_some(),
        "and the dataset is still held (the gate refused the removal too)"
    );
}

/// The gate reaches the visibility flip of a dataset the refused keyspace does carry.
///
/// The two tests above re-point to a listing with no packages, so `apply_package` never runs
/// under a refused gate. Here the re-pointed keyspace holds one of the channel's two
/// datasets, with a `visible` sidecar for it, and lacks the other. The gate refuses because
/// one is missing, and the present one keeps its last-known `hidden`, on the boot path and on
/// the periodic pass. The control at the end re-points with both present, where the gate
/// adopts and the flip applies, which shows it is the gate holding the flip.
#[tokio::test]
async fn a_refused_gate_does_not_flip_a_dataset_the_new_keyspace_still_carries() {
    let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    let rig = Rig::new(Arc::clone(&store), bucket_cfg("primary", false));
    let carried = "GDI-EE-UTARTU-20260409143052887";
    let missing = "GDI-EE-UTARTU-20260409143052888";
    rig.seed_package(carried, Some("hidden")).await;
    rig.seed_package(missing, Some("visible")).await;
    rig.monitor.reconcile().await;
    poll_until(Duration::from_secs(20), || {
        rig.state
            .cache
            .get(carried)
            .is_some_and(|e| e.state == DatasetState::Hidden)
            && rig.state.cache.get(missing).is_some()
    })
    .await;
    rig.await_visible(missing).await;
    rig.await_ingest_quiescent().await;

    // The re-pointed keyspace: `carried` present (same bytes) with a `visible` sidecar;
    // `missing` absent. Mismatch with something missing — the gate must refuse.
    let partial: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    put(
        &partial,
        &format!("{carried}.tar.c4gh"),
        build_tar_c4gh_bytes(&rig.work, carried, &rig.node_pk),
    )
    .await;
    put(
        &partial,
        &format!("{carried}.state.json"),
        br#"{"state":"visible"}"#.to_vec(),
    )
    .await;
    let repointed = S3Bucket {
        bucket: Some("other".to_owned()),
        ..bucket_cfg("primary", false)
    };
    let rebooted = BucketMonitor::with_store(
        Arc::clone(&partial),
        repointed.clone(),
        rig.state.clone(),
        rig.runtime.clone(),
    );
    rebooted.reconcile_for_readiness().await;
    assert_eq!(
        rig.state.cache.get(carried).map(|e| e.state),
        Some(DatasetState::Hidden),
        "boot: a keyspace the gate refuses must not flip a dataset it still carries"
    );
    // The periodic pass takes the other route into `apply_package`; same rule.
    rebooted.reconcile().await;
    assert_eq!(
        rig.state.cache.get(carried).map(|e| e.state),
        Some(DatasetState::Hidden),
        "periodic: a keyspace the gate refuses must not flip a dataset it still carries"
    );
    assert!(
        rig.state.cache.get(missing).is_some(),
        "and the dataset the new keyspace lacks is still held (removal refused)"
    );

    // Control: with nothing missing the gate adopts the keyspace, and the same sidecar
    // now applies — proving the hold above was the gate's doing.
    put(
        &partial,
        &format!("{missing}.tar.c4gh"),
        build_tar_c4gh_bytes(&rig.work, missing, &rig.node_pk),
    )
    .await;
    let adopting =
        BucketMonitor::with_store(partial, repointed, rig.state.clone(), rig.runtime.clone());
    adopting.reconcile().await;
    poll_until(Duration::from_secs(20), || {
        rig.state
            .cache
            .get(carried)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;
}

/// A witness whose write fails refuses removals rather than authorising them. A
/// first-observation arm that wrote best-effort and returned `true` regardless would, on a
/// read-only or full `data_dir`, be re-entered on every boot and authorise removals
/// unconditionally, including the boot after a re-point, which is the case the gate exists
/// for.
#[tokio::test]
#[serial_test::serial(faults)]
async fn a_witness_that_cannot_be_written_refuses_removals_until_it_can() {
    use gdi_node_standalone_core::faults::{FaultPoint, arm_io};

    let rig = Rig::standard();
    let id = "GDI-EE-UTARTU-20260409143052886";
    rig.seed_package(id, Some("visible")).await;

    // Every attempt to persist the witness fails (a read-only data dir); the dataset still
    // ingests and serves — only the removal gate is at stake.
    let fault = arm_io(
        FaultPoint::DurableWrite,
        ".keyspace-primary",
        std::io::ErrorKind::PermissionDenied,
        8,
    );
    rig.monitor.reconcile().await;
    rig.await_visible(id).await;
    assert!(
        !rig.data_dir.join(".keyspace-primary.json").exists(),
        "precondition: the witness could not be written"
    );

    // A deletion while the witness still cannot be recorded: nothing vouches for this
    // keyspace, so the removal must be refused — the dataset stays held.
    rig.store
        .delete(&ObjPath::from(format!("{id}.tar.c4gh")))
        .await
        .unwrap();
    rig.monitor.reconcile().await;
    assert!(
        rig.state.cache.get(id).is_some(),
        "with no witness on disk (the write keeps failing) removals must be refused"
    );

    // The disk recovers: the witness is recorded and the pending deletion applies.
    drop(fault);
    rig.monitor.reconcile().await;
    assert!(
        rig.data_dir.join(".keyspace-primary.json").is_file(),
        "the witness is written once the write can succeed"
    );
    rig.monitor.reconcile().await;
    assert!(
        rig.state.cache.get(id).is_none(),
        "once the witness vouches for the keyspace the legitimate deletion evicts"
    );
}

/// The gate's refusal is not spelled as the timer-only `process_removals = false`, which
/// `plan_removals` reads as "advance an already-pending confirmation". A suspected mass
/// removal confirmed on the previous pass would otherwise be evicted on a pass the gate
/// refused, which is the mass eviction the gate exists to prevent.
#[tokio::test]
async fn a_pending_mass_removal_does_not_advance_under_a_refusing_gate() {
    let rig = Rig::new(
        Arc::new(InMemory::new()),
        S3Bucket {
            marker_poll_interval: 1,
            ..bucket_cfg("primary", false)
        },
    );
    let ids = [
        "GDI-EE-UTARTU-20260409143052887",
        "GDI-EE-UTARTU-20260409143052888",
        "GDI-EE-UTARTU-20260409143052889",
    ];
    for id in ids {
        rig.seed_package(id, Some("visible")).await;
    }
    rig.monitor.reconcile().await;
    for id in ids {
        rig.await_visible(id).await;
    }
    rig.await_ingest_quiescent().await;

    // A bulk removal: the first pass only starts the confirmation.
    for id in ids {
        rig.store
            .delete(&ObjPath::from(format!("{id}.tar.c4gh")))
            .await
            .unwrap();
        let _ = rig
            .store
            .delete(&ObjPath::from(format!("{id}.state.json")))
            .await;
    }
    rig.monitor.reconcile().await;
    for id in ids {
        assert!(
            rig.state.cache.get(id).is_some(),
            "pass 1 only starts confirmation: {id}"
        );
    }

    // The gate now refuses (an unreadable witness), and a full poll interval passes: the
    // pending confirmation must not advance to eviction under the refusal.
    std::fs::write(rig.data_dir.join(".keyspace-primary.json"), b"not json").unwrap();
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    rig.monitor.reconcile().await;
    for id in ids {
        assert!(
            rig.state.cache.get(id).is_some(),
            "a refusing gate must hold a pending confirmation, not advance it into an eviction: {id}"
        );
        assert!(
            rig.data_dir.join(id).is_dir(),
            "{id}'s store must survive the refused pass"
        );
    }

    // Recovery (delete the corrupt witness: re-adopted on first observation) — the
    // confirmation resumes and the genuine bulk removal is honoured.
    std::fs::remove_file(rig.data_dir.join(".keyspace-primary.json")).unwrap();
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    rig.monitor.reconcile().await;
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    rig.monitor.reconcile().await;
    for id in ids {
        poll_until(Duration::from_secs(20), || {
            rig.state.cache.get(id).is_none()
        })
        .await;
    }
}
