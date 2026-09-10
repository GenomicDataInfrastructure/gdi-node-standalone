//! Operator-suppression enforcement on the S3 reconcile path: the pre-emptive ingest gate,
//! where a suppressed id is never downloaded or ingested, and the `Remove` erasure that stays
//! applied across a follow-up reconcile even though the source package is still in the bucket.
//! That is the anti-undo coupling between the eviction and the ingest gate. Driven through the
//! same `InMemory`-backed [`Rig`] as the other suites.
//!
//! The lower half of this file covers channel-level suppression: the same pre-emptive gate and
//! `Remove` erasure applied to a whole channel at once through a `channel-{name}.json`
//! override with no per-id file, plus the `BucketMonitor::run` poll-loop pause itself rather
//! than only the `apply_package` gate the id-level tests exercise.
use gdi_node_standalone_core::suppression::{
    SuppressMode, Suppression, remove_channel_file, suppressions_subdir, write_channel_file,
    write_file,
};

use super::*;

/// A suppression authored before the reconcile sees the package: the id is never downloaded,
/// ingested, or given a status entry, because `apply_package`'s gate short-circuits.
#[tokio::test]
async fn preemptive_suppression_blocks_s3_ingest() {
    let rig = Rig::standard();
    let id = "GDI-EE-UTARTU-20260409143052851";
    rig.seed_package(id, Some("visible")).await;

    // Suppress the id, then load it at the SIGUSR1 reload point, before any reconcile.
    let sub = suppressions_subdir(&rig.state.config.service.override_dir_resolved());
    write_file(
        &sub,
        id,
        &Suppression {
            mode: SuppressMode::Remove,
            reason: "pre-emptive".into(),
            at: String::new(),
        },
    )
    .unwrap();
    rig.state.reload_suppressions();

    rig.monitor.reconcile().await;
    rig.await_ingest_quiescent().await;

    assert!(
        rig.state.cache.get(id).is_none(),
        "a pre-emptively-suppressed S3 id must never be ingested/served"
    );
    assert!(
        rig.status_state(id).is_none(),
        "and must never acquire a status entry"
    );
    assert!(
        !rig.data_dir.join(id).exists(),
        "and no dataset dir may be downloaded/materialised"
    );
}

/// The startup reconcile must re-ask operator authority, as every other publish seam does.
///
/// `reconcile_for_readiness` applies each bucket sidecar's fetched visibility to the metadata
/// cache. Without a suppression consult, an owning-channel check and the status lock, an
/// operator `dataset hide` would be lifted on every restart. That verb is used for consent
/// withdrawal and embargo and never touches the bucket, so `{id}.state.json` still reads
/// `visible`. The dataset would be served on the unauthenticated Beacon and FDP planes for a
/// full `rescan_interval_seconds` (600 by default) while the suppression file,
/// `gdi_datasets_suppressed` and `_status/{id}.json` all read "withheld".
///
/// `writeback_does_not_advertise_a_suppressed_dataset_as_visible` is the same test for the
/// neighbouring writeback seam.
#[tokio::test]
async fn startup_reconcile_does_not_re_publish_an_operator_hidden_dataset() {
    let rig = Rig::standard();
    let id = "GDI-EE-UTARTU-20260409143052852";
    rig.seed_package(id, Some("visible")).await;

    // Serve it first, so a restart would find the id already in the cache.
    rig.monitor.reconcile().await;
    rig.await_visible(id).await;

    // The operator hides it. `Hide` is node-local, so the bucket sidecar still says visible,
    // and that is what the startup path must not copy back over the override.
    let sub = suppressions_subdir(&rig.state.config.service.override_dir_resolved());
    write_file(
        &sub,
        id,
        &Suppression {
            mode: SuppressMode::Hide,
            reason: "embargo".to_owned(),
            at: String::new(),
        },
    )
    .unwrap();
    rig.state.reload_suppressions();
    rig.state.enforce_suppressions().await;
    assert_eq!(
        rig.state.cache.get(id).map(|e| e.state),
        Some(DatasetState::Hidden),
        "precondition: the operator hide must be in force before the restart"
    );

    // The path a restart runs.
    rig.monitor.reconcile_for_readiness().await;
    rig.await_ingest_quiescent().await;

    assert_eq!(
        rig.state.cache.get(id).map(|e| e.state),
        Some(DatasetState::Hidden),
        "the startup reconcile must not re-publish an operator-hidden dataset from the \
         bucket sidecar"
    );
}

/// An operator `Remove` suppression erases an already-serving S3 dataset immediately: evict,
/// purge, and `rm data_dir/{id}`. It is independent of the mass-removal cross-poll
/// confirmation, which only defers a vanished listing. The erase stays applied across a
/// subsequent reconcile even though the package is still in the bucket, because the ingest
/// gate prevents the re-ingest undoing it.
#[tokio::test]
async fn operator_remove_erases_and_stays_gone_across_reconcile() {
    let rig = Rig::standard();
    let id = "GDI-EE-UTARTU-20260409143052852";
    rig.seed_package(id, Some("visible")).await;

    rig.monitor.reconcile().await;
    poll_until(Duration::from_secs(20), || {
        rig.state
            .cache
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;
    rig.await_ingest_quiescent().await;
    assert!(
        rig.data_dir.join(id).is_dir(),
        "sanity: the package ingested and materialised on disk"
    );

    // Operator Remove suppression plus the SIGUSR1 erase pathway (reload, then enforce). The
    // erase runs via `AppState::enforce_suppressions` rather than `apply_removed`, so it never
    // enters `plan_removals`' cross-poll mass-removal confirmation and is immediate.
    let sub = suppressions_subdir(&rig.state.config.service.override_dir_resolved());
    write_file(
        &sub,
        id,
        &Suppression {
            mode: SuppressMode::Remove,
            reason: "consent withdrawn".into(),
            at: String::new(),
        },
    )
    .unwrap();
    rig.state.reload_suppressions();
    rig.state.enforce_suppressions().await;

    assert!(
        rig.state.cache.get(id).is_none(),
        "operator Remove evicts the cache immediately (not deferred by the mass-removal guard)"
    );
    assert!(
        rig.status_state(id).is_none(),
        "operator Remove purges the status entry (the state endpoint 404s)"
    );
    assert!(
        !rig.data_dir.join(id).exists(),
        "operator Remove erases data_dir/{{id}}/"
    );

    // The package is still in the bucket. A subsequent reconcile must not re-ingest it: the
    // gate keeps the erase applied. This is the anti-undo coupling.
    rig.monitor.reconcile().await;
    rig.await_ingest_quiescent().await;
    assert!(
        rig.state.cache.get(id).is_none(),
        "the ingest gate prevents the still-present package from re-materialising the erased id"
    );
    assert!(rig.status_state(id).is_none());
    assert!(!rig.data_dir.join(id).exists());
}

// ---------------------------------------------------------------------------
// Channel-level suppression
// ---------------------------------------------------------------------------

/// A channel suppression authored before the reconcile sees the package blocks it
/// pre-emptively, as an id-level one does. Here no id-level file exists, only
/// `channel-primary.json`, so `effective(id, channel)` composes the bare channel-level entry
/// with no id-level counterpart.
#[tokio::test]
async fn preemptive_channel_suppression_blocks_s3_ingest() {
    let rig = Rig::standard();
    let id = "GDI-EE-UTARTU-20260409143052853";
    rig.seed_package(id, Some("visible")).await;

    let sub = suppressions_subdir(&rig.state.config.service.override_dir_resolved());
    write_channel_file(
        &sub,
        "primary",
        &Suppression {
            mode: SuppressMode::Hide,
            reason: "provider compromised".into(),
            at: String::new(),
        },
    )
    .unwrap();
    rig.state.reload_suppressions();

    rig.monitor.reconcile().await;
    rig.await_ingest_quiescent().await;

    assert!(
        rig.state.cache.get(id).is_none(),
        "a channel-suppressed id must never be ingested/served"
    );
    assert!(
        rig.status_state(id).is_none(),
        "and must never acquire a status entry"
    );
    assert!(
        !rig.data_dir.join(id).exists(),
        "and no dataset dir may be downloaded/materialised"
    );
}

/// `channel show` removes `channel-{name}.json` and reloads, resuming ingest on the next
/// reconcile.
#[tokio::test]
async fn channel_show_resumes_s3_ingest() {
    let rig = Rig::standard();
    let id = "GDI-EE-UTARTU-20260409143052854";
    rig.seed_package(id, Some("visible")).await;

    let sub = suppressions_subdir(&rig.state.config.service.override_dir_resolved());
    write_channel_file(
        &sub,
        "primary",
        &Suppression {
            mode: SuppressMode::Hide,
            reason: "provider compromised".into(),
            at: String::new(),
        },
    )
    .unwrap();
    rig.state.reload_suppressions();
    rig.monitor.reconcile().await;
    rig.await_ingest_quiescent().await;
    assert!(
        rig.state.cache.get(id).is_none(),
        "sanity: blocked while the channel is suppressed"
    );

    // `channel show`: remove the override and reload, which is the SIGUSR1 reload point.
    remove_channel_file(&sub, "primary").unwrap();
    rig.state.reload_suppressions();

    rig.monitor.reconcile().await;
    poll_until(Duration::from_secs(15), || {
        rig.state
            .cache
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;
    rig.await_ingest_quiescent().await;
}

/// `channel take-down` evicts every dataset of the channel at once. The store names only the
/// channel, not each member id, so this exercises `effective()`'s channel-only composition
/// finding both already-cached datasets.
#[tokio::test]
async fn channel_take_down_erases_every_dataset_of_the_channel() {
    let rig = Rig::standard();
    let id_a = "GDI-EE-UTARTU-20260409143052855";
    let id_b = "GDI-EE-UTARTU-20260409143052856";
    rig.seed_package(id_a, Some("visible")).await;
    rig.seed_package(id_b, Some("visible")).await;

    rig.monitor.reconcile().await;
    poll_until(Duration::from_secs(20), || {
        rig.state
            .cache
            .get(id_a)
            .is_some_and(|e| e.state == DatasetState::Visible)
            && rig
                .state
                .cache
                .get(id_b)
                .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;
    rig.await_ingest_quiescent().await;
    assert!(rig.data_dir.join(id_a).is_dir(), "sanity: id_a ingested");
    assert!(rig.data_dir.join(id_b).is_dir(), "sanity: id_b ingested");

    let sub = suppressions_subdir(&rig.state.config.service.override_dir_resolved());
    write_channel_file(
        &sub,
        "primary",
        &Suppression {
            mode: SuppressMode::Remove,
            reason: "provider compromised".into(),
            at: String::new(),
        },
    )
    .unwrap();
    rig.state.reload_suppressions();
    rig.state.enforce_suppressions().await;

    for id in [id_a, id_b] {
        assert!(rig.state.cache.get(id).is_none(), "{id} must be evicted");
        assert!(rig.status_state(id).is_none(), "{id} status must be purged");
        assert!(!rig.data_dir.join(id).exists(), "{id} dir must be erased");
    }
}

/// Precedence: a channel `Remove` with an id-level `Hide` on one of its datasets removes that
/// dataset. The most restrictive mode wins, even though the id's own override says `Hide`.
#[tokio::test]
async fn channel_remove_beats_a_more_permissive_id_level_hide() {
    let rig = Rig::standard();
    let id = "GDI-EE-UTARTU-20260409143052857";
    rig.seed_package(id, Some("visible")).await;
    rig.monitor.reconcile().await;
    poll_until(Duration::from_secs(15), || {
        rig.state
            .cache
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;
    rig.await_ingest_quiescent().await;

    let sub = suppressions_subdir(&rig.state.config.service.override_dir_resolved());
    write_file(
        &sub,
        id,
        &Suppression {
            mode: SuppressMode::Hide,
            reason: "id-level".into(),
            at: String::new(),
        },
    )
    .unwrap();
    write_channel_file(
        &sub,
        "primary",
        &Suppression {
            mode: SuppressMode::Remove,
            reason: "channel-level".into(),
            at: String::new(),
        },
    )
    .unwrap();
    rig.state.reload_suppressions();
    rig.state.enforce_suppressions().await;

    assert!(
        rig.state.cache.get(id).is_none(),
        "the most-restrictive mode (channel Remove) must win over the id's own Hide"
    );
    assert!(rig.status_state(id).is_none());
    assert!(!rig.data_dir.join(id).exists());
}

/// The `BucketMonitor::run` poll loop itself pauses while the channel is suppressed, not just
/// the per-id `apply_package` gate the tests above exercise. It never lists or downloads a
/// package seeded while paused, and resumes on the next wake once the suppression is lifted by
/// the `reconcile_trigger` nudge.
#[tokio::test]
async fn run_pauses_polling_while_channel_suppressed_and_resumes_after_lift() {
    let mut bucket = bucket_cfg("primary", false);
    bucket.marker_poll_interval = 1;
    bucket.full_poll_interval = 1;
    let rig = Rig::new(Arc::new(InMemory::new()), bucket);

    // Suppress the channel before the monitor's run() loop starts.
    let sub = suppressions_subdir(&rig.state.config.service.override_dir_resolved());
    write_channel_file(
        &sub,
        "primary",
        &Suppression {
            mode: SuppressMode::Hide,
            reason: "provider compromised".into(),
            at: String::new(),
        },
    )
    .unwrap();
    rig.state.reload_suppressions();

    let handle = tokio::spawn(rig.monitor.clone().run());

    // Seed a package while suppressed and give the paused monitor several 1s poll intervals
    // in which it must not notice it.
    let id = "GDI-EE-UTARTU-20260409143052858";
    rig.seed_package(id, Some("visible")).await;
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert!(
        rig.state.cache.get(id).is_none(),
        "a paused monitor must not ingest a package seeded while the channel is suppressed"
    );
    assert!(
        !rig.data_dir.join(id).exists(),
        "a paused monitor must not even download while suppressed"
    );

    // Lift the suppression and nudge the reconcile trigger, which is the SIGUSR1 path.
    remove_channel_file(&sub, "primary").unwrap();
    rig.state.reload_suppressions();
    rig.state.reconcile_trigger.notify_waiters();

    poll_until(Duration::from_secs(15), || {
        rig.state
            .cache
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;

    handle.abort();
}
