//! Fault-injection / chaos scenarios for the ingest write path.
//!
//! These drive the node end-to-end through the inbox runtime with a deterministic
//! fault armed at the ingest atomic-store chokepoint (`core::faults`), covering two
//! classes that are otherwise hard to reproduce:
//!
//! * Disk full (`ENOSPC`) mid-ingest — a resource-exhaustion I/O error is
//!   *transient*: the dataset must not be published or quarantined, its only copy
//!   (the inbox staging) must be left in place, and the next scan (space freed) must
//!   ingest it to `Visible`, exercising the [`is_transient`] classification
//!   end-to-end rather than at the unit level.
//! * Crash (panic) mid-publish — must be contained (never crash the worker),
//!   never leave a half-published dataset visible, and quarantine the artifact.
//!
//! [`is_transient`]: gdi_node_standalone_core::error::CoreError::is_transient
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::time::Duration;

use gdi_node_standalone::identities::NodeIdentities;
use gdi_node_standalone::ingest_runtime::IngestRuntime;
use gdi_node_standalone::state::AppState;
use gdi_node_standalone_core::cache::StatusIndex;
use gdi_node_standalone_core::config::ServiceConfig;
use gdi_node_standalone_core::faults::{FaultPoint, arm_delay, arm_enospc, arm_io, arm_panic};
use gdi_node_standalone_core::state::DatasetState;
use serial_test::serial;

use crate::fixtures::{await_ingest_quiescent, place_covid_staging_into_inbox, poll_until};

const CATALOG: &str = "gdi-aggregated";

/// A full scratch disk mid-ingest is transient: the dataset is neither published nor
/// quarantined and its only copy is left in the inbox, so the next scan (with space
/// freed) ingests it to `Visible`.
#[tokio::test]
#[serial(faults)]
async fn enospc_mid_ingest_is_transient_then_recovers() {
    const ID: &str = "GDI-EE-UTARTU-20260706120000001";
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    for d in [&data_dir, &inbox] {
        std::fs::create_dir_all(d).unwrap();
    }

    let config = crate::fixtures::inbox_config(&data_dir, &inbox, CATALOG);
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
    let runtime = IngestRuntime::start(state.clone());

    place_covid_staging_into_inbox(&inbox, ID, CATALOG);

    // Arm a single simulated ENOSPC at the ingest store point, scoped to this
    // dataset id so it cannot fire on a concurrent sibling test, then scan.
    {
        let _fault = arm_enospc(FaultPoint::IngestStore, ID, 1);
        runtime.scan_once().await;
        await_ingest_quiescent(&runtime).await;

        assert!(
            state
                .cache
                .get(ID)
                .is_none_or(|e| e.state != DatasetState::Visible),
            "a disk-full mid-ingest must not publish the dataset"
        );
        assert!(
            !data_dir.join(ID).exists(),
            "a disk-full mid-ingest must not leave a published dataset dir"
        );
        assert!(
            !inbox.join(".rejected").join(ID).exists(),
            "ENOSPC is transient: the dataset must NOT be quarantined"
        );
        assert!(
            inbox.join(ID).exists(),
            "the source staging (the only copy) must be left in place for retry"
        );
        {
            let status = state.status.lock().unwrap();
            assert!(
                status
                    .get(ID)
                    .is_none_or(|e| e.state != DatasetState::Error),
                "a transient ENOSPC must record no permanent error"
            );
        }
    } // fault disarmed (also auto-cleared after its single fire)

    // Space "freed": the next scan re-ingests the previously-failed dataset to a
    // healthy terminal state (an inbox ingest with no visibility signal settles to
    // `Hidden`) with no error recorded — proving the transient failure recovered.
    runtime.scan_once().await;
    poll_until(Duration::from_secs(20), || {
        state
            .cache
            .get(ID)
            .is_some_and(|e| matches!(e.state, DatasetState::Hidden | DatasetState::Visible))
    })
    .await;
    await_ingest_quiescent(&runtime).await;
    {
        let status = state.status.lock().unwrap();
        let entry = status
            .get(ID)
            .expect("the recovered dataset has a status entry");
        assert_ne!(
            entry.state,
            DatasetState::Error,
            "recovery must not leave the dataset errored"
        );
        assert!(
            entry.error_message.is_none(),
            "no permanent error is recorded after recovery"
        );
    }
}

/// A *permanent* I/O failure mid-ingest (a read-only filesystem, unlike a
/// transient disk-full) must be quarantined, not retried: the complement of the
/// ENOSPC case, so the transient-vs-permanent classification is covered in both
/// directions at the real ingest site.
#[tokio::test]
#[serial(faults)]
async fn permanent_io_error_mid_ingest_is_quarantined() {
    const ID: &str = "GDI-EE-UTARTU-20260706120000004";
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    for d in [&data_dir, &inbox] {
        std::fs::create_dir_all(d).unwrap();
    }

    let config = crate::fixtures::inbox_config(&data_dir, &inbox, CATALOG);
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
    let runtime = IngestRuntime::start(state.clone());
    place_covid_staging_into_inbox(&inbox, ID, CATALOG);

    {
        let _fault = arm_io(
            FaultPoint::IngestStore,
            ID,
            std::io::ErrorKind::ReadOnlyFilesystem,
            1,
        );
        runtime.scan_once().await;
        await_ingest_quiescent(&runtime).await;
    }

    // Permanent: the dataset reaches `error` and is quarantined, rather than left for retry
    // the way a transient ENOSPC is.
    poll_until(Duration::from_secs(15), || {
        state
            .status
            .lock()
            .unwrap()
            .get(ID)
            .is_some_and(|e| e.state == DatasetState::Error)
    })
    .await;
    assert!(
        state
            .cache
            .get(ID)
            .is_none_or(|e| e.state != DatasetState::Visible),
        "a permanent I/O error must not publish the dataset"
    );
    assert!(
        !data_dir.join(ID).exists(),
        "a permanent I/O error leaves nothing published under data_dir/{{id}}"
    );
    assert!(
        inbox.join(".rejected").join(ID).exists(),
        "a permanent I/O error quarantines the artifact (unlike a transient ENOSPC)"
    );
    assert!(
        !inbox.join(ID).exists(),
        "the staging is moved out of the scan path on quarantine"
    );
}

/// A crash (panic) partway through publishing must be contained by the ingest
/// panic boundary: the worker survives, the dataset never becomes visible, nothing
/// is published under `data_dir/{id}`, and the artifact is quarantined.
#[tokio::test]
#[serial(faults)]
async fn crash_mid_publish_is_contained_and_publishes_nothing() {
    const ID: &str = "GDI-EE-UTARTU-20260706120000002";
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    for d in [&data_dir, &inbox] {
        std::fs::create_dir_all(d).unwrap();
    }

    let config = crate::fixtures::inbox_config(&data_dir, &inbox, CATALOG);
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
    let runtime = IngestRuntime::start(state.clone());

    place_covid_staging_into_inbox(&inbox, ID, CATALOG);

    {
        let _fault = arm_panic(FaultPoint::IngestStore, ID, 1);
        // The blocking ingest panics mid-store; the guard must contain it so
        // `scan_once` returns normally rather than crashing the process.
        runtime.scan_once().await;
        await_ingest_quiescent(&runtime).await;
    }

    // A contained panic is permanent: the dataset reaches `error` and is quarantined.
    poll_until(Duration::from_secs(15), || {
        let status = state.status.lock().unwrap();
        status
            .get(ID)
            .is_some_and(|e| e.state == DatasetState::Error)
    })
    .await;
    assert!(
        state
            .cache
            .get(ID)
            .is_none_or(|e| e.state != DatasetState::Visible),
        "a crash mid-publish must never make the dataset visible"
    );
    assert!(
        !data_dir.join(ID).exists(),
        "the atomic rename means a crash mid-publish leaves nothing under data_dir/{{id}}"
    );
    assert!(
        inbox.join(".rejected").join(ID).exists(),
        "a permanent (panic) failure must quarantine the artifact"
    );
    // The runtime is still alive: a second scan over the drained inbox is clean.
    runtime.scan_once().await;
}

/// A crash mid-ingest leaves debris behind — a partial working dir under
/// `.incoming/` and a stray `.status.json.tmp` from an interrupted durable write.
/// A restart must load the (atomically written, therefore intact) status index,
/// ignore the stray `.tmp`, and rehydrate every published dataset from disk,
/// unbothered by the leftover working dir.
#[tokio::test]
async fn restart_after_crash_leftovers_rehydrates_published_datasets() {
    const ID: &str = "GDI-EE-UTARTU-20260706120000003";
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    for d in [&data_dir, &inbox] {
        std::fs::create_dir_all(d).unwrap();
    }

    // First run: ingest a dataset cleanly (publishing `data_dir/{id}/`) and persist
    // the status index, then "shut down" by dropping the runtime + state.
    {
        let config = crate::fixtures::inbox_config(&data_dir, &inbox, CATALOG);
        let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
        let runtime = IngestRuntime::start(state.clone());
        place_covid_staging_into_inbox(&inbox, ID, CATALOG);
        runtime.scan_once().await;
        poll_until(Duration::from_secs(20), || {
            state
                .cache
                .get(ID)
                .is_some_and(|e| matches!(e.state, DatasetState::Hidden | DatasetState::Visible))
        })
        .await;
        await_ingest_quiescent(&runtime).await;
        state
            .status
            .lock()
            .unwrap()
            .store(&data_dir.join(".status.json"))
            .unwrap();
        assert!(
            data_dir.join(ID).exists(),
            "the dataset is published under data_dir/{{id}}"
        );
    }

    // Simulate the on-disk debris a `kill -9` mid-store would leave: a partial
    // working dir under `.incoming/` and a stray, half-written `.status.json.tmp`
    // (the sibling temp of the crash-safe writer, never renamed into place).
    let torn_work = data_dir.join(".incoming").join(format!("{ID}.deadbeef"));
    std::fs::create_dir_all(&torn_work).unwrap();
    std::fs::write(
        torn_work.join("allele-freq.chr1.0.br10000000.partial.parquet"),
        b"PAR1 truncated junk",
    )
    .unwrap();
    std::fs::write(data_dir.join(".status.json.tmp"), b"{ half-written").unwrap();

    // Restart: the intact `.status.json` loads (the stray `.tmp` is ignored), a fresh
    // state hydrates, and the published dataset is recovered despite the debris.
    let status = StatusIndex::load(&data_dir.join(".status.json"))
        .expect("the atomically-written status index loads despite the stray .tmp");
    let config = crate::fixtures::inbox_config(&data_dir, &inbox, CATALOG);
    let state = AppState::new(config, status, NodeIdentities::empty());
    assert!(
        state.cache.get(ID).is_none(),
        "the cache starts empty before hydration"
    );
    let rehydrated = state.hydrate_cache_from_disk();
    assert!(
        rehydrated.loaded >= 1,
        "hydration rebuilt at least the published dataset from disk"
    );
    assert_eq!(
        rehydrated.skipped, 0,
        "and skipped nothing: a skip is a dataset that silently left serving"
    );
    assert!(
        state.cache.get(ID).is_some(),
        "the published dataset is recovered after restart, unbothered by the crash debris"
    );
}

/// A crash in the torn cross-store window, after the atomic publish rename committed the
/// dataset dir but before `on_success` recorded the status, must not wedge the completed
/// dataset into a permanent, unservable `Error`.
///
/// The `PostRename` fault point is the only way to reach this window; the `IngestStore` point
/// fires on the safe side, before the rename. The contained crash records `Error` while a
/// complete, valid dir sits on disk. A hydrate that skipped such a dir would leave the
/// dataset unserved, and any re-ingest would hit the immutability assert, so it could never
/// self-heal. On restart, hydrate recognises the valid manifest as proof the store committed
/// and recovers the dataset as `Hidden`, the fail-safe.
#[tokio::test]
#[serial(faults)]
async fn crash_after_publish_rename_recovers_on_restart() {
    const ID: &str = "GDI-EE-UTARTU-20260706120000010";
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    for d in [&data_dir, &inbox] {
        std::fs::create_dir_all(d).unwrap();
    }

    // First run: ingest with a panic armed in the torn window (immediately after the
    // publish rename). The dir is committed to disk; the crash prevents the success
    // status write, so the contained panic records a (now stale) `Error`.
    {
        let config = crate::fixtures::inbox_config(&data_dir, &inbox, CATALOG);
        let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
        let runtime = IngestRuntime::start(state.clone());
        place_covid_staging_into_inbox(&inbox, ID, CATALOG);

        {
            let _fault = arm_panic(FaultPoint::PostRename, ID, 1);
            runtime.scan_once().await;
            await_ingest_quiescent(&runtime).await;
        }

        poll_until(Duration::from_secs(15), || {
            let status = state.status.lock().unwrap();
            status
                .get(ID)
                .is_some_and(|e| e.state == DatasetState::Error)
        })
        .await;
        assert!(
            data_dir.join(ID).join("manifest.json").exists(),
            "the atomic rename committed a complete dataset dir before the crash"
        );
        // Persist the Error status index for the restart (as on_permanent_error did).
        state
            .status
            .lock()
            .unwrap()
            .store(&data_dir.join(".status.json"))
            .unwrap();
    }

    // Restart: reload the persisted (Error) status and hydrate from disk.
    let status = StatusIndex::load(&data_dir.join(".status.json")).unwrap();
    assert_eq!(
        status.get(ID).map(|e| e.state),
        Some(DatasetState::Error),
        "precondition: the persisted status really is the stale Error (the wedge)"
    );
    let config = crate::fixtures::inbox_config(&data_dir, &inbox, CATALOG);
    let state = AppState::new(config, status, NodeIdentities::empty());
    state.hydrate_cache_from_disk();

    let entry = state
        .cache
        .get(ID)
        .expect("the completed dataset must be recovered on restart, not wedged in Error");
    assert_eq!(
        entry.state,
        DatasetState::Hidden,
        "a crash after publish recovers the served dataset (Hidden), not a permanent Error"
    );
}

/// A crash in the torn erasure window — after a delete purged the status entry but
/// before `remove_dir_all` removed `data_dir/{id}/` — must not leave un-erased data that
/// a restart re-serves. The `PostStatusPurge` fault point reaches that window. A durable
/// `.deleting/{id}` intent marker written before the purge makes the erasure recoverable:
/// the next boot's `reap_deleting` finishes removing the directory.
#[tokio::test]
#[serial(faults)]
async fn crash_after_status_purge_completes_erasure_on_restart() {
    const ID: &str = "GDI-EE-UTARTU-20260706120000011";
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    for d in [&data_dir, &inbox] {
        std::fs::create_dir_all(d).unwrap();
    }

    // First run: ingest to a published dataset, then crash mid-delete.
    {
        let config = crate::fixtures::inbox_config(&data_dir, &inbox, CATALOG);
        let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
        let runtime = IngestRuntime::start(state.clone());

        // No visibility sidecar: the dataset settles to Hidden, which a `deleted`
        // sidecar can remove without `force` (reconcile_deleted refuses a live Visible
        // dataset unless forced).
        place_covid_staging_into_inbox(&inbox, ID, CATALOG);
        runtime.scan_once().await;
        poll_until(Duration::from_secs(20), || data_dir.join(ID).exists()).await;
        await_ingest_quiescent(&runtime).await;

        // Signal a delete, then crash in the torn window (status purged, dir present).
        // delete_dataset runs inline in the reconcile, so a panic there would propagate
        // out of scan_once — isolate it in a spawned task and catch the JoinError.
        std::fs::write(
            inbox.join(format!("{ID}.state.json")),
            br#"{"state":"deleted"}"#,
        )
        .unwrap();
        {
            let _fault = arm_panic(FaultPoint::PostStatusPurge, ID, 1);
            let joined = tokio::spawn(async move { runtime.scan_once().await }).await;
            assert!(
                joined.is_err(),
                "the PostStatusPurge crash must panic the delete task"
            );
        }

        // The wedge: the status entry was purged, but the directory (un-erased data) is
        // still on disk — with a durable intent marker recording the interrupted erasure.
        assert!(
            data_dir.join(ID).exists(),
            "the crash left the dataset dir on disk (the un-erased-data window)"
        );
        {
            let status = state.status.lock().unwrap();
            assert!(
                status.get(ID).is_none(),
                "the delete purged the status entry before the crash"
            );
        }
    }

    // Restart: the boot-time reap completes the interrupted erasure before hydrate, so
    // the purged-but-unremoved dataset is erased and never re-served.
    let reaped = gdi_node_standalone_core::util::reap_deleting(&data_dir, Some(&inbox)).len();
    assert_eq!(reaped, 1, "the interrupted erasure is completed on boot");
    assert!(
        !data_dir.join(ID).exists(),
        "the dataset directory is erased on restart — no un-erased data survives"
    );

    let status = StatusIndex::load(&data_dir.join(".status.json")).unwrap();
    let config = crate::fixtures::inbox_config(&data_dir, &inbox, CATALOG);
    let state = AppState::new(config, status, NodeIdentities::empty());
    state.hydrate_cache_from_disk();
    assert!(
        state.cache.get(ID).is_none(),
        "the erased dataset is never re-served after restart"
    );
}

/// Three-store consistency (cache / `data_dir` / `.status.json`) — a *torn publish*
/// (`data_dir` written, but the status write lost to a crash) must come back Hidden
/// on restart: recovered, never accidentally Visible, never lost. A sibling whose
/// status was recorded Visible is preserved, so the node distinguishes a confirmed
/// publish from an unconfirmed one and never lies about the latter.
#[tokio::test]
async fn torn_publish_recovers_hidden_never_visible() {
    const CONFIRMED: &str = "GDI-EE-UTARTU-20260706120000005";
    const TORN: &str = "GDI-EE-UTARTU-20260706120000006";
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    for d in [&data_dir, &inbox] {
        std::fs::create_dir_all(d).unwrap();
    }

    {
        let config = crate::fixtures::inbox_config(&data_dir, &inbox, CATALOG);
        let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
        let runtime = IngestRuntime::start(state.clone());
        for id in [CONFIRMED, TORN] {
            place_covid_staging_into_inbox(&inbox, id, CATALOG);
        }
        runtime.scan_once().await;
        poll_until(Duration::from_secs(20), || {
            [CONFIRMED, TORN]
                .iter()
                .all(|id| data_dir.join(id).exists())
        })
        .await;
        await_ingest_quiescent(&runtime).await;

        // Rewrite the persisted status index into the two crash states:
        let mut status = state.status.lock().unwrap();
        // CONFIRMED — its status write completed and marked it Visible.
        let mut e = status
            .get(CONFIRMED)
            .expect("confirmed dataset has a status entry")
            .clone();
        e.state = DatasetState::Visible;
        status.insert(CONFIRMED.to_owned(), e);
        // TORN — data_dir was published but the status write never happened.
        status.remove(TORN);
        status.store(&data_dir.join(".status.json")).unwrap();
    }

    // Restart: load the persisted status index and rehydrate from disk.
    let status = StatusIndex::load(&data_dir.join(".status.json")).unwrap();
    let config = crate::fixtures::inbox_config(&data_dir, &inbox, CATALOG);
    let state = AppState::new(config, status, NodeIdentities::empty());
    state.hydrate_cache_from_disk();

    assert_eq!(
        state.cache.get(CONFIRMED).map(|e| e.state),
        Some(DatasetState::Visible),
        "a confirmed publish keeps its recorded visibility across the restart"
    );
    assert_eq!(
        state.cache.get(TORN).map(|e| e.state),
        Some(DatasetState::Hidden),
        "a torn publish (data_dir present, status write lost) recovers HIDDEN — \
         never lost, and never accidentally Visible"
    );
}

/// Three-store consistency, the other direction — a dataset whose `data_dir` vanished
/// (disk loss / operator error) while the status index still references it must be
/// evicted by the authoritative reload, never served as a phantom.
#[tokio::test]
async fn vanished_data_dir_is_evicted_not_served_as_phantom() {
    const ID: &str = "GDI-EE-UTARTU-20260706120000007";
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    for d in [&data_dir, &inbox] {
        std::fs::create_dir_all(d).unwrap();
    }

    let config = crate::fixtures::inbox_config(&data_dir, &inbox, CATALOG);
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
    let runtime = IngestRuntime::start(state.clone());
    place_covid_staging_into_inbox(&inbox, ID, CATALOG);
    runtime.scan_once().await;
    poll_until(Duration::from_secs(20), || {
        state
            .cache
            .get(ID)
            .is_some_and(|e| matches!(e.state, DatasetState::Hidden | DatasetState::Visible))
    })
    .await;
    await_ingest_quiescent(&runtime).await;
    assert!(
        state.cache.get(ID).is_some(),
        "dataset is present after ingest"
    );

    // Its on-disk data vanishes, but the status index still references it.
    std::fs::remove_dir_all(data_dir.join(ID)).unwrap();

    // The authoritative full-reload reconcile must evict the ghost.
    state.hydrate_cache_from_disk();
    assert!(
        state.cache.get(ID).is_none(),
        "a dataset whose data_dir vanished must be evicted, never served as a phantom"
    );
}

/// A detached ingest, one that overran `ingest_timeout_seconds` and was left running on its
/// blocking thread rather than cancelled, is counted in the blocking gauge while it runs and
/// decrements when it finishes, so a run of timeouts cannot leak blocking-pool slots. The
/// `arm_delay` fault forces a deterministic timeout: the store-point guard sleeps well past
/// the 1 s deadline.
#[tokio::test]
#[serial(faults)]
async fn a_detached_timed_out_ingest_is_accounted_then_drains() {
    const ID: &str = "GDI-EE-UTARTU-20260706120000020";
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    for d in [&data_dir, &inbox] {
        std::fs::create_dir_all(d).unwrap();
    }

    // A short ingest deadline; the ingest sleeps 3s at the store point, so it overruns and
    // detaches. (The default test_config's 3600s timeout would never elapse.)
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"
inbox = "{}"
ingest_concurrency = 2
ingest_timeout_seconds = 1
rescan_interval_seconds = 3600

[catalogs]
{CATALOG} = "Genome of Europe Aggregated Data"

[beacon]
id = "org.test.beacon"
name = "Test Beacon"
"#,
        data_dir.display(),
        inbox.display(),
    );
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    cfg.preflight().unwrap();
    let state = AppState::new(cfg, StatusIndex::new(), NodeIdentities::empty());
    let runtime = IngestRuntime::start(state.clone());

    place_covid_staging_into_inbox(&inbox, ID, CATALOG);

    // The store-point guard sleeps 3 s against the 1 s deadline, forcing a detach. (Do not use
    // await_ingest_quiescent here: a detached job keeps its inflight claim, so that helper
    // would time out — poll the blocking gauge directly.)
    {
        let _fault = arm_delay(FaultPoint::IngestStore, ID, Duration::from_secs(3), 1);
        runtime.scan_once().await;

        // After the 1 s timeout the worker is freed but the detached blocking task is still
        // running its 3 s sleep, so it is counted in the blocking gauge.
        poll_until(Duration::from_secs(6), || {
            runtime.inflight_blocking_count() >= 1
        })
        .await;
        assert!(
            runtime.inflight_blocking_count() >= 1,
            "a detached (timed-out) ingest must be accounted in the blocking gauge while it runs"
        );

        // Once the 3s delay elapses the BlockingGuard decrements — the detached slot is
        // reclaimed, not leaked.
        poll_until(Duration::from_secs(10), || {
            runtime.inflight_blocking_count() == 0
        })
        .await;
    }
    assert_eq!(
        runtime.inflight_blocking_count(),
        0,
        "the detached task decremented the blocking gauge on completion — no leaked pool slot"
    );
}

/// The scrub sweep must not resurrect a dataset whose erasure is in flight.
///
/// `erase_dataset` purges the status row under the lock and removes the directory outside the
/// lock; between the two the id is uncached, valid and present on disk — exactly what the
/// sweep's disk-side pass looks for. A half-removed store scrubs `Indeterminate`, and
/// quarantining it synthesises an `error` row (`channel: "unknown"`) for a dataset the
/// operator just took down — unclearable afterwards, since the id is not cached. The
/// `.deleting/{id}` intent marker spans that window precisely and is the guard the sweep
/// has to honour, as the cache projection already does.
#[tokio::test]
#[serial(faults)]
async fn scrub_sweep_skips_a_dataset_whose_erasure_is_in_flight() {
    const ID: &str = "GDI-EE-UTARTU-20260706120000012";
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    for d in [&data_dir, &inbox] {
        std::fs::create_dir_all(d).unwrap();
    }

    let config = crate::fixtures::inbox_config(&data_dir, &inbox, CATALOG);
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
    let runtime = IngestRuntime::start(state.clone());

    // No visibility sidecar: the dataset settles to Hidden, which a `deleted` sidecar can
    // remove without `force`.
    place_covid_staging_into_inbox(&inbox, ID, CATALOG);
    runtime.scan_once().await;
    poll_until(Duration::from_secs(20), || data_dir.join(ID).exists()).await;
    await_ingest_quiescent(&runtime).await;

    // Erase, and stop in the torn window: status purged, marker written, dir present.
    std::fs::write(
        inbox.join(format!("{ID}.state.json")),
        br#"{"state":"deleted"}"#,
    )
    .unwrap();
    {
        let _fault = arm_panic(FaultPoint::PostStatusPurge, ID, 1);
        let joined = tokio::spawn(async move { runtime.scan_once().await }).await;
        assert!(
            joined.is_err(),
            "the PostStatusPurge crash must panic the delete task"
        );
    }
    assert!(
        gdi_node_standalone_core::util::is_deleting(&data_dir, ID),
        "precondition: the intent marker spans the erasure window"
    );
    // Model `remove_dir_all` mid-flight: the data files are already gone, the directory
    // and its manifest are not — the shape that scrubs `Indeterminate`.
    for entry in std::fs::read_dir(data_dir.join(ID)).unwrap().flatten() {
        if entry.path().extension().is_some_and(|x| x == "parquet") {
            std::fs::remove_file(entry.path()).unwrap();
        }
    }

    // The sweep is a timer running off the lock, so it runs concurrently with erasures.
    let failed = gdi_node_standalone::scrub::run_scrub_sweep(
        &state,
        gdi_node_standalone::scrub::ScrubPass::Periodic,
    );

    assert_eq!(
        failed, 0,
        "a dataset whose erasure is in flight is not a scrub failure"
    );
    assert!(
        !state.is_scrub_quarantined(ID),
        "the sweep must not quarantine a dataset the operator is erasing"
    );
    {
        let status = state.status.lock().unwrap();
        assert!(
            status.get(ID).is_none(),
            "no status row may be synthesised for an id whose erasure is in flight — the \
             erase purged it, and a resurrected `error` row would be unclearable"
        );
    }
}
