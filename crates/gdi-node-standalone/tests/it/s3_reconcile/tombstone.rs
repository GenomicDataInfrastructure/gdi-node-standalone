//! Removal, hide and visible flips, and eviction races: owner-removed packages, the
//! mass-eviction collapse guard, state-flip idempotency, the deleted-tombstone writeback
//! shape, in-flight-versus-removal races, and the stale-sidecar guard against re-disclosing a
//! concurrently hidden dataset.
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use gdi_node_standalone_core::cache::StatusEntry;
use tokio::sync::Notify;

use super::*;

/// Owner Removed: the `.tar.c4gh` is deleted -> cache evicted, status purged
/// (state endpoint would 404), and the dataset dir removed.
#[tokio::test]
async fn removed_package_evicts_and_purges() {
    let rig = Rig::standard();
    let id = "GDI-EE-UTARTU-20260409143052839";
    rig.seed_package(id, Some("visible")).await;

    rig.monitor.reconcile().await;
    poll_until(Duration::from_secs(20), || {
        rig.state
            .cache
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;
    assert!(rig.data_dir.join(id).is_dir());
    // Same in-flight-guard race as `collapsed_listing_does_not_mass_evict`: a still-set
    // guard would exclude this id from `apply_removed`'s owned set and skip the
    // eviction the assertions below require. Drain to quiescence first.
    rig.await_ingest_quiescent().await;

    // Remove the package from the bucket and reconcile.
    rig.store
        .delete(&ObjPath::from(format!("{id}.tar.c4gh")))
        .await
        .unwrap();
    let _ = rig
        .store
        .delete(&ObjPath::from(format!("{id}.state.json")))
        .await;
    rig.monitor.reconcile().await;

    assert!(
        rig.state.cache.get(id).is_none(),
        "cache evicted on removal"
    );
    assert!(rig.status_state(id).is_none(), "status purged on removal");
    assert!(
        !rig.data_dir.join(id).exists(),
        "dataset dir removed on removal"
    );
}

/// Collapse guard: a listing that drops many owned packages at once, as a broken or
/// truncated S3 response does, must not mass-evict served datasets. A single package
/// removal still evicts (see `removed_package_evicts_and_purges`); a majority of `>= 3`
/// vanishing in one poll is treated as a suspect listing and skipped, keeping the data
/// served.
#[tokio::test]
async fn collapsed_listing_does_not_mass_evict() {
    let rig = Rig::standard();
    let ids = [
        "GDI-EE-UTARTU-20260409143052901",
        "GDI-EE-UTARTU-20260409143052902",
        "GDI-EE-UTARTU-20260409143052903",
    ];
    for id in ids {
        rig.seed_package(id, Some("visible")).await;
    }
    rig.monitor.reconcile().await;
    for id in ids {
        poll_until(Duration::from_secs(20), || {
            rig.state
                .cache
                .get(id)
                .is_some_and(|e| e.state == DatasetState::Visible)
        })
        .await;
    }
    // Drain to full quiescence: `Visible` is published one step before the worker
    // clears the in-flight guard, and `apply_removed` excludes in-flight ids from its
    // owned set — so without this wait the collapse reconcile below can race that
    // window, under-count the owned set, and fail to trip the mass-removal guard.
    rig.await_ingest_quiescent().await;

    // A collapsed listing: every package vanishes from the bucket at once.
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

    // The mass eviction is suppressed: all three remain served, their local dirs and
    // status entries intact, rather than wiped on one anomalous poll.
    for id in ids {
        assert!(
            rig.state.cache.get(id).is_some(),
            "collapsed listing must not evict {id}"
        );
        assert!(
            rig.data_dir.join(id).is_dir(),
            "dataset dir for {id} must be retained"
        );
        assert!(
            rig.status_state(id).is_some(),
            "status for {id} must be retained"
        );
    }
}

/// A persistent mass removal, meaning a legitimate bulk unpublish rather than a one-poll
/// glitch, is applied once confirmed across polls rather than wedged forever. The positive
/// counterpart to `collapsed_listing_does_not_mass_evict`: the first collapse reconcile only
/// starts the confirmation, and a second reconcile that still sees the packages gone evicts
/// them.
#[tokio::test]
async fn confirmed_mass_removal_is_eventually_applied() {
    // A one-second poll interval, because the confirmation requires observations separated in
    // time rather than merely counted. A second look at the same instant is the same
    // observation twice, which would let an unauthenticated `POST /reconcile` collapse this
    // window on demand. The test waits out a real separation, and picks an interval that makes
    // one poll a second rather than the shipped thirty.
    let rig = Rig::new(
        Arc::new(InMemory::new()),
        S3Bucket {
            marker_poll_interval: 1,
            ..bucket_cfg("primary", false)
        },
    );
    let ids = [
        "GDI-EE-UTARTU-20260409143052911",
        "GDI-EE-UTARTU-20260409143052912",
        "GDI-EE-UTARTU-20260409143052913",
    ];
    for id in ids {
        rig.seed_package(id, Some("visible")).await;
    }
    rig.monitor.reconcile().await;
    for id in ids {
        poll_until(Duration::from_secs(20), || {
            rig.state
                .cache
                .get(id)
                .is_some_and(|e| e.state == DatasetState::Visible)
        })
        .await;
    }
    rig.await_ingest_quiescent().await;

    // A genuine bulk unpublish: every package removed from the bucket at once.
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

    // First reconcile after the collapse: the removal is only suspected, so it is deferred
    // for cross-poll confirmation rather than applied, and all three remain served.
    rig.monitor.reconcile().await;
    for id in ids {
        assert!(
            rig.state.cache.get(id).is_some(),
            "first collapse pass must only start confirmation, not evict {id}"
        );
    }

    // A back-to-back second pass changes nothing: the confirmation needs a separated
    // observation, so a burst cannot satisfy it. That is what the wait below is for; it is
    // not a sleep to pad the test.
    rig.monitor.reconcile().await;
    for id in ids {
        assert!(
            rig.state.cache.get(id).is_some(),
            "an unseparated second pass must not confirm the removal of {id}"
        );
    }

    // The absence persists into a reconcile a full poll interval later: now confirmed, the
    // datasets are evicted and purged — the bulk unpublish is honoured, not wedged.
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    rig.monitor.reconcile().await;
    for id in ids {
        poll_until(Duration::from_secs(20), || {
            rig.state.cache.get(id).is_none()
        })
        .await;
        assert!(
            !rig.data_dir.join(id).is_dir(),
            "confirmed removal must delete the local dir for {id}"
        );
        assert!(
            rig.status_state(id).is_none(),
            "confirmed removal must purge the status entry for {id}"
        );
    }
}

/// State-changed: a live dataset's sidecar flips visible<->hidden with no
/// re-download (the published files are untouched).
#[tokio::test]
async fn state_change_flips_visibility_without_reingest() {
    let rig = Rig::standard();
    let id = "GDI-EE-UTARTU-20260409143052840";
    rig.seed_package(id, Some("visible")).await;

    rig.monitor.reconcile().await;
    poll_until(Duration::from_secs(20), || {
        rig.state
            .cache
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;
    let mtime_before = std::fs::metadata(rig.data_dir.join(id).join("manifest.json"))
        .unwrap()
        .modified()
        .unwrap();
    // Capture the last_seen_signature right after initial ingest — it must not
    // change across state flips (no re-download, immutable package).
    let sig_before = {
        let status = rig.state.status.lock().unwrap();
        status
            .get(id)
            .and_then(|e| e.last_seen_signature.clone())
            .expect("last_seen_signature recorded after ingest")
    };

    // Flip the sidecar to hidden and reconcile.
    put(
        &rig.store,
        &format!("{id}.state.json"),
        br#"{"state":"hidden"}"#.to_vec(),
    )
    .await;
    rig.monitor.reconcile().await;
    poll_until(Duration::from_secs(5), || {
        rig.state
            .cache
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Hidden)
    })
    .await;
    assert_eq!(rig.status_state(id), Some(DatasetState::Hidden));

    // Flip back to visible.
    put(
        &rig.store,
        &format!("{id}.state.json"),
        br#"{"state":"visible"}"#.to_vec(),
    )
    .await;
    rig.monitor.reconcile().await;
    poll_until(Duration::from_secs(5), || {
        rig.state
            .cache
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;

    // The published manifest was never rewritten, so there was no re-ingest: both the mtime
    // and the last_seen_signature are unchanged.
    let mtime_after = std::fs::metadata(rig.data_dir.join(id).join("manifest.json"))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(
        mtime_before, mtime_after,
        "no re-download/re-store on a state flip"
    );
    let sig_after = {
        let status = rig.state.status.lock().unwrap();
        status
            .get(id)
            .and_then(|e| e.last_seen_signature.clone())
            .expect("last_seen_signature still present")
    };
    assert_eq!(
        sig_before, sig_after,
        "last_seen_signature must be unchanged across visibility flips (no re-download)"
    );
}

/// Tombstone writeback: after a package is removed with `write_status=true`, the
/// published `_status/{id}.json` has `state == "deleted"` and `source_signature`
/// absent.
#[tokio::test]
async fn writeback_deleted_tombstone_shape() {
    let rig = Rig::new(Arc::new(InMemory::new()), bucket_cfg("primary", true));
    let id = "GDI-EE-UTARTU-20260409143052881";
    rig.seed_package(id, Some("visible")).await;

    // First reconcile: ingest + initial status writeback.
    rig.monitor.reconcile().await;
    poll_until(Duration::from_secs(20), || {
        rig.state
            .cache
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;
    // Drain to quiescence before the removal reconcile below: a still-set in-flight
    // guard would exclude this id from `apply_removed`'s owned set and skip the eviction
    // the assertions require (same race as `collapsed_listing`/`removed_package`).
    rig.await_ingest_quiescent().await;
    // Second reconcile writes the terminal visible status.
    rig.monitor.reconcile().await;

    // Now remove the package from the bucket.
    rig.store
        .delete(&ObjPath::from(format!("{id}.tar.c4gh")))
        .await
        .unwrap();
    let _ = rig
        .store
        .delete(&ObjPath::from(format!("{id}.state.json")))
        .await;

    // Reconcile: triggers `apply_removed` + `writeback_deleted`.
    rig.monitor.reconcile().await;

    // The cache + status must be evicted.
    assert!(
        rig.state.cache.get(id).is_none(),
        "cache evicted on removal"
    );
    assert!(rig.status_state(id).is_none(), "status purged on removal");

    // The `_status/{id}.json` tombstone must exist with `state == "deleted"` and no
    // `source_signature`.
    let body = rig
        .store
        .get(&ObjPath::from(format!("_status/{id}.json")))
        .await
        .expect("a deleted tombstone _status object must be written")
        .bytes()
        .await
        .unwrap();
    let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(obj["id"], id);
    assert_eq!(obj["state"], "deleted", "tombstone state must be 'deleted'");
    assert!(
        obj.get("source_signature").is_none() || obj["source_signature"].is_null(),
        "source_signature must be absent from the deleted tombstone"
    );
    assert!(
        obj.get("updated_at").is_some(),
        "updated_at must be present"
    );
}

/// The removal pass must not race an in-flight re-ingest into a delete: `apply_removed`
/// excludes in-flight ids from the owned set, so a package that vanished from the
/// listing while its re-ingest is in flight is left in place. Once the in-flight guard
/// clears, a later reconcile evicts it normally (proving the test is not vacuous).
#[tokio::test]
async fn in_flight_dataset_is_not_evicted_by_a_concurrent_removal() {
    let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    let rig = Rig::new(Arc::clone(&store), bucket_cfg("primary", false));
    let id = "GDI-EE-UTARTU-20260706120000011";
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

    // The package vanishes from the bucket, so the next reconcile lists it as removed.
    let _ = rig
        .store
        .delete(&ObjPath::from(format!("{id}.tar.c4gh")))
        .await;
    let _ = rig
        .store
        .delete(&ObjPath::from(format!("{id}.state.json")))
        .await;

    // Reproduce the live-and-in-flight state: a re-ingest is in flight for this id.
    assert!(
        rig.runtime.test_mark_inflight(id),
        "claimed the in-flight guard"
    );

    // A reconcile that sees the package gone must not evict the in-flight dataset.
    rig.monitor.reconcile().await;
    assert!(
        rig.state.cache.get(id).is_some(),
        "an in-flight dataset must not be evicted by a concurrent removal pass"
    );
    assert!(
        rig.data_dir.join(id).exists(),
        "the in-flight dataset's directory must not be deleted mid-ingest"
    );

    // Once the in-flight guard clears, a later reconcile evicts it normally.
    rig.runtime.test_clear_inflight(id);
    rig.monitor.reconcile().await;
    poll_until(Duration::from_secs(20), || {
        rig.state.cache.get(id).is_none()
    })
    .await;
    assert!(
        !rig.data_dir.join(id).exists(),
        "eviction removes the dataset directory once it is no longer in flight"
    );
}

#[tokio::test]
async fn stale_sidecar_state_does_not_re_disclose_a_concurrently_hidden_dataset() {
    // `apply_state_change` resolves `desired` from an async sidecar GET, then writes it under
    // the status lock. If a concurrent authoritative writer hides the dataset during that GET,
    // applying the stale `desired = visible` would re-disclose it. The compare-and-set
    // precondition, comparing the pre-GET state to the state under the lock, drops the stale
    // flip.
    let armed = Arc::new(AtomicBool::new(false));
    let reached = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    // When armed, the first `*.state.json` GET (the sidecar read inside
    // `apply_state_change`) fires `reached` and parks on `release`, so the test can
    // interleave a concurrent authoritative write at the exact TOCTOU boundary.
    let store = {
        let (armed, reached, release) = (
            Arc::clone(&armed),
            Arc::clone(&reached),
            Arc::clone(&release),
        );
        HookStore::new("GatingGetStore")
            .on_get(move |location| {
                let gate = (location.as_ref().ends_with(".state.json")
                    && armed.swap(false, Ordering::SeqCst))
                .then(|| (Arc::clone(&reached), Arc::clone(&release)));
                Box::pin(async move {
                    if let Some((reached, release)) = gate {
                        reached.notify_one();
                        release.notified().await;
                    }
                    None
                })
            })
            .into_store()
    };
    let rig = Rig::new(store, bucket_cfg("primary", false));
    let id = "GDI-EE-UTARTU-20260409999999999";
    rig.seed_package(id, Some("visible")).await;

    // First reconcile (gate disarmed): the dataset ingests to Visible.
    rig.monitor.reconcile().await;
    rig.await_ingest_quiescent().await;
    assert_eq!(rig.status_state(id), Some(DatasetState::Visible));

    // Arm the gate; the next reconcile parks at the sidecar GET inside apply_state_change,
    // after `before`=Visible is captured and before the CAS re-check.
    armed.store(true, Ordering::SeqCst);
    let monitor = rig.monitor.clone();
    let poller = tokio::spawn(async move { monitor.reconcile().await });

    // Wait until the poller is parked at the sidecar GET.
    reached.notified().await;

    // A concurrent authoritative writer hides the dataset (co-locked cache + status write,
    // as every real mutator does) while the poller holds a now-stale `desired=visible`.
    {
        let mut status = rig.state.status.lock().unwrap();
        let _ = rig.state.cache.set_state(
            gdi_node_standalone_core::cache::StatusWrite::held(&status),
            id,
            DatasetState::Hidden,
        );
        if let Some(e) = status.get(id).cloned() {
            status.insert(
                id.to_owned(),
                StatusEntry {
                    state: DatasetState::Hidden,
                    ..e
                },
            );
        }
    }

    // Resume the poller and let the reconcile finish.
    release.notify_one();
    poller.await.unwrap();

    // The compare-and-set dropped the stale visible flip: the dataset stays `Hidden` in both
    // the cache and the status index — never re-disclosed.
    assert_eq!(
        rig.status_state(id),
        Some(DatasetState::Hidden),
        "a stale sidecar read must not re-disclose a concurrently-hidden dataset"
    );
    std::assert_matches!(
        rig.state.cache.get(id).map(|e| e.state),
        Some(DatasetState::Hidden),
        "cache must also stay Hidden"
    );
}

/// `apply_removed` records a removal for an id this monitor is ingesting whose package has
/// vanished from the listing, meaning it was deleted mid-ingest. The in-flight guard keeps
/// such an id out of the eviction set, so `on_success` needs this signal to publish it
/// `Hidden` rather than `Visible`.
#[tokio::test]
async fn a_package_deleted_while_in_flight_is_recorded_for_hidden_publish() {
    let rig = Rig::standard();
    let id = "GDI-EE-UTARTU-20260409143052701";
    // Reproduce the state a mid-ingest deletion leaves: this monitor enqueued `id` (so it
    // is tracked as ingesting) and `id` is in-flight, but its package is gone from the
    // (empty) bucket.
    rig.monitor.test_mark_ingesting(id);
    assert!(rig.runtime.test_mark_inflight(id));

    rig.monitor.reconcile().await;

    assert!(
        rig.state.take_removal_requested(id),
        "a package deleted while its id is in-flight must be recorded so on_success hides it"
    );
}

/// When a removal was recorded during ingest, `on_success` publishes the finished dataset
/// `Hidden` rather than the sidecar's `Visible`, so a package deleted mid-ingest is never
/// briefly served.
#[tokio::test]
async fn a_package_deleted_during_ingest_publishes_hidden_not_visible() {
    let rig = Rig::standard();
    let id = "GDI-EE-UTARTU-20260409143052702";
    rig.seed_package(id, Some("visible")).await;
    // Simulate the reconcile having observed the deletion while this ingest is in flight.
    rig.state.note_removal_requested(id);

    rig.monitor.reconcile().await;
    poll_until(Duration::from_secs(20), || {
        rig.state.cache.get(id).is_some()
    })
    .await;
    rig.await_ingest_quiescent().await;

    let entry = rig
        .state
        .cache
        .get(id)
        .expect("dataset present after ingest");
    assert_eq!(
        entry.state,
        DatasetState::Hidden,
        "a package deleted during ingest must publish Hidden, not the sidecar's Visible"
    );
}

/// A timer-only reconcile, one where the marker is unchanged, does not evict a dataset whose
/// package is absent. That is a truncated listing rather than an intended delete: a real
/// delete bumps the sync marker and arrives as a marker-triggered reconcile. This protects a
/// small bucket from a single anomalous empty listing while leaving the marker-triggered
/// single-poll eviction intact.
#[tokio::test]
async fn a_marker_unchanged_sweep_does_not_evict_a_vanished_package() {
    let rig = Rig::standard();
    let id = "GDI-EE-UTARTU-20260409143052703";
    rig.seed_package(id, Some("visible")).await;
    rig.monitor.reconcile().await; // process_removals = true
    poll_until(Duration::from_secs(20), || {
        rig.state
            .cache
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;
    rig.await_ingest_quiescent().await;

    // Delete the package, then run a marker-unchanged sweep: the dataset must survive.
    rig.store
        .delete(&ObjPath::from(format!("{id}.tar.c4gh")))
        .await
        .unwrap();
    let _ = rig
        .store
        .delete(&ObjPath::from(format!("{id}.state.json")))
        .await;
    rig.monitor.reconcile_with(false).await;
    assert!(
        rig.state.cache.get(id).is_some(),
        "a marker-unchanged sweep must not evict a vanished package (likely a glitch)"
    );

    // A marker-triggered or explicit reconcile does evict: the legitimate unpublish path.
    rig.monitor.reconcile().await;
    assert!(
        rig.state.cache.get(id).is_none(),
        "an explicit (marker-triggered) reconcile evicts the deleted dataset in one poll"
    );
}

/// A reload that replaces a bucket's monitor, after a credential or region change, hands the
/// outgoing monitor's in-flight set to the successor. An id still ingesting across the swap
/// stays visible to the successor's `apply_removed`, so a package deleted at source mid-ingest
/// is recorded for a `Hidden` publish rather than briefly served `Visible`.
#[tokio::test]
async fn a_reload_swap_carries_the_in_flight_set_so_a_mid_ingest_delete_is_still_recorded() {
    let rig = Rig::standard();
    let id = "GDI-EE-UTARTU-20260409143052702";
    // Monitor A enqueued `id` (tracked as ingesting) and it is in-flight in the shared runtime.
    rig.monitor.test_mark_ingesting(id);
    assert!(rig.runtime.test_mark_inflight(id));

    // The reload builds a fresh replacement over the same bucket and adopts A's in-flight set.
    let mut replacement = BucketMonitor::with_store(
        Arc::clone(&rig.store),
        bucket_cfg("primary", false),
        rig.state.clone(),
        rig.runtime.clone(),
    );
    replacement.adopt_ingesting(rig.monitor.ingesting_handle());

    // The package was deleted at source during the ingest, so the (empty) bucket lists nothing.
    replacement.reconcile().await;

    assert!(
        rig.state.take_removal_requested(id),
        "the successor must see the carried in-flight id and record the mid-ingest deletion"
    );
}

/// The break-test for the carry above: a replacement that starts with a fresh in-flight set
/// never sees the id, so the mid-ingest deletion goes unrecorded and the dataset is
/// published Visible and briefly served.
#[tokio::test]
async fn a_reload_swap_without_the_carry_loses_the_mid_ingest_delete() {
    let rig = Rig::standard();
    let id = "GDI-EE-UTARTU-20260409143052703";
    rig.monitor.test_mark_ingesting(id);
    assert!(rig.runtime.test_mark_inflight(id));

    // No adopt: the replacement's in-flight set is empty.
    let replacement = BucketMonitor::with_store(
        Arc::clone(&rig.store),
        bucket_cfg("primary", false),
        rig.state.clone(),
        rig.runtime.clone(),
    );
    replacement.reconcile().await;

    assert!(
        !rig.state.take_removal_requested(id),
        "without the carry the successor cannot record the deletion — this is what S3 F6 fixes"
    );
}
