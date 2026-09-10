//! Core reconcile happy paths: new-id ingest, idempotent re-presentation,
//! ignoring unrelated bucket objects, readiness across a restart, and status +
//! metadata-overlay writeback.
use super::*;
use gdi_node_standalone_core::cache::StatusEntry;
use gdi_node_standalone_core::model::LocalizedText;

/// New id with a `visible` sidecar -> ingested + visible, with the right channel
/// + `ETag` recorded, and the local dataset dir published.
#[tokio::test]
async fn new_id_is_ingested_and_visible() {
    let rig = Rig::standard();
    let id = "GDI-EE-UTARTU-20260409143052837";
    let etag = rig.seed_package(id, Some("visible")).await;

    rig.monitor.reconcile().await;
    rig.await_visible(id).await;

    let entry = rig.state.cache.get(id).unwrap();
    assert_eq!(entry.state, DatasetState::Visible);
    assert_eq!(entry.metadata.dataset_id, id);
    assert!(rig.data_dir.join(id).join("manifest.json").is_file());

    let status = rig.state.status.lock().unwrap();
    let e = status.get(id).expect("status entry recorded");
    assert_eq!(e.channel, "primary");
    assert_eq!(e.last_seen_signature.as_deref(), Some(etag.as_str()));
    assert_eq!(e.error_message, None);
}

/// A live id whose `.tar.c4gh` `ETag` changed -> ignored-and-logged (immutable),
/// the served copy is untouched, last-seen `ETag` advances.
#[tokio::test]
async fn live_id_re_presented_with_changed_etag_is_ignored() {
    let rig = Rig::standard();
    let id = "GDI-EE-UTARTU-20260409143052838";
    let etag1 = rig.seed_package(id, Some("visible")).await;

    rig.monitor.reconcile().await;
    rig.await_visible(id).await;

    // Re-upload a fresh package for the same id, giving a new ETag: a re-presentation.
    let bytes = build_tar_c4gh_bytes(&rig.work, id, &rig.node_pk);
    put(&rig.store, &format!("{id}.tar.c4gh"), bytes).await;
    let etag2 = etag_of(&rig.store, &format!("{id}.tar.c4gh")).await;
    assert_ne!(etag1, etag2, "a re-upload yields a new ETag");

    rig.monitor.reconcile().await;

    // Deterministic no-reingest proof: `last_seen_signature` advances to etag2 (the
    // re-presentation is tracked) but the dataset is not re-ingested, verified by
    // the recorded signature equalling etag2 AND the published manifest.json still
    // existing (a re-ingest would rewrite the dataset dir).
    let manifest_mtime = std::fs::metadata(rig.data_dir.join(id).join("manifest.json"))
        .unwrap()
        .modified()
        .unwrap();

    {
        let status = rig.state.status.lock().unwrap();
        let e = status.get(id).unwrap();
        // last-seen ETag advanced to the re-presented one (ignored, but tracked).
        assert_eq!(
            e.last_seen_signature.as_deref(),
            Some(etag2.as_str()),
            "last_seen_signature must advance to the re-presented ETag"
        );
    } // drop status guard before any .await

    let entry = rig.state.cache.get(id).unwrap();
    assert_eq!(
        entry.state,
        DatasetState::Visible,
        "live dataset stays served"
    );

    // A second reconcile must not trigger re-ingest: the mtime is unchanged.
    rig.monitor.reconcile().await;
    let manifest_mtime2 = std::fs::metadata(rig.data_dir.join(id).join("manifest.json"))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(
        manifest_mtime, manifest_mtime2,
        "no re-ingest: manifest.json mtime must not change across two reconciles after re-presentation"
    );
}

/// `_status/*` and unknown per-id objects are ignored by reconcile (no error, no
/// spurious dataset).
#[tokio::test]
async fn status_and_unknown_objects_are_ignored() {
    let rig = Rig::standard();
    let id = "GDI-EE-UTARTU-20260409143052841";
    rig.seed_package(id, Some("visible")).await;
    // A node-style status object + a future per-id sibling + the marker.
    put(
        &rig.store,
        &format!("_status/{id}.json"),
        br#"{"state":"visible"}"#.to_vec(),
    )
    .await;
    put(
        &rig.store,
        &format!("{id}.random.json"),
        br#"{"x":1}"#.to_vec(),
    )
    .await;
    put(
        &rig.store,
        "_sync_marker.json",
        br#"{"last_modified":"2026-01-01T00:00:00Z"}"#.to_vec(),
    )
    .await;

    rig.monitor.reconcile().await;
    rig.await_visible(id).await;

    // Exactly one dataset; the _status/metadata/marker objects spawned nothing.
    assert_eq!(rig.state.cache.len(), 1);
}

/// Readiness: a visible dataset's `.state.json` content is fetched at startup, so
/// it reads `visible` (not the hidden default) once ready — including a restart
/// where the dataset dir already exists.
#[tokio::test]
async fn readiness_fetches_sidecar_content() {
    let rig = Rig::standard();
    let id = "GDI-EE-UTARTU-20260409143052842";
    rig.seed_package(id, Some("visible")).await;

    // First readiness reconcile: ingests + becomes visible.
    rig.monitor.reconcile_for_readiness().await;
    rig.await_visible(id).await;
    assert_eq!(
        rig.state.cache.get(id).unwrap().state,
        DatasetState::Visible
    );

    // Simulate a restart: rebuild the `AppState`, runtime and monitor over the same store and
    // data dir (the dataset dir + status index persist). A bare cache would default
    // hidden; readiness must fetch the sidecar content and read visible.
    let restart = Rig::reopen(&rig);
    restart.monitor.reconcile_for_readiness().await;
    restart.await_visible(id).await;
    assert_eq!(
        restart.state.cache.get(id).unwrap().state,
        DatasetState::Visible,
        "sidecar content read at readiness -> visible, not the hidden default"
    );
}

impl Rig {
    /// Reopen a fresh AppState/runtime/monitor over an existing rig's store +
    /// data dir + identity (a restart). The cache starts empty; the data dir and
    /// status index persist on disk.
    fn reopen(prev: &Rig) -> Rig {
        // Reload the persisted status index from disk.
        let status = StatusIndex::load(&prev.data_dir.join(".status.json")).unwrap();
        // Reconstruct the config (identity path is embedded in prev's config).
        let config = (*prev.state.config).clone();
        // Preload the already-published dataset into the cache (a restart loads
        // datasets/{id}/ from disk; here we seed from prev's cache to mimic that,
        // defaulting to hidden so readiness must flip it via the sidecar fetch).
        let identities = gdi_node_standalone::identities::NodeIdentities::load(&config).unwrap();
        let state = AppState::new(config, status, identities);
        for entry in prev.state.cache.visible_datasets() {
            state.cache.insert(
                gdi_node_standalone_core::cache::StatusWrite::unshared(),
                gdi_node_standalone_core::cache::DatasetEntry {
                    state: DatasetState::Hidden,
                    ..(*entry).clone()
                },
            );
        }
        let runtime = IngestRuntime::start(state.clone());
        let monitor = BucketMonitor::with_store(
            Arc::clone(&prev.store),
            bucket_cfg("primary", false),
            state.clone(),
            runtime.clone(),
        );
        Rig {
            _tmp: tempfile::tempdir().unwrap(),
            work: prev.work.clone(),
            data_dir: prev.data_dir.clone(),
            node_pk: prev.node_pk.clone(),
            store: Arc::clone(&prev.store),
            state,
            monitor,
            runtime,
        }
    }
}

/// Status writeback: with `write_status = true`, after ingest the bucket has
/// `_status/{id}.json` with the right shape + `source_signature == the ETag`.
#[tokio::test]
async fn writeback_publishes_status_object() {
    let rig = Rig::new(Arc::new(InMemory::new()), bucket_cfg("primary", true));
    let id = "GDI-EE-UTARTU-20260409143052843";
    let etag = rig.seed_package(id, Some("visible")).await;

    // First reconcile enqueues + writes a `processing` status; wait for visible.
    rig.monitor.reconcile().await;
    rig.await_visible(id).await;
    // A second reconcile writes the terminal (visible) status object.
    rig.monitor.reconcile().await;

    let body = rig
        .store
        .get(&ObjPath::from(format!("_status/{id}.json")))
        .await
        .expect("a _status object was written")
        .bytes()
        .await
        .unwrap();
    let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(obj["id"], id);
    assert_eq!(obj["state"], "visible");
    assert_eq!(
        obj["source_signature"], etag,
        "source_signature is the tar.c4gh ETag"
    );
    assert!(obj.get("updated_at").is_some());
}

/// A dataset lost from the cache must be re-ingested even though its `ETag` is unchanged.
///
/// `hydrate_from_disk` drops a dataset whose `manifest.json` is unreadable, and runs once per
/// process. On a bucket-only node nothing else brings it back: the reconcile's
/// unchanged-signature early return treats a seen `ETag` as nothing to do, so the dataset
/// stays invisible for the life of the process and of every later one, because the next boot
/// drops it again.
///
/// What makes re-ingesting safe is the distinction between lost (absent from the cache with
/// no recorded error) and known-bad (an error is recorded). A known-bad id is not retried on
/// every poll, which is what the early return is for.
#[tokio::test]
async fn a_dataset_lost_from_the_cache_is_re_ingested_despite_an_unchanged_etag() {
    let rig = Rig::new(Arc::new(InMemory::new()), bucket_cfg("primary", true));
    let id = "GDI-EE-UTARTU-20260409143052845";
    rig.seed_package(id, Some("visible")).await;

    rig.monitor.reconcile().await;
    rig.await_visible(id).await;

    // Simulate the boot-time drop: the dataset leaves the cache, its signature stays
    // recorded, and no error is recorded for it (the manifest was unreadable, not invalid).
    // The returned entry is the evicted one; the point here is the eviction.
    let _evicted = rig
        .state
        .cache
        .remove(gdi_node_standalone_core::cache::StatusWrite::unshared(), id);
    assert!(rig.state.cache.get(id).is_none());

    // The bucket object has not changed, so the unchanged-signature path is taken.
    rig.monitor.reconcile().await;
    poll_until(Duration::from_secs(20), || {
        rig.state.cache.get(id).is_some()
    })
    .await;
    assert!(
        rig.state.cache.get(id).is_some(),
        "a dataset absent from the cache with no recorded error must be recovered, not \
         treated as known"
    );
}

/// An operator `dataset hide` must reach the provider's reverse channel.
///
/// `apply_suppressions_to_cache` touches the cache state only, never the status index, but
/// the status index has a consumer of its own: `writeback_owned` serialises
/// `StatusEntry.state` straight out of the index on every reconcile pass. Without a
/// suppression consult there, a hidden dataset is republished to `_status/{id}.json` as
/// `"state":"visible"`, and the provider polling that oracle is told the node is serving a
/// dataset the operator took down.
///
/// Every other suppression-versus-reconcile seam re-asks: `apply_package` gates
/// `apply_state_change`, and the inbox `on_success` path calls `publishable_state`.
#[tokio::test]
async fn writeback_does_not_advertise_a_suppressed_dataset_as_visible() {
    let rig = Rig::new(Arc::new(InMemory::new()), bucket_cfg("primary", true));
    let id = "GDI-EE-UTARTU-20260409143052844";
    rig.seed_package(id, Some("visible")).await;

    rig.monitor.reconcile().await;
    rig.await_visible(id).await;
    rig.monitor.reconcile().await;

    // The operator takes it down.
    let sub = gdi_node_standalone_core::suppression::suppressions_subdir(
        &rig.state.config.service.override_dir_resolved(),
    );
    gdi_node_standalone_core::suppression::write_file(
        &sub,
        id,
        &gdi_node_standalone_core::suppression::Suppression {
            mode: gdi_node_standalone_core::suppression::SuppressMode::Hide,
            reason: "operator take-down".to_owned(),
            at: String::new(),
        },
    )
    .unwrap();
    rig.state.reload_suppressions();
    rig.monitor.reconcile().await;

    let body = rig
        .store
        .get(&ObjPath::from(format!("_status/{id}.json")))
        .await
        .expect("a _status object was written")
        .bytes()
        .await
        .unwrap();
    let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_ne!(
        obj["state"], "visible",
        "the reverse channel must not advertise a dataset the operator hid: {obj}"
    );
    assert_eq!(obj["state"], "hidden", "{obj}");
}

/// A `{id}.metadata.json` object in the bucket patches the served metadata; deleting
/// it reverts to the baseline title.
///
/// The overlay JSON sets both `title` and `description` so `validate_overlay_result`
/// passes (the baseline manifest produced by `manifest_for` has `description: None`,
/// which is mandatory after merging — the overlay supplies it).
#[tokio::test]
async fn s3_metadata_overlay_applies_and_reverts() {
    let rig = Rig::standard();
    let id = "GDI-EE-UTARTU-20260409143052855";
    rig.seed_package(id, Some("visible")).await;

    // Trigger reconcile so the new package is enqueued for ingest.
    rig.monitor.reconcile().await;
    // Wait for the dataset to become visible (ingest completes in the background).
    rig.await_visible(id).await;

    // Put a metadata overlay; description is required by validate_overlay_result.
    put(
        &rig.store,
        &format!("{id}.metadata.json"),
        br#"{"title":"S3 corrected","description":"A corrected description."}"#.to_vec(),
    )
    .await;
    rig.monitor.reconcile().await;

    let entry = rig.state.cache.get(id).unwrap();
    assert_eq!(
        entry.metadata.title,
        LocalizedText::Plain("S3 corrected".to_owned()),
        "overlay title applied"
    );
    assert!(
        entry.metadata_modified.is_some(),
        "metadata_modified set after overlay applied"
    );
    let applied_modified = entry.metadata_modified.clone();

    // Delete the overlay object and reconcile — should revert to baseline.
    rig.store
        .delete(&ObjPath::from(format!("{id}.metadata.json")))
        .await
        .unwrap();
    rig.monitor.reconcile().await;

    let entry = rig.state.cache.get(id).unwrap();
    assert_eq!(
        entry.metadata.title,
        LocalizedText::Plain("COVID monogenic AFs".to_owned()),
        "reverted to baseline title"
    );
    // `dct:modified` is monotonic: a revert restores the baseline content but does not clear
    // or regress the modified time. The last `applied_at` is retained as a durable high-water
    // mark, so an incremental harvester never skips the revert.
    assert_eq!(
        entry.metadata_modified, applied_modified,
        "revert must retain the modified high-water mark, not clear it"
    );
}

/// A bucket does not revert a durable overlay for an id it does not own.
///
/// The overlay reconcile draws candidate ids from the node-global cache, since `cache.ids()`
/// spans every bucket. Without the ownership gate a non-owning bucket would find a foreign
/// id, see no overlay object in its own listing, and revert the owner's durable overlay on
/// every poll, flapping the published DCAT metadata between overlaid and baseline across a
/// multi-provider fleet.
#[tokio::test]
async fn non_owning_bucket_does_not_revert_a_foreign_overlay() {
    let rig = Rig::standard(); // channel "primary"
    let id = "GDI-EE-UTARTU-20260409143052777";
    rig.seed_package(id, Some("visible")).await;
    rig.monitor.reconcile().await;
    rig.await_visible(id).await;

    // Apply a real overlay so a proper durable overlay file exists on disk.
    put(
        &rig.store,
        &format!("{id}.metadata.json"),
        br#"{"title":"Foreign corrected","description":"An overlaid description."}"#.to_vec(),
    )
    .await;
    rig.monitor.reconcile().await;
    assert_eq!(
        rig.state.cache.get(id).unwrap().metadata.title,
        LocalizedText::Plain("Foreign corrected".to_owned()),
        "overlay applied by the owning bucket"
    );

    // Re-own the id to a different bucket and delete the overlay object, so "primary"'s
    // listing now carries no overlay for a foreign id it still sees in the global cache —
    // the exact revert-thrash trigger.
    {
        let mut status = rig.state.status.lock().unwrap();
        if let Some(e) = status.get(id).cloned() {
            status.insert(
                id.to_owned(),
                StatusEntry {
                    channel: "other-bucket".to_owned(),
                    ..e
                },
            );
        }
    }
    rig.store
        .delete(&ObjPath::from(format!("{id}.metadata.json")))
        .await
        .unwrap();
    rig.monitor.reconcile().await;

    // The foreign overlay must survive — "primary" does not own it, so it must not revert.
    assert_eq!(
        rig.state.cache.get(id).unwrap().metadata.title,
        LocalizedText::Plain("Foreign corrected".to_owned()),
        "a non-owning bucket must not revert a foreign overlay"
    );
    assert!(
        gdi_node_standalone_core::overlay_store::read_durable(&rig.data_dir, id).is_some(),
        "the foreign durable overlay must remain on disk"
    );
}
