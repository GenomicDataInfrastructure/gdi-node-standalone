//! Rejection guards, fail-safe defaults, and injected transient faults: the pre-download size
//! cap, the oversized-sidecar and overlay control-object guards, writeback-denied
//! degradation, the sanitized permanent-error status shape, fail-safe sidecar decoding, the
//! path-injection filter, and dependency outages (a failed list or get, ENOSPC, a slow but
//! progressing download).
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use object_store::ObjectMeta;
use object_store::path::Path as ObjPath;

use gdi_node_standalone_core::faults::{FaultPoint, arm_enospc};
use gdi_node_standalone_core::model::LocalizedText;
use serial_test::serial;

use super::*;

/// An oversize `.tar.c4gh`, an encrypted object larger than `max_package_bytes`, is refused
/// before download. It is recorded as a permanent `unsafe-archive` error keyed to its `ETag`,
/// never ingested into the served cache, and never streamed into `.incoming/`, which is what
/// guards against exhausting the disk.
#[tokio::test]
async fn oversize_package_is_rejected_before_download() {
    // Cap far below the real COVID package (a few KB encrypted), so the listing's
    // size gate trips before any GET.
    let rig = Rig::standard_capped(64);
    let id = "GDI-EE-UTARTU-20260409143052900";
    let etag = rig.seed_package(id, Some("visible")).await;

    rig.monitor.reconcile().await;

    // The reject path records `Error` synchronously within `reconcile` (it never
    // enqueues a worker job), so no polling is needed.
    assert_eq!(rig.status_state(id), Some(DatasetState::Error));
    {
        let status = rig.state.status.lock().unwrap();
        let e = status.get(id).expect("status entry recorded");
        assert_eq!(
            e.error_message,
            Some(gdi_node_standalone_core::error::ErrorClass::UnsafeArchive)
        );
        assert_eq!(e.last_seen_signature.as_deref(), Some(etag.as_str()));
    }

    // Never ingested into the served cache...
    assert!(
        rig.state.cache.get(id).is_none(),
        "oversize package must not be ingested"
    );
    // ...and never written to disk: no `.incoming/` download and no dataset dir. The
    // download path is what creates `.incoming/`, so it must not even exist here.
    let incoming = rig.data_dir.join(".incoming");
    let leaked_download =
        incoming.exists() && std::fs::read_dir(&incoming).is_ok_and(|mut d| d.next().is_some());
    assert!(
        !leaked_download,
        "oversize package must not be downloaded into .incoming/"
    );
    assert!(
        !rig.data_dir.join(id).exists(),
        "no dataset dir for a rejected package"
    );
}

/// An oversized `.state.json`, over the control-object size cap, is rejected by its
/// GET-reported size before the body is buffered, and the dataset defaults to hidden. A
/// multi-gigabyte sidecar therefore cannot exhaust memory. The oversized body here is valid
/// `"visible"` JSON, so dropping the size guard would parse it and wrongly keep the dataset
/// visible.
#[tokio::test]
async fn oversized_state_sidecar_is_rejected_and_defaults_hidden() {
    let rig = Rig::standard();
    let id = "GDI-EE-UTARTU-20260409143052850";
    rig.seed_package(id, Some("visible")).await;

    rig.monitor.reconcile().await;
    poll_until(Duration::from_secs(20), || {
        rig.state
            .cache
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;

    // Overwrite the sidecar with valid `"visible"` JSON padded past the 1 MiB
    // `MAX_CONTROL_OBJECT_BYTES` cap. That constant is `pub(crate)`, so use a clearly
    // oversized 2 MiB. The guard rejects it by GET-reported size before parsing, leaving the
    // dataset hidden; without the guard it parses as "visible" and stays visible.
    let mut oversized = br#"{"state":"visible"}"#.to_vec();
    oversized.resize(2 * 1024 * 1024, b' '); // trailing whitespace stays valid JSON
    put(&rig.store, &format!("{id}.state.json"), oversized).await;

    rig.monitor.reconcile().await;
    poll_until(Duration::from_secs(5), || {
        rig.state
            .cache
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Hidden)
    })
    .await;
    assert_eq!(rig.status_state(id), Some(DatasetState::Hidden));
}

/// Writeback graceful degradation: a store that denies `PutObject` to `_status/*`
/// disables writeback after the first denial; ingest still succeeds and the
/// dataset is still visible.
#[tokio::test]
async fn writeback_denied_disables_but_ingest_succeeds() {
    // Denies PUT (and multipart PUT) to any `_status/*` key with the `AccessDenied`
    // analog — the writeback-grant-revoked scenario.
    let denying = HookStore::new("DenyStatusPut")
        .on_put(|location| {
            location.as_ref().starts_with("_status/").then(|| {
                object_store::Error::PermissionDenied {
                    path: location.to_string(),
                    source: "test: writeback grant revoked".into(),
                }
            })
        })
        .into_store();
    let rig = Rig::new(Arc::clone(&denying), bucket_cfg("primary", true));
    let id = "GDI-EE-UTARTU-20260409143052844";
    rig.seed_package(id, Some("visible")).await;

    rig.monitor.reconcile().await;
    poll_until(Duration::from_secs(20), || {
        rig.state
            .cache
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;
    rig.monitor.reconcile().await;

    assert_eq!(
        rig.state.cache.get(id).unwrap().state,
        DatasetState::Visible,
        "ingest succeeds despite writeback denial"
    );
    assert!(
        rig.monitor.writeback_disabled(),
        "writeback disabled after the first AccessDenied"
    );
    // No _status object exists (every PUT was denied).
    let listed: Vec<_> = futures::stream::TryStreamExt::try_collect::<Vec<_>>(
        rig.store.list(Some(&ObjPath::from("_status"))),
    )
    .await
    .unwrap();
    assert!(listed.is_empty(), "no _status object written under denial");
}

/// The overlay twin of `oversized_state_sidecar_is_rejected_and_defaults_hidden`: an
/// oversized `{id}.metadata.json` overlay is rejected by its GET-reported size before
/// buffering, keeping the last-good metadata, so a multi-gigabyte overlay cannot exhaust
/// memory. The oversized body is a valid overlay that would change the title, so dropping the
/// size guard would parse and apply it.
#[tokio::test]
async fn oversized_metadata_overlay_is_rejected_keeping_last_good() {
    let rig = Rig::standard();
    let id = "GDI-EE-UTARTU-20260409143052856";
    rig.seed_package(id, Some("visible")).await;
    rig.monitor.reconcile().await;
    poll_until(Duration::from_secs(20), || {
        rig.state
            .cache
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;

    // A valid overlay that would change the title, padded past the 1 MiB cap. The guard
    // rejects it by size and keeps the last-good metadata; without the guard it parses and
    // is applied.
    let mut oversized =
        br#"{"title":"OVERSIZED","description":"padded past the control-object cap"}"#.to_vec();
    oversized.resize(2 * 1024 * 1024, b' ');
    put(&rig.store, &format!("{id}.metadata.json"), oversized).await;
    rig.monitor.reconcile().await;

    let entry = rig.state.cache.get(id).unwrap();
    assert_eq!(
        entry.metadata.title,
        LocalizedText::Plain("COVID monogenic AFs".to_owned()),
        "an oversized overlay must be rejected, keeping the baseline title"
    );
}

/// Status writeback on a permanent ingest error: with `write_status = true`, after a
/// package that provokes an unknown-catalog permanent error the bucket has
/// `_status/{id}.json` with `state == "error"`, a non-empty sanitized `error_message`
/// (the closed error class), and no raw path / internal detail in that message.
#[tokio::test]
async fn writeback_publishes_error_status_object() {
    // Build a tar.c4gh whose manifest references a catalog absent from the node config, so
    // ingest terminates with a permanent `unknown-catalog` error.
    let rig = Rig::new(Arc::new(InMemory::new()), bucket_cfg("primary", true));
    let id = "GDI-EE-UTARTU-20260409143052845";

    // Temporarily write the manifest with an unknown catalog into the tar.c4gh.
    let bytes = build_tar_c4gh_bytes_with_catalog(&rig.work, id, &rig.node_pk, "not-configured");
    put(&rig.store, &format!("{id}.tar.c4gh"), bytes).await;
    let _etag = etag_of(&rig.store, &format!("{id}.tar.c4gh")).await;

    // Reconcile: this enqueues the package + writes a `processing` status.
    rig.monitor.reconcile().await;

    // Wait for the status index to record the permanent error.
    poll_until(Duration::from_secs(20), || {
        rig.state
            .status
            .lock()
            .unwrap()
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Error)
    })
    .await;

    // A second reconcile writes the terminal (error) status object to the bucket.
    rig.monitor.reconcile().await;

    let body = rig
        .store
        .get(&ObjPath::from(format!("_status/{id}.json")))
        .await
        .expect("a _status object was written for the errored dataset")
        .bytes()
        .await
        .unwrap();
    let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(obj["id"], id);
    assert_eq!(obj["state"], "error", "state must be 'error'");

    let msg = obj["error_message"]
        .as_str()
        .expect("error_message must be present and a string");
    assert!(!msg.is_empty(), "error_message must be non-empty");
    // The sanitized closed class for an unknown catalog is exactly "unknown-catalog".
    assert_eq!(
        msg, "unknown-catalog",
        "error_message must be the sanitized closed class, not a raw internal detail"
    );
    // Confirm no raw path / internal detail leaked into the message.
    assert!(
        !msg.contains('/'),
        "error_message must not contain a path separator"
    );
    assert!(
        !msg.contains("not-configured"),
        "error_message must not echo raw catalog name"
    );
}

/// Build a `{id}.tar.c4gh` using an explicit catalog name (may differ from CATALOG).
fn build_tar_c4gh_bytes_with_catalog(
    work: &Path,
    id: &str,
    recipient: &PublicKey,
    catalog: &str,
) -> Vec<u8> {
    let staging = work.join(format!("{id}-catalog-variant"));
    std::fs::create_dir_all(&staging).unwrap();
    let vcf = test_util::covid_vcf_path();
    convert_vcf(
        &vcf,
        &staging,
        &ConvertOptions {
            assembly: "GRCh38".to_owned(),
            block_range: 10_000_000,
            min_allele_count: 0,
        },
    )
    .unwrap();
    // Overwrite the manifest with the supplied catalog name.
    let mut manifest = manifest_for(id, "gdi-aggregated", 1);
    catalog.clone_into(&mut manifest.metadata.catalog);
    std::fs::write(
        staging.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let tar_path = work.join(format!("{id}-catalog-variant.tar"));
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

    let tar = std::fs::read(&tar_path).unwrap();
    let mut out = Vec::new();
    let (sender_sk, _sender_pk) = generate_keypair();
    let mut reader = std::io::Cursor::new(tar);
    encrypt(
        &mut reader,
        &mut out,
        std::slice::from_ref(recipient),
        &sender_sk,
    )
    .unwrap();
    out
}

/// `fetch_state` fail-safe: every non-visible `.state.json` shape must default to
/// `Hidden`, never accidentally serving data. The three byte inputs each exercise a
/// distinct decode branch — unparseable JSON (serde error), the `deleted` value that is
/// not an S3-side visibility, and an unrecognised value (enum-None) — so all three are
/// retained as labelled cases.
#[tokio::test]
async fn non_visible_sidecar_shapes_default_to_hidden() {
    let cases: [(&str, &[u8]); 3] = [
        ("invalid JSON", b"not-json-at-all{{{"),
        (
            "`deleted` (not an S3 visibility value)",
            br#"{"state":"deleted"}"#,
        ),
        ("an unrecognised value", br#"{"state":"banana"}"#),
    ];
    for (i, (label, sidecar)) in cases.into_iter().enumerate() {
        let rig = Rig::standard();
        let id = format!("GDI-EE-UTARTU-2026040914305287{i}");
        put(
            &rig.store,
            &format!("{id}.tar.c4gh"),
            build_tar_c4gh_bytes(&rig.work, &id, &rig.node_pk),
        )
        .await;
        put(&rig.store, &format!("{id}.state.json"), sidecar.to_vec()).await;

        rig.monitor.reconcile().await;
        poll_until(Duration::from_secs(20), || {
            rig.state.cache.get(&id).is_some()
        })
        .await;

        let entry = rig.state.cache.get(&id).unwrap();
        assert_eq!(
            entry.state,
            DatasetState::Hidden,
            "sidecar with {label} must default to Hidden (fail-safe)"
        );
    }
}

/// `list()` path-injection guard: an object key whose derived id fails
/// `is_valid_dataset_id`, such as a name containing spaces, produces no cache entry,
/// no `_status`, and no `.incoming` artifact; a valid control package beside it
/// ingests normally.
#[tokio::test]
async fn invalid_id_key_is_filtered_out_valid_control_ingests() {
    let rig = Rig::standard();

    // An invalid key: the id derived from `not a valid id.tar.c4gh` contains spaces
    // and lower-case letters, which `is_valid_dataset_id` rejects.
    let invalid_key = "not a valid id.tar.c4gh";
    put(
        &rig.store,
        invalid_key,
        build_tar_c4gh_bytes(&rig.work, "GDI-EE-UTARTU-20260409143052875", &rig.node_pk),
    )
    .await;

    // A valid control package that should ingest normally.
    let ctrl_id = "GDI-EE-UTARTU-20260409143052876";
    rig.seed_package(ctrl_id, Some("visible")).await;

    rig.monitor.reconcile().await;
    poll_until(Duration::from_secs(20), || {
        rig.state
            .cache
            .get(ctrl_id)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;
    // Drain to quiescence: `on_success` removes the download's `.incoming/` source one
    // step after publishing to the cache, so the `.incoming/`-empty assertion below can
    // race that cleanup if it fires right after `Visible`.
    rig.await_ingest_quiescent().await;

    // The invalid id produced no cache entry.
    assert_eq!(
        rig.state.cache.len(),
        1,
        "only the valid control package must be cached"
    );
    // No .incoming artifact was left behind for the invalid key.
    let incoming = rig.data_dir.join(".incoming");
    if incoming.is_dir() {
        let leftovers: Vec<_> = std::fs::read_dir(&incoming)
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        assert!(
            leftovers.is_empty(),
            "no .incoming artifact must be left for an invalid-id key"
        );
    }
    // The valid control package published its dataset dir.
    assert!(rig.data_dir.join(ctrl_id).join("manifest.json").is_file());
}

/// Overlay keep-last-good: dropping a garbage-JSON `{id}.metadata.json` sidecar
/// on a published dataset leaves the served title unchanged and the dataset is not
/// hidden/quarantined.
#[tokio::test]
async fn s3_metadata_overlay_garbage_json_keeps_last_good() {
    let rig = Rig::standard();
    let id = "GDI-EE-UTARTU-20260409143052880";
    rig.seed_package(id, Some("visible")).await;

    rig.monitor.reconcile().await;
    poll_until(Duration::from_secs(20), || {
        rig.state
            .cache
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;

    // Record the baseline title before the overlay.
    let baseline_title = rig.state.cache.get(id).unwrap().metadata.title.clone();

    // Drop a garbage-JSON overlay (not valid JSON -> should be ignored).
    put(
        &rig.store,
        &format!("{id}.metadata.json"),
        b"{{NOT VALID JSON AT ALL{{{{".to_vec(),
    )
    .await;
    rig.monitor.reconcile().await;

    // The served title must be unchanged (last-good kept).
    let entry = rig.state.cache.get(id).unwrap();
    assert_eq!(
        entry.metadata.title, baseline_title,
        "garbage-JSON overlay must not change the served title (last-good kept)"
    );
    // The dataset must still be visible (not hidden, not quarantined).
    assert_eq!(
        entry.state,
        DatasetState::Visible,
        "a bad overlay must not hide or quarantine the dataset"
    );
    // ...and the operator must be able to see why nothing changed. Keeping last-good is
    // silent by construction: the served record is byte-identical to the one before the
    // overlay landed, so without this the S3 channel could stop reporting the rejection
    // entirely and every assertion above would still pass. `overlay_error` is the only
    // signal that distinguishes "your overlay was rejected" from "your overlay was a
    // no-op", and it is what `GET /datasets/{id}/state` surfaces to the orchestrator.
    assert_eq!(
        rig.state.overlay_error(id).as_deref(),
        Some("parse"),
        "a rejected overlay on the S3 channel must record why, not just keep last-good"
    );
}

// ---------- fault-injecting stores, built on the shared `HookStore` ----------

/// The generic transient error every injected S3 outage in this module reports.
fn injected() -> object_store::Error {
    object_store::Error::Generic {
        store: "FaultStore",
        source: "test: injected transient S3 outage".into(),
    }
}

/// A store whose `list` (the reconcile poll) and `get` (the package download) each fail
/// with a transient error while their toggle is set. The toggles are independent so a
/// test can fail the download while listing still succeeds. `get_attempts` counts
/// package-body GETs, so a test can assert a poll did not re-download.
fn fault_store(
    fail_list: Arc<AtomicBool>,
    fail_get: Arc<AtomicBool>,
    get_attempts: Arc<AtomicUsize>,
) -> Arc<dyn ObjectStore> {
    HookStore::new("FaultStore")
        .on_get(move |location| {
            if location.as_ref().ends_with(".tar.c4gh") {
                get_attempts.fetch_add(1, Ordering::SeqCst);
            }
            let fail = fail_get.load(Ordering::SeqCst);
            Box::pin(async move { fail.then(injected) })
        })
        .on_list(move |_| {
            let fail = fail_list.load(Ordering::SeqCst);
            Box::pin(async move { fail.then(injected) })
        })
        .into_store()
}

/// A bucket that lists more objects than `MAX_BUCKET_OBJECTS` fails the poll closed
/// instead of folding an unbounded, attacker-influenced listing into memory.
///
/// A shared bucket is a co-tenant trust boundary: a provider, or a co-tenant that can write
/// keys, flooding it with objects would otherwise grow the reconcile's working set without
/// limit inside the long-running node process, and take down a node serving every other
/// dataset.
///
/// The cap is `1_000_000`, which no test can reach by storing real objects, so the listing
/// is synthesised lazily. Every synthetic key is under `_status/`, which the fold skips, so
/// the only thing that can end this test is the cap itself.
#[tokio::test]
#[expect(
    clippy::default_trait_access,
    reason = "the field is chrono's DateTime<Utc>, and chrono is not a direct dependency \
              of this crate — naming the type to satisfy the lint would mean adding one \
              for a single test literal that the code under test never reads"
)]
async fn a_flooded_bucket_fails_the_poll_closed() {
    use gdi_node_standalone_core::s3_layout::MAX_BUCKET_OBJECTS;

    let store = HookStore::new("FloodedStore")
        .list_items(|| {
            Box::pin(futures::stream::iter((0..=MAX_BUCKET_OBJECTS).map(|i| {
                Ok(ObjectMeta {
                    location: ObjPath::from(format!("_status/{i}.json")),
                    // The epoch. Every synthetic key is under `_status/`, which the fold
                    // skips before it ever reads this, so the value cannot matter.
                    last_modified: Default::default(),
                    size: 1,
                    e_tag: None,
                    version: None,
                })
            })))
        })
        .into_store();
    let rig = Rig::new(Arc::clone(&store), bucket_cfg("primary", false));

    rig.monitor.reconcile().await;

    assert_eq!(
        rig.state
            .readiness
            .channel_health_snapshot()
            .get("primary")
            .copied(),
        Some(false),
        "a listing past the {MAX_BUCKET_OBJECTS}-object cap must fail the poll closed, \
         leaving the bucket unhealthy rather than reconciling a truncated view"
    );
}

/// A slow but progressing package download is tolerated: the reconcile waits for it and the
/// dataset ingests to visible. The S3 client's connect timeout bounds an unreachable bucket,
/// but a download in progress, such as a large package on a slow link, must be allowed to
/// finish rather than be cut off by an app-level timeout.
#[tokio::test]
async fn a_slow_but_progressing_download_still_ingests() {
    // Every GET sleeps before delegating: a slow-but-progressing download.
    let store = HookStore::new("SlowGetStore")
        .on_get(|_| {
            Box::pin(async {
                tokio::time::sleep(Duration::from_millis(500)).await;
                None
            })
        })
        .into_store();
    let rig = Rig::new(Arc::clone(&store), bucket_cfg("primary", false));
    let id = "GDI-EE-UTARTU-20260706120000010";
    rig.seed_package(id, Some("visible")).await;

    rig.monitor.reconcile().await;
    rig.await_ingest_quiescent().await;
    poll_until(Duration::from_secs(20), || {
        rig.state
            .cache
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;
}

/// A disk-full at the download stage, before ingest begins, is transient: the
/// dataset is neither published nor errored, no partial download leaks into
/// `.incoming`, and the next poll (space freed) downloads and ingests it.
#[tokio::test]
#[serial(faults)]
async fn enospc_during_s3_download_is_transient_then_recovers() {
    let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    let rig = Rig::new(Arc::clone(&store), bucket_cfg("primary", false));
    let id = "GDI-EE-UTARTU-20260706120000012";
    rig.seed_package(id, Some("visible")).await;

    {
        let _fault = arm_enospc(FaultPoint::S3Download, id, 1);
        rig.monitor.reconcile().await;
        assert!(
            rig.state.cache.get(id).is_none(),
            "a failed download must not publish the dataset"
        );
        assert!(
            rig.state.status.lock().unwrap().get(id).is_none(),
            "a transient download failure records no permanent error"
        );
    }
    // The aborted download left no partial file behind (RemoveOnDrop cleanup).
    let leaked =
        std::fs::read_dir(rig.data_dir.join(".incoming")).map_or(0, std::iter::Iterator::count);
    assert_eq!(
        leaked, 0,
        "an aborted download must not leak a partial file"
    );

    // Space freed: the next reconcile downloads and ingests to visible.
    rig.monitor.reconcile().await;
    rig.await_ingest_quiescent().await;
    poll_until(Duration::from_secs(20), || {
        rig.state
            .cache
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;
}

/// A disk-full when persisting the status index mid-reconcile must degrade gracefully:
/// the persist is best-effort, so the node does not crash and the freshly-ingested
/// dataset is still served from memory (its on-disk index just lags until a later
/// successful persist / a rehydrate rebuilds it).
#[tokio::test]
#[serial(faults)]
async fn enospc_on_status_persist_degrades_without_crashing() {
    let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    let rig = Rig::new(Arc::clone(&store), bucket_cfg("primary", false));
    let id = "GDI-EE-UTARTU-20260706120000013";
    rig.seed_package(id, Some("visible")).await;

    // Arm ENOSPC on this data dir's status-index persist only, keyed to its unique
    // path so it cannot fire on a concurrent test's persist).
    let status_path = rig
        .data_dir
        .join(".status.json")
        .to_string_lossy()
        .into_owned();
    {
        let _fault = arm_enospc(FaultPoint::DurableWrite, &status_path, 1);
        rig.monitor.reconcile().await;
        rig.await_ingest_quiescent().await;
    }

    // The persist failed, but best-effort: the node is alive and serves the dataset.
    poll_until(Duration::from_secs(20), || {
        rig.state
            .cache
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;
}

/// A failed S3 list flips that bucket's health to not-ready and ingests nothing. The next
/// good poll restores it and reconciles. This is the degrade-rather-than-crash contract the
/// design relies on.
#[tokio::test]
async fn failed_poll_flips_bucket_health_and_recovers() {
    let fail_list = Arc::new(AtomicBool::new(false));
    let fail_get = Arc::new(AtomicBool::new(false));
    let store = fault_store(
        Arc::clone(&fail_list),
        Arc::clone(&fail_get),
        Arc::new(AtomicUsize::new(0)),
    );
    let rig = Rig::new(Arc::clone(&store), bucket_cfg("primary", false));
    let id = "GDI-EE-UTARTU-20260409143052861";
    rig.seed_package(id, Some("visible")).await;

    // A faulted poll: list fails -> bucket "primary" marked not-ready, reconcile returns.
    fail_list.store(true, Ordering::SeqCst);
    rig.monitor.reconcile().await;
    assert_eq!(
        rig.state
            .readiness
            .channel_health_snapshot()
            .get("primary")
            .copied(),
        Some(false),
        "a failed poll flips the bucket unhealthy"
    );
    assert!(
        rig.state.cache.get(id).is_none(),
        "a failed poll ingests nothing"
    );

    // The next good poll restores readiness and reconciles the dataset to visible.
    fail_list.store(false, Ordering::SeqCst);
    rig.monitor.reconcile().await;
    assert_eq!(
        rig.state
            .readiness
            .channel_health_snapshot()
            .get("primary")
            .copied(),
        Some(true),
        "a good poll restores the bucket healthy"
    );
    poll_until(Duration::from_secs(20), || {
        rig.state
            .cache
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;
}

/// A transient download (`get`) failure leaves the dataset un-ingested, with no permanent
/// error and no quarantine, because the failure returns before any signature is recorded, so
/// the next reconcile re-attempts and ingests it.
#[tokio::test]
async fn transient_download_failure_requeues_then_recovers() {
    let fail_list = Arc::new(AtomicBool::new(false));
    let fail_get = Arc::new(AtomicBool::new(false));
    let store = fault_store(
        Arc::clone(&fail_list),
        Arc::clone(&fail_get),
        Arc::new(AtomicUsize::new(0)),
    );
    let rig = Rig::new(Arc::clone(&store), bucket_cfg("primary", false));
    let id = "GDI-EE-UTARTU-20260409143052860";
    rig.seed_package(id, Some("visible")).await;

    // List succeeds (id discovered) but the package download fails.
    fail_get.store(true, Ordering::SeqCst);
    rig.monitor.reconcile().await;

    // Not ingested, not errored, not quarantined: no cache entry and no status
    // entry (the download failure returns before any signature/status is written).
    assert!(
        rig.state.cache.get(id).is_none(),
        "a failed download must not publish the dataset"
    );
    assert!(
        rig.state.status.lock().unwrap().get(id).is_none(),
        "a transient download failure records no permanent error"
    );

    // Clear the fault: the next reconcile re-attempts and ingests to visible.
    fail_get.store(false, Ordering::SeqCst);
    rig.monitor.reconcile().await;
    poll_until(Duration::from_secs(20), || {
        rig.state
            .cache
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;
    assert!(
        rig.state
            .status
            .lock()
            .unwrap()
            .get(id)
            .unwrap()
            .error_message
            .is_none(),
        "no permanent error after recovery"
    );
}

/// A retraction must survive a transient listing failure.
///
/// The marker is the only thing that authorises removal processing: a timer-only sweep never
/// acts on absence, so a truncated listing cannot erase a bucket. Consuming a new marker
/// unconditionally, including when the reconcile it triggered failed and applied nothing,
/// would drop a provider's deletion permanently. `marker_changed` would not come back, the
/// later full poll would run with removals gated off, and the node would keep serving
/// withdrawn data.
#[tokio::test]
async fn a_failed_reconcile_does_not_consume_the_retraction_marker() {
    let fail_list = Arc::new(AtomicBool::new(false));
    let fail_get = Arc::new(AtomicBool::new(false));
    let store = fault_store(
        Arc::clone(&fail_list),
        Arc::clone(&fail_get),
        Arc::new(AtomicUsize::new(0)),
    );
    let mut bucket = bucket_cfg("primary", false);
    bucket.marker_poll_interval = 1;
    bucket.full_poll_interval = 1;
    let rig = Rig::new(Arc::clone(&store), bucket);

    let id = "GDI-EE-UTARTU-20260409143052862";
    rig.seed_package(id, Some("visible")).await;
    let handle = tokio::spawn(rig.monitor.clone().run());
    poll_until(Duration::from_secs(20), || {
        rig.state
            .cache
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;

    // The provider retracts the package and bumps the marker to announce it, but the
    // endpoint is briefly unavailable, so the marker-driven reconcile fails and applies
    // nothing.
    fail_list.store(true, Ordering::SeqCst);
    store
        .delete(&object_store::path::Path::from(format!("{id}.tar.c4gh")))
        .await
        .expect("delete package");
    put(
        &rig.store,
        "_sync_marker.json",
        br#"{"last_modified":"2026-02-02T00:00:00Z"}"#.to_vec(),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(2500)).await;

    // The endpoint recovers. The retraction must still be applied: the marker announcing
    // it was never successfully processed, so it must not have been consumed.
    fail_list.store(false, Ordering::SeqCst);
    poll_until(Duration::from_secs(20), || {
        rig.state.cache.get(id).is_none()
    })
    .await;
    handle.abort();
}

/// A transient ingest failure must not leak its `.incoming/` download.
///
/// The transient branch retries, and therefore re-downloads, so it has to remove its copy
/// the way `on_permanent_error` does. Otherwise every backed-off retry of a persistently
/// transient failure, such as Vault being down while minting a PME key or a full scratch
/// disk, orphans another full copy of the package on the volume the served datasets live
/// on, until the next restart's `reap_incoming`.
#[tokio::test]
#[serial(faults)]
async fn a_transient_ingest_failure_leaves_no_incoming_download() {
    let rig = Rig::standard();
    let id = "GDI-EE-UTARTU-20260409143052863";
    rig.seed_package(id, Some("visible")).await;

    // ENOSPC at the ingest store is classified transient (`CoreError::is_transient`), so
    // the job backs off and retries rather than erroring permanently.
    {
        let _fault = arm_enospc(FaultPoint::IngestStore, id, 1);
        rig.monitor.reconcile().await;
        rig.await_ingest_quiescent().await;
    }

    assert!(
        rig.state.cache.get(id).is_none(),
        "sanity: a transient failure must not publish the dataset"
    );
    let incoming = rig.data_dir.join(".incoming");
    let leaked: Vec<_> = std::fs::read_dir(&incoming)
        .map(|d| d.filter_map(Result::ok).map(|e| e.file_name()).collect())
        .unwrap_or_default();
    assert!(
        leaked.is_empty(),
        "a transient failure must not orphan its download; found {leaked:?}"
    );
}

/// A persistently failing package download must back off, not re-download on every poll.
///
/// A package that lists fine but always fails to download would otherwise be fetched in full
/// on every poll forever, with no attempt cap and nothing recorded: the transient-failure
/// backoff is recorded for ingest-stage failures, and the check that consults it runs after
/// the download. The download is the expensive half of the work, and the backend is already
/// known to be failing.
#[tokio::test]
#[serial]
async fn a_failing_download_backs_off_instead_of_refetching_every_poll() {
    let fail_list = Arc::new(AtomicBool::new(false));
    let fail_get = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicUsize::new(0));
    let store = fault_store(
        Arc::clone(&fail_list),
        Arc::clone(&fail_get),
        Arc::clone(&attempts),
    );
    let rig = Rig::new(Arc::clone(&store), bucket_cfg("primary", false));
    let id = "GDI-EE-UTARTU-20260409143052864";
    rig.seed_package(id, Some("visible")).await;

    fail_get.store(true, Ordering::SeqCst);
    // The first failure is not penalised, since `backoff_delay(1)` is zero: a blip recovers
    // on the next reconcile. Pacing begins at the second failure.
    rig.monitor.reconcile().await;
    rig.monitor.reconcile().await;
    let after_two = attempts.load(Ordering::SeqCst);
    assert!(after_two >= 2, "sanity: both polls attempted a download");

    // Now the id is inside a real backoff window, so this poll must not spend another
    // full download on a backend already known to be failing.
    rig.monitor.reconcile().await;
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        after_two,
        "a backing-off dataset must not be re-downloaded on every subsequent poll"
    );
}
