//! Integration tests for the inbox `deleted`-tombstone reconcile.
//!
//! Mirrors `inbox_ingest.rs`: builds a real staging dir (converting the COVID
//! reference VCF), drops it into the inbox alongside a `{id}.state.json` sidecar,
//! and drives `IngestRuntime::scan_once` directly. These exercise the `deleted`
//! semantics (re-drop and delete, state control):
//!
//! * a `deleted` sidecar for a currently-visible dataset is refused (still
//!   served, `datasets/{id}/` intact) unless `force:true`;
//! * a `deleted` sidecar for a hidden (or `force:true`) dataset removes
//!   `datasets/{id}/`, evicts the cache, and purges the status index (so the state
//!   404s);
//! * the surviving `deleted` tombstone suppresses re-ingest of a re-dropped
//!   package for the same id until the operator removes the sidecar.
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::path::Path;
use std::time::Duration;

use gdi_node_standalone::identities::NodeIdentities;
use gdi_node_standalone::ingest_runtime::IngestRuntime;
use gdi_node_standalone::state::AppState;
use gdi_node_standalone_core::cache::{DatasetProvenance, StatusEntry, StatusIndex};
use gdi_node_standalone_core::state::DatasetState;

use crate::fixtures::{place_covid_staging_into_inbox, poll_until};

/// Write an `{id}.state.json` sidecar atomically (temp + rename).
fn write_sidecar(inbox: &Path, id: &str, body: &str) {
    let final_path = inbox.join(format!("{id}.state.json"));
    let tmp = inbox.join(format!("{id}.state.json.partial"));
    std::fs::write(&tmp, body.as_bytes()).unwrap();
    std::fs::rename(&tmp, &final_path).unwrap();
}

/// Drain `runtime` to quiescence: poll `test_inflight_count() == 0` with a
/// bounded budget (up to ~500 ms at 5 ms intervals). Panics with a clear message
/// if the runtime does not drain within the budget, so a real hang still fails
/// fast rather than hanging the suite indefinitely.
async fn drain(runtime: &IngestRuntime) {
    for _ in 0..100 {
        if runtime.test_inflight_count() == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!(
        "IngestRuntime did not drain to quiescence within ~500 ms \
         (inflight count at deadline: {})",
        runtime.test_inflight_count()
    );
}

/// Deploy a local dataset and drive it to the given served state, returning the
/// `(AppState, IngestRuntime)` so the caller can keep reconciling.
async fn ingest_visible(data_dir: &Path, inbox: &Path, id: &str) -> (AppState, IngestRuntime) {
    place_covid_staging_into_inbox(inbox, id, "gdi-aggregated");
    write_sidecar(inbox, id, r#"{"state":"visible"}"#);

    let config = crate::fixtures::inbox_config(data_dir, inbox, "gdi-aggregated");
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
    let runtime = IngestRuntime::start(state.clone());
    runtime.scan_once().await;
    poll_until(Duration::from_secs(10), || {
        state
            .cache
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;
    crate::fixtures::await_ingest_quiescent(&runtime).await;
    (state, runtime)
}

/// A `deleted` sidecar for a currently-visible dataset is refused: the
/// dataset stays served and `datasets/{id}/` is intact (no `force`).
#[tokio::test]
async fn deleted_on_visible_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&inbox).unwrap();

    let id = "GDI-EE-UTARTU-20260409143052837";
    let (state, runtime) = ingest_visible(&data_dir, &inbox, id).await;

    // Flip the sidecar to deleted (no force) and reconcile.
    write_sidecar(&inbox, id, r#"{"state":"deleted"}"#);
    runtime.scan_once().await;

    // Drain to quiescence: the delete is a no-op (refused) but we must let the
    // reconcile path settle before asserting "nothing was removed".
    drain(&runtime).await;

    assert!(
        state
            .cache
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Visible),
        "a visible dataset must NOT be deleted without force"
    );
    assert!(
        data_dir.join(id).join("manifest.json").is_file(),
        "datasets/{{id}}/ must remain intact when delete is refused"
    );
    {
        let status = state.status.lock().unwrap();
        assert!(
            status.get(id).is_some(),
            "the status entry must remain when delete is refused"
        );
    }
}

/// Unpublish first (hidden), then `{"state":"deleted"}` removes `datasets/{id}/`,
/// evicts the cache, and purges the status index (so the state would 404).
#[tokio::test]
async fn deleted_on_hidden_removes_evicts_purges() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&inbox).unwrap();

    let id = "GDI-EE-UTARTU-20260409143052838";
    let (state, runtime) = ingest_visible(&data_dir, &inbox, id).await;

    // Unpublish (hidden) first.
    write_sidecar(&inbox, id, r#"{"state":"hidden"}"#);
    runtime.scan_once().await;
    poll_until(Duration::from_secs(5), || {
        state
            .cache
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Hidden)
    })
    .await;

    // Now delete.
    write_sidecar(&inbox, id, r#"{"state":"deleted"}"#);
    runtime.scan_once().await;

    poll_until(Duration::from_secs(5), || state.cache.get(id).is_none()).await;

    assert!(
        state.cache.get(id).is_none(),
        "the cache entry must be evicted on delete"
    );
    assert!(
        !data_dir.join(id).exists(),
        "datasets/{{id}}/ must be removed on delete"
    );
    {
        let status = state.status.lock().unwrap();
        assert!(
            status.get(id).is_none(),
            "the status entry must be purged on delete (so the state endpoint 404s)"
        );
    }
    // The deleted tombstone persists in the inbox.
    assert!(
        inbox.join(format!("{id}.state.json")).exists(),
        "the deleted sidecar must persist as a tombstone"
    );
}

/// A visible dataset + `{"state":"deleted","force":true}` is removed in one step.
#[tokio::test]
async fn deleted_force_on_visible_removes() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&inbox).unwrap();

    let id = "GDI-EE-UTARTU-20260409143052839";
    let (state, runtime) = ingest_visible(&data_dir, &inbox, id).await;

    write_sidecar(&inbox, id, r#"{"state":"deleted","force":true}"#);
    runtime.scan_once().await;

    poll_until(Duration::from_secs(5), || state.cache.get(id).is_none()).await;

    assert!(
        state.cache.get(id).is_none(),
        "force-delete must evict a visible dataset"
    );
    assert!(
        !data_dir.join(id).exists(),
        "force-delete must remove datasets/{{id}}/ even when visible"
    );
    {
        let status = state.status.lock().unwrap();
        assert!(
            status.get(id).is_none(),
            "force-delete must purge the status"
        );
    }
}

/// Tombstone suppression: after a delete, re-dropping the same id's package while
/// the `deleted` sidecar remains is not re-ingested and stays a 404; removing the
/// sidecar then re-dropping ingests fresh.
#[tokio::test]
async fn deleted_tombstone_suppresses_reingest_until_sidecar_removed() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&inbox).unwrap();

    let id = "GDI-EE-UTARTU-20260409143052840";
    let (state, runtime) = ingest_visible(&data_dir, &inbox, id).await;

    // Force-delete in one step.
    write_sidecar(&inbox, id, r#"{"state":"deleted","force":true}"#);
    runtime.scan_once().await;
    poll_until(Duration::from_secs(5), || state.cache.get(id).is_none()).await;

    // Re-drop the package while the deleted tombstone remains: must be suppressed.
    place_covid_staging_into_inbox(&inbox, id, "gdi-aggregated");
    runtime.scan_once().await;
    // Drain to quiescence: the suppressed re-drop must not enqueue any work, so
    // inflight count is zero immediately, but we poll to be certain before the
    // negative assertion ("id must stay absent").
    drain(&runtime).await;
    assert!(
        state.cache.get(id).is_none(),
        "a re-dropped package must be suppressed while the deleted tombstone remains"
    );
    {
        let status = state.status.lock().unwrap();
        assert!(
            status.get(id).is_none(),
            "the tombstoned id must not reappear in the status index"
        );
    }
    // The re-dropped staging dir was left in place (not consumed, not quarantined).
    assert!(
        inbox.join(id).exists(),
        "the suppressed re-drop must be left in the inbox (not consumed)"
    );

    // Remove the tombstone; the re-dropped package now ingests fresh.
    std::fs::remove_file(inbox.join(format!("{id}.state.json"))).unwrap();
    runtime.scan_once().await;
    poll_until(Duration::from_secs(10), || {
        state
            .cache
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Hidden)
    })
    .await;
    assert!(
        data_dir.join(id).join("manifest.json").is_file(),
        "removing the tombstone releases the id for fresh ingest"
    );
}

/// A `deleted` sidecar whose id is bucket-owned (channel != inbox in the
/// status index) is ignored-and-logged: nothing is removed.
#[tokio::test]
async fn deleted_on_bucket_owned_id_is_ignored() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&inbox).unwrap();

    let id = "GDI-EE-UTARTU-20260409143052841";
    // Seed a status index claiming this id is owned by an S3 bucket "primary",
    // and put a dataset dir on disk that the inbox sidecar must not remove.
    let mut status = StatusIndex::new();
    status.insert(
        id.to_owned(),
        StatusEntry {
            state: DatasetState::Hidden,
            error_message: None,
            channel: "primary".to_owned(),
            last_seen_signature: Some("\"etag\"".to_owned()),
            provenance: DatasetProvenance::Unknown,
        },
    );
    std::fs::create_dir_all(data_dir.join(id)).unwrap();
    std::fs::write(data_dir.join(id).join("manifest.json"), b"{}").unwrap();

    // Drop a deleted sidecar in the inbox targeting the bucket-owned id.
    write_sidecar(&inbox, id, r#"{"state":"deleted"}"#);

    let config = crate::fixtures::inbox_config(&data_dir, &inbox, "gdi-aggregated");
    let state = AppState::new(config, status, NodeIdentities::empty());
    let runtime = IngestRuntime::start(state.clone());
    runtime.scan_once().await;
    // Drain to quiescence: the bucket-owned id is ignored (no work enqueued);
    // poll the seam to confirm before the negative assertion.
    drain(&runtime).await;

    // The bucket-owned dataset dir + status entry are untouched.
    assert!(
        data_dir.join(id).join("manifest.json").is_file(),
        "a bucket-owned id's dir must not be removed by an inbox deleted sidecar"
    );
    {
        let status = state.status.lock().unwrap();
        let e = status
            .get(id)
            .expect("bucket-owned status entry must survive");
        assert_eq!(e.channel, "primary");
    }
}

/// A visibility sidecar whose id is bucket-owned is ignored just as a `deleted` one is.
/// Neither path may act on another channel's id, since the bucket is where that id's state
/// is declared. Guarding only the destructive path would leave the disclosing one open: an
/// inbox `{id}.state.json` could flip a bucket-owned dataset the provider set hidden back to
/// visible.
#[tokio::test]
async fn visibility_sidecar_on_bucket_owned_id_is_ignored() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&inbox).unwrap();

    let id = "GDI-EE-UTARTU-20260409143052842";
    let mut status = StatusIndex::new();
    status.insert(
        id.to_owned(),
        StatusEntry {
            state: DatasetState::Hidden,
            error_message: None,
            channel: "primary".to_owned(),
            last_seen_signature: Some("\"etag\"".to_owned()),
            provenance: DatasetProvenance::Unknown,
        },
    );
    std::fs::create_dir_all(data_dir.join(id)).unwrap();
    std::fs::write(data_dir.join(id).join("manifest.json"), b"{}").unwrap();

    let config = crate::fixtures::inbox_config(&data_dir, &inbox, "gdi-aggregated");
    let state = AppState::new(config, status, NodeIdentities::empty());
    // The dataset is cached hidden, exactly as the bucket declared it.
    state.cache.insert(
        gdi_node_standalone_core::cache::StatusWrite::unshared(),
        gdi_node_standalone_core::cache::DatasetEntry {
            id: id.to_owned(),
            metadata: crate::fixtures::sample_metadata(id),
            config: crate::fixtures::manifest_for(id, "gdi-aggregated", 1).config,
            state: DatasetState::Hidden,
            metadata_modified: None,
        },
    );

    // An inbox sidecar tries to publish another channel's dataset.
    write_sidecar(&inbox, id, r#"{"state":"visible"}"#);

    let runtime = IngestRuntime::start(state.clone());
    runtime.scan_once().await;
    drain(&runtime).await;

    assert_eq!(
        state.cache.get(id).map(|e| e.state),
        Some(DatasetState::Hidden),
        "an inbox sidecar must not disclose a bucket-owned dataset"
    );
}

/// A tombstone that cannot be read must still tombstone.
///
/// `{id}.state.json` reading `deleted` is the GDPR erasure record and the only thing
/// suppressing re-ingest of a package still sitting in the inbox. Truncate it — a crash
/// mid-write, a full disk, an interrupted `scp` — and the rule has to be the one every
/// other unreadable sidecar already gets: withhold, never release. Releasing it would
/// answer `404` ("never ingested") for an erased id and ingest a re-dropped package for it.
#[tokio::test]
async fn an_unreadable_tombstone_still_tombstones() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt as _;

    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&inbox).unwrap();

    let id = "GDI-EE-UTARTU-20260409143052845";
    let (state, runtime) = ingest_visible(&data_dir, &inbox, id).await;

    // Erase it, and let the erase settle.
    write_sidecar(&inbox, id, r#"{"state":"deleted","force":true}"#);
    runtime.scan_once().await;
    poll_until(Duration::from_secs(5), || state.cache.get(id).is_none()).await;
    crate::fixtures::await_ingest_quiescent(&runtime).await;

    // The erasure record is damaged: half a JSON document, as a torn write leaves it.
    write_sidecar(&inbox, id, r#"{"state":"del"#);

    // Re-drop the package while the damaged tombstone stands.
    place_covid_staging_into_inbox(&inbox, id, "gdi-aggregated");
    runtime.scan_once().await;
    crate::fixtures::await_ingest_quiescent(&runtime).await;

    assert!(
        state.cache.get(id).is_none(),
        "a re-dropped package must stay suppressed while an UNREADABLE tombstone stands — \
         a damaged erasure record releases nothing"
    );
    {
        let status = state.status.lock().unwrap();
        assert!(
            status.get(id).is_none(),
            "the tombstoned id must not reappear in the status index"
        );
    }
    assert!(
        inbox.join(id).exists(),
        "the suppressed re-drop is left in the inbox (not consumed, not quarantined)"
    );
    assert_eq!(
        state.state_sidecar_error(id).as_deref(),
        Some("unreadable"),
        "the damage is recorded where the oracle field and the rejected-sidecar metric read it"
    );

    // The oracle still says `410 Gone`, exactly as for a readable tombstone.
    let router = gdi_node_standalone::app::build_management_router(state.clone(), None);
    let resp = router
        .oneshot(
            Request::builder()
                .uri(format!("/datasets/{id}/state"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::GONE,
        "an erased id whose tombstone is damaged must not read as never ingested"
    );
}
