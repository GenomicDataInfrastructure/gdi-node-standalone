//! Integration test for the inbox-driven ingestion runtime.
//!
//! Builds a real staging directory (by converting the COVID reference VCF with
//! `core`'s `convert_vcf` and writing a manifest), drops it atomically into the
//! inbox alongside a `{id}.state.json` sidecar, runs a single inbox scan, and
//! polls the in-memory cache until the dataset is published — asserting the
//! consume/persist lifecycle. A second case drops a permanent-error package
//! (unknown catalog) and asserts it lands in `inbox/.rejected/{id}/` as `error`.
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::path::Path;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use gdi_node_standalone::identities::NodeIdentities;
use gdi_node_standalone::ingest_runtime::IngestRuntime;
use gdi_node_standalone::state::AppState;
use gdi_node_standalone_core::cache::StatusIndex;
use gdi_node_standalone_core::config::ServiceConfig;
use gdi_node_standalone_core::state::DatasetState;
use tower::ServiceExt as _; // for `oneshot`

use crate::fixtures::{
    build_covid_staging_dir, manifest_for, place_covid_staging_into_inbox, poll_until,
};

#[tokio::test]
async fn inbox_picks_up_staging_dir_and_publishes() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&inbox).unwrap();

    let id = "GDI-EE-UTARTU-20260409143052837";
    // Drop the staging dir + a {"state":"visible"} sidecar.
    place_covid_staging_into_inbox(&inbox, id, "gdi-aggregated");
    std::fs::write(
        inbox.join(format!("{id}.state.json")),
        br#"{"state":"visible"}"#,
    )
    .unwrap();

    let config = crate::fixtures::inbox_config(&data_dir, &inbox, "gdi-aggregated");
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
    let runtime = IngestRuntime::start(state.clone());

    runtime.scan_once().await;

    // Poll until the dataset is Visible (bounded — no fixed sleep).
    poll_until(Duration::from_secs(10), || {
        state
            .cache
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;

    let entry = state.cache.get(id).unwrap();
    assert_eq!(entry.state, DatasetState::Visible);
    assert_eq!(entry.metadata.dataset_id, id);
    assert_eq!(entry.config.assembly.reference, "GRCh38");

    // The published dataset dir exists with a manifest + parquet.
    let published = data_dir.join(id);
    assert!(published.join("manifest.json").is_file());
    let has_parquet = std::fs::read_dir(&published)
        .unwrap()
        .filter_map(Result::ok)
        .any(|e| e.file_name().to_string_lossy().ends_with(".parquet"));
    assert!(has_parquet, "a parquet must be published");

    // The dataset is published (Visible) one step before the worker consumes the
    // source and clears its in-flight guard; drain to quiescence before asserting.
    crate::fixtures::await_ingest_quiescent(&runtime).await;
    // The inbox staging dir was consumed (deleted); the sidecar persists.
    assert!(
        !inbox.join(id).exists(),
        "the staging dir must be consumed on success"
    );
    assert!(
        inbox.join(format!("{id}.state.json")).exists(),
        "the sidecar must persist"
    );

    // The status index recorded the inbox channel + a signature.
    {
        let status = state.status.lock().unwrap();
        let e = status.get(id).expect("status entry recorded");
        assert_eq!(e.channel, "inbox");
        assert!(e.last_seen_signature.is_some());
        assert_eq!(e.error_message, None);
    }
}

#[tokio::test]
async fn a_typoed_sidecar_on_a_visible_dataset_fails_safe_to_hidden() {
    // docs/operating.md promises "an unrecognised `state` value is treated as `hidden`,
    // never `visible` — a typo can only ever under-expose, never accidentally publish."
    // That must hold for an already-visible dataset too, not just a fresh one: the case
    // that matters is mistyping the value while trying to hide something public.
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&inbox).unwrap();

    let id = "GDI-EE-UTARTU-20260409143052841";
    place_covid_staging_into_inbox(&inbox, id, "gdi-aggregated");
    std::fs::write(
        inbox.join(format!("{id}.state.json")),
        br#"{"state":"visible"}"#,
    )
    .unwrap();

    let config = crate::fixtures::inbox_config(&data_dir, &inbox, "gdi-aggregated");
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

    // Now the operator tries to hide it and mistypes the value ("hiden").
    std::fs::write(
        inbox.join(format!("{id}.state.json")),
        br#"{"state":"hiden"}"#,
    )
    .unwrap();
    runtime.scan_once().await;

    assert_eq!(
        state.cache.get(id).unwrap().state,
        DatasetState::Hidden,
        "an unrecognised value on a VISIBLE dataset must fail safe to hidden, as the \
         docs promise — never leave it public"
    );
}

#[tokio::test]
async fn a_truncated_sidecar_on_a_visible_dataset_fails_safe_to_hidden() {
    // The sibling of `a_typoed_sidecar_on_a_visible_dataset_fails_safe_to_hidden`, one layer
    // up. That test covers a sidecar that parses to an unrecognised value; this one covers a
    // sidecar that does not parse at all, which is the shape a half-written retraction takes
    // (crash mid-write, disk full, interrupted copy, a partial `scp`).
    //
    // Keeping the previous state on a parse failure means an operator trying to hide a
    // public dataset leaves it published. `docs/operating.md` promises a typo "can only ever
    // under-expose"; the same must hold for a truncation.
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&inbox).unwrap();

    let id = "GDI-EE-UTARTU-20260409143052842";
    place_covid_staging_into_inbox(&inbox, id, "gdi-aggregated");
    std::fs::write(
        inbox.join(format!("{id}.state.json")),
        br#"{"state":"visible"}"#,
    )
    .unwrap();

    let config = crate::fixtures::inbox_config(&data_dir, &inbox, "gdi-aggregated");
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

    // The operator retracts it, and the write is cut short — valid JSON prefix, no closing
    // brace. `serde_json` rejects the whole document, so there is no `state` value to be
    // unrecognised: this is the parse-failure path, not the typo path.
    std::fs::write(inbox.join(format!("{id}.state.json")), br#"{"state":"hid"#).unwrap();
    runtime.scan_once().await;

    assert_eq!(
        state.cache.get(id).unwrap().state,
        DatasetState::Hidden,
        "a truncated sidecar on a VISIBLE dataset must fail safe to hidden — a half-written \
         retraction must never leave the dataset published"
    );
}

#[tokio::test]
async fn an_unreadable_sidecar_does_not_hide_a_dataset_it_has_no_authority_over() {
    // Failing safe to hidden is a state change, so it inherits the same authority checks as
    // any other sidecar-driven change. Otherwise "fail safe" becomes a way to hide a dataset
    // the inbox does not own, by dropping a corrupt file named after it. Here the id is owned
    // by a bucket channel, so the inbox sidecar is ignored rather than fail-safed.
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&inbox).unwrap();

    let id = "GDI-EE-UTARTU-20260409143052843";
    place_covid_staging_into_inbox(&inbox, id, "gdi-aggregated");
    std::fs::write(
        inbox.join(format!("{id}.state.json")),
        br#"{"state":"visible"}"#,
    )
    .unwrap();

    let config = crate::fixtures::inbox_config(&data_dir, &inbox, "gdi-aggregated");
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

    // Re-label the id as bucket-owned, then corrupt the inbox sidecar.
    {
        let mut status = state
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // `StatusIndex` exposes `get`/`insert`, not `get_mut` — clone, retag, re-insert.
        if let Some(mut e) = status.get(id).cloned() {
            e.channel = "some-bucket".to_owned();
            status.insert(id.to_owned(), e);
        }
    }
    std::fs::write(inbox.join(format!("{id}.state.json")), br#"{"stat"#).unwrap();
    runtime.scan_once().await;

    assert_eq!(
        state.cache.get(id).unwrap().state,
        DatasetState::Visible,
        "an unreadable INBOX sidecar must not change a BUCKET-owned dataset: failing safe \
         still respects channel ownership, or a corrupt file becomes a denial-of-service"
    );
}

#[tokio::test]
async fn inflight_redrop_of_live_dataset_is_not_quarantined() {
    // A re-drop for an id that is both live and still marked in-flight is a slow ingest
    // that crossed `ingest_timeout_seconds`: the worker was freed (RetainInflight keeps the
    // guard) but the detached blocking task ran to completion and wrote `datasets/{id}/`,
    // which the periodic full-reload re-hydrated into the cache without running
    // `on_success`. The still-present source drop must not be quarantined or audited as a
    // rejected immutable re-drop, which would misreport a successful ingest. Contrast the
    // quarantine of the same re-drop when the id is not in-flight, in phase (3) of
    // `inbox_redrop_unchanged_is_noop_changed_is_quarantined`.
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&inbox).unwrap();

    let id = "GDI-EE-UTARTU-20260409143052839";
    place_covid_staging_into_inbox(&inbox, id, "gdi-aggregated");
    std::fs::write(
        inbox.join(format!("{id}.state.json")),
        br#"{"state":"visible"}"#,
    )
    .unwrap();

    let config = crate::fixtures::inbox_config(&data_dir, &inbox, "gdi-aggregated");
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
    let runtime = IngestRuntime::start(state.clone());

    // First scan: publish the dataset (now live + immutable). `on_success` cleared its
    // in-flight guard.
    runtime.scan_once().await;
    poll_until(Duration::from_secs(10), || {
        state
            .cache
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;
    crate::fixtures::await_ingest_quiescent(&runtime).await;
    let orig_sig = {
        let status = state.status.lock().unwrap();
        status.get(id).unwrap().last_seen_signature.clone()
    };

    // Reproduce the timed-out-but-completed state: re-claim the in-flight guard for the
    // now-live id (as `RetainInflight` would have left it).
    assert!(
        runtime.test_mark_inflight(id),
        "the published id's guard was cleared, so re-claiming it must succeed"
    );

    // Drop a changed re-drop for the same id: the input the sibling test quarantines when
    // the id is not in-flight.
    let tmp_parent = inbox.join(".tmp-redrop");
    std::fs::create_dir_all(&tmp_parent).unwrap();
    let built = build_covid_staging_dir(&tmp_parent, id, "gdi-aggregated");
    let manifest_path = built.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    manifest["metadata"]["title"] = serde_json::json!(MODIFIED_REDROP_TITLE);
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::rename(&built, inbox.join(id)).unwrap();
    std::fs::remove_dir_all(&tmp_parent).unwrap();

    // Second scan: because the id is in-flight, the re-drop is left in place, not
    // quarantined. `scan_once` awaits the per-artifact decision, so the outcome is
    // settled once it returns.
    runtime.scan_once().await;

    assert!(
        inbox.join(id).exists(),
        "an in-flight re-drop (post-timeout completion) must be left in place, not quarantined"
    );
    assert!(
        !inbox.join(".rejected").join(id).exists(),
        "an in-flight re-drop must NOT be moved to .rejected/"
    );

    // The live dataset is untouched and its last-seen signature was not rewritten: the skip
    // returns before hashing and `record_signature`.
    let entry = state.cache.get(id).unwrap();
    assert_eq!(entry.state, DatasetState::Visible);
    let sig_after = {
        let status = state.status.lock().unwrap();
        status.get(id).unwrap().last_seen_signature.clone()
    };
    assert_eq!(
        sig_after, orig_sig,
        "an in-flight re-drop must not record a new signature"
    );
}

#[tokio::test]
async fn incomplete_staging_dir_is_retried_not_quarantined() {
    // A half-copied staging dir (manifest.json present, parquet not yet) is incomplete on
    // first sight: skipped and retried next scan, not a permanent error in
    // inbox/.rejected/. Drops are meant to be atomic, so a structurally incomplete artifact
    // is a transient failure.
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&inbox).unwrap();

    let id = "GDI-EE-UTARTU-20260409143052900";
    // A staging dir with a manifest but no parquet yet: a slipped-through partial.
    let staging = inbox.join(id);
    std::fs::create_dir_all(&staging).unwrap();
    std::fs::write(
        staging.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest_for(id, "gdi-aggregated", 1)).unwrap(),
    )
    .unwrap();

    let config = crate::fixtures::inbox_config(&data_dir, &inbox, "gdi-aggregated");
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
    let runtime = IngestRuntime::start(state.clone());
    runtime.scan_once().await;

    // Wide enough for an enqueue-and-quarantine to complete, so the assertions below see it
    // if the scan wrongly acts on the incomplete dir.
    tokio::time::sleep(Duration::from_millis(800)).await;

    assert!(
        !inbox.join(".rejected").join(id).exists(),
        "an incomplete staging dir must NOT be quarantined to .rejected/"
    );
    {
        let status = state.status.lock().unwrap();
        assert!(
            status.get(id).is_none(),
            "an incomplete staging dir must NOT be recorded as a permanent error"
        );
    }
    assert!(state.cache.get(id).is_none(), "nothing is served");
    // Left in place so a later scan can self-heal it once the rest of the copy lands.
    assert!(staging.join("manifest.json").is_file());

    // --- The parquet now lands: the same dir becomes complete and self-heals. ---
    // Build a complete staging dir elsewhere and copy its files (manifest + parquet)
    // into the inbox dir, simulating the remainder of the half-finished copy arriving;
    // a visible sidecar lets us assert it reaches the served Visible state.
    std::fs::write(
        inbox.join(format!("{id}.state.json")),
        br#"{"state":"visible"}"#,
    )
    .unwrap();
    let complete_parent = tmp.path().join("complete");
    std::fs::create_dir_all(&complete_parent).unwrap();
    let complete = build_covid_staging_dir(&complete_parent, id, "gdi-aggregated");
    for entry in std::fs::read_dir(&complete).unwrap().filter_map(Result::ok) {
        std::fs::copy(entry.path(), staging.join(entry.file_name())).unwrap();
    }

    runtime.scan_once().await;
    poll_until(Duration::from_secs(10), || {
        state
            .cache
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;

    // The once-incomplete dir healed: it published, is served, and was consumed.
    let published = data_dir.join(id);
    assert!(published.join("manifest.json").is_file());
    let has_parquet = std::fs::read_dir(&published)
        .unwrap()
        .filter_map(Result::ok)
        .any(|e| e.file_name().to_string_lossy().ends_with(".parquet"));
    assert!(has_parquet, "the self-healed dataset publishes a parquet");
    crate::fixtures::await_ingest_quiescent(&runtime).await;
    assert!(
        !inbox.join(id).exists(),
        "the healed staging dir must be consumed on success"
    );
}

#[tokio::test]
async fn permanent_error_package_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&inbox).unwrap();

    let id = "GDI-EE-UTARTU-20260409143052999";
    // A staging dir whose manifest references a catalog the node config does not know.
    place_covid_staging_into_inbox(&inbox, id, "not-a-configured-catalog");

    // Node config only knows gdi-aggregated.
    let config = crate::fixtures::inbox_config(&data_dir, &inbox, "gdi-aggregated");
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
    let runtime = IngestRuntime::start(state.clone());

    runtime.scan_once().await;

    // Poll until the status index records the error.
    poll_until(Duration::from_secs(10), || {
        let status = state.status.lock().unwrap();
        status
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Error)
    })
    .await;

    // The artifact was moved to inbox/.rejected/{id}/ (not re-scanned, not deleted).
    let rejected = inbox.join(".rejected").join(id);
    assert!(
        rejected.exists(),
        "a permanent-error package must move to inbox/.rejected/{{id}}/"
    );
    assert!(
        !inbox.join(id).exists(),
        "the original staging dir must be moved out of the scan path"
    );

    // The status entry carries a sanitized closed-class error message.
    {
        let status = state.status.lock().unwrap();
        let e = status.get(id).expect("status entry recorded");
        assert_eq!(e.state, DatasetState::Error);
        assert_eq!(e.channel, "inbox");
        // The closed public class for an unknown catalog.
        assert_eq!(
            e.error_message,
            Some(gdi_node_standalone_core::error::ErrorClass::UnknownCatalog)
        );
    }

    // The dataset is not visible.
    assert!(
        state
            .cache
            .get(id)
            .is_none_or(|e| e.state != DatasetState::Visible)
    );
}

/// An operator metadata overlay applied to a newly-ingested dataset updates the served title
/// and stamps `metadata_modified`. Removing the sidecar reverts to the baseline title but
/// retains `metadata_modified` at its high-water mark, so `dct:modified` never moves
/// backward.
#[tokio::test]
async fn inbox_metadata_overlay_applies_and_reverts() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&inbox).unwrap();

    let id = "GDI-EE-UTARTU-20260409143052839";
    // Ingest and publish the dataset first. Build the staging dir in a temp location, patch
    // the manifest to add a description (required by the overlay validator), then place it
    // atomically into the inbox.
    let tmp_build = tmp.path().join("build-overlay");
    std::fs::create_dir_all(&tmp_build).unwrap();
    let staging = build_covid_staging_dir(&tmp_build, id, "gdi-aggregated");
    // Patch description into the manifest so overlay validation succeeds.
    {
        let manifest_path = staging.join("manifest.json");
        let raw = std::fs::read(&manifest_path).unwrap();
        let mut m: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        m["metadata"]["description"] = serde_json::json!("A dataset description.");
        std::fs::write(&manifest_path, serde_json::to_vec_pretty(&m).unwrap()).unwrap();
    }
    std::fs::rename(&staging, inbox.join(id)).unwrap();
    std::fs::write(
        inbox.join(format!("{id}.state.json")),
        br#"{"state":"visible"}"#,
    )
    .unwrap();

    let config = crate::fixtures::inbox_config(&data_dir, &inbox, "gdi-aggregated");
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

    // Drop {id}.metadata.json with a corrected title.
    std::fs::write(
        inbox.join(format!("{id}.metadata.json")),
        br#"{"title":"Corrected title"}"#,
    )
    .unwrap();
    runtime.scan_once().await;

    let entry = state.cache.get(id).expect("still cached");
    assert_eq!(
        entry.metadata.title,
        gdi_node_standalone_core::model::LocalizedText::Plain("Corrected title".to_owned())
    );
    assert!(entry.metadata_modified.is_some(), "modified advanced");
    let applied_modified = entry.metadata_modified.clone();

    // Remove the sidecar → revert.
    std::fs::remove_file(inbox.join(format!("{id}.metadata.json"))).unwrap();
    runtime.scan_once().await;
    let entry = state.cache.get(id).unwrap();
    // After revert the title must be the baseline value, not merely different from the
    // overlay, so pin the exact string.
    assert_eq!(
        entry.metadata.title,
        gdi_node_standalone_core::model::LocalizedText::Plain("COVID monogenic AFs".to_owned()),
        "reverted title must equal the baseline"
    );
    // Monotonic dct:modified: revert restores the baseline content but must not move the
    // modified time backward. The last applied_at is retained as a durable high-water mark,
    // so an incremental harvester never sees a regression.
    assert_eq!(
        entry.metadata_modified, applied_modified,
        "revert must retain the modified high-water mark, not clear it to id-derived"
    );
}

/// A genuinely unrecognised sibling (a name the node has no handler for — not a
/// package, staging dir, `{id}.state.json`, or `{id}.metadata.json` overlay) must
/// be left in place (not consumed, not quarantined) and must not prevent the
/// staging dir beside it from ingesting successfully.
#[tokio::test]
async fn unrecognised_sibling_is_ignored_not_errored() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&inbox).unwrap();

    let id = "GDI-EE-UTARTU-20260409143052838";
    // A valid staging dir + a {"state":"visible"} sidecar, plus a genuinely
    // unrecognised `{id}.random.json` sibling the node has no handler for.
    place_covid_staging_into_inbox(&inbox, id, "gdi-aggregated");
    std::fs::write(
        inbox.join(format!("{id}.state.json")),
        br#"{"state":"visible"}"#,
    )
    .unwrap();
    let unknown_sibling = inbox.join(format!("{id}.random.json"));
    std::fs::write(&unknown_sibling, br#"{"note":"unrecognised"}"#).unwrap();

    let config = crate::fixtures::inbox_config(&data_dir, &inbox, "gdi-aggregated");
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
    let runtime = IngestRuntime::start(state.clone());

    runtime.scan_once().await;

    // The valid staging dir still ingests and publishes — the unknown sibling
    // did not break the scan.
    poll_until(Duration::from_secs(10), || {
        state
            .cache
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;
    crate::fixtures::await_ingest_quiescent(&runtime).await;
    assert!(data_dir.join(id).join("manifest.json").is_file());
    assert!(
        !inbox.join(id).exists(),
        "the staging dir must be consumed on success"
    );

    // The unknown sibling is ignored-and-logged: it is left in place (not
    // consumed, not quarantined to `.rejected/`) and produced no status entry.
    assert!(
        unknown_sibling.exists(),
        "an unrecognised sibling must be left untouched, not consumed"
    );
    assert!(
        !inbox
            .join(".rejected")
            .join(format!("{id}.random.json"))
            .exists(),
        "an unknown sibling must not be quarantined as an error"
    );
}

/// A live (Visible/Hidden) inbox id re-presented with an unchanged signature is a
/// pure no-op; re-presented with a changed signature it is quarantined to
/// `inbox/.rejected/{id}/`, the live entry is left intact, and the recorded
/// last-seen signature advances.
#[tokio::test]
async fn inbox_redrop_unchanged_is_noop_changed_is_quarantined() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&inbox).unwrap();

    let id = "GDI-EE-UTARTU-20260409143052801";

    // (1) Ingest + publish to Visible.
    place_covid_staging_into_inbox(&inbox, id, "gdi-aggregated");
    std::fs::write(
        inbox.join(format!("{id}.state.json")),
        br#"{"state":"visible"}"#,
    )
    .unwrap();

    let config = crate::fixtures::inbox_config(&data_dir, &inbox, "gdi-aggregated");
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

    // Capture the recorded last-seen signature after the first publish.
    let sig0 = {
        let status = state.status.lock().unwrap();
        status
            .get(id)
            .expect("status entry recorded")
            .last_seen_signature
            .clone()
            .expect("a signature is recorded on publish")
    };

    // (2) Re-drop the identical staging bytes: build_covid_staging_dir is deterministic for
    // the same VCF and manifest, so its signature equals sig0.
    place_covid_staging_into_inbox(&inbox, id, "gdi-aggregated");
    runtime.scan_once().await;

    // No quarantine, signature unchanged, entry still Visible.
    assert!(
        !inbox.join(".rejected").join(id).exists(),
        "an identical re-drop of a live id must NOT be quarantined"
    );
    {
        let status = state.status.lock().unwrap();
        let e = status.get(id).expect("status entry still present");
        assert_eq!(e.state, DatasetState::Visible);
        assert_eq!(e.channel, "inbox");
        assert_eq!(
            e.last_seen_signature.as_deref(),
            Some(sig0.as_str()),
            "an unchanged re-drop must not move the recorded signature"
        );
        assert_eq!(e.error_message, None);
    }
    assert_eq!(
        state.cache.get(id).unwrap().state,
        DatasetState::Visible,
        "the dataset stays Visible across an unchanged re-drop"
    );
    // The unchanged re-drop is a true no-op: neither ingested nor quarantined, so
    // the staging dir is left sitting in the inbox.
    assert!(
        inbox.join(id).exists(),
        "an unchanged re-drop is a no-op: the staging dir is left in place"
    );

    // (3) Re-drop a modified staging dir (different manifest bytes, so a different
    // signature) and rescan.
    build_modified_staging_into_inbox(&inbox, id, "gdi-aggregated");
    runtime.scan_once().await;

    // The changed re-drop is quarantined to inbox/.rejected/{id}/ (a directory).
    poll_until(Duration::from_secs(10), || {
        inbox.join(".rejected").join(id).exists()
    })
    .await;
    assert_quarantined_carrying_sentinel(&inbox, id);

    // The live Visible entry is untouched; the recorded signature advanced.
    let live = state.cache.get(id).unwrap();
    assert_eq!(
        live.state,
        DatasetState::Visible,
        "a changed re-drop must not disturb the live dataset"
    );
    // Immutability is about the served metadata, not just the state: the re-drop carried
    // `MODIFIED_REDROP_TITLE`, which must not have reached the published entry.
    assert!(
        !format!("{:?}", live.metadata.title).contains(MODIFIED_REDROP_TITLE),
        "an immutable dataset's metadata must not be overwritten by a re-drop"
    );
    {
        let status = state.status.lock().unwrap();
        let e = status.get(id).expect("status entry still present");
        assert_eq!(e.state, DatasetState::Visible);
        assert_eq!(e.channel, "inbox");
        assert_eq!(e.error_message, None);
        assert!(
            e.last_seen_signature.as_deref() != Some(sig0.as_str()),
            "a changed re-drop must advance the recorded last-seen signature"
        );
    }

    // The state oracle must carry a signal that the changed re-drop was ignored. A provider
    // polling `GET /datasets/<id>/state` (what `deploy --wait` and `status` use) otherwise
    // sees only `visible` with a null `error_message`, and cannot tell that its correction
    // was dropped. A same-millisecond id collision discards the second dataset by this same
    // path.
    assert!(
        state.superseded_redrop_at(id).is_some(),
        "a changed re-drop under a live id must be recorded for the state oracle"
    );
}

/// Overlay keep-last-good (inbox): dropping a garbage-JSON `{id}.metadata.json`
/// on a published visible dataset leaves the served title unchanged and the dataset
/// stays visible (not hidden, not quarantined). Mirrors the S3 overlay error path.
#[tokio::test]
async fn inbox_metadata_overlay_garbage_json_keeps_last_good() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&inbox).unwrap();

    let id = "GDI-EE-UTARTU-20260409143052802";
    place_covid_staging_into_inbox(&inbox, id, "gdi-aggregated");
    std::fs::write(
        inbox.join(format!("{id}.state.json")),
        br#"{"state":"visible"}"#,
    )
    .unwrap();

    let config = crate::fixtures::inbox_config(&data_dir, &inbox, "gdi-aggregated");
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

    // Record the baseline title before the bad overlay.
    let baseline_title = state.cache.get(id).unwrap().metadata.title.clone();

    // Drop a garbage-JSON overlay: it must be ignored (warn-and-keep).
    std::fs::write(
        inbox.join(format!("{id}.metadata.json")),
        b"{{NOT VALID JSON{{{{{{",
    )
    .unwrap();
    runtime.scan_once().await;

    // Title must be unchanged and the dataset must stay visible.
    let entry = state.cache.get(id).unwrap();
    assert_eq!(
        entry.metadata.title, baseline_title,
        "garbage-JSON overlay must not change the served title (last-good kept)"
    );
    assert_eq!(
        entry.state,
        DatasetState::Visible,
        "a bad overlay must not hide or quarantine the dataset"
    );
    // The bad sidecar must be left in place (not quarantined).
    assert!(
        inbox.join(format!("{id}.metadata.json")).exists(),
        "the bad overlay file must be left in place, not quarantined"
    );

    // The rejection must be observable: `GET /datasets/{id}/state` surfaces `overlay_error`
    // so an orchestrator can tell a dropped correction from an applied one. A log line alone
    // is not enough.
    assert_eq!(
        state.overlay_error(id).as_deref(),
        Some("parse"),
        "a rejected overlay must record a per-dataset overlay_error"
    );

    // A subsequent well-formed overlay applies and clears the recorded error.
    std::fs::write(
        inbox.join(format!("{id}.metadata.json")),
        br#"{"title":"Corrected Title"}"#,
    )
    .unwrap();
    runtime.scan_once().await;
    poll_until(Duration::from_secs(10), || {
        state
            .cache
            .get(id)
            .and_then(|e| e.metadata_modified)
            .is_some()
    })
    .await;
    assert_eq!(
        state.overlay_error(id),
        None,
        "a successful overlay apply must clear the recorded overlay_error"
    );
    assert!(
        state.cache.get(id).unwrap().metadata_modified.is_some(),
        "an applied overlay must stamp metadata_modified (the overlay_applied_at signal)"
    );
}

/// Assert a changed re-drop of `id` was quarantined to `inbox/.rejected/{id}/` as a
/// directory holding the moved manifest, and moved out of the scan path.
///
/// Also asserts the quarantined manifest still carries [`MODIFIED_REDROP_TITLE`]. That check
/// stops the caller's "the live entry does not contain the sentinel" assertion from passing
/// vacuously: it proves the re-drop carried a changed title, so a node that overwrote the
/// live metadata would be caught.
fn assert_quarantined_carrying_sentinel(inbox: &Path, id: &str) {
    let rejected = inbox.join(".rejected").join(id);
    assert!(
        rejected.is_dir(),
        "a changed re-drop of a live id is quarantined as inbox/.rejected/{{id}}/ (a dir)"
    );
    let manifest = rejected.join("manifest.json");
    assert!(
        manifest.is_file(),
        "the quarantined dir holds the moved staging dir's manifest"
    );
    assert!(
        String::from_utf8_lossy(&std::fs::read(&manifest).unwrap()).contains(MODIFIED_REDROP_TITLE),
        "the quarantined re-drop must carry the sentinel title"
    );
    assert!(
        !inbox.join(id).exists(),
        "the changed re-drop must be moved out of the scan path"
    );
    // The quarantine is owner-only. Asserted in the shared helper rather than in one test,
    // so every quarantine path this file exercises keeps the property. The directory is
    // node-created and holds rejected artifacts (plaintext staging dirs, VCF headers,
    // allele-frequency parquet) for `rejected_retention_hours`, 7 days by default, next to a
    // served store kept at 0o700. Inheriting the umask would leave it 0o755.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(inbox.join(".rejected"))
            .expect("quarantine dir exists")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o700,
            "inbox/.rejected/ must be owner-only (got {mode:o}): it holds decrypted dataset \
             content for days beside a 0700 store"
        );
    }
}

/// Sentinel title written into a modified re-drop by [`build_modified_staging_into_inbox`].
/// A live dataset is immutable, so this string must never reach the served metadata; its
/// absence is what proves the re-drop did not overwrite the published entry.
const MODIFIED_REDROP_TITLE: &str = "A changed title";

/// Build a staging dir for `id` whose manifest differs from the canonical one (a different
/// `numberOfRecords`, so different manifest bytes and a different inbox signature) and place
/// it atomically at `inbox/{id}`, replacing any prior staging dir left there by an unchanged
/// re-drop.
fn build_modified_staging_into_inbox(inbox: &Path, id: &str, catalog: &str) {
    let tmp_parent = inbox.join(format!(".tmp-mod-{id}"));
    std::fs::create_dir_all(&tmp_parent).unwrap();
    let built = build_covid_staging_dir(&tmp_parent, id, catalog);
    // A different numberOfRecords changes the manifest bytes, which are hashed into the
    // signature. The sentinel title lets the caller prove the live dataset's metadata was not
    // overwritten by the re-drop.
    let manifest_path = built.join("manifest.json");
    let raw = std::fs::read(&manifest_path).unwrap();
    let mut m: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    m["metadata"]["numberOfRecords"] = serde_json::json!(999_999);
    m["metadata"]["title"] = serde_json::json!(MODIFIED_REDROP_TITLE);
    std::fs::write(&manifest_path, serde_json::to_vec_pretty(&m).unwrap()).unwrap();
    let dest = inbox.join(id);
    // A prior unchanged re-drop leaves dest in place; clear it before the rename.
    let _ = std::fs::remove_dir_all(&dest);
    std::fs::rename(&built, &dest).unwrap();
    std::fs::remove_dir_all(&tmp_parent).unwrap();
}

/// A timed-out ingest still faces the writer-key gate, and still releases its id.
///
/// `spawn_blocking` cannot be cancelled, so a timeout hands the join handle to a supervisor
/// rather than dropping it. A dropped handle would leave the detached task running to
/// completion, including the store-time writer-key gate inside `store_atomically`, with its
/// outcome never applied: under `writer_policy = "enforce"` a store-time rejection would go
/// unadjudicated, and the id would stay in the in-flight set until a restart, so every later
/// reconcile would skip it. A slow ingest reaches the same outcome handling as a fast one.
#[tokio::test]
#[serial_test::serial(faults)]
async fn a_timed_out_ingest_still_faces_the_writer_gate_and_frees_its_id() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    for d in [&data_dir, &inbox] {
        std::fs::create_dir_all(d).unwrap();
    }
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"
inbox = "{}"
ingest_concurrency = 2
rescan_interval_seconds = 3600
ingest_timeout_seconds = 1

[catalogs]
gdi-aggregated = "Genome of Europe Aggregated Data"

[beacon]
id = "org.test.beacon"
name = "Test Beacon"

[ingest]
writer_policy = "enforce"
"#,
        data_dir.display(),
        inbox.display(),
    );
    let config = ServiceConfig::from_toml_str(&toml).unwrap();
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
    let runtime = IngestRuntime::start(state.clone());

    let id = "GDI-EE-UTARTU-20260409143052871";
    crate::fixtures::place_covid_staging_into_inbox(&inbox, id, "gdi-aggregated");

    // Stall the store past `ingest_timeout_seconds`, so the worker gives up on it.
    {
        let _slow = gdi_node_standalone_core::faults::arm_delay(
            gdi_node_standalone_core::faults::FaultPoint::IngestStore,
            id,
            Duration::from_secs(3),
            1,
        );
        runtime.scan_once().await;
        // Let the supervisor adopt and finish the detached task.
        poll_until(Duration::from_secs(30), || {
            !runtime.is_inflight_for_test(id)
        })
        .await;
    }

    // The plaintext drop carries no allow-listed writer key, so `enforce` must refuse it —
    // exactly as it would for an ingest that finished in time.
    assert!(
        state
            .cache
            .get(id)
            .is_none_or(|e| e.state != DatasetState::Visible),
        "a timed-out ingest must not publish past the writer gate"
    );
}

/// A standing tombstone must not re-emit its audit event on every scan.
///
/// The `deleted` sidecar stays in the inbox, because its presence is the ownership signal
/// that keeps a re-dropped package suppressed. So the delete path is re-entered on every scan
/// for as long as the operator leaves it there. Re-running the erase would re-emit
/// `dataset_state_change{cause=tombstone-delete}` once per scan for a dataset already gone,
/// filling the audit stream from a single artifact.
///
/// A plain `#[test]` owning its own runtime: the capture below is a thread-local subscriber,
/// so the scans must run on the thread it is installed on, which nesting inside
/// `#[tokio::test]` cannot do.
#[test]
#[serial_test::serial(env)]
fn a_standing_tombstone_audits_once_not_once_per_scan() {
    use tracing_subscriber::layer::SubscriberExt as _;

    crate::fixtures::ensure_capture_safe_tracing();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&inbox).unwrap();

    let id = "GDI-EE-UTARTU-20260409143052901";
    place_covid_staging_into_inbox(&inbox, id, "gdi-aggregated");
    std::fs::write(
        inbox.join(format!("{id}.state.json")),
        br#"{"state":"visible"}"#,
    )
    .unwrap();

    let config = crate::fixtures::inbox_config(&data_dir, &inbox, "gdi-aggregated");
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
    let runtime = rt.block_on(async { IngestRuntime::start(state.clone()) });
    rt.block_on(async {
        runtime.scan_once().await;
        poll_until(Duration::from_secs(20), || {
            state
                .cache
                .get(id)
                .is_some_and(|e| e.state == DatasetState::Visible)
        })
        .await;
        crate::fixtures::await_ingest_quiescent(&runtime).await;
    });

    // Tombstone it, then scan repeatedly with the sidecar left in place: the operator has
    // not removed it, which is the documented steady state.
    std::fs::write(
        inbox.join(format!("{id}.state.json")),
        br#"{"state":"deleted","force":true}"#,
    )
    .unwrap();

    let writer = test_util::CaptureWriter::new();
    let make = {
        let w = writer.clone();
        move || w.clone()
    };
    let subscriber = tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().json().with_writer(make));

    tracing::subscriber::with_default(subscriber, || {
        rt.block_on(async {
            for _ in 0..5 {
                runtime.scan_once().await;
                crate::fixtures::await_ingest_quiescent(&runtime).await;
            }
        });
    });

    let emitted = writer.contents().matches("tombstone-delete").count();
    assert_eq!(
        emitted, 1,
        "five scans over a standing tombstone must audit the delete ONCE (the transition), \
         not once per scan; got {emitted}"
    );
}

/// The state oracle must distinguish a deleted id from one never ingested.
///
/// The tool collapses every non-2xx into one "no authoritative view", which also covers
/// "unreachable" and "not seen yet". If both answered `404`, `deploy --wait` against a
/// tombstoned id could not tell it had been permanently refused, and would poll out its whole
/// `--wait-timeout` before blaming a slow ingest.
#[test]
#[serial_test::serial(env)]
fn a_tombstoned_id_answers_410_while_an_unknown_id_stays_404() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&inbox).unwrap();

    let id = "GDI-EE-UTARTU-20260409143052902";
    place_covid_staging_into_inbox(&inbox, id, "gdi-aggregated");
    std::fs::write(
        inbox.join(format!("{id}.state.json")),
        br#"{"state":"visible"}"#,
    )
    .unwrap();

    let config = crate::fixtures::inbox_config(&data_dir, &inbox, "gdi-aggregated");
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
    let runtime = rt.block_on(async { IngestRuntime::start(state.clone()) });
    rt.block_on(async {
        runtime.scan_once().await;
        poll_until(Duration::from_secs(20), || {
            state
                .cache
                .get(id)
                .is_some_and(|e| e.state == DatasetState::Visible)
        })
        .await;
        crate::fixtures::await_ingest_quiescent(&runtime).await;
    });

    // Tombstone it and let one scan apply the erase + publish the tombstone set.
    std::fs::write(
        inbox.join(format!("{id}.state.json")),
        br#"{"state":"deleted","force":true}"#,
    )
    .unwrap();
    rt.block_on(async {
        runtime.scan_once().await;
        crate::fixtures::await_ingest_quiescent(&runtime).await;
    });

    let status_of = |dataset: &str| {
        let router = gdi_node_standalone::app::build_management_router(state.clone(), None);
        rt.block_on(async {
            let req = Request::builder()
                .method("GET")
                .uri(format!("/datasets/{dataset}/state"))
                .body(Body::empty())
                .unwrap();
            router.oneshot(req).await.unwrap().status()
        })
    };

    assert_eq!(
        status_of(id),
        StatusCode::GONE,
        "a tombstoned id must answer 410 Gone — it existed and is intentionally refused"
    );
    assert_eq!(
        status_of("GDI-EE-UTARTU-20260409143052999"),
        StatusCode::NOT_FOUND,
        "an id the node never ingested must still be a plain 404"
    );
}

/// `inbox/.rejected/` holds plaintext quarantine (staging dirs, VCF headers,
/// allele-frequency parquet) for a week by default, and is created owner-only.
/// `create_private_dir` sets the mode only on components it creates, so a `.rejected/` that
/// an operator's `mkdir` already left at 0755 stays world-readable. Startup must tighten it,
/// as it tightens the data-dir root.
#[cfg(unix)]
#[tokio::test]
async fn a_pre_existing_rejected_dir_is_tightened_to_owner_only_at_startup() {
    use std::os::unix::fs::PermissionsExt as _;

    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    let rejected = inbox.join(".rejected");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&rejected).unwrap();
    std::fs::set_permissions(&rejected, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        std::fs::metadata(&rejected).unwrap().permissions().mode() & 0o777,
        0o755,
        "precondition: the quarantine dir pre-exists world-readable"
    );

    let config = crate::fixtures::inbox_config(&data_dir, &inbox, "gdi-aggregated");
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
    let _runtime = IngestRuntime::start(state);

    assert_eq!(
        std::fs::metadata(&rejected).unwrap().permissions().mode() & 0o777,
        0o700,
        "a pre-existing .rejected/ must be owner-only after startup"
    );
}
