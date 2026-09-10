//! Odds and ends on the same ingested COVID fixture that don't fit the
//! error/result/wiring buckets: the store/scrub check and the bare `service-info`
//! response.
use super::*;
use gdi_node_standalone::scrub::{ScrubDepth, ScrubPass, scrub_dataset};

#[tokio::test]
async fn store_scrub_validates_covid_dataset_at_all_depths() {
    // A plaintext-ingested dataset passes the scrub at every depth, and the digest
    // depth confirms the at-rest `parquet-digests.json` sidecar written at ingest.
    let (state, _tmp) = state_with_covid();
    for depth in [
        ScrubDepth::Footer,
        ScrubDepth::Full,
        ScrubDepth::Digest,
        ScrubDepth::FullDigest,
    ] {
        let r = scrub_dataset(&state, DATASET_ID, depth);
        assert!(r.ok, "{depth:?} scrub should pass: {}", r.detail);
    }
    let r = scrub_dataset(&state, DATASET_ID, ScrubDepth::Digest);
    assert!(
        r.detail.contains("digest ok"),
        "digest sidecar must verify: {}",
        r.detail
    );
}

/// The first sweep after start leaves out the rotating digest slice. It runs the readability
/// tier over every dataset and re-verifies the quarantined set, nothing more.
///
/// The digest tier costs `DIGEST_PER_SWEEP` whole-file rehashes, and running it on the first
/// tick would make every restart pay that before anything else off the critical path. A
/// dataset the boot pass skips is verified one `rescan_interval_seconds` later by the first
/// periodic pass, and the cursor is not advanced, so no slot is lost.
///
/// Whether the sweep ran the digest tier is observable: a plaintext store with no sidecar
/// fails closed at digest depth while its footer stays readable, so the boot pass passes this
/// store and the periodic pass fails it.
#[tokio::test]
async fn the_boot_pass_runs_the_readability_tier_only() {
    let (state, _tmp) = state_with_covid();
    std::fs::remove_file(covid_dataset_dir(&state).join("parquet-digests.json")).unwrap();

    let before = state
        .digest_scrub_cursor
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        gdi_node_standalone::scrub::run_scrub_sweep(&state, ScrubPass::Boot),
        0,
        "the boot pass runs the readability tier only, and the footer is intact"
    );
    assert_eq!(
        state
            .digest_scrub_cursor
            .load(std::sync::atomic::Ordering::Relaxed),
        before,
        "the boot pass must not consume a digest slot"
    );
    assert!(
        !state.is_scrub_quarantined(DATASET_ID),
        "the boot pass reached no verdict about the sidecar, so it may not quarantine"
    );

    assert_eq!(
        gdi_node_standalone::scrub::run_scrub_sweep(&state, ScrubPass::Periodic),
        1,
        "the periodic pass runs the digest tier, which fails closed on a missing sidecar"
    );
    assert!(state.is_scrub_quarantined(DATASET_ID));
}

/// Digest depth checks the sidecar and nothing else.
///
/// `parquet-digests.json` is written at ingest from the stored bytes, so it already answers
/// whether a byte changed. Re-running the full schema, value and uniqueness validation
/// underneath it repeats ingest-time work for no extra detection, and that repetition rather
/// than the hash is what the tier would cost. The reported detail is the discriminator: with
/// row validation running first, a mid-file flip is reported as `invalid parquet: …` and the
/// sidecar is never consulted.
#[tokio::test]
async fn digest_depth_is_hash_only_and_full_digest_still_validates_rows() {
    let (state, _tmp) = state_with_covid();
    corrupt_data_pages(&covid_dataset_dir(&state));

    let r = scrub_dataset(&state, DATASET_ID, ScrubDepth::Digest);
    assert!(
        !r.ok,
        "a mid-file byte flip must fail digest depth: {}",
        r.detail
    );
    assert!(
        r.detail.contains("digest mismatch"),
        "caught by the sidecar, not by row validation: {}",
        r.detail
    );

    // The same store at the combined depth comes back with the other verdict, which is what
    // binds `FullDigest` to its name. A clean store passes it whether or not row validation
    // runs, so only a store the validation rejects tells the two apart, and the validation
    // runs first, so its message is the one that surfaces.
    let both_bad = scrub_dataset(&state, DATASET_ID, ScrubDepth::FullDigest);
    assert!(
        !both_bad.ok,
        "full+digest on a flipped store: {}",
        both_bad.detail
    );
    assert!(
        both_bad.detail.contains("invalid parquet"),
        "FullDigest must still validate rows, and validation sees the flip before the \
         sidecar does: {}",
        both_bad.detail
    );

    // …and a store whose rows are valid and whose sidecar matches passes both depths —
    // the combined one being what the offline `verify --full --digest` runs.
    let (clean, _tmp_clean) = state_with_covid();
    let digest = scrub_dataset(&clean, DATASET_ID, ScrubDepth::Digest);
    assert!(
        digest.ok,
        "digest depth on a clean store: {}",
        digest.detail
    );
    let both = scrub_dataset(&clean, DATASET_ID, ScrubDepth::FullDigest);
    assert!(both.ok, "full+digest on a clean store: {}", both.detail);
    assert!(
        both.detail.contains("digest ok"),
        "the combined depth reports the digest verdict it ran last: {}",
        both.detail
    );
}

#[tokio::test]
async fn store_scrub_sweep_quarantines_an_unreadable_dataset() {
    // A corrupt or unreadable at-rest dataset is quarantined, meaning it goes to `Error` and
    // is evicted from the served view, rather than merely metered. Left `visible`, it would
    // 500 every query.
    let (state, _tmp) = state_with_covid();
    assert!(
        state
            .cache
            .visible_datasets()
            .iter()
            .any(|d| d.id == DATASET_ID),
        "served (Visible) before corruption"
    );

    // Four healthy copies of the store beside the one about to be corrupted; the assertion
    // at the end explains why five. Byte-for-byte copies pass every depth, including the
    // digest sidecar, and each is cached as a hydrated dataset would be.
    let dir = state.config.service.data_dir.join(DATASET_ID);
    let template = state
        .cache
        .get(DATASET_ID)
        .expect("the ingested dataset is cached");
    for i in 1..=4u8 {
        let copy_id = format!("GDI-EE-UTARTU-2026040914305290{i}");
        let copy = state.config.service.data_dir.join(&copy_id);
        std::fs::create_dir_all(&copy).unwrap();
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            std::fs::write(
                copy.join(entry.file_name()),
                std::fs::read(entry.path()).unwrap(),
            )
            .unwrap();
        }
        let mut cached = template.clone();
        cached.id = copy_id;
        state.cache.insert(
            gdi_node_standalone_core::cache::StatusWrite::unshared(),
            cached,
        );
    }

    // Corrupt the parquet magic on disk so the footer probe can no longer read it. Stored
    // parquets are written read-only, so make it writable first.
    let pq = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|x| x == "parquet"))
        .expect("a parquet file in the dataset dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut perms = std::fs::metadata(&pq).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&pq, perms).unwrap();
    }
    std::fs::write(&pq, b"\x00\x00\x00\x00not a parquet").unwrap();

    // The sweep detects the failure and quarantines it, rather than only counting it.
    let failed = gdi_node_standalone::scrub::run_scrub_sweep(&state, ScrubPass::Periodic);
    assert_eq!(failed, 1, "the unreadable dataset is counted as a failure");
    assert!(
        !state
            .cache
            .visible_datasets()
            .iter()
            .any(|d| d.id == DATASET_ID),
        "a scrub-failed dataset must be evicted from the served view, not left visible"
    );

    // The count feeds the `gdi_store_scrub_failed` gauge and the corruption still stands, so
    // every later sweep keeps reporting it. Otherwise `StoreScrubFailed` clears while the
    // dataset is still corrupt and still withheld. A quarantined id is skipped by the digest
    // slice and by the footer pass, so on each sweep the only pass that can count it is the
    // re-verification of the quarantined set. The four extra datasets show that pass counts
    // the corrupt one and not its healthy neighbours.
    for sweep in 1..=5 {
        let again = gdi_node_standalone::scrub::run_scrub_sweep(&state, ScrubPass::Periodic);
        assert!(
            again >= 1,
            "sweep {sweep}: a still-corrupt quarantined dataset must keep being reported; got {again}"
        );
        assert!(state.is_scrub_quarantined(DATASET_ID), "still quarantined");
    }
}

/// A dataset whose directory vanishes out of band, through a bad cleanup or a half-finished
/// restore, must not stay `visible`.
///
/// Left visible, it reports `gdi_store_scrub_failed = 0` while still being served, and both
/// provider recovery paths are blocked: `deploy` refuses because the dataset is already live,
/// and `delete` refuses on the visible guard.
#[tokio::test]
async fn store_scrub_sweep_detects_a_vanished_dataset_directory() {
    let (state, tmp) = state_with_covid();
    assert!(
        state
            .cache
            .visible_datasets()
            .iter()
            .any(|d| d.id == DATASET_ID),
        "served (Visible) before the directory vanishes"
    );

    // The whole dataset directory disappears — not corruption, absence.
    let dir = tmp.path().join("datasets").join(DATASET_ID);
    let dir = if dir.exists() {
        dir
    } else {
        state.config.service.data_dir.join(DATASET_ID)
    };
    assert!(
        dir.exists(),
        "fixture dir must exist before removal: {dir:?}"
    );
    std::fs::remove_dir_all(&dir).unwrap();

    let failed = gdi_node_standalone::scrub::run_scrub_sweep(&state, ScrubPass::Periodic);
    assert_eq!(
        failed, 1,
        "a dataset the node believes it holds, whose directory is GONE, must count as a \
         scrub failure — otherwise nothing alarms and it keeps being served"
    );
    assert!(
        !state
            .cache
            .visible_datasets()
            .iter()
            .any(|d| d.id == DATASET_ID),
        "a vanished dataset must be evicted from the served view, not left visible"
    );

    // The half that actually blocks recovery: the authoritative state oracle. While it
    // still answers `visible`, `deploy` refuses ("already live") and `delete` refuses
    // (visible-guard), so the provider cannot re-deploy or remove a dataset that
    // physically does not exist.
    let router = build_router(state);
    let req = Request::builder()
        .method("GET")
        .uri(format!("/datasets/{DATASET_ID}/state"))
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let reported = if status == StatusCode::OK {
        body_json(resp.into_body()).await["state"]
            .as_str()
            .unwrap_or("<absent>")
            .to_owned()
    } else {
        format!("<http {status}>")
    };
    assert_ne!(
        reported, "visible",
        "the state oracle must stop reporting `visible` for a dataset whose directory is \
         gone, or both provider recovery paths stay blocked"
    );
}

#[tokio::test]
async fn get_service_info_is_bare() {
    let (state, _tmp) = state_with_covid();
    let router = build_router(state);

    let req = Request::builder()
        .method("GET")
        .uri("/beacon/v2/service-info")
        .body(Body::empty())
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let v = body_json(resp.into_body()).await;
    // The bare GA4GH ServiceInfo is not wrapped in `{meta, response}`.
    assert!(v.get("meta").is_none(), "service-info must be bare");
    assert!(v.get("response").is_none());
    assert_eq!(v["id"], "org.test.beacon");
    assert_eq!(v["type"]["group"], "org.ga4gh");
}

/// Silent mid-file bit-rot is caught by the online sweep, not only by an offline
/// `verify --digest`.
///
/// A mid-file corruption passes the readability sweep and `verify` at its default depth, and
/// the dataset keeps being served. Only `verify --digest` catches it, and that needs the
/// exclusive data-dir lock, so it cannot run on a live node. The reference digests are on
/// disk the whole time.
#[tokio::test]
async fn store_scrub_sweep_detects_mid_file_bit_rot_online() {
    let (state, _tmp) = state_with_covid();
    assert!(
        state
            .cache
            .visible_datasets()
            .iter()
            .any(|d| d.id == DATASET_ID),
        "served before corruption"
    );

    corrupt_data_pages(&covid_dataset_dir(&state));

    // The node is running: no lock is taken and nothing is stopped.
    let failed = gdi_node_standalone::scrub::run_scrub_sweep(&state, ScrubPass::Periodic);
    assert_eq!(
        failed, 1,
        "the online sweep must detect at-rest corruption its footer tier cannot see"
    );
    assert!(
        !state
            .cache
            .visible_datasets()
            .iter()
            .any(|d| d.id == DATASET_ID),
        "a digest-failed dataset must stop being served, not merely be counted"
    );
}

/// The on-disk directory of the ingested COVID dataset, asserted present.
fn covid_dataset_dir(state: &AppState) -> std::path::PathBuf {
    let dir = state.config.service.data_dir.join(DATASET_ID);
    assert!(
        dir.is_dir(),
        "the ingested dataset dir must exist: {}",
        dir.display()
    );
    dir
}

/// Flip 64 bytes inside the data pages of the dataset's stored parquet, leaving the footer
/// intact. That is the at-rest corruption the footer tier cannot see.
///
/// The offset is derived, not guessed. A parquet file ends with
/// `[metadata][4-byte metadata length]["PAR1"]`, so the footer starts at
/// `len - 8 - metadata_len`, and anything at or after that is structure the footer tier
/// already parses. Picking the midpoint blindly lands there on a small file, which would make
/// this measure the readability check instead of the digest.
///
/// # Panics
///
/// Panics if the dataset holds no `allele-freq.*.parquet`, or if the derived offset does
/// not leave room for the flip before the footer.
fn corrupt_data_pages(dir: &Path) {
    let pq = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("allele-freq.") && n.ends_with(".parquet"))
        })
        .expect("a stored parquet");

    // Store files are written read-only (0400); widen to write, then restore.
    let mut perms = std::fs::metadata(&pq).unwrap().permissions();
    let original = perms.clone();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        perms.set_mode(0o644);
    }
    std::fs::set_permissions(&pq, perms).unwrap();

    let mut bytes = std::fs::read(&pq).unwrap();
    let len = bytes.len();
    let meta_len = u32::from_le_bytes([
        bytes[len - 8],
        bytes[len - 7],
        bytes[len - 6],
        bytes[len - 5],
    ]) as usize;
    let footer_start = len - 8 - meta_len;
    // Well inside the data region: after the 4-byte `PAR1` magic and before the footer.
    let target = 4 + (footer_start - 4) / 2;
    assert!(
        target + 64 < footer_start,
        "the corruption must land in data pages, not metadata \
         (target {target}, footer starts {footer_start})"
    );
    for b in &mut bytes[target..target + 64] {
        *b ^= 0xFF;
    }
    std::fs::write(&pq, &bytes).unwrap();
    std::fs::set_permissions(&pq, original).unwrap();
}
