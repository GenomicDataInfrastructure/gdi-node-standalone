//! Back-pressure / bounded-pool integration test.
//!
//! Floods `IngestRuntime` with more datasets than it has workers and verifies the three
//! properties of a bounded worker pool:
//!
//! 1. Bounded concurrency: the number of actively-processing workers
//!    (`test_active_count()`) never exceeds `ingest_concurrency`.
//! 2. No duplication: the claimed set (`test_inflight_count()`) never exceeds the
//!    distinct-id count, which is the `HashSet` dedup invariant.
//! 3. Clean drain: every flooded job completes and lands Visible, with the claim set
//!    draining back to 0.
//!
//! The ceiling assertion is not timing-sensitive. `test_active_count()` is incremented when
//! a worker picks a job off the queue and decremented when it finishes, and with
//! `ingest_concurrency` workers each holding at most one job the value cannot structurally
//! exceed `ingest_concurrency`, whatever the sampling timing. Only an unbounded spawn trips
//! it. The claimed set in assertion 2 is a different quantity, queued plus processing, and
//! can legitimately reach the flood size.
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::path::Path;
use std::time::{Duration, Instant};

use gdi_node_standalone::identities::NodeIdentities;
use gdi_node_standalone::ingest_runtime::IngestRuntime;
use gdi_node_standalone::state::AppState;
use gdi_node_standalone_core::cache::StatusIndex;
use gdi_node_standalone_core::config::ServiceConfig;
use gdi_node_standalone_core::state::DatasetState;

use crate::fixtures::place_covid_staging_into_inbox;

/// A minimal valid service config with a configurable `ingest_concurrency`.
fn test_config(data_dir: &Path, inbox: &Path, concurrency: usize) -> ServiceConfig {
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"
inbox = "{}"
ingest_concurrency = {concurrency}
rescan_interval_seconds = 3600

[catalogs]
gdi-aggregated = "Genome of Europe Aggregated Data"

[beacon]
id = "org.test.beacon"
name = "Test Beacon"
"#,
        data_dir.display(),
        inbox.display(),
    );
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    cfg.preflight().unwrap();
    cfg
}

/// Flood a small worker pool (`ingest_concurrency = 2`) with 7 distinct datasets
/// in a single scan, poll the two seams continuously while they process, then
/// drain and assert every dataset landed Visible.
///
/// Three assertions, none of them timing-sensitive (see the module doc):
///
/// 1. Bounded concurrency: `test_active_count() <= CONCURRENCY` on every poll, so the
///    actively-processing worker count never exceeds the pool size. This catches an
///    unbounded spawn.
/// 2. Dedup ceiling: `test_inflight_count() <= DATASET_COUNT` on every poll, so each
///    distinct id appears at most once in the claim `HashSet`. This catches a re-enqueue.
/// 3. Clean drain and completion: the claim set drains to 0 within a two-minute budget, so
///    no job is lost or wedged, and every dataset is then Visible in the cache and the
///    status index.
#[tokio::test]
async fn flooded_pool_stays_bounded_and_drains_every_job_clean() {
    const CONCURRENCY: usize = 2;
    const DATASET_COUNT: usize = 7;

    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&inbox).unwrap();

    // Build the dataset IDs and place visible-sidecar staging dirs into the inbox.
    let ids: Vec<String> = (1..=DATASET_COUNT)
        .map(|i| format!("GDI-EE-UTARTU-2026041900000000{i}"))
        .collect();

    for id in &ids {
        place_covid_staging_into_inbox(&inbox, id, "gdi-aggregated");
        // Each dataset gets a `visible` sidecar so it lands in DatasetState::Visible.
        std::fs::write(
            inbox.join(format!("{id}.state.json")),
            br#"{"state":"visible"}"#,
        )
        .unwrap();
    }

    let config = test_config(&data_dir, &inbox, CONCURRENCY);
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
    let runtime = IngestRuntime::start(state.clone());

    // Enqueue all datasets with a single scan.
    runtime.scan_once().await;

    // Poll the inflight count continuously until the runtime has drained to zero.
    //
    // Assertion (1): the count never exceeds DATASET_COUNT, so each id appears at most once
    // in the inflight HashSet. It fires on every poll, so a re-enqueue is caught at once.
    //
    // Assertion (2): the count eventually reaches 0 within 2 minutes.
    let deadline = Instant::now() + Duration::from_mins(2);
    loop {
        // Assertion (1): active workers never exceed the configured pool size.
        let active = runtime.test_active_count();
        assert!(
            active <= CONCURRENCY,
            "active worker count {active} exceeded ingest_concurrency {CONCURRENCY} \
             — the worker pool is not bounded (unbounded-spawn regression)"
        );
        // Assertion (2): the claim set never exceeds the distinct-id count.
        let count = runtime.test_inflight_count();
        assert!(
            count <= DATASET_COUNT,
            "inflight count {count} exceeded submitted dataset count {DATASET_COUNT} \
             — dedup invariant violated (an id was enqueued more than once)"
        );
        if count == 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "runtime did not drain within 2 min (inflight count still {count})"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // Assertion (3): all datasets processed successfully and are Visible.
    // A job lost in the queue or completed with an error would fail here.
    for id in &ids {
        let entry = state.cache.get(id);
        assert!(
            entry.is_some_and(|e| e.state == DatasetState::Visible),
            "dataset {id} was not found in the cache as Visible after draining \
             — bounded-concurrency + clean-drain under flood failed"
        );
    }

    // Confirm the status index matches (inbox channel, no error).
    {
        let status = state.status.lock().unwrap();
        for id in &ids {
            let e = status
                .get(id)
                .unwrap_or_else(|| panic!("no status entry for {id}"));
            assert_eq!(e.state, DatasetState::Visible, "status mismatch for {id}");
            assert_eq!(e.channel, "inbox", "channel mismatch for {id}");
            assert!(e.error_message.is_none(), "unexpected error for {id}");
        }
    }
}

/// The stuck-ingest gauge reads the runtime's own markers: an id the runtime marks
/// in flight is visible on `AppState::ingest_inflight` with the instant it was marked,
/// re-marking keeps the original stamp (so a retry cannot reset the age), and clearing
/// removes it. This is the link between `IngestRuntime` and the sampler that renders
/// `gdi_ingest_inflight_oldest_age_seconds`; the sampler's arithmetic has its own unit
/// test, the seed its own endpoint test.
#[tokio::test]
async fn inflight_markers_are_shared_with_the_state_and_stamped_once() {
    const ID: &str = "GDI-EE-UTARTU-20260903120000001";
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&inbox).unwrap();
    let config = test_config(&data_dir, &inbox, 1);
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
    let runtime = IngestRuntime::start(state.clone());

    let before = Instant::now();
    assert!(runtime.test_mark_inflight(ID));
    let stamped = state.ingest_inflight.lock().unwrap()[ID];
    assert!(stamped >= before && stamped <= Instant::now());

    assert!(
        !runtime.test_mark_inflight(ID),
        "a second mark must be refused"
    );
    assert_eq!(
        state.ingest_inflight.lock().unwrap()[ID],
        stamped,
        "a refused re-mark must not reset the stamp"
    );

    runtime.test_clear_inflight(ID);
    assert!(state.ingest_inflight.lock().unwrap().is_empty());
}
