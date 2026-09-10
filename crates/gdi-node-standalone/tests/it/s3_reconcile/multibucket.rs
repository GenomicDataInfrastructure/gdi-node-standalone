//! Multi-source / multi-monitor arbitration: cross-channel (inbox vs. bucket)
//! first-claimant ownership, and one hung bucket timing out without blocking the
//! startup reconcile of another healthy bucket.

use super::*;

/// Cross-channel collision: the inbox claims an id first; the same id presented
/// in a bucket is skipped-with-warning while the inbox owns it (no re-ingest, the
/// channel stays `inbox`).
#[tokio::test]
async fn cross_channel_first_claimant_owns_the_id() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let inbox = tmp.path().join("inbox");
    let work = tmp.path().join("work");
    let keys = tmp.path().join("keys");
    for d in [&data_dir, &inbox, &work, &keys] {
        std::fs::create_dir_all(d).unwrap();
    }
    let (node_sk, node_pk) = generate_keypair();
    let identity = keys.join("node.c4gh");
    write_identity(&identity, &node_sk);

    // A config with both an inbox and, logically, an S3 bucket channel.
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"
inbox = "{}"
ingest_concurrency = 2
rescan_interval_seconds = 3600

[catalogs]
{CATALOG} = "Genome of Europe Aggregated Data"

[beacon]
id = "org.test.beacon"
name = "Test Beacon"

[keys]
identities = ["{}"]
"#,
        data_dir.display(),
        inbox.display(),
        identity.display(),
    );
    let config = ServiceConfig::from_toml_str(&toml).unwrap();
    config.preflight().unwrap();
    let identities = gdi_node_standalone::identities::NodeIdentities::load(&config).unwrap();
    let state = AppState::new(config, StatusIndex::new(), identities);
    let runtime = IngestRuntime::start(state.clone());

    let id = "GDI-EE-UTARTU-20260409143052850";

    // Drop the package into the inbox + a visible sidecar, and ingest it (the
    // inbox is the first claimant).
    let inbox_bytes = build_tar_c4gh_bytes(&work, id, &node_pk);
    std::fs::write(inbox.join(format!("{id}.tar.c4gh")), inbox_bytes).unwrap();
    std::fs::write(
        inbox.join(format!("{id}.state.json")),
        br#"{"state":"visible"}"#,
    )
    .unwrap();
    runtime.scan_once().await;
    poll_until(Duration::from_secs(20), || {
        state
            .cache
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;
    {
        let status = state.status.lock().unwrap();
        assert_eq!(
            status.get(id).unwrap().channel,
            "inbox",
            "inbox is first claimant"
        );
    }

    // Now present the same id in a bucket and reconcile via a monitor sharing the
    // runtime: it must be skipped (the inbox owns it), with no channel change.
    let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    let bucket_bytes = build_tar_c4gh_bytes(&work, id, &node_pk);
    put(&store, &format!("{id}.tar.c4gh"), bucket_bytes).await;
    put(
        &store,
        &format!("{id}.state.json"),
        br#"{"state":"visible"}"#.to_vec(),
    )
    .await;
    let monitor = BucketMonitor::with_store(
        Arc::clone(&store),
        bucket_cfg("primary", false),
        state.clone(),
        runtime.clone(),
    );
    monitor.reconcile().await;
    // Deterministic: reconcile is synchronous for the skip decision (the bucket sees an
    // owned id and returns immediately without enqueuing). Assert the channel has not
    // changed without any sleep.
    let status = state.status.lock().unwrap();
    assert_eq!(
        status.get(id).unwrap().channel,
        "inbox",
        "the bucket re-presentation is skipped; inbox keeps ownership"
    );
}

/// A hung or slow bucket times out and is marked unhealthy without blocking the startup
/// reconcile of a healthy bucket. Awaiting each bucket sequentially with no timeout would let
/// one hung bucket stall boot for every provider. A shared state and runtime feed both
/// monitors, as `main` does.
#[tokio::test]
async fn hung_bucket_times_out_without_blocking_startup() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let keys = tmp.path().join("keys");
    for d in [&data_dir, &keys] {
        std::fs::create_dir_all(d).unwrap();
    }
    let (node_sk, _node_pk) = generate_keypair();
    let identity = keys.join("node.c4gh");
    write_identity(&identity, &node_sk);
    let config = test_config(&data_dir, &identity, None);
    let identities = gdi_node_standalone::identities::NodeIdentities::load(&config).unwrap();
    let state = AppState::new(config, StatusIndex::new(), identities);
    let runtime = IngestRuntime::start(state.clone());

    // A healthy (empty) bucket + a bucket whose list hangs far past the timeout.
    let good: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    // Its `list` sleeps far past the readiness timeout, then errors — modelling a hung
    // provider bucket. The timeout must pre-empt the sleep.
    let hung = HookStore::new("SlowListStore")
        .on_list(|_| {
            Box::pin(async {
                tokio::time::sleep(Duration::from_secs(30)).await;
                Some(HookStore::denied("list", &ObjPath::from("hung")))
            })
        })
        .into_store();
    let good_monitor = BucketMonitor::with_store(
        good,
        bucket_cfg("good", false),
        state.clone(),
        runtime.clone(),
    );
    let hung_monitor = BucketMonitor::with_store(
        hung,
        bucket_cfg("hung", false),
        state.clone(),
        runtime.clone(),
    );

    let start = Instant::now();
    BucketMonitor::reconcile_all_for_readiness(
        &[good_monitor, hung_monitor],
        Duration::from_millis(200),
        8,
    )
    .await;
    let elapsed = start.elapsed();

    // The 200 ms per-bucket timeout bounds it, not the hung bucket's 30 s sleep.
    assert!(
        elapsed < Duration::from_secs(5),
        "startup must not block on the hung bucket; took {elapsed:?}"
    );

    let health = state.readiness.channel_health_snapshot();
    assert_eq!(
        health.get("good").copied(),
        Some(true),
        "the healthy bucket reconciles despite the hung one"
    );
    assert_eq!(
        health.get("hung").copied(),
        Some(false),
        "the hung bucket is marked unhealthy on timeout"
    );
}
