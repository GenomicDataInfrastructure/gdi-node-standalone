//! The optional, `#[ignore]`d real-S3 smoke test (minio / Garage / Ceph RGW).
use super::*;

/// Optional real-endpoint smoke test (minio / Garage / Ceph RGW), `#[ignore]` by
/// default and skipped unless `GDI_TEST_S3_ENDPOINT` is set.
///
/// This is the integration coverage for the S3 profile: the `s3` feature without vault or
/// pme. The rig uses inline bucket credentials and a file-based identity, and the whole file
/// is `#![cfg(feature = "s3")]`, so the build under test carries no Vault or PME code.
///
/// The maintained route is `scripts/e2e/run-full.sh` (`ci-local.sh e2e-full`): it boots
/// the backends, exports every var below, and sets `GDI_TEST_REQUIRED=1` so a missing
/// one panics instead of skipping to a green. The snippet below is the by-hand route.
///
/// Spin up a backend and a bucket, then run:
/// ```text
/// docker run -d --name minio -p 19000:9000 \
///   -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin \
///   minio/minio server /data
/// # (create the bucket, e.g. via mc: `mc mb local/gdi-test`)
/// GDI_TEST_S3_ENDPOINT=http://127.0.0.1:19000 \
/// GDI_TEST_S3_BUCKET=gdi-test \
/// GDI_TEST_S3_KEY=minioadmin GDI_TEST_S3_SECRET=minioadmin \
/// # GDI_TEST_S3_REGION=garage as well, against Garage \
///   cargo test --features s3 --test it -- --ignored real_endpoint
/// ```
/// The same invocation works against any S3-compatible endpoint, including a real Ceph RGW,
/// by pointing `GDI_TEST_S3_*` at it. There is no Compose `ceph` profile; see the note at the
/// end of `docker-compose.yml`. The client is endpoint-agnostic, so this exercises the same
/// code path as `InMemory` while confirming the real signing, path-style and ranged-GET stack
/// against a live S3 service.
#[tokio::test]
#[ignore = "requires a real S3 endpoint via GDI_TEST_S3_ENDPOINT"]
async fn real_endpoint_round_trip() {
    let Some(endpoint) = test_util::endpoint_env("GDI_TEST_S3_ENDPOINT") else {
        return;
    };
    // Install the ring rustls provider (no-op if already installed) so an https
    // endpoint handshakes; harmless for http.
    gdi_node_standalone::preflight::install_crypto_provider();

    let bucket_name = std::env::var("GDI_TEST_S3_BUCKET").unwrap_or_else(|_| "gdi-test".to_owned());
    let key = std::env::var("GDI_TEST_S3_KEY").ok();
    let secret = std::env::var("GDI_TEST_S3_SECRET").ok();
    // Garage validates the region in the SigV4 signature (its `s3_region`, "garage" in
    // compose/garage.toml), so leaving this at the default makes every request fail to
    // authenticate. minio accepts any region.
    let region = std::env::var("GDI_TEST_S3_REGION").ok();
    let allow_http = endpoint.starts_with("http://");

    let bucket = S3Bucket {
        name: "real".to_owned(),
        endpoint: Some(endpoint),
        bucket: Some(bucket_name),
        path_style: true,
        allow_http,
        access_key_id: key,
        secret_access_key: secret,
        region,
        write_status: true,
        ..S3Bucket::default()
    };
    // Build the real object store via the production builder (the test seam shares
    // the same monitor code with InMemory).
    let store = gdi_node_standalone::s3::build_object_store(&bucket).expect("build real S3 client");
    let rig = Rig::new(Arc::clone(&store), bucket);

    let id = "GDI-EE-UTARTU-20260409143052999";
    // Clean any leftover objects from a prior run.
    for k in [
        format!("{id}.tar.c4gh"),
        format!("{id}.state.json"),
        format!("_status/{id}.json"),
    ] {
        let _ = store.delete(&ObjPath::from(k)).await;
    }

    let etag = rig.seed_package(id, Some("visible")).await;
    rig.monitor.reconcile().await;
    // 30s rather than the 20s `Rig::await_visible` bakes in: this is the one test that
    // crosses a real network to a live endpoint. Hence the explicit drain below.
    poll_until(Duration::from_secs(30), || {
        rig.state
            .cache
            .get(id)
            .is_some_and(|e| e.state == DatasetState::Visible)
    })
    .await;
    // Drain before the follow-up reconcile: `poll_until(Visible)` returns while the
    // worker may still hold the id's in-flight marker, and an in-flight id makes
    // `enqueue_s3`/`ingest_new` skip silently.
    rig.await_ingest_quiescent().await;
    rig.monitor.reconcile().await;

    let body = store
        .get(&ObjPath::from(format!("_status/{id}.json")))
        .await
        .expect("a _status object was written")
        .bytes()
        .await
        .unwrap();
    let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(obj["state"], "visible");
    assert_eq!(obj["source_signature"], etag);

    // Cleanup.
    for k in [
        format!("{id}.tar.c4gh"),
        format!("{id}.state.json"),
        format!("_status/{id}.json"),
    ] {
        let _ = store.delete(&ObjPath::from(k)).await;
    }
}
