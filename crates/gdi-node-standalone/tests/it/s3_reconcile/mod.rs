//! Integration tests for the S3 bucket monitor, driven entirely by
//! `object_store::memory::InMemory` — no Docker / no real S3.
//!
//! Each test seeds an in-memory bucket with a real `{id}.tar.c4gh` (encrypted to
//! the node identity, exactly like the inbox `tar_c4gh_ingest` test), drives the
//! [`BucketMonitor`] reconcile/readiness directly, and asserts the cache + status
//! index + writeback behaviour. The whole module is gated on the `s3` feature.
//!
//! Split by concern into submodules, each a focused slice of the same `it` test
//! binary (no new top-level `tests/*.rs`):
//!   * [`reconcile`]     — core ingest/visibility/status-writeback happy paths.
//!   * [`tombstone`]     — removal, hide/visible flips, and eviction races.
//!   * [`multibucket`]   — multi-source/multi-monitor arbitration (cross-channel
//!     ownership, one hung bucket vs. another healthy one).
//!   * [`prefix`]        — key-prefix confinement: what a prefixed channel serves, and
//!     what it neither sees nor requests outside the prefix.
//!   * [`reload`]        — monitor retirement: a channel stands down promptly so a config
//!     reload can replace it, instead of two monitors sharing one bucket.
//!   * [`errors`]        — rejection guards, fail-safe defaults, and injected
//!     transient faults (dependency outages, ENOSPC, slow downloads).
//!   * [`suppression`]   — operator suppression/channel-suppression enforcement.
//!   * [`reingest`]      — targeted bucket retry: the same-ETag short-circuit defeated
//!     by a `dataset reingest <id>` marker.
//!   * [`real_endpoint`] — the `#[ignore]`d real-S3 smoke test.
//!
//! This file (`mod.rs`) holds only what those submodules share: the shared
//! imports, the `Rig` test rig, and the package/config-building helpers.
#![cfg(feature = "s3")]
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
#![expect(
    clippy::similar_names,
    reason = "node/other sk/pk are the standard, clearest crypto naming"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use gdi_node_standalone::ingest_runtime::IngestRuntime;
use gdi_node_standalone::s3::BucketMonitor;
use gdi_node_standalone::state::AppState;
use gdi_node_standalone_core::cache::StatusIndex;
use gdi_node_standalone_core::config::{S3Bucket, ServiceConfig};
use gdi_node_standalone_core::convert::{ConvertOptions, convert_vcf};
use gdi_node_standalone_core::crypt4gh::{PublicKey, encrypt, generate_keypair};
use gdi_node_standalone_core::state::DatasetState;
use object_store::memory::InMemory;
use object_store::path::Path as ObjPath;
use object_store::{ObjectStore, ObjectStoreExt, PutPayload};

use crate::fixtures::{manifest_for, poll_until, write_identity};

mod errors;
mod hooks;
mod keyspace;
mod multibucket;
mod prefix;
mod real_endpoint;
mod reconcile;
mod reingest;
mod reload;
mod suppression;
mod tombstone;

use hooks::HookStore;

const CATALOG: &str = "gdi-aggregated";

// ---------- package construction (mirrors tar_c4gh_ingest.rs) ----------

/// Build a real `{id}.tar.c4gh` (COVID VCF -> staging -> uncompressed TAR ->
/// crypt4gh-encrypt to `recipient`), returning the encrypted bytes.
fn build_tar_c4gh_bytes(work: &Path, id: &str, recipient: &PublicKey) -> Vec<u8> {
    let staging = work.join(id);
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
    std::fs::write(
        staging.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest_for(id, "gdi-aggregated", 1)).unwrap(),
    )
    .unwrap();

    let tar_path = work.join(format!("{id}.tar"));
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

// ---------- test scaffolding ----------

fn test_config(data_dir: &Path, identity: &Path, max_package_bytes: Option<u64>) -> ServiceConfig {
    // Optional pre-download size cap line, exercised by the oversize-rejection test.
    let cap_line = max_package_bytes
        .map(|n| format!("max_package_bytes = {n}\n"))
        .unwrap_or_default();
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"
ingest_concurrency = 2
rescan_interval_seconds = 3600
{cap_line}

[catalogs]
{CATALOG} = "Genome of Europe Aggregated Data"

[beacon]
id = "org.test.beacon"
name = "Test Beacon"

[keys]
identities = ["{}"]
"#,
        data_dir.display(),
        identity.display(),
    );
    let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
    cfg.preflight().unwrap();
    cfg
}

fn bucket_cfg(name: &str, write_status: bool) -> S3Bucket {
    S3Bucket {
        name: name.to_owned(),
        endpoint: Some("http://in-memory".to_owned()),
        bucket: Some("test".to_owned()),
        write_status,
        ..S3Bucket::default()
    }
}

async fn put(store: &Arc<dyn ObjectStore>, key: &str, bytes: Vec<u8>) {
    store
        .put(&ObjPath::from(key), PutPayload::from(bytes))
        .await
        .unwrap();
}

async fn etag_of(store: &Arc<dyn ObjectStore>, key: &str) -> String {
    store
        .head(&ObjPath::from(key))
        .await
        .unwrap()
        .e_tag
        .expect("InMemory assigns an ETag")
}

/// A test rig: a node identity, the data dir, an `InMemory` store, the app state +
/// runtime, and a [`BucketMonitor`] over the store.
struct Rig {
    _tmp: tempfile::TempDir,
    work: PathBuf,
    data_dir: PathBuf,
    node_pk: PublicKey,
    store: Arc<dyn ObjectStore>,
    state: AppState,
    monitor: BucketMonitor,
    /// A handle to the same ingest runtime the monitor drives, so a test can drain to
    /// quiescence before asserting on a follow-up reconcile (see
    /// [`Rig::await_ingest_quiescent`]).
    runtime: IngestRuntime,
}

impl Rig {
    fn new(store: Arc<dyn ObjectStore>, bucket: S3Bucket) -> Self {
        Self::new_capped(store, bucket, None)
    }

    /// As [`Rig::new`], but with an explicit `max_package_bytes` pre-download size cap.
    fn new_capped(
        store: Arc<dyn ObjectStore>,
        bucket: S3Bucket,
        max_package_bytes: Option<u64>,
    ) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("data");
        let work = tmp.path().join("work");
        let keys = tmp.path().join("keys");
        for d in [&data_dir, &work, &keys] {
            std::fs::create_dir_all(d).unwrap();
        }
        let (node_sk, node_pk) = generate_keypair();
        let identity = keys.join("node.c4gh");
        write_identity(&identity, &node_sk);

        let config = test_config(&data_dir, &identity, max_package_bytes);
        let identities = gdi_node_standalone::identities::NodeIdentities::load(&config).unwrap();
        let state = AppState::new(config, StatusIndex::new(), identities);
        let runtime = IngestRuntime::start(state.clone());
        let monitor =
            BucketMonitor::with_store(Arc::clone(&store), bucket, state.clone(), runtime.clone());

        Self {
            _tmp: tmp,
            work,
            data_dir,
            node_pk,
            store,
            state,
            monitor,
            runtime,
        }
    }

    /// Wait until the ingest runtime is fully quiescent before asserting on
    /// post-publish side effects. See [`crate::fixtures::await_ingest_quiescent`] for
    /// why `poll_until(Visible)` is an insufficient barrier.
    async fn await_ingest_quiescent(&self) {
        crate::fixtures::await_ingest_quiescent(&self.runtime).await;
    }

    /// Wait until `id` is published and the ingest runtime has gone quiescent — the
    /// barrier a test must clear before driving a follow-up `reconcile()`.
    ///
    /// The two halves are inseparable, which is why they are one call. `on_success`
    /// publishes to the cache from inside `process_job`, but `worker_loop` releases the id's
    /// in-flight marker only after `process_job` returns, so `poll_until(Visible)` can return
    /// while the marker is still held. A follow-up reconcile then hits `try_mark_inflight` in
    /// `ingest_runtime::enqueue_s3`, which silently skips the enqueue (debug log, download
    /// discarded, `return false`) rather than queueing behind it. Skipping is right in
    /// production, where the next poll cycle retries, but a test that drives reconcile by hand
    /// has no next cycle: the re-ingest it waits for never happens and it hangs to its
    /// deadline. The window is narrow and widens under load.
    ///
    /// Prefer this over a hand-rolled `poll_until(… Visible)` anywhere in this suite. It is
    /// never wrong to drain, and reaching for the raw poll is how the barrier gets forgotten.
    async fn await_visible(&self, id: &str) {
        poll_until(Duration::from_secs(20), || {
            self.state
                .cache
                .get(id)
                .is_some_and(|e| e.state == DatasetState::Visible)
        })
        .await;
        self.await_ingest_quiescent().await;
    }

    fn standard() -> Self {
        Self::new(Arc::new(InMemory::new()), bucket_cfg("primary", false))
    }

    /// A standard rig whose `max_package_bytes` is `cap`, to drive the pre-download
    /// oversize-package rejection.
    fn standard_capped(cap: u64) -> Self {
        Self::new_capped(
            Arc::new(InMemory::new()),
            bucket_cfg("primary", false),
            Some(cap),
        )
    }

    /// Seed a real `{id}.tar.c4gh` (+ optional state sidecar) into the bucket,
    /// returning its `ETag`.
    async fn seed_package(&self, id: &str, state: Option<&str>) -> String {
        let bytes = build_tar_c4gh_bytes(&self.work, id, &self.node_pk);
        put(&self.store, &format!("{id}.tar.c4gh"), bytes).await;
        if let Some(s) = state {
            put(
                &self.store,
                &format!("{id}.state.json"),
                format!(r#"{{"state":"{s}"}}"#).into_bytes(),
            )
            .await;
        }
        etag_of(&self.store, &format!("{id}.tar.c4gh")).await
    }

    fn status_state(&self, id: &str) -> Option<DatasetState> {
        let status = self.state.status.lock().unwrap();
        status.get(id).map(|e| e.state)
    }
}
