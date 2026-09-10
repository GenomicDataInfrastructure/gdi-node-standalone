//! A bucket channel confined to a key `prefix`.
//!
//! The reconcile keeps addressing the flat [`gdi_node_standalone_core::s3_layout`] names
//! (`{id}.tar.c4gh`, `{id}.state.json`, `_sync_marker.json`, `_status/{id}.json`), and the
//! store built from the connection params applies the prefix. Two things are asserted: the
//! channel still works through that store, and everything outside the prefix is both
//! invisible and never requested. The second is the security claim, since the deployment this
//! exists for is a bucket shared with unrelated data such as database backups.
//!
//! Both tests drive the monitor over `scope_to_prefix`, the same wrapper
//! `build_object_store` applies in production, rather than a hand-rolled prefixing store.
use super::*;
use gdi_node_standalone_core::s3_conn::scope_to_prefix;

/// The deployment's prefix: `gdi-node-storage/` beside `backups/` in one bucket.
const PREFIX: &str = "gdi-node-storage/";

/// A bucket descriptor confined to [`PREFIX`].
fn prefixed_bucket(name: &str) -> S3Bucket {
    S3Bucket {
        prefix: PREFIX.to_owned(),
        ..bucket_cfg(name, false)
    }
}

/// A package under the prefix ingests and serves, while the rest of the bucket stays
/// invisible to the channel: a co-tenant `backups/` object, and a well-formed package at the
/// bucket root.
///
/// The root package is the decoy that makes this fail if the prefix stops being applied. An
/// unscoped listing would ingest it, where a `backups/`-only test would keep passing.
#[tokio::test]
async fn a_package_under_the_prefix_serves_and_the_rest_of_the_bucket_is_invisible() {
    let raw: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    let rig = Rig::new(
        scope_to_prefix(Arc::clone(&raw), PREFIX),
        prefixed_bucket("primary"),
    );

    let inside = "GDI-EE-UTARTU-20260409143052901";
    let outside = "GDI-EE-UTARTU-20260409143052902";
    // Seeded through the rig's (scoped) store, so it lands under the prefix.
    rig.seed_package(inside, Some("visible")).await;
    assert!(
        raw.head(&ObjPath::from(format!("{PREFIX}{inside}.tar.c4gh")))
            .await
            .is_ok(),
        "the seeded package must really be under the prefix, or this test proves nothing"
    );

    // The co-tenant objects, written to the bucket root through the unscoped store.
    put(&raw, "backups/base/wal-000001.gz", b"postgres".to_vec()).await;
    let decoy = build_tar_c4gh_bytes(&rig.work, outside, &rig.node_pk);
    put(&raw, &format!("{outside}.tar.c4gh"), decoy).await;
    put(
        &raw,
        &format!("{outside}.state.json"),
        br#"{"state":"visible"}"#.to_vec(),
    )
    .await;

    rig.monitor.reconcile().await;
    rig.await_visible(inside).await;

    assert!(
        rig.state.cache.get(outside).is_none(),
        "a package at the bucket root must not be ingested by a prefix-confined channel"
    );
    assert!(
        rig.status_state(outside).is_none(),
        "the channel must not even record a status entry for an object outside its prefix"
    );
}

/// A credential that can only see the prefix does not break the channel.
///
/// The store refuses every request whose key falls outside [`PREFIX`] with the
/// `AccessDenied` such a credential would produce — the root `ListBucket` included. The
/// channel must still reach `visible`, which it can only do by never making one: this is
/// the assertion behind "scope the node's S3 credential" being a usable control rather
/// than a way to take the node down.
#[tokio::test]
async fn a_credential_scoped_to_the_prefix_does_not_break_the_channel() {
    /// Whether `path` falls outside the grant.
    ///
    /// The grant is compared against `PREFIX` and its trailing-slash-free form:
    /// `object_store::path::Path` normalizes a trailing delimiter away, so the listing
    /// arrives here as `gdi-node-storage`, not `gdi-node-storage/`. That is an API-level
    /// spelling only — the S3 client re-appends the delimiter when it builds the
    /// `ListObjectsV2` query (`client/list.rs`), so the wire request a real bucket policy
    /// sees is `prefix=gdi-node-storage/` and an `s3:prefix` condition still matches.
    fn outside(path: &ObjPath) -> bool {
        let p = path.as_ref();
        !(p.starts_with(PREFIX) || p == PREFIX.trim_end_matches('/'))
    }

    let store = HookStore::new("PrefixScopedCredential")
        .on_get(|location| {
            let denied = outside(location).then(|| HookStore::denied("get", location));
            Box::pin(async move { denied })
        })
        .on_put(|location| outside(location).then(|| HookStore::denied("put", location)))
        .on_list(|prefix| {
            // `None` is a root listing; `Some(p)` must be inside the granted prefix.
            let denied = prefix
                .is_none_or(outside)
                .then(|| HookStore::denied("list", prefix.unwrap_or(&ObjPath::default())));
            Box::pin(async move { denied })
        })
        .into_store();

    let rig = Rig::new(scope_to_prefix(store, PREFIX), prefixed_bucket("primary"));
    let id = "GDI-EE-UTARTU-20260409143052903";
    rig.seed_package(id, Some("visible")).await;

    rig.monitor.reconcile().await;
    rig.await_visible(id).await;

    assert_eq!(
        rig.state.cache.get(id).map(|e| e.state),
        Some(DatasetState::Visible),
        "a prefix-scoped credential must serve the channel, not break it"
    );
}

/// The nested-key diagnostic (`note_nested_dataset_key`) latches: a correctly-named package
/// one segment below the keyspace this channel polls is warned about once per channel, not
/// once per poll. The offending keys are re-listed on every pass, and a warning that repeats
/// is a warning nobody reads.
#[test]
fn a_package_below_the_keyspace_is_warned_about_once_not_once_per_poll() {
    let (_result, logs) = test_util::capture_json_logs_flat(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let raw: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
            let rig = Rig::new(
                scope_to_prefix(Arc::clone(&raw), PREFIX),
                prefixed_bucket("primary"),
            );
            // The writer set one prefix level deeper than the channel polls.
            put(
                &raw,
                &format!("{PREFIX}provider-a/GDI-EE-UTARTU-20260409143052904.tar.c4gh"),
                b"not really a package".to_vec(),
            )
            .await;
            for _ in 0..3 {
                rig.monitor.reconcile().await;
            }
        });
    });
    let warnings = logs
        .lines()
        .filter(|l| l.contains("sits below the keyspace"))
        .count();
    assert_eq!(
        warnings, 1,
        "three polls over a standing nested key must warn exactly once: {logs}"
    );
    assert!(
        logs.contains("GDI-EE-UTARTU-20260409143052904"),
        "the warning names the dataset that will never be ingested: {logs}"
    );
}
