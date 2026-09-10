//! The tool's always-on S3 object operations (`upload` / `download` / `list`).
//!
//! Unlike the service's `s3` feature, the tool always links `object_store` and the
//! `ring`/rustls stack, because it is the networked binary. The bucket layout is flat at
//! the root: `{id}.tar.c4gh` (the package), `{id}.state.json` (the visibility sidecar),
//! `_sync_marker.json` (the change marker), and the node-written `_status/*` objects,
//! which the tool ignores on `list`.
//!
//! Each operation is a CLI-independent library function generic over
//! `Arc<dyn ObjectStore>`, so tests drive them with `object_store::memory::InMemory` and
//! need no Docker. `cmd_upload` / `cmd_download` / `cmd_list` are the thin clap wrappers.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use futures::stream::{StreamExt as _, TryStreamExt as _};
use gdi_node_standalone_core::config::{Profile, ProfileS3};
use gdi_node_standalone_core::id::is_valid_dataset_id;
use gdi_node_standalone_core::state::DatasetState;
use gdi_node_standalone_core::util::now_rfc3339;
use object_store::path::Path as ObjPath;
use object_store::{ObjectStore, ObjectStoreExt, PutPayload};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::task::JoinSet;

use crate::ToolError;

/// A cheaply-cloneable handle over the object store. `dyn ObjectStore` so the real
/// `AmazonS3` client and the test `InMemory` store share one code path.
pub type Store = Arc<dyn ObjectStore>;

// The S3 object-name contract is defined once in `core::s3_layout` so the tool
// (writer) and the service (reader) cannot drift; re-exported here so the local
// `crate::s3::*` names resolve.
pub use gdi_node_standalone_core::s3_layout::{
    MARKER_KEY, MAX_BUCKET_OBJECTS, OVERLAY_SUFFIX, STATE_SUFFIX, STATUS_PREFIX, StateSidecar,
    TAR_C4GH_SUFFIX,
};

/// The served visibility a dataset's `{id}.state.json` records.
///
/// A fresh `upload` writes `hidden` by default, but the tool also writes
/// `visible`: `publish` sets it, and `upload --replace` preserves (and so
/// re-writes) a dataset's current visibility. Readers treat any value other than
/// `visible`/`hidden` as `hidden` (fail-safe), matching the service's reconcile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    /// `{"state":"visible"}`.
    Visible,
    /// `{"state":"hidden"}` (the upload default, and the fail-safe fallback).
    Hidden,
}

impl Visibility {
    /// The canonical [`DatasetState`] this visibility maps to.
    #[must_use]
    pub const fn to_state(self) -> DatasetState {
        match self {
            Self::Visible => DatasetState::Visible,
            Self::Hidden => DatasetState::Hidden,
        }
    }

    /// The JSON `state` value (delegated to the canonical spelling in
    /// [`DatasetState::as_str`], so the vocabulary lives in one place).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.to_state().as_str()
    }
}

/// One listed dataset: its id and the visibility read from its sidecar.
#[derive(Debug, Clone)]
pub struct ListedDataset {
    /// The dataset id.
    pub id: String,
    /// The visibility from `{id}.state.json` (`hidden` when no sidecar exists).
    pub visibility: Visibility,
}

/// Install the process-wide rustls crypto provider (`ring`) before any TLS.
///
/// Mirrors the service's `preflight::install_crypto_provider`: `object_store` /
/// `reqwest` install no provider of their own (rustls `custom-provider`), so one
/// must be installed explicitly. Idempotent: a second call is a no-op.
pub fn install_crypto_provider() {
    // `install_default` returns Err if a provider is already installed; that is
    // fine (idempotent), so the result is intentionally discarded.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Build an `Arc<dyn ObjectStore>` for the active profile's bucket.
///
/// Endpoint-agnostic (custom `endpoint`, `path_style` and `allow_http`), so Ceph+Rook,
/// Garage and minio are one code path differing only by config, mirroring the service's
/// `build_object_store`. Honours the process-default `ring` provider installed by
/// [`install_crypto_provider`].
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) when `bucket`/`endpoint` are missing, when
/// exactly one of the two credentials is set, or when the builder rejects the
/// configuration.
pub fn build_object_store(s3: &ProfileS3) -> Result<Store, ToolError> {
    build_object_store_with(s3, gdi_node_standalone_core::tls::S3_METADATA_TIMEOUT)
}

/// [`build_object_store`] with an explicit per-request bound.
///
/// The only caller passing anything else is the test proving the tool's default store
/// bounds a stalled endpoint. Waiting out the real timeout would make that test the
/// critical path of the crate's unit suite, and the bound's numeric value is not part of
/// what it verifies, so it is injected instead.
///
/// This is the one place that chooses the bounded core constructor, and
/// [`build_object_store`] is a one-line delegation to it.
///
/// # Errors
///
/// As [`build_object_store`].
fn build_object_store_with(
    s3: &ProfileS3,
    request_timeout: std::time::Duration,
) -> Result<Store, ToolError> {
    // Bounded (per-request timeout plus a small retry budget) is the safe default,
    // because nearly every S3 request the tool makes is small: the upload pre-check HEAD,
    // the listing, the `.state.json` and `_status` objects, `doctor`'s write probe. An
    // endpoint that accepts the TCP connection and then never answers would otherwise hang
    // the tool forever, worst of all in `doctor`, whose job is diagnosing an unreachable
    // bucket. The package body is the one exception; see [`build_package_object_store`].
    gdi_node_standalone_core::s3_conn::build_metadata_object_store_with(
        &conn_params(s3)?,
        request_timeout,
    )
    .map_err(|e| ToolError::user(format!("building S3 client: {e}")))
}

/// The unbounded S3 client, for package bodies only: the multipart upload and the
/// `.tar.c4gh` download.
///
/// Wrapped in [`PackageStore`] so it cannot be passed where a metadata store is expected,
/// or vice versa. A per-request timeout here would be harmful: `object_store` bounds each
/// HTTP request, and in a multipart upload every part is a request, so a bound would abort
/// a legitimate large package on a slow provider uplink.
///
/// # Errors
///
/// As [`build_object_store`].
pub fn build_package_object_store(s3: &ProfileS3) -> Result<PackageStore, ToolError> {
    gdi_node_standalone_core::s3_conn::build_object_store(&conn_params(s3)?)
        .map(PackageStore)
        .map_err(|e| ToolError::user(format!("building S3 client: {e}")))
}

/// The unbounded package-body client, as a newtype.
///
/// It is not a `Store`: the body paths take a `&PackageStore` and everything else takes a
/// `&Store`, so the compiler enforces which client each S3 operation runs on. Swapping
/// them is what this split makes unrepresentable: a bounded body truncates multi-GB
/// uploads, and unbounded metadata hangs forever on a stalled endpoint.
#[derive(Clone)]
pub struct PackageStore(Store);

impl PackageStore {
    /// Wrap an existing store as the package-body client (the test seam: `InMemory`).
    #[must_use]
    pub fn new(store: Store) -> Self {
        Self(store)
    }
}

/// Map a profile's `s3` block to core's connection params. The one place the tool does so,
/// shared by the metadata and package builders, so the two clients can never address a
/// different bucket or sign with different credentials.
fn conn_params(
    s3: &ProfileS3,
) -> Result<gdi_node_standalone_core::s3_conn::S3ConnParams<'_>, ToolError> {
    let endpoint = s3
        .endpoint
        .as_deref()
        .filter(|e| !e.is_empty())
        .ok_or_else(|| ToolError::user("profile s3.endpoint is required for S3 operations"))?;
    let bucket = s3
        .bucket
        .as_deref()
        .filter(|b| !b.is_empty())
        .ok_or_else(|| ToolError::user("profile s3.bucket is required for S3 operations"))?;

    // The prefix must survive `object_store::path::Path` normalization unchanged, as it
    // must on the node; the rule is imported rather than restated. The node rejects a bad
    // prefix at boot. Without this the tool would accept every spelling the node refuses,
    // rewrite it (`a#b/` -> `a%23b/`, `../x/` -> `%2E%2E/x/`, `a//` -> `a/`) and report a
    // target it had not written to. Reader and writer address one keyspace, so a prefix
    // only one of them normalizes is an upload the node never lists.
    gdi_node_standalone_core::config::validate_key_prefix(&s3.prefix).map_err(|why| {
        ToolError::user(format!(
            "profile s3.prefix {:?} is invalid: {why}. It must match the node's \
             [[s3.buckets]].prefix for this channel exactly; the node refuses to boot on \
             this spelling, and a prefix set on only one side means uploads the node never \
             lists",
            s3.prefix
        ))
    })?;

    // The endpoint/region/path-style/signing config is centralized in core so the
    // tool and the service cannot drift (see core::s3_conn).
    Ok(gdi_node_standalone_core::s3_conn::S3ConnParams {
        endpoint,
        bucket,
        // Must equal the node's `[[s3.buckets]].prefix` for this channel: the tool writes
        // the same keyspace the node reads (see core::s3_layout).
        prefix: &s3.prefix,
        region: s3.region.as_deref(),
        path_style: s3.path_style,
        allow_http: s3.allow_http,
        access_key_id: s3.access_key_id.as_deref(),
        secret_access_key: s3.secret_access_key.as_deref(),
    })
}

/// The active profile's `[profiles.<name>.s3]` block, or the uniform "no
/// `[profiles.<name>.s3]` block" error naming the `verb` that needs it. One definition, so
/// the two store openers cannot drift on the message an operator sees.
fn profile_s3<'a>(active: &'a Profile, verb: &str) -> Result<&'a ProfileS3, ToolError> {
    active.s3.as_ref().ok_or_else(|| {
        ToolError::user(format!(
            "the active profile has no [profiles.<name>.s3] block; {verb} needs an S3 bucket"
        ))
    })
}

/// A pair of S3 credentials the wizard collected in this process, for the one run whose
/// environment cannot pick them up from `secrets.env` yet.
///
/// No `Debug`, like [`ProfileS3`]: it must never reach a log line or an error message.
#[derive(Clone)]
pub struct S3Credentials {
    /// The access key id.
    pub access_key_id: String,
    /// The secret access key paired with it.
    pub secret_access_key: String,
}

/// Resolve the active profile's S3 [`Store`], or a uniform "no `[profiles.<name>.s3]`
/// block" error naming the `verb` that needs it.
///
/// Collapses the `profile_s3` + [`install_crypto_provider`] +
/// [`build_object_store`] preamble shared by the plain S3 commands (`list`,
/// `download`, `upload`). Commands whose missing-bucket message is context-
/// specific (e.g. `check`'s `--local` alternative, the S3-owned-id guard in
/// `publish`/`delete`) keep their own bespoke error and call the two functions
/// directly.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) when the active profile has no `[profiles.<name>.s3]`
/// block, or when [`build_object_store`] rejects the configuration.
pub fn open_store(active: &Profile, verb: &str) -> Result<Store, ToolError> {
    let s3 = profile_s3(active, verb)?;
    install_crypto_provider();
    build_object_store(s3)
}

/// The human-readable `S3 bucket …` label for a profile's S3 target: the bucket name (or
/// `<unset>`) plus the endpoint when one is configured.
///
/// Defined once so the `target` field echoed in `--format json` results (`publish`,
/// `delete`) and the operator notes (`upload`, `list`, `download`) cannot drift on the
/// exact wording across the commands.
#[must_use]
pub(crate) fn target_label(s3: &ProfileS3) -> String {
    let bucket = s3.bucket.as_deref().unwrap_or("<unset>");
    // The prefix is part of what is being addressed, so it belongs in the label. The
    // failure it makes legible is a prefix set on one side only, whose symptom is a `list`
    // that reports nothing while the node serves happily.
    let bucket = if s3.prefix.is_empty() {
        bucket.to_owned()
    } else {
        format!("{bucket}/{}", s3.prefix.trim_end_matches('/'))
    };
    match s3.endpoint.as_deref() {
        Some(ep) => format!("S3 bucket {bucket} @ {ep}"),
        None => format!("S3 bucket {bucket}"),
    }
}

/// Resolve the active profile's unbounded [`PackageStore`]: the body client for
/// `upload`/`download` only. The same "no `[profiles.<name>.s3]` block" error as
/// [`open_store`].
///
/// A command that streams a package opens both: this for the body, [`open_store`] for the
/// HEAD pre-check, the visibility sidecar, and the marker bump.
///
/// # Errors
///
/// As [`open_store`].
pub fn open_package_store(active: &Profile, verb: &str) -> Result<PackageStore, ToolError> {
    let s3 = profile_s3(active, verb)?;
    install_crypto_provider();
    build_package_object_store(s3)
}

/// Whether `{id}.tar.c4gh` already exists in the bucket (the upload pre-check).
///
/// Classifies internally rather than handing back the raw `object_store::Error`. A call
/// site that re-wraps it with `ToolError::user` gives exit 1 for an expired STS session's
/// 403 on this HEAD, so a wrapper's `case $? in 4) refresh_creds;; esac` never fires.
/// `classify_object_store_error` must cover the whole S3 surface, and returning `ToolError`
/// binds that here: a new call site cannot wrap a raw error it never sees.
///
/// # Errors
///
/// A classified [`ToolError`] on any failure other than a clean `NotFound`.
pub async fn package_exists(store: &Store, id: &str) -> Result<bool, ToolError> {
    let key = ObjPath::from(format!("{id}{TAR_C4GH_SUFFIX}"));
    match store.head(&key).await {
        Ok(_) => Ok(true),
        Err(object_store::Error::NotFound { .. }) => Ok(false),
        Err(e) => Err(classify_object_store_error(
            &format!("checking package {id}"),
            e,
        )),
    }
}

/// Upload a local package's bytes to the bucket in the required write order: `{id}.tar.c4gh`
/// first, then `{id}.state.json` (`hidden`, upload's default), then `_sync_marker.json`
/// last, so the service only reacts once the data and state are complete.
///
/// Rejects an id already present unless `replace` is set. `--replace` re-uploads the
/// package, to retry an `error`ed id or refresh its bytes, and preserves the dataset's
/// current visibility: it never rewrites a `visible` dataset's sidecar to `hidden`, so a
/// re-upload cannot un-publish a live dataset. The node still ignores a changed package
/// source for a `visible`/`hidden` id, whose content is immutable; this guarantee is about
/// the visibility sidecar, which the node does reconcile.
///
/// Returns the [`Visibility`] the dataset is left in: `Hidden` for a fresh upload, the
/// preserved current value under `replace`. Returned rather than left implicit because the
/// caller has to report it, and a flat `hidden` would be wrong for the
/// `--replace`-of-a-visible-dataset case this function exists to protect.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) when the id already exists without `replace`, when
/// the current visibility cannot be read on a `--replace` (so the upload aborts rather
/// than risk resetting it), or on any PUT/HEAD failure.
pub async fn upload_package(
    store: &Store,
    package_store: &PackageStore,
    id: &str,
    package_path: &Path,
    replace: bool,
) -> Result<Visibility, ToolError> {
    if !replace && package_exists(store, id).await? {
        return Err(ToolError::user(format!(
            "dataset {id} is already present in the bucket (use --replace to re-upload an \
             error'ed id; a live dataset cannot be overwritten)"
        )));
    }

    // 1. The package, first, streamed from disk in parts: a `.tar.c4gh` is never held
    //    whole in RAM, and a multi-GB dataset is not bounded by the single-PUT 5 GiB
    //    ceiling. The multipart upload is aborted on any read or write error, so a failed
    //    upload leaves no committed parts behind (see `stream_file_multipart`).
    let tar_key = ObjPath::from(format!("{id}{TAR_C4GH_SUFFIX}"));
    stream_file_multipart(package_store, &tar_key, package_path).await?;

    // 2. The visibility sidecar, second. A fresh upload is `hidden`, the fail-safe
    //    default, so a new dataset is never auto-published. On `--replace`, preserve the
    //    dataset's current visibility instead of forcing `hidden`: re-uploading to retry
    //    an error'ed id or refresh a package must not un-publish a currently `visible`
    //    dataset, and writing `hidden` here would flip it dark on the node's next
    //    reconcile. A missing or unparseable sidecar reads back `hidden`, and a read
    //    error aborts the upload rather than risk resetting a live dataset's visibility
    //    on a transient fault.
    let visibility = if replace {
        fetch_visibility(store, id).await?
    } else {
        Visibility::Hidden
    };
    let state_key = ObjPath::from(format!("{id}{STATE_SUFFIX}"));
    let state_body = state_json(visibility);
    store
        .put(&state_key, PutPayload::from(state_body.into_bytes()))
        .await
        .map_err(|e| classify_object_store_error(&format!("uploading {state_key}"), e))?;

    // 3. The change marker, last (the write-order bump).
    bump_marker(store).await?;
    Ok(visibility)
}

/// The part size every multipart upload uses. 5 MiB is the S3 minimum for every part
/// but the last, and the size `object_store`'s own writer defaults to.
const PART_SIZE: usize = 5 * 1024 * 1024;

/// How many part uploads may be in flight at once. Peak memory is ~this ×
/// [`PART_SIZE`] regardless of file size; without the bound a fast disk read races
/// ahead of the network and piles up unbounded in-flight `put_part` tasks, so RAM and
/// concurrent-PUT pressure would scale with file size instead.
const MAX_INFLIGHT_PARTS: usize = 16;

/// Stream a local file to `key` via a multipart upload, reading it from disk in
/// bounded chunks so an arbitrarily large `.tar.c4gh` is never buffered whole in
/// memory and is not subject to the single-PUT 5 GiB ceiling.
///
/// Every failure path aborts the upload, best effort, before returning: a read error, a
/// failed part, and a failed `complete`. That is why this drives the `MultipartUpload`
/// handle itself instead of handing it to `object_store::WriteMultipart`. That writer
/// aborts only when `complete()` fails inside `finish()`, has no `Drop` impl, keeps the
/// upload handle private, and `finish()` consumes it, so a part failing while the writer is
/// still being fed returns `Err` with the handle gone and nothing left that could abort.
/// What that leaves behind is invisible: an incomplete multipart upload appears in no
/// `list`, the object never materializes, and S3 bills for every committed part until a
/// lifecycle rule expires it, which for a 20 GB package may be never.
///
/// Parts are handed to `put_part` in file order on this task; the returned futures are what
/// run concurrently. Part numbers are assigned by that synchronous call, so completion
/// order cannot reorder the object.
async fn stream_file_multipart(
    store: &PackageStore,
    key: &ObjPath,
    path: &Path,
) -> Result<(), ToolError> {
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|e| ToolError::user(format!("cannot open package {}: {e}", path.display())))?;
    let total = file.metadata().await.map_or(0, |m| m.len());
    let progress = crate::progress::StreamProgress::new(
        total,
        &format!("uploading {key}"),
        crate::progress::active(),
    );
    let mut upload = store.0.put_multipart(key).await.map_err(|e| {
        classify_object_store_error(&format!("starting multipart upload of {key}"), e)
    })?;

    let mut parts: JoinSet<object_store::Result<()>> = JoinSet::new();
    match stream_parts(&mut *upload, &mut parts, &mut file, key, path, &progress).await {
        Ok(()) => {
            progress.finish();
            Ok(())
        }
        Err(e) => {
            // Cancel what is still in flight before aborting: a part that lands after the
            // abort would re-create the upload this is trying to erase. `JoinSet::shutdown`
            // aborts each task and awaits it, as `WriteMultipart` does.
            parts.shutdown().await;
            let _ = upload.abort().await;
            Err(e)
        }
    }
}

/// The body of [`stream_file_multipart`]: read `file` into [`PART_SIZE`] parts, upload
/// them with at most [`MAX_INFLIGHT_PARTS`] in flight, and complete the upload.
///
/// Split out so every `?` in it funnels through the single abort site in its caller. The
/// alternative is an `abort` before each of five returns, which is the shape that loses
/// one.
async fn stream_parts(
    upload: &mut dyn object_store::MultipartUpload,
    parts: &mut JoinSet<object_store::Result<()>>,
    file: &mut tokio::fs::File,
    key: &ObjPath,
    path: &Path,
    progress: &crate::progress::StreamProgress,
) -> Result<(), ToolError> {
    let mut buf = vec![0u8; PART_SIZE];
    let mut filled = 0usize;
    let mut sent = 0u64;
    loop {
        let n = file
            .read(&mut buf[filled..])
            .await
            .map_err(|e| ToolError::user(format!("reading package {}: {e}", path.display())))?;
        if n == 0 {
            break;
        }
        filled += n;
        sent += n as u64;
        progress.set_position(sent);
        if filled == PART_SIZE {
            let full = std::mem::replace(&mut buf, vec![0u8; PART_SIZE]);
            spawn_part(upload, parts, full, key).await?;
            filled = 0;
        }
    }
    // The trailing partial part (the only one allowed under 5 MiB). An empty tail is not
    // uploaded: a zero-length object completes with no parts at all.
    if filled > 0 {
        buf.truncate(filled);
        spawn_part(upload, parts, buf, key).await?;
    }

    while let Some(joined) = parts.join_next().await {
        part_outcome(joined, key)?;
    }
    upload.complete().await.map_err(|e| {
        classify_object_store_error(&format!("completing multipart upload of {key}"), e)
    })?;
    Ok(())
}

/// Wait for capacity, then hand one part to the upload and spawn its future.
///
/// `put_part` is synchronous and assigns the part number, so calling it here, in file
/// order on one task, is what keeps the assembled object in order.
async fn spawn_part(
    upload: &mut dyn object_store::MultipartUpload,
    parts: &mut JoinSet<object_store::Result<()>>,
    payload: Vec<u8>,
    key: &ObjPath,
) -> Result<(), ToolError> {
    while parts.len() >= MAX_INFLIGHT_PARTS {
        match parts.join_next().await {
            Some(joined) => part_outcome(joined, key)?,
            None => break,
        }
    }
    parts.spawn(upload.put_part(PutPayload::from(payload)));
    Ok(())
}

/// Grade one finished part upload: the store's own error class on a failed PUT, and a
/// user error if the task itself died (a panic, or the cancellation of a shutdown).
fn part_outcome(
    joined: Result<object_store::Result<()>, tokio::task::JoinError>,
    key: &ObjPath,
) -> Result<(), ToolError> {
    match joined {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(classify_object_store_error(&format!("uploading {key}"), e)),
        Err(e) => Err(ToolError::user(format!(
            "uploading {key}: a part upload did not finish: {e}"
        ))),
    }
}

/// Upload an **in-memory** package: write the bytes to a `0o700` scratch file, then
/// stream them via [`upload_package`]. A convenience for callers that already hold
/// the `.tar.c4gh` bytes (primarily tests); the production `cmd_upload` path streams
/// straight from the package file so a large package never enters memory.
///
/// # Errors
///
/// Propagates scratch-staging and [`upload_package`] failures.
#[expect(
    clippy::disallowed_methods,
    reason = "stages the package bytes in a 0700 `Scratch` directory that is removed on drop"
)]
pub async fn upload_package_bytes(
    store: &Store,
    package_store: &PackageStore,
    id: &str,
    package_bytes: Vec<u8>,
    replace: bool,
) -> Result<Visibility, ToolError> {
    let scratch = crate::scratch::Scratch::new(&std::env::temp_dir().join(format!("upload-{id}")))
        .map_err(|e| ToolError::user(format!("creating scratch for upload: {e}")))?;
    let path = scratch.path().join("package.tar.c4gh");
    std::fs::write(&path, &package_bytes)
        .map_err(|e| ToolError::user(format!("staging package bytes: {e}")))?;
    upload_package(store, package_store, id, &path, replace).await
}

/// HEAD `{id}.tar.c4gh` and return its `ETag` (the `source_signature` a
/// `_status/{id}.json` is matched against). `None` when the package is absent or the store
/// reports no `ETag`.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) on any failure other than a clean `NotFound`.
pub async fn package_etag(store: &Store, id: &str) -> Result<Option<String>, ToolError> {
    let key = ObjPath::from(format!("{id}{TAR_C4GH_SUFFIX}"));
    match store.head(&key).await {
        Ok(meta) => Ok(meta.e_tag),
        Err(object_store::Error::NotFound { .. }) => Ok(None),
        Err(e) => Err(classify_object_store_error(&format!("checking {key}"), e)),
    }
}

use gdi_node_standalone_core::s3_layout::MAX_CONTROL_OBJECT_BYTES as MAX_STATUS_OBJECT_BYTES;

/// GET a small control object, rejecting one whose advertised size exceeds
/// [`MAX_STATUS_OBJECT_BYTES`] before its body is read; `None` when it is absent.
///
/// Both control-object readers go through here, so the cap cannot be applied to one
/// object and forgotten on the other. `what` names the object in the over-size error.
#[expect(
    clippy::disallowed_methods,
    reason = "the advertised size is checked against `MAX_STATUS_OBJECT_BYTES` immediately above"
)]
async fn get_control_object(
    store: &Store,
    key: &ObjPath,
    what: &str,
) -> Result<Option<Vec<u8>>, ToolError> {
    let result = match store.get(key).await {
        Ok(r) => r,
        Err(object_store::Error::NotFound { .. }) => return Ok(None),
        Err(e) => return Err(classify_object_store_error(&format!("reading {key}"), e)),
    };
    if result.meta.size > MAX_STATUS_OBJECT_BYTES {
        return Err(ToolError::user(format!(
            "{what} {key} is {} bytes, exceeding the {MAX_STATUS_OBJECT_BYTES}-byte cap",
            result.meta.size
        )));
    }
    let bytes = result
        .bytes()
        .await
        .map_err(|e| classify_object_store_error(&format!("reading {key}"), e))?;
    Ok(Some(bytes.to_vec()))
}

/// Read the node-written `_status/{id}.json` writeback object, returning its raw bytes.
/// `None` when absent: the bucket has `write_status` off, or the node has not processed
/// the dataset yet.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) on a GET failure other than `NotFound`, or when the
/// object's advertised size exceeds `MAX_STATUS_OBJECT_BYTES`.
pub async fn read_status_object(store: &Store, id: &str) -> Result<Option<Vec<u8>>, ToolError> {
    let key = ObjPath::from(format!("{STATUS_PREFIX}{id}.json"));
    get_control_object(store, &key, "status object").await
}

/// Bump `_sync_marker.json` to `{"last_modified": "<now rfc3339>"}` (written last
/// after any mutation).
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) on a PUT failure.
pub async fn bump_marker(store: &Store) -> Result<(), ToolError> {
    let body = format!(r#"{{"last_modified":"{}"}}"#, now_rfc3339());
    store
        .put(
            &ObjPath::from(MARKER_KEY),
            PutPayload::from(body.into_bytes()),
        )
        .await
        .map_err(|e| classify_object_store_error(&format!("bumping {MARKER_KEY}"), e))?;
    Ok(())
}

/// Probe that the bucket is writable: PUT a tiny object at the bucket root under a
/// reserved `.doctor-probe-<pid>.<nanos>` key, then DELETE it as best-effort cleanup. Used
/// by `doctor` to surface a read-only or missing-grant token up front.
///
/// The probe targets the root because that is where the tool's writers write
/// (`{id}.tar.c4gh`, `{id}.state.json`, `_sync_marker.json`); they only read the
/// node-reserved `_status/` prefix. Probing under `_status/` would mis-report writability
/// under a strictly prefix-scoped least-privilege policy. The reserved leading-dot key
/// never collides with a real package and both reconcilers ignore it as an unknown root
/// object; on success it is removed, so the probe is side-effect-free.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) when the PUT is denied (a read-only token) or any
/// other write error occurs. A DELETE failure is swallowed, being cleanup only.
pub async fn probe_writable(store: &Store) -> Result<(), ToolError> {
    // Unique per process and nanosecond, so two concurrent `doctor` runs against one
    // bucket cannot PUT or DELETE the same probe key. A second-granularity stamp alone
    // could collide and let one run's cleanup delete the other's.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let key = ObjPath::from(format!(".doctor-probe-{}.{nanos}", std::process::id()));
    store
        .put(&key, PutPayload::from(b"probe".to_vec()))
        .await
        .map_err(|e| {
            classify_object_store_error(
                "S3 bucket is not writable (your token may lack write permission)",
                e,
            )
        })?;
    // Best-effort cleanup; a failed delete does not fail the probe.
    let _ = store.delete(&key).await;
    Ok(())
}

/// Stream `{id}.tar.c4gh` straight to `dest` in constant memory, never holding the whole
/// package in a `Vec`, so a multi-GB package is not buffered in RAM. Used by `cmd_download`
/// and by `cmd_check`, which then reads only the manifest.
///
/// When `max_bytes` is `Some(cap)`, the object's advertised size is checked against the cap
/// before any byte is fetched, and an over-sized object is rejected without touching the
/// disk. `None` means no cap.
///
/// The destination lands at the umask default (typically `0644`), and a `--force` refresh
/// over a file the operator had tightened lands there too, because the scratch file is
/// renamed over it: the body is crypt4gh ciphertext, so its mode protects nothing.
///
/// # Errors
///
/// Returns a [`ToolError`] when the package is absent (`user`, exit 1), the request is
/// denied or unauthenticated (`auth`, exit 4), the request was throttled or
/// retry-exhausted (`transient`, exit 3), the advertised size exceeds `max_bytes` (`user`,
/// exit 1), or on any other GET or write failure (`user`). A failed GET or a rejected cap
/// leaves no partial file: the destination is created only once the body starts streaming,
/// and is removed on a write or stream error.
pub async fn download_package_to_path(
    store: &PackageStore,
    id: &str,
    dest: &std::path::Path,
    max_bytes: Option<u64>,
) -> Result<(), ToolError> {
    let key = ObjPath::from(format!("{id}{TAR_C4GH_SUFFIX}"));
    let result = store
        .0
        .get(&key)
        .await
        .map_err(|e| classify_get_error(&key, id, e))?;
    let total = result.meta.size;
    // Optional pre-download size cap: reject an over-sized object from the store's
    // advertised length before streaming a single byte, so a corrupt or hostile bucket
    // entry cannot fill the operator's disk.
    if let Some(cap) = max_bytes
        && total > cap
    {
        return Err(ToolError::user(format!(
            "package {id}{TAR_C4GH_SUFFIX} is {total} bytes, exceeding the {cap}-byte \
             --max-size cap; not downloaded"
        )));
    }
    let mut stream = result.into_stream();
    let progress = crate::progress::StreamProgress::new(
        total,
        &format!("downloading {id}"),
        crate::progress::active(),
    );

    // Stream into a scratch sibling and rename over `dest` only once the whole body has
    // landed. Writing straight to `dest` truncates it before the first byte arrives, and
    // the failure path below then deletes it, so a `download --force` refresh that lost
    // the connection mid-stream would destroy the copy the operator already had. The
    // previous package is not always re-fetchable. `Scratch` puts the partial on the same
    // filesystem as `dest`, so the rename is atomic, at 0o700, and removes it on drop for
    // every exit including the error paths.
    let scratch = crate::scratch::Scratch::new(dest)?;
    let partial = scratch.path().join("download.part");

    let write = async {
        #[expect(
            clippy::disallowed_methods,
            reason = "not secret, and streamed: the body is crypt4gh CIPHERTEXT of unbounded \
                      length, so 0644 discloses nothing and it cannot go through \
                      write_durable_atomic, which takes a &[u8]. The path is a scratch \
                      sibling inside a 0o700 dir, renamed over `dest` only on success, so a \
                      failed download cannot damage an existing file"
        )]
        let mut file = tokio::fs::File::create(&partial)
            .await
            .map_err(|e| ToolError::user(format!("creating {}: {e}", partial.display())))?;
        let mut sent = 0u64;
        while let Some(chunk) = stream
            .try_next()
            .await
            .map_err(|e| classify_object_store_error(&format!("streaming {key}"), e))?
        {
            file.write_all(&chunk)
                .await
                .map_err(|e| ToolError::user(format!("writing {}: {e}", partial.display())))?;
            sent += chunk.len() as u64;
            // Mid-stream cap: the pre-download check trusts the store's advertised
            // size, but a hostile or buggy backend can under-report it or grow the object
            // between HEAD and GET. Abort as soon as the streamed bytes pass the cap, so
            // --max-size is honoured against the actual body, not the claimed length.
            if let Some(cap) = max_bytes
                && sent > cap
            {
                return Err(ToolError::user(format!(
                    "download of {id}{TAR_C4GH_SUFFIX} passed the {cap}-byte --max-size cap \
                     mid-stream (the store under-reported its size); aborted"
                )));
            }
            progress.set_position(sent);
        }
        file.flush()
            .await
            .map_err(|e| ToolError::user(format!("flushing {}: {e}", partial.display())))?;
        // Durability before the rename: without it a crash can leave `dest` pointing at a
        // renamed-but-empty inode, which is worse than the partial we were avoiding.
        file.sync_all()
            .await
            .map_err(|e| ToolError::user(format!("syncing {}: {e}", partial.display())))?;
        drop(file);
        tokio::fs::rename(&partial, dest).await.map_err(|e| {
            ToolError::user(format!(
                "moving {} into place at {}: {e}",
                partial.display(),
                dest.display()
            ))
        })?;
        if let Some(parent) = dest.parent().filter(|p| !p.as_os_str().is_empty()) {
            gdi_node_standalone_core::util::fsync_dir(parent);
        }
        progress.finish();
        Ok::<(), ToolError>(())
    }
    .await;

    // No cleanup arm for `dest`: it is either untouched (the download failed before the
    // rename) or complete. The partial lives in `scratch`, which removes itself on drop.
    write
}

/// Download only the first `head_bytes` of the package into `dest` via a ranged GET
/// (clamped to the object's size), enough to cover the crypt4gh header + the leading
/// tar member (`manifest.json`).
///
/// `check`/`check --all` only needs the small front member, so this avoids transferring
/// the entire (potentially multi-GB) package payload per id just to read its manifest.
/// The truncated download decrypts cleanly because the manifest reader early-stops after
/// the first member, well before the truncation point.
///
/// # Errors
///
/// A [`ToolError`] when the object is missing/unreadable or `dest` cannot be written.
pub async fn download_package_head_to_path(
    store: &Store,
    id: &str,
    dest: &std::path::Path,
    head_bytes: u64,
) -> Result<(), ToolError> {
    let key = ObjPath::from(format!("{id}{TAR_C4GH_SUFFIX}"));
    let meta = store
        .head(&key)
        .await
        .map_err(|e| classify_get_error(&key, id, e))?;
    // Clamp the range to the object size so a small package (or a `head` shorter than
    // the whole object) is fetched whole rather than requesting past EOF.
    let end = meta.size.min(head_bytes);
    let bytes = store
        .get_range(&key, 0..end)
        .await
        .map_err(|e| classify_get_error(&key, id, e))?;
    #[expect(
        clippy::disallowed_methods,
        reason = "not secret: `bytes` is crypt4gh ciphertext and `dest` is a scratch path \
                  the caller creates and deletes"
    )]
    tokio::fs::write(dest, &bytes)
        .await
        .map_err(|e| ToolError::user(format!("writing {}: {e}", dest.display())))?;
    Ok(())
}

/// Map any `object_store` failure to a classified [`ToolError`], honouring the crate's
/// documented exit-code contract: denied/unauthenticated → `auth` (4),
/// throttled/retry-exhausted → `transient` (3), else `user` (1) plus a remediation hint.
///
/// `op` is a short verb phrase naming the step (`"uploading {key}"`, `"listing bucket"`),
/// used verbatim in the message. `NotFound` is not handled here, because only the caller
/// knows whether an absent object is an error at all, so a caller that cares must match it
/// before delegating.
///
/// Apply this to the whole S3 surface (PUT, multipart, LIST, DELETE, HEAD, GET), not just
/// download: an auth or transient failure on `upload`, `list` or `publish` that exits `1`
/// is indistinguishable from a user error, so automation keyed on exit 3 to retry, or exit
/// 4 to refresh credentials, never fires.
pub(crate) fn classify_object_store_error(op: &str, e: object_store::Error) -> ToolError {
    match e {
        object_store::Error::PermissionDenied { .. }
        | object_store::Error::Unauthenticated { .. } => {
            ToolError::auth(format!("not authorized: {op}: {}", terse(&e)))
        }
        other if is_transient_object_store(&other) => {
            ToolError::transient(format!("{op}: {}", terse(&other)))
        }
        other => {
            // LIST, and a per-key bulk-delete failure, surface a 403 as an untyped
            // `Generic` rather than a typed `PermissionDenied`, so its text is the only
            // signal there.
            if is_denied_object_store(&other) {
                return ToolError::auth(format!("not authorized: {op}: {}", terse(&other)));
            }
            // A hint is keyed off the error text, so it is gated on `Generic` too.
            let hint = generic_error_text(&other).map_or("", |msg| status_hint(&msg));
            ToolError::user(format!("{op}: {}{hint}", terse(&other)))
        }
    }
}

/// An object-store failure's text with any S3 XML error document folded down to its
/// `Code` and `Message`, and the whole original kept for `-v`.
///
/// The provider echoes an XML body on every 4xx and `object_store` puts it verbatim into
/// `Display`, so a denied `list` would print hundreds of characters of `<RequestId>` and
/// `<HostId>` on the single line the tool promises is user-fixable. The actionable part
/// leads either way; this drops the part no provider expects an operator to read.
fn terse(e: &object_store::Error) -> String {
    let text = e.to_string();
    // `split_once`, not byte offsets: the tool bans `str` slicing, which panics on a
    // multibyte boundary, and a provider's `<Message>` is free text that can carry one.
    let Some((head, xml)) = text
        .split_once("<?xml")
        .or_else(|| text.split_once("<Error>"))
    else {
        return text;
    };
    let field = |open: &str, close: &str| -> Option<String> {
        let (_, after) = xml.split_once(open)?;
        let (value, _) = after.split_once(close)?;
        Some(value.trim().to_owned())
    };
    let (Some(code), Some(message)) =
        (field("<Code>", "</Code>"), field("<Message>", "</Message>"))
    else {
        return text;
    };
    crate::output::note(&format!("s3 error body: {xml}"));
    format!("{head}{code}: {message}")
}

/// The `Display` text of an untyped [`object_store::Error::Generic`], or `None` for every
/// other variant. The single gate for text-sniffing an object-store failure.
///
/// `Generic`'s `Display` is `"Generic {store} error: {source}"` and carries no object key,
/// whereas every path-bearing variant (`NotFound`, `AlreadyExists`, `Precondition`,
/// `NotModified`) embeds the key. A dataset id is a timestamp, so an id like
/// `GDI-EE-UTARTU-20260409143040312` contains the substring `403`. Sniffing those variants'
/// text would escalate an ordinary failure to an auth error, or attach a misleading
/// remediation hint.
fn generic_error_text(e: &object_store::Error) -> Option<String> {
    matches!(e, object_store::Error::Generic { .. }).then(|| e.to_string())
}

/// Whether an object-store failure is an untyped (`Generic`) 403 / `AccessDenied`.
fn is_denied_object_store(e: &object_store::Error) -> bool {
    generic_error_text(e).is_some_and(|msg| {
        msg.contains("403") || msg.contains("Forbidden") || msg.contains("AccessDenied")
    })
}

/// Whether an object-store failure means "that key is not there", however the backend
/// spells it. Use this instead of matching [`object_store::Error::NotFound`] wherever an
/// absent object is not an error.
///
/// The typed variant alone is not enough on the delete path. A single `delete` is driven
/// through `delete_stream`, i.e. the S3 `DeleteObjects` bulk API, which answers `200 OK`
/// with per-key `<Error>` elements rather than an HTTP status. AWS omits an element for a
/// key that was already absent (delete is idempotent there), but Garage reports it, and
/// `object_store` maps a per-key error inside a `200` to [`object_store::Error::Generic`]
/// — never to `NotFound`. So a `NotFound`-only match is backend-dependent: it tolerates a
/// missing optional sidecar on AWS and minio and fails on Garage, which is this repo's
/// default Compose backend.
///
/// Keyed on the S3 error **code**, not on `404`, and deliberately so: unlike the other
/// text sniffers here this one must read a `Generic` that *does* embed the object key
/// (`DeleteObjects request failed for key {id}.metadata.json: … (code: NoSuchKey)`), and a
/// dataset id is a timestamp — `GDI-EE-UTARTU-20260404120000000` contains `404`. Matching
/// the status would read "deleted on 4 April" as "absent". `NoSuchKey` cannot occur in a
/// dataset id, so it is the one token that is safe to match against a key-bearing message.
pub(crate) fn is_not_found_object_store(e: &object_store::Error) -> bool {
    matches!(e, object_store::Error::NotFound { .. })
        || generic_error_text(e).is_some_and(|msg| msg.contains("NoSuchKey"))
}

/// Map an `object_store` GET failure for a package download: absent gives a
/// package-specific `user` message, everything else goes via
/// `classify_object_store_error`.
fn classify_get_error(key: &ObjPath, id: &str, e: object_store::Error) -> ToolError {
    match e {
        object_store::Error::NotFound { .. } => {
            ToolError::user(format!("no package {id}{TAR_C4GH_SUFFIX} in the bucket"))
        }
        other => classify_object_store_error(&format!("downloading {key}"), other),
    }
}

/// A short remediation hint for a non-2xx object-store failure, keyed on the HTTP status
/// embedded in the error text (`object_store` 0.13 exposes no typed status). Empty when no
/// known status is present: connectivity errors already carry rich messages, so this
/// targets only genuine non-2xx responses.
fn status_hint(msg: &str) -> &'static str {
    if msg.contains("403") || msg.contains("Forbidden") {
        ". Check the bucket policy and credentials. If you set them via \
         GDI_TOOL__PROFILES__<NAME>__..., confirm <NAME> matches your profile name exactly, \
         with underscores rather than hyphens. Then run `gdi-dataset-tool doctor`"
    } else if msg.contains("404") || msg.contains("NoSuchBucket") {
        ". Check the bucket name and endpoint, then run `gdi-dataset-tool doctor`"
    } else if msg.contains("400") || msg.contains("Bad Request") {
        ". Likely a region, path-style or endpoint misconfiguration; run \
         `gdi-dataset-tool doctor`"
    } else if msg.contains("500") || msg.contains("502") || msg.contains("504") {
        ". Server-side error; retry, then run `gdi-dataset-tool doctor` if it persists"
    } else {
        ""
    }
}

/// Heuristic: whether an `object_store` failure looks transient (retry may fix).
///
/// `object_store` 0.13 has no dedicated transient variant. A throttled or `5xx` request
/// surfaces as [`object_store::Error::Generic`] only after the client's own retry budget is
/// exhausted, with the HTTP status in the wrapped source, so this keys on that `Display`
/// text via [`generic_error_text`]. Kept conservative to keep false positives off the
/// transient (exit-3) path.
fn is_transient_object_store(e: &object_store::Error) -> bool {
    generic_error_text(e).is_some_and(|msg| {
        msg.contains("503")
            || msg.contains("429")
            || msg.contains("Service Unavailable")
            || msg.contains("Too Many Requests")
            || msg.contains("SlowDown")
            || msg.contains("timed out")
            || msg.contains("timeout")
    })
}

/// Where a package key sits: `(containing prefix, dataset id)`, or `None` when the key is
/// not a package at all.
///
/// The prefix is `""` at the bucket root and otherwise everything up to and including the
/// last `/`. [`list_datasets`] recognises root keys only, because a nested key fails its
/// `is_valid_dataset_id` check with the directory still on the id, so this exists to see
/// what that view cannot.
fn dataset_key_location(key: &str) -> Option<(&str, &str)> {
    if key.starts_with(STATUS_PREFIX) || key == MARKER_KEY {
        return None;
    }
    let rest = key.strip_suffix(TAR_C4GH_SUFFIX)?;
    let (prefix, id) = match rest.rfind('/') {
        Some(cut) => rest.split_at(cut + 1),
        None => ("", rest),
    };
    is_valid_dataset_id(id).then_some((prefix, id))
}

/// How many packages sit under each key prefix in the whole bucket (`""` is the root).
///
/// Only `list`'s prefix-desync probe uses this, and only when the profile's own prefixed
/// listing came back empty. It counts nested keys, which is the difference that matters: a
/// writer on `provider-a` against a node on `provider-b` sees its own prefix populated and
/// the root bare, so a root-only probe reports nothing wrong while the node ingests nothing.
///
/// # Errors
///
/// Returns a [`ToolError`] on a listing failure, classified like every other S3 op.
pub(crate) async fn dataset_locations(store: &Store) -> Result<BTreeMap<String, usize>, ToolError> {
    let mut found: BTreeMap<String, usize> = BTreeMap::new();
    let mut seen = 0usize;
    let mut list_stream = store.list(None);
    while let Some(meta) = list_stream.next().await {
        let meta = meta.map_err(|e| classify_object_store_error("listing bucket", e))?;
        seen += 1;
        if seen >= MAX_BUCKET_OBJECTS {
            break;
        }
        if let Some((prefix, _)) = dataset_key_location(meta.location.as_ref()) {
            *found.entry(prefix.to_owned()).or_default() += 1;
        }
    }
    Ok(found)
}

/// List the datasets in the bucket: map each `{id}.tar.c4gh` to its id and read its
/// `{id}.state.json` visibility (`hidden` when no sidecar). Ignores `_status/*`,
/// `_sync_marker.json`, and any unrecognized object (the additive-object rule).
///
/// Returned sorted by id. `list` does not probe the service per id; that is `status`'s
/// job.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) on a listing or sidecar-fetch failure.
pub async fn list_datasets(store: &Store) -> Result<Vec<ListedDataset>, ToolError> {
    // Bound on concurrent (independent) sidecar GETs when resolving visibility below.
    const VISIBILITY_FETCH_CONCURRENCY: usize = 16;

    // Fold the listing as it streams, collecting the ids whose `.tar.c4gh` is present
    // and the set of present sidecars, under a hard object cap: a shared bucket is a
    // co-tenant trust boundary, so a flood must fail this run rather than exhaust memory.
    // The ceiling is the one the node applies on reconcile (defined in
    // `core::s3_layout`), and nothing here collects the listing into an unbounded `Vec`.
    let mut ids: Vec<String> = Vec::new();
    let mut has_sidecar = std::collections::BTreeSet::new();
    let mut seen = 0usize;
    let mut list_stream = store.list(None);
    while let Some(meta) = list_stream.next().await {
        let meta = meta.map_err(|e| classify_object_store_error("listing bucket", e))?;
        if seen >= MAX_BUCKET_OBJECTS {
            return Err(ToolError::user(format!(
                "bucket lists more than {MAX_BUCKET_OBJECTS} objects; refusing to buffer the \
                 whole listing into memory"
            )));
        }
        seen += 1;
        let key = meta.location.as_ref();
        if key.starts_with(STATUS_PREFIX) || key == MARKER_KEY {
            continue;
        }
        if let Some(id) = key.strip_suffix(TAR_C4GH_SUFFIX)
            && is_valid_dataset_id(id)
        {
            ids.push(id.to_owned());
        } else if let Some(id) = key.strip_suffix(STATE_SUFFIX)
            && is_valid_dataset_id(id)
        {
            has_sidecar.insert(id.to_owned());
        }
        // Any other object (e.g. a `{id}.metadata.json` overlay sidecar, which
        // only the node consumes) is ignored.
    }
    ids.sort();
    ids.dedup();

    // Resolve each id's visibility with a bounded number of concurrent (independent)
    // sidecar GETs instead of one network round-trip at a time. `buffer_unordered`
    // reorders completions, so re-sort by id afterwards to keep the documented sorted
    // output. The `has_sidecar` lookup happens up front and only the resulting flag (bool)
    // is moved into each future, so no future borrows the shared set.
    let mut out: Vec<ListedDataset> = futures::stream::iter(ids)
        .map(|id| {
            let present = has_sidecar.contains(&id);
            async move {
                let visibility = if present {
                    fetch_visibility(store, &id).await?
                } else {
                    // No sidecar => hidden (fail-safe).
                    Visibility::Hidden
                };
                Ok::<ListedDataset, ToolError>(ListedDataset { id, visibility })
            }
        })
        .buffer_unordered(VISIBILITY_FETCH_CONCURRENCY)
        .try_collect()
        .await?;
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

/// Fetch + parse `{id}.state.json` into a [`Visibility`]. A missing sidecar, an
/// unparseable body, or any value other than `visible`/`hidden` maps to `hidden`
/// (fail-safe), matching the service's reconcile.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) on a GET failure other than `NotFound`, or when the
/// sidecar's advertised size exceeds [`MAX_STATUS_OBJECT_BYTES`].
pub async fn fetch_visibility(store: &Store, id: &str) -> Result<Visibility, ToolError> {
    let key = ObjPath::from(format!("{id}{STATE_SUFFIX}"));
    // The read is bounded by `get_control_object`: a `.state.json` is a few bytes of JSON,
    // but the bucket is provider-writable, so an unbounded read of a crafted multi-GiB
    // object would OOM the tool.
    let Some(bytes) = get_control_object(store, &key, "state sidecar").await? else {
        return Ok(Visibility::Hidden);
    };
    Ok(parse_visibility(&bytes))
}

/// Parse a `{id}.state.json` body into a [`Visibility`] (`visible`/`hidden`; any
/// other value or a parse error defaults to `hidden`).
fn parse_visibility(bytes: &[u8]) -> Visibility {
    match serde_json::from_slice::<StateSidecar>(bytes) {
        Ok(s) if DatasetState::from_visibility_str(&s.state) == Some(DatasetState::Visible) => {
            Visibility::Visible
        }
        _ => Visibility::Hidden,
    }
}

/// The `{id}.state.json` sidecar body, carrying the `schemaVersion` discriminator:
/// `{"schemaVersion":1,"state":"<state>"[,"force":true]}`.
///
/// Defines the on-wire shape in one place, so every writer (S3 and inbox; upload /
/// publish / unpublish / delete) emits an identical, versioned sidecar. Both readers parse
/// leniently and ignore `schemaVersion`, so it lets a future breaking change to this
/// control object be gated on the version rather than misparsed, matching the
/// `manifestVersion` gate and the CLI JSON's `schemaVersion`.
#[must_use]
pub fn state_sidecar_body(state: &str, force: bool) -> String {
    if force {
        format!(r#"{{"schemaVersion":1,"state":"{state}","force":true}}"#)
    } else {
        format!(r#"{{"schemaVersion":1,"state":"{state}"}}"#)
    }
}

fn state_json(visibility: Visibility) -> String {
    state_sidecar_body(visibility.as_str(), false)
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

    /// The desync probe must see packages the ordinary listing cannot.
    ///
    /// `list_datasets` recognises root keys only, because a nested key keeps its directory
    /// in the stripped id and fails `is_valid_dataset_id`, so a writer on `provider-a`
    /// against a node on `provider-b` sees a populated prefix, a bare root and no warning.
    #[test]
    fn dataset_key_location_sees_nested_packages_and_ignores_everything_else() {
        let id = "GOE-EE-TESTBIO-20260901104140076";
        assert_eq!(
            dataset_key_location(&format!("{id}.tar.c4gh")),
            Some(("", id)),
            "a root package sits under the empty prefix"
        );
        assert_eq!(
            dataset_key_location(&format!("provider-b/{id}.tar.c4gh")),
            Some(("provider-b/", id)),
            "a nested package is what the root-only view misses"
        );
        assert_eq!(
            dataset_key_location(&format!("a/b/c/{id}.tar.c4gh")),
            Some(("a/b/c/", id)),
            "the prefix is everything up to the last slash"
        );
        // Not packages: the node's writeback, the sync marker, sidecars, and anything whose
        // stem is not a dataset id.
        assert_eq!(
            dataset_key_location(&format!("{STATUS_PREFIX}{id}.json")),
            None
        );
        assert_eq!(dataset_key_location(MARKER_KEY), None);
        assert_eq!(dataset_key_location(&format!("{id}{STATE_SUFFIX}")), None);
        assert_eq!(dataset_key_location("notes.txt"), None);
        assert_eq!(dataset_key_location("provider-b/not-an-id.tar.c4gh"), None);
        assert_eq!(dataset_key_location(""), None);
    }

    /// The provider's XML body is folded to Code + Message; everything else is untouched.
    #[test]
    fn terse_folds_an_s3_xml_body_to_its_code_and_message() {
        let xml = object_store::Error::Generic {
            store: "S3",
            source: "Server returned non-2xx status code: 403 Forbidden: <?xml version=\"1.0\" \
                     encoding=\"UTF-8\"?><Error><Code>AccessDenied</Code><Message>Access \
                     Denied.</Message><BucketName>b</BucketName><RequestId>18D1</RequestId>\
                     <HostId>dd90</HostId></Error>"
                .into(),
        };
        let out = terse(&xml);
        assert!(out.contains("403 Forbidden"), "{out}");
        assert!(out.ends_with("AccessDenied: Access Denied."), "{out}");
        assert!(!out.contains("RequestId"), "{out}");
        assert!(!out.contains('<'), "{out}");

        // A failure with no XML body is passed through verbatim.
        let plain = object_store::Error::Generic {
            store: "S3",
            source: "connection refused".into(),
        };
        assert_eq!(terse(&plain), plain.to_string());
    }

    /// The writer refuses every prefix spelling the node refuses to boot on.
    ///
    /// Reader and writer address one keyspace. Accepting them all rewrites the prefix
    /// through `object_store::path::Path` (`a#b/` becomes `a%23b/`, `../x/` becomes
    /// `%2E%2E/x/`, `a//` becomes `a/`) and then reports a target the tool has not written
    /// to: the upload succeeds and the node never lists it.
    ///
    /// Asserted through `conn_params`, the one place the tool turns a profile into S3
    /// connection params, so no verb can reach a store without passing it.
    #[test]
    fn the_writer_refuses_a_prefix_the_node_would_refuse() {
        for bad in ["/leading/", "a//b", "a//", "a/../b", "a#b/", "a b/"] {
            let s3 = super::ProfileS3 {
                endpoint: Some("https://s3.example.org".to_owned()),
                bucket: Some("b".to_owned()),
                prefix: bad.to_owned(),
                ..Default::default()
            };
            // `let Err(..) else`, not `expect_err`: `S3ConnParams` is not `Debug`.
            let Err(err) = super::conn_params(&s3) else {
                panic!("prefix {bad:?} must be refused, as the node refuses it")
            };
            let msg = err.to_string();
            assert!(
                msg.contains("s3.prefix") && msg.contains(bad),
                "the error must name the field and the offending value: {msg}"
            );
        }

        // ...and still accepts the spellings that round-trip, including the deployment's own.
        for good in ["", "gdi-node-storage/", "gdi-node-storage", "a/b/c"] {
            let s3 = super::ProfileS3 {
                endpoint: Some("https://s3.example.org".to_owned()),
                bucket: Some("b".to_owned()),
                prefix: good.to_owned(),
                ..Default::default()
            };
            assert!(
                super::conn_params(&s3).is_ok(),
                "prefix {good:?} reaches the wire unchanged and must be accepted"
            );
        }
    }

    #[tokio::test]
    async fn the_default_store_bounds_a_stalled_endpoint() {
        // The bound is injected at 200 ms rather than waiting the production timeout.
        // The claim is that the tool's default store makes a stall fail instead of hang;
        // the bound's value is not part of that claim, and paying it in real time would
        // make this test the critical path of the crate's unit suite.
        const BOUND: std::time::Duration = std::time::Duration::from_millis(200);

        // `doctor`, `check`, `status`, `publish` and `list` all run against a bucket the
        // provider may have misconfigured, and `doctor` exists to diagnose an endpoint
        // that is not answering. With an unbounded default store, an endpoint that
        // accepts TCP and then stalls hangs the tool forever, with no timeout and no
        // output, which in a pipeline is an unbounded stall rather than a visible hang.
        let endpoint = test_util::stalling_endpoint();
        let s3 = super::ProfileS3 {
            endpoint: Some(endpoint),
            bucket: Some("b".to_owned()),
            region: None,
            path_style: true,
            allow_http: true,
            access_key_id: Some("k".to_owned()),
            secret_access_key: Some("s".to_owned()),
            ..Default::default()
        };
        let store = super::build_object_store_with(&s3, BOUND).unwrap();

        // The outer timeout is slack, not the assertion: if the per-request bound
        // regressed to unbounded, `package_exists` hangs, this fires, and the `is_ok()`
        // below still catches it.
        let bounded = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            super::package_exists(&store, "GDI-EE-UTARTU-1"),
        )
        .await;

        assert!(
            bounded.is_ok(),
            "a stalled endpoint must make the tool's metadata request fail, not hang forever"
        );
        assert!(
            bounded.unwrap().is_err(),
            "the stalled request must surface as an error the caller can report"
        );
    }

    #[test]
    fn status_hint_keys_on_embedded_status() {
        assert!(super::status_hint("downloading x: Generic { 403 Forbidden }").contains("doctor"));
        assert!(super::status_hint("downloading x: 400 Bad Request").contains("misconfiguration"));
        assert!(super::status_hint("downloading x: 502 Bad Gateway").contains("Server-side"));
        assert!(
            super::status_hint("downloading x: connection reset").is_empty(),
            "no known status -> no hint"
        );
    }

    use std::sync::atomic::{AtomicBool, Ordering};

    use async_trait::async_trait;
    use futures::stream::BoxStream;
    use object_store::memory::InMemory;
    use object_store::{
        CopyOptions, GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta,
        PutMultipartOptions, PutOptions, PutResult,
    };

    use super::*;

    /// A valid-looking dataset id for the in-memory store tests.
    fn id(n: u8) -> String {
        format!("GDI-EE-UTARTU-2026040914305283{n}")
    }

    fn mem_store() -> Store {
        Arc::new(InMemory::new())
    }

    async fn get_bytes(store: &Store, key: &str) -> Option<Vec<u8>> {
        match store.get(&ObjPath::from(key)).await {
            Ok(r) => Some(r.bytes().await.unwrap().to_vec()),
            Err(object_store::Error::NotFound { .. }) => None,
            Err(e) => panic!("unexpected get error: {e}"),
        }
    }

    #[tokio::test]
    async fn read_status_object_rejects_oversized_control_object() {
        let store = mem_store();
        let id = id(0);
        let key = format!("{STATUS_PREFIX}{id}.json");

        // A normal (tiny) status object reads back fine.
        store
            .put(
                &ObjPath::from(key.clone()),
                PutPayload::from(b"{}".to_vec()),
            )
            .await
            .unwrap();
        assert_eq!(
            read_status_object(&store, &id).await.unwrap(),
            Some(b"{}".to_vec())
        );

        // An oversized control object, such as a multi-GB `_status/{id}.json` placed by
        // an attacker with shared-bucket write, is rejected on its advertised size rather
        // than buffered whole into RAM.
        let big = vec![b'x'; usize::try_from(MAX_STATUS_OBJECT_BYTES).unwrap() + 1];
        store
            .put(&ObjPath::from(key), PutPayload::from(big))
            .await
            .unwrap();
        let err = read_status_object(&store, &id).await.unwrap_err();
        assert!(err.message.contains("exceeding"), "got: {}", err.message);
    }

    #[tokio::test]
    async fn upload_writes_three_objects_in_write_order() {
        let store = mem_store();
        let dataset = id(0);
        upload_package_bytes(
            &store,
            &PackageStore::new(store.clone()),
            &dataset,
            b"PACKAGE-BYTES".to_vec(),
            false,
        )
        .await
        .unwrap();

        // All three objects present.
        let tar = get_bytes(&store, &format!("{dataset}{TAR_C4GH_SUFFIX}"))
            .await
            .expect("package present");
        assert_eq!(tar, b"PACKAGE-BYTES");

        let state = get_bytes(&store, &format!("{dataset}{STATE_SUFFIX}"))
            .await
            .expect("state sidecar present");
        assert_eq!(parse_visibility(&state), Visibility::Hidden);

        let marker = get_bytes(&store, MARKER_KEY).await.expect("marker present");
        // The marker carries a last_modified timestamp.
        let marker_str = String::from_utf8(marker).unwrap();
        assert!(
            marker_str.contains("last_modified"),
            "marker = {marker_str}"
        );
        assert!(
            marker_str.contains('T'),
            "marker has an rfc3339 time: {marker_str}"
        );
    }

    #[tokio::test]
    async fn second_upload_rejected_without_replace() {
        let store = mem_store();
        let dataset = id(1);
        upload_package_bytes(
            &store,
            &PackageStore::new(store.clone()),
            &dataset,
            b"v1".to_vec(),
            false,
        )
        .await
        .unwrap();
        // A second upload of the same id is rejected.
        let err = upload_package_bytes(
            &store,
            &PackageStore::new(store.clone()),
            &dataset,
            b"v2".to_vec(),
            false,
        )
        .await
        .unwrap_err();
        assert!(err.message.contains("already present"), "{}", err.message);
        // The original package is untouched.
        let tar = get_bytes(&store, &format!("{dataset}{TAR_C4GH_SUFFIX}"))
            .await
            .unwrap();
        assert_eq!(tar, b"v1");
    }

    #[tokio::test]
    async fn replace_re_uploads_the_package() {
        let store = mem_store();
        let dataset = id(2);
        upload_package_bytes(
            &store,
            &PackageStore::new(store.clone()),
            &dataset,
            b"v1".to_vec(),
            false,
        )
        .await
        .unwrap();
        upload_package_bytes(
            &store,
            &PackageStore::new(store.clone()),
            &dataset,
            b"v2".to_vec(),
            true,
        )
        .await
        .unwrap();
        let tar = get_bytes(&store, &format!("{dataset}{TAR_C4GH_SUFFIX}"))
            .await
            .unwrap();
        assert_eq!(tar, b"v2");
    }

    #[tokio::test]
    async fn replace_preserves_visibility_and_does_not_unpublish() {
        // Re-uploading a currently-`visible` dataset with --replace must not rewrite its
        // sidecar to `hidden`, which would un-publish it on the node's next reconcile.
        // The current visibility is preserved.
        let store = mem_store();
        let dataset = id(9);
        upload_package_bytes(
            &store,
            &PackageStore::new(store.clone()),
            &dataset,
            b"v1".to_vec(),
            false,
        )
        .await
        .unwrap();
        // Publish it (simulate an operator `publish`: the sidecar now says visible).
        store
            .put(
                &ObjPath::from(format!("{dataset}{STATE_SUFFIX}")),
                PutPayload::from(state_json(Visibility::Visible).into_bytes()),
            )
            .await
            .unwrap();
        assert_eq!(
            fetch_visibility(&store, &dataset).await.unwrap(),
            Visibility::Visible
        );

        // Re-upload with --replace: the package changes but the visibility is preserved.
        let reported = upload_package_bytes(
            &store,
            &PackageStore::new(store.clone()),
            &dataset,
            b"v2".to_vec(),
            true,
        )
        .await
        .unwrap();
        assert_eq!(
            fetch_visibility(&store, &dataset).await.unwrap(),
            Visibility::Visible,
            "replace must preserve a visible dataset's visibility"
        );
        // The returned value is what the CLI reports to the operator, so it must agree
        // with the sidecar. Returning `()` would leave `cmd_upload` nothing to render but
        // a flat `hidden`, which on this path is wrong and cues a `publish` that can
        // disclose an intentionally hidden dataset. Reporting is downstream of the write.
        assert_eq!(
            reported,
            Visibility::Visible,
            "upload must REPORT the visibility it preserved, not assume hidden"
        );

        // A fresh (non-replace) upload of a new id is still hidden by default.
        let fresh = id(8);
        let reported_fresh = upload_package_bytes(
            &store,
            &PackageStore::new(store.clone()),
            &fresh,
            b"x".to_vec(),
            false,
        )
        .await
        .unwrap();
        assert_eq!(
            fetch_visibility(&store, &fresh).await.unwrap(),
            Visibility::Hidden
        );
        assert_eq!(
            reported_fresh,
            Visibility::Hidden,
            "a fresh upload reports the hidden it wrote"
        );
    }

    #[tokio::test]
    async fn download_to_path_streams_package_bytes() {
        let store = mem_store();
        let dataset = id(5);
        let original = b"\x00\x01\x02crypt4gh-bytes\xff".to_vec();
        upload_package_bytes(
            &store,
            &PackageStore::new(store.clone()),
            &dataset,
            original.clone(),
            false,
        )
        .await
        .unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out.tar.c4gh");
        download_package_to_path(&PackageStore::new(store.clone()), &dataset, &dest, None)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), original);
    }

    #[tokio::test]
    async fn download_head_fetches_only_the_front_and_clamps_to_size() {
        // `check` fetches only the leading manifest bytes via a ranged GET.
        let store = mem_store();
        let dataset = id(8);
        let original = b"HEADmanifestbytes....TAILtailtail".to_vec(); // 33 bytes
        upload_package_bytes(
            &store,
            &PackageStore::new(store.clone()),
            &dataset,
            original.clone(),
            false,
        )
        .await
        .unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("head.tar.c4gh");
        // A head smaller than the object fetches exactly the front bytes.
        download_package_head_to_path(&store, &dataset, &dest, 4)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"HEAD");
        // A head larger than the object clamps to the object size (no past-EOF error).
        download_package_head_to_path(&store, &dataset, &dest, 10_000)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), original);
    }

    #[tokio::test]
    async fn download_to_path_missing_package_errors_and_writes_nothing() {
        let store = mem_store();
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out.tar.c4gh");
        let err = download_package_to_path(&PackageStore::new(store.clone()), &id(6), &dest, None)
            .await
            .unwrap_err();
        assert!(err.message.contains("no package"), "{}", err.message);
        // The GET failed before the file was created, so no partial is left behind.
        assert!(!dest.exists());
    }

    /// `--max-size` is enforced against the body, not just the store's claimed length.
    ///
    /// The pre-download check reads `meta.size`, which is whatever the backend says. A
    /// hostile or buggy store can under-report (or report 0, or grow the object between
    /// the listing and the GET), and the operator's disk-exhaustion guard would then be a
    /// value the attacker controls. The mid-stream check is what makes the cap real.
    ///
    /// Here the store serves the true body but claims the object is one byte, so the
    /// pre-download check waves it through and only the mid-stream accounting can stop it.
    #[tokio::test]
    async fn download_over_cap_aborts_mid_stream_when_the_store_under_reports() {
        let dataset = id(9);
        let original = b"crypt4gh-oversized-bytes".to_vec();
        let real_size = original.len() as u64;
        let store = HookStore::new()
            .tamper_with_get(|result| result.meta.size = 1)
            .into_store();
        upload_package_bytes(
            &store,
            &PackageStore::new(store.clone()),
            &dataset,
            original,
            false,
        )
        .await
        .unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out.tar.c4gh");
        let cap = real_size / 2;
        assert!(cap > 1, "the cap must sit above the lie and below the body");

        let err = download_package_to_path(
            &PackageStore::new(store.clone()),
            &dataset,
            &dest,
            Some(cap),
        )
        .await
        .unwrap_err();

        assert!(
            err.message.contains("mid-stream"),
            "the abort must name the mid-stream cap, not the pre-download one: {}",
            err.message
        );
        assert_eq!(err.exit_code, crate::EXIT_USER);
        // The partial write is cleaned up, exactly as on the pre-download rejection.
        assert!(
            !dest.exists(),
            "an aborted download must not leave a truncated file behind"
        );
    }

    #[tokio::test]
    async fn download_over_cap_rejected_before_write() {
        let store = mem_store();
        let dataset = id(7);
        let original = b"crypt4gh-oversized-bytes".to_vec();
        let size = original.len() as u64;
        upload_package_bytes(
            &store,
            &PackageStore::new(store.clone()),
            &dataset,
            original,
            false,
        )
        .await
        .unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out.tar.c4gh");
        // A cap one byte under the advertised size is rejected before any streaming.
        let err = download_package_to_path(
            &PackageStore::new(store.clone()),
            &dataset,
            &dest,
            Some(size - 1),
        )
        .await
        .unwrap_err();
        assert!(err.message.contains("--max-size"), "{}", err.message);
        assert_eq!(err.exit_code, crate::EXIT_USER);
        // Rejected before the body was fetched, so no partial file was written.
        assert!(!dest.exists());
        // A cap at exactly the size still downloads (the guard is strictly `>`).
        download_package_to_path(
            &PackageStore::new(store.clone()),
            &dataset,
            &dest,
            Some(size),
        )
        .await
        .unwrap();
        assert!(dest.exists());
    }

    #[test]
    fn classify_get_error_maps_failure_classes() {
        let key = ObjPath::from("GDI.tar.c4gh");
        let not_found = object_store::Error::NotFound {
            path: "p".to_owned(),
            source: "missing".into(),
        };
        assert_eq!(
            classify_get_error(&key, "GDI", not_found).exit_code,
            crate::EXIT_USER
        );
        let denied = object_store::Error::PermissionDenied {
            path: "p".to_owned(),
            source: "denied".into(),
        };
        assert_eq!(
            classify_get_error(&key, "GDI", denied).exit_code,
            crate::EXIT_AUTH
        );
        let throttled = object_store::Error::Generic {
            store: "S3",
            source: "Error after 10 retries: 503 Service Unavailable".into(),
        };
        assert_eq!(
            classify_get_error(&key, "GDI", throttled).exit_code,
            crate::EXIT_TRANSIENT
        );
        let other = object_store::Error::Generic {
            store: "S3",
            source: "malformed response".into(),
        };
        assert_eq!(
            classify_get_error(&key, "GDI", other).exit_code,
            crate::EXIT_USER
        );
    }

    /// The classifier applied to every non-download op (PUT / multipart / LIST / DELETE /
    /// HEAD), so the whole S3 surface honours the exit-code contract, not just download.
    #[test]
    fn classify_object_store_error_maps_failure_classes() {
        let denied = object_store::Error::PermissionDenied {
            path: "p".to_owned(),
            source: "denied".into(),
        };
        assert_eq!(
            classify_object_store_error("uploading k", denied).exit_code,
            crate::EXIT_AUTH
        );
        let unauth = object_store::Error::Unauthenticated {
            path: "p".to_owned(),
            source: "no creds".into(),
        };
        assert_eq!(
            classify_object_store_error("listing bucket", unauth).exit_code,
            crate::EXIT_AUTH
        );
        let throttled = object_store::Error::Generic {
            store: "S3",
            source: "Error after 10 retries: 503 Service Unavailable".into(),
        };
        assert_eq!(
            classify_object_store_error("uploading k", throttled).exit_code,
            crate::EXIT_TRANSIENT
        );
        // LIST is the one op whose 403 object_store wraps in `Generic` rather than a typed
        // `PermissionDenied`, so the classifier must sniff the status text too.
        let denied_list = object_store::Error::Generic {
            store: "S3",
            source: "Error after 0 retries: 403 Forbidden".into(),
        };
        assert_eq!(
            classify_object_store_error("listing bucket", denied_list).exit_code,
            crate::EXIT_AUTH
        );
        let other = object_store::Error::Generic {
            store: "S3",
            source: "malformed response".into(),
        };
        assert_eq!(
            classify_object_store_error("listing bucket", other).exit_code,
            crate::EXIT_USER
        );
    }

    /// The auth sniff must fire only on the untyped `Generic` variant. Every path-bearing
    /// variant embeds the object key in its `Display`, and a dataset id is a timestamp:
    /// `GDI-EE-UTARTU-20260409143040312` contains "403", so sniffing their text would
    /// escalate an ordinary failure to an authentication error (exit 4).
    #[test]
    fn classify_object_store_error_never_reads_403_out_of_a_dataset_id() {
        let key = "GDI-EE-UTARTU-20260409143040312.tar.c4gh"; // gitleaks:allow - dataset id
        assert!(
            key.contains("403"),
            "the fixture id must exercise the hazard"
        );

        let exists = object_store::Error::AlreadyExists {
            path: key.to_owned(),
            source: "exists".into(),
        };
        assert_eq!(
            classify_object_store_error("uploading k", exists).exit_code,
            crate::EXIT_USER,
            "a path-bearing AlreadyExists must not be misread as an auth failure"
        );

        let missing = object_store::Error::NotFound {
            path: key.to_owned(),
            source: "missing".into(),
        };
        assert_eq!(
            classify_object_store_error("reading k", missing).exit_code,
            crate::EXIT_USER,
            "a path-bearing NotFound must not be misread as an auth failure"
        );
    }

    /// The same hazard for the remediation hint: only an untyped `Generic` hides an HTTP
    /// status in its `Display`. A `404`/`400`/`500` digit run inside the object key must
    /// not fake one and attach a misleading "run doctor" hint.
    #[test]
    fn classify_object_store_error_never_hints_off_a_dataset_id() {
        let key = "GDI-EE-UTARTU-2026040914404123.tar.c4gh"; // gitleaks:allow - dataset id
        assert!(
            key.contains("404"),
            "the fixture id must exercise the hazard"
        );
        let missing = object_store::Error::NotFound {
            path: key.to_owned(),
            source: "missing".into(),
        };

        let err = classify_object_store_error("reading k", missing);

        assert_eq!(err.exit_code, crate::EXIT_USER);
        assert!(
            !err.message.contains("doctor"),
            "a digit run in the key must not fake an HTTP status hint: {}",
            err.message
        );
    }

    #[test]
    fn is_transient_object_store_keys_on_retry_exhausted_generic() {
        assert!(is_transient_object_store(&object_store::Error::Generic {
            store: "S3",
            source: "Error after 10 retries: 503 Service Unavailable".into(),
        }));
        assert!(is_transient_object_store(&object_store::Error::Generic {
            store: "S3",
            source: "429 Too Many Requests".into(),
        }));
        assert!(!is_transient_object_store(&object_store::Error::Generic {
            store: "S3",
            source: "some unrelated failure".into(),
        }));
        assert!(!is_transient_object_store(&object_store::Error::NotFound {
            path: "p".to_owned(),
            source: "missing".into(),
        }));
    }

    #[tokio::test]
    async fn list_classifies_visible_and_hidden_and_ignores_noise() {
        let store = mem_store();
        let v1 = id(0);
        let v2 = id(1);
        let h1 = id(2);

        // Two visible, one hidden.
        upload_package_bytes(
            &store,
            &PackageStore::new(store.clone()),
            &v1,
            b"a".to_vec(),
            false,
        )
        .await
        .unwrap();
        upload_package_bytes(
            &store,
            &PackageStore::new(store.clone()),
            &v2,
            b"b".to_vec(),
            false,
        )
        .await
        .unwrap();
        upload_package_bytes(
            &store,
            &PackageStore::new(store.clone()),
            &h1,
            b"c".to_vec(),
            false,
        )
        .await
        .unwrap();
        // Flip v1, v2 to visible by overwriting their sidecars.
        for v in [&v1, &v2] {
            store
                .put(
                    &ObjPath::from(format!("{v}{STATE_SUFFIX}")),
                    PutPayload::from(state_json(Visibility::Visible).into_bytes()),
                )
                .await
                .unwrap();
        }
        // Noise that must be ignored: a node `_status/*` object.
        store
            .put(
                &ObjPath::from(format!("{STATUS_PREFIX}{v1}.json")),
                PutPayload::from(br#"{"state":"visible"}"#.to_vec()),
            )
            .await
            .unwrap();

        let listed = list_datasets(&store).await.unwrap();
        assert_eq!(listed.len(), 3, "three datasets, marker + _status ignored");

        let visible: Vec<&str> = listed
            .iter()
            .filter(|d| d.visibility == Visibility::Visible)
            .map(|d| d.id.as_str())
            .collect();
        let hidden: Vec<&str> = listed
            .iter()
            .filter(|d| d.visibility == Visibility::Hidden)
            .map(|d| d.id.as_str())
            .collect();
        assert_eq!(visible.len(), 2, "two visible: {visible:?}");
        assert_eq!(hidden, vec![h1.as_str()], "one hidden");
    }

    #[tokio::test]
    async fn list_datasets_returns_ids_sorted() {
        let store = mem_store();
        // Upload packages in non-sorted id order; `list_datasets` must return them sorted
        // by id (it re-sorts after the concurrent `buffer_unordered` sidecar fetches). An
        // in-memory store cannot force those completions out of order, so this pins the
        // sorted-and-complete contract (guarding against dropped ids / gross misordering)
        // rather than the exact reordering race.
        for n in [2u8, 0, 1] {
            upload_package_bytes(
                &store,
                &PackageStore::new(store.clone()),
                &id(n),
                b"pkg".to_vec(),
                false,
            )
            .await
            .unwrap();
        }
        let got: Vec<String> = list_datasets(&store)
            .await
            .unwrap()
            .into_iter()
            .map(|d| d.id)
            .collect();
        assert_eq!(got, vec![id(0), id(1), id(2)], "returned sorted by id");
    }

    #[test]
    fn build_object_store_requires_bucket_and_endpoint() {
        // Missing bucket.
        let s3 = ProfileS3 {
            endpoint: Some("http://localhost:9000".to_owned()),
            ..ProfileS3::default()
        };
        assert!(build_object_store(&s3).is_err());

        // One credential only is rejected.
        let s3 = ProfileS3 {
            bucket: Some("b".to_owned()),
            endpoint: Some("http://localhost:9000".to_owned()),
            access_key_id: Some("k".to_owned()),
            ..ProfileS3::default()
        };
        assert!(build_object_store(&s3).is_err());

        // Both creds + bucket + endpoint builds.
        let s3 = ProfileS3 {
            bucket: Some("b".to_owned()),
            endpoint: Some("http://localhost:9000".to_owned()),
            path_style: true,
            allow_http: true,
            access_key_id: Some("k".to_owned()),
            secret_access_key: Some("s".to_owned()),
            ..ProfileS3::default()
        };
        assert!(build_object_store(&s3).is_ok());
    }

    #[tokio::test]
    async fn probe_writable_succeeds_and_is_side_effect_free() {
        use futures::stream::TryStreamExt as _;
        let store = mem_store();
        probe_writable(&store).await.unwrap();
        // The probe PUTs then DELETEs its reserved key, so it leaves nothing behind.
        let remaining: Vec<_> = store.list(None).try_collect().await.unwrap();
        assert!(
            remaining.is_empty(),
            "probe must clean up its key: {remaining:?}"
        );
    }

    #[tokio::test]
    async fn probe_writable_surfaces_a_readonly_bucket() {
        // A read-only token: every PUT is denied. `doctor`'s probe must surface it.
        let store = HookStore::new().deny_all_puts().into_store();
        let err = probe_writable(&store).await.unwrap_err();
        assert!(err.message.contains("not writable"), "{}", err.message);
    }

    #[tokio::test]
    async fn list_treats_missing_and_unparseable_sidecars_as_hidden() {
        // The fail-safe: a package with no sidecar, or a sidecar that does not parse
        // to `visible`, lists as `hidden` (never accidentally exposed).
        let store = mem_store();
        let no_sidecar = id(5);
        let bad_sidecar = id(6);

        // (1) `.tar.c4gh` present, no `.state.json` at all -> the `else` fail-safe.
        store
            .put(
                &ObjPath::from(format!("{no_sidecar}{TAR_C4GH_SUFFIX}")),
                PutPayload::from(b"a".to_vec()),
            )
            .await
            .unwrap();
        // (2) sidecar present but an unknown/unparseable value -> parse fail-safe.
        store
            .put(
                &ObjPath::from(format!("{bad_sidecar}{TAR_C4GH_SUFFIX}")),
                PutPayload::from(b"b".to_vec()),
            )
            .await
            .unwrap();
        store
            .put(
                &ObjPath::from(format!("{bad_sidecar}{STATE_SUFFIX}")),
                PutPayload::from(br#"{"state":"on-vacation"}"#.to_vec()),
            )
            .await
            .unwrap();

        let listed = list_datasets(&store).await.unwrap();
        assert_eq!(listed.len(), 2, "both packages listed: {listed:?}");
        for d in &listed {
            assert_eq!(
                d.visibility,
                Visibility::Hidden,
                "{} must fail safe to hidden",
                d.id
            );
        }
    }

    #[tokio::test]
    async fn upload_surfaces_a_put_failure() {
        // A read-only bucket: the package upload is denied and the error names the
        // step. The package streams via a multipart upload, so the message reads
        // "... multipart upload of ...", which still names the upload step.
        let store = HookStore::new().deny_all_puts().into_store();
        let err = upload_package_bytes(
            &store,
            &PackageStore::new(store.clone()),
            &id(7),
            b"x".to_vec(),
            false,
        )
        .await
        .unwrap_err();
        assert!(err.message.contains("upload"), "{}", err.message);
        // A denied PUT is an AUTH failure (exit 4), not a user error: automation keyed on
        // the documented exit-code contract must be able to refresh credentials.
        assert_eq!(
            err.exit_code,
            crate::EXIT_AUTH,
            "a PermissionDenied PUT must exit {} (auth), got {}: {}",
            crate::EXIT_AUTH,
            err.exit_code,
            err.message
        );
    }

    /// A part upload that fails must abort the multipart upload, not just return an error.
    ///
    /// The parts already accepted stay committed otherwise, and an incomplete multipart
    /// upload is invisible: it appears in no `list`, the object never materializes, and the
    /// bucket is billed for it until a lifecycle rule expires it. `object_store`'s
    /// `WriteMultipart` cannot close it: `finish()` consumes the writer, aborts only when
    /// `complete()` fails, and the type has no `Drop`, so a part failing while the writer
    /// is still being fed leaves nothing that could abort.
    ///
    /// The package here is smaller than one part, which is the path where the failing
    /// `put_part` is the one `finish()` itself issues, and no amount of draining before
    /// `finish()` would cover it.
    #[tokio::test]
    async fn a_failed_part_upload_aborts_the_multipart_upload() {
        let aborted = Arc::new(AtomicBool::new(false));
        let store = HookStore::new()
            .fail_every_part(Arc::clone(&aborted))
            .into_store();

        let err = upload_package_bytes(
            &store,
            &PackageStore::new(store.clone()),
            &id(8),
            b"a small package".to_vec(),
            false,
        )
        .await
        .unwrap_err();

        assert!(
            err.message.contains("upload"),
            "the error must still name the step: {}",
            err.message
        );
        assert!(
            aborted.load(Ordering::SeqCst),
            "a failed part must abort the multipart upload; the committed parts are billed \
             and invisible otherwise"
        );
    }

    /// A package spanning several parts must round-trip byte-for-byte.
    ///
    /// Every other upload test here fits in a single part, so this is what exercises the
    /// chunking: part sizing, the trailing partial part, and the order the object is
    /// assembled in, given that part numbers are assigned by `put_part` at call time while
    /// the uploads run concurrently.
    #[tokio::test]
    async fn a_multi_part_package_round_trips_byte_for_byte() {
        let store = mem_store();
        let dataset = id(9);
        // Two full parts plus a partial one, with position-dependent content so a
        // reordering or a dropped part cannot compare equal.
        let bytes: Vec<u8> = (0..(2 * PART_SIZE + 1234))
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();

        upload_package_bytes(
            &store,
            &PackageStore::new(store.clone()),
            &dataset,
            bytes.clone(),
            false,
        )
        .await
        .unwrap();

        let stored = get_bytes(&store, &format!("{dataset}{TAR_C4GH_SUFFIX}"))
            .await
            .expect("the package object exists");
        assert_eq!(stored.len(), bytes.len(), "every part must be committed");
        assert_eq!(stored, bytes, "the parts must assemble in file order");
    }

    // ---------- a hook-driven wrapper store ----------

    /// Decide, from the target path, whether a put/multipart-put is refused.
    type PutHook = Box<dyn Fn(&ObjPath) -> Option<object_store::Error> + Send + Sync>;
    /// Rewrite a `GetResult` before the caller sees it.
    type GetHook = Box<dyn Fn(&mut GetResult) + Send + Sync>;
    /// Supply the [`MultipartUpload`] a `put_multipart` hands back.
    type MultipartHook = Box<dyn Fn() -> Box<dyn MultipartUpload> + Send + Sync>;

    /// A [`MultipartUpload`] whose every part fails, recording whether it was aborted.
    #[derive(Debug)]
    struct FailingUpload {
        aborted: Arc<AtomicBool>,
    }

    #[async_trait]
    impl MultipartUpload for FailingUpload {
        fn put_part(&mut self, _data: PutPayload) -> object_store::UploadPart {
            Box::pin(async {
                Err(object_store::Error::Generic {
                    store: "test",
                    source: "part upload failed".into(),
                })
            })
        }

        async fn complete(&mut self) -> object_store::Result<PutResult> {
            Err(object_store::Error::Generic {
                store: "test",
                source: "complete after a failed part".into(),
            })
        }

        async fn abort(&mut self) -> object_store::Result<()> {
            self.aborted.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    /// An [`InMemory`] store with optional hooks on `put`, `put_multipart` and `get`.
    ///
    /// Each hook changes one operation: refuse every PUT (a read-only token or revoked
    /// write grant), under-report an object's size (a hostile or buggy backend), or fail
    /// every part of a multipart upload. `ObjectStore` has seven required methods, so a
    /// wrapper per behaviour would be six verbatim delegations apiece; this writes them
    /// once.
    struct HookStore {
        inner: InMemory,
        on_put: Option<PutHook>,
        on_get: Option<GetHook>,
        on_multipart: Option<MultipartHook>,
    }

    impl HookStore {
        fn new() -> Self {
            Self {
                inner: InMemory::new(),
                on_put: None,
                on_get: None,
                on_multipart: None,
            }
        }

        /// Refuse every `put`/`put_multipart` with `PermissionDenied`.
        fn deny_all_puts(mut self) -> Self {
            self.on_put = Some(Box::new(|location| {
                Some(object_store::Error::PermissionDenied {
                    path: location.to_string(),
                    source: "test: bucket is read-only".into(),
                })
            }));
            self
        }

        /// Rewrite each `GetResult` before the caller sees it: the seam a test uses to
        /// make the store lie about an object's size while still serving the real body.
        fn tamper_with_get(mut self, f: impl Fn(&mut GetResult) + Send + Sync + 'static) -> Self {
            self.on_get = Some(Box::new(f));
            self
        }

        /// Hand back an upload whose every part fails, flagging `aborted` if the caller
        /// aborts it: the seam for "the network dropped mid-upload".
        fn fail_every_part(mut self, aborted: Arc<AtomicBool>) -> Self {
            self.on_multipart = Some(Box::new(move || {
                Box::new(FailingUpload {
                    aborted: Arc::clone(&aborted),
                })
            }));
            self
        }

        fn into_store(self) -> Store {
            Arc::new(self)
        }
    }

    impl std::fmt::Display for HookStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "HookStore")
        }
    }

    impl std::fmt::Debug for HookStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "HookStore")
        }
    }

    #[async_trait]
    impl ObjectStore for HookStore {
        async fn put_opts(
            &self,
            location: &ObjPath,
            payload: PutPayload,
            opts: PutOptions,
        ) -> object_store::Result<PutResult> {
            if let Some(err) = self.on_put.as_ref().and_then(|h| h(location)) {
                return Err(err);
            }
            self.inner.put_opts(location, payload, opts).await
        }

        async fn put_multipart_opts(
            &self,
            location: &ObjPath,
            opts: PutMultipartOptions,
        ) -> object_store::Result<Box<dyn object_store::MultipartUpload>> {
            if let Some(err) = self.on_put.as_ref().and_then(|h| h(location)) {
                return Err(err);
            }
            if let Some(hook) = self.on_multipart.as_ref() {
                return Ok(hook());
            }
            self.inner.put_multipart_opts(location, opts).await
        }

        async fn get_opts(
            &self,
            location: &ObjPath,
            options: GetOptions,
        ) -> object_store::Result<GetResult> {
            let mut result = self.inner.get_opts(location, options).await?;
            if let Some(hook) = self.on_get.as_ref() {
                hook(&mut result);
            }
            Ok(result)
        }

        fn delete_stream(
            &self,
            locations: BoxStream<'static, object_store::Result<ObjPath>>,
        ) -> BoxStream<'static, object_store::Result<ObjPath>> {
            self.inner.delete_stream(locations)
        }

        fn list(
            &self,
            prefix: Option<&ObjPath>,
        ) -> BoxStream<'static, object_store::Result<ObjectMeta>> {
            self.inner.list(prefix)
        }

        async fn list_with_delimiter(
            &self,
            prefix: Option<&ObjPath>,
        ) -> object_store::Result<ListResult> {
            self.inner.list_with_delimiter(prefix).await
        }

        async fn copy_opts(
            &self,
            from: &ObjPath,
            to: &ObjPath,
            options: CopyOptions,
        ) -> object_store::Result<()> {
            self.inner.copy_opts(from, to, options).await
        }
    }
}
