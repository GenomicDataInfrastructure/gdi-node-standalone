//! Small, dependency-light runtime helpers shared across the workspace.
//!
//! Trivial functions that more than one crate needs, such as the S3 monitor, the tool's S3
//! client and the ingest pipeline. Kept here so each has a single definition.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest as _, Sha256};

/// Current UTC time as an RFC3339 string, as used by a status object's `updated_at` or an
/// S3 sync marker's `last_modified`.
///
/// Falls back to the Unix epoch if formatting fails, so the function is total.
#[must_use]
pub fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

/// Format a Unix timestamp as RFC3339 UTC with a fixed 9-digit subsecond fraction,
/// `YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ`. This is the wire shape the structured log
/// `@timestamp` uses.
///
/// Falls back to the epoch string if the timestamp is out of range or formatting fails, so
/// the function is total.
#[must_use]
pub(crate) fn rfc3339_nanos(secs: u64, nanos: u32) -> String {
    let format = time::macros::format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:9]Z"
    );
    let total_nanos = i128::from(secs) * 1_000_000_000 + i128::from(nanos);
    time::OffsetDateTime::from_unix_timestamp_nanos(total_nanos)
        .ok()
        .and_then(|dt| dt.format(&format).ok())
        .unwrap_or_else(|| "1970-01-01T00:00:00.000000000Z".to_owned())
}

/// Current UTC time as RFC3339 with a 9-digit subsecond fraction. Reads the clock directly,
/// so it is safe to call from a panic hook before the tracing subscriber is initialized.
#[must_use]
pub fn now_rfc3339_nanos() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    rfc3339_nanos(now.as_secs(), now.subsec_nanos())
}

/// Whole seconds elapsed since the RFC3339 timestamp `at`, on the node clock. Negative when
/// `at` is in the future under clock skew, `None` when `at` does not parse as RFC3339.
///
/// Keeps RFC3339 age arithmetic in one place for callers such as the visibility-staleness
/// gate in the node crate, which does not depend on the `time` crate directly.
#[must_use]
pub fn rfc3339_age_seconds(at: &str) -> Option<i64> {
    let parsed =
        time::OffsetDateTime::parse(at, &time::format_description::well_known::Rfc3339).ok()?;
    Some((time::OffsetDateTime::now_utc() - parsed).whole_seconds())
}

/// Process-wide counter backing [`rand_suffix`].
static SUFFIX_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A unique, dependency-free `{rand}` suffix: nanoseconds since the epoch plus a
/// process-wide atomic counter, so concurrent calls never collide.
#[must_use]
pub fn rand_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let counter = SUFFIX_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{nanos:x}.{counter:x}")
}

/// Stream `reader` through SHA-256, returning the full 64-char lowercase hex
/// digest together with the number of bytes hashed.
///
/// Callers wanting a shorter id truncate the returned hex, which is ASCII, so a byte-range
/// slice is also a char-range slice.
///
/// # Errors
///
/// Propagates any I/O error from reading `reader`.
pub fn sha256_hex_reader<R: Read>(mut reader: R) -> io::Result<(String, u64)> {
    let mut hasher = Sha256::new();
    // 128 KiB read buffer: far fewer read syscalls than `io::copy`'s 8 KiB default on a
    // large file, at trivial memory cost. The digest is fed the same bytes either way.
    let mut buf = vec![0u8; 128 * 1024];
    let mut size: u64 = 0;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        size += n as u64;
    }
    Ok((sha256_hex(hasher), size))
}

/// Render a finalized SHA-256 hasher as 64 lowercase hex chars.
///
/// The one place the digest string format is defined, shared by [`sha256_hex_reader`] and
/// the converter's read-folded digest, so the two cannot drift in case and produce
/// mismatched `vcfid`s or manifest digests for the same bytes.
#[must_use]
pub fn sha256_hex(hasher: Sha256) -> String {
    // Nibble-table hex: branch-free, with no per-byte `fmt` dispatch. Output is identical
    // to `write!(hex, "{b:02x}")`.
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in digest {
        hex.push(HEX[(b >> 4) as usize] as char);
        hex.push(HEX[(b & 0x0f) as usize] as char);
    }
    hex
}

/// Read the whole file at `path` into memory, refusing a file larger than `cap` bytes.
///
/// The shared capped reader for any file whose size this process does not control, such as
/// a provider-supplied `manifest.json`, a sidecar or a package member. A bare
/// [`std::fs::read`] on such a path allocates a `Vec` sized to the on-disk length, so a
/// hostile multi-gigabyte file can exhaust memory, and in the inbox it does so on every
/// scan. Reading through a [`Read::take`] adaptor bounded at `cap + 1` keeps the allocation
/// at that bound whatever the file's real size, and errors the moment the content would
/// exceed `cap`, with no `stat`-then-read window.
///
/// It states the limit but does not enforce the call: `clippy.toml` bans `std::fs::write`
/// and `std::fs::File::create` but not `std::fs::read`, so nothing steers a new capped-read
/// site here. The remaining `fs::read` callers read node-owned control files whose size this
/// process does control, where a cap buys nothing.
///
/// # Errors
///
/// Propagates the [`io::Error`] from opening or reading `path`, or returns
/// [`io::ErrorKind::InvalidData`] if the content reaches `cap + 1` bytes.
pub fn read_capped(path: &Path, cap: u64) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    fs::File::open(path)?
        .take(cap.saturating_add(1))
        .read_to_end(&mut buf)?;
    if buf.len() as u64 > cap {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} exceeds the {cap}-byte cap", path.display()),
        ));
    }
    Ok(buf)
}

/// Atomically and durably write `bytes` to `path`.
///
/// Writes to a sibling temp file, fsyncs its contents, renames it over `path`, then makes a
/// best-effort fsync of the parent directory so the rename survives a crash. On any error
/// the temp file is removed. This is the crash-safe writer for the small control and state
/// files that must never be observed torn, zero-length, or missing their prior good
/// contents after a power loss: metadata overlays, lifecycle sidecars, tool config and the
/// node-identity backup blob. The parent directory must already exist.
///
/// The temp file is a sibling of `path`, so the rename is atomic on the same filesystem.
/// Concurrent writers must target distinct paths.
///
/// # Errors
///
/// Returns an [`io::Error`] if `path` has no file name, if the temp file cannot be created,
/// written or fsynced, or if the rename fails. A parent-directory fsync failure is tolerated
/// on platforms that cannot open a directory for sync.
pub fn write_durable_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_durable_atomic_inner(path, bytes, None)
}

/// Atomically and durably write secret `bytes` to `path` with Unix mode `0o600`.
///
/// As [`write_durable_atomic`], except the mode is applied to the temp file at `O_CREAT`,
/// never with a later `chmod`. `rename` preserves the temp's mode, so creating the temp
/// with `File::create`, which yields `0o666 & ~umask`, would expose the secret for the
/// duration of the write and leave the final key world-readable. `0o600` has no group or
/// other bits, so umask cannot widen it.
///
/// Use this for private-key and credential material, and [`write_durable_atomic`] for
/// everything else. On non-Unix it behaves like [`write_durable_atomic`].
///
/// # Errors
///
/// As [`write_durable_atomic`].
pub fn write_secret_durable(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_durable_atomic_inner(path, bytes, Some(0o600))
}

/// A temp sibling of `path` that no concurrent writer can collide with.
///
/// A fixed `{file_name}.tmp` would not do. `create_tmp` recovers from a leftover temp by
/// removing it and retrying once, which turns two concurrent writers of the same path into
/// data corruption: writer B unlinks A's in-progress temp and publishes its own, then A,
/// whose file descriptor is still valid, renames whatever now sits at that name over the
/// destination and returns `Ok`.
///
/// The suffix is the process id plus a monotonically increasing counter, so it is unique
/// across both concurrent processes and concurrent threads within one. The node and an
/// operator CLI one-shot can target the same override file. A unique name cannot clean up a
/// temp orphaned by a crash, so an orphan lingers under `{file_name}.tmp.*`; the shared
/// prefix keeps orphans identifiable, and silent corruption with a false `Ok` is the worse
/// failure.
fn tmp_sibling_for(path: &Path, file_name: &std::ffi::OsStr) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    path.with_file_name(format!(
        "{}.tmp.{}.{n}",
        file_name.to_string_lossy(),
        std::process::id()
    ))
}

/// The shared body of [`write_durable_atomic`] and [`write_secret_durable`]: temp, fsync,
/// rename, parent-directory fsync, removing the temp on any error. On Unix, `mode` is the
/// permission the temp file, and therefore the renamed destination, is created with.
fn write_durable_atomic_inner(path: &Path, bytes: &[u8], mode: Option<u32>) -> io::Result<()> {
    crate::faults::guard(
        crate::faults::FaultPoint::DurableWrite,
        &path.to_string_lossy(),
    )?;
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let tmp = tmp_sibling_for(path, file_name);

    // Every step from here to the rename either publishes `path` or leaves nothing
    // behind, so they share one cleanup: on any failure the temp sibling is removed.
    let write_and_publish = || -> io::Result<()> {
        let mut file = create_tmp(&tmp, mode)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&tmp, path)
    };
    if let Err(e) = write_and_publish() {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    // Best-effort parent-dir fsync so the rename entry is durable across a crash.
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fsync_dir(parent);
    }
    Ok(())
}

/// Create the temp file, applying `mode` at `O_CREAT` on Unix.
#[cfg(unix)]
fn create_tmp(tmp: &Path, mode: Option<u32>) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut opts = fs::OpenOptions::new();
    // `create_new` (O_EXCL) rather than `create` plus `truncate`: the mode passed to `open`
    // applies only when the file is created, so opening a pre-existing temp path would keep
    // whatever permissions it has, or follow a symlink pointing elsewhere. For a path
    // holding a secret that is the difference between 0600 and disclosure.
    opts.write(true).create_new(true);
    if let Some(m) = mode {
        opts.mode(m);
    }
    match opts.open(tmp) {
        Ok(file) => Ok(file),
        // A leftover temp from a crashed write is worth recovering: remove it and retry
        // once, so the retry still creates the file itself, applying `mode` and still
        // refusing to follow a symlink.
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            fs::remove_file(tmp)?;
            opts.open(tmp)
        }
        Err(e) => Err(e),
    }
}

/// Create the temp file. Non-Unix has no mode to apply.
#[cfg(not(unix))]
fn create_tmp(tmp: &Path, _mode: Option<u32>) -> io::Result<fs::File> {
    fs::File::create(tmp)
}

/// Owner-only mode for a node data-path directory: no group or other bits, so a co-located
/// uid on a shared volume cannot list or traverse the node's decrypted dataset tree.
/// Applied at mkdir, never with a later chmod.
#[cfg(unix)]
const PRIVATE_DIR_MODE: u32 = 0o700;
/// Owner-only mode for a node data-path file.
#[cfg(unix)]
const PRIVATE_FILE_MODE: u32 = 0o600;

/// Create `path` and any missing parents owner-only (`0o700` on Unix), so a shared-volume
/// co-tenant cannot traverse into decrypted dataset data.
///
/// The mode is applied at `O_CREAT` on every component this call creates, never with a
/// later chmod. A component that already exists keeps its mode, so the pre-existing
/// `data_dir` root is tightened explicitly in `main`. Use this for every node data-path
/// directory; the tool's scratch and producer paths carry their own posture.
///
/// # Errors
/// Propagates the directory-creation [`io::Error`].
#[cfg_attr(
    not(unix),
    expect(
        clippy::disallowed_methods,
        reason = "the chokepoint itself: the non-unix fallback has no mode to set"
    )
)]
#[cfg_attr(
    unix,
    expect(
        clippy::disallowed_methods,
        reason = "the chokepoint the DirBuilder::create ban steers callers to; it states \
                  the 0700 mode"
    )
)]
pub fn create_private_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(PRIVATE_DIR_MODE)
            .create(path)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path)
    }
}

/// Create or truncate `path` owner-only (`0o600` on Unix), applying the mode at `O_CREAT`,
/// for a transient decrypted payload such as the plaintext `.tar` or a PME parquet
/// destination on a shared-volume host. For a new path that must reject a pre-existing
/// entry, such as an extracted archive member, use [`create_private_file_new`].
///
/// # Errors
/// Propagates the open [`io::Error`].
#[cfg(unix)]
pub fn create_private_file(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(PRIVATE_FILE_MODE)
        .open(path)
}

/// The permission bits that expose a secret file beyond its owner.
pub const SECRET_MODE_FORBIDDEN_BITS: u32 = 0o077;

/// The permission bits of `path` when it is readable beyond its owner, else `None`.
///
/// The read-side counterpart to [`create_private_file`]: creating a key 0o600 protects
/// nothing if every later reader accepts it at 0o644. Returns `Some(mode & 0o7777)` when
/// `mode &` [`SECRET_MODE_FORBIDDEN_BITS`] is non-zero.
///
/// A path that cannot be statted yields `None` rather than a false alarm, since the caller
/// is about to open it and will report the real I/O error. Always `None` on non-Unix, where
/// these bits are not comparable.
#[cfg(unix)]
#[must_use]
pub fn loose_secret_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = fs::metadata(path).ok()?.permissions().mode();
    (mode & SECRET_MODE_FORBIDDEN_BITS != 0).then_some(mode & 0o7777)
}

/// Non-Unix: permission bits are not comparable, so nothing is ever reported.
#[cfg(not(unix))]
#[must_use]
pub fn loose_secret_mode(_path: &Path) -> Option<u32> {
    None
}

/// As [`create_private_file`] but with `create_new` (`O_CREAT|O_EXCL`), so it refuses a
/// pre-existing path, including a symlink: `O_EXCL` fails with `EEXIST` rather than
/// following it. `extract_tar_safely` needs this, because its lexical containment check
/// cannot stop `File::create` from following a symlink pre-planted at a member's
/// destination.
///
/// # Errors
/// Propagates the open [`io::Error`], including `AlreadyExists` when the destination exists.
#[cfg(unix)]
pub fn create_private_file_new(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .open(path)
}

/// Non-Unix [`create_private_file`]: no mode to apply.
#[cfg(not(unix))]
pub fn create_private_file(path: &Path) -> io::Result<fs::File> {
    fs::File::create(path)
}

/// Non-Unix [`create_private_file_new`]: no mode to apply.
#[cfg(not(unix))]
pub fn create_private_file_new(path: &Path) -> io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

/// As [`write_durable_atomic`], but the destination lands owner-only (`0o600` on Unix), with
/// the same crash-safe temp, fsync and rename and the mode applied at the temp's `O_CREAT`.
///
/// For a small node data-path control or state file, such as the status index, a provenance
/// sidecar or an operator override, on a shared-volume host. It differs from
/// [`write_secret_durable`] only in intent, private data rather than key material; both
/// delegate to the same inner writer.
///
/// # Errors
/// As [`write_durable_atomic`].
pub fn write_durable_atomic_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        write_durable_atomic_inner(path, bytes, Some(PRIVATE_FILE_MODE))
    }
    #[cfg(not(unix))]
    {
        write_durable_atomic_inner(path, bytes, None)
    }
}

/// Best-effort `fsync` of a directory, so a `rename` entry created within it survives a
/// crash. Without this a rename is only atomic, meaning a reader sees either the old or the
/// new name, and not durable, since the entry may still be page-cache only.
///
/// Errors are ignored: not every filesystem permits opening a directory for sync, and a
/// failure here must not fail an otherwise-complete operation.
pub fn fsync_dir(dir: &Path) {
    if let Ok(handle) = fs::File::open(dir) {
        let _ = handle.sync_all();
    }
}

/// The subdirectory of a `data_dir` holding durable dataset-deletion intent markers, a
/// write-ahead log for erasure.
const DELETING_DIR: &str = ".deleting";

/// Whether a durable deletion intent is currently recorded for `id`.
///
/// True from before the status purge until after the directory removal succeeds, the window
/// in which a dataset is being erased but its directory may still be on disk. A reload that
/// reads the directory during that window must not re-serve it. [`crate::cache::apply_scan`]
/// consults this so a walk that started earlier cannot undo a concurrent erase.
#[must_use]
pub fn is_deleting(data_dir: &Path, id: &str) -> bool {
    data_dir.join(DELETING_DIR).join(id).exists()
}

/// Record a durable intent to fully erase dataset `id`, written before its status entry is
/// purged and its `data_dir/{id}/` removed.
///
/// Deleting a dataset touches two stores: it purges the status index, then removes the
/// possibly very large directory off the reactor. A crash between the two would leave the
/// directory on disk with no status entry, which is un-erased data a restart could re-serve.
/// This marker makes the erasure recoverable, and [`reap_deleting`] finishes it on the next
/// boot. [`clear_deleting_marker`] clears it once the removal completes.
///
/// # Errors
/// Returns an [`io::Error`] if the marker directory or the durable marker file cannot be
/// written.
pub fn mark_deleting(data_dir: &Path, id: &str) -> io::Result<()> {
    let dir = data_dir.join(DELETING_DIR);
    create_private_dir(&dir)?;
    // Durable: the marker must survive a power loss inside the deletion window.
    #[expect(
        clippy::disallowed_methods,
        reason = "not secret: the marker body is the dataset id, inside a 0700 directory"
    )]
    write_durable_atomic(&dir.join(id), id.as_bytes())?;
    fsync_dir(&dir);
    Ok(())
}

/// Clear the deletion-intent marker for `id`, but only if the `remove_dir_all` it guards
/// succeeded or found nothing to remove.
///
/// Pass the result of the removal this marker guarded. The marker is a write-ahead token
/// from [`mark_deleting`] and must outlive a failed removal, so [`reap_deleting`] can retry
/// the erasure on the next boot. A bare unlink would strand the dataset directory on disk
/// with no retry token, leaving an incomplete erasure for an operator delete and re-opening
/// the admit-after-writer-reject bypass for a rejected payload. On a removal error other
/// than `NotFound` the marker is kept and the error returned unchanged.
///
/// Every retirement after an erasure goes through here, including `reap_deleting`'s
/// post-removal path, so no site can drop a retry token without having proven the removal
/// succeeded. The exception is `reap_deleting`'s junk-marker case: a marker whose name is
/// not a valid dataset id corresponds to no dataset directory, so there is nothing to
/// commit.
///
/// # Errors
/// Returns the `removed` error unchanged (leaving the marker in place) when it is not
/// `NotFound`.
pub fn clear_deleting_marker(data_dir: &Path, id: &str, removed: io::Result<()>) -> io::Result<()> {
    clear_deleting_marker_inner(data_dir, id, removed, Sync::Now)
}

/// Whether [`clear_deleting_marker_inner`] issues the directory barrier itself.
#[derive(Clone, Copy)]
enum Sync {
    /// `fsync` before returning: the caller retires one marker and must not return before
    /// the commit is durable.
    Now,
    /// Leave it to the caller, which retires a batch and issues one barrier for all of them.
    /// Sound because `fsync_dir` on the shared parent commits every unlink that preceded it,
    /// so N markers need N unlinks but one barrier.
    Deferred,
}

/// The body of [`clear_deleting_marker`], with the barrier made optional for the batch
/// caller.
fn clear_deleting_marker_inner(
    data_dir: &Path,
    id: &str,
    removed: io::Result<()>,
    sync: Sync,
) -> io::Result<()> {
    match removed {
        Ok(()) => {}
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    // Commit the write-ahead log as durably as `mark_deleting` writes its begin record.
    // Without the barrier the commit could live only in the page cache, and a power loss
    // would resurrect a marker whose erasure had already completed. `reap_deleting` would
    // replay it at the next boot against whatever now sits at `data_dir/{id}`, which after
    // the documented take-down-and-re-add recourse is a live dataset.
    match fs::remove_file(data_dir.join(DELETING_DIR).join(id)) {
        Ok(()) => {}
        // Already gone: an earlier pass, or `reap_deleting`, completed the erasure.
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    }
    if let Sync::Now = sync {
        fsync_dir(&data_dir.join(DELETING_DIR));
    }
    Ok(())
}

/// Every inbox-side path that can hold a copy of, or a sidecar about, dataset `id`.
///
/// This is what an erasure must reach beyond `data_dir/{id}`: the unconsumed drop, an
/// in-flight `.partial` drop, the provider's metadata sidecar, a plaintext staging
/// directory, its in-flight `.{id}.partial` twin, and the quarantine entry. The inbox
/// scanner skips both `.partial` shapes; a `deploy` killed mid-copy strands the twin with
/// the subject's parquet inside.
///
/// `{id}.state.json` is not in the list. A `deleted` sidecar there is the provider's
/// tombstone, the record that answers `410 Gone` and keeps a re-dropped package of this id
/// out until the operator removes it, so erasing it would re-open ingest for the very id
/// being erased.
///
/// One list, shared by the live erase and the boot replay in [`reap_deleting`] through
/// [`sweep_inbox_artifacts`], so the two cannot reach different sets. `id` must already be
/// validated, because it is joined onto a path.
#[must_use]
pub fn inbox_artifact_paths(inbox: &Path, id: &str) -> [PathBuf; 6] {
    use crate::s3_layout::{OVERLAY_SUFFIX, TAR_C4GH_SUFFIX};
    [
        inbox.join(format!("{id}{TAR_C4GH_SUFFIX}")),
        inbox.join(format!("{id}{TAR_C4GH_SUFFIX}.partial")),
        inbox.join(format!("{id}{OVERLAY_SUFFIX}")),
        inbox.join(id),
        inbox.join(format!(".{id}.partial")),
        inbox.join(".rejected").join(id),
    ]
}

/// Remove every inbox-side artifact of `id`, as listed by [`inbox_artifact_paths`].
///
/// Reports `(path, Ok)` per removal and `(path, Err)` per failure, omitting absent paths.
/// Never follows a symlink out of the inbox: it stats with `symlink_metadata` and unlinks a
/// link rather than descending it. This is blocking I/O, so call it off the async reactor.
///
/// Best-effort per path: one failure does not stop the others, and the caller decides how to
/// report. The dataset itself is erased by then, and a failure here must not mask that.
#[must_use]
pub fn sweep_inbox_artifacts(inbox: &Path, id: &str) -> Vec<(PathBuf, io::Result<()>)> {
    let mut swept = Vec::new();
    for path in inbox_artifact_paths(inbox, id) {
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        let removed = if meta.is_dir() {
            fs::remove_dir_all(&path)
        } else {
            fs::remove_file(&path)
        };
        swept.push((path, removed));
    }
    swept
}

/// Complete any dataset erasure interrupted by a crash.
///
/// For every intent marker under `data_dir/.deleting/`, removes the corresponding
/// `data_dir/{id}/` if it still exists, sweeps its inbox-side copies when `inbox` is
/// configured, then retires the marker. Returns the ids whose erasure this call completed.
///
/// The caller needs the ids, not just a count. Erasing `data_dir/{id}/` leaves that id's
/// `.status.json` entry behind with a `last_seen_signature` that still matches the unchanged
/// source object, so the S3 reconcile's non-live branch short-circuits on
/// `last_seen == etag` and never re-ingests. The dataset would stay wedged out of the store
/// until the provider modified the object. Boot purges these entries so a reaped id is
/// re-ingestable.
///
/// Call this at boot before hydrating the cache, so a purged-but-not-removed dataset is
/// erased and cannot be re-served. Best-effort per entry: a marker whose name is not a valid
/// dataset id is dropped as junk, and a dataset directory that cannot be removed is logged
/// with its marker kept for a later boot to retry, never aborting the whole reap. The inbox
/// sweep is best-effort too and does not hold the marker. The marker is retired on the
/// directory removal, as in the live erase, so a persistently unremovable inbox file cannot
/// pin a marker that a later boot would replay against a re-added live dataset.
pub fn reap_deleting(data_dir: &Path, inbox: Option<&Path>) -> Vec<String> {
    let dir = data_dir.join(DELETING_DIR);
    let Ok(entries) = fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut reaped: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        let marker = entry.path();
        let Some(id) = marker.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // A marker name that is not a valid dataset id cannot correspond to a real dataset
        // directory, and must never be joined onto `data_dir` for removal. Drop it.
        if !crate::id::is_valid_dataset_id(id) {
            let _ = fs::remove_file(&marker);
            continue;
        }
        match fs::remove_dir_all(data_dir.join(id)) {
            Ok(()) => {}
            // A NotFound target means the crash happened after the removal but before the
            // marker was cleared, so the erasure is already complete.
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::warn!(
                    dataset = %id,
                    error = %e,
                    "could not complete an interrupted dataset erasure; keeping the marker to retry next boot"
                );
                continue;
            }
        }
        // The inbox-side copies are part of the same erasure. The live path sweeps them
        // inside the `.deleting` window, so a crash between the directory removal and that
        // sweep leaves the marker standing and lands here. Finish them before retiring it.
        if let Some(inbox) = inbox {
            for (path, removed) in sweep_inbox_artifacts(inbox, id) {
                match removed {
                    Ok(()) => tracing::info!(
                        dataset = %id,
                        path = %path.display(),
                        "erased an inbox-side copy while completing an interrupted erasure"
                    ),
                    Err(e) => tracing::warn!(
                        dataset = %id,
                        path = %path.display(),
                        error = %e,
                        "could not erase an inbox-side copy while completing an interrupted \
                         erasure; it still holds data for an erased dataset"
                    ),
                }
            }
        }
        // Through the chokepoint rather than a bare unlink. The erasure succeeded, so the
        // write-ahead marker must be retired as durably as it was written, and only the ids
        // actually erased may be reported. Discarding an unlink failure here would tell the
        // caller the erasure completed while the marker survived to be replayed next boot.
        //
        // `Sync::Deferred` because the single `fsync_dir` after the loop commits every unlink
        // in it. A barrier per marker would make a recovery boot replaying N erasures issue
        // N+1 barriers on the data volume.
        if clear_deleting_marker_inner(data_dir, id, Ok(()), Sync::Deferred).is_err() {
            continue;
        }
        reaped.push(id.to_owned());
    }
    fsync_dir(&dir);
    reaped
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

    #[test]
    fn concurrent_durable_writers_do_not_steal_each_other_s_temp_file() {
        // A fixed `{name}.tmp` sibling would be a corruption path, because `create_tmp`
        // recovers from a leftover temp by removing it and retrying once. Writer B unlinks
        // A's in-progress temp and publishes its own, then A, whose fd is still valid,
        // renames whatever now sits at that name over the destination and returns `Ok`.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("contended.json");

        // Deterministic half: two temp names for one destination must differ.
        let name = path.file_name().expect("file name");
        let a = tmp_sibling_for(&path, name);
        let b = tmp_sibling_for(&path, name);
        assert_ne!(a, b, "two writers must not share a temp path");
        assert_eq!(a.parent(), path.parent(), "the temp stays a sibling");
        assert!(
            a.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("contended.json.tmp.")),
            "the shared prefix is what keeps a crash-orphaned temp identifiable: {a:?}"
        );

        // Stress half: whatever ends up on disk must be exactly one writer's bytes, never a
        // mix or a truncation. This is racy by nature, so it cannot prove absence, but it
        // catches the steal when that reproduces.
        let payloads: Vec<Vec<u8>> = (0..8u8).map(|i| vec![b'a' + i; 64 * 1024]).collect();
        std::thread::scope(|s| {
            for p in &payloads {
                let path = path.clone();
                s.spawn(move || {
                    write_durable_atomic(&path, p).expect("each writer publishes or errors");
                });
            }
        });
        let got = fs::read(&path).expect("destination exists");
        assert!(
            payloads.contains(&got),
            "the destination holds {} bytes matching no single writer — a torn or stolen \
             publish",
            got.len()
        );

        // No temp siblings survive a clean run.
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .expect("readdir")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp."))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn loose_secret_mode_flags_anything_readable_beyond_the_owner() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("key.pem");
        std::fs::write(&path, b"secret").expect("write");

        for mode in [0o600, 0o400] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
            assert_eq!(
                loose_secret_mode(&path),
                None,
                "owner-only {mode:o} is the intended posture"
            );
        }
        for mode in [0o644, 0o640, 0o604, 0o660] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
            assert_eq!(
                loose_secret_mode(&path),
                Some(mode),
                "{mode:o} exposes the key beyond its owner and must be reported"
            );
        }
        // A path that cannot be statted reports nothing rather than a false alarm.
        assert_eq!(loose_secret_mode(&dir.path().join("absent")), None);
    }

    use super::*;

    /// A marker present at boot with inbox-side copies: the reap finishes both halves of the
    /// erasure, the directory and every inbox shape, and leaves the provider's `deleted`
    /// tombstone, which is the retraction record rather than a copy of the data.
    ///
    /// The shapes are spelled out literally here, both created below and asserted absent
    /// after, rather than iterated off `inbox_artifact_paths`. Asserting absence over the
    /// derived list alone would pass while the list dropped or renamed a shape, because the
    /// loop would check paths that never existed. Set equality against the derived list binds
    /// the two spellings to each other.
    #[test]
    fn reap_deleting_sweeps_the_inbox_side_copies_and_keeps_the_tombstone() {
        const ID: &str = "GDI-EE-UTARTU-20260409143052837";
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("data");
        let inbox = tmp.path().join("inbox");
        std::fs::create_dir_all(data_dir.join(ID)).unwrap();
        std::fs::write(data_dir.join(ID).join("manifest.json"), b"{}").unwrap();
        let dirs = [
            inbox.join(".rejected").join(ID),
            inbox.join(ID),
            // `deploy_dir`'s in-flight temp tree: dot-prefixed so the scanner skips it, and
            // holding the subject's plaintext parquet when a deploy is killed mid-copy.
            inbox.join(format!(".{ID}.partial")),
        ];
        let files = [
            inbox.join(format!("{ID}.tar.c4gh")),
            inbox.join(format!("{ID}.tar.c4gh.partial")),
            inbox.join(format!("{ID}.metadata.json")),
        ];
        for dir in &dirs {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::write(dir.join("allele-freq.chr1.parquet"), b"plaintext").unwrap();
        }
        for file in &files {
            std::fs::write(file, b"x").unwrap();
        }
        let tombstone = inbox.join(format!("{ID}.state.json"));
        std::fs::write(&tombstone, br#"{"state":"deleted"}"#).unwrap();
        mark_deleting(&data_dir, ID).unwrap();

        let literal: std::collections::BTreeSet<PathBuf> =
            dirs.iter().chain(files.iter()).cloned().collect();
        let derived: std::collections::BTreeSet<PathBuf> =
            inbox_artifact_paths(&inbox, ID).into_iter().collect();
        assert_eq!(
            literal, derived,
            "the shapes this test creates and the shapes the erasure sweeps must be the \
             same set; add a new inbox-side shape to both"
        );

        assert_eq!(reap_deleting(&data_dir, Some(&inbox)), vec![ID.to_owned()]);

        assert!(!data_dir.join(ID).exists(), "the dir half is erased");
        assert!(!is_deleting(&data_dir, ID), "the marker is retired");
        for path in dirs.iter().chain(files.iter()) {
            assert!(
                !path.exists(),
                "inbox-side copy survived the reap: {path:?}"
            );
        }
        assert!(tombstone.exists(), "the `deleted` tombstone must survive");
    }

    #[test]
    fn reap_deleting_completes_an_interrupted_removal() {
        // A crash after the status entry is purged but before `remove_dir_all` runs leaves
        // the dataset directory on disk as un-erased data. The intent marker written first
        // lets the next boot finish the erasure.
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path();
        let id = "GDI-EE-UTARTU-20260409143052950";
        fs::create_dir_all(data_dir.join(id).join("sub")).unwrap();
        fs::write(data_dir.join(id).join("manifest.json"), b"{}").unwrap();
        mark_deleting(data_dir, id).unwrap();

        assert_eq!(reap_deleting(data_dir, None).len(), 1);
        assert!(
            !data_dir.join(id).exists(),
            "the orphaned dataset dir must be erased"
        );
        assert!(
            !data_dir.join(DELETING_DIR).join(id).exists(),
            "the intent marker must be cleared once the erasure completes"
        );
    }

    #[test]
    fn reap_deleting_clears_a_stale_marker_when_the_dir_is_already_gone() {
        // Crash after `remove_dir_all` but before the marker was cleared: the directory is
        // already gone, so the reap drops the stale marker.
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path();
        let id = "GDI-EE-UTARTU-20260409143052951";
        mark_deleting(data_dir, id).unwrap();
        assert_eq!(reap_deleting(data_dir, None).len(), 1);
        assert!(!data_dir.join(DELETING_DIR).join(id).exists());
    }

    #[test]
    fn mark_then_clear_on_success_leaves_nothing_to_reap() {
        // The no-crash path: a completed delete (removal Ok) clears its own marker.
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path();
        let id = "GDI-EE-UTARTU-20260409143052952";
        mark_deleting(data_dir, id).unwrap();
        assert!(data_dir.join(DELETING_DIR).join(id).exists());
        clear_deleting_marker(data_dir, id, Ok(())).unwrap();
        assert!(!data_dir.join(DELETING_DIR).join(id).exists());
        assert_eq!(reap_deleting(data_dir, None).len(), 0);
    }

    #[test]
    fn clear_keeps_the_marker_when_the_removal_failed() {
        // A failed `remove_dir_all` must leave the marker in place so `reap_deleting`
        // retries the erasure next boot. Clearing it unconditionally would strand un-erased
        // data and re-open the writer-reject bypass. The error is propagated.
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path();
        let id = "GDI-EE-UTARTU-20260409143052953";
        mark_deleting(data_dir, id).unwrap();
        let failed = Err(io::Error::new(io::ErrorKind::PermissionDenied, "EACCES"));
        let err = clear_deleting_marker(data_dir, id, failed).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            data_dir.join(DELETING_DIR).join(id).exists(),
            "a failed removal must keep the retry token"
        );
        // And a NotFound removal (crash after the dir was already gone) still clears it.
        clear_deleting_marker(data_dir, id, Err(io::Error::from(io::ErrorKind::NotFound))).unwrap();
        assert!(!data_dir.join(DELETING_DIR).join(id).exists());
    }

    #[test]
    fn reap_deleting_drops_a_junk_marker_and_never_escapes_data_dir() {
        // A marker whose name is not a valid dataset id must be dropped, never joined
        // onto data_dir and removed.
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path();
        fs::create_dir_all(data_dir.join(DELETING_DIR)).unwrap();
        fs::write(data_dir.join(DELETING_DIR).join("not-a-valid-id"), b"x").unwrap();
        // The reaped count excludes junk, and the junk marker is removed.
        assert_eq!(reap_deleting(data_dir, None).len(), 0);
        assert!(!data_dir.join(DELETING_DIR).join("not-a-valid-id").exists());
    }

    /// A secret PEM must never be readable by group or other, not even transiently. The mode
    /// has to be set on the temp file at `O_CREAT`, because `rename` preserves the temp's
    /// mode. Reusing `write_durable_atomic`, whose temp comes from `File::create` at 0o644,
    /// would expose the key during the write and leave the final key at 0o644.
    #[cfg(unix)]
    #[test]
    fn write_secret_durable_lands_0600_and_leaves_no_tmp() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provider.c4gh");

        write_secret_durable(&path, b"-----BEGIN CRYPT4GH PRIVATE KEY-----\n").unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the secret key must land 0o600, got {mode:o}");
        assert!(
            !path.with_file_name("provider.c4gh.tmp").exists(),
            "no temp file may survive"
        );
    }

    /// It replaces prior contents atomically, like `write_durable_atomic`.
    #[cfg(unix)]
    #[test]
    fn write_secret_durable_replaces_prior_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provider.c4gh");
        write_secret_durable(&path, b"old").unwrap();
        write_secret_durable(&path, b"new").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new");
    }

    #[cfg(unix)]
    #[test]
    fn private_helpers_land_owner_only_and_refuse_a_symlink() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();

        // A private directory is 0o700 and a private file 0o600, with no group or other
        // bits, so a co-located uid on a shared volume cannot traverse into or read
        // decrypted data.
        let sub = dir.path().join("nested/d");
        create_private_dir(&sub).unwrap();
        assert_eq!(
            fs::metadata(&sub).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let f = sub.join("f");
        create_private_file(&f).unwrap();
        assert_eq!(
            fs::metadata(&f).unwrap().permissions().mode() & 0o777,
            0o600
        );
        write_durable_atomic_private(&sub.join("s.json"), b"{}").unwrap();
        assert_eq!(
            fs::metadata(sub.join("s.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        // `create_private_file_new` (O_EXCL) refuses a pre-planted symlink at the
        // destination: it fails with EEXIST rather than following the link and writing
        // through it, which is the hole a lexical containment check cannot close.
        let outside = dir.path().join("outside.txt");
        fs::write(&outside, b"do not clobber").unwrap();
        let target = sub.join("member");
        std::os::unix::fs::symlink(&outside, &target).unwrap();
        let err = create_private_file_new(&target).unwrap_err();
        assert_eq!(
            err.kind(),
            io::ErrorKind::AlreadyExists,
            "a pre-existing symlink must be refused, not followed"
        );
        assert_eq!(
            fs::read(&outside).unwrap(),
            b"do not clobber",
            "the symlink target must be untouched"
        );

        // On a fresh path it creates 0o600.
        let fresh = sub.join("fresh");
        create_private_file_new(&fresh).unwrap();
        assert_eq!(
            fs::metadata(&fresh).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn write_durable_atomic_replaces_and_leaves_no_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        write_durable_atomic(&path, b"first").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        // A second write atomically replaces the contents in place.
        write_durable_atomic(&path, b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        // No leftover temp sibling remains after a successful write.
        assert!(!path.with_file_name("state.json.tmp").exists());
        // The only entry in the dir is the target file (temp was renamed, not left).
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec![std::ffi::OsString::from("state.json")]);
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    #[serial_test::serial(faults)]
    fn write_durable_atomic_surfaces_injected_enospc() {
        // A unique filename so the armed key cannot match a sibling test's write.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fault-probe-durable.json");
        let _g = crate::faults::arm_enospc(
            crate::faults::FaultPoint::DurableWrite,
            "fault-probe-durable",
            1,
        );
        let err = write_durable_atomic(&path, b"data").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::StorageFull);
        // The injected failure fires before any I/O, so nothing is written and no torn temp
        // sibling is left behind.
        assert!(!path.exists(), "a failed durable write publishes nothing");
        assert!(!path.with_file_name("fault-probe-durable.json.tmp").exists());
    }

    #[test]
    fn read_capped_reads_up_to_the_cap_and_rejects_beyond_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");

        // At the cap: accepted, exact bytes returned.
        fs::write(&path, vec![b'x'; 100]).unwrap();
        assert_eq!(read_capped(&path, 100).unwrap().len(), 100);
        // Under the cap: accepted.
        assert_eq!(read_capped(&path, 1000).unwrap().len(), 100);

        // One byte over: rejected as InvalidData, not truncated.
        fs::write(&path, vec![b'x'; 101]).unwrap();
        let err = read_capped(&path, 100).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        // A missing file propagates the open error.
        assert!(read_capped(&dir.path().join("absent"), 100).is_err());
    }

    #[test]
    fn read_capped_bounds_allocation_far_below_a_large_file() {
        // A large file is refused, never fully read: a 4 MiB file against a 1 KiB cap must
        // error, having allocated at most cap + 1 bytes.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big");
        fs::write(&path, vec![0u8; 4 * 1024 * 1024]).unwrap();
        let err = read_capped(&path, 1024).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn now_rfc3339_is_valid_rfc3339() {
        let s = now_rfc3339();
        assert!(
            time::OffsetDateTime::parse(&s, &time::format_description::well_known::Rfc3339).is_ok(),
            "now_rfc3339 must round-trip as RFC3339: {s}"
        );
        assert!(
            s.contains('T'),
            "RFC3339 carries a date/time separator: {s}"
        );
        assert!(s.starts_with("20"), "a 21st-century year: {s}");
    }

    #[test]
    fn sha256_hashes_across_multiple_read_chunks() {
        // 300 KiB > the 128 KiB internal buffer, so the read loop runs several iterations.
        let data = vec![0xAB_u8; 300_000];
        let (hex, size) = sha256_hex_reader(&data[..]).unwrap();
        assert_eq!(size, data.len() as u64);
        // Cross-check against a one-shot digest of the same bytes, hex-encoded by an
        // independent method, so the test is not circular with the function's own hex.
        let mut h = Sha256::new();
        h.update(&data);
        let want: String = h
            .finalize()
            .iter()
            .flat_map(|&b| [b >> 4, b & 0x0f])
            .map(|n| char::from_digit(u32::from(n), 16).expect("hex nibble"))
            .collect();
        assert_eq!(hex, want, "multi-chunk hash must equal a one-shot digest");
    }

    #[test]
    fn rand_suffix_is_unique_across_many_calls() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            let s = rand_suffix();
            assert!(s.contains('.'), "shape is `{{nanos:x}}.{{counter:x}}`: {s}");
            assert!(seen.insert(s), "rand_suffix collided");
        }
        assert_eq!(seen.len(), 1000);
    }

    #[test]
    fn sha256_hex_reader_matches_known_vectors() {
        // Canonical SHA-256 KATs for the empty string and "abc".
        let (hex, n) = sha256_hex_reader(&b""[..]).unwrap();
        assert_eq!(n, 0);
        assert_eq!(
            hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let (hex, n) = sha256_hex_reader(&b"abc"[..]).unwrap();
        assert_eq!(n, 3);
        assert_eq!(
            hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(hex.len(), 64, "the full digest is 64 lowercase hex chars");
    }

    #[test]
    fn rfc3339_nanos_renders_known_epochs() {
        assert_eq!(rfc3339_nanos(0, 0), "1970-01-01T00:00:00.000000000Z");
        // Unix 1e9 is the well-known 2001-09-09T01:46:40Z.
        assert_eq!(
            rfc3339_nanos(1_000_000_000, 0),
            "2001-09-09T01:46:40.000000000Z"
        );
        // Sub-second nanos are zero-padded to 9 digits (a valid RFC3339 fraction).
        assert_eq!(
            rfc3339_nanos(1_000_000_000, 123_456_789),
            "2001-09-09T01:46:40.123456789Z"
        );
    }

    #[test]
    fn rfc3339_nanos_parses_as_a_date() {
        // Any RFC3339 parser must accept the shape `YYYY-MM-DDTHH:MM:SS.fffffffffZ`.
        let s = rfc3339_nanos(1_750_000_000, 42);
        let (date, rest) = s.split_once('T').expect("has a T separator");
        assert_eq!(date.split('-').count(), 3, "Y-M-D");
        assert!(rest.ends_with('Z'), "UTC marker");
        assert!(rest.contains('.'), "fractional seconds");
    }

    /// A completed erasure must not be replayable against a dataset that was re-added.
    ///
    /// `mark_deleting` is durable, and so is `clear_deleting_marker`. A bare unlink with no
    /// `fsync_dir` would let a power loss resurrect a marker whose erasure had already
    /// finished, and `reap_deleting` replays a surviving marker unconditionally at the next
    /// boot. Since the documented recourse after a take-down is to re-add the dataset, that
    /// replay would land on live data. This pins both halves: the commit is durable, and a
    /// publish clears any stale intent regardless.
    #[test]
    fn a_resurrected_marker_does_not_erase_a_re_added_dataset() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let id = "GDI-EE-UTARTU-20260409143052837";

        // Take-down: intent recorded, directory erased, intent cleared.
        std::fs::create_dir_all(data_dir.join(id)).unwrap();
        mark_deleting(data_dir, id).unwrap();
        let removed = std::fs::remove_dir_all(data_dir.join(id));
        clear_deleting_marker(data_dir, id, removed).unwrap();
        assert!(
            !data_dir.join(DELETING_DIR).join(id).exists(),
            "a completed erasure clears its intent marker"
        );

        // The provider re-adds the same id; the store is published again.
        std::fs::create_dir_all(data_dir.join(id)).unwrap();
        std::fs::write(data_dir.join(id).join("manifest.json"), b"{}").unwrap();

        // Simulate the crash outcome a non-durable unlink would allow: the marker reappears.
        mark_deleting(data_dir, id).unwrap();
        // The publish chokepoint invalidates it; this is what `store_atomically` calls.
        clear_deleting_marker(data_dir, id, Ok(())).unwrap();

        // A later boot reaps nothing, and the re-added dataset survives.
        assert!(
            reap_deleting(data_dir, None).is_empty(),
            "no stale intent should remain"
        );
        assert!(
            data_dir.join(id).join("manifest.json").is_file(),
            "the re-added dataset must not be erased by a resurrected marker"
        );
    }

    /// A reap must name the ids it erased, so boot can drop their status entries.
    ///
    /// Returning only a count leaves a wedge. Erasing `data_dir/{id}/` leaves the
    /// `.status.json` entry and its `last_seen_signature` behind, the cache evicts the id so
    /// it is no longer live, and the S3 reconcile's non-live branch then returns early on
    /// `last_seen == etag` for the unchanged object and never re-ingests. The caller can only
    /// purge what the reap tells it about.
    #[test]
    fn reap_reports_which_ids_it_erased() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let erased = "GDI-EE-UTARTU-20260409143052837";
        let already_gone = "GDI-EE-UTARTU-20260409143052838";

        // One interrupted erasure with the directory still present, and one already
        // completed with the directory gone. Both markers are reaped and both ids must be
        // reported: the second's status entry is as stale as the first's.
        std::fs::create_dir_all(data_dir.join(erased)).unwrap();
        mark_deleting(data_dir, erased).unwrap();
        mark_deleting(data_dir, already_gone).unwrap();

        let mut reaped = reap_deleting(data_dir, None);
        reaped.sort();
        assert_eq!(reaped, vec![erased.to_owned(), already_gone.to_owned()]);
        assert!(
            !data_dir.join(erased).exists(),
            "the interrupted erasure is completed"
        );
        // Idempotent: a second boot has nothing left to reap or purge.
        assert!(reap_deleting(data_dir, None).is_empty());
    }

    /// Clearing an already-absent marker is a no-op rather than an error, so `reap_deleting`
    /// and the publish path can both run for the same id.
    #[test]
    fn clearing_an_absent_marker_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        clear_deleting_marker(tmp.path(), "GDI-EE-UTARTU-20260409143052837", Ok(())).unwrap();
    }
}
