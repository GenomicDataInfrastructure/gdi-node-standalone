//! Safe member validation for the two ingest inputs: a plaintext staging directory
//! ([`check_staging_dir`]) and an uncompressed TAR archive ([`extract_tar_safely`]).
//!
//! Both apply the same member-type and path-containment rules. Every entry must be a
//! regular file or a directory contained within the destination; symlinks, hardlinks and
//! special files (FIFOs, sockets, device nodes) are rejected and never followed; and the
//! member count and total size are bounded. The staging-dir path skips the decrypt and
//! untar of the earlier steps, so it applies those rules itself.

use std::{
    collections::HashSet,
    fs,
    io::{BufWriter, Read, Write as _},
    path::{Component, Path, PathBuf},
};

use tar::EntryType;

use crate::error::{CoreError, CoreResult};

/// Resource bounds for a staging directory.
///
/// Defaults bound a single dataset's staging dir: at most 100 000 members and
/// 16 GiB of regular-file bytes (well above a realistic aggregated dataset, but
/// finite so a hand-crafted tree cannot exhaust resources).
#[derive(Debug, Clone, Copy)]
pub struct ExtractBounds {
    /// Maximum number of members (files + directories) below the staging dir.
    pub max_members: usize,
    /// Maximum total size, in bytes, summed over all regular files.
    pub max_total_bytes: u64,
}

impl Default for ExtractBounds {
    fn default() -> Self {
        Self {
            max_members: 100_000,
            max_total_bytes: 16 * 1024 * 1024 * 1024,
        }
    }
}

/// A [`Read`] adapter that errors once more than `remaining` total bytes have been read.
/// Bounds the whole tar input in [`extract_tar_safely`] so the `tar` decoder cannot buffer
/// an unbounded PAX or GNU extension header into memory.
///
/// Public so the `gdi-dataset-tool` inspect paths (`list_members` / `read_manifest_json`)
/// can wrap their decrypt stream in the same cap the ingest extractor uses, instead of
/// handing an unbounded reader to `tar::Archive`.
pub struct CappedReader<R> {
    inner: R,
    remaining: u64,
}

impl<R: Read> CappedReader<R> {
    /// Wrap `inner`, erroring once more than `cap` total bytes have been read.
    pub fn new(inner: R, cap: u64) -> Self {
        Self {
            inner,
            remaining: cap,
        }
    }
}

impl<R: Read> Read for CappedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "tar input exceeds the max_total_bytes extraction cap",
            ));
        }
        let limit = usize::try_from(self.remaining)
            .unwrap_or(usize::MAX)
            .min(buf.len());
        let n = self.inner.read(&mut buf[..limit])?;
        self.remaining -= n as u64;
        Ok(n)
    }
}

/// Validate a plaintext staging directory's members.
///
/// Walks `dir` (without following symlinks): every entry must be a regular file
/// or a directory, contained within `dir`; any symlink, hardlink-evidence
/// (a regular file with a link count > 1), FIFO/socket/device/other special
/// entry, or any path that escapes `dir` (an absolute path or a `..` component)
/// is rejected with [`CoreError::UnsafeArchive`]. The member count is bounded by
/// `bounds.max_members` and the summed regular-file size by
/// `bounds.max_total_bytes`.
///
/// # Errors
///
/// Returns [`CoreError::UnsafeArchive`] on a disallowed member type, a path
/// escape, or a bounds violation, or [`CoreError::Io`] on a filesystem error.
pub fn check_staging_dir(dir: &Path, bounds: &ExtractBounds) -> CoreResult<()> {
    // Canonical root for the path-containment check. The root is canonicalised (it must
    // be a real directory the node controls) but never the members: a member is checked by
    // its lexical relation to the root and its `symlink_metadata`, so a symlink is
    // detected rather than resolved.
    let root = dir.canonicalize()?;

    let mut member_count: usize = 0;
    let mut total_bytes: u64 = 0;

    // Iterative walk over a stack of directories to visit, seeded with the root's
    // entries. The root itself is not counted as a member.
    let mut stack: Vec<PathBuf> = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        // Canonicalise each directory once, since all its entries share it as parent:
        // O(dirs) realpath syscalls rather than O(files). Symlinked directories are
        // rejected before they are pushed, so `current` is always a real directory the
        // node placed, and the per-entry name guard covers the leaf.
        check_dir_contained(&root, &current)?;
        for entry in fs::read_dir(&current)? {
            let entry = entry?;
            let path = entry.path();

            // Reject any entry whose final component is unsafe (absolute or `..`).
            check_entry_name(&path)?;

            // Never follow: inspect the link itself, not its target.
            let meta = fs::symlink_metadata(&path)?;
            let file_type = meta.file_type();

            member_count += 1;
            if member_count > bounds.max_members {
                return Err(unsafe_archive(format!(
                    "staging dir exceeds max_members {}",
                    bounds.max_members
                )));
            }

            if file_type.is_symlink() {
                return Err(unsafe_archive("staging dir contains a symlink"));
            }
            if file_type.is_dir() {
                stack.push(path);
                continue;
            }
            if file_type.is_file() {
                // Hardlink evidence: a regular file with more than one link is a second
                // name for an inode the node did not place here.
                reject_hardlink(&meta)?;
                total_bytes = total_bytes.saturating_add(meta.len());
                if total_bytes > bounds.max_total_bytes {
                    return Err(unsafe_archive(format!(
                        "staging dir exceeds max_total_bytes {}",
                        bounds.max_total_bytes
                    )));
                }
                continue;
            }

            // Anything else (FIFO, socket, block/char device, ...) is rejected.
            return Err(unsafe_archive(
                "staging dir contains a non-regular, non-directory member",
            ));
        }
    }

    Ok(())
}

/// Safely extract an uncompressed TAR stream into `dest`.
///
/// Mirrors the member-safety rules of [`check_staging_dir`], applied to a TAR archive. The
/// archive must be uncompressed (read with `tar::Archive::new`, i.e. `r:`, no gzip). Per
/// entry, in the order the code applies them, this:
///
/// * bounds the member count by `bounds.max_members`;
/// * rejects every non-regular, non-directory member type: symlinks, hardlinks, FIFOs,
///   sockets, block and character device nodes, and any other special entry;
/// * rejects any member whose path is absolute, holds a `..` or root component, is deeper
///   than `MAX_MEMBER_PATH_DEPTH` components, or escapes `dest` once joined (path
///   traversal / zip-slip). A bare `.` current-dir component is tolerated and normalized
///   away;
/// * rejects a duplicate in-package path (two members resolving to the same path);
/// * bounds the summed regular-file size by `bounds.max_total_bytes`;
/// * extracts regular files and directories into `dest`.
///
/// `dest` must already exist and the caller owns it, typically a fresh per-job working
/// directory. Member sizes come from the PAX-aware `entry.size()`, the exact byte count
/// streamed, which a PAX `size=` record can override the raw ustar header to. The running
/// total is checked before any bytes are written, so an oversized archive is rejected
/// without materialising it.
///
/// # Errors
///
/// Returns [`CoreError::UnsafeArchive`] on a disallowed member type, an unsafe or
/// escaping path, a duplicate path, or a bounds violation, or [`CoreError::Io`] on
/// a filesystem / TAR read error.
pub fn extract_tar_safely<R: Read>(
    tar_reader: R,
    dest: &Path,
    bounds: &ExtractBounds,
) -> CoreResult<()> {
    // Canonical root for the containment check; `dest` must already exist.
    let root = dest.canonicalize()?;

    // Bound the total bytes the tar decoder may read from the stream. The per-member
    // `entry.size()` budget below covers regular-file content, but the `tar` crate reads a
    // PAX (`x`/`g`) or GNU longname/longlink (`L`/`K`) extension header fully into memory
    // before the next real member is surfaced, so a header declaring a multi-GiB body is
    // never seen by that budget. The crate exposes no per-header hook, so cap the whole
    // input. A legitimate archive's raw size is its member content (at most
    // `max_total_bytes`) plus tar framing: a 512 B header, up to 512 B padding and at most
    // one short extension block per member, plus a 1 KiB trailer. So
    // `max_total_bytes + max_members * 1536 + 4096` never rejects a valid archive and still
    // bounds a hostile stream, whether or not the caller pre-capped the decrypted tar on
    // disk.
    let input_cap = bounds
        .max_total_bytes
        .saturating_add((bounds.max_members as u64).saturating_mul(1536))
        .saturating_add(4096);
    let mut archive = tar::Archive::new(CappedReader::new(tar_reader, input_cap));
    // Defence in depth: never honour archived ownership, permissions or mtime, and never
    // follow or create symlinks while unpacking.
    archive.set_preserve_permissions(false);
    archive.set_preserve_mtime(false);
    archive.set_unpack_xattrs(false);
    archive.set_overwrite(false);

    let mut member_count: usize = 0;
    let mut total_bytes: u64 = 0;
    let mut seen: HashSet<PathBuf> = HashSet::new();

    // A tar the decoder cannot parse is bad input, not a node fault, so it is
    // `unsafe-archive` and not `CoreError::Io`. `Io` classifies as `internal-error`, which
    // `is_node_retriable()` marks retriable: the ingest runtime would clear the state at
    // every startup, dropping the dataset off the operator's error list and polluting the
    // node-fault signal with a package fault only the provider can fix.
    let entries = archive
        .entries()
        .map_err(|e| unsafe_archive(format!("cannot read the archive index: {e}")))?;

    for entry in entries {
        let mut entry =
            entry.map_err(|e| unsafe_archive(format!("cannot read an archive member: {e}")))?;

        member_count += 1;
        if member_count > bounds.max_members {
            return Err(unsafe_archive(format!(
                "archive exceeds max_members {}",
                bounds.max_members
            )));
        }

        // Reject every member type that is not a plain regular file or directory.
        // GNU-sparse is not accepted: the tool only ever writes `Regular`, so a sparse
        // member is never legitimate and would widen the parser's attack surface on the
        // untrusted ingest path.
        let entry_type = entry.header().entry_type();
        let is_dir = entry_type == EntryType::Directory;
        let is_file = entry_type == EntryType::Regular;
        if !is_dir && !is_file {
            return Err(unsafe_archive(
                "archive contains a non-regular, non-directory member",
            ));
        }

        // Lexically validate the member path (no absolute / root / `..`; a `.` is
        // normalized away), then join it onto the canonical root and confirm it
        // stays inside.
        let raw = entry.path().map_err(|_| {
            unsafe_archive("archive member has a non-UTF-8 or unrepresentable path")
        })?;
        let safe_rel = safe_relative_path(&raw)?;
        let target = root.join(&safe_rel);
        if !target.starts_with(&root) {
            return Err(unsafe_archive(
                "archive member escapes the extraction directory",
            ));
        }

        // Reject two members resolving to the same in-package path.
        if !seen.insert(safe_rel.clone()) {
            return Err(unsafe_archive("archive contains a duplicate member path"));
        }

        if is_dir {
            crate::util::create_private_dir(&target)
                .map_err(|e| classify_member_write_error(e, "creating a member directory"))?;
            continue;
        }

        // Regular file: bound the cumulative size before writing. Use the PAX-aware
        // `entry.size()`, the exact byte count `io::copy` streams below, rather than the
        // raw ustar `header().size()` field. A PAX `size=` record overrides the header, so
        // budgeting on the header would undercount a member declaring header size 0 and a
        // huge PAX size, letting it bypass `max_total_bytes`.
        let size = entry.size();
        total_bytes = total_bytes.saturating_add(size);
        if total_bytes > bounds.max_total_bytes {
            return Err(unsafe_archive(format!(
                "archive exceeds max_total_bytes {}",
                bounds.max_total_bytes
            )));
        }

        if let Some(parent) = target.parent() {
            crate::util::create_private_dir(parent).map_err(|e| {
                classify_member_write_error(e, "creating a member's parent directory")
            })?;
        }
        // Buffer the extracted-file write: `io::copy` streams the entry body in small
        // chunks, so an unbuffered file would issue a write syscall per chunk. The size cap
        // is enforced on `entry.size()` above, so buffering changes nothing about what is
        // written.
        //
        // `create_private_file_new` (`O_CREAT|O_EXCL`) refuses a pre-existing destination,
        // so a pre-planted symlink at `target` fails EEXIST rather than being followed and
        // written through to a path outside `dest`. A lexical containment check cannot
        // close that hole. The file is created owner-only, 0o600.
        let mut out = BufWriter::new(
            crate::util::create_private_file_new(&target)
                .map_err(|e| classify_member_write_error(e, "creating a member file"))?,
        );
        let copied = std::io::copy(&mut entry, &mut out)?;
        out.flush()?;
        // A member whose body is shorter than its declared, PAX-overridable size is a
        // truncated and permanently malformed archive. The tar crate does not error here:
        // it short-reads, then reports "unexpected EOF during skip" from the iterator as a
        // kind-`Other` I/O error the node would misclassify as `internal-error` and retry
        // forever. Detect it from the short copy and fail it as `unsafe-archive`, which is
        // permanent, before the loop advances into that skip.
        if copied != size {
            return Err(CoreError::UnsafeArchive {
                detail: format!(
                    "archive member '{}' is truncated: header declares {size} bytes but only \
                     {copied} are present",
                    safe_rel.display()
                ),
            });
        }
    }

    Ok(())
}

/// Maximum number of normal path components a TAR member may have.
///
/// The dataset tool only writes shallow, fixed-shape paths (`manifest.json`,
/// `headers/<file>`, `allele-freq.*.parquet`), which are at most two deep. Rejecting a
/// deeper member stops a crafted archive of many deep, disjoint paths from driving
/// `create_dir_all` to materialise far more directories and inodes than `max_members`
/// bounds. At `8` the worst-case count of created directories is
/// `max_members * MAX_MEMBER_PATH_DEPTH`.
const MAX_MEMBER_PATH_DEPTH: usize = 8;

/// Validate a TAR member path and return it as a safe relative `PathBuf`.
///
/// Accepts a sequence of normal path components: rejects an absolute path, a
/// root/prefix component, a `..` parent component, and a path deeper than
/// [`MAX_MEMBER_PATH_DEPTH`] components. A `.` current-dir component is tolerated by
/// skipping it (normalized away). Returns [`CoreError::UnsafeArchive`] otherwise.
fn safe_relative_path(raw: &Path) -> CoreResult<PathBuf> {
    let mut out = PathBuf::new();
    let mut depth = 0usize;
    for component in raw.components() {
        match component {
            Component::Normal(part) => {
                depth += 1;
                if depth > MAX_MEMBER_PATH_DEPTH {
                    return Err(unsafe_archive(format!(
                        "archive member path exceeds the max depth of {MAX_MEMBER_PATH_DEPTH} components"
                    )));
                }
                out.push(part);
            }
            Component::CurDir => {
                // A bare "./foo" is tolerated by skipping the "." segment.
            }
            Component::ParentDir => {
                return Err(unsafe_archive(
                    "archive member path contains a `..` component",
                ));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(unsafe_archive("archive member path is absolute"));
            }
        }
    }
    if depth == 0 {
        return Err(unsafe_archive("archive member has an empty path"));
    }
    Ok(out)
}

/// Build a [`CoreError::UnsafeArchive`] from a non-sensitive detail. The single rejection
/// constructor for every member-safety, containment and bounds check in this module.
fn unsafe_archive(detail: impl Into<String>) -> CoreError {
    CoreError::UnsafeArchive {
        detail: detail.into(),
    }
}

/// Classify a filesystem error raised while materialising a member as the archive's fault
/// or the node's.
///
/// The distinction decides retry policy. `CoreError::Io` classifies as `internal-error`,
/// which is retriable, so an archive-caused failure landing there is re-fetched and
/// re-extracted on every restart while its error record drains from the operator's dataset
/// list. A hostile provider triggers that at will: members `a/b` then a regular file `a`
/// collide, as does the reverse order. The per-path `seen` set does not catch these,
/// because the paths differ and it is the resulting tree that cannot exist.
///
/// The three kinds below are properties of the member layout, so they are permanent
/// (`unsafe-archive`) and only a corrected package fixes them. Everything else
/// (`StorageFull`, `PermissionDenied`, an I/O fault) belongs to the node's environment,
/// stays `Io` and keeps retrying, because those do clear on their own.
///
/// The detail carries only the `ErrorKind`, never the error's `Display` or the path: this
/// string reaches the operator-visible error record, and member paths are
/// provider-controlled.
fn classify_member_write_error(err: std::io::Error, what: &str) -> CoreError {
    if matches!(
        err.kind(),
        std::io::ErrorKind::AlreadyExists
            | std::io::ErrorKind::IsADirectory
            | std::io::ErrorKind::NotADirectory
    ) {
        return unsafe_archive(format!(
            "archive member layout cannot be materialised ({what}: {:?}): two members \
             collide on a path component",
            err.kind()
        ));
    }
    CoreError::Io(err)
}

/// Reject a directory that escapes `root`, by canonical prefix. Called once per directory
/// visited rather than per entry, since every entry of a directory shares it as parent. A
/// failure to canonicalise is treated as contained, and caught instead by the per-entry
/// name guard and the symlink rejection in the walk.
fn check_dir_contained(root: &Path, dir: &Path) -> CoreResult<()> {
    if let Ok(canon) = dir.canonicalize()
        && !canon.starts_with(root)
    {
        return Err(unsafe_archive(
            "staging dir member escapes the staging directory",
        ));
    }
    Ok(())
}

/// Reject an entry whose final component is unsafe. A `read_dir` entry name should never
/// be `..`, `.`, absolute, or contain a separator, but guard explicitly. The containment
/// of its parent directory is checked once by [`check_dir_contained`].
fn check_entry_name(path: &Path) -> CoreResult<()> {
    if let Some(name) = path.file_name() {
        let name = name.to_string_lossy();
        if name == ".." || name == "." || name.contains('/') || name.contains('\\') {
            return Err(unsafe_archive("staging dir member has an unsafe name"));
        }
    }
    Ok(())
}

/// Reject a regular file with a hard link count greater than one.
#[cfg(unix)]
fn reject_hardlink(meta: &fs::Metadata) -> CoreResult<()> {
    use std::os::unix::fs::MetadataExt as _;
    if meta.nlink() > 1 {
        return Err(unsafe_archive("staging dir contains a hardlinked file"));
    }
    Ok(())
}

/// Non-unix: link counts are unavailable, so nothing to reject here.
#[cfg(not(unix))]
fn reject_hardlink(_meta: &fs::Metadata) -> CoreResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;
    use crate::error::ErrorClass;

    fn write_file(path: &Path, contents: &[u8]) {
        std::fs::write(path, contents).unwrap();
    }

    #[test]
    fn regular_members_pass() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("manifest.json"), b"{}");
        write_file(
            &dir.path()
                .join("allele-freq.chr3.4.br10000000.0123456789abcdef.parquet"),
            b"PAR1",
        );
        // A nested directory with a regular file is also fine.
        std::fs::create_dir(dir.path().join("headers")).unwrap();
        write_file(&dir.path().join("headers").join("x.vcf"), b"##\n");
        check_staging_dir(dir.path(), &ExtractBounds::default()).unwrap();
    }

    #[test]
    fn rejects_excessively_deep_member_path() {
        // A member path deeper than `MAX_MEMBER_PATH_DEPTH` is rejected, so a crafted
        // archive of many deep, disjoint paths cannot drive `create_dir_all` to materialise
        // far more directories and inodes than `max_members` bounds.
        let too_deep: PathBuf = (0..=MAX_MEMBER_PATH_DEPTH)
            .map(|i| format!("d{i}"))
            .collect();
        std::assert_matches!(
            safe_relative_path(&too_deep),
            Err(CoreError::UnsafeArchive { .. }),
            "a member path deeper than the cap must be rejected"
        );
        // A path exactly at the depth limit is still accepted (pins the boundary).
        let at_limit: PathBuf = (0..MAX_MEMBER_PATH_DEPTH)
            .map(|i| format!("d{i}"))
            .collect();
        assert!(
            safe_relative_path(&at_limit).is_ok(),
            "a member path at the depth cap must still be accepted"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_rejected() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("manifest.json"), b"{}");
        std::os::unix::fs::symlink("/etc/passwd", dir.path().join("evil")).unwrap();
        let err = check_staging_dir(dir.path(), &ExtractBounds::default()).unwrap_err();
        assert_eq!(err.class(), ErrorClass::UnsafeArchive);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_subdir_not_followed() {
        // A symlink to a directory must be rejected, never descended into.
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        write_file(&outside.path().join("secret"), b"x");
        std::os::unix::fs::symlink(outside.path(), dir.path().join("link")).unwrap();
        let err = check_staging_dir(dir.path(), &ExtractBounds::default()).unwrap_err();
        assert_eq!(err.class(), ErrorClass::UnsafeArchive);
    }

    #[cfg(unix)]
    #[test]
    fn staging_dir_hardlinked_file_rejected() {
        // A regular file with link count > 1 is a second name for an inode the node did
        // not place, and must be rejected. Exercises `reject_hardlink`'s `meta.nlink() > 1`
        // guard on a real hardlink, distinct from the tar `EntryType::Link` check in
        // `hardlink_member_rejected`.
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("manifest.json"), b"{}");
        let target = dir.path().join("data.parquet");
        write_file(&target, b"PAR1");
        // Second name for the same inode → both have nlink == 2.
        std::fs::hard_link(&target, dir.path().join("data.hardlink")).unwrap();
        let err = check_staging_dir(dir.path(), &ExtractBounds::default()).unwrap_err();
        assert_eq!(err.class(), ErrorClass::UnsafeArchive);
    }

    #[cfg(unix)]
    #[test]
    fn fifo_rejected() {
        // Create a FIFO with `mkfifo(1)`: the workspace forbids `unsafe`, so libc's
        // `mkfifo` is not reachable. Skip if the tool is unavailable.
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("pipe");
        let status = std::process::Command::new("mkfifo").arg(&fifo).status();
        match status {
            Ok(s) if s.success() && fifo.exists() => {}
            _ => return, // mkfifo unavailable in this sandbox; skip.
        }
        let err = check_staging_dir(dir.path(), &ExtractBounds::default()).unwrap_err();
        assert_eq!(err.class(), ErrorClass::UnsafeArchive);
        assert!(format!("{err}").contains("non-regular"));
    }

    #[test]
    fn count_bound_enforced() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("a"), b"1");
        write_file(&dir.path().join("b"), b"2");
        write_file(&dir.path().join("c"), b"3");
        let bounds = ExtractBounds {
            max_members: 2,
            ..ExtractBounds::default()
        };
        let err = check_staging_dir(dir.path(), &bounds).unwrap_err();
        assert_eq!(err.class(), ErrorClass::UnsafeArchive);
        assert!(format!("{err}").contains("max_members"));
    }

    #[test]
    fn size_bound_enforced() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("big"), &vec![0u8; 4096]);
        let bounds = ExtractBounds {
            max_total_bytes: 100,
            ..ExtractBounds::default()
        };
        let err = check_staging_dir(dir.path(), &bounds).unwrap_err();
        assert_eq!(err.class(), ErrorClass::UnsafeArchive);
        assert!(format!("{err}").contains("max_total_bytes"));
    }

    // ---- extract_tar_safely ----

    /// Append a regular-file member to a tar builder with normalized metadata.
    fn tar_file<W: std::io::Write>(builder: &mut tar::Builder<W>, name: &str, data: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, name, data).unwrap();
    }

    /// Build a single raw tar member with an arbitrary, possibly unsafe name, bypassing
    /// the `tar::Builder` path validation that rejects absolute and `..` paths at build
    /// time. Returns the full tar bytes: one member plus end-of-archive padding.
    fn raw_tar_member(name: &str, data: &[u8]) -> Vec<u8> {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o644);
        // Write the name directly into the fixed 100-byte name field, skipping the
        // `set_path` validation. Fits the short adversarial names used in tests.
        let name_bytes = name.as_bytes();
        assert!(
            name_bytes.len() <= 100,
            "test name must fit the v7 name field"
        );
        header.as_old_mut().name[..name_bytes.len()].copy_from_slice(name_bytes);
        header.set_cksum();

        let mut out = Vec::new();
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(data);
        // Pad the data to a 512-byte block boundary.
        let rem = data.len() % 512;
        if rem != 0 {
            out.extend(std::iter::repeat_n(0u8, 512 - rem));
        }
        // Two zero blocks terminate the archive.
        out.extend(std::iter::repeat_n(0u8, 1024));
        out
    }

    /// Append a member with an explicit entry type (for the special-file tests).
    fn tar_special<W: std::io::Write>(
        builder: &mut tar::Builder<W>,
        name: &str,
        entry_type: tar::EntryType,
        link: Option<&str>,
    ) {
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_entry_type(entry_type);
        header.set_mode(0o644);
        if let Some(link) = link {
            header.set_link_name(link).unwrap();
        }
        header.set_cksum();
        builder.append_data(&mut header, name, &[][..]).unwrap();
    }

    #[test]
    fn regular_tar_extracts() {
        let mut buf = Vec::new();
        {
            let mut b = tar::Builder::new(&mut buf);
            tar_file(&mut b, "manifest.json", b"{}");
            tar_file(&mut b, "headers/x.vcf", b"##\n");
            tar_file(
                &mut b,
                "allele-freq.chr3.4.br10000000.dead.parquet",
                b"PAR1",
            );
            b.finish().unwrap();
        }
        let dest = tempfile::tempdir().unwrap();
        extract_tar_safely(&buf[..], dest.path(), &ExtractBounds::default()).unwrap();
        assert!(dest.path().join("manifest.json").is_file());
        assert!(dest.path().join("headers/x.vcf").is_file());
        assert!(
            dest.path()
                .join("allele-freq.chr3.4.br10000000.dead.parquet")
                .is_file()
        );
    }

    #[test]
    fn absolute_path_rejected() {
        // `tar::Builder` would refuse an absolute name at build time, so craft the
        // member's header bytes directly.
        let buf = raw_tar_member("/etc/cron.d/x", b"x");
        let dest = tempfile::tempdir().unwrap();
        let err = extract_tar_safely(&buf[..], dest.path(), &ExtractBounds::default()).unwrap_err();
        assert_eq!(err.class(), ErrorClass::UnsafeArchive);
        assert!(format!("{err}").contains("absolute"));
    }

    #[test]
    fn parent_traversal_rejected() {
        // `..` is rejected by `set_path`, so build the raw header bytes directly.
        let buf = raw_tar_member("../escape.txt", b"pwned");
        let dest = tempfile::tempdir().unwrap();
        let err = extract_tar_safely(&buf[..], dest.path(), &ExtractBounds::default()).unwrap_err();
        assert_eq!(err.class(), ErrorClass::UnsafeArchive);
        assert!(format!("{err}").contains(".."));
        // Nothing escaped.
        assert!(!dest.path().parent().unwrap().join("escape.txt").exists());
    }

    #[test]
    fn symlink_member_rejected() {
        let mut buf = Vec::new();
        {
            let mut b = tar::Builder::new(&mut buf);
            tar_special(&mut b, "evil", tar::EntryType::Symlink, Some("/etc/passwd"));
            b.finish().unwrap();
        }
        let dest = tempfile::tempdir().unwrap();
        let err = extract_tar_safely(&buf[..], dest.path(), &ExtractBounds::default()).unwrap_err();
        assert_eq!(err.class(), ErrorClass::UnsafeArchive);
        assert!(format!("{err}").contains("non-regular"));
    }

    /// A file member colliding with a directory member must fail permanently.
    ///
    /// `a/b` implicitly creates directory `a`, so the later regular file `a` cannot be
    /// created. The paths differ, so the duplicate-path `seen` set does not catch it: the
    /// tree itself is unrealisable. The assertion is on the error class, because the class
    /// is what the retry decision reads.
    #[test]
    fn file_colliding_with_directory_member_is_permanent_not_retriable() {
        let mut buf = Vec::new();
        {
            let mut b = tar::Builder::new(&mut buf);
            tar_file(&mut b, "a/b", b"x");
            tar_file(&mut b, "a", b"y");
            b.finish().unwrap();
        }
        let dest = tempfile::tempdir().unwrap();
        let err = extract_tar_safely(&buf[..], dest.path(), &ExtractBounds::default()).unwrap_err();
        assert_eq!(
            err.class(),
            ErrorClass::UnsafeArchive,
            "a member-layout collision is the archive's fault and must be permanent, not a \
             retriable internal error: {err}"
        );
        assert!(
            !err.class().is_node_retriable(),
            "the whole point: this must not be retried forever"
        );
    }

    /// The reverse order of [`file_colliding_with_directory_member_is_permanent_not_retriable`]:
    /// a regular file `a`, then `a/b` whose parent creation hits a file.
    #[test]
    fn directory_under_a_file_member_is_permanent_not_retriable() {
        let mut buf = Vec::new();
        {
            let mut b = tar::Builder::new(&mut buf);
            tar_file(&mut b, "a", b"y");
            tar_file(&mut b, "a/b", b"x");
            b.finish().unwrap();
        }
        let dest = tempfile::tempdir().unwrap();
        let err = extract_tar_safely(&buf[..], dest.path(), &ExtractBounds::default()).unwrap_err();
        assert_eq!(
            err.class(),
            ErrorClass::UnsafeArchive,
            "parent-is-a-file is equally the archive's fault: {err}"
        );
    }

    #[test]
    fn hardlink_member_rejected() {
        let mut buf = Vec::new();
        {
            let mut b = tar::Builder::new(&mut buf);
            tar_file(&mut b, "manifest.json", b"{}");
            tar_special(&mut b, "alias", tar::EntryType::Link, Some("manifest.json"));
            b.finish().unwrap();
        }
        let dest = tempfile::tempdir().unwrap();
        let err = extract_tar_safely(&buf[..], dest.path(), &ExtractBounds::default()).unwrap_err();
        assert_eq!(err.class(), ErrorClass::UnsafeArchive);
        assert!(format!("{err}").contains("non-regular"));
    }

    #[test]
    fn gnu_sparse_member_rejected() {
        // The tool only writes `EntryType::Regular`, so a GNU-sparse member is never
        // legitimate and must never extract. A well-formed sparse member is rejected by
        // the `is_file` type check, and a malformed one, which is all `tar::Builder` can
        // emit, is rejected earlier when the reader fails to parse its sparse map.
        let mut buf = Vec::new();
        {
            let mut b = tar::Builder::new(&mut buf);
            tar_special(&mut b, "sparse.bin", tar::EntryType::GNUSparse, None);
            b.finish().unwrap();
        }
        let dest = tempfile::tempdir().unwrap();
        let result = extract_tar_safely(&buf[..], dest.path(), &ExtractBounds::default());
        assert!(
            result.is_err(),
            "a GNU-sparse member must be rejected, never extracted"
        );
        assert!(
            !dest.path().join("sparse.bin").exists(),
            "no sparse member may be written to disk"
        );
    }

    #[test]
    fn fifo_member_rejected() {
        let mut buf = Vec::new();
        {
            let mut b = tar::Builder::new(&mut buf);
            tar_special(&mut b, "pipe", tar::EntryType::Fifo, None);
            b.finish().unwrap();
        }
        let dest = tempfile::tempdir().unwrap();
        let err = extract_tar_safely(&buf[..], dest.path(), &ExtractBounds::default()).unwrap_err();
        assert_eq!(err.class(), ErrorClass::UnsafeArchive);
    }

    #[test]
    fn duplicate_member_path_rejected() {
        let mut buf = Vec::new();
        {
            let mut b = tar::Builder::new(&mut buf);
            tar_file(&mut b, "dup.txt", b"first");
            tar_file(&mut b, "dup.txt", b"second");
            b.finish().unwrap();
        }
        let dest = tempfile::tempdir().unwrap();
        let err = extract_tar_safely(&buf[..], dest.path(), &ExtractBounds::default()).unwrap_err();
        assert_eq!(err.class(), ErrorClass::UnsafeArchive);
        assert!(format!("{err}").contains("duplicate"));
    }

    #[test]
    fn tar_member_count_bound_enforced() {
        let mut buf = Vec::new();
        {
            let mut b = tar::Builder::new(&mut buf);
            tar_file(&mut b, "a", b"1");
            tar_file(&mut b, "b", b"2");
            tar_file(&mut b, "c", b"3");
            b.finish().unwrap();
        }
        let dest = tempfile::tempdir().unwrap();
        let bounds = ExtractBounds {
            max_members: 2,
            ..ExtractBounds::default()
        };
        let err = extract_tar_safely(&buf[..], dest.path(), &bounds).unwrap_err();
        assert_eq!(err.class(), ErrorClass::UnsafeArchive);
        assert!(format!("{err}").contains("max_members"));
    }

    #[test]
    fn tar_size_bound_enforced() {
        let mut buf = Vec::new();
        {
            let mut b = tar::Builder::new(&mut buf);
            tar_file(&mut b, "big", &vec![0u8; 4096]);
            b.finish().unwrap();
        }
        let dest = tempfile::tempdir().unwrap();
        let bounds = ExtractBounds {
            max_total_bytes: 100,
            ..ExtractBounds::default()
        };
        let err = extract_tar_safely(&buf[..], dest.path(), &bounds).unwrap_err();
        assert_eq!(err.class(), ErrorClass::UnsafeArchive);
        assert!(format!("{err}").contains("max_total_bytes"));
    }

    /// Append a tar block: the 512-byte header, the body, and zero-padding to the
    /// next 512-byte boundary.
    fn push_block(out: &mut Vec<u8>, header: &tar::Header, body: &[u8]) {
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(body);
        let rem = body.len() % 512;
        if rem != 0 {
            out.extend(std::iter::repeat_n(0u8, 512 - rem));
        }
    }

    /// Build a tar whose single regular member carries a PAX `size=` extension that
    /// overrides, and here exceeds, the raw ustar header size. The reader streams
    /// `pax_size` bytes, so `entry.size()` is `pax_size` while `entry.header().size()` is
    /// `raw_header_size`. `data` is the real `pax_size`-byte stream.
    fn pax_size_override_tar(
        name: &str,
        pax_size: u64,
        raw_header_size: u64,
        data: &[u8],
    ) -> Vec<u8> {
        assert_eq!(
            data.len() as u64,
            pax_size,
            "data must be exactly pax_size bytes"
        );

        // A length-prefixed PAX record "<len> size=<n>\n", where <len> is the total
        // byte length of the whole record line (self-referential).
        let records = {
            let body = format!(" size={pax_size}\n");
            let mut len = body.len() + 1;
            loop {
                let rec = format!("{len}{body}");
                if rec.len() == len {
                    break rec.into_bytes();
                }
                len = rec.len();
            }
        };

        let mut out = Vec::new();

        // 1. PAX local-extensions header (typeflag 'x'), with ustar magic so the reader
        //    recognises it and applies the records to the next member.
        let mut xhdr = tar::Header::new_ustar();
        xhdr.set_entry_type(tar::EntryType::XHeader);
        xhdr.set_size(records.len() as u64);
        xhdr.set_mode(0o644);
        let xname = b"PaxHeaders/size";
        xhdr.as_old_mut().name[..xname.len()].copy_from_slice(xname);
        xhdr.set_cksum();
        push_block(&mut out, &xhdr, &records);

        // 2. The regular member: raw header size is `raw_header_size`, but `data`
        //    (pax_size bytes) follows and the PAX record overrides the stored size.
        let mut fhdr = tar::Header::new_ustar();
        fhdr.set_entry_type(tar::EntryType::Regular);
        fhdr.set_size(raw_header_size);
        fhdr.set_mode(0o644);
        let name_bytes = name.as_bytes();
        assert!(name_bytes.len() <= 100, "name must fit the v7 name field");
        fhdr.as_old_mut().name[..name_bytes.len()].copy_from_slice(name_bytes);
        fhdr.set_cksum();
        push_block(&mut out, &fhdr, data);

        // End-of-archive: two zero blocks.
        out.extend(std::iter::repeat_n(0u8, 1024));
        out
    }

    #[test]
    fn pax_size_override_is_counted_at_its_real_size() {
        // A PAX `size=` record overrides the raw ustar header size and the reader streams
        // the PAX size. The cumulative-size guard must budget the PAX-aware `entry.size()`,
        // the bytes `io::copy` writes, rather than the raw header field: otherwise a member
        // declaring header size 0 and a huge PAX size bypasses `max_total_bytes`.
        let payload = vec![0u8; 100];
        let tar = pax_size_override_tar("big.parquet", 100, 0, &payload);

        // Check that the crafted archive is well-formed and that the PAX override is
        // honoured: with a generous cap it extracts, and the written file is the full PAX
        // size of 100 bytes rather than the 0-byte header field. That is the divergence
        // the budget must account for.
        let ok_dest = tempfile::tempdir().unwrap();
        let ok_bounds = ExtractBounds {
            max_total_bytes: 1000,
            ..ExtractBounds::default()
        };
        extract_tar_safely(&tar[..], ok_dest.path(), &ok_bounds).unwrap();
        let written = std::fs::metadata(ok_dest.path().join("big.parquet"))
            .unwrap()
            .len();
        assert_eq!(
            written, 100,
            "reader must stream the PAX size, not the 0-byte header size"
        );

        // The same member must be rejected under a 10-byte cap, which would not happen if
        // the guard budgeted the 0-byte raw header field.
        let dest = tempfile::tempdir().unwrap();
        let bounds = ExtractBounds {
            max_total_bytes: 10,
            ..ExtractBounds::default()
        };
        let err = extract_tar_safely(&tar[..], dest.path(), &bounds).unwrap_err();
        assert_eq!(err.class(), ErrorClass::UnsafeArchive);
        assert!(format!("{err}").contains("max_total_bytes"), "got: {err}");
    }

    /// Build a tar whose single member carries a PAX `size=` record declaring
    /// `declared_size` bytes but whose body is only `actual`, which is shorter.
    /// `entry.size()` reports `declared_size` while the stream runs out after `actual`, so
    /// the per-member `io::copy` hits EOF mid-member. Unlike [`pax_size_override_tar`],
    /// the declared byte count is not supplied.
    fn pax_size_lie_short_tar(name: &str, declared_size: u64, actual: &[u8]) -> Vec<u8> {
        let records = {
            let body = format!(" size={declared_size}\n");
            let mut len = body.len() + 1;
            loop {
                let rec = format!("{len}{body}");
                if rec.len() == len {
                    break rec.into_bytes();
                }
                len = rec.len();
            }
        };

        let mut out = Vec::new();
        let mut xhdr = tar::Header::new_ustar();
        xhdr.set_entry_type(tar::EntryType::XHeader);
        xhdr.set_size(records.len() as u64);
        xhdr.set_mode(0o644);
        let xname = b"PaxHeaders/size";
        xhdr.as_old_mut().name[..xname.len()].copy_from_slice(xname);
        xhdr.set_cksum();
        push_block(&mut out, &xhdr, &records);

        // The regular member: its raw ustar size matches the short body present, but the
        // PAX record overrides `entry.size()` to the much larger `declared_size`.
        let mut fhdr = tar::Header::new_ustar();
        fhdr.set_entry_type(tar::EntryType::Regular);
        fhdr.set_size(actual.len() as u64);
        fhdr.set_mode(0o644);
        let name_bytes = name.as_bytes();
        assert!(name_bytes.len() <= 100, "name must fit the v7 name field");
        fhdr.as_old_mut().name[..name_bytes.len()].copy_from_slice(name_bytes);
        fhdr.set_cksum();
        push_block(&mut out, &fhdr, actual);

        out.extend(std::iter::repeat_n(0u8, 1024));
        out
    }

    /// A stream the tar decoder cannot parse at all is bad input, not a node fault.
    ///
    /// As `CoreError::Io` it would classify as `internal-error`, which
    /// `is_node_retriable()` marks retriable, so the ingest runtime would clear it at every
    /// startup: the dataset's state would go empty on restart and drop off the error list,
    /// while structurally identical bad input (`unsafe-archive`, `invalid-manifest`)
    /// persisted. The operator would lose the record of a package only they can fix.
    #[test]
    fn a_undecodable_stream_is_unsafe_archive_not_internal_error() {
        // Not a tar at all: the decoder rejects it while reading the first header.
        let garbage = vec![0xABu8; 2048];
        let dest = tempfile::tempdir().unwrap();
        let err =
            extract_tar_safely(&garbage[..], dest.path(), &ExtractBounds::default()).unwrap_err();
        assert_eq!(
            err.class(),
            ErrorClass::UnsafeArchive,
            "an undecodable archive is bad input, not a node fault; got {err} ({:?})",
            err.class()
        );
        assert!(
            !err.class().is_node_retriable(),
            "a permanently-malformed archive must NOT be cleared and retried at startup — \
             that is what made it vanish from the error list"
        );
    }

    /// A PAX `size=` record that lies high but stays under `max_total_bytes` passes the
    /// cumulative-size guard, and `io::copy` then runs the stream dry mid-member. That
    /// truncated read is a malformed archive and must be classified `unsafe-archive`, which
    /// is permanent, rather than the retriable `internal-error`. Declared 1 GiB, body 100
    /// bytes, cap 4 GiB: under the cap, so the failure is the short read, not the bound.
    #[test]
    fn pax_size_lie_under_cap_is_unsafe_archive_not_internal_error() {
        let tar = pax_size_lie_short_tar("big.parquet", 1 << 30, &[0u8; 100]);
        let dest = tempfile::tempdir().unwrap();
        let bounds = ExtractBounds {
            max_total_bytes: 4u64 << 30,
            ..ExtractBounds::default()
        };
        let err = extract_tar_safely(&tar[..], dest.path(), &bounds).unwrap_err();
        assert_eq!(
            err.class(),
            ErrorClass::UnsafeArchive,
            "a member shorter than its declared PAX size is a malformed archive, not a \
             node fault; got {err} ({:?})",
            err.class()
        );
        assert!(
            !err.class().is_node_retriable(),
            "a permanently-malformed archive must not be retried"
        );
    }

    #[test]
    fn capped_reader_yields_up_to_cap_then_errors() {
        // The tar-input cap yields exactly `remaining` bytes, then errors with
        // `InvalidData`, rather than letting the tar decoder read an unbounded stream such
        // as a giant PAX or GNU extension-header body into memory.
        let data = [7u8; 100];
        let mut r = super::CappedReader {
            inner: &data[..],
            remaining: 40,
        };
        let mut out = Vec::new();
        let err = std::io::copy(&mut r, &mut out).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            out.len(),
            40,
            "reader yields exactly the cap before erroring"
        );
    }
}
