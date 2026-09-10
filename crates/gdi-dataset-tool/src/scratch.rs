//! A dot-prefixed, `0o700` scratch directory beside a target path, removed on
//! drop.
//!
//! Plaintext intermediates land on the same filesystem as the operator's target
//! (whatever volume they already secure), never a separate, possibly unencrypted or
//! RAM-backed `/tmp`. Scratch directories are `0o700` and removed on `Drop`, which
//! covers every normal exit including error and panic paths. A hard signal (Ctrl-C /
//! SIGTERM) skips `Drop`, so to bound the exposure of decrypted plaintext
//! [`Scratch::new`] also reaps stale sibling scratch directories left by a prior
//! interrupted run of the same target: matched on the exact `.<stem>.tmp.<pid>.<nanos>`
//! name, and only when their owning pid is known dead — or, on platforms where process
//! liveness cannot be probed, when the directory has gone stale. A live owner's scratch
//! is never reaped. `validate` uses this to decrypt and extract a `.tar.c4gh` for
//! inspection; `unpack` streams the decrypt straight into the extractor over a pipe and
//! never stages plaintext here.

use std::fs;
use std::path::{Path, PathBuf};

use crate::ToolError;

/// A `0o700` dot-prefixed scratch directory beside `target`, removed on drop.
pub struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    /// Create `.<basename>.tmp.<pid>.<nanos>/` next to `target` (same filesystem).
    ///
    /// # Errors
    ///
    /// Returns a [`ToolError`] (exit 1) if the directory cannot be created or its
    /// permissions cannot be set.
    pub fn new(target: &Path) -> Result<Self, ToolError> {
        let parent = target
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
        let stem = target
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("scratch");
        // Reap any plaintext left by a prior run of this target that died before `Drop`
        // ran (e.g. Ctrl-C), so leaked scratch does not accumulate silently here.
        reap_stale_siblings(&parent, stem);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = parent.join(format!(".{stem}.tmp.{}.{nanos}", std::process::id()));
        #[expect(
            clippy::disallowed_methods,
            reason = "the next statement chmods 0o700, covering a pre-existing dir too"
        )]
        fs::create_dir_all(&dir)
            .map_err(|e| ToolError::user(format!("cannot create {}: {e}", dir.display())))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
                .map_err(|e| ToolError::user(format!("cannot chmod {}: {e}", dir.display())))?;
        }
        Ok(Self { dir })
    }

    /// The scratch directory path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.dir
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // Best-effort cleanup on every normal exit (incl. error/panic paths). A hard
        // signal skips this — `reap_stale_siblings` is the backstop for that case.
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Best-effort: remove stale sibling scratch dirs left by a prior run **of this same
/// target** that died without running [`Scratch`]'s `Drop` (e.g. Ctrl-C).
///
/// A candidate must be named exactly `.<stem>.tmp.<pid>.<nanos>` — the leading dot and
/// the target's own `stem` are both required, so a directory this tool never created is
/// never a candidate, even in a shared, world-writable parent such as `/tmp`. Of those,
/// one is reaped only when its pid is not our own and [`should_reap`] agrees.
fn reap_stale_siblings(parent: &Path, stem: &str) {
    const STALE_AFTER: std::time::Duration = std::time::Duration::from_hours(1);
    let me = std::process::id();
    let Ok(entries) = fs::read_dir(parent) else {
        return;
    };
    let prefix = format!(".{stem}.tmp.");
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(pid) = scratch_pid(name, &prefix) else {
            continue;
        };
        if pid == me {
            continue;
        }
        let old = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age >= STALE_AFTER);
        if should_reap(pid_liveness(pid), old) {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
}

/// Extract the pid from a scratch dir name `.<stem>.tmp.<pid>.<nanos>`, given the
/// caller's precomputed `prefix` (`.<stem>.tmp.`). Returns `None` for any name that
/// does not carry that exact prefix, so a foreign directory is never matched.
fn scratch_pid(name: &str, prefix: &str) -> Option<u32> {
    let after = name.strip_prefix(prefix)?; // "<pid>.<nanos>"
    after.split_once('.')?.0.parse().ok()
}

/// Whether `pid` is a live process: `Some(true)`/`Some(false)` where the OS can tell us
/// (Linux `/proc/<pid>`), `None` where liveness is not knowable.
fn pid_liveness(pid: u32) -> Option<bool> {
    if cfg!(target_os = "linux") {
        Some(Path::new("/proc").join(pid.to_string()).exists())
    } else {
        None
    }
}

/// Reap a matching scratch only when its owner is known dead, or — where liveness is
/// not knowable — when it has gone stale. A live owner's scratch is never reaped, however
/// old: it belongs to a concurrent run and may hold an in-progress decrypted plaintext.
fn should_reap(alive: Option<bool>, old: bool) -> bool {
    match alive {
        Some(true) => false,
        Some(false) => true,
        None => old,
    }
}

/// Create a scratch file `0o600` on Unix (it holds decrypted or pre-rename bytes),
/// so intermediate sensitive content is never group/other-readable. The shared
/// helper for `pack` / `rekey` / `pkgio`.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) if the file cannot be created.
pub(crate) fn create_scratch_file(path: &Path) -> Result<fs::File, ToolError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| ToolError::user(format!("cannot create {}: {e}", path.display())))
    }
    #[cfg(not(unix))]
    {
        fs::File::create(path)
            .map_err(|e| ToolError::user(format!("cannot create {}: {e}", path.display())))
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;

    #[test]
    fn scratch_pid_parses_trailing_components() {
        // Stem with embedded dots must not confuse the `.tmp.<pid>.<nanos>` parse.
        assert_eq!(
            scratch_pid(".DS.tar.c4gh.tmp.4242.99", ".DS.tar.c4gh.tmp."),
            Some(4242)
        );
        assert_eq!(scratch_pid("not-a-scratch-dir", ".pkg.tmp."), None);
    }

    #[test]
    fn scratch_pid_requires_the_leading_dot_and_the_matching_stem() {
        // A foreign dir whose name merely contains `.tmp.<u32>.` is never matched.
        assert_eq!(
            scratch_pid("render.tmp.1699999999.cache", ".pkg.tmp."),
            None
        );
        // Another target's scratch is not ours to reap.
        assert_eq!(scratch_pid(".other.tmp.42.1", ".pkg.tmp."), None);
        // The leading dot is mandatory.
        assert_eq!(scratch_pid("pkg.tmp.42.1", ".pkg.tmp."), None);
        // A non-numeric pid slot is not a scratch dir.
        assert_eq!(scratch_pid(".pkg.tmp.notanum.1", ".pkg.tmp."), None);
    }

    /// A directory the tool never created must never be reaped, even when its name
    /// happens to carry a `.tmp.<number>.` substring whose number is not a live pid.
    #[test]
    fn reap_leaves_unrelated_directories_with_a_tmp_like_name() {
        let tmp = tempfile::tempdir().unwrap();
        // A third-party dir: no leading dot, not our stem; the number is not a live pid.
        let foreign = tmp.path().join(format!("render.tmp.{}.cache", u32::MAX));
        fs::create_dir_all(&foreign).unwrap();
        // A tool-shaped scratch, but for a different target stem.
        let other_stem = tmp.path().join(format!(".other.tmp.{}.1", u32::MAX));
        fs::create_dir_all(&other_stem).unwrap();
        // Our own stale scratch for this stem.
        let ours = tmp.path().join(format!(".pkg.tmp.{}.1", u32::MAX));
        fs::create_dir_all(&ours).unwrap();

        reap_stale_siblings(tmp.path(), "pkg");

        assert!(
            foreign.exists(),
            "an unrelated directory must never be reaped"
        );
        assert!(
            other_stem.exists(),
            "another target's scratch must not be reaped"
        );
        assert!(!ours.exists(), "our own stale scratch must be reaped");
    }

    /// Age alone must never reap a scratch whose pid is still alive: that dir belongs to
    /// a concurrent run and may hold an in-progress decrypted plaintext.
    #[cfg(target_os = "linux")]
    #[test]
    fn reap_never_removes_a_live_processes_scratch_however_old() {
        let tmp = tempfile::tempdir().unwrap();
        // pid 1 always exists on Linux and is never this test process.
        let live = tmp.path().join(".pkg.tmp.1.1");
        fs::create_dir_all(&live).unwrap();
        let two_hours_ago = std::time::SystemTime::now() - std::time::Duration::from_hours(2);
        let handle = fs::File::open(&live).unwrap();
        handle
            .set_times(fs::FileTimes::new().set_modified(two_hours_ago))
            .unwrap();

        reap_stale_siblings(tmp.path(), "pkg");

        assert!(
            live.exists(),
            "a live process's scratch must never be reaped on age alone"
        );
    }

    #[test]
    fn reaps_dead_pid_sibling_but_keeps_own_and_non_scratch() {
        let tmp = tempfile::tempdir().unwrap();
        let me = std::process::id();
        // A sibling from a dead pid (u32::MAX is never a live process) → reaped.
        let dead = tmp.path().join(format!(".pkg.tmp.{}.111", u32::MAX));
        fs::create_dir_all(&dead).unwrap();
        // A sibling tagged with our pid (a concurrent op of this very process) → kept.
        let mine = tmp.path().join(format!(".pkg.tmp.{me}.222"));
        fs::create_dir_all(&mine).unwrap();
        // A non-scratch dir (no `.tmp.` marker) → untouched.
        let other = tmp.path().join("datasets");
        fs::create_dir_all(&other).unwrap();

        reap_stale_siblings(tmp.path(), "pkg");

        assert!(!dead.exists(), "dead-pid scratch must be reaped");
        assert!(mine.exists(), "our own scratch must be kept");
        assert!(other.exists(), "non-scratch dirs must be untouched");
    }
}
