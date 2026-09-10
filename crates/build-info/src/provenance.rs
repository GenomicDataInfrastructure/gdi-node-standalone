// Resolution of the build-provenance values (git SHA and build epoch) and of the git paths
// whose movement invalidates them.
//
// `build.rs` `include!`s this file and runs it at compile time against the real repository;
// it is compiled a second time as a private `cfg(test)` module so the same code can be
// exercised against scratch repositories. A second copy of the ladder would drift from the
// one that stamps the binary, and the drift would be invisible: the stamped value looks
// plausible whether or not it is current.
//
// Because it is `include!`d it must stay self-contained (it owns its `use` items, and
// `build.rs` declares none of its own to collide with) and dependency-free, since a build
// script cannot depend on the crate it builds. The header is `//` and not `//!` for the
// same reason: an inner doc comment where `include!` pastes it is a compile error, E0753.

use std::path::Path;
use std::process::Command;

/// Width the stamped git SHA is abbreviated to.
///
/// `GITHUB_SHA` is a full 40-hex commit id, while `git rev-parse --short=12` returns a
/// *minimum* of 12 characters (more when 12 would be ambiguous). Without normalising
/// both, the stamped value changes width depending on where the binary was built.
/// Twelve hex characters stay a prefix of the full id, so comparing against a
/// full-length value — an image's `org.opencontainers.image.revision` label, say —
/// still matches by prefix.
pub(crate) const SHA_ABBREV: usize = 12;

/// The value stamped when no provenance can be resolved.
pub(crate) const UNKNOWN: &str = "unknown";

/// Run `git ARGS` in `dir`, returning the trimmed stdout on success.
///
/// Any failure — no `git` on `PATH`, no repository, a non-zero exit, non-UTF-8 or empty
/// output — yields `None`, so every caller falls through to its own default.
pub(crate) fn git_in(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_owned();
    (!s.is_empty()).then_some(s)
}

/// Truncate `sha` to [`SHA_ABBREV`] characters, leaving anything shorter — or not
/// sliceable there, so never a hex id — untouched, [`UNKNOWN`] included.
pub(crate) fn abbrev(sha: &str) -> &str {
    sha.get(..SHA_ABBREV).unwrap_or(sha)
}

/// The git SHA to stamp: `env_sha` (CI's `GITHUB_SHA`) when non-empty, else the
/// repository's `HEAD`, else [`UNKNOWN`]. Always abbreviated to [`SHA_ABBREV`].
pub(crate) fn resolve_sha(dir: &Path, env_sha: Option<&str>) -> String {
    let sha = env_sha
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .or_else(|| git_in(dir, &["rev-parse", "--short=12", "HEAD"]))
        .unwrap_or_else(|| UNKNOWN.to_owned());
    abbrev(&sha).to_owned()
}

/// The build epoch to stamp: `env_epoch` (`SOURCE_DATE_EPOCH`) when non-empty, else the
/// `HEAD` commit's committer epoch, else [`UNKNOWN`].
///
/// The committer epoch is commit-stable, so a rebuild from a given commit stamps the
/// same value — which is what keeps a from-source rebuild reproducible without anyone
/// having to set `SOURCE_DATE_EPOCH`.
pub(crate) fn resolve_epoch(dir: &Path, env_epoch: Option<&str>) -> String {
    env_epoch
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .or_else(|| git_in(dir, &["log", "-1", "--format=%ct"]))
        .unwrap_or_else(|| UNKNOWN.to_owned())
}

/// The git paths to watch so that a moved commit invalidates the stamped values.
///
/// Cargo re-runs a build script when a watched path changes, so this set decides whether
/// the stamp stays current. The resolved branch ref must be in it: `HEAD` is normally a
/// *symref* whose contents (`ref: refs/heads/<branch>`) do not change when you commit,
/// while the branch ref does. On a detached `HEAD` there is no symref, `symbolic-ref`
/// fails, and the `HEAD` file itself holds the commit id, so it is already the right
/// trigger. A path is watched even when it does not exist yet, because `git pack-refs`
/// deletes the loose ref file and the next commit recreates it; cargo notices the creation
/// without re-running the script on every build.
///
/// `--git-path` resolves each name to its real location, which is what makes this correct
/// inside a linked worktree (`HEAD` is per-worktree, `packed-refs` and the branch refs live
/// in the common directory). Outside a repository every `git` call fails and the set is
/// empty; the values are then [`UNKNOWN`] anyway, so there is nothing to invalidate.
pub(crate) fn watch_paths(dir: &Path) -> Vec<String> {
    let mut names = vec!["HEAD".to_owned(), "packed-refs".to_owned()];
    if let Some(head_ref) = git_in(dir, &["symbolic-ref", "-q", "HEAD"]) {
        names.push(head_ref);
    }
    names
        .iter()
        .filter_map(|name| git_in(dir, &["rev-parse", "--git-path", name]))
        .collect()
}
