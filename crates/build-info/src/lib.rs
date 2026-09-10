//! Compile-time build provenance shared by the `gdi-node-standalone` binaries.
//!
//! Both the service (`gdi-node-standalone`) and the `gdi-dataset-tool` embed the git
//! commit SHA and a build epoch in their version output (`--version` / `GET /version` /
//! the `gdi_build_info` metric). The values are produced by this crate's `build.rs` —
//! `GITHUB_SHA` / `SOURCE_DATE_EPOCH` when set, else read from `git`, else `"unknown"`
//! — and exposed here as constants, so both binaries report the same build. See
//! `src/provenance.rs` for the full resolution ladder.
//!
//! `rustc-env` vars are crate-scoped, so this crate is the only place
//! `env!("GDI_GIT_SHA")` / `env!("GDI_BUILD_EPOCH")` resolve.
//!
//! The constants live here; the rendering does not. [`version_provenance`] is the
//! tool's `--version` line, while the service prints its own so it can carry
//! `gdi_metadata_version` too. Tests on either side hold both to the same provenance
//! substrings, so a change to the shape here needs the matching change to
//! `gdi-node-standalone`'s `version_line`.

/// The git commit the binary was built from, abbreviated to 12 hex characters:
/// `GITHUB_SHA` when set, else the repository's `HEAD`, else `"unknown"` when no
/// repository is reachable (as inside the container image, whose `.dockerignore`
/// excludes `.git`).
///
/// Reflects `HEAD`, not the working tree: a build with uncommitted changes reports the
/// commit it was based on, with no marker distinguishing it.
pub const GIT_SHA: &str = env!("GDI_GIT_SHA");

/// The build epoch in Unix seconds: `SOURCE_DATE_EPOCH` when set, else the `HEAD`
/// commit's committer epoch, else `"unknown"` when no repository is reachable.
pub const BUILD_EPOCH: &str = env!("GDI_BUILD_EPOCH");

/// Format the provenance-bearing `--version` value: `"{version} (git {sha}, build_epoch
/// {epoch})"`.
///
/// The binary name is not included. clap already renders `--version` as
/// `"{bin_name} {version}"`, so a name baked in here is printed twice
/// (`gdi-dataset-tool gdi-dataset-tool 0.1.0 …`). Callers that render the line themselves
/// prepend their own name.
///
/// # Examples
///
/// ```
/// let v = gdi_build_info::version_provenance("0.1.0");
/// assert!(v.starts_with("0.1.0 (git "));
/// assert!(v.contains(", build_epoch "));
/// assert!(v.ends_with(')'));
/// // The name is the caller's (or clap's) to add, never ours.
/// assert!(!v.contains("gdi-dataset-tool"));
/// ```
#[must_use]
pub fn version_provenance(version: &str) -> String {
    format!("{version} (git {GIT_SHA}, build_epoch {BUILD_EPOCH})")
}

// The ladder that `build.rs` runs at compile time, compiled again here so the tests
// below exercise the very code that stamps the binary rather than a second copy of it.
#[cfg(test)]
#[path = "provenance.rs"]
mod provenance;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_provenance_embeds_version_git_and_epoch() {
        let v = version_provenance("9.9.9");
        assert!(
            v.starts_with("9.9.9 (git "),
            "must lead with the bare version + git; got: {v}"
        );
        assert!(
            v.contains(", build_epoch "),
            "must carry build_epoch; got: {v}"
        );
        assert!(v.ends_with(')'), "must be parenthesized; got: {v}");
    }

    /// clap renders `--version` as `"{bin_name} {version}"`, so a binary name baked into
    /// this string is printed twice. The provenance value must never carry a name of its
    /// own.
    #[test]
    fn version_provenance_never_embeds_a_binary_name() {
        let v = version_provenance("9.9.9");
        assert!(
            !v.contains("gdi-"),
            "the name is clap's to prepend; got: {v}"
        );
    }

    #[test]
    fn provenance_consts_are_nonempty() {
        // build.rs injects these (at minimum "unknown"); a missing var would fail to
        // compile via `env!`, so this also guards that the build script ran.
        assert!(!GIT_SHA.is_empty());
        assert!(!BUILD_EPOCH.is_empty());
    }
}

/// Tests for the compile-time resolution ladder, run against scratch repositories.
///
/// Nothing else reaches `build.rs`, and a `cargo test` that only checks string formatting
/// cannot see a defect in the ladder that stamps the binary.
#[cfg(test)]
mod provenance_tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

    use crate::provenance::{
        SHA_ABBREV, UNKNOWN, abbrev, git_in, resolve_epoch, resolve_sha, watch_paths,
    };
    use std::path::{Path, PathBuf};
    use std::process::Command;

    /// Run `git ARGS` in `dir`, asserting success. [`git_in`] cannot serve here: it
    /// reports empty stdout as failure, and `git init` / `git commit -q` are silent on
    /// success.
    fn git(dir: &Path, args: &[&str]) {
        let status = Command::new("git")
            .current_dir(dir)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed in {}", dir.display());
    }

    fn commit(dir: &Path) {
        // `--no-verify`: a contributor's hooks must never run inside a scratch repo.
        git(
            dir,
            &["commit", "-q", "--no-verify", "--allow-empty", "-m", "c"],
        );
    }

    /// A scratch repository with one commit and a local identity.
    fn repo() -> tempfile::TempDir {
        let td = tempfile::tempdir().unwrap();
        let dir = td.path();
        git(dir, &["init", "-q"]);
        git(dir, &["config", "user.email", "test@example.invalid"]);
        git(dir, &["config", "user.name", "test"]);
        git(dir, &["config", "commit.gpgsign", "false"]);
        commit(dir);
        td
    }

    /// Read the contents of `paths`, recording a path that does not exist as absent
    /// rather than skipping it — appearing is itself a change.
    ///
    /// `--git-path` yields a path relative to the working directory in an ordinary
    /// checkout and an absolute one inside a linked worktree, so relative entries are
    /// joined to `dir` here (cargo resolves them against the package root, which is
    /// where the build script runs).
    fn read_all(dir: &Path, paths: &[String]) -> Vec<Option<Vec<u8>>> {
        paths
            .iter()
            .map(|p| {
                let full = if Path::new(p).is_absolute() {
                    PathBuf::from(p)
                } else {
                    dir.join(p)
                };
                std::fs::read(full).ok()
            })
            .collect()
    }

    /// Assert that `op` invalidates the stamp: the watch set is captured once, before the
    /// change, and only that set is re-read afterwards.
    ///
    /// Recomputing the set afterwards would be a false pass, because cargo compares the
    /// paths the *previous* build emitted and can never notice a path it was not told
    /// about.
    fn assert_invalidates(dir: &Path, why: &str, op: impl FnOnce(&Path)) {
        let watched = watch_paths(dir);
        assert!(
            !watched.is_empty(),
            "precondition: nothing is being watched"
        );
        let before = read_all(dir, &watched);

        op(dir);

        assert_ne!(before, read_all(dir, &watched), "{why}");
    }

    /// `.git/HEAD` is a symref whose contents (`ref: refs/heads/x`) do not change when you
    /// commit; the branch ref does. Watching `HEAD` alone leaves every post-commit build
    /// stamping the previous commit.
    #[test]
    fn a_commit_changes_the_watched_state_with_loose_refs() {
        let td = repo();
        let dir = td.path();
        let before_sha = resolve_sha(dir, None);

        assert_invalidates(
            dir,
            "no watched path changed across a commit, so cargo will not re-run the \
             build script and the stamped SHA stays one commit stale",
            commit,
        );

        assert_ne!(
            before_sha,
            resolve_sha(dir, None),
            "precondition: the commit must have moved HEAD"
        );
    }

    /// The same with refs packed. `git pack-refs` deletes the loose ref file, so filtering
    /// the watch set by existence drops the branch ref precisely in the window where the
    /// next commit recreates it.
    #[test]
    fn a_commit_changes_the_watched_state_with_packed_refs() {
        let td = repo();
        let dir = td.path();
        git(dir, &["pack-refs", "--all"]);

        assert_invalidates(
            dir,
            "with refs packed the branch ref does not exist at build time; it must be \
             watched anyway, or the commit that recreates it triggers no re-run",
            commit,
        );
    }

    /// On a detached `HEAD` there is no symref to resolve and the `HEAD` file itself
    /// carries the commit id, so it is already the right trigger. This is the regime a
    /// CI checkout leaves behind.
    #[test]
    fn a_commit_changes_the_watched_state_on_a_detached_head() {
        let td = repo();
        let dir = td.path();
        git(dir, &["checkout", "-q", "--detach", "HEAD"]);

        assert_invalidates(
            dir,
            "a detached HEAD file holds the commit id and must invalidate the stamp",
            commit,
        );
    }

    #[test]
    fn the_env_sha_wins_and_is_abbreviated_to_one_width() {
        let td = repo();
        let dir = td.path();
        let full = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(resolve_sha(dir, Some(full)), full[..SHA_ABBREV].to_owned());
    }

    #[test]
    fn an_empty_env_sha_falls_through_to_git() {
        let td = repo();
        let dir = td.path();
        let head = git_in(dir, &["rev-parse", "HEAD"]).unwrap();
        let stamped = resolve_sha(dir, Some(""));

        assert_eq!(stamped.len(), SHA_ABBREV, "the stamped width must not vary");
        assert!(
            head.starts_with(&stamped),
            "{stamped} must be a prefix of {head}"
        );
        assert_eq!(stamped, resolve_sha(dir, None), "unset must match empty");
    }

    #[test]
    fn the_env_epoch_wins_and_git_supplies_a_commit_stable_fallback() {
        let td = repo();
        let dir = td.path();
        assert_eq!(resolve_epoch(dir, Some("1700000000")), "1700000000");

        let from_git = resolve_epoch(dir, None);
        assert!(
            from_git.chars().all(|c| c.is_ascii_digit()),
            "the committer epoch must be bare Unix seconds; got {from_git}"
        );
        assert_eq!(
            from_git,
            resolve_epoch(dir, Some("")),
            "an empty env value must fall through"
        );
        assert_eq!(
            from_git,
            resolve_epoch(dir, None),
            "the same commit must stamp the same epoch — this is what keeps a \
             from-source rebuild reproducible"
        );
    }

    #[test]
    fn outside_a_repository_both_values_are_unknown() {
        let td = tempfile::tempdir().unwrap();
        let dir = td.path();
        // git walks up, so this says nothing if TMPDIR itself sits inside a repository.
        // Assert that precondition rather than passing for the wrong reason.
        assert!(
            git_in(dir, &["rev-parse", "--git-dir"]).is_none(),
            "TMPDIR is inside a git repository; this test needs a repo-free scratch dir"
        );
        assert_eq!(resolve_sha(dir, None), UNKNOWN);
        assert_eq!(resolve_epoch(dir, None), UNKNOWN);
        assert!(
            watch_paths(dir).is_empty(),
            "nothing to invalidate when there is no repository"
        );
    }

    #[test]
    fn abbrev_leaves_anything_shorter_untouched() {
        assert_eq!(abbrev("0123456789abcdef"), "0123456789ab");
        assert_eq!(abbrev(UNKNOWN), UNKNOWN);
        assert_eq!(abbrev("abc"), "abc");
    }
}
