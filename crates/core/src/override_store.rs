//! Presence assertion for the operator-override store root.
//!
//! The store under `[service].override_dir` holds operator *intent*: dataset and channel
//! suppressions (`suppressions/`) and metadata corrections (`overlays/`). Unlike every
//! other directory on the data volume, none of it is reconstructible by re-ingesting from
//! the source bucket. Re-ingest restores each dataset to its *source-resolved* state,
//! which is the state an operator overrode.
//!
//! [`crate::suppression::load`] and [`crate::overlay_override::load`] both treat an
//! unreadable root as the empty set, because a node that has never suppressed anything
//! is indistinguishable on disk from one whose store has been destroyed. That default
//! is right for a fresh node and catastrophic after a data-volume loss: the documented
//! recovery (fresh PVC, re-ingest from the bucket) would silently re-serve every
//! withheld dataset, with no metric and no alert.
//!
//! `[service].require_override_store` lets an operator resolve that ambiguity from
//! *outside* the volume. The config is mounted from a ConfigMap/Secret, so it survives
//! the incident that destroys the store; setting the flag asserts "this node has an
//! override store", turning an absent root from a silent empty set into a refusal to
//! serve.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::error::{CoreError, CoreResult};

/// One loader store: the directory its loader opens, and the entry-name predicate that
/// loader admits.
struct Loader {
    dir: PathBuf,
    admits: fn(&str) -> bool,
}

/// The two loader stores, `root/suppressions/` and `root/overlays/`, each paired with what
/// its loader admits. Named once so the presence verdict, the populated probe and the boot
/// materialisation cannot drift from the set the loaders read, and so a third store cannot
/// be added without saying what it admits.
fn loaders(root: &Path) -> [Loader; 2] {
    [
        Loader {
            dir: crate::suppression::suppressions_subdir(root),
            admits: |name| crate::suppression::classify_entry(name).is_some(),
        },
        Loader {
            dir: crate::overlay_override::overlays_subdir(root),
            admits: |name| crate::overlay_override::loader_entry_id(name).is_some(),
        },
    ]
}

/// The two directories the loaders actually open: `root/suppressions/` and
/// `root/overlays/`.
///
/// Public so `overrides export`/`import` back up the set the loaders read, deriving both
/// the directories and the bundle's keys from here rather than restating the pair. A third
/// loader directory then flows into the backup for free.
#[must_use]
pub fn loader_dirs(root: &Path) -> [PathBuf; 2] {
    loaders(root).map(|loader| loader.dir)
}

/// Create a store's own directory **and every sibling loader directory**.
///
/// The write path for each store calls this instead of creating only its own directory, so
/// the first override of any kind materialises both. That is what makes [`is_present`]'s
/// reading true on a node that has not set `require_override_store`, where
/// [`ensure_present`] is a no-op: a missing subdirectory means the store was destroyed.
///
/// If the two directories could appear independently, `overrides export` would refuse to
/// run on a node that has recorded a suppression but never an overlay: it treats an absent
/// directory as an error rather than an empty map, because a backup that silently captured
/// nothing is worse than none.
///
/// Derives the root from `dir`'s parent: both loader directories are `root.join(_)` by
/// construction, so the parent is the root. A `dir` with no parent falls back to creating
/// just itself rather than guessing.
///
/// # Errors
/// Propagates the directory-creation [`std::io::Error`].
pub fn create_store_dir(dir: &Path) -> std::io::Result<()> {
    let Some(root) = dir.parent() else {
        return crate::util::create_private_dir(dir);
    };
    for sub in loader_dirs(root) {
        crate::util::create_private_dir(&sub)?;
    }
    Ok(())
}

/// `dir/{id}.json` for a dataset-keyed override store, rejecting an id that is not a valid
/// dataset id.
///
/// The one path builder every override store must use. The guard is a property of the
/// store, not of today's callers: a writer under `<override_dir>/` that took an
/// unvalidated id could be steered into `<override_dir>/reingest/../../x.json` with the
/// node's uid and operator-controlled content.
///
/// # Errors
///
/// [`std::io::ErrorKind::InvalidInput`] when `id` is not a valid dataset id.
pub fn store_file_path(dir: &Path, id: &str) -> std::io::Result<PathBuf> {
    if !crate::id::is_valid_dataset_id(id) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid dataset id {id:?}"),
        ));
    }
    Ok(dir.join(format!("{id}.json")))
}

/// The scope of a lift record: which override store the lifted entry came from, and
/// therefore which validator its key must pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LiftScope {
    /// A dataset-level override (`suppressions/{id}.json`); the key is a dataset id.
    Dataset,
    /// A channel-level override (`suppressions/channel-{name}.json`); the key is a channel
    /// name.
    Channel,
}

impl LiftScope {
    /// The wire and log spelling (`"dataset"` / `"channel"`), mirroring the serde rename
    /// above. An explicit `match`, for callers that need a `&'static str`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dataset => "dataset",
            Self::Channel => "channel",
        }
    }
}

/// `dir/{key}.{fresh-suffix}.json` for a lift record, rejecting a key the scope's loader
/// would reject: a dataset id via [`crate::id::is_valid_dataset_id`], a channel name via
/// [`crate::suppression::is_valid_channel_name`].
///
/// The lift-record sibling of [`store_file_path`]: the same guard with a different filename
/// shape. A record is append-only, so every call names a fresh file, and a channel key is
/// not a dataset id.
///
/// # Errors
///
/// [`std::io::ErrorKind::InvalidInput`] when `key` is not valid for `scope`.
pub fn lifted_file_path(dir: &Path, scope: LiftScope, key: &str) -> std::io::Result<PathBuf> {
    let valid = match scope {
        LiftScope::Dataset => crate::id::is_valid_dataset_id(key),
        LiftScope::Channel => crate::suppression::is_valid_channel_name(key),
    };
    if !valid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid {} key {key:?}", scope.as_str()),
        ));
    }
    Ok(dir.join(format!("{key}.{}.json", crate::util::rand_suffix())))
}

/// Whether the override store is present and readable.
///
/// "Intact" means the root and both loader directories. Checking only the root is not
/// enough: the loaders read `root/suppressions/` and `root/overlays/`, so a root that
/// survives while a subdirectory is deleted or made unreadable would pass the fail-closed
/// guard, the loader would return the empty set, and every operator withhold would be
/// silently lifted.
///
/// This whole-store verdict is for the boot assertion, `doctor`, and the absent gauge. A
/// loader must not use it: the two stores fail independently, so each checks its own
/// directory via [`loader_dir_present`].
#[must_use]
pub fn is_present(root: &Path) -> bool {
    root.is_dir() && loader_dirs(root).iter().all(|dir| loader_dir_present(dir))
}

/// Whether one loader's directory is present and readable.
///
/// The check that must accompany every fail-closed load, naming the same directory the
/// loader is about to read. A guard that checks a different path than the load is
/// decorative. Each caller passes its own subdirectory
/// ([`crate::suppression::suppressions_subdir`], [`crate::overlay_override::overlays_subdir`])
/// rather than sharing one root-level verdict, because the two stores fail independently.
///
/// Probes with `read_dir`, the same `opendir` the loaders issue, rather than `is_dir`. A
/// present-but-unreadable directory (EACCES, EIO or ESTALE on a network volume, EMFILE
/// under fd exhaustion) satisfies `stat` but fails `opendir`, so an `is_dir` guard would
/// pass while the loader read the empty set and silently lifted every withhold. Using the
/// loader's own operation makes guard and loader agree: whatever the loader cannot read,
/// this reports absent, and the caller keeps its last-good set.
#[must_use]
pub fn loader_dir_present(dir: &Path) -> bool {
    std::fs::read_dir(dir).is_ok()
}

/// `Ok(())` when `dir` is readable or absent, `Err` when it exists but cannot be read.
///
/// The boot-time half of the split the loaders make at runtime
/// ([`crate::suppression::load`], [`crate::overlay_override::load`]): absence is ambiguous
/// and tolerated, an I/O fault is not. [`loader_dir_present`] collapses both into "not
/// present", because its caller keeps its last-good set either way. This one keeps them
/// apart, because at boot there is no last-good set, and serving with an unknowable
/// withhold set is the disclosure the store exists to prevent.
///
/// # Errors
///
/// The underlying `read_dir` error when the directory exists but cannot be opened.
pub fn readable_or_absent(dir: &Path) -> std::io::Result<()> {
    match std::fs::read_dir(dir) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Whether the store currently holds at least one operator override: an entry a loader
/// would load, not merely a directory entry.
///
/// The used-marker input, and the advisory for a node with real overrides but no
/// `require_override_store`. It admits what the loaders admit
/// ([`crate::suppression::classify_entry`], [`crate::overlay_override::loader_entry_id`]).
/// A `.tmp.{pid}.{n}` sibling left by a crashed durable write, a `.gitkeep`, a `notes.json`
/// or an entry under an invalid id populates nothing, because the node applies nothing for
/// it. Counting any entry instead would let a node boot green with
/// `require_override_store` over a store the loaders read as empty. Counts `suppressions/`
/// and `overlays/` only: a `reingest/` marker is a transient request, not durable operator
/// intent. An entry that cannot be classified does not count, because the loaders skip it
/// too.
#[must_use]
pub fn is_populated(root: &Path) -> bool {
    loaders(root).iter().any(|loader| {
        std::fs::read_dir(&loader.dir).is_ok_and(|entries| {
            entries
                .flatten()
                .any(|entry| entry.file_name().to_str().is_some_and(loader.admits))
        })
    })
}

/// Assert the override-store root is present when the operator has declared it must be.
///
/// A no-op when `required` is false, which is the default posture and the correct one
/// for a node that has never recorded an override.
///
/// # This function must not create anything
///
/// A fail-closed presence assertion has to be a pure function of a filesystem it did not
/// touch. Materialising the loader directories and then testing them would check its own
/// side effect, so a re-provisioned empty volume would pass and the node would serve every
/// withheld dataset with `/health/ready` green. Nothing on the data volume would show the
/// withholds ever existed.
///
/// Creation belongs to [`create_store_dir`], the write-path chokepoint every override
/// writer already calls, and to the explicit `overrides init` verb for a node that
/// declares the store required before it has recorded an override.
///
/// # Errors
///
/// Returns [`CoreError::InvalidConfig`] when `required` is set and the store is not
/// intact: the root absent or not a directory, or either loader directory missing or
/// unreadable.
pub fn ensure_present(root: &Path, required: bool) -> CoreResult<()> {
    if !required {
        return Ok(());
    }
    if is_present(root) {
        return Ok(());
    }
    Err(CoreError::InvalidConfig {
        detail: "service.require_override_store is set but the operator-override store is \
                 not intact: the root is absent, is not a directory, or one of its \
                 `suppressions/` and `overlays/` directories is missing or unreadable. \
                 Operator suppressions and metadata corrections cannot be rebuilt by \
                 re-ingesting from the source bucket, so serving now would silently \
                 re-disclose every withheld dataset. If the store volume was lost, restore \
                 it from backup with `overrides import`. If this node genuinely has no \
                 overrides yet, initialise the empty store with `overrides init`, or clear \
                 service.require_override_store"
            .to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_present_root_with_no_loader_subdirs_is_not_present() {
        // A root that survives while a subdirectory is deleted or becomes unreadable must
        // not pass the fail-closed guard: the loaders read `root/suppressions/` and
        // `root/overlays/`, so they would return the empty set and every operator withhold
        // or correction would be silently dropped.
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("overrides");
        std::fs::create_dir_all(&root).expect("create root");
        assert!(
            !is_present(&root),
            "a root with no loader directories cannot serve overrides"
        );

        std::fs::create_dir_all(crate::suppression::suppressions_subdir(&root))
            .expect("create suppressions subdir");
        assert!(
            !is_present(&root),
            "one loader directory is not an intact store"
        );

        std::fs::create_dir_all(crate::overlay_override::overlays_subdir(&root))
            .expect("create overlays subdir");
        assert!(
            is_present(&root),
            "root + both loader dirs is an intact store"
        );
    }

    #[test]
    fn an_empty_but_present_root_is_refused_and_not_materialised() {
        // The case the flag exists for: a re-provisioned volume mounts a fresh empty
        // directory, so the root is a directory while every withhold is gone. If
        // `ensure_present` created the loader directories it would be testing its own side
        // effect, and the node would boot green with every withhold silently lifted.
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("overrides");
        std::fs::create_dir_all(&root).expect("create root");

        let err = ensure_present(&root, true)
            .expect_err("an empty re-provisioned store root must refuse to serve");
        std::assert_matches!(
            err,
            CoreError::InvalidConfig { .. },
            "expected InvalidConfig, got {err:?}"
        );
        assert!(
            !crate::suppression::suppressions_subdir(&root).exists(),
            "a presence ASSERTION must not create the thing it is asserting"
        );
        assert!(
            !crate::overlay_override::overlays_subdir(&root).exists(),
            "a presence ASSERTION must not create the thing it is asserting"
        );
    }

    #[test]
    fn required_and_missing_root_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("overrides");

        let err =
            ensure_present(&missing, true).expect_err("a required-but-absent store must fail");

        std::assert_matches!(
            err,
            CoreError::InvalidConfig { .. },
            "expected InvalidConfig, got {err:?}"
        );
    }

    #[test]
    fn required_and_intact_store_is_accepted() {
        // "Intact" is the root plus both loader directories, the set the loaders read.
        // `create_store_dir`, the write-path chokepoint that `overrides init` also calls,
        // produces that, so any node that has recorded an override or been initialised
        // passes without `ensure_present` creating anything.
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("overrides");
        create_store_dir(&crate::suppression::suppressions_subdir(&root))
            .expect("materialise the store the way a writer does");

        ensure_present(&root, true).expect("an intact store must pass");
    }

    #[test]
    fn not_required_and_missing_root_is_accepted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("overrides");

        ensure_present(&missing, false)
            .expect("the default posture must not fail a node with no store");
    }

    #[test]
    fn required_and_root_is_a_file_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let as_file = dir.path().join("overrides");
        std::fs::write(&as_file, b"not a directory").expect("write file");

        ensure_present(&as_file, true).expect_err("a non-directory root must fail");
    }

    #[test]
    fn is_populated_sees_a_suppression() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("overrides");
        assert!(!is_populated(&root), "a missing root holds nothing");

        let sub = crate::suppression::suppressions_subdir(&root);
        std::fs::create_dir_all(&sub).expect("create subdir");
        assert!(
            !is_populated(&root),
            "an empty suppressions dir is still unpopulated"
        );

        // `ds-1` is not a valid dataset id, so the loader ignores this file and it must
        // not populate the store either. A marker set over it would assert a withhold the
        // node never applies.
        std::fs::write(sub.join("ds-1.json"), b"{}").expect("write entry");
        assert!(
            !is_populated(&root),
            "an entry the loader ignores does not populate the store"
        );

        std::fs::write(sub.join("GDI-EE-UTARTU-20260409143052837.json"), b"{}")
            .expect("write entry");
        assert!(
            is_populated(&root),
            "a suppression the loader admits counts"
        );
    }

    #[test]
    fn is_populated_sees_a_channel_suppression() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("overrides");
        let sub = crate::suppression::suppressions_subdir(&root);
        std::fs::create_dir_all(&sub).expect("create subdir");
        std::fs::write(sub.join("channel-primary.json"), b"{}").expect("write entry");

        assert!(is_populated(&root), "a channel suppression counts");
    }

    #[test]
    fn is_populated_sees_an_overlay() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("overrides");
        let sub = crate::overlay_override::overlays_subdir(&root);
        std::fs::create_dir_all(&sub).expect("create subdir");
        std::fs::write(sub.join("ds-1.json"), b"{}").expect("write entry");
        assert!(
            !is_populated(&root),
            "an entry the overlay loader ignores does not populate the store"
        );

        std::fs::write(sub.join("GDI-EE-UTARTU-20260409143052837.json"), b"{}")
            .expect("write entry");
        assert!(is_populated(&root), "an overlay the loader admits counts");
    }

    #[test]
    fn is_populated_ignores_every_entry_the_loaders_ignore() {
        // The used marker must mean what the loaders would load. A stray entry they skip
        // (the `.tmp.{pid}.{n}` a crashed durable write leaves behind, a `.gitkeep`, a
        // `notes.json`, a `channel-` file with an unsafe name) must not make the probe say
        // "populated" while the node applies nothing. The probe admits what the loaders
        // admit, in both directories.
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("overrides");
        for sub in loader_dirs(&root) {
            std::fs::create_dir_all(&sub).expect("create subdir");
            for junk in [
                "GDI-EE-UTARTU-20260409143052837.json.tmp.123.4",
                ".gitkeep",
                "notes.json",
                "GDI-EE-UTARTU-20260409143052837",
                "gdi-ee-utartu-20260409143052837.json",
                "channel-.json",
                "channel-..json",
            ] {
                std::fs::write(sub.join(junk), b"{}").expect("write junk");
            }
        }
        assert!(
            !is_populated(&root),
            "junk in both loader directories must not populate the store"
        );
    }

    #[test]
    fn is_populated_ignores_transient_reingest_markers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("overrides");
        let sub = crate::reingest_request::requests_subdir(&root);
        std::fs::create_dir_all(&sub).expect("create subdir");
        std::fs::write(sub.join("ds-1.json"), b"{}").expect("write entry");

        assert!(
            !is_populated(&root),
            "reingest markers are transient requests, not durable intent, and must not trigger the advisory"
        );
    }

    #[test]
    fn is_present_distinguishes_dir_from_missing_and_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("overrides");
        assert!(!is_present(&root), "missing root must not be present");

        // A bare root is not enough: `suppression::load` reads `root/suppressions/`, and a
        // presence check that stops at the root would pass while the directory holding the
        // withholds is gone (see `a_present_root_with_no_loader_subdirs_is_not_present`).
        std::fs::create_dir_all(&root).expect("create root");
        assert!(
            !is_present(&root),
            "a root without suppressions/ is not readable"
        );

        std::fs::create_dir_all(crate::suppression::suppressions_subdir(&root))
            .expect("create suppressions subdir");
        std::fs::create_dir_all(crate::overlay_override::overlays_subdir(&root))
            .expect("create overlays subdir");
        assert!(is_present(&root), "root + both loader dirs must be present");

        let as_file = dir.path().join("file");
        std::fs::write(&as_file, b"x").expect("write file");
        assert!(!is_present(&as_file), "a file must not count as present");
    }

    #[cfg(unix)]
    #[test]
    fn loader_dir_present_is_false_for_a_present_but_unreadable_dir() {
        // `loader_dir_present` must probe with `read_dir` (`opendir`), the loader's own
        // syscall, rather than `is_dir` (`stat`). A directory that exists but cannot be
        // opened (EACCES) satisfies `stat` yet fails the loader's read, so a `stat`-based
        // guard would pass and the loader would adopt the empty set, silently lifting every
        // withhold.
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let sub = dir.path().join("suppressions");
        std::fs::create_dir_all(&sub).expect("create subdir");
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o000)).expect("chmod");

        // Probe rather than guess uid: root bypasses EACCES, so if the directory still
        // opens the scenario is untestable on this host. Restore permissions and skip.
        if std::fs::read_dir(&sub).is_ok() {
            std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o755)).ok();
            return;
        }

        assert!(sub.is_dir(), "the directory still exists — `stat` succeeds");
        assert!(
            !loader_dir_present(&sub),
            "a present-but-unreadable loader dir must read as absent (read_dir, not is_dir)"
        );

        // Restore so the tempdir can clean itself up.
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o755)).ok();
    }

    #[test]
    fn store_file_path_refuses_an_id_that_would_escape_the_store() {
        // One path builder, shared by every override store, so no caller can build the
        // same path shape from an unvalidated id.
        let dir = std::path::Path::new("/var/lib/gdi/overrides/reingest");
        for bad in [
            "../../etc/cron.d/x",
            "..",
            ".",
            "/etc/passwd",
            "GDI-EE-UTARTU-1/../../x",
            "",
        ] {
            let err = store_file_path(dir, bad)
                .expect_err("an id that is not a valid dataset id must be refused");
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "id {bad:?}");
        }
        // A well-formed id still resolves, inside the directory it was given.
        let ok = store_file_path(dir, "GDI-EE-UTARTU-1").expect("a valid id resolves");
        assert_eq!(ok, dir.join("GDI-EE-UTARTU-1.json"));
    }

    #[test]
    fn lifted_file_path_refuses_a_key_its_scope_would_not_load() {
        // The scope picks the validator, so a channel name is refused as a dataset key
        // and a traversal is refused as either.
        let dir = std::path::Path::new("/var/lib/gdi/overrides/lifted");
        for bad in ["../../etc/cron.d/x", "..", ".", "/etc/passwd", ""] {
            for scope in [LiftScope::Dataset, LiftScope::Channel] {
                let err = lifted_file_path(dir, scope, bad).expect_err("must be refused");
                assert_eq!(
                    err.kind(),
                    std::io::ErrorKind::InvalidInput,
                    "{scope:?} key {bad:?}"
                );
            }
        }
        lifted_file_path(dir, LiftScope::Dataset, "primary")
            .expect_err("a channel name is not a dataset id");

        let ok = lifted_file_path(dir, LiftScope::Dataset, "GDI-EE-UTARTU-1").expect("valid");
        assert_eq!(ok.parent(), Some(dir), "inside the directory it was given");
        let name = ok.file_name().and_then(|n| n.to_str()).expect("utf-8 name");
        assert!(
            name.starts_with("GDI-EE-UTARTU-1.")
                && std::path::Path::new(name)
                    .extension()
                    .is_some_and(|ext| ext == "json"),
            "append-only: `{{key}}.{{suffix}}.json`, got {name:?}"
        );
        let again = lifted_file_path(dir, LiftScope::Dataset, "GDI-EE-UTARTU-1").expect("valid");
        assert_ne!(ok, again, "every call names a fresh file");
        let ch = lifted_file_path(dir, LiftScope::Channel, "primary").expect("valid channel");
        assert_eq!(ch.parent(), Some(dir));
    }
}
