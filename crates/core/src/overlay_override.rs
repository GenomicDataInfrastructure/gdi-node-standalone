//! Operator-authored, node-local metadata-overlay override store, sibling of
//! [`crate::suppression`]. One file per override under `<override_dir>/overlays/`, with
//! the id as the filename. Each file is a bare [`MetadataOverlay`] field patch, the same
//! shape as the source-authored `{id}.metadata.json` sidecar the overlay engine
//! ([`crate::overlay_store`]) already reads from the inbox or bucket. This module is a
//! second, node-local input feed into that engine and never re-implements
//! merge, validate or apply.
//!
//! Precedence is operator over source, as in [`crate::suppression`]. While a node-local
//! override exists for an id, the node's reconcile skips the source-authored sidecar for
//! that id: it never applies it, and never reverts the node-local overlay because the
//! sidecar changed. Removing the override (`dataset correct <id> --reset`) lets the source
//! resume governing on the next reconcile.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::id::is_valid_dataset_id;
use crate::model::MetadataOverlay;

/// The set of active node-local metadata-overlay overrides, loaded from disk.
#[derive(Debug, Default, Clone)]
pub struct LocalOverlaySet {
    overlays: BTreeMap<String, MetadataOverlay>,
    /// Ids whose override file is present on disk but could not be read or parsed.
    ///
    /// They carry no patch, but they do carry the operator-over-source precedence claim, so
    /// a corrupt file cannot hand the id back to the source. Mirrors
    /// [`crate::suppression::SuppressionSet`]'s `degraded` counter.
    degraded: BTreeSet<String>,
    /// The overlay directory could not be read, as distinct from being absent. The set is
    /// then not authoritative and must not be adopted. See [`load`].
    unreadable: bool,
}

impl LocalOverlaySet {
    /// The node-local override patch for `id`, if any.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&MetadataOverlay> {
        self.overlays.get(id)
    }

    /// Whether a node-local override exists for `id`. Every source-driven overlay
    /// reconcile site consults this before touching the id.
    ///
    /// True for a degraded (unparseable) override too: the file's presence is the
    /// precedence claim, and only that keeps the source from reverting the id to its
    /// source metadata. See [`load`].
    #[must_use]
    pub fn contains(&self, id: &str) -> bool {
        self.overlays.contains_key(id) || self.degraded.contains(id)
    }

    /// Every overridden id in the store that carries an applicable patch.
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.overlays.keys().map(String::as_str)
    }

    /// Ids whose override file is present but unreadable/unparseable.
    pub fn degraded_ids(&self) -> impl Iterator<Item = &str> {
        self.degraded.iter().map(String::as_str)
    }

    /// How many override files are present but unreadable/unparseable.
    #[must_use]
    pub fn degraded(&self) -> usize {
        self.degraded.len()
    }

    /// Whether the overlay directory could not be read, as distinct from being absent.
    ///
    /// `true` means this set is not authoritative: it is empty because the read failed. A
    /// caller that adopts it drops every id's operator-over-source precedence claim at
    /// once, and the next reconcile re-publishes the source metadata each override was
    /// redacting.
    #[must_use]
    pub fn unreadable(&self) -> bool {
        self.unreadable
    }
}

/// `<override_dir>/overlays`.
#[must_use]
pub fn overlays_subdir(override_dir: &Path) -> PathBuf {
    override_dir.join("overlays")
}

/// The dataset id an `overlays/` entry name carries, if [`load`] admits it
/// (`{valid-id}.json`). `None` for anything the loader skips.
///
/// The one definition of what this store admits. [`load`] reads through it, and so does
/// [`crate::override_store::is_populated`], so the used marker counts what the loader would
/// load (see [`crate::suppression::classify_entry`]).
#[must_use]
pub fn loader_entry_id(file_name: &str) -> Option<&str> {
    let id = file_name.strip_suffix(".json")?;
    is_valid_dataset_id(id).then_some(id)
}

/// Load the node-local overlay set from `<override_dir>/overlays/*.json`.
///
/// Fails closed, like [`crate::suppression::load`]: an unparseable override file keeps its
/// id in the set as degraded rather than dropping it.
///
/// Dropping the id would release the operator-over-source precedence the reconcile path
/// consults, so the node would revert to the source metadata and re-publish, on every
/// public surface, the identifiable data a redaction override withheld. A truncated write
/// is enough to trigger that. Keeping the id with no patch holds the precedence claim, and
/// callers surface the degraded ids via [`LocalOverlaySet::degraded_ids`] so the state
/// oracle reports `overlay_error` instead of reporting healthy.
///
/// A missing directory is an empty set, and only `{valid-dataset-id}.json` entries are
/// considered.
///
/// An unreadable directory is different. It also yields an empty set, but with
/// [`LocalOverlaySet::unreadable`] set: that set is not authoritative and must not be
/// adopted, because adopting it drops every id's precedence claim at once and the next
/// reconcile re-publishes the metadata each override was redacting. Absent and unreadable
/// are indistinguishable by emptiness alone, which is why the flag exists.
#[must_use]
pub fn load(dir: &Path) -> LocalOverlaySet {
    let mut set = LocalOverlaySet::default();
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        // Absent: the documented empty-set case (see this function's doc).
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return set,
        // Unreadable: a corrupt file is kept as `degraded` so it retains the
        // operator-over-source precedence claim, and an unreadable directory is that same
        // failure for every id at once. Report it rather than returning an empty set the
        // caller would adopt.
        Err(e) => {
            tracing::error!(
                dir = %dir.display(),
                error = %e,
                "node-local overlay directory is unreadable; the caller keeps its \
                 last-good set instead of reverting every override"
            );
            set.unreadable = true;
            return set;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                // Surface rather than silently `.flatten()`-drop; a metadata correction
                // has no fail-closed state, so a lost entry just leaves last-good served.
                tracing::warn!(error = %e, "node-local overlay dir entry unreadable; skipped");
                continue;
            }
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(id) = loader_entry_id(name) else {
            continue;
        };
        if let Some(patch) = std::fs::read(entry.path())
            .ok()
            .and_then(|b| serde_json::from_slice::<MetadataOverlay>(&b).ok())
        {
            set.overlays.insert(id.to_owned(), patch);
        } else {
            // Fail closed: the filename carries the id, so keep the precedence claim even
            // though the body did not parse. Dropping it would hand the id back to the
            // source and revert a redaction.
            tracing::warn!(
                dataset = id,
                "node-local metadata override is present but unparseable; holding the \
                 override (last-good metadata stays served, source revert suppressed)"
            );
            set.degraded.insert(id.to_owned());
        }
    }
    set
}

/// Write one node-local overlay override file atomically (creates the overlays dir
/// if needed).
///
/// # Errors
/// Propagates I/O errors from directory creation, serialization, or the durable write.
pub fn write_file(dir: &Path, id: &str, patch: &MetadataOverlay) -> std::io::Result<()> {
    // Creates the sibling loader directory too, so the first override of any kind leaves
    // the store exportable. See `override_store::create_store_dir`.
    crate::override_store::create_store_dir(dir)?;
    let json = serde_json::to_vec_pretty(patch).map_err(std::io::Error::other)?;
    let target = crate::override_store::store_file_path(dir, id)?;
    crate::util::write_durable_atomic_private(&target, &json)
}

/// Remove one node-local overlay override file: `Ok(true)` when a file was removed,
/// `Ok(false)` when it was already absent. The caller keys the store's used marker on that
/// (see [`crate::suppression::remove_file`]).
///
/// # Errors
/// Propagates I/O errors other than `NotFound`.
pub fn remove_file(dir: &Path, id: &str) -> std::io::Result<bool> {
    match std::fs::remove_file(crate::override_store::store_file_path(dir, id)?) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;
    use std::fs;

    const ID: &str = "GDI-EE-UTARTU-20260409143052837";

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn title_patch(title: &str) -> MetadataOverlay {
        serde_json::from_str(&format!(r#"{{"title":"{title}"}}"#)).unwrap()
    }

    #[test]
    fn load_empty_or_missing_dir_is_empty() {
        let d = tmp();
        let set = load(&d.path().join("overlays")); // missing subdir
        assert!(set.get(ID).is_none());
        assert!(!set.contains(ID));
        assert_eq!(set.ids().count(), 0);
    }

    #[test]
    fn an_unparseable_override_keeps_precedence_so_the_source_cannot_revert_it() {
        // The disclosure case: an operator redacts identifiable metadata with
        // `dataset correct <id> --field description.en=REDACTED`, and a partial write or a
        // truncated restore leaves that override file unparseable. Dropping the id would
        // release the operator-over-source precedence, the reconcile would see no local
        // override, and the node would serve the source metadata with the redacted data
        // back on every public surface. The id stays present, holding precedence, while
        // offering no patch to apply.
        let d = tmp();
        let sub = overlays_subdir(d.path());
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join(format!("{ID}.json")), b"{").unwrap();

        let set = load(&sub);

        assert!(
            set.contains(ID),
            "an unparseable override must still hold precedence, or the source reverts it"
        );
        assert!(
            set.get(ID).is_none(),
            "there is no valid patch to apply: only the precedence claim survives"
        );
        assert_eq!(set.degraded_ids().collect::<Vec<_>>(), vec![ID]);
        assert_eq!(set.degraded(), 1);
    }

    #[test]
    fn write_then_load_then_remove_roundtrip() {
        let d = tmp();
        let sub = overlays_subdir(d.path());
        let patch = title_patch("Corrected title");
        write_file(&sub, ID, &patch).unwrap();

        let set = load(&sub);
        assert!(set.contains(ID));
        assert_eq!(set.get(ID), Some(&patch));
        assert_eq!(set.ids().collect::<Vec<_>>(), vec![ID]);

        remove_file(&sub, ID).unwrap();
        assert!(!load(&sub).contains(ID));
        remove_file(&sub, ID).unwrap(); // idempotent when already gone
    }

    #[test]
    fn corrupt_body_fails_closed_and_counts_degraded() {
        // Skipping a corrupt override does not leave the dataset at its last-good served
        // metadata: it releases the operator-over-source precedence, and the reconcile then
        // reverts the id to its source metadata, re-serving redacted data. The contract is
        // fail-closed, matching the sibling suppression store.
        let d = tmp();
        let sub = overlays_subdir(d.path());
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join(format!("{ID}.json")), b"{ this is not json").unwrap();

        let set = load(&sub);
        assert!(
            set.contains(ID),
            "a corrupt override must hold precedence so the source cannot revert it"
        );
        assert!(set.get(ID).is_none(), "but it offers no patch to apply");
        assert_eq!(set.degraded(), 1);
    }

    #[test]
    fn a_protected_field_fails_to_parse_and_fails_closed() {
        // `MetadataOverlay`'s `deny_unknown_fields` rejects datasetId, catalog and
        // numberOfRecords at parse time, so a hand-edited override file containing one is
        // another unparseable-body case and takes the same fail-closed path.
        let d = tmp();
        let sub = overlays_subdir(d.path());
        fs::create_dir_all(&sub).unwrap();
        fs::write(
            sub.join(format!("{ID}.json")),
            br#"{"datasetId":"OTHER-ID"}"#,
        )
        .unwrap();

        let set = load(&sub);
        assert!(set.contains(ID));
        assert!(set.get(ID).is_none());
        assert_eq!(set.degraded(), 1);
    }

    #[test]
    fn non_json_and_non_id_files_are_ignored() {
        let d = tmp();
        let sub = overlays_subdir(d.path());
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("README"), b"x").unwrap(); // no .json
        fs::write(sub.join("not-an-id.json"), b"{}").unwrap(); // invalid dataset id
        let set = load(&sub);
        assert!(set.get("not-an-id").is_none());
        assert_eq!(set.ids().count(), 0);
    }

    const ID2: &str = "GDI-EE-UTARTU-20260409143052838";

    #[test]
    fn multiple_overrides_are_all_loaded() {
        let d = tmp();
        let sub = overlays_subdir(d.path());
        write_file(&sub, ID, &title_patch("A")).unwrap();
        write_file(&sub, ID2, &title_patch("B")).unwrap();

        let set = load(&sub);
        let mut ids: Vec<&str> = set.ids().collect();
        ids.sort_unstable();
        assert_eq!(ids, [ID, ID2]);
    }
}
