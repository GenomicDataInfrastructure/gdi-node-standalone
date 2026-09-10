//! Operator-authored, node-local reingest-request marker store: a targeted retry of one
//! bucket dataset. One marker file per requested id under `<override_dir>/reingest/`,
//! with the id as the filename, the same idiom as [`crate::suppression`] and
//! [`crate::overlay_override`].
//!
//! `dataset reingest <id>` writes this marker for an id it cannot restore from
//! `inbox/.rejected/`, in practice a bucket-owned or not-yet-seen dataset pinned by the
//! S3 reconcile's same-ETag short-circuit. The running node processes every pending
//! marker on `SIGUSR1` and on the periodic override-reconcile: it clears the id's
//! recorded `last_seen_signature`, so the still-present source package no longer looks
//! unchanged, and wakes every S3 bucket monitor to reconcile now.
//!
//! A marker is declarative, not one-shot: processing it does not delete it. Each node
//! remembers the `requested_at` stamp it last acted on, per id, and acts only when the
//! marker carries a newer one. That is what lets several nodes share one override store:
//! deleting on processing would make the request a single-consumer queue, where whichever
//! node polled first consumes the request for every other.
//!
//! It also means the node never writes to the override store at all, like
//! [`crate::suppression`] and [`crate::overlay_override`], so the store can be mounted
//! read-only on the serving replicas where the operator CLI never runs.
//!
//! Markers accumulate, but boundedly: `dataset reingest <id>` rewrites `{id}.json` in
//! place, so the directory never exceeds one entry per dataset.
//!
//! A marker naming an id the node has no status entry for is a harmless no-op, since
//! there is no signature to clear. The stamp is still recorded, so it costs one pass
//! rather than one per pass forever.

use std::path::{Path, PathBuf};

use crate::id::is_valid_dataset_id;

/// `<override_dir>/reingest`.
#[must_use]
pub fn requests_subdir(override_dir: &Path) -> PathBuf {
    override_dir.join("reingest")
}

/// Write one reingest-request marker (creates the `reingest/` subdir if needed).
///
/// The `requested_at` timestamp in the body is what distinguishes a request a node has
/// already acted on from a fresh one (see [`list_requests`]). Writing the same id again
/// re-arms it for every reader, because the stamp moves.
///
/// # Errors
/// Propagates I/O errors from directory creation, or the durable write.
pub fn write_marker(dir: &Path, id: &str) -> std::io::Result<()> {
    crate::util::create_private_dir(dir)?;
    let body = format!(r#"{{"requested_at":"{}"}}"#, crate::util::now_rfc3339());
    let path = crate::override_store::store_file_path(dir, id)?;
    crate::util::write_durable_atomic_private(&path, body.as_bytes())
}

/// One pending reingest request: the dataset id, and the stamp its marker carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReingestRequest {
    /// The requested dataset id (the marker's filename, minus `.json`).
    pub id: String,
    /// The marker's `requested_at` value, or the empty string when it cannot be read.
    ///
    /// Empty rather than `Option`: a caller compares stamps for equality to decide
    /// "already acted on", and an unreadable marker must still converge on acted-on after
    /// one pass. Skipping it would re-trigger the request on every pass forever.
    pub requested_at: String,
}

/// Remove one reingest-request marker; `Ok(())` if it was already absent.
///
/// Not part of processing: the node does not delete a marker it has acted on (see the
/// module docs). This is for operator-side cancellation and cleanup, where a single caller
/// withdraws a request.
///
/// # Errors
/// Propagates I/O errors other than `NotFound`.
pub fn remove_marker(dir: &Path, id: &str) -> std::io::Result<()> {
    match std::fs::remove_file(crate::override_store::store_file_path(dir, id)?) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// List every pending reingest-request id. A missing directory is empty; only
/// `{valid-dataset-id}.json` entries are considered (junk is silently ignored — a
/// failure mode here is "one fewer retry queued", not a disclosure risk, so unlike
/// [`crate::suppression::load`] this need not fail closed on an unparseable/unexpected
/// entry).
#[must_use]
pub fn list_ids(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name();
            let name = name.to_str()?;
            let id = name.strip_suffix(".json")?;
            is_valid_dataset_id(id).then(|| id.to_owned())
        })
        .collect()
}

/// Every pending request, each paired with the `requested_at` stamp its marker carries.
///
/// The stamp is what makes processing idempotent per reader without deleting anything:
/// a caller records the stamp it acted on and skips the marker until that value changes.
/// See [`list_ids`] for the id-selection rules (junk is ignored, not fatal); an
/// unreadable or malformed body yields an empty stamp rather than dropping the request.
#[must_use]
pub fn list_requests(dir: &Path) -> Vec<ReingestRequest> {
    list_ids(dir)
        .into_iter()
        .map(|id| {
            let requested_at = read_requested_at(&dir.join(format!("{id}.json")));
            ReingestRequest { id, requested_at }
        })
        .collect()
}

/// The `requested_at` field of one marker file, or `""` when it cannot be read.
fn read_requested_at(path: &Path) -> String {
    let Ok(body) = std::fs::read_to_string(path) else {
        return String::new();
    };
    serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| {
            v.get("requested_at")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;

    const ID: &str = "GDI-EE-UTARTU-20260409143052837";
    const ID2: &str = "GDI-EE-UTARTU-20260409143052838";

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn list_ids_of_a_missing_dir_is_empty() {
        let d = tmp();
        assert!(list_ids(&d.path().join("reingest")).is_empty());
    }

    #[test]
    fn write_then_list_then_remove_roundtrip() {
        let d = tmp();
        let sub = requests_subdir(d.path());
        write_marker(&sub, ID).unwrap();
        assert_eq!(list_ids(&sub), vec![ID.to_owned()]);

        remove_marker(&sub, ID).unwrap();
        assert!(list_ids(&sub).is_empty());
        remove_marker(&sub, ID).unwrap(); // idempotent when already gone
    }

    #[test]
    fn list_ids_returns_every_pending_marker() {
        let d = tmp();
        let sub = requests_subdir(d.path());
        write_marker(&sub, ID).unwrap();
        write_marker(&sub, ID2).unwrap();
        let mut ids = list_ids(&sub);
        ids.sort_unstable();
        assert_eq!(ids, vec![ID.to_owned(), ID2.to_owned()]);
    }

    #[test]
    fn non_json_and_non_id_files_are_ignored() {
        let d = tmp();
        let sub = requests_subdir(d.path());
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("README"), b"x").unwrap(); // no .json
        std::fs::write(sub.join("not-an-id.json"), b"{}").unwrap(); // invalid id
        assert!(list_ids(&sub).is_empty());
    }

    #[test]
    fn write_marker_content_is_a_bare_informational_timestamp() {
        let d = tmp();
        let sub = requests_subdir(d.path());
        write_marker(&sub, ID).unwrap();
        let body = std::fs::read_to_string(sub.join(format!("{ID}.json"))).unwrap();
        assert!(body.contains("requested_at"), "{body}");
    }
}
