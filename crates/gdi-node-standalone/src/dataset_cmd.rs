//! Two `dataset` one-shots that act directly on the inbox, without going through an
//! operator-override store: `reingest` and `purge-rejected`.
//!
//! ## `dataset reingest <id>`
//!
//! Retry ingest for an id, whichever channel owns it. Two mechanisms are tried in order,
//! and neither needs the CLI to know which channel owns `id` up front:
//!
//! 1. **Inbox restore**: if `[service].inbox` is configured and `id` has a quarantined
//!    artifact under `inbox/.rejected/{id}`, move it back into the inbox under the name the
//!    scanner recognizes. Lock-free, synchronous, and immediately verifiable, since the
//!    artifact either moved or it did not.
//! 2. **Reingest-request marker**, the fallback and the only path when there is no
//!    quarantined artifact. That is most often a bucket-owned id pinned by the S3
//!    reconcile's same-ETag short-circuit. It writes a marker under
//!    `<override_dir>/reingest/{id}` and prints how to apply it now. The node clears the
//!    id's recorded signature and reconciles it on `SIGUSR1` or on its next periodic
//!    override-reconcile (see
//!    [`crate::state::AppState::process_reingest_requests`]). A marker for an id with
//!    nothing to retry, because it was never seen or is already erased, is a node-side
//!    no-op.
//!
//! ## `dataset purge-rejected [--older-than <dur>] [--dry-run]`
//!
//! Erase `inbox/.rejected/` quarantine entries on demand: a guard-railed operator lever for
//! an erasure request or disk pressure, independent of the automatic
//! `[service].rejected_retention_hours` GC ([`crate::ingest_runtime`]'s `gc_rejected_dir`).
//! It reuses that GC's entry and age semantics through
//! `ingest_runtime::read_rejected_entries`, a crate-private helper, so the two never judge
//! "what counts as an entry" differently. A local, synchronous filesystem operation on the
//! configured inbox's `.rejected/` dir: no override store, no signal, nothing for the
//! running node to apply later.

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use anyhow::{Context as _, Result, bail};

use gdi_node_standalone_core::config::ServiceConfig;
use gdi_node_standalone_core::id::is_valid_dataset_id;
use gdi_node_standalone_core::reingest_request::{requests_subdir, write_marker};
use gdi_node_standalone_core::s3_layout::TAR_C4GH_SUFFIX;

use crate::ingest_runtime::{RejectedEntry, read_rejected_entries, remove_rejected_entry};

/// Retry ingest for `id`: restore a quarantined inbox artifact if one exists, else
/// queue a node-side reingest request (the bucket path).
///
/// # Errors
///
/// Errors on a malformed id, on a quarantined artifact whose restore-name target is already
/// occupied by a fresh drop, which is never clobbered, or on a reingest-request marker that
/// could not be written.
pub fn reingest(config: &ServiceConfig, id: &str) -> Result<()> {
    if !is_valid_dataset_id(id) {
        bail!("invalid dataset id {id:?}");
    }
    if let Some(inbox) = &config.service.inbox {
        let quarantined = inbox.join(".rejected").join(id);
        if let Ok(meta) = std::fs::symlink_metadata(&quarantined) {
            return restore_from_quarantine(inbox, id, &quarantined, &meta);
        }
    }
    // No inbox configured, or nothing quarantined for this id: queue a node-side reingest
    // request. That is the bucket path, and it is harmless for an id with nothing to retry.
    request_reingest(config, id)
}

/// The inbox-restore mechanism: move `id`'s quarantined artifact back into the inbox so
/// the node re-ingests it on its next inbox scan.
///
/// A permanent-error ingest quarantines the source under `inbox/.rejected/{id}`, as either
/// a `.tar.c4gh` file or a staging directory. Once the external cause is corrected, this
/// moves it back under the name the inbox scan recognizes and the next scan re-enqueues it.
/// An absent or `error` id always re-ingests, because the same-signature skip applies only
/// to live datasets, so the status index needs no change: a successful re-ingest overwrites
/// the `error` entry and a failing one re-quarantines.
fn restore_from_quarantine(
    inbox: &std::path::Path,
    id: &str,
    quarantined: &std::path::Path,
    meta: &std::fs::Metadata,
) -> Result<()> {
    // Quarantine strips the name to a bare id, so the file-vs-dir kind reconstructs the
    // inbox name the scanner expects: a staging directory restores to `inbox/{id}`, a
    // `.tar.c4gh` file to `inbox/{id}.tar.c4gh`.
    let target = if meta.is_dir() {
        inbox.join(id)
    } else {
        inbox.join(format!("{id}{TAR_C4GH_SUFFIX}"))
    };
    if target.exists() {
        bail!(
            "refusing to reingest: {} already exists (a fresh drop is present); remove or \
             ingest it first",
            target.display()
        );
    }
    // Both paths are under the inbox, so this rename never crosses a device boundary.
    std::fs::rename(quarantined, &target)
        .with_context(|| format!("moving {} -> {}", quarantined.display(), target.display()))?;
    println!(
        "restored {} to {}; the node re-ingests {id} on its next inbox scan",
        quarantined.display(),
        target.display()
    );
    Ok(())
}

/// The bucket-retry mechanism: write a reingest-request marker under
/// `<override_dir>/reingest/{id}` and print how to apply it now.
///
/// This defeats the S3 reconcile's same-ETag short-circuit. The node clears `id`'s recorded
/// signature, so a still-present bucket package that errored on a since-fixed node-side
/// cause is no longer seen as unchanged and re-ingests on the next reconcile.
///
/// # Errors
///
/// Propagates an I/O error writing the marker file.
fn request_reingest(config: &ServiceConfig, id: &str) -> Result<()> {
    let dir = requests_subdir(&config.service.override_dir_resolved());
    write_marker(&dir, id).with_context(|| format!("writing reingest request for {id}"))?;
    println!(
        "queued a reingest request for {id}; the node clears its recorded signature and \
         re-ingests it once applied (harmless if {id} has nothing to retry)"
    );
    crate::override_advice::print_apply_now_hint();
    Ok(())
}

/// Which `.rejected/` entries [`purge_rejected`] selects: every entry when `older_than` is
/// `None`, otherwise only those whose age (`now - modified`) exceeds it. The comparison is
/// `age > threshold`, never `>=`, so an entry exactly `older_than` old is kept, matching the
/// automatic GC's boundary.
fn select_rejected(
    entries: Vec<RejectedEntry>,
    older_than: Option<Duration>,
) -> Vec<RejectedEntry> {
    let Some(threshold) = older_than else {
        return entries; // no filter: purge everything
    };
    let now = SystemTime::now();
    entries
        .into_iter()
        .filter(|e| now.duration_since(e.modified).unwrap_or(Duration::ZERO) > threshold)
        .collect()
}

/// `dataset purge-rejected [--older-than <dur>] [--dry-run]`: erase `inbox/.rejected/`
/// quarantine entries on demand (see the module doc). Without `--older-than` every entry is
/// purged; with it, only entries whose mtime is older than the given duration. `--dry-run`
/// lists what would be purged and returns before removing anything.
///
/// A missing `.rejected/` dir is a clean no-op rather than an error. Nothing outside
/// `.rejected/` is touched: entries come only from `read_rejected_entries`'s single-level
/// `read_dir` over that directory.
///
/// # Errors
///
/// Errors if `[service].inbox` is not configured, since without it there is no `.rejected/`
/// dir to act on.
pub fn purge_rejected(
    config: &ServiceConfig,
    older_than: Option<Duration>,
    dry_run: bool,
) -> Result<()> {
    let inbox = config.service.inbox.as_deref().context(
        "`dataset purge-rejected` requires [service].inbox to be configured (there is no \
         inbox/.rejected/ without one)",
    )?;
    let rejected = inbox.join(".rejected");
    let matching = select_rejected(read_rejected_entries(&rejected), older_than);

    if dry_run {
        if matching.is_empty() {
            println!(
                "dry-run: nothing to purge under {}; nothing written or removed",
                rejected.display()
            );
        } else {
            println!(
                "dry-run: would purge {} {} under {}; nothing written or removed:",
                matching.len(),
                plural(matching.len()),
                rejected.display()
            );
            for entry in &matching {
                println!("  {}", entry.path.display());
            }
        }
        return Ok(());
    }

    let (removed, failures) = remove_selected(&matching);
    // Audit the count unlinked, never the count enumerated: an operator satisfying a
    // deletion request must not be handed a record claiming deletions that did not happen.
    // Emitted for every real run, including a `removed = 0` no-op.
    crate::audit::purge_rejected(&config.audit, removed, older_than.map(|d| d.as_secs()));
    println!(
        "purged {removed} {} under {}",
        plural(removed),
        rejected.display()
    );
    if !failures.is_empty() {
        for (path, err) in &failures {
            eprintln!("error: could not purge {}: {err}", path.display());
        }
        // Fail loudly: a deletion command that reports success while the data is still on
        // disk is worse than one that fails. Most often these are entries owned by another
        // uid, such as the depositing user, which the node cannot remove.
        anyhow::bail!(
            "{} of {} quarantined {} could not be purged under {}; the data is still on \
             disk, commonly as an entry owned by another uid. Fix ownership or permissions \
             and re-run",
            failures.len(),
            matching.len(),
            plural(matching.len()),
            rejected.display()
        );
    }
    Ok(())
}

/// Unlink every selected entry, returning `(removed, failures)`.
///
/// `removed` counts only entries that were unlinked; `failures` carries the rest with the
/// error that stopped each. Split out of [`purge_rejected`] so the count is testable without
/// a foreign-uid fixture.
fn remove_selected(matching: &[RejectedEntry]) -> (usize, Vec<(PathBuf, std::io::Error)>) {
    let mut removed = 0usize;
    let mut failures = Vec::new();
    for entry in matching {
        match remove_rejected_entry(&entry.path, entry.is_dir) {
            Ok(()) => removed += 1,
            Err(e) => failures.push((entry.path.clone(), e)),
        }
    }
    (removed, failures)
}

/// `"entry"` singular vs `"entries"` plural for `n`, used only in `purge_rejected`'s
/// operator-facing output.
fn plural(n: usize) -> &'static str {
    if n == 1 { "entry" } else { "entries" }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;

    #[test]
    fn purge_counts_what_was_unlinked_not_what_was_enumerated() {
        // `purge-rejected` is the documented deletion lever for an erasure request, so the
        // reported and audited count must be the number actually unlinked. Reporting the
        // enumeration instead would write an affirmatively false deletion record.
        let tmp = tempfile::tempdir().unwrap();
        let present = tmp.path().join("GDI-EE-UTARTU-1.tar.c4gh");
        std::fs::write(&present, b"x").unwrap();
        let entries = vec![
            RejectedEntry {
                path: present.clone(),
                is_dir: false,
                modified: SystemTime::now(),
            },
            // Vanished between enumeration and unlink. It stands in for any failing
            // unlink, such as a foreign-uid staging dir the node cannot remove: enumerated,
            // but not removed.
            RejectedEntry {
                path: tmp.path().join("GDI-EE-UTARTU-2.tar.c4gh"),
                is_dir: false,
                modified: SystemTime::now(),
            },
        ];

        let (removed, failures) = remove_selected(&entries);

        assert_eq!(
            removed, 1,
            "only the entry actually unlinked may be counted"
        );
        assert_eq!(failures.len(), 1, "the failed unlink must be reported");
        assert!(!present.exists(), "the removable entry is really gone");
    }

    /// A config with `[service].inbox` set and `data_dir` a writable path under `root`. A
    /// `reingest` with nothing quarantined falls through to writing a reingest-request
    /// marker under `override_dir_resolved()`, which defaults to `<data_dir>/overrides/`.
    fn config_with_inbox(root: &std::path::Path) -> ServiceConfig {
        let toml = format!(
            r#"
[service]
base_url = "https://n.example.org/"
data_dir = "{}"
inbox = "{}"

[catalogs]
gdi-aggregated = "GoE"

[beacon]
id = "org.n.beacon"
name = "N"
environment = "test"

[beacon.organization]
id = "ee.ut.gdi"
name = "University of Tartu"
"#,
            root.join("data").display(),
            root.join("inbox").display()
        );
        ServiceConfig::from_toml_str(&toml).unwrap()
    }

    /// A config with no `[service].inbox`, so every `reingest` on it takes the marker path.
    fn config_without_inbox(root: &std::path::Path) -> ServiceConfig {
        let toml = format!(
            r#"
[service]
base_url = "https://n.example.org/"
data_dir = "{}"

[catalogs]
gdi-aggregated = "GoE"

[beacon]
id = "org.n.beacon"
name = "N"
environment = "test"

[beacon.organization]
id = "ee.ut.gdi"
name = "University of Tartu"
"#,
            root.join("data").display()
        );
        ServiceConfig::from_toml_str(&toml).unwrap()
    }

    const ID: &str = "GDI-EE-UTARTU-20260409143052837";

    #[test]
    fn reingest_rejects_a_malformed_id_regardless_of_channel() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_with_inbox(dir.path());
        assert!(reingest(&cfg, "../etc/passwd").is_err());

        let no_inbox = config_without_inbox(dir.path());
        assert!(reingest(&no_inbox, "../etc/passwd").is_err());
    }

    /// With no `[service].inbox` configured, every `reingest` takes the marker path and
    /// queues a request under `<override_dir>/reingest/{id}` rather than erroring, since an
    /// id with nothing to retry is a node-side no-op.
    #[test]
    fn reingest_with_no_inbox_configured_queues_a_reingest_marker() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_without_inbox(dir.path());

        reingest(&cfg, ID).unwrap();

        let marker =
            requests_subdir(&cfg.service.override_dir_resolved()).join(format!("{ID}.json"));
        assert!(marker.is_file(), "reingest must queue a marker for {ID}");
    }

    #[test]
    fn reingest_restores_a_quarantined_c4gh_file_to_the_inbox() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = dir.path().join("inbox");
        let rejected = inbox.join(".rejected");
        std::fs::create_dir_all(&rejected).unwrap();
        // A quarantined c4gh package: a file at `.rejected/{id}`, extension stripped.
        std::fs::write(rejected.join(ID), b"encrypted-bytes").unwrap();
        let cfg = config_with_inbox(dir.path());

        reingest(&cfg, ID).unwrap();
        // Restored under the name the scanner recognizes, and removed from quarantine.
        assert!(inbox.join(format!("{ID}.tar.c4gh")).is_file());
        assert!(!rejected.join(ID).exists());
        // The inbox path is synchronous and complete on its own, so no marker is written.
        assert!(
            !requests_subdir(&cfg.service.override_dir_resolved())
                .join(format!("{ID}.json"))
                .exists(),
            "an inbox restore must not also queue a reingest marker"
        );
    }

    #[test]
    fn reingest_restores_a_quarantined_staging_dir_to_the_inbox() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = dir.path().join("inbox");
        let rejected = inbox.join(".rejected");
        std::fs::create_dir_all(rejected.join(ID)).unwrap();
        // A staging dir carries a manifest.json.
        std::fs::write(rejected.join(ID).join("manifest.json"), b"{}").unwrap();
        let cfg = config_with_inbox(dir.path());

        reingest(&cfg, ID).unwrap();
        assert!(
            inbox.join(ID).is_dir(),
            "staging dir restores to inbox/{{id}}"
        );
        assert!(inbox.join(ID).join("manifest.json").is_file());
        assert!(!rejected.join(ID).exists());
        // The inbox path is synchronous and complete on its own, so no marker is written.
        assert!(
            !requests_subdir(&cfg.service.override_dir_resolved())
                .join(format!("{ID}.json"))
                .exists(),
            "an inbox restore must not also queue a reingest marker"
        );
    }

    /// With an inbox configured but nothing quarantined for `id`, `reingest` falls through
    /// to the marker path rather than erroring. That is the case a bucket-owned id hits, and
    /// the marker is harmless when there is nothing to retry.
    #[test]
    fn reingest_with_nothing_quarantined_falls_through_to_a_reingest_marker() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = dir.path().join("inbox");
        std::fs::create_dir_all(&inbox).unwrap();
        let cfg = config_with_inbox(dir.path());

        reingest(&cfg, ID).unwrap();

        let marker =
            requests_subdir(&cfg.service.override_dir_resolved()).join(format!("{ID}.json"));
        assert!(
            marker.is_file(),
            "nothing quarantined must fall through to queuing a reingest marker"
        );
    }

    #[test]
    fn reingest_refuses_to_clobber_a_fresh_drop_under_the_restore_name() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = dir.path().join("inbox");
        std::fs::create_dir_all(&inbox).unwrap();
        let cfg = config_with_inbox(dir.path());

        // A fresh drop already present under the restore name, plus a quarantined artifact:
        // refuse to clobber the fresh drop.
        std::fs::create_dir_all(inbox.join(".rejected")).unwrap();
        std::fs::write(inbox.join(".rejected").join(ID), b"x").unwrap();
        std::fs::write(inbox.join(format!("{ID}.tar.c4gh")), b"fresh").unwrap();
        let err = reingest(&cfg, ID).unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err}");
        // The fresh drop and the quarantined artifact are both untouched.
        assert_eq!(
            std::fs::read(inbox.join(format!("{ID}.tar.c4gh"))).unwrap(),
            b"fresh"
        );
        assert!(inbox.join(".rejected").join(ID).exists());
        // The clobber refusal is a hard error, with no fallback to the marker path.
        assert!(
            !requests_subdir(&cfg.service.override_dir_resolved())
                .join(format!("{ID}.json"))
                .exists()
        );
    }

    /// Capture the `audit`-target JSON emitted while running `f`, mirroring the helper in
    /// `suppress_cmd`, which is private to its module.
    fn capture_audit(f: impl FnOnce()) -> String {
        test_util::capture_json_logs(f).1
    }

    /// Write a file entry directly under `rejected`, creating the dir if needed, with mtime
    /// `age` in the past. Uses `File::set_modified`, as the `gc_rejected_dir` tests do.
    /// `age == Duration::ZERO` leaves the just-created mtime.
    fn write_rejected_entry(rejected: &std::path::Path, id: &str, age: Duration) {
        std::fs::create_dir_all(rejected).unwrap();
        let path = rejected.join(id);
        let f = std::fs::File::create(&path).unwrap();
        if !age.is_zero() {
            f.set_modified(SystemTime::now() - age).unwrap();
        }
    }

    #[test]
    fn purge_rejected_without_inbox_configured_errors() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_without_inbox(dir.path());
        let err = purge_rejected(&cfg, None, false).unwrap_err();
        assert!(err.to_string().contains("inbox"), "{err}");
    }

    #[test]
    fn purge_rejected_missing_rejected_dir_is_a_clean_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = dir.path().join("inbox");
        std::fs::create_dir_all(&inbox).unwrap(); // inbox exists; .rejected/ never created
        let cfg = config_with_inbox(dir.path());

        purge_rejected(&cfg, None, false).unwrap();
        purge_rejected(&cfg, None, true).unwrap();
        assert!(!inbox.join(".rejected").exists());
    }

    #[test]
    fn purge_rejected_dry_run_lists_matches_and_removes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = dir.path().join("inbox");
        let rejected = inbox.join(".rejected");
        write_rejected_entry(&rejected, ID, Duration::ZERO);
        let cfg = config_with_inbox(dir.path());

        purge_rejected(&cfg, None, true).unwrap();

        assert!(rejected.join(ID).exists(), "--dry-run must remove nothing");
    }

    #[test]
    fn purge_rejected_without_older_than_removes_everything() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = dir.path().join("inbox");
        let rejected = inbox.join(".rejected");
        write_rejected_entry(&rejected, ID, Duration::ZERO);
        write_rejected_entry(&rejected, "GDI-EE-UTARTU-20260409143052838", Duration::ZERO);
        let cfg = config_with_inbox(dir.path());

        purge_rejected(&cfg, None, false).unwrap();

        assert_eq!(
            std::fs::read_dir(&rejected).unwrap().count(),
            0,
            "no --older-than: every entry must be purged"
        );
    }

    const OLD: &str = ID;
    const NEW: &str = "GDI-EE-UTARTU-20260409143052838";

    #[test]
    fn purge_rejected_with_older_than_keeps_newer_entries() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = dir.path().join("inbox");
        let rejected = inbox.join(".rejected");
        // "old" is decades old and "new" is effectively age zero, so a 1-hour threshold
        // separates them regardless of wall-clock jitter.
        write_rejected_entry(&rejected, OLD, Duration::from_hours(24 * 365 * 55));
        write_rejected_entry(&rejected, NEW, Duration::ZERO);
        let cfg = config_with_inbox(dir.path());

        purge_rejected(&cfg, Some(Duration::from_hours(1)), false).unwrap();

        assert!(
            !rejected.join(OLD).exists(),
            "older-than-threshold must be purged"
        );
        assert!(
            rejected.join(NEW).exists(),
            "newer-than-threshold must be kept"
        );
    }

    #[test]
    fn purge_rejected_never_touches_anything_outside_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = dir.path().join("inbox");
        let rejected = inbox.join(".rejected");
        write_rejected_entry(&rejected, ID, Duration::ZERO);
        // A sibling artifact in the inbox root and a `.state.json` sidecar. Neither is
        // under `.rejected/`, so a purge must leave both alone.
        std::fs::write(inbox.join(format!("{ID}.tar.c4gh")), b"fresh drop").unwrap();
        let cfg = config_with_inbox(dir.path());

        purge_rejected(&cfg, None, false).unwrap();

        assert!(!rejected.join(ID).exists(), "the .rejected entry is purged");
        assert!(
            inbox.join(format!("{ID}.tar.c4gh")).exists(),
            "a sibling artifact outside .rejected/ must survive a purge"
        );
    }

    #[test]
    fn purge_rejected_emits_a_purge_rejected_audit_line_with_count() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = dir.path().join("inbox");
        let rejected = inbox.join(".rejected");
        write_rejected_entry(&rejected, ID, Duration::ZERO);
        let cfg = config_with_inbox(dir.path());

        let out = capture_audit(|| {
            purge_rejected(&cfg, None, false).unwrap();
        });
        assert!(out.contains("\"event\":\"purge_rejected\""), "{out}");
        assert!(
            out.contains("\"actor\":\"operator\""),
            "the file-writer is the operator actor: {out}"
        );
        assert!(out.contains("\"count\":1"), "{out}");
    }

    #[test]
    fn purge_rejected_real_run_with_nothing_matching_still_emits_a_count_zero_line() {
        // An operator who authorized a real purge that matched nothing still gets a trail.
        let dir = tempfile::tempdir().unwrap();
        let inbox = dir.path().join("inbox");
        std::fs::create_dir_all(&inbox).unwrap();
        let cfg = config_with_inbox(dir.path());

        let out = capture_audit(|| {
            purge_rejected(&cfg, None, false).unwrap();
        });
        assert!(out.contains("\"event\":\"purge_rejected\""), "{out}");
        assert!(out.contains("\"count\":0"), "{out}");
    }

    #[test]
    fn purge_rejected_dry_run_emits_no_audit_line() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = dir.path().join("inbox");
        let rejected = inbox.join(".rejected");
        write_rejected_entry(&rejected, ID, Duration::ZERO);
        let cfg = config_with_inbox(dir.path());

        let out = capture_audit(|| {
            purge_rejected(&cfg, None, true).unwrap();
        });
        assert!(out.is_empty(), "dry-run must emit no audit line: {out}");
    }

    #[test]
    fn purge_rejected_matches_a_staging_dir_entry_too() {
        // A quarantined staging dir must be purged as well as a `.tar.c4gh` file:
        // `gc_rejected_dir` handles dirs and files identically, and so must this.
        let dir = tempfile::tempdir().unwrap();
        let inbox = dir.path().join("inbox");
        let rejected = inbox.join(".rejected");
        std::fs::create_dir_all(rejected.join(ID)).unwrap();
        std::fs::write(rejected.join(ID).join("manifest.json"), b"{}").unwrap();
        let cfg = config_with_inbox(dir.path());

        purge_rejected(&cfg, None, false).unwrap();

        assert!(!rejected.join(ID).exists());
    }
}
