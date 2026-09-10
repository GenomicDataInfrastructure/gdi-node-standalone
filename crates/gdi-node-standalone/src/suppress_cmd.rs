//! The `dataset hide|take-down|show` one-shot commands: operator-authored withhold intent
//! verbs. Each writes or removes one suppression override file under
//! `<override_dir>/suppressions/{id}.json`, which is the durable source of truth
//! [`gdi_node_standalone_core::suppression`] reads at boot, on `SIGUSR1` and on every
//! reconcile pass. Each then prints how to make the running node apply it immediately; the
//! CLI never signals the node itself.
//!
//! `hide` withholds a dataset from disclosure and leaves the underlying data untouched, so
//! `show` reverses it. `take-down` withholds it and marks it for eviction, which is
//! irreversible from the node's perspective, since the node erases `data_dir/{id}` on its
//! next reconcile. `show` lifts an operator-authored withhold if there is one; a dataset the
//! source marked hidden stays hidden (see
//! `core::suppression::SuppressionSet::effective`).
//!
//! Each verb splits into a `*_write_only` function (id validation and the file effect,
//! unit-tested on its own) and a public wrapper that also prints the apply-now hint and an
//! operator confirmation, mirroring `dataset_cmd`'s shape.

use anyhow::{Context as _, Result, bail};

use gdi_node_standalone_core::config::ServiceConfig;
use gdi_node_standalone_core::id::is_valid_dataset_id;
use gdi_node_standalone_core::suppression::{
    self, SuppressMode, Suppression, remove_file, suppressions_subdir, write_file,
};
use gdi_node_standalone_core::util::now_rfc3339;

/// Reject a malformed dataset id up front. All four verbs source the check here, so the
/// error text cannot drift between them.
fn require_valid_id(id: &str) -> Result<()> {
    if is_valid_dataset_id(id) {
        Ok(())
    } else {
        bail!("invalid dataset id {id:?}")
    }
}

/// `dataset hide <id> --reason "…"`: withhold `id` from disclosure. The underlying data is
/// untouched, so [`show`] reverses it.
///
/// # Errors
///
/// Errors if `id` is malformed or the suppression file cannot be written.
pub fn hide(config: &ServiceConfig, id: &str, reason: &str) -> Result<()> {
    crate::override_advice::with_first_override_advice(config, || {
        hide_write_only(config, id, reason)?;
        // The actor is the file writer, this CLI process. Emitted right after the write
        // succeeds, whether or not the running node is up to apply it.
        crate::audit::dataset_suppressed(&config.audit, id, SuppressMode::Hide);
        println!("hid {id} (reason: {reason}); the node withholds it once applied");
        crate::override_advice::print_apply_now_hint();
        crate::override_advice::note_if_this_node_has_no_such_dataset(config, id);
        Ok(())
    })
}

/// The file effect of [`hide`], with no hint or confirmation output.
fn hide_write_only(config: &ServiceConfig, id: &str, reason: &str) -> Result<()> {
    require_valid_id(id)?;
    let dir = suppressions_subdir(&config.service.override_dir_resolved());
    write_file(
        &dir,
        id,
        &Suppression {
            mode: SuppressMode::Hide,
            reason: reason.to_owned(),
            at: now_rfc3339(),
        },
    )
    .with_context(|| format!("writing hide override for {id}"))?;
    // The store now holds at least one override: re-derive the data-volume marker.
    crate::override_marker::sync(config);
    Ok(())
}

/// `dataset take-down <id> --reason "…" [--dry-run]`: withhold `id` and mark it for
/// eviction. This is irreversible from the node's perspective: it erases `data_dir/{id}` and
/// refuses to re-ingest it on its next reconcile. `--dry-run` prints the plan and returns
/// before writing anything.
///
/// # Errors
///
/// Errors if `id` is malformed or the suppression file cannot be written.
pub fn take_down(config: &ServiceConfig, id: &str, reason: &str, dry_run: bool) -> Result<()> {
    require_valid_id(id)?;
    if dry_run {
        println!(
            "dry-run: would take down {id} (reason: {reason}); the node would evict its local \
             copy and refuse to re-ingest it; nothing written"
        );
        return Ok(());
    }
    crate::override_advice::with_first_override_advice(config, || {
        take_down_write_only(config, id, reason)?;
        crate::audit::dataset_suppressed(&config.audit, id, SuppressMode::Remove);
        println!("took down {id} (reason: {reason}); the node erases its local copy once applied");
        crate::override_advice::print_apply_now_hint();
        crate::override_advice::note_if_this_node_has_no_such_dataset(config, id);
        Ok(())
    })
}

/// The file effect of [`take_down`]. It always writes; the `--dry-run` short-circuit lives
/// in the public wrapper, before this is called.
fn take_down_write_only(config: &ServiceConfig, id: &str, reason: &str) -> Result<()> {
    require_valid_id(id)?;
    let dir = suppressions_subdir(&config.service.override_dir_resolved());
    write_file(
        &dir,
        id,
        &Suppression {
            mode: SuppressMode::Remove,
            reason: reason.to_owned(),
            at: now_rfc3339(),
        },
    )
    .with_context(|| format!("writing take-down override for {id}"))?;
    crate::override_marker::sync(config);
    Ok(())
}

/// `dataset unhide <id> --reason <text>` (alias `dataset show`): lift an operator-authored
/// withhold on `id`, if any. It removes only the operator's own override, so a source-hidden
/// dataset stays hidden.
///
/// `reason` is mandatory and goes to a durable [`crate::lift_record`] under
/// `<override_dir>/lifted/` rather than to the audit line, because operator reasons stay out
/// of the log stream: they are free text that can name data subjects. The override file this
/// lift deletes takes the withhold's own reason with it. The record is written only when an
/// override was lifted; a no-op lift re-exposes nothing and leaves only its audit line.
///
/// # Errors
///
/// Errors if `id` is malformed or the suppression file cannot be removed.
pub fn show(config: &ServiceConfig, id: &str, reason: &str) -> Result<()> {
    require_valid_id(id)?;
    // Capture what is being lifted before the file goes: the record names the lifted mode
    // and authoring time, which are unrecoverable after the removal. Fail-closed load, as
    // everywhere the answer gates an action on the store's contents.
    let dir = suppressions_subdir(&config.service.override_dir_resolved());
    let lifted = suppression::load_or_report(&dir)
        .context("reading the override store to record what this lift removes")?
        .get(id)
        .cloned();
    show_write_only(config, id)?;
    if let Some(lifted) = &lifted {
        crate::lift_record::record_dataset_lift(config, id, lifted, reason);
    }
    // Emitted on every `show`, including a no-op on an id with no override.
    crate::audit::dataset_unsuppressed(&config.audit, id);
    println!(
        "lifted the operator withhold on {id} (if any); the node resumes serving it once applied"
    );
    crate::override_advice::print_apply_now_hint();
    Ok(())
}

/// The file effect of [`show`], with no hint or confirmation output.
fn show_write_only(config: &ServiceConfig, id: &str) -> Result<()> {
    require_valid_id(id)?;
    let dir = suppressions_subdir(&config.service.override_dir_resolved());
    let removed =
        remove_file(&dir, id).with_context(|| format!("removing suppression override for {id}"))?;
    // The marker clears only if this lift emptied the store. A no-op lift removed nothing
    // and is no evidence the store is legitimately empty; on a structure-only restored store
    // it would otherwise disarm the boot refusal (see `override_marker`).
    crate::override_marker::sync_after_removal(config, removed);
    Ok(())
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;
    use gdi_node_standalone_core::suppression::load;

    const ID: &str = "GDI-EE-UTARTU-20260409143052837";

    /// Capture the `audit`-target JSON emitted while running `f`, mirroring the helper in
    /// `audit.rs`, which is private to its module.
    fn capture_with(f: impl FnOnce()) -> String {
        test_util::capture_json_logs(f).1
    }

    fn config_with_override_dir(dir: &std::path::Path) -> ServiceConfig {
        config_with_dirs(dir, std::path::Path::new("/var/lib/gdi/datasets"))
    }

    /// As [`config_with_override_dir`], with a real `data_dir`, where the marker lives.
    fn config_with_dirs(
        override_dir: &std::path::Path,
        data_dir: &std::path::Path,
    ) -> ServiceConfig {
        let toml = format!(
            r#"
[service]
base_url = "https://n.example.org/"
data_dir = "{}"
override_dir = "{}"

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
            data_dir.display(),
            override_dir.display(),
        );
        ServiceConfig::from_toml_str(&toml).unwrap()
    }

    /// The marker on the data volume is the one witness that a structure-only restored
    /// store once held withholds. A lift that removed nothing is no evidence the node
    /// emptied its own store, so it leaves the marker standing; only a lift that removed the
    /// last override clears it.
    #[test]
    fn a_no_op_unhide_leaves_the_used_marker_and_a_real_last_lift_clears_it() {
        const OTHER: &str = "GDI-EE-UTARTU-20260409143052999";
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        let cfg = config_with_dirs(&tmp.path().join("overrides"), &data_dir);
        let marker = crate::override_marker::marker_path(&cfg);

        hide_write_only(&cfg, ID, "embargo").unwrap();
        assert!(marker.exists(), "a hide sets the marker");

        // The files are lost while the tree survives, a structure-only restore. The marker,
        // on the data volume, survives with it.
        std::fs::remove_file(
            suppressions_subdir(&cfg.service.override_dir_resolved()).join(format!("{ID}.json")),
        )
        .unwrap();
        show_write_only(&cfg, OTHER).unwrap();
        assert!(marker.exists(), "a no-op lift must not clear the marker");

        hide_write_only(&cfg, ID, "again").unwrap();
        show_write_only(&cfg, ID).unwrap();
        assert!(
            !marker.exists(),
            "lifting the last override clears the marker"
        );
    }

    #[test]
    fn hide_writes_a_hide_file_take_down_writes_remove_show_removes_it() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_with_override_dir(dir.path());

        hide_write_only(&cfg, ID, "embargo").unwrap();
        let set = load(&suppressions_subdir(&cfg.service.override_dir_resolved()));
        let s = set.get(ID).unwrap();
        assert_eq!(s.mode, SuppressMode::Hide);
        assert_eq!(s.reason, "embargo");
        assert!(!s.at.is_empty());

        take_down_write_only(&cfg, ID, "consent withdrawn").unwrap();
        let set = load(&suppressions_subdir(&cfg.service.override_dir_resolved()));
        let s = set.get(ID).unwrap();
        assert_eq!(s.mode, SuppressMode::Remove);
        assert_eq!(s.reason, "consent withdrawn");

        show_write_only(&cfg, ID).unwrap();
        assert!(
            load(&suppressions_subdir(&cfg.service.override_dir_resolved()))
                .get(ID)
                .is_none()
        );
    }

    #[test]
    fn rejects_malformed_id() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_with_override_dir(dir.path());
        assert!(hide_write_only(&cfg, "../x", "r").is_err());
        assert!(take_down_write_only(&cfg, "../x", "r").is_err());
        assert!(show_write_only(&cfg, "../x").is_err());
    }

    #[test]
    fn show_of_an_unsuppressed_id_is_a_harmless_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_with_override_dir(dir.path());
        // Nothing suppressed yet: removing a file that was never written must not error.
        show_write_only(&cfg, ID).unwrap();
        assert!(
            load(&suppressions_subdir(&cfg.service.override_dir_resolved()))
                .get(ID)
                .is_none()
        );
    }

    #[test]
    fn take_down_dry_run_returns_before_writing_anything() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_with_override_dir(dir.path());

        take_down(&cfg, ID, "consent withdrawn", true).unwrap();
        // Dry-run: the suppressions dir must not even have been created.
        assert!(!suppressions_subdir(&cfg.service.override_dir_resolved()).exists());
    }

    #[test]
    fn take_down_dry_run_still_rejects_a_malformed_id() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_with_override_dir(dir.path());
        assert!(take_down(&cfg, "../x", "r", true).is_err());
    }

    /// The public wrappers perform the write, not only the `*_write_only` inner function.
    /// They are exercised directly because they also print the apply-now hint, which sends
    /// no signal (see [`crate::override_advice::print_apply_now_hint`]).
    #[test]
    fn public_wrappers_write_through_to_the_same_store() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_with_override_dir(dir.path());

        hide(&cfg, ID, "embargo").unwrap();
        assert_eq!(
            load(&suppressions_subdir(&cfg.service.override_dir_resolved()))
                .get(ID)
                .unwrap()
                .mode,
            SuppressMode::Hide
        );

        take_down(&cfg, ID, "consent withdrawn", false).unwrap();
        assert_eq!(
            load(&suppressions_subdir(&cfg.service.override_dir_resolved()))
                .get(ID)
                .unwrap()
                .mode,
            SuppressMode::Remove
        );

        show(&cfg, ID, "lift").unwrap();
        assert!(
            load(&suppressions_subdir(&cfg.service.override_dir_resolved()))
                .get(ID)
                .is_none()
        );
    }

    #[test]
    fn hide_emits_a_dataset_suppressed_audit_line() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_with_override_dir(dir.path());
        let out = capture_with(|| {
            hide(&cfg, ID, "embargo").unwrap();
        });
        assert!(out.contains("\"event\":\"dataset_suppressed\""), "{out}");
        assert!(
            out.contains("\"actor\":\"operator\""),
            "the file-writer is the operator actor: {out}"
        );
        assert!(out.contains("\"mode\":\"hide\""), "{out}");
        // The justification must not reach the log stream.
        assert!(
            !out.contains("embargo") && !out.contains("\"reason\""),
            "the operator justification is personal data and must not be logged: {out}"
        );
    }

    #[test]
    fn take_down_emits_a_dataset_suppressed_audit_line_with_remove_mode() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_with_override_dir(dir.path());
        let out = capture_with(|| {
            take_down(&cfg, ID, "consent withdrawn", false).unwrap();
        });
        assert!(out.contains("\"event\":\"dataset_suppressed\""), "{out}");
        assert!(out.contains("\"mode\":\"remove\""), "{out}");
        // A take-down reason is written to satisfy an erasure request and names the subject
        // who made it, so it never reaches the log stream.
        assert!(
            !out.contains("consent withdrawn") && !out.contains("\"reason\""),
            "the operator justification is personal data and must not be logged: {out}"
        );
    }

    #[test]
    fn take_down_dry_run_emits_no_audit_line() {
        // Dry-run writes nothing, so it must not falsely claim a suppression happened.
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_with_override_dir(dir.path());
        let out = capture_with(|| {
            take_down(&cfg, ID, "consent withdrawn", true).unwrap();
        });
        assert!(out.is_empty(), "dry-run must emit no audit line: {out}");
    }

    #[test]
    fn show_emits_a_dataset_unsuppressed_audit_line() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_with_override_dir(dir.path());
        let out = capture_with(|| {
            show(&cfg, ID, "consent re-granted").unwrap();
        });
        assert!(out.contains("\"event\":\"dataset_unsuppressed\""), "{out}");
        assert!(
            out.contains("\"actor\":\"operator\""),
            "the file-writer is the operator actor: {out}"
        );
        assert!(
            !out.contains("consent re-granted") && !out.contains("\"reason\""),
            "the lift justification is personal data and stays off the log stream: {out}"
        );
    }

    /// The lift's `--reason` lands durably in the lift record, along with what was lifted,
    /// and only when something was lifted: a no-op lift re-exposes nothing and leaves no
    /// record, only its audit line.
    #[test]
    fn show_writes_a_lift_record_iff_an_override_was_lifted() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_with_override_dir(dir.path());
        let lifted_dir = crate::lift_record::lifted_subdir(&cfg);

        // No-op lift: nothing was withheld, no record.
        show(&cfg, ID, "probing").unwrap();
        assert!(
            !lifted_dir.exists() || std::fs::read_dir(&lifted_dir).unwrap().count() == 0,
            "a no-op lift must not fabricate a re-exposure record"
        );

        // A real lift: hide, then unhide. One record, naming the lifted mode and why.
        hide(&cfg, ID, "erasure requested").unwrap();
        show(&cfg, ID, "consent re-granted").unwrap();
        let files: Vec<_> = std::fs::read_dir(&lifted_dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(files.len(), 1, "one lift, one record");
        let body: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&files[0]).unwrap()).unwrap();
        assert_eq!(body["key"], ID);
        assert_eq!(body["lifted_mode"], "hide");
        assert_eq!(body["reason"], "consent re-granted");
    }
}
