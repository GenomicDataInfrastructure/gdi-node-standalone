//! The `channel hide|take-down|show|list` commands: operator-authored withhold intent verbs
//! at channel granularity, where a channel is a whole `[[s3.buckets]]` provider or `inbox`.
//! This is the "stop serving this provider now" lever: `hide` and `take-down` withhold every
//! dataset of the channel and pause its ingest (`BucketMonitor::run`'s in-loop pause and
//! `IngestRuntime::scan_once`'s early return), and `show` lifts the withhold and resumes.
//!
//! It mirrors [`crate::suppress_cmd`]'s shape one level up. Each verb writes or removes
//! `<override_dir>/suppressions/channel-{name}.json`, in the same per-file store
//! [`gdi_node_standalone_core::suppression`] loads at boot, on `SIGUSR1` and on every
//! reconcile pass, with `channel-` as the filename discriminator from a dataset's
//! `{id}.json` in the same directory. Each then prints how to apply it now.
//!
//! `name` must be a channel the config knows about: a configured `[[s3.buckets]].name`, or
//! `inbox` with `[service].inbox` set. That is stricter than
//! [`gdi_node_standalone_core::suppression::is_valid_channel_name`], which only guards
//! filesystem safety, and it catches a mistyped or renamed provider before a suppression
//! file is created for a channel that will never exist.

use anyhow::{Context as _, Result, bail};

use gdi_node_standalone_core::config::ServiceConfig;

use crate::list_datasets::OutputFormat;
use gdi_node_standalone_core::suppression::{
    self, SuppressMode, Suppression, SuppressionSet, suppressions_subdir,
};
use gdi_node_standalone_core::util::now_rfc3339;

/// Reject a channel name the config does not know about. The override-authoring verbs
/// (`hide` and `take-down`) share this check, so the error text cannot drift between them.
///
/// [`show`] uses the wider [`require_liftable_channel`] instead.
fn require_configured_channel(config: &ServiceConfig, name: &str) -> Result<()> {
    if configured_channel_names(config).iter().any(|c| c == name) {
        return Ok(());
    }
    bail!(
        "unknown channel {name:?}: expected a configured [[s3.buckets]] name or `inbox` (with \
         [service].inbox set); run `channel list` to see configured channels"
    )
}

/// Reject a channel name for the override-lifting verb (`show`): it must be configured, or
/// already carry an override in the store.
///
/// This is wider than [`require_configured_channel`], because a withhold outlives the config
/// entry it was authored against. Suppression resolves as `effective(id, channel)` against
/// the channel recorded in the status index at ingest, so renaming or retiring a bucket
/// leaves every dataset it already ingested withheld by the orphaned `channel-{name}.json`.
/// [`list`] surfaces those entries as `"configured": false`, and `show` is the only verb that
/// removes one, so gating it on the configured set would make that drift unfixable through
/// the CLI on an image with no shell. A name that is neither configured nor present is still
/// rejected, which keeps the anti-typo posture.
fn require_liftable_channel(
    config: &ServiceConfig,
    name: &str,
    set: &SuppressionSet,
) -> Result<()> {
    if configured_channel_names(config).iter().any(|c| c == name) || set.channel_get(name).is_some()
    {
        return Ok(());
    }
    bail!(
        "unknown channel {name:?}: expected a configured [[s3.buckets]] name, `inbox` (with \
         [service].inbox set), or a channel that still carries an override; run `channel list` \
         to see both"
    )
}

/// Every channel this node is configured to ingest from: each `[[s3.buckets]].name`,
/// plus `inbox` when `[service].inbox` is set. Sorted for stable, readable output.
fn configured_channel_names(config: &ServiceConfig) -> Vec<String> {
    // `Reloadable::channels` is the single statement of which channels a config declares,
    // and the same set the orphan rule, the hydrate projection and every read surface
    // consult. `BTreeSet` iterates sorted, which is the order this list promises.
    gdi_node_standalone_core::config::Reloadable::from_config(config)
        .channels
        .into_iter()
        .collect()
}

/// `channel hide <name> --reason "…"`: withhold every dataset of `name` from disclosure and
/// pause its ingest. The underlying data is untouched, so [`show`] reverses it.
///
/// # Errors
///
/// Errors if `name` is not a configured channel or the suppression file cannot be
/// written.
pub fn hide(config: &ServiceConfig, name: &str, reason: &str) -> Result<()> {
    crate::override_advice::with_first_override_advice(config, || {
        hide_write_only(config, name, reason)?;
        crate::audit::channel_suppressed(&config.audit, name, SuppressMode::Hide);
        println!(
            "hid channel {name} (reason: {reason}); once applied the node withholds every \
             dataset of it and pauses its ingest"
        );
        crate::override_advice::print_apply_now_hint();
        Ok(())
    })
}

/// The file effect of [`hide`], with no hint or confirmation output.
fn hide_write_only(config: &ServiceConfig, name: &str, reason: &str) -> Result<()> {
    require_configured_channel(config, name)?;
    let dir = suppressions_subdir(&config.service.override_dir_resolved());
    suppression::write_channel_file(
        &dir,
        name,
        &Suppression {
            mode: SuppressMode::Hide,
            reason: reason.to_owned(),
            at: now_rfc3339(),
        },
    )
    .with_context(|| format!("writing hide override for channel {name}"))?;
    crate::override_marker::sync(config);
    Ok(())
}

/// `channel take-down <name> --reason "…" [--dry-run]`: withhold every dataset of `name`,
/// mark them for eviction, and pause the channel's ingest. This is irreversible from the
/// node's perspective: it erases each member's `data_dir/{id}` and refuses to re-ingest
/// while suppressed. `--dry-run` prints the plan and returns before writing anything.
///
/// # Errors
///
/// Errors if `name` is not a configured channel or the suppression file cannot be
/// written.
pub fn take_down(config: &ServiceConfig, name: &str, reason: &str, dry_run: bool) -> Result<()> {
    require_configured_channel(config, name)?;
    if dry_run {
        println!(
            "dry-run: would take down channel {name} (reason: {reason}); the node would \
             evict every dataset's local copy, refuse to re-ingest them, and pause the \
             channel's ingest; nothing written"
        );
        return Ok(());
    }
    crate::override_advice::with_first_override_advice(config, || {
        take_down_write_only(config, name, reason)?;
        crate::audit::channel_suppressed(&config.audit, name, SuppressMode::Remove);
        println!(
            "took down channel {name} (reason: {reason}); once applied the node erases every \
             dataset's local copy and pauses its ingest"
        );
        crate::override_advice::print_apply_now_hint();
        Ok(())
    })
}

/// The file effect of [`take_down`]. It always writes; the `--dry-run` short-circuit lives
/// in the public wrapper, before this is called.
fn take_down_write_only(config: &ServiceConfig, name: &str, reason: &str) -> Result<()> {
    require_configured_channel(config, name)?;
    let dir = suppressions_subdir(&config.service.override_dir_resolved());
    suppression::write_channel_file(
        &dir,
        name,
        &Suppression {
            mode: SuppressMode::Remove,
            reason: reason.to_owned(),
            at: now_rfc3339(),
        },
    )
    .with_context(|| format!("writing take-down override for channel {name}"))?;
    crate::override_marker::sync(config);
    Ok(())
}

/// `channel unhide <name> --reason <text>` (alias `channel show`): lift an operator-authored
/// withhold on `name`, if any, and resume its ingest. It removes only the operator's own
/// channel-level override, so a dataset its source marked hidden stays hidden.
///
/// `reason` is mandatory and goes to a durable [`crate::lift_record`] under
/// `<override_dir>/lifted/` rather than to the audit line; see [`crate::suppress_cmd::show`].
/// It is written only when an override was lifted, and a no-op lift leaves only its audit
/// line.
///
/// # Errors
///
/// Errors if `name` is not a configured channel or the suppression file cannot be
/// removed.
pub fn show(config: &ServiceConfig, name: &str, reason: &str) -> Result<()> {
    // Capture what is being lifted before its file goes. The durable home for `reason` is
    // the lift record, not the audit line (see `suppress_cmd::show`).
    let lifted = suppression::load_or_report(&suppressions_subdir(
        &config.service.override_dir_resolved(),
    ))
    .context("reading the override store to record what this lift removes")?
    .channel_get(name)
    .cloned();
    show_write_only(config, name)?;
    if let Some(lifted) = &lifted {
        crate::lift_record::record_channel_lift(config, name, lifted, reason);
    }
    crate::audit::channel_unsuppressed(&config.audit, name);
    println!(
        "lifted the operator withhold on channel {name} (if any); the node resumes serving \
         and ingesting it once applied"
    );
    crate::override_advice::print_apply_now_hint();
    Ok(())
}

/// The file effect of [`show`], with no hint or confirmation output.
fn show_write_only(config: &ServiceConfig, name: &str) -> Result<()> {
    let dir = suppressions_subdir(&config.service.override_dir_resolved());
    // Load first: the liftable check consults the store as well as the config, so a channel
    // that has left the config but still carries a withhold stays removable. Use
    // `load_or_report` rather than `load`, because this decides whether a withhold may be
    // lifted and an unreadable store would present as "no withhold here".
    let set: SuppressionSet = suppression::load_or_report(&dir)
        .context("reading the override store to check whether this channel is withheld")?;
    require_liftable_channel(config, name, &set)?;
    let removed = suppression::remove_channel_file(&dir, name)
        .with_context(|| format!("removing suppression override for channel {name}"))?;
    // The marker clears only if this lift emptied the store; a no-op lift is no evidence of
    // that (see `override_marker`).
    crate::override_marker::sync_after_removal(config, removed);
    Ok(())
}

/// `channel list`: read-only. Prints every configured channel (bucket names and `inbox`)
/// with its current suppression state, plus any suppressed channel the store still names but
/// the config no longer does, which is a renamed or removed provider whose override was
/// never lifted. Lock-free.
///
/// # Errors
///
/// Propagates a suppression-store read failure, which is not expected, since
/// [`suppression::load`] is fail-closed and does not error.
pub fn list(config: &ServiceConfig, format: OutputFormat) -> Result<()> {
    let dir = suppressions_subdir(&config.service.override_dir_resolved());
    let set: SuppressionSet = suppression::load_or_report(&dir)
        .context("reading the override store to list channel suppression state")?;

    let configured = configured_channel_names(config);
    let mut extra: Vec<String> = set
        .channel_names()
        .filter(|c| !configured.iter().any(|n| n == *c))
        .map(ToOwned::to_owned)
        .collect();
    extra.sort_unstable();

    // Configured first, then names that survive only in the override store, surfaced so an
    // operator does not lose track of a lingering override.
    let names: Vec<&str> = configured
        .iter()
        .map(String::as_str)
        .chain(extra.iter().map(String::as_str))
        .collect();

    if matches!(format, OutputFormat::Json) {
        // `dataset list` and `doctor` are scriptable, and `channel list` belongs with them.
        let rows: Vec<serde_json::Value> = names
            .iter()
            .map(|name| {
                let (state, reason) = set
                    .channel_get(name)
                    .map_or(("-", ""), |s| (s.mode.as_str(), s.reason.as_str()));
                serde_json::json!({
                    "channel": name,
                    "state": state,
                    "reason": reason,
                    "configured": configured.iter().any(|c| c == name),
                })
            })
            .collect();
        let out = serde_json::json!({ "schemaVersion": 1, "channels": rows });
        println!(
            "{}",
            serde_json::to_string_pretty(&out).unwrap_or_else(|_| "{}".to_owned())
        );
        return Ok(());
    }

    if names.is_empty() {
        println!("no channels configured (no [[s3.buckets]], no [service].inbox)");
        return Ok(());
    }

    println!(
        "{:<24} {:<10} {:<10} REASON",
        "CHANNEL", "STATE", "CONFIGURED"
    );
    for name in &names {
        print_channel_row(&set, name, configured.iter().any(|c| c == *name));
    }
    Ok(())
}

/// Print one `channel list` row for `name`, resolving its current override (if any)
/// from `set`. Split out of [`list`] so the configured/drift loops share one format.
///
/// `configured` is a column rather than a suffix, so the text form distinguishes a retired
/// channel's lingering withhold from a live one. The `--format json` rows carry the same
/// flag.
fn print_channel_row(set: &SuppressionSet, name: &str, configured: bool) {
    let configured = if configured { "yes" } else { "no" };
    match set.channel_get(name) {
        Some(s) => println!(
            "{:<24} {:<10} {configured:<10} {}",
            name,
            s.mode.as_str(),
            s.reason
        ),
        None => println!("{:<24} {:<10} {configured:<10} ", name, "-"),
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;
    use gdi_node_standalone_core::suppression::load;

    /// Capture the `audit`-target JSON emitted while running `f`, mirroring the helper in
    /// `suppress_cmd`, which is private to its module.
    fn capture_with(f: impl FnOnce()) -> String {
        test_util::capture_json_logs(f).1
    }

    fn config_with_bucket_and_inbox(
        override_dir: &std::path::Path,
        inbox: &std::path::Path,
    ) -> ServiceConfig {
        config_with_bucket_inbox_and_data(
            override_dir,
            inbox,
            std::path::Path::new("/var/lib/gdi/datasets"),
        )
    }

    /// As [`config_with_bucket_and_inbox`], with a real `data_dir`, where the marker lives.
    fn config_with_bucket_inbox_and_data(
        override_dir: &std::path::Path,
        inbox: &std::path::Path,
        data_dir: &std::path::Path,
    ) -> ServiceConfig {
        let toml = format!(
            r#"
[service]
base_url = "https://n.example.org/"
data_dir = "{}"
override_dir = "{}"
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

[[s3.buckets]]
name = "primary"
"#,
            data_dir.display(),
            override_dir.display(),
            inbox.display(),
        );
        ServiceConfig::from_toml_str(&toml).unwrap()
    }

    /// The channel twin of `suppress_cmd`'s marker test: a `channel unhide` that removed
    /// nothing leaves the marker standing, and lifting the last override clears it.
    #[test]
    fn a_no_op_channel_unhide_leaves_the_used_marker_and_a_real_last_lift_clears_it() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        let cfg = config_with_bucket_inbox_and_data(
            &tmp.path().join("overrides"),
            &tmp.path().join("inbox"),
            &data_dir,
        );
        let marker = crate::override_marker::marker_path(&cfg);

        hide_write_only(&cfg, "primary", "embargo").unwrap();
        assert!(marker.exists(), "a hide sets the marker");

        // The files are lost while the tree survives; the marker survives with it.
        let sub = suppressions_subdir(&cfg.service.override_dir_resolved());
        for entry in std::fs::read_dir(&sub).unwrap() {
            std::fs::remove_file(entry.unwrap().path()).unwrap();
        }
        show_write_only(&cfg, "primary").unwrap();
        assert!(marker.exists(), "a no-op lift must not clear the marker");

        hide_write_only(&cfg, "primary", "again").unwrap();
        show_write_only(&cfg, "primary").unwrap();
        assert!(
            !marker.exists(),
            "lifting the last override clears the marker"
        );
    }

    fn config_no_channels(override_dir: &std::path::Path) -> ServiceConfig {
        let toml = format!(
            r#"
[service]
base_url = "https://n.example.org/"
data_dir = "/var/lib/gdi/datasets"
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
            override_dir.display(),
        );
        ServiceConfig::from_toml_str(&toml).unwrap()
    }

    #[test]
    fn hide_writes_a_hide_file_take_down_writes_remove_show_removes_it() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = dir.path().join("inbox");
        let cfg = config_with_bucket_and_inbox(dir.path(), &inbox);

        hide_write_only(&cfg, "primary", "embargo").unwrap();
        let set = load(&suppressions_subdir(&cfg.service.override_dir_resolved()));
        let s = set.channel_get("primary").unwrap();
        assert_eq!(s.mode, SuppressMode::Hide);
        assert_eq!(s.reason, "embargo");
        assert!(!s.at.is_empty());

        take_down_write_only(&cfg, "primary", "consent withdrawn").unwrap();
        let set = load(&suppressions_subdir(&cfg.service.override_dir_resolved()));
        let s = set.channel_get("primary").unwrap();
        assert_eq!(s.mode, SuppressMode::Remove);
        assert_eq!(s.reason, "consent withdrawn");

        show_write_only(&cfg, "primary").unwrap();
        assert!(
            load(&suppressions_subdir(&cfg.service.override_dir_resolved()))
                .channel_get("primary")
                .is_none()
        );
    }

    #[test]
    fn inbox_is_a_valid_channel_when_configured() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = dir.path().join("inbox");
        let cfg = config_with_bucket_and_inbox(dir.path(), &inbox);
        hide_write_only(&cfg, "inbox", "compromised").unwrap();
        let set = load(&suppressions_subdir(&cfg.service.override_dir_resolved()));
        assert_eq!(set.channel_get("inbox").unwrap().mode, SuppressMode::Hide);
    }

    #[test]
    fn rejects_an_unconfigured_channel_name() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = dir.path().join("inbox");
        let cfg = config_with_bucket_and_inbox(dir.path(), &inbox);
        assert!(hide_write_only(&cfg, "not-a-real-bucket", "r").is_err());
        assert!(take_down_write_only(&cfg, "not-a-real-bucket", "r").is_err());
        assert!(show_write_only(&cfg, "not-a-real-bucket").is_err());
        // No inbox configured on this node, so "inbox" is not a valid channel either.
        let cfg2 = config_no_channels(dir.path());
        assert!(hide_write_only(&cfg2, "inbox", "r").is_err());
    }

    /// A withhold outlives the config entry it was authored against, and stays liftable.
    ///
    /// Suppression resolves as `effective(id, channel)` against the channel recorded in the
    /// status index at ingest, so renaming or retiring a bucket leaves every dataset it
    /// already ingested withheld by an orphaned `channel-{name}.json`. `channel list` reports
    /// that drift as `"configured": false`, and `show` is the only verb that removes one.
    /// Authoring a new override for an unconfigured channel is still refused, which is the
    /// typo the check exists to catch.
    #[test]
    fn show_lifts_an_override_whose_channel_has_left_the_config() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = dir.path().join("inbox");
        let configured = config_with_bucket_and_inbox(dir.path(), &inbox);

        hide_write_only(&configured, "primary", "provider compromised").unwrap();
        let sub = suppressions_subdir(&configured.service.override_dir_resolved());
        assert!(load(&sub).channel_get("primary").is_some());

        // The bucket is renamed or retired: the same override store, and a config that no
        // longer names `primary`.
        let retired = config_no_channels(dir.path());
        assert!(
            load(&sub).channel_get("primary").is_some(),
            "the withhold survives the config change — that is the whole problem"
        );

        show_write_only(&retired, "primary")
            .expect("a channel that still carries an override must remain liftable");
        assert!(
            load(&sub).channel_get("primary").is_none(),
            "the orphaned override must actually be removed"
        );

        // Still refused for a name that is neither configured nor present in the store, and
        // still refused for authoring against a retired channel.
        assert!(show_write_only(&retired, "never-existed").is_err());
        assert!(hide_write_only(&retired, "primary", "r").is_err());
    }

    #[test]
    fn rejects_a_path_traversal_channel_name_even_though_it_is_unconfigured_anyway() {
        // An unconfigured name is rejected whatever its shape, but confirm that the
        // traversal-looking one never reaches the filesystem.
        let dir = tempfile::tempdir().unwrap();
        let inbox = dir.path().join("inbox");
        let cfg = config_with_bucket_and_inbox(dir.path(), &inbox);
        assert!(hide_write_only(&cfg, "../evil", "r").is_err());
        assert!(!dir.path().join("evil.json").exists());
    }

    #[test]
    fn show_of_an_unsuppressed_channel_is_a_harmless_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = dir.path().join("inbox");
        let cfg = config_with_bucket_and_inbox(dir.path(), &inbox);
        show_write_only(&cfg, "primary").unwrap();
        assert!(
            load(&suppressions_subdir(&cfg.service.override_dir_resolved()))
                .channel_get("primary")
                .is_none()
        );
    }

    #[test]
    fn take_down_dry_run_returns_before_writing_anything() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = dir.path().join("inbox");
        let cfg = config_with_bucket_and_inbox(dir.path(), &inbox);
        take_down(&cfg, "primary", "consent withdrawn", true).unwrap();
        assert!(!suppressions_subdir(&cfg.service.override_dir_resolved()).exists());
    }

    #[test]
    fn take_down_dry_run_still_rejects_an_unconfigured_channel() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = dir.path().join("inbox");
        let cfg = config_with_bucket_and_inbox(dir.path(), &inbox);
        assert!(take_down(&cfg, "not-a-real-bucket", "r", true).is_err());
    }

    #[test]
    fn public_wrappers_write_through_to_the_same_store() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = dir.path().join("inbox");
        let cfg = config_with_bucket_and_inbox(dir.path(), &inbox);

        hide(&cfg, "primary", "embargo").unwrap();
        assert_eq!(
            load(&suppressions_subdir(&cfg.service.override_dir_resolved()))
                .channel_get("primary")
                .unwrap()
                .mode,
            SuppressMode::Hide
        );

        take_down(&cfg, "primary", "consent withdrawn", false).unwrap();
        assert_eq!(
            load(&suppressions_subdir(&cfg.service.override_dir_resolved()))
                .channel_get("primary")
                .unwrap()
                .mode,
            SuppressMode::Remove
        );

        show(&cfg, "primary", "lift").unwrap();
        assert!(
            load(&suppressions_subdir(&cfg.service.override_dir_resolved()))
                .channel_get("primary")
                .is_none()
        );
    }

    #[test]
    fn hide_emits_a_channel_suppressed_audit_line() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = dir.path().join("inbox");
        let cfg = config_with_bucket_and_inbox(dir.path(), &inbox);
        let out = capture_with(|| {
            hide(&cfg, "primary", "embargo").unwrap();
        });
        assert!(out.contains("\"event\":\"channel_suppressed\""), "{out}");
        assert!(out.contains("\"actor\":\"operator\""), "{out}");
        assert!(out.contains("\"mode\":\"hide\""), "{out}");
        assert!(out.contains("primary"), "{out}");
        // A channel-wide justification is the same operator free text about the same data
        // subjects, so it must not reach the log stream either.
        assert!(
            !out.contains("embargo") && !out.contains("\"reason\""),
            "the operator justification is personal data and must not be logged: {out}"
        );
    }

    #[test]
    fn show_emits_a_channel_unsuppressed_audit_line() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = dir.path().join("inbox");
        let cfg = config_with_bucket_and_inbox(dir.path(), &inbox);
        let out = capture_with(|| {
            show(&cfg, "primary", "incident closed").unwrap();
        });
        assert!(out.contains("\"event\":\"channel_unsuppressed\""), "{out}");
        assert!(out.contains("primary"), "{out}");
        assert!(
            !out.contains("incident closed") && !out.contains("\"reason\""),
            "the lift justification is personal data and stays off the log stream; it lands \
             the lift record instead: {out}"
        );
    }

    /// The channel lift's `--reason` lands durably in the lift record, along with what was
    /// lifted, and only when something was lifted. Without this twin of the dataset test,
    /// removing the `record_channel_lift` call would leave the suite green while a mandatory
    /// flag's value went nowhere.
    #[test]
    fn show_writes_a_lift_record_iff_an_override_was_lifted() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = dir.path().join("inbox");
        let cfg = config_with_bucket_and_inbox(dir.path(), &inbox);
        let lifted_dir = crate::lift_record::lifted_subdir(&cfg);

        // No-op lift: nothing was withheld, no record.
        show(&cfg, "primary", "probing").unwrap();
        assert!(
            !lifted_dir.exists() || std::fs::read_dir(&lifted_dir).unwrap().count() == 0,
            "a no-op lift must not fabricate a re-exposure record"
        );

        // A real lift: take down, then unhide. One record, naming the lifted mode and why.
        take_down(&cfg, "primary", "provider compromised", false).unwrap();
        show(&cfg, "primary", "incident closed").unwrap();
        let files: Vec<_> = std::fs::read_dir(&lifted_dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(files.len(), 1, "one lift, one record");
        let body: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&files[0]).unwrap()).unwrap();
        assert_eq!(body["scope"], "channel");
        assert_eq!(body["key"], "primary");
        assert_eq!(body["lifted_mode"], "remove");
        assert_eq!(body["reason"], "incident closed");
    }

    #[test]
    fn take_down_dry_run_emits_no_audit_line() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = dir.path().join("inbox");
        let cfg = config_with_bucket_and_inbox(dir.path(), &inbox);
        let out = capture_with(|| {
            take_down(&cfg, "primary", "consent withdrawn", true).unwrap();
        });
        assert!(out.is_empty(), "dry-run must emit no audit line: {out}");
    }

    #[test]
    fn list_runs_without_error_on_a_node_with_no_channels() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_no_channels(dir.path());
        list(&cfg, OutputFormat::Text).unwrap();
    }

    #[test]
    fn list_runs_without_error_with_configured_and_suppressed_channels() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = dir.path().join("inbox");
        let cfg = config_with_bucket_and_inbox(dir.path(), &inbox);
        hide(&cfg, "primary", "embargo").unwrap();
        list(&cfg, OutputFormat::Text).unwrap();
    }

    #[test]
    fn configured_channel_names_lists_buckets_and_inbox_sorted() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = dir.path().join("inbox");
        let cfg = config_with_bucket_and_inbox(dir.path(), &inbox);
        assert_eq!(configured_channel_names(&cfg), vec!["inbox", "primary"]);
    }

    #[test]
    fn configured_channel_names_is_empty_with_no_s3_and_no_inbox() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_no_channels(dir.path());
        assert!(configured_channel_names(&cfg).is_empty());
    }
}
