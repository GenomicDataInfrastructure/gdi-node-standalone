//! Durable records of lifted withholds: `<override_dir>/lifted/*.json`.
//!
//! Re-exposing data needs a justification as much as withholding it does. A withhold's
//! `--reason` lives in the override file it writes, and a lift removes that file. Operator
//! reasons stay out of the log stream, because they are free text that can name data
//! subjects, so this is where a lift's justification is kept.
//!
//! A lift record is written by `dataset unhide` and `channel unhide` when the override file
//! is removed, capturing what was lifted (scope, mode, when it was authored) and why. It
//! lives under `<override_dir>/lifted/`, on the same retention-governed volume but outside
//! every loader directory: the suppression and overlay loaders never read it, and
//! [`gdi_node_standalone_core::override_store::is_populated`] ignores it, because a lift
//! record is an audit artifact rather than an active override. `overrides export` captures
//! it under a separate `history` key, so a restore brings the justifications back; `import`
//! rewrites them here without making anything take effect.
//!
//! The paired `dataset_unsuppressed` and `channel_unsuppressed` audit lines carry the id and
//! event only, and correlate with a lift record by id. The record's `at` is stamped at write
//! time and the audit line's by the tracing subscriber on a later statement, so the two
//! timestamps differ and only the id is a usable key.
//!
//! The write goes through the override store's chokepoints like every other writer under
//! `<override_dir>/`. An operator-controlled key is a path, so
//! [`gdi_node_standalone_core::override_store::lifted_file_path`] validates it before
//! anything is created, and the directory is created owner-only like its `suppressions/`
//! and `overlays/` siblings: the listing names which ids and channels were re-exposed.
//!
//! Recording is best effort. The lift has already succeeded, so a failed record write warns
//! and names what could not be recorded instead of failing a completed governance action.

use std::path::PathBuf;

use gdi_node_standalone_core::config::ServiceConfig;
use gdi_node_standalone_core::override_store::{LiftScope, lifted_file_path};
use gdi_node_standalone_core::suppression::Suppression;
use gdi_node_standalone_core::util::{
    create_private_dir, now_rfc3339, write_durable_atomic_private,
};
use serde::Serialize;
use tracing::warn;

/// `<override_dir>/lifted`.
#[must_use]
pub(crate) fn lifted_subdir(config: &ServiceConfig) -> PathBuf {
    config.service.override_dir_resolved().join("lifted")
}

/// One lift, as persisted. Append-only: every lift writes a fresh file
/// (`{key}.{random}.json`), so repeated hide/lift cycles keep their full history.
#[derive(Debug, Serialize)]
struct LiftRecord<'a> {
    /// Which store the lifted override came from (`dataset` / `channel`).
    scope: LiftScope,
    /// The dataset id, or the channel name.
    key: &'a str,
    /// The lifted override's mode (`hide` / `remove`).
    lifted_mode: &'a str,
    /// When the lifted override was authored (its `at`).
    lifted_at: &'a str,
    /// The operator's justification for re-exposing (`--reason`).
    reason: &'a str,
    /// When the lift happened.
    at: String,
}

/// Record a dataset-scope lift of `lifted` (the override that was just removed).
pub fn record_dataset_lift(config: &ServiceConfig, id: &str, lifted: &Suppression, reason: &str) {
    write(config, LiftScope::Dataset, id, lifted, reason);
}

/// Record a channel-scope lift.
pub fn record_channel_lift(
    config: &ServiceConfig,
    channel: &str,
    lifted: &Suppression,
    reason: &str,
) {
    write(config, LiftScope::Channel, channel, lifted, reason);
}

fn write(config: &ServiceConfig, scope: LiftScope, key: &str, lifted: &Suppression, reason: &str) {
    let dir = lifted_subdir(config);
    // Validate the key before touching the filesystem: an unsafe key is a path, and a
    // refused record must create nothing, not even the directory.
    let path = match lifted_file_path(&dir, scope, key) {
        Ok(path) => path,
        Err(error) => {
            warn!(
                scope = scope.as_str(),
                key,
                error = %error,
                "refusing to record a lift under a key its store would not load; the audit \
                 line carries the event, the reason exists only in this session"
            );
            return;
        }
    };
    let record = LiftRecord {
        scope,
        key,
        lifted_mode: lifted.mode.as_str(),
        lifted_at: &lifted.at,
        reason,
        at: now_rfc3339(),
    };
    let result = create_private_dir(&dir)
        .map_err(|e| e.to_string())
        .and_then(|()| serde_json::to_vec_pretty(&record).map_err(|e| e.to_string()))
        .and_then(|bytes| write_durable_atomic_private(&path, &bytes).map_err(|e| e.to_string()));
    if let Err(error) = result {
        warn!(
            path = %path.display(),
            error,
            "the lift succeeded but its justification could not be recorded; the \
             audit line carries the event, the reason exists only in this session"
        );
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;
    use gdi_node_standalone_core::suppression::SuppressMode;

    fn config_in(dir: &std::path::Path) -> ServiceConfig {
        let toml = format!(
            "[service]\nbase_url=\"https://x.example\"\ndata_dir=\"{}\"\n\
             [beacon]\nid=\"o.x\"\nname=\"X\"\n",
            dir.display()
        );
        ServiceConfig::from_toml_str(&toml).unwrap()
    }

    #[test]
    fn a_lift_writes_one_record_carrying_what_was_lifted_and_why() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_in(dir.path());
        let lifted = Suppression {
            mode: SuppressMode::Hide,
            reason: "the WITHHOLD reason (already durable in the audit line)".to_owned(),
            at: "2026-08-01T00:00:00Z".to_owned(),
        };
        record_dataset_lift(
            &config,
            "GDI-EE-UTARTU-20260409143052837",
            &lifted,
            "erasure request withdrawn",
        );

        let files: Vec<_> = std::fs::read_dir(lifted_subdir(&config))
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(files.len(), 1, "one lift, one record");
        let body: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&files[0]).unwrap()).unwrap();
        assert_eq!(body["scope"], "dataset");
        assert_eq!(body["key"], "GDI-EE-UTARTU-20260409143052837");
        assert_eq!(body["lifted_mode"], "hide");
        assert_eq!(body["lifted_at"], "2026-08-01T00:00:00Z");
        assert_eq!(
            body["reason"], "erasure request withdrawn",
            "the RE-EXPOSURE justification is the record's whole purpose"
        );

        // A second lift of the same key appends, never overwrites.
        record_dataset_lift(&config, "GDI-EE-UTARTU-20260409143052837", &lifted, "again");
        assert_eq!(
            std::fs::read_dir(lifted_subdir(&config)).unwrap().count(),
            2,
            "history accumulates"
        );
    }

    /// `lifted/` lists which ids and channels were re-exposed, and when. The parallel
    /// listing of what is withheld lives in a 0700 `suppressions/`. No shipped deployment
    /// gives it a 0700 parent, so the directory's own mode is what protects it.
    #[cfg(unix)]
    #[test]
    fn the_lifted_dir_is_created_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let config = config_in(dir.path());
        let lifted = Suppression {
            mode: SuppressMode::Hide,
            reason: "r".to_owned(),
            at: String::new(),
        };
        record_dataset_lift(&config, "GDI-EE-UTARTU-20260409143052837", &lifted, "r");
        let mode = std::fs::metadata(lifted_subdir(&config))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o700,
            "lifted/ must be owner-only like its loader siblings"
        );
    }

    /// The record writer runs with the node's uid over operator-controlled content, so a
    /// key it does not validate is a path: `../evil` as a channel key would resolve to
    /// `<override_dir>/evil.{rand}.json`, outside `lifted/`.
    #[test]
    fn an_unsafe_key_writes_nothing_anywhere() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_in(dir.path());
        let lifted = Suppression {
            mode: SuppressMode::Hide,
            reason: "r".to_owned(),
            at: String::new(),
        };
        record_channel_lift(&config, "../evil", &lifted, "r");
        record_dataset_lift(&config, "../evil", &lifted, "r");
        record_dataset_lift(&config, "primary", &lifted, "r"); // a channel name is not an id

        assert!(
            !lifted_subdir(&config).exists(),
            "an unsafe key must be refused before anything is created"
        );
        let root = config.service.override_dir_resolved();
        let escaped: Vec<_> = std::fs::read_dir(&root)
            .map(|entries| entries.map(|e| e.unwrap().path()).collect())
            .unwrap_or_default();
        assert!(
            escaped.is_empty(),
            "nothing may land outside lifted/: {escaped:?}"
        );
    }

    #[test]
    fn lift_records_do_not_mark_the_store_as_populated() {
        // A `lifted/` dir full of records is not an active override set. The used marker
        // and the loaders must ignore it, or a node whose every withhold was lifted would
        // refuse to boot over its own audit trail.
        let dir = tempfile::tempdir().unwrap();
        let config = config_in(dir.path());
        let lifted = Suppression {
            mode: SuppressMode::Hide,
            reason: "r".to_owned(),
            at: String::new(),
        };
        record_channel_lift(&config, "primary", &lifted, "incident closed");
        assert!(
            !gdi_node_standalone_core::override_store::is_populated(
                &config.service.override_dir_resolved()
            ),
            "lift records are audit artifacts, not overrides"
        );
    }
}
