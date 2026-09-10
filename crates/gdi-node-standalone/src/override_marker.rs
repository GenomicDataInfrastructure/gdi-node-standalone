//! The override-store used marker: `data_dir/.override-store-used.json`.
//!
//! One durable bit: "this node's override store currently holds at least one override",
//! persisted on the data volume rather than the override volume, so it survives the one
//! loss the store itself cannot witness, the override volume being replaced wholesale.
//! `require_override_store`'s structural assertion
//! ([`gdi_node_standalone_core::override_store::ensure_present`]) covers a store whose root
//! or subdirectories are absent. A restore that recreates the directory tree without the
//! files, or an `overrides init` run against the wrong volume, presents an empty but intact
//! store, which is byte-identical to a node that legitimately holds no overrides. This
//! marker is what tells those two apart, and without it an erased dataset can be resurrected
//! by that shape on an otherwise green boot.
//!
//! Maintenance is one-directional. [`sync`] sets the marker whenever the store is populated,
//! after every override write and again at boot ([`sync_and_assert`]), so a write site that
//! forgets to call it is healed at the next boot. It never clears. Clearing has exactly two
//! callers: a lift or reset that removed the store's last entry ([`sync_after_removal`]),
//! and the operator attesting an empty store (`overrides init --yes`, via [`clear`]). A verb
//! that removed nothing must leave the marker alone. `dataset unhide` on an id with no
//! override is a supported, audited no-op, and on a structure-only-restored store the marker
//! is the only witness that the withholds ever existed, so "clear whenever the store is
//! empty" would let that no-op disarm the boot refusal.
//!
//! Both failure directions are safe. A stale present marker can only refuse a boot, which
//! `overrides import` or `overrides init --yes` recovers, and a stale absent marker leaves
//! the node no worse off than having no marker at all.
//!
//! The file's content is a timestamp for the operator's benefit; only its presence is
//! consulted, so a corrupt file still protects.

use std::path::PathBuf;

use gdi_node_standalone_core::config::ServiceConfig;
use gdi_node_standalone_core::error::{CoreError, CoreResult};
use gdi_node_standalone_core::override_store::is_populated;
use tracing::warn;

/// The marker's path: beside `.status.json` on the data volume, dot-prefixed so it can
/// never collide with a dataset directory.
#[must_use]
pub fn marker_path(config: &ServiceConfig) -> PathBuf {
    config.service.data_dir.join(".override-store-used.json")
}

/// Set the marker when the store holds at least one override. Idempotent, and it never
/// clears: an empty store is either legitimately empty or structure-only-restored, and this
/// function cannot tell which. Only the verb that removed the last entry
/// ([`sync_after_removal`]) or the operator ([`clear`]) can. Called after every override
/// write and at boot.
///
/// Best effort: it runs inside operator CLI verbs whose override write has already
/// succeeded, so a marker maintenance failure must not make the verb report failure. A
/// failed write warns, and the next write or boot re-derives it.
pub fn sync(config: &ServiceConfig) {
    if !is_populated(&config.service.override_dir_resolved()) {
        return;
    }
    let marker = marker_path(config);
    if marker.exists() {
        return;
    }
    if let Err(e) = gdi_node_standalone_core::util::write_durable_atomic_private(
        &marker,
        format!(
            "{{\"note\":\"this node's override store holds overrides; see \
             operating.md section 17\",\"since\":\"{}\"}}\n",
            gdi_node_standalone_core::util::now_rfc3339()
        )
        .as_bytes(),
    ) {
        warn!(
            path = %marker.display(),
            error = %e,
            "override-store used marker could not be written; it is re-derived on the \
             next override write or boot"
        );
    }
}

/// After an override removal, clear the marker only if this removal emptied the store.
///
/// `removed` is whether the verb deleted a file; the store removers report it, since
/// `suppression::remove_file` and its siblings return `Ok(true)` only for a real unlink. A
/// no-op lift is not evidence that this node emptied its own store, and on a
/// structure-only-restored store it is the verb that would otherwise disarm the boot
/// refusal, so it leaves the marker standing. A real removal that leaves other overrides in
/// place also leaves it standing.
pub fn sync_after_removal(config: &ServiceConfig, removed: bool) {
    if !removed || is_populated(&config.service.override_dir_resolved()) {
        return;
    }
    clear(config);
}

/// Remove the marker: the explicit statement that this store is intended to be empty.
///
/// Two callers only: [`sync_after_removal`], when a lift removed the store's last entry, and
/// `overrides init --yes`, when the operator attests an emptied store. Best effort. An
/// already-absent marker is success; any other failure warns and leaves the marker standing,
/// which is the safe direction, since a standing marker can only refuse a boot.
pub fn clear(config: &ServiceConfig) {
    let marker = marker_path(config);
    match std::fs::remove_file(&marker) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!(
            path = %marker.display(),
            error = %e,
            "override-store used marker could not be cleared; the next boot refuses, or \
             warns, over the empty store until `overrides init --yes` clears it"
        ),
    }
}

/// The boot half: self-heal the marker, then assert store content against it.
///
/// * Store populated: rewrite the marker and pass. This also backfills the marker on a
///   node that recorded overrides before the marker existed, and heals a mutation site that
///   skipped [`sync`].
/// * Store empty, marker present: the store once held overrides and now holds none without
///   the node having removed them. With `require` set this is fatal, because serving would
///   re-disclose every withheld dataset. Without `require` it warns, the same split
///   `ensure_present` makes.
/// * Store empty, no marker: a fresh node, or one emptied and attested; pass.
///
/// # Errors
///
/// Returns [`CoreError::InvalidConfig`] for the fatal arm, naming both recoveries.
pub fn sync_and_assert(config: &ServiceConfig, require: bool) -> CoreResult<()> {
    let marker = marker_path(config);
    if is_populated(&config.service.override_dir_resolved()) {
        sync(config);
        return Ok(());
    }
    if !marker.exists() {
        return Ok(());
    }
    if !require {
        warn!(
            marker = %marker.display(),
            "the override store is empty but this node's marker says it has held \
             overrides: if the store volume was replaced or restored structure-only, \
             every withhold is gone and previously-erased datasets will re-ingest. \
             Restore the store with `overrides import`, or, if you meant to empty it, \
             attest that with `overrides init --yes`"
        );
        return Ok(());
    }
    Err(CoreError::InvalidConfig {
        detail: "service.require_override_store is set and this node's data volume \
                 records that the override store has held overrides, but the store is \
                 now empty. An empty-but-intact store is what a structure-only restore, \
                 or an `overrides init` against the wrong volume, produces. Serving now \
                 would silently re-disclose every withheld dataset and re-ingest every \
                 erased one. Restore the store from backup with `overrides import`. Only \
                 if you meant to empty it, attest that with `overrides init --yes`, \
                 which clears this marker"
            .to_owned(),
    })
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;
    use gdi_node_standalone_core::suppression::{
        SuppressMode, Suppression, suppressions_subdir, write_file,
    };

    fn config_in(dir: &std::path::Path) -> ServiceConfig {
        let toml = format!(
            "[service]\nbase_url=\"https://x.example\"\ndata_dir=\"{}\"\n\
             [beacon]\nid=\"o.x\"\nname=\"X\"\n",
            dir.display()
        );
        ServiceConfig::from_toml_str(&toml).unwrap()
    }

    const ID: &str = "GDI-EE-UTARTU-20260409143052837";

    fn write_one_override(config: &ServiceConfig) {
        write_file(
            &suppressions_subdir(&config.service.override_dir_resolved()),
            ID,
            &Suppression {
                mode: SuppressMode::Hide,
                reason: "r".to_owned(),
                at: String::new(),
            },
        )
        .unwrap();
    }

    #[test]
    fn sync_sets_the_marker_and_never_clears_it() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_in(dir.path());

        sync(&config);
        assert!(!marker_path(&config).exists(), "empty store: no marker");

        write_one_override(&config);
        sync(&config);
        assert!(marker_path(&config).exists(), "an override sets the marker");

        // The files vanish out from under the node, the structure-only restore shape.
        // `sync` cannot tell that from a legitimate lift, so it must not clear: the marker
        // is the only witness that the withhold existed.
        std::fs::remove_file(
            suppressions_subdir(&config.service.override_dir_resolved()).join(format!("{ID}.json")),
        )
        .unwrap();
        sync(&config);
        assert!(
            marker_path(&config).exists(),
            "sync never clears: an empty store under the marker is a lost store until proven otherwise"
        );

        // A removal that removed nothing (a no-op `unhide`) is no such proof.
        sync_after_removal(&config, false);
        assert!(
            marker_path(&config).exists(),
            "a no-op lift must not clear the marker"
        );

        // A removal that did delete the last entry is: the node emptied its own store.
        sync_after_removal(&config, true);
        assert!(
            !marker_path(&config).exists(),
            "lifting the last override clears the marker"
        );
    }

    #[test]
    fn a_real_removal_that_leaves_other_overrides_keeps_the_marker() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_in(dir.path());
        write_one_override(&config);
        write_file(
            &suppressions_subdir(&config.service.override_dir_resolved()),
            "GDI-EE-UTARTU-20260409143052999",
            &Suppression {
                mode: SuppressMode::Hide,
                reason: "r".to_owned(),
                at: String::new(),
            },
        )
        .unwrap();
        sync(&config);
        assert!(marker_path(&config).exists());

        std::fs::remove_file(
            suppressions_subdir(&config.service.override_dir_resolved()).join(format!("{ID}.json")),
        )
        .unwrap();
        sync_after_removal(&config, true);
        assert!(
            marker_path(&config).exists(),
            "the store still holds an override, so the marker stands"
        );
    }

    #[test]
    fn an_emptied_store_with_the_marker_standing_refuses_the_required_boot() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_in(dir.path());
        write_one_override(&config);
        sync(&config);

        // The loss: the store is replaced by an empty but intact tree (root and subdirs, no
        // files), the structure-only restore shape that `ensure_present` accepts. The
        // marker, on the data volume, survives.
        let root = config.service.override_dir_resolved();
        std::fs::remove_dir_all(&root).unwrap();
        std::fs::create_dir_all(suppressions_subdir(&root)).unwrap();
        std::fs::create_dir_all(root.join("overlays")).unwrap();

        let err = sync_and_assert(&config, true).expect_err("must refuse");
        let msg = err.to_string();
        assert!(
            msg.contains("overrides import") && msg.contains("overrides init"),
            "the refusal names both recoveries: {msg}"
        );

        // Without the flag: a warning, not a refusal, the same split `ensure_present` makes.
        sync_and_assert(&config, false).expect("unrequired store only warns");

        // The attestation path: an operator who intends the store to be empty clears the
        // marker explicitly, which is what `overrides init --yes` calls, after which boot
        // passes. `sync` cannot get there, because it never clears.
        sync(&config);
        sync_and_assert(&config, true).expect_err("sync never clears the marker");
        clear(&config);
        sync_and_assert(&config, true).expect("attested-empty store boots");
    }

    #[test]
    fn a_populated_store_backfills_a_missing_marker_at_boot() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_in(dir.path());
        write_one_override(&config);
        assert!(
            !marker_path(&config).exists(),
            "written without sync — the pre-marker upgrade shape"
        );
        sync_and_assert(&config, true).expect("populated store passes");
        assert!(
            marker_path(&config).exists(),
            "boot backfills the marker, healing any missed sync"
        );
    }
}
