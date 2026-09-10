//! The `dataset correct <id> --field k=v… | --patch <file> | --reset` one-shot commands:
//! author or remove a node-local metadata-overlay override that feeds the overlay engine
//! (`core::overlay_store`). Each writes or removes one override file under
//! `<override_dir>/overlays/{id}.json`, which is the durable source of truth
//! `core::overlay_override` reads at boot, on `SIGUSR1` and on every reconcile pass. Each
//! then prints how to apply it immediately; the CLI cannot signal the node itself.
//!
//! The node's reconcile applies this override through the same field-patch,
//! `deny_unknown_fields`, protected-field, monotone-`dct:modified` and validate engine a
//! bucket or inbox `{id}.metadata.json` sidecar goes through, so the command also works for
//! a bucket-owned dataset with no bucket write: the node overlays the correction locally and
//! it takes precedence over the source's own sidecar, as `dataset hide|take-down|show`'s
//! suppression override does.
//!
//! `correct` splits into a `*_write_only` function (id and overlay validation and the file
//! effect, unit-tested on its own) and a public wrapper that also prints the apply-now hint
//! and an operator confirmation, mirroring `suppress_cmd`'s shape.

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use serde_json::{Map, Value};

use gdi_node_standalone_core::config::ServiceConfig;
use gdi_node_standalone_core::id::is_valid_dataset_id;
use gdi_node_standalone_core::model::MetadataOverlay;
use gdi_node_standalone_core::overlay_override::{overlays_subdir, remove_file, write_file};

/// Reject a malformed dataset id up front. Both verbs source the check here, so the error
/// text cannot drift between them.
fn require_valid_id(id: &str) -> Result<()> {
    if is_valid_dataset_id(id) {
        Ok(())
    } else {
        bail!("invalid dataset id {id:?}")
    }
}

/// Set `value` at a dotted `key` path in `map` (e.g. `title.en` sets
/// `map["title"]["en"]`), creating intermediate objects as needed.
///
/// An empty `path` is a no-op. [`apply_field`] cannot produce one, since `key.split('.')`
/// always yields at least one segment, but handling it keeps this helper free of a panic
/// contract.
///
/// # Errors
/// Errors if a path segment already holds a non-object value, which is a conflicting pair of
/// `--field` flags such as `--field title=Foo --field title.en=Bar`.
fn set_at_path(map: &mut Map<String, Value>, path: &[&str], value: Value) -> Result<()> {
    let Some((head, rest)) = path.split_first() else {
        return Ok(());
    };
    if rest.is_empty() {
        map.insert((*head).to_owned(), value);
        return Ok(());
    }
    let entry = map
        .entry((*head).to_owned())
        .or_insert_with(|| Value::Object(Map::new()));
    let Value::Object(nested) = entry else {
        bail!("--field {head} conflicts with an earlier --field that set it to a non-object value");
    };
    set_at_path(nested, rest, value)
}

/// Parse one `--field key=value`, setting `value` at the dotted `key` path in `map`
/// (e.g. `--field title.en=Foo` sets `map["title"]["en"] = "Foo"`).
///
/// `value` is parsed as JSON when it parses cleanly, so `--field
/// numberOfUniqueIndividuals=42` becomes a number and `--field keywords='["a","b"]'` becomes
/// an array. Anything else is taken as a bare JSON string, so a plain IRI or free-text value
/// needs no quoting (`--field license=https://creativecommons.org/licenses/by/4.0/`).
///
/// # Errors
/// Errors on a malformed `field` (no `=`), an empty key, or a [`set_at_path`] conflict.
fn apply_field(map: &mut Map<String, Value>, field: &str) -> Result<()> {
    let (key, value) = field
        .split_once('=')
        .with_context(|| format!("invalid --field {field:?}; expected key=value"))?;
    if key.is_empty() {
        bail!("invalid --field {field:?}; the key must not be empty");
    }
    let parsed =
        serde_json::from_str::<Value>(value).unwrap_or_else(|_| Value::String(value.to_owned()));
    let path: Vec<&str> = key.split('.').collect();
    // No `.with_context()` wrap: `set_at_path`'s message already names the conflicting key,
    // and another layer would bury it one level deeper in the anyhow chain, where a plain
    // `{err}` (what a CLI error print shows) would not reach it.
    set_at_path(map, &path, parsed)
}

/// Build a [`MetadataOverlay`] from repeated `--field key=value` pairs.
///
/// # Errors
/// Errors on a malformed pair (no `=`, an empty key, or a conflicting dotted path), or on a
/// resulting document that does not deserialize into `MetadataOverlay`. That includes an
/// unknown or protected key: `datasetId`, `catalog` and `numberOfRecords` are rejected at
/// parse time by `deny_unknown_fields` and cannot be set this way.
pub fn overlay_from_fields(fields: &[String]) -> Result<MetadataOverlay> {
    let mut map = Map::new();
    for field in fields {
        apply_field(&mut map, field)?;
    }
    serde_json::from_value(Value::Object(map)).context(
        "the --field patch is not a valid metadata overlay (an unknown key, or a protected \
         field: datasetId/catalog/numberOfRecords/populations can never be edited)",
    )
}

/// Read a `--patch <file>` as a [`MetadataOverlay`].
///
/// # Errors
/// Errors if the file cannot be read, or its content does not deserialize into
/// `MetadataOverlay`, with the same protected and unknown-key rejection as
/// [`overlay_from_fields`].
pub fn overlay_from_patch_file(path: &Path) -> Result<MetadataOverlay> {
    let raw = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&raw)
        .with_context(|| format!("{} is not a valid metadata overlay", path.display()))
}

/// `dataset correct <id> --field k=v… | --patch <file>`: author (or refresh) a
/// node-local metadata-overlay override for `id`, then exit.
///
/// # Errors
/// Errors if `id` is malformed, if `overlay` sets no field (a no-op, such as an empty
/// `--patch` file), or if the override file cannot be written.
pub fn correct(
    config: &ServiceConfig,
    id: &str,
    overlay: &MetadataOverlay,
    reason: Option<&str>,
) -> Result<()> {
    crate::override_advice::with_first_override_advice(config, || {
        correct_write_only(config, id, overlay)?;
        // The actor is the file writer, this CLI process. Emitted right after the write
        // succeeds, whether or not the running node is up to apply it.
        crate::audit::metadata_overlay_set(&config.audit, id, reason);
        println!(
            "wrote a node-local metadata override for {id}; once applied the node serves it \
             through the existing overlay engine, and it takes precedence over any \
             bucket/inbox {{id}}.metadata.json sidecar for {id}"
        );
        crate::override_advice::print_apply_now_hint();
        crate::override_advice::note_if_this_node_has_no_such_dataset(config, id);
        Ok(())
    })
}

/// The file effect of [`correct`], with no hint or confirmation output.
fn correct_write_only(config: &ServiceConfig, id: &str, overlay: &MetadataOverlay) -> Result<()> {
    require_valid_id(id)?;
    if overlay.is_empty() {
        bail!(
            "the metadata override sets no field; pass at least one --field or a non-empty --patch"
        );
    }
    // Validate before writing. The authoritative check runs at apply time
    // (`overlay_store::apply` then `validate_overlay_result`) and needs a baseline this CLI
    // does not hold, but without a check here a bad value lands durably and is reported as
    // written, and the node silently refuses the merge on its next reconcile.
    gdi_node_standalone_core::validate_pkg::validate_patch(overlay)
        .with_context(|| format!("the metadata override for {id} is not valid"))?;
    let dir = overlays_subdir(&config.service.override_dir_resolved());
    write_file(&dir, id, overlay).with_context(|| format!("writing metadata override for {id}"))?;
    crate::override_marker::sync(config);
    Ok(())
}

/// `dataset correct <id> --reset`: remove a node-local metadata-overlay override, then
/// exit. On the node's next reconcile the dataset reverts to the package baseline, or
/// resumes a source `{id}.metadata.json` if one is present. The monotone `dct:modified`
/// high-water mark is unaffected (see `core::overlay_store`).
///
/// # Errors
/// Errors if `id` is malformed or the override file cannot be removed.
pub fn reset(config: &ServiceConfig, id: &str) -> Result<()> {
    reset_write_only(config, id)?;
    crate::audit::metadata_overlay_cleared(&config.audit, id);
    println!(
        "removed the node-local metadata override on {id} (if any); once applied the node \
         reverts to the package baseline, or resumes a source {{id}}.metadata.json if present"
    );
    crate::override_advice::print_apply_now_hint();
    Ok(())
}

/// The file effect of [`reset`], with no hint or confirmation output.
fn reset_write_only(config: &ServiceConfig, id: &str) -> Result<()> {
    require_valid_id(id)?;
    let dir = overlays_subdir(&config.service.override_dir_resolved());
    let removed =
        remove_file(&dir, id).with_context(|| format!("removing metadata override for {id}"))?;
    // The marker clears only if this reset emptied the store; a no-op reset is no evidence
    // of that (see `override_marker`).
    crate::override_marker::sync_after_removal(config, removed);
    Ok(())
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;
    use gdi_node_standalone_core::overlay_override::load;

    const ID: &str = "GDI-EE-UTARTU-20260409143052837";

    /// Capture the `audit`-target JSON emitted while running `f`, mirroring the helper in
    /// `suppress_cmd`, which is private to its module.
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

    /// The overlay twin of `suppress_cmd`'s marker test: a `--reset` that removed nothing
    /// leaves the marker standing, and resetting the last override clears it.
    #[test]
    fn a_no_op_reset_leaves_the_used_marker_and_a_real_last_reset_clears_it() {
        const OTHER: &str = "GDI-EE-UTARTU-20260409143052999";
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        let cfg = config_with_dirs(&tmp.path().join("overrides"), &data_dir);
        let marker = crate::override_marker::marker_path(&cfg);
        let overlay = overlay_from_fields(&["title=Corrected".to_owned()]).unwrap();

        correct_write_only(&cfg, ID, &overlay).unwrap();
        assert!(marker.exists(), "a correction sets the marker");

        // The files are lost while the tree survives; the marker survives with it.
        std::fs::remove_file(
            overlays_subdir(&cfg.service.override_dir_resolved()).join(format!("{ID}.json")),
        )
        .unwrap();
        reset_write_only(&cfg, OTHER).unwrap();
        assert!(marker.exists(), "a no-op reset must not clear the marker");

        correct_write_only(&cfg, ID, &overlay).unwrap();
        reset_write_only(&cfg, ID).unwrap();
        assert!(
            !marker.exists(),
            "resetting the last override clears the marker"
        );
    }

    // -----------------------------------------------------------------------
    // overlay_from_fields
    // -----------------------------------------------------------------------

    #[test]
    fn scalar_field_becomes_a_bare_string() {
        let ov = overlay_from_fields(&[
            "license=https://creativecommons.org/licenses/by/4.0/".to_owned()
        ])
        .unwrap();
        assert_eq!(
            ov.license.as_deref(),
            Some("https://creativecommons.org/licenses/by/4.0/")
        );
    }

    #[test]
    fn dotted_field_sets_a_localized_map_entry() {
        let ov = overlay_from_fields(&[
            "title.en=Corrected title".to_owned(),
            "title.fi=Korjattu otsikko".to_owned(),
        ])
        .unwrap();
        match ov.title.unwrap() {
            gdi_node_standalone_core::model::LocalizedText::Map(m) => {
                assert_eq!(m.get("en").unwrap(), "Corrected title");
                assert_eq!(m.get("fi").unwrap(), "Korjattu otsikko");
            }
            plain @ gdi_node_standalone_core::model::LocalizedText::Plain(_) => {
                panic!("expected a language map, got {plain:?}")
            }
        }
    }

    #[test]
    fn numeric_field_is_coerced_via_json() {
        let ov = overlay_from_fields(&["numberOfUniqueIndividuals=42".to_owned()]).unwrap();
        assert_eq!(ov.number_of_unique_individuals, Some(42));
    }

    #[test]
    fn json_array_literal_field_becomes_a_list() {
        let ov = overlay_from_fields(&[r#"keywords=["covid","variant"]"#.to_owned()]).unwrap();
        assert_eq!(
            ov.keywords,
            Some(vec!["covid".to_owned(), "variant".to_owned()])
        );
    }

    #[test]
    fn a_protected_field_is_rejected_at_build_time() {
        for bad in ["datasetId=OTHER", "catalog=other", "numberOfRecords=7"] {
            let err = overlay_from_fields(&[bad.to_owned()]).unwrap_err();
            assert!(err.to_string().contains("protected"), "{bad} -> {err}");
        }
    }

    #[test]
    fn an_unknown_field_is_rejected() {
        assert!(overlay_from_fields(&["somethingElse=true".to_owned()]).is_err());
    }

    #[test]
    fn a_malformed_field_without_equals_is_rejected() {
        assert!(overlay_from_fields(&["title".to_owned()]).is_err());
    }

    #[test]
    fn conflicting_dotted_paths_are_rejected() {
        let err =
            overlay_from_fields(&["title=Plain title".to_owned(), "title.en=Nested".to_owned()])
                .unwrap_err();
        assert!(err.to_string().contains("conflicts"), "{err}");
    }

    #[test]
    fn a_patch_the_node_would_reject_is_refused_before_anything_is_written() {
        // Without a check at write time, a bad value lands durably and is reported as
        // written, and the node refuses the merge on its next reconcile: an accessRights
        // downgrade or a PII redaction would silently never apply.
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_with_override_dir(dir.path());
        let bad = MetadataOverlay {
            license: Some("not-an-iri".to_owned()),
            ..MetadataOverlay::default()
        };
        let err = correct_write_only(&cfg, ID, &bad)
            .expect_err("a value the node rejects must not be written");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("license"),
            "the error must name the field: {msg}"
        );

        let path = overlays_subdir(&cfg.service.override_dir_resolved()).join(format!("{ID}.json"));
        assert!(
            !path.exists(),
            "nothing may be left on disk for the node to find: {}",
            path.display()
        );

        // The same patch with a real IRI writes normally.
        let good = MetadataOverlay {
            license: Some("https://creativecommons.org/licenses/by/4.0/".to_owned()),
            ..MetadataOverlay::default()
        };
        correct_write_only(&cfg, ID, &good).expect("a valid patch still writes");
        assert!(path.is_file());
    }

    #[test]
    fn no_fields_yields_an_empty_overlay() {
        let ov = overlay_from_fields(&[]).unwrap();
        assert!(ov.is_empty());
    }

    // -----------------------------------------------------------------------
    // overlay_from_patch_file
    // -----------------------------------------------------------------------

    #[test]
    fn patch_file_round_trips_a_valid_overlay() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("patch.json");
        std::fs::write(&path, br#"{"title":"From a file"}"#).unwrap();
        let ov = overlay_from_patch_file(&path).unwrap();
        assert_eq!(
            ov.title,
            Some(gdi_node_standalone_core::model::LocalizedText::Plain(
                "From a file".to_owned()
            ))
        );
    }

    #[test]
    fn patch_file_rejects_a_protected_field() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("patch.json");
        std::fs::write(&path, br#"{"datasetId":"OTHER"}"#).unwrap();
        assert!(overlay_from_patch_file(&path).is_err());
    }

    #[test]
    fn patch_file_errors_on_a_missing_path() {
        let dir = tempfile::tempdir().unwrap();
        assert!(overlay_from_patch_file(&dir.path().join("missing.json")).is_err());
    }

    // -----------------------------------------------------------------------
    // correct / reset write effects + audit
    // -----------------------------------------------------------------------

    #[test]
    fn correct_writes_an_override_reset_removes_it() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_with_override_dir(dir.path());
        let overlay = overlay_from_fields(&["title=Corrected".to_owned()]).unwrap();

        correct_write_only(&cfg, ID, &overlay).unwrap();
        let set = load(&overlays_subdir(&cfg.service.override_dir_resolved()));
        assert_eq!(set.get(ID), Some(&overlay));

        reset_write_only(&cfg, ID).unwrap();
        assert!(
            load(&overlays_subdir(&cfg.service.override_dir_resolved()))
                .get(ID)
                .is_none()
        );
    }

    #[test]
    fn correct_rejects_a_malformed_id() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_with_override_dir(dir.path());
        let overlay = overlay_from_fields(&["title=X".to_owned()]).unwrap();
        assert!(correct_write_only(&cfg, "../x", &overlay).is_err());
        assert!(reset_write_only(&cfg, "../x").is_err());
    }

    #[test]
    fn correct_rejects_an_empty_overlay() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_with_override_dir(dir.path());
        let empty = MetadataOverlay::default();
        let err = correct_write_only(&cfg, ID, &empty).unwrap_err();
        assert!(err.to_string().contains("no field"), "{err}");
        assert!(
            !overlays_subdir(&cfg.service.override_dir_resolved()).exists(),
            "an empty overlay must not even create the overlays dir"
        );
    }

    #[test]
    fn reset_of_an_unoverridden_id_is_a_harmless_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_with_override_dir(dir.path());
        reset_write_only(&cfg, ID).unwrap();
        assert!(
            load(&overlays_subdir(&cfg.service.override_dir_resolved()))
                .get(ID)
                .is_none()
        );
    }

    #[test]
    fn public_wrappers_write_through_to_the_same_store() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_with_override_dir(dir.path());
        let overlay = overlay_from_fields(&["title=Corrected".to_owned()]).unwrap();

        // Run under `capture_with` even though the result is discarded. `tracing` caches
        // each callsite's `Interest` on its first hit, so a callsite first touched under the
        // ambient dispatcher can be cached as "never interested" and stay invisible to a
        // later scoped capture. Every touch has to happen inside a real subscriber.
        let _ = capture_with(|| {
            correct(&cfg, ID, &overlay, None).unwrap();
        });
        assert_eq!(
            load(&overlays_subdir(&cfg.service.override_dir_resolved())).get(ID),
            Some(&overlay)
        );

        let _ = capture_with(|| {
            reset(&cfg, ID).unwrap();
        });
        assert!(
            load(&overlays_subdir(&cfg.service.override_dir_resolved()))
                .get(ID)
                .is_none()
        );
    }

    #[test]
    fn correct_emits_a_metadata_overlay_set_audit_line() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_with_override_dir(dir.path());
        let overlay = overlay_from_fields(&["title=Corrected".to_owned()]).unwrap();
        let out = capture_with(|| {
            correct(&cfg, ID, &overlay, Some("provider mislabeled the cohort")).unwrap();
        });
        assert!(out.contains("\"event\":\"metadata_overlay_set\""), "{out}");
        assert!(
            out.contains("provider mislabeled the cohort"),
            "the --reason must be recorded in the audit line: {out}"
        );
        assert!(
            out.contains("\"actor\":\"operator\""),
            "the file-writer is the operator actor: {out}"
        );
    }

    #[test]
    fn reset_emits_a_metadata_overlay_cleared_audit_line() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_with_override_dir(dir.path());
        let out = capture_with(|| {
            reset(&cfg, ID).unwrap();
        });
        assert!(
            out.contains("\"event\":\"metadata_overlay_cleared\""),
            "{out}"
        );
        assert!(
            out.contains("\"actor\":\"operator\""),
            "the file-writer is the operator actor: {out}"
        );
    }
}
