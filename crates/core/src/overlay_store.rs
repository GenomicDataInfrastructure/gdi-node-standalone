//! Operator metadata overlay: durable persistence and the apply/revert/hydrate
//! orchestration shared by the inbox and S3 reconcile paths.
//!
//! The operator drops `{id}.metadata.json` (a [`MetadataOverlay`] patch) into the
//! inbox or S3 bucket. On reconcile the node merges it over the *pristine*
//! `datasets/{id}/manifest.json`, re-validates the result, and — if valid — writes
//! a durable `datasets/{id}/.metadata.overlay.json` ([`AppliedOverlay`]: the patch
//! plus a node-stamped `applied_at`). The durable file is the record of what is
//! applied; the cache holds the merged metadata with `applied_at` as its
//! `dct:modified`. Removing the operator sidecar reverts to baseline.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::BorrowedFormatItem;
use time::macros::format_description;

use crate::error::{CoreError, CoreResult};
use crate::model::{Manifest, ManifestMetadata, MetadataOverlay};
use crate::validate_pkg::validate_overlay_result;

pub use crate::s3_layout::OVERLAY_SUFFIX;

/// The node-written durable copy, under `datasets/{id}/`.
pub const DURABLE_OVERLAY_NAME: &str = ".metadata.overlay.json";

/// The node-written durable "modified high-water mark", under `datasets/{id}/`.
///
/// Records the latest `applied_at` ever stamped for the dataset. Unlike the overlay
/// itself, it is **not** removed on [`revert`], so the dataset's `dct:modified` never
/// moves backward when an overlay is reverted — a backward `dct:modified` can make an
/// incremental harvester skip a genuine change. Orthogonal to the overlay file, so it
/// never affects overlay *presence* (visibility/reconcile keys off [`read_durable`]).
pub const MODIFIED_HWM_NAME: &str = ".metadata.modified";

/// Fixed-width xsd:dateTime format: `YYYY-MM-DDTHH:MM:SS.mmmZ`.
///
/// Every node-stamped timestamp uses it, so lexicographic order is chronological order.
/// The `dct:modified` monotonicity guard and the `.max()` comparisons in the FDP metadata
/// path depend on that.
static XSD_DATETIME_FORMAT: &[BorrowedFormatItem<'static>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z");

/// The durable applied-overlay record persisted under `datasets/{id}/`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedOverlay {
    /// Node-stamped apply time (xsd:dateTime) → the dataset's `dct:modified`.
    pub applied_at: String,
    /// The validated operator patch.
    pub patch: MetadataOverlay,
}

/// What an [`apply`] changed relative to the previously-applied patch.
///
/// Field names only, plus the before/after of `access_rights`, not the whole patch. Every
/// other overlay field is DCAT metadata the FDP already publishes, so copying values into
/// the audit stream adds a second copy of record without adding evidence. `access_rights`
/// is the exception: its value (`PUBLIC` / `RESTRICTED` / `NON_PUBLIC`) is a disclosure
/// control, it is a short enum rather than free text, and the transition cannot be
/// reconstructed once the operator's override file is overwritten.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OverlayChange {
    /// Names of the fields whose value differs from the previously-applied patch, in
    /// declaration order. Empty when the patch is unchanged (an idempotent re-apply).
    pub changed_fields: Vec<&'static str>,
    /// `access_rights` as previously applied. `None` when it did not change, or when
    /// there was no prior patch.
    pub access_rights_before: Option<String>,
    /// `access_rights` after this apply. `None` when it did not change.
    pub access_rights_after: Option<String>,
}

/// Diff `next` against the previously-applied `prior` patch.
///
/// See [`OverlayChange`] for why this reports field names rather than values, and why
/// `access_rights` is the one exception.
#[must_use]
pub fn overlay_change(prior: Option<&MetadataOverlay>, next: &MetadataOverlay) -> OverlayChange {
    let baseline = MetadataOverlay::default();
    let prior = prior.unwrap_or(&baseline);
    let mut changed_fields = Vec::new();
    // Exhaustiveness guard: a new overlay field has to be a decision about whether its
    // name belongs in the audit trail. A field missing from the comparison below yields
    // `changed_fields: []`, the audit line is then skipped, and a correction leaves no
    // record. No `..` rest pattern, so a new field fails to compile until it is decided.
    let MetadataOverlay {
        title: _,
        description: _,
        access_rights: _,
        applicable_legislation: _,
        license: _,
        creator: _,
        health_category: _,
        keywords: _,
        number_of_unique_individuals: _,
        conforms_to: _,
        type_: _,
        legal_basis: _,
        is_referenced_by: _,
        other_identifier: _,
        contact_point: _,
    } = next;
    if prior.title != next.title {
        changed_fields.push("title");
    }
    if prior.description != next.description {
        changed_fields.push("description");
    }
    if prior.access_rights != next.access_rights {
        changed_fields.push("access_rights");
    }
    if prior.applicable_legislation != next.applicable_legislation {
        changed_fields.push("applicable_legislation");
    }
    if prior.license != next.license {
        changed_fields.push("license");
    }
    if prior.creator != next.creator {
        changed_fields.push("creator");
    }
    if prior.health_category != next.health_category {
        changed_fields.push("health_category");
    }
    if prior.keywords != next.keywords {
        changed_fields.push("keywords");
    }
    if prior.number_of_unique_individuals != next.number_of_unique_individuals {
        changed_fields.push("number_of_unique_individuals");
    }
    if prior.conforms_to != next.conforms_to {
        changed_fields.push("conforms_to");
    }
    if prior.type_ != next.type_ {
        changed_fields.push("type");
    }
    if prior.legal_basis != next.legal_basis {
        changed_fields.push("legal_basis");
    }
    if prior.is_referenced_by != next.is_referenced_by {
        changed_fields.push("is_referenced_by");
    }
    if prior.other_identifier != next.other_identifier {
        changed_fields.push("other_identifier");
    }
    if prior.contact_point != next.contact_point {
        changed_fields.push("contact_point");
    }

    let access_changed = prior.access_rights != next.access_rights;
    OverlayChange {
        changed_fields,
        access_rights_before: access_changed
            .then(|| prior.access_rights.clone())
            .flatten(),
        access_rights_after: access_changed.then(|| next.access_rights.clone()).flatten(),
    }
}

/// The outcome of a successful [`apply`].
#[derive(Debug, Clone)]
pub struct Applied {
    /// The merged metadata (baseline with overlay applied).
    pub metadata: ManifestMetadata,
    /// The node-stamped apply time (xsd:dateTime), reused if the patch was unchanged.
    pub applied_at: String,
    /// Non-fatal validation warnings from the merged result.
    pub warnings: Vec<String>,
    /// What this apply changed relative to the previously-applied patch. Empty on an
    /// idempotent re-apply, so a caller can emit an audit line only for a real correction.
    pub change: OverlayChange,
}

/// Current UTC time as `YYYY-MM-DDTHH:MM:SS.mmmZ`.
///
/// The fixed-width millisecond format makes lexicographic ordering chronological, which
/// the monotonicity guard in [`apply`] and the FDP-root `dct:modified` comparison rely on.
#[must_use]
pub fn now_xsd_datetime() -> String {
    let now = OffsetDateTime::now_utc();
    now.format(XSD_DATETIME_FORMAT)
        .unwrap_or_else(|_| format!("{}Z", now.unix_timestamp()))
}

fn dataset_dir(data_dir: &Path, id: &str) -> PathBuf {
    data_dir.join(id)
}

/// Read the pristine baseline metadata from `datasets/{id}/manifest.json`.
///
/// # Errors
///
/// Returns [`CoreError::Io`] if the file is missing or unreadable, or
/// [`CoreError::InvalidConfig`] if it cannot be parsed as a valid manifest.
pub fn load_baseline(data_dir: &Path, id: &str) -> CoreResult<ManifestMetadata> {
    let path = dataset_dir(data_dir, id).join("manifest.json");
    let raw = std::fs::read(&path).map_err(CoreError::Io)?;
    let manifest: Manifest =
        serde_json::from_slice(&raw).map_err(|e| CoreError::InvalidConfig {
            detail: format!("manifest.json for {id} is not valid: {e}"),
        })?;
    Ok(manifest.metadata)
}

fn durable_path(data_dir: &Path, id: &str) -> PathBuf {
    dataset_dir(data_dir, id).join(DURABLE_OVERLAY_NAME)
}

fn hwm_path(data_dir: &Path, id: &str) -> PathBuf {
    dataset_dir(data_dir, id).join(MODIFIED_HWM_NAME)
}

/// Read the persisted modified high-water mark for `id`, if present and non-empty.
///
/// A fixed-width `YYYY-MM-DDTHH:MM:SS.mmmZ` xsd:dateTime whose lexical order tracks
/// chronological order (so callers compare it with `>`/`.max()` directly).
#[must_use]
pub fn read_modified_hwm(data_dir: &Path, id: &str) -> Option<String> {
    let raw = std::fs::read_to_string(hwm_path(data_dir, id)).ok()?;
    let ts = raw.trim();
    if ts.is_empty() {
        None
    } else {
        Some(ts.to_owned())
    }
}

/// Persist `ts` as the modified high-water mark (crash-safe: tmp -> fsync -> rename).
fn write_modified_hwm(data_dir: &Path, id: &str, ts: &str) -> CoreResult<()> {
    crate::util::write_durable_atomic_private(&hwm_path(data_dir, id), ts.as_bytes())
        .map_err(CoreError::Io)
}

/// Read the durable applied-overlay for `id`, if one exists and parses cleanly.
///
/// Returns `None` if the file is absent or unparseable (treated as no overlay). A
/// present-but-corrupt file is logged at `warn` before falling back to baseline, so a
/// silently-reverted overlay is diagnosable. A read error on a present file is not logged.
#[must_use]
pub fn read_durable(data_dir: &Path, id: &str) -> Option<AppliedOverlay> {
    let raw = std::fs::read(durable_path(data_dir, id)).ok()?;
    match serde_json::from_slice(&raw) {
        Ok(overlay) => Some(overlay),
        Err(err) => {
            tracing::warn!(
                dataset = id,
                error = %err,
                "durable metadata overlay is present but unparseable; serving baseline metadata"
            );
            None
        }
    }
}

/// Persist the durable applied-overlay record for `id`. The write half of
/// [`read_durable`].
fn write_durable(data_dir: &Path, id: &str, applied: &AppliedOverlay) -> CoreResult<()> {
    let json = serde_json::to_vec_pretty(applied).map_err(|e| CoreError::InternalError {
        detail: format!("serializing applied overlay: {e}"),
    })?;
    // Crash-safe: tmp (`{DURABLE_OVERLAY_NAME}.tmp`) -> fsync -> rename -> dir fsync, so
    // a power loss right after `apply()` can never leave a torn overlay that
    // `reconcile_overlay_reverts` would then read back as authoritative visibility.
    crate::util::write_durable_atomic_private(&durable_path(data_dir, id), &json)
        .map_err(CoreError::Io)
}

/// Merge `patch` over the pristine baseline, validate the result, and persist
/// the durable overlay atomically.
///
/// If a durable overlay already exists with an identical patch, its `applied_at`
/// is reused (idempotent: restart or re-scan does not move `dct:modified`).
/// Otherwise a fresh monotonic `applied_at` is stamped. The durable file is left
/// untouched if validation fails.
///
/// # Errors
///
/// Returns [`CoreError`] if the baseline is unreadable, the merged metadata fails
/// gdi-metadata validation, or the durable file cannot be written.
pub fn apply(data_dir: &Path, id: &str, patch: &MetadataOverlay) -> CoreResult<Applied> {
    let mut metadata = load_baseline(data_dir, id)?;
    metadata.apply_overlay(patch);
    // Validate before writing: the durable file must be left untouched on error. Only the
    // warning class travels on, since the report's notes describe a valid configuration.
    let warnings = validate_overlay_result(&metadata)?.warnings;

    // Reuse the prior stamp when the patch is unchanged (idempotent), and guard
    // monotonicity for a changed patch so wall-clock skew never moves time backwards.
    // Fixed-width `…mmmZ` stamps compare lexicographically as chronologically, so `max` is
    // the monotonicity guard. Read once: the previously-applied patch is both the
    // idempotency check and the only place the pre-correction state still exists, because
    // the operator's override file is already overwritten by the time the node applies it.
    let previous = read_durable(data_dir, id);
    let change = overlay_change(previous.as_ref().map(|p| &p.patch), patch);
    let applied_at = match previous {
        Some(prev) if &prev.patch == patch => prev.applied_at,
        Some(prev) => now_xsd_datetime().max(prev.applied_at),
        None => now_xsd_datetime(),
    };
    // Floor against the persisted modified high-water mark so `dct:modified` never
    // regresses, including across a prior revert (whose mark survives the overlay delete)
    // and under wall-clock skew after the overlay was removed.
    let applied_at = match read_modified_hwm(data_dir, id) {
        Some(hwm) => applied_at.max(hwm),
        None => applied_at,
    };
    // Seed the floor from the dataset's baseline `dct:modified`, derived from the id's
    // build-epoch timestamp, so the first correction (before any mark exists) cannot move
    // `dct:modified` below the served baseline. This bites on a future-dated dataset: a
    // correction stamped "now" would otherwise regress a 2099 id. `--build-epoch` rejects
    // a future epoch for new builds; this covers datasets built without that check.
    let applied_at = match crate::datetime::dataset_datetime(id) {
        Some(baseline) if baseline > applied_at => baseline,
        _ => applied_at,
    };

    write_durable(
        data_dir,
        id,
        &AppliedOverlay {
            applied_at: applied_at.clone(),
            patch: patch.clone(),
        },
    )?;
    // Advance the high-water mark after the overlay is durable. If this write fails, the
    // overlay's own `applied_at` still floors a later hydrate (see `merged_for_hydrate`),
    // so the timestamp never regresses, and a retry re-establishes the mark.
    write_modified_hwm(data_dir, id, &applied_at)?;
    Ok(Applied {
        metadata,
        applied_at,
        warnings,
        change,
    })
}

/// Delete the durable overlay and return the pristine baseline metadata plus the
/// retained modified high-water mark.
///
/// A missing durable file is not an error: revert is idempotent. The modified high-water
/// mark is **kept**, because reverting to baseline content is itself a change and
/// `dct:modified` must not fall back below the last applied time. The caller surfaces the
/// returned `Option<String>` as the entry's `metadata_modified`.
///
/// # Errors
///
/// Returns [`CoreError::Io`] if the durable file exists but cannot be removed,
/// or if the baseline manifest is unreadable.
pub fn revert(data_dir: &Path, id: &str) -> CoreResult<(ManifestMetadata, Option<String>)> {
    let path = durable_path(data_dir, id);
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(CoreError::Io(e)),
    }
    let hwm = read_modified_hwm(data_dir, id);
    let baseline = load_baseline(data_dir, id)?;
    Ok((baseline, hwm))
}

/// Apply the durable overlay (if any) to a baseline during cache hydration.
///
/// No clock and no re-validation: the durable overlay was validated when applied. Returns
/// the merged metadata and the `metadata_modified` override. That override is the
/// persisted high-water mark (`>=` any `applied_at`, and it survives a revert), or the
/// durable `applied_at` when the mark is absent after a torn write, or `None` when neither
/// is present.
#[must_use]
pub fn merged_for_hydrate(
    data_dir: &Path,
    id: &str,
    mut baseline: ManifestMetadata,
) -> (ManifestMetadata, Option<String>) {
    let hwm = read_modified_hwm(data_dir, id);
    match read_durable(data_dir, id) {
        Some(applied) => {
            baseline.apply_overlay(&applied.patch);
            (baseline, Some(hwm.unwrap_or(applied.applied_at)))
        }
        None => (baseline, hwm),
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap permitted in tests")]
    use super::*;

    /// An auditor needs the shape of a correction (which fields moved) plus the
    /// before/after of `access_rights`, the one overlay field that is a disclosure control
    /// rather than published descriptive text.
    #[test]
    fn overlay_change_names_changed_fields_and_tracks_access_rights() {
        let prior = MetadataOverlay {
            license: Some("https://example.org/lic-a".to_owned()),
            access_rights: Some("RESTRICTED".to_owned()),
            ..MetadataOverlay::default()
        };
        let next = MetadataOverlay {
            license: Some("https://example.org/lic-b".to_owned()),
            access_rights: Some("PUBLIC".to_owned()),
            ..MetadataOverlay::default()
        };

        let change = overlay_change(Some(&prior), &next);

        assert_eq!(change.changed_fields, vec!["access_rights", "license"]);
        assert_eq!(change.access_rights_before.as_deref(), Some("RESTRICTED"));
        assert_eq!(change.access_rights_after.as_deref(), Some("PUBLIC"));
    }

    /// A re-apply of the identical patch must not look like a correction, or the
    /// idempotent reconcile would flood the audit trail with no-op "changed" lines.
    #[test]
    fn overlay_change_on_an_unchanged_patch_is_empty() {
        let p = MetadataOverlay {
            license: Some("https://example.org/lic-a".to_owned()),
            access_rights: Some("PUBLIC".to_owned()),
            ..MetadataOverlay::default()
        };

        let change = overlay_change(Some(&p), &p);

        assert!(change.changed_fields.is_empty());
        assert!(change.access_rights_before.is_none());
        assert!(change.access_rights_after.is_none());
    }

    /// The first correction has no prior patch: every field it sets is a change, and
    /// `access_rights_before` is genuinely absent rather than an empty string.
    #[test]
    fn overlay_change_against_no_prior_names_every_set_field() {
        let next = MetadataOverlay {
            access_rights: Some("PUBLIC".to_owned()),
            ..MetadataOverlay::default()
        };

        let change = overlay_change(None, &next);

        assert_eq!(change.changed_fields, vec!["access_rights"]);
        assert_eq!(change.access_rights_before, None);
        assert_eq!(change.access_rights_after.as_deref(), Some("PUBLIC"));
    }
    use crate::model::{Agent, FileEntry, FileGroup};
    use crate::model::{
        Assembly, DatasetMode, Internal, LocalizedText, Manifest, ManifestConfig, ManifestMetadata,
    };
    use std::fs;

    const ID: &str = "GDI-EE-UTARTU-20260409143052837";

    /// Build the sample manifest (title `"COVID monogenic AFs"`), with minimal
    /// `files`/`internal`/`config` and no `payload`.
    ///
    /// `payload: None` is set explicitly: these tests exercise the overlay patch path,
    /// which must leave the payload section untouched.
    fn sample_manifest(id: &str) -> Manifest {
        Manifest {
            payload: None,
            metadata: ManifestMetadata {
                dataset_id: id.to_owned(),
                catalog: "gdi-aggregated".to_owned(),
                title: LocalizedText::Plain("COVID monogenic AFs".to_owned()),
                description: Some(LocalizedText::Plain("A description.".to_owned())),
                access_rights:
                    "http://publications.europa.eu/resource/authority/access-right/PUBLIC"
                        .to_owned(),
                applicable_legislation: vec![
                    "http://data.europa.eu/eli/reg/2018/1725/oj".to_owned(),
                ],
                license: "https://creativecommons.org/licenses/by/4.0/".to_owned(),
                creator: vec![Agent {
                    name: "University of Tartu".to_owned(),
                }],
                health_category: vec![
                    "http://data.gdi.eu/core/p2/HealthCategoryHumanGenomic".to_owned(),
                ],
                keywords: None,
                number_of_unique_individuals: None,
                conforms_to: None,
                type_: None,
                legal_basis: None,
                is_referenced_by: None,
                other_identifier: None,
                contact_point: None,
                number_of_records: Some(1),
                populations: None,
            },
            files: vec![FileGroup {
                category: "VCF".to_owned(),
                reference: Some("GRCh38".to_owned()),
                precise_reference: None,
                files: vec![FileEntry {
                    path: "covid.vcf".to_owned(),
                    sha256: Some("a".repeat(64)),
                    size: Some(123),
                    conversion: None,
                }],
            }],
            internal: Internal {
                internal_id: Some("secret-internal-id".to_owned()),
                ..Internal::default()
            },
            config: ManifestConfig {
                mode: DatasetMode::Aggregated,
                block_range: 10_000_000,
                af_source: None,
                af_source_reference: None,
                min_allele_count: 0,
                hide_lower_counts: None,
                assembly: Assembly {
                    reference: "GRCh38".to_owned(),
                },
                manifest_version: 1,
                generated_by: "test".to_owned(),
            },
        }
    }

    /// Writes a minimal valid `datasets/{id}/manifest.json`; returns the temp `data_dir`.
    fn data_dir_with_manifest() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let ds = dir.path().join(ID);
        fs::create_dir_all(&ds).unwrap();
        let manifest = sample_manifest(ID);
        fs::write(
            ds.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        dir
    }

    #[test]
    #[expect(
        clippy::string_slice,
        reason = "test fixture: the sliced strings are ASCII literals defined in this module"
    )]
    fn now_xsd_datetime_has_millisecond_z_shape() {
        let ts = now_xsd_datetime();
        // Must end with 'Z' and have the shape YYYY-MM-DDTHH:MM:SS.mmmZ (24 chars).
        assert!(ts.ends_with('Z'), "timestamp must end with Z: {ts}");
        assert_eq!(ts.len(), 24, "timestamp must be 24 chars: {ts}");
        // Basic structural checks.
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[7..8], "-");
        assert_eq!(&ts[10..11], "T");
        assert_eq!(&ts[19..20], ".");
    }

    #[test]
    fn apply_merges_validates_and_writes_durable() {
        let dir = data_dir_with_manifest();
        let patch: MetadataOverlay = serde_json::from_str(r#"{"title":"New title"}"#).unwrap();
        let out = apply(dir.path(), ID, &patch).unwrap();
        assert_eq!(
            out.metadata.title,
            LocalizedText::Plain("New title".to_owned())
        );
        assert!(out.applied_at.ends_with('Z'));
        // Durable file exists and round-trips.
        let durable = read_durable(dir.path(), ID).unwrap();
        assert_eq!(durable.patch, patch);
        assert_eq!(durable.applied_at, out.applied_at);
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    #[serial_test::serial(faults)]
    fn overlay_write_fault_keeps_last_good_and_converges_on_retry() {
        // A durable-write failure partway through `apply()` must leave the previous
        // durable overlay intact, never a torn or lost file that reconcile could read back
        // as authoritative, and must not be fatal to recovery: once the fault clears, a
        // retry converges to the new overlay. Arm on the unique tempdir path so no sibling
        // test's write can match.
        let dir = data_dir_with_manifest();
        let arm_key = dir.path().to_string_lossy().into_owned();
        let good: MetadataOverlay = serde_json::from_str(r#"{"title":"Good"}"#).unwrap();
        let next: MetadataOverlay = serde_json::from_str(r#"{"title":"Next"}"#).unwrap();

        // Establish a last-good durable overlay.
        let first = apply(dir.path(), ID, &good).unwrap();
        assert_eq!(read_durable(dir.path(), ID).unwrap().patch, good);

        // Arm the durable-write fault, then apply a different overlay: the write must fail.
        {
            let _g =
                crate::faults::arm_enospc(crate::faults::FaultPoint::DurableWrite, &arm_key, 1);
            let err = apply(dir.path(), ID, &next).unwrap_err();
            std::assert_matches!(err, CoreError::Io(_), "got {err:?}");
        }
        // The previous durable overlay is untouched (last-good preserved).
        let after_fault = read_durable(dir.path(), ID).unwrap();
        assert_eq!(
            after_fault.patch, good,
            "a failed overlay write must keep the last-good overlay"
        );
        assert_eq!(after_fault.applied_at, first.applied_at);

        // The fault has cleared (guard dropped): a retry converges to the new overlay.
        apply(dir.path(), ID, &next).unwrap();
        assert_eq!(
            read_durable(dir.path(), ID).unwrap().patch,
            next,
            "a retry after the fault clears must converge to the new overlay"
        );
    }

    #[test]
    fn a_correction_on_a_future_dated_dataset_does_not_regress_modified() {
        // A dataset whose id embeds a future build-epoch serves that time as
        // `dct:modified`. The first correction stamps `applied_at` at "now", which without
        // the baseline floor would move `dct:modified` backward and break a harvester's
        // incremental sync. The seed holds it at the baseline.
        let future_id = "GDI-EE-UTARTU-20990101000000000";
        let dir = tempfile::tempdir().unwrap();
        let ds = dir.path().join(future_id);
        fs::create_dir_all(&ds).unwrap();
        fs::write(
            ds.join("manifest.json"),
            serde_json::to_vec(&sample_manifest(future_id)).unwrap(),
        )
        .unwrap();

        let baseline = crate::datetime::dataset_datetime(future_id).expect("valid id datetime");
        let patch: MetadataOverlay = serde_json::from_str(r#"{"title":"Corrected"}"#).unwrap();
        let applied = apply(dir.path(), future_id, &patch).unwrap();
        assert!(
            applied.applied_at >= baseline,
            "a correction must not move dct:modified below the future baseline: applied={} baseline={}",
            applied.applied_at,
            baseline,
        );
    }

    #[test]
    fn apply_is_stable_for_an_unchanged_patch() {
        let dir = data_dir_with_manifest();
        let patch: MetadataOverlay = serde_json::from_str(r#"{"title":"T"}"#).unwrap();
        let first = apply(dir.path(), ID, &patch).unwrap();
        let again = apply(dir.path(), ID, &patch).unwrap();
        assert_eq!(
            first.applied_at, again.applied_at,
            "unchanged patch keeps applied_at"
        );
    }

    #[test]
    fn apply_with_a_changed_patch_advances_or_holds_applied_at() {
        let dir = data_dir_with_manifest();
        let a: MetadataOverlay = serde_json::from_str(r#"{"title":"A title"}"#).unwrap();
        let b: MetadataOverlay = serde_json::from_str(r#"{"title":"B title"}"#).unwrap();
        let first = apply(dir.path(), ID, &a).unwrap();
        let second = apply(dir.path(), ID, &b).unwrap();
        // This establishes that a changed patch replaces the durable record and never
        // moves the stamp backward. It is not a strict-advancement assertion: the two
        // applies are microseconds apart. Strict advancement is covered by
        // `changed_patch_advances_applied_at_from_a_past_stamp`, and the future-skew hold
        // by `changed_patch_holds_a_future_applied_at_against_clock_skew`.
        assert!(
            second.applied_at >= first.applied_at,
            "applied_at must never regress: first={} second={}",
            first.applied_at,
            second.applied_at,
        );
        let durable = read_durable(dir.path(), ID).unwrap();
        assert_eq!(
            durable.patch, b,
            "the changed patch replaces the durable one"
        );
        assert_eq!(
            durable.applied_at, second.applied_at,
            "the returned stamp is the one persisted"
        );
    }

    #[test]
    fn changed_patch_holds_a_future_applied_at_against_clock_skew() {
        let dir = data_dir_with_manifest();
        // Seed a durable overlay stamped far in the future, as wall-clock skew would,
        // then apply a different patch. `now < future`, so the monotonicity guard must
        // hold the future stamp rather than move it backward.
        let future = "2999-01-01T00:00:00.000Z".to_owned();
        let seed: MetadataOverlay = serde_json::from_str(r#"{"title":"Seed"}"#).unwrap();
        write_durable(
            dir.path(),
            ID,
            &AppliedOverlay {
                applied_at: future.clone(),
                patch: seed,
            },
        )
        .unwrap();

        let changed: MetadataOverlay = serde_json::from_str(r#"{"title":"Changed"}"#).unwrap();
        let out = apply(dir.path(), ID, &changed).unwrap();
        assert_eq!(
            out.applied_at, future,
            "a changed patch must not move applied_at backward under clock skew"
        );
        let durable = read_durable(dir.path(), ID).unwrap();
        assert_eq!(durable.applied_at, future);
        assert_eq!(durable.patch, changed);
    }

    #[test]
    fn changed_patch_advances_applied_at_from_a_past_stamp() {
        // With a durable overlay stamped in the past, applying a different patch must
        // advance `applied_at` to "now", taking the monotonic branch. The seeded stamp is
        // fixed rather than "just now", so the result is deterministic.
        let dir = data_dir_with_manifest();
        // Above the id-derived baseline (`GDI-EE-UTARTU-20260409143052837` is
        // 2026-04-09T14:30:52.837Z) and below `now`. A seed below that baseline would not
        // isolate the monotonic branch, because the `dataset_datetime` floor would push
        // the result up to the baseline regardless.
        let past = "2026-05-01T00:00:00.000Z".to_owned();
        let seed: MetadataOverlay = serde_json::from_str(r#"{"title":"Seed"}"#).unwrap();
        write_durable(
            dir.path(),
            ID,
            &AppliedOverlay {
                applied_at: past.clone(),
                patch: seed,
            },
        )
        .unwrap();

        let changed: MetadataOverlay = serde_json::from_str(r#"{"title":"Changed"}"#).unwrap();
        let out = apply(dir.path(), ID, &changed).unwrap();
        // Fixed-width millisecond-Z stamps compare lexicographically as chronologically.
        assert!(
            out.applied_at > past,
            "a changed patch over a past stamp must advance applied_at: got {} vs seed {past}",
            out.applied_at,
        );
        let durable = read_durable(dir.path(), ID).unwrap();
        assert!(
            durable.applied_at > past,
            "the persisted stamp must also have advanced"
        );
        assert_eq!(durable.patch, changed);
    }

    #[test]
    fn apply_rejects_an_invalid_merge() {
        let dir = data_dir_with_manifest();
        let patch: MetadataOverlay = serde_json::from_str(r#"{"title":""}"#).unwrap();
        assert!(apply(dir.path(), ID, &patch).is_err());
        assert!(
            read_durable(dir.path(), ID).is_none(),
            "no durable file on reject"
        );
    }

    #[test]
    fn revert_removes_durable_and_returns_baseline() {
        let dir = data_dir_with_manifest();
        let patch: MetadataOverlay = serde_json::from_str(r#"{"title":"X"}"#).unwrap();
        apply(dir.path(), ID, &patch).unwrap();
        let (base, _hwm) = revert(dir.path(), ID).unwrap();
        assert_eq!(
            base.title,
            LocalizedText::Plain("COVID monogenic AFs".to_owned())
        );
        assert!(read_durable(dir.path(), ID).is_none());
    }

    #[test]
    fn revert_is_idempotent_when_no_durable_overlay_exists() {
        // A dataset with a manifest but no durable overlay reverts cleanly to the
        // pristine baseline: a missing durable file is idempotent, because the
        // `ErrorKind::NotFound` from `remove_file` is swallowed rather than propagated.
        let dir = data_dir_with_manifest();
        assert!(
            read_durable(dir.path(), ID).is_none(),
            "precondition: no durable overlay present"
        );
        let (base, hwm) =
            revert(dir.path(), ID).expect("revert with no overlay must be Ok(baseline)");
        assert_eq!(
            base.title,
            LocalizedText::Plain("COVID monogenic AFs".to_owned())
        );
        assert_eq!(
            hwm, None,
            "a dataset that never had an overlay has no modified high-water mark"
        );
    }

    #[test]
    fn merged_for_hydrate_applies_durable() {
        let dir = data_dir_with_manifest();
        let patch: MetadataOverlay = serde_json::from_str(r#"{"title":"H"}"#).unwrap();
        let applied = apply(dir.path(), ID, &patch).unwrap();
        let base = load_baseline(dir.path(), ID).unwrap();
        let (merged, modified) = merged_for_hydrate(dir.path(), ID, base);
        assert_eq!(merged.title, LocalizedText::Plain("H".to_owned()));
        assert_eq!(modified, Some(applied.applied_at));
    }

    #[test]
    fn revert_preserves_the_modified_high_water_mark() {
        // Reverting an overlay must not let `dct:modified` fall back to the older
        // baseline time: the last `applied_at` survives as a high-water mark, so an
        // incremental harvester never sees the timestamp regress.
        let dir = data_dir_with_manifest();
        let patch: MetadataOverlay = serde_json::from_str(r#"{"title":"X"}"#).unwrap();
        let applied = apply(dir.path(), ID, &patch).unwrap();

        let (base, hwm) = revert(dir.path(), ID).unwrap();
        assert_eq!(
            base.title,
            LocalizedText::Plain("COVID monogenic AFs".to_owned()),
            "revert restores baseline CONTENT"
        );
        assert_eq!(
            hwm.as_deref(),
            Some(applied.applied_at.as_str()),
            "revert must return the retained modified high-water mark, not None"
        );
        // The mark is durable: a hydrate after the revert still surfaces it, so a restart
        // does not regress `dct:modified` either.
        assert!(
            read_durable(dir.path(), ID).is_none(),
            "the overlay file itself is gone after revert"
        );
        let baseline = load_baseline(dir.path(), ID).unwrap();
        let (_m, modified) = merged_for_hydrate(dir.path(), ID, baseline);
        assert_eq!(
            modified,
            Some(applied.applied_at),
            "hydrate after revert must serve the high-water mark as dct:modified"
        );
    }

    #[test]
    fn apply_floors_applied_at_against_the_retained_hwm_after_revert() {
        // After a revert leaves a future-stamped high-water mark, a fresh apply whose
        // wall-clock stamp is earlier must be floored to the mark.
        let dir = data_dir_with_manifest();
        let future = "2999-01-01T00:00:00.000Z";
        write_durable(
            dir.path(),
            ID,
            &AppliedOverlay {
                applied_at: future.to_owned(),
                patch: serde_json::from_str(r#"{"title":"Seed"}"#).unwrap(),
            },
        )
        .unwrap();
        write_modified_hwm(dir.path(), ID, future).unwrap();

        // Revert removes the overlay but keeps the (future) mark.
        let (_b, hwm) = revert(dir.path(), ID).unwrap();
        assert_eq!(hwm.as_deref(), Some(future));

        // A new apply, stamped ~now (< future), must be floored to the retained mark.
        let patch: MetadataOverlay = serde_json::from_str(r#"{"title":"New"}"#).unwrap();
        let out = apply(dir.path(), ID, &patch).unwrap();
        assert_eq!(
            out.applied_at, future,
            "apply after revert must floor applied_at to the retained high-water mark"
        );
        assert_eq!(read_modified_hwm(dir.path(), ID).as_deref(), Some(future));
    }

    #[test]
    fn read_durable_ignores_a_stray_partial_tmp() {
        // A crash between the temp write and the atomic rename leaves a truncated
        // `{DURABLE_OVERLAY_NAME}.tmp` beside the valid durable file. The reader must
        // serve the valid durable content and never the stray `.tmp`.
        let dir = data_dir_with_manifest();
        let patch: MetadataOverlay = serde_json::from_str(r#"{"title":"Good"}"#).unwrap();
        let applied = apply(dir.path(), ID, &patch).unwrap();

        let stray = dir
            .path()
            .join(ID)
            .join(format!("{DURABLE_OVERLAY_NAME}.tmp"));
        fs::write(&stray, b"{ \"applied_at\": \"trunc").unwrap();

        let got = read_durable(dir.path(), ID).expect("the valid durable file still reads");
        assert_eq!(got.patch, patch);
        assert_eq!(got.applied_at, applied.applied_at);
        assert!(
            stray.is_file(),
            "the reader must not consume the stray .tmp (reaping is a separate concern)"
        );
    }

    #[test]
    fn read_durable_is_none_on_a_corrupt_durable_file() {
        // A torn write renamed into place, or on-disk corruption, leaves a malformed
        // durable file. `read_durable` tolerates it as no-overlay rather than propagating a
        // parse error, so hydration falls back to the pristine baseline.
        let dir = data_dir_with_manifest();
        let durable = dir.path().join(ID).join(DURABLE_OVERLAY_NAME);
        fs::write(
            &durable,
            b"{ \"applied_at\": \"2026-06-19T00:00:00.000Z\", \"pat",
        )
        .unwrap();

        assert!(
            read_durable(dir.path(), ID).is_none(),
            "a corrupt durable file is tolerated as None, not an error"
        );

        // merged_for_hydrate therefore serves the unchanged baseline with no
        // metadata_modified override.
        let base = load_baseline(dir.path(), ID).unwrap();
        let base_title = base.title.clone();
        let (merged, modified) = merged_for_hydrate(dir.path(), ID, base);
        assert_eq!(
            merged.title, base_title,
            "corrupt overlay => baseline served"
        );
        assert_eq!(
            modified, None,
            "corrupt overlay => no metadata_modified override"
        );
    }
}
