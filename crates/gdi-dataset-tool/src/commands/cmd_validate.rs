//! The `validate` command: run the shared structural gates on a local dataset
//! directory or a `.tar.c4gh` package, without producing output.
//!
//! `validate` runs the **same** Rust gates used at build and at service
//! ingestion: for a staging directory it runs `check_staging_dir` (member
//! safety) + the metadata gates over `manifest.json` (via the shared
//! `validate_package`) + `validate_parquet_dir`; for a `.tar.c4gh` it decrypts
//! with the provider identity, safe-extracts to a scratch dir beside the
//! package, then runs the same gates. Authoritative SHACL/HealthDCAT-AP
//! conformance is a CI concern, not this command.
//!
//! Each op's logic lives in a CLI-independent library function here; the CLI is a thin
//! wrapper.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use gdi_node_standalone_core::{
    extract::{ExtractBounds, check_staging_dir},
    model::{
        Manifest, PackageConfig, PackageFileEntry, PackageFileGroup, PackageMetadata, PackageYaml,
    },
    validate_parquet::{ParquetCaps, check_data_file_block_range, validate_parquet_dir},
    validate_pkg::validate_package_collect_all,
};

use crate::cli::{OutputFormat, ValidateArgs};
use crate::scratch::Scratch;
use crate::{ToolError, pkgio};

use crate::MANIFEST_NAME;

/// The collected outcome of validating a target: every problem found (not just the
/// first), plus warnings. Distinct from a `Result` so the CLI can report all
/// blocking errors in one pass (the linter ergonomic) — the node still gates on the
/// fail-fast `validate_package` at ingest, so this only diagnoses, never relaxes.
#[derive(Debug, Default)]
pub struct ValidateOutcome {
    /// Every blocking error found across the structural gates (empty ⇔ valid).
    pub errors: Vec<String>,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
}

impl ValidateOutcome {
    /// Whether the target passed (no blocking errors).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Fold a target-unusable failure into a reportable [`ValidateOutcome`] when the caller
/// asked for JSON, so `--format json` always emits its envelope.
///
/// A target that cannot be validated at all — a missing or unparseable `manifest.json`, a
/// decrypt failure, a path that is not a package — would otherwise exit non-zero having
/// printed nothing to stdout in JSON mode, the one shape a CI consumer cannot act on because
/// `jq` receives no input. It is also the likeliest failure this command sees, since a
/// malformed manifest is precisely what it exists to catch.
/// `cmd_deploy::wait_and_emit_verdict` holds the same rule for `deploy --wait`.
///
/// Such a failure is reported through the same envelope rather than a second channel: an
/// unusable target is a validation result, so it belongs in `errors` with `valid: false`.
/// Text mode is unchanged — a single `error:` line is already actionable there.
///
/// The exit code does not move: every [`validate_target`] failure is a `ToolError::user`
/// (the command is offline, so there is no transient/auth class to preserve), and the JSON
/// branch returns `Err` on `!is_valid()` regardless.
///
/// # Errors
///
/// Propagates the failure unchanged in text mode.
fn reportable_outcome(
    result: Result<ValidateOutcome, ToolError>,
    format: OutputFormat,
) -> Result<ValidateOutcome, ToolError> {
    match result {
        Ok(outcome) => Ok(outcome),
        Err(e) if format == OutputFormat::Json => Ok(ValidateOutcome {
            errors: vec![e.message],
            warnings: Vec::new(),
        }),
        Err(e) => Err(e),
    }
}

/// Run `validate`, reporting every problem found as text (default) or JSON.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) if the target cannot be validated at all (not
/// found, decrypt/extract failure, unreadable manifest), or if any blocking
/// validation error was found (the errors are reported first, in the chosen
/// format). Under `--format json` the envelope is printed to stdout first in both
/// cases, so a machine consumer always has something to parse.
pub fn run(
    args: &ValidateArgs,
    profile_name: Option<&str>,
    config_path: Option<&Path>,
) -> Result<(), ToolError> {
    let outcome = reportable_outcome(
        validate_target(&args.target, profile_name, config_path),
        args.format,
    )?;
    match args.format {
        OutputFormat::Json => {
            let json = serde_json::json!({
                "schemaVersion": 1,
                "target": args.target.display().to_string(),
                "valid": outcome.is_valid(),
                "errors": outcome.errors,
                "warnings": outcome.warnings,
            });
            // Pretty JSON to stdout (machine-readable; carries the full error list); the exit
            // code still signals pass/fail. Emitted through the shared chokepoint so `main`
            // knows a parseable object was already printed and does not add its error
            // envelope on top of it when this branch returns `Err` below.
            crate::output::emit_json(&json);
            if outcome.is_valid() {
                Ok(())
            } else {
                // The errors are in the JSON on stdout; a concise summary on stderr.
                Err(ToolError::user(format!(
                    "{} validation error(s) in {}",
                    outcome.errors.len(),
                    args.target.display()
                )))
            }
        }
        OutputFormat::Text => {
            for warning in &outcome.warnings {
                crate::output::always(&format!("warning: {warning}"));
            }
            if outcome.is_valid() {
                println!("ok: {} is a valid dataset", args.target.display());
                Ok(())
            } else {
                // Surface all collected errors in the returned message (one `; `-joined
                // line, which `main` prints as `error: …`) so a fixer sees every
                // problem in one pass instead of one-per-rerun.
                Err(ToolError::user(outcome.errors.join("; ")))
            }
        }
    }
}

/// Validate a staging directory or a `.tar.c4gh` package, collecting every problem.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) only when the target cannot be validated at all
/// (an unrecognised target, a decrypt/extract failure, or an unreadable manifest).
/// Per-field validation problems are returned inside the [`ValidateOutcome`], not as
/// an `Err`, so they can all be reported together.
pub fn validate_target(
    target: &Path,
    profile_name: Option<&str>,
    config_path: Option<&Path>,
) -> Result<ValidateOutcome, ToolError> {
    if target.is_dir() {
        crate::output::note(&format!(
            "validating dataset directory {}",
            target.display()
        ));
        return validate_dataset_dir(target, profile_name, config_path);
    }
    if target.is_file() {
        crate::output::note(&format!("validating package {}", target.display()));
        return validate_package_file(target, profile_name, config_path);
    }
    Err(ToolError::user(format!(
        "validate target not found (expected a staging directory or a .tar.c4gh): {}",
        target.display()
    )))
}

/// Decrypt + safe-extract a `.tar.c4gh` to a scratch dir, then validate it.
fn validate_package_file(
    package: &Path,
    profile_name: Option<&str>,
    config_path: Option<&Path>,
) -> Result<ValidateOutcome, ToolError> {
    let scratch = Scratch::new(package)?;
    let dest = scratch.path().join("extracted");
    #[expect(
        clippy::disallowed_methods,
        reason = "scratch below a Scratch root that is chmod 0o700 on creation"
    )]
    fs::create_dir_all(&dest)
        .map_err(|e| ToolError::user(format!("cannot create {}: {e}", dest.display())))?;
    crate::output::note(&format!(
        "decrypting + safe-extracting package into scratch {}",
        dest.display()
    ));

    pkgio::decrypt_and_extract_package(package, &dest, config_path)?;

    validate_dataset_dir(&dest, profile_name, config_path)
    // `scratch` (the extracted plaintext) is removed on drop.
}

/// Run the shared structural gates over a dataset directory: member safety, the
/// manifest metadata gates (collect-all), and the parquet gates — accumulating
/// every problem rather than stopping at the first.
fn validate_dataset_dir(
    dir: &Path,
    profile_name: Option<&str>,
    config_path: Option<&Path>,
) -> Result<ValidateOutcome, ToolError> {
    let mut outcome = ValidateOutcome::default();

    // 1. Member safety (same rule as service ingestion of a staging dir).
    crate::output::note("gate: member safety (check_staging_dir)");
    if let Err(e) = check_staging_dir(dir, &ExtractBounds::default()) {
        outcome.errors.push(e.to_string());
    }

    // 2. Metadata gates over manifest.json (shared with `build`). A missing /
    //    unparseable manifest is a hard precondition (we cannot validate at all).
    let manifest = load_manifest(dir)?;
    let package = manifest_to_package(&manifest);
    let declared_files: usize = package.files.iter().map(|g| g.files.len()).sum();
    crate::output::note(&format!(
        "gate: manifest metadata for {} ({} file group(s), {declared_files} declared file(s))",
        manifest.metadata.dataset_id,
        package.files.len()
    ));
    let catalogs = load_catalogs(profile_name, config_path);
    let full = validate_package_collect_all(&package, catalogs.as_ref());
    outcome
        .errors
        .extend(full.errors.iter().map(ToString::to_string));
    outcome.warnings.extend(full.warnings);

    // The node's ingest gate rejects an empty or non-canonical `config.assembly`
    // (`core::ingest`: "manifest config.assembly is empty" / "is not supported"), but
    // `validate_package` never looks at it — `manifest_to_package` drops the field
    // precisely because that gate does not read it. Without the check here the tool would
    // validate against a narrower contract than the node applies and green-light a package
    // ingest then rejects. Same reasoning as the `numberOfRecords` and `populations`
    // cross-checks below.
    let assembly = &manifest.config.assembly.reference;
    if assembly.is_empty() {
        outcome
            .errors
            .push("config.assembly is empty; the node rejects this at ingest".to_owned());
    } else if !gdi_node_standalone_core::chrom::is_known_assembly(assembly) {
        outcome.errors.push(format!(
            "config.assembly.reference {assembly:?} is not supported (expected GRCh37 or \
             GRCh38); the node rejects this at ingest"
        ));
    }

    // 3. Parquet gates (same self-check `build` runs).
    crate::output::note(&format!("gate: parquet files under {}", dir.display()));
    // Also cross-check the recount against the declared numberOfRecords: the node ingest
    // gate requires the field and rejects a mismatch, so `validate` must reject the same
    // package (else it green-lights an upload the node then fails). The count is already
    // computed by the parquet gate — bind it instead of discarding it.
    match validate_parquet_dir(dir, &ParquetCaps::default()) {
        Ok(scan) => {
            // The node cross-checks the advertised population set against the parquet at
            // ingest, exactly as it does `numberOfRecords`; report the same mismatch here.
            let declared: std::collections::BTreeSet<&str> = manifest
                .metadata
                .populations
                .iter()
                .flatten()
                .map(String::as_str)
                .collect();
            let observed: std::collections::BTreeSet<&str> =
                scan.populations.iter().map(String::as_str).collect();
            if manifest.metadata.populations.is_some() && declared != observed {
                outcome.errors.push(format!(
                    "metadata.populations {declared:?} != {observed:?} in the parquet data \
                     (the node rejects this mismatch at ingest)"
                ));
            }
            let counted = scan.distinct_variants;
            match manifest.metadata.number_of_records {
                Some(declared) if declared != counted => outcome.errors.push(format!(
                    "numberOfRecords ({declared}) != {counted} distinct variants in the parquet \
                     data (the node rejects this mismatch at ingest)"
                )),
                None => outcome
                    .errors
                    .push("numberOfRecords is required in the manifest but is absent".to_owned()),
                Some(_) => {}
            }
        }
        Err(e) => outcome.errors.push(e.to_string()),
    }
    // Parity with node ingest: each data file's filename blockRange must equal the
    // manifest's config.blockRange, else the serving node resolves no file for the block it
    // computes (Visible-but-unqueryable). `validate_parquet_dir` proves each row's POS falls
    // in its named block, but not that the name matches the manifest — check that here so
    // the tool rejects the same package the node would.
    if let Err(e) = check_data_file_block_range(dir, manifest.config.block_range) {
        outcome.errors.push(e.to_string());
    }

    crate::output::note(&format!(
        "validation complete: {} error(s), {} warning(s)",
        outcome.errors.len(),
        outcome.warnings.len()
    ));
    Ok(outcome)
}

/// Load `manifest.json` from a dataset directory.
///
/// Routed through [`gdi_node_standalone_core::ingest::read_manifest_bytes`], which applies
/// the same ceiling the node's ingest, `lint` and `diff` do, because it is the same function
/// rather than the same constant passed by hand.
///
/// `dir` is often a package an untrusted provider handed over, freshly extracted into
/// scratch under `ExtractBounds::default()`, whose `max_total_bytes` is 16 GiB. A 16 GiB
/// `manifest.json` is a legal member by that bound, and a bare `fs::read_to_string` would
/// slurp it whole and exhaust memory before a single gate ran.
fn load_manifest(dir: &Path) -> Result<Manifest, ToolError> {
    let path = dir.join(MANIFEST_NAME);
    let bytes = gdi_node_standalone_core::ingest::read_manifest_bytes(dir).map_err(|e| {
        // Discriminate the over-cap hit. Reporting every `read_capped` failure as "is not a
        // built dataset dir / .tar.c4gh package (no readable manifest.json)" would misname
        // the hostile-input case the cap exists to catch.
        if e.kind() == std::io::ErrorKind::InvalidData {
            // `read_capped` already formats this as "<path> exceeds the <cap>-byte cap",
            // so pass it through rather than prefixing the path a second time.
            ToolError::user(e.to_string())
        } else {
            ToolError::user(format!(
                "{} is not a built dataset dir / .tar.c4gh package (no readable manifest.json): {e}",
                dir.display()
            ))
        }
    })?;
    // Name the file: on the package route `dir` is a scratch extraction the user never
    // chose and cannot inspect, so a bare "manifest.json is not a valid manifest" would not
    // say which file failed.
    serde_json::from_slice(&bytes)
        .map_err(|e| ToolError::user(format!("{} is not a valid manifest: {e}", path.display())))
}

/// Load the active profile's catalog allow-list for membership checks, or
/// [`None`] offline / when no profile can be selected.
///
/// Profile selection is best-effort: `validate` is node-free and must stay usable
/// without a configured profile, so an unselectable profile (none configured,
/// ambiguous, etc.) yields [`None`] (structural-only validation) rather than an error.
fn load_catalogs(
    profile_name: Option<&str>,
    config_path: Option<&Path>,
) -> Option<BTreeMap<String, String>> {
    match crate::profile::load_active(config_path, profile_name) {
        Ok(active) if !active.catalogs.is_empty() => Some(active.catalogs),
        _ => None,
    }
}

/// Convert a generated [`Manifest`] into a [`PackageYaml`] so the shared
/// `validate_package` gates apply to it.
///
/// The two share the `metadata` / `files` / `internal` / `config` shape. The
/// manifest carries `datasetId` (not `prefix`/`org`) and the promoted
/// `config.assembly`; neither is checked by `validate_package`, so they are
/// dropped. `numberOfRecords` (manifest-only) is not carried into the
/// `PackageYaml`, so `validate_package` never sees it; it is re-validated
/// separately in `validate_dataset_dir` against the parquet distinct-variant
/// count.
fn manifest_to_package(m: &Manifest) -> PackageYaml {
    let md = &m.metadata;
    let metadata = PackageMetadata {
        // The manifest has a generated datasetId, not prefix/org; the gates here
        // do not look at prefix/org (those are checked at build), so leave them
        // empty.
        prefix: None,
        org: None,
        catalog: md.catalog.clone(),
        title: md.title.clone(),
        description: md.description.clone(),
        access_rights: md.access_rights.clone(),
        applicable_legislation: md.applicable_legislation.clone(),
        license: md.license.clone(),
        creator: md.creator.clone(),
        health_category: md.health_category.clone(),
        keywords: md.keywords.clone(),
        number_of_unique_individuals: md.number_of_unique_individuals,
        conforms_to: md.conforms_to.clone(),
        type_: md.type_.clone(),
        legal_basis: md.legal_basis.clone(),
        is_referenced_by: md.is_referenced_by.clone(),
        other_identifier: md.other_identifier.clone(),
        contact_point: md.contact_point.clone(),
    };

    let files = m
        .files
        .iter()
        .map(|g| PackageFileGroup {
            category: g.category.clone(),
            reference: g.reference.clone(),
            precise_reference: g.precise_reference.clone(),
            files: g
                .files
                .iter()
                .map(|f| PackageFileEntry::WithMeta {
                    path: f.path.clone(),
                    sha256: f.sha256.clone(),
                    size: f.size,
                })
                .collect(),
        })
        .collect();

    let c = &m.config;
    let config = PackageConfig {
        mode: c.mode,
        block_range: c.block_range,
        af_source: c.af_source.clone(),
        af_source_reference: c.af_source_reference.clone(),
        min_allele_count: c.min_allele_count,
        hide_lower_counts: c.hide_lower_counts,
    };

    PackageYaml {
        metadata,
        files,
        internal: m.internal.clone(),
        config,
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;
    use gdi_node_standalone_core::model::DatasetMode;

    #[test]
    fn missing_target_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("nope");
        let err = validate_target(&missing, None, None).unwrap_err();
        assert_eq!(err.exit_code, 1);
        assert!(err.message.contains("not found"), "msg: {}", err.message);
    }

    #[test]
    fn dir_without_manifest_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_target(tmp.path(), None, None).unwrap_err();
        assert_eq!(err.exit_code, 1);
        assert!(
            err.message.contains("manifest.json"),
            "msg: {}",
            err.message
        );
    }

    /// A minimal helper that exercises the manifest -> package conversion path.
    #[test]
    fn manifest_to_package_carries_metadata() {
        let m: Manifest = serde_json::from_str(
            r#"{
              "metadata": {
                "datasetId": "GDI-EE-UTARTU-20260409143052837",
                "catalog": "gdi-aggregated",
                "title": "T",
                "description": "D",
                "accessRights": "http://publications.europa.eu/resource/authority/access-right/PUBLIC",
                "applicableLegislation": ["http://data.europa.eu/eli/reg/2025/327/oj"],
                "license": "https://creativecommons.org/licenses/by/4.0/",
                "creator": [{"name": "C"}],
                "healthCategory": ["http://data.gdi.eu/core/p2/HealthCategoryHumanGenomic"],
                "numberOfRecords": 5
              },
              "files": [{"category": "VCF", "reference": "GRCh38",
                "files": [{"path": "a.vcf.gz", "sha256": "00", "size": 1}]}],
              "internal": {},
              "config": {"mode": "aggregated", "blockRange": 10000000,
                "assembly": {"reference": "GRCh38"}, "manifestVersion": 1,
                "generatedBy": "gdi-dataset-tool v0.1.0"}
            }"#,
        )
        .unwrap();
        let p = manifest_to_package(&m);
        assert_eq!(p.metadata.catalog, "gdi-aggregated");
        assert_eq!(p.metadata.applicable_legislation.len(), 1);
        assert_eq!(p.config.mode, DatasetMode::Aggregated);
        assert_eq!(p.files.len(), 1);
    }

    /// A target-unusable failure must still be reportable in JSON mode.
    ///
    /// Without the fold, `validate --format json` on a dir whose `manifest.json` is missing
    /// or unparseable exits 1 with empty stdout, so a `jq` consumer gets no input and cannot
    /// distinguish "the dataset is invalid" from "the tool broke". Folding the failure into
    /// the outcome is what lets the envelope print; assert the message survives into
    /// `errors`, not merely that some error is reported.
    #[test]
    fn a_target_unusable_failure_becomes_a_json_reportable_outcome() {
        let outcome = reportable_outcome(
            Err(ToolError::user(
                "cannot parse manifest.json: expected ident",
            )),
            OutputFormat::Json,
        )
        .expect("json mode must fold the failure into an outcome, not propagate it");
        assert!(
            !outcome.is_valid(),
            "an unusable target is not valid: {outcome:?}"
        );
        assert_eq!(
            outcome.errors,
            vec!["cannot parse manifest.json: expected ident".to_owned()],
            "the cause must survive verbatim into the envelope's errors"
        );
    }

    /// Text mode is left as it is: a single `error:` line is already actionable, and
    /// rerouting it through the outcome would drop the exit-code classification.
    #[test]
    fn text_mode_still_propagates_the_failure_unchanged() {
        let err = reportable_outcome(
            Err(ToolError::user("not a .tar.c4gh package")),
            OutputFormat::Text,
        )
        .expect_err("text mode must propagate");
        assert_eq!(err.message, "not a .tar.c4gh package");
        assert_eq!(err.exit_code, crate::EXIT_USER);
    }

    /// A successful validation is passed through in both formats — the fold must not
    /// manufacture an outcome when there was nothing wrong.
    #[test]
    fn a_successful_validation_passes_through_in_both_formats() {
        for format in [OutputFormat::Json, OutputFormat::Text] {
            let outcome = reportable_outcome(Ok(ValidateOutcome::default()), format)
                .expect("a valid target propagates");
            assert!(outcome.is_valid(), "{format:?} must stay valid");
            assert!(outcome.errors.is_empty(), "{format:?} must add no errors");
        }
    }
}
