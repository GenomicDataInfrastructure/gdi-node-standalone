//! The `build` command: convert a `package.yaml`'s VCF(s) into a validated
//! ingestible staging directory.
//!
//! Steps:
//! 1. Load the `package.yaml` and resolve relative file paths against its dir.
//! 2. Validate metadata (`validate_package`): print warnings/notes, fail on error.
//! 3. Resolve the country code (config < env < `--cc`).
//! 4. Generate the dataset ID from the real wall clock.
//! 5. Convert the first VCF group's VCFs into the staging dir through one build-wide
//!    `--jobs`-wide worker pool; verify distinct vcfids; single assembly. Then the
//!    post-conversion gates: reject an empty dataset, and honour `--strict`.
//! 6. Recount `numberOfRecords` — the distinct `(chr, POS, REF, ALT)` loci deduped
//!    (union) across the VCFs — from the written parquet via `validate_parquet_dir`,
//!    which validates it in the same pass. The per-VCF conversion counts then bound
//!    the result (`check_record_count_bounds`), keeping the check independent.
//! 7. Compute every source input file's sha256/size, build + write `manifest.json`.
//! 8. Write `headers/{vcfid}.vcf` (unless `--no-headers`).
//! 9. Self-check the scan's populations against the manifest, and the data files'
//!    filename blockRange.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io::{BufRead, BufReader, Read as _, Write as _};
use std::num::NonZero;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use gdi_node_standalone_core::{
    config::{Profile, ToolConfig},
    convert::{
        ConvertOptions, ConvertOutput, Diagnostic, MAX_POPULATIONS, Severity,
        convert_vcf_group as core_convert_vcf_group, partition_block_key, read_header_populations,
    },
    id::generate_dataset_id,
    model::{
        Assembly, ConversionStats, FileEntry, FileGroup, HeaderPolicy, Manifest, ManifestConfig,
        ManifestMetadata, PackageFileEntry, PackageFileGroup, PackageYaml,
        SUPPORTED_MANIFEST_VERSION,
    },
    validate_parquet::{
        ParquetCaps, ParquetScan, check_data_file_block_range, validate_parquet_dir,
    },
    validate_pkg::validate_package,
};

use crate::{ToolError, cli::BuildArgs};

/// The tool identity recorded in `config.generatedBy`. Derived from the crate
/// version at compile time so it can never silently drift from `--version` on a
/// release bump, which a hand-edited literal cannot guarantee.
const GENERATED_BY: &str = concat!("gdi-dataset-tool v", env!("CARGO_PKG_VERSION"));

/// Resolve the catalog allow-list used to validate `metadata.catalog` at build time.
///
/// Default (offline-friendly): the active profile's pinned `catalogs` allow-list (an
/// empty map when there is no profile / no pinned list — validation then falls back to
/// structural-only, since the node re-validates authoritatively at ingest).
///
/// With `refresh` (the `--refresh-catalogs` flag), prefer a live fetch from the node's
/// FDP root so the check reflects the node's current catalogs, falling back to the
/// pinned list (non-fatal) when the node is unreachable or the profile has no
/// `service_url` — a refresh must never turn an offline build into a hard failure.
fn resolve_catalogs(active: Option<&Profile>, refresh: bool) -> BTreeMap<String, String> {
    let pinned = active.map(|p| p.catalogs.clone()).unwrap_or_default();
    if !refresh {
        return pinned;
    }
    let Some(base) = active.and_then(|p| p.service_url.as_deref()) else {
        crate::output::warn(
            "warning: --refresh-catalogs: the active profile has no service_url; \
             using the pinned catalogs allow-list",
        );
        return pinned;
    };
    match crate::runtime::block_on(crate::catalogs::fetch_node_catalogs(base)) {
        // A refresh that succeeds but reports no catalogs must not silently disable the
        // check: the call site treats an empty allow-list as "validate structurally only",
        // which is weaker than what the operator asked for by passing the flag. Degrade
        // to the pinned list with a warning, exactly as the other two failure arms do.
        Ok(names) if names.is_empty() => {
            crate::output::warn(&format!(
                "warning: --refresh-catalogs: {base} reports no catalogs; \
                 using the pinned catalogs allow-list"
            ));
            pinned
        }
        Ok(names) => names.into_iter().map(|n| (n.clone(), n)).collect(),
        Err(e) => {
            crate::output::warn(&format!(
                "warning: --refresh-catalogs: catalog refresh from {base} failed ({}); \
                 falling back to the pinned catalogs allow-list",
                e.message
            ));
            pinned
        }
    }
}

/// How many diagnostics carry `severity`.
fn diagnostic_count(diagnostics: &[(String, Diagnostic)], severity: Severity) -> usize {
    diagnostics
        .iter()
        .filter(|(_, d)| d.severity == severity)
        .count()
}

/// The build timestamp: `--build-epoch` when pinned, otherwise the wall clock.
///
/// This is the build's only wall-clock read, so pinning it makes the generated
/// `datasetId` — and therefore `manifest.json` — a pure function of the inputs.
///
/// # Errors
///
/// Returns a [`ToolError`] when the system clock is before the Unix epoch.
fn resolve_build_epoch(args: &BuildArgs) -> Result<u64, ToolError> {
    match args.build_epoch {
        Some(pinned) => {
            let resolved = validate_pinned_epoch(pinned, now_unix_millis()?)?;
            // Pinning the epoch pins the dataset ID: the id is
            // `{prefix}-{cc}-{org}-{epoch}` and has no other varying part, so one epoch
            // reused across a batch from the same org mints one id for all of them. The
            // node keeps the first and discards the rest as immutable re-drops.
            //
            // A `note:`, not a `warning:`: warnings are reserved for something nothing in
            // the package asked for, and this is the declared consequence of a flag the
            // operator passed — a warning would also fail every reproducible
            // `build --strict`. Printed with a bare `eprintln!` like `deploy`/`upload`,
            // because `output::note` is `-v`-only and the batch operator will not pass `-v`.
            eprintln!(
                "note: --build-epoch pins the dataset ID as well as the manifest ({resolved} \
                 is now part of it). Pin it per dataset: reusing one epoch across a batch \
                 from the same org mints the same id for every one of them, and a node keeps \
                 only the first."
            );
            Ok(resolved)
        }
        None => now_unix_millis(),
    }
}

/// Clock-skew tolerance for a pinned `--build-epoch`: 24h, absorbing timezone mistakes and
/// NTP skew. A build-epoch further ahead than this is rejected.
const BUILD_EPOCH_FUTURE_SKEW_MS: u64 = 24 * 60 * 60 * 1000;

/// Validate a pinned `--build-epoch` (ms since the Unix epoch) against `now_ms`.
///
/// A future build date has no legitimate use: it forges `dct:issued`, which the FDP serves
/// verbatim, and breaks a harvester's `dct:modified` monotonicity, because correcting a
/// 2099-dated dataset moves `dct:modified` backward to now. A past epoch is fine, since
/// reproducible re-builds legitimately pin an old timestamp. This rejects only an epoch more
/// than 24h ahead of `now_ms` and passes any past or near-present value through unchanged.
///
/// # Errors
///
/// [`ToolError::user`] when `pinned` is more than [`BUILD_EPOCH_FUTURE_SKEW_MS`] ahead of `now_ms`.
fn validate_pinned_epoch(pinned: u64, now_ms: u64) -> Result<u64, ToolError> {
    if pinned > now_ms.saturating_add(BUILD_EPOCH_FUTURE_SKEW_MS) {
        return Err(ToolError::user(format!(
            "--build-epoch {pinned} is more than 24h in the future (now {now_ms}, ms since the \
             Unix epoch): a future build date forges dct:issued and breaks harvester \
             dct:modified monotonicity. Use a current or past epoch: a past value is fine \
             for a reproducible re-build."
        )));
    }
    Ok(pinned)
}

/// Print one conversion diagnostic to stderr, prefixed by its severity.
///
/// Both severities print at every verbosity: a `note:` is how a provider learns what the
/// conversion discarded, so routing it through `output::note` (gated at `-v`) would hide
/// exactly the information this channel exists to surface.
fn print_diagnostic(d: &Diagnostic) {
    crate::output::always(&diagnostic_line(d));
}

/// One conversion diagnostic as its stderr line, prefixed by severity.
///
/// `Diagnostic.message` folds provider-controlled text — the ignored INFO field ids are
/// raw VCF header bytes — so it is rendered through [`Untrusted`](crate::output::Untrusted),
/// exactly as `preview`'s report renders the same field.
fn diagnostic_line(d: &Diagnostic) -> String {
    let prefix = match d.severity {
        Severity::Warning => "warning",
        Severity::Note => "note",
    };
    format!("{prefix}: {}", crate::output::Untrusted(&d.message))
}

/// Prefix a per-source failure's message with the source VCF's path, keeping its exit code.
///
/// A multi-VCF build (a per-population/country split) would otherwise report an
/// accurate-but-anonymous "contig chr3 reappears" with no way to tell which of N inputs to
/// fix without bisecting.
fn with_source(source: &Path, mut err: ToolError) -> ToolError {
    err.message = format!("{}: {}", source.display(), err.message);
    err
}

/// A VCF that carries `NS` names its own cohort size. When the recommended
/// `numberOfUniqueIndividuals` is absent, put the value the VCFs suggest beside the warning
/// that asked for it, rather than leave the provider to count samples by hand. A hint,
/// never a gate: it is a `note:` line and counts toward nothing.
fn hint_individuals_from_ns(package: &PackageYaml, converted: &[ConvertedVcf]) {
    if package.metadata.number_of_unique_individuals.is_none()
        && let Some(peak) = converted
            .iter()
            .filter_map(|c| c.output.drops.ns_peak)
            .max()
    {
        crate::output::always(&format!(
            "note: numberOfUniqueIndividuals is absent; the VCF's NS peaks at {peak}. If \
             every sample is a distinct individual, that is the value to declare"
        ));
    }
}

/// What runs once every VCF has been converted and every diagnostic printed: two advisories,
/// then the two gates.
///
/// Both gates fail through the caller's `StagingGuard`, which removes the partial staging
/// dir.
///
/// * The **block-layout note** and the **`NS` hint** (advisory, never fatal) — printed
///   first, so they survive a `--strict` failure below.
/// * An **empty dataset** is never intentional — it is the end state of a mis-named INFO
///   header (no parseable `AF`) or a wholly non-primary-contig VCF. There is nothing to
///   serve, so this fails regardless of `--strict`.
/// * **`--strict`** fails only after every diagnostic has been printed, so a provider
///   fixes them all in one pass instead of discovering them one build at a time. `Note`s
///   never count: gating on the `min_allele_count` floor's tally would make strict mode
///   incompatible with the floor itself.
///
/// # Errors
///
/// [`ToolError::user`] when the group emitted no rows; [`ToolError::strict`] when
/// `--strict` is set and any `Warning`-severity diagnostic was emitted.
fn check_converted_output(
    args: &BuildArgs,
    package: &PackageYaml,
    converted: &[ConvertedVcf],
    metadata_warnings: usize,
) -> Result<(), ToolError> {
    hint_individuals_from_ns(package, converted);
    // Advisory first: it describes the parquet that was written, so a `--strict` build
    // that is about to fail still tells the provider about its layout.
    warn_if_split_across_blocks(converted);
    let total_rows: u64 = converted.iter().map(|c| c.output.rows_emitted).sum();
    if total_rows == 0 {
        return Err(ToolError::user(
            "the VCF group produced no rows; the dataset would be empty \
             (check the INFO field names and the contig labels)"
                .to_owned(),
        ));
    }

    let warning_count = metadata_warnings + count_conversion_warnings(converted);
    if args.strict && warning_count > 0 {
        return Err(ToolError::strict(format!(
            "--strict: {warning_count} warning(s); fix them or drop --strict \
             (note: lines are informational and never fail a build)"
        )));
    }
    Ok(())
}

/// Validate the package's metadata, print its diagnostics, and return how many were
/// warnings (the `--strict` denominator).
///
/// The three-tier obligation's advisories are all "you should fix this", so they count.
/// The report's `notes` describe a valid, deliberate configuration (a declared but inert
/// `hideLowerCounts`) and never do.
fn report_metadata_diagnostics(
    package: &PackageYaml,
    catalogs: Option<&BTreeMap<String, String>>,
) -> Result<usize, ToolError> {
    let report = validate_package(package, catalogs).map_err(|e| ToolError::from(&e))?;
    for warning in &report.warnings {
        crate::output::always(&format!("warning: {warning}"));
    }
    for note in &report.notes {
        crate::output::always(&format!("note: {note}"));
    }
    Ok(report.warnings.len())
}

/// Count the `Warning`-severity diagnostics across every converted VCF. `Note`s are
/// expected consequences of declared configuration, so they are not counted.
fn count_conversion_warnings(converted: &[ConvertedVcf]) -> usize {
    converted
        .iter()
        .flat_map(|c| &c.output.diagnostics)
        .filter(|d| d.severity == Severity::Warning)
        .count()
}

/// Values `build` already computed while converting one source VCF, keyed by source path,
/// so `build_files_section` neither re-hashes the file nor re-derives its provenance.
struct PrecomputedVcf {
    sha256: String,
    size: u64,
    conversion: ConversionStats,
}

/// The result of a successful `build`: the minted dataset ID, its staging dir, and the
/// machine-readable facts a CI pipeline needs (they are otherwise only on stderr).
pub struct BuildOutput {
    /// The generated dataset ID (`{prefix}-{cc}-{org}-{timestamp}`, where `timestamp` is
    /// the build time formatted as `YYYYMMDDHHMMSSmmm`, not raw epoch millis).
    pub dataset_id: String,
    /// The staging directory `<out>/<datasetId>/` holding the built dataset.
    pub staging: PathBuf,
    /// Every conversion diagnostic, paired with the source VCF file name that produced
    /// it. Metadata advisories are printed but not collected here — they belong to the
    /// package, not to a VCF.
    pub diagnostics: Vec<(String, Diagnostic)>,
    /// The population labels the built dataset serves (the manifest's `metadata.populations`).
    pub populations: Vec<String>,
    /// Whether this was a `--dry-run`: everything was converted and validated, then the
    /// staging dir was removed. [`Self::staging`] no longer exists.
    pub dry_run: bool,
}

/// Run `build`, printing a success line.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1, single-line message, no stack trace) on any
/// user-fixable failure: a malformed/invalid package, an unresolved country
/// code, a conversion error, a checksum mismatch, a vcfid collision, or an
/// assembly disagreement.
pub fn run(
    args: &BuildArgs,
    profile_name: Option<&str>,
    config_path: Option<&Path>,
) -> Result<(), ToolError> {
    let started = std::time::Instant::now();
    let out = build_staging_dir(args, profile_name, config_path)?;
    crate::output::note(&format!("build complete in {:.1?}", started.elapsed()));
    // A dry run's staging dir is gone: reporting its path would name a file that does not
    // exist, and `status: "ok"` alone would read as "a dataset was produced".
    let text = if out.dry_run {
        format!(
            "dry run: dataset {} would be built ({} population(s)); nothing written",
            out.dataset_id,
            out.populations.len()
        )
    } else {
        format!(
            "built dataset {} -> {}",
            out.dataset_id,
            out.staging.display()
        )
    };
    crate::output::emit_result(
        args.format,
        &text,
        &serde_json::json!({
            "schemaVersion": 1,
            "status": "ok",
            "action": if out.dry_run { "build-dry-run" } else { "build" },
            "datasetId": out.dataset_id,
            "path": if out.dry_run { serde_json::Value::Null }
                    else { serde_json::Value::String(out.staging.display().to_string()) },
            // What the dataset serves, and everything the conversion said about it.
            // The full per-VCF provenance is not duplicated here: it lives in the
            // manifest.json under `path`, and copying it would invite the two to drift.
            "populations": out.populations,
            "warnings": diagnostic_count(&out.diagnostics, Severity::Warning),
            "notes": diagnostic_count(&out.diagnostics, Severity::Note),
            "diagnostics": out
                .diagnostics
                .iter()
                .map(|(source, d)| serde_json::json!({
                    "severity": d.severity,
                    "message": d.message,
                    "source": source,
                }))
                .collect::<Vec<_>>(),
        }),
    );
    Ok(())
}

/// Reject a package whose `internal.pastVersion` is its own id.
///
/// `internal.pastVersion` names the single dataset this one supersedes. The node strips
/// `internal`, but an integrating system reads it as lineage, and a self-edge is a cycle
/// no walker terminates on — so a copy-paste of the id into its own package is refused.
///
/// Checked here rather than in `validate_pkg` because this is the first point where the
/// generated id and the declared predecessor both exist: `validate_pkg` runs against
/// `package.yaml`, before the id is derived.
///
/// # Errors
///
/// A [`ToolError`] naming the id when `pastVersion` equals it.
fn check_not_self_superseding(package: &PackageYaml, dataset_id: &str) -> Result<(), ToolError> {
    if package.internal.past_version.as_deref() == Some(dataset_id) {
        return Err(ToolError::user(format!(
            "internal.pastVersion is this dataset's own id ({dataset_id}): a dataset \
             cannot supersede itself. Point it at the previous dataset's id, or remove \
             the field if this is the first version."
        )));
    }
    Ok(())
}

/// Build the staging directory and return its dataset ID + path (no output line),
/// so `package` (build + pack) can reuse the build logic without duplicating it.
///
/// # Errors
///
/// Same failures as [`run`].
pub fn build_staging_dir(
    args: &BuildArgs,
    profile_name: Option<&str>,
    config_path: Option<&Path>,
) -> Result<BuildOutput, ToolError> {
    // 1. Load the package.yaml and find its directory.
    let package = load_package(&args.package, args.strict)?;
    let package_dir = args
        .package
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);

    // 2. Validate metadata. Offline-friendly: when a catalogs allow-list is available
    //    (the profile's pinned list, or a live fetch with `--refresh-catalogs`), enforce
    //    membership; otherwise validate structurally (empty -> None). Profile selection
    //    is best-effort here (`build` is node-free and must never require a profile): an
    //    unselectable profile leaves catalogs None.
    let tool_config = ToolConfig::load(config_path)
        .map_err(|e| ToolError::user(format!("loading tool config: {e}")))?;
    let active = crate::profile::load_active(config_path, profile_name).ok();
    let catalogs_resolved = resolve_catalogs(active.as_ref(), args.refresh_catalogs);
    let catalogs: Option<&BTreeMap<String, String>> =
        Some(&catalogs_resolved).filter(|c| !c.is_empty());
    let metadata_warnings = report_metadata_diagnostics(&package, catalogs)?;

    // 3. Resolve the country code (config < env < flag).
    let country_code = tool_config
        .resolve_country_code(args.country_code.as_deref())
        .ok_or_else(|| {
            ToolError::user(
                "country code is required but not set; supply it via one of (increasing \
                 precedence): the tool config `country_code` key, the \
                 `GDI_TOOL__COUNTRY_CODE` environment variable, or the `--country-code`/`--cc` flag"
                    .to_owned(),
            )
        })?;
    crate::output::note(&format!("country code: {country_code}"));

    // 4. Generate the dataset ID from the real wall clock.
    let prefix = package
        .metadata
        .prefix
        .as_deref()
        .ok_or_else(|| ToolError::user("package metadata.prefix is required (GOE or GDI)"))?;
    let org = package
        .metadata
        .org
        .as_deref()
        .ok_or_else(|| ToolError::user("package metadata.org is required"))?;
    let epoch_millis = resolve_build_epoch(args)?;
    let dataset_id = generate_dataset_id(prefix, &country_code, org, epoch_millis)
        .map_err(|e| ToolError::from(&e))?;

    check_not_self_superseding(&package, &dataset_id)?;

    // Build under a hidden name and promote it by rename only once `manifest.json` is
    // written (step 7 below). `StagingGuard` covers a graceful failure, but it is a `Drop`
    // impl and a SIGKILL runs no destructor — an OOM kill under a container memory cap is
    // exactly that. Without the hidden name, such a kill leaves `<out>/<datasetId>/`
    // holding real parquet with no manifest: something that looks like a staging dir, that
    // the node rejects at ingest, and that the next `build` refuses to overwrite without
    // `--force`. A dot-prefixed name cannot be mistaken for one, and the rename is atomic
    // within the same directory, so the final path only ever exists complete. (`deploy`
    // places artifacts into an inbox the same way.)
    let staging = args.out.join(&dataset_id);
    let building = args.out.join(format!(".{dataset_id}.partial"));
    // `--force` is about the final artifact, so it is checked against that path; the
    // hidden work dir is always recreated (a leftover one is debris by definition).
    clear_staging_target(&staging, args.force, args.dry_run)?;
    prepare_staging_dir(&building, true)?;
    // Remove the partially-built staging dir if any step below fails — a failed
    // `build` otherwise leaks a partial **plaintext** parquet dir (the exact material
    // the tool is careful to delete on success). Disarmed by `keep()` before `Ok`.
    let guard = StagingGuard(Some(building.clone()));
    // Everything below writes into the hidden dir; `staging` is only the promotion target.
    let staging = building;

    // 5. Convert each VCF in the first VCF group (parallel; see `convert_vcf_group`).
    let vcf_group = first_vcf_group(&package)?;
    let assembly = vcf_group
        .reference
        .clone()
        .ok_or_else(|| ToolError::user("the VCF file group must declare a reference (assembly)"))?;
    // Pass `--jobs` raw, where 0 means auto: the shared pool sizes itself off it without
    // clamping to the file count, so a single VCF still uses every core.
    let converted = convert_vcf_group(
        vcf_group,
        &package_dir,
        &package,
        &assembly,
        &staging,
        args.jobs,
    )?;

    // 5a/5b. Post-conversion checks: the layout note, the NS hint, an empty dataset, and
    // `--strict`.
    check_converted_output(args, &package, &converted, metadata_warnings)?;

    // 6. Recount `numberOfRecords` from the written PARQUET — and validate it in the same
    //    pass. The count is the distinct `(chr, POS, REF, ALT)` loci deduped across the
    //    dataset's VCFs: summing per-VCF counts double-counts a per-population split, whose
    //    files share loci and differ only in the population column, and the union is not
    //    recoverable from the summands. Holding every key in memory to union them is
    //    unbounded — hundreds of bytes per distinct variant, for a single u64. The parquet
    //    is POS-sorted and partitioned by `(chr, block)`, so `validate_parquet_dir` already
    //    derives exactly this number with a bounded-memory streaming merge.
    let scan =
        validate_parquet_dir(&staging, &ParquetCaps::default()).map_err(|e| ToolError::from(&e))?;
    let number_of_records = scan.distinct_variants;
    check_record_count_bounds(&converted, number_of_records)?;

    // 8. Write headers/{vcfid}.vcf (unless --no-headers). Done before the
    //    manifest's file checksums so the headers are part of the staged set.
    let header_policy = args.header_policy(active.as_ref());
    if header_policy != HeaderPolicy::None {
        write_headers(&converted, &staging, header_policy)?;
    }

    // 7. Compute every source input file's sha256/size, build + write manifest.json.
    //    Reuse each VCF's source digest already computed during conversion (its vcfid
    //    is that digest's first 16 chars) instead of hashing every VCF a second time;
    //    non-VCF files fall through to a fresh hash inside `build_files_section`.
    let precomputed: HashMap<PathBuf, PrecomputedVcf> = converted
        .iter()
        .map(|c| {
            (
                c.source.clone(),
                PrecomputedVcf {
                    sha256: c.output.source_sha256.clone(),
                    size: c.output.source_size,
                    conversion: ConversionStats::from(&c.output),
                },
            )
        })
        .collect();
    let files_section = build_files_section(&package.files, &package_dir, &precomputed)?;
    let mut manifest = build_manifest(
        &package,
        &dataset_id,
        number_of_records,
        &assembly,
        files_section,
        header_policy,
    );
    // Digest the packaged payload — every TAR member but `manifest.json`. `files` above
    // inventories the source VCFs only, so without this two builds from identical sources
    // with a different disclosure floor, projection or converter version are
    // indistinguishable at the manifest level. Computed here because steps 6 and 8 have
    // finished: the parquet and the `headers/` members are all on disk, and nothing writes
    // to staging after this.
    manifest.payload = Some(super::cmd_pack::payload_section(&staging)?);
    write_manifest(&manifest, &staging)?;

    // 9. Self-check: the parquet scan from step 6 already validated schema, caps, per-row
    //    values and `(POS, REF, ALT, population)` uniqueness. Assert its population set
    //    matches what the manifest declares, and — as node ingest does — that each data
    //    file's filename blockRange matches the manifest's, so a build can never emit a
    //    package the node would reject as Visible-but-unqueryable.
    self_check_populations(&scan, &manifest)?;
    check_data_file_block_range(&staging, manifest.config.block_range)
        .map_err(|e| ToolError::from(&e))?;

    // Success. A dry run leaves the guard armed, so dropping it removes the staging dir:
    // every gate ran against real output, and nothing durable remains — and it is never
    // promoted, so no `<out>/<datasetId>/` appears at all.
    let staging = promote_build(staging, &args.out, &dataset_id, guard, args.dry_run)?;
    Ok(BuildOutput {
        dataset_id,
        staging,
        diagnostics: collect_diagnostics(&converted),
        populations: manifest.metadata.populations.unwrap_or_default(),
        dry_run: args.dry_run,
    })
}

/// Pair every conversion diagnostic with the source VCF file name that produced it, so a
/// `--format json` consumer can attribute a warning to a file rather than scraping stderr.
fn collect_diagnostics(converted: &[ConvertedVcf]) -> Vec<(String, Diagnostic)> {
    converted
        .iter()
        .flat_map(|c| {
            let source = c.source.file_name().map_or_else(
                || c.source.display().to_string(),
                |n| n.to_string_lossy().into_owned(),
            );
            c.output
                .diagnostics
                .iter()
                .map(move |d| (source.clone(), d.clone()))
        })
        .collect()
}

/// Bound the parquet-recounted dataset `numberOfRecords` by the per-VCF distinct counts the
/// conversion produced independently: `max(per_vcf) <= dataset <= sum(per_vcf)`.
///
/// `numberOfRecords` is recounted from the written parquet (the only bounded-memory way to
/// dedup loci shared across a per-population split), so comparing it to itself would prove
/// nothing. These bounds are the strongest statement the conversion side can still make
/// without holding every key:
///
/// * `<= sum` — a locus in the union appears in at least one VCF.
/// * `>= max` — the union contains every locus of the largest VCF.
///
/// For a single VCF the two collapse to equality, so the common case is an exact
/// end-to-end cross-check, at O(1) memory.
///
/// # Errors
///
/// Returns a [`ToolError`] when the recount falls outside the bounds — the parquet and the
/// conversion disagree, and the node would reject the package at ingest.
fn check_record_count_bounds(converted: &[ConvertedVcf], counted: u64) -> Result<(), ToolError> {
    let per_vcf: Vec<u64> = converted
        .iter()
        .map(|c| c.output.number_of_records)
        .collect();
    let lower = per_vcf.iter().copied().max().unwrap_or(0);
    let upper: u64 = per_vcf.iter().copied().sum();
    if counted < lower || counted > upper {
        return Err(ToolError::user(format!(
            "build self-check: {counted} distinct variants recounted from the written parquet \
             falls outside [{lower}, {upper}], the bounds implied by the per-VCF conversion \
             counts {per_vcf:?}; refusing to emit a package the node would reject at ingest"
        )));
    }
    Ok(())
}

/// Assert the manifest's `metadata.populations` matches what the written parquet holds.
///
/// The manifest derives it from the VCF conversion; the node re-derives it from the parquet
/// at ingest and rejects a mismatch. Checking here refuses to emit a package the node would
/// reject. Takes the [`ParquetScan`] from the recount pass rather than re-scanning.
///
/// # Errors
///
/// Returns a [`ToolError`] on a claim mismatch.
fn self_check_populations(scan: &ParquetScan, manifest: &Manifest) -> Result<(), ToolError> {
    let declared: BTreeSet<&str> = manifest
        .metadata
        .populations
        .iter()
        .flatten()
        .map(String::as_str)
        .collect();
    let observed: BTreeSet<&str> = scan.populations.iter().map(String::as_str).collect();
    if declared != observed {
        return Err(ToolError::user(format!(
            "build self-check: metadata.populations {declared:?} from VCF conversion != \
             {observed:?} recounted from the written parquet; refusing to emit a package the \
             node would reject at ingest"
        )));
    }
    Ok(())
}

/// Removes a partially-built staging dir on an error return, so a failed `build`
/// never leaks a partial **plaintext** parquet dir. Disarmed via [`Self::keep`] on
/// the success path.
struct StagingGuard(Option<PathBuf>);

impl StagingGuard {
    /// Disarm the guard (the build succeeded; keep the staging dir).
    fn keep(mut self) {
        self.0 = None;
    }
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = std::fs::remove_dir_all(&path);
        }
    }
}

/// A single converted VCF: its source path, vcfid, and the conversion output.
struct ConvertedVcf {
    /// The resolved source VCF path.
    source: PathBuf,
    /// First 16 hex of the source VCF's SHA-256.
    vcfid: String,
    /// The conversion result (parquet files, record count, warnings).
    output: ConvertOutput,
}

/// The unknown-keys diagnostic, sanitised. The key names are copied verbatim from the
/// provider's `package.yaml`, and this text reaches the terminal on both arms: as a
/// `ToolError` under `--strict`, which `output::error_line` renders through
/// [`crate::output::Untrusted`], and through `output::always` otherwise, which does not.
/// Neutralising here, once, means neither arm can emit a raw control sequence.
fn unknown_keys_detail(path: &Path, unknown: &[String]) -> String {
    let detail = format!(
        "{} carries {} key(s) the package model does not recognise, which are dropped \
         without further warning: {}. Check the spelling against docs/package-format.md.",
        path.display(),
        unknown.len(),
        unknown.join(", ")
    );
    crate::output::Untrusted(&detail).to_string()
}

/// Keys the author wrote that the typed model does not know, as dotted paths.
///
/// `PackageYaml`, `PackageMetadata`, `PackageConfig` and `PackageFileGroup` are all
/// `deny_unknown_fields`, so a stray key at those levels already fails at parse. The three
/// shared leaf structs — `Internal`, `ContactPoint`, `OtherIdentifier` — cannot be: the node
/// deserialises the very same types out of `manifest.json` and must stay lenient there, so
/// an older node does not reject a newer package over a field it would discard anyway.
/// A typo inside them would otherwise be dropped in silence: `internal.pastVersoin` parses,
/// ships as `"internal": {}`, and the supersession link an integrating system consumes
/// never exists.
///
/// Rather than duplicating those types (two structs to update on every future field — and
/// `Internal` grows), the valid key set is derived from the model: re-serialise what parsed
/// and diff it against what was authored. Adding a field anywhere makes its key valid here
/// automatically, with nothing to keep in sync.
///
/// A key whose authored value is `null` is skipped: it parses to `None` and legitimately
/// vanishes from the round trip.
fn unknown_keys(authored: &serde_json::Value, parsed: &serde_json::Value, at: &str) -> Vec<String> {
    use serde_json::Value;
    let mut out = Vec::new();
    match (authored, parsed) {
        (Value::Object(a), Value::Object(p)) => {
            for (key, authored_v) in a {
                // An explicit `null` parses to `None` and legitimately drops out of the
                // round trip; it is an empty value, not an unrecognised key.
                if authored_v.is_null() {
                    continue;
                }
                let path = if at.is_empty() {
                    key.clone()
                } else {
                    format!("{at}.{key}")
                };
                match p.get(key) {
                    None => out.push(path),
                    Some(parsed_v) => out.extend(unknown_keys(authored_v, parsed_v, &path)),
                }
            }
        }
        (Value::Array(a), Value::Array(p)) => {
            for (i, (authored_v, parsed_v)) in a.iter().zip(p).enumerate() {
                out.extend(unknown_keys(authored_v, parsed_v, &format!("{at}[{i}]")));
            }
        }
        _ => {}
    }
    out
}

/// Load and parse the `package.yaml`, reporting keys the model does not know.
///
/// Unknown keys are a warning under a plain build and an error under `--strict`, matching
/// how the tool treats other authoring mistakes. See [`unknown_keys`] for why the check
/// lives here rather than as `deny_unknown_fields` on the types.
///
/// # Errors
///
/// A [`ToolError`] if the file cannot be read or parsed, or — under `strict` — if it
/// carries a key the model does not recognise.
pub(crate) fn load_package(path: &Path, strict: bool) -> Result<PackageYaml, ToolError> {
    let raw = fs::read_to_string(path)
        .map_err(|e| ToolError::user(format!("cannot read {}: {e}", path.display())))?;
    let package: PackageYaml = serde_saphyr::from_str(&raw)
        .map_err(|e| ToolError::user(format!("cannot parse {}: {e}", path.display())))?;

    // Diff what was authored against what the model round-trips. Both sides go through
    // `serde_json::Value` purely as a comparable shape; only keys are compared, never
    // values (YAML 1.1 coerces bare `y`/`n` to booleans, which would make value equality
    // meaningless here).
    let (Ok(authored), Ok(round_tripped)) = (
        serde_saphyr::from_str::<serde_json::Value>(&raw),
        serde_json::to_value(&package),
    ) else {
        // The typed parse already succeeded, so a failure to render either side as a
        // generic value is not something to fail the build over — skip the check.
        return Ok(package);
    };
    let unknown = unknown_keys(&authored, &round_tripped, "");
    if !unknown.is_empty() {
        let detail = unknown_keys_detail(path, &unknown);
        if strict {
            return Err(ToolError::user(detail));
        }
        crate::output::always(&format!("warning: {detail}"));
    }
    Ok(package)
}

/// Find the first VCF file group (case-insensitive `category == "VCF"`).
fn first_vcf_group(package: &PackageYaml) -> Result<&PackageFileGroup, ToolError> {
    package
        .files
        .iter()
        .find(|g| g.category.eq_ignore_ascii_case("VCF"))
        .ok_or_else(|| ToolError::user("no VCF file group found in the package"))
}

/// Resolve a file entry's path against the package directory (absolute paths are
/// used as-is).
fn resolve_path(
    package_dir: &Path,
    entry: &PackageFileEntry,
) -> (PathBuf, String, Option<String>, Option<u64>) {
    let (raw, sha256, size) = match entry {
        PackageFileEntry::Path(p) => (p.as_str(), None, None),
        PackageFileEntry::WithMeta { path, sha256, size } => (path.as_str(), sha256.clone(), *size),
    };
    let path = Path::new(raw);
    let resolved = if path.is_absolute() {
        path.to_path_buf()
    } else {
        package_dir.join(path)
    };
    (resolved, raw.to_owned(), sha256, size)
}

/// The provenance path recorded in the manifest's `files[]` for a source input.
///
/// The source's path relative to the `package.yaml`'s directory when it lives under it —
/// the normal case, and unique by construction, so a per-chromosome layout
/// (`chr1/data.vcf.gz`, `chr2/data.vcf.gz`) keeps two distinguishable provenance rows. A
/// source outside that directory cannot be relativized, so its `declared` string is
/// recorded verbatim.
///
/// Never the bare basename: two distinct-content sources sharing one would then be
/// indistinguishable to the consumer of this section, an integrating system's registry.
fn provenance_path(package_dir: &Path, resolved: &Path, declared: &str) -> String {
    resolved.strip_prefix(package_dir).map_or_else(
        |_| declared.to_owned(),
        // The manifest is a wire artifact read by an integrating system, so the separator
        // must not depend on the platform that ran `build` (`gdi-dataset-tool` ships a
        // Windows binary). Normalize to `/`; on Unix this is a no-op.
        |rel| {
            rel.to_string_lossy()
                .replace(std::path::MAIN_SEPARATOR, "/")
        },
    )
}

/// Move a completed build from its hidden work dir to `<out>/<datasetId>/`, atomically.
///
/// The rename is what makes the final path all-or-nothing: it only ever exists once
/// `manifest.json` and every gate are done, so a `build` killed part-way (an OOM kill is a
/// SIGKILL and runs no `Drop`) cannot leave something that looks like a staging dir.
///
/// A dry run is not promoted and keeps its guard armed, so dropping it removes the work
/// dir and no `<out>/<datasetId>/` ever appears.
fn promote_build(
    building: PathBuf,
    out: &Path,
    dataset_id: &str,
    guard: StagingGuard,
    dry_run: bool,
) -> Result<PathBuf, ToolError> {
    if dry_run {
        return Ok(building);
    }
    let final_path = out.join(dataset_id);
    fs::rename(&building, &final_path).map_err(|e| {
        ToolError::user(format!(
            "cannot move the completed build {} -> {}: {e}",
            building.display(),
            final_path.display()
        ))
    })?;
    guard.keep();
    Ok(final_path)
}

/// Make the final staging path available, honouring `--force` — and, on a dry run,
/// leaving it strictly alone.
///
/// Separate from [`prepare_staging_dir`] because the build never writes here directly: this
/// is the promotion target, so it must be left *absent*, not created. An existing directory
/// is still refused without `--force`.
///
/// A dry run writes nothing durable and never promotes into this path ([`promote_build`]
/// returns the work dir untouched), so it must not delete anything here either: with
/// `--force` it would destroy a real dataset to answer a question about a hypothetical
/// one, and without `--force` the "use --force to overwrite" advice would point a
/// preflight straight at the flag that does the deleting. A dry run therefore reports the
/// collision (the real build would need `--force`) and returns.
fn clear_staging_target(staging: &Path, force: bool, dry_run: bool) -> Result<(), ToolError> {
    if !staging.exists() {
        return Ok(());
    }
    if dry_run {
        crate::output::warn(&format!(
            "warning: {} already exists; this dry run leaves it untouched. A real build of \
             this dataset id would need --force to replace it",
            staging.display()
        ));
        return Ok(());
    }
    if !force {
        return Err(ToolError::user(format!(
            "staging directory {} already exists (use --force to overwrite)",
            staging.display()
        )));
    }
    fs::remove_dir_all(staging)
        .map_err(|e| ToolError::user(format!("cannot remove {}: {e}", staging.display())))
}

/// Create (or, with `force`, recreate) the staging directory.
#[expect(
    clippy::disallowed_methods,
    reason = "operator-chosen staging directory; members carry their own modes"
)]
fn prepare_staging_dir(staging: &Path, force: bool) -> Result<(), ToolError> {
    if staging.exists() {
        if !force {
            return Err(ToolError::user(format!(
                "staging directory {} already exists (use --force to overwrite)",
                staging.display()
            )));
        }
        fs::remove_dir_all(staging)
            .map_err(|e| ToolError::user(format!("cannot remove {}: {e}", staging.display())))?;
    }
    fs::create_dir_all(staging)
        .map_err(|e| ToolError::user(format!("cannot create {}: {e}", staging.display())))
}

/// What a build's parquet layout says about how it will be queried: how many position
/// blocks it wrote, how many hold files from more than one source VCF, and the worst one.
///
/// The decision half of [`warn_if_split_across_blocks`], split out so the rule is testable
/// without capturing stderr (the same shape `override_advice` uses on the node side).
#[derive(Debug, PartialEq, Eq)]
struct SplitBlockSummary {
    /// Position blocks written in total.
    blocks: usize,
    /// Blocks holding files from more than one source VCF.
    shared: usize,
    /// Files in the most-shared block.
    most: usize,
    /// That block's key, for naming it in the note.
    worst_block: String,
}

/// [`SplitBlockSummary`] when at least one block has more than one writer, else `None`.
fn split_block_summary(converted: &[ConvertedVcf]) -> Option<SplitBlockSummary> {
    let mut per_block: BTreeMap<String, usize> = BTreeMap::new();
    for file in converted
        .iter()
        .flat_map(|c| &c.output.parquet_files)
        .filter_map(|p| p.file_name().and_then(std::ffi::OsStr::to_str))
    {
        if let Some(key) = partition_block_key(file) {
            *per_block.entry(key).or_default() += 1;
        }
    }
    // Ties are broken toward the lowest key (`Reverse`), so a package whose blocks are all
    // equally shared always names the same one — `max_by_key` alone keeps the last match,
    // which would make the note's example an artifact of iteration order.
    let (worst_block, &most) = per_block
        .iter()
        .max_by_key(|&(key, &n)| (n, std::cmp::Reverse(key)))?;
    if most < 2 {
        return None;
    }
    Some(SplitBlockSummary {
        blocks: per_block.len(),
        shared: per_block.values().filter(|&&n| n > 1).count(),
        most,
        worst_block: worst_block.clone(),
    })
}

/// Tell the provider when two or more source VCFs wrote into the same `(chr, block)`
/// partition.
///
/// That is the per-population split shape: several VCFs covering the same positions,
/// differing only in the population column. It builds and serves correctly, but the node
/// cannot stream such a block — it buffers and sorts the whole thing, which measured
/// 462 MiB against 17 MiB for the same 1.6 M rows in one file, and neither `granularity`
/// nor `limit` bounds that peak (`docs/operating.md` §22, `gdi_beacon_merged_blocks_total`).
///
/// Said here because build time is the last moment the layout is still a choice: once the
/// package ships, the cost is the operator's and the fix is another build. A warning, never
/// a refusal — the shape is legitimate, and for some providers it is the only shape their
/// upstream publishes.
fn warn_if_split_across_blocks(converted: &[ConvertedVcf]) {
    let Some(s) = split_block_summary(converted) else {
        return;
    };
    crate::output::warn(&format!(
        "note: {} of {} position blocks hold files from more than one source VCF (up to {}, \
         in {}). This is the per-population split layout: it is valid and will serve \
         correctly, but a serving node must hold such a block in memory whole, so queries \
         over it cost several times what a single-file block costs. If these VCFs are one \
         population each over the same positions, building them as a single VCF with \
         per-population INFO fields avoids that.",
        s.shared, s.blocks, s.most, s.worst_block
    ));
}

/// Convert every VCF in the group through one build-wide shared worker pool (core's
/// [`core_convert_vcf_group`]). The cross-group single-assembly check below is redundant
/// for the CLI path — `validate_package` rejects more than one VCF group before conversion
/// runs — and is kept only for a direct caller that bypasses that gate.
///
/// Returns the per-VCF results, in declared order. The dataset-wide distinct
/// `numberOfRecords` is not computed here: the caller recounts it from the written
/// parquet (a bounded-memory streaming merge in `validate_parquet_dir`), since folding
/// per-VCF counts double-counts loci shared across a per-population split. Each VCF
/// writes parquet files whose names embed its own vcfid, so the
/// pool's concurrent writers into `staging` never collide; the lowest-index conversion
/// error (if any) is reported, and the vcfid-collision check is a deterministic
/// post-pass ([`finalize_converted`]) so the error is stable. One shared pool keeps
/// every core busy even when the VCFs are unequal in size.
fn convert_vcf_group(
    vcf_group: &PackageFileGroup,
    package_dir: &Path,
    package: &PackageYaml,
    assembly: &str,
    staging: &Path,
    jobs: usize,
) -> Result<Vec<ConvertedVcf>, ToolError> {
    // A dataset is single-assembly: every VCF group's reference must agree. Unreachable
    // from the CLI, where `validate_package` already rejects more than one VCF group.
    for group in &package.files {
        if group.category.eq_ignore_ascii_case("VCF")
            && let Some(reference) = &group.reference
            && reference != assembly
        {
            return Err(ToolError::user(format!(
                "VCF groups disagree on assembly: {reference:?} vs {assembly:?}"
            )));
        }
    }

    let opts = ConvertOptions {
        assembly: assembly.to_owned(),
        block_range: package.config.block_range,
        min_allele_count: package.config.min_allele_count,
    };

    let sources = resolve_vcf_sources(vcf_group, package_dir)?;
    // Fail fast on header-level violations before the (potentially multi-GB) conversion
    // writes anything: read only each source's header and reject a missing `AF` field, an
    // over-long population label, a bad `Number=`, or a dataset already over the population
    // cap — for all sources up front, rather than partway through the first VCF's scan.
    preflight_vcf_headers(&sources)?;
    let total = sources.len();
    // One worker pool spans the whole group: every VCF's partitions feed the same pool,
    // so a finished VCF's share of the cores is immediately reused by the others (no
    // per-VCF pool, no static `cores/jobs` split that idles cores when VCFs are unequal
    // in size). `--jobs` caps the pool size (and so peak memory + parallelism); 0 means
    // one worker per CPU. A single VCF still gets every core.
    let cores = std::thread::available_parallelism().map_or(1, NonZero::get);
    let pool_size = if jobs == 0 { cores } else { jobs };
    let started = AtomicUsize::new(0);
    crate::output::note(&format!(
        "converting {total} VCF(s) with {pool_size} worker(s)"
    ));

    // Live per-VCF byte progress for the otherwise-silent multi-GB conversion. Bars draw
    // to stderr only (the stdout result / `--format json` line is never touched) and only
    // when interactive and not silenced by `-q`; otherwise they are hidden no-ops and the
    // per-VCF milestone line falls back to the plain stderr progress path.
    let prog = crate::progress::ConvertProgress::for_paths(&sources, crate::progress::active());

    let results = core_convert_vcf_group(
        &sources,
        staging,
        &opts,
        pool_size,
        &|i| {
            // Fires as each VCF is picked up; printed cleanly above the live bars (or via
            // the plain stderr path when bars are disabled).
            let done = started.fetch_add(1, Ordering::Relaxed) + 1;
            prog.note(&format!(
                "converting VCF {done}/{total}: {}",
                sources[i].display()
            ));
        },
        &|i, n| prog.inc(i, n),
    );
    prog.finish();
    // VCF stage: relabel `invalid parquet:`. The user supplied a VCF and no parquet
    // exists yet.
    let results = results.map_err(|e| ToolError::from_vcf_stage(&e))?;

    // Assemble in declared order. `results` arrives in that same order, so the first error
    // seen is the lowest-index one — the reported failure is deterministic regardless of
    // which worker finished first.
    let mut converted: Vec<Option<ConvertedVcf>> = (0..sources.len()).map(|_| None).collect();
    let mut first_error: Option<ToolError> = None;
    for (i, result) in results.into_iter().enumerate() {
        match result {
            Ok(output) => {
                for d in &output.diagnostics {
                    print_diagnostic(d);
                }
                // Always echo what actually reached parquet, warning or not. A provider
                // who expected five populations and sees `Total` alone has mis-named
                // their INFO fields (or a floor collapsed them) — say so at build time,
                // not weeks later via an empty beacon query. Printed unconditionally
                // rather than via `output::note`, which only fires at `-v`.
                crate::output::always(&format!(
                    "{}: populations emitted ({}): {}",
                    sources[i].display(),
                    output.populations_emitted.len(),
                    if output.populations_emitted.is_empty() {
                        "(none)".to_owned()
                    } else {
                        output.populations_emitted.join(", ")
                    }
                ));
                converted[i] = Some(ConvertedVcf {
                    source: sources[i].clone(),
                    vcfid: output.vcfid.clone(),
                    output,
                });
            }
            Err(e) => {
                if first_error.is_none() {
                    // Same relabel as the group-level error above: this is a record of the
                    // user's VCF failing (an unknown contig, an incoherent AF), not parquet.
                    first_error = Some(with_source(&sources[i], ToolError::from_vcf_stage(&e)));
                }
            }
        }
    }
    if let Some(e) = first_error {
        return Err(e);
    }
    let converted = finalize_converted(converted)?;
    Ok(converted)
}

/// Resolve + existence-check every VCF source up front so a missing file fails fast
/// and deterministically (by its declared position), before any worker starts.
fn resolve_vcf_sources(
    vcf_group: &PackageFileGroup,
    package_dir: &Path,
) -> Result<Vec<PathBuf>, ToolError> {
    let mut sources: Vec<PathBuf> = Vec::with_capacity(vcf_group.files.len());
    for entry in &vcf_group.files {
        let (source, ..) = resolve_path(package_dir, entry);
        if !source.is_file() {
            return Err(ToolError::user(format!(
                "VCF file not found: {}",
                source.display()
            )));
        }
        sources.push(source);
    }
    if sources.is_empty() {
        return Err(ToolError::user("the VCF file group contains no files"));
    }
    Ok(sources)
}

/// Header-only preflight over the resolved sources, run before any conversion writes
/// output. Propagates each source's header-validation error (no `AF` field, over-long
/// population label, bad `Number=`) prefixed with its path, and rejects a dataset that
/// already declares more than [`MAX_POPULATIONS`] AF-bearing populations across the group.
///
/// The record-merge path in core remains the authoritative population cap (it counts only
/// populations that actually emit rows); this header count can only *overstate* it — the
/// sole gap being a population whose `AF` field carries zero records — so an over-cap
/// rejection here is a conservative fail-fast, never a false pass.
fn preflight_vcf_headers(sources: &[PathBuf]) -> Result<(), ToolError> {
    let mut af_populations: BTreeSet<String> = BTreeSet::new();
    for source in sources {
        let pops = read_header_populations(source)
            .map_err(|e| with_source(source, ToolError::from(&e)))?;
        af_populations.extend(pops);
        if af_populations.len() > MAX_POPULATIONS {
            return Err(ToolError::user(format!(
                "dataset exceeds the {MAX_POPULATIONS}-population cap: the VCF group's headers \
                 declare {}+ distinct populations with an AF field",
                af_populations.len()
            )));
        }
    }
    Ok(())
}

/// Assemble the per-worker results (in declared order) into the final list, checking
/// for vcfid collisions deterministically (the parallel conversion's only
/// order-sensitive step — deferred here so the reported pair is stable).
fn finalize_converted(results: Vec<Option<ConvertedVcf>>) -> Result<Vec<ConvertedVcf>, ToolError> {
    let mut converted: Vec<ConvertedVcf> = Vec::with_capacity(results.len());
    let mut seen_vcfids: BTreeMap<String, PathBuf> = BTreeMap::new();
    for slot in results {
        let Some(c) = slot else {
            return Err(ToolError::user(
                "internal error: a VCF source was neither converted nor reported as failed",
            ));
        };
        if let Some(prev) = seen_vcfids.get(&c.vcfid) {
            return Err(ToolError::user(format!(
                "vcfid collision: {} and {} share the first 16 hex of their SHA-256 ({}); \
                 change the dataset's VCF set",
                prev.display(),
                c.source.display(),
                c.vcfid
            )));
        }
        seen_vcfids.insert(c.vcfid.clone(), c.source.clone());
        converted.push(c);
    }
    Ok(converted)
}

/// Write `headers/{vcfid}.vcf` for each source VCF, filtered by `policy`.
///
/// Under the default [`HeaderPolicy::Minimal`] this is an allow-list of structural keys:
/// a `##<tool>Command=` line — the practical carrier of both subject identifiers (after
/// `-s`) and internal filesystem paths — is dropped, as is any key not on the list,
/// including ones no toolchain has invented yet.
///
/// Bgzipped (`.vcf.gz`) sources are decompressed first (see [`open_vcf_text_reader`])
/// so the staged header is the real VCF header text, matching the bgzip-aware
/// converter — not the raw gzip bytes a plaintext read would have scanned.
#[expect(
    clippy::disallowed_methods,
    reason = "header VCFs land in the staging directory, which `pack` consumes whole"
)]
fn write_headers(
    converted: &[ConvertedVcf],
    staging: &Path,
    policy: HeaderPolicy,
) -> Result<(), ToolError> {
    let headers_dir = staging.join("headers");
    #[expect(
        clippy::disallowed_methods,
        reason = "operator-chosen staging directory; header files are written with their own mode"
    )]
    fs::create_dir_all(&headers_dir)
        .map_err(|e| ToolError::user(format!("cannot create {}: {e}", headers_dir.display())))?;
    for c in converted {
        let reader = open_vcf_text_reader(&c.source)?;
        let out_path = headers_dir.join(format!("{}.vcf", c.vcfid));
        let mut out = fs::File::create(&out_path)
            .map_err(|e| ToolError::user(format!("cannot write {}: {e}", out_path.display())))?;
        for line in reader.lines() {
            let line = line
                .map_err(|e| ToolError::user(format!("cannot read {}: {e}", c.source.display())))?;
            if line.starts_with('#') {
                if let Some(kept) = filter_header_line(&line, policy) {
                    writeln!(out, "{kept}").map_err(|e| {
                        ToolError::user(format!("cannot write {}: {e}", out_path.display()))
                    })?;
                }
            } else {
                // VCF header lines are contiguous at the top of the file; the first data
                // record ends them. Stop here instead of scanning (and bgzf-decompressing)
                // the entire VCF body just to copy the leading `#` lines.
                break;
            }
        }
    }
    Ok(())
}

/// The `##` keys a `Minimal` header keeps: everything needed to interpret the parquet and
/// reproduce the conversion, and nothing that carries free text.
///
/// An allow-list by construction: a deny-list would have to name every carrier, and
/// `##<tool>Command=` lines — where sample identifiers after `-s` and internal filesystem
/// paths actually live — come in as many spellings as there are toolchains.
const MINIMAL_HEADER_KEYS: &[&str] = &[
    "fileformat",
    "INFO",
    "FORMAT",
    "FILTER",
    "contig",
    "reference",
    "assembly",
];

/// Keys carrying structured subject identifiers, kept only under
/// [`HeaderPolicy::WithIdentifiers`].
const IDENTIFIER_HEADER_KEYS: &[&str] = &["SAMPLE", "PEDIGREE"];

/// Apply `policy` to one `#`-prefixed header line, returning what to write (or `None` to
/// drop it).
///
/// # Panics
///
/// Never; `line` is expected to start with `#` and any other input is returned unchanged
/// under `Verbatim` and dropped otherwise.
fn filter_header_line(line: &str, policy: HeaderPolicy) -> Option<String> {
    match policy {
        // Verbatim means verbatim: the source bytes, infrastructure strings included. A
        // value that claimed "full" while quietly scrubbing would be unverifiable, and an
        // unverifiable sanitiser is worse than none.
        HeaderPolicy::Verbatim => return Some(line.to_owned()),
        // `None` writes no `headers/` member at all, so no line should reach here.
        HeaderPolicy::None => return None,
        HeaderPolicy::Minimal | HeaderPolicy::WithIdentifiers => {}
    }

    // The column line: the structured sample list. `WithIdentifiers` keeps it whole —
    // index-aligned and guaranteed present, which is what a consumer wanting identifiers
    // actually wants, rather than a regex scrape of whichever command line the producer's
    // toolchain happened to stamp.
    if line.starts_with("#CHROM") {
        return Some(if policy == HeaderPolicy::WithIdentifiers {
            line.to_owned()
        } else {
            strip_sample_columns(line).to_owned()
        });
    }

    // Everything else must be a `##key=value` meta line whose key is on the allow-list.
    // A bare `#comment` (no key to match) is dropped like any unrecognised carrier.
    let rest = line.strip_prefix("##")?;
    let key = rest.split('=').next().unwrap_or(rest);
    let allowed = MINIMAL_HEADER_KEYS.contains(&key)
        || (policy == HeaderPolicy::WithIdentifiers && IDENTIFIER_HEADER_KEYS.contains(&key));
    allowed.then(|| line.to_owned())
}

/// Drop the sample columns from a VCF `#CHROM` header line, leaving the eight fixed ones.
///
/// The `#CHROM` line names every sample in the source VCF, which for human data is a list
/// of subject identifiers; copied verbatim, those names would ship inside every package to
/// whoever operates the node. The header is packaged to record the source's
/// meta-information, and none of that needs the sample names: the node serves aggregate
/// allele frequencies and never reads them.
///
/// Any other `#` line passes through untouched.
fn strip_sample_columns(line: &str) -> &str {
    // CHROM POS ID REF ALT QUAL FILTER INFO | FORMAT sample1 sample2 ...
    const FIXED_COLUMNS: usize = 8;
    if !line.starts_with("#CHROM") {
        return line;
    }
    // Cut at the tab that ends the last fixed column (INFO); everything past it is FORMAT
    // plus the sample names. An aggregate VCF has no such tab and is returned unchanged.
    line.match_indices('\t')
        .nth(FIXED_COLUMNS - 1)
        .map_or(line, |(end, _)| line.split_at(end).0)
}

/// Open a VCF for line reading, transparently decompressing bgzipped input.
///
/// Detects the gzip magic (`1f 8b`) and wraps the file in the same bgzf reader the
/// noodles converter uses (BGZF is the VCF compression `bcftools` produces); a
/// plaintext VCF is read directly. Detection is by magic bytes, not extension, so a
/// mis-named file is handled correctly.
fn open_vcf_text_reader(path: &Path) -> Result<Box<dyn BufRead>, ToolError> {
    let read_err =
        |e: std::io::Error| ToolError::user(format!("cannot read {}: {e}", path.display()));
    let mut magic = [0u8; 2];
    let is_gzip = match fs::File::open(path)
        .map_err(read_err)?
        .read_exact(&mut magic)
    {
        Ok(()) => magic == [0x1f, 0x8b],
        // A file too short to hold the magic cannot be gzip; read it as plaintext.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => false,
        Err(e) => return Err(read_err(e)),
    };
    let file = fs::File::open(path).map_err(read_err)?;
    if is_gzip {
        Ok(Box::new(BufReader::new(noodles_bgzf::io::Reader::new(
            file,
        ))))
    } else {
        Ok(Box::new(BufReader::new(file)))
    }
}

/// Build the manifest `files` section: every group rewritten with the full (64-hex)
/// SHA-256 + size of each source input file, verified against any declared value.
///
/// This is upstream provenance for an integrating system's registry, not an inventory of
/// what the package ships: the source VCFs are never staged into the TAR (only `manifest.json`,
/// `headers/{vcfid}.vcf` and the derived `allele-freq.*.parquet` are), and the node strips
/// this whole section on ingest. So the recorded `path` is the source's path relative to
/// the package YAML's directory (see [`provenance_path`]) — the packed parquet payload
/// carries no per-file hash here and is checked semantically instead (record recount,
/// block-range).
fn build_files_section(
    file_groups: &[PackageFileGroup],
    package_dir: &Path,
    precomputed: &HashMap<PathBuf, PrecomputedVcf>,
) -> Result<Vec<FileGroup>, ToolError> {
    let mut groups: Vec<FileGroup> = Vec::with_capacity(file_groups.len());

    for group in file_groups {
        let mut entries: Vec<FileEntry> = Vec::with_capacity(group.files.len());
        for entry in &group.files {
            let (path, declared, declared_sha, declared_size) = resolve_path(package_dir, entry);
            // Reuse the digest computed during conversion (the VCFs) when available;
            // hash any other file (e.g. a non-VCF group member) here. A file the
            // converter never saw misses the map, so it carries no `conversion` block.
            let pre = precomputed.get(&path);
            let (sha256, size) = match pre {
                Some(p) => (p.sha256.clone(), p.size),
                None => file_sha256_and_size(&path)?,
            };
            if let Some(declared) = &declared_sha
                && !declared.eq_ignore_ascii_case(&sha256)
            {
                return Err(ToolError::user(format!(
                    "sha256 mismatch for {}: declared {declared}, computed {sha256}",
                    path.display()
                )));
            }
            if let Some(declared) = declared_size
                && declared != size
            {
                return Err(ToolError::user(format!(
                    "size mismatch for {}: declared {declared}, computed {size}",
                    path.display()
                )));
            }
            entries.push(FileEntry {
                path: provenance_path(package_dir, &path, &declared),
                sha256: Some(sha256),
                size: Some(size),
                conversion: pre.map(|p| p.conversion.clone()),
            });
        }
        groups.push(FileGroup {
            category: group.category.clone(),
            reference: group.reference.clone(),
            precise_reference: group.precise_reference.clone(),
            files: entries,
        });
    }

    Ok(groups)
}

/// Compute the full (64-hex) SHA-256 and size of a file.
fn file_sha256_and_size(path: &Path) -> Result<(String, u64), ToolError> {
    let file = fs::File::open(path)
        .map_err(|e| ToolError::user(format!("cannot read {}: {e}", path.display())))?;
    gdi_node_standalone_core::util::sha256_hex_reader(file)
        .map_err(|e| ToolError::user(format!("cannot hash {}: {e}", path.display())))
}

/// The sorted union of the populations every converted VCF actually emitted.
///
/// Derived from the `conversion` provenance already hanging off each VCF `FileEntry`, so
/// it reflects what reached parquet — not what the headers declared. `None` when no entry
/// carries provenance (nothing was converted), which keeps the manifest field absent
/// rather than advertising an empty set.
fn dataset_populations(files: &[FileGroup]) -> Option<Vec<String>> {
    let union: BTreeSet<&str> = files
        .iter()
        .flat_map(|g| &g.files)
        .filter_map(|e| e.conversion.as_ref())
        .flat_map(|c| c.output.populations.iter().map(String::as_str))
        .collect();
    if union.is_empty() {
        return None;
    }
    Some(union.into_iter().map(str::to_owned).collect())
}

/// Assemble the [`Manifest`] from the package metadata + the computed fields.
fn build_manifest(
    package: &PackageYaml,
    dataset_id: &str,
    number_of_records: u64,
    assembly: &str,
    files: Vec<FileGroup>,
    header_policy: HeaderPolicy,
) -> Manifest {
    let populations = dataset_populations(&files);
    let m = &package.metadata;
    let metadata = ManifestMetadata {
        dataset_id: dataset_id.to_owned(),
        catalog: m.catalog.clone(),
        title: m.title.clone(),
        description: m.description.clone(),
        access_rights: m.access_rights.clone(),
        applicable_legislation: m.applicable_legislation.clone(),
        license: m.license.clone(),
        creator: m.creator.clone(),
        health_category: m.health_category.clone(),
        keywords: m.keywords.clone(),
        number_of_unique_individuals: m.number_of_unique_individuals,
        conforms_to: m.conforms_to.clone(),
        type_: m.type_.clone(),
        legal_basis: m.legal_basis.clone(),
        is_referenced_by: m.is_referenced_by.clone(),
        other_identifier: m.other_identifier.clone(),
        contact_point: m.contact_point.clone(),
        // FDP-facing: consumed by the FAIR Data Point layer and external harvesters. The
        // beacon query path counts variant groups directly from Parquet and does not read
        // this field.
        number_of_records: Some(number_of_records),
        populations,
    };

    let c = &package.config;
    let config = ManifestConfig {
        mode: c.mode,
        block_range: c.block_range,
        af_source: c.af_source.clone(),
        af_source_reference: c.af_source_reference.clone(),
        min_allele_count: c.min_allele_count,
        hide_lower_counts: c.hide_lower_counts,
        assembly: Assembly {
            reference: assembly.to_owned(),
        },
        manifest_version: SUPPORTED_MANIFEST_VERSION,
        generated_by: GENERATED_BY.to_owned(),
    };

    // Record what the packaged `headers/` members actually contain, in the non-public
    // section the node strips and an integrating system reads. Stating it in the artifact
    // lets a consumer know what it holds without re-deriving it, and lets a package
    // claiming a restrictive policy be verified rather than trusted.
    let mut internal = package.internal.clone();
    internal.header_policy = Some(header_policy);

    Manifest {
        metadata,
        files,
        internal,
        // Filled in by the caller: the payload digest covers the staged files, and this
        // function is pure over the package spec and has no staging dir to read.
        // `build_staging_dir` sets it immediately after this call, before
        // `write_manifest`, and
        // `a_built_manifest_records_its_payload_digest` fails if that is ever dropped.
        payload: None,
        config,
    }
}

/// Refuse a serialized manifest larger than every reader in the workspace will accept.
///
/// [`MAX_MANIFEST_BYTES`](gdi_node_standalone_core::ingest::MAX_MANIFEST_BYTES) is enforced
/// by node ingest and by the tool's own `lint`/`inspect`/`diff`. Enforcing the same constant
/// at the producer keeps `build` from emitting, and `pack` from shipping, a package nothing
/// downstream can open — moving the failure from "ingest rejected your upload" to "your
/// build is too big", at the step that can still fix it.
///
/// # Errors
///
/// Returns a [`ToolError`] when `json` exceeds the shared cap.
fn check_manifest_size(json: &str) -> Result<(), ToolError> {
    let cap = gdi_node_standalone_core::ingest::MAX_MANIFEST_BYTES;
    let len = json.len() as u64;
    if len > cap {
        return Err(ToolError::user(format!(
            "the generated manifest.json is {len} bytes, over the {cap}-byte limit every \
             reader enforces: the node would refuse this package at ingest. Reduce the \
             per-file or population detail that inflates it."
        )));
    }
    Ok(())
}

/// Write the pretty-printed `manifest.json` into the staging directory.
#[expect(
    clippy::disallowed_methods,
    reason = "the manifest lands in the staging directory, which `pack` consumes whole"
)]
fn write_manifest(manifest: &Manifest, staging: &Path) -> Result<(), ToolError> {
    let json = serde_json::to_string_pretty(manifest)
        .map_err(|e| ToolError::user(format!("cannot serialize manifest: {e}")))?;
    // Before the write, so an oversized manifest is never left on disk for `pack` to ship.
    check_manifest_size(&json)?;
    let path = staging.join("manifest.json");
    fs::write(&path, json)
        .map_err(|e| ToolError::user(format!("cannot write {}: {e}", path.display())))
}

/// Current Unix time in milliseconds.
fn now_unix_millis() -> Result<u64, ToolError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ToolError::user("system clock is before the Unix epoch"))?;
    u64::try_from(now.as_millis()).map_err(|_| ToolError::user("system clock is out of range"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `build`'s diagnostic sink renders the message as untrusted text: the ignored-INFO
    /// diagnostic quotes raw VCF header ids, and `preview` already wrapped the same field.
    /// A terminal clear-screen sequence in a field id must not reach stderr.
    #[test]
    fn diagnostic_line_renders_the_message_as_untrusted() {
        let d =
            Diagnostic::warning("ignored non-conforming INFO fields: AF_\u{1b}[2J\u{1b}[Hspoofed");
        let line = diagnostic_line(&d);
        assert!(line.starts_with("warning: "), "{line:?}");
        assert!(
            !line.chars().any(char::is_control),
            "diagnostic_line rendered a control byte: {line:?}"
        );
        assert!(line.ends_with("AF_ [2J [Hspoofed"), "{line:?}");
        assert!(diagnostic_line(&Diagnostic::note("n")).starts_with("note: "));
    }

    #[test]
    fn the_producer_refuses_a_manifest_the_node_would_reject() {
        // `MAX_MANIFEST_BYTES` is enforced by every reader in the workspace: node ingest,
        // and the tool's own lint/inspect/diff. Without the producer-side check the failure
        // surfaces only after conversion, encryption and upload, as an ingest rejection on
        // the node, attributed to the package rather than to the build that made it.
        let cap = usize::try_from(gdi_node_standalone_core::ingest::MAX_MANIFEST_BYTES)
            .expect("cap fits usize");

        check_manifest_size(&"x".repeat(cap)).expect("exactly at the cap is accepted");

        let err = check_manifest_size(&"x".repeat(cap + 1))
            .expect_err("one byte over the reader cap must be refused at the producer");
        let msg = format!("{err}");
        assert!(
            msg.contains("manifest.json"),
            "the error must name the artifact: {msg}"
        );
        assert!(
            msg.contains(&gdi_node_standalone_core::ingest::MAX_MANIFEST_BYTES.to_string()),
            "the error must state the limit it enforces: {msg}"
        );
    }

    fn yaml_value(y: &str) -> serde_json::Value {
        serde_saphyr::from_str(y).expect("yaml parses")
    }

    /// A typo inside one of the three shared leaf structs must not be dropped in silence.
    #[test]
    fn a_typo_inside_internal_is_reported() {
        let authored = yaml_value("internal:\n  pastVersoin: \"GDI-EE-UTARTU-1\"\n");
        // What the model round-trips: `Internal` did not know the key, so it is absent.
        let round_tripped = serde_json::json!({ "internal": {} });
        let found = unknown_keys(&authored, &round_tripped, "");
        assert_eq!(
            found,
            vec!["internal.pastVersoin".to_owned()],
            "got {found:?}"
        );
    }

    /// A correctly-spelled key must not be reported.
    #[test]
    fn a_known_key_is_not_reported() {
        let authored = yaml_value("internal:\n  pastVersion: 1\n");
        let round_tripped = serde_json::json!({ "internal": { "pastVersion": 1 } });
        assert!(unknown_keys(&authored, &round_tripped, "").is_empty());
    }

    /// An explicit `null` legitimately vanishes from the round trip and is not a typo.
    #[test]
    fn an_explicit_null_is_not_an_unknown_key() {
        let authored = yaml_value("internal:\n  pastVersion: null\n");
        let round_tripped = serde_json::json!({ "internal": {} });
        assert!(unknown_keys(&authored, &round_tripped, "").is_empty());
    }

    /// End-to-end through the real loader: `--strict` must reject a typo'd key inside one of
    /// the lenient leaf structs, and a plain load must accept it with a warning.
    ///
    /// A typo like `internal.pastVersoin` otherwise ships as `"internal": {}`, so the
    /// supersession link a consuming registry reads never exists. The same typo one section
    /// up in `metadata:` or `config:` hard-fails, because those structs can carry
    /// `deny_unknown_fields` and the shared leaves cannot.
    #[test]
    fn strict_rejects_an_unknown_key_in_a_lenient_leaf_struct() {
        let dir = tempfile::tempdir().expect("tempdir");
        let yaml = dir.path().join("package.yaml");
        std::fs::write(&yaml, "metadata:\n  catalog: c\n  title: t\n  accessRights: PUBLIC\n  applicableLegislation: []\n  license: L\n  creator: []\n  healthCategory: []\ninternal:\n  pastVersoin: \"GDI-EE-UTARTU-20260409143052111\"\nfiles: []\nconfig:\n  mode: aggregated\n")
        .expect("write yaml");

        let err = load_package(&yaml, true).expect_err("--strict must reject the typo");
        let msg = err.to_string();
        assert!(
            msg.contains("does not recognise") && msg.contains("pastVersoin"),
            "must be the unknown-key rejection naming the key, not a parse error that merely \
             quotes the yaml: {msg}"
        );

        load_package(&yaml, false).expect("a plain load warns but still builds");
    }

    /// The property an allow-list has and a deny-list cannot: a `##` key nobody has
    /// invented yet does not survive.
    ///
    /// This is the test that discriminates the two designs. Extending a deny-list with
    /// `##bcftools_*` would pass a test that fed it a bcftools line and fail this one,
    /// because the carrier set is open-ended — `##GATKCommandLine`, `##DRAGENCommandLine`,
    /// `##source`, and whatever the next toolchain stamps.
    #[test]
    fn minimal_drops_an_unknown_header_key_carrying_identifiers() {
        let unknown =
            "##SomeToolNobodyHasWrittenYet=<cmd=\"call -s NA12878 /data/patients/c.vcf\">";
        assert_eq!(filter_header_line(unknown, HeaderPolicy::Minimal), None);
    }

    /// The real-world carrier: every mainstream caller stamps its command line, and that
    /// line holds both subject identifiers and internal filesystem paths.
    #[test]
    fn minimal_drops_tool_command_lines() {
        for line in [
            "##bcftools_viewCommand=view -s NA12878,NA12891 /data/patients/cohort.vcf.gz; Date=x",
            "##GATKCommandLine=<ID=HaplotypeCaller,CommandLine=\"-I /srv/subjects/x.bam\">",
            "##source=myPipeline-v3 /home/operator/run",
        ] {
            assert_eq!(
                filter_header_line(line, HeaderPolicy::Minimal),
                None,
                "must not ship: {line}"
            );
        }
    }

    /// What `Minimal` keeps: everything needed to interpret the parquet and reproduce the
    /// conversion. Dropping these would cost real provenance for no privacy gain.
    #[test]
    fn minimal_keeps_the_structural_keys() {
        for line in [
            "##fileformat=VCFv4.2",
            "##INFO=<ID=AF,Number=A,Type=Float,Description=\"Allele Frequency\">",
            "##FORMAT=<ID=GT,Number=1,Type=String,Description=\"Genotype\">",
            "##FILTER=<ID=PASS,Description=\"All filters passed\">",
            "##contig=<ID=chr21,length=46709983>",
            "##reference=GRCh38",
            "##assembly=GRCh38",
        ] {
            assert_eq!(
                filter_header_line(line, HeaderPolicy::Minimal),
                Some(line.to_owned()),
                "must be kept: {line}"
            );
        }
    }

    /// `#CHROM` is truncated under `Minimal` and kept whole under `WithIdentifiers` — the
    /// structured form of the sample list, which is what a consumer that wants identifiers
    /// actually wants (not a regex scrape of a command line).
    #[test]
    fn chrom_truncation_follows_the_policy() {
        let with_samples =
            "#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tNA12878\tNA12891";
        assert_eq!(
            filter_header_line(with_samples, HeaderPolicy::Minimal),
            Some("#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO".to_owned())
        );
        assert_eq!(
            filter_header_line(with_samples, HeaderPolicy::WithIdentifiers),
            Some(with_samples.to_owned())
        );
    }

    /// `WithIdentifiers` adds the structured identifier keys but still drops free text.
    #[test]
    fn with_identifiers_keeps_sample_lines_but_not_command_lines() {
        assert_eq!(
            filter_header_line("##SAMPLE=<ID=NA12878,Sex=F>", HeaderPolicy::WithIdentifiers),
            Some("##SAMPLE=<ID=NA12878,Sex=F>".to_owned())
        );
        assert_eq!(
            filter_header_line("##SAMPLE=<ID=NA12878,Sex=F>", HeaderPolicy::Minimal),
            None
        );
        assert_eq!(
            filter_header_line(
                "##bcftools_viewCommand=view -s NA12878 /data/x.vcf",
                HeaderPolicy::WithIdentifiers
            ),
            None
        );
    }

    /// `Verbatim` means verbatim — including the infrastructure strings. A value that
    /// claimed "full" while silently scrubbing would be unverifiable, which is exactly what
    /// makes the other policies trustworthy.
    #[test]
    fn verbatim_keeps_everything_byte_for_byte() {
        for line in [
            "##bcftools_viewCommand=view -s NA12878 /data/patients/cohort.vcf.gz",
            "#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tNA12878",
            "##SomeToolNobodyHasWrittenYet=x",
        ] {
            assert_eq!(
                filter_header_line(line, HeaderPolicy::Verbatim),
                Some(line.to_owned()),
                "verbatim must not alter: {line}"
            );
        }
    }

    /// The packaged `#CHROM` line must not carry sample identifiers.
    ///
    /// Copying every `#` line verbatim would ship a genotyped source VCF's full sample list
    /// — subject identifiers, for human data — inside every package, to whoever operates
    /// the node. The node serves aggregate frequencies and never reads those columns, so
    /// there is nothing to trade off.
    #[test]
    fn chrom_header_sheds_sample_columns() {
        let with_samples =
            "#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tNA12878\tNA12891";
        assert_eq!(
            strip_sample_columns(with_samples),
            "#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO",
            "FORMAT and every sample column must be dropped"
        );

        // An aggregate VCF (no genotypes) is already just the eight fixed columns.
        let no_samples = "#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO";
        assert_eq!(strip_sample_columns(no_samples), no_samples);

        // Every other header line is meta-information and passes through untouched.
        let meta = "##INFO=<ID=AF,Number=A,Type=Float,Description=\"Allele Frequency\">";
        assert_eq!(strip_sample_columns(meta), meta);
    }

    /// The manifest's `files[]` records source-input provenance. Truncating each entry to
    /// its bare basename would make two distinct-content sources that share a basename
    /// indistinguishable (`chr1/data.vcf.gz` and `chr2/data.vcf.gz` both becoming
    /// `data.vcf.gz`), collapsing a provenance row an integrating system's registry reads.
    /// The vcfid guard only catches byte-identical inputs, so it never fires here.
    #[test]
    fn files_section_records_the_declared_relative_path_not_the_basename() {
        use gdi_node_standalone_core::model::package::{PackageFileEntry, PackageFileGroup};

        let tmp = tempfile::tempdir().expect("tempdir");
        let package_dir = tmp.path();
        for (dir, body) in [("chr1", b"one".as_slice()), ("chr2", b"two".as_slice())] {
            fs::create_dir_all(package_dir.join(dir)).expect("mkdir");
            fs::write(package_dir.join(dir).join("data.vcf.gz"), body).expect("write");
        }
        let groups = vec![PackageFileGroup {
            category: "VCF".to_owned(),
            reference: Some("GRCh38".to_owned()),
            precise_reference: None,
            files: vec![
                PackageFileEntry::Path("chr1/data.vcf.gz".to_owned()),
                PackageFileEntry::Path("chr2/data.vcf.gz".to_owned()),
            ],
        }];

        let out =
            build_files_section(&groups, package_dir, &HashMap::new()).expect("files section");

        let paths: Vec<&str> = out[0].files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            paths,
            vec!["chr1/data.vcf.gz", "chr2/data.vcf.gz"],
            "each source must keep its disambiguating declared path"
        );
        assert_ne!(
            out[0].files[0].sha256, out[0].files[1].sha256,
            "the two sources differ in content"
        );
    }

    /// A source outside the package.yaml's directory cannot be relativized, so its declared
    /// string is recorded verbatim: still unique, still truthful.
    #[test]
    fn files_section_keeps_an_out_of_tree_declared_path_verbatim() {
        use gdi_node_standalone_core::model::package::{PackageFileEntry, PackageFileGroup};

        let tmp = tempfile::tempdir().expect("tempdir");
        let outside = tmp.path().join("elsewhere");
        fs::create_dir_all(&outside).expect("mkdir");
        let abs = outside.join("cohort.vcf.gz");
        fs::write(&abs, b"x").expect("write");
        let package_dir = tmp.path().join("pkg");
        fs::create_dir_all(&package_dir).expect("mkdir");

        let groups = vec![PackageFileGroup {
            category: "VCF".to_owned(),
            reference: Some("GRCh38".to_owned()),
            precise_reference: None,
            files: vec![PackageFileEntry::Path(abs.display().to_string())],
        }];

        let out = build_files_section(&groups, &package_dir, &HashMap::new()).expect("files");

        assert_eq!(out[0].files[0].path, abs.display().to_string());
    }

    /// One-shot loopback FDP root serving a single-catalog Turtle body, returning the
    /// base URL (so `resolve_catalogs(.., refresh=true)` fetches a real catalog name).
    fn stub_fdp_root(catalog: &str) -> String {
        stub_fdp_root_body(format!(
            "@prefix ldp: <http://www.w3.org/ns/ldp#> .\n\
             <x> ldp:contains <https://n/fairdp/catalog/{catalog}> .\n"
        ))
    }

    /// One-shot loopback FDP root serving an arbitrary Turtle body.
    fn stub_fdp_root_body(body: String) -> String {
        use std::io::Write as _;
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("addr");
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = std::io::Read::read(&mut s, &mut buf);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes());
                let _ = s.flush();
            }
        });
        format!("http://{addr}")
    }

    #[test]
    fn file_sha256_and_size_computes_the_real_digest() {
        // The manifest's per-file sha256/size are the integrity anchor the node and
        // any integrating system trust. Assert the real digest of known content, so a constant /
        // empty / wrong-hash return (the whole function stubbed out) is caught —
        // `build_produces_valid_staging_dir` only checks the digest length.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("f.bin");
        fs::write(&path, b"abc").expect("write temp file");
        let (sha, size) = file_sha256_and_size(&path).expect("hash the temp file");
        // SHA-256("abc") — the standard NIST vector, lowercase 64-hex.
        assert_eq!(
            sha,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(size, 3);
    }

    #[test]
    fn now_unix_millis_returns_a_plausible_current_time() {
        // Kills the constant-return stubs: real wall-clock ms is far past 2023-11
        // (1_700_000_000_000). A non-flaky lower bound, not an exact-time assertion.
        assert!(now_unix_millis().expect("system clock") > 1_700_000_000_000);
    }

    #[test]
    fn build_epoch_rejects_far_future_but_allows_past_and_present() {
        // A fixed "now" keeps the test clock-independent.
        let now = 1_767_225_600_000u64;
        // A far-future epoch (2099) is rejected.
        let y2099 = 4_070_908_800_000u64;
        let err = validate_pinned_epoch(y2099, now).expect_err("2099 must be rejected");
        assert!(format!("{err}").contains("future"), "{err}");
        // The present passes.
        assert_eq!(validate_pinned_epoch(now, now).expect("present ok"), now);
        // Within the 24h skew tolerance passes (a timezone/NTP mistake).
        assert_eq!(
            validate_pinned_epoch(now + BUILD_EPOCH_FUTURE_SKEW_MS, now).expect("skew ok"),
            now + BUILD_EPOCH_FUTURE_SKEW_MS
        );
        // Just past the tolerance is rejected.
        assert!(validate_pinned_epoch(now + BUILD_EPOCH_FUTURE_SKEW_MS + 1, now).is_err());
        // Any past epoch is fine (a reproducible re-build pins an old timestamp).
        let y1970 = 0u64;
        assert_eq!(validate_pinned_epoch(y1970, now).expect("past ok"), y1970);
        assert_eq!(
            validate_pinned_epoch(now - 1, now).expect("past ok"),
            now - 1
        );
    }

    #[test]
    fn resolve_catalogs_without_refresh_returns_pinned() {
        // The stub must be live and serve a different catalog than the pinned one. An
        // unreachable stub would make this vacuous: deleting the `if !refresh { return
        // pinned }` early return would then fetch, fail, and fall back to `pinned`
        // (non-fatal), so the test would pass while every offline build silently gained a
        // network round-trip. A reachable stub serving `live-cat` makes the early return
        // falsifiable — without it, the fetched set wins.
        let base = stub_fdp_root("live-cat");
        let prof = Profile {
            service_url: Some(base),
            catalogs: BTreeMap::from([("goe".to_owned(), "goe".to_owned())]),
            ..Profile::default()
        };
        assert_eq!(
            resolve_catalogs(Some(&prof), false),
            prof.catalogs,
            "without --refresh-catalogs the pinned list is used and no fetch happens"
        );
        // No active profile → empty (structural-only) map, never a fetch.
        assert!(resolve_catalogs(None, false).is_empty());
    }

    #[test]
    fn resolve_catalogs_refresh_fetches_live_over_pinned() {
        let base = stub_fdp_root("live-cat");
        let prof = Profile {
            service_url: Some(base),
            catalogs: BTreeMap::from([("stale".to_owned(), "stale".to_owned())]),
            ..Profile::default()
        };
        let got = resolve_catalogs(Some(&prof), true);
        assert!(
            got.contains_key("live-cat"),
            "a live refresh must use the node's catalogs: {got:?}"
        );
        assert!(
            !got.contains_key("stale"),
            "a successful refresh must not keep the stale pinned entry: {got:?}"
        );
    }

    #[test]
    fn resolve_catalogs_refresh_returning_zero_falls_back_to_pinned() {
        // A refresh that succeeds but yields no catalogs must degrade like the other
        // three (no service_url, unreachable node, fetch error): warn and keep the pinned
        // list. An empty map propagates to the call site, where `.filter(|c| !c.is_empty())`
        // turns it into `None` — silently downgrading the build to structural-only
        // validation for an operator who explicitly asked for the stricter live check.
        let base = stub_fdp_root_body(
            "@prefix ldp: <http://www.w3.org/ns/ldp#> .\n<x> a ldp:Container .\n".to_owned(),
        );
        let prof = Profile {
            service_url: Some(base),
            catalogs: BTreeMap::from([("pinned".to_owned(), "pinned".to_owned())]),
            ..Profile::default()
        };
        assert_eq!(
            resolve_catalogs(Some(&prof), true),
            prof.catalogs,
            "a zero-catalog refresh must not disable catalog validation"
        );
    }

    #[test]
    fn resolve_catalogs_refresh_failure_falls_back_to_pinned() {
        // Unreachable node (port 1 → connection refused): a refresh must degrade to the
        // pinned allow-list, never fail the build.
        let prof = Profile {
            service_url: Some("http://127.0.0.1:1".to_owned()),
            catalogs: BTreeMap::from([("pinned".to_owned(), "pinned".to_owned())]),
            ..Profile::default()
        };
        assert_eq!(resolve_catalogs(Some(&prof), true), prof.catalogs);
    }

    #[test]
    fn resolve_catalogs_refresh_without_service_url_falls_back() {
        let prof = Profile {
            service_url: None,
            catalogs: BTreeMap::from([("pinned".to_owned(), "pinned".to_owned())]),
            ..Profile::default()
        };
        assert_eq!(resolve_catalogs(Some(&prof), true), prof.catalogs);
    }

    /// `clear_staging_target` keeps `--force` semantics on the final path while leaving it
    /// absent, which is what makes the atomic promotion safe.
    ///
    /// The build writes to a hidden `.{id}.partial` dir and renames it into place only
    /// after `manifest.json` is written. `StagingGuard` cannot cover an OOM kill, which is a
    /// SIGKILL and runs no destructor, so without that the final path could hold real
    /// parquet with no manifest: something that looks like a staging dir, that the node
    /// rejects at ingest, and that the next build refuses to overwrite without `--force`.
    #[test]
    fn clear_staging_target_honours_force_and_leaves_the_path_absent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let staging = tmp.path().join("GDI-EE-UTARTU-20260101000000002");

        // Absent target: nothing to do, and nothing created — the promotion needs it free.
        clear_staging_target(&staging, false, false).expect("absent target is fine");
        assert!(
            !staging.exists(),
            "the final path must be left absent, not created: rename() into an existing \
             directory would nest the build inside it"
        );

        // Existing target, no --force: refused, and left intact.
        fs::create_dir_all(&staging).expect("mkdir");
        let sentinel = staging.join("stale.txt");
        fs::write(&sentinel, b"stale").expect("write sentinel");
        let err =
            clear_staging_target(&staging, false, false).expect_err("must refuse existing dir");
        assert!(
            err.message.contains("already exists"),
            "guard message must say 'already exists': {}",
            err.message
        );
        assert!(
            sentinel.exists(),
            "a refused build must leave the existing artifact intact"
        );

        // A dry run must not touch the target under either flag. `--dry-run` promises to
        // write nothing durable: with `--force` it would delete the operator's dataset and
        // then write nothing in its place, and refusing without `--force` would point a
        // preflight straight at the flag that does the deleting.
        for force in [false, true] {
            clear_staging_target(&staging, force, true)
                .unwrap_or_else(|e| panic!("a dry run (force={force}) must not fail: {e}"));
            assert!(
                sentinel.exists(),
                "a dry run (force={force}) must leave the existing artifact intact"
            );
        }

        // With --force: removed entirely, so the promotion rename has a free path.
        clear_staging_target(&staging, true, false).expect("force clears the target");
        assert!(
            !staging.exists(),
            "--force must remove the target, not recreate it empty"
        );
    }

    #[test]
    fn prepare_staging_dir_refuses_existing_unless_forced() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let staging = tmp.path().join("GDI-EE-UTARTU-20260101000000001");

        // Fresh path: created.
        prepare_staging_dir(&staging, false).expect("create fresh staging dir");
        assert!(staging.is_dir());

        // Seed a sentinel so we can prove --force actually wipes + recreates.
        let sentinel = staging.join("stale.txt");
        fs::write(&sentinel, b"stale").expect("write sentinel");

        // Existing path, no --force: refused, naming the guard; dir left intact.
        let err = prepare_staging_dir(&staging, false).expect_err("must refuse existing dir");
        assert!(
            err.message.contains("already exists"),
            "guard message must say 'already exists': {}",
            err.message
        );
        assert!(
            sentinel.exists(),
            "a refused build must leave the staging dir intact"
        );

        // With --force: prior contents wiped and the dir recreated empty.
        prepare_staging_dir(&staging, true).expect("force recreates staging dir");
        assert!(staging.is_dir());
        assert!(
            !sentinel.exists(),
            "--force must wipe prior staging contents"
        );
    }

    #[test]
    fn open_vcf_text_reader_handles_plaintext_and_bgzip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let header = "##fileformat=VCFv4.1\n\
             #CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n\
             3\t100\t.\tT\tC\t.\t.\tAF=0.5\n";

        // Plaintext: lines come back verbatim.
        let plain = dir.path().join("plain.vcf");
        fs::write(&plain, header).expect("write plain vcf");
        let plain_lines: Vec<String> = open_vcf_text_reader(&plain)
            .expect("open plain")
            .lines()
            .map(|l| l.expect("read line"))
            .collect();
        assert_eq!(plain_lines.len(), 3);
        assert!(plain_lines[0].starts_with("##fileformat"));

        // Bgzipped (.vcf.gz): the magic-byte path decompresses to the same lines.
        let gz = dir.path().join("in.vcf.gz");
        {
            use std::io::Write as _;
            let f = fs::File::create(&gz).expect("create gz");
            let mut w = noodles_bgzf::io::Writer::new(f);
            w.write_all(header.as_bytes()).expect("write bgzip");
            w.finish().expect("finish bgzip");
        }
        let gz_lines: Vec<String> = open_vcf_text_reader(&gz)
            .expect("open gz")
            .lines()
            .map(|l| l.expect("read line"))
            .collect();
        assert_eq!(
            gz_lines, plain_lines,
            "bgzipped header must decompress to the same lines"
        );
    }

    /// A `ConvertOutput` carrying only the field `check_record_count_bounds` reads.
    fn output_with(number_of_records: u64) -> ConvertOutput {
        ConvertOutput {
            parquet_files: Vec::new(),
            number_of_records,
            diagnostics: Vec::new(),
            drops: gdi_node_standalone_core::convert::DropCounts::default(),
            suppression: gdi_node_standalone_core::convert::SuppressionCounts::default(),
            rows_emitted: 0,
            populations_recognized: Vec::new(),
            ignored_info_fields: Vec::new(),
            populations_without_af: Vec::new(),
            populations_emitted: Vec::new(),
            vcfid: "deadbeefdeadbeef".to_owned(),
            source_sha256: String::new(),
            source_size: 0,
        }
    }

    /// The split-layout warning fires on the shape it names — files from two VCFs in one
    /// block — and stays quiet when every block has a single writer.
    ///
    /// Asserted on the decision (`split_block_summary`) rather than on stderr, so the test
    /// says what the operator is told without capturing output.
    #[test]
    fn the_split_layout_note_fires_only_on_a_shared_block() {
        fn vcf(vcfid: &str, files: &[&str]) -> ConvertedVcf {
            let mut out = output_with(0);
            out.parquet_files = files.iter().map(PathBuf::from).collect();
            ConvertedVcf {
                source: PathBuf::from(format!("{vcfid}.vcf")),
                vcfid: vcfid.to_owned(),
                output: out,
            }
        }

        // One VCF per block: nothing to say.
        let single = [
            vcf(
                "aaaaaaaaaaaaaaaa",
                &["allele-freq.chr21.0.br1000.aaaaaaaaaaaaaaaa.parquet"],
            ),
            vcf(
                "bbbbbbbbbbbbbbbb",
                &["allele-freq.chr22.0.br1000.bbbbbbbbbbbbbbbb.parquet"],
            ),
        ];
        assert_eq!(split_block_summary(&single), None);

        // Two VCFs over the same positions: the expensive shape.
        let split = [
            vcf(
                "aaaaaaaaaaaaaaaa",
                &[
                    "allele-freq.chr21.0.br1000.aaaaaaaaaaaaaaaa.parquet",
                    "allele-freq.chr21.1.br1000.aaaaaaaaaaaaaaaa.parquet",
                ],
            ),
            vcf(
                "bbbbbbbbbbbbbbbb",
                &[
                    "allele-freq.chr21.0.br1000.bbbbbbbbbbbbbbbb.parquet",
                    "allele-freq.chr21.1.br1000.bbbbbbbbbbbbbbbb.parquet",
                ],
            ),
        ];
        let summary = split_block_summary(&split).expect("a shared block is reported");
        assert_eq!(summary.shared, 2, "both blocks are shared");
        assert_eq!(summary.blocks, 2);
        assert_eq!(summary.most, 2, "two files in the worst block");
        assert_eq!(summary.worst_block, "chr21.0.br1000");
    }

    /// `numberOfRecords` is recounted from the parquet, so it cannot be compared to itself.
    /// These bounds are what the conversion side can still assert at O(1) memory — and for a
    /// single VCF they collapse to equality, an exact end-to-end cross-check.
    #[test]
    fn record_count_bounds_accept_the_union_and_reject_a_disagreement() {
        fn vcf(n: u64) -> ConvertedVcf {
            ConvertedVcf {
                source: PathBuf::from("x.vcf"),
                vcfid: "deadbeefdeadbeef".to_owned(),
                output: output_with(n),
            }
        }

        // Per-population split: two VCFs over the same 2 loci. The union is 2, not 4.
        assert!(check_record_count_bounds(&[vcf(2), vcf(2)], 2).is_ok());
        // Per-chromosome split: disjoint loci, so the union is the sum.
        assert!(check_record_count_bounds(&[vcf(1), vcf(1)], 2).is_ok());
        // Any union between the two extremes is legal (partial overlap).
        assert!(check_record_count_bounds(&[vcf(3), vcf(2)], 4).is_ok());

        // Single VCF: the bounds collapse to equality, so a wrong recount is caught exactly.
        assert!(check_record_count_bounds(&[vcf(7)], 7).is_ok());
        assert!(check_record_count_bounds(&[vcf(7)], 6).is_err());
        assert!(check_record_count_bounds(&[vcf(7)], 8).is_err());

        // Below max: the union cannot be smaller than its largest member.
        assert!(check_record_count_bounds(&[vcf(3), vcf(2)], 2).is_err());
        // Above sum: the union cannot exceed the total number of loci offered.
        assert!(check_record_count_bounds(&[vcf(3), vcf(2)], 6).is_err());
    }

    /// A provider-controlled key name reaches the terminal neutralised, on the warning arm
    /// as on the `--strict` arm.
    #[test]
    fn the_unknown_keys_warning_neutralises_control_bytes_in_key_names() {
        let hostile = "\x1b[2J\x1b[1;31mFATAL: node key compromised".to_owned();
        let text = unknown_keys_detail(Path::new("package.yaml"), &[hostile, "typo".to_owned()]);
        assert!(
            !text.chars().any(char::is_control),
            "control bytes must not reach the terminal: {text:?}"
        );
        assert!(text.contains("FATAL: node key compromised") && text.contains("typo"));
    }
}
