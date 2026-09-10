//! The `lint` command: an advisory, graded **quality report** over a built staging
//! directory or a `.tar.c4gh` package — distinct from `validate`'s binary structural
//! gate.
//!
//! `validate` answers "is this shippable?"; `lint` answers "is this good?" — it
//! consolidates recommended-metadata coverage, population coverage, the allele-
//! frequency distribution (AF=0 / AF≈1 / AC saturation), and low-AC exposure vs a
//! censoring threshold into one report a data controller can eyeball before
//! publishing. It never fails the build; it informs.
//! `--format json` emits the same report for CI gating and other machine consumers.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use gdi_node_standalone_core::convert::MAX_POPULATIONS;
use gdi_node_standalone_core::model::{Manifest, ManifestMetadata};
use gdi_node_standalone_core::parquet_io::{
    AlleleRow, DatasetDecryptor, PosWindow, read_matching_rows,
};
use gdi_node_standalone_core::popfield::TOTAL_POPULATION;
use gdi_node_standalone_core::s3_layout::is_data_file_name;
use gdi_node_standalone_core::validate_parquet::ParquetCaps;

use crate::ToolError;
use crate::cli::{LintArgs, OutputFormat};
use crate::scratch::Scratch;

/// AC strictly below this is flagged as low-allele-count exposure — the singleton /
/// rare-variant tier most relevant to a privacy floor. This is the lint's rare-cell
/// sensitivity, not the recommended k-anon floor: the recommended `[beacon].min_allele_count`
/// is 10 (≈2×k for k=5 individuals — see `node.quickstart.toml`), while the config default
/// is 0 (suppression off unless the operator opts in). Kept at 5 so the lint surfaces the
/// most-identifying cells without flooding on every below-recommended-floor row.
const LOW_AC_THRESHOLD: i32 = 5;

/// The advisory quality report. `--format json` emits its fields with a top-level
/// `schemaVersion: 1` merged in (via `output::versioned_value`), not the struct alone.
///
/// Serialized `camelCase`, like that envelope and every sibling report verb; without the
/// rename this struct would emit `dataset_id` and `low_ac_rows` beside `schemaVersion`. The
/// `populations` / `variant_types` maps are keyed by data (a population label, a variant
/// type), and `rename_all` does not rewrite map keys, so those are unaffected — which is
/// correct.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LintReport {
    /// The dataset id from the manifest.
    pub dataset_id: String,
    /// Advertised `numberOfRecords` (distinct variants).
    pub number_of_records: Option<u64>,
    /// Recommended metadata fields that are absent (provider should consider adding).
    pub recommended_absent: Vec<String>,
    /// Declared cohort size, if supplied.
    pub number_of_unique_individuals: Option<u64>,
    /// Total emitted allele-frequency rows across all populations.
    pub rows: usize,
    /// Site (row) count per population key.
    pub populations: BTreeMap<String, usize>,
    /// Row count per variant type (`SNP` / `MNP` / `INS` / `DEL` / `DELINS`).
    pub variant_types: BTreeMap<String, usize>,
    /// Rows whose `AF == 0` (a population in which the ALT was never observed —
    /// usually an artifact of how the source VCF was assembled).
    pub af_zero: usize,
    /// Rows whose `AF >= 0.9999` (near-fixed — the ALT is almost the reference).
    pub af_near_one: usize,
    /// Rows where `AC == AN` (saturated: every observed allele is the ALT).
    pub ac_eq_an: usize,
    /// The low-AC threshold used.
    pub low_ac_threshold: i32,
    /// Rows whose `AC` is below the threshold (rare-variant / singleton exposure).
    pub low_ac_rows: usize,
    /// The dataset serves only the aggregate `Total` population.
    ///
    /// Almost always a mistake: the provider's per-population INFO fields did not match
    /// the grammar (1000 Genomes `EUR_AF`, gnomAD `AF_nfe`), or a `minAlleleCount` floor
    /// erased every stratum. A genuinely unstratified dataset is the rare case.
    pub total_only: bool,
    /// What the build's `minAlleleCount` floor withheld, read from the manifest's
    /// per-VCF `conversion` provenance and summed. `None` when the manifest carries none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppression: Option<LintSuppression>,
    /// INFO field IDs the conversion grammar rejected, unioned across the source VCFs.
    /// A non-empty list next to `total_only` names the exact cause.
    pub ignored_info_fields: Vec<String>,
}

/// The build-time suppression totals, summed across a dataset's source VCFs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LintSuppression {
    /// Rows whose `AC` was below the floor.
    pub rows_below_floor: u64,
    /// Further rows the coherence collapse removed, regardless of their own `AC`.
    pub rows_collapsed_to_total: u64,
    /// Variant groups that lost at least one row to the collapse.
    pub variants_collapsed_to_total: u64,
}

/// Sum the per-VCF `conversion` provenance a manifest carries.
///
/// `None` when no file entry carries provenance (a package built without it, or a group
/// that is not VCF-only), so "unknown" is never rendered as "nothing was suppressed".
fn suppression_from(manifest: &Manifest) -> (Option<LintSuppression>, Vec<String>) {
    let stats: Vec<_> = manifest
        .files
        .iter()
        .flat_map(|g| &g.files)
        .filter_map(|e| e.conversion.as_ref())
        .collect();
    if stats.is_empty() {
        return (None, Vec::new());
    }
    let mut sup = LintSuppression {
        rows_below_floor: 0,
        rows_collapsed_to_total: 0,
        variants_collapsed_to_total: 0,
    };
    let mut ignored: BTreeSet<&str> = BTreeSet::new();
    for c in stats {
        sup.rows_below_floor = sup
            .rows_below_floor
            .saturating_add(c.suppressed.rows_below_floor);
        sup.rows_collapsed_to_total = sup
            .rows_collapsed_to_total
            .saturating_add(c.suppressed.rows_collapsed_to_total);
        sup.variants_collapsed_to_total = sup
            .variants_collapsed_to_total
            .saturating_add(c.suppressed.variants_collapsed_to_total);
        ignored.extend(c.discarded.ignored_info_fields.iter().map(String::as_str));
    }
    (Some(sup), ignored.into_iter().map(str::to_owned).collect())
}

/// Whether a `LocalizedText`/optional string-list metadata field is effectively
/// present.
fn has_keywords(meta: &ManifestMetadata) -> bool {
    meta.keywords.as_ref().is_some_and(|k| !k.is_empty())
}

/// Streaming fold of allele-frequency rows into the [`LintReport`] counters, so `lint`
/// can process a dataset one parquet file at a time instead of materialising every row
/// of every file at once (an unbounded peak on a multi-million-variant dataset).
#[derive(Default)]
struct LintAccumulator {
    rows: usize,
    populations: BTreeMap<String, usize>,
    variant_types: BTreeMap<String, usize>,
    af_zero: usize,
    af_near_one: usize,
    ac_eq_an: usize,
    low_ac_rows: usize,
}

/// Increment `key`'s counter, inserting it at 1 on first sight. Borrow-first, so a
/// repeated (tiny) population / variant-type key is not cloned once it has been seen.
fn bump(counts: &mut BTreeMap<String, usize>, key: &str) {
    if let Some(c) = counts.get_mut(key) {
        *c += 1;
    } else {
        counts.insert(key.to_owned(), 1);
    }
}

impl LintAccumulator {
    /// Fold one batch of rows (e.g. a single parquet file's worth) into the counters.
    fn fold(&mut self, rows: &[AlleleRow]) {
        for row in rows {
            self.rows += 1;
            bump(&mut self.populations, &row.population);
            bump(&mut self.variant_types, row.vt.as_str());
            if row.af == 0.0 {
                self.af_zero += 1;
            }
            if row.af >= 0.9999 {
                self.af_near_one += 1;
            }
            if let (Some(ac), Some(an)) = (row.ac, row.an)
                && ac == an
            {
                self.ac_eq_an += 1;
            }
            if row.ac.is_some_and(|ac| ac < LOW_AC_THRESHOLD) {
                self.low_ac_rows += 1;
            }
        }
    }

    /// Finalize into the report, joining the folded counters with the manifest fields.
    fn finalize(self, manifest: &Manifest) -> LintReport {
        let meta = &manifest.metadata;
        let mut recommended_absent = Vec::new();
        if !has_keywords(meta) {
            recommended_absent.push("keywords".to_owned());
        }
        if meta.number_of_unique_individuals.is_none() {
            recommended_absent.push("numberOfUniqueIndividuals".to_owned());
        }
        let total_only =
            self.populations.len() == 1 && self.populations.contains_key(TOTAL_POPULATION);
        let (suppression, ignored_info_fields) = suppression_from(manifest);
        LintReport {
            dataset_id: meta.dataset_id.clone(),
            number_of_records: meta.number_of_records,
            recommended_absent,
            number_of_unique_individuals: meta.number_of_unique_individuals,
            rows: self.rows,
            populations: self.populations,
            variant_types: self.variant_types,
            af_zero: self.af_zero,
            af_near_one: self.af_near_one,
            ac_eq_an: self.ac_eq_an,
            low_ac_threshold: LOW_AC_THRESHOLD,
            low_ac_rows: self.low_ac_rows,
            total_only,
            suppression,
            ignored_info_fields,
        }
    }
}

/// Build the report from a manifest + the dataset's allele-frequency rows. Pure: no
/// I/O, so it is unit-testable over synthetic input. (The `lint` command folds rows
/// file-by-file via `LintAccumulator` to bound memory; this convenience wraps the
/// same fold over an in-memory slice.)
#[must_use]
pub fn analyze(manifest: &Manifest, rows: &[AlleleRow]) -> LintReport {
    let mut acc = LintAccumulator::default();
    acc.fold(rows);
    acc.finalize(manifest)
}

/// Render a `key=count` histogram (sorted by key) as one line, sanitizing each
/// provider-controlled key for the terminal.
fn counts_line(counts: &BTreeMap<String, usize>) -> String {
    counts
        .iter()
        .map(|(k, n)| format!("{}={n}", crate::output::Untrusted(k)))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Render the report as a human-readable card.
fn render_text(r: &LintReport) {
    // Every string echoed below (`dataset_id`, population / variant-type labels, rejected
    // INFO field names) comes from the provider's manifest or parquet, so a crafted value
    // could inject terminal escapes and spoof a clean report. Route each through the shared
    // sanitizer. JSON output is unaffected (escaped).
    let clean = crate::output::sanitize_terminal;
    println!("dataset {}", clean(&r.dataset_id));
    println!(
        "  records: {}    individuals: {}",
        r.number_of_records
            .map_or_else(|| "?".to_owned(), |n| n.to_string()),
        r.number_of_unique_individuals
            .map_or_else(|| "(not declared)".to_owned(), |n| n.to_string()),
    );
    println!("  allele-frequency rows: {}", r.rows);
    if r.total_only {
        println!(
            "  ! this dataset serves only the aggregate `Total` population{}",
            if r.ignored_info_fields.is_empty() {
                String::new()
            } else {
                format!(
                    "; the conversion rejected these INFO fields: {}",
                    r.ignored_info_fields
                        .iter()
                        .map(|f| clean(f))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
        );
    }
    if let Some(s) = &r.suppression
        && (s.rows_below_floor > 0 || s.variants_collapsed_to_total > 0)
    {
        println!(
            "  build-time suppression: {} row(s) below the floor, {} more removed by collapsing {} variant(s) to Total",
            s.rows_below_floor, s.rows_collapsed_to_total, s.variants_collapsed_to_total
        );
    }
    if r.recommended_absent.is_empty() {
        println!("  recommended metadata: all present");
    } else {
        println!(
            "  recommended metadata absent: {}",
            r.recommended_absent.join(", ")
        );
    }
    println!(
        "  populations ({} of {} max): {}",
        r.populations.len(),
        MAX_POPULATIONS,
        counts_line(&r.populations)
    );
    println!("  variant types: {}", counts_line(&r.variant_types));
    println!(
        "  AF sanity: af=0 {} | af~1 {} | AC==AN {} | AC<{} {}",
        r.af_zero, r.af_near_one, r.ac_eq_an, r.low_ac_threshold, r.low_ac_rows
    );
}

/// Fold every `allele-freq.*.parquet` data file's rows into a [`LintReport`], reading one
/// file at a time so peak memory is a single file's rows rather than the whole dataset's
/// (which is unbounded on a large dataset).
fn analyze_streaming(dir: &Path, manifest: &Manifest) -> Result<LintReport, ToolError> {
    let caps = ParquetCaps::default();
    let window = PosWindow {
        lo: i64::MIN,
        hi: i64::MAX,
    };
    let decryptor = DatasetDecryptor::plaintext();
    let mut acc = LintAccumulator::default();
    let entries = std::fs::read_dir(dir)
        .map_err(|e| ToolError::user(format!("reading {}: {e}", dir.display())))?;
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        let is_data = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(is_data_file_name);
        if !is_data {
            continue;
        }
        let file_rows = read_matching_rows(&path, &caps, window, &|_, _, _, _| true, &decryptor)
            .map_err(|e| ToolError::user(format!("reading {}: {e}", path.display())))?;
        acc.fold(&file_rows);
        // `file_rows` is dropped here: only one file's rows are resident at a time.
    }
    Ok(acc.finalize(manifest))
}

/// Run `lint` over a built staging directory or a `.tar.c4gh` package.
///
/// A package is decrypted with the provider identity and safe-extracted to a scratch
/// dir (like `validate`), so `lint` works on the only artifact left after `package`
/// deletes the staging dir — rather than rejecting the `.tar.c4gh` with a misleading
/// "not a built dataset dir".
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) if the target has no readable `manifest.json`, a
/// package cannot be decrypted/extracted, or a data file cannot be read. (`--format`
/// is validated by clap before this runs.)
pub fn run(args: &LintArgs, config_path: Option<&Path>) -> Result<(), ToolError> {
    if args.path.is_file() {
        // A `.tar.c4gh` package: decrypt + extract to a scratch dir, then lint it. The
        // scratch (decrypted plaintext) is removed on drop / reaped on a later run.
        crate::output::note(&format!(
            "grading package {} (decrypt + extract to scratch)",
            args.path.display()
        ));
        let scratch = Scratch::new(&args.path)?;
        let dest = scratch.path().join("extracted");
        #[expect(
            clippy::disallowed_methods,
            reason = "scratch below a Scratch root that is chmod 0o700 on creation"
        )]
        std::fs::create_dir_all(&dest)
            .map_err(|e| ToolError::user(format!("cannot create {}: {e}", dest.display())))?;
        crate::pkgio::decrypt_and_extract_package(&args.path, &dest, config_path)?;
        return lint_dir(args, &dest);
    }
    lint_dir(args, &args.path)
}

/// Lint a materialized dataset directory (`manifest.json` + the parquet data files).
fn lint_dir(args: &LintArgs, dir: &Path) -> Result<(), ToolError> {
    // Capped: `dir` may be an untrusted, just-extracted package (a multi-GiB manifest fits
    // inside the extraction bound), so a bare `fs::read` here OOMs the operator's CLI. Same
    // 8 MiB cap the node and `inspect` apply.
    let manifest_bytes = gdi_node_standalone_core::ingest::read_manifest_bytes(dir).map_err(|e| {
        ToolError::user(format!(
            "{} is not a built dataset dir / .tar.c4gh package (no readable manifest.json): {e}",
            dir.display()
        ))
    })?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| ToolError::user(format!("manifest.json is not a valid manifest: {e}")))?;
    // Validate the provider-supplied datasetId with the same rule every other command uses,
    // before it is echoed anywhere: `lint` grades untrusted packages, so a control-laden id
    // would otherwise reach the terminal verbatim. (The `{:?}` Debug form escapes any
    // residual control bytes in the error itself.)
    if !gdi_node_standalone_core::id::is_valid_dataset_id(&manifest.metadata.dataset_id) {
        return Err(ToolError::user(format!(
            "manifest.json declares an invalid datasetId {:?}",
            manifest.metadata.dataset_id
        )));
    }
    crate::output::note(&format!(
        "grading dataset {} in {}",
        manifest.metadata.dataset_id,
        dir.display()
    ));
    crate::output::note(
        "scoring: recommended-metadata coverage, population coverage, AF/AC distribution, low-AC exposure",
    );
    let report = analyze_streaming(dir, &manifest)?;
    crate::output::note(&format!(
        "scored {} allele-frequency row(s); {} population(s), {} variant type(s)",
        report.rows,
        report.populations.len(),
        report.variant_types.len()
    ));

    match args.format {
        OutputFormat::Json => {
            let value = crate::output::versioned_value(&report)
                .map_err(|e| ToolError::user(format!("serializing report: {e}")))?;
            crate::output::emit_json(&value);
        }
        OutputFormat::Text => render_text(&report),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;
    use gdi_node_standalone_core::model::{Assembly, DatasetMode, LocalizedText, ManifestConfig};
    use gdi_node_standalone_core::variant::Vt;

    fn manifest(keywords: Option<Vec<String>>, individuals: Option<u64>) -> Manifest {
        Manifest {
            payload: None,
            metadata: ManifestMetadata {
                dataset_id: "GDI-EE-UTARTU-20260409143052837".to_owned(),
                catalog: "gdi-aggregated".to_owned(),
                title: LocalizedText::Plain("t".to_owned()),
                description: None,
                access_rights: "PUBLIC".to_owned(),
                applicable_legislation: vec![],
                license: "https://x".to_owned(),
                creator: vec![],
                health_category: vec![],
                keywords,
                number_of_unique_individuals: individuals,
                conforms_to: None,
                type_: None,
                legal_basis: None,
                is_referenced_by: None,
                other_identifier: None,
                contact_point: None,
                number_of_records: Some(2),
                populations: None,
            },
            files: vec![],
            internal: gdi_node_standalone_core::model::Internal::default(),
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

    #[test]
    fn a_total_only_dataset_is_flagged() {
        // Almost always a grammar mistake: the provider's per-population INFO fields did
        // not parse (1000 Genomes `EUR_AF`, gnomAD `AF_nfe`), or a floor erased them.
        let rows = vec![row("Total", Vt::Snp, 0.5, Some(100), Some(200))];
        let r = analyze(&manifest(None, None), &rows);
        assert!(r.total_only, "one population and it is Total");
    }

    /// Every key of `lint --format json` is `camelCase`, at every depth.
    ///
    /// Without the struct-level `rename_all`, `dataset_id` and `low_ac_rows` would sit
    /// beside the envelope's `schemaVersion` while the nested [`LintSuppression`] renders
    /// `camelCase`. The checker lives on [`crate::output`] so the sibling verb `preview`
    /// asserts the same contract with the same code.
    #[test]
    fn the_json_report_is_camel_case_at_every_depth() {
        let rows = vec![row("EE_F", Vt::Snp, 0.5, Some(100), Some(200))];
        let report = analyze(&manifest(None, Some(42)), &rows);
        let mut value = crate::output::versioned_value(&report).unwrap();

        // `populations` and `variantTypes` are keyed by data — a population label (`EE_F`)
        // and a variant type (`SNP`) read out of the dataset. `rename_all` does not rewrite
        // map keys and must not, so drop these before the walk rather than weaken it.
        let obj = value.as_object_mut().unwrap();
        let populations = obj.remove("populations");
        assert!(
            populations.is_some(),
            "expected a `populations` map to drop"
        );
        obj.remove("variantTypes");

        let offenders = crate::output::non_camel_keys(&value);
        assert!(
            offenders.is_empty(),
            "non-camelCase keys in `lint --format json`: {offenders:?}"
        );

        // Anti-vacuity: the renamed fields must actually be present, or an empty offender
        // list would just mean the report serialized to nothing interesting.
        assert!(
            value.get("datasetId").is_some() && value.get("lowAcRows").is_some(),
            "the report lacks the renamed fields, so a green result here is vacuous"
        );
    }

    #[test]
    fn a_multi_population_dataset_is_not_flagged() {
        let rows = vec![
            row("Total", Vt::Snp, 0.5, Some(100), Some(200)),
            row("EE", Vt::Snp, 0.4, Some(40), Some(100)),
        ];
        let r = analyze(&manifest(None, None), &rows);
        assert!(!r.total_only);
    }

    #[test]
    fn lint_surfaces_the_conversion_suppression_recorded_in_the_manifest() {
        // The provenance is in the packed manifest (only the node strips `files`), so a
        // provider linting their own package can see what the build withheld.
        let mut m = manifest(None, None);
        m.files = vec![gdi_node_standalone_core::model::FileGroup {
            category: "VCF".to_owned(),
            reference: Some("GRCh38".to_owned()),
            precise_reference: None,
            files: vec![gdi_node_standalone_core::model::FileEntry {
                path: "in.vcf".to_owned(),
                sha256: None,
                size: None,
                conversion: Some(conversion_stats(3, 4, 2, vec!["EUR_AF".to_owned()])),
            }],
        }];
        let rows = vec![row("Total", Vt::Snp, 0.5, Some(100), Some(200))];
        let r = analyze(&m, &rows);
        let sup = r.suppression.expect("provenance present");
        assert_eq!(sup.rows_below_floor, 3);
        assert_eq!(sup.rows_collapsed_to_total, 4);
        assert_eq!(sup.variants_collapsed_to_total, 2);
        assert_eq!(r.ignored_info_fields, ["EUR_AF"]);
    }

    #[test]
    fn a_manifest_without_provenance_reports_no_suppression() {
        let r = analyze(
            &manifest(None, None),
            &[row("Total", Vt::Snp, 0.5, None, None)],
        );
        assert!(r.suppression.is_none());
        assert!(r.ignored_info_fields.is_empty());
    }

    /// A `ConversionStats` with the given suppression counters and ignored fields.
    fn conversion_stats(
        below: u64,
        collapsed: u64,
        variants: u64,
        ignored: Vec<String>,
    ) -> gdi_node_standalone_core::model::ConversionStats {
        use gdi_node_standalone_core::model::{
            ConversionDiscarded, ConversionInput, ConversionOutput, ConversionStats,
            ConversionSuppressed,
        };
        ConversionStats {
            input: ConversionInput {
                records: 1,
                non_pass_records: 0,
                gvcf_reference_blocks: 0,
                populations_recognized: vec!["Total".to_owned()],
            },
            discarded: ConversionDiscarded {
                records_unsupported_contig: 0,
                records_no_supported_alt: 0,
                records_all_rows_withheld: 0,
                records_no_af: 0,
                alleles: 0,
                ignored_info_fields: ignored,
                populations_without_af: Vec::new(),
            },
            suppressed: ConversionSuppressed {
                rows_below_floor: below,
                rows_collapsed_to_total: collapsed,
                variants_collapsed_to_total: variants,
            },
            output: ConversionOutput {
                records: 1,
                records_emitted: 1,
                rows: 1,
                populations: vec!["Total".to_owned()],
            },
        }
    }

    fn row(pop: &str, vt: Vt, af: f32, ac: Option<i32>, an: Option<i32>) -> AlleleRow {
        AlleleRow {
            pos: 100,
            ref_: "T".to_owned(),
            alt: "C".to_owned(),
            vt,
            population: pop.to_owned(),
            af,
            ac,
            ac_hom: None,
            ac_het: None,
            ac_hemi: None,
            an,
        }
    }

    #[test]
    fn analyze_reports_coverage_and_af_sanity() {
        let rows = vec![
            row("Total", Vt::Snp, 0.085, Some(618), Some(8000)),
            row("FI_M", Vt::Snp, 0.0, Some(0), Some(40)), // af=0
            row("FI_F", Vt::Del, 1.0, Some(40), Some(40)), // af≈1 + AC==AN
            row("EE_M", Vt::Snp, 0.02, Some(2), Some(100)), // low-AC (2 < 5)
        ];
        // keywords present, individuals absent -> one recommended field flagged.
        let m = manifest(Some(vec!["covid".to_owned()]), None);
        let r = analyze(&m, &rows);

        assert_eq!(r.dataset_id, "GDI-EE-UTARTU-20260409143052837");
        assert_eq!(r.rows, 4);
        assert_eq!(
            r.recommended_absent,
            vec!["numberOfUniqueIndividuals".to_owned()]
        );
        assert_eq!(r.populations.len(), 4);
        assert_eq!(r.populations.get("FI_M"), Some(&1));
        assert_eq!(r.variant_types.get("SNP"), Some(&3));
        assert_eq!(r.variant_types.get("DEL"), Some(&1));
        assert_eq!(r.af_zero, 1);
        assert_eq!(r.af_near_one, 1);
        assert_eq!(r.ac_eq_an, 1);
        assert_eq!(r.low_ac_rows, 2); // af=0 row (AC=0) + EE_M (AC=2)
    }

    #[test]
    fn streaming_fold_equals_one_shot_analyze() {
        // The `lint` command folds each parquet file's rows into one `LintAccumulator`
        // (`analyze_streaming`); per-file folding must equal analyzing the concatenation,
        // or bounding memory would change the counts the report gives.
        let file_a = vec![
            row("Total", Vt::Snp, 0.0, Some(1), Some(10)),
            row("FI_M", Vt::Del, 1.0, Some(10), Some(10)),
        ];
        let file_b = vec![row("Total", Vt::Snp, 0.02, Some(2), Some(100))];
        let m = manifest(None, None);

        let mut acc = LintAccumulator::default();
        acc.fold(&file_a);
        acc.fold(&file_b);
        let streamed = acc.finalize(&m);

        let mut all = file_a.clone();
        all.extend(file_b.clone());
        let one_shot = analyze(&m, &all);

        assert_eq!(streamed.rows, 3);
        assert_eq!(streamed.rows, one_shot.rows);
        assert_eq!(streamed.populations, one_shot.populations);
        assert_eq!(streamed.variant_types, one_shot.variant_types);
        assert_eq!(streamed.af_zero, one_shot.af_zero);
        assert_eq!(streamed.ac_eq_an, one_shot.ac_eq_an);
        assert_eq!(streamed.low_ac_rows, one_shot.low_ac_rows);
    }

    #[test]
    fn analyze_flags_all_absent_recommended() {
        let r = analyze(&manifest(None, None), &[]);
        assert_eq!(
            r.recommended_absent,
            vec![
                "keywords".to_owned(),
                "numberOfUniqueIndividuals".to_owned()
            ]
        );
        assert_eq!(r.rows, 0);
    }

    fn write_manifest(dir: &std::path::Path, m: &Manifest) {
        std::fs::write(dir.join("manifest.json"), serde_json::to_vec(m).unwrap()).unwrap();
    }

    #[test]
    fn run_errors_when_manifest_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let err = run(
            &crate::cli::LintArgs {
                path: tmp.path().to_path_buf(),
                format: OutputFormat::Text,
            },
            None,
        )
        .unwrap_err();
        assert!(
            err.message.contains("no readable manifest.json"),
            "{}",
            err.message
        );
    }

    #[test]
    fn run_errors_on_unparseable_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("manifest.json"), b"not a manifest").unwrap();
        let err = run(
            &crate::cli::LintArgs {
                path: tmp.path().to_path_buf(),
                format: OutputFormat::Text,
            },
            None,
        )
        .unwrap_err();
        assert!(
            err.message.contains("not a valid manifest"),
            "{}",
            err.message
        );
    }

    #[test]
    fn run_text_and_json_render_a_manifest_only_dir() {
        let tmp = tempfile::tempdir().unwrap();
        write_manifest(tmp.path(), &manifest(None, None));
        run(
            &crate::cli::LintArgs {
                path: tmp.path().to_path_buf(),
                format: OutputFormat::Text,
            },
            None,
        )
        .unwrap();
        run(
            &crate::cli::LintArgs {
                path: tmp.path().to_path_buf(),
                format: OutputFormat::Json,
            },
            None,
        )
        .unwrap();
    }
}
