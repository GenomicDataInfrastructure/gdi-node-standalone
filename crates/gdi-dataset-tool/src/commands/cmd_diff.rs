//! `gdi-dataset-tool diff <A> <B>` — what changed between two builds of a dataset.
//!
//! `internal.pastVersion` records a predecessor but says nothing about what changed, so a
//! pipeline change that silently drops a population would ship unnoticed. This compares two
//! staging dirs and/or `.tar.c4gh` packages at the **manifest** level: the served
//! population set, the variant count, the disclosure floor, the assembly, and the
//! build-time suppression recorded in each package's conversion provenance.
//!
//! Manifest-level on purpose. The parquet rows are the bulk of a package and comparing
//! them would mean decrypting and scanning both in full; the manifest records per-file
//! digests, so a byte-level comparison is a digest comparison.
//!
//! Which digests are compared matters. `manifest.files` inventories the provider's source
//! VCF/BAM inputs, meaning what the dataset was built from rather than what the package
//! ships. Comparing those reports `identical` for two packages built from the same VCFs
//! with a different disclosure floor, column projection or converter version, which is the
//! case where an operator most needs to be told to redeploy. `manifest.payload` records the
//! packaged members, so it is compared in preference. A manifest that carries no such
//! section leaves only the sources, and the report says so
//! ([`DiffReport::comparison_basis`]) rather than quietly claiming a byte-level result.

use std::collections::BTreeSet;
use std::path::Path;

use gdi_node_standalone_core::model::Manifest;

use crate::ToolError;
use crate::cli::{DiffArgs, OutputFormat};
use crate::scratch::Scratch;

/// The differences between two dataset manifests.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffReport {
    /// The `datasetId` of the left/old package.
    pub old_dataset_id: String,
    /// The `datasetId` of the right/new package.
    pub new_dataset_id: String,
    /// `numberOfRecords` on each side (distinct variants).
    pub old_records: Option<u64>,
    /// `numberOfRecords` on each side (distinct variants).
    pub new_records: Option<u64>,
    /// Populations present in the new package but not the old.
    pub populations_added: Vec<String>,
    /// Populations present in the old package but not the new. A pipeline change that
    /// stops emitting a stratum lands here, which is the change most worth catching.
    pub populations_removed: Vec<String>,
    /// `config.minAlleleCount` on each side; a change silently alters what is published.
    pub old_min_allele_count: u32,
    /// `config.minAlleleCount` on each side.
    pub new_min_allele_count: u32,
    /// `config.assembly` on each side; a change makes the two incomparable.
    pub old_assembly: String,
    /// `config.assembly` on each side.
    pub new_assembly: String,
    /// INFO fields the new build rejected but the old did not — a header regression.
    pub newly_ignored_info_fields: Vec<String>,
    /// Rows the new build withheld to the floor, minus the old (may be negative).
    pub suppressed_rows_delta: i64,
    /// Data files present on both sides whose `sha256` differs — the content moved even
    /// when every summary field above is equal.
    pub files_changed: Vec<String>,
    /// Data files present only in the new package.
    pub files_added: Vec<String>,
    /// Data files present only in the old package. A file that disappears is a different
    /// event from one that was rewritten, so the two are reported separately.
    pub files_removed: Vec<String>,
    /// Which digest set `filesChanged`/`Added`/`Removed` came from.
    ///
    /// [`ComparisonBasis::Source`] means at least one manifest records no `payload`
    /// section, so those three fields describe the provider's upstream inputs, not the
    /// bytes served. `identical: true` on that basis is a weaker claim and must not be
    /// read as "the served data is unchanged".
    pub comparison_basis: ComparisonBasis,
    /// True when nothing this report models changed.
    pub identical: bool,
}

/// Sum a manifest's per-VCF suppression counters (below-floor + collapsed rows).
fn suppressed_rows(m: &Manifest) -> u64 {
    m.files
        .iter()
        .flat_map(|g| &g.files)
        .filter_map(|e| e.conversion.as_ref())
        .map(|c| {
            c.suppressed
                .rows_below_floor
                .saturating_add(c.suppressed.rows_collapsed_to_total)
        })
        .fold(0, u64::saturating_add)
}

/// The union of INFO field IDs a manifest's conversion provenance says were rejected.
fn ignored_info_fields(m: &Manifest) -> BTreeSet<&str> {
    m.files
        .iter()
        .flat_map(|g| &g.files)
        .filter_map(|e| e.conversion.as_ref())
        .flat_map(|c| c.discarded.ignored_info_fields.iter().map(String::as_str))
        .collect()
}

/// The population set a manifest advertises (empty when it declares none).
fn populations(m: &Manifest) -> BTreeSet<&str> {
    m.metadata
        .populations
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(String::as_str)
        .collect()
}

/// Compare two manifests. Pure: no I/O, so it is unit-testable over synthetic input.
#[must_use]
pub fn diff_manifests(old: &Manifest, new: &Manifest) -> DiffReport {
    let (old_pops, new_pops) = (populations(old), populations(new));
    let populations_added: Vec<String> = new_pops
        .difference(&old_pops)
        .map(|p| (*p).to_owned())
        .collect();
    let populations_removed: Vec<String> = old_pops
        .difference(&new_pops)
        .map(|p| (*p).to_owned())
        .collect();

    let (old_ignored, new_ignored) = (ignored_info_fields(old), ignored_info_fields(new));
    let newly_ignored_info_fields: Vec<String> = new_ignored
        .difference(&old_ignored)
        .map(|f| (*f).to_owned())
        .collect();

    let suppressed_rows_delta = i64::try_from(suppressed_rows(new)).unwrap_or(i64::MAX)
        - i64::try_from(suppressed_rows(old)).unwrap_or(i64::MAX);

    // Content, not just its summary. Every clause below compares a description of the data
    // (population set, record count, floor, assembly); two packages can agree on all of
    // them and still hold entirely different variants. Calling that "identical" invites the
    // one decision this command exists to inform — "nothing changed, no need to redeploy" —
    // to be made about data that did change. The per-file digests are already carried in
    // the manifest, so comparing them costs nothing.
    //
    // Prefer the packaged payload over the source inventory; see the module docs.
    let (comparison_basis, old_digests, new_digests) =
        match (payload_digests(old), payload_digests(new)) {
            (Some(o), Some(n)) => (ComparisonBasis::Payload, o, n),
            _ => (
                ComparisonBasis::Source,
                file_digests(old),
                file_digests(new),
            ),
        };
    let files_changed: Vec<String> = old_digests
        .iter()
        .filter(|(path, old_sha)| new_digests.get(*path).is_some_and(|new| new != *old_sha))
        .map(|(path, _)| (*path).to_owned())
        .collect();
    let files_added: Vec<String> = new_digests
        .keys()
        .filter(|p| !old_digests.contains_key(*p))
        .map(|p| (*p).to_owned())
        .collect();
    let files_removed: Vec<String> = old_digests
        .keys()
        .filter(|p| !new_digests.contains_key(*p))
        .map(|p| (*p).to_owned())
        .collect();

    let identical = populations_added.is_empty()
        && populations_removed.is_empty()
        && newly_ignored_info_fields.is_empty()
        && suppressed_rows_delta == 0
        && old.metadata.number_of_records == new.metadata.number_of_records
        && old.config.min_allele_count == new.config.min_allele_count
        && old.config.assembly.reference == new.config.assembly.reference
        && old_digests == new_digests;

    DiffReport {
        comparison_basis,
        old_dataset_id: old.metadata.dataset_id.clone(),
        new_dataset_id: new.metadata.dataset_id.clone(),
        old_records: old.metadata.number_of_records,
        new_records: new.metadata.number_of_records,
        populations_added,
        populations_removed,
        old_min_allele_count: old.config.min_allele_count,
        new_min_allele_count: new.config.min_allele_count,
        old_assembly: old.config.assembly.reference.clone(),
        new_assembly: new.config.assembly.reference.clone(),
        newly_ignored_info_fields,
        suppressed_rows_delta,
        files_changed,
        files_added,
        files_removed,
        identical,
    }
}

/// Read a manifest from a built staging dir or a `.tar.c4gh` package.
///
/// # Errors
///
/// Returns a [`ToolError`] when the target has no readable `manifest.json`, or when a
/// package cannot be decrypted.
fn load_manifest(target: &Path, config_path: Option<&Path>) -> Result<Manifest, ToolError> {
    if target.is_file() {
        let scratch = Scratch::new(target)?;
        let dest = scratch.path().join("extracted");
        #[expect(
            clippy::disallowed_methods,
            reason = "scratch below a Scratch root that is chmod 0o700 on creation"
        )]
        std::fs::create_dir_all(&dest)
            .map_err(|e| ToolError::user(format!("cannot create {}: {e}", dest.display())))?;
        crate::pkgio::decrypt_and_extract_package(target, &dest, config_path)?;
        return read_manifest(&dest);
    }
    read_manifest(target)
}

/// Parse `<dir>/manifest.json`.
fn read_manifest(dir: &Path) -> Result<Manifest, ToolError> {
    // Capped (see `cmd_lint::lint_dir`): `dir` may be an untrusted extracted package.
    let bytes = gdi_node_standalone_core::ingest::read_manifest_bytes(dir).map_err(|e| {
        ToolError::user(format!(
            "{} is not a built dataset dir / .tar.c4gh package (no readable manifest.json): {e}",
            dir.display()
        ))
    })?;
    let manifest: Manifest = serde_json::from_slice(&bytes)
        .map_err(|e| ToolError::user(format!("manifest.json is not a valid manifest: {e}")))?;
    // Gate the provider-supplied `datasetId` with the same rule every other command uses,
    // before it is echoed: `diff` prints both ids on its first line, so a control-laden id
    // from a package an operator is merely comparing would reach the terminal. Sanitizing
    // the render neuters the escapes; refusing the id also keeps the value out of the JSON
    // report and any downstream consumer of it. (The `{:?}` Debug form escapes any residual
    // control bytes in the error itself.)
    if !gdi_node_standalone_core::id::is_valid_dataset_id(&manifest.metadata.dataset_id) {
        return Err(ToolError::user(format!(
            "{} declares an invalid datasetId {:?}",
            dir.display(),
            manifest.metadata.dataset_id
        )));
    }
    Ok(manifest)
}

/// Run `diff`.
///
/// # Errors
///
/// Returns a [`ToolError`] when either target cannot be read as a dataset.
pub fn run(args: &DiffArgs, config_path: Option<&Path>) -> Result<(), ToolError> {
    let old = load_manifest(&args.old, config_path)?;
    let new = load_manifest(&args.new, config_path)?;
    let report = diff_manifests(&old, &new);

    match args.format {
        OutputFormat::Json => {
            let value = crate::output::versioned_value(&report)
                .map_err(|e| ToolError::user(format!("serializing diff report: {e}")))?;
            crate::output::emit_json(&value);
        }
        OutputFormat::Text => render_text(&report),
    }
    Ok(())
}

/// Render the diff as a human-readable card.
fn render_text(r: &DiffReport) {
    print!("{}", diff_text(r));
}

/// The human-readable card as a string.
///
/// Every string this emits — both `datasetId`s, the population names, the rejected INFO
/// field ids, the assembly labels, the data-file paths — comes out of a manifest inside a
/// package this command just decrypted, so a crafted value could inject terminal escapes
/// that overwrite the very lines the operator is reading. Each is routed through the shared
/// [`crate::output::sanitize_terminal`]. `--format json` is unaffected (JSON escaping
/// already neutralizes control bytes).
///
/// Returning a string instead of a run of `println!`s lets a test assert that guarantee over
/// the whole render (`cmd_inspect::member_files_line` follows the same pattern), rather than
/// leaving it to each new print site.
fn diff_text(r: &DiffReport) -> String {
    use std::fmt::Write as _;

    let clean = crate::output::sanitize_terminal;
    // A `, `-joined list of sanitized values.
    let clean_list = |v: &[String]| v.iter().map(|s| clean(s)).collect::<Vec<_>>().join(", ");
    let mut out = String::new();
    // `writeln!` into a String is infallible, so the results are discarded.
    let _ = writeln!(
        out,
        "{} -> {}",
        clean(&r.old_dataset_id),
        clean(&r.new_dataset_id)
    );
    // Printed on both paths: confined to the `identical` early return, a changed card would
    // list `data files added/removed` naming the provider's source VCFs with nothing saying
    // they are not the served bytes.
    if !r.identical {
        source_basis_caveat(&mut out, r);
    }
    if r.identical {
        let _ = writeln!(
            out,
            "  no change in the population set, variant count, floor, assembly, or any \
             data file digest"
        );
        source_basis_caveat(&mut out, r);
        return out;
    }
    let fmt = |n: Option<u64>| n.map_or_else(|| "?".to_owned(), |v| v.to_string());
    if r.old_records != r.new_records {
        let _ = writeln!(
            out,
            "  variants: {} -> {}",
            fmt(r.old_records),
            fmt(r.new_records)
        );
    }
    if !r.populations_removed.is_empty() {
        let _ = writeln!(
            out,
            "  ! populations removed: {}",
            clean_list(&r.populations_removed)
        );
    }
    if !r.populations_added.is_empty() {
        let _ = writeln!(
            out,
            "  populations added: {}",
            clean_list(&r.populations_added)
        );
    }
    if !r.newly_ignored_info_fields.is_empty() {
        let _ = writeln!(
            out,
            "  ! INFO fields newly rejected by the grammar: {}",
            clean_list(&r.newly_ignored_info_fields)
        );
    }
    if r.old_min_allele_count != r.new_min_allele_count {
        let _ = writeln!(
            out,
            "  minAlleleCount: {} -> {}",
            r.old_min_allele_count, r.new_min_allele_count
        );
    }
    if r.old_assembly != r.new_assembly {
        let _ = writeln!(
            out,
            "  ! assembly: {} -> {} (the two datasets are not comparable)",
            clean(&r.old_assembly),
            clean(&r.new_assembly)
        );
    }
    if r.suppressed_rows_delta != 0 {
        let _ = writeln!(
            out,
            "  rows withheld by the floor: {:+}",
            r.suppressed_rows_delta
        );
    }
    if !r.files_removed.is_empty() {
        let _ = writeln!(
            out,
            "  ! data files removed: {}",
            clean_list(&r.files_removed)
        );
    }
    if !r.files_added.is_empty() {
        let _ = writeln!(out, "  data files added: {}", clean_list(&r.files_added));
    }
    if !r.files_changed.is_empty() {
        let _ = writeln!(
            out,
            "  ! data file contents changed: {}",
            clean_list(&r.files_changed)
        );
    }
    out
}

/// The packaged-payload digests (`tar member -> sha256`), or `None` when this build
/// cannot use them: no `payload` section, or an `algorithm` it cannot compute.
///
fn payload_digests(m: &Manifest) -> Option<std::collections::BTreeMap<&str, &str>> {
    let payload = m.payload.as_ref()?;
    // An algorithm this build does not know is not a digest it can compare. Fall back to
    // the source inventory (and say so) rather than diffing opaque strings as if equal
    // meant identical.
    if !payload.algorithm_supported() {
        return None;
    }
    Some(
        payload
            .members
            .iter()
            .map(|(name, e)| (name.as_str(), e.sha256.as_str()))
            .collect(),
    )
}

/// Which digest set a report's `filesChanged`/`Added`/`Removed` were computed from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ComparisonBasis {
    /// `manifest.payload` — the bytes the packages actually ship. A byte-level result.
    Payload,
    /// `manifest.files` — the provider's source inventory, because at least one side
    /// records no payload. Two packages can agree here and still serve different data.
    Source,
}

/// Emit the source-basis caveat, when that is the basis.
///
/// On this basis the file lists name the provider's upstream inputs, not the packaged
/// data, so both an `identical` verdict and a list of changed files are weaker than they
/// read. One function so the two render paths cannot word it differently or drop one.
fn source_basis_caveat(out: &mut String, r: &DiffReport) {
    use std::fmt::Write as _;
    if r.comparison_basis != ComparisonBasis::Source {
        return;
    }
    let _ = writeln!(
        out,
        "  ! digests compared were the source inputs, not the packaged data: at least one \
         package records no usable `payload` section (it carries none, or declares a \
         digest algorithm this build cannot compute). Two packages built from the same \
         sources with a different floor, projection or tool version compare equal here, and \
         any file names listed are provider inputs rather than served data. Re-run `build` \
         on both to compare what is actually served."
    );
}

/// Stands in for a source entry that records no `sha256`.
///
/// Never equal to a real 64-hex digest, and — because `files_changed` compares the value
/// for the same path on both sides — two absent digests at one path still compare equal,
/// which is correct: nothing is known to have changed. What it prevents is two different
/// paths both reading `""`.
const ABSENT_DIGEST: &str = "<no digest recorded>";

/// The source-input digests, used only when a payload comparison is unavailable.
fn file_digests(m: &Manifest) -> std::collections::BTreeMap<&str, &str> {
    m.files
        .iter()
        .flat_map(|g| g.files.iter())
        // A file with no recorded digest maps to a per-path sentinel, never a shared "":
        // with `unwrap_or("")` two files that each recorded nothing would compare equal, so
        // two manifests carrying no source digests at all would report `identical: true` —
        // absence read as agreement, the one answer this command must never invent.
        .map(|f| {
            (
                f.path.as_str(),
                f.sha256.as_deref().unwrap_or(ABSENT_DIGEST),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use gdi_node_standalone_core::model::{
        Assembly, ConversionDiscarded, ConversionInput, ConversionOutput, ConversionStats,
        ConversionSuppressed, DatasetMode, FileEntry, FileGroup, Internal, LocalizedText,
        ManifestConfig, ManifestMetadata,
    };

    fn stats(below: u64, ignored: Vec<String>) -> ConversionStats {
        ConversionStats {
            input: ConversionInput {
                records: 1,
                non_pass_records: 0,
                gvcf_reference_blocks: 0,
                populations_recognized: vec![],
            },
            discarded: ConversionDiscarded {
                records_unsupported_contig: 0,
                records_no_supported_alt: 0,
                records_all_rows_withheld: 0,
                records_no_af: 0,
                alleles: 0,
                ignored_info_fields: ignored,
                populations_without_af: vec![],
            },
            suppressed: ConversionSuppressed {
                rows_below_floor: below,
                rows_collapsed_to_total: 0,
                variants_collapsed_to_total: 0,
            },
            output: ConversionOutput {
                records: 1,
                records_emitted: 1,
                rows: 1,
                populations: vec![],
            },
        }
    }

    /// Give a manifest a `payload` section with one member at `sha`.
    fn with_payload(mut m: Manifest, sha: &str) -> Manifest {
        let mut files = std::collections::BTreeMap::new();
        files.insert(
            "allele-freq.chr1.0.br0-1000.in.parquet".to_owned(),
            gdi_node_standalone_core::model::PayloadEntry {
                sha256: sha.to_owned(),
                size: 10,
            },
        );
        m.payload = Some(gdi_node_standalone_core::model::Payload {
            algorithm: "sha256".to_owned(),
            members: files,
        });
        m
    }

    /// Two packages built from identical source VCFs but shipping different parquet must
    /// not be reported as identical.
    ///
    /// `manifest.files` inventories the sources, so it agrees across such a pair — a
    /// different disclosure floor, column projection or converter version changes only what
    /// is shipped. Comparing sources alone would answer "identical", and the one decision
    /// this command exists to inform ("nothing changed, no need to redeploy") would be made
    /// about data that did change.
    #[test]
    fn a_changed_payload_is_detected_even_when_the_sources_are_identical() {
        let old = with_payload(manifest("A", 10, &["FIN"], 5, None), &"a".repeat(64));
        let new = with_payload(manifest("A", 10, &["FIN"], 5, None), &"b".repeat(64));
        // Both sides carry the same (empty) `files` source inventory, so a source-based
        // comparison cannot tell them apart — that is the point of the fixture.
        assert_eq!(file_digests(&old), file_digests(&new));

        let report = diff_manifests(&old, &new);
        assert_eq!(report.comparison_basis, ComparisonBasis::Payload);
        assert_eq!(
            report.files_changed,
            vec!["allele-freq.chr1.0.br0-1000.in.parquet".to_owned()],
            "a rewritten payload member must be reported as changed"
        );
        assert!(
            !report.identical,
            "two packages shipping different bytes are not identical"
        );
    }

    /// With no payload on either side the comparison falls back to sources, so it must say
    /// which basis it used — a weaker `identical` must not read as the stronger claim.
    #[test]
    fn a_package_without_a_payload_section_reports_the_weaker_basis() {
        let old = manifest("A", 10, &["FIN"], 5, None);
        let new = manifest("A", 10, &["FIN"], 5, None);
        assert_eq!(
            diff_manifests(&old, &new).comparison_basis,
            ComparisonBasis::Source
        );

        // One side alone is not enough: there is nothing to compare it against.
        let half = with_payload(manifest("A", 10, &["FIN"], 5, None), &"a".repeat(64));
        // The operator-facing card must say so, not just the JSON field.
        let text = diff_text(&diff_manifests(&old, &new));
        assert!(
            text.contains("source inputs, not the packaged data"),
            "a source-basis `identical` must be qualified in the text render; got:\n{text}"
        );

        assert_eq!(
            diff_manifests(&half, &new).comparison_basis,
            ComparisonBasis::Source,
            "a payload on only one side cannot support a byte-level verdict"
        );
    }

    fn manifest(
        id: &str,
        records: u64,
        pops: &[&str],
        floor: u32,
        conv: Option<ConversionStats>,
    ) -> Manifest {
        Manifest {
            payload: None,
            metadata: ManifestMetadata {
                dataset_id: id.to_owned(),
                catalog: "c".to_owned(),
                title: LocalizedText::Plain("t".to_owned()),
                description: None,
                access_rights: "PUBLIC".to_owned(),
                applicable_legislation: vec![],
                license: "https://x".to_owned(),
                creator: vec![],
                health_category: vec![],
                keywords: None,
                number_of_unique_individuals: None,
                conforms_to: None,
                type_: None,
                legal_basis: None,
                is_referenced_by: None,
                other_identifier: None,
                contact_point: None,
                number_of_records: Some(records),
                populations: Some(pops.iter().map(|p| (*p).to_owned()).collect()),
            },
            files: vec![FileGroup {
                category: "VCF".to_owned(),
                reference: Some("GRCh38".to_owned()),
                precise_reference: None,
                files: vec![FileEntry {
                    path: "in.vcf".to_owned(),
                    sha256: None,
                    size: None,
                    conversion: conv,
                }],
            }],
            internal: Internal::default(),
            config: ManifestConfig {
                mode: DatasetMode::Aggregated,
                block_range: 10_000_000,
                af_source: None,
                af_source_reference: None,
                min_allele_count: floor,
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
    fn a_silently_dropped_population_is_the_headline() {
        // The regression this command exists to catch: a pipeline change renames an INFO
        // field, the grammar rejects it, and a whole stratum stops being published.
        let old = manifest("A", 100, &["EE", "FI", "Total"], 0, Some(stats(0, vec![])));
        let new = manifest(
            "B",
            100,
            &["Total"],
            0,
            Some(stats(0, vec!["AF_FI".to_owned()])),
        );
        let d = diff_manifests(&old, &new);
        assert!(!d.identical);
        assert_eq!(d.populations_removed, ["EE", "FI"]);
        assert!(d.populations_added.is_empty());
        assert_eq!(d.newly_ignored_info_fields, ["AF_FI"]);
    }

    #[test]
    fn a_changed_floor_and_its_suppression_delta_are_reported() {
        let old = manifest("A", 100, &["Total"], 0, Some(stats(0, vec![])));
        let new = manifest("B", 100, &["Total"], 5, Some(stats(12, vec![])));
        let d = diff_manifests(&old, &new);
        assert_eq!(d.old_min_allele_count, 0);
        assert_eq!(d.new_min_allele_count, 5);
        assert_eq!(d.suppressed_rows_delta, 12);
        assert!(!d.identical);
    }

    /// Same metadata, different data must not report `identical`.
    ///
    /// Every other clause compares a description of the package — population set, record
    /// count, floor, assembly — and two builds can agree on all of them while holding
    /// entirely different variants. `identical` is the direct input to "nothing changed, no
    /// need to redeploy", so answering it from the summary alone invites that call to be
    /// made about data that did change.
    #[test]
    fn differing_file_digests_are_not_identical() {
        let mut a = manifest("A", 100, &["EE", "Total"], 0, Some(stats(0, vec![])));
        let mut b = manifest("B", 100, &["EE", "Total"], 0, Some(stats(0, vec![])));
        set_digest(&mut a, "sha256:aaaa");
        set_digest(&mut b, "sha256:bbbb");

        let d = diff_manifests(&a, &b);
        assert!(
            !d.identical,
            "packages whose data files differ must not be reported identical"
        );

        // ...and the same digest on both sides still compares equal.
        set_digest(&mut b, "sha256:aaaa");
        assert!(diff_manifests(&a, &b).identical);
    }

    #[test]
    fn a_digest_only_change_names_the_files_that_changed() {
        // A digest-only change must name the files that moved. Reporting
        // `identical: false` with every displayed value equal, and no line saying what
        // changed, is the one output that makes an operator distrust the tool.
        let mut a = manifest("A", 100, &["EE", "Total"], 0, Some(stats(0, vec![])));
        let mut b = manifest("B", 100, &["EE", "Total"], 0, Some(stats(0, vec![])));
        set_digest(&mut a, "sha256:aaaa");
        set_digest(&mut b, "sha256:bbbb");

        let d = diff_manifests(&a, &b);
        assert_eq!(
            d.files_changed,
            vec!["in.vcf".to_owned()],
            "the file whose content moved must be named"
        );
        assert!(d.files_added.is_empty() && d.files_removed.is_empty());

        // A file that disappears is a different event from one that was rewritten.
        let mut c = manifest("C", 100, &["EE", "Total"], 0, Some(stats(0, vec![])));
        set_digest(&mut c, "sha256:aaaa");
        c.files[0].files.clear();
        let d = diff_manifests(&a, &c);
        assert_eq!(d.files_removed, vec!["in.vcf".to_owned()]);
        assert!(d.files_changed.is_empty() && d.files_added.is_empty());

        // ...and identical digests name nothing.
        set_digest(&mut b, "sha256:aaaa");
        let d = diff_manifests(&a, &b);
        assert!(d.identical && d.files_changed.is_empty());
    }

    /// Set the (single) data file's content digest.
    fn set_digest(m: &mut Manifest, digest: &str) {
        for group in &mut m.files {
            for file in &mut group.files {
                file.sha256 = Some(digest.to_owned());
            }
        }
    }

    /// The text card must not be able to carry an escape sequence out of a package.
    ///
    /// Every field below is provider-controlled and lands in the render verbatim, on the
    /// operator's terminal, from a package `diff` decrypted for them. The escape here is the
    /// realistic one: erase the screen (`\x1b[2J`), home the cursor (`\x1b[H`) and print a
    /// reassuring line, so the `! populations removed` warning that is the reason to
    /// run `diff` never reaches the eye that asked for it.
    #[test]
    fn the_text_render_strips_escapes_from_every_provider_string() {
        let hostile = "\x1b[2Jno change\r";
        let mut old = manifest("A", 100, &[hostile, "Total"], 0, Some(stats(0, vec![])));
        let mut new = manifest(
            "B",
            200,
            &["Total"],
            5,
            Some(stats(3, vec![hostile.to_owned()])),
        );
        old.metadata.dataset_id = format!("OLD{hostile}");
        new.metadata.dataset_id = format!("NEW{hostile}");
        new.config.assembly.reference = hostile.to_owned();
        set_digest(&mut old, "sha256:aaaa");
        set_digest(&mut new, "sha256:bbbb");
        new.files[0].files[0].path = hostile.to_owned();

        let text = diff_text(&diff_manifests(&old, &new));

        assert!(
            text.chars().all(|c| c == '\n' || !c.is_control()),
            "no control byte other than the line separator may survive: {text:?}"
        );
        // ...and every field is still shown, inert: nothing the operator reads the card for
        // silently disappears with the escape.
        //
        // Derived from the sanitizer rather than spelled out, because this test is about
        // routing every provider string through it — not about what it does. A golden here
        // duplicated the sanitizer's rule and broke when that rule changed (control bytes
        // became a space instead of being dropped), which said nothing about this card.
        // `output`'s own tests pin the substitution itself.
        let inert = crate::output::sanitize_terminal(hostile);
        let inert = inert.as_str();
        assert!(
            text.contains(&format!("OLD{inert} -> NEW{inert}")),
            "{text}"
        );
        assert!(
            text.contains(&format!("populations removed: {inert}")),
            "{text}"
        );
        assert!(
            text.contains(&format!("newly rejected by the grammar: {inert}")),
            "{text}"
        );
        assert!(
            text.contains(&format!("assembly: GRCh38 -> {inert}")),
            "{text}"
        );
        assert!(text.contains("data files removed: in.vcf"), "{text}");
        assert!(
            text.contains(&format!("data files added: {inert}")),
            "{text}"
        );
    }

    /// A manifest whose `datasetId` is not a dataset id must be refused, not compared.
    ///
    /// `lint` runs this gate on the same untrusted input; `diff` prints both ids on its
    /// first line and emits them in `--format json`, and ran no gate at all.
    #[test]
    fn read_manifest_rejects_an_invalid_dataset_id() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path();
        let write = |m: &Manifest| {
            std::fs::write(
                dir.join("manifest.json"),
                serde_json::to_vec(m).expect("serialize manifest"),
            )
            .expect("write manifest");
        };

        let mut m = manifest(
            "GDI-EE-UTARTU-20260409143052837",
            1,
            &["Total"],
            0,
            Some(stats(0, vec![])),
        );
        write(&m);
        read_manifest(dir).expect("a well-formed id is accepted");

        m.metadata.dataset_id = "GDI-EE-UTARTU-2026\x1b[2Jok".to_owned();
        write(&m);
        let err = read_manifest(dir).expect_err("a control-laden datasetId must be refused");
        assert!(
            err.message.contains("invalid datasetId"),
            "the refusal must name what it rejected; got: {}",
            err.message
        );
        assert!(
            !err.message.contains('\x1b'),
            "the error itself must not re-emit the escape: {:?}",
            err.message
        );
    }

    #[test]
    fn two_identical_builds_report_no_change() {
        let a = manifest("A", 100, &["EE", "Total"], 0, Some(stats(0, vec![])));
        let b = manifest("B", 100, &["EE", "Total"], 0, Some(stats(0, vec![])));
        let d = diff_manifests(&a, &b);
        assert!(
            d.identical,
            "only the datasetId differs, and that is expected"
        );
    }
}
