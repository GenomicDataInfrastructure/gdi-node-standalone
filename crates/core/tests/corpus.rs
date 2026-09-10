//! Real-data conformance corpus: 1000 Genomes chr21 and gnomAD v4.1 chr21.
//!
//! The hand-built fixtures cannot express real cardinality, real INFO-field variety, real
//! multi-allelic representation or real line width. The COVID fixture the population
//! machinery is otherwise tested against carries one data record. Real data exposes shapes no
//! synthetic fixture presents:
//!
//! * gnomAD's 240 INFO definitions collapse to 9, and its `XX`/`XY` sex karyotypes look like
//!   two-letter country codes to a naive grammar.
//! * 1000 Genomes' five super-populations use a suffix convention the grammar cannot read, so
//!   they are dropped and the dataset is `Total`-only.
//! * `AN = 0` sites emit no rows, and must still be accounted for by a drop counter.
//! * 76% of the gnomAD slice is non-`PASS` and is converted anyway.
//!
//! The corpus is not committed (hundreds of megabytes). `scripts/fetch-corpus.sh` fetches a
//! content-pinned slice of each; `scripts/ci-local.sh corpus` wires both together. Without
//! `GDI_CORPUS_DIR` these tests report that they were skipped and pass, so a developer
//! without network still runs the rest of the gate.

use std::path::PathBuf;

use gdi_node_standalone_core::convert::{
    ConvertOptions, DropCounts, PreviewReport, Severity, preview_vcf,
};

/// The corpus directory, or `None` when unset (the tests then skip).
///
/// # Panics
/// When `GDI_CORPUS_REQUIRED` is set but `GDI_CORPUS_DIR` is not. A fully-skipped run prints
/// the same summary as a real one (`test result: ok. 2 passed`), and the skip notice goes to
/// stderr, which cargo captures for a passing test. A caller that needs the corpus actually
/// exercised therefore cannot tell the two apart from the outside, so `scripts/ci-local.sh
/// corpus` sets `GDI_CORPUS_REQUIRED=1` and this turns the skip into a hard failure.
fn corpus_dir() -> Option<PathBuf> {
    let dir = std::env::var_os("GDI_CORPUS_DIR");
    assert!(
        !(dir.is_none() && std::env::var_os("GDI_CORPUS_REQUIRED").is_some()),
        "GDI_CORPUS_REQUIRED is set but GDI_CORPUS_DIR is not: the real-data corpus gate would \
         have silently skipped every test. Run scripts/ci-local.sh corpus (it fetches and exports \
         the directory), or unset GDI_CORPUS_REQUIRED to allow the offline skip."
    );
    Some(PathBuf::from(dir?))
}

/// Preview one corpus slice, or `None` when the corpus is absent.
fn preview(name: &str, assembly: &str) -> Option<PreviewReport> {
    let path = corpus_dir()?.join(name);
    assert!(
        path.is_file(),
        "GDI_CORPUS_DIR is set but {} is missing; run scripts/fetch-corpus.sh",
        path.display()
    );
    let opts = ConvertOptions {
        assembly: assembly.to_owned(),
        block_range: 10_000_000,
        min_allele_count: 0,
    };
    Some(preview_vcf(&path, &opts).expect("the corpus must convert cleanly"))
}

/// Announce a skip loudly, so an absent corpus never looks like a pass.
fn skipped(name: &str) {
    eprintln!("skipped {name}: set GDI_CORPUS_DIR (see scripts/fetch-corpus.sh)");
}

/// Every input record either emits rows or is dropped by exactly one drop class.
///
/// The identity is what makes silent record loss unshippable. A manifest can otherwise publish
/// an input count, an output count that is lower, and every `discarded.*` counter at zero,
/// and no output-versus-output cross-check can notice.
fn assert_accounting(drops: &DropCounts) {
    assert!(
        drops.accounting_holds(),
        "record accounting broken: {drops:?}"
    );
}

/// 1000 Genomes phase 3, `chr21`: `GRCh37`, unprefixed contig `21`, 2504 genotype columns, and
/// the suffix population convention (`EAS_AF`) that the grammar cannot read.
#[test]
fn thousand_genomes_chr21_slice() {
    let Some(report) = preview("kg.chr21.slice.vcf", "GRCh37") else {
        return skipped("thousand_genomes_chr21_slice");
    };

    // The metric is the last `_`-token (`EAS_AF`), so `parse_info_field` sees `EAS` and gives
    // up. All five super-populations are dropped and the dataset is `Total`-only. The warning
    // is what stands between a provider and a silently unstratified national dataset.
    assert_eq!(report.populations_emitted, ["Total"]);
    assert_eq!(report.recognized_fields, ["AC", "AF", "AN"]);
    assert_eq!(
        report.ignored_info_fields,
        ["AFR_AF", "AMR_AF", "EAS_AF", "EUR_AF", "SAS_AF"]
    );

    // Multi-allelic splitting inflates the distinct-allele count above the record count, so
    // no identity can link `numberOfRecords` to `input_records`. The accounting identity
    // below is therefore stated over records.
    assert_eq!(report.number_of_records, 7628);
    assert_eq!(report.rows_emitted, 7628);
    assert!(report.number_of_records > report.drops.records_emitted);

    let d = &report.drops;
    assert_eq!(d.input_records, 7582);
    assert_eq!(d.dropped_unsupported_contig, 0);
    assert_eq!(d.dropped_no_supported_alt, 5); // symbolic SV ALTs (<CN0>, <INS:ME:ALU>, ...)
    assert_eq!(d.dropped_all_rows_withheld, 0);
    assert_eq!(d.records_emitted, 7577);
    assert_eq!(d.non_pass_records, 0); // a wholly PASS call set
    assert_eq!(d.alleles_not_left_trimmed, 0);
    assert_accounting(d);

    // No AN=0 sites here, so nothing collapses and no population is AF-less.
    assert_eq!(report.suppression.variants_collapsed_to_total, 0);
    assert!(report.populations_without_af.is_empty());

    // `--strict` must fail: a dropped population is exactly what it exists to catch.
    let warnings: Vec<&str> = report
        .diagnostics
        .iter()
        .filter(|d| d.severity == Severity::Warning)
        .map(|d| d.message.as_str())
        .collect();
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(warnings[0].contains("ignored non-conforming INFO fields"));
}

/// gnomAD `v4.1` genomes, `chr21`: `GRCh38`, `chr` prefix, 240 INFO definitions, sites-only,
/// `AN = 0` sites, and 76% non-`PASS`.
#[test]
fn gnomad_v4_chr21_slice() {
    let Some(report) = preview("gnomad.chr21.slice.vcf", "GRCh38") else {
        return skipped("gnomad_v4_chr21_slice");
    };

    // 240 INFO definitions collapse to 3 (`AC`, `AF`, `AN` — the unstratified totals). Every
    // real ancestry stratum (`afr`, `nfe`, `eas`, `sas`, `fin`, `ami`, `amr`, `asj`, `mid`,
    // `remaining`) is dropped: the grammar wants a 2-letter uppercase country code and `afr`
    // is neither.
    assert_eq!(report.recognized_fields, ["AC", "AF", "AN"]);
    assert_eq!(report.ignored_info_fields.len(), 102);
    assert!(report.ignored_info_fields.contains(&"AF_nfe".to_owned()));
    assert!(report.ignored_info_fields.contains(&"AF_grpmax".to_owned()));

    // gnomAD's sex-karyotype suffixes (`AF_XX` / `AF_XY`) are two uppercase ASCII letters, so
    // a bare "2-letter uppercase" test reads them as country codes and the dataset advertises
    // `XX` and `XY` as ancestries beside real codes like `EE`/`FI`. That is a population axis
    // meaning something else, published to the federation. `is_country_code` deny-lists those
    // two tokens, so the six `AC`/`AF`/`AN` x `XX`/`XY` fields join the ignored set and only
    // `Total` survives. No record is dropped by this: it removes columns, not rows.
    assert_eq!(report.populations_emitted, ["Total"]);
    for f in ["AF_XX", "AF_XY", "AN_XX", "AN_XY", "AC_XX", "AC_XY"] {
        assert!(
            report.ignored_info_fields.contains(&f.to_owned()),
            "{f} is a sex karyotype, not a country: it must be ignored, not emitted as a \
             population axis"
        );
    }

    assert_eq!(report.number_of_records, 17707);

    let d = &report.drops;
    assert_eq!(d.input_records, 17822);
    assert_eq!(d.dropped_unsupported_contig, 0);
    assert_eq!(d.dropped_no_supported_alt, 0);
    // `AN = 0` sites: gnomAD omits `AF`, `AF_XX` and `AF_XY` entirely, so no population has a
    // defined frequency and the record emits nothing. Those records belong to `dropped_no_af`
    // and not to `dropped_all_rows_withheld`: this preview runs with the floor at its default
    // of 0, so the floor cannot have withheld anything. Keeping the two counters separate is
    // what makes the distinction visible.
    assert_eq!(d.dropped_no_af, 115);
    assert_eq!(
        d.dropped_all_rows_withheld, 0,
        "the floor is off in this preview, so it cannot have withheld anything"
    );
    assert_eq!(d.records_emitted, 17707);
    assert_accounting(d);

    // `AN = 0` is undefined, not withheld. Reading it as a withheld cell triggers the k-anon
    // collapse, which discards the siblings' valid rows to close a differencing channel that
    // does not exist: `Total - sum(present)` recovers 0, which `AN = 0` already publishes.
    assert_eq!(report.suppression.variants_collapsed_to_total, 0);
    assert_eq!(report.suppression.rows_collapsed_to_total, 0);
    assert!(
        report.populations_without_af.is_empty(),
        "AN=0 must not be reported as an AF-less population: {:?}",
        report.populations_without_af
    );

    // One row per record: `Total` is the only surviving population, so gnomAD chr21 has no
    // multi-population axis left and this corpus exercises single-population conversion only.
    // The sibling-collapse shape it can no longer witness (one stratum at `AN = 0` while
    // `Total` and another stratum are valid) is pinned synthetically by
    // `convert::tests::an_zero_population_is_undefined_not_withheld`, over real country codes.
    assert_eq!(report.rows_emitted, report.number_of_records);
    assert_eq!(report.rows_emitted, 17_707);

    // Sites-only, so the ALT column is already bi-allelic and minimal.
    assert_eq!(d.alleles_discarded, 0);
    assert_eq!(d.alleles_not_left_trimmed, 0);
    assert_eq!(report.number_of_records, d.records_emitted);

    // 76% of the slice failed gnomAD's own filters (`AC0`, `AS_VQSR`) and is converted anyway.
    // Nothing in `package.yaml` declares an intent to publish non-`PASS` calls, so this is a
    // warning: a provider must not ship allele frequencies for variants their own pipeline
    // rejected and still get a green `--strict`.
    assert_eq!(d.non_pass_records, 13521);
    let warnings: Vec<&str> = report
        .diagnostics
        .iter()
        .filter(|d| d.severity == Severity::Warning)
        .map(|d| d.message.as_str())
        .collect();
    assert_eq!(warnings.len(), 2, "{warnings:?}");
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("FILTER other than PASS"))
    );
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("ignored non-conforming INFO fields"))
    );
}
