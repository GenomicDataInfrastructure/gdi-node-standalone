//! The realistic sample fixture, end to end: the converter reads it as the generator meant it.
//!
//! `scripts/gen-sample-vcf.py` simulates a three-country cohort's counts over real `GRCh38`
//! chr21 sites, plus chrX, chrY and chrM, in the shape a `bcftools +fill-tags -S groups`
//! sites-only export has, and writes a sidecar of the aggregates it produced.
//! `scripts/tests/test_gen_sample_vcf.py` checks that the committed bytes are the generator's
//! and that every record is coherent. This test closes the loop from the other side: `preview`
//! and `convert` report those aggregates, recognise all twelve populations, ignore no field
//! and raise no warning. The fixture is 1 637 records long, where the COVID fixture the rest
//! of the suite is built on has one.
//!
//! The values asserted are read from the sidecar, not restated here: the generator writes
//! both, so a regenerated fixture brings its own expectations with it.

use gdi_node_standalone_core::convert::{ConvertOptions, Severity, convert_vcf, preview_vcf};

fn opts() -> ConvertOptions {
    ConvertOptions {
        assembly: "GRCh38".into(),
        block_range: 10_000_000,
        min_allele_count: 0,
    }
}

fn expected() -> serde_json::Value {
    serde_json::from_str(test_util::sample_expected_json()).expect("the sidecar is JSON")
}

fn as_u64(v: &serde_json::Value) -> u64 {
    v.as_u64().expect("an integer aggregate")
}

#[test]
fn preview_reports_the_generators_aggregates_with_no_warning() {
    let want = expected();
    let report = preview_vcf(&test_util::sample_vcf_path(), &opts()).expect("the sample previews");

    assert_eq!(report.number_of_records, as_u64(&want["records"]));
    assert_eq!(report.rows_emitted, as_u64(&want["rowsEmitted"]));
    assert_eq!(report.drops.input_records, as_u64(&want["records"]));
    assert_eq!(
        report.drops.total_dropped(),
        0,
        "every record is a primary-contig SNV/indel"
    );
    assert_eq!(
        report.drops.total_af_zero_variants,
        as_u64(&want["totalAfZeroVariants"]),
        "the monomorphic sites the export keeps"
    );
    assert_eq!(report.drops.ns_peak, Some(as_u64(&want["nsPeak"])));
    assert_eq!(report.drops.non_pass_records, 0);

    let populations: Vec<String> = want["populations"]
        .as_array()
        .expect("a population list")
        .iter()
        .map(|p| p.as_str().expect("a label").to_owned())
        .collect();
    assert_eq!(report.populations_recognized, populations);
    assert_eq!(report.populations_emitted, populations);
    assert_eq!(report.af_population_count, populations.len());
    assert!(
        report.ignored_info_fields.is_empty(),
        "a fill-tags export names every population field in the grammar: {:?}",
        report.ignored_info_fields
    );
    assert!(report.populations_without_af.is_empty());
    let warnings: Vec<_> = report
        .diagnostics
        .iter()
        .filter(|d| d.severity == Severity::Warning)
        .collect();
    assert!(
        warnings.is_empty(),
        "a conforming export warns about nothing: {warnings:?}"
    );
}

#[test]
fn convert_writes_every_row_the_generator_counted() {
    let want = expected();
    let dir = tempfile::tempdir().expect("tempdir");
    let out = convert_vcf(&test_util::sample_vcf_path(), dir.path(), &opts())
        .expect("the sample converts");

    assert_eq!(out.number_of_records, as_u64(&want["records"]));
    assert_eq!(out.rows_emitted, as_u64(&want["rowsEmitted"]));
    assert_eq!(
        out.drops.total_af_zero_variants,
        as_u64(&want["totalAfZeroVariants"])
    );
    assert_eq!(out.drops.ns_peak, Some(as_u64(&want["nsPeak"])));
    // Every contig the generator wrote reached parquet: the partition file names carry the
    // canonical contig (`allele-freq.chrX.<block>…`), and chrX/chrY span several 10 Mb blocks.
    let contigs = want["recordsPerContig"]
        .as_object()
        .expect("per-contig counts");
    let names: Vec<String> = out
        .parquet_files
        .iter()
        .map(|p| {
            p.file_name()
                .expect("a file name")
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    for contig in contigs.keys() {
        assert!(
            names
                .iter()
                .any(|n| n.starts_with(&format!("allele-freq.{contig}."))),
            "no partition for {contig} among {names:?}"
        );
    }
    assert!(names.len() >= contigs.len(), "{names:?}");
    assert!(
        out.diagnostics.iter().all(|d| d.severity == Severity::Note),
        "{:?}",
        out.diagnostics
    );
}

/// `gdi-sample.package.yaml` is documented as a `--strict`-clean package, so it must parse and
/// validate without a warning, which is what `--strict` fails on.
///
/// Its `numberOfUniqueIndividuals` restates the sidecar's `individuals`, so this also binds
/// the two together.
#[test]
fn the_sample_package_yaml_is_strict_clean_and_agrees_with_the_sidecar() {
    use gdi_node_standalone_core::model::package::PackageYaml;
    use gdi_node_standalone_core::validate_pkg::validate_package;

    let package: PackageYaml =
        serde_saphyr::from_str(test_util::sample_package_yaml()).expect("package.yaml parses");
    let report = validate_package(&package, None).expect("package.yaml validates");
    assert!(
        report.warnings.is_empty(),
        "the sample package must stay --strict-clean; warnings: {:?}",
        report.warnings
    );
    let individuals = as_u64(&expected()["individuals"]);
    let declared = serde_json::to_value(&package).expect("serialises")["metadata"]
        ["numberOfUniqueIndividuals"]
        .as_u64();
    assert_eq!(
        declared,
        Some(individuals),
        "numberOfUniqueIndividuals must equal the sidecar's `individuals`"
    );
}
