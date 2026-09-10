//! Golden test for the aggregated VCF -> Parquet conversion, anchored to the
//! checked-in COVID reference VCF (chr `3`, bare numeric contig, `GRCh38`,
//! sites-only, one site at 1-based POS 45823240 T>C).
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::path::PathBuf;

use arrow_array::{Array, Float32Array, Int32Array, StringArray};
use gdi_node_standalone_core::convert::{ConvertOptions, ConvertOutput, convert_vcf};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use test_util::covid;

/// One decoded parquet row.
#[derive(Debug, Clone)]
struct Row {
    pos: i32,
    r#ref: String,
    alt: String,
    vt: String,
    population: String,
    af: f32,
    ac: Option<i32>,
    ac_hom: Option<i32>,
    ac_het: Option<i32>,
    ac_hemi: Option<i32>,
    an: Option<i32>,
}

/// Read every row from every parquet file using the arrow parquet reader.
fn read_all_rows(files: &[PathBuf]) -> Vec<Row> {
    let mut rows = Vec::new();
    for path in files {
        let file = std::fs::File::open(path).unwrap();
        #[expect(
            clippy::disallowed_methods,
            reason = "test fixture: this reads a parquet the test itself just wrote, so the Pages-vs-Values distinction the ban exists for cannot arise; the ban targets production readers of untrusted parquet"
        )]
        let reader = ParquetRecordBatchReaderBuilder::try_new(file)
            .unwrap()
            .build()
            .unwrap();
        for batch in reader {
            let batch = batch.unwrap();
            let pos = col_i32(&batch, "POS");
            let ref_ = col_str(&batch, "REF");
            let alt = col_str(&batch, "ALT");
            let vt = col_str(&batch, "VT");
            let population = col_str(&batch, "POPULATION");
            let af = col_f32(&batch, "AF");
            let ac = col_opt_i32(&batch, "AC");
            let ac_hom = col_opt_i32(&batch, "AC_HOM");
            let ac_het = col_opt_i32(&batch, "AC_HET");
            let ac_hemi = col_opt_i32(&batch, "AC_HEMI");
            let an = col_opt_i32(&batch, "AN");
            for i in 0..batch.num_rows() {
                rows.push(Row {
                    pos: pos.value(i),
                    r#ref: ref_.value(i).to_string(),
                    alt: alt.value(i).to_string(),
                    vt: vt.value(i).to_string(),
                    population: population.value(i).to_string(),
                    af: af.value(i),
                    ac: opt(ac, i),
                    ac_hom: opt(ac_hom, i),
                    ac_het: opt(ac_het, i),
                    ac_hemi: opt(ac_hemi, i),
                    an: opt(an, i),
                });
            }
        }
    }
    rows
}

fn col_i32<'a>(batch: &'a arrow_array::RecordBatch, name: &str) -> &'a Int32Array {
    batch
        .column_by_name(name)
        .unwrap()
        .as_any()
        .downcast_ref::<Int32Array>()
        .unwrap()
}

fn col_opt_i32<'a>(batch: &'a arrow_array::RecordBatch, name: &str) -> &'a Int32Array {
    col_i32(batch, name)
}

fn col_f32<'a>(batch: &'a arrow_array::RecordBatch, name: &str) -> &'a Float32Array {
    batch
        .column_by_name(name)
        .unwrap()
        .as_any()
        .downcast_ref::<Float32Array>()
        .unwrap()
}

fn col_str<'a>(batch: &'a arrow_array::RecordBatch, name: &str) -> &'a StringArray {
    batch
        .column_by_name(name)
        .unwrap()
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap()
}

fn opt(arr: &Int32Array, i: usize) -> Option<i32> {
    if arr.is_null(i) {
        None
    } else {
        Some(arr.value(i))
    }
}

#[test]
fn converts_covid_reference_vcf() {
    let dir = tempfile::tempdir().unwrap();
    let vcf = test_util::covid_vcf_path();
    let out: ConvertOutput = convert_vcf(
        &vcf,
        dir.path(),
        &ConvertOptions {
            assembly: "GRCh38".into(),
            block_range: 10_000_000,
            min_allele_count: 0,
        },
    )
    .expect("convert ok");

    // chr3 (bare numeric contig), block 45823240 / 10_000_000 = 4.
    assert!(
        out.parquet_files.iter().any(|p| p
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("allele-freq.chr3.4.br10000000.")),
        "expected an allele-freq.chr3.4.br10000000.* file, got {:?}",
        out.parquet_files
    );

    let rows = read_all_rows(&out.parquet_files);

    // The "Total" row carries the global statistics.
    let total = rows
        .iter()
        .find(|r| r.pos == 45_823_239 /* 1-based 45823240 - 1 */ && r.population == "Total")
        .expect("Total row");
    assert_eq!(total.r#ref, "T");
    assert_eq!(total.alt, "C");
    assert_eq!(total.vt, "SNP");
    assert!((total.af - 0.077_25).abs() < 1e-6);
    assert_eq!(total.ac, Some(i32::try_from(covid::TOTAL_AC).unwrap()));
    assert_eq!(total.an, Some(i32::try_from(covid::TOTAL_AN).unwrap()));
    assert_eq!(total.ac_hom, Some(65));
    assert_eq!(total.ac_het, Some(552));
    assert_eq!(total.ac_hemi, Some(1));

    let fi_m = rows
        .iter()
        .find(|r| r.pos == 45_823_239 && r.population == "FI_M")
        .expect("FI_M row");
    assert!((f64::from(fi_m.af) - covid::FI_M_AF).abs() < 1e-6);
    assert_eq!(fi_m.ac, Some(i32::try_from(covid::FI_M_AC).unwrap()));
    assert_eq!(fi_m.an, Some(1400));

    // numberOfRecords = distinct (chr,POS,REF,ALT) = 1 for this single-site,
    // single-ALT file.
    assert_eq!(out.number_of_records, 1);

    // vcfid is the first 16 hex chars of the VCF file's SHA-256.
    assert_eq!(out.vcfid.len(), 16);
    assert!(out.vcfid.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn convert_is_byte_reproducible() {
    // Two conversions of the same VCF must produce byte-identical parquet, so the
    // manifest's per-file sha256 is stable across builds. The fixture has several
    // populations at one POS, and rows are sorted deterministically: without that sort
    // their order follows the source HashMap's per-process-random iteration and the bytes
    // differ between runs.
    let vcf = test_util::covid_vcf_path();
    let opts = ConvertOptions {
        assembly: "GRCh38".into(),
        block_range: 10_000_000,
        min_allele_count: 0,
    };
    let convert_once = || {
        let dir = tempfile::tempdir().unwrap();
        let out = convert_vcf(&vcf, dir.path(), &opts).expect("convert ok");
        let mut files = out.parquet_files.clone();
        files.sort();
        let names: Vec<String> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        let bytes: Vec<Vec<u8>> = files.iter().map(|p| std::fs::read(p).unwrap()).collect();
        (names, bytes)
    };
    let (names_a, bytes_a) = convert_once();
    let (names_b, bytes_b) = convert_once();
    assert_eq!(names_a, names_b, "same set of parquet files");
    assert_eq!(
        bytes_a, bytes_b,
        "parquet bytes must be identical across builds (reproducible)"
    );
}
