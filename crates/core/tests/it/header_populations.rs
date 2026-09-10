//! `read_header_populations`: the header-only preflight derives the AF-bearing
//! populations and enforces the same header rules as conversion, without reading
//! records (so `build` can fail fast before writing any parquet).
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::io::Write as _;
use std::path::{Path, PathBuf};

use gdi_node_standalone_core::convert::read_header_populations;

const CHROM_LINE: &str = "#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";

fn write_vcf(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(body.as_bytes()).unwrap();
    path
}

#[test]
fn returns_af_bearing_populations_only() {
    let tmp = tempfile::tempdir().unwrap();
    // AF (Total) + AF_FI carry allele frequencies; AC_EE has no AF, so EE emits no
    // rows and must be excluded from the cap-relevant set.
    let vcf = write_vcf(
        tmp.path(),
        "a.vcf",
        &format!(
            "##fileformat=VCFv4.2\n\
             ##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
             ##INFO=<ID=AF_FI,Number=A,Type=Float,Description=\"af fi\">\n\
             ##INFO=<ID=AC_EE,Number=A,Type=Integer,Description=\"ac ee\">\n\
             ##contig=<ID=1>\n{CHROM_LINE}"
        ),
    );
    let mut pops = read_header_populations(&vcf).unwrap();
    pops.sort();
    assert_eq!(pops, vec!["FI".to_string(), "Total".to_string()]);
}

#[test]
fn preview_reports_af_population_count() {
    use gdi_node_standalone_core::convert::{ConvertOptions, preview_vcf};

    let tmp = tempfile::tempdir().unwrap();
    let vcf = write_vcf(
        tmp.path(),
        "p.vcf",
        &format!(
            "##fileformat=VCFv4.2\n\
             ##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
             ##INFO=<ID=AF_FI,Number=A,Type=Float,Description=\"af fi\">\n\
             ##INFO=<ID=AC_EE,Number=A,Type=Integer,Description=\"ac ee\">\n\
             ##contig=<ID=1>\n{CHROM_LINE}"
        ),
    );
    let opts = ConvertOptions {
        assembly: "GRCh38".to_owned(),
        block_range: 0,
        min_allele_count: 0,
    };
    let report = preview_vcf(&vcf, &opts).unwrap();
    // Total + FI carry AF; EE (AC only) is excluded from the cap-relevant count but
    // still appears in the recognized-population list.
    assert_eq!(report.af_population_count, 2);
    assert!(report.populations_recognized.contains(&"EE".to_string()));
}

#[test]
fn missing_af_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let vcf = write_vcf(
        tmp.path(),
        "noaf.vcf",
        &format!(
            "##fileformat=VCFv4.2\n\
             ##INFO=<ID=AC_FI,Number=A,Type=Integer,Description=\"ac fi\">\n\
             ##contig=<ID=1>\n{CHROM_LINE}"
        ),
    );
    let err = read_header_populations(&vcf).unwrap_err();
    assert!(
        format!("{err}").contains("No AF INFO fields found"),
        "unexpected error: {err}"
    );
}
