//! Criterion benchmark for the `g_variants` parquet scan path.
//!
//! [`scan_dataset`] is the read half of a query: [`select_files`] picks the candidate
//! partition files for the position window, then each is read with `read_matching_rows`
//! and the matches are accumulated into one `Vec<AlleleRow>`. `parquet_read` benches
//! `read_matching_rows` for a single file in isolation; this benches the multi-file
//! accumulate path a real `g_variants` query drives:
//!
//! * `scan_point` — a Sequence query hitting one variant in one block, and
//! * `scan_wide_range` — a Range query spanning every block, so the scan opens all
//!   partition files and accumulates every matching row (the heap-cost path the
//!   `max_query_rows` cap bounds).
//!
//! The dataset is converted once, outside the timed loop, so the fixture is fixed.
//!
//! Retention accounting is out of scope here: the scan runs against `UnboundedRetention`,
//! so the byte ceilings (`max_query_bytes` and the process-wide pool) are never charged
//! and only the row cap above is in play. That accounting is what turns a large scan into
//! a 503 rather than an allocation; a bench that shed under its own ceiling would measure
//! the ceiling. The two charging tests in `query.rs` cover it directly.
#![allow(
    clippy::disallowed_methods,
    reason = "test/bench code writes plain files: durability and atomicity are not properties under test"
)]

use std::hint::black_box;
use std::path::Path;

use criterion::{Criterion, criterion_group, criterion_main};
use gdi_node_standalone_beacon::query::{UnboundedRetention, scan_dataset};
use gdi_node_standalone_beacon::request::{Predicates, QueryKind};
use gdi_node_standalone_core::convert::{ConvertOptions, convert_vcf};
use gdi_node_standalone_core::parquet_io::DatasetDecryptor;
use gdi_node_standalone_core::validate_parquet::ParquetCaps;

const BLOCK_RANGE: u32 = 10_000_000;
/// Partitions, variants per partition, populations — sized so the wide-range scan
/// accumulates a realistic working set across several files.
const N_BLOCKS: usize = 6;
const VARIANTS_PER_BLOCK: usize = 800;
const N_POPS: usize = 8;

/// A 2-letter uppercase population code (`AA`, `AB`, …; the grammar's letters-only
/// form). `N_POPS` stays well under `26 * 26`.
fn pop_code(i: usize) -> String {
    let hi = u8::try_from(b'A' as usize + i / 26).unwrap_or(b'A');
    let lo = u8::try_from(b'A' as usize + i % 26).unwrap_or(b'A');
    format!("{}{}", hi as char, lo as char)
}

/// Convert a synthetic chr3 VCF straddling `N_BLOCKS` 10 Mb blocks into a fresh
/// tempdir, returning it. Each variant carries `AF`/`AC`/`AN` for `N_POPS`
/// populations, so a wide scan accumulates `N_BLOCKS × VARIANTS_PER_BLOCK × N_POPS`
/// rows. Deterministic.
fn multiblock_dataset() -> tempfile::TempDir {
    use std::fmt::Write as _;

    let mut vcf = String::from("##fileformat=VCFv4.1\n");
    for p in 0..N_POPS {
        let code = pop_code(p);
        let _ = write!(
            vcf,
            "##INFO=<ID=AF_{code},Number=A,Type=Float,Description=\"af\">\n\
             ##INFO=<ID=AC_{code},Number=A,Type=Integer,Description=\"ac\">\n\
             ##INFO=<ID=AN_{code},Number=1,Type=Integer,Description=\"an\">\n"
        );
    }
    vcf.push_str("##contig=<ID=3>\n#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n");
    for b in 0..N_BLOCKS {
        for v in 0..VARIANTS_PER_BLOCK {
            let pos = b * (BLOCK_RANGE as usize) + v + 1;
            let info: Vec<String> = (0..N_POPS)
                .map(|p| {
                    let code = pop_code(p);
                    format!("AF_{code}=0.1;AC_{code}=10;AN_{code}=100")
                })
                .collect();
            let _ = writeln!(vcf, "3\t{pos}\t.\tA\tG\t.\t.\t{}", info.join(";"));
        }
    }

    let dir = tempfile::tempdir().expect("tempdir for the multiblock dataset");
    let vcf_path = dir.path().join("multiblock.vcf");
    std::fs::write(&vcf_path, vcf).expect("write the multiblock vcf");
    convert_vcf(
        &vcf_path,
        dir.path(),
        &ConvertOptions {
            assembly: "GRCh38".into(),
            block_range: BLOCK_RANGE,
            min_allele_count: 0,
        },
    )
    .expect("convert the multiblock vcf to parquet");
    dir
}

fn scan(dir: &Path, kind: &QueryKind) -> usize {
    scan_dataset(
        dir,
        "3",
        BLOCK_RANGE,
        kind,
        &ParquetCaps::default(),
        &DatasetDecryptor::plaintext(),
        u64::MAX,
        &mut UnboundedRetention,
    )
    .expect("scan the dataset")
    .len()
}

fn bench_scan_dataset(c: &mut Criterion) {
    let tmp = multiblock_dataset();
    let dir = tmp.path();
    let mut group = c.benchmark_group("scan_dataset");

    // A point query: one block selected, one variant matched.
    let point = QueryKind::Sequence {
        pos: 2 * i64::from(BLOCK_RANGE),
        ref_: "A".into(),
        alt: "G".into(),
        predicates: Predicates::default(),
    };
    group.bench_function("scan_point", |b| {
        b.iter(|| black_box(scan(dir, black_box(&point))));
    });

    // A wide range over every block: all partition files opened, all matching rows
    // accumulated (the multi-file accumulate path the cap bounds).
    let wide = QueryKind::Range {
        start: 0,
        end: i64::try_from(N_BLOCKS * (BLOCK_RANGE as usize)).unwrap_or(i64::MAX),
        predicates: Predicates::default(),
    };
    group.bench_function("scan_wide_range", |b| {
        b.iter(|| black_box(scan(dir, black_box(&wide))));
    });

    group.finish();
}

criterion_group!(benches, bench_scan_dataset);
criterion_main!(benches);
