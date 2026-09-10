//! Criterion benchmark for the VCF -> Parquet conversion path.
//!
//! Times [`convert_vcf`] end to end (header parse, per-record INFO parse + value
//! validation, partition + sort, parquet encode + write) over two fixtures, so
//! conversion throughput is tracked alongside the read path (`parquet_read`):
//!
//! * the checked-in single-variant COVID fixture, and
//! * a generated multi-population, many-variant VCF (the realistic aggregated shape).
//!
//! Each conversion writes into a fresh tempdir inside the timed closure (a convert
//! must write parquet); the input VCFs are built once, outside the timed loop.
#![allow(
    clippy::disallowed_methods,
    reason = "test/bench code writes plain files: durability and atomicity are not properties under test"
)]

use std::hint::black_box;
use std::path::{Path, PathBuf};

use criterion::{Criterion, criterion_group, criterion_main};
use gdi_node_standalone_core::convert::{
    ConvertOptions, convert_vcf, convert_vcf_group, convert_vcf_with_worker_pool, preview_vcf,
};
use noodles_vcf as vcf;

/// Read every record (header plus the `read_record` loop) with no processing, isolating the
/// bare noodles parse cost.
///
/// `preview − scan_only` is the sequential per-record processing cost: stage-A extract,
/// stage-B INFO parse, emit. `convert` runs that emit and the encode on the worker pool, so it
/// lands near `preview` once the encode is hidden behind the parallel emit.
fn scan_only(path: &std::path::Path) -> u64 {
    let mut reader = vcf::io::reader::Builder::default()
        .build_from_path(path)
        .expect("open vcf");
    let _header = reader.read_header().expect("read header");
    let mut record = vcf::Record::default();
    let mut n = 0u64;
    while reader.read_record(&mut record).expect("read_record") != 0 {
        n += 1;
    }
    n
}

/// Synthetic multi-population VCF scale (matches the `parquet_read` synthetic size).
const N_VARIANTS: usize = 2000;
const N_POPS: usize = 16;

/// A 2-letter uppercase population code (`AA`, `AB`, … — the letters-only form the
/// popfield grammar recognizes, as in the converter's own tests). `N_POPS` stays
/// well under `26 * 26`.
fn pop_code(i: usize) -> String {
    let hi = u8::try_from(b'A' as usize + i / 26).unwrap_or(b'A');
    let lo = u8::try_from(b'A' as usize + i % 26).unwrap_or(b'A');
    format!("{}{}", hi as char, lo as char)
}

/// Write a synthetic aggregated VCF — `N_VARIANTS` ascending positions on chr3, each
/// carrying `AF`/`AC`/`AN` for `N_POPS` populations — into `dir`, returning its path.
/// Deterministic.
fn synthetic_vcf(dir: &Path) -> PathBuf {
    use std::fmt::Write as _;

    let mut vcf = String::from("##fileformat=VCFv4.1\n");
    for p in 0..N_POPS {
        let code = pop_code(p);
        // write! to a String is infallible; bind the must-use result to `_`.
        let _ = write!(
            vcf,
            "##INFO=<ID=AF_{code},Number=A,Type=Float,Description=\"af\">\n\
             ##INFO=<ID=AC_{code},Number=A,Type=Integer,Description=\"ac\">\n\
             ##INFO=<ID=AN_{code},Number=1,Type=Integer,Description=\"an\">\n"
        );
    }
    vcf.push_str("##contig=<ID=3>\n#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n");
    for v in 0..N_VARIANTS {
        let pos = 1_000_000 + v;
        let info: Vec<String> = (0..N_POPS)
            .map(|p| {
                let code = pop_code(p);
                format!("AF_{code}=0.1;AC_{code}=10;AN_{code}=100")
            })
            .collect();
        let _ = writeln!(vcf, "3\t{pos}\t.\tA\tG\t.\t.\t{}", info.join(";"));
    }
    let path = dir.join("synthetic.vcf");
    std::fs::write(&path, vcf).expect("write the synthetic vcf");
    path
}

/// Multi-block synthetic scale: `N_BLOCKS` partitions × `VARIANTS_PER_BLOCK`
/// variants × `N_POPS` populations. Spreads variants across several 10 Mb blocks so the
/// conversion writes many partition files (the realistic whole-chromosome shape),
/// exercising the per-partition sort + parquet (zstd) encode + write path that a
/// single-partition fixture does not.
const N_BLOCKS: usize = 8;
const VARIANTS_PER_BLOCK: usize = 1500;

/// Write a synthetic aggregated VCF whose `N_BLOCKS × VARIANTS_PER_BLOCK` ascending
/// positions on chr3 straddle `N_BLOCKS` 10 Mb blocks, each carrying `AF`/`AC`/`AN`
/// for `N_POPS` populations. Deterministic.
fn synthetic_multiblock_vcf(dir: &Path) -> PathBuf {
    synthetic_multiblock_n(dir, "multiblock.vcf", N_BLOCKS)
}

/// As [`synthetic_multiblock_vcf`], but with an explicit block count + file name (so a
/// "double-wide" VCF — twice the blocks/variants — can be compared against two normal
/// VCFs converted concurrently).
fn synthetic_multiblock_n(dir: &Path, name: &str, n_blocks: usize) -> PathBuf {
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
    for b in 0..n_blocks {
        for v in 0..VARIANTS_PER_BLOCK {
            // Block `b` spans [b·10Mb, (b+1)·10Mb); +1 keeps POS >= 1.
            let pos = b * 10_000_000 + v + 1;
            let info: Vec<String> = (0..N_POPS)
                .map(|p| {
                    let code = pop_code(p);
                    format!("AF_{code}=0.1;AC_{code}=10;AN_{code}=100")
                })
                .collect();
            let _ = writeln!(vcf, "3\t{pos}\t.\tA\tG\t.\t.\t{}", info.join(";"));
        }
    }
    let path = dir.join(name);
    std::fs::write(&path, vcf).expect("write the multiblock vcf");
    path
}

/// Default `GRCh38` / 10Mb-block / no-floor convert options.
fn opts() -> ConvertOptions {
    ConvertOptions {
        assembly: "GRCh38".into(),
        block_range: 10_000_000,
        min_allele_count: 0,
    }
}

fn bench_convert(c: &mut Criterion) {
    let mut group = c.benchmark_group("convert");

    let covid = test_util::covid_vcf_path();
    group.bench_function("convert_covid_fixture", |b| {
        b.iter(|| {
            let dir = tempfile::tempdir().expect("tempdir");
            let out = convert_vcf(black_box(covid.as_path()), dir.path(), &opts())
                .expect("convert covid");
            black_box(out);
        });
    });

    let syn_dir = tempfile::tempdir().expect("tempdir for the synthetic vcf");
    let syn = synthetic_vcf(syn_dir.path());
    group.bench_function("convert_multipop_synthetic", |b| {
        b.iter(|| {
            let dir = tempfile::tempdir().expect("tempdir");
            let out =
                convert_vcf(black_box(syn.as_path()), dir.path(), &opts()).expect("convert syn");
            black_box(out);
        });
    });

    // Multi-block conversion: writes N_BLOCKS partition files via the worker pool. Benched
    // alongside `preview_multiblock`, which does the same scan and per-record processing over
    // the same input without the sort, encode and write. `convert` parallelises the emit and
    // the sort/encode/write across the pool, so it lands near `preview` rather than at
    // `preview + encode`.
    let mb_dir = tempfile::tempdir().expect("tempdir for the multiblock vcf");
    let mb = synthetic_multiblock_vcf(mb_dir.path());
    group.bench_function("convert_multiblock", |b| {
        b.iter(|| {
            let dir = tempfile::tempdir().expect("tempdir");
            let out =
                convert_vcf(black_box(mb.as_path()), dir.path(), &opts()).expect("convert mb");
            black_box(out);
        });
    });
    group.bench_function("preview_multiblock", |b| {
        b.iter(|| {
            let report = preview_vcf(black_box(mb.as_path()), &opts()).expect("preview mb");
            black_box(report);
        });
    });
    group.bench_function("scan_only_multiblock", |b| {
        b.iter(|| black_box(scan_only(black_box(mb.as_path()))));
    });

    // Two VCFs converted concurrently, each on half the worker pool (the `cmd_build`
    // `cores/jobs` split), against one double-wide VCF on the full pool. The total work is
    // the same: two multiblock VCFs equal one VCF of twice the blocks. `_pool4` and `_pool2`
    // pin the pool sizes, so the comparison does not depend on the host CPU count.
    let big_dir = tempfile::tempdir().expect("tempdir for the double-wide vcf");
    let big = synthetic_multiblock_n(big_dir.path(), "doublewide.vcf", N_BLOCKS * 2);
    group.bench_function("one_doublewide_pool4", |b| {
        b.iter(|| {
            let dir = tempfile::tempdir().expect("tempdir");
            let out =
                convert_vcf_with_worker_pool(black_box(big.as_path()), dir.path(), &opts(), 4)
                    .expect("convert doublewide");
            black_box(out);
        });
    });
    group.bench_function("two_multiblock_concurrent_pool2", |b| {
        b.iter(|| {
            let d1 = tempfile::tempdir().expect("tempdir");
            let d2 = tempfile::tempdir().expect("tempdir");
            std::thread::scope(|s| {
                let h =
                    s.spawn(|| convert_vcf_with_worker_pool(mb.as_path(), d1.path(), &opts(), 2));
                let o2 = convert_vcf_with_worker_pool(mb.as_path(), d2.path(), &opts(), 2);
                black_box(h.join().expect("join").expect("convert vcf 1"));
                black_box(o2.expect("convert vcf 2"));
            });
        });
    });

    // Unequal VCFs, 12 blocks plus 4 blocks for the same 16 total: the case that separates
    // the two strategies. A static split gives each VCF half the cores, so when the small one
    // finishes its 2 workers idle while the big one crawls on the other 2. One shared 4-worker
    // pool over both reuses the small VCF's workers as soon as they free.
    let big12 = synthetic_multiblock_n(big_dir.path(), "big12.vcf", 12);
    let small4 = synthetic_multiblock_n(big_dir.path(), "small4.vcf", 4);
    group.bench_function("unequal_static_split_pool2x2", |b| {
        b.iter(|| {
            let d1 = tempfile::tempdir().expect("tempdir");
            let d2 = tempfile::tempdir().expect("tempdir");
            std::thread::scope(|s| {
                let h = s
                    .spawn(|| convert_vcf_with_worker_pool(big12.as_path(), d1.path(), &opts(), 2));
                let o2 = convert_vcf_with_worker_pool(small4.as_path(), d2.path(), &opts(), 2);
                black_box(h.join().expect("join").expect("convert big"));
                black_box(o2.expect("convert small"));
            });
        });
    });
    group.bench_function("unequal_shared_pool4", |b| {
        let sources = [big12.clone(), small4.clone()];
        b.iter(|| {
            let dir = tempfile::tempdir().expect("tempdir");
            let out = convert_vcf_group(&sources, dir.path(), &opts(), 4, &|_| {}, &|_, _| {})
                .expect("group setup");
            black_box(out);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_convert);
criterion_main!(benches);
