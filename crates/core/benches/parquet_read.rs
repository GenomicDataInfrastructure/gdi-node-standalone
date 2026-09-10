//! Criterion benchmark for the Parquet read + `POS` row-group-pushdown path.
//!
//! This is the `g_variants` query bottleneck: [`read_matching_rows`] opens an
//! `allele-freq.*.parquet` file, prunes row groups whose `POS` `[min, max]` lies
//! entirely outside the query window, and applies the exact predicate to every
//! decoded row.
//!
//! Two fixtures are used, both converted or written once, outside the timed loop, so
//! numbers are comparable across runs:
//!
//! * the checked-in `COVID.monogneic.aggregate.AFs.GRCh38.vcf` (a single variant) — a hit
//!   window that decodes the matching row group, and a pruned window past every row so the
//!   row-group-statistics fast path (no decode) is measured in isolation;
//! * a synthetic many-variant fixture (`N_VARIANTS * N_POPS` rows, production schema +
//!   writer properties) so `wide_window_decode_many` measures the decode + predicate cost
//!   at a realistic row count, not a single variant.
#![allow(
    clippy::disallowed_methods,
    reason = "test/bench code writes plain files: durability and atomicity are not properties under test"
)]

use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arrow_array::{Float32Array, Int32Array, RecordBatch, StringArray};
use criterion::{Criterion, criterion_group, criterion_main};
use gdi_node_standalone_core::convert::{ConvertOptions, convert_vcf};
use gdi_node_standalone_core::parquet_io::{
    DatasetDecryptor, PosWindow, allele_freq_schema, read_matching_rows, writer_properties,
};
use gdi_node_standalone_core::validate_parquet::ParquetCaps;
use parquet::arrow::arrow_writer::ArrowWriter;

/// The 0-based `POS` of the single COVID fixture variant (`chr3:45823240` 1-based).
const HIT_POS: i64 = 45_823_239;

/// Synthetic-fixture scale: distinct variant positions and per-variant population
/// rows (≈ `N_VARIANTS * N_POPS` rows in one block / row group).
const N_VARIANTS: i32 = 2000;
const N_POPS: i32 = 16;
const SYN_BASE_POS: i32 = 1_000_000;

/// Write a synthetic many-variant `allele-freq` parquet (one block) into `dir` and
/// return its path. Deterministic: `POS` ascending, `N_POPS` population rows per
/// `POS`, canonical schema + production [`writer_properties`].
fn synthetic_parquet(dir: &Path) -> PathBuf {
    let n = (N_VARIANTS * N_POPS) as usize;
    let mut pos = Vec::with_capacity(n);
    let mut population = Vec::with_capacity(n);
    for v in 0..N_VARIANTS {
        for p in 0..N_POPS {
            pos.push(SYN_BASE_POS + v);
            population.push(format!("POP_{p:02}"));
        }
    }
    let schema = allele_freq_schema();
    let count = Int32Array::from(vec![Some(100i32); n]);
    let batch = RecordBatch::try_new(
        Arc::clone(&schema),
        vec![
            Arc::new(Int32Array::from(pos)),
            Arc::new(StringArray::from(vec!["A"; n])),
            Arc::new(StringArray::from(vec!["G"; n])),
            Arc::new(StringArray::from(vec!["SNP"; n])),
            Arc::new(StringArray::from(population)),
            Arc::new(Float32Array::from(vec![0.1f32; n])),
            Arc::new(count.clone()),
            Arc::new(count.clone()),
            Arc::new(count.clone()),
            Arc::new(count.clone()),
            Arc::new(count),
        ],
    )
    .expect("build the synthetic record batch");
    let path = dir.join("allele-freq.chr3.0.br10000000.0123456789abcdef.parquet");
    let file = std::fs::File::create(&path).expect("create the synthetic parquet");
    let props = writer_properties().expect("build writer properties");
    let mut writer =
        ArrowWriter::try_new(file, schema, Some(props)).expect("create the arrow writer");
    writer.write(&batch).expect("write the synthetic batch");
    writer.close().expect("close the synthetic parquet");
    path
}

/// Convert the checked-in VCF fixture into a tempdir and return the first
/// `allele-freq.*.parquet` file path together with the holding tempdir.
///
/// The tempdir is returned so the caller keeps it alive for the bench's
/// lifetime (dropping it would delete the file).
fn fixture_parquet() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("create tempdir for the parquet fixture");
    let vcf = test_util::covid_vcf_path();
    let out = convert_vcf(
        &vcf,
        dir.path(),
        &ConvertOptions {
            assembly: "GRCh38".into(),
            block_range: 10_000_000,
            min_allele_count: 0,
        },
    )
    .expect("convert the checked-in VCF fixture to parquet");
    let path = out
        .parquet_files
        .into_iter()
        .next()
        .expect("conversion produced at least one parquet file");
    (dir, path)
}

fn bench_parquet_read(c: &mut Criterion) {
    let (_dir, parquet) = fixture_parquet();
    let caps = ParquetCaps::default();
    let decryptor = DatasetDecryptor::plaintext();
    // The exact sequence predicate (POS + REF + ALT), as the beacon scan applies.
    let keep = |pos: i32, ref_: &str, alt: &str, _vt: &str| {
        i64::from(pos) == HIT_POS && ref_ == "T" && alt == "C"
    };

    let mut group = c.benchmark_group("parquet_read");

    // A window covering the matching variant: the row group is decoded and the
    // predicate runs over its rows.
    let hit = PosWindow {
        lo: HIT_POS,
        hi: HIT_POS,
    };
    group.bench_function("hit_window_decode", |b| {
        b.iter(|| {
            let rows = read_matching_rows(
                black_box(&parquet),
                &caps,
                black_box(hit),
                &keep,
                &decryptor,
            )
            .expect("read the matching window");
            black_box(rows);
        });
    });

    // A window entirely past every row: row-group `POS` statistics prune the file
    // with no page decode — the pushdown fast path.
    let pruned = PosWindow {
        lo: HIT_POS + 1_000_000,
        hi: HIT_POS + 2_000_000,
    };
    group.bench_function("pruned_window_pushdown", |b| {
        b.iter(|| {
            let rows = read_matching_rows(
                black_box(&parquet),
                &caps,
                black_box(pruned),
                &keep,
                &decryptor,
            )
            .expect("read the pruned window");
            black_box(rows);
        });
    });

    // Synthetic many-variant fixture: a window covering every position with a
    // keep-all predicate, so the decode + predicate + row-collection cost is
    // measured over ~N_VARIANTS*N_POPS rows (realistic), not a single variant.
    let syn_dir = tempfile::tempdir().expect("create the synthetic tempdir");
    let syn_parquet = synthetic_parquet(syn_dir.path());
    let wide = PosWindow {
        lo: i64::from(SYN_BASE_POS),
        hi: i64::from(SYN_BASE_POS + N_VARIANTS),
    };
    let keep_all = |_pos: i32, _ref_: &str, _alt: &str, _vt: &str| true;
    group.bench_function("wide_window_decode_many", |b| {
        b.iter(|| {
            let rows = read_matching_rows(
                black_box(&syn_parquet),
                &caps,
                black_box(wide),
                &keep_all,
                &decryptor,
            )
            .expect("read the wide window");
            black_box(rows);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_parquet_read);
criterion_main!(benches);
