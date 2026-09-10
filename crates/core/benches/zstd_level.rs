//! Evidence for the zstd compression level used for aggregated parquet output.
//!
//! `parquet_io::writer_properties` writes at `ZSTD_LEVEL = 19`, one below the maximum. That
//! level is much slower to encode than the mid levels, while zstd decode speed is close to
//! level-independent, so the per-request beacon read gains nothing from a high level. This
//! bench locates the encode-time against on-disk-size knee. It builds its own
//! level-parameterised writer properties and changes nothing in production.
//!
//! Reported:
//!  * `zstd_encode/<level>` — encode time at each level, over a fixed semi-realistic
//!    allele-freq batch using the production schema and row-group cap.
//!  * a size table (encoded bytes per level, and the ratio against level 3) printed once at
//!    startup, since criterion times a benchmark but does not measure its output size.
//!  * `zstd_decode/<level>` — read-back time for the level-3 and level-19 files, which
//!    confirms the read side is indifferent to the level.
//!
//! The synthetic batch carries varied numeric values (AF/AC/AN pseudo-random, REF/ALT and
//! POPULATION cycled) so zstd has representative work. The absolute ratio is synthetic; the
//! level-to-level trend is the signal.
#![allow(
    clippy::disallowed_methods,
    reason = "test/bench code writes plain files: durability and atomicity are not properties under test"
)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::cast_possible_wrap,
    clippy::doc_markdown,
    reason = "bench: deterministic small-range numeric casts + prose-heavy module docs"
)]

use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arrow_array::{Float32Array, Int32Array, RecordBatch, StringArray};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use gdi_node_standalone_core::parquet_io::{
    DatasetDecryptor, PosWindow, allele_freq_schema, read_matching_rows,
};
use gdi_node_standalone_core::validate_parquet::ParquetCaps;
use parquet::arrow::arrow_writer::ArrowWriter;
use parquet::basic::{Compression, ZstdLevel};
use parquet::file::properties::{EnabledStatistics, WriterProperties};

/// Levels swept. 3/6/9/12/15 are the candidate mid-range; 19 is the current default.
const LEVELS: [i32; 6] = [3, 6, 9, 12, 15, 19];

/// Synthetic scale: distinct variant positions × per-variant population rows.
const N_VARIANTS: i32 = 10_000;
const N_POPS: i32 = 16;
const SYN_BASE_POS: i32 = 1_000_000;

/// Max rows per row group — mirrors `parquet_io::MAX_ROW_GROUP_SIZE` (a private const).
const MAX_ROW_GROUP_SIZE: usize = 64 * 1024;

/// REF/ALT alphabet cycled into the synthetic batch for a little column entropy.
const BASES: [&str; 4] = ["A", "C", "G", "T"];

/// Build writer properties at `level`, mirroring the production
/// `parquet_io::writer_properties()` for page statistics and the 64Ki row-group cap.
///
/// `data_page_row_count_limit` stays at the parquet default rather than the production
/// `DATA_PAGE_ROWS`, so the compression level is the only variable.
fn props_at_level(level: i32) -> WriterProperties {
    let level = ZstdLevel::try_new(level).expect("zstd level in range");
    WriterProperties::builder()
        .set_compression(Compression::ZSTD(level))
        .set_statistics_enabled(EnabledStatistics::Page)
        .set_max_row_group_row_count(Some(MAX_ROW_GROUP_SIZE))
        .build()
}

/// A fixed, semi-realistic allele-freq batch with varied numeric values so zstd has
/// representative work (not a constant-column trivially-compressible block).
fn synthetic_batch() -> RecordBatch {
    let n = (N_VARIANTS * N_POPS) as usize;
    let mut pos = Vec::with_capacity(n);
    let mut ref_ = Vec::with_capacity(n);
    let mut alt = Vec::with_capacity(n);
    let mut population = Vec::with_capacity(n);
    let mut af = Vec::with_capacity(n);
    let mut ac = Vec::with_capacity(n);
    let mut an = Vec::with_capacity(n);
    for v in 0..N_VARIANTS {
        for p in 0..N_POPS {
            // Cheap deterministic pseudo-random mix (avoids per-row constant columns).
            let h = (v as u32)
                .wrapping_mul(2_654_435_761)
                .wrapping_add((p as u32).wrapping_mul(40_503));
            pos.push(SYN_BASE_POS + v);
            ref_.push(BASES[(h % 4) as usize]);
            alt.push(BASES[(h / 4 % 4) as usize]);
            population.push(format!("POP_{p:02}"));
            af.push((h % 1000) as f32 / 1000.0);
            ac.push(Some((h % 500) as i32));
            an.push(Some(1000 + (h % 9000) as i32));
        }
    }
    RecordBatch::try_new(
        allele_freq_schema(),
        vec![
            Arc::new(Int32Array::from(pos)),
            Arc::new(StringArray::from(ref_)),
            Arc::new(StringArray::from(alt)),
            Arc::new(StringArray::from(vec!["SNP"; n])),
            Arc::new(StringArray::from(population)),
            Arc::new(Float32Array::from(af)),
            Arc::new(Int32Array::from(ac.clone())),
            Arc::new(Int32Array::from(ac.clone())),
            Arc::new(Int32Array::from(ac.clone())),
            Arc::new(Int32Array::from(ac)),
            Arc::new(Int32Array::from(an)),
        ],
    )
    .expect("build synthetic batch")
}

/// Encode `batch` to an in-memory parquet at `level`; return the encoded bytes.
fn encode(batch: &RecordBatch, level: i32) -> Vec<u8> {
    let mut writer = ArrowWriter::try_new(Vec::new(), batch.schema(), Some(props_at_level(level)))
        .expect("create arrow writer");
    writer.write(batch).expect("write batch");
    writer.into_inner().expect("finish writer")
}

/// Write `bytes` to `dir/name` and return the path.
fn write_file(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).expect("write parquet file");
    path
}

fn bench_zstd(c: &mut Criterion) {
    let batch = synthetic_batch();
    let rows = batch.num_rows();

    // One-time size table: criterion measures time, not bytes.
    eprintln!("\n=== zstd size table ({rows} rows) ===");
    eprintln!("level |    bytes | ratio-vs-3");
    let base = encode(&batch, 3).len() as f64;
    for &lvl in &LEVELS {
        let sz = encode(&batch, lvl).len();
        eprintln!("{lvl:>5} | {sz:>8} | {:.4}", sz as f64 / base);
    }
    eprintln!("(lower 'ratio-vs-3' = smaller file than level 3)\n");

    // Encode time per level.
    let mut group = c.benchmark_group("zstd_encode");
    group.sample_size(20); // level 19 is slow; keep total runtime bounded.
    for &lvl in &LEVELS {
        group.bench_with_input(BenchmarkId::from_parameter(lvl), &lvl, |b, &lvl| {
            b.iter(|| black_box(encode(&batch, lvl)));
        });
    }
    group.finish();

    // Decode level-independence: read back level 3 and level 19, and time each read.
    let dir = tempfile::tempdir().expect("tempdir");
    let p3 = write_file(dir.path(), "lvl3.parquet", &encode(&batch, 3));
    let p19 = write_file(dir.path(), "lvl19.parquet", &encode(&batch, 19));
    let caps = ParquetCaps::default();
    let decryptor = DatasetDecryptor::plaintext();
    let wide = PosWindow {
        lo: i64::from(SYN_BASE_POS),
        hi: i64::from(SYN_BASE_POS + N_VARIANTS),
    };
    let keep_all = |_p: i32, _r: &str, _a: &str, _v: &str| true;
    let mut dgroup = c.benchmark_group("zstd_decode");
    for (label, path) in [("lvl3", &p3), ("lvl19", &p19)] {
        dgroup.bench_with_input(BenchmarkId::from_parameter(label), path, |b, path| {
            b.iter(|| {
                let rows = read_matching_rows(
                    black_box(path),
                    &caps,
                    black_box(wide),
                    &keep_all,
                    &decryptor,
                )
                .expect("read back");
                black_box(rows);
            });
        });
    }
    dgroup.finish();
}

criterion_group!(benches, bench_zstd);
criterion_main!(benches);
