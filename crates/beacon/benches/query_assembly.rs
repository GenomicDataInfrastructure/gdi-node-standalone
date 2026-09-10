//! Criterion benchmark for the `g_variants` query-assembly hot path.
//!
//! The assembly half of a query: group the scanned [`AlleleRow`]s by `(POS, REF, ALT)` and
//! build each variant's `frequencyInPopulations`. The resilience bounds cap worst-case
//! work; this measures steady-state cost.
//!
//! The fixture is the checked-in COVID VCF, converted to Parquet and scanned once outside
//! the timed loop, so the bench input is a fixed, comparable row vector. Three criterion
//! benches run over it. `assemble` covers the grouping and build step over pre-scanned
//! rows. `scan_and_assemble` covers the read and assemble pair, hand-composed from
//! `scan_dataset` and `assemble`. `assemble_many_variants` runs over a synthetic
//! `N_VARIANTS`×`N_POPS` input, because the COVID fixture holds a single variant.
//!
//! Retention accounting is out of scope here: the scan runs against `UnboundedRetention`,
//! so `RetentionSink::charge` and `release` are bypassed and a regression in the shedding
//! path is invisible. A bench that shed under its own ceiling would measure the ceiling.
//! That path is covered by
//! `both_scan_paths_actually_charge_their_sink_and_honour_a_refusal` and
//! `the_aggregate_path_credits_back_each_block_buffer_it_has_folded` in `query.rs`.

use std::hint::black_box;
use std::path::Path;

use criterion::{Criterion, criterion_group, criterion_main};
use gdi_node_standalone_beacon::BeaconParams;
use gdi_node_standalone_beacon::model::Pagination;
use gdi_node_standalone_beacon::query::{
    DatasetPage, PageSpec, UnboundedRetention, assemble, scan_dataset,
};
use gdi_node_standalone_beacon::request::{Predicates, QueryKind};
use gdi_node_standalone_core::convert::{ConvertOptions, convert_vcf};
use gdi_node_standalone_core::model::{Assembly, DatasetMode, ManifestConfig};
use gdi_node_standalone_core::parquet_io::{AlleleRow, DatasetDecryptor};
use gdi_node_standalone_core::validate_parquet::ParquetCaps;
use gdi_node_standalone_core::variant::Vt;

/// The dataset id used for the assembled `variantInternalId` hashing.
const DATASET_ID: &str = "GDI-EE-UTARTU-20260409143052837";

/// A `ManifestConfig` for the COVID `GoE` dataset (`GRCh38`, `af_source` set) —
/// the same shape the assemble integration test uses.
fn covid_manifest_config() -> ManifestConfig {
    ManifestConfig {
        mode: DatasetMode::Aggregated,
        block_range: 10_000_000,
        af_source: Some("The Genome of Europe".to_owned()),
        af_source_reference: None,
        min_allele_count: 0,
        hide_lower_counts: None,
        assembly: Assembly {
            reference: "GRCh38".to_owned(),
        },
        manifest_version: 1,
        generated_by: "gdi-dataset-tool/bench".to_owned(),
    }
}

/// A representative beacon config for the assembled `meta`.
fn beacon_cfg() -> BeaconParams {
    BeaconParams {
        id: "ee.ut.af-beacon.production".to_owned(),
        name: "GDI Estonia Beacon".to_owned(),
        ..BeaconParams::default()
    }
}

/// Convert the checked-in COVID VCF fixture into a fresh tempdir.
fn covid_dataset() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("create tempdir for the dataset fixture");
    let vcf = test_util::covid_vcf_path();
    convert_vcf(
        &vcf,
        dir.path(),
        &ConvertOptions {
            assembly: "GRCh38".into(),
            block_range: 10_000_000,
            min_allele_count: 0,
        },
    )
    .expect("convert the checked-in VCF fixture to parquet");
    dir
}

/// Scan the COVID T>C site and return its rows (the assemble bench input).
fn covid_rows(dir: &Path) -> Vec<AlleleRow> {
    let kind = QueryKind::Sequence {
        pos: 45_823_239,
        ref_: "T".into(),
        alt: "C".into(),
        predicates: Predicates::default(),
    };
    scan_dataset(
        dir,
        "3",
        10_000_000,
        &kind,
        &ParquetCaps::default(),
        &DatasetDecryptor::plaintext(),
        u64::MAX,
        &mut UnboundedRetention,
    )
    .expect("scan the COVID T>C site")
}

/// Synthetic-fixture scale for the grouping/assembly bench.
const N_VARIANTS: i32 = 2000;
const N_POPS: i32 = 16;
const SYN_BASE_POS: i32 = 1_000_000;

/// Deterministic many-variant input for `assemble`: `N_VARIANTS` distinct positions, each
/// with `N_POPS` population rows in one dataset. Built once, outside the timed loop, so
/// the grouping, per-variant frequency build and sort cost is measured at a realistic
/// scale. Paging is not part of that cost: the scan applies the window while folding, so
/// `assemble` never sees the rows a page excludes.
fn synthetic_rows() -> Vec<AlleleRow> {
    let mut rows = Vec::with_capacity((N_VARIANTS * N_POPS) as usize);
    for v in 0..N_VARIANTS {
        for p in 0..N_POPS {
            rows.push(AlleleRow {
                pos: SYN_BASE_POS + v,
                ref_: "A".to_owned(),
                alt: "G".to_owned(),
                vt: Vt::Snp,
                population: format!("POP_{p:02}"),
                af: 0.1,
                ac: Some(100),
                ac_hom: Some(8),
                ac_het: Some(92),
                ac_hemi: Some(0),
                an: Some(1000),
            });
        }
    }
    rows
}

fn bench_query_assembly(c: &mut Criterion) {
    let dir = covid_dataset();
    let rows = covid_rows(dir.path());
    let cfg = covid_manifest_config();
    let bcfg = beacon_cfg();
    let pagination = Pagination::new(0, 10);
    let base_url = "https://gdi-ee.example.org";

    let mut group = c.benchmark_group("query_assembly");

    // The pure assembly step over pre-scanned rows: grouping + frequency build.
    group.bench_function("assemble", |b| {
        b.iter(|| {
            let resp = assemble(
                black_box(vec![(
                    DATASET_ID.to_owned(),
                    &cfg,
                    None,
                    "3",
                    DatasetPage::from_rows(rows.clone(), PageSpec::everything())
                        .expect("group the pre-scanned rows into a page"),
                )]),
                &pagination,
                &bcfg,
                base_url,
                "record",
            );
            black_box(resp);
        });
    });

    // End-to-end scan + assemble (read path + assembly together).
    group.bench_function("scan_and_assemble", |b| {
        b.iter(|| {
            let scanned = covid_rows(dir.path());
            let resp = assemble(
                vec![(
                    DATASET_ID.to_owned(),
                    &cfg,
                    None,
                    "3",
                    DatasetPage::from_rows(scanned, PageSpec::everything())
                        .expect("group the scanned rows into a page"),
                )],
                &pagination,
                &bcfg,
                base_url,
                "record",
            );
            black_box(resp);
        });
    });

    // Synthetic many-variant input: the grouping, frequency-build and sort cost over
    // N_VARIANTS groups × N_POPS populations. `from_rows` sits inside the timed closure
    // because grouping happens in the fold rather than in `assemble`, so timing
    // `assemble` alone would not measure it.
    let many = synthetic_rows();
    group.bench_function("assemble_many_variants", |b| {
        b.iter(|| {
            let resp = assemble(
                black_box(vec![(
                    DATASET_ID.to_owned(),
                    &cfg,
                    None,
                    "3",
                    DatasetPage::from_rows(many.clone(), PageSpec::everything())
                        .expect("group the synthetic rows into a page"),
                )]),
                &pagination,
                &bcfg,
                base_url,
                "record",
            );
            black_box(resp);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_query_assembly);
criterion_main!(benches);
