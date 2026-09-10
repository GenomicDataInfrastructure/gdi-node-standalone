//! Property / metamorphic / differential tests for the beacon query math.
//!
//! The error-prone core of the query path is the block-span and lookback file selection
//! ([`select_files`]), the half-open overlap predicates ([`scan_dataset`]) and the
//! page-index POS pruning. Elsewhere they are covered only by golden and unit tests over
//! the one COVID fixture, where a wrong answer would be baked in.
//!
//! A differential oracle here asserts the real pruned reader returns the same hits as a
//! brute-force linear scan over every row, and a repack-invariance metamorphic test asserts
//! the hit set does not change when the same data is partitioned at a different
//! `blockRange`. Neither relation needs hand-written expected output, so they catch the
//! off-by-one, wrong-block, lookback and pruning errors a golden cannot.
//!
//! Fixtures are written with the production [`writer_properties`], statistics on, so the
//! differential exercises the real row-group POS pruning, where the reader skips a row
//! group whose POS statistics fall outside the query window, rather than a degraded
//! read-everything path. Queries carry empty predicates, isolating the POS, overlap and
//! selection math from the ref, alt and type filters.
#![allow(
    clippy::disallowed_methods,
    reason = "test/bench code writes plain files: durability and atomicity are not properties under test"
)]
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use arrow_array::{Float32Array, Int32Array, RecordBatch, StringArray};
use gdi_node_standalone_beacon::model::Pagination;
use gdi_node_standalone_beacon::query::{
    AggregateScan, DatasetCounts, PageSpec, UnboundedRetention, assemble, scan_dataset,
    scan_dataset_counts, scan_dataset_page,
};
use gdi_node_standalone_beacon::request::{Predicates, QueryKind};
use gdi_node_standalone_core::error::CoreResult;
use gdi_node_standalone_core::model::{Assembly, DatasetMode, ManifestConfig};
use gdi_node_standalone_core::parquet_io::{
    DatasetDecryptor, allele_freq_schema, writer_properties,
};
use gdi_node_standalone_core::validate_parquet::ParquetCaps;
use parquet::arrow::arrow_writer::ArrowWriter;
use proptest::prelude::*;

const CHR: &str = "3";

/// One variant: the differential's hit key (`POS`, `REF`, `ALT`). Each is written with a
/// single `Total` population, so one variant is one row.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Variant {
    pos: i32,
    ref_: String,
    alt: String,
}

/// Empty row predicates, isolating the POS and overlap math. `Predicates` is
/// `#[non_exhaustive]`, so it is built through its all-`None` `Default`.
fn no_preds() -> Predicates {
    Predicates::default()
}

/// Write `variants` into `dir`, partitioned by `pos / block_range`, or into the single
/// block 0 when `block_range == 0`, as the converter does: one POS-sorted parquet per
/// block, canonical schema, production writer properties.
fn write_partitioned(dir: &Path, block_range: u32, variants: &[Variant]) {
    let mut by_block: BTreeMap<u64, Vec<&Variant>> = BTreeMap::new();
    for v in variants {
        let pos = u64::try_from(v.pos).unwrap_or_default();
        let block = if block_range == 0 {
            0
        } else {
            pos / u64::from(block_range)
        };
        by_block.entry(block).or_default().push(v);
    }
    for (block, mut rows) in by_block {
        rows.sort(); // POS-ascending (Variant Ord is pos, ref_, alt)
        let n = rows.len();
        let schema = allele_freq_schema();
        let pos = Int32Array::from(rows.iter().map(|r| r.pos).collect::<Vec<_>>());
        let ref_ = StringArray::from(rows.iter().map(|r| r.ref_.as_str()).collect::<Vec<_>>());
        let alt = StringArray::from(rows.iter().map(|r| r.alt.as_str()).collect::<Vec<_>>());
        let vt = StringArray::from(vec!["SNP"; n]);
        let pop = StringArray::from(vec!["Total"; n]);
        let af = Float32Array::from(vec![0.1f32; n]);
        let count = Int32Array::from(vec![Some(0i32); n]);
        let batch = RecordBatch::try_new(
            Arc::clone(&schema),
            vec![
                Arc::new(pos),
                Arc::new(ref_),
                Arc::new(alt),
                Arc::new(vt),
                Arc::new(pop),
                Arc::new(af),
                Arc::new(count.clone()),
                Arc::new(count.clone()),
                Arc::new(count.clone()),
                Arc::new(count.clone()),
                Arc::new(count),
            ],
        )
        .unwrap();
        let name = format!("allele-freq.chr{CHR}.{block}.br{block_range}.0123456789abcdef.parquet");
        let file = std::fs::File::create(dir.join(name)).unwrap();
        let mut writer =
            ArrowWriter::try_new(file, schema, Some(writer_properties().unwrap())).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
    }
}

/// The aggregate (`boolean`/`count`) fold's answer for the same query, from the path that
/// never materialises rows.
///
/// Returns the `CoreResult` rather than unwrapping, so a fold failure is a legible test
/// failure rather than a panic from inside a proptest case. The fold fails closed on an
/// unsorted stream.
fn count_fold(dir: &Path, block_range: u32, kind: &QueryKind) -> CoreResult<DatasetCounts> {
    scan_dataset_counts(
        dir,
        CHR,
        block_range,
        kind,
        &ParquetCaps::default(),
        &DatasetDecryptor::plaintext(),
        AggregateScan {
            // This harness has no process-wide ceiling to enforce.
            sink: &mut UnboundedRetention,
            max_query_bytes: u64::MAX,
            floor: 0,
        },
    )
}

/// The real query path's hit set: selected files, POS-pruned, then matched per row.
fn scan_hits(dir: &Path, block_range: u32, kind: &QueryKind) -> BTreeSet<Variant> {
    scan_dataset(
        dir,
        CHR,
        block_range,
        kind,
        &ParquetCaps::default(),
        &DatasetDecryptor::plaintext(),
        u64::MAX,
        &mut UnboundedRetention,
    )
    .unwrap()
    .into_iter()
    .map(|r| Variant {
        pos: r.pos,
        ref_: r.ref_,
        alt: r.alt,
    })
    .collect()
}

/// The oracle: a brute-force linear scan applying the same predicates as `scan_dataset`
/// over every variant, with no file selection and no pruning. With empty predicates the
/// ref, alt and type filters are a no-op, so this is the pure overlap and exact-match
/// definition.
fn brute_force(variants: &[Variant], kind: &QueryKind) -> BTreeSet<Variant> {
    variants
        .iter()
        .filter(|v| {
            let v_start = i64::from(v.pos);
            let v_end = v_start + i64::try_from(v.ref_.len()).unwrap();
            match kind {
                QueryKind::Sequence { pos, ref_, alt, .. } => {
                    v_start == *pos && &v.ref_ == ref_ && &v.alt == alt
                }
                QueryKind::Range { start, end, .. } => v_start < *end && v_end > *start,
                QueryKind::Bracket {
                    s_min,
                    s_max,
                    e_min,
                    e_max,
                    ..
                } => *s_min <= v_start && v_start <= *s_max && *e_min <= v_end && v_end <= *e_max,
                // `Empty`, meaning no variant params, and any future `#[non_exhaustive]`
                // variant match nothing.
                _ => false,
            }
        })
        .cloned()
        .collect()
}

/// A 1..24-base `ACGTN` allele.
fn acgtn() -> impl Strategy<Value = String> {
    proptest::collection::vec(prop::sample::select(vec!['A', 'C', 'G', 'T', 'N']), 1..24)
        .prop_map(|v| v.into_iter().collect())
}

fn variant() -> impl Strategy<Value = Variant> {
    (0i32..2000, acgtn(), acgtn()).prop_map(|(pos, ref_, alt)| Variant { pos, ref_, alt })
}

/// A set of distinct variants (deduped by (pos, ref, alt) so each is one hit key).
fn variant_set() -> impl Strategy<Value = Vec<Variant>> {
    proptest::collection::vec(variant(), 0..30).prop_map(|mut vs| {
        vs.sort();
        vs.dedup();
        vs
    })
}

/// Block ranges generous enough to bound the per-case file count (a single block, or
/// 50..500, giving at most about 40 blocks over the 0..2000 POS range) while still
/// exercising multi-block selection and the cross-file merge.
fn block_range() -> impl Strategy<Value = u32> {
    prop_oneof![Just(0u32), 50u32..500]
}

/// Predicate-aware oracle: the same overlap and bracket geometry as [`brute_force`], plus
/// the `Predicates`, applied as `query::matches_predicates` does. A present ref or alt is
/// an equality check, `variant_type` is set-membership, so the row `vt` must be one of the
/// selected labels, and `min_len` and `max_len` are inclusive bounds on the
/// alternate-allele length `len(ALT)`. Generated rows all carry `vt = "SNP"`.
fn brute_force_pred(variants: &[Variant], kind: &QueryKind) -> BTreeSet<Variant> {
    let preds = match kind {
        QueryKind::Range { predicates, .. } | QueryKind::Bracket { predicates, .. } => {
            Some(predicates)
        }
        _ => None,
    };
    variants
        .iter()
        .filter(|v| {
            let v_start = i64::from(v.pos);
            let v_end = v_start + i64::try_from(v.ref_.len()).unwrap();
            let geometry = match kind {
                QueryKind::Range { start, end, .. } => v_start < *end && v_end > *start,
                QueryKind::Bracket {
                    s_min,
                    s_max,
                    e_min,
                    e_max,
                    ..
                } => *s_min <= v_start && v_start <= *s_max && *e_min <= v_end && v_end <= *e_max,
                _ => false,
            };
            if !geometry {
                return false;
            }
            let Some(p) = preds else {
                return true;
            };
            let alt_len = i64::try_from(v.alt.len()).unwrap();
            if let Some(want) = &p.ref_
                && &v.ref_ != want
            {
                return false;
            }
            if let Some(want) = &p.alt
                && &v.alt != want
            {
                return false;
            }
            if let Some(want) = &p.variant_type
                && !want.iter().any(|w| w == "SNP")
            {
                return false;
            }
            if let Some(min) = p.min_len
                && alt_len < min
            {
                return false;
            }
            if let Some(max) = p.max_len
                && alt_len > max
            {
                return false;
            }
            true
        })
        .cloned()
        .collect()
}

/// A random `Predicates`, built from `Default` plus field assignment, because the struct is
/// `#[non_exhaustive]` and a literal is not constructible from this test crate. Lengths span
/// 0..=24: alleles are 1 to 24 bases with a delta of at most 23, so 24 also exercises the
/// upper edge where no row can satisfy the bound.
fn predicates_strategy() -> impl Strategy<Value = Predicates> {
    (
        proptest::option::of(acgtn()),
        proptest::option::of(acgtn()),
        proptest::option::of(prop_oneof![
            Just(vec!["SNP".to_owned()]),
            Just(vec!["MNP".to_owned()]),
            Just(vec!["INS".to_owned()]),
            Just(vec!["DEL".to_owned()]),
            Just(vec!["DELINS".to_owned()]),
            // The indel umbrella expands to a multi-label set.
            Just(vec![
                "INS".to_owned(),
                "DEL".to_owned(),
                "DELINS".to_owned()
            ]),
        ]),
        proptest::option::of(0i64..=24),
        proptest::option::of(0i64..=24),
    )
        .prop_map(|(ref_, alt, variant_type, min_len, max_len)| {
            let mut p = Predicates::default();
            p.ref_ = ref_;
            p.alt = alt;
            p.variant_type = variant_type;
            p.min_len = min_len;
            p.max_len = max_len;
            p
        })
}

/// A minimal aggregated-mode manifest with the disclosure floor off, so the pagination
/// property below isolates paging from suppression, which `suppression_properties.rs` owns.
fn plain_manifest_config(block_range: u32) -> ManifestConfig {
    ManifestConfig {
        mode: DatasetMode::Aggregated,
        block_range,
        af_source: None,
        af_source_reference: None,
        min_allele_count: 0,
        hide_lower_counts: None,
        assembly: Assembly {
            reference: "GRCh38".to_owned(),
        },
        manifest_version: 1,
        generated_by: "proptest".to_owned(),
    }
}

/// Assemble one dataset at `record` granularity under `(skip, limit)`, returning the
/// emitted variant keys in order plus the reported true total.
fn emitted_page(
    dir: &Path,
    br: u32,
    kind: &QueryKind,
    skip: u64,
    limit: u64,
) -> (Vec<Variant>, u64) {
    // Drives the paged scan: the window is applied while folding, so this exercises the
    // path that serves `record` queries rather than a post-hoc slice.
    let page = scan_dataset_page(
        dir,
        CHR,
        br,
        kind,
        &ParquetCaps::default(),
        &DatasetDecryptor::plaintext(),
        u64::MAX,
        PageSpec {
            floor: 0,
            skip,
            limit,
        },
        &mut UnboundedRetention,
    )
    .unwrap();
    let cfg = plain_manifest_config(br);
    let resp = assemble(
        vec![("DS".to_owned(), &cfg, None, CHR, page)],
        &Pagination::new(skip, limit),
        &crate::fixtures::beacon_cfg(),
        "https://node.example.org",
        "record",
    );
    let body = resp.response.expect("record granularity keeps the body");
    let ids = body
        .result_sets
        .iter()
        .flat_map(|rs| rs.results.iter())
        .map(|r| Variant {
            pos: i32::try_from(r.variation.location.interval.start.value).unwrap(),
            ref_: r.variation.reference_bases.clone(),
            alt: r.variation.alternate_bases.clone(),
        })
        .collect();
    let total = body.result_sets.iter().map(|rs| rs.results_count).sum();
    (ids, total)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Range (half-open overlap) hits match the brute-force oracle for any data,
    /// query window, and block size.
    #[test]
    fn range_query_differential(
        vs in variant_set(),
        start in 0i64..2000,
        span in 1i64..600,
        br in block_range(),
    ) {
        let kind = QueryKind::Range { start, end: start + span, predicates: no_preds() };
        let dir = tempfile::tempdir().unwrap();
        write_partitioned(dir.path(), br, &vs);
        prop_assert_eq!(scan_hits(dir.path(), br, &kind), brute_force(&vs, &kind));
    }

    /// Bracket hits match the oracle.
    #[test]
    fn bracket_query_differential(
        vs in variant_set(),
        s_min in 0i64..2000,
        s_width in 0i64..300,
        e_off in 0i64..400,
        e_width in 0i64..300,
        br in block_range(),
    ) {
        let s_max = s_min + s_width;
        let e_min = s_min + e_off;
        let e_max = e_min + e_width;
        let kind = QueryKind::Bracket { s_min, s_max, e_min, e_max, predicates: no_preds() };
        let dir = tempfile::tempdir().unwrap();
        write_partitioned(dir.path(), br, &vs);
        prop_assert_eq!(scan_hits(dir.path(), br, &kind), brute_force(&vs, &kind));
    }

    /// Exact-match (Sequence) hits match the oracle. Aimed at an existing variant when the
    /// set is non-empty, so the path is hit rather than left empty.
    #[test]
    fn sequence_query_differential(
        vs in variant_set(),
        idx in any::<prop::sample::Index>(),
        br in block_range(),
    ) {
        let kind = if vs.is_empty() {
            QueryKind::Sequence { pos: 100, ref_: "T".to_owned(), alt: "C".to_owned(), predicates: Predicates::default() }
        } else {
            let v = &vs[idx.index(vs.len())];
            QueryKind::Sequence { pos: i64::from(v.pos), ref_: v.ref_.clone(), alt: v.alt.clone(), predicates: Predicates::default() }
        };
        let dir = tempfile::tempdir().unwrap();
        write_partitioned(dir.path(), br, &vs);
        prop_assert_eq!(scan_hits(dir.path(), br, &kind), brute_force(&vs, &kind));
    }

    /// Repack invariance: the same data partitioned at two different block sizes returns
    /// identical hits, and both equal the brute-force oracle. This is the direct test of the
    /// lookback and block-span arithmetic.
    #[test]
    fn repack_invariance(
        vs in variant_set(),
        start in 0i64..2000,
        span in 1i64..600,
    ) {
        let kind = QueryKind::Range { start, end: start + span, predicates: no_preds() };
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        write_partitioned(d1.path(), 47, &vs);
        write_partitioned(d2.path(), 113, &vs);
        let h1 = scan_hits(d1.path(), 47, &kind);
        let h2 = scan_hits(d2.path(), 113, &kind);
        prop_assert_eq!(&h1, &h2);
        prop_assert_eq!(h1, brute_force(&vs, &kind));
    }

    /// The `boolean`/`count` streaming fold must report the record path's surviving-group
    /// count exactly, over multi-block datasets.
    ///
    /// `scan_dataset_counts` never materialises rows: it folds groups as they stream and
    /// closes one the moment the `(POS, REF, ALT)` key changes. That is correct only if the
    /// rows arrive globally sorted, which means only if `select_files` hands back its files
    /// in POS-ascending order. `aggregate_fold_counts_agree_with_the_record_path`, the other
    /// differential for this path, runs on the COVID fixture, which emits a single data
    /// file, so it cannot stream the fold across a file boundary. `block_range()` yields up
    /// to about 40 blocks over the 0..2000 POS range, which spans the 9-to-10 digit boundary
    /// where an unpadded filename sort misorders.
    ///
    /// Not covered here: two `vcfid` files sharing one block, a multi-VCF package that
    /// `write_partitioned` does not produce. There the POS spans overlap outright, no file
    /// ordering can fix it, and the merge arm of `fold_matching_rows` handles it instead.
    #[test]
    fn count_fold_differential(
        vs in variant_set(),
        start in 0i64..2000,
        span in 1i64..600,
        br in block_range(),
    ) {
        let kind = QueryKind::Range { start, end: start + span, predicates: no_preds() };
        let dir = tempfile::tempdir().unwrap();
        write_partitioned(dir.path(), br, &vs);
        let expected = brute_force(&vs, &kind);

        let got = count_fold(dir.path(), br, &kind);
        prop_assert!(
            got.is_ok(),
            "count fold failed where the record path succeeds (br={}, start={}, span={}): {}",
            br,
            start,
            span,
            got.as_ref().err().map(ToString::to_string).unwrap_or_default()
        );
        let got = got.unwrap();
        // One variant is one row, with a single `Total` population, and floor 0 suppresses
        // nothing, so each matching variant is one surviving group.
        prop_assert_eq!(got.surviving, u64::try_from(expected.len()).unwrap());
        prop_assert_eq!(got.exists, !expected.is_empty());
    }

    /// Paging is slicing, and the true total is page-independent.
    ///
    /// For every window, the emitted variant keys must equal the unpaged emission sliced to
    /// `[skip, skip+limit)`, and `results_count` must report the same true total whatever
    /// the window is.
    ///
    /// The record path decides inclusion while folding rather than slicing afterwards, so
    /// the window boundary, the ordering and the page-independence of the total are all
    /// decided in the scan. This relation is what holds them to the slicing definition.
    #[test]
    fn paging_is_slicing_and_the_total_is_page_independent(
        vs in variant_set(),
        start in 0i64..2000,
        span in 1i64..600,
        br in block_range(),
        skip in 0u64..6,
        limit in 1u64..6,
    ) {
        let kind = QueryKind::Range { start, end: start + span, predicates: no_preds() };
        let dir = tempfile::tempdir().unwrap();
        write_partitioned(dir.path(), br, &vs);

        // The oracle is the brute-force hit set, independent of the pagination path.
        // Slicing one run of `assemble` against another cancels any uniform offset out and
        // passes a broken `skip`: an off-by-one in `skip` survives that formulation.
        let oracle: Vec<Variant> = brute_force(&vs, &kind).into_iter().collect();
        let expected: Vec<Variant> = oracle
            .iter()
            .skip(usize::try_from(skip).unwrap())
            .take(usize::try_from(limit).unwrap())
            .cloned()
            .collect();

        let (page, total_paged) = emitted_page(dir.path(), br, &kind, skip, limit);
        prop_assert_eq!(
            &page, &expected,
            "page (skip={}, limit={}) is not the oracle's slice", skip, limit
        );
        prop_assert_eq!(
            total_paged,
            u64::try_from(oracle.len()).unwrap(),
            "results_count must be the true total, not the page length"
        );
    }

    /// Range hits with random predicates match the predicate-aware oracle: the ref, alt and
    /// `variant_type` equality filters and the inclusive `min_len` and `max_len` bounds,
    /// conjoined with the overlap geometry. The other differentials use only empty
    /// predicates, so this is the coverage for `matches_predicates`, which filters on
    /// untrusted query input.
    #[test]
    fn range_predicate_differential(
        vs in variant_set(),
        start in 0i64..2000,
        span in 1i64..600,
        br in block_range(),
        preds in predicates_strategy(),
    ) {
        let kind = QueryKind::Range { start, end: start + span, predicates: preds };
        let dir = tempfile::tempdir().unwrap();
        write_partitioned(dir.path(), br, &vs);
        prop_assert_eq!(scan_hits(dir.path(), br, &kind), brute_force_pred(&vs, &kind));
    }
}
