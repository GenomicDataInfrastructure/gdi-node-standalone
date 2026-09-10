//! Golden + unit tests for `g_variants` response assembly.
//!
//! The golden test scans the checked-in COVID fixture through the real [`scan_dataset`]
//! path and asserts the assembled [`BeaconResponse`] matches the `frequencyInPopulations`
//! wire contract in `docs/api.md`. The unit tests exercise the `min_allele_count` floor: a
//! population below the floor is dropped, and a dataset whose every population is dropped
//! becomes a per-dataset `exists:false` miss, materialized so an `ALL` or `MISS` query can
//! account for it and hidden by the default `HIT` filter.

#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use gdi_node_standalone_beacon::BeaconParams;
use gdi_node_standalone_beacon::model::BeaconResponse;
use gdi_node_standalone_beacon::model::Pagination;
use gdi_node_standalone_beacon::query::{
    DatasetPage, PageSpec, UnboundedRetention, apply_include_resultset_responses, assemble,
    effective_floor, scan_dataset, shape_for_granularity,
};
use gdi_node_standalone_beacon::request::{IncludeResultsetResponses, Predicates, QueryKind};
use gdi_node_standalone_core::convert::{ConvertOptions, convert_vcf};
use gdi_node_standalone_core::model::{Assembly, DatasetMode, ManifestConfig};
use gdi_node_standalone_core::parquet_io::{AlleleRow, DatasetDecryptor};
use gdi_node_standalone_core::validate_parquet::ParquetCaps;
use gdi_node_standalone_core::variant::Vt;
use proptest::prelude::*;
use test_util::covid;

/// A `ManifestConfig` for the COVID `GoE` dataset (`GRCh38`, `af_source` set).
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
        generated_by: "gdi-dataset-tool/test".to_owned(),
    }
}

/// The page the scan would have produced for `rows` under `cfg`'s effective floor.
///
/// The scan applies the window, so a test that wants one states it here rather than passing
/// it to `assemble`. The floor must be the one `assemble_dataset` re-applies.
fn page_win(cfg: &ManifestConfig, rows: Vec<AlleleRow>, skip: u64, limit: u64) -> DatasetPage {
    let floor = effective_floor(cfg, &crate::fixtures::beacon_cfg());
    DatasetPage::from_rows(rows, PageSpec { floor, skip, limit }).expect("group rows into a page")
}

/// [`page_win`] with the window wide open.
fn page(cfg: &ManifestConfig, rows: Vec<AlleleRow>) -> DatasetPage {
    page_win(cfg, rows, 0, u64::MAX)
}

/// [`page`] for a test that assembles under non-default beacon params. The floor is
/// `max(node, dataset)`, so the page must be built with the same pair it is assembled with.
fn page_with(cfg: &ManifestConfig, bcfg: &BeaconParams, rows: Vec<AlleleRow>) -> DatasetPage {
    let floor = effective_floor(cfg, bcfg);
    DatasetPage::from_rows(
        rows,
        PageSpec {
            floor,
            ..PageSpec::everything()
        },
    )
    .expect("group rows into a page")
}

/// Convert the COVID fixture into a fresh tempdir.
fn covid_dataset() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
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
    .unwrap();
    dir
}

/// Scan the COVID T>C site and return its rows.
fn covid_rows() -> Vec<AlleleRow> {
    let dir = covid_dataset();
    let kind = QueryKind::Sequence {
        pos: 45_823_239,
        ref_: "T".into(),
        alt: "C".into(),
        predicates: Predicates::default(),
    };
    scan_dataset(
        dir.path(),
        "3",
        10_000_000,
        &kind,
        &ParquetCaps::default(),
        &DatasetDecryptor::plaintext(),
        u64::MAX,
        &mut UnboundedRetention,
    )
    .unwrap()
}

#[test]
fn assembles_covid_resultset() {
    let cfg = covid_manifest_config();
    let bcfg = crate::fixtures::beacon_cfg();
    let dataset_id = "GDI-EE-UTARTU-20260409143052837".to_owned();
    let rows = covid_rows();

    let resp: BeaconResponse = assemble(
        vec![(dataset_id.clone(), &cfg, None, "3", page(&cfg, rows))],
        &Pagination::new(0, 10),
        &bcfg,
        "https://gdi-ee.example.org",
        "record",
    );

    // One resultSet for the dataset, exact count, correct id.
    let body = resp
        .response
        .as_ref()
        .expect("assemble yields a response body");
    assert_eq!(body.result_sets.len(), 1);
    let rs = &body.result_sets[0];
    assert_eq!(rs.id, dataset_id);
    assert_eq!(rs.results_count, 1);
    assert_eq!(rs.results.len(), 1);
    assert!(rs.exists);
    assert_eq!(rs.set_type, "dataset");

    let entry = &rs.results[0];
    let fip = &entry.frequency_in_populations[0];
    assert_eq!(fip.source, "The Genome of Europe");
    // af_source_reference unset falls back to base_url, and is never omitted.
    assert_eq!(fip.source_reference, "https://gdi-ee.example.org");

    // FI_M and Total appear with the known values.
    let fi_m = fip
        .frequencies
        .iter()
        .find(|f| f.population == "FI_M")
        .expect("FI_M frequency present");
    assert!((f64::from(fi_m.allele_frequency) - covid::FI_M_AF).abs() < 1e-4);
    assert_eq!(fi_m.allele_count, Some(covid::FI_M_AC));
    assert_eq!(fi_m.allele_number, Some(1400));

    let total = fip
        .frequencies
        .iter()
        .find(|f| f.population == "Total")
        .expect("Total frequency present");
    assert!((total.allele_frequency - 0.077_25).abs() < 1e-4);
    assert_eq!(total.allele_count, Some(covid::TOTAL_AC));
    assert_eq!(total.allele_number, Some(covid::TOTAL_AN));

    // VRS sequence_id = refseq:NC_000003.12 (GRCh38 chr3).
    assert_eq!(entry.variation.location.sequence_id, "refseq:NC_000003.12");

    // Valid SNV genomic HGVS id (POS+1 1-based: 45823239 + 1 = 45823240).
    assert_eq!(
        entry.identifiers.genomic_hgvs_id,
        "NC_000003.12:g.45823240T>C"
    );

    // responseSummary aggregates.
    assert!(resp.response_summary.exists);
    assert_eq!(resp.response_summary.num_total_results, Some(1));

    // Golden snapshot of the exact wire nesting.
    insta::assert_json_snapshot!(resp);
}

#[test]
fn min_allele_count_drops_population_below_floor() {
    let mut cfg = covid_manifest_config();
    cfg.min_allele_count = 200; // FI_M (AC 119) below, Total (AC 618) above.
    let bcfg = crate::fixtures::beacon_cfg();
    let rows = covid_rows();

    let resp = assemble(
        vec![(
            "GDI-EE-UTARTU-1".to_owned(),
            &cfg,
            None,
            "3",
            page(&cfg, rows),
        )],
        &Pagination::new(0, 10),
        &bcfg,
        "https://gdi-ee.example.org",
        "record",
    );

    let body = resp
        .response
        .as_ref()
        .expect("assemble yields a response body");
    let rs = &body.result_sets[0];
    let fip = &rs.results[0].frequency_in_populations[0];
    // FI_M (AC 119) is below the floor. A sub-population was suppressed, so the
    // cross-partition collapse drops every non-Total breakdown, including sex and country
    // aggregates that individually clear 200, and no suppressed cell can be recovered by
    // subtraction (FI_F = FI - FI_M, or F = Total - M). Only the aggregate Total is served.
    let pops: Vec<&str> = fip
        .frequencies
        .iter()
        .map(|f| f.population.as_str())
        .collect();
    assert_eq!(
        pops,
        vec!["Total"],
        "a suppressed sub-population must collapse the group to Total only"
    );
    // The retained Total still respects the floor.
    assert!(fip.frequencies[0].allele_count.is_none_or(|ac| ac >= 200));
}

#[test]
fn suppressed_dataset_becomes_exists_false_and_is_hidden_under_hit() {
    let mut cfg = covid_manifest_config();
    cfg.min_allele_count = 1_000_000; // above every population's AC.
    let bcfg = crate::fixtures::beacon_cfg();

    let resp = assemble(
        vec![(
            "GDI-EE-UTARTU-1".to_owned(),
            &cfg,
            None,
            "3",
            page(&cfg, covid_rows()),
        )],
        &Pagination::new(0, 10),
        &bcfg,
        "https://gdi-ee.example.org",
        "record",
    );

    // Raw assembly materializes the considered dataset as an `exists:false` miss, so an
    // `ALL` or `MISS` query can account for it. Dropping it silently would make a `0`
    // indistinguishable from a dataset that was never consulted.
    let body = resp
        .response
        .as_ref()
        .expect("assemble yields a response body");
    assert_eq!(body.result_sets.len(), 1);
    assert!(!body.result_sets[0].exists);
    assert_eq!(body.result_sets[0].results_count, 0);
    assert!(body.result_sets[0].results.is_empty());
    // The aggregate summary is still a truthful negative.
    assert!(!resp.response_summary.exists);
    assert_eq!(resp.response_summary.num_total_results, Some(0));

    // The default HIT filter still hides the miss, so the default wire is unchanged.
    let hit = apply_include_resultset_responses(resp, IncludeResultsetResponses::Hit);
    assert!(
        hit.response
            .as_ref()
            .expect("HIT keeps the response body")
            .result_sets
            .is_empty()
    );
}

#[test]
fn min_allele_count_suppresses_small_genotype_cells() {
    // A population that clears the AC floor can still expose a singleton homozygote.
    // Coherent sub-count withholding in `gate_subcounts`: when any genotype sub-count is a
    // non-empty group below the floor (`1 <= v < floor`), all three sub-counts are withheld
    // together, so none can be recovered from AC and the survivors. AC, AN and AF are
    // unaffected and still served, because the population itself clears the floor.
    let rows = vec![AlleleRow {
        pos: 100,
        ref_: "A".to_owned(),
        alt: "T".to_owned(),
        vt: Vt::Snp,
        population: "Total".to_owned(),
        af: 0.01,
        ac: Some(10),    // >= floor 5: population survives; AC/AN/AF still served
        ac_hom: Some(1), // 1 <= 1 < 5: in_danger → triggers coherent all-None
        ac_het: Some(8), // safe individually, but withheld with the others
        ac_hemi: None,
        an: Some(1000),
    }];
    let mut cfg = covid_manifest_config();
    cfg.min_allele_count = 5;

    let resp = assemble(
        vec![(
            "GDI-EE-UTARTU-1".to_owned(),
            &cfg,
            None,
            "3",
            page(&cfg, rows),
        )],
        &Pagination::new(0, 10),
        &crate::fixtures::beacon_cfg(),
        "https://gdi-ee.example.org",
        "record",
    );
    let f = &resp.response.as_ref().expect("a body").result_sets[0].results[0]
        .frequency_in_populations[0]
        .frequencies[0];
    assert_eq!(f.population, "Total");
    assert_eq!(
        f.allele_count,
        Some(10),
        "AC cleared the floor, still served"
    );
    assert_eq!(f.allele_number, Some(1000));
    assert_eq!(
        f.allele_count_homozygous, None,
        "singleton homozygote is in_danger: all three sub-counts are withheld"
    );
    assert_eq!(
        f.allele_count_heterozygous, None,
        "withheld coherently with hom (even though het=8 >= floor) to prevent recovery"
    );
}

#[test]
fn effective_floor_is_max_of_beacon_and_manifest() {
    // The effective serving floor is max(node [beacon].min_allele_count, the dataset
    // manifest's min_allele_count). The other floor tests vary only the manifest floor,
    // with the node floor at its default 0, so this covers the node-floor leg and the max()
    // interaction.
    //
    // FI_M has AC=119, so straddling it with floors 100 and 150 makes max() and min()
    // distinguishable: under max(150) FI_M is suppressed, and under min(100) it would
    // survive. Total (AC=618) clears either floor.

    // Case A: the node [beacon] floor is the higher of the two.
    let bcfg_high = BeaconParams {
        min_allele_count: 150,
        ..crate::fixtures::beacon_cfg()
    };
    let mut cfg_low = covid_manifest_config();
    cfg_low.min_allele_count = 100;
    let resp = assemble(
        vec![(
            "GDI-EE-UTARTU-1".to_owned(),
            &cfg_low,
            None,
            "3",
            page_with(&cfg_low, &bcfg_high, covid_rows()),
        )],
        &Pagination::new(0, 10),
        &bcfg_high,
        "https://gdi-ee.example.org",
        "record",
    );
    let fip = &resp.response.as_ref().expect("a body").result_sets[0].results[0]
        .frequency_in_populations[0];
    assert!(
        !fip.frequencies.iter().any(|f| f.population == "FI_M"),
        "max(node 150, dataset 100)=150 must drop FI_M (AC 119); a min() would keep it"
    );
    assert!(
        fip.frequencies.iter().any(|f| f.population == "Total"),
        "Total (AC 618) clears the floor"
    );

    // Case B: the dataset manifest floor is the higher of the two. The same effective floor
    // reached from the other side, so the rule is max() rather than node-floor-only.
    let bcfg_low = BeaconParams {
        min_allele_count: 100,
        ..crate::fixtures::beacon_cfg()
    };
    let mut cfg_high = covid_manifest_config();
    cfg_high.min_allele_count = 150;
    let resp = assemble(
        vec![(
            "GDI-EE-UTARTU-1".to_owned(),
            &cfg_high,
            None,
            "3",
            page_with(&cfg_high, &bcfg_low, covid_rows()),
        )],
        &Pagination::new(0, 10),
        &bcfg_low,
        "https://gdi-ee.example.org",
        "record",
    );
    let fip = &resp.response.as_ref().expect("a body").result_sets[0].results[0]
        .frequency_in_populations[0];
    assert!(
        !fip.frequencies.iter().any(|f| f.population == "FI_M"),
        "max(node 100, dataset 150)=150 must drop FI_M (AC 119) from the dataset side too"
    );
    assert!(fip.frequencies.iter().any(|f| f.population == "Total"));
}

/// A real, non-empty COVID `BeaconResponse` (one matching resultSet).
fn covid_response() -> BeaconResponse {
    assemble(
        vec![(
            "GDI-EE-UTARTU-1".to_owned(),
            &covid_manifest_config(),
            None,
            "3",
            page(&covid_manifest_config(), covid_rows()),
        )],
        &Pagination::new(0, 10),
        &crate::fixtures::beacon_cfg(),
        "https://gdi-ee.example.org",
        "record",
    )
}

#[test]
fn include_all_and_hit_leave_result_sets_unchanged() {
    for include in [
        IncludeResultsetResponses::All,
        IncludeResultsetResponses::Hit,
    ] {
        let shaped = apply_include_resultset_responses(covid_response(), include);
        let body = shaped
            .response
            .as_ref()
            .expect("ALL/HIT keep the response body");
        assert_eq!(body.result_sets.len(), 1, "ALL/HIT keep the matching set");
        // responseSummary still reflects the true match.
        assert!(shaped.response_summary.exists);
        assert_eq!(shaped.response_summary.num_total_results, Some(1));
    }
}

#[test]
fn include_miss_empties_result_sets_but_keeps_summary() {
    // `covid_response()` holds one dataset and it hits, so MISS, which keeps only the
    // `exists:false` misses, drops it and leaves an empty `resultSets` with the response
    // member still present. `include_miss_returns_only_the_miss_dataset` covers MISS
    // returning an actual miss.
    let shaped =
        apply_include_resultset_responses(covid_response(), IncludeResultsetResponses::Miss);
    let body = shaped
        .response
        .as_ref()
        .expect("MISS keeps the response member, with empty resultSets");
    assert!(
        body.result_sets.is_empty(),
        "MISS drops the only dataset (a hit)"
    );
    // responseSummary is untouched: it still reports the true match.
    assert!(shaped.response_summary.exists);
    assert_eq!(shaped.response_summary.num_total_results, Some(1));
}

#[test]
fn include_none_keeps_response_member_with_empty_result_sets() {
    // NONE keeps the `response` member with an empty `resultSets` rather than dropping it:
    // `beaconResultsetsResponse` requires `response`, so dropping it would serve a
    // schema-non-conformant body at record granularity.
    let shaped =
        apply_include_resultset_responses(covid_response(), IncludeResultsetResponses::None);
    let body = shaped
        .response
        .as_ref()
        .expect("NONE keeps the response member, with empty resultSets");
    assert!(body.result_sets.is_empty(), "NONE clears resultSets");
    // meta and responseSummary survive and report the true match.
    assert!(shaped.response_summary.exists);
    assert_eq!(shaped.response_summary.num_total_results, Some(1));

    // The serialized JSON keeps the `response` key: the beaconResultsetsResponse schema
    // requires meta, responseSummary and response.
    let v = serde_json::to_value(&shaped).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("meta"));
    assert!(obj.contains_key("responseSummary"));
    assert!(
        obj.contains_key("response"),
        "NONE keeps the schema-required response key"
    );
}

#[test]
fn granularity_record_is_unchanged() {
    // record serves the full body; returnedGranularity stays "record".
    let shaped = shape_for_granularity(covid_response(), "record");
    assert_eq!(shaped.meta.returned_granularity, "record");
    let body = shaped.response.as_ref().expect("record keeps the body");
    assert_eq!(body.result_sets.len(), 1);
    assert_eq!(shaped.response_summary.num_total_results, Some(1));
}

#[test]
fn granularity_count_drops_body_keeps_count() {
    // count: no per-population body, but exists and numTotalResults remain.
    let shaped = shape_for_granularity(covid_response(), "count");
    assert_eq!(shaped.meta.returned_granularity, "count");
    assert!(shaped.response.is_none(), "count drops the response body");
    assert!(shaped.response_summary.exists);
    assert_eq!(shaped.response_summary.num_total_results, Some(1));

    let v = serde_json::to_value(&shaped).unwrap();
    let obj = v.as_object().unwrap();
    assert!(
        !obj.contains_key("response"),
        "count omits the response key"
    );
    assert_eq!(v["responseSummary"]["numTotalResults"].as_u64(), Some(1));
    assert_eq!(v["meta"]["returnedGranularity"], "count");
}

#[test]
fn granularity_boolean_discloses_only_exists() {
    // boolean: no body and no count, so only `exists` is disclosed.
    let shaped = shape_for_granularity(covid_response(), "boolean");
    assert_eq!(shaped.meta.returned_granularity, "boolean");
    assert!(shaped.response.is_none(), "boolean drops the response body");
    assert!(shaped.response_summary.exists);
    assert_eq!(
        shaped.response_summary.num_total_results, None,
        "boolean withholds the count"
    );

    let v = serde_json::to_value(&shaped).unwrap();
    let summary = v["responseSummary"].as_object().unwrap();
    assert!(summary.contains_key("exists"));
    assert!(
        !summary.contains_key("numTotalResults"),
        "boolean omits numTotalResults so the count is not disclosed"
    );
    assert_eq!(v["meta"]["returnedGranularity"], "boolean");
}

/// `n` synthetic `AlleleRow`s at distinct positions, each its own surviving group, with
/// floor 0 so none are suppressed.
fn synthetic_rows(positions: &[i32]) -> Vec<AlleleRow> {
    positions
        .iter()
        .map(|&pos| AlleleRow {
            pos,
            ref_: "A".to_owned(),
            alt: "T".to_owned(),
            vt: Vt::Snp,
            population: "Total".to_owned(),
            af: 0.01,
            ac: Some(10),
            ac_hom: Some(2),
            ac_het: Some(8),
            ac_hemi: None,
            an: Some(1000),
        })
        .collect()
}

/// One synthetic row at an explicit `(pos, ref, alt)` with an explicit `AC`.
fn row_at(pos: i32, ref_: &str, alt: &str, ac: i32) -> AlleleRow {
    AlleleRow {
        pos,
        ref_: ref_.to_owned(),
        alt: alt.to_owned(),
        vt: Vt::Snp,
        population: "Total".to_owned(),
        af: 0.01,
        ac: Some(ac),
        ac_hom: Some(0),
        ac_het: Some(ac),
        ac_hemi: None,
        an: Some(1000),
    }
}

/// Rows that share a POS but differ in REF or ALT are distinct variants and must not be
/// coalesced into one group.
///
/// Grouping keys on the composite `(POS, REF, ALT)`. The other fixtures in this crate use
/// distinct positions, so this is what exercises the discrimination half of that key:
/// dropping the `alt` or `ref_` comparison from the coalescing condition merges two
/// different alleles into a single group and fails nothing else.
///
/// This is the shape production sees. The converter splits multi-allelic VCF lines (see
/// `core::convert`'s `multi_allelic_split_stores_minimal_alleles_not_the_union_ref`), so a
/// site with `ALT=T,G` becomes these two rows.
///
/// The consequence is not only a wrong variant list. Merged groups pool their allele counts,
/// so a site whose alleles are individually below the k-anonymity floor could surface as one
/// group above it, making the merge a disclosure risk rather than a display defect.
#[test]
fn rows_sharing_a_pos_but_differing_in_alt_are_separate_groups() {
    let rows = vec![
        // A multi-allelic site: same POS and REF, two different ALTs.
        row_at(100, "A", "T", 11),
        row_at(100, "A", "G", 22),
        // Same POS again, but a different REF as well (an indel at the same coordinate).
        row_at(100, "AT", "A", 33),
        // A control at another position, so a total collapse is distinguishable from a
        // partial one.
        row_at(200, "C", "G", 44),
    ];

    let cfg = covid_manifest_config(); // min_allele_count 0 — no suppression in play
    let bcfg = crate::fixtures::beacon_cfg();
    let resp = assemble(
        vec![("DS-1".to_owned(), &cfg, None, "3", page(&cfg, rows))],
        &Pagination::new(0, 100),
        &bcfg,
        "https://gdi-ee.example.org",
        "record",
    );

    let rs = &resp.response.as_ref().expect("a body").result_sets[0];
    assert_eq!(
        rs.results_count, 4,
        "four distinct (POS, REF, ALT) keys must yield four groups, not a merge"
    );

    let keys: Vec<(i64, String, String)> = rs
        .results
        .iter()
        .map(|e| {
            (
                e.variation.location.interval.start.value,
                e.variation.reference_bases.clone(),
                e.variation.alternate_bases.clone(),
            )
        })
        .collect();
    assert_eq!(
        keys.len(),
        4,
        "every group is emitted, not just counted: {keys:?}"
    );
    let distinct: std::collections::BTreeSet<_> = keys.iter().collect();
    assert_eq!(
        distinct.len(),
        4,
        "the emitted groups are distinct — a merge would repeat a key: {keys:?}"
    );

    // The three groups at POS 100 keep their own allele counts. Pooling them (11+22+33) is
    // the disclosure-relevant failure, so assert the counts stayed apart rather than only
    // that the group count is right.
    let mut at_100: Vec<Option<u64>> = rs
        .results
        .iter()
        .filter(|e| e.variation.location.interval.start.value == 100)
        .map(|e| e.frequency_in_populations[0].frequencies[0].allele_count)
        .collect();
    at_100.sort_unstable();
    assert_eq!(
        at_100,
        vec![Some(11), Some(22), Some(33)],
        "each allele keeps its own AC; merged groups would pool them"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// `resultsCount` is the true surviving group count, invariant under paging, while
    /// `results[]` is the position-sorted groups sliced by `[skip, skip+limit)` and clamped.
    /// Distinct positions give N groups, and floor 0 keeps them all.
    #[test]
    fn assemble_pagination_slices_and_count(
        positions in proptest::collection::hash_set(0i32..1_000_000, 1..40),
        skip in 0u64..50,
        limit in 0u64..50,
    ) {
        let mut sorted: Vec<i32> = positions.into_iter().collect();
        sorted.sort_unstable();
        let n = sorted.len();
        let rows = synthetic_rows(&sorted);

        let cfg = covid_manifest_config(); // min_allele_count 0
        let bcfg = crate::fixtures::beacon_cfg();           // min_allele_count default 0
        let resp = assemble(
            vec![("DS-1".to_owned(), &cfg, None, "3", page_win(&cfg, rows, skip, limit))],
            &Pagination::new(skip, limit),
            &bcfg,
            "https://gdi-ee.example.org",
            "record",
        );

        let body = resp.response.as_ref().expect("non-empty groups -> a body");
        prop_assert_eq!(body.result_sets.len(), 1);
        let rs = &body.result_sets[0];

        // resultsCount = the true surviving count, independent of skip/limit.
        prop_assert_eq!(rs.results_count, u64::try_from(n).unwrap());

        // results[] is the sorted positions sliced by [skip, skip+limit) and clamped. The
        // synthetic ref_ is one base, so interval.start == pos.
        let skip_us = usize::try_from(skip).unwrap();
        let take_us = usize::try_from(limit).unwrap();
        let expected: Vec<i32> = sorted.iter().copied().skip(skip_us).take(take_us).collect();
        let got: Vec<i32> = rs
            .results
            .iter()
            .map(|e| i32::try_from(e.variation.location.interval.start.value).unwrap())
            .collect();
        prop_assert_eq!(got, expected);
    }
}

// ---- includeResultsetResponses per-dataset accounting ----
//
// A g_variants query that resolves an assembly scans every dataset of that assembly, and a
// dataset with no surviving group is a per-dataset miss. Beacon v2
// `includeResultsetResponses` selects which per-dataset resultSets are returned: HIT, the
// default, only hits; MISS only misses; ALL both; NONE none. `responseSummary` always
// reports the true aggregate regardless of the filter. Dropping every miss would leave a
// `0` indistinguishable from a dataset that was never consulted.

/// Two datasets of the same assembly: `HIT-DS` holds the COVID variant, `MISS-DS`
/// does not (empty scan). Assembled at record granularity, unfiltered.
fn hit_and_miss_response() -> BeaconResponse {
    let cfg = covid_manifest_config();
    assemble(
        vec![
            (
                "HIT-DS".to_owned(),
                &cfg,
                None,
                "3",
                page(&cfg, covid_rows()),
            ),
            (
                "MISS-DS".to_owned(),
                &cfg,
                None,
                "3",
                page(&cfg, Vec::new()),
            ),
        ],
        &Pagination::new(0, 10),
        &crate::fixtures::beacon_cfg(),
        "https://gdi-ee.example.org",
        "record",
    )
}

#[test]
fn include_all_returns_both_hit_and_miss_datasets() {
    let shaped =
        apply_include_resultset_responses(hit_and_miss_response(), IncludeResultsetResponses::All);
    let body = shaped
        .response
        .as_ref()
        .expect("ALL keeps the response body");
    let ids: Vec<&str> = body.result_sets.iter().map(|rs| rs.id.as_str()).collect();
    assert!(
        ids.contains(&"HIT-DS") && ids.contains(&"MISS-DS"),
        "ALL must return every considered dataset, got {ids:?}"
    );
    let miss = body
        .result_sets
        .iter()
        .find(|rs| rs.id == "MISS-DS")
        .expect("the miss dataset is present under ALL");
    assert!(!miss.exists);
    assert_eq!(miss.results_count, 0);
    assert!(miss.results.is_empty());
    // The aggregate summary still reports only the true match, which is the hit.
    assert!(shaped.response_summary.exists);
    assert_eq!(shaped.response_summary.num_total_results, Some(1));
}

#[test]
fn include_miss_returns_only_the_miss_dataset() {
    let shaped =
        apply_include_resultset_responses(hit_and_miss_response(), IncludeResultsetResponses::Miss);
    let body = shaped
        .response
        .as_ref()
        .expect("MISS keeps the response body");
    assert_eq!(
        body.result_sets.len(),
        1,
        "only the miss remains under MISS"
    );
    assert_eq!(body.result_sets[0].id, "MISS-DS");
    assert!(!body.result_sets[0].exists);
    // responseSummary is independent of the filter: it still reports the true match.
    assert!(shaped.response_summary.exists);
    assert_eq!(shaped.response_summary.num_total_results, Some(1));
}

#[test]
fn include_hit_hides_miss_datasets_preserving_default_wire() {
    let shaped =
        apply_include_resultset_responses(hit_and_miss_response(), IncludeResultsetResponses::Hit);
    let body = shaped
        .response
        .as_ref()
        .expect("HIT keeps the response body");
    assert_eq!(
        body.result_sets.len(),
        1,
        "HIT returns only the matching dataset"
    );
    assert_eq!(body.result_sets[0].id, "HIT-DS");
    assert!(body.result_sets[0].exists);
}

#[test]
fn suppressed_and_absent_datasets_assemble_to_identical_miss() {
    // The same dataset id and the same floor: one holds the variant entirely below the
    // floor, the other does not hold it at all. Both must assemble to a byte-identical
    // `exists:false` resultSet, or the wire reveals which case occurred, which is the
    // membership inference the floor exists to prevent.
    let mut cfg = covid_manifest_config();
    cfg.min_allele_count = 1_000_000; // above the COVID Total AC (618): fully suppressed.

    let suppressed = assemble(
        vec![("D".to_owned(), &cfg, None, "3", page(&cfg, covid_rows()))],
        &Pagination::new(0, 10),
        &crate::fixtures::beacon_cfg(),
        "https://gdi-ee.example.org",
        "record",
    );
    let absent = assemble(
        vec![("D".to_owned(), &cfg, None, "3", page(&cfg, Vec::new()))],
        &Pagination::new(0, 10),
        &crate::fixtures::beacon_cfg(),
        "https://gdi-ee.example.org",
        "record",
    );
    let s = serde_json::to_value(&suppressed).unwrap();
    let a = serde_json::to_value(&absent).unwrap();
    assert_eq!(
        s["response"]["resultSets"], a["response"]["resultSets"],
        "suppressed and absent must be indistinguishable at the resultSet level"
    );
    assert_eq!(s["response"]["resultSets"][0]["exists"], false);
}

// ---- gdiDatasetInfo in-band disclosure ----
//
// Every resultSet, hit or miss, carries the effective suppression floor, so a client
// reading a `0` can bound the true count to `{0} ∪ [1, floor)` from the query response
// itself without cross-referencing `/datasets`. The floor is the same `max(node, dataset)`
// the suppression applied, so the disclosure can never understate it.

#[test]
fn miss_resultset_discloses_floor_so_zero_is_interpretable() {
    let mut cfg = covid_manifest_config();
    cfg.min_allele_count = 1_000_000; // suppresses the COVID variant entirely.
    let resp = assemble(
        vec![("D".to_owned(), &cfg, None, "3", page(&cfg, covid_rows()))],
        &Pagination::new(0, 10),
        &crate::fixtures::beacon_cfg(),
        "https://gdi-ee.example.org",
        "record",
    );
    let shaped = apply_include_resultset_responses(resp, IncludeResultsetResponses::All);
    let body = shaped.response.as_ref().expect("ALL keeps the body");
    let miss = &body.result_sets[0];
    assert!(!miss.exists, "the fully-suppressed dataset is a miss");
    assert_eq!(
        miss.gdi_dataset_info.min_allele_count, 1_000_000,
        "the miss must disclose the floor that suppressed it"
    );
    assert_eq!(miss.gdi_dataset_info.assembly, "GRCh38");

    // And it is on the wire under the namespaced camelCase key the contract uses.
    let v = serde_json::to_value(&body.result_sets[0]).unwrap();
    assert_eq!(v["gdiDatasetInfo"]["minAlleleCount"], 1_000_000);
}

#[test]
fn disclosed_floor_is_effective_max_of_node_and_dataset() {
    // node floor 5, dataset floor 2, so the effective floor is 5 and the COVID variant
    // still hits.
    let mut cfg = covid_manifest_config();
    cfg.min_allele_count = 2;
    let bcfg = BeaconParams {
        min_allele_count: 5,
        ..crate::fixtures::beacon_cfg()
    };
    let resp = assemble(
        vec![(
            "D".to_owned(),
            &cfg,
            None,
            "3",
            page_with(&cfg, &bcfg, covid_rows()),
        )],
        &Pagination::new(0, 10),
        &bcfg,
        "https://gdi-ee.example.org",
        "record",
    );
    let rs = &resp.response.as_ref().unwrap().result_sets[0];
    assert_eq!(
        rs.gdi_dataset_info.min_allele_count, 5,
        "the node floor wins when higher"
    );

    // node floor 0, the default, and dataset floor 7, so the effective floor is 7.
    let mut cfg2 = covid_manifest_config();
    cfg2.min_allele_count = 7;
    let resp2 = assemble(
        vec![("D".to_owned(), &cfg2, None, "3", page(&cfg2, covid_rows()))],
        &Pagination::new(0, 10),
        &crate::fixtures::beacon_cfg(),
        "https://gdi-ee.example.org",
        "record",
    );
    let rs2 = &resp2.response.as_ref().unwrap().result_sets[0];
    assert_eq!(
        rs2.gdi_dataset_info.min_allele_count, 7,
        "the dataset floor wins when higher"
    );
}

#[test]
fn resultset_discloses_dataset_populations() {
    let cfg = covid_manifest_config();
    let pops = vec!["FI_M".to_owned(), "Total".to_owned()];
    let resp = assemble(
        vec![(
            "D".to_owned(),
            &cfg,
            Some(pops.as_slice()),
            "3",
            page(&cfg, covid_rows()),
        )],
        &Pagination::new(0, 10),
        &crate::fixtures::beacon_cfg(),
        "https://gdi-ee.example.org",
        "record",
    );
    let rs = &resp.response.as_ref().unwrap().result_sets[0];
    assert_eq!(
        rs.gdi_dataset_info.populations.as_deref(),
        Some(pops.as_slice()),
        "the dataset's served populations are disclosed on the resultSet"
    );
}

/// `pagination.limit` is applied per dataset, not across the whole response.
///
/// Each selected dataset materialises its own `ResultSet` with its own `[skip, skip+limit)`
/// window and `assemble` concatenates them, so a page carries up to `datasets × limit`
/// entries while `meta.receivedRequestSummary.pagination.limit` echoes the smaller number.
/// The other paging tests use one dataset, the shape where per-dataset and global paging
/// are indistinguishable.
///
/// Pinned rather than changed: the GDI Beacon nests results under `resultSets`, Beacon v2
/// does not settle paging semantics across them, and making `limit` global would change
/// bytes on the wire for every multi-dataset consumer, which is an externally breaking
/// change. `docs/api.md` and `BeaconParams::max_page_limit` say "per dataset", and this
/// test keeps them honest.
#[test]
fn pagination_limit_is_per_dataset_not_global() {
    let positions: Vec<i32> = (0..10).map(|i| i * 100).collect();
    let cfg = covid_manifest_config();
    let bcfg = crate::fixtures::beacon_cfg();
    let limit = 3u64;

    let resp = assemble(
        vec![
            (
                "DS-1".to_owned(),
                &cfg,
                None,
                "3",
                page_win(&cfg, synthetic_rows(&positions), 0, limit),
            ),
            (
                "DS-2".to_owned(),
                &cfg,
                None,
                "3",
                page_win(&cfg, synthetic_rows(&positions), 0, limit),
            ),
        ],
        &Pagination::new(0, limit),
        &bcfg,
        "https://gdi-ee.example.org",
        "record",
    );

    let body = resp.response.as_ref().expect("non-empty groups -> a body");
    assert_eq!(
        body.result_sets.len(),
        2,
        "one resultSet per selected dataset"
    );
    for rs in &body.result_sets {
        assert_eq!(
            rs.results.len(),
            usize::try_from(limit).unwrap(),
            "each dataset pages independently"
        );
        assert_eq!(
            rs.results_count,
            u64::try_from(positions.len()).unwrap(),
            "resultsCount stays the true surviving count, unaffected by paging"
        );
    }
    let total: usize = body.result_sets.iter().map(|rs| rs.results.len()).sum();
    assert_eq!(
        total,
        usize::try_from(limit).unwrap() * 2,
        "the concatenated page is datasets x limit — an operator sizing a buffer from the \
         echoed `limit` under-provisions by the dataset count"
    );
}
