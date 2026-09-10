//! Disclosure-control (k-anonymity) property tests, a bounded model-check of the
//! single-variant differencing gate, and a demonstration of the acknowledged
//! cross-dataset residual.
//!
//! The suppression logic lives in `query.rs` (`row_survives`, `emittable_rows`,
//! `gate_subcounts`). `emittable_rows` and `VariantGroup` are private, so these tests drive
//! it through the public [`assemble`] boundary.
//!
//! Scope: every property here runs with the byte ceiling maxed and `UnboundedRetention` in
//! place of a real sink, so retention refusal, the 503 a saturated node returns instead of
//! an answer, is not covered. A property test must not shed under its own memory ceiling.
//! The charging path is covered directly by
//! `both_scan_paths_actually_charge_their_sink_and_honour_a_refusal` and
//! `the_aggregate_path_credits_back_each_block_buffer_it_has_folded` in `query.rs`.
//!
//! What is asserted here:
//! * **Monotonicity** — raising the floor only ever removes emitted cells or withholds
//!   counts; it never reveals a previously-suppressed cell or changes a surviving count.
//! * **Collapse-to-Total** — whenever any cell in a variant group is suppressed, the
//!   emitted breakdown is Total-only, or empty, never a partial subset that would let a
//!   client recover the suppressed cell by subtraction. This is the anti-differencing gate.
//! * **Cross-dataset isolation** — adding a second dataset to a query never changes the
//!   first dataset's emitted result.
//! * **Bounded model-check** — the collapse gate is exhaustively hole-free over a small
//!   space of coherent variant groups: no config lets a suppressed cell survive
//!   single-variant subtraction.
//! * **Membership-inference indistinguishability** — a floor-suppressed cell, a genuinely
//!   absent cell, and a queried-but-nonexistent dataset produce wire-indistinguishable
//!   responses across boolean, count and record granularity, driven through
//!   `scan_dataset`, `assemble` and `shape_for_granularity`.
//! * **Cross-dataset residual**, demonstrated rather than fixed — with the node floor at
//!   its shipped default `0`, per-dataset manifest floors are independent, so a permissive
//!   sibling dataset leaks a cell a strict dataset suppresses. This is the
//!   `docs/architecture.md` limit that cross-dataset differencing is out of scope, made
//!   concrete.
//!
//! The residual multi-variant statistical reconstruction, Homer-style over many variants of
//! a shared cohort, is out of scope in `query.rs` and requires differential privacy. It is
//! characterised in the threat-model doc rather than attacked here.

#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::collections::BTreeMap;

use gdi_node_standalone_beacon::BeaconParams;
use gdi_node_standalone_beacon::model::{BeaconResponse, Pagination};
use gdi_node_standalone_beacon::query::{
    DatasetPage, PageSpec, UnboundedRetention, assemble, effective_floor, scan_dataset,
    shape_for_granularity,
};
use gdi_node_standalone_beacon::request::{Predicates, QueryKind};
use gdi_node_standalone_core::convert::{ConvertOptions, convert_vcf};
use gdi_node_standalone_core::model::{Assembly, DatasetMode, ManifestConfig};
use gdi_node_standalone_core::parquet_io::{AlleleRow, DatasetDecryptor};
use gdi_node_standalone_core::validate_parquet::ParquetCaps;
use gdi_node_standalone_core::variant::Vt;
use proptest::prelude::*;

const BASE: &str = "https://gdi-ee.example.org";

/// The eight non-`Total` populations of the redundant marginal set (country×sex leaves
/// + per-country + per-sex). Their presence-or-absence is the collapse observable.
const NON_TOTAL_COUNT: usize = 8;

/// A manifest config with the given per-dataset suppression floor.
fn manifest_with_floor(floor: u32) -> ManifestConfig {
    ManifestConfig {
        mode: DatasetMode::Aggregated,
        block_range: 10_000_000,
        af_source: Some("The Genome of Europe".to_owned()),
        af_source_reference: None,
        min_allele_count: floor,
        hide_lower_counts: None,
        assembly: Assembly {
            reference: "GRCh38".to_owned(),
        },
        manifest_version: 1,
        generated_by: "gdi-dataset-tool/test".to_owned(),
    }
}

/// One `(population, ac, an)` cell as an `AlleleRow`, with `af = ac/an` as a client sees
/// it. Genotype sub-counts are left `None`, because these tests exercise the AC plane.
#[expect(
    clippy::cast_precision_loss,
    reason = "test cell counts are small and exact in f32"
)]
fn row(pos: i32, pop: &str, ac: u64, an: u64) -> AlleleRow {
    let af = if an > 0 { ac as f32 / an as f32 } else { 0.0 };
    AlleleRow {
        pos,
        ref_: "A".to_owned(),
        alt: "T".to_owned(),
        vt: Vt::Snp,
        population: pop.to_owned(),
        af,
        ac: Some(i32::try_from(ac).unwrap()),
        ac_hom: None,
        ac_het: None,
        ac_hemi: None,
        an: Some(i32::try_from(an).unwrap()),
    }
}

/// The same cell as [`row`], with the exact `AC` column absent. The client still derives
/// the count as `round(AF * AN)`, which is what `alt_carriers` computes.
fn row_af_only(pos: i32, pop: &str, ac: u64, an: u64) -> AlleleRow {
    AlleleRow {
        ac: None,
        ..row(pos, pop, ac, an)
    }
}

/// Build a coherent redundant marginal set for one variant from the four country×sex leaf
/// cells (FI and EE × M and F), computing the per-country, per-sex and Total marginals so
/// every summation identity the suppression logic assumes holds.
fn coherent_variant(
    pos: i32,
    fi_m: (u64, u64),
    fi_f: (u64, u64),
    ee_m: (u64, u64),
    ee_f: (u64, u64),
) -> Vec<AlleleRow> {
    let add = |a: (u64, u64), b: (u64, u64)| (a.0 + b.0, a.1 + b.1);
    let fi = add(fi_m, fi_f);
    let ee = add(ee_m, ee_f);
    let m = add(fi_m, ee_m);
    let f = add(fi_f, ee_f);
    let total = add(fi, ee);
    vec![
        row(pos, "FI_M", fi_m.0, fi_m.1),
        row(pos, "FI_F", fi_f.0, fi_f.1),
        row(pos, "EE_M", ee_m.0, ee_m.1),
        row(pos, "EE_F", ee_f.0, ee_f.1),
        row(pos, "FI", fi.0, fi.1),
        row(pos, "EE", ee.0, ee.1),
        row(pos, "M", m.0, m.1),
        row(pos, "F", f.0, f.1),
        row(pos, "Total", total.0, total.1),
    ]
}

/// The emitted `population -> (alleleCount, alleleNumber)` map for `dataset_id` in the
/// response, empty when that dataset's variant was dropped. This is the client observable.
fn emitted_for(
    resp: &BeaconResponse,
    dataset_id: &str,
) -> BTreeMap<String, (Option<u64>, Option<u64>)> {
    let Some(body) = resp.response.as_ref() else {
        return BTreeMap::new();
    };
    let Some(rs) = body.result_sets.iter().find(|rs| rs.id == dataset_id) else {
        return BTreeMap::new();
    };
    let Some(entry) = rs.results.first() else {
        return BTreeMap::new();
    };
    entry.frequency_in_populations[0]
        .frequencies
        .iter()
        .map(|f| (f.population.clone(), (f.allele_count, f.allele_number)))
        .collect()
}

/// The page the scan would have produced for `rows` under `cfg`'s effective floor.
///
/// `bcfg` must be the params the caller then passes to `assemble`. The floor is chosen once,
/// at scan time, and `assemble_dataset` re-applies it. Passing the default here while
/// assembling under a node floor would assemble a page suppressed at the wrong floor, which
/// is what this argument prevents.
fn page_for(cfg: &ManifestConfig, bcfg: &BeaconParams, rows: Vec<AlleleRow>) -> DatasetPage {
    DatasetPage::from_rows(
        rows,
        PageSpec {
            floor: effective_floor(cfg, bcfg),
            ..PageSpec::everything()
        },
    )
    .expect("page")
}

fn assemble_one(dataset_id: &str, cfg: &ManifestConfig, rows: Vec<AlleleRow>) -> BeaconResponse {
    // The scan decides suppression, grouping and paging. These properties feed rows
    // directly, so they build the page the scan would have produced, taking the floor from
    // the same `effective_floor` pair `assemble_dataset` applies.
    let page = page_for(cfg, &crate::fixtures::beacon_cfg(), rows);
    assemble(
        vec![(dataset_id.to_owned(), cfg, None, "3", page)],
        &Pagination::new(0, 10),
        &crate::fixtures::beacon_cfg(),
        BASE,
        "record",
    )
}

/// A leaf strategy: `(ac, an)` with `an >= ac` (can't have more alt alleles than total).
fn leaf() -> impl Strategy<Value = (u64, u64)> {
    (0u64..400, 0u64..1600).prop_map(|(ac, extra)| (ac, ac + extra))
}

proptest! {
    /// Raising the floor is monotone: every population still emitted at the higher floor is
    /// also emitted at the lower one with the same allele count and number. A higher floor
    /// only withholds; it never reveals or changes a surviving cell.
    #[test]
    fn raising_the_floor_only_suppresses_never_reveals(
        fi_m in leaf(), fi_f in leaf(), ee_m in leaf(), ee_f in leaf(),
        f_low in 0u32..300, delta in 0u32..300,
    ) {
        let f_high = f_low + delta;
        let low = emitted_for(
            &assemble_one("DS", &manifest_with_floor(f_low),
                coherent_variant(100, fi_m, fi_f, ee_m, ee_f)),
            "DS",
        );
        let high = emitted_for(
            &assemble_one("DS", &manifest_with_floor(f_high),
                coherent_variant(100, fi_m, fi_f, ee_m, ee_f)),
            "DS",
        );
        for (pop, counts) in &high {
            prop_assert_eq!(
                low.get(pop), Some(counts),
                "population {} emitted at floor {} but not identically at the lower floor {}",
                pop, f_high, f_low
            );
        }
    }

    /// The anti-differencing gate: whenever any cell is suppressed, the emitted breakdown
    /// is Total-only, or empty, never a partial subset of the non-Total populations, which
    /// would let a client recover the suppressed cell by subtraction.
    #[test]
    fn suppression_collapses_to_total_never_a_partial_breakdown(
        fi_m in leaf(), fi_f in leaf(), ee_m in leaf(), ee_f in leaf(),
        floor in 1u32..400,
    ) {
        let e = emitted_for(
            &assemble_one("DS", &manifest_with_floor(floor),
                coherent_variant(100, fi_m, fi_f, ee_m, ee_f)),
            "DS",
        );
        let non_total = e.keys().filter(|p| p.as_str() != "Total").count();
        prop_assert!(
            non_total == 0 || non_total == NON_TOTAL_COUNT,
            "emitted must be the full breakdown or Total-only, never a partial subset; got {:?}",
            e.keys().collect::<Vec<_>>()
        );
    }

    /// Cross-dataset isolation: a dataset's emitted result is identical whether it is
    /// queried alone or alongside another dataset, because per-dataset suppression is
    /// independent.
    #[test]
    fn adding_a_second_dataset_never_changes_the_first(
        a0 in leaf(), a1 in leaf(), a2 in leaf(), a3 in leaf(),
        b0 in leaf(), b1 in leaf(), b2 in leaf(), b3 in leaf(),
        fa in 0u32..300, fb in 0u32..300,
    ) {
        let cfg_a = manifest_with_floor(fa);
        let cfg_b = manifest_with_floor(fb);
        let rows_a = coherent_variant(100, a0, a1, a2, a3);
        let rows_b = coherent_variant(100, b0, b1, b2, b3);

        let alone = emitted_for(&assemble_one("A", &cfg_a, rows_a.clone()), "A");
        let together = emitted_for(
            &assemble(
                vec![
                    ("A".to_owned(), &cfg_a, None, "3", page_for(&cfg_a, &crate::fixtures::beacon_cfg(), rows_a)),
                    ("B".to_owned(), &cfg_b, None, "3", page_for(&cfg_b, &crate::fixtures::beacon_cfg(), rows_b)),
                ],
                &Pagination::new(0, 10), &crate::fixtures::beacon_cfg(), BASE, "record",
            ),
            "A",
        );
        prop_assert_eq!(alone, together, "dataset A's result changed when B was added");
    }
}

/// Bounded, exhaustive model-check of the single-variant differencing gate: over a small
/// space of coherent variant groups, whenever a cell is suppressed the group must collapse
/// to Total-only, so no suppressed cell is recoverable by single-variant subtraction. This
/// covers the enumerated space exhaustively rather than by random sampling.
#[test]
fn bounded_model_check_single_variant_gate_is_hole_free() {
    let floor = 3u32;
    let cfg = manifest_with_floor(floor);
    let an = 1000u64; // large, fixed → the complement tail never fires; isolates the AC tail
    let mut configs = 0u64;
    let mut collapsed = 0u64;
    for a in 0..=6u64 {
        for b in 0..=6u64 {
            for c in 0..=6u64 {
                for d in 0..=6u64 {
                    let e = emitted_for(
                        &assemble_one(
                            "DS",
                            &cfg,
                            coherent_variant(100, (a, an), (b, an), (c, an), (d, an)),
                        ),
                        "DS",
                    );
                    let non_total = e.keys().filter(|p| p.as_str() != "Total").count();
                    assert!(
                        non_total == 0 || non_total == NON_TOTAL_COUNT,
                        "single-variant gate hole at leaves ({a},{b},{c},{d}) floor {floor}: \
                         partial breakdown {:?} enables subtraction",
                        e.keys().collect::<Vec<_>>()
                    );
                    configs += 1;
                    if non_total == 0 {
                        collapsed += 1;
                    }
                }
            }
        }
    }
    // The enumerated space is 7^4 coherent groups, a mix of collapsed and fully-emitted,
    // with no partial-breakdown holes.
    assert_eq!(configs, 7 * 7 * 7 * 7);
    assert!(
        collapsed > 0 && collapsed < configs,
        "sanity: the space must contain both collapsed and fully-emitted groups (got {collapsed}/{configs})"
    );
}

/// The completeness gate must depend on the count being derivable, not on the `AC` column
/// being present, because the client's subtraction does not depend on it either.
///
/// `marginal_set_incomplete` is the defence for a sibling withheld before the data reached
/// this node, by a build that dropped a below-floor population without collapsing. It
/// anchors on `Total` and checks whether an axis's present members leave a remainder in
/// `1..floor`. `row_survives` treats `round(AF * AN)` as the client's own derivation of a
/// missing `AC` (`alt_carriers`), so an axis whose members ship `AF` and `AN` but no `AC`
/// is as subtractable as one that ships `AC`.
///
/// Both encodings below describe the same cohort, with `Total` at 10 carriers, `M` at 9 and
/// an `F` of 1 withheld, and the client recovers `F = Total - M = 1` from either. The gate
/// collapses both to `Total`.
#[test]
fn the_completeness_gate_does_not_depend_on_the_ac_column_being_present() {
    let floor = 5;
    let cfg = manifest_with_floor(floor);
    let pops = |rows: Vec<AlleleRow>| -> Vec<String> {
        emitted_for(&assemble_one("DS", &cfg, rows), "DS")
            .into_keys()
            .collect()
    };

    // Exact `AC` on the surviving sibling: remainder 10 - 9 = 1 ∈ 1..5 → collapse.
    assert_eq!(
        pops(vec![row(100, "Total", 10, 100), row(100, "M", 9, 100)]),
        vec!["Total".to_owned()],
        "an exact-AC sibling must trigger the collapse"
    );

    // Same cohort, `AC` column absent on the sibling. `round(0.09 * 100) = 9`, so the
    // client's subtraction is unchanged, and so is the gate's verdict.
    assert_eq!(
        pops(vec![
            row(100, "Total", 10, 100),
            row_af_only(100, "M", 9, 100)
        ]),
        vec!["Total".to_owned()],
        "a sibling whose count is derivable from AF*AN must trigger the same collapse; \
         dropping the AC column must not disable the anti-differencing gate"
    );
}

/// A complete axis must not be collapsed just because its members are `AF`-only: the
/// remainder is 0, not in `1..floor`. This guards the rule above against over-collapsing.
#[test]
fn a_complete_af_only_axis_is_not_collapsed() {
    let cfg = manifest_with_floor(5);
    let rows = vec![
        row(100, "Total", 20, 200),
        row_af_only(100, "M", 12, 100),
        row_af_only(100, "F", 8, 100),
    ];
    let emitted: Vec<String> = emitted_for(&assemble_one("DS", &cfg, rows), "DS")
        .into_keys()
        .collect();
    assert_eq!(
        emitted,
        vec!["F".to_owned(), "M".to_owned(), "Total".to_owned()],
        "a complete AF-only breakdown leaves remainder 0 and must be emitted in full"
    );
}

/// The acknowledged cross-dataset residual, made concrete. This demonstrates the
/// `docs/architecture.md` limit that cross-dataset differencing is out of scope; it is not a
/// code defect.
///
/// With the node `[beacon].min_allele_count` at its shipped default `0`, each dataset's
/// effective floor is its own manifest floor. Two datasets that share a subgroup but set
/// different floors therefore disagree: the permissive one emits the cell the strict one
/// suppresses, and an attacker reads the suppressed value from the sibling in full. The
/// mitigation is a non-zero node-wide floor, which `max(node, manifest)` enforces on every
/// dataset. That is the risk of shipping suppression off by default.
#[test]
fn cross_dataset_floor_asymmetry_leaks_a_suppressed_cell() {
    // FI_M ac=2 is far below dataset B's floor of 200, and shared with permissive dataset A.
    let variant = || coherent_variant(100, (2, 1400), (105, 1400), (99, 1300), (111, 1300));
    let cfg_open = manifest_with_floor(0); // dataset A: an operator left the floor at 0
    let cfg_guarded = manifest_with_floor(200); // dataset B: a strict floor

    // Node floor 0, the shipped default, so max(node, manifest) is the manifest floor.
    let resp = assemble(
        vec![
            (
                "DS-open".to_owned(),
                &cfg_open,
                None,
                "3",
                page_for(&cfg_open, &crate::fixtures::beacon_cfg(), variant()),
            ),
            (
                "DS-guarded".to_owned(),
                &cfg_guarded,
                None,
                "3",
                page_for(&cfg_guarded, &crate::fixtures::beacon_cfg(), variant()),
            ),
        ],
        &Pagination::new(0, 10),
        &crate::fixtures::beacon_cfg(),
        BASE,
        "record",
    );

    let open = emitted_for(&resp, "DS-open");
    let guarded = emitted_for(&resp, "DS-guarded");

    // The strict dataset suppressed FI_M, collapsing its group to Total only.
    assert!(
        !guarded.contains_key("FI_M"),
        "the guarded dataset must suppress the rare FI_M cell"
    );
    assert_eq!(
        guarded.keys().filter(|p| p.as_str() != "Total").count(),
        0,
        "the guarded dataset collapses to Total-only"
    );
    // The permissive sibling leaks the same shared cell in full.
    assert_eq!(
        open.get("FI_M").and_then(|(ac, _)| *ac),
        Some(2),
        "the suppressed cell is recoverable verbatim from the lower-floor sibling dataset \
         — cross-dataset differencing, unmitigated with a node floor of 0"
    );
}

// ---- Differencing quantification: recovered-cell counts -----------------------
//
// `cross_dataset_floor_asymmetry_leaks_a_suppressed_cell` above demonstrates one leaked
// cell. The two tests below turn "differencing is out of scope" into concrete counts, each
// of which tightens when its mitigation lands:
//   * Within a single dataset, the `emittable_rows` collapse means a differencing solver
//     recovers none of the suppressed cells.
//   * Across datasets, with the shipped node floor of 0, a permissive sibling leaks every
//     cell a strict sibling suppresses; raising a node-wide floor drops that count to 0.

/// [`beacon_cfg`] with an explicit node-wide suppression floor (`effective floor =
/// max(node, per-dataset manifest floor)`).
fn beacon_cfg_with_floor(node_floor: u32) -> BeaconParams {
    BeaconParams {
        min_allele_count: node_floor,
        ..crate::fixtures::beacon_cfg()
    }
}

/// A within-dataset differencing solver over the served cells. Applies the fixed
/// COVID-shaped marginal identities (`Total = FI + EE = M + F`, `FI = FI_M + FI_F`,
/// `EE = EE_M + EE_F`, `M = FI_M + EE_M`, `F = FI_F + EE_F`), solving any equation with
/// exactly one unknown, to a fixpoint. Returns how many of the 8 non-`Total` cells become
/// determined. Pure test code over the map [`emitted_for`] returns, using no crate
/// internals.
fn solve_marginal_system(emitted: &BTreeMap<String, (Option<u64>, Option<u64>)>) -> usize {
    use std::collections::HashMap;
    let mut known: HashMap<&str, u64> = HashMap::new();
    for (pop, (ac, _)) in emitted {
        if let Some(v) = ac {
            known.insert(pop.as_str(), *v);
        }
    }
    let eqs: [(&str, [&str; 2]); 6] = [
        ("Total", ["FI", "EE"]),
        ("Total", ["M", "F"]),
        ("FI", ["FI_M", "FI_F"]),
        ("EE", ["EE_M", "EE_F"]),
        ("M", ["FI_M", "EE_M"]),
        ("F", ["FI_F", "EE_F"]),
    ];
    loop {
        let mut progressed = false;
        for (sum, [a, b]) in eqs {
            match (known.get(sum), known.get(a), known.get(b)) {
                // sum and one addend known -> the other addend is determined.
                (Some(&s), None, Some(&vb)) => {
                    if let Some(x) = s.checked_sub(vb) {
                        known.insert(a, x);
                        progressed = true;
                    }
                }
                (Some(&s), Some(&va), None) => {
                    if let Some(x) = s.checked_sub(va) {
                        known.insert(b, x);
                        progressed = true;
                    }
                }
                // both addends known -> the sum is determined.
                (None, Some(&va), Some(&vb)) => {
                    known.insert(sum, va + vb);
                    progressed = true;
                }
                _ => {}
            }
        }
        if !progressed {
            break;
        }
    }
    ["FI_M", "FI_F", "EE_M", "EE_F", "FI", "EE", "M", "F"]
        .iter()
        .filter(|p| known.contains_key(**p))
        .count()
}

/// Within a single dataset, differencing recovers nothing. Every non-`Total` cell is below
/// the floor, so `emittable_rows` collapses the whole breakdown to `Total` only, and the
/// solver is left with one equation (`Total = Σ 8 unknowns`) that determines none of them.
/// Re-emitting a partial breakdown would let the solver recover a cell and fail this. The
/// non-vacuity check shows the solver itself can difference.
#[test]
fn within_dataset_differencing_recovers_no_suppressed_cell() {
    // an = 1400 per leaf keeps the complement (refc) tail from firing. The low tail, each
    // non-Total cell below 100, is what the floor of 100 acts on. Total = 180 clears it, so
    // the group collapses to Total only rather than vanishing.
    let variant = coherent_variant(100, (45, 1400), (45, 1400), (45, 1400), (45, 1400));
    let emitted = emitted_for(
        &assemble_one("DS", &manifest_with_floor(100), variant),
        "DS",
    );
    assert_eq!(
        emitted.keys().filter(|p| p.as_str() != "Total").count(),
        0,
        "every below-floor cell collapsed: only Total is served"
    );
    assert_eq!(
        solve_marginal_system(&emitted),
        0,
        "the collapse leaves Total = Σ(8 unknowns): differencing determines 0 of the 8 cells"
    );

    // Non-vacuity: the same solver recovers every cell from a partial breakdown, all cells
    // but FI_M, so the 0 above is the collapse rather than a dead solver.
    // FI = FI_M + FI_F gives FI_M = 90 - 45 as the missing cell, and the rest cascade.
    let mut partial: BTreeMap<String, (Option<u64>, Option<u64>)> = BTreeMap::new();
    for (p, ac) in [
        ("Total", 180),
        ("FI", 90),
        ("EE", 90),
        ("M", 90),
        ("F", 90),
        ("FI_F", 45),
        ("EE_M", 45),
        ("EE_F", 45),
    ] {
        partial.insert(p.to_owned(), (Some(ac), None));
    }
    assert_eq!(
        solve_marginal_system(&partial),
        NON_TOTAL_COUNT,
        "the solver recovers cells from a partial breakdown, so the 0 above is the collapse rather than a dead solver"
    );
}

/// Across datasets, the recovered-cell count is the whole non-`Total` set with the shipped
/// node floor of 0, and 0 once a node-wide floor is set. Two datasets cover the same
/// variant: a strict one with manifest floor 100, which collapses to Total only, and a
/// permissive sibling at floor 0. With node floor 0, `max(0, manifest)` leaves the sibling
/// at floor 0, so every cell the strict dataset suppressed is readable verbatim from it. A
/// non-zero node floor collapses the sibling too, closing the partition.
#[test]
fn cross_dataset_differencing_recovers_every_cell_until_a_node_floor_closes_it() {
    let variant = || coherent_variant(100, (45, 1400), (45, 1400), (45, 1400), (45, 1400));
    let cfg_open = manifest_with_floor(0);
    let cfg_guarded = manifest_with_floor(100);

    let recovered = |node_floor: u32| -> usize {
        let bcfg = beacon_cfg_with_floor(node_floor);
        let resp = assemble(
            vec![
                (
                    "DS-open".to_owned(),
                    &cfg_open,
                    None,
                    "3",
                    page_for(&cfg_open, &bcfg, variant()),
                ),
                (
                    "DS-guarded".to_owned(),
                    &cfg_guarded,
                    None,
                    "3",
                    page_for(&cfg_guarded, &bcfg, variant()),
                ),
            ],
            &Pagination::new(0, 10),
            &bcfg,
            BASE,
            "record",
        );
        let open = emitted_for(&resp, "DS-open");
        let guarded = emitted_for(&resp, "DS-guarded");
        // Cells suppressed in the guarded dataset but read verbatim from the open sibling.
        open.keys()
            .filter(|p| p.as_str() != "Total")
            .filter(|p| !guarded.contains_key(p.as_str()))
            .count()
    };

    assert_eq!(
        recovered(0),
        NON_TOTAL_COUNT,
        "node floor 0 (the shipped default): every cell the guarded dataset suppresses is \
         recoverable from its floor-0 sibling — cross-dataset differencing, unmitigated"
    );
    assert_eq!(
        recovered(100),
        0,
        "a node-wide floor collapses the permissive sibling too, dropping the \
         recovered-cell count to 0"
    );
}

// ---- Membership-inference wire-shape indistinguishability ----
//
// The companion at the beacon-crate logic level to the service-level
// `membership_inference_*` HTTP tests in
// `crates/gdi-node-standalone/tests/it/beacon_membership_inference.rs`, which guard
// wire-indistinguishability over the full HTTP stack and are not replaced by this.
//
// A `g_variants` query whose variant is (1) present but fully suppressed by the
// `min_allele_count` floor, (2) genuinely absent from an existing dataset, or (3) matched
// against no dataset at all must assemble to the same observable shape at every
// granularity. Otherwise the assembled response leaks which case occurred before any HTTP
// framing.
//
// The COVID fixture holds one variant (chr3:45823240 T>C, Total AC=618), so a node
// `[beacon].min_allele_count` above 618 suppresses the whole group, which `assemble` then
// drops entirely, collapsing scenario (1) into (2) and (3).

/// Convert the COVID fixture into a fresh tempdir with the given build-time floor.
fn covid_dataset_built_with_floor(min_allele_count: u32) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let vcf = test_util::covid_vcf_path();
    convert_vcf(
        &vcf,
        dir.path(),
        &ConvertOptions {
            assembly: "GRCh38".into(),
            block_range: 10_000_000,
            min_allele_count,
        },
    )
    .unwrap();
    dir
}

/// Convert the COVID fixture into a fresh tempdir, as `assemble.rs`'s helper does.
fn covid_dataset() -> tempfile::TempDir {
    covid_dataset_built_with_floor(0)
}

/// The COVID fixture's only variant, as `scan_dataset` addresses it (0-based).
const COVID_POS: i64 = 45_823_239;

/// Build-time suppression must never leave the served output more recoverable than serving
/// the same cohort unbuilt. This is the only test that drives `convert` and `assemble`
/// together, so it is what binds the two suppression layers.
///
/// If `convert` dropped below-floor populations without collapsing, the serve gate would
/// receive a partial marginal set whose remainder sits far outside `1..floor` and goes
/// undetected, while `LV_F = LV - LV_M` falls out by subtraction. Removing `convert`'s
/// collapse makes this test fail. The serve-side completeness check alone does not catch
/// it, because the missing cells leave no below-floor remainder on their axis.
#[test]
fn building_with_a_floor_never_weakens_the_served_output() {
    let floor = 100u32; // drops EE_F (89), LV_F (95) and EE_M (99); Total AC is 618
    let cfg = manifest_with_floor(floor);
    let pops = |dir: &tempfile::TempDir| -> Vec<String> {
        emitted_for(
            &assemble_one("DS", &cfg, scan_chr3(dir.path(), COVID_POS)),
            "DS",
        )
        .into_keys()
        .collect()
    };

    let unbuilt = pops(&covid_dataset_built_with_floor(0));
    let built = pops(&covid_dataset_built_with_floor(floor));

    // Non-vacuity: this floor must bite, or the test proves nothing.
    assert_eq!(
        unbuilt,
        vec!["Total".to_owned()],
        "serving the unsuppressed parquet at floor {floor} must collapse to Total"
    );
    assert_eq!(
        built, unbuilt,
        "a parquet built at the floor must serve identically to one built without it; \
         a difference means build-time suppression changed what a client can recover"
    );
}

/// Scan `dir` for the exact `(pos, "T", "C")` sequence query on chr3.
fn scan_chr3(dir: &std::path::Path, pos: i64) -> Vec<AlleleRow> {
    let kind = QueryKind::Sequence {
        pos,
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
    .unwrap()
}

/// The membership-observable projection of an assembled and shaped response: everything a
/// client can see that could distinguish suppressed from absent or no dataset.
fn membership_observable(v: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "exists": v["responseSummary"]["exists"],
        "hasNumTotalResults": v["responseSummary"].get("numTotalResults").is_some(),
        "numTotalResults": v["responseSummary"].get("numTotalResults").cloned(),
        "hasResponseMember": v.get("response").is_some(),
        "returnedGranularity": v["meta"]["returnedGranularity"],
    })
}

/// For one granularity, the three negative scenarios must be wire-indistinguishable.
fn assert_membership_scenarios_equivalent(granularity: &str) {
    let dir = covid_dataset();
    let dataset_id = "GDI-EE-UTARTU-1".to_owned();
    // A node floor above the fixture's only variant's Total AC (618) suppresses it
    // entirely.
    let bcfg = BeaconParams {
        min_allele_count: 1000,
        ..crate::fixtures::beacon_cfg()
    };
    let cfg = manifest_with_floor(0);

    // (1) present but fully suppressed: the real variant, floored away.
    let rows1 = scan_chr3(dir.path(), 45_823_239);
    let resp1 = assemble(
        vec![(
            dataset_id.clone(),
            &cfg,
            None,
            "3",
            page_for(&cfg, &bcfg, rows1),
        )],
        &Pagination::new(0, 10),
        &bcfg,
        BASE,
        granularity,
    );
    let v1 = serde_json::to_value(shape_for_granularity(resp1, granularity)).unwrap();

    // (2) genuinely absent variant in the same existing dataset (chr3:1, no row).
    let rows2 = scan_chr3(dir.path(), 1);
    let resp2 = assemble(
        vec![(dataset_id, &cfg, None, "3", page_for(&cfg, &bcfg, rows2))],
        &Pagination::new(0, 10),
        &bcfg,
        BASE,
        granularity,
    );
    let v2 = serde_json::to_value(shape_for_granularity(resp2, granularity)).unwrap();

    // (3) no dataset matched the query, so there is nothing to scan or assemble.
    let resp3 = assemble(
        Vec::new(),
        &Pagination::new(0, 10),
        &bcfg,
        BASE,
        granularity,
    );
    let v3 = serde_json::to_value(shape_for_granularity(resp3, granularity)).unwrap();

    let o1 = membership_observable(&v1);
    let o2 = membership_observable(&v2);
    let o3 = membership_observable(&v3);
    assert_eq!(
        o1, o2,
        "[{granularity}] suppressed vs absent differ:\n{o1}\nvs\n{o2}"
    );
    assert_eq!(
        o1, o3,
        "[{granularity}] suppressed vs no-dataset differ:\n{o1}\nvs\n{o3}"
    );

    // All three are negatives (exists:false).
    assert_eq!(o1["exists"], false, "all three must report no match");
    assert_eq!(o1["returnedGranularity"], granularity);
}

#[test]
fn membership_inference_boolean_is_indistinguishable_at_assembly_level() {
    assert_membership_scenarios_equivalent("boolean");
}

#[test]
fn membership_inference_count_is_indistinguishable_at_assembly_level() {
    assert_membership_scenarios_equivalent("count");
}

#[test]
fn membership_inference_record_is_indistinguishable_at_assembly_level() {
    assert_membership_scenarios_equivalent("record");
}
