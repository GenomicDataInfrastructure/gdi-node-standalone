//! Population-hierarchy coherence for one variant's per-population counts.
//!
//! The sibling of [`crate::subcounts`], one level up. `subcounts` checks that a single
//! population's genotype cells partition its own `AC`; this checks that populations
//! partition each other the way the label grammar says they do.
//!
//! [`crate::popfield`] defines that grammar — `Total` | `[MF]` | `[A-Z]{2}` |
//! `[A-Z]{2}_[MF]` — so the refinement relation is decidable from the label alone:
//! `FI_M` refines both `FI` and `M`, and `FI` and `M` each refine `Total`.
//!
//! # What is checked, and what is not
//!
//! Only conditions that are provably impossible, so a legitimate export can never trip
//! this:
//!
//! * a child's `AN`/`AC` exceeding its parent's, since a subset cannot be larger than the
//!   set containing it, whatever the cohort looks like;
//! * a parent whose children on one axis are all present and whose `AN`s sum exactly to
//!   the parent's: those children partition the parent, so their `AC`s cannot sum to more
//!   than the parent's.
//!
//! Not checked: `Σ countries == Total`, or any axis-sums-to-Total identity, on `AC` alone.
//! `popfield` documents each axis as a partition of `Total`, but a real export can omit a
//! cohort's country, and inferring a violation from `AC` without `AN` proving the partition
//! would reject honest data. The `AN`-proved rule above covers the same mistake wherever it
//! is provable.
//!
//! This catches the mis-stratified-pipeline class: swapped sex labels, a subgroup computed
//! on the wrong cohort, a merge that double-counts carriers. `build`, `preview`, `validate`
//! and `lint`, and the node's ingest re-check, all report it.

use std::collections::BTreeMap;

use crate::popfield::{PopulationAxis, TOTAL_POPULATION, population_axis};

/// A population-hierarchy contradiction in one variant's counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HierarchyError {
    /// A child population's count exceeds the parent's containing it.
    ChildExceedsParent {
        /// The metric that overflowed (`AN` or `AC`).
        field: &'static str,
        /// The refining label, e.g. `FI_M`.
        child: String,
        /// Its value.
        child_value: i64,
        /// The containing label, e.g. `FI`.
        parent: String,
        /// The parent's value.
        parent_value: i64,
    },
    /// Children that provably partition a parent (their `AN`s sum to it exactly) carry
    /// more carriers between them than the parent does.
    PartitionExceedsParent {
        /// The containing label.
        parent: String,
        /// The parent's `AC`.
        parent_ac: i64,
        /// The summed `AC` of the partitioning children.
        children_ac: i64,
        /// Those children, in label order.
        children: Vec<String>,
    },
}

impl std::fmt::Display for HierarchyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChildExceedsParent {
                field,
                child,
                child_value,
                parent,
                parent_value,
            } => write!(
                f,
                "{field} for population {child} ({child_value}) exceeds {field} for the \
                 population containing it, {parent} ({parent_value}): a subgroup cannot be \
                 larger than the group it belongs to"
            ),
            Self::PartitionExceedsParent {
                parent,
                parent_ac,
                children_ac,
                children,
            } => write!(
                f,
                "populations {} together have AC {children_ac}, more than the {parent} they \
                 partition (AC {parent_ac}). Their AN sums to {parent}'s exactly, so they \
                 cover the same cohort and cannot hold more carriers",
                children.join(" + ")
            ),
        }
    }
}

/// One population's counts, as this check needs them.
#[derive(Debug, Clone, Copy, Default)]
pub struct PopCounts {
    /// Allele count, when the producer supplied one.
    pub ac: Option<i64>,
    /// Allele number, when the producer supplied one.
    pub an: Option<i64>,
}

/// Is `child` a strict refinement of `parent` under the [`crate::popfield`] grammar?
///
/// `Total` contains everything; a country×sex label refines both its country and its sex.
/// Returns `false` for equal labels and for unrelated ones (`FI` vs `EE`, `FI_M` vs `EE_M`).
#[must_use]
fn refines(child: &str, parent: &str) -> bool {
    if child == parent {
        return false;
    }
    if parent == TOTAL_POPULATION {
        // Every grammar-valid non-Total label is a subset of Total.
        return population_axis(child).is_some() && child != TOTAL_POPULATION;
    }
    let (Some(child_axis), Some(parent_axis)) = (population_axis(child), population_axis(parent))
    else {
        return false;
    };
    // Only country×sex refines anything other than Total, and only its own two tokens.
    if child_axis != PopulationAxis::CountrySex {
        return false;
    }
    let Some((country, sex)) = child.split_once('_') else {
        return false;
    };
    match parent_axis {
        PopulationAxis::Country => parent == country,
        PopulationAxis::Sex => parent == sex,
        PopulationAxis::CountrySex => false,
    }
}

/// The children of `parent` on `axis`: the labels of that axis refining it.
///
/// The axis grouping is what makes the sum meaningful. Each axis independently covers the
/// whole cohort, so pooling `Total`'s children across axes would sum `AN` to a multiple of
/// `Total`'s own and reject healthy data. Each axis is summed against the parent on its
/// own.
///
/// For any parent other than `Total` this yields members on the country×sex axis alone,
/// because [`refines`] admits no other axis below `Total`. Iterating every axis costs two
/// empty scans there and generalises the rule at `Total`.
fn partition_children_on<'a>(
    parent: &str,
    axis: PopulationAxis,
    pops: &'a BTreeMap<String, PopCounts>,
) -> Vec<&'a String> {
    pops.keys()
        .filter(|c| population_axis(c) == Some(axis) && refines(c, parent))
        .collect()
}

/// Check one variant's per-population counts for hierarchy contradictions.
///
/// # Errors
///
/// Returns the first [`HierarchyError`] found, in deterministic label order.
pub fn check_hierarchy(pops: &BTreeMap<String, PopCounts>) -> Result<(), HierarchyError> {
    // Rule 1: containment. A subset cannot exceed its superset on either metric.
    for (child, child_counts) in pops {
        for (parent, parent_counts) in pops {
            if !refines(child, parent) {
                continue;
            }
            for (field, child_value, parent_value) in [
                ("AN", child_counts.an, parent_counts.an),
                ("AC", child_counts.ac, parent_counts.ac),
            ] {
                if let (Some(c), Some(p)) = (child_value, parent_value)
                    && c > p
                {
                    return Err(HierarchyError::ChildExceedsParent {
                        field,
                        child: child.clone(),
                        child_value: c,
                        parent: parent.clone(),
                        parent_value: p,
                    });
                }
            }
        }
    }

    // Rule 2: a provable partition cannot hold more carriers than what it partitions.
    for (parent, parent_counts) in pops {
        let (Some(parent_alleles), Some(parent_carriers)) = (parent_counts.an, parent_counts.ac)
        else {
            continue;
        };
        for axis in PopulationAxis::ALL {
            let children = partition_children_on(parent, axis, pops);
            if children.is_empty() {
                continue;
            }
            // Every child must carry both metrics, or the partition is not established.
            let mut child_alleles: i64 = 0;
            let mut child_carriers: i64 = 0;
            let mut complete = true;
            for child in &children {
                if let (Some(an), Some(ac)) = (pops[*child].an, pops[*child].ac) {
                    child_alleles = child_alleles.saturating_add(an);
                    child_carriers = child_carriers.saturating_add(ac);
                } else {
                    complete = false;
                    break;
                }
            }
            // `an_sum == parent_an` proves these children cover the parent exactly. A
            // smaller sum means the export omits part of the cohort, which is legitimate.
            if complete && child_alleles == parent_alleles && child_carriers > parent_carriers {
                return Err(HierarchyError::PartitionExceedsParent {
                    parent: parent.clone(),
                    parent_ac: parent_carriers,
                    children_ac: child_carriers,
                    children: children.into_iter().cloned().collect(),
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;

    fn pops(entries: &[(&str, Option<i64>, Option<i64>)]) -> BTreeMap<String, PopCounts> {
        entries
            .iter()
            .map(|(name, ac, an)| ((*name).to_owned(), PopCounts { ac: *ac, an: *an }))
            .collect()
    }

    #[test]
    fn refinement_follows_the_label_grammar() {
        assert!(refines("FI_M", "FI"), "country x sex refines its country");
        assert!(refines("FI_M", "M"), "country x sex refines its sex");
        assert!(refines("FI", "Total"));
        assert!(refines("M", "Total"));
        assert!(refines("FI_M", "Total"));
        assert!(!refines("FI", "FI"), "a label does not refine itself");
        assert!(!refines("FI_M", "EE"), "a different country is unrelated");
        assert!(!refines("FI_M", "F"), "the other sex is unrelated");
        assert!(!refines("FI", "M"), "country and sex are incomparable");
        assert!(!refines("Total", "FI"), "Total refines nothing");
    }

    /// A breakdown where every identity holds exactly. The check must be silent on it, or
    /// it would reject real data rather than the pipeline bugs it targets.
    #[test]
    fn a_coherent_breakdown_passes() {
        let p = pops(&[
            ("Total", Some(100), Some(8000)),
            ("EE", Some(50), Some(4000)),
            ("FI", Some(50), Some(4000)),
            ("EE_M", Some(30), Some(2000)),
            ("EE_F", Some(20), Some(2000)),
            ("FI_M", Some(25), Some(2000)),
            ("FI_F", Some(25), Some(2000)),
            ("M", Some(55), Some(4000)),
            ("F", Some(45), Some(4000)),
        ]);
        assert_eq!(check_hierarchy(&p), Ok(()));
    }

    /// M and F partition EE exactly by AN, but carry 510 carriers inside a parent of 10.
    #[test]
    fn carriers_exceeding_the_partitioned_parent_are_rejected() {
        let p = pops(&[
            ("EE", Some(10), Some(4000)),
            ("EE_M", Some(500), Some(2000)),
            ("EE_F", Some(10), Some(2000)),
        ]);
        let err = check_hierarchy(&p).unwrap_err();
        // AC_EE_M (500) > AC_EE (10) trips containment first, which is also correct: the
        // message names the pair rather than the sum.
        std::assert_matches!(
            err,
            HierarchyError::ChildExceedsParent { field: "AC", .. },
            "got {err:?}"
        );
    }

    /// The partition rule proper: no single child exceeds the parent, but together they do.
    #[test]
    fn a_partition_summing_past_its_parent_is_rejected() {
        let p = pops(&[
            ("EE", Some(10), Some(4000)),
            ("EE_M", Some(8), Some(2000)),
            ("EE_F", Some(7), Some(2000)),
        ]);
        let err = check_hierarchy(&p).unwrap_err();
        match err {
            HierarchyError::PartitionExceedsParent {
                parent,
                parent_ac,
                children_ac,
                ..
            } => {
                assert_eq!(parent, "EE");
                assert_eq!(parent_ac, 10);
                assert_eq!(children_ac, 15);
            }
            other @ HierarchyError::ChildExceedsParent { .. } => {
                panic!("expected a partition error, got {other:?}")
            }
        }
    }

    #[test]
    fn an_larger_than_the_parents_is_rejected() {
        let p = pops(&[("EE", Some(1), Some(4000)), ("EE_M", Some(1), Some(9000))]);
        let err = check_hierarchy(&p).unwrap_err();
        std::assert_matches!(
            err,
            HierarchyError::ChildExceedsParent { field: "AN", .. },
            "got {err:?}"
        );
    }

    /// An export that omits part of the cohort must not be rejected: the children's AN
    /// does not sum to the parent's, so they are not proved to partition it and their AC
    /// sum says nothing.
    #[test]
    fn an_incomplete_breakdown_is_not_an_error() {
        let p = pops(&[
            ("EE", Some(10), Some(4000)),
            // Only the male stratum is published: AN 2000 != 4000, so no partition is proved.
            ("EE_M", Some(9), Some(2000)),
        ]);
        assert_eq!(check_hierarchy(&p), Ok(()));
    }

    /// Missing metrics cannot prove anything either way.
    #[test]
    fn absent_counts_are_silent() {
        let p = pops(&[
            ("EE", None, Some(4000)),
            ("EE_M", Some(5000), None),
            ("EE_F", Some(1), Some(2000)),
        ]);
        assert_eq!(check_hierarchy(&p), Ok(()));
    }

    /// The partition rule is about the axis, not one privileged spelling of it.
    ///
    /// `EE` + `FI` sum on `AN` to `Total`'s exactly, so by this module's own criterion they
    /// cover the same cohort, yet they carry 15 alternate alleles inside a `Total` of 10.
    /// The same case as [`a_partition_summing_past_its_parent_is_rejected`], one level up.
    #[test]
    fn a_country_partition_summing_past_total_is_rejected() {
        let p = pops(&[
            ("Total", Some(10), Some(8000)),
            ("EE", Some(8), Some(4000)),
            ("FI", Some(7), Some(4000)),
        ]);
        let err = check_hierarchy(&p).unwrap_err();
        match err {
            HierarchyError::PartitionExceedsParent {
                parent,
                parent_ac,
                children_ac,
                children,
            } => {
                assert_eq!(parent, TOTAL_POPULATION);
                assert_eq!(parent_ac, 10);
                assert_eq!(children_ac, 15);
                assert_eq!(children, vec!["EE".to_owned(), "FI".to_owned()]);
            }
            other @ HierarchyError::ChildExceedsParent { .. } => {
                panic!("expected a country-axis partition error, got {other:?}")
            }
        }
    }

    /// The same on the sex axis, where a swapped-label pipeline bug lands.
    #[test]
    fn a_sex_partition_summing_past_total_is_rejected() {
        let p = pops(&[
            ("Total", Some(10), Some(8000)),
            ("M", Some(8), Some(4000)),
            ("F", Some(7), Some(4000)),
        ]);
        let err = check_hierarchy(&p).unwrap_err();
        match err {
            HierarchyError::PartitionExceedsParent {
                parent,
                parent_ac,
                children_ac,
                children,
            } => {
                assert_eq!(parent, TOTAL_POPULATION);
                assert_eq!(parent_ac, 10);
                assert_eq!(children_ac, 15);
                assert_eq!(children, vec!["F".to_owned(), "M".to_owned()]);
            }
            other @ HierarchyError::ChildExceedsParent { .. } => {
                panic!("expected a sex-axis partition error, got {other:?}")
            }
        }
    }

    /// Axes must be summed separately. Every axis of a coherent breakdown covers the whole
    /// cohort, so pooling `Total`'s children across axes would sum `AN` to three times
    /// `Total`'s, turning the healthy fixture below into a false rejection.
    #[test]
    fn axes_are_not_pooled_when_summing_a_partition() {
        let p = pops(&[
            ("Total", Some(100), Some(8000)),
            ("EE", Some(50), Some(4000)),
            ("FI", Some(50), Some(4000)),
            ("M", Some(55), Some(4000)),
            ("F", Some(45), Some(4000)),
            ("EE_M", Some(30), Some(2000)),
            ("EE_F", Some(20), Some(2000)),
            ("FI_M", Some(25), Some(2000)),
            ("FI_F", Some(25), Some(2000)),
        ]);
        assert_eq!(check_hierarchy(&p), Ok(()));
    }

    /// Countries need not partition Total: an axis that does not sum to the parent is not
    /// evidence of a mistake, and `AC` alone must not be used to infer one.
    #[test]
    fn countries_not_summing_to_total_is_not_an_error() {
        let p = pops(&[
            ("Total", Some(100), Some(8000)),
            ("EE", Some(50), Some(4000)),
            // FI omitted entirely: a legitimate partial export.
        ]);
        assert_eq!(check_hierarchy(&p), Ok(()));
    }
}
