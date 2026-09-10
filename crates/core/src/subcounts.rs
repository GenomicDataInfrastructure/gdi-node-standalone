//! Genotype sub-count coherence: `AC_Hom`, `AC_Het` and `AC_Hemi` partition `AC`.
//!
//! The three sub-counts count **alleles**, not individuals. A homozygous-alternate
//! individual contributes 2 to both `AC` and `AC_Hom`; a heterozygote contributes 1 to
//! `AC` and `AC_Het`; a hemizygote contributes 1 to `AC` and `AC_Hemi`. Every alternate
//! allele therefore falls in exactly one of the three genotype classes, so when all three
//! are reported they sum to `AC` exactly, and `AC_Hom` is even at a diploid site.
//!
//! This is the `bcftools +fill-tags` convention the producer VCFs are written with. Their
//! `##INFO` descriptions read "Total number of alternate alleles (type Hom) in called
//! genotypes", and the `GoE` aggregate-data proposal's worked example satisfies it.
//!
//! A sub-count that is absent means *not reported*, not zero, so the present sub-counts may
//! only be required to sum to at most `AC`. Requiring exact equality is reserved for the
//! case where all three are present.
//!
//! The producer (`convert`) and the node's ingest gate (`validate_parquet`) both call
//! into this module, so each enforces the rule independently: the node cannot trust a
//! hand-assembled package.

use core::fmt;

/// Why a population row's genotype sub-counts are incoherent with its `AC`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubcountError {
    /// One sub-count alone exceeds `AC`. Impossible: each counts a subset of `AC`'s alleles.
    Exceeds {
        /// The offending column (`AC_HOM`, `AC_HET` or `AC_HEMI`).
        field: &'static str,
        /// Its value.
        value: i64,
        /// The row's `AC`.
        ac: i64,
    },
    /// The present sub-counts sum past `AC`.
    SumExceeds {
        /// Sum of the sub-counts that are present.
        sum: i64,
        /// The row's `AC`.
        ac: i64,
    },
    /// All three sub-counts are present but do not partition `AC`.
    NotAPartition {
        /// `AC_HOM`.
        hom: i64,
        /// `AC_HET`.
        het: i64,
        /// `AC_HEMI`.
        hemi: i64,
        /// Their sum.
        sum: i64,
        /// The row's `AC`.
        ac: i64,
    },
}

impl fmt::Display for SubcountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Exceeds { field, value, ac } => write!(
                f,
                "{field} ({value}) exceeds AC ({ac}): a genotype sub-count is a subset of AC's alleles"
            ),
            Self::SumExceeds { sum, ac } => write!(
                f,
                "the genotype sub-counts sum to {sum}, exceeding AC ({ac})"
            ),
            Self::NotAPartition {
                hom,
                het,
                hemi,
                sum,
                ac,
            } => write!(
                f,
                "AC_HOM ({hom}) + AC_HET ({het}) + AC_HEMI ({hemi}) = {sum}, which does not equal \
                 AC ({ac}); the sub-counts count alleles and must partition AC exactly when all \
                 three are reported"
            ),
        }
    }
}

/// Check that one population row's genotype sub-counts cohere with its `AC`.
///
/// `None` means the field is absent from the source, i.e. *not reported* — never zero. A
/// row with no `AC` has nothing to check against and is accepted.
///
/// Callers must reject negative counts first; this function assumes non-negative inputs and
/// draws no conclusion from a negative one.
///
/// # Errors
///
/// Returns [`SubcountError::Exceeds`] when a single sub-count is larger than `AC`,
/// [`SubcountError::SumExceeds`] when the reported sub-counts sum past `AC`, and
/// [`SubcountError::NotAPartition`] when all three are reported but do not sum to `AC`.
pub fn check_subcounts(
    ac: Option<i64>,
    hom: Option<i64>,
    het: Option<i64>,
    hemi: Option<i64>,
) -> Result<(), SubcountError> {
    let Some(ac) = ac else {
        return Ok(());
    };

    for (field, value) in [("AC_HOM", hom), ("AC_HET", het), ("AC_HEMI", hemi)] {
        if let Some(value) = value
            && value > ac
        {
            return Err(SubcountError::Exceeds { field, value, ac });
        }
    }

    let sum = hom
        .unwrap_or(0)
        .saturating_add(het.unwrap_or(0))
        .saturating_add(hemi.unwrap_or(0));
    if sum > ac {
        return Err(SubcountError::SumExceeds { sum, ac });
    }

    if let (Some(hom), Some(het), Some(hemi)) = (hom, het, hemi)
        && sum != ac
    {
        return Err(SubcountError::NotAPartition {
            hom,
            het,
            hemi,
            sum,
            ac,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three worked-example rows from the `GoE` aggregate-data proposal, which is the
    /// authority for what the sub-counts count. Each partitions its `AC` exactly, and each
    /// `AC_Hom` is even — as it must be, since a homozygote contributes two alleles.
    #[test]
    fn goe_proposal_rows_are_coherent() {
        for (ac, hom, het, hemi) in [
            (18065, 4840, 13225, 0), // population F
            (7102, 2400, 4702, 0),   // population FR_M
            (478, 20, 458, 0),       // population FR_F
        ] {
            assert_eq!(
                check_subcounts(Some(ac), Some(hom), Some(het), Some(hemi)),
                Ok(()),
                "AC={ac} HOM={hom} HET={het} HEMI={hemi}"
            );
            assert_eq!(hom % 2, 0, "AC_Hom {hom} must be even at a diploid site");
        }
    }

    /// Pins the convention, not just the arithmetic. If `AC_Hom` counted homozygous
    /// *individuals* rather than alleles, `AC` would be `2*hom + het + hemi` and the `GoE`
    /// rows would be incoherent.
    #[test]
    fn the_individual_counting_convention_is_rejected() {
        // GoE population F under the individual reading: 2*4840 + 13225 = 22905 != 18065.
        let err = check_subcounts(Some(18065), Some(4840 * 2), Some(13225), Some(0));
        std::assert_matches!(
            err,
            Err(SubcountError::SumExceeds { .. }),
            "expected the individual-counting reading to be incoherent, got {err:?}"
        );
    }

    #[test]
    fn absent_subcounts_need_only_not_exceed_ac() {
        // Fixture population `FI`: AC_HEMI is absent, so no exact partition is required.
        assert_eq!(
            check_subcounts(Some(224), Some(16), Some(208), None),
            Ok(())
        );
        // ...but the reported ones still may not sum past AC.
        assert_eq!(
            check_subcounts(Some(224), Some(17), Some(208), None),
            Err(SubcountError::SumExceeds { sum: 225, ac: 224 })
        );
    }

    #[test]
    fn a_single_subcount_may_not_exceed_ac() {
        assert_eq!(
            check_subcounts(Some(10), Some(11), None, None),
            Err(SubcountError::Exceeds {
                field: "AC_HOM",
                value: 11,
                ac: 10
            })
        );
    }

    #[test]
    fn all_three_present_must_partition_ac_exactly() {
        assert_eq!(
            check_subcounts(Some(618), Some(65), Some(552), Some(1)),
            Ok(())
        );
        // A short sum means some alternate allele lies in no genotype class.
        assert_eq!(
            check_subcounts(Some(618), Some(64), Some(552), Some(1)),
            Err(SubcountError::NotAPartition {
                hom: 64,
                het: 552,
                hemi: 1,
                sum: 617,
                ac: 618
            })
        );
    }

    #[test]
    fn a_row_without_ac_is_accepted() {
        assert_eq!(check_subcounts(None, Some(5), Some(5), Some(5)), Ok(()));
    }

    /// Real inputs widen from `i32`, so the sum cannot overflow in practice; pin the
    /// saturating path anyway so a future widening of the column type cannot panic here.
    /// Each sub-count equals `AC` (so `Exceeds` does not fire first) and the sum saturates.
    #[test]
    fn saturating_sum_cannot_overflow() {
        let big = i64::MAX - 1;
        assert_eq!(
            check_subcounts(Some(big), Some(big), Some(big), Some(big)),
            Err(SubcountError::SumExceeds {
                sum: i64::MAX,
                ac: big
            })
        );
    }
}
