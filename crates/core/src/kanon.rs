//! The k-anonymity row rule, shared by the build-time and serve-time floors.
//!
//! The floor exists at two points with two owners: the provider's
//! `config.minAlleleCount` drops rows permanently at `convert`, and the node operator's
//! `[beacon].min_allele_count` suppresses on the way out. The effective floor is
//! `max(build, serve)`.
//!
//! One rule, one implementation. It checks the explicit `AC`, the count derivable from
//! `AF * AN`, and the complement tail (a rare reference-carrier group whose own `AC` can
//! sit far above the floor). The two callers differ in one respect only, expressed as
//! [`RowVerdict::Uncountable`].

/// What the k-anonymity floor says about one population row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowVerdict {
    /// The group is provably at or above the floor (or empty, or the floor is off).
    Serve,
    /// A non-empty group below the floor on either tail: withhold it.
    Suppress,
    /// `AF > 0` (the variant exists) but neither an exact nor a client-derivable carrier
    /// count, so the group cannot be proven to be at or above the floor.
    ///
    /// The two callers diverge here, which is why this is a verdict and not a `bool`:
    ///
    /// * Serve time suppresses it, failing closed. An exists query would otherwise
    ///   confirm a possible below-floor singleton. The cost is bounded and reversible: the
    ///   operator can lower `[beacon].min_allele_count`, and the data stays in the store.
    ///
    /// * Build time keeps it. `AF` is the only required frequency field, `AC` and `AN`
    ///   are optional, so an AF-only dataset is a supported shape. Failing closed here
    ///   would permanently delete every row of such a dataset under any floor above zero,
    ///   at the one moment the data still exists. Serve time covers the disclosure risk on
    ///   every response.
    Uncountable,
}

/// The alt-allele carrier count `AC` for the low-tail check, or `None` when it cannot be
/// established.
///
/// Prefers the exact `AC`. When the `AC` field is absent it reconstructs
/// `AC = round(AF * AN)` from the served `AF`/`AN`, the derivation a client can perform
/// from the fields on the wire (the `f32 -> f64` widening is lossless), so the floor
/// reasons about the same count. Otherwise an `AC`-absent row that still ships `AF`+`AN`
/// leaks a below-floor singleton. Returns `None` when neither an exact `AC` nor both
/// `AF (> 0)` and `AN` are available: an `AF`-only row with no `AN` carries no derivable
/// integer count, so nothing leaks through the count channel. Its existence-channel
/// re-identifiability is handled by [`classify_row`], which reports it as
/// [`RowVerdict::Uncountable`] and lets each caller decide.
#[must_use]
pub fn alt_carriers(ac: Option<i32>, an: Option<i32>, af: f32) -> Option<i64> {
    if let Some(ac) = ac {
        return Some(i64::from(ac));
    }
    if af > 0.0
        && let Some(an) = an
    {
        // The client's own derivation: round(AF * AN) to nearest. Both `f64::from`
        // widenings are lossless (`f32`, and `i32` fits f64's mantissa).
        let est = (f64::from(af) * f64::from(an)).round();
        // `est` is cohort-bounded (AF in [0,1], AN an i32), so the cast cannot overflow.
        // It saturates safely if it did: an over-large AC is never in `1..floor`, so the
        // row survives.
        #[expect(
            clippy::cast_possible_truncation,
            reason = "round(AF*AN) as i64 is cohort-bounded and saturates safely"
        )]
        let est = est as i64;
        // Floor the derived count at 1. `AF > 0` states the variant is present, so the
        // group cannot be empty: a derived `0` means `AF * AN` fell below the resolution
        // the published numbers carry (AF = 1.0e-4 with AN = 2000 gives round(0.2) = 0).
        // Callers treat a count of `0` as an empty group that always serves, which is true
        // of a reported `AC = 0` and false of a derived one. Only the reconstruction is
        // floored; an explicit `ac` returns above, untouched.
        return Some(est.max(1));
    }
    None
}

/// The reference-allele carrier count `refc = AN - AC` for the complement-tail check, or
/// `None` when it cannot be established.
///
/// Takes `AC` from [`alt_carriers`] (exact or `AF`/`AN`-reconstructed) and prefers the
/// exact `AN`. When the `AN` field is absent it reconstructs `AN = round(AC / AF)`, valid
/// because `AF = AC/AN` and `AF > 0` whenever `AC > 0`. Rounding is to nearest, the same
/// derivation a client performs from the served `AC`/`AF`, so the floor reasons about the
/// `refc` a client can recover. Rounding down would undershoot `AN`, because the `f32`
/// `AF` widens slightly above the true `AC/AN`, and would collapse a true single
/// reference carrier to a served `refc = 0`, leaking the below-floor group this check
/// suppresses.
///
/// Returns `None` when `AC` cannot be established, and when `AN` is absent and `AC == 0`:
/// the reference group is then the whole cohort, the large safe side, and `AN` is not
/// derivable from `AF == 0`. With `AN` absent and `AC` present, `AC` is the exact `ac`
/// argument, since [`alt_carriers`] only reconstructs `AC` when `AN` is present.
#[must_use]
pub fn reference_carriers(ac: Option<i32>, an: Option<i32>, af: f32) -> Option<i64> {
    // `AF == 0` with `AN` present means `AC == 0` unambiguously: the alt group is empty,
    // so every one of the `AN` alleles is a reference carrier.
    //
    // This case must be answered before the `?` below. `alt_carriers` reports `None` for
    // it, because it derives nothing from `AF == 0` and there is no low-tail question to
    // ask about an empty alt group. Opening with `alt_carriers(..)?` would make the
    // complement tail unreachable for this shape and publish a below-floor reference
    // cohort, while the same wire content with `AC` spelled `0` is suppressed. `popfield`
    // accepts `AF`/`AN` independently of `AC`, so a producer VCF carrying `AN_x`/`AF_x`
    // without `AC_x` reaches this.
    if ac.is_none()
        && af <= 0.0
        && let Some(an) = an
    {
        return Some(i64::from(an).max(0));
    }
    let carriers = alt_carriers(ac, an, af)?;
    if let Some(an) = an {
        // Ingest guarantees AC <= AN; clamp defensively against malformed rows.
        return Some((i64::from(an) - carriers).max(0));
    }
    if let Some(ac_i32) = ac
        && ac_i32 > 0
        && af > 0.0
    {
        // `f64::from(i32)` is lossless (i32 fits in f64's 52-bit mantissa). Round to
        // nearest, not floor, so the reconstructed `AN` matches the client-recoverable
        // value instead of undershooting and hiding a true `refc = 1` on the survive side.
        let an_est_f = (f64::from(ac_i32) / f64::from(af)).round();
        // `an_est_f` is round(AC/AF), an integer-valued f64. For a normal AF it is
        // cohort-sized. For a tiny AF the `as i64` cast saturates to `i64::MAX`, the safe
        // direction: an over-large `refc` is never in `(1..floor)`, so the row survives.
        #[expect(
            clippy::cast_possible_truncation,
            reason = "round(AC/AF) saturates for a tiny AF; an over-large refc still serves"
        )]
        let an_est = an_est_f as i64;
        return Some((an_est - i64::from(ac_i32)).max(0));
    }
    None
}

/// Apply the floor to one row's counts.
///
/// `floor <= 0` disables the rule entirely (the default posture).
///
/// A row is [`RowVerdict::Suppress`]ed when it exposes a **non-empty** group smaller than
/// the floor on either tail: the low tail (`1 <= AC < floor`) or the complement tail
/// (`1 <= AN - AC < floor`). An empty group (`AC == 0`, or `refc == 0`) is never
/// re-identifying and always serves.
#[must_use]
pub fn classify_row(ac: Option<i32>, an: Option<i32>, af: f32, floor: i64) -> RowVerdict {
    if floor <= 0 {
        return RowVerdict::Serve;
    }
    // Low tail: a rare (non-empty, below-floor) alt-carrier group.
    if let Some(carriers) = alt_carriers(ac, an, af)
        && (1..floor).contains(&carriers)
    {
        return RowVerdict::Suppress;
    }
    // Complement tail: a rare reference-carrier group.
    if let Some(refc) = reference_carriers(ac, an, af)
        && (1..floor).contains(&refc)
    {
        return RowVerdict::Suppress;
    }
    // Neither an exact nor a derivable count, but the variant is present. An `AF == 0` row
    // is an empty, non-present alt group, never re-identifying, so it is exempt.
    //
    // Testing `alt_carriers` alone is sufficient: under this arm's `af > 0.0` guard
    // `reference_carriers` skips its `AF == 0` case and reaches its own
    // `alt_carriers(..)?`, so it returns `None` whenever `alt_carriers` does.
    if af > 0.0 && alt_carriers(ac, an, af).is_none() {
        return RowVerdict::Uncountable;
    }
    RowVerdict::Serve
}

/// The number of distinct individuals an allele-count floor guarantees.
///
/// The floor counts alleles, not people: a homozygous carrier contributes 2 to `AC`, so
/// `AC = floor` can come from as few as `ceil(floor / 2)` individuals. Every caller that
/// answers "how many people does this protect?" uses this one conversion, because a
/// truncating `floor / 2` disagrees for every odd floor and claims `floor = 1` protects
/// zero individuals.
///
/// # Examples
///
/// ```
/// use gdi_node_standalone_core::kanon::individuals_floor;
///
/// assert_eq!(individuals_floor(0), 0);  // the floor is off
/// assert_eq!(individuals_floor(1), 1);  // one allele still needs one person
/// assert_eq!(individuals_floor(5), 3);  // two homozygotes + one heterozygote
/// assert_eq!(individuals_floor(10), 5); // the recommended 2*k for k = 5
/// ```
#[must_use]
pub const fn individuals_floor(min_allele_count: u32) -> u32 {
    min_allele_count.div_ceil(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three verdicts must be distinguishable here, because neither caller can tell
    /// them apart: `beacon` maps `Suppress | Uncountable => false`, and `convert` keeps
    /// both `Uncountable` and `Serve`. A change from `Uncountable` to `Suppress` inside
    /// `classify_row` is invisible at both call sites, and it would make the build-time
    /// floor permanently delete every row of an AF-only dataset.
    #[test]
    fn an_uncountable_row_is_classified_as_such_not_suppressed() {
        // AF > 0, no AC, no AN: the variant exists but no count is derivable.
        assert_eq!(
            classify_row(None, None, 0.01, 5),
            RowVerdict::Uncountable,
            "an AF-only row must be Uncountable — mapping it to Suppress deletes every row \
             of an AF-only dataset at build time"
        );
        // AF == 0 is an empty, non-present alt group: never re-identifying.
        assert_eq!(classify_row(None, None, 0.0, 5), RowVerdict::Serve);
    }

    #[test]
    fn the_low_tail_uses_the_exact_ac_then_the_derivable_one() {
        // Exact AC below the floor.
        assert_eq!(
            classify_row(Some(2), Some(1000), 0.002, 5),
            RowVerdict::Suppress
        );
        // No AC, but round(AF * AN) = 2 is client-derivable and below the floor.
        assert_eq!(
            classify_row(None, Some(1000), 0.002, 5),
            RowVerdict::Suppress
        );
        // An empty group is never re-identifying.
        assert_eq!(classify_row(Some(0), Some(1000), 0.0, 5), RowVerdict::Serve);
        // Comfortably above the floor.
        assert_eq!(
            classify_row(Some(50), Some(1000), 0.05, 5),
            RowVerdict::Serve
        );
    }

    #[test]
    fn the_complement_tail_is_checked_even_when_ac_is_far_above_the_floor() {
        // AC 998 of AN 1000: refc = 2, below a floor of 5, while AC is 200x it.
        assert_eq!(
            classify_row(Some(998), Some(1000), 0.998, 5),
            RowVerdict::Suppress
        );
        // refc == 0 (fixed variant) is an empty reference group: serves.
        assert_eq!(
            classify_row(Some(1000), Some(1000), 1.0, 5),
            RowVerdict::Serve
        );
    }

    #[test]
    fn an_af_zero_row_with_an_present_is_a_provable_ac_zero_and_takes_the_complement_tail() {
        // AC absent, AN = 4, AF = 0.0. `AF == 0` with `AN` present means `AC == 0`
        // unambiguously, so refc = 4: below a floor of 5, and a 4-allele (2-individual)
        // cohort is what the floor exists to hide.
        assert_eq!(classify_row(None, Some(4), 0.0, 5), RowVerdict::Suppress);
        assert_eq!(reference_carriers(None, Some(4), 0.0), Some(4));

        // The same wire content with AC spelled explicitly: the two spellings must agree.
        assert_eq!(classify_row(Some(0), Some(4), 0.0, 5), RowVerdict::Suppress);

        // A large reference cohort is not re-identifying and still serves.
        assert_eq!(classify_row(None, Some(2000), 0.0, 5), RowVerdict::Serve);
        // AN absent: nothing is derivable, so the row is untouched by this arm.
        assert_eq!(reference_carriers(None, None, 0.0), None);
    }

    #[test]
    fn a_disabled_floor_classifies_everything_as_serve() {
        for floor in [0i64, -1] {
            assert_eq!(
                classify_row(Some(1), Some(1000), 0.001, floor),
                RowVerdict::Serve
            );
            assert_eq!(classify_row(None, None, 0.5, floor), RowVerdict::Serve);
        }
    }

    /// Pin the `round(AF * AN)` reconstruction itself, not just a verdict it produces.
    ///
    /// The values are chosen so the two arms disagree: `round(0.5 * 20) = 10` serves,
    /// while `round(0.5 / 20) = 0` floors to 1 and suppresses.
    #[test]
    fn the_af_times_an_reconstruction_is_pinned() {
        assert_eq!(alt_carriers(None, Some(20), 0.5), Some(10));
        // ...and the verdict it drives, so the number and the decision are pinned together.
        assert_eq!(classify_row(None, Some(20), 0.5, 5), RowVerdict::Serve);
    }

    /// Pin the `AN`-absent reconstruction: the arithmetic, both guards, and the verdict.
    #[test]
    fn the_an_absent_reconstruction_is_pinned() {
        // AC = 100 at AF = 0.98 reconstructs AN = round(102.04) = 102, so refc = 2: a
        // below-floor reference group whose own AC sits far above the floor.
        assert_eq!(reference_carriers(Some(100), None, 0.98), Some(2));
        assert_eq!(classify_row(Some(100), None, 0.98, 5), RowVerdict::Suppress);

        // The guards are `> 0`, not `>= 0`. With AC == 0 there is no alt group to divide
        // by and the reference group is the whole cohort, so this declines.
        assert_eq!(reference_carriers(Some(0), None, 0.5), None);
        // With AF == 0 the division is by zero: `AC / 0.0` is infinity, which the `as i64`
        // cast saturates to `i64::MAX`. Declining is the only correct answer.
        assert_eq!(reference_carriers(Some(5), None, 0.0), None);
    }

    /// Mirror the `individuals_floor` doctest as a unit test.
    ///
    /// The doctest documents the conversion; this asserts it under the runner that gates
    /// the build, which does not execute doctests.
    #[test]
    fn individuals_floor_matches_its_documented_table() {
        assert_eq!(individuals_floor(0), 0, "the floor is off");
        assert_eq!(individuals_floor(1), 1, "one allele still needs one person");
        assert_eq!(
            individuals_floor(5),
            3,
            "two homozygotes + one heterozygote"
        );
        assert_eq!(individuals_floor(10), 5, "the recommended 2*k for k = 5");
    }
}
