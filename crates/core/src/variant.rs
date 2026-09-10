//! REF/ALT handling and variant-type classification.
//!
//! An allele reaches storage whitespace-trimmed, uppercased, and reduced to its
//! **`POS`-preserving minimal representation** by [`right_trim_alleles`] — the shared
//! *suffix* is dropped, the shared *prefix* is not (that would advance `POS`). The trim
//! exists because the converter splits multi-allelic lines and therefore authors the
//! per-allele `(REF, ALT)` pairs itself: splitting `AT -> ATT,A` invents `(AT, ATT)`, a
//! pair no provider wrote and which no Beacon client would query for.
//!
//! Everything downstream then uses those stored alleles verbatim: `v_end`, the VRS bases,
//! the HGVS id, and the Sequence exact-match never re-trim (a deletion stored as
//! `REF=AC, ALT=A` is matched as `AC`/`A`, never `C` and an empty string).
//!
//! The common prefix+suffix trimming in [`classify_vt`] is a separate thing: it derives the
//! `VT` label *only*, and never touches what is stored. Because trimming is idempotent, the
//! label is the same before and after [`right_trim_alleles`].

use std::borrow::Cow;

/// Variant type label stored in the `VT` column.
///
/// The classification is derived from the REF/ALT pair (see [`classify_vt`]) using a
/// small, standards-aligned vocabulary: `SNP`/`MNP` for equal-length substitutions,
/// `INS`/`DEL` for pure insertions/deletions, and `DELINS` for a complex
/// length-changing substitution (the HGVS `delins`). Every real (REF ≠ ALT) variant
/// maps to exactly one of these — there is no `UNKNOWN` fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vt {
    /// Single-nucleotide substitution (both trimmed remainders length 1, differing).
    Snp,
    /// Multi-nucleotide (block) substitution: equal-length trimmed remainders longer
    /// than one base.
    Mnp,
    /// Pure insertion: the REF-side trimmed remainder is empty.
    Ins,
    /// Pure deletion: the ALT-side trimmed remainder is empty.
    Del,
    /// Complex deletion-insertion (HGVS `delins`): both trimmed remainders are
    /// non-empty and of differing length.
    Delins,
}

impl Vt {
    /// The stored string label (`"SNP"` / `"MNP"` / `"INS"` / `"DEL"` / `"DELINS"`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Snp => "SNP",
            Self::Mnp => "MNP",
            Self::Ins => "INS",
            Self::Del => "DEL",
            Self::Delins => "DELINS",
        }
    }

    /// Parse a stored `VT` label back into the enum, exactly inverting [`Self::as_str`].
    ///
    /// `None` for anything outside the five-label vocabulary. This is the single definition
    /// of what the `VT` column may hold: the ingest gate rejects an out-of-vocabulary value
    /// and the read path decodes through this, so the two cannot disagree about which
    /// labels are storable.
    ///
    /// # Examples
    ///
    /// ```
    /// use gdi_node_standalone_core::variant::Vt;
    ///
    /// assert_eq!(Vt::parse("DELINS"), Some(Vt::Delins));
    /// assert_eq!(Vt::parse("delins"), None, "the stored label is upper-case");
    /// assert_eq!(Vt::parse("SV"), None);
    /// ```
    #[must_use]
    pub fn parse(label: &str) -> Option<Self> {
        match label {
            "SNP" => Some(Self::Snp),
            "MNP" => Some(Self::Mnp),
            "INS" => Some(Self::Ins),
            "DEL" => Some(Self::Del),
            "DELINS" => Some(Self::Delins),
            _ => None,
        }
    }
}

/// Uppercase and whitespace-trim an allele. The first half of the storage form; the
/// converter then applies [`right_trim_alleles`] to the split `(REF, ALT)` pair.
///
/// Returns `None` when the result is empty (an empty allele is never stored).
///
/// # Examples
///
/// ```
/// use gdi_node_standalone_core::variant::normalize_allele;
///
/// // Lowercase is uppercased and surrounding whitespace is trimmed.
/// assert_eq!(normalize_allele(" acgt ").as_deref(), Some("ACGT"));
/// // An empty or whitespace-only allele is never stored.
/// assert_eq!(normalize_allele("   "), None);
/// ```
#[must_use]
pub fn normalize_allele(s: &str) -> Option<Cow<'_, str>> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    // Fast path: an already-uppercase allele (the overwhelming common case for the
    // `ACGTN` data this handles) is returned borrowed — no allocation. Only when an
    // ASCII-lowercase byte is present do we allocate the uppercased form.
    // `to_ascii_uppercase` touches ASCII letters only, so a string with no
    // ASCII-lowercase byte is already byte-identical to its uppercased form.
    if t.bytes().any(|b| b.is_ascii_lowercase()) {
        Some(Cow::Owned(t.to_ascii_uppercase()))
    } else {
        Some(Cow::Borrowed(t))
    }
}

/// True if every byte of `s` is in `{A, C, G, T, N}` (and `s` is non-empty).
///
/// The input should already be uppercased (see [`normalize_allele`]); lowercase
/// bases are not accepted here.
///
/// # Examples
///
/// ```
/// use gdi_node_standalone_core::variant::is_literal_acgtn;
///
/// assert!(is_literal_acgtn("ACGTN"));
/// // Symbolic alleles, breakends, the missing value, and `*` are all rejected.
/// assert!(!is_literal_acgtn("<DEL>"));
/// assert!(!is_literal_acgtn("*"));
/// assert!(!is_literal_acgtn("")); // empty is never literal
/// ```
#[must_use]
pub fn is_literal_acgtn(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| matches!(b, b'A' | b'C' | b'G' | b'T' | b'N'))
}

/// True if `alt` is a supported alternate allele: a literal `ACGTN` string.
///
/// Rejects symbolic alleles (`<DEL>`), breakend notation (`[`/`]`), the missing
/// value (`.`), and the overlapping-deletion marker (`*`). Equivalent to
/// [`is_literal_acgtn`] because that predicate already excludes every non-`ACGTN`
/// character, but named separately to make the call sites (the ALT filter) read
/// intentionally.
#[must_use]
pub fn alt_is_supported(alt: &str) -> bool {
    is_literal_acgtn(alt)
}

/// Drop the shared suffix of `ref_`/`alt`, keeping at least one base on each side.
///
/// This is the half of VCF minimal representation that does **not** move `POS`, and it is
/// the half a multi-allelic split needs. Splitting `AT -> ATT,A` yields the pair
/// `(AT, ATT)`, which no provider wrote and which is not minimal: the canonical form is
/// `(A, AT)`. Because the converter authors those per-allele pairs itself, emitting them
/// un-trimmed is a defect in its own output, not a fidelity-preserving choice — a Beacon
/// client querying the canonical `referenceBases`/`alternateBases` would silently miss the
/// variant.
///
/// The complementary left-trim is excluded: dropping a shared prefix advances `POS`, which
/// can push a row out of the coordinate order [`crate::convert`] enforces and across a
/// `blockRange` boundary into a partition whose filename no longer describes it. Callers
/// detect that case with [`is_left_trimmable`] and warn instead of rewriting.
///
/// Trimming is idempotent, so re-running a build over already-minimal alleles is a no-op.
///
/// # Examples
///
/// ```
/// use gdi_node_standalone_core::variant::right_trim_alleles;
///
/// // The pair a multi-allelic split invents, reduced to the canonical deletion.
/// assert_eq!(right_trim_alleles("GATGAAATGAA", "GATGAA"), ("GATGAA", "G"));
/// // An already-minimal pair is untouched.
/// assert_eq!(right_trim_alleles("A", "G"), ("A", "G"));
/// // At least one base always remains on each side.
/// assert_eq!(right_trim_alleles("AT", "T"), ("AT", "T"));
/// ```
#[must_use]
#[expect(
    clippy::string_slice,
    reason = "the loop only decrements past a byte that equals one of ALT's ACGTN bytes and is_ascii(), so rl/al always land on a char boundary"
)]
pub fn right_trim_alleles<'a>(ref_: &'a str, alt: &'a str) -> (&'a str, &'a str) {
    let rb = ref_.as_bytes();
    let ab = alt.as_bytes();
    let mut rl = rb.len();
    let mut al = ab.len();
    // `is_ascii` keeps the byte indices on `char` boundaries even if a caller hands us a
    // non-ASCII REF: a matching byte is one of ALT's `ACGTN` bytes, hence a standalone
    // ASCII char, so `rl`/`al` can never land inside a multi-byte sequence.
    while rl > 1 && al > 1 && rb[rl - 1] == ab[al - 1] && rb[rl - 1].is_ascii() {
        rl -= 1;
        al -= 1;
    }
    (&ref_[..rl], &alt[..al])
}

/// True when `ref_`/`alt` still share a leading base with more than one base on each side,
/// i.e. reaching minimal representation would require advancing `POS`.
///
/// Apply [`right_trim_alleles`] first: this answers "is the *right-trimmed* pair still
/// non-minimal", which is the only case the converter cannot fix without breaking the
/// sorted-`POS` invariant.
///
/// # Examples
///
/// ```
/// use gdi_node_standalone_core::variant::{is_left_trimmable, right_trim_alleles};
///
/// // `TGATA -> TGATAGATAGGTA` right-trims to `TGA -> TGATAGATAGG`, still prefix-shared.
/// let (r, a) = right_trim_alleles("TGATA", "TGATAGATAGGTA");
/// assert!(is_left_trimmable(r, a));
/// // A canonical insertion shares its anchor base but has a one-base REF: nothing to trim.
/// assert!(!is_left_trimmable("A", "AT"));
/// ```
#[must_use]
pub fn is_left_trimmable(ref_: &str, alt: &str) -> bool {
    let rb = ref_.as_bytes();
    let ab = alt.as_bytes();
    rb.len() > 1 && ab.len() > 1 && rb[0] == ab[0]
}

/// Classify a variant by trimming the common prefix+suffix of REF/ALT, then
/// comparing the remainders.
///
/// The trimming affects the **label only**; callers store REF/ALT verbatim.
///
/// * `INS` — the REF-side remainder is empty (pure insertion).
/// * `DEL` — the ALT-side remainder is empty (pure deletion).
/// * `SNP` — both remainders length 1 (single-base substitution).
/// * `MNP` — both remainders non-empty and of equal length > 1 (block substitution).
/// * `DELINS` — both remainders non-empty and of differing length (complex indel).
///
/// # Preconditions
///
/// The caller must pass a real variant (`ref_ != alt` after normalisation): the
/// convert path filters identical REF/ALT alleles as non-variants before this is
/// reached, so both trimmed remainders can never be simultaneously empty (which is
/// the only REF/ALT pair the five labels above cannot describe).
///
/// # Examples
///
/// ```
/// use gdi_node_standalone_core::variant::{classify_vt, Vt};
///
/// assert_eq!(classify_vt("T", "C"), Vt::Snp);
/// // A deletion: trimming the shared `A` prefix leaves `C` vs `` (ALT side empty).
/// assert_eq!(classify_vt("AC", "A"), Vt::Del);
/// // An insertion: the REF side is empty after trimming.
/// assert_eq!(classify_vt("A", "AC"), Vt::Ins);
/// // An equal-length multi-nucleotide (block) substitution.
/// assert_eq!(classify_vt("AT", "GC"), Vt::Mnp);
/// // Both sides non-empty and different length: a complex delins.
/// assert_eq!(classify_vt("AT", "GCC"), Vt::Delins);
/// // The label is stored verbatim via `Vt::as_str`.
/// assert_eq!(classify_vt("T", "C").as_str(), "SNP");
/// ```
#[must_use]
pub fn classify_vt(ref_: &str, alt: &str) -> Vt {
    let (r, a) = trim_common_affix(ref_, alt);
    match (r.len(), a.len()) {
        // One side is entirely shared context: a pure insertion or deletion.
        (0, _) => Vt::Ins,
        (_, 0) => Vt::Del,
        // Single-base substitution.
        (1, 1) => Vt::Snp,
        // Equal-length (> 1) block substitution.
        (rl, al) if rl == al => Vt::Mnp,
        // Both sides non-empty with differing length: a complex delins.
        _ => Vt::Delins,
    }
}

/// Strip the shared leading prefix then the shared trailing suffix of `r` and `a`,
/// returning the remaining byte slices.
///
/// Operates byte-wise — valid because `ACGTN` alleles are ASCII. Handles the
/// all-shared case (one string fully consumed) by leaving an empty remainder rather
/// than over-trimming into the other slice: `zip` stops at the shorter side, and the
/// suffix scan runs over what *remains* of each slice after the prefix, so neither
/// scan can reach past the other's remainder.
#[expect(
    clippy::string_slice,
    reason = "REF/ALT are validated ACGTN (ASCII) before reaching here, so the byte offsets computed above are char boundaries"
)]
fn trim_common_affix<'a>(r: &'a str, a: &'a str) -> (&'a str, &'a str) {
    let rb = r.as_bytes();
    let ab = a.as_bytes();

    // Shared prefix length, bounded by the shorter string.
    let pre = rb.iter().zip(ab).take_while(|(x, y)| x == y).count();

    // Shared suffix length, scanned backwards over what remains of *each* slice after
    // the prefix (so a fully-consumed string yields an empty remainder, never a
    // negative or overlapping range).
    let suf = rb[pre..]
        .iter()
        .rev()
        .zip(ab[pre..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();

    (&r[pre..rb.len() - suf], &a[pre..ab.len() - suf])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_after_trim_but_stores_verbatim() {
        assert_eq!(classify_vt("T", "C"), Vt::Snp);
        assert_eq!(classify_vt("AC", "A"), Vt::Del); // deletion (ALT side empties)
        assert_eq!(classify_vt("A", "AC"), Vt::Ins); // insertion (REF side empties)
        assert_eq!(classify_vt("AT", "GC"), Vt::Mnp); // equal-len block substitution
        assert_eq!(classify_vt("AT", "GCC"), Vt::Delins); // complex: 2 vs 3, both non-empty
        assert_eq!(classify_vt("ATG", "C"), Vt::Delins); // complex: 3 vs 1, no shared affix
    }

    #[test]
    fn accepts_only_literal_acgtn() {
        assert_eq!(normalize_allele(" t ").as_deref(), Some("T"));
        assert!(is_literal_acgtn("ACGTN"));
        assert!(!is_literal_acgtn("<DEL>"));
        assert!(!is_literal_acgtn("A]3:1]")); // breakend
        assert!(!is_literal_acgtn("*"));
    }

    #[test]
    fn vt_as_str_labels() {
        assert_eq!(Vt::Snp.as_str(), "SNP");
        assert_eq!(Vt::Mnp.as_str(), "MNP");
        assert_eq!(Vt::Ins.as_str(), "INS");
        assert_eq!(Vt::Del.as_str(), "DEL");
        assert_eq!(Vt::Delins.as_str(), "DELINS");
    }

    #[test]
    fn normalize_allele_trims_and_rejects_empty() {
        assert_eq!(normalize_allele("acgt").as_deref(), Some("ACGT"));
        assert_eq!(normalize_allele("  AC  ").as_deref(), Some("AC"));
        assert_eq!(normalize_allele("   "), None);
        assert_eq!(normalize_allele(""), None);
    }

    #[test]
    fn alt_is_supported_rejects_non_literal() {
        assert!(alt_is_supported("A"));
        assert!(alt_is_supported("ACGTN"));
        assert!(!alt_is_supported("<INS>"));
        assert!(!alt_is_supported("[2:321682[A")); // breakend
        assert!(!alt_is_supported(".")); // missing
        assert!(!alt_is_supported("*")); // overlapping deletion
        assert!(!alt_is_supported("")); // empty
    }

    #[test]
    fn trim_common_affix_handles_all_shared() {
        // ALT fully shares its bytes with the head of REF (deletion of "C").
        assert_eq!(trim_common_affix("AC", "A"), ("C", ""));
        // Insertion: REF fully shared with head of ALT.
        assert_eq!(trim_common_affix("A", "AC"), ("", "C"));
        // Shared prefix + suffix around a SNP core.
        assert_eq!(trim_common_affix("GATC", "GTTC"), ("A", "T"));
        // Identical strings collapse to empty remainders on both sides.
        assert_eq!(trim_common_affix("ACGT", "ACGT"), ("", ""));
        // No shared affix at all.
        assert_eq!(trim_common_affix("T", "C"), ("T", "C"));
    }

    #[test]
    fn trim_common_affix_handles_homopolymer_indels() {
        // Homopolymer (same-base) indels over-trim if either post-prefix remainder bound is
        // computed wrong: for "A"/"AA" the shared prefix "A" also matches as a suffix, so
        // the suffix scan must stay clamped to each slice's post-prefix remainder.
        // Otherwise the result slice is `r[1..0]`, a reversed range that panics out of
        // bounds. These are the most common bcftools-normalised indel shapes.
        assert_eq!(trim_common_affix("A", "AA"), ("", "A"));
        assert_eq!(trim_common_affix("AA", "A"), ("A", ""));
        assert_eq!(trim_common_affix("AA", "AAA"), ("", "A"));
        assert_eq!(trim_common_affix("AAA", "AA"), ("A", ""));
        assert_eq!(classify_vt("A", "AA"), Vt::Ins);
        assert_eq!(classify_vt("AA", "A"), Vt::Del);
    }

    #[test]
    fn classify_vt_with_shared_affix_still_correct() {
        // SNP wrapped in identical context: GATC vs GTTC → SNP (A vs T).
        assert_eq!(classify_vt("GATC", "GTTC"), Vt::Snp);
        // Deletion with shared prefix: ATG vs A → DEL (ALT side empties).
        assert_eq!(classify_vt("ATG", "A"), Vt::Del);
        // Insertion with shared prefix: A vs ATG → INS (REF side empties).
        assert_eq!(classify_vt("A", "ATG"), Vt::Ins);
        // Equal-length, fully differing, length 3 → MNP (block substitution).
        assert_eq!(classify_vt("AAT", "AGC"), Vt::Mnp);
    }

    /// The real pairs a multi-allelic split invents, taken verbatim from 1000 Genomes
    /// phase-3 chr21. Each is what the converter would store without the right-trim.
    #[test]
    fn right_trim_reduces_the_pairs_a_split_invents() {
        // 21:9443612 REF=GATGAAATGAA ALT=GATGAA,G  → allele 1 is a 5-base deletion.
        assert_eq!(right_trim_alleles("GATGAAATGAA", "GATGAA"), ("GATGAA", "G"));
        // 21:9489357 REF=CATAT ALT=CAT,C
        assert_eq!(right_trim_alleles("CATAT", "CAT"), ("CAT", "C"));
        // 21:9712098 REF=AT ALT=ATT,A → allele 1 is a 1-base insertion, not `AT>ATT`.
        assert_eq!(right_trim_alleles("AT", "ATT"), ("A", "AT"));
        // 21:9851112 REF=TA ALT=TAA,T
        assert_eq!(right_trim_alleles("TA", "TAA"), ("T", "TA"));
    }

    #[test]
    fn right_trim_is_idempotent_and_keeps_one_base_each_side() {
        for (r, a) in [("GATGAAATGAA", "GATGAA"), ("AT", "ATT"), ("A", "G")] {
            let once = right_trim_alleles(r, a);
            let twice = right_trim_alleles(once.0, once.1);
            assert_eq!(once, twice, "trimming {r}>{a} must be idempotent");
            assert!(!once.0.is_empty() && !once.1.is_empty());
        }
        // A pure deletion cannot be trimmed away: one base must anchor each side.
        assert_eq!(right_trim_alleles("AA", "A"), ("AA", "A"));
    }

    /// `classify_vt` trims both affixes for its label, so the trim must not move the VT.
    /// If it ever did, a rebuild would silently relabel every split indel.
    #[test]
    fn right_trim_never_changes_the_variant_type() {
        for (r, a) in [
            ("GATGAAATGAA", "GATGAA"),
            ("CATAT", "CAT"),
            ("AT", "ATT"),
            ("TA", "TAA"),
            ("GATC", "GTTC"),
        ] {
            let (rt, at) = right_trim_alleles(r, a);
            assert_eq!(
                classify_vt(r, a),
                classify_vt(rt, at),
                "VT moved for {r}>{a}"
            );
        }
    }

    /// The 8 alleles in 1000G chr21 that right-trimming cannot canonicalise: reaching
    /// minimal form would advance POS, breaking the sorted-POS invariant, so the converter
    /// warns rather than rewriting. Pinned so a change that also left-trims cannot land
    /// without confronting the ordering consequence.
    #[test]
    fn left_trimmable_pairs_are_detected_not_rewritten() {
        // 21:22292532 REF=TGATA ALT=TGATAGATAGGTA → right-trims, still prefix-shared.
        let (r, a) = right_trim_alleles("TGATA", "TGATAGATAGGTA");
        assert!(
            is_left_trimmable(r, a),
            "{r}>{a} still shares a leading base"
        );
        // 21:15713994 REF=TT ALT=TTG
        let (r, a) = right_trim_alleles("TT", "TTG");
        assert!(is_left_trimmable(r, a));

        // Canonical forms have nothing left to trim on the left.
        assert!(!is_left_trimmable("A", "AT")); // insertion anchor
        assert!(!is_left_trimmable("AT", "A")); // deletion anchor
        assert!(!is_left_trimmable("A", "G")); // SNP
        // `GATGAA>G` is fully minimal after the right-trim.
        let (r, a) = right_trim_alleles("GATGAAATGAA", "GATGAA");
        assert!(!is_left_trimmable(r, a));
    }
}
