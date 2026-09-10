//! Chromosome normalization and the `RefSeq` accession ↔ chromosome table.
//!
//! Contig labels arriving from a VCF `#CHROM` column (or a Beacon `referenceName`)
//! are normalized to the canonical set `1..=22`, `X`, `Y`, `M`. Three forms are
//! accepted: a bare/`chr`-prefixed chromosome label, `MT` (normalized to `M`), and
//! a primary-assembly `RefSeq` accession resolved through the static table below.
//! Non-primary contigs (decoys, scaffolds, alt-haplotypes, …) are *skipped*
//! (`Ok(None)`), while a truly unknown label is an error.

use std::borrow::Cow;

use crate::error::{CoreResult, invalid_parquet};

/// One row of the `RefSeq` accession ↔ chromosome table: the canonical chromosome
/// label and its assembly-specific accessions for `GRCh37` and `GRCh38`.
struct AccessionRow {
    /// Canonical chromosome label (`1`..=`22`, `X`, `Y`, `M`).
    chr: &'static str,
    /// Primary-assembly `RefSeq` accession for `GRCh37`.
    grch37: &'static str,
    /// Primary-assembly `RefSeq` accession for `GRCh38`.
    grch38: &'static str,
}

/// The `RefSeq` accession ↔ chromosome table.
///
/// Gotchas: `X` is `NC_000023`, `Y` is `NC_000024`, and the mitochondrion uses the
/// non-`rCRS` `NC_001807.4` for `GRCh37` but `rCRS` `NC_012920.1` for `GRCh38`.
static ACCESSIONS: &[AccessionRow] = &[
    AccessionRow {
        chr: "1",
        grch37: "NC_000001.10",
        grch38: "NC_000001.11",
    },
    AccessionRow {
        chr: "2",
        grch37: "NC_000002.11",
        grch38: "NC_000002.12",
    },
    AccessionRow {
        chr: "3",
        grch37: "NC_000003.11",
        grch38: "NC_000003.12",
    },
    AccessionRow {
        chr: "4",
        grch37: "NC_000004.11",
        grch38: "NC_000004.12",
    },
    AccessionRow {
        chr: "5",
        grch37: "NC_000005.9",
        grch38: "NC_000005.10",
    },
    AccessionRow {
        chr: "6",
        grch37: "NC_000006.11",
        grch38: "NC_000006.12",
    },
    AccessionRow {
        chr: "7",
        grch37: "NC_000007.13",
        grch38: "NC_000007.14",
    },
    AccessionRow {
        chr: "8",
        grch37: "NC_000008.10",
        grch38: "NC_000008.11",
    },
    AccessionRow {
        chr: "9",
        grch37: "NC_000009.11",
        grch38: "NC_000009.12",
    },
    AccessionRow {
        chr: "10",
        grch37: "NC_000010.10",
        grch38: "NC_000010.11",
    },
    AccessionRow {
        chr: "11",
        grch37: "NC_000011.9",
        grch38: "NC_000011.10",
    },
    AccessionRow {
        chr: "12",
        grch37: "NC_000012.11",
        grch38: "NC_000012.12",
    },
    AccessionRow {
        chr: "13",
        grch37: "NC_000013.10",
        grch38: "NC_000013.11",
    },
    AccessionRow {
        chr: "14",
        grch37: "NC_000014.8",
        grch38: "NC_000014.9",
    },
    AccessionRow {
        chr: "15",
        grch37: "NC_000015.9",
        grch38: "NC_000015.10",
    },
    AccessionRow {
        chr: "16",
        grch37: "NC_000016.9",
        grch38: "NC_000016.10",
    },
    AccessionRow {
        chr: "17",
        grch37: "NC_000017.10",
        grch38: "NC_000017.11",
    },
    AccessionRow {
        chr: "18",
        grch37: "NC_000018.9",
        grch38: "NC_000018.10",
    },
    AccessionRow {
        chr: "19",
        grch37: "NC_000019.9",
        grch38: "NC_000019.10",
    },
    AccessionRow {
        chr: "20",
        grch37: "NC_000020.10",
        grch38: "NC_000020.11",
    },
    AccessionRow {
        chr: "21",
        grch37: "NC_000021.8",
        grch38: "NC_000021.9",
    },
    AccessionRow {
        chr: "22",
        grch37: "NC_000022.10",
        grch38: "NC_000022.11",
    },
    AccessionRow {
        chr: "X",
        grch37: "NC_000023.10",
        grch38: "NC_000023.11",
    },
    AccessionRow {
        chr: "Y",
        grch37: "NC_000024.9",
        grch38: "NC_000024.10",
    },
    AccessionRow {
        chr: "M",
        grch37: "NC_001807.4",
        grch38: "NC_012920.1",
    },
];

/// Canonical assembly label for `GRCh37`.
const GRCH37: &str = "GRCh37";
/// Canonical assembly label for `GRCh38`.
const GRCH38: &str = "GRCh38";

/// Whether `assembly` is one of the two assemblies the node supports, matched
/// case-sensitively (`GRCh37` / `GRCh38`).
///
/// Catches an assembly typo (`hg38`, `grch38`, `GRCh38 ` with a trailing space) at
/// build, lint and validate time, instead of letting it surface deep in conversion as a
/// cryptic per-record accession mismatch. Strict rather than normalizing, so the declared
/// assembly always matches the accessions the node cross-checks against
/// ([`accession_for`] / [`accession_to_chr`]).
///
/// # Examples
///
/// ```
/// use gdi_node_standalone_core::chrom::is_known_assembly;
///
/// assert!(is_known_assembly("GRCh38"));
/// assert!(is_known_assembly("GRCh37"));
/// assert!(!is_known_assembly("hg38"));
/// assert!(!is_known_assembly("GRCH38"));
/// ```
#[must_use]
pub fn is_known_assembly(assembly: &str) -> bool {
    KNOWN_ASSEMBLIES.contains(&assembly)
}

/// The assembly labels the converter accepts, in wizard menu order. Both
/// [`is_known_assembly`] and the wizard's pick-list read this list.
pub const KNOWN_ASSEMBLIES: [&str; 2] = [GRCH37, GRCH38];

/// Bare scaffold-accession prefixes that mark a non-primary contig (skipped).
const SCAFFOLD_PREFIXES: &[&str] = &["GL", "KI", "JH", "GJ", "KN", "KQ", "KV", "KZ", "ML"];

/// The `RefSeq` accession for `(chr, assembly)`, or `None` if the pair is unknown.
///
/// `chr` must already be a canonical label (`1`..=`22`, `X`, `Y`, `M`); `assembly`
/// is matched case-sensitively against `GRCh37` / `GRCh38`.
///
/// # Examples
///
/// ```
/// use gdi_node_standalone_core::chrom::accession_for;
///
/// assert_eq!(accession_for("X", "GRCh37"), Some("NC_000023.10"));
/// // The mitochondrion is assembly-specific (rCRS only on GRCh38).
/// assert_eq!(accession_for("M", "GRCh38"), Some("NC_012920.1"));
/// // An unknown assembly (matched case-sensitively) yields `None`.
/// assert_eq!(accession_for("1", "hg38"), None);
/// ```
#[must_use]
pub fn accession_for(chr: &str, assembly: &str) -> Option<&'static str> {
    let row = ACCESSIONS.iter().find(|r| r.chr == chr)?;
    match assembly {
        GRCH37 => Some(row.grch37),
        GRCH38 => Some(row.grch38),
        _ => None,
    }
}

/// Resolve a `RefSeq` accession to its `(chromosome, assembly)` pair, or `None` if
/// the accession is not a primary-assembly accession in the table.
///
/// The mitochondrial accessions are assembly-specific in the table just like the
/// autosomes, so this returns the assembly the accession belongs to; mito callers
/// that need cross-check exemption handle that in [`normalize_contig`].
#[must_use]
pub fn accession_to_chr(acc: &str) -> Option<(&'static str, &'static str)> {
    for row in ACCESSIONS {
        if row.grch37 == acc {
            return Some((row.chr, GRCH37));
        }
        if row.grch38 == acc {
            return Some((row.chr, GRCH38));
        }
    }
    None
}

/// Strip a leading, case-insensitive `chr` *prefix* (not a character-set strip).
///
/// `chr7` → `7`, `CHR7` → `7`, `rch3` → `rch3` (unchanged). Only the first three
/// characters are considered, and only when they spell `chr` in any case.
/// The `beacon` crate strips the same prefix from an untrusted `referenceName` before
/// matching it, so this is the one definition. A second copy could disagree on the
/// multibyte edge case, turning a bad `referenceName` into a `500` instead of a `400`.
#[must_use]
#[expect(
    clippy::string_slice,
    reason = "the guard above proves bytes 0..3 are the ASCII prefix `chr`, so byte 3 is a char boundary"
)]
pub fn strip_chr_prefix(raw: &str) -> &str {
    // Compare the first three bytes, not `raw[..3]`, which panics when byte index 3 is
    // inside a multi-byte UTF-8 char. When the prefix is `chr` (ASCII), byte 3 is a char
    // boundary, so `&raw[3..]` is safe.
    if raw.len() >= 3 && raw.as_bytes()[..3].eq_ignore_ascii_case(b"chr") {
        &raw[3..]
    } else {
        raw
    }
}

/// Strip a trailing `RefSeq` version suffix (`.<digits>`) from an accession label,
/// leaving a label without such a suffix unchanged. `NC_007605.1` → `NC_007605`;
/// `hs37d5` → `hs37d5`; `HLA-A*01:01` → unchanged.
fn strip_refseq_version(raw: &str) -> &str {
    match raw.rsplit_once('.') {
        Some((stem, ver)) if !ver.is_empty() && ver.bytes().all(|b| b.is_ascii_digit()) => stem,
        _ => raw,
    }
}

/// True if `raw` is a GRC patch / novel-sequence name: `HG`, one or more ASCII digits,
/// then `_` (`HG1012_PATCH`, `HG107_HG2565_PATCH`, `HG142_HG150_NOVEL_TEST`). Byte-wise and
/// case-insensitive; never slices `raw`, which is untrusted `#CHROM` input.
fn is_grc_patch_name(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    if bytes.len() < 4 || !bytes[..2].eq_ignore_ascii_case(b"HG") {
        return false;
    }
    let digits = bytes[2..].iter().take_while(|b| b.is_ascii_digit()).count();
    digits > 0 && bytes.get(2 + digits) == Some(&b'_')
}

/// True if `raw` matches a known non-primary contig that should be skipped, in the order
/// checked below: decoys and EBV, the `chrUn_`/`Un_`/`HLA-`/`NW_`/`NT_`/`HSCHR` prefixes,
/// GRC `HG<n>_` patch names, bare scaffold accessions, the `_alt`/`_random`/`_fix`/
/// `_decoy` suffixes, and `_hapN` alt-haplotypes.
#[expect(
    clippy::string_slice,
    reason = "`idx` is the byte offset of the ASCII literal `_hap`, so `idx + 4` is a char boundary"
)]
fn is_non_primary_skip(raw: &str) -> bool {
    // Decoys and EBV (exact, case-insensitive). The EBV decoy travels under two names —
    // `NC_007605` in the GRCh37 `hs37d5` set and `chrEBV` in the GRCh38 full analysis set —
    // and a whole-genome joint call carries records on it, so both must skip rather than
    // fail the file at its first EBV record. RefSeq accessions carry a `.N` version suffix
    // (e.g. `NC_007605.1`); strip it before the exact compare so the versioned form still
    // matches the unversioned decoy stem.
    const DECOYS: &[&str] = &["hs37d5", "hs38d1", "NC_007605", "chrEBV"];
    let unversioned = strip_refseq_version(raw);
    if DECOYS.iter().any(|d| unversioned.eq_ignore_ascii_case(d)) {
        return true;
    }
    // Byte-wise, case-insensitive prefix test — never char-boundary-slices `s`
    // (`raw[..n]` panics on a multi-byte UTF-8 boundary; `raw` is untrusted VCF
    // `#CHROM` input).
    let has_prefix = |s: &str, p: &str| {
        s.len() >= p.len() && s.as_bytes()[..p.len()].eq_ignore_ascii_case(p.as_bytes())
    };
    // Prefixes. `NW_`/`NT_` are RefSeq unplaced-scaffold / unlocalized-contig
    // accessions (e.g. `NW_009646201.1`) — the RefSeq analog of the bare GenBank
    // scaffold prefixes below. Primary `NC_` chromosome accessions are resolved
    // earlier in `normalize_contig` and never reach here, so these prefixes cannot
    // swallow a real chromosome.
    if ["chrUn_", "Un_", "HLA-", "NW_", "NT_"]
        .iter()
        .any(|p| has_prefix(raw, p))
    {
        return true;
    }
    // GRC names for alternate loci (`HSCHR6_MHC_COX_CTG1`, `HSCHR19KIR_…`, `HSCHRX_…`) and
    // patches (`HG1012_PATCH`, `HG107_HG2565_PATCH`, `HG142_HG150_NOVEL_TEST`): what an
    // Ensembl *toplevel* FASTA calls the sequences UCSC spells `chr6_GL000250v2_alt`. A
    // VCF called against that file carries 512 such labels beside the 25 chromosomes, and
    // no primary chromosome is spelled either way.
    if has_prefix(raw, "HSCHR") || is_grc_patch_name(raw) {
        return true;
    }
    // Bare scaffold-accession prefixes (e.g. `GL000207.1`), with or without a
    // leading `chr` (e.g. `chrGL000207`) — a `chr` prefix must not defeat the match.
    let unprefixed = strip_chr_prefix(raw);
    if SCAFFOLD_PREFIXES
        .iter()
        .any(|p| has_prefix(raw, p) || has_prefix(unprefixed, p))
    {
        return true;
    }
    // Suffixes `_alt`, `_random`, `_fix`, `_decoy` — each independently non-primary.
    let lower = raw.to_ascii_lowercase();
    if ["_alt", "_random", "_fix", "_decoy"]
        .iter()
        .any(|s| lower.ends_with(s))
    {
        return true;
    }
    // Alt-haplotype `_hapN` (N = one or more ASCII digits).
    if let Some(idx) = lower.rfind("_hap") {
        let tail = &lower[idx + 4..];
        if !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()) {
            return true;
        }
    }
    false
}

/// Resolve a `chr`-prefix-stripped label to its canonical `&'static str` table
/// entry, case-insensitively, mapping the `MT` alias to `M`. Returns `None` when
/// `stripped` is not a canonical chromosome. Allocation-free: it compares the input
/// case-insensitively against the fixed label set rather than uppercasing it.
fn canonical_static(stripped: &str) -> Option<&'static str> {
    if stripped.eq_ignore_ascii_case("MT") {
        return Some("M");
    }
    ACCESSIONS
        .iter()
        .map(|r| r.chr)
        .find(|chr| stripped.eq_ignore_ascii_case(chr))
}

/// Normalize a raw contig label against the dataset's declared assembly.
///
/// Returns:
/// * `Ok(Some(chr))` — a canonical chromosome to index.
/// * `Ok(None)` — a recognised non-primary contig to skip without error.
/// * `Err(_)` — a contradictory accession (assembly mismatch) or a truly unknown
///   label.
///
/// # Examples
///
/// ```
/// use gdi_node_standalone_core::chrom::normalize_contig;
///
/// # fn main() -> Result<(), gdi_node_standalone_core::error::CoreError> {
/// // A `chr`-prefixed label normalizes to its canonical form.
/// assert_eq!(normalize_contig("chr7", "GRCh38")?.as_deref(), Some("7"));
/// // `MT` folds to `M`.
/// assert_eq!(normalize_contig("MT", "GRCh38")?.as_deref(), Some("M"));
/// // A primary-assembly accession resolves to its chromosome.
/// assert_eq!(normalize_contig("NC_000023.11", "GRCh38")?.as_deref(), Some("X"));
/// // A recognised non-primary contig (decoy) is skipped without error.
/// assert_eq!(normalize_contig("hs37d5", "GRCh38")?, None);
/// // A truly unknown label is an error.
/// assert!(normalize_contig("banana", "GRCh38").is_err());
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns [`CoreError::InvalidParquet`](crate::error::CoreError::InvalidParquet) when a
/// primary-assembly accession contradicts `dataset_assembly` (the mitochondrion is exempt),
/// or when the label is neither a known chromosome, a skip-listed non-primary contig, nor a
/// resolvable primary-assembly accession.
pub fn normalize_contig(
    raw: &str,
    dataset_assembly: &str,
) -> CoreResult<Option<Cow<'static, str>>> {
    // 1. RefSeq accession (assembly-specific; mitochondrion exempt from cross-check).
    if let Some((chr, acc_assembly)) = accession_to_chr(raw) {
        if chr == "M" {
            return Ok(Some(Cow::Borrowed("M")));
        }
        if acc_assembly != dataset_assembly {
            return Err(invalid_parquet(format!(
                "accession {raw} is {acc_assembly} but dataset assembly is {dataset_assembly}"
            )));
        }
        return Ok(Some(Cow::Borrowed(chr)));
    }

    // 2. chr-prefix strip, then resolve to the canonical `&'static` label
    //    (case-insensitive, `MT` → `M`) with no allocation.
    if let Some(chr) = canonical_static(strip_chr_prefix(raw)) {
        return Ok(Some(Cow::Borrowed(chr)));
    }

    // 3. Known non-primary contigs are skipped without error.
    if is_non_primary_skip(raw) {
        return Ok(None);
    }

    // 4. Anything else is an unknown contig.
    Err(invalid_parquet(format!("unknown contig label: {raw}")))
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;

    /// Every contig label of every published reference set is classified, either kept as a
    /// primary chromosome or skipped as non-primary, and none is an error. A reference
    /// set's own contig list is what a whole-genome VCF carries, and one unclassified label
    /// aborts a whole build at its first record, so the classification is checked against
    /// the real lists rather than a hand-picked sample. Two shapes are easy to miss:
    /// `chrEBV`, 1 label of 3366 in the `GRCh38` analysis set, and the GRC alt-locus and
    /// patch names, 512 of 706 in Ensembl's toplevel set.
    #[test]
    fn every_contig_of_the_published_reference_sets_is_classified() {
        for set in test_util::reference_contig_sets() {
            let mut primary = 0;
            let mut skipped = 0;
            for name in set.names.lines().filter(|l| !l.is_empty()) {
                match normalize_contig(name, set.assembly) {
                    Ok(Some(_)) => primary += 1,
                    Ok(None) => skipped += 1,
                    Err(e) => panic!("{}: contig {name:?} is not classified: {e}", set.source),
                }
            }
            assert_eq!(
                primary, 25,
                "{}: 1..22, X, Y and the mitochondrion",
                set.source
            );
            assert!(
                skipped > 0,
                "{}: the non-primary contigs must be skipped",
                set.source
            );
        }
        for skipped in [
            ("chrEBV", "GRCh38"),
            ("NC_007605", "GRCh37"),
            ("HSCHR6_MHC_COX_CTG1", "GRCh38"),
            ("HSCHR19KIR_FH05_A_HAP_CTG3_1", "GRCh38"),
            ("HG1012_PATCH", "GRCh38"),
            ("HG107_HG2565_PATCH", "GRCh38"),
            ("HG142_HG150_NOVEL_TEST", "GRCh38"),
        ] {
            assert_eq!(
                normalize_contig(skipped.0, skipped.1).unwrap(),
                None,
                "{} must be skipped",
                skipped.0
            );
        }
        // The patch rule is `HG<digits>_`, no looser: a label that merely starts with `HG`
        // stays unknown rather than silently skipped.
        assert!(!is_grc_patch_name("HG_PATCH"));
        assert!(!is_grc_patch_name("HG12PATCH"));
        assert!(!is_grc_patch_name("HGX_1"));
        assert!(normalize_contig("HGabc_1", "GRCh38").is_err());
    }

    /// `beacon`'s public `g_variants` endpoint feeds an untrusted `referenceName` straight
    /// into this, so a `raw[..3]` slice off a char boundary would panic and surface as a
    /// `500` rather than a `400`. Pinned here, where that prefix strip is defined.
    #[test]
    fn strip_chr_prefix_handles_multibyte_referencename_without_panicking() {
        assert_eq!(strip_chr_prefix("chr7"), "7");
        assert_eq!(strip_chr_prefix("CHR3"), "3");
        assert_eq!(strip_chr_prefix("rch3"), "rch3");
        // `ab\u{e9}` is bytes 61 62 C3 A9: byte index 3 is inside the multi-byte char.
        assert_eq!(strip_chr_prefix("ab\u{e9}"), "ab\u{e9}");
    }

    #[test]
    fn normalizes_names() {
        assert_eq!(
            normalize_contig("chr3", "GRCh38").unwrap().as_deref(),
            Some("3")
        );
        assert_eq!(
            normalize_contig("3", "GRCh38").unwrap().as_deref(),
            Some("3")
        );
        assert_eq!(
            normalize_contig("MT", "GRCh38").unwrap().as_deref(),
            Some("M")
        );
        assert_eq!(
            normalize_contig("CHR7", "GRCh38").unwrap().as_deref(),
            Some("7")
        );
        // accession resolves and assembly cross-checks
        assert_eq!(
            normalize_contig("NC_000023.11", "GRCh38")
                .unwrap()
                .as_deref(),
            Some("X")
        );
        assert!(normalize_contig("NC_000011.9", "GRCh38").is_err()); // GRCh37 accession in GRCh38 → reject
        // mito accession exempt from cross-check
        assert_eq!(
            normalize_contig("NC_012920.1", "GRCh37")
                .unwrap()
                .as_deref(),
            Some("M")
        );
        // non-primary contigs skipped (Ok(None))
        assert_eq!(normalize_contig("hs37d5", "GRCh38").unwrap(), None);
        assert_eq!(normalize_contig("chrUn_xxx", "GRCh38").unwrap(), None);
        // A bare scaffold accession and its `chr`-prefixed form are both skipped rather
        // than hard-rejected: a `chr` prefix must not defeat the scaffold match.
        assert_eq!(normalize_contig("GL000207.1", "GRCh38").unwrap(), None);
        assert_eq!(normalize_contig("chrGL000207", "GRCh38").unwrap(), None);
        // A non-ASCII `#CHROM` label (untrusted VCF input) whose first bytes straddle a
        // multi-byte char must not panic in the prefix/scaffold matchers. It is simply
        // unknown, so it yields a clean error.
        assert!(normalize_contig("ab\u{3a9}", "GRCh38").is_err()); // "abΩ"
        // truly unknown errors
        assert!(normalize_contig("banana", "GRCh38").is_err());
    }

    #[test]
    fn accession_lookup_matches_table() {
        assert_eq!(accession_for("X", "GRCh37"), Some("NC_000023.10"));
        assert_eq!(accession_for("Y", "GRCh38"), Some("NC_000024.10"));
        assert_eq!(accession_for("M", "GRCh38"), Some("NC_012920.1"));
        assert_eq!(accession_for("M", "GRCh37"), Some("NC_001807.4"));
    }

    #[test]
    fn chr_strip_is_a_true_prefix_strip() {
        // CHR7 must lose only the leading `chr`, not the char-set {c,h,r}.
        assert_eq!(strip_chr_prefix("CHR7"), "7");
        assert_eq!(strip_chr_prefix("chr3"), "3");
        // `rch3` does not start with `chr`, so it must be left untouched.
        assert_eq!(strip_chr_prefix("rch3"), "rch3");
        // A multi-byte UTF-8 char straddling byte index 3 must not panic, since slicing
        // `raw[..3]` is not at a char boundary: `ab\u{e9}` is bytes 61 62 C3 A9.
        assert_eq!(strip_chr_prefix("ab\u{e9}"), "ab\u{e9}");
        assert!(normalize_contig("rch3", "GRCh38").is_err());
    }

    #[test]
    fn mt_accession_resolves_for_either_assembly() {
        // rCRS in a GRCh37 dataset is legitimate (exempt from cross-check).
        assert_eq!(
            normalize_contig("NC_012920.1", "GRCh38")
                .unwrap()
                .as_deref(),
            Some("M")
        );
        // Non-rCRS GRCh37 mito accession in a GRCh38 dataset is also exempt.
        assert_eq!(
            normalize_contig("NC_001807.4", "GRCh38")
                .unwrap()
                .as_deref(),
            Some("M")
        );
    }

    #[test]
    fn skips_scaffold_and_haplotype_contigs() {
        assert_eq!(normalize_contig("GL000207.1", "GRCh37").unwrap(), None);
        assert_eq!(normalize_contig("KI270706.1", "GRCh38").unwrap(), None);
        assert_eq!(normalize_contig("NC_007605", "GRCh38").unwrap(), None); // EBV
        assert_eq!(
            normalize_contig("chr1_KI270706v1_random", "GRCh38").unwrap(),
            None
        );
        assert_eq!(
            normalize_contig("chr19_KI270938v1_alt", "GRCh38").unwrap(),
            None
        );
        assert_eq!(
            normalize_contig("chr1_gl000191_hap1", "GRCh38").unwrap(),
            None
        );
        assert_eq!(normalize_contig("HLA-A*01:01", "GRCh38").unwrap(), None);
    }

    #[test]
    fn skips_refseq_scaffold_and_versioned_ebv_contigs() {
        // RefSeq unplaced/unlocalized scaffold accessions (NW_*, NT_*) are the RefSeq
        // analog of the bare GenBank scaffold prefixes, so they must be skipped (Ok(None))
        // like their UCSC-named equivalents rather than aborted as an unknown label.
        // Otherwise a standard RefSeq-accession VCF, whose primary chromosomes are the
        // resolved NC_ accessions, fails the whole conversion at its first scaffold record
        // while the equivalent UCSC-named VCF succeeds.
        assert_eq!(normalize_contig("NW_009646201.1", "GRCh38").unwrap(), None);
        assert_eq!(normalize_contig("NT_187633.1", "GRCh38").unwrap(), None);
        // The EBV decoy appears in real VCFs in its versioned RefSeq form; the trailing
        // `.N` version must not defeat the (unversioned) decoy match.
        assert_eq!(normalize_contig("NC_007605.1", "GRCh38").unwrap(), None);
        // A primary chromosome accession is still resolved to its chromosome (the decoy
        // stem-match must not over-skip real NC_ chromosomes).
        assert_eq!(
            normalize_contig("NC_000001.11", "GRCh38")
                .unwrap()
                .as_deref(),
            Some("1")
        );
    }

    #[test]
    fn fix_decoy_suffixes_skip_and_non_digit_hap_tail_errors() {
        // `is_non_primary_skip`'s suffix chain and `_hapN` guard. A `_fix` patch contig
        // and a `_decoy` contig are recognised non-primary contigs, skipped without error
        // (Ok(None)). Both are asserted because an `any` -> `all` slip in the suffix set
        // would require `_fix` and `_decoy` together and stop matching either.
        assert_eq!(
            normalize_contig("chr1_KN196472v1_fix", "GRCh38").unwrap(),
            None,
            "a _fix patch contig is skipped, not an error"
        );
        assert_eq!(
            normalize_contig("chr1_decoy", "GRCh38").unwrap(),
            None,
            "a _decoy contig is skipped, not an error"
        );
        // A `_hap` tail that is not all-digits is not an alt-haplotype: it must remain an
        // Err (unknown label) rather than being skipped. Pins the `!tail.is_empty() &&
        // all-digits` guard, where an `&&` -> `||` slip would skip any non-empty
        // `_hap` tail such as `_hapX`.
        assert!(
            normalize_contig("weird_hapX", "GRCh38").is_err(),
            "a non-digit _hap tail is an unknown label, not a skip"
        );
    }

    #[test]
    fn accession_to_chr_distinguishes_assembly() {
        assert_eq!(accession_to_chr("NC_000023.10"), Some(("X", GRCH37)));
        assert_eq!(accession_to_chr("NC_000023.11"), Some(("X", GRCH38)));
        assert_eq!(accession_to_chr("NC_000024.9"), Some(("Y", GRCH37)));
        assert_eq!(accession_to_chr("NC_000024.10"), Some(("Y", GRCH38)));
        assert_eq!(accession_to_chr("NC_999999.9"), None);
    }

    #[test]
    fn accession_roundtrip_is_exhaustive_bijection() {
        // The full canonical chromosome label set (1..=22, X, Y, M). "M", not "MT": MT is
        // an accepted input alias of normalize_contig, never a table key. Exhaustive over
        // the finite (chr, assembly) domain.
        const CHRS: &[&str] = &[
            "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16",
            "17", "18", "19", "20", "21", "22", "X", "Y", "M",
        ];
        for &chr in CHRS {
            for &assembly in &[GRCH37, GRCH38] {
                let acc = accession_for(chr, assembly)
                    .unwrap_or_else(|| panic!("no accession for ({chr}, {assembly})"));
                assert_eq!(
                    accession_to_chr(acc),
                    Some((chr, assembly)),
                    "round-trip failed for ({chr}, {assembly}) via {acc}",
                );
            }
        }

        // Negatives: accession_for is a raw lookup with no normalization, so non-key
        // labels and non-canonical assemblies resolve to None.
        for &bad_chr in &["23", "0", "x", "MT", "chr1", "", " 1"] {
            assert_eq!(accession_for(bad_chr, GRCH38), None);
        }
        for &bad_asm in &["hg38", "grch38", "GRCH38", "GRCh39", ""] {
            assert_eq!(accession_for("1", bad_asm), None);
        }
        for &bogus in &["NC_999999.9", "", "X", "NC_000001.99", "NC_000023"] {
            assert_eq!(accession_to_chr(bogus), None);
        }
    }
}
