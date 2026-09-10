//! Population-aware INFO field grammar parser.
//!
//! A population-stratified INFO field is one of the metrics `AF`, `AC`, `AN`,
//! `AC_Hom`, `AC_Het`, `AC_Hemi`, optionally carrying a 2-letter uppercase country
//! code and/or a sex token (`M`/`F`). For the `AC_Hom`/`AC_Het`/`AC_Hemi` metrics
//! the `Hom`/`Het`/`Hemi` qualifier may appear **before or after** the population
//! tokens (`AC_Hom_EE` ≡ `AC_EE_Hom`). The country code is **not** ISO-validated.
//!
//! Anything that does not fit the grammar (an unknown metric, two country tokens,
//! an `AF`/`AN` carrying a Hom/Het/Hemi qualifier, or any junk token) yields
//! [`None`] — the caller drops the field with a build-time warning; it is never
//! fatal.

/// The aggregate population key: the sum over every cohort, emitted when an INFO field
/// carries neither a country code nor a sex token.
///
/// Spelled here once. [`parse_info_field`] produces it, the build-time k-anonymity
/// collapse in `convert` keeps this population, and the serving gate in `beacon::query`
/// collapses to it. All three must agree, so none may spell it independently.
pub const TOTAL_POPULATION: &str = "Total";

/// The partition axis a non-[`TOTAL_POPULATION`] population label belongs to.
///
/// The per-sex, per-country and country×sex breakdowns are each a partition of
/// [`TOTAL_POPULATION`]: every axis sums to it. This is the decoder for the label grammar
/// [`parse_info_field`] encodes, and lives beside it so the two cannot drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PopulationAxis {
    /// Per-sex, e.g. `M`.
    Sex,
    /// Per-country, e.g. `FI`.
    Country,
    /// Country×sex, e.g. `FI_M`.
    CountrySex,
}

impl PopulationAxis {
    /// The number of distinct axes, for sizing per-axis accumulators.
    pub const COUNT: usize = 3;

    /// Every axis, for a caller that must consider each partition of
    /// [`TOTAL_POPULATION`] separately (e.g. [`crate::hierarchy`]'s partition rule).
    ///
    /// The explicit `[Self; Self::COUNT]` length means a fourth variant cannot be added
    /// without the compiler demanding it appear here too.
    pub const ALL: [Self; Self::COUNT] = [Self::Sex, Self::Country, Self::CountrySex];

    /// This axis as a dense index in `0..`[`Self::COUNT`].
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Sex => 0,
            Self::Country => 1,
            Self::CountrySex => 2,
        }
    }
}

/// The partition axis of a population label, or [`None`] for [`TOTAL_POPULATION`].
///
/// Decodes what [`parse_info_field`] encodes: `Total` | `[MF]` | `[A-Z]{2}` |
/// `[A-Z]{2}_[MF]`. A sex token is one ASCII byte and a country code two, so byte length
/// discriminates the two single-token forms. A label reaching here that is not
/// grammar-valid is producer-supplied garbage, classified by branch order: a token
/// containing `_` as `CountrySex`, an otherwise one-byte token as `Sex`, anything else as
/// `Country`.
///
/// The grammar is a contract shared with other GDI consumers, which split the same label,
/// so a change to [`parse_info_field`]'s encoding must be reflected here. The tests in this
/// module pin the pair over every label the encoder emits and over the token predicates it
/// is built from.
#[must_use]
pub fn population_axis(pop: &str) -> Option<PopulationAxis> {
    if pop == TOTAL_POPULATION {
        None
    } else if pop.contains('_') {
        Some(PopulationAxis::CountrySex)
    } else if pop.len() == 1 {
        Some(PopulationAxis::Sex)
    } else {
        Some(PopulationAxis::Country)
    }
}

/// The statistic a parsed INFO field contributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Metric {
    /// Allele frequency (`AF`).
    Af,
    /// Allele count (`AC`).
    Ac,
    /// Allele number (`AN`).
    An,
    /// Homozygous allele count (`AC_Hom`).
    AcHom,
    /// Heterozygous allele count (`AC_Het`).
    AcHet,
    /// Hemizygous allele count (`AC_Hemi`).
    AcHemi,
}

/// A parsed population-stratified INFO field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoField {
    /// Which statistic this field carries.
    pub metric: Metric,
    /// Population key: `Total` | `CC` | `M` | `F` | `CC_SEX`.
    pub population: String,
}

/// The zygosity qualifier carried by an `AC_Hom`/`AC_Het`/`AC_Hemi` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Qualifier {
    Hom,
    Het,
    Hemi,
}

/// Recognise a zygosity qualifier token (case-sensitive: `Hom`/`Het`/`Hemi`).
fn parse_qualifier(tok: &str) -> Option<Qualifier> {
    match tok {
        "Hom" => Some(Qualifier::Hom),
        "Het" => Some(Qualifier::Het),
        "Hemi" => Some(Qualifier::Hemi),
        _ => None,
    }
}

/// Two-letter tokens that are not country codes, whatever else they look like.
///
/// `XX` and `XY` are gnomAD's chromosomal-sex strata (`AF_XX`, `AC_XY`, …). They are two
/// uppercase letters, so a length-and-case test alone accepts them and publishes them as
/// countries in `populations`, which rides every beacon `datasets` entry and every
/// `g_variants` resultSet as `gdiDatasetInfo.populations`. ISO 3166-1 alpha-2 reserves `XX`
/// as user-assigned and leaves `XY` unassigned, so rejecting them costs no legitimate
/// provider anything.
///
/// A rejected field falls into the "ignored non-conforming INFO fields" diagnostic, which
/// warns and fails `build --strict`; on gnomAD input the result is a `Total`-only dataset,
/// as `docs/gdi-dataset-tool.md` describes. This is a small deny-list rather than ISO
/// validation: the country code is otherwise unvalidated (see the module docs), and a
/// provider using a private two-letter grouping must keep working.
const NOT_COUNTRY_CODES: [&str; 2] = ["XX", "XY"];

/// True if `tok` is exactly two uppercase ASCII letters and is not one of the reserved
/// sex-chromosome tokens (a country code; not otherwise ISO-3166-validated).
fn is_country_code(tok: &str) -> bool {
    tok.len() == 2
        && tok.bytes().all(|b| b.is_ascii_uppercase())
        && !NOT_COUNTRY_CODES.contains(&tok)
}

/// True if `tok` is a sex token (`M` or `F`).
fn is_sex(tok: &str) -> bool {
    tok == "M" || tok == "F"
}

/// Whether a population label, as stored in a dataset's parquet, is one
/// [`parse_info_field`] can emit: `Total`, a sex token, a country code, or
/// `<country>_<sex>`, with `XX`/`XY` excluded, as they are at build time.
///
/// `build` emits no other label, but a dataset converted by an older tool, or assembled by
/// hand, carries whatever its parquet says, and `populations` is a public disclosure field.
/// The node's ingest gate consults this to warn, not to reject: a pre-existing `XX`/`XY`
/// stratum is the provider's to rebuild or the operator's to hide, and neither can act on
/// what nothing reports.
#[must_use]
pub fn is_conforming_population_label(label: &str) -> bool {
    label == TOTAL_POPULATION
        || is_sex(label)
        || is_country_code(label)
        || label
            .split_once('_')
            .is_some_and(|(country, sex)| is_country_code(country) && is_sex(sex))
}

/// Parse one INFO field ID into a `(metric, population)` pair, or `None` if it does
/// not fit the grammar (the caller drops and warns).
///
/// Grammar: the first `_`-delimited token must be `AF`, `AC`, or `AN`. The
/// remaining tokens may contain at most one zygosity qualifier (`Hom`/`Het`/`Hemi`,
/// valid only with `AC`), at most one 2-letter uppercase country code, and at most
/// one sex token (`M`/`F`), in any order; any other or duplicate token rejects the
/// field. The population key is the country and sex tokens joined with `_`
/// (`Total` when neither is present).
///
/// # Examples
///
/// ```
/// use gdi_node_standalone_core::popfield::{parse_info_field, InfoField, Metric};
///
/// // A bare metric carries the `Total` population.
/// assert_eq!(
///     parse_info_field("AF"),
///     Some(InfoField { metric: Metric::Af, population: "Total".to_string() })
/// );
/// // Country + sex tokens join into the population key, qualifier order is free.
/// assert_eq!(
///     parse_info_field("AC_Hom_EE"),
///     Some(InfoField { metric: Metric::AcHom, population: "EE".to_string() })
/// );
/// // Non-conforming fields (e.g. `AF` with a Het qualifier) yield `None`.
/// assert_eq!(parse_info_field("AF_EE_Het"), None);
/// assert_eq!(parse_info_field("DP"), None);
/// ```
#[must_use]
pub fn parse_info_field(id: &str) -> Option<InfoField> {
    let mut tokens = id.split('_');

    // First token selects the metric base; must be AF | AC | AN.
    let base = tokens.next()?;
    if !matches!(base, "AF" | "AC" | "AN") {
        return None;
    }

    let mut qualifier: Option<Qualifier> = None;
    let mut country: Option<&str> = None;
    let mut sex: Option<&str> = None;

    for tok in tokens {
        if let Some(q) = parse_qualifier(tok) {
            if qualifier.is_some() {
                return None; // duplicate qualifier
            }
            qualifier = Some(q);
        } else if is_country_code(tok) {
            if country.is_some() {
                return None; // a second country token (e.g. AF_FI_NL)
            }
            country = Some(tok);
        } else if is_sex(tok) {
            if sex.is_some() {
                return None; // duplicate sex token
            }
            sex = Some(tok);
        } else {
            return None; // uninterpretable token
        }
    }

    // A zygosity qualifier is valid only on AC; AF/AN carrying one is rejected.
    let metric = match (base, qualifier) {
        ("AF", None) => Metric::Af,
        ("AN", None) => Metric::An,
        ("AC", None) => Metric::Ac,
        ("AC", Some(Qualifier::Hom)) => Metric::AcHom,
        ("AC", Some(Qualifier::Het)) => Metric::AcHet,
        ("AC", Some(Qualifier::Hemi)) => Metric::AcHemi,
        // AF/AN with a qualifier, or any other combination, is non-conforming.
        _ => return None,
    };

    // Population key = join(country, sex) or the aggregate key if neither present.
    let population = match (country, sex) {
        (Some(cc), Some(s)) => format!("{cc}_{s}"),
        (Some(cc), None) => cc.to_string(),
        (None, Some(s)) => s.to_string(),
        (None, None) => TOTAL_POPULATION.to_string(),
    };

    Some(InfoField { metric, population })
}

/// The rule an INFO ID broke when [`parse_info_field`] rejected it — in the words a
/// provider can act on. Ordered so a grouped report lists the most common shapes first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RejectReason {
    /// The metric is not the first token (`EUR_AF`): the grammar is `AF_<pop>`.
    MetricNotFirst,
    /// A lowercase token (`AF_nfe`, `AC_FI_raw`): every population token is uppercase.
    LowercaseToken,
    /// An uppercase alphabetic token of three or more letters (`AF_EUR`): a country code
    /// is exactly two.
    LongCode,
    /// `XX` / `XY`: chromosomal-sex strata, not country codes.
    SexChromosomeToken,
    /// A `Hom`/`Het`/`Hemi` qualifier on `AF` or `AN`; only `AC` carries one.
    QualifierOnAfOrAn,
    /// Two tokens of one kind (two country codes, two sexes, two qualifiers).
    DuplicateToken,
    /// A token that is none of the above (`AC_Hom2`, `AF_1KG`).
    UnknownToken,
}

impl RejectReason {
    /// The rule, phrased for the ignored-fields warning.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::MetricNotFirst => {
                "the metric is not the first token (the grammar is `AF_<population>`, not \
                 `<population>_AF`)"
            }
            Self::LowercaseToken => {
                "a lowercase token; a population token is a two-letter uppercase country \
                 code, `M`/`F`, or `Hom`/`Het`/`Hemi`"
            }
            Self::LongCode => {
                "an uppercase token of three or more letters; a country code is exactly two \
                 letters"
            }
            Self::SexChromosomeToken => "`XX`/`XY` are chromosomal-sex strata, not country codes",
            Self::QualifierOnAfOrAn => {
                "a `Hom`/`Het`/`Hemi` qualifier on `AF` or `AN`; only `AC` carries one"
            }
            Self::DuplicateToken => {
                "two tokens of the same kind (two country codes, two sexes, or two qualifiers)"
            }
            Self::UnknownToken => {
                "a token that is neither a country code, `M`/`F`, nor `Hom`/`Het`/`Hemi`"
            }
        }
    }
}

/// Why [`parse_info_field`] rejects `id`, or `None` when it parses.
///
/// The same token predicates as the parser, walked in the same order, so the two cannot
/// disagree about whether an ID parses (`rejection_reason_agrees_with_the_parser` pins the
/// equivalence over random token sequences). The first offending token decides; an ID
/// whose tokens are all recognised but combined illegally reports the combination.
///
/// # Examples
///
/// ```
/// use gdi_node_standalone_core::popfield::{rejection_reason, RejectReason};
///
/// assert_eq!(rejection_reason("EUR_AF"), Some(RejectReason::MetricNotFirst));
/// assert_eq!(rejection_reason("AF_nfe"), Some(RejectReason::LowercaseToken));
/// assert_eq!(rejection_reason("AF_EUR"), Some(RejectReason::LongCode));
/// assert_eq!(rejection_reason("AF_FI_M"), None);
/// ```
#[must_use]
pub fn rejection_reason(id: &str) -> Option<RejectReason> {
    let mut tokens = id.split('_');
    let Some(base) = tokens.next() else {
        return Some(RejectReason::UnknownToken);
    };
    if !matches!(base, "AF" | "AC" | "AN") {
        return Some(if id.split('_').any(|t| matches!(t, "AF" | "AC" | "AN")) {
            RejectReason::MetricNotFirst
        } else {
            RejectReason::UnknownToken
        });
    }
    let mut qualifiers = 0;
    let mut countries = 0;
    let mut sexes = 0;
    for tok in tokens {
        if parse_qualifier(tok).is_some() {
            qualifiers += 1;
        } else if is_country_code(tok) {
            countries += 1;
        } else if is_sex(tok) {
            sexes += 1;
        } else if NOT_COUNTRY_CODES.contains(&tok) {
            return Some(RejectReason::SexChromosomeToken);
        } else if !tok.is_empty() && tok.bytes().all(|b| b.is_ascii_lowercase()) {
            return Some(RejectReason::LowercaseToken);
        } else if tok.len() >= 3 && tok.bytes().all(|b| b.is_ascii_uppercase()) {
            return Some(RejectReason::LongCode);
        } else {
            return Some(RejectReason::UnknownToken);
        }
    }
    if qualifiers > 1 || countries > 1 || sexes > 1 {
        return Some(RejectReason::DuplicateToken);
    }
    if qualifiers == 1 && base != "AC" {
        return Some(RejectReason::QualifierOnAfOrAn);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each rejection class is named for the ID shapes that exercise it, and an ID that
    /// parses has no reason. Removing a class from `rejection_reason` fails the row that
    /// names it.
    #[test]
    fn rejection_reason_names_the_rule_each_shape_breaks() {
        use RejectReason::{
            DuplicateToken, LongCode, LowercaseToken, MetricNotFirst, QualifierOnAfOrAn,
            SexChromosomeToken, UnknownToken,
        };
        for (id, want) in [
            ("EUR_AF", MetricNotFirst),
            ("EAS_AF", MetricNotFirst),
            ("AF_nfe", LowercaseToken),
            ("AC_FI_raw", LowercaseToken),
            ("AF_EUR", LongCode),
            ("AC_Hom_NAN_M", LongCode),
            ("AF_XX", SexChromosomeToken),
            ("AC_XY_Hom", SexChromosomeToken),
            ("AF_EE_Het", QualifierOnAfOrAn),
            ("AN_EE_Hom", QualifierOnAfOrAn),
            ("AC_M_F", DuplicateToken),
            ("AF_FI_NL", DuplicateToken),
            ("AC_Hom_Het", DuplicateToken),
            ("AC_Hom2", UnknownToken),
            ("AF_1KG", UnknownToken),
            ("AF_", UnknownToken),
            ("NS", UnknownToken),
        ] {
            assert_eq!(rejection_reason(id), Some(want), "{id}");
            assert!(parse_info_field(id).is_none(), "{id} must not parse");
        }
        for id in ["AF", "AF_FI", "AC_Hom_EE", "AC_EE_M_Het", "AN_F"] {
            assert_eq!(
                rejection_reason(id),
                None,
                "{id} parses, so it has no reason"
            );
        }
    }

    /// The stored-label grammar is what `parse_info_field` can emit: `Total`, `M`/`F`, a
    /// country code, or `<country>_<sex>`. `XX`/`XY` are excluded at both ends, so a label
    /// the parser would never produce is one ingest warns about.
    #[test]
    fn conforming_population_labels_are_exactly_what_the_parser_emits() {
        for ok in ["Total", "M", "F", "EE", "EE_M", "NL_F"] {
            assert!(
                is_conforming_population_label(ok),
                "{ok} is emitted by build"
            );
        }
        for bad in [
            "XX", "XY", "XX_M", "ee", "EEE", "E", "EE_X", "_M", "EE_", "", "nfe",
        ] {
            assert!(
                !is_conforming_population_label(bad),
                "{bad} is never emitted by build"
            );
        }
        // Consistency with the parser: whatever it emits conforms.
        for id in ["AF", "AF_EE", "AC_EE_M", "AN_F", "AC_Hom_NL_F"] {
            let field = parse_info_field(id).expect("a conforming INFO id");
            assert!(
                is_conforming_population_label(&field.population),
                "{id} -> {} must conform",
                field.population
            );
        }
    }

    /// The `_F` and bare `F` sex suffixes must survive a grammar refactor. Other GDI
    /// consumers split the population label as `^([A-Z]{2})(_[MF])?$`, bare `[MF]`, or
    /// `Total`, and `parses_grammar` covers only the male and country side.
    #[test]
    fn population_female_sex_suffix_is_preserved() {
        assert_eq!(
            parse_info_field("AF_FI_F"),
            Some(InfoField {
                metric: Metric::Af,
                population: "FI_F".into()
            })
        );
        assert_eq!(
            parse_info_field("AF_F"),
            Some(InfoField {
                metric: Metric::Af,
                population: "F".into()
            })
        );
    }

    /// gnomAD's chromosomal-sex strata must not be published as countries.
    ///
    /// `populations` is served publicly as `gdiDatasetInfo.populations`, so accepting
    /// `XX`/`XY` would put two fake country codes on the disclosure surface.
    #[test]
    fn sex_chromosome_tokens_are_not_country_codes() {
        for id in ["AF_XX", "AC_XY", "AN_XX", "AC_XX_Hom", "AF_XY_M"] {
            assert!(
                parse_info_field(id).is_none(),
                "{id} must NOT parse: XX/XY are gnomAD sex strata, not countries — parsing \
                 them publishes a fake country code in `gdiDatasetInfo.populations`"
            );
        }
        // Real country codes are untouched, including the neighbours of the deny-list.
        for (id, pop) in [
            ("AF_EE", "EE"),
            ("AF_FI", "FI"),
            ("AF_XA", "XA"),
            ("AF_XZ", "XZ"),
            ("AF_YY", "YY"),
        ] {
            let parsed = parse_info_field(id)
                .unwrap_or_else(|| panic!("{id} is a well-formed country field and must parse"));
            assert_eq!(parsed.population, pop, "{id} must yield population {pop}");
        }
    }

    #[test]
    fn parses_grammar() {
        assert_eq!(
            parse_info_field("AF"),
            Some(InfoField {
                metric: Metric::Af,
                population: "Total".into()
            })
        );
        assert_eq!(
            parse_info_field("AF_FI"),
            Some(InfoField {
                metric: Metric::Af,
                population: "FI".into()
            })
        );
        assert_eq!(
            parse_info_field("AF_FI_M"),
            Some(InfoField {
                metric: Metric::Af,
                population: "FI_M".into()
            })
        );
        assert_eq!(
            parse_info_field("AC_M"),
            Some(InfoField {
                metric: Metric::Ac,
                population: "M".into()
            })
        );
        // qualifier before OR after the population are equivalent keys/metrics
        assert_eq!(
            parse_info_field("AC_Hom_EE"),
            Some(InfoField {
                metric: Metric::AcHom,
                population: "EE".into()
            })
        );
        assert_eq!(
            parse_info_field("AC_EE_Hom"),
            Some(InfoField {
                metric: Metric::AcHom,
                population: "EE".into()
            })
        );
        assert_eq!(
            parse_info_field("AN_FI"),
            Some(InfoField {
                metric: Metric::An,
                population: "FI".into()
            })
        );
        // non-conforming → None (ignored, warned by caller)
        assert_eq!(parse_info_field("DP"), None);
        assert_eq!(parse_info_field("AF_FI_NL"), None); // two country tokens
        assert_eq!(parse_info_field("AF_EE_Het"), None); // AF has no Het qualifier
        assert_eq!(parse_info_field("MULTI_ALLELIC"), None);
    }

    #[test]
    fn qualifier_before_or_after_with_sex_is_equivalent() {
        let want = Some(InfoField {
            metric: Metric::AcHet,
            population: "FI_M".into(),
        });
        assert_eq!(parse_info_field("AC_FI_M_Het"), want);
        assert_eq!(parse_info_field("AC_Het_FI_M"), want);
        assert_eq!(parse_info_field("AC_FI_Het_M"), want); // qualifier interleaved
    }

    #[test]
    fn hemi_and_plain_ac_variants() {
        assert_eq!(
            parse_info_field("AC_Hemi"),
            Some(InfoField {
                metric: Metric::AcHemi,
                population: "Total".into()
            })
        );
        assert_eq!(
            parse_info_field("AC_LV_F_Het"),
            Some(InfoField {
                metric: Metric::AcHet,
                population: "LV_F".into()
            })
        );
        assert_eq!(
            parse_info_field("AC"),
            Some(InfoField {
                metric: Metric::Ac,
                population: "Total".into()
            })
        );
    }

    #[test]
    fn rejects_malformed_tokens() {
        assert_eq!(parse_info_field(""), None); // empty
        assert_eq!(parse_info_field("AF_fi"), None); // lowercase country
        assert_eq!(parse_info_field("AF_FIN"), None); // 3-letter token
        assert_eq!(parse_info_field("AN_EE_Hom"), None); // AN with qualifier
        assert_eq!(parse_info_field("AC_M_F"), None); // two sex tokens
        assert_eq!(parse_info_field("AC_Hom_Het"), None); // two qualifiers
        assert_eq!(parse_info_field("NS"), None); // unknown metric
    }

    use proptest::prelude::*;

    /// A 2-uppercase-letter country code (matches `is_country_code`).
    fn country() -> impl Strategy<Value = String> {
        proptest::collection::vec(prop::sample::select(vec!['A', 'C', 'G', 'T']), 2..=2)
            .prop_map(|v| v.into_iter().collect())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// `rejection_reason` and `parse_info_field` are two walks over the same token
        /// predicates; this pins that they never disagree about whether an ID parses, over
        /// random sequences of every token kind the grammar knows and the shapes that
        /// break it.
        #[test]
        fn rejection_reason_agrees_with_the_parser(
            tokens in proptest::collection::vec(
                prop::sample::select(vec![
                    "AF", "AC", "AN", "Hom", "Het", "Hemi", "M", "F", "EE", "FI", "XX",
                    "nfe", "EUR", "raw", "Hom2", "1KG", "",
                ]),
                1..=5,
            ),
        ) {
            let id = tokens.join("_");
            prop_assert_eq!(
                rejection_reason(&id).is_some(),
                parse_info_field(&id).is_none(),
                "{}", id
            );
        }

        /// Permutation invariance: the optional tokens (a qualifier, valid only on AC, a
        /// country code, and a sex token) may appear in any order after the base, and every
        /// ordering parses to the same `InfoField`.
        #[test]
        fn permutation_invariant(
            base in prop::sample::select(vec!["AF".to_owned(), "AC".to_owned(), "AN".to_owned()]),
            with_qual in any::<bool>(),
            qual in prop::sample::select(vec!["Hom".to_owned(), "Het".to_owned(), "Hemi".to_owned()]),
            with_cc in any::<bool>(),
            cc in country(),
            with_sex in any::<bool>(),
            sx in prop::sample::select(vec!["M".to_owned(), "F".to_owned()]),
            seed in any::<u64>(),
        ) {
            // A qualifier is grammatical only on AC; on AF/AN it forces None, making a
            // permutation-of-None case trivially true, so restrict it to AC.
            let mut opts: Vec<String> = Vec::new();
            if with_qual && base == "AC" {
                opts.push(qual);
            }
            if with_cc {
                opts.push(cc);
            }
            if with_sex {
                opts.push(sx);
            }

            let canonical_id = std::iter::once(base.clone())
                .chain(opts.iter().cloned())
                .collect::<Vec<_>>()
                .join("_");
            let mut rotated = opts.clone();
            if !rotated.is_empty() {
                let k = usize::try_from(seed).unwrap_or(0) % rotated.len();
                rotated.rotate_left(k);
            }
            let rotated_id = std::iter::once(base)
                .chain(rotated)
                .collect::<Vec<_>>()
                .join("_");

            prop_assert_eq!(parse_info_field(&canonical_id), parse_info_field(&rotated_id));
        }

        /// A duplicated token class (two country codes, two sex tokens, or two qualifiers
        /// on AC) always rejects.
        #[test]
        fn duplicate_class_rejected(cc1 in country(), cc2 in country(), which in 0u8..3) {
            let id = match which {
                0 => {
                    let other = if cc1 == cc2 { "ZZ".to_owned() } else { cc2 };
                    "AC_".to_owned() + &cc1 + "_" + &other
                }
                1 => "AC_M_F".to_owned(),
                _ => "AC_Hom_Het".to_owned(),
            };
            prop_assert!(parse_info_field(&id).is_none());
        }
    }

    /// Every axis has a distinct dense index inside `0..COUNT`, so the per-axis
    /// accumulators in `beacon`'s completeness gate cannot alias.
    #[test]
    fn population_axis_indices_are_dense_and_distinct() {
        let all = [
            PopulationAxis::Sex,
            PopulationAxis::Country,
            PopulationAxis::CountrySex,
        ];
        assert_eq!(all.len(), PopulationAxis::COUNT);
        let mut seen = [false; PopulationAxis::COUNT];
        for axis in all {
            let i = axis.index();
            assert!(i < PopulationAxis::COUNT, "{axis:?} index {i} out of range");
            assert!(!seen[i], "{axis:?} aliases index {i}");
            seen[i] = true;
        }
    }

    /// [`population_axis`] discriminates `Sex` from `Country` by byte length, and
    /// `CountrySex` by the `_` join. That holds only while the token predicates the encoder
    /// is built from keep their shapes, so this constrains the predicates themselves rather
    /// than the labels they produce today. Widening `is_sex` to accept `"MALE"`, or
    /// `is_country_code` to accept a single letter, would re-classify an axis and
    /// mis-partition `beacon`'s k-anonymity completeness gate.
    ///
    /// The encoder tries `is_country_code` before `is_sex`, so a two-letter uppercase sex
    /// token could never reach the `sex` slot. The disjointness assertion pins that this
    /// precedence does not matter.
    #[test]
    fn sex_and_country_token_shapes_keep_population_axis_decodable() {
        let mut candidates: Vec<String> = Vec::new();
        for a in b'A'..=b'Z' {
            candidates.push(char::from(a).to_string());
            for b in b'A'..=b'Z' {
                candidates.push(format!("{}{}", char::from(a), char::from(b)));
            }
        }
        // Plausible widenings a future edit might reach for.
        for extra in [
            "XX", "XY", "MALE", "FEMALE", "OTHER", "FIN", "EST", "LVA", "m", "f",
        ] {
            candidates.push(extra.to_owned());
        }

        for tok in &candidates {
            assert!(
                !tok.contains('_'),
                "test bug: {tok:?} contains the ID separator"
            );
            if is_sex(tok) {
                assert_eq!(
                    tok.len(),
                    1,
                    "sex token {tok:?} is not one byte: population_axis would classify it as Country"
                );
            }
            if is_country_code(tok) {
                assert!(
                    tok.len() >= 2,
                    "country token {tok:?} is one byte: population_axis would classify it as Sex"
                );
            }
            assert!(
                !(is_sex(tok) && is_country_code(tok)),
                "token {tok:?} is both a sex and a country code; the encoder's arm order \
                 would silently decide the axis"
            );
        }
        // The aggregate key must not be mistaken for a country label.
        assert!(!is_country_code(TOTAL_POPULATION) && !is_sex(TOTAL_POPULATION));
    }

    /// The population label is an encode/decode pair spanning crates: [`parse_info_field`]
    /// writes the key, [`population_axis`] classifies it, and `beacon`'s k-anonymity
    /// completeness gate partitions the marginals on that classification. This pins the pair
    /// over every label the encoder emits today; the token-shape test above covers labels a
    /// future widening would add.
    #[test]
    fn population_axis_decodes_every_encoded_label() {
        assert_eq!(
            parse_info_field("AF"),
            Some(InfoField {
                metric: Metric::Af,
                population: TOTAL_POPULATION.to_owned(),
            }),
            "an unqualified metric must encode the aggregate key"
        );
        assert_eq!(population_axis(TOTAL_POPULATION), None);

        for s in ["M", "F"] {
            let field = parse_info_field(&format!("AF_{s}"));
            assert_eq!(field.as_ref().map(|f| f.population.as_str()), Some(s));
            assert_eq!(population_axis(s), Some(PopulationAxis::Sex), "{s}");
        }

        for a in b'A'..=b'Z' {
            for b in b'A'..=b'Z' {
                let cc = format!("{}{}", char::from(a), char::from(b));
                // The reserved sex-chromosome tokens are not countries: see
                // `NOT_COUNTRY_CODES`. Asserted explicitly below, so the exception is part
                // of this contract rather than a hole in it.
                if NOT_COUNTRY_CODES.contains(&cc.as_str()) {
                    assert!(
                        parse_info_field(&format!("AF_{cc}")).is_none(),
                        "AF_{cc} must NOT parse: {cc} is a sex stratum, not a country"
                    );
                    continue;
                }
                let country = parse_info_field(&format!("AF_{cc}"));
                assert_eq!(
                    country.as_ref().map(|f| f.population.as_str()),
                    Some(cc.as_str()),
                    "AF_{cc} must encode population {cc}"
                );
                assert_eq!(population_axis(&cc), Some(PopulationAxis::Country), "{cc}");

                for s in ["M", "F"] {
                    let key = format!("{cc}_{s}");
                    let crossed = parse_info_field(&format!("AF_{cc}_{s}"));
                    assert_eq!(
                        crossed.as_ref().map(|f| f.population.as_str()),
                        Some(key.as_str()),
                        "AF_{cc}_{s} must encode population {key}"
                    );
                    assert_eq!(
                        population_axis(&key),
                        Some(PopulationAxis::CountrySex),
                        "{key}"
                    );
                }
            }
        }
    }
}
