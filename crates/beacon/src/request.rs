//! `g_variants` request parsing, normalization, classification, and bounds.
//!
//! The request `params` are the merged
//! `query.requestParameters` (POST body) or query string (GET), represented as a
//! JSON object so a value may be a string, number, boolean, or array uniformly.
//!
//! Parsing normalizes the fields *without* deciding the query type;
//! classification inspects the arity-preserved `start`/`end` vectors to
//! pick Sequence / Range / Bracket, enforces insufficiency / unsupported-parameter
//! rejection, and applies the span bound; the pagination bounds are applied
//! separately by `apply_pagination`.

use crate::BeaconParams;
use gdi_node_standalone_core::chrom::{accession_for, accession_to_chr, strip_chr_prefix};
use gdi_node_standalone_core::variant::{is_literal_acgtn, normalize_allele};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::model::Pagination;

/// A request `params` object: the merged Beacon `requestParameters`.
pub type RequestParams = Map<String, Value>;

/// A rejection carrying the HTTP status and a public, path-free message.
///
/// The message is drawn from a small closed set of human-readable strings (it
/// never leaks internal detail) and becomes the `errorMessage` of a Beacon v2
/// `beaconErrorResponse`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BeaconReject {
    /// HTTP status code (e.g. `400`).
    pub code: u16,
    /// Human-readable, path-free message.
    pub message: String,
}

impl BeaconReject {
    /// Build a `400 Bad Request` rejection with the given public message.
    ///
    /// The message must be a path-free, public string (it becomes the wire
    /// `errorMessage`). Exposed so handlers can record and render an envelope-level 400,
    /// such as a variant query that resolves no assembly, through the same reject path as
    /// parse and classify failures.
    #[must_use]
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            code: 400,
            message: message.into(),
        }
    }
}

/// The normalized, arity-preserved query, before classification.
///
/// `start`/`end` keep the request's element count (1 or 2) because their arity
/// selects the query type in [`classify`], and `end` is never synthesized.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NormalizedQuery {
    /// Canonical chromosome label (`1`..=`22`, `X`, `Y`, `M`).
    pub reference_name: String,
    /// Arity-preserved start coordinates (1 or 2 elements).
    pub start: Vec<i64>,
    /// Arity-preserved end coordinates (0, 1, or 2 elements; never synthesized).
    pub end: Vec<i64>,
    /// Folded reference bases (`ACGTN`-only), if supplied.
    pub reference_bases: Option<String>,
    /// Folded alternate bases (`ACGTN`-only), if supplied.
    pub alternate_bases: Option<String>,
    /// Resolved assembly id (`GRCh37` / `GRCh38`), if supplied or resolved.
    pub assembly_id: Option<String>,
    /// Variant type predicate: the set of canonical labels the query selects
    /// (usually one; `INDEL` expands to `INS`/`DEL`/`DELINS`), if supplied.
    pub variant_type: Option<Vec<String>>,
    /// Minimum `len(ALT)`, if supplied.
    pub variant_min_length: Option<i64>,
    /// Maximum `len(ALT)`, if supplied.
    pub variant_max_length: Option<i64>,
    /// Case-folded granularity (`boolean` | `count` | `record`).
    pub requested_granularity: String,
    /// The raw request params, retained for classification (unsupported-param and
    /// enum checks read these directly).
    pub raw: RequestParams,
}

/// True if `chr` is a canonical chromosome label (`1`..=`22`, `X`, `Y`, `M`).
///
/// Uses the static accession table as the membership oracle: every canonical
/// label has a `GRCh38` accession, so a `Some` result means the label is known.
fn is_canonical_chr(chr: &str) -> bool {
    accession_for(chr, "GRCh38").is_some()
}

/// Normalize an `assemblyId` value to the canonical `GRCh37` / `GRCh38` labels.
///
/// Accepts the canonical labels and the common synonyms `hg19`/`b37` → `GRCh37`
/// and `hg38`/`b38` → `GRCh38`, all case-insensitively. Returns `None` for an
/// unrecognised value (the caller turns that into a `400`).
///
/// It also folds a GRC patch suffix (`.p<digits>`, such as `GRCh38.p13`, a value the Beacon
/// v2 spec lists as valid) onto the canonical stem, since a patch release shares the primary
/// assembly's coordinates.
///
/// # Examples
///
/// ```
/// use gdi_node_standalone_beacon::request::normalize_assembly;
///
/// // Synonyms and case variants all fold to the canonical label.
/// assert_eq!(normalize_assembly("hg38"), Some("GRCh38".to_string()));
/// assert_eq!(normalize_assembly("b37"), Some("GRCh37".to_string()));
/// assert_eq!(normalize_assembly("grch38"), Some("GRCh38".to_string()));
/// // An unrecognised value yields `None`.
/// assert_eq!(normalize_assembly("hg99"), None);
/// ```
#[must_use]
pub fn normalize_assembly(raw: &str) -> Option<String> {
    let t = strip_grc_patch(raw.trim());
    if t.eq_ignore_ascii_case("GRCh37")
        || t.eq_ignore_ascii_case("hg19")
        || t.eq_ignore_ascii_case("b37")
    {
        Some("GRCh37".to_owned())
    } else if t.eq_ignore_ascii_case("GRCh38")
        || t.eq_ignore_ascii_case("hg38")
        || t.eq_ignore_ascii_case("b38")
    {
        Some("GRCh38".to_owned())
    } else {
        None
    }
}

/// Strip a trailing GRC patch suffix (`.p<digits>`) from an assembly name.
///
/// `GRCh38.p13` → `GRCh38`. Only a `.p` + all-ASCII-digits suffix is removed, so a
/// versioned `RefSeq` accession (`GCF_000001405.39`, where `.39` is not a `.pN` suffix)
/// and a malformed suffix (`GRCh38.p13.extra`, `GRCh38.p`) are left intact and fall
/// through to the unrecognised (`None`) path. The patch number is not range-checked,
/// because every patch shares the stem's coordinates.
fn strip_grc_patch(t: &str) -> &str {
    if let Some((stem, patch)) = t.split_once('.')
        && let Some(digits) = patch.strip_prefix(['p', 'P'])
        && !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
    {
        return stem;
    }
    t
}

/// Fold a `referenceBases`/`alternateBases` value: trim + uppercase, then require
/// it be a non-empty `ACGTN` string.
///
/// # Examples
///
/// ```
/// use gdi_node_standalone_beacon::request::fold_bases;
///
/// # fn main() -> Result<(), gdi_node_standalone_beacon::request::BeaconReject> {
/// // Trimmed and uppercased to the canonical `ACGTN` form.
/// assert_eq!(fold_bases(" acgt ")?, "ACGT");
/// // An IUPAC ambiguity code has no `ACGTN` match and is a `400`.
/// assert_eq!(fold_bases("R").unwrap_err().code, 400);
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns a `400` [`BeaconReject`] when the folded value is empty or contains a
/// non-`ACGTN` character. IUPAC ambiguity codes are rejected, having no defined match
/// against the `ACGTN`-only store.
pub fn fold_bases(raw: &str) -> Result<String, BeaconReject> {
    let folded = normalize_allele(raw).ok_or_else(|| {
        BeaconReject::bad_request(
            "empty referenceBases/alternateBases is not supported; \
             query insertions/deletions with variantType (DEL/INS/INDEL)",
        )
    })?;
    if is_literal_acgtn(&folded) {
        Ok(folded.into_owned())
    } else {
        Err(BeaconReject::bad_request(
            "referenceBases/alternateBases must be ACGTN",
        ))
    }
}

/// Case-fold a `requestedGranularity` value to the lowercase Beacon v2 enum.
///
/// Returns `Some(folded)` for `boolean` | `count` | `record` (any case), else
/// `None`.
///
/// # Examples
///
/// ```
/// use gdi_node_standalone_beacon::request::fold_granularity;
///
/// assert_eq!(fold_granularity("RECORD"), Some("record".to_string()));
/// assert_eq!(fold_granularity("Count"), Some("count".to_string()));
/// // A value outside the enum yields `None`.
/// assert_eq!(fold_granularity("full"), None);
/// ```
#[must_use]
pub fn fold_granularity(raw: &str) -> Option<String> {
    let lower = raw.trim().to_ascii_lowercase();
    match lower.as_str() {
        "boolean" | "count" | "record" => Some(lower),
        _ => None,
    }
}

/// Read a string param, returning `None` if absent and an error if present but not
/// a JSON string.
fn str_param<'a>(params: &'a RequestParams, key: &str) -> Result<Option<&'a str>, BeaconReject> {
    match params.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.as_str())),
        Some(_) => Err(BeaconReject::bad_request(format!("{key} must be a string"))),
    }
}

/// Resolve a `variantType` query value to the set of canonical stored labels it
/// selects (`SNP` / `MNP` / `INS` / `DEL` / `DELINS`, produced by
/// `gdi_node_standalone_core::variant::classify_vt`), accepting common nomenclature
/// synonyms case-insensitively (e.g. `SNV` → `SNP`, `insertion` → `INS`,
/// `MIXED` → `DELINS`).
///
/// Most values resolve to a single label. The umbrella term `INDEL` resolves to the
/// set of all length-changing types (`INS`, `DEL`, `DELINS`): the node stores those
/// separately, which is finer than the GA4GH reference stack, whose ingestion merges
/// them into one `INDEL` label. `variantType=INDEL` therefore matches any of them, so a
/// client using the reference vocabulary still gets the expected result.
///
/// # Errors
///
/// Returns a `400` [`BeaconReject`] for any value outside the recognised set, so an
/// unsupported type is an explicit error rather than a silently-empty result.
fn normalize_variant_type(raw: &str) -> Result<Vec<String>, BeaconReject> {
    let labels: &[&str] = match raw.trim().to_ascii_uppercase().as_str() {
        "SNP" | "SNV" => &["SNP"],
        "MNP" | "MNV" => &["MNP"],
        "INS" | "INSERTION" => &["INS"],
        "DEL" | "DELETION" => &["DEL"],
        "DELINS" | "MIXED" | "COMPLEX" => &["DELINS"],
        // The umbrella indel term matches every length-changing type.
        "INDEL" => &["INS", "DEL", "DELINS"],
        _ => {
            return Err(BeaconReject::bad_request(
                "unsupported variantType (supported: SNP, MNP, INS, DEL, DELINS, INDEL)",
            ));
        }
    };
    Ok(labels.iter().map(|s| (*s).to_owned()).collect())
}

/// Parse a coordinate array param into an arity-preserved `Vec<i64>`.
///
/// Accepts a JSON array of integers, a single integer, or a comma-separated
/// string (split and parsed). An absent param yields an empty vector. Arity > 2,
/// a non-integer element, or a negative coordinate is a `400`.
fn parse_coords(params: &RequestParams, key: &str) -> Result<Vec<i64>, BeaconReject> {
    let raw = match params.get(key) {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(v) => v,
    };
    let out: Vec<i64> = match raw {
        Value::Array(arr) => arr
            .iter()
            .map(|elem| coord_from_value(elem, key))
            .collect::<Result<Vec<_>, _>>()?,
        Value::Number(_) => vec![coord_from_value(raw, key)?],
        Value::String(s) => {
            let mut v = Vec::new();
            for part in s.split(',') {
                let p = part.trim();
                if p.is_empty() {
                    return Err(BeaconReject::bad_request(format!(
                        "{key} has an empty element"
                    )));
                }
                let n: i64 = p
                    .parse()
                    .map_err(|_| BeaconReject::bad_request(format!("{key} must be integer")))?;
                v.push(check_coord_bounds(n, key)?);
            }
            v
        }
        _ => {
            return Err(BeaconReject::bad_request(format!(
                "{key} must be an array of integers"
            )));
        }
    };
    if out.len() > 2 {
        return Err(BeaconReject::bad_request(format!(
            "{key} has more than 2 elements"
        )));
    }
    Ok(out)
}

/// The maximum accepted genomic coordinate.
///
/// `POS` is stored as an `i32` in the allele-frequency parquet, so no variant can
/// carry a coordinate above [`i32::MAX`]; a request value beyond it can never match.
/// Rejecting it here bounds the file-selection work in
/// [`crate::query::select_files`], whose block span is `coord / block_range`,
/// independently of `max_query_span_bp`, which an operator may disable by setting it to
/// `0`. A single crafted Range or Bracket request therefore cannot drive an unbounded
/// block enumeration and abort the process.
const MAX_COORD: i64 = i32::MAX as i64;

/// Bound a parsed coordinate to `[0, MAX_COORD]`.
///
/// A negative coordinate is rejected (Beacon coordinates are non-negative); a value
/// above [`MAX_COORD`] (the `i32` `POS` storage ceiling) is rejected so it cannot
/// drive an unbounded `select_files` block enumeration regardless of the span cap.
fn check_coord_bounds(n: i64, key: &str) -> Result<i64, BeaconReject> {
    if n < 0 {
        return Err(BeaconReject::bad_request(format!("{key} must be >= 0")));
    }
    if n > MAX_COORD {
        return Err(BeaconReject::bad_request(format!(
            "{key} exceeds the maximum genomic coordinate"
        )));
    }
    Ok(n)
}

/// Parse one coordinate value (a non-negative, in-range integer) from a JSON value.
fn coord_from_value(v: &Value, key: &str) -> Result<i64, BeaconReject> {
    let n = v
        .as_i64()
        .ok_or_else(|| BeaconReject::bad_request(format!("{key} must be integer")))?;
    check_coord_bounds(n, key)
}

/// Validate the `variantMinLength`/`variantMaxLength` bounds.
///
/// Both bound an absolute length (`len(ALT)`), so a negative value
/// is meaningless (GA4GH `defaultSchema`: `minimum 0`) and `min > max` is a
/// contradiction that can never match. Either is a `400` rather than a silently
/// empty result.
fn check_variant_lengths(min: Option<i64>, max: Option<i64>) -> Result<(), BeaconReject> {
    if let Some(min) = min
        && min < 0
    {
        return Err(BeaconReject::bad_request("variantMinLength must be >= 0"));
    }
    if let Some(max) = max
        && max < 0
    {
        return Err(BeaconReject::bad_request("variantMaxLength must be >= 0"));
    }
    if let (Some(min), Some(max)) = (min, max)
        && min > max
    {
        return Err(BeaconReject::bad_request(
            "variantMinLength must be <= variantMaxLength",
        ));
    }
    Ok(())
}

/// Parse an optional signed-length param (`variantMinLength`/`variantMaxLength`).
fn parse_length(params: &RequestParams, key: &str) -> Result<Option<i64>, BeaconReject> {
    match params.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n
            .as_i64()
            .map(Some)
            .ok_or_else(|| BeaconReject::bad_request(format!("{key} must be integer"))),
        Some(Value::String(s)) => s
            .trim()
            .parse::<i64>()
            .map(Some)
            .map_err(|_| BeaconReject::bad_request(format!("{key} must be integer"))),
        Some(_) => Err(BeaconReject::bad_request(format!("{key} must be integer"))),
    }
}

/// Parse and normalize the `g_variants` request parameters.
///
/// Normalizes `referenceName` (chr-prefix strip / accession resolution),
/// `start`/`end` (arity preserved; `end` never synthesized), `assemblyId`
/// (synonyms resolved), `referenceBases`/`alternateBases` (folded to `ACGTN`),
/// and `requestedGranularity` (case-folded; defaulted from `cfg` if omitted). It
/// does not classify the query; see [`classify`].
///
/// # Examples
///
/// ```
/// use gdi_node_standalone_beacon::request::parse_request;
/// use gdi_node_standalone_beacon::BeaconParams;
/// use serde_json::json;
///
/// # fn main() -> Result<(), gdi_node_standalone_beacon::request::BeaconReject> {
/// let cfg = BeaconParams::default();
/// let params = json!({ "referenceName": "chr3", "assemblyId": "hg38" })
///     .as_object()
///     .expect("a JSON object")
///     .clone();
///
/// let q = parse_request(&params, &cfg)?;
/// assert_eq!(q.reference_name, "3"); // chr-prefix stripped
/// assert_eq!(q.assembly_id.as_deref(), Some("GRCh38")); // synonym resolved
/// assert_eq!(q.requested_granularity, "record"); // defaulted from config
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns a `400` [`BeaconReject`] for malformed input: a non-string where a
/// string is required, a chromosome outside `1`..=`22`|`X`|`Y`|`M`, an
/// accession that contradicts a supplied `assemblyId`, an unknown assembly, a
/// non-`ACGTN` allele, a bad granularity, or an over-arity / non-integer
/// coordinate.
pub fn parse_request(
    params: &RequestParams,
    cfg: &BeaconParams,
) -> Result<NormalizedQuery, BeaconReject> {
    // assemblyId (normalized first so referenceName accession resolution can cross-check).
    let assembly_from_param = match str_param(params, "assemblyId")? {
        Some(raw) => Some(
            normalize_assembly(raw)
                .ok_or_else(|| BeaconReject::bad_request("unknown assemblyId"))?,
        ),
        None => None,
    };

    // referenceName: accession resolution or chr-prefix strip + canonical check.
    let (reference_name, assembly_id) = match str_param(params, "referenceName")? {
        Some(raw) => resolve_reference_name(raw, assembly_from_param)?,
        None => (String::new(), assembly_from_param),
    };

    let start = parse_coords(params, "start")?;
    let end = parse_coords(params, "end")?;

    let reference_bases = str_param(params, "referenceBases")?
        .map(fold_bases)
        .transpose()?;
    let alternate_bases = str_param(params, "alternateBases")?
        .map(fold_bases)
        .transpose()?;

    let variant_type = str_param(params, "variantType")?
        .map(normalize_variant_type)
        .transpose()?;
    let variant_min_length = parse_length(params, "variantMinLength")?;
    let variant_max_length = parse_length(params, "variantMaxLength")?;
    check_variant_lengths(variant_min_length, variant_max_length)?;

    let requested_granularity = match str_param(params, "requestedGranularity")? {
        Some(raw) => fold_granularity(raw)
            .ok_or_else(|| BeaconReject::bad_request("unknown requestedGranularity"))?,
        None => cfg.default_granularity.clone(),
    };

    Ok(NormalizedQuery {
        reference_name,
        start,
        end,
        reference_bases,
        alternate_bases,
        assembly_id,
        variant_type,
        variant_min_length,
        variant_max_length,
        requested_granularity,
        raw: params.clone(),
    })
}

/// Resolve `referenceName` to `(chromosome, assembly)`.
///
/// If `raw` is a `RefSeq` accession, it resolves to both a chromosome and an
/// assembly; when an `assemblyId` was also supplied the two must agree, and a
/// disagreement is a `400` rather than a silent overwrite. Otherwise `raw` is treated
/// as a (possibly `chr`-prefixed) chromosome label and validated against the
/// canonical set.
fn resolve_reference_name(
    raw: &str,
    assembly_from_param: Option<String>,
) -> Result<(String, Option<String>), BeaconReject> {
    if let Some((chr, acc_assembly)) = accession_to_chr(raw) {
        if let Some(ref given) = assembly_from_param
            && given != acc_assembly
        {
            return Err(BeaconReject::bad_request(
                "referenceName accession contradicts assemblyId",
            ));
        }
        return Ok((chr.to_owned(), Some(acc_assembly.to_owned())));
    }

    let stripped = strip_chr_prefix(raw).to_ascii_uppercase();
    let label = if stripped == "MT" {
        "M".to_owned()
    } else {
        stripped
    };
    if is_canonical_chr(&label) {
        Ok((label, assembly_from_param))
    } else {
        Err(BeaconReject::bad_request("unsupported referenceName"))
    }
}

/// Optional row predicates carried by a range/bracket query.
///
/// A present `referenceBases`/`alternateBases` adds `REF ==`/`ALT ==`;
/// `variant_type` adds `VT ∈ set`, the labels the query selects: one of
/// `SNP`, `MNP`, `INS`, `DEL` or `DELINS`, or the `INS`/`DEL`/`DELINS` set for `INDEL`.
/// The length bounds constrain `len(ALT)`.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Predicates {
    /// Optional `REF ==` predicate.
    pub ref_: Option<String>,
    /// Optional `ALT ==` predicate.
    pub alt: Option<String>,
    /// Optional `VT ∈ set` predicate: the canonical labels the query selects
    /// (`SNP`/`MNP`/`INS`/`DEL`/`DELINS`; `INDEL` selects `INS`/`DEL`/`DELINS`).
    pub variant_type: Option<Vec<String>>,
    /// Optional lower bound on `len(ALT)`.
    pub min_len: Option<i64>,
    /// Optional upper bound on `len(ALT)`.
    pub max_len: Option<i64>,
}

/// The classified query shape.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum QueryKind {
    /// Exact-match: `POS == pos AND REF == ref_ AND ALT == alt`.
    Sequence {
        /// The exact `POS`.
        pos: i64,
        /// The exact `REF`.
        ref_: String,
        /// The exact `ALT`.
        alt: String,
        /// Optional row predicates. The exact match already pins `REF` and `ALT`, so only
        /// the `variantType` and length bounds add constraints. They are applied, so a
        /// submitted filter is honoured on the exact-allele shape as it is on the Range and
        /// Bracket shapes.
        predicates: Predicates,
    },
    /// Half-open overlap: `v_start < end AND v_end > start`.
    Range {
        /// Window start (`start[0]`).
        start: i64,
        /// Window end (`end[0]`).
        end: i64,
        /// Optional row predicates.
        predicates: Predicates,
    },
    /// Bracketed: `s_min <= v_start <= s_max AND e_min <= v_end <= e_max`.
    Bracket {
        /// `start[0]`.
        s_min: i64,
        /// `start[1]`.
        s_max: i64,
        /// `end[0]`.
        e_min: i64,
        /// `end[1]`.
        e_max: i64,
        /// Optional row predicates.
        predicates: Predicates,
    },
    /// No variant parameters at all. The caller returns `200` with empty `resultSets`,
    /// which is not an error.
    Empty,
}

/// Unsupported request parameters that make a query insufficient (`400`).
const UNSUPPORTED_PARAMS: &[&str] = &[
    "geneId",
    "mateName",
    "aminoacidChange",
    "genomicAlleleShortForm",
];

/// Reject a query carrying any non-empty `filters` selector.
///
/// The aggregated allele-frequency beacon advertises no filtering terms
/// (`/filtering_terms` is empty), so it cannot honour a `filters` selector. Silently
/// ignoring one would return an unfiltered result the caller believes was narrowed, which
/// is a disclosure hazard, so it is a `400`, consistent with the other unsupported-parameter
/// rejections.
///
/// A `filters` value can arrive in several JSON shapes. A POST body carries an array, or a
/// scalar or object when malformed; a GET query string carries every value as a plain
/// string, and a comma-separated `?filters=…` is a legitimate GA4GH Beacon v2 shape. Every
/// present, non-null, non-empty value is therefore rejected, not only a non-empty array:
/// checking the array shape alone is a no-op on the GET string form and drops the filter
/// silently. An absent, `null` or empty value is a no-op (`Ok`).
///
/// Applied only on the aggregated `g_variants` path. The sensitive `individuals`
/// placeholder serves no data and does not reject, being the future home of real filter
/// handling.
///
/// # Errors
///
/// Returns a `400` [`BeaconReject`] when `params` carries a non-empty `filters` value.
pub fn reject_unsupported_filters(params: &RequestParams) -> Result<(), BeaconReject> {
    let carries_filter = match params.get("filters") {
        None | Some(Value::Null) => false,
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
        // A bare scalar (number / bool) is not a valid empty sentinel, so treat any
        // present one as a filter attempt.
        Some(Value::Bool(_) | Value::Number(_)) => true,
    };
    if carries_filter {
        return Err(BeaconReject::bad_request(
            "filters are not supported: this beacon advertises no filtering terms (see /filtering_terms)",
        ));
    }
    Ok(())
}

/// The `includeResultsetResponses` envelope enum (Beacon v2; default `HIT`).
///
/// [`assemble`](crate::query::assemble) materializes one resultSet per considered dataset,
/// a hit or an `exists:false` miss, and this selector filters that view afterwards (see
/// [`crate::query::apply_include_resultset_responses`]).
// `Serialize` exists so `receivedRequestSummary` can echo the applied value as the
// enum itself rather than a `String`: the vendored `IncludeResultsetResponses` `$def`
// admits exactly four members and no `null`, so a stringly-typed echo could emit a value
// the node's own `beacon_schema_conformance` gate rejects, while this type cannot.
// `UPPERCASE` is the wire spelling those four members carry in the `$def`'s `enum`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "UPPERCASE")]
#[non_exhaustive]
pub enum IncludeResultsetResponses {
    /// Return every considered dataset: hits and `exists:false` misses.
    All,
    /// Return only the matching (hit) per-dataset result sets. The default.
    #[default]
    Hit,
    /// Return only the non-matching (`exists:false`) per-dataset result sets.
    Miss,
    /// Return an empty `resultSets`. The `response` member is kept and empty, which
    /// `beaconResultsetsResponse` requires at `record` granularity.
    None,
}

/// Parse the `includeResultsetResponses` request param into its enum.
///
/// Absent / `null` defaults to [`IncludeResultsetResponses::Hit`]. The value is
/// validated identically to `check_envelope` (it is also enforced there), so a
/// classified request is guaranteed parseable here.
///
/// # Errors
///
/// Returns a `400` [`BeaconReject`] when the value is present but not a string, or
/// is a string outside the `{all, HIT, MISS, NONE}` enum.
pub fn parse_include_resultset_responses(
    params: &RequestParams,
) -> Result<IncludeResultsetResponses, BeaconReject> {
    match params.get("includeResultsetResponses") {
        None | Some(Value::Null) => Ok(IncludeResultsetResponses::Hit),
        Some(v) => {
            let s = v.as_str().ok_or_else(|| {
                BeaconReject::bad_request("includeResultsetResponses must be a string")
            })?;
            match s {
                "ALL" => Ok(IncludeResultsetResponses::All),
                "HIT" => Ok(IncludeResultsetResponses::Hit),
                "MISS" => Ok(IncludeResultsetResponses::Miss),
                "NONE" => Ok(IncludeResultsetResponses::None),
                _ => Err(BeaconReject::bad_request(
                    "includeResultsetResponses outside the allowed enum",
                )),
            }
        }
    }
}

/// The requested dataset scope from a `datasetIds` request field: [`None`] when the field
/// is absent (meaning "all visible datasets"), `Some(ids)` when one was submitted.
///
/// GA4GH clients place `datasetIds` under `query` (a sibling of `requestParameters`) or inside
/// `requestParameters`; both reach the merged [`RequestParams`]. Accepts a JSON array of
/// strings (POST) or a comma-separated string (the GET query-string form, mirroring how
/// `start`/`end` accept a comma string). Parsing is lenient: a non-string element or a
/// wrong-typed value is skipped rather than rejected. Blank entries are dropped.
///
/// Absent and present-but-unresolvable must not collapse to the same value. Returning a bare
/// `Vec` would collapse them, because the caller reads "no ids" as "no scope filter", so
/// `datasetIds: []`, `[null]`, `[7]`, `true` and `""` would each widen the query to every
/// visible dataset instead of narrowing it to none. That is the false affirmation the scope
/// exists to prevent, and it is invisible at `boolean`/`count` granularity, where the
/// per-dataset resultSets are dropped and only the OR-ed `exists` survives, so the client
/// cannot tell the hit came from a dataset it never asked about. A submitted-but-empty scope
/// therefore yields `Some(vec![])`, which selects nothing.
#[must_use]
pub fn parse_dataset_ids(params: &RequestParams) -> Option<Vec<String>> {
    let value = match params.get("datasetIds") {
        None | Some(Value::Null) => return None,
        Some(value) => value,
    };
    Some(match value {
        Value::Array(items) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect(),
        Value::String(s) => s
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect(),
        // Present but not a shape that can carry ids (bool / number / object): a scope was
        // requested and none of it resolved, so it selects nothing.
        _ => Vec::new(),
    })
}

/// Build the optional range/bracket predicates from the normalized query.
fn predicates_of(q: &NormalizedQuery) -> Predicates {
    Predicates {
        ref_: q.reference_bases.clone(),
        alt: q.alternate_bases.clone(),
        variant_type: q.variant_type.clone(),
        min_len: q.variant_min_length,
        max_len: q.variant_max_length,
    }
}

/// True when the request carries any variant-selecting parameter.
///
/// `assemblyId`, granularity, pagination, `includeResultsetResponses`, and
/// `testMode` are envelope parameters, not variant selectors, so they do not
/// count.
fn has_variant_params(q: &NormalizedQuery) -> bool {
    !q.reference_name.is_empty()
        || !q.start.is_empty()
        || !q.end.is_empty()
        || q.reference_bases.is_some()
        || q.alternate_bases.is_some()
        || q.variant_type.is_some()
        || q.variant_min_length.is_some()
        || q.variant_max_length.is_some()
}

/// Reject a query carrying any unsupported (`UNSUPPORTED_PARAMS`) variant selector (`400`).
///
/// Shared by the `g_variants` envelope check and the `datasets` collection handler so
/// an unsupported selector (`geneId`, `mateName`, …) is a consistent `400` on every
/// entry type rather than a silently-ignored `200` on one of them.
///
/// # Errors
///
/// Returns a `400` [`BeaconReject`] naming the first present, non-null unsupported
/// parameter.
pub fn reject_unsupported_params(params: &RequestParams) -> Result<(), BeaconReject> {
    for key in UNSUPPORTED_PARAMS {
        // Only a present, non-null value is an unsupported selector. A `null`, which a
        // client that serializes every optional field will send, carries no selector and
        // must not trip the rejection. The rest of the parser treats `null` as absent too.
        if matches!(params.get(*key), Some(v) if !v.is_null()) {
            return Err(BeaconReject::bad_request(format!(
                "unsupported parameter: {key}"
            )));
        }
    }
    Ok(())
}

/// Validate the request envelope: reject unsupported params, a non-boolean
/// `testMode`, and an out-of-enum `includeResultsetResponses`.
///
/// Applied before the empty / shape classification so a request carrying only an
/// unsupported parameter is a `400`, not `Empty`.
fn check_envelope(q: &NormalizedQuery) -> Result<(), BeaconReject> {
    reject_unsupported_params(&q.raw)?;
    check_envelope_params(&q.raw)
}

/// Validate the three Beacon envelope fields every entry type shares, independent of the
/// query normalization: `testMode`, `includeResultsetResponses` and `requestedGranularity`.
///
/// Separate from the private `check_envelope`, which takes a `NormalizedQuery` that only a
/// variant query produces, so `/datasets` can apply the same checks `g_variants` and
/// `/individuals` get. `docs/api.md` promises a `400` for all three unconditionally.
///
/// # Errors
/// [`BeaconReject`] `400` for a non-boolean `testMode`, an out-of-enum
/// `includeResultsetResponses`, or an unknown `requestedGranularity`.
pub fn check_envelope_params(params: &RequestParams) -> Result<(), BeaconReject> {
    // `testMode` may arrive as a JSON bool in a POST body, or as a string in a GET query,
    // where every value is a string (`?testMode=false`). Validate it is a
    // boolean, so a non-boolean is a `400`, but accept both `true` and `false`: Beacon
    // v2 mandates that the beacon respond to a testMode request, and this all-public
    // aggregate beacon holds no sensitive data, so testMode is a no-op that is echoed
    // back (see `echo_received_request`) rather than acted on.
    testmode_flag(params.get("testMode"))?;

    // Validate `includeResultsetResponses` (the parsed value is read in the handler
    // via `parse_include_resultset_responses`; this rejects an out-of-enum value).
    parse_include_resultset_responses(params)?;

    // The same rejection the variant path applies while normalizing (`unknown
    // requestedGranularity`), stated once so the two cannot drift.
    if let Some(raw) = str_param(params, "requestedGranularity")? {
        fold_granularity(raw)
            .ok_or_else(|| BeaconReject::bad_request("unknown requestedGranularity"))?;
    }

    Ok(())
}

/// Interpret a `testMode` envelope value as an optional bool.
///
/// Accepts a JSON bool or the string forms `"true"`/`"false"` (case-insensitive,
/// trimmed), so a GET query, whose values are all strings, behaves identically to a POST
/// body. Returns `Ok(None)` when absent or null, and a `400` for any other value.
///
/// Exposed so the audit layer records `testMode` with the same interpretation the envelope
/// validation uses, rather than a stricter JSON-bool-only read that would misreport a GET
/// `?testMode=true`.
///
/// # Errors
///
/// Returns a `400` [`BeaconReject`] when the value is present but not a bool or a
/// `"true"`/`"false"` string.
pub fn testmode_flag(value: Option<&Value>) -> Result<Option<bool>, BeaconReject> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(Value::String(s)) => match s.trim().to_ascii_lowercase().as_str() {
            "true" => Ok(Some(true)),
            "false" => Ok(Some(false)),
            _ => Err(BeaconReject::bad_request("testMode must be a boolean")),
        },
        Some(_) => Err(BeaconReject::bad_request("testMode must be a boolean")),
    }
}

/// Enforce the range/bracket span cap (`max_query_span_bp`; `0` = unlimited).
///
/// Sequence queries are exempt. The bracket span is measured across the full
/// reachable extent `s_min..e_max`.
fn check_span(span: i64, cfg: &BeaconParams) -> Result<(), BeaconReject> {
    let cap = cfg.max_query_span_bp;
    // A non-positive span (degenerate / inverted window) can never exceed a cap;
    // `try_from` fails for negatives, so it short-circuits safely.
    if cap > 0
        && let Ok(span) = u64::try_from(span)
        && span > cap
    {
        return Err(BeaconReject::bad_request("query span exceeds the limit"));
    }
    Ok(())
}

/// Classify a normalized query into a [`QueryKind`] and enforce insufficiency,
/// unsupported-parameter, envelope, and span bounds.
///
/// # Examples
///
/// ```
/// use gdi_node_standalone_beacon::request::{classify, parse_request, QueryKind};
/// use gdi_node_standalone_beacon::BeaconParams;
/// use serde_json::json;
///
/// # fn main() -> Result<(), gdi_node_standalone_beacon::request::BeaconReject> {
/// let cfg = BeaconParams::default();
///
/// // A `start` + `end` pair classifies as a half-open Range query.
/// let params = json!({ "referenceName": "1", "start": [100], "end": [200] })
///     .as_object()
///     .expect("a JSON object")
///     .clone();
/// let q = parse_request(&params, &cfg)?;
/// std::assert_matches!(classify(&q, &cfg)?, QueryKind::Range { start: 100, end: 200, .. });
///
/// // An empty request is not an error: it is `QueryKind::Empty`.
/// let empty = parse_request(&serde_json::Map::new(), &cfg)?;
/// std::assert_matches!(classify(&empty, &cfg)?, QueryKind::Empty);
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns a `400` [`BeaconReject`] for an unsupported parameter
/// (`geneId`/`mateName`/`aminoacidChange`/`genomicAlleleShortForm`), a non-boolean
/// `testMode`, an out-of-enum `includeResultsetResponses`, a coordinate
/// shape that matches none of Sequence/Range/Bracket, or a range/bracket span
/// over `cfg.max_query_span_bp`. A request with no variant parameters at all is
/// not an error: it returns [`QueryKind::Empty`].
pub fn classify(q: &NormalizedQuery, cfg: &BeaconParams) -> Result<QueryKind, BeaconReject> {
    check_envelope(q)?;

    if !has_variant_params(q) {
        return Ok(QueryKind::Empty);
    }

    // From here a variant selector is present, so a referenceName is required.
    if q.reference_name.is_empty() {
        return Err(BeaconReject::bad_request(
            "insufficient query: missing referenceName",
        ));
    }

    match (q.start.as_slice(), q.end.as_slice()) {
        // Sequence: start(1) + referenceBases + alternateBases, no end.
        ([pos], []) => {
            let (Some(ref_), Some(alt)) = (&q.reference_bases, &q.alternate_bases) else {
                return Err(BeaconReject::bad_request(
                    "insufficient query: sequence needs referenceBases and alternateBases",
                ));
            };
            Ok(QueryKind::Sequence {
                pos: *pos,
                ref_: ref_.clone(),
                alt: alt.clone(),
                predicates: predicates_of(q),
            })
        }
        // Range: start(1) + end(1).
        ([start], [end]) => {
            // Reject an inverted window: `start > end` is contradictory input that the
            // overlap predicate (`v_start < end AND v_end > start`) would otherwise
            // turn into misleading gap-spanning matches rather than a clear 400.
            if *start > *end {
                return Err(BeaconReject::bad_request("range start must be <= end"));
            }
            check_span(end - start, cfg)?;
            Ok(QueryKind::Range {
                start: *start,
                end: *end,
                predicates: predicates_of(q),
            })
        }
        // Bracket: start(2) + end(2).
        ([s_min, s_max], [e_min, e_max]) => {
            // Reject a contradictory bracket: each sub-range must be ordered
            // (`s_min <= s_max`, `e_min <= e_max`) and the start interval must not lie
            // entirely past the latest possible end (`s_min <= e_max`), else the
            // bracket is unsatisfiable / inverted and would return a silent empty set.
            if *s_min > *s_max || *e_min > *e_max || *s_min > *e_max {
                return Err(BeaconReject::bad_request(
                    "bracket coordinates must satisfy s_min <= s_max, e_min <= e_max, and s_min <= e_max",
                ));
            }
            check_span(e_max - s_min, cfg)?;
            Ok(QueryKind::Bracket {
                s_min: *s_min,
                s_max: *s_max,
                e_min: *e_min,
                e_max: *e_max,
                predicates: predicates_of(q),
            })
        }
        _ => Err(BeaconReject::bad_request(
            "insufficient query: unsupported coordinate shape",
        )),
    }
}

/// Apply pagination defaulting and clamping (Response bound).
///
/// `skip` defaults to `0`; `limit` defaults to `cfg.default_page_limit` when the
/// request omits it. An explicit `limit: 0` is Beacon v2's unbounded sentinel and is
/// treated as the maximum and then clamped, never as "return nothing". Every explicit
/// `limit` is clamped to `cfg.max_page_limit`, so the public endpoint never assembles an
/// unbounded result set.
///
/// # Examples
///
/// ```
/// use gdi_node_standalone_beacon::request::apply_pagination;
/// use gdi_node_standalone_beacon::BeaconParams;
///
/// // Defaults: default_page_limit 10, max_page_limit 1000.
/// let cfg = BeaconParams::default();
///
/// // Omitted values default (skip 0, limit = default_page_limit).
/// let p = apply_pagination(None, None, &cfg);
/// assert_eq!((p.skip, p.limit), (0, 10));
///
/// // The GDI User Portal's 1000-row range page is served whole, not clamped.
/// assert_eq!(apply_pagination(None, Some(1000), &cfg).limit, 1000);
///
/// // An over-cap limit is clamped, and `limit: 0` (the Beacon "unbounded"
/// // sentinel) is treated as the cap, never as "return nothing".
/// assert_eq!(apply_pagination(None, Some(5000), &cfg).limit, 1000);
/// assert_eq!(apply_pagination(None, Some(0), &cfg).limit, 1000);
/// ```
#[must_use]
pub fn apply_pagination(
    req_skip: Option<u64>,
    req_limit: Option<u64>,
    cfg: &BeaconParams,
) -> Pagination {
    // `skip` is not clamped: it selects a window into an already-scanned result set, so a
    // huge value costs no more than a small one, because the scan runs and dominates
    // either way, and it yields an empty page.
    let skip = req_skip.unwrap_or(0);
    let requested = match req_limit {
        Some(0) => cfg.max_page_limit, // 0 = unbounded -> clamp to the cap.
        Some(l) => l,
        None => cfg.default_page_limit,
    };
    let limit = requested.min(cfg.max_page_limit);
    Pagination { skip, limit }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;

    fn cfg() -> BeaconParams {
        BeaconParams::default()
    }

    fn raw_with(key: &str, value: &str) -> RequestParams {
        let mut m = Map::new();
        m.insert(key.to_owned(), Value::String(value.to_owned()));
        m
    }

    #[test]
    fn normalizes_request_fields() {
        let q = parse_request(&raw_with("referenceName", "chr3"), &cfg()).unwrap();
        assert_eq!(q.reference_name, "3");
        assert_eq!(normalize_assembly("hg38"), Some("GRCh38".into()));
        assert_eq!(fold_bases(" a ").unwrap(), "A");
        assert!(fold_bases("R").is_err()); // IUPAC ambiguity rejected
        assert_eq!(fold_granularity("RECORD"), Some("record".into()));
    }

    #[test]
    fn reject_unsupported_filters_rejects_non_empty_only() {
        // A non-empty `filters` array is a 400 (this beacon advertises no filtering terms).
        let mut with_filter = Map::new();
        with_filter.insert(
            "filters".to_owned(),
            Value::Array(vec![serde_json::json!({ "id": "NCIT:C20197" })]),
        );
        assert!(reject_unsupported_filters(&with_filter).is_err());

        // Absent, null and empty-array `filters` are all no-ops, indistinguishable from no
        // filter submitted.
        assert!(reject_unsupported_filters(&Map::new()).is_ok());
        let mut null_filter = Map::new();
        null_filter.insert("filters".to_owned(), Value::Null);
        assert!(reject_unsupported_filters(&null_filter).is_ok());
        let mut empty_filter = Map::new();
        empty_filter.insert("filters".to_owned(), Value::Array(vec![]));
        assert!(reject_unsupported_filters(&empty_filter).is_ok());
    }

    #[test]
    fn reject_unsupported_filters_rejects_get_string_and_scalar_forms() {
        // On GET every query value arrives as a plain String, so a `?filters=...` term is a
        // non-empty String rather than an array. An array-only guard is a silent no-op on
        // it, dropping the filter and returning an unnarrowed 200. It must be a 400.
        assert!(reject_unsupported_filters(&raw_with("filters", "NCIT:C20197")).is_err());
        // An empty string is a no-op, indistinguishable from no filter submitted.
        assert!(reject_unsupported_filters(&raw_with("filters", "")).is_ok());
        // A bare scalar (number / bool) present is also treated as an unsupported filter.
        let mut scalar = Map::new();
        scalar.insert("filters".to_owned(), serde_json::json!(1));
        assert!(reject_unsupported_filters(&scalar).is_err());
        // A non-empty object form is rejected too.
        let mut obj = Map::new();
        obj.insert("filters".to_owned(), serde_json::json!({ "id": "x" }));
        assert!(reject_unsupported_filters(&obj).is_err());
    }

    #[test]
    fn assembly_synonyms_resolve() {
        assert_eq!(normalize_assembly("hg19"), Some("GRCh37".into()));
        assert_eq!(normalize_assembly("B38"), Some("GRCh38".into()));
        assert_eq!(normalize_assembly("grch37"), Some("GRCh37".into()));
        assert_eq!(normalize_assembly("nonsense"), None);
    }

    #[test]
    fn assembly_patch_versions_fold_to_canonical_stem() {
        // The Beacon v2 spec lists `GRCh38.p13` as a valid assemblyId. A patch release
        // shares the primary-assembly coordinates, so it folds to the canonical stem.
        assert_eq!(normalize_assembly("GRCh38.p13"), Some("GRCh38".into()));
        assert_eq!(normalize_assembly("grch38.P14"), Some("GRCh38".into()));
        assert_eq!(normalize_assembly("GRCh37.p13"), Some("GRCh37".into()));
        // The patch number is not range-checked, since every patch shares coordinates.
        assert_eq!(normalize_assembly("GRCh38.p999"), Some("GRCh38".into()));
        // A versioned RefSeq accession is not a `.pN` suffix, so it stays unhandled
        // (`None`) rather than being mangled by dot-splitting.
        assert_eq!(normalize_assembly("GCF_000001405.39"), None);
        // A malformed patch suffix is not stripped.
        assert_eq!(normalize_assembly("GRCh38.p13.extra"), None);
        assert_eq!(normalize_assembly("GRCh38.p"), None);
    }

    #[test]
    fn empty_and_iupac_bases_rejected() {
        // An empty base (the spec's trimmed-indel form) is a 400 whose message points
        // the client at the supported way to query indels (`variantType`), rather than
        // the reference's misleading silent `exists: false`.
        let empty = fold_bases("").unwrap_err();
        assert_eq!(empty.code, 400);
        assert!(
            empty.message.contains("variantType"),
            "empty-base rejection should redirect to variantType, got: {}",
            empty.message
        );
        assert!(fold_bases("   ").is_err());
        // An IUPAC ambiguity code is a 400 naming the accepted `ACGTN` set.
        let iupac = fold_bases("Y").unwrap_err();
        assert_eq!(iupac.code, 400);
        assert!(iupac.message.contains("ACGTN"), "got: {}", iupac.message);
        assert_eq!(fold_bases("acgtn").unwrap(), "ACGTN");
    }

    #[test]
    fn granularity_defaults_from_config() {
        let q = parse_request(&Map::new(), &cfg()).unwrap();
        assert_eq!(q.requested_granularity, "record");
        let q2 = parse_request(&raw_with("requestedGranularity", "Count"), &cfg()).unwrap();
        assert_eq!(q2.requested_granularity, "count");
    }

    #[test]
    fn accession_disagreeing_with_assembly_is_400() {
        let mut m = Map::new();
        m.insert(
            "referenceName".to_owned(),
            Value::String("NC_000011.10".to_owned()), // GRCh38 chr11
        );
        m.insert("assemblyId".to_owned(), Value::String("GRCh37".to_owned()));
        let err = parse_request(&m, &cfg()).unwrap_err();
        assert_eq!(err.code, 400);
    }

    #[test]
    fn accession_resolves_chr_and_assembly() {
        let q = parse_request(&raw_with("referenceName", "NC_000011.10"), &cfg()).unwrap();
        assert_eq!(q.reference_name, "11");
        assert_eq!(q.assembly_id.as_deref(), Some("GRCh38"));
    }

    #[test]
    fn end_is_never_synthesized() {
        let mut m = raw_with("referenceName", "1");
        m.insert("start".to_owned(), Value::Array(vec![Value::from(100)]));
        m.insert("referenceBases".to_owned(), Value::String("A".to_owned()));
        m.insert("alternateBases".to_owned(), Value::String("T".to_owned()));
        let q = parse_request(&m, &cfg()).unwrap();
        assert_eq!(q.start, vec![100]);
        assert!(q.end.is_empty()); // not auto-filled
    }

    #[test]
    fn coords_parse_array_and_csv_and_reject_over_arity() {
        let mut m = raw_with("referenceName", "1");
        m.insert("start".to_owned(), Value::String("100,200".to_owned()));
        let q = parse_request(&m, &cfg()).unwrap();
        assert_eq!(q.start, vec![100, 200]);

        let mut m3 = raw_with("referenceName", "1");
        m3.insert(
            "start".to_owned(),
            Value::Array(vec![Value::from(1), Value::from(2), Value::from(3)]),
        );
        assert_eq!(parse_request(&m3, &cfg()).unwrap_err().code, 400);
    }

    #[test]
    fn chromosome_outside_canonical_is_400() {
        assert_eq!(
            parse_request(&raw_with("referenceName", "23"), &cfg())
                .unwrap_err()
                .code,
            400
        );
        // MT folds to M and is accepted.
        let q = parse_request(&raw_with("referenceName", "MT"), &cfg()).unwrap();
        assert_eq!(q.reference_name, "M");
    }

    // ---- classification + bounds ----

    fn seq_query() -> NormalizedQuery {
        let mut m = raw_with("referenceName", "1");
        m.insert("start".to_owned(), Value::Array(vec![Value::from(100)]));
        m.insert("referenceBases".to_owned(), Value::String("A".to_owned()));
        m.insert("alternateBases".to_owned(), Value::String("T".to_owned()));
        parse_request(&m, &cfg()).unwrap()
    }

    fn range_query() -> NormalizedQuery {
        let mut m = raw_with("referenceName", "1");
        m.insert("start".to_owned(), Value::Array(vec![Value::from(100)]));
        m.insert("end".to_owned(), Value::Array(vec![Value::from(200)]));
        parse_request(&m, &cfg()).unwrap()
    }

    fn bracket_query() -> NormalizedQuery {
        let mut m = raw_with("referenceName", "1");
        m.insert(
            "start".to_owned(),
            Value::Array(vec![Value::from(100), Value::from(150)]),
        );
        m.insert(
            "end".to_owned(),
            Value::Array(vec![Value::from(200), Value::from(250)]),
        );
        parse_request(&m, &cfg()).unwrap()
    }

    fn empty_query() -> NormalizedQuery {
        parse_request(&Map::new(), &cfg()).unwrap()
    }

    fn with_param(key: &str, value: &str) -> NormalizedQuery {
        // Attach the param to an otherwise-valid range query.
        let mut m = raw_with("referenceName", "1");
        m.insert("start".to_owned(), Value::Array(vec![Value::from(100)]));
        m.insert("end".to_owned(), Value::Array(vec![Value::from(200)]));
        m.insert(key.to_owned(), Value::String(value.to_owned()));
        parse_request(&m, &cfg()).unwrap()
    }

    fn with_bool(key: &str, value: bool) -> NormalizedQuery {
        let mut m = raw_with("referenceName", "1");
        m.insert("start".to_owned(), Value::Array(vec![Value::from(100)]));
        m.insert("end".to_owned(), Value::Array(vec![Value::from(200)]));
        m.insert(key.to_owned(), Value::Bool(value));
        parse_request(&m, &cfg()).unwrap()
    }

    #[test]
    fn classification_matrix() {
        std::assert_matches!(
            classify(&seq_query(), &cfg()),
            Ok(QueryKind::Sequence { .. })
        );
        std::assert_matches!(
            classify(&range_query(), &cfg()),
            Ok(QueryKind::Range { .. })
        );
        std::assert_matches!(
            classify(&bracket_query(), &cfg()),
            Ok(QueryKind::Bracket { .. })
        );
        assert_eq!(
            classify(&with_param("geneId", "X"), &cfg())
                .unwrap_err()
                .code,
            400
        );
        // `testMode:true` is accepted, because Beacon v2 mandates a response. See
        // `testmode_true_and_false_are_both_accepted`.
        assert_eq!(
            classify(&with_param("includeResultsetResponses", "WRONG"), &cfg())
                .unwrap_err()
                .code,
            400
        );
        for v in ["ALL", "HIT", "MISS", "NONE"] {
            assert!(classify(&with_param("includeResultsetResponses", v), &cfg()).is_ok());
        }
        std::assert_matches!(classify(&empty_query(), &cfg()), Ok(QueryKind::Empty));
    }

    #[test]
    fn unsupported_params_each_reject() {
        for key in [
            "geneId",
            "mateName",
            "aminoacidChange",
            "genomicAlleleShortForm",
        ] {
            assert_eq!(
                classify(&with_param(key, "x"), &cfg()).unwrap_err().code,
                400
            );
        }
    }

    #[test]
    fn sequence_without_alleles_is_insufficient() {
        // start(1) but no end and no referenceBases/alternateBases -> 400.
        let mut m = raw_with("referenceName", "1");
        m.insert("start".to_owned(), Value::Array(vec![Value::from(100)]));
        let q = parse_request(&m, &cfg()).unwrap();
        assert_eq!(classify(&q, &cfg()).unwrap_err().code, 400);
    }

    #[test]
    fn span_cap_rejects_wide_range_but_exempts_sequence() {
        let mut narrow = cfg();
        narrow.max_query_span_bp = 50;
        // Range of span 100 > 50 -> 400.
        assert_eq!(classify(&range_query(), &narrow).unwrap_err().code, 400);
        // Sequence is exempt regardless of cap.
        assert!(classify(&seq_query(), &narrow).is_ok());
        // Bracket extent 100..250 = span 150 > 50 -> 400.
        assert_eq!(classify(&bracket_query(), &narrow).unwrap_err().code, 400);
        // Cap 0 = unlimited.
        let mut unlimited = cfg();
        unlimited.max_query_span_bp = 0;
        assert!(classify(&range_query(), &unlimited).is_ok());
    }

    #[test]
    fn testmode_true_and_false_are_both_accepted() {
        // Beacon v2 mandates that the beacon respond to a `testMode` request. This is an
        // all-public aggregate beacon with no sensitive data to withhold, so `testMode` is
        // a no-op and both `true` and `false` are accepted.
        assert!(classify(&with_bool("testMode", false), &cfg()).is_ok());
        assert!(classify(&with_bool("testMode", true), &cfg()).is_ok());
    }

    #[test]
    fn testmode_string_forms_match_bool_get_post_parity() {
        // GET coerces every value to a string. `testMode=false` and `testMode=true` are
        // both valid booleans and are accepted like the POST bools, for GET/POST parity.
        assert!(classify(&with_param("testMode", "false"), &cfg()).is_ok());
        assert!(classify(&with_param("testMode", "FALSE"), &cfg()).is_ok());
        assert!(classify(&with_param("testMode", "true"), &cfg()).is_ok());
        // A non-boolean string is still a 400: input validation, not a mode rejection.
        assert_eq!(
            classify(&with_param("testMode", "maybe"), &cfg())
                .unwrap_err()
                .code,
            400
        );
    }

    #[test]
    fn include_resultset_responses_parses_enum_and_defaults_to_hit() {
        // Absent -> default HIT.
        assert_eq!(
            parse_include_resultset_responses(&Map::new()).unwrap(),
            IncludeResultsetResponses::Hit
        );
        // Null -> default HIT.
        let mut null_map = Map::new();
        null_map.insert("includeResultsetResponses".to_owned(), Value::Null);
        assert_eq!(
            parse_include_resultset_responses(&null_map).unwrap(),
            IncludeResultsetResponses::Hit
        );
        // Each enum member parses to its variant.
        for (s, want) in [
            ("ALL", IncludeResultsetResponses::All),
            ("HIT", IncludeResultsetResponses::Hit),
            ("MISS", IncludeResultsetResponses::Miss),
            ("NONE", IncludeResultsetResponses::None),
        ] {
            let m = raw_with("includeResultsetResponses", s);
            assert_eq!(parse_include_resultset_responses(&m).unwrap(), want);
        }
        // Out-of-enum / non-string -> 400.
        assert_eq!(
            parse_include_resultset_responses(&raw_with("includeResultsetResponses", "WRONG"))
                .unwrap_err()
                .code,
            400
        );
        let mut bool_map = Map::new();
        bool_map.insert("includeResultsetResponses".to_owned(), Value::Bool(true));
        assert_eq!(
            parse_include_resultset_responses(&bool_map)
                .unwrap_err()
                .code,
            400
        );
    }

    #[test]
    fn dataset_ids_parses_array_and_comma_string_leniently() {
        // Absent, and explicit null, give `None`: no scope at all, so all visible datasets.
        assert_eq!(parse_dataset_ids(&Map::new()), None);
        let mut null_scope = Map::new();
        null_scope.insert("datasetIds".to_owned(), Value::Null);
        assert_eq!(parse_dataset_ids(&null_scope), None);
        // A JSON array (POST): collected, trimmed; blanks and non-strings dropped.
        let arr = serde_json::json!({ "datasetIds": [" A ", "B", "", 7, "  "] })
            .as_object()
            .unwrap()
            .clone();
        assert_eq!(
            parse_dataset_ids(&arr),
            Some(vec!["A".to_owned(), "B".to_owned()])
        );
        // A comma-separated string (the GET query-string form).
        assert_eq!(
            parse_dataset_ids(&raw_with("datasetIds", "X, Y ,,Z")),
            Some(vec!["X".to_owned(), "Y".to_owned(), "Z".to_owned()])
        );
    }

    #[test]
    fn a_submitted_but_unresolvable_dataset_scope_is_not_absent() {
        // The distinction the bare-`Vec` return could not express. Each of these submits a
        // scope that resolves to no ids; the caller must select nothing, not fall back to
        // "all visible datasets" (a false affirmation at boolean/count granularity, where
        // the per-dataset resultSets are dropped and only the OR-ed `exists` is visible).
        let empty_array = serde_json::json!({ "datasetIds": [] })
            .as_object()
            .unwrap()
            .clone();
        let all_junk = serde_json::json!({ "datasetIds": [null, 7, "  "] })
            .as_object()
            .unwrap()
            .clone();
        let mut wrong_type = Map::new();
        wrong_type.insert("datasetIds".to_owned(), Value::Bool(true));

        for (label, params) in [
            ("empty array", empty_array),
            ("all-unusable elements", all_junk),
            ("wrong-typed value", wrong_type),
            ("empty string", raw_with("datasetIds", "")),
            ("commas only", raw_with("datasetIds", " , ,")),
        ] {
            assert_eq!(
                parse_dataset_ids(&params),
                Some(Vec::new()),
                "{label}: a submitted scope that resolves to nothing must stay Some(empty) \
                 — None would widen the query to every visible dataset"
            );
        }
    }

    #[test]
    fn pagination_defaults_and_clamps() {
        let c = cfg(); // default_page_limit 10, max_page_limit 1000
        // Omitted -> defaults.
        let p = apply_pagination(None, None, &c);
        assert_eq!(p.skip, 0);
        assert_eq!(p.limit, 10);
        // Explicit within range passes through.
        let p2 = apply_pagination(Some(5), Some(42), &c);
        assert_eq!(p2.skip, 5);
        assert_eq!(p2.limit, 42);
        // The GDI User Portal's 1000-row range page is exactly at the cap: served whole.
        let p3 = apply_pagination(None, Some(1000), &c);
        assert_eq!(p3.limit, 1000);
        // Over the cap is clamped.
        let p4 = apply_pagination(None, Some(5000), &c);
        assert_eq!(p4.limit, 1000);
        // limit:0 (Beacon-unbounded) is clamped to the cap, never echoed verbatim.
        let p5 = apply_pagination(None, Some(0), &c);
        assert_eq!(p5.limit, 1000);
    }

    #[test]
    fn parse_length_handles_number_string_and_rejects_bad_types() {
        // Absent / null -> Ok(None).
        assert_eq!(parse_length(&Map::new(), "variantMinLength").unwrap(), None);
        let mut null_map = Map::new();
        null_map.insert("variantMinLength".to_owned(), Value::Null);
        assert_eq!(parse_length(&null_map, "variantMinLength").unwrap(), None);

        // Integer JSON number -> Ok(Some(n)), including negative.
        let mut num = Map::new();
        num.insert("variantMinLength".to_owned(), Value::from(5));
        assert_eq!(parse_length(&num, "variantMinLength").unwrap(), Some(5));
        let mut neg = Map::new();
        neg.insert("variantMinLength".to_owned(), Value::from(-3));
        assert_eq!(parse_length(&neg, "variantMinLength").unwrap(), Some(-3));

        // Non-integer number (1.5) -> error.
        let mut frac = Map::new();
        frac.insert("variantMinLength".to_owned(), Value::from(1.5_f64));
        assert!(parse_length(&frac, "variantMinLength").is_err());

        // String parses, surrounding whitespace trimmed.
        assert_eq!(
            parse_length(&raw_with("variantMaxLength", "  42 "), "variantMaxLength").unwrap(),
            Some(42)
        );
        // Unparseable string -> error.
        assert!(parse_length(&raw_with("variantMaxLength", "abc"), "variantMaxLength").is_err());

        // Wrong JSON type (bool) -> error.
        let mut b = Map::new();
        b.insert("variantMaxLength".to_owned(), Value::Bool(true));
        assert!(parse_length(&b, "variantMaxLength").is_err());
    }

    #[test]
    fn variant_type_normalizes_and_accepts_synonyms() {
        // Canonical value, case-insensitive + whitespace-trimmed; resolves to one label.
        let q = parse_request(&raw_with("variantType", " snp "), &cfg()).unwrap();
        assert_eq!(q.variant_type, Some(vec!["SNP".to_owned()]));
        // Nomenclature synonyms fold onto the canonical stored token.
        for (input, canonical) in [
            ("SNV", "SNP"),
            ("mnv", "MNP"),
            ("insertion", "INS"),
            ("Deletion", "DEL"),
            ("delins", "DELINS"),
            ("MIXED", "DELINS"),
            ("complex", "DELINS"),
        ] {
            let q = parse_request(&raw_with("variantType", input), &cfg()).unwrap();
            assert_eq!(
                q.variant_type,
                Some(vec![canonical.to_owned()]),
                "{input} must normalize to {canonical}"
            );
        }
        // The umbrella term INDEL selects every length-changing type, matching the
        // reference vocabulary, which stores insertions and deletions merged as INDEL.
        let q_indel = parse_request(&raw_with("variantType", "indel"), &cfg()).unwrap();
        assert_eq!(
            q_indel.variant_type,
            Some(vec![
                "INS".to_owned(),
                "DEL".to_owned(),
                "DELINS".to_owned()
            ])
        );
        // Absent -> None.
        let q3 = parse_request(&Map::new(), &cfg()).unwrap();
        assert_eq!(q3.variant_type, None);
        // An unrecognised value is a 400, not a silently-empty result.
        let err = parse_request(&raw_with("variantType", "DUP"), &cfg()).unwrap_err();
        assert_eq!(err.code, 400);
        assert!(parse_request(&raw_with("variantType", "banana"), &cfg()).is_err());
        // A non-string variantType is rejected.
        let mut bad = Map::new();
        bad.insert("variantType".to_owned(), Value::from(7));
        assert!(parse_request(&bad, &cfg()).is_err());
    }

    #[test]
    fn coordinate_above_i32_max_is_rejected() {
        // A coordinate beyond the i32 POS ceiling can never match and is rejected at parse,
        // so it cannot drive an unbounded select_files block enumeration. This holds
        // independently of max_query_span_bp.
        let over = (i64::from(i32::MAX) + 1).to_string();
        let mut s = raw_with("referenceName", "1");
        s.insert("start".to_owned(), Value::String(over));
        s.insert("end".to_owned(), Value::String("0".to_owned()));
        assert_eq!(parse_request(&s, &cfg()).unwrap_err().code, 400);

        // The bracket `s_max` dimension is bounded too.
        let mut b = raw_with("referenceName", "1");
        b.insert(
            "start".to_owned(),
            Value::Array(vec![Value::from(0), Value::from(i64::from(i32::MAX) + 1)]),
        );
        b.insert(
            "end".to_owned(),
            Value::Array(vec![Value::from(0), Value::from(0)]),
        );
        assert_eq!(parse_request(&b, &cfg()).unwrap_err().code, 400);

        // The boundary value i32::MAX is accepted.
        let mut ok = raw_with("referenceName", "1");
        ok.insert("start".to_owned(), Value::String(i32::MAX.to_string()));
        assert!(parse_request(&ok, &cfg()).is_ok());
    }

    #[test]
    fn inverted_range_and_bracket_rejected() {
        // start > end in a range is a 400, not a gap-spanning match.
        let mut r = raw_with("referenceName", "1");
        r.insert("start".to_owned(), Value::Array(vec![Value::from(200)]));
        r.insert("end".to_owned(), Value::Array(vec![Value::from(100)]));
        let q = parse_request(&r, &cfg()).unwrap();
        assert_eq!(classify(&q, &cfg()).unwrap_err().code, 400);

        // s_min > s_max is rejected.
        let mut b = raw_with("referenceName", "1");
        b.insert(
            "start".to_owned(),
            Value::Array(vec![Value::from(150), Value::from(100)]),
        );
        b.insert(
            "end".to_owned(),
            Value::Array(vec![Value::from(200), Value::from(250)]),
        );
        let q = parse_request(&b, &cfg()).unwrap();
        assert_eq!(classify(&q, &cfg()).unwrap_err().code, 400);

        // s_min > e_max (start interval entirely past the latest end) is rejected.
        let mut b2 = raw_with("referenceName", "1");
        b2.insert(
            "start".to_owned(),
            Value::Array(vec![Value::from(300), Value::from(400)]),
        );
        b2.insert(
            "end".to_owned(),
            Value::Array(vec![Value::from(100), Value::from(200)]),
        );
        let q = parse_request(&b2, &cfg()).unwrap();
        assert_eq!(classify(&q, &cfg()).unwrap_err().code, 400);
    }

    #[test]
    fn variant_lengths_validated() {
        // A negative bound and a min > max contradiction are both 400.
        let mut neg = raw_with("referenceName", "1");
        neg.insert("variantMinLength".to_owned(), Value::from(-1));
        assert_eq!(parse_request(&neg, &cfg()).unwrap_err().code, 400);

        let mut inv = raw_with("referenceName", "1");
        inv.insert("variantMinLength".to_owned(), Value::from(10));
        inv.insert("variantMaxLength".to_owned(), Value::from(5));
        assert_eq!(parse_request(&inv, &cfg()).unwrap_err().code, 400);

        // A valid non-negative min <= max passes.
        let mut ok = raw_with("referenceName", "1");
        ok.insert("variantMinLength".to_owned(), Value::from(1));
        ok.insert("variantMaxLength".to_owned(), Value::from(5));
        assert!(parse_request(&ok, &cfg()).is_ok());
    }

    #[test]
    fn coordinate_lower_bound_zero_ok_negative_rejected() {
        // Zero is a valid coordinate; a negative one is a 400. Pins the `n < 0`
        // guard boundary: a `<=` mutant rejects 0, a `==` mutant accepts -1.
        let mut zero = raw_with("referenceName", "1");
        zero.insert("start".to_owned(), Value::Array(vec![Value::from(0)]));
        zero.insert("end".to_owned(), Value::Array(vec![Value::from(100)]));
        assert!(parse_request(&zero, &cfg()).is_ok());

        let mut neg = raw_with("referenceName", "1");
        neg.insert("start".to_owned(), Value::Array(vec![Value::from(-1)]));
        neg.insert("end".to_owned(), Value::Array(vec![Value::from(100)]));
        assert_eq!(parse_request(&neg, &cfg()).unwrap_err().code, 400);
    }

    #[test]
    fn variant_length_boundaries_zero_and_equal_are_valid() {
        // A zero-length bound is valid (schema minimum 0) and min == max is valid;
        // only a negative bound or min > max is a 400. Pins the `< 0` guards (a `<=`
        // mutant rejects 0) and the `min > max` guard (a `>=` mutant rejects equal).
        for k in ["variantMinLength", "variantMaxLength"] {
            let mut m = raw_with("referenceName", "1");
            m.insert(k.to_owned(), Value::from(0));
            assert!(
                parse_request(&m, &cfg()).is_ok(),
                "{k} = 0 must be accepted"
            );
        }
        let mut eq = raw_with("referenceName", "1");
        eq.insert("variantMinLength".to_owned(), Value::from(5));
        eq.insert("variantMaxLength".to_owned(), Value::from(5));
        assert!(parse_request(&eq, &cfg()).is_ok());

        // A negative max is a 400 (a `==` mutant would accept -1).
        let mut neg = raw_with("referenceName", "1");
        neg.insert("variantMaxLength".to_owned(), Value::from(-1));
        assert_eq!(parse_request(&neg, &cfg()).unwrap_err().code, 400);
    }

    #[test]
    fn span_cap_boundary_and_arithmetic() {
        // At span == cap the query is accepted, because the test is `span > cap` rather
        // than `>=`. range_query has span 100, so cap 100 must pass, and a `+` in place of
        // the `-` in the `end - start` span (100 becoming 300) would reject it.
        let mut at_cap = cfg();
        at_cap.max_query_span_bp = 100;
        assert!(classify(&range_query(), &at_cap).is_ok());

        // One below the span is rejected (pins the reject side).
        let mut over = cfg();
        over.max_query_span_bp = 99;
        assert_eq!(classify(&range_query(), &over).unwrap_err().code, 400);

        // Bracket extent (100..250 = 150) at cap 150 is accepted; a `- with +`
        // mutant in the `e_max - s_min` span (150 -> 350) would reject it.
        let mut b_at_cap = cfg();
        b_at_cap.max_query_span_bp = 150;
        assert!(classify(&bracket_query(), &b_at_cap).is_ok());
    }

    #[test]
    fn range_start_equal_end_and_degenerate_bracket_are_valid() {
        // start == end is a valid (empty half-open) Range, not a 400: pins
        // `start > end` (a `>=` mutant would reject it).
        let mut r = raw_with("referenceName", "1");
        r.insert("start".to_owned(), Value::Array(vec![Value::from(100)]));
        r.insert("end".to_owned(), Value::Array(vec![Value::from(100)]));
        let q = parse_request(&r, &cfg()).unwrap();
        std::assert_matches!(
            classify(&q, &cfg()),
            Ok(QueryKind::Range {
                start: 100,
                end: 100,
                ..
            })
        );

        // A fully-degenerate bracket (all four bounds equal, s_min == e_max) is
        // valid: pins the three `s_min > s_max` / `e_min > e_max` / `s_min > e_max`
        // ordering checks (any `>=` or `==` mutant would reject it).
        let mut b = raw_with("referenceName", "1");
        b.insert(
            "start".to_owned(),
            Value::Array(vec![Value::from(100), Value::from(100)]),
        );
        b.insert(
            "end".to_owned(),
            Value::Array(vec![Value::from(100), Value::from(100)]),
        );
        let q = parse_request(&b, &cfg()).unwrap();
        std::assert_matches!(
            classify(&q, &cfg()),
            Ok(QueryKind::Bracket {
                s_min: 100,
                s_max: 100,
                e_min: 100,
                e_max: 100,
                ..
            })
        );
    }

    #[test]
    fn classify_propagates_predicates_into_the_query_kind() {
        // A `predicates_of` -> Default mutant would silently drop the
        // length/ref/alt filters from the built query.
        let mut m = raw_with("referenceName", "1");
        m.insert("start".to_owned(), Value::Array(vec![Value::from(100)]));
        m.insert("end".to_owned(), Value::Array(vec![Value::from(200)]));
        m.insert("variantMinLength".to_owned(), Value::from(3));
        let q = parse_request(&m, &cfg()).unwrap();
        let Ok(QueryKind::Range { predicates, .. }) = classify(&q, &cfg()) else {
            panic!("expected a Range");
        };
        assert_eq!(predicates.min_len, Some(3));
    }

    #[test]
    fn coordinates_accept_a_bare_number_not_only_an_array() {
        // GA4GH allows `start`/`end` as a single integer OR an array; deleting the
        // `Value::Number` arm of `parse_coords` would reject the bare-integer form.
        let mut m = raw_with("referenceName", "1");
        m.insert("start".to_owned(), Value::from(100));
        m.insert("end".to_owned(), Value::from(200));
        let q = parse_request(&m, &cfg()).unwrap();
        std::assert_matches!(
            classify(&q, &cfg()),
            Ok(QueryKind::Range {
                start: 100,
                end: 200,
                ..
            })
        );
    }

    #[test]
    fn testmode_flag_string_true_parses_as_true() {
        // The GET string `"true"` must parse to the bool `true`, not fall through to a
        // "must be a boolean" 400: deleting the `"true"` match arm is a silent behaviour
        // change that a `.code == 400` assertion cannot see, so assert the parsed value
        // directly.
        assert_eq!(
            testmode_flag(Some(&Value::String("true".to_owned()))).unwrap(),
            Some(true)
        );
        assert_eq!(
            testmode_flag(Some(&Value::String("TRUE".to_owned()))).unwrap(),
            Some(true)
        );
    }

    #[test]
    fn has_variant_params_counts_each_variant_selector() {
        // An empty envelope carries no variant selector.
        assert!(!has_variant_params(&empty_query()));

        // Each selector alone must make the query non-empty; a `|| -> &&` mutant in
        // the disjunction would drop one selector and misclassify it as Empty.
        let single = |k: &str, v: Value| {
            let mut m = Map::new();
            m.insert(k.to_owned(), v);
            parse_request(&m, &cfg()).unwrap()
        };
        assert!(has_variant_params(&single(
            "referenceName",
            Value::from("1")
        )));
        assert!(has_variant_params(&single(
            "start",
            Value::Array(vec![Value::from(100)])
        )));
        assert!(has_variant_params(&single(
            "end",
            Value::Array(vec![Value::from(200)])
        )));
        assert!(has_variant_params(&single(
            "referenceBases",
            Value::from("A")
        )));
        assert!(has_variant_params(&single(
            "alternateBases",
            Value::from("T")
        )));
        assert!(has_variant_params(&single(
            "variantType",
            Value::from("SNP")
        )));
        assert!(has_variant_params(&single(
            "variantMinLength",
            Value::from(3)
        )));
        assert!(has_variant_params(&single(
            "variantMaxLength",
            Value::from(3)
        )));
    }

    #[test]
    fn unsupported_param_null_is_ignored() {
        // An explicit null for an unsupported param is treated as absent.
        let mut m = raw_with("referenceName", "1");
        m.insert("start".to_owned(), Value::Array(vec![Value::from(100)]));
        m.insert("end".to_owned(), Value::Array(vec![Value::from(200)]));
        m.insert("geneId".to_owned(), Value::Null);
        let q = parse_request(&m, &cfg()).unwrap();
        std::assert_matches!(classify(&q, &cfg()), Ok(QueryKind::Range { .. }));

        // A present non-null value still rejects.
        let mut m2 = raw_with("referenceName", "1");
        m2.insert("start".to_owned(), Value::Array(vec![Value::from(100)]));
        m2.insert("end".to_owned(), Value::Array(vec![Value::from(200)]));
        m2.insert("geneId".to_owned(), Value::String("BRCA1".to_owned()));
        let q2 = parse_request(&m2, &cfg()).unwrap();
        assert_eq!(classify(&q2, &cfg()).unwrap_err().code, 400);
    }

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// `apply_pagination` never exceeds the cap, and `limit:0` maps to the cap
        /// (never 0). The cap/default vary so the clamp is genuinely exercised.
        #[test]
        fn apply_pagination_never_exceeds_cap(
            req_skip in prop::option::of(0u64..1_000),
            req_limit in prop::option::of(0u64..10_000),
            max_page in 1u64..1_000,
            default_page in 1u64..1_000,
        ) {
            let cfg = BeaconParams {
                max_page_limit: max_page,
                default_page_limit: default_page,
                ..BeaconParams::default()
            };
            let p = apply_pagination(req_skip, req_limit, &cfg);
            prop_assert!(p.limit <= cfg.max_page_limit);
            prop_assert!(p.limit >= 1, "limit is never 0");
            if req_limit == Some(0) {
                prop_assert_eq!(p.limit, cfg.max_page_limit);
            }
        }

        /// `check_span` (cap > 0) rejects a span strictly above the cap and accepts
        /// anything at or below it; a non-positive span is always accepted.
        #[test]
        fn check_span_enforces_cap(cap in 1u64..1_000_000, span in -100i64..2_000_000) {
            let cfg = BeaconParams {
                max_query_span_bp: cap,
                ..BeaconParams::default()
            };
            let over = u64::try_from(span).is_ok_and(|s| s > cap);
            prop_assert_eq!(check_span(span, &cfg).is_err(), over);
        }
    }
}
