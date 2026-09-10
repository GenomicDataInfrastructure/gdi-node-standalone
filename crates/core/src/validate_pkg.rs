//! Input metadata validation for a `package.yaml`, mirroring gdi-metadata's
//! three obligation tiers (the spec-defined enum/pattern/IRI/cardinality/
//! `sh:uniqueLang` constraints, and the field size limits).
//!
//! [`validate_package`] is shared by the tool's `build` and `validate` commands
//! so the same gates (and the same warnings) surface in both. The function
//! returns [`Err`] on any mandatory / enum / pattern / IRI / cardinality /
//! `sh:uniqueLang` / size violation, and otherwise [`Ok`] with a
//! [`ValidationReport`] carrying the non-fatal recommended-tier warnings.
//!
//! The obligation tiers are:
//! * **Mandatory** missing -> [`Err`] (the build cannot proceed).
//! * **Recommended** top-level field missing (`keywords`,
//!   `numberOfUniqueIndividuals`) -> a warning naming the field, build still ok. These
//!   describe the dataset, so `build --strict` fails on them.
//! * **Recommended** sub-field of a present optional parent
//!   (`contactPoint.hasURL`, `otherIdentifier.schemaAgency`) -> a note. Failing a strict
//!   build on a cosmetic nit teaches providers to drop `--strict`, which is the flag that
//!   catches the losses that matter.
//! * **Optional** missing -> silent (omitted from the FDP output).

use std::collections::{BTreeMap, HashSet};

use crate::{
    error::{CoreError, CoreResult},
    id::is_valid_dataset_id,
    model::{
        ContactPoint, DatasetMode, LocalizedText, ManifestMetadata, OtherIdentifier,
        PackageFileEntry, PackageFileGroup, PackageMetadata, PackageYaml,
    },
};

/// The result of a successful package validation: the non-fatal warnings to
/// surface (recommended fields/sub-fields that are absent, unrecognized file
/// categories, ...). An empty `warnings` means the package is fully enriched.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidationReport {
    /// Non-fatal warnings, each naming the field(s) it concerns. Something to fix:
    /// `build --strict` fails when this is non-empty.
    pub warnings: Vec<String>,
    /// Informational notes about a valid configuration (e.g. a declared but inert
    /// `hideLowerCounts`). Never a reason to fail a strict build.
    pub notes: Vec<String>,
}

// ── Field size limits ──

/// `catalog name` cap.
pub const MAX_CATALOG_LEN: usize = 64;

/// Whether `name` is a safe catalog name: non-empty, ASCII alphanumeric plus `-_.`, at most
/// [`MAX_CATALOG_LEN`] chars, no leading dot and no `..`.
///
/// Lives beside the cap it enforces, and is the single definition behind both callers: the
/// service config's `[catalogs]` preflight (a malformed key would produce a broken `/fairdp`
/// IRI via `NamedNode::new_unchecked`) and the node's HTTP boundary guard.
#[must_use]
pub fn is_safe_catalog_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().count() <= MAX_CATALOG_LEN
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && !name.starts_with('.')
        && !name.contains("..")
}
/// `internalId` cap.
const MAX_INTERNAL_ID_LEN: usize = 64;
/// `title` per-language-value cap.
pub const MAX_TITLE_LEN: usize = 255;
/// `description` per-language-value cap.
pub const MAX_DESCRIPTION_LEN: usize = 10_000;
/// Maximum language entries in a localized field.
const MAX_LOCALIZED_ENTRIES: usize = 24;
/// `keyword` (each) cap.
pub const MAX_KEYWORD_LEN: usize = 64;
/// `keywords` count cap.
pub const MAX_KEYWORDS_COUNT: usize = 50;
/// `creator name` cap.
pub const MAX_CREATOR_NAME_LEN: usize = 255;
/// `creator` count cap.
const MAX_CREATORS_COUNT: usize = 64;
/// `contactPoint fn` cap.
const MAX_CONTACT_FN_LEN: usize = 255;
/// `email` cap (RFC 5321).
pub const MAX_EMAIL_LEN: usize = 254;
/// URL cap (`hasURL`, `afSourceReference`, ...).
const MAX_URL_LEN: usize = 2048;
/// IRI cap (every IRI metadata field).
const MAX_IRI_LEN: usize = 2048;
/// `otherIdentifier.notation` cap.
const MAX_NOTATION_LEN: usize = 255;
/// `otherIdentifier.schemaAgency` cap.
const MAX_SCHEMA_AGENCY_LEN: usize = 128;
/// `otherIdentifier.name` cap.
const MAX_OTHER_ID_NAME_LEN: usize = 255;
/// `otherIdentifier` count cap.
const MAX_OTHER_IDS_COUNT: usize = 50;
/// Count cap for the plain IRI-list fields (`applicableLegislation`, `legalBasis`,
/// `isReferencedBy`).
///
/// Each entry survives into the served DCAT-AP graph, so an unbounded list is an
/// amplification lever on the unauthenticated `GET /fairdp/dataset/{id}`, where one
/// oversized manifest is re-serialised on every request. 64 is far above any real value (a
/// dataset cites a handful of EU legislation IRIs) and far below the size at which
/// re-serialising the list becomes one.
const MAX_IRI_LIST_COUNT: usize = 64;
/// `file category` / `reference` / `preciseReference` cap.
const MAX_FILE_CATEGORY_LEN: usize = 32;
/// File groups count cap.
const MAX_FILE_GROUPS: usize = 64;
/// Files-per-group count cap.
const MAX_FILES_PER_GROUP: usize = 10_000;
/// In-package relative file path cap.
const MAX_FILE_PATH_LEN: usize = 1024;

// ── Enum vocabularies ──

/// `accessRights` authority IRIs (the three EU access-right tokens).
pub const ACCESS_RIGHTS: &[&str] = &[
    "http://publications.europa.eu/resource/authority/access-right/PUBLIC",
    "http://publications.europa.eu/resource/authority/access-right/RESTRICTED",
    "http://publications.europa.eu/resource/authority/access-right/NON_PUBLIC",
];

/// `type` IRIs — the single defined synthetic-data value.
pub const DATASET_TYPES: &[&str] =
    &["https://publications.europa.eu/resource/authority/dataset-type/SYNTHETIC_DATA"];

/// `healthCategory` IRIs: the closed set gdi-metadata's `DatasetShape` enumerates
/// (`sh:in`, 3 values; vendored `Dataset.ttl`).
///
/// Fail-closed. An in-namespace but non-enumerated value, such as
/// `…/HealthCategoryGenomic` (missing `Human`) or `…/HealthCategoryHumanProteomic`, is
/// rejected. The FDP emitter serves the value verbatim (`NamedNode::new_unchecked`) and a
/// conforming DCAT harvester validates it against this `sh:in`, so accepting a value the
/// shape forbids would publish RDF that a harvester rejects. The drift guard
/// `closed_sets_match_vendored_shape` keeps this list equal, as a set, to the vendored
/// `Dataset.ttl` `sh:in`.
pub const HEALTH_CATEGORIES: &[&str] = &[
    "http://data.gdi.eu/core/p2/HealthCategoryHumanGenetic",
    "http://data.gdi.eu/core/p2/HealthCategoryHumanEpigenomic",
    "http://data.gdi.eu/core/p2/HealthCategoryHumanGenomic",
];

/// `conformsTo` IRIs: the closed set gdi-metadata's `DatasetShape` enumerates
/// (`sh:in`, 3 values; vendored `Dataset.ttl`).
///
/// Fail-closed, same rationale as [`HEALTH_CATEGORIES`]. A namespace-prefix check over
/// `…/core/p2/` would accept any GDI concept, including a health-category IRI or a
/// mis-cased `1MGcompliant`, and serve it as non-conformant `dct:conformsTo`.
pub const CONFORMS_TO: &[&str] = &[
    "http://data.gdi.eu/core/p2/ExternallyGoverned",
    "http://data.gdi.eu/core/p2/1MGCompliant",
    "http://data.gdi.eu/core/p2/1MGCohort",
];

/// The human label for a [`CONFORMS_TO`] IRI: the `rdfs:label` the vendored `Dataset.ttl`
/// gives the concept, so the wizard's menu matches the GDI sheet.
///
/// Curated rather than derived from the IRI tail, because `1MGCompliant` → "1+MG compliant"
/// is not a case split. It lives beside the set so the vocabulary and its wording stay one
/// fact; the drift guard `conforms_to_labels_match_the_vendored_shape` fails when a
/// re-vendor adds a member or relabels one.
///
/// An IRI outside the set, which a validated value cannot be, falls back to its last path
/// segment. That fallback is what lets the drift guard see an unlabelled member.
#[must_use]
pub fn conforms_to_label(iri: &str) -> &str {
    match iri {
        "http://data.gdi.eu/core/p2/ExternallyGoverned" => "Externally governed",
        "http://data.gdi.eu/core/p2/1MGCompliant" => "1+MG compliant",
        "http://data.gdi.eu/core/p2/1MGCohort" => "1+MG cohort",
        other => other.rsplit('/').next().unwrap_or(other),
    }
}

/// The ELI of the European Health Data Space regulation — the `sh:defaultValue` the
/// gdi-metadata `DatasetShape` gives `dcatap:applicableLegislation`.
///
/// The tool's `init` scaffold, the wizard's legislation step and the absent-EHDS warning
/// below all read it from here, so the three cannot drift on the IRI itself.
pub const EHDS_ELI: &str = "http://data.europa.eu/eli/reg/2025/327/oj";

/// The warning [`validate_package`] emits when `applicableLegislation` does not cite
/// [`EHDS_ELI`].
///
/// A warning, not an error: HealthDCAT-AP r6 says the EHDS ELI "can be used where
/// relevant" and the GDI shape carries it as `sh:defaultValue` rather than a fixed value,
/// so a provider may legitimately drop it. The tool prints it from the validation report;
/// the node logs it at `warn` on ingest.
#[must_use]
pub fn ehds_absent_warning() -> String {
    format!("EHDS ELI absent; health datasets are expected to cite it (add {EHDS_ELI})")
}

/// Whether `value` matches the `hasEmail` shape `^mailto:.+@.+\..+$`: a `mailto:`
/// prefix, a non-empty local part, `@`, then a domain carrying an interior `.` with
/// a non-empty label on each side.
///
/// Hand-rolled (no `regex`) so it needs no fallible static-regex compile, honouring the
/// no-`expect`/`unwrap` convention for production library code.
#[must_use]
pub fn is_mailto_email(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("mailto:") else {
        return false;
    };
    let Some((local, domain)) = rest.split_once('@') else {
        return false;
    };
    // `.+@.+\..+`: non-empty local part, and a domain with a `.` that has at least
    // one character before it (within the domain) and at least one after.
    !local.is_empty()
        && matches!(domain.split_once('.'), Some((label, tld)) if !label.is_empty() && !tld.is_empty())
}

/// Validate a parsed `package.yaml` against the obligation tiers and the
/// spec-defined constraints.
///
/// `node_catalogs` is the node's catalog allow-list (catalog name -> display
/// title); when [`Some`], the package's `catalog` must be a member. Pass
/// [`None`] for the offline/air-gapped path where the catalog list is not
/// available (the node remains the authoritative gate at ingest).
///
/// # Errors
///
/// Returns [`CoreError::InvalidManifest`] on any mandatory-field, enum,
/// pattern, IRI, cardinality, `sh:uniqueLang`, or size-limit violation, and
/// [`CoreError::UnknownCatalog`] when `node_catalogs` is supplied and the
/// package's catalog is not in it. `config.mode == individual` (individual-level
/// genotypes) is rejected as "not yet supported".
pub fn validate_package(
    p: &PackageYaml,
    node_catalogs: Option<&BTreeMap<String, String>>,
) -> CoreResult<ValidationReport> {
    let mut warnings = Vec::new();
    let mut notes = Vec::new();

    validate_mode(p)?;

    // `init` scaffolds required fields as `REPLACE:`-prefixed placeholders; a
    // build/validate over an unfilled template must fail clearly.
    reject_replace_markers("", p)?;

    validate_catalog(p, node_catalogs)?;
    validate_core_metadata(&p.metadata, &mut warnings)?;
    validate_recommended(&p.metadata, &mut warnings)?;
    validate_optional_metadata(&p.metadata, &mut notes)?;
    validate_internal(p)?;
    validate_config(p, &mut warnings, &mut notes)?;
    validate_files(p, &mut warnings)?;

    Ok(ValidationReport { warnings, notes })
}

/// The outcome of a collect-all validation pass: every section-level error, plus
/// the warnings accumulated along the way.
#[derive(Debug, Default)]
pub struct FullValidation {
    /// Every section-level hard error found. Empty ⇔ the package is valid.
    pub errors: Vec<CoreError>,
    /// Non-fatal warnings accumulated across the sections.
    pub warnings: Vec<String>,
    /// Informational notes accumulated across the sections.
    pub notes: Vec<String>,
}

impl FullValidation {
    /// Whether the package passed (no hard errors).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Validate a `package.yaml`, collecting every independent section's first error instead
/// of failing fast.
///
/// [`validate_package`] is the ingest gate: it returns on the first hard violation, which
/// is correct for the node but forces a provider to fix and rerun one error at a time. This
/// runs the same checks and keeps going across the independent sections (catalog,
/// core/recommended/optional metadata, internal, config, files), so a `package.yaml` with
/// problems in several sections reports them all in one pass.
///
/// It is section-granular: at most one error per section, the first within it. The node
/// still gates on [`validate_package`], so this never relaxes what is accepted.
#[must_use]
pub fn validate_package_collect_all(
    p: &PackageYaml,
    node_catalogs: Option<&BTreeMap<String, String>>,
) -> FullValidation {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut notes = Vec::new();

    // Each section is independent (it reads only its own slice of the package and
    // never panics — it returns `Err`), so a failure in one does not invalidate
    // running the others. Collect the first error from each rather than stopping.
    let mut collect = |result: CoreResult<()>| {
        if let Err(e) = result {
            errors.push(e);
        }
    };
    collect(validate_mode(p));
    collect(reject_replace_markers("", p));
    collect(validate_catalog(p, node_catalogs));
    collect(validate_core_metadata(&p.metadata, &mut warnings));
    collect(validate_recommended(&p.metadata, &mut warnings));
    collect(validate_optional_metadata(&p.metadata, &mut notes));
    collect(validate_internal(p));
    collect(validate_config(p, &mut warnings, &mut notes));
    collect(validate_files(p, &mut warnings));

    FullValidation {
        errors,
        warnings,
        notes,
    }
}

/// Reject the deferred individual-level (record) tier — only `aggregated` is built.
///
/// Shared by both entry points so the two cannot drift on the rejection message.
fn validate_mode(p: &PackageYaml) -> CoreResult<()> {
    if p.config.mode != DatasetMode::Aggregated {
        return Err(invalid(
            "config.mode=individual (individual-level genotypes) is not yet supported",
        ));
    }
    Ok(())
}

/// Validate the `catalog` field (non-empty, size cap, node-allow-list membership).
fn validate_catalog(
    p: &PackageYaml,
    node_catalogs: Option<&BTreeMap<String, String>>,
) -> CoreResult<()> {
    let catalog = &p.metadata.catalog;
    if catalog.is_empty() {
        return Err(invalid("catalog is mandatory and must not be empty"));
    }
    check_max_chars("catalog", catalog, MAX_CATALOG_LEN)?;
    if let Some(catalogs) = node_catalogs
        && !catalogs.contains_key(catalog)
    {
        return Err(CoreError::UnknownCatalog {
            name: catalog.clone(),
        });
    }
    Ok(())
}

/// Validate the mandatory metadata: title/description, access-rights, legislation,
/// license, creator, and health-category.
///
/// Pushes the absent-EHDS advisory ([`ehds_absent_warning`]) onto `warnings`; every other
/// finding here is a hard error.
fn validate_core_metadata(m: &PackageMetadata, warnings: &mut Vec<String>) -> CoreResult<()> {
    validate_localized("title", &m.title, MAX_TITLE_LEN)?;
    match &m.description {
        None => return Err(invalid("description is mandatory and must not be empty")),
        Some(desc) => validate_localized("description", desc, MAX_DESCRIPTION_LEN)?,
    }

    validate_enum("accessRights", &m.access_rights, ACCESS_RIGHTS)?;
    validate_iri("accessRights", &m.access_rights)?;

    // `prefix` is optional in package.yaml (the manifest carries the generated datasetId
    // instead, so it is `None` there), but when present it is a closed {GOE,GDI}
    // vocabulary — the same set `build` enforces at dataset-ID generation (`id.rs`).
    // Reject an out-of-vocab prefix at the validate gate too, so `validate` does not
    // green-light a package that `build` then fails with a cryptic late error.
    if let Some(prefix) = &m.prefix {
        validate_enum("metadata.prefix", prefix, &crate::id::DATASET_ID_PREFIXES)?;
    }

    if m.applicable_legislation.is_empty() {
        return Err(invalid(
            "applicableLegislation must have at least one entry",
        ));
    }
    validate_iri_list("applicableLegislation", &m.applicable_legislation)?;
    // The EHDS ELI is the shape's `sh:defaultValue`, not a fixed value, so its absence is
    // an advisory rather than a rejection.
    if !m.applicable_legislation.iter().any(|iri| iri == EHDS_ELI) {
        warnings.push(ehds_absent_warning());
    }

    if m.license.is_empty() {
        return Err(invalid("license is mandatory and must not be empty"));
    }
    validate_iri("license", &m.license)?;

    if m.creator.is_empty() {
        return Err(invalid("creator must have at least one entry"));
    }
    check_max_count("creator", m.creator.len(), MAX_CREATORS_COUNT)?;
    for agent in &m.creator {
        if agent.name.is_empty() {
            return Err(invalid("a creator name must not be empty"));
        }
        check_max_chars("a creator name", &agent.name, MAX_CREATOR_NAME_LEN)?;
    }

    if m.health_category.is_empty() {
        return Err(invalid("healthCategory must have at least one entry"));
    }
    for iri in &m.health_category {
        validate_iri("healthCategory", iri)?;
        validate_health_category(iri)?;
    }

    Ok(())
}

/// Validate the recommended-tier fields, pushing a naming warning when absent.
fn validate_recommended(m: &PackageMetadata, warnings: &mut Vec<String>) -> CoreResult<()> {
    match &m.keywords {
        None => warnings.push("recommended field \"keywords\" is absent".to_owned()),
        Some(kws) => {
            check_max_count("keywords", kws.len(), MAX_KEYWORDS_COUNT)?;
            for kw in kws {
                check_max_chars("a keyword", kw, MAX_KEYWORD_LEN)?;
            }
        }
    }
    if m.number_of_unique_individuals.is_none() {
        warnings.push("recommended field \"numberOfUniqueIndividuals\" is absent".to_owned());
    }
    Ok(())
}

/// Validate the optional metadata fields (validated when present, silent when
/// absent).
///
/// A recommended sub-field of a present optional parent (`contactPoint.hasURL`,
/// `otherIdentifier.schemaAgency`) is an advisory and lands in `notes`, not `warnings`.
/// See the module docs for the tier split.
fn validate_optional_metadata(m: &PackageMetadata, notes: &mut Vec<String>) -> CoreResult<()> {
    if let Some(conforms) = &m.conforms_to {
        for iri in conforms {
            validate_iri("conformsTo", iri)?;
            validate_conforms_to(iri)?;
        }
    }
    if let Some(type_) = &m.type_ {
        validate_enum("type", type_, DATASET_TYPES)?;
        validate_iri("type", type_)?;
    }
    if let Some(legal) = &m.legal_basis {
        validate_iri_list("legalBasis", legal)?;
    }
    if let Some(refs) = &m.is_referenced_by {
        validate_iri_list("isReferencedBy", refs)?;
    }
    if let Some(other_ids) = &m.other_identifier {
        validate_other_identifiers(other_ids, notes)?;
    }
    if let Some(cp) = &m.contact_point {
        validate_contact_point(cp, notes)?;
    }
    Ok(())
}

/// Validate the `internal` section size caps and the `pastVersion` ID shape.
fn validate_internal(p: &PackageYaml) -> CoreResult<()> {
    if let Some(internal_id) = &p.internal.internal_id {
        check_max_chars("internalId", internal_id, MAX_INTERNAL_ID_LEN)?;
    }
    if let Some(past) = &p.internal.past_version
        && !is_valid_dataset_id(past)
    {
        return Err(invalid("pastVersion is not a valid dataset ID"));
    }
    Ok(())
}

/// Validate the `config.hideLowerCounts` declaration.
///
/// `hideLowerCounts` is the declared sensitive-tier individual-match-count floor, a
/// forward-looking knob for the deferred individual-level path. On the aggregated
/// allele-frequency tier this node builds it is never applied to the data: it is only
/// recorded verbatim into `manifest.json` (`config.hideLowerCounts`) so a future consumer
/// can read the provider's intent. This function therefore:
///
/// * rejects a value `< 1`, since a count floor of zero or negative is meaningless (the
///   field is an integer `>= 1`);
/// * warns when it is exactly `1`, the disabled no-op setting (a floor of 1 hides
///   nothing), so the provider knows it has no effect even where applied;
/// * emits an informational note that the floor is inert on this aggregated package: it is
///   carried into the manifest but not enforced here.
///
/// When the field is absent there is nothing to record and this is a no-op.
fn validate_config(
    p: &PackageYaml,
    warnings: &mut Vec<String>,
    notes: &mut Vec<String>,
) -> CoreResult<()> {
    let Some(floor) = p.config.hide_lower_counts else {
        return Ok(());
    };
    if floor == 0 {
        return Err(invalid("config.hideLowerCounts must be an integer >= 1"));
    }
    if floor == 1 {
        warnings
            .push("config.hideLowerCounts is 1, which disables the count floor (no-op)".to_owned());
    }
    // A declared floor is legitimate: it is recorded for the future sensitive tier. A
    // warning here would fail every `build --strict` that sets it, so it is a note.
    notes.push(format!(
        "config.hideLowerCounts ({floor}) is recorded but inert on an aggregated package; \
         it is carried into the manifest, not applied to the data"
    ));
    Ok(())
}

/// Build a user-facing [`CoreError::InvalidManifest`] from a static detail.
fn invalid(detail: &str) -> CoreError {
    CoreError::InvalidManifest {
        detail: detail.to_owned(),
    }
}

/// Reject a string longer than `max` characters: `"{what} exceeds the {max}-char limit"`.
///
/// The message interpolates the constant the check compares against, so the limit and the
/// text reporting it cannot drift apart.
fn check_max_chars(what: &str, value: &str, max: usize) -> CoreResult<()> {
    if value.chars().count() > max {
        return Err(invalid(&format!("{what} exceeds the {max}-char limit")));
    }
    Ok(())
}

/// Reject a collection of more than `max` entries: `"{what} count exceeds the {max} limit"`.
/// Interpolates the constant it compares against, as [`check_max_chars`] does, so the limit
/// and the text reporting it cannot drift apart.
fn check_max_count(what: &str, len: usize, max: usize) -> CoreResult<()> {
    if len > max {
        return Err(invalid(&format!("{what} count exceeds the {max} limit")));
    }
    Ok(())
}

/// Validate one plain IRI-list field: bound its count, then every entry.
///
/// One function rather than the pair of checks repeated per field. These fields are
/// validated on both the package path (`validate_core_metadata`,
/// `validate_optional_metadata`) and the overlay path (`validate_patch`), and a cap applied
/// to only one leaves the metadata-overlay route uncapped.
fn validate_iri_list(field: &str, iris: &[String]) -> CoreResult<()> {
    check_max_count(field, iris.len(), MAX_IRI_LIST_COUNT)?;
    for iri in iris {
        validate_iri(field, iri)?;
    }
    Ok(())
}

/// The placeholder prefix `init` writes for every required field the provider must supply
/// (e.g. `title: "REPLACE: Dataset title"`).
const REPLACE_MARKER: &str = "REPLACE:";

/// Reject any string leaf still carrying an `init` `REPLACE:` placeholder.
///
/// `init` scaffolds a `package.yaml` whose unfilled fields are `REPLACE:`-prefixed, and
/// `build`/`validate` must fail on any that remain so an unfilled template cannot be
/// packaged.
///
/// Serde-driven rather than a hand-maintained field list: the template plants markers in
/// `metadata`, `files[].reference`, the VCF path, `config.afSource` and
/// `config.afSourceReference`, and a list that must be extended per template field will be
/// forgotten. The next field added anywhere in the document is covered without touching
/// this. `ServiceConfig::preflight`'s `<SET ME` leaf walk mirrors it.
fn reject_replace_markers<T: serde::Serialize>(prefix: &str, value: &T) -> CoreResult<()> {
    let json = serde_json::to_value(value)
        .map_err(|e| invalid(&format!("could not inspect the package: {e}")))?;
    let mut hits = Vec::new();
    collect_replace_marker_paths(prefix, &json, &mut hits);
    if hits.is_empty() {
        return Ok(());
    }
    Err(invalid(&format!(
        "{} still has the init `{REPLACE_MARKER}` placeholder; fill it in before building",
        hits.join(", ")
    )))
}

/// Collect the dotted paths of every string leaf beginning with the `REPLACE:` marker.
fn collect_replace_marker_paths(prefix: &str, value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) if s.trim_start().starts_with(REPLACE_MARKER) => {
            out.push(if prefix.is_empty() {
                "<root>".to_owned()
            } else {
                prefix.to_owned()
            });
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let path = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                collect_replace_marker_paths(&path, v, out);
            }
        }
        serde_json::Value::Array(items) => {
            for (i, v) in items.iter().enumerate() {
                collect_replace_marker_paths(&format!("{prefix}[{i}]"), v, out);
            }
        }
        _ => {}
    }
}

/// Validate a localized text field: per-value length cap, the entry-count cap,
/// and `sh:uniqueLang` over a language map.
fn validate_localized(field: &str, text: &LocalizedText, max_value_len: usize) -> CoreResult<()> {
    match text {
        LocalizedText::Plain(s) => check_localized_value(field, s, max_value_len),
        LocalizedText::Map(map) => {
            if map.is_empty() {
                return Err(invalid(&format!("{field} language map must not be empty")));
            }
            if map.len() > MAX_LOCALIZED_ENTRIES {
                return Err(invalid(&format!(
                    "{field} language map exceeds the {MAX_LOCALIZED_ENTRIES}-entry limit"
                )));
            }
            check_unique_lang(field, map.keys())?;
            for value in map.values() {
                check_localized_value(field, value, max_value_len)?;
            }
            Ok(())
        }
    }
}

/// Validate one localized value: non-empty, and within the per-value length cap.
///
/// Applied identically to a `Plain` value and to every language-map value. An empty map
/// value (e.g. `title: {en: ""}`) would emit an empty langString (`""@en`) for a mandatory,
/// non-empty field, which the gdi-metadata `DatasetShape` rejects.
fn check_localized_value(field: &str, value: &str, max_value_len: usize) -> CoreResult<()> {
    if value.is_empty() {
        return Err(invalid(&format!("{field} must not be empty")));
    }
    check_max_chars(field, value, max_value_len)
}

/// Enforce `sh:uniqueLang`: every key must be a well-formed BCP-47 tag, and the
/// keys must be unique after canonicalisation (case-insensitive on the tag).
///
/// `{en, EN}` and `{en-US, en-us}` collapse to one canonical tag and are
/// rejected; `en` vs `en-GB` are distinct and allowed; an ill-formed tag (e.g.
/// `e`, `en_US` with an underscore, an empty subtag) is rejected.
fn check_unique_lang<'a>(field: &str, keys: impl Iterator<Item = &'a String>) -> CoreResult<()> {
    let mut seen = HashSet::new();
    for key in keys {
        let canonical = canonical_bcp47(key)
            .ok_or_else(|| invalid(&format!("{field} has an ill-formed language tag {key:?}")))?;
        if !seen.insert(canonical) {
            return Err(invalid(&format!(
                "{field} has duplicate language tags after canonicalisation ({key:?})"
            )));
        }
    }
    Ok(())
}

/// Canonicalise a BCP-47 language tag, or [`None`] if it is ill-formed.
///
/// This is a conservative validator covering the langtag shape used by metadata
/// language maps: a 2-8 letter primary language subtag, optionally followed by
/// `-`-separated subtags each of which is 1-8 ASCII alphanumerics. Canonical
/// form lowercases the whole tag, which suffices to collapse `en`/`EN` and
/// `en-US`/`en-us`. It does not implement full RFC 5646 (no extlang/script/variant/
/// extension/privateuse canonical casing), which the `sh:uniqueLang` gate does not need.
///
/// Two consumers, one definition. `check_unique_lang` uses this as the `sh:uniqueLang`
/// comparison key, and the FDP emitter (`gdi_node_standalone_fairdp::graph`) uses it as the
/// tag it puts on the wire. They must agree: this function accepts `en-US`, the spelling
/// RFC 5646 recommends, while RDF 1.1 defines a langString's value space with the tag
/// lowercased. An emitter echoing the key verbatim would serve `"…"@en-US`, and the graph
/// would no longer equal its own re-parse.
///
/// # Examples
///
/// ```
/// use gdi_node_standalone_core::validate_pkg::canonical_bcp47;
///
/// assert_eq!(canonical_bcp47("en-US").as_deref(), Some("en-us"));
/// assert_eq!(canonical_bcp47("EN").as_deref(), Some("en"));
/// // Ill-formed tags have no canonical form.
/// assert_eq!(canonical_bcp47("en_US"), None);
/// assert_eq!(canonical_bcp47("e"), None);
/// ```
#[must_use]
pub fn canonical_bcp47(tag: &str) -> Option<String> {
    if tag.is_empty() {
        return None;
    }
    let mut subtags = tag.split('-');
    let primary = subtags.next()?;
    // Primary language subtag: 2-3 (or 4-8 reserved/registered) ASCII letters.
    if !(2..=8).contains(&primary.len()) || !primary.bytes().all(|b| b.is_ascii_alphabetic()) {
        return None;
    }
    for sub in subtags {
        if !(1..=8).contains(&sub.len()) || !sub.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return None;
        }
    }
    Some(tag.to_ascii_lowercase())
}

/// Reject a value not in the allowed set.
///
/// # Errors
///
/// Returns [`CoreError::InvalidManifest`] if `value` is not in `allowed`.
pub fn validate_enum(field: &str, value: &str, allowed: &[&str]) -> CoreResult<()> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(invalid(&format!("{field} value {value:?} is not allowed")))
    }
}

/// Validate `healthCategory`: one of the closed [`HEALTH_CATEGORIES`] set
/// (gdi-metadata `DatasetShape` `sh:in`).
///
/// # Errors
///
/// Returns [`CoreError::InvalidManifest`] if `iri` is not one of the enumerated GDI
/// health-category concepts.
pub(crate) fn validate_health_category(iri: &str) -> CoreResult<()> {
    validate_enum("healthCategory", iri, HEALTH_CATEGORIES)
}

/// Validate `conformsTo`: one of the closed [`CONFORMS_TO`] set (gdi-metadata
/// `DatasetShape` `sh:in`).
///
/// The message names the whole allowed set: `conformsTo` is the one closed vocabulary a
/// provider hand-writes from the `init` scaffold (the wizard offers a menu), and "is not
/// allowed" alone leaves them guessing at three IRIs that differ only in capitalisation.
///
/// # Errors
///
/// Returns [`CoreError::InvalidManifest`] if `iri` is not one of the enumerated GDI
/// compliance concepts.
pub(crate) fn validate_conforms_to(iri: &str) -> CoreResult<()> {
    if CONFORMS_TO.contains(&iri) {
        Ok(())
    } else {
        // `{iri:?}` (Debug): the value is provider-controlled and this message reaches an
        // operator's terminal, so control characters stay inert.
        Err(invalid(&format!(
            "conformsTo value {iri:?} is not allowed; the closed set is: {}",
            CONFORMS_TO.join(", ")
        )))
    }
}

/// Reject any character forbidden in a serialized RFC 3987 IRI / Turtle `IRIREF`.
///
/// `url::Url::parse` silently *accepts* (by percent-encoding or stripping)
/// characters that are illegal in a serialized IRI — notably `<`, `>`, `"`, space,
/// and control characters — but the FDP RDF serializer emits a `NamedNode` verbatim
/// as `<…>` with **no** escaping (`oxrdf::NamedNode::new_unchecked`). A metadata
/// value carrying those characters could therefore break out of the angle-bracket
/// `IRIREF` and inject arbitrary triples into the served Turtle. Rejecting them at
/// the validation gate ensures such a value never reaches the graph builder. The
/// forbidden set is exactly the Turtle `IRIREF` exclusion: `<` `>` `"` `{` `}` `|`
/// `^` `` ` `` `\`, plus every code point in `U+0000..=U+0020` (controls and space).
fn reject_iri_unsafe_chars(field: &str, value: &str) -> CoreResult<()> {
    if let Some(c) = find_iri_unsafe_char(value) {
        return Err(invalid(&format!(
            "{field} value {value:?} contains a character not allowed in an IRI ({c:?})"
        )));
    }
    Ok(())
}

/// The first character in `value` forbidden in a serialized RFC 3987 IRI / Turtle
/// `IRIREF` — the exclusion set `<` `>` `"` `{` `}` `|` `^` `` ` `` `\` plus every
/// code point in `U+0000..=U+0020` (controls and space) — or `None` if clean.
///
/// Shared by the package validation path ([`reject_iri_unsafe_chars`]) and the
/// service-config preflight (`config::service`) so the two can never drift on this
/// security-critical char set: both emit the value verbatim into `<…>` in the
/// served Turtle via `NamedNode::new_unchecked`, so both must reject the same set.
pub(crate) fn find_iri_unsafe_char(value: &str) -> Option<char> {
    value.chars().find(|&c| {
        matches!(c, '<' | '>' | '"' | '{' | '}' | '|' | '^' | '`' | '\\') || c <= '\u{20}'
    })
}

/// The URI schemes permitted in a metadata IRI/URL that is emitted verbatim into the
/// public FDP RDF.
///
/// `url::Url::parse` accepts `javascript:`, `data:`, `file:`, `vbscript:` and more. Served
/// in a DCAT/FAIR graph, those feed a stored-XSS or local-file vector to a downstream RDF
/// consumer such as a browser-based catalog. Legitimate identifier and reference IRIs in
/// this metadata use HTTP(S), URN, DOI or FTP. `url::Url::scheme` is already lowercased, so
/// the match is case-insensitive.
const ALLOWED_IRI_SCHEMES: &[&str] = &["http", "https", "urn", "doi", "ftp", "ftps"];

/// Reject an IRI/URL whose scheme is not in [`ALLOWED_IRI_SCHEMES`].
fn reject_disallowed_scheme(field: &str, value: &str, parsed: &url::Url) -> CoreResult<()> {
    let scheme = parsed.scheme();
    if !ALLOWED_IRI_SCHEMES.contains(&scheme) {
        return Err(invalid(&format!(
            "{field} value {value:?} uses a disallowed URI scheme {scheme:?} (allowed: {ALLOWED_IRI_SCHEMES:?})"
        )));
    }
    Ok(())
}

/// Validate an IRI metadata field: parses as an absolute URL with a scheme and a
/// non-empty host (or, for `urn:`/`w3id`-style identifiers, a non-empty path),
/// carries no `IRIREF`-forbidden character (see RFC 3987 §2.2), uses an allowed
/// URI scheme (http/https/urn/doi/ftp/ftps — see `ALLOWED_IRI_SCHEMES`), and is
/// within the IRI length cap.
///
/// # Errors
///
/// Returns [`CoreError::InvalidManifest`] on a size-limit violation, a forbidden
/// `IRIREF` character, a disallowed URI scheme, an unparseable IRI, or an IRI with
/// neither host nor path.
pub fn validate_iri(field: &str, value: &str) -> CoreResult<()> {
    if value.chars().count() > MAX_IRI_LEN {
        return Err(invalid(&format!(
            "{field} IRI exceeds the {MAX_IRI_LEN}-char limit"
        )));
    }
    reject_iri_unsafe_chars(field, value)?;
    let parsed = url::Url::parse(value)
        .map_err(|_| invalid(&format!("{field} value {value:?} is not a valid IRI/URL")))?;
    reject_disallowed_scheme(field, value, &parsed)?;
    // Require a scheme and either a host (http/https/...) or a non-empty
    // opaque path (urn:, ...). A relative or scheme-less string fails
    // url::Url::parse, so reaching here means a scheme is present.
    let has_host = parsed.host_str().is_some_and(|h| !h.is_empty());
    let has_path = !parsed.path().is_empty() && parsed.path() != "/";
    if !has_host && !has_path {
        return Err(invalid(&format!(
            "{field} value {value:?} has no authority or path"
        )));
    }
    Ok(())
}

/// Validate an email field: the `^mailto:.+@.+\..+$` pattern + the length cap.
///
/// # Errors
///
/// Returns [`CoreError::InvalidManifest`] if the value exceeds the length cap,
/// does not match the `mailto:` pattern, or contains an `IRIREF`-forbidden character.
pub fn validate_email(field: &str, value: &str) -> CoreResult<()> {
    if value.chars().count() > MAX_EMAIL_LEN {
        return Err(invalid(&format!(
            "{field} exceeds the {MAX_EMAIL_LEN}-char limit"
        )));
    }
    if !is_mailto_email(value) {
        // The value is not echoed. This error travels the ingest error chain into the
        // node's structured log, and the address is a provider contact e-mail from an
        // untrusted package. The field path makes the fault fixable; the hint below is
        // structural, so it stays diagnostic without carrying the data.
        let hint = if value.strip_prefix("mailto:").is_none() {
            "missing the `mailto:` prefix"
        } else if !value.contains('@') {
            "missing `@`"
        } else {
            "the domain needs a dot with a non-empty label on each side"
        };
        return Err(invalid(&format!(
            "{field} is not a mailto: email ({hint}); value not shown"
        )));
    }
    // `hasEmail` is emitted as a `mailto:` IRI, so the `.+` wildcards above must not
    // be allowed to smuggle an `IRIREF`-breaking character into the served RDF.
    reject_iri_unsafe_chars(field, value)?;
    Ok(())
}

/// Bound a free-text field that is served verbatim but is not an IRI.
///
/// `config.afSource` is the case this exists for: a human-readable provenance label rendered
/// beside `afSourceReference` in every `frequencyInPopulations` entry. It is not a URL, so
/// [`validate_url`]'s scheme allow-list does not apply, but it shares the two properties
/// that matter. It is cloned per result entry, so an unbounded value multiplies by the page
/// limit and the dataset count into an unauthenticated memory amplifier, and it reaches a
/// client that may render it, so control characters have no place in it.
///
/// It shares `MAX_IRI_LEN` with its sibling because the two are displayed together and a
/// second, different limit would be a fact that drifts.
///
/// # Errors
///
/// [`CoreError::InvalidManifest`] when the value is over-long or carries a control char.
pub fn validate_bounded_text(field: &str, value: &str) -> CoreResult<()> {
    if value.chars().count() > MAX_IRI_LEN {
        return Err(invalid(&format!(
            "{field} exceeds the {MAX_IRI_LEN}-char limit"
        )));
    }
    if let Some(bad) = value.chars().find(|c| c.is_control()) {
        return Err(invalid(&format!(
            "{field} contains the control character {bad:?}, which is served verbatim to clients"
        )));
    }
    Ok(())
}

/// Validate a URL field (e.g. `hasURL`): parses as a URL within the URL cap and
/// carries no `IRIREF`-forbidden character (it is emitted as an IRI).
///
/// # Errors
///
/// Returns [`CoreError::InvalidManifest`] if the value exceeds the length cap,
/// contains a forbidden character, or is not a parseable URL.
pub fn validate_url(field: &str, value: &str) -> CoreResult<()> {
    if value.chars().count() > MAX_URL_LEN {
        return Err(invalid(&format!(
            "{field} URL exceeds the {MAX_URL_LEN}-char limit"
        )));
    }
    reject_iri_unsafe_chars(field, value)?;
    let parsed = url::Url::parse(value)
        .map_err(|_| invalid(&format!("{field} value {value:?} is not a valid URL")))?;
    // Same scheme allow-list as `validate_iri`: a `hasURL`/reference value is emitted as
    // an IRI into the public RDF too.
    reject_disallowed_scheme(field, value, &parsed)
}

/// Validate the `otherIdentifier` list (size caps + the recommended `schemaAgency`
/// sub-field advisory, pushed onto `notes`).
fn validate_other_identifiers(
    other_ids: &[OtherIdentifier],
    notes: &mut Vec<String>,
) -> CoreResult<()> {
    check_max_count("otherIdentifier", other_ids.len(), MAX_OTHER_IDS_COUNT)?;
    for oi in other_ids {
        if oi.notation.is_empty() {
            return Err(invalid("otherIdentifier.notation must not be empty"));
        }
        check_max_chars("otherIdentifier.notation", &oi.notation, MAX_NOTATION_LEN)?;
        match &oi.schema_agency {
            None => notes.push(
                "recommended sub-field \"schemaAgency\" is absent on an otherIdentifier".to_owned(),
            ),
            Some(sa) => {
                check_max_chars("otherIdentifier.schemaAgency", sa, MAX_SCHEMA_AGENCY_LEN)?;
            }
        }
        if let Some(name) = &oi.name {
            check_max_chars("otherIdentifier.name", name, MAX_OTHER_ID_NAME_LEN)?;
        }
    }
    Ok(())
}

/// Validate the dataset-level `contactPoint` (mandatory `fn`/`hasEmail` when
/// present; recommended `hasURL` sub-field advisory, pushed onto `notes`).
fn validate_contact_point(cp: &ContactPoint, notes: &mut Vec<String>) -> CoreResult<()> {
    let Some(fn_) = &cp.fn_ else {
        return Err(invalid(
            "contactPoint.fn is required when contactPoint is present",
        ));
    };
    if fn_.is_empty() {
        return Err(invalid("contactPoint.fn must not be empty"));
    }
    check_max_chars("contactPoint.fn", fn_, MAX_CONTACT_FN_LEN)?;

    let Some(email) = &cp.has_email else {
        return Err(invalid(
            "contactPoint.hasEmail is required when contactPoint is present",
        ));
    };
    validate_email("contactPoint.hasEmail", email)?;

    match &cp.has_url {
        None => {
            notes.push("recommended sub-field \"hasURL\" is absent on the contactPoint".to_owned());
        }
        Some(url) => validate_url("contactPoint.hasURL", url)?,
    }
    Ok(())
}

/// Validate the `files` section: a VCF group must be present with a `reference`;
/// size/count caps; the `afSourceReference` URL when present.
fn validate_files(p: &PackageYaml, warnings: &mut Vec<String>) -> CoreResult<()> {
    check_max_count("file groups", p.files.len(), MAX_FILE_GROUPS)?;

    let mut vcf_group_count = 0usize;
    for group in &p.files {
        check_max_chars("file category", &group.category, MAX_FILE_CATEGORY_LEN)?;
        if let Some(reference) = &group.reference {
            check_max_chars("file reference", reference, MAX_FILE_CATEGORY_LEN)?;
        }
        if let Some(pr) = &group.precise_reference {
            check_max_chars("file preciseReference", pr, MAX_FILE_CATEGORY_LEN)?;
        }
        check_max_count("files per group", group.files.len(), MAX_FILES_PER_GROUP)?;
        for entry in &group.files {
            let path = match entry {
                PackageFileEntry::Path(path) | PackageFileEntry::WithMeta { path, .. } => path,
            };
            check_max_chars("a file path", path, MAX_FILE_PATH_LEN)?;
        }

        if group.category.eq_ignore_ascii_case("VCF") {
            vcf_group_count += 1;
            validate_vcf_group(group)?;
        } else if !is_recommended_category(&group.category) {
            warnings.push(format!(
                "file category {:?} is not in the recommended set",
                group.category
            ));
        }
    }

    if vcf_group_count == 0 {
        return Err(invalid("a VCF file group is required"));
    }
    // `build` converts only the first VCF group, so a second `category: VCF` group's
    // variants would be dropped from the dataset without a warning: the build self-check
    // cannot catch it, because the recount and `numberOfRecords` both reflect the first
    // group alone. The provider must merge every VCF into one group; multiple files per
    // group is fine.
    if vcf_group_count > 1 {
        return Err(invalid(
            "more than one VCF file group is present, but only the first is converted; \
             merge all VCF files into a single VCF group",
        ));
    }

    // afSourceReference is an optional URL; validate it when present.
    if let Some(asr) = &p.config.af_source_reference {
        validate_url("afSourceReference", asr)?;
    }

    Ok(())
}

/// Validate the VCF group's own requirements: a supported assembly `reference`,
/// and at least one file. The generic size/count caps are applied by the caller.
fn validate_vcf_group(group: &PackageFileGroup) -> CoreResult<()> {
    let Some(reference) = &group.reference else {
        return Err(invalid(
            "the VCF file group must declare a reference (assembly)",
        ));
    };
    // The reference is the dataset assembly: it becomes `convert`'s `opts.assembly`.
    // Validating it here, at the cheapest gate, turns a typo (`hg38`, a trailing space)
    // into a clear message instead of an accession mismatch deep in conversion. The match
    // is case-sensitive with no normalization.
    if !crate::chrom::is_known_assembly(reference) {
        return Err(invalid(&format!(
            "the VCF file group reference (assembly) {reference:?} is not supported (expected GRCh37 or GRCh38)"
        )));
    }
    if group.files.is_empty() {
        return Err(invalid("the VCF file group must contain at least one file"));
    }
    Ok(())
}

/// Validate an operator metadata patch on its own, before it is written to disk.
///
/// [`validate_overlay_result`] is the authoritative check, but it validates the merged
/// metadata and so needs a baseline, which `dataset correct` does not hold: the dataset may
/// not be ingested yet. Without a check here the CLI writes a durable override and reports
/// success for any value, and a correction the node later rejects never takes effect.
///
/// This validates every field the patch sets, with that field's own rule, so a malformed
/// value is caught while the operator can still fix it. [`validate_overlay_result`] still
/// catches whatever only the merge can reveal. Presence rules for fields the patch does not
/// set are not checked here; the baseline supplies those. A field the patch sets to an
/// empty list is checked, because that is a replacement the merge would perform and the
/// node would then reject.
///
/// # Errors
///
/// Returns the first gdi-metadata violation among the patch's set fields.
pub fn validate_patch(patch: &crate::model::MetadataOverlay) -> CoreResult<()> {
    // Exhaustiveness guard: no `..`, so a 16th overlay field fails to compile until someone
    // decides what validating it means. The sibling guards in `overlay_change` and
    // `apply_overlay` exist for the same reason.
    let crate::model::MetadataOverlay {
        title,
        description,
        access_rights,
        applicable_legislation,
        license,
        creator,
        health_category,
        keywords,
        number_of_unique_individuals: _,
        conforms_to,
        type_,
        legal_basis,
        is_referenced_by,
        other_identifier,
        contact_point,
    } = patch;

    if let Some(t) = title {
        validate_localized("title", t, MAX_TITLE_LEN)?;
    }
    if let Some(d) = description {
        validate_localized("description", d, MAX_DESCRIPTION_LEN)?;
    }
    if let Some(ar) = access_rights {
        validate_enum("accessRights", ar, ACCESS_RIGHTS)?;
        validate_iri("accessRights", ar)?;
    }
    if let Some(legislation) = applicable_legislation {
        if legislation.is_empty() {
            return Err(invalid(
                "applicableLegislation must have at least one entry",
            ));
        }
        validate_iri_list("applicableLegislation", legislation)?;
    }
    if let Some(lic) = license {
        if lic.is_empty() {
            return Err(invalid("license must not be empty"));
        }
        validate_iri("license", lic)?;
    }
    if let Some(agents) = creator {
        if agents.is_empty() {
            return Err(invalid("creator must have at least one entry"));
        }
        check_max_count("creator", agents.len(), MAX_CREATORS_COUNT)?;
        for agent in agents {
            if agent.name.is_empty() {
                return Err(invalid("a creator name must not be empty"));
            }
            check_max_chars("a creator name", &agent.name, MAX_CREATOR_NAME_LEN)?;
        }
    }
    if let Some(cats) = health_category {
        if cats.is_empty() {
            return Err(invalid("healthCategory must have at least one entry"));
        }
        for iri in cats {
            validate_iri("healthCategory", iri)?;
            validate_health_category(iri)?;
        }
    }
    if let Some(kws) = keywords {
        check_max_count("keywords", kws.len(), MAX_KEYWORDS_COUNT)?;
        for kw in kws {
            check_max_chars("a keyword", kw, MAX_KEYWORD_LEN)?;
        }
    }
    if let Some(conforms) = conforms_to {
        for iri in conforms {
            validate_iri("conformsTo", iri)?;
            validate_conforms_to(iri)?;
        }
    }
    if let Some(t) = type_ {
        validate_enum("type", t, DATASET_TYPES)?;
        validate_iri("type", t)?;
    }
    if let Some(legal) = legal_basis {
        validate_iri_list("legalBasis", legal)?;
    }
    if let Some(refs) = is_referenced_by {
        validate_iri_list("isReferencedBy", refs)?;
    }
    // The sub-field advisories these two produce are notes, not errors, and a CLI that is
    // about to print its own confirmation has nowhere useful to put them.
    let mut notes = Vec::new();
    if let Some(ids) = other_identifier {
        validate_other_identifiers(ids, &mut notes)?;
    }
    if let Some(cp) = contact_point {
        validate_contact_point(cp, &mut notes)?;
    }
    Ok(())
}

/// Validate a metadata section produced by applying an operator overlay to a
/// dataset's baseline. Runs the same mandatory/recommended/optional/placeholder
/// metadata checks as ingest (catalog membership and the package's
/// files/internal/config are out of scope — an overlay never changes them).
///
/// Returns the non-fatal advisories the section raised, in the same two classes
/// [`validate_package`] uses. `warnings` are things to fix: an omitted recommended-tier
/// field, or the absent EHDS ELI ([`ehds_absent_warning`]). `notes` describe a valid
/// configuration, such as a present optional parent missing a recommended sub-field. The
/// node logs the two classes at different levels, so they stay separate lists.
///
/// # Errors
/// Returns the first gdi-metadata violation (empty mandatory field, bad enum,
/// malformed IRI, duplicate language, oversize value, leftover `REPLACE:` marker).
pub fn validate_overlay_result(m: &ManifestMetadata) -> CoreResult<ValidationReport> {
    let pm = m.as_package_metadata();
    let mut warnings = Vec::new();
    let mut notes = Vec::new();
    reject_replace_markers("metadata", &pm)?;
    validate_core_metadata(&pm, &mut warnings)?;
    validate_recommended(&pm, &mut warnings)?;
    validate_optional_metadata(&pm, &mut notes)?;
    Ok(ValidationReport { warnings, notes })
}

/// Whether `category` is in the recommended file-category set (warn otherwise).
fn is_recommended_category(category: &str) -> bool {
    const RECOMMENDED: &[&str] = &["BAM", "CRAM", "FASTA", "FASTQ", "SAM", "TEXT", "PDF"];
    RECOMMENDED.iter().any(|r| category.eq_ignore_ascii_case(r))
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;
    use crate::error::ErrorClass;

    /// A valid `package.yaml` with every mandatory + recommended field present.
    fn sample_package() -> PackageYaml {
        let raw = include_str!("../tests/fixtures/package.yaml");
        serde_saphyr::from_str(raw).expect("fixture package.yaml parses")
    }

    /// The node catalog allow-list used in tests.
    fn node_catalogs() -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert(
            "gdi-aggregated".to_owned(),
            "Genome of Europe Aggregated Data".to_owned(),
        );
        m
    }

    #[test]
    fn obligation_tiers() {
        let mut p = sample_package();
        // All present -> no warnings, ok.
        let report = validate_package(&p, Some(&node_catalogs())).unwrap();
        assert!(
            report.warnings.is_empty(),
            "expected no warnings, got {:?}",
            report.warnings
        );

        // Missing recommended keywords -> ok + warning naming "keywords".
        p.metadata.keywords = None;
        let report = validate_package(&p, Some(&node_catalogs())).unwrap();
        assert!(report.warnings.iter().any(|w| w.contains("keywords")));

        // Missing mandatory license -> error.
        p.metadata.license = String::new();
        assert!(validate_package(&p, Some(&node_catalogs())).is_err());
    }

    #[test]
    fn multiple_vcf_groups_rejected() {
        // `build` converts only the first `category: VCF` group, so a second group's
        // variants would be dropped without a warning. The provider must merge their VCFs
        // into a single group.
        let mut p = sample_package();
        let first_vcf = p
            .files
            .iter()
            .find(|g| g.category.eq_ignore_ascii_case("VCF"))
            .expect("fixture has a VCF group")
            .clone();
        p.files.push(first_vcf);
        let err = validate_package(&p, Some(&node_catalogs())).unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidManifest);
        assert!(
            format!("{err}").to_lowercase().contains("vcf"),
            "expected a VCF-group message, got: {err}"
        );
    }

    #[test]
    fn replace_marker_in_required_field_rejected() {
        // An init template left with a `REPLACE:` placeholder must fail.
        let mut p = sample_package();
        p.metadata.title = LocalizedText::Plain("REPLACE: Dataset title".to_owned());
        let err = validate_package(&p, Some(&node_catalogs())).unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidManifest);
        assert!(format!("{err}").contains("REPLACE"), "msg: {err}");

        // The license placeholder is likewise rejected.
        let mut p = sample_package();
        p.metadata.license = "REPLACE: License IRI".to_owned();
        let err = validate_package(&p, Some(&node_catalogs())).unwrap_err();
        assert!(format!("{err}").contains("REPLACE"), "msg: {err}");
    }

    #[test]
    fn replace_marker_outside_metadata_is_rejected() {
        // The `init` template plants markers outside `metadata` as well: `config.afSource`,
        // `config.afSourceReference`, `files[].reference` and the VCF path. `afSource` is
        // otherwise bounded only at the node's ingest gate (`validate_bounded_text`), not by
        // this tool-side validator, and flows verbatim into every Beacon response's
        // `frequencyInPopulations[].source`.
        let mut p = sample_package();
        p.config.af_source = Some("REPLACE: study or cohort name".to_owned());
        let err = validate_package(&p, Some(&node_catalogs())).unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidManifest);
        assert!(
            format!("{err}").contains("config.afSource"),
            "the message must name the offending path: {err}"
        );

        // A marker anywhere in `files` is caught by the same walk; no per-field entry.
        let mut p = sample_package();
        p.files[0].reference = Some("REPLACE: GRCh38".to_owned());
        let err = validate_package(&p, Some(&node_catalogs())).unwrap_err();
        assert!(
            format!("{err}").contains("REPLACE"),
            "a marker in `files` must be rejected too: {err}"
        );
    }

    #[test]
    fn missing_recommended_unique_individuals_warns() {
        let mut p = sample_package();
        p.metadata.number_of_unique_individuals = None;
        let report = validate_package(&p, Some(&node_catalogs())).unwrap();
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.contains("numberOfUniqueIndividuals"))
        );
    }

    #[test]
    fn hide_lower_counts_absent_is_silent() {
        // The sample fixture leaves hideLowerCounts unset; it must not warn.
        let p = sample_package();
        assert!(p.config.hide_lower_counts.is_none());
        let report = validate_package(&p, Some(&node_catalogs())).unwrap();
        assert!(
            !report
                .warnings
                .iter()
                .any(|w| w.contains("hideLowerCounts")),
            "absent hideLowerCounts must not warn, got {:?}",
            report.warnings
        );
    }

    #[test]
    fn hide_lower_counts_zero_rejected() {
        // A count floor must be an integer >= 1.
        let mut p = sample_package();
        p.config.hide_lower_counts = Some(0);
        let err = validate_package(&p, Some(&node_catalogs())).unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidManifest);
        assert!(format!("{err}").contains("hideLowerCounts"), "msg: {err}");
    }

    #[test]
    fn hide_lower_counts_one_warns_disabled_and_notes_inert() {
        // A floor of 1 hides nothing (disabled no-op) -> a warning, plus the
        // always-on informational note that it is inert on an aggregated package.
        let mut p = sample_package();
        p.config.hide_lower_counts = Some(1);
        let report = validate_package(&p, Some(&node_catalogs())).unwrap();
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.contains("disables the count floor")),
            "expected the disabled/no-op warning, got {:?}",
            report.warnings
        );
        assert!(
            report
                .notes
                .iter()
                .any(|n| n.contains("inert on an aggregated package")),
            "expected the inert note, got {:?}",
            report.notes
        );
    }

    #[test]
    fn hide_lower_counts_inert_message_is_a_note_not_a_warning() {
        // Declaring `hideLowerCounts` is legitimate: it is recorded for the future
        // sensitive tier. A warning would make `build --strict` fail every build that sets
        // it, so the inert-field message belongs in `notes`.
        let mut p = sample_package();
        p.config.hide_lower_counts = Some(5);
        let report = validate_package(&p, Some(&node_catalogs())).unwrap();
        assert!(
            report
                .notes
                .iter()
                .any(|n| n.contains("recorded but inert")),
            "the inert-field message must be a note, got notes {:?}",
            report.notes
        );
        assert!(
            !report.warnings.iter().any(|w| w.contains("inert")),
            "the inert-field message must not be a warning, got {:?}",
            report.warnings
        );
    }

    #[test]
    fn hide_lower_counts_enabled_notes_inert_only() {
        // A floor > 1 is a valid declared value: no disabled-warning, but still
        // the informational note that it is recorded, not applied here.
        let mut p = sample_package();
        p.config.hide_lower_counts = Some(5);
        let report = validate_package(&p, Some(&node_catalogs())).unwrap();
        assert!(
            !report
                .warnings
                .iter()
                .any(|w| w.contains("disables the count floor")),
            "a floor > 1 must not warn as disabled, got {:?}",
            report.warnings
        );
        assert!(
            report
                .notes
                .iter()
                .any(|n| n.contains("inert on an aggregated package")),
            "expected the inert note, got {:?}",
            report.notes
        );
    }

    #[test]
    fn optional_missing_is_silent() {
        let mut p = sample_package();
        // Drop every optional field: no warnings should result. `description` is mandatory
        // (`DatasetShape` `sh:minCount 1`), so it is not dropped here.
        p.metadata.conforms_to = None;
        p.metadata.type_ = None;
        p.metadata.legal_basis = None;
        p.metadata.is_referenced_by = None;
        p.metadata.other_identifier = None;
        p.metadata.contact_point = None;
        let report = validate_package(&p, Some(&node_catalogs())).unwrap();
        assert!(
            report.warnings.is_empty(),
            "optional fields should not warn, got {:?}",
            report.warnings
        );
    }

    #[test]
    fn missing_description_rejected() {
        let mut p = sample_package();
        p.metadata.description = None;
        let err = validate_package(&p, Some(&node_catalogs())).unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidManifest);
        assert!(
            format!("{err}").contains("description"),
            "error message should name the field: {err}"
        );
    }

    #[test]
    fn unknown_enum_rejected() {
        let mut p = sample_package();
        p.metadata.access_rights = "http://example.org/not-an-access-right".to_owned();
        let err = validate_package(&p, Some(&node_catalogs())).unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidManifest);
    }

    #[test]
    fn prefix_out_of_vocab_rejected() {
        // The {GOE,GDI} vocabulary is enforced at the validate gate, not only at `build`.
        let mut p = sample_package();
        p.metadata.prefix = Some("FOO".to_owned());
        let err = validate_package(&p, Some(&node_catalogs())).unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidManifest);
    }

    #[test]
    fn prefix_goe_gdi_and_absent_accepted() {
        for prefix in [Some("GOE".to_owned()), Some("GDI".to_owned()), None] {
            let mut p = sample_package();
            p.metadata.prefix = prefix.clone();
            assert!(
                validate_package(&p, Some(&node_catalogs())).is_ok(),
                "prefix {prefix:?} should validate"
            );
        }
    }

    #[test]
    fn unknown_catalog_rejected() {
        let mut p = sample_package();
        p.metadata.catalog = "not-a-catalog".to_owned();
        let err = validate_package(&p, Some(&node_catalogs())).unwrap_err();
        assert_eq!(err.class(), ErrorClass::UnknownCatalog);
    }

    #[test]
    fn offline_skips_catalog_check() {
        let mut p = sample_package();
        p.metadata.catalog = "any-catalog".to_owned();
        // None -> offline -> the catalog membership check is skipped.
        validate_package(&p, None).unwrap();
    }

    #[test]
    fn unique_lang_collision_rejected() {
        let mut p = sample_package();
        let mut map = BTreeMap::new();
        map.insert("en".to_owned(), "Title".to_owned());
        map.insert("EN".to_owned(), "Title again".to_owned());
        p.metadata.title = LocalizedText::Map(map);
        let err = validate_package(&p, Some(&node_catalogs())).unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidManifest);
    }

    #[test]
    fn unique_lang_region_collision_rejected() {
        let mut p = sample_package();
        let mut map = BTreeMap::new();
        map.insert("en-US".to_owned(), "color".to_owned());
        map.insert("en-us".to_owned(), "colour".to_owned());
        p.metadata.title = LocalizedText::Map(map);
        assert!(validate_package(&p, Some(&node_catalogs())).is_err());
    }

    #[test]
    fn unique_lang_distinct_regions_allowed() {
        let mut p = sample_package();
        let mut map = BTreeMap::new();
        map.insert("en".to_owned(), "Title".to_owned());
        map.insert("en-GB".to_owned(), "Titel".to_owned());
        p.metadata.title = LocalizedText::Map(map);
        validate_package(&p, Some(&node_catalogs())).unwrap();
    }

    #[test]
    fn ill_formed_lang_tag_rejected() {
        let mut p = sample_package();
        let mut map = BTreeMap::new();
        map.insert("e".to_owned(), "Title".to_owned()); // single-letter primary
        p.metadata.title = LocalizedText::Map(map);
        assert!(validate_package(&p, Some(&node_catalogs())).is_err());
    }

    #[test]
    fn bad_email_rejected() {
        let mut p = sample_package();
        if let Some(cp) = &mut p.metadata.contact_point {
            cp.has_email = Some("data@example.org".to_owned()); // missing mailto:
        }
        assert!(validate_package(&p, Some(&node_catalogs())).is_err());
    }

    #[test]
    fn good_email_accepted() {
        assert!(validate_email("e", "mailto:data@example.org").is_ok());
        assert!(validate_email("e", "mailto:a.b@example.co.uk").is_ok());
        assert!(validate_email("e", "mailto:no-at-sign.com").is_err());
        assert!(validate_email("e", "mailto:no@dot").is_err());
        // `is_mailto_email` edge cases: an empty local part, a domain whose only dot is
        // leading or trailing, and a missing prefix.
        assert!(validate_email("e", "mailto:@gdi.ut.ee").is_err());
        assert!(validate_email("e", "mailto:a@.ee").is_err());
        assert!(validate_email("e", "mailto:a@ut.").is_err());
        assert!(validate_email("e", "data@example.org").is_err());
    }

    #[test]
    fn invalid_iri_rejected() {
        // Case 1: `Url::parse` fails outright, the "is not a valid IRI/URL" branch. Use a
        // hyphenated token rather than a space: the IRIREF-char gate catches a space
        // earlier, so it would not reach the parse-failure branch.
        let mut p = sample_package();
        p.metadata.license = "not-a-url".to_owned();
        let err = validate_package(&p, Some(&node_catalogs())).unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidManifest);
        assert!(
            format!("{err}").contains("license"),
            "error should name the offending field: {err}"
        );
        assert!(
            format!("{err}").contains("not a valid IRI/URL"),
            "error should cite the parse failure: {err}"
        );

        // Case 2: `Url::parse` succeeds and the scheme is allowed, but the IRI has neither
        // a host nor a non-trivial path. `urn:` parses (scheme present, no authority, empty
        // path) and fails the host-or-path check.
        let mut p = sample_package();
        p.metadata.license = "urn:".to_owned();
        let err = validate_package(&p, Some(&node_catalogs())).unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidManifest);
        assert!(
            format!("{err}").contains("license"),
            "error should name the offending field: {err}"
        );
        assert!(
            format!("{err}").contains("has no authority or path"),
            "error should cite the authority/path check: {err}"
        );
    }

    #[test]
    fn disallowed_iri_scheme_rejected() {
        // Schemes that `url::Url::parse` accepts but that must never reach the public FDP
        // RDF: stored-XSS and local-file vectors in a downstream RDF consumer.
        for bad in [
            "javascript:alert(1)",
            "data:text/html,x",
            "file:///etc/passwd",
        ] {
            let mut p = sample_package();
            p.metadata.license = bad.to_owned();
            let Err(err) = validate_package(&p, Some(&node_catalogs())) else {
                panic!("{bad:?} must be rejected")
            };
            assert_eq!(err.class(), ErrorClass::InvalidManifest);
            assert!(
                format!("{err}").contains("disallowed URI scheme"),
                "{bad:?} should be rejected on the scheme allowlist: {err}"
            );
        }
        // An allowed scheme (https, urn, doi) still validates.
        for ok in [
            "https://example.org/license",
            "urn:nbn:fi:1234",
            "doi:10.1234/abcd",
        ] {
            let mut p = sample_package();
            p.metadata.license = ok.to_owned();
            validate_package(&p, Some(&node_catalogs()))
                .unwrap_or_else(|e| panic!("{ok:?} should validate: {e}"));
        }
    }

    #[test]
    fn iri_with_turtle_breaking_chars_rejected() {
        // A value that `url::Url::parse` accepts, by percent-encoding or stripping the
        // dangerous characters, but that would break out of the `<…>` IRIREF the FDP
        // serializer emits verbatim. That is RDF triple injection.
        let injection =
            "http://e.com/a> . <http://attacker/s> <http://attacker/p> <http://attacker/o";
        let mut p = sample_package();
        p.metadata.license = injection.to_owned();
        let err = validate_package(&p, Some(&node_catalogs())).unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidManifest);
        assert!(
            format!("{err}").contains("not allowed in an IRI"),
            "error should cite the IRIREF-char rejection: {err}"
        );

        // A bare space (the simplest malformed IRIREF, which breaks the harvester's
        // whole-document Turtle parse) is likewise rejected on every IRI field.
        for bad in [
            "http://e.com/a b",
            "http://e.com/\u{0}",
            "http://e.com/\"quote",
        ] {
            let mut p = sample_package();
            p.metadata.license = bad.to_owned();
            assert!(
                validate_package(&p, Some(&node_catalogs())).is_err(),
                "{bad:?} must be rejected"
            );
        }

        // A `mailto:` hasEmail carrying an IRIREF-breaking char is rejected too (the
        // email regex `.+` would otherwise match `>`/space/`<`).
        let mut p = sample_package();
        if let Some(cp) = &mut p.metadata.contact_point {
            cp.has_email = Some("mailto:a@b.c> <http://attacker/s> <p> <o".to_owned());
        }
        assert!(validate_package(&p, Some(&node_catalogs())).is_err());
    }

    #[test]
    fn empty_creator_rejected() {
        let mut p = sample_package();
        p.metadata.creator.clear();
        assert!(validate_package(&p, Some(&node_catalogs())).is_err());
    }

    #[test]
    fn empty_applicable_legislation_rejected() {
        let mut p = sample_package();
        p.metadata.applicable_legislation.clear();
        assert!(validate_package(&p, Some(&node_catalogs())).is_err());
    }

    #[test]
    fn title_too_long_rejected() {
        let mut p = sample_package();
        p.metadata.title = LocalizedText::Plain("x".repeat(256));
        assert!(validate_package(&p, Some(&node_catalogs())).is_err());
    }

    #[test]
    fn individual_mode_rejected() {
        let mut p = sample_package();
        p.config.mode = DatasetMode::Individual;
        let err = validate_package(&p, Some(&node_catalogs())).unwrap_err();
        assert!(format!("{err}").contains("not yet supported"));
    }

    #[test]
    fn missing_vcf_reference_rejected() {
        let mut p = sample_package();
        p.files[0].reference = None;
        assert!(validate_package(&p, Some(&node_catalogs())).is_err());
    }

    #[test]
    fn unknown_vcf_assembly_rejected() {
        // A typo'd / unsupported assembly is caught at validation, naming the value
        // and the supported set, rather than failing deep in conversion.
        for bad in ["hg38", "GRCH38", "GRCh38 ", "GRCh36"] {
            let mut p = sample_package();
            p.files[0].reference = Some(bad.to_owned());
            let err = validate_package(&p, Some(&node_catalogs())).unwrap_err();
            assert_eq!(err.class(), ErrorClass::InvalidManifest);
            assert!(
                format!("{err}").contains("GRCh37 or GRCh38"),
                "error should name the supported assemblies for {bad:?}: {err}"
            );
        }
    }

    #[test]
    fn known_vcf_assemblies_accepted() {
        for ok in ["GRCh37", "GRCh38"] {
            let mut p = sample_package();
            p.files[0].reference = Some(ok.to_owned());
            assert!(
                validate_package(&p, Some(&node_catalogs())).is_ok(),
                "{ok} must validate"
            );
        }
    }

    #[test]
    fn collect_all_reports_errors_from_multiple_sections() {
        // Two faults in two independent sections: fail-fast `validate_package`
        // reports only the first; `validate_package_collect_all` reports both.
        let mut p = sample_package();
        p.metadata.license = String::new(); // core-metadata section
        p.files[0].reference = Some("hg38".to_owned()); // files section
        let report = validate_package_collect_all(&p, Some(&node_catalogs()));
        assert!(!report.is_valid());
        assert!(
            report.errors.len() >= 2,
            "expected errors from >=2 sections: {:?}",
            report.errors
        );
        let joined = report
            .errors
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ");
        assert!(
            joined.contains("license"),
            "should report license: {joined}"
        );
        assert!(
            joined.contains("GRCh37 or GRCh38"),
            "should report the assembly fault too: {joined}"
        );
    }

    #[test]
    fn collect_all_clean_package_is_valid() {
        let report = validate_package_collect_all(&sample_package(), Some(&node_catalogs()));
        assert!(report.is_valid(), "errors: {:?}", report.errors);
    }

    #[test]
    fn past_version_not_a_valid_id_rejected() {
        let mut p = sample_package();
        p.internal.past_version = Some("not-a-valid-id".to_owned());
        let err = validate_package(&p, Some(&node_catalogs())).unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidManifest);
        assert!(
            format!("{err}").contains("pastVersion"),
            "error should name pastVersion: {err}"
        );
    }

    #[test]
    fn missing_vcf_group_rejected() {
        let mut p = sample_package();
        // Change the VCF group's category so no VCF group exists.
        p.files[0].category = "BAM".to_owned();
        let err = validate_package(&p, Some(&node_catalogs())).unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidManifest);
        assert!(
            format!("{err}").contains("VCF file group is required"),
            "error should mention 'VCF file group is required': {err}"
        );
    }

    #[test]
    fn empty_vcf_group_files_rejected() {
        let mut p = sample_package();
        // The VCF group is files[0]; clear its files list.
        p.files[0].files.clear();
        let err = validate_package(&p, Some(&node_catalogs())).unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidManifest);
        assert!(
            format!("{err}").contains("at least one file"),
            "error should mention 'at least one file': {err}"
        );
    }

    /// A recommended sub-field of a present optional parent is an advisory, not a warning,
    /// because `build --strict` fails on any warning. Both halves are asserted so a move
    /// back to `warnings` cannot pass.
    #[test]
    fn contact_point_without_url_notes_but_does_not_warn() {
        let mut p = sample_package();
        if let Some(cp) = &mut p.metadata.contact_point {
            cp.has_url = None;
        }
        let report = validate_package(&p, Some(&node_catalogs())).unwrap();
        assert!(report.notes.iter().any(|n| n.contains("hasURL")));
        assert!(
            !report.warnings.iter().any(|w| w.contains("hasURL")),
            "a missing hasURL must never fail --strict: {:?}",
            report.warnings
        );
    }

    #[test]
    fn other_identifier_without_schema_agency_notes_but_does_not_warn() {
        let mut p = sample_package();
        if let Some(ois) = &mut p.metadata.other_identifier {
            ois[0].schema_agency = None;
        }
        let report = validate_package(&p, Some(&node_catalogs())).unwrap();
        assert!(report.notes.iter().any(|n| n.contains("schemaAgency")));
        assert!(
            !report.warnings.iter().any(|w| w.contains("schemaAgency")),
            "a missing schemaAgency must never fail --strict: {:?}",
            report.warnings
        );
    }

    #[test]
    fn unrecognized_file_category_warns() {
        let mut p = sample_package();
        // The fixture's second group is "BAM" (recommended); change to a free string.
        p.files[1].category = "SOMETHING".to_owned();
        let report = validate_package(&p, Some(&node_catalogs())).unwrap();
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.contains("recommended set"))
        );
    }

    #[test]
    fn a_rejected_contact_email_is_not_echoed_into_the_error() {
        // The message must not embed the address. This error travels the ingest error chain
        // into the node's structured log, and the value is a provider contact e-mail from an
        // untrusted package. The field path is what makes the fault fixable.
        let pii = "mailto:alice.example@hospital.example.org";
        let err = validate_email(
            "contactPoint.hasEmail",
            "alice.example@hospital.example.org",
        )
        .expect_err("a bare address is not a mailto: email");
        let msg = format!("{err}");
        assert!(
            !msg.contains("alice.example"),
            "the address must not reach the log: {msg}"
        );
        assert!(
            msg.contains("contactPoint.hasEmail"),
            "the field path must survive, since it is what makes this fixable: {msg}"
        );

        // A valid address still passes.
        validate_email("contactPoint.hasEmail", pii).expect("a well-formed mailto: passes");
    }

    #[test]
    fn validate_patch_rejects_values_the_node_would_reject() {
        // Without this gate `dataset correct` writes a durable override and reports success
        // for any value: the other validation is at apply time (`overlay_store::apply`),
        // which needs a baseline the CLI does not hold. An accessRights downgrade or a PII
        // redaction would then never take effect while the CLI reported success.
        use crate::model::MetadataOverlay;

        let bad_license = MetadataOverlay {
            license: Some("not-an-iri".to_owned()),
            ..MetadataOverlay::default()
        };
        let err = validate_patch(&bad_license).expect_err("a non-IRI license must be rejected");
        assert!(
            format!("{err}").contains("license"),
            "name the field: {err}"
        );

        // A closed vocabulary is enforced, not just IRI shape.
        let bad_access = MetadataOverlay {
            access_rights: Some("https://example.org/not-a-known-access-right".to_owned()),
            ..MetadataOverlay::default()
        };
        assert!(validate_patch(&bad_access).is_err());

        // An empty replacement for a mandatory, non-empty list is a downgrade the merge
        // would produce and the node would then reject.
        let empties = MetadataOverlay {
            creator: Some(vec![]),
            ..MetadataOverlay::default()
        };
        assert!(
            validate_patch(&empties).is_err(),
            "creator must stay non-empty"
        );

        // A well-formed patch passes. An empty patch is not this function's business:
        // `correct_write_only` rejects it with its own message.
        let good = MetadataOverlay {
            license: Some("https://creativecommons.org/licenses/by/4.0/".to_owned()),
            access_rights: Some(ACCESS_RIGHTS[0].to_owned()),
            ..MetadataOverlay::default()
        };
        validate_patch(&good).expect("a well-formed patch must pass");
        validate_patch(&MetadataOverlay::default()).expect("an empty patch validates vacuously");
    }

    /// The IRI-list count cap holds on the overlay path too, at the cap and one over it.
    ///
    /// `validate_iri_list` exists so the package path and `validate_patch` cannot drift on
    /// this cap; this pins the wiring on the overlay side, as
    /// `every_package_cap_is_enforced_at_max_and_max_plus_one` does on the package side.
    /// Without it, dropping the `check_max_count` call from `validate_iri_list`, or calling
    /// `validate_iri` per entry here instead of the list validator, leaves the
    /// `dataset correct` route uncapped with every test green.
    #[test]
    fn every_overlay_iri_list_is_capped_at_max_and_max_plus_one() {
        use crate::model::MetadataOverlay;

        type Setter = fn(&mut MetadataOverlay, usize);
        let cases: &[(&str, Setter)] = &[
            ("applicableLegislation", |p, n| {
                p.applicable_legislation = Some(vec!["https://example.org/x".to_owned(); n]);
            }),
            ("legalBasis", |p, n| {
                p.legal_basis = Some(vec!["https://example.org/x".to_owned(); n]);
            }),
            ("isReferencedBy", |p, n| {
                p.is_referenced_by = Some(vec!["https://example.org/x".to_owned(); n]);
            }),
        ];
        for (field, set) in cases {
            let mut at_max = MetadataOverlay::default();
            set(&mut at_max, MAX_IRI_LIST_COUNT);
            validate_patch(&at_max).unwrap_or_else(|e| {
                panic!("{field}: exactly MAX ({MAX_IRI_LIST_COUNT}) must pass: {e}")
            });

            let mut over = MetadataOverlay::default();
            set(&mut over, MAX_IRI_LIST_COUNT + 1);
            let err = validate_patch(&over)
                .expect_err("MAX+1 entries must be rejected on the overlay path");
            let msg = err.to_string();
            assert!(
                msg.contains(field) && msg.contains("count exceeds"),
                "{field}: the rejection must be the COUNT cap naming the field: {msg}"
            );
        }
    }

    // ── validate_overlay_result tests ──────────────────────────────────────────

    /// A valid `ManifestMetadata` with every mandatory field present.
    fn manifest_metadata_fixture() -> ManifestMetadata {
        use crate::model::Agent;
        ManifestMetadata {
            dataset_id: "GDI-EE-UTARTU-20260409143052837".to_owned(),
            catalog: "gdi-aggregated".to_owned(),
            title: LocalizedText::Plain("COVID monogenic AFs".to_owned()),
            description: Some(LocalizedText::Plain("A description.".to_owned())),
            access_rights: "http://publications.europa.eu/resource/authority/access-right/PUBLIC"
                .to_owned(),
            applicable_legislation: vec!["http://data.europa.eu/eli/reg/2018/1725/oj".to_owned()],
            license: "https://creativecommons.org/licenses/by/4.0/".to_owned(),
            creator: vec![Agent {
                name: "University of Tartu".to_owned(),
            }],
            health_category: vec![
                "http://data.gdi.eu/core/p2/HealthCategoryHumanGenomic".to_owned(),
            ],
            keywords: None,
            number_of_unique_individuals: None,
            conforms_to: None,
            type_: None,
            legal_basis: None,
            is_referenced_by: None,
            other_identifier: None,
            contact_point: None,
            number_of_records: Some(1),
            populations: None,
        }
    }

    #[test]
    fn overlay_result_accepts_a_valid_merge() {
        let mut m = manifest_metadata_fixture();
        m.title = LocalizedText::Plain("A corrected title".to_owned());
        assert!(validate_overlay_result(&m).is_ok());
    }

    #[test]
    fn overlay_result_rejects_empty_mandatory_title() {
        let mut m = manifest_metadata_fixture();
        m.title = LocalizedText::Plain(String::new());
        assert!(validate_overlay_result(&m).is_err());
    }

    #[test]
    fn overlay_result_rejects_bad_access_rights() {
        let mut m = manifest_metadata_fixture();
        m.access_rights = "http://example.org/not-an-access-right".to_owned();
        assert!(validate_overlay_result(&m).is_err());
    }

    #[test]
    fn exposed_field_validators_are_callable() {
        // These compile only if the items are `pub` (this module's tests see them
        // via `super::`, but the assertions also document the contract the wizard relies on).
        assert!(super::validate_email("contactPoint.hasEmail", "mailto:a@b.co").is_ok());
        assert!(super::validate_email("contactPoint.hasEmail", "a@b.co").is_err());
        assert!(super::validate_url("hasURL", "https://example.org").is_ok());
        assert!(
            super::validate_enum(
                "accessRights",
                super::ACCESS_RIGHTS[0],
                super::ACCESS_RIGHTS
            )
            .is_ok()
        );
        assert!(super::validate_enum("accessRights", "PUBLIC", super::ACCESS_RIGHTS).is_err());
        assert!(
            super::validate_health_category(
                "http://data.gdi.eu/core/p2/HealthCategoryHumanGenomic"
            )
            .is_ok()
        );
        assert!(super::validate_conforms_to("http://data.gdi.eu/core/p2/1MGCompliant").is_ok());
        assert!(
            super::validate_iri("license", "https://creativecommons.org/licenses/by/4.0/").is_ok()
        );
        assert_eq!(super::DATASET_TYPES.len(), 1);
    }

    /// Fail-closed: `healthCategory` and `conformsTo` accept only the closed `sh:in` sets,
    /// not any in-namespace value. A namespace-prefix check would let an
    /// in-namespace-but-non-enumerated IRI pass ingest and be served as RDF that a
    /// conforming DCAT harvester rejects against `DatasetShape`.
    #[test]
    fn health_and_conforms_reject_non_enumerated_in_namespace_values() {
        // Every enumerated value is accepted.
        for iri in super::HEALTH_CATEGORIES {
            assert!(
                super::validate_health_category(iri).is_ok(),
                "{iri} rejected"
            );
        }
        for iri in super::CONFORMS_TO {
            assert!(super::validate_conforms_to(iri).is_ok(), "{iri} rejected");
        }
        // In-namespace but not enumerated is rejected. `HealthCategoryGenomic` lacks the
        // `Human` segment; `…Proteomic` is not a member.
        assert!(
            super::validate_health_category("http://data.gdi.eu/core/p2/HealthCategoryGenomic")
                .is_err()
        );
        assert!(
            super::validate_health_category(
                "http://data.gdi.eu/core/p2/HealthCategoryHumanProteomic"
            )
            .is_err()
        );
        // Wrong case and an unrelated core/p2 IRI are rejected for conformsTo: a
        // namespace-prefix check would accept even a health-category IRI here.
        assert!(super::validate_conforms_to("http://data.gdi.eu/core/p2/1MGcompliant").is_err());
        assert!(
            super::validate_conforms_to("http://data.gdi.eu/core/p2/HealthCategoryHumanGenomic")
                .is_err()
        );
    }

    /// A language-map value that is empty must be rejected the same way an empty
    /// `Plain` value is — otherwise a mandatory field emits an empty `""@en`
    /// langString that the gdi-metadata `DatasetShape` rejects.
    #[test]
    fn localized_map_rejects_empty_value() {
        let mut map = std::collections::BTreeMap::new();
        map.insert("en".to_owned(), String::new());
        let text = LocalizedText::Map(map);
        assert!(super::validate_localized("title", &text, MAX_TITLE_LEN).is_err());
    }

    /// Drift guard: the closed Rust sets must stay equal to the `sh:in` lists in the
    /// vendored gdi-metadata `Dataset.ttl`. A re-vendor that changes the controlled
    /// vocabulary must update these consts in the same commit, or this fails.
    #[test]
    fn closed_sets_match_vendored_shape() {
        let ttl = vendored_dataset_shape();
        // (sh:path, Rust const, name) for every closed set `Dataset.ttl` defines as an
        // inline `sh:in ( … )` list. `dct:accessRights` is a blank-node collection
        // (`sh:in _:…`), not an inline list, so `ACCESS_RIGHTS` is not reconstructed here.
        let cases: &[(&str, &[&str], &str)] = &[
            (
                "healthdcatap:healthCategory",
                super::HEALTH_CATEGORIES,
                "HEALTH_CATEGORIES",
            ),
            ("dct:conformsTo", super::CONFORMS_TO, "CONFORMS_TO"),
            ("dct:type", super::DATASET_TYPES, "DATASET_TYPES"),
        ];
        for &(path, konst, name) in cases {
            let vendored = sh_in_iris(&ttl, path);
            let rust: std::collections::BTreeSet<String> =
                konst.iter().map(|s| (*s).to_owned()).collect();
            assert_eq!(
                vendored, rust,
                "{name} has drifted from the vendored Dataset.ttl `sh:in` for `{path}` \
                 — update the const or re-vendor the shape in the same commit"
            );
        }
    }

    /// Prefix to namespace expansions for the CURIEs used inside the `sh:in ( … )` lists of
    /// the vendored `Dataset.ttl`, kept in step with its `@prefix` declarations.
    const TTL_PREFIXES: &[(&str, &str)] = &[
        ("gdi", "http://data.gdi.eu/core/p2/"),
        (
            "type",
            "https://publications.europa.eu/resource/authority/dataset-type/",
        ),
    ];

    /// Expand one `sh:in` member token to a full IRI, accepting both an already-expanded
    /// `<http://…>` form and a `prefix:LOCAL` CURIE (via [`TTL_PREFIXES`]). Returns `None`
    /// for a token in neither form, so a foreign token is dropped rather than mis-mapped.
    /// Accepting both forms means a re-vendor that switches notation does not silently drop
    /// members.
    fn expand_ttl_iri(tok: &str) -> Option<String> {
        if let Some(iri) = tok.strip_prefix('<').and_then(|s| s.strip_suffix('>')) {
            return Some(iri.to_owned());
        }
        TTL_PREFIXES.iter().find_map(|(pfx, ns)| {
            tok.strip_prefix(&format!("{pfx}:"))
                .map(|local| format!("{ns}{local}"))
        })
    }

    /// Extract the `sh:in ( … )` members of the property shape whose `sh:path` is
    /// `path`, as full IRIs (see [`expand_ttl_iri`] for the accepted member forms).
    /// Test-only and simple: it keys on the stable `sh:path`/`sh:in` shape rather than
    /// parsing Turtle, and panics with a message naming `path` if that structure changes,
    /// so a re-vendor that reshapes the file gives an actionable failure.
    fn sh_in_iris(ttl: &str, path: &str) -> std::collections::BTreeSet<String> {
        let after_path = ttl
            .split_once(&format!("sh:path {path}"))
            .unwrap_or_else(|| {
                panic!("Dataset.ttl: no `sh:path {path}` shape (structure changed?)")
            })
            .1;
        // `sh:path {path}` … the property shape's first following inline `sh:in ( … )`.
        let Some((list, _)) = after_path
            .split_once("sh:in")
            .and_then(|(_, rest)| rest.split_once('('))
            .and_then(|(_, rest)| rest.split_once(')'))
        else {
            panic!("Dataset.ttl: no inline `sh:in ( … )` list after `sh:path {path}`")
        };
        list.split_whitespace().filter_map(expand_ttl_iri).collect()
    }

    /// The vendored gdi-metadata `Dataset.ttl`, the source every closed-set drift guard in
    /// this module compares against.
    fn vendored_dataset_shape() -> String {
        let ttl_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../conformance/shapes/gdi-metadata/Dataset.ttl");
        std::fs::read_to_string(&ttl_path).unwrap_or_else(|e| {
            panic!(
                "cannot read vendored shape {} (drift guard for the closed sh:in sets): {e}",
                ttl_path.display()
            )
        })
    }

    /// The `rdfs:label "…"@en` the vendored shape gives the concept named by `curie`
    /// (e.g. `gdi:1MGCompliant`). Test-only and simple, like [`sh_in_iris`]: it keys on the
    /// stable `<curie> a …; rdfs:label "…"` shape and panics with a message naming the
    /// concept if that structure changes.
    fn rdfs_label(ttl: &str, curie: &str) -> String {
        let block = ttl
            .split_once(&format!("\n{curie} a "))
            .unwrap_or_else(|| panic!("Dataset.ttl: no `{curie} a …` concept (structure changed?)"))
            .1;
        // Bound the search to this concept's own statement; the concepts are separated by a
        // blank line. A concept missing its label then cannot borrow the next one's and pass
        // the guard.
        let block = block.split_once("\n\n").map_or(block, |(head, _)| head);
        let (_, rest) = block
            .split_once("rdfs:label \"")
            .unwrap_or_else(|| panic!("Dataset.ttl: `{curie}` carries no `rdfs:label`"));
        rest.split_once('"')
            .unwrap_or_else(|| panic!("Dataset.ttl: unterminated `rdfs:label` on `{curie}`"))
            .0
            .to_owned()
    }

    /// Drift guard: every [`CONFORMS_TO`] member's menu label must be the `rdfs:label` the
    /// vendored shape gives it. The wording is hand-written, because no case-split
    /// derivation turns the IRI tail `1MGCompliant` into "1+MG compliant", so this is what
    /// stops it drifting from the sheet a provider reads.
    #[test]
    fn conforms_to_labels_match_the_vendored_shape() {
        let ttl = vendored_dataset_shape();
        for iri in super::CONFORMS_TO {
            let local = iri.rsplit('/').next().unwrap_or(iri);
            let vendored = rdfs_label(&ttl, &format!("gdi:{local}"));
            assert_eq!(
                super::conforms_to_label(iri),
                vendored,
                "the menu label for {iri} has drifted from the vendored Dataset.ttl \
                 `rdfs:label` — update `conforms_to_label` or re-vendor the shape in the \
                 same commit"
            );
        }
        // A member with no curated label falls back to its IRI tail, which is never the
        // vendored wording. That is how this guard sees a re-vendored, wider set.
        assert_eq!(
            super::conforms_to_label("http://data.gdi.eu/core/p2/SomethingNew"),
            "SomethingNew"
        );
    }

    #[test]
    fn overlay_result_rejects_empty_creator() {
        let mut m = manifest_metadata_fixture();
        m.creator.clear();
        assert!(validate_overlay_result(&m).is_err());
    }

    /// A `conformsTo` value outside the closed set fails the whole-package gate, not just
    /// the field helper, and the rejection names the three allowed IRIs. They differ only in
    /// capitalisation, so "is not allowed" alone leaves a hand-author guessing.
    #[test]
    fn a_conforms_to_value_outside_the_closed_set_fails_the_package() {
        let mut p = sample_package();
        p.metadata.conforms_to = Some(vec!["http://data.gdi.eu/core/p2/1MGcompliant".to_owned()]);
        let err = validate_package(&p, Some(&node_catalogs())).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("conformsTo"), "{msg}");
        for allowed in super::CONFORMS_TO {
            assert!(
                msg.contains(allowed),
                "the rejection must name every allowed IRI; {allowed} missing from: {msg}"
            );
        }
        // Every enumerated value, together, is accepted.
        p.metadata.conforms_to = Some(super::CONFORMS_TO.iter().map(|s| (*s).to_owned()).collect());
        let report = validate_package(&p, Some(&node_catalogs()))
            .expect("the enumerated conformsTo values are accepted");
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    }

    /// A package whose `applicableLegislation` omits the EHDS ELI is valid and warns. The
    /// EHDS ELI is the shape's `sh:defaultValue`, not a fixed value, so removing it is a
    /// provider's call. The cardinality rule (at least one entry) stays a hard error.
    #[test]
    fn an_absent_ehds_eli_warns_instead_of_failing() {
        let mut p = sample_package();
        // The fixture cites the EHDS ELI: no such warning.
        let report = validate_package(&p, Some(&node_catalogs())).unwrap();
        assert!(
            !report.warnings.contains(&ehds_absent_warning()),
            "a package citing the EHDS ELI must not warn: {:?}",
            report.warnings
        );

        // Replaced by another well-formed ELI: still valid, now warns.
        p.metadata.applicable_legislation =
            vec!["http://data.europa.eu/eli/reg/2016/679/oj".to_owned()];
        let report = validate_package(&p, Some(&node_catalogs()))
            .expect("an absent EHDS ELI must not fail the package");
        assert!(
            report.warnings.contains(&ehds_absent_warning()),
            "{:?}",
            report.warnings
        );
        // The tool's collect-all path reports it too (that is what `build` prints).
        let full = validate_package_collect_all(&p, Some(&node_catalogs()));
        assert!(full.is_valid(), "errors: {:?}", full.errors);
        assert!(
            full.warnings.contains(&ehds_absent_warning()),
            "{:?}",
            full.warnings
        );

        // An empty list is still a hard error: the warning does not soften cardinality.
        p.metadata.applicable_legislation.clear();
        assert!(validate_package(&p, Some(&node_catalogs())).is_err());
    }

    /// The same advisory on the node's ingest/overlay path, which validates a manifest's
    /// metadata section rather than a `package.yaml`. The node logs what this returns.
    #[test]
    fn overlay_result_warns_when_the_ehds_eli_is_absent() {
        let mut m = manifest_metadata_fixture();
        // The fixture cites a different ELI.
        let report = validate_overlay_result(&m).expect("a non-EHDS ELI is still valid");
        assert!(
            report.warnings.contains(&ehds_absent_warning()),
            "{report:?}"
        );
        m.applicable_legislation.push(EHDS_ELI.to_owned());
        let report = validate_overlay_result(&m).unwrap();
        assert!(
            !report.warnings.contains(&ehds_absent_warning()),
            "{report:?}"
        );
    }

    /// A note must not be delivered as a warning. The node logs warnings at `warn`, so
    /// merging the two classes would put a "your optional contactPoint has no recommended
    /// hasURL" line in front of an operator once per dataset per ingest. This pins the same
    /// split [`validate_package`] keeps, on the overlay/ingest entry point.
    #[test]
    fn overlay_result_keeps_notes_out_of_the_warnings() {
        let mut m = manifest_metadata_fixture();
        // A complete-but-unenriched optional parent: the note case.
        m.contact_point = Some(ContactPoint {
            fn_: Some("Data team".to_owned()),
            has_email: Some("mailto:data@example.org".to_owned()),
            has_url: None,
        });
        // Fill the recommended tier so the only remaining advisories are the note and the
        // absent-EHDS warning; otherwise "warnings is non-empty" proves nothing.
        m.keywords = Some(vec!["genomics".to_owned()]);
        m.number_of_unique_individuals = Some(1200);

        let report = validate_overlay_result(&m).expect("a note is not a rejection");
        assert!(
            report.notes.iter().any(|n| n.contains("hasURL")),
            "the sub-field advisory must be a NOTE: {report:?}"
        );
        assert!(
            !report.warnings.iter().any(|w| w.contains("hasURL")),
            "a note must never arrive as a warning: {report:?}"
        );
        assert_eq!(
            report.warnings,
            vec![ehds_absent_warning()],
            "the only warning here is the absent EHDS ELI: {report:?}"
        );
    }

    // ── Boundary tests for the size/count caps ─────────────────────────────────
    //
    // Each test asserts both sides of a `> MAX` comparison: an input of size MAX+1 is
    // rejected and one of size exactly MAX is accepted. Without both, a cap that accepts
    // arbitrarily oversize input and one that false-rejects the exactly-MAX value are
    // indistinguishable. The MAX-length value is always a valid value of that exact length,
    // so only the length check can reject it; an over-long garbage string would trip a
    // later parse step instead.

    // -- directly-callable helpers --

    #[test]
    fn iri_length_cap_boundary() {
        // A valid https IRI of exactly MAX chars passes; one char more is rejected.
        let base = "https://e.org/";
        let at_max = format!("{base}{}", "a".repeat(MAX_IRI_LEN - base.len()));
        assert_eq!(at_max.chars().count(), MAX_IRI_LEN);
        assert!(
            validate_iri("iri", &at_max).is_ok(),
            "exactly MAX must pass"
        );
        let over = format!("{base}{}", "a".repeat(MAX_IRI_LEN + 1 - base.len()));
        assert_eq!(over.chars().count(), MAX_IRI_LEN + 1);
        assert!(
            validate_iri("iri", &over).is_err(),
            "MAX+1 must be rejected"
        );
    }

    #[test]
    fn url_length_cap_boundary() {
        let base = "https://e.org/";
        let at_max = format!("{base}{}", "a".repeat(MAX_URL_LEN - base.len()));
        assert_eq!(at_max.chars().count(), MAX_URL_LEN);
        assert!(
            validate_url("url", &at_max).is_ok(),
            "exactly MAX must pass"
        );
        let over = format!("{base}{}", "a".repeat(MAX_URL_LEN + 1 - base.len()));
        assert!(
            validate_url("url", &over).is_err(),
            "MAX+1 must be rejected"
        );
    }

    #[test]
    fn email_length_cap_boundary() {
        // Fixed framing "mailto:" (7) + "@e.org" (6); the local part fills the rest,
        // so the value is a valid mailto email of the exact target length.
        let framing = "mailto:".len() + "@e.org".len();
        let at_max = format!("mailto:{}@e.org", "a".repeat(MAX_EMAIL_LEN - framing));
        assert_eq!(at_max.chars().count(), MAX_EMAIL_LEN);
        assert!(
            validate_email("email", &at_max).is_ok(),
            "exactly MAX must pass"
        );
        let over = format!("mailto:{}@e.org", "a".repeat(MAX_EMAIL_LEN + 1 - framing));
        assert_eq!(over.chars().count(), MAX_EMAIL_LEN + 1);
        assert!(
            validate_email("email", &over).is_err(),
            "MAX+1 must be rejected"
        );
    }

    #[test]
    fn localized_entries_count_cap_boundary() {
        // MAX_LOCALIZED_ENTRIES distinct valid BCP-47 keys is accepted; one more is
        // rejected. The generous `max_value_len` (100) ensures only the entry-count
        // check can fire, and the keys ("aa".."ay") are all well-formed and distinct.
        let alphabet = b"abcdefghijklmnopqrstuvwxyz";
        let keys = |n: usize| -> BTreeMap<String, String> {
            alphabet
                .iter()
                .take(n)
                .map(|&c| (format!("a{}", c as char), "v".to_owned()))
                .collect()
        };
        let at_max = LocalizedText::Map(keys(MAX_LOCALIZED_ENTRIES));
        assert!(
            validate_localized("t", &at_max, 100).is_ok(),
            "exactly MAX entries must pass"
        );
        let over = LocalizedText::Map(keys(MAX_LOCALIZED_ENTRIES + 1));
        assert!(
            validate_localized("t", &over, 100).is_err(),
            "MAX+1 entries must be rejected"
        );
    }

    #[test]
    fn localized_value_len_cap_boundary() {
        // Covers both the `Plain` and the map-value length checks with a small
        // caller-controlled max, so the value-length check is the sole gate.
        const MAX: usize = 5;
        assert!(
            validate_localized("t", &LocalizedText::Plain("a".repeat(MAX)), MAX).is_ok(),
            "Plain exactly MAX must pass"
        );
        assert!(
            validate_localized("t", &LocalizedText::Plain("a".repeat(MAX + 1)), MAX).is_err(),
            "Plain MAX+1 must be rejected"
        );
        let map_of = |len: usize| {
            let mut m = BTreeMap::new();
            m.insert("en".to_owned(), "a".repeat(len));
            LocalizedText::Map(m)
        };
        assert!(
            validate_localized("t", &map_of(MAX), MAX).is_ok(),
            "Map value exactly MAX must pass"
        );
        assert!(
            validate_localized("t", &map_of(MAX + 1), MAX).is_err(),
            "Map value MAX+1 must be rejected"
        );
    }

    #[test]
    fn other_identifiers_count_cap_boundary() {
        let mut w = Vec::new();
        let ids = |n: usize| -> Vec<crate::model::OtherIdentifier> {
            (0..n)
                .map(|_| crate::model::OtherIdentifier {
                    notation: "n".to_owned(),
                    schema_agency: Some("DataCite".to_owned()),
                    name: None,
                })
                .collect()
        };
        assert!(
            validate_other_identifiers(&ids(MAX_OTHER_IDS_COUNT), &mut w).is_ok(),
            "exactly MAX ids must pass"
        );
        assert!(
            validate_other_identifiers(&ids(MAX_OTHER_IDS_COUNT + 1), &mut w).is_err(),
            "MAX+1 ids must be rejected"
        );
    }

    #[test]
    fn other_identifier_notation_len_cap_boundary() {
        let mut w = Vec::new();
        let one = |len: usize| {
            vec![crate::model::OtherIdentifier {
                notation: "a".repeat(len),
                schema_agency: Some("DataCite".to_owned()),
                name: None,
            }]
        };
        assert!(
            validate_other_identifiers(&one(MAX_NOTATION_LEN), &mut w).is_ok(),
            "exactly MAX notation must pass"
        );
        assert!(
            validate_other_identifiers(&one(MAX_NOTATION_LEN + 1), &mut w).is_err(),
            "MAX+1 notation must be rejected"
        );
    }

    #[test]
    fn other_identifier_schema_agency_len_cap_boundary() {
        let mut w = Vec::new();
        let one = |len: usize| {
            vec![crate::model::OtherIdentifier {
                notation: "n".to_owned(),
                schema_agency: Some("a".repeat(len)),
                name: None,
            }]
        };
        assert!(
            validate_other_identifiers(&one(MAX_SCHEMA_AGENCY_LEN), &mut w).is_ok(),
            "exactly MAX schemaAgency must pass"
        );
        assert!(
            validate_other_identifiers(&one(MAX_SCHEMA_AGENCY_LEN + 1), &mut w).is_err(),
            "MAX+1 schemaAgency must be rejected"
        );
    }

    #[test]
    fn other_identifier_name_len_cap_boundary() {
        let mut w = Vec::new();
        let one = |len: usize| {
            vec![crate::model::OtherIdentifier {
                notation: "n".to_owned(),
                schema_agency: Some("DataCite".to_owned()),
                name: Some("a".repeat(len)),
            }]
        };
        assert!(
            validate_other_identifiers(&one(MAX_OTHER_ID_NAME_LEN), &mut w).is_ok(),
            "exactly MAX name must pass"
        );
        assert!(
            validate_other_identifiers(&one(MAX_OTHER_ID_NAME_LEN + 1), &mut w).is_err(),
            "MAX+1 name must be rejected"
        );
    }

    // -- logic-bug survivors (not length caps) --

    #[test]
    fn canonical_bcp47_rejects_ill_formed_subtags() {
        // Each ill-formed case makes exactly one of the subtag check's two disjuncts (bad
        // length, non-alphanumeric) true, so neither may be dropped.
        assert!(
            canonical_bcp47("en-u_s").is_none(),
            "non-alphanumeric subtag must be rejected"
        );
        assert!(
            canonical_bcp47("en-").is_none(),
            "empty trailing subtag must be rejected"
        );
        assert!(
            canonical_bcp47("en-US").is_some(),
            "a well-formed tag must canonicalise"
        );
    }

    #[test]
    fn iri_host_only_accepted() {
        // A host-only IRI (host present, path "/") must pass.
        assert!(validate_iri("license", "https://example.org").is_ok());
    }

    // -- fixture-based caps (mutate one field of a valid package) --

    /// Every package-level cap is enforced at MAX and rejected at MAX+1.
    ///
    /// The comparison itself lives in two shared helpers (`check_max_chars`,
    /// `check_max_count`) plus four inline sites, so one case per helper would cover it.
    /// What the table below carries is the wiring: that each field is capped at all, and
    /// against its own constant rather than a neighbouring one. Deleting a `check_max_*`
    /// call site or swapping two constants fails here.
    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "a data table: the length is one row per capped field, which is the point \
                  of collapsing fifteen tests into it. Splitting it would put the cases and \
                  the assertions in different functions for no gain."
    )]
    fn every_package_cap_is_enforced_at_max_and_max_plus_one() {
        use crate::model::{Agent, PackageFileEntry};

        // `n` is the cap in the field's own units: characters for a length cap, elements
        // for a count cap. Non-capturing, so these coerce to plain fn pointers.
        type Setter = fn(&mut PackageYaml, usize);
        /// `false` validates offline (`catalogs: None`). Only `metadata.catalog` needs it:
        /// with an allow-list present, an over-long catalog name fails membership before the
        /// length gate, so the test would pass for the wrong reason. Carried per case rather
        /// than special-cased in the loop, so the exception is visible.
        type WithCatalogs = bool;
        let cases: &[(&str, usize, Setter, WithCatalogs)] = &[
            (
                "metadata.title",
                MAX_TITLE_LEN,
                |p, n| {
                    p.metadata.title = LocalizedText::Plain("a".repeat(n));
                },
                true,
            ),
            (
                "metadata.description",
                MAX_DESCRIPTION_LEN,
                |p, n| {
                    p.metadata.description = Some(LocalizedText::Plain("a".repeat(n)));
                },
                true,
            ),
            (
                "metadata.catalog",
                MAX_CATALOG_LEN,
                |p, n| {
                    p.metadata.catalog = "a".repeat(n);
                },
                false,
            ),
            (
                "metadata.keywords[]",
                MAX_KEYWORD_LEN,
                |p, n| {
                    p.metadata.keywords = Some(vec!["a".repeat(n)]);
                },
                true,
            ),
            (
                "metadata.keywords.len",
                MAX_KEYWORDS_COUNT,
                |p, n| {
                    p.metadata.keywords = Some(vec!["k".to_owned(); n]);
                },
                true,
            ),
            (
                "metadata.creator.len",
                MAX_CREATORS_COUNT,
                |p, n| {
                    p.metadata.creator = vec![
                        Agent {
                            name: "x".to_owned()
                        };
                        n
                    ];
                },
                true,
            ),
            // The three plain IRI-list fields share one cap through `validate_iri_list`;
            // each is wired separately, so each gets a row.
            (
                "metadata.applicableLegislation.len",
                MAX_IRI_LIST_COUNT,
                |p, n| {
                    p.metadata.applicable_legislation =
                        vec!["https://example.org/legislation".to_owned(); n];
                },
                true,
            ),
            (
                "metadata.legalBasis.len",
                MAX_IRI_LIST_COUNT,
                |p, n| {
                    p.metadata.legal_basis =
                        Some(vec!["https://example.org/legal-basis".to_owned(); n]);
                },
                true,
            ),
            (
                "metadata.isReferencedBy.len",
                MAX_IRI_LIST_COUNT,
                |p, n| {
                    p.metadata.is_referenced_by =
                        Some(vec!["https://example.org/reference".to_owned(); n]);
                },
                true,
            ),
            (
                "metadata.creator[].name",
                MAX_CREATOR_NAME_LEN,
                |p, n| {
                    p.metadata.creator = vec![Agent {
                        name: "a".repeat(n),
                    }];
                },
                true,
            ),
            (
                "metadata.contactPoint.fn",
                MAX_CONTACT_FN_LEN,
                |p, n| {
                    p.metadata
                        .contact_point
                        .as_mut()
                        .expect("fixture has a contactPoint")
                        .fn_ = Some("a".repeat(n));
                },
                true,
            ),
            (
                "internal.internalId",
                MAX_INTERNAL_ID_LEN,
                |p, n| {
                    p.internal.internal_id = Some("a".repeat(n));
                },
                true,
            ),
            (
                "files.len",
                MAX_FILE_GROUPS,
                |p, n| {
                    // `build` converts only the first VCF group, so a package may carry at
                    // most one (`multiple_vcf_groups_rejected`). Pad with the fixture's
                    // non-VCF group so this exercises the group-count cap and nothing else.
                    let vcf = p.files[0].clone();
                    let non_vcf = p.files[1].clone();
                    p.files = std::iter::once(vcf)
                        .chain(std::iter::repeat_n(non_vcf, n - 1))
                        .collect();
                },
                true,
            ),
            (
                "files[0].files.len",
                MAX_FILES_PER_GROUP,
                |p, n| {
                    // Mutate the VCF group so the has-VCF requirement stays satisfied.
                    p.files[0].files = vec![PackageFileEntry::Path("f.vcf".to_owned()); n];
                },
                true,
            ),
            (
                "files[0].files[].path",
                MAX_FILE_PATH_LEN,
                |p, n| {
                    p.files[0].files = vec![PackageFileEntry::Path("a".repeat(n))];
                },
                true,
            ),
            (
                "files[1].category",
                MAX_FILE_CATEGORY_LEN,
                |p, n| {
                    p.files[1].category = "a".repeat(n);
                },
                true,
            ),
            (
                "files[1].reference",
                MAX_FILE_CATEGORY_LEN,
                |p, n| {
                    p.files[1].reference = Some("a".repeat(n));
                },
                true,
            ),
            (
                "files[1].preciseReference",
                MAX_FILE_CATEGORY_LEN,
                |p, n| {
                    p.files[1].precise_reference = Some("a".repeat(n));
                },
                true,
            ),
        ];

        let catalogs = node_catalogs();
        for (field, cap, set, with_catalogs) in cases {
            let allow = with_catalogs.then_some(&catalogs);

            let mut at_max = sample_package();
            set(&mut at_max, *cap);
            assert!(
                validate_package(&at_max, allow).is_ok(),
                "{field}: exactly MAX ({cap}) must pass"
            );

            let mut over = sample_package();
            set(&mut over, cap + 1);
            assert!(
                validate_package(&over, allow).is_err(),
                "{field}: MAX+1 ({}) must be rejected",
                cap + 1
            );
        }
    }
}
