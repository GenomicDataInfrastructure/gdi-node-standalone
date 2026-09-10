//! Controlled vocabularies + pure per-field resolvers for the wizard's author flow.
//!
//! Each resolver returns `Ok(normalized)` or `Err(message)` so it can back a
//! [`crate::wizard::prompts::Prompter::input_validated`] validator and be unit-tested
//! without any terminal. Validation reuses `gdi_node_standalone_core::validate_pkg` so the
//! wizard's checks never drift from the build/validate gate.

use gdi_node_standalone_core::chrom::is_known_assembly;
use gdi_node_standalone_core::validate_pkg::{ACCESS_RIGHTS, validate_email, validate_iri};

/// The assembly labels the build/validate path accepts (case-sensitive) — re-exported
/// from `core::chrom`, the single source.
pub use gdi_node_standalone_core::chrom::KNOWN_ASSEMBLIES as ASSEMBLIES;
/// The dataset-id prefixes — re-exported from `core::id`, the single source (the ID
/// regex, the mint-time check, and `validate_pkg` all read the same constant).
pub use gdi_node_standalone_core::id::DATASET_ID_PREFIXES as PREFIXES;

/// The last path segment of a closed-set IRI — the raw material for menu labels, so a
/// re-vendored, wider set reaches the wizard menus with zero wizard edits.
#[must_use]
pub fn iri_tail(iri: &str) -> &str {
    iri.rsplit('/').next().unwrap_or(iri)
}

/// Menu labels for [`ACCESS_RIGHTS`], index-aligned, derived from the authority IRIs
/// (`…/PUBLIC` → "PUBLIC") instead of a hand-kept twin list that could drift.
#[must_use]
pub fn access_right_labels() -> Vec<String> {
    ACCESS_RIGHTS
        .iter()
        .map(|iri| iri_tail(iri).to_owned())
        .collect()
}

/// The menu label for a health-category IRI, derived from the IRI itself:
/// `…/HealthCategoryHumanGenomic` → "Human genomic". Derivation (not a hand list) is
/// what makes a re-vendored, wider `HEALTH_CATEGORIES` appear in the wizard for free.
#[must_use]
pub fn health_category_label(iri: &str) -> String {
    let tail = iri_tail(iri);
    let concept = tail.strip_prefix("HealthCategory").unwrap_or(tail);
    let mut label = String::with_capacity(concept.len() + 4);
    for (i, c) in concept.chars().enumerate() {
        if c.is_ascii_uppercase() && i > 0 {
            label.push(' ');
            label.push(c.to_ascii_lowercase());
        } else {
            label.push(c);
        }
    }
    label
}
/// The EHDS ELI pre-checked in `applicableLegislation` — `core`'s constant is the single
/// source (the node's absent-EHDS warning reads the same one), so this is a binding, not
/// a second copy of the value.
pub const EHDS_ELI: &str = gdi_node_standalone_core::validate_pkg::EHDS_ELI;
/// The GDPR ELI, pre-checked in `applicableLegislation` when the dataset discloses
/// personal data (see `author::gdpr_default`).
pub const GDPR_ELI: &str = "http://data.europa.eu/eli/reg/2016/679/oj";
/// The single dataset-type IRI for synthetic data — `core`'s closed set is the single
/// source; this is a binding, not a second copy of the value.
pub const SYNTHETIC_TYPE_IRI: &str = gdi_node_standalone_core::validate_pkg::DATASET_TYPES[0];
/// The standard Genome of Europe `config.afSource` value — what MAP stage-1 (`GoE`)
/// datasets carry, and what the legacy production beacon emitted for every response.
/// Single-sourced here so the wizard's offer and the `init` template's example
/// cannot drift.
pub const GOE_AF_SOURCE: &str = "The Genome of Europe";
/// The `config.afSourceReference` URL paired with [`GOE_AF_SOURCE`].
pub const GOE_AF_SOURCE_REFERENCE: &str = "https://genomeofeurope.eu/";
/// Curated license suggestions: (label, IRI).
///
/// EU Publications Office licence-authority IRIs, not the creativecommons.org deed URLs.
/// Catalog harvesters resolve a display label by dereferencing the IRI for RDF, which the
/// authority serves as a multilingual `skos:prefLabel` and the deed pages do not, so a deed
/// URL renders as a raw
/// URL (or, with its trailing slash, as "not available") in a portal's distribution
/// view. "Other (enter IRI)" still accepts any IRI the validator passes.
pub const LICENSE_SUGGESTIONS: &[(&str, &str)] = &[
    (
        "CC BY 4.0: reuse with attribution (typical for public aggregated data)",
        "http://publications.europa.eu/resource/authority/licence/CC_BY_4_0",
    ),
    (
        "CC0 1.0: public domain (typical for synthetic data)",
        "http://publications.europa.eu/resource/authority/licence/CC0",
    ),
];
/// The health-category choices: every IRI of the vendored closed set with its derived
/// label, in set order. The node rejects any IRI outside the set, so there is no
/// "Other" escape to offer.
#[must_use]
pub fn health_category_choices() -> Vec<(String, &'static str)> {
    gdi_node_standalone_core::validate_pkg::HEALTH_CATEGORIES
        .iter()
        .map(|iri| (health_category_label(iri), *iri))
        .collect()
}

/// The `conformsTo` choices: every IRI of the vendored closed set with the label the
/// shape gives it (`core::validate_pkg::conforms_to_label`), in set order.
///
/// Like [`health_category_choices`] the set is closed — the node rejects any IRI outside
/// it — so there is no "Other" escape to offer; unlike it, the labels are curated in
/// `core` beside the set (no case-split derivation turns `1MGCompliant` into
/// "1+MG compliant"), and a drift guard there ties them to the shape's `rdfs:label`.
#[must_use]
pub fn conforms_to_choices() -> Vec<(String, &'static str)> {
    gdi_node_standalone_core::validate_pkg::CONFORMS_TO
        .iter()
        .map(|iri| {
            (
                gdi_node_standalone_core::validate_pkg::conforms_to_label(iri).to_owned(),
                *iri,
            )
        })
        .collect()
}

/// The full access-right authority IRI for an [`access_right_labels`] index.
#[must_use]
pub fn access_right_iri(idx: usize) -> &'static str {
    ACCESS_RIGHTS[idx.min(ACCESS_RIGHTS.len() - 1)]
}

/// Resolve + validate an assembly label (case-sensitive `GRCh37`/`GRCh38`).
///
/// # Errors
/// `Err(message)` when the value is not a known assembly.
pub fn resolve_assembly(s: &str) -> Result<String, String> {
    if is_known_assembly(s) {
        Ok(s.to_owned())
    } else {
        Err(format!(
            "assembly must be one of {ASSEMBLIES:?} (case-sensitive)"
        ))
    }
}

/// Resolve + validate a `mailto:` email via the core validator.
///
/// # Errors
/// `Err(message)` when the value is not a valid `mailto:` email.
pub fn resolve_email(s: &str) -> Result<String, String> {
    validate_email("hasEmail", s)
        .map(|()| s.to_owned())
        .map_err(|e| e.to_string())
}

/// Resolve + validate an IRI field via the core validator.
///
/// # Errors
/// `Err(message)` when the value is not a valid IRI.
pub fn resolve_iri(field: &str, s: &str) -> Result<String, String> {
    validate_iri(field, s)
        .map(|()| s.to_owned())
        .map_err(|e| e.to_string())
}

/// Resolve + validate a health-category IRI against the vendored closed set (the node
/// rejects anything else, so accepting it at a prompt would only defer the failure).
///
/// # Errors
/// `Err(message)` naming the allowed values when `s` is not in the set.
pub fn resolve_health_category(s: &str) -> Result<String, String> {
    let t = s.trim();
    if gdi_node_standalone_core::validate_pkg::HEALTH_CATEGORIES.contains(&t) {
        Ok(t.to_owned())
    } else {
        Err(format!(
            "healthCategory must be one of the closed set: {}",
            gdi_node_standalone_core::validate_pkg::HEALTH_CATEGORIES.join(", ")
        ))
    }
}

/// Resolve a required free-text field bounded by `core`'s own cap (trims; rejects
/// empty and over-long answers), so a too-long value fails at its prompt — re-asked
/// inline — instead of in a lump at the review loop after the last question. The cap is
/// the exported `validate_pkg` constant, so a cap change flows to the prompt for free.
///
/// # Errors
/// `Err(message)` when the trimmed value is empty or exceeds `max_chars`.
pub fn resolve_bounded(field: &str, s: &str, max_chars: usize) -> Result<String, String> {
    let t = resolve_nonempty(field, s)?;
    if t.chars().count() > max_chars {
        return Err(format!("{field} exceeds the {max_chars}-char limit"));
    }
    Ok(t)
}

/// Resolve a required non-empty field (trims; rejects empty/whitespace).
///
/// # Errors
/// `Err(message)` when the trimmed value is empty.
pub fn resolve_nonempty(field: &str, s: &str) -> Result<String, String> {
    let t = s.trim();
    if t.is_empty() {
        Err(format!("{field} must not be empty"))
    } else {
        Ok(t.to_owned())
    }
}

/// Maximum profile-name length (matches the config `catalog name` cap spirit).
const MAX_PROFILE_NAME_LEN: usize = 64;

/// Resolve + validate a profile name: a lowercase identifier `[a-z][a-z0-9_]*`
/// (trimmed, ≤ `MAX_PROFILE_NAME_LEN`).
///
/// The charset is narrow for two reasons:
/// 1. **Env-overlay round-trip.** S3 credentials are supplied via
///    `GDI_TOOL__PROFILES__<NAME>__…`, which figment splits on `__` and lowercases —
///    so an env override can only ever address a *lowercase* profile key. A stored
///    name with uppercase or a `-` (e.g. `Prod`, `ee-prod`) would never receive its
///    credentials (they'd land in a phantom `prod`/`ee_prod` key), and `upload` would
///    fail "missing credentials" despite a correctly-filled `secrets.env`. Restricting
///    the name to what the env overlay can spell keeps the config key and the override
///    key in lockstep. See [`gdi_node_standalone_core::config::ToolConfig::phantom_profile_twins`].
/// 2. **Path safety.** The name is interpolated into filesystem paths (the pinned
///    recipient `recipients/{name}.pub`); rejecting `/`, `.` and `..` prevents a name
///    from escaping the config directory.
///
/// # Errors
/// `Err(message)` when the trimmed value is empty, too long, or contains a character
/// outside `[a-z0-9_]` / does not start with a lowercase letter.
pub fn resolve_profile_name(s: &str) -> Result<String, String> {
    let t = s.trim();
    if t.is_empty() {
        return Err("profile name must not be empty".to_owned());
    }
    if t.len() > MAX_PROFILE_NAME_LEN {
        return Err(format!(
            "profile name must be at most {MAX_PROFILE_NAME_LEN} characters"
        ));
    }
    let mut chars = t.chars();
    let first_ok = chars.next().is_some_and(|c| c.is_ascii_lowercase());
    let rest_ok = chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if first_ok && rest_ok {
        Ok(t.to_owned())
    } else {
        Err(
            "profile name must be a lowercase identifier: start with a-z, then a-z / 0-9 / _ \
             (no uppercase, hyphens, or path characters)"
                .to_owned(),
        )
    }
}

/// Validate + normalize a two-letter country code, mirroring `core::id`'s dataset-id
/// rule (exactly two uppercase ASCII letters). Accepts lower-case and up-cases it, so
/// a typo like a 3-letter code is caught inline in the wizard rather than failing late
/// at the build stage.
///
/// # Errors
/// A message when `s` (trimmed) is not exactly two ASCII letters.
pub fn resolve_country_code(s: &str) -> Result<String, String> {
    let t = s.trim().to_ascii_uppercase();
    if t.len() == 2 && t.bytes().all(|b| b.is_ascii_uppercase()) {
        Ok(t)
    } else {
        Err("country code must be exactly two ASCII letters (e.g. EE)".to_owned())
    }
}

/// Validate + normalize the provider org abbreviation, mirroring `core::id`'s rule
/// (1..=16 uppercase ASCII letters). Accepts lower-case and up-cases it, so a bad
/// value is caught inline rather than failing late at build.
///
/// # Errors
/// A message when `s` (trimmed) is empty, over 16 chars, or not all ASCII letters.
pub fn resolve_org(s: &str) -> Result<String, String> {
    let t = s.trim().to_ascii_uppercase();
    if (1..=16).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_uppercase()) {
        Ok(t)
    } else {
        Err("org must be 1 to 16 ASCII letters (e.g. EXAMPLE)".to_owned())
    }
}

/// Resolve a non-negative integer field.
///
/// # Errors
/// `Err(message)` when the value does not parse as a `u64`.
pub fn resolve_u64(field: &str, s: &str) -> Result<u64, String> {
    s.trim()
        .parse::<u64>()
        .map_err(|_| format!("{field} must be a non-negative whole number"))
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;

    #[test]
    fn org_and_country_code_resolvers_enforce_id_rules() {
        // Up-case and validate against core::id's dataset-id rules.
        assert_eq!(resolve_country_code(" ee ").unwrap(), "EE");
        assert!(resolve_country_code("USA").is_err()); // 3 letters
        assert!(resolve_country_code("F1").is_err()); // non-letter
        assert!(resolve_country_code("").is_err());
        assert_eq!(resolve_org("utartu").unwrap(), "UTARTU");
        assert!(resolve_org("").is_err());
        assert!(resolve_org("A234567890123456X").is_err()); // 17 chars > 16
        assert!(resolve_org("TH-L").is_err()); // non-letter
    }

    #[test]
    fn profile_name_resolver_enforces_lowercase_identifier() {
        // The default and typical names pass.
        assert_eq!(resolve_profile_name("default").unwrap(), "default");
        assert_eq!(resolve_profile_name(" ee_prod ").unwrap(), "ee_prod");
        assert_eq!(resolve_profile_name("node2").unwrap(), "node2");
        // Uppercase and hyphens are rejected: the env overlay can't address them, so
        // credentials would silently never apply.
        assert!(resolve_profile_name("Prod").is_err());
        assert!(resolve_profile_name("Estonia").is_err());
        assert!(resolve_profile_name("ee-prod").is_err());
        // Path characters are rejected: pinned-recipient path traversal.
        assert!(resolve_profile_name("../../tmp/x").is_err());
        assert!(resolve_profile_name("a/b").is_err());
        // Must start with a letter; empty is rejected.
        assert!(resolve_profile_name("2node").is_err());
        assert!(resolve_profile_name("_x").is_err());
        assert!(resolve_profile_name("   ").is_err());
    }

    #[test]
    fn assembly_resolver_matches_core() {
        assert_eq!(resolve_assembly("GRCh38").unwrap(), "GRCh38");
        assert!(resolve_assembly("hg38").is_err());
        assert!(resolve_assembly("GRCH38").is_err()); // case-sensitive, like core
    }

    #[test]
    fn email_resolver_requires_mailto() {
        assert!(resolve_email("mailto:a@b.co").is_ok());
        assert!(resolve_email("a@b.co").is_err());
    }

    #[test]
    fn iri_resolver_rejects_unsafe() {
        assert!(resolve_iri("license", "https://creativecommons.org/licenses/by/4.0/").is_ok());
        assert!(resolve_iri("license", "not a url").is_err());
    }

    #[test]
    fn access_right_idx_maps_to_full_iri() {
        assert!(access_right_iri(0).ends_with("/PUBLIC"));
        assert_eq!(
            access_right_iri(0),
            gdi_node_standalone_core::validate_pkg::ACCESS_RIGHTS[0]
        );
        // Labels are derived from the IRIs, index-aligned, one per entry — the property
        // that lets a re-vendored authority list relabel itself.
        let labels = access_right_labels();
        assert_eq!(labels.len(), ACCESS_RIGHTS.len());
        assert_eq!(labels[0], "PUBLIC");
        assert!(labels.iter().all(|l| !l.is_empty()));
    }

    /// Every entry of every closed set must derive a usable, non-empty menu label —
    /// otherwise a re-vendor could panic or blank a wizard menu instead of widening it.
    #[test]
    fn closed_set_labels_derive_from_the_iris() {
        use gdi_node_standalone_core::validate_pkg::HEALTH_CATEGORIES;
        let labels: Vec<String> = HEALTH_CATEGORIES
            .iter()
            .map(|iri| health_category_label(iri))
            .collect();
        assert!(labels.contains(&"Human genomic".to_owned()), "{labels:?}");
        assert!(labels.contains(&"Human genetic".to_owned()), "{labels:?}");
        assert!(
            labels.contains(&"Human epigenomic".to_owned()),
            "{labels:?}"
        );
        assert!(labels.iter().all(|l| !l.is_empty()));
        // An IRI outside the shape's naming convention still labels sensibly.
        assert_eq!(health_category_label("http://x.example/Foo"), "Foo");
        // The choices pair every set entry with its label, in set order.
        let choices = health_category_choices();
        assert_eq!(choices.len(), HEALTH_CATEGORIES.len());
        assert!(
            choices
                .iter()
                .zip(HEALTH_CATEGORIES)
                .all(|((_, iri), set_iri)| iri == set_iri)
        );
    }

    /// The `conformsTo` menu offers the whole vendored closed set, in set order, under
    /// the GDI wording — and nothing else (an "Other" row could only author a package the
    /// node rejects).
    #[test]
    fn conforms_to_choices_cover_the_closed_set_with_gdi_wording() {
        use gdi_node_standalone_core::validate_pkg::CONFORMS_TO;
        let choices = conforms_to_choices();
        assert_eq!(choices.len(), CONFORMS_TO.len());
        assert!(
            choices
                .iter()
                .zip(CONFORMS_TO)
                .all(|((_, iri), set_iri)| iri == set_iri),
            "{choices:?}"
        );
        let labels: Vec<&str> = choices.iter().map(|(l, _)| l.as_str()).collect();
        assert_eq!(
            labels,
            ["Externally governed", "1+MG compliant", "1+MG cohort"]
        );
    }

    #[test]
    fn health_category_resolver_is_closed() {
        assert!(
            resolve_health_category("http://data.gdi.eu/core/p2/HealthCategoryHumanGenomic")
                .is_ok()
        );
        let err =
            resolve_health_category("http://data.gdi.eu/core/p2/HealthCategoryHumanProteomic")
                .expect_err("outside the closed set");
        assert!(err.contains("closed set"), "{err}");
    }

    #[test]
    fn bounded_resolver_rejects_over_cap_at_the_prompt() {
        assert_eq!(resolve_bounded("title", " ok ", 10).unwrap(), "ok");
        assert!(resolve_bounded("title", "", 10).is_err());
        let long = "x".repeat(11);
        let err = resolve_bounded("title", &long, 10).expect_err("over the cap");
        assert!(err.contains("10-char"), "{err}");
    }

    #[test]
    fn u64_resolver() {
        assert_eq!(
            resolve_u64("numberOfUniqueIndividuals", "1200").unwrap(),
            1200
        );
        assert!(resolve_u64("numberOfUniqueIndividuals", "-1").is_err());
    }
}
