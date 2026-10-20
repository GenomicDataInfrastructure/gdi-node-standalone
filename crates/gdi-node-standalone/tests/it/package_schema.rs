//! The published manifest and overlay schemas refuse what the validator refuses.
//!
//! `docs/package-format.md` makes the schemas the contract a consumer generates code from, so
//! a rule only the validator knows is one a consumer silently lacks. Each case here is a
//! value the node refuses at ingest; the schema must refuse it too, and a value at the limit
//! must pass both.
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use gdi_node_standalone_core::model::{Manifest, MetadataOverlay};
use gdi_node_standalone_core::validate_pkg::{
    ACCESS_RIGHTS, CONFORMS_TO, DATASET_TYPES, EHDS_ELI, HEALTH_CATEGORIES, MAX_CONTACT_FN_LEN,
    MAX_CREATOR_NAME_LEN, MAX_CREATORS_COUNT, MAX_IRI_LEN, MAX_IRI_LIST_COUNT, MAX_PROVENANCE_LEN,
    MAX_TYPICAL_AGE, validate_overlay_result, validate_patch,
};
use serde_json::{Value, json};

const THEME: &str =
    "https://hdeu-dcat.data.health.europa.eu/resource/authority/health-theme/HEALTH_PRODUCTS";

fn schema(file: &str) -> jsonschema::Validator {
    let path = format!("{}/../../docs/{file}", env!("CARGO_MANIFEST_DIR"));
    let schema: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    jsonschema::validator_for(&schema).unwrap()
}

fn golden_manifest() -> Value {
    let path = format!(
        "{}/../core/tests/fixtures/manifest.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// The golden manifest with `metadata.<field>` set to `value`.
fn manifest_with(field: &str, value: Value) -> Value {
    let mut manifest = golden_manifest();
    manifest["metadata"][field] = value;
    manifest
}

fn node_accepts_manifest(manifest: &Value) -> bool {
    serde_json::from_value::<Manifest>(manifest.clone())
        .is_ok_and(|m| validate_overlay_result(&m.metadata).is_ok())
}

fn node_accepts_overlay(overlay: &Value) -> bool {
    serde_json::from_value::<MetadataOverlay>(overlay.clone())
        .is_ok_and(|o| validate_patch(&o).is_ok())
}

fn long(n: usize) -> String {
    "a".repeat(n)
}

/// A valid IRI exactly `len` characters long.
fn iri(len: usize) -> String {
    let base = "https://example.org/";
    format!("{base}{}", long(len - base.len()))
}

/// Field values the node refuses, each with a value at the limit that it accepts.
#[expect(
    clippy::too_many_lines,
    reason = "a data table, one row per rule; both tests loop over the same rows"
)]
fn cases() -> Vec<(&'static str, &'static str, Value, Value)> {
    let contact = |fn_: Value, email: Value| json!({"fn": fn_, "hasEmail": email});
    let email = json!("mailto:data@example.org");
    let creators = |n: usize| json!(vec![json!({"name": "C"}); n]);
    let mut cases = vec![
        (
            "contact point without a name or e-mail",
            "contactPoint",
            json!({}),
            contact(json!("Data team"), email.clone()),
        ),
        (
            "contact name too long",
            "contactPoint",
            contact(json!(long(MAX_CONTACT_FN_LEN + 1)), email.clone()),
            contact(json!(long(MAX_CONTACT_FN_LEN)), email),
        ),
        (
            "e-mail without mailto:",
            "contactPoint",
            contact(json!("Data team"), json!("data@example.org")),
            contact(json!("Data team"), json!("mailto:data@example.org")),
        ),
        (
            "e-mail domain without a dot",
            "contactPoint",
            contact(json!("Data team"), json!("mailto:data@example")),
            contact(json!("Data team"), json!("mailto:data@ex.ample.org")),
        ),
        (
            "e-mail with a space",
            "contactPoint",
            contact(json!("Data team"), json!("mailto:da ta@example.org")),
            contact(json!("Data team"), json!("mailto:da.ta@example.org")),
        ),
        (
            "minimum age too high",
            "minTypicalAge",
            json!(MAX_TYPICAL_AGE + 1),
            json!(MAX_TYPICAL_AGE),
        ),
        (
            "maximum age too high",
            "maxTypicalAge",
            json!(MAX_TYPICAL_AGE + 1),
            json!(MAX_TYPICAL_AGE),
        ),
        ("empty provenance", "provenance", json!(""), json!("P")),
        (
            "provenance too long",
            "provenance",
            json!(long(MAX_PROVENANCE_LEN + 1)),
            json!(long(MAX_PROVENANCE_LEN)),
        ),
        (
            "empty provenance map",
            "provenance",
            json!({}),
            json!({"en": "P"}),
        ),
        (
            "health theme outside the vocabulary",
            "healthTheme",
            json!(["https://example.org/GENOMICS"]),
            json!([THEME]),
        ),
        (
            "health theme listed twice",
            "healthTheme",
            json!([THEME, THEME]),
            json!([THEME]),
        ),
        (
            "health category outside the vocabulary",
            "healthCategory",
            json!(["https://example.org/GENOMICS"]),
            json!([HEALTH_CATEGORIES[0]]),
        ),
        (
            "conformsTo outside the vocabulary",
            "conformsTo",
            json!(["https://example.org/compliant"]),
            json!([CONFORMS_TO[0]]),
        ),
        (
            "dataset type outside the vocabulary",
            "type",
            json!(["https://example.org/REAL_DATA"]),
            json!([DATASET_TYPES[0]]),
        ),
        (
            "access rights outside the vocabulary",
            "accessRights",
            json!("https://example.org/OPEN"),
            json!(ACCESS_RIGHTS[0]),
        ),
        (
            "no legislation",
            "applicableLegislation",
            json!([]),
            json!([EHDS_ELI]),
        ),
        ("no creator", "creator", json!([]), json!([{"name": "C"}])),
        (
            "creator without a name",
            "creator",
            json!([{"name": ""}]),
            json!([{"name": "C"}]),
        ),
        (
            "too many creators",
            "creator",
            creators(MAX_CREATORS_COUNT + 1),
            creators(MAX_CREATORS_COUNT),
        ),
        (
            "creator name too long",
            "creator",
            json!([{"name": long(MAX_CREATOR_NAME_LEN + 1)}]),
            json!([{"name": long(MAX_CREATOR_NAME_LEN)}]),
        ),
        ("empty licence", "license", json!(""), json!(iri(40))),
        (
            "licence too long",
            "license",
            json!(iri(MAX_IRI_LEN + 1)),
            json!(iri(MAX_IRI_LEN)),
        ),
    ];
    // One validator rule covers all three IRI lists.
    for field in ["applicableLegislation", "legalBasis", "isReferencedBy"] {
        cases.push((
            "too many IRIs",
            field,
            json!(vec![iri(40); MAX_IRI_LIST_COUNT + 1]),
            json!(vec![iri(40); MAX_IRI_LIST_COUNT]),
        ));
        cases.push((
            "IRI too long",
            field,
            json!([iri(MAX_IRI_LEN + 1)]),
            json!([iri(MAX_IRI_LEN)]),
        ));
    }
    cases
}

#[test]
fn the_manifest_schema_refuses_what_the_node_refuses() {
    let schema = schema("manifest.schema.json");
    assert!(
        schema.is_valid(&golden_manifest()),
        "the golden manifest is valid"
    );
    for (case, field, refused, accepted) in cases() {
        let bad = manifest_with(field, refused);
        assert!(
            !node_accepts_manifest(&bad),
            "{case} ({field}): the node must refuse it"
        );
        assert!(
            !schema.is_valid(&bad),
            "{case} ({field}): the schema must refuse it"
        );

        let good = manifest_with(field, accepted);
        assert!(
            node_accepts_manifest(&good),
            "{case} ({field}): the node accepts the limit"
        );
        assert!(
            schema.is_valid(&good),
            "{case} ({field}): the schema accepts the limit"
        );
    }
}

#[test]
fn the_overlay_schema_refuses_what_the_node_refuses() {
    let schema = schema("metadata-overlay.schema.json");
    for (case, field, refused, accepted) in cases() {
        let bad = json!({ field: refused });
        assert!(
            !node_accepts_overlay(&bad),
            "{case} ({field}): the node must refuse it"
        );
        assert!(
            !schema.is_valid(&bad),
            "{case} ({field}): the schema must refuse it"
        );

        let good = json!({ field: accepted });
        assert!(
            node_accepts_overlay(&good),
            "{case} ({field}): the node accepts the limit"
        );
        assert!(
            schema.is_valid(&good),
            "{case} ({field}): the schema accepts the limit"
        );
    }
}
