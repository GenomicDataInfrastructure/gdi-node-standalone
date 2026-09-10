//! Coverage for the `receivedRequestSummary` and error-`meta` echo helpers:
//! [`submitted_request_echo`], [`echo_received_request`], [`error_response_meta`] and
//! [`entry_schema`], all four `pub fn` in `query.rs`.
//!
//! These assertions run at the beacon-crate API boundary rather than through a router, so
//! they need no HTTP. The service crate keeps only the thin wiring halves, in
//! `crates/gdi-node-standalone/tests/it/beacon_query/` and
//! `crates/gdi-node-standalone/tests/it/beacon_collections.rs`.

#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use gdi_node_standalone_beacon::BeaconParams;
use gdi_node_standalone_beacon::query::{
    echo_received_request, entry_schema, error_response_meta, submitted_request_echo,
};
use gdi_node_standalone_beacon::request::RequestParams;
use serde_json::{Map, Value, json};

fn beacon_cfg() -> BeaconParams {
    BeaconParams {
        id: "org.test.beacon".to_owned(),
        name: "Test Beacon".to_owned(),
        ..BeaconParams::default()
    }
}

/// A [`RequestParams`] map built from `(key, value)` pairs.
fn params(entries: Vec<(&str, Value)>) -> RequestParams {
    let mut m = Map::new();
    for (k, v) in entries {
        m.insert(k.to_owned(), v);
    }
    m
}

#[test]
fn submitted_request_echo_returns_arrays_verbatim() {
    let filters = json!([{ "id": "NCIT:C20197" }]);
    let schemas =
        json!([{ "entityType": "genomicVariant", "schema": "https://example.org/custom" }]);
    let p = params(vec![
        ("filters", filters.clone()),
        ("requestedSchemas", schemas.clone()),
    ]);

    let (got_filters, got_schemas) = submitted_request_echo(&p);
    assert_eq!(got_filters, filters.as_array().unwrap().clone());
    assert_eq!(got_schemas, schemas.as_array().unwrap().clone());
}

#[test]
fn submitted_request_echo_defaults_to_empty_when_absent_or_not_an_array() {
    // Absent.
    let (filters, schemas) = submitted_request_echo(&Map::new());
    assert!(filters.is_empty());
    assert!(schemas.is_empty());

    // Present but not an array: an empty list, never a panic or a reflected scalar.
    let p = params(vec![
        ("filters", json!("oops")),
        ("requestedSchemas", json!(42)),
    ]);
    let (filters, schemas) = submitted_request_echo(&p);
    assert!(filters.is_empty());
    assert!(schemas.is_empty());
}

/// `requestedSchemas` is client-supplied and echoed into `receivedRequestSummary`, where the
/// vendored schema types its items as `SchemasPerEntity` (`"type": "object"`). A non-object
/// element therefore makes the node's own response violate its own conformance gate.
///
/// The scalar case is covered above: not an array yields an empty list. This pins the case
/// one level down, an array of scalars. Echoing `requestedSchemas: [42,"x",null]` verbatim
/// would let any client force a schema-non-conformant response out of the node, the same
/// hazard `requestParameters` is not echoed for.
#[test]
fn submitted_request_echo_drops_non_object_requested_schemas() {
    let p = params(vec![("requestedSchemas", json!([42, "x", null, true, []]))]);
    let (_filters, schemas) = submitted_request_echo(&p);
    assert!(
        schemas.is_empty(),
        "every requestedSchemas element is a non-object and must be dropped, got: {schemas:?}"
    );

    // A well-formed element survives alongside a junk one: the filter drops only the parts
    // that would break the schema, never a legitimate echo.
    let mixed = params(vec![(
        "requestedSchemas",
        json!([{ "entityType": "genomicVariant", "schema": "https://example.org/x" }, 42]),
    )]);
    let (_filters, schemas) = submitted_request_echo(&mixed);
    assert_eq!(schemas.len(), 1, "the object element must be kept");
    assert_eq!(schemas[0]["entityType"], "genomicVariant");
}

/// A `g_variants` or `datasets` query carrying object-valued `requestedSchemas` echoes them
/// in `receivedRequestSummary`, which is Beacon v2's transparency mechanism. `testMode` is
/// echoed too.
#[test]
fn echo_received_request_echoes_requested_schemas_and_test_mode() {
    let cfg = beacon_cfg();
    let mut meta = error_response_meta(&cfg, "genomicVariant");

    let schemas =
        json!([{ "entityType": "genomicVariant", "schema": "https://example.org/custom" }]);
    let p = params(vec![
        ("requestedSchemas", schemas.clone()),
        ("testMode", json!(true)),
    ]);
    echo_received_request(&mut meta, &p);

    assert_eq!(
        meta.received_request_summary.requested_schemas,
        schemas.as_array().unwrap().clone(),
        "requestedSchemas echoed verbatim"
    );
    assert!(meta.received_request_summary.test_mode, "testMode echoed");

    // The wire shape: requestedSchemas lives under receivedRequestSummary, and no
    // `filters` key is emitted there. This beacon advertises no filtering terms and
    // rejects a submitted one, so nothing legitimate reaches this point.
    let v = serde_json::to_value(&meta).unwrap();
    let summary = &v["receivedRequestSummary"];
    assert_eq!(summary["requestedSchemas"], schemas);
    assert!(
        summary.get("filters").is_none(),
        "filters are never echoed: {summary}"
    );
}

/// With no `requestedSchemas` or `testMode` submitted, `requestedSchemas` is a present but
/// empty array, required with `minItems: 0`, and `testMode` defaults to false.
#[test]
fn echo_received_request_defaults_when_nothing_submitted() {
    let cfg = beacon_cfg();
    let mut meta = error_response_meta(&cfg, "genomicVariant");
    echo_received_request(&mut meta, &Map::new());

    assert!(meta.received_request_summary.requested_schemas.is_empty());
    assert!(!meta.received_request_summary.test_mode);

    let v = serde_json::to_value(&meta).unwrap();
    assert_eq!(
        v["receivedRequestSummary"]["requestedSchemas"],
        json!([]),
        "requestedSchemas is present-but-empty, not omitted"
    );
}

/// A submitted `includeResultsetResponses` is echoed in `receivedRequestSummary`, so a
/// client can confirm which shaping it got rather than inferring it from the resultSets.
#[test]
fn echo_received_request_echoes_a_submitted_include_resultset_responses() {
    let cfg = beacon_cfg();
    let mut meta = error_response_meta(&cfg, "genomicVariant");
    let p = params(vec![("includeResultsetResponses", json!("MISS"))]);
    echo_received_request(&mut meta, &p);

    let summary = &serde_json::to_value(&meta).unwrap()["receivedRequestSummary"];
    assert_eq!(
        summary["includeResultsetResponses"],
        json!("MISS"),
        "the submitted shaping is echoed, not the HIT default: {summary}"
    );
}

/// Nothing submitted still echoes the shaping the node applied: `HIT`, the value the
/// vendored `$def` declares as its default and reads an absent field as. Omitting the key
/// would leave a client unable to tell that hit-only default apart from a beacon that
/// ignored the field, and a `null` echo is outside the `$def`'s four-member `enum`, so it
/// would fail `beacon_schema_conformance`.
#[test]
fn echo_received_request_default_fills_include_resultset_responses_to_hit() {
    let cfg = beacon_cfg();
    let mut meta = error_response_meta(&cfg, "genomicVariant");
    echo_received_request(&mut meta, &Map::new());

    let summary = &serde_json::to_value(&meta).unwrap()["receivedRequestSummary"];
    assert_eq!(
        summary["includeResultsetResponses"],
        json!("HIT"),
        "an absent submission echoes the applied HIT default, present and non-null: {summary}"
    );
}

/// A 400 on `/datasets` must name the `dataset` schema in its error meta, not the
/// request-agnostic `genomicVariant` default. The HTTP-wiring half, that `reject_datasets`
/// passes the literal `"dataset"` string, stays in the service crate.
#[test]
fn error_response_meta_names_the_dataset_entry_type() {
    let cfg = beacon_cfg();
    let meta = error_response_meta(&cfg, "dataset");
    assert_eq!(meta.returned_schemas.len(), 1);
    assert_eq!(meta.returned_schemas[0].entry_type, "dataset");
    assert!(meta.returned_schemas[0].schema.contains("datasets/"));

    let v = serde_json::to_value(&meta).unwrap();
    assert_eq!(
        v["returnedSchemas"][0]["entityType"], "dataset",
        "the wire key is entityType, not entryType: {v}"
    );
}

#[test]
fn error_response_meta_defaults_pagination_and_granularity() {
    let cfg = beacon_cfg();
    let meta = error_response_meta(&cfg, "genomicVariant");
    assert_eq!(meta.returned_granularity, "record");
    assert_eq!(meta.api_version, cfg.api_version);
    assert_eq!(
        meta.received_request_summary.pagination.limit,
        cfg.default_page_limit
    );
    assert_eq!(meta.received_request_summary.pagination.skip, 0);
}

#[test]
fn entry_schema_maps_each_known_entry_type_and_falls_back_for_unknown() {
    let api_version = "v2.2.0";

    let variant = entry_schema("genomicVariant", api_version);
    assert_eq!(variant.entry_type, "genomicVariant");
    assert!(
        variant
            .schema
            .contains("genomicVariations/defaultSchema.json")
    );

    let dataset = entry_schema("dataset", api_version);
    assert_eq!(dataset.entry_type, "dataset");
    assert!(dataset.schema.contains("datasets/defaultSchema.json"));

    let individual = entry_schema("individual", api_version);
    assert_eq!(individual.entry_type, "individual");
    assert!(individual.schema.contains("individuals/defaultSchema.json"));

    // An unrecognised entry type keeps the literal label but falls back to the
    // genomicVariant schema URL, the node's primary entry type.
    let unknown = entry_schema("widget", api_version);
    assert_eq!(unknown.entry_type, "widget");
    assert!(
        unknown
            .schema
            .contains("genomicVariations/defaultSchema.json")
    );
}
