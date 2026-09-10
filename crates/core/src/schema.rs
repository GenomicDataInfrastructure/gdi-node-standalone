//! JSON Schema generation for the JSON contracts exchanged around the node: the
//! package/handoff objects the tool, the operator and any integrating system read or write,
//! plus the two management-plane responses an integrating system reads over HTTP rather
//! than from a bucket: the query statistics it polls and the catalog listing it discovers.
//!
//! Each contract's type shape is defined in one place: these schemas are derived from the
//! serde models (`#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]`), the
//! checked-in `docs/*.schema.json` files are exactly this output, and a freshness test in
//! `crates/core/tests/it/model_roundtrip.rs` regenerates and diffs them, so the docs, the
//! schemas and the Rust structs cannot drift. `docs/package-format.md` points at them
//! rather than restating field types in prose, and a consumer validates or generates code
//! against them instead of hand-transcribing the structs.
//!
//! Compiled only under the `schema` feature, which no shipped binary enables. The freshness
//! test runs in the `test_schema` leg of `scripts/ci-local.sh`.
//!
//! The schemas mirror the wire types. Runtime rules the structs do not express stay in the
//! prose beside the schema link: `numberOfRecords` is required at ingest though it is
//! `Option` on the wire, and the node re-derives and enforces
//! `numberOfRecords`/`populations`.
//!
//! Adding a contract schema is one [`SCHEMAS`](crate::schema::SCHEMAS) entry plus the
//! `derive` on its type. The freshness guard then covers it automatically.

use crate::catalogs::CatalogList;
use crate::model::{Manifest, MetadataOverlay};
use crate::query_stats::QueryStatsSnapshot;
use crate::s3_layout::{StateSidecar, StatusWriteback};

/// Serialize a derived schema to pretty JSON with a trailing newline.
fn to_pretty(schema: &schemars::Schema) -> String {
    // A derived schema is plain JSON, so serialization is infallible. On the impossible
    // failure this yields an empty body, which the `schema_files_match_the_models`
    // freshness test catches as a mismatch. Panicking is not an option here: `expect_used`
    // is forbidden in library code.
    let mut out = serde_json::to_string_pretty(schema).unwrap_or_default();
    out.push('\n');
    out
}

/// JSON Schema (draft 2020-12) of the package [`Manifest`] (`manifest.json`).
#[must_use]
pub fn manifest() -> String {
    to_pretty(&schemars::schema_for!(Manifest))
}

/// JSON Schema of the operator metadata-overlay patch [`MetadataOverlay`]
/// (`{id}.metadata.json`), the sidecar written to correct served metadata.
#[must_use]
pub fn metadata_overlay() -> String {
    to_pretty(&schemars::schema_for!(MetadataOverlay))
}

/// JSON Schema of the visibility sidecar [`StateSidecar`] (`{id}.state.json`), written by
/// the tool's `publish`/`unpublish`/`delete` to show or hide a dataset. On the inbox
/// channel it also deletes one.
#[must_use]
pub fn state_sidecar() -> String {
    to_pretty(&schemars::schema_for!(StateSidecar))
}

/// JSON Schema of the node's status writeback [`StatusWriteback`] (`_status/{id}.json`), the
/// object the node writes and the tool reads to detect ingest drift.
#[must_use]
pub fn status_writeback() -> String {
    to_pretty(&schemars::schema_for!(StatusWriteback))
}

/// JSON Schema of the management-plane query-statistics document [`QueryStatsSnapshot`]
/// (`GET /stats/queries`), the per-dataset usage counters an integrating system polls.
/// Served over HTTP rather than written to S3, and bound the same way: a consumer
/// generates its model from this file.
#[must_use]
pub fn query_stats() -> String {
    to_pretty(&schemars::schema_for!(QueryStatsSnapshot))
}

/// JSON Schema of the management-plane catalog listing [`CatalogList`] (`GET /catalogs`),
/// the `[catalogs]` table an integrating system reads to learn which catalog ids the node
/// accepts at ingest, as plain JSON rather than the FDP root's RDF.
#[must_use]
pub fn catalogs() -> String {
    to_pretty(&schemars::schema_for!(CatalogList))
}

/// A schema generator: produces the pretty-printed JSON Schema for one contract.
pub type SchemaGenerator = fn() -> String;

/// The published schemas: the checked-in `docs/<file>` and the generator that produces it.
/// The freshness guard loops over this, so a new schema is one entry here plus the derive.
pub const SCHEMAS: &[(&str, SchemaGenerator)] = &[
    ("manifest.schema.json", manifest),
    ("metadata-overlay.schema.json", metadata_overlay),
    ("state-sidecar.schema.json", state_sidecar),
    ("status-writeback.schema.json", status_writeback),
    ("query-stats.schema.json", query_stats),
    ("catalogs.schema.json", catalogs),
];
