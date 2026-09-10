//! Shared types, dataset logic, validation, and ingestion for gdi-node-standalone.
#![deny(
    clippy::expect_used,
    reason = "library code returns `Result` and never panics; tests are exempt via `allow-expect-in-tests` in clippy.toml"
)]
#![deny(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::string_slice,
    reason = "library code logs via `tracing` rather than printing, and `str` byte-slicing panics on a multibyte boundary: slice by a char boundary or use `get`"
)]
#![cfg_attr(
    test,
    allow(
        clippy::disallowed_methods,
        reason = "unit tests write plain files: durability and atomicity are not properties under test"
    )
)]
#![warn(missing_docs)]

/// The pinned gdi-metadata release tag whose SHACL model the node's emitted FDP
/// graph conforms to.
///
/// A build-time constant, not a runtime config field: the emitted model is the
/// compiled-in static mapping table, so a TOML value could not change what the
/// node emits. Conformance is asserted out-of-band by the pySHACL job against
/// the pinned shapes. Surfaced in the service binary's `--version` output.
pub const GDI_METADATA_VERSION: &str = "1.2.0";

#[cfg(test)]
mod lint_canary;

pub mod cache;
pub mod catalogs;
pub mod chrom;
pub mod config;
pub mod convert;
pub mod crypt4gh;
pub mod datetime;
pub mod digest;
pub mod error;
pub mod extract;
pub mod faults;
pub mod hierarchy;
pub mod id;
pub mod ingest;
pub mod kanon;
pub mod model;
pub mod overlay_override;
pub mod overlay_store;
pub mod override_store;
pub mod panic_guard;
pub mod parquet_io;
pub mod parquet_pages;
pub mod popfield;
pub mod query_stats;
pub mod reingest_request;
#[cfg(feature = "s3")]
pub mod s3_conn;
pub mod s3_layout;
/// JSON Schema generation for the package/handoff JSON contracts (dev/gen only).
#[cfg(feature = "schema")]
pub mod schema;
pub mod state;
pub mod subcounts;
pub mod suppression;
#[cfg(any(feature = "http", feature = "s3"))]
pub mod tls;
pub mod util;
pub mod validate_parquet;
pub mod validate_pkg;
pub mod variant;
