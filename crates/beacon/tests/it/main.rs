//! Consolidated integration-test binary for the `beacon` crate.
//!
//! Every suite here links `gdi_node_standalone_core` and the arrow/parquet/noodles closure
//! behind it, so one `tests/*.rs` per suite would re-embed all of it once per linked
//! executable. Add a new suite as `mod <name>;` with the source at `tests/it/<name>.rs`,
//! not as a new top-level `tests/*.rs`.

mod assemble;
mod collections;
mod fixtures;
mod query_proptest;
mod response_meta;
mod suppression_properties;
