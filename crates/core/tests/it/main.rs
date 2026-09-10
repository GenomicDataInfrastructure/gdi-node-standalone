//! Consolidated integration-test binary for `gdi-node-standalone-core`.
//!
//! Cargo compiles every top-level `tests/*.rs` file into its own test binary, each statically
//! linking the whole crate and its dependency closure, plus a full copy of the DWARF debug
//! info at the default `debug = 2`. Collapsing the independent suites into modules of this one
//! `it` binary keeps `target/` small and the link step short.
//!
//! Add a new integration suite here as `mod <name>;`, with the source at `tests/it/<name>.rs`.
//! A new top-level `tests/*.rs` file would resurrect a separate binary.
//!
//! Four suites stay standalone `tests/*.rs` binaries: `crypt4gh_interop` and `corpus`, each
//! run by target name (`--test crypt4gh_interop`, `--test corpus`), plus `crypt4gh_kat` and
//! `sample_fixture`.
#![allow(
    clippy::disallowed_methods,
    reason = "test/bench code writes plain files: durability and atomicity are not properties under test"
)]

mod convert_covid;
mod header_populations;
mod model_roundtrip;
mod parquet_probes;
