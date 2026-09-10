//! GA4GH Beacon v2.2.0 response model, request parse/classify, and query
//! execution/assembly over Parquet — a reusable, framework-agnostic library.
//! HTTP wiring lives in the `gdi-node-standalone` service binary (`beacon_http`).
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

pub mod model;
pub mod params;
pub mod query;
pub mod request;

pub use params::BeaconParams;
