//! FAIR Data Point rendering for gdi-node-standalone.
//!
//! Maps the node's metadata model to RDF via a single static mapping table (the
//! in-repo encoding of the gdi-metadata SHACL shape) and renders the **Dataset**,
//! **Distribution**, and inline **`DataService`** records, plus the **FDP-root**
//! and **Catalog** records with their LDP navigation. Each record is built once as
//! an [`oxrdf::Graph`] and serialised to both Turtle (primary) and expanded
//! JSON-LD (secondary) from that one representation, so the formats cannot drift.
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

pub mod context;
pub mod datetime;
pub mod graph;
// The static SHACL mapping table is internal, consumed only by `graph`, so evolving
// it is not a public-API change.
pub(crate) mod mapping;
pub mod root;
pub mod serialize;
mod vocab;

pub use context::FdpContext;
pub use graph::{dataset_graph, distribution_graph};
pub use root::{CatalogListing, catalog_graph, fdp_root_graph};
pub use serialize::{serialize_jsonld, serialize_turtle};
