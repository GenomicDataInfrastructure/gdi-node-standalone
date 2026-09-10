//! Consolidated integration-test binary for the `gdi-node-standalone` service.
//!
//! Each suite is a module of this single `it` binary, so cargo links one test executable
//! rather than one per suite, each of which would embed the whole service and its dependency
//! closure (axum, arrow and parquet, noodles, the crypt4gh stack). Add a new suite as
//! `mod <name>;` with the source at `tests/it/<name>.rs`, not as a new top-level
//! `tests/*.rs` file, which would create a separate binary.
//!
//! Four suites keep their own `tests/*.rs` target:
//!   * `beacon_info` — insta snapshot files key on the binary name.
//!   * `conformance_crawl` and `conformance_agreement` — invoked by target name
//!     (`--test conformance_crawl --test conformance_agreement`).
//!   * `beacon_schema_conformance` — separate by convention, as the vendored-schema
//!     validation of live responses; it carries no `#[ignore]`d tests and so runs in the
//!     ordinary sweep. See `docs/testing.md` § Conformance.
//!
//! The `s3`, `vault` and `pme` suites are cfg-gated to their feature, and each file also
//! keeps its own inner `#![cfg(feature = …)]`. With the feature off the module is absent.
#![allow(
    clippy::disallowed_methods,
    reason = "test/bench code writes plain files: durability and atomicity are not properties under test"
)]

mod api_doc_routes;
mod beacon_collections;
mod beacon_individuals;
mod beacon_membership_inference;
mod beacon_middleware;
mod beacon_query;
mod beacon_split_mount;
mod binary_cli;
mod config_examples;
mod corrupt_parquet_query;
mod dataset_list_route;
mod e2e_slice;
mod fault_injection;
mod fdp_crawl;
mod fdp_routes;
mod fixtures;
mod health_state;
mod inbox_deleted_tombstone;
mod inbox_ingest;
mod ingest_backpressure;
mod ingest_panic;
mod key_perms;
mod metrics_endpoint;
mod not_found_shapes;
mod operating_doc_cli;
mod operator_flows;
mod public_cors_fallback;
mod query_stats_route;
mod reingest_route;
mod reload_route;
mod request_id_planes;
mod restart_rehydrate;
mod route_inventory;
mod seams;
mod serve_shutdown;
mod tar_c4gh_ingest;

#[cfg(feature = "pme")]
mod pme_roundtrip;
#[cfg(feature = "s3")]
mod s3_reconcile;
#[cfg(feature = "vault")]
mod vault_precedence;
