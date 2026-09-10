//! Consolidated integration-test binary for `gdi-dataset-tool`.
//!
//! Every suite is a module of this single `it` binary, so cargo links one test
//! executable rather than one per suite, each statically re-linking the whole CLI and
//! its dependency closure. Add a new suite as `mod <name>;` with the source at
//! `tests/it/<name>.rs`, not as a new top-level `tests/*.rs` file, which would build a
//! separate binary.
#![allow(
    clippy::disallowed_methods,
    reason = "test code writes plain files; durability is not under test"
)]

mod build_e2e;
mod bundled_sample;
mod catalogs_e2e;
mod check_e2e;
mod cli_docs;
mod config_e2e;
mod deploy_e2e;
mod doctor_e2e;
mod init_e2e;
mod inspect_e2e;
mod keys_e2e;
mod keys_rotation_e2e;
mod lifecycle_e2e;
mod lint_e2e;
mod pack_e2e;
mod s3_plane_e2e;
mod status_e2e;
mod unpack_e2e;
mod validate_e2e;
mod validators_reachable;
mod wizard_e2e;
