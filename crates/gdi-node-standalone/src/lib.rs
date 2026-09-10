//! The `gdi-node-standalone` service: wires config loading + preflight, the inbox
//! ingest runtime (bounded worker pool + declarative `{id}.state.json`
//! reconcile), and the Beacon HTTP surface (`g_variants` + minimal informational
//! endpoints + `/.well-known/c4gh-recipient`) with its resilience layers
//! (rate-limit, concurrency cap, timeout, size guard), and the FAIR Data Point
//! surface (`/fairdp` + catalog/dataset/distribution resources, Turtle/JSON-LD
//! content negotiation; always mounted but inert (404) unless `[fairdp]` is configured).
#![deny(
    clippy::expect_used,
    clippy::string_slice,
    reason = "a panic in production code is a crash, and `str` byte-slicing panics on a multibyte boundary. `print_stdout`/`print_stderr` are absent here because a CLI legitimately writes to stdout and stderr. Tests are exempt via `allow-expect-in-tests` in clippy.toml, which needs a literal `#[cfg(test)]`, so a module gated on `cfg(all(test, feature = ...))` needs its own attribute"
)]
#![cfg_attr(
    test,
    allow(
        clippy::string_slice,
        reason = "test code slices literals it owns; the multibyte hazard is a property of runtime input, which a test fixture is not"
    )
)]
#![cfg_attr(
    test,
    allow(
        clippy::disallowed_methods,
        reason = "unit tests write plain files: durability and atomicity are not properties under test"
    )
)]
#![warn(missing_docs)]

pub mod app;
/// Privacy-aware audit trail (`audit`-target `tracing` lines). Public so the binary's
/// startup path can emit the boot-time [`audit::keyless_degraded`] line; the
/// query/mutation emitters are `pub(crate)` and called from within the lib.
pub mod audit;
pub mod beacon_http;
pub mod beacon_info;
pub mod catalogs_http;
pub mod control_http;
pub mod datasets_http;
pub mod fairdp_http;
pub mod health;
pub mod id_guard;
pub mod identities;
pub mod ingest_backoff;
pub mod ingest_runtime;
// The `dataset` one-shot (author a visibility/delete sidecar) and the `datasets` /
// `doctor` read-only one-shots; always compiled — they touch only config + the on-disk
// status index/sidecars, independent of the Vault/S3/PME features.
pub mod dataset_cmd;
// The `dataset correct <id> --field k=v… | --patch <file> | --reset` one-shots: author or
// remove a node-local metadata-overlay override, then print how to apply it, since the CLI
// never signals the node. Always compiled, like `dataset_cmd` and `suppress_cmd`; it touches
// only config and the on-disk overlay-override store, feeding the existing overlay engine.
pub mod correct_cmd;
pub mod doctor;
pub mod lift_record;
pub mod list_datasets;
pub mod logging;
pub mod metrics;
#[cfg(feature = "otel")]
pub mod metrics_otel;
pub mod override_advice;
pub mod override_marker;
pub mod overrides_cmd;
pub mod preflight;
pub mod scrub;
pub mod state;
pub mod stats_http;
// The `dataset hide|take-down|show` one-shots: author or remove an operator suppression
// override, then print how to apply it, since the CLI never signals the node. Always
// compiled, like `dataset_cmd` above; it touches only config and the on-disk suppression
// store.
pub mod suppress_cmd;
// The `channel hide|take-down|show|list` one-shots: the channel-granularity sibling of
// `suppress_cmd`, withholding and pausing ingest for an entire configured channel at once.
// Always compiled, same rationale as `suppress_cmd`.
pub mod channel_cmd;

// Networked subsystems, compiled only when their Cargo feature is enabled.
// The lite/default build links none of them.
#[cfg(feature = "s3")]
pub mod s3;
// Vault secret-source precedence (identities + S3 creds from Vault over inline
// config); compiled with the Vault client.
#[cfg(feature = "vault")]
pub mod secrets;
#[cfg(feature = "vault")]
pub mod vault;
// The `identity init` one-shot (mint the node crypt4gh identity into Vault);
// compiled with the Vault client.
#[cfg(feature = "vault")]
pub mod init_identity;
// The `identity init` one-shot for a file-backed identity (the non-Vault `[keys]` posture).
// Not feature-gated: a plain, no-Vault node still needs to mint its own crypt4gh identity
// without reaching for the provider's CLI.
pub mod init_identity_file;
// The `identity rotate` one-shot (add a new node identity beside the existing one);
// compiled with the Vault client.
#[cfg(feature = "vault")]
pub mod rotate_identity;
// The `identity retire` one-shot (remove the oldest retained node identity);
// compiled with the Vault client.
#[cfg(feature = "vault")]
pub mod retire_identity;
// The `identity list` one-shot (read-only: print the node identity state without
// dumping secret PEMs); compiled with the Vault client.
#[cfg(feature = "vault")]
pub mod list_identity;
// The same read-only inspection for the file-backed (`[keys]`) posture. Not feature-gated:
// a lite node has key files too.
pub mod list_identity_file;
// The `identity backup` / `identity restore` pair: export the node identity from
// Vault encrypted to an operator recipient, and restore it onto a fresh node;
// compiled with the Vault client.
#[cfg(feature = "vault")]
pub mod identity_backup;
// At-rest Parquet Modular Encryption wiring (Vault-minted DEK + cached key
// retriever); compiled only under the `pme` feature.
#[cfg(feature = "pme")]
pub mod pme;
// The `pme reseal` one-shot. Not feature-gated: a lite or vault-only build must still be
// able to tell the operator that this binary has no at-rest sentinel, rather than failing
// with an unknown-subcommand error that reads like a typo.
pub mod pme_cmd;
