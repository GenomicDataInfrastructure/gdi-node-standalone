//! Fuzz the state-file decoders the node re-reads at boot and on every reconcile pass.
//!
//! The input bytes are read as each of the small JSON control files whose bytes the node did
//! not necessarily write this run: a hand-edited or bit-rotted `datasets/.status.json`, an
//! operator-dropped `{id}.state.json` visibility or tombstone sidecar, an `{id}.metadata.json`
//! overlay, a durable `.metadata.overlay.json`, or a `_status/{id}.json` writeback read from a
//! bucket. The same input is fed to every decoder.
//!
//! Each must return `Ok` or `Err` and never panic or overflow (the fuzz profile enables
//! `overflow-checks`). A crash is a boot that cannot complete, reachable from one corrupt or
//! hostile control file.
#![no_main]

use libfuzzer_sys::fuzz_target;

use gdi_node_standalone_core::cache::StatusIndex;
use gdi_node_standalone_core::model::MetadataOverlay;
use gdi_node_standalone_core::overlay_store::AppliedOverlay;
use gdi_node_standalone_core::s3_layout::{StateSidecar, StatusWriteback};

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<StatusIndex>(data); // datasets/.status.json (boot index)
    let _ = serde_json::from_slice::<AppliedOverlay>(data); // .metadata.overlay.json (durable, hydrate)
    let _ = serde_json::from_slice::<MetadataOverlay>(data); // {id}.metadata.json (operator overlay)
    let _ = serde_json::from_slice::<StateSidecar>(data); // {id}.state.json (visibility / tombstone)
    let _ = serde_json::from_slice::<StatusWriteback>(data); // _status/{id}.json (bucket writeback)
});
