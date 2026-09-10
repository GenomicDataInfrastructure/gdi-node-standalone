//! Fuzz the node ingest manifest trust gate: the validation, not just the parse.
//!
//! The input bytes are the `manifest.json` of a hand-assembled `.tar.c4gh`. They are parsed
//! with `serde_json::from_slice::<Manifest>`, and a parseable manifest then goes through the
//! checks `ingest::parse_and_validate_manifest` applies, in the same order: the id, the
//! metadata (mandatory fields, `sh:in` enums, IRI and IRIREF character safety, contactPoint),
//! the assembly, and the served-URL check a forged package must satisfy before its record can
//! reach the public FDP and Beacon plane.
//!
//! Those validators consume attacker-controlled strings — descriptions, IRIs and a served
//! `afSourceReference` URL — and must reject them with a clean `Err`, never panicking or
//! overflowing (the fuzz profile enables `overflow-checks`). A crash is reachable from any
//! package a provider uploads.
#![no_main]

use libfuzzer_sys::fuzz_target;

use gdi_node_standalone_core::model::Manifest;
use gdi_node_standalone_core::validate_pkg::{validate_overlay_result, validate_url};
use gdi_node_standalone_core::{chrom, id};

fuzz_target!(|data: &[u8]| {
    // The parse itself is under test: it must never panic on arbitrary bytes. Only a
    // parseable manifest goes on to reach the gate; a parse failure is a clean reject.
    let Ok(manifest) = serde_json::from_slice::<Manifest>(data) else {
        return;
    };
    let meta = &manifest.metadata;
    // The gate's checks, in the order `parse_and_validate_manifest` runs them. Each must
    // return without panicking on any parsed-but-arbitrary manifest content.
    let _ = id::is_valid_dataset_id(&meta.dataset_id);
    let _ = validate_overlay_result(meta);
    let _ = chrom::is_known_assembly(&manifest.config.assembly.reference);
    if let Some(asr) = &manifest.config.af_source_reference {
        let _ = validate_url("config.afSourceReference", asr);
    }
});
