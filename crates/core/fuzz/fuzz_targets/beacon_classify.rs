//! Fuzz the Beacon coordinate classifier.
//!
//! The input bytes are read as the JSON object a Beacon query normalizes from, on the public
//! request plane. `parse_request` normalizes it and `classify` then decides its coordinate
//! shape (Sequence, Range or Bracket), rejects inverted windows and enforces the span cap.
//! The `beacon_request` target stops at `parse_request`, so this one drives a parsed query on
//! into the span arithmetic.
//!
//! `classify` must return a coordinate shape or a `400` reject, never panicking and never
//! overflowing (the fuzz profile enables `overflow-checks`). A crash is a denial of service
//! reachable from an unauthenticated query, such as a Bracket `s_max` that bypasses the span
//! cap or an `s_max > e_max` window.
#![no_main]

use libfuzzer_sys::fuzz_target;

use gdi_node_standalone_beacon::request::{classify, parse_request};
use gdi_node_standalone_beacon::BeaconParams;

fuzz_target!(|data: &[u8]| {
    // Interpret the input as the JSON object a beacon request normalizes from. Invalid
    // or non-object JSON is not a classify target.
    let Ok(serde_json::Value::Object(params)) = serde_json::from_slice::<serde_json::Value>(data)
    else {
        return;
    };
    let cfg = BeaconParams::default();
    // Only a successfully-normalized query reaches `classify` on the real serve path;
    // a parse reject is a clean 400, not a classify input.
    if let Ok(query) = parse_request(&params, &cfg) {
        // The contract under fuzzing: classify never panics and never overflows on any
        // parsed query — it returns a QueryKind or a 400 reject.
        let _ = classify(&query, &cfg);
    }
});
