//! Fuzz the Beacon request parser.
//!
//! The input bytes are read as the JSON object a Beacon query arrives as, from the GET query
//! string or the POST body on the public request plane. `parse_request` and
//! `parse_include_resultset_responses` consume those parameters untrusted.
//!
//! Both must return a parsed query or a `400` reject and never panic. A crash is a denial of
//! service reachable from an unauthenticated query.
#![no_main]

use libfuzzer_sys::fuzz_target;

use gdi_node_standalone_beacon::request::{parse_include_resultset_responses, parse_request};
use gdi_node_standalone_beacon::BeaconParams;

fuzz_target!(|data: &[u8]| {
    // `RequestParams` is a JSON object; interpret the input as one. Non-object JSON
    // (or invalid JSON) is not a parse target, so skip it.
    let Ok(serde_json::Value::Object(params)) = serde_json::from_slice::<serde_json::Value>(data)
    else {
        return;
    };
    let cfg = BeaconParams::default();
    // Assert only that parsing never panics (both Ok and a 400 reject are fine).
    let _ = parse_request(&params, &cfg);
    let _ = parse_include_resultset_responses(&params);
});
