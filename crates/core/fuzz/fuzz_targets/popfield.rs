//! Fuzz the population-aware INFO-field grammar parser.
//!
//! The input bytes are read as a VCF INFO-field ID, a string a provider's file controls.
//!
//! `parse_info_field` must return `Some` or `None` for any input and never panic. A crash is
//! reachable from any VCF the build path reads.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Must never panic, whatever the input.
        let _ = gdi_node_standalone_core::popfield::parse_info_field(s);
    }
});
