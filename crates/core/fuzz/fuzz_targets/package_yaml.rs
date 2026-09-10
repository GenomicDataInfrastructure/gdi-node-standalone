//! Fuzz the `package.yaml` parser.
//!
//! The input bytes are a hand-authored `package.yaml`, deserialised into the typed
//! [`PackageYaml`] model through serde-saphyr as the dataset tool does on the build path.
//!
//! Parsing must return `Ok` or `Err` and never panic. A crash is a build that aborts on a
//! file its author can only fix by guessing.
#![no_main]

use libfuzzer_sys::fuzz_target;

use gdi_node_standalone_core::model::PackageYaml;

fuzz_target!(|data: &[u8]| {
    // serde-saphyr exposes `from_slice`; ignore Ok/Err, assert no panic.
    let _ = serde_saphyr::from_slice::<PackageYaml>(data);
});
