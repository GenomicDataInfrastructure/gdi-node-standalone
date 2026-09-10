//! Fuzz the crypt4gh header decoder.
//!
//! The input bytes are an external `.tar.c4gh` stream — magic, version, header packets and
//! body segments — read under a fixed throwaway identity they almost never decrypt under.
//! `decrypt` is the first code to touch such a stream, and what is under test is the parser
//! rather than a successful decrypt.
//!
//! It must return `Ok` or `Err` and never panic. A crash is reachable from any package a
//! provider uploads.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;

use gdi_node_standalone_core::crypt4gh::{decrypt, generate_keypair, SecretKey};

/// One throwaway identity, generated once and reused across iterations so the RNG is not
/// driven on the per-input hot path.
///
/// The fuzzer feeds bytes that almost never decrypt under this key. What is under test is the
/// parser, not a successful decrypt.
fn identity() -> &'static SecretKey {
    static IDENTITY: OnceLock<SecretKey> = OnceLock::new();
    IDENTITY.get_or_init(|| generate_keypair().0)
}

fuzz_target!(|data: &[u8]| {
    let identities = [identity().clone()];
    let mut sink: Vec<u8> = Vec::new();
    // Must return (Ok or Err), never panic, on any byte stream.
    let _ = decrypt(&mut &data[..], &mut sink, &identities);
});
