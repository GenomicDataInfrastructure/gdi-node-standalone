//! Fuzz the crypt4gh body (segment / AEAD) decoder.
//!
//! The input bytes are the body of a `.tar.c4gh` stream. They are appended to a valid header
//! encrypted to a fixed recipient identity, so the session key is recovered and `decrypt`
//! proceeds into the 64 KiB ChaCha20-Poly1305 segment loop with its per-segment length and
//! allocation handling. The `crypt4gh_header` target feeds arbitrary bytes under a throwaway
//! key, so it bails at the empty-session-keys check and never reaches that loop.
//!
//! `decrypt` must return `Ok` or `Err` and never panic, overflow (the fuzz profile enables
//! `overflow-checks`) or over-allocate, even though every segment fails its AEAD tag under a
//! random body. A crash is reachable from any package a provider uploads.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;

use gdi_node_standalone_core::crypt4gh::{decrypt, encrypt, generate_keypair, SecretKey};

/// The fixed recipient identity the fuzzed streams are addressed to. Generated once
/// (the RNG is not driven on the per-input hot path).
fn recipient() -> &'static SecretKey {
    static RECIPIENT: OnceLock<SecretKey> = OnceLock::new();
    RECIPIENT.get_or_init(|| generate_keypair().0)
}

/// A valid crypt4gh header addressed to [`recipient`], with a zero-length body.
///
/// Produced by encrypting an empty plaintext: an empty crypt4gh body is zero segments, so the
/// output is exactly `magic + version + packet_count + packet`. The fuzzer appends its bytes
/// after this as the body, so `decrypt` recovers the session key from the header and then
/// feeds the fuzzed bytes into `decrypt_body`.
fn header_prefix() -> &'static Vec<u8> {
    static HEADER: OnceLock<Vec<u8>> = OnceLock::new();
    HEADER.get_or_init(|| {
        let sender = generate_keypair().0;
        let recipient_pk = recipient().public_key();
        let mut out = Vec::new();
        let mut empty: &[u8] = &[];
        encrypt(&mut empty, &mut out, &[recipient_pk], &sender)
            .expect("encrypting an empty plaintext to a fresh recipient must succeed");
        out
    })
}

fuzz_target!(|data: &[u8]| {
    // A valid header addressed to `recipient()`, then the fuzzer-controlled body.
    let mut stream: Vec<u8> = header_prefix().clone();
    stream.extend_from_slice(data);

    let identities = [recipient().clone()];
    let mut sink: Vec<u8> = Vec::new();
    // Must return (Ok or Err), never panic, on any body byte stream.
    let _ = decrypt(&mut &stream[..], &mut sink, &identities);
});
