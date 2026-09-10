//! Crypt4GH decrypt known-answer test against frozen, reference-authored vectors.
//!
//! The ciphertexts under `tests/fixtures/crypt4gh_kat/` were produced by the reference
//! `crypt4gh==1.8.6` encrypting known plaintexts to `recipient.sec`'s public key. Because they
//! come from an independent implementation, they catch self-consistent wire-format drift in
//! this decoder that a Rust-only encrypt-then-decrypt round trip cannot. The code path they
//! cover ingests attacker-controlled `.tar.c4gh`.
//!
//! Unlike `crypt4gh_interop.rs`, which drives the live Python `crypt4gh` and is `#[ignore]`d,
//! this runs in the default `cargo test` and needs no Python.
//!
//! `recipient.sec` is an unencrypted (`--nocrypt`) throwaway key that exists only to decrypt
//! these vectors. It guards nothing.
//!
//! Regenerating the fixtures (only if the format or recipient must change), from
//! `tests/fixtures/crypt4gh_kat/`:
//!
//! ```sh
//! pip install crypt4gh==1.8.6
//! crypt4gh-keygen --sk recipient.sec --pk recipient.pub --nocrypt -f
//! printf 'GA4GH Crypt4GH KAT v1\n' \
//!   | crypt4gh encrypt --recipient_pk recipient.pub > vec1_short.c4gh
//! python3 -c "import sys; sys.stdout.buffer.write(b'\xab'*70000)" \
//!   | crypt4gh encrypt --recipient_pk recipient.pub > vec2_multiseg.c4gh
//! printf '' | crypt4gh encrypt --recipient_pk recipient.pub > vec3_empty.c4gh
//! ```

#![expect(
    clippy::doc_markdown,
    reason = "docs reference Crypt4GH / GA4GH / PEM / Python by name as prose, not code"
)]

use gdi_node_standalone_core::crypt4gh::{self, parse_secret_key};

/// The reference-generated recipient secret key (unencrypted `--nocrypt` PEM).
const RECIPIENT_SEC: &str = include_str!("fixtures/crypt4gh_kat/recipient.sec");

/// Decrypt `ciphertext` with the frozen recipient key and assert it yields exactly
/// `expected`.
fn assert_kat(name: &str, ciphertext: &[u8], expected: &[u8]) {
    let sk = parse_secret_key(RECIPIENT_SEC).expect("parse reference recipient secret key");
    let mut out = Vec::new();
    crypt4gh::decrypt(&mut &ciphertext[..], &mut out, &[sk])
        .unwrap_or_else(|e| panic!("KAT {name}: decrypt failed: {e}"));
    assert_eq!(out, expected, "KAT {name}: plaintext mismatch");
}

/// Short message: a single partial body segment.
#[test]
fn kat_short_message() {
    assert_kat(
        "vec1_short",
        include_bytes!("fixtures/crypt4gh_kat/vec1_short.c4gh"),
        b"GA4GH Crypt4GH KAT v1\n",
    );
}

/// 70000 bytes: one full 64 KiB body segment plus a partial second one, which a
/// single-segment payload cannot exercise.
#[test]
fn kat_multi_segment() {
    assert_kat(
        "vec2_multiseg",
        include_bytes!("fixtures/crypt4gh_kat/vec2_multiseg.c4gh"),
        &vec![0xAB_u8; 70_000],
    );
}

/// Empty payload: a valid header with zero body segments.
#[test]
fn kat_empty_payload() {
    assert_kat(
        "vec3_empty",
        include_bytes!("fixtures/crypt4gh_kat/vec3_empty.c4gh"),
        b"",
    );
}
