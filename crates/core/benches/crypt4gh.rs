//! Criterion benchmark for the hand-rolled Crypt4GH codec encrypt/decrypt
//! throughput.
//!
//! This workspace owns the codec on the dataset handoff path, so a throughput regression here
//! is its own to catch rather than a dependency's. The codec is always compiled, with no
//! feature gate, so this bench runs in every build.
//!
//! The payload is a fixed in-memory fixture generated from a constant seed, so numbers are
//! comparable across runs. It is larger than 64 KiB, so several ChaCha20-Poly1305 body
//! segments are exercised. Throughput is reported in bytes/s via `Throughput::Bytes`.
#![expect(
    clippy::doc_markdown,
    reason = "docs use proper nouns (Crypt4GH, ChaCha20-Poly1305) as prose, not code"
)]
#![expect(
    clippy::similar_names,
    reason = "recipient/sender sk/pk are the standard, clearest crypto naming"
)]

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use gdi_node_standalone_core::crypt4gh::{
    PublicKey, SecretKey, decrypt, encrypt, generate_keypair,
};

/// Fixed payload size: 1 MiB + 777 bytes, so the body spans many 64 KiB segments
/// and the final partial segment is also exercised.
const PAYLOAD_LEN: usize = 1024 * 1024 + 777;

/// Build the fixed, deterministic benchmark payload.
///
/// A small xorshift PRNG seeded with a constant fills the buffer, so the bytes are identical
/// on every run and incompressible enough to represent a genomic payload.
fn fixed_payload() -> Vec<u8> {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut out = Vec::with_capacity(PAYLOAD_LEN);
    for _ in 0..PAYLOAD_LEN {
        // xorshift64
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.push((state & 0xFF) as u8);
    }
    out
}

/// Encrypt `payload` once, returning the Crypt4GH container bytes (the decrypt
/// bench input).
fn encrypt_once(payload: &[u8], recipient: &PublicKey, sender_sk: &SecretKey) -> Vec<u8> {
    let mut encrypted = Vec::new();
    encrypt(
        &mut &payload[..],
        &mut encrypted,
        std::slice::from_ref(recipient),
        sender_sk,
    )
    .expect("encrypt the fixed benchmark payload");
    encrypted
}

fn bench_crypt4gh(c: &mut Criterion) {
    let payload = fixed_payload();
    let (recip_sk, recip_pk) = generate_keypair();
    let (sender_sk, _sender_pk) = generate_keypair();

    let mut group = c.benchmark_group("crypt4gh");
    group.throughput(Throughput::Bytes(PAYLOAD_LEN as u64));

    group.bench_function("encrypt", |b| {
        b.iter(|| {
            let out = encrypt_once(black_box(&payload), &recip_pk, &sender_sk);
            black_box(out);
        });
    });

    let encrypted = encrypt_once(&payload, &recip_pk, &sender_sk);
    let identities = [recip_sk];
    group.bench_function("decrypt", |b| {
        b.iter(|| {
            let mut decrypted = Vec::with_capacity(PAYLOAD_LEN);
            decrypt(&mut black_box(&encrypted[..]), &mut decrypted, &identities)
                .expect("decrypt the fixed benchmark container");
            black_box(decrypted);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_crypt4gh);
criterion_main!(benches);
