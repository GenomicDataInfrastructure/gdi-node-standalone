//! Hand-rolled Crypt4GH (GA4GH) container codec over RustCrypto primitives.
//!
//! Implements the minimal subset the handoff path needs: the version-1 file format with
//! `X25519_chacha20_ietf_poly1305` header packets and 64 KiB ChaCha20-Poly1305 body
//! segments. Correctness is validated by interop with the reference Python `crypt4gh`
//! implementation, not only by a Rust self-round-trip.
//!
//! [`rewrap_header`] re-keys a header to a new recipient set, for node-identity rotation.
//! Edit lists, AES bulk encryption and passphrase-wrapped secret keys are out of scope.
//!
//! ## Why a hand-rolled codec instead of the `crypt4gh` crate
//!
//! The only published `crypt4gh` crate is a libsodium FFI binding. It requires `unsafe`,
//! which the workspace-wide `unsafe_code = "forbid"` rules out, and links a C library, which
//! fights the static-musl and `FROM scratch` deployment matrix. Its crypto fallback pulls
//! `rust-crypto 0.2.x`, unmaintained under RUSTSEC-2016-0005 and so a `cargo deny` failure,
//! and its stale transitive pins collide with the workspace's exact-pin policy. This module
//! therefore owns the framing over audited RustCrypto primitives: `x25519-dalek`,
//! `chacha20poly1305` and `blake2`. Revisit that choice if a pure-Rust,
//! `forbid(unsafe)`-compatible crypt4gh crate is published.
//!
//! File layout:
//!
//! ```text
//! magic "crypt4gh" (8) || version u32-le (=1) || packet_count u32-le
//! packet_count header packets
//! body: a sequence of 64 KiB cipher segments
//! ```
//!
//! ## Integrity boundary (what the AEAD does and does not authenticate)
//!
//! Each body segment and header packet is an independent ChaCha20-Poly1305 unit with empty
//! AAD and a self-carried random nonce. A tag authenticates a unit's contents under its key
//! but binds neither its ordinal position nor the total count, and nothing binds the body to
//! its header beyond the shared session key: no AAD, no length field, no end-of-stream
//! marker. A party holding only the ciphertext can therefore reorder or duplicate whole
//! equal-size segments, truncate the stream on a segment boundary, or splice a body between
//! headers if a session key is ever reused across payloads, and every affected segment still
//! decrypts.
//!
//! This is inherent to the Crypt4GH v1 format and shared with the reference implementation.
//! It cannot be fixed inside the codec without breaking wire-format interop, so whole-stream
//! integrity must come from the layer above. On the ingest path the decrypted tar's structure
//! and the parquet and `numberOfRecords` validation reject such manipulation, and [`encrypt`]
//! draws a fresh random session key per call, so distinct payloads never share a key. Treat a
//! successful [`decrypt`] as per-segment authenticity, not end-to-end stream authenticity.
#![expect(
    clippy::doc_markdown,
    reason = "the docs use Crypt4GH, GA4GH and RustCrypto as prose, not as code"
)]

mod body;
mod header;
pub mod keys;

use std::io::{Read, Write};

use body::{decrypt_body, encrypt_body};
use header::{PacketDecrypt, SESSION_KEY_LEN, decrypt_packet, encrypt_packet};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

pub use body::{CIPHER_SEGMENT_SIZE, SEGMENT_SIZE};
pub use keys::{
    PublicKey, SecretKey, generate_keypair, parse_public_key, parse_secret_key,
    public_key_fingerprint, serialize_public_key, serialize_secret_key,
};

use crate::error::{CoreError, CoreResult};

/// Crypt4GH magic number.
const MAGIC: &[u8; 8] = b"crypt4gh";
/// Crypt4GH format version implemented here.
const VERSION: u32 = 1;
/// Byte length of the header envelope: `magic(8) || version u32-le(4) || packet_count u32-le(4)`.
/// The first header packet begins at this offset.
const HEADER_PREFIX_LEN: usize = 16;
/// Upper bound on a single header packet's on-disk length (the u32-le prefix).
///
/// A legitimate data-encryption-parameters packet is about 108 bytes, and even an edit-list
/// packet is small. The length prefix is attacker-controlled, so a value near `u32::MAX` must
/// be rejected before allocating, or the first bytes of an external `.tar.c4gh` exhaust
/// memory. 8 KiB is far above any real packet and far below an exhausting allocation.
const MAX_HEADER_PACKET_LEN: usize = 8192;

/// Upper bound on the attacker-controlled header `packet_count`.
///
/// `packet_count` is a `u32` read straight from the start of an external `.tar.c4gh`. There
/// is one header packet per recipient identity, so a real package has a handful, while a
/// hostile count would spin the per-packet read and trial-decrypt loop over a crafted
/// multi-gigabyte header. Capped up front, symmetric with [`MAX_HEADER_PACKET_LEN`]. 1024 is
/// far above any real recipient count.
const MAX_HEADER_PACKETS: u32 = 1024;

/// Maximum trial decryptions — packets x identities — any header reader will attempt.
///
/// [`MAX_HEADER_PACKETS`] bounds the packet count, and so the header's size, but not the
/// asymmetric work: every reader loops over packets times identities, and each inner step is
/// an X25519 scalar multiplication. A header at the packet cap would force
/// `1024 x |identities|` futile scalar multiplications from a package a provider only has to
/// upload. Bounding one factor of a product bounds nothing.
///
/// 4096 is far above the largest realistic shape, since a package is wrapped to a handful of
/// recipients and a node holds a small rotation set, so a legitimate product is dozens.
///
/// `write_header_prefix` does not mirror this bound, unlike [`MAX_HEADER_PACKETS`], because
/// the budget depends on the reader's identity count, which a writer cannot know. A header
/// this codec emits can therefore be refused by a reader holding many identities, but only
/// above hundreds of recipients, which the packet cap already rules out.
const MAX_HEADER_DECRYPT_ATTEMPTS: u64 = 4096;

/// Refuse a header whose packet count, against this many identities, would cost more than
/// [`MAX_HEADER_DECRYPT_ATTEMPTS`] trial decryptions.
///
/// Checked once up front, before any packet is read, so the work is never begun rather than
/// abandoned partway.
///
/// # Errors
///
/// [`CoreError::DecryptFailed`] when the product exceeds the budget.
fn check_decrypt_budget(packet_count: u32, identities: usize) -> CoreResult<()> {
    let attempts =
        u64::from(packet_count).saturating_mul(u64::try_from(identities).unwrap_or(u64::MAX));
    if attempts > MAX_HEADER_DECRYPT_ATTEMPTS {
        return Err(CoreError::DecryptFailed);
    }
    Ok(())
}

/// Maximum number of distinct bulk-data session keys the read path accepts from a header.
///
/// A valid Crypt4GH stream carries one session key, wrapped once per recipient, so a
/// legitimate package yields a single distinct key after de-duplication however many
/// recipients the node owns. This cap rejects a hostile header that packs many distinct
/// decryptable keys purely to amplify [`body::decrypt_body`]'s per-segment trial-decrypt
/// cost: the winner pin there bounds only a stable winner, so an alternating-winner body
/// would otherwise force a tag failure per key on every 64 KiB segment.
const MAX_SESSION_KEYS: usize = 8;

/// Write the header envelope (`magic || version || packet_count`), refusing a count this
/// codec's own reader would reject.
///
/// Bounding an emitter only by `u32::try_from` would let it write a header that
/// [`read_header_prefix`] rejects as malformed, a file this codec produces and cannot read.
/// The realistic trigger is an operator configuring more than [`MAX_HEADER_PACKETS`]
/// recipients in a pack or rekey profile. Both writers funnel through this helper, checked
/// against the same constant the reader checks, so the two halves stay in agreement.
///
/// # Errors
///
/// [`CoreError::InternalError`] when `packets` exceeds [`MAX_HEADER_PACKETS`].
fn write_header_prefix<W: std::io::Write>(writer: &mut W, packets: usize) -> CoreResult<u32> {
    let count = u32::try_from(packets)
        .ok()
        .filter(|n| *n <= MAX_HEADER_PACKETS)
        .ok_or_else(|| CoreError::InternalError {
            detail: format!(
                "refusing to emit a crypt4gh header with {packets} packets: this codec reads \
                 at most {MAX_HEADER_PACKETS}, so the file would be unreadable by its own \
                 reader (too many recipients?)"
            ),
        })?;
    writer.write_all(MAGIC)?;
    writer.write_all(&VERSION.to_le_bytes())?;
    writer.write_all(&count.to_le_bytes())?;
    Ok(count)
}

/// Read and validate the Crypt4GH header envelope `magic || version || packet_count` from
/// `reader`, returning the packet count, already bounded by [`MAX_HEADER_PACKETS`].
///
/// This single-sources the envelope parse that [`decrypt`], [`recover_writer_keys`],
/// [`rewrap_header`] and [`header_len`] share. It parses attacker input, so the magic,
/// version and count checks must not drift between the four readers.
///
/// # Errors
/// [`CoreError::DecryptFailed`] on a wrong magic or version, a `packet_count` above
/// [`MAX_HEADER_PACKETS`], or a truncated read. [`CoreError::Io`] only on an underlying I/O
/// error.
fn read_header_prefix<R: Read>(reader: &mut R) -> CoreResult<u32> {
    let mut prefix = [0u8; HEADER_PREFIX_LEN];
    read_exact_or_decrypt_fail(reader, &mut prefix)?;
    if &prefix[..8] != MAGIC {
        return Err(CoreError::DecryptFailed);
    }
    let version = u32::from_le_bytes([prefix[8], prefix[9], prefix[10], prefix[11]]);
    if version != VERSION {
        return Err(CoreError::DecryptFailed);
    }
    let packet_count = u32::from_le_bytes([prefix[12], prefix[13], prefix[14], prefix[15]]);
    if packet_count > MAX_HEADER_PACKETS {
        return Err(CoreError::DecryptFailed);
    }
    Ok(packet_count)
}

/// Byte length of a Crypt4GH stream's header, computed from a leading prefix of the stream
/// without decrypting. The header is the envelope `magic || version || packet_count` plus
/// every length-prefixed header packet.
///
/// The body, a sequence of [`CIPHER_SEGMENT_SIZE`]-byte cipher segments, begins at the
/// returned offset. A consumer performing a ranged read of a `.tar.c4gh`, such as one
/// fetching only the front-of-package `manifest.json` over S3, uses this to size the range:
/// `header_len(prefix)? + n * CIPHER_SEGMENT_SIZE` covers the header plus `n` whole body
/// segments. A ranged read must end on such a segment boundary, because a mid-segment cut
/// fails to decrypt. It is published so a consumer need not re-derive the wire framing.
///
/// Returns `Ok(None)` when `prefix` is too short to contain every packet's length field, in
/// which case the caller should fetch a larger prefix and retry. An `Ok(Some(len))` may
/// exceed `prefix.len()`, which is how the caller learns how many bytes to fetch.
///
/// # Errors
/// [`CoreError::DecryptFailed`] on a malformed header envelope, or a packet count or packet
/// length outside the bounds the decrypt path enforces.
pub fn header_len(prefix: &[u8]) -> CoreResult<Option<usize>> {
    if prefix.len() < HEADER_PREFIX_LEN {
        return Ok(None);
    }
    // The same envelope parser the decrypt path runs, fed the leading 16 bytes as a reader,
    // so the two framing parsers cannot drift on magic, version or packet count.
    let packet_count = read_header_prefix(&mut &prefix[..HEADER_PREFIX_LEN])?;
    let mut pos = HEADER_PREFIX_LEN;
    for _ in 0..packet_count {
        let Some(len_bytes) = prefix.get(pos..pos + 4) else {
            return Ok(None);
        };
        let total_len =
            u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
        // The same bound `read_header_packet` enforces, so the two framing parsers cannot
        // disagree on what a valid packet length is.
        if !(8..=MAX_HEADER_PACKET_LEN).contains(&total_len) {
            return Err(CoreError::DecryptFailed);
        }
        pos = pos.checked_add(total_len).ok_or(CoreError::DecryptFailed)?;
    }
    Ok(Some(pos))
}

/// Whether any of `identities` can open the Crypt4GH header in `reader`, recovering the bulk
/// session key, without reading the body.
///
/// Reads only the header envelope and packets, so a caller may feed just the leading bytes of
/// a package, such as a ranged S3 `GET` sized with [`header_len`]. This detects a package
/// that would become undecryptable if a given identity were retired: when the header opens
/// with none of the surviving identities, retiring is unsafe, and the package must be rekeyed
/// to a current recipient first.
///
/// # Errors
/// [`CoreError::DecryptFailed`] on a malformed header envelope, or on a prefix too short to
/// contain the whole header. A truncated header is indistinguishable from a malformed one, so
/// size the prefix with [`header_len`] first. [`CoreError::Io`] only on an underlying read
/// error.
pub fn header_opens_with<R: Read>(reader: &mut R, identities: &[SecretKey]) -> CoreResult<bool> {
    let packet_count = read_header_prefix(reader)?;
    // Bound the work, not just the packet count: see `check_decrypt_budget`.
    check_decrypt_budget(packet_count, identities.len())?;
    for _ in 0..packet_count {
        let content = read_header_packet(reader)?;
        for identity in identities {
            if let PacketDecrypt::Session { .. } = decrypt_packet(&content, identity)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Read one length-prefixed Crypt4GH header packet's content from `reader`.
///
/// The 4-byte little-endian length prefix includes its own 4 bytes, and the total must lie
/// in `[8, MAX_HEADER_PACKET_LEN]`. The upper bound rejects a hostile length prefix before
/// allocating, and is single-sourced so the header readers cannot drift on it.
///
/// # Errors
/// [`CoreError::DecryptFailed`] if the length prefix is out of bounds;
/// [`CoreError::Io`] on a short read.
fn read_header_packet<R: Read>(reader: &mut R) -> CoreResult<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    read_exact_or_decrypt_fail(reader, &mut len_buf)?;
    let total_len = u32::from_le_bytes(len_buf) as usize;
    if !(8..=MAX_HEADER_PACKET_LEN).contains(&total_len) {
        return Err(CoreError::DecryptFailed);
    }
    let content_len = total_len - 4;
    let mut content = vec![0u8; content_len];
    read_exact_or_decrypt_fail(reader, &mut content)?;
    Ok(content)
}

/// Encrypt `reader` into `writer` as a Crypt4GH file addressed to `recipients`,
/// written by `sender_sk`.
///
/// A single random session (data) key is generated and carried in one header
/// packet per recipient. The body is streamed in 64 KiB segments under that
/// session key, so memory use is constant regardless of input size.
///
/// # Errors
/// Returns [`CoreError::InvalidConfig`] if `recipients` is empty,
/// [`CoreError::Io`] on a read/write failure, or [`CoreError::InternalError`]
/// if header/body AEAD encryption fails.
pub fn encrypt<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    recipients: &[PublicKey],
    sender_sk: &SecretKey,
) -> CoreResult<()> {
    if recipients.is_empty() {
        return Err(CoreError::InvalidConfig {
            detail: "crypt4gh encrypt requires at least one recipient".to_string(),
        });
    }

    // One session key for the whole body, as the reference implementation does.
    let mut session_key = Zeroizing::new([0u8; SESSION_KEY_LEN]);
    OsRng.fill_bytes(session_key.as_mut());

    // Build one header packet per recipient.
    let mut packets: Vec<Vec<u8>> = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        packets.push(encrypt_packet(&session_key, sender_sk, recipient)?);
    }

    write_header_prefix(writer, packets.len())?;
    for packet in &packets {
        writer.write_all(packet)?;
    }

    encrypt_body(reader, writer, &session_key)?;
    Ok(())
}

/// Decrypt a Crypt4GH file from `reader` into `writer`, trying each identity in
/// `identities` until one decrypts a header packet.
///
/// The body is streamed in 64 KiB segments, so memory use is constant.
///
/// # Errors
/// Returns [`CoreError::DecryptFailed`] if the magic/version is wrong, the
/// header is malformed, or no identity can decrypt any header packet; or
/// [`CoreError::Io`] on a read/write failure.
pub fn decrypt<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    identities: &[SecretKey],
) -> CoreResult<()> {
    decrypt_authenticated(reader, writer, identities).map(|_| ())
}

/// Decrypt as [`decrypt`] does, and also return the writer public key of the header packet
/// whose session key decrypted the body. `None` only for a body with no segments.
///
/// This is the only writer key it is safe to gate on. A Crypt4GH header is a list of
/// independent, self-framed, position-independent packets, and [`recover_writer_keys`] reports
/// the writer of every packet the node can open, including one copied verbatim out of somebody
/// else's package. Admitting on "any recovered fingerprint is allow-listed" would treat
/// possession of a third party's ciphertext as proof that they wrote this body: an attacker
/// could prepend a harvested packet to a package they authored and be admitted, and audited,
/// as the harvested packet's writer.
///
/// Naming the writer by the key that opened the body makes that splice inert, because the
/// spliced packet's session key is not the one the body decrypts under.
///
/// # Errors
/// As [`decrypt`].
pub fn decrypt_authenticated<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    identities: &[SecretKey],
) -> CoreResult<Option<PublicKey>> {
    // ----- Envelope -----
    let packet_count = read_header_prefix(reader)?;
    // Bound the work, not just the packet count: see `check_decrypt_budget`.
    check_decrypt_budget(packet_count, identities.len())?;

    // ----- Header packets -----
    // The recovered session keys are the bulk-data ChaCha20-Poly1305 keys, held in a
    // `Zeroizing` vector so every key is wiped on drop rather than left in freed heap.
    // Pre-sized so pushing never reallocates: a growth realloc would strand already-copied
    // key bytes in the freed backing buffer, un-zeroized.
    let mut session_keys: Zeroizing<Vec<[u8; SESSION_KEY_LEN]>> =
        Zeroizing::new(Vec::with_capacity(
            usize::try_from(packet_count)
                .unwrap_or(0)
                .min(MAX_SESSION_KEYS),
        ));
    // The writer public key of the packet each session key came from, index-aligned with
    // `session_keys` so the body's winning key index names its writer. Public material, so
    // no zeroization is warranted.
    let mut writer_keys: Vec<PublicKey> = Vec::with_capacity(session_keys.capacity());
    for _ in 0..packet_count {
        let content = read_header_packet(reader)?;

        for identity in identities {
            match decrypt_packet(&content, identity)? {
                PacketDecrypt::Session { key, writer_pk } => {
                    // De-duplicate identical keys and cap the distinct count at
                    // `MAX_SESSION_KEYS`: a valid stream wraps one session key, once per
                    // recipient, so this admits every legitimate package. The read path
                    // needs the hard cap because, unlike rewrap, it feeds the keys to the
                    // body decryptor.
                    if !session_keys.iter().any(|k| k[..] == key[..]) {
                        if session_keys.len() >= MAX_SESSION_KEYS {
                            return Err(CoreError::DecryptFailed);
                        }
                        session_keys.push(*key);
                        // Pushed together so the two stay index-aligned.
                        writer_keys.push(writer_pk);
                    }
                    break;
                }
                // A decrypted but non-session packet, such as an edit list, is ignored on
                // read: this codec does not honour edit lists.
                PacketDecrypt::WrongIdentity
                | PacketDecrypt::Unsupported
                | PacketDecrypt::DecryptedUnsupported => {}
            }
        }
    }

    if session_keys.is_empty() {
        return Err(CoreError::DecryptFailed);
    }

    // ----- Body -----
    // The winning index names the packet that authenticated the body. A header packet whose
    // key never opened a segment, such as one spliced in from another package, is not it.
    let winner = decrypt_body(reader, writer, &session_keys)?;
    Ok(winner.and_then(|i| writer_keys.get(i).cloned()))
}

/// Recover the Crypt4GH writer public keys from a stream's header by decrypting each header
/// packet with `identities`, without decrypting the body.
///
/// The writer key is bound into each header packet's key derivation, so it is the one
/// provenance signal a package carries without a signature. `inspect` and `validate` surface
/// it so an operator can see who wrote a package. De-duplicated, in first-seen order, and
/// read-only.
///
/// This is proof of possession, not an authenticated identity. A packet decrypts only if its
/// carried writer key is the genuine public key of whatever secret the author used, so it
/// cannot be set to a victim's key without that victim's secret. It is not a signature:
/// anyone who knows the recipient's public key can author a valid package under a fresh
/// writer key of their own. Treat the returned key as a trust anchor only when compared
/// against an out-of-band allowlist, never as an unforgeable claim of origin.
///
/// # Errors
/// Returns [`CoreError::DecryptFailed`] on a bad magic/version/header or if no
/// identity decrypts any packet; or [`CoreError::Io`] on a read failure.
pub fn recover_writer_keys<R: Read>(
    reader: &mut R,
    identities: &[SecretKey],
) -> CoreResult<Vec<PublicKey>> {
    let packet_count = read_header_prefix(reader)?;
    // Bound the work, not just the packet count: see `check_decrypt_budget`.
    check_decrypt_budget(packet_count, identities.len())?;

    let mut writers: Vec<PublicKey> = Vec::new();
    for _ in 0..packet_count {
        let content = read_header_packet(reader)?;
        for identity in identities {
            if let PacketDecrypt::Session { writer_pk, .. } = decrypt_packet(&content, identity)? {
                if !writers.iter().any(|w| w.as_bytes() == writer_pk.as_bytes()) {
                    writers.push(writer_pk);
                }
                break;
            }
        }
    }

    if writers.is_empty() {
        return Err(CoreError::DecryptFailed);
    }
    Ok(writers)
}

/// Re-key (rewrap) a Crypt4GH stream's header to a new recipient set, copying the
/// encrypted body byte-for-byte.
///
/// This is the node-identity rotation primitive, and rotating an identity must not
/// re-encrypt the payload. The owner recovers the session key by decrypting an existing
/// header packet with one of `identities`, then writes a fresh header that encrypts that same
/// session key to `new_recipients`, passing every body segment through unchanged. The output
/// is a complete, valid Crypt4GH stream.
///
/// `new_recipients` replace the original recipient list, so the fresh header no longer lets a
/// prior recipient re-derive the session key through its own header. This is re-addressing,
/// not revocation. The body is copied byte-for-byte under the same session key, so a prior
/// recipient that retained that session key from an earlier decrypt, or kept a copy of the
/// original ciphertext, can still recover the plaintext. Rewrap therefore gives neither
/// forward secrecy nor revocation; real revocation would require re-encrypting the body under
/// a fresh session key. A fresh ephemeral sender keypair writes the new header packets, as
/// the reference implementation does when given no writer key, so the rewrap leaks no
/// provider identity into the new header.
///
/// The body is streamed in 64 KiB cipher segments, so memory use is constant whatever the
/// payload size.
///
/// # Errors
/// Returns [`CoreError::InvalidConfig`] if `new_recipients` is empty,
/// [`CoreError::DecryptFailed`] if the magic/version is wrong, the header is
/// malformed, or no identity in `identities` can decrypt any header packet,
/// [`CoreError::InvalidManifest`] if the stream carries a non-data-encryption header packet,
/// such as an edit list, that rewrap cannot faithfully re-encode, or [`CoreError::Io`] on a
/// read or write failure.
pub fn rewrap_header<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    identities: &[SecretKey],
    new_recipients: &[PublicKey],
) -> CoreResult<()> {
    rewrap_header_as(reader, writer, identities, new_recipients, None)
}

/// As [`rewrap_header`], but optionally stamps the rewritten header with a specific writer
/// key instead of a fresh ephemeral one.
///
/// The writer key a node checks against its `writer_policy = enforce` allow-list is the
/// Crypt4GH sender public key of the header packets. A plain rewrap mints a fresh ephemeral
/// sender, so the fingerprint changes on every rekey and an enforcing node rejects the
/// result, even though the node-key-rotation runbook tells every provider to rekey. Passing
/// the provider's own key re-stamps the header with it, so the recovered fingerprint is
/// stable, knowable in advance and already allow-listed, being the key that authored the
/// original package. `None` keeps the ephemeral behaviour, which suits a node that does not
/// enforce.
///
/// # Errors
///
/// As [`rewrap_header`]: empty `new_recipients`, an unreadable/undecryptable header, a
/// non-data-encryption header packet, or a write failure.
pub fn rewrap_header_as<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    identities: &[SecretKey],
    new_recipients: &[PublicKey],
    writer_sk: Option<&SecretKey>,
) -> CoreResult<()> {
    if new_recipients.is_empty() {
        return Err(CoreError::InvalidConfig {
            detail: "crypt4gh rewrap requires at least one new recipient".to_string(),
        });
    }

    // ----- Envelope (magic || version || packet_count) -----
    let packet_count = read_header_prefix(reader)?;
    // Bound the work, not just the packet count: see `check_decrypt_budget`.
    check_decrypt_budget(packet_count, identities.len())?;

    // ----- Recover the session key(s) from the old header -----
    // The body is unchanged, so only the data-encryption keys are needed. The old header
    // packets are consumed and nothing from them is emitted.
    let mut session_keys: Vec<Zeroizing<[u8; SESSION_KEY_LEN]>> =
        Vec::with_capacity(usize::try_from(packet_count).unwrap_or(0));
    for _ in 0..packet_count {
        let content = read_header_packet(reader)?;

        for identity in identities {
            match decrypt_packet(&content, identity)? {
                PacketDecrypt::Session { key, .. } => {
                    // A package may wrap the same session key in several packets, one per
                    // owned recipient. Recording it once keeps the rewrapped header minimal
                    // and mirrors the writer-key de-duplication in `recover_writer_keys`.
                    // These are locally recovered keys, so a non-constant-time compare is
                    // fine.
                    if !session_keys.iter().any(|k| k[..] == key[..]) {
                        session_keys.push(key);
                    }
                    break;
                }
                // A packet that decrypted but is not a data-encryption-parameters packet,
                // such as an edit list, cannot be faithfully re-encoded here. Reject it
                // rather than dropping it from the rewrapped output.
                PacketDecrypt::DecryptedUnsupported => {
                    return Err(CoreError::InvalidManifest {
                        detail: "crypt4gh rewrap does not support a stream containing a \
                                 non-data-encryption header packet (e.g. an edit list)"
                            .to_string(),
                    });
                }
                PacketDecrypt::WrongIdentity | PacketDecrypt::Unsupported => {}
            }
        }
    }

    if session_keys.is_empty() {
        return Err(CoreError::DecryptFailed);
    }

    // ----- Emit a fresh header addressed to the new recipients -----
    // The sender key stamps the writer key the node's allow-list checks. Given a
    // `writer_sk`, stamp that key so the writer identity is stable and allow-listable;
    // otherwise a fresh ephemeral keypair writes the new packets and the rewrap is tied to no
    // persistent writer identity. Each recovered session key is re-wrapped to each new
    // recipient, preserving a multi-key body.
    //
    // The ephemeral key is bound outside the branch so a borrow of it outlives the arm.
    let ephemeral_sk;
    let sender_sk = if let Some(sk) = writer_sk {
        sk
    } else {
        ephemeral_sk = generate_keypair().0;
        &ephemeral_sk
    };
    let mut packets: Vec<Vec<u8>> = Vec::with_capacity(session_keys.len() * new_recipients.len());
    for session_key in &session_keys {
        for recipient in new_recipients {
            packets.push(encrypt_packet(session_key, sender_sk, recipient)?);
        }
    }

    write_header_prefix(writer, packets.len())?;
    for packet in &packets {
        writer.write_all(packet)?;
    }

    // ----- Copy the body byte-for-byte (no re-encryption) -----
    copy_stream(reader, writer)?;
    Ok(())
}

/// Copy the remainder of `reader` to `writer` in bounded chunks (the unchanged
/// Crypt4GH body during a header rewrap), in constant memory.
fn copy_stream<R: Read, W: Write>(reader: &mut R, writer: &mut W) -> CoreResult<()> {
    // One cipher segment's worth keeps memory bounded and matches the body's natural
    // segment size. Any similar size would do for a raw copy.
    let mut buf = vec![0u8; body::CIPHER_SEGMENT_SIZE];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => writer.write_all(&buf[..n])?,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(CoreError::Io(e)),
        }
    }
    Ok(())
}

/// Read exactly `buf.len()` bytes, mapping a shortfall or EOF to
/// [`CoreError::DecryptFailed`], because a truncated header is a decrypt failure rather than
/// a generic I/O error. Real I/O errors still surface as [`CoreError::Io`].
fn read_exact_or_decrypt_fail<R: Read>(reader: &mut R, buf: &mut [u8]) -> CoreResult<()> {
    match reader.read_exact(buf) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Err(CoreError::DecryptFailed),
        Err(e) => Err(CoreError::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    #![expect(
        clippy::similar_names,
        reason = "sender/recipient sk/pk are the standard, clearest crypto naming"
    )]

    #[test]
    fn the_header_trial_decrypt_budget_bounds_packets_times_identities() {
        // `MAX_HEADER_PACKETS` bounds the packet count, not the asymmetric work: every
        // header reader loops over packets times identities, and each inner step is an
        // X25519 scalar multiplication. A header at the packet cap forces
        // 1024 x |identities| futile scalar multiplications from a package a provider only
        // has to upload.
        assert!(check_decrypt_budget(1, 1).is_ok());
        // A real package: a handful of recipients, a node holding a rotation set.
        assert!(check_decrypt_budget(8, 8).is_ok());
        // The packet cap alone, against a single identity, is still fine.
        assert!(check_decrypt_budget(MAX_HEADER_PACKETS, 1).is_ok());

        // The amplification: the packet cap against a realistic rotation set.
        assert!(
            check_decrypt_budget(MAX_HEADER_PACKETS, 16).is_err(),
            "1024 packets x 16 identities is 16384 futile scalar multiplications"
        );
        // The product is what is bounded, so it trips from either direction.
        assert!(check_decrypt_budget(MAX_HEADER_PACKETS / 2, 32).is_err());
        // No overflow panic on absurd inputs.
        assert!(check_decrypt_budget(u32::MAX, usize::MAX).is_err());
    }

    use super::*;

    /// Anything the emitters produce must be accepted by this codec's own reader.
    ///
    /// Bounding `packet_count` only by `u32::try_from` would let more than
    /// `MAX_HEADER_PACKETS` recipients write a header that `read_header_prefix` rejects as
    /// malformed, a file the codec produces and cannot read. The check lives in one helper,
    /// against the same constant the reader uses.
    #[test]
    fn the_emitter_refuses_a_packet_count_its_own_reader_would_reject() {
        let mut out = Vec::new();
        let err = write_header_prefix(&mut out, MAX_HEADER_PACKETS as usize + 1)
            .expect_err("a count above the reader's bound must be refused at write time");
        assert!(
            err.to_string().contains("unreadable by its own reader"),
            "the error should say why: {err}"
        );
        assert!(
            out.is_empty(),
            "nothing may be written when the count is refused"
        );

        // The boundary itself is accepted, and round-trips through the reader.
        let mut ok = Vec::new();
        let n = write_header_prefix(&mut ok, MAX_HEADER_PACKETS as usize).expect("at the bound");
        assert_eq!(n, MAX_HEADER_PACKETS);
        assert_eq!(
            read_header_prefix(&mut &ok[..]).expect("reader accepts what the writer emitted"),
            MAX_HEADER_PACKETS
        );
    }

    #[test]
    fn header_opens_with_only_a_recipient_identity() {
        // A package addressed to recipient A opens with A's key, not with a stranger's.
        let (recip_sk, recip_pk) = generate_keypair();
        let (stranger_sk, _stranger_pk) = generate_keypair();
        let (sender_sk, _sender_pk) = generate_keypair();
        let mut encrypted = Vec::new();
        encrypt(
            &mut &b"payload"[..],
            &mut encrypted,
            &[recip_pk],
            &sender_sk,
        )
        .unwrap();

        assert!(super::header_opens_with(&mut &encrypted[..], &[recip_sk]).unwrap());
        assert!(!super::header_opens_with(&mut &encrypted[..], &[stranger_sk]).unwrap());
        // No identities cannot open anything.
        assert!(!super::header_opens_with(&mut &encrypted[..], &[]).unwrap());
    }

    #[test]
    fn header_opens_with_reads_only_the_header_not_the_body() {
        // Feeding only the header bytes, with no body, is enough to answer openability.
        let (recip_sk, recip_pk) = generate_keypair();
        let (sender_sk, _sender_pk) = generate_keypair();
        let mut encrypted = Vec::new();
        encrypt(
            &mut &sample_payload()[..],
            &mut encrypted,
            &[recip_pk],
            &sender_sk,
        )
        .unwrap();
        let hlen = super::header_len(&encrypted).unwrap().unwrap();
        assert!(super::header_opens_with(&mut &encrypted[..hlen], &[recip_sk]).unwrap());
    }

    #[test]
    fn public_header_len_of_empty_payload_is_the_whole_stream() {
        // Encrypting an empty payload yields a header and zero body segments, so the whole
        // stream is the header. A consumer can therefore learn the exact header length from
        // the leading bytes alone, without re-encrypting.
        let (_recip_sk, recip_pk) = generate_keypair();
        let (sender_sk, _sender_pk) = generate_keypair();
        let mut encrypted = Vec::new();
        encrypt(
            &mut std::io::empty(),
            &mut encrypted,
            &[recip_pk],
            &sender_sk,
        )
        .unwrap();
        assert_eq!(
            super::header_len(&encrypted).unwrap(),
            Some(encrypted.len()),
            "empty-payload stream is header-only"
        );
    }

    #[test]
    fn public_header_len_is_payload_independent() {
        // The header length depends only on the recipient set, not the payload, which is
        // what lets a ranged reader size the front-read from a short probe.
        let (_recip_sk, recip_pk) = generate_keypair();
        let (sender_sk, _sender_pk) = generate_keypair();
        let recips = [recip_pk];
        let mut empty = Vec::new();
        encrypt(&mut std::io::empty(), &mut empty, &recips, &sender_sk).unwrap();
        let mut big = Vec::new();
        encrypt(&mut &sample_payload()[..], &mut big, &recips, &sender_sk).unwrap();
        assert_eq!(
            super::header_len(&big).unwrap(),
            Some(empty.len()),
            "header length must be independent of the payload"
        );
    }

    #[test]
    fn public_header_len_is_none_when_prefix_too_short() {
        // Too few bytes to determine the header length is a recoverable "fetch more"
        // rather than a malformed-header error.
        let (_recip_sk, recip_pk) = generate_keypair();
        let (sender_sk, _sender_pk) = generate_keypair();
        let mut encrypted = Vec::new();
        encrypt(
            &mut std::io::empty(),
            &mut encrypted,
            &[recip_pk],
            &sender_sk,
        )
        .unwrap();
        assert_eq!(super::header_len(&encrypted[..8]).unwrap(), None);
        assert_eq!(super::header_len(&[]).unwrap(), None);
    }

    #[test]
    fn public_header_len_rejects_a_malformed_envelope() {
        // Wrong magic and wrong version are malformed, not "fetch more".
        let mut bad_magic = vec![0u8; 16];
        bad_magic[..8].copy_from_slice(b"NOTc4gh!");
        std::assert_matches!(super::header_len(&bad_magic), Err(CoreError::DecryptFailed));

        let mut bad_version = Vec::new();
        bad_version.extend_from_slice(MAGIC);
        bad_version.extend_from_slice(&2u32.to_le_bytes()); // version 2, unsupported
        bad_version.extend_from_slice(&0u32.to_le_bytes()); // packet_count 0
        std::assert_matches!(
            super::header_len(&bad_version),
            Err(CoreError::DecryptFailed)
        );
    }

    fn sample_payload() -> Vec<u8> {
        // Over 64 KiB, to force multiple body segments.
        (0..(65_536u32 * 2 + 777))
            .map(|i| u8::try_from(i % 253).unwrap_or(0))
            .collect()
    }

    #[test]
    fn rust_roundtrip() {
        let (recip_sk, recip_pk) = generate_keypair();
        let (sender_sk, _sender_pk) = generate_keypair();
        let payload = sample_payload();

        let mut encrypted = Vec::new();
        encrypt(&mut &payload[..], &mut encrypted, &[recip_pk], &sender_sk).unwrap();

        let mut decrypted = Vec::new();
        decrypt(&mut &encrypted[..], &mut decrypted, &[recip_sk]).unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn wrong_identity_decrypt_fails() {
        let (_recip_sk, recip_pk) = generate_keypair();
        let (sender_sk, _sender_pk) = generate_keypair();
        let (other_sk, _other_pk) = generate_keypair();
        let payload = b"top secret";

        let mut encrypted = Vec::new();
        encrypt(&mut &payload[..], &mut encrypted, &[recip_pk], &sender_sk).unwrap();

        let mut out = Vec::new();
        std::assert_matches!(
            decrypt(&mut &encrypted[..], &mut out, &[other_sk]),
            Err(CoreError::DecryptFailed)
        );
    }

    #[test]
    fn tampered_header_packet_ciphertext_fails() {
        // Flip one byte inside the single header packet's ChaCha20-Poly1305 ciphertext and
        // decrypt with the correct key. The header AEAD tag check must fail, so no session
        // key is recovered. This is integrity rather than confidentiality: a wrong-key
        // failure alone does not prove tamper rejection under the right key.
        let (recip_sk, recip_pk) = generate_keypair();
        let (sender_sk, _sender_pk) = generate_keypair();
        let payload = [0xA5u8; 100];

        let mut encrypted = Vec::new();
        encrypt(&mut &payload[..], &mut encrypted, &[recip_pk], &sender_sk).unwrap();

        // Layout for a 100-byte payload, one recipient: 16-byte envelope ||
        // 108-byte header packet || 128-byte body segment (12 nonce + 100 ct + 16
        // tag) = 252 bytes. Guard the offsets against a framing change.
        assert_eq!(encrypted.len(), 252, "unexpected stream layout");
        // Header packet ciphertext+tag is bytes [68, 124); 100 is mid-ciphertext.
        encrypted[100] ^= 0x01;

        let mut out = Vec::new();
        std::assert_matches!(
            decrypt(&mut &encrypted[..], &mut out, &[recip_sk]),
            Err(CoreError::DecryptFailed)
        );
    }

    #[test]
    fn tampered_body_segment_ciphertext_fails() {
        // Flip one byte in the first body segment's ciphertext and decrypt with the correct
        // key: the segment AEAD tag check must reject it.
        let (recip_sk, recip_pk) = generate_keypair();
        let (sender_sk, _sender_pk) = generate_keypair();
        let payload = [0xA5u8; 100];

        let mut encrypted = Vec::new();
        encrypt(&mut &payload[..], &mut encrypted, &[recip_pk], &sender_sk).unwrap();

        assert_eq!(encrypted.len(), 252, "unexpected stream layout");
        // Body segment starts at 124: nonce [124,136), ciphertext [136,236),
        // tag [236,252). 200 is inside the ciphertext.
        encrypted[200] ^= 0x01;

        let mut out = Vec::new();
        std::assert_matches!(
            decrypt(&mut &encrypted[..], &mut out, &[recip_sk]),
            Err(CoreError::DecryptFailed)
        );
    }

    #[test]
    fn tampered_body_segment_nonce_fails() {
        // Flip one byte in the first body segment's 12-byte nonce and decrypt with the
        // correct key. The keystream no longer matches, so the Poly1305 tag check fails.
        let (recip_sk, recip_pk) = generate_keypair();
        let (sender_sk, _sender_pk) = generate_keypair();
        let payload = [0xA5u8; 100];

        let mut encrypted = Vec::new();
        encrypt(&mut &payload[..], &mut encrypted, &[recip_pk], &sender_sk).unwrap();

        assert_eq!(encrypted.len(), 252, "unexpected stream layout");
        // First body segment nonce occupies bytes [124, 136).
        encrypted[124] ^= 0x01;

        let mut out = Vec::new();
        std::assert_matches!(
            decrypt(&mut &encrypted[..], &mut out, &[recip_sk]),
            Err(CoreError::DecryptFailed)
        );
    }

    #[test]
    fn truncated_multi_segment_body_is_rejected() {
        // Encrypt a payload spanning more than one body segment, then for several prefix
        // lengths that cut the stream mid-segment, after one or more whole earlier segments,
        // assert that `decrypt` fails. This is the "stream cut in transit after valid earlier
        // segments" case. The output is not asserted empty: the streaming codec writes each
        // whole earlier segment before the truncated tail fails.
        let (recip_sk, recip_pk) = generate_keypair();
        let (sender_sk, _sender_pk) = generate_keypair();
        let payload = sample_payload();

        let mut encrypted = Vec::new();
        encrypt(&mut &payload[..], &mut encrypted, &[recip_pk], &sender_sk).unwrap();

        let header = header_len_of(&encrypted);
        let seg = body::CIPHER_SEGMENT_SIZE;
        assert!(
            encrypted.len() > header + seg,
            "test payload must span more than one body segment"
        );

        // Cuts that all land strictly inside a segment, never on a clean boundary:
        // 1 byte into segment 0; 10 bytes into segment 1; mid-segment 1.
        let truncations = [header + 1, header + seg + 10, header + seg + (seg / 2)];
        for &cut in &truncations {
            assert!(
                cut < encrypted.len(),
                "truncation {cut} must be a strict prefix"
            );
            let prefix = &encrypted[..cut];
            let mut out = Vec::new();
            std::assert_matches!(
                decrypt(&mut &prefix[..], &mut out, std::slice::from_ref(&recip_sk)),
                Err(CoreError::DecryptFailed),
                "decrypt of a {cut}-byte mid-segment prefix must fail",
            );
        }
    }

    #[test]
    fn malformed_header_errors_not_panics() {
        let (sk, _pk) = generate_keypair();
        let mut out = Vec::new();
        // magic + version=1 + then garbage where a packet length should be.
        let input = b"crypt4gh\x01\x00\x00\x00garbage";
        let result = decrypt(&mut &input[..], &mut out, &[sk]);
        std::assert_matches!(
            result,
            Err(CoreError::DecryptFailed),
            "a malformed header must produce DecryptFailed, got {result:?}"
        );
    }

    #[test]
    fn out_of_range_header_packet_length_is_rejected_without_allocating() {
        // The `MAX_HEADER_PACKET_LEN` bound (the packet length must be in `8..=MAX`) is
        // enforced up front, before any allocation. What is locked is the boundary itself
        // rather than one literal: too-small, just-over-max and hostile-huge are all
        // rejected.
        let max = u32::try_from(MAX_HEADER_PACKET_LEN).unwrap_or(u32::MAX);
        for bad_len in [0u32, 1, 7, max + 1, 0x00ff_ffff, 0xffff_ff6c] {
            let (sk, _pk) = generate_keypair();
            let mut input = Vec::new();
            input.extend_from_slice(b"crypt4gh");
            input.extend_from_slice(&1u32.to_le_bytes()); // version
            input.extend_from_slice(&1u32.to_le_bytes()); // packet_count
            input.extend_from_slice(&bad_len.to_le_bytes()); // out-of-range length
            let mut out = Vec::new();
            std::assert_matches!(
                decrypt(&mut &input[..], &mut out, &[sk]),
                Err(CoreError::DecryptFailed),
                "header packet length {bad_len} (outside 8..={MAX_HEADER_PACKET_LEN}) must be rejected"
            );
        }
    }

    #[test]
    fn oversized_packet_count_is_rejected_before_reading_packets() {
        // A hostile packet_count must be rejected after the 16-byte envelope prefix, not by
        // looping over (up to ~4.29e9) crafted header packets. Feeding a count just over the
        // cap followed by many minimal valid packets, decrypt must consume only the prefix.
        struct Counting<'a> {
            data: &'a [u8],
            pos: usize,
        }
        impl std::io::Read for Counting<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = std::io::Read::read(&mut &self.data[self.pos..], buf)?;
                self.pos += n;
                Ok(n)
            }
        }

        let (sk, _pk) = generate_keypair();
        let mut input = Vec::new();
        input.extend_from_slice(b"crypt4gh");
        input.extend_from_slice(&1u32.to_le_bytes()); // version
        input.extend_from_slice(&(MAX_HEADER_PACKETS + 1).to_le_bytes()); // packet_count
        for _ in 0..2000 {
            input.extend_from_slice(&8u32.to_le_bytes()); // total_len = 8 (min valid)
            input.extend_from_slice(&[0u8; 4]); // 4 bytes content
        }

        let mut reader = Counting {
            data: &input,
            pos: 0,
        };
        let mut out = Vec::new();
        std::assert_matches!(
            decrypt(&mut reader, &mut out, &[sk]),
            Err(CoreError::DecryptFailed)
        );
        assert!(
            reader.pos <= 16,
            "decrypt consumed {} bytes; the packet-count cap should reject after the 16-byte prefix",
            reader.pos
        );
    }

    #[test]
    fn empty_recipients_is_rejected() {
        let (sender_sk, _pk) = generate_keypair();
        let mut out = Vec::new();
        std::assert_matches!(
            encrypt(&mut &b"x"[..], &mut out, &[], &sender_sk),
            Err(CoreError::InvalidConfig { .. })
        );
    }

    #[test]
    fn rewrap_rotates_from_a_to_b() {
        // Pure-Rust rotation proof (no Python): encrypt to A, rewrap A->B, then
        // (1) B decrypts to the original plaintext, and
        // (2) A alone can no longer decrypt (the rotation property).
        let (sk_a, pk_a) = generate_keypair();
        let (sk_b, pk_b) = generate_keypair();
        let (sender_sk, _sender_pk) = generate_keypair();
        let payload = sample_payload();

        // Encrypt to A.
        let mut to_a = Vec::new();
        encrypt(&mut &payload[..], &mut to_a, &[pk_a], &sender_sk).unwrap();

        // Rewrap the header from A to B; the new recipients replace the old set.
        let mut to_b = Vec::new();
        rewrap_header(
            &mut &to_a[..],
            &mut to_b,
            std::slice::from_ref(&sk_a),
            &[pk_b],
        )
        .unwrap();

        // B decrypts to the original plaintext.
        let mut decrypted = Vec::new();
        decrypt(&mut &to_b[..], &mut decrypted, &[sk_b]).unwrap();
        assert_eq!(decrypted, payload, "B must decrypt the rewrapped package");

        // The body bytes are unchanged, since only the header was rewritten.
        let body_a = &to_a[header_len_of(&to_a)..];
        let body_b = &to_b[header_len_of(&to_b)..];
        assert_eq!(body_a, body_b, "rewrap must copy the body byte-for-byte");

        // The rotation property: A alone can no longer decrypt the new package.
        let mut out = Vec::new();
        std::assert_matches!(
            decrypt(&mut &to_b[..], &mut out, &[sk_a]),
            Err(CoreError::DecryptFailed),
            "A must NOT be able to decrypt after rotation to B"
        );
    }

    #[test]
    fn rewrap_as_stamps_a_stable_writer_key_the_node_can_recover() {
        // A plain rewrap mints a fresh ephemeral sender, so the recovered writer key is
        // random and `writer_policy = enforce` rejects the rekeyed package. Stamping the
        // rewrap with the provider's own key makes the recovered writer key that key's public
        // half: stable, knowable and allow-listable, so a rekey survives enforcement.
        let (sk_a, pk_a) = generate_keypair();
        let (sk_b, pk_b) = generate_keypair();
        let (sender_sk, _sender_pk) = generate_keypair();
        let (provider_sk, provider_pk) = generate_keypair();
        let payload = sample_payload();

        let mut to_a = Vec::new();
        encrypt(&mut &payload[..], &mut to_a, &[pk_a], &sender_sk).unwrap();

        // Rewrap A to B, stamped with the provider key.
        let mut to_b = Vec::new();
        rewrap_header_as(
            &mut &to_a[..],
            &mut to_b,
            std::slice::from_ref(&sk_a),
            std::slice::from_ref(&pk_b),
            Some(&provider_sk),
        )
        .unwrap();

        // B still decrypts, so correctness is preserved.
        let mut decrypted = Vec::new();
        decrypt(&mut &to_b[..], &mut decrypted, std::slice::from_ref(&sk_b)).unwrap();
        assert_eq!(decrypted, payload);

        // The recovered writer key, which the node checks against its allow-list, is the
        // provider's key rather than a random ephemeral one.
        let writers = recover_writer_keys(&mut &to_b[..], std::slice::from_ref(&sk_b)).unwrap();
        assert_eq!(writers.len(), 1);
        assert_eq!(
            writers[0].as_bytes(),
            provider_pk.as_bytes(),
            "rewrap --as must stamp the provider's key as the writer"
        );

        // By contrast, a plain rewrap yields a writer key that is neither the provider's nor
        // the original sender's, but a fresh ephemeral one.
        let mut to_b_ephemeral = Vec::new();
        rewrap_header(
            &mut &to_a[..],
            &mut to_b_ephemeral,
            std::slice::from_ref(&sk_a),
            std::slice::from_ref(&pk_b),
        )
        .unwrap();
        let eph =
            recover_writer_keys(&mut &to_b_ephemeral[..], std::slice::from_ref(&sk_b)).unwrap();
        assert_ne!(
            eph[0].as_bytes(),
            provider_pk.as_bytes(),
            "the plain rewrap must NOT coincidentally stamp the provider key"
        );
    }

    #[test]
    fn rewrap_to_multiple_recipients_all_can_decrypt() {
        // Rewrap to {B, C}: both new recipients decrypt; the old A does not.
        let (sk_a, pk_a) = generate_keypair();
        let (sk_b, pk_b) = generate_keypair();
        let (sk_c, pk_c) = generate_keypair();
        let (sender_sk, _sender_pk) = generate_keypair();
        let payload = b"rotate to two new recipients".to_vec();

        let mut to_a = Vec::new();
        encrypt(&mut &payload[..], &mut to_a, &[pk_a], &sender_sk).unwrap();

        let mut to_bc = Vec::new();
        rewrap_header(
            &mut &to_a[..],
            &mut to_bc,
            std::slice::from_ref(&sk_a),
            &[pk_b, pk_c],
        )
        .unwrap();

        for sk in [sk_b, sk_c] {
            let mut out = Vec::new();
            decrypt(&mut &to_bc[..], &mut out, &[sk]).unwrap();
            assert_eq!(out, payload);
        }
        let mut out = Vec::new();
        std::assert_matches!(
            decrypt(&mut &to_bc[..], &mut out, &[sk_a]),
            Err(CoreError::DecryptFailed)
        );
    }

    #[test]
    fn rewrap_empty_recipients_is_rejected() {
        let (sk_a, pk_a) = generate_keypair();
        let (sender_sk, _pk) = generate_keypair();
        let mut to_a = Vec::new();
        encrypt(&mut &b"x"[..], &mut to_a, &[pk_a], &sender_sk).unwrap();
        let mut out = Vec::new();
        std::assert_matches!(
            rewrap_header(&mut &to_a[..], &mut out, &[sk_a], &[]),
            Err(CoreError::InvalidConfig { .. })
        );
    }

    #[test]
    fn rewrap_wrong_identity_fails() {
        // No identity can decrypt the old header, so nothing is emitted.
        let (_sk_a, pk_a) = generate_keypair();
        let (other_sk, _other_pk) = generate_keypair();
        let (_sk_b, pk_b) = generate_keypair();
        let (sender_sk, _pk) = generate_keypair();
        let mut to_a = Vec::new();
        encrypt(&mut &b"secret"[..], &mut to_a, &[pk_a], &sender_sk).unwrap();
        let mut out = Vec::new();
        std::assert_matches!(
            rewrap_header(&mut &to_a[..], &mut out, &[other_sk], &[pk_b]),
            Err(CoreError::DecryptFailed)
        );
    }

    #[test]
    fn rewrap_rejects_stream_with_non_session_packet() {
        // A header carrying a decryptable non-data-encryption packet, such as an edit list,
        // must make rewrap fail loudly rather than drop the packet and emit a header that no
        // longer represents the input stream.
        use super::header::encrypt_packet_with_type;
        let (sk_r, pk_r) = generate_keypair();
        let (sender_sk, _p) = generate_keypair();
        let (_sk_b, pk_b) = generate_keypair();
        let session_key = [3u8; SESSION_KEY_LEN];

        // Envelope, a valid data packet and an edit-list packet, both addressed to R. There
        // is no body, because rewrap rejects during header recovery.
        let data = encrypt_packet_with_type(0, &session_key, &sender_sk, &pk_r).unwrap();
        let editlist = encrypt_packet_with_type(1, &session_key, &sender_sk, &pk_r).unwrap();
        let mut stream = Vec::new();
        stream.extend_from_slice(b"crypt4gh");
        stream.extend_from_slice(&1u32.to_le_bytes()); // version
        stream.extend_from_slice(&2u32.to_le_bytes()); // packet_count = 2
        stream.extend_from_slice(&data);
        stream.extend_from_slice(&editlist);

        let mut out = Vec::new();
        let res = rewrap_header(
            &mut &stream[..],
            &mut out,
            std::slice::from_ref(&sk_r),
            &[pk_b],
        );
        std::assert_matches!(
            res,
            Err(CoreError::InvalidManifest { .. }),
            "rewrap of a stream with a non-data-encryption header packet must be rejected, got {res:?}"
        );
        assert!(out.is_empty(), "a rejected rewrap must emit nothing");
    }

    #[test]
    fn rewrap_deduplicates_identical_session_keys() {
        // A package encrypted to two owned recipients wraps the same session key in two
        // header packets. Rewrapping with both identities must recover that key once and
        // emit a single packet per new recipient, not one per duplicate.
        let (sk_r1, pk_r1) = generate_keypair();
        let (sk_r2, pk_r2) = generate_keypair();
        let (sender_sk, _p) = generate_keypair();
        let (sk_b, pk_b) = generate_keypair();
        let payload = b"dedupe the recovered session key".to_vec();

        let mut to_r = Vec::new();
        encrypt(&mut &payload[..], &mut to_r, &[pk_r1, pk_r2], &sender_sk).unwrap();

        let mut to_b = Vec::new();
        rewrap_header(&mut &to_r[..], &mut to_b, &[sk_r1, sk_r2], &[pk_b]).unwrap();

        // Exactly one header packet: one de-duplicated session key times one recipient.
        let count = u32::from_le_bytes([to_b[12], to_b[13], to_b[14], to_b[15]]);
        assert_eq!(
            count, 1,
            "rewrap must de-duplicate the identical recovered session key"
        );

        // B still decrypts to the original plaintext.
        let mut out = Vec::new();
        decrypt(&mut &to_b[..], &mut out, &[sk_b]).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn decrypt_tolerates_and_ignores_a_non_session_header_packet() {
        // Rewrap rejects such a package, but the read path must tolerate an external one
        // carrying a non-data-encryption header packet: decrypt ignores it and recovers the
        // body through the data packet. Exercises the `DecryptedUnsupported` arm end to end.
        use super::header::encrypt_packet_with_type;
        let (sk_r, pk_r) = generate_keypair();
        let (sender_sk, _p) = generate_keypair();
        let session_key = [5u8; SESSION_KEY_LEN];
        let payload = b"body recovered despite an edit-list packet in the header".to_vec();

        // Header: a data packet plus an edit-list packet, both addressed to R.
        let data = encrypt_packet_with_type(0, &session_key, &sender_sk, &pk_r).unwrap();
        let editlist = encrypt_packet_with_type(1, &session_key, &sender_sk, &pk_r).unwrap();
        let mut body = Vec::new();
        encrypt_body(&mut &payload[..], &mut body, &session_key).unwrap();

        let mut stream = Vec::new();
        stream.extend_from_slice(b"crypt4gh");
        stream.extend_from_slice(&1u32.to_le_bytes()); // version
        stream.extend_from_slice(&2u32.to_le_bytes()); // packet_count = 2
        stream.extend_from_slice(&data);
        stream.extend_from_slice(&editlist);
        stream.extend_from_slice(&body);

        let mut out = Vec::new();
        decrypt(&mut &stream[..], &mut out, std::slice::from_ref(&sk_r)).unwrap();
        assert_eq!(
            out, payload,
            "decrypt must ignore the edit-list packet and recover the body"
        );
    }

    #[test]
    fn decrypt_rejects_a_header_packing_too_many_distinct_session_keys() {
        // A hostile header can pack many distinct session keys, all decryptable by the
        // node's recipient identity, purely to amplify `decrypt_body`'s per-segment
        // trial-decrypt cost. The winner pin there bounds only a stable winner, so an
        // alternating-winner body defeats it and forces a trial per key on every 64 KiB
        // segment. The read path must reject a header whose distinct session-key count
        // exceeds `MAX_SESSION_KEYS`; a valid stream carries one.
        use super::header::encrypt_packet_with_type;
        let (sk_r, pk_r) = generate_keypair();
        let (sender_sk, _p) = generate_keypair();
        let payload = b"amplification".to_vec();

        let n = MAX_SESSION_KEYS + 1;
        let mut stream = Vec::new();
        stream.extend_from_slice(b"crypt4gh");
        stream.extend_from_slice(&1u32.to_le_bytes()); // version
        stream.extend_from_slice(&(u32::try_from(n).unwrap()).to_le_bytes()); // packet_count
        for i in 0..n {
            // Distinct session key per packet, each wrapped to the same recipient.
            let session_key = [u8::try_from(i).unwrap(); SESSION_KEY_LEN];
            let packet = encrypt_packet_with_type(0, &session_key, &sender_sk, &pk_r).unwrap();
            stream.extend_from_slice(&packet);
        }
        // The body is encrypted with the first key, so a permissive reader would decrypt it.
        let mut body = Vec::new();
        encrypt_body(&mut &payload[..], &mut body, &[0u8; SESSION_KEY_LEN]).unwrap();
        stream.extend_from_slice(&body);

        let mut out = Vec::new();
        let res = decrypt(&mut &stream[..], &mut out, std::slice::from_ref(&sk_r));
        std::assert_matches!(
            res,
            Err(CoreError::DecryptFailed),
            "a header with more than MAX_SESSION_KEYS distinct session keys must be rejected, got {res:?}"
        );
    }

    /// The public [`header_len`] as a test helper: a complete, valid header always
    /// resolves, so the double-unwrap is sound for the well-formed streams these tests
    /// build.
    fn header_len_of(stream: &[u8]) -> usize {
        super::header_len(stream).unwrap().unwrap()
    }

    #[test]
    fn multi_recipient_each_can_decrypt() {
        let (sk_a, pk_a) = generate_keypair();
        let (sk_b, pk_b) = generate_keypair();
        let (sender_sk, _sender_pk) = generate_keypair();
        let payload = b"shared with two".to_vec();

        let mut encrypted = Vec::new();
        encrypt(&mut &payload[..], &mut encrypted, &[pk_a, pk_b], &sender_sk).unwrap();

        for sk in [sk_a, sk_b] {
            let mut out = Vec::new();
            decrypt(&mut &encrypted[..], &mut out, &[sk]).unwrap();
            assert_eq!(out, payload);
        }
    }

    use crate::crypt4gh::body::SEGMENT_SIZE;
    use proptest::prelude::*;

    /// Payload lengths biased onto the 64 KiB segment boundaries and their neighbours, plus
    /// a broad general range, materialized into a deterministic byte buffer so proptest
    /// generates and shrinks small integers rather than megabyte vectors.
    fn boundary_payload() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            Just(0usize),
            Just(1usize),
            Just(SEGMENT_SIZE - 1),
            Just(SEGMENT_SIZE),
            Just(SEGMENT_SIZE + 1),
            Just(2 * SEGMENT_SIZE - 1),
            Just(2 * SEGMENT_SIZE),
            Just(2 * SEGMENT_SIZE + 1),
            0usize..=200_000,
        ]
        .prop_map(|len| {
            (0..len)
                .map(|i| u8::try_from(i % 251).unwrap_or(0))
                .collect()
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        /// For arbitrary plaintext and a recipient set of one to four keypairs, every
        /// recipient secret key decrypts the single ciphertext back to the exact plaintext.
        /// Boundary-biased lengths lock the 64 KiB segment framing against an off-by-one,
        /// which would be data corruption on the encrypted handoff.
        #[test]
        fn roundtrip_all_recipients_recover_plaintext(
            payload in boundary_payload(),
            recipient_count in 1u32..=4,
        ) {
            let (sender_sk, _sender_pk) = generate_keypair();
            let mut recipient_sks: Vec<SecretKey> = Vec::new();
            let mut recipient_pks: Vec<PublicKey> = Vec::new();
            for _ in 0..recipient_count {
                let (sk, pk) = generate_keypair();
                recipient_sks.push(sk);
                recipient_pks.push(pk);
            }
            let mut encrypted = Vec::new();
            encrypt(&mut &payload[..], &mut encrypted, &recipient_pks, &sender_sk).unwrap();
            for sk in &recipient_sks {
                let mut decrypted = Vec::new();
                decrypt(&mut &encrypted[..], &mut decrypted, std::slice::from_ref(sk)).unwrap();
                prop_assert_eq!(&decrypted, &payload);
            }
        }

        /// Confidentiality: a key that is not among the recipients cannot decrypt the
        /// ciphertext. It cannot derive the session key, so decryption fails closed rather
        /// than yielding any plaintext.
        #[test]
        fn non_recipient_key_never_decrypts(payload in boundary_payload()) {
            let (sender_sk, _sender_pk) = generate_keypair();
            let (_recipient_sk, recipient_pk) = generate_keypair();
            let (stranger_sk, _stranger_pk) = generate_keypair();
            let mut encrypted = Vec::new();
            encrypt(&mut &payload[..], &mut encrypted, &[recipient_pk], &sender_sk).unwrap();
            let mut out = Vec::new();
            prop_assert!(decrypt(&mut &encrypted[..], &mut out, &[stranger_sk]).is_err());
        }

        /// Integrity: a tampered ciphertext must never decrypt to the wrong plaintext. The
        /// AEAD check either rejects the flipped byte, or, for a byte outside any
        /// authenticated region, still yields the exact original.
        #[test]
        fn tampered_ciphertext_is_rejected_or_still_correct(
            payload in boundary_payload(),
            flip in any::<prop::sample::Index>(),
        ) {
            let (sender_sk, _sender_pk) = generate_keypair();
            let (recipient_sk, recipient_pk) = generate_keypair();
            let mut encrypted = Vec::new();
            encrypt(&mut &payload[..], &mut encrypted, &[recipient_pk], &sender_sk).unwrap();
            prop_assume!(!encrypted.is_empty());
            let idx = flip.index(encrypted.len());
            encrypted[idx] ^= 0x01;
            let mut out = Vec::new();
            // Detected tampering gives an `Err`. If the flipped byte was outside any
            // authenticated region, decryption still succeeds and must yield the exact
            // original plaintext.
            if decrypt(&mut &encrypted[..], &mut out, &[recipient_sk]).is_ok() {
                prop_assert_eq!(out, payload);
            }
        }
    }

    /// A header packet harvested from an allow-listed provider's package and spliced into an
    /// attacker's own must not be reported as this package's writer.
    ///
    /// Crypt4GH header packets are independent, self-framed and position-independent, so
    /// anyone holding a copy of a legitimate `.tar.c4gh` can lift the provider's packet out of
    /// it verbatim. Recovering provenance by an independent pass over the header, and admitting
    /// on "any recovered fingerprint is allow-listed", would admit that splice under
    /// `writer_policy = "enforce"` and audit it as the harvested provider. Binding provenance
    /// to the packet whose session key decrypted the body makes the spliced packet inert.
    #[test]
    fn a_spliced_foreign_header_packet_is_not_reported_as_the_writer() {
        let (node_sk, node_pk) = generate_keypair();
        let (provider_sk, provider_pk) = generate_keypair(); // allow-listed writer P
        let (attacker_sk, attacker_pk) = generate_keypair(); // not allow-listed

        let pkg = |payload: &[u8], sender: &SecretKey| {
            let mut out = Vec::new();
            encrypt(
                &mut &payload[..],
                &mut out,
                std::slice::from_ref(&node_pk),
                sender,
            )
            .unwrap();
            out
        };
        let from_provider = pkg(b"legitimate payload from P", &provider_sk);
        let from_attacker = pkg(b"ATTACKER PAYLOAD", &attacker_sk);

        let hp = header_len(&from_provider).unwrap().unwrap();
        let ha = header_len(&from_attacker).unwrap().unwrap();

        // magic || version || packet_count=2 || P's harvested packet || A's packet || A's body
        let mut spliced = Vec::new();
        spliced.extend_from_slice(&from_attacker[..12]);
        spliced.extend_from_slice(&2u32.to_le_bytes());
        spliced.extend_from_slice(&from_provider[HEADER_PREFIX_LEN..hp]);
        spliced.extend_from_slice(&from_attacker[HEADER_PREFIX_LEN..ha]);
        spliced.extend_from_slice(&from_attacker[ha..]);

        // The unauthenticated helper still sees both keys, which is why it must not drive
        // admission. It remains for `inspect`, which reports rather than gates.
        let seen = recover_writer_keys(&mut &spliced[..], std::slice::from_ref(&node_sk)).unwrap();
        assert_eq!(seen.len(), 2, "both packets are openable by the node");
        assert!(
            seen.iter().any(|k| k.as_bytes() == provider_pk.as_bytes()),
            "the harvested packet is present in the header"
        );

        // The authenticated answer names the writer of the packet that opened the body.
        let mut plain = Vec::new();
        let writer = decrypt_authenticated(
            &mut &spliced[..],
            &mut plain,
            std::slice::from_ref(&node_sk),
        )
        .unwrap()
        .expect("a non-empty body has an authenticating packet");
        assert_eq!(plain, b"ATTACKER PAYLOAD", "the body is the attacker's");
        assert_eq!(
            writer.as_bytes(),
            attacker_pk.as_bytes(),
            "provenance must name the writer whose key decrypted the body"
        );
        assert_ne!(
            writer.as_bytes(),
            provider_pk.as_bytes(),
            "the spliced provider packet must NOT be reported as this package's writer"
        );

        // Unspliced packages still resolve to their real writer.
        let mut out = Vec::new();
        let honest = decrypt_authenticated(
            &mut &from_provider[..],
            &mut out,
            std::slice::from_ref(&node_sk),
        )
        .unwrap()
        .unwrap();
        assert_eq!(honest.as_bytes(), provider_pk.as_bytes());
        drop(attacker_sk);
    }
}
