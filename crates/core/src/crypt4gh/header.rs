//! Crypt4GH header packet codec (`X25519_chacha20_ietf_poly1305`).
//!
//! On-disk a header packet is:
//!
//! ```text
//! u32-le packet_length (includes these 4 bytes)
//! u32-le encryption_method      (0 = X25519_chacha20_ietf_poly1305)
//! [32]   writer/sender X25519 public key
//! [12]   nonce
//! [..]   ChaCha20-Poly1305 ciphertext+tag
//! ```
//!
//! The decrypted packet content is:
//!
//! ```text
//! u32-le packet_type            (0 = data encryption parameters)
//! u32-le data_encryption_method (0 = chacha20_ietf_poly1305)
//! [32]   session (data) key
//! ```
//!
//! Shared-key derivation, as libsodium's `crypto_kx` fixes it:
//!
//! ```text
//! q          = X25519(sender_sk, recipient_pk)              // the DH point
//! shared_key = Blake2b-512(q || recipient_pk || sender_pk)[0..32]
//! ```
//!
//! The recipient is the libsodium "client" and the sender is the "server". The same formula
//! yields the identical key on both ends, because the DH point is symmetric. Encryption uses
//! `shared_key`, and decryption re-derives it from the recipient secret key and the writer
//! public key carried in the packet.
#![expect(
    clippy::doc_markdown,
    reason = "docs use proper nouns (Crypt4GH, ChaCha20-Poly1305, Blake2b-512, X25519) as prose, not code"
)]
#![expect(
    clippy::similar_names,
    reason = "sender/recipient sk/pk are the standard, clearest crypto naming"
)]

use blake2::digest::consts::U64;
use blake2::{Blake2b, Digest};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_core::{OsRng, RngCore};
use x25519_dalek::x25519;
use zeroize::{Zeroize, Zeroizing};

use super::keys::{PublicKey, SecretKey};
use crate::error::{CoreError, CoreResult};

/// `X25519_chacha20_ietf_poly1305`.
pub(crate) const HEADER_ENCRYPTION_METHOD: u32 = 0;
/// Packet type: data encryption parameters.
pub(crate) const PACKET_TYPE_DATA_ENC: u32 = 0;
/// Bulk (body) data encryption method: chacha20_ietf_poly1305.
pub(crate) const DATA_ENCRYPTION_METHOD: u32 = 0;

const NONCE_LEN: usize = 12;
/// Length of the ChaCha20-Poly1305 session/data (bulk body) key carried in a header packet.
pub(crate) const SESSION_KEY_LEN: usize = 32;

type Blake2b512 = Blake2b<U64>;

/// Derive the Crypt4GH header shared key.
///
/// The construction is fixed by libsodium's `crypto_kx`:
///
/// ```text
/// q          = X25519(local_sk, peer_pk)
/// shared_key = Blake2b-512(q || recipient_pk || sender_pk)[0..32]
/// ```
///
/// `sender` is always the message writer and `recipient` always the message recipient. The
/// DH point is symmetric, so both ends compute the same key. The writer calls this with
/// `local_sk = sender_sk` and `peer_pk = recipient_pk`; the reader calls it with
/// `local_sk = recipient_sk` and `peer_pk = sender_pk`. Only the DH inputs differ, and the
/// hash ordering of `recipient_pk` then `sender_pk` is identical on both ends.
fn derive_shared_key(
    local_sk: &SecretKey,
    peer_pk: &PublicKey,
    sender_pk: &PublicKey,
    recipient_pk: &PublicKey,
) -> Option<Zeroizing<[u8; 32]>> {
    // `StaticSecret` stores the clamped scalar. Expose its raw bytes to compute the bare DH
    // point, matching libsodium's `crypto_scalarmult`.
    let scalar = Zeroizing::new(local_sk.0.to_bytes());
    let shared_point = Zeroizing::new(x25519(*scalar, *peer_pk.as_bytes()));

    // Reject a low-order peer public key, catching the whole low-order subgroup at once.
    // Such a key forces the X25519 shared point to all-zero whatever the local secret, so
    // the derived key would be a fixed, attacker-known value. The all-zero outcome depends
    // only on the public peer key, so this comparison leaks nothing about `local_sk` and
    // needs no constant-time treatment. `None` lets the encrypt path refuse a degenerate
    // recipient and the decrypt path treat a degenerate header sender key as a failure.
    if shared_point.iter().all(|&b| b == 0) {
        return None;
    }

    let mut hasher = Blake2b512::new();
    hasher.update(shared_point.as_ref());
    hasher.update(recipient_pk.as_bytes());
    hasher.update(sender_pk.as_bytes());
    let mut digest = hasher.finalize();

    // Build the shared key inside its `Zeroizing` wrapper: `[u8; 32]` is `Copy`, so
    // wrapping a plain local would leave an un-scrubbed copy in this stack frame. Then
    // scrub the full 64-byte digest, whose unused second half is also secret.
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&digest[..32]);
    digest.zeroize();
    Some(key)
}

/// Encrypt a session key into a single on-disk header packet (with the leading
/// u32-le length prefix), addressed to `recipient_pk` from `sender_sk`.
///
/// # Errors
/// Returns [`CoreError::InternalError`] if the recipient public key is low-order, giving a
/// degenerate all-zero shared secret that would expose the session key, or if the AEAD
/// encryption fails, which cannot happen for valid keys.
pub(crate) fn encrypt_packet(
    session_key: &[u8; SESSION_KEY_LEN],
    sender_sk: &SecretKey,
    recipient_pk: &PublicKey,
) -> CoreResult<Vec<u8>> {
    encrypt_packet_of_type(PACKET_TYPE_DATA_ENC, session_key, sender_sk, recipient_pk)
}

/// Build one on-disk header packet whose decrypted content advertises `packet_type`.
///
/// Production emits only [`PACKET_TYPE_DATA_ENC`], through [`encrypt_packet`]. The parameter
/// exists so a test can synthesize a non-data packet, such as an edit list, through the same
/// framing the reader parses rather than duplicating the wire assembly.
///
/// # Errors
/// Returns [`CoreError::InternalError`] if the recipient public key is low-order, giving a
/// degenerate all-zero shared secret, or if the AEAD encryption fails, which cannot happen
/// for valid keys.
fn encrypt_packet_of_type(
    packet_type: u32,
    session_key: &[u8; SESSION_KEY_LEN],
    sender_sk: &SecretKey,
    recipient_pk: &PublicKey,
) -> CoreResult<Vec<u8>> {
    let sender_pk = sender_sk.public_key();
    // Writer side: local_sk = sender_sk, peer_pk = recipient_pk.
    let shared =
        derive_shared_key(sender_sk, recipient_pk, &sender_pk, recipient_pk).ok_or_else(|| {
            CoreError::InternalError {
                detail: "recipient X25519 public key is low-order (degenerate shared secret); \
                     refusing to encrypt to it"
                    .to_owned(),
            }
        })?;

    // Decrypted packet content: type || data_enc_method(0) || session_key.
    let mut content = Zeroizing::new(Vec::with_capacity(8 + SESSION_KEY_LEN));
    content.extend_from_slice(&packet_type.to_le_bytes());
    content.extend_from_slice(&DATA_ENCRYPTION_METHOD.to_le_bytes());
    content.extend_from_slice(session_key);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(shared.as_ref()));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: content.as_ref(),
                aad: &[],
            },
        )
        .map_err(|_| CoreError::InternalError {
            detail: "header packet encryption failed".to_string(),
        })?;

    // packet body = method || writer_pk || nonce || ciphertext+tag
    let body_len = 4 + 32 + NONCE_LEN + ciphertext.len();
    let mut packet = Vec::with_capacity(4 + body_len);
    let total_len = u32::try_from(4 + body_len).map_err(|_| CoreError::InternalError {
        detail: "header packet too large".to_string(),
    })?;
    packet.extend_from_slice(&total_len.to_le_bytes());
    packet.extend_from_slice(&HEADER_ENCRYPTION_METHOD.to_le_bytes());
    packet.extend_from_slice(sender_pk.as_bytes());
    packet.extend_from_slice(&nonce_bytes);
    packet.extend_from_slice(&ciphertext);
    Ok(packet)
}

/// Test-only: synthesize a header packet advertising an arbitrary `packet_type`, such as `1`
/// for an edit list, so tests can exercise the decrypted-but-unsupported path.
///
/// # Errors
/// Same as [`encrypt_packet`].
#[cfg(test)]
pub(crate) fn encrypt_packet_with_type(
    packet_type: u32,
    session_key: &[u8; SESSION_KEY_LEN],
    sender_sk: &SecretKey,
    recipient_pk: &PublicKey,
) -> CoreResult<Vec<u8>> {
    encrypt_packet_of_type(packet_type, session_key, sender_sk, recipient_pk)
}

/// Outcome of attempting to decrypt one header packet with one identity.
pub(crate) enum PacketDecrypt {
    /// Decrypted session key, plus the writer public key carried in the packet and bound
    /// into the key derivation. This is the one provenance signal a package holds.
    Session {
        key: Zeroizing<[u8; SESSION_KEY_LEN]>,
        writer_pk: PublicKey,
    },
    /// This identity is not the recipient, so the AEAD tag mismatched. Try another.
    WrongIdentity,
    /// The packet uses an unsupported encryption method, `method != 0`, so it was never
    /// decrypted. Ignore it.
    Unsupported,
    /// The packet decrypted for this identity, but its content is not a
    /// data-encryption-parameters packet: an edit list, for instance. A reader may ignore
    /// it, but a faithful re-encoder ([`super::rewrap_header`]) must reject it rather than
    /// drop it silently.
    DecryptedUnsupported,
}

/// Try to decrypt a header packet's content with one recipient key. The content is the
/// bytes after the u32-le length prefix: `method || writer_pk || nonce || ct`.
///
/// Distinguishes a wrong-identity AEAD failure, [`PacketDecrypt::WrongIdentity`], from a
/// structurally corrupt packet, which is an `Err`.
///
/// # Errors
/// Returns [`CoreError::DecryptFailed`] if the packet is too short to contain
/// the method, writer key, nonce, and tag.
pub(crate) fn decrypt_packet(
    packet_content: &[u8],
    recipient_sk: &SecretKey,
) -> CoreResult<PacketDecrypt> {
    // method(4) || writer_pk(32) || nonce(12) || ct (>=16 for the tag)
    const MIN: usize = 4 + 32 + NONCE_LEN + 16;
    if packet_content.len() < MIN {
        return Err(CoreError::DecryptFailed);
    }
    let method = u32::from_le_bytes([
        packet_content[0],
        packet_content[1],
        packet_content[2],
        packet_content[3],
    ]);
    if method != HEADER_ENCRYPTION_METHOD {
        return Ok(PacketDecrypt::Unsupported);
    }
    let writer_pk_bytes: [u8; 32] = packet_content[4..36]
        .try_into()
        .map_err(|_| CoreError::DecryptFailed)?;
    let writer_pk = PublicKey::from_bytes(writer_pk_bytes);
    let nonce = &packet_content[36..36 + NONCE_LEN];
    let ciphertext = &packet_content[36 + NONCE_LEN..];

    // Reader side: local_sk = recipient_sk, peer_pk = writer_pk (the sender).
    // The hash ordering stays q || recipient_pk || sender_pk, where the sender
    // is the writer carried in the packet.
    let recipient_pk = recipient_sk.public_key();
    // A low-order writer key in the header gives a degenerate shared secret, so treat the
    // packet as undecryptable rather than deriving a fixed, attacker-known key.
    let shared = derive_shared_key(recipient_sk, &writer_pk, &writer_pk, &recipient_pk)
        .ok_or(CoreError::DecryptFailed)?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(shared.as_ref()));
    let plaintext = match cipher.decrypt(
        Nonce::from_slice(nonce),
        Payload {
            msg: ciphertext,
            aad: &[],
        },
    ) {
        Ok(p) => Zeroizing::new(p),
        Err(_) => return Ok(PacketDecrypt::WrongIdentity),
    };

    parse_packet_content(&plaintext[..], writer_pk)
}

fn parse_packet_content(plaintext: &[u8], writer_pk: PublicKey) -> CoreResult<PacketDecrypt> {
    if plaintext.len() < 8 + SESSION_KEY_LEN {
        return Err(CoreError::DecryptFailed);
    }
    let packet_type = u32::from_le_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]);
    if packet_type != PACKET_TYPE_DATA_ENC {
        // An edit list or other type: decrypted, but not a session-key packet.
        return Ok(PacketDecrypt::DecryptedUnsupported);
    }
    let data_method = u32::from_le_bytes([plaintext[4], plaintext[5], plaintext[6], plaintext[7]]);
    if data_method != DATA_ENCRYPTION_METHOD {
        return Ok(PacketDecrypt::DecryptedUnsupported);
    }
    // Build the recovered key inside its `Zeroizing` wrapper, so no untracked copy of the
    // bulk session key lingers in this stack frame after return.
    let mut key = Zeroizing::new([0u8; SESSION_KEY_LEN]);
    key.copy_from_slice(&plaintext[8..8 + SESSION_KEY_LEN]);
    Ok(PacketDecrypt::Session { key, writer_pk })
}

/// Derive the shared key the way the writer would, with the recipient as the peer.
///
/// Exposed for the derivation parity test, so it can assert that encryption and decryption
/// agree on the same construction.
#[cfg(test)]
pub(crate) fn shared_key_for_test(
    sender_sk: &SecretKey,
    recipient_pk: &PublicKey,
) -> Option<[u8; 32]> {
    let sender_pk = sender_sk.public_key();
    derive_shared_key(sender_sk, recipient_pk, &sender_pk, recipient_pk).map(|k| *k)
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::super::keys::generate_keypair;
    use super::*;

    #[test]
    fn shared_key_agrees_between_writer_and_reader() {
        let (sender_sk, sender_pk) = generate_keypair();
        let (recip_sk, recip_pk) = generate_keypair();

        // Writer side: sender encrypts to recipient.
        let writer = shared_key_for_test(&sender_sk, &recip_pk).unwrap();
        // Reader side: the recipient decrypts, deriving its local secret against the
        // writer public key, ordered q || recipient_pk || sender_pk.
        let reader = *derive_shared_key(&recip_sk, &sender_pk, &sender_pk, &recip_pk).unwrap();
        assert_eq!(writer, reader);
    }

    #[test]
    fn low_order_recipient_key_is_rejected() {
        // An all-zero public key is the canonical low-order point, since x25519(_, 0) == 0
        // makes the derived shared secret all-zero whatever the local secret. The derivation
        // must return `None`, so encrypting to it errors rather than producing a fixed,
        // attacker-known key.
        let (sender_sk, _sender_pk) = generate_keypair();
        let zero_pk = PublicKey::from_bytes([0u8; 32]);
        assert!(
            shared_key_for_test(&sender_sk, &zero_pk).is_none(),
            "an all-zero (low-order) recipient key must be rejected"
        );
        let session_key = [7u8; SESSION_KEY_LEN];
        std::assert_matches!(
            encrypt_packet(&session_key, &sender_sk, &zero_pk),
            Err(CoreError::InternalError { .. }),
            "encrypting to a low-order recipient must error"
        );
    }

    #[test]
    fn packet_round_trips() {
        let (sender_sk, sender_pk) = generate_keypair();
        let (recip_sk, recip_pk) = generate_keypair();
        let session_key = [7u8; SESSION_KEY_LEN];
        let packet = encrypt_packet(&session_key, &sender_sk, &recip_pk).unwrap();
        // Strip the u32 length prefix.
        let content = &packet[4..];
        match decrypt_packet(content, &recip_sk).unwrap() {
            PacketDecrypt::Session { key, writer_pk } => {
                assert_eq!(*key, session_key);
                // The recovered writer key is the sender's public key (provenance).
                assert_eq!(writer_pk.as_bytes(), sender_pk.as_bytes());
            }
            _ => panic!("expected session key"),
        }
    }

    #[test]
    fn wrong_identity_is_distinguished() {
        let (sender_sk, _sender_pk) = generate_keypair();
        let (_recip_sk, recip_pk) = generate_keypair();
        let (other_sk, _other_pk) = generate_keypair();
        let session_key = [1u8; SESSION_KEY_LEN];
        let packet = encrypt_packet(&session_key, &sender_sk, &recip_pk).unwrap();
        match decrypt_packet(&packet[4..], &other_sk).unwrap() {
            PacketDecrypt::WrongIdentity => {}
            _ => panic!("expected wrong identity"),
        }
    }

    #[test]
    fn short_packet_errors() {
        let (sk, _pk) = generate_keypair();
        assert!(matches!(
            decrypt_packet(b"too short", &sk),
            Err(CoreError::DecryptFailed)
        ));
    }

    #[test]
    fn low_order_writer_key_in_header_is_rejected_on_decrypt() {
        // The decrypt-side twin of `low_order_recipient_key_is_rejected`. A header packet
        // advertising an all-zero writer key forces the reader's derived shared secret to
        // all-zero, so `decrypt_packet` must fail before the AEAD step rather than deriving
        // a fixed, attacker-known key and trial-decrypting under it.
        let (recip_sk, _recip_pk) = generate_keypair();
        // content = method(0) || writer_pk(all-zero) || nonce || minimal ciphertext.
        let mut content = Vec::new();
        content.extend_from_slice(&HEADER_ENCRYPTION_METHOD.to_le_bytes());
        content.extend_from_slice(&[0u8; 32]); // low-order writer_pk
        content.extend_from_slice(&[0u8; NONCE_LEN]);
        content.extend_from_slice(&[0u8; 16]); // tag-length ciphertext; never reached
        assert!(
            matches!(
                decrypt_packet(&content, &recip_sk),
                Err(CoreError::DecryptFailed)
            ),
            "a low-order writer key in a header packet must be rejected on decrypt"
        );
    }

    #[test]
    fn decrypted_non_data_packet_is_decrypted_unsupported() {
        // A packet that decrypts for the recipient but carries a non-data packet type, such
        // as an edit list, is `DecryptedUnsupported`. That is distinct from `WrongIdentity`,
        // an AEAD failure, and from `Unsupported`, a foreign encryption method.
        let (sender_sk, _sp) = generate_keypair();
        let (recip_sk, recip_pk) = generate_keypair();
        let session_key = [9u8; SESSION_KEY_LEN];
        let packet = encrypt_packet_with_type(1, &session_key, &sender_sk, &recip_pk).unwrap();
        match decrypt_packet(&packet[4..], &recip_sk).unwrap() {
            PacketDecrypt::DecryptedUnsupported => {}
            _ => panic!("expected DecryptedUnsupported for an edit-list packet"),
        }
    }

    /// Frame a header packet carrying arbitrary decrypted `content`, rather than the fixed
    /// `type || method || session_key` layout, reusing the writer-side AEAD framing
    /// `encrypt_packet_of_type` uses. Lets a test produce a packet that AEAD-decrypts
    /// cleanly for the recipient but whose plaintext has a non-standard length.
    fn frame_raw_content(
        content: &[u8],
        sender_sk: &SecretKey,
        recipient_pk: &PublicKey,
    ) -> Vec<u8> {
        let sender_pk = sender_sk.public_key();
        let shared = derive_shared_key(sender_sk, recipient_pk, &sender_pk, recipient_pk).unwrap();
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(shared.as_ref()));
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: content,
                    aad: &[],
                },
            )
            .unwrap();
        let body_len = 4 + 32 + NONCE_LEN + ciphertext.len();
        let mut packet = Vec::with_capacity(4 + body_len);
        packet.extend_from_slice(&u32::try_from(4 + body_len).unwrap().to_le_bytes());
        packet.extend_from_slice(&HEADER_ENCRYPTION_METHOD.to_le_bytes());
        packet.extend_from_slice(sender_pk.as_bytes());
        packet.extend_from_slice(&nonce_bytes);
        packet.extend_from_slice(&ciphertext);
        packet
    }

    #[test]
    fn header_packet_below_min_length_is_rejected_not_panic() {
        // The length guard rejects any packet shorter than method + writer_pk + nonce + tag,
        // which is 64 bytes, before any fixed-offset slice runs. Weaken that minimum and a
        // mid-length packet slips through, so the slices panic out of bounds on the
        // attacker-controlled ingest path. Every boundary must give a clean error.
        let (sk, _pk) = generate_keypair();
        for len in [0usize, 9, 16, 31, 32, 33, 36, 40, 44, 47, 48, 63] {
            let content = vec![0u8; len];
            assert!(
                matches!(decrypt_packet(&content, &sk), Err(CoreError::DecryptFailed)),
                "packet content of length {len} (< MIN=64) must be DecryptFailed, not a panic"
            );
        }
    }

    #[test]
    fn header_packet_with_short_plaintext_is_rejected_not_panic() {
        // A packet that AEAD-decrypts but whose plaintext is shorter than
        // 8 + SESSION_KEY_LEN must be rejected, never indexed at `plaintext[8..40]`, which
        // would panic out of bounds. An author holding the recipient's public key can craft
        // one.
        let (sender_sk, _sp) = generate_keypair();
        let (recip_sk, recip_pk) = generate_keypair();
        // 39-byte plaintext: one short of the minimum session-key packet content.
        let packet = frame_raw_content(&[0u8; 39], &sender_sk, &recip_pk);
        assert!(
            matches!(
                decrypt_packet(&packet[4..], &recip_sk),
                Err(CoreError::DecryptFailed)
            ),
            "a packet decrypting to a <40-byte plaintext must be DecryptFailed, not a panic"
        );
    }
}
