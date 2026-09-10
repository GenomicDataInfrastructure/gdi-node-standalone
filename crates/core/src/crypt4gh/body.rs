//! Crypt4GH body codec: 64 KiB ChaCha20-Poly1305 segments, streamed.
//!
//! The body is a sequence of independently-decryptable cipher segments. Each
//! plaintext segment of up to [`SEGMENT_SIZE`] bytes becomes
//! `nonce(12) || ChaCha20-Poly1305(plaintext, nonce, session_key)` on disk, so
//! the cipher segment is at most [`CIPHER_SEGMENT_SIZE`] bytes. A fresh random
//! nonce is drawn per segment. Encryption and decryption both stream one
//! segment at a time, holding only a single segment in memory.
//!
//! Nonces are fresh 96-bit random values per segment, as in the reference implementation,
//! so uniqueness under one session key is probabilistic rather than counter-guaranteed. The
//! collision probability stays below 2^-32 until roughly 2^32 segments, about 256 TiB, under
//! a single key. No per-key segment cap is imposed, and a per-call session key keeps each
//! key's segment count low.
#![expect(
    clippy::doc_markdown,
    reason = "the docs use Crypt4GH and ChaCha20-Poly1305 as prose, not as code"
)]

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use rand_core::{OsRng, RngCore};
use std::io::{Read, Write};

use super::header::SESSION_KEY_LEN;
use crate::error::{CoreError, CoreResult};
use zeroize::Zeroizing;

/// Plaintext segment size (64 KiB), fixed by the Crypt4GH version-1 format.
pub const SEGMENT_SIZE: usize = 65_536;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// `nonce + plaintext + tag` for a full segment.
pub const CIPHER_SEGMENT_SIZE: usize = SEGMENT_SIZE + NONCE_LEN + TAG_LEN;

/// Encrypt the whole of `reader` into `writer` as 64 KiB cipher segments under
/// `session_key`, in constant memory.
///
/// # Errors
/// Returns [`CoreError::Io`] on a read/write failure, or
/// [`CoreError::InternalError`] if the AEAD encryption fails.
pub(crate) fn encrypt_body<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    session_key: &[u8; SESSION_KEY_LEN],
) -> CoreResult<()> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(session_key));
    // `Zeroizing`, as for every other segment buffer in this codec. The success path
    // overwrites this in place with ciphertext, so the exposure is the error path: a read or
    // write failure mid-stream would otherwise drop a buffer holding 64 KiB of plaintext
    // un-scrubbed.
    let mut plaintext = Zeroizing::new(vec![0u8; SEGMENT_SIZE]);

    loop {
        let n = read_full(reader, &mut plaintext)?;
        if n == 0 {
            break;
        }

        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        // Encrypt in place: `plaintext[..n]` becomes the ciphertext and the 16-byte tag
        // comes back detached, so no segment allocates. The wire layout is
        // `nonce || ciphertext || tag`.
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce_bytes), &[], &mut plaintext[..n])
            .map_err(|_| CoreError::InternalError {
                detail: "body segment encryption failed".to_string(),
            })?;

        writer.write_all(&nonce_bytes)?;
        writer.write_all(&plaintext[..n])?;
        writer.write_all(tag.as_slice())?;

        if n < SEGMENT_SIZE {
            break;
        }
    }
    Ok(())
}

/// Decrypt the body in `reader` into `writer`, trying each session key per
/// segment, in constant memory.
///
/// Returns the index into `session_keys` of the key that decrypted the body, or `None` for a
/// body with no segments. The caller needs this to name the header packet that authenticated
/// the body. A Crypt4GH header is a list of independent, position-independent packets, so
/// "some packet in this header was written by X" is a weaker claim than "X wrote this body",
/// and only the latter may be gated on.
///
/// # Errors
/// Returns [`CoreError::Io`] on a read/write failure, or
/// [`CoreError::DecryptFailed`] if a segment is malformed or no session key
/// decrypts it.
pub(crate) fn decrypt_body<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    session_keys: &[[u8; SESSION_KEY_LEN]],
) -> CoreResult<Option<usize>> {
    let ciphers: Vec<ChaCha20Poly1305> = session_keys
        .iter()
        .map(|k| ChaCha20Poly1305::new(Key::from_slice(k)))
        .collect();

    // Reusable scratch for the multi-key retry path. An in-place trial decrypt XORs the
    // keystream into the buffer before the tag is checked, so a wrong-key attempt scrambles
    // it; with more than one candidate key the trial therefore runs against this copy and a
    // failure never consumes the original ciphertext. Allocated once, and empty in the
    // single-key case, which decrypts in place.
    //
    // `Zeroizing` because both buffers hold plaintext after decryption, which on the
    // identity-restore path is the node's own secret key material. A plain `Vec` would leave
    // it in freed heap for a core dump, swap or a later allocation to pick up.
    let mut scratch: Zeroizing<Vec<u8>> = Zeroizing::new(if ciphers.len() > 1 {
        vec![0u8; SEGMENT_SIZE]
    } else {
        Vec::new()
    });

    // The index of the candidate cipher that decrypted the previous segment. A valid
    // Crypt4GH stream wraps one session key in every header packet, so the same cipher
    // decrypts every segment, and trying it first bounds the multi-key work to
    // `N + segments` rather than `N × segments`. Without it a hostile package can carry
    // `MAX_HEADER_PACKETS` distinct-key packets with the real key last, forcing a tag
    // failure per packet per 64 KiB segment across the whole body.
    let mut pinned_idx: Option<usize> = None;

    let mut cipher_segment = Zeroizing::new(vec![0u8; CIPHER_SEGMENT_SIZE]);
    loop {
        let n = read_full(reader, &mut cipher_segment)?;
        if n == 0 {
            break;
        }
        // Smallest valid segment is nonce + tag (an empty plaintext).
        if n < NONCE_LEN + TAG_LEN {
            return Err(CoreError::DecryptFailed);
        }
        // Copy the small fixed-size nonce and tag out so the ciphertext region in
        // `cipher_segment` can be borrowed mutably for in-place decryption.
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes.copy_from_slice(&cipher_segment[..NONCE_LEN]);
        let mut tag_bytes = [0u8; TAG_LEN];
        tag_bytes.copy_from_slice(&cipher_segment[n - TAG_LEN..n]);
        let plaintext_len = n - NONCE_LEN - TAG_LEN;

        let decrypted = match ciphers.as_slice() {
            // Single key, the common case: decrypt straight into the segment buffer.
            [cipher] => {
                let ok = cipher
                    .decrypt_in_place_detached(
                        Nonce::from_slice(&nonce_bytes),
                        &[],
                        &mut cipher_segment[NONCE_LEN..n - TAG_LEN],
                        Tag::from_slice(&tag_bytes),
                    )
                    .is_ok();
                if ok {
                    // Record the winner here too: the caller reads `pinned_idx` to identify
                    // the header packet that authenticated the body.
                    pinned_idx = Some(0);
                }
                ok
            }
            // Multiple candidate keys: try each against a scratch copy, so a wrong key's
            // scrambling does not destroy the ciphertext for the next try. The cipher that
            // decrypted the previous segment is tried first, so a legitimate single-key
            // stream costs one trial per segment after the first and a hostile many-key
            // package cannot amplify per-segment work by placing the real key last.
            candidates => {
                let prev = pinned_idx;
                let order = prev
                    .into_iter()
                    .chain((0..candidates.len()).filter(move |i| Some(*i) != prev));
                let mut ok = false;
                for i in order {
                    scratch[..plaintext_len]
                        .copy_from_slice(&cipher_segment[NONCE_LEN..n - TAG_LEN]);
                    if candidates[i]
                        .decrypt_in_place_detached(
                            Nonce::from_slice(&nonce_bytes),
                            &[],
                            &mut scratch[..plaintext_len],
                            Tag::from_slice(&tag_bytes),
                        )
                        .is_ok()
                    {
                        cipher_segment[NONCE_LEN..n - TAG_LEN]
                            .copy_from_slice(&scratch[..plaintext_len]);
                        // Latch the winner rather than overwriting it. The caller reads
                        // `pinned_idx` as the body's provenance, the header packet whose key
                        // authenticated it, so reassigning per segment would name whichever
                        // key won the last one.
                        //
                        // That is forgeable: take a legitimate package from an allow-listed
                        // provider, build a header carrying your own packet plus theirs
                        // lifted verbatim, encrypt your own tar under your own key padded to
                        // whole segments, then append one body segment copied from their
                        // package. The last segment would win, the decode would report their
                        // public key, and the writer gate would admit you under
                        // `writer_policy = enforce`. The trailing segment lands after your
                        // tar's end-of-archive marker, which the extractor never reads.
                        //
                        // A valid stream wraps one session key and uses it for every segment,
                        // and a multi-packet header wraps that same key for several
                        // recipients, so disagreement is not a shape an honest producer
                        // emits. The runtime check below makes "one key authenticated the
                        // whole body" an invariant this decoder enforces per segment. It is
                        // not a type-level guarantee: nothing stops a future caller reading
                        // `pinned_idx` before the loop ends.
                        if pinned_idx.is_some_and(|prev| prev != i) {
                            return Err(CoreError::DecryptFailed);
                        }
                        pinned_idx = Some(i);
                        ok = true;
                        break;
                    }
                }
                ok
            }
        };
        if !decrypted {
            return Err(CoreError::DecryptFailed);
        }
        writer.write_all(&cipher_segment[NONCE_LEN..n - TAG_LEN])?;

        // A short read means EOF after this final segment.
        if n < CIPHER_SEGMENT_SIZE {
            break;
        }
    }
    Ok(pinned_idx)
}

/// Read until `buf` is full or EOF; returns the number of bytes read.
///
/// Tolerates short reads from the underlying reader, such as a pipe, so a non-file `Read`
/// still yields full 64 KiB segments.
fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> CoreResult<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(CoreError::Io(e)),
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;

    #[test]
    fn body_round_trips_multi_segment() {
        let session_key = [3u8; SESSION_KEY_LEN];
        // Over 64 KiB, to exercise multiple segments plus a partial tail.
        let plaintext: Vec<u8> = (0..(SEGMENT_SIZE * 2 + 1234))
            .map(|i| u8::try_from(i % 251).unwrap_or(0))
            .collect();

        let mut encrypted = Vec::new();
        encrypt_body(&mut &plaintext[..], &mut encrypted, &session_key).unwrap();

        let mut decrypted = Vec::new();
        decrypt_body(&mut &encrypted[..], &mut decrypted, &[session_key]).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn empty_body_round_trips() {
        let session_key = [9u8; SESSION_KEY_LEN];
        let mut encrypted = Vec::new();
        encrypt_body(&mut &b""[..], &mut encrypted, &session_key).unwrap();
        // Empty plaintext means no segments are written.
        assert!(encrypted.is_empty());
        let mut decrypted = Vec::new();
        decrypt_body(&mut &encrypted[..], &mut decrypted, &[session_key]).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn exact_segment_boundary_round_trips() {
        let session_key = [5u8; SESSION_KEY_LEN];
        let plaintext = vec![0xABu8; SEGMENT_SIZE];
        let mut encrypted = Vec::new();
        encrypt_body(&mut &plaintext[..], &mut encrypted, &session_key).unwrap();
        let mut decrypted = Vec::new();
        decrypt_body(&mut &encrypted[..], &mut decrypted, &[session_key]).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_session_key_fails() {
        let session_key = [1u8; SESSION_KEY_LEN];
        let plaintext = b"some data";
        let mut encrypted = Vec::new();
        encrypt_body(&mut &plaintext[..], &mut encrypted, &session_key).unwrap();
        let mut out = Vec::new();
        let wrong = [2u8; SESSION_KEY_LEN];
        std::assert_matches!(
            decrypt_body(&mut &encrypted[..], &mut out, &[wrong]),
            Err(CoreError::DecryptFailed)
        );
    }

    #[test]
    fn a_body_whose_segments_disagree_on_the_key_is_rejected() {
        // `pinned_idx` is the caller's provenance signal. Overwriting it per segment would
        // let a body of your own segments, with one segment lifted from an allow-listed
        // provider's package, report that provider as the writer, which
        // `writer_policy = enforce` would then admit.
        //
        // The first body is an exact multiple of SEGMENT_SIZE so it emits only full cipher
        // segments. A short segment would signal EOF and the appended one would never be
        // read, which is why the attack pads.
        let mine = [7u8; SESSION_KEY_LEN];
        let theirs = [9u8; SESSION_KEY_LEN];

        let mut spliced = Vec::new();
        encrypt_body(&mut &vec![1u8; SEGMENT_SIZE][..], &mut spliced, &mine).unwrap();
        encrypt_body(&mut &vec![2u8; 64][..], &mut spliced, &theirs).unwrap();

        // A wrong key, a truncated stream and a corrupt tag all produce `DecryptFailed`
        // too, so the assertion below cannot by itself tell "rejected for disagreeing" from
        // "this fixture never decrypted at all". Decrypting each half under its own key
        // first must succeed, which leaves disagreement as the only thing for the combined
        // stream to fail on.
        let mut half = Vec::new();
        let mut first = Vec::new();
        encrypt_body(&mut &vec![1u8; SEGMENT_SIZE][..], &mut first, &mine).unwrap();
        assert_eq!(
            decrypt_body(&mut &first[..], &mut half, &[mine]).unwrap(),
            Some(0),
            "the spliced fixture's first segment must be valid under `mine` on its own"
        );
        let mut half2 = Vec::new();
        let mut second = Vec::new();
        encrypt_body(&mut &vec![2u8; 64][..], &mut second, &theirs).unwrap();
        assert_eq!(
            decrypt_body(&mut &second[..], &mut half2, &[theirs]).unwrap(),
            Some(0),
            "the spliced fixture's appended segment must be valid under `theirs` on its own"
        );

        let mut out = Vec::new();
        let err = decrypt_body(&mut &spliced[..], &mut out, &[mine, theirs]).unwrap_err();
        std::assert_matches!(
            err,
            CoreError::DecryptFailed,
            "a body whose segments authenticate under DIFFERENT keys must be rejected, not \
             attributed to whichever key happened to win the last segment; got {err:?}"
        );

        // The writer is dirty on rejection, and callers must honour that. This decryptor
        // streams, so by the time the second segment is found to disagree the first has
        // already been written out and `out` holds a full SEGMENT_SIZE of the attacker's
        // plaintext beside an `Err`. Pinned here because the signature does not show it.
        //
        // No caller consumes the writer on `Err`: `ingest.rs` takes `decrypt_result?` before
        // the extract step, so the partial `package.tar` is never read and `WorkDirGuard`
        // removes it; `pkgio.rs` renders an error and never reads the pipe;
        // `identity_backup.rs` drops its `Zeroizing` buffer.
        assert_eq!(
            out.len(),
            SEGMENT_SIZE,
            "the rejected splice must have left exactly the first segment's plaintext in \
             the writer; if this changed, re-check that no caller reads the writer on Err"
        );

        // Control: the same two keys on a body encrypted wholly under one of them still
        // decrypt, so the latch rejects disagreement rather than multi-key candidates.
        let mut clean = Vec::new();
        encrypt_body(&mut &vec![3u8; SEGMENT_SIZE + 5][..], &mut clean, &theirs).unwrap();
        let mut ok_out = Vec::new();
        let winner = decrypt_body(&mut &clean[..], &mut ok_out, &[mine, theirs]).unwrap();
        assert_eq!(
            winner,
            Some(1),
            "the single authenticating key must be reported"
        );
    }

    #[test]
    fn multi_key_decrypts_when_correct_key_is_not_first() {
        // Exercises the scratch-copy retry path: the first candidate key fails, scrambling
        // its scratch copy in place, and the second, correct key must still recover the
        // original ciphertext across multiple segments.
        let right = [7u8; SESSION_KEY_LEN];
        let wrong = [8u8; SESSION_KEY_LEN];
        let plaintext: Vec<u8> = (0..(SEGMENT_SIZE + 777))
            .map(|i| u8::try_from(i % 251).unwrap_or(0))
            .collect();

        let mut encrypted = Vec::new();
        encrypt_body(&mut &plaintext[..], &mut encrypted, &right).unwrap();

        let mut decrypted = Vec::new();
        decrypt_body(&mut &encrypted[..], &mut decrypted, &[wrong, right]).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn truncated_segment_errors_not_panics() {
        let session_key = [1u8; SESSION_KEY_LEN];
        // Fewer bytes than nonce plus tag.
        let garbage = [0u8; 10];
        let mut out = Vec::new();
        std::assert_matches!(
            decrypt_body(&mut &garbage[..], &mut out, &[session_key]),
            Err(CoreError::DecryptFailed)
        );
    }
}
