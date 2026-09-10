//! Crypt4GH key formats and X25519 keypair generation.
//!
//! Implements only the unencrypted Crypt4GH secret-key format produced by
//! `crypt4gh-keygen --nocrypt`, plus the Crypt4GH public recipient format. This codec never
//! reads passphrase-wrapped keys; they are rejected with a clear error.
//!
//! Wire formats, byte-for-byte as the Crypt4GH reference implementation writes them:
//!
//! * Public key: a PEM envelope `-----BEGIN CRYPT4GH PUBLIC KEY-----` whose
//!   base64 body is the raw 32-byte X25519 public key.
//! * Secret key: a PEM envelope `-----BEGIN CRYPT4GH PRIVATE KEY-----` whose
//!   base64 body is `magic("c4gh-v1") || enc_string(kdf) || enc_string(cipher)
//!   || enc_string(key_material) [|| enc_string(comment)]`, where `enc_string`
//!   is `u16-be length || bytes`. For unencrypted keys `kdf == "none"`,
//!   `cipher == "none"` and `key_material` is the raw 32-byte X25519 secret.
#![expect(
    clippy::doc_markdown,
    reason = "the docs use Crypt4GH and X25519 as prose, not as code"
)]

use rand_core::OsRng;
use x25519_dalek::{PublicKey as DalekPublic, StaticSecret};
use zeroize::Zeroizing;

use crate::error::{CoreError, CoreResult};

/// Magic word prefixing the binary body of a Crypt4GH secret-key file.
const SECRET_MAGIC: &[u8] = b"c4gh-v1";
const PUBLIC_PEM_LABEL: &str = "CRYPT4GH PUBLIC KEY";
const PRIVATE_PEM_LABEL: &str = "CRYPT4GH PRIVATE KEY";

/// An X25519 public key, 32 bytes: a crypt4gh recipient, the key a package is encrypted to.
///
/// Public material is not secret, so the raw bytes are exposed. `Clone` but not `Copy`.
#[derive(Clone)]
pub struct PublicKey(pub(crate) DalekPublic);

impl PublicKey {
    /// Construct from raw 32 X25519 bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(DalekPublic::from(bytes))
    }

    /// The raw 32-byte X25519 public key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl core::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Public key is not sensitive, but keep Debug terse.
        f.debug_tuple("PublicKey").finish()
    }
}

/// An X25519 secret key, 32 bytes: a local identity, the key that decrypts. Zeroized on
/// drop.
///
/// The inner [`StaticSecret`] is zeroized on drop through the `zeroize` feature of
/// `x25519-dalek`. The type implements neither `Debug` nor `Display`, so secret material
/// cannot reach a log.
#[derive(Clone)]
pub struct SecretKey(pub(crate) StaticSecret);

impl SecretKey {
    /// Construct from raw 32 X25519 bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(StaticSecret::from(bytes))
    }

    /// The corresponding X25519 public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(DalekPublic::from(&self.0))
    }
}

/// Generate a fresh random X25519 keypair using the OS CSPRNG.
#[must_use]
pub fn generate_keypair() -> (SecretKey, PublicKey) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = DalekPublic::from(&secret);
    (SecretKey(secret), PublicKey(public))
}

/// Serialize a public recipient key to the Crypt4GH PEM format.
#[must_use]
pub fn serialize_public_key(pk: &PublicKey) -> String {
    pem_wrap(PUBLIC_PEM_LABEL, pk.as_bytes())
}

/// A short, stable fingerprint of a public recipient key, rendered `sha256:<hex>`.
///
/// The SHA-256 of the raw 32-byte X25519 public key, so the value is independent of PEM
/// whitespace and an operator can confirm which key the node publishes without diffing
/// whole PEM blocks. Public material only.
#[must_use]
pub fn public_key_fingerprint(pk: &PublicKey) -> String {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(pk.as_bytes());
    // `util::sha256_hex` renders the 64-lowercase-char hex shared with the manifest and
    // `vcfid` digests, so this cannot drift from them in case or width.
    format!("sha256:{}", crate::util::sha256_hex(hasher))
}

/// Serialize a secret key to the unencrypted Crypt4GH secret-key PEM format, the
/// `kdf == "none"` and `cipher == "none"` form `parse_secret_key` reads.
///
/// The raw secret and the assembled body are held in `Zeroizing` buffers and wiped once the
/// PEM is built. The returned `String` carries the base64-encoded secret and is not
/// zeroized, so a caller that retains it should wrap it in `Zeroizing`.
#[must_use]
pub fn serialize_secret_key(sk: &SecretKey) -> String {
    // Body: magic "c4gh-v1" || enc_string("none") || enc_string("none")
    //       || enc_string(raw 32-byte secret).
    let raw = Zeroizing::new(sk.0.to_bytes());
    let mut body = Zeroizing::new(Vec::with_capacity(SECRET_MAGIC.len() + 2 + 4 + 2 + 4 + 32));
    body.extend_from_slice(SECRET_MAGIC);
    push_enc_string(&mut body, b"none");
    push_enc_string(&mut body, b"none");
    push_enc_string(&mut body, &raw[..]);
    pem_wrap(PRIVATE_PEM_LABEL, &body)
}

/// Append a `u16-be length || bytes` length-prefixed string to `out`.
fn push_enc_string(out: &mut Vec<u8>, s: &[u8]) {
    // Lengths here are tiny, so the cast never truncates.
    let len = u16::try_from(s.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(s);
}

/// Parse a Crypt4GH public recipient key from its PEM file contents.
///
/// # Errors
/// Returns [`CoreError::InvalidManifest`] if the PEM envelope is malformed or
/// the decoded body is not exactly 32 bytes.
pub fn parse_public_key(pem: &str) -> CoreResult<PublicKey> {
    let body = pem_unwrap(pem, PUBLIC_PEM_LABEL)?;
    let bytes: [u8; 32] = body[..]
        .try_into()
        .map_err(|_| invalid("public key is not 32 bytes"))?;
    Ok(PublicKey::from_bytes(bytes))
}

/// Parse an unencrypted Crypt4GH secret key from its PEM file contents.
///
/// Only the `kdf == "none"` and `cipher == "none"` form is supported. A passphrase-wrapped
/// key yields a [`CoreError::InvalidManifest`] naming the unsupported encryption.
///
/// # Errors
/// Returns [`CoreError::InvalidManifest`] if the PEM envelope or binary body is
/// malformed, the magic word is wrong, the key is passphrase-encrypted, or the
/// key material is not 32 bytes.
pub fn parse_secret_key(pem: &str) -> CoreResult<SecretKey> {
    // The decoded body carries the raw 32-byte X25519 secret, so `Zeroizing` wipes its heap
    // allocation on drop. The caller's own PEM string still holds the secret unzeroized;
    // this only avoids adding a second un-scrubbed copy.
    let body = Zeroizing::new(pem_unwrap(pem, PRIVATE_PEM_LABEL)?);
    parse_secret_key_body(&body)
}

fn parse_secret_key_body(body: &[u8]) -> CoreResult<SecretKey> {
    let mut cur = Cursor::new(body);
    let magic = cur.take(SECRET_MAGIC.len())?;
    if magic != SECRET_MAGIC {
        return Err(invalid("not a Crypt4GH secret key (bad magic)"));
    }
    let kdf = cur.take_string()?;
    if kdf != b"none" {
        return Err(invalid(
            "passphrase-wrapped Crypt4GH secret keys are not supported",
        ));
    }
    let cipher = cur.take_string()?;
    if cipher != b"none" {
        return Err(invalid("encrypted Crypt4GH secret keys are not supported"));
    }
    let key_material = cur.take_string()?;
    let bytes: [u8; 32] = key_material
        .try_into()
        .map_err(|_| invalid("secret key material is not 32 bytes"))?;
    // Scrub this buffer on drop. Best-effort: `[u8; 32]` is `Copy`, so `Zeroizing::new`
    // copies rather than consumes and `SecretKey::from_bytes` takes the key by value, which
    // leaves `bytes` and the argument copy un-scrubbed. What is guaranteed is that the key's
    // final home is wiped, since `StaticSecret` carries the `zeroize` feature, and that the
    // decoded PEM body is `Zeroizing` in the caller. Removing the stack copies would mean
    // changing `from_bytes` to borrow.
    let zeroizing = Zeroizing::new(bytes);
    Ok(SecretKey::from_bytes(*zeroizing))
}

fn invalid(detail: &str) -> CoreError {
    CoreError::InvalidManifest {
        detail: detail.to_string(),
    }
}

// PEM envelope: label plus base64 body.

fn pem_wrap(label: &str, body: &[u8]) -> String {
    let mut out = String::new();
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    out.push_str(&base64_encode(body));
    out.push('\n');
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

fn pem_unwrap(pem: &str, label: &str) -> CoreResult<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut in_body = false;
    let mut b64 = String::new();
    for line in pem.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line == begin {
            in_body = true;
            continue;
        }
        if line == end {
            return base64_decode(&b64);
        }
        if in_body {
            b64.push_str(line);
        }
    }
    if in_body {
        Err(invalid("PEM is missing its END line"))
    } else {
        Err(invalid("PEM is missing its BEGIN line"))
    }
}

// Length-prefixed string reader: `u16-be length || bytes`.

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn take(&mut self, n: usize) -> CoreResult<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| invalid("key field length overflow"))?;
        if end > self.data.len() {
            return Err(invalid("truncated Crypt4GH secret key"));
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn take_string(&mut self) -> CoreResult<&'a [u8]> {
        let len_bytes = self.take(2)?;
        let len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
        self.take(len)
    }
}

// Minimal standard-alphabet base64.

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(B64_ALPHABET[(b0 >> 2) as usize] as char);
        out.push(B64_ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64_ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64_ALPHABET[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn base64_decode(input: &str) -> CoreResult<Vec<u8>> {
    // For a secret-key body the decoded symbol stream reconstructs the key bits, so
    // `Zeroizing` wipes its 6-bit-packed form on drop rather than leaving it in freed heap.
    // The public-key path decodes non-secret bytes, where the wrapper costs a few bytes.
    let mut symbols: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(input.len()));
    for &byte in input.as_bytes() {
        match byte {
            b'=' | b'\r' | b'\n' | b' ' | b'\t' => {}
            _ => {
                let v = base64_value(byte).ok_or_else(|| invalid("invalid base64 in key"))?;
                symbols.push(v);
            }
        }
    }
    let mut out = Vec::with_capacity(symbols.len() / 4 * 3);
    for group in symbols.chunks(4) {
        let n = group.len();
        if n == 1 {
            return Err(invalid("invalid base64 length in key"));
        }
        let b0 = group[0];
        let b1 = group[1];
        out.push((b0 << 2) | (b1 >> 4));
        if n >= 3 {
            let b2 = group[2];
            out.push((b1 << 4) | (b2 >> 2));
            if n == 4 {
                let b3 = group[3];
                out.push((b2 << 6) | b3);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;

    #[test]
    fn base64_round_trip_matches_known_vector() {
        // "Man" -> "TWFu", the RFC 4648 example.
        assert_eq!(base64_encode(b"Man"), "TWFu");
        assert_eq!(base64_decode("TWFu").unwrap(), b"Man");
        // Padding cases.
        assert_eq!(base64_encode(b"M"), "TQ==");
        assert_eq!(base64_decode("TQ==").unwrap(), b"M");
        assert_eq!(base64_encode(b"Ma"), "TWE=");
        assert_eq!(base64_decode("TWE=").unwrap(), b"Ma");
    }

    #[test]
    fn public_key_pem_round_trips() {
        let (_sk, pk) = generate_keypair();
        let pem = serialize_public_key(&pk);
        let parsed = parse_public_key(&pem).unwrap();
        assert_eq!(parsed.as_bytes(), pk.as_bytes());
    }

    #[test]
    fn secret_key_derives_matching_public() {
        let (sk, pk) = generate_keypair();
        assert_eq!(sk.public_key().as_bytes(), pk.as_bytes());
    }

    #[test]
    fn public_key_fingerprint_is_stable_and_hex() {
        let pk = PublicKey::from_bytes([0xABu8; 32]);
        let fp = public_key_fingerprint(&pk);
        assert!(fp.starts_with("sha256:"), "shape: {fp}");
        // The 7-char `sha256:` prefix plus 64 lowercase hex chars.
        assert_eq!(fp.len(), 71, "{fp}");
        assert!(
            fp.strip_prefix("sha256:")
                .unwrap()
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "lowercase hex only: {fp}"
        );
        // Deterministic and key-dependent.
        assert_eq!(
            fp,
            public_key_fingerprint(&PublicKey::from_bytes([0xABu8; 32]))
        );
        assert_ne!(
            fp,
            public_key_fingerprint(&PublicKey::from_bytes([0x01u8; 32]))
        );
    }

    #[test]
    fn secret_key_pem_round_trips() {
        let (sk, pk) = generate_keypair();
        let pem = serialize_secret_key(&sk);
        // Re-parse: the round-tripped secret derives the same public key.
        let parsed = parse_secret_key(&pem).unwrap();
        assert_eq!(parsed.public_key().as_bytes(), pk.as_bytes());
        // The serialized form is the unencrypted variant the parser accepts.
        assert!(pem.contains("BEGIN CRYPT4GH PRIVATE KEY"));
    }

    #[test]
    fn passphrase_wrapped_secret_key_is_rejected() {
        // magic plus kdf="scrypt" is unsupported: it must error, not panic.
        let mut body = Vec::new();
        body.extend_from_slice(SECRET_MAGIC);
        body.extend_from_slice(&(6u16).to_be_bytes());
        body.extend_from_slice(b"scrypt");
        let pem = pem_wrap(PRIVATE_PEM_LABEL, &body);
        // `SecretKey` has no `Debug`, so this uses `matches!` rather than `unwrap_err`.
        assert!(matches!(
            parse_secret_key(&pem),
            Err(CoreError::InvalidManifest { .. })
        ));
    }

    #[test]
    fn malformed_secret_key_errors_not_panics() {
        let pem = pem_wrap(PRIVATE_PEM_LABEL, b"\x00\x01\x02");
        assert!(parse_secret_key(&pem).is_err());
        assert!(parse_public_key("not a pem at all").is_err());
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let (_sk, pk) = generate_keypair();
        // `PublicKey`'s `Debug` is terse, and `SecretKey` has no `Debug` impl.
        assert_eq!(format!("{pk:?}"), "PublicKey");
    }
}
