//! Loading the node's crypt4gh identities from `[keys].identities` files.
//!
//! The service reads each unencrypted crypt4gh secret-key file listed in
//! `[keys].identities` and holds the parsed [`SecretKey`]s in order. They are tried in turn
//! when decrypting an inbound `.tar.c4gh`, and the first is the node's published recipient.
//! With an empty list the node is keyless: the encrypted path and
//! `/.well-known/c4gh-recipient` are disabled.
//!
//! Key material lives in [`SecretKey`], which zeroizes its inner `StaticSecret` on drop (the
//! `x25519-dalek` `zeroize` feature). The wrapper here has no `Debug`/`Display`, so
//! identities can never be logged.
//!
//! On Unix the loader stats each key file. A group- or other-readable file
//! (`mode & 0o077 != 0`) refuses startup, because `[service].strict_key_perms` defaults to
//! `true`; setting it to `false` downgrades that to a warning. The check is skipped on
//! non-unix and for an empty identity list.

use std::path::Path;

use anyhow::{Context as _, Result};
use gdi_node_standalone_core::config::ServiceConfig;
use gdi_node_standalone_core::crypt4gh::{
    PublicKey, SecretKey, parse_secret_key, serialize_public_key,
};
use tracing::{info, warn};
use zeroize::Zeroizing;

/// The node's loaded crypt4gh identities, in `[keys].identities` order.
///
/// Holds zeroize-backed [`SecretKey`]s, and is neither `Debug` nor `Clone` so key material
/// is never copied or logged. Cheap to wrap behind an `Arc` in the service state.
pub struct NodeIdentities {
    /// Parsed secret keys, tried in order; the first is the published recipient.
    secrets: Vec<SecretKey>,
}

impl NodeIdentities {
    /// Load the identities from `[keys].identities`, running the key-file
    /// permission policy.
    ///
    /// Relative identity paths are resolved against the process working directory
    /// (the deployment mounts absolute paths; tests use absolute temp paths).
    ///
    /// # Errors
    ///
    /// Returns an error if a key file cannot be read or parsed, or, when
    /// `[service].strict_key_perms` is set, if a key file is group- or other-readable.
    pub fn load(config: &ServiceConfig) -> Result<Self> {
        let mut secrets = Vec::with_capacity(config.keys.identities.len());
        for path in &config.keys.identities {
            check_key_perms(path, config.service.strict_key_perms)?;
            // Hold the secret PEM in a zeroized buffer, as `init_identity` and
            // `rotate_identity` do, so the plaintext key does not linger in freed heap.
            let pem = Zeroizing::new(
                std::fs::read_to_string(path)
                    .with_context(|| format!("reading crypt4gh identity {}", path.display()))?,
            );
            let sk = parse_secret_key(&pem)
                .with_context(|| format!("parsing crypt4gh identity {}", path.display()))?;
            secrets.push(sk);
        }
        if secrets.is_empty() {
            info!(
                "no crypt4gh identities configured; encrypted .tar.c4gh ingest and /.well-known/c4gh-recipient are disabled"
            );
        } else {
            info!(count = secrets.len(), "loaded crypt4gh node identities");
        }
        Ok(Self { secrets })
    }

    /// Build an empty (keyless) identity set.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            secrets: Vec::new(),
        }
    }

    /// Build identities from in-memory crypt4gh secret-key PEMs, in the given order. The
    /// first is the published recipient.
    ///
    /// This is the Vault-backed path: the KV secret holds one or more PEM bodies and the
    /// Vault `secrets` loader passes them here in load order, overriding the inline `[keys]`
    /// files. No key-file permission check applies, because the material never touches disk.
    /// The PEM strings are parsed and dropped; the parsed [`SecretKey`]s zeroize on drop.
    ///
    /// # Errors
    ///
    /// Returns an error if any PEM fails to parse as an unencrypted crypt4gh
    /// secret key.
    pub fn from_pems<'a, I>(pems: I) -> Result<Self>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut secrets = Vec::new();
        for (idx, pem) in pems.into_iter().enumerate() {
            let sk = parse_secret_key(pem)
                .with_context(|| format!("parsing Vault crypt4gh identity #{idx}"))?;
            secrets.push(sk);
        }
        if secrets.is_empty() {
            info!("Vault crypt4gh identity secret held no keys; node is keyless");
        } else {
            info!(
                count = secrets.len(),
                "loaded crypt4gh node identities from Vault"
            );
        }
        Ok(Self { secrets })
    }

    /// The identities, in order, for
    /// [`gdi_node_standalone_core::ingest::ingest_tar_c4gh_with_bounds`], which is the entry
    /// point the service calls.
    #[must_use]
    pub fn secrets(&self) -> &[SecretKey] {
        &self.secrets
    }

    /// Whether any identity is configured (the encrypted path is enabled).
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        !self.secrets.is_empty()
    }

    /// The node's recipient, the public key of the first identity, or `None` when keyless.
    #[must_use]
    pub fn recipient(&self) -> Option<PublicKey> {
        self.secrets.first().map(SecretKey::public_key)
    }

    /// The node's recipient serialized as the crypt4gh PEM, or `None` when keyless.
    ///
    /// This is the body served at `/.well-known/c4gh-recipient`.
    #[must_use]
    pub fn recipient_pem(&self) -> Option<String> {
        self.recipient().map(|pk| serialize_public_key(&pk))
    }
}

/// Apply the key-file permission policy to one identity path.
///
/// On Unix a group- or other-readable file (`mode & 0o077 != 0`) errors when `strict` is
/// set, which is the default, and warns when it is false. A no-op on non-unix.
#[cfg(unix)]
fn check_key_perms(path: &Path, strict: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let meta = std::fs::metadata(path)
        .with_context(|| format!("statting crypt4gh identity {}", path.display()))?;
    let mode = meta.permissions().mode();
    if mode & 0o077 != 0 {
        if strict {
            anyhow::bail!(
                "crypt4gh identity {} is group/other-readable (mode {:o}); strict_key_perms is set, refusing to start (recommend chmod 0400/0600)",
                path.display(),
                mode & 0o7777
            );
        }
        warn!(
            path = %path.display(),
            mode = format!("{:o}", mode & 0o7777),
            "crypt4gh identity is group/other-readable; recommend chmod 0400/0600 (set strict_key_perms to refuse startup)"
        );
    }
    Ok(())
}

/// Non-unix: file permission bits are not comparable, so the check is a no-op.
#[cfg(not(unix))]
fn check_key_perms(_path: &Path, _strict: bool) -> Result<()> {
    Ok(())
}
