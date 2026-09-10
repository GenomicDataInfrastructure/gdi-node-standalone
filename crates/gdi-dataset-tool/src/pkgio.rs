//! Shared `.tar.c4gh` package I/O helpers used by `validate`, `unpack`, and
//! `inspect`.
//!
//! A package is crypt4gh-encrypted to the node recipient plus the provider's own
//! recipient, so the provider can always decrypt its own packages with its own
//! identity. These helpers load the provider identities (the whole `[keys].identities`
//! rotation list, tried in order so a package encrypted to a now-retired key still
//! decrypts) and decrypt a package, either fully (to a scratch file) or only the
//! leading bytes a metadata-only consumer needs.

use std::fs;
use std::io::Write as _;
use std::path::Path;

use gdi_node_standalone_core::crypt4gh::{
    PublicKey, SecretKey, decrypt, public_key_fingerprint, recover_writer_keys,
};
use gdi_node_standalone_core::error::CoreError;
use gdi_node_standalone_core::extract::{ExtractBounds, extract_tar_safely};
use gdi_node_standalone_core::id::is_valid_dataset_id;

use crate::scratch::create_scratch_file;
use crate::{ToolError, commands::cmd_keys};

// The encrypted-package suffix is defined once in `core::s3_layout`; re-exported
// here so `crate::pkgio::TAR_C4GH_SUFFIX` is the local name.
pub use gdi_node_standalone_core::s3_layout::TAR_C4GH_SUFFIX;

/// Derive the dataset id from a `{id}.tar.c4gh` package path, validating it.
///
/// Used by `upload` and `deploy` to key S3 objects / inbox names by the id, so a
/// renamed or malformed package fails fast rather than uploading under a bad key.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) if the file name is not `{id}.tar.c4gh`, is
/// non-UTF-8, or the derived id is not a valid dataset id.
pub fn dataset_id_from_package(package: &Path) -> Result<String, ToolError> {
    let name = package
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| {
            ToolError::user(format!(
                "non-UTF-8 package file name: {}",
                package.display()
            ))
        })?;
    let id = name.strip_suffix(TAR_C4GH_SUFFIX).ok_or_else(|| {
        ToolError::user(format!(
            "package name must be {{id}}{TAR_C4GH_SUFFIX}: {}",
            package.display()
        ))
    })?;
    if !is_valid_dataset_id(id) {
        return Err(ToolError::user(format!(
            "package name does not carry a valid dataset id: {}",
            package.display()
        )));
    }
    Ok(id.to_owned())
}

/// Load all the provider's crypt4gh identities (the rotation list), in order.
///
/// # Errors
///
/// Propagates any failure from [`cmd_keys::load_all_provider_secrets`].
pub fn provider_identities(config_path: Option<&Path>) -> Result<Vec<SecretKey>, ToolError> {
    cmd_keys::load_all_provider_secrets(config_path)
}

/// Reject a file that is not a crypt4gh package, leaving `reader` rewound to the start.
///
/// A crypt4gh file begins with the 8-byte `crypt4gh` magic. Every key-consuming read path
/// calls this first, before demanding a provider identity: whether a file is a package has
/// nothing to do with which keys you hold, so `lint notes.txt` must say "not a .tar.c4gh
/// package", not "no provider identity" (nor the opaque "decrypt failed" the crypto layer
/// would emit). One definition, so the two read paths cannot drift into disagreeing about
/// what a package looks like.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) if the path is a directory, if the leading 8 bytes
/// are present but are not the `crypt4gh` magic, or if the file cannot be rewound. (A
/// file shorter than 8 bytes, whose prefix cannot be read, is not rejected here and
/// falls through to the decrypt path.)
fn ensure_crypt4gh_magic(reader: &mut fs::File, package: &Path) -> Result<(), ToolError> {
    use std::io::{Read as _, Seek as _};
    // Opening a directory read-only succeeds, so without this check the mistake only
    // surfaces inside the decrypt, misreported as a key mismatch — and `build` produces
    // a directory, so pointing a packed-file verb at one is a natural slip.
    if reader.metadata().is_ok_and(|m| m.is_dir()) {
        return Err(ToolError::user(format!(
            "{} is a directory, not a .tar.c4gh package; this command reads the packed \
             file `pack` produces; a staging directory is what `validate`, `lint` and \
             `deploy` take",
            package.display()
        )));
    }
    let mut magic = [0u8; 8];
    if reader.read_exact(&mut magic).is_ok() && &magic != b"crypt4gh" {
        return Err(ToolError::user(format!(
            "{} is not a .tar.c4gh package (no crypt4gh header); run `build`/`pack` first, \
             or point at a real package",
            package.display()
        )));
    }
    reader
        .rewind()
        .map_err(|e| ToolError::user(format!("cannot read package {}: {e}", package.display())))
}

/// Decrypt the whole `.tar.c4gh` at `package` into the plaintext TAR file at
/// `tar_out`, trying every configured provider identity in order (so a package
/// encrypted to a now-retired key still decrypts — `decrypt` iterates the identity list).
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) if the package cannot be read, no provider
/// identity can decrypt it, or the plaintext TAR cannot be written.
pub fn decrypt_package_to(
    package: &Path,
    tar_out: &Path,
    config_path: Option<&Path>,
) -> Result<(), ToolError> {
    // Delegate to the streaming variant so the magic sniff ("not a .tar.c4gh package")
    // and the identity-aware decrypt-failure message are shared rather than duplicated;
    // it decrypts straight into the scratch file.
    let mut writer = create_scratch_file(tar_out)?;
    decrypt_package_to_writer(package, &mut writer, config_path)?;
    writer
        .flush()
        .map_err(|e| ToolError::user(format!("cannot flush {}: {e}", tar_out.display())))?;
    Ok(())
}

/// Decrypt `package` into `writer`, streaming — without staging the whole plaintext to
/// a scratch file. A metadata-only consumer (e.g. one reading just `manifest.json`, the
/// small first member) supplies a sink it stops reading from once it has what it needs;
/// dropping that sink's read end then makes our write fail with [`std::io::ErrorKind::BrokenPipe`],
/// which is treated here as a deliberate early stop (`Ok`), not a decrypt failure. A real
/// decrypt failure (e.g. no provider identity can decrypt the header) still returns `Err`.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) if the package cannot be opened or genuinely cannot
/// be decrypted with a provider identity.
pub fn decrypt_package_to_writer<W: std::io::Write>(
    package: &Path,
    writer: &mut W,
    config_path: Option<&Path>,
) -> Result<(), ToolError> {
    let mut reader = fs::File::open(package)
        .map_err(|e| ToolError::user(format!("cannot read package {}: {e}", package.display())))?;
    ensure_crypt4gh_magic(&mut reader, package)?;
    let identities = provider_identities(config_path)?;
    match decrypt(&mut reader, writer, &identities) {
        Ok(()) => Ok(()),
        // The consumer stopped early (dropped its read end) — not a decrypt failure; let
        // the consumer's own result stand.
        Err(CoreError::Io(e)) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(e) => {
            let n = identities.len();
            // Name which keys were tried, with their fingerprints. The failure that actually
            // bites is a config-dir mismatch: identities resolve under the config dir, so
            // `pack` run without `--config` and `inspect` run with it silently use different
            // key sets. "none of the configured identities could decrypt it" gives the
            // operator no way to see that; the paths + fingerprints do.
            let tried = cmd_keys::resolve_identities(config_path).map_or_else(
                |_| "<could not resolve identity paths>".to_owned(),
                |paths| {
                    paths
                        .iter()
                        .zip(identities.iter())
                        .map(|(path, sk)| {
                            format!(
                                "{} ({})",
                                path.display(),
                                public_key_fingerprint(&sk.public_key())
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                },
            );
            Err(ToolError::user(format!(
                "cannot decrypt {}: none of the {n} configured provider identit{} could decrypt it \
                 ({e}). Tried: {tried}. The package is wrapped to a recipient that none of these \
                 keys match. Check the file is a real .tar.c4gh package (not truncated/partial), and \
                 that the key it was wrapped to is listed in [keys].identities. Identities \
                 resolve under the config directory, so running with `--config` can select a \
                 different key set than the default.",
                package.display(),
                if n == 1 { "y" } else { "ies" },
            )))
        }
    }
}

/// Recover the package's `Crypt4GH` writer/sender public key(s) — read-only header
/// inspection (the body is never decrypted). The writer key is the only provenance
/// signal a package carries absent a signature: it is *proof-of-possession*, not an
/// authenticated identity (anyone who knows the recipient's public key can author a
/// package under a fresh writer key of their own), so it is trustworthy only when
/// compared against an out-of-band allowlist of known writer keys.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) if the package cannot be read, or no provider
/// identity can decrypt any header packet.
pub fn recover_writer_keys_of(
    package: &Path,
    config_path: Option<&Path>,
) -> Result<Vec<PublicKey>, ToolError> {
    let mut reader = fs::File::open(package)
        .map_err(|e| ToolError::user(format!("cannot read package {}: {e}", package.display())))?;
    // Sniff before demanding a key — see `ensure_crypt4gh_magic`. `inspect` reaches this
    // path, and pointing it at a text file must not be reported as a missing identity.
    ensure_crypt4gh_magic(&mut reader, package)?;
    let identities = provider_identities(config_path)?;
    recover_writer_keys(&mut reader, &identities).map_err(|e| {
        ToolError::user(format!(
            "cannot recover the writer key from {}: {e}",
            package.display()
        ))
    })
}

/// The `sha256:<hex>` fingerprint of each recovered writer/sender public key.
#[must_use]
pub fn writer_key_fingerprints(keys: &[PublicKey]) -> Vec<String> {
    keys.iter().map(public_key_fingerprint).collect()
}

/// Decrypt a `.tar.c4gh` package and safe-extract its TAR into `dest`.
///
/// Streams the crypt4gh decrypt straight into the safe extractor over an in-process
/// pipe, so the whole plaintext TAR is never staged to disk alongside the extracted
/// tree (that would be a redundant full-size copy). The decrypt runs on a worker thread
/// feeding the pipe; the calling thread reads + extracts into `dest`. A genuine decrypt
/// failure is surfaced over the truncated-stream extract symptom. Shared by `validate`
/// and `lint`.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) if the pipe cannot be created, the package cannot be
/// decrypted, or the TAR fails safe extraction.
pub fn decrypt_and_extract_package(
    package: &Path,
    dest: &Path,
    config_path: Option<&Path>,
) -> Result<(), ToolError> {
    let (reader, mut writer) =
        std::io::pipe().map_err(|e| ToolError::user(format!("cannot create decrypt pipe: {e}")))?;
    let package_owned = package.to_path_buf();
    let config_owned = config_path.map(Path::to_path_buf);
    let decrypt_thread = std::thread::spawn(move || {
        decrypt_package_to_writer(&package_owned, &mut writer, config_owned.as_deref())
    });
    // Live byte progress over the decrypt→extract stream (validate/lint decrypt and
    // extract the full parquet payload — tens of seconds to minutes on a multi-GB
    // package). Sized to the `.tar.c4gh` ciphertext length, TTY-gated like unpack/pack.
    let total = std::fs::metadata(package).map_or(0, |m| m.len());
    let sp =
        crate::progress::StreamProgress::new(total, "reading package", crate::progress::active());
    let extract_result = extract_tar_safely(sp.wrap_read(reader), dest, &ExtractBounds::default())
        .map_err(|e| ToolError::user(e.to_string()));
    let decrypt_result = decrypt_thread
        .join()
        .unwrap_or_else(|_| Err(ToolError::user("decrypt thread panicked during extraction")));
    sp.finish();
    // Surface a genuine decrypt failure over the truncated-stream extract symptom.
    decrypt_result?;
    extract_result?;
    Ok(())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
mod tests {
    use std::path::PathBuf;

    use super::*;

    /// A name not ending in `.tar.c4gh` → error mentioning the expected suffix.
    #[test]
    fn dataset_id_from_package_rejects_wrong_extension() {
        let path = PathBuf::from("GDI-EE-UTARTU-20260409143052837.tar.gz");
        let err = dataset_id_from_package(&path).unwrap_err();
        assert!(
            err.message.contains(TAR_C4GH_SUFFIX),
            "error must mention the expected suffix; got: {}",
            err.message
        );
    }

    /// A `.tar.c4gh` name whose stem is not a valid dataset id → error.
    #[test]
    fn dataset_id_from_package_rejects_invalid_id_stem() {
        let path = PathBuf::from("not-a-valid-id.tar.c4gh");
        let err = dataset_id_from_package(&path).unwrap_err();
        assert!(
            err.message.contains("valid dataset id"),
            "error must mention 'valid dataset id'; got: {}",
            err.message
        );
    }

    /// A well-formed `{id}.tar.c4gh` name → returns the correct dataset id.
    #[test]
    fn dataset_id_from_package_round_trips_valid_name() {
        let id = "GDI-EE-UTARTU-20260409143052837";
        let path = PathBuf::from(format!("{id}{TAR_C4GH_SUFFIX}"));
        let got = dataset_id_from_package(&path).unwrap();
        assert_eq!(got, id, "round-trip: extracted id must match the stem");
    }

    /// A directory argument is named for what it is — `build` produces one, so a
    /// packed-file verb pointed at it must not diagnose a key mismatch.
    #[test]
    fn decrypt_package_rejects_a_directory_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let mut sink = Vec::new();
        let err = decrypt_package_to_writer(dir.path(), &mut sink, None).unwrap_err();
        assert!(
            err.message.contains("is a directory"),
            "error must name the directory mistake; got: {}",
            err.message
        );
        assert!(
            !err.message.contains("identit"),
            "must not be reported as an identity/key problem; got: {}",
            err.message
        );
    }
}
