//! The `identity list` one-shot for a file-backed node identity, the non-Vault (`[keys]`)
//! posture. The Vault posture is `crate::list_identity`, which reads the identity state out
//! of Vault KV (a plain code span, since a lite rustdoc has nothing to link).
//!
//! This reports what the loader ([`crate::identities`]) will do at boot rather than forming
//! a separate opinion about the files: same order, same published-recipient rule (the first
//! entry), same permission policy including `[service].strict_key_perms`. Run it before a
//! restart and it tells you whether the node comes back.
//!
//! It prints public material only: the path, the role, a SHA-256 fingerprint of the public
//! key, and the file mode. Never the secret PEM.

use std::path::Path;

use anyhow::{Result, bail};
use zeroize::Zeroizing;

use gdi_node_standalone_core::config::ServiceConfig;
use gdi_node_standalone_core::crypt4gh::{parse_secret_key, public_key_fingerprint};

/// One configured identity file's inspected state.
pub(crate) struct Entry {
    /// Role text: the published recipient, or decrypt-only.
    role: &'static str,
    /// The configured path, as written in `[keys].identities`.
    pub(crate) path: String,
    /// `sha256:…` of the public key, or `None` when the file could not be read/parsed.
    fingerprint: Option<String>,
    /// A problem that would stop the node booting, if any.
    pub(crate) fatal: Option<String>,
    /// A non-fatal note (loose permissions on a non-strict node).
    pub(crate) warning: Option<String>,
}

/// Print the node's file-backed crypt4gh identity state: one line per `[keys].identities`
/// entry, with its role, public-key fingerprint and file mode.
///
/// Reports rather than aborting on the first bad entry, so the output names every bad
/// entry. The non-zero exit comes at the end if any entry would stop the node booting.
///
/// # Errors
///
/// Returns an error, which `main` maps to a non-zero exit, when any configured identity is
/// missing, unreadable, not an unencrypted crypt4gh v1 secret key, or, when
/// `[service].strict_key_perms` is set, group- or other-readable. These are the conditions
/// under which [`crate::identities::NodeIdentities::load`] refuses to start.
pub fn run(config: &ServiceConfig) -> Result<()> {
    let paths = &config.keys.identities;
    if paths.is_empty() {
        println!(
            "no crypt4gh identities configured ([keys].identities is empty or absent): this \
             node is KEYLESS. It cannot ingest encrypted .tar.c4gh packages, and \
             /.well-known/c4gh-recipient is disabled. That is a valid posture for a \
             plaintext-only node; `identity init` mints a key if it was not intended."
        );
        return Ok(());
    }

    let strict = config.service.strict_key_perms;
    let entries: Vec<Entry> = paths
        .iter()
        .enumerate()
        .map(|(i, path)| inspect(path, i == 0, strict))
        .collect();

    println!(
        "node crypt4gh identities ({} configured in [keys].identities, tried in order; \
         the first is the published recipient):",
        entries.len()
    );
    for (i, e) in entries.iter().enumerate() {
        println!("  [{i}] {:<20} {}", e.role, e.path);
        match (&e.fingerprint, &e.fatal) {
            (Some(fp), _) => println!("      fingerprint: {fp}"),
            (None, Some(err)) => println!("      ERROR: {err}"),
            (None, None) => {}
        }
        if let Some(w) = &e.warning {
            println!("      WARNING: {w}");
        }
    }

    let failed: Vec<&Entry> = entries.iter().filter(|e| e.fatal.is_some()).collect();
    if !failed.is_empty() {
        bail!(
            "{} of {} configured identities cannot be loaded; the node would REFUSE TO \
             START. Fix or remove the listed entries.",
            failed.len(),
            entries.len()
        );
    }
    // The identity-plane read is auditable in both postures, matching the Vault twin
    // (`list_identity`). Records only the count, never a path or a fingerprint.
    crate::audit::identity_listed(&config.audit, entries.len());
    Ok(())
}

/// Inspect one identity file: parse it for a fingerprint and apply the loader's
/// permission policy. Never returns key material.
///
/// `pub(crate)` so `doctor` reaches this predictor instead of re-implementing it. A second
/// spelling of "would this key load?" can report `OK` for key material it never opened.
pub(crate) fn inspect(path: &Path, published: bool, strict: bool) -> Entry {
    let role = if published {
        "PUBLISHED RECIPIENT"
    } else {
        "decrypt-only"
    };
    let display = path.display().to_string();
    let mut entry = Entry {
        role,
        path: display,
        fingerprint: None,
        fatal: None,
        warning: None,
    };

    // Permissions first: a loose key file is worth saying even when it also fails to
    // parse, and under `strict_key_perms` it is itself a boot blocker.
    match key_mode(path) {
        Ok(Some(mode)) if mode & 0o077 != 0 => {
            let msg = format!(
                "mode {:o} is group/other-readable; recommend chmod 0600 (or 0400)",
                mode & 0o7777
            );
            if strict {
                entry.fatal = Some(format!("{msg}; strict_key_perms is set"));
            } else {
                entry.warning = Some(msg);
            }
        }
        Ok(_) => {}
        Err(e) => entry.fatal = Some(e),
    }

    // Read and parse. `Zeroizing` so the secret PEM does not linger in freed heap, matching
    // the loader and the mint paths.
    match std::fs::read_to_string(path).map(Zeroizing::new) {
        Ok(pem) => match parse_secret_key(&pem) {
            Ok(sk) => entry.fingerprint = Some(public_key_fingerprint(&sk.public_key())),
            Err(e) => {
                entry.fatal.get_or_insert(format!(
                    "not an UNENCRYPTED crypt4gh v1 secret key ({e}); the loader accepts \
                     only `kdf`/`cipher` = none, as produced by `crypt4gh-keygen --nocrypt`"
                ));
            }
        },
        Err(e) => {
            entry
                .fatal
                .get_or_insert(format!("cannot read the identity file: {e}"));
        }
    }
    entry
}

/// The file's permission bits on unix; `Ok(None)` where they are not comparable.
#[cfg(unix)]
fn key_mode(path: &Path) -> Result<Option<u32>, String> {
    use std::os::unix::fs::PermissionsExt as _;
    match std::fs::metadata(path) {
        Ok(meta) => Ok(Some(meta.permissions().mode())),
        Err(e) => Err(format!("cannot stat the identity file: {e}")),
    }
}

/// Non-unix: permission bits are not comparable, so only existence is checked.
#[cfg(not(unix))]
fn key_mode(path: &Path) -> Result<Option<u32>, String> {
    match std::fs::metadata(path) {
        Ok(_) => Ok(None),
        Err(e) => Err(format!("cannot stat the identity file: {e}")),
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;
    use gdi_node_standalone_core::crypt4gh::{generate_keypair, serialize_secret_key};

    /// Write a real crypt4gh secret key at `path` with mode `mode`.
    fn write_key(path: &Path, mode: u32) {
        let (sk, _pk) = generate_keypair();
        std::fs::write(path, serialize_secret_key(&sk)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
    }

    fn config_with(paths: Vec<std::path::PathBuf>, strict: bool) -> ServiceConfig {
        let mut cfg = ServiceConfig::default();
        cfg.keys.identities = paths;
        cfg.service.strict_key_perms = strict;
        cfg
    }

    #[test]
    fn keyless_node_is_reported_and_is_not_an_error() {
        // An empty list is a valid posture (a plaintext-only node), not a misconfiguration.
        run(&config_with(vec![], false)).expect("a keyless node lists cleanly");
    }

    #[test]
    fn first_entry_is_the_published_recipient_and_the_rest_are_decrypt_only() {
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a.c4gh");
        let b = tmp.path().join("b.c4gh");
        write_key(&a, 0o600);
        write_key(&b, 0o600);

        let published = inspect(&a, true, false);
        let secondary = inspect(&b, false, false);
        assert_eq!(published.role, "PUBLISHED RECIPIENT");
        assert_eq!(secondary.role, "decrypt-only");
        // Distinct keys must fingerprint distinctly, so the output tells which key is
        // which after a rotation.
        assert!(published.fingerprint.is_some());
        assert_ne!(published.fingerprint, secondary.fingerprint);
        run(&config_with(vec![a, b], false)).expect("two good keys load");
    }

    #[test]
    fn a_missing_or_unparseable_identity_is_fatal_because_the_node_would_not_boot() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("absent.c4gh");
        assert!(inspect(&missing, true, false).fatal.is_some());
        assert!(run(&config_with(vec![missing], false)).is_err());

        let junk = tmp.path().join("junk.c4gh");
        std::fs::write(&junk, b"not a crypt4gh key").unwrap();
        let e = inspect(&junk, true, false);
        assert!(e.fatal.is_some(), "unparseable key must be fatal");
        assert!(
            e.fingerprint.is_none(),
            "no fingerprint for an unparsed key"
        );
        assert!(run(&config_with(vec![junk], false)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn loose_permissions_warn_but_only_block_the_boot_under_strict_key_perms() {
        // This mirrors `identities::check_key_perms`: the command predicts the loader, so
        // the two policies must not diverge.
        let tmp = tempfile::tempdir().unwrap();
        let loose = tmp.path().join("loose.c4gh");
        write_key(&loose, 0o644);

        let lax = inspect(&loose, true, false);
        assert!(
            lax.warning.is_some(),
            "loose perms warn on a non-strict node"
        );
        assert!(lax.fatal.is_none(), "and do not block its boot");
        assert!(run(&config_with(vec![loose.clone()], false)).is_ok());

        let strict = inspect(&loose, true, true);
        assert!(
            strict.fatal.is_some(),
            "strict_key_perms turns loose perms into a boot blocker"
        );
        assert!(run(&config_with(vec![loose], true)).is_err());
    }
}
