//! The `identity init` one-shot for a file-backed node identity, the non-Vault (`[keys]`)
//! posture. The Vault posture is `crate::init_identity`, which mints the identity straight
//! into Vault KV (a plain code span, since a lite rustdoc has nothing to link).
//!
//! A node without `[vault]` needs the same key on disk at `[keys].identities`, and the node
//! mints its own rather than borrowing the provider CLI's `keys generate`, which mints a
//! provider identity to a path driven by the provider tool's config.
//!
//! The target is whatever the config already declares, so the key cannot land somewhere the
//! node will not read it: `--file` if given, else the first `[keys].identities` entry, which
//! is the published recipient (see [`crate::identities`]).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use gdi_node_standalone_core::config::ServiceConfig;
use gdi_node_standalone_core::crypt4gh::{
    generate_keypair, parse_public_key, parse_secret_key, public_key_fingerprint,
    serialize_public_key, serialize_secret_key,
};
use gdi_node_standalone_core::util::{write_durable_atomic, write_secret_durable};
use zeroize::Zeroizing;

/// Mint the node crypt4gh identity into a file, or import it when `from` is set.
///
/// Create-only: an existing key is the one irreplaceable node secret, since it decrypts
/// every inbound `.tar.c4gh` and all PME-at-rest parquet, so it is never silently replaced.
/// `ensure` treats an already-provisioned identity as success, for an idempotent re-run of a
/// bring-up script. `force` replaces it, first copying the old key to a timestamped
/// `.bak-<epoch>` sibling.
///
/// # Errors
///
/// Returns an error when no target can be resolved, when the target exists and neither
/// `ensure` nor `force` was given, when `from` is not a readable unencrypted crypt4gh
/// key, or when the key cannot be written.
pub fn run(
    config: &ServiceConfig,
    ensure: bool,
    force: bool,
    from: Option<&Path>,
    file: Option<&Path>,
) -> Result<()> {
    let target = resolve_target(config, file)?;

    if target.exists() {
        if ensure {
            println!(
                "node crypt4gh identity already provisioned at {}",
                target.display()
            );
            print_existing_recipient(&target);
            return Ok(());
        }
        if !force {
            bail!(
                "refusing to replace the existing node identity at {}: it is the one \
                 irreplaceable node secret (it decrypts every ingested package and all \
                 PME-at-rest parquet, so a package wrapped to it can be read with NO other \
                 key). Pass --ensure to treat an already-provisioned identity as success, \
                 or --force to replace it (the old key is first copied to a `.bak-<epoch>` \
                 sibling).",
                target.display()
            );
        }
    }

    // Mint a fresh keypair, or import and validate the supplied one. Importing parses the
    // key here, so an identity the loader would reject at boot fails now instead.
    let (secret_pem, recipient_pem) = if let Some(path) = from {
        let pem =
            Zeroizing::new(std::fs::read_to_string(path).with_context(|| {
                format!("reading the identity to import from {}", path.display())
            })?);
        let secret_key = parse_secret_key(&pem).with_context(|| {
            format!(
                "{} is not an UNENCRYPTED crypt4gh v1 secret key: the node loader accepts \
                 only `kdf`/`cipher` = none (as produced by `crypt4gh-keygen --nocrypt`); a \
                 passphrase-protected or OpenSSH key is rejected at startup",
                path.display()
            )
        })?;
        (pem, serialize_public_key(&secret_key.public_key()))
    } else {
        warn_if_datasets_predate_new_identity(&config.service.data_dir);
        let (secret_key, public_key) = generate_keypair();
        (
            Zeroizing::new(serialize_secret_key(&secret_key)),
            serialize_public_key(&public_key),
        )
    };

    // Only reachable with `--force`; the create-only guard above returned otherwise.
    if target.exists() {
        back_up_replaced_identity(&target)?;
    }

    if let Some(parent) = target.parent()
        && !parent.as_os_str().is_empty()
    {
        // Owner-only: this directory holds the node's private key.
        gdi_node_standalone_core::util::create_private_dir(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }

    // `write_secret_durable`, not a bare write: temp, fsync, rename, parent fsync, with
    // `0o600` applied to the temp at `O_CREAT`. A later chmod would expose the key for the
    // duration of the write, and `rename` preserves the temp's mode. The node also refuses
    // to start on a group- or other-readable identity under `strict_key_perms`.
    write_secret_durable(&target, secret_pem.as_bytes())
        .with_context(|| format!("writing the node identity to {}", target.display()))?;

    let recipient = recipient_path(&target);
    #[expect(
        clippy::disallowed_methods,
        reason = "not secret: the PUBLIC recipient PEM; the secret PEM uses write_secret_durable four lines above"
    )]
    write_durable_atomic(&recipient, recipient_pem.as_bytes())
        .with_context(|| format!("writing the node recipient to {}", recipient.display()))?;

    crate::audit::identity_initialized(
        &config.audit,
        &target.display().to_string(),
        from.is_some(),
    );

    println!("wrote node crypt4gh identity to {}", target.display());
    println!("wrote node recipient to {}", recipient.display());
    print_recipient(&recipient_pem);
    // There is no `identity backup` for a file key: the file is the only copy. The advisory
    // goes to stderr so it cannot corrupt a captured recipient PEM on stdout.
    eprintln!(
        "next: back this key file up somewhere safe and keep its mode at 0600. It is the \
         one irreplaceable node secret, and losing it makes every ingested dataset \
         unreadable."
    );
    Ok(())
}

/// Resolve where the identity should be written: `--file`, else the first configured
/// `[keys].identities` entry.
///
/// Defaulting to the config rather than a hard-coded path means the key cannot land
/// somewhere the node will not read it, and the operator never has to restate the path.
///
/// # Errors
///
/// Errors when neither is available, naming both ways to fix it.
pub(crate) fn resolve_target(config: &ServiceConfig, file: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = file {
        return Ok(path.to_path_buf());
    }
    if let Some(first) = config.keys.identities.first() {
        return Ok(first.clone());
    }
    bail!(
        "no target for the node identity: pass `--file <PATH>`, or set `[keys].identities` \
         in the config. Its first entry is the published recipient, and is where \
         `identity init` writes."
    )
}

/// Whether `data_dir` already holds at least one published dataset, meaning an immediate
/// `<data_dir>/<id>/manifest.json`, the same post-atomic-rename marker the reload walk
/// ([`gdi_node_standalone_core::cache`]) treats as a committed dataset.
///
/// Best effort and non-fatal: an unreadable or absent `data_dir` reads as no datasets, so
/// this can only add a warning, never block minting.
pub(crate) fn data_dir_has_published_datasets(data_dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(data_dir) else {
        return false;
    };
    entries
        .flatten()
        .any(|entry| entry.path().join("manifest.json").is_file())
}

/// Warn on stderr when a fresh identity is minted onto a `data_dir` that already holds
/// published datasets.
///
/// That is the shape of an ephemeral-secrets loss: an in-memory dev `OpenBao` is wiped by a
/// restart, the node loses its identity, and the operator mints a new one over surviving
/// data, leaving the old identity's PME-at-rest parquet unreadable. Minting onto an empty
/// volume stays silent, and the warning is skipped when `--from` imports a specific key.
pub(crate) fn warn_if_datasets_predate_new_identity(data_dir: &Path) {
    if data_dir_has_published_datasets(data_dir) {
        eprintln!(
            "warning: minting a new node identity, but published datasets already exist \
             under {}. If the previous identity was lost, PME-at-rest data under those \
             datasets stays encrypted to the old key and is unreadable. Proceed only if \
             this is a new node; otherwise restore the previous identity first.",
            data_dir.display()
        );
    }
}

/// The recipient (public key) written beside the secret: `<target>.pub`.
fn recipient_path(target: &Path) -> PathBuf {
    let mut name = target.as_os_str().to_owned();
    name.push(".pub");
    PathBuf::from(name)
}

/// Preserve the identity `--force` is about to replace, at [`backup_path`].
///
/// Reads, then calls [`write_secret_durable`], rather than `fs::copy`. The bytes are the
/// node's private crypt4gh key, and `fs::copy` is wrong for them twice over: it opens the
/// destination `O_WRONLY|O_CREAT|O_TRUNC`, which follows a symlink at `backup` and lets a
/// pre-planted link steer an unrecoverable secret to an attacker-chosen path, and it carries
/// the source's mode rather than choosing one, which can leave a 0644 `.bak` of
/// credential-bearing bytes. `write_secret_durable` writes 0600 atomically through the same
/// chokepoint every other secret write uses, and `clippy.toml` bans `std::fs::copy` so the
/// next such site cannot repeat this.
///
/// # Errors
///
/// Fails if a backup already exists, since one is never overwritten, or if the read or the
/// durable write fails.
///
/// [`write_secret_durable`]: gdi_node_standalone_core::util::write_secret_durable
fn back_up_replaced_identity(target: &Path) -> Result<()> {
    let backup = backup_path(target);
    // Never overwrite an existing backup. The stamp is nanosecond-resolution, so a
    // collision is not expected, but what is being preserved is unrecoverable, so a
    // collision must stop the operation rather than consume the copy it would replace.
    if backup.exists() {
        anyhow::bail!(
            "a backup already exists at {}; refusing to overwrite it; move it aside first",
            backup.display()
        );
    }
    // The private key passes through this process only to be copied, so hold it in a wiping
    // buffer like every other site that reads it and it does not outlive the copy.
    let key_bytes = Zeroizing::new(std::fs::read(target).with_context(|| {
        format!(
            "reading the identity at {} to back it up; refusing to destroy it",
            target.display()
        )
    })?);
    gdi_node_standalone_core::util::write_secret_durable(&backup, &key_bytes).with_context(
        || {
            format!(
                "backing the replaced identity up to {}; refusing to destroy it",
                backup.display()
            )
        },
    )?;
    eprintln!(
        "the replaced identity was backed up to {}; anything wrapped to it can be read \
         with NO other key; keep it until every package has been re-keyed",
        backup.display()
    );
    Ok(())
}

/// Where a `--force`-replaced key is preserved: `<target>.bak-<epoch_nanos>`.
///
/// The stamp is nanoseconds rather than seconds. The node identity is not reconstructible,
/// and at seconds resolution two `--force` runs inside the same second resolve to the same
/// backup path, so the second run would overwrite the first run's backup with the key the
/// first run installed, leaving the original key in neither the live path nor a backup.
fn backup_path(target: &Path) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let mut name = target.as_os_str().to_owned();
    name.push(format!(".bak-{stamp}"));
    PathBuf::from(name)
}

/// Print the recipient PEM followed by its fingerprint. The fingerprint is best effort: a
/// recipient PEM that does not re-parse still prints, without the fingerprint line.
fn print_recipient(recipient_pem: &str) {
    println!("node recipient:");
    print!("{recipient_pem}");
    if let Ok(public_key) = parse_public_key(recipient_pem) {
        println!(
            "recipient fingerprint: {}",
            public_key_fingerprint(&public_key)
        );
    }
}

/// Print the recipient of an already-provisioned identity, on the `--ensure` path. Best
/// effort: a re-run must not fail because the existing key is unreadable here, since the
/// node's loader is the authority on that.
fn print_existing_recipient(target: &Path) {
    let Ok(pem) = std::fs::read_to_string(target).map(Zeroizing::new) else {
        return;
    };
    let Ok(secret_key) = parse_secret_key(&pem) else {
        return;
    };
    print_recipient(&serialize_public_key(&secret_key.public_key()));
}

#[cfg(test)]
mod tests {

    /// Two backups taken in quick succession must not collide.
    ///
    /// At seconds resolution two `--force` runs in the same second produce the same path,
    /// and the second overwrites the original key's backup with the key the first run
    /// installed. That key is the one file on the node that re-ingest cannot rebuild.
    #[test]
    fn successive_identity_backups_do_not_collide() {
        let target = std::path::Path::new("/tmp/node.key");
        let a = backup_path(target);
        let b = backup_path(target);
        assert_ne!(a, b, "two backups in the same second must not share a path");
    }
    use super::*;

    /// A config whose `[keys].identities` names `path` as the published recipient.
    fn config_with_identity(path: &Path) -> ServiceConfig {
        let mut config = ServiceConfig::default();
        config.keys.identities = vec![path.to_path_buf()];
        config
    }

    fn read(path: &Path) -> String {
        std::fs::read_to_string(path).expect("read key")
    }

    #[test]
    fn mints_an_unencrypted_key_and_its_recipient() {
        let tmp = tempfile::tempdir().expect("tmp");
        let key = tmp.path().join("node.c4gh");
        let config = config_with_identity(&key);

        run(&config, false, false, None, None).expect("mint");

        let pem = read(&key);
        parse_secret_key(&pem).expect("the minted key must be an unencrypted crypt4gh key");
        let pub_pem = read(&key.with_extension("c4gh.pub"));
        parse_public_key(&pub_pem).expect("the recipient must be a crypt4gh public key");
    }

    #[cfg(unix)]
    #[test]
    fn minted_key_is_not_group_or_world_readable() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().expect("tmp");
        let key = tmp.path().join("node.c4gh");
        run(&config_with_identity(&key), false, false, None, None).expect("mint");

        let mode = std::fs::metadata(&key).expect("stat").permissions().mode();
        assert_eq!(
            mode & 0o077,
            0,
            "the node identity must not be group/world readable (the loader refuses it \
             under strict_key_perms); got {mode:o}"
        );
    }

    /// The predicate behind the "minting over surviving data" warning: a
    /// `<data_dir>/<id>/manifest.json` means a dataset published here, so minting a new node
    /// identity over it is flagged. An empty or manifest-less volume must not trip it, or
    /// the warning would fire on every first-run install and be tuned out.
    #[test]
    fn published_datasets_are_detected_but_an_empty_volume_is_not() {
        let tmp = tempfile::tempdir().expect("tmp");
        let data_dir = tmp.path();

        assert!(
            !data_dir_has_published_datasets(data_dir),
            "an empty data_dir is a fresh node — no warning"
        );

        // A partial dir with no `manifest.json` is not a published dataset.
        std::fs::create_dir(data_dir.join("scratch")).expect("mkdir");
        assert!(
            !data_dir_has_published_datasets(data_dir),
            "a dir without manifest.json is not a published dataset"
        );

        // The post-atomic-rename marker: a subdir carrying a manifest.json.
        std::fs::create_dir(data_dir.join("ds-1")).expect("mkdir");
        std::fs::write(data_dir.join("ds-1").join("manifest.json"), b"{}").expect("write");
        assert!(
            data_dir_has_published_datasets(data_dir),
            "a <id>/manifest.json means a dataset committed here — must be detected"
        );
    }

    #[test]
    fn refuses_to_overwrite_an_existing_identity() {
        let tmp = tempfile::tempdir().expect("tmp");
        let key = tmp.path().join("node.c4gh");
        let config = config_with_identity(&key);
        run(&config, false, false, None, None).expect("mint");
        let original = read(&key);

        let err = run(&config, false, false, None, None)
            .expect_err("a second init must not silently replace the one irreplaceable secret");
        assert!(
            format!("{err:#}").contains("--force"),
            "the refusal must name the way out; got: {err:#}"
        );
        assert_eq!(read(&key), original, "the existing key must be untouched");
    }

    #[test]
    fn ensure_is_an_idempotent_no_op() {
        let tmp = tempfile::tempdir().expect("tmp");
        let key = tmp.path().join("node.c4gh");
        let config = config_with_identity(&key);
        run(&config, false, false, None, None).expect("mint");
        let original = read(&key);

        run(&config, true, false, None, None).expect("--ensure re-run must succeed");
        assert_eq!(
            read(&key),
            original,
            "--ensure must keep the provisioned key, not re-mint it"
        );
    }

    #[test]
    fn force_replaces_the_key_but_backs_the_old_one_up() {
        let tmp = tempfile::tempdir().expect("tmp");
        let key = tmp.path().join("node.c4gh");
        let config = config_with_identity(&key);
        run(&config, false, false, None, None).expect("mint");
        let original = read(&key);

        run(&config, false, true, None, None).expect("--force must replace");
        assert_ne!(read(&key), original, "--force must mint a new key");

        let backup = std::fs::read_dir(tmp.path())
            .expect("readdir")
            .filter_map(std::result::Result::ok)
            .find(|e| e.file_name().to_string_lossy().contains(".bak-"))
            .expect("--force must preserve the replaced key: losing it loses every dataset");
        assert_eq!(
            std::fs::read_to_string(backup.path()).expect("read backup"),
            original
        );
    }

    #[test]
    fn target_defaults_to_the_first_configured_identity() {
        let tmp = tempfile::tempdir().expect("tmp");
        let first = tmp.path().join("recipient.c4gh");
        let mut config = config_with_identity(&first);
        config.keys.identities.push(tmp.path().join("older.c4gh"));

        let target = resolve_target(&config, None).expect("resolve");
        assert_eq!(
            target, first,
            "the key must land where the node will actually READ it — the first \
             [keys].identities entry (the published recipient)"
        );
    }

    #[test]
    fn explicit_file_overrides_the_configured_identity() {
        let tmp = tempfile::tempdir().expect("tmp");
        let configured = tmp.path().join("configured.c4gh");
        let explicit = tmp.path().join("explicit.c4gh");
        let config = config_with_identity(&configured);

        let target = resolve_target(&config, Some(&explicit)).expect("resolve");
        assert_eq!(target, explicit);
    }

    #[test]
    fn without_a_target_the_error_names_both_ways_to_fix_it() {
        let config = ServiceConfig::default(); // no [keys], no --file
        let err = resolve_target(&config, None).expect_err("no target is an error");
        let msg = format!("{err:#}");
        assert!(msg.contains("--file"), "must name --file; got: {msg}");
        assert!(
            msg.contains("[keys]") || msg.contains("identities"),
            "must name the config field; got: {msg}"
        );
    }

    #[test]
    fn from_imports_an_existing_key_instead_of_minting() {
        let tmp = tempfile::tempdir().expect("tmp");
        let source = tmp.path().join("existing.c4gh");
        let (sk, _pk) = generate_keypair();
        std::fs::write(&source, serialize_secret_key(&sk)).expect("write source");

        let key = tmp.path().join("node.c4gh");
        run(
            &config_with_identity(&key),
            false,
            false,
            Some(&source),
            None,
        )
        .expect("import");

        assert_eq!(
            read(&key),
            read(&source),
            "--from must install the supplied key, not a freshly minted one"
        );
    }

    #[test]
    fn from_rejects_a_key_the_node_could_not_load() {
        let tmp = tempfile::tempdir().expect("tmp");
        let source = tmp.path().join("garbage.c4gh");
        std::fs::write(&source, "not a crypt4gh key").expect("write source");
        let key = tmp.path().join("node.c4gh");

        run(
            &config_with_identity(&key),
            false,
            false,
            Some(&source),
            None,
        )
        .expect_err("importing a key the loader would reject must fail here, not at boot");
        assert!(
            !key.exists(),
            "a rejected import must not leave a broken identity behind"
        );
    }
}
