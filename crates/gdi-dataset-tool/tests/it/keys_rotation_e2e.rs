//! End-to-end tests for provider key rotation via `[keys].identities`.
//!
//! Covers: the implicit single-identity default (empty/absent `[keys]`), primary
//! auto-generation, and multi-identity decryption — a package encrypted to a
//! now-retired identity (a non-primary entry in the list) still decrypts because
//! every configured identity is tried in order.
//!
//! These exercise the CLI-independent `cmd_keys` / `pkgio` library functions
//! directly. The default-resolution path honours `--config` (the config-file
//! dir), so no process-global `$GDI_CONFIG_DIR` is needed and the tests need not
//! be `#[serial]`.
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::fs;
use std::io::Cursor;
use std::path::Path;

use gdi_node_standalone_core::crypt4gh::{
    SecretKey, encrypt, generate_keypair, serialize_public_key, serialize_secret_key,
};

/// Write a TOML config at `dir/tool.toml` with the given body, returning its path.
fn write_config(dir: &Path, body: &str) -> std::path::PathBuf {
    let cfg = dir.join("tool.toml");
    fs::write(&cfg, body).unwrap();
    cfg
}

/// Write a crypt4gh secret-key file (0o600 not required for the test) at `path`.
fn write_secret(path: &Path, sk: &SecretKey) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, serialize_secret_key(sk)).unwrap();
}

/// crypt4gh-encrypt `plaintext` to `recipient` (with an ephemeral sender) into a
/// `.tar.c4gh`-shaped file at `out`.
fn encrypt_to(
    out: &Path,
    plaintext: &[u8],
    recipient: &gdi_node_standalone_core::crypt4gh::PublicKey,
) {
    let (sender_sk, _sender_pk) = generate_keypair();
    let mut writer = fs::File::create(out).unwrap();
    encrypt(
        &mut Cursor::new(plaintext),
        &mut writer,
        std::slice::from_ref(recipient),
        &sender_sk,
    )
    .unwrap();
}

#[test]
fn empty_keys_defaults_to_single_provider_identity() {
    // No [keys] section: the primary identity resolves to <config_dir>/keys/provider.c4gh
    // and is auto-generated on first use.
    let tmp = tempfile::tempdir().unwrap();
    let cfg = write_config(tmp.path(), "");

    let sk =
        gdi_dataset_tool::commands::cmd_keys::load_or_generate_provider_secret(Some(&cfg)).unwrap();
    let primary = tmp.path().join("keys/provider.c4gh");
    assert!(
        primary.is_file(),
        "default primary identity must be created"
    );

    // The derived recipient matches the loaded secret's public key.
    let recipient = gdi_dataset_tool::commands::cmd_keys::provider_recipient(Some(&cfg)).unwrap();
    assert_eq!(
        serialize_public_key(&recipient),
        serialize_public_key(&sk.public_key())
    );

    // load_all returns exactly the one (auto-generated) identity.
    let all = gdi_dataset_tool::commands::cmd_keys::load_all_provider_secrets(Some(&cfg)).unwrap();
    assert_eq!(all.len(), 1);
}

/// The decrypt path must never mint a key.
///
/// Auto-generating a missing primary can only ever fail: a fresh random keypair cannot
/// decrypt a package wrapped to somebody else's recipient. It would write a secret key into
/// whatever config dir was resolved and then report that "the configured identity" cannot
/// decrypt, naming an identity the tool had just invented. Error instead, and leave the
/// filesystem alone.
#[test]
fn missing_primary_identity_errors_and_writes_nothing() {
    let tmp = tempfile::tempdir().unwrap();

    // The retired (second) identity exists up front; the primary does not.
    let (retired_sk, _retired_pk) = generate_keypair();
    write_secret(&tmp.path().join("keys/retired.c4gh"), &retired_sk);

    let cfg = write_config(
        tmp.path(),
        "[keys]\nidentities = [\"keys/current.c4gh\", \"keys/retired.c4gh\"]\n",
    );

    // `unwrap_err` would require SecretKey: Debug (it is intentionally not), so map Ok to ().
    let Err(err) =
        gdi_dataset_tool::commands::cmd_keys::load_all_provider_secrets(Some(&cfg)).map(|_| ())
    else {
        panic!("a missing primary must be an error on the decrypt path, not a fresh key");
    };
    assert_eq!(err.exit_code, 1);
    assert!(
        err.message.contains("no provider identity at"),
        "must name the identity it wanted: {}",
        err.message
    );
    assert!(
        err.message.contains("config directory"),
        "must name the config-dir trap that causes this: {}",
        err.message
    );

    // The other half of the rule: no key was written as a side effect of a read.
    assert!(
        !tmp.path().join("keys/current.c4gh").exists(),
        "a read-only decrypt path must not mint a secret key"
    );
}

#[test]
fn missing_non_primary_identity_is_an_error() {
    // A configured-but-missing retired identity is a hard error, distinct from a missing
    // primary. The primary must therefore exist here, or this would test the other case;
    // see `missing_primary_identity_errors_and_writes_nothing`.
    let tmp = tempfile::tempdir().unwrap();
    let (current_sk, _current_pk) = generate_keypair();
    write_secret(&tmp.path().join("keys/current.c4gh"), &current_sk);

    let cfg = write_config(
        tmp.path(),
        "[keys]\nidentities = [\"keys/current.c4gh\", \"keys/gone.c4gh\"]\n",
    );
    // `unwrap_err` would require SecretKey: Debug (it is intentionally not), so
    // map the Ok side to () first.
    let Err(err) =
        gdi_dataset_tool::commands::cmd_keys::load_all_provider_secrets(Some(&cfg)).map(|_| ())
    else {
        panic!("a missing retired identity must be an error");
    };
    assert_eq!(err.exit_code, 1);
    assert!(err.message.contains("missing"), "{}", err.message);
}

#[test]
fn package_encrypted_to_retired_identity_still_decrypts() {
    // The rotation scenario: a package was encrypted to a provider recipient that
    // is now retired (the 2nd entry in identities). Decryption tries every
    // identity, so it still decrypts.
    let tmp = tempfile::tempdir().unwrap();

    // The old primary (now retired) and the current primary both exist on disk.
    let (retired_secret, retired_recipient) = generate_keypair();
    let (current_secret, _current_recipient) = generate_keypair();
    write_secret(&tmp.path().join("keys/current.c4gh"), &current_secret);
    write_secret(&tmp.path().join("keys/retired.c4gh"), &retired_secret);

    // Config lists the current key first, the retired key second.
    let cfg = write_config(
        tmp.path(),
        "[keys]\nidentities = [\"keys/current.c4gh\", \"keys/retired.c4gh\"]\n",
    );

    // A package encrypted only to the retired recipient.
    let pkg = tmp.path().join("DS.tar.c4gh");
    let plaintext = b"hello retired identity";
    encrypt_to(&pkg, plaintext, &retired_recipient);

    // decrypt_package_to loads all identities and tries each -> succeeds.
    let tar_out = tmp.path().join("out.tar");
    gdi_dataset_tool::pkgio::decrypt_package_to(&pkg, &tar_out, Some(&cfg))
        .expect("a package encrypted to the retired identity must still decrypt");
    assert_eq!(fs::read(&tar_out).unwrap(), plaintext);

    // Sanity: the current identity alone cannot decrypt it (so the test really
    // exercises the rotation list, not the primary).
    let single = write_config(tmp.path(), "[keys]\nidentities = [\"keys/current.c4gh\"]\n");
    let tar_fail = tmp.path().join("fail.tar");
    let err = gdi_dataset_tool::pkgio::decrypt_package_to(&pkg, &tar_fail, Some(&single))
        .expect_err("the current identity alone must NOT decrypt the retired package");
    assert!(err.message.contains("decrypt"), "{}", err.message);
}

#[test]
fn relative_identities_resolve_against_the_config_dir() {
    // Relative identity paths resolve against the config-file's parent dir.
    let nested = tempfile::tempdir().unwrap();
    let conf_dir = nested.path().join("etc");
    fs::create_dir_all(&conf_dir).unwrap();
    let cfg = write_config(&conf_dir, "[keys]\nidentities = [\"keys/provider.c4gh\"]\n");

    // First use auto-generates it next to the config file, not the cwd.
    gdi_dataset_tool::commands::cmd_keys::load_or_generate_provider_secret(Some(&cfg)).unwrap();
    assert!(
        conf_dir.join("keys/provider.c4gh").is_file(),
        "the identity must land beside the config file"
    );
}
