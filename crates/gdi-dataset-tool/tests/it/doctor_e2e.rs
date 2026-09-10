//! Integration tests for `doctor`: a valid profile + reachable stub is all-green;
//! a broken recipient or an unreachable node surfaces the specific failure. Doctor
//! is read-only — it creates nothing (no S3 writes here; offline path).
//!
//! The provider identity lives under `$GDI_CONFIG_DIR` (process-global), so the
//! tests that set it are `#[serial]`.

#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::fs;
use std::path::Path;

use clap::Parser as _;
use gdi_dataset_tool::cli::DoctorArgs;
use gdi_node_standalone_core::crypt4gh::{generate_keypair, serialize_public_key};
use serial_test::serial;

/// Generate a provider identity under `dir` (so `doctor`'s read-only load passes),
/// returning the guard that keeps `GDI_CONFIG_DIR` pointed at it.
///
/// The guard is returned rather than held here: dropping it at the end of this helper
/// would restore the variable before the caller ever ran `doctor`. Callers must bind it
/// (`let _config_dir = ...`) for the life of the test, which also makes the restore
/// survive a failing assertion. `EnvGuard` is itself `#[must_use]`, so a discarded return
/// already warns; repeating the attribute here is `clippy::double_must_use`.
fn make_provider_identity(dir: &Path) -> test_util::EnvGuard {
    let guard = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir);
    let cli = gdi_dataset_tool::cli::Cli::try_parse_from(["gdi-dataset-tool", "keys", "generate"])
        .unwrap();
    gdi_dataset_tool::run(cli).expect("keys generate");
    guard
}

/// Write a valid crypt4gh node recipient file, returning its path.
fn make_node_recipient(dir: &Path) -> std::path::PathBuf {
    let (_sk, pk) = generate_keypair();
    let path = dir.join("node.c4gh.pub");
    fs::write(&path, serialize_public_key(&pk)).unwrap();
    path
}

#[test]
#[serial(env)]
fn offline_valid_profile_is_all_green() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = make_provider_identity(tmp.path());
    let recipient = make_node_recipient(tmp.path());

    // A profile config: an offline recipient file + a catalogs allow-list, no URL.
    let cfg = tmp.path().join("tool.toml");
    fs::write(
        &cfg,
        format!(
            "[profiles.default]\nnode_recipient_file = \"{}\"\n\n[profiles.default.catalogs]\nsynthetic-data = \"Synthetic\"\n",
            recipient.display()
        ),
    )
    .unwrap();

    let args = DoctorArgs {
        offline: true,
        recipient: None,
        format: gdi_dataset_tool::cli::OutputFormat::Text,
    };
    gdi_dataset_tool::commands::cmd_doctor::run(&args, None, Some(&cfg))
        .expect("doctor offline all-green");
}

/// `doctor` must not certify a provider key that is readable beyond its owner.
///
/// The shared read path warns on stderr and hands the key back, which is right for the
/// working verbs. `doctor` is different: it exists to certify the setup, its `--format
/// json` report has no warning rung at all, and the node fails closed on exactly this
/// condition (`strict_key_perms`). Reporting `ok` would answer "is this machine set up
/// correctly?" with yes about a key any local user can read.
#[cfg(unix)]
#[test]
#[serial(env)]
fn offline_world_readable_provider_key_fails() {
    use std::os::unix::fs::PermissionsExt as _;

    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = make_provider_identity(tmp.path());
    let recipient = make_node_recipient(tmp.path());

    // Everything else is the all-green fixture above; the only difference is the mode.
    let key = tmp.path().join("keys").join("provider.c4gh");
    assert!(
        key.is_file(),
        "the fixture must have minted {}",
        key.display()
    );
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();

    let cfg = tmp.path().join("tool.toml");
    fs::write(
        &cfg,
        format!(
            "[profiles.default]\nnode_recipient_file = \"{}\"\n\n[profiles.default.catalogs]\nsynthetic-data = \"Synthetic\"\n",
            recipient.display()
        ),
    )
    .unwrap();

    let args = DoctorArgs {
        offline: true,
        recipient: None,
        format: gdi_dataset_tool::cli::OutputFormat::Text,
    };
    let err = gdi_dataset_tool::commands::cmd_doctor::run(&args, None, Some(&cfg))
        .expect_err("a 0644 provider key must not be certified");

    assert!(
        err.message.contains("provider-identity"),
        "the failure must name the check that failed; got: {}",
        err.message
    );
    assert_eq!(
        err.exit_code,
        gdi_dataset_tool::EXIT_USER,
        "a fixable local mode bit is a user error; got {}: {}",
        err.exit_code,
        err.message
    );
}

#[test]
#[serial(env)]
fn offline_broken_recipient_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = make_provider_identity(tmp.path());

    // A recipient file with garbage content.
    let bad = tmp.path().join("bad.pub");
    fs::write(&bad, "this is not a crypt4gh recipient").unwrap();
    let cfg = tmp.path().join("tool.toml");
    fs::write(
        &cfg,
        format!(
            "[profiles.default]\nnode_recipient_file = \"{}\"\n\n[profiles.default.catalogs]\nc = \"C\"\n",
            bad.display()
        ),
    )
    .unwrap();

    let args = DoctorArgs {
        offline: true,
        recipient: None,
        format: gdi_dataset_tool::cli::OutputFormat::Text,
    };
    let err = gdi_dataset_tool::commands::cmd_doctor::run(&args, None, Some(&cfg)).unwrap_err();
    assert!(
        err.message.contains("node-recipient"),
        "names the failing check: {}",
        err.message
    );
}

#[test]
#[serial(env)]
fn online_unreachable_node_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = make_provider_identity(tmp.path());
    let recipient = make_node_recipient(tmp.path());

    // A service_url pointing at a dead port -> the online FDP / recipient checks fail.
    let cfg = tmp.path().join("tool.toml");
    fs::write(
        &cfg,
        format!(
            "[profiles.default]\nservice_url = \"http://127.0.0.1:1\"\nnode_recipient_file = \"{}\"\n",
            recipient.display()
        ),
    )
    .unwrap();

    let args = DoctorArgs {
        offline: false,
        recipient: None,
        format: gdi_dataset_tool::cli::OutputFormat::Text,
    };
    let err = gdi_dataset_tool::commands::cmd_doctor::run(&args, None, Some(&cfg)).unwrap_err();
    assert!(
        err.message.contains("fdp-root") || err.message.contains("node-recipient"),
        "names a failing online check: {}",
        err.message
    );
}

#[test]
#[serial(env)]
fn missing_provider_identity_fails_readonly() {
    // A config dir with no provider identity: doctor must report it (and not create
    // one — read-only).
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path());
    let recipient = make_node_recipient(tmp.path());
    let cfg = tmp.path().join("tool.toml");
    fs::write(
        &cfg,
        format!(
            "[profiles.default]\nnode_recipient_file = \"{}\"\n\n[profiles.default.catalogs]\nc = \"C\"\n",
            recipient.display()
        ),
    )
    .unwrap();

    let args = DoctorArgs {
        offline: true,
        recipient: None,
        format: gdi_dataset_tool::cli::OutputFormat::Text,
    };
    let err = gdi_dataset_tool::commands::cmd_doctor::run(&args, None, Some(&cfg)).unwrap_err();
    assert!(
        err.message.contains("provider-identity"),
        "names the failing check: {}",
        err.message
    );
    // Read-only: doctor must not have generated the identity.
    assert!(
        !tmp.path().join("keys/provider.c4gh").exists(),
        "doctor must not create the provider identity"
    );
}
