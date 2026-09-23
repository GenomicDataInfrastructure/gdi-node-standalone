//! Credentials `wizard setup` stores are seen by a later, separate process.
//!
//! `tool-secrets.toml` is the only way they get there, and an in-process test can't catch a
//! break in that hand-off, so this runs the real binary.

#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::path::Path;
use std::process::Command;

use gdi_node_standalone_core::config::{SECRETS_FILE, set_s3_credentials};

/// `profiles --format json` for `config` in a new process, without inherited `GDI_TOOL__`
/// variables and with an empty config dir.
fn profiles_json(config: &Path, config_dir: &Path) -> (serde_json::Value, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_gdi-dataset-tool"));
    cmd.args([
        "--config",
        config.to_str().unwrap(),
        "profiles",
        "--format",
        "json",
    ])
    .env("GDI_CONFIG_DIR", config_dir);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("GDI_TOOL__") {
            cmd.env_remove(key);
        }
    }
    let out = cmd.output().expect("spawn gdi-dataset-tool");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(out.status.success(), "profiles failed: {stderr}");
    (serde_json::from_str(&stdout).unwrap(), stdout + &stderr)
}

/// The `default` profile's two credential tokens (`set` / `unset`).
fn credential_tokens(json: &serde_json::Value) -> (String, String) {
    let profile = json["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "default")
        .unwrap();
    let token = |key: &str| profile["s3"][key].as_str().unwrap().to_owned();
    (token("access_key_id"), token("secret_access_key"))
}

#[test]
fn a_later_process_reads_the_stored_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let config_dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("tool.toml");
    std::fs::write(
        &config,
        "[profiles.default.s3]\nbucket = \"gdi-datasets\"\nendpoint = \"https://s3.example.org\"\n",
    )
    .unwrap();

    // Control: no credentials file, no credentials, so the check below can fail.
    let (before, _) = profiles_json(&config, config_dir.path());
    assert_eq!(credential_tokens(&before), ("unset".into(), "unset".into()));

    // What setup writes, beside the config it saved.
    set_s3_credentials(
        &dir.path().join(SECRETS_FILE),
        "default",
        "AKIAEXAMPLEKEY",
        "not-a-real-secret-value",
    )
    .unwrap();

    let (after, printed) = profiles_json(&config, config_dir.path());
    assert_eq!(
        credential_tokens(&after),
        ("set".into(), "set".into()),
        "a separate process reads tool-secrets.toml on its own"
    );
    assert!(
        !printed.contains("AKIAEXAMPLEKEY") && !printed.contains("not-a-real-secret-value"),
        "no credential is ever printed: {printed}"
    );
}
