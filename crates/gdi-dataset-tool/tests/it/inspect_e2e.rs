//! End-to-end tests for `gdi-dataset-tool inspect`.
//!
//! Exercises the CLI-independent library functions (`read_manifest_json`,
//! `list_members`) directly so the assertions inspect returned data rather than
//! captured stdout. The provider keypair is auto-generated under
//! `$GDI_CONFIG_DIR` (process-global), so the tests are `#[serial]`.
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::fs;
use std::path::{Path, PathBuf};

use clap::Parser as _;
use gdi_dataset_tool::cli::Cli;
use gdi_dataset_tool::commands::cmd_inspect::{list_members, read_manifest_json};
use gdi_node_standalone_core::crypt4gh::{SecretKey, generate_keypair, serialize_public_key};
use gdi_node_standalone_core::model::Manifest;
use serial_test::serial;

fn write_node_recipient(dir: &Path) -> PathBuf {
    let (_sk, pk): (SecretKey, _) = generate_keypair();
    let recipient = dir.join("node.c4gh.pub");
    fs::write(&recipient, serialize_public_key(&pk)).unwrap();
    recipient
}

fn package_covid(tmp: &Path, out: &Path) {
    let recipient = write_node_recipient(tmp);
    let package = test_util::write_covid_package(&tmp.join("covid-pkg"));
    let cli = Cli::try_parse_from([
        "gdi-dataset-tool",
        "package",
        package.to_str().unwrap(),
        "--cc",
        "EE",
        "--build-out",
        tmp.join("build").to_str().unwrap(),
        "--recipient",
        recipient.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
    ])
    .unwrap();
    gdi_dataset_tool::run(cli).expect("package succeeds");
}

#[test]
#[serial(env)]
fn inspect_manifest_prints_valid_json() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("config"));
    let pkg = tmp.path().join("pkg.tar.c4gh");
    package_covid(tmp.path(), &pkg);

    let json = read_manifest_json(&pkg, None).expect("manifest reads");
    let manifest: Manifest = serde_json::from_str(&json).expect("manifest is valid JSON");
    assert!(
        manifest.metadata.dataset_id.starts_with("GDI-EE-UTARTU-"),
        "datasetId carried, got {}",
        manifest.metadata.dataset_id
    );
    assert_eq!(manifest.config.assembly.reference, "GRCh38");

    // The CLI path also succeeds end-to-end (prints to stdout).
    let cli = Cli::try_parse_from([
        "gdi-dataset-tool",
        "inspect",
        pkg.to_str().unwrap(),
        "--manifest",
    ])
    .unwrap();
    gdi_dataset_tool::run(cli).expect("inspect --manifest succeeds");
}

#[test]
#[serial(env)]
fn inspect_files_lists_members_with_sizes() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("config"));
    let pkg = tmp.path().join("pkg.tar.c4gh");
    package_covid(tmp.path(), &pkg);

    let members = list_members(&pkg, None).expect("members list");
    assert!(!members.is_empty(), "package has members");

    // manifest.json is present and is the first member (metadata prefix order).
    assert_eq!(
        members.first().map(|m| m.name.as_str()),
        Some("manifest.json"),
        "manifest.json is first; got {members:?}"
    );
    // Every member has a non-zero recorded size, and at least one parquet.
    assert!(members.iter().all(|m| m.size > 0), "sizes recorded");
    assert!(
        members
            .iter()
            .any(|m| m.name.starts_with("allele-freq.") && m.name.ends_with(".parquet")),
        "a parquet payload member is listed; got {members:?}"
    );

    // The CLI path for the default structure view and --files succeeds.
    for extra in [vec![], vec!["--files", "--order", "size-desc"]] {
        let mut argv = vec!["gdi-dataset-tool", "inspect", pkg.to_str().unwrap()];
        argv.extend(extra);
        let cli = Cli::try_parse_from(argv).unwrap();
        gdi_dataset_tool::run(cli).expect("inspect succeeds");
    }
}
