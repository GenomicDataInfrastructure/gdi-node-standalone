//! End-to-end tests for `gdi-dataset-tool unpack`.
//!
//! `unpack` decrypts a `.tar.c4gh` with the provider identity, safe-extracts it
//! to an arbitrary directory, and re-validates the result. The provider keypair
//! is auto-generated under `$GDI_CONFIG_DIR` (process-global), so the tests are
//! `#[serial]`.
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::fs;
use std::path::{Path, PathBuf};

use clap::Parser as _;
use gdi_dataset_tool::cli::Cli;
use gdi_node_standalone_core::crypt4gh::{SecretKey, generate_keypair, serialize_public_key};
use gdi_node_standalone_core::validate_parquet::{ParquetCaps, validate_parquet_dir};
use serial_test::serial;

fn write_node_recipient(dir: &Path) -> PathBuf {
    let (_sk, pk): (SecretKey, _) = generate_keypair();
    let recipient = dir.join("node.c4gh.pub");
    fs::write(&recipient, serialize_public_key(&pk)).unwrap();
    recipient
}

/// Package the COVID dataset to `out`, encrypted to (node, provider-own).
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
fn unpack_extracts_and_revalidates() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("config"));

    let pkg = tmp.path().join("pkg.tar.c4gh");
    package_covid(tmp.path(), &pkg);

    let out = tmp.path().join("unpacked");
    let cli = Cli::try_parse_from([
        "gdi-dataset-tool",
        "unpack",
        pkg.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
    ])
    .unwrap();
    gdi_dataset_tool::run(cli).expect("unpack succeeds");

    // manifest.json + at least one parquet were extracted.
    assert!(
        out.join("manifest.json").is_file(),
        "manifest.json extracted"
    );
    let parquet_present = fs::read_dir(&out).unwrap().filter_map(Result::ok).any(|e| {
        let n = e.file_name();
        let n = n.to_string_lossy();
        n.starts_with("allele-freq.") && n.ends_with(".parquet")
    });
    assert!(parquet_present, "a parquet payload was extracted");

    // The extracted directory re-validates as parquet.
    validate_parquet_dir(&out, &ParquetCaps::default()).expect("extracted parquet is valid");
}

#[test]
#[serial(env)]
fn unpack_refuses_non_empty_output_without_force() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("config"));

    let pkg = tmp.path().join("pkg.tar.c4gh");
    package_covid(tmp.path(), &pkg);

    let out = tmp.path().join("unpacked");
    fs::create_dir_all(&out).unwrap();
    fs::write(out.join("existing"), b"x").unwrap();

    let cli = Cli::try_parse_from([
        "gdi-dataset-tool",
        "unpack",
        pkg.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
    ])
    .unwrap();
    let err = gdi_dataset_tool::run(cli).expect_err("non-empty output without --force fails");
    assert_eq!(err.exit_code, 1);
    assert!(err.message.contains("not empty"), "msg: {}", err.message);
}
