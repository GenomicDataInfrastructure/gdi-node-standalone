//! End-to-end: `lint` accepts a `.tar.c4gh` package (decrypt + extract), not just a built
//! staging directory, so it can run on the artifact left after `package` deletes the
//! staging directory.
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use clap::Parser as _;
use gdi_dataset_tool::cli::Cli;
use gdi_node_standalone_core::crypt4gh::{generate_keypair, serialize_public_key};
use serial_test::serial;

#[test]
#[serial(env)]
fn lint_accepts_a_tar_c4gh_package() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("config"));

    // A node recipient to encrypt the package to (the provider-own recipient is added
    // automatically and is what `lint` decrypts with).
    let (_node_sk, node_pk) = generate_keypair();
    let recipient = tmp.path().join("node.pub");
    std::fs::write(&recipient, serialize_public_key(&node_pk)).unwrap();

    // `package` the fixture into a `.tar.c4gh` (which also deletes the staging directory).
    let out = tmp.path().join("pkg.tar.c4gh");
    let package = test_util::write_covid_package(&tmp.path().join("covid-pkg"));
    let cli = Cli::try_parse_from([
        "gdi-dataset-tool",
        "package",
        package.to_str().unwrap(),
        "--cc",
        "EE",
        "--build-out",
        tmp.path().join("build").to_str().unwrap(),
        "--recipient",
        recipient.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
    ])
    .unwrap();
    gdi_dataset_tool::run(cli).expect("package succeeds");
    assert!(out.is_file(), "the packaged .tar.c4gh must exist");

    // `lint` the package: the `is_file()` decrypt-and-extract path, not a directory.
    let cli = Cli::try_parse_from(["gdi-dataset-tool", "lint", out.to_str().unwrap()]).unwrap();
    gdi_dataset_tool::run(cli).expect("lint accepts a .tar.c4gh package");
}

#[test]
#[serial(env)]
fn lint_rejects_a_non_package_file() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("config"));

    // A plain file that is neither a staging directory nor a `.tar.c4gh`: the magic sniff
    // must reject it with a clear message rather than an opaque "decrypt failed".
    let bogus = tmp.path().join("notes.txt");
    std::fs::write(&bogus, b"this is not a crypt4gh package").unwrap();
    let cli = Cli::try_parse_from(["gdi-dataset-tool", "lint", bogus.to_str().unwrap()]).unwrap();
    let err = gdi_dataset_tool::run(cli).expect_err("a non-package file must fail");
    assert_eq!(err.exit_code, 1);
    assert!(
        err.message.contains("not a .tar.c4gh package"),
        "must name the wrong input type: {}",
        err.message
    );
}
