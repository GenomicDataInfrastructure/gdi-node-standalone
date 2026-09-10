//! End-to-end tests for `gdi-dataset-tool` `pack` and `package`.
//!
//! These build/package a dataset, then decrypt the produced `.tar.c4gh` with the node
//! secret (via the core crypt4gh codec) and untar it to assert the member order
//! `docs/package-format.md` specifies, plus a valid payload.
//!
//! The provider keypair is auto-generated under `$GDI_CONFIG_DIR`; that env var
//! is process-global, so every test here is `#[serial]`.
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use clap::Parser as _;
use gdi_dataset_tool::cli::Cli;
use gdi_node_standalone_core::crypt4gh::{
    SecretKey, decrypt, generate_keypair, serialize_public_key,
};
use gdi_node_standalone_core::validate_parquet::{ParquetCaps, validate_parquet_dir};
use serial_test::serial;

/// Write a fresh node keypair into `dir`, returning (`recipient_file`, secret).
fn write_node_keypair(dir: &Path) -> (PathBuf, SecretKey) {
    let (sk, pk) = generate_keypair();
    let recipient = dir.join("node.c4gh.pub");
    fs::write(&recipient, serialize_public_key(&pk)).unwrap();
    (recipient, sk)
}

/// Decrypt `package` with `identity` and return the plaintext TAR bytes.
fn decrypt_package(package: &Path, identity: &SecretKey) -> Vec<u8> {
    let encrypted = fs::read(package).unwrap();
    let mut tar_bytes = Vec::new();
    decrypt(
        &mut Cursor::new(&encrypted),
        &mut tar_bytes,
        std::slice::from_ref(identity),
    )
    .expect("node identity decrypts the package");
    tar_bytes
}

/// Return the TAR member names in order, and extract them into `dest`.
fn untar_into(tar_bytes: &[u8], dest: &Path) -> Vec<String> {
    let mut archive = tar::Archive::new(Cursor::new(tar_bytes));
    let mut names = Vec::new();
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap().into_owned();
        names.push(path.to_string_lossy().into_owned());
        entry.unpack_in(dest).unwrap();
    }
    names
}

/// Build the COVID staging directory under `build_out` and return it. The package is
/// materialized into a sibling `covid-pkg` dir under `build_out`'s parent temp dir.
fn build_covid_staging(build_out: &Path) -> PathBuf {
    let pkg_dir = build_out
        .parent()
        .expect("build_out must have a parent temp dir")
        .join("covid-pkg");
    let cli = Cli::try_parse_from([
        "gdi-dataset-tool",
        "build",
        test_util::write_covid_package(&pkg_dir).to_str().unwrap(),
        "--cc",
        "EE",
        "-o",
        build_out.to_str().unwrap(),
    ])
    .unwrap();
    gdi_dataset_tool::run(cli).expect("build succeeds");
    single_subdir(build_out)
}

#[test]
#[serial(env)]
fn pack_produces_decryptable_ordered_tar_c4gh() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("config"));

    // A node recipient the test controls (so we can decrypt the package).
    let (recipient_file, node_secret) = write_node_keypair(tmp.path());

    // 1. build a staging directory for the COVID dataset.
    let build_out = tmp.path().join("build");
    let staging = build_covid_staging(&build_out);

    // 2. pack --recipient <node.pub> -o <out>.
    let out = tmp.path().join("out.tar.c4gh");
    let cli = Cli::try_parse_from([
        "gdi-dataset-tool",
        "pack",
        staging.to_str().unwrap(),
        "--recipient",
        recipient_file.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
    ])
    .unwrap();
    gdi_dataset_tool::run(cli).expect("pack succeeds");
    assert!(out.is_file(), "the .tar.c4gh must be written");

    // 3. decrypt with the node secret and untar.
    let tar_bytes = decrypt_package(&out, &node_secret);
    let dest = tmp.path().join("extracted");
    fs::create_dir_all(&dest).unwrap();
    let names = untar_into(&tar_bytes, &dest);

    assert_member_order(&names);

    // The provider can also decrypt (its own recipient is the 2nd recipient).
    let provider_secret = load_provider_secret(&tmp.path().join("config"));
    let _ = decrypt_package(&out, &provider_secret);

    // The parquet payload round-trips: it re-validates after extraction.
    validate_parquet_dir(&dest, &ParquetCaps::default()).expect("extracted parquet is valid");
}

#[test]
#[serial(env)]
fn package_builds_and_packs_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("config"));

    let (recipient_file, node_secret) = write_node_keypair(tmp.path());

    let out = tmp.path().join("pkg.tar.c4gh");
    let build_out = tmp.path().join("build");
    let package = test_util::write_covid_package(&tmp.path().join("covid-pkg"));
    let cli = Cli::try_parse_from([
        "gdi-dataset-tool",
        "package",
        package.to_str().unwrap(),
        "--cc",
        "EE",
        "--build-out",
        build_out.to_str().unwrap(),
        "--recipient",
        recipient_file.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
    ])
    .unwrap();
    gdi_dataset_tool::run(cli).expect("package succeeds");
    assert!(out.is_file(), "package must write the .tar.c4gh");

    // Decrypt + untar -> a valid dataset.
    let tar_bytes = decrypt_package(&out, &node_secret);
    let dest = tmp.path().join("extracted");
    fs::create_dir_all(&dest).unwrap();
    let names = untar_into(&tar_bytes, &dest);
    assert_member_order(&names);
    validate_parquet_dir(&dest, &ParquetCaps::default()).expect("extracted parquet is valid");
}

#[test]
#[serial(env)]
fn package_offline_with_local_recipient_and_catalog_allow_list() {
    // The full air-gapped path: build + pack with no network. The node recipient
    // is a local file (--recipient), the catalog is validated against the
    // profile's offline `catalogs` allow-list (no online FDP), and the dataset
    // ID + the provider keypair are generated locally. Nothing here reaches out.
    let tmp = tempfile::tempdir().unwrap();
    // Provider identity (and dataset-ID/key material) live locally under here.
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("config"));

    let (recipient_file, node_secret) = write_node_keypair(tmp.path());

    // A profile config with an offline `catalogs` allow-list that includes the
    // covid fixture's catalog (`gdi-aggregated`) and no service_url, so catalog
    // membership is enforced from the local allow-list rather than an online FDP.
    let cfg = tmp.path().join("tool.toml");
    fs::write(
        &cfg,
        "[profiles.default]\n\n[profiles.default.catalogs]\ngdi-aggregated = \"Genome of Europe Aggregated Data\"\n",
    )
    .unwrap();

    let out = tmp.path().join("pkg.tar.c4gh");
    let build_out = tmp.path().join("build");
    let package = test_util::write_covid_package(&tmp.path().join("covid-pkg"));
    let cli = Cli::try_parse_from([
        "gdi-dataset-tool",
        "--config",
        cfg.to_str().unwrap(),
        "package",
        package.to_str().unwrap(),
        "--cc",
        "EE",
        "--build-out",
        build_out.to_str().unwrap(),
        "--recipient",
        recipient_file.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
        // Keep the staging directory so we can assert the locally-generated ID below;
        // staging cleanup is exercised by `package_deletes_staging_dir_after_success`.
        "--keep",
    ])
    .unwrap();
    gdi_dataset_tool::run(cli).expect("offline package succeeds");
    assert!(out.is_file(), "offline package must write the .tar.c4gh");

    // The dataset ID was generated locally and encodes the prefix/cc/org.
    let staging = single_subdir(&build_out);
    let dataset_id = staging.file_name().unwrap().to_str().unwrap();
    assert!(
        dataset_id.starts_with("GDI-EE-UTARTU-"),
        "dataset ID must be generated locally, got {dataset_id}"
    );

    // The locally-generated node identity decrypts the package -> key gen local.
    let tar_bytes = decrypt_package(&out, &node_secret);
    let dest = tmp.path().join("extracted");
    fs::create_dir_all(&dest).unwrap();
    let names = untar_into(&tar_bytes, &dest);
    assert_member_order(&names);
    validate_parquet_dir(&dest, &ParquetCaps::default()).expect("extracted parquet is valid");
}

#[test]
#[serial(env)]
fn package_offline_rejects_catalog_not_in_allow_list() {
    // The offline allow-list is authoritative when present: a catalog absent from
    // it is rejected at build (no network consulted).
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("config"));
    let (recipient_file, _node_secret) = write_node_keypair(tmp.path());

    // Allow-list that does not contain `gdi-aggregated`.
    let cfg = tmp.path().join("tool.toml");
    fs::write(
        &cfg,
        "[profiles.default]\n\n[profiles.default.catalogs]\nsome-other-catalog = \"Other\"\n",
    )
    .unwrap();

    let out = tmp.path().join("pkg.tar.c4gh");
    let build_out = tmp.path().join("build");
    let package = test_util::write_covid_package(&tmp.path().join("covid-pkg"));
    let cli = Cli::try_parse_from([
        "gdi-dataset-tool",
        "--config",
        cfg.to_str().unwrap(),
        "package",
        package.to_str().unwrap(),
        "--cc",
        "EE",
        "--build-out",
        build_out.to_str().unwrap(),
        "--recipient",
        recipient_file.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
    ])
    .unwrap();
    let err = gdi_dataset_tool::run(cli).expect_err("catalog not in allow-list must fail");
    assert!(
        err.message.contains("gdi-aggregated") || err.message.to_lowercase().contains("catalog"),
        "error should name the unknown catalog, got: {}",
        err.message
    );
    assert!(
        !out.exists(),
        "no package should be written on a rejected catalog"
    );
}

#[test]
#[serial(env)]
fn package_deletes_staging_dir_after_success() {
    // `package` deletes the staging directory after a successful pack, because it holds
    // plaintext genotype-derived intermediates.
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("config"));
    let (recipient_file, _node_secret) = write_node_keypair(tmp.path());

    let out = tmp.path().join("pkg.tar.c4gh");
    let build_out = tmp.path().join("build");
    let package = test_util::write_covid_package(&tmp.path().join("covid-pkg"));
    let cli = Cli::try_parse_from([
        "gdi-dataset-tool",
        "package",
        package.to_str().unwrap(),
        "--cc",
        "EE",
        "--build-out",
        build_out.to_str().unwrap(),
        "--recipient",
        recipient_file.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
    ])
    .unwrap();
    gdi_dataset_tool::run(cli).expect("package succeeds");
    assert!(out.is_file(), "package must write the .tar.c4gh");
    // The staging directory under build_out is gone.
    let staging_present = fs::read_dir(&build_out)
        .is_ok_and(|rd| rd.filter_map(Result::ok).any(|e| e.path().is_dir()));
    assert!(
        !staging_present,
        "package must delete the staging dir after a successful pack"
    );
}

#[test]
#[serial(env)]
fn package_keep_retains_staging_dir() {
    // `--keep` retains the staging directory.
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("config"));
    let (recipient_file, _node_secret) = write_node_keypair(tmp.path());

    let out = tmp.path().join("pkg.tar.c4gh");
    let build_out = tmp.path().join("build");
    let package = test_util::write_covid_package(&tmp.path().join("covid-pkg"));
    let cli = Cli::try_parse_from([
        "gdi-dataset-tool",
        "package",
        package.to_str().unwrap(),
        "--cc",
        "EE",
        "--build-out",
        build_out.to_str().unwrap(),
        "--recipient",
        recipient_file.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
        "--keep",
    ])
    .unwrap();
    gdi_dataset_tool::run(cli).expect("package --keep succeeds");
    assert!(out.is_file(), "package must write the .tar.c4gh");
    // The staging directory under build_out is retained.
    let staging = single_subdir(&build_out);
    assert!(
        staging.join("manifest.json").is_file(),
        "--keep must retain the staging dir (manifest present)"
    );
}

#[test]
#[serial(env)]
fn pack_refuses_existing_output_without_force() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("config"));
    let (recipient_file, _node_secret) = write_node_keypair(tmp.path());

    let build_out = tmp.path().join("build");
    let staging = build_covid_staging(&build_out);

    let out = tmp.path().join("out.tar.c4gh");
    fs::write(&out, b"existing").unwrap();

    let cli = Cli::try_parse_from([
        "gdi-dataset-tool",
        "pack",
        staging.to_str().unwrap(),
        "--recipient",
        recipient_file.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
    ])
    .unwrap();
    let err = gdi_dataset_tool::run(cli).expect_err("existing output without --force fails");
    assert_eq!(err.exit_code, 1);
    assert!(
        err.message.contains("already exists"),
        "msg: {}",
        err.message
    );
}

/// `-o` means different things per subcommand: for `build` it is the staging-dir parent
/// directory, for `pack` it is the package file. Carrying the `build -o build` habit over to
/// `pack` would otherwise yield "output already exists (use --force)", and `--force` cannot
/// help, since a directory is not a package file.
///
/// `resolve_output` makes the habit work: an existing directory means "write the package
/// in here", so `pack -o build` lands `build/{id}.tar.c4gh`. What is pinned is that
/// behaviour, not any particular error message.
#[test]
#[serial(env)]
fn pack_output_pointing_at_a_directory_writes_the_package_inside_it() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("config"));
    let (recipient_file, _node_secret) = write_node_keypair(tmp.path());

    let build_out = tmp.path().join("build");
    let staging = build_covid_staging(&build_out);
    let dataset_id = staging
        .file_name()
        .and_then(|n| n.to_str())
        .expect("staging dir is named for the dataset id")
        .to_owned();

    // Exactly the habit: reuse the `build -o build` directory as `pack -o`.
    let cli = Cli::try_parse_from([
        "gdi-dataset-tool",
        "pack",
        staging.to_str().unwrap(),
        "--recipient",
        recipient_file.to_str().unwrap(),
        "-o",
        build_out.to_str().unwrap(),
    ])
    .unwrap();
    gdi_dataset_tool::run(cli).expect("`-o <dir>` must place the package inside the directory");

    let expected = build_out.join(format!("{dataset_id}.tar.c4gh"));
    assert!(
        expected.is_file(),
        "the package must land at <dir>/{{id}}.tar.c4gh; got: {}",
        expected.display()
    );
}

#[test]
#[serial(env)]
fn pack_uses_node_recipient_file_when_no_url_configured() {
    // Offline path: no service_url / node_recipient_url, only node_recipient_file.
    // pack must resolve the recipient from the file with zero network.
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("config"));
    let (recipient_file, node_secret) = write_node_keypair(tmp.path());

    let cfg = tmp.path().join("tool.toml");
    fs::write(
        &cfg,
        format!(
            "[profiles.default]\nnode_recipient_file = \"{}\"\n",
            recipient_file.display()
        ),
    )
    .unwrap();

    let build_out = tmp.path().join("build");
    let staging = build_covid_staging(&build_out);

    let out = tmp.path().join("out.tar.c4gh");
    let cli = Cli::try_parse_from([
        "gdi-dataset-tool",
        "--config",
        cfg.to_str().unwrap(),
        "pack",
        staging.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
    ])
    .unwrap();
    gdi_dataset_tool::run(cli).expect("pack uses node_recipient_file offline");
    // Decryptable with the node secret -> the file recipient was used.
    let _ = decrypt_package(&out, &node_secret);
}

#[test]
#[serial(env)]
fn pack_recipient_flag_wins_over_configured_url() {
    // `--recipient` is highest precedence: even with a (dead) service_url that
    // would otherwise be fetched, the explicit file wins and no network happens.
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("config"));
    let (recipient_file, node_secret) = write_node_keypair(tmp.path());

    let cfg = tmp.path().join("tool.toml");
    fs::write(
        &cfg,
        "[profiles.default]\nservice_url = \"http://127.0.0.1:1\"\n",
    )
    .unwrap();

    let build_out = tmp.path().join("build");
    let staging = build_covid_staging(&build_out);

    let out = tmp.path().join("out.tar.c4gh");
    let cli = Cli::try_parse_from([
        "gdi-dataset-tool",
        "--config",
        cfg.to_str().unwrap(),
        "pack",
        staging.to_str().unwrap(),
        "--recipient",
        recipient_file.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
    ])
    .unwrap();
    gdi_dataset_tool::run(cli).expect("--recipient wins over a configured URL");
    let _ = decrypt_package(&out, &node_secret);
}

#[test]
#[serial(env)]
fn pack_falls_back_to_the_configured_pin_when_the_url_is_dead() {
    // When node_recipient_url (here via service_url) is configured, pack fetches it
    // online first — but a fetch failure with a configured `node_recipient_file` pin
    // falls back to the pin (with a warning) instead of erroring: the pin is what a
    // successful fetch would be verified against, so encrypting to it is
    // security-neutral. Without the fallback a wizard-made offline profile, where setup
    // makes service_url mandatory, cannot pack at all while the node is down.
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("config"));
    let (recipient_file, node_secret) = write_node_keypair(tmp.path());

    // Both a (dead) service_url and a valid local file are configured; the URL path is
    // primary, and with it dead the configured pin is what a successful fetch would have
    // been verified against — so pack falls back to it (with a warning) rather than error.
    let cfg = tmp.path().join("tool.toml");
    fs::write(
        &cfg,
        format!(
            "[profiles.default]\nservice_url = \"http://127.0.0.1:1\"\nnode_recipient_file = \"{}\"\n",
            recipient_file.display()
        ),
    )
    .unwrap();

    let build_out = tmp.path().join("build");
    let staging = build_covid_staging(&build_out);

    let out = tmp.path().join("out.tar.c4gh");
    let cli = Cli::try_parse_from([
        "gdi-dataset-tool",
        "--config",
        cfg.to_str().unwrap(),
        "pack",
        staging.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
    ])
    .unwrap();
    gdi_dataset_tool::run(cli)
        .expect("a dead node with a configured pin must pack offline, not error");
    // The package really is encrypted to the pinned node key.
    let _ = decrypt_package(&out, &node_secret);
}

/// Assert the package-format member order: `manifest.json` first, all `headers/*` before
/// any `allele-freq.*` parquet member, and at least one parquet present.
fn assert_member_order(names: &[String]) {
    assert_eq!(
        names.first().map(String::as_str),
        Some("manifest.json"),
        "manifest.json must be the FIRST member; got {names:?}"
    );

    let first_parquet = names
        .iter()
        .position(|n| n.starts_with("allele-freq.") && n.ends_with(".parquet"))
        .expect("at least one allele-freq.*.parquet member");

    // Every headers/* member must come before the first parquet member.
    for (i, name) in names.iter().enumerate() {
        if name.starts_with("headers/") {
            assert!(
                i < first_parquet,
                "headers/* ({name}) must precede the parquet payload; got {names:?}"
            );
        }
    }

    // No member after the first parquet may be a header or the manifest.
    for name in &names[first_parquet..] {
        assert!(
            !name.starts_with("headers/") && name != "manifest.json",
            "the payload tail must be parquet only; offender: {name} in {names:?}"
        );
    }
}

/// Load the auto-generated provider secret from `config/keys/provider.c4gh`.
fn load_provider_secret(config_dir: &Path) -> SecretKey {
    let pem = fs::read_to_string(config_dir.join("keys/provider.c4gh")).unwrap();
    gdi_node_standalone_core::crypt4gh::parse_secret_key(&pem).unwrap()
}

/// Return the single subdirectory of `out` (the `<datasetId>/` staging directory).
fn single_subdir(out: &Path) -> PathBuf {
    let mut dirs: Vec<PathBuf> = fs::read_dir(out)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    assert_eq!(
        dirs.len(),
        1,
        "expected one staging dir under {}",
        out.display()
    );
    dirs.remove(0)
}
