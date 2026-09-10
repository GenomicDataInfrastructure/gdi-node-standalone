//! End-to-end tests for `gdi-dataset-tool validate`.
//!
//! `validate` runs the shared structural gates on a `build` staging directory or
//! a `.tar.c4gh` package (decrypting with the provider identity). The provider
//! keypair is auto-generated under `$GDI_CONFIG_DIR`; that env var is
//! process-global, so every test here is `#[serial]`.
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use clap::Parser as _;
use gdi_dataset_tool::cli::Cli;
use gdi_node_standalone_core::crypt4gh::{SecretKey, generate_keypair, serialize_public_key};
use serial_test::serial;

/// Write a minimal tool.toml config with a single `[profiles.default.catalogs]`
/// block containing the given catalog names.
fn write_config_with_catalogs(dir: &Path, catalogs: &[&str]) -> PathBuf {
    let cfg_path = dir.join("tool.toml");
    let mut body = "[profiles.default]\n\n[profiles.default.catalogs]\n".to_owned();
    for name in catalogs {
        let _ = writeln!(body, "{name} = \"{name}\"");
    }
    fs::write(&cfg_path, &body).unwrap();
    cfg_path
}

/// Run validate with an explicit config path (routes through the catalog allow-list).
///
/// `validate_target` collects problems into a `ValidateOutcome` rather than failing fast,
/// so this mirrors what the CLI does: a non-valid outcome becomes an `Err` carrying the
/// joined error messages.
fn validate_with_config(target: &Path, cfg_path: &Path) -> Result<(), gdi_dataset_tool::ToolError> {
    let outcome =
        gdi_dataset_tool::commands::cmd_validate::validate_target(target, None, Some(cfg_path))?;
    if outcome.is_valid() {
        Ok(())
    } else {
        Err(gdi_dataset_tool::ToolError::user(outcome.errors.join("; ")))
    }
}

/// Write a fresh node keypair into `dir`, returning the recipient file path.
fn write_node_recipient(dir: &Path) -> PathBuf {
    let (_sk, pk): (SecretKey, _) = generate_keypair();
    let recipient = dir.join("node.c4gh.pub");
    fs::write(&recipient, serialize_public_key(&pk)).unwrap();
    recipient
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

/// Build the COVID staging directory under `build_out` and return it. The package is
/// materialized into a sibling `covid-pkg` dir under `build_out`'s parent temp dir.
fn build_covid(build_out: &Path) -> PathBuf {
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

fn validate(target: &Path) -> Result<(), gdi_dataset_tool::ToolError> {
    let cli =
        Cli::try_parse_from(["gdi-dataset-tool", "validate", target.to_str().unwrap()]).unwrap();
    gdi_dataset_tool::run(cli)
}

/// The single `allele-freq.*.parquet` data file directly under a `build_covid`
/// staging directory. Shared by every test that overwrites it to force a parquet-gate
/// failure, so the "find it" logic cannot drift between them.
fn find_data_parquet(staging: &Path) -> PathBuf {
    fs::read_dir(staging)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.file_name().is_some_and(|n| {
                let n = n.to_string_lossy();
                n.starts_with("allele-freq.") && n.ends_with(".parquet")
            })
        })
        .expect("a parquet file exists")
}

#[test]
#[serial(env)]
fn validate_staging_dir_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("config"));
    let build_out = tmp.path().join("build");
    let staging = build_covid(&build_out);

    validate(&staging).expect("a valid staging dir validates (exit 0)");
}

#[test]
#[serial(env)]
fn validate_tampered_staging_dir_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("config"));
    let build_out = tmp.path().join("build");
    let staging = build_covid(&build_out);

    // Corrupt the manifest so the metadata gate rejects it (empty license).
    let manifest_path = staging.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["metadata"]["license"] = serde_json::Value::String(String::new());
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let err = validate(&staging).expect_err("a tampered manifest fails validation");
    assert_eq!(err.exit_code, 1);
    assert!(
        err.message.contains("license"),
        "expected 'license' in error message, got: {}",
        err.message
    );
}

#[test]
#[serial(env)]
fn validate_blockrange_mismatch_fails_like_node_ingest() {
    // Node parity: a package whose manifest `config.blockRange` disagrees with its data
    // files' `br{N}` filenames is visible-but-unqueryable on the node, whose serve path
    // resolves files by the configured blockRange. `validate` must reject it too, so a
    // producer learns before uploading rather than after ingest.
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("config"));
    let build_out = tmp.path().join("build");
    let staging = build_covid(&build_out);

    // The COVID build names its files `...br10000000...`; retype the manifest's
    // blockRange so it disagrees, without touching the (still self-consistent) files.
    let manifest_path = staging.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["config"]["blockRange"] = serde_json::json!(5_000_000);
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let err = validate(&staging).expect_err("a blockRange/filename mismatch fails validation");
    assert_eq!(err.exit_code, 1);
    assert!(
        err.message.contains("blockRange"),
        "expected 'blockRange' in error message, got: {}",
        err.message
    );
}

#[test]
#[serial(env)]
fn validate_corrupt_parquet_staging_dir_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("config"));
    let build_out = tmp.path().join("build");
    let staging = build_covid(&build_out);

    // Overwrite a parquet file with garbage so the parquet gate rejects it.
    let parquet = find_data_parquet(&staging);
    fs::write(&parquet, b"not a parquet file").unwrap();

    let err = validate(&staging).expect_err("a corrupt parquet fails validation");
    assert_eq!(err.exit_code, 1);
    assert!(
        err.message.contains("parquet"),
        "expected 'parquet' in error message, got: {}",
        err.message
    );
}

#[test]
#[serial(env)]
fn validate_subprocess_suppresses_the_raw_panic_for_a_handled_decode_panic() {
    // A crafted parquet whose embedded Arrow IPC schema panics `arrow-ipc`'s
    // `fb_to_schema` is caught by core's `catch_parquet_panic`
    // (`std::panic::catch_unwind`) and reported as a clean `invalid parquet: parquet
    // decode panicked ...` error. A `std::panic::set_hook` callback fires before that
    // `catch_unwind` sees the unwind, so the `panic_guard` thread-local is what keeps the
    // default hook's raw "thread 'main' panicked at ..." message off stderr for a case the
    // product handles cleanly. This runs the real binary as a subprocess rather than the
    // in-process `validate()` helper the other tests use: the panic hook is installed by
    // `main()`, so only a real process exercises the end-to-end stderr contract.
    let tmp = tempfile::tempdir().unwrap();
    let config_dir = tmp.path().join("config");
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", &config_dir);
    let build_out = tmp.path().join("build");
    let staging = build_covid(&build_out);

    // Overwrite the real parquet file with the checked-in crash reproducer: a crafted
    // footer whose embedded Arrow IPC schema has no `fields`, kept in core's tracked
    // fixtures (`validate_parquet::tests::fuzz_crash_artifacts_are_errors_not_panics`).
    let parquet = find_data_parquet(&staging);
    let malformed = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../core/tests/fixtures/malformed/fuzz_crash_fc0ea292.parquet");
    assert!(
        malformed.is_file(),
        "fixture missing at {}",
        malformed.display()
    );
    fs::copy(&malformed, &parquet).unwrap();

    // An empty config dir, set explicitly at the spawn site rather than inherited: this
    // isolates the run from any real user config, as the in-process tests above do.
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_gdi-dataset-tool"))
        .args(["validate", staging.to_str().unwrap()])
        .env("GDI_CONFIG_DIR", &config_dir)
        .output()
        .expect("spawn gdi-dataset-tool");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "a malformed parquet must fail validation; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("parquet decode panicked"),
        "expected the clean panic-boundary error on stderr, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked at"),
        "the raw Rust panic message leaked to stderr for a handled decode panic; \
         stderr:\n{stderr}"
    );
}

#[test]
#[serial(env)]
fn validate_package_file_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("config"));
    let recipient = write_node_recipient(tmp.path());

    // package -> a .tar.c4gh encrypted to (node, provider-own).
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

    // validate the package: decrypt with the provider identity + re-run gates.
    validate(&out).expect("a packaged .tar.c4gh validates (exit 0)");
}

/// An oversized `manifest.json` must be refused by the byte cap.
///
/// Why the cap exists: `validate` is routinely pointed at a package a provider handed
/// over, which it decrypts and safe-extracts into scratch under `ExtractBounds::default()`
/// — 16 GiB of members permitted, so a 16 GiB `manifest.json` is a legal member and
/// reading it whole is an OOM the operator's CLI takes on the attacker's schedule. The cap
/// is the node's 8 MiB ceiling, shared with `lint` and `diff`.
///
/// This test drives a plain staging directory, so it never enters the decrypt /
/// safe-extract path that motivates the cap; `validate_package_file_succeeds` above is
/// what drives the package route. Nor can any assertion below see where the refusal
/// happens: an implementation that slurped the file, parsed it, and only then compared
/// `len()` against the cap would pass identically. What is pinned is that the refusal
/// happens and that it names the cap.
#[test]
#[serial(env)]
fn validate_refuses_an_oversized_manifest_on_size() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("config"));
    let build_out = tmp.path().join("build");
    let staging = build_covid(&build_out);

    let manifest_path = staging.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    let cap = usize::try_from(gdi_node_standalone_core::ingest::MAX_MANIFEST_BYTES).unwrap();
    // The padding must land in a field that already exists, so the file stays a manifest
    // that parses into a real `Manifest` and the only thing wrong with it is its size.
    // `serde_json`'s `IndexMut` inserts a missing key rather than failing, so without this
    // check a renamed or newly-optional `description` would silently turn the fixture into
    // "manifest with an unexpected extra field", and the refusal under test could come
    // from that instead.
    assert!(
        manifest["metadata"]["description"].is_string(),
        "the fixture pads an EXISTING string field; `metadata.description` is not a string \
         in a freshly built manifest, so this test is no longer doing what it says"
    );
    manifest["metadata"]["description"] = serde_json::Value::String("a".repeat(cap + 1));
    fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap()).unwrap();

    let err = validate(&staging).expect_err("a manifest past the cap must be refused");
    assert_eq!(err.exit_code, 1);
    assert!(
        err.message.contains("exceeds") && err.message.contains(&cap.to_string()),
        "the refusal must name the byte cap it hit, not a parse or metadata problem; got: {}",
        err.message
    );
}

#[test]
#[serial(env)]
fn validate_missing_target_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("config"));
    let err = validate(&tmp.path().join("nope")).expect_err("a missing target fails");
    assert_eq!(err.exit_code, 1);
}

// A config whose allow-list excludes the dataset's catalog must fail.
#[test]
#[serial(env)]
fn validate_excluded_catalog_fails_with_unknown_catalog() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("config"));
    let build_out = tmp.path().join("build");
    let staging = build_covid(&build_out);

    // The COVID dataset uses the `gdi-aggregated` catalog; exclude it.
    let cfg_path = write_config_with_catalogs(tmp.path(), &["synthetic-data"]);
    let err = validate_with_config(&staging, &cfg_path)
        .expect_err("excluded catalog must fail validation");
    assert_eq!(err.exit_code, 1);
    assert!(
        err.message.contains("unknown catalog") || err.message.contains("UnknownCatalog"),
        "expected 'unknown catalog' in error message, got: {}",
        err.message
    );
}

// A config whose allow-list includes the dataset's catalog must pass.
#[test]
#[serial(env)]
fn validate_included_catalog_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("config"));
    let build_out = tmp.path().join("build");
    let staging = build_covid(&build_out);

    // Include `gdi-aggregated` (the COVID dataset's catalog) in the allow-list.
    let cfg_path = write_config_with_catalogs(tmp.path(), &["gdi-aggregated"]);
    validate_with_config(&staging, &cfg_path)
        .expect("catalog present in allow-list must pass validation");
}

/// seam: `validate` must reject what the node rejects at ingest.
///
/// The tool validates a package against `validate_package`, but the node applies more than
/// that at ingest: `core::ingest` refuses an empty or non-canonical `config.assembly`
/// outright, even though `validate_package` never reads that field. Any gap between the two
/// lets a package pass `validate` locally, upload cleanly, and only then be refused — the
/// failure surfacing on the node, to the operator, instead of on the provider's machine
/// where it can still be fixed.
///
/// Pins both sides of the seam: whatever verdict the node's gate reaches, the tool must
/// reach it too.
#[test]
#[serial(env)]
fn validate_rejects_an_assembly_the_node_would_reject() {
    for bad in ["", "hg38", "GRCH38"] {
        let tmp = tempfile::tempdir().unwrap();
        let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("config"));
        let build_out = tmp.path().join("build");
        let staging = build_covid(&build_out);

        let manifest_path = staging.join("manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
        manifest["config"]["assembly"]["reference"] = serde_json::Value::String(bad.to_owned());
        fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();

        // The node's gate, consulted directly: this is the verdict the tool must match.
        let node_accepts =
            !bad.is_empty() && gdi_node_standalone_core::chrom::is_known_assembly(bad);
        assert!(
            !node_accepts,
            "fixture must be one the node rejects: {bad:?}"
        );

        assert!(
            validate(&staging).is_err(),
            "validate must reject assembly {bad:?}, which the node refuses at ingest"
        );
    }
}
