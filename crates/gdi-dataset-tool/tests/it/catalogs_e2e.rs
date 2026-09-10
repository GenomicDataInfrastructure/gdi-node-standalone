//! Integration tests for `catalogs`: the online path parses a stubbed FDP-root
//! Turtle listing two catalogs; the offline path reads the profile's `catalogs`
//! allow-list from a config file (no Docker).

#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::process::Command;

use clap::Parser as _;
use gdi_dataset_tool::catalogs;
use gdi_dataset_tool::cli::{CatalogsArgs, Cli, Command as CliCommand};

fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(fut)
}

#[test]
fn online_parses_two_catalogs_from_fdp_root() {
    let ttl = r"
@prefix fdp-o: <https://w3id.org/fdp/fdp-o#> .
@prefix ldp: <http://www.w3.org/ns/ldp#> .
<https://node.example/fairdp> a fdp-o:FAIRDataPoint ;
  ldp:contains <https://node.example/fairdp/catalog/synthetic-data> ,
               <https://node.example/fairdp/catalog/gdi-aggregated> .
";
    let base = serve(ttl, 200, "text/turtle");
    let names = block_on(catalogs::fetch_node_catalogs(&base)).unwrap();
    assert_eq!(names, vec!["gdi-aggregated", "synthetic-data"]);
}

#[test]
fn online_unreachable_node_errors() {
    let err = block_on(catalogs::fetch_node_catalogs("http://127.0.0.1:1")).unwrap_err();
    assert!(err.message.contains("cannot reach"), "{}", err.message);
}

#[test]
fn offline_reads_the_profile_allow_list() {
    // A config with an offline catalogs allow-list under [profiles.<name>.catalogs].
    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("tool.toml");
    std::fs::write(
        &cfg,
        r#"
[profiles.default.catalogs]
synthetic-data = "Synthetic data"
gdi-aggregated = "GoE aggregated"
"#,
    )
    .unwrap();

    // `catalogs --offline` reads the allow-list (no network).
    let cli = Cli::try_parse_from([
        "gdi-dataset-tool",
        "--config",
        cfg.to_str().unwrap(),
        "catalogs",
        "--offline",
    ])
    .unwrap();
    std::assert_matches!(
        cli.command,
        CliCommand::Catalogs(CatalogsArgs { offline: true, .. })
    );

    // Run the actual binary and capture its stdout to verify the resolved
    // allow-list is correct (not just that the command succeeds).
    let output = Command::new(env!("CARGO_BIN_EXE_gdi-dataset-tool"))
        .args(["--config", cfg.to_str().unwrap(), "catalogs", "--offline"])
        .output()
        .expect("spawn gdi-dataset-tool");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "catalogs --offline must succeed; stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Each catalog is printed as "{name}\t{title}" — assert both are present.
    assert!(
        stdout.contains("synthetic-data") && stdout.contains("Synthetic data"),
        "stdout must contain synthetic-data entry; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("gdi-aggregated") && stdout.contains("GoE aggregated"),
        "stdout must contain gdi-aggregated entry; stdout:\n{stdout}"
    );

    // Exactly two catalog lines must be printed (no extra entries).
    let catalog_lines: Vec<&str> = stdout.lines().filter(|l| l.contains('\t')).collect();
    assert_eq!(
        catalog_lines.len(),
        2,
        "expected exactly 2 catalog lines, got {}; stdout:\n{stdout}",
        catalog_lines.len()
    );
}

#[test]
fn offline_without_allow_list_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("empty.toml");
    // A profile with no catalogs allow-list: selection succeeds (sole profile),
    // but the offline path has nothing to list.
    std::fs::write(&cfg, "[profiles.default]\n").unwrap();
    let err = gdi_dataset_tool::commands::cmd_catalogs::run(
        &CatalogsArgs {
            dry_run: false,
            offline: true,
            sync: false,
            format: gdi_dataset_tool::cli::OutputFormat::Text,
        },
        None,
        Some(&cfg),
    )
    .unwrap_err();
    assert!(err.message.contains("no catalogs"), "{}", err.message);
}

#[test]
fn sync_persists_node_catalogs_into_the_profile() {
    let ttl = r"
@prefix fdp-o: <https://w3id.org/fdp/fdp-o#> .
@prefix ldp: <http://www.w3.org/ns/ldp#> .
<https://node.example/fairdp> a fdp-o:FAIRDataPoint ;
  ldp:contains <https://node.example/fairdp/catalog/synthetic-data> ,
               <https://node.example/fairdp/catalog/gdi-aggregated> .
";
    let base = serve(ttl, 200, "text/turtle");

    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("tool.toml");
    std::fs::write(
        &cfg,
        format!("[profiles.default]\nservice_url = \"{base}\"\n"),
    )
    .unwrap();

    gdi_dataset_tool::run(
        Cli::try_parse_from([
            "gdi-dataset-tool",
            "--config",
            cfg.to_str().unwrap(),
            "catalogs",
            "--sync",
        ])
        .unwrap(),
    )
    .expect("catalogs --sync succeeds");

    // The config now carries the two catalogs in the allow-list.
    let reloaded = gdi_node_standalone_core::config::ToolConfig::load(Some(&cfg)).unwrap();
    let cat = &reloaded.profiles["default"].catalogs;
    assert!(cat.contains_key("gdi-aggregated"), "synced: {cat:?}");
    assert!(cat.contains_key("synthetic-data"), "synced: {cat:?}");
    // The previous config is preserved in a .bak sibling.
    let mut bak = cfg.clone().into_os_string();
    bak.push(".bak");
    assert!(std::path::Path::new(&bak).exists(), "backup created");
}

/// `catalogs --sync` must preserve inline S3 credentials the operator hand-wrote.
///
/// `ProfileS3`'s credential fields are `#[serde(skip_serializing)]`, so re-serialising the
/// whole file would drop them from the live config, turning the next S3 call into an
/// anonymous client, and leave them only in the `.bak`. That moves the secret to a less
/// visible file in the same directory rather than off disk. The write is in place.
#[test]
fn sync_preserves_inline_disk_credentials() {
    let ttl = r"
@prefix fdp-o: <https://w3id.org/fdp/fdp-o#> .
@prefix ldp: <http://www.w3.org/ns/ldp#> .
<https://node.example/fairdp> a fdp-o:FAIRDataPoint ;
  ldp:contains <https://node.example/fairdp/catalog/synthetic-data> .
";
    let base = serve(ttl, 200, "text/turtle");

    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("tool.toml");
    // Write a config that includes inline S3 credentials.
    std::fs::write(
        &cfg,
        format!(
            "[profiles.default]\nservice_url = \"{base}\"\n\
             [profiles.default.s3]\nsecret_access_key = \"inline-secret\"\n"
        ),
    )
    .unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_gdi-dataset-tool"))
        .args(["--config", cfg.to_str().unwrap(), "catalogs", "--sync"])
        .output()
        .expect("spawn gdi-dataset-tool");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "catalogs --sync must succeed; stderr:\n{stderr}"
    );
    let after = std::fs::read_to_string(&cfg).expect("config still readable");
    assert!(
        after.contains("inline-secret"),
        "the operator's inline credential must survive --sync; file:\n{after}"
    );
    assert!(
        !stderr.contains("inline S3"),
        "there is nothing to warn about any more; stderr:\n{stderr}"
    );
}

/// `catalogs --sync` says nothing about credentials supplied via env vars — there is no
/// inline credential in the file to preserve or comment on.
#[test]
fn sync_no_warn_for_env_only_credentials() {
    let ttl = r"
@prefix fdp-o: <https://w3id.org/fdp/fdp-o#> .
@prefix ldp: <http://www.w3.org/ns/ldp#> .
<https://node.example/fairdp> a fdp-o:FAIRDataPoint ;
  ldp:contains <https://node.example/fairdp/catalog/synthetic-data> .
";
    let base = serve(ttl, 200, "text/turtle");

    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("tool.toml");
    // On-disk config has no inline credentials.
    std::fs::write(
        &cfg,
        format!("[profiles.default]\nservice_url = \"{base}\"\n"),
    )
    .unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_gdi-dataset-tool"))
        .args(["--config", cfg.to_str().unwrap(), "catalogs", "--sync"])
        // Credentials are only in the env (the recommended approach).
        .env(
            "GDI_TOOL__PROFILES__default__S3__SECRET_ACCESS_KEY",
            "env-secret-value",
        )
        .output()
        .expect("spawn gdi-dataset-tool");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "catalogs --sync must succeed; stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("inline S3"),
        "must NOT warn when credentials are env-only; stderr:\n{stderr}"
    );
}

/// `catalogs --offline --format json` nests the entries under a versioned envelope
/// (`{"schemaVersion":1,"catalogs":[ {name,title}, ... ]}`) rather than a bare array.
#[test]
fn offline_json_nests_catalogs_under_schema_version() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("tool.toml");
    std::fs::write(
        &cfg,
        r#"
[profiles.default.catalogs]
synthetic-data = "Synthetic data"
gdi-aggregated = "GoE aggregated"
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_gdi-dataset-tool"))
        .args([
            "--config",
            cfg.to_str().unwrap(),
            "catalogs",
            "--offline",
            "--format",
            "json",
        ])
        .output()
        .expect("spawn gdi-dataset-tool");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "catalogs --offline --format json must succeed; stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout must be one JSON object: {e}; stdout:\n{stdout}"));
    assert_eq!(
        v["schemaVersion"], 1,
        "must carry schemaVersion; got:\n{stdout}"
    );
    let cats = v["catalogs"]
        .as_array()
        .unwrap_or_else(|| panic!("catalogs must be an array; got:\n{stdout}"));
    assert_eq!(cats.len(), 2, "two catalogs; got:\n{stdout}");
    assert!(
        cats.iter().any(|c| c["name"] == "synthetic-data"),
        "must list synthetic-data; got:\n{stdout}"
    );
}

/// `catalogs --sync --format json` emits a versioned action envelope rather than the prose
/// sentence, so a machine consumer can read the result.
#[test]
fn sync_json_emits_versioned_action_envelope() {
    let ttl = r"
@prefix fdp-o: <https://w3id.org/fdp/fdp-o#> .
@prefix ldp: <http://www.w3.org/ns/ldp#> .
<https://node.example/fairdp> a fdp-o:FAIRDataPoint ;
  ldp:contains <https://node.example/fairdp/catalog/synthetic-data> ,
               <https://node.example/fairdp/catalog/gdi-aggregated> .
";
    let base = serve(ttl, 200, "text/turtle");

    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("tool.toml");
    std::fs::write(
        &cfg,
        format!("[profiles.default]\nservice_url = \"{base}\"\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_gdi-dataset-tool"))
        .args([
            "--config",
            cfg.to_str().unwrap(),
            "catalogs",
            "--sync",
            "--format",
            "json",
        ])
        .output()
        .expect("spawn gdi-dataset-tool");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "catalogs --sync --format json must succeed; stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The prose sentence must not leak into the JSON stdout.
    assert!(
        !stdout.contains("synced "),
        "json mode must not print the prose sentence; stdout:\n{stdout}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout must be one JSON object: {e}; stdout:\n{stdout}"));
    assert_eq!(v["schemaVersion"], 1, "schemaVersion; got:\n{stdout}");
    assert_eq!(v["action"], "catalogs-sync", "action; got:\n{stdout}");
    assert_eq!(v["profile"], "default", "resolved profile; got:\n{stdout}");
    assert_eq!(
        v["path"],
        cfg.to_str().unwrap(),
        "config path written; got:\n{stdout}"
    );
    let cats = v["catalogs"]
        .as_array()
        .unwrap_or_else(|| panic!("catalogs must be an array; got:\n{stdout}"));
    assert_eq!(cats.len(), 2, "two synced catalogs; got:\n{stdout}");

    // The catalogs were actually persisted (the sync still ran).
    let reloaded = gdi_node_standalone_core::config::ToolConfig::load(Some(&cfg)).unwrap();
    assert_eq!(reloaded.profiles["default"].catalogs.len(), 2);
}

/// Serve one request with `body` + `content_type`, returning the base URL.
fn serve(body: &str, status: u16, content_type: &str) -> String {
    test_util::serve_once(body, status, content_type)
}
