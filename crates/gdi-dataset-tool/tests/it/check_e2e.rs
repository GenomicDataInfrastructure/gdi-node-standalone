//! Integration tests for `check`: a stubbed FDP dataset graph that matches the
//! package's manifest passes; a mismatched graph is reported as an error. Drives
//! the `cmd_check` wrapper over a local staging directory + a loopback FDP stub (no
//! Docker, no S3).

#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use gdi_dataset_tool::cli::CheckArgs;

const ID: &str = "GDI-EE-UTARTU-20260409143052837";
const TITLE: &str = "Synthetic AF dataset";
const LICENSE: &str = "https://creativecommons.org/licenses/by/4.0/";
const ACCESS_RIGHTS: &str = "http://publications.europa.eu/resource/authority/access-right/PUBLIC";

/// Write a minimal valid `manifest.json` into a staging directory, returning it.
fn staging_dir() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = format!(
        r#"{{
  "metadata": {{
    "datasetId": "{ID}",
    "catalog": "synthetic-data",
    "title": "{TITLE}",
    "accessRights": "{ACCESS_RIGHTS}",
    "applicableLegislation": ["http://data.europa.eu/eli/reg/2025/327/oj"],
    "license": "{LICENSE}",
    "creator": [{{"name": "University of Tartu"}}],
    "healthCategory": ["http://example/cat"]
  }},
  "config": {{
    "mode": "aggregated",
    "blockRange": 0,
    "assembly": {{"reference": "GRCh38"}},
    "manifestVersion": 1,
    "generatedBy": "gdi-dataset-tool"
  }}
}}"#
    );
    std::fs::write(tmp.path().join("manifest.json"), manifest).unwrap();
    tmp
}

/// A config file pointing `service_url` at `base`.
fn config_with_service_url(base: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("tool.toml");
    std::fs::write(
        &cfg,
        format!("[profiles.default]\nservice_url = \"{base}\"\n"),
    )
    .unwrap();
    (tmp, cfg)
}

fn matching_graph() -> String {
    format!(
        r#"<https://n/fairdp/dataset/{ID}> a dcat:Dataset ;
  dct:identifier "{ID}"^^xsd:string ;
  dct:title "{TITLE}" ;
  dct:license <{LICENSE}> ;
  dct:accessRights <{ACCESS_RIGHTS}> ."#
    )
}

#[test]
fn matching_fdp_graph_passes() {
    let staging = staging_dir();
    let base = serve(&matching_graph(), 200);
    let (_keep, cfg) = config_with_service_url(&base);

    let args = CheckArgs {
        id: None,
        all: false,
        hidden: false,
        visible: false,
        local: Some(staging.path().to_path_buf()),
        format: gdi_dataset_tool::cli::OutputFormat::Text,
    };
    gdi_dataset_tool::commands::cmd_check::run(&args, None, Some(&cfg)).unwrap();
}

#[test]
fn mismatched_fdp_graph_is_reported() {
    let staging = staging_dir();
    // A graph with the wrong title -> the title field mismatches.
    let body = matching_graph().replace(TITLE, "COMPLETELY WRONG TITLE");
    let base = serve(&body, 200);
    let (_keep, cfg) = config_with_service_url(&base);

    let args = CheckArgs {
        id: None,
        all: false,
        hidden: false,
        visible: false,
        local: Some(staging.path().to_path_buf()),
        format: gdi_dataset_tool::cli::OutputFormat::Text,
    };
    let err = gdi_dataset_tool::commands::cmd_check::run(&args, None, Some(&cfg)).unwrap_err();
    assert!(err.message.contains("does not match"), "{}", err.message);
    assert!(
        err.message.contains(ID),
        "names the dataset: {}",
        err.message
    );
}

/// `check --all` over S3 must check every selected id and report the failures together.
///
/// This is the S3 selector path; the `--local` tests above cover the other branch. A bucket
/// structurally contains ids whose FDP record cannot be read (`upload` deposits hidden, and
/// the dataset route serves only visible datasets), so aborting on the first would discard
/// every prior result. Both ids must therefore appear in the final verdict, not just the
/// first.
///
/// Both packages here are unreadable rather than merely hidden, which exercises the same
/// per-id `unavailable` outcome without needing two real crypt4gh packages.
#[test]
fn s3_all_checks_every_id_and_reports_them_together() {
    use std::sync::Arc;
    const ID2: &str = "GDI-EE-UTARTU-20260409143052838";

    let store: gdi_dataset_tool::s3::Store = Arc::new(object_store::memory::InMemory::new());
    let package_store = gdi_dataset_tool::s3::PackageStore::new(Arc::clone(&store));
    for id in [ID, ID2] {
        gdi_dataset_tool::runtime::block_on(gdi_dataset_tool::s3::upload_package_bytes(
            &store,
            &package_store,
            id,
            b"not-a-real-crypt4gh-package".to_vec(),
            false,
        ))
        .unwrap();
    }

    let base = serve(&matching_graph(), 200);
    let args = CheckArgs {
        id: None,
        all: true,
        hidden: false,
        visible: false,
        local: None,
        format: gdi_dataset_tool::cli::OutputFormat::Text,
    };
    let err =
        gdi_dataset_tool::commands::cmd_check::run_with(&args, &base, Some(&store), None, None)
            .expect_err("two unreadable packages must both be reported as mismatches");

    for id in [ID, ID2] {
        assert!(
            err.message.contains(id),
            "the verdict must name EVERY failing id — aborting on the first would drop {id}: {}",
            err.message
        );
    }
}

/// The `--local` path must not require an `[s3]` block: `run_with` accepts `None` for the
/// store, which is what lets the documented no-S3 workflow run without a bucket.
#[test]
fn local_check_needs_no_store() {
    let staging = staging_dir();
    let base = serve(&matching_graph(), 200);
    let args = CheckArgs {
        id: None,
        all: false,
        hidden: false,
        visible: false,
        local: Some(staging.path().to_path_buf()),
        format: gdi_dataset_tool::cli::OutputFormat::Text,
    };
    gdi_dataset_tool::commands::cmd_check::run_with(&args, &base, None, None, None)
        .expect("the local path must run with no store at all");
}

#[test]
fn local_check_json_carries_schema_version() {
    // A matching FDP graph plus `--format json` must emit the versioned envelope
    // `{"schemaVersion":1,"results":[ {id, fields}, ... ]}`, not a bare array.
    let staging = staging_dir();
    let base = serve(&matching_graph(), 200);
    let (_keep, cfg) = config_with_service_url(&base);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_gdi-dataset-tool"))
        .args([
            "--config",
            cfg.to_str().unwrap(),
            "check",
            "--local",
            staging.path().to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("spawn gdi-dataset-tool");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "check --local --format json must succeed; stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout must be one JSON object: {e}; stdout:\n{stdout}"));
    assert_eq!(v["schemaVersion"], 1, "schemaVersion; got:\n{stdout}");
    let results = v["results"]
        .as_array()
        .unwrap_or_else(|| panic!("results must be an array; got:\n{stdout}"));
    assert_eq!(results.len(), 1, "one checked dataset; got:\n{stdout}");
    assert_eq!(
        results[0]["id"], ID,
        "the checked dataset id; got:\n{stdout}"
    );
}

#[test]
fn missing_service_url_errors() {
    let staging = staging_dir();
    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("tool.toml");
    // A profile with no service_url: selection succeeds (sole profile), but the
    // service_url check fails.
    std::fs::write(&cfg, "[profiles.default]\n").unwrap();
    let args = CheckArgs {
        id: None,
        all: false,
        hidden: false,
        visible: false,
        local: Some(staging.path().to_path_buf()),
        format: gdi_dataset_tool::cli::OutputFormat::Text,
    };
    let err = gdi_dataset_tool::commands::cmd_check::run(&args, None, Some(&cfg)).unwrap_err();
    assert!(err.message.contains("service_url"), "{}", err.message);
}

fn serve(body: &str, status: u16) -> String {
    test_util::serve_once(body, status, "text/turtle")
}
