//! Integration tests for `deploy`: atomic inbox drop of a
//! `.tar.c4gh` file and of a staging directory, plus the management-plane
//! live-id guard — all over a temp dir + a tiny local HTTP stub (no Docker).

#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::io::{Read as _, Write as _};
use std::net::TcpListener;

use gdi_dataset_tool::commands::cmd_deploy::deploy_artifact;

/// A valid dataset id for the inbox/name keys.
const ID: &str = "GDI-EE-UTARTU-20260409143052837";

/// `deploy --inbox <dir>` fully specifies its target, so it must not require a tool
/// profile: dropping a package into a directory needs nothing else. Demanding one would
/// fail with "no profiles configured" on the local, no-S3 path.
#[test]
fn deploy_with_explicit_inbox_needs_no_profile() {
    let tmp = tempfile::tempdir().unwrap();
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&inbox).unwrap();
    let pkg = tmp.path().join(format!("{ID}.tar.c4gh"));
    std::fs::write(&pkg, b"ENCRYPTED-PACKAGE").unwrap();

    // A syntactically valid tool config that configures no profiles at all.
    let cfg = tmp.path().join("tool.toml");
    std::fs::write(&cfg, "country_code = \"EE\"\n").unwrap();

    let args = gdi_dataset_tool::cli::DeployArgs {
        artifact: pkg,
        inbox: Some(inbox.clone()),
        replace: false,
        wait: false,
        wait_timeout: 120,
        management_url: None,
        format: gdi_dataset_tool::cli::OutputFormat::Text,
    };
    gdi_dataset_tool::commands::cmd_deploy::run(&args, None, Some(&cfg))
        .expect("--inbox must not require a [profiles.*] block");

    assert!(
        inbox.join(format!("{ID}.tar.c4gh")).is_file(),
        "the package must land in the explicitly named inbox"
    );
}

/// The escape hatch is narrow: without `--inbox` there is nothing to fall back on, so a
/// profileless config must still fail (rather than silently deploying nowhere).
#[test]
fn deploy_without_inbox_still_requires_a_profile() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = tmp.path().join(format!("{ID}.tar.c4gh"));
    std::fs::write(&pkg, b"ENCRYPTED-PACKAGE").unwrap();
    let cfg = tmp.path().join("tool.toml");
    std::fs::write(&cfg, "country_code = \"EE\"\n").unwrap();

    let args = gdi_dataset_tool::cli::DeployArgs {
        artifact: pkg,
        inbox: None,
        replace: false,
        wait: false,
        wait_timeout: 120,
        management_url: None,
        format: gdi_dataset_tool::cli::OutputFormat::Text,
    };
    let err = gdi_dataset_tool::commands::cmd_deploy::run(&args, None, Some(&cfg))
        .expect_err("no --inbox and no profile must be an error");
    assert!(
        err.message.contains("no profiles configured"),
        "must still name the missing profile: {}",
        err.message
    );
}

#[test]
fn deploy_file_lands_atomically() {
    let tmp = tempfile::tempdir().unwrap();
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&inbox).unwrap();
    let pkg = tmp.path().join(format!("{ID}.tar.c4gh"));
    std::fs::write(&pkg, b"ENCRYPTED-PACKAGE").unwrap();

    // No service_url -> the guard is skipped, deploy proceeds.
    deploy_artifact(&pkg, &inbox, None, false).unwrap();

    // The final name is present with the right bytes.
    let landed = inbox.join(format!("{ID}.tar.c4gh"));
    assert!(landed.is_file(), "final package present");
    assert_eq!(std::fs::read(&landed).unwrap(), b"ENCRYPTED-PACKAGE");

    // No `*.partial` left behind.
    let leftover: Vec<_> = std::fs::read_dir(&inbox)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".partial"))
        .collect();
    assert!(leftover.is_empty(), "no partial left: {leftover:?}");
}

#[test]
fn deploy_staging_dir_lands_as_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&inbox).unwrap();
    let staging = tmp.path().join(ID);
    std::fs::create_dir_all(staging.join("headers")).unwrap();
    std::fs::write(staging.join("manifest.json"), br#"{"metadata":{}}"#).unwrap();
    std::fs::write(staging.join("allele-freq.chr1.parquet"), b"PARQUET").unwrap();
    std::fs::write(staging.join("headers/v.vcf"), b"##fileformat").unwrap();

    deploy_artifact(&staging, &inbox, None, false).unwrap();

    let landed = inbox.join(ID);
    assert!(landed.is_dir(), "staging dir present");
    assert!(landed.join("manifest.json").is_file());
    assert_eq!(
        std::fs::read(landed.join("allele-freq.chr1.parquet")).unwrap(),
        b"PARQUET"
    );
    assert_eq!(
        std::fs::read(landed.join("headers/v.vcf")).unwrap(),
        b"##fileformat"
    );

    // No dot-prefixed temp dir left behind.
    let leftover: Vec<_> = std::fs::read_dir(&inbox)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with('.'))
        .collect();
    assert!(leftover.is_empty(), "no dot-dir left: {leftover:?}");
}

#[test]
fn deploy_refuses_live_id_via_node_guard() {
    let tmp = tempfile::tempdir().unwrap();
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&inbox).unwrap();
    let pkg = tmp.path().join(format!("{ID}.tar.c4gh"));
    std::fs::write(&pkg, b"PKG").unwrap();

    // A one-shot HTTP server that reports the id as `visible`.
    let base = serve_state(r#"{"id":"x","state":"visible","channel":"inbox"}"#, 200);

    let err = deploy_artifact(&pkg, &inbox, Some(&base), false).unwrap_err();
    assert!(err.message.contains("already live"), "{}", err.message);
    // Nothing was dropped.
    assert!(!inbox.join(format!("{ID}.tar.c4gh")).exists());
}

/// `--replace` is the documented escape from the live-id guard, and the only way to
/// overwrite a live dataset. A bypass that stopped working would block the documented
/// recovery path, and one that fired unconditionally would silently disarm the guard the
/// test above asserts, so both sides need pinning. Same fixture as
/// `deploy_refuses_live_id_via_node_guard`, opposite flag and opposite expectation.
#[test]
fn deploy_replace_bypasses_the_live_id_guard() {
    let tmp = tempfile::tempdir().unwrap();
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&inbox).unwrap();
    let pkg = tmp.path().join(format!("{ID}.tar.c4gh"));
    std::fs::write(&pkg, b"REPLACEMENT-PKG").unwrap();

    // The node reports the id as `visible` — precisely the state the guard refuses.
    let base = serve_state(r#"{"id":"x","state":"visible","channel":"inbox"}"#, 200);

    deploy_artifact(&pkg, &inbox, Some(&base), true).expect("--replace must deploy over a live id");
    let landed = inbox.join(format!("{ID}.tar.c4gh"));
    assert!(landed.is_file(), "the replacement package must land");
    assert_eq!(
        std::fs::read(&landed).unwrap(),
        b"REPLACEMENT-PKG",
        "the dropped bytes are the replacement, not a stale artifact"
    );
}

#[test]
fn deploy_proceeds_for_errored_id_via_node_guard() {
    let tmp = tempfile::tempdir().unwrap();
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&inbox).unwrap();
    let pkg = tmp.path().join(format!("{ID}.tar.c4gh"));
    std::fs::write(&pkg, b"FIXED-PKG").unwrap();

    // The node reports the id `error` -> error-recovery -> deploy proceeds.
    let base = serve_state(r#"{"id":"x","state":"error","channel":"inbox"}"#, 200);

    deploy_artifact(&pkg, &inbox, Some(&base), false).unwrap();
    assert!(inbox.join(format!("{ID}.tar.c4gh")).is_file());
}

#[test]
fn deploy_proceeds_when_node_unreachable() {
    let tmp = tempfile::tempdir().unwrap();
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&inbox).unwrap();
    let pkg = tmp.path().join(format!("{ID}.tar.c4gh"));
    std::fs::write(&pkg, b"PKG").unwrap();

    // A port nothing is listening on -> connection refused -> proceed (backstop).
    deploy_artifact(&pkg, &inbox, Some("http://127.0.0.1:1"), false).unwrap();
    assert!(inbox.join(format!("{ID}.tar.c4gh")).is_file());
}

#[test]
fn deploy_missing_artifact_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&inbox).unwrap();
    let err = deploy_artifact(&tmp.path().join("nope.tar.c4gh"), &inbox, None, false).unwrap_err();
    assert!(err.message.contains("not found"), "{}", err.message);
}

// Deploy guard tests.

/// (a) Deploying a staging directory whose name is not a valid dataset id → error
/// "not a valid dataset id".
#[test]
fn deploy_invalid_dataset_id_name_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&inbox).unwrap();

    // Create a directory whose name is not a valid dataset id.
    let bad_dir = tmp.path().join("not-a-valid-id");
    std::fs::create_dir_all(&bad_dir).unwrap();
    std::fs::write(bad_dir.join("manifest.json"), br#"{"metadata":{}}"#).unwrap();

    let err = deploy_artifact(&bad_dir, &inbox, None, false).unwrap_err();
    assert!(
        err.message.contains("not a valid dataset id"),
        "expected 'not a valid dataset id' in error, got: {}",
        err.message
    );
}

/// (b) Deploying a valid-named dir with no manifest.json → error
/// "has no manifest.json".
#[test]
fn deploy_staging_dir_without_manifest_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&inbox).unwrap();

    // A valid dataset-id-named directory that contains no manifest.json.
    let no_manifest = tmp.path().join(ID);
    std::fs::create_dir_all(&no_manifest).unwrap();

    let err = deploy_artifact(&no_manifest, &inbox, None, false).unwrap_err();
    assert!(
        err.message.contains("manifest.json"),
        "expected 'manifest.json' in error, got: {}",
        err.message
    );
}

/// (c) Deploying twice into the same inbox: second attempt asserts "already
/// holds a staging directory" and the first artifact is still intact.
#[test]
fn deploy_twice_refuses_second_staging_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&inbox).unwrap();

    // First deploy: a staging directory.
    let staging = tmp.path().join(ID);
    std::fs::create_dir_all(&staging).unwrap();
    std::fs::write(staging.join("manifest.json"), br#"{"metadata":{}}"#).unwrap();
    deploy_artifact(&staging, &inbox, None, false).unwrap();

    // The first artifact must be present.
    assert!(
        inbox.join(ID).is_dir(),
        "first staging dir must land in inbox"
    );
    assert!(
        inbox.join(ID).join("manifest.json").is_file(),
        "first artifact must have manifest.json"
    );

    // Second deploy of the same id: must be refused.
    let err = deploy_artifact(&staging, &inbox, None, false).unwrap_err();
    assert!(
        err.message.contains("already holds a staging dir"),
        "expected 'already holds a staging dir' in error, got: {}",
        err.message
    );

    // First artifact must still be intact.
    assert!(
        inbox.join(ID).join("manifest.json").is_file(),
        "first artifact must still be intact after refused second deploy"
    );
}

/// `--management-url` must decide the pre-drop baseline probe, not just the `--wait` poll.
///
/// A wizard-authored profile collects only `service_url`, the public plane, which 404s
/// `/datasets/{id}/state`. If the baseline were probed from the profile alone it would be
/// `None`, and the poll would then read the previous ingest's stale `error` as being about
/// this drop, failing a deploy that is in fact fine.
///
/// Asserted through the live-id guard, which reads the same probe: the profile's
/// `service_url` 404s while `--management-url` reports the id `visible`. Only a baseline
/// taken from the management URL can see `visible`, so the refusal proves which plane was
/// read.
#[test]
fn management_url_decides_the_pre_drop_baseline_not_just_the_wait_poll() {
    let tmp = tempfile::tempdir().unwrap();
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&inbox).unwrap();
    let pkg = tmp.path().join(format!("{ID}.tar.c4gh"));
    std::fs::write(&pkg, b"PKG").unwrap();

    let public = serve_state(r#"{"detail":"not found"}"#, 404);
    let management = serve_state(r#"{"id":"x","state":"visible","channel":"inbox"}"#, 200);

    let cfg = tmp.path().join("tool.toml");
    std::fs::write(
        &cfg,
        format!("[profiles.default]\nservice_url = \"{public}\"\n"),
    )
    .unwrap();

    let args = gdi_dataset_tool::cli::DeployArgs {
        artifact: pkg,
        inbox: Some(inbox.clone()),
        replace: false,
        wait: false,
        wait_timeout: 120,
        management_url: Some(management),
        format: gdi_dataset_tool::cli::OutputFormat::Text,
    };
    let err = gdi_dataset_tool::commands::cmd_deploy::run(&args, None, Some(&cfg))
        .expect_err("the baseline must be probed on --management-url, which reports `visible`");
    assert!(
        err.to_string().contains("already live"),
        "expected the live-id guard to fire from the management-plane probe, got: {err}"
    );
    assert!(
        !inbox.join(format!("{ID}.tar.c4gh")).exists(),
        "nothing may be dropped when the guard refuses"
    );
}

/// The opposite direction, so the rule above cannot turn a false reject into a false
/// accept: with the management plane reporting `error` — the documented recovery case —
/// the same wiring must still let the corrected package through.
#[test]
fn management_url_baseline_still_allows_the_errored_id_recovery() {
    let tmp = tempfile::tempdir().unwrap();
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&inbox).unwrap();
    let pkg = tmp.path().join(format!("{ID}.tar.c4gh"));
    std::fs::write(&pkg, b"FIXED-PKG").unwrap();

    let public = serve_state(r#"{"detail":"not found"}"#, 404);
    let management = serve_state(r#"{"id":"x","state":"error","channel":"inbox"}"#, 200);

    let cfg = tmp.path().join("tool.toml");
    std::fs::write(
        &cfg,
        format!("[profiles.default]\nservice_url = \"{public}\"\n"),
    )
    .unwrap();

    let args = gdi_dataset_tool::cli::DeployArgs {
        artifact: pkg,
        inbox: Some(inbox.clone()),
        replace: false,
        wait: false,
        wait_timeout: 120,
        management_url: Some(management),
        format: gdi_dataset_tool::cli::OutputFormat::Text,
    };
    gdi_dataset_tool::commands::cmd_deploy::run(&args, None, Some(&cfg))
        .expect("an `error` id is the recovery path and must still deploy");
    assert!(
        inbox.join(format!("{ID}.tar.c4gh")).is_file(),
        "the corrected package must land"
    );
}

/// Spin up a one-request HTTP/1.1 server on an ephemeral loopback port that
/// answers any request with `status` + JSON `body`, then returns its base URL.
/// The listener thread serves a single connection and exits (enough for one
/// guard probe).
fn serve_state(body: &str, status: u16) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let body = body.to_owned();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            // Drain the request headers, best effort; the stub does not route on them.
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let resp = format!(
                "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
        }
    });
    format!("http://{addr}")
}
