//! Integration tests for the lifecycle ops (`publish` / `unpublish` / `delete`):
//! channel routing via a loopback `GET /datasets/{id}/state` stub + the declarative
//! `{id}.state.json` edit over an `InMemory` S3 store and a temp inbox (no Docker;
//! same shape as the deploy harness).
//!
//! The tests marked "command-driven" drive `cmd_delete::run` / `cmd_publish::run`
//! directly; the others drive the lower-level `state::*` helpers.

#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::fs;
use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;

use gdi_dataset_tool::commands::{cmd_delete, cmd_publish};
use gdi_dataset_tool::s3::{self, MARKER_KEY, STATE_SUFFIX, Store, TAR_C4GH_SUFFIX};
use gdi_dataset_tool::state::{self, Channel};
use object_store::ObjectStoreExt;
use object_store::memory::InMemory;
use object_store::path::Path as ObjPath;

/// A valid dataset id for the bucket/inbox keys.
const ID: &str = "GDI-EE-UTARTU-20260409143052837";

/// Write a minimal tool TOML where the profile's `service_url` (which is also
/// used as the management URL fallback) points at `base`.
fn write_service_config(tmp: &Path, inbox_path: &Path, base: &str) -> std::path::PathBuf {
    let cfg = tmp.join("tool.toml");
    fs::write(
        &cfg,
        format!(
            "[profiles.default]\ninbox = \"{}\"\nservice_url = \"{base}\"\n",
            inbox_path.display()
        ),
    )
    .unwrap();
    cfg
}

fn mem_store() -> Store {
    Arc::new(InMemory::new())
}

fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(fut)
}

async fn get_str(store: &Store, key: &str) -> Option<String> {
    match store.get(&ObjPath::from(key)).await {
        Ok(r) => Some(String::from_utf8(r.bytes().await.unwrap().to_vec()).unwrap()),
        Err(object_store::Error::NotFound { .. }) => None,
        Err(e) => panic!("unexpected get error: {e}"),
    }
}

/// leaf-helper test: exercises `state::s3_set_state` directly, to confirm the sidecar and
/// marker writes work in isolation.
#[test]
fn s3_set_state_writes_sidecar_and_bumps_marker_leaf() {
    let store = mem_store();
    block_on(state::s3_set_state(&store, ID, "visible")).unwrap();

    let sidecar = block_on(get_str(&store, &format!("{ID}{STATE_SUFFIX}"))).unwrap();
    assert!(sidecar.contains(r#""state":"visible""#), "{sidecar}");
    assert!(
        block_on(get_str(&store, MARKER_KEY)).is_some(),
        "marker bumped"
    );
}

/// command-driven: `cmd_publish::run` routes to the inbox channel (node reports
/// `channel:"inbox"`) and the inbox `{id}.state.json` sidecar appears with
/// `"state":"visible"`.
///
/// Drives the command rather than the S3 write directly, so `resolve_channel`'s routing is
/// what is under test.
#[test]
fn publish_routes_to_inbox_channel_via_command() {
    let tmp = tempfile::tempdir().unwrap();
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&inbox).unwrap();

    // Node reports the id on the inbox channel (hidden → visible is a valid
    // publish, since `hidden` is a live state).
    let base = serve_state(r#"{"id":"x","state":"hidden","channel":"inbox"}"#, 200);
    let cfg = write_service_config(tmp.path(), &inbox, &base);

    let args = gdi_dataset_tool::cli::PublishArgs {
        management_url: None,
        id: ID.to_owned(),
        s3: false,
        local: false,
        inbox: None,
        format: gdi_dataset_tool::cli::OutputFormat::Text,
    };
    // Drive the command: resolves channel via the management plane, writes the
    // inbox sidecar.
    cmd_publish::run(&args, true, Some("default"), Some(cfg.as_path())).unwrap();

    // The inbox sidecar must contain "visible".
    let sidecar_path = inbox.join(format!("{ID}{STATE_SUFFIX}"));
    let body = fs::read_to_string(&sidecar_path).unwrap();
    assert!(
        body.contains(r#""state":"visible""#),
        "sidecar must be visible after publish; got: {body}"
    );
}

/// command-driven: `unpublish` is the same entry point with `make_visible = false`, and
/// it must write `hidden` where `publish` writes `visible`.
///
/// `unpublish` has no `cmd_unpublish` module: `lib.rs` routes it to
/// `cmd_publish::run(&args, false, ..)`. Without a test that passes `false`, inverting or
/// ignoring `make_visible` in the handler would change nothing observable.
#[test]
fn unpublish_routes_to_inbox_channel_and_writes_hidden() {
    let tmp = tempfile::tempdir().unwrap();
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&inbox).unwrap();

    // Node reports the id visible on the inbox channel — the state unpublish acts on.
    let base = serve_state(r#"{"id":"x","state":"visible","channel":"inbox"}"#, 200);
    let cfg = write_service_config(tmp.path(), &inbox, &base);

    let args = gdi_dataset_tool::cli::PublishArgs {
        management_url: None,
        id: ID.to_owned(),
        s3: false,
        local: false,
        inbox: None,
        format: gdi_dataset_tool::cli::OutputFormat::Text,
    };
    cmd_publish::run(&args, false, Some("default"), Some(cfg.as_path())).unwrap();

    let sidecar_path = inbox.join(format!("{ID}{STATE_SUFFIX}"));
    let body = fs::read_to_string(&sidecar_path).unwrap();
    assert!(
        body.contains(r#""state":"hidden""#),
        "unpublish must write hidden; got: {body}"
    );
    // ...and specifically not the publish outcome, so an inverted or ignored
    // `make_visible` cannot pass by writing a sidecar of the wrong polarity.
    assert!(
        !body.contains(r#""state":"visible""#),
        "unpublish must not leave the dataset visible; got: {body}"
    );
}

/// command-driven: `publish --inbox <dir>` needs no tool profile.
///
/// `deploy --inbox` requires none either, so `publish` must not demand one: that would
/// end a profile-free deploy by handing the operator a next step that dies with "no
/// profiles configured". Naming the directory fully specifies the target; there is nothing
/// left for a profile to supply.
#[test]
fn publish_with_explicit_inbox_needs_no_profile() {
    let tmp = tempfile::tempdir().unwrap();
    let inbox = tmp.path().join("inbox");
    fs::create_dir_all(&inbox).unwrap();

    // A syntactically valid tool config that configures no profiles at all.
    let cfg = tmp.path().join("tool.toml");
    fs::write(&cfg, "country_code = \"EE\"\n").unwrap();

    let args = gdi_dataset_tool::cli::PublishArgs {
        management_url: None,
        id: ID.to_owned(),
        s3: false,
        local: false,
        inbox: Some(inbox.clone()),
        format: gdi_dataset_tool::cli::OutputFormat::Text,
    };
    cmd_publish::run(&args, true, None, Some(cfg.as_path()))
        .expect("--inbox must not require a [profiles.*] block");

    let body = fs::read_to_string(inbox.join(format!("{ID}{STATE_SUFFIX}"))).unwrap();
    assert!(
        body.contains(r#""state":"visible""#),
        "the sidecar must land in the explicitly named inbox; got: {body}"
    );
}

/// `--inbox` must not silently write a local sidecar for a dataset the node says lives on
/// S3 — the node would ignore it and the command would report success. `resolve_channel`
/// gives the node's view precedence over `--local`, so without a guard the explicitly named
/// directory would just be dropped on the floor.
#[test]
fn publish_inbox_flag_refuses_an_s3_owned_dataset() {
    let tmp = tempfile::tempdir().unwrap();
    let inbox = tmp.path().join("inbox");
    fs::create_dir_all(&inbox).unwrap();

    // The node authoritatively reports this id on an S3 channel.
    let base = serve_state(r#"{"id":"x","state":"hidden","channel":"primary"}"#, 200);
    let cfg = write_service_config(tmp.path(), &inbox, &base);

    let args = gdi_dataset_tool::cli::PublishArgs {
        management_url: None,
        id: ID.to_owned(),
        s3: false,
        local: false,
        inbox: Some(inbox.clone()),
        format: gdi_dataset_tool::cli::OutputFormat::Text,
    };
    let err = cmd_publish::run(&args, true, Some("default"), Some(cfg.as_path()))
        .expect_err("--inbox on an S3-owned dataset must not silently no-op");
    assert!(
        err.message.contains("owned by the S3 channel"),
        "must name the owning channel: {}",
        err.message
    );
    assert!(
        !inbox.join(format!("{ID}{STATE_SUFFIX}")).exists(),
        "no sidecar may be written when the channel is refused"
    );
}

#[test]
fn unpublish_routes_to_inbox_channel() {
    // The node reports the id live on the inbox channel.
    let base = serve_state(r#"{"id":"x","state":"visible","channel":"inbox"}"#, 200);
    let ns = block_on(state::probe_node_state(&base, ID))
        .unwrap()
        .unwrap();
    assert_eq!(ns.channel, Channel::Inbox);

    // Unpublish = write the inbox sidecar hidden.
    let tmp = tempfile::tempdir().unwrap();
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&inbox).unwrap();
    state::inbox_write_sidecar(&inbox, ID, r#"{"state":"hidden"}"#).unwrap();
    let body = std::fs::read_to_string(inbox.join(format!("{ID}{STATE_SUFFIX}"))).unwrap();
    assert_eq!(body, r#"{"state":"hidden"}"#);
}

#[test]
fn publish_refuses_a_non_live_id() {
    // The node reports the id as `processing` (not yet live).
    let base = serve_state(
        r#"{"id":"x","state":"processing","channel":"primary"}"#,
        200,
    );
    let ns = block_on(state::probe_node_state(&base, ID))
        .unwrap()
        .unwrap();
    assert!(
        !ns.is_live(),
        "processing is not live -> publish must refuse"
    );
}

#[test]
fn delete_s3_channel_removes_objects_and_bumps_marker() {
    let base = serve_state(r#"{"id":"x","state":"hidden","channel":"primary"}"#, 200);
    let ns = block_on(state::probe_node_state(&base, ID))
        .unwrap()
        .unwrap();
    assert_eq!(ns.channel, Channel::S3);
    assert!(!ns.is_visible(), "hidden -> delete allowed without --force");

    let store = mem_store();
    block_on(s3::upload_package_bytes(
        &store,
        &s3::PackageStore::new(store.clone()),
        ID,
        b"PKG".to_vec(),
        false,
    ))
    .unwrap();
    block_on(state::s3_delete(&store, ID)).unwrap();

    assert!(
        block_on(get_str(&store, &format!("{ID}{TAR_C4GH_SUFFIX}"))).is_none(),
        "package removed"
    );
    assert!(
        block_on(get_str(&store, &format!("{ID}{STATE_SUFFIX}"))).is_none(),
        "sidecar removed"
    );
    assert!(
        block_on(get_str(&store, MARKER_KEY)).is_some(),
        "marker bumped"
    );
}

/// command-driven: `cmd_delete::run` on an inbox-channel hidden dataset writes
/// the `{"state":"deleted"}` sidecar into the inbox.
///
/// Drives `cmd_delete::run` rather than `state::inbox_write_sidecar`, so the full command
/// path — channel routing and sidecar construction — is what is exercised.
#[test]
fn delete_inbox_channel_writes_deleted_sidecar() {
    let tmp = tempfile::tempdir().unwrap();
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&inbox).unwrap();

    // Node reports the id as hidden on the inbox channel.
    let base = serve_state(r#"{"id":"x","state":"hidden","channel":"inbox"}"#, 200);
    let cfg = write_service_config(tmp.path(), &inbox, &base);

    let args = gdi_dataset_tool::cli::DeleteArgs {
        id: ID.to_owned(),
        management_url: None,
        force: false,
        dry_run: false,
        s3: false,
        local: false,
        inbox: None,
        format: gdi_dataset_tool::cli::OutputFormat::Text,
    };
    cmd_delete::run(&args, Some("default"), Some(cfg.as_path())).unwrap();

    let body = fs::read_to_string(inbox.join(format!("{ID}{STATE_SUFFIX}"))).unwrap();
    assert_eq!(
        body, r#"{"schemaVersion":1,"state":"deleted"}"#,
        "deleted sidecar must be written by the command"
    );
}

/// command-driven: `cmd_delete::run` refuses a *visible* inbox dataset (without
/// `--force`), naming the visible state; with `--force` it writes
/// `{"state":"deleted","force":true}` into the inbox.
///
/// Drives `cmd_delete::run` for both branches rather than `state::probe_node_state` and
/// `state::inbox_write_sidecar`, so the refusal is asserted against the command and not
/// merely against the probe's return value.
#[test]
fn delete_refuses_a_visible_id_unless_forced() {
    // Refusal branch
    let tmp = tempfile::tempdir().unwrap();
    let inbox = tmp.path().join("inbox");
    std::fs::create_dir_all(&inbox).unwrap();

    // Node reports `visible` on the inbox channel.  The stub must serve two
    // requests (one refusal + one forced delete probe), so we spin two servers.
    let base_refuse = serve_state(r#"{"id":"x","state":"visible","channel":"inbox"}"#, 200);
    let cfg_refuse = write_service_config(tmp.path(), &inbox, &base_refuse);

    let args_no_force = gdi_dataset_tool::cli::DeleteArgs {
        id: ID.to_owned(),
        management_url: None,
        force: false,
        dry_run: false,
        s3: false,
        local: false,
        inbox: None,
        format: gdi_dataset_tool::cli::OutputFormat::Text,
    };
    let err =
        cmd_delete::run(&args_no_force, Some("default"), Some(cfg_refuse.as_path())).unwrap_err();
    assert!(
        err.message.contains("visible") || err.message.contains("use --force"),
        "refusal message must mention 'visible' or 'use --force'; got: {}",
        err.message
    );
    // Nothing was written.
    assert!(
        !inbox.join(format!("{ID}{STATE_SUFFIX}")).exists(),
        "no sidecar must be written on refusal"
    );

    // Forced branch
    let tmp2 = tempfile::tempdir().unwrap();
    let inbox2 = tmp2.path().join("inbox");
    std::fs::create_dir_all(&inbox2).unwrap();
    let base_force = serve_state(r#"{"id":"x","state":"visible","channel":"inbox"}"#, 200);
    let cfg_force = write_service_config(tmp2.path(), &inbox2, &base_force);

    let args_force = gdi_dataset_tool::cli::DeleteArgs {
        id: ID.to_owned(),
        management_url: None,
        force: true,
        dry_run: false,
        s3: false,
        local: false,
        inbox: None,
        format: gdi_dataset_tool::cli::OutputFormat::Text,
    };
    cmd_delete::run(&args_force, Some("default"), Some(cfg_force.as_path())).unwrap();

    let body = fs::read_to_string(inbox2.join(format!("{ID}{STATE_SUFFIX}"))).unwrap();
    assert!(
        body.contains(r#""state":"deleted""#) && body.contains(r#""force":true"#),
        "forced delete sidecar must carry force:true; got: {body}"
    );
}

#[test]
fn probe_unreachable_node_yields_no_authoritative_view() {
    // A port nothing is listening on -> connection refused -> None (fall back).
    let ns = block_on(state::probe_node_state("http://127.0.0.1:1", ID)).unwrap();
    assert!(ns.is_none());
}

/// Spin up a one-request HTTP/1.1 server on an ephemeral loopback port answering
/// any request with `status` + JSON `body`, then return its base URL.
fn serve_state(body: &str, status: u16) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let body = body.to_owned();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
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

/// The profile-less `--inbox` delete must refuse when it cannot confirm visibility.
///
/// This is the invocation the no-config track prescribes. With no tool config there is no
/// `management_url`, so the state oracle is absent and the visible-guard has nothing to
/// check. Proceeding there would destroy a publicly-served dataset at exit 0 with no
/// `--force`.
///
/// The two escape hatches are asserted alongside, so the refusal cannot later be "fixed" by
/// making the path unusable.
#[test]
fn profile_less_inbox_delete_refuses_when_visibility_is_unconfirmable() {
    let tmp = tempfile::tempdir().unwrap();
    let inbox = tmp.path().join("inbox");
    fs::create_dir_all(&inbox).unwrap();

    // No config path and no profile: exactly `gdi-dataset-tool delete <id> --inbox <dir>`.
    let args = gdi_dataset_tool::cli::DeleteArgs {
        id: ID.to_owned(),
        management_url: None,
        force: false,
        dry_run: false,
        s3: false,
        local: false,
        inbox: Some(inbox.clone()),
        format: gdi_dataset_tool::cli::OutputFormat::Text,
    };
    let err = cmd_delete::run(&args, None, None).unwrap_err();
    assert!(
        err.message.contains("cannot confirm"),
        "the refusal must name the UNCONFIRMABLE case, not the visible one — the remedy \
         differs (--management-url, not `unpublish`); got: {}",
        err.message
    );
    assert!(
        !inbox.join(format!("{ID}{STATE_SUFFIX}")).exists(),
        "no delete sidecar may be written when the guard could not run"
    );

    // Escape hatch 1: --force still deletes, because the operator said so explicitly.
    let forced = gdi_dataset_tool::cli::DeleteArgs {
        force: true,
        ..args
    };
    cmd_delete::run(&forced, None, None).unwrap();
    let body = fs::read_to_string(inbox.join(format!("{ID}{STATE_SUFFIX}"))).unwrap();
    assert!(
        body.contains(r#""state":"deleted""#) && body.contains(r#""force":true"#),
        "--force must remain a working escape hatch; got: {body}"
    );
}

/// Escape hatch 2: `--management-url` gives the profile-less path an oracle, so the guard
/// runs for real rather than being bypassed.
///
/// Without this flag the only way past the refusal above is `--force`, which skips the
/// check entirely — that is, the safe path would be unreachable and every operator pushed
/// onto the unsafe one.
#[test]
fn profile_less_inbox_delete_can_reach_an_oracle_via_management_url() {
    let tmp = tempfile::tempdir().unwrap();
    let inbox = tmp.path().join("inbox");
    fs::create_dir_all(&inbox).unwrap();

    let base = serve_state(r#"{"id":"x","state":"visible","channel":"inbox"}"#, 200);
    let args = gdi_dataset_tool::cli::DeleteArgs {
        id: ID.to_owned(),
        management_url: Some(base),
        force: false,
        dry_run: false,
        s3: false,
        local: false,
        inbox: Some(inbox.clone()),
        format: gdi_dataset_tool::cli::OutputFormat::Text,
    };
    let err = cmd_delete::run(&args, None, None).unwrap_err();
    // The two refusals both contain the word "visible" ("cannot confirm whether dataset x is
    // currently visible"), so a bare `contains("visible")` passes whether or not the flag
    // reached the oracle. Assert the confirmed-visible wording and the absence of the
    // unconfirmable one.
    assert!(
        err.message.contains("reads as visible") && !err.message.contains("cannot confirm"),
        "with an oracle reachable the guard must report the VISIBLE refusal, proving it \
         actually consulted the node; got: {}",
        err.message
    );
    assert!(
        !inbox.join(format!("{ID}{STATE_SUFFIX}")).exists(),
        "no sidecar on refusal"
    );
}
