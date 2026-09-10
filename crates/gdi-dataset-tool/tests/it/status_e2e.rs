//! Integration tests for `status`: the management-plane path (a loopback state
//! stub), the remote `_status/{id}.json` path over `InMemory` S3 (published state /
//! `unavailable`), and the freshness/diff signal — no Docker.
//!
//! These drive the CLI-independent library functions the `cmd_status` wrapper uses
//! (`state::probe_node_state`, `s3::package_etag`, `s3::read_status_object`,
//! `status::*`).

#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::fs;
use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::sync::Arc;

use gdi_dataset_tool::cli::StatusArgs;
use gdi_dataset_tool::commands::cmd_status;
use gdi_dataset_tool::s3::{self, STATUS_PREFIX, Store};
use gdi_dataset_tool::state::{self, Channel};
use gdi_dataset_tool::status::{self, NodeStatus, Sync};
use object_store::memory::InMemory;
use object_store::path::Path as ObjPath;
use object_store::{ObjectStoreExt, PutPayload};

const ID: &str = "GDI-EE-UTARTU-20260409143052837";

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

async fn put_status(store: &Store, id: &str, body: &str) {
    store
        .put(
            &ObjPath::from(format!("{STATUS_PREFIX}{id}.json")),
            PutPayload::from(body.as_bytes().to_vec()),
        )
        .await
        .unwrap();
}

#[test]
fn management_plane_reports_service_state_and_sync() {
    // The state endpoint reports the dataset visible on an S3 channel.
    let base = serve_state(r#"{"id":"x","state":"visible","channel":"primary"}"#, 200);
    let ns = block_on(state::probe_node_state(&base, ID))
        .unwrap()
        .unwrap();
    assert_eq!(ns.channel, Channel::S3);

    // A package present + no drift => in-sync.
    let store = mem_store();
    block_on(s3::upload_package_bytes(
        &store,
        &s3::PackageStore::new(store.clone()),
        ID,
        b"PKG".to_vec(),
        false,
    ))
    .unwrap();
    let etag = block_on(s3::package_etag(&store, ID)).unwrap();
    assert!(etag.is_some(), "InMemory yields an ETag");
    let sync = status::channel_sync(ns.channel, etag.is_some(), false);
    assert_eq!(sync, Sync::InSync);
}

#[test]
fn remote_status_path_reports_published_state() {
    // No management plane: read the node's writeback whose source_signature
    // matches the current package ETag -> the published state is authoritative.
    let store = mem_store();
    block_on(s3::upload_package_bytes(
        &store,
        &s3::PackageStore::new(store.clone()),
        ID,
        b"PKG".to_vec(),
        false,
    ))
    .unwrap();
    let etag = block_on(s3::package_etag(&store, ID)).unwrap().unwrap();
    block_on(put_status(
        &store,
        ID,
        // Built with serde, not `format!`: an ETag is an opaque token that legitimately
        // contains quotes (object_store >= 0.14.1 returns the RFC-correct `"0"` rather than
        // a bare `0`), and interpolating one into hand-written JSON produces invalid JSON.
        &serde_json::json!({
            "id": ID,
            "state": "visible",
            "source_signature": etag,
            "updated_at": "t",
        })
        .to_string(),
    ));

    let wb_bytes = block_on(s3::read_status_object(&store, ID))
        .unwrap()
        .unwrap();
    let wb = status::parse_writeback(&wb_bytes).unwrap();
    let st = status::remote_node_status(Some(&wb), Some(&etag));
    assert_eq!(
        st,
        NodeStatus::State {
            state: "visible".to_owned(),
            error_message: None
        }
    );
}

#[test]
fn remote_status_stale_signature_is_pending_drift() {
    let store = mem_store();
    block_on(s3::upload_package_bytes(
        &store,
        &s3::PackageStore::new(store.clone()),
        ID,
        b"NEW-PKG".to_vec(),
        false,
    ))
    .unwrap();
    let etag = block_on(s3::package_etag(&store, ID)).unwrap().unwrap();
    // The writeback is for an older package signature.
    block_on(put_status(
        &store,
        ID,
        &serde_json::json!({
            "id": ID,
            "state": "error",
            "error_message": "bad parquet",
            "source_signature": format!("old-{etag}"),
        })
        .to_string(),
    ));
    let wb_bytes = block_on(s3::read_status_object(&store, ID))
        .unwrap()
        .unwrap();
    let wb = status::parse_writeback(&wb_bytes).unwrap();
    let st = status::remote_node_status(Some(&wb), Some(&etag));
    assert_eq!(st, NodeStatus::Pending, "stale signature -> pending");
    // Pending is drift.
    assert_eq!(status::channel_sync(Channel::S3, true, true), Sync::Drifted);
}

#[test]
fn remote_status_no_writeback_is_unavailable() {
    // The bucket has write_status off (no `_status/{id}.json`).
    let store = mem_store();
    block_on(s3::upload_package_bytes(
        &store,
        &s3::PackageStore::new(store.clone()),
        ID,
        b"PKG".to_vec(),
        false,
    ))
    .unwrap();
    let wb_bytes = block_on(s3::read_status_object(&store, ID)).unwrap();
    assert!(wb_bytes.is_none());
    let st = status::remote_node_status(None, Some("etag"));
    assert_eq!(st, NodeStatus::Unavailable);
}

#[test]
fn diff_shows_package_etag_present() {
    // The diff's `package` aspect: present + an ETag when the package is in S3.
    let store = mem_store();
    block_on(s3::upload_package_bytes(
        &store,
        &s3::PackageStore::new(store.clone()),
        ID,
        b"PKG".to_vec(),
        false,
    ))
    .unwrap();
    let etag = block_on(s3::package_etag(&store, ID)).unwrap();
    assert!(etag.is_some(), "the diff reports the package ETag");

    // A missing package -> the sync is `missing`.
    let empty = mem_store();
    let missing_etag = block_on(s3::package_etag(&empty, ID)).unwrap();
    assert!(missing_etag.is_none());
    assert_eq!(
        status::channel_sync(Channel::S3, missing_etag.is_some(), false),
        Sync::Missing
    );
}

#[test]
fn inbox_dataset_has_no_remote_to_diff() {
    // An inbox-owned dataset reports sync: local (no S3 remote).
    assert_eq!(
        status::channel_sync(Channel::Inbox, false, false),
        Sync::Local
    );
}

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

// Orchestration tests: drive `cmd_status::run`, the real entry point, through a config
// file plus a loopback management-plane stub. The tests above cover the leaf helpers
// directly; these cover the wrapper that wires them together.

/// Write a minimal tool.toml config that points `management_url` at `mgmt_base`
/// and has no S3 bucket (so store=None, the no-network path after state lookup).
fn write_mgmt_config(dir: &std::path::Path, mgmt_base: &str) -> std::path::PathBuf {
    let cfg = dir.join("tool.toml");
    fs::write(
        &cfg,
        format!("[profiles.default]\nmanagement_url = \"{mgmt_base}\"\n"),
    )
    .unwrap();
    cfg
}

/// Write a minimal tool.toml config with an inbox path but no S3 (inbox-only node).
fn write_inbox_config(dir: &std::path::Path, inbox: &str) -> std::path::PathBuf {
    let cfg = dir.join("tool.toml");
    fs::write(&cfg, format!("[profiles.default]\ninbox = \"{inbox}\"\n")).unwrap();
    cfg
}

/// The management plane overrides the remote: `cmd_status::run` routes through
/// `probe_node_state` and propagates the authoritative state from the management plane
/// rather than from the S3 writeback. The observable outcome is exit 0.
#[test]
fn cmd_status_run_management_plane_reports_visible() {
    let tmp = tempfile::tempdir().unwrap();
    // One-shot state stub: returns `visible` on the S3 channel.
    let base = serve_state(
        &format!(r#"{{"id":"{ID}","state":"visible","channel":"primary"}}"#),
        200,
    );
    let cfg_path = write_mgmt_config(tmp.path(), &base);
    let args = StatusArgs {
        id: Some(ID.to_owned()),
        diff: false,
        all: false,
        format: gdi_dataset_tool::cli::OutputFormat::Text,
        management_url: None,
    };
    // run must succeed: management plane visible + no S3 (sync=missing is non-fatal).
    cmd_status::run(&args, None, Some(&cfg_path))
        .expect("cmd_status::run succeeds with management-plane visible state");
}

/// An inbox dataset has no S3 remote: `cmd_status::run` with an inbox-only profile and no
/// management-plane URL must succeed and report `sync: local`. Stdout is not captured here,
/// so the absence of an error is the observable outcome.
#[test]
fn cmd_status_run_inbox_only_profile_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let inbox = tmp.path().join("inbox");
    fs::create_dir_all(&inbox).unwrap();
    let cfg_path = write_inbox_config(tmp.path(), inbox.to_str().unwrap());
    let args = StatusArgs {
        id: Some(ID.to_owned()),
        diff: false,
        all: false,
        format: gdi_dataset_tool::cli::OutputFormat::Text,
        management_url: None,
    };
    // No management plane, no S3: the command falls through to infer_channel
    // (inbox configured → Channel::Inbox) and reports sync: local.
    cmd_status::run(&args, None, Some(&cfg_path))
        .expect("cmd_status::run succeeds for an inbox-only profile");
}

/// An unavailable management plane (500) degrades gracefully: `cmd_status::run` treats a
/// failed probe as "no authoritative state" and falls back to the remote writeback path,
/// which without S3 is `NodeStatus::Unavailable`.
#[test]
fn cmd_status_run_management_plane_error_degrades_gracefully() {
    let tmp = tempfile::tempdir().unwrap();
    let base = serve_state("internal error", 500);
    let cfg_path = write_mgmt_config(tmp.path(), &base);
    let args = StatusArgs {
        id: Some(ID.to_owned()),
        diff: false,
        all: false,
        format: gdi_dataset_tool::cli::OutputFormat::Text,
        management_url: None,
    };
    // A 500 from the management plane must not crash the command — it degrades
    // to the S3/remote path (which also has no data → unavailable/missing).
    cmd_status::run(&args, None, Some(&cfg_path))
        .expect("cmd_status::run degrades gracefully on management-plane 500");
}
