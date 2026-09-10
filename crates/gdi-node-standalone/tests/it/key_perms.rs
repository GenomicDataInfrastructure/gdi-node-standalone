//! `[service].strict_key_perms` gate: a group/other-readable crypt4gh identity
//! file must refuse startup under `strict_key_perms`, load (with a warning) when
//! it's off, and an owner-only key passes either way. Unix-only — the permission
//! check is a no-op elsewhere.
#![cfg(unix)]
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use gdi_node_standalone::identities::NodeIdentities;
use gdi_node_standalone_core::config::ServiceConfig;
use gdi_node_standalone_core::crypt4gh::{generate_keypair, serialize_secret_key};

/// Write a fresh crypt4gh identity PEM at `mode`.
fn write_key(dir: &Path, mode: u32) -> PathBuf {
    let path = dir.join("node.c4gh");
    let (sk, _pk) = generate_keypair();
    std::fs::write(&path, serialize_secret_key(&sk)).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}

fn config(data_dir: &Path, key: &Path, strict: bool) -> ServiceConfig {
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"
strict_key_perms = {strict}

[beacon]
id = "org.test.beacon"
name = "Test Beacon"

[keys]
identities = ["{}"]
"#,
        data_dir.display(),
        key.display(),
    );
    ServiceConfig::from_toml_str(&toml).unwrap()
}

#[test]
fn strict_refuses_group_other_readable_key() {
    let dir = tempfile::tempdir().unwrap();
    let key = write_key(dir.path(), 0o644); // group/other-readable
    // `NodeIdentities` is not `Debug`, so bind the error directly.
    let Err(err) = NodeIdentities::load(&config(dir.path(), &key, true)) else {
        panic!("a 0644 key must be refused under strict_key_perms");
    };
    let msg = err.to_string();
    assert!(msg.contains("strict_key_perms"), "unexpected error: {msg}");
    assert!(
        msg.contains("group/other-readable"),
        "unexpected error: {msg}"
    );
}

#[test]
fn non_strict_loads_group_other_readable_key() {
    let dir = tempfile::tempdir().unwrap();
    let key = write_key(dir.path(), 0o644);
    let ids = NodeIdentities::load(&config(dir.path(), &key, false))
        .expect("non-strict must load a loose-perm key (warn only)");
    assert!(ids.is_enabled(), "the single identity loaded");
}

#[test]
fn strict_accepts_owner_only_key() {
    let dir = tempfile::tempdir().unwrap();
    let key = write_key(dir.path(), 0o600); // owner-only
    let ids = NodeIdentities::load(&config(dir.path(), &key, true))
        .expect("a 0600 key passes even under strict_key_perms");
    assert!(ids.is_enabled());
}

#[derive(Clone)]
struct LogBuf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
impl std::io::Write for LogBuf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Capture JSON `tracing` output emitted on the calling thread while `f` runs. This repeats
/// the `audit.rs` idiom, whose capture harness is module-private.
fn capture<R>(f: impl FnOnce() -> R) -> (String, R) {
    use tracing_subscriber::layer::SubscriberExt as _;
    // Keep this thread-local capture reliable under the parallel harness (see helper docs).
    crate::fixtures::ensure_capture_safe_tracing();
    let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let w = LogBuf(std::sync::Arc::clone(&buf));
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .json()
            .with_writer(move || w.clone()),
    );
    let r = tracing::subscriber::with_default(subscriber, f);
    let logs = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
    (logs, r)
}

#[test]
fn loose_perms_load_logs_path_not_key_bytes() {
    // A group/other-readable key under the non-strict setting warns about the path and the
    // mode, but the key material must never reach the log stream.
    let dir = tempfile::tempdir().unwrap();
    let key = write_key(dir.path(), 0o644);
    let pem = std::fs::read_to_string(&key).unwrap();
    let (logs, res) = capture(|| NodeIdentities::load(&config(dir.path(), &key, false)));
    res.expect("non-strict must load a loose-perm key (warn only)");

    // The base64 key body (the secret) must not appear in the captured logs.
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    assert!(!body.is_empty(), "the PEM must have a base64 body");
    assert!(
        !logs.contains(&body),
        "key material leaked into logs: {logs}"
    );
}
