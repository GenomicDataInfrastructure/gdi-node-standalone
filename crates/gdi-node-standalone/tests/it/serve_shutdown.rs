//! Process-level check of the serving binary's exit: SIGTERM, drain, quiesce,
//! `service.stopped`, exit 0, promptly, from any point after the first bind.
//!
//! `binary_cli.rs` covers the one-shot verbs but not `serve`, and the Compose e2e boots the
//! real stack without timing the exit. This boots the binary on ephemeral ports with an empty
//! data dir, so the drain is immediate and what is measured is the whole path from SIGTERM to
//! exit.
//!
//! Two arrival times are covered: after the public plane demonstrably serves
//! ([`sigterm_exits_zero_promptly_and_logs_service_stopped`]) and at the very first
//! listener log line, while startup is still running
//! ([`sigterm_at_the_first_listen_line_still_drains`]).
//!
//! Unix-only: it sends SIGTERM through `kill(1)` (no libc/nix dependency in this crate).

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read as _, Write as _};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The structured marker a plane logs when its listener is bound, on both planes.
///
/// The gate matches this marker, not the word "listening" in the human message: `event.action`
/// is set at exactly the two bind sites, so a future prose log line that happens to say
/// "listening" cannot satisfy the gate and let a test signal before anything is bound.
const LISTEN_EVENT: &str = r#""event.action":"service.listen""#;

/// Two distinct free loopback ports for the public and management planes.
///
/// Port `0` cannot be written into the config: `ServiceConfig::preflight` refuses a
/// `management_addr` that equals `listen`, and `"127.0.0.1:0"` is byte-identical to
/// itself. So the ports are chosen here, the probe listeners dropped, and the concrete
/// numbers written into the TOML.
fn two_free_ports() -> (u16, u16) {
    let public = std::net::TcpListener::bind("127.0.0.1:0").expect("bind public probe port");
    let mgmt = std::net::TcpListener::bind("127.0.0.1:0").expect("bind management probe port");
    let ports = (
        public.local_addr().expect("public probe addr").port(),
        mgmt.local_addr().expect("management probe addr").port(),
    );
    drop(public);
    drop(mgmt);
    ports
}

/// Kills and reaps the node on drop, so a panic anywhere in this test cannot leave a serving
/// process behind.
///
/// `std::process::Child` does not kill on drop, but `tempfile::TempDir` does delete on drop.
/// Without this guard, an assertion that fires before the `kill -TERM`, such as the
/// listener-log `recv_timeout` or `await_serving`'s deadline, would unwind, delete the data
/// dir, and leave an orphaned node holding a listener and an unlinked flock. It is redundant
/// on the happy path, which waits for the exit and asserts its code.
struct ChildGuard(std::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// One `GET /health/live` against a bound plane, returning the raw response bytes.
///
/// `Connection: close` so the server ends the body by closing, which makes
/// `read_to_end` a complete read without parsing `Content-Length`.
fn probe_once(port: u16) -> std::io::Result<Vec<u8>> {
    let mut sock = TcpStream::connect(("127.0.0.1", port))?;
    sock.set_read_timeout(Some(Duration::from_secs(5)))?;
    sock.write_all(b"GET /health/live HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")?;
    let mut body = Vec::new();
    sock.read_to_end(&mut body)?;
    Ok(body)
}

/// Serve two sequential requests off `port` before the test signals the process.
///
/// A listen log line says only that the socket is bound. `serve_http` logs it, then builds
/// the router, and only then does `serve_bounded`'s accept loop run. Two sequential responses
/// show the loop has gone round with nothing queued, so every `select!` branch, including the
/// shutdown one, has been polled. That is the "fully up" arrival time, as opposed to the
/// unsynchronised one [`sigterm_at_the_first_listen_line_still_drains`] takes.
///
/// The status does not matter, since the public plane answers `/health/live` with 404, only
/// that a well-formed reply came back.
fn await_serving(port: u16, deadline: Instant) {
    for _ in 0..2 {
        loop {
            match probe_once(port) {
                Ok(body) if body.starts_with(b"HTTP/1.1 ") => break,
                Ok(_) | Err(_) => {
                    assert!(
                        Instant::now() < deadline,
                        "the node must answer on 127.0.0.1:{port} before the deadline"
                    );
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
    }
}

/// The smallest config that boots a serving node: an empty data dir (keyless, no ingest
/// channel), both planes on loopback, and a drain short enough that the whole test is
/// bounded. Returns the config path.
fn write_config(dir: &std::path::Path, public_port: u16, mgmt_port: u16) -> std::path::PathBuf {
    let data_dir = dir.join("datasets");
    std::fs::create_dir_all(&data_dir).expect("data dir");
    // `.display()` inside explicit quotes is the suite's idiom for a path in generated TOML
    // (`binary_cli.rs`, `config_examples.rs`); a `tempdir` path carries nothing TOML needs
    // escaped.
    let data_dir = data_dir.display().to_string();
    let config_path = dir.join("node.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"
[service]
listen = "127.0.0.1:{public_port}"
management_addr = "127.0.0.1:{mgmt_port}"
base_url = "http://localhost:{public_port}"
data_dir = "{data_dir}"
shutdown_drain_seconds = 3
# Preflight refuses `request_timeout_seconds > shutdown_drain_seconds`, and the default
# is 30 — so shortening the drain here means shortening the request timeout with it.
request_timeout_seconds = 3

[beacon]
id = "org.test.beacon"
name = "Test"
"#
        ),
    )
    .expect("config");
    config_path
}

/// A spawned serving node and everything a test needs to drive it to exit.
///
/// Field order matters. Struct fields drop in declaration order, so `node`, the
/// [`ChildGuard`] that kills and reaps, drops before `_dir`, and the data dir the node is
/// writing to outlives the process instead of being deleted under it.
struct ServingNode {
    /// The node process, killed and reaped on drop.
    node: ChildGuard,
    /// The public data plane's port.
    public_port: u16,
    /// The management plane's port.
    mgmt_port: u16,
    /// Every stderr line as it is read, to gate on a log event.
    lines: mpsc::Receiver<String>,
    /// The stderr reader thread. Joining it yields the whole log, and returns only once
    /// stderr closes, that is, after the process exits.
    reader: std::thread::JoinHandle<String>,
    /// The config file and data dir. Held only to keep them on disk for the process'
    /// lifetime, and dropped last — see the type doc.
    _dir: tempfile::TempDir,
}

/// Boot the serving binary on two free loopback ports with an empty data dir.
///
/// Returns as soon as the process is spawned, with no startup yet observed, which is what the
/// first-listen-line test needs. `GDI_LOG` is pinned because the assertions read `INFO` events
/// off stderr, and an inherited `GDI_LOG` or `RUST_LOG` would silence them.
fn spawn_serving_node() -> ServingNode {
    let dir = tempfile::tempdir().expect("tempdir");
    let (public_port, mgmt_port) = two_free_ports();
    let config_path = write_config(dir.path(), public_port, mgmt_port);

    let mut node = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_gdi-node-standalone"))
            .args([
                "--config",
                config_path.to_str().expect("utf-8 path"),
                "serve",
            ])
            .env_remove("GDI_CONFIG")
            .env("GDI_LOG", "info")
            .env_remove("RUST_LOG")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn serve"),
    );
    let stderr = node.0.stderr.take().expect("piped stderr");

    // A reader thread forwards every log line as it arrives and accumulates the whole
    // log: a test needs the former to gate on and the latter to assert against.
    let (tx, rx) = mpsc::channel::<String>();
    let reader = std::thread::spawn(move || {
        let mut all = String::new();
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            all.push_str(&line);
            all.push('\n');
            let _ = tx.send(line);
        }
        all
    });

    ServingNode {
        node,
        public_port,
        mgmt_port,
        lines: rx,
        reader,
        _dir: dir,
    }
}

/// Send SIGTERM to `pid` through `kill(1)`, asserting the signal was delivered.
fn kill_term(pid: u32) {
    let status = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .expect("kill(1) available");
    assert!(status.success(), "kill -TERM failed: {status}");
}

/// Reap `child`, failing the test if it has not exited within `budget`.
///
/// Polls rather than blocking in `wait`, so the budget is enforced here — a hang is a
/// named failure instead of the harness' own timeout with nothing said about the cause.
fn wait_with_deadline(
    child: &mut std::process::Child,
    budget: Duration,
) -> std::process::ExitStatus {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return status;
        }
        assert!(
            start.elapsed() < budget,
            "the node did not exit within {budget:?} of SIGTERM"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn sigterm_exits_zero_promptly_and_logs_service_stopped() {
    let mut node = spawn_serving_node();

    // Wait for both listeners.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut seen_public = false;
    let mut seen_mgmt = false;
    while !(seen_public && seen_mgmt) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let line = node
            .lines
            .recv_timeout(remaining)
            .expect("the node must log both listeners within 30 s");
        seen_public |= line.contains("HTTP server listening");
        seen_mgmt |= line.contains("management plane listening");
    }
    // Both accept loops must be live before the signal — see `await_serving`.
    await_serving(node.mgmt_port, deadline);
    await_serving(node.public_port, deadline);

    let sent = Instant::now();
    kill_term(node.node.0.id());

    // Drain 3 s max (idle → immediate) + management stop 2 s + quiesce 0 → well under 15 s.
    let exit = wait_with_deadline(&mut node.node.0, Duration::from_secs(15));
    let elapsed = sent.elapsed();
    let logs = node.reader.join().expect("reader thread");

    assert_eq!(
        exit.code(),
        Some(0),
        "clean SIGTERM exit is 0; logs:\n{logs}"
    );
    assert!(
        logs.contains("service.drained"),
        "drain logged; logs:\n{logs}"
    );
    assert!(
        logs.contains("service.stopped"),
        "stop logged; logs:\n{logs}"
    );
    assert!(
        logs.contains("teardown_ms"),
        "teardown duration logged; logs:\n{logs}"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "exit took {elapsed:?}; the teardown after the drain must be bounded"
    );
}

#[test]
fn sigterm_at_the_first_listen_line_still_drains() {
    // Everything from the first bind to the serve loop's first poll is a stretch in which a
    // handler installed by the future that loop polls would not yet exist, so the signal would
    // take its default disposition: exit 143, no drain, no `service.stopped`. Armed in `run`
    // before any bind, the signal is buffered by tokio and honoured at that first poll. Three
    // rounds, because where inside the stretch the signal lands varies with scheduling.
    for round in 0..3 {
        let mut node = spawn_serving_node();
        // Gate on the first bind event, whichever plane binds first, without waiting for
        // that plane to answer. This test is about the arrival time `await_serving` excludes.
        loop {
            let line = node
                .lines
                .recv_timeout(Duration::from_secs(30))
                .expect("the node must log a listener within 30 s");
            if line.contains(LISTEN_EVENT) {
                break;
            }
        }
        kill_term(node.node.0.id());

        let exit = wait_with_deadline(&mut node.node.0, Duration::from_secs(15));
        let logs = node.reader.join().expect("reader thread");
        assert_eq!(
            exit.code(),
            Some(0),
            "round {round}: SIGTERM at the first listen line must drain, not die on the \
             signal's default disposition; logs:\n{logs}"
        );
        assert!(
            logs.contains("service.drained") && logs.contains("service.stopped"),
            "round {round}: the drain and the stop must both be logged; logs:\n{logs}"
        );
    }
}
