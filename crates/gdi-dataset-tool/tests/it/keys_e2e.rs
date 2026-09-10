//! End-to-end tests for `gdi-dataset-tool keys` (generate + show).
//!
//! The provider keypair is written under `$GDI_CONFIG_DIR`; that env var is
//! process-global, so these tests are `#[serial]`.
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::fs;
use std::path::Path;
use std::process::Command;

use clap::Parser as _;
use gdi_dataset_tool::cli::Cli;
use gdi_node_standalone_core::crypt4gh::{generate_keypair, serialize_public_key};
use serial_test::serial;

/// Run the built `gdi-dataset-tool` binary with `args`, `GDI_CONFIG_DIR` set to
/// `config_dir`, returning captured (stdout, success). Used to assert what
/// `keys show` prints (the in-process `run` would write to the inherited stdout).
fn run_tool_capture(config_dir: &Path, args: &[&str]) -> (String, bool) {
    let output = Command::new(env!("CARGO_BIN_EXE_gdi-dataset-tool"))
        .args(args)
        .env("GDI_CONFIG_DIR", config_dir)
        .output()
        .expect("spawn gdi-dataset-tool");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        output.status.success(),
    )
}

#[test]
#[serial(env)]
fn keys_generate_then_show_round_trips() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path());

    // generate
    let cli = Cli::try_parse_from(["gdi-dataset-tool", "keys", "generate"]).unwrap();
    gdi_dataset_tool::run(cli).expect("keys generate succeeds");

    // The secret file exists, 0o600 on Unix.
    let secret = tmp.path().join("keys/provider.c4gh");
    assert!(secret.is_file(), "provider secret must be written");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = fs::metadata(&secret).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "provider secret must be 0o600");
    }

    // The written recipient parses back to a valid public key.
    let pub_path = tmp.path().join("keys/provider.c4gh.pub");
    let pem = fs::read_to_string(&pub_path).unwrap();
    gdi_node_standalone_core::crypt4gh::parse_public_key(&pem).expect("recipient parses");

    // generate again without --force is refused (does not overwrite).
    let before = fs::read_to_string(&secret).unwrap();
    let cli = Cli::try_parse_from(["gdi-dataset-tool", "keys", "generate"]).unwrap();
    let err = gdi_dataset_tool::run(cli).expect_err("re-generate without --force fails");
    assert_eq!(err.exit_code, 1);
    assert_eq!(
        fs::read_to_string(&secret).unwrap(),
        before,
        "must not overwrite"
    );

    // --force backs the existing key up to a `.bak-<ts>` sibling, then replaces it.
    let cli = Cli::try_parse_from(["gdi-dataset-tool", "keys", "generate", "--force"]).unwrap();
    gdi_dataset_tool::run(cli).expect("keys generate --force succeeds");

    // The primary was regenerated (fresh material) ...
    assert_ne!(
        fs::read_to_string(&secret).unwrap(),
        before,
        "--force must write a fresh key"
    );
    // ... and the old secret + its recipient were preserved under a timestamped backup.
    let keys_dir = tmp.path().join("keys");
    let names: Vec<String> = fs::read_dir(&keys_dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    let secret_bak = names
        .iter()
        .find(|n| n.starts_with("provider.c4gh.bak-"))
        .unwrap_or_else(|| panic!("old secret key must be backed up; saw {names:?}"));
    assert!(
        names
            .iter()
            .any(|n| n.starts_with("provider.c4gh.pub.bak-")),
        "old recipient must be backed up; saw {names:?}"
    );
    assert_eq!(
        fs::read_to_string(keys_dir.join(secret_bak)).unwrap(),
        before,
        "the backup must hold the ORIGINAL key material"
    );

    // `keys show` loads the identity and does not error.
    let cli = Cli::try_parse_from(["gdi-dataset-tool", "keys", "show"]).unwrap();
    gdi_dataset_tool::run(cli).expect("keys show succeeds");
}

#[test]
#[serial(env)]
fn keys_show_prints_profile_node_recipient_offline() {
    // `keys show` prints the active profile's node recipient
    // (offline, from node_recipient_file). The binary is invoked so its stdout
    // can be captured.
    let tmp = tempfile::tempdir().unwrap();
    let config_dir = tmp.path().join("config");

    // A node recipient file the profile points at.
    let (_node_sk, node_pk) = generate_keypair();
    let node_pem = serialize_public_key(&node_pk);
    let recipient_file = tmp.path().join("node.c4gh.pub");
    fs::write(&recipient_file, &node_pem).unwrap();

    let cfg = tmp.path().join("tool.toml");
    fs::write(
        &cfg,
        format!(
            "[profiles.default]\nnode_recipient_file = \"{}\"\n",
            recipient_file.display()
        ),
    )
    .unwrap();

    let (stdout, ok) = run_tool_capture(
        &config_dir,
        &["--config", cfg.to_str().unwrap(), "keys", "show"],
    );
    assert!(ok, "keys show must succeed offline; stdout:\n{stdout}");
    assert!(
        stdout.contains("provider identity:"),
        "must print the provider identity path; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("node recipient:"),
        "must print the node recipient label; stdout:\n{stdout}"
    );
    // The node recipient's PEM body is printed verbatim.
    let node_body = node_pem.lines().nth(1).unwrap();
    assert!(
        stdout.contains(node_body),
        "must print the node recipient key material; stdout:\n{stdout}"
    );
}

#[test]
#[serial(env)]
fn keys_show_notes_unavailable_node_recipient() {
    // With no profile config (no URL/file), `keys show` must remain usable and
    // print an informational note rather than failing.
    let tmp = tempfile::tempdir().unwrap();
    let config_dir = tmp.path().join("config");

    let (stdout, ok) = run_tool_capture(&config_dir, &["keys", "show"]);
    assert!(
        ok,
        "keys show must succeed with no profile; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("node recipient: <unavailable"),
        "must note the node recipient is unavailable; stdout:\n{stdout}"
    );
}

#[test]
#[serial(env)]
fn keys_show_auto_generates_when_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path());

    // No prior generate: `show` auto-generates the identity on first use.
    let cli = Cli::try_parse_from(["gdi-dataset-tool", "keys", "show"]).unwrap();
    gdi_dataset_tool::run(cli).expect("keys show auto-generates");
    assert!(
        tmp.path().join("keys/provider.c4gh").is_file(),
        "show must create the identity if missing"
    );
}

#[test]
fn pin_recipient_fetches_and_writes_the_pin() {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

    let (_sk, pk) = generate_keypair();
    let pem = serialize_public_key(&pk);

    // One-shot loopback server returning the PEM.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let body = pem.clone();
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes());
            let _ = s.flush();
        }
    });

    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("node.pub");
    gdi_dataset_tool::run(clap::Parser::parse_from([
        "gdi-dataset-tool",
        "keys",
        "pin-recipient",
        "--url",
        &format!("http://{addr}/.well-known/c4gh-recipient"),
        "-o",
        out.to_str().unwrap(),
    ]))
    .expect("pin-recipient succeeds");

    let pinned = std::fs::read_to_string(&out).unwrap();
    assert_eq!(pinned, pem, "pinned file holds the served recipient PEM");
}

/// The air-gapped path: a recipient handed over as a file is pinned without any network,
/// a differing file is refused as a rotation, and `--force` adopts it. Without `--file`
/// the only way to adopt a rotated key offline is to delete the pin by hand.
#[test]
fn pin_recipient_pins_a_local_file_and_force_adopts_a_rotated_one() {
    let tmp = tempfile::tempdir().unwrap();
    let (_sk1, pk1) = generate_keypair();
    let (_sk2, pk2) = generate_keypair();
    let v1 = tmp.path().join("node-v1.pub");
    let v2 = tmp.path().join("node-v2.pub");
    std::fs::write(&v1, serialize_public_key(&pk1)).unwrap();
    std::fs::write(&v2, serialize_public_key(&pk2)).unwrap();
    let out = tmp.path().join("pins/node.pub");
    let pin = |file: &std::path::Path, force: bool| {
        let mut argv = vec![
            "gdi-dataset-tool".to_owned(),
            "keys".to_owned(),
            "pin-recipient".to_owned(),
            "--file".to_owned(),
            file.to_str().unwrap().to_owned(),
            "-o".to_owned(),
            out.to_str().unwrap().to_owned(),
        ];
        if force {
            argv.push("--force".to_owned());
        }
        gdi_dataset_tool::run(clap::Parser::parse_from(argv))
    };

    pin(&v1, false).expect("a first pin from a file succeeds offline");
    assert_eq!(
        std::fs::read_to_string(&out).unwrap(),
        serialize_public_key(&pk1)
    );

    let err = pin(&v2, false).expect_err("a differing key must be refused without --force");
    assert!(
        err.message.contains("differs") && err.message.contains("--file"),
        "the refusal names the rotation and the offline remedy: {}",
        err.message
    );
    assert_eq!(
        std::fs::read_to_string(&out).unwrap(),
        serialize_public_key(&pk1),
        "a refused rotation leaves the old pin in place"
    );

    pin(&v2, true).expect("--force adopts the rotated key");
    assert_eq!(
        std::fs::read_to_string(&out).unwrap(),
        serialize_public_key(&pk2)
    );
}

#[test]
fn pin_recipient_writes_a_relative_pin_next_to_the_config_not_the_cwd() {
    // `pin-recipient` must resolve a relative `node_recipient_file` the way every reader
    // (`pack`, `doctor`, `keys show`) does, against the config dir via
    // `Profile::node_recipient_path`, not against the process CWD. Resolving it against
    // the CWD lands the pin where nothing looks: `pack` then fails closed telling the
    // operator to run the command that just reported success, and after a genuine node-key
    // rotation `--force` writes a fresh CWD copy while the stale pin still governs.
    //
    // Asserted without touching the process CWD (this suite mutates no global state): the
    // pin must appear under the config dir, and the CWD-relative path must not be created.
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

    let (_sk, pk) = generate_keypair();
    let pem = serialize_public_key(&pk);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let body = pem.clone();
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes());
            let _ = s.flush();
        }
    });

    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("tool.toml");
    // A relative pin path, which is what the shipped `config init` template hands the
    // operator (`# node_recipient_file = "recipients/default.pub"`).
    let rel = "recipients/pinned-node.pub";
    std::fs::write(
        &cfg,
        format!("[profiles.default]\nnode_recipient_file = \"{rel}\"\n"),
    )
    .unwrap();

    let cwd_relative = std::path::Path::new(rel);
    assert!(
        !cwd_relative.exists(),
        "precondition: the CWD-relative pin path must not already exist"
    );

    gdi_dataset_tool::run(clap::Parser::parse_from([
        "gdi-dataset-tool",
        "--config",
        cfg.to_str().unwrap(),
        "keys",
        "pin-recipient",
        "--url",
        &format!("http://{addr}/.well-known/c4gh-recipient"),
    ]))
    .expect("pin-recipient succeeds");

    // Sample the CWD-relative path and clean it up before asserting: on a regression the
    // command writes a real file into the source tree, and a failing test must not leave
    // it behind. `remove_dir` (not `remove_dir_all`) so this can only delete a directory
    // this test created and left empty.
    let leaked = cwd_relative.exists();
    if leaked {
        let _ = std::fs::remove_file(cwd_relative);
        if let Some(parent) = cwd_relative.parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }

    let want = tmp.path().join(rel);
    assert!(
        want.is_file(),
        "the pin must land beside the CONFIG at {}, where every reader looks",
        want.display()
    );
    assert_eq!(std::fs::read_to_string(&want).unwrap(), pem);
    assert!(
        !leaked,
        "the pin must NOT be written relative to the process CWD"
    );
}
