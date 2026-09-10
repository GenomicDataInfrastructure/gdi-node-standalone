//! Process-level smoke of the service binary's non-serving subcommands.
//!
//! Every other test in this crate calls handler functions in-process, which leaves what an
//! operator or Docker invokes uncovered: argv parsing, the exit code, and what lands on
//! stdout and stderr.
//!
//! `healthcheck` is the sharpest of these. `Dockerfile`'s `HEALTHCHECK` runs
//! `["/gdi-node-standalone", "healthcheck"]`, so a build that always exits 0 marks every
//! container permanently healthy, and one that always exits non-zero crash-loops the
//! deployment. Neither is visible to an in-process test.
//!
//! `serve` is not covered here. It binds listeners and runs forever, so the Compose e2e in
//! `scripts/e2e/` is where it belongs.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The service binary under test, built by cargo for this integration target.
fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_gdi-node-standalone"))
}

/// A path relative to the workspace root.
///
/// Cargo runs this test binary with the package root (`crates/gdi-node-standalone/`) as the
/// working directory, so a bare relative name like `"node.example.toml"` does not resolve and
/// a subcommand handed one dies with "config file not found" instead of doing the thing under
/// test.
fn repo_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

/// `(exit code, stdout, stderr)` — the whole observable contract of a one-shot run.
fn run(args: &[&str]) -> (Option<i32>, String, String) {
    let out = bin()
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("spawning the service binary with {args:?}: {e}"));
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn version_exits_zero_and_names_the_binary_and_model_version() {
    let (code, stdout, stderr) = run(&["version"]);
    assert_eq!(code, Some(0), "version must succeed; stderr: {stderr}");
    assert!(
        stdout.starts_with("gdi-node-standalone "),
        "version names the binary: {stdout}"
    );
    // The pinned gdi-metadata model version is a build-time constant and part of the
    // published contract that aggregators read, so it must appear here.
    assert!(
        stdout.contains("gdi_metadata_version"),
        "version reports the pinned metadata model version: {stdout}"
    );
}

#[test]
fn config_dump_defaults_emits_reparseable_toml_with_no_config_file() {
    // Must work on a box with nothing deployed: it reads no config and touches no data dir.
    let (code, stdout, stderr) = run(&["config", "dump-defaults"]);
    assert_eq!(
        code,
        Some(0),
        "dump-defaults must succeed; stderr: {stderr}"
    );
    assert!(
        stdout.contains("[service]"),
        "dump-defaults emits the service section: {stdout}"
    );
    // Round-trip: whatever it prints must be loadable as the config it claims to be.
    let parsed: toml::Value = toml::from_str(&stdout)
        .unwrap_or_else(|e| panic!("dump-defaults emitted invalid TOML: {e}\n{stdout}"));
    assert!(
        parsed.get("service").is_some(),
        "parsed defaults carry [service]: {stdout}"
    );
}

/// `node.example.toml` is not deployable as shipped: it carries `<SET ME: …>` placeholders
/// for the S3 and Vault credential fields, so preflight rejects it on every build profile.
///
/// The config path has to be absolute. A bare `"node.example.toml"` resolves against the
/// package root, where the file is absent, and the binary then dies with `config check FAILED
/// (node.example.toml): config file not found`, which satisfies the exit-code, "config check
/// FAILED" and file-name assertions on its own. The `placeholder` assertion below is what
/// stops a "file not found" run from passing.
#[test]
fn check_config_rejects_the_shipped_example_and_says_why() {
    let example = repo_path("node.example.toml");
    assert!(
        example.exists(),
        "node.example.toml is missing at {} — without it this test would pass on the \
         'config file not found' error path instead of checking the verdict",
        example.display()
    );
    let (code, stdout, stderr) = run(&["--config", &example.to_string_lossy(), "check-config"]);
    assert_ne!(
        code,
        Some(0),
        "the shipped example must not pass check-config as-is; stdout: {stdout}"
    );
    assert!(
        stdout.contains("config check FAILED"),
        "check-config reports the verdict on stdout: {stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("node.example.toml"),
        "the verdict names the file it checked: {stdout}"
    );
    assert!(
        stdout.contains("placeholder"),
        "the verdict must be the PLACEHOLDER rejection, not an incidental failure such as a \
         missing file — that is the contract this test exists to pin: {stdout}"
    );
}

#[test]
fn healthcheck_fails_when_the_node_is_not_ready() {
    // The Dockerfile HEALTHCHECK path in the state that matters in a deployment: the
    // container is up and something is bound, but it is not serving a ready response.
    // `healthcheck` has to report failure, or every container is marked healthy whatever the
    // node is doing.
    //
    // The fixture is a listener that accepts and immediately drops, not a closed port.
    // `health_probe_ready` tries both loopback families and reports failure only after the
    // second, so on a host where `::1` is dropped rather than refused a closed port costs the
    // full 5 s connect timeout.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe port");
    let addr = listener.local_addr().expect("probe addr");
    let accepter = std::thread::spawn(move || {
        // One connection is enough: the probe makes a single attempt per address.
        // Read the request before closing. Dropping the stream immediately resets the
        // connection mid-write, and the probe then reports the reset rather than the
        // readiness verdict, which would make the assertion below pass for the wrong reason.
        if let Ok((mut stream, _)) = listener.accept() {
            use std::io::Read as _;
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf);
            drop(stream);
        }
    });
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = dir.path().join("config.toml");
    let (code, stdout, _) = run(&["config", "dump-defaults"]);
    assert_eq!(code, Some(0), "dump-defaults for the healthcheck fixture");
    // Point the management plane at the closed port: connection refused, promptly.
    let doctored = stdout.replace(
        "management_addr = \"127.0.0.1:9090\"",
        &format!("management_addr = \"{addr}\""),
    );
    assert_ne!(
        doctored, stdout,
        "the defaults must carry a management_addr for this test to redirect; got:\n{stdout}"
    );
    std::fs::write(&cfg, doctored).expect("write config");

    let (code, stdout, stderr) = run(&[
        "--config",
        cfg.to_str().expect("utf8 config path"),
        "healthcheck",
    ]);
    let _ = accepter.join();
    assert_ne!(
        code,
        Some(0),
        "healthcheck must fail against a node that is not serving ready — an always-zero \
         healthcheck marks every container permanently healthy.\nstdout: {stdout}\nstderr: \
         {stderr}"
    );
    // ...and it must fail for the right reason. Asserting only the exit code would be
    // satisfied by a config-load error, that is, by never reaching the probe at all, which
    // would let a broken probe hide behind a green test.
    assert!(
        stderr.contains("not ready"),
        "healthcheck must reach the readiness probe and report its verdict, not fail \
         earlier: {stderr}"
    );
}

/// Writes a minimal deployable config into `dir` and returns its path.
///
/// `node.example.toml` cannot serve here. It is not deployable as shipped, so `check-config`
/// never reaches the summary block on it.
fn minimal_config(dir: &Path, opt_ins_on: bool) -> PathBuf {
    let data = dir.join("data");
    let inbox = dir.join("inbox");
    std::fs::create_dir_all(&data).expect("creating the data dir");
    std::fs::create_dir_all(&inbox).expect("creating the inbox");
    // Paths come from `tempfile`, so they carry no quote or backslash to escape.
    let (data, inbox) = (data.display(), inbox.display());
    let on = if opt_ins_on { "true" } else { "false" };
    let floor = if opt_ins_on { 5 } else { 0 };
    let body = format!(
        "[service]\n\
         base_url = \"https://node.example.org\"\n\
         data_dir = \"{data}\"\n\
         inbox = \"{inbox}\"\n\
         expose_dataset_list = {on}\n\
         [beacon]\n\
         id = \"ee.example.af-beacon.production\"\n\
         name = \"Example Node\"\n\
         min_allele_count = {floor}\n\
         [beacon.organization]\n\
         id = \"org.example\"\n\
         name = \"Example Org\"\n\
         [stats]\n\
         enabled = {on}\n\
         [control]\n\
         enabled = {on}\n"
    );
    let path = dir.join("node.toml");
    std::fs::write(&path, body).expect("writing the minimal config");
    path
}

/// `check-config` is the documented pre-deploy gate: it lets an operator see the posture
/// before applying it. Three opt-ins change what the management plane mounts, namely the full
/// inventory including hidden datasets, the per-dataset query counters, and three
/// unauthenticated action endpoints. A fourth setting disables small-count suppression.
///
/// This pins that the summary discriminates on all four. It is not a wording test: the
/// assertions are that the on-run and the off-run differ, and that each states the
/// consequence, so an operator reading the dry run can tell the two postures apart.
#[test]
fn check_config_summary_discriminates_the_management_plane_opt_ins() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let on_dir = tmp.path().join("on");
    let off_dir = tmp.path().join("off");
    std::fs::create_dir_all(&on_dir).expect("on dir");
    std::fs::create_dir_all(&off_dir).expect("off dir");

    let on_cfg = minimal_config(&on_dir, true);
    let off_cfg = minimal_config(&off_dir, false);

    let (on_code, on_out, on_err) = run(&["--config", &on_cfg.to_string_lossy(), "check-config"]);
    let (off_code, off_out, off_err) =
        run(&["--config", &off_cfg.to_string_lossy(), "check-config"]);
    assert_eq!(
        on_code,
        Some(0),
        "opt-ins-on config must check OK: {on_err}"
    );
    assert_eq!(
        off_code,
        Some(0),
        "opt-ins-off config must check OK: {off_err}"
    );

    for key in [
        "mgmt_inventory",
        "mgmt_stats",
        "mgmt_control",
        "k_anon_floor",
    ] {
        let on_line = summary_line(&on_out, key);
        let off_line = summary_line(&off_out, key);
        assert_ne!(
            on_line, off_line,
            "`{key}` must differ between the opt-in-on and opt-in-off runs, or the dry run \
             cannot show the operator which posture they are about to deploy\n\
             ON : {on_line}\nOFF: {off_line}"
        );
    }

    // Each on line states the consequence rather than echoing `true`, so an operator who has
    // never read the config reference can act on the dry run alone.
    assert!(
        summary_line(&on_out, "mgmt_inventory").contains("hidden"),
        "the inventory line says hidden datasets are enumerated: {on_out}"
    );
    assert!(
        summary_line(&on_out, "mgmt_control").contains("UNAUTHENTICATED"),
        "the control line says the action endpoints are unauthenticated: {on_out}"
    );
    // ...and names every action endpoint, from the one list the router is bound to. A
    // partial list tells an operator less than the plane mounts.
    for route in gdi_node_standalone::app::CONTROL_ROUTES {
        assert!(
            summary_line(&on_out, "mgmt_control").contains(route),
            "the control line must name {route}: {on_out}"
        );
    }
    assert!(
        summary_line(&off_out, "k_anon_floor").contains("DISABLED"),
        "a zero floor is reported as suppression DISABLED, not as the number 0: {off_out}"
    );
}

/// The `  key = value` line for `key`, or a marker naming the miss.
fn summary_line(stdout: &str, key: &str) -> String {
    stdout
        .lines()
        .find(|l| l.trim_start().starts_with(key))
        .map_or_else(
            || format!("<no `{key}` line in the summary>"),
            str::to_owned,
        )
}

/// A refused start is a log event, not a terminal message. The serving process's stderr is a
/// log stream, and a refused start (here an unreadable config, the same exit path as an
/// override-store or identity refusal) is the one fatal class no metric rule can see, because
/// the process is gone before `/metrics` exists. It lands as one structured, `Alert`-tagged
/// line a log rule can route with the reason, keeping the "all stderr is NDJSON" promise the
/// panic hook makes.
#[test]
fn a_refused_start_is_one_alert_tagged_json_line() {
    assert_refused_start_is_one_alert_tagged_json_line(&[]);
}

/// The explicit `serve` subcommand is the same serving process, so its refusal takes the same
/// log-event shape rather than the plain `Error:` report a one-shot verb gets.
#[test]
fn an_explicit_serve_refused_start_is_the_same_alert_tagged_json_line() {
    assert_refused_start_is_one_alert_tagged_json_line(&["serve"]);
}

fn assert_refused_start_is_one_alert_tagged_json_line(args: &[&str]) {
    let out = bin()
        .args(args)
        .env("GDI_CONFIG", "/nonexistent/gdi-node-standalone/node.toml")
        .env("LOG_FORMAT", "json")
        .output()
        .expect("spawning the service binary");
    assert_eq!(out.status.code(), Some(1), "a refused start exits 1");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let last = stderr
        .lines()
        .rfind(|l| !l.trim().is_empty())
        .unwrap_or_else(|| panic!("stderr must carry the refusal: {stderr:?}"));
    let line: serde_json::Value = serde_json::from_str(last)
        .unwrap_or_else(|e| panic!("the refusal must be one JSON line ({e}): {last:?}"));
    assert_eq!(line["level"], "ERROR", "{line}");
    assert_eq!(line["tags"], serde_json::json!(["Alert"]), "{line}");
    assert_eq!(line["event.action"], "startup", "{line}");
    assert_eq!(line["event.outcome"], "failure", "{line}");
    let error = line["error"].as_str().unwrap_or_default();
    assert!(
        error.contains("loading config"),
        "the cause chain must travel in `error`: {line}"
    );
    assert_eq!(line["service.name"], "gdi-node-standalone", "{line}");
}

/// Under `LOG_FORMAT=ecs` the same refusal takes the ECS envelope the other lines use.
#[test]
fn a_refused_start_under_ecs_takes_the_ecs_envelope() {
    let out = bin()
        .env("GDI_CONFIG", "/nonexistent/gdi-node-standalone/node.toml")
        .env("LOG_FORMAT", "ecs")
        .output()
        .expect("spawning the service binary");
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    let last = stderr
        .lines()
        .rfind(|l| !l.trim().is_empty())
        .unwrap_or_default();
    let line: serde_json::Value =
        serde_json::from_str(last).unwrap_or_else(|e| panic!("not JSON ({e}): {last:?}"));
    assert_eq!(line["log.level"], "error", "{line}");
    assert_eq!(line["tags"], serde_json::json!(["Alert"]), "{line}");
    assert_eq!(line["event.action"], "startup", "{line}");
    assert_eq!(line["event.outcome"], "failure", "{line}");
    assert!(line["error.message"].is_string(), "{line}");
    assert_eq!(line["ecs.version"], "8.11.0", "{line}");
}

/// A subcommand is an operator at a terminal, so its failure keeps the plain `Error:` report
/// a human expects. Only the serving path's refusal is a log event.
#[test]
fn a_subcommand_failure_keeps_the_plain_error_report() {
    let (code, _stdout, stderr) = run(&["--config", "/nonexistent/node.toml", "check-config"]);
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("Error:"),
        "a one-shot verb reports like a CLI tool: {stderr:?}"
    );
    assert!(
        !stderr.contains("\"Alert\""),
        "a one-shot verb is not an alarm: {stderr:?}"
    );
}
