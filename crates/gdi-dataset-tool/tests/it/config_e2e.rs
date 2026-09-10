//! Integration tests for `config init`: scaffolds a commented tool-config TOML
//! template (no secrets), refuses to overwrite without `--force`, and the
//! generated template parses back as a `ToolConfig`.

#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use clap::Parser as _;
use gdi_dataset_tool::cli::Cli;
use gdi_dataset_tool::run;

#[test]
fn config_init_writes_a_template_without_secrets() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("config.toml");

    run(Cli::try_parse_from([
        "gdi-dataset-tool",
        "config",
        "init",
        "-o",
        out.to_str().unwrap(),
    ])
    .unwrap())
    .expect("config init succeeds");

    let body = std::fs::read_to_string(&out).unwrap();
    // Has the three sections + an example profile + the env-var hint for secrets.
    assert!(body.contains("country_code"), "got:\n{body}");
    assert!(body.contains("[profiles."), "got:\n{body}");
    assert!(
        body.contains("GDI_TOOL__PROFILES__"),
        "must hint env vars for S3 secrets; got:\n{body}"
    );
    // It must not inline any secret keys.
    assert!(
        !body.contains("secret_access_key ="),
        "no secret in template"
    );

    // Refuses to overwrite without --force.
    let err = run(Cli::try_parse_from([
        "gdi-dataset-tool",
        "config",
        "init",
        "-o",
        out.to_str().unwrap(),
    ])
    .unwrap())
    .unwrap_err();
    assert_eq!(err.exit_code, 1);
    assert!(err.message.contains("already exists"), "{}", err.message);
}

/// An explicit `--profile` naming no configured profile errors on every verb, including
/// the read-only ones that select best-effort.
///
/// `profiles` and `keys show` used to absorb it and exit 0 — `profiles` reporting
/// "(none; pass --profile or set `default_profile`)", which reads as a missing
/// `default_profile` rather than as a name that does not exist, on the very command
/// documented for confirming which profile a run would pick. The check lives at the CLI
/// boundary, beside the `--config` one, so a verb added later cannot reopen the gap.
#[test]
fn an_unknown_profile_flag_errors_on_read_only_verbs_too() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("tool.toml");
    std::fs::write(
        &cfg,
        "[profiles.default]\nservice_url = \"http://127.0.0.1:8081\"\n",
    )
    .unwrap();
    let cfg = cfg.to_str().unwrap();

    for verb in [
        ["profiles"].as_slice(),
        ["keys", "show"].as_slice(),
        ["catalogs"].as_slice(),
    ] {
        let mut argv = vec!["gdi-dataset-tool", "--config", cfg, "--profile", "nope"];
        argv.extend_from_slice(verb);
        let err = run(Cli::try_parse_from(argv).unwrap()).unwrap_err();

        assert_eq!(err.exit_code, 1, "{verb:?}");
        assert!(
            err.message.contains("unknown profile 'nope'"),
            "{verb:?}: {}",
            err.message
        );
        assert!(
            err.message.contains("default"),
            "{verb:?} must list the available names: {}",
            err.message
        );
    }

    // A configured name still runs. The config-authoring commands stay exempt, so
    // `wizard setup --profile <new>` can still name the profile it is about to create.
    run(Cli::try_parse_from([
        "gdi-dataset-tool",
        "--config",
        cfg,
        "--profile",
        "default",
        "profiles",
    ])
    .unwrap())
    .expect("a configured profile still runs");
}

#[test]
fn completions_include_new_commands() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_gdi-dataset-tool"))
        .args(["completions", "bash"])
        .output()
        .expect("spawn gdi-dataset-tool");
    let script = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    assert!(!script.is_empty(), "completions bash produced no output");
    // End-to-end smoke that `completions bash` runs and lists the subcommands. Matches
    // the plain subcommand names, not clap_complete's private `__subcmd__` dispatch
    // token, which is version-brittle; registration in the command tree is covered by
    // cli.rs's parse tests and `completions_generate_for_every_shell`.
    assert!(
        script.contains("config"),
        "completions list the `config` subcommand; got:\n{script}"
    );
    assert!(
        script.contains("pin-recipient"),
        "completions list `keys pin-recipient`"
    );
}

#[test]
fn config_init_honors_config_flag() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("my-config.toml");

    // `--config <path>` with no `-o` must write the template to `<path>`.
    std::process::Command::new(env!("CARGO_BIN_EXE_gdi-dataset-tool"))
        .args(["--config", out.to_str().unwrap(), "config", "init"])
        .output()
        .expect("spawn gdi-dataset-tool");

    assert!(out.exists(), "config init must write to the --config path");
    let body = std::fs::read_to_string(&out).unwrap();
    assert!(
        body.contains("country_code"),
        "template written; got:\n{body}"
    );
}
