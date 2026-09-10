//! End-to-end wizard tests via the [`ScriptedPrompter`] (no TTY needed).
//!
//! The TTY guard ([`gdi_dataset_tool::wizard::prompts::require_tty`]) lives in
//! the `lib.rs` dispatch arm, not in [`gdi_dataset_tool::wizard::run`], so the
//! orchestrator is fully testable here without an interactive terminal.

#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use clap::Parser as _;
use gdi_dataset_tool::cli::{BuildArgs, Cli, Command, OutputFormat, Stage, WizardArgs};
use gdi_dataset_tool::wizard::prompts::ScriptedPrompter;

/// The widest a wizard prompt may be and still fit an 80-column terminal alongside
/// dialoguer's `? ` prefix and its trailing arrow.
const PROMPT_BUDGET: usize = 72;

/// The wizard's `[n/N]` banner numbering derives from the `Stage` enum, so adding a stage
/// renumbers every banner at once. No banner may hard-code its own `[n/N]`, and the stage
/// list must come from the enum rather than a hand-written array that a new variant would
/// leave stale.
#[test]
fn stage_numbering_comes_from_the_enum() {
    // `all()` is the enum's variant list (`ValueEnum::value_variants`), so this pins the
    // journey's length by hand — the one fact a new variant must consciously update.
    assert_eq!(
        Stage::count(),
        5,
        "a new Stage variant renumbers the journey: update this"
    );
    assert_eq!(Stage::Setup.step(), 1);
    assert_eq!(Stage::Publish.step(), Stage::count());
    let steps: Vec<usize> = Stage::all().iter().map(|s| s.step()).collect();
    assert_eq!(steps, (1..=Stage::count()).collect::<Vec<_>>());
}

/// A `--from` after `--to` selects an empty stage range, which must be an error rather
/// than a silent exit 0. Entered at `wizard::run` with a scripted prompter, below the
/// CLI's interactive-terminal guard; the prompter must not be consulted at all, since no
/// stage runs.
#[test]
fn a_from_stage_after_the_to_stage_is_refused() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config_path = tmp.path().join("tool.toml");
    std::fs::write(&config_path, "country_code = \"EE\"\n").expect("write config");
    let args = WizardArgs {
        command: None,
        from: Stage::Build,
        to: Stage::Author,
        output: tmp.path().join("package.yaml"),
        recipient: None,
    };
    let err =
        gdi_dataset_tool::wizard::run(&ScriptedPrompter::new(), &args, None, Some(&config_path))
            .expect_err("an empty stage range must be refused");
    assert!(
        err.message.contains("no stage would run"),
        "the refusal names the empty range: {}",
        err.message
    );
}

// Parse tests

#[test]
fn wizard_and_setup_parse() {
    // `wizard --from author --to pack` parses as Command::Wizard.
    let w = Cli::try_parse_from([
        "gdi-dataset-tool",
        "wizard",
        "--from",
        "author",
        "--to",
        "pack",
    ])
    .unwrap();
    std::assert_matches!(w.command, Command::Wizard(_));

    // `wizard setup` parses as Command::Wizard with a Setup subcommand.
    let s = Cli::try_parse_from(["gdi-dataset-tool", "wizard", "setup"]).unwrap();
    std::assert_matches!(s.command, Command::Wizard(_));

    // `--from` accepts only the stages that can begin a run, and `--help` must advertise
    // exactly those: a possible-value the run then rejects is a lie in the help text.
    for stage in ["pack", "publish"] {
        let rejected = Cli::try_parse_from(["gdi-dataset-tool", "wizard", "--from", stage]);
        let err = rejected
            .expect_err("--from {stage} must not parse")
            .to_string();
        assert!(
            err.contains("[possible values: setup, author, build]"),
            "the rejection must name what IS accepted; got: {err}"
        );
    }
}

// Scripted author answers, in the shared order `author_greenfield` asks them in.
//
// author_greenfield prompt order (no profile catalogs, no profile org):
//   INPUT:   vcf_path (a file)
//   CONFIRM: add another VCF file or directory?
//   SELECT:  assembly (pre-selected from the header when it says)
//   SELECT:  prefix
//   INPUT:   org
//   CONFIRM: remember the org in the profile?
//   INPUT:   catalog          (free text — no profile catalogs, no node to refresh from)
//   INPUT:   title
//   INPUT:   description
//   CONFIRM: add keywords?   → INPUT: keywords
//   CONFIRM: record cohort?  → INPUT: numberOfUniqueIndividuals
//   CONFIRM: synthetic?
//   INPUT:   creator
//   MULTISELECT: health_categories (Human genomic pre-checked)
//   MULTISELECT: conformsTo (nothing pre-checked; empty = omit the field)
//   SELECT:  access_rights
//   SELECT:  license
//   MULTISELECT: applicable legislation (EHDS pre-checked; GDPR by the data-derived rule)
//   CONFIRM: add another legislation ELI or IRI?  → INPUT: the ELI/IRI, then re-asked
//   CONFIRM: GoE provenance? (declined → INPUT: afSource, INPUT: afSourceReference)
//   INPUT:   minAlleleCount
//   SELECT:  review — write / edit / abort
//
// This list is positional: every scenario below therefore asserts that the journey
// completed (the run returned Ok and the package.yaml exists), because a script that
// derails on an inserted prompt can otherwise still "pass" by asserting only what it
// checked before the derailment. `a_missing_answer_fails_the_journey` is the break-test
// that keeps that assertion honest.

fn scripted_author(fixture: &str) -> ScriptedPrompter {
    ScriptedPrompter::new()
        .with_inputs(vec![
            fixture,                                    // VCF path
            "UTARTU",                                   // org
            "gdi-aggregated",                           // catalog (free text; no profile catalogs)
            "AF test (synthetic data)",                 // title
            "Synthetic allele-frequency test dataset.", // description (required by validator)
            "allele-frequency,genomics",                // keywords (comma-separated)
            "2504",                                     // numberOfUniqueIndividuals
            "Test Institute",                           // creator
            "5",                                        // minAlleleCount (the wizard asks for it)
        ])
        .with_selects(vec![
            1, // assembly: GRCh38 (index 1 in ASSEMBLIES = ["GRCh37", "GRCh38"])
            0, // prefix: GOE (index 0 in PREFIXES = ["GOE", "GDI"])
            0, // access rights: PUBLIC (index 0)
            0, // license: CC-BY-4.0 (index 0 in LICENSE_SUGGESTIONS)
            0, // review: 0 = write it
        ])
        .with_confirms(vec![
            false, // Add another VCF file or directory?
            false, // Remember the org in the profile?
            true,  // Add discovery keywords?
            true,  // Record cohort size?
            true,  // Is this synthetic data?
            false, // Add another legislation ELI or IRI?
            true,  // Use the standard Genome of Europe AF provenance? -> fills BOTH fields
        ])
        .with_multiselects(vec![
            vec![2], // health categories: index 2 = Human genomic (genetic, epigenomic, genomic)
            vec![],  // conformsTo: nothing ticked -> the field is omitted
            vec![0], // applicable legislation: the EHDS row only
        ])
}

// Orchestrator test

#[test]
fn wizard_authors_via_orchestrator() {
    let fixture_path = test_util::covid_vcf_path();
    let fixture = fixture_path.to_str().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let pkg = dir.path().join("package.yaml");

    let p = scripted_author(fixture);
    // A config of its own, so the run cannot pick up whatever profile the host's default
    // config dir holds (a `service_url` there would add the catalog-refresh offer).
    let config_path = dir.path().join("tool.toml");
    std::fs::write(&config_path, "country_code = \"EE\"\n").unwrap();

    // Run only the Author stage (no setup, no build, no TTY guard in wizard::run).
    let args = WizardArgs {
        command: None,
        from: Stage::Author,
        to: Stage::Author,
        output: pkg.clone(),
        recipient: None,
    };

    let res = gdi_dataset_tool::wizard::run(&p, &args, None, Some(&config_path));
    assert!(res.is_ok(), "wizard author stage failed: {res:?}");
    assert!(pkg.exists(), "package.yaml must have been written");

    // The written YAML must parse as a PackageYaml …
    let yaml = std::fs::read_to_string(&pkg).unwrap();
    let pkg_model: gdi_node_standalone_core::model::PackageYaml =
        serde_saphyr::from_str(&yaml).unwrap();
    // The wizard asks for `minAlleleCount` rather than defaulting it, so the guided path
    // never silently ships suppression off. The scripted answer must reach the file.
    assert_eq!(
        pkg_model.config.min_allele_count, 5,
        "the wizard's floor answer must reach package.yaml"
    );
    // The plain journey: the EHDS row ticked and nothing else, no conformsTo. The field
    // must be omitted rather than defaulted — a node-level constant on every dataset
    // would invent a per-dataset fact.
    assert_eq!(
        pkg_model.metadata.applicable_legislation,
        ["http://data.europa.eu/eli/reg/2025/327/oj".to_owned()]
    );
    assert_eq!(pkg_model.metadata.conforms_to, None, "{yaml}");
    // … and pass the holistic validator.
    let report =
        gdi_node_standalone_core::validate_pkg::validate_package_collect_all(&pkg_model, None);
    assert!(
        report.is_valid(),
        "authored package.yaml must be valid; errors: {:?}",
        report.errors
    );
    assert!(
        report.warnings.is_empty(),
        "the default journey cites the EHDS ELI, so it must not warn: {:?}",
        report.warnings
    );
}

/// The legislation and `conformsTo` journey through the orchestrator, not the prompt
/// helpers: tick a `conformsTo` value, untick the EHDS row, and type an extra ELI. All
/// three must reach the written `package.yaml`, and dropping the EHDS ELI must leave the
/// package valid with a warning rather than rejected.
#[test]
fn the_authored_package_carries_conforms_to_and_every_legislation_entry() {
    let fixture_path = test_util::covid_vcf_path();
    let dir = tempfile::tempdir().unwrap();
    let pkg = dir.path().join("package.yaml");
    let config_path = dir.path().join("tool.toml");
    std::fs::write(&config_path, "country_code = \"EE\"\n").unwrap();

    let national = "https://www.riigiteataja.ee/akt/128122023011";
    let p = scripted_author(fixture_path.to_str().unwrap())
        .with_inputs(vec![
            fixture_path.to_str().unwrap(),
            "UTARTU",
            "gdi-aggregated",
            "AF test (synthetic data)",
            "Synthetic allele-frequency test dataset.",
            "allele-frequency,genomics",
            "2504",
            "Test Institute",
            national, // the one freely typed legislation IRI
            "5",
        ])
        .with_multiselects(vec![
            vec![2],    // health categories: Human genomic
            vec![0, 1], // conformsTo: Externally governed + 1+MG compliant
            vec![1],    // legislation: GDPR only, the EHDS row is unticked
        ])
        .with_confirms(vec![
            false, // Add another VCF file or directory?
            false, // Remember the org in the profile?
            true,  // Add discovery keywords?
            true,  // Record cohort size?
            true,  // Is this synthetic data?
            true,  // Add another legislation ELI or IRI? -> yes, the national one
            false, // Add another legislation ELI or IRI? -> no more
            true,  // Use the standard Genome of Europe AF provenance?
        ]);

    let res = gdi_dataset_tool::wizard::run(
        &p,
        &WizardArgs {
            command: None,
            from: Stage::Author,
            to: Stage::Author,
            output: pkg.clone(),
            recipient: None,
        },
        None,
        Some(&config_path),
    );
    assert!(res.is_ok(), "wizard author stage failed: {res:?}");
    assert!(pkg.exists(), "package.yaml must have been written");

    let yaml = std::fs::read_to_string(&pkg).unwrap();
    let pkg_model: gdi_node_standalone_core::model::PackageYaml =
        serde_saphyr::from_str(&yaml).unwrap();
    assert_eq!(
        pkg_model.metadata.conforms_to,
        Some(vec![
            "http://data.gdi.eu/core/p2/ExternallyGoverned".to_owned(),
            "http://data.gdi.eu/core/p2/1MGCompliant".to_owned(),
        ]),
        "{yaml}"
    );
    assert_eq!(
        pkg_model.metadata.applicable_legislation,
        [
            "http://data.europa.eu/eli/reg/2016/679/oj".to_owned(),
            national.to_owned(),
        ],
        "the ticked row and the typed entry, in that order: {yaml}"
    );
    // Valid, with the advisory, not an error.
    let report =
        gdi_node_standalone_core::validate_pkg::validate_package_collect_all(&pkg_model, None);
    assert!(report.is_valid(), "errors: {:?}", report.errors);
    assert!(
        report
            .warnings
            .contains(&gdi_node_standalone_core::validate_pkg::ehds_absent_warning()),
        "{:?}",
        report.warnings
    );
}

/// Break-test for the positional scripts above: a scenario that omits one answer must
/// fail, loudly. Every scripted journey in this file is a fixed-order queue, so a prompt
/// added to `author_greenfield` silently shifts every later answer by one; the guarantee
/// that this cannot pass unnoticed is that a short script errors and that each scenario
/// asserts the journey completed. This test is the evidence for the first half.
#[test]
fn a_missing_answer_fails_the_journey() {
    let fixture_path = test_util::covid_vcf_path();
    let dir = tempfile::tempdir().unwrap();
    let pkg = dir.path().join("package.yaml");
    // The full script, minus the legislation multi-select answer.
    let p = scripted_author(fixture_path.to_str().unwrap()).with_multiselects(vec![
        vec![2], // health categories
        vec![],  // conformsTo
                 // The applicable-legislation answer is missing, which is the point.
    ]);
    let err = gdi_dataset_tool::wizard::author::author_greenfield(
        &p,
        &pkg,
        &gdi_dataset_tool::wizard::author::AuthorContext::default(),
        false,
    )
    .expect_err("a script that runs out of answers must fail, not write a package");
    assert!(
        err.message.contains("ran dry"),
        "the failure must name the exhausted queue; got: {}",
        err.message
    );
    assert!(
        !pkg.exists(),
        "nothing may be written after a derailed script"
    );
}

// Completions coverage

#[test]
fn completions_include_wizard() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_gdi-dataset-tool"))
        .args(["completions", "bash"])
        .output()
        .expect("spawn gdi-dataset-tool");
    let script = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    assert!(!script.is_empty(), "completions bash produced no output");
    // Plain subcommand name, not clap_complete's version-brittle private `__subcmd__`
    // dispatch token; registration is covered by cli.rs's parse tests and
    // `completions_generate_for_every_shell`.
    assert!(
        script.contains("wizard"),
        "completions list the wizard subcommand; got:\n{script}"
    );
}

// --from pack/publish guard

#[test]
fn wizard_rejects_from_pack_and_from_publish() {
    let dir = tempfile::tempdir().unwrap();
    let pkg = dir.path().join("package.yaml");
    let p = ScriptedPrompter::new();
    for stage in [Stage::Pack, Stage::Publish] {
        let args = WizardArgs {
            command: None,
            from: stage,
            to: Stage::Publish,
            output: pkg.clone(),
            recipient: None,
        };
        let result = gdi_dataset_tool::wizard::run(&p, &args, None, None);
        assert!(
            result.is_err(),
            "--from {stage:?} must be rejected, but run() returned Ok"
        );
        let msg = result.unwrap_err().message;
        assert!(
            msg.contains("--from must be one of setup|author|build"),
            "--from {stage:?} error message was: {msg}"
        );
    }
}

// Build to pack orchestration, end to end.

/// Restores the process CWD + `GDI_CONFIG_DIR` on drop, so a panic inside
/// `wizard::run` cannot leak a deleted CWD / env value into later tests.
struct RestoreEnv {
    cwd: std::path::PathBuf,
    gdi_config_dir: Option<std::ffi::OsString>,
}

impl Drop for RestoreEnv {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.cwd);
        match &self.gdi_config_dir {
            Some(v) => test_util::set_env("GDI_CONFIG_DIR", v),
            None => test_util::remove_env("GDI_CONFIG_DIR"),
        }
    }
}

/// Drive `wizard::run(from=Author, to=Pack)` end to end. This exercises the
/// `build_output` threading from the Build stage into Pack.
///
/// What is asserted:
/// - `wizard::run` returns `Ok(())`.
/// - A `.tar.c4gh` file appears in the CWD (which we set to the temp dir via
///   `set_current_dir`; pack writes `{dataset_id}.tar.c4gh` there by default).
/// - The build staging directory exists under `<tempdir>/build/`.
///
/// We use `#[serial]` because:
/// (a) `set_current_dir` is process-global, and
/// (b) `GDI_CONFIG_DIR` is a process env var.
#[test]
#[serial_test::serial(env)]
fn wizard_author_to_pack_e2e() {
    use gdi_node_standalone_core::crypt4gh::{generate_keypair, serialize_public_key};

    let fixture_path = test_util::covid_vcf_path();
    let fixture = fixture_path.to_str().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let pkg = dir.path().join("package.yaml");

    // Generate a node keypair and write the public key for pack to use.
    let (_sk, pk) = generate_keypair();
    let node_pub = dir.path().join("node.pub");
    std::fs::write(&node_pub, serialize_public_key(&pk)).unwrap();

    // Write a minimal config TOML with country_code and a node_recipient_file.
    let config_path = dir.path().join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            "country_code = \"EE\"\n\n[profiles.default]\nnode_recipient_file = \"{}\"\n",
            node_pub.display()
        ),
    )
    .unwrap();

    // Scripted author answers (same order as author_greenfield):
    //   INPUT:   vcf_path
    //   SELECT:  assembly (index 1 = GRCh38)
    //   SELECT:  prefix   (index 0 = GOE)
    //   INPUT:   org
    //   INPUT:   catalog  (free text; no profile catalogs)
    //   INPUT:   title
    //   INPUT:   description
    //   SELECT:  access_rights (index 0 = PUBLIC)
    //   SELECT:  license       (index 0 = CC-BY-4.0)
    //   INPUT:   creator
    //   SELECT:  health_category (index 0 = Human genomic)
    //   CONFIRM: add keywords?
    //   CONFIRM: record cohort size?
    //   CONFIRM: synthetic?
    //   CONFIRM: use standard GoE AF provenance? (declined here -> the two prompts below)
    //   INPUT:   afSource (optional, empty)
    //   INPUT:   afSourceReference (optional, empty)
    let p = ScriptedPrompter::new()
        .with_inputs(vec![
            fixture,                                    // VCF path
            "UTARTU",                                   // org
            "gdi-aggregated",                           // catalog
            "AF test (synthetic data)",                 // title
            "Synthetic allele-frequency test dataset.", // description (non-empty required)
            "allele-frequency,genomics",                // keywords (comma-separated)
            "2504",                                     // numberOfUniqueIndividuals
            "Test Institute",                           // creator
            "",                                         // afSource (optional, empty)
            "",                                         // afSourceReference (optional, empty)
            "5",                                        // minAlleleCount (the wizard asks for it)
        ])
        .with_selects(vec![
            1, // assembly: GRCh38 (index 1)
            0, // prefix: GOE (index 0)
            0, // access rights: PUBLIC (index 0)
            0, // license: CC-BY-4.0 (index 0)
            0, // review: write it
        ])
        .with_confirms(vec![
            false, // Add another VCF file or directory?
            false, // Remember the org in the profile?
            true,  // Add discovery keywords?
            true,  // Record cohort size?
            true,  // Is this synthetic data?
            false, // Add another legislation ELI or IRI?
            false, // Use the standard Genome of Europe AF provenance? -> NO: blank-skip path
            true,  // Publish these populations? (the Build stage's disclosure preview)
            false, // Remove the staging dir? — KEEP it (asserted below)
        ])
        .with_multiselects(vec![
            vec![2], // health categories: Human genomic
            vec![],  // conformsTo: nothing ticked
            vec![0], // applicable legislation: the EHDS row only
        ]);

    // Save + restore CWD and GDI_CONFIG_DIR via a drop-guard so they are restored
    // even if `wizard::run` panics — a leaked (deleted) CWD or env value would
    // otherwise corrupt every later test. Relative-path outputs (build/,
    // *.tar.c4gh) land in the temp dir without polluting the workspace.
    // Capture the originals before mutating, then install the guard.
    let _restore = RestoreEnv {
        cwd: std::env::current_dir().unwrap(),
        gdi_config_dir: std::env::var_os("GDI_CONFIG_DIR"),
    };
    std::env::set_current_dir(dir.path()).unwrap();
    test_util::set_env("GDI_CONFIG_DIR", dir.path());

    let result = gdi_dataset_tool::wizard::run(
        &p,
        &WizardArgs {
            command: None,
            from: Stage::Author,
            to: Stage::Pack,
            output: pkg,
            recipient: None,
        },
        None,
        Some(&config_path),
    );

    // CWD + GDI_CONFIG_DIR are restored by `_restore` on scope exit (or panic).
    assert!(result.is_ok(), "wizard author→pack failed: {result:?}");

    // A .tar.c4gh must have been produced in the temp dir by the Pack stage.
    let c4gh_files: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(std::result::Result::ok)
        .filter(|e| e.path().to_string_lossy().ends_with(".tar.c4gh"))
        .collect();
    assert!(
        !c4gh_files.is_empty(),
        "expected a .tar.c4gh in the temp dir; found none"
    );

    // The build staging directory must also exist.
    let build_dir = dir.path().join("build");
    assert!(build_dir.exists(), "build staging directory must exist");

    // The GoE-provenance confirm was declined and both follow-up prompts answered
    // blank, so the authored package.yaml must carry neither afSource key.
    let authored = std::fs::read_to_string(dir.path().join("package.yaml")).unwrap();
    assert!(
        !authored.contains("afSource"),
        "declining the GoE provenance offer must leave afSource/afSourceReference unset"
    );

    // Every prompt this journey actually reached must fit an 80-column terminal.
    //
    // `dialoguer` finalizes a prompt by erasing one row (`\r\x1b[2K`), so a prompt wider
    // than the terminal keeps its first row on screen and the transcript shows the question
    // twice. The budget is asserted over the prompts the wizard reached rather than over a
    // hand-kept list of literals, which would drift the moment a prompt is reworded.
    //
    // Answers are echoed on the same line and can be arbitrarily long (a path), so this
    // bounds the question only; that is the part the wizard controls.
    let overlong: Vec<String> = p
        .seen_prompts()
        .into_iter()
        .filter(|line| line.chars().count() > PROMPT_BUDGET)
        .collect();
    assert!(
        overlong.is_empty(),
        "these prompts/labels exceed {PROMPT_BUDGET} chars and will wrap on an 80-column \
         terminal — move the explanation to an `output::progress` note above the prompt, \
         as FLOOR_NOTE does: {overlong:#?}"
    );
}

// The publish stage, the only one that touches a node.
//
// Publish/Deploy is the one stage that reaches out of the process and installs something
// into a node's inbox, so it needs coverage rather than stopping at `pack`. In particular
// the wizard's setup collects only a `service_url` (the public plane), while a
// `deploy --wait` polls the dataset-state oracle on the management plane, which the public
// plane 404s: unexercised, that combination hangs for the full timeout and then blames the
// node for a dataset that ingested seconds earlier.
//
// Both branches are covered, because they deploy different artifacts: a keyed node gets the
// `{id}.tar.c4gh`, a keyless one gets the plaintext staging directory (there is no
// recipient to encrypt to). Both resolve their artifact relative to the process CWD, which
// is why these are `#[serial]` behind the same `RestoreEnv` guard the pack test uses.

/// Drive the wizard all the way through Publish → "Deploy to inbox" on a keyed node, and
/// assert the `.tar.c4gh` actually lands in the node's inbox.
#[test]
#[serial_test::serial(env)]
fn wizard_publish_deploys_the_package_to_the_inbox() {
    use gdi_node_standalone_core::crypt4gh::{generate_keypair, serialize_public_key};

    let fixture_path = test_util::covid_vcf_path();
    let fixture = fixture_path.to_str().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let pkg = dir.path().join("package.yaml");
    let inbox = dir.path().join("inbox");
    // The node provisions its inbox and the tool requires it rather than creating it, so
    // the fixture stands in for a node that has started at least once.
    std::fs::create_dir_all(&inbox).unwrap();

    let (_sk, pk) = generate_keypair();
    let node_pub = dir.path().join("node.pub");
    std::fs::write(&node_pub, serialize_public_key(&pk)).unwrap();

    // The profile carries the `inbox` the Deploy stage resolves (it passes `inbox: None`,
    // so the profile is the only source). No `management_url`, exactly as the wizard's own
    // setup writes it: that is the shape a `--wait` deploy has to cope with.
    let config_path = dir.path().join("tool.toml");
    std::fs::write(
        &config_path,
        format!(
            "country_code = \"EE\"\n\n[profiles.default]\nnode_recipient_file = \"{}\"\n\
             inbox = \"{}\"\n",
            node_pub.display(),
            inbox.display(),
        ),
    )
    .unwrap();

    let p = publish_prompter(fixture, /* keyless */ false);

    let _restore = RestoreEnv {
        cwd: std::env::current_dir().unwrap(),
        gdi_config_dir: std::env::var_os("GDI_CONFIG_DIR"),
    };
    std::env::set_current_dir(dir.path()).unwrap();
    test_util::set_env("GDI_CONFIG_DIR", dir.path());

    let result = gdi_dataset_tool::wizard::run(
        &p,
        &WizardArgs {
            command: None,
            from: Stage::Author,
            to: Stage::Publish,
            output: pkg,
            recipient: None,
        },
        None,
        Some(&config_path),
    );
    assert!(result.is_ok(), "wizard author→publish failed: {result:?}");

    let landed: Vec<_> = std::fs::read_dir(&inbox)
        .expect("the Deploy stage must land the package in the node's inbox")
        .filter_map(std::result::Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        landed.iter().any(|n| n.ends_with(".tar.c4gh")),
        "the wizard must deploy the package into the node's inbox; inbox holds: {landed:?}"
    );

    // The cleanup confirm (default yes, answered yes) removed the staging directory: the
    // package carries everything, and a rebuild recreates it.
    let build_dir = dir.path().join("build");
    let staging_left =
        std::fs::read_dir(&build_dir).map_or(0, |entries| entries.filter_map(Result::ok).count());
    assert_eq!(
        staging_left, 0,
        "accepting the cleanup confirm must remove the packed staging dir"
    );
    assert_publish_menu_defaults_to_sending(&p);
}

/// The publish question must pre-select sending, on both channels.
///
/// The inbox and S3 routes are the same decision, so they must not carry opposite
/// defaults: an operator who has just configured a bucket and supplied credentials would
/// otherwise ship nothing by pressing Enter. Both routes land the dataset hidden, so the
/// review window is the hidden state and not the transfer. Asserted on the index the menu
/// was rendered with, which is what Enter selects.
fn assert_publish_menu_defaults_to_sending(p: &ScriptedPrompter) {
    let publish_menus: Vec<(String, usize)> = p
        .seen_select_defaults()
        .into_iter()
        .filter(|(prompt, _)| prompt.starts_with("Send the "))
        .collect();
    assert_eq!(
        publish_menus.len(),
        1,
        "exactly one publish menu per run; got {publish_menus:?}"
    );
    assert_eq!(
        publish_menus[0].1, 0,
        "the publish menu must pre-select the send route, not Skip: {publish_menus:?}"
    );
}

/// The keyless branch: no recipient, so `pack` is skipped and the wizard deploys the
/// plaintext staging directory instead. A different artifact down a different code path,
/// and the path a single-operator node takes.
#[test]
#[serial_test::serial(env)]
fn wizard_publish_deploys_the_staging_dir_when_keyless() {
    let fixture_path = test_util::covid_vcf_path();
    let fixture = fixture_path.to_str().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let pkg = dir.path().join("package.yaml");
    let inbox = dir.path().join("inbox");
    // The node provisions its inbox and the tool requires it rather than creating it, so
    // the fixture stands in for a node that has started at least once.
    std::fs::create_dir_all(&inbox).unwrap();

    // `keyless = true`: no node recipient exists, and none is needed.
    let config_path = dir.path().join("tool.toml");
    std::fs::write(
        &config_path,
        format!(
            "country_code = \"EE\"\n\n[profiles.default]\nkeyless = true\ninbox = \"{}\"\n",
            inbox.display(),
        ),
    )
    .unwrap();

    let p = publish_prompter(fixture, /* keyless */ true);

    let _restore = RestoreEnv {
        cwd: std::env::current_dir().unwrap(),
        gdi_config_dir: std::env::var_os("GDI_CONFIG_DIR"),
    };
    std::env::set_current_dir(dir.path()).unwrap();
    test_util::set_env("GDI_CONFIG_DIR", dir.path());

    let result = gdi_dataset_tool::wizard::run(
        &p,
        &WizardArgs {
            command: None,
            from: Stage::Author,
            to: Stage::Publish,
            output: pkg,
            recipient: None,
        },
        None,
        Some(&config_path),
    );
    assert!(
        result.is_ok(),
        "keyless wizard author→publish failed: {result:?}"
    );

    // A staging directory (with its manifest), not a package — and emphatically no `.tar.c4gh`:
    // a keyless run has no recipient, so anything encrypted here would be a bug.
    let entries: Vec<_> = std::fs::read_dir(&inbox)
        .expect("the Deploy stage must land the staging dir in the node's inbox")
        .filter_map(std::result::Result::ok)
        .collect();
    let staged = entries
        .iter()
        .find(|e| e.path().is_dir())
        .expect("the keyless wizard must deploy a staging DIR into the inbox");
    assert!(
        staged.path().join("manifest.json").is_file(),
        "the deployed staging dir must carry its manifest.json"
    );
    assert!(
        !entries
            .iter()
            .any(|e| e.path().to_string_lossy().ends_with(".tar.c4gh")),
        "a keyless run has no recipient — it must not produce an encrypted package"
    );
    assert_publish_menu_defaults_to_sending(&p);
}

/// The scripted answers for a full Author → … → Publish run.
///
/// Identical to the author script in [`wizard_author_to_pack_e2e`], plus the one extra
/// SELECT the Publish stage asks. The keyed menu is built from the profile — this one has
/// an inbox and no S3, so it reads `[Deploy to the node's inbox, Skip]` — and the keyless
/// menu is `[Deploy the staging dir…, Skip]`: deploy is index 0 on both.
fn publish_prompter(fixture: &str, keyless: bool) -> ScriptedPrompter {
    let deploy_choice = 0;
    // A keyed run packs and is then asked to remove the staging directory (default yes —
    // answered yes here, asserted by the caller); a keyless run never packs, so the
    // question never comes.
    let mut confirms = vec![
        false, // Add another VCF file or directory?
        false, // Remember the org in the profile?
        true,  // Add discovery keywords?
        true,  // Record cohort size?
        true,  // Is this synthetic data?
        false, // Add another legislation ELI or IRI?
        false, // Use the standard Genome of Europe AF provenance? -> NO: blank-skip path
        true,  // Publish these populations? (the Build stage's disclosure preview)
    ];
    if !keyless {
        confirms.push(true); // Remove the staging dir? — yes (the default)
    }
    ScriptedPrompter::new()
        .with_inputs(vec![
            fixture,
            "UTARTU",
            "gdi-aggregated",
            "AF test (synthetic data)",
            "Synthetic allele-frequency test dataset.",
            "allele-frequency,genomics",
            "0",
            "Test Institute",
            "",
            "",
            "5",
        ])
        .with_selects(vec![
            1,             // assembly: GRCh38
            0,             // prefix: GOE
            0,             // access rights: PUBLIC
            0,             // license: CC-BY-4.0
            0,             // review: write it
            deploy_choice, // Publish? -> deploy to the inbox
        ])
        .with_confirms(confirms)
        .with_multiselects(vec![
            vec![2], // health categories: Human genomic
            vec![],  // conformsTo: nothing ticked
            vec![0], // applicable legislation: the EHDS row only
        ])
}

// Drift guard: an authored package.yaml must build.

#[test]
fn authored_package_builds() {
    let fixture_path = test_util::covid_vcf_path();
    let fixture = fixture_path.to_str().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let pkg = dir.path().join("package.yaml");
    let build_out = dir.path().join("build");

    // Author the package.yaml via the wizard author module directly.
    let p = scripted_author(fixture);
    let author_res = gdi_dataset_tool::wizard::author::author_greenfield(
        &p,
        &pkg,
        &gdi_dataset_tool::wizard::author::AuthorContext::default(),
        false,
    );
    assert!(author_res.is_ok(), "author step failed: {author_res:?}");

    // The GoE-provenance confirm was accepted, so the authored package.yaml must carry
    // the standard pair — the exact strings, pinning the user-facing values themselves.
    let authored = std::fs::read_to_string(&pkg).unwrap();
    assert!(
        authored.contains(r#"afSource: "The Genome of Europe""#),
        "accepting the GoE provenance offer must set afSource"
    );
    assert!(
        authored.contains(r#"afSourceReference: "https://genomeofeurope.eu/""#),
        "accepting the GoE provenance offer must set afSourceReference"
    );

    // Build it — the ultimate drift guard: wizard output must build successfully.
    let build_res = gdi_dataset_tool::commands::cmd_build::run(
        &BuildArgs {
            package: pkg.clone(),
            country_code: Some("EE".into()),
            out: build_out.clone(),
            force: true,
            no_headers: false,
            header_policy: None,
            strict: false,
            dry_run: false,
            build_epoch: None,
            jobs: 1,
            refresh_catalogs: false,
            format: OutputFormat::Text,
        },
        None,
        None,
    );
    assert!(
        build_res.is_ok(),
        "authored package must build: {build_res:?}"
    );
    assert!(
        build_out.exists(),
        "staging directory must have been created"
    );
}

/// The disclosure preview must actually gate: declining "Publish these populations?"
/// stops the wizard before it builds/packs anything. A preview that only prints, and
/// proceeds regardless, would be decoration rather than a control.
#[test]
#[serial_test::serial(env)]
fn declining_the_disclosure_preview_aborts_the_wizard() {
    use gdi_node_standalone_core::crypt4gh::{generate_keypair, serialize_public_key};

    let fixture_path = test_util::covid_vcf_path();
    let fixture = fixture_path.to_str().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let pkg = dir.path().join("package.yaml");

    let (_sk, pk) = generate_keypair();
    let node_pub = dir.path().join("node.pub");
    std::fs::write(&node_pub, serialize_public_key(&pk)).unwrap();
    let config_path = dir.path().join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            "country_code = \"EE\"\n\n[profiles.default]\nnode_recipient_file = \"{}\"\n",
            node_pub.display()
        ),
    )
    .unwrap();

    let p = scripted_author(fixture).with_confirms(vec![
        false, // Add another VCF file or directory?
        false, // Remember the org in the profile?
        true,  // Add discovery keywords?
        true,  // Record cohort size?
        true,  // Is this synthetic data?
        false, // Add another legislation ELI or IRI?
        true,  // Use the standard Genome of Europe AF provenance?
        false, // Publish these populations?  -> NO: the operator refuses the disclosure
    ]);

    let _restore = RestoreEnv {
        cwd: std::env::current_dir().unwrap(),
        gdi_config_dir: std::env::var_os("GDI_CONFIG_DIR"),
    };
    std::env::set_current_dir(dir.path()).unwrap();
    test_util::set_env("GDI_CONFIG_DIR", dir.path());

    let result = gdi_dataset_tool::wizard::run(
        &p,
        &WizardArgs {
            command: None,
            from: Stage::Author,
            to: Stage::Pack,
            output: pkg,
            recipient: None,
        },
        None,
        Some(&config_path),
    );

    let err = result.expect_err("declining the disclosure preview must stop the wizard");
    assert!(
        err.message.contains("disclosure preview"),
        "the abort must say WHY it stopped; got: {}",
        err.message
    );
    // The Author journey completed before the gate refused: the positional script fed
    // every author prompt, so this is an operator's refusal, not a derailed script.
    assert!(
        dir.path().join("package.yaml").exists(),
        "the Author stage must have written its package.yaml before the disclosure gate"
    );
    // Nothing may have been produced: the refusal precedes the build.
    assert!(
        !dir.path().join("build").exists(),
        "a declined disclosure must not build the dataset"
    );
    assert!(
        std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .all(|e| !e.file_name().to_string_lossy().ends_with(".tar.c4gh")),
        "a declined disclosure must not pack a package"
    );
}

/// The failure menu offers a plain retry (for a cause fixed outside package.yaml) and
/// loops: a retry that fails again re-opens the menu, and Abort surfaces the build
/// error instead of swallowing it.
#[test]
#[serial_test::serial(env)]
fn build_failure_retry_loops_and_abort_returns_the_error() {
    let dir = tempfile::tempdir().unwrap();
    let pkg = test_util::write_covid_package(dir.path());
    let good = std::fs::read_to_string(&pkg).unwrap();
    // Break the build without breaking the preview (same shape as the editor test).
    let broken = good.replace("  prefix: \"GDI\"\n", "");
    assert_ne!(broken, good);
    std::fs::write(&pkg, &broken).unwrap();
    let config_path = dir.path().join("config.toml");
    std::fs::write(&config_path, "country_code = \"EE\"\n").unwrap();

    let p = ScriptedPrompter::new()
        .with_confirms(vec![true]) // disclosure preview
        .with_selects(vec![1, 2]); // Retry (fails the same way) → Abort

    let _restore = RestoreEnv {
        cwd: std::env::current_dir().unwrap(),
        gdi_config_dir: std::env::var_os("GDI_CONFIG_DIR"),
    };
    std::env::set_current_dir(dir.path()).unwrap();
    test_util::set_env("GDI_CONFIG_DIR", dir.path());

    let err = gdi_dataset_tool::wizard::run(
        &p,
        &WizardArgs {
            command: None,
            from: Stage::Build,
            to: Stage::Build,
            output: pkg.clone(),
            recipient: None,
        },
        None,
        Some(&config_path),
    )
    .expect_err("abort after a failed retry must surface the build error");
    assert!(
        err.message.contains("prefix"),
        "the surfaced error must be the build's own: {}",
        err.message
    );
}

/// The Build stage's edit-and-retry recovery: when the first build fails, choosing
/// "Edit package.yaml" opens the `Prompter::editor` seam, writes the edited YAML back,
/// and retries the build once. This is the only path that drives `p.editor(...)`
/// (`wizard/mod.rs`, the marker-free failure branch), so it is the only test that
/// exercises `ScriptedPrompter::with_editors`.
///
/// Construction: a canonical, buildable `covid-package.yaml` with its `metadata.prefix`
/// line removed. Build requires `prefix` (`GOE`/`GDI`) to mint the dataset id, so the
/// first build fails — but the disclosure `preview` only converts the VCF and never
/// reads `prefix`, so the preview still passes and the failure lands squarely in the
/// retry menu. The scripted editor returns the intact (prefix-bearing) YAML, so the
/// retry builds.
///
/// Non-vacuity is structural: if the editor answer were not queued, `p.editor` would
/// pop an empty queue and error with "scripted prompter ran dry on editor", failing the
/// retry and the test. The final `package.yaml == good` assertion further proves the
/// editor branch actually ran (the file on disk was rewritten to the editor's output).
///
/// `#[serial(env)]` for the same reason as the other Build-stage tests: `set_current_dir`
/// and `GDI_CONFIG_DIR` are process-global.
#[test]
#[serial_test::serial(env)]
fn build_failure_edit_and_retry_recovers_via_the_editor() {
    let dir = tempfile::tempdir().unwrap();
    // Materialize the canonical (buildable) package + its VCF into `dir`.
    let pkg = test_util::write_covid_package(dir.path());
    let good = std::fs::read_to_string(&pkg).unwrap();

    // Break the build without breaking the preview: drop `metadata.prefix`. The id
    // minter requires it; the preview does not touch it.
    let broken = good.replace("  prefix: \"GDI\"\n", "");
    assert_ne!(
        broken, good,
        "the fixture's prefix line must have been removed"
    );
    assert!(
        !broken.contains("prefix"),
        "the broken package must have no prefix for the first build to fail"
    );
    std::fs::write(&pkg, &broken).unwrap();

    // Build needs a country code; supply it via the tool config (no node/recipient is
    // needed — this run stops at Build).
    let config_path = dir.path().join("config.toml");
    std::fs::write(&config_path, "country_code = \"EE\"\n").unwrap();

    // Build stage only: one confirm (disclosure preview), then the build fails →
    // one select (0 = "Edit package.yaml"), one editor answer (the fixed YAML), and a
    // second disclosure confirm — the edit may have changed the source set, so the gate
    // re-runs against the edited file before the rebuild.
    let p = ScriptedPrompter::new()
        .with_confirms(vec![true, true]) // disclosure preview, before and after the edit
        .with_selects(vec![0]) // "Build failed. What next?" — 0 = Edit package.yaml
        .with_editors(vec![good.as_str()]); // the editor returns the intact YAML

    let _restore = RestoreEnv {
        cwd: std::env::current_dir().unwrap(),
        gdi_config_dir: std::env::var_os("GDI_CONFIG_DIR"),
    };
    std::env::set_current_dir(dir.path()).unwrap();
    test_util::set_env("GDI_CONFIG_DIR", dir.path());

    let result = gdi_dataset_tool::wizard::run(
        &p,
        &WizardArgs {
            command: None,
            from: Stage::Build,
            to: Stage::Build,
            output: pkg.clone(),
            recipient: None,
        },
        None,
        Some(&config_path),
    );

    assert!(
        result.is_ok(),
        "the edited retry must build; got: {result:?}"
    );

    // The editor branch ran: the file on disk was rewritten to the editor's output.
    assert_eq!(
        std::fs::read_to_string(&pkg).unwrap(),
        good,
        "the editor's YAML must have been written back to package.yaml"
    );

    // The retry actually built: `build/<datasetId>/` holds a manifest + parquet. The
    // first build could not have produced this (it failed before minting an id).
    let build_dir = dir.path().join("build");
    let staging = std::fs::read_dir(&build_dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.is_dir())
        .expect("the retry build must create build/<datasetId>/");
    assert!(
        staging.join("manifest.json").is_file(),
        "the retry build must write a manifest"
    );
    assert!(
        std::fs::read_dir(&staging)
            .unwrap()
            .filter_map(Result::ok)
            .any(|e| e.file_name().to_string_lossy().ends_with(".parquet")),
        "the retry build must write parquet"
    );
}

/// The wizard passes no `--header-policy`, so its Build stage ships whatever the profile
/// recorded at setup — here `with-identifiers` — and surfaces that through the single
/// disclosure confirm: exactly one `confirm` is scripted, so an extra prompt would run the
/// prompter dry and fail the build.
#[test]
#[serial_test::serial(env)]
fn wizard_build_stage_applies_the_profile_header_policy() {
    let dir = tempfile::tempdir().unwrap();
    let pkg = test_util::write_covid_package(dir.path());
    let config_path = dir.path().join("config.toml");
    std::fs::write(
        &config_path,
        "country_code = \"EE\"\n\n[profiles.default]\nheader_policy = \"with-identifiers\"\n",
    )
    .unwrap();
    let p = ScriptedPrompter::new().with_confirms(vec![true]); // the disclosure preview

    let _restore = RestoreEnv {
        cwd: std::env::current_dir().unwrap(),
        gdi_config_dir: std::env::var_os("GDI_CONFIG_DIR"),
    };
    std::env::set_current_dir(dir.path()).unwrap();
    test_util::set_env("GDI_CONFIG_DIR", dir.path());

    gdi_dataset_tool::wizard::run(
        &p,
        &WizardArgs {
            command: None,
            from: Stage::Build,
            to: Stage::Build,
            output: pkg,
            recipient: None,
        },
        None,
        Some(&config_path),
    )
    .unwrap();

    let staging = std::fs::read_dir(dir.path().join("build"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.is_dir())
        .expect("build/<datasetId>/ must exist");
    let raw = std::fs::read_to_string(staging.join("manifest.json")).unwrap();
    let manifest: gdi_node_standalone_core::model::Manifest = serde_json::from_str(&raw).unwrap();
    assert_eq!(
        manifest.internal.header_policy,
        Some(gdi_node_standalone_core::model::HeaderPolicy::WithIdentifiers)
    );
}

// The Author stage on an existing, complete package.yaml

/// A complete `package.yaml` in the way is a question, never a silent pass through into
/// Build: Build mints a fresh id every run, so a directory still holding the previous
/// dataset's file would otherwise republish that dataset under a new id. "Abort" leaves the
/// file alone; "author a new one" (the default) asks for a path and leaves it alone too.
#[test]
fn an_existing_complete_package_yaml_is_a_question_not_a_pass_through() {
    let dir = tempfile::tempdir().unwrap();
    let pkg = test_util::write_covid_package(dir.path());
    let before = std::fs::read_to_string(&pkg).unwrap();
    // A config of its own (see `wizard_authors_via_orchestrator`).
    let config_path = dir.path().join("tool.toml");
    std::fs::write(&config_path, "country_code = \"EE\"\n").unwrap();
    let author_only = |out: &std::path::Path| WizardArgs {
        command: None,
        from: Stage::Author,
        to: Stage::Author,
        output: out.to_path_buf(),
        recipient: None,
    };

    // Abort (row 3).
    let p = ScriptedPrompter::new().with_selects(vec![3]);
    let err = gdi_dataset_tool::wizard::run(&p, &author_only(&pkg), None, Some(&config_path))
        .expect_err("abort must stop the wizard");
    assert!(err.message.contains("--from build"), "{}", err.message);
    assert_eq!(
        std::fs::read_to_string(&pkg).unwrap(),
        before,
        "abort must not touch the file"
    );

    // Author a new one (row 2): the new path is asked first, then the usual questions.
    let new_pkg = dir.path().join("second.yaml");
    let fixture_path = test_util::covid_vcf_path();
    let p = ScriptedPrompter::new()
        .with_inputs(vec![
            new_pkg.to_str().unwrap(),                  // path for the new package.yaml
            fixture_path.to_str().unwrap(),             // VCF path
            "UTARTU",                                   // org
            "gdi-aggregated",                           // catalog
            "Second dataset",                           // title
            "Authored beside a previous package.yaml.", // description
            "allele-frequency,genomics",                // keywords
            "2504",                                     // numberOfUniqueIndividuals
            "Test Institute",                           // creator
            "0",                                        // minAlleleCount
        ])
        .with_selects(vec![
            2, // existing package.yaml: author a new one
            1, // assembly: GRCh38
            0, // prefix: GOE
            0, // access rights: PUBLIC
            0, // license: CC-BY-4.0
            0, // review: write it
        ])
        .with_multiselects(vec![
            vec![2], // health categories: Human genomic
            vec![],  // conformsTo: nothing ticked
            vec![0], // applicable legislation: the EHDS row only
        ])
        .with_confirms(vec![
            false, // Add another VCF file or directory?
            false, // Remember the org in the profile?
            true,  // Add discovery keywords?
            true,  // Record cohort size?
            true,  // Is this synthetic data?
            false, // Add another legislation ELI or IRI?
            true,  // Use the standard Genome of Europe AF provenance?
        ]);
    gdi_dataset_tool::wizard::run(&p, &author_only(&pkg), None, Some(&config_path))
        .expect("authoring a new package.yaml beside the old one must succeed");
    assert!(
        new_pkg.exists(),
        "the new package.yaml must have been written"
    );
    assert!(
        std::fs::read_to_string(&new_pkg)
            .unwrap()
            .contains("Second dataset")
    );
    assert_eq!(
        std::fs::read_to_string(&pkg).unwrap(),
        before,
        "the previous package.yaml must be untouched"
    );
}

/// The review gate's "Abort" writes nothing and says the answers are gone.
#[test]
fn aborting_the_review_writes_nothing() {
    let fixture_path = test_util::covid_vcf_path();
    let dir = tempfile::tempdir().unwrap();
    let pkg = dir.path().join("package.yaml");
    let p = scripted_author(fixture_path.to_str().unwrap()).with_selects(vec![
        1, // assembly
        0, // prefix
        0, // access rights
        0, // license
        2, // review: abort
    ]);
    let err = gdi_dataset_tool::wizard::author::author_greenfield(
        &p,
        &pkg,
        &gdi_dataset_tool::wizard::author::AuthorContext::default(),
        false,
    )
    .expect_err("abort at the review must fail authoring");
    assert!(err.message.contains("discarded"), "{}", err.message);
    assert!(!pkg.exists(), "nothing may be written after an abort");
}

/// With `org` on the profile the Author stage neither asks for it nor offers to remember
/// it — the scripted answers carry no org input and no "remember" confirm, so an extra
/// prompt would run the prompter dry.
#[test]
fn the_profile_org_is_used_without_asking() {
    let fixture_path = test_util::covid_vcf_path();
    let dir = tempfile::tempdir().unwrap();
    let pkg = dir.path().join("package.yaml");
    let config_path = dir.path().join("tool.toml");
    std::fs::write(
        &config_path,
        "country_code = \"EE\"\n\n[profiles.default]\norg = \"UTARTU\"\n",
    )
    .unwrap();
    let p = ScriptedPrompter::new()
        .with_inputs(vec![
            fixture_path.to_str().unwrap(),
            "gdi-aggregated",
            "AF test (synthetic data)",
            "Synthetic allele-frequency test dataset.",
            "allele-frequency,genomics",
            "2504",
            "Test Institute",
            "0",
        ])
        .with_selects(vec![1, 0, 0, 0, 0])
        .with_multiselects(vec![
            vec![2], // health categories: Human genomic
            vec![],  // conformsTo: nothing ticked
            vec![0], // applicable legislation: the EHDS row only
        ])
        .with_confirms(vec![
            false, // Add another VCF?
            true,  // keywords
            true,  // cohort
            true,  // synthetic
            false, // Add another legislation ELI or IRI?
            true,  // GoE provenance
        ]);
    gdi_dataset_tool::wizard::run(
        &p,
        &WizardArgs {
            command: None,
            from: Stage::Author,
            to: Stage::Author,
            output: pkg.clone(),
            recipient: None,
        },
        None,
        Some(&config_path),
    )
    .expect("authoring with a profile org must succeed");
    let yaml = std::fs::read_to_string(&pkg).unwrap();
    assert!(yaml.contains("org: \"UTARTU\""), "{yaml}");
}

/// Without `org` on the profile the Author stage asks once and, when told to, stores the
/// answer in the profile — so the next run never asks.
#[test]
fn a_typed_org_is_remembered_in_the_profile_when_asked_to() {
    let fixture_path = test_util::covid_vcf_path();
    let dir = tempfile::tempdir().unwrap();
    let pkg = dir.path().join("package.yaml");
    let config_path = dir.path().join("tool.toml");
    std::fs::write(
        &config_path,
        "country_code = \"EE\"\n\n[profiles.default]\nservice_url = \"https://node.example.org\"\n",
    )
    .unwrap();
    let p = scripted_author(fixture_path.to_str().unwrap()).with_confirms(vec![
        false, // Add another VCF?
        true,  // Remember the org in the profile? yes
        false, // No catalogs pinned — fetch the node's list now? (the profile names a node)
        true,  // keywords
        true,  // cohort
        true,  // synthetic
        false, // Add another legislation ELI or IRI?
        true,  // GoE provenance
    ]);
    gdi_dataset_tool::wizard::run(
        &p,
        &WizardArgs {
            command: None,
            from: Stage::Author,
            to: Stage::Author,
            output: pkg,
            recipient: None,
        },
        None,
        Some(&config_path),
    )
    .expect("authoring must succeed");
    let cfg = gdi_node_standalone_core::config::ToolConfig::load(Some(&config_path)).unwrap();
    assert_eq!(
        cfg.profiles["default"].org.as_deref(),
        Some("UTARTU"),
        "the org must have been stored in the profile"
    );
    assert_eq!(
        cfg.profiles["default"].service_url.as_deref(),
        Some("https://node.example.org"),
        "storing the org must not disturb the rest of the profile"
    );
}
