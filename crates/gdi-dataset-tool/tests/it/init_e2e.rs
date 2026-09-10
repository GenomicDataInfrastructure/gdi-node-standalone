//! End-to-end tests for `gdi-dataset-tool init`.
//!
//! Asserts the scaffolded template (a) is rejected by `build` as-is (its
//! `REPLACE:` markers are present), and (b) after the `REPLACE:` markers are
//! filled in, parses as a valid `PackageYaml` with the EHDS ELI pre-filled.
// Every test pins `GDI_CONFIG_DIR` to its own tempdir so a user-level
// `~/.config/gdi/tool.toml` cannot leak settings into the assertions.
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::fs;
use std::path::Path;

use clap::Parser as _;
use gdi_dataset_tool::cli::Cli;
use gdi_node_standalone_core::model::{DatasetMode, PackageYaml};
use serial_test::serial;

/// The EHDS ELI the template pre-fills into `applicableLegislation`.
const EHDS_ELI: &str = "http://data.europa.eu/eli/reg/2025/327/oj";

fn run_init(out: &Path) {
    let cli =
        Cli::try_parse_from(["gdi-dataset-tool", "init", "-o", out.to_str().unwrap()]).unwrap();
    gdi_dataset_tool::run(cli).expect("init succeeds");
}

#[test]
#[serial(env)]
fn init_writes_template_rejected_by_build_as_is() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("cfg"));
    let out = tmp.path().join("package.yaml");
    run_init(&out);
    assert!(out.is_file(), "init must write the template");

    let body = fs::read_to_string(&out).unwrap();
    assert!(body.contains(EHDS_ELI), "EHDS ELI must be pre-filled");
    assert!(
        body.contains("REPLACE:"),
        "REQUIRED fields are placeholders"
    );

    // build over the unfilled template must fail (REPLACE markers present).
    let cli = Cli::try_parse_from([
        "gdi-dataset-tool",
        "build",
        out.to_str().unwrap(),
        "--cc",
        "EE",
        "-o",
        tmp.path().join("build").to_str().unwrap(),
    ])
    .unwrap();
    let err = gdi_dataset_tool::run(cli).expect_err("unfilled template is rejected");
    assert_eq!(err.exit_code, 1);
    assert!(
        err.message.contains("REPLACE"),
        "the error must name the REPLACE marker; got {}",
        err.message
    );
}

#[test]
#[serial(env)]
fn init_does_not_ship_an_active_number_of_unique_individuals() {
    // The scaffold must leave `numberOfUniqueIndividuals` commented out. An active
    // `numberOfUniqueIndividuals: 0` is a valid cohort size, so a provider who fills only
    // the REPLACE markers would ship a dataset advertising a cohort of zero and `--strict`
    // would pass it. Absent, the recommended-field-absent path warns under `--strict`.
    //
    // This asserts the rule through the CLI. The wizard is the other renderer of the same
    // rule and is guarded separately by
    // `wizard::author::tests::no_tool_authored_package_ships_a_cohort_size_of_zero`.
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("cfg"));
    let out = tmp.path().join("package.yaml");
    run_init(&out);
    let body = fs::read_to_string(&out).unwrap();

    let has_active = body
        .lines()
        .any(|l| l.trim_start().starts_with("numberOfUniqueIndividuals:"));
    assert!(
        !has_active,
        "the scaffold must NOT ship an active numberOfUniqueIndividuals (a literal 0 passes \
         --strict silently); it must be commented so --strict warns while absent. Body:\n{body}"
    );
    // The field is still documented (shown commented) so a provider knows to set it.
    assert!(
        body.contains("numberOfUniqueIndividuals"),
        "the field must still be documented (commented) in the scaffold"
    );
}

#[test]
#[serial(env)]
fn init_refuses_existing_without_force() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("cfg"));
    let out = tmp.path().join("package.yaml");
    run_init(&out);
    let cli =
        Cli::try_parse_from(["gdi-dataset-tool", "init", "-o", out.to_str().unwrap()]).unwrap();
    let err = gdi_dataset_tool::run(cli).expect_err("existing file without --force fails");
    assert_eq!(err.exit_code, 1);
    assert!(err.message.contains("already exists"));

    // --force overwrites.
    let cli = Cli::try_parse_from([
        "gdi-dataset-tool",
        "init",
        "-o",
        out.to_str().unwrap(),
        "--force",
    ])
    .unwrap();
    gdi_dataset_tool::run(cli).expect("init --force overwrites");
}

#[test]
#[serial(env)]
fn init_scaffolds_catalog_names_from_profile_allow_list() {
    // The profile `catalogs` allow-list scaffolds `init`'s
    // `metadata.catalog`, offline. The first name becomes the value; others are
    // listed in a trailing comment.
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("cfg"));
    let cfg = tmp.path().join("tool.toml");
    fs::write(
        &cfg,
        "[profiles.default]\n\n[profiles.default.catalogs]\ngdi-aggregated = \"Genome of Europe Aggregated\"\n\
         synthetic-data = \"Synthetic\"\n",
    )
    .unwrap();

    let out = tmp.path().join("package.yaml");
    let cli = Cli::try_parse_from([
        "gdi-dataset-tool",
        "--config",
        cfg.to_str().unwrap(),
        "--profile",
        "default",
        "init",
        "-o",
        out.to_str().unwrap(),
    ])
    .unwrap();
    gdi_dataset_tool::run(cli).expect("init --profile default succeeds");

    let body = fs::read_to_string(&out).unwrap();
    // The first allow-listed name (BTreeMap-sorted) is the value, not a REPLACE.
    assert!(
        body.contains(r#"catalog: "gdi-aggregated""#),
        "the catalog value must be scaffolded from the allow-list; body:\n{body}"
    );
    assert!(
        !body.contains("REPLACE: catalog name"),
        "the static catalog placeholder must be replaced; body:\n{body}"
    );
    // The other catalog is offered in a comment.
    assert!(
        body.contains("other allowed catalogs: synthetic-data"),
        "remaining catalogs must be listed in a comment; body:\n{body}"
    );

    // The scaffolded YAML still parses (the catalog comment is valid YAML).
    let parsed: PackageYaml = serde_saphyr::from_str(&body.replace("REPLACE:", "filled-")).unwrap();
    assert_eq!(parsed.metadata.catalog, "gdi-aggregated");
}

#[test]
#[serial(env)]
fn init_keeps_static_placeholder_without_profile_catalogs() {
    // With no catalogs allow-list, `init` keeps the static placeholder (and must
    // not fail or require a profile).
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("cfg"));
    let cfg = tmp.path().join("tool.toml");
    fs::write(&cfg, "[profiles.default]\n").unwrap();

    let out = tmp.path().join("package.yaml");
    let cli = Cli::try_parse_from([
        "gdi-dataset-tool",
        "--config",
        cfg.to_str().unwrap(),
        "init",
        "-o",
        out.to_str().unwrap(),
    ])
    .unwrap();
    gdi_dataset_tool::run(cli).expect("init without catalogs succeeds");

    let body = fs::read_to_string(&out).unwrap();
    assert!(
        body.contains(r#"catalog: "REPLACE: catalog name""#),
        "the static placeholder must remain without an allow-list; body:\n{body}"
    );
}

#[test]
#[serial(env)]
fn filled_template_parses_as_valid_package_with_ehds_eli() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("cfg"));
    let out = tmp.path().join("package.yaml");
    run_init(&out);

    // Fill every REPLACE marker with a plausible value, then parse.
    let body = fs::read_to_string(&out).unwrap();
    let filled = body
        .replace("REPLACE: GOE or GDI", "GOE")
        .replace("REPLACE: ORG", "UTARTU")
        .replace("REPLACE: catalog name", "gdi-aggregated")
        .replace("REPLACE: Dataset title", "Aggregated allele frequencies")
        .replace(
            "REPLACE: Dataset description",
            "Aggregated allele frequencies for a cohort.",
        )
        .replace(
            "REPLACE: http://publications.europa.eu/resource/authority/access-right/PUBLIC",
            "http://publications.europa.eu/resource/authority/access-right/PUBLIC",
        )
        .replace(
            "REPLACE: license IRI",
            "https://creativecommons.org/licenses/by/4.0/",
        )
        .replace(
            "REPLACE: Creating organisation",
            "Genome of Europe - EE node",
        )
        .replace(
            "REPLACE: http://data.gdi.eu/core/p2/HealthCategoryHumanGenomic",
            "http://data.gdi.eu/core/p2/HealthCategoryHumanGenomic",
        )
        .replace("REPLACE: GRCh38", "GRCh38")
        .replace("REPLACE: path/to/your.vcf.gz", "data.vcf.gz")
        .replace("REPLACE: study or cohort name", "The Genome of Europe")
        .replace(
            "REPLACE: https://example.org/",
            "https://genomeofeurope.eu/",
        );

    assert!(
        !filled.contains("REPLACE:"),
        "all REPLACE markers should be filled; leftover in:\n{filled}"
    );

    let parsed: PackageYaml = serde_saphyr::from_str(&filled).expect("filled template parses");
    assert_eq!(
        parsed.metadata.applicable_legislation,
        vec![EHDS_ELI.to_owned()],
        "the EHDS ELI must survive into the parsed package"
    );
    assert_eq!(parsed.metadata.prefix.as_deref(), Some("GOE"));
    assert_eq!(parsed.metadata.catalog, "gdi-aggregated");
    assert_eq!(parsed.config.mode, DatasetMode::Aggregated);
    assert_eq!(parsed.files.len(), 1);
    assert!(parsed.files[0].category.eq_ignore_ascii_case("VCF"));
}
