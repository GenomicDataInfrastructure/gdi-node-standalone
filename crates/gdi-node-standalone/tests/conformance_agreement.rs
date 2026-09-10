//! The dual-encoding agreement guard.
//!
//! The Rust build-time gate (`validate_package`) and the pySHACL shapes are two independent
//! encodings of the same gdi-metadata model, so they can drift. This test pins them together
//! over the fixture corpus in `conformance/fixtures/`:
//!
//! * a pure-Rust portion, which always runs, asserts `validate_package` accepts the valid
//!   baseline and rejects each negative fixture, that each negative is the baseline plus
//!   exactly one perturbation, and that it is rejected for the rule it is named after
//!   (missing mandatory, bad enum, bad pattern, uniqueLang collision) rather than for some
//!   other reason;
//! * an `#[ignore]` portion, which needs the venv, renders the corresponding dataset record
//!   to RDF and runs `conformance/check_dataset.py` (pySHACL over the gdi-metadata shapes),
//!   asserting pySHACL gives the same verdict the Rust gate gave (valid conforms, negative
//!   violates) and names the same rule. A divergence on either fails.
//!
//! Both sides read the same on-disk `package.yaml`: the gate validates it directly, and
//! [`Fixture::metadata`] parses it into the model to render the RDF. A rejected package never
//! reaches rendering in production, so rendering one here is what asks the dual-encoding
//! question: if a hole let a bad value through the Rust gate, would pySHACL catch it, and the
//! other way round.
#![allow(
    clippy::disallowed_methods,
    reason = "test/bench code writes plain files: durability and atomicity are not properties under test"
)]
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use gdi_node_standalone_core::cache::DatasetEntry;
use gdi_node_standalone_core::config::{
    ContactPointCfg, FairdpConfig, FairdpHdab, FairdpPublisher,
};
use gdi_node_standalone_core::model::{
    Assembly, DatasetMode, ManifestConfig, ManifestMetadata, PackageYaml,
};
use gdi_node_standalone_core::state::DatasetState;
use gdi_node_standalone_core::validate_pkg::{validate_overlay_result, validate_package};
use gdi_node_standalone_fairdp::{FdpContext, dataset_graph, serialize_turtle};

const BASE_URL: &str = "https://test.example.org";
const BEACON_PATH: &str = "/beacon/v2";
const DATASET_ID: &str = "GDI-EE-UTARTU-20260409143052837";

/// Which single rule a fixture breaks (or `Valid`). The agreement test pairs the
/// Rust-gate verdict and the pySHACL verdict per variant.
#[derive(Debug, Clone, Copy)]
enum Fixture {
    Valid,
    MissingMandatoryHealthCategory,
    MissingDescription,
    BadEnumAccessRights,
    BadEmailPattern,
    UniqueLangCollision,
}

impl Fixture {
    /// The package.yaml file under `conformance/fixtures/` this variant drives.
    fn package_path(self) -> PathBuf {
        let fixtures = conformance_dir().join("fixtures");
        match self {
            Fixture::Valid => fixtures.join("valid/baseline.package.yaml"),
            Fixture::MissingMandatoryHealthCategory => {
                fixtures.join("negative/missing-mandatory-health-category.package.yaml")
            }
            Fixture::MissingDescription => {
                fixtures.join("negative/missing-description.package.yaml")
            }
            Fixture::BadEnumAccessRights => {
                fixtures.join("negative/bad-enum-access-rights.package.yaml")
            }
            Fixture::BadEmailPattern => fixtures.join("negative/bad-email-pattern.package.yaml"),
            Fixture::UniqueLangCollision => {
                fixtures.join("negative/unique-lang-collision.package.yaml")
            }
        }
    }

    /// Whether the Rust gate is expected to accept this fixture.
    fn rust_accepts(self) -> bool {
        matches!(self, Fixture::Valid)
    }

    /// The rule this fixture exists to exercise, as a substring of the gate's error.
    ///
    /// Without this, the corpus only proves the fixture is rejected for some reason. A
    /// negative that also dropped a mandatory field would still be rejected, the test would
    /// stay green, and the fixture would stop proving the rule it is named after. `None` for
    /// the valid baseline.
    fn expected_rejection(self) -> Option<&'static str> {
        match self {
            Fixture::Valid => None,
            Fixture::MissingMandatoryHealthCategory => Some("healthCategory"),
            Fixture::MissingDescription => Some("description"),
            Fixture::BadEnumAccessRights => Some("accessRights"),
            Fixture::BadEmailPattern => Some("hasEmail"),
            Fixture::UniqueLangCollision => Some("title"),
        }
    }

    /// The SHACL rule this fixture must be rejected by, as a substring of pySHACL's report.
    ///
    /// The mirror of [`Self::expected_rejection`] on the Python side. `check_dataset.py`
    /// prints `VIOLATES: <message>`, so the reason is on the wire; comparing only the boolean
    /// verdict would let a fixture that starts violating a different constraint keep the test
    /// green while ceasing to exercise its own rule.
    ///
    /// This names the constraint (`not in list` for `sh:in`, `same Language` for
    /// `sh:uniqueLang`, `gdi:KindShape` for the contact-point node shape) rather than the
    /// field, so a message that merely mentions the field cannot satisfy it.
    fn expected_shacl_rejection(self) -> Option<&'static str> {
        match self {
            Fixture::Valid => None,
            Fixture::MissingMandatoryHealthCategory => Some("healthdcatap:healthCategory"),
            Fixture::MissingDescription => Some("dct:description"),
            Fixture::BadEnumAccessRights => Some("not in list"),
            Fixture::BadEmailPattern => Some("gdi:KindShape"),
            Fixture::UniqueLangCollision => Some("same Language"),
        }
    }

    /// The dotted field paths on which this fixture's `package.yaml` may differ from the
    /// baseline: its one perturbation, and nothing else.
    ///
    /// This is the structural half of the guard, and it closes what error-message pinning
    /// cannot. `validate_package_collect_all` reports section-level errors and each section
    /// short-circuits at its first `?`, so a second violation inside the same section is
    /// invisible to the gate. Comparing the parsed fixture against the parsed baseline sees
    /// it whatever the gate reports.
    fn expected_diff_paths(self) -> &'static [&'static str] {
        match self {
            Fixture::Valid => &[],
            Fixture::MissingMandatoryHealthCategory => &["metadata.healthCategory"],
            Fixture::MissingDescription => &["metadata.description"],
            Fixture::BadEnumAccessRights => &["metadata.accessRights"],
            Fixture::BadEmailPattern => &["metadata.contactPoint.hasEmail"],
            Fixture::UniqueLangCollision => &["metadata.title.EN"],
        }
    }

    /// Build the rendered dataset record's metadata from this fixture's on-disk
    /// `package.yaml`, the same file the Rust gate reads.
    ///
    /// Deriving this from the YAML rather than hand-authoring a second encoding keeps the two
    /// sides from drifting: pySHACL only ever sees this side, so a field the YAML carries but
    /// a hand-written struct omitted would go unexercised.
    fn metadata(self) -> ManifestMetadata {
        let m = self.package_yaml().metadata;
        ManifestMetadata {
            // `package.yaml` carries `prefix` and `org`; the node mints `datasetId` at build
            // time. This test renders rather than ingests, so pin the constant the FDP context
            // is configured with.
            dataset_id: DATASET_ID.to_owned(),
            catalog: m.catalog,
            title: m.title,
            description: m.description,
            access_rights: m.access_rights,
            applicable_legislation: m.applicable_legislation,
            license: m.license,
            creator: m.creator,
            health_category: m.health_category,
            keywords: m.keywords,
            number_of_unique_individuals: m.number_of_unique_individuals,
            conforms_to: m.conforms_to,
            type_: m.type_,
            legal_basis: m.legal_basis,
            is_referenced_by: m.is_referenced_by,
            other_identifier: m.other_identifier,
            contact_point: m.contact_point,
            // Not authored in `package.yaml`: the node computes both during ingest. This test
            // renders a record instead, so a synthetic count is right (any nonNegativeInteger
            // validates) and there are no per-population rows to derive.
            number_of_records: Some(123_456),
            populations: None,
        }
    }

    /// This fixture's `package.yaml`, parsed. The single authored copy of the fixture.
    fn package_yaml(self) -> PackageYaml {
        let raw = std::fs::read_to_string(self.package_path()).unwrap();
        serde_saphyr::from_str(&raw)
            .unwrap_or_else(|e| panic!("{self:?} must deserialize to be rendered: {e}"))
    }
}

const ALL_FIXTURES: &[Fixture] = &[
    Fixture::Valid,
    Fixture::MissingMandatoryHealthCategory,
    Fixture::MissingDescription,
    Fixture::BadEnumAccessRights,
    Fixture::BadEmailPattern,
    Fixture::UniqueLangCollision,
];

/// The node-identity FDP config for rendering.
fn fairdp_config() -> FairdpConfig {
    FairdpConfig {
        title: "GDI Estonia FAIR Data Point".to_owned(),
        description: Some("Aggregated genomic metadata for GDI Estonia".to_owned()),
        issued: "2026-01-01T00:00:00Z".to_owned(),
        license: "https://creativecommons.org/licenses/by/4.0/".to_owned(),
        language: "http://publications.europa.eu/resource/authority/language/ENG".to_owned(),
        theme: vec!["http://publications.europa.eu/resource/authority/data-theme/HEAL".to_owned()],
        theme_taxonomy: None,
        applicable_legislation: vec!["http://data.europa.eu/eli/reg/2025/327/oj".to_owned()],
        publisher: FairdpPublisher {
            name: "University of Tartu".to_owned(),
            homepage: Some("https://gdi.ut.ee".to_owned()),
            mbox: Some("mailto:gdi@example.org".to_owned()),
            contact_point: ContactPointCfg {
                fn_: "GDI Estonia".to_owned(),
                has_email: "mailto:gdi@example.org".to_owned(),
                // Distinct from homepage (see fairdp/tests/render.rs).
                has_url: Some("https://gdi.ut.ee/contact".to_owned()),
            },
        },
        hdab: FairdpHdab {
            name: "Estonian HDAB".to_owned(),
            contact_point: ContactPointCfg {
                fn_: "Estonian HDAB".to_owned(),
                has_email: "mailto:hdab@example.org".to_owned(),
                has_url: None,
            },
        },
    }
}

/// A minimal config block for rendering the entry (config never feeds dataset RDF
/// rules the fixtures touch).
fn render_config() -> ManifestConfig {
    ManifestConfig {
        mode: DatasetMode::Aggregated,
        block_range: 10_000_000,
        af_source: None,
        af_source_reference: None,
        min_allele_count: 0,
        hide_lower_counts: None,
        assembly: Assembly {
            reference: "GRCh38".to_owned(),
        },
        manifest_version: 1,
        generated_by: "test".to_owned(),
    }
}

/// The node catalog allow-list used by the Rust gate.
fn node_catalogs() -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert("gdi-aggregated".to_owned(), "GoE Aggregated".to_owned());
    m
}

fn conformance_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance")
        .canonicalize()
        .expect("conformance/ exists")
}

fn venv_python() -> PathBuf {
    if let Ok(py) = std::env::var("GDI_FDP_PYTHON") {
        return PathBuf::from(py);
    }
    if let Ok(venv) = std::env::var("GDI_FDP_VENV") {
        return PathBuf::from(venv).join("bin/python");
    }
    // The fallback when neither GDI_FDP_PYTHON nor GDI_FDP_VENV is set. If this interpreter
    // is absent the test fails hard: `pyshacl_conforms` panics on the failed spawn rather than
    // reporting a false green.
    std::env::temp_dir().join("gdi-node-standalone-fdp-venv/bin/python")
}

/// The Rust-gate verdict for a fixture: parse its package.yaml and run
/// `validate_package`.
fn rust_gate_accepts(fixture: Fixture) -> bool {
    let raw = std::fs::read_to_string(fixture.package_path()).unwrap();
    let pkg: PackageYaml = match serde_saphyr::from_str(&raw) {
        Ok(p) => p,
        // A package that does not even deserialize is a rejection too.
        Err(_) => return false,
    };
    validate_package(&pkg, Some(&node_catalogs())).is_ok()
}

/// The pySHACL verdict for a fixture: render its dataset record, write it, and run
/// `check_dataset.py`. Returns `true` when pySHACL reports conformance.
fn pyshacl_conforms(fixture: Fixture, py: &Path, out_dir: &Path) -> (bool, String) {
    let fairdp = fairdp_config();
    let ctx = FdpContext::new(BASE_URL, BEACON_PATH, &fairdp);
    let entry = DatasetEntry {
        id: DATASET_ID.to_owned(),
        metadata: fixture.metadata(),
        config: render_config(),
        state: DatasetState::Visible,
        metadata_modified: None,
    };
    let ttl = serialize_turtle(&dataset_graph(&entry, &ctx));
    let file = out_dir.join(format!("dataset-{}.ttl", variant_slug(fixture)));
    std::fs::write(&file, &ttl).unwrap();

    let script = conformance_dir().join("check_dataset.py");
    let output = Command::new(py)
        .arg(&script)
        .arg(&file)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn {}: {e}", py.display()));
    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    // Exit 0 conforms, 1 violates. Exit 2 is a usage error and is a hard fail.
    assert!(
        output.status.code() == Some(0) || output.status.code() == Some(1),
        "check_dataset.py errored (not a clean conforms/violates) for {fixture:?}:\n{combined}"
    );
    (output.status.success(), combined)
}

fn variant_slug(fixture: Fixture) -> &'static str {
    match fixture {
        Fixture::Valid => "valid",
        Fixture::MissingMandatoryHealthCategory => "missing-health-category",
        Fixture::MissingDescription => "missing-description",
        Fixture::BadEnumAccessRights => "bad-enum",
        Fixture::BadEmailPattern => "bad-email",
        Fixture::UniqueLangCollision => "unique-lang",
    }
}

/// Every hard error the Rust gate reports for a fixture's on-disk `package.yaml`.
fn rust_gate_errors(fixture: Fixture) -> Vec<String> {
    let raw = std::fs::read_to_string(fixture.package_path()).unwrap();
    let pkg: PackageYaml = match serde_saphyr::from_str(&raw) {
        Ok(p) => p,
        Err(e) => return vec![format!("deserialize: {e}")],
    };
    gdi_node_standalone_core::validate_pkg::validate_package_collect_all(
        &pkg,
        Some(&node_catalogs()),
    )
    .errors
    .iter()
    .map(ToString::to_string)
    .collect()
}

/// A fixture's `package.yaml` parsed into the model, then into JSON for structural diffing.
fn fixture_json(fixture: Fixture) -> serde_json::Value {
    let raw = std::fs::read_to_string(fixture.package_path()).unwrap();
    let pkg: PackageYaml = serde_saphyr::from_str(&raw)
        .unwrap_or_else(|e| panic!("{fixture:?} must deserialize to compare it: {e}"));
    serde_json::to_value(pkg).unwrap()
}

/// The dotted paths at which two JSON values differ. A key present in only one side is a
/// difference at that key; scalars and arrays are compared whole.
fn diff_paths(a: &serde_json::Value, b: &serde_json::Value, prefix: &str, out: &mut Vec<String>) {
    match (a, b) {
        (serde_json::Value::Object(ma), serde_json::Value::Object(mb)) => {
            let mut keys: Vec<&String> = ma.keys().chain(mb.keys()).collect();
            keys.sort_unstable();
            keys.dedup();
            for k in keys {
                let path = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                match (ma.get(k), mb.get(k)) {
                    (Some(va), Some(vb)) => diff_paths(va, vb, &path, out),
                    _ => out.push(path),
                }
            }
        }
        _ => {
            if a != b {
                out.push(prefix.to_owned());
            }
        }
    }
}

/// Every negative fixture is the baseline plus exactly one perturbation.
///
/// `conformance/fixtures/valid/baseline.package.yaml` says each negative derives from it and
/// breaks the single rule its filename names. The rejection-reason guard cannot see a second
/// violation inside the same validation section, because sections short-circuit at their
/// first `?`, so an extra perturbation could take over as the real cause while the test
/// stayed green.
///
/// Comparing the parsed fixture against the parsed baseline is independent of the gate and
/// catches that.
#[test]
fn each_negative_fixture_is_a_single_perturbation_of_the_baseline() {
    let baseline = fixture_json(Fixture::Valid);
    for &fixture in ALL_FIXTURES {
        if matches!(fixture, Fixture::Valid) {
            continue;
        }
        let mut paths = Vec::new();
        diff_paths(&baseline, &fixture_json(fixture), "", &mut paths);
        paths.sort();

        let expected: Vec<String> = fixture
            .expected_diff_paths()
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        assert_eq!(
            paths, expected,
            "{fixture:?} must differ from the baseline at EXACTLY its named field.\n  \
             expected: {expected:?}\n  actual:   {paths:?}\n\
             An extra difference means the fixture no longer isolates the rule it is named \
             for; a missing one means it no longer perturbs anything."
        );
    }
}

/// Each negative fixture is rejected for the rule it is named after, not merely rejected.
///
/// A boolean accept/reject alone would let a fixture that broke some other rule keep being
/// rejected while no longer exercising the rule in its filename. Two assertions cover that:
/// the gate reports exactly one error (catching a second violation in a different validation
/// section), and that error names the fixture's rule (catching a rejection for something else
/// entirely, including a YAML that no longer deserializes).
///
/// Neither sees a second violation inside the same section, because a section short-circuits
/// at its first `?`. That blind spot is covered structurally by
/// [`each_negative_fixture_is_a_single_perturbation_of_the_baseline`], which compares the
/// parsed fixtures and never consults the gate. Keep both.
#[test]
fn each_negative_fixture_is_rejected_for_its_own_rule() {
    for &fixture in ALL_FIXTURES {
        let errors = rust_gate_errors(fixture);
        let Some(expected) = fixture.expected_rejection() else {
            assert!(
                errors.is_empty(),
                "the valid baseline must produce no errors, got: {errors:?}"
            );
            continue;
        };

        assert_eq!(
            errors.len(),
            1,
            "{fixture:?} must trip exactly one validation SECTION, but the gate reported \
             {} errors: {errors:?}",
            errors.len()
        );
        assert!(
            errors[0].contains(expected),
            "{fixture:?} is rejected for the WRONG reason: expected an error naming \
             `{expected}`, got `{}`. The fixture no longer proves the rule it is named for.",
            errors[0]
        );
    }
}

/// Pure-Rust: the Rust gate's verdict on every fixture (no Python). Asserts the
/// valid baseline is accepted and every negative is rejected.
#[test]
fn rust_gate_accepts_valid_rejects_negatives() {
    for &fixture in ALL_FIXTURES {
        let accepts = rust_gate_accepts(fixture);
        assert_eq!(
            accepts,
            fixture.rust_accepts(),
            "Rust gate verdict mismatch for {fixture:?}: got accepts={accepts}, expected accepts={}",
            fixture.rust_accepts()
        );

        // Validator agreement. `metadata()` is derived from the same on-disk `package.yaml`
        // the gate read above, so the two encodings cannot drift; that is structural. What
        // this pins is different: the package validator (`validate_package`, over
        // `PackageYaml`) and the overlay validator (`validate_overlay_result`, over
        // `ManifestMetadata`) are two validators of the same field model, and they can
        // diverge. No Python needed.
        let struct_result = validate_overlay_result(&fixture.metadata());
        let struct_accepts = struct_result.is_ok();
        assert_eq!(
            struct_accepts, accepts,
            "VALIDATOR DIVERGENCE for {fixture:?}: the overlay gate and the package gate \
             disagree on the same fixture (overlay_accepts={struct_accepts}, \
             package_accepts={accepts}) — one of them has stopped enforcing a rule."
        );

        // Agreeing on the verdict is not agreeing on the reason: two validators can reject
        // for different rules and a boolean comparison calls that agreement. This closes the
        // same weakness `expected_rejection` closes on the package side.
        if let (Some(needle), Err(err)) = (fixture.expected_rejection(), struct_result) {
            let msg = err.to_string();
            assert!(
                msg.contains(needle),
                "VALIDATOR DIVERGENCE for {fixture:?}: the overlay gate rejects it, but for \
                 the WRONG rule — expected an error naming {needle:?}, got {msg:?}. Both \
                 gates rejecting is not the same as both enforcing the same rule."
            );
        }
    }
}

/// `ALL_FIXTURES` must cover every fixture file on disk.
///
/// The corpus is iterated, never counted, so adding a negative `package.yaml` without its
/// `Fixture` variant would leave every test above looking at a smaller set and still
/// reporting green. This counts the real files in the fixture directories.
#[test]
fn all_fixtures_covers_every_fixture_file_on_disk() {
    let fixtures = conformance_dir().join("fixtures");
    let count_yaml = |dir: &str| {
        std::fs::read_dir(fixtures.join(dir))
            .unwrap_or_else(|e| panic!("cannot read {dir} fixtures: {e}"))
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".package.yaml"))
            .count()
    };
    let on_disk = count_yaml("valid") + count_yaml("negative");
    assert_eq!(
        ALL_FIXTURES.len(),
        on_disk,
        "ALL_FIXTURES has {} entries but conformance/fixtures/ holds {on_disk} \
         *.package.yaml file(s) — a fixture was added or removed without updating the \
         Fixture enum, so the corpus silently covers less than it appears to.",
        ALL_FIXTURES.len()
    );

    // Every variant must also point at a file that exists, so a matching count cannot be a
    // coincidence of two wrong numbers.
    for &fixture in ALL_FIXTURES {
        let path = fixture.package_path();
        assert!(
            path.is_file(),
            "{fixture:?} points at {} which does not exist",
            path.display()
        );
    }
}

/// Dual-encoding agreement: pySHACL gives the same verdict the Rust gate gives on every
/// fixture, so the valid baseline conforms and each negative violates. A divergence between
/// the two independent encodings fails the build.
#[test]
#[ignore = "needs the Python conformance venv; run with --ignored and GDI_FDP_PYTHON/GDI_FDP_VENV"]
fn rust_gate_and_pyshacl_agree() {
    let py = venv_python();
    let out_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/conformance/agreement");
    std::fs::create_dir_all(&out_dir).unwrap();

    for &fixture in ALL_FIXTURES {
        let rust_accepts = rust_gate_accepts(fixture);
        // `rust_gate_accepts_valid_rejects_negatives` pins the Rust-gate verdict without
        // Python. This adds the pySHACL cross-check over the same fixtures.
        let (pyshacl_conforms, out) = pyshacl_conforms(fixture, &py, &out_dir);
        println!(
            "{fixture:?}: rust_accepts={rust_accepts} pyshacl_conforms={pyshacl_conforms}\n{out}"
        );

        assert_eq!(
            rust_accepts, pyshacl_conforms,
            "DUAL-ENCODING DIVERGENCE for {fixture:?}: Rust gate accepts={rust_accepts} but \
             pySHACL conforms={pyshacl_conforms} — the two encodings disagree.\n{out}"
        );

        // Agreeing on the verdict is not agreeing on the rule. Pin pySHACL's rejection to the
        // constraint this fixture exists to break, as the Rust side does.
        if let Some(needle) = fixture.expected_shacl_rejection() {
            assert!(
                out.contains(needle),
                "WRONG SHACL RULE for {fixture:?}: pySHACL rejected it, but the report does \
                 not name {needle:?} — this fixture is no longer exercising the constraint \
                 it is named after.\n{out}"
            );
        }
    }
}
