//! End-to-end test for `gdi-dataset-tool build` over the COVID reference VCF.
//!
//! Drives the library [`gdi_dataset_tool::run`] with a parsed `build` command
//! (no separate binary harness needed), then asserts the staging directory
//! layout and the generated `manifest.json` contents.
// Every test pins `GDI_CONFIG_DIR` to its own tempdir so a user-level
// `~/.config/gdi/tool.toml` cannot leak settings into the assertions.
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::fs;
use std::path::{Path, PathBuf};

use clap::Parser as _;
use gdi_dataset_tool::cli::{BuildArgs, Cli, HeaderPolicyArg, OutputFormat};
use gdi_dataset_tool::commands::cmd_build;
use gdi_node_standalone_core::model::{HeaderPolicy, Manifest};
use serial_test::serial;

/// Extract the error from a `build_staging_dir` call, panicking if it
/// unexpectedly succeeded. [`cmd_build::BuildOutput`] does not implement
/// `Debug`, so `.unwrap_err()` / `.expect_err()` do not compile.
fn expect_build_err(
    result: Result<cmd_build::BuildOutput, gdi_dataset_tool::ToolError>,
    context: &str,
) -> gdi_dataset_tool::ToolError {
    match result {
        Err(e) => e,
        Ok(_) => panic!("expected build to fail ({context}), but it succeeded"),
    }
}

/// Build a `BuildArgs` using the COVID fixture VCF + the given output dir.
///
/// Mirrors what the CLI does after parsing, so tests can call
/// `cmd_build::build_staging_dir` directly without spawning a subprocess.
fn covid_build_args(out: &Path) -> BuildArgs {
    let pkg_dir = out
        .parent()
        .expect("out must have a parent temp dir")
        .join("covid-pkg");
    BuildArgs {
        package: test_util::write_covid_package(&pkg_dir),
        country_code: Some("EE".to_owned()),
        out: out.to_path_buf(),
        force: false,
        no_headers: true,
        header_policy: None,
        strict: false,
        dry_run: false,
        build_epoch: None,
        jobs: 0,
        refresh_catalogs: false,
        format: OutputFormat::Text,
    }
}

/// Read a staging directory's parquet files into a `name -> bytes` map (excludes
/// `manifest.json`), so two builds can be compared byte-for-byte. Parquet file names
/// embed the source vcfid (a content hash), not the wall-clock dataset id, so they
/// are stable across builds.
fn parquet_files(staging: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
    let mut map = std::collections::BTreeMap::new();
    for entry in fs::read_dir(staging).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "parquet") {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            map.insert(name, fs::read(&path).unwrap());
        }
    }
    map
}

/// Parallel conversion must be deterministic: building the same multi-VCF package
/// sequentially (`--jobs 1`) and in parallel (`--jobs 4`) must yield byte-identical
/// parquet output and the same cross-VCF-deduped `numberOfRecords`. Conversion order,
/// which a parallel run varies, must not affect the result.
#[test]
#[serial(env)]
fn parallel_build_matches_sequential_build() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("cfg"));
    let pkg_dir = tmp.path().join("pkg");
    fs::create_dir_all(&pkg_dir).unwrap();

    // A per-population split: two VCFs over shared loci (3:100, 3:200) but distinct
    // populations (Total vs NL), so the (variant, population) pairs stay unique while
    // the (chr,POS,REF,ALT) keys overlap and must dedup. B adds 3:300. Distinct keys
    // across both = 3. Distinct bytes -> distinct vcfids.
    let hdr_total = "##fileformat=VCFv4.1\n\
##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
##contig=<ID=3>\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";
    let hdr_nl = "##fileformat=VCFv4.1\n\
##INFO=<ID=AF_NL,Number=A,Type=Float,Description=\"af nl\">\n\
##contig=<ID=3>\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";
    fs::write(
        pkg_dir.join("a.vcf"),
        format!("{hdr_total}3\t100\t.\tT\tC\t.\t.\tAF=0.5\n3\t200\t.\tA\tG\t.\t.\tAF=0.4\n"),
    )
    .unwrap();
    fs::write(
        pkg_dir.join("b.vcf"),
        format!(
            "{hdr_nl}3\t100\t.\tT\tC\t.\t.\tAF_NL=0.6\n3\t200\t.\tA\tG\t.\t.\tAF_NL=0.45\n3\t300\t.\tG\tT\t.\t.\tAF_NL=0.1\n"
        ),
    )
    .unwrap();

    // Reuse the validated covid package metadata, swapping the file list for our two
    // VCFs (so package validation passes for the same reasons the covid build does).
    let template = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/covid-package.yaml"),
    )
    .unwrap();
    let pkg_yaml = template.replace(
        "      - \"COVID.monogneic.aggregate.AFs.GRCh38.vcf\"",
        "      - \"a.vcf\"\n      - \"b.vcf\"",
    );
    assert!(
        pkg_yaml.contains("a.vcf"),
        "file-list substitution must apply"
    );
    let pkg_path = pkg_dir.join("package.yaml");
    fs::write(&pkg_path, pkg_yaml).unwrap();

    let build = |jobs: usize, out_name: &str| {
        let args = BuildArgs {
            package: pkg_path.clone(),
            country_code: Some("EE".to_owned()),
            out: tmp.path().join(out_name),
            force: false,
            no_headers: true,
            header_policy: None,
            strict: false,
            dry_run: false,
            build_epoch: None,
            jobs,
            refresh_catalogs: false,
            format: OutputFormat::Text,
        };
        let built = match cmd_build::build_staging_dir(&args, None, None) {
            Ok(b) => b,
            Err(e) => panic!("build jobs={jobs} failed: {e}"),
        };
        let raw = fs::read_to_string(built.staging.join("manifest.json")).unwrap();
        let manifest: Manifest = serde_json::from_str(&raw).unwrap();
        (
            manifest.metadata.number_of_records,
            parquet_files(&built.staging),
        )
    };

    let (n_seq, files_seq) = build(1, "seq");
    let (n_par, files_par) = build(4, "par");

    assert_eq!(
        n_seq,
        Some(3),
        "distinct (chr,POS,REF,ALT) across both VCFs"
    );
    assert_eq!(
        n_seq, n_par,
        "numberOfRecords must not depend on the job count"
    );
    assert_eq!(
        files_seq.len(),
        2,
        "one parquet file per VCF (single chr/block)"
    );
    assert_eq!(
        files_seq, files_par,
        "parquet output must be byte-identical regardless of the job count"
    );
}

/// Minimal required metadata lines for a package.yaml (all non-optional fields
/// plus `description` which is validated as mandatory by `validate_package`).
const MIN_META: &str = "\
metadata:
  prefix: \"GDI\"
  org: \"UTARTU\"
  catalog: \"gdi-aggregated\"
  title: \"Test dataset\"
  description: \"A test dataset for unit tests.\"
  accessRights: \"http://publications.europa.eu/resource/authority/access-right/PUBLIC\"
  applicableLegislation:
    - \"http://data.europa.eu/eli/reg/2025/327/oj\"
  license: \"https://creativecommons.org/licenses/by/4.0/\"
  creator:
    - name: \"Test\"
  healthCategory:
    - \"http://data.gdi.eu/core/p2/HealthCategoryHumanGenomic\"";

/// Build a minimal package.yaml that lists `vcf_name` under a VCF group with
/// the given `reference` assembly.  The YAML is written to `pkg_path`.
fn write_package_yaml(pkg_path: &Path, vcf_name: &str, reference: &str) {
    let yaml = format!(
        "{MIN_META}\nfiles:\n  - category: \"VCF\"\n    reference: \"{reference}\"\n    files:\n      - \"{vcf_name}\"\nconfig:\n  mode: aggregated\n  blockRange: 10000000\n  minAlleleCount: 0\n"
    );
    fs::write(pkg_path, yaml).unwrap();
}

/// Return the single subdirectory of `out` (the `<datasetId>/` staging directory).
fn single_subdir(out: &Path) -> PathBuf {
    let mut dirs: Vec<PathBuf> = fs::read_dir(out)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    assert_eq!(
        dirs.len(),
        1,
        "expected exactly one staging dir under {}",
        out.display()
    );
    dirs.remove(0)
}

#[test]
#[serial(env)]
fn build_produces_valid_staging_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("cfg"));
    let out = tmp.path().join("out");
    let package = test_util::write_covid_package(&tmp.path().join("covid-pkg"));

    let cli = Cli::try_parse_from([
        "gdi-dataset-tool",
        "build",
        package.to_str().unwrap(),
        "--cc",
        "EE",
        "-o",
        out.to_str().unwrap(),
    ])
    .unwrap();

    gdi_dataset_tool::run(cli).expect("build succeeds");

    // The staging directory is <out>/<datasetId>/.
    let staging = single_subdir(&out);
    let dataset_id = staging.file_name().unwrap().to_str().unwrap();
    assert!(
        dataset_id.starts_with("GDI-EE-UTARTU-"),
        "datasetId should encode the prefix/cc/org, got {dataset_id}"
    );

    // manifest.json must exist.
    let manifest_path = staging.join("manifest.json");
    assert!(manifest_path.is_file(), "manifest.json must be written");

    // At least one allele-freq.chr3.*.parquet must exist (chr3, block 4).
    let parquet_present = fs::read_dir(&staging)
        .unwrap()
        .filter_map(Result::ok)
        .any(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            name.starts_with("allele-freq.chr3.") && name.ends_with(".parquet")
        });
    assert!(
        parquet_present,
        "an allele-freq.chr3.*.parquet must be written"
    );

    // headers/{vcfid}.vcf must exist by default.
    let headers_dir = staging.join("headers");
    assert!(headers_dir.is_dir(), "headers/ must be written by default");
    let header_present = fs::read_dir(&headers_dir)
        .unwrap()
        .filter_map(Result::ok)
        .any(|e| e.file_name().to_string_lossy().ends_with(".vcf"));
    assert!(header_present, "a headers/{{vcfid}}.vcf must be written");

    // Parse the manifest and assert the computed/carried fields.
    let raw = fs::read_to_string(&manifest_path).unwrap();
    let manifest: Manifest = serde_json::from_str(&raw).expect("manifest parses");

    assert_eq!(manifest.metadata.dataset_id, dataset_id);
    assert_eq!(manifest.metadata.number_of_records, Some(1));
    assert_eq!(manifest.config.assembly.reference, "GRCh38");
    assert_eq!(
        manifest.config.af_source.as_deref(),
        Some("The Genome of Europe")
    );
    assert_eq!(
        manifest.config.af_source_reference.as_deref(),
        Some("https://genomeofeurope.eu/")
    );
    assert_eq!(manifest.config.manifest_version, 1);
    assert!(manifest.config.generated_by.starts_with("gdi-dataset-tool"));
    assert_eq!(manifest.metadata.catalog, "gdi-aggregated");

    // The files section carries computed sha256/size for every staged file.
    assert!(
        !manifest.files.is_empty(),
        "files section must be populated"
    );
    for group in &manifest.files {
        for entry in &group.files {
            assert_eq!(
                entry.sha256.as_ref().map(String::len),
                Some(64),
                "sha256 must be a 64-hex digest for {}",
                entry.path
            );
            assert!(
                entry.size.is_some(),
                "size must be computed for {}",
                entry.path
            );
        }
    }
}

// Guard tests: file-list shapes `build` must reject.

/// (a) vcfid collision: two VCF inputs with identical bytes share the same
/// SHA-256 prefix → build must refuse with "vcfid collision".
#[test]
#[serial(env)]
fn build_vcfid_collision_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("cfg"));
    let vcf_src = test_util::covid_vcf_path();

    // Copy the same VCF twice under different names.
    let vcf_a = tmp.path().join("a.vcf");
    let vcf_b = tmp.path().join("b.vcf");
    fs::copy(&vcf_src, &vcf_a).unwrap();
    fs::copy(&vcf_src, &vcf_b).unwrap();

    // Write a package.yaml that lists both (identical bytes → identical SHA-256 prefix).
    let pkg_path = tmp.path().join("package.yaml");
    let yaml = format!(
        "{MIN_META}\nfiles:\n  - category: \"VCF\"\n    reference: \"GRCh38\"\n    files:\n      - \"a.vcf\"\n      - \"b.vcf\"\nconfig:\n  mode: aggregated\n  blockRange: 10000000\n  minAlleleCount: 0\n"
    );
    fs::write(&pkg_path, yaml).unwrap();

    let args = BuildArgs {
        package: pkg_path,
        country_code: Some("EE".to_owned()),
        out: tmp.path().join("out"),
        force: false,
        no_headers: true,
        header_policy: None,
        strict: false,
        dry_run: false,
        build_epoch: None,
        jobs: 0,
        refresh_catalogs: false,
        format: OutputFormat::Text,
    };
    let err = expect_build_err(
        cmd_build::build_staging_dir(&args, None, None),
        "build should have failed",
    );
    assert!(
        err.message.contains("vcfid collision"),
        "expected 'vcfid collision' in error, got: {}",
        err.message
    );
}

/// (b) multiple VCF file groups: `build` converts only the first VCF group, so a
/// second one's variants would be silently dropped. `validate_package` (run before
/// conversion) must refuse the package outright — here with two groups that also happen
/// to declare different assemblies, but the count alone is the rejection reason.
#[test]
#[serial(env)]
fn build_rejects_multiple_vcf_groups() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("cfg"));
    let vcf_src = test_util::covid_vcf_path();

    let vcf_a = tmp.path().join("a.vcf");
    let vcf_b = tmp.path().join("b.vcf");
    fs::copy(&vcf_src, &vcf_a).unwrap();
    fs::copy(&vcf_src, &vcf_b).unwrap();

    // Two VCF groups declaring different assemblies.
    let pkg_path = tmp.path().join("package.yaml");
    let yaml = format!(
        "{MIN_META}\nfiles:\n  - category: \"VCF\"\n    reference: \"GRCh38\"\n    files:\n      - \"a.vcf\"\n  - category: \"VCF\"\n    reference: \"GRCh37\"\n    files:\n      - \"b.vcf\"\nconfig:\n  mode: aggregated\n  blockRange: 10000000\n  minAlleleCount: 0\n"
    );
    fs::write(&pkg_path, yaml).unwrap();

    let args = BuildArgs {
        package: pkg_path,
        country_code: Some("EE".to_owned()),
        out: tmp.path().join("out"),
        force: false,
        no_headers: true,
        header_policy: None,
        strict: false,
        dry_run: false,
        build_epoch: None,
        jobs: 0,
        refresh_catalogs: false,
        format: OutputFormat::Text,
    };
    let err = expect_build_err(
        cmd_build::build_staging_dir(&args, None, None),
        "build should have failed",
    );
    assert!(
        err.message.contains("more than one VCF file group"),
        "expected a multiple-VCF-group rejection, got: {}",
        err.message
    );
    // A failed build must not leak its partial (plaintext) staging directory: the
    // cleanup guard removes it on the error path, so `out` holds no staging subdir.
    let leftovers: Vec<PathBuf> = fs::read_dir(&args.out)
        .map(|d| {
            d.filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .collect()
        })
        .unwrap_or_default();
    assert!(
        leftovers.is_empty(),
        "failed build leaked a partial staging dir: {leftovers:?}"
    );
}

/// (c) declared sha256 mismatch: a `WithMeta` file entry with a wrong declared
/// sha256 → build must refuse mentioning "sha256 mismatch".
#[test]
#[serial(env)]
fn build_sha256_mismatch_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("cfg"));
    test_util::write_covid_vcf(tmp.path());

    // Package with a wrong declared sha256 for the VCF.
    let pkg_path = tmp.path().join("package.yaml");
    let sha_field = "0000000000000000000000000000000000000000000000000000000000000000";
    let yaml = format!(
        "{MIN_META}\nfiles:\n  - category: \"VCF\"\n    reference: \"GRCh38\"\n    files:\n      - path: \"COVID.monogneic.aggregate.AFs.GRCh38.vcf\"\n        sha256: \"{sha_field}\"\nconfig:\n  mode: aggregated\n  blockRange: 10000000\n  minAlleleCount: 0\n"
    );
    fs::write(&pkg_path, yaml).unwrap();

    let args = BuildArgs {
        package: pkg_path,
        country_code: Some("EE".to_owned()),
        out: tmp.path().join("out"),
        force: false,
        no_headers: true,
        header_policy: None,
        strict: false,
        dry_run: false,
        build_epoch: None,
        jobs: 0,
        refresh_catalogs: false,
        format: OutputFormat::Text,
    };
    let err = expect_build_err(
        cmd_build::build_staging_dir(&args, None, None),
        "build should have failed",
    );
    assert!(
        err.message.contains("sha256 mismatch"),
        "expected 'sha256 mismatch' in error, got: {}",
        err.message
    );
}

/// (c') declared size mismatch: a `WithMeta` file entry with a wrong declared
/// size → build must refuse mentioning "size mismatch" (the `declared != size`
/// guard, parallel to the sha256 one above).
#[test]
#[serial(env)]
fn build_size_mismatch_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("cfg"));
    test_util::write_covid_vcf(tmp.path());

    // Package declaring a wrong size (1 byte) for the much larger VCF.
    let pkg_path = tmp.path().join("package.yaml");
    let yaml = format!(
        "{MIN_META}\nfiles:\n  - category: \"VCF\"\n    reference: \"GRCh38\"\n    files:\n      - path: \"COVID.monogneic.aggregate.AFs.GRCh38.vcf\"\n        size: 1\nconfig:\n  mode: aggregated\n  blockRange: 10000000\n  minAlleleCount: 0\n"
    );
    fs::write(&pkg_path, yaml).unwrap();

    let args = BuildArgs {
        package: pkg_path,
        country_code: Some("EE".to_owned()),
        out: tmp.path().join("out"),
        force: false,
        no_headers: true,
        header_policy: None,
        strict: false,
        dry_run: false,
        build_epoch: None,
        jobs: 0,
        refresh_catalogs: false,
        format: OutputFormat::Text,
    };
    let err = expect_build_err(
        cmd_build::build_staging_dir(&args, None, None),
        "build should have failed",
    );
    assert!(
        err.message.contains("size mismatch"),
        "expected 'size mismatch' in error, got: {}",
        err.message
    );
}

/// (d) `--force` rebuilds over an existing staging directory without error.
///
/// The staging path is `<out>/<datasetId>/` where the ID embeds epoch milliseconds
/// computed inside `build_staging_dir`.  Because the ID is derived from the live
/// wall clock there is no way to pre-create the exact path it will choose, so the
/// "already exists" guard (which fires when `--force` is false and the computed
/// path already exists) cannot be triggered deterministically from outside the
/// function without production changes.  That path is tested at the unit level in
/// `cmd_build::prepare_staging_dir`.
///
/// What can be verified here end-to-end: a second build with `--force=true` must
/// succeed even when the output directory already contains a staging directory from the
/// first build.
#[test]
#[serial(env)]
fn build_force_flag_rebuilds_staging() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("cfg"));
    let out = tmp.path().join("out");

    // First build: populates <out>/<id1>/.
    cmd_build::build_staging_dir(&covid_build_args(&out), None, None)
        .expect("first build should succeed");

    // Second build with --force: must succeed even though <out> is non-empty.
    let args_force = BuildArgs {
        force: true,
        ..covid_build_args(&out)
    };
    cmd_build::build_staging_dir(&args_force, None, None)
        .expect("--force build should succeed over an existing output dir");
}

#[test]
#[serial(env)]
fn build_without_country_code_fails_clearly() {
    let tmp = tempfile::tempdir().unwrap();
    // This test's own, more thorough guard (empty dir + GDI_TOOL__COUNTRY_CODE removed)
    // is below; the file-wide per-test guard would be redundant here.
    let out = tmp.path().join("out");
    let package = test_util::write_covid_package(&tmp.path().join("covid-pkg"));

    // Hermetic country-code resolution: point `$GDI_CONFIG_DIR` at an empty dir so the
    // three real sources (config file, env, flag) all come up empty. Without this the
    // build resolves `country_code` from the developer's or CI box's own
    // `~/.config/gdi/tool.toml` and the "fails clearly" assertion silently passes on a
    // build that succeeded. `config_dir()` checks `GDI_CONFIG_DIR` first, so an empty dir
    // short-circuits `XDG_CONFIG_HOME`/`HOME`.
    let empty_cfg = tmp.path().join("empty-config");
    std::fs::create_dir_all(&empty_cfg).unwrap();
    let _cfg_guard = test_util::EnvGuard::set("GDI_CONFIG_DIR", &empty_cfg);
    let _cc_guard = test_util::EnvGuard::remove("GDI_TOOL__COUNTRY_CODE");

    let cli = Cli::try_parse_from([
        "gdi-dataset-tool",
        "build",
        package.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
    ])
    .unwrap();

    let err = gdi_dataset_tool::run(cli).expect_err("no country code -> error");
    // User-fixable error: exit 1, message names the three sources.
    assert_eq!(err.exit_code, 1);
    assert!(err.message.contains("country"), "message: {}", err.message);
    assert!(err.message.contains("--country-code") || err.message.contains("--cc"));
    assert!(err.message.contains("GDI_TOOL__COUNTRY_CODE"));
}

#[test]
#[serial(env)]
fn build_no_headers_omits_headers_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("cfg"));
    let out = tmp.path().join("out");
    let package = test_util::write_covid_package(&tmp.path().join("covid-pkg"));

    let cli = Cli::try_parse_from([
        "gdi-dataset-tool",
        "build",
        package.to_str().unwrap(),
        "--cc",
        "EE",
        "-o",
        out.to_str().unwrap(),
        "--no-headers",
    ])
    .unwrap();

    gdi_dataset_tool::run(cli).expect("build succeeds");
    let staging = single_subdir(&out);
    assert!(
        !staging.join("headers").exists(),
        "--no-headers must omit headers/"
    );
}

#[test]
#[serial(env)]
fn build_carries_hide_lower_counts_into_manifest() {
    // hideLowerCounts is the declared sensitive-tier count floor. It is never
    // applied to the aggregated data this node builds, but `build` must carry it
    // verbatim into manifest.json `config.hideLowerCounts`.
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("cfg"));
    let out = tmp.path().join("out");
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");

    // Copy the package + its VCF into a temp dir with `hideLowerCounts: 5` added
    // to the config, so the relative VCF path still resolves beside the package.
    let pkg_src = fs::read_to_string(fixtures.join("covid-package.yaml")).unwrap();
    let pkg_with_floor = format!("{pkg_src}  hideLowerCounts: 5\n");
    let pkg_dir = tmp.path().join("pkg");
    fs::create_dir_all(&pkg_dir).unwrap();
    fs::write(pkg_dir.join("covid-package.yaml"), &pkg_with_floor).unwrap();
    test_util::write_covid_vcf(&pkg_dir);

    let package = pkg_dir.join("covid-package.yaml");
    let cli = Cli::try_parse_from([
        "gdi-dataset-tool",
        "build",
        package.to_str().unwrap(),
        "--cc",
        "EE",
        "-o",
        out.to_str().unwrap(),
        "--no-headers",
    ])
    .unwrap();
    gdi_dataset_tool::run(cli).expect("build succeeds with hideLowerCounts");

    let staging = single_subdir(&out);
    let raw = fs::read_to_string(staging.join("manifest.json")).unwrap();
    // The integer is carried verbatim under the camelCase key.
    assert!(
        raw.contains("\"hideLowerCounts\": 5"),
        "manifest must carry hideLowerCounts verbatim, got:\n{raw}"
    );
    let manifest: Manifest = serde_json::from_str(&raw).expect("manifest parses");
    assert_eq!(manifest.config.hide_lower_counts, Some(5));
}

/// A header-only build args helper for the preflight guard tests below.
fn build_args_for(pkg: &Path, out: &Path) -> BuildArgs {
    BuildArgs {
        package: pkg.to_path_buf(),
        country_code: Some("EE".to_owned()),
        out: out.to_path_buf(),
        force: false,
        no_headers: true,
        header_policy: None,
        strict: false,
        dry_run: false,
        build_epoch: None,
        jobs: 0,
        refresh_catalogs: false,
        format: OutputFormat::Text,
    }
}

/// The header preflight rejects a VCF with no `AF` INFO field before conversion, with
/// the source path prefixed onto the error.
#[test]
#[serial(env)]
fn build_missing_af_field_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("cfg"));
    let vcf = "##fileformat=VCFv4.2\n\
        ##INFO=<ID=AC,Number=A,Type=Integer,Description=\"ac\">\n\
        ##contig=<ID=1>\n\
        #CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";
    fs::write(tmp.path().join("noaf.vcf"), vcf).unwrap();
    let pkg = tmp.path().join("package.yaml");
    write_package_yaml(&pkg, "noaf.vcf", "GRCh38");
    let out = tmp.path().join("out");
    let err = expect_build_err(
        cmd_build::build_staging_dir(&build_args_for(&pkg, &out), None, None),
        "no AF field",
    );
    assert!(
        err.message.contains("No AF INFO fields found") && err.message.contains("noaf.vcf"),
        "expected a path-prefixed no-AF error, got: {}",
        err.message
    );
}

/// The header preflight rejects a dataset that declares more than the 512-population
/// cap, from the header alone, before conversion.
#[test]
#[serial(env)]
fn build_exceeds_population_cap_is_rejected() {
    use std::fmt::Write as _;
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("cfg"));
    let mut vcf = String::from("##fileformat=VCFv4.2\n");
    // 513 distinct AF_<two-letter> populations — one over the 512 cap.
    let mut count = 0;
    'outer: for a in b'A'..=b'Z' {
        for b in b'A'..=b'Z' {
            writeln!(
                vcf,
                "##INFO=<ID=AF_{}{},Number=A,Type=Float,Description=\"af\">",
                a as char, b as char
            )
            .unwrap();
            count += 1;
            if count == 513 {
                break 'outer;
            }
        }
    }
    vcf.push_str("##contig=<ID=1>\n#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n");
    fs::write(tmp.path().join("big.vcf"), &vcf).unwrap();
    let pkg = tmp.path().join("package.yaml");
    write_package_yaml(&pkg, "big.vcf", "GRCh38");
    let out = tmp.path().join("out");
    let err = expect_build_err(
        cmd_build::build_staging_dir(&build_args_for(&pkg, &out), None, None),
        "over population cap",
    );
    assert!(
        err.message.contains("population cap"),
        "expected a population-cap error, got: {}",
        err.message
    );
}

/// A one-record VCF whose header declares a suffix-convention population field
/// (`EUR_AF`, the 1000 Genomes style, which the grammar rejects) and whose single record
/// carries a `*` spanning-deletion ALT alongside a real `G`.
const LOSSY_VCF: &str = "##fileformat=VCFv4.2\n\
##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
##INFO=<ID=EUR_AF,Number=A,Type=Float,Description=\"eur\">\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n\
1\t100\t.\tA\tG,*\t.\tPASS\tAF=0.25,0.1;EUR_AF=0.4,0.1\n";

#[test]
#[serial(env)]
fn build_records_conversion_provenance_on_the_vcf_entry() {
    // Both losses — a dropped population column and a dropped ALT allele — must land in
    // the manifest, not merely on stderr where the next reader will never see them.
    let dir = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path().join("cfg"));
    fs::write(dir.path().join("in.vcf"), LOSSY_VCF).unwrap();
    let pkg = dir.path().join("package.yaml");
    write_package_yaml(&pkg, "in.vcf", "GRCh38");

    let out = dir.path().join("build");
    let mut args = covid_build_args(&out);
    args.package = pkg;
    let built = cmd_build::build_staging_dir(&args, None, None).expect("build succeeds");

    let text = fs::read_to_string(built.staging.join("manifest.json")).unwrap();
    let manifest: Manifest = serde_json::from_str(&text).unwrap();
    let conv = manifest.files[0].files[0]
        .conversion
        .as_ref()
        .expect("the VCF entry carries conversion provenance");

    assert_eq!(conv.input.records, 1);
    assert_eq!(conv.discarded.ignored_info_fields, ["EUR_AF"]);
    assert_eq!(conv.discarded.alleles, 1, "the `*` ALT was discarded");
    assert_eq!(conv.output.rows, 1);
    assert_eq!(conv.output.populations, ["Total"]);
    assert_eq!(
        conv.input.populations_recognized,
        ["Total"],
        "EUR_AF never became a population"
    );
}

// `build --strict`

/// `MIN_META` plus every recommended field, so `validate_package` emits zero warnings.
/// Without this a `--strict` test would fail on the three-tier metadata advisories and
/// prove nothing about the conversion diagnostics it actually targets.
const FULL_META: &str = "\
metadata:
  prefix: \"GDI\"
  org: \"UTARTU\"
  catalog: \"gdi-aggregated\"
  title: \"Test dataset\"
  description: \"A test dataset for unit tests.\"
  accessRights: \"http://publications.europa.eu/resource/authority/access-right/PUBLIC\"
  applicableLegislation:
    - \"http://data.europa.eu/eli/reg/2025/327/oj\"
  license: \"https://creativecommons.org/licenses/by/4.0/\"
  creator:
    - name: \"Test\"
  healthCategory:
    - \"http://data.gdi.eu/core/p2/HealthCategoryHumanGenomic\"
  keywords:
    - \"allele-frequency\"
  numberOfUniqueIndividuals: 100";

/// Write a `package.yaml` whose metadata is warning-clean, listing `in.vcf`.
fn write_full_package_yaml(pkg_path: &Path, min_allele_count: u32) {
    let yaml = format!(
        "{FULL_META}\nfiles:\n  - category: \"VCF\"\n    reference: \"GRCh38\"\n    files:\n      - \"in.vcf\"\nconfig:\n  mode: aggregated\n  blockRange: 10000000\n  minAlleleCount: {min_allele_count}\n"
    );
    fs::write(pkg_path, yaml).unwrap();
}

/// Run `build` over `vcf_body` with a warning-clean package. Returns the result.
fn run_full_build(
    dir: &Path,
    vcf_body: &str,
    min_allele_count: u32,
    strict: bool,
) -> Result<cmd_build::BuildOutput, gdi_dataset_tool::ToolError> {
    fs::write(dir.join("in.vcf"), vcf_body).unwrap();
    let pkg = dir.join("package.yaml");
    write_full_package_yaml(&pkg, min_allele_count);
    let mut args = covid_build_args(&dir.join("build"));
    args.package = pkg;
    args.strict = strict;
    cmd_build::build_staging_dir(&args, None, None)
}

/// Three populations (`Total`, `EE`, `FI`); `FI` has AC=2 and falls below a floor of 5.
const THREE_POPULATION_VCF: &str = "##fileformat=VCFv4.2\n\
##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
##INFO=<ID=AC,Number=A,Type=Integer,Description=\"ac\">\n\
##INFO=<ID=AN,Number=1,Type=Integer,Description=\"an\">\n\
##INFO=<ID=AF_EE,Number=A,Type=Float,Description=\"ee af\">\n\
##INFO=<ID=AC_EE,Number=A,Type=Integer,Description=\"ee ac\">\n\
##INFO=<ID=AF_FI,Number=A,Type=Float,Description=\"fi af\">\n\
##INFO=<ID=AC_FI,Number=A,Type=Integer,Description=\"fi ac\">\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n\
1\t100\t.\tA\tG\t.\tPASS\tAF=0.25;AC=250;AN=1000;AF_EE=0.4;AC_EE=248;AF_FI=0.01;AC_FI=2\n";

/// A non-conforming INFO field and a population with AC/AN but no AF: two warnings.
const TWO_WARNING_VCF: &str = "##fileformat=VCFv4.2\n\
##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
##INFO=<ID=EUR_AF,Number=A,Type=Float,Description=\"eur\">\n\
##INFO=<ID=AC_NO,Number=A,Type=Integer,Description=\"no ac\">\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n\
1\t100\t.\tA\tG\t.\tPASS\tAF=0.25;EUR_AF=0.4;AC_NO=5\n";

#[test]
#[serial(env)]
fn the_full_meta_fixture_emits_no_metadata_warnings() {
    // Guards the two tests below: if the fixture itself warns, `--strict` failures and
    // successes would be measuring the wrong thing.
    let dir = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path().join("cfg"));
    let pkg = dir.path().join("package.yaml");
    write_full_package_yaml(&pkg, 0);
    let package: gdi_node_standalone_core::model::PackageYaml =
        serde_saphyr::from_str(&fs::read_to_string(&pkg).unwrap()).unwrap();
    let report = gdi_node_standalone_core::validate_pkg::validate_package(&package, None).unwrap();
    assert!(
        report.warnings.is_empty(),
        "fixture is not warning-clean: {:?}",
        report.warnings
    );
}

#[test]
#[serial(env)]
fn strict_build_fails_on_a_non_conforming_info_field() {
    let dir = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path().join("cfg"));
    let err = expect_build_err(
        run_full_build(dir.path(), LOSSY_VCF, 0, true),
        "EUR_AF is a warning",
    );
    assert!(
        format!("{err}").contains("1 warning(s)"),
        "expected a strict failure naming 1 warning, got: {err}"
    );
}

/// `build --strict` exits **5**, not 1, when it runs as a real process.
///
/// `EXIT_STRICT` exists so CI can tell "your data has problems" from "the tool broke",
/// which is the whole point of a code other than 1. Asserting `err.exit_code` from the
/// library, or only `status.success()` from a spawned binary, never crosses `main`'s
/// shim:
///
/// ```ignore
/// ExitCode::from(u8::try_from(err.exit_code).unwrap_or(1))
/// ```
///
/// so a shim that collapsed every classified failure to a generic 1 would go unnoticed,
/// and a pipeline branching on 5 would start treating a data warning as a tool crash.
///
/// The assertion is on 5, not on "non-zero": 1 is simultaneously `EXIT_USER`, the
/// `unwrap_or` fallback, and clap's own failure mode, so an assertion that accepted 1 would
/// pass no matter how badly the shim were broken.
#[test]
#[serial(env)]
fn strict_build_exits_with_the_strict_code_not_the_generic_one() {
    let dir = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path().join("cfg"));
    fs::write(dir.path().join("in.vcf"), LOSSY_VCF).unwrap();
    let pkg = dir.path().join("package.yaml");
    write_full_package_yaml(&pkg, 0);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_gdi-dataset-tool"))
        .args([
            "build",
            pkg.to_str().unwrap(),
            "--country-code",
            "EE",
            "--output",
            dir.path().join("build").to_str().unwrap(),
            "--no-headers",
            "--strict",
        ])
        .output()
        .expect("spawn gdi-dataset-tool");

    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(
        output.status.code(),
        Some(gdi_dataset_tool::EXIT_STRICT),
        "a --strict warning must reach the process exit code as {}, not collapse to a \
         generic failure; stderr:\n{stderr}",
        gdi_dataset_tool::EXIT_STRICT
    );
    assert!(
        stderr.contains("--strict"),
        "the single-line error must name the cause; stderr:\n{stderr}"
    );
}

#[test]
#[serial(env)]
fn strict_build_succeeds_when_only_the_floor_fired() {
    // The small-count floor is a privacy control, not a data problem. A floor-enabled
    // build emits only notes, so `--strict` must not fail: otherwise the floor would be
    // unusable in a strict pipeline.
    let dir = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path().join("cfg"));
    run_full_build(dir.path(), THREE_POPULATION_VCF, 5, true)
        .unwrap_or_else(|e| panic!("notes must never fail --strict, got: {e}"));
}

#[test]
#[serial(env)]
fn strict_counts_every_warning_rather_than_bailing_on_the_first() {
    // If the build short-circuited on the first warning the count would read 1, and the
    // provider would fix one problem, re-run, and meet the next.
    let dir = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path().join("cfg"));
    let err = expect_build_err(
        run_full_build(dir.path(), TWO_WARNING_VCF, 0, true),
        "two warnings",
    );
    assert!(
        format!("{err}").contains("2 warning(s)"),
        "expected a strict failure naming 2 warnings, got: {err}"
    );
}

#[test]
#[serial(env)]
fn a_warning_does_not_fail_a_non_strict_build() {
    let dir = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path().join("cfg"));
    run_full_build(dir.path(), LOSSY_VCF, 0, false)
        .unwrap_or_else(|e| panic!("warnings are advisory without --strict, got: {e}"));
}

/// Every record sits on the `hs37d5` decoy contig, so nothing survives the projection.
const ALL_DECOY_VCF: &str = "##fileformat=VCFv4.2\n\
##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n\
hs37d5\t50\t.\tA\tG\t.\tPASS\tAF=0.5\n";

#[test]
#[serial(env)]
fn a_build_that_emits_no_rows_fails_even_without_strict() {
    // An empty dataset is never intentional, and it is the end state of a mis-named INFO
    // header or a wholly non-primary-contig VCF. Nothing to serve => hard error.
    let dir = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path().join("cfg"));
    let err = expect_build_err(
        run_full_build(dir.path(), ALL_DECOY_VCF, 0, false),
        "zero rows",
    );
    assert!(
        format!("{err}").contains("produced no rows"),
        "expected an empty-dataset error, got: {err}"
    );
}

#[test]
#[serial(env)]
fn manifest_metadata_records_the_dataset_population_set() {
    // The node strips `files` at ingest, so the per-VCF provenance never reaches serve
    // time. The dataset-wide population union must therefore live in `metadata`, which
    // survives ingest — otherwise the beacon cannot tell a user which populations exist.
    let dir = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path().join("cfg"));
    let built = run_full_build(dir.path(), THREE_POPULATION_VCF, 0, false).expect("build");
    let text = fs::read_to_string(built.staging.join("manifest.json")).unwrap();
    let manifest: Manifest = serde_json::from_str(&text).unwrap();
    assert_eq!(
        manifest.metadata.populations.as_deref(),
        Some(["EE".to_owned(), "FI".to_owned(), "Total".to_owned()].as_slice()),
        "sorted union across the VCF group"
    );
}

#[test]
#[serial(env)]
fn manifest_population_set_reflects_the_floor_not_the_header() {
    // Under a floor only `Total` survives, and that is what the node will serve.
    let dir = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path().join("cfg"));
    let built = run_full_build(dir.path(), THREE_POPULATION_VCF, 5, false).expect("build");
    let text = fs::read_to_string(built.staging.join("manifest.json")).unwrap();
    let manifest: Manifest = serde_json::from_str(&text).unwrap();
    assert_eq!(
        manifest.metadata.populations.as_deref(),
        Some(["Total".to_owned()].as_slice())
    );
}

#[test]
#[serial(env)]
fn strict_failure_has_its_own_exit_code() {
    // Exit 1 is "user error" — a malformed package.yaml, a missing file, a bad checksum.
    // CI must be able to distinguish "your data has problems" from "the tool broke".
    let dir = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path().join("cfg"));
    let err = expect_build_err(
        run_full_build(dir.path(), LOSSY_VCF, 0, true),
        "strict failure",
    );
    assert_eq!(
        err.exit_code,
        gdi_dataset_tool::EXIT_STRICT,
        "a --strict failure must not share exit 1 with a malformed package"
    );
    assert_ne!(err.exit_code, gdi_dataset_tool::EXIT_USER);
}

#[test]
#[serial(env)]
fn build_output_carries_diagnostics_and_the_population_set_for_ci() {
    // The diagnostics are printed to stderr, which CI cannot parse. `build --format json`
    // must carry them, plus what the dataset actually serves.
    let dir = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path().join("cfg"));
    let built = run_full_build(dir.path(), LOSSY_VCF, 0, false).expect("build");
    let warnings: Vec<&str> = built
        .diagnostics
        .iter()
        .filter(|(_, d)| d.severity == gdi_node_standalone_core::convert::Severity::Warning)
        .map(|(_, d)| d.message.as_str())
        .collect();
    assert_eq!(warnings.len(), 1, "the EUR_AF field is one warning");
    assert!(warnings[0].contains("ignored non-conforming INFO fields"));
    assert_eq!(
        built.diagnostics[0].0, "in.vcf",
        "each diagnostic names its source"
    );
    assert_eq!(built.populations, ["Total"]);
}

#[test]
#[serial(env)]
fn dry_run_validates_everything_but_writes_nothing() {
    // A provider with 24 chromosome VCFs has no other way to preflight the whole group:
    // `preview` is single-VCF, and `validate`/`lint` need an already-built staging directory.
    let dir = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path().join("cfg"));
    fs::write(dir.path().join("in.vcf"), THREE_POPULATION_VCF).unwrap();
    let pkg = dir.path().join("package.yaml");
    write_full_package_yaml(&pkg, 0);
    let out = dir.path().join("build");
    let mut args = covid_build_args(&out);
    args.package = pkg;
    args.dry_run = true;

    let built = cmd_build::build_staging_dir(&args, None, None).expect("dry run succeeds");
    assert!(built.dry_run);
    assert_eq!(
        built.populations,
        ["EE", "FI", "Total"],
        "it really converted"
    );
    assert!(
        !built.staging.exists(),
        "a dry run must leave no staging dir behind: {}",
        built.staging.display()
    );
}

/// A fixed `build_epoch`, in milliseconds, shared by the two tests that need one.
///
/// Both derive their behaviour from it — one to make two builds collide on the same
/// dataset id, the other to make two builds byte-identical — so the literal is written
/// once rather than twice, where the two copies could drift apart.
const PINNED_BUILD_EPOCH_MS: u64 = 1_700_000_000_000;

/// A dry run over an already built dataset id must not touch what is there.
///
/// The test above uses a fresh `--out`, so it can only show that a dry run creates
/// nothing; it cannot see the destructive half. `clear_staging_target` must stay behind
/// the `dry_run` check: a `build --dry-run --force` that cleared the target would remove
/// the existing `<out>/<datasetId>/` and then, correctly per `--dry-run`, write nothing to
/// replace it. Operators are routed straight at that combination, because without
/// `--force` the same dry run fails with "already exists (use --force to overwrite)". The
/// build epoch is pinned so both runs mint the same id, which is what makes the second run
/// collide with the first.
#[test]
#[serial(env)]
fn a_dry_run_never_clears_an_existing_staging_dir() {
    let dir = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path().join("cfg"));
    fs::write(dir.path().join("in.vcf"), THREE_POPULATION_VCF).unwrap();
    let pkg = dir.path().join("package.yaml");
    write_full_package_yaml(&pkg, 0);
    let out = dir.path().join("build");
    let mut args = covid_build_args(&out);
    args.package = pkg;
    args.build_epoch = Some(PINNED_BUILD_EPOCH_MS);

    let real = cmd_build::build_staging_dir(&args, None, None).expect("the real build");
    let manifest = real.staging.join("manifest.json");
    let before = fs::read(&manifest).unwrap();

    // 1. A dry run without --force must not fail over the collision: telling a preflight to
    //    re-run with the flag that deletes the dataset is the trap this closes.
    args.dry_run = true;
    let dry = cmd_build::build_staging_dir(&args, None, None)
        .expect("a dry run over an existing id must not demand --force");
    assert!(dry.dry_run);
    assert_eq!(
        fs::read(&manifest).unwrap(),
        before,
        "the existing build must be byte-for-byte untouched"
    );

    // 2. ...and with --force, which must not delete it outright.
    //
    // A sentinel, because the two assertions below cannot tell "untouched" from "deleted
    // and rebuilt". `build_epoch` is pinned here precisely so the second run derives the
    // same id and collides — and that also makes a rebuild byte-identical, so
    // `fs::read(&manifest) == before` holds either way and `is_dir()` is true either way.
    // A clear-then-rebuild would have passed this test unchanged. The sentinel is not
    // reproduced by a rebuild, so its survival is the discrimination.
    let sentinel = real.staging.join(".not-rebuilt");
    fs::write(&sentinel, b"present before the --dry-run --force").unwrap();

    args.force = true;
    let forced = cmd_build::build_staging_dir(&args, None, None).expect("dry run with --force");
    // The return value has to be inspected: without it, a build that silently ignored
    // `dry_run` under `--force` would satisfy every assertion below.
    assert!(
        forced.dry_run,
        "--dry-run --force must still report a DRY RUN, not a completed build"
    );
    assert!(
        real.staging.is_dir(),
        "--dry-run --force must not remove {}",
        real.staging.display()
    );
    assert!(
        sentinel.is_file(),
        "--dry-run --force cleared and rebuilt the staging dir: the sentinel is gone. The \
         manifest comparison below cannot see this, because the pinned build epoch makes a \
         rebuild byte-identical."
    );
    assert_eq!(
        fs::read(&manifest).unwrap(),
        before,
        "--dry-run --force must not rewrite the existing build either"
    );
}

#[test]
#[serial(env)]
fn dry_run_still_fails_a_bad_build() {
    // It must be a real preflight, not a no-op that always succeeds.
    let dir = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path().join("cfg"));
    fs::write(dir.path().join("in.vcf"), ALL_DECOY_VCF).unwrap();
    let pkg = dir.path().join("package.yaml");
    write_full_package_yaml(&pkg, 0);
    let out = dir.path().join("build");
    let mut args = covid_build_args(&out);
    args.package = pkg;
    args.dry_run = true;
    let err = expect_build_err(cmd_build::build_staging_dir(&args, None, None), "zero rows");
    assert!(format!("{err}").contains("produced no rows"));
}

#[test]
#[serial(env)]
fn a_pinned_build_epoch_makes_the_manifest_byte_reproducible() {
    // Parquet bytes are deterministic and the tar layer normalizes mtime/uid/gid, so
    // `datasetId` — derived from the wall clock — is the only thing between two identical
    // inputs and an identical manifest. The .tar.c4gh can never match: crypt4gh draws a
    // fresh session key and per-segment nonces from the OS CSPRNG.
    let dir = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path().join("cfg"));
    fs::write(dir.path().join("in.vcf"), THREE_POPULATION_VCF).unwrap();
    let pkg = dir.path().join("package.yaml");
    write_full_package_yaml(&pkg, 0);

    let build_once = |out: &Path| -> String {
        let mut args = covid_build_args(out);
        args.package = pkg.clone();
        args.build_epoch = Some(PINNED_BUILD_EPOCH_MS);
        let built = cmd_build::build_staging_dir(&args, None, None).expect("build");
        fs::read_to_string(built.staging.join("manifest.json")).unwrap()
    };

    let a = build_once(&dir.path().join("out-a"));
    let b = build_once(&dir.path().join("out-b"));
    assert_eq!(a, b, "same inputs + same epoch => byte-identical manifest");
    assert!(
        a.contains("GDI-EE-UTARTU-"),
        "the id still has the expected shape"
    );
}

#[test]
#[serial(env)]
fn an_unpinned_build_epoch_still_uses_the_wall_clock() {
    let dir = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path().join("cfg"));
    let built = run_full_build(dir.path(), THREE_POPULATION_VCF, 0, false).expect("build");
    assert!(
        built.dataset_id.starts_with("GDI-EE-UTARTU-2"),
        "{}",
        built.dataset_id
    );
}

/// Every staged member except `manifest.json`, keyed the way `payload.members` keys them:
/// a `/`-separated path relative to the staging directory.
fn staged_members(staging: &Path) -> std::collections::BTreeMap<String, PathBuf> {
    fn walk(dir: &Path, prefix: &str, out: &mut std::collections::BTreeMap<String, PathBuf>) {
        for entry in fs::read_dir(dir).unwrap().filter_map(Result::ok) {
            let name = entry.file_name().to_string_lossy().into_owned();
            let key = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            let path = entry.path();
            if path.is_dir() {
                walk(&path, &key, out);
            } else if key != "manifest.json" {
                out.insert(key, path);
            }
        }
    }
    let mut out = std::collections::BTreeMap::new();
    walk(staging, "", &mut out);
    out
}

/// The manifest a build writes must record its payload digests.
///
/// `cmd_build.rs` names this test as the guard on
/// `manifest.payload = Some(payload_section(&staging))` in `run`, which fills in the
/// `payload: None` that `build_manifest` returns. Dropping that assignment would be silent
/// in both directions: nothing else populates `Manifest.payload`, and `pack`'s
/// `verify_staged_payload` returns `Ok(())` on `payload: None`, so the pre-sign
/// verification of the packaged bytes would degrade to a no-op rather than an error.
///
/// Asserts the digests against the bytes actually on disk, not merely that the section is
/// present: a `payload` populated with the wrong hashes would satisfy presence while
/// making `verify_staged_payload` reject every honest package.
#[test]
#[serial(env)]
fn a_built_manifest_records_its_payload_digest() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("cfg"));
    let out = tmp.path().join("out");
    let package = test_util::write_covid_package(&tmp.path().join("covid-pkg"));

    let cli = Cli::try_parse_from([
        "gdi-dataset-tool",
        "build",
        package.to_str().unwrap(),
        "--cc",
        "EE",
        "-o",
        out.to_str().unwrap(),
    ])
    .unwrap();
    gdi_dataset_tool::run(cli).expect("build succeeds");

    let staging = single_subdir(&out);
    let manifest: Manifest =
        serde_json::from_slice(&fs::read(staging.join("manifest.json")).unwrap()).unwrap();

    let payload = manifest
        .payload
        .expect("a built manifest must carry a `payload` section");
    assert!(
        payload.algorithm_supported(),
        "build must declare an algorithm this workspace can verify, got {:?}",
        payload.algorithm
    );

    let members = staged_members(&staging);
    assert!(
        !members.is_empty(),
        "the staging dir has no members besides manifest.json — this test would pass \
         vacuously"
    );
    assert_eq!(
        payload.members.keys().collect::<Vec<_>>(),
        members.keys().collect::<Vec<_>>(),
        "payload.members must name EVERY staged member except manifest.json, and nothing else"
    );

    for (name, path) in &members {
        let entry = &payload.members[name];
        let (sha, size) =
            gdi_node_standalone_core::util::sha256_hex_reader(fs::File::open(path).unwrap())
                .unwrap();
        assert_eq!(
            entry.sha256, sha,
            "payload digest for {name} does not match the bytes on disk"
        );
        assert_eq!(entry.size, size, "payload size for {name} is wrong");
    }
}

/// A `tool.toml` whose sole profile records `with-identifiers` as its header policy.
fn tool_config_with_identifiers(dir: &Path) -> PathBuf {
    let config_path = dir.join("tool.toml");
    fs::write(
        &config_path,
        "country_code = \"EE\"\n\n[profiles.default]\nheader_policy = \"with-identifiers\"\n",
    )
    .unwrap();
    config_path
}

fn built_header_policy(args: &BuildArgs, config_path: &Path) -> Option<HeaderPolicy> {
    let built = cmd_build::build_staging_dir(args, None, Some(config_path)).unwrap();
    let raw = fs::read_to_string(built.staging.join("manifest.json")).unwrap();
    let manifest: Manifest = serde_json::from_str(&raw).unwrap();
    manifest.internal.header_policy
}

/// A profile's `header_policy` is what `build` applies when no flag is given — the
/// deployment-level default `wizard setup` records.
#[test]
#[serial(env)]
fn build_applies_the_profile_header_policy_when_no_flag_is_given() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("cfg"));
    let config_path = tool_config_with_identifiers(tmp.path());
    let mut args = covid_build_args(&tmp.path().join("build"));
    args.no_headers = false;
    args.header_policy = None;
    assert_eq!(
        built_header_policy(&args, &config_path),
        Some(HeaderPolicy::WithIdentifiers)
    );
}

/// The flag is per-invocation and always wins over the profile.
#[test]
#[serial(env)]
fn build_header_policy_flag_overrides_the_profile() {
    let tmp = tempfile::tempdir().unwrap();
    let _config_dir = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path().join("cfg"));
    let config_path = tool_config_with_identifiers(tmp.path());
    let mut args = covid_build_args(&tmp.path().join("build"));
    args.no_headers = false;
    args.header_policy = Some(HeaderPolicyArg::Minimal);
    assert_eq!(
        built_header_policy(&args, &config_path),
        Some(HeaderPolicy::Minimal)
    );
}
