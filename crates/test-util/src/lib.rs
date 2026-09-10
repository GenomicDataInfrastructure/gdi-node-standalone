//! Dev-only test helpers shared across the workspace's test suites.
//!
//! This crate is the audited home for the `unsafe` `std::env` mutators Rust 2024 requires:
//! `set_var`/`remove_var` are `unsafe` because mutating the environment races with readers
//! that do not go through `std::env`. The workspace sets `unsafe_code = "deny"`, this crate
//! inherits that like any other member, and its two blocks carry
//! `#[expect(unsafe_code, ...)]`. Production code stays unsafe-free.
//!
//! These helpers are not the only env mutators in the workspace. `figment::Jail`, a
//! dev-dependency of `core`, calls `set_var` from its own call sites, and every env
//! mutation in `core`'s config suite is a `jail.set_env`. That `unsafe` lives inside the
//! dependency where `unsafe_code` cannot see it, so those sites are held to the same serial
//! key by the `global_state_mutators_carry_their_serial_key` guard.
#![expect(
    clippy::disallowed_methods,
    reason = "test fixtures write plain files: durability and atomicity are not under test"
)]

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Expected values of the shared COVID test fixture
/// (`COVID.monogneic.aggregate.AFs.GRCh38.vcf`), which holds one variant
/// (`chr3:45823240 T>C`). Test suites across the workspace assert against these
/// constants rather than repeating the numbers.
///
/// The count fields are `u64` here; the core `AlleleRow` parses counts as `i32`,
/// so assertions against that type cast (`covid::TOTAL_AC as i32`).
pub mod covid {
    /// `Total` population allele **count** (`alleleCount` / `ac`).
    pub const TOTAL_AC: u64 = 618;
    /// `Total` population allele **number** (`alleleNumber` / `an`).
    pub const TOTAL_AN: u64 = 8000;
    /// `FI_M` population allele **count**, below a 200 floor and above 100.
    pub const FI_M_AC: u64 = 119;
    /// `FI_M` population allele **frequency** (`alleleFrequency`); chosen so its
    /// shortest round-tripping decimal is `0.085` (an `f32 -> f64` widening probe).
    pub const FI_M_AF: f64 = 0.085;
}

/// The env var that turns a real-endpoint smoke's skip into a hard failure.
///
/// Set it in any runner that has just booted the backends the smokes need.
/// `scripts/e2e/run-full.sh` boots Garage and `OpenBao`, then sets this. It is the only
/// consumer, and it re-spells the name as a shell literal; the
/// `the_required_env_flag_is_exported_by_the_runner_that_promises_it` guard keeps the two
/// in step.
pub const REQUIRED_ENV_FLAG: &str = "GDI_TEST_REQUIRED";

/// Read the endpoint env var that gates an `#[ignore]`d real-endpoint smoke.
///
/// These smokes carry two gates: `#[ignore]`, so a plain `cargo test` skips them, and an
/// early return when the endpoint var is unset, so `--ignored` without a backend does not
/// fail. The second gate makes a false green easy, so it is conditional. Without
/// [`REQUIRED_ENV_FLAG`] this returns `None` and the caller returns early, which is the
/// normal developer run. With the flag set a runner has asserted a backend is there, so a
/// missing or empty var panics.
///
/// # Panics
/// If `var` is unset or empty while [`REQUIRED_ENV_FLAG`] is set to a non-empty
/// value.
#[must_use]
pub fn endpoint_env(var: &str) -> Option<String> {
    let value = std::env::var(var).ok().filter(|v| !v.is_empty());
    if value.is_none() {
        assert!(
            std::env::var(REQUIRED_ENV_FLAG)
                .ok()
                .is_none_or(|v| v.is_empty()),
            "{REQUIRED_ENV_FLAG} is set, so this real-endpoint smoke must RUN, but \
             {var} is unset or empty. The runner that set {REQUIRED_ENV_FLAG} is \
             responsible for exporting it; skipping here would be a false green."
        );
        eprintln!("skipping: {var} not set");
    }
    value
}

/// Set a process environment variable (test-only).
///
/// # Concurrency
/// Call this only from tests that serialize environment access (`#[serial(env)]`). That is
/// necessary but not sufficient; read the safety note on the block below before adding a
/// call site.
pub fn set_env<K: AsRef<OsStr>, V: AsRef<OsStr>>(key: K, value: V) {
    // SAFETY: a knowingly-accepted unsoundness, not a discharged obligation.
    //
    // `std::env::set_var` requires that no other thread read the environment through
    // functions or global variables other than the ones in `std::env`. Reads through
    // `std::env` are already synchronized against us by std's own lock. The hazard is
    // readers outside it (libc `getenv`, DNS resolution via `ToSocketAddrs`, TZ handling),
    // which no lint or attribute can enumerate, and std makes no stable guarantee about
    // which functions do it. Its own conclusion is that the only sound option in a
    // multi-threaded program is to not call this at all.
    //
    // `#[serial(env)]` orders env mutators against each other and nothing more. It says
    // nothing about a libc read on a tokio worker, or on the detached socket threads
    // `stalling_endpoint` and `serve_once` leave running; the mutual exclusion it does buy
    // is enforced by `global_state_mutators_carry_their_serial_key`. What bounds the risk
    // is process isolation: `scripts/ci-local.sh` gates on `cargo nextest`, one process per
    // test, and its no-nextest fallback forces a single test thread. Prefer passing env to a
    // child process (`Command::env`, as `crates/gdi-dataset-tool/tests/it/keys_e2e.rs` does)
    // over mutating our own: that is sound outright and needs no serial key.
    #[expect(
        unsafe_code,
        reason = "Rust 2024 requires unsafe for std::env::set_var; this crate is its audited home"
    )]
    unsafe {
        std::env::set_var(key, value);
    };
}

/// Set an env var for the rest of the current scope, restoring the previous value (or its
/// absence) on `Drop`.
///
/// The hand-rolled alternative (save the old value, set, assert, put it back with a
/// trailing statement) restores only when the assertions pass. A failing assertion unwinds
/// past the restore and leaves the variable pointing at a deleted tempdir for every later
/// test in the process, turning one genuine failure into a cascade of unrelated ones.
/// `Drop` runs during unwind; a trailing statement does not.
///
/// Callers must still be `#[serial(env)]`: this fixes the restore, not the mutual
/// exclusion (`global_state_mutators_carry_their_serial_key` enforces that half).
#[must_use = "the guard restores on Drop; dropping it immediately restores immediately"]
pub struct EnvGuard {
    key: OsString,
    prev: Option<OsString>,
}

impl EnvGuard {
    /// Set `key` to `value`, remembering what was there before.
    pub fn set<K: AsRef<OsStr>, V: AsRef<OsStr>>(key: K, value: V) -> Self {
        let key = key.as_ref().to_owned();
        let prev = std::env::var_os(&key);
        set_env(&key, value);
        Self { key, prev }
    }

    /// Remove `key`, remembering what was there before.
    pub fn remove<K: AsRef<OsStr>>(key: K) -> Self {
        let key = key.as_ref().to_owned();
        let prev = std::env::var_os(&key);
        remove_env(&key);
        Self { key, prev }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match self.prev.take() {
            Some(v) => set_env(&self.key, v),
            None => remove_env(&self.key),
        }
    }
}

/// Remove a process environment variable (test-only). Same contract as [`set_env`],
/// including the part where `#[serial(env)]` is necessary but not sufficient.
pub fn remove_env<K: AsRef<OsStr>>(key: K) {
    // SAFETY: `std::env::remove_var` carries the same contract and the same
    // knowingly-accepted unsoundness as `set_env`. The reasoning is written down there.
    #[expect(
        unsafe_code,
        reason = "Rust 2024 requires unsafe for std::env::remove_var; this crate is its audited home"
    )]
    unsafe {
        std::env::remove_var(key);
    };
}

/// Run `f` with a thread-local `tracing` subscriber that renders every event as JSON into
/// an in-memory buffer, and return what it captured.
///
/// This is the workspace's single copy of the capture-subscriber wiring, so every suite's
/// assertions agree about what a log line looks like.
///
/// Fields are not flattened: an event's fields land under a `fields` object, matching
/// `tracing-subscriber`'s default JSON shape. Use [`capture_json_logs_flat`] for the
/// flattened shape.
///
/// # Concurrency
/// `with_default` is thread-local, so the capture only sees events emitted on the calling
/// thread. If a callsite's global interest has been cached as "uninterested" by a sibling
/// test running without any subscriber, events can be dropped before dispatch. Install a
/// permissive global default for the binary if you hit that (see the `it` harness's
/// `ensure_capture_safe_tracing`).
pub fn capture_json_logs<R>(f: impl FnOnce() -> R) -> (R, String) {
    capture_with_layer(false, f)
}

/// As [`capture_json_logs`], but with `flatten_event(true)`: an event's fields are
/// emitted at the top level of the JSON object instead of nested under `fields`.
pub fn capture_json_logs_flat<R>(f: impl FnOnce() -> R) -> (R, String) {
    capture_with_layer(true, f)
}

fn capture_with_layer<R>(flatten: bool, f: impl FnOnce() -> R) -> (R, String) {
    use tracing_subscriber::layer::SubscriberExt as _;

    let writer = CaptureWriter::new();
    let make = {
        let w = writer.clone();
        move || w.clone()
    };
    let layer = tracing_subscriber::fmt::layer()
        .json()
        .flatten_event(flatten)
        .with_writer(make);
    let subscriber = tracing_subscriber::registry().with(layer);
    let out = tracing::subscriber::with_default(subscriber, f);
    (out, writer.contents())
}

/// A loopback TCP endpoint that accepts the connection and then never answers.
///
/// This is the failure a *connect* timeout cannot catch: the handshake succeeded, so the
/// client is simply waiting for a response that never comes. Only a per-request timeout
/// bounds it, which is what the callers of this helper exist to prove.
///
/// `std` rather than `tokio`: the server side never needs to be async for the client under
/// test to be, and staying dependency-free keeps this crate usable from the two workspace
/// members that have no tokio dependency.
///
/// A detached thread holds the listener and its accepted sockets for the lifetime of the
/// process, so the sockets stay established; a test binary is short-lived.
///
/// # Panics
/// If the loopback bind fails.
#[must_use]
pub fn stalling_endpoint() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind stalling endpoint");
    let addr = listener.local_addr().expect("local_addr");
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for sock in listener.incoming() {
            match sock {
                // Keep the socket established and never write a response.
                Ok(s) => held.push(s),
                Err(_) => break,
            }
        }
    });
    format!("http://{addr}")
}

/// A loopback HTTP endpoint that answers one request with `status`, `content_type` and
/// `body`, then closes. Returns the base URL.
///
/// One-shot so that a test which accidentally makes a second request gets a connection
/// error rather than a silently-repeated canned answer.
///
/// # Panics
/// If the loopback bind fails.
#[must_use]
pub fn serve_once(body: &str, status: u16, content_type: &str) -> String {
    use std::io::{Read as _, Write as _};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind one-shot server");
    let addr = listener.local_addr().expect("local_addr");
    let body = body.to_owned();
    let content_type = content_type.to_owned();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            // Drain the request line/headers so the client's write completes before the
            // response goes out; the content is irrelevant to every caller.
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf);
            // Empty reason phrase rather than a fixed `OK`, which would render a 404 as
            // the self-contradicting `HTTP/1.1 404 OK`. RFC 9112 allows an empty reason
            // phrase and clients ignore it.
            let resp = format!(
                "HTTP/1.1 {status} \r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
        }
    });
    format!("http://{addr}")
}

/// A cloneable in-memory [`Write`] sink for capturing a `tracing` subscriber's output in
/// tests. Clone it into a subscriber's `with_writer` / `make_writer` closure, run the
/// emit under `with_default`, then read the captured output back with [`Self::contents`]
/// or [`Self::bytes`]. Only the sink is shared; the subscriber and layer configuration
/// (JSON/ECS/filters) stays at each call site.
#[derive(Clone, Default)]
pub struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl CaptureWriter {
    /// A fresh, empty capture buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A copy of the captured raw bytes.
    ///
    /// # Panics
    /// If the buffer mutex was poisoned by a panic inside a concurrent write.
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        self.0
            .lock()
            .expect("capture buffer lock not poisoned")
            .clone()
    }

    /// The captured output decoded as UTF-8.
    ///
    /// # Panics
    /// If the capture is not valid UTF-8, or if the buffer mutex was poisoned (both
    /// test-only failure modes).
    #[must_use]
    pub fn contents(&self) -> String {
        String::from_utf8(self.bytes()).expect("captured tracing output is valid UTF-8")
    }
}

impl Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("capture buffer lock not poisoned")
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Raw bytes of the canonical COVID VCF fixture, which every crate shares. Pair with
/// [`covid`] for its expected numeric contents.
#[must_use]
pub fn covid_vcf_bytes() -> &'static [u8] {
    include_bytes!("../tests/fixtures/COVID.monogneic.aggregate.AFs.GRCh38.vcf")
}

/// Raw bytes of the chr7 COVID VCF variant.
#[must_use]
pub fn covid_chr7_vcf_bytes() -> &'static [u8] {
    include_bytes!("../tests/fixtures/COVID.monogneic.aggregate.AFs.chr7.GRCh38.vcf")
}

/// The contig names of one published human reference set, as a VCF called against it
/// carries them in `#CHROM` / `##contig`: one name per line, in the set's own order.
#[derive(Debug, Clone, Copy)]
pub struct ReferenceContigSet {
    /// The assembly the set builds (`GRCh37` | `GRCh38`), as `core::chrom` spells it.
    pub assembly: &'static str,
    /// The reference file the names come from, for a failure message.
    pub source: &'static str,
    /// Newline-separated contig names.
    pub names: &'static str,
}

/// Every published human reference set's contig list, so a contig classifier can be
/// checked against what real VCFs carry rather than a hand-picked sample: the 1000 Genomes
/// / GATK `GRCh38` "full analysis set plus decoy and HLA" (3 366), `hs37d5` (86), UCSC `hg38`
/// (455) and `hg19` (93), and Ensembl's `GRCh38` *toplevel* (706: primary, alt haplotypes
/// and patches) and `GRCh37` primary assembly (84). Names are the `.fai` / `chrom.sizes` /
/// REST `top_level_region` column, unedited.
#[must_use]
pub fn reference_contig_sets() -> [ReferenceContigSet; 6] {
    [
        ReferenceContigSet {
            assembly: "GRCh38",
            source: "GRCh38_full_analysis_set_plus_decoy_hla.fa.fai",
            names: include_str!(
                "../tests/fixtures/reference-contigs/GRCh38_full_analysis_set_plus_decoy_hla.contigs"
            ),
        },
        ReferenceContigSet {
            assembly: "GRCh37",
            source: "hs37d5.fa.gz.fai",
            names: include_str!("../tests/fixtures/reference-contigs/hs37d5.contigs"),
        },
        ReferenceContigSet {
            assembly: "GRCh38",
            source: "UCSC hg38.chrom.sizes",
            names: include_str!("../tests/fixtures/reference-contigs/UCSC_hg38.contigs"),
        },
        ReferenceContigSet {
            assembly: "GRCh37",
            source: "UCSC hg19.chrom.sizes",
            names: include_str!("../tests/fixtures/reference-contigs/UCSC_hg19.contigs"),
        },
        ReferenceContigSet {
            assembly: "GRCh38",
            source: "Ensembl Homo_sapiens.GRCh38.dna.toplevel.fa.gz.fai",
            names: include_str!(
                "../tests/fixtures/reference-contigs/Ensembl_GRCh38_toplevel.contigs"
            ),
        },
        ReferenceContigSet {
            assembly: "GRCh37",
            source: "Ensembl GRCh37 primary assembly (REST info/assembly top_level_region)",
            names: include_str!(
                "../tests/fixtures/reference-contigs/Ensembl_GRCh37_primary.contigs"
            ),
        },
    ]
}

/// Path to the **realistic sample** VCF: a synthetic, sites-only allele-frequency export
/// in the shape a `bcftools +fill-tags -S groups` chain produces: 1 637 records over
/// chr21/X/Y/M, twelve populations (`Total`, three countries, two sexes, their products),
/// hemizygous X/Y and haploid M counts, split multi-allelic rows, a rare-heavy spectrum and
/// a caller's own annotations. Real `GRCh38` chr21 sites from a gnomAD v4.1 slice, used
/// under the gnomAD Terms of Use, with
/// simulated counts; no individual's data. Generated by `scripts/gen-sample-vcf.py` from
/// `sites.tsv.gz` and a pinned seed; `scripts/tests/test_gen_sample_vcf.py` proves the
/// committed bytes are what the generator produces.
#[must_use]
pub fn sample_vcf_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample/gdi-sample.GRCh38.vcf.gz")
}

/// The generator's ground truth for [`sample_vcf_path`]: the aggregates the converter must
/// report (`records`, `rowsEmitted`, `rowsPerPopulation`, `populations`,
/// `totalAfZeroVariants`, `nsPeak`, …), as JSON text.
#[must_use]
pub fn sample_expected_json() -> &'static str {
    include_str!("../tests/fixtures/sample/gdi-sample.expected.json")
}

/// The `package.yaml` that builds [`sample_vcf_path`] as a `--strict`-clean dataset.
#[must_use]
pub fn sample_package_yaml() -> &'static str {
    include_str!("../tests/fixtures/sample/gdi-sample.package.yaml")
}

/// Materialize the realistic sample's `package.yaml` and VCF into `dir`, returning the
/// package path, which is the input `build` takes.
///
/// # Panics
/// Panics (test-only helper) if a write fails.
#[expect(
    clippy::must_use_candidate,
    reason = "called for the side effect of materializing the fixture; the returned path is a convenience"
)]
pub fn write_sample_package(dir: &Path) -> PathBuf {
    std::fs::copy(sample_vcf_path(), dir.join("gdi-sample.GRCh38.vcf.gz"))
        .expect("copy sample vcf fixture");
    let p = dir.join("gdi-sample.package.yaml");
    std::fs::write(&p, sample_package_yaml()).expect("write sample package fixture");
    p
}

/// Filesystem path to the canonical on-disk COVID VCF copy inside `test-util`.
/// Use when a consumer needs a stable read-only path (e.g. `convert` a file in place).
#[must_use]
pub fn covid_vcf_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/COVID.monogneic.aggregate.AFs.GRCh38.vcf")
}

/// Materialize the canonical COVID VCF into `dir` (e.g. a test tempdir that the
/// dataset tool will pack). Returns the written path.
///
/// # Panics
/// Panics (test-only helper) if the write fails.
#[expect(
    clippy::must_use_candidate,
    reason = "called for the side effect of materializing the fixture; the returned path is a convenience"
)]
pub fn write_covid_vcf(dir: &Path) -> PathBuf {
    let p = dir.join("COVID.monogneic.aggregate.AFs.GRCh38.vcf");
    std::fs::write(&p, covid_vcf_bytes()).expect("write covid vcf fixture");
    p
}

/// The canonical COVID `covid-package.yaml` fixture text, shared by the tool and e2e
/// test suites so they all build the same package.
#[must_use]
pub fn covid_package_yaml() -> &'static str {
    include_str!("../tests/fixtures/covid-package.yaml")
}

/// Materialize the canonical COVID package into `dir`: writes `covid-package.yaml`
/// (from [`covid_package_yaml`]) plus the COVID VCF it references (via
/// [`write_covid_vcf`]). Returns the path to the written `covid-package.yaml`.
///
/// # Panics
/// Panics (test-only helper) if the directory cannot be created or either write fails.
#[expect(
    clippy::must_use_candidate,
    reason = "called for the side effect of materializing the fixture; the returned path is a convenience"
)]
pub fn write_covid_package(dir: &Path) -> PathBuf {
    #[expect(clippy::disallowed_methods, reason = "test fixture directory")]
    std::fs::create_dir_all(dir).expect("create package dir");
    let yaml = dir.join("covid-package.yaml");
    std::fs::write(&yaml, covid_package_yaml()).expect("write covid-package.yaml");
    write_covid_vcf(dir);
    yaml
}

/// A minimal but valid stored `manifest.json`, as the node writes one into
/// `data_dir/{id}/` after ingest.
///
/// The store scrub parses the stored manifest, and an unparseable one silently takes a
/// dataset out of serving (`cache::apply_scan` skips it on every reload) while
/// `GET /datasets/{id}/state` still answers `visible`. So a test that only needs "a
/// published dataset directory exists" must write something parseable rather than `{}`.
/// Single-sourced here so the required-field set lives in one place rather than in every
/// test that needs a store on disk.
///
/// `datasetId` is a parameter because several call sites assert on the id.
#[must_use]
pub fn stored_manifest_json(dataset_id: &str) -> String {
    format!(
        r#"{{
  "metadata": {{
    "datasetId": "{dataset_id}",
    "catalog": "gdi-aggregated",
    "title": "test dataset",
    "description": "a minimal valid stored manifest for tests",
    "accessRights": "http://publications.europa.eu/resource/authority/access-right/PUBLIC",
    "applicableLegislation": ["http://data.europa.eu/eli/reg/2025/327/oj"],
    "license": "https://creativecommons.org/licenses/by/4.0/",
    "creator": [{{ "name": "test" }}],
    "healthCategory": ["http://data.gdi.eu/core/p2/HealthCategoryHumanGenomic"],
    "numberOfRecords": 1
  }},
  "config": {{
    "mode": "aggregated",
    "blockRange": 10000000,
    "assembly": {{ "reference": "GRCh38" }},
    "manifestVersion": 1,
    "generatedBy": "test-util"
  }}
}}"#
    )
}

/// The current process's effective uid, stdlib-only (no `libc`/`nix`).
///
/// Reads the `Uid:` line of `/proc/self/status`, whose four whitespace-separated fields are
/// the real, effective, saved and filesystem uid; the second is the EUID the kernel's DAC
/// (discretionary access control) checks use. When procfs is unavailable (a stripped
/// container without `/proc` mounted, or a non-Linux Unix) it falls back to creating a
/// throwaway file and reading its owner back through
/// [`std::os::unix::fs::MetadataExt::uid`], since a file this process just created is owned
/// by its own effective uid.
///
/// Unix-only: `MetadataExt::uid` and the notion of a uid do not exist on Windows, and every
/// call site is itself `#[cfg(unix)]`.
#[cfg(unix)]
fn effective_uid() -> u32 {
    use std::os::unix::fs::MetadataExt as _;

    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        let parsed = status.lines().find_map(|line| {
            let rest = line.strip_prefix("Uid:")?;
            rest.split_whitespace().nth(1)?.parse::<u32>().ok()
        });
        if let Some(uid) = parsed {
            return uid;
        }
    }
    let probe = std::env::temp_dir().join(format!(".gdi-euid-probe-{}", std::process::id()));
    std::fs::write(&probe, b"").expect("write euid-probe file");
    let uid = std::fs::metadata(&probe)
        .expect("stat euid-probe file")
        .uid();
    let _ = std::fs::remove_file(&probe);
    uid
}

/// Skip a `chmod`-based permission-denial test when running as root, printing the reason.
///
/// Root bypasses the kernel's DAC checks entirely: a `chmod 000` file still reads and a
/// `chmod 000` directory still lists, so a test asserting on a denied-access fixture would
/// pass for the wrong reason. Root is the default user inside a container, so the tests
/// that rely on such a fixture (`crates/gdi-node-standalone/src/scrub.rs`,
/// `crates/gdi-node-standalone/src/overrides_cmd.rs`) call this immediately after applying
/// the restrictive mode and before undoing it:
///
/// ```ignore
/// std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
/// if test_util::skip_if_root() {
///     std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
///     return;
/// }
/// ```
///
/// Unix-only, like `effective_uid`: a `chmod`-based fixture has no Windows equivalent, so
/// every call site is itself `#[cfg(unix)]` and this is not offered there.
#[cfg(unix)]
#[must_use = "ignoring this discards whether the test must skip"]
pub fn skip_if_root() -> bool {
    let root = effective_uid() == 0;
    if root {
        println!(
            "SKIP: running as root defeats a chmod-based permission fixture (root bypasses \
             the kernel's DAC checks); nothing to assert."
        );
    }
    root
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    /// The `crates/` directory, resolved absolutely from this crate's manifest.
    ///
    /// Every guard below roots its walk here. Resolving `".."` against the current
    /// directory instead would escape into any nested checkout and report offenders outside
    /// the tree under test; the `scanned > N` assertions only catch scanning too little.
    fn crates_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crates/ is one level above crates/test-util")
            .to_path_buf()
    }

    /// Recursively collect every `.rs` file under `dir`.
    fn rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // `target/` holds vendored and generated sources that are not ours to
                // police, and a nested worktree is a second checkout with its own
                // `crates/`: descending into either makes the guard police a different tree.
                if path
                    .file_name()
                    .is_some_and(|n| n == "target" || n == ".worktrees")
                {
                    continue;
                }
                rs_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    /// The `fn` body starting at or after `start`.
    ///
    /// Delimited by the closing brace at the `fn`'s own indentation rather than by counting
    /// braces: Rust test bodies are full of `{}` inside `format!`/`assert!` strings, and a
    /// naive counter runs past the end and swallows the next test. `cargo fmt --check` is a
    /// gate leg, so the closing brace is reliably at that column.
    fn body_of(lines: &[&str], start: usize) -> String {
        let mut i = start;
        while i < lines.len() && !lines[i].contains("fn ") {
            i += 1;
        }
        if i >= lines.len() {
            return String::new();
        }
        let indent: String = lines[i].chars().take_while(|c| c.is_whitespace()).collect();
        let close = format!("{indent}}}");
        let mut end = i + 1;
        while end < lines.len() && lines[end] != close {
            end += 1;
        }
        lines[i..=end.min(lines.len() - 1)].join("\n")
    }

    /// Every spelling that mutates process env.
    ///
    /// `EnvGuard::` is listed because it is the form this crate tells callers to prefer,
    /// and it contains neither `set_env(` nor `remove_env(`; keying only on those two would
    /// leave the guard blind to the API that adoption is moving toward. `jail.set_env(`
    /// (figment's `Jail`, which `core`'s config suite uses throughout) is already matched by
    /// the `set_env(` entry, and is spelled out so a later tightening to
    /// `test_util::set_env(` cannot silently drop those sites.
    const ENV_MUTATORS: [&str; 4] = ["set_env(", "remove_env(", "EnvGuard::", "jail.set_env("];

    /// Every spelling that arms a `core::faults` fault point.
    const FAULT_ARMERS: [&str; 4] = ["arm_once(", "arm_delay(", "arm_enospc(", "faults::arm"];

    /// Binding names that mean "I am saving this to put it back".
    ///
    /// Keyed on save-intent names rather than any `let x = std::env::var(..)`: the
    /// workspace has a dozen or so legitimate such reads (defaults via `unwrap_or_else`,
    /// `GDI_CORPUS_DIR`, `GDI_BLESS_SCHEMA`, `build.rs`), and none binds one of these
    /// names. Widening further would trade a real catch for a pile of false positives.
    const SAVE_NAMES: [&str; 5] = [
        "let prev",
        "let old",
        "let previous",
        "let saved",
        "let orig",
    ];

    /// Whether `attrs` carries a `#[serial(..)]` naming `group`.
    ///
    /// Matches the group as a comma-separated token inside the parens rather than testing
    /// for the literal `serial(env)`, so a test that needs two locks can spell it
    /// `#[serial(env, faults)]` without being reported as unkeyed.
    fn carries_serial_key(attrs: &str, group: &str) -> bool {
        let mut rest = attrs;
        while let Some(at) = rest.find("serial(") {
            rest = &rest[at + "serial(".len()..];
            let Some(end) = rest.find(')') else { break };
            if rest[..end].split(',').any(|k| k.trim() == group) {
                return true;
            }
        }
        false
    }

    /// `EnvGuard` restores the previous value even when the scope unwinds, which is the
    /// reason it exists: a save/restore written as a trailing statement is skipped by a
    /// failing assertion, leaking the override into every later test in the process.
    #[test]
    #[serial(env)]
    fn env_guard_restores_on_unwind_not_just_on_success() {
        const KEY: &str = "GDI_TEST_ENV_GUARD_UNWIND";

        // Case 1: an absent var must be absent again after a panic.
        remove_env(KEY);
        let caught = std::panic::catch_unwind(|| {
            let _g = EnvGuard::set(KEY, "inner");
            assert_eq!(std::env::var(KEY).as_deref(), Ok("inner"));
            panic!("simulated assertion failure");
        });
        assert!(caught.is_err(), "the inner panic must propagate");
        assert!(
            std::env::var_os(KEY).is_none(),
            "an absent var must be absent again after the guarded scope unwinds"
        );

        // Case 2: a var that was set must hold its old value again.
        set_env(KEY, "outer");
        let caught = std::panic::catch_unwind(|| {
            let _g = EnvGuard::set(KEY, "inner");
            panic!("simulated assertion failure");
        });
        assert!(caught.is_err());
        assert_eq!(
            std::env::var(KEY).as_deref(),
            Ok("outer"),
            "the prior value must be restored after unwind"
        );

        // Case 3: `remove` is symmetric.
        {
            let _g = EnvGuard::remove(KEY);
            assert!(std::env::var_os(KEY).is_none());
        }
        assert_eq!(std::env::var(KEY).as_deref(), Ok("outer"));
        remove_env(KEY);
    }

    /// No test may wait out `S3_METADATA_TIMEOUT`.
    ///
    /// The constant is 15 s of pure sleeping, not work, so a test that builds a production
    /// store and waits it out costs the same on an idle machine as on a loaded one and
    /// lands straight on the gate's critical path.
    ///
    /// Both call sites are one-line delegations (`build_metadata_object_store` to
    /// `..._with`, `build_object_store` to `..._with`), so a test that needs the bounding
    /// behaviour injects a small bound and never names the constant. Referencing it from
    /// test code is therefore the signal.
    ///
    /// Scoped to this one constant: it is the only
    /// `pub const *TIMEOUT* = Duration::from_secs(..)` in `core`, so the class currently
    /// has a single member. Add arms here if that stops being true.
    #[test]
    fn no_test_waits_out_the_s3_metadata_timeout() {
        const NEEDLE: &str = "S3_METADATA_TIMEOUT";

        let mut files = Vec::new();
        rs_files(&crates_dir(), &mut files);
        let mut offenders = Vec::new();
        let mut scanned = 0_usize;
        for path in files {
            // This guard names the constant in its own body and assertion text.
            if path.ends_with("test-util/src/lib.rs") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            scanned += 1;
            // Test code is either a file under a `tests/` dir, or everything after this
            // file's `#[cfg(test)]` marker, the layout every module in this workspace
            // uses (unit tests last).
            let in_tests_dir = path.components().any(|c| c.as_os_str() == "tests");
            let cfg_test_at = text.find("#[cfg(test)]");
            let mut offset = 0_usize;
            for (n, line) in text.lines().enumerate() {
                let here = offset;
                offset += line.len() + 1;
                let trimmed = line.trim_start();
                // Prose may discuss the constant freely; only code counts.
                if trimmed.starts_with("//") || !line.contains(NEEDLE) {
                    continue;
                }
                if in_tests_dir || cfg_test_at.is_some_and(|at| here > at) {
                    offenders.push(format!("{}:{}", path.display(), n + 1));
                }
            }
        }
        assert!(
            scanned > 100,
            "scanned only {scanned} files: the walker is broken, so this guard would \
             pass having checked nothing"
        );
        assert!(
            offenders.is_empty(),
            "test code references {NEEDLE} at {offenders:?}. A test that needs the \
             bounding BEHAVIOUR should inject a small bound through \
             `build_metadata_object_store_with` / `build_object_store_with` instead — \
             waiting the real 15 s buys nothing and lands straight on the gate's \
             critical path."
        );
    }

    /// The hand-rolled save/restore shape must not come back.
    ///
    /// `EnvGuard` is only worth having if new code reaches for it, and nothing about a
    /// `let prev = std::env::var_os(...)` line looks wrong on review; it reads as careful.
    /// This guard is what makes the careful-looking version fail.
    #[test]
    fn no_hand_rolled_env_save_restore() {
        let mut offenders = Vec::new();
        let mut scanned = 0_usize;
        let mut files = Vec::new();
        rs_files(&crates_dir(), &mut files);
        for path in files {
            // This very guard names the pattern in its own assertion text.
            if path.ends_with("test-util/src/lib.rs") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            scanned += 1;
            for (n, line) in text.lines().enumerate() {
                let l = line.trim();
                // Two axes: a save-intent binding name and either read form. Keying on one
                // read misses the other (`std::env::var(` as well as `var_os(`), which are
                // equivalent here, and any synonym for the binding name walks straight past.
                let reads_env = l.contains("std::env::var_os(") || l.contains("std::env::var(");
                if reads_env && SAVE_NAMES.iter().any(|n| l.starts_with(n)) {
                    offenders.push(format!("{}:{}", path.display(), n + 1));
                }
            }
        }
        assert!(
            scanned > 100,
            "scanned only {scanned} files: the walker is broken, so this guard would \
             pass having checked nothing"
        );
        assert!(
            offenders.is_empty(),
            "hand-rolled env save/restore found at {offenders:?}. Use \
             `test_util::EnvGuard::set(KEY, value)` instead: it restores on `Drop`, so a \
             failing assertion cannot leak the override into later tests."
        );
    }

    /// Every test that mutates process-global state must hold the lock that names it.
    ///
    /// `serial_test` keys its locks by name, so a bare `#[serial]` and a `#[serial(env)]`
    /// are two independent mutexes that do not exclude each other. A bare-keyed env mutator
    /// runs concurrently with a keyed one, and the safety reasoning on [`set_env`], which
    /// justifies the one `unsafe` block this workspace permits, stops holding. The same
    /// applies to `core::faults`, whose registry is a process-global
    /// `HashMap<FaultPoint, Armed>`: two differently-keyed arms clobber each other, and one
    /// guard's `Drop` disarms what the other still needs.
    ///
    /// Both are inert under `cargo nextest`, a process per test, and under `ci-local.sh`'s
    /// no-nextest fallback, which sets `RUST_TEST_THREADS=1` rather than
    /// `-- --test-threads=1` because everything after `--` also reaches the
    /// `harness = false` bench targets, whose CLI rejects the flag. A hand-run
    /// multi-threaded `cargo test --workspace` is where the races are real.
    ///
    /// The lock is chosen by an attribute while the mutation happens in the body, so no
    /// signature can make the body demand its own lock. Hence a text scan rather than a
    /// single-sourced fact.
    ///
    /// # Blind spots
    ///
    /// Two shapes slip past, so green here does not prove that no unkeyed mutator exists.
    ///
    /// 1. Indirection. Only the test's own body is scanned, so a test calling a helper that
    ///    mutates env (`fn arrange() { set_env(..) }`) is invisible.
    /// 2. Truncation. [`body_of`] ends the body at the first line equal to the `fn`'s
    ///    closing-brace column, so a mutation placed after an embedded raw string that
    ///    contains a dedented `}` is not seen.
    ///
    /// Closing either needs call-graph analysis or real brace matching, and a guard that
    /// cries wolf gets ignored. The residual risk is bounded by the runner instead, by
    /// process isolation or by one test thread. If that stops being true, shrink the
    /// population of env mutators by preferring `Command::env` to a child process, rather
    /// than growing the parser.
    #[test]
    fn global_state_mutators_carry_their_serial_key() {
        let mut files = Vec::new();
        rs_files(&crates_dir(), &mut files);
        assert!(files.len() > 50, "found only {} .rs files", files.len());

        let mut offenders = Vec::new();
        for path in &files {
            // This crate defines the mutators; its own `fn set_env` is not a call site.
            if path.ends_with("test-util/src/lib.rs") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(path) else {
                continue;
            };
            let lines: Vec<&str> = text.lines().collect();
            for (idx, line) in lines.iter().enumerate() {
                if !line.trim_start().starts_with("#[") || !line.contains("test") {
                    continue;
                }
                // Only look at `#[test]` / `#[tokio::test]` attribute blocks.
                if !(line.contains("#[test]") || line.contains("::test]")) {
                    continue;
                }
                let body = body_of(&lines, idx);
                // The attribute block runs from this test's first attribute line down to
                // its `fn`. Walk upward first: `#[serial(env)]` above `#[test]` is equally
                // valid Rust, and collecting only downward would report it as unkeyed.
                let mut first_attr = idx;
                while first_attr > 0 && lines[first_attr - 1].trim_start().starts_with("#[") {
                    first_attr -= 1;
                }
                let attrs: String = lines[first_attr..]
                    .iter()
                    .take_while(|l| !l.contains("fn "))
                    .copied()
                    .collect::<Vec<_>>()
                    .join(" ");
                // Both groups are checked independently: an `else if` chain would let a
                // test that touches env and faults satisfy the guard with only the env key.
                let mut needed: Vec<&str> = Vec::new();
                if ENV_MUTATORS.iter().any(|t| body.contains(t)) {
                    needed.push("env");
                }
                if FAULT_ARMERS.iter().any(|t| body.contains(t)) {
                    needed.push("faults");
                }
                for group in needed {
                    if carries_serial_key(&attrs, group) {
                        continue;
                    }
                    let name = lines[idx..]
                        .iter()
                        .find(|l| l.contains("fn "))
                        .unwrap_or(&"?")
                        .trim();
                    offenders.push(format!(
                        "{}:{} needs #[serial({group})]; {name}",
                        path.display(),
                        idx + 1
                    ));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "tests mutating process-global state without the matching serial group \
             (a bare #[serial] is a DIFFERENT lock and excludes nothing):\n  {}",
            offenders.join("\n  ")
        );
    }

    /// The runner that promises a backend must export the flag that makes the promise
    /// binding.
    ///
    /// [`endpoint_env`] turns a real-endpoint smoke's skip into a hard failure only when
    /// [`REQUIRED_ENV_FLAG`] is set, and nothing in Rust reads that const outside this
    /// crate: its only consumer is `scripts/e2e/run-full.sh`, which re-spells the name as a
    /// shell literal. Rename the const and the script keeps exporting the old variable,
    /// so every real-endpoint smoke takes its env-absent early return and `--ignored`
    /// reports a pass having exercised nothing.
    ///
    /// A shell script cannot import a Rust const, so the duplication is irreducible. Keyed
    /// on an `export` statement rather than any mention, because `scripts/e2e/run-full.sh`
    /// and `docs/testing.md` both discuss the variable in prose and prose must not be able
    /// to satisfy the guard.
    #[test]
    fn the_required_env_flag_is_exported_by_the_runner_that_promises_it() {
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("workspace root is two levels above crates/test-util")
            .join("scripts/e2e/run-full.sh");
        let text = std::fs::read_to_string(&script).unwrap_or_else(|e| {
            panic!(
                "cannot read {} ({e}) — the runner that exports {REQUIRED_ENV_FLAG} has \
                 moved, so this guard would otherwise pass having checked nothing",
                script.display()
            )
        });
        let needle = format!("export {REQUIRED_ENV_FLAG}=");
        assert!(
            text.lines().any(|l| l.trim_start().starts_with(&needle)),
            "{} has no `{needle}...` statement. `endpoint_env` promotes a missing endpoint \
             var to a hard failure ONLY when {REQUIRED_ENV_FLAG} is set; without that \
             export every real-endpoint smoke silently early-returns and the whole \
             `--ignored` run is a false green.",
            script.display()
        );
    }

    /// The `unsafe` exemption stays scoped to this crate.
    ///
    /// The workspace sets `unsafe_code = "deny"` rather than `"forbid"` so that this crate,
    /// the audited home for the `std::env` mutators Rust 2024 requires, can inherit the
    /// whole workspace lint set and annotate its two blocks. `forbid` cannot be overridden
    /// in source, so buying the exemption that way would also cost this crate `pedantic`,
    /// `unwrap_used`, `todo`, `dbg_macro` and `unreachable_pub`.
    ///
    /// What `deny` gives up is that any crate could re-allow the lint, in source or in its
    /// manifest. This guard is that difference made binding: the exemption is one named
    /// site, not an open door.
    #[test]
    fn unsafe_code_is_allowed_only_in_the_audited_crate() {
        let crates_dir = crates_dir();
        let mut files = Vec::new();
        rs_files(&crates_dir, &mut files);
        assert!(
            files.len() > 50,
            "found only {} .rs files — the walker is broken, so this guard would pass \
             having checked nothing",
            files.len()
        );

        let mut offenders = Vec::new();
        for path in &files {
            // This crate is the exemption; its two annotated blocks are the allowance.
            if path.ends_with("test-util/src/lib.rs") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(path) else {
                continue;
            };
            for (n, line) in text.lines().enumerate() {
                if line.trim_start().starts_with("//") {
                    continue;
                }
                if line.contains("allow(unsafe_code") || line.contains("expect(unsafe_code") {
                    offenders.push(format!("{}:{}", path.display(), n + 1));
                }
            }
        }
        // A crate can also re-level the lint in its manifest, which no source scan sees.
        for entry in std::fs::read_dir(&crates_dir)
            .into_iter()
            .flatten()
            .flatten()
        {
            if entry.file_name() == "test-util" {
                continue;
            }
            let manifest = entry.path().join("Cargo.toml");
            let Ok(text) = std::fs::read_to_string(&manifest) else {
                continue;
            };
            for (n, line) in text.lines().enumerate() {
                if line.trim_start().starts_with("unsafe_code") {
                    offenders.push(format!("{}:{}", manifest.display(), n + 1));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "`unsafe_code` is re-leveled outside the audited crate at {offenders:?}. The \
             workspace uses `deny` (not `forbid`) only so `test-util` can carry \
             `#[expect(unsafe_code)]` on its two `std::env` blocks; every other crate must \
             stay unsafe-free. If a new site genuinely needs `unsafe`, move it behind an \
             audited helper here rather than widening the exemption."
        );
    }

    #[test]
    fn covid_vcf_bytes_are_the_canonical_fixture() {
        // Format smoke check only. The semantic contract (the exact allele counts this
        // fixture must yield) is pinned where it matters: `crates/core/tests/it/convert_covid.rs`
        // parses these bytes and asserts `total.ac == covid::TOTAL_AC`, `total.an ==
        // TOTAL_AN` and the FI-male AF/AC. A byte-length pin here would add no coverage
        // those content assertions do not already give, and would trip on every
        // legitimate whitespace or header edit.
        let b = covid_vcf_bytes();
        assert!(
            b.starts_with(b"##fileformat=VCF"),
            "canonical fixture must be a well-formed VCF"
        );
    }

    #[test]
    fn write_covid_vcf_materializes_a_real_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = write_covid_vcf(dir.path());
        assert!(p.exists());
        assert_eq!(std::fs::read(&p).expect("read"), covid_vcf_bytes());
    }

    #[test]
    fn write_covid_package_materializes_yaml_and_vcf() {
        let dir = tempfile::tempdir().expect("tempdir");
        let yaml_path = write_covid_package(dir.path());
        assert!(yaml_path.exists(), "covid-package.yaml must be written");
        assert!(
            dir.path()
                .join("COVID.monogneic.aggregate.AFs.GRCh38.vcf")
                .exists(),
            "the referenced VCF must be written alongside the package"
        );
        assert_eq!(
            std::fs::read_to_string(&yaml_path).expect("read"),
            covid_package_yaml(),
            "written yaml must match the canonical fixture text"
        );
    }

    /// `effective_uid()` must agree with the system's own answer. `id -u` shells out to
    /// the same kernel the `/proc` parse (or its file-owner fallback) reads, so this checks
    /// the stdlib-only implementation independently rather than restating it.
    #[cfg(unix)]
    #[test]
    fn effective_uid_matches_id_dash_u() {
        let out = std::process::Command::new("id")
            .arg("-u")
            .output()
            .expect("run `id -u`");
        assert!(out.status.success(), "id -u exited non-zero");
        let want: u32 = String::from_utf8(out.stdout)
            .expect("id -u output is not UTF-8")
            .trim()
            .parse()
            .expect("id -u did not print a number");
        assert_eq!(
            effective_uid(),
            want,
            "effective_uid() must report the same uid `id -u` does"
        );
    }

    /// `skip_if_root()` must return exactly `effective_uid() == 0`, so this pins the
    /// boolean against the uid check itself rather than against the environment the suite
    /// happens to run in.
    #[cfg(unix)]
    #[test]
    fn skip_if_root_reflects_effective_uid() {
        assert_eq!(skip_if_root(), effective_uid() == 0);
    }
}

/// The byte offset just past the `}` closing the block whose `{` is at `open`, skipping
/// braces inside string literals and `//` comments.
fn block_end(src: &str, open: usize) -> usize {
    let bytes = src.as_bytes();
    let mut depth = 0usize;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    if bytes[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    bytes.len()
}

/// Whether a `#[cfg(…)]` attribute line gates on `test`: `cfg(test)`, `cfg(all(test, …))`
/// or `cfg(any(test, …))`.
fn is_test_cfg(attr_line: &str) -> bool {
    let inner = attr_line.trim_start();
    inner.starts_with("#[cfg(")
        && (inner.starts_with("#[cfg(test)")
            || inner.starts_with("#[cfg(all(test")
            || inner.starts_with("#[cfg(any(test"))
}

/// `src` with every test-gated `mod … { … }` cut out, by brace matching.
///
/// For source-scanning guards that must see production code only. Not "the text before the
/// first test module": a file may hold several, with production code between them
/// (`crates/gdi-node-standalone/src/s3.rs` has three), and clippy's
/// `items_after_test_module` does not forbid that, so cutting at the first one silently
/// skips the rest. Attributes between the `cfg` and the `mod` are stepped over; a test
/// `cfg` on anything other than a `mod` is left alone. The Python twin is
/// `scripts/tests/_helpers.strip_test_modules`.
#[must_use]
pub fn production_text(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut from = 0;
    while let Some(at) = src[from..].find("\n#[cfg(") {
        let attr_at = from + at + 1;
        let attr_end = src[attr_at..].find('\n').map_or(src.len(), |n| attr_at + n);
        if !is_test_cfg(&src[attr_at..attr_end]) {
            out.push_str(&src[from..attr_end]);
            from = attr_end;
            continue;
        }
        // Further attributes may sit between the cfg and the item.
        let mut cursor = attr_end;
        while src[cursor..].trim_start().starts_with("#[") {
            let skip = src[cursor..].len() - src[cursor..].trim_start().len();
            cursor += skip;
            cursor = src[cursor..].find('\n').map_or(src.len(), |n| cursor + n);
        }
        if !src[cursor..].trim_start().starts_with("mod ") {
            out.push_str(&src[from..attr_end]);
            from = attr_end;
            continue;
        }
        let Some(brace) = src[cursor..].find('{') else {
            break;
        };
        out.push_str(&src[from..attr_at]);
        from = block_end(src, cursor + brace);
    }
    out.push_str(&src[from..]);
    out
}

#[cfg(test)]
mod production_text_tests {
    use super::production_text;

    #[test]
    fn production_between_two_test_modules_survives() {
        let src = "fn a() {}\n#[cfg(test)]\nmod tests { fn t() { let _ = \"{\"; } // }\n}\n\
                   fn b() {}\n#[cfg(all(test, feature = \"x\"))]\n#[allow(dead_code)]\n\
                   mod more { fn u() {} }\nfn c() {}\n";
        let kept = production_text(src);
        assert!(kept.contains("fn a()") && kept.contains("fn b()") && kept.contains("fn c()"));
        assert!(!kept.contains("fn t()") && !kept.contains("fn u()"));
    }

    #[test]
    fn a_test_cfg_on_a_non_module_item_is_left_alone() {
        let src = "#[cfg(test)]\nconst FIXTURE: &str = \"x\";\nfn a() {}\n";
        assert_eq!(production_text(src), src);
    }
}
