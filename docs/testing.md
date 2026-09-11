# Testing

How `gdi-node-standalone` is tested: the kinds of tests, where each kind lives, how to add
one, and how to run them. [`CONTRIBUTING.md`](../CONTRIBUTING.md) covers the gate that
enforces it.

## Philosophy

Two rules shape where a test goes:

1. **Test the logic in the crate that owns it; test only the wiring in the crate that
   wires it.** A property of the Beacon query math is tested in the `beacon` crate; that
   the HTTP layer serves it correctly is tested in the `gdi-node-standalone` service crate. The
   library crates (`core`, `beacon`, `fairdp`) own their own correctness; the service
   crate's integration tests are for orchestration and HTTP wiring, not re-proving
   library logic.
2. **One integration-test binary per crate.** Each crate's `tests/` compiles into a single
   `it` binary: `tests/it/main.rs` with `mod <area>;` per suite, not one binary per file.
   Each separate `tests/*.rs` file is a separate linked executable that re-embeds the whole
   dependency closure, so each crate keeps one. Add a new integration suite as a module
   of `it`, never as a new top-level `tests/*.rs`.

   The exceptions are the service's `beacon_info`, `beacon_schema_conformance`,
   `conformance_crawl` and `conformance_agreement`; `core`'s `corpus`, `crypt4gh_interop`,
   `crypt4gh_kat` and `sample_fixture`; and `gdi-dataset-tool`'s `tls_roots`. Several are
   addressed by target name from `ci-local.sh` (`--test corpus`, `--test crypt4gh_interop`,
   the conformance pair), so folding those into `it` breaks the gate. `fairdp` is a single
   standalone file with a small closure. `beacon`'s suites are not exceptions: they all
   reach `core` and would each re-embed the arrow/parquet/noodles closure, so they share
   one `tests/it/` binary.

## The tiers

| # | Tier | Home | What it is |
| --- | --- | --- | --- |
| 1 | **Unit** | `src/` `#[cfg(test)]` (or a sibling `mod tests` file when large) | Fast, in-process, no I/O or process spawn; tests the module it sits in. |
| 2 | **Property** | unit-invariant → inline `src/`; system property → `tests/` | `proptest`-driven invariants. |
| 3 | **Integration** | the crate's single `tests/it/` binary | Cross-module / HTTP / wiring behaviour. |
| 4 | **Snapshot / golden** | `tests/snapshots/`, plus one inline case | `insta` goldens for contract-shaped output. |
| 5 | **Conformance** | Rust in the service `tests/`; Python in `conformance/` | GA4GH Beacon v2 + FDP/DCAT standards conformance. |
| 6 | **Fuzz** | `crates/core/fuzz` | `cargo-fuzz` targets over untrusted-input parsers. |
| 7 | **Bench** | `benches/` (criterion) | Advisory hot-path microbenchmarks; gate nothing. |
| 8 | **Guard** | `tests/it/` drift-guards + scheduled jobs | Executable invariants about the repo itself. |
| — | *(out-of-process)* | `scripts/e2e`, `scripts/load`, `scripts/soak`, `scripts/chaos` | Compose-stack e2e + `oha` load + leak/crash-loop soak + toxiproxy S3/Vault chaos. `e2e`/`chaos` need Docker; `load`/`soak` boot their own node and build the release binaries if absent. |

---

### 1. Unit

Inline `#[cfg(test)] mod tests` in the source file under test. This is the bulk of the
suite, especially in `core` (crypto, parquet, convert, config, validation). No I/O, no
process spawn, fast. A large test module may live in a sibling file included with
`mod tests;`, as `core/src/config/mod.rs` includes `config/tests.rs`.

- **Add:** a `#[test]`/`#[tokio::test]` fn in the module's `#[cfg(test)] mod tests`.
- **Env mutation:** never call `std::env::set_var`/`remove_var` directly (the workspace
  forbids `unsafe`, which they now require). Use `test_util::set_env`/`remove_env` and
  mark the test `#[serial(env)]` (see [Fixtures](#shared-fixtures)).

### 2. Property (`proptest`)

`proptest` is pinned in `core`, `beacon`, `fairdp`. The home rule:

- A property of a single unit's invariant lives inline in that `src/` module, as in
  `core/src/id.rs`, `core/src/popfield.rs`, `beacon/src/query.rs`, `beacon/src/request.rs`
  and `core/src/crypt4gh/mod.rs`.
- A property spanning modules, or asserting a system behaviour, lives under the crate's
  `tests/`: as a module of the tier-3 `tests/it/` binary where the crate has one
  (`beacon/tests/it/query_proptest.rs`, `beacon/tests/it/suppression_properties.rs`), or
  as its own binary in a crate that already keeps loose ones (`fairdp/tests/render.rs`).
  That is not licence to add a second binary to a crate that has only `tests/it/`.

A property test and a fuzz target over the same parser are not redundant; see
[Kept on purpose](#kept-on-purpose).

### 3. Integration

The crate's single `tests/it/` binary. Files are named for the area under test
(`tests/it/<area>.rs`), wired with `mod <area>;` in `tests/it/main.rs`. Large suites are
split into a directory module — `tests/it/s3_reconcile/` (a dozen files: `mod.rs` plus
`errors`, `hooks`, `keyspace`, `multibucket`, `prefix`, `real_endpoint`, `reconcile`,
`reingest`, `reload`, `suppression`, `tombstone`) and
`tests/it/beacon_query/{mod,errors,misc,results,wiring}.rs` — still one binary. Read
`mod.rs` for the current member list rather than this sentence; it is the file that
declares them.

Feature-gated suites (`s3`, `vault`, `pme`) are `#[cfg(feature = "…")] mod …;` in
`main.rs` and carry their own inner `#![cfg(feature = "…")]`; absent without the feature.

> **Naming note.** In `gdi-dataset-tool` most integration suites are named
> `tests/it/*_e2e.rs`, which is a misnomer: they are in-process tests that call the command
> handlers directly, and only a handful spawn the binary to assert a stdout or stderr
> contract. True end-to-end is the Compose script below. Name new tool integration suites
> `tests/it/<area>.rs`, as `bundled_sample.rs`, `cli_docs.rs` and `validators_reachable.rs`
> already are.

### 4. Snapshot / golden (`insta`)

Goldens for contract-shaped output live in each crate's `tests/snapshots/`:
`fairdp/tests/snapshots/` (RDF N-Triples renderings), `beacon/tests/it/snapshots/`
(`g_variants` resultset, datasets collection), `gdi-node-standalone/tests/snapshots/`
(the six `beacon_info__*` Beacon informational endpoints).

Two are inline, both unit-level contracts that keep a `src/snapshots/` file beside the
code they pin: `beacon/src/model.rs`'s `frequencyInPopulations` serialization contract, and
`gdi-dataset-tool/src/cli.rs`'s `cli_argument_surface_is_pinned`, which pins the CLI's
own argument surface. The tier rule is the same as for tests: a unit-level golden is
inline, an integration-level golden is in `tests/`.

- **Review changes** with `cargo insta test --review`, never a blind `--accept`. A model
  change that churns a `beacon_info__*` golden is the conformance guard working, because
  that golden is the exact GA4GH-shaped document.

### 5. Conformance

Standards conformance is guarded on two sides:

- **Rust** (in the service `tests/`): `beacon_schema_conformance.rs` validates real
  responses against the vendored GA4GH Beacon v2.2.0 JSON Schemas — the envelope against
  the framework set (`conformance/ga4gh-beacon-v2/`) and every `g_variants` `results[]`
  item against the default-model entity schema
  (`conformance/ga4gh-beacon-v2-default-model/`) and the VRS 1.3 schema it `$ref`s
  (`conformance/ga4gh-vrs-1.3/`); `conformance_crawl.rs` crawls `/fairdp` and emits a
  unioned Turtle graph; `conformance_agreement.rs` guards the Rust gate against the
  Python pySHACL result so the two encodings cannot drift. `conformance_crawl.rs` and
  `conformance_agreement.rs` are **standalone test binaries** (not folded into `it`)
  because `ci-local.sh conformance` invokes them by target name with `-- --ignored` and
  asserts the exact ignored-test count per target. `beacon_schema_conformance.rs` is kept
  separate by convention; it carries no `#[ignore]`d tests and runs in the ordinary
  `cargo test`/nextest sweep.
- **Python** (in `conformance/`, isolated from the Rust build, never shipped): pySHACL +
  `ckanext-dcat` over the crawled FDP graph (`check_fdp.py`, `check_fdp_negative.py`,
  `check_ckanext.py`, `check_dataset.py`), and a Rust↔Python `crypt4gh` interop round-trip
  (`crates/core/tests/crypt4gh_interop.rs` against pinned `crypt4gh==1.8.6`).

The Python-dependent Rust tests are `#[ignore]` by default (they need a venv discovered
via `GDI_FDP_PYTHON`/`GDI_FDP_VENV` / `C4GH_VENV`), so a plain `cargo test` needs no
Python.

Run them with `./scripts/ci-local.sh conformance` and `./scripts/ci-local.sh crypt4gh`.
Both build a cached venv under `target/venv/` on first use (network once) and both are in
`ci-local.sh all`. Each asserts the **exact** number of `#[ignore]`d tests it selected —
`cargo test -- --ignored` exits 0 when it matches zero tests, so a renamed or un-ignored
test would otherwise run nothing and still pass.

### 5b. Guarding the guards (stdlib `unittest`)

Several of the project's gates are themselves Python, and each has a pure-stdlib
`unittest` suite pinning the properties it depends on. Stdlib only is enforced, not
merely conventional: `test_suite_is_stdlib_only.py` fails if anything under
`scripts/tests/` imports a third-party package. `script-tests` runs inside `quick`, so a
dependency there would make a missing module block every commit touching `scripts/`.

The one guard that genuinely needs a third-party parser lives in `scripts/tests/k8s/`
behind its own `all`-only leg (`ci-local.sh k8s-manifests`), with PyYAML pinned and
hash-locked in `scripts/tests/k8s/requirements.txt`. That is the pattern to copy if you
add another: a sibling directory with its own leg, never a dependency in the flat suite.

| Suite | Guards | Run |
| --- | --- | --- |
| `scripts/tests/test_check_dashboard_metrics.py` | Only PromQL `expr:` fields count as "alerted" — never a comment or an `annotations.summary`. That `expr: \|` block scalars are still seen. And that every Loki **log panel** selects on a label Alloy actually emits, naming a real Compose service. | `python3 -m unittest discover -s scripts/tests -p 'test_*.py'` (also run by `ci-local.sh script-tests`) |
| `scripts/tests/test_check_ci_gate.py` | Every `ci.yml` job is a `ci-success` dependency, and every `scheduled.yml`/`e2e-full.yml` job is wired into its `notify`; no gate in any of the three gains an `if:`/`continue-on-error` without a reasoned allowlist entry; the declared MSRV does not exceed the `rust-toolchain.toml` pin. | same command |
| `scripts/tests/test_load_checks.py` | `scripts/load/checks.py` fails **closed** when oha reports no status codes, on both the baseline and saturation legs. | same command |
| `conformance/test_check_dataset.py` | `check_dataset.py` refuses to emit `CONFORMS` from an empty shapes graph (SHACL conforms vacuously when nothing is targeted). | `./scripts/ci-local.sh conformance` — runs it inside the cached `target/venv/fdp` venv; that leg is in `all` |

**The rule, not the table, is the contract.** `ci-local.sh script-tests` runs
`python3 -m unittest discover -s scripts/tests -p 'test_*.py'`, so every
`scripts/tests/test_*.py` is discovered and run by `all`, and adding a guard suite is a
matter of dropping a file there. The table above lists three of the suites under
`scripts/tests/` (`ls scripts/tests/test_*.py | wc -l` counts them all) plus one of the two
under `conformance/` (`test_check_dataset.py` and `test_check_fdp_negative.py`, both
discovered by that leg), chosen because their guarded property states in one line. It is
not an inventory.

Because discovery is a glob, the leg also asserts a floor on the number of tests it found.
A file renamed off `test_*.py`, moved a directory deeper, or whose `TestCase` loses its
`test_` prefix, otherwise produces a smaller run that `unittest` still reports as `OK`.
Removing a test is fine; lowering the floor in the same commit is what makes it
intentional.

`./scripts/ci-local.sh script-tests` runs the `scripts/tests/` suites, and is in both `all`
and `quick`, so the pre-commit hook runs them too. That matters because several of them
(`test_pre_commit_hook`, `test_ci_local_preflight`) guard the hook and gate machinery a
commit is about to use. `scripts/tests/k8s/` is excluded from that path and runs only in
`all`, because it guards an example Kustomize base that rarely changes and does not justify
a hard PyYAML dependency on every commit. The `conformance/` suite needs the pinned venv, so
`./scripts/ci-local.sh conformance` runs it after building or reusing `target/venv/fdp` and
before the checkers themselves.

### 5c. The gate graph, and the toolchain it runs on

`ci-success` is the single required check for branch protection: it `needs:` every job, runs
`if: always()`, and fails on any `failure` or `cancelled`. Two subtleties are enforced
mechanically rather than by comment:

- It also fails on an unexpected `skipped`, because a gate that stops matching its own `if:`
  would otherwise stop enforcing while the required check stayed green. The allowlist is the
  `ALLOWED_SKIPS` env value on that step, and there is one copy of it: `check-ci-gate.py`
  reads it back from the workflow and uses it to reject an un-allowlisted job-level `if:`.
- `scripts/check-ci-gate.py`, in `ci-local.sh ci-gate` and in the `actionlint` job, asserts
  every job in `ci.yml` is a `ci-success` dependency, so a new gate cannot be added and left
  unwired. It applies the same rules to the `notify` jobs in `scheduled.yml` and
  `e2e-full.yml`: an unwired weekly job fails on cron and opens no tracking issue, and a
  `continue-on-error` on the RustSec `advisories` scan would mute it silently.

> The guards live in `ci-local.sh all` (`ci-gate`, `dashboard`) rather than only in a
> workflow step, so they answer for a local tree too: CI is a post-push verdict, not one
> you can get before you commit. Any cadence this document names ("weekly") is a
> workflow's, and a claim about a live upstream: a fork runs schedules only with Actions
> enabled, and GitHub disables them after 60 days of repository inactivity.

`rust-toolchain.toml` pins the dev toolchain, and a toolchain file outranks `rustup
default`, so every bare `cargo` compiles with that pin rather than whatever `stable` the
runner installed. `check-ci-gate.py` therefore also asserts `rust-version` does not exceed
that pin; an MSRV below the pin is the conservative configuration and is allowed. The
toolchain pin tracks current stable, with the MSRV a separate ratchet below it, so the
weekly `stable-canary` job in `scheduled.yml` runs `cargo +stable clippy` and `check` and
emits a notice when stable moves ahead of the pin. New lints surface there rather than in a
contributor's PR.

### 6. Fuzz (`cargo-fuzz`)

`crates/core/fuzz` is an isolated nightly sub-workspace, excluded from the stable
`--workspace` gates. Eleven targets fuzz the untrusted-input parsers: `crypt4gh_header`,
`crypt4gh_body`, `tar_extract`, `vcf_convert`, `parquet_validate`, `manifest_gate`,
`boot_state`, `package_yaml`, `beacon_request`, `beacon_classify` and `popfield`.

Four go beyond a bare parser. `crypt4gh_body` reaches the 64 KiB segment and AEAD decoder
past the header, fed a valid header so a session key is recovered. `manifest_gate` runs the
node ingest trust-gate validators (id, enum, IRI, assembly) on top of the serde parse.
`boot_state` covers the on-disk and reconcile state-file decoders: `.status.json`, overlays
and sidecars. `beacon_classify` drives the coordinate span and window arithmetic.

**Fuzz to regression pipeline:** when a fuzzer finds a crash, its minimized artifact is
committed as a regression fixture under `crates/core/tests/fixtures/malformed/`, for example
`fuzz_crash_82778894.parquet`, and asserted by a unit test, so that input stays guarded
outside a fuzz run.

- **Run** `cargo +nightly fuzz run <target>` by hand. Nothing fuzzes on a per-change gate:
  a time-boxed weekly `fuzz` job is declared in `scheduled.yml`, and `all` carries only
  `ci-local.sh fuzz-smoke`, which compile-checks the targets against the current library
  API and does not fuzz. There is a second local leg that does: `ci-local.sh fuzz-short`
  runs every target for `FUZZ_SECONDS` (default 10s) each, and it is in the `release`
  meta-leg, so a tag does fuzz briefly.

### 7. Bench (criterion, advisory)

Eight `criterion` benches (`harness = false`): `core/benches/` has convert, parquet_read,
crypt4gh, hydrate and zstd_level; `beacon/benches/` has query_assembly and scan_dataset;
`fairdp/benches/` has render, covering Turtle and JSON-LD RDF serialization. They gate
nothing and nothing runs them automatically: a weekly `benches` job is declared in
`scheduled.yml`, and no `ci-local.sh` leg invokes `cargo bench`.

The service's ingest orchestration and the tool's `pack` throughput are not benched. Their
CPU-bound inner loops (`convert`, `crypt4gh`, `parquet`) are, and a service or tool bench
would mostly measure tokio scheduling and I/O, which criterion measures poorly. fairdp
render is CPU work on the `/fairdp` request path, so it earns one. Add a targeted bench
only when a specific perf question demands it.

- **Run** `cargo bench -p gdi-node-standalone-core -p gdi-node-standalone-beacon -p gdi-node-standalone-fairdp`.
  Not `--features full`: all eight benches live in those three crates, and `full` is declared
  only by `gdi-node-standalone`, which has no `benches/` directory, so the flag changes
  nothing about what is benchmarked.

### 8. Guard (drift guards)

Executable invariants about the repo itself, so docs, config and dashboards cannot
silently drift from code:

- `config_examples` — the example TOMLs parse and match the defaults.
- `api_doc_routes` — `docs/api.md` matches the router.
- The Grafana dashboard check (`scripts/check-dashboard-metrics.py`) — every charted or
  alerted series exists and is documented, plus the presentation invariants: no overlapping
  panels, one unit per axis, stat tiles reduce rather than draw every sample, an alert named
  in a title is charted by that panel, and the disk tile's step is the `LowDisk` margin.
- `instrument-guard` — no auto-capturing `#[instrument]` on the serving path, a
  trace-privacy invariant.
- `vendored-sync` — the vendored conformance files are byte-identical to their upstream
  pins. It needs the network, so it is a weekly job rather than part of `all`.
- `bundled_sample` — the README quickstart's sample dataset stays byte-identical to the
  canonical `test-util` fixture.

Two lighter config-drift guards run locally in `all`. `vendored-files` checks each set's
on-disk file count against its `VENDORED.md` `**Files:**`, catching a locally deleted shape
the byte-check cannot see. `workflow-tool-pins` checks that install-action `tool:` version
pins agree across `ci.yml`, `release.yml` and `scheduled.yml`; the `ci.yml` actionlint job
invokes the same target.

Those two are an internal-consistency check. The `pins` leg adds the external half for
actions: each `uses: owner/repo@<sha> # <tag>` still resolves upstream to the tag its
comment names, since SHA-pinning buys immutability but not provenance, and a SHA that is
not that version would otherwise read as reviewed. It needs the network, so drift is a
warning there and fatal under `pins-strict`/`release`; a comment naming a branch (`stable`)
is existence-checked only, because a branch head moves by design. Its network-free half,
`scripts/tests/test_action_pin_comments.py`, asserts that every pinned `uses:` carries a
comment: the upstream check enumerates on that comment, so an uncommented pin would not be
flagged, merely unchecked.

`cargo-semver-checks` (public library API) belongs in this list but is not enforced: it is
in neither meta-leg, because its default baseline is HEAD. Now that `v1.0.0-rc.1` exists,
run it against that tag by hand:
`SEMVER_BASELINE=v1.0.0-rc.1 ./scripts/ci-local.sh semver-checks`.

### Out-of-process

- `scripts/e2e/run.sh` — Compose-stack lite e2e (build+pack a fixture → inbox → query →
  FDP crawl → publish/unpublish); wrapped by `ci-local.sh e2e`. `scripts/e2e/run-full.sh` —
  the full Garage + OpenBao + PME crypt4gh round-trip; wrapped by `ci-local.sh e2e-full`
  (and pulled into the `release` meta-leg). Its step 10 also runs the three
  **real-endpoint smokes** below, which are the only tests in the repo that touch a real
  S3 service and a real KV-v2 + Transit engine rather than `InMemory` and a wiremock.
- `scripts/load/run.sh` — `oha` HTTP load harness; hard-fails only on a load-shed
  regression (throughput numbers are advisory). Wrapped by `ci-local.sh load`, and with
  `soak` and `crash-loop` by the `harness` meta-leg, but in no gate: each boots its own
  node and costs minutes, so they are run on demand rather than per change.
- `scripts/soak/leak.sh` (+ `checks.py`) — endurance/leak soak: samples the node process's
  RSS / open-fds / thread count across request rounds and asserts a plateau, not a
  sustained climb (distinguishes a leak from healthy cache fill).

  **Know which load you soaked.** The default profile drives one single-position query at
  8 clients against the one-variant COVID fixture, a page of one row, and settles within a
  few MiB. That is a fine leak detector and a poor model of the load
  [`deployment.md`'s resource baseline](deployment.md#resource-baseline) reports, where 32
  clients pulling 1000-row pages reach roughly 1 GiB and keep about 920 MiB after the load
  stops. The trend check is the same either way; only the regime differs, so a green
  default run says nothing about the heavy one. `SOAK_PACKAGE`, `SOAK_QUERY` and
  `SOAK_PROBE_MATCH` switch profiles. The script header carries a ready-made heavy
  invocation over the realistic sample. Overriding the query without the probe match is
  refused rather than silently soaking a zero-result path.

  `scripts/soak/crash-loop.sh` — SIGKILLs the node at jittered moments across cycles (real
  `kill -9`, no unwinding) and asserts the store converges on restart: kept dataset served,
  deleted dataset erased with no `.deleting` marker, no orphan `.incoming`.
- `scripts/chaos/run.sh` (+ `docker-compose.chaos.yml`) — real-dependency S3/Vault chaos: a
  toxiproxy sidecar injects latency / connection-reset / timeout on the wire between the
  node and Garage/OpenBao; asserts the node degrades gracefully and recovers or fails
  closed. On-demand (needs the e2e image build).
- `ci-local.sh image-scan` — `docker build` the shipped image + `trivy image` its base
  layer; fails on a fixable HIGH/CRITICAL CVE (in `release`).
- `ci-local.sh licenses` — regenerate the `cargo-about` attribution bundle and diff it
  against the committed `THIRD-PARTY-LICENSES.md`; fails on drift (in `release`).
- `ci-local.sh coverage` — `cargo-llvm-cov` summary (advisory, no floor) **plus the
  zero-coverage guard, which is not advisory and fails on a file the suite never enters**.
  Runs in `release`; out of `all` only because it is slow.

#### The three real-endpoint smokes

`real_endpoint_round_trip` (S3), `real_vault_kv_and_transit_round_trip` (KV v2 + Transit)
and `real_openbao_pme_round_trip` (PME at rest) live in the service `tests/it` under
`--features full`. They carry a **double gate**: `#[ignore]`, plus an early return when
their endpoint env var is unset — so `--ignored` without a backend does not fail.

That second gate can produce a false green: a runner that boots a backend and then skips
the smoke reports a pass for nothing. `run-full.sh` boots exactly the backends they need,
points them at it, and exports `GDI_TEST_REQUIRED=1`, which turns the skip into a panic in
`test_util::endpoint_env`.

Three of the values must be overridden for a real deployment:

| Var | Hand-rolled-dev default | Compose stack |
| --- | --- | --- |
| `GDI_TEST_S3_REGION` | unset | `garage` — Garage validates its `s3_region` inside the SigV4 signature, so the default region cannot authenticate at all |
| `GDI_TEST_VAULT_KV_PATH` | `gdi/c4gh` | `gdi-node-standalone/c4gh-identities` (`compose/node.full.toml`) |
| `GDI_TEST_TRANSIT_KEY` | `gdi-at-rest` | `gdi-node-standalone-at-rest` (`compose/setup.sh`) |

The S3 smoke gets its **own** bucket (`gdi-smoke`, minted by a one-off `<backend>-setup`
run), never the node's `gdi-datasets`: it seeds package and `_status/` objects, and a
running node reconciles and writes status into whatever it monitors, so one shared bucket
would race the node for those keys.

---

## Shared fixtures

Shared test data lives in one place, the dev-only `test-util` crate, behind a small API, so
a fixture change is one edit. `test-util` is also the one place `unsafe` is allowed, for the
`std::env` mutators. It does not opt out of the workspace lints: the policy is
`unsafe_code = "deny"` rather than `forbid`, so this crate inherits the whole lint set and
scopes its exemption with a self-expiring `#[expect(unsafe_code, reason = "…")]` on the item
itself.

| Item | Use |
| --- | --- |
| `test_util::covid_vcf_bytes()` / `covid_chr7_vcf_bytes()` | canonical COVID VCF bytes |
| `test_util::covid_vcf_path()` | stable read-only path to the canonical VCF |
| `test_util::write_covid_vcf(dir)` | materialize the VCF into a caller tempdir |
| `test_util::covid_package_yaml()` | canonical `covid-package.yaml` text |
| `test_util::write_covid_package(dir)` | materialize package.yaml + VCF into a caller tempdir |
| `test_util::covid::{TOTAL_AC, TOTAL_AN, FI_M_AC, FI_M_AF}` | the fixture's expected magic numbers, defined in one place for assertions |
| `test_util::reference_contig_sets()` | every contig label of six published reference sets (GRCh38 analysis set 3 366, `hs37d5` 86, UCSC hg38 455 / hg19 93, Ensembl GRCh38 toplevel 706 / GRCh37 primary 84) — `core::chrom` sweeps them all so no label a whole-genome VCF can carry is an error |
| `test_util::sample_vcf_path()` / `sample_expected_json()` / `sample_package_yaml()` / `write_sample_package(dir)` | the realistic sample below: the VCF, the generator's ground-truth aggregates, and a `--strict`-clean package for it |
| `test_util::set_env` / `remove_env` | the only sanctioned env mutators; callers must carry `#[serial(env)]`, enforced by the guard below |
| `test_util::CaptureWriter` | in-memory sink for capturing `tracing` output in tests |

`test_util::global_state_mutators_carry_their_serial_key` walks `crates/` and fails if a
`#[test]` calls an env mutator without `#[serial(env)]`, or arms a `core::faults` point
without `#[serial(faults)]`. `serial_test` keys locks by name, so a bare `#[serial]` is a
different lock that excludes neither. The race is inert under nextest, which runs a process
per test, and real under a plain `cargo test`.

The README quickstart's bundled sample in `gdi-dataset-tool/tests/fixtures/` is a second
on-disk copy of the VCF and package, kept as a user-facing runnable example. The
`bundled_sample` guard keeps it byte-identical to the canonical `test-util` copy.

### The realistic sample

The COVID fixture has one record, so nothing in the hand-written fixtures looks like a
provider's export. `crates/test-util/tests/fixtures/sample/` holds one that does.
`gdi-sample.GRCh38.vcf.gz` is a BGZF file of about 490 KB holding 1 637 sites over chr21, X,
Y and M, in the shape a `bcftools +fill-tags -S groups` sites-only chain produces: twelve
populations (`Total`, `EE`, `FI`, `LV`, `M`, `F` and their products),
`AC_Hom`/`AC_Het`/`AC_Hemi` partitions, hemizygous male X outside the PAR and Y, haploid M,
`AF=.` where a stratum has `AN=0`, split multi-allelic rows sharing one set of calls, a
rare-heavy spectrum with a few monomorphic sites, the caller's annotations and the bcftools
provenance header. The chr21 positions, alleles, rsIDs and per-ancestry base frequencies come
from a gnomAD v4.1 corpus slice, released for use without restriction under the
[gnomAD Terms of Use](https://gnomad.broadinstitute.org/terms) — not CC0, so do not label it
as such. Every count is simulated from those base frequencies, so no individual's data is
present and the published numbers are not gnomAD's.

It is generated, not hand-edited. `scripts/gen-sample-vcf.py generate` writes it from the
committed `sites.tsv.gz` and the script's pinned `DEFAULT_SEED`, together with
`gdi-sample.expected.json`, the aggregates the converter must report. Two guards bind the
four files. `scripts/tests/test_gen_sample_vcf.py` regenerates and compares decompressed
text, so the zlib build does not matter, and checks every record's coherence in plain Python.
`crates/core/tests/sample_fixture.rs` runs `preview` and `convert`, asserts the sidecar's
numbers, twelve populations, no ignored field and no warning, and parses
`gdi-sample.package.yaml` the way `build` does, asserting it validates `--strict`-clean and
that its `numberOfUniqueIndividuals` equals the sidecar's `individuals`. To change the
sample, change the script or the site list and regenerate; a hand-edited fixture fails the
first guard. `select`, the step that built the site list, needs the corpus slice from
`scripts/fetch-corpus.sh` and is not part of any gate.

The same script scales to a whole-genome export for sizing and load work.
`scripts/gen-sample-vcf.py generate --synthetic-sites 10000000 --out big.vcf.gz` needs no
site list: it spreads the sites over every GRCh38 contig in proportion to length (plus a
sparse Y and a few on M), streams BGZF to disk in fixed chunks simulated in parallel
(`--jobs`), and writes the same file whatever the job count. Above `HWE_EXACT_MAX_RARE`
rare alleles the Hardy-Weinberg fields come from the asymptotic test rather than the exact
one, which is what bounds the per-site cost; the converter never reads them.

## Running the suite

The runner and its targets are documented in
[`CONTRIBUTING.md` § Local validation pipeline](../CONTRIBUTING.md#local-validation-pipeline):
which target to run when (`quick`, `all`, `release`), which of them the GitHub workflows
share, and why `ci-local.sh` is the gate rather than a mirror of one. This section covers
only what is specific to the test suite.

One target belongs here rather than there: `coverage`, which runs `cargo-llvm-cov` over
`--features full`. Its percentage summary is advisory and enforces no floor, but the leg as
a whole is not: it also runs the zero-coverage guard, which fails on any file the suite never
enters. `release` runs it for that half, and `all` omits it because it is slow. Run it on
demand to see what a change leaves unexercised.

Tests run under `cargo nextest`, which isolates each test in its own process.
`.config/nextest.toml` defines three profiles: `default` for local runs; `ci`, which emits
JUnit and disables fail-fast, selected by `ci-local.sh` when `CI=1`; and `quick`, which sets
only `fail-fast = true`. `quick` applies no filter and inherits `default`'s `heavy`
overrides and `slow-timeout`, because a profile's own `overrides` are additive rather than
suppressing, so it runs the same set under the same concurrency cap and merely stops
earlier. `ci-local.sh quick` is an unrelated gate target that shares the name.

A `heavy` test group caps the concurrency of the `s3_reconcile`, `vault_precedence` and
`pme_roundtrip` suites so they do not contend for sockets and mock backends. It is a
resource cap, and for two of those three it is the only concurrency control:
`vault_precedence` and `pme_roundtrip` carry no `#[serial]`, and almost none of the
`s3_reconcile` tests do. That is sound, because they use per-test `wiremock` ports and
`object_store::InMemory` and share no state, but it means the cap does not hold under a
plain `cargo test`, which ignores nextest groups.

`#[serial]` remains the correctness mechanism for genuinely global state, and it is keyed:
`#[serial(env)]` for `test_util::set_env` and `remove_env` callers, `#[serial(faults)]` for
`core::faults` arms. Those are different locks and a bare `#[serial]` excludes neither, so
`test_util::global_state_mutators_carry_their_serial_key` enforces the pairing.

Doctests run separately (`cargo test --doc`), as nextest does not run them.

While iterating, scope to what you changed: `cargo nextest run -p <crate> --test it
<module>::`, adding `--features <feat>` for a feature-gated suite.

## Kept on purpose

These look like duplication and are not. Do not consolidate them away.

- **A `proptest` and a fuzz target over the same parser.** A property test asserts an
  invariant; a fuzz target asserts that nothing crashes. Different guarantees.
- **Security last-guards.** The last test guarding a disclosure-control or crypto property
  (k-anonymity suppression, crypt4gh, tar-extraction containment, ingest validation) is never
  removed, even where it overlaps another layer. Where the service and a library both guard a
  k-anonymity property, one at the logic layer and one at the wire, both stay.
- **Full-document conformance snapshots.** The `beacon_info__*` and RDF goldens pin the whole
  GA4GH- or FDP-shaped document. A model change that churns them is the guard firing, so they
  are not collapsed to field assertions.
- **The `#[ignore]` real-endpoint smokes.** They cost nothing in the default run and are the
  only in-repo check of the real backends. `scripts/e2e/run-full.sh` exports the `GDI_TEST_*`
  contract once Garage and OpenBao are healthy and runs each one by name with a `1 passed`
  assertion, and `GDI_TEST_REQUIRED=1` turns their env-absent early return into a hard
  failure. Both halves matter: a name filter that matches nothing exits 0, and a silent skip
  reports green having connected to nothing.
- **Per-test granularity.** Merge tests into a table-driven loop only when a family is
  genuinely one case per variant and the loop reduces code. Parametrizing compact,
  heterogeneous tests adds complexity without benefit.

## Adding a test — quick guide

- A **function's logic**: a unit test in its `src/` module.
- An **invariant over generated inputs**: a `proptest`, inline for a unit invariant and in
  `tests/` for a system property.
- **HTTP or cross-module wiring**: a module in the crate's `tests/it/`.
- A **library property** such as query math, RDF rendering or crypto: put it in the library
  crate (`beacon`, `fairdp`, `core`) rather than the service. Use a `src/` unit test if it
  needs internals, else the library's `tests/`.
- An **exact output document**: an `insta` snapshot in `tests/snapshots/`.
- **A parser against untrusted input**: a `cargo-fuzz` target, plus any crash committed as a
  `tests/fixtures/malformed/` regression.
