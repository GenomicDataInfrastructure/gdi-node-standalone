# Contributing to `gdi-node-standalone`

A Rust workspace: a GA4GH Beacon and a FAIR Data Point in one service binary, and the data
provider's dataset tool beside it. This guide is what you need to change it; the
[README](README.md) covers running it, and [docs/testing.md](docs/testing.md) the test
suite. One rule above all others: `scripts/ci-local.sh all` is the gate, and nothing else
runs it for you.

The node is published but not in active use, and nobody is on call for it (the README says
so up front), so a pull request may wait; a green gate is what lets it be merged quickly
when someone does look. Found a bug? Open an issue with the command you ran, its output,
and the binary's `--version`.

| You want to | Read |
| --- | --- |
| build it and run the tests | [Prerequisites and toolchain](#prerequisites-and-toolchain), then [Checking a change](#checking-a-change) |
| fix a bug or add a feature | those two, [Code style and conventions](#code-style-and-conventions), [Conventional Commits](#conventional-commits), [Before you open a PR](#before-you-open-a-pr) |
| add a config knob | [Adding a config field](#adding-a-config-field) |
| bump or add a dependency | [Dependencies and `Cargo.lock`](#dependencies-and-cargolock), [MSRV policy](#msrv-policy) |
| understand the crates and the lite/full split | [Project layout](#project-layout), [Build profiles](#build-profiles) |
| cut a release (maintainers) | [Cutting a release](#cutting-a-release), [Branch protection](#branch-protection) |

## Getting the source

```bash
git clone https://github.com/GenomicDataInfrastructure/gdi-node-standalone.git   # or your fork, with this URL as `upstream`
cd gdi-node-standalone
git switch -c <short-branch-name>
scripts/dev-setup.sh        # checks the toolchain, offers the pre-commit hook and the build speedups
```

Open pull requests against `main`. Everything here applies from a fork too, except
[cutting a release](#cutting-a-release), [branch protection](#branch-protection) and the
`full-e2e` PR label, which needs triage rights.

## Prerequisites and toolchain

Building, testing and committing need `git`, `curl`, `python3` and a C toolchain
(`build-essential`, `gcc`, or the Xcode Command Line Tools): every crate compiles at least
one C build script, and the pre-commit hook runs Python. `scripts/dev-setup.sh --check`
reports what is missing; without the flag it also offers to install the hook and the
[build speedups](#faster-local-builds).

Install rustup with no default toolchain. `rust-toolchain.toml` pins the channel and the
components, and rustup installs that toolchain the first time you run `cargo` in the
checkout, so a default `stable` would only be a second download:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none
```

That pin is the compiler you develop and lint with; the Dockerfile's `FROM rust:` builder
must match it, and the gate checks that they agree. The other version in the tree, the
minimum supported Rust version or MSRV `1.96`, is the floor the crates must still compile
on, and moves on its own rules: see [MSRV policy](#msrv-policy).

The full gate, `scripts/ci-local.sh all`, is a sequence of *legs*, one check each. It
needs more tools, and checks that each is installed before any leg runs:

- `cargo-deny`, `cargo-machete` and `cargo-cyclonedx` (`cargo install <tool> --locked`)
  for the advisory, unused-dependency and SBOM legs;
- `gitleaks`, at or above the version `ci-local.sh` names in `GITLEAKS_MIN_VERSION`: an
  older rule set reports clean on findings it cannot see;
- `uv`, which runs the pinned `ruff` and `reuse` through `uvx` and is the only supported
  way to regenerate the `conformance/*.lock` hash-locks;
- `python3` from 3.12 up, with PyYAML importable for the `k8s-manifests` leg. PyYAML is not
  preflighted, so a missing one fails partway through `all`. Put it in a virtualenv, since
  the system `pip` refuses on Debian, Ubuntu and Fedora, and run the gate from that shell:
  `uv venv && . .venv/bin/activate && uv pip install -r scripts/tests/k8s/requirements.lock --require-hashes`.
  The conformance and crypt4gh legs build their own venvs under `target/venv/` on the
  `.python-version` pin; `GDI_FDP_PYTHON` and `C4GH_VENV` point them at interpreters you
  already have.

`cargo-nextest` is not checked, but you want it: it runs every test in its own process,
which the suite needs because many tests mutate the process environment, and without it
the gate falls back to a single-threaded `cargo test` and says so. A prebuilt binary
(`cargo binstall cargo-nextest`, or the
[nextest releases](https://github.com/nextest-rs/nextest/releases)) is much quicker than
`cargo install`.

Optional: `cargo-insta` to review a moved `insta` golden
([docs/testing.md § Snapshot](docs/testing.md#4-snapshot--golden-insta)), and
`cargo-llvm-cov`, `cross` and nightly `cargo-fuzz` for the release-tier and scheduled legs.

### Faster local builds

`mold` and unpacked debuginfo cut relink time on the large test binaries. When `mold` is
installed (it needs gcc 12 or newer), `scripts/dev-setup.sh` offers to write this to the
user-level `~/.cargo/config.toml`:

```toml
[target.x86_64-unknown-linux-gnu]
rustflags = ["-C", "link-arg=-fuse-ld=mold"]

[profile.dev]
split-debuginfo = "unpacked"
```

It stays at user level rather than in the repository: a linker override in the tree would
break anyone without `mold`, and a gitignored `.cargo/config.toml` is absent from every
worktree. Adding or removing either line forces one full rebuild per `target/`, so do it
with no gate in flight. `unpacked` leaves DWARF in the object files; backtraces keep
`file:line` as long as `target/` is intact.

## Project layout

A Cargo workspace (`resolver = "3"`, edition 2024) of seven crates:

| Path | Crate | What it is |
| --- | --- | --- |
| `crates/core` | `gdi-node-standalone-core` | VCF→Parquet conversion, the config and manifest types, the crypt4gh codec, TAR packaging, shared validation |
| `crates/beacon` | `gdi-node-standalone-beacon` | Beacon query execution over Parquet |
| `crates/fairdp` | `gdi-node-standalone-fairdp` | FAIR Data Point RDF, as Turtle and JSON-LD |
| `crates/gdi-node-standalone` | `gdi-node-standalone` | the service binary: Beacon and FDP endpoints, inbox reconcile, and S3/Vault/PME when built `full` |
| `crates/gdi-dataset-tool` | `gdi-dataset-tool` | the provider CLI: the wizard, `build`, `validate`, `pack`, `upload`, `deploy`, `publish` |
| `crates/build-info` | `gdi-build-info` | `GIT_SHA` and `BUILD_EPOCH` at compile time, so `--version`, `GET /version` and the `gdi_build_info` metric agree |
| `crates/test-util` | `test-util` | dev-only test helpers, and the one audited home for the `unsafe` env mutators tests need |

The libraries are `publish = false` and used only inside the workspace, so the compiler
catches any breaking change to their APIs. `crates/core/fuzz` is its own workspace,
excluded from this one, with its own `Cargo.lock`, so `--workspace` commands never build
it. Fuzzing itself needs `cargo +nightly fuzz`; the `fuzz-smoke` and `deny-fuzz` legs
compile-check and advisory-scan it on the pinned stable toolchain.

## Build profiles

S3, Vault and at-rest Parquet Modular Encryption (PME) are compile-time features of the
service crate. A bare `cargo build` is the **lite** node: no S3, no Vault, no PME, no
`ring`, no outbound connection. `--features full` is the shipped, networked binary. The
dataset tool is always networked and has no feature gates.

| Feature | What it adds |
| --- | --- |
| `s3` | bucket polling (`[[s3.buckets]]`): `object_store` and its `reqwest` stack |
| `vault` | the Vault KV and Transit client (`[vault]`); without it, secrets come from local `[keys]` files |
| `pme` | Parquet Modular Encryption at rest; implies `vault`, and turns on `parquet/encryption` in `core` and `beacon` |
| `tls` | internal, shared by `s3` and `vault`: `rustls` on the `ring` provider, with bundled Mozilla roots so a static binary verifies TLS without an OS CA bundle |
| `full` | `s3` + `vault` + `pme` |
| `otel` | OTLP trace and metric export, a diagnostic; not part of `full`, never shipped |

What the profiles guarantee, and what checks it:

- **lite** links no `ring`; the `graph` leg asserts that `cargo tree --no-default-features
  -i ring` finds nothing. It still links the C `zstd` codec, so it is not pure Rust.
  crypt4gh is a pure-Rust codec, so a lite node still ingests `.tar.c4gh` packages with a
  local `[keys]` identity.
- **full** links exactly one crypto library, `ring`, statically, because it cross-compiles
  and links to musl cleanly. `deny.toml` bans `aws-lc-rs` and `aws-lc-sys`, and the `graph`
  leg asserts `aws-lc-sys` is absent from the full and s3 graphs.
- **`--features s3` alone** is the common public-data shape: S3 ingest with a file-based
  `[keys]` identity and none of the Vault or PME code. It is linted, tested and
  graph-checked, but not released; the shipped `full` binary with `[vault]` omitted
  behaves the same.

A config section whose feature is not compiled in is refused at startup with a "rebuild
with `--features …`" error, never ignored.

```bash
cargo build                               # lite
cargo build --features full               # the shipped binary
cargo build --features s3                 # one capability; `vault` and `pme` likewise (pme implies vault)
cargo build --release --features full     # release profile: thin LTO, codegen-units = 1, symbols stripped
```

## Checking a change

While iterating, scope to what you changed: `cargo check -p <crate>`, and
`cargo nextest run -p <crate> --test it <module>::` for one test module
(`--features <feat>` for a gated suite). Before you call a change done, run
`scripts/ci-local.sh`, which groups the legs into targets:

```bash
scripts/ci-local.sh quick      # what the pre-commit hook runs: fmt + lite clippy + the scripts' unit suite
scripts/ci-local.sh lint       # every lint, no tests: adds full-profile clippy and ruff
scripts/ci-local.sh all        # the per-change gate; run it before you push
scripts/ci-local.sh release    # the tag-time gate: `all` plus the Docker and cross legs
scripts/ci-local.sh help       # every target and leg, what it runs, and in what order
```

`ci-local.sh` is the gate, not a mirror of one: most CI jobs call it, and the legs CI does
not run (the `release` tier) are the ones whose failures surface late and expensively if
you skip them. `all` works without Docker; its two Docker legs, `promtool` and
`shellcheck`, print `SKIPPED`, and no green marker is recorded. `release` refuses the
skip. The only checks with no local counterpart are the macOS and Windows tool builds, two
small guards that live inline in the `actionlint` job, and the release job's attestation
and GHCR publish.

A rename that spans code, config, docs and Compose is caught by the seam guards in
`crates/gdi-node-standalone/tests/it/seams.rs`; `scripts/ci-local.sh seams` runs just
those. The kinds of tests, where each lives and how to add one are in
[docs/testing.md](docs/testing.md).

**Do not edit the tree while a gate runs.** `cargo` compiles the dependency graph for
minutes before it reaches the workspace crates, so an edit landing mid-run is compiled
into a mix of before and after, and the failure it reports is an artifact.

**Worktrees.** Create one with `git worktree add .worktrees/<name> -b <branch> origin/main`;
in a clone with no remote that fails with `fatal: Needed a single revision`, so branch
from `HEAD` instead. Keep them under `.worktrees/`, which `.gitleaks.toml` tells the parent
checkout's `secrets` leg to skip, and run the gate from inside the worktree before
merging. Give each worktree its own `target/`; never share `CARGO_TARGET_DIR`. Two things
are shared across worktrees: the [build speedups](#faster-local-builds), which live in the
user-level cargo config, and the [one gate slot](#one-gate-per-machine).

### The pre-commit hook

Git cannot install hooks from the repository, so once per clone:

```bash
git config core.hooksPath .githooks      # or let scripts/dev-setup.sh do it
```

The hook always runs the doc-attachment check and rustfmt. It runs lite clippy at
`-D warnings` only when a staged file can change a clippy result (Rust, `Cargo.*`,
`clippy.toml`, `rust-toolchain.toml`, `.cargo/config.toml`), because a full clippy takes
minutes and most commits are docs, YAML or shell. The skip is soft: a wrongly skipped lint
surfaces at `ci-local.sh all`. Depending on what else is staged it also runs:

- full-profile clippy, when staged Rust carries a `#[cfg(feature = …)]` gate, since lite
  clippy never compiles gated code;
- the gate's own unit suite, for a staged `scripts/` or `.githooks/` path or `ruff.toml`;
- the `ruff` leg, for staged Python or `ruff.toml`, the one path that needs network;
- `fuzz-smoke`, the `--locked` compile-check of the fuzz workspace, for a staged
  `Cargo.toml` or `Cargo.lock`. When it fails, relock with
  `cargo check --manifest-path crates/core/fuzz/Cargo.toml --bins`.

A missing `uv` warns rather than blocks. `git commit --no-verify` is the escape for a
work-in-progress commit. `scripts/tests/test_pre_commit_hook.py` pins the exact patterns.

### Running `all`

It takes many minutes, longer on a cold tree. Start it in the background and carry on.

A green run records a key of the tree and the toolchain in `target/.gate-ok`, and the next
`all` on an identical tree within `GATE_TTL_HOURS` re-runs only the legs whose verdict can
change on its own, `secrets` and the advisory scans, so a cached green never masks a fresh
CVE. A tree that changed mid-run prints `NOT RECORDED`, and the next run is full. The key
is content, not mtime, so a `touch` does not invalidate it. `GATE_FORCE=1` runs everything
regardless. `scripts/gate-key.sh` says what the key covers and what it cannot see.

### One gate per machine

Two gates at once thrash a machine, so the heavy targets (`all`, `release`, and the
compiling and whole-suite legs) take one machine-wide lock, shared by the checkout and
every worktree. A waiting run says who holds it, prints a heartbeat every minute, and
reports the time it queued beside the leg timings. `quick`, `lint`, the clippy legs and
everything the hook runs never wait. `GATE_QUEUE=0` skips the lock when you know the
machine is idle.

Do not `nice` a gate: a niced gate starves beside any nice-0 load. Kill one by process
group (`kill -TERM -- -<pgid>`), so an orphaned `cargo` does not keep the lock.

### Keeping `target/` in check

`target/` holds a separate artifact set per toolchain and feature set, and reaches tens of
GB. `scripts/ci-local.sh sweep` reclaims it: `cargo-sweep --installed`, then `--maxsize`
(default 20GB). `SWEEP_MAXSIZE` must carry a unit, since `cargo sweep` reads a bare number
as megabytes.

### CI

GitHub Actions: `ci.yml` on pull requests and on pushes to `main` and `v*` tags;
`release.yml` on a `v*` tag; `scheduled.yml` weekly (Mondays 06:00 UTC) and `e2e-full.yml`
three hours later, both also on demand. `ci-success` is the one job every other job feeds,
and the only status check branch protection requires, so a new gate becomes required by
being added.

Most `ci.yml` jobs call `ci-local.sh` targets (`lint` is `quick`; a few run two or three),
so `help` is their documentation. Five of them (`sbom`, `conformance`, `crypt4gh-interop`,
`cross-compile`, `e2e-smoke`) and most weekly jobs restate their commands inline, so edit
both sides when you change one. Every Action is pinned to a commit SHA with the version in
a trailing comment; Dependabot version updates are off (security updates still run), so
bumps are by hand, and the weekly `pins` job checks each SHA against its comment.

These workflows first ran at publication, and some legs have run only a few times. Treat
an early red as a possible pipeline defect and report it rather than work around it.

### Weekly and on-demand jobs

`scheduled.yml` runs what is too slow or too advisory for a pull request:

- fuzzing, benches, and the load and soak harnesses;
- a fresh RustSec scan, vendored-file drift, and `pins`, which checks the tree's external
  pins (Action SHAs, the beacon-v2 release, the vendored gdi-metadata shapes, the
  distroless digest) against upstream;
- coverage, advisory there (the local `coverage` leg adds the zero-coverage guard), the
  image scan, the attribution-bundle check, and a `stable` canary;
- the aarch64 and macOS/Windows builds, and the real-data `corpus` run.

Nearly all have a local counterpart, a `ci-local.sh` target or a script under `scripts/`;
the macOS and Windows builds do not. A failed run opens or updates one tracking issue.

`e2e-full.yml` is the full Garage + OpenBao + PME round-trip and the toxiproxy chaos run,
weekly and on a PR labelled `full-e2e`. Apply the label to a change touching the
crypt4gh-ingest, at-rest-encryption or S3 path. Labelling needs triage rights, so from a
fork say so in the PR and ask a maintainer, or run `ci-local.sh e2e-full` yourself.

`pins` and `vendored-sync` need network, and `pins` spends the unauthenticated GitHub API
budget, so export `GITHUB_TOKEN` for it (sent to `api.github.com` only). Drift warns in a
working tree and fails under `PINS_STRICT=1`, which `release` and the weekly job set.
`licenses` is not in `all`, because it needs `cargo-about`, so a green `all` can leave
`THIRD-PARTY-LICENSES.md` stale after a dependency bump; run `ci-local.sh licenses` after
touching dependencies.

### Mutation testing

`scripts/mutants-audit.sh` runs `cargo-mutants` on demand: the whole workspace (hours), one
package (`-p`), or one file (`-f`). A surviving mutant is usually a missing assertion, and
the test that closes it carries the protection from then on, which is why nothing
schedules it. The script's header covers its traps and what it cannot see.

## MSRV policy

MSRV `1.96` is declared once, as `rust-version = "1.96"` in `[workspace.package]`, and
inherited by every crate. It is a ratchet, separate from the toolchain pin: raised only
when a dependency the code needs (dev-dependencies included) or a language feature it
needs requires it, never lowered, and never "the pin minus one".

The number governs more than which compiler builds the tree. With `resolver = "3"` it
steers `cargo update`, which prefers the newest release of each dependency compatible with
the floor and reports the rest as "N unchanged dependencies behind latest" (`cargo update
--verbose` names them). Clippy reads it too, and suggests no API newer than the floor. So
the floor is a statement about the dependency graph and the code, not a promise to a
compiler someone has installed.

The `msrv` leg runs `cargo +1.96.0 check --workspace --all-targets --locked`, lite and
full, installing that toolchain first if it is absent. `--all-targets` is what makes
dev-dependencies count. It pins the earliest patch rather than the two-component channel,
which rustup would resolve to the newest patch in the series, a compiler newer than the
claim; and it asserts that the `rustc` that ran is that patch. A dependency whose own
`rust-version` is above the floor fails this leg, and that is the ratchet's trigger: raise
the floor or hold the dependency. To check a bump locally, run `scripts/ci-local.sh msrv`.

To raise the MSRV, change `rust-version` in `[workspace.package]`, in one commit, and say
so in the PR. `ci-local.sh` reads the value from `Cargo.toml`, and
`scripts/tests/test_msrv_prose_bound.py` fails on any restatement in prose (here, in
`README.md`, in `docs/deployment.md` and elsewhere) that disagrees.

## Code style and conventions

Lint policy is the `[workspace.lints]` table in the root `Cargo.toml`, inherited by every
crate, so a bare `cargo clippy` enforces what the gate does: `clippy::all` and
`clippy::pedantic` at `warn`, promoted to errors by the gate's `-D warnings`; a noisy
pedantic lint may be turned off there, one at a time and with a reason. The rules a
reviewer will hold you to:

- **No `unsafe`.** `unsafe_code = "deny"` everywhere. The one exception is `test-util`,
  the audited home of the `unsafe` `std::env::set_var`/`remove_var` that Rust 2024
  requires: tests call `test_util::set_env`/`remove_env`, never `std::env`, and a test
  fails on an allow or expect of that lint anywhere else. If you think you need
  `unsafe`, raise it in the PR first; the default answer is no.
- **No `.unwrap()` or `.expect()` in library code** (`clippy::unwrap_used`). `Result`
  and `?`; `thiserror` in libraries, `anyhow` in binaries. Tests may unwrap.
- **Suppress with `#[expect(clippy::…, reason = "…")]`, never `#[allow]`**, and only once
  fixing the root cause is ruled out. A stale `expect` warns, so suppressions cannot
  linger.
- **`cargo fmt` at rustfmt defaults.** Imports grouped `std`, external, internal; wildcard
  imports only as `use super::*` in test modules.
- **Async:** cancellation-safe tasks, especially in `tokio::select!`; no sync I/O or heavy
  CPU on the executor; no non-`Send` value held across an `.await`.
- **`tracing`, not `println!`,** in library code.
- **`///` on every public API**, with `# Errors` and `# Panics`; doc examples compile and
  run.
- **No placeholders:** no `todo!()`, `unimplemented!()`, `// TODO` or elided blocks.
  Write complete, compilable code.

### Comments say what is; the commit log says what changed

Comments are dense here: a rule that only prose states, with nothing checking it, is the
defect this tree works hardest to avoid, so the *why* beside the code earns its place. Two
rules keep rationale and history apart.

Write the rationale in the present tense, about the code that exists: a claim about the
alternative, not a story about a previous revision.

```rust
// NO:  `first_data_file_magic` used to swallow every error with `.ok()?`, so an EIO
//      arrived as Indeterminate and the sweep quarantined a healthy dataset.
// YES: An I/O fault says nothing about the data, so it must not reach the quarantine
//      path: withholding a dataset because one `read_dir` returned EIO turns a blip
//      into an operator-action outage.
```

The story goes in the commit message, at whatever length it deserves; `git log -S` and
`git blame` find it.

A `///` doc on a type that derives `JsonSchema` is published: `schemars` copies it into
`docs/*.schema.json`, which integrators read as the normative description of a wire field.
Say what the field is in the `///` and put the rationale in a `//` comment. A test fails
on a Rust path separator in any published description.

## Adding a config field

The shipped example configs are pinned to the typed config by
`crates/gdi-node-standalone/tests/it/config_examples.rs`, and its failure messages do not
spell out the rules, so:

1. **Add the field** to its section struct in `crates/core/src/config/service.rs`, with a
   `///` and a value in the struct's `Default`.
2. **Validate it** in `ServiceConfig::preflight`, so a bad value fails at boot rather than
   at the first request, with accept and reject cases in `crates/core/src/config/tests.rs`
   (`assert_preflight_case`).
3. **Document it in `node.example.toml`**, the annotated reference. A tuning knob is shown
   at its default; the guard compares every example leaf against
   `ServiceConfig::default()`. A field that must show a deployment value instead
   (`service.base_url`, `catalogs`, `keys.identities`) goes in `EXAMPLE_OVERRIDE_PREFIXES`
   in the same test, and an entry there with no real deviation fails too. A knob shown
   commented out (`# key = <value>`) counts as documented, so an opt-in feature need not
   ship an active key.
4. Both config structs are `deny_unknown_fields`, so a stale or typo'd key in any shipped
   example, `compose/` included, fails the guard.

One gap is held by review, not by the guard. Completeness is derived from
`ServiceConfig::default()`, and these structs put `skip_serializing_if` on every `Option`
and collection, so a new `Option`, `Vec` or `String` field serializes to no leaf and is not
forced into the example (a bare `Option<T>` without the attribute would serialize to a
`null` leaf and be caught). Closing it in code would mean a second copy of the field list,
the drift a guard exists to prevent, so document the field anyway; every such field is
documented today.

## Dependencies and `Cargo.lock`

- **Shared dependencies are exact-pinned** in `[workspace.dependencies]` (`"=x.y.z"`). Add
  new shared ones there, and match existing constraints to avoid duplicate crate versions.
- **`default-features = false`**, enabling only what you use. This keeps the C and
  assembly surface to `ring` alone and cross-compiles clean; the `arrow`/`parquet` subtree
  is trimmed to the individual `arrow-*` crates.
- **No new external crate** without explicit confirmation in the PR. Prefer std and what
  is already in the tree.
- **Never hand-edit `Cargo.lock`.** After changing a `Cargo.toml`, a plain `cargo check`
  (no `--locked`) regenerates it; commit it, since every gate builds `--locked`.
- **`cargo deny check` is the supply-chain gate**: the licence allow-list, the RustSec
  advisories, and the bans in `deny.toml` (`aws-lc-rs`, `aws-lc-sys`, and `ring` below
  0.17.14). The `ignore` list is empty and `advisory-not-detected` is an error, so an
  ignore cannot outlive its advisory. It reads the feature-independent `Cargo.lock`, so it
  sees `ring` whichever features a build enables; a separate `cargo audit` is unnecessary.
- **Never commit secrets** or generated config and state that carries credentials.

## Conventional Commits

[Conventional Commits](https://www.conventionalcommits.org/), concise, imperative and
lowercase: `<type>(<scope>): <summary>`, with an optional body and footer. Types in use:
`feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`, `chore`.

```text
feat(beacon): pushdown POS filter into row-group pruning
fix(parser): resolve overflow panic
ci: pin ring floor in deny.toml bans

feat(core)!: change DatasetDecryptor key-retrieval signature

BREAKING CHANGE: DatasetDecryptor::new now takes a &KeyStore.
```

A breaking change carries `!` after the type or scope, a `BREAKING CHANGE:` footer, or
both. One that touches a public wire contract, the Beacon `resultSets` shape or the FAIR
Data Point graph, is also recorded under `## [Unreleased]` in `CHANGELOG.md`.

## Cutting a release

For maintainers. Pushing a `vX.Y.Z` tag runs `release.yml`, which cross-compiles every
artifact, generates the SBOM and provenance, and publishes the GitHub Release and the
container image. The checks that gate the publish run only on the tag, so the local gate
is what stands between you and a broken release.

**First, get `scripts/ci-local.sh release` green.** It is `all` plus the Docker, cross,
coverage, licence and e2e legs (`help` lists them); it needs Docker, `cross`, `trivy`,
`cargo-about` and `cargo-llvm-cov`, tens of GB in `target/`, and hours. Then:

1. **Set `version` in `[workspace.package]` to exactly what you ship**, pre-release suffix
   included: `1.0.0-rc.1` for a candidate, `1.0.0` for the release. `version-guard`
   compares the tag to this string without stripping. The suffix belongs in the manifest
   because every version surface (`--version`, `GET /version`, the log preamble,
   `gdi_build_info`, the Beacon `info` response) reads `CARGO_PKG_VERSION`; a candidate
   that called itself `1.0.0` could not be told from the release over the wire. Write it
   dotted (`-rc.1`, not `-rc1`): SemVer compares dotted numeric identifiers numerically,
   so `-rc.11` sorts above `-rc.2`, while `-rc11` sorts below `-rc2`.
2. **Refresh both lockfiles and the attribution bundle.** A plain `cargo check` updates
   `Cargo.lock`. `crates/core/fuzz/Cargo.lock` does not follow, because the fuzz workspace
   depends on `core` and `beacon` by path and records their versions; regenerate it with
   `cargo check --manifest-path crates/core/fuzz/Cargo.toml --bins`, or `fuzz-smoke` fails
   with `cannot update the lock file … because --locked was passed`. Regenerate
   `THIRD-PARTY-LICENSES.md` with `cargo about generate about.hbs -o THIRD-PARTY-LICENSES.md`;
   the `licenses` leg guards it but runs only in `release`, so treat this as mandatory.
   Commit all three.
3. **Roll the changelog.** `CHANGELOG.md` is hand-curated: under `## [Unreleased]`, only
   consumer-facing and breaking changes, since the per-commit history is appended to the
   release body automatically. Add a `## [X.Y.Z] - YYYY-MM-DD` heading below the guidance
   comment and move the entries under it, leaving `## [Unreleased]` and its comment in
   place; renaming that heading would carry the comment (HTML, so GitHub never renders it)
   into the versioned section. The release workflow fails if the `## [X.Y.Z]` section is
   missing, so an un-rolled changelog blocks the release rather than being dropped. At the
   bottom, start the `[Unreleased]` compare link at the new tag and add a `[X.Y.Z]` link to
   its release.
4. **Update the version in prose.** `README.md` and several docs name the current release,
   with and without the `v`, and nothing checks them;
   `git grep -nF "$old" -- ':!*Cargo.lock' ':!THIRD-PARTY-LICENSES.md'` finds every site.
5. **Commit, tag that commit `vX.Y.Z`, push the tag.** `release.yml` gates `publish` and
   `image` behind `gate`, `version-guard` and `changelog-guard`, and `ci.yml` runs on the
   tag too; if anything is red, nothing publishes: fix and re-tag. A `v0.x` or suffixed
   tag publishes as a pre-release and leaves `:latest` alone.

For a release candidate, set the version to `X.Y.Z-rc.N` and tag `vX.Y.Z-rc.N`. The
changelog guard and the notes assembly strip the suffix, so a candidate draws its notes
from the `## [X.Y.Z]` section it is a candidate for; you do not roll a section per
candidate.

**A rehearsal is not a dry run.** `prerelease` is set, but the Release is published,
every artifact is uploaded and attested, and the image is pushed to `ghcr.io`. To undo one
you delete both the Release and the GHCR tag by hand.

## Branch protection

For maintainers; these are GitHub settings (Settings → Branches, or Rulesets), not files.
Require the `ci-success` status check on `main`, and only that one: it `needs:` every
gate, so a newly added gate becomes required automatically. Code-owner review is not yet
possible: the path map is parked at `.github/CODEOWNERS.draft`, inert until renamed, and
its header gives the activation order. Substitute real handles first, then rename, then
enable the toggle; in any other order every pull request touching those paths blocks.

## Before you open a PR

Keep a PR to one change, say what you assumed and what you left out, ask when unsure, and
don't refactor around it. Then check:

1. `scripts/ci-local.sh all` is green on the final tree.
2. If you changed a `Cargo.toml`, `cargo check` regenerated `Cargo.lock` and it is
   committed; if the dependency set changed, `ci-local.sh licenses` is green too.
3. If you raised the MSRV, it is the one value, `rust-version`, and the PR says so.
4. If you changed a wizard prompt, `docs/images/wizard.svg` is re-recorded with
   `scripts/demo/record-wizard.sh`; its header says what it needs.
5. Commit messages are Conventional Commits, and a wire-contract change is in
   `CHANGELOG.md`.
6. Open the PR against `main`. `ci-success` must pass.
