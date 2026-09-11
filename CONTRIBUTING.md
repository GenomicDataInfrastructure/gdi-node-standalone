# Contributing to `gdi-node-standalone`

`gdi-node-standalone` is a standalone Rust implementation of the core GDI node
functionality: Beacon, FAIR Data Point, and the dataset tool. This document is the
developer onboarding guide. It covers the workspace layout, the lite/full build profiles,
and the validation pipeline a change must pass. You should be able to onboard from this
file alone.

## Table of contents

- [Getting the source](#getting-the-source)
- [Prerequisites and toolchain](#prerequisites-and-toolchain)
- [Project layout](#project-layout)
- [Build profiles (the lite/full feature matrix)](#build-profiles-the-litefull-feature-matrix)
  - [Feature reference](#feature-reference)
  - [What lite vs full guarantee](#what-lite-vs-full-guarantee)
  - [Common build commands](#common-build-commands)
- [Local validation pipeline](#local-validation-pipeline)
  - [Install the pre-commit hook](#install-the-pre-commit-hook)
  - [The commands the runner (and CI) enforce](#the-commands-the-runner-and-ci-enforce)
  - [What each CI job runs](#what-each-ci-job-runs)
- [MSRV policy](#msrv-policy)
- [Code style and conventions](#code-style-and-conventions)
- [Adding a config field](#adding-a-config-field)
- [Dependencies and `Cargo.lock`](#dependencies-and-cargolock)
- [Conventional Commits](#conventional-commits)
- [Cutting a release (maintainers)](#cutting-a-release-maintainers)
- [Branch protection (maintainers)](#branch-protection-maintainers)
- [Behavioural principles](#behavioural-principles)
- [Before you open a PR](#before-you-open-a-pr)

## Getting the source

If you have write access, clone directly:

```bash
git clone https://github.com/GenomicDataInfrastructure/gdi-node-standalone.git
cd gdi-node-standalone
git switch -c <short-branch-name>
```

Otherwise fork first, on GitHub, then clone your fork and add the upstream remote so you
can keep it current:

```bash
git clone https://github.com/<you>/gdi-node-standalone.git
cd gdi-node-standalone
git remote add upstream https://github.com/GenomicDataInfrastructure/gdi-node-standalone.git
git switch -c <short-branch-name>
```

Then install the pre-commit hook, which is a one-time step per clone and is described under
[Install the pre-commit hook](#install-the-pre-commit-hook).

Open the pull request against `main`. Everything below applies the same either way, bar a
few exceptions marked `(maintainers)` where they appear — cutting a release and branch
protection — plus the `full-e2e` label, which needs triage rights you will not have on a
fork.

## Prerequisites and toolchain

You need `git`, `curl`, and a C toolchain (`cc`, from `build-essential` / `gcc` / the Xcode
Command Line Tools). Every crate builds at least one C-dependent build script — `zstd-sys`
pulls one in even on the ring-free lite profile — so without a linker the first
`cargo build --workspace` fails with ``error: linker `cc` not found``. rustup's installer
only warns about a missing linker, it does not block. `scripts/dev-setup.sh --check`
verifies all three.

If `rustup` is not installed yet:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none
```

Use `--default-toolchain none`. rustup's default installs a `stable` toolchain, and
`cd`-ing into this repository then installs the pinned toolchain separately, doubling a
~1.5 GB download for nothing. `--profile minimal` is a reasonable alternative if you also
want rustup-managed toolchains for other projects.

The toolchain is pinned. A committed `rust-toolchain.toml` selects the channel and
components, so every build uses the same compiler and lint set:

```toml
# rust-toolchain.toml
[toolchain]
channel = "1.98.0"
components = ["clippy", "rustfmt"]
```

`rustup` installs and selects `1.98.0` when you `cd` into the repository. You do not need
to select a toolchain manually.

Two version numbers, answering different questions:

- **`channel = "1.98.0"`** in `rust-toolchain.toml` is the toolchain you develop and lint
  with. The Dockerfile's `FROM rust:` builder must match it; `ci-local.sh ci-gate` asserts
  that, since a Dockerfile cannot read the version out of another file.
- **MSRV `1.96`** (`rust-version` in `[workspace.package]`) is the minimum Rust the crates
  must still compile on. It is a ratchet, not a function of the pin: raised only when
  something requires it, never lowered. See [MSRV policy](#msrv-policy).

The full local pipeline also needs these tools. `preflight_all` checks them, plus `curl`
and `rustup`, up front, so a missing one is reported before any leg runs:

- `cargo-deny` — license, advisory and ban checks, including the RustSec scan. Install with
  `cargo install cargo-deny --locked`.
- `cargo-machete` — the unused-dependency gate (`cargo install cargo-machete --locked`).
- `cargo-cyclonedx` — CycloneDX SBOM generation
  (`cargo install cargo-cyclonedx --locked`).
- `gitleaks` — the scanner behind the `secrets` leg, run over the working tree against
  `.gitleaks.toml`. `ci-local.sh` enforces a minimum version (`GITLEAKS_MIN_VERSION`);
  an older rule set reports clean on findings it cannot see. Install:
  <https://github.com/gitleaks/gitleaks#installing>.
- `python3` — several `all` legs are Python: the guards `ci-gate`, `dashboard`,
  `doc-attachment`, `script-tests` and `k8s-manifests`, plus `conformance` and `crypt4gh`,
  which build cached venvs under `target/venv/` from `conformance/requirements.txt` and
  `conformance/requirements-crypt4gh.txt`. `corpus` needs it only when it fetches its data
  slices. `k8s-manifests` additionally needs PyYAML, the one third-party import among the
  guards; preflight only checks that a binary exists, so a missing PyYAML fails partway
  into `all`. Install it with
  a virtualenv, and run the gate from that same shell — the leg imports PyYAML with the
  ambient `python3`, so an unactivated venv does not help:
  `uv venv && . .venv/bin/activate && uv pip install -r scripts/tests/k8s/requirements.lock
  --require-hashes`. A bare `pip install` fails on any PEP 668 distro (Debian, Ubuntu,
  Fedora) with `externally-managed-environment`, and so does `uv pip install` outside a
  virtualenv. Set
  `GDI_FDP_PYTHON` / `C4GH_VENV` to reuse an interpreter you already have.
- `uv` — required for the `ruff` and `reuse` legs, and the only supported way to regenerate
  the two `conformance/*.lock` hash-locks
  (`uv pip compile --universal --generate-hashes …`).
  Both legs shell out through `uvx`, so neither tool needs a separate install; their
  versions are pinned in `scripts/ci-local.sh` (`RUFF_VERSION`, `REUSE_VERSION`), ruff's
  rule selection lives in `ruff.toml`, and REUSE's annotations live in `REUSE.toml`.
  Install: <https://docs.astral.sh/uv/getting-started/installation/>.

Python has the same floor-versus-pin split as Rust. `.python-version` (3.14) is the pin:
`ensure_venv` builds the conformance and crypt4gh venvs on it, and those venvs install
third-party wheels and produce real verdicts. `ruff.toml`'s `target-version` (py312) is
the floor: the stdlib-only guard legs run on ambient `python3` and behave identically
across versions. Anything from 3.12 up runs the gate, and the `ruff` leg proves it every
run by parsing all of `conformance/` and `scripts/` with a floor interpreter.

Optional, for the scheduled and on-demand legs: `cargo-llvm-cov` (coverage),
`cargo-semver-checks` (public-API drift), `cross` (cross-compilation), and `cargo-fuzz` on
nightly (the isolated fuzz workspace). Also optional, but needed the first time a change
moves an `insta` golden: `cargo-insta`
(`cargo install cargo-insta --locked`), which
[`docs/testing.md`](docs/testing.md#4-snapshot--golden-insta) tells you to review snapshots
with. No gate leg needs it — the goldens are asserted by the ordinary test run — so it is
listed here rather than above, and `scripts/dev-setup.sh` reports it among the optional
tools.

## Project layout

This repository is a Cargo workspace (`resolver = "3"`, edition 2024) with seven members
plus one excluded fuzz workspace:

| Path | Crate name | Kind | Purpose |
| --- | --- | --- | --- |
| `crates/build-info` | `gdi-build-info` | library (internal, `publish = false`) | Compile-time build provenance: `GIT_SHA` and `BUILD_EPOCH`, taken from the environment, else from `git`, else `"unknown"`. Both binaries depend on it, so their `--version`, `GET /version` and the `gdi_build_info` metric cannot drift. |
| `crates/core` | `gdi-node-standalone-core` | library | VCF→Parquet conversion, manifest/config types, the crypt4gh codec, TAR packaging, shared validation. |
| `crates/beacon` | `gdi-node-standalone-beacon` | library | GA4GH Beacon query execution over Parquet (scan, pushdown, `frequencyInPopulations` assembly). |
| `crates/fairdp` | `gdi-node-standalone-fairdp` | library | FAIR Data Point RDF emission (Turtle + JSON-LD via `oxrdf`/`oxttl`/`oxjsonld`). |
| `crates/gdi-node-standalone` | `gdi-node-standalone` | service binary | The node HTTP service: Beacon + FDP endpoints, inbox reconcile, and S3/Vault/PME when built `full`. |
| `crates/gdi-dataset-tool` | `gdi-dataset-tool` | binary (+ `gdi_dataset_tool` lib) | The dataset CLI: `build` (VCF→parquet), `validate`, `pack`, and the networked `upload`/`deploy` ops. `deploy --inbox` and `publish --inbox` are local filesystem copies needing neither a profile nor network. |
| `crates/test-util` | `test-util` | library (dev-only) | Shared test helper: safe `set_env`/`remove_env` wrappers, the single audited home for the `unsafe` `std::env` mutators Rust 2024 requires. Never built into a shipped artifact. |

The three library crates (`core`, `beacon`, `fairdp`) are the public API surface. The
`semver-checks` job reports API breaks on them, but it is advisory and its local leg is
outside `ci-local.sh all`, so nothing enforces it: run
`./scripts/ci-local.sh semver-checks` yourself when you touch one of their public APIs.
The two binaries are not public-API surfaces. `test-util` and `gdi-build-info` are
internal helpers.

`crates/core/fuzz` is its own isolated workspace, excluded from the root workspace. It
carries its own `Cargo.lock` and is built only with `cargo +nightly fuzz`, so the stable
`--workspace` gates and `cargo deny` never compile or scan it.

## Build profiles (the lite/full feature matrix)

S3, Vault, and at-rest Parquet Modular Encryption (PME) are compile-time optional. A bare
`cargo build` or `cargo install` yields the lite node, a minimal no-network binary; the
networked dependencies are linked only when asked for. This shrinks the default node's
dependency graph, attack surface, and advisory-tracking burden.

All feature flags live on the `gdi-node-standalone` service crate, except `pme`, which is
also a feature on the `core` and `beacon` library crates that the service forwards into.

### Feature reference

| Feature | Default? | Gates | Pulls in |
| --- | --- | --- | --- |
| `default` | yes (`[]`) | The lite build: no S3, no Vault, no PME. | Nothing extra: no `ring`, no outbound TLS. |
| `s3` | no | S3 bucket monitoring (`[[s3.buckets]]`). | `object_store` and its `reqwest`/`quick-xml` stack, `futures`, `time`, and the internal `tls` group. |
| `vault` | no | The Vault KV/Transit client (`[vault]`). With it off, secrets come from local `[keys]` files. | `reqwest`, `base64`, `thiserror`, and the internal `tls` group. |
| `pme` | no | At-rest Parquet Modular Encryption (AES-GCM, per-file DEK wrapped via Vault Transit). | Implies `vault`; turns on `core/pme` + `beacon/pme` → `parquet/encryption` → `ring`. |
| `tls` | no (internal) | Enabled automatically by `s3` or `vault`. Cargo cannot auto-enable on "s3 OR vault", so both list it. | `rustls` with `custom-provider`, the `ring` provider, `reqwest` (`rustls-no-provider`, no `aws-lc-rs`), and `core/http`, whose `tls::https_client_builder` merges the bundled Mozilla roots onto the platform verifier so a static binary verifies TLS with no OS CA bundle. |
| `full` | no | The networked / container artifact, feature-identical to production. | `= ["s3", "vault", "pme"]`. |
| `otel` | no | OTLP export: turns the existing `tracing` spans into exported traces when `[service].otlp_endpoint` is set, and pushes the `/metrics` series as OTLP metrics when `otlp_metrics_interval_seconds` is set. A no-op when unset. Not part of `full`. | `opentelemetry`, `opentelemetry_sdk`, `opentelemetry-otlp`, `tracing-opentelemetry`, over HTTP/protobuf on the blocking `reqwest` client. It selects no TLS feature of its own, so `https://` endpoints work only in a build that already carries the `tls` group. Exported spans are content-free: the `audit` target is filtered out. |

PME needs `ring` but not TLS, so the rustls provider install is gated on `tls` rather than
on `ring`.

On `core` and `beacon`, `pme` exists as a standalone feature (`core`'s
`pme = ["parquet/encryption"]`, `beacon`'s `pme = ["gdi-node-standalone-core/pme"]`) so
those crates can be built with encryption support independently.

The `gdi-dataset-tool` binary is always networked. It links `object_store`, `reqwest` and
the `ring`/`rustls` stack unconditionally, so it has no feature gates of its own.

### What lite vs full guarantee

- **lite (default).** Dropping `s3`/`vault`/`pme` removes `ring` and the whole TLS and
  root-certificate apparatus. The `graph` leg asserts this with
  `cargo tree --no-default-features -i ring`, which must find no `ring` node. It is not
  "pure Rust": the lite node still links the C `zstd` parquet codec. The accurate claim is
  no `ring`, no network, smaller graph. crypt4gh package transit is a pure-Rust codec and
  stays available, so a lite node can still ingest `.tar.c4gh` packages with a local
  `[keys]` identity.
- **full.** Links exactly one C/assembly crypto library, `ring`, statically. The workspace
  standardizes on `ring` rather than `aws-lc-rs` because `ring` cross-compiles and
  statically links cleanly to `musl`. The `graph` leg asserts the full graph links no
  `aws-lc-sys`, and `deny.toml` bans `aws-lc-rs`/`aws-lc-sys` outright.
- **S3 profile (`--features s3`, no Vault or PME).** The common public-data deployment:
  S3 ingest with a file-based `[keys]` identity and volume-level at-rest encryption. Like
  `full` it links `ring` for TLS and SigV4, but compiles in none of the Vault or PME code.
  It is lint-checked, tested and graph-asserted alongside the others. It is not a separate
  released binary: run the shipped `full` binary with `[vault]` omitted for identical
  behaviour, or build `--features s3` from source for the smaller footprint.

A config section whose Cargo feature is not compiled in (`[[s3.buckets]]` without `s3`,
`[vault]` without `vault`, `[vault].transit_key` without `pme`) is rejected at startup by
the config preflight with a "rebuild with `--features …`" error, never silently ignored.

### Common build commands

```bash
# Lite (default) — what `cargo build`/`cargo install` yields.
cargo build

# Full — S3 + Vault + PME (the production/container build).
cargo build --features full

# One capability at a time (each implies `tls` where relevant).
cargo build --features s3
cargo build --features vault          # pme is off; vault is standalone
cargo build --features pme            # implies vault

# Release artifacts (thin LTO, codegen-units=1, symbols stripped).
cargo build --release --features full
```

## Local validation pipeline

While iterating, scope to what you changed: `cargo check -p <crate>` for a type-check, and
`cargo test -p <crate> --test it <module>::` for a single test module, adding
`--features <feat>` for a feature-gated suite. Even the lightest runner target below
cold-builds the whole tree, so reach for the runner before you finish a change:

```bash
./scripts/ci-local.sh          # default target `all`: the full pre-push pipeline
./scripts/ci-local.sh quick    # fast subset: fmt + lite clippy + script-tests
./scripts/ci-local.sh release  # the tag-time gate: `all` plus the heavy Docker/cross legs
./scripts/ci-local.sh help     # every target, and what each one does
```

CI runs on GitHub Actions: `ci.yml` on pull requests, pushes to `main` and `v*` tags;
`release.yml` on a `v*` tag; `scheduled.yml` and `e2e-full.yml` weekly. `ci-success` is
the rollup every other job feeds, and it is the one check to require in branch protection —
see [Branch protection (maintainers)](#branch-protection-maintainers), which is where that
setting's status is recorded.

Run `ci-local.sh` before you push regardless. It is not a mirror of CI — most CI jobs are
thin wrappers around it, so it *is* the gate, and the legs it runs that CI does not (the
heavy `release`-tier ones) are the ones that fail late and expensively.

Fourteen `ci.yml` jobs invoke the script directly — `lint` (as `ci-local.sh quick`),
`rust`, `supply-chain`, `profiles`, `msrv`, `doctests`, `promtool`, `actionlint`,
`shellcheck`, `ruff`, `reuse`, `secrets`, `fuzz-smoke` and `doc-attachment` — so those
definitions cannot drift from the local run. Six restate their commands inline: `sbom`,
`conformance`,
`crypt4gh-interop`, `semver-checks`, `cross-compile` and `e2e-smoke`. In `scheduled.yml`,
`corpus` and `pins` call the script; the rest restate their commands. Every inline
definition is hand-kept in step with its `ci-local.sh` counterpart and will diverge if only
one side is edited.

**These workflows are young.** They first ran at publication, and `release.yml` has run
once, for `v1.0.0-rc.1`. Plenty of legs have still run only once or twice, so treat an
early red as a possible pipeline defect and report it rather than working around it.

`all` covers every non-Docker check, including `sbom`, `conformance`, `crypt4gh`, the
`fuzz-smoke` compile-check of the excluded fuzz harnesses, and the real-data `corpus`.
Two exceptions:

- `promtool` and `shellcheck` need Docker. Without it they print a visible `SKIPPED` line,
  repeat it in the final summary, and the run continues. `release` sets
  `GATE_STRICT_LEGS=1` and refuses the skip.
- `semver-checks` stays out of `all` because it builds two trees. Run it explicitly when
  you touch a public API of `core`, `beacon` or `fairdp`. The local leg defaults to
  `SEMVER_BASELINE=HEAD`, comparing your uncommitted work against the last commit.

The Docker and cross legs — `cross`, `cross-arm`, `e2e`, `e2e-full`, `image-scan`,
`licenses` — are bundled into the `release` meta-leg. Between them `cross` and `cross-arm`
build-verify the full shipped Linux set (x86_64 plus aarch64), so the local tag gate
misses no shipped Linux target. The only checks with no local counterpart are the
macOS/Windows `cross-native` builds and the release job's keyless attestation and GHCR
publish, both of which need a hosted runner.

The script passes `-D warnings`, matching how the warn-level lints in `[workspace.lints]`
are promoted, so a local run reproduces the pipeline's strictness exactly.

A rename that spans code, config, docs and Compose is caught by the cross-artifact seam
guards in `crates/gdi-node-standalone/tests/it/seams.rs`. They are tests, so `all` runs
them; `./scripts/ci-local.sh seams` runs only those for a fast check without a full
workspace build.

Two traps a long run tempts you into:

- **Do not edit the tree while a gate run is in flight.** `cargo` compiles the dependency
  graph for many minutes before it reaches the workspace crates, so an edit landing
  mid-run is compiled into a torn mix of before and after. The failure it reports is an
  artifact, not a real error. Get a green run on a clean tree, then edit.
- **Worktrees.** `git worktree add <path> -b <branch> origin/main` is the usual form. In a
  clone with no remote configured it fails with `fatal: Needed a single revision`; branch
  from local `HEAD` instead, `git worktree add <path> -b <branch> HEAD`. Give each worktree
  its own `target/`; do not
  share `CARGO_TARGET_DIR`. `.gitleaks.toml` makes the parent checkout's `secrets` leg
  skip nested `.worktrees/` checkouts, so run the gate from inside a worktree before
  merging its branch. Two things are shared across worktrees: the
  [build speedups](#optional-local-build-speedups) live in the user-level
  `~/.cargo/config.toml`, and the heavy targets take
  [one slot per machine](#one-gate-per-machine).

For the test taxonomy — the kinds of tests, where each lives, how to add one, and the
shared-fixture API — see [`docs/testing.md`](docs/testing.md). This section covers the
commands that run them.

### Install the pre-commit hook

Git cannot install its own hooks, because `.git/config` is not versioned, so this is a
one-time step per clone:

```bash
git config core.hooksPath .githooks
```

`scripts/dev-setup.sh` offers to do it for you.

`.githooks/pre-commit` always runs rustfmt, which parses rather than compiles. It runs
lite clippy at `-D warnings` only when a staged path can change a clippy result: `*.rs`,
`Cargo.toml`/`Cargo.lock`, `clippy.toml`, `rust-toolchain.toml`, `.cargo/config.toml`.
`clippy --workspace --all-targets` spans every target of all seven crates and takes
minutes cold, and most commits here are docs, YAML, shell or dashboards. The skip is soft:
a wrongly-skipped lint surfaces at `ci-local.sh all`.

The hook also dispatches on what else is staged:

- a staged `scripts/` or `.githooks/` path runs the gate's own unit suite;
- staged Python under `scripts/` or `conformance/` runs the `ruff` leg;
- a staged `Cargo.toml`/`Cargo.lock` runs `fuzz-smoke`, the `--locked` compile-check of
  the isolated fuzz workspace. When that leg reds, relock with
  `cargo check --manifest-path crates/core/fuzz/Cargo.toml` (no `--locked`);
- staged Rust carrying a `#[cfg(feature = "...")]` gate also runs clippy at the full
  profile, since lite clippy never compiles gated code.

A missing `uv` degrades to a warning rather than blocking the commit, on every path
including the feature-gate escalation. The one path that needs network is `ruff`: staged
Python with `uv` present shells out to `uvx ruff@<pinned>`, which fetches ruff and, the
first time, an interpreter. That specific `git commit` can fail offline;
`git commit --no-verify` is the escape from it, and from the hook generally for a
work-in-progress commit.

`scripts/tests/test_pre_commit_hook.py` pins every one of these classifiers, and the hook
owns the patterns, so they are not restated here.

### Running `all`

The full gate takes many minutes, and considerably longer on a cold tree. Run it in the
background and carry on rather than watching it or polling it in a loop.

It also short-circuits. `scripts/gate-key.sh` hashes every tracked and
untracked-but-not-ignored file by working-tree content, plus `rustc -vV` and
`cargo --version`; a green run records that key and a timestamp in `target/.gate-ok`. The
key is sampled before the legs run, since that is the tree they verify, and is recorded
only if the tree is still identical when they finish. A run whose tree changed mid-flight
prints `NOT RECORDED`, and the next `all` runs in full.

If the key still matches and the marker is under `GATE_TTL_HOURS` (default 24) old, `all`
skips the pure legs and runs only the ones whose verdict is not a function of the tree:
`secrets` first, because gitleaks reads gitignored files the key cannot see, then
`cargo-deny`, `deny-fuzz` and `pip-audit`, whose verdicts track advisory databases. A
cache hit must never mask a fresh CVE. `pins` is not re-run there: it spends a scarce
unauthenticated GitHub API budget, and exhausting that budget makes it report
`UNREACHABLE`, which it treats as a pass.

```bash
GATE_FORCE=1 ./scripts/ci-local.sh all   # ignore the marker, run everything
```

The key is one hash for the whole gate rather than one per leg: a key per leg would be a
chance per leg to manufacture a false green. Its blind spots are gitignored files and
environment variables (`GDI_CORPUS_DIR`, `GDI_FDP_PYTHON`), both asserted in
`scripts/tests/test_gate_key.py` so they stay known, and both backstopped by the TTL and
by the marker living under `target/`, where `cargo clean` or `ci-local.sh sweep` discards
it.

The key hashes content, not mtime. A bare `touch` makes cargo rebuild but does not
invalidate the marker, because a content-identical tree produces the same gate result.

### One gate per machine

Concurrent gates do not share a machine, they thrash it. Queued one at a time they finish
one after another instead of all at once at the end, so the first verdict arrives early.

So the heavy targets — `all`, `release`, every compiling leg of `all`, and the whole-suite
test legs (the `GATE_QUEUE_LEGS` array in `ci-local.sh`) — take one machine-wide slot via
`scripts/gate-queue.sh`, a `flock` on `/tmp/gdi-node-standalone-gate-<uid>.lock` shared by
the main checkout and every worktree. A run that finds the slot taken prints who holds it,
a heartbeat every minute, and `queued Ns; starting` when it gets in; the wait is reported
again beside the leg timings so it is never mistaken for leg time. The interactive rungs —
`quick`, `lint`, `fmt`, the clippy legs, everything the pre-commit hook runs — never
queue, and `scripts/tests/test_gate_queue_wiring.py` pins both directions.

```bash
GATE_QUEUE=0 ./scripts/ci-local.sh all   # skip the slot (you know the machine is idle)
GATE_LOCK=/path/to/lock …                 # a different slot file
```

Do not `nice` the gate: a niced gate starves next to any nice-0 bulk load. The slot is a
descriptor inherited by everything the gate spawns, so an orphaned `cargo` keeps it, and
the waiter names it. Kill by process group (`kill -TERM -- -<pgid>`) so the children go
too.

### Keeping `target/` in check

One `target/` accumulates a separate artifact set per toolchain and feature-set
combination, which is how it reaches tens of GB and forces a `cargo clean` that makes the
next gate run cold. `ci-local.sh sweep` is maintenance, not a gate, and reclaims it:

```bash
./scripts/ci-local.sh sweep          # cargo-sweep --installed + --maxsize (default 20GB)
SWEEP_MAXSIZE=40GB ./scripts/ci-local.sh sweep
```

`--installed` drops artifacts from toolchains you no longer have. `SWEEP_MAXSIZE` must
carry an explicit unit: `cargo sweep --maxsize` reads a bare number as megabytes, so a
unitless value is rejected rather than silently deleting almost everything.

### Optional local build speedups

`scripts/dev-setup.sh` does all of this for you. It checks the toolchain and the gate's
required tools, offers to install the pre-commit hook, and — only when `mold` is present —
offers to write the user-level `~/.cargo/config.toml` below. `--check` reports without
changing anything.

Neither setting is committed: a linker override in the repo breaks anyone without the tool
installed. Put them at user level rather than per checkout. Cargo merges
`$CARGO_HOME/config.toml` into every project on the machine, worktrees included, whereas a
gitignored `.cargo/config.toml` is not part of a checkout and so is absent from every
worktree. `dev-setup.sh` flags a leftover per-checkout file and offers to move it up. It
never edits an existing user-level file, because a second `[profile.dev]` table breaks
cargo; it prints the block instead.

`mold` is a faster linker, and `split-debuginfo = "unpacked"` stops DWARF being copied
into every binary. Together they cut relink time on the large test binaries substantially.
To opt in, install `mold` (it needs gcc 12 or newer) and put this in
`~/.cargo/config.toml`, or `$CARGO_HOME/config.toml` if you set `CARGO_HOME`:

```toml
[target.x86_64-unknown-linux-gnu]
rustflags = ["-C", "link-arg=-fuse-ld=mold"]

[profile.dev]
split-debuginfo = "unpacked"
```

`unpacked` leaves DWARF in the object files instead of copying it into every binary.
Backtraces keep `file:line` as long as `target/` is intact, so the binaries are not
relocatable, which is one reason this stays out of the repo's build contract. Adding or
removing either line changes every unit's fingerprint and forces one full rebuild of each
`target/` on the machine, so do it with no gate in flight. The `cross` legs are
unaffected: the container has its own `$HOME`, and `ci-local.sh` passes `RUSTFLAGS=`
through anyway.

### The commands the runner (and CI) enforce

[What each CI job runs](#what-each-ci-job-runs) maps each command to its job. Three
properties of the pipeline:

- The committed `Cargo.lock` is authoritative, and `--locked` honours it exactly. If you
  changed only source, keep `--locked`.
- The suite runs under `cargo nextest`. Install a prebuilt binary rather than
  `cargo install cargo-nextest --locked`, which is a from-source build:
  `cargo binstall cargo-nextest` (needs
  [`cargo-binstall`](https://github.com/cargo-bins/cargo-binstall)), or take the release
  binary from the [nextest releases
  page](https://github.com/nextest-rs/nextest/releases). nextest runs each test in its own
  process. It does not run doctests, so those stay on `cargo test --doc`.

  Prefer nextest, or pass `-- --test-threads=1`. A multi-threaded `cargo test` is not a
  slower equivalent here. Well over a hundred test sites mutate process environment, and
  `std::env::set_var` is `unsafe` in Rust 2024 because it races with environment readers
  outside `std::env` — libc `getenv`, DNS resolution, TZ handling — on any other live
  thread. `#[serial(env)]` orders the mutators against each other and does nothing about
  those readers. Process isolation or a single test thread is what bounds it, and
  `scripts/ci-local.sh` supplies one or the other on every leg. A bare
  `cargo test --workspace` gives you neither.
- MSRV is verified separately by the `msrv` target, `cargo +1.96.0 check --all-targets`
  over both the lite and full profiles. The leg pins the earliest patch of the declared
  floor rather than the two-component channel, and cargo keys artifacts by toolchain, so
  this leg shares nothing with `target/` and is two cold whole-graph type-checks plus a
  second installed toolchain. Plan for it rather than expecting a cached run. See
  [MSRV policy](#msrv-policy).

### What each CI job runs

`.github/workflows/ci.yml` runs on every pull request and on pushes to `main` and `v*`
tags. Scoping `push` to `main` and tags stops a same-repo PR branch from running the whole
matrix twice. The blocking jobs are `lint`, `rust`, `supply-chain`, `profiles`, `msrv`,
`doctests`, `promtool`, `actionlint`, `shellcheck`, `ruff`, `sbom`, `cross-compile`,
`e2e-smoke`, `conformance`, `crypt4gh-interop`, `secrets`, `fuzz-smoke`,
`doc-attachment` and `reuse`, aggregated by a single `ci-success` rollup job.
`semver-checks` is the one advisory job and does not block. Make that the only required
status check in branch protection, so a newly-added gate becomes required automatically.

`semver-checks` is also a `ci-success` dependency and runs per PR, but it is advisory:
`continue-on-error: true` makes it report success to the rollup even when it fails
(allowlisted with a reason in `CI_ADVISORY` in `scripts/check-ci-gate.py`), and being
PR-only it is additionally in `ALLOWED_SKIPS` so push and tag runs tolerate its `skipped`
result. Re-arm it by dropping `continue-on-error` if any of `core`/`beacon`/`fairdp` is
ever published or consumed as a versioned dependency.

The heavier `e2e-smoke-full`, `coverage`, and the aarch64-linux and macOS/Windows cross
legs run weekly instead; see
[Scheduled / on-demand jobs](#scheduled--on-demand-jobs-scheduledyml). Every Action is
pinned to a commit SHA with the version in a trailing comment, and Dependabot keeps the
pins current.

| Job | What it does |
| --- | --- |
| **`lint`** | Fast early gate: `ci-local.sh quick` (fmt + lite clippy + the scripts unit suite). The build-heavy jobs `needs:` it, so a formatting or lint slip cancels them up front. |
| **`rust`** | The lite gate: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, and `cargo nextest run --workspace --locked`. |
| **`supply-chain`** | `cargo deny check` (RustSec advisories over `Cargo.lock`, plus licenses, bans and sources) and `cargo machete`. Split out of `rust` so a test failure cannot mask a supply-chain failure or the reverse. |
| **`profiles`** | Clippy and `cargo nextest` at the full and s3 profiles, the vault-only and `--no-default-features` clippy passes, the feature-matrix and `schema` legs, the `cargo tree` graph assertions, and the `#[instrument]` privacy and `axum::serve` connection-bounds guards. The `full,otel` legs are not here: they form the opt-in `otel` aggregate, since trace export is never part of a shipped artifact. |
| **`msrv`** | Pins the earliest patch of the declared floor (**1.96** → `1.96.0`) and runs `cargo +1.96.0 check --workspace --all-targets --locked` for both lite and full. `--all-targets` compiles test and bench targets, so dev-dependencies count. It asserts the resolved `rustc` matches, so a floating channel cannot substitute a newer patch. |
| **`doctests`** | `cargo test --doc --workspace --locked` (lite and full), plus the `doc` target: `RUSTDOCFLAGS=-D warnings cargo doc` over all features and over the lite default. The lite pass is what catches a dangling intra-doc link to a feature-gated item. |
| **`promtool`** | `promtool check rules`, `check config` and `test rules` over `compose/observability/` in the pinned Prometheus image. The rule tests are the only proof that an alert can fire on the input it was written for. |
| **`actionlint`** | `actionlint` over every workflow file: YAML, `${{ }}` typos, bad `runs-on`/`uses` refs, matrix mistakes, and inline `run:` shell via bundled shellcheck. Also runs the release-target guard, which requires every `release.yml` target to be build-verified somewhere or explicitly allowlisted. |
| **`shellcheck`** | `shellcheck` at `--severity=warning` over the standalone scripts (`scripts/**`, `compose/*.sh`). actionlint's bundled shellcheck covers only inline `run:` blocks, not these. |
| **`ruff`** | `ruff check` and `ruff format --check` over `conformance/` and `scripts/`, via `uvx` at the pinned `RUFF_VERSION`. Also asserts `ruff.toml`'s `target-version` floor stays at or below the `.python-version` pin, so ruff cannot modernize these scripts into syntax an older interpreter rejects. |
| **`semver-checks`** | `cargo-semver-checks` on `core`, `beacon` and `fairdp` at `feature-group: all-features`, diffing against the PR's base commit via `baseline-rev`. The crates are `publish = false`, so the git baseline is what makes the check run at all. Advisory: a break annotates the PR rather than blocking it. |
| **`sbom`** | `cargo cyclonedx --all --format json` over the whole `Cargo.lock`, producing a CycloneDX SBOM artifact. |
| **`cross-compile`** | Five x86_64-Linux legs via `cross`, on the `release-verify` profile: the `gdi-dataset-tool` CLI for gnu and static musl, the service for gnu and static musl at `--features full`, and a musl `--features s3` build-verify. The aarch64 and macOS/Windows legs run weekly. |
| **`e2e-smoke`** | `./scripts/e2e/run.sh`: build the service image, bring up the minimal Compose stack, pack a fixture, poll `/datasets/{id}/state` to `visible`, then assert a Beacon query, an FDP crawl, and publish/unpublish. |
| **`conformance`** | pySHACL and ckanext-dcat over the crawled-and-unioned FDP graph, plus the dual-encoding agreement test. Python only, isolated from the Rust build and never shipped. |
| **`crypt4gh-interop`** | Rust↔Python crypt4gh round-trip (encrypt→decrypt, reverse, key parse) against the pinned `crypt4gh==1.8.6`. Isolated and never shipped. |
| **`secrets`** | `gitleaks` over the working tree against the repo's own `.gitleaks.toml`, so the same exemptions govern CI and a developer machine. gitleaks is fetched from its release and checksum-verified, because it is not in install-action's tool list. |
| **`fuzz-smoke`** | Compile-gates every `cargo-fuzz` target against the current library API, on the pinned stable toolchain — it does not fuzz. Also runs the pin- and licence-drift comparisons between the isolated fuzz manifest and the root workspace, which nothing else checks. |
| **`doc-attachment`** | No `///` doc comment or attribute detached from the item it documents, diffed against the pull request's base commit rather than the leg's default window. The pre-commit hook covers staged changes, but a fork contributor has not installed it. |
| **`reuse`** | `reuse lint`, via `uvx` at the pinned `REUSE_VERSION`: every file must resolve to a copyright holder and an SPDX licence through the directory annotations in `REUSE.toml`. Also asserts the two root `LICENSE-*` files still match their `LICENSES/` counterparts. Its own job rather than a step in `ruff`, so a lint failure and a licensing failure cannot mask each other. |

The `pins` leg has no `ci.yml` job: it is a verdict about the world rather than about the
commit, so it runs weekly in `scheduled.yml` as its own `pins` job (with `PINS_STRICT=1`),
alongside `vendored-sync`.
`scripts/vendored.sh pins` asserts that the userportal's deployed CKAN-extension refs, the
gdi-metadata HealthDCAT-AP lineage, the GA4GH beacon-v2 latest release tag, the pinned
GitHub Action tags and the Dockerfile's base-image digest all still resolve to what this
tree pins. It needs network, and unauthenticated GitHub API calls are rate-limited per IP,
so export `GITHUB_TOKEN` — sent to `api.github.com` only — to lift the budget. Real drift,
including a pinned path that 404s, fails the gate. A rate-limited or unreachable host
warns instead, because that is a verdict about your connection. `pins-strict`, which
`release` runs, makes drift fatal.

### Scheduled / on-demand jobs (`scheduled.yml`)

These are advisory, slow, or expensive, and gate nothing on a pull request. They run
weekly (Mondays 06:00 UTC) and on demand via `workflow_dispatch`.

The full-stack e2e runs from its own `e2e-full.yml`, weekly on the same day but three
hours later (Mondays 09:00 UTC), and additionally on a PR labelled `full-e2e`. The stagger
is deliberate: both workflows open a tracking issue when they fail, so a shared start time
turns one bad Monday into two issues. Apply the label to a PR touching the crypt4gh-ingest,
at-rest-encryption or S3 path. Labelling needs triage rights, which a fork contributor does
not have: say so in the PR description and ask a maintainer, or run `ci-local.sh e2e-full`
locally, which needs no permissions. The **Local** command reproduces each job; those
inside the `release` meta-leg are marked.

- **`fuzz`** — time-boxed `cargo-fuzz` over every `crates/core/fuzz` harness. Local:
  `ci-local.sh fuzz-short` (**`release`**) time-boxes every target; `cargo +nightly fuzz
  run <target>` drives one.
- **`benches`** — `criterion` hot-path benches, advisory. Local:
  `cargo bench -p gdi-node-standalone-core -p gdi-node-standalone-beacon -p gdi-node-standalone-fairdp`.
- **`load`** — `oha` load harness; fails on a load-shed regression. Local:
  `scripts/load/run.sh`, which boots its own node and needs `oha`.
- **`soak`** — endurance and crash-loop harnesses. `scripts/soak/leak.sh` asserts an
  RSS/open-fd/thread plateau; `scripts/soak/crash-loop.sh` `kill -9`s the node and asserts
  the store converges on restart. Local: run those scripts directly.
- **`advisories`** — re-runs the RustSec scan against the shipped lockfile and the
  isolated fuzz lockfile; fails on a freshly-disclosed advisory. Local: `ci-local.sh deny`
  covers the workspace lock. The fuzz lock is a local gap: scan it by hand with
  `cargo deny --locked --manifest-path crates/core/fuzz/Cargo.toml check advisories` after
  refreshing it.
- **`vendored-sync`** — two questions, one tree. `scripts/vendored.sh check` asserts every
  vendored conformance file is byte-identical to its pinned commit. Because that commit is
  an immutable SHA it stays green however far upstream moves, so `scripts/vendored.sh
  drift` answers the other question, comparing the same files against the upstream branch
  named in each `VENDORED.md`. Exit 3 means upstream moved, which is news rather than a
  defect, so the job runs it `continue-on-error` and it stays out of `all`. Local: both
  need network.
- **`cross-native`** — macOS and Windows `gdi-dataset-tool` builds. No local leg: it needs
  those operating systems.
- **`cross-linux-arm`** — aarch64-linux service build-verify (gnu and static musl, full
  profile) plus the glibc floor guard. Local: `ci-local.sh cross-arm` (**`release`**).
- **`coverage`** — `cargo llvm-cov`. The percentage is advisory; the zero-coverage guard
  is not, and `check-coverage-zero.py` fails on any source file over 50 lines that no test
  enters. Local: `ci-local.sh coverage` (**`release`**).
- **`image-scan`** — build the shipped image and Trivy-scan its base layer; a fixable
  HIGH/CRITICAL CVE fails. Local: `ci-local.sh image-scan` (**`release`**).
- **`licenses`** — regenerates the `cargo-about` attribution bundle and fails if the
  committed `THIRD-PARTY-LICENSES.md` is stale. It stays out of `all` because
  `cargo-about` has no prebuilt installer, so a dependency bump can leave the bundle stale
  through a green `all`. Run it after touching dependencies. Local: `ci-local.sh licenses`
  (**`release`**). The bundle's *scope* is guarded on every `all`: `ci-gate` asserts
  `about.toml`'s `targets` equals the set `release.yml` ships.
- **`stable-canary`** — builds on fresh `+stable` to signal when upstream stable has moved
  past the `rust-toolchain.toml` pin. Never a gate. Local: `cargo +stable check --workspace`.
- **`corpus`** — real-data conformance against 1000 Genomes and gnomAD chr21 slices. Weekly
  rather than per-PR because the leg range-downloads those slices first; the corpus is
  cached
  between runs. Local: `ci-local.sh corpus`.
- **`pins`** — external pin freshness: the userportal deploy refs and gdi-metadata lineage
  this tree follows, plus the Dockerfile base-image digests. Weekly because it is a verdict
  about the world, not about the commit. Local: `PINS_STRICT=1 ci-local.sh pins` (the job
  sets that so drift is fatal there; a working tree only warns).
- **`notify`** — opens or updates one tracking issue on a failed weekly run. No local
  equivalent.
- **`e2e-smoke-full`** (`e2e-full.yml`) — the full Garage + OpenBao + PME crypt4gh
  round-trip. Local: `ci-local.sh e2e-full` (**`release`**).
- **`chaos`** (`e2e-full.yml`) — toxiproxy latency, reset and black-hole faults on the S3
  and Vault wire. Local: `ci-local.sh chaos` (needs Docker).

### Mutation testing (`scripts/mutants-audit.sh`, not a CI job)

`cargo-mutants` grades how well the suite asserts behaviour: it mutates the code and asks
whether any test fails. A surviving mutant is a missing assertion, not usually a bug. It
is a discovery tool: once the gaps are closed, the resulting tests carry the regression
protection. That is why it is not a scheduled job. Run it on demand:

```bash
./scripts/mutants-audit.sh                             # whole workspace (hours)
./scripts/mutants-audit.sh -p gdi-node-standalone-beacon     # one package
./scripts/mutants-audit.sh -p gdi-node-standalone-core -f validate_pkg.rs   # one file
```

It defaults to `--all-features`, so every `cfg`-gated block is compiled and nothing is a
phantom survivor of never-compiled code. It guards two silent `cargo-mutants` traps — a
`-f` pattern containing a slash matches nothing, and `--in-place` does not restore the
tree if the run dies — and prints a per-file catch rate.

`--against <name>` diffs against `.github/mutants-baseline-<name>.txt`. No baseline ships
in the tree, so it fails immediately, before the run rather than after it. To use it,
restore a baseline from git history and reproduce the selection recorded in its
`# selection:` header.

## MSRV policy

The Minimum Supported Rust Version is `1.96`, declared once as `rust-version = "1.96"` in
`[workspace.package]` and inherited by every crate. It is a ratchet: raised only when
something requires it, never lowered, and not a function of the `1.98.0` development
toolchain in `rust-toolchain.toml`. The pin tracks current stable on its own cadence; the
floor moves when it must.

Either of these raises it:

- a dependency, dev-dependencies included, whose release we want declares a higher
  `rust-version`;
- a language or library feature we want that stabilised above the floor.

The floor is not "the pin minus one release", because the number governs more than which
compiler builds the tree. With `resolver = "3"` (edition 2024), `rust-version` steers
dependency resolution: `cargo update` prefers the newest release of each dependency
compatible with the floor and reports the rest as "N unchanged dependencies behind latest"
(`cargo update --verbose` names them and the floor each one needs). Nothing published
consumes these crates, and anyone building from source with rustup gets the pinned
toolchain regardless of the floor. So the declared number is a statement about the
dependency graph and the code, not a promise to a compiler somebody has installed. A
ratchet keeps it honest and makes each raise a visible decision. `check-ci-gate.py`'s
`msrv_job_is_degenerate` check reports if the floor and the pin ever coincide, since a
floor equal to the pin makes the `msrv` leg re-verify the compiler every other leg used.

- Clippy reads `rust-version` and will not suggest APIs newer than the floor.
- The `msrv` job runs `cargo +1.96.0 check --workspace --all-targets --locked` for both
  the lite and full profiles. `--all-targets` compiles the test and bench targets, which
  is what makes dev-dependencies count: a plain `check` never builds them, so a
  dev-dependency's floor above the MSRV would pass unnoticed. It is `check`, not
  `build`/`test`; correctness belongs to the `rust` and `profiles` jobs. The `+<MSRV>` pin
  takes rustup precedence over both `rustup default` and the toolchain file, so the check
  runs on the floor.
- **The leg pins the earliest patch, not the channel.** `rust-version` is a floor
  ("1.96 or newer works"), so two components is correct there, but `rustup` resolves a
  two-component channel to the newest patch in the series, which is a compiler newer than
  the claim. `scripts/ci-local.sh` therefore derives `MSRV_TOOLCHAIN` by appending `.0` and
  asserts the resolved `rustc -vV` release equals it. That earliest patch (`1.96.0`) does
  not coincide with the `rust-toolchain.toml` pin (`1.98.0`). `check-ci-gate.py` cannot
  catch this class of drift: it compares declared strings, not the compiler that ran.
- A dependency that raises its own `rust-version` above the MSRV fails the `msrv` job, and
  that failure is the ratchet's trigger: raise the floor or hold the dependency. If you
  bump a dependency, run the check locally:

  ```bash
  rustup toolchain install 1.96.0
  cargo +1.96.0 check --workspace --all-targets --locked
  cargo +1.96.0 check --workspace --all-targets --features full --locked
  ```

To raise the MSRV, change one value: `rust-version` in `[workspace.package]`. Everything
else derives from it. `scripts/ci-local.sh` reads it out of `Cargo.toml` with `sed`, and
the literal `1.96` beside it is an unreachable fallback, not a second place the number is
defined; the `msrv` job carries no `MSRV=` at all and calls `ci-local.sh msrv`. The
number is restated in prose here, in `README.md` and in `docs/deployment.md`, and every
restatement is bound to `Cargo.toml` by `scripts/tests/test_msrv_prose_bound.py`, which
fails on the first one that disagrees. Do it in one commit and call it out in your PR. The
`msrv` job's toolchain action is pinned to `stable`, not the MSRV: the runner installs and
pins the MSRV toolchain via `cargo +<MSRV>`, so there is no per-version action SHA to keep
in sync.

## Code style and conventions

Lint policy lives in the root `Cargo.toml` `[workspace.lints]` table and is inherited by
every crate via `[lints] workspace = true`, so a bare `cargo clippy` enforces the same set
the pipeline does. The policy:

- **`unsafe_code = "deny"`** — no `unsafe` Rust. `deny` rather than `forbid`, because
  `forbid` cannot be overridden in source, which would force the dev-only `test-util`
  crate to opt out of `[lints]` entirely and drop the whole workspace lint set from the
  one crate that carries `unsafe`. Under `deny` it inherits everything and scopes its
  exemption with a self-expiring `#[expect(unsafe_code, reason = "…")]` on the item.
  `test-util` is the single audited home for the `unsafe` `std::env::set_var`/`remove_var`
  that Rust 2024 requires, and its own
  `unsafe_code_is_allowed_only_in_the_audited_crate` guard fails the build if an
  allow/expect of that lint appears anywhere else. Tests must call
  `test_util::set_env`/`remove_env`, never `std::env` directly. If you believe you need
  `unsafe`, raise it in the PR first; the default answer is no.
- **No `.unwrap()` / `.expect()` in library code.** `clippy::unwrap_used` is on at `warn`,
  promoted to an error by `-D warnings`. Use `Result` and propagate with `?`. Prefer
  `thiserror` for library errors and `anyhow` for binaries. Both are permissible in tests.
- **`clippy::all` + `clippy::pedantic`** at `warn`. A noisy individual pedantic lint may
  be allowed back one at a time, with justification.
- **Suppressions use `#[expect(clippy::…, reason = "…")]`, not `#[allow]`.** An `expect`
  that no longer applies surfaces as a warning, so stale suppressions do not linger. Fix
  the root cause first; suppress only when unavoidable.
- **Formatting** is `cargo fmt` at rustfmt defaults. Run `cargo fmt --all` before
  committing; the `fmt` leg fails on `--check`.
- **Imports** grouped `std`, external crates, internal modules. Avoid wildcard imports
  except `use super::*` in test modules.
- **Async**: keep tasks cancellation-safe, especially in `tokio::select!`; never block the
  executor with sync I/O or heavy CPU; never hold a non-`Send` type across an `.await`.
- **Logging** via `tracing`, not `println!`/`eprintln!` in library code.
- **Documentation**: `///` docs on all public APIs, with panics under `# Panics` and
  errors under `# Errors`. Doc examples must compile and run.
- **No placeholders**: no `todo!()`, `// TODO`, or elided blocks. Write complete,
  compilable code.

### Comments say what is; the commit log says what changed

Comments are dense in this tree: an invariant that is stated but not bound is the failure
this guards against, so the *why* beside the code earns its place. Two rules keep the
rationale and the history apart.

**Write the rationale in the present tense, about the code that exists.** A reader needs
to know why the code must be this way, which is a claim about the alternative, not a story
about a previous revision. Prefer the counterfactual:

```rust
// NO:  `first_data_file_magic` used to swallow every error with `.ok()?`, so an EIO
//      arrived as Indeterminate and the sweep quarantined a healthy dataset.
// YES: An I/O fault says nothing about the data, so it must not reach the quarantine
//      path: withholding a dataset because one `read_dir` returned EIO turns a blip
//      into an operator-action outage.
```

The history is not lost. `git log -S'<phrase>' -p` and `git blame` find it, and the commit
that changed the behaviour is where a reader who needs the story will look. Put the story
in the commit message, at whatever length it deserves.

**A `///` doc on a type that derives `JsonSchema` is published.** `schemars` copies it
verbatim into `docs/*.schema.json`, a consumer-facing contract, so an internal note there
ships to every integrator as the normative description of a wire field, referring to
symbols they cannot see. Say what the field is in the `///` and put the rationale in a
`//` comment, which `schemars` cannot read.
`no_published_schema_description_names_a_rust_item` fails the build on a Rust path
separator in any published description.

## Adding a config field

The shipped example configs are pinned to the typed config by the drift guards in
`crates/gdi-node-standalone/tests/it/config_examples.rs`. Their requirements are not
obvious from the failure messages alone, so:

1. **Add the field** to its section struct in `crates/core/src/config/service.rs`, with a
   doc comment and a value in that struct's `Default`.
2. **Validate it** in `ServiceConfig::preflight`, so a bad value fails at boot rather than
   at the first request, and cover it in `crates/core/src/config/tests.rs`. The
   table-driven `assert_preflight_case` / `Expect` harness takes accept and reject cases.
3. **Document it in `node.example.toml`**, the exhaustive annotated reference:
   * a plain tuning knob must be shown at its built-in default. The guard compares every
     example leaf against `ServiceConfig::default()` and fails on any divergence;
   * if the example must instead show an illustrative deployment value, as `base_url`,
     `catalogs` and `keys.identities` do, add its dotted path to
     `EXAMPLE_OVERRIDE_PREFIXES` in the same test. That entry is itself checked for being
     used, so a prefix with no real deviation fails too.
4. Both config structs are `deny_unknown_fields`, so a stale or typo'd key in any shipped
   example, `compose/` included, fails the guard rather than being silently ignored.

There is a known gap, held by review rather than by the guard. The completeness check
derives its expected leaves from `ServiceConfig::default()`, so a field whose default
serializes to no leaf at all is not forced into `node.example.toml` by any test. The
discriminator is the serde attribute, not the type: `#[serde(skip_serializing_if = ...)]`
removes the leaf, while a bare `Option<T>` with no such attribute serializes to a `null`
leaf and is caught.
These structs apply `skip_serializing_if` to every `Option` and collection by convention,
so assume an `Option`, `Vec` or `String` field you add will not be caught. Every one of
them is documented today; keep it that way. Closing this in code would mean maintaining a
second copy of the field list, which is the drift a guard is meant to prevent.

A knob shown commented out (`# key = <value>`, as the `otel` knobs are) counts as
documented and satisfies completeness, so an opt-in feature does not have to ship an
active key.

## Dependencies and `Cargo.lock`

- **Shared deps are exact-pinned** in `[workspace.dependencies]`, for example
  `anyhow = "=1.0.104"`. Add new shared deps there, pinned with `=`, and match existing
  version constraints to avoid duplicate crate versions.
- **Pull deps with `default-features = false`** and enable only the features you use. This
  holds the C and assembly surface to the single `ring` dependency and keeps
  cross-compiles clean. The `arrow`/`parquet` subtree is the heaviest and is trimmed to
  the individual `arrow-*` sub-crates.
- **Do not add new external crates** without explicit confirmation in the PR. Prefer std
  and crates already in the tree.
- **Never hand-edit `Cargo.lock`.** If you change `Cargo.toml`, regenerate the lockfile
  with a plain `cargo check` (no `--locked`), then commit it so the `--locked` gates pass:

  ```bash
  cargo check        # regenerates Cargo.lock
  git add Cargo.lock
  ```

- **Supply chain.** `cargo deny check` is the single gate: it enforces the license
  allow-list, scans the RustSec advisory database, and applies the bans in `deny.toml`.
  `aws-lc-rs` and `aws-lc-sys` are denied outright, and `ring < 0.17.14` is denied because
  the 0.17.13 AVX2 regression breaks Windows cross-compiles. The `ignore` list is empty,
  and `-D advisory-not-detected` is what catches an ignore that outlives its advisory. It
  runs over the feature-independent `Cargo.lock`, so it sees `ring` regardless of which
  features a build enables. `cargo deny` subsumes the advisory scan, so a separate
  `cargo audit` is not needed, though it works as a local cross-check.
- **Never commit secrets** or generated config and state carrying credentials.

## Conventional Commits

This repository uses [Conventional Commits](https://www.conventionalcommits.org/). Keep
messages concise, imperative, and lowercase.

Format:

```
<type>(<optional scope>): <summary>

<optional body>

<optional footer, e.g. BREAKING CHANGE: ...>
```

Common types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`, `chore`.
Examples:

```text
feat: add trait implementation
fix(parser): resolve overflow panic
feat(beacon): pushdown POS filter into row-group pruning
docs(fairdp): document JSON-LD serialiser panic conditions
ci: pin ring floor in deny.toml bans
refactor(core): borrow &str in manifest validation

feat(core)!: change DatasetDecryptor key-retrieval signature

BREAKING CHANGE: DatasetDecryptor::new now takes a &KeyStore.
```

Breaking changes use a `!` after the type or scope, a `BREAKING CHANGE:` footer, or both.
Breaking a public library crate's API is reported by the advisory `semver-checks` job,
which does not block; bump the crate version accordingly. A breaking change to a public
wire contract — the Beacon `resultSets` shape or the FAIR Data Point graph — must also be
recorded under `## [Unreleased]` in `CHANGELOG.md` for downstream consumers.

## Cutting a release (maintainers)

Releases are tag-driven: pushing a `vX.Y.Z` tag runs `.github/workflows/release.yml`,
which cross-compiles every artifact, generates the SBOM and provenance, and publishes the
GitHub Release and container image. Several checks gate the publish, but they run only on
the tag, so the local gate is the only thing standing between you and a broken release.

**First, run `./scripts/ci-local.sh release` and get it green.** `release()` in
`ci-local.sh` is the authority. It is `all` plus thirteen further legs: `lint-docker`
(actionlint, promtool, shellcheck, compose and dockerfile-check), the `otel` aggregate,
`fuzz-short`, `vendored-check`, `licenses`, `coverage`, `e2e`, `e2e-observability` (the
one link the dashboard and promtool guards cannot check: that `/metrics` is actually
scraped and queryable), `cross`, `cross-arm`, `image-provenance`, `image-scan`, and
`e2e-full`. Budget for it: beyond Docker and `cross` it needs network, `cargo-llvm-cov`,
tens of GB in `target/`, and several GB of container images, and it runs for hours.

Then:

1. **Set the version to exactly what you are shipping.** Put it in `version` under
   `[workspace.package]`, **including any pre-release suffix**: `1.0.0-rc.1` for a
   candidate, `1.0.0` for the release. `version-guard` compares the tag to this string with
   no stripping and fails on any disagreement.

   The suffix belongs here and not only in the tag because this value is what the binary
   reports — `--version`, `GET /version`, the log preamble, `gdi_build_info` and the Beacon
   `info` response all read `CARGO_PKG_VERSION`. A candidate that called itself `1.0.0`
   could not be told apart from the release by an operator or by a federation aggregator.

   Write the suffix dotted (`-rc.1`, not `-rc1`): SemVer compares dot-separated all-digit
   identifiers numerically, so `-rc.11` sorts above `-rc.2`, while undotted it is a single
   alphanumeric identifier and `-rc11` sorts *below* `-rc2`.
2. **Refresh both lockfiles and the attribution bundle.** Run a build or check so
   `Cargo.lock` picks up the new version, and commit it, since the whole pipeline builds
   `--locked`.

   **A second lockfile.** `crates/core/fuzz/Cargo.lock` does not follow the bump. The fuzz
   crate is its own workspace and depends on `core` and `beacon` by path, so it records
   their versions; a bump leaves it stale and `fuzz-smoke` then fails with
   `cannot update the lock file … because --locked was passed`. Regenerate it with
   `cargo check --manifest-path crates/core/fuzz/Cargo.toml --bins` (no `--locked`) and
   commit it too.

   If
   the dependency closure changed, regenerate the attribution that ships with the binaries
   and inside the image — `cargo about generate about.hbs -o THIRD-PARTY-LICENSES.md` —
   and commit it. The `licenses` leg drift-guards this file but runs only in `release`, so
   treat regenerating it as mandatory rather than conditional.
3. **Roll the changelog.** `CHANGELOG.md` is minimal and hand-curated: under
   `## [Unreleased]`, record only consumer-facing and breaking changes as you develop, not
   every commit, since the full per-commit history is appended to the release body
   automatically. That guidance lives in an HTML comment under
   `## [Unreleased]` in `CHANGELOG.md`, which GitHub does not render, so it never leaks
   into a release body. To cut the release, add a `## [X.Y.Z] - YYYY-MM-DD` heading below
   that comment and move the body under it, leaving a fresh empty `[Unreleased]` above.
   Do not rename the `## [Unreleased]` heading itself, or the guidance comment moves into
   the versioned section with it. The "Assemble release notes" step fails if there is no
   `## [X.Y.Z]` section, so an un-rolled changelog blocks the release rather than being
   silently dropped.
4. **Commit and tag.** Commit the above, then tag that same commit `vX.Y.Z` and push the
   tag. A `v0.x` tag and any suffixed tag publish as pre-releases and do not move
   `:latest`; only a stable tag does.

   Update the version strings in the prose too. `README.md`, `docs/deployment.md`,
   `docs/gdi-dataset-tool.md`, `docs/operating.md` and `docs/testing.md` name the current
   release, and nothing checks them: `git grep 'v1\.0\.0-rc\.1'` finds the lot.
5. **What the tag enforces.** `release.yml` gates `publish` and `image` behind `gate`
   (`ci-local.sh rust supply-chain`), `version-guard`, and the changelog assembly, and
   `ci.yml` also runs on the tag. If anything is red, nothing publishes: fix and re-tag.

To ship a release candidate, set the version to `X.Y.Z-rc.N` and tag `vX.Y.Z-rc.N`.
`version-guard` requires the two to match exactly. `changelog-guard` and the release-notes
assembly still strip the suffix, deliberately: a candidate draws its notes from the
`## [X.Y.Z]` section it is a candidate *for*, so you do not roll a changelog section per
candidate. With the version at `1.0.0-rc.1` and a `## [1.0.0]` section rolled,
`v1.0.0-rc.1` satisfies both.

**A rehearsal is not a dry run.** `prerelease:` is set, but the GitHub Release is published
rather than drafted, every artifact is uploaded and attested, and `image` pushes and
attests `ghcr.io/…:<tag>`. Only `:latest` is withheld. To undo a rehearsal you must delete
both the Release *and* the GHCR tag; nothing does it for you.

**A pre-release binary says so**, because step 1 puts the suffix in the manifest and every
version surface reads it. An operator or an aggregator can tell a candidate from the release
over the wire.

## Branch protection (maintainers)

These are GitHub repository settings (Settings → Branches / Rulesets), not files, so a
maintainer with admin rights must enable them:

- **Require the `ci-success` status check** on the default branch, and only that one. It
  is the rollup that `needs:` every gate, so requiring it means a newly-added gate becomes
  required automatically, with no per-job checklist to maintain.
- **Require review from Code Owners — not yet possible.** The path map exists, but it is
  parked at `.github/CODEOWNERS.draft` and is therefore inert: GitHub reads code owners
  only from a file named exactly `CODEOWNERS` in `.github/`, the root, or `docs/`, so the
  suffix keeps it out of the lookup entirely.

  It is parked rather than deleted because the path list is the valuable part. It assigns
  the paths where a silent change would weaken a guarantee nothing else re-checks: the
  gate's own implementation, the CI and release pipeline, the Dependabot config, the supply
  chain (`deny.toml`, `Cargo.lock`, the hash-locked conformance requirement locks, the
  container and cross build definitions, the toolchain pin, the licence-attribution
  config), the disclosure-control and crypt4gh cores, the vendored conformance fixtures,
  and the Kubernetes deployment.

  To activate, in this order: substitute a real team or handle for every
  `@REPLACE-BEFORE-ENABLING-CODEOWNERS`, rename the file to `.github/CODEOWNERS`, then
  enable the toggle. Doing it in any other order leaves GitHub unable to resolve an owner,
  which blocks every pull request touching those paths and renders a "CODEOWNERS errors"
  banner on a publicly visible settings page.

## Behavioural principles

Four principles guide changes here:

- Think before coding: surface tradeoffs, state assumptions, and ask when unsure.
- Prefer the simplest thing: the minimum code that solves the problem, with no speculative
  generality.
- Keep changes focused: touch only what you must, and do not refactor adjacent code
  unprompted.
- Work to a goal: define what success is, verify it with tests, and loop until green.

## Before you open a PR

1. Run the full [local validation pipeline](#the-commands-the-runner-and-ci-enforce) and
   confirm it is green.
2. If you changed `Cargo.toml`, run a plain `cargo check` to regenerate `Cargo.lock` and
   commit it.
3. If you raised the MSRV, change the one value — `rust-version` in `[workspace.package]`
   — and note it in the PR. There is no `msrv` pin to update: `ci-local.sh` derives the
   value from `Cargo.toml`.
4. Use Conventional Commit messages.
5. If you changed a wizard prompt, re-record `docs/images/wizard.svg` with
   `scripts/demo/record-wizard.sh`; its header says what it needs.
6. Open the PR. Every job in [What each CI job runs](#what-each-ci-job-runs) must pass.
