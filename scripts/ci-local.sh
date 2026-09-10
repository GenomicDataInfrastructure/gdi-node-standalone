#!/usr/bin/env bash
# scripts/ci-local.sh — the validation gate for gdi-node-standalone.
#
# One definition of the check pipeline, invoked both by contributors and by the GitHub
# Actions workflow jobs, so the two cannot drift. Most targets need only `cargo`,
# `cargo-deny` and `cargo-nextest`. The Docker targets wrap the same pinned images the
# workflows use, so an image tag and its digest live in one place.
#
# Three things to know before running it:
#
#   * Nothing else runs these checks for you. Run `all` before calling a change done,
#     and `release` before a `v*` tag.
#   * `all` works without Docker. Its two Docker legs print a `SKIPPED` line instead of
#     failing, the final summary repeats it, and no green marker is recorded, so the
#     tree stays unverified until the tool is installed and `all` is re-run. `release`
#     and CI refuse the skip.
#   * `all` is slow enough to start in the background and keep working. `quick` and
#     `lint` are the fast rungs for the inner loop.
#
# Usage:
#   scripts/ci-local.sh [target ...]      # default target: all
#
# Composite targets:
#   all              the per-change gate. Verdicts about this tree run first, verdicts
#                    about the world (an upstream repo, an advisory database) run last,
#                    because the run stops at the first failure. A green run records a
#                    marker under target/, and the next run on an unchanged tree and
#                    toolchain re-runs only the legs whose verdict can move on its own.
#                    The legs, in order:
#                    script-tests + doc-attachment + secrets + k8s-manifests +
#                    ci-gate + workflow-tool-pins + vendored-files + dashboard +
#                    promtool + shellcheck + sbom + rust + profiles + doctests +
#                    doc + msrv + fuzz-smoke + conformance + crypt4gh + corpus +
#                    ruff + reuse + pins + supply-chain
#   release          the tag-time gate. It forces a complete `all`, makes external-pin
#                    drift fatal and refuses every skip, and it needs Docker, cross,
#                    trivy and cargo-about. Expect hours. The legs it runs:
#                    all + lint-docker + otel + fuzz-short + vendored-check + licenses +
#                    coverage + e2e + e2e-observability + cross + cross-arm +
#                    image-provenance + image-scan + e2e-full
#   quick            what the pre-commit hook runs: fmt + clippy-lite + script-tests
#   lint             every lint the tree can fail, no tests: fmt + clippy-lite +
#                    clippy-full + ruff. The middle rung between `quick` and `all`.
#                    `quick` compiles only the default features, so this is where
#                    feature-gated Rust gets linted, and `ruff` covers the Python no
#                    Rust lint sees. The pre-commit hook runs `ruff` only when Python is
#                    staged; this rung always runs it.
#   lint-docker      dockerfile-check + actionlint + promtool + shellcheck + compose.
#                    The name means lint using Docker; `dockerfile-check` is the member
#                    that lints the Dockerfiles. In `release`, and out of `all` apart
#                    from promtool and shellcheck, so a contributor without Docker can
#                    still run the per-change gate.
#   rust             fmt + clippy-lite + test-lite
#   profiles         the feature-gated build profiles: clippy-full + clippy-s3 +
#                    clippy-vault + clippy-no-default + feature-matrix + test-full +
#                    test-s3 + test-schema + graph + instrument-guard + serve-guard
#   supply-chain     deny + deny-fuzz + machete + pip-audit. cargo-deny cannot see
#                    Python, which is what pip-audit is here for.
#   otel             opt-in: clippy-otel + test-otel + graph-otel. The `otel` feature is
#                    a diagnostic that is never shipped, so it is out of `all`. Run it
#                    when you touch the OTLP export seam or bump opentelemetry/reqwest.
#                    It carries the wire-level assertion that exported spans omit query
#                    content, which exists only under `--features otel`.
#   harness          load + soak + crash-loop, the host-process harnesses. Each boots
#                    its own node and builds the release binaries if they are absent, so
#                    it takes minutes. Needs `oha`, `curl` and python3.
#
# Build, lint and test legs:
#   fmt              cargo fmt --all --check
#   clippy-lite      clippy over the default features
#   clippy-full      clippy with --features full (s3 + vault + pme)
#   clippy-s3        clippy with --features s3 only, no vault and no pme
#   clippy-vault     clippy with --features vault only, no s3 and no pme
#   clippy-no-default clippy --no-default-features, the lite-only arms
#   clippy-otel      clippy with --features full,otel
#   feature-matrix   compile the feature combinations no other leg builds
#   test-lite        the workspace suite on the default features
#   test-full        the suite with --features full, over the crates carrying gated code
#   test-s3          the s3-only suite; it fails if fewer than 500 tests run
#   test-schema      docs/*.schema.json freshness, the only leg that enables `schema`
#   test-otel        the service suite with --features full,otel
#   doctests         cargo test --doc (lite + full)
#   doc              cargo doc with -D warnings: broken intra-doc links, all features + lite
#   msrv             cargo +<MSRV> check --all-targets (lite + full), on the earliest
#                    patch of the declared floor. It installs that toolchain if absent
#                    and type-checks the whole graph cold, so budget for it.
#   graph            cargo-tree assertions: the lite graph is ring-free, and the s3 and
#                    full graphs link no aws-lc-sys, because the workspace standardises
#                    on ring for TLS
#   graph-otel       the same assertion for the full,otel graph
#   preflight-all    check every external tool `all` needs, and stop
#
# Guards (python3, no Docker):
#   script-tests     unit tests for the gate's own guards: this script's preflight list,
#                    gate-key/status/record, the pre-commit hook, dev-reset.sh and the
#                    load/soak checks. Stdlib only, and on the pre-commit path.
#   doc-attachment   no doc comment detached from the item it documents. It compares the
#                    working tree against HEAD~30 (the root commit on a shorter history),
#                    or against GDI_DOC_ATTACHMENT_BASE when set; CI passes the pull
#                    request's base commit. Not the staged-versus-HEAD default the
#                    pre-commit hook uses, which sees nothing on an unstaged tree.
#   k8s-manifests    the deploy/kubernetes contract guard. The only Python here that
#                    needs a third-party import: pip install -r
#                    scripts/tests/k8s/requirements.lock --require-hashes. In `all` and
#                    not in `quick`, so that import is not needed to commit.
#   ci-gate          workflow gate-graph integrity: every ci.yml job is a `ci-success`
#                    dependency, no un-allowlisted `if:` or `continue-on-error` sits on
#                    a gate, and rust-toolchain.toml still matches `rust-version`
#   workflow-tool-pins install-action `tool: <name>@<ver>` pins agree across ci.yml,
#                    release.yml and scheduled.yml
#   dashboard        the Grafana dashboard names only metrics the code emits
#   instrument-guard no auto-capturing #[instrument] on the serving or query path, where
#                    it would copy query arguments into exported spans
#   serve-guard      no bare `axum::serve(` on the serving path: both planes go through
#                    the bounded accept loop, which adds the header-read timeout and the
#                    connection cap that `axum::serve` has neither of
#   seams            cross-artifact facts: the code against the Dockerfile, the Compose
#                    stacks and the operator docs (the config path, the config file
#                    names, quoted defaults). These are tests, so `all` already runs
#                    them; this target runs them alone for a fast docs loop.
#   secrets          gitleaks over the working tree, so a secret is caught before it is
#                    committed rather than after. It runs the native binary, not a
#                    container, which is why it is in `all`. Exemptions are inline
#                    `gitleaks:allow` and there is no baseline file.
#   vendored-files   the vendored file count on disk matches each VENDORED.md, which
#                    catches a deleted file without touching the network
#   vendored-check   (network) every vendored file is byte-identical to its pinned
#                    upstream commit. Needs curl. In `release`, not in `all`, because a
#                    verdict that depends on an upstream host does not belong per change.
#
# Supply chain and artifacts:
#   deny             cargo deny check: advisories, licenses, bans and sources
#   deny-fuzz        the same advisory scan for the isolated cargo-fuzz workspace, whose
#                    own lockfile the scan above cannot see
#   machete          cargo machete, the unused-dependency gate
#   pip-audit        advisory scan of the conformance and crypt4gh Python lockfiles
#   sbom             cargo-cyclonedx SBOM generation
#   pins             (network) the external upstream pins (userportal refs, gdi-metadata
#                    lineage), the GitHub action pins (`uses: owner/repo@sha # tag`) and
#                    the Dockerfile base-image digest still resolve to what is pinned
#                    here. The base-image half needs Docker and skips visibly without
#                    it. Drift and an unreachable host are both warnings, because
#                    neither is a defect in this tree; `pins-strict` makes them fatal.
#   pins-strict      the same check with drift fatal, which is what `release` runs.
#                    Being behind is a warning per change and a failure at a tag.
#   licenses         cargo-about drift guard: THIRD-PARTY-LICENSES.md must match the
#                    shipped dependency graph. In `release`.
#   semver-checks    the public API of core, beacon and fairdp against $SEMVER_BASELINE
#                    (default HEAD). Advisory, slow, and in no composite target.
#   reuse            REUSE 3.3 licensing compliance: every file resolves to a copyright
#                    holder and an SPDX licence, via the directory annotations in
#                    REUSE.toml rather than ~600 per-file headers. Also asserts the two
#                    root LICENSE-* files still match their LICENSES/ counterparts, which
#                    are the same text in two places because the release and the images
#                    ship the root names while REUSE reads the SPDX-named ones.
#   ruff             lint and format check over the conformance/ and scripts/ Python
#   fuzz-smoke       the cargo-fuzz targets still compile; it does not fuzz
#   fuzz-short       a time-boxed run of every fuzz target (FUZZ_SECONDS, default 10
#                    seconds each; needs a nightly toolchain). In `release`.
#   mutants          the mutation audit, scripts/mutants-audit.sh. On demand, hours, and
#                    in no composite target; read that script's header first.
#   coverage         cargo-llvm-cov over --features full. The percentage is advisory,
#                    but the zero-coverage guard it also runs is not: that one fails on
#                    a file the suite never enters. In `release`, and out of `all` only
#                    because it is slow.
#
# Conformance and real data:
#   conformance      pySHACL and ckanext agree on both encodings (the venv is cached
#                    under target/; needs python3, and network on the first run)
#   crypt4gh         a Rust-to-Python crypt4gh round-trip against the pinned crypt4gh
#                    release (its venv is cached under target/venv)
#   corpus           real-data conformance: the pinned conversion of a 1000 Genomes and
#                    gnomAD chr21 slice, fetched once into target/corpus
#
# Docker targets:
#   actionlint       lint the workflow YAML and the shell embedded in it
#   promtool         the Prometheus alert rules parse, their unit tests pass, and the
#                    config parses. Also in `all`, where it skips visibly without Docker.
#   `shellcheck`     shellcheck over scripts/, compose/ and .githooks/. Also in `all`,
#                    where it skips visibly without Docker. Backticked because a comment
#                    whose first word is shellcheck is read as a directive.
#   compose          every shipped Compose stack parses, each invoked the way its own
#                    documentation prescribes
#   dockerfile-check BuildKit lint of both Dockerfiles, building nothing, plus a
#                    non-fatal note when an `@sha256:` pin in them has moved upstream
#   image-provenance build the image and assert it reports the commit and build epoch it
#                    was built with. In `release`.
#   image-scan       build the shipped image and Trivy-scan its OS layer; a fixable HIGH
#                    or CRITICAL CVE fails. In `release`.
#   cross            build-verify the five x86_64 Linux targets and the glibc floor
#                    guard, from the matrix in ci.yml. Needs Docker and `cross`, and
#                    tens of GB under target/. In `release`.
#   cross-arm        build-verify the two aarch64 Linux targets and the glibc floor,
#                    from the matrix in scheduled.yml. In `release`, so the tag gate
#                    covers aarch64 as well as x86_64.
#   e2e              the lite Compose-stack smoke test, scripts/e2e/run.sh
#   e2e-full         the Garage + OpenBao + PME at-rest crypt4gh round-trip,
#                    scripts/e2e/run-full.sh. The heaviest test here; in `release`.
#   e2e-observability the node's /metrics is scraped by Prometheus and queryable, the
#                    one link the dashboard and promtool guards cannot check
#   chaos            toxiproxy latency, reset and black-hole faults on the S3 and Vault
#                    wire. Out of `harness`, because it is the one that needs Docker.
#
# Harness legs (host processes):
#   load             an oha baseline (all 2xx) and a saturation run (shedding works).
#                    Boots its own node; needs `oha` and python3.
#   soak             the RSS, fd and thread plateau over SOAK_ROUNDS of sustained query
#                    load. Boots its own node; needs `oha` and python3.
#   crash-loop       kill -9 mid-write, then assert the store converges on reboot.
#                    Needs only curl.
#
# Maintenance:
#   sweep            reclaim stale target/ artifacts with cargo-sweep. `--installed`
#                    drops what a no-longer-installed toolchain built, `--maxsize`
#                    (${SWEEP_MAXSIZE:-20GB}) caps the rest. It deletes build artifacts,
#                    so it gates nothing and is in no composite target.
#   help             print this text
#
# Every run also warns, without failing, when HEAD is not rebased onto `main`: a green
# gate on a stale base is how parallel work breaks here. It does not block, because
# `main` can move again while the gate runs.
#
# Env:
#   MSRV             the minimum supported Rust the `msrv` leg checks (default:
#                    `rust-version` from Cargo.toml). The leg pins the earliest patch of
#                    that floor, so `1.96` verifies `1.96.0`.
#   CARGO_INCREMENTAL defaults to 0 here: gate legs are full builds, where incremental
#                    compilation buys nothing and costs real disk.
#   GATE_FORCE       set to 1 to ignore `target/.gate-ok` and run every leg of `all`,
#                    even when the tree and toolchain are unchanged since the last green
#   GATE_STRICT_LEGS set to 1 to make a leg that would otherwise skip on a missing tool
#                    die instead: `promtool` and `shellcheck` without Docker, and the
#                    kustomize renders inside `k8s-manifests` without kubectl.
#                    `release` exports it, and a CI runner (`CI` set) gets it
#                    unconditionally, because a skip there is a misconfigured runner.
#   GATE_TTL_HOURS   how long a green `all` marker stays valid (default: 24). It bounds
#                    how long a short-circuit can persist when something outside the key
#                    moves.
#   GATE_QUEUE       set to 0 to skip the machine-wide gate slot. By default every heavy
#                    target (`all`, `release`, the compiling legs of `all`, the
#                    whole-suite test legs; the GATE_QUEUE_LEGS array) runs under
#                    scripts/gate-queue.sh, so two checkouts on one machine run their gates
#                    one after the other instead of thrashing it. The fast rungs, and
#                    everything the pre-commit hook runs, never queue.
#   GATE_LOCK        the slot's lock file (default:
#                    /tmp/gdi-node-standalone-gate-<uid>.lock). One file per machine,
#                    shared by every checkout, because what they contend for is the CPU.
#   PINS_STRICT      set to 1 to make external-pin drift fatal instead of a warning.
#                    It is what the `pins-strict` target sets and what `release`
#                    exports.
#   SWEEP_MAXSIZE    the target/ ceiling for `sweep`, with an explicit unit (default:
#                    20GB). A unitless value is rejected, because cargo-sweep would read
#                    it as megabytes.
set -euo pipefail

# Gate legs are full builds across many feature sets, where incremental compilation buys
# nothing and costs real disk: target/ accumulates a separate artifact set per toolchain
# and feature-set combination, and that sprawl is what eventually forces a `cargo clean`,
# which makes the next gate run cold. The interactive inner loop (plain `cargo` outside
# this script) keeps incremental on, and an explicit `CARGO_INCREMENTAL=1` wins here.
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"

# Single-sourced from the workspace manifest so the floor cannot diverge from
# `rust-version`. An explicit `MSRV=…` still overrides, and the literal below is reached
# only when the manifest line is unreadable.
MSRV="${MSRV:-$(sed -n -E 's/^rust-version[[:space:]]*=[[:space:]]*"([0-9.]+)".*/\1/p' "$(dirname "${BASH_SOURCE[0]}")/../Cargo.toml" | head -1)}"
MSRV="${MSRV:-1.96}"

# `rust-version` is a floor — that version or newer works — so two components is correct
# there. rustup resolves a two-component channel to the newest patch in the series, which
# would verify a compiler newer than the floor. Pin the earliest patch of the floor
# instead: `X.Y` becomes `X.Y.0`. Three-component values and `nightly-*` pass through
# untouched, so an explicit `MSRV=…` override still means what it says.
MSRV_TOOLCHAIN="$MSRV"
[[ "$MSRV_TOOLCHAIN" =~ ^[0-9]+\.[0-9]+$ ]] && MSRV_TOOLCHAIN="${MSRV_TOOLCHAIN}.0"

# This script's absolute path, resolved before main() changes directory: the gate queue
# re-execs the script through scripts/gate-queue.sh, and `$0` may be relative to a cwd
# that main() has already left.
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/$(basename "${BASH_SOURCE[0]}")"

if [[ -t 1 ]]; then
  C_HEAD=$'\033[1;34m'; C_DIM=$'\033[2m'; C_OK=$'\033[1;32m'; C_ERR=$'\033[1;31m'; C_OFF=$'\033[0m'
else
  C_HEAD=''; C_DIM=''; C_OK=''; C_ERR=''; C_OFF=''
fi

step() { printf '\n%s==> %s%s\n' "$C_HEAD" "$*" "$C_OFF"; }
run()  { printf '%s$ %s%s\n' "$C_DIM" "$*" "$C_OFF"; "$@"; }

# --- Per-leg wall clock -------------------------------------------------------
# `timed <leg>` records each leg's seconds and `print_leg_timings` renders them after the
# run, slowest first, so a slow gate can be attributed to a leg. It wraps the dispatch
# rather than `step()`: a leg calls `step` once and then does arbitrary work after it, so
# timing `step` would measure the printf.
GATE_TIMINGS=()
GATE_SUB_TIMINGS=()

# Legs that may skip visibly instead of dying on a missing tool.
#
# `all` stays runnable without Docker, so a contributor on a locked-down machine can run
# the whole per-change gate. A leg whose tool is absent records a skip here rather than
# calling `die` as `need` does. Every skip is printed where it happens and repeated in the
# final summary, so "passed" is never printed over a leg that did not run. Under
# GATE_STRICT_LEGS=1 (`release` exports it) or on a CI runner (`CI` set, where a missing
# tool means a misconfigured runner), `record_skip` dies instead.
#
# A run that skipped a leg does not record the green marker. If it did, the next run on
# the same tree would short-circuit and print a clean "passed" with no skip line at all,
# over a leg that has still never run. `gate_record_green` refuses the marker; the run
# itself still passes with its skips in the summary, and the tree stays unverified until
# the tool is installed and `all` is re-run.
GATE_SKIPPED=()
# record_skip <leg> <reason>
record_skip() {
  local leg="$1" why="$2"
  if [[ "${GATE_STRICT_LEGS:-0}" == 1 || -n "${CI:-}" ]]; then
    die "$leg may not be skipped here ($why): GATE_STRICT_LEGS=1 or CI is set — install the tool."
  fi
  GATE_SKIPPED+=("$leg ($why)")
  printf '%sSKIPPED: %s (%s)%s\n' "$C_ERR" "$leg" "$why" "$C_OFF"
}
# skip_unless <tool> <leg> <consequence> — the optional-tool counterpart of `need`.
# Returns 1 after recording the skip, so a leg reads `skip_unless docker promtool "…" || return 0`.
# Not spelled `need`: test_ci_local_preflight.py demands every `need`ed tool of an `all`
# leg in preflight_all's required list, which would make `all` die up front on exactly the
# machine this exists for.
skip_unless() {
  local tool="$1" leg="$2" why="$3"
  command -v "$tool" >/dev/null 2>&1 && return 0
  record_skip "$leg" "$tool not installed — $why"
  return 1
}
print_skipped_legs() {
  (( ${#GATE_SKIPPED[@]} )) || return 0
  local entry
  printf '\n%s==> %d leg(s) SKIPPED — their verdict is unknown, not green%s\n' \
    "$C_ERR" "${#GATE_SKIPPED[@]}" "$C_OFF"
  for entry in "${GATE_SKIPPED[@]}"; do printf '  SKIPPED: %s\n' "$entry"; done
}
timed() {
  local t0=$SECONDS
  "$@"
  GATE_TIMINGS+=("$((SECONDS - t0)) $1")
}

# Sub-leg timing, for the aggregates that dominate the total: `profiles` is one label over
# a large fraction of the gate, which says where to look and nothing more. These are
# reported under their parent and not added to the total, so the top-level figures stay
# comparable across runs.
timed_sub() {
  local t0=$SECONDS
  "$@"
  GATE_SUB_TIMINGS+=("$((SECONDS - t0)) $1")
}

print_leg_timings() {
  (( ${#GATE_TIMINGS[@]} )) || return 0
  local total=0 entry secs
  for entry in "${GATE_TIMINGS[@]}"; do
    secs="${entry%% *}"
    total=$((total + secs))
  done
  printf '\n%s==> leg timings (slowest first; %ds total)%s\n' "$C_HEAD" "$total" "$C_OFF"
  # The slot wait happened before this process started (the wrapper re-execs), so it is
  # not in any leg and not in the total — but it is where a "slow gate" often went.
  if (( ${GATE_QUEUE_WAIT:-0} > 0 )); then
    printf '   queued %ds behind another gate before the first leg (not in the total)\n' \
      "$GATE_QUEUE_WAIT"
  fi
  printf '%s\n' "${GATE_TIMINGS[@]}" | sort -rn | while read -r secs name; do
    printf '  %5ds  %s\n' "$secs" "$name"
  done
  (( ${#GATE_SUB_TIMINGS[@]} )) || return 0
  printf '\n%s    within `profiles` (already counted above)%s\n' "$C_DIM" "$C_OFF"
  printf '%s\n' "${GATE_SUB_TIMINGS[@]}" | sort -rn | while read -r secs name; do
    printf '      %5ds  %s\n' "$secs" "$name"
  done
}
die()  { printf '%serror: %s%s\n' "$C_ERR" "$*" "$C_OFF" >&2; exit 1; }

# A guard that enumerates something must fail when the enumeration comes up empty.
# Otherwise "found nothing" and "found nothing wrong" are the same exit code, and the leg
# prints ok having verified nothing.
#
# A new enumeration site should call this rather than reinvent the judgement.
assert_nonempty() {  # assert_nonempty <value> <label> [hint]
  [[ -n "${1//[[:space:]]/}" ]] \
    || die "${2}: the enumeration came up empty, so this check verified nothing.${3:+ $3}"
}

# The counting variant, separate for a reason: `assert_nonempty "$count"` looks right and
# is wrong, because the string "0" is non-empty and sails through.
assert_positive() {  # assert_positive <count> <label> [hint]
  [[ "${1:-0}" =~ ^[0-9]+$ && "${1:-0}" -gt 0 ]] \
    || die "${2}: counted ${1:-0}, so this check verified nothing.${3:+ $3}"
}

# need <binary> <install-hint>
need() {
  command -v "$1" >/dev/null 2>&1 || die "required tool '$1' not found. install with: $2"
}

have_nextest() { cargo nextest --version >/dev/null 2>&1; }

# run_tests [extra cargo args...]
#
# The no-nextest fallback is unconditionally single-threaded: every leg here has tests
# that share process state, so none of them may run in parallel in one process.
run_tests() {
  # `--workspace` unless the caller named packages itself. cargo rejects `-p` together
  # with `--workspace`, and forcing the latter would make a scoped leg run the whole
  # workspace while still looking scoped.
  local scope=(--workspace)
  local arg
  for arg in "$@"; do
    if [[ "$arg" == "-p" || "$arg" == "--package" ]]; then
      scope=()
      break
    fi
  done
  if have_nextest; then
    if [[ -n "${CI:-}" ]]; then
      run cargo nextest run "${scope[@]}" --locked --profile ci "$@"
    else
      run cargo nextest run "${scope[@]}" --locked "$@"
    fi
  else
    # shellcheck disable=SC2016  # the backticked `cargo test` is literal text, not a command substitution
    printf '%sWARNING: cargo-nextest not found, falling back to plain `cargo test`. The two are not equivalent: nextest isolates every test in its own process, so a test sensitive to that isolation can pass here and fail under nextest. Install: cargo install cargo-nextest --locked%s\n' "$C_ERR" "$C_OFF"
    # --all-targets excludes doctests (the `doctests` target covers those).
    #
    # Always single-threaded. `test_util::set_env` interleaves with libc env readers on
    # other threads, so the suite is only sound one test at a time in a process. nextest
    # gets that from process isolation; this fallback buys it with one thread.
    #
    # Serialised through the env var, not `-- --test-threads=1`: everything after `--`
    # goes to every target `--all-targets` selected, including the `harness = false` bench
    # targets, and criterion's CLI rejects the flag outright. libtest honours
    # RUST_TEST_THREADS, the bench binaries ignore an env var they do not read, and
    # `--all-targets` coverage is kept.
    run env RUST_TEST_THREADS=1 cargo test "${scope[@]}" --all-targets --locked "$@"
  fi
}

fmt() { step "rustfmt --check"; run cargo fmt --all --check; }

# `target/debug/.gdi-clippy-warm` is `.githooks/pre-commit`'s marker for "clippy has
# completed in this worktree at least once"; the hook warns that it will build from cold
# only when the marker is absent. Every path that warms clippy must write it, or the next
# commit warns about a target/ that is in fact warm. It lives under target/, so it is
# already gitignored and `cargo clean` clears it with everything else.
clippy_lite()       { step "clippy — lite (default features)";        run cargo clippy --workspace --all-targets --locked -- -D warnings; mkdir -p target/debug && : > target/debug/.gdi-clippy-warm; }
clippy_full()       { step "clippy — full (s3 + vault + pme)";        run cargo clippy --workspace --all-targets --features full --locked -- -D warnings; }
# The S3 profile: `s3` alone, no vault and no pme (S3 ingest, file-based identity,
# volume-level at-rest; the common public-data deployment). Lints the s3-only cfg
# combination, so an item gated behind `s3` cannot depend on a vault- or pme-only symbol
# that the `full` pass would mask.
clippy_s3()         { step "clippy — s3 only (S3 profile: no Vault, no PME)"; run cargo clippy -p gdi-node-standalone --features s3 --all-targets --locked -- -D warnings; }
# `vault` alone, no s3 and no pme: Vault-sourced identity with inbox-only ingest. Not a
# documented deployment shape, but a selectable feature combination, and one whose defects
# the `full` pass masks because s3 and pme are on there.
clippy_vault()      { step "clippy — vault only (no S3, no PME)"; run cargo clippy -p gdi-node-standalone --features vault --all-targets --locked -- -D warnings; }
clippy_no_default() { step "clippy — lite-only (no-default-features)"; run cargo clippy -p gdi-node-standalone --no-default-features --all-targets --locked -- -D warnings; }
clippy_otel()       { step "clippy — full,otel (OTLP trace export)";   run cargo clippy -p gdi-node-standalone --features full,otel --all-targets --locked -- -D warnings; }

test_lite() { step "tests — lite";  run_tests; }
# The full profile (s3 + vault + pme), scoped to the crates that carry feature-gated code.
#
# `full` resolves to s3+vault+pme, and only `core` and `gdi-node-standalone` contain
# `cfg(feature = …)` for any of them. `beacon` is included because its `pme` feature
# forwards to core's, so its scan tests exercise a different `DatasetDecryptor` even though
# the crate carries no feature-gated code of its own. `gdi-dataset-tool` and `fairdp` have
# no feature gates, so under `--features full` their tests are identical to the ones
# `test_lite` already ran.
#
# Scoping it this way also stops the tool's slowest test, which proves a 15 s bound
# behaviourally and so has no honest fast version, from running a second time.
#
# Floor assertion, the same trap as `test_s3`, `test_schema` and `corpus`: a `-p` selector
# that stops matching exits 0.
test_full() {
  step "tests — full (s3 + vault + pme; the crates with feature-gated code)"
  local log
  log="$(mktemp)"
  run_tests -p gdi-node-standalone-core -p gdi-node-standalone-beacon \
    -p gdi-node-standalone --features full 2>&1 | tee "$log"
  local n floor=800
  n=$(parse_passed_count "$log")
  rm -f "$log"
  [[ "${n:-0}" -ge "$floor" ]] ||
    die "full leg ran ${n:-0} tests, expected >= $floor (did a -p selector stop matching?)"
  printf '%sok: full profile exercised %s tests%s\n' "$C_OK" "$n" "$C_OFF"
}
# The OTLP trace-export privacy test exists only under `--features otel`, so the default
# `test_full` never runs it and `clippy_otel` compiles it without executing it. Run the
# gdi-node-standalone suite under `full,otel` so the wire-level "exported spans omit query
# content" assertion actually runs.
test_otel() { step "tests — full,otel (OTLP trace-export privacy)"; run_tests -p gdi-node-standalone --features full,otel; }
# The S3 profile suite: the s3-gated code under `--features s3` alone, with vault and pme
# left out of the build, so their suites are cfg'd out.
#
# It runs single-threaded in the no-nextest fallback like every other leg: the s3 tests
# themselves share no network state, but the leg includes `core`, whose config suite
# mutates process env, plus the service's own env tests. The gated nextest path is
# unaffected and still gets process isolation per test.
#
# Scoped to the two crates that carry `cfg(feature = "s3")` code: the service
# (src/{s3,ingest_runtime,retire_identity,main}.rs, tests/it/{s3_reconcile,health_state})
# and core (tls.rs, s3_conn, lint_canary). `beacon`, `fairdp` and `gdi-dataset-tool` have
# none, so under `--features s3` their tests are byte-identical to the ones `test_lite`
# and `test_full` already ran.
#
# The floor assertion is the trap `test_schema` and `corpus` guard too: `cargo test` and
# nextest exit 0 when a `-p` selector matches nothing, so a crate rename would silently
# empty this leg. A floor rather than an exact count, because the failure guarded against
# is "ran almost nothing", not "ran one fewer".
test_s3()   {
  step "tests — s3 only (S3 profile; the crates with cfg(feature = \"s3\") code)"
  local log
  log="$(mktemp)"
  run_tests -p gdi-node-standalone -p gdi-node-standalone-core --features s3 2>&1 | tee "$log"
  local n floor=500
  n=$(parse_passed_count "$log")
  rm -f "$log"
  [[ "${n:-0}" -ge "$floor" ]] ||
    die "s3 leg ran ${n:-0} tests, expected >= $floor (did a -p selector stop matching?)"
  printf '%sok: s3 profile exercised %s tests%s\n' "$C_OK" "$n" "$C_OFF"
}
# The `docs/*.schema.json` freshness guard (`model_roundtrip.rs::schema_files_match_the_models`)
# is `#[cfg(feature = "schema")]`, and no other leg enables `schema`: `full` is s3+vault+pme,
# and the only `--all-features` uses are `doc` (compiles, runs nothing) and `semver-checks`
# (advisory, runs no tests). So without this leg the guard never executes anywhere, and a
# serde change silently ships stale schemas — the published type contract consumers
# validate against (docs/package-format.md, "Canonical type contract").
#
# Scoped to `-p …-core`: adding `schema` to `test_full` would make its feature set differ
# from clippy_full, doctests, msrv and graph, and rebuild the whole workspace a second time
# in the full configuration. `--all-features` is not an option either, because it would
# also switch on `fault-injection` (turning `faults::guard` from a no-op into a real check)
# and `otel`, changing test behaviour workspace-wide.
#
# The `1 passed` assertion is what keeps the leg honest: `cargo test <filter>` exits 0 when
# the filter matches zero tests, so a rename would leave this leg dormant and green. Same
# trap `assert_ignored_count` exists for.
test_schema() {
  step "tests — schema (docs/*.schema.json freshness guard)"
  local log
  log="$(mktemp)"
  run cargo test -p gdi-node-standalone-core --locked --features schema --test it schema_files \
    2>&1 | tee "$log"
  local n
  n=$(sed -n -E 's/.*test result: ok\. ([0-9]+) passed.*/\1/p' "$log" | tail -1)
  rm -f "$log"
  [[ "${n:-0}" -eq 1 ]] || die "schema leg ran ${n:-0} tests, expected 1 (was schema_files_match_the_models renamed or its cfg changed?)"
}

doctests() {
  step "doctests — lite + full"
  run cargo test --doc --workspace --locked
  run cargo test --doc --workspace --features full --locked
}

# Broken intra-doc-link gate. `cargo test --doc` compiles doc examples but does not check
# intra-doc links, so a module move or a method rename can leave a dangling [`path`] link
# that nothing catches. Build the docs with the lint promoted to an error and private
# items included, twice: once with all features, so feature-gated and private targets are
# linked too, and once on the lite default, the plain `cargo doc` a reader runs. A link to
# an s3-, vault- or pme-gated item resolves under the first and dangles under the second.
doc() {
  step "rustdoc — broken intra-doc links (all features, private items)"
  run env RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --workspace --all-features --document-private-items --locked
  step "rustdoc — broken intra-doc links (lite default features, private items)"
  run env RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --workspace --document-private-items --locked
}

deny() {
  step "cargo-deny (advisories + licenses + bans + sources)"
  need cargo-deny "cargo install cargo-deny --locked"
  # `-D advisory-not-detected`: an `ignore` in deny.toml is a claim about the outside world
  # ("no upstream fix exists yet"). Nothing here proposes the bump that would falsify such a
  # claim, so an expired mute reads as true forever. Promoting this diagnostic to an error
  # fails the gate the moment an ignored advisory stops matching anything, so a stale mute
  # is deleted rather than inherited.
  run cargo deny check --deny advisory-not-detected
  # The isolated cargo-fuzz crate carries its own lockfile, invisible to the scan above.
  # It is covered by `deny_fuzz`, which `supply_chain` runs next.
}

# Advisory scan of the isolated cargo-fuzz workspace (crates/core/fuzz).
#
# `crates/core/fuzz` is excluded from the root workspace (it builds only on nightly under
# `cargo +nightly fuzz`) and carries its own `Cargo.lock`, so the `cargo deny check` above,
# which resolves the root workspace, never sees one of its dependencies.
#
# `--locked` means a dependency bump that leaves the fuzz lock behind fails here, with a
# message naming the lock, instead of dropping the fuzz closure out of advisory coverage.
# Refresh it in the same change:
#   cargo generate-lockfile --manifest-path crates/core/fuzz/Cargo.toml
#
# Advisories only, not licenses, bans or sources: this is dev-only tooling that ships in no
# binary, so the policies the shipped graph must satisfy do not apply to it, and enforcing
# them here would only generate noise nobody can act on.
deny_fuzz() {
  step "cargo-deny — the isolated cargo-fuzz workspace (its own lockfile)"
  need cargo-deny "cargo install cargo-deny --locked"
  run cargo deny --locked --manifest-path crates/core/fuzz/Cargo.toml check advisories
}

machete() {
  step "cargo-machete (unused-dependency gate)"
  need cargo-machete "cargo install cargo-machete --locked"
  run cargo machete
}

# The Python half of the advisory scan. `cargo deny` covers every Rust crate and cannot see
# Python, so the conformance and crypt4gh closures (pyshacl, rdflib, lxml, and the
# cryptography/PyNaCl stack behind crypt4gh) would otherwise have no advisory gate. The
# hash-locked lockfiles make that closure reproducible; they do not make it audited, and a
# pinned-and-hashed vulnerable version is exactly as vulnerable.
#
# Audits the hash-locked lockfiles, the exact artifacts `ensure_venv` installs, in a
# throwaway uvx environment, so installing the auditor cannot perturb the venvs that produce
# the conformance and crypt4gh verdicts. `--strict` fails on any finding; add
# `--ignore-vuln <ID>` for a disputed or unfixable advisory, the `[advisories] ignore`
# analogue in deny.toml.
#
# The `.lock`, not the `.txt`: pip-audit resolves a requirements file, so auditing the
# loosely-pinned `.txt` reports on a dependency set that is not the one installed. An
# advisory against the pinned version, fixed in a newer one the resolution picks up, would
# be reported clean while the vulnerable package sat in the venv producing the verdict.
#
# Pinned like RUFF_VERSION: a pip-audit release must not be able to turn the gate red, or
# silently stop reporting, without a reviewed bump here.
PIP_AUDIT_VERSION='2.10.1'
pip_audit() {
  step "pip-audit — advisory scan of the installed Python closure (the lockfiles)"
  need uv "https://docs.astral.sh/uv/getting-started/installation/"
  local lock
  for lock in conformance/requirements.lock conformance/requirements-crypt4gh.lock; do
    [[ -f "$lock" ]] || die "pip-audit: $lock is missing — it is what ensure_venv installs"
    # `--no-deps` matches the workflow job: the lock is already a complete pinned closure.
    # Letting pip-audit re-resolve it would cost a network round-trip and reintroduce the
    # gap auditing the lock closes, because a resolution is not the installed set.
    run uvx "pip-audit@${PIP_AUDIT_VERSION}" --strict --no-deps -r "$lock"
  done
}

# Assert that <pkg> is absent from a feature-resolved dependency graph.
#
# Cargo's exit status must be inspected, not grep's: a failed `cargo tree` prints nothing,
# exactly like a graph that does not contain the package, so `cargo tree | grep -q` reports
# ok on a renamed feature having checked nothing. The statuses to tell apart:
#
#   -i <pkg in the lock, absent from this graph>  -> exit 0, empty stdout      success
#   -i <pkg present in this graph>                -> exit 0, output            failure
#   -i <pkg absent from the lock entirely>        -> 101 "did not match any packages"
#                                                                              success
#   --features <bogus>                            -> 101, some other message   error
#
# The last two both exit 101, so failing on non-zero is not enough. They are told apart by
# cargo's message: "did not match any packages" is the strongest form of absence, the crate
# is not in the dependency graph at all, while any other failure means the query never ran.
assert_pkg_absent_from_graph() {
  local pkg="$1" desc="$2"
  shift 2
  local out status
  # `&& … || …` keeps `set -e` from killing the script on a non-zero cargo exit, so the
  # status can be inspected rather than silently swallowed.
  out=$(cargo tree "$@" --edges no-dev --locked -i "$pkg" 2>&1) && status=0 || status=$?
  if [ "$status" -ne 0 ]; then
    # Not in the dependency graph at all, the strongest form of "absent", so the invariant
    # holds.
    if printf '%s\n' "$out" | grep -q 'did not match any packages'; then
      printf '%sok: %s (not in the graph at all)%s\n' "$C_OK" "$desc" "$C_OFF"
      return 0
    fi
    printf '%s\n' "$out" >&2
    die "cargo tree exited $status while asserting: $desc — the invariant was not checked (renamed feature?)"
  fi
  if printf '%s\n' "$out" | grep -q "^$pkg "; then
    printf '%s\n' "$out"
    die "$pkg is linked into $desc"
  fi
  printf '%sok: %s%s\n' "$C_OK" "$desc" "$C_OFF"
}

graph() {
  step "graph guarantee — lite is ring-free"
  assert_pkg_absent_from_graph ring \
    "the lite (default) service graph — it must be ring-free" \
    -p gdi-node-standalone --no-default-features

  step "graph guarantee — full has no aws-lc-sys"
  # The workspace standardizes on `ring`; the full feature-resolved graph must link no
  # `aws-lc-sys` (the C crypto backend). Distinct from cargo-deny, which scans the
  # feature-independent Cargo.lock.
  assert_pkg_absent_from_graph aws-lc-sys \
    "the full service graph — the workspace standardizes on ring" \
    -p gdi-node-standalone --features full

  step "graph guarantee — s3 has no aws-lc-sys"
  # The S3 profile (s3 only, no Vault or PME) links `ring` for TLS and SigV4 but must link
  # no `aws-lc-sys`. Asserted independently, so an object_store or reqwest bump cannot pull
  # aws-lc-rs into the s3-only graph, which the `full` assertion would mask.
  assert_pkg_absent_from_graph aws-lc-sys \
    "the s3 service graph — the workspace standardizes on ring" \
    -p gdi-node-standalone --features s3
}

# The `full,otel` half of the graph guarantee. Split out of `graph()` and into the
# opt-in `otel` aggregate: it is the only graph assertion whose subject is a feature
# that is never shipped, and asserting it needs a whole extra feature-resolved build.
graph_otel() {
  step "graph guarantee — full,otel has no aws-lc-sys"
  # The optional otel (OTLP export) feature must stay ring-only too. It selects no TLS
  # feature of its own, so under `full` it rides the workspace's ring-only rustls and the
  # `full,otel` graph must link no `aws-lc-sys` either. That keeps an otel or reqwest bump
  # from pulling aws-lc-rs in silently.
  #
  # `assert_pkg_absent_from_graph` inspects cargo's own exit status rather than grep's: a
  # bogus `--features` makes cargo exit 101 with empty stdout, which grep cannot tell apart
  # from a clean graph.
  assert_pkg_absent_from_graph aws-lc-sys \
    "the full,otel service graph — otel trace export must stay HTTP/ring-only" \
    -p gdi-node-standalone --features full,otel
}

# The crate `src/` trees that make up the serving/query path, shared by the two guards below
# so they cannot enumerate different sets. An explicit list rather than a `find`, because it
# encodes intent ("what serves traffic"): `gdi-dataset-tool` and `test-util` are excluded
# because an `#[instrument]` in an offline CLI captures nothing a client can reach.
#
# `assert_serving_path_dirs` is what makes the list trustworthy. `grep -r` over a path that
# does not exist prints nothing and exits non-zero, which after `2>/dev/null || true` is
# indistinguishable from a clean scan, so a crate rename would blind both guards while they
# kept printing ok.
SERVING_PATH_DIRS=(
  crates/core/src
  crates/beacon/src
  crates/fairdp/src
  crates/gdi-node-standalone/src
)

# Fail loudly when the enumeration above has gone stale. Call this as a plain statement:
# inside `$(...)` the `die` would exit only the subshell.
assert_serving_path_dirs() {
  local d
  for d in "${SERVING_PATH_DIRS[@]}"; do
    [[ -d "$d" ]] ||
      die "serving-path guard: '$d' does not exist — the source enumeration is stale (crate renamed or moved). Update SERVING_PATH_DIRS in scripts/ci-local.sh; until then neither guard's verdict means anything."
  done
}

# Privacy drift guard for OTLP trace export (logging.rs, docs/operating.md §16). The
# content-free guarantee excludes the `audit` target and relies on there being no
# `#[instrument]` on the serving or query path: it would auto-capture function arguments,
# such as beacon query coordinates, as span fields under a non-audit target and slip past
# the exclusion. This trips on the first one, so the author scrubs the fields (`skip_all`,
# no sensitive `fields(...)`) and extends the export filter and the wiremock test.
instrument_guard() {
  step "privacy guard — no auto-capturing #[instrument] on the serving/query path"
  # A plain statement, never inside the `$(...)` below: `die` in a command substitution
  # exits only the subshell, leaving `hits` empty and the guard printing ok.
  assert_serving_path_dirs
  local hits
  hits=$(grep -rnE '#\[(tracing::)?instrument' "${SERVING_PATH_DIRS[@]}" 2>/dev/null || true)
  if [[ -n "$hits" ]]; then
    printf '%s\n' "$hits"
    die "#[instrument] found on the serving/query path — review OTLP trace-export privacy (logging.rs export_target_allowed + the wiremock test) before allowing it"
  fi
  printf '%sok: no auto-capturing #[instrument] on the serving/query path%s\n' "$C_OK" "$C_OFF"
}

axum_serve_guard() {
  step "connection-bounds guard — no axum::serve on the serving path"
  # `axum::serve` has no header-read timeout and no connection cap; both planes must go
  # through the bounded hyper accept loop `main::serve_bounded` instead. A re-introduced
  # `axum::serve(` on the serving path is a gate failure rather than a review
  # responsibility. Scans src only; integration-test harnesses may serve freely.
  assert_serving_path_dirs # plain statement, for the reason given in `instrument_guard`
  local hits
  hits=$(grep -rnE 'axum::serve\(' "${SERVING_PATH_DIRS[@]}" 2>/dev/null || true)
  if [[ -n "$hits" ]]; then
    printf '%s\n' "$hits"
    die "axum::serve found on the serving path — route it through main::serve_bounded (bounded header-read timeout + connection cap); axum::serve has neither"
  fi
  printf '%sok: no axum::serve on the serving path%s\n' "$C_OK" "$C_OFF"
}

msrv() {
  step "MSRV — cargo +$MSRV_TOOLCHAIN check --all-targets (lite + full; dev-dependencies count)"
  # `$MSRV_TOOLCHAIN` is the earliest patch of the declared floor `$MSRV`, derived near the
  # top of this file, never the floating two-component channel.
  #
  # Budget for this leg. The floor is a ratchet below the rust-toolchain.toml pin and cargo
  # keys artifacts by toolchain, so the two checks below share nothing with the rest of
  # target/ and are cold whole-graph type-checks. `--all-targets` compiles the test and
  # bench targets too: a plain `check` never builds dev-dependencies, so a dev-dependency
  # whose own floor is above the MSRV would pass unnoticed.
  #
  # The explicit `+` pin is what keeps the check on the MSRV once the floor drops below the
  # dev toolchain: by rustup precedence the toolchain file beats `rustup default`, so only
  # an explicit `+<ver>` guarantees the compiler being verified is the floor.
  need rustup "https://rustup.rs"
  if ! rustup toolchain list 2>/dev/null | grep -q "^${MSRV_TOOLCHAIN}"; then
    run rustup toolchain install "${MSRV_TOOLCHAIN}" --profile minimal --no-self-update
  fi
  # Compare what actually ran, not what was declared. A two-component channel resolving to
  # a newer patch is invisible to `check-ci-gate.py`, which compares only the declared
  # strings in Cargo.toml and rust-toolchain.toml.
  local got
  got="$(rustup run "${MSRV_TOOLCHAIN}" rustc -vV | sed -n 's/^release: //p')"
  [[ "$got" == "${MSRV_TOOLCHAIN}" ]] ||
    die "MSRV leg resolved to rustc ${got}, expected ${MSRV_TOOLCHAIN} — the floor is not being verified"
  run cargo "+${MSRV_TOOLCHAIN}" check --workspace --all-targets --locked
  run cargo "+${MSRV_TOOLCHAIN}" check --workspace --all-targets --features full --locked
}

# --- Docker-based lint targets (the same pinned images the workflow jobs run) ---
# Unlike the pure-cargo targets above, these need Docker. The digests here are the single
# source for both local runs and the `actionlint`, `promtool` and `shellcheck` workflow
# jobs, which invoke these targets, so a version and its digest cannot drift apart. Bump
# the tag and the digest together: Dependabot does not see an inline `docker run` image,
# so these are bumped by hand.
ACTIONLINT_IMAGE='rhysd/actionlint:1.7.12@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667'
PROMETHEUS_IMAGE='prom/prometheus:v3.14.0@sha256:5ce7540c3c00ef4ab0c9d2c995c6a5b9c421f44b4a115d97a2c7af3b1c21cbb0'
SHELLCHECK_IMAGE='koalaman/shellcheck:v0.11.0@sha256:61862eba1fcf09a484ebcc6feea46f1782532571a34ed51fedf90dd25f925a8d'
# No GITLEAKS_IMAGE: `secrets` runs the native binary so it can sit in `all` rather than in
# the Docker-only `lint-docker`. Going native gives up the digest pin, so this floor
# replaces it. It is enforced in `secrets`, not merely declared here.
GITLEAKS_MIN_VERSION='8.30.1'

# The same floor, for the same reason, for the other native scanner. `image-scan` asserts
# no fixable HIGH or CRITICAL CVE in the shipped base, and an old trivy reports exactly
# that about a base it cannot analyse: a false green on the artifact that ships. `need`
# proves presence, and presence is not a version. A floor rather than the exact pin the
# workflows install, because exact-pinning a scanner blocks a security fix while a newer
# one can only fail loudly. Keep it at or below the workflow pin, and do not mirror that
# value here.
# This guards the binary. Trivy fetches its vulnerability database itself and refuses to
# run on a hopelessly stale one, so database freshness is not this floor's job.
TRIVY_MIN_VERSION='0.72.0'

actionlint() {
  step "actionlint — workflow + embedded-shell lint (.github/workflows/)"
  need docker "https://docs.docker.com/get-docker/"
  run docker run --rm -v "$PWD:/repo" --workdir /repo "$ACTIONLINT_IMAGE" -color
}

promtool() {
  step "promtool — Prometheus rules + config check"
  # In `all`, so `skip_unless` rather than `need`: without Docker this leg skips visibly.
  # `release` and CI refuse the skip.
  skip_unless docker promtool "alert rules NOT checked" || return 0
  run docker run --rm --entrypoint promtool -v "$PWD/compose/observability:/obs:ro" \
    "$PROMETHEUS_IMAGE" check rules /obs/rules/gdi-node-standalone.yml
  run docker run --rm --entrypoint promtool -v "$PWD/compose/observability:/obs:ro" \
    "$PROMETHEUS_IMAGE" check config /obs/prometheus.yml
  # Unit tests: every rule fires on the input it was written for, and the guarded ones
  # stay quiet on the input they must ignore. `check rules` above proves only that the
  # file parses; a threshold with the comparison inverted parses fine.
  run docker run --rm --entrypoint promtool -v "$PWD/compose/observability:/obs:ro" \
    "$PROMETHEUS_IMAGE" test rules /obs/rules/tests/gdi-node-standalone.test.yml
}

compose_config() {
  step "compose — every shipped stack parses (incl. the chaos overlay's own profile)"
  need docker "https://docs.docker.com/get-docker/"
  # Each overlay is validated the way its own docs tell an operator to invoke it. The chaos
  # overlay is why this leg exists: `toxiproxy` is profile-gated while the node
  # `depends_on` it, so without `--profile chaos` Compose rejects the whole project
  # ("depends on undefined service") and the fault-injection stack cannot start at all.
  run docker compose -f docker-compose.yml config -q
  run docker compose -f docker-compose.yml -f docker-compose.s3.yml config -q
  run docker compose -f docker-compose.minimal.yml config -q
  # docker-compose.external.yml is not validated here. It is the bring-your-own stack, and
  # its `.env.external.example` ships `<SET ME: ...>` placeholders that cannot interpolate
  # ("invalid spec: ... too many colons"). Validating it would mean inventing operator
  # values, which proves nothing about the file an operator will use.
  run docker compose -f docker-compose.observability.yml config -q
  # The overlay's own header documents this combination, and scripts/e2e/run-observability.sh
  # depends on it. Validating the overlay alone would not catch a merge conflict with the
  # stack it is layered onto.
  run docker compose -f docker-compose.minimal.yml \
    -f docker-compose.observability.yml config -q
  # The overlay's header lists the full-stack combination first, and it is the harder merge
  # of the two: the base node carries long-form `depends_on` (condition: service_healthy)
  # plus the `<<: *node-security` / `logging: *default-logging` anchors, while the overlay
  # overrides it with short-form `depends_on: [alloy]`. Minimal has no `depends_on` at all,
  # so that combination merges a list into nothing and exercises none of this. The minimal
  # pairing also has a second net in scripts/e2e/run-observability.sh; this one has none.
  run docker compose -f docker-compose.yml \
    -f docker-compose.observability.yml config -q
  run docker compose --profile chaos \
    -f docker-compose.yml -f docker-compose.chaos.yml config -q
}

# Every Dockerfile in this repo. All are linted and all have their pins watched: the ops
# sidecar image (Dockerfile.ops, a shell, tar and the two static musl binaries for the
# Kubernetes inbox shape) carries its own frontend, builder and runtime pins, and a pin
# nothing watches freezes silently. Enumerated rather than listed, so a third Dockerfile
# cannot escape both guards by not being named.
_dockerfiles() {
  find . -maxdepth 1 -type f -name 'Dockerfile*' -printf '%f\n' | LC_ALL=C sort
}

# Emits "<ref> <sha256:…>" for every digest-pinned image in $1 (default: Dockerfile): the
# line-1 `# syntax=` frontend directive and each `FROM <ref>@<digest>`. Stages carrying no
# digest (`FROM scratch`, `FROM ${BIN_SOURCE}`) have nothing to compare and are skipped.
# Kept as its own function so the parse is unit-testable without Docker or a network.
_dockerfile_digest_pins() {
  sed -n \
    -e 's/^# *syntax=\([^@[:space:]]*\)@\(sha256:[0-9a-f]*\).*/\1 \2/p' \
    -e 's/^FROM[[:space:]]\{1,\}\([^@[:space:]]*\)@\(sha256:[0-9a-f]*\).*/\1 \2/p' \
    "${1:-Dockerfile}"
}

# The same, across every Dockerfile, de-duplicated: the two files share the frontend and
# builder pins, and reporting one drift twice trains people to skim the notes.
_all_dockerfile_digest_pins() {
  local f
  while read -r f; do
    _dockerfile_digest_pins "$f"
  done < <(_dockerfiles) | sort -u
}

dockerfile_check() {
  step "dockerfile — BuildKit lint of the image definition (resolves bases, builds nothing)"
  need docker "https://docs.docker.com/get-docker/"
  # `lint-docker` lints *using* Docker (actionlint, promtool, shellcheck, compose); this
  # leg lints the Dockerfiles themselves. It is the only per-change check of the builder
  # stage: `image-scan` and `image-provenance` are both outside `all`, and the released
  # image is assembled from the `prebuilt` stage, which never enters `builder`.
  #
  # `--check` runs BuildKit's own rule set and resolves the pinned base images without
  # executing a build step, so it costs seconds against the tens of minutes of a real
  # `image-scan`.
  #
  # What it does and does not catch, measured against mutations of this Dockerfile:
  #   caught  lowercase `as` in `FROM ... as builder`            (FromAsCasing)   -> exit 1
  #   caught  `COPY --from=` naming a stage that does not exist                   -> exit 1
  #   missed  `${VAR}` used in a RUN with no matching `ARG`                       -> exit 0
  #   missed  a typo'd `${FEATURES_TYPO}` in a RUN                                -> exit 0
  # Docker does not substitute an unknown build arg; it hands the text to the shell, which
  # expands it to empty, so a mis-plumbed ARG is not a lint violation at all. This leg is a
  # cheap floor for structural and style mistakes, not a check that the image carries what
  # it should. `image-provenance` binds that, by building and asking the binary.
  #
  # Both Dockerfiles, because both ship: the service image and the ops sidecar image the
  # Kubernetes inbox shape needs (Dockerfile.ops).
  local dockerfile
  while read -r dockerfile; do
    run docker build --check -f "$dockerfile" .
  done < <(_dockerfiles)

  # Upstream-movement watch for every digest-pinned image in both files: the syntax
  # frontend that supplies the rules `--check` just ran, the shared Rust builder base, and
  # the two runtimes (distroless for the service, Alpine for the ops sidecar).
  # Pinning buys reproducibility and keeps arbitrary new code out of the build, but
  # Dependabot bumps none of the three, so without a watch a pin freezes silently. For the
  # frontend that means a linter reporting clean on rules it never learned; for the two
  # bases it means continuing to ship the layer a rebuild was published to replace.
  #
  # It watches every pin, not just the frontend: a builder base can be rebuilt under a
  # still-valid tag, and only a watch on that pin reports it.
  #
  # The same split the conformance legs use: `check` compares against the pin and so can
  # never see upstream move; a separate drift report is what sees it.
  #
  # Non-fatal: upstream moving is news, not a defect in this tree, and it must not turn an
  # offline run red. Fetch failure is per-image silent for the same reason. `set -o
  # pipefail` is in force, so the fetch must carry `|| upstream=""` or an unreachable
  # registry kills the leg outright.
  local pins ref pinned upstream hint
  pins="$(_all_dockerfile_digest_pins)"
  # A guard that enumerates must fail when the enumeration comes up empty (see `die` above):
  # if a Dockerfile reformat breaks the parse, a watch that silently checks nothing is
  # indistinguishable from one that checked everything and found it clean.
  [[ -n "$pins" ]] || die "no digest-pinned images parsed from the Dockerfiles — the watch would be a no-op"
  while read -r ref pinned; do
    [[ -n "$ref" ]] || continue
    upstream="$(docker buildx imagetools inspect "$ref" 2>/dev/null \
      | sed -n 's/^Digest: *\(sha256:[0-9a-f]*\).*/\1/p')" || upstream=""
    [[ -n "$upstream" ]] || continue          # unreachable or offline: stay silent
    [[ "$pinned" != "$upstream" ]] || continue
    case "$ref" in
      docker/dockerfile*) hint='newer frontends add check rules; refresh the `# syntax=` line' ;;
      *)                  hint='base rebuilds are normally CVE fixes; refresh the `FROM …@sha256:` pin' ;;
    esac
    printf '%snote: %s has moved past its pinned digest%s\n' "$C_DIM" "$ref" "$C_OFF"
    printf '%s      pinned   %s%s\n' "$C_DIM" "$pinned" "$C_OFF"
    printf '%s      upstream %s%s\n' "$C_DIM" "$upstream" "$C_OFF"
    printf '%s      %s%s\n' "$C_DIM" "$hint" "$C_OFF"
  done <<< "$pins"
}

# Observability drift + coverage guard: the hand-maintained dashboard JSON is not
# promtool-linted, and promtool never checks metric existence anyway. This cross-
# references the metric names metrics.rs declares against the dashboard and alert rules: no
# charted series may reference a renamed/removed metric, and no declared metric may
# be left unobserved (uncharted AND unalerted AND not allowlisted). Pure-Python, no
# Docker.
dashboard() {
  step "dashboard — Grafana drift + metric coverage check"
  need python3 "https://www.python.org/downloads/"
  run python3 scripts/check-dashboard-metrics.py
}

# Doc-attachment guard: an item inserted between a doc comment and the item it documents
# silently re-parents that doc, so the inserted item carries two docs and the victim
# carries none. It compiles, `cargo doc` is happy, and `missing_docs` does not see it,
# because a doc is present on the thief and the victim is usually private.
#
# .githooks/pre-commit runs the same script in its default mode, `git diff --cached`, which
# is right for a hook and blind to uncommitted work. `all` runs before committing, when the
# tree is dirty, so this leg compares the working tree against a revision instead.
#
# It does not fire on the two legitimate operations that would otherwise make it noise:
# renaming a documented item, or deleting an item together with its doc. It fires only when
# an item that still exists lost its doc.
#
# It is a diff guard, so a green leg is not a claim about the whole tree. It compares
# per-name against the given revision and can only see an item lose a doc it had there. A
# doc stolen between two items that are both new in the working tree has no "before" for
# either name, and is invisible to it.
#
# The revision is thirty commits back rather than HEAD, because HEAD is clean on every
# clean tree: a detachment that already reached a commit (a bypassed hook, a merge, a
# commit made from another checkout) would never be seen again. The single-revision form
# compares the working tree against that revision, so it covers the uncommitted work as
# well as the last thirty commits. A detachment older than that is what a one-off
# `--range <sha>` sweep is for. On a shorter history, the root commit.
doc_attachment() {
  step "doc-attachment — no doc comment detached from the item it documents"
  need python3 "https://www.python.org/downloads/"
  local base
  # `GDI_DOC_ATTACHMENT_BASE` lets a caller name the revision to diff against; CI passes
  # the pull request's base commit, which is the honest "before" for the change under
  # review. It also repairs the one case the HEAD~30 default cannot cover: immediately
  # after a history squash the root commit *is* HEAD, so the fallback diffs the working tree
  # against HEAD and sees only uncommitted work. That lasts until a second commit exists.
  base="${GDI_DOC_ATTACHMENT_BASE:-}"
  if [[ -n "$base" ]]; then
    git rev-parse --verify --quiet "$base^{commit}" >/dev/null ||
      die "GDI_DOC_ATTACHMENT_BASE='$base' is not a commit in this repository. Leave it unset to use the default HEAD~30 window"
  else
    base="$(git rev-parse --verify --quiet HEAD~30 || git rev-list --max-parents=0 HEAD | tail -1)"
    if [[ "$(git rev-parse "$base")" == "$(git rev-parse HEAD)" ]]; then
      printf '%sWARNING: doc-attachment has no history to diff against (the root commit is HEAD), so it can only see uncommitted work. Pass GDI_DOC_ATTACHMENT_BASE to widen it.%s\n' "$C_ERR" "$C_OFF"
    fi
  fi
  run python3 scripts/check-doc-attachment.py --range "$base"
}

# The scripts/tests suite: unit tests for the shell and Python that guard this gate —
# this script's own preflight list, the gate-key/status/record trio, the pre-commit hook,
# dev-reset.sh, the deploy/kubernetes contract, and the load/soak check modules.
#
# Its own leg, rather than a glob inside `dashboard`, so the banner names what it runs and
# no guard file is run twice per gate. It runs first in ALL_LEGS: it takes seconds, so a
# broken guard surfaces before the rest of the pipeline rather than after it.
#
# Stdlib only. This leg is in `quick`, so it runs on the pre-commit path, where a missing
# third-party module would hard-fail every commit touching scripts/. The one file that
# needs an import (test_k8s_manifests.py, PyYAML) lives in scripts/tests/k8s/ behind its
# own leg. A test added under scripts/tests/ may import stdlib and _helpers only.
script_tests() {
  step "script-tests — unit tests for the gate's own shell + Python guards"
  need python3 "https://www.python.org/downloads/"
  # Assert the discovery actually found them. Discovery is a glob, and nothing downstream
  # notices a smaller set: rename a file off `test_*.py`, move it into a subdirectory
  # (unittest does not recurse into non-packages), or let a TestCase lose its `test_`
  # prefix, and discovery reports a smaller green run. A floor rather than an exact count:
  # tests are added freely, none may vanish.
  #
  # The floor is not the binding, though: a whole file can leave the glob without dropping
  # the total below it. What binds "a test file left the glob" is the set comparison below.
  # Every `.py` in scripts/tests, bar the `_helpers` module, must have contributed at least
  # one test to this run, read off unittest's own `-v` listing. Every `.py`, not every
  # `test_*.py`: a file renamed off the glob leaves both sides of a `test_*.py` comparison
  # and is invisible to it. The set never churns on an added test and cannot be satisfied
  # by a file discovery did not load. The floor stays, close to actual, for the one shape
  # the set cannot see: a file that survives with its cases renamed off `test_`.
  local log
  log="$(mktemp)"
  run python3 -m unittest discover -v -s scripts/tests -p 'test_*.py' 2>&1 | tee "$log"
  local n floor=430
  n=$(sed -n -E 's/^Ran ([0-9]+) tests? in .*/\1/p' "$log" | tail -1)
  local on_disk discovered missing
  on_disk="$(find scripts/tests -maxdepth 1 -name '*.py' ! -name '_*' -printf '%f\n' | sed 's/\.py$//' | LC_ALL=C sort)"
  # `-v` prints one `test_x (module.Class.test_x) ... ok` line per test; the module is the
  # first dotted component inside the parentheses.
  discovered="$(sed -n -E 's/^[A-Za-z0-9_]+ \(([A-Za-z0-9_]+)\.[A-Za-z0-9_.]+\).*/\1/p' "$log" | LC_ALL=C sort -u)"
  missing="$(comm -23 <(printf '%s\n' "$on_disk") <(printf '%s\n' "$discovered"))"
  rm -f "$log"
  [[ -z "$missing" ]] ||
    die "scripts/tests file(s) on disk contributed NO test to this run: $(printf '%s ' $missing)— renamed off the test_*.py glob, no test_ method, or a failed import"
  assert_positive "$(printf '%s\n' "$discovered" | grep -c .)" "script-tests" "no test module parsed from unittest's -v listing — the module-set check would pass vacuously"
  [[ "${n:-0}" -ge "$floor" ]] ||
    die "scripts unit tests ran ${n:-0}, expected >= $floor — cases left a file that still exists (if the removal was intended, lower the floor in the same commit)"
  printf '%sok: scripts unit tests exercised %s tests across %s files%s\n' "$C_OK" "$n" "$(printf '%s\n' "$discovered" | grep -c .)" "$C_OFF"
}

# The deploy/kubernetes/ contract guard, split from `script-tests` because it is the only
# Python here that needs a third-party import. PyYAML is the right call for it, since
# regex-parsing nested YAML for `securityContext.fsGroup` would be a guard you could not
# trust, but it does not justify a hard dependency on the pre-commit path. These manifests
# are an example base that changes a couple of times a year, so the guard belongs in `all`
# rather than `quick`. Discovery runs from scripts/tests/k8s/ with scripts/tests on
# PYTHONPATH, so the suite shares _helpers rather than recomputing the repo root.
k8s_manifests() {
  step "k8s-manifests — deploy/kubernetes contract guard (PyYAML)"
  need python3 "https://www.python.org/downloads/"
  # The pin and its hash-lock must agree, or CI installs a version nothing reviewed.
  assert_lock_current scripts/tests/k8s/requirements.txt scripts/tests/k8s/requirements.lock
  python3 -c 'import yaml' 2>/dev/null \
    || die "python3 module 'yaml' (PyYAML) not found. This leg imports it with the ambient python3, so install into a virtualenv and run the gate from that shell: uv venv && . .venv/bin/activate && uv pip install -r scripts/tests/k8s/requirements.lock --require-hashes"
  local log
  log="$(mktemp)"
  run env PYTHONPATH=scripts/tests python3 -m unittest discover -s scripts/tests/k8s -p 'test_*.py' 2>&1 | tee "$log"
  # Keep the floor within one class of the actual count, so a dropped class is a red
  # rather than a smaller green.
  local n floor=50 skipped
  n=$(sed -n -E 's/^Ran ([0-9]+) tests? in .*/\1/p' "$log" | tail -1)
  # unittest counts a skipped test as run, so the floor alone cannot see it. The only skips
  # in that suite are the `kubectl kustomize` renders, the one assertion that catches an
  # overlay that does not build, so surface them as a gate-level skip.
  skipped=$(sed -n -E 's/^OK \(skipped=([0-9]+)\)$/\1/p' "$log" | tail -1)
  rm -f "$log"
  [[ "${n:-0}" -ge "$floor" ]] ||
    die "k8s manifest guard ran ${n:-0} tests, expected >= $floor (if the removal was intended, lower the floor in the same commit)"
  if [[ "${skipped:-0}" -gt 0 ]]; then
    record_skip k8s-manifests "$skipped test(s) skipped: kubectl not installed, so the kustomize renders are NOT checked"
  fi
  printf '%sok: k8s manifest contract exercised %s tests%s\n' "$C_OK" "$n" "$C_OFF"
}

# Gate-integrity guard: `ci-success` is the one required check, and this leg is what makes
# its promise ("a gate cannot silently stop being enforced") true. Asserts every ci.yml
# job is a `ci-success` dependency, that no gate gains an `if:`/`continue-on-error`
# without an allowlist entry, and that the rust-toolchain.toml dev pin still matches the
# declared MSRV. Pure-Python, no Docker — cheap enough for the `all` pipeline.
ci_gate() {
  step "ci-gate — CI gate-graph integrity + toolchain/MSRV coherence"
  need python3 "https://www.python.org/downloads/"
  run python3 scripts/check-ci-gate.py
}

# Ruff — lint + format check over the project's Python (conformance checkers + gate/harness
# scripts). Everything shipped is Rust, but this Python guards the Rust gate, so it gets the
# same treatment. Run through `uvx` at an EXACT pin: uv is already required to
# regenerate the conformance lockfiles, so this adds no new prerequisite, and pinning means a
# ruff release cannot turn the gate red (or silently stop enforcing a rule) without a
# reviewed bump here. Rules are pinned in ruff.toml for the same reason.
RUFF_VERSION='0.16.4'
ruff() {
  step "ruff — lint + format check (conformance/ + scripts/)"
  need uv "https://docs.astral.sh/uv/getting-started/installation/"
  # Check the config before running ruff, not after. A target-version above the pin makes
  # ruff rewrite these scripts into syntax the older interpreter rejects, and `format
  # --check` would then fail with a bare diff that says nothing about the cause.
  # ruff.toml's `target-version` is the syntax floor and must stay at or below the
  # interpreter pinned in .python-version. PEP 758's unparenthesized `except A, B:` is the
  # case in point: valid on 3.14, a SyntaxError on 3.13 and older. The two files state
  # different facts, a floor and a pin, as `rust-version` and rust-toolchain.toml do, so
  # this asserts their ordering rather than equality.
  local pin floor
  pin="$(tr -d '[:space:]' < .python-version)"
  floor="$(sed -n -E 's/^target-version[[:space:]]*=[[:space:]]*"py([0-9]+)".*/\1/p' ruff.toml | head -1)"
  [[ -n "$pin" && -n "$floor" ]] ||
    die "ruff: could not read .python-version ('$pin') / ruff.toml target-version ('$floor')"
  # "3.14" -> 314, "py312" -> 312; compare as integers.
  [[ "${pin//./}" -ge "$floor" ]] ||
    die "ruff.toml target-version py${floor} is NEWER than the .python-version pin ${pin}; ruff would rewrite conformance/ + scripts/ into syntax that interpreter cannot parse. Lower target-version, or raise the pin."
  # Offline once the pinned ruff is cached. Otherwise `uvx` re-resolves against PyPI on
  # every run, and a PyPI timeout turns a tree verdict red on the network. The first
  # networked run warms the cache and every later run needs none. `uvx --offline` fails
  # fast when the pin is not cached, so this cannot mask a missing toolchain.
  local -a ruff_cmd=(uvx "ruff@${RUFF_VERSION}")
  if uvx --offline "ruff@${RUFF_VERSION}" --version >/dev/null 2>&1; then
    ruff_cmd=(uvx --offline "ruff@${RUFF_VERSION}")
  fi
  # `ruff format --check` checks and never rewrites: the gate must not edit the tree it is
  # verifying.
  run "${ruff_cmd[@]}" check conformance/ scripts/
  run "${ruff_cmd[@]}" format --check conformance/ scripts/

  # Prove the floor rather than declaring it. `target-version` promises that these scripts
  # still parse on the older interpreter a contributor may have, and ruff keeps that promise
  # only for the rewrites it makes itself. The `msrv` leg does the same for Rust by
  # compiling with `cargo +$MSRV`. This is the Python equivalent, and it is nearly free
  # because uv fetches the floor interpreter itself.
  local floor_py="${floor:0:1}.${floor:1}"   # "312" -> "3.12"
  printf '%s$ uv run --python %s python  # parse every .py at the declared floor%s\n' \
    "$C_DIM" "$floor_py" "$C_OFF"
  # The file set is asserted non-empty inside the snippet, and the count it prints is
  # asserted positive again below, so an empty selection cannot pass as a clean parse.
  local parsed
  parsed="$(uv run --quiet --no-project --python "$floor_py" python -c '
import ast, pathlib, sys
files = sorted(p for d in ("conformance", "scripts") for p in pathlib.Path(d).rglob("*.py"))
if not files:
    sys.exit("no .py files found under conformance/ or scripts/ — the syntax floor would be proved on NOTHING")
bad = []
for f in files:
    try:
        ast.parse(f.read_text(encoding="utf-8"), filename=str(f))
    except SyntaxError as e:
        bad.append("  %s:%s: %s" % (f, e.lineno, e.msg))
ver = sys.version.split()[0]
if bad:
    sys.exit("does NOT parse on Python %s:\n%s" % (ver, "\n".join(bad)))
print("  %d file(s) parse on Python %s" % (len(files), ver))
')" || die "the declared syntax floor py${floor} is not real — the files above do not parse on Python ${floor_py} (or no files were found). Either fix them, or raise target-version in ruff.toml to a version they do parse on."
  printf '%s\n' "$parsed"
  assert_positive "$(sed -n -E 's/^ *([0-9]+) file\(s\) parse on Python .*/\1/p' <<<"$parsed" | tail -1)" \
    "ruff syntax-floor prover" "It parsed ZERO files under conformance/ + scripts/; did the directories move?"
  printf 'ok: ruff %s clean; syntax floor py%s VERIFIED, <= pinned interpreter %s\n' "$RUFF_VERSION" "$floor" "$pin"
}

# Workflow drift guard, and the single source for the install-action tool pins.
# taiki-e/install-action tool pins (`tool: <name>@<ver>`) are copied across
# ci.yml/release.yml/scheduled.yml with only prose "keep in step" comments, and Dependabot's
# github-actions ecosystem cannot see install-action tool versions. Assert that every tool
# name carrying a version pin resolves to one version across all three workflows, so a
# half-applied bump fails here. The ci.yml `actionlint` job invokes this target rather than
# duplicating the grep, so the two cannot drift.
workflow_tool_pins() {
  step "workflow tool pins — install-action versions agree across ci/release/scheduled"
  local files=(.github/workflows/ci.yml .github/workflows/release.yml .github/workflows/scheduled.yml)
  local f pins bad
  for f in "${files[@]}"; do
    [[ -f "$f" ]] || die "workflow tool-pin guard: $f not found — the workflow enumeration is stale"
  done
  pins=$(grep -hoE 'tool:[[:space:]]*[a-zA-Z0-9_-]+@[0-9][0-9A-Za-z.+-]*' "${files[@]}" \
    | sed -E 's/tool:[[:space:]]*([a-zA-Z0-9_-]+)@([0-9][0-9A-Za-z.+-]*)/\1 \2/' | sort -u)
  # The files existing is not the same as the pattern still matching. If install-action's
  # `tool: name@version` syntax changes, this grep yields nothing, `bad` is empty, and the
  # leg agrees that all zero pins agree with each other.
  assert_nonempty "$pins" "workflow tool-pin guard" \
    "no 'tool: name@version' lines matched in ${files[*]} — the pin syntax changed, or install-action is no longer used."
  bad=$(echo "$pins" | awk 'NF==2 {c[$1]++; v[$1]=v[$1]" "$2} END{for(n in c) if(c[n]>1) print "  - "n":"v[n]}')
  if [[ -n "$bad" ]]; then
    printf '%s\n' "$bad"
    die "a pinned install-action tool has divergent versions across workflows (unify them)"
  fi
  printf '%sok: all versioned install-action tool pins agree across workflows%s\n' "$C_OK" "$C_OFF"
}

# Vendored-input drift guard (network-free half). Delegates to scripts/vendored.sh (the single
# source of the logic): assert each vendored set's on-disk payload file count still matches its
# VENDORED.md `**Files:**`, catching a locally deleted shape the network byte-`check` misses
# because it only compares surviving files. It also asserts that every payload file still
# matches its SHA256SUMS entry, catching an in-place edit the count cannot see: weakening an
# `sh:minCount` in a vendored shape, or deleting a `"required"` array from a Beacon schema,
# leaves the count identical and makes every downstream check pass more easily. The
# byte-for-byte comparison against upstream needs the network and stays in `scheduled.yml`.
vendored_files() {
  step "vendored files — count matches VENDORED.md + content matches SHA256SUMS"
  run bash scripts/vendored.sh verify
}

# Base-image digest freshness — pure comparison half, no I/O. Split out from the Docker
# call around it (`_base_image_freshness`, below) specifically so it is unit-testable
# without Docker or a network: scripts/tests/test_base_image_digest_pin.py extracts this
# function's source out of this file and runs it with equal/unequal digests.
_base_image_digest_check() {  # _base_image_digest_check <pinned> <upstream>
  local pinned="$1" upstream="$2"
  if [[ "$pinned" == "$upstream" ]]; then
    printf 'ok: base image pin matches upstream (%s)\n' "$pinned"
    return 0
  fi
  printf '%snote: gcr.io/distroless/cc-debian13:nonroot has moved past its pinned digest%s\n' "$C_DIM" "$C_OFF"
  printf '%s      pinned   %s%s\n' "$C_DIM" "$pinned" "$C_OFF"
  printf '%s      upstream %s%s\n' "$C_DIM" "$upstream" "$C_OFF"
  return 1
}

# Extracts the first `Digest:` line from `docker buildx imagetools inspect` text output on
# stdin. That is the manifest-list digest, which is what a `FROM …@sha256:` pin pins. The
# text rendering prints one `Digest:` line up top and then each platform's own manifest
# under a `Name: …@sha256:…` line, but no version of docker guarantees that shape, and
# `sed -n '…/p'` prints every matching line. `head -n1` makes "first line wins" the
# contract rather than an accident of today's output. Kept separate from
# `_base_image_freshness` below so it is unit-testable without Docker: feed it canned
# multi-`Digest:` text on stdin.
_first_upstream_digest() {
  sed -n 's/^Digest: *\(sha256:[0-9a-f]*\).*/\1/p' | head -n1
}

# Base-image digest freshness — I/O half: resolves the CURRENT upstream digest and hands
# both digests to `_base_image_digest_check`. Reuses `_dockerfile_digest_pins` (the same
# parse `dockerfile_check` uses) rather than a second regex over the Dockerfile, so there
# is one source for "what is pinned". Docker-optional like `promtool`: `skip_unless`
# records a visible skip in `all` and dies under `GATE_STRICT_LEGS=1`/`CI` (release()
# exports the former), so a release cannot silently skip this the way `all` may.
#
# Returns 0 when clean, unreachable (offline/registry down — a verdict about the
# network, not the pin), or skipped; 1 only on confirmed drift, which `pins()` turns
# into WARN (`all`) or FAIL (`PINS_STRICT=1`, the same split as the external pins below.
_base_image_freshness() {
  local ref='gcr.io/distroless/cc-debian13:nonroot'
  skip_unless docker "base image digest freshness" "base image freshness NOT checked" || return 0
  local pinned upstream
  # Every Dockerfile's pin for the base, not `Dockerfile`'s alone: the two files carry the
  # same distroless digest with nothing else forcing agreement, so reading one would let a
  # bump that forgot the other pass. Two different digests for one ref is itself drift, and
  # is reported before the network is asked.
  pinned="$(_all_dockerfile_digest_pins | awk -v r="$ref" '$1 == r {print $2}' | sort -u)"
  assert_nonempty "$pinned" "base image digest freshness" \
    "no Dockerfile pin found for $ref — the freshness check would be a no-op"
  if [[ "$(printf '%s\n' "$pinned" | grep -c .)" -ne 1 ]]; then
    printf '%sthe Dockerfiles pin %s at DIFFERENT digests — bump them together:%s\n%s\n' \
      "$C_ERR" "$ref" "$C_OFF" "$pinned"
    return 1
  fi
  upstream="$(docker buildx imagetools inspect "$ref" 2>/dev/null | _first_upstream_digest)"
  if [[ -z "$upstream" ]]; then
    printf '%sWARNING: could not resolve the current digest for %s (offline / registry down) — SKIPPED, not verified.%s\n' \
      "$C_ERR" "$ref" "$C_OFF"
    return 0
  fi
  _base_image_digest_check "$pinned" "$upstream"
}

# Turns `_base_image_freshness`'s clean/drift verdict into the same warn-in-`all`,
# fail-under-`PINS_STRICT=1` split the external pins below use. It stays a separate gate
# rather than an arm of the external-pins `case`, because test_gate_ordering.py asserts by
# regex over the literal source that the non-strict drift arm ends in its own `return 0`.
# Threading a second concern through that `case` would make the assertion stop meaning what
# it says.
_base_image_pin_gate() {
  _base_image_freshness && return 0
  if [[ "${PINS_STRICT:-0}" == "1" ]]; then
    die "base image digest drift — see above. Re-resolve with 'docker buildx imagetools inspect gcr.io/distroless/cc-debian13:nonroot' and bump tag+digest together in the Dockerfile."
  fi
  printf '%sWARNING: base image digest DRIFT — see above. Not fatal here — `release` and `pins-strict` fail closed on this.%s\n' "$C_ERR" "$C_OFF"
  return 0
}

# External-pin drift guard, the network half of the same script. It is in `all`, at the
# cost of a few raw.githubusercontent GETs, because a pin nothing watches moves without
# anything reporting it.
#
# `all` already touches the network elsewhere (`corpus` fetches, `ensure_venv` fetches
# once), but this is the only leg that does so on every run, so it must not turn a flight
# without wifi into a red gate. `vendored.sh pins` returns 1 for real drift and 2 for
# unreachable, and only the former is fatal here. An unreachable check is reported loudly
# and skipped: it is a verdict about the network, not about the pins. Drift is a verdict
# about the federation rather than about this tree, so it does not fail `all` either.
#
# Every pin in EXTERNAL_PINS points at a repository this project does not control: two CKAN
# extension refs, a lineage string in the metadata repository's README, and the beacon-v2
# `releases/latest` tag. Any of them can move because someone else committed, and
# `all_legs()` is a bare loop under `set -e`, so a fatal verdict here would take every
# later leg with it, including everything that compiles or tests. Upstream moving is not a
# defect in this tree, and a gate that reddens for it is a gate people learn to ignore.
#
# The signal is relocated rather than weakened: drift is reported on every run, and stays
# fatal where being behind the federation costs something, in `pins-strict` on demand and
# in `release` before any artifact ships, which exports PINS_STRICT=1.
pins() {
  step "external pins — userportal deploy refs + gdi-metadata lineage (network); base image digest freshness (Docker)"
  _base_image_pin_gate
  local rc=0
  bash scripts/vendored.sh pins || rc=$?
  case "$rc" in
    0) return 0 ;;
    2) printf '%sWARNING: external pins could not be fetched (offline / upstream down) — SKIPPED, not verified. Re-run scripts/ci-local.sh pins when connected.%s\n' "$C_ERR" "$C_OFF"; return 0 ;;
    *)
      if [[ "${PINS_STRICT:-0}" == "1" ]]; then
        die "external pin drift — see above. Follow the federation in lockstep (bump EXTERNAL_PINS in scripts/vendored.sh + the matching note in conformance/requirements.txt); do not get ahead of it."
      fi
      printf '%sWARNING: external pin DRIFT — see above. The federation moved; this tree did not break.\n' "$C_ERR"
      printf '  Follow it in lockstep (bump EXTERNAL_PINS in scripts/vendored.sh + the matching note\n'
      printf '  in conformance/requirements.txt); do not get ahead of it. Not fatal here — `release`\n'
      printf '  and `pins-strict` fail closed on this.%s\n' "$C_OFF"
      return 0
      ;;
  esac
}

# --- Seams -------------------------------------------------------------------
# The cross-artifact checks: the code vs the Dockerfile vs the Compose stacks vs the
# operator-facing docs. They live in `crates/gdi-node-standalone/tests/it/seams.rs`, so they
# already ride `test-lite`/`test-full` inside `all` — this leg just runs them alone, for a
# fast loop when you are editing docs or Compose and do not want the whole suite.
seams() {
  step "seams — code vs Dockerfile vs Compose vs docs (cross-artifact facts)"
  run cargo test --locked -p gdi-node-standalone --test it seams
}

# Warn, without failing, when the branch is not rebased onto `main`.
#
# A gate that is green on a stale base says nothing about the merge. This warns rather than
# blocks: `main` can move again while the gate runs, so failing would only thrash the branch
# into rebase loops. It exists so that "the gate was green" is not read as "the merge is
# safe".
seam_staleness_warning() {
  git rev-parse --verify --quiet main >/dev/null 2>&1 || return 0
  [ "$(git rev-parse --abbrev-ref HEAD)" != "main" ] || return 0
  if ! git merge-base --is-ancestor main HEAD 2>/dev/null; then
    printf '%swarning: HEAD is not rebased onto main (%s).%s\n' \
      "$C_ERR" "$(git rev-parse --short main)" "$C_OFF" >&2
    printf '%s         A green gate on a stale base says nothing about the merge. Rebase\n' "$C_DIM" >&2
    printf '         onto main and re-run before you merge.%s\n\n' "$C_OFF" >&2
  fi
}

# Named `shellcheck_lint` so it does not shadow the `shellcheck` binary; the dispatch
# `shellcheck` target maps here. `--severity=warning` gates real bugs (warnings and
# errors); the style and info findings (SC2086, SC2015, SC2016) are reported by a lower
# severity and are not gated.
shellcheck_lint() {
  step "shellcheck — scripts/ + compose/ + .githooks/ (warning+ severity)"
  # In `all`, so `skip_unless` rather than `need`, the same shape as `promtool`. Without
  # Docker it skips visibly, and `release` and CI refuse the skip.
  skip_unless docker shellcheck "shell scripts NOT linted" || return 0
  # Enumerate rather than hardcode: a fixed list exempts every script added after it was
  # written, so the gate reports success while covering less and less.
  # (`.githooks/*` has no extension, hence the separate find.)
  local files
  mapfile -t files < <(
    { find scripts compose -name '*.sh' -type f
      find .githooks -type f 2>/dev/null || true
    } | sort
  )
  if [ ${#files[@]} -eq 0 ]; then
    die "shellcheck: found no shell scripts to lint — the enumeration is broken"
  fi
  printf '%s\n' "  linting ${#files[@]} script(s)"
  run docker run --rm -v "$PWD:/repo" --workdir /repo "$SHELLCHECK_IMAGE" \
    --severity=warning "${files[@]}"
}

# Fail fast if a supply-chain tool is missing, before running its checks. Both are hard
# `need`s with no fallback, so a contributor missing one learns in seconds. cargo-deny and
# cargo-machete do not compile the workspace, so this aggregate is fast and independent of
# `rust`, and it has its own workflow job for that reason: a fmt, clippy or test failure
# cannot hide a deny or machete failure.
preflight_supply_chain() {
  need cargo-deny    "cargo install cargo-deny --locked"
  need cargo-machete "cargo install cargo-machete --locked"
}

# fuzz_pin_drift <fuzz-manifest> <root-manifest>
#
# Every `[dependencies]` entry of the fuzz manifest that the root workspace also pins must
# carry the same `=version`, in either TOML shape: `name = "=1.2.3"` or
# `name = { version = "=1.2.3", … }`. A pin the root holds but this cannot read is fatal
# rather than skipped, because a pin the parser does not recognise drops out of the
# comparison and a drift then passes unseen. Its own function, taking the paths as
# arguments, so scripts/tests/test_fuzz_pin_drift.py can drive it against scratch
# manifests.
fuzz_pin_drift() {
  local manifest="$1" root="$2"
  local line name ver root_ver bad=0 compared=0 in_deps=0 sub_name="" unparsed=()
  while IFS= read -r line; do
    # The plain `[dependencies]` table (in_deps=1) and every `[dependencies.<crate>]`
    # sub-table (in_deps=2). Skipping the sub-table form would drop a shared pin written as
    # `[dependencies.serde_json]` with `version = "=0.9.1"` out of the comparison, and let
    # a one-major drift pass.
    if [[ "$line" =~ ^\[([^]]+)\] ]]; then
      sub_name=""
      if [[ "${BASH_REMATCH[1]}" == "dependencies" ]]; then
        in_deps=1
      elif [[ "${BASH_REMATCH[1]}" =~ ^dependencies\.([a-zA-Z0-9_-]+)$ ]]; then
        in_deps=2
        sub_name="${BASH_REMATCH[1]}"
      else
        in_deps=0
      fi
      continue
    fi
    (( in_deps )) || continue
    if (( in_deps == 2 )); then
      # In a sub-table only the `version =` key is a pin; `path`, `features`,
      # `default-features` carry none, and a sub-table with no `version` at all is a path
      # dependency. Rewritten into the `name = "..."` shape so the one set of version
      # regexes below reads it. A second parser would be a second place to drift.
      [[ "$line" =~ ^version[[:space:]]*= ]] || continue
      line="${sub_name} =${line#*=}"
    fi
    # The name is taken from any key shape, `name =` or `name.version =`, so a spelling the
    # version regexes below do not know still reaches the fatal "unparsed" arm.
    [[ "$line" =~ ^([a-zA-Z0-9_-]+)(\.[a-zA-Z0-9_-]+)*[[:space:]]*= ]] || continue
    name="${BASH_REMATCH[1]}"
    # Only deps the root workspace also pins are shared facts; fuzz-only deps
    # (libfuzzer-sys) legitimately have no counterpart.
    root_ver="$(sed -n -E "s/^${name}[[:space:]]*=[[:space:]]*\{?[[:space:]]*(version[[:space:]]*=[[:space:]]*)?\"=([0-9][^\"]*)\".*/\2/p" "$root" | head -1)"
    [[ -z "$root_ver" ]] && continue
    if [[ "$line" =~ ^${name}[[:space:]]*=[[:space:]]*\"=([0-9][^\"]*)\" ]] \
       || [[ "$line" =~ ^${name}[[:space:]]*=[[:space:]]*\{.*version[[:space:]]*=[[:space:]]*\"=([0-9][^\"]*)\" ]]; then
      ver="${BASH_REMATCH[1]}"
    else
      unparsed+=("$name")
      continue
    fi
    compared=$((compared + 1))
    if [[ "$ver" != "$root_ver" ]]; then
      printf '  - %s: fuzz pins =%s but the root workspace pins =%s\n' "$name" "$ver" "$root_ver"
      bad=1
    fi
  done < "$manifest"
  [[ ${#unparsed[@]} -eq 0 ]] ||
    die "fuzz pin-drift guard could not read the pin for: ${unparsed[*]} in $manifest — the root workspace pins it, so it must be compared. Write it as \`name = \"=x.y.z\"\` or \`name = { version = \"=x.y.z\", ... }\`, or teach fuzz_pin_drift the new shape; never let it drop out silently"
  # `bad=0` is also what "compared nothing" looks like, so assert the comparison ran.
  assert_positive "$compared" "fuzz pin-drift guard" "It compared ZERO shared pins in $manifest; the manifest's shape probably changed — fix the parser rather than trusting this pass."
  [[ "$bad" -eq 0 ]] ||
    die "$manifest has drifted from the root workspace pins in $root (it is a separate workspace and cannot inherit them — bump both together, then regenerate its lock with a plain \`cargo check --manifest-path $manifest --bins\`)"
  printf 'ok: %d shared fuzz pin(s) agree with the root workspace\n' "$compared"
}

# The fuzz crate cannot inherit `license`: its empty `[workspace]` table makes it its own
# workspace root, and that root declares no `[workspace.package]`, so `license.workspace =
# true` fails to parse outright. The literal it carries instead is a second copy of the
# root's licence, and a relicence that touches only `[workspace.package]` would leave this
# crate silently declaring the old terms in a repo that is published under the new ones.
# Same shape and same reason as fuzz_pin_drift above; kept separate so the failure names
# the licence rather than a pin. Both sides are asserted non-empty first, because a regex
# that stops matching would otherwise compare "" against "" and pass.
fuzz_license_drift() {
  local manifest="$1" root="$2" fuzz_lic root_lic
  fuzz_lic="$(sed -n -E 's/^license[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' "$manifest" | head -1)"
  root_lic="$(awk -F'"' '/^\[workspace\.package\]/{f=1} f&&/^license[[:space:]]*=/{print $2; exit}' "$root")"
  [[ -n "$root_lic" ]] ||
    die "fuzz licence-drift guard: could not read \`license\` from [workspace.package] in $root: the guard would compare nothing. Fix the parser, do not trust this pass"
  [[ -n "$fuzz_lic" ]] ||
    die "$manifest declares no literal \`license\`. It cannot inherit one (it is its own workspace root), so add \`license = \"$root_lic\"\` to match $root"
  [[ "$fuzz_lic" == "$root_lic" ]] ||
    die "$manifest declares license \"$fuzz_lic\" but $root declares \"$root_lic\". The fuzz crate is a separate workspace and cannot inherit it, so relicence both together"
  printf 'ok: fuzz crate licence "%s" agrees with the root workspace\n' "$fuzz_lic"
}

# Compile-gate every cargo-fuzz target against the current library API. The fuzz crate is
# an isolated workspace, with its own Cargo.lock and excluded from the main one, so
# `cargo check --workspace` never compiles it and a target that drifts out of sync with the
# library rots without anything reporting it. Compile-check every target here with the
# pinned stable toolchain, so the drift is caught before a commit. This leg does not fuzz:
# running the targets needs nightly, cargo-fuzz and ASan, and stays in scheduled.yml, which
# enumerates targets with `cargo fuzz list` so a new one is picked up. A missing manifest is
# a hard error, not a skip.
fuzz_smoke() {
  step "fuzz targets — compile-gate (rot check; does not fuzz)"
  local manifest="crates/core/fuzz/Cargo.toml"
  [ -f "$manifest" ] || { printf 'FAIL: %s not found\n' "$manifest" >&2; return 1; }
  # The fuzz crate is its own workspace, excluded from the root one so `--workspace` gates
  # and `cargo deny` skip it, and cargo cannot inherit `[workspace.dependencies]` across
  # workspaces. Any dependency it shares with the root manifest is therefore a second copy
  # of that version, and since it also depends on `core` and `beacon` by path, a root bump
  # the copy does not follow is an unresolvable version conflict rather than a warning.
  # Cargo offers no way to delete the duplication, so assert the copies agree, before the
  # compile, so the failure names the drifted pin instead of a wall of resolver output.
  fuzz_pin_drift "$manifest" Cargo.toml
  fuzz_license_drift "$manifest" Cargo.toml
  run cargo check --manifest-path "$manifest" --bins --locked
}

# --- CI job aggregates (kept in lock-step with .github/workflows/ci.yml) -------
feature_matrix() {
  step "feature matrix — the combinations no other leg compiles or lints"
  # 1-2. Two of the six selectable service profiles are built by no other leg: `pme`
  #      (vault+pme, no S3) and `s3,vault` (no PME). `full` covers s3+vault+pme and the
  #      single-feature legs cover s3 and vault alone, so a `cfg` arm reachable only in
  #      these two pairings could break unnoticed. `check` rather than `clippy`: the
  #      question is whether the combination still compiles, and a full lint pass per
  #      combination would cost minutes on a gate that already runs long.
  run cargo check -p gdi-node-standalone --features pme --all-targets --locked
  run cargo check -p gdi-node-standalone --features s3,vault --all-targets --locked

  # 3. `core`'s `schema` module is compiled only by `test_schema`, a `cargo test` run, so
  #    without this pass no clippy invocation sees it and the crate's own
  #    `deny(expect_used)` and `disallowed-methods` chokepoint do not apply to it.
  run cargo clippy -p gdi-node-standalone-core --features schema --all-targets --locked -- -D warnings

  # 4. `clippy_no_default` lints the service with no default features, but `--all-targets`
  #    pulls dev-dependencies, and `gdi-node-standalone` dev-depends on `gdi-dataset-tool`,
  #    which enables `core/s3`. That compiles `core` with s3 during the lite-only leg and
  #    leaves its lite arms unlinted. Linting core directly keeps it genuinely lite:
  #    `cargo tree -p gdi-node-standalone-core --no-default-features -i object_store` finds
  #    nothing. This closes a lint gap, not a shipping gap; `graph()` covers the shipped
  #    binary graph with `--edges no-dev`.
  run cargo clippy -p gdi-node-standalone-core --no-default-features --all-targets --locked -- -D warnings

  # 5. `core`'s features must be self-contained, usable by a consumer that is not
  #    `gdi-node-standalone`. `object_store` calls `reqwest::tls::…`, which needs a TLS
  #    feature on reqwest that only `core/http` activates, so `core/s3` can depend on it
  #    without declaring it: inside this workspace the service's `s3` implies its `tls`,
  #    which implies `core/http`. Anyone building `core` with `s3` alone gets errors from
  #    inside a third-party crate instead.
  #
  #    Checked alone rather than with `--workspace`: feature unification with a sibling
  #    that enables `http` is what hides this, so a workspace-wide invocation would pass
  #    while the standalone case stayed broken.
  run cargo check -p gdi-node-standalone-core --features s3 --all-targets --locked
}

rust()         { fmt; clippy_lite; test_lite; }
supply_chain() { preflight_supply_chain; deny; deny_fuzz; machete; pip_audit; }
profiles() {
  timed_sub clippy_full
  timed_sub clippy_s3
  timed_sub clippy_vault
  timed_sub clippy_no_default
  timed_sub feature_matrix
  timed_sub test_full
  timed_sub test_s3
  timed_sub test_schema
  timed_sub graph
  timed_sub instrument_guard
  timed_sub axum_serve_guard
}
# Opt-in, and not part of `all`; see the `otel` entry in the usage block above.
# `instrument_guard` stays in `profiles`: it is a pure grep over the serving path with no
# otel build, and it is the guard that keeps the export filter honest in the first place.
otel()         { clippy_otel; test_otel; graph_otel; }
# --- convenience aggregates ---------------------------------------------------
# `quick` is what the pre-commit hook runs. `script_tests` belongs in it because those
# tests guard the hook itself, this script's preflight list and the gate-key/status/record
# trio, and they cost seconds against clippy-lite's tens of seconds.
#
# `need python3` comes first: `script_tests` checks for it too, but only after clippy_lite
# has run, so a machine without python3 would pay a cold clippy build before learning it
# cannot finish.
quick()        { need python3 "https://www.python.org/downloads/"; fmt; clippy_lite; script_tests; }
lint()         { fmt; clippy_lite; clippy_full; ruff; }
# The `all` leg list is data, not a call sequence.
#
# An array cannot be misparsed, so the leg list stays readable to the guards under any
# wrapper (`timed`, `timed_sub`, a retry, a per-leg log capture) and any reformatting of
# this file. scripts/tests/test_ci_local_preflight.py reads ALL_LEGS directly and unwraps
# the wrappers only for the inner hops, where calls are still written as plain shell.
# The order matters, and the rule is one question: can this leg's verdict change while the
# tree stands still?
#
#   * no  -> it is a verdict about this tree. Run it first.
#   * yes -> it is a verdict about the world (an upstream repo, an advisory database, a
#            package index). Run it last.
#
# `all_legs()` is a bare loop under `set -e`, so the first non-zero leg ends the run and
# everything after it is skipped. With the world-verdict legs in front, an event unrelated
# to this tree, such as an upstream tag cut or a new advisory, skips every leg that compiles
# or tests anything.
#
# The world-verdict set overlaps the set `all()` re-runs on a short-circuit without being
# the same set. `supply_chain` (deny and deny-fuzz against RustSec, pip-audit against PyPI)
# is in both. `pins` is a world verdict, so it runs last here, but it is not re-run on a
# short-circuit: upstream refs do not move hourly, and its unauthenticated GitHub API calls
# are budgeted per hour and per address, so re-running it every time exhausts that budget
# and every later run reports unreachable, which the leg treats as a pass. `secrets` is
# re-run for a different reason: its input is outside the key. `ruff` is a tree verdict
# that fetches its toolchain over the network, so it sits at the boundary, after everything
# that compiles.
#
# `secrets` is the one exception to "world verdicts last": it is fast, purely local, and
# its whole purpose is to catch the secret about to be committed, which is most useful
# early. It is re-run on a short-circuit for the key-coverage reason above.
#
# `promtool` is a tree verdict, since the rules, their tests and the image digest all live
# here, and it is the one leg in this list that needs Docker. Without Docker it skips
# visibly rather than making `all` require it.
ALL_LEGS=(
  # --- tree verdicts: a red here is a real defect in this commit ---------------------
  script_tests doc_attachment secrets k8s_manifests ci_gate workflow_tool_pins vendored_files dashboard promtool shellcheck_lint sbom
  rust profiles doctests doc msrv fuzz_smoke conformance crypt4gh corpus
  # --- boundary: tree verdict, network-fetched toolchain -----------------------------
  ruff reuse_lint
  # --- world verdicts: a red here may be someone else's commit or a new advisory ------
  pins supply_chain
)
all_legs()     { local leg; for leg in "${ALL_LEGS[@]}"; do timed "$leg"; done; }

# --- Whole-gate short-circuit -------------------------------------------------
# A large share of full-gate runs re-verify a tree with no edits and no git operations
# since the previous run, and each of those costs the whole pipeline again.
#
# So: if the tree and the compilers are byte-identical to the last green `all`, skip the
# pure legs. One key for the whole gate, not one per leg: a key per leg is a chance per leg
# to manufacture a false green, and most CI jobs are thin wrappers around this script.
# See scripts/gate-key.sh for what the key covers and what it does not.
#
# `secrets`, `deny`, `deny_fuzz` and `pip_audit` still run on every short-circuit. Each
# reads something the key does not cover: files gitleaks sees, the RustSec database for
# both the root lockfile and the fuzz crate's own, and PyPI. A cache hit must not hide a
# fresh advisory or a secret dropped into an ignored file. `secrets` runs first, because
# the branch is a bare sequence under `set -e` and a new advisory would otherwise end the
# run before the leg that exists to catch the secret about to be committed. `pins` is not
# here: its unauthenticated GitHub API calls are budgeted per hour, and re-running them on
# every short-circuit exhausts the budget until the leg reports unreachable, which counts
# as a pass.
# The marker also expires (GATE_TTL_HOURS, default 24) so no skip can persist unbounded,
# and it lives under target/ so `cargo clean`/`sweep` fails it safe toward a full run.
# The decision itself lives in scripts/gate-status.sh so it is testable without running the
# whole gate (scripts/tests/test_gate_status.py). It reports STALE for every failure mode.
gate_marker() { printf '%s/target/.gate-ok' "$PWD"; }

# Record the green run, but only if the tree still matches what the legs actually tested.
# The key is sampled before `all_legs` (see `all`) and passed in here: this script tells you
# to run `all` in the background and keep working, so an edit landing mid-run is expected,
# and hashing the tree afterwards would stamp the marker with a tree nothing compiled. The
# decision lives in scripts/gate-record.sh so it is testable without running the whole gate
# (scripts/tests/test_gate_record.py).
gate_record_green() {
  local key_before="$1"
  # A run that skipped a leg has not verified this tree; see the note above `GATE_SKIPPED`.
  # Refused at this one chokepoint, so no caller can record past it.
  if (( ${#GATE_SKIPPED[@]} )); then
    printf '%snot recording a green marker: %d leg(s) SKIPPED, so this tree is not verified — install the tool and re-run `all`%s\n' \
      "$C_ERR" "${#GATE_SKIPPED[@]}" "$C_OFF"
    return 0
  fi
  run scripts/gate-record.sh --key-before "$key_before" --marker "$(gate_marker)"
}

# Every external tool the `all` gate needs, checked once up front.
#
# `need` is called inside the leg that uses a tool, so a missing one surfaces only when
# that leg runs. The MSRV leg sits near the end of the gate, so a missing rustup toolchain
# would be discovered only there, and one tool at a time: a fresh machine would pay a full
# gate per missing tool. This reports all of them at once, in seconds.
#
# Scoped to what `all` runs. docker, cross, objdump, trivy, cargo-about, cargo-llvm-cov,
# cargo-semver-checks and cargo-sweep belong to the release, coverage and Docker legs, and
# demanding them here would block a valid `all` run. `docker` stays out even though
# `promtool` (in `all`) uses it: that leg goes through `skip_unless`, not `need`, and skips
# visibly, which demanding Docker here would defeat.
#
# The per-leg `need` calls stay as a free safety net, and
# scripts/tests/test_ci_local_preflight.py asserts this list covers every tool the `all`
# legs need, so adding a `need` to a leg without listing it here fails the gate rather than
# restoring late discovery.
preflight_all() {
  step "preflight — external tools the full gate needs"
  local missing=()
  # tool<TAB>install hint
  local -a required=(
    $'python3	https://www.python.org/downloads/'
    $'curl	https://curl.se/download.html'
    $'rustup	https://rustup.rs'
    $'uv	https://docs.astral.sh/uv/getting-started/installation/'
    $'gitleaks	https://github.com/gitleaks/gitleaks#installing'
    $'cargo-deny	cargo install cargo-deny --locked'
    $'cargo-machete	cargo install cargo-machete --locked'
    $'cargo-cyclonedx	cargo install cargo-cyclonedx --locked'
  )
  local entry tool hint
  for entry in "${required[@]}"; do
    tool="${entry%%$'\t'*}"
    command -v "$tool" >/dev/null 2>&1 || missing+=("$entry")
  done
  if (( ${#missing[@]} )); then
    printf '%serror: %d required tool(s) missing — install ALL of these, then re-run:%s\n' \
      "$C_ERR" "${#missing[@]}" "$C_OFF" >&2
    for entry in "${missing[@]}"; do
      tool="${entry%%$'\t'*}"; hint="${entry#*$'\t'}"
      printf '  %-18s %s\n' "$tool" "$hint" >&2
    done
    printf '%s(scripts/dev-setup.sh checks these and more)%s\n' "$C_DIM" "$C_OFF" >&2
    exit 1
  fi
  printf '%sok: all %d required tools present%s\n' "$C_OK" "${#required[@]}" "$C_OFF"
}

all() {
  preflight_all
  local verdict
  verdict="$(scripts/gate-status.sh || true)"
  if [[ "$verdict" == FRESH* ]]; then
    step "all — SHORT-CIRCUIT: inputs unchanged since the last green run"
    printf '%s  %s\n' "$C_DIM" "$verdict"
    printf '  tree + toolchain hash matches the marker in target/.gate-ok, so the pure\n'
    printf '  legs would re-derive a result already on record. Running only the legs\n'
    printf '  whose verdict is not a function of the key: secrets (files the key cannot\n'
    printf '  see), then the advisory scans (cargo-deny + deny-fuzz / RustSec, pip-audit\n'
    printf '  / PyPI). Not pins: upstream refs do not move hourly, and its GitHub API\n'
    printf '  calls would spend the 60/h unauthenticated budget within a few\n'
    printf '  short-circuits. Force a complete run with GATE_FORCE=1, or by editing\n'
    printf '  anything at all.%s\n' "$C_OFF"
    # `secrets` first, for its own reason: its input is not what the key hashes.
    # gate-key.sh covers tracked and untracked-not-ignored files, while `gitleaks --no-git`
    # ignores .gitignore and reads everything else too. Fuzzing changes what this leg scans
    # while leaving the key byte-identical, so the tree reads FRESH and the one leg whose
    # input just changed would be the one skipped. It runs before the three below because
    # a new advisory there aborts the run under `set -e`, which would hide it.
    secrets
    deny
    deny_fuzz
    pip_audit
    printf '%sok: short-circuited — last full green was %s%s\n' \
      "$C_OK" "$(date -d "@$(cut -d' ' -f2 "$(gate_marker)")" '+%Y-%m-%d %H:%M')" "$C_OFF"
    return 0
  fi
  [[ -n "$verdict" ]] && printf '%s%s%s\n' "$C_DIM" "$verdict" "$C_OFF"
  # Sample the tree key before the legs run: that is the tree they are about to verify.
  # Anything that lands while they run is untested, and must not inherit this green.
  local key_before
  key_before="$(scripts/gate-key.sh .)"
  all_legs
  print_leg_timings
  gate_record_green "$key_before"
}
# The tag-time gate: the whole per-change gate (`all`) plus the checks that only matter once
# artifacts ship. Attribution currency (`licenses`), cross-compilation and the glibc floor
# for the full shipped Linux set (`cross` for x86_64, `cross-arm` for aarch64), the image
# base-CVE scan (`image-scan`) and the full at-rest round-trip (`e2e-full`). Run it before
# cutting a `v*` tag; it is heavy, and that is fine for a rare release gate. It includes
# `coverage`, not for the percentage, which gates nothing, but for the zero-coverage guard
# it carries. It excludes `semver-checks`, whose default baseline is HEAD and so is
# meaningless at a tag: run that explicitly against the previous release tag,
# `SEMVER_BASELINE=v1.0.0 …`.
# `licenses` stays release-only: cargo-about is slow and would become a hard prerequisite
# for every `all` run. The tradeoff is that a dependency bump can leave
# THIRD-PARTY-LICENSES.md stale through a fully green `all`. `release` catches it before
# any artifact ships, so run `scripts/ci-local.sh licenses` yourself after touching
# dependencies.
# The Docker-based linters, as one leg. They stay out of `all` so a contributor without
# Docker can still run it, and they are in `release`, which already requires Docker for
# `image-scan`, `cross`, `cross-arm` and `e2e-full`. Without this leg, this script, every
# workflow YAML and the PromQL alerting rules are linted by nothing.
# --- secrets ------------------------------------------------------------------
# Generated credentials and local environment files never enter a commit: rendered configs,
# `generated-secrets-*.txt`, `*.env` files and per-environment state directories. `.gitignore`
# and care are not enough on their own, so this leg scans for the shape of a secret.
#
# It scans the working tree (`--no-git`), not just history: the failure to catch is a
# secret about to be committed, and a history scan finds it only once it is too late.
#
# The native binary rather than a container, which is what lets it live in `all` instead of
# `lint-docker`. That placement is the point: `lint-docker` is reached only by `release`,
# so a guard against "a secret about to be committed" placed there gates no commit.
secrets() {
  step "secrets — gitleaks over the working tree"
  need gitleaks "https://github.com/gitleaks/gitleaks#installing"
  # Replaces the digest pin the Docker image carried. A floor, not an exact match: for a
  # scanner the dangerous direction is old, because an older rule set reports clean on a
  # tree it cannot analyse, which is a false green. A newer one can only fail loudly, and
  # exact-pinning would block a security fix. Assert what runs, not what is declared:
  # `need` proves presence, and presence is not a version.
  local have
  have="$(gitleaks version 2>/dev/null | tr -d '[:space:]')"
  have="${have#v}"
  [[ -n "$have" ]] || die "could not parse 'gitleaks version' output"
  printf '%s\n%s\n' "$GITLEAKS_MIN_VERSION" "$have" | sort -V -C \
    || die "gitleaks $have is below the $GITLEAKS_MIN_VERSION floor — an older rule set would report clean on findings it cannot see. Upgrade: https://github.com/gitleaks/gitleaks#installing"
  printf 'ok: gitleaks %s >= %s\n' "$have" "$GITLEAKS_MIN_VERSION"
  # No baseline file. Exemptions are inline `gitleaks:allow` comments at the finding.
  #
  # A baseline fingerprints each finding as (file, rule, line), so it is a second copy of
  # "this line holds a fake credential" stored away from the line, and it drifts whenever a
  # line moves or a file is deleted. An inline comment moves with the line and disappears
  # with it.
  #
  # It is also reviewable. Clearing findings by regenerating a baseline produces an opaque
  # JSON diff, which is an easy place for a real leak to ride along, while
  # `+ // gitleaks:allow` next to a credential has to be justified in review.
  #
  # Not a path allowlist either: exempting `crates/**/src/*.rs` would blind the scanner to
  # whole production files, whereas each pragma exempts one line.
  run gitleaks detect --no-git --redact --source . --config .gitleaks.toml

  # The `crates/core/fuzz/corpus/` path exemption in .gitleaks.toml is a whole-subtree
  # exemption, the shape that config argues against everywhere else. It earns its place for
  # generated inputs: `--no-git` ignores .gitignore, so without it the scan walks thousands
  # of fuzzer-grown blobs, one of which trips `generic-api-key` and makes this leg
  # unrunnable. The subtree also holds committed seeds, which that exemption would hide.
  #
  # So scan the tracked seeds with the exemption absent. Copying them out under flattened
  # names is what removes it: no path here can match `^crates/core/fuzz/corpus/`, so the
  # full default ruleset applies. A credential committed under the corpus fails the gate,
  # while a fuzzer-grown one cannot stall it.
  local seeds
  seeds="$(mktemp -d)"
  local n=0
  while IFS= read -r -d '' f; do
    # Flattened: `<target>/<seed>` would still sit under a path the exemption matches once
    # gitleaks resolves it, and these must be scanned without it.
    cp "$f" "$seeds/$(printf '%s' "${f#crates/core/fuzz/corpus/}" | tr / _)"
    n=$((n + 1))
  done < <(git ls-files -z crates/core/fuzz/corpus/)
  if ((n == 0)); then
    rm -rf "$seeds"
    die "no tracked fuzz-corpus seeds found — the exemption's residual check is scanning nothing, which would report clean whatever is committed there"
  fi
  run gitleaks detect --no-git --redact --source "$seeds"
  rm -rf "$seeds"
  printf 'ok: %d tracked fuzz-corpus seeds scanned without the subtree exemption\n' "$n"
}

# Pinned for the same reason as RUFF_VERSION above: a reuse release must not change this
# gate's verdict without a reviewed bump. Run through `uvx`, so the only prerequisite is
# `uv`, which the `ruff` leg already requires.
REUSE_VERSION='6.2.0'
reuse_lint() {
  step "reuse — REUSE 3.3 licensing compliance (every file has copyright + licence)"
  need uv "https://docs.astral.sh/uv/getting-started/installation/"
  # The licence texts in LICENSES/ are the ones REUSE resolves `SPDX-License-Identifier`
  # against; the two root files are the copies the release and both images ship. Same text,
  # two locations, because release.yml and the Dockerfiles copy `LICENSE-APACHE`/
  # `LICENSE-MIT` by name into staged artifacts and into the image, while REUSE requires
  # SPDX-named files under LICENSES/. Assert the copies are identical rather than letting a
  # correction land in one and not the other.
  local pair
  for pair in "LICENSE-MIT:LICENSES/MIT.txt" "LICENSE-APACHE:LICENSES/Apache-2.0.txt"; do
    local root="${pair%%:*}" spdx="${pair##*:}"
    [[ -f "$root" ]] || die "$root is missing. It is copied by name into the published artifacts and into both images, so the build stages would break without it"
    [[ -f "$spdx" ]] || die "$spdx is missing. REUSE resolves every SPDX-License-Identifier against LICENSES/, so the tree would not be compliant without it"
    cmp -s "$root" "$spdx" ||
      die "$root and $spdx have diverged. They are the same licence text in two places: the root name is what the release and the images ship, the LICENSES/ name is what REUSE reads. Copy one onto the other"
  done
  printf 'ok: root LICENSE-* files match their LICENSES/ counterparts\n'
  local -a reuse_cmd=(uvx "--from" "reuse==${REUSE_VERSION}" reuse)
  if uvx --offline --from "reuse==${REUSE_VERSION}" reuse --version >/dev/null 2>&1; then
    reuse_cmd=(uvx --offline "--from" "reuse==${REUSE_VERSION}" reuse)
  fi
  # `"lint"` quoted, not bare: scripts/tests/test_gate_queue_wiring.py scans command
  # position for calls to this script's own functions, and a bare `lint` here reads as a
  # call to the `lint` aggregate — which compiles, and would classify this leg as a builder
  # that must go through the gate queue. Quoting keeps the argument out of that scan.
  run "${reuse_cmd[@]}" "lint"
}

# --- fuzz-short ---------------------------------------------------------------
# `fuzz_smoke` only compile-checks the targets. This leg runs them.
#
# Time-boxed and in `release` rather than `all`: a few minutes is fine once per tag, and
# fuzzing is a discovery tool. A green short run proves very little, while a crash proves a
# great deal. Minimize any crash it finds and commit it as a fixture under
# `crates/core/tests/fixtures/malformed/`, as docs/testing.md describes.
#
# Needs nightly (cargo-fuzz uses `-Z sanitizer`). `FUZZ_SECONDS` overrides the per-target
# budget for a deeper run.
fuzz_short() {
  step "fuzz-short — time-boxed run of every target (${FUZZ_SECONDS:-10}s each)"
  need cargo-fuzz "cargo install cargo-fuzz --locked"
  local secs="${FUZZ_SECONDS:-10}"
  local targets
  mapfile -t targets < <(cd crates/core/fuzz && cargo +nightly fuzz list)
  [ ${#targets[@]} -gt 0 ] || die "fuzz-short: no targets listed — the harness is broken"
  printf '%s  %d target(s), %ss each%s\n' "$C_DIM" "${#targets[@]}" "$secs" "$C_OFF"
  local t
  for t in "${targets[@]}"; do
    run cargo +nightly fuzz run --fuzz-dir crates/core/fuzz "$t" -- \
      -max_total_time="$secs" -print_final_stats=1
  done
}

# --- on-demand: named so they are discoverable ---------------------------------
# These need a live stack or hours of CPU, so none belongs in a meta-leg. They are named
# here so the harnesses can be run without knowing their file paths.
mutants() {
  step "mutants — mutation audit (on demand; hours. see the script's header)"
  # No `"$@"`: the dispatcher loops over a target list, so there is no per-target argument
  # tail any leg could forward — load/soak/chaos/crash-loop/e2e-observability all call their
  # script bare. Pass flags by invoking ./scripts/mutants-audit.sh directly.
  run ./scripts/mutants-audit.sh
}

lint_docker()  { dockerfile_check; actionlint; promtool; shellcheck_lint; compose_config; }
# The lite `e2e` runs before `e2e_full`: it is the cheapest full-system check here, and
# failing fast beats failing after the heavy stack is up.
#
# `otel` is here because the OTLP trace-export privacy assertion ("exported spans omit
# query content") exists only under `--features otel`, so no other leg executes it.
# `coverage` is here rather than in `all`: instrumenting the full-feature workspace and
# running it single-threaded is far too slow for the per-change gate. It belongs in a
# composite leg all the same, because it carries `check-coverage-zero.py`, the one
# non-advisory part, which fails on any source file over 50 lines that no test reaches.
release() {
  # A cached green must not stand in for the tag gate.
  #
  # `all` short-circuits when the tree and toolchain hash matches a recent marker, running
  # only deny, pip-audit, pins and secrets. GATE_FORCE=1 overrides that here, so a release
  # cannot ship an image, a cross-compile and an e2e-full run on top of a core this run
  # never compiled. The marker's key also excludes external tool versions, so installing or
  # removing cargo-nextest, which swaps process-isolated tests for single-threaded ones,
  # leaves it valid; scripts/gate-key.sh states what the key does and does not cover.
  #
  # PINS_STRICT restores the other half: external pin drift is a warning in the per-change
  # gate, but shipping while behind the federation is the case that costs something, so it
  # fails closed here. GATE_STRICT_LEGS closes the last gap: a leg that `all` lets skip on a
  # missing tool dies here instead, because a release gate that skipped the alert-rule tests
  # is not a release gate.
  export GATE_FORCE=1 PINS_STRICT=1 GATE_STRICT_LEGS=1
  all; lint_docker; otel; fuzz_short; vendored_check; licenses; coverage; e2e; e2e_observability; cross_compile; cross_arm; image_provenance; image_scan; e2e_full
}

# The full vendored-integrity check: re-fetches every vendored file from its pinned
# upstream commit, asserts byte-identity, then checks the external pins. `vendored_files`,
# in `all`, only counts what is on disk; this is what proves the content still matches what
# was reviewed.
#
# It needs the network, so it stays out of `all` and runs in `release`, before any artifact
# ships.
vendored_check() {
  step "vendored-check — every vendored file byte-identical to its pinned commit (network)"
  need curl "https://curl.se/download.html"
  run scripts/vendored.sh check
}

# --- Out-of-process harnesses -------------------------------------------------
# Reachable by name, so the load, soak, crash-loop and chaos harnesses can be run without
# knowing the file paths. None is in `all`: each costs minutes plus a release build, and a
# gate that grows without limit stops being run at all. The Docker legs stay out for the
# same reason.
load() {
  step "load — oha baseline + saturation (asserts load-shed still sheds)"
  need oha "cargo install oha --locked"
  need python3 "https://www.python.org/downloads/"
  run scripts/load/run.sh
}
soak() {
  step "soak — RSS/fd/thread plateau over sustained query load"
  need oha "cargo install oha --locked"
  need python3 "https://www.python.org/downloads/"
  run scripts/soak/leak.sh
}
crash_loop() {
  step "crash-loop — kill -9 mid-write, assert the store converges on reboot"
  need curl "https://curl.se/download.html"
  run scripts/soak/crash-loop.sh
}
e2e_observability() {
  step "e2e-observability — node /metrics -> prometheus scrape -> queryable (Docker)"
  need docker "https://docs.docker.com/get-docker/"
  need curl "https://curl.se/download.html"
  run scripts/e2e/run-observability.sh
}
chaos() {
  step "chaos — toxiproxy latency/reset/black-hole on the S3 + Vault wire (Docker)"
  need docker "https://docs.docker.com/get-docker/"
  run scripts/chaos/run.sh
}
# The host-process harnesses, mirroring what scheduled.yml's soak and load jobs run.
# `chaos` stays out: it is the only one that needs Docker, just as `all` excludes the Docker
# legs so a contributor without Docker can still run the gate.
harness()      { load; soak; crash_loop; }

# --- Real-data conformance corpus -------------------------------------------
# The hand-built fixtures cannot express real cardinality, INFO-field variety, multi-allelic
# representation or line width: the COVID fixture the population machinery is tested against
# holds a single data record. `crates/core/tests/corpus.rs` pins the exact conversion of a
# content-addressed slice of 1000 Genomes chr21 and gnomAD v4.1 chr21, and
# `scripts/fetch-corpus.sh` fetches them by HTTP range and verifies their sha256.
#
# It is in `all` because those tests pass vacuously when `GDI_CORPUS_DIR` is unset, which
# keeps the rest of the gate runnable without a network but makes them worthless on their
# own. This leg is the guarantee: it fetches first, then exports the directory, and the
# tests hard-fail on a set-but-empty one. Like `conformance` and `crypt4gh`, only the first
# run needs the network; the slices are cached under `target/corpus/`.
corpus() {
  step "corpus — real-data conformance (1000 Genomes + gnomAD chr21 slices)"
  local dir="${GDI_CORPUS_DIR:-$PWD/target/corpus}"
  if [[ ! -f "$dir/kg.chr21.slice.vcf" || ! -f "$dir/gnomad.chr21.slice.vcf" ]]; then
    need curl "https://curl.se/download.html"
    need python3 "https://www.python.org/downloads/"
    run scripts/fetch-corpus.sh "$dir"
  fi
  export GDI_CORPUS_DIR="$dir"
  # Assert the leg exercised the corpus, in two independent ways.
  #
  # `corpus.rs` skips and passes when `GDI_CORPUS_DIR` is unset, and a fully-skipped run
  # prints what a real run prints, `test result: ok. 2 passed`. Scraping the skip notice
  # cannot tell them apart, because it is an `eprintln!` and cargo captures stderr for
  # passing tests. The guarantee is bound in the test binary instead: `GDI_CORPUS_REQUIRED=1`
  # turns an unset corpus dir into a hard failure. The count check below catches the other
  # half, a renamed or removed test, where `--test corpus` selects fewer than 2 and still
  # exits 0.
  export GDI_CORPUS_REQUIRED=1
  local log
  log="$(mktemp)"
  run cargo test -p gdi-node-standalone-core --locked --test corpus 2>&1 | tee "$log"
  local n
  n=$(parse_passed_count "$log")
  rm -f "$log"
  [[ "$n" -eq 2 ]] ||
    die "corpus leg ran $n real-data tests, expected 2 (renamed/removed/added? update the count if intended)"
  printf '%sok: corpus leg exercised %s real-data tests%s\n' "$C_OK" "$n" "$C_OFF"
}

# --- Python-backed gates: conformance + crypt4gh interop --------------------
# These mirror the `conformance` and `crypt4gh-interop` workflow jobs. Those build their
# venvs in $RUNNER_TEMP; locally they are cached under `target/venv/`, so only the first
# run needs the network. Set
# `GDI_FDP_PYTHON` / `C4GH_VENV` to reuse an interpreter you already have.
# Every top-level `name==version` pin in the human-facing requirements file (the one
# Dependabot/GitHub advisories read) must appear verbatim in the hash-locked lockfile that
# `ensure_venv` actually installs from. Otherwise a reviewed bump to the requirements file
# would be ignored, because the venv installs the stale locked version, or a mismatched
# transitive closure would put unverified code into the dev and CI Python. This is a
# network-free text check (no PyPI round-trip), so it runs on every gate. It is scoped to
# real `==` pins, not prose, so a comment cannot satisfy it; regenerate the lock in the same
# change with `uv pip compile --universal --generate-hashes <requirements> -o <lock>`.
# `--universal` is required: without it the lock is resolved against whichever Python the
# regenerating developer happens to run, hard-pinning that interpreter's conditional
# dependencies into a file a differently-versioned environment installs. See the header of
# conformance/requirements.txt.
assert_lock_current() {  # assert_lock_current <requirements-file> <lock-file>
  local req="$1" lock="$2" line name ver norm pins=0
  [[ -f "$lock" ]] || die "missing hash-locked lockfile $lock (regenerate: uv pip compile --universal --generate-hashes $req -o $lock)"
  while IFS= read -r line; do
    line="${line%%#*}"                                 # strip trailing comment
    line="${line//[[:space:]]/}"                        # strip all whitespace
    [[ "$line" == *"=="* ]] || continue                # only pinned lines
    name="${line%%==*}"; ver="${line##*==}"
    norm="$(printf '%s' "$name" | tr '[:upper:]_.' '[:lower:]--')"   # PyPI name normalization
    grep -iqE "^${norm}==${ver}([[:space:]\\]|\$)" "$lock" \
      || die "$req pins $name==$ver but $lock does not (regenerate: uv pip compile --universal --generate-hashes $req -o $lock)"
    pins=$((pins + 1))
  done < "$req"
  # A requirements file with no `==` lines would match nothing above and report success
  # having compared nothing.
  assert_positive "$pins" "lock guard for $req" \
    "no pinned (name==version) lines were found, so $lock was never compared against anything."
}

# The identity of a built venv: the lock it was installed from plus the interpreter pin it was
# built on. Anything that changes either must invalidate the cache.
venv_stamp() {  # venv_stamp <lock-file>
  cat "$1" .python-version 2>/dev/null | sha256sum | cut -d' ' -f1
}

# The interpreter a built venv really runs, as `major.minor`, empty if unreadable. The stamp
# above hashes the pin file, which is what the venv should have been built on rather than
# what it was. The two differ on the `uv`-absent path below, and only this can tell.
venv_python_minor() {  # venv_python_minor <venv-dir>
  "$1/bin/python" -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null || true
}

ensure_venv() {  # ensure_venv <name> <requirements-file>
  local dir="target/venv/$1" req="$2" lock="${2%.txt}.lock"
  # Verify the lock tracks the reviewed pins before the cache short-circuit, so a stale cached
  # venv cannot hide a drifted lock. Also called by each Python-backed leg before it decides
  # whether to build a venv at all, because `GDI_FDP_PYTHON` / `C4GH_VENV` skip this function
  # entirely; the double call is an idempotent text check, and neither site can be forgotten.
  assert_lock_current "$req" "$lock"
  local pin pin_minor
  pin="$(tr -d '[:space:]' < .python-version 2>/dev/null || true)"
  pin_minor="$(printf '%s' "$pin" | cut -d. -f1,2)"
  # ...and key the cache on those same inputs, which covers the inverse and more likely case:
  # a stale cached venv hiding a correctly updated lock. The existence of `bin/python` says
  # only that some venv was built here once, not from which lock or on which interpreter.
  # Without this, a reviewed version bump reinstalls nothing and the crypt4gh and conformance
  # legs render their verdict against the old packages while printing success.
  local want stamp="$dir/.gdi-venv-stamp" have_minor
  want="$(venv_stamp "$lock")"
  if [[ -x "$dir/bin/python" ]]; then
    if [[ -f "$stamp" && "$(cat "$stamp")" == "$want" ]]; then
      # The stamp covers the lock and the pin file, but says nothing about the interpreter
      # the venv was really built on. The `uv`-absent fallback below builds on ambient
      # python3 and stamps as though it had honoured the pin, so without this re-check a
      # later `uv` install would never rebuild and every conformance and crypt4gh verdict
      # would come from the wrong interpreter.
      have_minor="$(venv_python_minor "$dir")"
      if [[ -z "$pin_minor" || -z "$have_minor" || "$have_minor" == "$pin_minor" ]]; then
        return 0
      fi
      if ! command -v uv >/dev/null 2>&1; then
        # Still no way to honour the pin. Re-print rather than rebuild: `uv` is not a hard
        # prerequisite for these legs, and rebuilding here would go to the network on
        # every run. The warning is the gate, so the cache must not silence it.
        printf '%sWARNING: %s runs Python %s but .python-version pins %s — this venv produces the conformance/crypt4gh VERDICT, and CI uses the pin. Install uv to match CI.%s\n' \
          "$C_ERR" "$dir" "$have_minor" "$pin_minor" "$C_OFF"
        return 0
      fi
      printf '%svenv %s is on Python %s but the pin is %s, and uv is now available — rebuilding%s\n' \
        "$C_DIM" "$dir" "$have_minor" "$pin_minor" "$C_OFF"
    else
      printf '%svenv %s was built from a different lock/interpreter — rebuilding%s\n' \
        "$C_DIM" "$dir" "$C_OFF"
    fi
    run rm -rf "$dir"
  fi
  step "venv — creating $dir from $lock (hash-locked; one-time; needs network)"
  # Build this venv on the pinned interpreter, unlike the stdlib-only guard legs, which are
  # version-agnostic and run on ambient `python3`. The difference is what goes into it:
  # pySHACL, rdflib, lxml and cryptography are third-party, their wheels are built per
  # interpreter, and these venvs produce the conformance and crypt4gh verdicts. The workflow
  # jobs build them under `actions/setup-python` at .python-version, so a local venv on some
  # other interpreter renders its verdict on a different closure.
  # uv is preferred because it fetches the pinned version itself (sub-second, cached); the
  # `python3 -m venv` fallback keeps uv from becoming a hard prerequisite for these legs, at
  # the cost of whatever interpreter the developer has.
  if [[ -n "$pin" ]] && command -v uv >/dev/null 2>&1; then
    # --seed installs pip into the venv; a bare `uv venv` has none, and the hash-locked
    # install below uses pip's `--require-hashes` rather than uv's resolver.
    run uv venv --quiet --seed --python "$pin" "$dir"
  else
    need python3 "https://www.python.org/downloads/"
    printf '%sWARNING: building %s with ambient python3 (%s), not the pinned %s — CI uses the pin, so a version-sensitive conformance/crypt4gh result may differ here. Install uv to match CI.%s\n' \
      "$C_ERR" "$dir" "$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null || echo '?')" "${pin:-?}" "$C_OFF"
    run python3 -m venv "$dir"
  fi
  # No `pip install --upgrade pip` here. That fetches an unpinned, unhashed wheel from PyPI
  # into the venv the next line hardens with `--require-hashes`, and it is the component that
  # decides how every later install is verified. `uv venv --seed` and `python3 -m venv`
  # already seed a pip new enough for `--require-hashes`, supported since pip 8. If a lock
  # ever needs a newer pip, add `pip==<version>` with its hash to the lock and let the single
  # `--require-hashes` install below cover it.
  # --require-hashes: pip refuses any dist whose artifact hash is not pinned in the lock, and
  # refuses the whole install unless every transitive requirement is hash-pinned. This is the
  # supply-chain gate for the only Python in the project, which is tooling and ships in no
  # binary.
  run "$dir/bin/pip" install --quiet --require-hashes -r "$lock"
  # Stamp last: a venv is only cacheable once the hash-locked install succeeded, so an
  # interrupted or failed install leaves no stamp and the next run rebuilds rather than trusting
  # a half-populated directory.
  printf '%s\n' "$want" >"$stamp"
}

# Assert a `cargo test -- --ignored` run selected exactly <expected> tests.
# `cargo test` exits 0 when `--ignored` matches no tests, so a renamed or un-ignored test
# would run nothing and still pass. A loose `>=1` is not enough either: it stays green when
# some but not all of the tests stop being selected.
# The `N passed` from the last `test result:` line of a captured cargo-test run, or 0.
# Single source for every leg that must prove a test binary actually selected something.
parse_passed_count() {  # parse_passed_count <logfile>
  # Understands both harnesses. libtest prints `test result: ok. N passed`, nextest prints
  # `Summary [ 1.23s] N tests run: N passed`. A parser that knows only one of them returns 0
  # for the other, which reads like "ran nothing" and manufactures the failure these count
  # assertions exist to detect.
  #
  # libtest prints one line per test binary, so the counts must be summed: taking the last
  # line alone reports one binary's total, trips a leg's own floor and blames the scope for
  # a defect in the counter. nextest's `Summary` is already a total, so that branch stays
  # `tail -1`.
  local n
  n=$(sed -n -E 's/.*test result: ok\. ([0-9]+) passed.*/\1/p' "$1" \
      | awk '{s+=$1} END{if (NR) print s}')
  if [[ -z "$n" ]]; then
    n=$(sed -E 's/\x1b\[[0-9;]*m//g' "$1" \
        | sed -n -E 's/.*Summary.*[[:space:]]([0-9]+) tests run:.*/\1/p' | tail -1)
  fi
  printf '%s' "${n:-0}"
}

assert_ignored_count() {  # assert_ignored_count <expected> <logfile> <label>
  local n
  n=$(parse_passed_count "$2")
  [[ "$n" -eq "$1" ]] || die "$3 ran $n ignored tests, expected $1 (renamed/un-ignored/added? update the count if intended)"
}

conformance() {
  step "conformance — Rust gate <-> pySHACL dual-encoding agreement"
  local py="${GDI_FDP_PYTHON:-}"
  # The lock guard is a property of the reviewed pins, not of how this run obtains an
  # interpreter, and it must run on every gate. `GDI_FDP_PYTHON` skips `ensure_venv`, so
  # assert it before the branch, for both branches.
  assert_lock_current conformance/requirements.txt conformance/requirements.lock
  if [[ -z "$py" ]]; then
    ensure_venv fdp conformance/requirements.txt
    py="$PWD/target/venv/fdp/bin/python"
  fi
  # The Python checkers are gates too (a SHACL run over an empty shapes graph conforms
  # vacuously); their non-triviality tests run first.
  #
  # `unittest discover` exits 0 when it discovers no tests, so a renamed file, a moved
  # directory or a changed `-p` pattern would leave this step green having asserted nothing.
  # A floor rather than an exact count: adding a checker test is expected, and what is
  # guarded is discovery collapsing toward zero.
  #
  # The floor is read back from ci.yml rather than repeated here, the same single-sourcing
  # as the glibc floor below, so this gate and the workflow cannot disagree about how many
  # tests is enough. check-ci-gate.py fails if that `min=` line stops being readable.
  local dlog dn dmin
  dmin="$(python3 scripts/check-ci-gate.py --conformance-floor)"
  [[ -n "$dmin" ]] || die "could not read the conformance test floor from ci.yml (see check-ci-gate.py --conformance-floor)"
  dlog="$(mktemp)"
  printf '%s$ %s -m unittest discover -s conformance -p "test_*.py"%s\n' "$C_DIM" "$py" "$C_OFF"
  "$py" -m unittest discover -s conformance -p "test_*.py" -v 2>&1 | tee "$dlog"
  dn=$(sed -n -E 's/^Ran ([0-9]+) tests? in .*/\1/p' "$dlog" | tail -1)
  rm -f "$dlog"
  [[ "${dn:-0}" -ge "$dmin" ]] ||
    die "conformance non-triviality suite ran ${dn:-0} tests, expected >= $dmin (renamed/moved test file, or a changed discover pattern?)"
  printf '%sok: conformance non-triviality suite ran %s tests%s\n' "$C_OK" "$dn" "$C_OFF"
  local t log
  for t in conformance_crawl conformance_agreement; do
    log="$(mktemp)"
    printf '%s$ GDI_FDP_PYTHON=%s cargo test -p gdi-node-standalone --locked --test %s -- --ignored%s\n' "$C_DIM" "$py" "$t" "$C_OFF"
    GDI_FDP_PYTHON="$py" cargo test -p gdi-node-standalone --locked --test "$t" -- --ignored --nocapture 2>&1 | tee "$log"
    assert_ignored_count 1 "$log" "conformance binary $t"
    rm -f "$log"
  done
}

crypt4gh() {
  step "crypt4gh — Rust<->Python interop against the pinned crypt4gh==1.8.6"
  local venv="${C4GH_VENV:-}"
  # Same reason as the `conformance` leg: `C4GH_VENV` skips `ensure_venv` and therefore skipped
  # the lock guard with it.
  assert_lock_current conformance/requirements-crypt4gh.txt conformance/requirements-crypt4gh.lock
  if [[ -z "$venv" ]]; then
    ensure_venv c4gh conformance/requirements-crypt4gh.txt
    venv="$PWD/target/venv/c4gh"
  fi
  local log
  log="$(mktemp)"
  printf '%s$ C4GH_VENV=%s C4GH_INTEROP_REQUIRED=1 cargo test -p gdi-node-standalone-core --locked --test crypt4gh_interop -- --ignored%s\n' "$C_DIM" "$venv" "$C_OFF"
  # C4GH_INTEROP_REQUIRED turns a missing reference venv into a hard failure inside the test
  # binary. Without it a skipped interop test still passes, and `assert_ignored_count` counts
  # passed tests, so vacuous skips would read as a green leg that verified nothing against
  # the reference implementation.
  C4GH_VENV="$venv" C4GH_INTEROP_REQUIRED=1 cargo test -p gdi-node-standalone-core --locked --test crypt4gh_interop -- --ignored --nocapture 2>&1 | tee "$log"
  assert_ignored_count 7 "$log" "crypt4gh-interop"
  rm -f "$log"
}

# CycloneDX SBOM generation. Sub-second, and its `*.cdx.json` output is gitignored.
# CI uploads the files with `if-no-files-found: error`; assert the same locally.
sbom() {
  step "sbom — CycloneDX generation (the release/PR artifact must still build)"
  need cargo-cyclonedx "cargo install cargo-cyclonedx --locked"
  # Count only what this run produced. Counting every *.cdx.json in the tree would let a
  # stale artifact from an earlier run satisfy the floor, and this leg exists to prove the
  # artifact still builds.
  local stamp
  stamp="$(mktemp)"
  run cargo cyclonedx --all --format json --spec-version 1.5
  local n
  n=$(find . -name "*.cdx.json" -not -path "./target/*" -newer "$stamp" | wc -l)
  rm -f "$stamp"
  [[ "$n" -gt 0 ]] || die "cargo cyclonedx produced no *.cdx.json in this run (stale artifacts from an earlier run do not count)"
  printf 'ok: %s CycloneDX SBOM file(s) generated\n' "$n"
}

# Public-API break detection for the three library crates. Not in `all`: it builds both the
# baseline tree and the current one, so it is slow, and it is advisory. The default baseline
# is HEAD, so it compares uncommitted work against the last commit; set SEMVER_BASELINE to
# any other revision.
semver_checks() {
  step "semver-checks — core/beacon/fairdp public API vs ${SEMVER_BASELINE:-HEAD}"
  need cargo-semver-checks "cargo install cargo-semver-checks --locked"
  run cargo semver-checks --baseline-rev "${SEMVER_BASELINE:-HEAD}" \
    -p gdi-node-standalone-core -p gdi-node-standalone-beacon -p gdi-node-standalone-fairdp --all-features
}

# Lite end-to-end smoke against the minimal Compose stack. Docker + several minutes, so
# it stays out of `all`, exactly like the other Docker targets.
e2e() {
  step "e2e — lite end-to-end smoke against the minimal Compose stack (Docker)"
  need docker "https://docs.docker.com/get-docker/"
  run ./scripts/e2e/run.sh
}

# Assert a gnu binary's highest referenced GLIBC symbol stays at or below <max>, so the
# tool download and the deployed service keep running on every still-supported distro
# (2.28 = RHEL/Rocky 8). Mirrors the CI `glibc floor guard` step.
glibc_floor_guard() {  # glibc_floor_guard <binary> <max-allowed>
  local bin="$1" allowed="$2" max
  max=$(objdump -T "$bin" | grep -oE "GLIBC_[0-9.]+" | sort -V | tail -1)
  max="${max#GLIBC_}"
  [[ -n "$max" ]] || die "no GLIBC symbols found in $bin (not a gnu binary?)"
  printf '%s\n%s\n' "$max" "$allowed" | sort -V -C \
    || die "glibc floor $max exceeds $allowed (would drop RHEL8) — a dep pulled a newer symbol or cross's base bumped"
  printf 'ok: glibc floor %s <= %s\n' "$max" "$allowed"
}

# Build-verify a cross matrix in cross-rs's digest-pinned containers (Cross.toml), then
# glibc-floor-guard the gnu targets. Shared by the two cross legs so the loop lives once.
#
# The matrix and the glibc floor are read from the workflows via check-ci-gate.py rather
# than copied: a second list of target, crate and feature triples would drift, and this leg
# would build-verify a different set than the workflows do. `ci-gate`, in `all`, fails if
# either matrix becomes unparseable, so an empty loop cannot pass silently.
#
# Not in `all`: it needs Docker, `cross` and `--profile release-verify` builds, and tens of
# GB in target/. Check free disk first, because a full disk surfaces here as an `ld` SIGBUS.
_cross_build_matrix() {  # _cross_build_matrix <label> <check-ci-gate.py matrix flag>
  local label="$1" flag="$2"
  need docker "https://docs.docker.com/get-docker/"
  need cross "cargo install cross --locked --version 0.2.5"
  need objdump "apt-get install binutils"
  need python3 "https://www.python.org/downloads/"

  local floor rows
  floor="$(python3 scripts/check-ci-gate.py --glibc-floor)"
  rows="$(python3 scripts/check-ci-gate.py "$flag")"
  [[ -n "$rows" ]] || die "no $label matrix rows parsed from the workflow — refusing to pass having built nothing"
  # Build the gnu targets first.
  #
  # Every row here shares one host build-script directory, the `release-verify` profile,
  # because cargo compiles build scripts for the host triple regardless of `--target`. The
  # gnu container is old, which is what buys the low glibc floor, while the musl one is not,
  # so whichever runs first leaves scripts the other must be able to execute. One direction
  # works and the other cannot:
  #
  #   gnu then musl : scripts need GLIBC_2.18, musl's newer libc runs them        -> OK
  #   musl then gnu : scripts need GLIBC_2.28-2.30, gnu's 2.23 cannot run them    -> FAILS
  #
  # The failure is `build-script-build: /lib/.../libc.so.6: version 'GLIBC_2.28' not
  # found`, a message that names libc and says nothing about ordering, from a leg that
  # runs only before a tag.
  #
  # The matrix is read from the workflow, so its order is whatever ci.yml lists, and
  # reordering those rows is the kind of edit that looks free. Sorting here makes the leg
  # enforce the ordering it depends on rather than inherit it. Stable within each group:
  # awk emits in input order, so the workflow still decides everything except
  # gnu-before-musl. A workflow run is immune, because it puts each row on a fresh runner.
  rows="$(printf '%s\n' "$rows" | awk '$1 ~ /-gnu$/'; printf '%s\n' "$rows" | awk '$1 !~ /-gnu$/')"
  printf 'glibc floor: %s\n%s rows:\n%s\n' "$floor" "$(printf '%s\n' "$rows" | wc -l)" "$rows"

  # `env RUSTFLAGS=` makes this leg hermetic against a project-local `.cargo/config.toml`.
  # That file is gitignored and never exists in CI, but the cross container mounts the
  # project directory, so on a developer machine the cargo running inside the image reads it.
  # A leftover per-checkout copy of the mold linker override then fails the link with
  # `cc: error: unrecognized command line option '-fuse-ld=mold'`, because the container has
  # no mold, and nothing in that message names the file responsible. The dev setup writes
  # the override to the user-level `~/.cargo/config.toml`, which the container cannot see.
  #
  # `Cross.toml`'s `[build.env] passthrough` is the other half: without it this export
  # never reaches the container. See that file for why the alternatives do not work, and
  # for the caveat that this clears every rustflag, not only the linker one. It neutralises
  # RUSTFLAGS and nothing else: a leftover per-checkout config that sets
  # `[target.*].linker`, `[build].target-dir` or any `[net]` key is still read inside the
  # container. Delete such a file rather than expecting this to shadow it.
  local target crate features
  while read -r target crate features; do
    step "$label — $crate -> $target${features:+ (--features $features)}"
    if [[ -n "$features" ]]; then
      run env RUSTFLAGS= cross build --profile release-verify --locked -p "$crate" --target "$target" --features "$features"
    else
      run env RUSTFLAGS= cross build --profile release-verify --locked -p "$crate" --target "$target"
    fi
    case "$target" in
      *-gnu) glibc_floor_guard "target/$target/release-verify/$crate" "$floor" ;;
      *)     printf 'skip: glibc floor guard (not a gnu target)\n' ;;
    esac
  done <<< "$rows"
}

# The per-PR CI `cross-compile` set: the five x86_64 Linux targets (matrix read from ci.yml).
cross_compile() { step "cross — build-verify the per-PR x86_64 Linux targets (Docker; SLOW)"; _cross_build_matrix cross --cross-matrix; }

# The weekly `cross-linux-arm` set: the two aarch64-linux service targets (matrix read from
# scheduled.yml) that the trimmed per-PR matrix no longer covers. `release` runs this right
# after `cross`, so the local tag gate build-verifies the full shipped Linux set, x86_64 and
# aarch64. Also runnable standalone.
cross_arm() { step "cross-arm — build-verify the weekly aarch64-linux targets (Docker; SLOW)"; _cross_build_matrix cross-arm --cross-matrix-arm; }

# --- Release-only and advisory legs -----------------------------------------
# None of these is in `all`: each needs Docker, a from-source tool, or produces a number
# rather than a pass or a fail. `release` bundles the first three plus `cross` and
# `cross-arm`; `coverage` is in `release` for its zero-coverage guard, the percentage
# itself being advisory. Each mirrors the check its release workflow job runs.

# Full-stack end-to-end: Garage (S3), OpenBao (Vault) and a PME at-rest crypt4gh
# round-trip. The heaviest test here, since it builds the service image and boots Garage
# and OpenBao, so it stays out of `all` and lives in `release`. The lite `e2e` smoke is the
# per-change counterpart; this one exercises the S3, Vault and at-rest-encryption path
# `e2e` does not.
e2e_full() {
  step "e2e-full — Garage + OpenBao + PME at-rest crypt4gh round-trip (Docker)"
  need docker "https://docs.docker.com/get-docker/"
  run ./scripts/e2e/run-full.sh
}

# Third-party attribution drift guard. THIRD-PARTY-LICENSES.md carries the full licence
# texts and copyright notices, and ships inside the release binaries and the container
# image, so a dependency bump that changes the shipped licence set must refresh it.
# Regenerate from the current lockfile and hard-fail if the committed copy differs. Not in
# `all`, because cargo-about has no prebuilt installer and must be built from source, so it
# lives in `release`, where attribution ships. On failure, regenerate and commit; the hint
# below gives the command.
licenses() {
  step "licenses — THIRD-PARTY-LICENSES.md is current (cargo-about drift guard)"
  need cargo-about "cargo install cargo-about --version 0.9.2 --locked --features cli"
  local gen
  gen="$(mktemp)"
  # --fail: refuse to emit a bundle with a missing or unclearable licence. A new dependency
  # with no detectable licence must be resolved rather than shipped un-attributed.
  run cargo about generate --fail about.hbs -o "$gen"
  if ! diff -u THIRD-PARTY-LICENSES.md "$gen"; then
    rm -f "$gen"
    die "THIRD-PARTY-LICENSES.md is stale — a shipped dependency's licence set changed. Refresh: cargo about generate about.hbs -o THIRD-PARTY-LICENSES.md (then commit)"
  fi
  rm -f "$gen"
  printf '%sok: THIRD-PARTY-LICENSES.md matches the current dependency graph%s\n' "$C_OK" "$C_OFF"
}

# Container base-CVE gate. `cargo deny`, in `supply-chain`, covers Rust-crate advisories
# from Cargo.lock and cannot see CVEs in the image's OS layer: the distroless base ships
# glibc, libgcc and friends, which carry their own advisories. Build the same multi-stage
# image that ships and Trivy-scan it. A fixable HIGH or CRITICAL fails the leg, and the fix
# is to bump the base digest in the Dockerfile. It needs Docker and a fresh vulnerability
# database, so it rides in `release` rather than `all`.
image_scan() {
  step "image-scan — Trivy base-layer CVE scan of the shipped image (Docker)"
  need docker "https://docs.docker.com/get-docker/"
  need trivy "https://trivy.dev/latest/getting-started/installation/ — the workflows install a pinned trivy; locally, anything >= TRIVY_MIN_VERSION"
  # Assert what runs, not what the workflow declares; see TRIVY_MIN_VERSION.
  local have
  have="$(trivy --version 2>/dev/null | sed -n 's/^Version: *//p' | head -1 | tr -d '[:space:]')"
  have="${have#v}"
  [[ -n "$have" ]] || die "could not parse 'trivy --version' output"
  printf '%s\n%s\n' "$TRIVY_MIN_VERSION" "$have" | sort -V -C \
    || die "trivy $have is below the $TRIVY_MIN_VERSION floor — an older scanner reports a clean base it cannot analyse. Upgrade: https://trivy.dev/latest/getting-started/installation/"
  printf 'ok: trivy %s >= %s\n' "$have" "$TRIVY_MIN_VERSION"
  run docker build -f Dockerfile -t gdi-node-standalone:scan .
  # --ignore-unfixed: an unpatchable base CVE leaves nothing to do, so it must not block a
  # release. A fixable HIGH or CRITICAL exits non-zero, and the release stops until the base
  # digest is bumped.
  run trivy image --ignore-unfixed --severity HIGH,CRITICAL --exit-code 1 --quiet gdi-node-standalone:scan
  printf '%sok: no fixable HIGH/CRITICAL CVE in the shipped image base%s\n' "$C_OK" "$C_OFF"
}

image_provenance() {
  step "image-provenance — the built image REPORTS the provenance it was built with (Docker)"
  need docker "https://docs.docker.com/get-docker/"
  # This covers the defect class `dockerfile-check` cannot see. A mis-plumbed build ARG is
  # not a syntax error, because Docker hands an unknown `${VAR}` to the shell, which expands
  # it to empty. An undeclared or unforwarded `SOURCE_DATE_EPOCH` therefore leaves
  # `build_epoch` reading "unknown" in a perfectly valid image. Only building the image and
  # asking the binary catches it, and `image-scan` builds with no build args, so it would
  # pass either way.
  local sha epoch short out
  sha="$(git rev-parse HEAD)"
  epoch="$(git log -1 --format=%ct)"
  short="${sha:0:12}"
  run docker build --build-arg GITHUB_SHA="$sha" --build-arg SOURCE_DATE_EPOCH="$epoch" \
    -t gdi-node-standalone:provenance .
  out="$(docker run --rm gdi-node-standalone:provenance --version)"
  printf '  %s\n' "$out"
  # The SHA is asserted at its abbreviated width: build.rs normalises both sources to 12
  # characters, so matching the full 40-character input would fail on a correct build.
  case "$out" in
    *"git $short"*) ;;
    *) die "image --version reports no 'git $short': $out" ;;
  esac
  case "$out" in
    *"build_epoch $epoch"*) ;;
    *) die "image --version reports no 'build_epoch $epoch': $out" ;;
  esac
  printf '%sok: the image reports the commit and epoch it was built with%s\n' "$C_OK" "$C_OFF"
}

# Instrumented line and region coverage over the full-feature workspace. It reports and
# enforces no floor, because a coverage number gates nothing and asserting one invites
# gaming. It is in `release` for its zero-coverage guard, which fails on a file the suite
# never enters, and out of `all` because it needs a full instrumented rebuild of the
# workspace. Run it on demand to see what a change leaves unexercised.
coverage() {
  step "coverage — cargo-llvm-cov over the full-feature workspace (percentage advisory; the zero-coverage guard is not)"
  need cargo-llvm-cov "cargo install cargo-llvm-cov --locked"
  # cargo-llvm-cov needs the llvm-tools component; add it best-effort when rustup is present.
  if command -v rustup >/dev/null 2>&1; then
    rustup component add llvm-tools-preview >/dev/null 2>&1 || true
  fi
  # --test-threads=1: the full-profile suite shares process/Vault/PME state (the same reason
  # test_full serialises in the plain-cargo fallback), so a parallel instrumented run races.
  # One instrumented run, two reports. `--no-report` collects the profile data, and the two
  # `report` invocations below re-render it without re-running the suite. Rendering each
  # view from scratch would pay the whole instrumented test cost twice for identical data.
  run cargo llvm-cov --workspace --features full --locked --no-report -- --test-threads=1
  run cargo llvm-cov report --summary-only

  # The one part of coverage that is not advisory. A percentage floor is gameable and
  # nobody acts on it, which is why the summary above gates nothing. Zero is categorically
  # different from low: it means no test reaches the file at all, so every invariant in it
  # is asserted by nothing.
  local cov_json
  cov_json="$(mktemp --suffix=.json)"
  run cargo llvm-cov report --json --summary-only --output-path "$cov_json"
  run python3 scripts/check-coverage-zero.py "$cov_json"
  rm -f "$cov_json"
}

# --- Maintenance (not a gate leg) --------------------------------------------
# Outside `all`, because it deletes build artifacts: a gate that throws away a warm target/
# mid-session turns the next run cold. It guards nothing, so the rule that a guard outside
# `all` is dead code does not apply to it.
#
# `--installed` drops artifacts built by toolchains that are no longer installed. After
# retiring a stale MSRV toolchain that is its whole orphaned variant set, which nothing else
# reclaims. `--maxsize` is the standing ceiling that keeps target/ from growing back
# to the size that forces a full `cargo clean`, and with it a cold gate afterwards.
sweep() {
  step "sweep — reclaim stale target/ artifacts (maintenance; not part of \`all\`)"
  need cargo-sweep "cargo install cargo-sweep --locked"
  run cargo sweep --installed .
  # Always carry an explicit unit: `--maxsize` defaults to megabytes, so a bare
  # `--maxsize 20` means 20 MB and deletes essentially the whole target directory. Reject a
  # unitless override rather than interpreting it as megabytes.
  local maxsize="${SWEEP_MAXSIZE:-20GB}"
  [[ "$maxsize" =~ ^[0-9]+(MB|GB)$ ]] ||
    die "SWEEP_MAXSIZE must carry an explicit unit (e.g. 20GB, 500MB); got '${maxsize}'"
  run cargo sweep --maxsize "$maxsize" .
}

usage() { awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "${BASH_SOURCE[0]}"; }

# --- Gate queue: one heavy run per machine ------------------------------------
# Concurrent gates thrash a machine rather than share it: several overlapping runs finish
# far later than the same runs taken one at a time, and they starve any scoped `cargo test`
# running alongside. So the heavy targets take one slot per machine (scripts/gate-queue.sh,
# a flock). First in, first out finishes the first gate at its own pace instead of
# finishing all of them at the end, and the wait is printed rather than spent inside a
# silent "still compiling".
#
# The list below is checked: scripts/tests/test_gate_queue_wiring.py derives every target
# that compiles or tests from this script's own call graph and requires each to be listed
# here, or in its INTERACTIVE_BUILDERS map with a reason. Those are the lint rungs
# (`quick`, `lint`, the clippy legs, `feature-matrix`) and the one-crate inner loops
# (`test-schema`, `seams`): re-running one of those to check a single finding must not wait
# behind another session's full gate, and nothing the pre-commit hook runs may queue. A new
# leg that builds and is in neither list fails the gate rather than running unqueued.
# Not `nice`, either: a niced gate starves next to any bulk load at normal priority.
GATE_QUEUE_LEGS=(
  all release
  rust profiles msrv doctests doc fuzz-smoke fuzz-short conformance crypt4gh corpus
  test-lite test-full test-s3 test-otel otel
  coverage semver-checks mutants harness load soak chaos
  e2e e2e-full e2e-observability cross cross-arm image-scan image-provenance crash-loop
)
gate_queue_wanted() {
  local t h
  for t in "$@"; do
    for h in "${GATE_QUEUE_LEGS[@]}"; do [[ "$t" == "$h" ]] && return 0; done
  done
  return 1
}
# One file per machine: the main checkout and every worktree share it, because what they
# contend for is the CPU. Per-user, so two accounts on one machine do not fight over its
# mode.
gate_lock_path() { printf '%s' "${GATE_LOCK:-/tmp/gdi-node-standalone-gate-$(id -u).lock}"; }

main() {
  cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  local targets=("$@")
  [[ ${#targets[@]} -eq 0 ]] && targets=(all)
  # Take the machine-wide slot before anything runs. The wrapper sets GATE_QUEUE_WAIT for
  # the re-exec'd child, so this cannot recurse; GATE_QUEUE=0 opts out.
  if [[ -z "${GATE_QUEUE_WAIT:-}" && "${GATE_QUEUE:-1}" != 0 ]] && gate_queue_wanted "${targets[@]}"; then
    exec scripts/gate-queue.sh --lock "$(gate_lock_path)" --label "$PWD" -- "$SELF" "${targets[@]}"
  fi
  # Say it before the legs run: a green result on a stale base is the outcome most likely to
  # be mistaken for "safe to merge".
  seam_staleness_warning
  for t in "${targets[@]}"; do
    case "$t" in
      all)               all ;;
      release)           release ;;
      quick)             quick ;;
      lint)              lint ;;
      lint-docker)       lint_docker ;;
      secrets)           secrets ;;
      reuse)             reuse_lint ;;
      fuzz-short)        fuzz_short ;;
      mutants)           mutants ;;
      rust)              rust ;;
      supply-chain)      supply_chain ;;
      deny-fuzz)         deny_fuzz ;;
      profiles)          profiles ;;
      otel)              otel ;;
      msrv)              msrv ;;
      doctests)          doctests ;;
      doc)               doc ;;
      fmt)               fmt ;;
      preflight-all)     preflight_all ;;
      clippy-lite)       clippy_lite ;;
      clippy-full)       clippy_full ;;
      clippy-s3)         clippy_s3 ;;
      clippy-vault)      clippy_vault ;;
      clippy-no-default) clippy_no_default ;;
      feature-matrix)    feature_matrix ;;
      clippy-otel)       clippy_otel ;;
      instrument-guard)  instrument_guard ;;
      serve-guard)       axum_serve_guard ;;
      test-lite)         test_lite ;;
      test-full)         test_full ;;
      test-otel)         test_otel ;;
      test-s3)           test_s3 ;;
      test-schema)       test_schema ;;
      deny)              deny ;;
      machete)           machete ;;
      pip-audit)         pip_audit ;;
      graph)             graph ;;
      graph-otel)        graph_otel ;;
      actionlint)        actionlint ;;
      promtool)          promtool ;;
      compose)           compose_config ;;
      dockerfile-check)  dockerfile_check ;;
      load)              load ;;
      soak)              soak ;;
      crash-loop)        crash_loop ;;
      chaos)             chaos ;;
      e2e-observability) e2e_observability ;;
      harness)           harness ;;
      dashboard)         dashboard ;;
      script-tests)      script_tests ;;
      doc-attachment)    doc_attachment ;;
      k8s-manifests)     k8s_manifests ;;
      ci-gate)           ci_gate ;;
      workflow-tool-pins) workflow_tool_pins ;;
      vendored-files)    vendored_files ;;
      vendored-check)    vendored_check ;;
      ruff)              ruff ;;
      pins)              pins ;;
      pins-strict)       PINS_STRICT=1 pins ;;
      seams)             seams ;;
      conformance)       conformance ;;
      crypt4gh)          crypt4gh ;;
      fuzz-smoke)        fuzz_smoke ;;
      corpus)            corpus ;;
      sbom)              sbom ;;
      semver-checks)     semver_checks ;;
      sweep)             sweep ;;
      e2e)               e2e ;;
      e2e-full)          e2e_full ;;
      cross)             cross_compile ;;
      cross-arm)         cross_arm ;;
      image-provenance) image_provenance ;;
      image-scan)        image_scan ;;
      licenses)          licenses ;;
      coverage)          coverage ;;
      shellcheck)        shellcheck_lint ;;
      help|-h|--help)    usage; return 0 ;;
      *)                 printf 'unknown target: %s\n\n' "$t" >&2; usage >&2; exit 2 ;;
    esac
  done
  print_skipped_legs
  if (( ${#GATE_SKIPPED[@]} )); then
    printf '\n%s✓ ci-local.sh: %s passed — with %d leg(s) SKIPPED, listed above%s\n' \
      "$C_OK" "${targets[*]}" "${#GATE_SKIPPED[@]}" "$C_OFF"
  else
    printf '\n%s✓ ci-local.sh: %s passed%s\n' "$C_OK" "${targets[*]}" "$C_OFF"
  fi
}

main "$@"
