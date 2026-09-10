#!/usr/bin/env bash
# scripts/mutants-audit.sh — on-demand mutation audit.
#
# Mutation testing is a discovery tool, not a gate. It grades how well the existing suite
# asserts behaviour: it mutates the code and asks whether any test fails. A surviving
# mutant is usually a missing assertion rather than a bug, and once the gap is closed the
# new test carries the regression protection from then on. So this runs on demand, and
# nothing schedules it.
#
# A full workspace audit is several thousand mutants and takes hours. Run it when you want
# a fresh picture, quarterly or before a release. Scope it to one package or one file for a
# targeted answer in minutes.
#
# Two harness traps this script guards against, both silent:
#   1. `cargo mutants -f` matches nothing when the pattern contains a slash:
#          -f crypt4gh/header.rs  -> 0 mutants        -f header.rs -> the file's mutants
#      A scope miss is indistinguishable from "everything passed", so this script asserts
#      that the number of mutants tested equals the number cargo-mutants lists for the
#      same selection, and aborts on any mismatch.
#   2. `--in-place` rewrites the source tree and does not restore it if the run dies
#      (OOM, full disk, Ctrl-C). A clean tree is required, and it is restored on exit.
#
# What this cannot see. Do not chase these as test gaps:
#   * Doctests. `--test-tool nextest` cannot run them, so behaviour asserted only by a
#     doctest looks like a survivor. Use --doctests (slower `cargo test`), or convert the
#     doctest into a `#[cfg(test)]` unit test.
#   * Cross-crate assertions. cargo-mutants runs `nextest --package=<mutated>`, so a
#     `core` mutant killed by a test in `gdi-node-standalone` appears to survive. Use
#     --workspace-tests to widen the scope (much slower).
#   * Files with no tests. Mutating them yields ~100% survivors: that is a missing test
#     suite, not a list of gaps to triage. The per-file catch-rate table makes it obvious.
#   * `crates/core/fuzz` (its own isolated workspace) and macro-generated code.
#
# `--against <name>` needs a `.github/mutants-baseline-<name>.txt` survivor set, and none
# is in the tree. Restore one from git history, then reproduce the selection recorded in
# its `# selection:` header (that `-f` list and feature set, not this script's
# `--all-features` default) together with the cargo-mutants version recorded beside it.
# Any other selection enumerates a different mutant population, and the comparison is
# meaningless. `norm()` strips those `#` header lines before diffing.
#
# Usage:
#   scripts/mutants-audit.sh                                     # whole workspace
#   scripts/mutants-audit.sh -p gdi-node-standalone-beacon       # one package
#   scripts/mutants-audit.sh -p gdi-node-standalone-core -f validate_pkg.rs
#   scripts/mutants-audit.sh -p gdi-dataset-tool --shard 0/4     # split a long run
#   scripts/mutants-audit.sh -p gdi-node-standalone-beacon --against beacon
set -euo pipefail

# A baseline is only comparable against the version it was seeded with: cargo-mutants
# enumerates the mutants, so another version can produce a different mutant set.
readonly PINNED_VERSION="27.1.0"
readonly MIN_FREE_GB=15
readonly ALL_PACKAGES=(
  gdi-node-standalone-core gdi-node-standalone-beacon gdi-node-standalone-fairdp
  gdi-node-standalone gdi-dataset-tool
)

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
note() { printf '  %s\n' "$*"; }

packages=() files=() shard="" against="" test_tool="nextest" workspace_tests=false

while [ $# -gt 0 ]; do
  case "$1" in
    -p|--package) packages+=("$2"); shift 2 ;;
    -f|--file)    files+=("$2");    shift 2 ;;
    --shard)      shard="$2";       shift 2 ;;
    --against)    against="$2";     shift 2 ;;
    --doctests)   test_tool="cargo"; shift ;;
    --workspace-tests) workspace_tests=true; shift ;;
    # Derive the header's extent rather than hardcoding a line range, which is a second
    # copy of "where the header ends" and drifts: print from after the shebang to the
    # first line that is neither a comment nor blank.
    -h|--help)    awk 'NR>1 { if ($0 !~ /^#/ && NF) exit; print }' "$0"; exit 0 ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
done

cd "$(git rev-parse --show-toplevel)"

# --- preconditions -----------------------------------------------------------
command -v cargo-mutants >/dev/null 2>&1 || die "cargo-mutants not installed (cargo install cargo-mutants --version ${PINNED_VERSION} --locked)"
version="$(cargo mutants --version | awk '{print $2}')"
[ "$version" = "$PINNED_VERSION" ] ||
  printf 'warning: cargo-mutants %s != pinned %s; the mutant set (and any baseline diff) may differ\n' "$version" "$PINNED_VERSION" >&2

# Trap 2: --in-place rewrites the tree. Refuse to run over uncommitted work, and put the
# tree back on any exit, including a crash, a full disk, or Ctrl-C.
#
# The precondition proves crates/ is clean at the start, not at the end. An audit runs for
# hours and is meant to be backgrounded, so a bare `git checkout -- crates/` in the exit
# trap would discard whatever was edited meanwhile, and --in-place leaves no scratch copy
# to recover from. So restore_tree captures a patch under mutants.out/ (this script's
# output directory, already gitignored) and prints its path before reverting.
[ -z "$(git status --porcelain -- crates/)" ] || die "crates/ has uncommitted changes; --in-place would rewrite them"
restore_tree() {
    [ -n "$(git status --porcelain -- crates/ 2>/dev/null)" ] || return 0
    mkdir -p mutants.out
    _patch="mutants.out/crates-at-exit-$(date +%Y%m%d-%H%M%S).patch"
    if git diff -- crates/ >"$_patch" 2>/dev/null && [ -s "$_patch" ]; then
        printf '\nnote: crates/ was dirty at exit; saved to %s before restoring.\n' "$_patch" >&2
        printf '      If you edited crates/ during the run, recover with: git apply %s\n' "$_patch" >&2
    else
        rm -f "$_patch"
    fi
    git checkout -- crates/ 2>/dev/null ||
        printf '\nwarning: could not restore crates/. Inspect `git status` before trusting the tree.\n' >&2
}
trap restore_tree EXIT

# Resolve `--against` here, before the run, not at the diff step that consumes it: a
# baseline that is not there must cost a usage error, not a whole audit.
baseline=""
if [ -n "$against" ]; then
  baseline=".github/mutants-baseline-${against}.txt"
  [ -f "$baseline" ] ||
    die "no such baseline: $baseline. Restore one from git history and match the selection and cargo-mutants version recorded in its header, or drop --against."
fi

free_gb="$(df --output=avail -BG . | tail -1 | tr -dc '0-9')"
[ "$free_gb" -ge "$MIN_FREE_GB" ] || die "only ${free_gb}G free, need >= ${MIN_FREE_GB}G; a full disk mid-run leaves the tree mutated"

# Trap 1: a `-f` pattern containing a slash silently matches nothing.
if [ "${#files[@]}" -gt 0 ]; then
  for f in "${files[@]}"; do
    case "$f" in */*) die "-f '$f' contains a slash: cargo-mutants would match nothing. Use the bare filename, such as 'header.rs'." ;; esac
  done
fi

# --- build the selection -----------------------------------------------------
# --all-features compiles every cfg-gated block, which removes the phantom class: mutants
# in code that was never compiled and therefore always "survive". That is why this audit
# needs no per-feature legs and no file or regex exclusions.
sel=(--all-features)
[ "${#packages[@]}" -eq 0 ] && packages=("${ALL_PACKAGES[@]}")
for p in "${packages[@]}"; do sel+=(--package "$p"); done
if [ "${#files[@]}" -gt 0 ]; then
  for f in "${files[@]}"; do sel+=(-f "$f"); done
fi
[ -n "$shard" ] && sel+=(--shard "$shard")
if $workspace_tests; then sel+=(--test-workspace true); fi

# --- arithmetic guard (trap 1) -----------------------------------------------
# Ask cargo-mutants how many mutants this exact selection yields, before running it.
# If the run tests a different number, the selection silently missed files.
echo "==> enumerating selection"
expected="$(cargo mutants --list "${sel[@]}" | wc -l | tr -d ' ')"
[ "$expected" -gt 0 ] || die "selection matched 0 mutants; check -p and -f, since a slash in -f matches nothing"
note "expecting ${expected} mutants"

# --- run ---------------------------------------------------------------------
export PROPTEST_DISABLE_FAILURE_PERSISTENCE=1  # mutants make proptests fail; don't persist seeds
echo "==> running (this rewrites crates/ in place and restores it on exit)"
cargo mutants --in-place --timeout 180 --test-tool "$test_tool" "${sel[@]}" || true

# A run killed by a full disk or an OOM leaves no missed.txt: refuse to report on partial
# data, which would under-count the survivors.
[ -f mutants.out/missed.txt ] || die "no mutants.out/missed.txt: the run did not complete. Check free disk and memory. The tree is restored on exit."
tested="$(cat mutants.out/caught.txt mutants.out/missed.txt mutants.out/unviable.txt mutants.out/timeout.txt 2>/dev/null | wc -l | tr -d ' ')"

if [ "$tested" -ne "$expected" ]; then
  die "scope miss: expected ${expected} mutants, the run accounted for ${tested}. Some files were skipped, see trap 1 in this script's header. These results are not trustworthy."
fi
note "arithmetic guard: ${tested} == ${expected} ✓"

# --- report ------------------------------------------------------------------
echo
echo "==> per-file catch rate (0% caught = the file has no tests; write tests, don't triage)"
python3 - <<'PY'
import collections, pathlib
def load(n):
    p = pathlib.Path("mutants.out")/f"{n}.txt"
    return p.read_text().splitlines() if p.exists() else []
def key(line): return line.split(":")[0]
caught, missed = collections.Counter(), collections.Counter()
for l in load("caught"):  caught[key(l)] += 1
for l in load("missed"):  missed[key(l)] += 1
files = sorted(set(caught) | set(missed))
print(f"  {'file':<52}{'caught':>7}{'missed':>7}{'rate':>7}")
for f in files:
    c, m = caught[f], missed[f]
    rate = 100*c/(c+m) if c+m else 0
    flag = "  <- no assertions" if rate == 0 else ""
    print(f"  {f[-52:]:<52}{c:>7}{m:>7}{rate:>6.0f}%{flag}")
print(f"\n  total caught={sum(caught.values())} missed={sum(missed.values())}")
PY

if [ -n "$against" ]; then
  # `$baseline` was resolved and existence-checked in the preconditions, so it is present
  # here and the path is written down once.
  echo
  echo "==> diff vs ${baseline}, in both directions"
  echo "    Reproduce the selection and cargo-mutants version recorded in the"
  echo "    '# selection:' header of ${baseline}, or this diff compares different"
  echo "    mutant populations and means nothing."
  # Normalise for comparison: drop the '# …' header block and blank lines, strip
  # :line:col (which churns on any edit above the mutant), and sort bytewise. The header
  # deletes only matter for the baseline; missed.txt has no '#' or blank lines.
  # Never `comm <(..) <(..)`: with a process substitution as its first operand, comm
  # silently returns a wrong diff.
  export LC_ALL=C
  norm() { sed -E '/^[[:space:]]*#/d; /^[[:space:]]*$/d; s/^([^:]+):[0-9]+:[0-9]+:/\1:/' "$1" | sort -u; }
  now="$(mktemp)"; base="$(mktemp)"
  norm mutants.out/missed.txt > "$now"
  norm "$baseline" > "$base"
  echo "  New survivors, absent from the baseline. An assertion regressed, or new code is unasserted:"
  comm -23 "$now" "$base" | sed 's/^/    + /' || true
  echo "  Baseline entries killed since. The baseline over-lists:"
  comm -13 "$now" "$base" | sed 's/^/    - /' || true
  rm -f "$now" "$base"
fi

echo
echo "==> full survivor list: mutants.out/missed.txt"
# This line runs before the EXIT trap that does the restoring, so it says "on exit"
# rather than claiming a restore that has not happened. `restore_tree` reports what
# actually happened, including the saved-patch path when crates/ was dirty.
echo "==> nothing was committed; crates/ is restored on exit (see any note below)."
