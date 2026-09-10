#!/usr/bin/env bash
# One-shot developer setup: check the toolchain, install the git hook, and offer the
# optional local build speedups.
#
# It reports which external tools the build, the commit hook and the full gate each
# need and which of them are missing, offers to install the opt-in pre-commit hook,
# and offers a user-level cargo config that speeds up linking.
#
# Safe to re-run. It changes nothing without saying so first, and never installs a
# tool on your behalf: a missing one is reported with the command that installs it,
# rather than being installed silently.
#
#   scripts/dev-setup.sh            # report + prompt for the optional bits
#   scripts/dev-setup.sh --check    # report only; exit non-zero if a required tool is missing
#   scripts/dev-setup.sh --yes      # accept the optional bits without prompting
#
# Run it from anywhere in the checkout: it anchors itself to the repo root.

set -euo pipefail

# `git` first, and by hand: the anchoring `cd` below is itself a git call, so without it
# this script would die on `git: command not found` before any report — the one required
# tool it could not otherwise name.
if ! command -v git >/dev/null 2>&1; then
  printf 'MISSING git. Install it (apt install git, dnf install git, or Xcode Command Line Tools); this checkout and its pre-commit hook both need it.\n' >&2
  exit 1
fi

cd "$(git rev-parse --show-toplevel)"

CHECK_ONLY=0
ASSUME_YES=0
for arg in "$@"; do
  case "$arg" in
    --check) CHECK_ONLY=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    -h|--help) sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

if [ -t 1 ]; then
  BOLD=$'\033[1m'; OK=$'\033[32m'; WARN=$'\033[33m'; ERR=$'\033[31m'; DIM=$'\033[2m'; OFF=$'\033[0m'
else
  BOLD=''; OK=''; WARN=''; ERR=''; DIM=''; OFF=''
fi

section() { printf '\n%s== %s%s\n' "$BOLD" "$1" "$OFF"; }
yes_no() {
  [ "$ASSUME_YES" -eq 1 ] && return 0
  [ -t 0 ] || return 1   # non-interactive and no --yes: decline, do not hang
  printf '%s [y/N] ' "$1"
  read -r reply
  case "$reply" in [yY]*) return 0 ;; *) return 1 ;; esac
}

missing_required=0

# --- 1. Rust toolchain --------------------------------------------------------
section "Rust toolchain"
if command -v cargo >/dev/null 2>&1; then
  printf '  %sok%s   %s\n' "$OK" "$OFF" "$(cargo --version)"
  # rust-toolchain.toml pins the version; rustup honours it automatically.
  if [ -f rust-toolchain.toml ]; then
    pinned="$(grep -oE 'channel *= *"[^"]+"' rust-toolchain.toml | head -1 | cut -d'"' -f2 || true)"
    [ -n "$pinned" ] && printf '  %sthe repo pins channel %s (rust-toolchain.toml); rustup applies it here%s\n' \
      "$DIM" "$pinned" "$OFF"
  fi
else
  printf '  %sMISSING%s cargo. Install rustup: https://rustup.rs\n' "$ERR" "$OFF"
  missing_required=1
fi

# --- 2. Required for build, test and commit -----------------------------------
# These block the first build and the first commit, not only the full gate. `cc`, a C
# toolchain and linker: every crate builds at least one C-dependent build script, so
# `cargo build --workspace` fails with `error: linker `cc` not found` without one, and
# rustup's installer only warns about it. `python3`: `scripts/ci-local.sh quick` runs it
# for `script-tests`, and `.githooks/pre-commit` runs `check-doc-attachment.py` on every
# commit regardless of what changed. `curl`: CONTRIBUTING names it alongside git and cc,
# `ci-local.sh` preflights it, and several legs fetch with it — reported here so the claim
# that this script verifies the required set is true rather than nearly true. (`git` is
# checked at the top of this file, before the anchoring `cd`.)
section "Required for build, test and commit"
if command -v cc >/dev/null 2>&1; then
  printf '  %sok%s   %s\n' "$OK" "$OFF" "$(cc --version | head -1)"
else
  printf '  %sMISSING%s cc. Install a C toolchain: apt install build-essential, dnf install gcc, or Xcode Command Line Tools\n' "$ERR" "$OFF"
  missing_required=1
fi
if command -v python3 >/dev/null 2>&1; then
  printf '  %sok%s   %s\n' "$OK" "$OFF" "$(python3 --version)"
else
  printf '  %sMISSING%s python3. Install it from https://www.python.org/downloads/\n' "$ERR" "$OFF"
  missing_required=1
fi
if command -v git >/dev/null 2>&1; then
  printf '  %sok%s   %s\n' "$OK" "$OFF" "$(git --version)"
else
  # Unreachable in practice: the guard at the top of this file exits first. Kept so the
  # required set is listed in one place, and so the report stays complete if that
  # anchoring `cd` ever stops being a git call.
  printf '  %sMISSING%s git. Install it: apt install git, dnf install git, or Xcode Command Line Tools\n' "$ERR" "$OFF"
  missing_required=1
fi
if command -v curl >/dev/null 2>&1; then
  printf '  %sok%s   %s\n' "$OK" "$OFF" "$(curl --version | head -1)"
else
  printf '  %sMISSING%s curl. Install it: apt install curl, dnf install curl, or from https://curl.se/download.html\n' "$ERR" "$OFF"
  missing_required=1
fi

# --- 3. Tools scripts/ci-local.sh all needs (not required for build/test/commit) ------
# Delegates to the gate's own preflight so this list cannot drift from it. Not folded
# into missing_required: none of these block `cargo build`, `cargo test -p <crate>`,
# `scripts/ci-local.sh quick` or a commit. Only the full `scripts/ci-local.sh all` needs
# them, and several take minutes to build from source.
section "Tools scripts/ci-local.sh all needs (optional: for the full gate, not for building, testing or committing)"
if ./scripts/ci-local.sh preflight-all >/dev/null 2>&1; then
  printf '  %sok%s   every tool scripts/ci-local.sh all needs is present\n' "$OK" "$OFF"
else
  ./scripts/ci-local.sh preflight-all 2>&1 | grep -vE '^(==>|✓)' || true
  printf '  %sNone of the above is required to build, test or commit. They are needed only\n' "$DIM"
  printf '  by `scripts/ci-local.sh all`. Prefer a prebuilt binary where one exists:\n'
  printf '  gitleaks, cargo-deny and cargo-machete publish one, cargo-cyclonedx does not.%s\n' "$OFF"
fi

# --- 4. Optional tools --------------------------------------------------------
# Not needed by `all`; used by the release, coverage and Docker legs, plus the one
# interactive workflow (`cargo insta`) the test docs tell you to reach for. Reported so an
# absence is known before a release, or before a snapshot review, rather than at one.
section "Optional tools (release / coverage / Docker legs, and snapshot review)"
for entry in \
  $'docker\tDocker legs: lint-docker (actionlint, promtool, shellcheck, compose), e2e*, chaos, image-scan, cross' \
  $'cargo-insta\treview insta snapshots (docs/testing.md): cargo install cargo-insta --locked' \
  $'cargo-sweep\treclaim target/ space: cargo install cargo-sweep --locked' \
  $'cargo-llvm-cov\tcoverage report: cargo install cargo-llvm-cov --locked' \
  $'cargo-semver-checks\tAPI-break check: cargo install cargo-semver-checks --locked' \
  $'cargo-about\tlicence attribution: cargo install cargo-about --locked' \
  $'cross\tcross-compile legs: cargo install cross --locked' \
  $'trivy\timage CVE scan: https://aquasecurity.github.io/trivy/'
do
  tool="${entry%%$'\t'*}"; note="${entry#*$'\t'}"
  if command -v "$tool" >/dev/null 2>&1; then
    printf '  %sok%s   %s\n' "$OK" "$OFF" "$tool"
  else
    printf '  %s--%s   %-20s %s%s%s\n' "$WARN" "$OFF" "$tool" "$DIM" "$note" "$OFF"
  fi
done

# --- 5. Git hook --------------------------------------------------------------
section "Pre-commit hook"
current_hooks="$(git config core.hooksPath || true)"
if [ "$current_hooks" = ".githooks" ]; then
  printf '  %sok%s   core.hooksPath=.githooks (runs ci-local.sh quick on commit)\n' "$OK" "$OFF"
elif [ -n "$current_hooks" ] && [ "${current_hooks#/}" != "$current_hooks" ]; then
  # .git/config is not per-worktree, so an absolute hooksPath makes every worktree run
  # the main checkout's hook file. The relative form resolves per-worktree, from the repo
  # root and from a subdirectory alike.
  printf '  %s!!%s   core.hooksPath is an absolute path (%s)\n' "$WARN" "$OFF" "$current_hooks"
  printf '       .git/config is shared, so every worktree runs that file, not its own.\n'
  if [ "$CHECK_ONLY" -eq 1 ]; then
    printf '       run without --check to rewrite it as the relative .githooks\n'
  elif yes_no "  Rewrite it as the relative \`.githooks\`?"; then
    git config core.hooksPath .githooks
    printf '  %sok%s   rewritten\n' "$OK" "$OFF"
  else
    printf '  %s--%s   left as-is\n' "$WARN" "$OFF"
  fi
elif [ "$CHECK_ONLY" -eq 1 ]; then
  printf '  %s--%s   not installed; run without --check to enable\n' "$WARN" "$OFF"
else
  printf '  the hook runs ci-local.sh quick (fmt + clippy) before each commit.\n'
  printf '  %sIn a fresh worktree the first run is a full cold build.%s\n' "$DIM" "$OFF"
  if yes_no "  Install it (git config core.hooksPath .githooks)?"; then
    git config core.hooksPath .githooks
    printf '  %sok%s   installed\n' "$OK" "$OFF"
  else
    printf '  %s--%s   skipped\n' "$WARN" "$OFF"
  fi
fi

# --- 6. Local build speedups --------------------------------------------------
# mold speeds up linking, and unpacked split-debuginfo speeds it up further. The config
# stays out of the repo, because a committed linker override breaks anyone without mold
# installed. It goes in the user-level cargo config rather than in the checkout, because
# cargo merges $CARGO_HOME/config.toml into every project on the machine, worktrees
# included, while a gitignored per-checkout file is not part of a checkout at all. An
# existing user-level file is never edited, since a second [profile.dev] table breaks
# cargo; the block is printed for the user to add instead.
section "Local build speedups (optional, user-level cargo config)"
user_cfg="${CARGO_HOME:-$HOME/.cargo}/config.toml"
speedup_block() {
  cat <<'TOML'
# Local build speedups, user-level so every checkout and worktree on this machine
# inherits them: cargo merges $CARGO_HOME/config.toml into every project. Written by
# scripts/dev-setup.sh in the gdi-node-standalone checkout; delete it freely. rustflags
# are part of every unit's fingerprint, so adding or removing this file rebuilds each
# existing target/ once.
[target.x86_64-unknown-linux-gnu]
rustflags = ["-C", "link-arg=-fuse-ld=mold"]

[profile.dev]
split-debuginfo = "unpacked"
TOML
}
has_mold_cfg() { [ -f "$1" ] && grep -q 'fuse-ld=mold' "$1"; }

# The per-checkout form: worktrees do not inherit it, so offer to move it up a level, or
# report it as redundant when the user-level file already carries the block. A declined
# move is remembered, so the block below does not then offer to write the user-level
# file: that would be the same question twice, and a yes would leave two configs.
declined_move=0
if [ -f .cargo/config.toml ]; then
  printf '  %s!!%s   ./.cargo/config.toml is per-checkout; worktrees do not inherit it\n' "$WARN" "$OFF"
  if [ -f "$user_cfg" ]; then
    printf '       %s already exists; delete ./.cargo/config.toml once it carries the same block\n' "$user_cfg"
  elif [ "$CHECK_ONLY" -eq 1 ]; then
    printf '       run without --check to move it to %s\n' "$user_cfg"
  elif yes_no "  Move it to $user_cfg (every worktree then inherits it)?"; then
    mkdir -p "$(dirname "$user_cfg")"
    mv .cargo/config.toml "$user_cfg"
    printf '  %sok%s   moved; each existing worktree target/ rebuilds once on its next build\n' "$OK" "$OFF"
  else
    printf '  %s--%s   left as-is\n' "$WARN" "$OFF"
    declined_move=1
  fi
fi

if has_mold_cfg "$user_cfg"; then
  printf '  %sok%s   %s links with mold; every checkout on this machine inherits it\n' "$OK" "$OFF" "$user_cfg"
elif [ -f "$user_cfg" ]; then
  printf '  %s--%s   %s exists but has no mold override, and is not edited because a\n' "$WARN" "$OFF" "$user_cfg"
  printf '       second [profile.dev] table would break cargo. Add this block yourself:\n'
  speedup_block | sed 's/^/       /'
elif ! command -v mold >/dev/null 2>&1; then
  printf '  %s--%s   mold not installed. It makes linking substantially faster.\n' "$WARN" "$OFF"
  printf '       %sapt install mold%s (needs gcc >= 12), then re-run this script.\n' "$DIM" "$OFF"
elif [ "$CHECK_ONLY" -eq 1 ]; then
  printf '  %s--%s   mold is installed but unconfigured; run without --check to write %s\n' "$WARN" "$OFF" "$user_cfg"
elif [ "$declined_move" -eq 1 ]; then
  printf '  %s--%s   not writing %s: you just declined moving ./.cargo/config.toml there\n' "$WARN" "$OFF" "$user_cfg"
else
  printf '  mold is installed but unused. Writing %s enables it plus\n' "$user_cfg"
  printf '  unpacked split-debuginfo, which speeds up linking further, for every checkout\n'
  printf '  and worktree on this machine.\n'
  printf '  %sTrade-offs: unpacked debuginfo leaves DWARF in object files, so test binaries\n' "$DIM"
  printf '  are not relocatable, which is fine locally; and rustflags re-fingerprint every\n'
  printf '  unit, so each existing target/ rebuilds once. Do this with no gate in flight.%s\n' "$OFF"
  if yes_no "  Write $user_cfg?"; then
    mkdir -p "$(dirname "$user_cfg")"
    speedup_block > "$user_cfg"
    printf '  %sok%s   written\n' "$OK" "$OFF"
  else
    printf '  %s--%s   skipped: %s not written\n' "$WARN" "$OFF" "$user_cfg"
  fi
fi

# --- 7. Disk ------------------------------------------------------------------
# target/ trees are the largest thing a checkout accumulates, and each worktree carries
# its own; they must not share CARGO_TARGET_DIR.
section "Disk"
if [ -d target ]; then
  printf '  target/ is %s\n' "$(du -sh target 2>/dev/null | cut -f1)"
  printf '  %sreclaim with: scripts/ci-local.sh sweep   (needs cargo-sweep; SWEEP_MAXSIZE takes an explicit unit)%s\n' "$DIM" "$OFF"
else
  printf '  no target/ yet; the first build creates it and it will reach several GB\n'
fi

# --- Summary ------------------------------------------------------------------
if [ "$missing_required" -eq 1 ]; then
  printf '\n%sSome REQUIRED tools are missing. Install them before building, testing or committing.%s\n' "$ERR" "$OFF"
  exit 1
fi
printf '\n%sReady.%s Next:\n' "$OK" "$OFF"
printf '  cargo test -p <crate>            %sthe fast inner loop%s\n' "$DIM" "$OFF"
printf '  scripts/ci-local.sh quick        %sfmt + clippy, seconds%s\n' "$DIM" "$OFF"
printf '  scripts/ci-local.sh all          %sthe full gate; one run per machine at a time, a second queues%s\n' "$DIM" "$OFF"
printf '  See CONTRIBUTING.md for the test taxonomy and build profiles.\n'
