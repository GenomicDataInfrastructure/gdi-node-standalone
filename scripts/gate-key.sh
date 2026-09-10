#!/usr/bin/env bash
#
# Print a content hash of everything `scripts/ci-local.sh all` depends on, so that `all`
# can short-circuit when its inputs are byte-identical to those of the last green run.
# A full gate run costs tens of minutes, and re-verifying an unchanged tree proves nothing.
#
# In the key:
#   * every tracked file and every untracked-but-not-ignored file, hashed by its
#     working-tree content. An uncommitted edit changes the key, and a tracked file
#     deleted in the working tree drops out of the listing and changes it too. The
#     listing is sorted, so whether a file is untracked, staged or committed does not
#     change the key;
#   * `rustc -vV` and `cargo --version`. The same source built by a different compiler is
#     a different result, and a two-component channel such as `+1.96` floats to 1.96.1.
#
# Not in the key. This is the residual risk, asserted in scripts/tests/test_gate_key.py so
# that it stays a known fact:
#   * gitignored files. A local `.env` or `config.toml` can change without changing the
#     key, and gate legs do read such files: `secrets` runs `gitleaks --no-git`, which
#     ignores .gitignore and so scans thousands of files this key cannot see. A
#     `cargo fuzz` run changes what `secrets` scans while leaving the key identical. So a
#     short-circuit re-runs `secrets` first, alongside deny, deny-fuzz and pip-audit, for
#     the same reason those three are there: their verdict is not a function of this key.
#   * file mode. `sha256sum` hashes content, so `chmod +x scripts/new-leg.sh` leaves the
#     key byte-identical even though it decides whether the hook and `run` can execute
#     the script at all.
#   * environment variables (`GDI_CORPUS_DIR`, `GDI_FDP_PYTHON`, …) and the versions of
#     externally-installed tools (`cargo-deny`, `cargo-about`, the pinned Docker images).
#   * anything time-dependent, above all the RustSec advisory database. That is why a
#     short-circuit still runs those four legs instead of skipping the lot, and why the
#     marker carries a TTL. `pins` is not among them: a dozen or so GitHub API calls per
#     run would spend the unauthenticated budget, and upstream refs do not move hourly, so
#     it runs in every full `all` instead.
#
# Usage: scripts/gate-key.sh [repo-root]   (defaults to the enclosing git work tree)
set -euo pipefail

root="${1:-$(git rev-parse --show-toplevel)}"
cd "$root"

# Capture the file listing to a temp file first; a variable cannot hold it, because
# `$(…)` strips the `-z` NULs. A `git ls-files` failure or an empty listing is fatal
# rather than swallowed: in a non-git tree, or under a hijacked `GIT_DIR`, a swallowed
# failure collapses the key to the toolchain versions alone, a tree-independent constant
# that `gate-status` then reports as FRESH over any tree.
listing="$(mktemp)"
trap 'rm -f "$listing"' EXIT
# Sorted, so the key is a function of the tree's content and not of the index: git lists
# tracked files first and untracked ones after, so an unsorted listing changes the moment
# a new file is staged, and every commit that adds a file pays a full re-run for no
# change in bytes. Byte order (LC_ALL=C), so the result cannot depend on the caller's
# locale either.
if ! git ls-files -z --cached --others --exclude-standard | LC_ALL=C sort -z >"$listing"; then
  echo "gate-key: 'git ls-files' failed in $root; refusing to emit a tree-independent key" >&2
  exit 1
fi
if [ ! -s "$listing" ]; then
  echo "gate-key: 'git ls-files' listed no files in $root; is it a git work tree?" >&2
  exit 1
fi
# `-z` + `-0` so newlines in filenames cannot split a record. sha256sum preserves input
# order even when xargs batches. The `|| true` tolerates only a per-file `sha256sum`
# failure: a path that `git ls-files --cached` still lists but which is deleted or
# renamed in the working tree drops out of the digest, which is how a delete or a rename
# changes the key. The listing failure that would collapse the whole key is fatal above.
hashes="$(xargs -0 -r sha256sum <"$listing" 2>/dev/null || true)"
# A wholesale hashing failure is fatal too: no `sha256sum` on PATH, or `xargs` failing.
# The listing was non-empty, so an empty digest means nothing was hashed and the key
# would collapse to `rustc -vV` + `cargo --version`, a tree-independent constant that
# reads FRESH on any later tree.
if [ -z "$hashes" ]; then
  echo "gate-key: hashing the listing produced nothing in $root, so sha256sum or xargs is missing or failing; refusing to emit a tree-independent key" >&2
  exit 1
fi
{
  printf '%s\n' "$hashes"
  rustc -vV 2>/dev/null || true
  cargo --version 2>/dev/null || true
} | sha256sum | cut -d' ' -f1
