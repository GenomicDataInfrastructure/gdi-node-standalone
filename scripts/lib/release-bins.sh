# shellcheck shell=bash
# Sourced by the load and soak harnesses once they have cd'd to $ROOT.

# release_bins: set NODE and TOOL, building the release binaries first unless both are
# given. Don't skip cargo just because the binaries exist: it is a no-op on a fresh
# build, and otherwise an old binary in target/release gets tested instead of the
# current code. Look for them where cargo puts them: $CARGO_TARGET_DIR, else $ROOT/target.
release_bins() {
  if [ -z "${NODE:-}" ] || [ -z "${TOOL:-}" ]; then
    echo "==> building release binaries"
    cargo build --release --locked --bins -p gdi-node-standalone -p gdi-dataset-tool
  fi
  local target="${CARGO_TARGET_DIR:-$ROOT/target}"
  TOOL="${TOOL:-$target/release/gdi-dataset-tool}"
  NODE="${NODE:-$target/release/gdi-node-standalone}"
}
