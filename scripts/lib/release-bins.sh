# shellcheck shell=bash
# Sourced by the load and soak harnesses once they have cd'd to $ROOT.

# release_bins: set NODE and TOOL, building the release binaries first unless both are
# given. Don't skip cargo just because the binaries exist: it is a no-op on a fresh
# build, and otherwise an old binary in target/release gets tested instead of the
# current code.
release_bins() {
  if [ -z "${NODE:-}" ] || [ -z "${TOOL:-}" ]; then
    echo "==> building release binaries"
    cargo build --release --locked --bins -p gdi-node-standalone -p gdi-dataset-tool
  fi
  TOOL="${TOOL:-$ROOT/target/release/gdi-dataset-tool}"
  NODE="${NODE:-$ROOT/target/release/gdi-node-standalone}"
}
