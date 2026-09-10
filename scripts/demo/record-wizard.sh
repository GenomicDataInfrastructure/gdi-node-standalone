#!/usr/bin/env bash
# Record the README's animated wizard session from a real run of `gdi-dataset-tool wizard`.
#
# Prerequisites
#   * a node the wizard can talk to, with an S3 bucket it can upload to. The shipped Compose
#     S3 stack on its default host ports is the intended one:
#       gdi-node-standalone --config compose/node.s3.toml identity init --file compose/keys/node.c4gh
#       COMPOSE_PROFILES=garage docker compose -f docker-compose.yml -f docker-compose.s3.yml up -d
#   * the release tool (`cargo build --release -p gdi-dataset-tool`), docker, python3, and
#     node's `npx` (it fetches svg-term-cli, which renders the SVG).
#
# Usage
#   scripts/demo/record-wizard.sh [OUT.svg]             default: docs/images/wizard.svg
#
#   DEMO_NODE_URL / DEMO_MGMT_URL / DEMO_S3_ENDPOINT / DEMO_S3_BUCKET / DEMO_S3_REGION /
#   DEMO_S3_ACCESS_KEY / DEMO_S3_SECRET_KEY point at another stack (shifted host ports, a
#   bucket of your own). DEMO_KEEP=1 keeps the scratch dir with the .cast; DEMO_DUMP=1 also
#   writes the ANSI-stripped transcript there, which is what to read when a prompt changed and
#   drive-wizard.py's SCRIPT table needs the new wording.
#
# The wizard runs in a throwaway container with a clean home directory, so every path in the
# recording is a provider's (`/home/provider/...`), not this machine's. `--network host` is
# what lets it reach the stack's loopback-published ports. The image is pinned by digest like
# every other image in the tree; Debian trixie's glibc is newer than the tool's floor.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

OUT="${1:-docs/images/wizard.svg}"
: "${DEMO_NODE_URL:=http://127.0.0.1:8080}"
: "${DEMO_MGMT_URL:=http://127.0.0.1:9090}"
: "${DEMO_S3_ENDPOINT:=http://127.0.0.1:3900}"
: "${DEMO_S3_BUCKET:=gdi-datasets}"
: "${DEMO_S3_REGION:=garage}"
: "${DEMO_S3_ACCESS_KEY:=GK0123456789abcdef01234567}"
: "${DEMO_S3_SECRET_KEY:=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"
TOOL="${DEMO_TOOL:-target/release/gdi-dataset-tool}"
IMAGE="python:3.13-slim-trixie@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285"

for c in docker python3 npx; do
  command -v "$c" >/dev/null 2>&1 || { echo "record-wizard: need $c on PATH" >&2; exit 1; }
done
[ -x "$TOOL" ] || { echo "record-wizard: no tool binary at $TOOL (cargo build --release -p gdi-dataset-tool)" >&2; exit 1; }
# A recording of a stale binary would show prompts the wizard no longer asks. The
# tool's sources include the core crate's, which every wizard step reads config through.
if [ -n "$(find crates/gdi-dataset-tool/src crates/core/src -name '*.rs' -newer "$TOOL" -print -quit)" ]; then
  echo "record-wizard: $TOOL is older than the tool's sources; rebuild it first (cargo build --release -p gdi-dataset-tool)" >&2
  exit 1
fi
curl -fsS "$DEMO_MGMT_URL/health/ready" >/dev/null 2>&1 \
  || { echo "record-wizard: no ready node at $DEMO_MGMT_URL (start the Compose S3 stack first)" >&2; exit 1; }

work="$(mktemp -d)"
# Named, and removed on exit: when the driver gives up on a prompt it kills the docker client,
# and an unnamed `--rm` container would go on running the wizard's prompt for hours.
container="gdi-wizard-recording-$$"
cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  if [ "${DEMO_KEEP:-0}" != 1 ]; then rm -rf "$work"; fi
}
trap cleanup EXIT
mkdir -p "$work/home/work"
dump=()
if [ "${DEMO_DUMP:-0}" = 1 ]; then dump=(--dump "$work/transcript.txt"); fi

python3 scripts/demo/drive-wizard.py --out "$work/wizard.cast" "${dump[@]}" \
  --node-url "$DEMO_NODE_URL" --management-url "$DEMO_MGMT_URL" \
  --s3-endpoint "$DEMO_S3_ENDPOINT" --s3-bucket "$DEMO_S3_BUCKET" --s3-region "$DEMO_S3_REGION" \
  --s3-access-key "$DEMO_S3_ACCESS_KEY" --s3-secret-key "$DEMO_S3_SECRET_KEY" -- \
  docker run --rm -it --name "$container" --network host --user "$(id -u):$(id -g)" \
    -e HOME=/home/provider -e TERM=xterm-256color -w /home/provider/work \
    -v "$work/home:/home/provider" \
    -v "$REPO_ROOT/crates/test-util/tests/fixtures/sample:/home/provider/work/data:ro" \
    -v "$(realpath "$TOOL"):/usr/local/bin/gdi-dataset-tool:ro" \
    "$IMAGE" gdi-dataset-tool wizard

npx -y svg-term-cli --in "$work/wizard.cast" --out "$OUT" --window --width 100 --height 32 --padding 12
echo "record-wizard: wrote $OUT ($(wc -c <"$OUT") bytes)"
if [ "${DEMO_KEEP:-0}" = 1 ]; then echo "record-wizard: scratch kept at $work"; fi
