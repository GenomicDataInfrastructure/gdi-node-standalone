#!/bin/sh
# Reset the dev stack: destroy the secrets and data volumes together.
#
# Secrets and data must not get independent lifecycles. If the secrets backend loses its
# keys while the datasets volume survives, the data left behind is permanently
# undecryptable, so this script never removes one without the other.
#
# Destructive, so it refuses to act without --yes.

set -eu

# Anchor to the repo root before anything reads the working directory.
#
# Everything below is derived from the working directory: `PROJECT` comes from
# `basename $(pwd)`, `docker compose down -v` picks its project, and therefore its volume
# set, from the working directory, and the `--keys` unlink is a relative path. Run from
# another directory that hosts a Compose stack, all of those resolve to that stack and
# this script destroys it, while printing a summary that describes it accurately.
#
# `$0`-relative rather than `git rev-parse --show-toplevel`, so it also works when the
# script is invoked by absolute path from a directory outside any git repository.
cd "$(dirname "$0")/.."

DRY_RUN=0
CONFIRMED=0
DROP_KEYS=0

usage() {
    cat <<'EOF'
usage: scripts/dev-reset.sh [--dry-run] [--yes] [--keys]

  --dry-run   print what would be destroyed, then exit without touching anything
  --yes       actually destroy it; there is no interactive prompt
  --keys      also delete compose/keys/node.c4gh, the identity you minted by hand

Destroys the dev stack's containers and all its volumes: the secrets backend
storage and keys, the datasets and inbox volumes, and the S3 backend volumes.
EOF
}

for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        --yes)     CONFIRMED=1 ;;
        --keys)    DROP_KEYS=1 ;;
        -h|--help) usage; exit 0 ;;
        *)         echo "unknown argument: $arg" >&2; usage >&2; exit 2 ;;
    esac
done

# The Compose project name, which labels every container and volume this stack
# creates. Compose derives it from the directory name unless overridden.
PROJECT="${COMPOSE_PROJECT_NAME:-$(basename "$(pwd)" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9_-]//g')}"
LABEL="com.docker.compose.project=$PROJECT"

# Discover what exists rather than reciting a hardcoded list. The volume set depends on
# which overlays have been used, and `down -v` against the base file alone leaves every
# overlay volume behind. A hardcoded list here would be a second copy of the compose
# files' volume set and would drift from them.
if command -v docker >/dev/null 2>&1; then
    FOUND_VOLUMES=$(docker volume ls --filter "label=$LABEL" --format '{{.Name}}' 2>/dev/null || true)
    FOUND_CONTAINERS=$(docker ps -a --filter "label=$LABEL" --format '{{.Names}}' 2>/dev/null || true)
else
    FOUND_VOLUMES=""
    FOUND_CONTAINERS=""
fi

echo "This will destroy the following dev state (Compose project '$PROJECT'):"
echo
if [ -n "$FOUND_VOLUMES" ]; then
    echo "  volumes:"
    echo "$FOUND_VOLUMES" | sed 's/^/    /'
else
    echo "  volumes:    none found, nothing to remove"
fi
echo
if [ -n "$FOUND_CONTAINERS" ]; then
    echo "  containers:"
    echo "$FOUND_CONTAINERS" | sed 's/^/    /'
else
    echo "  containers: none found"
fi
echo
echo "  This includes the secrets backend storage (node identity + Transit key) and"
echo "  the datasets volume together. Removing one without the other leaves data that"
echo "  no surviving key can read."

if [ "$DROP_KEYS" -eq 1 ]; then
    echo "  files:   compose/keys/node.c4gh (--keys given)"
else
    echo "  KEPT:    compose/keys/node.c4gh; pass --keys to delete it too"
fi
echo

if [ "$DRY_RUN" -eq 1 ]; then
    echo "dry run: nothing was destroyed"
    exit 0
fi

if [ "$CONFIRMED" -ne 1 ]; then
    echo "refusing to destroy anything without --yes (or use --dry-run)" >&2
    exit 1
fi

command -v docker >/dev/null 2>&1 || { echo "docker not found" >&2; exit 1; }

echo "removing containers and volumes..."
# `down -v` handles the base file's services and volumes, and --remove-orphans takes
# containers from any overlay no longer in the config. It does not remove the overlays'
# volumes, so the label-scoped sweep below finishes the job: `down` stops things
# gracefully, the sweep guarantees completeness.
docker compose down -v --remove-orphans

REMAINING=$(docker volume ls --filter "label=$LABEL" --format '{{.Name}}' 2>/dev/null || true)
if [ -n "$REMAINING" ]; then
    echo "removing overlay volumes left behind by \`down -v\`:"
    echo "$REMAINING" | sed 's/^/    /'
    # shellcheck disable=SC2086 # word-splitting is wanted: one arg per volume name
    docker volume rm $REMAINING >/dev/null
fi

STILL_THERE=$(docker volume ls --filter "label=$LABEL" --format '{{.Name}}' 2>/dev/null || true)
if [ -n "$STILL_THERE" ]; then
    echo "ERROR: these volumes could not be removed:" >&2
    echo "$STILL_THERE" | sed 's/^/    /' >&2
    echo "something may still be using them; try: docker compose down --remove-orphans" >&2
    exit 1
fi

if [ "$DROP_KEYS" -eq 1 ]; then
    rm -f compose/keys/node.c4gh compose/keys/node.c4gh.pub
    echo "removed compose/keys/node.c4gh{,.pub}"
fi

echo "done. Next: docker compose up -d --build && docker compose run --rm setup"
echo "      then: docker compose run --rm gdi-node-standalone identity init"
