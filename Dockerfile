# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
#
# The syntax frontend is digest-pinned like both `FROM` images below, and it is not an
# ordinary base image: BuildKit downloads and executes it to build every stage, and it
# supplies the rule set behind `docker build --check`. A floating reference would run
# arbitrary new code on each build and change the lint rules silently.
#
# Dependabot's `docker` ecosystem updates `FROM` lines, not this directive, so nothing
# bumps it automatically — and a frozen frontend means new check rules never arrive,
# which is its own quiet failure. `ci-local.sh dockerfile-check` therefore reports
# (without failing) when upstream `docker/dockerfile:1` has moved past this digest.
#
# Single multi-stage Dockerfile packaging the `gdi-node-standalone` service. It covers both
# build paths via the `BIN_SOURCE` build-arg, so there is one runtime stage and no twin to
# keep in sync:
#
#   * BIN_SOURCE=builder  (default) — recompile from source. Used by local / Compose
#     builds and the `e2e-smoke` CI job. Feature-identical to the release artifact but
#     not guaranteed byte-identical.
#   * BIN_SOURCE=prebuilt — no recompile. The release `image` job stages the
#     already-released, cross-built x86_64 `gnu` (glibc) binary (plus the attribution
#     bundle) into the build context; this path packages it verbatim, so the published
#     image binary is byte-identical to the downloadable release binary and its SLSA
#     attestation covers the same bytes.
#
# The `gdi-dataset-tool` CLI is not in this image (it ships as separate signed release
# binaries). Runtime is `distroless/cc-debian13` (glibc + libgcc, no shell, no package
# manager); the service runs on glibc because it serves ~1.8-4x the Beacon throughput
# of a static musl build under concurrent load (musl's `mallocng` serialises
# allocation across the async worker pool). The binary needs no writable system paths,
# so the image runs with a read-only root filesystem; only the mounted `data_dir` (and
# `inbox`, if used) are writable. The non-root user is a numeric uid `65532:65532` (the
# distroless `nonroot` uid) — match the Kubernetes securityContext (`runAsNonRoot: true`,
# `runAsUser: 65532`).

# BIN_SOURCE selects which stage the final runtime COPYs from. Declared globally (before
# the first FROM) so it is usable in the `COPY --from=${BIN_SOURCE}` in the runtime stage.
ARG BIN_SOURCE=builder

# ---------------------------------------------------------------------------
# builder — recompile from source (BIN_SOURCE=builder). Pinned by digest as well as
# tag: the readable `1.98-trixie` tag is mutable (can be re-pushed), so the `@sha256:`
# index digest fixes the exact multi-arch builder image; it is Debian 13, the same
# glibc as the distroless runtime below. Dependabot's `docker` ecosystem refreshes both.
# ---------------------------------------------------------------------------
FROM rust:1.98.0-trixie@sha256:7f7a53a25a0319dd8284e279d529d45759cb384d59b14cc6806132910f45522e AS builder

WORKDIR /build

# Copy the whole workspace. `.dockerignore` keeps `target/`, `.git/`, etc. out of the
# build context so the layer cache is not busted by local build artifacts.
COPY . .

# FEATURES defaults to `full` (S3 + Vault + PME — feature-identical to the bare-metal
# release artifact). The dev/observability Compose overlay overrides it
# (`--build-arg FEATURES=full,otel`) to compile in the optional OTLP trace-export seam;
# the released image/binary keep the default `full` (otel is never shipped).
ARG FEATURES=full
# Optional build provenance, surfaced by `--version` / `GET /version` /
# `gdi_build_info{git_sha}`. Both default empty -> build.rs records "unknown".
#
# These ARGs are the only way provenance reaches an image built from this stage:
# `.dockerignore` excludes `.git`, so build.rs's `git` fallback cannot run in here. In
# the repo, `ci-local.sh image-provenance` and the Compose stacks pass both through
# `build.args`. The released image is built from the `prebuilt` stage below, packaging a
# binary whose provenance was baked in by the release job. They exist for anyone building
# their own image who wants a real commit instead of "unknown":
#   docker build --build-arg GITHUB_SHA="$(git rev-parse HEAD)" \
#                --build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" .
ARG GITHUB_SHA=
ARG SOURCE_DATE_EPOCH=
# BuildKit cache mounts (enabled by `# syntax=docker/dockerfile:1`) so a rebuild does
# not cold-recompile the whole dependency graph: the cargo registry/git and `target/`
# persist across builds. `target/` is a cache mount (ephemeral, not in the image
# layer), so the binary must be copied out to a real path in this same RUN. The
# committed attribution bundle + project licences (present via `COPY . .`) are staged
# alongside it under /staged so the runtime COPY is identical across both BIN_SOURCE
# paths. `sharing=locked` serialises the target dir so parallel builds can't corrupt it.
RUN --mount=type=cache,target=/build/target,sharing=locked \
    --mount=type=cache,target=/root/.cargo/registry,sharing=locked \
    --mount=type=cache,target=/root/.cargo/git,sharing=locked \
    GITHUB_SHA="${GITHUB_SHA}" SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
    cargo build --release --locked --features "${FEATURES}" \
        -p gdi-node-standalone \
    && mkdir -p /staged/licenses \
    && cp target/release/gdi-node-standalone /staged/gdi-node-standalone \
    && cp THIRD-PARTY-LICENSES.md LICENSE-APACHE LICENSE-MIT /staged/licenses/ \
    # Sanity-check the dynamic binary links cleanly (no unresolved libs); the runtime
    # `distroless/cc` base provides glibc + libgcc, which is all a Rust binary needs.
    && ldd /staged/gdi-node-standalone | grep -q 'libc.so' \
    && ! ldd /staged/gdi-node-standalone | grep -q 'not found' \
    && echo "ok: gdi-node-standalone is a dynamic glibc binary, all libs resolve"

# ---------------------------------------------------------------------------
# prebuilt — package the already-released binary verbatim (BIN_SOURCE=prebuilt). The
# release `image` job stages `gdi-node-standalone` + the three licence files into the build
# context; this stage normalises their layout under /staged to match the builder.
# `FROM scratch` holds no tools — pure file staging. On a `builder` build this stage is
# unreferenced, so BuildKit skips it entirely (the release-only context files need not
# exist for a local recompile build).
# ---------------------------------------------------------------------------
FROM scratch AS prebuilt
COPY gdi-node-standalone /staged/gdi-node-standalone
COPY THIRD-PARTY-LICENSES.md LICENSE-APACHE LICENSE-MIT /staged/licenses/

# Source selector: resolve BIN_SOURCE to a fixed stage name. ARG expansion is supported
# in `FROM` (but not in `COPY --from=`), so this is how the runtime COPY below sources
# from either `builder` or `prebuilt` without a variable in `--from`. Only the selected
# upstream stage is built; the other is skipped.
FROM ${BIN_SOURCE} AS binsrc

# ---------------------------------------------------------------------------
# Runtime: distroless/cc (glibc + libgcc) + the binary + the attribution bundle.
# ---------------------------------------------------------------------------
# The `nonroot` tag is mutable and is re-pushed whenever the base is rebuilt for CVE fixes,
# so a stale digest pin keeps shipping the old layer. Check this pin whenever you touch the
# image, and verify a new one with `trivy --severity HIGH,CRITICAL --ignore-unfixed` before
# committing it. Re-resolve with
#   docker buildx imagetools inspect gcr.io/distroless/cc-debian13:nonroot
# (or the registry manifest API) and bump tag+digest together. `ci-local.sh pins`
# checks this digest against the current upstream one on every run (WARN in `all`,
# fail under `PINS_STRICT=1`).
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:c31ff9abcb1910f3ab25c7957bdaf0bfe12a01eb546e8df2282f1c8f682b606c

# The service reads its config from GDI_CONFIG (default /etc/gdi-node-standalone/node.toml)
# and persists state under data_dir; both are mounted at runtime (a ConfigMap/Secret +
# a PVC/named volume).
ENV GDI_CONFIG=/etc/gdi-node-standalone/node.toml

# Non-root numeric uid:gid. The distroless `nonroot` base already defaults to this user;
# pin it explicitly (numeric, not a name) so K8s `runAsNonRoot` admission stays
# satisfied even if the base's default USER ever changes.
#
# Declared before the mount points below so the `WORKDIR`s that create them inherit this
# uid — see the ordering note there.
USER 65532:65532

# Pre-create the three mount points owned by 65532, so a fresh named volume inherits that
# ownership when Docker seeds it from the image and the service can write without an
# external chown. `WORKDIR` is the only tool available here: the runtime base is
# distroless (no shell, so no `RUN mkdir`) and `binsrc` may resolve to the `scratch`
# `prebuilt` stage, so the directories cannot be staged upstream either. Under BuildKit
# `WORKDIR` creates missing directories owned by the current `USER`, which is why `USER`
# is declared above.
#
# The third is the operator-override store, pre-created for the same reason as the other
# two even though it is absent from `VOLUME` below. `deploy/kubernetes` puts that store on
# its own PVC at exactly this path (configmap.yaml's `override_dir`, pvc.yaml,
# deployment.yaml), because it is the one directory a re-ingest cannot rebuild, and
# `docs/operating.md` §17 tells operators to keep it on separately-backed storage. Under
# Kubernetes, `securityContext.fsGroup: 65532` makes that mount writable. Under Docker a
# named volume at a path the image does not pre-create is created root-owned, so
# `overrides init` fails with EACCES and the node refuses to boot under
# `require_override_store`. Pre-creating the path makes
# `-v vol:/var/lib/gdi-node-standalone/overrides` work unattended.
#
# Pre-creating the root cannot weaken `require_override_store`:
# `override_store::ensure_present` demands the root plus `suppressions/` and `overlays/`,
# so an empty pre-created root still refuses to serve.
#
# Order matters: Docker discards writes made to a path after its `VOLUME` declaration,
# so these must precede it. Keep them adjacent.
WORKDIR /var/lib/gdi-node-standalone/datasets
WORKDIR /var/lib/gdi-node-standalone/inbox
WORKDIR /var/lib/gdi-node-standalone/overrides
WORKDIR /

# Durable mount points: the data dir (and the inbox, if used) must be on durable
# storage — a named volume / PVC, never emptyDir. The real volumes are supplied by
# Compose / K8s.
#
# A fresh named volume inherits the 65532 ownership set above only at a path the image
# pre-creates, so `docker run -v vol:/var/lib/gdi-node-standalone/datasets` works
# unattended — as does the override store's path, pre-created above for that reason.
# Three cases still need an external chown, because Docker never seeds them from the
# image: a bind mount (host path, host ownership); a Kubernetes PVC (use
# `securityContext.fsGroup: 65532`); and a named volume at any path not pre-created above
# — `override_dir` pointed somewhere of your own choosing, say — which Docker creates
# root-owned and the service then cannot write. A pre-existing volume created by an older
# image likewise keeps its old root ownership — `docker compose down -v` to recreate it.
#
# The override store is not declared here. `override_dir` defaults to
# `<data_dir>/overrides`, inside the datasets volume, so a separate volume for it is
# opt-in. Declaring it would mint an anonymous volume on every `docker run` for operators
# who never opt in, and would extend the durability requirement above to a path that does
# not carry one by default.
VOLUME ["/var/lib/gdi-node-standalone/datasets", "/var/lib/gdi-node-standalone/inbox"]

# The public beacon/FDP listener (see [service].listen) and the mandatory management
# plane (health + dataset-state + metrics; see [service].management_addr). Informational
# only — the actual bind comes from config; these are the conventional defaults.
EXPOSE 8080 9090

# Container health: the binary self-probes the management plane's /health/ready on
# loopback (distroless has no shell or curl to probe with). Exec form (no shell).
# --start-period absorbs node startup: probes get connection refused until the
# management listener binds, then 503 by design through the initial reconcile. Tune it
# up (e.g. 120s+) for a large S3 estate or a populated PME store, whose cold DEK unwraps
# can hold /health/ready at 503 well past the default window.
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
    CMD ["/gdi-node-standalone", "healthcheck"]

# The entrypoint is the service. It reads GDI_CONFIG / the default path; pass
# `--config <path>` or extra flags as `docker run ... <args>` (appended as CMD).
ENTRYPOINT ["/gdi-node-standalone"]

# Binary + third-party attribution bundle, from whichever source stage BIN_SOURCE
# selected (builder = recompiled, prebuilt = released-verbatim). The attribution bundle
# under /usr/share/doc discharges the permissive-licence binary-redistribution notice.
COPY --from=binsrc --chown=65532:65532 /staged/gdi-node-standalone /gdi-node-standalone
COPY --from=binsrc --chown=65532:65532 /staged/licenses/ /usr/share/doc/gdi-node-standalone/
