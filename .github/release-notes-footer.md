---

**Artifacts**

Published assets for this release, generated from what was staged, so this list cannot
drift from the build matrix the way a hand-written platform list does:

__ARTIFACTS__

What they are:

- `gdi-dataset-tool` — the data-provider CLI that builds, validates and packs a dataset.
- `gdi-node-standalone` — the node service, with S3 + Vault + PME compiled in and every one
  of them optional. The `gnu`/glibc builds are the primary, deployed artifact; the
  fully-static `musl` builds are a fallback for Alpine / NixOS / hard-static hosts where
  the dynamic glibc binary cannot run. For an inbox-only node, leave `[s3]`/`[vault]`
  unconfigured and the optional subsystems stay dormant.
- `SHA256SUMS` — checksums covering every artifact above.
- `*.cdx.json` — one CycloneDX SBOM per shipped binary (`gdi-node-standalone.cdx.json`,
  `gdi-dataset-tool.cdx.json`).
- `THIRD-PARTY-LICENSES.md`, `LICENSE-APACHE`, `LICENSE-MIT` — attribution bundle and the
  project's own dual licence.

Every artifact carries a SLSA build-provenance attestation; verify with
`gh attestation verify <file> --repo __REPO__`.

The container image is published to GHCR (`ghcr.io/__IMAGE__`) from the same released
x86_64 `gnu`/glibc binary (no recompile), so the image and that bare-metal binary are
byte-identical; it carries its own SLSA build-provenance attestation.
