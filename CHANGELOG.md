# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The library crates `gdi-node-standalone-core`, `gdi-node-standalone-beacon` and
`gdi-node-standalone-fairdp` follow SemVer for their Rust API by convention; nothing
enforces it. All three are `publish = false`, the `semver-checks` job in
`.github/workflows/ci.yml` is PR-only and advisory, and `scripts/ci-local.sh all` excludes
it, so run `scripts/ci-local.sh semver-checks` yourself when you change a public API.

The public **wire contracts** are a stability surface too. The GDI-specific Beacon
`resultSets` nesting and the FAIR Data Point graph shape are pinned by golden and snapshot
tests. A change to either is externally breaking: version-bump it (`api_version` for
Beacon; `gdi_metadata_version` / `manifestVersion` for the metadata model) and record it
here for the aggregator, harvester and GDI User Portal. Regenerating a snapshot is not a
licence to merge one silently.

<!-- Keep this file minimal and hand-curated. Record only consumer-facing and breaking
changes, especially to the Beacon / FDP wire contracts above. The full per-commit history
lives in git (Conventional Commits); release bodies also append an auto-generated commit
list below the section curated here. -->

## [Unreleased]

<!--
Record only real entries here. See CONTRIBUTING.md#cutting-a-release for rolling this
section into `## [X.Y.Z] - YYYY-MM-DD` at release time. Move only the real entries; leave
this comment under `## [Unreleased]`. The release workflow fails if no versioned section
exists.

The `## [1.0.0]` date below is the intended release date, not a tagged fact: no tag has
been cut. Correct it to the actual date if the tag slips, before pushing `v1.0.0`.

No tag exists yet either, so `[Unreleased]` at the bottom points at the commit log rather
than a compare range. Change it to `compare/v1.0.0...HEAD` once `v1.0.0` is tagged, which
is also when `[1.0.0]` starts resolving.
-->

## [1.0.0] - 2026-09-09

*Prepared, not yet tagged: this section becomes true when `v1.0.0` is pushed, and the link
at the bottom resolves from that moment.*

Initial public release. There is no earlier public version, so this section records the
baseline rather than a set of changes: it names the contracts this release establishes, so
that every later entry has something concrete to be breaking *against*.

### Added

- **The `gdi-node-standalone` service** — a GA4GH Beacon v2 endpoint and a FAIR Data Point
  served on a public plane, with a separate in-cluster management plane. It ingests
  crypt4gh-encrypted `.tar.c4gh` dataset packages from an S3 bucket or a filesystem inbox
  and stores aggregated Parquet at rest, optionally encrypted.
- **The `gdi-dataset-tool` provider CLI** — builds, validates and packs a dataset package
  from VCF, for a data provider who does not run the node.

### Contracts established by this release

A change to any of the wire contracts below is externally breaking. Bump the stated version
and record it here, so the aggregator, harvester and GDI User Portal can act on it. The Rust
version is not a wire contract: it is a ratchet, raised when a dependency needs it, and is
listed only so a packager knows what the source needs.

| Contract | Version |
| --- | --- |
| Beacon API (`[beacon].api_version`) | `v2.2.0` |
| Beacon variant location encoding | GA4GH VRS 1.3 |
| GDI metadata model (`gdi_metadata_version`) | `1.2.0` |
| Dataset package (`manifestVersion`) | `1` |
| Minimum supported Rust version | `1.96` |

The FAIR Data Point graph shape follows the FDP specification and DCAT-AP; it is pinned by
snapshot tests rather than by a version number of its own.

[Unreleased]: https://github.com/GenomicDataInfrastructure/gdi-node-standalone/commits/main
[1.0.0]: https://github.com/GenomicDataInfrastructure/gdi-node-standalone/releases/tag/v1.0.0
