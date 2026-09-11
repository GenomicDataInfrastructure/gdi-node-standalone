# `gdi-dataset-tool` — provider guide

The complete reference for `gdi-dataset-tool`, the command-line tool a data provider runs
to prepare, package, and ship GDI dataset packages to a `gdi-node-standalone` node. The
[README](../README.md) holds the project overview and a 5-minute local quickstart.

> ### If you read nothing else
>
> The happy path is four verbs, and which four depends on your node.
> [`init`](#init) scaffolds a `package.yaml` and [`build`](#build) turns your VCF into a
> validated staging directory. Then either [`pack`](#pack) encrypts it to the node's
> recipient and [`upload`](#upload) ships it to S3, or, for a co-located keyless node,
> [`deploy`](#deploy) drops the staging directory straight into its inbox with no `pack`
> and no keys. [`package`](#package) is `build` + `pack` in one step, and
> [`wizard`](#wizard) walks the whole journey interactively.
>
> Three things trip up new providers:
>
> - The country code is a build-time identity, not a setting you can change later. It is
>   baked into the dataset id. See [Concepts](#concepts).
> - Re-keying for a `writer_policy = enforce` node needs `--as <your-provider-key>`.
>   Without it the node rejects every re-keyed package. See [`rekey`](#rekey).
> - You may not learn that ingest failed. [`status`](#status) reads the node's management
>   plane, which is usually not reachable from outside the cluster; failing that it needs
>   the bucket's opt-in `_status/` writeback. Agree one of the two with your node operator
>   before you ship.

---

## Table of contents

- [Overview](#overview)
- [Installation](#installation)
- [Concepts](#concepts)
  - [The dataset ID](#the-dataset-id)
  - [The package (`.tar.c4gh`)](#the-package-tarc4gh)
  - [Recipients and the provider keypair](#recipients-and-the-provider-keypair)
  - [Install channels: S3 vs inbox](#install-channels-s3-vs-inbox)
- [Configuration](#configuration)
  - [Tool config file](#tool-config-file)
  - [Sections and fields](#sections-and-fields)
  - [Environment variables](#environment-variables)
  - [Global flags](#global-flags)
- [`package.yaml` authoring](#packageyaml-authoring)
  - [The `metadata` section](#the-metadata-section)
  - [The `files` section](#the-files-section)
  - [The `internal` section](#the-internal-section)
  - [The `config` section](#the-config-section)
- [Data requirements and constraints](#data-requirements-and-constraints)
  - [What `build` keeps from the VCF](#what-build-keeps-from-the-vcf)
  - [INFO field naming (the population grammar)](#info-field-naming-the-population-grammar)
  - [What the `minAlleleCount` floor removes](#what-the-minallelecount-floor-removes)
  - [Notes vs warnings, and `--strict`](#notes-vs-warnings-and---strict)
  - [Preflighting a whole package](#preflighting-a-whole-package)
  - [Reproducible builds](#reproducible-builds)
  - [Comparing two builds](#comparing-two-builds)
  - [Conversion provenance in the manifest](#conversion-provenance-in-the-manifest)
- [Resources](#resources)
  - [Memory: `--jobs` is the only lever](#memory---jobs-is-the-only-lever)
  - [Disk](#disk)
- [Provider-side key management](#provider-side-key-management)
- [Command reference](#command-reference)
  - [Setup](#setup-commands)
  - [Authoring](#authoring-commands)
  - [Packaging](#packaging-commands)
  - [Key management](#key-management-commands)
  - [S3 deploy workflow](#s3-deploy-workflow)
  - [Inbox deploy workflow](#inbox-deploy-workflow)
  - [Offline / air-gapped workflow](#offline--air-gapped-workflow)
  - [Lifecycle](#lifecycle-commands)
  - [Inspection and troubleshooting](#inspection-and-troubleshooting-commands)
- [End-to-end workflows](#end-to-end-workflows)
- [Troubleshooting](#troubleshooting)

---

## Overview

`gdi-dataset-tool` is run by an external data provider — a hospital, biobank or research
institute — to turn source VCF files into an encrypted dataset package and ship it to a
node. It can also be run at the node itself to manage datasets in S3.

The typical lifecycle is:

```
S3 node      init  ──►  build  ──►  pack   ──►  upload  ──►  publish
             (template) (parquet)  (.tar.c4gh)  (S3)        (make visible)

inbox node   init  ──►  build  ──────────────►  deploy  ──►  publish
             (template) (parquet)               (inbox)      (make visible)
```

The second row is the co-located case, the README's Quickstart 1. The node reads a local
inbox, so the package never crosses a trust boundary and encrypting it to a key on the same
disk buys nothing. Set `keyless = true` on the profile and `deploy` ships the staging
directory itself: no `pack`, no recipient, no keys to manage.

`build` and `pack` are usually run together via the `package` convenience command.

Output discipline (see [Output and diagnostics](#output-and-diagnostics)):

- Data output (`inspect --manifest`, `list`, `status`) goes to stdout, kept clean for
  piping.
- Logs, warnings, and progress go to stderr.

All user-fixable errors print a single-line message to stderr, with no stack trace. The
process exit code classifies the failure so scripts can branch on it:

| Code | Meaning |
|------|---------|
| `0` | Success. |
| `1` | Error: a general, user-fixable failure. |
| `2` | Usage: bad flags or argument parsing. |
| `3` | Transient: a retryable upstream failure, such as an HTTP 503. |
| `4` | Auth: an authentication or authorization failure, such as an HTTP 403. |
| `5` | Strict: `build --strict` was passed and a `warning:` was emitted. The tool worked; the input data has problems. See [`--strict`](#notes-vs-warnings-and---strict). |

> The whole S3 surface honours this contract. `upload`, `list`, `delete`,
> `publish`/`unpublish`, `status` and `download` all classify a denied request as `4` and
> a throttled or retry-exhausted one as `3`, so scripts branch on `3` to retry and on `4`
> to refresh credentials.

---

## Installation

The tool is a single Rust binary in the `gdi-node-standalone` Cargo workspace. You do not
need to run a node to use it: a data provider builds packages on their own machine and
ships them to whoever operates the node.

**Get the source:**

```bash
git clone https://github.com/GenomicDataInfrastructure/gdi-node-standalone.git
cd gdi-node-standalone
```

**What you need.** A Rust toolchain and a C compiler. `rust-toolchain.toml` pins the
toolchain, so `rustup` selects it when you enter the directory; install `rustup` from
<https://rustup.rs> if you do not have it. The minimum supported Rust
version is 1.96, and every crate builds a C-dependent build script, so a linker
(`build-essential`, `gcc`, or the Xcode command line tools) must be present.

Nothing else: no S3 endpoint, no Vault, no at-rest encryption. The binary does always link
the S3 and network stack, as the note below explains.

> **There are prebuilt binaries now.** `v1.0.0-rc.1` ships the tool for Linux (`gnu` and
> `musl`), macOS on Apple silicon and Windows, with checksums and a provenance attestation,
> on the [Releases page](https://github.com/GenomicDataInfrastructure/gdi-node-standalone/releases).
> Building from source, below, still works.

During development, run it through Cargo:

```bash
cargo run -p gdi-dataset-tool -- <command> [args...]
```

To build a release binary:

```bash
cargo build --release -p gdi-dataset-tool
# binary at target/release/gdi-dataset-tool
```

The tool always links the S3 and network stack; there is no no-network build variant.
The package-creation path (`build`, `validate`, `pack`, `package`) still works offline.
Only the networked commands need connectivity (see
[Offline / air-gapped workflow](#offline--air-gapped-workflow)).

> The examples below use `gdi-dataset-tool <command>`. When running from the
> workspace, prefix with `cargo run -p gdi-dataset-tool --`.

**Shell completions.** Generate a completion script with
`gdi-dataset-tool completions <bash|zsh|fish|elvish|powershell>` and install it where the
shell expects it, for example
`gdi-dataset-tool completions bash > /etc/bash_completion.d/gdi-dataset-tool`.

---

## Concepts

### The dataset ID

Format: `(GOE|GDI)-CC-ORG-YYYYMMDDHHMMSSmmm`

| Part | Meaning | Source |
|------|---------|--------|
| `GOE` / `GDI` | prefix | `metadata.prefix` in `package.yaml` |
| `CC` | two-letter uppercase country code | tool config / env / `--cc` flag (see precedence below) |
| `ORG` | institute abbreviation, 1–16 uppercase letters | `metadata.org` in `package.yaml` |
| `YYYYMMDDHHMMSSmmm` | 17-digit UTC timestamp (millisecond precision) | generated automatically at build time |

Example: `GDI-EE-EXAMPLE-20260409143052837`.

The tool generates the whole ID at `build`/`package` time. The millisecond timestamp
makes same-org collisions between two builds negligible, and the `upload`/`deploy` guards
catch the remainder.

**Country-code precedence** (lowest → highest):

1. the tool config's root-level `country_code`
2. the `GDI_TOOL__COUNTRY_CODE` environment variable
3. the `--country-code` / `--cc` flag on `build` / `package`

There is no default. If none of the three is set, `build`/`package` fail with an error
naming all three sources. `init` mints no ID and is unaffected.

Validation of an ID the tool did not mint (`internal.pastVersion`, or an ID from another
node) uses the broader pattern `^(GOE|GDI)-[A-Z]{2}-[A-Z]+-[0-9]+$` plus an overall
64-character cap, so foreign short-numeric IDs like `GDI-FI-THL-1` are accepted.

### The package (`.tar.c4gh`)

A package is an uncompressed TAR archive encrypted with crypt4gh. The member order is a
small metadata prefix followed by the bulk payload:

```
manifest.json                              # first member — metadata prefix
headers/{vcfid}.vcf                        # one per source VCF; see --header-policy / --no-headers
allele-freq.<chr>.<n>.<...>.parquet        # bulk payload — aggregated allele frequencies
```

Every member has normalized permissions (files `0o644`), cleared ownership (uid and gid 0,
empty uname and gname), and a fixed mtime of 0, so the output is reproducible. Because
`manifest.json` is first and the payload is last, a metadata-only consumer, `inspect
--manifest` included, reads the front of the package and stops before the parquet.

The output file name is `{datasetId}.tar.c4gh`.

### Recipients and the provider keypair

Every package is encrypted to two crypt4gh recipients:

1. **The node**, its public recipient, and mandatory. Resolved from a local file: the
   `--recipient` flag, or the active profile's `node_recipient_file`.
2. **The provider**, their own recipient, derived from the first `[keys].identities` entry
   and added automatically so you can always decrypt your own packages.

Adding the provider as a recipient never affects the node's ability to decrypt.
`inspect`, `unpack`, `validate` and `check` decrypt a package by trying every configured
provider identity in order, so a package encrypted to a now-retired key still decrypts.

When the node recipient is fetched online (the profile's `node_recipient_url`, or
`service_url`'s `/.well-known/c4gh-recipient`) rather than supplied as a local file, the
tool pins the fetched key trust-on-first-use at
`<config_dir>/recipients/<host>.<hash>.pub`. The pin is keyed on the recipient URL rather
than the profile name, so one node has one pin however many profiles reach it. The first
fetch records the key and every later fetch must match it, so a spoofed or compromised
endpoint cannot silently substitute a recipient.

If the key cannot be anchored at all (no `--recipient`, no `node_recipient_file`, and no
resolvable config directory to pin into) `pack`/`package` fails closed rather than trust
the endpoint blindly. Establish trust explicitly with `--recipient <file>`, an
out-of-band copy of the node's public key, or with `node_recipient_file`. This comes up in
minimal and CI environments with no `$HOME` or `$XDG_CONFIG_HOME`.

The provider's identities are configured by `[keys].identities` (see
[Provider-side key management](#provider-side-key-management)). The primary is
auto-generated on first use if missing, or explicitly with `keys generate`.

### Install channels: S3 vs inbox

A node consumes datasets through one of two channels. Pick the one your node uses:

- **S3** — `upload` PUTs the package into an S3 bucket the node monitors. The bucket is
  the source of truth and the node reconciles it.
- **Inbox** — `deploy` copies the package, or a staging directory, into the node's local
  inbox directory. Used for co-located and no-S3 nodes, and as the drop point for the
  offline workflow.

> A hand-assembled inbox staging directory must be named exactly its `datasetId`. The
> inbox derives the dataset id from the directory name, not from the manifest, mirroring
> how the S3 channel uses the object key. `build` and `deploy` name the directory for you,
> so only a hand-built drop can get this wrong.
>
> How it fails depends on the name:
>
> - A name that is not a valid dataset id is ignored, with a log line naming the rename
>   that fixes it: `WARN ignored: an inbox staging dir must be named EXACTLY its datasetId`.
> - A name that is a valid dataset id but not the manifest's is not caught by that
>   warning. The id comes from the directory, so the drop proceeds and fails later as a
>   generic `invalid-manifest`. On a hand-built drop, check the directory name against
>   `manifest.json`'s `datasetId` first.

The lifecycle commands (`publish`, `unpublish`, `delete`) and `status` route themselves to
the correct channel. When the node's management plane (`GET /datasets/{id}/state`) is
reachable they read the authoritative channel there; otherwise they fall back to the
profile shape, with `--s3` and `--local` as an explicit override.

---

## Configuration

### Tool config file

The tool reads a TOML config file from `--config <PATH>`; a missing file at that path is
tolerated as empty. With no `--config` it falls back to `<config_dir>/tool.toml` and reads
that if it exists, otherwise the run is configured from the `GDI_TOOL__` env overlay
alone. The file is merged at the lowest precedence, so the env overlay always wins over
it. A stale `tool.toml` in your config dir is still picked up on a bare invocation, so
pass `--config` (or set `GDI_CONFIG_DIR`) when you need to be sure which file is in play.

> A complete annotated reference lives at
> [`tool.example.toml`](../tool.example.toml) in the repo root.

Every value can be overridden by a `GDI_TOOL__SECTION__KEY` environment variable, with a
double-underscore separator; root-level keys use the single form `GDI_TOOL__KEY`. Where a
command has an equivalent flag, the flag wins.

The tool config has two sections plus root-level keys: the provider-wide `country_code`
and `default_profile` at the top of the file, the provider's own crypt4gh identities under
`[keys]`, and one or more named target-node deployments under `[profiles.<name>]`.

### Sections and fields

The complete annotated schema — every section and key, with types and defaults — lives in
[`tool.example.toml`](../tool.example.toml). This section covers only the behaviour a bare
field list does not make obvious.

**Root-level keys.** There is no `[tool]` section; these keys appear before any `[section]`
header, and the loader rejects unknown keys. `country_code` is baked into every dataset ID
at the lowest precedence, overridden by `GDI_TOOL__COUNTRY_CODE` and then by `--cc`.
`default_profile` names the profile used when `--profile` is omitted. With exactly one
profile configured that one is used; with several, `--profile` or this key is required.

**`[keys]`** — the provider's own crypt4gh identities, tried in order when decrypting the
provider's own packages (`inspect`, `unpack`, `validate`, `check`). The first is primary:
its recipient is derived and added as the second encryption recipient on every package, so
there is no separate `recipient` field and you can always decrypt what you ship. Rotate by
prepending a new identity and keeping the retired ones after it. Paths are absolute, or
resolve relative to the config dir (the parent of the `--config` file, else the gdi config
dir). The primary is auto-generated `0o600` if missing; a configured-but-missing retired
entry is an error.

**`[profiles.<name>]`** — one complete target-node deployment each: public and management
URLs, inbox, node recipient, S3 bucket, catalog allow-list, all switched together by
`--profile`. Which command reads which key:

| Key | Read by |
|-----|---------|
| `service_url` | `check`, `doctor`, `catalogs`, `status --all`, recipient fetch. The node's public base URL, serving `/fairdp` and `/.well-known/c4gh-recipient`. For a co-located no-S3 node, its loopback address. |
| `management_url` | `deploy`, `upload`, `delete`, `publish`, `unpublish`, `status`, `check`. The node's management-plane listener (`[service].management_addr`), serving the authoritative `GET /datasets/{id}/state` oracle, and the only live-state source for an inbox-only node. Optional: unset, it falls back to `service_url`, then degrades — writes still proceed via the ingest-time re-validation backstop, and `status` falls back to the S3 sidecar or reports `unavailable`. `--management-url` overrides it on `deploy`, `upload`, `delete`, `publish`, `unpublish` and `status`, so a profile-less run can still reach the oracle. `delete` does not degrade; it refuses (see [`delete`](#delete)). |
| `inbox` | `deploy`, `publish`, `unpublish`, `delete` on the inbox channel. The local inbox of a co-located node; `deploy --inbox` overrides it. |
| `node_recipient_url` / `node_recipient_file` | `pack`, `package`, `rekey`, `doctor`. The node's crypt4gh recipient. With a `service_url` or `node_recipient_url` set it is fetched over HTTP (URL default `{service_url}/.well-known/c4gh-recipient`), and a configured `node_recipient_file` is the pin the fetched key must match. A failed fetch falls back to that pin with a warning; a missing or mismatching pin fails closed. Re-pin with `keys pin-recipient --force` after verifying a rotation out of band. With no URL configured, `node_recipient_file` is the recipient itself. `--recipient <file>` overrides both. |
| `catalogs` | `build`, `validate`, `catalogs`, `doctor`. A table, not a list: `[profiles.<name>.catalogs]` maps each catalog name to its display title (`gdi-aggregated = "Genome of Europe Aggregated Data"`). The keys are the offline allow-list, enforcing `metadata.catalog` membership when non-empty and structural-only when empty. The titles are cosmetic; the node re-validates at ingest. |
| `s3` | `upload`, `download`, `list`, and the S3-channel lifecycle. Omit the block for an inbox-only node. |
| `org` | The wizard's Author stage and `profiles`. The institute abbreviation minted into every dataset id built under this profile: the `<ORG>` of `GDI-<CC>-<ORG>-…`, 1–16 uppercase ASCII letters. A fact about the provider, like `country_code`. `wizard setup` asks for it once, and with it set the wizard never asks per dataset. `build` still reads `metadata.org` from `package.yaml`. |
| `keyless` | `pack`, `package`, `deploy`, `doctor`, and the wizard. Declares that the target node runs with no crypt4gh identity, so nothing is encrypted to it and `deploy` ships the `build` staging directory itself. With it set, `doctor` stops asking for a node recipient and the wizard skips `pack`. Type: bool. Default `false`. |
| `header_policy` | `build`, `package`, and the wizard's Build stage. What the packaged `headers/{vcfId}.vcf` members contain when no `--header-policy` or `--no-headers` flag is given: `minimal` (the built-in default), `with-identifiers`, or `none`. A flag always wins over the profile. `verbatim` is not accepted in a profile; it stays a per-invocation flag. The node drops these members at ingest (see [package format](package-format.md)). |

**`[profiles.<name>.s3]`** — the profile's S3 bucket, endpoint-agnostic across Ceph+Rook,
Garage and minio. Set both credentials or neither. Neither means anonymous unsigned read,
which works for a public bucket but not for writing or listing a private one; setting
exactly one is an error. `upload` and the lifecycle commands need a read/write token, and
a read-only token fails writes with an access-denied error.

**`prefix`** confines the profile to one key prefix inside that bucket, and must equal the
`prefix` on the node's `[[s3.buckets]]` entry for the same channel (see
[deployment.md](deployment.md#sharing-a-bucket-with-something-that-is-not-a-data-source)).
Omit it for the whole bucket. Set on one side only, it is a desync in which every signal
you get is a success: `upload` writes where the node never lists, and `list` / `status`
report an empty bucket the node is serving from.

> Each direction is reported on the side that can see it, so check both logs before
> assuming the upload was the problem.
>
> - **Node prefixed, writer not.** The channel's prefix lists empty, and the node cannot
>   tell that from an empty bucket. `list` can: an empty listing makes it look once at the
>   whole bucket and name the prefix your objects sit under.
> - **Writer prefixed, node not**, or the writer one level deeper. The node's listing
>   returns the key, recognises a valid dataset id below the keyspace it polls, and says
>   so, naming the key, the id, and what it is polling.
>
> Neither is a refusal, and neither stops the channel serving: a bucket shared with a
> second node on a different prefix is a supported topology. Each is one line per channel
> per process lifetime.

The tool applies the same validation the node boots on: slash-separated segments of
letters, digits, `-`, `_` or `.`, with at most one trailing `/`. Anything else, such as a
leading `/`, a `//`, a `.` or `..` segment, or a character S3 advises against, is refused
with an error naming the value rather than rewritten into a prefix you did not write.

### Environment variables

| Variable | Effect |
|----------|--------|
| `GDI_TOOL__COUNTRY_CODE` | Overrides the root-level `country_code`. |
| `GDI_TOOL__DEFAULT_PROFILE` | Overrides the root-level `default_profile`. |
| `GDI_TOOL__PROFILES__<NAME>__…` | Overrides `[profiles.<name>]` keys, e.g. `GDI_TOOL__PROFILES__DEV__SERVICE_URL`. Profile names must use `_`, not `-`: the overlay splits on `__` and cannot spell a hyphen, so `[profiles.ee-prod]` is unreachable by env and the injected value lands in a separate `ee_prod` phantom profile. The tool warns when it detects such a twin. |
| `GDI_TOOL__KEYS__IDENTITIES` | Overrides `[keys].identities`. |
| `GDI_CONFIG_DIR` | Overrides the gdi config directory (where `keys/` lives, and where the default `tool.toml` is looked up when `--config` is omitted). |
| `XDG_CONFIG_HOME` | If `GDI_CONFIG_DIR` is unset, the config dir is `$XDG_CONFIG_HOME/gdi`. |
| `HOME` | Final fallback: `$HOME/.config/gdi`. |

S3 credentials use the config keys `access_key_id` and `secret_access_key`, or their
`GDI_TOOL__PROFILES__<NAME>__S3__…` env overrides. The tool does not read the standard
`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` variables.

### Global flags

These apply to every subcommand:

| Flag | Meaning |
|------|---------|
| `--config <PATH>` | Path to the tool config TOML (overrides the default `<config_dir>/tool.toml` lookup). |
| `--profile <NAME>` | The active profile (`[profiles.<name>]`) to act on. Omitted, the root-level `default_profile` is used, or the sole configured profile. An unknown name errors and lists the available profiles. |
| `-v`, `--verbose` | Add diagnostic notes to stderr. The default level prints per-step progress. `-vv` is accepted but adds nothing; there is no level above `-v`. The stdout result and `--format json` are unchanged. |
| `-q`, `--quiet` | Suppress per-step progress. Warnings, errors and the result still print. Mutually exclusive with `-v`, and stderr-only, so the stdout result is unchanged. |

---

## `package.yaml` authoring

`package.yaml` is the human-authored input. It has four sections:

- `metadata` — FDP-public, per-dataset metadata.
- `files` — the content and provenance inventory. The `VCF` group drives the parquet
  conversion. Non-public: the node strips it at ingest.
- `internal` — non-public bookkeeping, opaque to the node.
- `config` — processing options.

Scaffold one with [`init`](#init), which writes a fully-commented template.
`build`/`validate` reject any leftover `REPLACE:` marker, so a fresh template cannot be
packaged until filled in.

Field names on the wire are camelCase (`accessRights`, `hasEmail`). `title` and
`description` may be a plain string or a language map (`{en: "...", et: "..."}`).

### The `metadata` section

```yaml
metadata:
  # --- Core identity (REQUIRED) ---
  prefix: "GDI"                 # GOE or GDI; combines with CC + org + timestamp into the dataset ID
  org: "EXAMPLE"                   # institute abbreviation (1-16 uppercase letters)
  catalog: "gdi-aggregated"     # must match a catalog the node accepts
  title: "Genome of Europe Estonia aggregated allele frequencies"
  description: "Aggregated allele frequencies for the GoE Estonia cohort."

  # --- Access, rights & legal (REQUIRED) ---
  accessRights: "http://publications.europa.eu/resource/authority/access-right/PUBLIC"
  applicableLegislation:        # >= 1; init pre-fills the EHDS ELI (removable — build warns)
    - "http://data.europa.eu/eli/reg/2025/327/oj"
    - "http://data.europa.eu/eli/reg/2016/679/oj"   # GDPR, when personal data is disclosed
  license: "http://publications.europa.eu/resource/authority/licence/CC_BY_4_0"  # reuse licence IRI

  # --- Agents (REQUIRED, >= 1) ---
  creator:                      # publisher/hdab live in the node's [fairdp] config, not here
    - name: "Genome of Europe - EE node"

  # --- Health-specific (REQUIRED, >= 1) ---
  healthCategory:
    - "http://data.gdi.eu/core/p2/HealthCategoryHumanGenomic"

  # --- Recommended (non-fatal warning if absent) ---
  keywords:
    - allele-frequency
    - genomics
  numberOfUniqueIndividuals: 1234   # distinct sequenced subjects across the whole dataset

  # --- Optional ---
  conformsTo:                    # closed set: ExternallyGoverned | 1MGCompliant | 1MGCohort
    - "http://data.gdi.eu/core/p2/1MGCompliant"
  type: "https://publications.europa.eu/resource/authority/dataset-type/SYNTHETIC_DATA"  # synthetic only
  legalBasis:
    - "https://w3id.org/dpv#Consent"
  isReferencedBy:
    - "https://doi.org/10.1234/example"
  otherIdentifier:
    - notation: "DOI-12345"      # required within the identifier
      schemaAgency: "DataCite"   # recommended
      name: "Example identifier" # optional
  contactPoint:                  # dataset-level contact (fn + hasEmail required when present)
    fn: "Data team"
    hasEmail: "mailto:data@example.org"
    hasURL: "https://example.org"
```

Cardinality follows the grouping comments above: Core identity, Access/rights, Agents and
Health-specific are required, then recommended, then optional. A few shapes the comments
do not spell out. `title` and `description` accept a plain string or a language map.
`accessRights` is an authority IRI (`PUBLIC`, `RESTRICTED` or `NON_PUBLIC`). Each
`otherIdentifier` entry is `{notation, schemaAgency?, name?}`. `catalog` is enforced
against the node's set only when a `catalogs` allow-list is configured.

Two fields have contents the tool has an opinion about:

- **`applicableLegislation`** (>= 1) is a list of plain IRIs. An
  [ELI](http://data.europa.eu/eli/ontology) is the expected shape, but nothing enforces
  ELI syntax, so national gazette URLs are accepted as they come. `init` pre-fills the
  EHDS ELI and the wizard pre-ticks it, because health datasets are expected to cite it.
  You may remove it, and `build`/`validate` then emit `warning: EHDS ELI absent — health
  datasets are expected to cite it`. A plain build still succeeds; `--strict` fails on that
  warning like any other. The node logs the same line at `warn` when it ingests such a
  package. Add the GDPR ELI when the dataset discloses personal data, plus any national
  act that applies.
- **`conformsTo`** (optional) is a closed set: the three GDI standards
  `ExternallyGoverned` ("Externally governed"), `1MGCompliant` ("1+MG compliant") and
  `1MGCohort` ("1+MG cohort") under `http://data.gdi.eu/core/p2/`. Any other value is
  rejected by `build`, `validate` and node ingest with a message naming the three. There
  is no default: a value here is a claim about this dataset.

### The `files` section

The dataset's content + provenance inventory. The **first `VCF` group is
required** and drives parquet conversion. Paths are relative (to the YAML's
directory) or absolute. `sha256`/`size` are optional: if provided they are
verified against the file (error on mismatch); if omitted they are computed.

```yaml
files:
  - category: "VCF"             # reserved value (case-insensitive); drives parquet conversion
    reference: "GRCh38"         # REQUIRED on the VCF group — sets the dataset assembly
    preciseReference: "GRCh38.p14"   # optional — patch-level provenance (not used for matching)
    files:
      - "relative/to/yaml/file1.vcf.gz"
      - "/absolute/path/file2.vcf.gz"
  - category: "BAM"            # free string; integrated-mode provenance only (does not travel in the package)
    reference: "GRCh38"
    files:
      - path: "file2.bam"
        sha256: "181f1574af8632a70329f015ea121a0a5b6c7d8e9f0a1b2c3d4e5f6071829304"  # verified if provided
        size: 1234567                                                              # verified if provided
```

A dataset is single-assembly: every VCF group's `reference` must agree. Only the VCF
group's converted parquet, and the optional headers, travel in the package. Non-VCF
entries are inventory for an integrating system (see the package format's `files` and
`internal` sections) and a standalone node ignores them.

> Listing several VCFs that cover the same positions has a serving cost, so prefer one
> VCF per position range. Each source VCF converts to its own `…{vcfId}.parquet`, so VCFs
> split by position (chr1 in one, chr2 in another, or one per block) produce one file per
> block and cost nothing extra. VCFs split by population put several files carrying
> different populations over the same loci into one block. The tool accepts and packages
> that correctly, but the node cannot stream such a block: it reads, buffers and sorts the
> whole block's matching rows before it can answer.
>
> Peak node memory then scales with the block, not with the client's page size. Over a
> block of 1.6 M rows, one file per block costs around 17 MiB where eight files cost around
> 462 MiB, for the same query and the same answer. `boolean` and `count` queries pay it as
> well as `record`, because the buffer exists to order the rows before anything decides
> what to keep.
>
> The package is valid and the node serves it correctly. A node with a
> `[service].max_query_bytes` ceiling refuses the query with a `400` rather than growing
> without limit. If you can emit one VCF per position range instead of one per population,
> merging a locus's populations into a single record, the node's read path stays
> streaming. If you cannot, tell the node's operator so they can size for it (see
> [operating.md](operating.md#22-one-datasets-queries-cost-far-more-than-its-neighbours)).
>
> `build` reports when a package lands in this shape, naming how many position blocks hold
> files from more than one source VCF and the worst one. It is a note, never a refusal.
> On the serving side the same shape increments `gdi_beacon_merged_blocks_total`.

### The `internal` section

```yaml
internal:
  internalId: "EGV012346"                            # optional org-internal handle
  pastVersion: "GDI-EE-EXAMPLE-20240601120000004"       # optional; the single dataset this one supersedes
```

Both fields are optional and opaque to the node: the tool carries them, the node strips
them at ingest. `pastVersion`, if set, must be a valid dataset ID. The section may be
omitted entirely.

`internal` is author-supplied bookkeeping, carried through untouched. It holds no
conversion provenance. What `build` discarded is recorded per source VCF under
[`files`](#conversion-provenance-in-the-manifest), where the tool generates it.

### The `config` section

```yaml
config:
  mode: aggregated              # aggregated = allele frequencies (the only mode implemented)
  blockRange: 10000000          # position-based block range in bases (0 = single file per chromosome)
  afSource: "The Genome of Europe"                 # allele-frequency provenance source (free text)
  afSourceReference: "https://genomeofeurope.eu/"  # provenance source reference (URL)
  minAlleleCount: 0             # build-time AC floor (0 = off); rows below it never reach parquet
  # hideLowerCounts: 5          # sensitive-tier floor (recorded only; nothing is filtered here)
```

`mode` is required, and `aggregated` is the only accepted value; `individual` is reserved
and rejected. The rest are optional. `blockRange` defaults to `10000000` and
`minAlleleCount` to `0` when omitted. `afSource`, `afSourceReference` and
`hideLowerCounts` have no default, and the values above are examples; the `afSource` pair
shown is the standard Genome of Europe one, which `init` and the wizard offer. A package
that omits `afSource`/`afSourceReference` is served with the node's own `[beacon].name`
and `[service].base_url` as the beacon `source` and `sourceReference`. `minAlleleCount` is
a build-time AC floor, minimising data at source; `hideLowerCounts` is only recorded in
the manifest, not applied here.

The generated `manifest.json` mirrors these four sections, with `prefix`/`org`
replaced by the computed `datasetId`, all `sha256`/`size` values computed,
`config` gaining `assembly` (promoted from the VCF group's `reference`),
`manifestVersion` and `generatedBy`, and `metadata` gaining the computed
`numberOfRecords` and `populations`.

---

## Data requirements and constraints

`build` enforces a fixed set of structural rules on the source VCFs. Most are checked up
front: the assembly is validated before any conversion, and the AF and label rules are read
from the VCF headers before a single row is written, so `build` fails fast rather than
partway through a long conversion. `preview` and `lint` also report the population-count
headroom, so a too-large dataset surfaces before `build`.

| Constraint | Rule | When it fails |
|------------|------|---------------|
| **Reference assembly** | The VCF group's `reference` must be exactly `GRCh37` or `GRCh38`. Every contig must resolve to a RefSeq accession for that assembly; an unknown contig, or one whose accession belongs to the *other* assembly, is rejected. The non-primary contigs of the standard reference sets — decoys (`hs37d5`, `hs38d1`, the EBV decoy as `NC_007605` or `chrEBV`), unplaced/unlocalized/alt/random/fix scaffolds, `HLA-*` — are skipped and counted as dropped records, never rejected. | `build` / `validate` (assembly value up front; contig accessions during conversion) |
| **Allele-frequency field** | At least one `AF` INFO field (`Number=A`, per-ALT) must be present — an aggregated allele-frequency dataset with no AF has nothing to serve. | `build` (VCF header preflight) |
| **Populations — count** | At most **512** distinct populations per dataset. | `build` (hard cap); `preview` / `lint` report the count vs the cap |
| **Populations — label** | Each population label is at most **16** characters. Labels are derived from the INFO field name, e.g. `AF_FI`, `AF_FI_M` — see [INFO field naming](#info-field-naming-the-population-grammar). A field that does not match the grammar is dropped with a warning. | `build` (VCF header preflight) |
| **AF-less populations** | A population that carries `AC`/`AN` but no `AF` field emits no rows and is omitted (it does not count toward the 512 cap). If a population you expected is missing from the output, check that it has an `AF_*` field. | (not an error — reported as a warning) |
| **Mode** | `config.mode` must be `aggregated`. `individual`, for individual-level genotypes, is reserved and rejected. | `build` / `validate` |
| **VCF format** | Parsed by [`noodles`](https://github.com/zaeleus/noodles); a well-formed `##fileformat=VCFv4.x` header is expected. There is no explicit version gate — a malformed or unsupported header surfaces as a parse error at `build`. | `build` |

`numberOfRecords` in `manifest.json` is the number of distinct
`(chromosome, POS, REF, ALT)` loci across all VCFs in the first VCF group, deduplicated.
It is neither the sum of per-file row counts nor the population-stratified row count, so a
dataset split into per-population files that share loci reports the shared locus count.

The node applies further structural caps at ingest: per-file and total decompressed size,
REF length, coordinate ordering, and allele alphabet. Run `validate` on the built package,
and `check` against a live node, to confirm it passes those gates before you ship it.

### What `build` keeps from the VCF

`build` does **not** store your VCF. It projects each record into a fixed
eleven-column Parquet schema and keeps nothing else:

```
POS, REF, ALT, VT, POPULATION, AF, AC, AC_HOM, AC_HET, AC_HEMI, AN
```

Values that survive are stored and served verbatim; `AF` is never rounded or re-derived
from `AC`/`AN`. Everything outside that schema is discarded:

- **`ID`, `QUAL`, `FILTER`, `FORMAT`, and all per-sample genotype columns** are never
  read. There is no `FILTER=PASS` gate: a `q10` record is converted like a `PASS` one.
  `build` and `preview` report how many records carried a non-`PASS` filter. Pre-filter
  the VCF if that is not what you want.
- **`CHROM` is not a column.** It is normalized (`chr7` → `7`, `MT` → `M`, RefSeq
  accessions resolved) and encoded in the partition file name.
- **`POS` is stored 0-based**, as Beacon v2 and VRS `SequenceLocation` require. No
  information is lost.
- **Every INFO key outside the grammar below** is dropped.
- **Unsupported ALT alleles are dropped even from records that survive.** A record
  `A → G,*` publishes its `G` and discards the `*`. `build` counts these as
  `discarded.alleles` and does not warn, because spanning deletions make the count
  non-zero on most real population VCFs.

### INFO field naming (the population grammar)

A population is derived from the INFO field's name, so the name is a contract. An ID
parses only when its first `_`-separated token is `AF`, `AC` or `AN`, followed in any
order by at most one of each of:

| Token | Meaning | Notes |
|-------|---------|-------|
| `Hom` / `Het` / `Hemi` | zygosity qualifier | case-sensitive; **valid only on `AC`** |
| two uppercase letters | country code | e.g. `FI`, `EE` — length and case are checked, the value is not |
| `M` / `F` | sex | |

#### What the genotype sub-counts count

`AC_Hom`, `AC_Het` and `AC_Hemi` count alleles, not individuals, and they partition `AC`.
A homozygous-alternate individual contributes 2 to both `AC` and `AC_Hom`; a heterozygote
contributes 1 to `AC` and `AC_Het`; a hemizygote contributes 1 to `AC` and `AC_Hemi`. Every
alternate allele falls in exactly one genotype class, so:

- When all three are reported, `AC_Hom + AC_Het + AC_Hemi == AC` exactly.
- When only some are reported, the reported ones sum to at most `AC`. An absent sub-count
  means not reported, not zero.
- `AC_Hom` is even at a diploid site, and `AC_Hemi` is exactly the number of hemizygous
  individuals.

This is the `bcftools +fill-tags` convention (`##INFO` description: *"Total number of
alternate alleles (type Hom) in called genotypes"*). `build` rejects an incoherent set, and
the node re-checks it independently at ingest, since a hand-assembled package never passed
through `build`.

Because the floor counts alleles, its guarantee in individuals differs by genotype class:
a floor of `f` protects at least `⌈f/2⌉` homozygotes but `f` heterozygotes and `f`
hemizygotes. Size the floor for the homozygous case.

The population label is `country_sex`, or whichever of the two is present, or `Total` when
neither is. `AF` fields must be declared `Number=A`. `AN` may be `Number=1` or `Number=A`,
but that is one choice for the whole file rather than per field: every AN-family field must
agree, and mixing them fails the build with *"AN-family Number is inconsistent: `<ID>`
disagrees with earlier AN fields"*. The bare `AN` is a reserved VCF key whose declared
`Number` the reader pins to `1`, so a file that wants the `Number=A` form uses AN-family
names (`AN_Total`, `AN_EE`, …) throughout rather than redeclaring `AN`.

`AF` is served verbatim, never recomputed from `AC`/`AN`, and the k-anonymity floor reads
carrier counts as `round(AF × AN)` when the `AC` column is absent. `build`, and the node
independently at ingest, therefore require `AF` to be the population's own `AC / AN`:
`round(AF × AN) == AC`, within a tolerance that scales with `AN`. The tolerance is one
allele up to 1.67 M alleles, then `ceil(AN × 6e-7)`: 2 at 2 M, 3 at 4 M, 6 at 10 M. That is
the slack a six-significant-digit `AF`, the precision common VCF writers print, can lose to
decimal and `f32` rounding, so an `AF` derived from this cohort's `AC / AN` passes at any
cohort size. A frequency over a different denominator, such as a `popmax`, `faf` or imputed
value, diverges by orders of magnitude more and is rejected. Carry such a value in its own
field, not `AF`.

A reconstruction that rounds down to zero is read as one carrier, not none. `AF > 0` states
the variant is present, so a derived `0` means `AF × AN` fell below the resolution the
published numbers carry (`AF = 1.0e-4` with `AN = 2000` gives `round(0.2) = 0`). Such a row
is suppressed by a non-zero floor rather than served. An explicitly reported `AC = 0` is a
real empty group and is unaffected. If rows disappear under the floor, emit a
full-precision `AF`: one rounded below `1 / AN` cannot describe a group that exists.

| Field ID | Parses? | Population |
|----------|---------|------------|
| `AF` | yes | `Total` |
| `AF_FI` | yes | `FI` |
| `AF_FI_M` | yes | `FI_M` |
| `AC_Hom_EE` (≡ `AC_EE_Hom`) | yes | `EE` |
| `EUR_AF`, `EAS_AF` | **no** | — (1000 Genomes suffix convention: the metric is not first) |
| `AF_nfe`, `AF_afr` | **no** | — (gnomAD lowercase labels) |
| `AF_EUR`, `AF_FIN` | **no** | — (a three-letter code; a country code is exactly two letters) |
| `AC_FI_raw` | **no** | — (`raw` is a lowercase token; every population token must be uppercase) |
| `AF_Hom` | **no** | — (a qualifier on `AF`) |
| `DP`, `MQ` | no | — (not an allele-frequency field, no warning) |

> Both public conventions fail this grammar: 1000 Genomes puts the metric last (`EUR_AF`)
> and gnomAD uses lowercase population labels (`AF_nfe`). Their per-population columns are
> dropped and the dataset ends up with a single `Total` population. `build` and `preview`
> warn with `ignored non-conforming INFO fields: …`, naming every dropped field and the
> rule each one broke, grouped by rule, and echo the populations actually emitted. Run
> `preview` on one VCF before you commit to a build, and check that the emitted population
> list is the one you expect.

### What the `minAlleleCount` floor removes

A non-zero `config.minAlleleCount` withholds any population row that exposes a non-empty
group smaller than the floor on either tail:

- **The low tail**, a rare alt-carrier group. The count is the exact `AC` when present,
  otherwise the client-derivable `round(AF × AN)`, so omitting the `AC` field does not
  exempt a row whose count a reader could reconstruct anyway.
- **The complement tail**, a rare reference-carrier group with `AN − AC` below the floor,
  which a near-fixed variant has even when its own `AC` is far above the floor.

An empty group (`AC == 0`) is never re-identifying and always survives. A row with `AF` but
neither `AC` nor `AN` carries no derivable count and is kept at build time. Dropping it
would delete every row of an AF-only dataset, and the serve-time floor withholds it on
every response anyway.

It also withholds that row's siblings. If one population of a variant is suppressed, only
the `Total` row is kept, because a partial set would let `Total − Σ(survivors)` recover the
suppressed cell. A population far above the floor is therefore dropped when a sibling falls
below it.

This is the build-time floor: the rows are dropped from the package and never reach a node,
so changing it later means rebuilding. It is a different knob from the node's serve-time
`[beacon].min_allele_count`, which applies to every response and can be retuned by
restarting. The two compose as `max(build-time, serve-time)`, so leaving this at `0` is
fine provided the node sets its own.

Both apply the same row rule, with one difference: an uncountable row (`AF` present, no
`AC`, no `AN`) is kept at build time and withheld at serve time. Build-time drops are
permanent while a serve-time withhold is reversible, so the irreversible side takes the
cautious option.

Both losses are reported separately. `preview` prints one line:

```
k-anonymity suppression: 1 row(s) below the floor, 1 row(s) removed by collapsing 1 variant(s) to Total
```

`build` reports the same two counts as `note:` diagnostics, one for the floor and one for
the coherence collapse.

Mind the unit: the floor counts alleles, not individuals. A homozygous carrier contributes
2 to `AC`, so use about `2*k` for `k` distinct people (`10` for `k = 5`; `minAlleleCount: 5`
is roughly three-individual anonymity). Mind the scope too: the floor bounds singleton and
small-cell re-identification only. At no value does it prevent membership inference
("is my target in this cohort?"), which operates on the common variants that always clear
the floor. A membership-sensitive cohort needs the authenticated tier or differential
privacy, not a bigger floor.

### Notes vs warnings, and `--strict`

`build` and `preview` emit two kinds of non-fatal diagnostic, and the distinction decides
whether a build can fail on it.

A **`note:`** is an expected consequence of configuration you declared. It never fails a
build:

| Note | Why it is not a mistake |
|------|-------------------------|
| the `min_allele_count` floor suppressed N rows | You set the floor. |
| k-anonymity coherence collapsed N variants | The floor's differencing defence. |
| dropped N of M input records | An SV-heavy or decoy-bearing VCF legitimately loses records. |
| N of M emitted variant(s) have Total AF=0 | Your export states it with `AC=0` and `AF=0`: the cohort carries no copy of that allele, typically a site that became monomorphic under sample QC. The row is stored and served like any other, a variant present with frequency 0. If that is not what you mean to publish, remove monomorphic sites first with `bcftools view -c 1`. |
| numberOfUniqueIndividuals is absent; the VCF's NS peaks at N | The recommended field is missing, which is the warning beside it. This is the value your own `NS` suggests, when every sample is a distinct individual. |

A **`warning:`** is something you probably did not intend:

| Warning | Likely cause |
|---------|--------------|
| `ignored non-conforming INFO fields: …` | Your population fields do not match the grammar. |
| `population X has AC/AN but no AF` | A pipeline bug: X emits no rows. |
| `input appears to be a gVCF` | Wrong input type. Convert to a sites or AF VCF. |
| `recommended field "…" is absent` | Incomplete metadata. |
| `N allele(s) are not left-aligned` | The VCF is not normalized: REF and ALT still share a leading base, so an exact-match Beacon query misses those alleles. Run `bcftools norm -m -any -f <reference.fa>` before building. |
| `EHDS ELI absent — health datasets are expected to cite it` | `applicableLegislation` does not cite `http://data.europa.eu/eli/reg/2025/327/oj`. Removing it is a decision you are allowed to make, since the GDI shape treats the ELI as a default rather than a fixed value, but it is still a warning, so `--strict` fails on it. |
| `N of M input records have a FILTER other than PASS` | Your export carried calls your own pipeline rejected, such as VQSR-failed or `AC0`. The converter does not gate on `FILTER`, so their allele frequencies would be published as authoritative. |

`build --strict` fails when any warning was emitted. It prints every diagnostic first, then
reports the count, so you fix them in one pass rather than one build at a time.

Notes never count: the floor's tally fires on any dataset with a non-zero
`minAlleleCount`, so gating on notes would be incompatible with the privacy control. One
rule decides which a diagnostic is: a note reports a consequence of something your
`package.yaml` declares, a warning reports something nothing in the package asked for. No
field declares "publish non-`PASS` calls", which is why that tally is a warning.

There is no way to accept an individual warning. If your export legitimately contains
non-`PASS` records, either pre-filter the VCF with `bcftools view -f PASS` or run without
`--strict`.

```console
$ gdi-dataset-tool build package.yaml --cc EE --strict
warning: ignored non-conforming INFO fields: EAS_AF, EUR_AF, AFR_AF — 3 because of the metric is not the first token (the grammar is `AF_<population>`, not `<population>_AF`) (e.g. EAS_AF, EUR_AF, AFR_AF)
warning: 1 of 2 input records have a FILTER other than PASS and were converted anyway — …
error: --strict: 2 warning(s); fix them or drop --strict (note: lines are informational …)
```

A `--strict` failure exits `5`, distinct from the general user-error exit `1`, so a script
can tell "your data has problems" from "the tool broke". `3` is a transient remote-service
failure, `4` an auth failure, and `2` is clap's own argument-parse code.

`build --format json` carries the machine-readable form: the population set, the warning
and note counts, and every diagnostic with the source VCF that produced it. The full
per-VCF provenance lives in the `manifest.json` at the emitted `path`.

Independently of `--strict`, a build whose VCF group emits **zero rows** is always an
error: an empty dataset is never intentional, and it is what a mis-named INFO header or a
wholly non-primary-contig VCF produces.

### Preflighting a whole package

`preview` covers one VCF, and `validate` / `lint` need an already-built staging dir. To
check a multi-VCF group before committing to a build:

```bash
gdi-dataset-tool build package.yaml --cc EE --dry-run
```

Every VCF is converted and every gate runs; the staging dir is then discarded. A build
that would fail still fails.

To see what a floor would cost before choosing it:

```bash
gdi-dataset-tool preview chr1.vcf.gz --min-allele-count 5 --floor-impact
# floor impact (minAlleleCount 5): 2 of 3 row(s) withheld (66.7%), 1 kept
# populations erased entirely by the floor (2): EE, FI
```

`EE` can be erased with an `AC` far above the floor, because the coherence collapse removes
a withheld row's siblings. Under `--format json` the report gains a `floorImpact` object
with the same fields.

The repository's sample (`crates/test-util/tests/fixtures/sample/gdi-sample.GRCh38.vcf.gz`:
1 637 variants, twelve populations, a rare-heavy spectrum) at a floor of 10 alleles:

```bash
gdi-dataset-tool preview crates/test-util/tests/fixtures/sample/gdi-sample.GRCh38.vcf.gz \
    --min-allele-count 10 --floor-impact
# distinct records: 413
# rows that would be emitted: 2386
# k-anonymity suppression: 6411 row(s) below the floor, 10687 row(s) removed by collapsing 1447 variant(s) to Total
# floor impact (minAlleleCount 10): 17098 of 19484 row(s) withheld (87.8%), 2386 kept
# populations erased entirely by the floor (0): (none)
```

Most of the loss is the collapse rather than the floor itself. On a cohort where most
variants are rare, almost every variant has some stratum under the floor, and its siblings
go with it. A variant whose `Total` is itself under the floor keeps no row at all, which is
why 1 637 variants become 413 distinct records. No population is erased entirely, because
each keeps its rows on the common variants.

### Reproducible builds

The parquet bytes are deterministic and `pack` normalizes every tar member's mtime, owner,
mode, and order. The one remaining source of nondeterminism is the `datasetId`, derived
from the wall clock. Pin it and the `manifest.json` becomes a pure function of the inputs:

```bash
gdi-dataset-tool build package.yaml --cc EE --build-epoch 1700000000000
```

The encrypted `.tar.c4gh` can never be byte-reproduced: crypt4gh draws a fresh random
session key and a fresh nonce per segment. Compare digests at the parquet and manifest
layer instead. The manifest already records each file's SHA-256.

### Comparing two builds

`internal.pastVersion` names a predecessor; `diff` says what actually changed:

```bash
gdi-dataset-tool diff old-staging/ new.tar.c4gh
# GDI-EE-EXAMPLE-… -> GDI-EE-EXAMPLE-…
#   ! populations removed: EE, FI
#   ! INFO fields newly rejected by the grammar: EE_AF, FI_AF
```

The failure it exists to catch: a pipeline change renames the population INFO fields, the
grammar rejects them, both builds succeed, and a whole stratum silently stops being
published. `lint` flags the same dataset in isolation as `Total`-only.

### Conversion provenance in the manifest

`build` records what it discarded from each source VCF, on that file's entry in the
manifest's `files` section:

```jsonc
"files": [{
  "category": "VCF",
  "reference": "GRCh38",
  "files": [{
    "path": "chr1.vcf.gz",
    "sha256": "9f2b…",
    "size": 4823910,
    "conversion": {
      "input": {
        "records": 1200000,
        "nonPassRecords": 900,          // kept: FILTER is not a gate
        "gvcfReferenceBlocks": 0,       // >0 means the input is a gVCF
        "populationsRecognized": ["EE", "FI", "Total"]
      },
      "discarded": {
        "recordsUnsupportedContig": 12,
        "recordsNoSupportedAlt": 340,
        "recordsAllRowsWithheld": 438,  // the k-anon floor withheld every row
        "recordsNoAf": 115,             // the input carried no AF to emit
        "alleles": 51,                  // from records that survived
        "ignoredInfoFields": ["EUR_AF", "EAS_AF"],
        "populationsWithoutAf": ["NO"]
      },
      "suppressed": {
        "rowsBelowFloor": 12,
        "rowsCollapsedToTotal": 24,
        "variantsCollapsedToTotal": 8
      },
      "output": {
        "records": 1199648,
        "recordsEmitted": 1199210,
        "rows": 3400000,
        "populations": ["EE", "FI", "Total"]
      }
    }
  }]
}]
```

> A record can emit no population row for two unrelated reasons, counted separately
> because the remedies are opposite:
>
> - **`recordsAllRowsWithheld`** — the k-anonymity floor withheld every row, including the
>   coherence collapse. Fix by changing `--min-allele-count`, or accept the loss.
> - **`recordsNoAf`** — no population had an allele frequency to emit, most commonly a site
>   with `AC`/`AN` but no `AF` at all. gnomAD's `AN=0` sites are this case. Fix it upstream
>   in your export; the floor is not involved.

Read top to bottom, the block is the story of the conversion: what came in, what the
projection threw away, what disclosure control withheld, what reached Parquet.
`gvcfReferenceBlocks` is a subset of `recordsNoSupportedAlt`, not a separate drop class.
The four `records*` counts under `discarded` are the whole-record drop classes, and they
close the record identity against `output.recordsEmitted`; the equation is in
[package-format.md](package-format.md). The closing term is `recordsEmitted` rather than
`output.records`, which counts distinct `(chr, POS, REF, ALT)` alleles and is inflated by
multi-allelic splitting. `discarded.alleles` counts ALT alleles lost from records published
on another ALT, so it sits outside the identity.

One invariant holds:
`output.rows + suppressed.rowsBelowFloor + suppressed.rowsCollapsedToTotal` equals the rows
that would exist at `minAlleleCount = 0`. There is no comparable relation between
`input.records` and `output.records`: multi-allelic splitting inflates the distinct-locus
count and shared loci deflate it.

`metadata.populations`, the dataset-wide union of `output.populations`, is the exception:
the node re-derives it from the parquet at ingest and rejects a mismatch, as it does
`numberOfRecords`. `build` self-checks the same claim before emitting a package.

Everything else in the `conversion` block is an unverified provider claim. The source VCFs
are not shipped in the package, so the neighbouring `sha256` already describes a file no
consumer receives, and these counters are the same trust class. The node strips the entire
`files` section at ingest, so provenance never influences what is served. It exists for the
provider's own records and for an integrating system's registry.

The tool version and the applied floor are not repeated here. They are in
`config.generatedBy` and `config.minAlleleCount`.

---

## Resources

Peak memory is set by `--jobs`, not by the size of your VCF, and disk is a fraction of the
input that depends on the VCF's shape.

> [`docs/deployment.md`](deployment.md#resource-baseline) sizes the node, not this tool.
> If you are a data provider producing packages, this section is the one you want.

The figures below are for a 1.60 GB, 7.06 M-record VCF converted by a release build. They
track the workload rather than the machine, so treat the shape as transferable and measure
your own input before provisioning for a batch.

### Memory: `--jobs` is the only lever

`-j`/`--jobs` defaults to `0`, meaning one worker per logical CPU, so on a default run your
machine's core count sets peak memory:

| `-j` | peak RSS |
| --- | --- |
| 1 | 277 MiB |
| 2 | 483 MiB |
| 4 | 688 MiB |
| 8 | 960 MiB (oversubscribed) |

Growth is sub-linear, roughly +206 MiB per doubling of `-j`, so eight times the workers
cost about 3.5 times the memory. Input size barely moves it: doubling the VCF from 4 GB to
8 GB (17.6 M to 35.2 M records) moves peak RSS by under 2 %. The last row has more workers
than cores, which suppresses memory growth because they never run genuinely concurrently;
read it as a floor rather than a figure to extrapolate from.

> The lever needs a big enough input to bite. On a chromosome-slice-sized input each
> worker's buffers never fill, so `-j` barely moves peak memory even while it still cuts
> wall time. Size a container from the table when your VCFs are gigabyte-scale, and
> measure when they are not.

> `-j` cannot exceed your input's partition count. The unit of parallel work is the
> `(chromosome, POS / block_range)` partition, one parquet file each, so the useful worker
> count is bounded by how many partitions your VCF spans and workers beyond that idle. With
> the default `block_range` of 10 Mbp, a VCF covering a single 10 Mbp window is one
> partition, and `-j` does nothing to it, not even to throughput.
>
> This is easy to hit without noticing, because per-chromosome VCFs are the normal way
> population data is distributed. A whole chromosome spans many blocks and parallelises
> fine; a narrow slice of one does not. If `-j` is not helping, count your partitions, one
> file per partition in the staging directory, before reaching for more workers.

Three practical rules:

- **In a memory-capped container, set `-j` explicitly.** `-j 0` respects a CPU restriction,
  so a CPU-limited container picks a sensible worker count on its own. A memory-limited one
  does not: under a cgroup v2 `memory.max` of 512 MiB with swap off, the VCF above is
  OOM-killed at four workers and completes at one. The kill is `SIGKILL`, so the tool
  cannot warn you and you get no diagnostic at all. The build runs under a hidden
  `.{datasetId}.partial` directory and is renamed into place only once complete, so a kill
  leaves no `<out>/<datasetId>/` to clean up or mistake for a finished build. Delete the
  `.partial` leftover at your leisure.
- **Do not exceed your physical cores.** Oversubscribing is worse on every axis: more wall
  time and more CPU for more memory.
- **Budget time by population count, not by file size.** Memory and disk scale with input
  size; wall time does not. It scales with the number of populations, because each one is a
  separate row per locus. At comparable input size and row count, a 512-population dataset
  builds roughly thirteen times slower than a 6-population one. The node accepts up to 512
  populations, so a provider at that cap should expect minutes rather than seconds, and an
  operator's `ingest_timeout_seconds` should be budgeted from population count rather than
  from package size.

Do not extrapolate the memory table to a machine with many more cores, where `-j 0` spawns
that many genuinely concurrent workers. Measure before sizing, or set `-j` explicitly.

### Disk

Two artifacts sit on disk, and both are fractions of the input VCF:

| Artifact | Size | Written by |
| --- | --- | --- |
| staging directory (parquet) | ~8.9 % of the input VCF for a typical whole-genome export | `build` |
| `.tar.c4gh` package | ~1.00× the staging directory | `pack` |

> That fraction is a typical value, not an upper bound. It holds across input size — 4 GB
> and 8 GB agree — but not across input shape, and shape dominates in both directions. The
> fraction is how much of each line survives the projection.
>
> Far below it: on the two real slices `scripts/fetch-corpus.sh` pins, an 82 MiB gnomAD
> sites-only VCF produced a 424 KiB staging dir (0.5 %) and a 74 MiB 1000 Genomes VCF
> produced 52 KiB (0.07 %). Both are overwhelmingly bytes the projection discards: gnomAD
> carries 240 INFO definitions of which the grammar keeps nine, and 1000G carries 2 504
> genotype columns that are never read.
>
> Above it, which is the case that costs you: no genotype columns to discard, and dense
> `AF`/`AC`/`AN` INFO that the projection keeps. A sites-only, INFO-dense, genotype-free
> VCF (286 MB, 1.2 M records, 6 populations) produced a 31.2 MiB staging dir, or 10.9 %,
> with the package at 1.001× staging and 21.9 % for the two held at once.

Budget about 22 % of the input VCF to run `package`, which produces both artifacts and
holds them at once, plus room for the VCF itself. The fraction is bounded by your input's
shape rather than by a constant: a VCF that is mostly genotype columns lands far under, and
one that is mostly INFO fields the projection keeps lands over. Measure one representative
file before provisioning for a batch.

---

## Provider-side key management

The provider's crypt4gh identities are configured by `[keys].identities` (see
[Sections and fields](#sections-and-fields)). With that list empty or absent, the single
primary identity is `<config-dir>/keys/provider.c4gh`:

| File | Contents | Permissions |
|------|----------|-------------|
| `provider.c4gh` | the X25519 secret key (crypt4gh PEM, **unencrypted**) | `0o600` on Unix |
| `provider.c4gh.pub` | the X25519 public recipient (crypt4gh PEM) | normal |

Relative identity paths resolve against the config dir: the parent of the `--config` file
when set, else `$GDI_CONFIG_DIR`, else `$XDG_CONFIG_HOME/gdi`, else `$HOME/.config/gdi`.
Each secret-key file gets a sibling `<name>.pub` recipient when generated.

The secret key is stored unencrypted. The codec reads the plain crypt4gh secret-key
format, not a passphrase-wrapped one, and passphrase-wrapped keys are not implemented.
Protection is file permissions (`0o600`) plus volume-level encryption, not an in-file
passphrase. If you hold a passphrase-wrapped key, unwrap it out of band first, for example
with `crypt4gh-keygen`, and supply the plain key.

Treat `0o600` as a floor, not a control. It stops another local account reading the
file. It stops nothing running as you, and nothing that can read the volume: a backup
snapshot, a mounted disk image, a container escape, a lost laptop. One read of
`provider.c4gh` decrypts every package that provider has ever produced, past and future,
because the same identity is a recipient on all of them and there is no per-package key to
rotate away from. Keep it on an encrypted-at-rest volume (LUKS, FileVault, BitLocker, or a
KMS-backed cloud disk), or hold it in a secrets manager and materialise it only for the
duration of a `pack` or `rekey` run. The tool cannot enforce this and does not check it.

> Back up `provider.c4gh` out of band. It is your only key to your own packages. Lose
> it, along with any `.bak-*` siblings, and you can neither decrypt nor `rekey` anything
> you have already shipped. There is no recovery, and the node cannot help. Keep an
> offline copy under the same encrypted-at-rest custody as the original.

The primary identity is auto-generated on first use, by `pack`/`package` and by the
decrypting commands, if it is missing. `keys generate` creates it explicitly, and
`--force` backs up the existing key before replacing it. `keys show` prints its recipient
and path. See [Key management commands](#key-management-commands).

**Key rotation.** Prepend a freshly generated identity to `[keys].identities` and keep the
retired ones after it. New packages are then encrypted to the new primary's recipient,
while `inspect`, `unpack`, `validate` and `check` still decrypt older packages by trying
every listed identity in order. Drop a retired key from the list once you no longer hold
packages encrypted to it.

**Provider-side security reminders.** The tool reads full source genotypes to compute
aggregates, so:

- Run on an encrypted volume (LUKS, FileVault, BitLocker). Do not rely on `shred` on
  modern SSDs or copy-on-write filesystems.
- Treat the `build/{id}/` staging dir, the scratch dir, and the source VCFs as sensitive.
  Scratch is a dot-prefixed dir beside the output (`.<name>.tmp.<pid>.<nanos>/`, `0o700`,
  files `0o600`), removed on normal completion, error or panic, but not on signal
  interruption (Ctrl-C, SIGINT, SIGTERM), because cleanup is `Drop`-only. An interrupted
  `inspect` or `validate` leaves decrypted plaintext behind; remove any stray
  `.<name>.tmp.*` dir by hand.
- The provider key must not be group- or other-readable.
- Only the crypt4gh-encrypted package leaves the provider.

---

## Command reference

The full set of subcommands, in the order `--help` lists them, which is the order you meet
them. The reference sections below are grouped by workflow instead, so some verbs sit
elsewhere: `init` and `keys` have sections of their own, `diff` is under Packaging,
`preview` under Inspection, and `unpack` under the air-gapped workflow.

| Stage | Commands |
| --- | --- |
| get started | `wizard` · `config` · `init` · `keys` |
| author | `preview` · `build` · `validate` · `lint` · `diff` |
| package | `pack` · `package` · `rekey` · `inspect` · `unpack` |
| ship | `upload` · `deploy` · `download` · `list` |
| lifecycle | `publish` · `unpublish` · `delete` · `status` |
| diagnose | `check` · `doctor` · `catalogs` · `profiles` · `completions` |

`keys` has three subcommands: `generate`, `show` and `pin-recipient`. `completions` emits
a shell-completion script (see [Installation](#installation)).

---

### Setup commands

#### `wizard`

Run a guided, interactive end-to-end flow: it walks you through authoring a `package.yaml`
and producing a package, prompting for the pieces `build` and `package` otherwise take as
flags. Non-interactive automation should call the individual commands instead.

```bash
gdi-dataset-tool wizard [--from <STAGE>] [--to <STAGE>] [-o <PATH>] [--recipient <PATH>]
gdi-dataset-tool wizard setup           # first-run config + keys setup
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--from <STAGE>` | `setup` | Start at this stage, skipping the earlier ones. One of `setup`, `author`, `build`. Pack and Publish need the build output the same run produced, so they cannot begin one. |
| `--to <STAGE>` | `publish` | Stop after this stage. One of `setup`, `author`, `build`, `pack`, `publish`. |
| `-o`, `--output <PATH>` | `package.yaml` | Output path for the authored `package.yaml`. |
| `--recipient <PATH>` | profile URL fetch | Local node recipient file for the offline path, recorded as the profile's `node_recipient_file`. |

The five stages:

- **Setup** collects the profile: its name, the node's public `service_url` (blank if there
  is no node yet), an optional `management_url`, the node recipient, a catalog sync,
  optional S3 (bucket, endpoint, region, key prefix, the two credentials, channel name),
  the country code, the institute abbreviation `org`, and the VCF header policy. It is
  skipped once the profile is complete, and a re-run pre-fills what the profile already
  records. Credentials are typed hidden and stored owner-only in `secrets.env`, which
  lives with the pin and the provider key in the config dir: the parent of the `--config`
  file when set, else the gdi config dir. Adding a second profile asks one more question,
  which of the configured profiles should be the default, because a config with several
  profiles and no `default_profile` selects nothing and every command then stops with "no
  profile selected".
- **Author** asks for the source VCFs, then the catalog entry, the access and legal
  fields, Beacon provenance and disclosure controls. It previews the VCF headers,
  pre-selects the assembly when they agree, offers the catalog allow-list with a refresh
  row that re-syncs from the node, and shows the rendered `package.yaml` for **Write /
  Edit in `$EDITOR` / Abort** before writing anything.
- **Build** shows a disclosure preview, takes an explicit yes, then builds with the
  profile's `header_policy`. The staging dir is written to `build/` beside the
  `package.yaml`, not the working directory. On failure it offers **Edit package.yaml /
  Retry the build / Abort** in a loop, and an edit re-runs the disclosure gate.
- **Pack** writes the package beside the `package.yaml` and offers to remove the now
  redundant staging dir. A keyless profile skips this stage.
- **Publish** offers only the routes the profile can take: S3 when credentials are in hand,
  the inbox when one is configured. Either route lands the dataset hidden. Every run that
  built ends with a summary naming the dataset id, the package path, the manifest, the
  publish outcome, and one next step.

A failure in Pack or Publish prints how to continue from the artifacts already produced
(`pack <staging>`, `upload <package>`), with no rebuild and the same dataset id.

Running the wizard in a directory that still holds a previous dataset's `package.yaml`
asks whether to rebuild it as it is, minting a new dataset id, edit it first, author a new
one at another path, or abort. `--from build` rebuilds it without asking.

`--from` and `--to` select a stage range, not files: `--from build --to pack` re-runs the
build and packs, reusing the `package.yaml` that `-o` names.

`wizard setup` is the first-run helper, the guided equivalent of `config init` plus
`keys generate`. It also records the profile's default VCF header policy, which the Build
stage then shows in its disclosure preview. The wizard never widens that policy on its
own; change the profile, or call `build` directly.

> No node URL and no recipient file yet? You can still author and build. Setup needs some
> way to reach a recipient, so with neither it stops. That gates `pack`, which cannot
> encrypt without the node's key, but not the work before it. Skip the stage instead:
>
> ```bash
> gdi-dataset-tool wizard --from author --to build
> ```
>
> This writes `package.yaml`, converts the VCFs and validates the result into
> `build/<datasetId>/`. When the operator sends the recipient, `pack build/<datasetId>`
> finishes the job, with no rebuild and the same dataset id.

#### `config`

Scaffold a tool configuration file. `config init` writes an annotated template in the
`tool.example.toml` shape, which you then edit: a country code and a `[profiles.<name>]`
block.

```bash
gdi-dataset-tool config init [-o <PATH>] [--force]
```

| Flag | Default | Meaning |
|------|---------|---------|
| `-o`, `--output <PATH>` | the default config path | Where to write the scaffold. |
| `--force` | off | Overwrite an existing config file. |

See [Tool config file](#tool-config-file) for the fields it scaffolds.

---

### Authoring commands

#### `init`

Scaffold a new `package.yaml` template.

```bash
gdi-dataset-tool init [-o <PATH>] [--force]
```

| Flag | Default | Meaning |
|------|---------|---------|
| `-o`, `--output <PATH>` | `package.yaml` | Output path for the scaffold. |
| `--force` | off | Overwrite an existing output file. |

The template carries all four sections with `REPLACE:`-prefixed placeholders for the
required fields. The exception is `applicableLegislation`, pre-filled with the EHDS ELI:
it is removable at the cost of a `build` warning that `--strict` fails on, and extendable
with the GDPR ELI or a national act. Recommended fields sit under their own header, and
optional fields are shown commented out. `init` mints no dataset ID and needs no profile
or country code.

```bash
gdi-dataset-tool init -o my-dataset.yaml
```

#### `build`

Convert a `package.yaml`'s VCFs into a validated staging directory `<out>/<datasetId>/`,
containing `manifest.json`, the parquet files, and optionally `headers/`.

```bash
gdi-dataset-tool build <PACKAGE> [--cc <CC>] [-o <DIR>] [--force] \
    [--no-headers|--header-policy <POLICY>] [--strict] [--refresh-catalogs]
```

| Flag | Default | Meaning |
|------|---------|---------|
| `<PACKAGE>` (positional) | (required) | The `package.yaml`. |
| `--country-code`, `--cc <CC>` | — | Two-letter country code (highest-precedence source). |
| `-o`, `--output <DIR>` | `build` | Output directory; the staging dir is `<out>/<datasetId>/`. |
| `--force` | off | Overwrite an existing staging directory. |
| `--no-headers` | off | Exclude VCF headers entirely (records `internal.headerPolicy: none`). |
| `--header-policy <POLICY>` | profile `header_policy`, else `minimal` | What the packaged headers contain: `minimal` (structural keys only, `#CHROM` truncated to the eight fixed columns), `with-identifiers` (also the `#CHROM` sample columns and `##SAMPLE`/`##PEDIGREE`), or `verbatim` (the source header byte-for-byte, **including tool command lines**, which carry sample identifiers and internal filesystem paths). Recorded in `internal.headerPolicy`. |
| `--dry-run` | off | Convert and gate everything, then discard the output. Writes nothing durable. |
| `--build-epoch <MILLIS>` | wall clock | Pin the build timestamp so `datasetId` and `manifest.json` are reproducible. |
| `--strict` | off | Fail the build if any `warning:` was emitted. `note:` lines never fail a build; see [Notes vs warnings](#notes-vs-warnings-and---strict). It also promotes an unrecognised `package.yaml` key to an error, where a plain build warns. The shared leaf sections `internal`, `contactPoint` and `otherIdentifier` cannot reject unknown keys at parse time, because the node deserialises the same types out of `manifest.json` and must stay lenient there. |
| `-j`, `--jobs <N>` | `0` (one per logical CPU) | Conversion worker-pool size. Lower it to cap peak memory and parallelism; a single VCF still uses the whole pool. |
| `--refresh-catalogs` | off | Before validating, fetch the node's live catalogs for this build only. It does not write to the profile; use `catalogs --sync` to persist them. |
| `--format` | `text` | `text` (the human result line) or `json`, the machine-readable result object carrying the population set, the warning and note counts, and every diagnostic with its source VCF. |

`build` validates the metadata, printing non-fatal warnings to stderr and failing on
errors, resolves the country code, mints the dataset ID, converts each VCF in the first VCF
group to parquet, writes the manifest, and self-checks the parquet. The staging dir is what
`pack` consumes, and it is left in place for inspection.

```bash
gdi-dataset-tool build my-dataset.yaml --cc EE -o build
# built dataset GDI-EE-EXAMPLE-20260409143052837 -> build/GDI-EE-EXAMPLE-20260409143052837
```

#### `validate`

Run the shared structural gates on a local staging directory or a `.tar.c4gh` package,
producing no output artifact.

```bash
gdi-dataset-tool validate <PATH> [--format text|json]
```

| Flag | Default | Meaning |
|------|---------|---------|
| `<PATH>` | (required) | A staging directory or a `.tar.c4gh` package. |
| `--format` | `text` | `text` (a single `error:` line per failure) or `json`, a `{schemaVersion, target, valid, errors, warnings}` object collecting every problem found in one pass. The envelope is printed even when the target cannot be validated at all, such as an unreadable `manifest.json` or a decrypt failure, so a machine consumer always has something to parse. The exit code still signals pass or fail. |

It runs the same gates used at build and at service ingestion: member safety, the metadata
gates over `manifest.json`, and the parquet gates. For a `.tar.c4gh` it first decrypts with
the provider identity and safe-extracts to a scratch dir. A configured `catalogs`
allow-list is enforced; without one, validation is structural. Authoritative SHACL and
HealthDCAT-AP conformance is out of scope for this command.

```bash
gdi-dataset-tool validate build/GDI-EE-EXAMPLE-20260409143052837
gdi-dataset-tool validate GDI-EE-EXAMPLE-20260409143052837.tar.c4gh
```

#### `lint`

Print an advisory quality report over a built staging directory. Where `validate` is a
binary pass/fail gate, `lint` answers "is this good?" before you publish. It never fails
the build: exit 0 unless the directory is unreadable or `--format` is invalid.

```bash
gdi-dataset-tool lint <PATH> [--format text|json]
```

| Flag | Default | Meaning |
|------|---------|---------|
| `<PATH>` | (required) | A `build` output staging directory, holding `manifest.json` and `allele-freq.*.parquet`, or a `.tar.c4gh` package, decrypted to scratch first. |
| `--format` | `text` | `text` (human card) or `json` (the same report, for machine consumers). |

The report covers recommended-metadata coverage (`keywords`,
`numberOfUniqueIndividuals`), per-population and per-variant-type site counts, and an
allele-frequency sanity scan: `AF=0`, `AF≈1`, `AC==AN` saturation, and low-AC or
rare-variant exposure against a threshold. Every line is a per-signal count, not a verdict.
Reading the numbers against your own thresholds is the provider's call.

```bash
gdi-dataset-tool lint build/GDI-EE-EXAMPLE-20260409143052837
gdi-dataset-tool lint build/GDI-EE-EXAMPLE-20260409143052837 --format json
```

---

### Packaging commands

#### `diff`

Report what changed between two builds. It compares the served population set, the variant
count, the `minAlleleCount` floor, the assembly, the build-time suppression each package's
conversion provenance records, and the data-file digests. It is advisory and never fails.

```bash
gdi-dataset-tool diff <OLD> <NEW> [--format text|json]
```

| Flag | Default | Meaning |
|------|---------|---------|
| `<OLD>` / `<NEW>` | (required) | Each is a built staging directory or a `.tar.c4gh` package. |
| `--format` | `text` | `text` (the human report) or `json` (the same report as a machine-readable object). |

Which digests are compared is reported as `comparisonBasis`:

| `comparisonBasis` | Compared | Strength of `identical` |
|---|---|---|
| `payload` | `manifest.payload` — the bytes each package ships | Byte-level. Nothing served changed. |
| `source` | `manifest.files` — the provider's upstream VCF/BAM inventory | **Weaker.** Two packages built from the same sources with a different floor, projection, or tool version compare equal here. |

`source` is the fallback whenever at least one package records no usable `payload`, either
because it predates the section or because it declares a digest algorithm this build cannot
compute. The text report flags the fallback and names both possibilities. Re-run `build` on
both sides to get a `payload` comparison. See
[package-format.md](package-format.md) for the section itself.

#### `pack`

Encrypt an existing staging directory into `{datasetId}.tar.c4gh`.

```bash
gdi-dataset-tool pack <STAGING_DIR> [--recipient <PATH>] [-o <PATH>] [--force]
```

| Flag | Default | Meaning |
|------|---------|---------|
| `<STAGING_DIR>` (positional) | (required) | The `build/{datasetId}/` staging directory. |
| `--recipient <PATH>` | fetched from profile URL, else `node_recipient_file` | Local crypt4gh recipient file for the node (overrides the profile's URL fetch). |
| `-o`, `--output <PATH>` | `{datasetId}.tar.c4gh` in cwd | Output path. An existing directory means "into here", as `cp` reads it: the package lands at `<dir>/{datasetId}.tar.c4gh`. |
| `--force` | off | Overwrite an existing output file. |
| `--format` | `text` | `text` (the human result line) or `json` (a single machine-readable result object). |

The dataset ID is derived from the staging directory's name. The package is encrypted to
the node recipient plus the provider's own recipient. The node recipient is resolved in
order: `--recipient <file>` if passed; otherwise, when the profile has a `service_url` or
`node_recipient_url`, it is fetched over HTTP and verified against the configured
`node_recipient_file` pin. When that fetch fails, `pack`/`package` fall back to the pin,
the configured file or an existing trust-on-first-use pin, with a warning. The pin is what
a successful fetch would have been verified against, so the fallback cannot weaken trust.
A configured pin that is missing or invalid stays a hard error, and with no pin at all an
unreachable node fails `pack`. With no URL configured, `node_recipient_file` is read
directly.

`pack` refuses a staging directory whose bytes no longer match the `payload` its
`manifest.json` recorded at `build` time: a member truncated, replaced, added or removed.
Packing it would publish a package whose manifest describes bytes it does not carry. Re-run
`build` instead. A directory that records no `payload` is not checked, because absent means
unknown rather than verified.

```bash
gdi-dataset-tool pack build/GDI-EE-EXAMPLE-20260409143052837 --recipient node.pub
```

#### `package`

Run `build` + `pack` in one step.

```bash
gdi-dataset-tool package <PATH> [--cc <CC>] [--build-out <DIR>] \
    [--no-headers|--header-policy <POLICY>] [--recipient <PATH>] [-o <PATH>] [--force] [--refresh-catalogs]
```

| Flag | Default | Meaning |
|------|---------|---------|
| `<PACKAGE>` (positional) | (required) | The `package.yaml`. |
| `--country-code`, `--cc <CC>` | — | Two-letter country code (highest-precedence source). |
| `--build-out <DIR>` | `build` | Build output dir; staging is `<build-out>/<datasetId>/`. |
| `--no-headers` | off | Exclude VCF headers entirely. |
| `--header-policy <POLICY>` | profile `header_policy`, else `minimal` | As `build --header-policy`. |
| `-j`, `--jobs <N>` | `0` (one per logical CPU) | Conversion worker-pool size; lower it to cap peak memory and parallelism (a single VCF still uses the whole pool). |
| `--recipient <PATH>` | fetched from profile URL, else `node_recipient_file` | Node recipient file (overrides the profile's URL fetch). |
| `-o`, `--output <PATH>` | `{datasetId}.tar.c4gh` in cwd | Output path. An existing directory means "into here", as `cp` reads it: the package lands at `<dir>/{datasetId}.tar.c4gh`. |
| `--force` | off | Overwrite an existing staging dir **and** output file. |
| `--keep` | off | Keep the staging directory after a successful pack. It is deleted by default, because it holds plaintext genotype-derived intermediates. |
| `--refresh-catalogs` | off | Before building, fetch the node's live catalogs for this build only. It does not write to the profile; use `catalogs --sync` to persist them. |
| `--format` | `text` | `text` (the human result line) or `json` (a single machine-readable result object). |

```bash
gdi-dataset-tool package my-dataset.yaml --cc EE --recipient node.pub
# packaged GDI-EE-EXAMPLE-20260409143052837 -> GDI-EE-EXAMPLE-20260409143052837.tar.c4gh
```

> `package` deletes the staging directory after a successful pack, because it holds
> plaintext genotype-derived intermediates. Pass `--keep` to retain `build/{datasetId}/`
> for inspection.

#### `rekey`

Re-wrap a `.tar.c4gh` package's crypt4gh header to a new node recipient, copying the
encrypted body unchanged. This is the package-owner step of a node-identity rotation (see
[operating.md](operating.md) §9). Rotating an identity does not re-encrypt the payload:
`rekey` decrypts the existing header's session key with the provider's identities and
re-wraps that same key to the new recipient set.

```bash
gdi-dataset-tool rekey <PACKAGE> [--recipient <PATH>] [-o <PATH>] [--force] [--as <PATH>]
```

| Flag | Default | Meaning |
|------|---------|---------|
| `<PACKAGE>` | (required) | The `.tar.c4gh` package to re-key. Must be named `{datasetId}.tar.c4gh` — the same naming contract `upload`/`deploy` enforce, so `rekey` cannot silently rewrite an arbitrarily-named file in place. |
| `--recipient <PATH>` | active profile's node recipient | Local crypt4gh recipient file for the **new** node identity (same precedence as `pack --recipient`). |
| `-o`, `--output <PATH>` | re-key **in place** (needs `--force`) | Output path for the re-keyed package. |
| `--force` | off | Overwrite an existing output file (required for in-place). |
| `--as <SECRET_KEY_PATH>` | a fresh ephemeral writer key | Re-sign the re-wrapped header as this crypt4gh secret key, so the recovered writer fingerprint stays stable and allow-listable. Required to re-key for a `writer_policy = enforce` node; see the warning below. |
| `--format` | `text` | `text` (the human result line) or `json` (a single machine-readable result object, carrying `recipients` plus both `input` and `path`). |

> On a `writer_policy = enforce` node, pass `--as <your-provider-key>`. A plain `rekey`
> re-signs the header with a fresh ephemeral writer key, so the recovered writer
> fingerprint changes and an `enforce` node rejects every re-keyed package with
> `error/writer-rejected`. Passing the provider key that authored the original package
> keeps the fingerprint the one already on the channel's `allowed_writer_fingerprints`:
>
> ```bash
> gdi-dataset-tool rekey <id>.tar.c4gh --as ~/.config/gdi/keys/provider.c4gh --force
> ```
>
> Without `--as`, `rekey` prints a `warning:` to stderr at every verbosity, including
> `-q`, saying it signed with a fresh ephemeral writer key and that a
> `writer_policy = enforce` node will reject the package. The tool cannot read the node's
> policy, so the warning is phrased conditionally; on a `warn` or `off` node the plain
> form is fine. Pass `-v` to also see the resulting writer fingerprint, which is what you
> would add to `allowed_writer_fingerprints`.

The new recipient set replaces the old one, since the point of rotation is to retire the
old node recipient. The package is re-wrapped to the new node recipient plus the
provider's own recipient, mirroring `pack`, so the provider can still decrypt its own
re-keyed packages. The body is copied byte for byte, with no payload re-encryption. The
package is decrypted with the whole provider rotation list, `[keys].identities` tried in
order, so a package addressed to a now-retired provider key still opens.

```bash
# In place against the active profile's new node recipient.
gdi-dataset-tool rekey GDI-EE-EXAMPLE-20260409143052837.tar.c4gh --force

# Or to a new object with an offline recipient file (S3 objects are immutable).
gdi-dataset-tool rekey GDI-EE-EXAMPLE-20260409143052837.tar.c4gh \
    -o GDI-EE-EXAMPLE-20260409143052837.rekeyed.tar.c4gh --recipient new-node.pub
```

Once every package has been re-keyed, retire the old node identity. That is an operator
step; see [operating.md](operating.md) §9.

---

### Key management commands

#### `keys generate`

Create or replace the primary provider crypt4gh identity, the first `[keys].identities`
entry. It defaults to `<config-dir>/keys/provider.c4gh`.

```bash
gdi-dataset-tool keys generate [--force]
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--force` | off | Replace an existing primary identity instead of erroring. The old secret and its `.pub` are first moved aside to timestamped `.bak-<ts>` siblings, and a warning naming the backup is printed. |

Writes the primary secret (`0o600`) and its `.pub` recipient. Generation is otherwise
automatic on first use, so this is mainly for the offline path and explicit rotation. Only
the primary is generated here; add retired keys to `[keys].identities` by hand.

> **Caution:** the regenerated primary cannot decrypt or re-key packages already wrapped
> to the old recipient. Only the `.bak-<ts>` backup can. To rotate without losing access
> to older packages, do not use `--force`. Prepend the new key to `[keys].identities` and
> keep the old one after it (see **Key rotation** above).

```bash
gdi-dataset-tool keys generate
# wrote provider identity to ~/.config/gdi/keys/provider.c4gh
# wrote provider recipient to ~/.config/gdi/keys/provider.c4gh.pub
```

#### `keys show`

Print the primary provider recipient (the X25519 public key in crypt4gh PEM) and its file
path, the active profile's node recipient, and one line per additional configured identity.
If no primary identity exists yet, it is auto-generated first. It stays usable offline:
when the node recipient cannot be resolved it prints a note rather than failing.

```bash
gdi-dataset-tool keys show
# provider identity: ~/.config/gdi/keys/provider.c4gh
# -----BEGIN CRYPT4GH PUBLIC KEY-----
# ...
# additional identity: ~/.config/gdi/keys/provider-prev.c4gh <base64-recipient>
# node recipient:
# -----BEGIN CRYPT4GH PUBLIC KEY-----
# ...
```

#### `keys pin-recipient`

Pin the node's crypt4gh recipient trust-on-first-use for the active profile, so a later
`upload`, `deploy` or `rekey` fails closed if the node ever serves a different recipient
than the one you first trusted. It resolves the recipient in order: an explicit `--url`,
else the profile's `node_recipient_url` or `{service_url}/.well-known/c4gh-recipient`,
else the profile's `node_recipient_file` for the offline path. It prints the fingerprint
and writes the recipient PEM to the pin file. The pin lives in that file; nothing is
written back to the config.

```bash
gdi-dataset-tool keys pin-recipient [--url <URL> | --file <PATH>] [-o <PATH>] [--force]
```

`--file <PATH>` pins a recipient handed over offline, such as a `.pub` on a USB stick,
instead of fetching one. It is also the only way to adopt a rotated node key where no URL
is reachable: `wizard setup --recipient <file>` refuses a pin that differs and has no
`--force` of its own, so run `keys pin-recipient --file <PATH> --force` after verifying the
rotation out of band.

| Flag | Default | Meaning |
|------|---------|---------|
| `--url <URL>` | profile `node_recipient_url`, else `{service_url}/.well-known/c4gh-recipient` | Fetch the recipient from this URL. Mutually exclusive with `--file`. |
| `--file <PATH>` | — | Pin a recipient handed over offline instead of fetching one. Mutually exclusive with `--url`. |
| `-o`, `--output <PATH>` | profile `node_recipient_file`, else `<config_dir>/recipients/<host>_<port>.<hash>.pub` | Where to write the pinned recipient PEM (e.g. `recipients/127.0.0.1_8081.f6ac1fc112aec9f3.pub`). A destination, never a recipient source. |
| `--force` | off | Re-pin over an existing pin, accepting a changed recipient. |

With no `--url`, no `--file`, and no `service_url`/`node_recipient_url` on the profile, the
recipient is read from the profile's `node_recipient_file`. Set that key to pin
air-gapped.

---

### S3 deploy workflow

The S3 channel uses a flat bucket layout written by the tool:

```
_sync_marker.json                              # change marker (bumped after any mutation)
{id}.tar.c4gh                                  # the package
{id}.state.json                                # visibility sidecar ({"state":"visible"|"hidden"})
_status/{id}.json                              # node-written ingest result; the tool ignores it on list
```

All S3 commands act on the **active profile's** `[profiles.<name>.s3]` bucket.

#### `upload`

PUT a local `.tar.c4gh` into the bucket (hidden by default), in the spec write
order (package, then the `hidden` state sidecar, then the marker bump last).

```bash
gdi-dataset-tool upload <PACKAGE> [--replace]
                                  [--wait] [--wait-timeout <SECONDS>] [--management-url <URL>]
```

| Flag | Default | Meaning |
|------|---------|---------|
| `<PACKAGE>` | (required) | The local `{id}.tar.c4gh` to upload. |
| `--replace` | off | Re-upload an id already present in the bucket — to retry an `error`ed id with a fixed package. Preserves the dataset's current visibility (see below). |
| `--wait` | off | Block until the node has ingested the package, instead of returning once the bytes are in the bucket. Exits non-zero with the node's reason if the package is rejected, where a naive `until state == visible` loop would report a timeout. Needs a reachable management plane. |
| `--wait-timeout <SECONDS>` | `300` | How long `--wait` polls before giving up. Higher than `deploy`'s default because an S3 bucket is polled, so the node may not look for the package for a poll interval before ingest starts. |
| `--management-url <URL>` | profile `management_url`, else `service_url` | Where `--wait` polls the dataset-state oracle. |
| `--format` | `text` | `text` (the human result line) or `json` (a single machine-readable result object). Both report a `state`. Without `--wait` that is the visibility `upload` wrote, or under `--replace` the preserved one. With `--wait` the object is emitted after the wait and `state` is the node's terminal ingest state, alongside `"waited": true`; a rejection emits `"status":"error"` with the node's `"reason"` before the non-zero exit. |

By default `upload` rejects an id already present in the bucket, a client-side guard
against an accidental sub-second ID collision. `--replace` re-uploads on request, but
does not overwrite the immutable package: the node ignores the changed source bytes for an
already-installed id. `--replace` preserves the dataset's current visibility and bumps the
marker, so a re-upload can never silently un-publish a live dataset. A `visible` dataset
stays visible with no further step. Do not re-run `publish` reflexively: a dataset hidden
for a reason, such as a consent withdrawal or a legal hold, also stays hidden, and
publishing it would disclose it.

The node ingests asynchronously, and an S3 bucket is polled rather than watched. With the
shipped defaults the node does not look for the id for up to about 30 s, its
`_sync_marker.json` HeadObject poll (`[[s3.buckets]].marker_poll_interval`), or up to
about 5 min if the marker bump was missed and it falls back to the unconditional full
rescan (`full_poll_interval`). A tuned node has its own numbers. A successful `upload`
only lands the bytes in the bucket, so an initial silence from `status <id>` is expected
rather than a failure. Run `status <id>` to confirm the node picked them up, and
`check <id>` once you `publish`. `upload` prints this latency as a `note:` on stderr,
except under `--wait`, which waits the gap out and reports the terminal state instead.

```bash
gdi-dataset-tool upload GDI-EE-EXAMPLE-20260409143052837.tar.c4gh
# uploaded GDI-EE-EXAMPLE-20260409143052837 (hidden)
```

> `--wait` is also how you catch a mis-targeted upload. A successful `upload` proves
> only that the bytes reached the bucket, not that the bucket is the one this node reads.
> Point the profile at the wrong bucket, or omit the `prefix` the node's
> `[[s3.buckets]].prefix` confines it to, and the upload succeeds, `list` shows the
> dataset, and the node never sees it. It polls a keyspace your object is not in, reports
> zero poll errors, and stays healthy. `--wait` turns that silence into a timeout that
> names the id, the earliest signal either side can give you. See
> [prefix](#sections-and-fields) for the desync itself.

#### `download`

GET a `{id}.tar.c4gh` from the bucket to a local path (backup, transfer).
S3-only; there is no local analog.

```bash
gdi-dataset-tool download <ID> [-o <PATH>] [--force] [--format text|json] [--max-size <BYTES>]
```

| Flag | Default | Meaning |
|------|---------|---------|
| `<ID>` | (required) | Dataset id; `{id}.tar.c4gh` is fetched. |
| `-o`, `--output <PATH>` | `{id}.tar.c4gh` | Output path. An existing directory means "into here", as `cp` reads it: the package lands at `<dir>/{id}.tar.c4gh`. |
| `--force` | off | Overwrite an existing output file. |
| `--format` | `text` | `text` (human result line) or `json` (machine-readable result). |
| `--max-size <BYTES>` | (none) | Refuse to download if the object exceeds this size — a guard against an oversized/hostile package before it lands on disk. |

```bash
gdi-dataset-tool download GDI-EE-EXAMPLE-20260409143052837 -o backup.tar.c4gh
```

#### `list`

List datasets in the bucket with their visibility (from the `{id}.state.json`
sidecars). Output is `id<TAB>visibility` to stdout.

> An empty result under a `prefix` is checked against the rest of the bucket. On its own
> an empty listing is indistinguishable from an empty bucket, and it is the only signal
> a [prefix desync](#sections-and-fields) gives the writer. When the listing comes back
> empty, `list` looks once at the whole bucket and warns if datasets are sitting outside
> the keyspace it was told to use. The node does not run this probe from its side.

```bash
gdi-dataset-tool list [--visible | --hidden] [--format text|json]
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--visible` | off | Show only visible datasets. |
| `--hidden` | off | Show only hidden datasets. |
| `--format` | `text` | `text` (the `id<TAB>visibility` listing) or `json`. |

`--visible` and `--hidden` are mutually exclusive; omit both to show all. `list` reads only
the bucket. It does not probe the service per id, which is `status`'s job, and it ignores
the marker and `_status/*` objects. There is no error filter, because the service-side
`error` and `processing` states are never written to S3.

```bash
gdi-dataset-tool list --hidden
```

---

### Inbox deploy workflow

#### `deploy`

Copy a `.tar.c4gh` **or** a prepared staging directory into the node's local
inbox for ingestion. The drop is **atomic** (staged as a `*.partial` file or a
dot-prefixed dir, then `rename()`d into place), so the node's inbox scan only
ever sees a complete artifact.

```bash
gdi-dataset-tool deploy <ARTIFACT> [--inbox <DIR>] [--replace]
                                   [--wait] [--wait-timeout <SECONDS>] [--management-url <URL>]
```

| Flag | Default | Meaning |
|------|---------|---------|
| `<ARTIFACT>` | (required) | A `{id}.tar.c4gh`, or a `build/{id}/` staging dir containing `manifest.json`. |
| `--inbox <DIR>` | profile `inbox` | The node inbox directory to drop into. Naming it fully specifies the target, so `deploy` then needs no tool profile. It must already exist; see the note below. |
| `--replace` | off | Re-present an id already on the node, to retry an `error`ed id. Also required to overwrite an artifact already sitting in the inbox: both local writers refuse an existing target without it. |
| `--wait` | off | Block until the node finishes ingesting, instead of returning the moment the file lands. Exits non-zero with the node's reason if the package is rejected, where a naive `until state == visible` loop would wait out the timeout and report the wrong thing. |
| `--wait-timeout <SECONDS>` | `120` | How long `--wait` polls before giving up. |
| `--management-url <URL>` | profile `management_url`, else `service_url` | Where `--wait` polls the dataset-state oracle. Needed when there is no profile: `--inbox` says where to drop the package, this says where to watch it land. |
| `--format` | `text` | `text` (the human result line) or `json` (a single machine-readable result object). With `--wait` it is emitted after the wait and carries `"waited": true` plus the terminal `"state"`; a rejection emits `"status":"error"` with the node's `"reason"` before the non-zero exit. |

When the node's management plane (`management_url`, else `service_url`) is reachable,
`deploy` refuses an id that is already live, `visible` or `hidden`, unless `--replace`. An
unreachable node proceeds, since the node is the backstop and ignores a changed source for
a live id. To remove an inbox-owned dataset, use [`delete`](#delete). The node ingests
asynchronously: a successful `deploy` only drops the artifact into the inbox, so run
`status <id>`, or `check <id>` once visible, to confirm it went live.

> The inbox must already exist; the tool will not create it. The node creates its inbox at
> startup, so on any node that has run it is there. An absent one means the path is
> wrong, and `deploy`, `publish`, `unpublish` and `delete` all refuse rather than create
> it. A created-on-demand inbox would turn the one signal a mistyped path gives, `ENOENT`,
> into a phantom inbox that accepts every drop while the node reads the real one and sees
> nothing. If you are staging a drop before the node's first start, `mkdir -p <inbox>`
> first; the error message names that command.

```bash
gdi-dataset-tool deploy GDI-EE-EXAMPLE-20260409143052837.tar.c4gh --inbox /var/inbox
# deployed GDI-EE-EXAMPLE-20260409143052837 -> /var/inbox/GDI-EE-EXAMPLE-20260409143052837.tar.c4gh
```

---

### Offline / air-gapped workflow

The package-creation path needs **no network**: `build`, `validate`, `pack`, and
`package` use only local inputs. Two node-specific inputs must be provisioned
out-of-band (a small bundle the operator hands you):

1. **The node's crypt4gh recipient.** Supply it via `--recipient` or the profile's
   `node_recipient_file`. With no `service_url` or `node_recipient_url` configured, the
   file is the recipient. With a URL configured, `pack`/`package` still try the fetch
   first, because that is what verifies the pin, but a failed fetch falls back to the pin
   with a warning, so an air-gapped or not-yet-running node does not block packing.
   `--recipient` overrides both. `gdi-dataset-tool wizard setup` sets this up: answer its
   "Node service URL" prompt with a blank line when there is no node to name, and give it
   the recipient file the operator sent you. The wizard copies that file to
   `<config-dir>/recipients/<profile>.pub` and records the copy, so the profile keeps
   working once the medium it arrived on is gone.
2. **The catalog allow-list**, the profile's `catalogs`, so `build`, `validate`,
   `catalogs` and `init` can validate and offer catalog names without reaching the node.
   With no `service_url` there is nothing to sync from, so `wizard setup` offers to take
   the names as free text; blank is a fine answer. Supplying them turns the authoring
   step's catalog question into a pick-list, but the list is enforced once non-empty
   (`error: unknown catalog: …`), so a list typed wrong from memory blocks catalogs the
   node would have accepted. Leave it blank unless the operator told you the names.

Handoff is also out of band. An air-gapped provider can neither `upload` to S3 nor reach
the node, so the finished `.tar.c4gh` moves over the operator's approved channel, physical
media or file transfer, and is dropped into the node's inbox. It is crypt4gh-encrypted to
the node recipient, so it is safe to carry over untrusted media.

Typical air-gapped flow:

```bash
# 1. Generate / confirm your provider identity once.
gdi-dataset-tool keys generate

# 2. Build + pack with the operator-supplied node recipient (no network).
gdi-dataset-tool package my-dataset.yaml --cc EE --recipient node.pub

# 3. Carry the .tar.c4gh out on media; the operator drops it into the inbox.
```

`pack` and `unpack` are the air-gapped pair: `pack` encrypts, `unpack` materialises
plaintext back out.

#### `unpack`

Decrypt with the provider identity, validate, and extract a `.tar.c4gh` to an arbitrary
directory, for inspection or manual transfer. To install a package into a node, use
`deploy`, not `unpack`.

```bash
gdi-dataset-tool unpack <PACKAGE> -o <DIR> [--force]
```

| Flag | Default | Meaning |
|------|---------|---------|
| `<PACKAGE>` | (required) | The `.tar.c4gh` to decrypt and extract. |
| `-o`, `--output <DIR>` | (required) | Output directory (created if missing). |
| `--force` | off | Extract into a non-empty output directory. |

After extracting, `unpack` re-runs the structural gates so the output is
known-valid.

```bash
gdi-dataset-tool unpack GDI-EE-EXAMPLE-20260409143052837.tar.c4gh -o extracted
```

---

### Lifecycle commands

These operate on an already-installed dataset and route by channel. When the node's
management plane (`GET /datasets/{id}/state`) is reachable, the tool reads the
authoritative channel there. Otherwise it falls back to `--s3` or `--local`, or infers
from the profile shape: S3 configured means S3, else inbox. The write is the same
declarative `{id}.state.json` edit on both channels — a bucket sidecar plus a marker bump
for S3, an inbox sidecar for local.

#### `publish` / `unpublish`

Make a hidden dataset visible (`publish`) or a visible one hidden
(`unpublish`).

```bash
gdi-dataset-tool publish   <ID> [--s3 | --local] [--inbox <DIR>] [--management-url <URL>]
gdi-dataset-tool unpublish <ID> [--s3 | --local] [--inbox <DIR>] [--management-url <URL>]
```

| Flag | Default | Meaning |
|------|---------|---------|
| `<ID>` | (required) | The dataset id. |
| `--s3` | off | Select the S3 channel **when the node cannot be asked**. It is a fallback, not an override: with the management plane reachable its authoritative channel wins and this flag is ignored (see the preamble above). |
| `--local` | off | Select the local (inbox) channel on the same terms as `--s3`, and ignored on the same terms. |
| `--inbox <DIR>` | profile `inbox` | The inbox to write the `{id}.state.json` sidecar into. Implies `--local` and needs no tool profile, the same escape hatch `deploy --inbox` takes. Refused if the node reports the dataset is owned by an S3 channel, where the sidecar would be silently ignored. |
| `--management-url <URL>` | profile `management_url` | The node's management-plane base URL for the state oracle, which supplies the dataset's authoritative channel and confirms it is live. Needed on the profile-less `--inbox` path, which otherwise has no oracle to consult. |
| `--format` | `text` | `text` or `json`, a single machine-readable result object carrying `state`, `channel` and `applied`. `state` is the state written to the sidecar, and `applied` is always `false`: the command never waits for the node to read it, so treating `state` as the node's current state is wrong for up to one `rescan_interval_seconds`. Poll `GET <management_url>/datasets/<ID>/state`, or run `check <ID>`, to observe the flip. |

`--s3` and `--local` are mutually exclusive. Both verbs are refused unless the dataset is
currently live, `visible` or `hidden`, per the state endpoint. When the node is
unreachable the edit proceeds, since the node ignores a sidecar for an unknown id. The
node applies the visibility flip asynchronously: read
`GET <management_url>/datasets/<id>/state`, or run `check <id>`, to confirm it took
effect. `status <id>` also works wherever a tool profile is configured.

```bash
gdi-dataset-tool publish GDI-EE-EXAMPLE-20260409143052837
# published GDI-EE-EXAMPLE-20260409143052837: wrote the visible sidecar on inbox /srv/gdi/inbox.
# The node applies it on its next scan; its management-plane
# /datasets/GDI-EE-EXAMPLE-20260409143052837/state reports when it has
```

> `unpublish` on a node's only remaining dataset does not retract it from a GDI User
> Portal harvest. The portal's FDP harvester computes new, changed and deleted ids only
> when its crawl returns at least one dataset. A crawl of a node with zero visible datasets
> is indistinguishable from a failed crawl, so it is a no-op rather than a retraction, and
> the portal keeps the stale entry listed with an `access_url` that now answers
> `exists:false`. This is consumer-side behaviour: the command still succeeds and the node
> still reports `hidden`. A node with two or more datasets is unaffected. To retract the
> last dataset from an affected portal, ask the portal operator to clear the source
> (`harvester clearsource`) rather than relying on the next harvest. See
> `docs/operating.md` §12/§13 for the node-side lifecycle.

#### `delete`

Remove a dataset from the node, routed by channel. An S3-owned id removes its
`.tar.c4gh`, `.state.json` and `.metadata.json` from the bucket and bumps the marker. The
overlay goes with the package because ids are reusable, and one left behind would govern
whatever is uploaded under that id next. An inbox-owned id writes its inbox
`{id}.state.json` as `{"state":"deleted"}`, and the service reconciles it and removes
`datasets/{id}/`.

```bash
gdi-dataset-tool delete <ID> [--force] [--dry-run] [--s3 | --local] [--inbox <DIR>]
                             [--management-url <URL>]
```

| Flag | Default | Meaning |
|------|---------|---------|
| `<ID>` | (required) | The dataset id. |
| `--force` | off | Delete even a currently-visible dataset (for an inbox dataset this writes `{"state":"deleted","force":true}`). |
| `--dry-run` | off | Preview the delete: resolve the channel and target, run the visibility guard, then report what would be deleted. Writes nothing. Run this first. |
| `--s3` | off | Select the S3 channel **when the node cannot be asked**; ignored while the management plane is reachable, whose channel wins (see the preamble to these commands). |
| `--local` | off | Select the local (inbox) channel on the same terms as `--s3`, and ignored on the same terms. |
| `--inbox <DIR>` | profile `inbox` | The inbox to write the `{id}.state.json` sidecar into. Implies `--local` and needs no tool profile, the same escape hatch `deploy --inbox` and `publish --inbox` take. |
| `--management-url <URL>` | profile `management_url` | The node's management-plane base URL for the visibility guard. Needed on the profile-less `--inbox` path, which otherwise has no state oracle to consult. |
| `--format` | `text` | `text` or `json` (a single machine-readable result object). |

`delete` is refused if the dataset is currently visible, unless `--force`. `unpublish`
first to be safe. `--s3` and `--local` are mutually exclusive.

`delete` fails closed when it cannot check. An unreachable node makes a
`publish`/`unpublish` edit a harmless no-op, but `delete` is irreversible, so it refuses
rather than proceeding when visibility cannot be determined at all:

```console
$ gdi-dataset-tool delete GDI-EE-EXAMPLE-20260409143052837 --inbox /srv/gdi/inbox
error: cannot confirm whether dataset GDI-EE-EXAMPLE-20260409143052837 is currently visible:
no management-plane state oracle is reachable, so the visible-guard cannot run. …
```

That is the profile-less `--inbox` form: with no tool config there is no `management_url`,
so there is nothing to ask. Three ways forward, in preference order:

1. **`--management-url http://127.0.0.1:9090`** gives it the oracle, and the guard then
   runs for real. This is the one to reach for.
2. **`unpublish` first**, then delete.
3. **`--force`** deletes without the check. Correct when the node is genuinely gone, as in
   a decommission; wrong as a habit.

```bash
gdi-dataset-tool unpublish GDI-EE-EXAMPLE-20260409143052837
gdi-dataset-tool delete    GDI-EE-EXAMPLE-20260409143052837
```

---

### Inspection and troubleshooting commands

Six read-only verbs sit at different points on the lifecycle. None of them mutates a
package or the node. Which one to reach for, earliest to latest:

| Verb | Where on the timeline | What it does |
|------|-----------------------|--------------|
| `preview` | before `build` | Dry-runs one VCF: header parse plus per-record validation, writing no staging dir. It is not the same gate as `build`, because it judges records individually, so cross-record checks such as the duplicate `(chrom, POS, REF, ALT)` gate run only in `build`. A clean `preview` does not guarantee a clean `build`; use `build --dry-run` for the faithful check. |
| `validate` | after `build`, before `pack`/ship | Binary pass/fail structural gates over a staging dir **or** a `.tar.c4gh`. |
| `lint` | after `build`, before `publish` | Advisory per-signal quality counts; never fails the build. |
| `inspect` | any `.tar.c4gh`, any time | Prints one package's manifest or member listing — it **reads**, it compares nothing. |
| `check` | after `publish` | Asserts the served FDP record agrees with the package on four public fields. |
| `doctor` | before shipping | Read-only preflight of the profile + node reachability. |

`validate` and `lint` are documented under [Authoring](#authoring-commands). The sections
that follow here are `preview`, `inspect`, `status`, `catalogs`, `check`, `doctor` and
`profiles`.

#### `preview`

Dry-run a VCF through the conversion's header parse and record validation without writing
a staging directory, to sanity-check what `build` would produce. It reports the recognized
populations, the recognized AF/AC INFO fields, the distinct-record and emitted-row counts,
the `NS` peak when the VCF carries that field (the individual count it suggests for
`numberOfUniqueIndividuals`), and any warnings and notes. Bgzipped `.vcf.gz` input is
accepted.

To see a full-size report before you have an export of your own, preview the repository's
sample: a synthetic 1 637-site, twelve-population export in the shape a
`bcftools +fill-tags -S groups` chain produces
(`crates/test-util/tests/fixtures/sample/gdi-sample.GRCh38.vcf.gz`, with a `--strict`-clean
`gdi-sample.package.yaml` beside it; see [`docs/testing.md`](testing.md#shared-fixtures)).

```bash
gdi-dataset-tool preview <VCF> [--assembly GRCh38] [--block-range 10000000] \
    [--min-allele-count 0] [--floor-impact] [--format text|json]
```

| Flag | Default | Meaning |
|------|---------|---------|
| `<VCF>` | (required) | The VCF (plain or `.vcf.gz`) to preview. |
| `--assembly` | `GRCh38` | Assembly used for contig validation. |
| `--block-range` | `10000000` | Position block size in bases (matches `build`'s `blockRange`; `0` = a single group). |
| `--min-allele-count` | `0` | Build-time minimum allele-count floor. |
| `--floor-impact` | off | Also report what the floor withholds: one aggregate line (`N of M row(s) withheld (P%), K kept`) plus the names of the populations it erases entirely. It is not a per-population row count. It converts the VCF a second time with no floor to get the baseline, so it roughly doubles the run; `--min-allele-count 0` short-circuits that. |
| `--format` | `text` | `text` or `json`. |

#### `inspect`

Inspect a local `.tar.c4gh` without deploying it to a node. It decrypts with the provider
identity to a scratch TAR in constant memory. The scratch dir is removed on normal
completion, error or panic, but not on signal interruption: a Ctrl-C leaves a stray
`.<name>.tmp.*` dir of decrypted plaintext to remove by hand.

```bash
gdi-dataset-tool inspect <PACKAGE> [--manifest | --files [--order <ORDER>]]
```

| Flag | Default | Meaning |
|------|---------|---------|
| `<PACKAGE>` | (required) | The `.tar.c4gh` to inspect. |
| `--manifest` | — | Print `manifest.json` (the first member) and stop — never reads into the parquet payload. |
| `--files` | — | List every member with its size. |
| `--order <ORDER>` | `name` | Sort order for `--files`: `name`, `name-desc`, `size` or `size-desc`. Requires `--files`. |
| `--format` | `text` | `text` or `json`. Manifest mode emits the manifest object; `--files` and the default emit a member array. `inspect` builds its JSON directly and carries no `schemaVersion`, the one `--format json` verb without the versioned envelope. |

`--manifest` and `--files` are mutually exclusive. With no mode flag, `inspect` prints the
member list in archive order. The manifest JSON and member listing go to stdout.

```bash
gdi-dataset-tool inspect GDI-EE-EXAMPLE-20260409143052837.tar.c4gh --files --order size-desc
gdi-dataset-tool inspect GDI-EE-EXAMPLE-20260409143052837.tar.c4gh --manifest | jq .metadata
```

#### `status`

Show a dataset's resolved node state, channel, and sync summary. State comes from the
management plane (`/datasets/{id}/state`) when reachable. A remote tool falls back to the
bucket's `_status/{id}.json` writeback, or reports node state `unavailable`. The sync
summary is S3-relative (`in-sync`, `drifted`, `missing`); an inbox-owned dataset reports
`sync: local`.

The reported `state` is not self-describing: it may come from the live node oracle or from
a possibly stale `_status/{id}.json` S3 sidecar, and the text output does not say which.
Without a `management_url` configured or passed, treat the reported `state` as
non-authoritative. The `--format json` output carries a `stateSource` field, `"node"` for
the authoritative oracle or `"sidecar"` for the S3-derived one, so a script can tell the
two apart.

```bash
gdi-dataset-tool status (<ID> [--diff] | --all) [--management-url <URL>]
```

| Flag | Default | Meaning |
|------|---------|---------|
| `<ID>` | (required, or `--all`) | The dataset id. |
| `--all` | off | Report on every dataset (S3 listing, or — on a no-S3 node — the FDP-visible datasets). Mutually exclusive with `--diff`. |
| `--diff` | off | Show the granular file / `ETag` / state diff between the local copy and S3. Requires an id; S3-only. |
| `--management-url <URL>` | profile `management_url` | The node's management-plane base URL for the state oracle. It applies to `--all` too, including the up-front reachability probe, so the command cannot decide the node is down against one base and then query another. |
| `--format` | `text` | `text` or `json`. The JSON form carries `stateSource`, which the text output does not expose. |

`--all` requires no id. `--diff` requires an id and is S3-only; a local dataset says so.
For `--all` on a no-S3 node, the id set is the FDP-visible datasets enumerated from the
node's catalogs.

```bash
gdi-dataset-tool status GDI-EE-EXAMPLE-20260409143052837 --diff
gdi-dataset-tool status --all
```

#### `catalogs`

List the catalog names this node accepts: online from the node's public FDP root
(`{service_url}/fairdp`), offline from the profile's `catalogs` allow-list. Used to
validate `metadata.catalog` and to scaffold `init`.

```bash
gdi-dataset-tool catalogs [--offline] [--sync [--dry-run]] [--format text|json]
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--offline` | off | Use the offline `catalogs` allow-list even when a `service_url` is set. |
| `--sync` | off | Fetch the node's live catalogs and persist them into the active profile's `catalogs` allow-list, a config-file write, so later offline runs and `metadata.catalog` validation match the node. The wizard's catalog list offers the same refresh. |
| `--dry-run` | off | With `--sync`, fetch and report what would change, the added and removed catalog names, writing nothing. `--sync` rewrites the whole config file, dropping comments and any inline S3 credentials, so run this first. |
| `--format` | `text` | `text` (the `name<TAB>title` listing) or `json`. |

Output is `name<TAB>title` (the title from the allow-list when known).

```bash
gdi-dataset-tool catalogs
gdi-dataset-tool catalogs --offline
```

#### `check`

Spot-check that the running service's FDP output agrees with the package on its key public
fields. It reads the package's `manifest.json`, fetches the served FDP record
(`{service_url}/fairdp/dataset/{id}`), and asserts that four fields — `datasetId`, `title`,
`license` and `accessRights` — are present and consistent. The comparison is containment,
not a full-record diff, so a passing `check` confirms those four agree rather than that the
whole served record is correct. The service must be running.

```bash
gdi-dataset-tool check (<ID> | --all | --hidden | --visible | --local <PATH>) [--format text|json]
```

| Flag | Default | Meaning |
|------|---------|---------|
| `<ID>` | (one target required) | A concrete S3 dataset id to check. |
| `--all` | off | Check every dataset in the S3 bucket. Mutually exclusive with `<ID>`, `--local`, `--visible`, and `--hidden`. |
| `--hidden` | off | Check only hidden S3 datasets. Mutually exclusive with `--all`, `--visible`, and `--local`. |
| `--visible` | off | Check only visible S3 datasets. Mutually exclusive with `--all`, `--hidden`, and `--local`. |
| `--local <PATH>` | — | Check a local artifact (a `.tar.c4gh` or a staging dir) instead of S3 (the no-S3 workflow). |
| `--format` | `text` | `text` or `json` — machine-readable per-dataset check results. |

`check` needs a configured `service_url`. The S3 selectors need a `[profiles.<name>.s3]`
block; `--local` does not. It exits non-zero, naming the failing ids, if any checked
dataset's served FDP output disagrees with the package on one of those four fields.

Under `--all`, a dataset the node does not serve is reported as `UNAVAILABLE`
(`unavailable` under `--format json`) and counts as a mismatch. A hidden dataset is the
usual case, since `upload` deposits hidden by default and the FDP dataset route serves
only visible datasets. The run still checks every remaining id and still emits the full
JSON envelope; only the exit code reflects the failure.

```bash
gdi-dataset-tool check GDI-EE-EXAMPLE-20260409143052837
gdi-dataset-tool check --all
gdi-dataset-tool check --local GDI-EE-EXAMPLE-20260409143052837.tar.c4gh
```

Exactly one target is required, and a listing selector cannot be combined with an id.
`check <ID> --hidden` and `check <ID> --local <PATH>` are rejected with a usage message.

#### `doctor`

A read-only, side-effect-free preflight of the active profile and a node's reachability.
Run it before shipping a package so a broken profile, recipient or endpoint surfaces up
front rather than at `upload` or `deploy`.

```bash
gdi-dataset-tool doctor [--offline] [--recipient <PATH>]
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--offline` | off | Run only the offline checks (skip the FDP / S3 reachability probes). |
| `--recipient <PATH>` | profile node recipient | Local crypt4gh recipient file for the node. |
| `--format` | `text` | `text` (the per-check `[OK  ]`/`[FAIL]` lines) or `json` (a machine-readable report). |

It validates that the profile loads, that the provider identity loads without being
generated, that its recipient derives, that the key is not readable beyond its owner, and
that the resolved node recipient is a usable crypt4gh recipient. On Unix a group- or
world-readable key fails the check, because file permissions are the only protection an
unencrypted key has; fix it with `chmod 600`. Online it also checks that the FDP root
responds, that the catalog list is fetchable, and, if an S3 block is set, that the bucket
is writable, via a probe PUT and DELETE on a reserved key. It does not probe the
management plane's `/health/ready`. Offline it checks the local recipient file and the
`catalogs` allow-list. A failure exits non-zero.

`--recipient <file>` is independent of `--offline`: passed on its own it points the
node-recipient check at that local file while still running the online FDP, catalog and S3
probes. So if a bare `doctor` fails the node-recipient check, re-run
`doctor --recipient node.pub` to validate a recipient you hold, or `doctor --offline` to
skip the online probes entirely.

```bash
gdi-dataset-tool doctor
gdi-dataset-tool doctor --offline --recipient node.pub
```

#### `profiles`

Print the configured profiles and which one is active, with the resolved bucket and
endpoint. Read-only, with S3 credentials redacted. Use it to confirm which profile a bare
invocation would pick before running a networked verb.

```bash
gdi-dataset-tool profiles [--format text|json]
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--format` | `text` | `text` (default) or `json` — a machine-readable `{active, default_profile, profiles}` object (credentials redacted). |

It also prints the hyphen-versus-underscore phantom-twin warning described under
[Troubleshooting](#troubleshooting), so it is the quickest way to see whether a
`GDI_TOOL__PROFILES__<NAME>__…` override landed on the profile you meant.

---

## End-to-end workflows

### S3-backed node

```bash
# 1. One-time: provider identity + sanity check.
gdi-dataset-tool keys generate
gdi-dataset-tool doctor

# 2. Author + build + pack.
gdi-dataset-tool init -o my-dataset.yaml
# ... edit my-dataset.yaml ...
gdi-dataset-tool package my-dataset.yaml --cc EE
gdi-dataset-tool validate GDI-EE-EXAMPLE-...tar.c4gh     # optional structural re-check

# 3. Upload (hidden), publish, then confirm.
gdi-dataset-tool upload GDI-EE-EXAMPLE-...tar.c4gh
gdi-dataset-tool list --hidden                           # confirm it landed (still hidden)
gdi-dataset-tool publish GDI-EE-EXAMPLE-...
gdi-dataset-tool check GDI-EE-EXAMPLE-...                 # verify the served FDP record (404s while hidden)
gdi-dataset-tool status GDI-EE-EXAMPLE-...                # sync summary; needs a management_url to be authoritative
```

### Inbox / co-located node

```bash
gdi-dataset-tool package my-dataset.yaml --cc EE --recipient node.pub
gdi-dataset-tool deploy GDI-EE-EXAMPLE-...tar.c4gh --inbox /var/lib/gdi-node-standalone/inbox
gdi-dataset-tool publish GDI-EE-EXAMPLE-... --local
```

### Air-gapped

```bash
# On the air-gapped machine (operator-supplied node.pub + catalogs in config):
gdi-dataset-tool keys generate
gdi-dataset-tool doctor --offline --recipient node.pub
gdi-dataset-tool package my-dataset.yaml --cc EE --recipient node.pub
# Carry GDI-EE-EXAMPLE-...tar.c4gh out on approved media; operator drops it into the inbox.
```

### Batch (many datasets)

`upload` and `deploy` are safe to re-run over a whole set. Each refuses an id already
present in the bucket or already live on the node, exiting non-zero for that id without
overwriting it, because a live dataset is immutable. A second pass therefore installs only
the new ids and reports the already-present ones. Use `--replace` to retry an `error`ed id.
Partial-failure orchestration, such as retries and parallelism, belongs in your own script.

Branch on the [exit code](#overview) rather than parsing messages: `3`, transient, is the
one worth retrying, while `2`, usage, and `4`, auth, are not. Most networked verbs
(`upload`, `deploy`, `status`, `check`, `doctor`) also accept `--format text|json` for
machine-readable output.

```bash
# S3: upload every local package; keep going past ids already in the bucket.
for pkg in *.tar.c4gh; do
  gdi-dataset-tool upload "$pkg" || echo "skipped $pkg (already present or failed)" >&2
done
gdi-dataset-tool list --hidden          # review, then publish the ones you want

# Inbox: deploy every package into the node's inbox, tolerating already-live ids.
for pkg in *.tar.c4gh; do
  gdi-dataset-tool deploy "$pkg" --inbox /var/lib/gdi-node-standalone/inbox \
    || echo "skipped $pkg (already live or failed)" >&2
done
```

### JSON result shape

The result the state-changing verbs emit under `--format json` follows a stable contract
you can script against. Each such verb prints one JSON result object. The read verbs `list`
and `catalogs` print a different object, `{"schemaVersion": 1, "datasets": [...]}` and
`{"schemaVersion": 1, "catalogs": [...]}`, whose rows are `{"id", "visibility"}` and
`{"name", "title"}`, so script those as `jq '.datasets[]'` and `jq '.catalogs[]'` rather
than `jq '.[]'`. The result object's keys are:

> `schemaVersion` is not limited to this mutation-result contract. The report verbs
> `status`, `lint`, `doctor`, `preview`, `diff`, `validate` and `profiles` wrap their own
> structured `--format json` shapes in the same versioned envelope, so they carry
> `"schemaVersion": 1` too and a consumer can version-gate report and action output alike.
> The one exception is `inspect`, which builds its JSON directly and carries no
> `schemaVersion`.

| Field | Notes |
|-------|-------|
| `schemaVersion` | Integer result-object contract version (currently `1`); bumped **only** on a breaking change to this shape. |
| `status` | `"ok"` on success. |
| `action` | The verb: `build`, `pack`, `upload`, `publish`, `delete`, `rekey`, `deploy`, `download`, … |
| `datasetId` | The dataset id, when the verb operates on one. |
| `path` | The **local** artifact a verb produces / acts on: `build` (the staging dir), `pack`/`package` (the `.tar.c4gh`), `download` (the written file), `rekey` (the output package — `rekey` also emits `input`). |
| `target` | The **remote** bucket / inbox a verb acts on: `upload`, `publish`/`unpublish`, `delete`, `deploy`. |

A verb carries either `path`, for local-artifact verbs, or `target`, for remote and
channel verbs, never both. Each verb also adds its own fields: `rekey`'s `recipients`,
`upload`'s `replace`, `delete`'s `force`, and `publish`/`unpublish`'s `state`, `channel`
and `applied`.

Failures are machine-readable too. Under `--format json`, a command that fails without
producing its own object emits an error envelope on stdout rather than leaving it empty, so
a consumer always has something to parse:

```json
{ "schemaVersion": 1, "status": "error", "reason": "…", "exitCode": 1 }
```

`reason` is the same single line printed to stderr, and `exitCode` mirrors the process exit
code, so a script can branch on the failure class without parsing prose. A verb that reports
its own failure shape emits that instead and never both: `validate` returns its
`{valid: false, errors: […]}` envelope, `doctor` its failed checks, `check` its per-dataset
results. In every case exactly one JSON object reaches stdout.

---

## Troubleshooting

**`country code is required but not set`** — `build`/`package` could not resolve a country
code. Set one of, in increasing precedence: the tool config's root-level `country_code`,
which sits under no section; `GDI_TOOL__COUNTRY_CODE`; or `--cc`.

**`output already exists` / `staging directory ... already exists`** — pass `--force` to
overwrite. These are the `build`, `pack`, `package`, `init`, `download` and `unpack` output
guards.

**`no node recipient: pass --recipient <file>, set the profile's node_recipient_url (or
service_url), or set node_recipient_file`** — `pack`/`package` could not resolve a node
recipient. Supply `--recipient node.pub`, or set `node_recipient_file` when the profile
configures no `service_url` or `node_recipient_url`. With a URL configured the recipient is
fetched over HTTP and verified against the pin; `--recipient` overrides the fetch.

**`invalid recipient ...` / `node recipient ... is not a valid recipient`** — the recipient
file or URL is not a valid crypt4gh public key. Confirm it is the X25519 public key in
crypt4gh PEM format.

**`cannot decrypt <package>: none of the N configured provider identities could decrypt
it`** (`inspect`, `unpack`, `validate`, `check`) — the package was not encrypted to any of
your provider recipients. Packages are encrypted to the provider's recipient at `pack`
time, so if you replaced rather than prepended your identity, add the old key back to
`[keys].identities`. Identities resolve under the config dir, so running with `--config`
can select a different key set than the default.

**`the active profile has no [profiles.<name>.s3] block`** — an S3 command (`upload`,
`download`, `list`, or an S3-channel lifecycle op) ran without a `[profiles.<name>.s3]`
block in the config. Add one, or use the inbox channel.

**`S3 bucket is not writable (your token may lack write permission)`** — `doctor`'s write
probe, a PUT of a temporary `.doctor-probe-*` key, was denied. The token is read-only, or
the bucket policy withholds `s3:PutObject`. `upload` and every lifecycle write need a
read/write token.

**`not authorized: <step>: ...`** — an operation was denied, and the message names the
failing step, such as `uploading <key>` or `listing bucket`. The command exits `4`, so
automation can branch on it and refresh credentials. Before requesting new ones, check the
likelier cause: if you set the credentials via `GDI_TOOL__PROFILES__<NAME>__…`, `<NAME>`
must match the profile name exactly, with underscores rather than hyphens, or the injected
values land in a separate phantom profile and the request goes out unauthenticated. The
tool prints `warning: profiles '<a>' and '<b>' differ only by '-' vs '_'…` on every
networked verb when it detects such a twin, so check stderr, or run
`gdi-dataset-tool profiles`, which prints the same warning alongside what it loaded. Then
run `gdi-dataset-tool doctor`.

**`dataset <id> is already live on the node` / `dataset <id> is already present in the
bucket`** — the id is already installed. `upload` and `deploy` refuse to re-present it
without `--replace`. On S3, `--replace` does not overwrite the immutable package bytes,
because the node ignores a changed source. It preserves the dataset's current visibility
and bumps the marker, so a live dataset stays live and a hidden one stays hidden.

**`dataset ... is not live` (publish/unpublish)** — only a `visible` or `hidden` dataset
can be published or unpublished. Ingest it first, and let it leave `processing`.

**`dataset <id> reads as visible on the node's state oracle` (delete)** — `unpublish` it
first, or pass `--force`. If you have just run `unpublish`, the oracle lags the sidecar by
a few seconds; wait and retry.

**`cannot determine the dataset's channel`** — a lifecycle op could not reach the node, and
the profile has neither an S3 block nor an `inbox`. Pass `--s3` or `--local`.

**`unknown profile '<name>'`** — the name is not in `[profiles.<name>]`. The message lists
the available profiles. Pick one of those, or omit `--profile` to use the root-level
`default_profile` or the sole configured profile.

**`no profile selected` / `no profiles configured`** — a node-targeting command ran with
several profiles, or none, and no selection. Pass `--profile <name>` or set the root-level
`default_profile`.

**Clearing a dataset stuck in `error`** — the node leaves a bad package in `error`. Fix the
`package.yaml`, rebuild and repack, then re-present with `upload --replace` on S3 or
`deploy --replace` on the inbox. Use `status <id>` to confirm the state, `check <id>` to
compare the served record against the package, and `inspect --manifest` to read the
packaged metadata.

**Diagnosing a broken setup** — run `doctor`, or `doctor --offline`, to check the profile,
provider identity, node recipient, FDP reachability, catalogs and S3 writability in one
shot.

### Output and diagnostics

- The tool is a one-shot CLI and installs no logger. There is no `RUST_LOG`, `LOG_FORMAT`
  or colour control; verbosity is the global `-v` and `-q` flags, and they affect stderr
  only. Command results go to stdout, kept clean for piping. Diagnostics and the
  single-line cause chain of a failure go to stderr, and the process exit code (`0`, `1`,
  `2`, `3`, `4` or `5`; see the [exit-code table](#overview)) is the status signal.
- Nothing it prints reveals key material, S3 credentials, sample identifiers,
  subject-revealing paths, or genotype values.
