# Package format (`.tar.c4gh`)

The normative on-disk format of a GDI dataset package: the interchange contract any tool
that produces or consumes a package builds against. The `gdi-dataset-tool` `build` and
`pack` commands write it and the node ingests it, and this document specifies it for both
and for any third-party producer or consumer.

For the authoring workflow, the `package.yaml` you write, which is not this format, see
[gdi-dataset-tool.md](gdi-dataset-tool.md). For how the node stores a package after ingest
see [architecture.md](architecture.md).

## Encryption envelope

A package is an **uncompressed TAR** (see below) encrypted with **crypt4gh v1** and named
`{datasetId}.tar.c4gh`. The framing is standard crypt4gh:

```
magic "crypt4gh" (8 bytes) │ version u32-le (= 1) │ packet_count u32-le
  │ packet_count header packets (one per recipient)
  │ body: a sequence of 64 KiB ChaCha20-Poly1305 cipher segments
```

- The package is addressed to one or more recipients, normally the node's published
  crypt4gh recipient. A fresh random session key is drawn per encryption.
- crypt4gh headers are re-wrappable, so the recipient set can be changed by rewriting only
  the header, with no payload re-encryption. That is what `gdi-dataset-tool rekey` does for
  a node-identity rotation.

**Recipient and writer key are different keys.** Confusing them breaks ingest. The
*recipient* is the public key a package is encrypted **to**, normally the node's. The
*writer key* is the secret key the header was signed **with**, that is, who packed it. On
ingest the node recovers the writer key's fingerprint (`sha256:<hex>`) and checks it against
that channel's allow-list — `[ingest].inbox_allowed_writer_fingerprints` for the inbox,
`allowed_writer_fingerprints` on the bucket for S3. `[ingest].writer_policy` decides what a
failed check costs.

The trap is that a plain `gdi-dataset-tool rekey` mints a fresh ephemeral writer key unless
`--as` names one. The fingerprint therefore changes, and a node running `writer_policy =
"enforce"` rejects a package it previously accepted. Pass `--as` with the original identity
when re-keying a package that must stay attributable to the same provider.

### Ranged front read (reading the manifest without the payload)

`manifest.json` is the first TAR member, so a consumer that needs only metadata can read
the leading bytes of even a multi-GB `.tar.c4gh` (over S3, a ranged `GET`), decrypt those,
and stop before the parquet payload. To size that range you need the header length and the
segment size:

- **Header length.** The header is `magic(8) ‖ version(4) ‖ packet_count(4)` followed by
  `packet_count` packets, each prefixed by its own u32-le total length (the prefix includes
  its own 4 bytes). The header ends, and the body begins, at `16 + Σ packet_len`. This is
  derivable from the header bytes alone; a consumer need not decrypt or re-encrypt to find
  it. `gdi_node_standalone_core::crypt4gh::header_len(prefix) -> Result<Option<usize>>` is
  the authoritative definition of this framing. It returns `None` if the prefix is too
  short, in which case fetch more and retry.
- **Segment size.** The body is a sequence of fixed cipher segments of
  `CIPHER_SEGMENT_SIZE` = `SEGMENT_SIZE (65536) + 12-byte nonce + 16-byte tag` = **65564**
  bytes, each decrypting to up to `SEGMENT_SIZE` = **65536** plaintext bytes (both are
  public constants of `crypt4gh`).
- **The boundary rule.** A ranged read must end on a segment boundary,
  `header_len + n·CIPHER_SEGMENT_SIZE`. A cut in the middle of a segment fails to decrypt;
  the reference Python `crypt4gh` raises `ValueError: Could not decrypt that block` after
  emitting the good prefix. One whole segment, 64 KiB of plaintext, more than covers the
  `manifest.json` at the front of a typical package. If `manifest.json` is larger, fetch
  further whole segments until its TAR member is complete.

## TAR layout

The plaintext inside the envelope is an uncompressed TAR with a strict member order:

| # | Member | Notes |
| --- | --- | --- |
| 1 | `manifest.json` | Always first, so a metadata-only consumer reads it without touching the payload. |
| 2 | `headers/{vcfId}.vcf` | Sorted; the source VCF headers, filtered by `internal.headerPolicy`. Dropped at ingest and not served, so like `files` and `internal` this is a producer-to-integrating-system channel (see [`files` / `internal`](#files--internal-stripped-at-ingest)). |
| 3 | `allele-freq.chr{CHR}.{block}.br{range}.{vcfId}.parquet` | Sorted; the aggregated-frequency payload, last. |

Parquet member names are six dot-separated components: `allele-freq`, `chr{CHR}` (`1`–`22`,
`X`, `Y`, `M`), `{block}`, `br{range}`, `{vcfId}`, `parquet`. For example,
`allele-freq.chr3.0.br10000000.0123456789abcdef.parquet`. TAR entry headers are normalized
for reproducibility: mode `0644`, uid and gid `0`, empty owner names, mtime `0`, regular
files only.

> **Several `{vcfId}`s may share one `{block}`, and a consumer must not assume otherwise.**
> One source VCF yields one `{vcfId}`, so a package built from several VCFs can hold several
> files for the same `chr` and `block`. Rows are sorted by `(POS, REF, ALT, POPULATION)`
> within each file, never across files. Sources split by population cover the same loci, so
> their `POS` spans overlap and reading the files back to back yields a `POS` that jumps
> backwards. A consumer that needs ordered rows must merge the block's files; one that
> assumes concatenation is ordered will mis-group silently.
>
> The reference node merges such a block in memory before folding it, at a cost described in
> [operating.md §22](operating.md#22-one-datasets-queries-cost-far-more-than-its-neighbours).
> Packages that split by position rather than population put one file in each block and
> avoid the question.

## `manifest.json`

The package's first member. Serialized `camelCase`. Top level:

> **Canonical type contract:** [`manifest.schema.json`](manifest.schema.json) is the
> authoritative machine-readable schema (JSON Schema draft 2020-12), generated from the Rust
> `Manifest` model in `crates/core/src/model` and held to it by a freshness test. It carries
> every field's name, type and description. The tables below are a human-readable summary,
> and on any conflict the schema wins. Validate or code-generate against the schema rather
> than hand-transcribing these tables. Semantics the schema cannot express are noted inline
> below: `numberOfRecords` is required at ingest though optional on the wire, and the node
> re-derives and enforces both `numberOfRecords` and `populations`.

| Field | Type | Required? | Meaning |
| --- | --- | --- | --- |
| `metadata` | object | yes | FDP-public per-dataset metadata (below). |
| `files` | array | no | Upstream source provenance (VCF/BAM inventory). Stripped at ingest. |
| `internal` | object | no | Non-public, node-opaque bookkeeping. Stripped at ingest. |
| `payload` | object | no | Digests of the packaged members (below). Retained at ingest. |
| `config` | object | yes | Processing options + provenance (below). |

### `metadata`

| Field | Type | Required? | Meaning |
| --- | --- | --- | --- |
| `datasetId` | string | yes | The generated dataset ID (replaces the authoring `prefix`/`org`). |
| `catalog` | string | yes | Must match a catalog the node accepts. |
| `title` | string \| lang-map | yes | Plain string or a `{lang: text}` map. |
| `description` | string \| lang-map | yes | Ingest rejects a manifest without it; `manifest.schema.json` lists it under `required`. |
| `accessRights` | IRI string | yes | Access-right authority IRI. |
| `applicableLegislation` | IRI array (≥ 1) | yes | EU ELI IRIs. Omitting the EHDS ELI (`http://data.europa.eu/eli/reg/2025/327/oj`) is a warning, not a rejection. |
| `license` | IRI string | yes | Reuse license IRI. |
| `creator` | `[{name}]` (≥ 1) | yes | Creating agents. |
| `healthCategory` | IRI array (≥ 1) | yes | GDI health-category IRIs. |
| `keywords` | string array | no | Discovery tags. |
| `numberOfUniqueIndividuals` | uint | no | Distinct sequenced subjects. |
| `conformsTo` | IRI array | no | GDI standards-compliance IRIs, a closed set: `ExternallyGoverned`, `1MGCompliant` and `1MGCohort` under `http://data.gdi.eu/core/p2/`. Any other value is rejected. |
| `type` | IRI string | no | Dataset-type IRI (set only for synthetic data). |
| `legalBasis` | IRI array | no | DPV legal-basis IRIs. |
| `isReferencedBy` | IRI array | no | Publication DOI IRIs. |
| `otherIdentifier` | `[{notation, schemaAgency?, name?}]` | no | Secondary identifiers. |
| `contactPoint` | `{fn?, hasEmail?, hasURL?}` | no | Dataset-level contact. |
| `numberOfRecords` | uint | required at ingest | Distinct `(chr, POS, REF, ALT)` count. The node re-counts and rejects a mismatch. |
| `populations` | string array | no | The population labels the dataset serves, sorted: the union of each source VCF's emitted set, after the build-time `minAlleleCount` floor. The node re-derives it from the parquet and rejects a mismatch, as for `numberOfRecords`; an absent claim is accepted. Served on the beacon `datasets` entry as `gdiDatasetInfo.populations`. |

### `config`

Serialized `camelCase` with `deny_unknown_fields`, so an unrecognized key fails ingest
loudly.

| Field | Type | Required? | Meaning |
| --- | --- | --- | --- |
| `mode` | `aggregated` \| `individual` | yes | Only `aggregated` is implemented; `individual` is rejected. |
| `blockRange` | uint | yes | Position block range in bases (`0` = one file per chromosome). |
| `afSource` | string | no | Allele-frequency provenance source (free text). |
| `afSourceReference` | string (URL) | no | Provenance source reference. |
| `minAlleleCount` | uint | no (default `0`) | AC floor. Applied at build as data minimisation, and re-applied at serve time at the effective floor `max([beacon].min_allele_count, this value)`. A node can raise a declared floor but never lower it, and an out-of-band parquet built without the drop is still suppressed. Disclosed as `gdiDatasetInfo.minAlleleCount`. |
| `hideLowerCounts` | uint | no | Declared sensitive-tier floor, recorded only. Applied neither at build nor at serve. |
| `assembly` | `{reference}` | yes | The dataset assembly the node reads (promoted from the VCF group's `reference`; a dataset is single-assembly). |
| `manifestVersion` | uint | yes | Manifest schema version — see below. |
| `generatedBy` | string | yes | The tool identity that produced the manifest. |

### `files` / `internal` (stripped at ingest)

Who reads these sections is a deployment choice, not a node feature. They exist for the
provider's own records and, optionally, for an integrating system: a back-office of the node
operator's own that reads a package's non-public parts (`files`, `internal`, `headers/`) for
its registry, lineage or sample bookkeeping. A standalone node needs no such system.

`files` is the inventory of the provider's source inputs, `[{category, reference?,
preciseReference?, files: [{path, sha256?, size?, conversion?}]}]`, recorded as provenance
rather than as the served payload. `internal` is `{internalId?, pastVersion?,
headerPolicy?}`, node-opaque bookkeeping. The node parses both as opaque and then strips
them: neither reaches the stored `datasets/{id}/manifest.json`, which carries `metadata`,
`config` and `payload`. `payload` is kept where these two are not, because it describes the
bytes this node now serves rather than the provider's upstream inputs.

### `payload` (retained at ingest)

`{algorithm, members: {"<tar member>": {sha256, size}}}`: the SHA-256 and size of every TAR
member the package carries except `manifest.json` itself, keyed by member name
(`headers/{vcfId}.vcf`, `allele-freq.*.parquet`) and sorted by key. `algorithm` is
`"sha256"`, encoded in the schema as an `enum` with `^[0-9a-f]{64}$` on each digest, so a
document declaring anything else is schema-invalid rather than merely unverifiable.

The inner key is `members`, not `files`, because a top-level `files` already means the
provider's source inventory.

**`payload` is what the package ships; `files` is what it was built from.** They are not
interchangeable: two packages built from identical source VCFs with a different
`minAlleleCount` floor, column projection or tool version have identical `files` and
different payloads. `gdi-dataset-tool diff` therefore prefers `payload` and reports which
basis it used, as `comparisonBasis: payload | source`.

> **The retained `payload` is the package's inventory, not the served directory's.** The
> node keeps the section verbatim, including its `headers/{vcfId}.vcf` entries, but drops
> the `headers/` members themselves at store time as data minimisation. They are therefore
> digested in the record and absent from `<data_dir>/{id}/` on every healthy dataset. A
> consumer re-verifying the stored manifest against the served directory must check the
> `allele-freq.*.parquet` entries and treat the `headers/` ones as a record of what arrived,
> not as files it should find. Only the parquet entries describe bytes the node still holds.

The section is optional. **Absence means unknown, never "no payload"**: consumers must not
treat a missing `payload` as a verification that passed.

* `pack` refuses a staging directory whose bytes no longer match a recorded `payload`, such
  as a partially-copied `rsync`, an ENOSPC truncation or a hand-pruned directory, so a
  package whose manifest describes bytes it does not carry cannot be signed. With no
  `payload` recorded the check is skipped, not failed.
* The node verifies it at ingest, after the manifest is validated and before anything is
  stored or `files` and `internal` are stripped, so a package that does not contain what it
  declares leaves nothing behind in the data dir. The `parquet-digests.json` sidecar cannot
  answer this, because it is computed from the received bytes: a package that disagreed with
  its own manifest would have the disagreement recorded faithfully and `verify --digest`
  would report `ok`.
* Member names are validated before use. They are attacker-influenced input joined onto a
  filesystem path, so a name that escapes the package (`../…`, absolute, `.`-segments) is
  rejected rather than followed.
* The node retains it, unlike `files` and `internal`: it carries no upstream provenance, and
  it is the only at-rest record of what the served data was supposed to be.

`internal`, `contactPoint` and `otherIdentifier` accept unknown keys at parse time, and must:
the node deserialises these same shapes out of a provider's `manifest.json`, so an older node
has to tolerate a field a newer package added rather than reject a package over a section it
discards anyway. The cost is that a typo in one of them is dropped silently, so
`gdi-dataset-tool build` reports unrecognised keys as a warning and `build --strict` as an
error. Every other `package.yaml` section rejects unknown keys at parse time.

Each `path` is the source file's path relative to the `package.yaml`'s directory,
`/`-separated on every platform, or the operator's declared string verbatim when the file
lies outside that directory. It is not an in-package member name; the source files are never
shipped inside the `.tar.c4gh`. Keeping the relative path rather than the bare basename lets
a per-chromosome layout (`chr1/data.vcf.gz`, `chr2/data.vcf.gz`) record two distinguishable
provenance rows.

Each VCF entry carries a `conversion` block recording what the VCF-to-parquet projection
discarded, ordered along the pipeline. Most fields are `uint` counts; four are string arrays.
The exact wire shape is pinned by the `crates/core/tests/fixtures/manifest.json` round-trip
guard.

```json
"conversion": {
  "input":      { "records": 1000, "nonPassRecords": 12, "gvcfReferenceBlocks": 3,
                  "populationsRecognized": ["EE", "FI", "Total"] },
  "discarded":  { "recordsUnsupportedContig": 4, "recordsNoSupportedAlt": 5,
                  "recordsAllRowsWithheld": 3, "alleles": 6,
                  "ignoredInfoFields": ["EUR_AF", "SAS_AF"], "populationsWithoutAf": ["LV"] },
  "suppressed": { "rowsBelowFloor": 7, "rowsCollapsedToTotal": 8, "variantsCollapsedToTotal": 9 },
  "output":     { "records": 900, "recordsEmitted": 988, "rows": 2700,
                  "populations": ["EE", "FI", "Total"] }
}
```

The four string-array fields are `input.populationsRecognized`,
`discarded.ignoredInfoFields`, `discarded.populationsWithoutAf` and `output.populations`.
They are label lists; a consumer that types them as integers fails to parse a real package.
Every other field is a `uint` count.

`input.gvcfReferenceBlocks` is a subset of `discarded.recordsNoSupportedAlt`, not a drop
class of its own. The four `records*` counts under `discarded` are the whole-record drop
classes, and they close the record identity with `output.recordsEmitted`:

```text
input.records == discarded.recordsUnsupportedContig
               + discarded.recordsNoSupportedAlt
               + discarded.recordsAllRowsWithheld
               + discarded.recordsNoAf
               + output.recordsEmitted
```

`recordsAllRowsWithheld` and `recordsNoAf` are the two ways a record can emit nothing. They
are separate counters because their remedies are opposite:

| Counter | Cause | What the provider does about it |
| --- | --- | --- |
| `discarded.recordsAllRowsWithheld` | the k-anonymity floor withheld every row (including its coherence collapse) | change `config.minAlleleCount`, or accept the loss |
| `discarded.recordsNoAf` | no population had an allele frequency to emit — the input carried no usable `AF` | fix the upstream export; the floor is not involved |

Keeping them apart matters because a record with no usable `AF`, such as a gnomAD `AN = 0`
site where `AF`, `AF_XX` and `AF_XY` are all omitted, is not a disclosure-control drop. A
provider who saw it counted as one would go looking at a floor setting that had done nothing.

A manifest written without `recordsNoAf` omits it (`#[serde(default)]`, so it reads as `0`)
and folds those records into `recordsAllRowsWithheld`. The identity still closes, with a
coarser attribution.

The closing term is `output.recordsEmitted`, not `output.records`. The latter counts distinct
`(chr, POS, REF, ALT)` alleles, which multi-allelic splitting inflates and shared loci
deflate, so it can never close against `input.records`. `discarded.alleles` counts ALT alleles
lost from records that were published on another ALT, so it is outside this identity too. A
manifest that omits `recordsAllRowsWithheld` or `recordsEmitted` (both `#[serde(default)]`)
cannot close the identity.

The source VCFs are not shipped, so the neighbouring `sha256` already describes a file no
consumer receives. The `conversion` block is the same trust class: an unverified provider
claim, never used for serving. The one exception is the dataset-wide `metadata.populations`,
which the node re-derives from the parquet and enforces. The whole `files` section is
stripped at ingest.

## Overlay sidecars

Sidecars are small JSON files dropped beside a package, in the same S3 prefix or inbox
directory, to drive node behaviour out of band. They are not part of the encrypted archive.

A note on `deleted`, the **tombstone** state: it is an instruction, not a description. It
says "remove this dataset", and it appears in two directions — as a value an orchestrator
writes into `{id}.state.json`, and as the node's own `{"state":"deleted"}` status
writeback. Reading it as a report of something already gone, in either direction, inverts
its meaning.

Both sidecar bodies have a generated, freshness-guarded JSON Schema an orchestrator can
validate against, derived from the same models the node parses:
[`state-sidecar.schema.json`](state-sidecar.schema.json) and
[`metadata-overlay.schema.json`](metadata-overlay.schema.json).

**`{id}.state.json`** — visibility. Lenient parse (unknown keys, including a
`schemaVersion`, are tolerated):

```json
{ "schemaVersion": 1, "state": "visible", "force": false }
```

- `state` (required): `visible` | `hidden` | `deleted`.
- `force` (optional, default `false`): bypasses the `deleted` safety guard.
- `traceparent` (optional): a W3C `traceparent` string. When it is present and the node is
  configured to trust the sidecar source (`[service].trust_sidecar_traceparent`), the
  package's `ingest_job` span is parented under it, so a producer can correlate its publish
  with the node's ingest across the HTTP-less S3 handoff. Absent, the node starts a fresh
  server-side root. That flag is separate from `[service].trust_inbound_traceparent`, which
  governs `traceparent` HTTP headers on the two listeners: writing this sidecar means
  holding bucket write credentials, while sending a header only means reaching the port, so
  trusting one must not require trusting the other.

The sampling flag travels with the `traceparent`. Trace-flags ending `-00` mark it as not
sampled, so the node's `ingest_job` span for that package, and everything under it, is
dropped rather than exported. The node honours that upstream decision rather than overriding
it, which means the writer of the sidecar decides whether the ingest is observable. To get
the node's ingest trace, sample your own publish span (`-01`). Omit `traceparent` entirely
and the node roots its own trace, which is always exported.

**`deleted` means different things per channel.** On the local inbox channel it is a delete
command: it removes the dataset directory and status, and `force` bypasses the
visible-dataset guard. On an S3 bucket, deletion means removing the `{id}.tar.c4gh` object,
so a `deleted` `.state.json` there is not a delete verb. Rather than treat it as `hidden`
silently, the node surfaces it with a warn log and the
`gdi_s3_deleted_sidecar_ignored_total{channel}` metric, and keeps the dataset hidden, so an
orchestrator that reused the inbox verb on an S3 channel can tell its deletion did not take
effect. To delete on S3, remove the object, for example with `gdi-dataset-tool delete`, which
also bumps `_sync_marker.json`.

**`{id}.metadata.json`** is an operator metadata overlay patch. Serialized `camelCase` with
`deny_unknown_fields`; every field is optional, and a present field overwrites the baseline
while an absent one leaves it untouched. It may carry any `metadata` field except the
protected `datasetId`, `catalog`, `numberOfRecords` and `populations`. Setting one of those
fails to parse and rejects the entire patch, not just the offending field; the last two are
node-derived from the parquet at ingest and so are not operator-editable.

On reconcile the node merges the patch over the pristine manifest, re-validates it, and
writes a durable `.metadata.overlay.json` holding `{applied_at, patch}`, where `applied_at`
is a node-stamped `YYYY-MM-DDTHH:MM:SS.mmmZ` timestamp surfaced as `dct:modified`. Removing
the sidecar reverts to baseline.

### Node status writeback (`_status/{id}.json`) — the reverse channel

The two sidecars above flow from orchestrator to node. The status writeback flows the other
way: on a bucket where `[[s3.buckets]].write_status` is enabled, the node writes its
per-dataset result to the reserved `_status/{id}.json` object, and the tool or an integrating
system reads it to detect drift without querying the node's management API. Its type contract
is the generated, freshness-guarded
[`status-writeback.schema.json`](status-writeback.schema.json):

```json
{ "schemaVersion": 1, "id": "GDI-…", "state": "visible",
  "source_signature": "\"9a0e…\"", "updated_at": "2026-07-10T20:08:00.000Z" }
```

- `state` (required): `processing` | `visible` | `hidden` | `error` | `deleted`.
- `source_signature` (present except on `deleted`): the `.tar.c4gh` `ETag` this result is
  for. A reader compares it against the package's current ETag, per the signature contract
  below, to tell a fresh result from a stale one.
- `error_message` (present only on `state: error`): a sanitized, closed-class string drawn
  from the fixed error-class vocabulary (see [api.md](api.md)), never a raw internal error.
- `schemaVersion`, `id` and `updated_at` are provenance. Readers parse leniently, requiring
  only `state`, so an older or partial object still deserializes. The on-wire keys are mixed:
  `schemaVersion` is camelCase and the rest are snake_case, which the schema pins as-is.

## Package change detection (the S3 signature contract)

On the S3 channel, the node detects whether a `{id}.tar.c4gh` has changed by its object
`ETag`, falling back to the object's last-modified timestamp when the endpoint reports no
ETag. That is the dataset's source signature: an unchanged signature means nothing to do, a
changed one means a new or changed package. Two consequences follow that a producer must
know.

- **The ETag is upload-method dependent, not a content hash.** A single-part `PUT` yields an
  ETag that is the object's MD5, but a multipart upload yields a composite ETag,
  `md5-of-part-md5s-N`. The same bytes re-uploaded with a different part size, or by a
  different client, therefore present as a changed package. Re-upload a package the same way
  you first uploaded it if you intend no change.
- **A dataset is immutable once served.** A live (`visible` or `hidden`) dataset is not
  re-ingested when its package is re-presented, whatever the ETag: the re-presented bytes are
  logged and ignored, and only a `{id}.state.json` visibility flip takes effect. To replace a
  served dataset's payload, delete it and re-add it under a new id, since datasets are
  content-versioned by id rather than mutated in place. An `error` dataset is re-attempted
  when its signature changes, which is the intended retry lever; see
  [operating.md §4](operating.md).

An orchestrator that wants a stable, content-addressed notion of "changed" should track its
own content hash of the plaintext it packaged, rather than relying on the transport ETag.

## Versioning and compatibility

- **`config.manifestVersion` is the format version**, currently `1`. The tool stamps it and
  the node rejects any other value at ingest. There is no tolerant path that reads an older
  or newer manifest.
- The contract is therefore exact-match: a node accepts packages whose `manifestVersion`
  equals the version it supports. A bump is a coordinated change. A producer must not emit a
  version a target node does not accept, and a node upgrade that changes the supported
  version is a breaking change recorded in the [CHANGELOG](../CHANGELOG.md).
- **Only `{id}.state.json` is tolerant.** It carries a `schemaVersion` discriminator,
  currently `1`, that the node ignores along with any other unknown key, so that sidecar can
  gain fields without breaking older nodes. The `_status/{id}.json` writeback is read
  leniently in the other direction, requiring only `state`.
- **`{id}.metadata.json` is strict.** It accepts no `schemaVersion` key and no unrecognized
  field, because that field list is the editable allow-list. Adding a field to the overlay is
  therefore a breaking change for strict consumers rather than an additive one, and is
  recorded in the [CHANGELOG](../CHANGELOG.md).
