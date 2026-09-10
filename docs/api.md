# gdi-node-standalone HTTP API reference

The HTTP contract for a running `gdi-node-standalone` node: what each endpoint is, which
listener serves it, and how it behaves. The companion docs are the
[operator runbook](operating.md) and the [provider guide](gdi-dataset-tool.md).

The node serves two listeners, and the split is a security boundary. The public plane
carries only visible-dataset data. The management plane exposes the hidden-dataset state
oracle and operational metrics, so it must stay off the public Ingress. See
[operating.md §1](operating.md#1-health-and-readiness-endpoints) for health-probe detail
and [operating.md §21](operating.md#21-audit-log) for what is audited.

## Beacon mount prefix

`{prefix}` below is the configured beacon mount path: `[beacon].aggregated_base_path`
(default `/aggregated/beacon/v2`) and `[beacon].sensitive_base_path` (default
`/sensitive/beacon/v2`). The two differ by default, so the node mounts an aggregated
beacon (`g_variants` + `datasets`) and a separate sensitive beacon (`individuals`). Set
them equal to mount one combined beacon serving all three entry types.

## Public plane

Served on `[service].listen` (default `0.0.0.0:8080`).

| Method | Path | Purpose | CORS |
|--------|------|---------|----------|
| GET | `/` | Service directory: `{"services": {"beacon": "<aggregated prefix>", "fairdp": "/fairdp"}}` (`fairdp` only when `[fairdp]` is configured; the sensitive prefix is never listed) | yes¹ |
| GET | `{prefix}` , `{prefix}/info` | Beacon `BeaconInfo` (the root is the bare base path; the trailing-slash form is not a route) | yes (aggregated/combined) / no (sensitive)¹ |
| GET | `{prefix}/service-info` | GA4GH `ServiceInfo` | yes (aggregated/combined) / no (sensitive)¹ |
| GET | `{prefix}/configuration` | Beacon configuration, scoped to the mount | yes (aggregated/combined) / no (sensitive)¹ |
| GET | `{prefix}/entry_types` | Entry-type definitions | yes (aggregated/combined) / no (sensitive)¹ |
| GET | `{prefix}/map` | Beacon map | yes (aggregated/combined) / no (sensitive)¹ |
| GET | `{prefix}/filtering_terms` | Filtering terms (currently empty) | yes (aggregated/combined) / no (sensitive)¹ |
| GET, POST | `{prefix}/g_variants` | Genomic-variant query (aggregated/combined) | yes¹ |
| GET, POST | `{prefix}/datasets` | Dataset query (aggregated/combined) | yes¹ |
| GET, POST | `{prefix}/individuals` | Individuals placeholder (sensitive/combined) | yes (combined) / no (split)² |
| GET | `/fairdp` | FAIR Data Point root (RDF) | yes |
| GET | `/fairdp/` | `308 Permanent Redirect` to the FDP root | yes |
| GET | `/fairdp/catalog/{id}` | FDP Catalog record | yes |
| GET | `/fairdp/dataset/{id}` | FDP Dataset record | yes |
| GET | `/fairdp/distribution/{id}` | FDP Distribution record | yes |
| GET | `/.well-known/c4gh-recipient` | The node's crypt4gh recipient (PEM) | no³ |

¹ CORS (GET+POST, `content-type`) applies to the aggregated/combined beacon mount and the
FDP only. Every informational route above is mounted under *both* prefixes, so with the
default split prefixes the same path answers with CORS under `aggregated_base_path` and
without it under `sensitive_base_path` — hence the per-mount marker. `g_variants` and
`datasets` need no such marker because they exist only on the aggregated/combined mount,
as `individuals` exists only on the sensitive/combined one.
`[service].cors_allowed_origins` decides which origins it admits: empty, the
default, sends `Access-Control-Allow-Origin: *`; a non-empty allow-list of exact origins
(`scheme://host[:port]`) echoes the caller's `Origin` when it is on the list (with
`Vary: Origin`) and sends no `Allow-Origin` when it is not. The same policy governs every
public response, including the error responses synthesized outside the routed mounts (the
resilience `414`/`413`/`408`/`503`/`500` and the unmatched-path `404`), so a restricted
node does not leak a readable error body to an origin it refuses to serve. CORS is a
browser control, not an access control: it does not restrain `curl` or a server-side fetch.
² With the default distinct prefixes, `individuals` is served from a separate sensitive
mount that carries no CORS. Setting the two prefixes equal collapses the mounts into one
combined beacon, and `individuals` then carries CORS. ³ `/.well-known/c4gh-recipient` is
fetched by the provider tool, not by a browser.

- FDP routes content-negotiate on `Accept` and serve two forms: `text/turtle` (or its
  `application/x-turtle` alias) when offered, otherwise `application/ld+json`. Every other
  `Accept` — missing, `*/*`, `application/rdf+xml`, `application/n-triples` — gets JSON-LD
  with a `200`, never a `406`. There is no strict-negotiation opt-out. Every negotiated
  `200` carries `Vary: accept` — the redirect and the `text/plain` errors do not, having
  nothing negotiated to vary on — and the routes return `404` when `[fairdp]` is
  unconfigured.
- Every public-plane response carries `Cache-Control: no-store`. The beacon answers a
  disclosure-controlled query and the FDP record follows an operator overlay that can change
  between calls, so neither is safe for a shared cache to keep; a client that wants to avoid
  a re-query should hold the result itself rather than rely on an intermediary.
- `/.well-known/c4gh-recipient` returns the recipient as a PEM body
  (`Content-Type: text/plain; charset=utf-8`) plus an `X-C4GH-Recipient-Fingerprint`
  response header, so a re-wrapping operator can confirm the key without diffing the PEM.
  A keyless node answers `404`. The fingerprint is `sha256:<hex>`, the lowercase-hex
  SHA-256 of the raw 32-byte X25519 public key — the same value `identity list`,
  `identity init` and `rekey` print.
- A trailing slash is not a route, with one exception. `{prefix}/`,
  `/fairdp/dataset/{id}/`, `/fairdp/profile/service/` and every other slash-suffixed path
  answer `404` in their surface's dialect. `/fairdp/` instead answers
  `308 Permanent Redirect` with `Location: /fairdp`, so a harvester configured with the
  slashed source URL does not read the FDP's `404` as an empty FAIR Data Point and complete
  a green harvest with zero datasets. The redirect is present whether or not `[fairdp]` is
  configured, so it cannot be used to probe for the block.
- `/fairdp/profile/{service|catalog}` is unrouted (`404`): the `dct:conformsTo` profile
  markers are opaque and not served. Like every other unknown path under `/fairdp` it
  answers in the FDP's own dialect, a bare `text/plain` `not found`, not the Beacon
  envelope (see [Error responses](#error-responses)).
- Resilience envelope (public plane): a request target (path + query) over 8 KiB → `414`;
  a body over `[service].max_request_body_bytes` → `413`; a request over
  `[service].request_timeout_seconds` → `408`; load-shed past
  `[service].max_concurrent_requests` → `503`; a handler panic → `500`. Each is counted on
  `gdi_http_requests_rejected_total{reason}` and rendered in the dialect of the surface the
  request was for (see [Error responses](#error-responses)). `413` can only arise on a
  beacon `POST`, since the FDP is `GET`-only.
- The management plane carries the same timeout, load-shed and panic-catch, so a client of
  the state oracle must expect `408`, `503` and `500` there too. They are rendered as bare
  tower statuses rather than as `beaconErrorResponse`. `/health/live` and `/health/ready`
  are exempt from admission control alone: they skip the semaphore and the load-shed, so a
  saturated plane cannot make the kubelet evict a node that is serving correctly, but they
  keep the timeout and the panic-catch.
- Every public-plane response carries a server-generated `x-request-id`, and any inbound
  value is ignored. It also appears in the logs and in every JSON error body, so a client
  can quote it for correlation. On the responses that carry CORS it is listed in
  `Access-Control-Expose-Headers`, so a cross-origin browser client can read it.
- The management plane's traced routes carry one too, and that plane honours an inbound
  `x-request-id` and echoes it back, so an orchestrator can follow one request across the
  boundary. An inbound value is adopted only if it is 1–128 bytes of visible ASCII;
  anything else is replaced by a server-minted id rather than rejected. The planes differ
  because the public plane is internet-facing, where a caller-chosen correlation id is
  worse than none, while the management listener binds loopback by default.
  `/health/live`, `/health/ready` and `/metrics` sit outside that layer and carry no
  request id in either direction.
- Every public-plane response carries `X-Content-Type-Options: nosniff`, which prevents
  MIME-sniffing of the JSON, RDF and PEM bodies. The management plane does not.

## Beacon query behaviour

`{prefix}/g_variants`, `{prefix}/datasets`, and `{prefix}/individuals` accept the Beacon v2
query framework either as GET query-string parameters or as a POST JSON body
(`query.requestParameters` plus the `query.filters`, `query.pagination`,
`query.requestedGranularity` and `query.includeResultsetResponses` siblings).

The envelope fields live under `query`. Seven keys are read from `query.*`, the canonical
location: `includeResultsetResponses`, `requestedGranularity`, `testMode`, `pagination`,
`filters`, `requestedSchemas` and `datasetIds`. The same key nested inside
`query.requestParameters` is also honoured, and the `query.*` sibling wins when both carry
it. A key placed at the **top level**, as a sibling of `query` rather than a member of it,
is not the Beacon v2 location and is silently ignored, so a client asking for `ALL` or
`MISS` there gets the `HIT` default's hits-only shape. `filters` is the one exception: a
top-level `filters` is lifted so it can be rejected with the same `400` a canonical one
gets, because an ignored filter would let a client believe the result set was narrowed when
it was not.

The field semantics are the GA4GH Beacon v2 contract — consult the
[Beacon v2 spec (v2.2.0, the version this node pins)](https://github.com/ga4gh-beacon/beacon-v2/tree/v2.2.0)
([reference docs](https://docs.genomebeacons.org/)), not this doc. What follows is where
this node constrains or deviates from it.

- **Variant selectors:** `referenceName`, `assemblyId`, `start`, `end`, `referenceBases`,
  `alternateBases`, `variantType`, `variantMinLength`, `variantMaxLength`. Once any variant
  selector is present, `referenceName` is required. `assemblyId` is normalized to one
  canonical assembly (`GRCh38`/`hg38`/`b38`, and a GRC patch suffix such as `GRCh38.p13`
  folds to its stem, since a patch shares the primary assembly's coordinates), and a
  `referenceName` accession that contradicts it is `400`. The normalization does not cover
  versioned RefSeq assembly accessions such as `GCF_000001405.39`; those are `400`, so use
  the name forms.
- **`assemblyId` selects among the assemblies the node serves.** A dataset is only ever
  searched under its own assembly, which `/datasets` reports as `gdiDatasetInfo.assembly`,
  so a cross-assembly false hit is impossible. What the request's `assemblyId` selects:

  | Request | Response |
  |---|---|
  | omits `assemblyId`, one assembly among the visible datasets | `200`, searched under that assembly; the assumed value is echoed as `meta.receivedRequestSummary.assumedAssemblyId` |
  | omits `assemblyId`, several served | `400` — `assemblyId is ambiguous: this node serves several assemblies (…); name one in requestParameters.assemblyId` |
  | names a recognised assembly (`GRCh37`/`GRCh38` after synonym folding) that no visible dataset holds | `200` with `exists: false` and no `resultSets` — not a claim that any dataset was consulted |
  | names a value the normalization cannot resolve | `400` `unknown assemblyId` |
  | the node holds no visible dataset at all | `200`, `exists: false`, whatever `assemblyId` says |

  `assumedAssemblyId` is a node extension key, because Beacon v2 has no field for a
  server-filled value and the standard `requestParameters` echo types every entry as an
  object. It appears only when the node assumed the assembly.
- **Base characters.** `referenceBases` and `alternateBases` are validated to `ACGTN` only,
  a narrowing of the GA4GH pattern `^([ACGTUNRYSWKMBDHV\-\.]*)$`: an aggregated
  allele-frequency beacon stores concrete `ACGTN` alleles and cannot resolve an ambiguity
  code, so a non-`ACGTN` base is a `400`. `N` is accepted but matched literally, so
  `referenceBases: "N"` equals a stored `N` and nothing else. Query deletions and
  insertions with `variantType` (`DEL`/`INS`/`INDEL`), not with the empty-`alternateBases`
  form. Coordinates are non-negative and bounded to `2^31 − 1`.
- **The query span is capped.** A Range or Bracket query whose span exceeds
  `[beacon].max_query_span_bp` (default `10000000`) is a `400`
  (`query span exceeds the limit`), not a truncated `200`. A bracket's span is measured
  across its full reachable extent (`s_min` to `e_max`), not the width of either bracket,
  so two narrow brackets far apart are rejected on the distance between them. Sequence
  queries are exempt. The cap is a per-deployment availability control (`0` disables it)
  and is advertised on no endpoint, so split whole-chromosome scans into chunks rather than
  assuming a particular limit across a federation.
- **`variantType` is a small, allele-derived vocabulary.** The node classifies every stored
  variant from its `REF`/`ALT` alleles, after trimming the shared prefix and suffix, into
  exactly one of `SNP` (single-base substitution), `MNP` (equal-length multi-base
  substitution), `INS` (pure insertion), `DEL` (pure deletion) or `DELINS` (a complex,
  length-changing substitution, HGVS *delins*). It does not read a VCF `SVTYPE` and never
  stores structural types (`DUP`/`CNV`/`INV`/`BND`), which are dropped at ingest. A filter
  is normalized case-insensitively and accepts the synonyms `SNV`→`SNP`, `MNV`→`MNP`,
  `INSERTION`→`INS`, `DELETION`→`DEL`, `MIXED`/`COMPLEX`→`DELINS`. `INDEL` matches all
  three length-changing types (`INS`, `DEL`, `DELINS`), so a client using the GA4GH
  reference vocabulary still gets the expected result. Any other value is a `400` rather
  than a misleading `exists: false`.
- **`variantMinLength` / `variantMaxLength` bound the alternate-allele length.** The node
  filters on `len(alternateBases)`, so an SNV has length 1 and `variantMinLength=1`
  includes it. This matches the GDI reference beacon, so a length-filtered query returns
  the same variant set across a federation. The GA4GH v2.2 schema marks both parameters
  "without prescribed use".
- **`requestedGranularity`** ∈ `boolean | count | record`; when omitted it falls back to
  `[beacon.configuration].default_granularity`. An unknown value is `400`. Aggregate counts
  below `[beacon].min_allele_count` are suppressed, so a `count` or `record` response may
  omit low-frequency entries; when the floor suppresses any population of a variant the
  response collapses to the aggregate `Total` only, so a suppressed cell cannot be
  recovered by subtracting its siblings. The `datasets` listing is public registry metadata
  with no disclosure ceiling to lower, so it always serves `record`
  (`returnedGranularity: record`) while echoing the client's `requestedGranularity` in
  `receivedRequestSummary`.
- **`includeResultsetResponses`** ∈ `ALL | HIT | MISS | NONE`; omitted → `HIT`. Every
  dataset consulted for the query becomes a resultSet, either a hit (`exists: true`) or a
  per-dataset miss (`exists: false`, empty `results`). `HIT` returns only the hits, `MISS`
  only the misses, `ALL` both, `NONE` an empty `resultSets`. `responseSummary` reports the
  true aggregate regardless of the filter. An out-of-enum value is `400`. The applied value
  is echoed in `meta.receivedRequestSummary.includeResultsetResponses`, so the hit-only
  default is visible rather than inferred.
- **Pagination.** `skip` defaults to `0`; `limit` defaults to `[beacon].default_page_limit`
  (default `10`) and is clamped to `[beacon].max_page_limit` (default `1000`); `limit: 0`,
  Beacon's "unbounded" sentinel, is likewise clamped to the cap. The clamp is silent on the
  status line but not on the wire: `meta.receivedRequestSummary.pagination` carries the
  effective `skip` and `limit`. An operator may lower the cap — it is the query path's
  memory knob, see [deployment.md](deployment.md#resource-baseline) — so read the echo
  rather than assuming `1000` across a federation.

  **`skip` and `limit` apply per dataset, not across the response.** Each selected dataset
  becomes its own `resultSet` with its own `[skip, skip+limit)` window, and the response
  concatenates them, so a query matching *N* visible datasets returns up to `N × limit`
  entries while `meta.receivedRequestSummary.pagination.limit` echoes the per-dataset
  value. Size buffers and paging loops from `N × limit`, and scope a query to one dataset
  with `datasetIds` if you need a single bounded window. Beacon v2 does not define paging
  across `resultSets`; this is the GDI nesting's reading of it.
- **`filters` are rejected, not applied.** This beacon advertises no filtering terms
  (`/filtering_terms` is empty), so a non-empty `filters` selector on `g_variants` or
  `datasets` is a `400` (`filters are not supported…`) rather than a silently-unfiltered
  `200` the caller believes was narrowed. An empty or absent `filters` is a no-op. The
  `individuals` placeholder accepts a structural `filters` list as a no-op and does not
  echo it back: the vendored summary schema types `filters` items as strings while clients
  send objects, and the field is optional, so omitting it is conformant and matches
  `g_variants` and `datasets`, which never echo one either.
- **`testMode`** is accepted and is a no-op: the query is answered normally and the
  submitted flag is echoed in `meta.receivedRequestSummary.testMode` on every entry type. A
  non-boolean `testMode` is a `400`. Everything this node serves is public aggregate allele
  frequency data, which satisfies the vendored `$defs/TestMode` requirement that the
  instance "SHOULD use virtual or non-sensitive data". The echo is of the received flag;
  the node does not emit the optional top-level `meta.testMode`.
- **Unsupported query types → `400`.** `geneId` (Gene ID Query), `aminoacidChange` and
  `genomicAlleleShortForm` (Genomic Allele Query), and `mateName` (breakend) are valid
  Beacon v2 query types that this position-indexed beacon does not implement, so they are a
  `400` rather than a misleading `exists: false`, on both `g_variants` and `datasets`.
- **Bodies and content type.** On the POST surface a missing or wrong `Content-Type` is
  `415`. There is no `422`: a semantically-invalid query is a `400` `beaconErrorResponse`.
  A misplaced envelope — a bare top-level `requestParameters` with no `query` wrapper, or a
  non-object `query` — is a `400` on `g_variants` rather than a misleading empty-query
  `200`; a genuinely empty query (`{}`, `{"query":{}}`) is a `200`. `datasets` and
  `individuals` do not apply that check and read a bare top-level `requestParameters`
  leniently. A successful query is `200`, including an all-empty result; every error is a
  `beaconErrorResponse`.
- **Leniency.** Unknown or extra top-level and `requestParameters` fields are ignored, for
  forward compatibility; an accession-form `referenceName` (`NC_000003.12`) is accepted and
  matched, where the GA4GH reference implementation rejects it; and `requestedSchema` on
  the informational endpoints is accepted and ignored, since the node serves its single
  default schema.
- **`datasetIds` scopes the query.** A `datasetIds` array, placed under `query` or inside
  `requestParameters` (a comma-separated string on the GET surface), restricts the
  `g_variants` scan to the named datasets. An absent list scans every visible dataset. A
  requested id that is not currently visible, hidden or unknown, contributes no resultSet,
  so a dataset-scoped existence query never returns a hit from an out-of-scope dataset.

  Absent and submitted-but-empty differ. A `datasetIds` that is present but resolves to no
  usable id — `[]`, `[null]`, `[7]`, `""`, `","` — scopes the query to nothing and returns
  no resultSets; it does not fall back to every visible dataset. Collapsing the two would
  re-create the out-of-scope hit this field exists to prevent, invisibly at `boolean` and
  `count` granularity where only the OR-ed `exists` reaches the client.

### Example

A boolean query is `200`; an empty or no-match query returns `exists: false`. An empty
query carries no variant selectors, so no assembly is resolved for it. The wire envelope
conforms to the GA4GH `beaconBooleanResponse` schema, and `beaconId` and `returnedSchemas`
reflect the node's `[beacon].id` and pinned model:

```bash
curl '{base}/aggregated/beacon/v2/g_variants?requestedGranularity=boolean'
```

<!-- example:g-variants-boolean (verified against live output by tests/it/api_doc_routes.rs) -->
```json
{
  "meta": {
    "beaconId": "org.test.beacon",
    "apiVersion": "v2.2.0",
    "returnedGranularity": "boolean",
    "returnedSchemas": [
      {
        "entityType": "genomicVariant",
        "schema": "https://raw.githubusercontent.com/ga4gh-beacon/beacon-v2/v2.2.0/models/json/beacon-v2-default-model/genomicVariations/defaultSchema.json"
      }
    ],
    "receivedRequestSummary": {
      "apiVersion": "v2.2.0",
      "requestedGranularity": "boolean",
      "testMode": false,
      "includeResultsetResponses": "HIT",
      "requestedSchemas": [],
      "pagination": { "skip": 0, "limit": 10 }
    }
  },
  "responseSummary": { "exists": false }
}
```

A `record`-granularity hit additionally returns `response.resultSets[].results[]` with
`frequencyInPopulations` (allele counts and frequencies) — see the COVID query in the
[README's Quickstart 1](../README.md#quickstart-1--see-it-work).

#### The `frequencies[]` object

Each `frequencyInPopulations[].frequencies[]` entry (`crates/beacon/src/model.rs`
`Frequency`) carries one population's counts. `GoE` below is Genome of Europe, the
allele-frequency network this node's extension fields are shared with:

| Field | GA4GH / GDI | Source column | Presence |
| --- | --- | --- | --- |
| `population` | GA4GH-standard, required | `POPULATION` | always |
| `alleleFrequency` | GA4GH-standard, required | `AF` | always |
| `alleleCount` | GDI/`GoE` extension | `AC` | omitted when the source VCF carried no `AC` for the population |
| `alleleNumber` | GDI/`GoE` extension | `AN` | omitted when the source VCF carried no `AN` for the population |
| `alleleCountHomozygous` | GDI/`GoE` extension | `AC_Hom` INFO → parquet `AC_HOM` | omitted, never `0`, when that population's `AC_Hom` was absent from the source VCF, independently of `AC_Het`/`AC_Hemi` |
| `alleleCountHeterozygous` | GDI/`GoE` extension | `AC_Het` INFO → parquet `AC_HET` | as above, for `AC_Het` |
| `alleleCountHemizygous` | GDI/`GoE` extension | `AC_Hemi` INFO → parquet `AC_HEMI` | as above, for `AC_Hemi` |

Only `population` and `alleleFrequency` are part of the Beacon v2 default model; the five
count fields are the GDI/`GoE` network's permitted, non-portable extension. Every count
field is optional and an absent source value omits the JSON key rather than emitting `0`,
because `0` is itself a meaningful count — a population that exists but has no homozygous
carriers. The three genotype sub-counts
(`alleleCountHomozygous`/`Heterozygous`/`Hemizygous`) are withheld together, even when
present in the source, whenever serving one of them below `[beacon].min_allele_count` would
let a client recover a suppressed cell by subtracting sibling populations from `Total`;
`alleleCount`, `alleleNumber` and `alleleFrequency` are unaffected. Populations that
predate the `AC_Hom`/`AC_Het`/`AC_Hemi` VCF INFO fields carry none of the three keys, which
is a genuinely absent source column rather than a suppression.

### The `variation` object (VRS 1.3)

Each `results[]` entry is a Beacon v2.2.0 genomic variation record, the entity
`meta.returnedSchemas[].schema` names, carrying `variantInternalId`, `variation`,
`identifiers` and `frequencyInPopulations`. Its `variation` is a `LegacyVariation`:
`referenceBases`, `alternateBases`, `variantType`, and a `location` encoded per
[GA4GH VRS 1.3](https://w3id.org/ga4gh/schema/vrs/1.3/vrs.json), which the default model
`$ref`s. The wire values below come from the COVID sample dataset:

<!-- example:g-variants-variation (verified against live output by tests/it/api_doc_routes.rs) -->
```json
"variation": {
  "location": {
    "type": "SequenceLocation",
    "sequence_id": "refseq:NC_000003.12",
    "interval": {
      "type": "SequenceInterval",
      "start": { "type": "Number", "value": 45823239 },
      "end":   { "type": "Number", "value": 45823240 }
    }
  },
  "referenceBases": "T",
  "alternateBases": "C",
  "variantType": "SNP"
}
```

- **Every VRS class carries its `type`.** `SequenceLocation`, `SequenceInterval` and
  `Number` each declare `type` in their `required` set with `additionalProperties: false`,
  so an untyped location or interval matches no VRS class.
- **Coordinates are objects, not bare integers.** `interval.start` and `.end` are
  `oneOf [DefiniteRange, IndefiniteRange, Number]`, all objects, so read the coordinate
  from `interval.start.value`. They are 0-based half-open (`start` = VCF `POS - 1`, `end` =
  `start + len(referenceBases)`), so the example above is the single base at 1-based
  position 45 823 240.
- **`sequence_id` is a CURIE**, `refseq:{accession}` for the query's assembly and
  chromosome, and stays `snake_case` because it is a VRS key rather than a Beacon one. It
  is always present: ingest admits only GRCh37 and GRCh38 and only canonical contigs, and a
  dataset whose store disagrees with its manifest is served as a miss with an `error` log
  rather than as a location without its reference sequence. `identifiers.genomicHGVSId` is
  rendered from the same accession, so it is present on every served entry too.

### Error responses

Every query-semantic rejection on a beacon endpoint, and every resilience error
(`414`/`413`/`408`/`503`/`500`) on a request under a beacon prefix, uses the Beacon
`beaconErrorResponse` envelope: the same `meta` shape a success carries, plus an `error`
object whose `errorCode` is the originating HTTP status (`meta` abbreviated here):

```json
{
  "meta": { "beaconId": "…", "apiVersion": "v2.2.0", "returnedGranularity": "…", "returnedSchemas": ["…"], "receivedRequestSummary": { "…": "…" } },
  "error": { "errorCode": 400, "errorMessage": "unsupported parameter: geneId" },
  "requestId": "018f…"
}
```

The top-level `requestId` mirrors the `x-request-id` response header.

Three caveats on the envelope:

- **`405` is the exception.** A wrong method on a real route returns a bare status with an
  empty body and an `Allow` header, with no envelope and no `error` block. A conformant
  client cannot reach it on a valid operation, but a client that always parses the envelope
  body should special-case it.
- An unmatched path (`404`), and every resilience error the layers synthesize
  (`414`/`408`/`503`/`500`), answers in the dialect of the surface the request was for, so
  a mistyped path is told what it missed rather than handed a Beacon envelope for a FAIR
  Data Point typo:
  - **under a beacon prefix** (`{prefix}/nope`, `{prefix}/g_variants/extra`; and, for the
    resilience errors, the bare prefix itself — which is a route, not a `404`: `GET
    {prefix}` serves `BeaconInfo`, as the route table above says): the
    `beaconErrorResponse` envelope above, with `errorMessage`
    `no Beacon endpoint matches this path` for the `404`, and `request target exceeds the
    maximum length` / `request timed out` / `service overloaded` / `internal error` for the
    resilience errors. The two differ in `returnedSchemas`: a resilience error names that
    mount's primary entry type (`genomicVariant` on the aggregated or combined mount,
    `individual` on the sensitive mount), while the `404` carries an empty list, because a
    path that matched no route was interpreted as no entity. The field is still present and
    still conformant (`ListOfSchemas` sets no `minItems`), so a client must not index
    `returnedSchemas[0]` on a `404`;
  - **under `/fairdp`**: the FDP's bare `text/plain` — `not found`, or the same resilience
    messages — which is what an unknown catalog or a hidden dataset gets;
  - **anywhere else** (`/nope`, `/robots.txt`, `/fairdb`, a management path on
    the public listener): a neutral JSON body,
    `{"status": 404, "message": "no route matches this path", "services": {…},
    "requestId": "…"}` for the `404`, whose `services` is the same directory `GET /`
    serves, and `{"status": <code>, "message": "…", "requestId": "…"}` for a resilience
    error. It stays JSON so `requestId` can be injected, and it carries the public CORS
    policy.

  The surface is decided from the request path, matching at a segment boundary, so
  `/fairdpx` is not the FDP. A handler's own error response is never re-rendered, which is
  why a *routed* path never yields the neutral body even when it answers `404`:
  `/.well-known/c4gh-recipient` on a keyless node is the case to know, answering its own
  `404` as `text/plain` — `no crypt4gh recipient configured` — so a client must not assume
  a JSON body there. Its trailing-slash form `/.well-known/c4gh-recipient/` matches no
  route and does get the neutral JSON. Only the
  last two dialects are not the envelope, so a client that parses every error body as a
  `beaconErrorResponse` must key on the path it requested.
- **The error `meta` names the endpoint's entry type but not its granularity.**
  `returnedSchemas` names the schema of the entry type you called
  (`genomicVariant` / `dataset` / `individual`), except on an unmatched-path `404` where it
  is empty. `returnedGranularity` is always the `record` default on an error, since nothing
  was returned. Correlate an error by `error.errorCode` and `requestId` plus the endpoint,
  not by `meta.returnedGranularity`.

## FAIR Data Point (FDP) responses

The `/fairdp*` resources serve RDF (DCAT-AP + FDP-O), content-negotiated to Turtle or
JSON-LD. `/fairdp` is the FDP root, an `fdp-o:FAIRDataPoint` that `ldp:contains` each
configured catalog; `/fairdp/catalog/{id}`, `/fairdp/dataset/{id}` and
`/fairdp/distribution/{id}` are the `dcat:Catalog`, `dcat:Dataset` and `dcat:Distribution`
records beneath it. Only visible datasets appear. The root document is illustrative —
blank-node ids and triple order vary, so it is not byte-pinned; the shape is validated
against the `gdi-metadata` SHACL shapes by the harness in
[`conformance/`](../conformance/README.md):

```turtle
@prefix dct:   <http://purl.org/dc/terms/> .
@prefix dcat:  <http://www.w3.org/ns/dcat#> .
@prefix fdp-o: <https://w3id.org/fdp/fdp-o#> .
@prefix ldp:   <http://www.w3.org/ns/ldp#> .
@prefix foaf:  <http://xmlns.com/foaf/0.1/> .
@prefix vcard: <http://www.w3.org/2006/vcard/ns#> .
@prefix xsd:   <http://www.w3.org/2001/XMLSchema#> .

<https://node.example.org/fairdp>
    a fdp-o:FAIRDataPoint , fdp-o:MetadataService , dcat:DataService ;
    dct:title "GDI Estonia FAIR Data Point" ;
    dct:license <http://publications.europa.eu/resource/authority/licence/CC_BY_4_0> ;
    dct:language <http://publications.europa.eu/resource/authority/language/ENG> ;
    dct:conformsTo <https://node.example.org/fairdp/profile/service> ;
    fdp-o:conformsToFdpSpec <https://specs.fairdatapoint.org/v1.2/fdp-specs-v1.2.html> ;
    fdp-o:metadataIdentifier <https://node.example.org/fairdp> ;
    fdp-o:metadataIssued "2026-01-01T00:00:00Z"^^xsd:dateTime ;
    fdp-o:metadataModified "2026-01-01T00:00:00Z"^^xsd:dateTime ;
    dcat:endpointURL <https://node.example.org/fairdp> ;
    dct:publisher [ a foaf:Agent ; foaf:name "Example Organisation" ] ;
    dcat:contactPoint [ a vcard:Kind ; vcard:fn "GDI Estonia" ; vcard:hasEmail <mailto:gdi@example.org> ] ;
    ldp:contains          <https://node.example.org/fairdp/catalog/gdi-aggregated> ;
    fdp-o:metadataCatalog <https://node.example.org/fairdp/catalog/gdi-aggregated> .
```

`dct:conformsTo` points at `/fairdp/profile/service`, which is unrouted (`404`): the
profile marker is opaque, not a served document.

`dct:language` is the node-level `[fairdp].language`, an EU language-authority IRI
defaulting to English, and appears on all three record kinds — the root, every catalog and
every dataset. There is no per-dataset language: a node publishes in one.

## Management plane

Served on `[service].management_addr` (default `127.0.0.1:9090`). This plane carries the
hidden-dataset state oracle and operational metrics, so keep it off the public Ingress:
in-cluster binding plus a `NetworkPolicy`, or a host firewall on bare metal.

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/health/live` | Liveness (always `200`) |
| GET | `/health/ready` | Readiness and per-subsystem detail (`200` / `503`) |
| GET | `/version` | Build version (JSON) |
| GET | `/catalogs` | The configured catalogs (id + title) as plain JSON — the ids a package's `metadata.catalog` must name |
| GET | `/datasets/{id}/state` | One dataset's serving state, for any id including `hidden` and `error` |
| GET | `/datasets` | The whole dataset inventory — opt-in, present only with `[service].expose_dataset_list = true`, else `404` |
| GET | `/datasets/suppressed` | The datasets an operator is currently withholding — same flag and same disclosure class, else `404` |
| GET | `/stats/queries` | Per-dataset usage counters since boot — opt-in, present only with `[stats].enabled = true`, else `404` |
| POST | `/reload` | Re-read the config file, as `SIGHUP` does — opt-in, present only with `[control].enabled = true`, else `404` |
| POST | `/reconcile` | Run the `SIGUSR1` pass now — same opt-in flag; `202` |
| POST | `/log-level` | Flip diagnostic logging like `SIGUSR2`, with an auto-revert window — same opt-in flag |
| POST | `/datasets/{id}/reingest` | Clear one dataset's recorded source signature and run the reconcile pass now — same opt-in flag and same pacing clock as `/reconcile` |
| GET | `/metrics` | Prometheus exposition (present only when a recorder installed) |

The management plane carries no CORS and no beacon error envelope; a handler panic is a
bare `500`. High-frequency health probes are not traced.

**Where per-dataset facts live.** Anything keyed by dataset id — the state oracle, the
inventory, the usage counters — is a management-plane surface and never a `/metrics` label.
Metric labels stay bounded and content-free, because a scrape target is cheap to grant and
a dataset-id label would carry an enumeration of every id, hidden ones included, wherever
those series are shipped. Per-dataset counts therefore live on the flag-gated
`/stats/queries` route.

## Management response bodies

The management endpoints return small, fixed JSON documents rather than Beacon envelopes.
Error statuses are the exception: `GET /datasets/{id}/state` returns a bare `text/plain`
body on `400` and an empty body on `404`, and a handler panic is a bare `500`, so a
programmatic consumer should check the status code before parsing the body as JSON.

**`GET /version`** — build and version info, always `200` (values illustrative):

```json
{
  "service_version": "1.0.0-rc.1",
  "gdi_metadata_version": "<pinned gdi-metadata model version>",
  "git_sha": "<git commit, 12 hex chars; 'unknown' if no repository was reachable>",
  "build_epoch": "<Unix seconds; 'unknown' if no repository was reachable>"
}
```

Both provenance fields are strings, `unknown` included: `build_epoch` is not a number. See
[operating.md §18](operating.md#18-upgrades-version-skew-and-rollback) for how each is
resolved.

**`GET /catalogs`** — the configured catalogs, always `200`. The `[catalogs]` table as
plain JSON, sorted by id, read from the same `SIGHUP`-reloadable snapshot as the FDP root,
so the two cannot disagree. This is the surface an integrating system reads to learn which
catalog ids this node accepts at ingest; harvesters keep reading the FDP root. The body is
[`catalogs.schema.json`](catalogs.schema.json):

```json
{
  "catalogs": [
    {"id": "gdi-aggregated", "title": "Genome of Europe Aggregated Data"}
  ]
}
```

**`GET /health/ready`** — `200` when ready, else `503`. `draining` appears only while
shutting down; each subsystem is `ok`, `not-configured` or `unavailable`
(`not-configured` is never a failure) and `initial_reconcile` is `done` or `pending`. Shown
for a keyless, no-S3, no-Vault node:

> `draining` is not pollable: do not build a probe or dashboard on it. A shutdown stops
> the listener accepting new connections immediately, so a fresh connection during the
> drain is refused rather than answered `503 {"draining": true}`. Only a connection
> opened before the `SIGTERM` can observe the field, and only for the few milliseconds
> before it closes. For the same ordering reason `gdi_ingest_total{outcome="cancelled"}` is
> unscrapeable: the ingest drain runs after the management listener stops. Treat both as
> post-mortem log evidence, not as live signals.

<!-- example:health-ready (verified against live output by tests/it/api_doc_routes.rs) -->
```json
{
  "ready": true,
  "degraded": false,
  "subsystems": {
    "s3": "not-configured",
    "vault": "not-configured",
    "at_rest": "not-configured",
    "key_material": "ok",
    "initial_reconcile": "done"
  }
}
```

`at_rest` is the PME master key: `not-configured` unless `[vault].transit_key` is set, `ok`
when the key unwrapped this node's sentinel, and one of two distinct failures:

| value | meaning | what to do |
|---|---|---|
| `mismatch` | the configured Transit key can no longer decrypt data this node wrote (a replaced key, or a reset secrets backend) | recover the key ([operating.md §17](operating.md#17-disaster-recovery)). `pme reseal` refuses: the mismatch is real |
| `unverifiable` | the check could not be completed from local state — the sentinel is unreadable, unparseable, or names a scheme this build does not know | inspect the sentinel, then `pme reseal --yes`; if the scheme is unknown, deploy the newer binary |

Both gate `ready`, and they are reported separately because the operator's next step
differs. `at_rest` is separate from `vault` because in that state Vault is reachable and
answering, so reporting it under `vault` would misdirect triage at connectivity. Unlike a
dark provider bucket it does gate `ready`, because a node whose at-rest store is unreadable
would answer queries while every PME-backed read fails.

`degraded` is `true` whenever any configured subsystem reads `unavailable`, including the
per-bucket S3 health that does not gate `ready`. So `ready: true, degraded: true` means
"serving, but at least one provider bucket is dark, so the served view is incomplete". It
is always present, and it is not the complement of `ready`.

When `[[s3.buckets]]` is configured, `subsystems` also carries an `s3_buckets` object with
per-channel health (`ok` / `unavailable`), and `subsystems.s3` rolls them
up. S3 bucket health does not gate readiness: a degraded provider bucket reports
`unavailable` but the node stays `ready`, since it must not drop every other provider from
rotation. Alert on `gdi_s3_poll_errors_total` or `gdi_health_ready{component="s3"}`, not on
`component="overall"`.

The body also carries a top-level `s3_markers` object, present once at least one bucket has
reconciled: a per-channel `{ observed_marker, last_reconcile_at }` naming the
`_sync_marker.json` change-token the node last reconciled on, and when. This is the
read-side handoff ack. An orchestrator that writes a package, bumps `_sync_marker.json` and
`HEAD`s the marker to learn its new `ETag` can poll `s3_markers[channel].observed_marker`
until it equals that `ETag`, or wait for `last_reconcile_at` to advance past its write,
instead of using a blind timeout.

**`GET /datasets`** — the node's whole dataset inventory as a JSON array, `200`. Present
only when `[service].expose_dataset_list = true`; otherwise the route does not exist and
the plane answers `404`, so a consumer should treat it as best-effort and fall back to
per-id `state` polls. Each element is
`{id, state, channel, provenance, suppressed?, source_state?}`: the same objects
`dataset list --format json` prints, from the same collector. Unsuppressed rows omit
`suppressed` rather than emitting `null`. The route takes no query parameters and refuses
any with `400`, so a mis-spelled question cannot read as an authoritative answer.

`state` is the effective serving state: the source-declared state with any operator
override composed over it, and likewise the offboarding withhold for an orphaned channel
(one the status index still owns datasets for but the running configuration does not
declare; a bucket a config reload added counts as declared from the moment the reload
lands). It is the same answer `GET /datasets/{id}/state` gives, and the same rule the
node's own serving path applies. When an override has masked a different declared state,
`source_state` carries what the index recorded, so an `error` dataset that is also withheld
reports `state: hidden`, `source_state: error`; when nothing was masked the key is omitted.

The operator's suppression justification is not on this route, nor on
`dataset list --format json`, for the reason given under `GET /datasets/{id}/state` below.
A consumer needs *that* a dataset is withheld and in which mode.

The route reads the on-disk status index, as the CLI does, so a source-declared
`visible`↔`hidden` flip may lag by at most one reconcile. An operator override is composed
in on top of that index value, because the node never writes a withhold back to the index;
the override file is the durable record.

An override is applied from the node's in-memory set, not read from the store per request.
That set refreshes on reload (`SIGUSR1`) and on the periodic override reconcile
(`rescan_interval_seconds`, 600 s by default), so a `dataset hide` or `take-down` written
to the store can take that long to appear here. The same in-memory set gates what the
Beacon serves, so reading the store per request here alone would make this route report
`hidden` for a dataset the node is still answering. If you need an override applied now,
apply it with `SIGUSR1`; to read what the store holds independently of node state, use
`dataset list`.

**`GET /datasets/suppressed`** — the datasets an operator is currently withholding: same
array shape, same `[service].expose_dataset_list` flag, same audit event, `400` on any
query parameter. The plain listing structurally cannot answer this, because a `take-down`
erases the local copy and purges the status entry, so the dataset survives only as an
override; those rows are synthesized only for this route, so a completed erasure cannot
leak into the plain listing as merely "hidden". An orphaned channel's datasets, withheld by
configuration rather than by an override, are listed here too, with `source_state` set and
no `suppressed` key. A read failure is a `500` with a bare `text/plain` body, since the
underlying error can name a filesystem path this plane does not put on the wire.

**`GET /stats/queries`** — per-dataset usage counters, `200`. Present only when
`[stats].enabled = true`; otherwise the route does not exist and the plane answers `404`,
so a consumer should treat it as a capability to probe. The body is
[`query-stats.schema.json`](query-stats.schema.json):

```json
{
  "schemaVersion": 1,
  "startedAt": "2026-08-07T09:00:00Z",
  "asOf": "2026-08-07T12:34:56Z",
  "datasets": {
    "GDI-EE-EXAMPLE-1751234567890": {"consulted": 152, "hit": 37, "listed": 12, "fairdpReads": 9}
  }
}
```

The four counters are in memory and since process start, monotonic within a boot:

| Counter | Incremented when |
| --- | --- |
| `consulted` | the dataset was in the selection set of an answered `g_variants` query, at any granularity |
| `hit` | that same query matched this dataset (`exists` for this dataset, not the OR-ed answer) |
| `listed` | the dataset appeared in the served page of a Beacon `/datasets` response |
| `fairdpReads` | `/fairdp/dataset/{id}` or `/fairdp/distribution/{id}` was read; a catalog read is catalog-keyed and is not attributed to its datasets |

Not counted: a rejected query, which is rejected before dataset resolution and so carries
no dataset attribution (see `beacon_query_rejected` in the audit stream instead), the
`/individuals` placeholder, and the info, configuration, map and service-info routes.

`startedAt` is the boot identity, and it is what makes the endpoint pollable: counters
restart from zero when the process does, so a consumer differencing two snapshots must
compare `startedAt` first. Unchanged means `current − previous` is the traffic between the
polls; changed means the node restarted and the current values are the whole story. It is
process start, never config-reload time, so a `SIGHUP` leaves it alone. Entries for erased
datasets persist until restart, and hidden datasets appear here, the same disclosure class
as the state oracle on the same private plane.

**`POST /reload`** — re-read the config file. Present only when `[control].enabled = true`;
otherwise the route does not exist (`404`). Bodyless, so it cannot inject configuration, it
only tells the node to re-read its own already-trusted file, and idempotent, so it is safe
to retry.

It runs the same implementation `SIGHUP` runs: the reloadable subset (`[catalogs]` plus the
`[ingest]` writer allow-list), any added `[[s3.buckets]]` entry or changed bucket
credentials, and the PME DEK-cache flush. A change outside that subset is logged as
restart-only and not applied, exactly as with the signal.

The flush matters during an at-rest key revocation: it drops every cached plaintext DEK,
bounding revocation latency to the request rather than to the cache TTL, and it runs
whether or not the candidate config was accepted. Without `pods/exec` it is the only
non-disruptive way to get it — see `operating.md` §10 step 5.

What the endpoint adds over the signal is an answer:

```json
{"applied": true, "restart_required": false, "detail": "…"}
```

```json
{"applied": false, "reason": "invalid", "detail": "…"}
```

**Read `restart_required`, not `applied`.** `applied: true` only means the reloadable
subset was swapped in; the same file may also have changed something outside it. That is
the common case: every opt-in flag decides route mounting at boot, and every `endpoint`,
`bucket` or `prefix` edit re-points a keyspace, so all of them are restart-only.
`restart_required` is absent on a refusal, where nothing was applied at all.

`reason` is a closed set of two: `unparsable` (the file could not be read or parsed as
TOML) and `invalid` (it parsed but failed the same startup validation boot runs). Both are
`200`, because a refusal is an answer, the node is healthy, and the running config is
untouched. The underlying error is in the node's log rather than in the body, since it can
name filesystem paths this plane does not put on the wire.

Two other statuses: `429` with `Retry-After` inside the `[control].min_interval_seconds`
window (default `10`; a refused request does not restart the window), and `503` during the
boot window before the action is installed.

**`POST /reconcile`** — run the `SIGUSR1` pass now: reload and enforce the operator
suppression store and the node-local overlay overrides, drain queued `dataset reingest`
markers, rescan the inbox, and wake every bucket monitor. Same opt-in flag and same rate
limit as `/reload`; bodyless.

It answers `202 Accepted`, not `200`:

```json
{"started": true, "detail": "…"}
```

The pass is unbounded work — a full inbox rescan on a large node — so the response means
started, not finished. Poll `GET /datasets/{id}/state` for the effect, exactly as after a
`SIGUSR1`. This matters most for a withhold: `dataset hide` and `take-down` write a
suppression file, and nothing applies it until the next reconcile.

It cannot accelerate a deletion. A suspected mass removal is confirmed across polls
separated by at least one `marker_poll_interval` before anything is evicted, so calling
this endpoint in a burst neither confirms nor speeds up an eviction.

**`POST /datasets/{id}/reingest`** — clear one dataset's recorded source signature and run
the reconcile pass now: the HTTP twin of `dataset reingest <id>` for a bucket-owned id.
Same opt-in flag as `/reconcile`, and paced on that endpoint's clock, since it starts the
same pass. Bodyless; the id is the path.

It answers `202 Accepted`:

```json
{"cleared": true, "started": true, "detail": "…"}
```

`cleared` means the id's `last_seen_signature` is gone from the status index, so the S3
reconcile's same-ETag short-circuit no longer pins the unchanged package to its `error`.
`started` means the shared reconcile pass has been detached to wake the bucket monitors.
Poll `GET /datasets/{id}/state` for the effect. Nothing is written to the override store,
so it stays never-written-by-the-node and may be mounted read-only on a serving replica.

Other statuses: `400` for a malformed id; `404` for a well-formed id this node has no
status entry for, never seen or already erased, so there is no signature to clear; `409`
when clearing would change nothing — a live (`visible`/`hidden`) id is already served, an
inbox-owned id is restored with `dataset reingest <id>` on the host, and an `error` id with
no recorded signature re-ingests on its own. The three refusals are decided before the
pacing window is consumed. `429` with `Retry-After` applies inside the shared window, and
`503` before the reconcile action is installed, clearing nothing.

A data-fault error class (`invalid-manifest`, `invalid-parquet-schema`, `unsafe-archive`)
is not helped by this endpoint: those clear only on a changed package (`upload --replace`),
exactly as for the CLI.

**`POST /log-level`** — flip diagnostic logging, setting the node's own crates to `debug`,
exactly as `SIGUSR2` does. Bodyless and a toggle: on if it was off, off if it was on.

```json
{"verbose": true, "filter": "…", "reverts_in_seconds": 900, "detail": "…"}
```

The difference from the signal is the auto-revert: turning verbosity on schedules a return
to the boot-time level after `[control].log_level_revert_seconds` (default `900`). That
prevents `debug` being left on in production indefinitely and bounds the log-flood denial
of service someone reaching this plane could otherwise sustain. Turning it off by hand
cancels the pending revert, and re-arming supersedes it; a revert never overrides a later
decision, whichever trigger made it, so a `SIGUSR2` supersedes a pending revert exactly as
a second `POST /log-level` does. `reverts_in_seconds` is omitted when the call turned
verbosity off. These bodies are snake_case like the rest of the management plane, not
camelCase like the Beacon surface and `/stats/queries`.

**`GET /datasets/{id}/state`** — `200` for a known id, `400` malformed, `410` deleted,
`404` never ingested.

`410 Gone` is returned while a `deleted` tombstone sidecar for the id stands in the inbox:
the dataset existed, was erased, and any re-drop of it is actively suppressed. It is
distinct from `404` so that a client can tell "permanently refused" from "not picked up
yet". Removing the sidecar releases the id, and un-suppresses any package still sitting in
the inbox, after which the id answers `404` again. A sidecar that cannot be read at all,
truncated or not JSON, for an id the node is not serving is held as a tombstone too rather
than released: the tombstone is the erasure record, and a torn write must not turn `410`
into `404` and re-open ingest. Such a file is counted on
`gdi_state_sidecar_rejected_total{reason="unreadable"}`, and repairing or removing it
releases the id.

The body's required fields are `id`, `state`, `channel` and `provenance`. `channel` is the
source provenance, `inbox` or the owning bucket's name; `provenance` is the crypt4gh
writer-key provenance described below. `state` is the effective serving state, with any
active operator suppression composed over the declared state, so the body can never say
`state: "visible"` while carrying a `suppression` object beside it.

The optional fields:

| Field | Present when |
| --- | --- |
| `source_state` | an override masked a different declared state; it reports what the source resolved to |
| `error_message` | the dataset's ingest errored. An errored *and* suppressed id reads `state: "hidden"`, `source_state: "error"` with the class retained |
| `overlay_applied_at` | an operator metadata overlay (`{id}.metadata.json`) is applied; the value is its `dct:modified` stamp |
| `overlay_error` | the last overlay was rejected; one of `fetch`, `parse`, `validate` |
| `state_sidecar_error` | the last `{id}.state.json` was rejected; one of `unreadable`, `unrecognized` |
| `superseded_redrop_at` | a changed re-upload under this live id was ignored (RFC3339) |
| `stale` | the owning channel has been dark for longer than `[service].max_visibility_staleness_seconds` |
| `suppression` | an operator `dataset hide` or `take-down` override is active: `{mode, at}`, `mode` ∈ `hide` \| `remove` |
| `last_seen_signature` | the node has recorded a signature for the id |

Each is omitted, never `null` or `false`, when it does not apply. Four of them need more
than a row:

- `overlay_error = "parse"` also reports a node-local operator override (`dataset correct`)
  whose stored file is present but unparseable. That id keeps its last-good served metadata
  and is not reverted to the source, so this field is the only signal that the override
  store is degraded; treat it as an alert. The same case is counted as
  `gdi_overlay_apply_failed_total{channel="local-override",reason="parse"}`, so it is
  alertable without polling per id.
- `state_sidecar_error` is the visibility counterpart. A rejected visibility sidecar fails
  the dataset safe to `hidden`, so this field is what distinguishes a dataset an operator
  hid from one withdrawn from the public plane by a truncated or malformed sidecar write.
  Its counter is `gdi_state_sidecar_rejected_total{channel,reason}`.
- `superseded_redrop_at` is the only signal that a correction did not land. A live dataset
  is immutable, so re-uploading corrected bytes under the same id is quarantined or dropped
  and the entry stays `visible`. Clear it by re-issuing the correction as a `take-down`
  plus re-add, or under a new id.
- **Read `state` and `stale` together.** `state: "visible"` with `stale: true` means the
  node is not serving the dataset on the public plane, because it can no longer confirm the
  provider still publishes it. A consumer that ignores the field reports a withheld dataset
  as visible.

`last_seen_signature` is the opaque identifier of the artifact the node last processed
under this id: an S3 `ETag`, or an inbox package's content hash. It changes exactly when
the node has processed different bytes, which is how a client tells "the node has not
looked at my upload yet" from "the node looked at it and rejected it"; `deploy --wait` uses
it for that, because comparing `error_message` strings cannot distinguish a re-rejection
from the pre-existing error. **Compare it for equality only.** It is not a digest of the
dataset contents, its construction differs per channel, and nothing about its format is
stable.

The operator's justification for a suppression is not served here. It is free text that in
practice names people, and this plane is unauthenticated; read it from the override file,
the audit stream or `dataset list`. See [operating.md §12](operating.md#12-dataset-lifecycle-and-state-transitions)
for the CLI and the override's precedence over the source.

The example below is a dataset with a recovered writer key, no overlay and no suppression:

<!-- example:dataset-state (verified against live output by tests/it/api_doc_routes.rs) -->
```json
{
  "id": "GDI-EE-EXAMPLE-20260409143052837",
  "state": "visible",
  "channel": "inbox",
  "provenance": {
    "kind": "recovered",
    "fingerprints": [
      "sha256:59dea1f5d1b035cf30101bcec603973ded73f8727616b58b8912d38c66e4f022"
    ]
  },
  "last_seen_signature": "sha256:73ec88d6edd94412b2f35612903048abf5cac990b908d73e86fedd14757523b5"
}
```

`provenance` is the crypt4gh writer-key provenance recorded at ingest, tagged by `kind`:

| `kind` | meaning | `fingerprints` |
|---|---|---|
| `recovered` | the header yielded writer-key fingerprint(s) | present, non-empty |
| `plaintext` | an inbox staging dir with no crypt4gh envelope | absent |
| `recovery_failed` | a `.tar.c4gh` that published but whose header would not parse | absent |
| `unknown` | no successful ingest has recorded provenance for this id | absent |

The fingerprint is proof-of-possession, not an authenticated producer identity: anyone
holding the node's public recipient key can author a package under a fresh writer key of
their own. Whether the node gates on that key depends on `[ingest].writer_policy`:

| `writer_policy` | behaviour | what the fingerprint means to you |
|---|---|---|
| `off` (default) | the fingerprint is recorded, never enforced | an accountability record only — "which key wrote this?", after the fact |
| `warn` | a writer outside the channel's allow-list is logged and still ingested | as above, plus an operator-side signal |
| `enforce` | a writer outside the channel's allow-list is rejected (`error_message: writer-rejected`) | the producer is on the allow-list configured for that channel |

The allow-lists are per channel — `[ingest].inbox_allowed_writer_fingerprints` for the
local inbox, `allowed_writer_fingerprints` on each `[[s3.buckets]]` entry — so a key
legitimate for one provider does not authorise publishing as another. Under `off` or
`warn`, treat the fingerprint as trustworthy only when compared against an out-of-band
allow-list of known writer keys. Under `enforce` the node has already made that comparison.

**`error_message` vocabulary.** When `state` is `error`, `error_message` is one of a
closed, path-free set — the same strings that label the `gdi_ingest_total{error_class=…}`
metric — so a client may match on them exhaustively. The set is the `ErrorClass` enum in
`crates/core/src/error.rs`, held in sync with this table by a test that fails the build if
the two diverge:

| `error_message` | Cause |
| --- | --- |
| `invalid-config` | Service configuration failed startup preflight. |
| `invalid-manifest` | `manifest.json` failed schema, required-field or cross-check validation. Includes a `numberOfRecords` or `populations` mismatch, a wrong `manifestVersion`, a bad `mode` or `assembly`, or an unknown `config` key. |
| `invalid-parquet-schema` | The parquet payload failed schema or per-value validation. |
| `unsafe-archive` | A TAR or staging member failed the safety checks, or the package exceeded a size cap. |
| `unknown-catalog` | The manifest's `catalog` is not one the node is configured to accept. |
| `decrypt-failed` | crypt4gh decryption failed: no configured node identity decrypts the package, or it is corrupt or truncated. |
| `query-too-large` | A client request matched more than a configured limit. A client error surfaced on the beacon path, not an ingest state. |
| `resource-exhausted` | A server-side ceiling was full when the request arrived, currently the process-wide beacon query-memory budget. Surfaced on the beacon path as a `503`, never a 4xx, because the request may be well formed and retrying it later can succeed. Not an ingest state. |
| `writer-rejected` | The artifact's producer is not trusted for its channel under an `enforce` `[ingest].writer_policy`, so it is not published. Two shapes carry this class: a `.tar.c4gh` whose recovered crypt4gh writer key is not on the channel's allow-list, and an unidentified plaintext staging-dir drop, which carries no writer key at all and so can never be allow-listed. The class does not imply the artifact was encrypted. |
| `scrub-failed` | A stored dataset failed the at-rest store scrub: a PME (`PARE`) parquet did not decrypt or authenticate. Either the at-rest bytes were tampered with, or the key material that wrote them is gone. Distinct from `decrypt-failed`, which is the package envelope at ingest. Node-side, so it is drained at startup and re-attempted once the key is restored. |
| `internal-error` | A catch-all internal failure, including a transient infra fault such as Vault being unreachable, which the node retries rather than persists. |

## Standards conformance and known deltas

**Machine-readable contract, in lieu of OpenAPI.** The node ships no hand-maintained
OpenAPI document; for a GA4GH Beacon that would duplicate the upstream spec and drift. The
machine-readable contract is instead the set of schemas its responses are validated
against: the vendored GA4GH Beacon v2.2.0 JSON schemas under
[`conformance/ga4gh-beacon-v2/`](../conformance/ga4gh-beacon-v2) (requests, responses,
configuration) and
[`conformance/ga4gh-beacon-v2-default-model/`](../conformance/ga4gh-beacon-v2-default-model)
(the `genomicVariations` entity), with the [VRS 1.3](../conformance/ga4gh-vrs-1.3) schema
the latter `$ref`s, and the FAIR Data Point / DCAT SHACL shapes under
[`conformance/shapes/`](../conformance/shapes). Integrating clients should treat those
upstream schemas and shapes as authoritative; this document is the human-readable reference
on top of them.

**Beacon v2.** The public beacon targets the GA4GH Beacon v2 API, pinned to **v2.2.0** via
`[beacon].api_version`; the authoritative contract is the
[upstream spec](https://github.com/ga4gh-beacon/beacon-v2/tree/v2.2.0)
([reference docs](https://docs.genomebeacons.org/)), not this doc. The framework response
schemas are vendored verbatim (see `conformance/ga4gh-beacon-v2/VENDORED.md`). The node's
real `/info`, `/service-info`, `/configuration`, `/entry_types`, `/filtering_terms` and
`/map` responses, its `g_variants` boolean, count and record responses, and its
`beaconErrorResponse` are validated against those schemas, along with a `/map` crawl that
validates every advertised endpoint by entry type and every `g_variants` `results[]` item
against the default-model and VRS 1.3 entity schemas (see
[the `variation` object](#the-variation-object-vrs-13)). FAIR Data Point / DCAT output is
validated separately against the pinned `gdi-metadata` SHACL shapes — see
[`conformance/README.md`](../conformance/README.md). RDF is content-negotiated, so it is
not modelled as a JSON contract.

The following HTTP-surface deltas matter when integrating against the node.
Emitted-metric-signal deltas are operator-facing and live in
[operating.md §2](operating.md#2-reading-the-metrics) and
[§3](operating.md#3-alert-thresholds-quick-reference).

- **The public plane performs no authentication or authorization.** The aggregated Beacon
  and the FAIR Data Point are open, so that count, boolean and aggregate-record discovery
  need no credential. A production GDI deployment that needs registered or controlled
  access must front the node with an external LS-AAI/OIDC + REMS/DAC layer, either an
  Ingress OIDC proxy or an integrated back-office proxy. The node has no built-in auth and
  no sensitive tier.
- **`/info` carries the network-registry fields only when they are configured.**
  `alternativeUrl` (`[beacon].alternative_url`) and `organization.logoUrl`
  (`[beacon.organization].logo_url`) are optional `beaconInfoResponse` fields, and the node
  emits each key only when the config sets it; an unset field is absent, never `null`. The
  GDI allele-frequency network reads both, and a member that omits either has been observed
  to degrade the network's member listing rather than just its own entry. Queries still
  aggregate, so the symptom is easy to miss. Set both on any node that joins a network — see
  [deployment.md](deployment.md#registering-with-a-beacon-network).
- **The public plane has no admin or control surface.** Nothing on it triggers a re-ingest
  or otherwise mutates state, so the public surface cannot enumerate hidden datasets. The
  management plane is a different matter: behind `[control].enabled` it mounts four action
  endpoints — `POST /reload`, `POST /reconcile` (which drains queued re-ingest markers),
  `POST /log-level` and `POST /datasets/{id}/reingest` — documented in the management-plane
  section above. They are opt-in, off by default, bound to loopback by default,
  unauthenticated when enabled, and rate-limited; what keeps them safe is the bind address
  and the NetworkPolicy. Out-of-band re-ingest (see
  [operating.md §5](operating.md#5-forcing-a-re-ingest)) remains available and is the only
  route when `[control]` is off.
- **Per-IP rate limiting is the fronting Ingress's job, not the node's.** The node has a
  global concurrency cap and load-shed for resource protection, but no per-client rate
  limit, because the real client IP is known at the proxy rather than behind it. Configure
  per-IP throttling at the Ingress or reverse proxy. The node's own re-identification
  control is small-count suppression: set `[beacon].min_allele_count` to a non-zero floor.
  A `WARN` is logged at startup in every environment while it is `0`, because the
  aggregated `g_variants` plane is unauthenticated regardless of the `environment` label.
  Rate-limiting only slows probing; suppression prevents the leak.
- **Also set a per-source connection limit, which is a different directive.** A rate
  limiter counts requests, and the cheapest way to deny this node's public plane makes
  none: hold idle TCP sockets until the per-plane connection cap is reached. Ordinary
  clients then get connection resets, no rate counter moves, no `http_request` audit line
  is written, and the only signal is `gdi_http_connections_rejected_total{plane="public"}`
  climbing. The cap itself behaves correctly, so this is a gap in ingress configuration
  rather than in the node. Use `limit_conn` (nginx) or `maxConnectionsPerSource` and its
  equivalents (Traefik, HAProxy, Envoy) alongside the per-IP rate limit; neither
  substitutes for the other. Slowloris is fully handled: half-sent bodies fill
  `max_concurrent_requests`, ordinary clients get a clean `503`, and the node recovers the
  moment the sockets close.

## Dataset disclosure (`gdiDatasetInfo`)

Every `datasets` collection entry, and every `g_variants` `resultSets[]` entry whether a hit
or an `exists: false` miss, carries a GDI-namespaced `gdiDatasetInfo` object:

```json
{
  "id": "GDI-EE-EXAMPLE-…",
  "name": "…",
  "gdiDatasetInfo": {
    "assembly": "GRCh38",
    "populations": ["EE", "FI", "Total"],
    "minAlleleCount": 5
  }
}
```

Without it a beacon answer is ambiguous. A variant absent from a population may have been
suppressed rather than never observed, and a query against the wrong assembly matches
nothing; in both cases absence reads as zero. Carrying it on the query response, not only
on `/datasets`, is what makes a `0` self-describing: a client reading an `exists: false`
resultSet with `minAlleleCount: 5` knows the true count is bounded to `{0} ∪ [1, 5)`,
without a second call and without having to already know which dataset ids to look up.

- `assembly` — the only assembly this dataset is ever searched under. A `g_variants` query
  naming a different one never consults it, and is answered `exists: false` with no
  resultSet, so the miss cannot be mistaken for "consulted and not found". A query naming
  no assembly is answered under this one when it is the only one the node serves, and is
  `400` "ambiguous" when it is not.
- `populations` — the labels the dataset actually serves, after the build-time floor.
  Omitted, rather than empty, when a package predates the field. Verified at ingest against
  the `POPULATION` column of the parquet, exactly as `numberOfRecords` is, so a manifest
  claiming a population the data does not hold is rejected.
- `minAlleleCount` — the effective floor, `max(node, dataset)`. `0` means no suppression.

This is a dataset-level disclosure and never a per-result one: it rides on the resultSet,
which is the dataset, never on a `results[]` entry. Naming the floor says that thresholds
exist; flagging an individual suppressed row would reveal which variants have below-floor
cells, the fact the `Total`-collapse exists to hide. The value is query-independent, so a
suppressed and an absent dataset still assemble to a byte-identical `exists: false`
resultSet.

The beacon-v2 `Dataset` and `resultSet` schemas are both `additionalProperties: true`, so
the extension is additive and conformant on either, and `apiVersion` is unchanged.

## See also

- [operating.md §1 — Health and readiness endpoints](operating.md#1-health-and-readiness-endpoints) — probe wiring, readiness-drain semantics, what `200` and `503` mean.
- [operating.md §2 — Reading the metrics](operating.md#2-reading-the-metrics) and [§3 — Alert thresholds](operating.md#3-alert-thresholds-quick-reference) — the `/metrics` series and what to alert on.
- [operating.md §21 — Audit log](operating.md#21-audit-log) — which requests are audited, including the dataset-state oracle.
- [operating.md §12 — Dataset lifecycle and state transitions](operating.md#12-dataset-lifecycle-and-state-transitions) — the states behind `GET /datasets/{id}/state`.
- [`node.example.toml`](../node.example.toml) — the listener, mount-prefix, body-limit and timeout knobs referenced above.
