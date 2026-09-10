# Vendored GA4GH Beacon v2 framework JSON Schemas

These `.json` files are vendored (copied verbatim) from the GA4GH `beacon-v2` framework,
the source of truth for the Beacon v2 *wire* response shapes (`beaconInfoResponse`,
`beaconConfigurationResponse`, `beaconResultsetsResponse`, `beaconCountResponse`,
`beaconBooleanResponse`, `beaconErrorResponse`, and the common, section and configuration
sub-schemas they `$ref`).

They are used only by the in-repo Rust test
`crates/gdi-node-standalone/tests/beacon_schema_conformance.rs`, which drives the node's
real `/info`, `/configuration` and `/g_variants` responses in-process and validates the
JSON bodies against these schemas. The node does not vendor, embed or serve these files in
the shipped binaries.

This is the hermetic Beacon wire-schema conformance gate: it runs with no binary install
and no network, closing the wire-schema misread gap the golden snapshots in
`crates/gdi-node-standalone/tests/beacon_info.rs` cannot. It is an ordinary `cargo test`
target, so it runs in the `rust` leg of `scripts/ci-local.sh`, which is the gate to run
before committing. An external GA4GH crawler, `beacon-verifier`, can cross-check a booted
node out-of-band, but is not a standing CI job. These files live next to the FDP shapes
under `conformance/` so all vendored conformance inputs share one home.

## Source

- **Repository:** `ga4gh-beacon/beacon-v2`
- **Path:** `framework/json/`
- **Tag:** `v2.2.0`
- **Commit:** `c6558bf2e6494df3905f7b2df66e903dfe509500` (2025-07-01)
- **Branch:** `main`

  That is the branch `scripts/vendored.sh drift` compares against, to ask whether upstream
  has moved. (`check` compares against the **Commit** above, which is immutable, so it can
  never answer that question.) A new *release* is watched separately, via the
  `EXTERNAL_PINS` entry on the GitHub releases API.
- **Files:** `36`
- **License:** CC0 1.0 Universal (public domain dedication) — see the upstream `LICENSE`.

`../ga4gh-beacon-v2-default-model/` is vendored from the same repository at this same
commit, from a different upstream path (`models/json/beacon-v2-default-model/`), which is
why it is a separate set: `scripts/vendored.sh` pins one path per set. Re-vendor the two
together. `check` compares each set against its own recorded commit, so bumping one and not
the other would pin them to different upstream states; both `check` and `verify` therefore
also compare the two `Commit:` pins to each other and fail if they differ.

## What was copied

The entire `framework/json/` schema tree except the `examples*/` directories (36 files):
the response schemas plus their `$ref` targets under `common/`, `responses/sections/` and
`configuration/`, and the `requests/` tree. The examples are illustrative documents, not
`$ref`-ed by any schema, so they are excluded.

### Five of the 36 are vendored for fidelity, not for validation

Reachability from the eleven root schemas `beacon_schema_conformance.rs` builds validators
for is 31 of 36. These five are loaded into the retriever map and never validated against
anything:

| File | Why it is here anyway |
|------|----------------------|
| `requests/beaconRequestBody.json` | The node validates **responses**; nothing `$ref`s the request tree from a response schema. |
| `requests/beaconRequestMeta.json` | ditto |
| `requests/filteringTerms.json` | ditto — the *response* side is `responses/sections/beaconFilteringTermsResults.json`, which is reached. |
| `endpoints.json` | Upstream's endpoint catalogue, not a schema. Carries its own inert `"version": "2.0.0"` (see the note below). |
| `common/ontologizedElement.json` | A common type no reached schema happens to `$ref`. |

Keeping them is deliberate: the vendored set is a byte-identical subtree of upstream, so
`scripts/vendored.sh check` is a clean directory diff rather than a comparison against a
hand-curated selection, and a curated set would have to be re-curated on every re-vendor.
They are covered by `SHA256SUMS` and the `**Files:**` count like everything else. Do not
tidy them away: the exact count is asserted by `load_schemas()`, which reads it from this
file.

## Integrity (`SHA256SUMS`)

`SHA256SUMS` in this directory pins the content of every vendored schema. The `**Files:**`
count above proves nothing was added or deleted; the manifest proves nothing was edited in
place. That distinction matters, because the conformance test is positive-only over most of
this tree: it asserts real responses conform, never that a malformed one is rejected.
Deleting a `"required"` array from a schema makes it strictly more permissive, so every
existing assertion still passes and the file count does not move. `scripts/vendored.sh
verify` checks both, offline, on every `ci-local.sh all`.

Do not hand-edit these files. Re-vendor with `scripts/vendored.sh fetch beacon`, which
regenerates the manifest, or run `scripts/vendored.sh sums` after a deliberate change and
review the hash diff next to the content diff.

The node's `[beacon].api_version` is pinned to `v2.2.0` to match this vendored framework
version. Re-vendor from a new tag and bump the `api_version` together, as a deliberate,
reviewed change — the wire contract is a stability surface.

## `$ref` resolution

The schemas declare draft 2020-12 and use relative cross-file `$ref`s (`../common/…`,
`./sections/…`, `../configuration/…`) and carry no `$id`, so a retrieved document's base
URI is the URI it was fetched from. The test preserves the directory layout above and
serves every file through a custom blocking `jsonschema::Retrieve` keyed by
`https://ga4gh.test/beacon-v2/<relpath>`, so the relative refs resolve to sibling files
deterministically, with no network.

## `endpoints.json`

`endpoints.json` is part of the upstream tree but is inert in this harness: it is not
`$ref`-ed by any vendored schema, and the test validates the node's `/map` against the live
response plus the `beaconMapSchema`, never against this file. It also self-declares
`"info": { "version": "2.0.0" }`, which is upstream's own value for that document and is
orthogonal to the pinned framework version (`v2.2.0`) and to the node's
`[beacon].api_version`; do not read it as the framework version. It is retained only to
keep the vendored `framework/json/` tree complete.
