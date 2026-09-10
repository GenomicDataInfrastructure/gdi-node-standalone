# Vendored GA4GH Beacon v2 default-model JSON Schemas

These `.json` files are vendored (copied verbatim) from the GA4GH `beacon-v2` default
model, the source of truth for the *entity* shapes a Beacon serves inside
`response.resultSets[].results[]`, as opposed to the *envelope* shapes vendored next door
in `../ga4gh-beacon-v2/` (the framework).

Only the `genomicVariations` entity is vendored, plus the two `common/` files it `$ref`s.
That is the entity this node serves, and `genomicVariations/defaultSchema.json` is exactly
the schema the node's own `meta.returnedSchemas[].schema` URL names, so validating against
it is validating against the contract the node advertises.

They are used only by the in-repo Rust test
`crates/gdi-node-standalone/tests/beacon_schema_conformance.rs`, which drives the node's
real `/g_variants` response in-process and validates every `results[]` item against
`genomicVariations/defaultSchema.json`. The node does not vendor, embed or serve these
files in the shipped binaries.

## Why this set exists

The framework's `responses/sections/beaconResultsets.json` constrains `results` as
`{"type": "array", "items": {"type": "object"}}`, so any object passes. Validating the
envelope alone therefore says nothing about the payload: a `variation.location` conforming
to no VRS 1.3 class — a bare-integer `interval.start`/`interval.end` with no `type`
discriminator on either the location or the interval — passes the framework schemas, while
a generated Java client that models the coordinate as an object cannot deserialise a bare
JSON number. Vendoring the default model is what turns "the payload is an object" into "the
payload is a GA4GH genomic variation".

## Source

- **Repository:** `ga4gh-beacon/beacon-v2`
- **Path:** `models/json/beacon-v2-default-model/`
- **Tag:** `v2.2.0`
- **Commit:** `c6558bf2e6494df3905f7b2df66e903dfe509500` (2025-07-01)
- **Branch:** `main`

  That is the branch `scripts/vendored.sh drift` compares against, to ask whether upstream
  has moved. (`check` compares against the **Commit** above, which is immutable, so it can
  never answer that question.) A new *release* is watched separately, via the
  `EXTERNAL_PINS` entry on the GitHub releases API — one watch covers this set and the
  framework set, since both are pinned to the same `beacon-v2` commit.
- **Files:** `3`
- **License:** CC0 1.0 Universal (public domain dedication) — see the upstream `LICENSE`.

Same repository and same commit as `../ga4gh-beacon-v2/`, in a separate directory because
`scripts/vendored.sh` pins one upstream *path* per set and the framework and the model are
different subtrees. Re-vendor the two together; `scripts/vendored.sh verify` fails if the
two `Commit:` pins differ.

## What was copied

The `genomicVariations` entity schema and the `common/` files it `$ref`s — a curated
subset, not the whole model tree:

| File | Why |
|------|-----|
| `genomicVariations/defaultSchema.json` | The entity the node serves; the schema its `meta.returnedSchemas[].schema` names. |
| `common/info.json` | `$ref`-ed by `defaultSchema.json` as `../common/info.json` (the `info` property). |
| `common/externalReference.json` | `$ref`-ed by `defaultSchema.json` as `../common/externalReference.json` (`Identifiers.variantAlternativeIds[]`). |

The rest of `models/json/beacon-v2-default-model/` (`individuals`, `biosamples`, `runs`,
`analyses`, `cohorts`, `datasets`, the other 20 `common/` files, and every `endpoints.json`
and `requestParameters*.json`) is not vendored: this node serves the aggregated
`genomicVariant` entity, and vendoring schemas nothing validates against would be unverified
weight. `scripts/vendored.sh check` compares the files that are here against upstream and
does not notice files upstream has that we do not, so picking a new one up is a deliberate
re-vendor decision, exactly as for the framework set.

Two `$ref` targets of `defaultSchema.json` live outside this directory and are therefore
not counted above:

- `https://raw.githubusercontent.com/ga4gh-beacon/beacon-v2/main/framework/json/common/ontologyTerm.json`
  — an absolute upstream URL, already vendored in `../ga4gh-beacon-v2/common/ontologyTerm.json`.
  The test's retriever serves the vendored copy under that absolute URL. Upstream writes
  `main`, not the pinned tag; the vendored copy is the one at the pinned commit, which is
  the stricter reading.
- `https://w3id.org/ga4gh/schema/vrs/1.3/vrs.json` — vendored in `../ga4gh-vrs-1.3/`, which
  has its own `VENDORED.md` (a different upstream repository).

## Integrity (`SHA256SUMS`)

`SHA256SUMS` in this directory pins the content of every vendored schema; the `**Files:**`
count above proves nothing was added or deleted. Both halves matter for the same reason
they do in the framework set: the conformance test is positive-over-live-output, so
deleting a `"required"` array — or the `oneOf` under `variation` — makes the schema strictly
more permissive while every assertion still passes at an unchanged file count.
`scripts/vendored.sh verify` checks both, offline, on every `ci-local.sh all`.

The behavioural half is `default_model_schema_rejects_the_pre_vrs_variation_shape` in
`beacon_schema_conformance.rs`: it feeds the schema a pre-VRS `variation` and requires a
complaint, so a gutted or mis-resolved schema graph fails loudly instead of silently
accepting everything.

Do not hand-edit these files. Re-vendor with
`scripts/vendored.sh fetch beacon-v2-default-model`, which regenerates the manifest, or run
`scripts/vendored.sh sums` after a deliberate change and review the hash diff next to the
content diff.
