# Vendored GA4GH VRS 1.3 JSON Schema

`vrs.json` is vendored (copied verbatim) from the GA4GH Variation Representation
Specification (VRS), series 1.3 — the schema that defines `SequenceLocation`,
`SequenceInterval` and `Number`, which is the exact shape of `variation.location` inside a
Beacon v2 genomic-variation record.

It is here because the Beacon v2 default model `$ref`s it by absolute URL and does not
carry a copy: `../ga4gh-beacon-v2-default-model/genomicVariations/defaultSchema.json`
refers to
`https://w3id.org/ga4gh/schema/vrs/1.3/vrs.json#/definitions/{Location,MolecularVariation,SystemicVariation}`.
Without this file the default-model schema graph cannot be built offline at all, so the
conformance test would either need the network, which that hermetic gate does not allow, or
would have to skip the very subschema the node's `location` is validated against.

It is used only by the in-repo Rust test
`crates/gdi-node-standalone/tests/beacon_schema_conformance.rs`, whose retriever serves it
under the absolute `w3id.org` URI above. The node does not vendor, embed or serve it in the
shipped binaries.

## Source

- **Repository:** `ga4gh/vrs`
- **Path:** `schema/`
- **Origin URL:** `https://w3id.org/ga4gh/schema/vrs/1.3/vrs.json` — the URL the Beacon
  default model `$ref`s. It is a w3id.org permanent identifier that `302`-redirects to
  `https://raw.githubusercontent.com/ga4gh/vrs/1.3/schema/vrs.json`, which is what the pin
  below names. The copy here was fetched from the w3id URL and re-fetched from the pinned
  commit; both are byte-identical.
- **Commit:** `01b12e9440edd172762dd7d540f28e0a2f836a4e` (2024-08-12)
- **Branch:** `1.3`

  `1.3` is a maintenance *branch*, not a tag: upstream `main` is the 2.x line, so
  `scripts/vendored.sh drift` must compare against `1.3` or it would report permanent false
  drift against a schema series this file is not from. (`check` compares against the
  **Commit** above, which is immutable.)
- **Files:** `1`
- **SHA-256:** `f34241a13f6cb734685cacd899614f19b46e107397d10515f264e10361bd4515`
  (also in `SHA256SUMS`, which is what `scripts/vendored.sh verify` reads; repeated here so
  the provenance block is self-contained).
- **License:** Apache License 2.0 — see the upstream `LICENSE`. Upstream ships no
  `NOTICE` file. `/LICENSES/Apache-2.0.txt` in this repository is the accompanying
  licence text that redistribution under Apache-2.0 § 4(a) requires.

A separate directory from the two `beacon-v2` sets because `scripts/vendored.sh` pins one
upstream repository and path per set, and this is a different repository on a different
release cadence. VRS 1.3 is frozen: Beacon v2.2.0 pins the 1.3 series by URL, so this file
moves only if the `1.3` branch itself is amended.

## What was copied

`schema/vrs.json` only. The rest of upstream `schema/` — `vrs.yaml`, the source the JSON is
generated from, plus its `def/` fragments — is not vendored: nothing `$ref`s it, and the
JSON is the artifact the Beacon model points at.

`vrs.json` declares draft-07 (`"$schema": "http://json-schema.org/draft-07/schema"`) while
the Beacon schemas around it declare draft 2020-12, and it carries no `$id`, so the test
registers it under its `w3id.org` URI explicitly and lets the `jsonschema` crate pick the
dialect up from the document's own `$schema`. All of its `$ref`s are internal
(`#/definitions/…`), so this one file closes the graph.

## Integrity (`SHA256SUMS`)

`SHA256SUMS` pins the content and the `**Files:**` count pins the file set;
`scripts/vendored.sh verify` checks both, offline, on every `ci-local.sh all`. The direction
that matters here is an in-place edit: `SequenceLocation` and `SequenceInterval` both carry
`"additionalProperties": false` and a `required` array containing `type`, and deleting
either would let the node's pre-VRS `variation.location` validate again, at an unchanged
file count.

`default_model_schema_rejects_the_pre_vrs_variation_shape` in
`beacon_schema_conformance.rs` is the behavioural half of that guard: it requires the schema
graph to reject the old shape.

Do not hand-edit this file. Re-vendor with `scripts/vendored.sh fetch vrs`, which
regenerates the manifest, or run `scripts/vendored.sh sums` after a deliberate change and
review the hash diff next to the content diff.
