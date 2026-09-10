# Vendored gdi-metadata SHACL shapes

These `.ttl` files are vendored (copied verbatim) from the GDI gdi-metadata repository,
which is the source of truth for the field set, cardinalities, controlled vocabularies and
the dataset-ID pattern. gdi-node-standalone implements its own Rust model of that and does
not vendor, embed or serve these files in the shipped binaries; they are used only by the
conformance gate, to validate the node's real output.

That gate is the `scripts/ci-local.sh conformance` leg, which is also part of
`scripts/ci-local.sh all`. Run it yourself after re-vendoring.

## Source

- **Repository:** `GenomicDataInfrastructure/gdi-metadata`
- **Path:** `Formulasation(shacl)/core/PiecesShape/`
- **Commit:** `3f1085db284c76367d508cc2db35ba58c90cac26`
- **Branch:** `main`

  That is the branch `scripts/vendored.sh drift` compares against, to ask whether upstream
  has moved. (`check` compares against the **Commit** above, which is immutable, so it can
  never answer that question.)

- **License:** Apache License 2.0, copyright Health-RI. Upstream is REUSE-compliant and
  keeps its licence texts in `LICENSES/` rather than a root `LICENSE`; each `.ttl` here
  carries its own `SPDX-FileCopyrightText` / `SPDX-License-Identifier` header, copied
  verbatim along with the file. `/LICENSES/Apache-2.0.txt` in this repository is the
  accompanying licence text that redistribution under Apache-2.0 § 4(a) requires.
- **Files:** `9`
- **`git describe`:** `1.1.0-14-g3f1085d`

## What was copied

| File | Shape(s) | `sh:targetClass` |
|------|----------|------------------|
| `Dataset.ttl` | `DatasetShape` | `dcat:Dataset` |
| `Distribution.ttl` | `DistributionShape` | `dcat:Distribution` |
| `Catalog.ttl` | `CatalogShape` | `dcat:Catalog` |
| `DataService.ttl` | `DataServiceShape` | `dcat:DataService` (the inline accessService and the `/fairdp` root) |
| `AgentCreator.ttl` | `AgentCreatorShape` | `foaf:Agent` (the `dct:creator`) |
| `AgentHdab.ttl` | `AgentHdabShape` | `foaf:Agent` (the `dct:publisher` / `healthdcatap:hdab`) |
| `Kind.ttl` | `KindShape` | `vcard:Kind` (contact points) |
| `Identifier.ttl` | `IdentifierShape` | `adms:Identifier` (the `otherIdentifier` blank node) |
| `Resource.ttl` | `ResourceShape` | `dcat:Resource` (stub) |

### Shapes that contribute no unique coverage

Three entries above are weaker than the table suggests. They are retained byte-faithfully
because these files are vendored rather than authored here, but do not read the table as a
coverage claim.

`Resource.ttl` is an intentionally vacuous stub. `ResourceShape` declares only a
`sh:targetClass` (`dcat:Resource`) with no property constraints, so it can never report a
violation. It is upstream's GDI v1.1 placeholder and contributes no active coverage to the
gate; its presence in the shape set does not mean Resource is validated.

`AgentCreatorShape` is fully subsumed by `AgentHdabShape`. Both declare `sh:targetClass
foaf:Agent`, and SHACL applies every shape whose target matches, so both run against every
`foaf:Agent` node regardless of the role it plays. The per-role reading in the table (the
`dct:creator` versus the `dct:publisher`/`hdab`) describes intent, not something SHACL
expresses: there is no `sh:targetSubjectsOf` or qualified-value scoping here. Since the two
declare identical constraints on `foaf:name` (`sh:minCount 1`, `sh:nodeKind sh:Literal`,
`sh:uniqueLang`), `AgentCreatorShape` enforces nothing `AgentHdabShape` does not.

That has a second-order effect on `check_fdp_negative.py`: because the duplication is
same-class rather than cross-class, `foaf:Agent` never appears in that script's
shared-mandatory reasoning, and relaxing one of the two shapes leaves the mandatory pair
derivable from its sibling. The `derived-mandatory.txt` snapshot is what catches that — a
relaxation changes the snapshot even when it does not change the verdict.

`CatalogShape#dcat:dataset` is a property shape with no constraint components. It carries
only `sh:name` and `sh:description` (`Catalog.ttl`), which are non-validating annotations,
so it can never report a violation, despite its own description asserting that a catalog
"contains one or more datasets". A catalog with zero `dcat:dataset` links conforms. The FDP
shapes cover the analogous structure via `dct:hasPart`, which is where the one deliberate
`sh:minCount 0` relaxation lives; see `../fdp/fdp-catalog.ttl`.

Similarly permissive, though not empty: `Dataset.ttl`'s `dcat:distribution` carries only
`sh:nodeKind sh:IRI`, so a dataset with zero distributions conforms, and
`healthdcatap:hdab`, `dcat:contactPoint` and `adms:identifier` are `sh:node`-only with no
`sh:minCount`. Nothing in SHACL requires `healthdcatap:hdab` or
`healthdcatap:numberOfRecords`, which is why `check_ckanext.py` checks both per dataset.

## Integrity (`SHA256SUMS`)

`SHA256SUMS` in this directory pins the content of every vendored file. The `**Files:**`
count above proves nothing was added or deleted; the manifest proves nothing was edited in
place, which is the direction that matters. Weakening an `sh:minCount` here keeps the file
count identical and makes every downstream check pass more easily, so only the checksums
can see it. `scripts/vendored.sh verify` checks both, offline, on every `ci-local.sh all`.

Do not hand-edit these files. To change them legitimately, re-vendor with
`scripts/vendored.sh fetch gdi-metadata`, which regenerates the manifest, or run
`scripts/vendored.sh sums` after a deliberate change and review the hash diff next to the
content diff. If you want to relax a constraint, do it in the in-repo `../fdp/` shapes
instead; those are authored here and are not covered by this manifest.

## `gdi_metadata_version` pin

The node pins the model as the build-time constant `gdi_metadata_version = "1.2.0"`
(`crates/core/src/lib.rs`). That tag is the gdi-metadata *model* version the node's static
mapping table targets; the vendored files above are the SHACL encoding of that model at the
recorded commit. Re-vendor from a new commit and bump the constant together, as a
deliberate, reviewed change — the wire contract is a stability surface.

### Provenance reconciliation

`git describe` resolves the vendored commit (`3f1085d`) as `1.1.0-14-g3f1085d`, while the
build constant targets `"1.2.0"`. This is not a content mismatch. Upstream, `1.1.0` and
`1.2.0` are both *lightweight* tags on the same commit (`1f03f33`), and the vendored commit
`3f1085d` is 14 commits ahead of that tag; it was upstream `master`/HEAD at vendor time.
`git describe` names the nearest *older* tag, which is why the prefix reads `1.1.0-…` even
though the model series is 1.2.0.

A `diff` of the checked-in `Dataset.ttl` against upstream `3f1085d` is empty: the vendored
files are byte-identical to that commit, so the pin is exact and re-vendoring from
`3f1085d` reproduces what is checked in.

The `contact-point`, `publisher`, `status` and `keyword` property shapes are present in the
vendored `Dataset.ttl`, both as `DatasetShape sh:property` references and as their shape
definitions. They were added upstream in the commits after the `1.2.0` tag and up to
`3f1085d` (`f856b25` reworked the contact point, `dc179e5` added `adms:status`), and
upstream's `CHANGELOG` still lists `adms:status` under `[Unreleased]`. The `1.2.0` *tag*
content is therefore a subset of the vendored files, not a superset: re-vendoring from the
`1.2.0` tag would drop those four constraints, which the conformance gate relies on. The
`"1.2.0"` constant names the upstream *model series*; the vendored snapshot is that series
at upstream HEAD (`3f1085d`), carrying the still-unreleased `adms:status` addition. Any
future re-vendor to a newer commit, plus the corresponding update to the Rust model,
fixtures and constant, should be done together as one tracked change.

## Standalone-parsing note

`check_fdp.py` and `check_dataset.py` load these files by concatenating them — after a
shared `@prefix` preamble (`_SHARED_PREFIXES` in `check_fdp.py`) — and parsing the result
as one Turtle document. The preamble exists because some upstream files use a `@prefix`
without declaring it (`Identifier.ttl` uses `foaf:`). Declaring the common prefixes up
front makes prefix resolution independent of glob and sort order without patching the
byte-faithful vendored files; each file's own `@prefix` lines still override the preamble
for that file's triples.
