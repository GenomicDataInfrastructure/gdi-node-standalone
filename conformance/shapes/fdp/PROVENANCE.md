# FDP v1.2 structural shapes — provenance and update procedure

These two SHACL files, `fdp-root.ttl` and `fdp-catalog.ttl`, are authored in-repo, not
vendored. Unlike the GA4GH Beacon schemas (`../../ga4gh-beacon-v2/VENDORED.md`) and the
gdi-metadata shapes (`../gdi-metadata/VENDORED.md`), which are copied verbatim from an
upstream repository at a pinned commit, these are hand-written here and have no upstream
file to re-sync from.

## What they are

The FDP-structural layer of the conformance gate: the mandatory FAIR Data Point
bookkeeping that the gdi-metadata field-model shapes do not cover.

- `fdp-root.ttl` → `<#FAIRDataPointShape>`, targeting `fdp-o:FAIRDataPoint` (the `/fairdp`
  root). Encodes the FDP v1.2 §4.2.1 mandatory property set.
- `fdp-catalog.ttl` → `<#FDPCatalogShape>`, targeting `dcat:Catalog`. Encodes the FDP v1.2
  §4.2.2 mandatory property set, with the single documented relaxation (`dct:hasPart`
  `sh:minCount 0`, so an empty catalog conforms).

Both run via `check_fdp.py`, alongside the gdi-metadata shapes, driven by the
`conformance_crawl` integration test. That test is `#[ignore]`d because it needs the Python
conformance venv, so it is exercised by the `conformance` leg of `scripts/ci-local.sh`,
which builds the venv and passes `--ignored`, and hence by `scripts/ci-local.sh all`. Run
that leg yourself after touching either shape.

Internals of the publisher (`foaf:Agent`) and contact point (`vcard:Kind`) are
intentionally not re-checked here: the gdi-metadata `AgentHdabShape` and `KindShape` target
those nodes by `rdf:type` over the same unioned graph.

## The two sources of truth

Each constraint is derived from, and traceable to, both of:

1. **The FDP v1.2 specification** — the normative property tables in §4.2.1 (FAIR Data
   Point / RepositoryMetadata) and §4.2.2 (Catalog):
   <https://specs.fairdatapoint.org/v1.2/fdp-specs-v1.2.html>. This fixes which properties
   are mandatory and at what cardinality.
2. **This repository's own FDP emitter** — `crates/fairdp/src/root.rs` (`fdp_root_graph`
   and `catalog_graph`) and `crates/fairdp/src/vocab.rs`. The shapes constrain only
   properties the emitter actually produces, so a shape never asserts something the node
   cannot serve, and never silently misses a property the node does serve. The
   `fdp-o:conformsToFdpSpec` marker value is the `FDP_SPEC_V1_2` constant in `vocab.rs`.

These shapes are not derived or copied from any node implementation, including any
deprecated reference node. The authoritative source for the FDP-structural requirements is
the published FDP v1.2 spec; the second input is this repo's own emitter. Do not
re-introduce a dependency on a reference-node implementation.

## How to update them

There is no re-vendor step. Update when either source of truth moves:

- **The FDP spec version changes** (a v1.3, say): re-read the new §4.2.1 and §4.2.2
  property tables, adjust the property set and cardinalities here to match, and update the
  `FDP_SPEC_V1_2` constant in `crates/fairdp/src/vocab.rs` — and so the emitted
  `fdp-o:conformsToFdpSpec` value — in the same reviewed change. Update the spec section
  references in the file headers and here.
- **The emitter changes** (`crates/fairdp/src/root.rs` starts emitting a new mandatory
  property, drops one, or changes a node kind or datatype): mirror the change here so the
  shape still validates exactly what the node serves.

Either way, prove the change with `scripts/ci-local.sh conformance` — that is the gate. The
raw invocation below runs the same harness, for iterating on one shape:

```bash
python3 -m venv .conformance-venv
# Install from the lockfile, not the .txt: it is hash-pinned, and `--require-hashes`
# refuses the install unless every transitive dependency is pinned too.
.conformance-venv/bin/pip install --require-hashes -r conformance/requirements.lock
GDI_FDP_PYTHON=$PWD/.conformance-venv/bin/python \
  cargo test -p gdi-node-standalone --test conformance_crawl -- --ignored --nocapture
```

That booted-node crawl asserts two things together:

1. **`check_fdp.py`** — the node's real emitted graph still conforms to these shapes, and
   to the gdi-metadata shapes.
2. **`check_fdp_negative.py`** — the shapes still discriminate. It mutates the live union,
   dropping one mandatory triple at a time, and requires pySHACL to reject the result. A
   shape that has gone vacuous, through a `sh:targetClass` typo for instance, is caught
   here rather than by the positive check.

A change that makes the positive check pass but the negative check fail has weakened the
gate: fix the shape, do not relax the negative.
