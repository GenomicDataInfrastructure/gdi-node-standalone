# Conformance harnesses (FDP + Beacon)

This directory holds the FDP out-of-band conformance harness (below) and the vendored
GA4GH Beacon v2 schemas: the framework (envelope) schemas under
[`ga4gh-beacon-v2/`](ga4gh-beacon-v2/VENDORED.md), the default-model (entity) schemas under
[`ga4gh-beacon-v2-default-model/`](ga4gh-beacon-v2-default-model/VENDORED.md), and the
[VRS 1.3](ga4gh-vrs-1.3/VENDORED.md) schema the model `$ref`s. All three are consumed by
the in-repo Rust test `crates/gdi-node-standalone/tests/beacon_schema_conformance.rs` (see
[Beacon wire-schema conformance](#beacon-wire-schema-conformance) at the end).

## FDP conformance

Out-of-band conformance for the node's real emitted FAIR Data Point output. These scripts
run in their own venv, isolated from the pure-Rust build, and are never shipped in either
binary. They carry all but one of the project's third-party Python dependencies: the
exception is `scripts/tests/k8s/`, which needs PyYAML to parse the Kustomize output it
guards and keeps its own hash-locked pin and its own `all`-only leg (`k8s-manifests`) for
exactly that reason. Everything else under `scripts/` installs nothing and runs under the
system `python3`. On the pre-commit path that is enforced rather than merely intended:
`scripts/tests/test_suite_is_stdlib_only.py` fails if any flat `scripts/tests/*.py` grows a
third-party import, and names `scripts/tests/k8s/` as the pattern to copy instead.

## What runs

The Rust integration test `conformance_crawl::fdp_union_conforms_to_shapes_and_consumer`
(in `crates/gdi-node-standalone/tests/`) ingests a small fixture corpus — 3 catalogs, one of
them empty, and 6 datasets: a fully-enriched one, a minimal one, one in a second catalog, a
multi-VCF one whose `numberOfRecords` is a build-time aggregate, a hidden one and an errored
one (the last two must not be reachable). It starts the FDP router and crawls the live FDP
the way the userportal harvester does: `GET /fairdp` with `Accept: text/turtle`, BFS over
`ldp:contains`, each catalog, dataset and `dcat:distribution` fetched separately, unioned
into `target/conformance/union.ttl`. It then runs:

- **`check_fdp.py <union.ttl>`** — the must-have gate: pySHACL over the unioned graph
  against two shape sets.
  - `shapes/fdp/` — the FDP v1.2 root/Catalog shapes, covering the FDP-structural
    conformance the gdi-metadata shapes do not. Authored in-repo from the FDP v1.2 spec
    and the `crates/fairdp` emitter; see
    [`shapes/fdp/PROVENANCE.md`](shapes/fdp/PROVENANCE.md).
  - `shapes/gdi-metadata/` — the pinned gdi-metadata Dataset / Distribution / Catalog /
    DataService shapes plus their AgentCreator, AgentHdab, Kind, Identifier and Resource
    dependencies (9 files), which are the GDI field model. Three of those contribute no
    unique coverage; `shapes/gdi-metadata/VENDORED.md` says which and why.

  The only `sh:minCount` relaxation is `dct:hasPart` `sh:minCount 0`, baked into
  `shapes/fdp/fdp-catalog.ttl`, so an empty catalog conforms. That file documents two
  deliberate deviations from the bare FDP §4.2.2 table; the second is
  `fdp-o:conformsToFdpSpec` demoted to a form-only check on Catalog (no `minCount`). A
  third form-only property shape, `fdp-o:metadataCatalog`, lives in `fdp-root.ttl`.
- **`check_fdp_negative.py <union.ttl>`** — negative meta-validation, also a must-have.
  It confirms the union conforms, then mutates it and requires pySHACL to reject each
  mutant. The mutation set is derived from the shapes: every predicate with
  `sh:minCount >= 1` is dropped union-wide, and a second pass drops each mandatory
  property from instances of its own `sh:targetClass` only. This proves the shapes
  discriminate; a positive-only check would still print `CONFORMS` when a `sh:targetClass`
  typo had silently disabled an entire shape.

  Three properties make that real rather than nominal.

  - **Rejections are attributed.** The per-class pass requires a violation on every
    mutated instance, carrying the dropped predicate as its `sh:resultPath` and the
    expected `sh:sourceConstraintComponent`. Asking only "did something reject this?" is
    not enough: the FDP root is typed both `fdp-o:FAIRDataPoint` and `dcat:DataService`,
    so a fully `sh:deactivated` `DataServiceShape` would still look rejected on its
    neighbour's violation.
  - **Value constraints are mutated too, not just presence** — all eight mutable kinds
    (`in`, `pattern`, `datatype`, `nodeKind`, `class`, `node`, `maxCount`, `uniqueLang`).
    Each kind gets its own strategy, because one generic substitution cannot isolate them:
    a probe breaking `sh:pattern` must keep the original term type and datatype, a probe
    breaking `sh:nodeKind` must be the wrong term type by construction, and
    `maxCount`/`uniqueLang` can only be violated by adding a value rather than editing one.
    Every violation must carry the matching `sh:sourceConstraintComponent`, so a mutation
    cannot pass because some other rule on the same predicate happened to fire. These are
    the rules carrying disclosure and identity meaning: `healthCategory`, `accessRights`,
    `conformsTo`, `adms:status`, the dataset-ID grammar and the contact-email format.
  - **The whole derivation is snapshotted.** Deriving the mutation set from the shapes
    means relaxing a constraint deletes the mutation that would catch it, silently, while
    staying green. `shapes/derived-mandatory.txt` records the complete set: predicates,
    `(class, predicate)` pairs, `(shape, class, predicate)` triples, and every declared
    constraint of any kind (`minCount`, `maxCount`, `datatype`, `nodeKind`, `pattern`,
    `uniqueLang`, `class`, `node`, `in`, with `sh:in` members sorted and joined so dropping
    one vocabulary member changes the line). Every run diffs against it, so a relaxation
    shows up as a deleted line in review. Regenerate it only when you mean to, with
    `python conformance/check_fdp_negative.py --write-snapshot`.

  The last two are a pincer, and neither alone suffices: mutation catches a constraint that
  is declared but not enforced, the snapshot catches one that is no longer declared, since
  a deleted `sh:pattern` generates no mutation to fail.

  A mandatory-presence constraint the union does not exercise is a failure, not a silent
  skip. A value constraint is reported and skipped, for one of two reasons the output
  distinguishes:

  - the property is optional and the corpus does not populate it (`dct:type`,
    `Distribution`'s `adms:status`). Closable by extending the corpus, at the cost of a
    fixture less like a real node.
  - the site is structurally unexercisable. Every remaining `sh:uniqueLang` skip is this:
    the node emits those paths as plain literals because the model behind them is a string,
    not a language map (`Agent.name` and `OtherIdentifier.name` for `foaf:name`, the
    catalog title and description, and the fixed `DataService` / `Distribution` titles). A
    literal with no language tag cannot violate `sh:uniqueLang`, so no output this node can
    produce would exercise the rule, and closing the gap would mean changing the wire model
    to suit a test. `dct:title` and `dct:description` on `dcat:Dataset` are the only
    localized paths, and both are exercised: the enriched corpus dataset is bilingual in
    both, while the minimal one stays plain so the `LocalizedText::Plain` render path is
    covered too.
- **`check_ckanext.py <union.ttl>`** — consumer compatibility, the nice-to-have check.
  The profile the userportal deploys is `fairdatapoint_dcat_ap`
  (`ckanext.fairdatapoint.profiles.FAIRDataPointDCATAPProfile`), which subclasses
  `euro_health_dcat_ap` to add tag validation, `tags_translated` sanitising and label
  resolution. It overrides no predicate read, so the parent's predicate set is the
  deployed one. It ships in the harvester extension
  (`gdi-userportal-ckanext-fairdatapoint`), not in `ckanext-dcat`, so a harvester bump can
  change the profile with the `ckanext-dcat` pin standing still; both refs are watched (see
  [Version pins](#version-pins)).

  The check prefers the real `ckanext-dcat` `RDFParser` on the parent profile, since the
  subclass's package is not installed in this venv and only the parent's reads are under
  test. The standalone venv has no full CKAN, so it degrades to a direct rdflib parse
  mirroring those exact predicate reads and prints a `[best-effort]` note. In practice that
  fallback is the live tier: `ckanext-dcat==2.4.2` installs, but importing it raises
  `ModuleNotFoundError: pkg_resources`, which the pinned interpreter's venv does not
  provide.

  Every field is required on every dataset, not merely somewhere in the graph. An
  existential check would let one healthy dataset vouch for all of them, which matters here
  because `healthdcatap:hdab`, `healthdcatap:numberOfRecords`, `dct:language` on a dataset
  and `dct:format` on every distribution are mandated by no SHACL shape. This check is
  their only per-record cover.

The dual-encoding agreement test
`conformance_agreement::{rust_gate_accepts_valid_rejects_negatives,
rust_gate_and_pyshacl_agree}` pins the Rust gate (`validate_package`) and pySHACL together
over `fixtures/`: a valid baseline and five negatives, each breaking one rule — two
missing-mandatory cases (`description` and `healthCategory`), a bad enum (`accessRights`),
a bad email pattern, and a `uniqueLang` collision.

Both sides read the same on-disk `package.yaml`: the Rust gate validates it directly, and
`Fixture::metadata()` parses it into `ManifestMetadata` to render the RDF that
`check_dataset.py` validates. A second, hand-authored Rust copy of each fixture would be
two independently authored artifacts, but the two encodings drift, and a coupling guard
comparing only the accept-or-reject verdict cannot see that drift: a dropped field just
stops being exercised on the Python side. Deriving one encoding from the other removes the
duplicate instead of guarding it, and loses nothing, because the YAML still exercises the
parse path and the struct still exercises the render path.

The test asserts pySHACL gives the same verdict as the Rust gate, and that its report names
the constraint the fixture is named after (`sh:in`, `sh:uniqueLang`, `gdi:KindShape`, and
so on) — agreeing on the verdict is not agreeing on the rule. A separate assertion pins
that the package validator and the overlay validator agree on the same fixture.
`ALL_FIXTURES` is also checked against the `*.package.yaml` files on disk, so adding a
fixture and forgetting its enum variant cannot silently shrink the corpus.

## Running locally

Run the leg — it builds the venv itself, from the hash-locked lockfile, on the pinned
interpreter:

```bash
scripts/ci-local.sh conformance
```

Most of the tests in these two binaries are not `#[ignore]` and run in the ordinary suite
(`cargo test -p gdi-node-standalone`); exactly one per binary needs the Python venv and is
marked `#[ignore]`. The leg asserts that count, so an un-ignored or renamed test cannot
silently stop being selected.

To drive the venv-gated pair by hand, point the test at an interpreter and run with
`--ignored`:

```bash
python3 -m venv .conformance-venv
# Install from the lockfile, not the .txt: it is hash-pinned, and `--require-hashes`
# refuses the install unless every transitive dependency is pinned too.
.conformance-venv/bin/pip install --require-hashes -r conformance/requirements.lock

# Either set GDI_FDP_PYTHON to the python binary, or GDI_FDP_VENV to the venv dir.
GDI_FDP_PYTHON=$PWD/.conformance-venv/bin/python \
  cargo test -p gdi-node-standalone --test conformance_crawl --test conformance_agreement \
  -- --ignored --nocapture
```

Note `.python-version` pins the interpreter these venvs must be built on (currently 3.14);
`ci-local.sh` warns when it cannot honour that, because a version-sensitive pySHACL result
would then differ from CI's.

You can also run a check by hand once a `union.ttl` exists:

```bash
.conformance-venv/bin/python conformance/check_fdp.py target/conformance/union.ttl
```

## Version pins

- **`gdi_metadata_version` = `1.2.0`** — the build-time constant
  (`GDI_METADATA_VERSION` in `crates/core/src/lib.rs`, reported by `--version`) recording
  the gdi-metadata model tag the node's static mapping table encodes. The vendored shapes
  under `shapes/gdi-metadata/` are that model; see `shapes/gdi-metadata/VENDORED.md` for
  the exact upstream commit they were copied from.
- **pyshacl / rdflib / ckanext-dcat** — pinned in `requirements.txt` and resolved into the
  hash-locked `requirements.lock` (regenerate both together with
  `uv pip compile --universal --generate-hashes`); bump them in a reviewed change.
  `ckanext-dcat` is pinned to `2.4.2`, the upstream base of the GDI fork the userportal
  deploys (`gdi-userportal-ckanext-dcat @ v2.4.2`, with harvester
  `gdi-userportal-ckanext-fairdatapoint @ v1.6.12`, per gdi-userportal-ckan-docker). The
  profile the deployment names is `fairdatapoint_dcat_ap`, supplied by the harvester ref as
  a subclass of the fork's `euro_health_dcat_ap`, so the `ckanext-dcat` pin alone would not
  see a profile change. That is why both refs are watched below. `check_ckanext.py` runs an
  rdflib hand-mirror of the inherited `euro_health_dcat_ap` reads, because the real
  `RDFParser` needs full CKAN and so never loads in this venv.
- **Guards on all of the above.** Which gate reaches each one differs, and the difference
  matters, so it is stated per guard rather than claimed for the list. The offline
  integrity of these files is fully covered by `scripts/ci-local.sh all`; the two guards
  that ask a question about *upstream* are not in it:
  - `vendored.sh verify` (network-free, in the `vendored_files` leg) — every vendored file
    still matches its `SHA256SUMS` entry and its set's declared `**Files:**` count. The
    count catches an added or deleted file; the checksums catch an in-place edit, which is
    the dangerous direction, because weakening a vendored `sh:minCount` or deleting a
    `"required"` array from a Beacon schema makes everything downstream pass more easily.
  - `vendored.sh pins` (network, in the `pins` leg). Under `all`, both an unreachable
    network and real drift warn and pass: drift here means the federation moved, not that
    this tree broke, so it is reported rather than fatal. `release` and `pins-strict` set
    `PINS_STRICT=1` and fail closed on drift. Four watches (`EXTERNAL_PINS`): the
    userportal's two deployed CKAN-extension refs, gdi-metadata's declared HealthDCAT-AP
    release, and the latest GA4GH beacon-v2 release tag — the only watch on a standard
    rather than on what the federation deploys. That last one reads the releases API,
    because a release is a tag and tags are in no file the repo contains: beacon-v2's own
    CHANGELOG tops out at `2.0.0` while the repo is tagged `v2.2.0`, so a file-based watch
    would be a dead guard. The same subcommand also runs `check_action_pins`, which is
    about this repo rather than the federation: it re-resolves every
    `uses: owner/repo@<sha> # <tag>` in the workflows and reports a SHA that no longer is
    that tag.
  - `pip-audit` (in the `supply_chain` leg) — the advisory scan for the one corner
    `cargo deny` cannot see. It audits the `.lock` files, not the `.txt`: pip-audit resolves
    a requirements file, and the loose `.txt` can resolve a newer version than the lock pins
    and the venv installs, so auditing it would report on a dependency set that is not the
    one installed. Like `cargo deny` and `pins`, it runs even on a gate short-circuit,
    because its verdict moves with the advisory database rather than with your tree.
  - `vendored.sh check` (network, byte-for-byte against the pinned upstream commit) — the
    integrity check: is our copy still faithful to what we pinned? It fetches each set at
    its pinned commit, an immutable SHA, so it stays green however far upstream advances.
    **Not in `ci-local.sh all`**, only in `release` and the weekly workflow. Unlike `pins`
    it cannot degrade to a warning: it folds an unreachable upstream into a failure by
    design, because a fetch that did not happen verified nothing, so putting it in the
    per-change gate would redden every offline run. What `all` gives up by omitting it is
    narrow — `verify` above already proves nothing in the tree was added, deleted or
    edited — leaving only the question of whether upstream still serves those bytes at that
    commit, which is a verdict about someone else's repository.
  - `vendored.sh drift` (network) — the question `check` cannot answer: has upstream moved?
    Same files, compared against the upstream branch (`**Branch:**` in each `VENDORED.md`).
    Exit 3 means upstream moved, which is news rather than a defect, since this tree is
    pinned. It is not in `ci-local.sh all`: it makes tens of network fetches, and a gate
    that reddens because someone else committed is one people learn to ignore.
  - Both are also scheduled weekly in `.github/workflows/scheduled.yml`, which runs on
    GitHub Actions (see [`CONTRIBUTING.md`](../CONTRIBUTING.md)). Two caveats. In a fork,
    scheduled workflows run only if the fork enables Actions, and GitHub disables a
    repository's schedules after 60 days of inactivity — so "weekly" is a claim about a
    live upstream, not a guarantee for every checkout. And a weekly verdict is not a
    pre-merge one: it tells you upstream moved, days after you merged. Run them by hand
    when you touch a vendored input: `scripts/vendored.sh check` and
    `scripts/vendored.sh drift`, or a full `scripts/ci-local.sh release`.

  One input has no automated watch: `shapes/fdp/` is hand-derived from the FDP v1.2
  specification document, and no watch on a spec document would be meaningful. See its
  `PROVENANCE.md`.

## Beacon wire-schema conformance

Unlike the FDP harness, this is a pure in-repo Rust test: no Python, no venv, no network,
no external binary. It runs as an ordinary `cargo test` target, picked up by the `rust` leg
of `scripts/ci-local.sh`, which is the gate to run before committing.
`crates/gdi-node-standalone/tests/beacon_schema_conformance.rs` drives the node's real
responses in-process — `/info`, `/configuration`, `/service-info`, `/entry_types`,
`/filtering_terms` and `/g_variants` (all four granularities plus the absent-variant miss
and the error envelope) — and crawls `/map`, GETting every advertised endpoint and
validating each JSON body against the vendored GA4GH Beacon v2 v2.2.0 framework schemas
under [`ga4gh-beacon-v2/`](ga4gh-beacon-v2/VENDORED.md). See that `VENDORED.md` for the
schema provenance and the `$ref`-resolution approach.

The framework schemas are the envelope only: `responses/sections/beaconResultsets.json`
constrains `results` as `{"type": "array", "items": {"type": "object"}}`, so any object
passes. `g_variants_results_conform_to_the_default_model_schema` closes that by validating
every `results[]` item against the vendored default-model `genomicVariations` entity schema
([`ga4gh-beacon-v2-default-model/`](ga4gh-beacon-v2-default-model/VENDORED.md)) and,
through its `$ref`s, [VRS 1.3](ga4gh-vrs-1.3/VENDORED.md). Without it, a
`variation.location` matching no VRS class passes the envelope check while a generated Java
client cannot deserialise the response at all.

Several things keep this from being a positive-only check, which schemas that constrain
nothing would satisfy:

- `vendored_schemas_reject_malformed_bodies` perturbs a known-good body at three depths and
  requires a complaint each time. A schema whose `required` arrays were lost accepts all
  three and, being more permissive, would keep every other assertion in the file green.
- `default_model_schema_rejects_the_pre_vrs_variation_shape` does the same for the entity
  half: it feeds the schema graph a pre-VRS `variation`, plus each of its three tags dropped
  individually, and requires a complaint each time.
- `every_root_schema_enforces_its_required_members` does the same in breadth over all ten
  root response schemas, reading each schema's own `required` list rather than hard-coding
  one, so it adapts to a re-vendor, and asserting that list is non-empty first. Together
  these make "the vendored tree still constrains things" a statement about the tree rather
  than about one file.
- The `/map` crawl runs over both an aggregated mount and a combined one, and pins which
  entry types each served. Without the combined mount, `individual` goes unvalidated:
  `covid_state` splits the mounts, so that arm is unreachable and one of the three GA4GH
  entry types sits outside the gate. Nothing advertised may refuse to serve — a non-200
  validates against the error schema, so tolerating refusals would let a test named "all
  conform" pass with half the advertised surface dead.

Each vendored set's file count is read from its own `VENDORED.md` rather than hard-coded, so
this test and `scripts/vendored.sh verify` cannot disagree about how many schemas exist.

An external GA4GH crawler (`beacon-verifier`) can cross-check a booted node out-of-band,
but is deliberately not a standing CI job: it adds no coverage this in-repo test lacks, and
the published tool is unmaintained.
