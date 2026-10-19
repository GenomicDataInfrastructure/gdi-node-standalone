#!/usr/bin/env python3
"""Consumer-compatibility check: does the node's FDP graph survive the reads the
userportal's DCAT consumer performs?

Complements ``check_fdp.py``: SHACL checks the shape, this checks what the harvester
actually reads, which catches namespace and predicate mismatches a passing shape would not.

The deployed profile is ``fairdatapoint_dcat_ap``
(``ckanext.fairdatapoint.profiles.FAIRDataPointDCATAPProfile``), a subclass of
``euro_health_dcat_ap``'s ``EuropeanHealthDCATAPProfile``. Every userportal harvest source
names it (``{"profile": "fairdatapoint_dcat_ap"}`` in ``harvest_sources.md``; the harvester
ignores the global ``ckanext.dcat.rdf.profiles`` in ``setup_scheming.sh``), and it lives in
the harvester repository (``gdi-userportal-ckanext-fairdatapoint``), not in
``ckanext-dcat``. It adds tag validation, ``tags_translated`` sanitising and label
resolution on top of the parent's reads and overrides no predicate, so the parent's
predicate set below is the deployed one.

The real ``RDFParser`` needs a full CKAN install, so this check mirrors its predicate reads
in plain rdflib. The list was last checked on 2026-10-19 against the forks the userportal
then deployed (``gdi-userportal-ckanext-dcat`` v2.5.2,
``gdi-userportal-ckanext-fairdatapoint`` v1.7.3). CI does not watch them, so if a harvest
of this node loses a field, compare this list with the dcat fork's
``profiles/euro_health_dcat_ap.py`` and ``profiles/euro_dcat_ap_base.py``.

The assertions are the consumer-facing fields: a ``dcat:Catalog``; each
``dcat:Dataset``'s ``dct:title``, ``dct:identifier`` and ``dct:language``; each
``dcat:Distribution``'s ``dcat:accessURL`` and ``dct:format``; and the healthdcatap fields
the profile reads (``healthdcatap:numberOfRecords``, ``healthdcatap:healthCategory``,
``healthdcatap:hdab``). Four of those — ``hdab``, ``numberOfRecords``, ``dct:language``
and ``dct:format`` — are mandated by no SHACL shape, so this check is their only
per-record cover.

Exits 0 when every dataset carries every field, 1 when one is missing, 2 on bad
arguments.

Usage::

    python check_ckanext.py <union.ttl>
"""

from __future__ import annotations

import sys
from pathlib import Path

from rdflib import Graph, Namespace
from rdflib.namespace import RDF

DCAT = Namespace("http://www.w3.org/ns/dcat#")
DCT = Namespace("http://purl.org/dc/terms/")
HEALTHDCATAP = Namespace("http://healthdataportal.eu/ns/health#")
DPV = Namespace("https://w3id.org/dpv#")


class CheckFailure(Exception):
    """A field that should have survived the consumer parse is missing."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailure(message)


def _require_every(missing: dict[str, list[str]], total: int) -> None:
    """Fail if any dataset is missing a consumer-facing field.

    The quantifier matters. An existential check over the whole graph would let a single
    surviving dataset with a ``dct:title`` vouch for every dataset, which is wrong for a
    consumer-compatibility check and worst exactly where this check is the only cover:
    ``healthdcatap:hdab`` and ``healthdcatap:numberOfRecords`` are mandated by no SHACL
    shape, so nothing else in the suite looks at them. An existential check stays green
    until the field is stripped from every dataset at once.
    """
    if not missing:
        return
    detail = "; ".join(
        f"{field}: missing from {len(ids)} of {total} dataset(s) (e.g. {min(ids)})"
        for field, ids in sorted(missing.items())
    )
    raise CheckFailure(f"consumer-facing field(s) absent per-dataset — {detail}")


def direct_parse(g: Graph) -> None:
    """Direct rdflib parse mirroring the deployed profile's predicate reads.

    Asserts that every dataset carries the fields the module docstring lists.
    ``dpv:hasLegalBasis`` is optional, so it is only counted.
    """
    catalogs = list(g.subjects(RDF.type, DCAT.Catalog))
    _require(
        bool(catalogs), "no dcat:Catalog in the graph (consumer would harvest nothing)"
    )

    datasets = list(g.subjects(RDF.type, DCAT.Dataset))
    _require(bool(datasets), "no dcat:Dataset in the graph")

    # Every dataset must carry every field the profile reads. See `_require_every` for why
    # an existential quantifier is the wrong one here in particular: hdab and
    # numberOfRecords have no SHACL cover at all.
    missing: dict[str, list[str]] = {}

    def note(field: str, subject: object) -> None:
        missing.setdefault(field, []).append(str(subject))

    for ds in datasets:
        # DCAT-AP core reads.
        if next(g.objects(ds, DCT.title), None) is None:
            note("dct:title", ds)
        if next(g.objects(ds, DCT.identifier), None) is None:
            note("dct:identifier", ds)
        # Each distribution's accessURL (the profile reads dcat:distribution ->
        # dcat:accessURL). A dataset with no distribution at all would present the
        # consumer with nothing to fetch, so that is a miss too.
        dists = list(g.objects(ds, DCAT.distribution))
        if not dists or any(
            next(g.objects(dist, DCAT.accessURL), None) is None for dist in dists
        ):
            note("dcat:accessURL", ds)
        # `dct:format` on every distribution. `_distribution_format` unwraps an authority
        # IRI only from this predicate; with `dcat:mediaType` alone the raw IANA URL ends
        # up in the portal's `res_format` facet. Like hdab/numberOfRecords, no SHACL shape
        # mandates it, so this is its only per-record cover.
        if not dists or any(
            next(g.objects(dist, DCT["format"]), None) is None for dist in dists
        ):
            note("dct:format", ds)
        # `dct:language` on the dataset itself — the portal's `language` field.
        # Also uncovered by any shape.
        if next(g.objects(ds, DCT.language), None) is None:
            note("dct:language", ds)
        # healthdcatap reads.
        for label, pred in (
            ("healthdcatap:numberOfRecords", HEALTHDCATAP.numberOfRecords),
            ("healthdcatap:healthCategory", HEALTHDCATAP.healthCategory),
            ("healthdcatap:hdab", HEALTHDCATAP.hdab),
        ):
            if next(g.objects(ds, pred), None) is None:
                note(label, ds)

    _require_every(missing, len(datasets))

    # dpv:hasLegalBasis is read as dpv namespace, never healthdcatap.
    # It is optional per-dataset, so we only note its presence, not require it.
    legal = list(g.objects(predicate=DPV.hasLegalBasis))
    print(
        f"rdflib consumer-parse of {len(datasets)} dataset(s), "
        f"{len(catalogs)} catalog(s): title / identifier / accessURL / format / language / "
        "healthdcatap:{numberOfRecords,healthCategory,hdab} present on every dataset"
        + (f"; dpv:hasLegalBasis seen {len(legal)}x" if legal else "")
        + "."
    )


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <union.ttl>", file=sys.stderr)
        return 2
    union_path = Path(argv[1])
    if not union_path.is_file():
        print(f"union graph not found: {union_path}", file=sys.stderr)
        return 2

    try:
        g = Graph()
        g.parse(union_path, format="turtle")
        direct_parse(g)
        print("\nckanext-dcat consumer-compatibility: OK.")
        return 0
    except CheckFailure as exc:
        print(f"\nckanext-dcat consumer-compatibility FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
