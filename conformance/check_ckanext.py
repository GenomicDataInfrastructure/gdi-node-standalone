#!/usr/bin/env python3
"""Consumer-compatibility check: does the node's FDP graph survive the reads the
userportal's DCAT consumer performs?

This is the nice-to-have conformance check, complementing ``check_fdp.py`` (pySHACL, the
must-have). pySHACL checks the shape; this checks what is actually read, catching
namespace and predicate mismatches a passing SHACL shape would not.

The deployed profile is ``fairdatapoint_dcat_ap``
(``ckanext.fairdatapoint.profiles.FAIRDataPointDCATAPProfile``), a subclass of
``euro_health_dcat_ap``'s ``EuropeanHealthDCATAPProfile``. It is what the userportal
configures (``setup_scheming.sh``'s ``ckanext.dcat.rdf.profiles`` and every
``harvest_sources.md`` entry's ``{"profile": "fairdatapoint_dcat_ap"}``), and it lives in
the harvester repository (``gdi-userportal-ckanext-fairdatapoint``), not in
``ckanext-dcat``. It adds tag validation, ``tags_translated`` sanitising and label
resolution on top of the parent's reads and overrides no predicate, so the parent's
predicate set below is the deployed one. A harvester bump therefore changes this profile
without touching the ``ckanext-dcat`` pin, which is why both refs are watched by
``vendored.sh pins`` (see ``conformance/README.md``).

In practice the rdflib mirror (tier 2) is what runs: the real ``ckanext-dcat``
``RDFParser`` needs full CKAN (``ckan.lib.helpers`` and friends) plus
``pkg_resources``, neither of which the isolated conformance venv provides, so tier 1
does not load here. The hand-mirror is therefore the live check, pinned to the fork the
userportal deploys, rather than a degraded stand-in. Tier 1 stays wired for a venv that
does carry full CKAN.

Two tiers, in order of fidelity:

1. Real parser (preferred): round-trip the union through
   ``ckanext.dcat.processors.RDFParser`` with the ``euro_health_dcat_ap`` profile. That
   is the deployed profile's parent, and the closest this venv can get: the subclass
   ships in ``ckanext-fairdatapoint``, which is not installed here (only ``ckanext-dcat``
   is pinned in ``requirements.txt``), and the reads under test are the parent's.
2. Best-effort fallback: when that import fails, parse the union directly with rdflib,
   mirroring the deployed profile's exact predicate reads — those of
   ``EuropeanHealthDCATAPProfile``, since the subclass adds none (DCAT-AP 3.0 core plus
   the ``healthdcatap:`` / ``dpv:`` predicate set) — and assert the same fields survive.
   It prints a ``[best-effort]`` note and the tier used.

Either way the assertions are the same consumer-facing fields: a ``dcat:Catalog``; each
``dcat:Dataset``'s ``dct:title``, ``dct:identifier`` and ``dct:language``; each
``dcat:Distribution``'s ``dcat:accessURL`` and ``dct:format``; and the healthdcatap fields
the profile reads (``healthdcatap:numberOfRecords``, ``healthdcatap:healthCategory``,
``healthdcatap:hdab``). Four of those — ``hdab``, ``numberOfRecords``, ``dct:language``
and ``dct:format`` — are mandated by no SHACL shape, so this check is their only
per-record cover.

Exit code: 0 on a successful parse or a clean skip, so a missing CKAN never hard-fails the
build (pySHACL is the gate); non-zero only when a field that should have survived the
parse is missing.

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


def _require_every(missing: dict[str, list[str]], total: int, tier: str) -> None:
    """Fail if any dataset is missing a consumer-facing field.

    The quantifier matters. An existential check over the whole graph would let a single
    surviving dataset with a ``dct:title`` vouch for every dataset, which is wrong for a
    consumer-compatibility check and worst exactly where this tier is the only cover:
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
    raise CheckFailure(
        f"[{tier}] consumer-facing field(s) absent per-dataset — {detail}"
    )


def try_real_parser(union_path: Path) -> bool:
    """Attempt the real ``ckanext-dcat`` ``RDFParser`` + health profile.

    Returns True if it ran (and the assertions passed); False if ``ckanext-dcat``
    cannot be wired up standalone (missing CKAN) so the caller should fall back.
    Raises :class:`CheckFailure` if it ran but an expected field was dropped.
    """
    try:
        from ckanext.dcat.processors import RDFParser
    # BLE001: the blind catch is deliberate. This probe must degrade to the best-effort
    # rdflib parse on any failure to wire up ckanext-dcat standalone: ImportError without
    # CKAN, but also the AttributeError/RuntimeError its plugin loader raises part-way in.
    # Narrowing it would turn a tier downgrade into a conformance-leg crash.
    except Exception as exc:  # noqa: BLE001  # pragma: no cover - depends on env
        print(
            f"[best-effort] real ckanext-dcat RDFParser unavailable ({type(exc).__name__}: {exc}); "
            "falling back to a direct rdflib consumer-parse."
        )
        return False

    # The deployed profile's PARENT: `fairdatapoint_dcat_ap` subclasses this one and
    # ships in `ckanext-fairdatapoint`, which this venv does not install (see the module
    # docstring). The predicate reads asserted below are the parent's either way.
    parser = RDFParser(profiles=["euro_health_dcat_ap"])
    parser.parse(union_path.read_text(encoding="utf-8"), _format="turtle")
    datasets = list(parser.datasets())
    _require(bool(datasets), "ckanext-dcat parsed zero datasets from the FDP graph")

    # Per-dataset, and each healthdcatap field separately: accepting `health_category OR
    # number_of_records OR hdab` as one flag would make this tier weaker than the rdflib
    # fallback below, which requires all three, so coverage would silently drop the day a
    # venv did carry full CKAN. Keep the two tiers asserting the same thing.
    missing: dict[str, list[str]] = {}

    def note(field: str, ident: str) -> None:
        missing.setdefault(field, []).append(ident)

    for ds in datasets:
        ident = str(ds.get("identifier") or ds.get("name") or ds.get("title") or "?")
        if not ds.get("title"):
            note("title", ident)
        if not ds.get("identifier"):
            note("identifier", ident)
        resources = ds.get("resources", [])
        if not resources or not all(
            r.get("access_url") or r.get("url") for r in resources
        ):
            note("accessURL", ident)
        # The CKAN-dict twins of the two predicates tier 2 checks below. Key names read
        # off the INSTALLED `ckanext/dcat/profiles/euro_dcat_ap_base.py`: the distribution
        # loop sets `resource_dict["format"]` from `_distribution_format`, and the dataset
        # list loop maps `dct:language` to `language`.
        # Weaker than tier 2's `dct:format` check: `_distribution_format` also populates
        # `format` from a `dcat:mediaType` fallback, so this passes on a distribution
        # carrying only mediaType. It is inert while tier 1 does not run; tighten it
        # against the installed profile's keys once a full-CKAN venv exists.
        if not resources or not all(r.get("format") for r in resources):
            note("format", ident)
        for key in ("language", "health_category", "number_of_records", "hdab"):
            if not ds.get(key):
                note(key, ident)

    _require_every(missing, len(datasets), "real parser")
    print(
        f"[real parser] ckanext-dcat euro_health_dcat_ap parsed {len(datasets)} dataset(s); "
        "title / identifier / accessURL / format / language / healthdcatap fields survived "
        "on every one."
    )
    return True


def fallback_direct_parse(g: Graph) -> None:
    """Direct rdflib parse mirroring the deployed profile's predicate reads.

    Asserts the same consumer-facing fields survive, using the exact predicates
    ``EuropeanHealthDCATAPProfile.parse_dataset`` reads (verified against the
    installed ``ckanext/dcat/profiles/euro_health_dcat_ap.py`` and ``euro_dcat_ap_3``).

    Pins: the deployed profile is ``fairdatapoint_dcat_ap`` from
    ``gdi-userportal-ckanext-fairdatapoint @ v1.6.12``, a subclass that adds tag sanitising
    and label resolution and overrides no predicate read, so this hand-mirror tracks its
    parent in the GDI fork ``gdi-userportal-ckanext-dcat @ v2.4.2`` (what the userportal
    deploys; ``requirements.txt`` pins the matching upstream base ``ckanext-dcat==2.4.2``
    for the optional real-parser tier). Both refs are watched by ``vendored.sh pins``,
    because a harvester bump can change the profile with the ``ckanext-dcat`` pin standing
    still.

    The parent ``euro_health_dcat_ap`` profile reads
    ``healthdcatap:{numberOfRecords,healthCategory,hdab}`` (namespace
    ``http://healthdataportal.eu/ns/health#``) and ``dpv:hasLegalBasis``
    (``https://w3id.org/dpv#``), plus the DCAT-AP core ``dct:title``, ``dct:identifier``
    and ``dcat:accessURL`` — the subset asserted below, checked against the fork's
    ``profiles/euro_health_dcat_ap.py`` at v2.4.2. Re-check this list when bumping, so the
    best-effort tier cannot drift from the deployed profile.
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

    _require_every(missing, len(datasets), "best-effort")

    # dpv:hasLegalBasis is read as dpv namespace, never healthdcatap.
    # It is optional per-dataset, so we only note its presence, not require it.
    legal = list(g.objects(predicate=DPV.hasLegalBasis))
    print(
        f"[best-effort] direct rdflib consumer-parse of {len(datasets)} dataset(s), "
        f"{len(catalogs)} catalog(s): title / identifier / accessURL / format / language / "
        "healthdcatap:{numberOfRecords,healthCategory,hdab} present on every dataset"
        + (f"; dpv:hasLegalBasis seen {len(legal)}x" if legal else "")
        + "."
    )
    print(
        "[best-effort] note: the standalone conformance venv has no full CKAN, so the actual "
        "ckanext-dcat RDFParser could not run; this mirrors its exact predicate reads instead."
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
        if try_real_parser(union_path):
            print("\nckanext-dcat consumer-compatibility: OK (real parser).")
            return 0
        g = Graph()
        g.parse(union_path, format="turtle")
        fallback_direct_parse(g)
        print("\nckanext-dcat consumer-compatibility: OK (best-effort fallback).")
        return 0
    except CheckFailure as exc:
        print(f"\nckanext-dcat consumer-compatibility FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
