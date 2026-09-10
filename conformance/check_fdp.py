#!/usr/bin/env python3
"""Out-of-band pySHACL conformance check for a crawled-and-unioned FDP graph.

It validates the node's real emitted output — one rdflib graph, produced by crawling the
live FDP the way the userportal harvester does and unioning every fetched Turtle
resource — against the two shape sets:

  (a) the FDP v1.2 root/Catalog shapes (``conformance/shapes/fdp/``) over the
      ``fdp-o:FAIRDataPoint`` root and ``dcat:Catalog`` records: the FDP structural
      conformance the gdi-metadata shapes do not cover (the bookkeeping triplet,
      ``dct:conformsTo`` / ``fdp-o:conformsToFdpSpec``, ``dct:isPartOf``,
      ``dcat:themeTaxonomy`` and so on);
  (b) the pinned gdi-metadata shapes (``conformance/shapes/gdi-metadata/``, Dataset /
      Distribution / Catalog / DataService and their AgentCreator / AgentHdab / Kind /
      Identifier dependencies) over the dataset, distribution, catalog and DataService
      records: the GDI field model.

Both sets validate the same unioned graph. SHACL only applies a shape to a node matching
the shape's target, so each layer is checked by the shapes that target it. The single
relaxation is ``dct:hasPart`` ``sh:minCount 0`` for empty catalogs, baked into
``fdp-catalog.ttl`` (see that file's header).

Exit code is non-zero on any violation; the full pySHACL report is printed.

Usage::

    python check_fdp.py <union.ttl>
"""

from __future__ import annotations

import sys
from pathlib import Path

from pyshacl import validate
from rdflib import Graph, URIRef

HERE = Path(__file__).resolve().parent
FDP_SHAPES = HERE / "shapes" / "fdp"
GDI_SHAPES = HERE / "shapes" / "gdi-metadata"

RDF_TYPE = URIRef("http://www.w3.org/1999/02/22-rdf-syntax-ns#type")

# A shared prefix preamble, prepended before the vendored shape files are concatenated.
# Some upstream gdi-metadata files use a prefix without declaring it (``Identifier.ttl``
# uses ``foaf:``) and rely on a sibling file that sorts earlier in the glob to have
# declared it, which makes correctness depend on alphabetical file order. Declaring the
# common prefixes up front makes the union order-independent without editing the
# byte-faithful vendored files: each file's own ``@prefix`` lines still appear after this
# and override these bindings for that file's triples, so this supplies only a fallback
# for an otherwise-undeclared prefix.
_SHARED_PREFIXES = """\
@prefix foaf: <http://xmlns.com/foaf/0.1/> .
@prefix dct: <http://purl.org/dc/terms/> .
@prefix dcat: <http://www.w3.org/ns/dcat#> .
@prefix sh: <http://www.w3.org/ns/shacl#> .
@prefix owl: <http://www.w3.org/2002/07/owl#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix skos: <http://www.w3.org/2004/02/skos/core#> .
@prefix adms: <http://www.w3.org/ns/adms#> .
@prefix vcard: <http://www.w3.org/2006/vcard/ns#> .
"""


def load_shapes(*dirs: Path) -> Graph:
    """Union every ``*.ttl`` under the given directories into one shapes graph.

    The files are concatenated (after a shared ``@prefix`` preamble — see
    ``_SHARED_PREFIXES``) and parsed as one Turtle document per call. The preamble
    makes prefix resolution independent of glob/sort order without patching the
    vendored files; each file's own ``@prefix`` lines still override it.
    """
    blob = (
        _SHARED_PREFIXES
        + "\n"
        + "\n".join(
            ttl.read_text(encoding="utf-8")
            for d in dirs
            for ttl in sorted(d.glob("*.ttl"))
        )
    )
    shapes = Graph()
    shapes.parse(data=blob, format="turtle")
    return shapes


def run(name: str, data: Graph, shapes: Graph) -> bool:
    """Validate ``data`` against ``shapes``; print the report; return conformance.

    ``inference="none"`` and ``advanced=True`` mirror how the node's output is consumed:
    no RDFS/OWL closure is assumed, because the node emits exactly what it serves, and the
    gdi-metadata shapes use SHACL-AF features (``sh:node`` over blank nodes, ``sh:in``
    lists).
    """
    conforms, _report_graph, report_text = validate(
        data_graph=data,
        shacl_graph=shapes,
        inference="none",
        advanced=True,
        meta_shacl=False,
        debug=False,
    )
    status = "CONFORMS" if conforms else "VIOLATIONS"
    print(f"\n===== {name}: {status} =====")
    if not conforms:
        print(report_text)
    return conforms


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <union.ttl>", file=sys.stderr)
        return 2
    union_path = Path(argv[1])
    if not union_path.is_file():
        print(f"union graph not found: {union_path}", file=sys.stderr)
        return 2

    data = Graph()
    data.parse(union_path, format="turtle")
    print(f"loaded {len(data)} triples from {union_path}")

    fdp_shapes = load_shapes(FDP_SHAPES)
    gdi_shapes = load_shapes(GDI_SHAPES)

    # Non-triviality guard: a SHACL run over an empty or under-populated data graph, or
    # against an empty shapes graph, reports CONFORMS vacuously, because SHACL only applies
    # a shape to a node matching its target and zero target nodes means zero violations.
    # Assert the union carries instances of every class the shapes target, and that each
    # shapes graph is non-empty, before trusting a CONFORMS verdict. Otherwise a broken
    # crawl, empty fixtures or a mis-globbed shapes directory prints CONFORMS while proving
    # nothing.
    if len(data) == 0:
        print(
            "FAIL: the union graph is empty (wrong path? broken crawl?)",
            file=sys.stderr,
        )
        return 1
    if len(fdp_shapes) == 0 or len(gdi_shapes) == 0:
        print(
            "FAIL: a shapes graph loaded 0 triples (no .ttl found / glob broke?)",
            file=sys.stderr,
        )
        return 1
    required_classes = {
        "fdp-o:FAIRDataPoint": URIRef("https://w3id.org/fdp/fdp-o#FAIRDataPoint"),
        "dcat:Catalog": URIRef("http://www.w3.org/ns/dcat#Catalog"),
        "dcat:Dataset": URIRef("http://www.w3.org/ns/dcat#Dataset"),
        "dcat:Distribution": URIRef("http://www.w3.org/ns/dcat#Distribution"),
    }
    missing = [
        name
        for name, cls in required_classes.items()
        if next(data.triples((None, RDF_TYPE, cls)), None) is None
    ]
    if missing:
        print(
            f"FAIL: the union has no instances of {missing} — a CONFORMS verdict over "
            "it would be vacuous (broken crawl / empty fixtures?)",
            file=sys.stderr,
        )
        return 1

    ok_fdp = run("FDP v1.2 root/Catalog shapes", data, fdp_shapes)
    ok_gdi = run(
        "gdi-metadata Dataset/Distribution/Catalog/DataService shapes", data, gdi_shapes
    )

    if ok_fdp and ok_gdi:
        print(
            "\nALL CONFORMANT (both shape sets, only the dct:hasPart minCount-0 relaxation)."
        )
        return 0
    print("\nCONFORMANCE FAILED — see the violation report(s) above.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
