#!/usr/bin/env python3
"""pySHACL a single rendered dataset graph against the gdi-metadata shapes.

Helper for the dual-encoding agreement test, which requires the Rust gate and pySHACL to
agree on every fixture. The Rust side renders one ``dcat:Dataset`` record (and its
blank-node sub-graph) to Turtle and feeds it here; this script validates it against the
pinned gdi-metadata shapes (``conformance/shapes/gdi-metadata/``) and prints a single
line:

    CONFORMS

or

    VIOLATES: <first violation message>

and exits 0 (conforms) / 1 (violates) / 2 (usage). The Rust test reads that verdict and
asserts it matches the Rust gate's accept/reject verdict for the same fixture, so a
divergence between the two encodings fails the build.

Only the gdi-metadata shapes run here, not the FDP root/Catalog shapes: a bare dataset
record has no root or catalog node for those to target, and the field-model rules
(cardinality, enum, pattern, uniqueLang) the negative fixtures break live entirely in the
gdi-metadata shapes.

Usage::

    python check_dataset.py <dataset.ttl>
"""

from __future__ import annotations

import sys
from pathlib import Path

from check_fdp import RDF_TYPE, load_shapes
from pyshacl import validate
from rdflib import Graph, Namespace, URIRef

HERE = Path(__file__).resolve().parent
GDI_SHAPES = HERE / "shapes" / "gdi-metadata"

DCAT_DATASET = URIRef("http://www.w3.org/ns/dcat#Dataset")


def load_gdi_shapes() -> Graph:
    """Concatenate + parse the gdi-metadata shapes.

    Delegates to ``check_fdp.load_shapes`` so both scripts load the vendored shapes one
    way. A second implementation here would have to repeat the shared ``@prefix``
    preamble, and omitting it parses only by glob order: ``AgentCreator.ttl`` sorts before
    ``Identifier.ttl`` and declares the ``foaf:`` prefix the latter uses without declaring.
    That is the dependence the preamble exists to remove.
    """
    return load_shapes(GDI_SHAPES)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <dataset.ttl>", file=sys.stderr)
        return 2
    data_path = Path(argv[1])
    if not data_path.is_file():
        print(f"dataset graph not found: {data_path}", file=sys.stderr)
        return 2

    data = Graph()
    data.parse(data_path, format="turtle")
    shapes = load_gdi_shapes()

    # Non-triviality guard (mirrors check_fdp.py): SHACL only applies a shape to a node
    # matching its target, so an empty shapes graph yields zero violations and pySHACL
    # reports conforms=True vacuously. Without this, a moved or renamed shapes directory,
    # or a broken glob, makes this script print CONFORMS for every fixture, the negative
    # ones included, while proving nothing. Fail loudly instead.
    if len(shapes) == 0:
        print(
            f"FAIL: the gdi-metadata shapes graph loaded 0 triples from {GDI_SHAPES} "
            "(no .ttl found / glob broke?) — a CONFORMS verdict would be vacuous",
            file=sys.stderr,
        )
        return 1

    # The data side of the same property. Every shape here targets dcat:Dataset, directly
    # or via sh:node from it, so a graph with no dcat:Dataset instance has zero target
    # nodes, yields zero violations, and reports conforms=True having validated nothing.
    # That matters because the caller (conformance_agreement.rs) compares this verdict
    # against the Rust gate's: a collapsed or mis-rendered graph would read as CONFORMS,
    # that is, as the two encodings agreeing, which is what this script exists to test.
    if next(data.triples((None, RDF_TYPE, DCAT_DATASET)), None) is None:
        print(
            f"FAIL: {data_path} carries no dcat:Dataset instance ({len(data)} triple(s)) "
            "— a CONFORMS verdict over it would be vacuous",
            file=sys.stderr,
        )
        return 1

    conforms, report_graph, report_text = validate(
        data_graph=data,
        shacl_graph=shapes,
        inference="none",
        advanced=True,
    )
    if conforms:
        print("CONFORMS")
        return 0

    # Surface the first violation message for a readable agreement-test diff.
    sh = Namespace("http://www.w3.org/ns/shacl#")
    msg = next(report_graph.objects(predicate=sh.resultMessage), None)
    print(f"VIOLATES: {msg if msg is not None else 'see report'}")
    print(report_text, file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
