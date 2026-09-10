#!/usr/bin/env python3
"""Negative (meta-validation) conformance check for the FDP shapes.

``check_fdp.py`` proves the node's emitted FDP graph conforms. That alone cannot tell a
real shape set from a vacuous one: a typo'd ``sh:targetClass``, or an ``sh:minCount`` that
never fires, lets a malformed graph pass while the suite still prints ``CONFORMS``. This
script proves the shapes *discriminate*. It takes the same crawled union, confirms it
conforms, then mutates it four ways and requires pySHACL to reject each result, for the
right reason (see "Attribution" below):

1. drop each mandatory property union-wide;
2. drop it only from instances of the declaring shape's ``sh:targetClass``;
3. violate every value constraint — all eight mutable kinds (``sh:in``, ``sh:pattern``,
   ``sh:datatype``, ``sh:nodeKind``, ``sh:class``, ``sh:node``, ``sh:maxCount``,
   ``sh:uniqueLang``) — so each is proven to fire rather than merely to be declared. These
   carry the disclosure and identity meaning here: ``healthCategory``, ``accessRights``,
   ``conformsTo``, ``adms:status``, the dataset-ID grammar and the contact-email format.
   Each kind needs its own strategy and its own expected
   ``sh:sourceConstraintComponent``: see :func:`_probe_for`;
4. diff the whole derived constraint set against a committed snapshot, which is what
   catches a constraint that was deleted rather than merely stopped firing.

(3) and (4) are a pincer: mutation catches "declared but not enforced", the snapshot
catches "no longer declared". Neither alone is enough — a deleted ``sh:pattern`` generates
no mutation to fail, and an ``sh:deactivated`` shape keeps every snapshot line intact.

The mutation set is derived from the shapes themselves — every property shape with an
``sh:minCount >= 1`` or a value constraint, across both the FDP and gdi-metadata shape
sets — rather than from a hand-maintained predicate list, which rots as constraints are
added. Add a constraint to any shape and it is covered here automatically.

A predicate a shape mandates but the crawled union does not contain (a shape whose target
class the fixtures never exercise) is a failure, not a silent skip: an untested constraint
shrinks coverage as surely as a relaxed one, reached from the data side instead of the
shape side. A *value* constraint on an optional property the corpus does not populate is
reported and skipped, because requiring those would force the corpus to carry every
optional field.

**(4) The snapshot closes the circularity.** Deriving the mutation set from the shapes
makes the set of things tested a function of the thing being tested: relax an
``sh:minCount`` and you get one fewer test and a green run, not a failing test. Detecting
"this shape got weaker" needs a reference outside the shape, so :data:`SNAPSHOT_PATH`
records the complete derived set and every run diffs against it. A relaxation then shows
up as a deleted line in review instead of as silence. The snapshot is a second copy of a
fact, which is usually worth deleting rather than adding; here the duplication is the
point, because the property being checked is that the first copy has not changed.
Regenerate it with ``--write-snapshot`` when you intend the change.

**Attribution.** Asking only "did *something* reject this?" is not enough, because an
unrelated shape can supply the rejection: the FDP root is typed ``fdp-o:FAIRDataPoint``,
``fdp-o:MetadataService`` and ``dcat:DataService``, so dropping ``dct:title`` from every
``dcat:DataService`` instance also strips it from the root, where ``FAIRDataPointShape``
fires. The per-class pass therefore requires a violation on every mutated instance,
carrying the dropped predicate as its ``sh:resultPath``. If a shape targeting class C
mandates P, then dropping P from all instances of C must flag all of them; if only some
are flagged, another shape is doing the work and C's own shape is not discriminating.

Like ``check_fdp.py``, the negatives are built from the live union rather than from
hand-maintained ``.ttl`` blobs, so they track the real emitted model.

Usage::

    python check_fdp_negative.py <union.ttl>
    python check_fdp_negative.py --write-snapshot     # after a deliberate shape change
"""

from __future__ import annotations

import sys
from pathlib import Path

from pyshacl import validate
from rdflib import Graph, Literal, URIRef
from rdflib.namespace import XSD

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
# E402: this import must follow the sys.path insert above — check_fdp is a sibling
# script, not an installed module, so it is unimportable until HERE is on the path.
import check_fdp  # noqa: E402

SH = "http://www.w3.org/ns/shacl#"
SH_PATH = URIRef(SH + "path")
SH_MIN_COUNT = URIRef(SH + "minCount")
SH_PROPERTY = URIRef(SH + "property")
SH_TARGET_CLASS = URIRef(SH + "targetClass")
SH_RESULT_PATH = URIRef(SH + "resultPath")
SH_FOCUS_NODE = URIRef(SH + "focusNode")
SH_VALIDATION_RESULT = URIRef(SH + "ValidationResult")
SH_SOURCE_COMPONENT = URIRef(SH + "sourceConstraintComponent")
SH_IN = URIRef(SH + "in")
SH_PATTERN = URIRef(SH + "pattern")
RDF_TYPE = URIRef("http://www.w3.org/1999/02/22-rdf-syntax-ns#type")

# The constraint components a violation can be attributed to. Pinning the COMPONENT (not
# just the path) is what stops a mutation from being "caught" by a different rule on the
# same predicate — substituting a value can trip `sh:datatype` or `sh:nodeKind` instead of
# the `sh:pattern` the mutation was aimed at, and a path-only check cannot tell.
MIN_COUNT_COMPONENT = URIRef(SH + "MinCountConstraintComponent")

# The constraint kinds a VALUE mutation can target, each with the `sh:` predicate that
# declares it and the `sh:sourceConstraintComponent` its violation must carry. A single
# property shape usually declares several of these, and one substituted value can trip more
# than one at once, so requiring the specific component is what keeps each mutation a test
# of the constraint it names rather than of whichever rule happens to fire first.
MUTABLE_CONSTRAINTS: list[tuple[str, URIRef]] = [
    ("in", SH_IN),
    ("pattern", SH_PATTERN),
    ("datatype", URIRef(SH + "datatype")),
    ("nodeKind", URIRef(SH + "nodeKind")),
    ("class", URIRef(SH + "class")),
    ("node", URIRef(SH + "node")),
    ("maxCount", URIRef(SH + "maxCount")),
    ("uniqueLang", URIRef(SH + "uniqueLang")),
]

COMPONENT_FOR = {
    "in": URIRef(SH + "InConstraintComponent"),
    "pattern": URIRef(SH + "PatternConstraintComponent"),
    "datatype": URIRef(SH + "DatatypeConstraintComponent"),
    "nodeKind": URIRef(SH + "NodeKindConstraintComponent"),
    "class": URIRef(SH + "ClassConstraintComponent"),
    "node": URIRef(SH + "NodeConstraintComponent"),
    "maxCount": URIRef(SH + "MaxCountConstraintComponent"),
    "uniqueLang": URIRef(SH + "UniqueLangConstraintComponent"),
}

# Every constraint the shapes declare, recorded in the snapshot: the mutable ones plus
# `sh:minCount`, which is mutated by the two PRESENCE passes instead. DERIVED from
# MUTABLE_CONSTRAINTS rather than restated, so a constraint kind can never be mutated
# without also being snapshotted (the reverse of the two lists silently disagreeing).
RECORDED_CONSTRAINTS: list[tuple[str, URIRef]] = [
    ("minCount", SH_MIN_COUNT),
    *MUTABLE_CONSTRAINTS,
]

# Substituted for a real value to violate `sh:in` / `sh:pattern`. Chosen to be outside every
# controlled vocabulary in the shapes and to match neither declared pattern
# (`^mailto:.+@.+\..+$`, `^(GOE|GDI)-[A-Z]{2}-[A-Z]+-[0-9]+$`). The IRI form uses the
# reserved `.invalid` TLD so it can never accidentally resolve to anything real.
PROBE_IRI = URIRef("http://example.invalid/gdi-negative-probe")
PROBE_TEXT = "gdi-negative-probe"

# The committed record of what the shapes currently mandate. See "(4) The snapshot closes
# the circularity" in the module docstring for why this exists. It sits beside both shape
# sets because it is derived from both.
SNAPSHOT_PATH = HERE / "shapes" / "derived-mandatory.txt"

SNAPSHOT_HEADER = """\
# Derived mandatory constraints — the complete set this repo's SHACL shapes enforce.
#
# GENERATED. Do not hand-edit. Regenerate after a DELIBERATE shape change with:
#     python conformance/check_fdp_negative.py --write-snapshot
#
# Why this file exists: check_fdp_negative.py derives its mutation set from the shapes'
# own `sh:minCount` declarations, so relaxing a constraint deletes the very mutation that
# would catch it — silently, and the suite stays green. A snapshot is the only offline way
# to see that: a relaxation removes a line here, which shows up in review.
#
# A line removed means a constraint was relaxed or a shape was disabled: either a real
# regression, or a re-vendor you must review. A line added means a new mandatory
# constraint; regenerate and commit it in the same change.
#
# Format (sorted):
#   P <predicate>                    a property shape mandates this predicate somewhere
#   C <class> <predicate>            some NodeShape with this sh:targetClass mandates it
#   S <shape> <class> <predicate>    this NodeShape mandates it (finest granularity: a
#                                    sibling shape can keep a C line alive after this
#                                    shape stopped enforcing, so S moves first)
#   K <shape> <path> <kind> <value>  ANY declared constraint — minCount, maxCount, datatype,
#                                    nodeKind, pattern, uniqueLang, class, node, in. The
#                                    mutation passes cannot exercise every kind, but every
#                                    kind can be RECORDED, and "the constraint vanished" is
#                                    the failure that matters. For `in`, <value> is the
#                                    sorted members joined by `|`, so dropping one member of
#                                    a controlled vocabulary changes the line.
"""


def _min_count_int(value: object) -> int | None:
    """Parse an ``sh:minCount`` object literal to ``int``, or ``None`` if it is absent
    (``value is None``) or not an integer.

    Every shape-derivation pass below shares this guard, so they agree on what counts as a
    mandatory constraint. Callers treat ``None`` and ``< 1`` identically (skip).
    """
    if value is None:
        return None
    try:
        return int(value.toPython())
    except (TypeError, ValueError):
        return None


def mandatory_predicates(*shape_graphs: Graph) -> list[URIRef]:
    """Every predicate a property shape requires (``sh:minCount >= 1``) across the
    given shape graphs, as a sorted, de-duplicated list.

    Only simple IRI ``sh:path`` predicates are considered; a complex path (a blank
    node — sequence / inverse / alternative path) is skipped, since the
    per-predicate "drop every triple" mutation below is not well defined for one.
    Neither shape set currently uses a complex path.
    """
    preds: set[URIRef] = set()
    for g in shape_graphs:
        for shape, _, min_count in g.triples((None, SH_MIN_COUNT, None)):
            n = _min_count_int(min_count)
            if n is None or n < 1:
                continue
            path = g.value(shape, SH_PATH)
            if isinstance(path, URIRef):
                preds.add(path)
    return sorted(preds, key=str)


def mandatory_class_predicate_pairs(
    *shape_graphs: Graph,
) -> list[tuple[URIRef, URIRef]]:
    """Every ``(targetClass, predicate)`` pair a property shape requires
    (``sh:minCount >= 1``), across the given shape graphs, sorted and de-duplicated.

    This is the shape-level (per target class) refinement of
    :func:`mandatory_predicates`. The global per-predicate drop proves only
    predicate-level discrimination: a predicate mandated by several shapes (``dct:title``
    on Catalog, Dataset and Distribution) is dropped union-wide and counts as rejected as
    long as any one of those shapes still fires, so a single shape whose target class is
    typo'd or whose ``sh:minCount`` is relaxed stays masked by the others. Pairing each
    mandatory predicate with the ``sh:targetClass`` of the NodeShape that declares it lets
    the mutation drop the predicate from instances of that class only, isolating each
    shape's contribution. A NodeShape with no ``sh:targetClass`` (referenced only via
    ``sh:node``) contributes no pair here and stays covered by the global drop.

    Only simple IRI ``sh:path`` predicates are considered (a complex/blank-node path
    is skipped, as for :func:`mandatory_predicates`); neither shape set uses one.
    """
    pairs: set[tuple[URIRef, URIRef]] = set()
    for g in shape_graphs:
        for shape, _, prop in g.triples((None, SH_PROPERTY, None)):
            n = _min_count_int(g.value(prop, SH_MIN_COUNT))
            if n is None or n < 1:
                continue
            path = g.value(prop, SH_PATH)
            if not isinstance(path, URIRef):
                continue
            for _, _, cls in g.triples((shape, SH_TARGET_CLASS, None)):
                if isinstance(cls, URIRef):
                    pairs.add((cls, path))
    return sorted(pairs, key=lambda cp: (str(cp[0]), str(cp[1])))


def mandatory_shape_class_predicate(
    *shape_graphs: Graph,
) -> list[tuple[URIRef, URIRef, URIRef]]:
    """Every ``(declaringShape, targetClass, predicate)`` a property shape requires.

    The finest granularity available, and the one the snapshot needs. ``(class,
    predicate)`` alone is too coarse to notice a relaxation when a sibling shape mandates
    the same pair on the same class, which happens here: ``AgentCreator.ttl`` and
    ``AgentHdab.ttl`` both target ``foaf:Agent`` with identical ``foaf:name`` constraints,
    and the FDP and gdi-metadata sets both constrain ``dcat:Catalog``. Under a pair-keyed
    snapshot, relaxing either half of a duplicated pair changes nothing recorded. Keying on
    the declaring shape makes each shape's own contribution visible.
    """
    out: set[tuple[URIRef, URIRef, URIRef]] = set()
    for g in shape_graphs:
        for shape, _, prop in g.triples((None, SH_PROPERTY, None)):
            n = _min_count_int(g.value(prop, SH_MIN_COUNT))
            if n is None or n < 1:
                continue
            path = g.value(prop, SH_PATH)
            if not isinstance(path, URIRef) or not isinstance(shape, URIRef):
                continue
            for _, _, cls in g.triples((shape, SH_TARGET_CLASS, None)):
                if isinstance(cls, URIRef):
                    out.add((shape, cls, path))
    return sorted(out, key=lambda t: (str(t[0]), str(t[1]), str(t[2])))


def _rdf_list(g: Graph, node: object) -> list[object]:
    """Expand an RDF collection (``rdf:first``/``rdf:rest``) into a Python list.

    `sh:in` values are RDF lists. One of them (`dct:accessRights` in ``Dataset.ttl``) is a
    blank-node collection rather than an inline `( ... )`, so this has to traverse rather
    than pattern-match the source text.
    """
    return list(g.items(node)) if node is not None else []


def constraint_declarations(*shape_graphs: Graph) -> list[tuple[str, str, str, str]]:
    """Every ``(shape, path, constraint, value)`` the shapes declare, sorted.

    This is the full declaration record, not just the mandatory-presence slice the mutation
    passes use. The mutation model cannot cover every constraint kind, but the snapshot can
    record all of them, and "the constraint disappeared" is the failure that matters.
    Deleting an `sh:pattern`, dropping a member from an `sh:in` list, or loosening
    `sh:maxCount` each change a line here.
    """
    out: set[tuple[str, str, str, str]] = set()
    for g in shape_graphs:
        for shape, _, prop in g.triples((None, SH_PROPERTY, None)):
            path = g.value(prop, SH_PATH)
            if not isinstance(path, URIRef) or not isinstance(shape, URIRef):
                continue
            for name, pred in RECORDED_CONSTRAINTS:
                value = g.value(prop, pred)
                if value is None:
                    continue
                if pred == SH_IN:
                    # Sort the members so the line is stable, and join them so REMOVING one
                    # member (a real relaxation of a controlled vocabulary) changes the line.
                    rendered = "|".join(sorted(str(v) for v in _rdf_list(g, value)))
                else:
                    rendered = str(value)
                out.add((str(shape), str(path), name, rendered))
    return sorted(out)


def value_constraint_sites(
    *shape_graphs: Graph,
) -> list[tuple[URIRef, URIRef, str, object]]:
    """Every ``(targetClass, path, constraint, spec)`` site a VALUE mutation can target.

    Covers all EIGHT mutable constraint kinds, on shapes with an ``sh:targetClass`` (so the
    mutation knows which instances to perturb). ``spec`` carries whatever that kind's
    mutation needs — the `sh:in` members, the declared datatype/nodeKind/class/shape, or the
    `sh:maxCount` integer.

    `sh:minCount` is absent here: it is the presence mutation, covered by the two passes
    above, and re-deriving it would double-count it.
    """
    sites: dict[tuple[URIRef, URIRef, str], object] = {}
    for g in shape_graphs:
        for shape, _, prop in g.triples((None, SH_PROPERTY, None)):
            path = g.value(prop, SH_PATH)
            if not isinstance(path, URIRef):
                continue
            for _, _, cls in g.triples((shape, SH_TARGET_CLASS, None)):
                if not isinstance(cls, URIRef):
                    continue
                for kind, pred in MUTABLE_CONSTRAINTS:
                    value = g.value(prop, pred)
                    if value is None:
                        continue
                    if kind == "in":
                        sites[(cls, path, kind)] = _rdf_list(g, value)
                    elif kind == "maxCount":
                        n = _min_count_int(value)
                        if n is not None:
                            sites[(cls, path, kind)] = n
                    elif kind == "uniqueLang":
                        # Only `sh:uniqueLang true` constrains anything.
                        if str(value).lower() in {"true", "1"}:
                            sites[(cls, path, kind)] = True
                    else:
                        sites[(cls, path, kind)] = value
    return sorted(
        ((cls, path, kind, spec) for (cls, path, kind), spec in sites.items()),
        key=lambda s: (str(s[0]), str(s[1]), s[2]),
    )


def derived_lines(
    mandatory: list[URIRef],
    pairs: list[tuple[URIRef, URIRef]],
    triples: list[tuple[URIRef, URIRef, URIRef]],
    constraints: list[tuple[str, str, str, str]],
) -> list[str]:
    """The snapshot body for a derivation: sorted ``P``/``C``/``S`` lines (no header).

    ``S`` subsumes ``C``, but all three are recorded because they fail differently: a lost
    ``P`` means nothing mandates the predicate any more, a lost ``C`` means nothing
    mandates it on that class, and a lost ``S`` means *this particular shape* stopped —
    which may still be masked by a sibling, and is the earliest signal of the three.
    """
    return (
        [f"P {pred}" for pred in mandatory]
        + [f"C {cls} {pred}" for cls, pred in pairs]
        + [f"S {shape} {cls} {pred}" for shape, cls, pred in triples]
        + [
            f"K {shape} {path} {name} {value}"
            for shape, path, name, value in constraints
        ]
    )


def read_snapshot() -> list[str] | None:
    """The recorded derivation, or ``None`` if the snapshot file is absent."""
    if not SNAPSHOT_PATH.is_file():
        return None
    return [
        line
        for line in SNAPSHOT_PATH.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    ]


def write_snapshot(lines: list[str]) -> None:
    """(Re)generate the snapshot from a derivation."""
    SNAPSHOT_PATH.write_text(
        SNAPSHOT_HEADER + "\n".join(lines) + "\n", encoding="utf-8"
    )


def check_snapshot(lines: list[str]) -> list[str]:
    """Diff a derivation against the committed snapshot; return failure messages.

    This is the guard that a relaxation cannot satisfy by doing less work: a removed
    constraint removes a line, and a removed line is a failure. Both directions fail —
    an ADDED constraint is also a shape change, and must be reviewed and committed
    rather than absorbed silently.
    """
    recorded = read_snapshot()
    if recorded is None:
        return [
            (
                f"the derivation snapshot {SNAPSHOT_PATH} is MISSING — without it, "
                "relaxing an sh:minCount silently deletes its own mutation and this "
                "check stays green. Regenerate with: "
                "python conformance/check_fdp_negative.py --write-snapshot"
            )
        ]
    have, want = set(lines), set(recorded)
    failures: list[str] = []
    for gone in sorted(want - have):
        failures.append(
            f"NO LONGER MANDATED: {gone!r} is in {SNAPSHOT_PATH.name} but the shapes no "
            "longer derive it — a constraint was RELAXED (sh:minCount lowered), a shape "
            "was disabled/typo'd, or a re-vendor weakened the model. If deliberate, "
            "regenerate the snapshot in the same change."
        )
    for added in sorted(have - want):
        failures.append(
            f"NEWLY MANDATED: the shapes derive {added!r} but {SNAPSHOT_PATH.name} does "
            "not record it. If deliberate, regenerate the snapshot in the same change."
        )
    return failures


def load_union(union_path: Path) -> Graph:
    """Parse a fresh copy of the union graph (so each mutation starts clean)."""
    g = Graph()
    g.parse(union_path, format="turtle")
    return g


def _validate(data: Graph, shapes: Graph) -> tuple[bool, Graph]:
    """``(conforms, report_graph)`` — same engine config as ``check_fdp.run``
    (``inference="none"``, ``advanced=True``), but without printing the full report, so
    the per-mutation output stays one line each.

    The report graph is returned, not just the boolean, because attribution needs to know
    *which* constraint fired: "rejected for some reason" is how a deactivated shape passes
    on a neighbour's violation.
    """
    conforms, report_graph, _report_text = validate(
        data_graph=data,
        shacl_graph=shapes,
        inference="none",
        advanced=True,
        meta_shacl=False,
        debug=False,
    )
    return conforms, report_graph


def _violations_on(
    report: Graph, pred: URIRef, component: URIRef | None = None
) -> set[object]:
    """Focus nodes flagged with ``sh:resultPath`` = ``pred``.

    When ``component`` is given, the violation must also carry that
    ``sh:sourceConstraintComponent``. Substituting a value to break `sh:pattern` can just as
    easily trip `sh:datatype` or `sh:nodeKind` on the same predicate; a path-only match
    cannot tell those apart, and would report the pattern rule as live when the datatype
    rule is doing the work.
    """
    focus: set[object] = set()
    for result in report.subjects(RDF_TYPE, SH_VALIDATION_RESULT):
        if report.value(result, SH_RESULT_PATH) != pred:
            continue
        if (
            component is not None
            and report.value(result, SH_SOURCE_COMPONENT) != component
        ):
            continue
        node = report.value(result, SH_FOCUS_NODE)
        if node is not None:
            focus.add(node)
    return focus


def _flagged_for(
    data: Graph,
    fdp_shapes: Graph,
    gdi_shapes: Graph,
    pred: URIRef,
    component: URIRef | None = None,
) -> tuple[set[object], bool]:
    """``(focus nodes flagged on `pred`, whether either set rejected at all)``.

    Both shape sets are consulted and their results unioned: a violation may come from
    either, and short-circuiting on the first rejection would let an unrelated shape's
    verdict stand in for the one under test.
    """
    flagged: set[object] = set()
    rejected = False
    for shapes in (fdp_shapes, gdi_shapes):
        conforms, report = _validate(data, shapes)
        if conforms:
            continue
        rejected = True
        flagged |= _violations_on(report, pred, component)
    return flagged, rejected


def rejected_for_predicate(
    data: Graph, fdp_shapes: Graph, gdi_shapes: Graph, pred: URIRef
) -> tuple[bool, str]:
    """Union-wide pass: SOME shape must flag ``pred`` itself.

    Not per-instance: the predicate spans classes, and a holder no shape mandates it on is
    legitimately unflagged. Attribution here means only that the rejection is about the
    predicate that was dropped.
    """
    flagged, rejected = _flagged_for(data, fdp_shapes, gdi_shapes, pred)
    if flagged:
        return True, ""
    if rejected:
        return False, "rejected, but NOT for the dropped predicate"
    return False, "still CONFORMS"


def _probe_for(kind: str, old: object, spec: object) -> object:
    """The replacement term that violates ``kind`` and as little else as possible.

    Each kind needs a DIFFERENT probe, which is the whole reason this is not one generic
    substitution: a value chosen to break `sh:pattern` must stay the right RDF term type and
    datatype (or it breaks `sh:nodeKind`/`sh:datatype` instead and the mutation silently
    tests the wrong rule), while a value chosen to break `sh:nodeKind` must be the wrong term
    type by construction.
    """
    if kind in {"in", "pattern"}:
        # Same term type, same datatype — isolate the value rule.
        return (
            Literal(PROBE_TEXT, datatype=old.datatype, lang=old.language)
            if isinstance(old, Literal)
            else PROBE_IRI
        )
    if kind == "datatype":
        # A literal of a different datatype than the one declared.
        declared = str(spec)
        return (
            Literal("1", datatype=XSD.integer)
            if not declared.endswith("#integer")
            else Literal(PROBE_TEXT, datatype=XSD.string)
        )
    if kind == "nodeKind":
        # The wrong term kind by construction: a literal where an IRI/blank node is
        # required, an IRI where a literal is required.
        wants_literal = "Literal" in str(spec) and "IRI" not in str(spec)
        return PROBE_IRI if wants_literal else Literal(PROBE_TEXT)
    # class / node: a bare IRI carries no `rdf:type` and no properties, so it satisfies
    # neither an `sh:class` membership test nor an `sh:node` shape's own constraints.
    return PROBE_IRI


def mutate_site(
    mutant: Graph, cls: URIRef, pred: URIRef, kind: str, spec: object
) -> tuple[set[object], str]:
    """Apply ``kind``'s mutation to every instance of ``cls`` that carries ``pred``.

    Returns ``(instances actually mutated, a human-readable description)``. Six kinds
    SUBSTITUTE a value; `maxCount` and `uniqueLang` ADD one, because those constraints are
    about the shape of the value SET and cannot be violated by editing a single term.
    """
    instances = [s for s, _, _ in mutant.triples((None, RDF_TYPE, cls))]
    mutated: set[object] = set()
    detail = ""

    if kind == "maxCount":
        limit = int(spec) if isinstance(spec, int) else 1
        for inst in instances:
            existing = list(mutant.triples((inst, pred, None)))
            if not existing:
                continue
            # Add enough DISTINCT terms to exceed the cap. Their own validity is irrelevant:
            # `sh:maxCount` is violated by the count, whatever the values are.
            for i in range(limit + 1 - len(existing)):
                mutant.add((inst, pred, URIRef(f"{PROBE_IRI}-{i}")))
            mutated.add(inst)
        detail = f"add values past sh:maxCount {limit}"
        return mutated, detail

    if kind == "uniqueLang":
        for inst in instances:
            langs = [
                o.language
                for _, _, o in mutant.triples((inst, pred, None))
                if isinstance(o, Literal) and o.language
            ]
            if not langs:
                continue
            # A second literal in a language already present is what uniqueLang bans.
            mutant.add((inst, pred, Literal(PROBE_TEXT, lang=langs[0])))
            mutated.add(inst)
        detail = "add a duplicate-language literal"
        return mutated, detail

    allowed = (
        {str(a) for a in spec} if kind == "in" and isinstance(spec, list) else set()
    )
    probe: object = PROBE_IRI
    for inst in instances:
        for _, _, old in list(mutant.triples((inst, pred, None))):
            probe = _probe_for(kind, old, spec)
            # A probe that happened to satisfy the constraint would make the mutation a
            # silent no-op, so refuse rather than report a green.
            if str(probe) in allowed:
                raise AssertionError(
                    f"probe {probe!r} is itself in the sh:in list for <{pred}> — pick another"
                )
            mutant.remove((inst, pred, old))
            mutant.add((inst, pred, probe))
            mutated.add(inst)
    return mutated, f":= {probe}"


def rejected_for_instances(
    data: Graph,
    fdp_shapes: Graph,
    gdi_shapes: Graph,
    pred: URIRef,
    instances: set[object],
    component: URIRef | None = None,
) -> tuple[bool, str]:
    """Per-class pass: every mutated instance must be flagged on ``pred``.

    The strict quantifier is the point. If a shape targeting class C mandates P, dropping
    P from all instances of C must flag all of them. Requiring only one violation would let
    a multi-typed node satisfy the check for its whole class: the FDP root is typed both
    ``fdp-o:FAIRDataPoint`` and ``dcat:DataService``, so a fully deactivated
    ``gdi:DataServiceShape`` still leaves ``FAIRDataPointShape`` flagging the root while
    every other DataService instance goes unprotected.
    """
    flagged, rejected = _flagged_for(data, fdp_shapes, gdi_shapes, pred, component)
    unflagged = instances - flagged
    if not unflagged:
        return True, ""
    if flagged:
        return False, (
            f"only {len(flagged)} of {len(instances)} mutated instance(s) flagged on this "
            f"predicate; unflagged: {sorted(str(n) for n in unflagged)[:3]} — another "
            "shape is supplying the rejection, this class's own shape is not"
        )
    if rejected:
        return False, "rejected, but NOT for the dropped predicate on these instances"
    return False, "still CONFORMS"


def main(argv: list[str]) -> int:
    write_mode = len(argv) == 2 and argv[1] == "--write-snapshot"
    if not write_mode and len(argv) != 2:
        print(f"usage: {argv[0]} <union.ttl> | --write-snapshot", file=sys.stderr)
        return 2

    fdp_shapes = check_fdp.load_shapes(check_fdp.FDP_SHAPES)
    gdi_shapes = check_fdp.load_shapes(check_fdp.GDI_SHAPES)

    # The mutation set, derived from the shapes (not hand-maintained).
    mandatory = mandatory_predicates(fdp_shapes, gdi_shapes)
    class_pairs = mandatory_class_predicate_pairs(fdp_shapes, gdi_shapes)
    shape_triples = mandatory_shape_class_predicate(fdp_shapes, gdi_shapes)
    constraints = constraint_declarations(fdp_shapes, gdi_shapes)
    value_sites = value_constraint_sites(fdp_shapes, gdi_shapes)
    lines = derived_lines(mandatory, class_pairs, shape_triples, constraints)

    if write_mode:
        write_snapshot(lines)
        print(f"wrote {SNAPSHOT_PATH} ({len(lines)} derived constraint(s))")
        print(
            "Review the diff: a removed line means a constraint was relaxed, which is the "
            "change this snapshot exists to make visible."
        )
        return 0

    union_path = Path(argv[1])
    if not union_path.is_file():
        print(f"union graph not found: {union_path}", file=sys.stderr)
        return 2

    # (4) The non-circular guard, first: the data-driven passes below can only test what
    # the shapes still declare, so a relaxation makes them quieter rather than redder.
    # This is the one check that sees a constraint disappear.
    print("===== derived mandatory set must match the committed snapshot =====")
    snapshot_failures = check_snapshot(lines)
    if snapshot_failures:
        print("\nSNAPSHOT CHECK FAILED:", file=sys.stderr)
        for failure in snapshot_failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print(
        f"OK: all {len(lines)} derived constraint(s) match {SNAPSHOT_PATH.name} "
        f"({len(mandatory)} predicate(s), {len(class_pairs)} (class, predicate) pair(s)).\n"
    )

    print(f"derived {len(mandatory)} mandatory predicate(s) from the shapes:")
    for pred in mandatory:
        print(f"  - {pred}")

    # Sanity: the unmutated union must conform to both sets, or the negatives prove
    # nothing.
    print("\n===== sanity: the unmutated union must CONFORM to both shape sets =====")
    baseline = load_union(union_path)
    base_fdp, _ = _validate(baseline, fdp_shapes)
    base_gdi, _ = _validate(baseline, gdi_shapes)
    if not (base_fdp and base_gdi):
        print(
            "FAIL: the unmutated union does not conform; cannot meta-validate",
            file=sys.stderr,
        )
        return 1
    print("baseline CONFORMS.")

    print("\n===== mutations: dropping each mandatory predicate must be REJECTED =====")
    failures: list[str] = []
    skipped: list[str] = []
    checked = 0
    for pred in mandatory:
        mutant = load_union(union_path)
        removed = list(mutant.triples((None, pred, None)))
        if not removed:
            skipped.append(str(pred))
            continue
        for triple in removed:
            mutant.remove(triple)
        checked += 1
        ok, why = rejected_for_predicate(mutant, fdp_shapes, gdi_shapes, pred)
        if ok:
            print(f"  REJECTED  drop every <{pred}> ({len(removed)} triple(s))")
        else:
            print(f"  {why.upper()}  drop every <{pred}>  <-- BUG")
            failures.append(
                f"dropping every <{pred}> ({len(removed)} triple(s)): {why} — "
                "a shape mandates it but no shape set enforces it on the present data"
            )

    if skipped:
        print(
            f"\nnote: {len(skipped)} mandatory predicate(s) absent from this union "
            "(their shape's target class is not exercised by the fixtures), skipped:"
        )
        for pred in skipped:
            print(f"  - {pred}")

    # Shape-level discrimination: drop each mandatory property from instances of its
    # own target class only, so a single silently-disabled shape (a typo'd
    # sh:targetClass or a relaxed sh:minCount) is not masked by another shape that
    # mandates the same predicate on a different class.
    print(
        "\n===== per-(targetClass, path) mutations: dropping a mandatory property "
        "from instances of its OWN target class must be REJECTED ====="
    )
    class_failures: list[str] = []
    class_skipped: list[str] = []
    class_checked = 0
    for cls, pred in class_pairs:
        mutant = load_union(union_path)
        instances = [s for s, _, _ in mutant.triples((None, RDF_TYPE, cls))]
        # Only instances that ACTUALLY lost a triple are expected to be flagged: one that
        # never carried the predicate was already non-conformant or already exempt, and
        # demanding a violation on it would make this pass fail for the wrong reason.
        mutated: set[object] = set()
        removed = []
        for inst in instances:
            triples = list(mutant.triples((inst, pred, None)))
            if triples:
                mutated.add(inst)
                removed.extend(triples)
        if not removed:
            class_skipped.append(f"{cls} / {pred}")
            continue
        for triple in removed:
            mutant.remove(triple)
        class_checked += 1
        ok, why = rejected_for_instances(
            mutant, fdp_shapes, gdi_shapes, pred, mutated, MIN_COUNT_COMPONENT
        )
        if ok:
            print(f"  REJECTED  drop <{pred}> from {len(mutated)} <{cls}> instance(s)")
        else:
            print(f"  NOT ATTRIBUTED  drop <{pred}> from <{cls}> instances  <-- BUG")
            class_failures.append(
                f"dropping <{pred}> from <{cls}> instances: {why} — the shape mandating "
                "it on that target class is silently disabled or non-discriminating"
            )

    # Value constraints. The two passes above mutate presence only, so on their own they say
    # nothing about whether a controlled vocabulary or a format rule fires: a gutted `sh:in`
    # list or a deleted `sh:pattern` is invisible to a presence-only check. Substitute an
    # out-of-range value and require the violation to be attributed to the right constraint
    # component on the right instances.
    print(
        "\n===== value mutations: an out-of-range sh:in / sh:pattern value must be "
        "REJECTED, by that constraint ====="
    )
    value_failures: list[str] = []
    value_skipped: list[str] = []
    value_checked = 0
    for cls, pred, kind, spec in value_sites:
        mutant = load_union(union_path)
        mutated, detail = mutate_site(mutant, cls, pred, kind, spec)
        if not mutated:
            value_skipped.append(f"{cls} / {pred} ({kind})")
            continue
        value_checked += 1
        ok, why = rejected_for_instances(
            mutant, fdp_shapes, gdi_shapes, pred, mutated, COMPONENT_FOR[kind]
        )
        if ok:
            print(
                f"  REJECTED  sh:{kind:<10} <{pred}> {detail} "
                f"on {len(mutated)} <{cls}> instance(s)"
            )
        else:
            print(f"  NOT ATTRIBUTED  sh:{kind} <{pred}> on <{cls}>  <-- BUG")
            value_failures.append(
                f"violating sh:{kind} for <{pred}> on <{cls}> instances ({detail}): {why} "
                "— that constraint is not enforced on the present data"
            )

    if class_skipped:
        print(
            f"\nnote: {len(class_skipped)} (targetClass, predicate) pair(s) not "
            "exercised by this union (class absent / no such triple), skipped."
        )

    all_failures = failures + class_failures + value_failures
    print(
        f"\nglobal: checked {checked} mutation(s), {len(skipped)} skipped. "
        f"per-class: checked {class_checked} mutation(s), {len(class_skipped)} skipped. "
        f"value: checked {value_checked} mutation(s), {len(value_skipped)} skipped. "
        f"{len(all_failures)} failure(s)."
    )
    if all_failures:
        print("\nNEGATIVE META-VALIDATION FAILED:", file=sys.stderr)
        for failure in all_failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    # A floor on the work, not just on the verdict. The snapshot above pins how many
    # constraints exist; this pins how many of them this union exercised.
    #
    # A skip is not neutral: it means a mandated constraint went untested this run, which is
    # the same silent shrink as a relaxed sh:minCount, reached from the data side instead of
    # the shape side. The corpus exercises all of them, so the honest floor is zero skips.
    # If this fires, either the fixture corpus stopped covering a shape's target class (fix
    # the corpus, that is real lost coverage), or a shape was added for a class the corpus
    # never had, in which case its mutation proves nothing and the corpus should grow too.
    if skipped or class_skipped:
        print(
            f"FAIL: {len(skipped)} predicate mutation(s) and {len(class_skipped)} "
            "per-class mutation(s) were SKIPPED — the union does not exercise every "
            "constraint the shapes mandate, so this run verified less than the snapshot "
            "says exists. Extend the fixture corpus in conformance_crawl.rs to cover them.",
            file=sys.stderr,
        )
        return 1
    # Value-constraint skips are reported, not fatal: unlike the mandatory predicates above,
    # an `sh:in`/`sh:pattern` site can legitimately target an optional property the corpus
    # does not populate (`adms:status`, `dct:type` on a non-synthetic dataset). Making these
    # fatal would force the corpus to carry every optional field, giving a fixture less like
    # the real node the crawl is meant to represent.
    if value_skipped:
        print(
            f"\nnote: {len(value_skipped)} value-constraint site(s) not exercised by this "
            "union, skipped. There are two reasons a site lands here, and only one of them "
            "is a corpus gap:"
        )
        print(
            "  (a) optional property the corpus does not populate — `dct:type` (set only on "
            "synthetic datasets) and `Distribution`'s `adms:status`. Closable by extending "
            "the fixture corpus, at the cost of a corpus less like a real node."
        )
        print(
            "  (b) structurally unexercisable — every remaining `sh:uniqueLang` site. The "
            "node emits those paths as plain literals because the model behind them is a "
            "string, not a language map: `Agent.name` / `OtherIdentifier.name` "
            "(`foaf:name`), the catalog title and description, and the fixed `DataService` "
            "/ `Distribution` titles. A literal with no language tag cannot violate "
            "`sh:uniqueLang`, so no output this node can produce would exercise the rule; "
            "closing these would mean changing the wire model to suit a test. `dct:title` "
            "and `dct:description` on `dcat:Dataset` are the only localized paths, and both "
            "are exercised."
        )
        for site in value_skipped:
            print(f"  - {site}")
    print(
        "\nALL MUTATIONS CORRECTLY REJECTED — the FDP / gdi-metadata shapes "
        "discriminate at predicate AND target-class granularity, and each rejection is "
        "attributed to the constraint under test."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
