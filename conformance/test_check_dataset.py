#!/usr/bin/env python3
"""Non-triviality tests for ``check_dataset.py``.

SHACL only applies a shape to a node matching its ``sh:targetClass``, so an empty shapes
graph targets nothing, produces zero violations, and makes pySHACL report
``conforms=True`` vacuously. A ``check_dataset.py`` whose shapes glob silently matched
nothing would print ``CONFORMS`` and exit 0 for every fixture, the negative ones included,
while proving nothing.

``check_fdp.py`` guards this in its own ``main``. These tests pin the same property for
``check_dataset.py``.

Requires the pinned conformance venv (pyshacl, rdflib). Run:
``python -m unittest discover -s conformance -p 'test_*.py'``
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import check_dataset

# A single dcat:Dataset with none of the mandatory gdi-metadata fields. Under the real
# shapes this violates; under an empty shapes graph it "conforms" vacuously.
BARE_DATASET_TTL = """
@prefix dcat: <http://www.w3.org/ns/dcat#> .
<http://example.org/d1> a dcat:Dataset .
"""

# Triples, but nothing typed dcat:Dataset, so every shape targets zero nodes and SHACL
# reports conforms=True having validated nothing. Distinct from the empty-file case only
# in that it proves the guard checks the type, not merely the triple count.
UNTYPED_TTL = """
@prefix dct: <http://purl.org/dc/terms/> .
<http://example.org/d1> dct:title "hello" .
"""


class ShapesNonTriviality(unittest.TestCase):
    def setUp(self):
        self._real_shapes = check_dataset.GDI_SHAPES
        self._tmp = tempfile.TemporaryDirectory()
        self.data_ttl = Path(self._tmp.name) / "dataset.ttl"
        self.data_ttl.write_text(BARE_DATASET_TTL, encoding="utf-8")

    def tearDown(self):
        check_dataset.GDI_SHAPES = self._real_shapes
        self._tmp.cleanup()

    def test_real_shapes_dir_loads_triples(self):
        self.assertGreater(len(check_dataset.load_gdi_shapes()), 0)

    def test_empty_shapes_glob_must_not_report_conforms(self):
        """A mis-globbed / moved shapes dir must FAIL, not pass vacuously."""
        empty = Path(self._tmp.name) / "no-shapes"
        empty.mkdir()
        check_dataset.GDI_SHAPES = empty
        rc = check_dataset.main(["check_dataset.py", str(self.data_ttl)])
        self.assertNotEqual(
            rc, 0, "empty shapes graph reported CONFORMS — the check is vacuous"
        )

    def test_bare_dataset_violates_under_the_real_shapes(self):
        """The fixture really is invalid, so the test above proves something."""
        rc = check_dataset.main(["check_dataset.py", str(self.data_ttl)])
        self.assertEqual(rc, 1)

    def test_empty_data_graph_must_not_report_conforms(self):
        """The DATA side of the same vacuity: no target node, no violations."""
        empty_data = Path(self._tmp.name) / "empty.ttl"
        empty_data.write_text("", encoding="utf-8")
        rc = check_dataset.main(["check_dataset.py", str(empty_data)])
        self.assertNotEqual(
            rc, 0, "an EMPTY data graph reported CONFORMS — the check is vacuous"
        )

    def test_untyped_data_graph_must_not_report_conforms(self):
        """Triples but no ``dcat:Dataset`` still targets nothing, so still vacuous."""
        untyped = Path(self._tmp.name) / "untyped.ttl"
        untyped.write_text(UNTYPED_TTL, encoding="utf-8")
        rc = check_dataset.main(["check_dataset.py", str(untyped)])
        self.assertNotEqual(
            rc, 0, "an UNTYPED data graph reported CONFORMS — the check is vacuous"
        )


if __name__ == "__main__":
    unittest.main()
