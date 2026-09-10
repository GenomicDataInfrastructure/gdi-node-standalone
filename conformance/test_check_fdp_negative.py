#!/usr/bin/env python3
"""Non-triviality tests for ``check_fdp_negative.py``.

That checker derives its own mutation set from the shapes it tests, so relaxing a
constraint does not fail a test: it deletes one, and the run stays green with a smaller
counter. The committed snapshot, mechanism (4) in that module's docstring, is the only
part that can see a constraint disappear. It works only if ``check_snapshot`` reports both
directions and the derivation is non-empty to begin with, which is what these tests pin:
the checker's own mutation loop tests the shapes, so something else has to test the
checker.

Requires the pinned conformance venv (pyshacl, rdflib). Run:
``python -m unittest discover -s conformance -p 'test_*.py'``
"""

from __future__ import annotations

import unittest

import check_fdp_negative as cfn


class SnapshotDiffTests(unittest.TestCase):
    """``check_snapshot`` is the only mechanism that sees a deleted constraint."""

    def test_a_relaxed_constraint_is_reported_as_no_longer_mandated(self) -> None:
        recorded = cfn.read_snapshot()
        self.assertIsNotNone(
            recorded,
            "the committed snapshot must exist; without it every case below is vacuous",
        )
        assert recorded is not None
        # Anti-vacuity: an empty snapshot would make both directions trivially clean.
        self.assertGreater(
            len(recorded),
            10,
            f"the snapshot derives only {len(recorded)} lines — too few to be the real "
            "constraint set, so these tests would prove nothing",
        )

        # Drop one line, exactly as relaxing an sh:minCount to 0 would.
        relaxed = [line for line in recorded if line != recorded[0]]
        failures = cfn.check_snapshot(relaxed)
        self.assertTrue(
            any("NO LONGER MANDATED" in f for f in failures),
            "removing a derived constraint must be reported as a relaxation; this is the "
            "exact failure the snapshot exists for, and it got: " + repr(failures),
        )

    def test_a_newly_added_constraint_is_also_reported(self) -> None:
        recorded = cfn.read_snapshot()
        assert recorded is not None
        failures = cfn.check_snapshot(
            [*recorded, "Fake|Shape|http://example.org/p|added"]
        )
        self.assertTrue(
            any("NEWLY MANDATED" in f for f in failures),
            "an added constraint is a shape change and must be reviewed, not absorbed",
        )

    def test_an_unchanged_derivation_is_clean(self) -> None:
        """The control: without it, a check_snapshot that failed on EVERYTHING would
        satisfy both tests above while being useless."""
        recorded = cfn.read_snapshot()
        assert recorded is not None
        self.assertEqual(
            cfn.check_snapshot(list(recorded)),
            [],
            "the committed snapshot must agree with itself",
        )


class DerivationIsActuallyInvokedTests(unittest.TestCase):
    """The derivation must run, not just the snapshot comparison.

    Every test above reads ``shapes/derived-mandatory.txt`` and diffs it against itself,
    and none of them calls ``derived_lines``. A shapes file that derives zero constraints
    would leave all three green, because ``check_snapshot`` is only ever handed the
    committed lines and so never learns that the shapes stopped producing them. The
    anti-vacuity floor above does not cover this either: it bounds the size of the
    committed artifact, which stays as large as the day it was written whatever the shapes
    do.
    """

    def _derive(self) -> list[str]:
        """Re-run the derivation the way ``main`` does, from the real shape graphs."""
        fdp_shapes = cfn.check_fdp.load_shapes(cfn.check_fdp.FDP_SHAPES)
        gdi_shapes = cfn.check_fdp.load_shapes(cfn.check_fdp.GDI_SHAPES)
        return cfn.derived_lines(
            cfn.mandatory_predicates(fdp_shapes, gdi_shapes),
            cfn.mandatory_class_predicate_pairs(fdp_shapes, gdi_shapes),
            cfn.mandatory_shape_class_predicate(fdp_shapes, gdi_shapes),
            cfn.constraint_declarations(fdp_shapes, gdi_shapes),
        )

    def test_the_shapes_still_derive_a_non_empty_constraint_set(self) -> None:
        lines = self._derive()
        self.assertGreater(
            len(lines),
            10,
            f"the shapes derive only {len(lines)} constraint(s). The mutation set this "
            "checker builds is derived FROM the shapes, so an empty derivation means the "
            "negative suite mutates nothing and passes having tested nothing.",
        )

    def test_the_derivation_still_matches_the_committed_snapshot(self) -> None:
        # The snapshot must remain derivable from the shapes, not merely present on disk
        # and self-consistent.
        self.assertEqual(
            sorted(self._derive()),
            sorted(cfn.read_snapshot() or []),
            "the derivation no longer reproduces shapes/derived-mandatory.txt. If the "
            "shapes changed on purpose, regenerate it with "
            "`python conformance/check_fdp_negative.py --write-snapshot` and review the "
            "diff — a REMOVED line is a relaxed constraint.",
        )


if __name__ == "__main__":
    unittest.main()
