#!/usr/bin/env python3
"""Unit tests for scripts/gate-record.sh, the decision to record a green run.

The gate's short-circuit is only as trustworthy as the marker it writes. `all` is meant to
run in the background while work continues, so the tree can legitimately change while the
legs are running. Recording the post-run tree hash would then certify a tree that was
never tested: the legs finish green having tested the tree as it stood when they started,
the marker names the edited tree, and the next `all` short-circuits on code nothing
compiled.

The marker may therefore only be written when the tree is byte-identical to what the legs
tested. These tests pin that without running the gate.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from _helpers import SCRIPTS

SCRIPT = SCRIPTS / "gate-record.sh"
NOW = "1000000"


class GateRecordTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.marker = Path(self.tmp.name) / ".gate-ok"

    def tearDown(self):
        self.tmp.cleanup()

    def run_record(self, *, before, now_key, env=None):
        # Scrub ambient GATE_* so a caller's `GATE_FORCE=1 ci-local.sh all` cannot leak
        # into the case under test; one of its legs runs this suite.
        base = {k: v for k, v in os.environ.items() if not k.startswith("GATE_")}
        base.update(env or {})
        return subprocess.run(
            [
                str(SCRIPT),
                "--key-before",
                before,
                "--key-now",
                now_key,
                "--marker",
                str(self.marker),
                "--now",
                NOW,
            ],
            capture_output=True,
            text=True,
            env=base,
            check=False,
        )

    def test_unchanged_tree_records_the_marker(self):
        r = self.run_record(before="abc123", now_key="abc123")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("RECORDED", r.stdout)
        self.assertTrue(
            self.marker.exists(), "marker must be written for an unchanged tree"
        )
        self.assertEqual(self.marker.read_text().split(), ["abc123", NOW])

    def test_tree_changed_during_the_run_does_not_record(self):
        r = self.run_record(before="abc123", now_key="DIFFERENT")
        self.assertEqual(
            r.returncode, 0, "a changed tree is not a gate failure, only unrecordable"
        )
        self.assertIn("NOT RECORDED", r.stdout)
        self.assertFalse(
            self.marker.exists(),
            "a tree edited mid-run was never tested; recording it would certify untested code",
        )

    def test_a_changed_tree_leaves_an_existing_marker_untouched(self):
        # An older green marker must survive a run that cannot record. Its key no longer
        # matches the current tree, so gate-status reports STALE and the next `all` runs
        # in full.
        self.marker.write_text("oldkey 999\n")
        r = self.run_record(before="abc123", now_key="DIFFERENT")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.marker.read_text(), "oldkey 999\n")


if __name__ == "__main__":
    unittest.main()
