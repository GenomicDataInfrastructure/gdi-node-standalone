"""Unit tests for ``scripts/gate-status.sh``, the whole-gate short-circuit decision.

This is the logic that decides whether to skip most of the gate's legs, and a wrong "skip"
produces a false green. So every failure mode is asserted to be STALE rather than trusted
to be: missing, empty, malformed, non-numeric, mismatched, expired and clock-skewed
markers must all fall back to a full run. Only an exact key match inside the TTL may report
FRESH.

Complements ``test_gate_key.py``, which covers what goes into the key. Pure stdlib,
discovered by the ``dashboard`` leg's ``test_*.py`` sweep, so it runs inside ``all``.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from _helpers import SCRIPTS

SCRIPT = SCRIPTS / "gate-status.sh"
KEY = "a" * 64
HOUR = 3600
NOW = 1_700_000_000  # fixed: the script takes --now so tests never depend on wall clock


class GateStatusTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.marker = Path(self.tmp.name) / ".gate-ok"

    def tearDown(self):
        self.tmp.cleanup()

    def run_status(self, *, key=KEY, now=NOW, env=None):
        # Scrub any ambient GATE_* override before overlaying the per-test env, so a
        # caller who exported one cannot leak it into the script under test. Each case sets
        # the GATE_* vars it exercises; the rest fall to gate-status.sh's defaults.
        base = {k: v for k, v in os.environ.items() if not k.startswith("GATE_")}
        e = {**base, **(env or {})}
        return subprocess.run(
            [
                "bash",
                str(SCRIPT),
                "--marker",
                str(self.marker),
                "--key",
                key,
                "--now",
                str(now),
            ],
            capture_output=True,
            text=True,
            env=e,
            check=False,
        )

    def assertFresh(self, r):
        self.assertEqual(r.returncode, 0, f"expected FRESH, got: {r.stdout}{r.stderr}")
        self.assertTrue(r.stdout.startswith("FRESH"), r.stdout)

    def assertStale(self, r, because=None):
        self.assertEqual(r.returncode, 1, f"expected STALE, got: {r.stdout}{r.stderr}")
        self.assertTrue(r.stdout.startswith("STALE"), r.stdout)
        if because:
            self.assertIn(because, r.stdout)

    def write(self, text):
        self.marker.write_text(text)

    # --- the one case that may short-circuit ------------------------------
    def test_exact_key_inside_ttl_is_fresh(self):
        self.write(f"{KEY} {NOW - 2 * HOUR}\n")
        self.assertFresh(self.run_status())

    def test_just_inside_ttl_is_fresh(self):
        self.write(f"{KEY} {NOW - 23 * HOUR - 3599}\n")
        self.assertFresh(self.run_status())

    def test_zero_age_is_fresh(self):
        self.write(f"{KEY} {NOW}\n")
        self.assertFresh(self.run_status())

    # --- everything else must fall back to a full run ---------------------
    def test_missing_marker_is_stale(self):
        self.assertStale(self.run_status(), "no marker")

    def test_empty_marker_is_stale(self):
        self.write("")
        self.assertStale(self.run_status(), "empty")

    def test_malformed_marker_is_stale(self):
        self.write("only-one-field\n")
        self.assertStale(self.run_status(), "malformed")

    def test_non_numeric_timestamp_is_stale(self):
        self.write(f"{KEY} not-a-timestamp\n")
        self.assertStale(self.run_status(), "not an integer")

    def test_key_mismatch_is_stale(self):
        self.write(f"{'b' * 64} {NOW}\n")
        self.assertStale(self.run_status(), "changed since the last green run")

    def test_expired_marker_is_stale(self):
        self.write(f"{KEY} {NOW - 25 * HOUR}\n")
        self.assertStale(self.run_status(), "past the 24h TTL")

    def test_exactly_at_ttl_is_stale(self):
        """24h is the boundary and must not be trusted: the TTL is exclusive."""
        self.write(f"{KEY} {NOW - 24 * HOUR}\n")
        self.assertStale(self.run_status(), "TTL")

    def test_future_timestamp_is_stale(self):
        """Clock skew must not be able to extend a skip past the TTL."""
        self.write(f"{KEY} {NOW + 10 * HOUR}\n")
        self.assertStale(self.run_status(), "future")

    # --- overrides ---------------------------------------------------------
    def test_gate_force_overrides_a_valid_marker(self):
        self.write(f"{KEY} {NOW}\n")
        self.assertStale(self.run_status(env={"GATE_FORCE": "1"}), "GATE_FORCE=1")

    def test_custom_ttl_is_honoured(self):
        self.write(f"{KEY} {NOW - 5 * HOUR}\n")
        self.assertFresh(self.run_status(env={"GATE_TTL_HOURS": "8"}))
        self.assertStale(self.run_status(env={"GATE_TTL_HOURS": "4"}), "TTL")

    def test_unknown_argument_is_an_error_not_a_verdict(self):
        r = subprocess.run(
            ["bash", str(SCRIPT), "--nope"], capture_output=True, text=True, check=False
        )
        self.assertEqual(r.returncode, 2)
        self.assertNotIn("FRESH", r.stdout)

    def test_trailing_fields_do_not_break_parsing(self):
        """A field appended to the marker by a later version must not break parsing."""
        self.write(f"{KEY} {NOW} extra-future-field\n")
        self.assertFresh(self.run_status())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
