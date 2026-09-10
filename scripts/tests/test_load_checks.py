#!/usr/bin/env python3
"""Tests for ``scripts/load/checks.py``, the load harness's pass/fail assertions.

The harness exists to catch two regressions: requests failing under a light load, and
the load-shed arm not tripping under saturation. Both assertions read
``statusCodeDistribution`` out of oha's JSON. If that map is ever empty or absent (an
oha schema change, or a run whose only outcomes were transport errors recorded under
``errorDistribution``), a "no non-2xx responses" test passes vacuously and the harness
prints OK while proving nothing.

Every assertion here must fail CLOSED on an empty or missing distribution.

Pure stdlib. Run: ``python3 -m unittest discover -s scripts/tests -p 'test_*.py'``
"""

import unittest

from _helpers import load_module

checks = load_module("scripts/load/checks.py", "load_checks")


def report(codes, **extra):
    d = {"summary": {"requestsPerSec": 1234.0}, "latencyPercentiles": {"p99": 0.01}}
    if codes is not None:
        d["statusCodeDistribution"] = codes
    d.update(extra)
    return d


class Baseline(unittest.TestCase):
    """Under the concurrency limit every response must be 2xx, and must be observed."""

    def test_all_2xx_passes(self):
        ok, _ = checks.check_baseline(report({"200": 500}))
        self.assertTrue(ok)

    def test_a_non_2xx_fails(self):
        ok, msg = checks.check_baseline(report({"200": 499, "500": 1}))
        self.assertFalse(ok)
        self.assertIn("500", msg)

    def test_empty_distribution_fails_closed(self):
        """An empty distribution must not pass vacuously."""
        ok, msg = checks.check_baseline(report({}))
        self.assertFalse(ok)
        self.assertIn("no status codes", msg.lower())

    def test_missing_distribution_fails_closed(self):
        ok, msg = checks.check_baseline(report(None))
        self.assertFalse(ok)
        self.assertIn("no status codes", msg.lower())

    def test_only_non_2xx_fails(self):
        ok, _ = checks.check_baseline(report({"503": 10}))
        self.assertFalse(ok)

    def test_zero_counts_fail_closed(self):
        """A present-but-all-zero map has no successful request to vouch for."""
        ok, _ = checks.check_baseline(report({"200": 0}))
        self.assertFalse(ok)


class Saturation(unittest.TestCase):
    """Over the limit the load-shed arm must return at least one 503."""

    def test_shed_observed_passes(self):
        ok, _ = checks.check_saturation(report({"200": 100, "503": 7}))
        self.assertTrue(ok)

    def test_no_shed_fails(self):
        ok, _ = checks.check_saturation(report({"200": 100}))
        self.assertFalse(ok)

    def test_empty_distribution_fails_closed(self):
        ok, msg = checks.check_saturation(report({}))
        self.assertFalse(ok)
        self.assertIn("no status codes", msg.lower())

    def test_missing_distribution_fails_closed(self):
        ok, _ = checks.check_saturation(report(None))
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
