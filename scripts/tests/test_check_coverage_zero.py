#!/usr/bin/env python3
"""Guard for `check-coverage-zero.py`: the properties it must not lose.

The check's job is to notice absence, so the cases below are the ones where it could stop
noticing: an empty report, a file it cannot read, and a percentage of exactly zero against
a missing percentage.

Pure stdlib, like every other guard suite here.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from _helpers import load_module

ccz = load_module("scripts/check-coverage-zero.py", "check_coverage_zero")


def report(*files: tuple[str, float]) -> dict:
    """An llvm-cov-shaped report from (filename, region-percent) pairs."""
    return {
        "data": [
            {
                "files": [
                    {"filename": name, "summary": {"regions": {"percent": pct}}}
                    for name, pct in files
                ]
            }
        ]
    }


class ZeroCoverageDetection(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        src = self.root / "crates" / "demo" / "src"
        src.mkdir(parents=True)
        # Comfortably over MIN_LINES, so size never masks the coverage verdict.
        (src / "big.rs").write_text("\n".join(f"// line {i}" for i in range(200)))
        (src / "tiny.rs").write_text("// one line\n")
        self.addCleanup(self._tmp.cleanup)

    def test_zero_percent_file_is_reported(self) -> None:
        got = ccz.zero_covered_files(
            report(("/x/crates/demo/src/big.rs", 0.0)), self.root
        )
        self.assertEqual(len(got), 1, got)
        self.assertIn("demo/src/big.rs", got[0])

    def test_covered_file_is_not_reported(self) -> None:
        got = ccz.zero_covered_files(
            report(("/x/crates/demo/src/big.rs", 0.4)), self.root
        )
        self.assertEqual(got, [])

    def test_small_file_is_exempt_by_size(self) -> None:
        got = ccz.zero_covered_files(
            report(("/x/crates/demo/src/tiny.rs", 0.0)), self.root
        )
        self.assertEqual(got, [])

    def test_missing_percent_is_not_treated_as_zero(self) -> None:
        # A report shape change that drops `percent` must not read as "0% covered" and
        # fail every file, turning a schema drift into a wall of false positives.
        entry = {"filename": "/x/crates/demo/src/big.rs", "summary": {"regions": {}}}
        got = ccz.zero_covered_files({"data": [{"files": [entry]}]}, self.root)
        self.assertEqual(got, [])

    def test_test_and_bench_sources_are_ignored(self) -> None:
        got = ccz.zero_covered_files(
            report(
                ("/x/crates/demo/tests/it/foo.rs", 0.0),
                ("/x/crates/demo/benches/bar.rs", 0.0),
            ),
            self.root,
        )
        self.assertEqual(got, [])

    def test_unreadable_file_still_counts(self) -> None:
        # A path in the report that is not on disk must not be skipped: skipping is how a
        # renamed file leaves the check unnoticed.
        got = ccz.zero_covered_files(
            report(("/x/crates/demo/src/gone.rs", 0.0)), self.root
        )
        self.assertEqual(len(got), 1, got)

    def test_allowlisted_path_is_exempt(self) -> None:
        self.assertTrue(
            ccz.ALLOWLIST, "the allowlist should carry its entries with reasons"
        )
        for path, reason in ccz.ALLOWLIST.items():
            self.assertTrue(reason.strip(), f"{path} is allowlisted without a reason")
            got = ccz.zero_covered_files(report((f"/x/{path}", 0.0)), self.root)
            self.assertEqual(got, [], f"{path} is allowlisted but was reported")


class BrokenRunDetection(unittest.TestCase):
    """An empty report is a failed measurement, not a clean result."""

    def test_empty_report_exits_nonzero(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"data": [{"files": []}]}, fh)
            path = fh.name
        self.assertEqual(ccz.main(["check-coverage-zero.py", path]), 2)

    def test_missing_file_exits_nonzero(self) -> None:
        self.assertEqual(ccz.main(["check-coverage-zero.py", "/nonexistent.json"]), 2)


if __name__ == "__main__":
    unittest.main()
