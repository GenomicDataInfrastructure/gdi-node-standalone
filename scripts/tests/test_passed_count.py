#!/usr/bin/env python3
"""Non-triviality tests for ``parse_passed_count`` / ``assert_ignored_count``.

These two are the gate's vacuity detectors. Several legs assert "this step ran N tests",
so that a renamed binary, a dropped ``-p`` selector or an un-``#[ignore]``d test cannot
leave a leg green having run nothing.

``parse_passed_count``'s own failure mode is to return 0, which is indistinguishable from
the "ran nothing" condition it exists to detect. A parser that handles only one of the two
log formats, or that reads one test binary's count instead of the sum of all of them, is
therefore silent.

The function bodies, ``die`` included, are extracted from ``ci-local.sh`` rather than
restated here, so these tests exercise the shipped code and cannot drift from it.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _helpers import SCRIPTS

CI_LOCAL = SCRIPTS / "ci-local.sh"


def _extract(name: str) -> str:
    """The shipped text of one shell function, from ``ci-local.sh``."""
    src = CI_LOCAL.read_text(encoding="utf-8")
    m = re.search(rf"^{re.escape(name)}\(\) \{{.*?^\}}", src, re.MULTILINE | re.DOTALL)
    assert m, (
        f"{name} is no longer defined in ci-local.sh in a form this test can extract; "
        "it was renamed or reformatted, and this guard is now testing nothing"
    )
    return m.group(0)


def _run(body: str, call: str, log_text: str) -> subprocess.CompletedProcess[str]:
    """Run `call` against the shipped function bodies, including the shipped `die`.

    `die` is extracted from ci-local.sh rather than stubbed, so the death tests assert the
    shipped exit code and stderr conventions rather than a stub's. Only the colour
    variables `die` interpolates are supplied, and they are supplied empty so the message
    assertions match plain text.
    """
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as fh:
        fh.write(log_text)
        log = fh.name
    script = (
        f"C_ERR=''; C_OFF=''\n{_extract_line('die')}\n{body}\n{call.format(log=log)}\n"
    )
    try:
        return subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True, check=False
        )
    finally:
        # `delete=False` means nothing removes the log; each case cleans up its own.
        Path(log).unlink(missing_ok=True)


def _extract_line(name: str) -> str:
    """The shipped text of a one-line shell function, from ``ci-local.sh``."""
    src = CI_LOCAL.read_text(encoding="utf-8")
    m = re.search(rf"^{re.escape(name)}\(\)\s+\{{.*\}}$", src, re.MULTILINE)
    assert m, (
        f"{name} is no longer a one-line function in ci-local.sh; this guard would "
        "otherwise fall back to testing a stub of its own conventions"
    )
    return m.group(0)


class ParsePassedCountTests(unittest.TestCase):
    BODY = _extract("parse_passed_count")

    def test_libtest_counts_are_summed_across_binaries(self) -> None:
        """libtest prints one result line per test binary. Taking only the last
        under-reports by the whole rest of the suite."""
        log = (
            "test result: ok. 1319 passed; 0 failed\n"
            "test result: ok. 8 passed; 0 failed\n"
        )
        out = _run(self.BODY, 'parse_passed_count "{log}"', log)
        self.assertEqual(out.stdout.strip(), "1327", out.stderr)

    def test_a_nextest_summary_is_read(self) -> None:
        """A parser that handles only libtest reads a nextest summary as 0, which is
        indistinguishable from "this leg ran nothing".

        The fixture keeps run != passed, so it also pins which of the two numbers is read.
        Skipped tests are not part of the run total, so the counts below are a shape
        nextest can actually emit.
        """
        log = "     Summary [  30.147s] 1927 tests run: 1926 passed, 1 failed, 10 skipped\n"
        out = _run(self.BODY, 'parse_passed_count "{log}"', log)
        self.assertNotEqual(
            out.stdout.strip(), "0", "a nextest summary must not parse as zero"
        )
        # The count answers "did this leg run anything?", so `tests run` is the right
        # quantity rather than `passed`: a leg whose tests all failed still ran.
        self.assertEqual(out.stdout.strip(), "1927", out.stderr)

    def test_a_clean_nextest_summary_is_read(self) -> None:
        """The all-green shape, which is what every passing leg prints.

        The fixture above discriminates run from passed. This one is the shape the gate
        sees on every green run, so a parser that handled only the `N failed` variant
        would break every leg while that test stayed green.
        """
        log = "     Summary [  30.147s] 1927 tests run: 1927 passed, 10 skipped\n"
        out = _run(self.BODY, 'parse_passed_count "{log}"', log)
        self.assertEqual(out.stdout.strip(), "1927", out.stderr)

    def test_a_log_with_no_result_line_is_zero(self) -> None:
        """The control: a genuinely empty run must still read 0, so the two cases above
        are distinguishing formats rather than a parser that always finds something."""
        out = _run(
            self.BODY, 'parse_passed_count "{log}"', "compiling...\nnothing here\n"
        )
        self.assertEqual(out.stdout.strip(), "0", out.stderr)


class AssertIgnoredCountTests(unittest.TestCase):
    BODY = _extract("parse_passed_count") + "\n" + _extract("assert_ignored_count")

    def test_a_mismatched_count_dies(self) -> None:
        log = "test result: ok. 1 passed; 0 failed\n"
        out = _run(self.BODY, 'assert_ignored_count 2 "{log}" leg', log)
        self.assertNotEqual(out.returncode, 0, "a count mismatch must fail the leg")
        self.assertIn("ran 1 ignored tests, expected 2", out.stderr)

    def test_a_zero_count_dies(self) -> None:
        """The leg ran nothing and must not pass.

        `assertNotEqual(returncode, 0)` alone is satisfied by any breakage of this harness:
        a bash syntax error, a missing `die`, an unreadable log. The stderr assertion is
        what separates "the guard fired" from "the guard never ran".
        """
        out = _run(self.BODY, 'assert_ignored_count 1 "{log}" leg', "no tests here\n")
        self.assertNotEqual(out.returncode, 0, "'ran nothing' must fail the leg")
        self.assertIn("ran 0 ignored tests, expected 1", out.stderr)

    def test_a_matching_count_passes(self) -> None:
        """Without this control, an `assert_ignored_count` that died on everything would
        satisfy both tests above while being useless."""
        log = "test result: ok. 1 passed; 0 failed\n"
        out = _run(self.BODY, 'assert_ignored_count 1 "{log}" leg', log)
        self.assertEqual(out.returncode, 0, out.stderr)


if __name__ == "__main__":
    unittest.main()
