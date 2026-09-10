#!/usr/bin/env python3
"""Tests for ``scripts/soak/checks.py``, the soak harness's leak-trend assertions.

A soak has to tell a genuine leak, a sustained upward trend that never plateaus, apart
from healthy warmup fill, which grows during warmup and then stays flat. Comparing the
last value against the post-warmup minimum flags a blocking-pool ramp as a leak, so all
three series use the same middle-third against last-third plateau test.

Pure stdlib. Run: ``python3 -m unittest discover -s scripts/tests -p 'test_*.py'``
"""

import contextlib
import io
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

from _helpers import load_module

checks = load_module("scripts/soak/checks.py", "soak_checks")


def run_main(tsv_body: str, warmup: int = 0) -> int:
    """Drive checks.main() over a samples file and return its exit code.

    `main` is where a fail-open would live: an empty or truncated samples file must not
    read as `PASS`.

    `main` reads sys.argv and the SOAK_* env vars, so both are patched: an ambient
    SOAK_FD_TOL in the caller's shell would otherwise silently change the verdict.
    """
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp) / "samples.tsv"
        path.write_text(tsv_body, encoding="utf-8")
        with (
            mock.patch.object(sys, "argv", ["checks.py", str(path), str(warmup)]),
            mock.patch.dict(os.environ),
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            for key in [k for k in os.environ if k.startswith("SOAK_")]:
                del os.environ[key]
            return checks.main()


HEADER = "round\trss_kb\tfds\tthreads\n"


def rows(n: int, rss: int = 100_000, fds: int = 40, threads: int = 30) -> str:
    return "".join(f"{r}\t{rss}\t{fds}\t{threads}\n" for r in range(1, n + 1))


class Plateau(unittest.TestCase):
    def test_warmup_ramp_then_flat_is_not_a_leak(self):
        # threads ramp 17->30 during warmup, then stay flat at 30: a healthy blocking-pool
        # ramp. A (last - min) check flags it; the plateau check, middle third against last
        # third, must not.
        threads = [17, 20, 24, 28, 30, 30, 30, 30, 30, 30, 30, 30]
        fds = [40] * 12
        rss = [100_000] * 12
        failures = checks.leak_failures(
            rss, fds, threads, fd_tol=8, thread_tol=4, rss_plateau_frac=0.10
        )
        self.assertEqual(
            failures, [], f"a warmup ramp that plateaus is not a leak: {failures}"
        )

    def test_sustained_thread_climb_is_a_leak(self):
        # threads keep climbing through the last third: a real task or thread leak.
        threads = [20, 20, 20, 20, 24, 28, 32, 36, 40, 44, 48, 52]
        fds = [40] * 12
        rss = [100_000] * 12
        failures = checks.leak_failures(
            rss, fds, threads, fd_tol=8, thread_tol=4, rss_plateau_frac=0.10
        )
        self.assertTrue(
            any("thread" in f for f in failures),
            f"a sustained climb must fail: {failures}",
        )

    def test_sustained_fd_climb_is_a_leak(self):
        fds = [40, 40, 40, 40, 45, 50, 55, 60, 66, 72, 78, 84]
        threads = [30] * 12
        rss = [100_000] * 12
        failures = checks.leak_failures(
            rss, fds, threads, fd_tol=8, thread_tol=4, rss_plateau_frac=0.10
        )
        self.assertTrue(
            any("fd" in f for f in failures),
            f"a sustained fd climb must fail: {failures}",
        )

    def test_rss_still_climbing_is_a_leak(self):
        rss = [
            100_000,
            100_000,
            100_000,
            100_000,
            110_000,
            120_000,
            130_000,
            140_000,
            150_000,
            160_000,
            170_000,
            180_000,
        ]
        failures = checks.leak_failures(
            rss, [40] * 12, [30] * 12, fd_tol=8, thread_tol=4, rss_plateau_frac=0.10
        )
        self.assertTrue(
            any("RSS" in f or "memory" in f for f in failures),
            f"climbing RSS must fail: {failures}",
        )


class MainFailsClosed(unittest.TestCase):
    """`main` must refuse to render a verdict it cannot support.

    Each case below would otherwise print a pass and exit 0, a green soak that asserted
    nothing.
    """

    def test_a_healthy_run_still_passes(self):
        # The control. Without this the cases below could pass for the wrong reason.
        self.assertEqual(run_main(HEADER + rows(12)), 0)

    def test_header_only_file_fails_closed(self):
        self.assertNotEqual(
            run_main(HEADER), 0, "a samples file with no rows asserts nothing"
        )

    def test_truncated_run_fails_closed(self):
        self.assertNotEqual(
            run_main(HEADER + rows(4)),
            0,
            f"fewer than {checks.MIN_SAMPLES} post-warmup rounds cannot support a "
            "plateau verdict",
        )

    def test_warmup_consuming_every_row_fails_closed(self):
        # 12 rows but warmup=11 leaves one measured round.
        self.assertNotEqual(run_main(HEADER + rows(12), warmup=11), 0)

    def test_a_dead_node_fails_closed(self):
        # leak.sh's /proc reads fall back to 0 once the process is gone, so a crash looks
        # like a perfectly flat series, which every plateau test passes.
        self.assertNotEqual(
            run_main(HEADER + rows(12, rss=0, fds=0, threads=0)),
            0,
            "an all-zero series is a dead process, not a healthy plateau",
        )

    def test_a_node_that_died_partway_fails_closed(self):
        self.assertNotEqual(run_main(HEADER + rows(12, rss=0)), 0)


if __name__ == "__main__":
    unittest.main()
