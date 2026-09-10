#!/usr/bin/env python3
"""Guard: `run-full.sh`'s `wait_log` finds a needle in a large log under `pipefail`.

`compose logs … | grep -q "$needle"` under `set -o pipefail` fails in reverse: grep exits
at the first match, the compose CLI dies of SIGPIPE writing the rest, the pipeline's status
is 141, and a needle that is in the log reads as absent. The e2e then fails on a working
stack. Capturing first and matching from a here-string is what avoids it.

This runs the shipped function, extracted from run-full.sh so it cannot drift, with a stub
`compose` that emits a 5 MB log carrying the needle on its first line, under the same
`set -euo pipefail` the script sets.
"""

import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from _helpers import SCRIPTS

RUN_FULL = SCRIPTS / "e2e" / "run-full.sh"


def _extract(name: str) -> str:
    src = RUN_FULL.read_text(encoding="utf-8")
    m = re.search(
        rf"^{re.escape(name)}\(\)\s*\{{.*?^\}}", src, re.MULTILINE | re.DOTALL
    )
    assert m, f"{name} is no longer defined in run-full.sh in an extractable form"
    return m.group(0)


def _run(body: str, log: Path, needle: str) -> subprocess.CompletedProcess[str]:
    # `date` is stubbed to jump 31 s per call, so the 60 s deadline computed from the first
    # call admits exactly one pass of the loop: the hit path runs once, and the miss path is
    # exercised without costing a real minute. A 61 s jump would put the first check past
    # the deadline, making the failure the stub's. The counter lives in a file, because
    # `$(date +%s)` runs the stub in a subshell where a variable's increment is lost.
    counter = log.with_suffix(".clock")
    counter.write_text("0", encoding="utf-8")
    script = (
        "set -euo pipefail\n"
        f"compose() {{ cat '{log}'; }}\n"
        'fail() { echo "FAIL: $*"; exit 7; }\n'
        f"date() {{ local n; n=$(( $(cat '{counter}') + 31 )); "
        f'echo "$n" > \'{counter}\'; echo "$n"; }}\n'
        "sleep() { :; }\n"
        f"{body}\n"
        f"wait_log {needle!r} 'the needle was not seen'\n"
        'echo "MATCHED"\n'
    )
    return subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, check=False
    )


class WaitLogTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="gdi-wait-log-"))
        cls.log = cls.tmp / "compose.log"
        with cls.log.open("w", encoding="utf-8") as fh:
            fh.write("INFO PME at-rest active (Vault-minted DEK via Transit)\n")
            filler = "INFO ingest tick nothing to do " * 8 + "\n"
            written = 0
            while written < 5 * 1024 * 1024:
                fh.write(filler)
                written += len(filler)
        cls.body = _extract("wait_log")

    @classmethod
    def tearDownClass(cls):
        subprocess.run(["rm", "-rf", str(cls.tmp)], check=False)

    def test_the_shipped_body_captures_before_matching(self):
        # The structural half, so a failure names the pipeline shape rather than SIGPIPE.
        self.assertNotRegex(
            self.body,
            r"compose logs[^\n]*\|\s*grep",
            "wait_log pipes `compose logs` straight into grep; under pipefail the compose "
            "CLI's SIGPIPE fails the pipeline on the first match",
        )

    def test_a_needle_at_the_top_of_a_5mb_log_matches_under_pipefail(self):
        proc = _run(self.body, self.log, "PME at-rest active")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("MATCHED", proc.stdout)
        self.assertNotIn("FAIL:", proc.stdout)

    def test_an_absent_needle_still_fails_with_the_message(self):
        proc = _run(self.body, self.log, "never logged")
        self.assertEqual(proc.returncode, 7, proc.stdout + proc.stderr)
        self.assertIn("FAIL: the needle was not seen", proc.stdout)


if __name__ == "__main__":
    unittest.main()
