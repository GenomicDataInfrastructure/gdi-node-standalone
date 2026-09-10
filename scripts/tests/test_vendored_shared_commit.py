#!/usr/bin/env python3
"""Guard: the two beacon-v2 vendored sets, framework and default model, pin one commit.

They vendor different paths of the same `ga4gh-beacon/beacon-v2` commit. A re-vendor that
bumps one VENDORED.md and forgets the other leaves framework and model at different
upstream commits while `check` and `verify` stay green, because each set is byte-identical
to its own pin. `vendored.sh` asserts the shared commit rather than documenting it, and
this exercises that shipped function against a scratch tree.
"""

import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from _helpers import SCRIPTS

VENDORED = SCRIPTS / "vendored.sh"


def _extract(name: str) -> str:
    src = VENDORED.read_text(encoding="utf-8")
    m = re.search(rf"^{re.escape(name)}\(\) \{{.*?^\}}", src, re.MULTILINE | re.DOTALL)
    assert m, f"{name} is no longer defined in vendored.sh in an extractable form"
    return m.group(0)


def _run(framework_commit: str, model_commit: str) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for rel, commit in (
            ("conformance/ga4gh-beacon-v2", framework_commit),
            ("conformance/ga4gh-beacon-v2-default-model", model_commit),
        ):
            d = root / rel
            d.mkdir(parents=True)
            (d / "VENDORED.md").write_text(
                f"# Vendored\n\n- **Repository:** `ga4gh-beacon/beacon-v2`\n- **Commit:** `{commit}`\n",
                encoding="utf-8",
            )
        script = "\n".join(
            [
                "set -uo pipefail",
                f'cd "{root}"',
                _extract("md_field"),
                _extract("check_shared_commit"),
                "check_shared_commit",
            ]
        )
        return subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True, check=False
        )


class SharedCommitTest(unittest.TestCase):
    def test_a_matching_pair_passes_and_names_the_commit(self):
        p = _run("a" * 40, "a" * 40)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("a" * 12, p.stdout)

    def test_a_mismatched_pair_fails_and_names_both(self):
        p = _run("a" * 40, "b" * 40)
        self.assertEqual(p.returncode, 1, p.stdout)
        self.assertIn("SHARED-COMMIT MISMATCH", p.stderr)
        self.assertIn("a" * 12, p.stderr)
        self.assertIn("b" * 12, p.stderr)

    def test_a_missing_commit_line_fails_rather_than_matching_empty_to_empty(self):
        # Two absent pins compare equal as empty strings; the guard must not call that OK.
        p = _run("", "")
        self.assertEqual(p.returncode, 1, p.stdout)

    def test_the_shipped_script_calls_it_from_verify_and_check(self):
        src = VENDORED.read_text(encoding="utf-8")
        verify_body = src.split("  verify)", 1)[1].split("  drift)", 1)[0]
        check_body = src.split("  check)", 1)[1].split("  verify)", 1)[0]
        self.assertIn("check_shared_commit", verify_body)
        self.assertIn("check_shared_commit", check_body)


if __name__ == "__main__":
    unittest.main()
