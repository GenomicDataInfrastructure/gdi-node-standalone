#!/usr/bin/env python3
"""Guard: the fuzz crate's literal `license` cannot drift from the root workspace's.

`crates/core/fuzz` declares an empty `[workspace]` table, which makes it its own workspace
root. That root declares no `[workspace.package]`, so `license.workspace = true` does not
merely resolve to nothing — cargo refuses to parse the manifest at all. The crate therefore
carries a literal, which is a second copy of a fact the root also states, and a relicence
that edits only `[workspace.package]` would leave this crate declaring the old terms in a
repository published under the new ones.

The comparison lives in `fuzz_license_drift <fuzz-manifest> <root-manifest>`, extracted
from ci-local.sh and driven here against scratch manifests, so these tests exercise the
shipped function and cannot drift from it.

The empty-root case matters as much as the mismatch case: both sides are derived by a
regex, and a regex that stops matching would compare "" against "" and pass. That is the
shape a guard fails silently in, so it is asserted explicitly below.
"""

import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from _helpers import REPO_ROOT, SCRIPTS

CI_LOCAL = SCRIPTS / "ci-local.sh"

ROOT_OK = '[workspace.package]\nversion = "1.0.0"\nlicense = "MIT OR Apache-2.0"\n'
ROOT_NO_LICENSE = '[workspace.package]\nversion = "1.0.0"\n'


def _extract(name: str) -> str:
    src = CI_LOCAL.read_text(encoding="utf-8")
    m = re.search(
        rf"^{re.escape(name)}\(\)\s*\{{.*?^\}}", src, re.MULTILINE | re.DOTALL
    )
    assert m, f"{name} is no longer defined in ci-local.sh in an extractable form"
    return m.group(0)


def _extract_line(name: str) -> str:
    src = CI_LOCAL.read_text(encoding="utf-8")
    m = re.search(rf"^{re.escape(name)}\(\)\s+\{{.*\}}$", src, re.MULTILINE)
    assert m, f"{name} is no longer a one-line function in ci-local.sh"
    return m.group(0)


def run_guard(
    fuzz_toml: str, root_toml: str = ROOT_OK
) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory(prefix="gdi-fuzz-license-") as tmp:
        fuzz = Path(tmp) / "fuzz.toml"
        root = Path(tmp) / "root.toml"
        fuzz.write_text(fuzz_toml, encoding="utf-8")
        root.write_text(root_toml, encoding="utf-8")
        # The shipped `die`, not a stub, so the death tests assert the shipped convention:
        # a message on stderr and a non-zero exit.
        script = "\n".join(
            [
                "C_ERR=''; C_OFF=''",
                _extract_line("die"),
                _extract("fuzz_license_drift"),
                f"fuzz_license_drift '{fuzz}' '{root}'",
            ]
        )
        return subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True, check=False
        )


FUZZ_OK = '[package]\nname = "fuzz"\nlicense = "MIT OR Apache-2.0"\n\n[workspace]\n'


class FuzzLicenseDriftTest(unittest.TestCase):
    def test_matching_licence_passes_and_names_it(self):
        proc = run_guard(FUZZ_OK)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("MIT OR Apache-2.0", proc.stdout)

    def test_a_drifted_licence_is_fatal(self):
        proc = run_guard(
            '[package]\nname = "fuzz"\nlicense = "Apache-2.0"\n\n[workspace]\n'
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("Apache-2.0", proc.stderr)
        self.assertIn("MIT OR Apache-2.0", proc.stderr)

    def test_a_missing_fuzz_licence_is_fatal_and_names_the_value_to_add(self):
        proc = run_guard('[package]\nname = "fuzz"\n\n[workspace]\n')
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("cannot inherit", proc.stderr)
        self.assertIn("MIT OR Apache-2.0", proc.stderr)

    def test_an_unreadable_root_licence_is_fatal_rather_than_a_vacuous_pass(self):
        # The failure this exists for: if the root regex stops matching, both sides are ""
        # and a naive equality check reports success having compared nothing.
        proc = run_guard(FUZZ_OK, root_toml=ROOT_NO_LICENSE)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("compare nothing", proc.stderr)

    def test_the_shipped_manifests_agree(self):
        # Not a scratch fixture: the actual pair the gate runs against, so this file fails
        # if the repository itself drifts, not only if the parser does.
        fuzz = (REPO_ROOT / "crates/core/fuzz/Cargo.toml").read_text(encoding="utf-8")
        root = (REPO_ROOT / "Cargo.toml").read_text(encoding="utf-8")
        proc = run_guard(fuzz, root_toml=root)
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
