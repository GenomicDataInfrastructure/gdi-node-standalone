#!/usr/bin/env python3
"""Guard: the fuzz-crate pin comparison reads both TOML shapes and cannot skip a pin.

`crates/core/fuzz` is its own workspace and cannot inherit `[workspace.dependencies]`, so
every dep it shares with the root is a second copy of that version, and `fuzz_smoke`
compares the copies before compiling. A comparison that knows only `name = "=1.2.3"` drops
a pin written as `name = { version = "=1.2.3", … }`, and a counter that fires only when
every pin vanishes does not notice.

The comparison lives in `fuzz_pin_drift <fuzz-manifest> <root-manifest>`, extracted from
ci-local.sh and driven here against scratch manifests, so these tests exercise the shipped
function and cannot drift from it.
"""

import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from _helpers import SCRIPTS

CI_LOCAL = SCRIPTS / "ci-local.sh"

ROOT = """[workspace.dependencies]
serde_json = "=1.0.151"
serde-saphyr = "=1.1.0"
tempfile = { version = "=3.27.0", default-features = false }
"""


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


def run_guard(fuzz_toml: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory(prefix="gdi-fuzz-pins-") as tmp:
        fuzz = Path(tmp) / "fuzz.toml"
        root = Path(tmp) / "root.toml"
        fuzz.write_text(fuzz_toml, encoding="utf-8")
        root.write_text(ROOT, encoding="utf-8")
        # The shipped `die` and `assert_positive` rather than stubs, so the death tests
        # assert the shipped conventions: a message on stderr and a non-zero exit.
        script = "\n".join(
            [
                "C_ERR=''; C_OFF=''",
                _extract_line("die"),
                _extract("assert_positive"),
                _extract("fuzz_pin_drift"),
                f"fuzz_pin_drift '{fuzz}' '{root}'",
            ]
        )
        return subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True, check=False
        )


class FuzzPinDriftTest(unittest.TestCase):
    def test_matching_pins_in_both_shapes_pass_and_are_counted(self):
        proc = run_guard(
            '[package]\nname = "fuzz"\nversion = "0.0.0"\n\n'
            '[dependencies]\nlibfuzzer-sys = "=0.4.13"\n'
            'serde_json = "=1.0.151"\n'
            'serde-saphyr = { version = "=1.1.0", default-features = false }\n'
            'tempfile = "=3.27.0"\n\n'
            '[dependencies.gdi-node-standalone-core]\npath = ".."\n'
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("ok: 3 shared fuzz pin(s) agree", proc.stdout)

    def test_a_drifted_pin_in_table_form_is_reported(self):
        # Table form, two majors behind the root.
        proc = run_guard(
            "[dependencies]\n"
            'serde_json = { version = "=1.0.151" }\n'
            'serde-saphyr = { version = "=0.0.27", default-features = false }\n'
            'tempfile = "=3.27.0"\n'
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn(
            "serde-saphyr: fuzz pins =0.0.27 but the root workspace pins =1.1.0",
            proc.stdout,
        )
        self.assertIn("drifted", proc.stderr)

    def test_a_drifted_pin_in_sub_table_form_is_reported(self):
        # `[dependencies.<crate>]` with its own `version` line, which must not be taken
        # for a path dependency and skipped.
        proc = run_guard(
            "[dependencies]\n"
            'tempfile = "=3.27.0"\n'
            "\n"
            "[dependencies.serde-saphyr]\n"
            'version = "=0.0.27"\n'
            "default-features = false\n"
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn(
            "serde-saphyr: fuzz pins =0.0.27 but the root workspace pins =1.1.0",
            proc.stdout,
        )

    def test_a_sub_table_without_a_version_is_a_path_dependency_and_skipped(self):
        proc = run_guard(
            "[dependencies]\n"
            'serde_json = "=1.0.151"\n'
            "\n"
            "[dependencies.serde-saphyr]\n"
            'path = "../saphyr"\n'
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_a_shared_pin_the_parser_cannot_read_is_fatal_not_skipped(self):
        # A shape neither regex knows, for a dep the root pins: it must die naming the
        # dep, because skipping is how an unreadable pin escapes the comparison.
        proc = run_guard(
            '[dependencies]\nserde_json = "=1.0.151"\n'
            'serde-saphyr.version = "=1.1.0"\n'
            'tempfile = "=3.27.0"\n'
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("could not read the pin for: serde-saphyr", proc.stderr)

    def test_comparing_nothing_is_fatal(self):
        proc = run_guard('[dependencies]\nlibfuzzer-sys = "=0.4.13"\n')
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("counted 0", proc.stderr)

    def test_the_real_manifests_agree(self):
        # The guard run against the tree it ships in, so a drift is red here and not only
        # in the compile leg.
        fuzz = (SCRIPTS.parent / "crates" / "core" / "fuzz" / "Cargo.toml").read_text(
            encoding="utf-8"
        )
        root = (SCRIPTS.parent / "Cargo.toml").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory(prefix="gdi-fuzz-pins-") as tmp:
            f = Path(tmp) / "fuzz.toml"
            r = Path(tmp) / "root.toml"
            f.write_text(fuzz, encoding="utf-8")
            r.write_text(root, encoding="utf-8")
            script = "\n".join(
                [
                    "C_ERR=''; C_OFF=''",
                    _extract_line("die"),
                    _extract("assert_positive"),
                    _extract("fuzz_pin_drift"),
                    f"fuzz_pin_drift '{f}' '{r}'",
                ]
            )
            proc = subprocess.run(
                ["bash", "-c", script], capture_output=True, text=True, check=False
            )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertRegex(proc.stdout, r"ok: [1-9]\d* shared fuzz pin\(s\) agree")


if __name__ == "__main__":
    unittest.main()
