#!/usr/bin/env python3
"""Guard: the load and soak harnesses rebuild their release binaries on every run.

They used to build only when a binary was missing, so a stale target/release from an
older checkout got tested instead of the current code. This runs `release_bins`
(scripts/lib/release-bins.sh) with a stub `cargo` on PATH and checks when it builds and
what NODE and TOOL end up as.
"""

import os
import pathlib
import subprocess
import tempfile
import unittest

from _helpers import SCRIPTS

LIB = SCRIPTS / "lib" / "release-bins.sh"
HARNESSES = [
    SCRIPTS / "load" / "run.sh",
    SCRIPTS / "soak" / "leak.sh",
    SCRIPTS / "soak" / "crash-loop.sh",
]
BUILD_ARGS = (
    "build --release --locked --bins -p gdi-node-standalone -p gdi-dataset-tool"
)


class ReleaseBinsTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="gdi-release-bins-")
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name) / "repo"
        release = self.root / "target" / "release"
        release.mkdir(parents=True)
        # Already built: the case the old "build if missing" check skipped.
        for name in ("gdi-node-standalone", "gdi-dataset-tool"):
            (release / name).write_text("#!/bin/sh\n")
            (release / name).chmod(0o755)
        stub_dir = pathlib.Path(tmp.name) / "bin"
        stub_dir.mkdir()
        self.cargo_log = pathlib.Path(tmp.name) / "cargo.log"
        stub = stub_dir / "cargo"
        stub.write_text('#!/bin/sh\nprintf \'%s\\n\' "$*" >> "$CARGO_LOG"\n')
        stub.chmod(0o755)
        self.path = f"{stub_dir}{os.pathsep}{os.environ.get('PATH', '')}"

    def run_release_bins(self, **given) -> dict:
        env = {
            k: v
            for k, v in os.environ.items()
            if k not in ("NODE", "TOOL", "CARGO_LOG", "CARGO_TARGET_DIR")
        }
        env.update(PATH=self.path, CARGO_LOG=str(self.cargo_log), **given)
        script = (
            'set -euo pipefail; ROOT="$1"; cd "$ROOT"; . "$2"; release_bins; '
            'printf "NODE=%s\\nTOOL=%s\\n" "$NODE" "$TOOL"'
        )
        proc = subprocess.run(
            ["bash", "-c", script, "release-bins-test", str(self.root), str(LIB)],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return dict(
            line.split("=", 1) for line in proc.stdout.splitlines() if "=" in line
        )

    def cargo_calls(self) -> list[str]:
        if not self.cargo_log.exists():
            return []
        return self.cargo_log.read_text().splitlines()

    def test_builds_even_when_the_binaries_already_exist(self):
        out = self.run_release_bins()
        self.assertEqual(self.cargo_calls(), [BUILD_ARGS])
        self.assertEqual(out["NODE"], f"{self.root}/target/release/gdi-node-standalone")
        self.assertEqual(out["TOOL"], f"{self.root}/target/release/gdi-dataset-tool")

    def test_both_binaries_given_skips_the_build(self):
        out = self.run_release_bins(NODE="/opt/node", TOOL="/opt/tool")
        self.assertEqual(self.cargo_calls(), [])
        self.assertEqual((out["NODE"], out["TOOL"]), ("/opt/node", "/opt/tool"))

    def test_one_binary_given_still_builds_the_other(self):
        out = self.run_release_bins(NODE="/opt/node")
        self.assertEqual(self.cargo_calls(), [BUILD_ARGS])
        self.assertEqual(out["NODE"], "/opt/node")
        self.assertEqual(out["TOOL"], f"{self.root}/target/release/gdi-dataset-tool")

    def test_a_target_dir_from_the_environment_is_where_it_looks(self):
        # cargo builds into CARGO_TARGET_DIR; reading $ROOT/target would run a stale binary.
        elsewhere = self.root.parent / "elsewhere"
        out = self.run_release_bins(CARGO_TARGET_DIR=str(elsewhere))
        self.assertEqual(out["NODE"], f"{elsewhere}/release/gdi-node-standalone")
        self.assertEqual(out["TOOL"], f"{elsewhere}/release/gdi-dataset-tool")

    def test_every_harness_calls_it(self):
        for path in HARNESSES:
            with self.subTest(script=path.name):
                lines = [
                    line.strip()
                    for line in path.read_text(encoding="utf-8").splitlines()
                    if not line.lstrip().startswith("#")
                ]
                self.assertIn("release_bins", lines, f"{path} never calls release_bins")


if __name__ == "__main__":
    unittest.main()
