#!/usr/bin/env python3
"""Tests for scripts/dev-reset.sh: argument handling, dry-run safety, completeness.

The script destroys every dev volume, so the properties that matter are:

  1. it cannot destroy anything without an explicit --yes;
  2. --dry-run performs no destructive call, though read-only discovery is fine;
  3. a --yes run removes the overlay volumes too, not just the base file's, because
     `docker compose down -v` against the base leaves prometheus, loki, tempo and
     grafana behind;
  4. if any volume survives, the script fails rather than reporting success.

All four are asserted by running the real script with a stubbed `docker` on PATH that
records its invocations. The stub is stateful: `volume ls` keeps reporting volumes until a
`volume rm` happens, which is how the real thing behaves and is what exercises the
script's sweep-then-verify path.
"""

import os
import pathlib
import subprocess
import tempfile
import unittest

from _helpers import SCRIPTS

SCRIPT = SCRIPTS / "dev-reset.sh"

# `compose down -v` does not clear the marker, because it does not remove overlay
# volumes: the script's own sweep is what finishes the job.
STUB = """#!/bin/sh
echo "$@" >> "$DOCKER_CALLS"
case "$1 $2" in
  "volume ls")
      [ -f "$STUB_STATE/removed" ] && exit 0
      echo proj_datasets
      echo proj_prometheus-data
      exit 0 ;;
  "volume rm")
      touch "$STUB_STATE/removed"; exit 0 ;;
  "ps -a")
      [ -f "$STUB_STATE/removed" ] && exit 0
      echo proj-openbao-1
      exit 0 ;;
esac
exit 0
"""

# Never clears state: every `volume ls` keeps reporting volumes, simulating a
# removal that silently failed.
STUB_NEVER_REMOVES = """#!/bin/sh
echo "$@" >> "$DOCKER_CALLS"
case "$1 $2" in
  "volume ls") echo proj_datasets; exit 0 ;;
  "ps -a")     echo proj-openbao-1; exit 0 ;;
esac
exit 0
"""


class DevResetTest(unittest.TestCase):
    def run_script(self, *args, stub=STUB):
        tmp = tempfile.mkdtemp()
        bindir = pathlib.Path(tmp) / "bin"
        bindir.mkdir()
        state = pathlib.Path(tmp) / "state"
        state.mkdir()
        docker = bindir / "docker"
        docker.write_text(stub)
        docker.chmod(0o755)
        calls = pathlib.Path(tmp) / "calls.txt"
        calls.write_text("")
        env = dict(os.environ)
        env["PATH"] = f"{bindir}:{env['PATH']}"
        env["DOCKER_CALLS"] = str(calls)
        env["STUB_STATE"] = str(state)
        proc = subprocess.run(
            ["sh", str(SCRIPT), *args],
            capture_output=True,
            text=True,
            env=env,
            cwd=tmp,
            # The non-zero exits are the assertions here, so a raising `check=True` would
            # invert the test. Passed explicitly for ruff PLW1510.
            check=False,
        )
        return proc, calls.read_text()

    @staticmethod
    def destructive(calls):
        """The calls that actually destroy something."""
        return [
            line
            for line in calls.splitlines()
            if line.startswith("compose down") or line.startswith("volume rm")
        ]

    def test_refuses_without_yes(self):
        proc, calls = self.run_script()
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(self.destructive(calls), [])

    def test_dry_run_makes_no_destructive_call(self):
        proc, calls = self.run_script("--dry-run")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.destructive(calls), [])

    def test_dry_run_lists_the_discovered_volumes(self):
        proc, _ = self.run_script("--dry-run")
        self.assertIn("proj_datasets", proc.stdout)
        self.assertIn("proj_prometheus-data", proc.stdout)

    def test_dry_run_lists_the_discovered_containers(self):
        proc, _ = self.run_script("--dry-run")
        self.assertIn("proj-openbao-1", proc.stdout)

    def test_yes_tears_down_and_sweeps_overlay_volumes(self):
        proc, calls = self.run_script("--yes")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(any(c.startswith("compose down") for c in calls.splitlines()))
        self.assertIn("-v", calls)
        # `down -v` leaves overlay volumes behind, so the sweep must happen.
        self.assertTrue(
            any(c.startswith("volume rm") for c in calls.splitlines()),
            f"expected a sweeping `volume rm`, got:\n{calls}",
        )

    def test_fails_loudly_when_volumes_survive(self):
        proc, _ = self.run_script("--yes", stub=STUB_NEVER_REMOVES)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("could not be removed", proc.stderr)

    def test_keys_kept_by_default_and_said_so(self):
        proc, _ = self.run_script("--dry-run")
        self.assertIn("compose/keys", proc.stdout)
        self.assertIn("KEPT", proc.stdout)

    def test_unknown_argument_is_rejected(self):
        proc, calls = self.run_script("--wipe-everything")
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(self.destructive(calls), [])


if __name__ == "__main__":
    unittest.main()
