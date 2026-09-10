#!/usr/bin/env python3
"""Guard: a leg that skips on a missing tool says so, and cannot skip under `release`.

`promtool test rules` is the only thing that proves an alert can fire, so it belongs in
`all`. `all` must stay runnable without Docker, so a missing `docker` records a visible
skip rather than dying. Three properties make that honest:

  1. with `docker` shadowed off PATH, `ci-local.sh promtool` exits 0 and prints the
     distinctive `SKIPPED: promtool (docker not installed — alert rules NOT checked)`
     line, and the final summary is not a bare "passed";
  2. under GATE_STRICT_LEGS=1, which `release` exports, the same run dies and the SKIPPED
     line does not appear; likewise on a CI runner (`CI` set);
  3. `promtool` is in ALL_LEGS at all.

The script is executed rather than grepped: the skip line comes from the shipped
`skip_unless` and `record_skip`, on a PATH built from every executable the real PATH holds
except `docker`. The test therefore needs no Docker and cannot pass by accident on a
machine that has it.
"""

import os
import pathlib
import re
import subprocess
import tempfile
import unittest

from _helpers import REPO_ROOT, SCRIPTS, strip_comments

SCRIPT = SCRIPTS / "ci-local.sh"
SKIP_LINE = "SKIPPED: promtool (docker not installed — alert rules NOT checked)"


def shadow_path(exclude: str) -> str:
    """A directory of symlinks to every executable on PATH except `exclude`.

    Shadowing rather than prepending a stub. `command -v` finds the first executable
    match, so a non-executable decoy is skipped and an executable one is found. Only a
    PATH without the tool at all makes `command -v` fail the way an uninstalled tool does.
    """
    shadow = tempfile.mkdtemp(prefix="gdi-shadow-path-")
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        d = pathlib.Path(entry)
        if not d.is_dir():
            continue
        for f in d.iterdir():
            if f.name == exclude:
                continue
            target = shadow + os.sep + f.name
            if os.access(f, os.X_OK) and not os.path.lexists(target):
                os.symlink(f, target)
    return shadow


def run_promtool(target: str = "promtool", **extra_env) -> subprocess.CompletedProcess:
    env = {
        "HOME": os.environ.get("HOME", "/"),
        "PATH": run_promtool.shadow,
        "GATE_QUEUE": "0",
        "NO_COLOR": "1",
        **extra_env,
    }
    return subprocess.run(
        ["bash", str(SCRIPT), target],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


class PromtoolSkipTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        run_promtool.shadow = shadow_path("docker")
        # The shadow must actually lack docker, or every assertion below is about a
        # different question. It must still hold bash, which the script is run with.
        cls.assertFalse(
            cls(), os.path.exists(run_promtool.shadow + "/docker"), "docker leaked in"
        )
        cls.assertTrue(cls(), os.path.exists(run_promtool.shadow + "/bash"))

    @classmethod
    def tearDownClass(cls):
        for f in pathlib.Path(run_promtool.shadow).iterdir():
            f.unlink()
        os.rmdir(run_promtool.shadow)

    def test_without_docker_the_leg_skips_visibly_and_passes(self):
        proc = run_promtool()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(SKIP_LINE, proc.stdout)
        # Twice: once where it happened, once in the summary. A single mention at the top
        # of a long log is one a reader scrolls past.
        self.assertGreaterEqual(proc.stdout.count(SKIP_LINE), 2, proc.stdout)
        last = proc.stdout.rstrip().splitlines()[-1]
        self.assertIn("SKIPPED", last, f"the final line is a bare pass: {last!r}")
        self.assertNotRegex(last, r"passed$", "a bare 'passed' over a skipped leg")

    def test_under_the_release_flag_the_skip_is_impossible(self):
        proc = run_promtool(GATE_STRICT_LEGS="1")
        self.assertNotEqual(proc.returncode, 0, "strict mode let the leg skip")
        self.assertNotIn("SKIPPED", proc.stdout)
        self.assertIn("promtool may not be skipped", proc.stderr)
        self.assertIn("docker", proc.stderr)

    def test_on_a_ci_runner_the_skip_is_impossible_too(self):
        proc = run_promtool(CI="true")
        self.assertNotEqual(proc.returncode, 0, "CI let the leg skip")
        self.assertNotIn("SKIPPED", proc.stdout)


# The two Docker legs `all` runs: dispatch target, function name, and the skip line's
# reason. Both belong in `all`, because a leg reachable only from `release` is checked by
# nothing that runs routinely.
DOCKER_LEGS_IN_ALL = {
    "promtool": ("promtool", "alert rules NOT checked"),
    "shellcheck": ("shellcheck_lint", "shell scripts NOT linted"),
}


class DockerLegsAreInAllTest(unittest.TestCase):
    def test_every_docker_leg_is_an_all_leg(self):
        text = SCRIPT.read_text(encoding="utf-8")
        m = re.search(r"^ALL_LEGS=\((.*?)^\)", text, re.DOTALL | re.MULTILINE)
        self.assertIsNotNone(m, "could not find ALL_LEGS")
        legs = strip_comments(m.group(1)).split()
        for target, (function, _) in DOCKER_LEGS_IN_ALL.items():
            self.assertIn(
                function,
                legs,
                f"`{target}` left ALL_LEGS; it falls back to a tier nothing runs "
                "routinely, so its check stops happening",
            )

    def test_every_docker_leg_uses_skip_unless_not_need(self):
        # `need docker` would make test_ci_local_preflight.py demand Docker in
        # preflight_all, which then dies up front on exactly the Docker-less machine the
        # skip exists for.
        text = strip_comments(SCRIPT.read_text(encoding="utf-8"))
        for target, (function, _) in DOCKER_LEGS_IN_ALL.items():
            m = re.search(
                rf"^{function}\(\) \{{(.*?)^\}}", text, re.DOTALL | re.MULTILINE
            )
            self.assertIsNotNone(m, f"could not find {function}()")
            self.assertNotRegex(m.group(1), r"\bneed\s+docker\b")
            self.assertRegex(m.group(1), rf"\bskip_unless\s+docker\s+{target}\b")

    def test_without_docker_shellcheck_skips_visibly_too(self):
        # The behavioural half of the promtool suite above, for the second leg: the
        # skip line is produced by the shipped `record_skip`, on a PATH without docker.
        shadow = shadow_path("docker")
        try:
            run_promtool.shadow = shadow
            proc = run_promtool("shellcheck")
        finally:
            for f in pathlib.Path(shadow).iterdir():
                f.unlink()
            os.rmdir(shadow)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        line = "SKIPPED: shellcheck (docker not installed — shell scripts NOT linted)"
        self.assertGreaterEqual(proc.stdout.count(line), 2, proc.stdout)


class SkipsNeverRecordGreenTest(unittest.TestCase):
    """A run with a skip must not leave the marker a later run short-circuits on.

    Otherwise the next run reads FRESH, runs only the short-circuit legs, and prints a
    clean pass with no skip line for a leg that never ran. The refusal lives in
    `gate_record_green`, the one chokepoint. This drives the shipped function with a stub
    `run` and asserts it is not reached while `GATE_SKIPPED` is non-empty.
    """

    def _drive(self, skipped: str) -> subprocess.CompletedProcess:
        text = SCRIPT.read_text(encoding="utf-8")
        m = re.search(
            r"^gate_record_green\(\) \{(.*?)^\}", text, re.DOTALL | re.MULTILINE
        )
        self.assertIsNotNone(m, "could not find gate_record_green()")
        script = "\n".join(
            [
                "C_ERR=''; C_OFF=''",
                "gate_marker() { printf 'marker'; }",
                "run() { printf 'RECORDED %s\\n' \"$*\"; }",
                f"GATE_SKIPPED=({skipped})",
                "gate_record_green() {" + m.group(1) + "}",
                "gate_record_green somekey",
            ]
        )
        return subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True, check=False
        )

    def test_a_skipped_leg_blocks_the_marker(self):
        proc = self._drive("'promtool (docker not installed)'")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("RECORDED", proc.stdout)
        self.assertIn("not recording a green marker", proc.stdout)

    def test_no_skips_records_the_marker(self):
        proc = self._drive("")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("RECORDED scripts/gate-record.sh", proc.stdout)


if __name__ == "__main__":
    unittest.main()
