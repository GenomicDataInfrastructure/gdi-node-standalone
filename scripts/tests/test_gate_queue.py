#!/usr/bin/env python3
"""Unit tests for ``scripts/gate-queue.sh``, the one-gate-at-a-time slot.

Overlapping gates do not share the machine, they thrash it. Three equal gates under
processor sharing all finish at about 3T; queued FIFO they finish at T, 2T and 3T. Same
total work, earlier verdicts, and the wait is visible instead of being spent inside a long
"still compiling".

The wrapper is generic (``--lock <file> -- <command>``), so it can be exercised here with
``sleep`` instead of a full gate. ``ci-local.sh`` re-execs itself under it for the heavy
targets, and ``test_gate_queue_wiring.py`` pins which ones. Pure stdlib.
"""

import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from _helpers import SCRIPTS

SCRIPT = SCRIPTS / "gate-queue.sh"


def stamp(path: Path, tag: str) -> str:
    """A shell fragment appending `<tag> <monotonic-ish seconds>` to `path`."""
    return f"printf '%s %s\\n' {tag} \"$(date +%s.%N)\" >> {path}"


def stamps(path: Path) -> dict[str, float]:
    out = {}
    for line in path.read_text().splitlines():
        tag, when = line.split()
        out[tag] = float(when)
    return out


class GateQueueTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.lock = self.dir / "gate.lock"

    def tearDown(self):
        self.tmp.cleanup()

    def launch(self, *command, label="wt", env=None, heartbeat=None):
        e = {k: v for k, v in os.environ.items() if not k.startswith("GATE_")}
        if heartbeat is not None:
            e["GATE_QUEUE_HEARTBEAT"] = str(heartbeat)
        e.update(env or {})
        return subprocess.Popen(
            [
                "bash",
                str(SCRIPT),
                "--lock",
                str(self.lock),
                "--label",
                label,
                "--",
                *command,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=e,
        )

    def run_queue(self, *command, **kw):
        p = self.launch(*command, **kw)
        out, err = p.communicate(timeout=60)
        return p.returncode, out, err

    # --- uncontended ------------------------------------------------------
    def test_uncontended_run_is_silent_and_exports_a_zero_wait(self):
        rc, out, err = self.run_queue("sh", "-c", 'echo "wait=$GATE_QUEUE_WAIT"')
        self.assertEqual(rc, 0, err)
        self.assertIn("wait=0", out)
        self.assertNotIn("queued", out + err)

    def test_command_exit_status_is_propagated(self):
        rc, _, _ = self.run_queue("sh", "-c", "exit 7")
        self.assertEqual(rc, 7)

    def test_holder_line_names_the_pid_and_the_label(self):
        rc, out, _ = self.run_queue(
            "sh", "-c", f'cat "{self.lock}"; echo "pid=$$"', label="/some/worktree"
        )
        self.assertEqual(rc, 0)
        # The wrapper execs the command, so the command's own pid is the holder's pid.
        pid = out.split("pid=")[-1].strip()
        self.assertIn(f"pid={pid}", out)
        self.assertIn("label=/some/worktree", out)

    def test_slot_is_free_again_once_the_command_has_exited(self):
        self.run_queue("true")
        rc, out, err = self.run_queue("true")
        self.assertEqual(rc, 0)
        self.assertNotIn("queued", out + err)

    # --- contended --------------------------------------------------------
    def test_second_gate_starts_only_after_the_first_has_finished(self):
        log = self.dir / "stamps"
        first = self.launch(
            "sh",
            "-c",
            f"{stamp(log, 'A-start')}; sleep 2; {stamp(log, 'A-end')}",
            label="/wt/a",
        )
        time.sleep(0.5)
        second = self.launch(
            "sh",
            "-c",
            f'{stamp(log, "B-start")}; echo "wait=$GATE_QUEUE_WAIT"',
            label="/wt/b",
        )
        first.communicate(timeout=60)
        out, err = second.communicate(timeout=60)
        self.assertEqual(second.returncode, 0, err)
        t = stamps(log)
        self.assertGreaterEqual(
            t["B-start"],
            t["A-end"],
            "the second gate ran while the first still held the slot",
        )
        wait = int(out.split("wait=")[-1].strip())
        self.assertGreaterEqual(wait, 1, "the child must be told how long it queued")
        self.assertIn("queued", out)
        self.assertIn("label=/wt/a", out, "the waiter must name who holds the slot")
        self.assertIn("GATE_QUEUE=0", out, "the waiter must say how to skip the queue")

    def test_waiting_prints_a_heartbeat_so_a_log_reader_can_tell_queued_from_hung(self):
        first = self.launch("sleep", "2.5", label="/wt/a")
        time.sleep(0.5)
        second = self.launch("true", label="/wt/b", heartbeat=1)
        first.communicate(timeout=60)
        out, _ = second.communicate(timeout=60)
        self.assertRegex(out, r"still queued after \d+s")

    def test_a_zero_heartbeat_is_clamped_rather_than_spinning(self):
        # `flock -w 0` is a non-blocking try, so GATE_QUEUE_HEARTBEAT=0 would make the
        # wait loop print "still queued" as fast as the shell can. It is clamped to at
        # least 1 s, so a 2.5 s wait prints a handful of lines rather than thousands.
        first = self.launch("sleep", "2.5", label="/wt/a")
        time.sleep(0.5)
        second = self.launch("true", label="/wt/b", heartbeat=0)
        first.communicate(timeout=60)
        out, _ = second.communicate(timeout=60)
        self.assertEqual(second.returncode, 0, out)
        self.assertLessEqual(
            out.count("still queued"),
            5,
            f"the wait loop spun on a zero heartbeat:\n{out[:500]}",
        )

    def test_an_inherited_descriptor_keeps_the_slot_until_its_last_holder_exits(self):
        # Known, and asserted so it stays known: the lock is a descriptor, so a child the
        # gate leaves behind still holds the slot. That is correct while the child is still
        # burning CPU, and a leg that left a daemon running would hold it too. `all` spawns
        # no daemon, and the waiter names the holder so a stuck slot is diagnosable.
        log = self.dir / "stamps"
        first = self.launch(
            "sh", "-c", f"(sleep 2; {stamp(log, 'orphan-end')}) & exit 0", label="/wt/a"
        )
        first.communicate(timeout=60)  # the wrapper's own process is gone…
        second = self.launch("sh", "-c", stamp(log, "B-start"), label="/wt/b")
        second.communicate(timeout=60)
        t = stamps(log)
        self.assertGreaterEqual(t["B-start"], t["orphan-end"])

    # --- degraded / misuse ------------------------------------------------
    def test_without_flock_the_command_still_runs_with_a_warning(self):
        # A missing util-linux must never block a gate: run unqueued and say so.
        shim = self.dir / "bin"
        shim.mkdir()
        for tool in ("sh", "bash", "date", "cat", "sleep", "mkdir", "id"):
            found = None
            for d in os.environ.get("PATH", "").split(os.pathsep):
                cand = Path(d) / tool
                if cand.is_file() and os.access(cand, os.X_OK):
                    found = cand
                    break
            if found is not None:
                (shim / tool).symlink_to(found)
        rc, out, err = self.run_queue(
            "sh", "-c", 'echo "wait=$GATE_QUEUE_WAIT"', env={"PATH": str(shim)}
        )
        self.assertEqual(rc, 0, err)
        self.assertIn("wait=0", out)
        self.assertIn("flock", err, "must say why it is running unqueued")

    def test_missing_command_separator_is_a_usage_error(self):
        p = subprocess.run(
            ["bash", str(SCRIPT), "--lock", str(self.lock), "true"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(p.returncode, 2)
        self.assertIn("usage", p.stderr.lower())

    def test_missing_lock_path_is_a_usage_error(self):
        p = subprocess.run(
            ["bash", str(SCRIPT), "--", "true"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(p.returncode, 2)
        self.assertIn("usage", p.stderr.lower())


if __name__ == "__main__":
    sys.exit(unittest.main())
