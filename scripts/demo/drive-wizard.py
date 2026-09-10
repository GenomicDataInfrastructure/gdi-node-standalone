#!/usr/bin/env python3
"""Drive one complete `gdi-dataset-tool wizard` session and record it as an asciicast.

The README's animated wizard session is a real run, not a mock-up: this script starts the
wizard on a pseudo-terminal, answers every prompt at a human pace, and writes what the
terminal showed, with timings, as an asciicast v2 file that `record-wizard.sh` renders to
SVG. The answers are the SCRIPT table below. When a prompt changes, change its entry here
and re-record; a prompt this script does not expect stalls the run and is reported with the
last screenful of output, so a drifted recording cannot be produced by accident.

The command to drive is everything after `--`; `record-wizard.sh` passes a container that
gives the wizard a clean home directory, so the paths in the recording are a provider's.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import pty
import random
import re
import select
import struct
import sys
import termios
import time

ENTER = b"\r"
TAB = b"\t"
SPACE = b" "
UP = b"\x1b[A"
DOWN = b"\x1b[B"
YES = b"y"
NO = b"n"

# Escape sequences and carriage returns, stripped before prompt matching only; the recording
# keeps every byte the terminal received.
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07|\r")

# One entry per prompt, in the order the wizard asks. The first element is a fragment the
# prompt line must contain; the rest are keystrokes: `str` is typed at a human pace, `bytes`
# is sent as one key, `float` is a pause in seconds.
Step = tuple


def script(a: argparse.Namespace) -> list[Step]:
    """The answers for one session, from the endpoints the caller passed."""
    return [
        # Setup
        ("Profile name", ENTER),
        ("Node service URL", a.node_url, ENTER),
        ("Node management URL", a.management_url, ENTER),
        ("Trust this recipient?", 1.2, YES),
        ("Sync catalogs from the node?", YES),
        ("Configure S3 upload?", YES),
        ("S3 bucket name", a.s3_bucket, ENTER),
        ("S3 endpoint URL", a.s3_endpoint, ENTER),
        ("S3 region", a.s3_region, ENTER),
        ("Key prefix in the bucket", ENTER),
        ("S3 access key id", a.s3_access_key, ENTER),
        ("S3 secret access key", a.s3_secret_key, ENTER),
        ("Channel name", "primary", ENTER),
        ("Path-style S3 URLs?", YES),
        ("Two-letter country code", "EE", ENTER),
        ("Institute abbreviation for dataset ids", "EXAMPLE", ENTER),
        ("VCF headers to ship in packages", ENTER),
        # Author
        ("VCF file or directory of VCFs", "data/gdi-sample.G", 0.6, TAB, 0.8, ENTER),
        ("Add another VCF file or directory?", NO),
        ("Assembly", ENTER),
        ("Dataset ID prefix", ENTER),
        ("Catalog", ENTER),
        ("Dataset title", "Synthetic allele frequencies, twelve populations", ENTER),
        (
            "Description",
            "Synthetic aggregated allele frequencies for a node demo.",
            ENTER,
        ),
        ("Add discovery keywords?", YES),
        ("Keywords (comma-separated)", ENTER),
        ("Record cohort size?", YES),
        ("Distinct sequenced subjects", "500", ENTER),
        ("Is this synthetic data?", YES),
        ("Creating organisation", "Example Institute", ENTER),
        ("Health categories", 0.8, ENTER),
        ("Conforms to", 0.8, ENTER),
        ("Access rights", 0.5, UP, 0.5, ENTER),
        ("License", 0.5, DOWN, 0.5, ENTER),
        ("Applicable legislation", 0.8, ENTER),
        ("Add another legislation ELI or IRI?", NO),
        ("Use the standard Genome of Europe AF provenance?", YES),
        ("Withhold rows with allele count below", "10", ENTER),
        ("Write package.yaml?", 1.5, ENTER),
        # Build
        (a.build_question, 2.0, YES),
        # Pack
        ("Remove the staging dir?", YES),
        # Publish
        ("Send the package to the node now?", ENTER),
    ]


class Recorder:
    """Collects terminal output with timestamps and writes an asciicast v2 file."""

    def __init__(self, cols: int, rows: int, idle_limit: float) -> None:
        self.cols = cols
        self.rows = rows
        self.idle_limit = idle_limit
        self.events: list[tuple[float, str]] = []
        self.started = time.monotonic()

    def output(self, text: str) -> None:
        self.events.append((time.monotonic() - self.started, text))

    def write(self, path: str, hold: float) -> None:
        header = {
            "version": 2,
            "width": self.cols,
            "height": self.rows,
            "timestamp": int(time.time()),
            "env": {"TERM": "xterm-256color", "SHELL": "/bin/bash"},
        }
        # Long silences (a container starting, an upload) are shortened to `idle_limit`
        # so the recording keeps its pace; nothing else about the timeline changes.
        shifted = 0.0
        previous = 0.0
        last = 0.0
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(header) + "\n")
            for at, text in self.events:
                gap = at - previous
                if gap > self.idle_limit:
                    shifted += gap - self.idle_limit
                previous = at
                last = round(at - shifted, 4)
                fh.write(json.dumps([last, "o", text]) + "\n")
            # Hold the final screen. The renderer ends its loop at the last event, so the
            # wizard's closing summary would show for no time at all; a no-op escape (cursor
            # visible, which it already is) `hold` seconds later keeps it on screen. Added
            # after the idle compression above, which would otherwise shorten it.
            fh.write(json.dumps([round(last + hold, 4), "o", "\x1b[?25h"]) + "\n")


def spawn(argv: list[str], cols: int, rows: int) -> tuple[int, int]:
    """Start `argv` on a new pseudo-terminal of the given size; returns (pid, master fd)."""
    pid, fd = pty.fork()
    if pid == 0:
        size = struct.pack("HHHH", rows, cols, 0, 0)
        fcntl.ioctl(sys.stdin.fileno(), termios.TIOCSWINSZ, size)
        os.execvp(argv[0], argv)
    return pid, fd


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True, help="asciicast v2 file to write")
    ap.add_argument("--cols", type=int, default=100)
    ap.add_argument("--rows", type=int, default=32)
    ap.add_argument("--prompt", default="provider@laptop:~/work$ ")
    ap.add_argument("--command-shown", default="gdi-dataset-tool wizard")
    ap.add_argument("--node-url", required=True)
    ap.add_argument("--management-url", required=True)
    ap.add_argument("--s3-endpoint", required=True)
    ap.add_argument("--s3-bucket", required=True)
    ap.add_argument("--s3-region", required=True)
    ap.add_argument("--s3-access-key", required=True)
    ap.add_argument("--s3-secret-key", required=True)
    ap.add_argument(
        "--build-question",
        default="Publish these populations",
        help="a fragment of the disclosure-preview confirmation the Build stage asks",
    )
    ap.add_argument(
        "--think", type=float, default=0.7, help="seconds before each answer"
    )
    ap.add_argument(
        "--keystroke", type=float, default=0.045, help="seconds per typed char"
    )
    ap.add_argument("--idle-limit", type=float, default=1.5)
    ap.add_argument(
        "--hold", type=float, default=8.0, help="seconds the final screen stays"
    )
    ap.add_argument(
        "--timeout", type=float, default=60.0, help="seconds to wait per prompt"
    )
    ap.add_argument(
        "--dump", help="write the ANSI-stripped transcript here, for tuning"
    )
    ap.add_argument("argv", nargs=argparse.REMAINDER, help="-- command to drive")
    a = ap.parse_args()
    argv = a.argv[1:] if a.argv and a.argv[0] == "--" else a.argv
    if not argv:
        ap.error("the command to drive goes after `--`")

    rec = Recorder(a.cols, a.rows, a.idle_limit)
    dump = open(a.dump, "w", encoding="utf-8") if a.dump else None  # noqa: SIM115
    rng = random.Random(7)

    # A shell prompt and the command, typed, so the recording starts where a provider would.
    rec.output(a.prompt)
    time.sleep(0.8)
    for ch in a.command_shown:
        time.sleep(a.keystroke * rng.uniform(0.7, 1.4))
        rec.output(ch)
    time.sleep(0.5)
    rec.output("\r\n")

    pid, fd = spawn(argv, a.cols, a.rows)
    steps = script(a)
    seen = ""
    index = 0
    last_answer = time.monotonic()

    def pump(wait: float) -> bool:
        """Read what the wizard printed within `wait` seconds; False once it has exited."""
        nonlocal seen
        ready, _, _ = select.select([fd], [], [], wait)
        if fd not in ready:
            return True
        try:
            data = os.read(fd, 65536)
        except OSError:
            return False
        if not data:
            return False
        text = data.decode("utf-8", "replace")
        rec.output(text)
        seen += ANSI.sub("", text)
        if dump:
            dump.write(text)
        return True

    def send(key: bytes) -> None:
        os.write(fd, key)

    alive = True
    while alive:
        alive = pump(0.05)
        if index < len(steps) and steps[index][0] in seen:
            # Cleared before answering, not after: the wizard prints the next prompt in the
            # same breath as it confirms this answer, and that must stay visible.
            seen = ""
            time.sleep(a.think)
            for action in steps[index][1:]:
                if isinstance(action, float):
                    end = time.monotonic() + action
                    while time.monotonic() < end:
                        pump(0.05)
                elif isinstance(action, bytes):
                    send(action)
                    pump(0.05)
                else:
                    for ch in action:
                        send(ch.encode())
                        end = time.monotonic() + a.keystroke * rng.uniform(0.6, 1.5)
                        while time.monotonic() < end:
                            pump(0.02)
            index += 1
            last_answer = time.monotonic()
        elif index < len(steps) and time.monotonic() - last_answer > a.timeout:
            tail = seen[-1500:]
            sys.stderr.write(
                f"no prompt containing {steps[index][0]!r} within {a.timeout:.0f}s; "
                f"last output:\n{tail}\n"
            )
            os.kill(pid, 9)
            return 2

    _, status = os.waitpid(pid, 0)
    rec.write(a.out, a.hold)
    if dump:
        dump.close()
    if index < len(steps):
        sys.stderr.write(f"the wizard ended after {index} of {len(steps)} prompts\n")
        return 3
    code = os.waitstatus_to_exitcode(status)
    if code != 0:
        sys.stderr.write(f"the wizard exited with {code}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
