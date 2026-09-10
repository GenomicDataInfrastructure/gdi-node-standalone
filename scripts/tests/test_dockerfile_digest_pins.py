#!/usr/bin/env python3
"""Guard: the Dockerfile digest watch must see every digest-pinned image in the file.

`dockerfile_check` compares each `@sha256:` pin in the Dockerfile against the digest the
registry currently serves and prints a note when one has drifted. That is only worth
anything if the parse feeding it is complete: a pin the parser does not emit is a pin
nothing watches, and the leg still exits 0, because "found nothing" and "found nothing
wrong" are the same output.

A tag stays valid while the image behind it is rebuilt, so an unwatched pin drifts with
the leg reporting clean.

The completeness assertion derives the expected set from the Dockerfile itself rather than
hard-coding today's images. A hard-coded count would be a second copy of the same fact and
would drift with it, and it would stay green when a fourth pinned stage is added, which is
the case that must fail here.
"""

import pathlib
import re
import subprocess
import tempfile
import unittest

from _helpers import REPO_ROOT, SCRIPTS

SCRIPT = SCRIPTS / "ci-local.sh"
DOCKERFILE = REPO_ROOT / "Dockerfile"
#: The ops sidecar image: a shell, tar and the two static musl binaries, for the Kubernetes
#: inbox shape. A second file with its own frontend, builder and runtime pins, so a watch
#: that reads one file by name misses all of them.
OPS_DOCKERFILE = REPO_ROOT / "Dockerfile.ops"

#: Every digest pin, however it is written: the `# syntax=` directive and each `FROM`.
ANY_DIGEST = re.compile(r"@(sha256:[0-9a-f]{64})")


def extract_function(name: str) -> str:
    """Return the shell source of `name` as written in ci-local.sh.

    Read from the real script rather than duplicated here, so this exercises the code
    that actually runs and cannot silently test a stale copy of it.
    """
    text = SCRIPT.read_text(encoding="utf-8")
    match = re.search(
        rf"^{re.escape(name)}\(\) \{{$.*?^\}}$", text, re.MULTILINE | re.DOTALL
    )
    assert match, f"{name}() not found in {SCRIPT}; it was renamed or reshaped"
    return match.group(0)


def run_parser(workdir, arg: str = "") -> list[tuple[str, str]]:
    """Run `_dockerfile_digest_pins` against a Dockerfile in `workdir`."""
    body = extract_function("_dockerfile_digest_pins")
    proc = subprocess.run(
        ["bash", "-c", f"set -euo pipefail\n{body}\n_dockerfile_digest_pins {arg}"],
        cwd=workdir,
        capture_output=True,
        text=True,
        check=True,
    )
    return [
        (parts[0], parts[1])
        for line in proc.stdout.splitlines()
        if (parts := line.split()) and len(parts) == 2
    ]


def run_all_parser(workdir) -> list[tuple[str, str]]:
    """Run `_all_dockerfile_digest_pins`, the union the watch actually consumes."""
    body = "\n".join(
        extract_function(name)
        for name in (
            "_dockerfiles",
            "_dockerfile_digest_pins",
            "_all_dockerfile_digest_pins",
        )
    )
    proc = subprocess.run(
        ["bash", "-c", f"set -euo pipefail\n{body}\n_all_dockerfile_digest_pins"],
        cwd=workdir,
        capture_output=True,
        text=True,
        check=True,
    )
    return [
        (parts[0], parts[1])
        for line in proc.stdout.splitlines()
        if (parts := line.split()) and len(parts) == 2
    ]


class DigestPinParse(unittest.TestCase):
    def test_finds_every_digest_in_the_real_dockerfile(self):
        """No `@sha256:` in the Dockerfile may be invisible to the watch."""
        text = DOCKERFILE.read_text(encoding="utf-8")
        in_file = set(ANY_DIGEST.findall(text))
        self.assertTrue(
            in_file, "no digest pins in Dockerfile; the fixture assumption broke"
        )

        parsed = run_parser(REPO_ROOT)
        self.assertEqual(
            in_file,
            {digest for _, digest in parsed},
            "a digest pin in the Dockerfile is not emitted by _dockerfile_digest_pins, so "
            "nothing watches it for upstream drift",
        )

    def test_the_watch_covers_every_digest_in_every_dockerfile(self):
        """Both files, through the function `dockerfile_check` actually calls.

        The ops image is a second shipped artifact with its own runtime base (Alpine) and
        its own frontend line. Watching only `Dockerfile` leaves that base unwatched.
        """
        # Enumerated from the tree and compared against the shipped `_dockerfiles()`. A
        # hand-written pair would check two names against the same two names in
        # ci-local.sh, so a third `Dockerfile.<x>` would escape both.
        paths = sorted(REPO_ROOT.glob("Dockerfile*"))
        self.assertGreaterEqual(
            len(paths), 2, "expected at least Dockerfile + Dockerfile.ops"
        )
        self.assertIn(DOCKERFILE, paths)
        self.assertIn(OPS_DOCKERFILE, paths)
        body = extract_function("_dockerfiles")
        proc = subprocess.run(
            ["bash", "-c", f"set -euo pipefail\n{body}\n_dockerfiles"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(
            [p.name for p in paths],
            proc.stdout.split(),
            "ci-local.sh's _dockerfiles() and the Dockerfile* files on disk disagree",
        )
        in_files = set()
        for path in paths:
            self.assertTrue(path.is_file(), f"{path.name} is missing")
            found = set(ANY_DIGEST.findall(path.read_text(encoding="utf-8")))
            self.assertTrue(found, f"no digest pins in {path.name}")
            in_files |= found

        watched = {digest for _, digest in run_all_parser(REPO_ROOT)}
        self.assertEqual(
            in_files,
            watched,
            "a digest pin in one of the Dockerfiles is not emitted by "
            "_all_dockerfile_digest_pins, so nothing watches it for upstream drift",
        )

    def test_emits_a_resolvable_ref_for_each_pin(self):
        """The ref must be the bare image reference, which `imagetools inspect` takes."""
        for ref, digest in run_parser(REPO_ROOT):
            with self.subTest(ref=ref):
                self.assertNotIn("@", ref, "ref still carries its digest")
                self.assertNotIn(" ", ref)
                # `FROM x@sha256:… AS builder` must not leak the stage name into the ref.
                self.assertNotRegex(ref, r"(?i)\bas\b")
                self.assertRegex(digest, r"^sha256:[0-9a-f]{64}$")

    def test_skips_stages_that_carry_no_digest(self):
        """`FROM scratch` / `FROM ${ARG}` have nothing to compare and must not appear."""
        fixture = (
            "# syntax=docker/dockerfile:1@sha256:" + "a" * 64 + "\n"
            "FROM scratch AS prebuilt\n"
            "FROM ${BIN_SOURCE} AS binsrc\n"
            "FROM alpine:3\n"
            "FROM rust:1@sha256:" + "b" * 64 + " AS builder\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            (pathlib.Path(tmp) / "Dockerfile").write_text(fixture, encoding="utf-8")
            parsed = run_parser(tmp)
        self.assertEqual(
            [
                ("docker/dockerfile:1", "sha256:" + "a" * 64),
                ("rust:1", "sha256:" + "b" * 64),
            ],
            parsed,
        )


if __name__ == "__main__":
    unittest.main()
