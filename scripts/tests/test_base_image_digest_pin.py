#!/usr/bin/env python3
"""Guard: the `pins` leg's base-image digest comparison behaves on equal/unequal input.

`ci-local.sh`'s `pins` leg compares the Dockerfile's pinned distroless digest against the
one `docker buildx imagetools inspect` resolves now, a note in `all` and in the weekly job
and a failure under `BASE_IMAGE_STRICT=1` for a release. Without it a base pin can fall
arbitrarily far behind upstream between releases with nothing executed noticing.

The comparison (`_base_image_digest_check`) is split out from the Docker call around it
(`_base_image_freshness`) so it can be tested without Docker or a network. This file
extracts that function's source out of ci-local.sh and runs it with equal and unequal
digest pairs.

It also covers `_first_upstream_digest`, the parser for that inspect output. `sed -n
'…/p'` prints every matching line, so a rendering carrying more than one `Digest:` line
would yield a multi-line "digest" that could only ever compare as drift against the
single-line pin. A synthetic multi-`Digest:` fixture pins the single-line result.
"""

import re
import subprocess
import unittest

from _helpers import REPO_ROOT, SCRIPTS

SCRIPT = SCRIPTS / "ci-local.sh"

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


def extract_function(name: str) -> str:
    """Return the shell source of `name` as written in ci-local.sh.

    Read from the real script rather than duplicated here, so this exercises the code
    that actually runs and cannot silently test a stale copy of it.
    """
    text = SCRIPT.read_text(encoding="utf-8")
    match = re.search(
        rf"^{re.escape(name)}\(\) \{{.*?$.*?^\}}$", text, re.MULTILINE | re.DOTALL
    )
    assert match, f"{name}() not found in {SCRIPT}; it was renamed or reshaped"
    return match.group(0)


def run_check(pinned: str, upstream: str) -> subprocess.CompletedProcess:
    """Run `_base_image_digest_check <pinned> <upstream>` in isolation.

    The function prints through `$C_DIM`, `$C_ERR` and `$C_OFF`. They are defined empty
    here, as the real script does when stdout is not a tty, so `set -u` cannot trip on
    them.
    """
    body = extract_function("_base_image_digest_check")
    script = (
        "set -euo pipefail\n"
        "C_DIM='' ; C_ERR='' ; C_OFF=''\n"
        f"{body}\n"
        '_base_image_digest_check "$1" "$2"\n'
    )
    return subprocess.run(
        ["bash", "-c", script, "_", pinned, upstream],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


class BaseImageFreshnessReturnCodes(unittest.TestCase):
    """`_base_image_freshness` tells "upstream moved" (1) from "this tree is inconsistent" (2).

    `_base_image_pin_gate` demotes the former to a note unless BASE_IMAGE_STRICT=1 and must
    keep the latter fatal, so the two need distinct codes. Run with the Docker-touching
    helpers stubbed: two different pins for the base are reported before the registry is
    asked, so no `docker` is needed to reach that branch.
    """

    def test_two_different_pins_for_the_base_return_2_before_asking_the_registry(self):
        body = extract_function("_base_image_freshness")
        script = (
            "set -euo pipefail\n"
            "C_DIM='' ; C_ERR='' ; C_OFF=''\n"
            "skip_unless() { return 0; }\n"
            "assert_nonempty() { :; }\n"
            "_all_dockerfile_digest_pins() {\n"
            "  echo 'gcr.io/distroless/cc-debian13:nonroot sha256:" + "a" * 64 + "'\n"
            "  echo 'gcr.io/distroless/cc-debian13:nonroot sha256:" + "b" * 64 + "'\n"
            "}\n"
            "docker() { echo 'registry was asked' >&2; exit 99; }\n"
            f"{body}\n"
            "rc=0; _base_image_freshness || rc=$?\n"
            'echo "rc=$rc"\n'
        )
        proc = subprocess.run(
            ["bash", "-c", script],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertIn("rc=2", proc.stdout, proc.stdout + proc.stderr)
        self.assertNotIn("registry was asked", proc.stderr)
        self.assertIn("DIFFERENT digests", proc.stdout)


class BaseImageDigestCheck(unittest.TestCase):
    def test_equal_digests_are_clean(self):
        proc = run_check(DIGEST_A, DIGEST_A)
        self.assertEqual(0, proc.returncode, proc.stderr)
        self.assertIn(DIGEST_A, proc.stdout)
        self.assertIn("ok:", proc.stdout)
        self.assertNotIn("drift", proc.stdout.lower())

    def test_unequal_digests_report_drift_and_fail(self):
        proc = run_check(DIGEST_A, DIGEST_B)
        self.assertEqual(1, proc.returncode, proc.stderr)
        self.assertIn(DIGEST_A, proc.stdout)
        self.assertIn(DIGEST_B, proc.stdout)
        self.assertIn("pinned", proc.stdout)
        self.assertIn("upstream", proc.stdout)
        self.assertNotIn("ok:", proc.stdout)

    def test_same_object_different_case_is_not_silently_equal(self):
        # The comparison must be a literal string match, not a case-normalised one:
        # sha256 digests are lowercase by convention, and two digests that differ only in
        # case are still two different digests.
        proc = run_check(DIGEST_A, DIGEST_A.upper())
        self.assertEqual(1, proc.returncode, proc.stderr)


def run_first_upstream_digest(stdin_text: str) -> subprocess.CompletedProcess:
    """Pipe `stdin_text` through `_first_upstream_digest` in isolation."""
    body = extract_function("_first_upstream_digest")
    script = f"set -euo pipefail\n{body}\n_first_upstream_digest\n"
    return subprocess.run(
        ["bash", "-c", script],
        cwd=REPO_ROOT,
        input=stdin_text,
        capture_output=True,
        text=True,
        check=False,
    )


class FirstUpstreamDigest(unittest.TestCase):
    def test_a_single_digest_line_is_returned(self):
        proc = run_first_upstream_digest(
            f"Name:      whatever\nDigest:    {DIGEST_A}\n"
        )
        self.assertEqual(0, proc.returncode, proc.stderr)
        self.assertEqual(DIGEST_A, proc.stdout.strip())

    def test_only_the_first_of_two_digest_lines_is_returned(self):
        # A rendering with a second `Digest:` line must not turn the result into a
        # two-line string.
        proc = run_first_upstream_digest(
            f"Digest:    {DIGEST_A}\nDigest:    {DIGEST_B}\n"
        )
        self.assertEqual(0, proc.returncode, proc.stderr)
        self.assertEqual(DIGEST_A, proc.stdout.strip())
        self.assertNotIn(DIGEST_B, proc.stdout)

    def test_realistic_multi_platform_output_yields_only_the_manifest_list_digest(self):
        # The shape `docker buildx imagetools inspect` prints for a multi-arch image: one
        # `Digest:` line for the manifest list, then each platform's own digest inside a
        # `Name: …@sha256:…` line rather than a `Digest:` line of its own.
        fixture = (
            "Name:      gcr.io/distroless/cc-debian13:nonroot\n"
            "MediaType: application/vnd.oci.image.index.v1+json\n"
            f"Digest:    {DIGEST_A}\n"
            "\n"
            "Manifests: \n"
            f"  Name:      gcr.io/distroless/cc-debian13:nonroot@{DIGEST_B}\n"
            "  MediaType: application/vnd.oci.image.manifest.v1+json\n"
            "  Platform:  linux/amd64\n"
        )
        proc = run_first_upstream_digest(fixture)
        self.assertEqual(0, proc.returncode, proc.stderr)
        self.assertEqual(DIGEST_A, proc.stdout.strip())

    def test_no_digest_line_yields_empty(self):
        proc = run_first_upstream_digest("error: no such manifest\n")
        self.assertEqual(0, proc.returncode, proc.stderr)
        self.assertEqual("", proc.stdout.strip())


class BaseImagePinIsWatched(unittest.TestCase):
    """The freshness check must watch the pin the Dockerfile ships, not a copy of it.

    Extracting the pin is covered by test_dockerfile_digest_pins.py; this class only
    checks that there is exactly one pin to watch. That the `pins` leg runs the check is
    covered by executing the leg, in test_gate_ordering.py.
    """

    def test_dockerfile_carries_exactly_one_distroless_nonroot_pin(self):
        text = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
        pins = re.findall(
            r"^FROM[ \t]+gcr\.io/distroless/cc-debian13:nonroot@(sha256:[0-9a-f]{64})",
            text,
            re.MULTILINE,
        )
        self.assertEqual(
            1,
            len(pins),
            "expected exactly one gcr.io/distroless/cc-debian13:nonroot FROM pin in "
            "Dockerfile; the freshness check assumes there is one to watch",
        )


if __name__ == "__main__":
    unittest.main()
