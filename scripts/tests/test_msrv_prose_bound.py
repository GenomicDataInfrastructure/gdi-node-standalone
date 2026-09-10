#!/usr/bin/env python3
"""Guard: every restatement of the MSRV agrees with `rust-version` in `Cargo.toml`.

`Cargo.toml` is the single source of the floor, and `scripts/ci-local.sh` derives the
`msrv` leg from it. The number is nevertheless restated in prose, in `CONTRIBUTING.md`,
`README.md` and `docs/deployment.md`, and once more as the script's unreachable fallback
literal. Restatements drift: a bump touches around twenty sites, and one left behind is
easy to miss. Raises are rare, which makes a stale restatement more likely to survive,
not less.

Scoped so prose cannot satisfy it vacuously: every matched site must equal the manifest,
and every watched site must yield at least one match, so a rewrite that drops the number
fails here instead of un-guarding the file.
"""

import re
import unittest

from _helpers import REPO_ROOT

CARGO_TOML = REPO_ROOT / "Cargo.toml"

#: Sites that quote the two-component floor. Each pattern's first group captures it.
FLOOR_SITES: tuple[tuple[str, str], ...] = (
    ("README.md", r"MSRV \*\*(\d+\.\d+)\*\*"),
    ("docs/deployment.md", r"MSRV \*\*(\d+\.\d+)\*\*"),
    ("CONTRIBUTING.md", r"MSRV `(\d+\.\d+)`"),
    ("CONTRIBUTING.md", r"Minimum Supported Rust Version is `(\d+\.\d+)`"),
    ("CONTRIBUTING.md", r'rust-version = "(\d+\.\d+)"'),
    ("CONTRIBUTING.md", r"\(\*\*(\d+\.\d+)\*\* → `\d+\.\d+\.\d+`\)"),
    ("CONTRIBUTING.md", r'\("(\d+\.\d+) or newer works"\)'),
    ("CONTRIBUTING.md", r"the literal `(\d+\.\d+)` beside it"),
    ("scripts/ci-local.sh", r'^MSRV="\$\{MSRV:-(\d+\.\d+)\}"'),
    # ruff.toml explains the Python floor by analogy to the Rust one and quotes it, so
    # that quoted number needs binding like any other restatement.
    ("ruff.toml", r'rust-version = "(\d+\.\d+)"'),
    # The provider guide tells a data provider what to install before building the tool.
    # The sentence wraps between "Rust" and "version", so the pattern spans whitespace.
    ("docs/gdi-dataset-tool.md", r"minimum supported Rust\s+version is (\d+\.\d+)"),
    # The changelog's contract table. It is a released-section fact and will freeze once
    # `v1.0.0` ships, but until then a ratchet must move it like every other restatement.
    ("CHANGELOG.md", r"Minimum supported Rust version \| `(\d+\.\d+)`"),
)

#: Sites that quote the leg's earliest-patch toolchain, which must be `<floor>.0`.
PATCH_SITES: tuple[tuple[str, str], ...] = (
    ("CONTRIBUTING.md", r"cargo \+(\d+\.\d+\.\d+) check"),
    ("CONTRIBUTING.md", r"rustup toolchain install (\d+\.\d+\.\d+)"),
    ("CONTRIBUTING.md", r"earliest patch \(`(\d+\.\d+\.\d+)`\)"),
    ("CONTRIBUTING.md", r"\(\*\*\d+\.\d+\*\* → `(\d+\.\d+\.\d+)`\)"),
)


def declared_floor() -> str:
    """The `rust-version` in `[workspace.package]`, as written."""
    match = re.search(
        r'^\s*rust-version\s*=\s*"([0-9.]+)"', CARGO_TOML.read_text(), re.MULTILINE
    )
    if match is None:
        raise AssertionError(f"{CARGO_TOML} declares no rust-version")
    return match.group(1)


def sites(file: str, pattern: str) -> list[tuple[int, str]]:
    """Every (line number, captured version) the pattern matches in the file."""
    text = (REPO_ROOT / file).read_text()
    return [
        (text.count("\n", 0, m.start()) + 1, m.group(1))
        for m in re.finditer(pattern, text, re.MULTILINE)
    ]


class MsrvProseIsBoundToCargoToml(unittest.TestCase):
    """The prose restatements and the fallback literal equal the manifest."""

    def test_floor_restatements_match(self) -> None:
        floor = declared_floor()
        mismatches = [
            f"{file}:{line}: says {found}, Cargo.toml says {floor}"
            for file, pattern in FLOOR_SITES
            for line, found in sites(file, pattern)
            if found != floor
        ]
        self.assertEqual([], mismatches, "\n".join(mismatches))

    def test_patch_restatements_match(self) -> None:
        expected = f"{declared_floor()}.0"
        mismatches = [
            f"{file}:{line}: says {found}, the leg pins {expected}"
            for file, pattern in PATCH_SITES
            for line, found in sites(file, pattern)
            if found != expected
        ]
        self.assertEqual([], mismatches, "\n".join(mismatches))

    def test_every_watched_site_still_states_the_floor(self) -> None:
        """A prose rewrite that drops the number must fail here, not un-guard the site.

        Checked per (file, pattern) rather than per file: CONTRIBUTING.md carries six
        patterns, and a per-file check would let five go silent while the sixth kept the
        file watched.
        """
        silent = [
            f"{file}: /{pattern}/"
            for file, pattern in FLOOR_SITES + PATCH_SITES
            if not sites(file, pattern)
        ]
        self.assertEqual(
            [], silent, "no MSRV restatement matched at:\n" + "\n".join(silent)
        )


if __name__ == "__main__":
    unittest.main()
