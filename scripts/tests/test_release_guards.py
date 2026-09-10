#!/usr/bin/env python3
"""Guard: the release-tag guards + notes assembly behave as `release.yml` documents.

`.github/workflows/release.yml` runs only on a `v*` tag, so nothing in the per-change gate
executes these three shell snippets end to end. Each one is extracted from the workflow by
its step name and run for real, as `bash -c`, against a synthetic `Cargo.toml` and
`CHANGELOG.md`. What these tests exercise is therefore the shipped shell, not a
re-implementation of it that could drift from what ships.

This suite pins:

  * `version-guard`'s "Assert the tag matches [workspace.package].version" step accepts a
    pre-release-suffixed tag (`v0.1.0-rc1`) checked against the tag's base version, and
    still rejects a tag whose base version disagrees with `[workspace.package].version`,
    with or without a suffix.
  * `changelog-guard`'s "Assert CHANGELOG.md has a section for this version" step accepts
    the same pre-release tag against the base version's `## [X.Y.Z]` heading.
  * `publish`'s "Assemble release notes from CHANGELOG.md" step produces a body with
    neither a reference-style link-definition line nor the `[Unreleased]` boilerplate
    text, when CHANGELOG.md is authored as CONTRIBUTING.md prescribes: guidance parked in
    an HTML comment under `[Unreleased]`, never renamed into a versioned section.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from _helpers import REPO_ROOT

RELEASE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release.yml"

VERSION_GUARD_STEP = "Assert the tag matches [workspace.package].version"
CHANGELOG_GUARD_STEP = "Assert CHANGELOG.md has a section for this version"
ASSEMBLE_NOTES_STEP = "Assemble release notes from CHANGELOG.md"


def _step_block(text: str, step_name: str) -> str:
    """The raw text from a `- name: <step_name>` line to the next step at the same indent."""
    pattern = re.compile(
        r"^([ \t]*)- name:\s*" + re.escape(step_name) + r"\s*$", re.MULTILINE
    )
    matches = list(pattern.finditer(text))
    if len(matches) != 1:
        raise AssertionError(
            f"expected exactly one step named {step_name!r} in release.yml, found "
            f"{len(matches)}; the step was renamed or duplicated"
        )
    m = matches[0]
    indent = m.group(1)
    start = m.end()
    next_step = re.search(rf"^{re.escape(indent)}- ", text[start:], re.MULTILINE)
    return text[start : start + next_step.start()] if next_step else text[start:]


def extract_run_shell(step_name: str) -> str:
    """The literal shell script under a `run: |` block scalar for the named step.

    Read straight from `release.yml` rather than re-typed here, so this test binds to what
    ships rather than to a copy that can drift from it.
    """
    text = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    block = _step_block(text, step_name)
    m = re.search(r"^([ \t]*)run:\s*\|[ \t]*\n", block, re.MULTILINE)
    if not m:
        raise AssertionError(f"step {step_name!r} has no 'run: |' block scalar")
    run_indent = len(m.group(1))
    body = block[m.end() :]
    lines: list[str] = []
    for line in body.splitlines():
        if line.strip() == "":
            lines.append("")
            continue
        cur_indent = len(line) - len(line.lstrip(" "))
        if cur_indent <= run_indent:
            break
        lines.append(line)
    if not lines:
        raise AssertionError(f"step {step_name!r}'s 'run: |' block extracted no lines")
    content_indent = min(
        len(line) - len(line.lstrip(" ")) for line in lines if line.strip()
    )
    return (
        "\n".join(line[content_indent:] if line.strip() else "" for line in lines)
        + "\n"
    )


def run_step(
    step_name: str, *, cwd: Path, ref_name: str, repository: str = "example/example"
) -> subprocess.CompletedProcess[str]:
    """Extract `step_name`'s shell and execute it in `cwd` with the given tag."""
    script = extract_run_shell(step_name)
    env = {**os.environ, "GITHUB_REF_NAME": ref_name, "GITHUB_REPOSITORY": repository}
    return subprocess.run(
        ["bash", "-c", script],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def write_cargo_toml(root: Path, version: str) -> None:
    (root / "Cargo.toml").write_text(
        f'[workspace]\nmembers = []\n\n[workspace.package]\nversion = "{version}"\n'
        'edition = "2024"\n',
        encoding="utf-8",
    )


def write_changelog_good(root: Path, version: str) -> None:
    """The correct shape: guidance parked in an HTML comment above the target section, the
    target section holding only a real entry, and the trailing reference-style link
    definition right after it with nothing else following. This is how the real
    CHANGELOG.md is written.
    """
    text = (
        "# Changelog\n\n"
        "## [Unreleased]\n\n"
        "<!--\n"
        "Nothing has been released yet: this guidance is not a changelog entry.\n"
        "-->\n\n"
        f"## [{version}] - 2026-01-01\n\n"
        "### Added\n\n"
        "- A real, synthetic entry.\n\n"
        "[Unreleased]: https://example.invalid/commits/main\n"
    )
    (root / "CHANGELOG.md").write_text(text, encoding="utf-8")


def write_changelog_bad_rename(root: Path, version: str) -> None:
    """The broken shape: `## [Unreleased]`'s own boilerplate prose carried into the
    versioned section, uncommented. It is what renaming `## [Unreleased]` to `## [X.Y.Z]`
    produces, instead of moving only the real entries.
    """
    text = (
        "# Changelog\n\n"
        "## [Unreleased]\n\n"
        f"## [{version}] - 2026-01-01\n\n"
        "Nothing has been released yet: no v* tag has ever been cut.\n\n"
        "### Added\n\n"
        "- A real, synthetic entry.\n\n"
        "[Unreleased]: https://example.invalid/commits/main\n"
    )
    (root / "CHANGELOG.md").write_text(text, encoding="utf-8")


def write_footer(root: Path) -> None:
    github_dir = root / ".github"
    github_dir.mkdir(parents=True, exist_ok=True)
    (github_dir / "release-notes-footer.md").write_text(
        "---\n\n**Artifacts**\n\n__ARTIFACTS__\n\nRepo: __REPO__\n", encoding="utf-8"
    )


def write_footer_with_image(root: Path, image_line: str) -> None:
    """A footer carrying both placeholders, as the shipped one does.

    `image_line` is injected verbatim so a test can write the correct
    `ghcr.io/__IMAGE__` or the historical, broken `ghcr.io/__REPO__`.
    """
    github_dir = root / ".github"
    github_dir.mkdir(parents=True, exist_ok=True)
    (github_dir / "release-notes-footer.md").write_text(
        "---\n\n**Artifacts**\n\n__ARTIFACTS__\n\n"
        "Verify with `gh attestation verify <file> --repo __REPO__`.\n\n"
        f"{image_line}\n",
        encoding="utf-8",
    )


def write_staged(root: Path) -> None:
    staged = root / "staged"
    staged.mkdir(parents=True, exist_ok=True)
    (staged / "dummy-binary").write_text("synthetic\n", encoding="utf-8")


class ExtractionSanity(unittest.TestCase):
    """An extraction that found nothing would make every assertion below pass vacuously."""

    def test_each_step_extracts_a_nonempty_script(self):
        for step in (VERSION_GUARD_STEP, CHANGELOG_GUARD_STEP, ASSEMBLE_NOTES_STEP):
            with self.subTest(step=step):
                script = extract_run_shell(step)
                self.assertTrue(script.strip(), f"{step!r} extracted an empty script")
                self.assertIn("GITHUB_REF_NAME", script)


class VersionGuard(unittest.TestCase):
    def test_exact_match_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_cargo_toml(root, "0.1.0")
            result = run_step(VERSION_GUARD_STEP, cwd=root, ref_name="v0.1.0")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("ok:", result.stdout)

    def test_a_prerelease_tag_matches_a_manifest_carrying_the_same_suffix(self):
        """The manifest carries the exact version shipped, suffix included.

        It is not enough for the base versions to agree: the manifest value is what the
        binary reports through `--version`, `GET /version`, the log preamble,
        `gdi_build_info` and the Beacon `info` response, so a candidate whose manifest said
        `0.1.0` would be indistinguishable from the release over the wire.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_cargo_toml(root, "0.1.0-rc.1")
            result = run_step(VERSION_GUARD_STEP, cwd=root, ref_name="v0.1.0-rc.1")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("ok:", result.stdout)

    def test_a_prerelease_tag_against_a_base_version_manifest_now_fails(self):
        """A base-version-only match is rejected.

        Stripping the suffix would let `v0.1.0-rc.1` be tagged against a `0.1.0` manifest,
        so the candidate would report itself as the release.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_cargo_toml(root, "0.1.0")
            result = run_step(VERSION_GUARD_STEP, cwd=root, ref_name="v0.1.0-rc.1")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("::error::", result.stdout)

    def test_a_release_tag_against_a_prerelease_manifest_fails(self):
        """The other direction: do not ship `1.0.0` from a tree that still says `-rc.1`."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_cargo_toml(root, "0.1.0-rc.1")
            result = run_step(VERSION_GUARD_STEP, cwd=root, ref_name="v0.1.0")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("::error::", result.stdout)

    def test_mismatch_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_cargo_toml(root, "0.1.0")
            result = run_step(VERSION_GUARD_STEP, cwd=root, ref_name="v0.2.0")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("::error::", result.stdout)

    def test_prerelease_mismatch_still_fails(self):
        """A pre-release suffix does not bypass a genuine version mismatch."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_cargo_toml(root, "0.1.0")
            result = run_step(VERSION_GUARD_STEP, cwd=root, ref_name="v0.2.0-rc1")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("::error::", result.stdout)


class ChangelogGuard(unittest.TestCase):
    def test_exact_match_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_changelog_good(root, "0.1.0")
            result = run_step(CHANGELOG_GUARD_STEP, cwd=root, ref_name="v0.1.0")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_prerelease_suffix_ok_against_base_versions_section(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_changelog_good(root, "0.1.0")
            result = run_step(CHANGELOG_GUARD_STEP, cwd=root, ref_name="v0.1.0-rc1")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_mismatch_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_changelog_good(root, "0.1.0")
            result = run_step(CHANGELOG_GUARD_STEP, cwd=root, ref_name="v0.2.0")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("::error::", result.stdout)


class AssembleReleaseNotes(unittest.TestCase):
    def _assemble(self, root: Path, ref_name: str) -> str:
        write_footer(root)
        write_staged(root)
        result = run_step(
            ASSEMBLE_NOTES_STEP,
            cwd=root,
            ref_name=ref_name,
            repository="example/example",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return (root / "RELEASE_NOTES.md").read_text(encoding="utf-8")

    def test_excludes_reference_link_definition(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_changelog_good(root, "0.1.0")
            notes = self._assemble(root, "v0.1.0")
            self.assertNotIn(
                "[Unreleased]: https://example.invalid/commits/main", notes
            )
            self.assertIn("A real, synthetic entry.", notes)

    def test_prerelease_tag_assembles_against_base_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_changelog_good(root, "0.1.0")
            notes = self._assemble(root, "v0.1.0-rc1")
            self.assertIn("A real, synthetic entry.", notes)
            self.assertNotIn(
                "[Unreleased]: https://example.invalid/commits/main", notes
            )

    def test_repo_and_image_placeholders_get_different_casing(self):
        """`--repo` needs the canonical name; a container reference must be lowercase.

        One placeholder cannot serve both. Substituting the mixed-case repository into the
        image path produced a release body advertising a reference docker rejects outright
        with `repository name must be lowercase`.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_changelog_good(root, "0.1.0")
            write_footer_with_image(root, "Image: `ghcr.io/__IMAGE__`")
            write_staged(root)
            result = run_step(
                ASSEMBLE_NOTES_STEP,
                cwd=root,
                ref_name="v0.1.0",
                repository="GenomicDataInfrastructure/gdi-node-standalone",
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            notes = (root / "RELEASE_NOTES.md").read_text(encoding="utf-8")
            self.assertIn("--repo GenomicDataInfrastructure/gdi-node-standalone", notes)
            self.assertIn(
                "ghcr.io/genomicdatainfrastructure/gdi-node-standalone", notes
            )
            self.assertNotIn("__REPO__", notes)
            self.assertNotIn("__IMAGE__", notes)

    def test_an_uppercase_image_path_is_rejected(self):
        """The negative control: the historical bug must now fail the step, not ship."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_changelog_good(root, "0.1.0")
            write_footer_with_image(root, "Image: `ghcr.io/__REPO__`")
            write_staged(root)
            result = run_step(
                ASSEMBLE_NOTES_STEP,
                cwd=root,
                ref_name="v0.1.0",
                repository="GenomicDataInfrastructure/gdi-node-standalone",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("uppercase", result.stdout + result.stderr)

    def test_excludes_old_unreleased_boilerplate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_changelog_good(root, "0.1.0")
            notes = self._assemble(root, "v0.1.0")
            self.assertNotIn("Nothing has been released", notes)

    def test_negative_control_detects_boilerplate_when_present(self):
        """The substring check above must be able to fail.

        Assembling the broken CHANGELOG shape does surface the phrase, so the previous
        test is not vacuously green.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_changelog_bad_rename(root, "0.1.0")
            notes = self._assemble(root, "v0.1.0")
            self.assertIn("Nothing has been released", notes)


if __name__ == "__main__":
    unittest.main()
