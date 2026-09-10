"""Unit tests for ``scripts/gate-key.sh``, the whole-gate short-circuit key.

The key decides whether ``ci-local.sh all`` may skip its pure legs. An under-sensitive key
manufactures a false green, so the sensitivity is asserted here rather than assumed. The
two known blind spots, gitignored files and environment variables, are asserted too, so a
reader learns them from a passing test.

Pure stdlib. Discovered by the ``dashboard`` leg's ``test_*.py`` sweep.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from _helpers import SCRIPTS

GATE_KEY = SCRIPTS / "gate-key.sh"


def _clean_env(**overrides):
    """Ambient env with every ``GIT_*`` var stripped, plus any overrides.

    ``gate-key.sh`` runs ``git ls-files`` inside the repo it is handed, and this suite drives
    a throwaway temp repo. A caller inside a git hook or ``git rebase -x`` exports
    ``GIT_DIR`` and ``GIT_INDEX_FILE``, which would redirect those git commands away from
    the temp repo, so the edits under test would not change the listing. Scrubbing
    ``GIT_*`` keeps the subprocess pointed at the repo it was given.
    """
    base = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    base.update(overrides)
    return base


def _git(repo, *args):
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        env=_clean_env(),
    )


class GateKeyTest(unittest.TestCase):
    def setUp(self):
        if shutil.which("git") is None:  # pragma: no cover - git is a hard dep here
            self.skipTest("git not available")
        self.tmp = tempfile.mkdtemp(prefix="gate-key-")
        self.repo = Path(self.tmp)
        _git(self.repo, "init", "-q")
        _git(self.repo, "config", "user.email", "t@example.invalid")
        _git(self.repo, "config", "user.name", "t")
        (self.repo / "src.rs").write_text("fn main() {}\n")
        (self.repo / ".gitignore").write_text("/target\nlocal.env\n")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-qm", "init")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def key(self):
        out = subprocess.run(
            ["bash", str(GATE_KEY), str(self.repo)],
            check=True,
            capture_output=True,
            text=True,
            env=_clean_env(),
        )
        return out.stdout.strip()

    # --- it must be stable -------------------------------------------------
    def test_is_deterministic(self):
        self.assertEqual(self.key(), self.key())

    def test_is_a_sha256_hex_digest(self):
        k = self.key()
        self.assertEqual(len(k), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in k))

    # --- it must notice real changes ---------------------------------------
    def test_editing_a_tracked_file_changes_the_key(self):
        before = self.key()
        (self.repo / "src.rs").write_text("fn main() { let x = 1; }\n")
        self.assertNotEqual(before, self.key())

    def test_reverting_an_edit_restores_the_key(self):
        before = self.key()
        (self.repo / "src.rs").write_text("changed\n")
        self.assertNotEqual(before, self.key())
        (self.repo / "src.rs").write_text("fn main() {}\n")
        self.assertEqual(before, self.key())

    def test_uncommitted_edits_count(self):
        """The gate runs against the working tree, so committing must not matter."""
        (self.repo / "src.rs").write_text("dirty\n")
        dirty = self.key()
        _git(self.repo, "commit", "-qam", "commit the same content")
        self.assertEqual(dirty, self.key())

    def test_new_untracked_file_changes_the_key(self):
        before = self.key()
        (self.repo / "extra.rs").write_text("// new\n")
        self.assertNotEqual(before, self.key())

    def test_deleting_a_tracked_file_changes_the_key(self):
        before = self.key()
        (self.repo / "src.rs").unlink()
        self.assertNotEqual(before, self.key())

    def test_renaming_a_file_changes_the_key(self):
        before = self.key()
        (self.repo / "src.rs").rename(self.repo / "renamed.rs")
        self.assertNotEqual(before, self.key())

    # --- a non-git tree must fail, not emit a tree-independent key ----------
    def test_staging_or_committing_a_new_file_does_not_change_the_key(self):
        # The key is a function of the tree's content, not of the index. `git ls-files
        # --cached --others` lists tracked files first and untracked ones after, so a new
        # file moves within the listing the moment it is staged, and a key that hashed the
        # listing in order would change with it. The fixture name sorts before src.rs,
        # which is what makes it move once tracked.
        (self.repo / "aaa_new.rs").write_text("pub fn f() {}\n")
        untracked = self.key()
        _git(self.repo, "add", "aaa_new.rs")
        self.assertEqual(self.key(), untracked, "staging a new file changed the key")
        _git(self.repo, "commit", "-qm", "add")
        self.assertEqual(self.key(), untracked, "committing a new file changed the key")

    def test_non_git_dir_exits_nonzero_and_emits_no_key(self):
        """A directory that is not a git work tree must fail loudly.

        Swallowing the ``git ls-files`` failure collapses the key to the toolchain
        versions alone, a tree-independent constant, and ``gate-status`` then reports
        FRESH over arbitrarily changed code.
        """
        non_git = tempfile.mkdtemp(prefix="gate-key-nongit-")
        try:
            out = subprocess.run(
                ["bash", str(GATE_KEY), non_git],
                capture_output=True,
                text=True,
                env=_clean_env(),
                check=False,
            )
            self.assertNotEqual(
                out.returncode, 0, f"a non-git tree must fail; stdout={out.stdout!r}"
            )
            self.assertEqual(
                out.stdout.strip(), "", "no key may be emitted for a non-git tree"
            )
        finally:
            shutil.rmtree(non_git, ignore_errors=True)

    def test_a_missing_sha256sum_exits_nonzero_and_emits_no_key(self):
        """The hashing half of the same fail-open.

        If a missing ``sha256sum`` is swallowed, the key collapses to the toolchain
        versions alone and every later run reads FRESH on any tree. The tool is shadowed
        off PATH rather than stubbed, because ``command -v`` finds the first executable
        match.
        """
        shadow = tempfile.mkdtemp(prefix="gate-key-shadow-")
        try:
            for entry in os.environ.get("PATH", "").split(os.pathsep):
                d = Path(entry)
                if not d.is_dir():
                    continue
                for f in d.iterdir():
                    target = Path(shadow) / f.name
                    if (
                        f.name != "sha256sum"
                        and os.access(f, os.X_OK)
                        and not target.exists()
                    ):
                        target.symlink_to(f)
            self.assertFalse(
                (Path(shadow) / "sha256sum").exists(), "sha256sum leaked in"
            )
            self.assertTrue(
                (Path(shadow) / "git").exists(), "git must survive the shadow"
            )
            out = subprocess.run(
                ["bash", str(GATE_KEY), str(self.repo)],
                capture_output=True,
                text=True,
                env=_clean_env(PATH=shadow),
                check=False,
            )
            self.assertNotEqual(out.returncode, 0, f"stdout={out.stdout!r}")
            self.assertEqual(
                out.stdout.strip(), "", "no key may be emitted when nothing was hashed"
            )
            self.assertIn("produced nothing", out.stderr)
        finally:
            shutil.rmtree(shadow, ignore_errors=True)

    def test_filenames_with_spaces_are_handled(self):
        before = self.key()
        (self.repo / "a file with spaces.rs").write_text("x\n")
        self.assertNotEqual(before, self.key())

    def test_filenames_with_NEWLINES_are_handled(self):
        # A newline in a path is why gate-key.sh pairs `git ls-files -z` with `xargs -0`:
        # with line-delimited output the name splits into two bogus paths, sha256sum fails
        # on both, and the key stops covering the file. Spaces alone do not show that,
        # since `xargs` without -0 splits on them too.
        before = self.key()
        (self.repo / "weird\nname.rs").write_text("x\n")
        after = self.key()
        self.assertNotEqual(
            before,
            after,
            "a file whose name contains a newline must still change the key",
        )

    # --- the known blind spots ---------------------------------------------
    def test_gitignored_files_do_NOT_change_the_key(self):
        """A known limitation, asserted so that it stays known.

        A local `.env`, a `config.toml`, or anything under `/target` can change without
        invalidating a green marker. Gate legs are not supposed to read such files, and
        nothing enforces that, which is why the marker also carries a TTL.
        """
        before = self.key()
        (self.repo / "local.env").write_text("SECRET=1\n")
        (self.repo / "target").mkdir()
        (self.repo / "target" / "junk").write_text("build output\n")
        self.assertEqual(before, self.key())

    def test_environment_variables_do_NOT_change_the_key(self):
        """A known limitation: `GDI_CORPUS_DIR` and friends steer legs but are not hashed."""
        before = self.key()
        out = subprocess.run(
            ["bash", str(GATE_KEY), str(self.repo)],
            check=True,
            capture_output=True,
            text=True,
            env=_clean_env(GDI_CORPUS_DIR="/somewhere/else"),
        )
        self.assertEqual(before, out.stdout.strip())

    # --- the toolchain is an input -----------------------------------------
    def _stub_toolchain(self):
        """A PATH dir with ``rustc``/``cargo`` stubs that report ``$GDI_FAKE_TOOLCHAIN``.

        Both stubs ignore their arguments, so they answer ``rustc -vV`` and
        ``cargo --version`` alike.
        """
        binn = self.repo / "stub-bin"
        binn.mkdir(exist_ok=True)
        for tool in ("rustc", "cargo"):
            p = binn / tool
            p.write_text(f'#!/bin/sh\necho "{tool} ${{GDI_FAKE_TOOLCHAIN}}"\n')
            p.chmod(0o755)
        return binn

    def _key_with_toolchain(self, version, stub_bin):
        out = subprocess.run(
            ["bash", str(GATE_KEY), str(self.repo)],
            check=True,
            capture_output=True,
            text=True,
            env=_clean_env(
                PATH=f"{stub_bin}{os.pathsep}{os.environ.get('PATH', '')}",
                GDI_FAKE_TOOLCHAIN=version,
            ),
        )
        return out.stdout.strip()

    def test_toolchain_version_is_part_of_the_key(self):
        """Same source and a different rustc must produce a different key.

        Asserted behaviourally, by running the script against stub compilers. Grepping the
        script for ``rustc -vV`` would be satisfied by its own comment, so the toolchain
        could stop being an input while this stayed green, and ``all`` would
        short-circuit onto a green recorded against a different compiler.
        """
        stub = self._stub_toolchain()
        # `stub-bin/` is untracked but not ignored, so it is itself in the listing. Both
        # keys are taken with it already on disk, so the only difference between the runs
        # is what the stubs print.
        first = self._key_with_toolchain("1.96.0", stub)
        second = self._key_with_toolchain("1.97.1", stub)
        self.assertNotEqual(
            first,
            second,
            "a different reported toolchain must change the key; the compiler is an input",
        )

    def test_same_toolchain_keeps_the_key(self):
        """The control for the test above: identical stubs, identical key.

        Without this, a key that simply changed on every invocation (a clock, a nonce)
        would satisfy the sensitivity assertion while being useless as a short-circuit.
        """
        stub = self._stub_toolchain()
        self.assertEqual(
            self._key_with_toolchain("1.96.0", stub),
            self._key_with_toolchain("1.96.0", stub),
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
