#!/usr/bin/env python3
"""Unit tests for ``scripts/dev-setup.sh``: the local build speedups go user-level.

The mold and split-debuginfo settings belong in ``$CARGO_HOME/config.toml``, not in a
gitignored ``.cargo/config.toml`` inside the checkout. A gitignored file is not part of a
checkout, so a new worktree does not carry it and links every binary with the stock
linker. Cargo merges the user-level file into every project on the machine, worktrees
included, so "every worktree links with mold" is held by cargo's config hierarchy rather
than by a per-worktree step nobody runs.

Exercised in a throwaway ``git init`` repo with a stub ``ci-local.sh`` and shim tools on
PATH, so nothing here touches the real repo, the real ``$HOME`` or the real hooks. Pure
stdlib.
"""

import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from _helpers import SCRIPTS, clean_git_env

SCRIPT = SCRIPTS / "dev-setup.sh"

MOLD_LINE = 'rustflags = ["-C", "link-arg=-fuse-ld=mold"]'
UNPACKED_LINE = 'split-debuginfo = "unpacked"'

#: Everything dev-setup.sh, and git under it, execs from PATH. `cargo` and `mold` are
#: shims. `cc`, `python3`, `git` and `curl` are real symlinks, because the script prints
#: their own `--version` output; they are the tools required to build, test and commit, and
#: a missing one makes `--check` exit non-zero.
TOOLS = (
    "bash",
    "sh",
    "git",
    "grep",
    "sed",
    "head",
    "cut",
    "tr",
    "du",
    "cat",
    "mkdir",
    "mv",
    "dirname",
    "basename",
    "uname",
    "date",
    "cc",
    "python3",
    "curl",
)


def executable(path: Path, text: str) -> None:
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class DevSetupTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.repo = root / "repo"
        self.home = root / "home"
        self.bin = root / "bin"
        for d in (self.repo / "scripts", self.home, self.bin):
            d.mkdir(parents=True)
        subprocess.run(
            ["git", "init", "-q", str(self.repo)], check=True, env=clean_git_env()
        )
        # Loud, not silent: under a hook's GIT_DIR this init would create nothing here and
        # re-initialise the real repository instead (see clean_git_env).
        assert (self.repo / ".git").is_dir(), (
            "git init did not create the throwaway repo"
        )
        shutil.copy(SCRIPT, self.repo / "scripts" / "dev-setup.sh")
        executable(self.repo / "scripts" / "ci-local.sh", "#!/bin/sh\nexit 0\n")
        executable(self.bin / "cargo", "#!/bin/sh\necho 'cargo 1.0.0 (shim)'\n")
        # A private PATH with only the tools the script needs, so "mold is not installed"
        # is a state this suite controls rather than one the host happens to be in.
        for tool in TOOLS:
            real = shutil.which(tool)
            if real is None:
                raise AssertionError(f"{tool} not found on PATH; the suite cannot run")
            (self.bin / tool).symlink_to(real)
        self.user_cfg = self.home / ".cargo" / "config.toml"
        self.checkout_cfg = self.repo / ".cargo" / "config.toml"

    def tearDown(self):
        self.tmp.cleanup()

    def with_mold(self):
        executable(self.bin / "mold", "#!/bin/sh\nexit 0\n")

    def remove_tool(self, name):
        """Take a tool out of the private PATH, to test its absence."""
        (self.bin / name).unlink()

    def run_setup(self, *args, env=None):
        e = clean_git_env()
        e.pop("CARGO_HOME", None)
        e["HOME"] = str(self.home)
        e["PATH"] = str(self.bin)
        e.update(env or {})
        return subprocess.run(
            ["bash", "scripts/dev-setup.sh", *args],
            cwd=self.repo,
            capture_output=True,
            text=True,
            env=e,
            check=False,
        )

    # --- writing the user-level file ----------------------------------------
    def test_check_reports_the_user_level_path_and_writes_nothing(self):
        self.with_mold()
        r = self.run_setup("--check")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn(str(self.user_cfg), r.stdout)
        self.assertIn("run without --check", r.stdout)
        self.assertFalse(self.user_cfg.exists())
        self.assertFalse(self.checkout_cfg.exists())

    # --- required-tool tiering: only what `quick`/build/commit needs blocks --------
    def test_missing_cc_is_required_and_blocks_check(self):
        # `cc` is needed by the first `cargo build`, not only by the full gate.
        self.with_mold()
        self.remove_tool("cc")
        r = self.run_setup("--check")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("MISSING", r.stdout)
        self.assertIn("cc", r.stdout)
        self.assertIn("Some REQUIRED tools are missing", r.stdout)

    def test_missing_python3_is_required_and_blocks_check(self):
        # `script-tests` and the hook's doc-attachment check both need python3 on every
        # commit, not only on `all`.
        self.with_mold()
        self.remove_tool("python3")
        r = self.run_setup("--check")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("MISSING", r.stdout)
        self.assertIn("python3", r.stdout)
        self.assertIn("Some REQUIRED tools are missing", r.stdout)

    def test_gate_only_tools_missing_is_reported_but_does_not_block_check(self):
        # `uv`, `gitleaks`, `cargo-deny` and the rest are needed only by
        # `scripts/ci-local.sh all`, so their absence must be visible without failing
        # `--check`. Folding them in would tell a newcomer to build gate-only tools from
        # source before the tool that actually blocks the first build.
        self.with_mold()
        executable(
            self.repo / "scripts" / "ci-local.sh",
            "#!/bin/sh\n"
            'if [ "$1" = preflight-all ]; then\n'
            '  echo "error: 5 required tool(s) missing" >&2\n'
            "  exit 1\n"
            "fi\n"
            "exit 0\n",
        )
        r = self.run_setup("--check")
        self.assertEqual(
            r.returncode,
            0,
            f"a gate-only tool must not block --check: {r.stdout}{r.stderr}",
        )
        self.assertIn(
            "is required to build, test or commit",
            r.stdout,
            "the report must say plainly that these tools do not block the inner loop",
        )

    def test_a_missing_required_tool_fails_check_and_is_named(self):
        # The complement of the test above: CONTRIBUTING tells the reader this script
        # verifies the tools the first build and the first commit need, so each one must
        # actually be checked. Asserting the failure is what keeps that claim true.
        self.with_mold()
        self.remove_tool("curl")

        r = self.run_setup("--check")

        self.assertNotEqual(
            r.returncode, 0, f"a missing required tool must fail --check: {r.stdout}"
        )
        self.assertIn("MISSING curl", r.stdout, "the report must name the missing tool")

    def test_without_git_the_script_says_so_instead_of_dying_on_the_anchoring_cd(self):
        # The script anchors itself with `git rev-parse --show-toplevel`, so without git it
        # would abort on `git: command not found` before printing anything — the one
        # required tool it could not otherwise report. The guard runs before that `cd`.
        self.with_mold()
        self.remove_tool("git")

        r = self.run_setup("--check")

        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        # The exact guard text, not just "git": without the guard bash's own
        # `git: command not found` would also contain that word, and the assertion would
        # pass on the very failure it exists to rule out.
        self.assertIn(
            "MISSING git",
            r.stdout + r.stderr,
            "a missing git must be named, not surface as a bare command-not-found",
        )
        # And it must stop *before* the report: without git the anchoring `cd` resolves to
        # nothing, so every path the report prints would be measured against whatever
        # directory the caller happened to be in. Reaching the first section at all is the
        # failure this guard exists to prevent, and is what distinguishes it from the
        # required-tool row further down.
        self.assertNotIn(
            "== Rust toolchain",
            r.stdout,
            "the git guard must run before the anchoring cd, not as a report row",
        )

    def test_yes_writes_mold_and_unpacked_debuginfo_at_user_level_not_in_the_checkout(
        self,
    ):
        self.with_mold()
        r = self.run_setup("--yes")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        text = self.user_cfg.read_text()
        self.assertIn(MOLD_LINE, text)
        self.assertIn(UNPACKED_LINE, text)
        self.assertFalse(
            self.checkout_cfg.exists(),
            "the config belongs at user level, not inside the checkout",
        )

    def test_cargo_home_is_honoured(self):
        self.with_mold()
        cargo_home = Path(self.tmp.name) / "cargo-home"
        r = self.run_setup("--yes", env={"CARGO_HOME": str(cargo_home)})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn(MOLD_LINE, (cargo_home / "config.toml").read_text())
        self.assertFalse(self.user_cfg.exists())

    def test_without_mold_nothing_is_written_and_the_install_hint_is_printed(self):
        r = self.run_setup("--yes")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("apt install mold", r.stdout)
        self.assertFalse(self.user_cfg.exists())

    # --- an existing user-level file is the user's ------------------------------
    def test_existing_user_config_with_mold_is_reported_ok_and_left_alone(self):
        self.with_mold()
        self.user_cfg.parent.mkdir()
        original = (
            f"[net]\nretry = 3\n\n[target.x86_64-unknown-linux-gnu]\n{MOLD_LINE}\n"
        )
        self.user_cfg.write_text(original)
        r = self.run_setup("--yes")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.user_cfg.read_text(), original)
        self.assertRegex(r.stdout, r"ok\s+.*config\.toml")

    def test_existing_user_config_without_mold_is_never_edited_and_the_block_is_printed(
        self,
    ):
        self.with_mold()
        self.user_cfg.parent.mkdir()
        original = "[net]\nretry = 3\n"
        self.user_cfg.write_text(original)
        r = self.run_setup("--yes")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(
            self.user_cfg.read_text(),
            original,
            "appending a second [profile.dev] table would break cargo",
        )
        self.assertIn(MOLD_LINE, r.stdout, "the user must be shown what to add")
        self.assertIn("not edited", r.stdout)

    # --- the legacy per-checkout file ------------------------------------------
    def legacy(self):
        self.checkout_cfg.parent.mkdir()
        self.checkout_cfg.write_text(
            f"[target.x86_64-unknown-linux-gnu]\n{MOLD_LINE}\n\n[profile.dev]\n{UNPACKED_LINE}\n"
        )

    def test_legacy_checkout_config_is_flagged_as_not_inherited_by_worktrees(self):
        self.with_mold()
        self.legacy()
        r = self.run_setup("--check")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("worktree", r.stdout.lower())
        self.assertTrue(self.checkout_cfg.exists(), "--check must not move anything")
        self.assertFalse(self.user_cfg.exists())

    def test_yes_moves_the_legacy_checkout_config_to_user_level(self):
        self.with_mold()
        self.legacy()
        r = self.run_setup("--yes")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse(self.checkout_cfg.exists())
        self.assertIn(MOLD_LINE, self.user_cfg.read_text())

    def test_declining_the_move_is_not_followed_by_an_offer_to_write(self):
        # Interactive run with no --yes and no tty, where `yes_no` declines every prompt.
        # Asking "Move it?" and then "Write ~/.cargo/config.toml?" is the same question
        # twice, and a yes to the second leaves two configs. `yes_no` prints its prompt
        # only on a tty, so the observable for "the write was offered" is that branch's
        # own `skipped: … not written` line.
        self.with_mold()
        self.legacy()
        r = self.run_setup()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("left as-is", r.stdout)
        self.assertNotIn(
            "not written", r.stdout, "offered to write after the move was declined"
        )
        self.assertIn("you just declined", r.stdout)
        self.assertFalse(self.user_cfg.exists())
        self.assertTrue(self.checkout_cfg.exists())

    def test_without_a_legacy_config_the_write_is_still_offered(self):
        # The control: the one-question rule must not swallow the offer when there was
        # no first question.
        self.with_mold()
        r = self.run_setup()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("not written", r.stdout, "the write was not offered at all")
        self.assertNotIn("you just declined", r.stdout)

    def test_legacy_checkout_config_is_not_moved_over_an_existing_user_config(self):
        self.with_mold()
        self.legacy()
        self.user_cfg.parent.mkdir()
        original = f"[target.x86_64-unknown-linux-gnu]\n{MOLD_LINE}\n"
        self.user_cfg.write_text(original)
        r = self.run_setup("--yes")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.user_cfg.read_text(), original)
        self.assertTrue(self.checkout_cfg.exists())
        self.assertIn(
            "delete", r.stdout.lower(), "must say the checkout copy is now redundant"
        )


if __name__ == "__main__":
    unittest.main()
