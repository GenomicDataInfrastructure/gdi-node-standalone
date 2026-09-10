#!/usr/bin/env python3
"""Guard: the gate's leg order and fatality rules, which are invisible in a green run.

Breaking one of these does not turn a leg red. It stops the leg from running at all:

  1. `all_legs()` is a bare loop under `set -e`, so the first non-zero leg ends the run. A
     leg whose verdict is about the world (an upstream repo, an advisory database) must
     therefore run after every leg that compiles and tests this tree.

  2. External-pin drift is a warning in `all` and fatal only where shipping is at stake.
     Otherwise an upstream cutting a tag turns the per-change gate red with no edit that
     could fix it, and skips every leg behind it.

  3. `release` must not inherit `all`'s short-circuit, or a tag-time gate can Trivy-scan
     and cross-compile on top of a core it never compiled.

  4. `secrets` reads files the gate key cannot see, because `gitleaks --no-git` ignores
     .gitignore, so its input can change while the key stays byte-identical. It must
     re-run on a short-circuit, and it must run first there, ahead of legs that abort the
     run on a new advisory. `pins` must not re-run there: its unauthenticated API budget
     is exhausted within a few short-circuits, after which it passes unconditionally.

  5. `dev-reset.sh` must anchor to its own location before deriving its Compose project,
     or running it from a sibling repo destroys that stack's volumes.

  6. `mutants-audit.sh` reverts `crates/` on exit after a long run, so it must save the
     working tree first.

Assertions read `strip_comments()` output wherever they are about behaviour, so a comment
restating a rule cannot satisfy the guard for it.
"""

import re
import unittest

from _helpers import SCRIPTS, strip_comments

CI_LOCAL = SCRIPTS / "ci-local.sh"
DEV_RESET = SCRIPTS / "dev-reset.sh"
MUTANTS = SCRIPTS / "mutants-audit.sh"

#: Legs that compile or execute Rust. A world-verdict leg must not precede any of these.
COMPILING_LEGS = ("rust", "profiles", "doctests", "doc", "msrv")

#: Legs whose verdict can change while the tree stands still, so they run last.
#: `secrets` is the exception: it is local, fast and wanted early, and the short-circuit
#: test below covers it separately.
WORLD_VERDICT_LEGS = ("pins", "supply_chain")


def body(text: str, name: str) -> str:
    """The stripped body of a shell function, up to the closing brace at column 0."""
    m = re.search(
        rf"^{re.escape(name)}\(\) \{{(.*?)^\}}", text, re.DOTALL | re.MULTILINE
    )
    if m is None:
        raise AssertionError(f"could not find a `{name}()` function in the script")
    return strip_comments(m.group(1))


def all_legs(text: str) -> list[str]:
    m = re.search(r"^ALL_LEGS=\((.*?)^\)", text, re.DOTALL | re.MULTILINE)
    if m is None:
        raise AssertionError("could not find ALL_LEGS")
    return strip_comments(m.group(1)).split()


def documented_all_legs(text: str) -> list[str]:
    """The leg list `--help` prints for the `all` target, in printed order.

    `usage()` echoes this script's leading comment block verbatim, so that enumeration is
    a second copy of `ALL_LEGS`. It is user-facing and cannot be deleted, so it is bound
    here instead. It names targets (`script-tests`, `shellcheck`) where the array holds
    functions (`script_tests`, `shellcheck_lint`), so each entry is resolved through the
    script's own dispatch table. A hyphen-to-underscore rewrite is the fallback for a
    target the table does not name.
    """
    entry = re.search(r"^#   all\s{2,}(.*?)(?=^#   \S)", text, re.DOTALL | re.MULTILINE)
    if entry is None:
        raise AssertionError(
            "could not find the `all` entry in the usage block; if its shape changed, "
            "fix this parser rather than dropping the check, or the two copies of the "
            "leg list drift again"
        )
    joined = " ".join(line.lstrip("#").strip() for line in entry.group(1).splitlines())
    # The legs follow the last colon and stop at the trailing parenthetical aside.
    _, _, tail = joined.rpartition(":")
    tail = tail.split("(")[0]
    dispatch = target_to_function(text)
    return [
        dispatch.get(leg.strip(), leg.strip().replace("-", "_"))
        for leg in tail.split("+")
        if leg.strip()
    ]


def target_to_function(text: str) -> dict[str, str]:
    """The script's own `target) function ;;` dispatch table.

    The usage block names targets (`cross`) and the meta-leg bodies call functions
    (`cross_compile`). Resolving through the table the script already defines means this
    guard learns a renamed target for free, instead of carrying a second mapping to drift.
    """
    arms = re.findall(
        r"^\s{4,}([a-z0-9|.-]+)\)\s+(?:\w+=\S+\s+)?(\w+)\s*;;", text, re.MULTILINE
    )
    table = {target: fn for target, fn in arms if "|" not in target}
    if len(table) < 20:
        raise AssertionError(
            f"only {len(table)} dispatch arms parsed from ci-local.sh; the `case` shape "
            "changed and this guard would stop resolving target names"
        )
    return table


def documented_release_legs(text: str) -> list[str]:
    """The leg list `--help` prints for the `release` target, in printed order.

    The same duplication `documented_all_legs` binds, one usage entry further down.
    """
    entry = re.search(
        r"^#   release\s{2,}(.*?)(?=^#   \S)", text, re.DOTALL | re.MULTILINE
    )
    if entry is None:
        raise AssertionError("could not find the `release` entry in the usage block")
    joined = " ".join(line.lstrip("#").strip() for line in entry.group(1).splitlines())
    _, _, tail = joined.partition(":")
    tail = tail.split("(")[0]
    dispatch = target_to_function(text)
    return [
        dispatch.get(leg.strip(), leg.strip().replace("-", "_"))
        for leg in tail.split("+")
        if leg.strip()
    ]


def fresh_branch(text: str) -> str:
    """Just the FRESH short-circuit branch of `all()`, not the whole function.

    The assertion below is that these legs run when the gate short-circuits. Searched
    against the whole `all()` body it would also be satisfied by a call on the normal
    path, so moving a leg out of the short-circuit would leave it green.
    """
    all_body = body(text, "all")
    m = re.search(
        r'\[\[ "\$verdict" == FRESH\* \]\]; then(.*?)^\s*return 0',
        all_body,
        re.DOTALL | re.MULTILINE,
    )
    if m is None:
        raise AssertionError("could not find the FRESH short-circuit branch of `all()`")
    return m.group(1)


class LegOrderTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = CI_LOCAL.read_text(encoding="utf-8")
        cls.legs = all_legs(cls.text)

    def test_the_leg_list_parsed(self):
        # Anti-vacuity, derived rather than guessed. A numeric floor would be a third copy
        # of the list's length, and legs could vanish beneath it. `--help` already
        # enumerates the legs, so requiring exact agreement pins the count without writing
        # one down, and fails when a leg leaves the array but is still advertised.
        self.assertEqual(
            self.legs,
            documented_all_legs(self.text),
            "ALL_LEGS and the leg list `--help` prints for `all` have drifted. They are "
            "the same fact in two places and the usage block is user-facing, so fix "
            "whichever is wrong rather than relaxing this.",
        )
        self.assertEqual(
            len(self.legs),
            len(set(self.legs)),
            f"duplicate leg in ALL_LEGS: {self.legs}",
        )

    def test_every_leg_is_a_function_that_exists(self):
        # A typo'd leg name is not a parse error: `timed "$leg"` would call a command that
        # does not exist, and the array shape stays perfectly valid.
        for leg in self.legs:
            self.assertRegex(
                self.text,
                rf"(?m)^{re.escape(leg)}\(\)",
                f"ALL_LEGS names `{leg}` but ci-local.sh defines no such function",
            )

    def test_the_gate_actually_iterates_the_array_this_suite_checks(self):
        # Every ordering assertion here is about the array, and says nothing about
        # execution unless the runner walks that array in order. An `all_legs()` rewritten
        # to call legs by hand could reorder the gate and leave this whole file green.
        self.assertRegex(
            strip_comments(self.text),
            r'all_legs\(\)\s*\{[^}]*for\s+\w+\s+in\s+"\$\{ALL_LEGS\[@\]\}"',
            "`all_legs()` no longer iterates ALL_LEGS, so the order asserted in this file "
            "is not the order the gate runs",
        )

    def test_every_leg_named_here_is_really_in_the_list(self):
        # Binds the constants above to reality: a leg renamed in ci-local.sh would
        # otherwise silently drop out of both assertions and leave them green.
        for leg in COMPILING_LEGS + WORLD_VERDICT_LEGS:
            self.assertIn(
                leg, self.legs, f"{leg!r} is not in ALL_LEGS; it was renamed or removed"
            )

    def test_world_verdict_legs_run_after_everything_that_compiles(self):
        last_compiling = max(self.legs.index(leg) for leg in COMPILING_LEGS)
        for leg in WORLD_VERDICT_LEGS:
            self.assertGreater(
                self.legs.index(leg),
                last_compiling,
                f"{leg!r} runs at position {self.legs.index(leg)}, before "
                f"{self.legs[last_compiling]!r} at {last_compiling}. `all_legs()` stops at "
                "the first failure, so a verdict about the world would skip the legs that "
                "verify this tree. Move it after them.",
            )

    def test_ruff_runs_after_every_leg_that_compiles(self):
        # `ruff` is a tree verdict, but it fetches its toolchain through `uvx`, so a cold
        # cache plus a PyPI outage would skip every compile and test leg behind it.
        for leg in COMPILING_LEGS:
            self.assertGreater(
                self.legs.index("ruff"),
                self.legs.index(leg),
                f"`ruff` runs before `{leg}`. It fetches over the network, so a PyPI "
                f"outage would skip `{leg}` entirely.",
            )


class ShortCircuitTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.branch = strip_comments(fresh_branch(CI_LOCAL.read_text(encoding="utf-8")))

    #: The legs a FRESH marker must still run: their verdict is not a function of the key.
    RERUN = ("secrets", "deny", "deny_fuzz", "pip_audit")

    def _called(self) -> list[str]:
        """The leg calls in the FRESH branch, in order (a bare name on its own line)."""
        return re.findall(r"^\s*([a-z_]+)\s*$", self.branch, re.MULTILINE)

    def test_short_circuit_reruns_every_leg_whose_input_is_outside_the_key(self):
        # gate-key.sh hashes tracked and untracked-not-ignored files plus the toolchain. A
        # leg whose verdict depends on anything else must re-run even on a FRESH marker,
        # or the short-circuit becomes a way of never running it. `deny_fuzz` is a second
        # advisory scan, over the fuzz crate's own lockfile, which the root scan misses.
        # The search is scoped to the FRESH branch, so a call elsewhere in `all()` cannot
        # satisfy it.
        called = self._called()
        for leg in self.RERUN:
            self.assertIn(
                leg,
                called,
                f"the FRESH short-circuit does not call `{leg}`; its verdict is not a "
                "function of the gate key, so skipping it makes the cached green false",
            )

    def test_secrets_runs_first_on_the_short_circuit(self):
        # The branch is a bare sequence under `set -e`, so a new advisory unrelated to
        # this tree can end the run before `secrets`, the one leg that is about the secret
        # someone is about to commit.
        called = self._called()
        self.assertTrue(called, "no leg calls parsed from the FRESH branch")
        self.assertEqual(
            called[0],
            "secrets",
            f"`secrets` runs at position {called.index('secrets') if 'secrets' in called else '?'} "
            f"of the short-circuit ({called}); an advisory red ahead of it hides it",
        )

    def test_pins_is_not_rerun_on_the_short_circuit(self):
        # The leg makes a dozen unauthenticated GitHub API calls per run against a
        # 60-per-hour budget, so a few short-circuits exhaust it, every pin then reports
        # UNREACHABLE and the leg returns 0. Upstream refs do not move hourly, and `pins`
        # still runs in every full `all`.
        self.assertNotIn(
            "pins",
            self._called(),
            "`pins` is back in the FRESH short-circuit; it exhausts the GitHub API budget "
            "and then silently passes",
        )


class ReleaseIsNeverCachedTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.release_body = body(CI_LOCAL.read_text(encoding="utf-8"), "release")

    # Both assertions demand an export or an assignment, not merely the characters. A bare
    # `assertIn` is satisfied by any mention, including an `echo` or a help string.
    def test_release_forces_a_complete_run(self):
        self.assertRegex(
            self.release_body,
            r"(?m)^\s*(export\s+[^\n]*)?\bGATE_FORCE=1\b",
            "`release` calls `all`, which short-circuits on a marker under 24 h old. "
            "Without GATE_FORCE=1 exported, a tag-time gate can ship artifacts built on a "
            "core it never compiled.",
        )

    def test_release_makes_pin_drift_fatal_again(self):
        self.assertRegex(
            self.release_body,
            r"(?m)^\s*(export\s+[^\n]*)?\bPINS_STRICT=1\b",
            "pin drift is a warning in the per-change gate; `release` is where being "
            "behind the federation actually costs something, so it must fail closed",
        )

    def test_release_forbids_skipped_legs(self):
        # `all` lets `promtool` skip visibly without Docker. The export is what makes
        # `record_skip` die instead, so a release gate cannot skip the alert-rule tests.
        # test_ci_local_skips.py executes that path.
        self.assertRegex(
            self.release_body,
            r"(?m)^\s*(export\s+[^\n]*)?\bGATE_STRICT_LEGS=1\b",
            "`release` no longer exports GATE_STRICT_LEGS=1, so a missing Docker lets "
            "it skip the alert-rule tests and still print a green tag gate",
        )


class ReleaseLegsAreDocumentedTest(unittest.TestCase):
    """`--help`'s `release` list must be the legs `release()` runs, in order."""

    def test_the_documented_release_legs_are_the_ones_it_runs(self):
        text = CI_LOCAL.read_text(encoding="utf-8")
        # The leg run is the last non-empty line of the body. The `export` above it sets
        # GATE_FORCE and PINS_STRICT and is not a leg, so the whole body cannot be split
        # on `;`.
        run_line = [ln for ln in body(text, "release").splitlines() if ln.strip()][-1]
        called = [leg.strip() for leg in run_line.split(";") if leg.strip()]
        self.assertEqual(
            called,
            documented_release_legs(text),
            "the `release` usage entry and the `release()` body have drifted. The entry "
            "is printed verbatim by `--help`, so fix whichever of the two is wrong.",
        )


class PinDriftFatalityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pins_body = body(CI_LOCAL.read_text(encoding="utf-8"), "pins")

    def test_drift_is_only_fatal_under_strict_mode(self):
        # Asserts the structure, a `die` opening a `PINS_STRICT` conditional, rather than
        # two string offsets. Comparing offsets lets a `PINS_STRICT` mentioned in an
        # earlier `printf` appear to guard a `die` that is unconditional.
        self.assertRegex(
            self.pins_body,
            r"if\s*\[\[[^]]*PINS_STRICT[^]]*\]\];\s*then\s+die\b",
            "the drift `die` is no longer the guarded branch of a PINS_STRICT "
            "conditional; `all` would then go red because an upstream moved, skipping "
            "every leg after `pins`",
        )
        # The other half of the same rule: with strict mode off, the drift arm must fall
        # through to `return 0`. A guarded `die` alone says nothing about the branch that
        # runs on every per-change gate.
        self.assertRegex(
            self.pins_body,
            r"fi\s+(printf[^\n]*\n\s*)+return 0",
            "the non-strict drift path no longer ends in `return 0`; `all` would go red "
            "because an upstream moved, skipping every leg after `pins`",
        )


class AnchoringTest(unittest.TestCase):
    def test_dev_reset_anchors_before_it_reads_the_working_directory(self):
        text = strip_comments(DEV_RESET.read_text(encoding="utf-8"))
        # The `cd` must be anchored to the script, not merely present: any column-0 `cd`
        # would satisfy a guard whose subject is that PROJECT must not come from the
        # caller's directory.
        cd = re.search(
            r"^cd .*(\$0|BASH_SOURCE|rev-parse --show-toplevel)", text, re.MULTILINE
        )
        project = re.search(r"^PROJECT=", text, re.MULTILINE)
        if cd is None:
            self.fail(
                "dev-reset.sh no longer anchors itself to its own location before "
                "deriving PROJECT (expected a `cd` relative to $0 / BASH_SOURCE / the "
                "git toplevel)"
            )
        if project is None:
            self.fail("dev-reset.sh no longer derives PROJECT")
        self.assertLess(
            cd.start(),
            project.start(),
            "PROJECT is derived before the `cd`, so it comes from the caller's directory. "
            "Run from a sibling repo with its own Compose stack, `docker compose down -v` "
            "then destroys that stack's volumes.",
        )


class MutantsRestoreTest(unittest.TestCase):
    def test_the_exit_trap_saves_the_tree_before_reverting(self):
        text = MUTANTS.read_text(encoding="utf-8")
        restore = body(text, "restore_tree")
        # `git diff` must be redirected to a file. Ordering alone proves nothing: output
        # to the terminal satisfies "a patch is captured" while leaving edits made during
        # the run just as unrecoverable.
        saved = re.search(r"git diff[^\n]*>\s*\"?\$?[\w{]", restore)
        checkout = restore.find("git checkout")
        if saved is None:
            self.fail(
                "restore_tree runs `git diff` but does not redirect it to a file, so "
                "nothing is actually saved before the checkout discards it"
            )
        self.assertNotEqual(checkout, -1, "restore_tree no longer restores the tree")
        self.assertLess(
            saved.start(),
            checkout,
            "restore_tree reverts before saving. A full audit runs for hours in the "
            "background, so anything edited meanwhile is destroyed with no backup, and "
            "`--in-place` leaves no scratch copy to recover from.",
        )

    def test_the_trap_is_actually_installed(self):
        text = strip_comments(MUTANTS.read_text(encoding="utf-8"))
        # Trailing signals are allowed, so that `trap restore_tree EXIT INT TERM` passes.
        self.assertIsNotNone(
            re.search(r"^trap restore_tree EXIT\b", text, re.MULTILINE),
            "restore_tree exists but nothing installs it as the EXIT trap",
        )

    def test_success_message_does_not_claim_a_restore_that_has_not_happened(self):
        # A past-tense "the tree is restored" printed from the main body runs before the
        # EXIT trap that does the restoring, so it can never be false.
        text = strip_comments(MUTANTS.read_text(encoding="utf-8"))
        self.assertNotIn(
            "the tree is restored;",
            text,
            "this message runs before the EXIT trap that does the restoring, so it "
            "asserts a past-tense fact that has not happened yet",
        )
        # The message must still say something. An `assertNotIn` for an absent literal
        # passes for any rewording, including deleting the line altogether.
        self.assertRegex(
            text,
            r"restored on exit",
            "the run no longer tells the operator the tree is restored on exit. The "
            "assertion above only forbids the past-tense claim, so without this one, "
            "deleting the message altogether passes.",
        )


if __name__ == "__main__":
    unittest.main()
