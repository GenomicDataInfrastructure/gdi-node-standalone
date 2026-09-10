#!/usr/bin/env python3
"""Guard: the pre-commit hook's clippy-skip classifier.

The hook skips clippy when no staged path can change a clippy result, so a commit that
touches no Rust does not pay for a foregone conclusion. That is only safe if the
classifier is right, so this pins it against a table of real paths from this repository.

The regex is extracted from the hook rather than restated here. A copy would drift, and a
drifted copy would test nothing. This fails if the hook's pattern stops matching what the
table says it must.

A wrongly skipped clippy surfaces at `ci-local.sh all` rather than in `main`, so this
guards trust in the hook rather than correctness of the tree.
"""

import re
import subprocess
import unittest

from _helpers import REPO_ROOT, strip_comments

HOOK = REPO_ROOT / ".githooks" / "pre-commit"

# Assertions about what the hook does read `code`, which is comment-stripped. Only
# assertions genuinely about documentation may read `text`: a comment can state the
# opposite of the property an assertion is named for and still satisfy it.


#: Paths that must trigger clippy: each can change what clippy reports.
MUST_TRIGGER = [
    "crates/core/src/lib.rs",
    "crates/gdi-node-standalone/src/vault.rs",
    "crates/core/fuzz/fuzz_targets/parquet_validate.rs",
    "crates/gdi-node-standalone/tests/it/main.rs",
    "build.rs",
    "Cargo.toml",
    "Cargo.lock",
    "crates/core/Cargo.toml",
    "crates/core/fuzz/Cargo.lock",
    "clippy.toml",
    "rust-toolchain.toml",
    ".cargo/config.toml",
]

#: Paths that must not trigger clippy: none can change a clippy result. Each is a file
#: type this repository commits on its own.
MUST_NOT_TRIGGER = [
    "docs/deployment.md",
    "docs/operating.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "docker-compose.yml",
    "docker-compose.external.yml",
    "compose/secrets-init.sh",
    "compose/openbao.hcl",
    "scripts/dev-reset.sh",
    "scripts/tests/k8s/test_k8s_manifests.py",
    "compose/observability/rules/gdi-node-standalone.yml",
    "compose/observability/grafana/dashboards/gdi-node-standalone.json",
    "deploy/kubernetes/base/deployment.yaml",
    ".github/workflows/ci.yml",
    ".gitignore",
    # Adversarial: 'rs' appears, but not as the extension.
    "docs/rs-notes.md",
    "crates/core/src/rsync-notes.txt",
]


def hook_regex() -> str:
    """The `rust_trigger` pattern, read out of the hook itself."""
    text = HOOK.read_text(encoding="utf-8")
    m = re.search(r"# RUST_TRIGGER_RE\n\s*rust_trigger='([^']+)'", text)
    if not m:
        raise AssertionError(
            "could not find the RUST_TRIGGER_RE marker + rust_trigger='...' line in "
            f"{HOOK}; the hook changed shape and this guard needs updating with it"
        )
    return m.group(1)


def matches(pattern: str, path: str) -> bool:
    """Classify with grep -E, which is what the hook runs."""
    proc = subprocess.run(
        ["grep", "-qE", pattern],
        input=f"{path}\n",
        text=True,
        check=False,
    )
    return proc.returncode == 0


class PreCommitClassifierTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pattern = hook_regex()

    def test_the_pattern_was_extracted(self):
        self.assertTrue(self.pattern, "empty pattern extracted from the hook")

    def test_rust_relevant_paths_trigger_clippy(self):
        for path in MUST_TRIGGER:
            with self.subTest(path=path):
                self.assertTrue(
                    matches(self.pattern, path),
                    f"{path} must run clippy; it can change what clippy reports",
                )

    def test_non_rust_paths_skip_clippy(self):
        for path in MUST_NOT_TRIGGER:
            with self.subTest(path=path):
                self.assertFalse(
                    matches(self.pattern, path),
                    f"{path} cannot change a clippy result, so the hook must skip it",
                )

    def test_hook_still_runs_fmt_unconditionally(self):
        # rustfmt parses rather than compiles and is cheap, so it stays on every path.
        # Without it, formatting drifts on commits that touch .rs incidentally.
        text = HOOK.read_text(encoding="utf-8")
        self.assertIn(
            "ci-local.sh fmt",
            text,
            "the skip branch must still run rustfmt, not nothing at all",
        )

    def test_hook_explains_the_skip_to_the_developer(self):
        # A silent skip is indistinguishable from a broken hook.
        text = HOOK.read_text(encoding="utf-8")
        self.assertIn("skipping clippy", text)


def guard_regex() -> str:
    """The `guard_trigger` pattern, read out of the hook itself."""
    text = HOOK.read_text(encoding="utf-8")
    m = re.search(r"# GUARD_TRIGGER_RE\n\s*guard_trigger='([^']+)'", text)
    if not m:
        raise AssertionError(
            "could not find the GUARD_TRIGGER_RE marker + guard_trigger='...' line in "
            f"{HOOK}; the hook changed shape and this guard needs updating with it"
        )
    return m.group(1)


#: Staging any of these can invalidate a scripts/tests guard without touching Rust, so the
#: hook must run the suite. Otherwise it runs only on Rust-relevant commits and in `all`,
#: never on the commits most likely to break it.
GUARD_MUST_TRIGGER = [
    "scripts/ci-local.sh",
    "scripts/gate-key.sh",
    "scripts/gate-status.sh",
    "scripts/dev-reset.sh",
    "scripts/tests/test_gate_key.py",
    "scripts/tests/_helpers.py",
    "scripts/load/checks.py",
    ".githooks/pre-commit",
    "ruff.toml",
]

#: These must not. Either nothing asserts against them, or, for deploy/kubernetes/, the
#: guard that does is the `k8s-manifests` leg, which needs PyYAML and so runs in `all`
#: rather than on the commit path. Keeping it out of the hook is what makes `script-tests`
#: stdlib-only.
GUARD_MUST_NOT_TRIGGER = [
    "deploy/kubernetes/base/pvc.yaml",
    "deploy/kubernetes/base/deployment.yaml",
    "docs/operating.md",
    "CHANGELOG.md",
    "README.md",
    "crates/core/src/lib.rs",
    "compose/openbao.hcl",
    "docker-compose.yml",
    # Adversarial: the prefixes must be anchored, not matched anywhere in the path.
    "docs/scripts-notes.md",
    "crates/core/src/scripts/mod.rs",
    "conformance/ruff.toml",
]


class GuardTriggerTest(unittest.TestCase):
    """The hook must run script-tests when a path those tests assert against is staged."""

    @classmethod
    def setUpClass(cls):
        cls.pattern = guard_regex()
        cls.code = strip_comments(HOOK.read_text(encoding="utf-8"))

    def test_the_pattern_was_extracted(self):
        self.assertTrue(self.pattern, "empty guard pattern extracted from the hook")

    def test_gate_guard_paths_run_the_script_tests(self):
        for path in GUARD_MUST_TRIGGER:
            with self.subTest(path=path):
                self.assertTrue(
                    matches(self.pattern, path),
                    f"{path} is asserted against by scripts/tests/, so staging it must run them",
                )

    def test_unrelated_paths_do_not(self):
        for path in GUARD_MUST_NOT_TRIGGER:
            with self.subTest(path=path):
                self.assertFalse(
                    matches(self.pattern, path),
                    f"{path} cannot invalidate a scripts/tests guard, so running them costs "
                    "time for nothing",
                )

    def test_the_hook_actually_runs_the_leg_on_a_match(self):
        # The regex being right is worthless if the branch runs something else.
        self.assertIn("ci-local.sh fmt script-tests", self.code)


def py_regex() -> str:
    """The `py_trigger` pattern, read out of the hook itself."""
    text = HOOK.read_text(encoding="utf-8")
    m = re.search(r"# PY_TRIGGER_RE\n\s*py_trigger='([^']+)'", text)
    if not m:
        raise AssertionError(
            "could not find the PY_TRIGGER_RE marker + py_trigger='...' line in "
            f"{HOOK}; the hook changed shape and this guard needs updating with it"
        )
    return m.group(1)


#: Staging any of these puts Python through `ruff`'s lint and format check in `all`, so
#: the hook must check it too. `fmt` is rustfmt and `script-tests` passes regardless of
#: layout, so nothing else on the commit path catches a `ruff format` violation.
PY_MUST_TRIGGER = [
    "scripts/tests/test_gate_key.py",
    "scripts/tests/_helpers.py",
    "scripts/check-ci-gate.py",
    "scripts/load/checks.py",
    "conformance/check_dataset.py",
    "conformance/test_check_dataset.py",
    "ruff.toml",
]

#: These must not: ruff lints `conformance/` and `scripts/` only, and a non-Python file
#: in them cannot carry a Python formatting error.
PY_MUST_NOT_TRIGGER = [
    "scripts/ci-local.sh",
    "scripts/e2e/run.sh",
    ".githooks/pre-commit",
    "crates/core/src/lib.rs",
    "docs/operating.md",
    "deploy/kubernetes/base/pvc.yaml",
    # Adversarial: ruff does not lint these trees, so a .py there is out of scope.
    "crates/core/fuzz/generate.py",
    "docs/example.py",
    # Adversarial: the prefixes must be anchored, not matched anywhere in the path.
    "docs/scripts/notes.py",
]


class PyTriggerTest(unittest.TestCase):
    """The hook must run ruff when it stages Python that `ci-local.sh ruff` will lint."""

    @classmethod
    def setUpClass(cls):
        cls.pattern = py_regex()
        cls.code = strip_comments(HOOK.read_text(encoding="utf-8"))

    def test_the_pattern_was_extracted(self):
        self.assertTrue(self.pattern, "empty py pattern extracted from the hook")

    def test_ruff_linted_paths_trigger_the_check(self):
        for path in PY_MUST_TRIGGER:
            with self.subTest(path=path):
                self.assertTrue(
                    matches(self.pattern, path),
                    f"{path} is linted by `ci-local.sh ruff`, so staging it must run ruff",
                )

    def test_other_paths_do_not(self):
        for path in PY_MUST_NOT_TRIGGER:
            with self.subTest(path=path):
                self.assertFalse(
                    matches(self.pattern, path),
                    f"{path} carries no Python that ruff lints, so running ruff costs time "
                    "for nothing",
                )

    def test_the_hook_actually_runs_ruff_on_a_match(self):
        # The regex being right is worthless if the branch runs something else.
        self.assertIn("ci-local.sh ruff", self.code)

    def test_a_missing_uv_degrades_loudly_rather_than_silently(self):
        """The skip must be announced. A lint that quietly does not run is the bug."""
        self.assertIn("command -v uv", self.code)
        self.assertRegex(
            self.code,
            r"WARNING[^\n]*uv",
            "the uv-absent branch must warn that ruff did not run, not skip in silence",
        )


def feature_regex() -> str:
    """The `feature_trigger` pattern, read out of the hook itself."""
    text = HOOK.read_text(encoding="utf-8")
    m = re.search(r"# FEATURE_TRIGGER_RE\n\s*feature_trigger='([^']+)'", text)
    if not m:
        raise AssertionError(
            "could not find the FEATURE_TRIGGER_RE marker + feature_trigger='...' line in "
            f"{HOOK}; the hook changed shape and this guard needs updating with it"
        )
    return m.group(1)


class FeatureProfileEscalationTest(unittest.TestCase):
    """`quick` lints the default profile only, so `#[cfg(feature = ...)]` code is never
    compiled by it and a lint on gated code surfaces only in `all`. The hook escalates to
    `quick clippy-full` when the staged content carries a gate. Not to `lint`, which would
    also drag in ruff and its `uv` requirement."""

    @classmethod
    def setUpClass(cls):
        cls.pattern = feature_regex()
        cls.text = HOOK.read_text(encoding="utf-8")
        cls.code = strip_comments(cls.text)

    def test_the_pattern_matches_a_real_gate(self):
        for line in (
            '#[cfg(feature = "vault")]',
            '    #[cfg(feature = "pme")]',
            '#[cfg(feature="s3")]',
        ):
            with self.subTest(line=line):
                self.assertTrue(
                    matches(self.pattern, line), f"{line!r} is a feature gate"
                )

    def test_the_pattern_ignores_a_gate_quoted_in_prose(self):
        # A `///` doc comment may quote `#[cfg(feature = "s3")]` in a file that carries no
        # gate of its own. An unanchored pattern would escalate on that.
        for line in (
            '/// in this module (it exists only under `#[cfg(feature = "s3")]`).',
            '// #[cfg(feature = "vault")] — commented out',
        ):
            with self.subTest(line=line):
                self.assertFalse(
                    matches(self.pattern, line),
                    f"{line!r} is prose, not a gate",
                )

    def test_whole_module_gating_is_derived_from_the_crate_roots(self):
        # `#[cfg(feature = "pme")] mod pme;` leaves no gate inside `pme.rs`, so a content
        # match alone cannot see it. The hook derives those names from the crate roots.
        self.assertIn("gated_module_names", self.code)
        # One line of context, not two: with two, a `pub mod util;` that merely follows a
        # gated `pub mod tls;` is collected as well, and escalating on an ungated module
        # costs time on every commit for no coverage.
        self.assertIn("-A1", self.code)
        self.assertNotIn("-A2", self.code)

    def test_the_pattern_ignores_non_gates(self):
        # `cfg(unix)` and `cfg(test)` are not feature gates: they compile under the lite
        # profile too, so escalating on them would tax commits for no coverage gain.
        for line in (
            "#[cfg(unix)]",
            "#[cfg(test)]",
            '#[cfg(target_os = "linux")]',
            "// mentions cfg(feature) in prose only",
            'let s = "feature";',
        ):
            with self.subTest(line=line):
                self.assertFalse(
                    matches(self.pattern, line),
                    f"{line!r} must not escalate; it is compiled by the lite profile",
                )

    def test_escalation_reads_the_index_not_the_worktree(self):
        # Reading the index is what makes this correct under `git add -p` and `--amend`:
        # the classification must describe what is being committed, not whatever the
        # worktree holds. Without `--cached` the hook classifies unstaged edits and can
        # skip clippy on a staged feature gate.
        self.assertIn("git grep -q --cached", self.code)

    def test_escalation_runs_quick_plus_clippy_full_not_lint(self):
        # Not `ci-local.sh lint`: that is fmt, clippy-lite, clippy-full and ruff, and
        # `ruff` requires uv, so a commit carrying a feature-gated Rust file but no Python
        # would be refused without uv. `quick clippy-full` gives the same coverage, fmt
        # plus clippy-lite plus script-tests plus the full-profile clippy pass, and does
        # not touch ruff.
        self.assertIn("ci-local.sh quick clippy-full", self.code)
        self.assertNotIn("ci-local.sh lint", self.code)
        self.assertIn("carrying a feature gate", self.code)


class ManifestTriggerTest(unittest.TestCase):
    """A staged crate manifest or lock also compile-gates the fuzz workspace.

    `crates/core/fuzz` is its own workspace with its own `Cargo.lock`, checked `--locked`
    by the `fuzz-smoke` gate leg. Adding a dependency edge to a crate the fuzz targets
    depend on leaves that lock stale, and without this trigger the red surfaces only in
    `all`.
    """

    def setUp(self):
        text = HOOK.read_text(encoding="utf-8")
        m = re.search(r"# MANIFEST_TRIGGER_RE\n\s*manifest_trigger='([^']+)'", text)
        self.assertIsNotNone(
            m,
            "could not find the MANIFEST_TRIGGER_RE marker + manifest_trigger='...' line in .githooks/pre-commit",
        )
        self.pattern = m.group(1)
        self.code = text

    def test_manifests_and_locks_trigger_the_fuzz_gate(self):
        for path in (
            "Cargo.toml",
            "Cargo.lock",
            "crates/beacon/Cargo.toml",
            "crates/core/fuzz/Cargo.lock",
        ):
            self.assertTrue(matches(self.pattern, path), path)

    def test_other_paths_do_not(self):
        for path in (
            "crates/beacon/src/lib.rs",
            "Cargo.toml.orig",
            "docs/Cargo.md",
            "scripts/ci-local.sh",
            "clippy.toml",
        ):
            self.assertFalse(matches(self.pattern, path), path)

    def test_the_hook_actually_runs_the_fuzz_leg_on_a_match(self):
        self.assertIn("ci-local.sh fuzz-smoke", self.code)
        self.assertIn("compile-gating the fuzz workspace", self.code)


if __name__ == "__main__":
    unittest.main()
