#!/usr/bin/env python3
"""Guard: which ci-local.sh targets take the machine-wide gate slot, and that they do.

``scripts/gate-queue.sh`` serialises heavy gate runs, and ``test_gate_queue.py`` covers
the slot itself. This file pins the wiring in ``ci-local.sh``, where the heavy set is an
explicit array. Such a list drifts in both directions:

  * a target added to the dispatch table and not to the array runs unqueued, which brings
    back the overlapping gates the queue exists to end;
  * an interactive tier added to the array blocks a commit behind another session's gate,
    because the pre-commit hook runs ``quick``, ``fmt`` and ``ruff`` through this script.

So every queued name must be a real target, the meta-gates and every compiling leg of
``all`` must queue, and the tiers the hook and the inner loop run must not. The re-exec
must happen before dispatch, be guarded against re-entry, and honour the opt-out. The wait
must be reported next to the leg timings, so it is not mistaken for leg time.

Behavioural assertions read ``strip_comments()`` output; only the documentation assertion
reads the raw banner.
"""

import os
import re
import subprocess
import tempfile
import unittest

from _helpers import REPO_ROOT, SCRIPTS, strip_comments

CI_LOCAL = SCRIPTS / "ci-local.sh"
HOOK = REPO_ROOT / ".githooks" / "pre-commit"

#: The legs of `all` that compile or execute Rust. Every one of them must queue.
COMPILING_LEGS_OF_ALL = (
    "rust",
    "profiles",
    "msrv",
    "doctests",
    "doc",
    "fuzz-smoke",
    "conformance",
    "crypt4gh",
    "corpus",
)

#: Interactive rungs: the hook and the inner loop. None of them may ever queue.
INTERACTIVE = (
    "quick",
    "lint",
    "fmt",
    "clippy-lite",
    "script-tests",
    "ruff",
    "secrets",
    "preflight-all",
    "help",
)

_TARGET = re.compile(r"^      ([a-z0-9-]+)\)", re.MULTILINE)
_HEADER_END = re.compile(r"^[^#\s]", re.MULTILINE)


def body(text: str, name: str) -> str:
    """The stripped body of a shell function, either a one-liner (`f() { …; }`) or a block."""
    one = re.search(rf"^{re.escape(name)}\(\)\s*\{{ (.*) \}}\s*$", text, re.MULTILINE)
    if one is not None:
        return strip_comments(one.group(1))
    m = re.search(
        rf"^{re.escape(name)}\(\)\s*\{{(.*?)^\}}", text, re.DOTALL | re.MULTILINE
    )
    if m is None:
        raise AssertionError(f"could not find a `{name}()` function in ci-local.sh")
    return strip_comments(m.group(1))


# --- Which targets build, derived from the script itself ---------------------------------
# The explicit array can only be checked against something that is not another list, so
# "targets that compile or test" is derived from ci-local.sh's own call graph. A function
# is a builder if its body runs cargo, cross, a docker build or one of the harness scripts
# that do, or if it calls a function that is. Every dispatch target resolving to a builder
# must then be queued, or named in INTERACTIVE_BUILDERS with the reason it is not.

_FUNC = re.compile(r"^([a-z_][a-z0-9_]*)\(\)\s*\{", re.MULTILINE)
_ARM = re.compile(r"^      ([a-z0-9|-]+)\)\s+(.*?) ;;", re.MULTILINE)
_BUILDS = re.compile(
    r"\bcargo\s+(?:\+\S+\s+)?"
    r"(?:build|check|test|nextest|clippy|doc|run|llvm-cov|semver-checks|mutants|fuzz)\b"
    r"|\bcross\s+build\b|\bdocker\s+build\b(?!\s+--check)"
    r"|\bscripts/(?:soak|load|e2e|chaos|mutants-audit)"
)
_STRING = re.compile(r'"[^"]*"|\'[^\']*\'')
_IDENT = re.compile(r"[a-z_][a-z0-9_]*")

#: Targets that compile but stay out of the queue, each with its reason. They are the lint
#: and check rungs that `lint` is made of, plus the one-crate, one-feature inner loops: a
#: developer re-running one of these must not wait behind another session's gate. The
#: equality below fails both ways, on a builder added here without being queued and on a
#: queued builder left here.
INTERACTIVE_BUILDERS = {
    "quick": "the pre-commit hook's tier: fmt + clippy-lite + script-tests",
    "lint": "the middle rung: every lint and no tests, run between commits",
    "clippy-lite": "the hook's own lint",
    "clippy-full": "member of `lint`; a whole-workspace lint, seconds warm",
    "clippy-s3": "profile lint",
    "clippy-vault": "profile lint",
    "clippy-no-default": "profile lint",
    "clippy-otel": "profile lint (opt-in feature)",
    "feature-matrix": "cargo check over feature combinations: a lint, not a test run",
    "test-schema": "one crate, one feature: the docs/*.schema.json inner loop",
    "seams": "documented as the fast docs/Compose loop",
}


def function_bodies(code: str) -> dict[str, str]:
    return {name: body(code, name) for name in _FUNC.findall(code)}


_PREFIX = {
    "env",
    "timed",
    "timed_sub",
    "run",
    "exec",
    "command",
    "time",
    "if",
    "elif",
    "while",
    "until",
    "then",
    "do",
    "else",
    "!",
}
_ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_SPLIT = re.compile(r"\$\(|[;&|(){}\n]")


def calls(fn_body: str, names: set[str]) -> set[str]:
    """Function names at command position. An identifier anywhere is not a call: `--all`
    would make every `cargo fmt --all` a call to `all()`, `rust-toolchain` one to `rust()`."""
    found = set()
    for chunk in _SPLIT.split(_STRING.sub(" ", fn_body)):
        toks = chunk.split()
        while toks and (toks[0] in _PREFIX or _ASSIGN.match(toks[0])):
            toks.pop(0)
        if toks and toks[0] in names:
            found.add(toks[0])
    return found


def builder_functions(code: str) -> set[str]:
    bodies = function_bodies(code)
    names = set(bodies)
    graph = {n: calls(b, names) for n, b in bodies.items()}
    all_legs = re.search(r"^ALL_LEGS=\((.*?)^\)", code, re.DOTALL | re.MULTILINE)
    if all_legs is None:
        raise AssertionError("could not find ALL_LEGS=( … ) in ci-local.sh")
    graph.setdefault("all_legs", set()).update(all_legs.group(1).split())
    builders = {n for n, b in bodies.items() if _BUILDS.search(b)}
    grew = True
    while grew:
        grew = False
        for n, callees in graph.items():
            if n not in builders and callees & builders:
                builders.add(n)
                grew = True
    return builders


def target_functions(code: str) -> dict[str, str]:
    """Dispatch target -> the function main() runs for it (`pins-strict) PINS_STRICT=1 pins`)."""
    names = set(_FUNC.findall(code))
    out = {}
    for targets, cmd in _ARM.findall(code[code.index("\nmain() {") :]):
        fns = [t for t in cmd.split() if t in names]
        for t in targets.split("|"):
            if fns:
                out[t] = fns[-1]
    return out


def hook_invocations(code: str) -> list[tuple[str, list[str]]]:
    """Every line on which the hook executes ci-local.sh, as `(env_prefix, targets)`.

    Not the targets it merely names in a message. An env-prefixed invocation such as
    `GATE_QUEUE=0 ./scripts/ci-local.sh fuzz-smoke` must match, and the prefix is kept,
    because it is what decides whether the line queues. Targets are read to the end of the
    line: a whitespace class that spans newlines pads the set with `else`, `fi` and
    `printf` from the lines below.
    """
    return [
        (m.group(1).strip(), m.group(2).split())
        for m in re.finditer(
            r"^[ \t]*((?:[A-Za-z_][A-Za-z0-9_]*=\S*[ \t]+)*)\./scripts/ci-local\.sh"
            r"((?:[ \t]+[a-z0-9-]+)+)",
            code,
            re.MULTILINE,
        )
    ]


def hook_targets(code: str) -> set[str]:
    """Every literal target the hook executes, whatever its env prefix."""
    return {t for _, targets in hook_invocations(code) for t in targets}


def hook_targets_that_would_queue(code: str) -> set[str]:
    """The targets the hook executes without `GATE_QUEUE=0`: the ones the queue applies to.

    `GATE_QUEUE=0` is the documented opt-out, so a queued leg run under it is the
    interactive form rather than a commit that blocks behind another session's gate.
    """
    return {
        t
        for prefix, targets in hook_invocations(code)
        for t in targets
        if not re.search(r"(^|\s)GATE_QUEUE=0(\s|$)", prefix)
    }


def queued_legs(code: str) -> list[str]:
    m = re.search(r"^GATE_QUEUE_LEGS=\((.*?)^\)", code, re.DOTALL | re.MULTILINE)
    if m is None:
        raise AssertionError("could not find GATE_QUEUE_LEGS=( … ) in ci-local.sh")
    return m.group(1).split()


class GateQueueWiringTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = CI_LOCAL.read_text(encoding="utf-8")
        cls.code = strip_comments(cls.text)
        cls.queued = queued_legs(cls.code)
        cls.targets = set(_TARGET.findall(cls.code[cls.code.index("\nmain() {") :]))
        cls.main = body(cls.text, "main")

    def test_the_queued_set_and_the_dispatch_table_parsed(self):
        self.assertGreaterEqual(len(self.queued), 5, self.queued)
        self.assertGreater(len(self.targets), 30, "dispatch table did not parse")

    def test_every_queued_name_is_a_real_target(self):
        self.assertEqual(
            set(self.queued) - self.targets,
            set(),
            "GATE_QUEUE_LEGS names something main() cannot dispatch",
        )

    def test_the_meta_gates_queue(self):
        for t in ("all", "release"):
            self.assertIn(t, self.queued)

    def test_every_compiling_leg_of_all_queues(self):
        self.assertEqual(set(COMPILING_LEGS_OF_ALL) - set(self.queued), set())

    def test_the_interactive_tiers_never_queue(self):
        self.assertEqual(set(INTERACTIVE) & set(self.queued), set())

    def test_nothing_the_pre_commit_hook_runs_queues(self):
        hook = strip_comments(HOOK.read_text(encoding="utf-8"))
        ran_by_hook = hook_targets(hook)
        self.assertGreaterEqual(
            len(ran_by_hook),
            3,
            "the hook no longer invokes ci-local.sh by literal target",
        )
        # The env-prefixed line must be seen, and it must be the opted-out form: without
        # `GATE_QUEUE=0` it would queue.
        self.assertIn(
            "fuzz-smoke", ran_by_hook, "the GATE_QUEUE=0 fuzz-smoke line is invisible"
        )
        self.assertIn(
            "fuzz-smoke", self.queued, "fuzz-smoke is no longer in GATE_QUEUE_LEGS"
        )
        self.assertEqual(
            hook_targets_that_would_queue(hook) & set(self.queued),
            set(),
            "a commit would block behind another session's gate",
        )

    def test_main_reexecs_under_the_queue_before_dispatching(self):
        self.assertIn("gate-queue.sh", self.main)
        self.assertIn("gate_queue_wanted", self.main)
        self.assertLess(
            self.main.index("gate-queue.sh"),
            self.main.index('for t in "${targets[@]}"'),
            "the slot must be taken before any leg runs",
        )

    def test_the_reexec_is_guarded_against_reentry_and_honours_the_opt_out(self):
        guard = self.main[: self.main.index("gate-queue.sh")]
        self.assertIn(
            "GATE_QUEUE_WAIT", guard, "re-entry guard: the child must not queue again"
        )
        # The opt-out expression, not the substring: a bare `GATE_QUEUE` match is
        # satisfied by the `GATE_QUEUE_WAIT` re-entry check on the line above it.
        self.assertRegex(
            guard,
            r'"\$\{GATE_QUEUE:-1\}"\s*!=\s*0',
            "GATE_QUEUE=0 must skip the queue (the guard no longer tests the variable)",
        )

    def test_the_default_lock_is_one_file_for_every_checkout(self):
        lock = body(self.text, "gate_lock_path")
        self.assertIn("GATE_LOCK", lock, "the path must be overridable")
        # Behavioural and token-based, because neither alone covers the other. The probe
        # runs the shipped function from two directories with GATE_LOCK unset and requires
        # the same path; a per-checkout path would let worktrees run their gates
        # concurrently. Both probe directories sit outside any repo, so a path spelled off
        # `git rev-parse` fails identically in both and compares equal, and `BASH_SOURCE`
        # reads the same under `bash -c` both times. The token checks cover those two
        # spellings.
        for token in ("PWD", "git rev-parse", "BASH_SOURCE", "target/"):
            self.assertNotIn(
                token,
                lock,
                f"the default lock path is spelled per-checkout via {token!r}",
            )
        fn = re.search(
            r"^gate_lock_path\(\)\s*\{.*?\}$", self.text, re.MULTILINE | re.DOTALL
        )
        self.assertIsNotNone(fn, "could not extract gate_lock_path")
        paths = []
        for _ in range(2):
            with tempfile.TemporaryDirectory(prefix="gdi-lock-") as cwd:
                proc = subprocess.run(
                    ["bash", "-c", f"{fn.group(0)}\ngate_lock_path"],
                    cwd=cwd,
                    env={k: v for k, v in os.environ.items() if k != "GATE_LOCK"},
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                paths.append(proc.stdout.strip())
        self.assertTrue(paths[0], "gate_lock_path printed nothing")
        self.assertEqual(
            paths[0],
            paths[1],
            f"the default lock path depends on the working directory: {paths}",
        )
        self.assertTrue(
            paths[0].startswith("/"), f"the default lock path is relative: {paths[0]}"
        )

    def test_every_target_that_builds_or_tests_queues_unless_listed_as_interactive(
        self,
    ):
        builders = builder_functions(self.code)
        self.assertIn("all", builders)
        self.assertIn("rust", builders, "the call-graph walk lost a one-liner meta-leg")
        self.assertIn("harness", builders, "the call-graph walk lost a harness script")
        building_targets = {
            t for t, fn in target_functions(self.code).items() if fn in builders
        }
        self.assertGreater(
            len(building_targets), 25, "the builder derivation collapsed"
        )
        unqueued = building_targets - set(self.queued)
        self.assertEqual(
            unqueued,
            set(INTERACTIVE_BUILDERS),
            "a target that builds is neither queued nor listed as interactive, or "
            "INTERACTIVE_BUILDERS names one that no longer builds or is now queued",
        )

    def test_the_wait_is_reported_with_the_leg_timings(self):
        self.assertIn("GATE_QUEUE_WAIT", body(self.text, "print_leg_timings"))

    def test_the_knobs_are_documented_in_the_banner(self):
        m = _HEADER_END.search(self.text)
        banner = self.text[: m.start()] if m else self.text
        for knob in ("GATE_QUEUE", "GATE_LOCK"):
            self.assertRegex(
                banner,
                re.compile(rf"^#   {knob}\b", re.MULTILINE),
                f"{knob} missing from the Env: block",
            )


class ClippyWarmMarkerTest(unittest.TestCase):
    """`.githooks/pre-commit` prints its "will build from cold" warning only when this
    marker is absent, so everything that warms `target/` must write it. Otherwise running
    `clippy_lite` directly, the scoped inner loop CONTRIBUTING recommends, leaves a warm
    tree looking cold at the next commit. The path is duplicated between two independently
    executable scripts, and this guard keeps the two copies in step.
    """

    MARKER = "target/debug/.gdi-clippy-warm"

    def test_the_hook_reads_this_marker(self):
        hook_code = strip_comments(HOOK.read_text(encoding="utf-8"))
        self.assertIn(self.MARKER, hook_code)

    def test_clippy_lite_writes_the_same_marker_on_success(self):
        fn_body = body(CI_LOCAL.read_text(encoding="utf-8"), "clippy_lite")
        self.assertIn(
            self.MARKER,
            fn_body,
            "clippy_lite() must write the hook's marker path after a successful run, or "
            'the hook\'s "will build from cold" warning fires on a target/ that is '
            "actually warm",
        )


if __name__ == "__main__":
    unittest.main()
