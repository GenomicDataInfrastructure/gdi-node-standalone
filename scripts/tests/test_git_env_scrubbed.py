#!/usr/bin/env python3
"""Guard: every test that shells out to git scrubs the ``GIT_*`` environment.

The pre-commit hook runs this suite, and git exports ``GIT_DIR`` and ``GIT_INDEX_FILE``
to hooks. A ``git init <tmpdir>`` under that ``GIT_DIR`` creates no repo in the tmpdir. It
re-initialises the real repository's gitdir and writes ``core.bare = true`` into the
shared ``.git/config``, because a worktree gitdir does not end in ``/.git`` and git
guesses "bare". The main checkout is then unusable as a work tree while the suite stays
green. ``_helpers.clean_git_env`` removes those variables, and this file makes using it a
property of the suite rather than a convention.

Pure stdlib.
"""

import ast
import re
import unittest

from _helpers import SCRIPTS

TESTS = SCRIPTS / "tests"
#: A subprocess argv that starts with git, as text. Used only to decide which files are
#: worth parsing, and to pin the spellings the AST walk must recognise.
_GIT_ARGV = re.compile(r"\[\s*[\"']git[\"']")


#: The `subprocess` entry points that take an argv.
_RUNNERS = frozenset({"run", "call", "check_call", "check_output", "Popen"})


class _Spellings:
    """How a module names `subprocess` and its runners, and which local names hold a git
    argv, read off the module's own imports and assignments.

    Matching only the bare `subprocess.run(…)` would miss `from subprocess import run`,
    `import subprocess as sp`, and an argv bound to a name first, while `_GIT_ARGV` still
    counted the file as checked.
    """

    def __init__(self, tree: ast.AST) -> None:
        self.module_names = {"subprocess"}
        self.runner_names: set[str] = set()
        self.git_argv_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "subprocess":
                        self.module_names.add(alias.asname or "subprocess")
            elif isinstance(node, ast.ImportFrom) and node.module == "subprocess":
                for alias in node.names:
                    if alias.name in _RUNNERS:
                        self.runner_names.add(alias.asname or alias.name)
            elif isinstance(node, ast.Assign) and _is_git_list(node.value):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.git_argv_names.add(target.id)

    def is_runner_call(self, node: ast.Call) -> bool:
        func = node.func
        if isinstance(func, ast.Attribute):
            return (
                isinstance(func.value, ast.Name)
                and func.value.id in self.module_names
                and func.attr in _RUNNERS
            )
        return isinstance(func, ast.Name) and func.id in self.runner_names

    def argv_is_git(self, node: ast.Call) -> bool:
        if not node.args:
            return False
        first = node.args[0]
        if isinstance(first, ast.Name):
            return first.id in self.git_argv_names
        return _is_git_list(first)


def _is_git_list(node: ast.AST) -> bool:
    if not isinstance(node, (ast.List, ast.Tuple)) or not node.elts:
        return False
    head = node.elts[0]
    return isinstance(head, ast.Constant) and head.value == "git"


def unscrubbed_git_calls(source: str) -> list[int]:
    """Line numbers of every subprocess runner call with a git argv that passes no `env=`.

    The check is per invocation, via the AST. A file-granular one would let a single
    `clean_git_env(` anywhere in a file immunise every other git call in it. `env=` must be
    a keyword of that call; any value counts, including a hand-built env, because what
    matters is that the environment is decided at the call site. `_Spellings` recognises
    every spelling of the runner (`subprocess.run`, `sp.run`, a bare imported `run`) and of
    the argv (a literal list, or a name assigned one).
    """
    tree = ast.parse(source)
    spellings = _Spellings(tree)
    return sorted(
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and spellings.is_runner_call(node)
        and spellings.argv_is_git(node)
        and not any(kw.arg == "env" for kw in node.keywords)
    )


class GitEnvScrubbedTest(unittest.TestCase):
    def test_every_git_invocation_scrubs_the_git_environment(self):
        offenders = []
        checked = 0
        # rglob, not glob: scripts/tests/k8s/ is part of the suite and shells out to git
        # under the same hook environment.
        for path in sorted(TESTS.rglob("test_*.py")):
            text = path.read_text(encoding="utf-8")
            if not _GIT_ARGV.search(text):
                continue
            checked += 1
            for line in unscrubbed_git_calls(text):
                offenders.append(f"{path.relative_to(TESTS)}:{line}")
        self.assertGreaterEqual(
            checked, 2, "no test appears to run git; the argv pattern is broken"
        )
        self.assertEqual(
            offenders,
            [],
            "these git invocations inherit the ambient environment, which under the "
            "pre-commit hook carries GIT_DIR and rewrites the real repository. Pass "
            "env=_helpers.clean_git_env() on every call, not once per file",
        )

    def test_every_import_spelling_and_a_named_argv_are_seen(self):
        # Spellings that `_GIT_ARGV` counts as checked, so the AST walk must see them too.
        cases = {
            "from-import": (
                'from subprocess import run\nrun(["git", "init", "-q", "x"])\n'
            ),
            "aliased-module": (
                'import subprocess as sp\nsp.check_output(["git", "status"])\n'
            ),
            "named-argv": (
                "import subprocess\n"
                'cmd = ["git", "init", "-q", "x"]\n'
                "subprocess.run(cmd)\n"
            ),
        }
        for label, src in cases.items():
            with self.subTest(spelling=label):
                self.assertEqual([len(src.splitlines())], unscrubbed_git_calls(src))
        # ...and the same three, scrubbed, are clean.
        for label, src in cases.items():
            with self.subTest(spelling=f"{label}-scrubbed"):
                scrubbed = src.rstrip(")\n") + ", env=clean_git_env())\n"
                self.assertEqual([], unscrubbed_git_calls(scrubbed))

    def test_the_guard_reports_the_unscrubbed_call_beside_a_scrubbed_one(self):
        # One scrubbed call and one unscrubbed call in the same file.
        src = (
            "import subprocess\n"
            "def a(repo):\n"
            '    subprocess.run(["git", "init", "-q", str(repo)], env=clean_git_env())\n'
            "def b(repo):\n"
            '    subprocess.run(["git", "init", "-q", str(repo)])\n'
            "def c(repo):\n"
            "    subprocess.check_output([\n"
            "        'git', 'rev-parse', 'HEAD',\n"
            "    ], cwd=repo, text=True)\n"
            "def d(repo):\n"
            '    subprocess.run(["ls", "(not git)"], check=True)\n'
            "def e(repo):\n"
            '    subprocess.run(["git", "status"], env={"PATH": "/usr/bin"})\n'
        )
        self.assertEqual(unscrubbed_git_calls(src), [5, 7])

    def test_the_guard_recognises_an_unscrubbed_call(self):
        # The file-selection pattern must match how these suites spell a git call, or a
        # file is skipped before the AST walk sees it.
        self.assertTrue(
            _GIT_ARGV.search('subprocess.run(["git", "init", "-q", str(repo)])')
        )
        self.assertTrue(_GIT_ARGV.search('[\n            "git",\n'))
        self.assertTrue(_GIT_ARGV.search("['git', 'status']"))


if __name__ == "__main__":
    unittest.main()
