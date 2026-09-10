#!/usr/bin/env python3
"""Guard: the `scripts/tests/` suite may import only the standard library.

`script-tests` runs inside `quick`, on the pre-commit path. A third-party import here
turns a missing module into a hard failure for every commit that touches `scripts/`, even
when the commit changed nothing that test reads. A test that needs a third-party package
belongs in a sibling directory with its own gate leg. See `k8s_manifests()` in
ci-local.sh for the shape, and `scripts/tests/k8s/` for an example.

The scan is non-recursive, because subdirectories are where the exempt suites live.
"""

import ast
import sys
import unittest

from _helpers import SCRIPTS

SUITE = SCRIPTS / "tests"

#: The suite's own shared fixtures. Not stdlib, but not a dependency either.
ALLOWED = {"_helpers"}


def top_level_imports(path) -> set[str]:
    """Every top-level package name imported by a module, via AST rather than regex.

    A regex over `^import ` would miss `if TYPE_CHECKING:` blocks and function-local
    imports, both of which still fail at the point they run.
    """
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".")[0])
    return names


class StdlibOnlyTest(unittest.TestCase):
    def test_the_suite_was_found(self):
        # Without this, a wrong SUITE path makes the check below iterate nothing and pass.
        self.assertTrue(
            list(SUITE.glob("*.py")),
            f"no Python found directly under {SUITE}, so this guard would pass vacuously",
        )

    def test_no_third_party_imports_on_the_pre_commit_path(self):
        for path in sorted(SUITE.glob("*.py")):
            with self.subTest(file=path.name):
                offenders = sorted(
                    top_level_imports(path) - sys.stdlib_module_names - ALLOWED
                )
                self.assertFalse(
                    offenders,
                    f"{path.name} imports {offenders}, which `script-tests` would then "
                    "require on the pre-commit path. Move the test to a sibling directory "
                    "with its own leg (see scripts/tests/k8s/), or drop the dependency.",
                )


if __name__ == "__main__":
    unittest.main()
