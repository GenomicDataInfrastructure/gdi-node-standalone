"""Shared fixtures for the `scripts/` guard tests.

Single-sources what every guard needs: where the repository root is, how to import a guard
whose filename contains a hyphen, and how to read a shell script without its comments.

A wrong repo-root depth does not crash. It resolves to a directory that does not exist,
`glob()` returns nothing, and a guard reports success having checked nothing. The
assertion at the bottom of this file turns that into a loud failure.
"""

import importlib.util
import os
import pathlib
import re
import sys
import types

#: The repository root. This file's location is the only place the depth of
#: `scripts/tests/` below the root is written down.
REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
SCRIPTS = REPO_ROOT / "scripts"


def load_module(relative_path: str, name: str) -> types.ModuleType:
    """Import a module by path, for guards whose filenames contain a hyphen.

    Registers the module in `sys.modules` before executing it. `@dataclass` resolves its
    string annotations through `sys.modules`, so a path-loaded module that defines
    dataclasses (check-ci-gate.py does) raises at import without this.
    """
    path = REPO_ROOT / relative_path
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def clean_git_env(**overrides) -> dict:
    """The ambient env with every ``GIT_*`` variable removed, plus ``overrides``.

    Every test that shells out to git must use this. Git exports ``GIT_DIR`` and
    ``GIT_INDEX_FILE`` to hooks, and the pre-commit hook runs this suite. Under that
    ``GIT_DIR`` a ``git init <tmpdir>`` creates no ``.git`` in the tmpdir. It
    re-initialises the real repository's gitdir and writes ``core.bare = true`` into the
    shared ``.git/config``, because a worktree gitdir does not end in ``/.git``. The main
    checkout is then unusable as a work tree while the tests still pass.
    ``test_git_env_scrubbed.py`` enforces the rule.
    """
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(overrides)
    return env


def strip_comments(text: str) -> str:
    """Drop whole-line `#` comments.

    An assertion about what a script does must read only what it runs. Searching raw text
    lets an assertion bind to a comment that states the opposite of the property it is
    named for.
    """
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


#: The opening of a `tracing` event macro: `warn!(`, `tracing::info!(`, ...
MACRO_OPEN = re.compile(r"\b(?:tracing::)?(?:error|warn|info|debug|trace)!\s*\(")


def invocation_at(text: str, start: int) -> str:
    """The macro invocation from `start` to its matching `)`, string-aware.

    A message like "(treated as transient)" holds parentheses, so the scan tracks
    string literals (with escapes) and counts only the parentheses outside them. Shared by
    every guard that reads tracing fields: the only text a tracing field can live in is the
    invocation, and a guard that reads raw source instead collects every `let x =` in the
    tree.
    """
    first = text.index("(", start)
    depth = 0
    in_string = False
    escaped = False
    for index in range(first, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    raise ValueError("unbalanced macro invocation")


# Fail loudly on a wrong depth rather than silently resolving paths into nothing.
if not (REPO_ROOT / "Cargo.toml").is_file():
    raise AssertionError(
        f"REPO_ROOT resolved to {REPO_ROOT}, which contains no Cargo.toml. These helpers "
        "moved to a different depth below the repository root; fix REPO_ROOT here rather "
        "than in each test; every path in this suite derives from it."
    )


def _block_end(src: str, open_brace: int) -> int:
    """The index just past the `}` that closes the block whose `{` is at `open_brace`,
    skipping braces inside string literals and `//` comments (a test module is full of
    both: `"{}"` format strings, `// { not a brace`)."""
    depth = 0
    i = open_brace
    n = len(src)
    while i < n:
        c = src[i]
        if c == '"':
            i += 1
            while i < n and src[i] != '"':
                if src[i] == "\\":
                    i += 1
                i += 1
        elif c == "/" and src.startswith("//", i):
            while i < n and src[i] != "\n":
                i += 1
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def strip_test_modules(src: str) -> str:
    """`src` with every `#[cfg(test)]`-gated `mod … { … }` cut out, by brace matching.

    Not "the text before the first test module". A file may hold several test modules with
    production code between them (`s3.rs` has three), and clippy's
    `items_after_test_module` does not forbid that; splitting on the first one would leave
    the production tail unchecked. Attributes between the `cfg` and the `mod` are stepped
    over; a `#[cfg(test)]` on anything other than a `mod` is left alone.
    """
    out = []
    pos = 0
    while True:
        at = src.find("\n#[cfg(test)]", pos)
        if at < 0:
            break
        attr_at = at + 1
        cursor = attr_at + len("#[cfg(test)]")
        # Further attributes may sit between the cfg and the item.
        while src[cursor:].lstrip().startswith("#["):
            cursor += len(src[cursor:]) - len(src[cursor:].lstrip())
            nl = src.find("\n", cursor)
            cursor = len(src) if nl < 0 else nl
        if not src[cursor:].lstrip().startswith("mod "):
            out.append(src[pos : attr_at + len("#[cfg(test)]")])
            pos = attr_at + len("#[cfg(test)]")
            continue
        brace = src.find("{", cursor)
        if brace < 0:
            break
        out.append(src[pos:attr_at])
        pos = _block_end(src, brace)
    out.append(src[pos:])
    return "".join(out)
