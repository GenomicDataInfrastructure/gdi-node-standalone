#!/usr/bin/env python3
"""Guard: an edit must not detach a doc comment from the item it documents.

Inserting an item between a doc comment and the item it documents re-parents the doc
silently:

    /// Scan the selected datasets ...        <- written for `scan_selected_datasets`
    /// ... twenty more lines ...
    const SCAN_POOL_MULTIPLIER: usize = 4;    <- inserted here; now owns all of it

    async fn scan_selected_datasets(...)      <- now has no documentation at all

The result compiles, `cargo doc` is happy, and `missing_docs` sees a doc on the item that
took it while the item that lost it is often private or `pub(crate)`. The old revision is
the only place that records what the doc was attached to, so this is a diff guard rather
than a lint, and it stays silent on every item it has not seen change.

What it checks:
  Rust  -- an item (fn/struct/enum/trait/type/const/static/mod/union) that carried a
           `///` doc comment in the old revision and carries none in the new one.
        -- an item that carried a tracked attribute and now does not, counted per name:
           `test`/`rstest`/`test_case`/`bench` (the test stops running and the suite still
           reports green), `serial` (the test still runs but no longer holds its lock, so it
           races its siblings and the failure lands somewhere else), `ignore` (a skipped
           test starts running) and `should_panic` (a test that asserted a panic now passes
           only if it does not). A bare `fn` inserted above a test takes the attributes
           that sat above it, the same way.
  Shell -- a usage/header entry (`#   name   description`) that lost continuation lines,
           which is how an inserted entry adopts its predecessor's trailing line.
        -- a function that had a leading `#` comment block and now has none.

Renames are not reported: an item that changes name disappears from the old set, and this
guard only speaks about names present in both revisions.

Usage::

    scripts/check-doc-attachment.py                  # staged vs HEAD (the pre-commit path)
    scripts/check-doc-attachment.py --range main     # working tree vs another revision
    scripts/check-doc-attachment.py --range A..B     # two revisions

Exit status is 1 when something detached, 0 otherwise. There is no allowlist: an intended
detachment is justified in the commit message instead.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys

#: Item kinds whose doc attachment is tracked. `impl` is absent: an `impl` block carries
#: no name of its own, so two impls of the same trait cannot be told apart across
#: revisions without resolving types.
RUST_ITEM = re.compile(
    r"^(?:pub(?:\s*\([^)]*\))?\s+)?"
    r"(?:default\s+|const\s+|async\s+|unsafe\s+|extern\s+\"[^\"]*\"\s+)*"
    r"(?P<kind>fn|struct|enum|trait|type|const|static|mod|union)\b"
    r"\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)

#: Attributes tracked per name, because losing one is silent and changes what runs.
#: One "is this a test" flag would not see `#[serial(env)]` dropped from a function that
#: still carries `#[test]`: the count is unchanged, but the test now races `std::env`
#: against its siblings and the damage surfaces as a flake elsewhere. `ignore` is tracked
#: for the opposite reason: losing it makes a skipped test start running, usually in an
#: environment that cannot support it.
TRACKED_ATTRS = frozenset(
    {"test", "rstest", "test_case", "bench", "serial", "ignore", "should_panic"}
)

#: What losing each one costs, appended to the report so the message is actionable.
ATTR_CONSEQUENCE = {
    "test": "It no longer runs, and the suite still reports green.",
    "rstest": "It no longer runs, and the suite still reports green.",
    "test_case": "It no longer runs, and the suite still reports green.",
    "bench": "It is no longer benchmarked.",
    "serial": "It still runs, but no longer serialised, so it races its siblings on the "
    "state it was serialised for and the failure appears in an unrelated test.",
    "ignore": "A skipped test now runs, in an environment that may not support it.",
    "should_panic": "A test that asserted a panic now passes only if it does not panic.",
}

#: An outer attribute's name, normalised: the last `::` segment, arguments stripped.
#: `#[tokio::test]` -> `test`, `#[serial(env)]` -> `serial`, `#[ignore = "why"]` -> `ignore`.
ATTR_NAME = re.compile(r"^#\[\s*((?:\w+\s*::\s*)*\w+)")


def attr_name(line: str) -> str | None:
    """The tracked name of an outer attribute, or `None` if it is not one we follow."""
    m = ATTR_NAME.match(line)
    if m is None:
        return None
    name = m.group(1).replace(" ", "").split("::")[-1]
    return name if name in TRACKED_ATTRS else None


def _strip_noncode(text: str) -> list[tuple[str, str]]:
    """Split `text` into `(classification, payload)` per line.

    Classification is one of `doc` (an outer `///` line), `innerdoc` (`//!`, which
    documents the enclosing module rather than the next item), or `code`. For `code` the
    payload has string literals, char literals and `/* */` comments blanked, so a brace
    inside `"{"` cannot move the nesting depth and an item keyword quoted in prose cannot
    be mistaken for a declaration.
    """
    out: list[tuple[str, str]] = []
    in_block = False
    in_raw: int | None = None
    for line in text.splitlines():
        lstr = line.lstrip()
        if not in_block and in_raw is None:
            if lstr.startswith("///"):
                out.append(("doc", lstr[3:].strip()))
                continue
            if lstr.startswith("//!"):
                out.append(("innerdoc", lstr[3:].strip()))
                continue
        code: list[str] = []
        i = 0
        while i < len(line):
            if in_block:
                j = line.find("*/", i)
                if j == -1:
                    i = len(line)
                else:
                    in_block = False
                    i = j + 2
                continue
            if in_raw is not None:
                needle = '"' + "#" * in_raw
                j = line.find(needle, i)
                if j == -1:
                    i = len(line)
                else:
                    in_raw = None
                    i = j + len(needle)
                continue
            ch = line[i]
            if ch == "/" and line.startswith("/*", i):
                in_block = True
                i += 2
                continue
            if ch == "/" and line.startswith("//", i):
                break
            raw = re.match(r'r(#*)"', line[i:])
            if raw:
                in_raw = len(raw.group(1))
                i += raw.end()
                continue
            if ch == '"':
                i += 1
                while i < len(line):
                    if line[i] == "\\":
                        i += 2
                        continue
                    if line[i] == '"':
                        i += 1
                        break
                    i += 1
                continue
            if ch == "'":
                lit = re.match(r"'(?:\\.|[^'\\])'", line[i:])
                if lit:
                    i += lit.end()
                    continue
            code.append(ch)
            i += 1
        out.append(("code", "".join(code)))
    return out


class ItemFacts:
    """How many times a `(kind, name)` appears, and how many of those are documented."""

    __slots__ = ("attrs", "documented", "total")

    def __init__(self) -> None:
        self.total = 0
        self.documented = 0
        #: attribute name -> how many occurrences of this item carried it.
        self.attrs: dict[str, int] = {}


def rust_items(text: str) -> dict[tuple[str, str], ItemFacts]:
    """Map each `(kind, name)` to its occurrence / documented / test-attribute counts.

    Counts rather than positions, because positions move for reasons that are not
    defects. A `(kind, name)` can appear more than once, such as a `#[cfg]` pair or the
    same helper name in two modules; comparing counts reports the one that lost its doc
    without requiring the two revisions to line up.
    """
    facts: dict[tuple[str, str], ItemFacts] = {}
    pending_doc = False
    pending_attrs: set[str] = set()
    attr_depth = 0
    for kind_t, payload in _strip_noncode(text):
        if kind_t == "doc":
            pending_doc = True
            continue
        if kind_t == "innerdoc":
            # `//!` documents the enclosing module. Reading it as the next item's doc
            # would make every file's first item look documented.
            pending_doc = False
            pending_attrs = set()
            continue
        stripped = payload.strip()
        if attr_depth > 0:
            attr_depth += payload.count("(") + payload.count("[")
            attr_depth -= payload.count(")") + payload.count("]")
            continue
        if not stripped:
            # A blank line does not detach a doc comment in Rust, so the pending doc
            # survives it. Only an item or a non-attribute statement clears it.
            continue
        if stripped.startswith("#["):
            if (name := attr_name(stripped)) is not None:
                pending_attrs.add(name)
            depth = (
                stripped.count("(")
                + stripped.count("[")
                - stripped.count(")")
                - stripped.count("]")
            )
            attr_depth = max(depth, 0)
            continue
        match = RUST_ITEM.match(stripped)
        if match:
            key = (match.group("kind"), match.group("name"))
            entry = facts.setdefault(key, ItemFacts())
            entry.total += 1
            entry.documented += int(pending_doc)
            for attr in pending_attrs:
                entry.attrs[attr] = entry.attrs.get(attr, 0) + 1
        pending_doc = False
        pending_attrs = set()
    return facts


#: A usage entry: `#` then a name column then two-or-more spaces then a description.
#: Two spaces is what separates an entry from its own wrapped continuation.
SH_ENTRY = re.compile(r"^#(?P<pad>\s{2,})(?P<name>[A-Za-z][\w.-]*)(?P<gap>\s{2,})\S")
SH_COMMENT = re.compile(r"^#(?P<pad>\s+)\S")
SH_FUNC = re.compile(r"^(?P<name>[A-Za-z_][\w-]*)\s*\(\)\s*\{")


def shell_facts(text: str) -> tuple[dict[str, int], set[str], set[str]]:
    """Continuation-line counts per usage entry, and functions carrying a comment block.

    A continuation is a `#` line whose text begins at or past the description column of
    the entry above it, the shape `usage()` prints verbatim as `--help`. An entry inserted
    directly above another entry's wrapped line adopts that line, and `--help` then
    describes the wrong entry.
    """
    continuations: dict[str, int] = {}
    documented_funcs: set[str] = set()
    all_funcs: set[str] = set()
    current: str | None = None
    desc_col = 0
    saw_comment = False
    for line in text.splitlines():
        entry = SH_ENTRY.match(line)
        if entry:
            name = entry.group("name")
            current = name
            desc_col = 1 + len(entry.group("pad")) + len(name) + len(entry.group("gap"))
            continuations.setdefault(name, 0)
            saw_comment = True
            continue
        comment = SH_COMMENT.match(line)
        if comment:
            if current is not None and 1 + len(comment.group("pad")) >= desc_col:
                continuations[current] += 1
            saw_comment = True
            continue
        if line.startswith("#"):
            saw_comment = True
            continue
        func = SH_FUNC.match(line)
        if func:
            all_funcs.add(func.group("name"))
            if saw_comment:
                documented_funcs.add(func.group("name"))
        current = None
        saw_comment = False
    return continuations, documented_funcs, all_funcs


def _git(args: list[str]) -> str:
    done = subprocess.run(["git", *args], capture_output=True, text=True, check=False)
    return done.stdout if done.returncode == 0 else ""


def _changed_paths(old_rev: str | None, new_rev: str | None) -> list[str]:
    if old_rev is None:
        raw = _git(["diff", "--cached", "--name-only", "--diff-filter=ACMR"])
    elif new_rev is None:
        raw = _git(["diff", "--name-only", "--diff-filter=ACMR", old_rev])
    else:
        raw = _git(["diff", "--name-only", "--diff-filter=ACMR", old_rev, new_rev])
    return [p for p in raw.splitlines() if p.endswith((".rs", ".sh"))]


def _blob(rev: str | None, path: str, staged: bool) -> str:
    if rev is not None:
        return _git(["show", f"{rev}:{path}"])
    if staged:
        return _git(["show", f":{path}"])
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except OSError:
        return ""


def check_rust(old: str, new: str, path: str) -> list[str]:
    """Report every `(kind, name)` that lost a doc comment or a test attribute."""
    before, after = rust_items(old), rust_items(new)
    problems: list[str] = []
    for key, was in before.items():
        now = after.get(key)
        if now is None or now.total < was.total:
            # Deleted or renamed: this guard has nothing to say.
            continue
        if now.documented < was.documented:
            problems.append(
                f"{path}: {key[0]} `{key[1]}` lost its doc comment "
                f"({was.documented} of {was.total} documented before, "
                f"{now.documented} of {now.total} now). An item inserted between a doc "
                f"comment and the item it documents re-parents that doc silently."
            )
        # `had`/`has`, not `before`/`after`: those two names are the item dicts of this
        # function's scope and must not be rebound here.
        for attr, had in sorted(was.attrs.items()):
            has = now.attrs.get(attr, 0)
            if has < had:
                problems.append(
                    f"{path}: {key[0]} `{key[1]}` lost its #[{attr}] attribute "
                    f"({had} before, {has} now). {ATTR_CONSEQUENCE.get(attr, '')}".rstrip()
                )
    return problems


def check_shell(old: str, new: str, path: str) -> list[str]:
    """Report usage entries that lost continuation lines, and un-commented functions."""
    old_cont, old_documented, _ = shell_facts(old)
    new_cont, new_documented, new_all = shell_facts(new)
    problems: list[str] = []
    for name, count in old_cont.items():
        now = new_cont.get(name)
        if now is not None and now < count:
            problems.append(
                f"{path}: usage entry `{name}` lost {count - now} continuation line(s) "
                f"({count} before, {now} now). An entry inserted above another entry's "
                f"wrapped line adopts it, and `--help` then prints it under the wrong flag."
            )
    # Only functions still present in the new revision: one that was deleted or renamed
    # has not lost a comment block, it has gone.
    for name in sorted((old_documented - new_documented) & new_all):
        problems.append(
            f"{path}: function `{name}` lost its leading comment block. An item "
            f"inserted between a `#` block and the function it describes re-parents it."
        )
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--range",
        dest="rev_range",
        default=None,
        help="revision or A..B to compare against (default: staged vs HEAD)",
    )
    args = parser.parse_args()

    if args.rev_range is None:
        # The pre-commit path: what is about to be committed, against its parent.
        old_rev, new_rev, staged = "HEAD", None, True
        paths = _changed_paths(None, None)
    else:
        if ".." in args.rev_range:
            old_rev, tail = args.rev_range.split("..", 1)
            new_rev = tail or None
        else:
            old_rev, new_rev = args.rev_range, None
        staged = False
        paths = _changed_paths(old_rev, new_rev)
    problems: list[str] = []
    for path in paths:
        old = _blob(old_rev, path, staged=False)
        new = _blob(new_rev, path, staged=staged)
        if not new:
            continue
        if path.endswith(".rs"):
            problems.extend(check_rust(old, new, path))
        else:
            problems.extend(check_shell(old, new, path))

    if problems:
        print("doc-attachment: something detached from the item it documents\n")
        for line in problems:
            print(f"  {line}")
        print(
            "\nIf the detachment is intended (the doc was deleted, or the test "
            "retired), say so in the commit message and re-run with --no-verify. "
            "There is no allowlist."
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
