#!/usr/bin/env python3
"""Guard: `preflight_all` must cover every tool the `all` gate actually needs.

`preflight_all` reports every missing tool up front, in seconds, instead of one per leg
discovered minutes into the pipeline. That only holds if its list stays complete.

The list is necessarily a second copy of the `need` calls scattered through the leg
functions, so this asserts the copy is a superset of what those legs require. Adding
`need jq` to a leg inside `all` without listing `jq` in `preflight_all` fails here, rather
than sending the gate back to discovering it mid-run.

The rule is one-directional. `preflight_all` may list a tool no leg currently `need`s,
since a leg may shell out without a `need` line, but it may never omit one.

Which legs count is read from the `ALL_LEGS` array rather than inferred from `all_legs`'s
body. A call sequence can be wrapped (`timed <leg>`) into a shape this traversal no longer
recognises, leaving the coverage assertion comparing empty sets; an array cannot.
`unwrap_dispatchers` handles the same hazard on the inner hops, where calls are still
written as plain shell.
"""

import re
import unittest

from _helpers import SCRIPTS, strip_comments

SCRIPT = SCRIPTS / "ci-local.sh"


def read_script() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def function_bodies(text: str) -> dict[str, str]:
    """Map every shell function name to its body text.

    Handles both shapes used in this script: the one-liner
    ``name()  { step "..."; run cargo ...; }`` and the multi-line block whose
    terminating brace sits alone at column 0.
    """
    bodies: dict[str, str] = {}
    lines = text.splitlines()
    i = 0
    define = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\(\)\s*\{(.*)$")
    while i < len(lines):
        m = define.match(lines[i])
        if not m:
            i += 1
            continue
        name, rest = m.group(1), m.group(2)
        # A definition line may continue with `\`. Join it before deciding one-liner vs
        # block: `foo() { a; \` does not end in `}`, so an unjoined line is misread as a
        # block and swallows every following function up to the next column-0 `}`.
        while rest.rstrip().endswith("\\") and i + 1 < len(lines):
            i += 1
            rest = rest.rstrip().removesuffix("\\") + " " + lines[i]
        if rest.rstrip().endswith("}"):  # one-liner
            bodies[name] = rest.rstrip().removesuffix("}")
            i += 1
            continue
        collected = [rest]
        i += 1
        while i < len(lines) and lines[i] != "}":
            collected.append(lines[i])
            i += 1
        bodies[name] = "\n".join(collected)
        i += 1
    return bodies


def needs_in(body: str) -> set[str]:
    return set(re.findall(r"\bneed\s+([A-Za-z0-9_-]+)", body))


def optional_in(body: str) -> set[str]:
    """Tools a leg may skip on: `skip_unless <tool> <leg> <why>`, the visible-skip form."""
    return set(re.findall(r"\bskip_unless\s+([A-Za-z0-9_-]+)", body))


#: A function call sits in command position: at the start of a line, or straight after a
#: separator. Matching only there keeps names inside strings and arguments, such as the
#: word `docker` inside a `--help` blurb, from counting as calls.
#:
#: `re.MULTILINE` is required. Without it `^` anchors only at the start of the body string,
#: and in a multi-line leg body a newline is not in the separator set, so only the first
#: call is ever seen.
_CALL = re.compile(
    r"(?:^|[;&|(]|&&|\|\||\bthen\b|\bdo\b|\belse\b)\s*([A-Za-z_][A-Za-z0-9_-]*)",
    re.MULTILINE,
)


#: Dispatch wrappers invoke their first argument, so the real call sits one token to the
#: right of command position. `timed ci_gate` is a call to `ci_gate`, not to `timed`.
#: Every wrapper must be named here. One this list does not know hides every call it
#: wraps, and the coverage assertion below weakens without failing.
_WRAPPERS = ("timed_sub", "timed", "run")
_WRAPPER_CALL = re.compile(
    r"((?:^|[;&|(]|&&|\|\||\bthen\b|\bdo\b|\belse\b)\s*)(?:"
    + "|".join(_WRAPPERS)
    + r")\s+",
    re.MULTILINE,
)


def unwrap_dispatchers(body: str) -> str:
    """Delete wrapper tokens from command position, repeatedly (they may nest)."""
    while True:
        pruned = _WRAPPER_CALL.sub(r"\1", body)
        if pruned == body:
            return body
        body = pruned


def calls_in(body: str, known: set[str]) -> set[str]:
    """Repo-defined functions invoked from a body, in command position only.

    Comments are stripped first. The script's comments name other legs in prose, so a
    token match over raw text would drag release-only legs into the reachable set and
    force the preflight to demand tools the run does not need.
    """
    found = set(_CALL.findall(unwrap_dispatchers(strip_comments(body))))
    return {t for t in found & known if t not in {"need", *_WRAPPERS}}


def all_legs_list(text: str) -> list[str]:
    """The legs `all` runs, read from the ALL_LEGS array declaration.

    Read as data rather than inferred from `all_legs`'s body. A call sequence can be
    wrapped (`timed <leg>`) into something this parser no longer recognises; an array
    cannot.
    """
    m = re.search(r"^ALL_LEGS=\(\s*(.*?)^\)", text, re.MULTILINE | re.DOTALL)
    if not m:
        return []
    return [
        tok
        for tok in strip_comments(m.group(1)).split()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", tok)
    ]


class PreflightCoverageTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = read_script()
        cls.bodies = function_bodies(cls.text)

    def test_the_script_parsed(self):
        self.assertIn("all_legs", self.bodies, "could not parse ci-local.sh functions")
        self.assertIn("preflight_all", self.bodies, "preflight_all is missing")

    def declared_tools(self) -> set[str]:
        """Tools listed in preflight_all's `required` array."""
        body = self.bodies["preflight_all"]
        # Entries look like `$'python3<TAB>https://...'`, where the tab is a literal tab
        # byte in the file rather than a backslash-t sequence.
        return set(re.findall(r"\$'([A-Za-z0-9_-]+)[\t]", body))

    def _reachable_tools(self, extract) -> set[str]:
        """Every tool `extract` finds in a body reachable from ALL_LEGS, transitively."""
        known = set(self.bodies)
        seen: set[str] = set()
        frontier = set(all_legs_list(self.text))
        tools: set[str] = set()
        while frontier:
            fn = frontier.pop()
            if fn in seen:
                continue
            seen.add(fn)
            body = self.bodies.get(fn, "")
            tools |= extract(body)
            frontier |= calls_in(body, known) - seen
        return tools

    def required_tools(self) -> set[str]:
        """Every tool reachable from the ALL_LEGS legs, following calls transitively."""
        return self._reachable_tools(needs_in)

    def optional_tools(self) -> set[str]:
        """Every tool an `all` leg may visibly skip on, through `skip_unless`."""
        return self._reachable_tools(optional_in)

    def test_all_legs_are_real_functions(self):
        """Every ALL_LEGS entry must name a function that exists.

        A typo in the array is otherwise a `command not found` minutes into the gate.
        """
        legs = all_legs_list(self.text)
        self.assertTrue(legs, "ALL_LEGS is empty or unparseable")
        unknown = [leg for leg in legs if leg not in self.bodies]
        self.assertFalse(unknown, f"ALL_LEGS names undefined function(s): {unknown}")

    def test_all_legs_is_what_all_legs_runs(self):
        """`all_legs` must dispatch the array, not a hand-written second copy."""
        body = self.bodies["all_legs"]
        self.assertIn(
            "ALL_LEGS",
            body,
            "all_legs no longer iterates ALL_LEGS; the array this guard reads would "
            "then describe a leg set nothing runs",
        )

    def test_preflight_declares_a_nonempty_list(self):
        self.assertTrue(
            self.declared_tools(),
            "preflight_all declares no tools; the parser or the array shape changed",
        )

    def test_reachability_finds_real_tools(self):
        # Sanity-check the traversal itself: if this ever returns nothing, the coverage
        # assertion below would pass vacuously.
        found = self.required_tools()
        self.assertTrue(
            found, "no `need` calls reachable from all_legs; the parser is broken"
        )
        self.assertIn(
            "cargo-deny",
            found,
            "expected the supply-chain leg's cargo-deny to be reachable from all_legs",
        )

    def test_preflight_covers_every_tool_the_all_gate_needs(self):
        missing = self.required_tools() - self.declared_tools()
        self.assertFalse(
            missing,
            "preflight_all does not list tool(s) that legs inside `all` require: "
            f"{sorted(missing)}. Add them to its `required` array, or the gate goes "
            "back to discovering them mid-run.",
        )

    def test_optional_tools_are_never_demanded_by_preflight(self):
        # The other direction of the same rule: a tool reached through `skip_unless` must
        # not be in preflight_all, or `all` dies up front on exactly the machine the skip
        # exists for. The non-emptiness check comes first, or disjointness would pass
        # vacuously.
        optional = self.optional_tools()
        self.assertIn(
            "docker",
            optional,
            "no `skip_unless docker` reachable from ALL_LEGS; either promtool left "
            "`all` or it went back to `need`, which makes `all` require Docker",
        )
        self.assertFalse(
            optional & self.required_tools(),
            "a tool is both `need`ed and `skip_unless`ed inside `all`; pick one",
        )
        self.assertFalse(
            optional & self.declared_tools(),
            f"preflight_all demands {sorted(optional & self.declared_tools())}, which "
            "`all` is meant to run without, since the leg skips visibly. Remove it from "
            "the `required` array.",
        )


if __name__ == "__main__":
    unittest.main()
