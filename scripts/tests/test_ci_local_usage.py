#!/usr/bin/env python3
"""Guard: every dispatchable target of ci-local.sh appears in its `--help` header.

The dispatch `case` and the usage block are two copies of one list, and they drift. A
target added to the `case` alone is runnable but undiscoverable except by reading the
dispatch table.

The header is not generated from an array, because the two are not the same fact. The
`case` is behaviour; the header is prose explaining why each leg exists and what it costs,
which flattening into a table would destroy. So this asserts that they agree rather than
merging them.

The rule is one-directional, like the preflight guard: the header may document something
that is not a dispatch target, such as an aggregate or a concept, but it may never omit a
target.
"""

import re
import unittest

from _helpers import SCRIPTS, strip_comments

SCRIPT = SCRIPTS / "ci-local.sh"

#: The usage block is the leading comment banner, before the first line of code. Found by
#: search rather than by a hardcoded line count: the header grows, and a stale range is
#: the drift this file exists to catch.
_HEADER_END = re.compile(r"^[^#\s]", re.MULTILINE)

#: `      target)   fn ;;` inside main()'s case.
_TARGET = re.compile(r"^      ([a-z0-9-]+)\)", re.MULTILINE)

#: `#   name   description`, where the name may be backticked.
#:
#: The backticks are not decoration. A comment whose first word is `shellcheck` is parsed
#: by shellcheck as a directive, so documenting that target in the bare form fails
#: ci-local.sh's own lint with SC1073. Backticking is the accepted escape, so this guard
#: must tolerate it.
_DOCUMENTED = re.compile(r"^#   `?([a-z0-9-]+)`?(?:\s|$)", re.MULTILINE)


def read() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def header(text: str) -> str:
    m = _HEADER_END.search(text)
    return text[: m.start()] if m else text


def dispatch_targets(text: str) -> set[str]:
    """Targets from main()'s case arms."""
    body = text[text.index("\nmain() {") :]
    return set(_TARGET.findall(body))


def documented_targets(text: str) -> set[str]:
    return set(_DOCUMENTED.findall(header(text)))


class UsageCoversDispatchTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = read()

    def test_the_header_was_found(self):
        # Without this, a header that failed to parse yields an empty documented set and
        # the assertion below reports every target as missing, for the wrong reason. The
        # inverse, an empty target set passing vacuously, is covered next.
        self.assertGreater(
            len(header(self.text).splitlines()),
            50,
            "the usage banner did not parse, so this guard would compare nothing",
        )

    def test_dispatch_targets_were_found(self):
        targets = dispatch_targets(self.text)
        self.assertGreater(
            len(targets),
            30,
            f"only {len(targets)} dispatch targets parsed; the `case` shape changed and "
            "this guard would pass having compared almost nothing",
        )

    def test_every_dispatch_target_is_documented(self):
        undocumented = sorted(
            dispatch_targets(self.text) - documented_targets(self.text)
        )
        self.assertFalse(
            undocumented,
            f"dispatchable but absent from the `--help` header: {undocumented}. Add a "
            "`#   <target>   <what it does>` line, or remove the dispatch arm.",
        )

    def test_the_header_is_prose_not_a_generated_table(self):
        # The header carries the rationale, which is why this is a guard and not a dedup.
        # If it ever collapses to bare names, merging it into the dispatch table becomes
        # the better answer and this guard should be replaced rather than satisfied.
        body = strip_comments(self.text)
        self.assertNotIn(
            "TARGET_DOC",
            body,
            "a generated usage table would make this guard the wrong tool; delete it "
            "and single-source the list instead",
        )


if __name__ == "__main__":
    unittest.main()
