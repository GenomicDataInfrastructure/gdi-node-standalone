#!/usr/bin/env python3
"""Guard: no `tracing` event field may be named `target`.

`target` is the tracing target, and it is the field `docs/operating.md` §21 tells an
operator to route the compliance stream on:

    filter on the concrete `"target":"audit"` field in each line

An event that declares its own `target = ...` field does not replace that. The default
`LOG_FORMAT=json` writer emits both, producing a line with a duplicate `target` key:

    {"message":"s3 channel target and credential source","bucket":"primary",
     "source":"vault","target":"gdi-datasets/gdi-node-storage",
     "target":"gdi_node_standalone::s3"}

RFC 8259 says object names should be unique and leaves duplicates implementation-defined.
jq and Python keep the last one, which here is the tracing target, so routing survives by
accident. Other parsers raise, and some ingest paths reject the document outright.
`docs/operating.md` §15 and §21.1 point these lines at a log store, so the jq behaviour is
not something to rely on.

Only the default `json` format collides. Under `LOG_FORMAT=ecs` the event field lands in
`labels.target` and the tracing target in `log.logger`, so ECS output does not show it.

Scope: `tracing` macro invocations in the shipped crates. Tests are excluded, because a
test may construct a line with an arbitrary field set to assert how it renders.
"""

import pathlib
import re
import unittest

from _helpers import REPO_ROOT

CRATES = REPO_ROOT / "crates"

#: A `target = ...` / `target = %...` / `target: ...` field inside a tracing macro call.
#: Narrow by construction: it must sit at a field position, at the start of a line after
#: indent or directly after `(` or `,`, so `self.target`, `target()` and `let target =`
#: do not match.
FIELD = re.compile(r"(?:^\s*|[(,]\s*)target\s*=\s*[^=]")

#: The macros whose named arguments become log fields.
MACROS = (
    "trace!",
    "debug!",
    "info!",
    "warn!",
    "error!",
    "event!",
    "span!",
    "instrument",
)


def _rust_sources() -> list[pathlib.Path]:
    out = []
    for p in CRATES.rglob("*.rs"):
        parts = p.parts
        if "tests" in parts or "benches" in parts or "fuzz" in parts:
            continue
        out.append(p)
    return out


def offending_lines(text: str) -> list[tuple[int, str]]:
    """`(line number, raw line)` for every `target =` field inside a tracing macro call."""
    out: list[tuple[int, str]] = []
    # A tracing macro call may span many lines, so track whether we are inside one.
    depth_from_macro = 0
    for n, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("//", 1)[0]
        # `tracing::debug!(target: "audit", ...)` uses a colon, not `=`, and is the
        # sanctioned way to set the target. Only `=` shadows.
        if depth_from_macro == 0 and not any(m in line for m in MACROS):
            continue
        if FIELD.search(line):
            out.append((n, raw))
        # Close the span when the call's parens balance out. The count starts at zero on
        # the opening line: seeding it with 1 would leave a single-line call such as
        # `info!("x");` at depth 1 forever, and every later line in the file would read as
        # "inside a macro".
        depth_from_macro += line.count("(") - line.count(")")
        if depth_from_macro <= 0:
            depth_from_macro = 0
    return out


class NoEventFieldShadowsTarget(unittest.TestCase):
    def test_a_single_line_macro_closes_the_span(self) -> None:
        # `info!("x");` on one line must leave the scanner outside a macro, so an ordinary
        # assignment two lines later is not read as a tracing field. A multi-line event
        # declaring `target =` must still be reported.
        src = (
            'tracing::info!("one line");\n'
            "let x = 1;\n"
            "target = x;\n"
            "tracing::warn!(\n"
            "    target = %x,\n"
            '    "shadows"\n'
            ");\n"
        )
        self.assertEqual([n for n, _ in offending_lines(src)], [5])

    def test_sources_exist(self) -> None:
        """A glob that matches nothing would make every assertion below vacuous."""
        self.assertGreater(
            len(_rust_sources()),
            50,
            "expected to find the shipped Rust sources under crates/",
        )

    def test_no_tracing_event_declares_a_target_field(self) -> None:
        offenders: list[str] = []
        for path in _rust_sources():
            for n, raw in offending_lines(path.read_text(encoding="utf-8")):
                offenders.append(f"  {path.relative_to(REPO_ROOT)}:{n}: {raw.strip()}")
        self.assertEqual(
            offenders,
            [],
            "these tracing events declare a field named `target`, which shadows the tracing "
            "target and emits a duplicate JSON key under the default LOG_FORMAT=json, the "
            "same key docs/operating.md §21 routes the audit stream on:\n"
            + "\n".join(offenders)
            + "\nRename the field (e.g. `keyspace`). To set the tracing target, use the "
            "macro's `target:` form (colon), which is not a field.",
        )


if __name__ == "__main__":
    unittest.main()
