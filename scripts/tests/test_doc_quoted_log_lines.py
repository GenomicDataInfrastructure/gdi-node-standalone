#!/usr/bin/env python3
"""Guard: a log line quoted in the docs must match what the node actually emits.

The docs quote log lines so an operator can recognise them. When an emit site gains a
field or renames one, a quoted line stays parseable while no longer being what the node
prints, and nothing compares the two. The docs are where an operator learns what to grep
for, so a stale quote is a wrong answer delivered with authority.

Scope: across `docs/**/*.md` and `node.example.toml`, only plain-text log lines quoted
inside fenced blocks are checked, and the rule is that **every `field=` name in such a
line must exist as a `tracing` field at some emit site in the Rust sources.** A broader
rule, "every quoted string that looks like a log message", matches prose instead.

The check grows with the docs: quote another log line and it is checked. It does not check
the message text or the values, because the values are per-deployment examples
(`bucket=primary`).

It cannot catch a doc sentence that describes behaviour the node does not have. Only a
behavioural test catches that class (see `ingest_runtime::shutdown_cancellation_tests`).
"""

import pathlib
import re
import unittest

from _helpers import MACRO_OPEN, REPO_ROOT, invocation_at

#: Files whose fenced blocks may quote a node log line.
DOC_GLOBS = ("docs/**/*.md", "node.example.toml")

#: A quoted log line: a fenced-block line opening with a tracing level.
LOG_LINE = re.compile(r"^(WARN|INFO|ERROR|DEBUG|TRACE)\b")

#: `field=` in a quoted log line. Values are not captured: they are examples, not contract.
DOC_FIELD = re.compile(r"\b([a-z_][a-z0-9_]*)=")

#: A `tracing` field inside a macro invocation: `field = ...`, `field = %...`,
#: `field = ?...`. `(?!=)` keeps a `==` comparison in an argument expression out.
RUST_FIELD = re.compile(r"(?:^|[(,\s])([a-z_][a-z0-9_]*)\s*=(?!=)")
#: The shorthand forms `%field` / `?field` as a BARE argument (directly after `(` or `,`),
#: which name a field after the identifier itself. Anchored to the argument boundary so
#: the `%b` in `bucket = %b` is a value, not a second field.
RUST_SHORTHAND = re.compile(r"[(,]\s*[%?]([a-z_][a-z0-9_]*)\s*[,)]")
#: A string literal, so a message like "prefix={prefix}" cannot contribute `prefix`.
STRING_LITERAL = re.compile(r'"(?:[^"\\]|\\.)*"')

#: Words that appear before `=` in a log line but are not fields (units, prose).
NOT_FIELDS = frozenset({"e", "g", "i"})


def _strip_blockquote(text: str) -> str:
    """Remove leading `>` markers so fences inside blockquotes are visible.

    Without this the scan misses a fenced block nested in a `>` callout, and so checks
    less than it reports.
    """
    return "\n".join(re.sub(r"^\s*>\s?", "", line) for line in text.splitlines())


def quoted_log_lines() -> list[tuple[str, str]]:
    """`(file, line)` for every plain-text log line quoted inside a fenced block."""
    root = pathlib.Path(REPO_ROOT)
    out: list[tuple[str, str]] = []
    paths: list[pathlib.Path] = []
    for glob in DOC_GLOBS:
        paths.extend(sorted(root.glob(glob)))
    for path in paths:
        text = _strip_blockquote(path.read_text(encoding="utf-8"))
        for block in re.finditer(r"```[a-zA-Z]*\n(.*?)```", text, re.DOTALL):
            for raw in block.group(1).splitlines():
                line = raw.strip()
                if LOG_LINE.match(line) and len(line) > 25:
                    out.append((str(path.relative_to(root)), line))
    return out


def fields_in_invocation(invocation: str) -> set[str]:
    """The field names one tracing macro invocation declares."""
    body = STRING_LITERAL.sub('""', invocation)
    return set(RUST_FIELD.findall(body)) | set(RUST_SHORTHAND.findall(body))


def rust_tracing_fields() -> set[str]:
    """Every identifier used as a field inside a `tracing` macro invocation in `crates/`.

    Inside the invocation only. Running the field pattern over raw file text collects
    every `let x =` in the tree, including locals such as `target` that are not fields at
    all, and a doc quoting one of those names would then pass. The macro invocation is the
    only text a tracing field can live in, and `invocation_at` extracts it string-aware.
    """
    root = pathlib.Path(REPO_ROOT) / "crates"
    fields: set[str] = set()
    for path in root.rglob("*.rs"):
        text = path.read_text(encoding="utf-8")
        for match in MACRO_OPEN.finditer(text):
            fields |= fields_in_invocation(invocation_at(text, match.start()))
    return fields


def problems_for(lines: list[tuple[str, str]], rust: set[str]) -> list[str]:
    """Every quoted field that no emit site declares.

    Callable on a synthetic line, so the case below exercises the shipped extractor.
    """
    problems = []
    for path, line in lines:
        for field in DOC_FIELD.findall(line):
            if field in NOT_FIELDS or field in rust:
                continue
            problems.append(
                f"{path}: `{field}=` is quoted but no emit site uses it\n    {line}"
            )
    return problems


class DocQuotedLogLines(unittest.TestCase):
    def test_the_scan_finds_the_known_quoted_lines(self):
        # An extractor that matches nothing passes forever. Pin that the scan is live,
        # and that it sees inside blockquoted fences; one of the two known lines is.
        lines = quoted_log_lines()
        self.assertGreaterEqual(
            len(lines),
            2,
            f"expected at least the two known quoted log lines, found {lines}",
        )
        joined = " ".join(line for _f, line in lines)
        self.assertIn("s3 channel target and credential source", joined)
        self.assertIn("beacon query memory", joined)

    def test_every_field_in_a_quoted_log_line_exists_in_the_sources(self):
        rust = rust_tracing_fields()
        self.assertGreater(
            len(rust), 50, "the Rust field extractor found suspiciously few fields"
        )
        problems = problems_for(quoted_log_lines(), rust)
        self.assertEqual(
            problems,
            [],
            "a doc quotes a log field the node does not emit; the docs are where an "
            "operator learns what to grep for:\n" + "\n".join(problems),
        )

    def test_the_real_extractor_rejects_the_renamed_field(self):
        # Run against the shipped extractor rather than a hand-written set. `target` is a
        # local in dozens of `let target =` lines, and
        # test_no_event_field_shadows_target.py forbids it as a tracing field, so it must
        # be absent from the real set and a doc quoting it must fail.
        rust = rust_tracing_fields()
        self.assertNotIn(
            "target",
            rust,
            "`target` is in the extracted field set; the extractor is reading outside "
            "tracing macro invocations (a `let target =` is not a log field)",
        )
        self.assertIn("keyspace", rust)
        line = "INFO s3 channel target and credential source channel=primary source=vault target=gdi/x"
        problems = problems_for([("synthetic.md", line)], rust)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("`target=`", problems[0])

    def test_the_extractor_reads_only_inside_the_invocation(self):
        # The narrowing itself, on a synthetic source: a local assignment beside a macro
        # and a `field=` inside the message string must both be ignored; the real field
        # forms (`k = v`, `%k`, `?k`, `k = %v`) must all be seen.
        src = (
            "let target = 1;\n"
            'tracing::info!(bucket = %b, ?err, source = src, "prefix={prefix} x=1");\n'
            "let other = 2;\n"
        )
        found = set()
        for m in MACRO_OPEN.finditer(src):
            found |= fields_in_invocation(invocation_at(src, m.start()))
        self.assertEqual(found, {"bucket", "err", "source"})


if __name__ == "__main__":
    unittest.main()
