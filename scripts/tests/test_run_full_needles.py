#!/usr/bin/env python3
"""Guard: every log line `run-full.sh` waits for is emitted by a `tracing` event.

`wait_log` greps the node's logs for a fixed string, and only the full-stack e2e runs it.
Reword the message at its emit site and nothing else notices: the gate stays green, and the
next e2e-full run times out at that `wait_log` in a leg that works, blaming the behaviour the
leg exists to prove. The SIGHUP add message moving from "this bucket" to "this channel" did
exactly that.

This reads every `wait_log` needle out of the script and requires it inside a string literal
of a `tracing` event macro in the non-test sources under `crates/*/src`. A doc comment or an
error string holding the same words cannot satisfy it. A needle shaped like a JSON field
(`"name":value`, which is how `LOG_FORMAT=json` renders one) is bound to a tracing field of
that name instead, because its value is per deployment.

It binds the text, not the level or the conditions under which the event fires. The e2e run
is what proves those.
"""

import re
import unittest

from _helpers import (
    MACRO_OPEN,
    REPO_ROOT,
    SCRIPTS,
    invocation_at,
    strip_comments,
    strip_test_modules,
)

RUN_FULL = SCRIPTS / "e2e" / "run-full.sh"

#: A `wait_log` call and its first argument, a double- or single-quoted word.
WAIT_LOG_CALL = re.compile(r"""^\s*wait_log\s+("[^"]*"|'[^']*')""", re.MULTILINE)
#: Any `wait_log` call, whatever its argument looks like. The function definition,
#: `wait_log() {`, has no whitespace before its parenthesis and is not a call.
ANY_WAIT_LOG_CALL = re.compile(r"^\s*wait_log\s", re.MULTILINE)
#: A needle passed by variable: `"$NAME"` or `"${NAME}"`.
VARIABLE_REF = re.compile(r"\$\{?([A-Z_][A-Z0-9_]*)\}?")
#: A plain `NAME="value"` assignment, which is what a `"$NAME"` needle resolves to.
ASSIGNMENT = re.compile(r'^([A-Z_][A-Z0-9_]*)="([^"$`]*)"$', re.MULTILINE)
#: A needle matching one field of a JSON log line: `"name":value`.
JSON_FIELD = re.compile(r'^"([a-z_][a-z0-9_]*)":')
#: A Rust string literal. `\\[\s\S]` rather than `\\.`, so that a `\` line continuation
#: is read as one escape instead of ending the match.
STRING_LITERAL = re.compile(r'"(?:[^"\\]|\\[\s\S])*"')
#: A string continuation. The `\`, the newline and the next line's leading whitespace are
#: not part of the string's value.
CONTINUATION = re.compile(r"\\\n\s*")


def needles(script: str) -> list[str]:
    """Every `wait_log` needle in `script`, with a `"$NAME"` argument resolved."""
    text = strip_comments(script)
    values = dict(ASSIGNMENT.findall(text))
    out = []
    for quoted in WAIT_LOG_CALL.findall(text):
        needle = quoted[1:-1]
        ref = VARIABLE_REF.fullmatch(needle)
        if ref:
            if ref.group(1) not in values:
                raise AssertionError(
                    f"wait_log reads its needle from ${ref.group(1)}, which run-full.sh "
                    "does not assign as a plain literal this guard can resolve"
                )
            needle = values[ref.group(1)]
        out.append(needle)
    return out


def invocations_in(src: str) -> list[str]:
    """Every `tracing` event macro invocation in `src`."""
    return [invocation_at(src, match.start()) for match in MACRO_OPEN.finditer(src)]


def source_invocations() -> list[str]:
    """Every `tracing` event macro invocation in non-test code under `crates/*/src`."""
    out = []
    for path in sorted(REPO_ROOT.glob("crates/*/src/**/*.rs")):
        if path.name == "tests.rs" or "tests" in path.relative_to(REPO_ROOT).parts:
            continue
        out.extend(invocations_in(strip_test_modules(path.read_text(encoding="utf-8"))))
    return out


def declares_field(invocation: str, name: str) -> bool:
    """Whether `invocation` declares a field `name`, as `name = v`, `%name` or `?name`.

    String literals are blanked first, so a message that merely mentions `name = true`
    does not count as declaring it.
    """
    body = STRING_LITERAL.sub('""', invocation)
    pattern = rf"[(,]\s*[%?]?{re.escape(name)}\s*(?:=(?!=)|[,)])"
    return re.search(pattern, body) is not None


def problems_for(found: list[str], invocations: list[str]) -> list[str]:
    """Every needle that no invocation emits.

    Callable on synthetic invocations, so the cases below exercise the shipped matcher.
    """
    messages = [
        CONTINUATION.sub("", literal[1:-1])
        for invocation in invocations
        for literal in STRING_LITERAL.findall(invocation)
    ]
    problems = []
    for needle in found:
        field = JSON_FIELD.match(needle)
        if field:
            if not any(declares_field(inv, field.group(1)) for inv in invocations):
                problems.append(
                    f"{needle!r}: no tracing event declares a `{field.group(1)}` field"
                )
        elif not any(needle in message for message in messages):
            problems.append(f"{needle!r}: no tracing event message contains it")
    return problems


class RunFullNeedles(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = RUN_FULL.read_text(encoding="utf-8")
        cls.needles = needles(cls.script)
        cls.invocations = source_invocations()

    def test_every_wait_log_call_yields_a_needle(self):
        # Both counts derive from the same text, so equality alone passes when both
        # patterns match nothing. The floor and the resolved variable pin that the scan
        # is live.
        calls = ANY_WAIT_LOG_CALL.findall(strip_comments(self.script))
        self.assertGreaterEqual(
            len(calls),
            8,
            "found fewer wait_log calls than run-full.sh makes: the call pattern stopped "
            "matching, or a call was removed (lower this floor in the same commit)",
        )
        self.assertEqual(
            len(self.needles),
            len(calls),
            "a wait_log call passes its needle in a form this guard cannot read, so it "
            f"would go unchecked. Read: {self.needles}",
        )
        self.assertIn("PME active", self.needles)

    def test_every_needle_is_emitted_by_a_tracing_event(self):
        self.assertGreater(
            len(self.invocations),
            100,
            "the tracing macro scan found suspiciously few invocations",
        )
        problems = problems_for(self.needles, self.invocations)
        self.assertEqual(
            problems,
            [],
            "run-full.sh waits for log text that no tracing event in crates/ emits, so "
            "e2e-full would time out at that wait_log in a leg that works:\n"
            + "\n".join(problems),
        )

    def test_the_real_sources_reject_the_pre_rename_add_message(self):
        # The wording run-full.sh waited for after the emit site had moved to "channel".
        # Run against the real invocation set, so a scan that matched everything fails.
        problems = problems_for(["config reload added this bucket"], self.invocations)
        self.assertEqual(len(problems), 1, problems)

    def test_only_a_tracing_event_message_satisfies_a_needle(self):
        needle = "config reload added this channel"
        elsewhere = (
            f"/// {needle}, in a doc comment\n"
            f'let e = anyhow!("{needle}");\n'
            'info!(channel = %n, "config reload changed this channel");\n'
        )
        emitted = (
            'info!(channel = %n, "config reload added \\\n'
            '       this channel; starting its monitor");\n'
        )
        self.assertEqual(len(problems_for([needle], invocations_in(elsewhere))), 1)
        self.assertEqual(problems_for([needle], invocations_in(emitted)), [])

    def test_a_json_field_needle_binds_to_a_declared_field(self):
        needle = '"trust_sidecar_traceparent":true'
        in_message = 'warn!("trust_sidecar_traceparent = true is set");\n'
        declared = (
            "warn!(\n"
            "    trust_sidecar_traceparent = config.service.trust_sidecar_traceparent,\n"
            '    "a traceparent-trust flag is set"\n'
            ");\n"
        )
        self.assertEqual(len(problems_for([needle], invocations_in(in_message))), 1)
        self.assertEqual(problems_for([needle], invocations_in(declared)), [])


if __name__ == "__main__":
    unittest.main()
