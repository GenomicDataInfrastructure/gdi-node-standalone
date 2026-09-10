"""The log and trace vocabularies keep one shape each, and every audit line carries both keys.

An operator expects one vocabulary across audit lines, alarm lines and span names, not
several. This guard holds that shape:

* every tracing span name is snake_case;
* every `event = "…"` (the audit vocabulary the runbook's catalogue pins) is snake_case;
* every `event.action = "…"` is dotted ECS form (`service.start`, `beacon.query.reject`);
* every tracing invocation carrying `event = "…"` also carries `event.action = "…"`, so the
  one machine key selects audit lines too.

Source-level, in the style of `test_alert_tag_shape.py`: the values are literals at the call
sites, so this is where drift starts.
"""

import re
import unittest

from _helpers import MACRO_OPEN, REPO_ROOT, invocation_at, strip_test_modules

CRATES = REPO_ROOT / "crates"

SPAN_NAME = re.compile(
    r"\b(?:info|debug|trace|warn|error)_span!\s*\(\s*(?:parent:\s*[^,]+,\s*)?\"([^\"]+)\""
)
EVENT = re.compile(r'\bevent\s*=\s*"([^"]+)"')
ACTION = re.compile(r'\bevent\.action\s*=\s*"([^"]+)"')
SNAKE = re.compile(r"^[a-z][a-z0-9_]*$")
DOTTED = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")


def source_files():
    return sorted(
        path
        for path in CRATES.rglob("*.rs")
        if "/target/" not in path.as_posix() and "/tests/" not in path.as_posix()
    )


def invocations(text):
    return [invocation_at(text, match.start()) for match in MACRO_OPEN.finditer(text)]


class EventVocabularyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spans = []  # (file, name)
        cls.events = []  # (file, invocation)
        cls.actions = []  # (file, value)
        for path in source_files():
            # Production code only: a `#[cfg(test)] mod …` holds fixtures that emit a
            # bare `event` to exercise the layers. Every test module is cut out by brace
            # matching, since a file may hold several with production emit sites between
            # them.
            text = strip_test_modules(path.read_text(encoding="utf-8"))
            rel = path.relative_to(REPO_ROOT).as_posix()
            cls.spans.extend((rel, m.group(1)) for m in SPAN_NAME.finditer(text))
            for invocation in invocations(text):
                if EVENT.search(invocation):
                    cls.events.append((rel, invocation))
                cls.actions.extend(
                    (rel, m.group(1)) for m in ACTION.finditer(invocation)
                )

    def test_the_scan_saw_the_repo(self):
        # Vacuity guards: an empty scan would pass every assertion below.
        self.assertGreaterEqual(len(self.spans), 20, self.spans)
        self.assertGreaterEqual(len(self.events), 30, len(self.events))
        self.assertGreaterEqual(len(self.actions), 50, len(self.actions))

    def test_span_names_are_snake_case(self):
        bad = [(f, n) for f, n in self.spans if not SNAKE.match(n)]
        self.assertEqual([], bad, f"span names that are not snake_case: {bad}")

    def test_audit_event_names_are_snake_case(self):
        bad = [
            (f, m.group(1))
            for f, inv in self.events
            for m in EVENT.finditer(inv)
            if not SNAKE.match(m.group(1))
        ]
        self.assertEqual([], bad, f"`event` values that are not snake_case: {bad}")

    def test_event_actions_are_dotted_ecs_names(self):
        bad = [(f, v) for f, v in self.actions if not DOTTED.match(v)]
        self.assertEqual([], bad, f"`event.action` values that are not dotted: {bad}")

    def test_every_audit_line_also_carries_event_action(self):
        missing = [
            (f, EVENT.search(inv).group(1))
            for f, inv in self.events
            if not ACTION.search(inv)
        ]
        self.assertEqual(
            [], missing, f"tracing sites with `event` but no `event.action`: {missing}"
        )

    # --- the scanner itself -----------------------------------------------------------

    def test_the_scanner_finds_a_kebab_span_and_a_dotless_action(self):
        self.assertEqual(
            ["check-layout"],
            [
                m.group(1)
                for m in SPAN_NAME.finditer('info_span!("check-layout").entered()')
            ],
        )
        self.assertEqual(
            ["ingest_job"],
            [
                m.group(1)
                for m in SPAN_NAME.finditer(
                    'tracing::info_span!(parent: &job_span, "ingest_job")'
                )
            ],
        )
        self.assertIsNone(DOTTED.match("startup"))
        self.assertIsNotNone(DOTTED.match("vault.token.reauth"))
        self.assertIsNone(SNAKE.match("beacon.query"))

    def test_the_scanner_pairs_event_with_action_inside_one_invocation(self):
        paired = 'fn f() { info!(target: "audit", event = "x_y", event.action = "x.y", "m"); }'
        alone = 'fn f() { info!(target: "audit", event = "x_y", "m"); }'
        (inv,) = invocations(paired)
        self.assertTrue(EVENT.search(inv) and ACTION.search(inv))
        (inv,) = invocations(alone)
        self.assertTrue(EVENT.search(inv) and not ACTION.search(inv))


if __name__ == "__main__":
    unittest.main()
