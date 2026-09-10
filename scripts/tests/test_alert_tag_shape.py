"""Every `alert = true` log site names what happened, and the runbook lists it.

`alert = true` is how a tracing site asks for `tags: ["Alert"]` (docs/operating.md §15).
The alerting rule routes on that tag and puts `event.action` in the ticket subject, so a
site that tags without naming what happened raises a ticket that says nothing. An action
the runbook does not list leaves whoever holds the ticket without a "what to do" row.

The fatal path (`report_fatal`, action `startup`) is built by hand in logging.rs, so this
guard, which reads tracing macro invocations, does not see it.
"""

import re
import unittest

from _helpers import MACRO_OPEN, REPO_ROOT, invocation_at

CRATES = REPO_ROOT / "crates"
RUNBOOK = REPO_ROOT / "docs" / "operating.md"

ALERT_FIELD = re.compile(r"\balert\s*=\s*true\b")
ACTION = re.compile(r'\bevent\.action\s*=\s*"([^"]+)"')
OUTCOME = re.compile(r'\bevent\.outcome\s*=\s*"([^"]+)"')
# Emitted by the fatal path in logging.rs, not by a tracing site.
FATAL_ACTION = "startup"


def alert_sites(text):
    """Every tracing macro invocation in `text` carrying `alert = true`."""
    return [
        invocation
        for match in MACRO_OPEN.finditer(text)
        for invocation in [invocation_at(text, match.start())]
        if ALERT_FIELD.search(invocation)
    ]


def source_files():
    return sorted(
        path
        for path in CRATES.rglob("*.rs")
        if "/target/" not in path.as_posix() and "/tests/" not in path.as_posix()
    )


def runbook_actions(text):
    """The `event.action` column of the §15 "Alarm lines" table."""
    lines = text[text.index("**Alarm lines") :].splitlines()
    rows = []
    in_table = False
    past_header = False
    for line in lines:
        if line.strip().startswith("|"):
            in_table = True
            if line.strip().startswith("|---"):
                past_header = True  # the header row names the column, not an action
                continue
            found = re.match(r"^\s*\| `([a-z][a-z0-9_.]*)` \|", line)
            if found and past_header:
                rows.append(found.group(1))
        elif in_table:
            break
    return set(rows)


class AlertTagShapeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sites = {}
        for path in source_files():
            found = alert_sites(path.read_text(encoding="utf-8"))
            if found:
                cls.sites[path.relative_to(REPO_ROOT).as_posix()] = found
        cls.documented = runbook_actions(RUNBOOK.read_text(encoding="utf-8"))

    def test_there_are_tagged_sites(self):
        # Vacuity guard: an empty scan would pass every assertion below.
        self.assertGreaterEqual(sum(map(len, self.sites.values())), 5, self.sites)

    def test_every_site_names_an_action_and_an_outcome(self):
        for path, invocations in self.sites.items():
            for invocation in invocations:
                self.assertRegex(
                    invocation, ACTION, f"{path}: alert without event.action"
                )
                self.assertRegex(
                    invocation, OUTCOME, f"{path}: alert without event.outcome"
                )

    def test_every_action_has_a_runbook_row_and_no_row_is_stale(self):
        used = {
            ACTION.search(invocation).group(1)
            for invocations in self.sites.values()
            for invocation in invocations
            if ACTION.search(invocation)
        }
        self.assertTrue(
            self.documented, "no Alarm lines table in docs/operating.md §15"
        )
        self.assertLessEqual(
            used,
            self.documented,
            f"tagged actions without a §15 row: {sorted(used - self.documented)}",
        )
        self.assertLessEqual(
            self.documented,
            used | {FATAL_ACTION},
            f"§15 rows for actions no site emits: {sorted(self.documented - used - {FATAL_ACTION})}",
        )

    # --- the scanner itself -------------------------------------------------------------

    def test_the_scanner_reports_a_site_that_tags_without_naming_the_action(self):
        snippet = 'fn f() { warn!(alert = true, error = %e, "renewal failed"); }'
        (site,) = alert_sites(snippet)
        self.assertIsNone(ACTION.search(site))

    def test_the_scanner_is_string_aware(self):
        snippet = (
            'warn!(alert = true, event.action = "x.y", event.outcome = "failure", '
            '"failed (treated as transient); see \\"docs\\" (again)");\n'
            'other!(alert = true, "not counted twice")'
        )
        sites = alert_sites(snippet)
        self.assertEqual(len(sites), 1, sites)
        self.assertTrue(sites[0].endswith('(again)")'), sites[0])

    def test_the_scanner_ignores_untagged_invocations(self):
        self.assertEqual(alert_sites('warn!(error = %e, "plain");'), [])


if __name__ == "__main__":
    unittest.main()
