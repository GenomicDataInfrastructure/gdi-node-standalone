#!/usr/bin/env python3
"""Guard: every alert rule has a promtool case, and every case names a live rule.

`promtool check rules` proves the rules file parses. `promtool test rules` proves a rule
fires on the input it was written for, but only for the rules that have a case. An
inverted threshold on a rule with no case parses, passes `check rules`, and never fires.

Set equality is asserted both ways: a rule without a case is untested, and a case without
a rule tests nothing, because promtool does not fail a case whose alertname matches no
rule.

Stdlib regexes over the YAML, not a parser: the two shapes are one-line keys
(`- alert: Name`, `alertname: Name`) and the suite must stay stdlib-only.
"""

import re
import unittest

from _helpers import REPO_ROOT

RULES = sorted((REPO_ROOT / "compose" / "observability" / "rules").glob("*.yml"))
CASES = sorted(
    (REPO_ROOT / "compose" / "observability" / "rules" / "tests").glob("*.test.yml")
)
_ALERT = re.compile(r"^\s*-\s*alert:\s*([A-Za-z0-9_]+)\s*$", re.MULTILINE)
_CASE = re.compile(r"^\s*alertname:\s*([A-Za-z0-9_]+)\s*$", re.MULTILINE)
#: Anti-vacuity floor: the rules file carries well over this many rules, and a parser
#: that silently matched a handful would otherwise pass the equality on two small sets.
FLOOR = 40


def rule_names() -> set[str]:
    return {m for p in RULES for m in _ALERT.findall(p.read_text(encoding="utf-8"))}


def case_names() -> set[str]:
    return {m for p in CASES for m in _CASE.findall(p.read_text(encoding="utf-8"))}


class PromtoolCaseCoverageTest(unittest.TestCase):
    def test_the_files_were_found(self):
        self.assertTrue(RULES, "no rules file under compose/observability/rules/")
        self.assertTrue(CASES, "no promtool test file under rules/tests/")

    def test_enough_rules_were_parsed(self):
        rules = rule_names()
        self.assertGreaterEqual(
            len(rules),
            FLOOR,
            f"parsed only {len(rules)} rules; the `- alert:` shape changed, or rules were "
            "removed. Fix the parser or lower FLOOR in the same commit",
        )

    def test_every_rule_has_a_case_and_every_case_names_a_rule(self):
        rules, cases = rule_names(), case_names()
        self.assertEqual(
            rules - cases,
            set(),
            "alert rule(s) with no promtool case: an inverted threshold there parses, "
            "passes `check rules`, and never fires. Add a firing case, and a non-firing "
            "one where the rule has a `for` window or a threshold",
        )
        self.assertEqual(
            cases - rules,
            set(),
            "promtool case(s) naming a rule that does not exist; promtool does not fail "
            "such a case, so a renamed rule leaves its old case green forever",
        )


if __name__ == "__main__":
    unittest.main()
