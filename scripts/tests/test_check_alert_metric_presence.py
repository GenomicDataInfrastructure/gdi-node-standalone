#!/usr/bin/env python3
"""Unit tests for `scripts/check-alert-metric-presence.py`.

The guard itself runs only inside the observability e2e leg, which needs Docker. Without
these tests its parsing and its two-way exemption rule are never exercised by the gate a
developer can run.
"""

import pathlib
import unittest

from _helpers import REPO_ROOT, load_module

CAMP = load_module(
    "scripts/check-alert-metric-presence.py", "check_alert_metric_presence"
)

# 20+ metrics, because the guard refuses to run on a suspiciously small parse.
FILLER = "\n".join(
    f"      - alert: A{i}\n        expr: gdi_filler_{i} > 0" for i in range(20)
)
RULES = f"""groups:
  - name: node
    rules:
{FILLER}
      - alert: PmeMasterKeyMismatch
        expr: gdi_pme_master_key_mismatch > 0
        annotations:
          summary: "mentions gdi_never_referenced_in_an_expr in prose only"
      - alert: Latency
        expr: histogram_quantile(0.9, rate(gdi_http_duration_seconds_bucket[5m])) > 1
      - alert: BlockScalar
        expr: |
          sum(rate(gdi_block_scalar_only[5m]))
            > 0
        for: 5m
      - alert: FoldedScalar
        expr: >
          gdi_folded_scalar_only > 0
      - alert: PlainContinuation
        expr: gdi_plain_first
          + gdi_plain_continued > 0
"""


def _scrape(*names: str) -> str:
    """A minimal Prometheus text-format body exporting `names`."""
    lines = []
    for n in names:
        lines.append(f"# TYPE {n} gauge")
        lines.append(f"{n} 0")
    return "\n".join(lines) + "\n"


ALL_FILLER = tuple(f"gdi_filler_{i}" for i in range(20))
#: The metrics the block, folded and plain-continuation fixtures name. Exported in the
#: scrapes of tests about other properties, so each of those stays about one thing.
SCALAR_FIXTURES = (
    "gdi_block_scalar_only",
    "gdi_folded_scalar_only",
    "gdi_plain_first",
    "gdi_plain_continued",
)


class AlertedMetrics(unittest.TestCase):
    def test_reads_expr_lines_only(self):
        found = CAMP.alerted_metrics(RULES)
        self.assertIn("gdi_pme_master_key_mismatch", found)
        self.assertNotIn(
            "gdi_never_referenced_in_an_expr",
            found,
            "a name in an annotations.summary does not make an alert depend on it; "
            "counting prose lets the guard pass for the wrong reason",
        )

    def test_histogram_suffixes_fold_to_the_base_series(self):
        self.assertIn("gdi_http_duration_seconds", CAMP.alerted_metrics(RULES))

    def test_block_scalars_and_continuations_are_read_in_full(self):
        # The shipped rules file writes BeaconServingErrors and FdpServingErrors as
        # `expr: |`, so a parser that reads only the first line leaves them unchecked.
        found = CAMP.alerted_metrics(RULES)
        self.assertIn("gdi_block_scalar_only", found)
        self.assertIn("gdi_folded_scalar_only", found)
        self.assertIn("gdi_plain_first", found)
        self.assertIn("gdi_plain_continued", found)
        # That the block ends at the next key, so `for: 5m` is not swallowed into the
        # expression, is shown by `test_reads_expr_lines_only` and its
        # `annotations.summary` fixture.

    def test_a_block_scalar_alert_on_an_absent_metric_fails(self):
        # An `expr: |` alert whose series is never exported must be reported, not
        # silently skipped.
        scrape = _scrape(
            *ALL_FILLER,
            "gdi_http_duration_seconds",
            "gdi_pme_master_key_mismatch",
            "gdi_folded_scalar_only",
            "gdi_plain_first",
            "gdi_plain_continued",
        )
        problems = CAMP.check(RULES, scrape, {})
        self.assertTrue(
            any("gdi_block_scalar_only" in p for p in problems),
            f"the block-scalar alert's metric must be reported as missing; got {problems}",
        )


class ExportedMetrics(unittest.TestCase):
    def test_type_lines_alone_do_not_count_as_exported(self):
        # `describe_gauge!` emits HELP and TYPE with no sample behind it. Counting a TYPE
        # line as exported would blind the guard to exactly that case.
        self.assertEqual(CAMP.exported_metrics("# TYPE gdi_x gauge\n"), set())

    def test_a_sample_line_counts_with_or_without_labels(self):
        got = CAMP.exported_metrics('gdi_a 1\ngdi_b{k="v"} 2\n')
        self.assertEqual(got, {"gdi_a", "gdi_b"})


class Check(unittest.TestCase):
    def test_a_declared_but_never_exported_metric_fails(self):
        problems = CAMP.check(
            RULES,
            _scrape(*ALL_FILLER, *SCALAR_FIXTURES, "gdi_http_duration_seconds"),
            {},
        )
        self.assertTrue(
            any("gdi_pme_master_key_mismatch" in p for p in problems),
            f"an alerted metric that is never exported must be reported; got {problems}",
        )

    def test_an_expect_absent_metric_is_allowed_to_be_missing(self):
        problems = CAMP.check(
            RULES,
            _scrape(*ALL_FILLER, *SCALAR_FIXTURES, "gdi_http_duration_seconds"),
            {"gdi_pme_master_key_mismatch": "lite node"},
        )
        self.assertEqual(problems, [])

    def test_an_expect_absent_metric_that_IS_present_fails(self):
        # The two-way rule: an exemption must fail once the metric is exported again, so
        # a one-way allow-list cannot outlive the condition that justified it.
        problems = CAMP.check(
            RULES,
            _scrape(
                *ALL_FILLER, "gdi_http_duration_seconds", "gdi_pme_master_key_mismatch"
            ),
            {"gdi_pme_master_key_mismatch": "lite node"},
        )
        self.assertTrue(
            any("IS exported" in p for p in problems),
            f"a stale exemption must fail; got {problems}",
        )

    def test_an_exemption_for_an_unalerted_metric_fails(self):
        problems = CAMP.check(
            RULES,
            _scrape(
                *ALL_FILLER, "gdi_http_duration_seconds", "gdi_pme_master_key_mismatch"
            ),
            {"gdi_not_in_any_rule": "stale"},
        )
        self.assertTrue(
            any("dead weight" in p for p in problems),
            f"an exemption naming a metric no rule references must fail; got {problems}",
        )

    def test_a_broken_extractor_fails_instead_of_passing_silently(self):
        problems = CAMP.check("groups: []\n", _scrape("gdi_a"), {})
        self.assertTrue(
            any("extractor is probably broken" in p for p in problems),
            f"parsing ~nothing must fail loudly, not pass; got {problems}",
        )


class ExpectAbsentParsing(unittest.TestCase):
    def test_a_reason_is_mandatory(self):
        with self.assertRaises(SystemExit):
            CAMP.parse_expect_absent(["gdi_x"])
        with self.assertRaises(SystemExit):
            CAMP.parse_expect_absent(["gdi_x="])

    def test_name_and_reason_are_split_and_stripped(self):
        self.assertEqual(
            CAMP.parse_expect_absent([" gdi_x = no S3 here "]), {"gdi_x": "no S3 here"}
        )


class ShippedRulesAreParseable(unittest.TestCase):
    """The real rules file must parse to a plausible metric set, so that a YAML reformat
    or a new rule layout cannot reduce this guard to a no-op that still exits 0."""

    def test_the_shipped_rules_yield_a_substantial_metric_set(self):
        rules = (
            pathlib.Path(REPO_ROOT)
            / "compose"
            / "observability"
            / "rules"
            / "gdi-node-standalone.yml"
        ).read_text(encoding="utf-8")
        found = CAMP.alerted_metrics(rules)
        self.assertGreater(len(found), 20, f"only parsed {sorted(found)}")
        self.assertTrue(all(n.startswith("gdi_") for n in found), sorted(found))


if __name__ == "__main__":
    unittest.main()
