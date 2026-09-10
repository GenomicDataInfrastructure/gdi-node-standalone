#!/usr/bin/env python3
"""Regression tests for ``scripts/check-dashboard-metrics.py``.

The guard catches a metric that is emitted but wired to nothing. A guard that can be
satisfied by prose goes green for the wrong reason, and goes red the moment someone
rewords a comment.

These tests pin the one property the guard depends on: an alert rule "references" a
metric only when the metric appears in a PromQL ``expr:``, never when it appears in a
comment, an ``annotations.summary``, or any other prose field. This mirrors the
constraint ``dashboard_query_series`` already enforces on the dashboard side.

Pure stdlib. Run: ``python3 -m unittest discover -s scripts/tests -p 'test_*.py'``
"""

import unittest

from _helpers import REPO_ROOT, load_module

ROOT = REPO_ROOT
cdm = load_module("scripts/check-dashboard-metrics.py", "check_dashboard_metrics")


COMMENT_ONLY = """
groups:
  - name: example
    rules:
      # Alert on the standing COUNT; gdi_store_scrub_last_run_timestamp_seconds is named here in
      # PROSE only, which must not make it count as alerted (that is what this fixture
      # pins). Synthetic — not a claim about the real rules file.
      - alert: StoreScrubFailed
        expr: gdi_store_scrub_failed > 0
        for: 0m
        annotations:
          summary: "see gdi_prose_only_total for background"
"""

BLOCK_SCALAR = """
groups:
  - name: example
    rules:
      - alert: BeaconServingErrors
        expr: |
          sum(rate(gdi_beacon_requests_total{status_class="5xx"}[5m]))
            / sum(rate(gdi_beacon_requests_total[5m])) > 0.05
          and sum(rate(gdi_beacon_requests_total[5m])) > 0.1
        for: 10m
        annotations:
          summary: "gdi_summary_only_total must not leak out of the block"
"""

FOLDED_SCALAR = """
groups:
  - name: example
    rules:
      - alert: Folded
        expr: >
          gdi_folded_total > 0
        for: 1m
"""


class AlertExprSeries(unittest.TestCase):
    """``alert_expr_series`` must see PromQL and nothing else."""

    def test_metric_named_only_in_a_comment_is_not_alerted(self):
        self.assertNotIn(
            "gdi_store_scrub_last_run_timestamp_seconds",
            cdm.alert_expr_series(COMMENT_ONLY),
        )

    def test_metric_named_only_in_an_annotation_is_not_alerted(self):
        self.assertNotIn("gdi_prose_only_total", cdm.alert_expr_series(COMMENT_ONLY))

    def test_metric_used_in_an_inline_expr_is_alerted(self):
        self.assertIn("gdi_store_scrub_failed", cdm.alert_expr_series(COMMENT_ONLY))

    def test_metrics_inside_a_literal_block_expr_are_alerted(self):
        self.assertIn("gdi_beacon_requests_total", cdm.alert_expr_series(BLOCK_SCALAR))

    def test_a_literal_block_expr_ends_at_the_next_key(self):
        """The block must stop at `for:`/`annotations:`, not swallow the summary."""
        self.assertNotIn("gdi_summary_only_total", cdm.alert_expr_series(BLOCK_SCALAR))

    def test_metrics_inside_a_folded_block_expr_are_alerted(self):
        self.assertIn("gdi_folded_total", cdm.alert_expr_series(FOLDED_SCALAR))

    def test_no_expr_yields_no_series(self):
        self.assertEqual(set(), cdm.alert_expr_series("# gdi_only_a_comment_total\n"))


ALLOY = """
discovery.relabel "containers" {
  rule {
    source_labels = ["__meta_docker_container_name"]
    regex         = "/(.*)"
    target_label  = "container"
  }
  rule {
    source_labels = ["__meta_docker_container_label_com_docker_compose_service"]
    target_label  = "service"
  }
  rule {
    target_label = "job"
    replacement  = "docker-logs"
  }
}
"""

COMPOSE = """
x-logging: &default-logging
  options:
    max-size: "10m"
services:
  gdi-node-standalone:
    image: x
  garage:
    image: y
volumes:
  datasets:
"""


def logs_dashboard(expr):
    return {
        "panels": [
            {
                "type": "logs",
                "title": "Node logs",
                "datasource": {"type": "loki", "uid": "loki"},
                "targets": [
                    {"datasource": {"type": "loki", "uid": "loki"}, "expr": expr}
                ],
            }
        ]
    }


class AlloyAndComposeParsing(unittest.TestCase):
    def test_alloy_target_labels(self):
        self.assertEqual(
            {"container", "service", "job"}, cdm.alloy_target_labels(ALLOY)
        )

    def test_compose_services_ignores_anchors_and_volumes(self):
        self.assertEqual(
            {"gdi-node-standalone", "garage"}, cdm.compose_services(COMPOSE)
        )

    def test_stream_selector_is_parsed(self):
        self.assertEqual(
            {"service": "gdi-node-standalone", "job": "docker-logs"},
            cdm.parse_stream_selector(
                '{service="gdi-node-standalone", job="docker-logs"}'
            ),
        )


class LogPanelSelectors(unittest.TestCase):
    """A log panel whose selector cannot match is the failure it exists to detect."""

    def check(self, expr):
        return cdm.check_log_panels(logs_dashboard(expr), ALLOY, COMPOSE)

    def test_a_correct_selector_passes(self):
        self.assertEqual([], self.check('{service="gdi-node-standalone"}'))

    def test_selecting_on_container_is_rejected(self):
        """`container` is `<project>-<service>-<n>`, so it cannot match a service name."""
        problems = "\n".join(self.check('{container="gdi-node-standalone"}'))
        self.assertIn("container", problems)
        self.assertIn("COMPOSE_PROJECT_NAME", problems)

    def test_a_label_no_relabel_rule_produces_is_rejected(self):
        problems = "\n".join(self.check('{app="gdi-node-standalone"}'))
        self.assertIn("app", problems)
        self.assertIn("config.alloy", problems)

    def test_a_service_value_that_is_not_a_compose_service_is_rejected(self):
        problems = "\n".join(self.check('{service="gdi-node-liet"}'))
        self.assertIn("gdi-node-liet", problems)

    def test_a_selector_without_service_is_rejected(self):
        """`job` is `docker-logs` on every container, so it discriminates nothing."""
        problems = "\n".join(self.check('{job="docker-logs"}'))
        self.assertIn("service", problems)

    def test_a_dashboard_with_no_log_panels_is_clean(self):
        self.assertEqual([], cdm.check_log_panels({"panels": []}, ALLOY, COMPOSE))


class ShippedRulesFile(unittest.TestCase):
    """Pin the real rules file, so an edit cannot reintroduce a prose-only reference."""

    def setUp(self):
        self.alerted = cdm.alert_expr_series(cdm.RULES.read_text())

    def test_multiline_expr_metrics_are_still_seen(self):
        # These live only inside `expr: |` blocks. A single-line regex would drop them
        # and report the two serving-error alerts as drift.
        self.assertIn("gdi_beacon_requests_total", self.alerted)
        self.assertIn("gdi_fairdp_requests_total", self.alerted)

    def test_comment_only_metric_is_not_counted_as_alerted(self):
        # This metric's only occurrence in the rules file is a prose comment, so it must
        # not appear in `alerted`. `AlertExprSeries` covers the parser synthetically; this
        # case pins the shipped file, so its subject must be a metric that is comment-only
        # today. If `gdi_datasets_suppressed` gains an alert, re-point this at whatever is
        # comment-only then rather than deleting the case.
        self.assertNotIn("gdi_datasets_suppressed", self.alerted)


class ShippedLogPanels(unittest.TestCase):
    """The real dashboard's log panels must resolve against the real Alloy + Compose."""

    def test_shipped_dashboard_log_panels_are_selectable(self):
        import json

        self.assertEqual(
            [],
            cdm.check_log_panels(
                json.loads(cdm.DASHBOARD.read_text()),
                cdm.ALLOY.read_text(),
                cdm.COMPOSE.read_text(),
            ),
        )


class PresentationChecks(unittest.TestCase):
    """Each presentation check must go red on the defect it exists for and stay clean on
    the fixed shape."""

    RULES = """
groups:
  - name: example
    rules:
      - alert: LowDisk
        expr: gdi_disk_free_bytes < 5e9
        for: 5m
      - alert: VaultRenewalFailing
        expr: increase(gdi_vault_reauth_total{outcome="failed"}[15m]) > 0
        for: 0m
"""

    @staticmethod
    def panel(title, typ="timeseries", exprs=(), grid=None, **extra):
        p = {
            "type": typ,
            "title": title,
            "gridPos": grid or {"h": 8, "w": 12, "x": 0, "y": 0},
            "targets": [{"expr": e} for e in exprs],
        }
        p.update(extra)
        return p

    def test_overlapping_panels_are_reported(self):
        a = self.panel("A", grid={"h": 8, "w": 12, "x": 0, "y": 40})
        b = self.panel("B", grid={"h": 8, "w": 12, "x": 0, "y": 40})
        c = self.panel("C", grid={"h": 8, "w": 12, "x": 12, "y": 40})
        problems = cdm.gridpos_overlaps({"panels": [a, b, c]})
        self.assertEqual(1, len(problems))
        self.assertIn("'A'", problems[0])
        self.assertIn("'B'", problems[0])
        self.assertEqual([], cdm.gridpos_overlaps({"panels": [a, c]}))

    def test_stat_showing_every_sample_needs_instant_targets(self):
        bad = self.panel(
            "probe",
            "stat",
            ["probe_success"],
            options={"reduceOptions": {"values": True}},
        )
        self.assertEqual(
            1, len(cdm.stat_panels_showing_every_sample({"panels": [bad]}))
        )
        bad["targets"][0]["instant"] = True
        self.assertEqual([], cdm.stat_panels_showing_every_sample({"panels": [bad]}))
        reduced = self.panel(
            "probe",
            "stat",
            ["probe_success"],
            options={"reduceOptions": {"values": False}},
        )
        self.assertEqual(
            [], cdm.stat_panels_showing_every_sample({"panels": [reduced]})
        )

    def test_threshold_colouring_needs_steps(self):
        bad = self.panel(
            "Uptime",
            "stat",
            ["gdi_uptime_seconds"],
            fieldConfig={"defaults": {"color": {"mode": "thresholds"}}},
        )
        self.assertEqual(
            1, len(cdm.threshold_colored_panels_without_steps({"panels": [bad]}))
        )
        good = self.panel(
            "Uptime",
            "stat",
            ["gdi_uptime_seconds"],
            fieldConfig={
                "defaults": {
                    "color": {"mode": "thresholds"},
                    "thresholds": {"steps": [{"color": "text", "value": None}]},
                }
            },
        )
        self.assertEqual(
            [], cdm.threshold_colored_panels_without_steps({"panels": [good]})
        )

    def test_a_stat_with_no_color_key_still_colours_by_thresholds(self):
        # Grafana's default colour mode for stat and gauge is thresholds, so a panel that
        # omits `color` inherits [green@null, red@80] rather than opting out.
        implicit = self.panel(
            "Uptime",
            "stat",
            ["gdi_uptime_seconds"],
            fieldConfig={"defaults": {"unit": "s"}},
        )
        self.assertEqual(
            1, len(cdm.threshold_colored_panels_without_steps({"panels": [implicit]}))
        )
        series = self.panel(
            "Rate", "timeseries", ["gdi_x"], fieldConfig={"defaults": {"unit": "s"}}
        )
        self.assertEqual(
            [], cdm.threshold_colored_panels_without_steps({"panels": [series]})
        )

    def test_a_novalue_tile_needs_a_neutral_base(self):
        def tile(base):
            return self.panel(
                "Token file age",
                "stat",
                ["gdi_vault_token_file_age_seconds"],
                fieldConfig={
                    "defaults": {
                        "noValue": "no token_file",
                        "color": {"mode": "thresholds"},
                        "thresholds": {
                            "steps": [
                                {"color": base, "value": None},
                                {"color": "red", "value": 3600},
                            ]
                        },
                    }
                },
            )

        problems = cdm.novalue_tiles_with_a_status_coloured_base(
            {"panels": [tile("green")]}
        )
        self.assertEqual(1, len(problems))
        self.assertIn("'green'", problems[0])
        self.assertEqual(
            [],
            cdm.novalue_tiles_with_a_status_coloured_base({"panels": [tile("text")]}),
        )
        # No noValue: the base colour is the tile's own business.
        plain = tile("green")
        del plain["fieldConfig"]["defaults"]["noValue"]
        self.assertEqual(
            [], cdm.novalue_tiles_with_a_status_coloured_base({"panels": [plain]})
        )

    def test_alert_named_panel_must_chart_the_alerts_series(self):
        wrong = self.panel(
            "Vault renewal failures (VaultRenewalFailing, CRITICAL)",
            exprs=["increase(gdi_vault_renewal_failures_total[15m])"],
        )
        problems = cdm.alert_named_panels_missing_series(
            {"panels": [wrong]}, self.RULES
        )
        self.assertEqual(1, len(problems))
        self.assertIn("gdi_vault_reauth_total", problems[0])
        right = self.panel(
            "Re-auth outcomes (VaultRenewalFailing)",
            exprs=["sum by (outcome) (increase(gdi_vault_reauth_total[1h]))"],
        )
        self.assertEqual(
            [], cdm.alert_named_panels_missing_series({"panels": [right]}, self.RULES)
        )
        # A title that merely contains an alert name as a substring is not naming it.
        unrelated = self.panel("NotLowDiskAtAll", exprs=["gdi_uptime_seconds"])
        self.assertEqual(
            [],
            cdm.alert_named_panels_missing_series({"panels": [unrelated]}, self.RULES),
        )

    def test_mixed_units_on_one_axis_are_reported(self):
        rate_and_count = self.panel(
            "Ingest",
            exprs=[
                "gdi_ingest_queue_depth",
                "sum by (outcome) (rate(gdi_ingest_total[5m]))",
            ],
        )
        self.assertEqual(1, len(cdm.mixed_unit_panels({"panels": [rate_and_count]})))
        age_and_count = self.panel(
            "Age",
            exprs=[
                "time() - gdi_ingest_last_progress_timestamp_seconds",
                "gdi_ingest_queue_depth",
            ],
        )
        self.assertEqual(1, len(cdm.mixed_unit_panels({"panels": [age_and_count]})))
        counts = self.panel(
            "Counts", exprs=["gdi_ingest_queue_depth", "gdi_ingest_inflight"]
        )
        self.assertEqual([], cdm.mixed_unit_panels({"panels": [counts]}))
        seconds = self.panel(
            "Latency",
            exprs=[
                "histogram_quantile(0.5, sum by (le) (rate(gdi_x_seconds_bucket[5m])))",
                "increase(gdi_x_seconds_sum[1h]) / increase(gdi_x_seconds_count[1h])",
            ],
        )
        self.assertEqual([], cdm.mixed_unit_panels({"panels": [seconds]}))
        # Stat tiles are not an axis; mixing units across tiles is fine.
        tiles = self.panel(
            "Stat",
            "stat",
            exprs=[
                "gdi_store_scrub_failed",
                "time() - gdi_store_scrub_last_run_timestamp_seconds",
            ],
        )
        self.assertEqual([], cdm.mixed_unit_panels({"panels": [tiles]}))

    def test_disk_tile_must_carry_the_lowdisk_margin(self):
        def disk(step):
            return self.panel(
                "Disk",
                "stat",
                ["gdi_disk_free_bytes"],
                fieldConfig={
                    "defaults": {
                        "thresholds": {
                            "steps": [
                                {"color": "red", "value": None},
                                {"color": "yellow", "value": step},
                            ]
                        }
                    }
                },
            )

        self.assertEqual(
            1, len(cdm.disk_threshold_mismatch({"panels": [disk(10e9)]}, self.RULES))
        )
        self.assertEqual(
            [], cdm.disk_threshold_mismatch({"panels": [disk(5000000000)]}, self.RULES)
        )
        # A rules file with no LowDisk expression blinds the check, which is a problem.
        self.assertEqual(
            1, len(cdm.disk_threshold_mismatch({"panels": [disk(5e9)]}, "groups: []"))
        )


class ShippedDashboardPresentation(unittest.TestCase):
    """The real dashboard passes every presentation check against the real rules."""

    def test_shipped_dashboard_passes_every_presentation_check(self):
        import json

        dashboard = json.loads(cdm.DASHBOARD.read_text())
        # Every check iterates `panels`, so an empty or renamed top-level key would make
        # this pass having inspected nothing.
        self.assertGreater(
            len(list(cdm.all_panels(dashboard))),
            20,
            "the shipped dashboard parsed to almost no panels, so this passes vacuously",
        )
        self.assertEqual([], cdm.check_presentation(dashboard, cdm.RULES.read_text()))


if __name__ == "__main__":
    unittest.main()
