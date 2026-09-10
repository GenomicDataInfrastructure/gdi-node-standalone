#!/usr/bin/env python3
"""Observability drift + coverage guard.

Checks over the node's metrics, the checked-in Grafana dashboard and the Prometheus alert
rules. ``promtool check rules`` validates PromQL syntax but never confirms that a metric
name exists, since metrics only exist at runtime, so a renamed or removed metric passes
it. This guard closes that gap by taking the ``"gdi_..."`` string literals registered in
``crates/gdi-node-standalone/src/metrics.rs`` as the list of metrics that exist.

1. DRIFT: every ``gdi_*`` series the dashboard charts must resolve to a declared
   metric (histogram ``_bucket``/``_sum``/``_count`` suffixes and recording-rule
   ``record:`` names allowed). Catches a panel left pointing at a renamed or removed
   series.

2. COVERAGE: every declared metric must be observed somewhere, charted on the dashboard
   or referenced by an alert rule. Catches a metric that is emitted but wired to nothing.

   There is no exemption list. A metric with nowhere to go is a question about the
   metric, not a gap in this guard.

   "Charted" and "alerted" both mean *named in a PromQL query*: a panel target's
   ``expr``/``query``, or an alert rule's ``expr``. A metric named only in a panel
   title, a rule comment, or an ``annotations.summary`` does not count. Otherwise this
   check is satisfiable by prose: it passes for the wrong reason when a dead metric hides
   behind a comment, and later fails for the wrong reason when that comment is reworded.

3. RUNBOOK PARITY: ``docs/operating.md`` must carry every alert rule name in its §3
   marker block and a catalogue row for each, and a §2 metrics-table row for every
   declared metric.

4. EMISSION: every declared metric must have a ``counter!``/``gauge!``/``histogram!``
   call site in the node source. Declared, charted and alerted says nothing about
   whether the series is ever written.

5. LOG PANELS: every Loki panel must select on a label Alloy emits, must not use an
   unstable one, and its ``service="…"`` value must be a real Compose service. A
   selector that can never match renders an empty panel, which is indistinguishable from
   a quiet node.

6. PRESENTATION: panel layout, chart form, thresholds and axis units, which no name
   check can see.

Pure stdlib, no Docker, no running node. Exit: 0 = clean, 1 = problem, 2 = IO error.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DASHBOARD = ROOT / "compose/observability/grafana/dashboards/gdi-node-standalone.json"
METRICS_RS = ROOT / "crates/gdi-node-standalone/src/metrics.rs"
SRC_DIR = ROOT / "crates/gdi-node-standalone/src"
RULES = ROOT / "compose/observability/rules/gdi-node-standalone.yml"
OPERATING_MD = ROOT / "docs/operating.md"
ALLOY = ROOT / "compose/observability/alloy/config.alloy"
COMPOSE = ROOT / "docker-compose.yml"

# Log-stream labels a dashboard panel must not select on, and why. Alloy derives
# `container` from the Docker container name, and Compose names containers
# `<project>-<service>-<n>`, so the name moves with `COMPOSE_PROJECT_NAME` / `-p` and a
# panel pinned to `container="gdi-node-standalone"` silently matches nothing.
UNSTABLE_LOG_LABELS = {
    "container": "Alloy sets it from the Docker container name, and Compose names "
    "containers `<project>-<service>-<n>`, so it moves with COMPOSE_PROJECT_NAME",
    "job": "set unconditionally to `docker-logs` on every container, so it "
    "discriminates nothing",
}

# The one stable discriminator: Compose's own `com.docker.compose.service` label.
REQUIRED_LOG_LABEL = "service"

# Delimiters of the machine-checked rule-name list in docs/operating.md §3. The list
# between them must equal the set of `alert:` names in RULES (see check 3 below).
ALERT_NAMES_START = "<!-- alert-rule-names:start -->"
ALERT_NAMES_END = "<!-- alert-rule-names:end -->"

# Delimiters of the machine-checked metrics table in docs/operating.md §2. Scoping the
# doc-coverage check to this block stops a metric named only in prose from satisfying it.
METRIC_NAMES_START = "<!-- metric-names:start -->"
METRIC_NAMES_END = "<!-- metric-names:end -->"

HIST_SUFFIXES = ("_bucket", "_sum", "_count")


def declared_metric_names(src):
    """The ``"gdi_..."`` string literals registered in metrics.rs: the metrics that exist."""
    return set(re.findall(r'"(gdi_[a-z0-9_]+)"', src))


def recording_rule_names(rules_text):
    return set(re.findall(r"record:\s*([A-Za-z0-9_:]+)", rules_text))


def referenced_series(blob):
    return set(re.findall(r"gdi_[a-z0-9_]+", blob))


def alert_expr_values(rules_text):
    """Every PromQL string under an ``expr:`` key in the rules YAML, and nothing else.

    Handles both forms the rules file uses: an inline scalar (``expr: foo > 0``) and a
    block scalar (``expr: |`` / ``expr: >``) whose body is the following more-indented
    lines. Stops at the next key at or below the ``expr:`` indent, so a metric named in
    a sibling ``annotations.summary`` never leaks into the result.

    Hand-rolled because this script is stdlib-only (no PyYAML): it must run in CI and on
    a contributor's machine with nothing installed.
    """
    values = []
    lines = rules_text.splitlines()
    i = 0
    while i < len(lines):
        m = re.match(r"^(\s*)expr:\s*(.*)$", lines[i])
        if not m:
            i += 1
            continue
        indent, rest = len(m.group(1)), m.group(2).strip()
        i += 1
        if rest and rest[0] not in "|>":
            values.append(rest)  # inline scalar
            continue
        # Block scalar: consume the more-indented body (blank lines belong to it).
        while i < len(lines):
            line = lines[i]
            if line.strip() and (len(line) - len(line.lstrip())) <= indent:
                break
            values.append(line)
            i += 1
    return values


def alert_expr_series(rules_text):
    """gdi_* series named in the alert rules' PromQL ``expr:`` fields, and nowhere else.

    A metric mentioned only in a comment or an annotation is not alerted on, and must not
    count as observed for the COVERAGE check below. This is the constraint
    ``dashboard_query_series`` enforces on the dashboard side: scanning the whole file
    would make COVERAGE satisfiable by prose.
    """
    return referenced_series("\n".join(alert_expr_values(rules_text)))


def documented_series(doc_text):
    """gdi_* metrics the runbook's §2 table describes: the backticked name in the first
    cell of a table row inside the ``metric-names`` marker block.

    Scoped, rather than a whole-file ``gdi_*`` scan, for the same reason the §3 alert-name
    check is scoped: a whole-file scan is satisfiable by prose. A metric mentioned in
    passing, in another row's Notes column or in an alert-rule description, would count as
    documented, so the guard would pass for the wrong reason and later go red when that
    prose is reworded.
    """
    start = doc_text.find(METRIC_NAMES_START)
    end = doc_text.find(METRIC_NAMES_END)
    if start == -1 or end == -1 or end < start:
        return None
    block = doc_text[start + len(METRIC_NAMES_START) : end]
    described = set()
    for raw in block.splitlines():
        line = raw.strip()
        if not line.startswith("|"):
            continue
        first_cell = line.split("|")[1].strip()
        m = re.fullmatch(r"`(gdi_[a-z0-9_]+)`", first_cell)
        if m:
            described.add(m.group(1))
    return described


def iter_nodes(node):
    """Yield every dict in a decoded-JSON structure, depth-first, parent before child."""
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from iter_nodes(value)
    elif isinstance(node, list):
        for item in node:
            yield from iter_nodes(item)


def dashboard_query_series(dashboard):
    """gdi_* series in the dashboard's PromQL query fields (``expr``/``query`` on panel
    targets), and nowhere else in the JSON. A metric named only in a panel title or
    description does not count as charted: otherwise a dead panel that renames its query
    but keeps the old name in the title would pass the DRIFT check, and a metric mentioned
    in prose would satisfy COVERAGE without ever being plotted."""
    queries = []
    for node in iter_nodes(dashboard):
        for key in ("expr", "query"):
            value = node.get(key)
            if isinstance(value, str):
                queries.append(value)
    return referenced_series("\n".join(queries))


def alert_names_in_rules(rules_text):
    """Every ``- alert: <Name>`` in the Prometheus rules file: the alerts that exist."""
    return set(
        re.findall(r"^\s*-?\s*alert:\s*([A-Za-z0-9_]+)", rules_text, re.MULTILINE)
    )


def alert_names_in_doc(doc_text):
    """The backticked rule names inside the §3 ``alert-rule-names`` marker block."""
    start = doc_text.find(ALERT_NAMES_START)
    end = doc_text.find(ALERT_NAMES_END)
    if start == -1 or end == -1 or end < start:
        return None
    return set(re.findall(r"`([A-Za-z0-9_]+)`", doc_text[start:end]))


def alert_names_in_doc_table(doc_text):
    """The rule names named by §3's alert-catalogue rows, not by its marker block.

    The marker block is a flat list: it says an alert is documented somewhere in §3, not
    that the operator-facing table has a row for it. A rule can be listed in the block and
    still have no entry an operator could read.

    Each row names its rule in the first cell (``| **Label** (`RuleName`) | … |``), so the
    catalogue can be compared to the rules file directly.
    """
    lines = doc_text.split("\n")
    try:
        start = next(
            i for i, ln in enumerate(lines) if ln.startswith("## 3. Alert thresholds")
        )
    except StopIteration:
        return None
    end = next(
        (i for i in range(start + 1, len(lines)) if lines[i].startswith("## 4.")),
        len(lines),
    )
    names = set()
    for ln in lines[start:end]:
        if not ln.startswith("| **"):
            continue
        m = re.match(r"\|\s*\*\*.+?\*\*\s*\(`([A-Za-z0-9_]+)`\)", ln)
        if m:
            names.add(m.group(1))
    return names


def declared_metric_consts(src):
    """Each ``pub const IDENT: &str = "gdi_..."`` as an ``(IDENT, series_name)`` pair.

    Metrics are emitted through these consts (not the raw string), so the emission check
    resolves the const identifier rather than the ``gdi_*`` literal.
    """
    return re.findall(r'pub const (\w+)\s*:\s*&str\s*=\s*"(gdi_[a-z0-9_]+)"', src)


def emitted_metric_consts(src_blob):
    """Const identifiers that appear as the first argument of an emit macro
    (``counter!`` / ``gauge!`` / ``histogram!``), with or without a ``[crate::]metrics::``
    prefix. The ``(?<![A-Za-z_])`` boundary excludes ``describe_counter!`` and friends,
    which register a metric rather than emit it."""
    return set(
        re.findall(
            r"(?<![A-Za-z_])(?:counter|gauge|histogram)!\s*\(\s*"
            r"(?:(?:crate::)?metrics::)?([A-Z][A-Z0-9_]+)\b",
            src_blob,
        )
    )


def base_name(metric):
    for suffix in HIST_SUFFIXES:
        if metric.endswith(suffix):
            return metric[: -len(suffix)]
    return metric


def alloy_target_labels(alloy_text):
    """Every label an Alloy `discovery.relabel` rule writes (`target_label = "x"`)."""
    return set(
        re.findall(
            r'^\s*target_label\s*=\s*"([A-Za-z_][A-Za-z0-9_]*)"',
            alloy_text,
            re.MULTILINE,
        )
    )


def compose_services(compose_text):
    """Service names under the top-level ``services:`` key.

    Two-space keys, terminated by the next column-0 key, so the ``x-*`` YAML anchors and
    the ``volumes:`` block never leak in.
    """
    out = set()
    in_services = False
    for line in compose_text.splitlines():
        if re.match(r"^services:\s*$", line):
            in_services = True
            continue
        if in_services and re.match(r"^\S", line):
            break
        if in_services:
            m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
            if m:
                out.add(m.group(1))
    return out


def parse_stream_selector(expr):
    """The `{k="v", …}` LogQL stream selector at the head of a query, as a dict."""
    m = re.search(r"\{([^}]*)\}", expr)
    if not m:
        return {}
    return dict(re.findall(r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"]*)"', m.group(1)))


def loki_panels(dashboard):
    """`(title, expr)` for every panel target on a Loki datasource."""
    out = []
    for node in iter_nodes(dashboard):
        ds = node.get("datasource")
        is_loki = isinstance(ds, dict) and ds.get("type") == "loki"
        if is_loki and node.get("targets"):
            for t in node["targets"]:
                if isinstance(t, dict) and isinstance(t.get("expr"), str):
                    out.append((node.get("title", "<untitled>"), t["expr"]))
    return out


def check_log_panels(dashboard, alloy_text, compose_text):
    """Every Loki panel must select on a label that exists and a value that can match.

    The metric checks above guard PromQL series names; this one guards LogQL. A panel
    pinned to a selector that cannot match renders empty forever, which an operator cannot
    tell apart from a quiet node.
    """
    problems = []
    produced = alloy_target_labels(alloy_text)
    services = compose_services(compose_text)

    for title, expr in loki_panels(dashboard):
        selector = parse_stream_selector(expr)
        where = f"log panel {title!r} (`{expr}`)"
        if not selector:
            problems.append(
                f'LOG PANEL: {where} has no `{{label="value"}}` stream selector.'
            )
            continue
        for label in sorted(selector):
            if label not in produced:
                problems.append(
                    f"LOG PANEL: {where} selects on `{label}`, which no relabel rule in "
                    f"{ALLOY.relative_to(ROOT)} produces (it writes: {sorted(produced)}). "
                    "The panel can never match."
                )
            elif label in UNSTABLE_LOG_LABELS:
                problems.append(
                    f"LOG PANEL: {where} selects on `{label}`: {UNSTABLE_LOG_LABELS[label]}. "
                    f"Select on `{REQUIRED_LOG_LABEL}` instead."
                )
        if REQUIRED_LOG_LABEL not in selector:
            problems.append(
                f"LOG PANEL: {where} does not select on `{REQUIRED_LOG_LABEL}`, the only "
                "stable per-container discriminator Alloy emits."
            )
        else:
            value = selector[REQUIRED_LOG_LABEL]
            if value not in services:
                problems.append(
                    f'LOG PANEL: {where} selects `{REQUIRED_LOG_LABEL}="{value}"`, which is '
                    f"not a service in {COMPOSE.relative_to(ROOT)} (it defines: "
                    f"{sorted(services)}). The panel can never match."
                )
    return problems


# --- Presentation checks -------------------------------------------------------------
#
# Everything above checks names. A dashboard can be wrong on a healthy node in ways no name
# check sees: panels sharing a grid cell, a stat tile drawing one box per scrape sample, a
# tile with no threshold steps inheriting Grafana's red-above-80, a panel titled after an
# alert it does not chart, seconds and counts on one axis, and a disk tile whose threshold
# is a second copy of the LowDisk margin. Each check below binds one of those, and each has
# a synthetic red case in the tests, so it is known to fail when its subject breaks.


def top_level_panels(dashboard):
    """The panels Grafana lays out on the grid: every top-level entry, rows included.

    Panels nested under a collapsed row keep stale absolute coordinates and are not laid
    out, so they are not part of the overlap check.
    """
    return [p for p in dashboard.get("panels", []) if isinstance(p, dict)]


def all_panels(dashboard):
    """Every panel, including those nested under a collapsed row."""
    out = []
    for p in top_level_panels(dashboard):
        out.append(p)
        out.extend(q for q in (p.get("panels") or []) if isinstance(q, dict))
    return out


def _title(panel):
    return panel.get("title") or "<untitled>"


def gridpos_overlaps(dashboard):
    """Two laid-out panels sharing any grid cell. Grafana resolves it silently by pushing
    the later one down, and every row below ripples with it."""
    boxes = [
        (_title(p), p["gridPos"])
        for p in top_level_panels(dashboard)
        if isinstance(p.get("gridPos"), dict)
    ]
    problems = []
    for i, (ta, a) in enumerate(boxes):
        for tb, b in boxes[i + 1 :]:
            if (
                a["x"] < b["x"] + b["w"]
                and b["x"] < a["x"] + a["w"]
                and a["y"] < b["y"] + b["h"]
                and b["y"] < a["y"] + a["h"]
            ):
                problems.append(
                    f"LAYOUT: panels {ta!r} (y={a['y']}, x={a['x']}) and {tb!r} "
                    f"(y={b['y']}, x={b['x']}) overlap on the grid."
                )
    return problems


def stat_panels_showing_every_sample(dashboard):
    """A `stat` panel with `reduceOptions.values: true` draws one tile per sample of a
    range query. Legal only when every target is an instant query (one value per
    series)."""
    problems = []
    for p in all_panels(dashboard):
        if p.get("type") != "stat":
            continue
        reduce = (p.get("options") or {}).get("reduceOptions") or {}
        if not reduce.get("values"):
            continue
        targets = [t for t in (p.get("targets") or []) if isinstance(t, dict)]
        if not all(t.get("instant") is True for t in targets):
            problems.append(
                f"STAT: {_title(p)!r} shows every value (`reduceOptions.values: true`) over "
                "a range query, one tile per scrape sample. Use `values: false` with a "
                "reducer, or make every target `instant: true`."
            )
    return problems


#: Panel types whose colour mode is `thresholds` when `fieldConfig.defaults.color` is
#: omitted. That is Grafana's own default for them, so a panel that says nothing is one.
IMPLICIT_THRESHOLD_TYPES = ("stat", "gauge")

#: Base-step colours that paint nothing as a status: what a `noValue` tile may use.
NEUTRAL_COLORS = ("text", "transparent")


def colors_by_thresholds(panel):
    """Whether Grafana colours `panel` by its threshold steps, declared or implied by the
    panel type. A `stat` with no `color` key at all still inherits `[green@null, red@80]`,
    so the type has to imply the mode."""
    defaults = (panel.get("fieldConfig") or {}).get("defaults") or {}
    mode = (defaults.get("color") or {}).get("mode")
    if mode is None:
        return panel.get("type") in IMPLICIT_THRESHOLD_TYPES
    return mode == "thresholds"


def threshold_colored_panels_without_steps(dashboard):
    """`color.mode: thresholds` with no steps falls back to Grafana's default (green, red
    at 80), so an uptime in seconds reads red above 80."""
    problems = []
    for p in all_panels(dashboard):
        defaults = (p.get("fieldConfig") or {}).get("defaults") or {}
        if not colors_by_thresholds(p):
            continue
        steps = (defaults.get("thresholds") or {}).get("steps") or []
        if not steps:
            problems.append(
                f"THRESHOLDS: {_title(p)!r} colours by thresholds but declares no steps, so "
                "Grafana's default `red >= 80` applies to whatever the value is."
            )
    return problems


def novalue_tiles_with_a_status_coloured_base(dashboard):
    """A `stat`/`gauge` that sets `noValue` paints that text with its base threshold step,
    so a green base renders "no token_file" in green and the operator reads "not
    configured" over a file that is configured and unreadable. A tile with a `noValue`
    needs a neutral base (`text`/`transparent`); its status colours start at the first
    real step.
    """
    problems = []
    for p in all_panels(dashboard):
        if p.get("type") not in IMPLICIT_THRESHOLD_TYPES:
            continue
        defaults = (p.get("fieldConfig") or {}).get("defaults") or {}
        if defaults.get("noValue") is None or not colors_by_thresholds(p):
            continue
        steps = (defaults.get("thresholds") or {}).get("steps") or []
        base = next((s for s in steps if s.get("value") is None), None)
        if base is None or base.get("color") in NEUTRAL_COLORS:
            continue
        problems.append(
            f"NOVALUE: {_title(p)!r} sets noValue={defaults['noValue']!r} but its base "
            f"threshold step is {base.get('color')!r}. Grafana paints the noValue text with "
            "the base step, so absent data reads as that status. Use a neutral base "
            f"({'/'.join(NEUTRAL_COLORS)}) and colour from the first real step."
        )
    return problems


def alert_exprs_by_name(rules_text):
    """``{alert name: set of gdi_* series its expr queries}`` for every rule."""
    out = {}
    chunks = re.split(r"^\s*-\s*alert:\s*", rules_text, flags=re.MULTILINE)
    for chunk in chunks[1:]:
        name = chunk.split(None, 1)[0].strip()
        out[name] = referenced_series("\n".join(alert_expr_values(chunk)))
    return out


def panel_query_series(panel):
    exprs = [
        t.get("expr")
        for t in (panel.get("targets") or [])
        if isinstance(t, dict) and isinstance(t.get("expr"), str)
    ]
    return referenced_series("\n".join(exprs))


def alert_named_panels_missing_series(dashboard, rules_text):
    """A panel whose title names an alert must query every series that alert's `expr`
    queries. A panel titled after an alert but charting a neighbouring metric leaves the
    alert's own series uncharted, which COVERAGE cannot see because it accepts "alerted"
    as observed."""
    alerts = alert_exprs_by_name(rules_text)
    problems = []
    for p in all_panels(dashboard):
        title = _title(p)
        charted = {base_name(s) for s in panel_query_series(p)}
        for name, series in alerts.items():
            if not re.search(rf"\b{re.escape(name)}\b", title):
                continue
            missing = sorted({base_name(s) for s in series} - charted)
            if missing:
                problems.append(
                    f"ALERT PANEL: {title!r} names {name} but does not chart the series that "
                    f"alert keys on: {missing}."
                )
    return problems


def unit_class(expr):
    """Which axis an expression belongs on: `seconds`, `bytes`, `rate` (a per-window or
    per-second count) or `count`. Approximate: it needs to separate a seconds-valued line
    from a count on the same axis, not to type PromQL."""
    if "histogram_quantile(" in expr:
        if "_seconds_bucket" in expr:
            return "seconds"
        if "_bytes_bucket" in expr:
            return "bytes"
        return "count"
    if re.search(r"\b(?:rate|irate|increase)\(", expr):
        if "_seconds_sum" in expr:
            return "seconds"
        if "_bytes_sum" in expr:
            return "bytes"
        return "rate"
    if "time()" in expr:
        return "seconds"
    names = re.findall(r"\b(?:gdi_[a-z0-9_]+|probe_success|up)\b", expr)
    if any(n.endswith("_seconds") for n in names):
        return "seconds"
    if any(n.endswith("_bytes") for n in names):
        return "bytes"
    return "count"


def mixed_unit_panels(dashboard):
    """A `timeseries` panel whose targets belong on different axes. An axis carries one
    unit, and a per-second rate beside a small count, or an age in seconds beside a queue
    depth, flattens the smaller series into the baseline. Split the panel instead."""
    problems = []
    for p in all_panels(dashboard):
        if p.get("type") != "timeseries":
            continue
        classes = {}
        for t in p.get("targets") or []:
            if isinstance(t, dict) and isinstance(t.get("expr"), str):
                classes.setdefault(
                    unit_class(t["expr"]), t.get("legendFormat") or t["expr"]
                )
        if len(classes) > 1:
            problems.append(
                f"UNITS: {_title(p)!r} puts {sorted(classes)} on one axis "
                f"(e.g. {' vs '.join(repr(v) for v in classes.values())}). One unit per "
                "axis; split the panel."
            )
    return problems


def disk_threshold_mismatch(dashboard, rules_text):
    """The disk tile's warning step must be the `LowDisk` margin, not a copy of it."""
    m = re.search(r"gdi_disk_free_bytes\s*<\s*([0-9.eE+]+)", rules_text)
    if not m:
        return [
            (
                "DISK THRESHOLD: no `gdi_disk_free_bytes < N` expression in the rules "
                "file, so the tile's steps cannot be checked against the LowDisk margin."
            )
        ]
    margin = float(m.group(1))
    problems = []
    for p in all_panels(dashboard):
        if "gdi_disk_free_bytes" not in panel_query_series(p):
            continue
        defaults = (p.get("fieldConfig") or {}).get("defaults") or {}
        steps = (defaults.get("thresholds") or {}).get("steps") or []
        values = [s.get("value") for s in steps if s.get("value") is not None]
        if margin not in [float(v) for v in values]:
            problems.append(
                f"DISK THRESHOLD: {_title(p)!r} has threshold steps {values}, none of which "
                f"is the LowDisk margin {margin:g} from the rules file."
            )
    return problems


def check_presentation(dashboard, rules_text):
    """All seven presentation checks, in one list."""
    return (
        gridpos_overlaps(dashboard)
        + stat_panels_showing_every_sample(dashboard)
        + threshold_colored_panels_without_steps(dashboard)
        + novalue_tiles_with_a_status_coloured_base(dashboard)
        + alert_named_panels_missing_series(dashboard, rules_text)
        + mixed_unit_panels(dashboard)
        + disk_threshold_mismatch(dashboard, rules_text)
    )


def main():
    # All of these are required, not best-effort. Behind an `is_file()` guard, deleting or
    # renaming one would remove the alert-doc parity check or the whole log-panel check
    # while the script still printed ok.
    for path in (DASHBOARD, METRICS_RS, RULES, ALLOY, COMPOSE):
        if not path.is_file():
            print(
                f"error: missing {path}. The check that reads it cannot run, and "
                "skipping it would report success having verified less than it claims",
                file=sys.stderr,
            )
            return 2

    declared = declared_metric_names(METRICS_RS.read_text())
    if not declared:
        print(f"error: no gdi_* metric names found in {METRICS_RS}", file=sys.stderr)
        return 2

    rules_text = RULES.read_text()  # required; see the presence loop in main()
    record_names = recording_rule_names(rules_text)
    resolvable = declared | record_names

    charted = dashboard_query_series(json.loads(DASHBOARD.read_text()))
    alerted = alert_expr_series(rules_text)

    problems = []

    def unresolved(series):
        return sorted(
            m for m in series if m not in resolvable and base_name(m) not in resolvable
        )

    # 1. DRIFT — dashboard and alert-rule series that resolve to no declared metric.
    # promtool validates the rules' PromQL syntax but never that a metric exists, so a
    # renamed or removed metric survives it in both files; this catches it.
    for kind, path, bad in (
        ("DASHBOARD", DASHBOARD, unresolved(charted)),
        ("RULES", RULES, unresolved(alerted)),
    ):
        if bad:
            problems.append(
                f"{kind} DRIFT: {len(bad)} series in {path.relative_to(ROOT)} have no "
                f"matching metric in {METRICS_RS.relative_to(ROOT)}:\n"
                + "\n".join(f"  - {m}" for m in bad)
                + "\n  A metric was likely renamed or removed in metrics.rs; update "
                "that file, or fix the typo in the panel or rule."
            )

    # 2. COVERAGE — declared metrics observed nowhere.
    observed = {base_name(m) for m in charted | alerted}
    unobserved = sorted(m for m in declared if m not in observed)
    if unobserved:
        problems.append(
            f"COVERAGE: {len(unobserved)} declared metric(s) are neither charted nor "
            "alerted:\n"
            + "\n".join(f"  - {m}" for m in unobserved)
            + "\n  Chart it on the dashboard, reference it from an alert rule, or "
            "delete the metric. There is no prose escape hatch."
        )

    # 3. ALERT-DOC PARITY — the runbook's §3 rule-name list must equal the rules file's
    # `alert:` set. Catches an alert added, removed or renamed in the rules yml but not
    # reflected in docs/operating.md §3. promtool never reads the runbook.
    doc_text = OPERATING_MD.read_text() if OPERATING_MD.is_file() else ""
    rules_alerts = alert_names_in_rules(rules_text)
    doc_alerts = alert_names_in_doc(doc_text)
    if doc_alerts is None:
        problems.append(
            f"ALERT-DOC PARITY: the `alert-rule-names` marker block "
            f"({ALERT_NAMES_START} … {ALERT_NAMES_END}) is missing from "
            f"{OPERATING_MD.relative_to(ROOT)} §3. Restore it: it pins the runbook's "
            "alert list to the rules file."
        )
    elif rules_alerts and doc_alerts != rules_alerts:
        missing_in_doc = sorted(rules_alerts - doc_alerts)
        stale_in_doc = sorted(doc_alerts - rules_alerts)
        lines = []
        if missing_in_doc:
            lines.append(
                "  alerts in the rules file but not in the §3 runbook list (document them):\n"
                + "\n".join(f"    - {a}" for a in missing_in_doc)
            )
        if stale_in_doc:
            lines.append(
                "  names in the §3 runbook list with no matching alert (remove or rename):\n"
                + "\n".join(f"    - {a}" for a in stale_in_doc)
            )
        problems.append(
            f"ALERT-DOC DRIFT: {RULES.relative_to(ROOT)} `alert:` set and the §3 "
            f"rule-name list in {OPERATING_MD.relative_to(ROOT)} disagree:\n"
            + "\n".join(lines)
        )

    # 3b. ALERT-TABLE PARITY — every shipped alert needs a row an operator can read, not
    # just an entry in the flat marker list, which the check above cannot tell apart.
    table_alerts = alert_names_in_doc_table(doc_text)
    if table_alerts is None:
        problems.append(
            f"ALERT-TABLE PARITY: no `## 3. Alert thresholds` section found in "
            f"{OPERATING_MD.relative_to(ROOT)}, so the catalogue check is blind."
        )
    elif rules_alerts and table_alerts != rules_alerts:
        no_row = sorted(rules_alerts - table_alerts)
        no_rule = sorted(table_alerts - rules_alerts)
        lines = []
        if no_row:
            lines.append(
                "  shipped alerts with no row in the §3 catalogue (add one; an operator\n"
                "  reads the table, not the marker list):\n"
                + "\n".join(f"    - {a}" for a in no_row)
            )
        if no_rule:
            lines.append(
                "  §3 rows naming an alert that does not exist (remove/rename them):\n"
                + "\n".join(f"    - {a}" for a in no_rule)
            )
        problems.append(
            f"ALERT-TABLE PARITY: the §3 catalogue rows in "
            f"{OPERATING_MD.relative_to(ROOT)} do not match {RULES.relative_to(ROOT)}:\n"
            + "\n".join(lines)
        )

    # 4. METRIC-DOC COVERAGE — every declared metric must be documented in the operators'
    # runbook (§2 "Reading the metrics"). The COVERAGE check above only says a metric is
    # charted or alerted; this one says it is described for a human operator.
    doc_series = documented_series(doc_text)
    if doc_series is None:
        problems.append(
            f"METRIC-DOC COVERAGE: {OPERATING_MD.relative_to(ROOT)} §2 lost its "
            f"`{METRIC_NAMES_START}` / `{METRIC_NAMES_END}` markers — restore them (they "
            "scope the doc-coverage check to the metrics table, so prose elsewhere in the "
            "runbook cannot satisfy it)"
        )
    else:
        undocumented = sorted(m for m in declared if m not in doc_series)
        if undocumented:
            problems.append(
                f"METRIC-DOC COVERAGE: {len(undocumented)} declared metric(s) have no row "
                f"in the {OPERATING_MD.relative_to(ROOT)} §2 metrics table (a passing "
                "mention elsewhere in the runbook does not count):\n"
                + "\n".join(f"  - {m}" for m in undocumented)
            )
        stale = sorted(m for m in doc_series if m not in declared)
        if stale:
            problems.append(
                f"METRIC-DOC DRIFT: {len(stale)} metric(s) documented in the "
                f"{OPERATING_MD.relative_to(ROOT)} §2 table are not declared in "
                f"{METRICS_RS.relative_to(ROOT)} (remove or rename the row):\n"
                + "\n".join(f"  - {m}" for m in stale)
            )

    # 5. EMISSION — every declared metric must have at least one emit call site
    # (counter!/gauge!/histogram!) in the node source. Checks 1-4 say a metric is declared,
    # charted, alerted and documented; none of them says it is written. A deleted emit on a
    # still-alerted metric passes them all and leaves a critical alert at no-data. Metrics
    # are emitted via their const as the macro's first arg (the helper fns in metrics.rs
    # count). An emit that exists only in test code is not distinguished here; this catches
    # a metric with no emit macro at all.
    src_blob = "".join(p.read_text() for p in sorted(SRC_DIR.rglob("*.rs")))
    emitted = emitted_metric_consts(src_blob)
    never_emitted = sorted(
        name
        for (ident, name) in declared_metric_consts(METRICS_RS.read_text())
        if ident not in emitted
    )
    if never_emitted:
        problems.append(
            f"EMISSION: {len(never_emitted)} declared metric(s) have no counter!/gauge!/"
            f"histogram! emit site under {SRC_DIR.relative_to(ROOT)} (declared but never "
            "fired — a deleted emit, or a describe-only registration):\n"
            + "\n".join(f"  - {m}" for m in never_emitted)
        )

    # 6. LOG PANELS — a Loki panel's stream selector must use a label Alloy actually
    # emits, must not use an unstable one, and must name a real Compose service. Checks
    # 1-5 cover PromQL series names; nothing covered LogQL, and a selector that can never
    # match renders an empty panel that is indistinguishable from a quiet node.
    dashboard_json = json.loads(DASHBOARD.read_text())
    # Unconditional: both files are asserted present in the loop at the top of main().
    problems.extend(
        check_log_panels(dashboard_json, ALLOY.read_text(), COMPOSE.read_text())
    )

    # 7. PRESENTATION — layout, chart form and units. Checks 1-6 are about names, and a
    # dashboard whose names all resolve can still be unreadable.
    problems.extend(check_presentation(dashboard_json, rules_text))

    if problems:
        print("\n\n".join(problems), file=sys.stderr)
        return 1

    n_logs = len(loki_panels(dashboard_json))
    n_panels = sum(1 for p in all_panels(dashboard_json) if p.get("type") != "row")
    print(
        f"ok: {len(charted)} charted series resolve; all {len(declared)} declared "
        f"metrics are observed (charted/alerted) and documented; "
        f"{len(rules_alerts)} alert rules match the §3 runbook list; "
        f"{n_logs} log panel(s) select a label Alloy emits on a real Compose service; "
        f"{n_panels} panels pass the layout / stat / threshold / alert-title / unit / "
        "disk-margin checks."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
