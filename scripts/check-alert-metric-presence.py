#!/usr/bin/env python3
"""Guard: every metric a Prometheus alert rule keys on must be exported by a live node.

A series that is never emitted cannot exceed a threshold, so an alert on it is dead in
every state, healthy included. Nothing else sees that. ``check-dashboard-metrics.py``
compares the rules against the metric names declared in ``metrics.rs``, and
``promtool check rules`` validates PromQL syntax without resolving any name. The gap is
between declared and exported, and only a real scrape closes it.

The input is therefore a scrape of a booted node, taken by
``scripts/e2e/run-observability.sh``. An in-process registry cannot stand in for it:
gauges written by ``IngestRuntime::start`` and ``metrics::sample_once`` are absent until
a real boot runs them.

``--expect-absent NAME=REASON`` is enforced both ways. A metric may be legitimately absent
because the node under test does not configure its subsystem (a lite node exports no
``gdi_vault_*``), so the caller names it with a reason. An expect-absent metric that turns
out to be present is also an error, so an exemption cannot outlive its condition.

That bounds the guard's reach: the observability e2e boots a lite node, so the series
that only a fully configured node exports (``gdi_s3_*``, the Vault gauges with no zero
seed, the PME series) are exempted there and checked only on a node that configures them.
"""

import argparse
import pathlib
import re
import sys

#: A metric name inside an `expr:`.
METRIC = re.compile(r"\bgdi_[a-z0-9_]+")

#: Histogram/summary suffixes that decorate a base series name.
SUFFIXES = ("_bucket", "_sum", "_count")


def base_name(name: str) -> str:
    """Fold a histogram/summary suffix back to the base series name."""
    for suffix in SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def alerted_metrics(rules_text: str) -> set[str]:
    """Every `gdi_*` metric named in an alert rule's `expr:`.

    Reads `expr:` values only. A name in a rule comment or in an `annotations.summary`
    does not make an alert depend on it, and counting those would let this guard pass for
    the wrong reason, then fail later when someone rewords a sentence.

    The value is the whole YAML scalar, not the rest of the `expr:` line. A block scalar
    (`expr: |` / `expr: >`) and a plain scalar continued on the next line both put the
    PromQL on the lines below, indented deeper than the key. This file is stdlib-only,
    since a pre-commit-path test imports it and must not need PyYAML, so the continuation
    rule is spelled out: every following line indented deeper than the key, blank lines
    included, which is what YAML does for both scalar forms.
    """
    found: set[str] = set()
    lines = rules_text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.lstrip()
        i += 1
        if not stripped.startswith("expr:"):
            continue
        indent = len(line) - len(stripped)
        parts = [stripped[len("expr:") :]]
        while i < len(lines) and (
            not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > indent
        ):
            parts.append(lines[i])
            i += 1
        found.update(base_name(m) for m in METRIC.findall(" ".join(parts)))
    return found


def exported_metrics(scrape_text: str) -> set[str]:
    """Every base series name present in a Prometheus text-format scrape.

    Skips `#` HELP/TYPE lines: a `# TYPE` line is emitted by `describe_*!` alone, with no
    sample behind it, so counting it would read a registered-but-never-emitted metric as
    exported.
    """
    found: set[str] = set()
    for line in scrape_text.splitlines():
        if not line or line.startswith("#"):
            continue
        name = re.split(r"[{ ]", line, maxsplit=1)[0]
        if name:
            found.add(base_name(name))
    return found


def parse_expect_absent(entries: list[str]) -> dict[str, str]:
    """`name=reason` pairs. The reason is mandatory: an unexplained exemption cannot be
    re-checked later."""
    out: dict[str, str] = {}
    for entry in entries:
        name, sep, reason = entry.partition("=")
        if not sep or not reason.strip():
            raise SystemExit(
                f"--expect-absent needs `name=reason`, got {entry!r}; an exemption without "
                "a stated reason cannot be re-checked later"
            )
        out[name.strip()] = reason.strip()
    return out


def check(
    rules_text: str, scrape_text: str, expect_absent: dict[str, str]
) -> list[str]:
    """Return the list of problems; empty means pass."""
    alerted = alerted_metrics(rules_text)
    if len(alerted) < 20:
        return [
            (
                f"parsed only {len(alerted)} alerted metrics from the rules file. The "
                "extractor is probably broken, and a guard that checks nothing passes "
                "silently."
            )
        ]
    exported = exported_metrics(scrape_text)
    problems = []

    stale = sorted(n for n in expect_absent if n in exported)
    for name in stale:
        problems.append(
            f"{name}: listed in --expect-absent ({expect_absent[name]}) but IS exported. "
            "Drop the exemption; it is now hiding a real check."
        )

    unknown = sorted(n for n in expect_absent if n not in alerted)
    for name in unknown:
        problems.append(
            f"{name}: listed in --expect-absent but no alert rule references it. The "
            "exemption is dead weight."
        )

    missing = sorted(n for n in alerted if n not in exported and n not in expect_absent)
    for name in missing:
        problems.append(
            f"{name}: backs an alert rule but is not exported, so the alert can never "
            "fire; a series that is never emitted cannot exceed a threshold. Seed it at "
            "boot with metrics::seed_always_present, or drop the alert."
        )
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rules", required=True, type=pathlib.Path)
    ap.add_argument(
        "--scrape",
        required=True,
        help="a file holding a Prometheus text-format scrape, or `-` for stdin",
    )
    ap.add_argument(
        "--expect-absent",
        action="append",
        default=[],
        metavar="NAME=REASON",
        help="a metric this particular node is not expected to export, and why",
    )
    args = ap.parse_args()

    rules_text = args.rules.read_text(encoding="utf-8")
    scrape_text = (
        sys.stdin.read()
        if args.scrape == "-"
        else pathlib.Path(args.scrape).read_text(encoding="utf-8")
    )
    expect_absent = parse_expect_absent(args.expect_absent)

    problems = check(rules_text, scrape_text, expect_absent)
    alerted = alerted_metrics(rules_text)
    # Say what was skipped and why: a guard that narrows its own scope silently reads as
    # "everything is covered" when it is not.
    for name, reason in sorted(expect_absent.items()):
        print(f"skip: {name} — {reason}")
    if problems:
        print(
            f"FAIL: {len(problems)} problem(s) across {len(alerted)} alerted metrics",
            file=sys.stderr,
        )
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print(
        f"ok: all {len(alerted) - len(expect_absent)} in-scope alerted metrics are exported "
        f"({len(expect_absent)} skipped)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
