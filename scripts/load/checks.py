#!/usr/bin/env python3
"""Pass/fail assertions for the load harness (``scripts/load/run.sh``).

They live here, rather than in inline heredocs, so they can be unit-tested.

Both checks read ``statusCodeDistribution`` from oha's ``--output-format json`` report.
Both fail closed when that map is missing or empty. A run whose only outcomes were
transport errors, which oha records under ``errorDistribution``, or an oha schema change,
must turn the harness red rather than print OK having observed nothing.

Usage::

    python3 scripts/load/checks.py baseline   <report.json>
    python3 scripts/load/checks.py saturation <report.json>

Exit: 0 = assertion held, 1 = assertion failed, 2 = usage. Pure stdlib.
"""

from __future__ import annotations

import json
import sys

_NO_CODES = "no status codes in the report (empty or absent statusCodeDistribution)"


def _codes(report):
    """The status-code histogram as ``{code: count}``, counts coerced to int."""
    raw = report.get("statusCodeDistribution") or {}
    return {str(k): int(v) for k, v in raw.items()}


def _has_observations(codes):
    """True when the histogram recorded at least one response (else fail closed)."""
    return bool(codes) and any(codes.values())


def _summary(report):
    rps = report.get("summary", {}).get("requestsPerSec")
    p99 = report.get("latencyPercentiles", {}).get("p99")
    bits = []
    if rps is not None:
        bits.append(f"{rps:.0f} rps")
    if p99 is not None:
        bits.append(f"p99={p99 * 1000:.1f} ms")
    return ", ".join(bits)


def check_baseline(report):
    """Under the concurrency limit, every response must be 2xx.

    Returns ``(ok, message)``. Fails when the distribution is empty/absent, when no 2xx
    was actually observed, or when any non-2xx appears.
    """
    codes = _codes(report)
    if not _has_observations(codes):
        return False, f"baseline: {_NO_CODES}; cannot conclude 'all 2xx'"
    two_xx = sum(v for k, v in codes.items() if k.startswith("2"))
    if two_xx == 0:
        return False, f"baseline: zero 2xx responses observed, codes={codes}"
    non_2xx = {k: v for k, v in codes.items() if not k.startswith("2") and v}
    if non_2xx:
        return False, (
            f"baseline (under the concurrency limit) had non-2xx responses: {non_2xx}"
        )
    return True, f"baseline all-2xx ({two_xx} requests)"


def check_saturation(report):
    """Over the concurrency limit, the load-shed arm must return at least one 503."""
    codes = _codes(report)
    if not _has_observations(codes):
        return False, f"saturation: {_NO_CODES}; cannot conclude the shed arm tripped"
    shed = codes.get("503", 0)
    if shed <= 0:
        return False, (
            f"expected the load-shed arm to return >=1 503 under saturation, got {codes}"
        )
    return True, f"load-shed tripped ({shed}x 503)"


def main(argv):
    if len(argv) != 3 or argv[1] not in ("baseline", "saturation"):
        print(f"usage: {argv[0]} baseline|saturation <report.json>", file=sys.stderr)
        return 2
    with open(argv[2], encoding="utf-8") as fh:
        report = json.load(fh)

    summary = _summary(report)
    print(f"  {argv[1]}: {summary}, codes={_codes(report)}")

    check = check_baseline if argv[1] == "baseline" else check_saturation
    ok, message = check(report)
    if not ok:
        print(f"FAIL: {message}", file=sys.stderr)
        return 1
    print(f"  OK: {message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
