#!/usr/bin/env python3
"""Leak-trend check for scripts/soak/leak.sh.

Reads the `round\trss_kb\tfds\tthreads` TSV the soak writes and decides whether the node
process is leaking. A soak has to tell a genuine leak (a sustained upward trend that
never plateaus) apart from healthy cache fill (grows during warmup, then flat).

Rules, all applied after dropping the first `warmup` rounds. All three series use the same
middle-third-versus-last-third plateau test, so a warmup ramp that then flattens is not
mistaken for a leak:
  * open fds: the last-third mean must not exceed the middle-third mean by more than
    SOAK_FD_TOL, an absolute count. A sustained climb is an fd leak.
  * thread count: the same, with SOAK_THREAD_TOL, for a task or thread leak.
  * RSS: the last-third mean must not exceed the middle-third mean by more than
    SOAK_RSS_PLATEAU_FRAC, a fraction, since RSS is not a small integer count.
A leak keeps climbing through the last third; a healthy process is flat across the middle
and last thirds even if it grew during warmup.

Exit 0 = healthy, 1 = leak suspected, 2 = usage / not enough samples.
Thresholds are lenient by default (this is advisory); tighten via env for a long run.
"""

import os
import sys


def mean(xs):
    return sum(xs) / len(xs) if xs else 0.0


#: The plateau test splits the series in thirds, so it is meaningless below this many
#: post-warmup samples. `_thirds` returns None below it, and `main` refuses to render a
#: verdict below it rather than printing PASS having asserted nothing.
MIN_SAMPLES = 6


def _thirds(series):
    """(middle-third mean, last-third mean) for a plateau comparison, or None when there
    are fewer than MIN_SAMPLES samples."""
    if len(series) < MIN_SAMPLES:
        return None
    third = len(series) // 3
    return mean(series[third : 2 * third]), mean(series[2 * third :])


def leak_failures(rss, fds, threads, fd_tol, thread_tol, rss_plateau_frac):
    """The leak-trend verdict over already-post-warmup series: a list of failure strings,
    empty when healthy. All three use the same plateau shape; fds and threads compare an
    absolute count excess, RSS a fractional one."""
    failures = []
    for name, series, tol, unit in (
        ("open fds", fds, fd_tol, "fd"),
        ("threads", threads, thread_tol, "thread/task"),
    ):
        t = _thirds(series)
        if t is not None:
            m_mid, m_last = t
            if m_last - m_mid > tol:
                failures.append(
                    f"{name} still climbing after warmup: middle-third mean {m_mid:.0f} -> "
                    f"last-third mean {m_last:.0f} (+{m_last - m_mid:.0f} > tol {tol}); {unit} leak"
                )
    t = _thirds(rss)
    if t is not None:
        m_mid, m_last = t
        if m_mid > 0 and (m_last - m_mid) / m_mid > rss_plateau_frac:
            failures.append(
                f"RSS still climbing after warmup: middle-third mean {m_mid:.0f}KB -> "
                f"last-third mean {m_last:.0f}KB (+{100 * (m_last - m_mid) / m_mid:.1f}% > "
                f"{100 * rss_plateau_frac:.0f}%); memory leak suspected"
            )
    return failures


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: checks.py <samples.tsv> [warmup]", file=sys.stderr)
        return 2
    warmup = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    fd_tol = int(os.environ.get("SOAK_FD_TOL", "8"))
    thread_tol = int(os.environ.get("SOAK_THREAD_TOL", "4"))
    rss_plateau_frac = float(os.environ.get("SOAK_RSS_PLATEAU_FRAC", "0.10"))

    rows = []
    with open(sys.argv[1]) as fh:
        fh.readline()  # skip the header row
        for line in fh:
            parts = line.split()
            if len(parts) < 4:
                continue
            rows.append(tuple(int(p) for p in parts[:4]))

    measured = [r for r in rows if r[0] > warmup]

    # Fail rather than note-and-continue. Below MIN_SAMPLES every `_thirds` returns None,
    # no failures are collected and the run would print PASS, making an empty or truncated
    # samples file indistinguishable from a clean soak. Exit 2, not 1: this is the
    # "not enough samples" case the docstring defines, not a suspected leak.
    #
    # SOAK_ALLOW_SHORT opts out for a short smoke run. It defaults off and prints what it
    # skipped, because an env var that can weaken a guard must stay explicit and visible.
    if len(measured) < MIN_SAMPLES:
        msg = (
            f"only {len(measured)} measured round(s) after warmup={warmup}; the plateau "
            f"test needs at least {MIN_SAMPLES}. Raise SOAK_ROUNDS or lower SOAK_WARMUP."
        )
        if os.environ.get("SOAK_ALLOW_SHORT") != "1":
            print(
                f"FAIL: {msg} Refusing to report a verdict from too few samples "
                f"(set SOAK_ALLOW_SHORT=1 to run it as a smoke test anyway).",
                file=sys.stderr,
            )
            return 2
        print(
            f"NOTE: {msg} SOAK_ALLOW_SHORT=1 is set, so trend assertions are skipped.",
            file=sys.stderr,
        )
        measured = measured or rows

    rss = [r[1] for r in measured]
    fds = [r[2] for r in measured]
    threads = [r[3] for r in measured]

    # A node that died mid-soak reads as all-zeros rather than as an error: leak.sh
    # samples /proc/<pid>/ and falls back to 0 once the process is gone, and a flat zero
    # series passes every plateau test. A live process always has non-zero RSS and fds.
    if not any(rss) or not any(fds):
        print(
            "FAIL: every RSS or fd sample is 0. The node process was not running for "
            "these rounds, so the trend was measured against nothing.",
            file=sys.stderr,
        )
        return 1

    failures = leak_failures(rss, fds, threads, fd_tol, thread_tol, rss_plateau_frac)

    # Report the plateau shape of each series (informational).
    for name, series, unit in (
        ("RSS", rss, "KB"),
        ("fds", fds, ""),
        ("threads", threads, ""),
    ):
        t = _thirds(series)
        if t is not None:
            print(f"{name}: middle-third {t[0]:.0f}{unit}, last-third {t[1]:.0f}{unit}")

    if failures:
        for f in failures:
            print(f"FAIL: {f}", file=sys.stderr)
        return 1
    print("PASS: no fd/thread/memory leak signal")
    return 0


if __name__ == "__main__":
    sys.exit(main())
