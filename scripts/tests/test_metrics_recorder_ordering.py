#!/usr/bin/env python3
"""Guard: no `metrics::` write in `run()` (the startup orchestration) may precede the recorder
install (`metrics::install_recorder`).

`metrics::` is a no-op until a recorder is installed. A write that runs before the install
lands on nothing, and the series is then absent for the life of the process rather than
zero. Every alert written as `<series> > 0` sits green forever, because a series that is
never emitted cannot exceed anything. The absence of a gauge or counter looks exactly like
"nothing happened yet", so the ordering is invisible in a green run.

Fixing this one call site at a time does not hold: the next boot-time gauge reintroduces
it and nothing fails. The install belongs before every write, and this guard keeps it
there.

The check is on source order rather than at runtime, because reproducing the failure needs
a booted node in a specific degraded posture: a replaced Transit key, an orphaned channel.
"""

import re
import unittest

from _helpers import REPO_ROOT

MAIN_RS = REPO_ROOT / "crates" / "gdi-node-standalone" / "src" / "main.rs"

#: The install call this guard anchors on. Matched as a prefix, so the argument list may
#: grow without breaking the anchor.
INSTALL_CALL = "metrics::install_recorder("

#: A `metrics::` write. Matches both the bare path (`metrics::foo(`) and the crate-
#: qualified one (`gdi_node_standalone::metrics::foo(`), which main.rs uses in both forms.
#:
#: `[!(]` rather than `(` alone, so a direct `metrics`-crate macro (`metrics::gauge!(…)`,
#: `metrics::counter!(…)`) is caught too. main.rs writes only through this crate's own
#: typed helper functions, so the macro arm matches nothing today; it covers the form a
#: later edit would reach for.
METRICS_WRITE = re.compile(r"\bmetrics::[a-z_][a-z0-9_]*\s*[!(]")


def _strip_comment(line: str) -> str:
    """Drop a trailing `//` comment. Crude but sufficient: main.rs has no `//` in a string
    literal on a line that also calls `metrics::`, and a false positive here only makes
    the guard stricter, never lets a real write through."""
    return line.split("//", 1)[0]


#: A function definition, at any indentation: `fn name(`, `pub async fn name<`, ...
FN_DEF = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([a-z_][a-z0-9_]*)\s*[<(]"
)
#: A call by name. Also matches a method call (`state.load(`), which can only make the
#: guard stricter, but not a path-qualified one (`preflight::run(`): that names another
#: module's function, and reading it as main.rs's own `run` would make the orchestrator a
#: writer callee of every function that calls any `::run(`.
CALL = re.compile(r"(?<![:\w])([a-z_][a-z0-9_]*)\s*\(")


def function_regions(lines: list[str]) -> dict[str, tuple[int, int]]:
    """`name -> (start, end)` line indices; a function's region runs to the next `fn`."""
    defs = [
        (i, m.group(1))
        for i, ln in enumerate(lines)
        if (m := FN_DEF.match(_strip_comment(ln)))
    ]
    regions: dict[str, tuple[int, int]] = {}
    for k, (start, name) in enumerate(defs):
        end = defs[k + 1][0] if k + 1 < len(defs) else len(lines)
        regions.setdefault(name, (start, end))
    return regions


def _callees(lines: list[str], region: tuple[int, int]) -> set[str]:
    """Names called from a function body (its own `fn` line excluded)."""
    s, e = region
    return {
        c
        for ln in lines[s + 1 : e]
        for c in CALL.findall(_strip_comment(ln))
        if not FN_DEF.match(_strip_comment(ln))
    }


def metrics_writers(
    lines: list[str],
    regions: dict[str, tuple[int, int]],
    exclude: set[str] = frozenset(),
) -> set[str]:
    """Every function that writes `metrics::`, directly or through a function that does.

    The relation is closed transitively: a helper that calls a writer is a writer. Grepping
    `run`'s pre-install lines for a literal `metrics::` plus a hand-named helper misses the
    next helper added before the install. `exclude` is the orchestrator itself, which
    writes after the install; treating it as a writer would make every caller of anything
    named like it one too.
    """
    writers = {
        name
        for name, (s, e) in regions.items()
        if name not in exclude
        and any(METRICS_WRITE.search(_strip_comment(ln)) for ln in lines[s:e])
    }
    changed = True
    while changed:
        changed = False
        for name, region in regions.items():
            if name in writers or name in exclude:
                continue
            if _callees(lines, region) & writers:
                writers.add(name)
                changed = True
    return writers


def offenders_before_install(lines: list[str]) -> list[tuple[int, str]]:
    """`(line number, text)` for every write or writer-call in `run` before the install."""
    installs = [i for i, ln in enumerate(lines) if INSTALL_CALL in _strip_comment(ln)]
    if len(installs) != 1:
        raise AssertionError(
            f"expected exactly one `{INSTALL_CALL}` call site, found {len(installs)}"
        )
    install = installs[0]
    regions = function_regions(lines)
    enclosing = [n for n, (s, e) in regions.items() if s <= install < e]
    if len(enclosing) != 1:
        raise AssertionError("could not find the function enclosing the install call")
    run_name = enclosing[0]
    start = regions[run_name][0]
    writers = metrics_writers(lines, regions, exclude={run_name})
    out = []
    for i in range(start, install):
        code = _strip_comment(lines[i])
        if METRICS_WRITE.search(code) or (set(CALL.findall(code)) & writers):
            out.append((i + 1, lines[i].strip()))
    return out


class MetricsRecorderOrdering(unittest.TestCase):
    def setUp(self) -> None:
        self.assertTrue(MAIN_RS.is_file(), f"{MAIN_RS} not found; the crate moved")
        self.lines = MAIN_RS.read_text(encoding="utf-8").splitlines()

    def _install_line(self) -> int:
        hits = [
            i for i, ln in enumerate(self.lines) if INSTALL_CALL in _strip_comment(ln)
        ]
        self.assertEqual(
            len(hits),
            1,
            f"expected exactly one `{INSTALL_CALL}` call site in main.rs, found {len(hits)}"
            "; this guard anchors on it, so update the anchor if it moved",
        )
        return hits[0]

    def _enclosing_fn_line(self, idx: int) -> int:
        """The nearest preceding top-level `fn`: the function the install sits in."""
        for i in range(idx, -1, -1):
            if re.match(r"^(pub )?(async )?fn ", self.lines[i]):
                return i
        self.fail("could not find the function enclosing the install call")
        raise AssertionError  # unreachable; keeps the checker happy

    def test_install_precedes_every_metrics_write_in_its_function(self) -> None:
        offenders = offenders_before_install(self.lines)
        self.assertEqual(
            offenders,
            [],
            "these `metrics::` writes, or calls to functions in main.rs that write, run "
            "before `install_metrics` and will land on no recorder: the series is "
            "silently absent for the life of the process, and any `> 0` alert over it "
            "can never fire:\n"
            + "\n".join(f"  main.rs:{n}: {t}" for n, t in offenders)
            + "\nMove the write after the install, or move the install earlier.",
        )

    def test_the_call_graph_catches_a_new_helper_called_before_the_install(
        self,
    ) -> None:
        """A helper one hop away from `run` must still be reported."""
        src = """\
fn check_new_thing(state: &AppState) {
    metrics::new_thing_gauge(state.count());
}
fn indirect(state: &AppState) {
    check_new_thing(state);
}
async fn run() -> Result<()> {
    let state = AppState::new();
    indirect(&state);
    check_new_thing(&state);
    let metrics_handle = metrics::install_recorder(None);
    check_new_thing(&state);
    Ok(())
}
""".splitlines()
        offenders = offenders_before_install(src)
        self.assertEqual(
            [n for n, _ in offenders],
            [9, 10],
            f"expected the direct and the two-hop call before the install; got {offenders}",
        )
        writers = metrics_writers(src, function_regions(src), exclude={"run"})
        self.assertEqual(writers, {"check_new_thing", "indirect"})

    def test_the_install_is_inside_the_orchestration(self) -> None:
        """If the install moves out of `run`, the scope this guard checks is wrong and it
        would pass while checking a function that has no metric writes at all.

        `run` is the startup orchestration: parse, load, bind, serve. `main` is a thin
        exit-status wrapper around it.
        """
        start = self._enclosing_fn_line(self._install_line())
        self.assertIn(
            "fn run(",
            self.lines[start],
            f"expected `{INSTALL_CALL}` to sit in `run`, found it in: "
            f"{self.lines[start].strip()}",
        )

    def test_the_alerted_pme_gauge_is_written_after_the_install(self) -> None:
        """`gdi_pme_master_key_mismatch` must be emittable.

        Named explicitly rather than left to the generic rule above: its alert is critical
        with `for: 0m`, and it guards "PME parquet at rest is undecryptable".
        """
        install = self._install_line()
        writes = [
            i
            for i, ln in enumerate(self.lines)
            if "pme_master_key_mismatch(" in _strip_comment(ln)
            and "fn " not in _strip_comment(ln)
            and "audit::" not in _strip_comment(ln)
        ]
        self.assertTrue(
            writes,
            "no `metrics::pme_master_key_mismatch(...)` write found; if the gauge was "
            "removed, drop its alert rule and this assertion in the same commit",
        )
        # The writes live in `verify_at_rest_key`, so what matters is that the call to it
        # happens after the install.
        calls = [
            i
            for i, ln in enumerate(self.lines)
            if "verify_at_rest_key(&state)" in _strip_comment(ln)
        ]
        self.assertTrue(
            calls, "no `verify_at_rest_key(&state)` call site found in main.rs"
        )
        for c in calls:
            self.assertGreater(
                c,
                install,
                f"main.rs:{c + 1} calls `verify_at_rest_key` before `install_metrics` "
                f"(main.rs:{install + 1}); its `gdi_pme_master_key_mismatch` write would "
                "land on no recorder and the critical alert over it could never fire",
            )


if __name__ == "__main__":
    unittest.main()
