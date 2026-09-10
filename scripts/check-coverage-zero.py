#!/usr/bin/env python3
"""Fail when a non-trivial source file has zero coverage.

There is no floor on the aggregate. A global "coverage must be >= N%" gate can be
satisfied by testing easy code and moves when unrelated files change size, so
`ci-local.sh coverage` reports the percentage without gating on it.

A whole file at zero is what this gates instead. Zero means no test exercises the module,
so every invariant in it is asserted by nothing.

Input: the LLVM coverage export that `cargo llvm-cov --json` emits.

    {"data": [{"files": [{"filename": "...", "summary": {"regions": {"percent": 0.0}}}]}]}

Usage::

    cargo llvm-cov --workspace --features full --locked --json --output-path cov.json
    python3 scripts/check-coverage-zero.py cov.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# A file smaller than this is not worth failing the gate over: `mod.rs` re-export shims,
# tiny newtype wrappers, generated shims. Counted in lines of the file on disk, not in
# coverage regions, so the threshold means what a reader expects.
MIN_LINES = 50

# Paths that are allowed to have zero coverage, each with the reason. Keep it short and
# reasoned: an allowlist that grows without argument is how the check stops meaning
# anything. Matched as a path suffix.
ALLOWLIST: dict[str, str] = {
    "crates/gdi-node-standalone/src/main.rs": (
        "the binary entry point: `main()` and the argv dispatch are covered at process "
        "level by tests/it/binary_cli.rs, which llvm-cov does not attribute back here"
    ),
    "crates/core/src/lint_canary.rs": (
        "zero runtime coverage is the correct state: every fn exists only to be linted "
        "and is never called (see its module docs). It is guarded by "
        "`unfulfilled_lint_expectations` under -D warnings, not by tests: a clippy.toml "
        "path that stops resolving fails the build there"
    ),
    "crates/gdi-dataset-tool/src/main.rs": (
        "same: the tool's entry point is exercised by the CARGO_BIN_EXE spawns in "
        "tests/it/, whose coverage is not attributed to the spawned binary"
    ),
}


def zero_covered_files(report: dict, repo_root: Path) -> list[str]:
    """Every non-allowlisted source file over MIN_LINES with 0% region coverage."""
    offenders: list[str] = []
    for block in report.get("data", []):
        for entry in block.get("files", []):
            name = entry.get("filename", "")
            # Only our own sources. Vendored deps and generated files are not ours to test.
            if "/crates/" not in name or "/tests/" in name or "/benches/" in name:
                continue
            percent = entry.get("summary", {}).get("regions", {}).get("percent")
            if percent is None or percent > 0.0:
                continue
            rel = name.split("/crates/", 1)[1]
            rel = f"crates/{rel}"
            if any(rel.endswith(alw) or alw.endswith(rel) for alw in ALLOWLIST):
                continue
            path = repo_root / rel
            try:
                lines = len(path.read_text(encoding="utf-8").splitlines())
            except OSError:
                lines = (
                    MIN_LINES + 1
                )  # cannot read it: do not let that silence the check
            if lines >= MIN_LINES:
                offenders.append(f"{rel} ({lines} lines, 0% regions covered)")
    return sorted(offenders)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <llvm-cov-json>", file=sys.stderr)
        return 2
    report_path = Path(argv[1])
    if not report_path.is_file():
        print(f"error: {report_path} does not exist", file=sys.stderr)
        return 2
    report = json.loads(report_path.read_text(encoding="utf-8"))
    # A report with no files at all is a broken run, not a clean one. Without this the
    # check would report success having measured nothing.
    total_files = sum(len(b.get("files", [])) for b in report.get("data", []))
    if total_files == 0:
        print(
            "error: the coverage report lists no files, so the run measured nothing",
            file=sys.stderr,
        )
        return 2

    repo_root = Path(__file__).resolve().parent.parent
    offenders = zero_covered_files(report, repo_root)
    if offenders:
        print(
            f"error: {len(offenders)} source file(s) over {MIN_LINES} lines have zero "
            "coverage; no test reaches them at all:",
            file=sys.stderr,
        )
        for line in offenders:
            print(f"  {line}", file=sys.stderr)
        print(
            "\nEither add a test, or add the path to ALLOWLIST in this script with a "
            "reason.",
            file=sys.stderr,
        )
        return 1
    print(
        f"ok: no unreached source file over {MIN_LINES} lines ({total_files} files checked)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
