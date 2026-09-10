#!/usr/bin/env python3
"""Guard: the cross legs build every gnu target before any musl one.

Every row of a cross matrix shares one host build-script directory: cargo compiles build
scripts for the host triple whatever `--target` says, and all rows use the same
`release-verify` profile. The `cross` containers do not share a glibc. The gnu image is
old, which is what makes its glibc floor worth asserting; the musl image is not. So
whichever container runs first leaves behind build scripts the other has to execute, and
only one order works:

    gnu then musl : the scripts need an old glibc, musl's newer libc runs them  -> OK
    musl then gnu : the scripts need a newer glibc than the gnu image ships     -> FAILS

The failure reads ``build-script-build: /lib/.../libc.so.6: version `GLIBC_2.28' not
found``: a message that names libc, says nothing about ordering, and comes from a leg that
is not in `all` and so runs only before a tag.

The matrix is read from the workflows, so without the sort the order would be whatever
ci.yml happens to list, enforced nowhere and broken by an edit that looks cosmetic. This
pins the sort itself, and pins that the real matrices come out gnu-first once it has run.

The shipped line is extracted from `ci-local.sh` and executed rather than re-implemented
here. A copy of the sort would agree with the original no matter what either did.
"""

import re
import subprocess
import unittest

from _helpers import REPO_ROOT, SCRIPTS

CI_LOCAL = SCRIPTS / "ci-local.sh"
# The one shipped statement under test: `rows="$( … awk … )"`.
_SORT = re.compile(r'^\s*(rows="\$\(printf .*awk .*\)")\s*$', re.MULTILINE)


def sort_line() -> str:
    """The gnu-first sort exactly as `ci-local.sh` ships it."""
    text = CI_LOCAL.read_text(encoding="utf-8")
    hits = _SORT.findall(text)
    if len(hits) != 1:
        raise AssertionError(
            f"expected exactly one gnu-first sort statement in ci-local.sh, found {len(hits)}"
        )
    return hits[0]


def apply_sort(rows: list[str]) -> list[str]:
    """Run the shipped statement over `rows` and return what it produced."""
    script = 'rows="$1"\n' + sort_line() + '\nprintf "%s\\n" "$rows"\n'
    out = subprocess.run(
        ["bash", "-c", script, "bash", "\n".join(rows)],
        capture_output=True,
        text=True,
        check=True,
    )
    # rstrip: a row whose features field is empty ends in a space, and whether that
    # survives the round trip is not what this file is about.
    return [line.rstrip() for line in out.stdout.splitlines() if line.strip()]


def libc_of(row: str) -> str:
    return "gnu" if row.split()[0].endswith("-gnu") else "musl"


class CrossMatrixGnuFirst(unittest.TestCase):
    def assert_gnu_first(self, rows: list[str], what: str) -> None:
        seen_musl = False
        for row in rows:
            if libc_of(row) == "musl":
                seen_musl = True
            elif seen_musl:
                self.fail(
                    f"{what}: gnu row {row.split()[0]!r} comes after a musl row; the gnu "
                    f"container cannot run build scripts the musl one left behind. Order:\n"
                    + "\n".join(rows)
                )

    def test_sort_puts_every_gnu_row_first(self):
        """A musl-first input comes back gnu-first."""
        rows = [
            "x86_64-unknown-linux-musl gdi-dataset-tool ",
            "x86_64-unknown-linux-gnu gdi-dataset-tool ",
            "x86_64-unknown-linux-musl gdi-node-standalone full",
            "aarch64-unknown-linux-gnu gdi-node-standalone full",
        ]
        out = apply_sort(rows)
        self.assert_gnu_first(out, "sorted synthetic matrix")

    def test_sort_changes_only_the_order(self):
        """No row is dropped, duplicated or rewritten, and each group keeps its order."""
        rows = [
            "x86_64-unknown-linux-musl gdi-node-standalone s3",
            "x86_64-unknown-linux-gnu gdi-dataset-tool ",
            "x86_64-unknown-linux-musl gdi-dataset-tool ",
            "x86_64-unknown-linux-gnu gdi-node-standalone full",
        ]
        out = apply_sort(rows)
        self.assertEqual(
            sorted(out), sorted(r.rstrip() for r in rows), "the set of rows changed"
        )
        # Stable: the workflow still decides everything except gnu-before-musl.
        self.assertEqual(
            [r for r in out if libc_of(r) == "gnu"],
            [r.rstrip() for r in rows if libc_of(r) == "gnu"],
            "gnu rows were reordered among themselves",
        )
        self.assertEqual(
            [r for r in out if libc_of(r) == "musl"],
            [r.rstrip() for r in rows if libc_of(r) == "musl"],
            "musl rows were reordered among themselves",
        )

    def test_the_real_matrices_come_out_gnu_first(self):
        """Both shipped matrices, as parsed from the workflows, survive the sort gnu-first."""
        for flag in ("--cross-matrix", "--cross-matrix-arm"):
            with self.subTest(flag=flag):
                parsed = subprocess.run(
                    ["python3", str(SCRIPTS / "check-ci-gate.py"), flag],
                    capture_output=True,
                    text=True,
                    check=True,
                    cwd=REPO_ROOT,
                )
                rows = [r.rstrip() for r in parsed.stdout.splitlines() if r.strip()]
                self.assertTrue(rows, f"{flag} parsed no rows")
                self.assert_gnu_first(apply_sort(rows), f"real {flag}")


if __name__ == "__main__":
    unittest.main()
