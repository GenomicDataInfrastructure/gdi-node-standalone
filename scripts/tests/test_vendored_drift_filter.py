#!/usr/bin/env python3
"""Guard: `vendored.sh drift [set]` watches one set and tells drift from no network.

The `pins` leg runs `drift gdi-metadata` fatally under PINS_STRICT, since the shapes are the
contract the conformance gate validates against, while Beacon and VRS drift stays advisory.
That needs a set filter and distinct exit codes: 0 clean, 2 fetch failure without drift, 3
upstream moved (a file removed upstream counts), 1 this tree broken or a set name matching
nothing (a typo must not read as "unreachable" and pass as a warning).

Run through the real script with a stub `curl` that serves the local vendored files back,
one of them altered, or nothing.
"""

import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from _helpers import REPO_ROOT, SCRIPTS

VENDORED = SCRIPTS / "vendored.sh"
SET_DIR = REPO_ROOT / "conformance" / "shapes" / "gdi-metadata"

#: Serves `$STUB_LOCAL/<rel>` for `$STUB_PREFIX/<rel>`, altering `$STUB_DRIFT_FILE`, and
#: records every URL. STUB_NET_DOWN=1 is curl exit 7 with no HTTP code.
STUB_CURL = """#!/usr/bin/env bash
url=""; out=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift ;;
    https://*) url="$1" ;;
  esac
  shift
done
printf '%s\\n' "$url" >> "$STUB_URLS"
if [ "${STUB_NET_DOWN:-0}" = 1 ]; then printf '000 '; exit 7; fi
case "$url" in
  "$STUB_PREFIX"/*)
    rel="${url#"$STUB_PREFIX"/}"
    if [ -f "$STUB_LOCAL/$rel" ]; then
      cp "$STUB_LOCAL/$rel" "$out"
      [ "$rel" = "${STUB_DRIFT_FILE:-}" ] && printf '\\n# moved upstream\\n' >> "$out"
      printf '200 41'; exit 0
    fi ;;
esac
printf '404 41'; exit 22
"""


def md_field(key: str) -> str:
    text = (SET_DIR / "VENDORED.md").read_text(encoding="utf-8")
    m = re.search(rf"\*\*{key}:\*\*[^`]*`([^`]*)`", text)
    assert m, f"{key} not in {SET_DIR}/VENDORED.md"
    return m.group(1)


class DriftFilterTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="gdi-drift-"))
        self.addCleanup(
            lambda: subprocess.run(["rm", "-rf", str(self.tmp)], check=False)
        )
        stub = self.tmp / "curl"
        stub.write_text(STUB_CURL, encoding="utf-8")
        stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
        self.urls = self.tmp / "urls"
        self.urls.touch()
        repo, path = md_field("Repository"), md_field("Path").rstrip("/")
        self.prefix = (
            f"https://raw.githubusercontent.com/{repo}/{md_field('Branch')}/{path}"
        )

    def run_drift(
        self,
        *args: str,
        drift_file: str = "",
        net_down: bool = False,
        local: Path = SET_DIR,
    ):
        env = {
            **os.environ,
            "PATH": f"{self.tmp}{os.pathsep}{os.environ['PATH']}",
            "STUB_URLS": str(self.urls),
            "STUB_PREFIX": self.prefix,
            "STUB_LOCAL": str(local),
            "STUB_DRIFT_FILE": drift_file,
            "STUB_NET_DOWN": "1" if net_down else "0",
            "GITHUB_TOKEN": "",
        }
        return subprocess.run(
            ["bash", str(VENDORED), "drift", *args],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_a_set_filter_fetches_only_that_set(self):
        proc = self.run_drift("gdi-metadata")
        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
        urls = self.urls.read_text(encoding="utf-8").split()
        self.assertTrue(urls)
        self.assertTrue(all(u.startswith(self.prefix) for u in urls), urls)
        self.assertNotIn("beacon", proc.stdout)

    def test_an_upstream_change_in_the_filtered_set_exits_3(self):
        proc = self.run_drift("gdi-metadata", drift_file="Dataset.ttl")
        self.assertEqual(3, proc.returncode, proc.stdout + proc.stderr)
        self.assertRegex(proc.stdout, r"DRIFT\s+Dataset\.ttl")

    def test_no_network_exits_2_and_is_not_called_drift(self):
        proc = self.run_drift("gdi-metadata", net_down=True)
        self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
        self.assertIn("FETCH-FAIL", proc.stdout)
        self.assertNotIn("DRIFT", proc.stdout)

    def test_a_set_name_matching_nothing_is_an_error_not_a_verdict(self):
        proc = self.run_drift("no-such-set")
        self.assertEqual(1, proc.returncode, proc.stdout + proc.stderr)
        self.assertIn("no vendored set matches", proc.stderr)
        self.assertEqual("", self.urls.read_text(encoding="utf-8"))

    def test_a_shape_removed_upstream_is_drift_not_a_fetch_failure(self):
        # A 404 is upstream saying the file is gone, which is the strongest form of
        # "moved"; read as a network failure it would pass the strict pins leg as SKIPPED.
        upstream = self.tmp / "upstream"
        shutil.copytree(SET_DIR, upstream)
        (upstream / "Resource.ttl").unlink()
        proc = self.run_drift("gdi-metadata", local=upstream)
        self.assertEqual(3, proc.returncode, proc.stdout + proc.stderr)
        self.assertRegex(proc.stdout, r"GONE\s+Resource\.ttl")
        self.assertNotIn("verdict about the", proc.stderr)

    def run_drift_in_copy(self, mutate) -> subprocess.CompletedProcess:
        """Run `drift gdi-metadata` from a copy of the tree with `mutate(set_dir)` applied.

        The script anchors on its own location, so a copy holding `scripts/vendored.sh` and
        the one set is a complete tree for this subcommand. Upstream still serves the real
        set, so whatever `mutate` did is a local fact, not drift.
        """
        tree = self.tmp / "tree"
        (tree / "scripts").mkdir(parents=True)
        shutil.copy(VENDORED, tree / "scripts" / "vendored.sh")
        copy = tree / "conformance" / "shapes" / "gdi-metadata"
        shutil.copytree(SET_DIR, copy)
        mutate(copy)
        env = {
            **os.environ,
            "PATH": f"{self.tmp}{os.pathsep}{os.environ['PATH']}",
            "STUB_URLS": str(self.urls),
            "STUB_PREFIX": self.prefix,
            "STUB_LOCAL": str(SET_DIR),
            "STUB_DRIFT_FILE": "",
            "STUB_NET_DOWN": "0",
            "GITHUB_TOKEN": "",
        }
        return subprocess.run(
            ["bash", str(tree / "scripts" / "vendored.sh"), "drift", "gdi-metadata"],
            cwd=tree,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_a_vendored_file_missing_locally_is_a_tree_defect_not_ok(self):
        # Every surviving file matches upstream, so the counters alone say "clean"; the
        # VENDORED.md file count is what knows a file is missing.
        proc = self.run_drift_in_copy(lambda d: (d / "Resource.ttl").unlink())
        self.assertEqual(1, proc.returncode, proc.stdout + proc.stderr)
        self.assertNotIn("OK: every vendored file", proc.stdout)
        self.assertIn("FILE-COUNT MISMATCH", proc.stderr)

    def test_an_unparseable_vendored_md_exits_1_cleanly(self):
        def blank_commit(d):
            md = d / "VENDORED.md"
            md.write_text(
                re.sub(
                    r"(?m)^- \*\*Commit:\*\*.*$", "", md.read_text(encoding="utf-8")
                ),
                encoding="utf-8",
            )

        proc = self.run_drift_in_copy(blank_commit)
        self.assertEqual(1, proc.returncode, proc.stdout + proc.stderr)
        self.assertNotIn("unbound variable", proc.stderr)
        self.assertIn("could not parse", proc.stderr)


if __name__ == "__main__":
    unittest.main()
