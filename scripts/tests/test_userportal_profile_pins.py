#!/usr/bin/env python3
"""Guard: `vendored.sh pins` watches what the userportal's profile reads, not which tag it deploys.

`check_ckanext.py` hand-mirrors the deployed harvest profile, and the conformance venv pins
the GDI dcat fork's upstream base. Both are facts about the forks at whatever tag the
userportal deploys, so `check_userportal_profiles` reads the tags from the userportal's own
`ckan/Dockerfile` and compares content at those tags: a `sha256=` entry by hash, a
`requirement=<name>` entry against the version `conformance/requirements.txt` pins.

Run against a stub `curl` on PATH that serves fixture files by URL. Exit codes follow
`check_pins`: 0 clean, 1 drift, 2 unreachable.
"""

import hashlib
import os
import re
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from _helpers import SCRIPTS, strip_comments

VENDORED = SCRIPTS / "vendored.sh"
RAW = "https://raw.githubusercontent.com"


def _extract(name: str) -> str:
    src = VENDORED.read_text(encoding="utf-8")
    m = re.search(rf"^{re.escape(name)}\(\) \{{.*?^\}}", src, re.MULTILINE | re.DOTALL)
    assert m, f"{name} is no longer defined in vendored.sh in an extractable form"
    return m.group(0)


#: Serves `$STUB_FILES/<url path with / as __>`, 404 (curl exit 22) for anything else, and
#: curl exit 7 with no HTTP code when STUB_NET_DOWN=1.
STUB_CURL = """#!/usr/bin/env bash
url=""; out=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift ;;
    https://*) url="$1" ;;
  esac
  shift
done
if [ "${STUB_NET_DOWN:-0}" = 1 ]; then printf '000 '; exit 7; fi
key="${url#https://raw.githubusercontent.com/}"; key="${key//\\//__}"
if [ -f "$STUB_FILES/$key" ]; then cp "$STUB_FILES/$key" "$out"; printf '200 41'; exit 0; fi
printf '404 41'; exit 22
"""

HEALTH_PROFILE = "class EuropeanHealthDCATAPProfile:\n    reads = ['hdab']\n"
FDP_PROFILE = (
    "class FAIRDataPointDCATAPProfile(EuropeanHealthDCATAPProfile):\n    pass\n"
)


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def dockerfile(
    dcat_ref: str = "v9.9.9",
    fdp_ref: str = "v1.0.0",
    fdp: bool = True,
    quoted: bool = False,
) -> str:
    # The userportal installs forks in two shapes: `-e git+URL.git@ref#egg=name`, and the
    # quoted `'name[extras] @ git+URL.git@ref'` it already uses for ckanext-scheming.
    dcat = (
        f"        'ckanext-dcat[x] @ git+https://github.com/Org/fork-dcat.git@{dcat_ref}' \\"
        if quoted
        else f"        -e git+https://github.com/Org/fork-dcat.git@{dcat_ref}#egg=ckanext-dcat \\"
    )
    lines = ["RUN pip install \\", dcat]
    if fdp:
        lines.append(
            f"        -e git+https://github.com/Org/fork-fdp.git@{fdp_ref}#egg=ckanext-fairdatapoint \\"
        )
    lines.append("        ckanext-dcat")
    return "\n".join(lines) + "\n"


def pyproject(version: str) -> str:
    # A dependency string carrying the pinned version too, so an unanchored match on the
    # bare number would pass a moved [project] version.
    return (
        "[project]\n"
        'name = "ckanext-dcat"\n'
        f'version = "{version}"\n'
        'dependencies = ["ckanext-scheming>=2.4.4"]\n'
    )


class UserportalProfilePinsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="gdi-userportal-pins-"))
        self.addCleanup(
            lambda: subprocess.run(["rm", "-rf", str(self.tmp)], check=False)
        )
        stub_dir = self.tmp / "bin"
        stub_dir.mkdir()
        stub = stub_dir / "curl"
        stub.write_text(STUB_CURL, encoding="utf-8")
        stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
        self.files = self.tmp / "files"
        self.files.mkdir()
        (self.tmp / "conformance").mkdir()
        (self.tmp / "conformance" / "requirements.txt").write_text(
            "pyshacl==0.40.1\nckanext-dcat==2.4.4\nrdflib==7.6.0\n", encoding="utf-8"
        )
        self.serve("Org/portal/main/ckan/Dockerfile", dockerfile())
        self.serve("Org/fork-dcat/v9.9.9/pyproject.toml", pyproject("2.4.4"))
        self.serve(
            "Org/fork-dcat/v9.9.9/ckanext/dcat/profiles/health.py", HEALTH_PROFILE
        )
        self.serve("Org/fork-fdp/v1.0.0/ckanext/fairdatapoint/profiles.py", FDP_PROFILE)

    def serve(self, path: str, content: str) -> None:
        (self.files / path.replace("/", "__")).write_text(content, encoding="utf-8")

    def run_check(self, net_down: bool = False) -> subprocess.CompletedProcess:
        pins = [
            "Org/fork-dcat|pyproject.toml|requirement=ckanext-dcat|dcat base",
            f"Org/fork-dcat|ckanext/dcat/profiles/health.py|sha256={sha256(HEALTH_PROFILE)}|health profile",
            f"Org/fork-fdp|ckanext/fairdatapoint/profiles.py|sha256={sha256(FDP_PROFILE)}|fdp profile",
        ]
        script = "\n".join(
            [
                "set -euo pipefail",
                f"RAW={RAW!r}",
                'USERPORTAL_DOCKERFILE="Org/portal/main|ckan/Dockerfile"',
                "USERPORTAL_PROFILE_PINS=(",
                *(f"  {p!r}" for p in pins),
                ")",
                _extract("curl_to"),
                _extract("classify_fetch_failure"),
                _extract("check_userportal_profiles"),
                "rc=0; check_userportal_profiles || rc=$?",
                'echo "rc=$rc"',
            ]
        )
        env = {
            **os.environ,
            "PATH": f"{self.tmp / 'bin'}{os.pathsep}{os.environ['PATH']}",
            "STUB_FILES": str(self.files),
            "STUB_NET_DOWN": "1" if net_down else "0",
            "GITHUB_TOKEN": "",
        }
        return subprocess.run(
            ["bash", "-c", script],
            cwd=self.tmp,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def rc(self, proc: subprocess.CompletedProcess) -> int:
        m = re.search(r"^rc=(\d+)$", proc.stdout, re.MULTILINE)
        self.assertIsNotNone(m, f"no rc line:\n{proc.stdout}\n{proc.stderr}")
        return int(m.group(1))

    def test_matching_content_at_the_deployed_tags_passes(self):
        proc = self.run_check()
        self.assertEqual(0, self.rc(proc), proc.stdout + proc.stderr)
        self.assertRegex(
            proc.stdout, r"OK\s+health profile\s+\(Org/fork-dcat@v9\.9\.9\)"
        )
        self.assertRegex(proc.stdout, r"OK\s+fdp profile\s+\(Org/fork-fdp@v1\.0\.0\)")
        self.assertRegex(proc.stdout, r"OK\s+dcat base\s+\(Org/fork-dcat@v9\.9\.9")

    def test_a_new_tag_carrying_identical_content_is_not_drift(self):
        # The reason this check exists: a userportal release that moves the tag but not
        # the profile or the base must pass without anyone touching this tree.
        self.serve("Org/portal/main/ckan/Dockerfile", dockerfile("v10.0.0", "v1.1.0"))
        self.serve("Org/fork-dcat/v10.0.0/pyproject.toml", pyproject("2.4.4"))
        self.serve(
            "Org/fork-dcat/v10.0.0/ckanext/dcat/profiles/health.py", HEALTH_PROFILE
        )
        self.serve("Org/fork-fdp/v1.1.0/ckanext/fairdatapoint/profiles.py", FDP_PROFILE)
        proc = self.run_check()
        self.assertEqual(0, self.rc(proc), proc.stdout + proc.stderr)
        self.assertIn("@v10.0.0", proc.stdout)

    def test_the_quoted_install_form_resolves_the_tag_without_its_quote(self):
        self.serve("Org/portal/main/ckan/Dockerfile", dockerfile(quoted=True))
        proc = self.run_check()
        self.assertEqual(0, self.rc(proc), proc.stdout + proc.stderr)
        self.assertRegex(
            proc.stdout, r"OK\s+health profile\s+\(Org/fork-dcat@v9\.9\.9\)"
        )

    def test_changed_profile_content_at_the_deployed_tag_is_drift(self):
        self.serve(
            "Org/fork-dcat/v9.9.9/ckanext/dcat/profiles/health.py",
            HEALTH_PROFILE + "    reads.append('extra')\n",
        )
        proc = self.run_check()
        self.assertEqual(1, self.rc(proc), proc.stdout + proc.stderr)
        self.assertRegex(
            proc.stdout, r"DRIFT\s+health profile\s+\(Org/fork-dcat@v9\.9\.9"
        )
        self.assertRegex(proc.stdout, r"OK\s+fdp profile")

    def test_a_moved_upstream_base_version_is_drift(self):
        # The expected version is the one in requirements.txt; nothing else states it.
        self.serve("Org/fork-dcat/v9.9.9/pyproject.toml", pyproject("2.5.0"))
        proc = self.run_check()
        self.assertEqual(1, self.rc(proc), proc.stdout + proc.stderr)
        self.assertRegex(proc.stdout, r"DRIFT\s+dcat base\s+\(Org/fork-dcat@v9\.9\.9")
        self.assertIn("2.5.0", proc.stdout)
        self.assertIn("2.4.4", proc.stdout)

    def test_a_fork_no_longer_installed_from_the_dockerfile_is_drift(self):
        self.serve("Org/portal/main/ckan/Dockerfile", dockerfile(fdp=False))
        proc = self.run_check()
        self.assertEqual(1, self.rc(proc), proc.stdout + proc.stderr)
        self.assertRegex(proc.stdout, r"GONE\s+fdp profile\s+\(Org/fork-fdp")
        self.assertRegex(proc.stdout, r"OK\s+health profile")

    def test_a_pinned_path_missing_at_the_deployed_tag_is_drift(self):
        (
            self.files / "Org__fork-fdp__v1.0.0__ckanext__fairdatapoint__profiles.py"
        ).unlink()
        proc = self.run_check()
        self.assertEqual(1, self.rc(proc), proc.stdout + proc.stderr)
        self.assertRegex(proc.stdout, r"GONE\s+fdp profile\s+\(HTTP 404")

    def test_a_missing_dockerfile_is_drift_not_unreachable(self):
        # The userportal moving its Dockerfile is the deployment changing shape; read as
        # a network failure, every later run would pass with a warning.
        (self.files / "Org__portal__main__ckan__Dockerfile").unlink()
        proc = self.run_check()
        self.assertEqual(1, self.rc(proc), proc.stdout + proc.stderr)
        self.assertRegex(proc.stdout, r"GONE\s+userportal ckan/Dockerfile")

    def test_no_network_is_unreachable_not_drift(self):
        proc = self.run_check(net_down=True)
        self.assertEqual(2, self.rc(proc), proc.stdout + proc.stderr)
        self.assertIn("UNREACHABLE", proc.stdout)
        self.assertNotIn("DRIFT", proc.stdout)


class ShippedPinsTest(unittest.TestCase):
    def test_the_shipped_pins_are_well_formed(self):
        src = VENDORED.read_text(encoding="utf-8")
        m = re.search(
            r"^USERPORTAL_PROFILE_PINS=\((.*?)^\)", src, re.MULTILINE | re.DOTALL
        )
        assert m, "USERPORTAL_PROFILE_PINS is no longer an array literal in vendored.sh"
        entries = re.findall(r'^\s*"([^"]+)"', m.group(1), re.MULTILINE)
        reqs = (SCRIPTS.parent / "conformance" / "requirements.txt").read_text(
            encoding="utf-8"
        )
        self.assertTrue(entries)
        for e in entries:
            fields = e.split("|")
            self.assertEqual(4, len(fields), e)
            exp = fields[2]
            self.assertRegex(
                exp, r"^(sha256=[0-9a-f]{64}|requirement=[A-Za-z0-9_.-]+)$", e
            )
            if exp.startswith("requirement="):
                name = exp.split("=", 1)[1]
                self.assertRegex(
                    reqs,
                    rf"(?m)^{re.escape(name)}==",
                    f"{name} is not pinned in conformance/requirements.txt",
                )

    def test_both_pin_subcommands_run_the_profile_check(self):
        # Read what the script runs, not what its comments say.
        src = strip_comments(VENDORED.read_text(encoding="utf-8"))
        dispatch = src[src.index('case "$cmd" in') :]
        for arm in ("check)", "pins)"):
            body = dispatch[dispatch.index(arm) :]
            body = body[: body.index(";;")]
            self.assertIn("check_userportal_profiles", body, f"the `{arm}` arm")


if __name__ == "__main__":
    unittest.main()
