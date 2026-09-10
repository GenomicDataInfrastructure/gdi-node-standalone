#!/usr/bin/env python3
"""Guard: `vendored.sh pins` names a GitHub rate limit as such, and sends the token only there.

`pins` makes about a dozen `api.github.com` calls per run against an unauthenticated
budget of 60 per hour per IP, which every worktree on a machine shares. A few gate runs in
an hour exhaust it, after which each pin prints `UNREACHABLE` and the leg returns 0: a
guard that has stopped guarding, with nothing in its output naming the cause or the
remedy.

Two properties, asserted against the shipped `curl_to` with a stub `curl` on PATH. The
function is extracted from vendored.sh, so these cannot drift from it.

  1. a 403 whose `x-ratelimit-remaining` is 0 sets CURL_RATELIMITED=1, and any other 403,
     such as a bad credential or a blocked IP, does not. The leg can then print
     RATE-LIMITED with the GITHUB_TOKEN remedy only when that is the cause.
  2. GITHUB_TOKEN is attached to `api.github.com` requests only. A bearer sent to every
     URL in EXTERNAL_PINS would hand it to whichever host a future pin names.
"""

import os
import re
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from _helpers import SCRIPTS

VENDORED = SCRIPTS / "vendored.sh"


def _extract(name: str) -> str:
    src = VENDORED.read_text(encoding="utf-8")
    m = re.search(rf"^{re.escape(name)}\(\) \{{.*?^\}}", src, re.MULTILINE | re.DOTALL)
    assert m, f"{name} is no longer defined in vendored.sh in an extractable form"
    return m.group(0)


#: A `curl` that records its argv and fakes GitHub's answer. `-w` output is what the
#: real curl prints for `%{http_code} %header{x-ratelimit-remaining}`; the exit code is
#: curl's own `--fail` code (22) for an HTTP error.
STUB_CURL = """#!/usr/bin/env bash
printf '%s\\n' "$@" > "$STUB_ARGV"
case "$STUB_MODE" in
  ok)          printf '200 41'; exit 0 ;;
  ratelimited) printf '403 0'; exit 22 ;;
  forbidden)   printf '403 41'; exit 22 ;;
  old-curl)    printf '403 %%header{x-ratelimit-remaining}'; exit 22 ;;
esac
"""


class CurlToTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="gdi-vendored-"))
        self.addCleanup(
            lambda: subprocess.run(["rm", "-rf", str(self.tmp)], check=False)
        )
        stub = self.tmp / "curl"
        stub.write_text(STUB_CURL, encoding="utf-8")
        stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
        self.argv = self.tmp / "argv"

    def _curl_to(self, url: str, mode: str, token: str = "") -> tuple[int, str]:
        script = (
            f"{_extract('curl_to')}\n"
            f"rc=0; curl_to {url!r} /dev/null || rc=$?\n"
            'printf "rc=%s code=%s ratelimited=%s\\n" "$rc" "$CURL_HTTP_CODE" "$CURL_RATELIMITED"\n'
        )
        env = {
            **os.environ,
            "PATH": f"{self.tmp}{os.pathsep}{os.environ['PATH']}",
            "STUB_MODE": mode,
            "STUB_ARGV": str(self.argv),
            "GITHUB_TOKEN": token,
        }
        proc = subprocess.run(
            ["bash", "-c", script], env=env, capture_output=True, text=True, check=False
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return proc.stdout.strip(), self.argv.read_text(encoding="utf-8").splitlines()

    def test_a_spent_budget_is_rate_limited_and_any_other_403_is_not(self):
        out, _ = self._curl_to(
            "https://api.github.com/repos/x/y/commits/v1", "ratelimited"
        )
        self.assertEqual(out, "rc=22 code=403 ratelimited=1")
        out, _ = self._curl_to(
            "https://api.github.com/repos/x/y/commits/v1", "forbidden"
        )
        self.assertEqual(out, "rc=22 code=403 ratelimited=0")
        out, _ = self._curl_to("https://api.github.com/repos/x/y/commits/v1", "ok")
        self.assertEqual(out, "rc=0 code=200 ratelimited=0")

    def test_an_old_curl_that_cannot_read_headers_never_claims_rate_limiting(self):
        # curl < 7.83 prints `%header{...}` literally; that must read as unknown, not 0.
        out, _ = self._curl_to(
            "https://api.github.com/repos/x/y/commits/v1", "old-curl"
        )
        self.assertEqual(out, "rc=22 code=403 ratelimited=0")

    def test_the_token_goes_to_the_api_host_only(self):
        _, argv = self._curl_to(
            "https://api.github.com/repos/x/y/releases/latest", "ok", token="tok-1"
        )
        self.assertIn("Authorization: Bearer tok-1", argv)
        _, argv = self._curl_to(
            "https://raw.githubusercontent.com/x/y/main/README.md", "ok", token="tok-1"
        )
        self.assertFalse(
            [a for a in argv if "tok-1" in a],
            f"the token was sent to a non-API host: {argv}",
        )
        _, argv = self._curl_to("https://api.github.com/repos/x/y/commits/v1", "ok")
        self.assertFalse([a for a in argv if a.startswith("Authorization")])


class RateLimitIsReportedTest(unittest.TestCase):
    def test_both_pin_checks_print_the_remedy_on_a_rate_limit(self):
        # The leg-level half: the flag curl_to sets must reach a line naming the cause and
        # GITHUB_TOKEN in both checks. A remedy printed by one and not the other sends the
        # reader to the wrong function.
        for fn in ("check_pins", "check_action_pins"):
            body = _extract(fn)
            self.assertRegex(
                body,
                r'CURL_RATELIMITED[^\n]*\n\s*echo "\s*RATE-LIMITED[^\n]*GITHUB_TOKEN',
                f"{fn} does not print a RATE-LIMITED line naming GITHUB_TOKEN when "
                "curl_to reports a spent budget",
            )


if __name__ == "__main__":
    unittest.main()
