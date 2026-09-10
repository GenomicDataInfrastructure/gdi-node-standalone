#!/usr/bin/env python3
"""Guard: the chaos harness must wait longer than the probe it is waiting on.

scripts/chaos/run.sh asserts that `/health/ready` degrades when Vault is black-holed. That
signal does not arrive instantly: Vault health reaches readiness through a periodic probe
on `VAULT_LIVENESS_INTERVAL`. A wait shorter than that interval expires before the signal
it asserts can arrive, so the scenario can only report a false explanation.

Two numbers in two languages have to agree, and the duplication cannot be deleted, because
a shell timeout cannot read a Rust `const`. The agreement is asserted here instead.
"""

import re
import unittest

from _helpers import REPO_ROOT, SCRIPTS

CHAOS = SCRIPTS / "chaos" / "run.sh"
MAIN_RS = REPO_ROOT / "crates" / "gdi-node-standalone" / "src" / "main.rs"

#: `const VAULT_LIVENESS_INTERVAL: Duration = Duration::from_mins(1);`
_INTERVAL = re.compile(
    r"const\s+VAULT_LIVENESS_INTERVAL:\s*Duration\s*=\s*Duration::from_(secs|mins)\((\d+)\)"
)

#: `if wait_unready 90; then`: the window the vault-down scenario allows.
_WAIT_UNREADY = re.compile(r"wait_unready\s+(\d+)")


def probe_interval_secs() -> int:
    m = _INTERVAL.search(MAIN_RS.read_text(encoding="utf-8"))
    if not m:
        raise AssertionError(
            f"could not find VAULT_LIVENESS_INTERVAL in {MAIN_RS}; it was renamed or "
            "reshaped, and this guard is now comparing nothing"
        )
    value = int(m.group(2))
    return value * 60 if m.group(1) == "mins" else value


class ChaosWaitsOutTheProbeTest(unittest.TestCase):
    def test_the_interval_was_parsed(self):
        # Anti-vacuity: a failed parse raises above, but pin a sane value so a regex that
        # matches something absurd cannot make the comparison trivially true.
        self.assertGreaterEqual(probe_interval_secs(), 1)

    def test_the_wait_was_parsed(self):
        waits = _WAIT_UNREADY.findall(CHAOS.read_text(encoding="utf-8"))
        self.assertTrue(
            waits,
            f"no `wait_unready <secs>` call found in {CHAOS}; the guard compares nothing",
        )

    def test_every_unready_wait_outlasts_the_vault_probe(self):
        interval = probe_interval_secs()
        waits = [
            int(w) for w in _WAIT_UNREADY.findall(CHAOS.read_text(encoding="utf-8"))
        ]
        too_short = [w for w in waits if w <= interval]
        self.assertFalse(
            too_short,
            f"chaos waits {too_short}s for a readiness change that a {interval}s probe "
            "delivers. The assertion expires before the signal can arrive, so it can only "
            "report a false explanation. Raise the wait above the probe interval.",
        )


if __name__ == "__main__":
    unittest.main()
