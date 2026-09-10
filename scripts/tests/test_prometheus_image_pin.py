#!/usr/bin/env python3
"""Guard: the promtool image ci-local.sh pins is the image the compose overlay runs.

`scripts/ci-local.sh promtool` evaluates the alert rules with `PROMETHEUS_IMAGE`, and
`docker-compose.observability.yml` runs Prometheus with its own `image:` line. They are
one fact written twice: the rules must be checked by the Prometheus that will load them.
Both carry a `@sha256:` digest, so bumping one and not the other stays invisible until a
rule parses under one version and not the other.
"""

import re
import unittest

from _helpers import REPO_ROOT, SCRIPTS

CI_LOCAL = SCRIPTS / "ci-local.sh"
COMPOSE = REPO_ROOT / "docker-compose.observability.yml"
_REF = re.compile(r"prom/prometheus:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}")


class PrometheusImagePinTest(unittest.TestCase):
    def test_ci_local_and_the_compose_overlay_pin_one_prometheus(self):
        gate = re.search(
            r"^PROMETHEUS_IMAGE='([^']+)'",
            CI_LOCAL.read_text(encoding="utf-8"),
            re.MULTILINE,
        )
        self.assertIsNotNone(
            gate, "PROMETHEUS_IMAGE is no longer a single-quoted assignment"
        )
        compose = _REF.findall(COMPOSE.read_text(encoding="utf-8"))
        self.assertEqual(
            len(compose),
            1,
            f"expected one digest-pinned prom/prometheus in the overlay, found {compose}",
        )
        self.assertRegex(gate.group(1), _REF, "the gate's image is not digest-pinned")
        self.assertEqual(
            gate.group(1),
            compose[0],
            "ci-local.sh's PROMETHEUS_IMAGE and docker-compose.observability.yml's image "
            "differ, so the rules would be checked by a Prometheus other than the one "
            "that loads them; bump both in the same commit",
        )


if __name__ == "__main__":
    unittest.main()
