#!/usr/bin/env python3
"""Guard: the gate's tests never read the developer's own tool config.

``ToolConfig::load`` reads the config directory (``GDI_CONFIG_DIR``, else
``$XDG_CONFIG_HOME/gdi``) and merges ``GDI_TOOL__*`` overrides, which the README tells users
to export. ``user_config_isolation`` in ``ci-local.sh`` builds the ``env`` prefix that hides
both from the test legs; this runs the shipped function.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _helpers import SCRIPTS

CI_LOCAL = SCRIPTS / "ci-local.sh"
PREFIX = '"${USER_CONFIG_ISOLATION[@]}"'


def _extract(name: str) -> str:
    """The shipped text of one shell function, from ``ci-local.sh``."""
    src = CI_LOCAL.read_text(encoding="utf-8")
    m = re.search(rf"^{re.escape(name)}\(\) \{{.*?^\}}", src, re.MULTILINE | re.DOTALL)
    assert m, (
        f"{name} is no longer defined in ci-local.sh in a form this test can extract; "
        "it was renamed or reformatted, and this guard is now testing nothing"
    )
    return m.group(0)


class UserConfigIsolationTest(unittest.TestCase):
    def test_the_prefix_drops_the_config_dir_and_every_tool_override(self):
        with tempfile.TemporaryDirectory(prefix="gdi-isolation-") as tmp:
            env = {k: v for k, v in os.environ.items() if not k.startswith("GDI_")}
            env.update(
                GDI_CONFIG_DIR="/somewhere/else",
                GDI_TOOL__COUNTRY_CODE="FI",
                GDI_TOOL__PROFILES__DEFAULT__ORG="EXAMPLE",
                GDI_TOOLBOX="kept",
            )
            script = (
                f"{_extract('user_config_isolation')}\n"
                f"user_config_isolation\n{PREFIX} env\n"
            )
            out = subprocess.run(
                ["bash", "-c", script],
                cwd=tmp,
                env=env,
                capture_output=True,
                text=True,
                check=True,
            ).stdout
            lines = out.splitlines()
            names = {line.split("=", 1)[0] for line in lines if "=" in line}
            self.assertEqual(
                sorted(n for n in names if n.startswith("GDI_TOOL__")), [], out
            )
            self.assertNotIn("GDI_CONFIG_DIR", names)
            self.assertIn("GDI_TOOLBOX", names, "only the override prefix is dropped")
            self.assertIn(f"XDG_CONFIG_HOME={tmp}/target/test-user-config", lines)


if __name__ == "__main__":
    unittest.main()
