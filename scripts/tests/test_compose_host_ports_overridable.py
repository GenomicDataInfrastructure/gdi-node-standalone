#!/usr/bin/env python3
"""Guard: every compose `ports:` entry maps its HOST port through a GDI_HOST_PORT_* variable.

A compose file with hard-coded host ports cannot run beside another stack, so the release
gate's e2e legs could not run beside a developer's dev stack or beside each other. Two
stacks racing for one host port do not fail loudly. The second `compose up` either dies
deep inside `up` with "address already in use", or appears to succeed while talking to
another project's service.

Every host port mapping must read `${GDI_HOST_PORT_<NAME>:-<default>}`, so an operator, or
a second e2e run through GDI_E2E_PROJECT_SUFFIX, can shift the whole stack sideways with
one exported variable while the defaults stay what README.md and docs/deployment.md
promise. docs/deployment.md carries the table of variable names. This guard enforces only
the shape of each `ports:` entry, which is what a copy-pasted mapping gets wrong.

Parsed with a small line-based, indentation-tracking state machine rather than PyYAML:
`script-tests` runs on the pre-commit path and must stay stdlib-only
(test_suite_is_stdlib_only.py).
"""

import re
import unittest

from _helpers import REPO_ROOT, strip_comments

COMPOSE_FILES = sorted(REPO_ROOT.glob("docker-compose*.yml"))
# A published port mapping, quoted exactly as Compose expects: an optional bind IP, then
# HOST:CONTAINER, where HOST must be a `${GDI_HOST_PORT_<NAME>:-<default>}` interpolation
# (never a bare int) and CONTAINER is the literal in-container port.
_ENTRY_RE = re.compile(
    r'^"(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:)?'
    r"\$\{GDI_HOST_PORT_[A-Z0-9_]+:-\d+\}:\d+\"$"
)


def ports_entries(text: str) -> list[tuple[int, str]]:
    """Return (line number, raw list-item text) for every item under a `ports:` key.

    Tracks indentation: a `ports:` key (itself a list item's key, e.g. under a service)
    opens the block; the block closes at the first later line whose indentation is <= the
    key's own. Blank and whole-line-comment lines are skipped without affecting the state,
    so a comment above a port entry (every entry here has one) cannot look like the line
    that closes the block.
    """
    entries: list[tuple[int, str]] = []
    in_ports = False
    ports_indent = -1
    for lineno, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if in_ports and indent <= ports_indent:
            in_ports = False
        if stripped == "ports:":
            in_ports = True
            ports_indent = indent
            continue
        if in_ports:
            match = re.match(r"^-\s*(\S.*\S|\S)$", stripped)
            if match:
                entries.append((lineno, match.group(1)))
    return entries


class ComposeHostPortsOverridableTest(unittest.TestCase):
    def test_compose_files_were_found(self):
        # Without this, a glob typo makes every check below iterate nothing and pass.
        self.assertTrue(
            COMPOSE_FILES,
            f"no docker-compose*.yml found under {REPO_ROOT}, so this guard would pass "
            "vacuously",
        )

    def test_files_with_a_ports_key_yield_at_least_one_entry(self):
        # Guards the parser: a state machine that never opens a block would leave the
        # entry check iterating nothing per file and passing vacuously.
        for path in COMPOSE_FILES:
            text = path.read_text(encoding="utf-8")
            if re.search(r"^\s+ports:\s*$", text, re.MULTILINE):
                with self.subTest(file=path.name):
                    self.assertTrue(
                        ports_entries(text),
                        f"{path.name} has a ports: key but the parser extracted no "
                        "entries; the indentation-tracking state machine is broken",
                    )

    def test_every_ports_entry_derives_its_host_port_from_a_variable(self):
        checked = 0
        for path in COMPOSE_FILES:
            text = path.read_text(encoding="utf-8")
            for lineno, raw in ports_entries(text):
                quoted = re.match(r'^"[^"]*"', raw)
                with self.subTest(file=path.name, line=lineno):
                    self.assertIsNotNone(
                        quoted,
                        f"{path.name}:{lineno}: {raw!r} is not a quoted port mapping "
                        '(compose needs "${GDI_HOST_PORT_<NAME>:-<default>}:<container>" '
                        "quoted whole, or YAML parses ${…} as its own syntax)",
                    )
                    self.assertRegex(
                        quoted.group(0),
                        _ENTRY_RE,
                        f"{path.name}:{lineno}: {quoted.group(0)} does not map its host "
                        "port through ${GDI_HOST_PORT_<NAME>:-<default>}; see "
                        "docs/deployment.md's host-port table",
                    )
                checked += 1
        # If nothing was checked at all, because every file's ports_entries() came back
        # empty, every assertion above passed by never running.
        self.assertGreater(
            checked,
            0,
            "no ports: entries were checked at all, so this test would pass vacuously",
        )

    def test_every_e2e_script_preflights_the_host_ports_it_is_about_to_bind(self):
        # The compose files parameterise their host ports, but each `scripts/e2e/run*.sh`
        # is what must refuse to start when one is already held; otherwise a passing e2e
        # may be talking to a developer's dev stack. The scripts are enumerated rather
        # than listed, so one added later is covered the day it lands.
        scripts = sorted((REPO_ROOT / "scripts" / "e2e").glob("run*.sh"))
        self.assertTrue(
            scripts, "no scripts/e2e/run*.sh found, so this would pass vacuously"
        )
        for path in scripts:
            # Comments stripped: a `# TODO: copy the e2e_port_holder() block` line would
            # otherwise satisfy a guard about the call itself.
            text = strip_comments(path.read_text(encoding="utf-8"))
            with self.subTest(script=path.name):
                # assertTrue, not assertIn: assertIn's failure message prints the whole
                # haystack, which here is the entire script.
                self.assertTrue(
                    "e2e_port_holder()" in text,
                    f"{path.name} omits the host-port preflight; copy the "
                    "`E2E_PORTS` / `e2e_port_holder` block from scripts/e2e/run.sh so "
                    "this leg refuses to run beside a stack already holding its ports",
                )
                self.assertTrue(
                    "already bound" in text,
                    f"{path.name} has the preflight helper but never fails on a bound "
                    "port; the block must call `fail` when one is held",
                )
                # The probe must not be a pipeline ending in `grep -q`: under pipefail
                # grep's early exit SIGPIPEs the producer, the pipeline returns 141, and a
                # busy port reads as free.
                self.assertNotRegex(
                    text,
                    r"ss -ltn[^\n]*\|[^\n]*grep -q",
                    f"{path.name} probes ports through a `| grep -q` pipeline, which fails "
                    "open under pipefail; use the single-process awk form from run.sh",
                )


if __name__ == "__main__":
    unittest.main()
