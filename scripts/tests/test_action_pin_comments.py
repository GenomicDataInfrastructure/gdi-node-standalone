"""Guard: every SHA-pinned `uses:` carries a version comment, and `pins` verifies them.

The network half lives in `scripts/vendored.sh check_action_pins`, which compares each
`uses: owner/repo@<sha> # <tag>` against what upstream says that tag resolves to. That
check can only see pins it can enumerate, and it enumerates on the `# <tag>` comment. A
pin written without one is not reported as a problem, it is simply not checked. This file
closes that hole without needing the network.

SHA-pinning gives immutability, not provenance. The comment is the only human-readable
statement of which version is pinned, and the only thing a reviewer checks a bump against.
A pin whose SHA is not the one that tag names runs unreviewed code while every reader
believes otherwise.
"""

import re
import unittest

from _helpers import REPO_ROOT, strip_comments

WORKFLOWS = REPO_ROOT / ".github" / "workflows"

#: Any `uses:` at a pinned 40-hex SHA, comment or not.
_PINNED = re.compile(
    r"uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([0-9a-f]{40})([^\n]*)"
)
#: A `uses:` pinned to something other than a 40-hex SHA (a tag or branch ref).
_UNPINNED = re.compile(
    r"uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@(?![0-9a-f]{40}\b)(\S+)"
)


def _workflow_files():
    return sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))


class ActionPinCommentTest(unittest.TestCase):
    def test_workflows_are_present(self):
        """A glob that matches nothing would make every assertion below vacuous."""
        self.assertGreaterEqual(
            len(_workflow_files()), 4, f"expected the four workflows under {WORKFLOWS}"
        )

    def test_every_sha_pin_carries_a_version_comment(self):
        missing = []
        for path in _workflow_files():
            text = path.read_text(encoding="utf-8")
            for lineno, line in enumerate(text.splitlines(), 1):
                m = _PINNED.search(line)
                if not m:
                    continue
                trailing = m.group(3)
                # `# v2.9.2` or `# stable`. A bare `#`, or nothing, leaves the network
                # check with no claim to verify.
                if not re.search(r"#\s*\S+", trailing):
                    missing.append(f"{path.name}:{lineno} {m.group(1)}")
        self.assertFalse(
            missing,
            f"SHA-pinned action(s) with no version comment: {missing}. "
            "`vendored.sh check_action_pins` enumerates on that comment, so an "
            "uncommented pin goes unverified. Add `# vX.Y.Z`, or the branch name, "
            "beside the SHA.",
        )

    def test_no_action_is_pinned_to_a_mutable_ref(self):
        """A tag or branch ref is remotely mutable, which is why this repo pins SHAs."""
        loose = []
        for path in _workflow_files():
            for lineno, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), 1
            ):
                # `uses: ./.github/...` (local composite actions) has no owner/repo form
                # and is not remotely mutable, so the pattern does not match it.
                m = _UNPINNED.search(line)
                if m:
                    loose.append(f"{path.name}:{lineno} {m.group(1)}@{m.group(2)}")
        self.assertFalse(
            loose,
            f"action(s) pinned to a mutable ref: {loose}; upstream can move a tag under "
            "us. Pin the 40-hex commit SHA and put the version in a trailing comment.",
        )

    def test_the_pins_leg_actually_runs_the_action_check(self):
        """Wiring guard: the check exists and the `pins` command calls it.

        A `check_action_pins` that is defined but never invoked is a guard that verifies
        nothing.
        """
        # Read what the script runs, not what its comments say: a comment restating the
        # call would otherwise satisfy this assertion.
        script = strip_comments(
            (REPO_ROOT / "scripts" / "vendored.sh").read_text(encoding="utf-8")
        )
        self.assertIn(
            "check_action_pins()",
            script,
            "check_action_pins is not defined in vendored.sh",
        )
        # The dispatch must invoke it, not merely define it.
        self.assertRegex(
            script,
            r"arc=0;\s*check_action_pins",
            "the `pins` dispatch does not invoke check_action_pins",
        )


if __name__ == "__main__":
    unittest.main()
