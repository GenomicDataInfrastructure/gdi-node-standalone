"""Guard: no checksum-valid Estonian personal code (isikukood) may be committed.

Usernames in this system are isikukoodid, so realistic-looking ones turn up naturally in
test fixtures, sample audit reasons and docs. A validly-checksummed code may belong to a
real person, and nothing inside this repo can prove otherwise, so the sanctioned test
material is a code whose check digit is wrong. Tests need the shape, never the validity.

The rule is a repo-wide scan rather than a review habit because writing a realistic code
is the natural thing to do, including in a test whose own subject is that
person-identifying text must not leak.

`gitleaks` cannot cover this. An isikukood has no secret-shaped entropy, and the `secrets`
leg would have to be taught a personal-data rule rather than a credential one.

Scope: every tracked file, since a code is as identifying in a Markdown table as in a
`.rs` string. Binary and undecodable files are read with replacement and will not match.
"""

import pathlib
import re
import subprocess
import tempfile
import unittest

from _helpers import REPO_ROOT, clean_git_env

#: Weights for the first and (fallback) second modulo-11 rounds.
_W1 = (1, 2, 3, 4, 5, 6, 7, 8, 9, 1)
_W2 = (3, 4, 5, 6, 7, 8, 9, 1, 2, 3)

#: An 11-digit run not glued to further digits. The negative lookarounds matter: dataset
#: ids embed a 17-digit timestamp (`GDI-EE-UTARTU-20260409143052837`), and without them
#: every such id would offer several 11-digit windows to test.
_CODE = re.compile(r"(?<!\d)(\d{11})(?!\d)")


def _check_digit(first_ten: str) -> int:
    """The official modulo-11 check digit, with the documented second round."""
    digits = [int(c) for c in first_ten]
    # strict=True: both sides are exactly 10 wide, and a length drift would silently
    # truncate the sum and hand back a plausible-looking but wrong check digit.
    remainder = sum(a * b for a, b in zip(digits, _W1, strict=True)) % 11
    if remainder == 10:
        remainder = sum(a * b for a, b in zip(digits, _W2, strict=True)) % 11
        if remainder == 10:
            return 0
    return remainder


def _is_valid_isikukood(code: str) -> bool:
    """True only for a code that is structurally plausible and correctly checksummed.

    Plausibility keeps the guard quiet on ordinary 11-digit numbers (timestamps, sizes,
    ids): the first digit encodes century+sex and is 1-6, and the embedded date must be a
    real month and day.
    """
    if code[0] not in "123456":
        return False
    month, day = int(code[3:5]), int(code[5:7])
    if not (1 <= month <= 12 and 1 <= day <= 31):
        return False
    return _check_digit(code[:10]) == int(code[10])


def tracked_files(root: pathlib.Path) -> list[str]:
    """Every tracked path under `root`, read NUL-separated so a path may hold anything.

    `-z` is required. Splitting on whitespace cuts a path containing a space into
    non-paths, and `-z` also turns off git's quoting of non-ASCII names, which no split
    can undo. Either way the affected paths would go unscanned.
    """
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        capture_output=True,
        text=True,
        check=True,
        env=clean_git_env(),
    ).stdout
    return [rel for rel in out.split("\0") if rel]


def offenders_in(root: pathlib.Path) -> list[str]:
    """`file:line` for every checksum-valid code in a tracked file under `root`.

    An unreadable tracked path fails the scan rather than being skipped. "Could not read
    it" and "read it and found nothing" must not share an exit code, or the scan reports
    clean having checked less than it claims.
    """
    offenders: list[str] = []
    unreadable: list[str] = []
    for rel in tracked_files(root):
        path = root / rel
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            unreadable.append(f"{rel} ({exc.strerror})")
            continue
        for match in _CODE.finditer(text):
            if _is_valid_isikukood(match.group(1)):
                line = text[: match.start()].count("\n") + 1
                # Report the location, never the code: echoing it into a log would
                # republish the thing the guard exists to keep out of the repo.
                offenders.append(f"{rel}:{line}")
    if unreadable:
        raise AssertionError(
            f"{len(unreadable)} tracked path(s) could not be read, so the isikukood scan "
            f"is INCOMPLETE and its verdict means nothing: {unreadable}"
        )
    return offenders


class NoValidIsikukoodTest(unittest.TestCase):
    def _tracked_files(self):
        out = tracked_files(REPO_ROOT)
        # A guard that iterates nothing reports success having checked nothing.
        self.assertGreater(
            len(out),
            100,
            "git ls-files returned almost nothing, so the scan would be vacuous",
        )
        return out

    def test_the_checksum_helper_agrees_with_known_values(self):
        """Pin the algorithm itself, so the scan below cannot pass by being broken.

        Without this, replacing the modulo-11 body with a constant would leave the
        repo-wide scan green.
        """
        # The check digit is derived at runtime from the ten-digit base, so no source file
        # holds a complete valid code and the scan below cannot be blinded by its own
        # fixture.
        self.assertEqual(_check_digit("3991231999"), 7)
        self.assertTrue(
            _is_valid_isikukood("3991231999" + str(_check_digit("3991231999")))
        )
        # Same shape, wrong check digit: what a fixture may carry.
        self.assertFalse(_is_valid_isikukood("39912319998"))
        # Structurally implausible: leading 7 is not a century/sex marker, month 99.
        self.assertFalse(_is_valid_isikukood("79912319997"))
        self.assertFalse(_is_valid_isikukood("39999319997"))

    def test_no_tracked_file_carries_a_valid_isikukood(self):
        self._tracked_files()
        offenders = offenders_in(REPO_ROOT)
        self.assertFalse(
            offenders,
            "checksum-valid isikukood committed at "
            f"{offenders}; it may belong to a real person. Use a code whose check digit "
            "is wrong: tests need the shape, never the validity.",
        )

    def _scratch_repo(self, rel: str, body: str) -> pathlib.Path:
        """A throwaway repository tracking one file at `rel` with `body`."""
        root = pathlib.Path(tempfile.mkdtemp(prefix="gdi-isikukood-"))
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", str(root)], check=False))
        env = clean_git_env()
        subprocess.run(["git", "-C", str(root), "init", "-q"], check=True, env=env)
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "add", "-A"], check=True, env=env)
        return root

    def test_a_tracked_path_with_a_space_is_scanned(self):
        # The valid code is derived at runtime, never spelled out.
        valid = "3991231999" + str(_check_digit("3991231999"))
        root = self._scratch_repo("dir with space/x.rs", valid + "\n")
        self.assertEqual(offenders_in(root), ["dir with space/x.rs:1"])

    def test_a_non_ascii_tracked_path_is_scanned(self):
        valid = "3991231999" + str(_check_digit("3991231999"))
        root = self._scratch_repo("üks/kood.md", "id " + valid + "\n")
        self.assertEqual(offenders_in(root), ["üks/kood.md:1"])

    def test_an_unreadable_tracked_path_fails_the_scan(self):
        root = self._scratch_repo("a/b.txt", "nothing here\n")
        (root / "a" / "b.txt").unlink()  # tracked in the index, gone from the tree
        with self.assertRaisesRegex(AssertionError, "INCOMPLETE"):
            offenders_in(root)


if __name__ == "__main__":
    unittest.main()
