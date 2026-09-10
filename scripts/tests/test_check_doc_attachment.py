#!/usr/bin/env python3
"""Unit tests for `scripts/check-doc-attachment.py`.

Each positive case is the smallest fixture that reproduces a shape this tree really
contains. Each negative case is an edit that must stay silent, because a guard that fires
on ordinary work gets suppressed rather than obeyed.

Every rule is checked in both directions: the fixture fails, and the same edit without the
defect passes. A rule asserted only in the failing direction is satisfied by a checker
that reports everything.
"""

import unittest

from _helpers import load_module

CHECK = load_module("scripts/check-doc-attachment.py", "check_doc_attachment")


# A `const` inserted between a function's doc comment and the function itself.
RUST_BEFORE = """\
/// Scan the selected datasets off the async executor.
///
/// Returns a [`ScanReject`] on a scan failure.
async fn scan_selected_datasets(a: u8) -> u8 { a }
"""

RUST_AFTER_STOLEN = """\
/// Scan the selected datasets off the async executor.
///
/// Returns a [`ScanReject`] on a scan failure.
/// How many scans may run globally before shedding.
const SCAN_POOL_MULTIPLIER: usize = 4;

async fn scan_selected_datasets(a: u8) -> u8 { a }
"""

RUST_AFTER_CORRECT = """\
/// How many scans may run globally before shedding.
const SCAN_POOL_MULTIPLIER: usize = 4;

/// Scan the selected datasets off the async executor.
///
/// Returns a [`ScanReject`] on a scan failure.
async fn scan_selected_datasets(a: u8) -> u8 { a }
"""


class RustDocSteal(unittest.TestCase):
    def test_an_inserted_item_that_steals_a_doc_is_reported(self):
        problems = CHECK.check_rust(RUST_BEFORE, RUST_AFTER_STOLEN, "beacon_http.rs")
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("scan_selected_datasets", problems[0])
        self.assertIn("lost its doc comment", problems[0])

    def test_the_same_insertion_done_correctly_is_silent(self):
        # Control for the case above: the same insertion, doc left attached. If this
        # fires, the rule reports the insertion rather than the detachment.
        self.assertEqual(
            CHECK.check_rust(RUST_BEFORE, RUST_AFTER_CORRECT, "beacon_http.rs"), []
        )

    def test_deleting_an_item_outright_is_not_a_detachment(self):
        self.assertEqual(CHECK.check_rust(RUST_BEFORE, "", "x.rs"), [])

    def test_renaming_an_item_is_not_a_detachment(self):
        renamed = RUST_BEFORE.replace("scan_selected_datasets", "scan_chosen_datasets")
        self.assertEqual(CHECK.check_rust(RUST_BEFORE, renamed, "x.rs"), [])

    def test_adding_a_documented_item_is_silent(self):
        added = RUST_BEFORE + "\n/// A new helper.\nfn helper() {}\n"
        self.assertEqual(CHECK.check_rust(RUST_BEFORE, added, "x.rs"), [])

    def test_an_undocumented_item_that_was_never_documented_is_silent(self):
        # The rule speaks only about docs that existed before the edit, which is why it
        # is a diff guard: an undocumented private helper is ordinary here.
        before = "fn helper() {}\n"
        after = "fn helper() {}\nfn other() {}\n"
        self.assertEqual(CHECK.check_rust(before, after, "x.rs"), [])


class RustTestAttributeSteal(unittest.TestCase):
    """A bare `fn` anchored above a test steals its `#[test]`; the test stops running."""

    BEFORE = "#[test]\nfn the_gate_rejects_a_short_key() { assert!(true); }\n"
    AFTER = (
        "#[test]\n"
        "fn helper_inserted_here() { assert!(true); }\n"
        "fn the_gate_rejects_a_short_key() { assert!(true); }\n"
    )

    def test_a_stolen_test_attribute_is_reported(self):
        problems = CHECK.check_rust(self.BEFORE, self.AFTER, "it.rs")
        self.assertTrue(
            any("lost its #[test]" in p for p in problems),
            f"the stolen #[test] was not reported: {problems}",
        )

    def test_losing_serial_is_caught_even_when_the_test_attribute_survives(self):
        """A dropped `#[serial(env)]` must be reported even though `#[test]` survives.

        The test still runs, so nothing fails. It races `std::env` against every other
        test in the process, and the damage surfaces as an unrelated flake elsewhere.
        """
        before = "#[test]\n#[serial(env)]\nfn env_test() { assert!(true); }\n"
        after = "#[test]\nfn env_test() { assert!(true); }\n"
        problems = CHECK.check_rust(before, after, "it.rs")
        self.assertTrue(
            any("lost its #[serial]" in p for p in problems),
            f"a dropped #[serial] was not reported: {problems}",
        )
        self.assertFalse(
            any("#[test]" in p for p in problems),
            "#[test] is still present and must not be reported as lost",
        )

    def test_losing_ignore_is_caught(self):
        before = '#[test]\n#[ignore = "needs docker"]\nfn heavy() {}\n'
        after = "#[test]\nfn heavy() {}\n"
        problems = CHECK.check_rust(before, after, "it.rs")
        self.assertTrue(any("lost its #[ignore]" in p for p in problems), problems)

    def test_attribute_names_are_normalised(self):
        # `#[tokio::test]` is the same role as `#[test]`; `#[serial(env)]` and
        # `#[ignore = "x"]` carry arguments that are not part of the name.
        self.assertEqual(CHECK.attr_name("#[tokio::test]"), "test")
        self.assertEqual(CHECK.attr_name("#[serial(env)]"), "serial")
        self.assertEqual(CHECK.attr_name('#[ignore = "why"]'), "ignore")
        self.assertEqual(
            CHECK.attr_name('#[should_panic(expected = "x")]'), "should_panic"
        )
        # Untracked attributes are not followed: `#[cfg]` and `#[derive]` change
        # routinely, and reporting them would drown the signal.
        self.assertIsNone(CHECK.attr_name('#[cfg(feature = "s3")]'))
        self.assertIsNone(CHECK.attr_name("#[derive(Debug)]"))
        self.assertIsNone(CHECK.attr_name("#[must_use]"))

    def test_a_correctly_inserted_test_is_silent(self):
        correct = (
            "#[test]\nfn helper_inserted_here() { assert!(true); }\n\n"
            "#[test]\nfn the_gate_rejects_a_short_key() { assert!(true); }\n"
        )
        self.assertEqual(CHECK.check_rust(self.BEFORE, correct, "it.rs"), [])


class RustParsing(unittest.TestCase):
    def test_an_inner_doc_does_not_count_as_documenting_the_next_item(self):
        # `//!` documents the enclosing module. Counting it would make the first item of
        # every file look documented, and losing a doc there would then go unreported.
        items = CHECK.rust_items("//! Module docs.\nfn first() {}\n")
        self.assertEqual(items[("fn", "first")].documented, 0)

    def test_attributes_between_a_doc_and_its_item_do_not_detach_it(self):
        items = CHECK.rust_items(
            '/// Documented.\n#[cfg(feature = "s3")]\n#[must_use]\nfn f() {}\n'
        )
        self.assertEqual(items[("fn", "f")].documented, 1)

    def test_a_multi_line_attribute_does_not_detach_a_doc(self):
        items = CHECK.rust_items(
            "/// Documented.\n"
            '#[expect(\n    clippy::too_many_lines,\n    reason = "big",\n)]\n'
            "fn f() {}\n"
        )
        self.assertEqual(items[("fn", "f")].documented, 1)

    def test_an_item_keyword_inside_a_string_is_not_an_item(self):
        items = CHECK.rust_items('fn real() { let s = "fn fake() {"; }\n')
        self.assertIn(("fn", "real"), items)
        self.assertNotIn(("fn", "fake"), items)

    def test_an_item_keyword_inside_a_line_comment_is_not_an_item(self):
        items = CHECK.rust_items("// fn commented() {}\nfn real() {}\n")
        self.assertNotIn(("fn", "commented"), items)
        self.assertIn(("fn", "real"), items)

    def test_two_cfg_gated_copies_of_one_name_are_counted_separately(self):
        # A name may be defined twice behind opposite `cfg`s. Losing the doc on one of
        # them must still be reported.
        text = (
            "/// Doc A.\n#[cfg(unix)]\nfn create_tmp() {}\n"
            "/// Doc B.\n#[cfg(not(unix))]\nfn create_tmp() {}\n"
        )
        facts = CHECK.rust_items(text)[("fn", "create_tmp")]
        self.assertEqual((facts.total, facts.documented), (2, 2))
        halved = text.replace("/// Doc B.\n", "")
        self.assertTrue(CHECK.check_rust(text, halved, "util.rs"))


# A usage entry inserted above another entry's wrapped continuation line, so `--help`
# prints that continuation under the wrong leg.
SH_BEFORE = """\
#   vendored-files   vendored on-disk file count matches each VENDORED.md
#                    (network-free deleted-file guard)
#   pins             external upstream pins
"""

SH_AFTER_STOLEN = """\
#   vendored-files   vendored on-disk file count matches each VENDORED.md
#   pins-strict      the same check with drift FATAL
#                    (network-free deleted-file guard)
#   pins             external upstream pins
"""

SH_AFTER_CORRECT = """\
#   vendored-files   vendored on-disk file count matches each VENDORED.md
#                    (network-free deleted-file guard)
#   pins-strict      the same check with drift FATAL
#   pins             external upstream pins
"""


class ShellUsageSteal(unittest.TestCase):
    def test_an_entry_that_lost_its_continuation_line_is_reported(self):
        problems = CHECK.check_shell(SH_BEFORE, SH_AFTER_STOLEN, "ci-local.sh")
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("vendored-files", problems[0])

    def test_inserting_the_entry_below_the_continuation_is_silent(self):
        # Control: the same new entry, placed so it steals nothing.
        self.assertEqual(
            CHECK.check_shell(SH_BEFORE, SH_AFTER_CORRECT, "ci-local.sh"), []
        )

    def test_a_function_that_lost_its_comment_block_is_reported(self):
        before = "# What this leg does.\nsecrets() {\n  :\n}\n"
        after = "helper() {\n  :\n}\nsecrets() {\n  :\n}\n"
        problems = CHECK.check_shell(before, after, "ci-local.sh")
        self.assertTrue(
            any("`secrets`" in p for p in problems),
            f"the un-commented function was not reported: {problems}",
        )

    def test_a_deleted_function_is_not_reported_as_losing_its_comment(self):
        before = "# What this leg does.\nsecrets() {\n  :\n}\n"
        self.assertEqual(CHECK.check_shell(before, "", "ci-local.sh"), [])


class GuardIsNotVacuous(unittest.TestCase):
    """The fixtures must actually exercise the parser, not slip past it."""

    def test_the_rust_fixture_parses_into_the_items_it_names(self):
        items = CHECK.rust_items(RUST_AFTER_STOLEN)
        self.assertIn(("const", "SCAN_POOL_MULTIPLIER"), items)
        self.assertIn(("fn", "scan_selected_datasets"), items)
        self.assertEqual(items[("fn", "scan_selected_datasets")].documented, 0)

    def test_the_shell_fixture_parses_into_the_entries_it_names(self):
        continuations, _, _ = CHECK.shell_facts(SH_BEFORE)
        self.assertEqual(continuations.get("vendored-files"), 1)
        self.assertEqual(continuations.get("pins"), 0)


if __name__ == "__main__":
    unittest.main()
