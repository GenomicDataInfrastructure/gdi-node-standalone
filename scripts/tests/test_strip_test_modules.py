#!/usr/bin/env python3
"""Guard for `_helpers.strip_test_modules`, the production-text extractor every
source-scanning guard uses instead of splitting on the first `#[cfg(test)]`.

The shape it exists for is a file with several test modules and production code between
them; `crates/gdi-node-standalone/src/s3.rs` has three. The shapes it must not trip on are
a `#[cfg(test)]` that gates a non-module item, and a test module full of braces inside
strings and comments.
"""

import unittest

from _helpers import REPO_ROOT, strip_test_modules

S3 = REPO_ROOT / "crates" / "gdi-node-standalone" / "src" / "s3.rs"


class StripTestModulesTest(unittest.TestCase):
    def test_production_between_two_test_modules_survives(self):
        src = (
            "fn a() {}\n"
            "#[cfg(test)]\n"
            'mod tests { fn t() { let _ = "{"; } // } not a brace\n }\n'
            'fn b() { info!(event = "kept"); }\n'
            "#[cfg(test)]\n"
            "#[allow(dead_code)]\n"
            "mod more_tests { fn u() {} }\n"
            "fn c() {}\n"
        )
        kept = strip_test_modules(src)
        self.assertIn("fn a()", kept)
        self.assertIn("fn b()", kept)
        self.assertIn('event = "kept"', kept)
        self.assertIn("fn c()", kept)
        self.assertNotIn("fn t()", kept)
        self.assertNotIn("fn u()", kept)
        self.assertNotIn("mod tests", kept)

    def test_a_cfg_test_on_a_non_module_item_is_left_alone(self):
        src = '#[cfg(test)]\nconst FIXTURE: &str = "x";\nfn a() {}\n'
        self.assertEqual(src, strip_test_modules(src))

    def test_the_real_s3_rs_keeps_its_production_tail(self):
        # Three test modules, with production code after the first.
        src = S3.read_text(encoding="utf-8")
        self.assertGreaterEqual(
            src.count("\n#[cfg(test)]\nmod "), 3, "s3.rs changed shape"
        )
        kept = strip_test_modules(src)
        self.assertNotIn("\nmod tests {", kept)
        self.assertNotIn("\nmod nested_key_tests {", kept)
        self.assertIn(
            "fn credential_source",
            kept,
            "the production tail after the first test module was cut",
        )
        self.assertLess(len(kept), len(src))


if __name__ == "__main__":
    unittest.main()
