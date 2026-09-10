#!/usr/bin/env python3
"""Guard: a wizard prompt is short enough that it is not itself the reason a line wraps.

`dialoguer` redraws a finished prompt by clearing **one** line. A prompt that wrapped
leaves its first line on the screen forever, so the transcript of a wizard run fills with
half-prompts. Three prompts have been shortened for exactly this reason (the S3 key
prefix, the channel name, the S3 region); a fourth was added over-long in the same commit
that shortened two of them, because nothing here measured them.

The bound is on the prompt alone, which is the only part a prompt's author controls.
`ColorfulTheme` renders a finished prompt as `✔ ` + prompt + ` · ` + the answer: five
columns of decoration, so on an 80-column terminal the prompt and the answer share 75. A
prompt over `MAX_PROMPT_COLUMNS` leaves no room for even a short answer and wraps on its
own. Nothing can make wrapping impossible, because an answer is arbitrarily long, but past
this the prompt is the cause.

Scope: every `Prompter` call in `wizard/` that takes a prompt string. Guidance that does
not fit goes above the prompt, as an `output::progress` line: it is printed once, never
redrawn, so it may wrap harmlessly. That is the shape the S3 prefix, channel and region
prompts use.
"""

import pathlib
import re
import unittest

from _helpers import REPO_ROOT

WIZARD = REPO_ROOT / "crates" / "gdi-dataset-tool" / "src" / "wizard"

#: 80 columns, less the five the theme spends on `✔ ` and ` · `, less three left for the
#: shortest answer worth echoing. The longest prompt in the tree sits just under it.
MAX_PROMPT_COLUMNS = 72

#: Every prompt-taking method on `Prompter`. Each takes its prompt as the first argument.
PROMPT_CALLS = (
    "input_validated",
    "input_path",
    "confirm",
    "secret",
    "select",
    "multi_select",
)

#: A floor, so a rename or a refactor that stops the parser from finding the calls fails
#: here instead of passing having measured nothing.
MIN_PROMPTS_FOUND = 50

_CALL = re.compile(r"\.(" + "|".join(PROMPT_CALLS) + r")\s*\(\s*", re.DOTALL)
_LITERAL = re.compile(r'"((?:[^"\\]|\\.)*)"', re.DOTALL)


def prompts() -> list[tuple[pathlib.Path, str, str]]:
    """Every (file, method, prompt) triple in `wizard/`, prompts un-escaped and unwrapped."""
    found = []
    for path in sorted(WIZARD.rglob("*.rs")):
        source = path.read_text(encoding="utf-8")
        for call in _CALL.finditer(source):
            tail = source[call.end() :]
            literal = _LITERAL.match(tail.lstrip())
            if literal is None:
                # A prompt built at runtime (`&format!(..)`) or passed through a variable.
                continue
            text = literal.group(1)
            # A Rust string continued with a trailing backslash: the backslash, the newline
            # and the leading whitespace of the next line are not in the rendered string.
            text = re.sub(r"\\\n\s*", "", text)
            text = text.replace('\\"', '"')
            found.append((path, call.group(1), text))
    return found


class WizardPromptWidth(unittest.TestCase):
    def test_the_parser_still_finds_the_prompts(self) -> None:
        self.assertGreaterEqual(
            len(prompts()),
            MIN_PROMPTS_FOUND,
            "the prompt parser found almost nothing; the Prompter API or the wizard "
            "layout changed and this guard is measuring an empty set",
        )

    def test_no_prompt_is_long_enough_to_wrap_on_its_own(self) -> None:
        over = [
            (path.name, method, len(text), text)
            for path, method, text in prompts()
            if len(text) > MAX_PROMPT_COLUMNS
        ]
        self.assertEqual(
            over,
            [],
            f"prompts longer than {MAX_PROMPT_COLUMNS} columns wrap on an 80-column "
            "terminal, and dialoguer clears only one line when it redraws them, so the "
            "first line is left behind. Move the guidance to an output::progress line "
            "above the prompt, as the S3 prefix, channel and region prompts do.",
        )


if __name__ == "__main__":
    unittest.main()
