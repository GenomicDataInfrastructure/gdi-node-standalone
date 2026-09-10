#!/usr/bin/env python3
"""Guard: every secret-bearing root config `.gitignore` excludes, `.dockerignore` excludes too.

`.gitignore` and `.dockerignore` encode two overlapping facts about the same files.
`.gitignore` keeps a credential out of a commit; `.dockerignore` keeps it out of the
`COPY . .` build context, and so out of the `builder` image layer that `--target builder`,
a BuildKit cache export or `docker history` can read. For the operator config files
(`node.toml`, `tool.toml` and the other default discovery names, which hold a Vault token
and S3 access keys) both facts coincide: a committed copy and a build-context copy are
both leaks.

The two files cannot be merged, because git and docker read different files with different
syntax and no include mechanism. The fact is therefore written twice, and it drifts: a
`.gitignore` entry with no `.dockerignore` counterpart lets `COPY . .` carry a live token
into the builder layer on any machine that followed the docs and created one.

The set of files to check is derived from `.gitignore`, from the root-anchored
single-segment `*.toml` entries it excludes, rather than hard-coded here. A hard-coded
pair would be a third copy of the same fact, and it would stay green when a new secret
root config is added to `.gitignore` and missed in `.dockerignore`, which is the case that
must fail.

Scope is narrow: root-anchored `*.toml` only. `.gitignore` also excludes
`compose/keys/*`, `.env.external`, `*.c4gh` and more, but `.dockerignore` covers those by
broader means (`compose/`, `.env.*`, `*.c4gh`), so requiring a verbatim counterpart for
every entry would false-fail. The root config files are the one class where a per-file
exclusion is both required and easy to miss, because they sit at the context root where
`COPY . .` picks them up first.
"""

import re
import unittest

from _helpers import REPO_ROOT

GITIGNORE = REPO_ROOT / ".gitignore"
DOCKERIGNORE = REPO_ROOT / ".dockerignore"

#: A root-anchored, single-segment TOML exclusion such as `/node.toml`. Not
#: `/.cargo/config.toml`, a nested build config rather than a credential, and not a bare
#: unanchored `foo.toml`. This is the shape `.gitignore` uses for the operator configs.
ROOT_TOML = re.compile(r"^/[^/]+\.toml$")


def active_patterns(path):
    """The exclusion patterns a `*ignore` file actually applies.

    Drops blank lines, whole-line `#` comments, and `!`-negations (re-includes, which
    are the opposite of an exclusion). Whatever survives is a rule the tool enforces.
    """
    out = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        out.append(line)
    return out


def basename_excluded(patterns, filename):
    """Whether `filename` (e.g. `node.toml`) is excluded by any of `patterns`.

    Compares on the bare filename after stripping a leading `/`, so `/node.toml` (anchored
    to the context root) and `node.toml` (anywhere) both count, since both keep the root
    file out. The anchoring difference between the two does not affect the property under
    test: either form excludes the credential-bearing root file.
    """
    return any(p.lstrip("/") == filename for p in patterns)


class SecretRootConfigsAreExcludedFromTheBuildContext(unittest.TestCase):
    def setUp(self):
        self.assertTrue(GITIGNORE.is_file(), f"missing {GITIGNORE}")
        self.assertTrue(DOCKERIGNORE.is_file(), f"missing {DOCKERIGNORE}")
        self.gitignore = active_patterns(GITIGNORE)
        self.dockerignore = active_patterns(DOCKERIGNORE)

    def secret_root_configs(self):
        """The root `*.toml` files `.gitignore` treats as secret, as bare filenames."""
        return sorted(p.lstrip("/") for p in self.gitignore if ROOT_TOML.match(p))

    def test_gitignore_actually_lists_some(self):
        """Fail loud if the derivation finds nothing.

        A guard that discovers an empty set and then checks it passes having verified
        nothing. If `.gitignore` stops excluding the root operator configs, that is itself
        the leak, so this is a hard failure rather than a silent skip. Two is the floor
        because there are two operator binaries, each with its own default config.
        """
        found = self.secret_root_configs()
        self.assertGreaterEqual(
            len(found),
            2,
            ".gitignore no longer excludes the operator root configs (expected at least "
            f"node.toml and tool.toml); found {found}. Either they were dropped from "
            ".gitignore (a commit-leak regression) or the ROOT_TOML pattern here no "
            "longer matches how they are written.",
        )

    def test_dockerignore_excludes_each_one(self):
        """No secret root config may escape into the docker build context."""
        for cfg in self.secret_root_configs():
            self.assertTrue(
                basename_excluded(self.dockerignore, cfg),
                f"{cfg} is excluded from git by .gitignore but not from the docker build "
                f"context by .dockerignore, so `COPY . .` copies it into the builder "
                f"layer. Add `/{cfg}` to .dockerignore (see the block there next to the "
                f".env.* exclusions).",
            )

    def test_membership_check_discriminates(self):
        """A file that is not excluded must read as not excluded.

        Guards the guard: if `basename_excluded` ever returned True unconditionally, the
        real assertion above would pass while checking nothing. A name no ignore file
        mentions must come back False.
        """
        self.assertFalse(
            basename_excluded(self.dockerignore, "definitely-not-ignored.toml"),
            "the membership check reports an unlisted file as excluded, so "
            "test_dockerignore_excludes_each_one verifies nothing.",
        )


if __name__ == "__main__":
    unittest.main()
