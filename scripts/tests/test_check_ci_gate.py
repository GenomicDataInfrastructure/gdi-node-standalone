#!/usr/bin/env python3
"""Tests for ``scripts/check-ci-gate.py``, the guard on the CI gate graph itself.

`ci-success` is the single required check for branch protection. It `needs:` every gate
and fails if any reports `failure`/`cancelled`. Two ways a gate can silently stop
enforcing, neither of which turns the check red:

* a new job is added to ``ci.yml`` but never wired into ``ci-success.needs``. It runs, it
  can fail, and nothing blocks the merge;
* an existing gate gains an ``if:`` (or ``continue-on-error: true``) and starts reporting
  ``skipped``/``success`` on the common path, which ``ci-success`` tolerates.

These tests pin the static half of that guard. Pure stdlib.
Run: ``python3 -m unittest discover -s scripts/tests -p 'test_*.py'``
"""

import unittest
from typing import ClassVar

from _helpers import REPO_ROOT, load_module

ROOT = REPO_ROOT
gate = load_module("scripts/check-ci-gate.py", "check_ci_gate")


WORKFLOW = """
name: ci
on: [push]
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - name: a step with its own if
        if: always()
        run: echo hi
  rust:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
  semver-checks:
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'
    continue-on-error: true
    steps:
      - run: echo hi
  ci-success:
    name: ci-success
    if: always()
    needs:
      - lint
      - rust
      - semver-checks
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
"""


class Parsing(unittest.TestCase):
    def test_finds_every_top_level_job(self):
        self.assertEqual(
            set(gate.workflow_jobs(WORKFLOW)),
            {"lint", "rust", "semver-checks", "ci-success"},
        )

    def test_a_step_level_if_is_not_a_job_level_if(self):
        """`lint` has an `if:` on a step, which must not mark the job as skippable."""
        self.assertFalse(gate.workflow_jobs(WORKFLOW)["lint"].conditional)

    def test_job_level_if_and_continue_on_error_are_seen(self):
        job = gate.workflow_jobs(WORKFLOW)["semver-checks"]
        self.assertTrue(job.conditional)
        self.assertTrue(job.advisory)

    def test_ci_success_needs_are_extracted(self):
        self.assertEqual(
            gate.ci_success_needs(WORKFLOW), ["lint", "rust", "semver-checks"]
        )

    def test_ci_success_always_is_detected(self):
        self.assertTrue(gate.workflow_jobs(WORKFLOW)["ci-success"].conditional)


INLINE_NEEDS = """
jobs:
  fuzz:
    runs-on: ubuntu-latest
  canary:
    runs-on: ubuntu-latest
  notify:
    needs: [fuzz, canary]
    if: failure()
    runs-on: ubuntu-latest
"""


class NeedsParsing(unittest.TestCase):
    """`needs:` appears in both YAML forms across this repo's workflows."""

    def test_block_list_form(self):
        self.assertEqual(
            ["lint", "rust", "semver-checks"], gate.job_needs(WORKFLOW, "ci-success")
        )

    def test_inline_list_form(self):
        self.assertEqual(["fuzz", "canary"], gate.job_needs(INLINE_NEEDS, "notify"))

    def test_a_job_with_no_needs(self):
        self.assertEqual([], gate.job_needs(WORKFLOW, "lint"))


class AggregateCoverage(unittest.TestCase):
    """Every job must be a dependency of its workflow's aggregate/notify job.

    In `ci.yml` an unwired job cannot block a merge. In `scheduled.yml` and `e2e-full.yml`
    an unwired job fails weekly and no tracking issue is opened.
    """

    def test_a_fully_wired_notify_passes(self):
        self.assertEqual(
            [],
            gate.check_notify_workflow(INLINE_NEEDS, "notify", "sched.yml", set(), {}),
        )

    def test_a_scheduled_job_missing_from_notify_is_reported(self):
        broken = INLINE_NEEDS.replace("needs: [fuzz, canary]", "needs: [fuzz]")
        problems = "\n".join(
            gate.check_notify_workflow(broken, "notify", "sched.yml", set(), {})
        )
        self.assertIn("canary", problems)
        self.assertIn("notify", problems)

    def test_a_missing_aggregate_is_reported(self):
        broken = INLINE_NEEDS.replace("  notify:\n", "  other:\n")
        problems = "\n".join(
            gate.check_notify_workflow(broken, "notify", "sched.yml", set(), {})
        )
        self.assertIn("notify", problems)


class AllowlistIsSingleSourced(unittest.TestCase):
    """There is one list of skippable jobs: `ALLOWED_SKIPS` in the `ci-success` step.

    The workflow needs the value at runtime, so the workflow owns it and the script reads
    it. A copy in the script would be one more fact to keep in step.
    """

    def test_the_allowlist_is_read_from_the_workflow(self):
        self.assertEqual(
            {"semver-checks"},
            gate.parse_allowed_skips('  ALLOWED_SKIPS: "semver-checks"\n'),
        )

    def test_multiple_entries_are_split_on_whitespace(self):
        self.assertEqual(
            {"a", "b"}, gate.parse_allowed_skips('  ALLOWED_SKIPS: "a b"\n')
        )

    def test_an_empty_allowlist_is_empty(self):
        self.assertEqual(set(), gate.parse_allowed_skips('  ALLOWED_SKIPS: ""\n'))

    def test_a_missing_env_var_is_none(self):
        self.assertIsNone(gate.parse_allowed_skips("jobs:\n"))

    def test_the_shipped_ci_yml_declares_one(self):
        self.assertIsNotNone(gate.parse_allowed_skips(gate.CI_YML.read_text()))

    def test_a_job_the_workflow_allowlists_may_carry_an_if(self):
        """Widening ALLOWED_SKIPS is the only edit needed; the script follows."""
        widened = WORKFLOW.replace(
            "  rust:\n    runs-on: ubuntu-latest\n",
            "  rust:\n    runs-on: ubuntu-latest\n    if: github.ref == 'refs/heads/main'\n",
        )
        self.assertNotEqual([], gate.check_workflow(widened, {"semver-checks"}))
        self.assertEqual([], gate.check_workflow(widened, {"semver-checks", "rust"}))


NOTIFY_WF = """
jobs:
  advisories:
    runs-on: ubuntu-latest
  benches:
    runs-on: ubuntu-latest
    continue-on-error: true
  notify:
    needs: [advisories, benches]
    if: failure()
    runs-on: ubuntu-latest
"""


class NotifyWorkflowSilentGates(unittest.TestCase):
    """A `continue-on-error` scheduled job reports `success`, so `notify` never fires."""

    ADVISORY: ClassVar[dict[str, str]] = {
        "benches": "advisory microbenchmarks; gate nothing"
    }

    def check(self, text):
        return gate.check_notify_workflow(
            text, "notify", "sched.yml", set(), self.ADVISORY
        )

    def test_the_shipped_shape_passes(self):
        self.assertEqual([], self.check(NOTIFY_WF))

    def test_muting_a_real_scheduled_gate_is_reported(self):
        """If `advisories` (the RustSec scan) gains continue-on-error, nobody is told."""
        broken = NOTIFY_WF.replace(
            "  advisories:\n    runs-on: ubuntu-latest\n",
            "  advisories:\n    runs-on: ubuntu-latest\n    continue-on-error: true\n",
        )
        problems = "\n".join(self.check(broken))
        self.assertIn("advisories", problems)
        self.assertIn("continue-on-error", problems)

    def test_an_unexpected_if_on_a_scheduled_job_is_reported(self):
        broken = NOTIFY_WF.replace(
            "  advisories:\n    runs-on: ubuntu-latest\n",
            "  advisories:\n    runs-on: ubuntu-latest\n    if: false\n",
        )
        problems = "\n".join(self.check(broken))
        self.assertIn("advisories", problems)

    def test_a_stale_advisory_allowlist_entry_is_reported(self):
        fixed = NOTIFY_WF.replace("    continue-on-error: true\n", "")
        problems = "\n".join(self.check(fixed))
        self.assertIn("no longer", problems)

    def test_an_unwired_job_is_still_reported(self):
        broken = NOTIFY_WF.replace(
            "needs: [advisories, benches]", "needs: [advisories]"
        )
        problems = "\n".join(self.check(broken))
        self.assertIn("benches", problems)


CROSS_WF = """
jobs:
  cross-compile:
    strategy:
      matrix:
        include:
          - name: tool-linux-gnu
            os: ubuntu-latest
            target: x86_64-unknown-linux-gnu
            crate: gdi-dataset-tool
            features: ""
          - name: service-musl
            os: ubuntu-latest
            target: x86_64-unknown-linux-musl
            crate: gdi-node-standalone
            features: "full"
    steps:
      - run: |
          printf '%s\\n2.28\\n' "${max#GLIBC_}" | sort -V -C
  e2e-smoke:
    runs-on: ubuntu-latest
"""


class CrossMatrixIsSingleSourced(unittest.TestCase):
    """`ci-local.sh cross` reads the matrix from ci.yml rather than copying it.

    A second copy of seven target/crate/feature triples would drift with the first, and
    `cross` would then build-verify a different set than CI claims to. Same for the glibc
    floor constant.
    """

    def test_rows_are_extracted_in_order(self):
        self.assertEqual(
            [
                ("x86_64-unknown-linux-gnu", "gdi-dataset-tool", ""),
                ("x86_64-unknown-linux-musl", "gdi-node-standalone", "full"),
            ],
            gate.cross_matrix(CROSS_WF),
        )

    def test_the_glibc_floor_is_extracted(self):
        self.assertEqual("2.28", gate.glibc_floor(CROSS_WF))

    def test_the_shipped_ci_yml_has_the_per_pr_x86_64_rows(self):
        # The per-PR cross-compile matrix is x86_64-only. The two aarch64-linux service
        # legs run in the weekly `cross-linux-arm` job in scheduled.yml.
        rows = gate.cross_matrix(gate.CI_YML.read_text())
        self.assertEqual(5, len(rows))
        self.assertIn(
            ("x86_64-unknown-linux-musl", "gdi-node-standalone", "full"), rows
        )
        # aarch64 runs weekly, not per-PR.
        self.assertNotIn(
            ("aarch64-unknown-linux-musl", "gdi-node-standalone", "full"), rows
        )

    def test_the_shipped_ci_yml_declares_a_glibc_floor(self):
        self.assertEqual("2.28", gate.glibc_floor(gate.CI_YML.read_text()))

    def test_an_empty_matrix_is_a_problem_not_a_silent_no_op(self):
        """A `cross` target that loops over zero rows would pass having built nothing."""
        problems = "\n".join(
            gate.check_cross_matrix("jobs:\n  other:\n    runs-on: x\n")
        )
        self.assertIn("cross-compile", problems)

    def test_a_PARTIALLY_unparseable_matrix_is_reported(self):
        """Some rows parse, so the count is non-zero and the local `cross` target
        build-verifies a smaller set than CI claims to."""
        broken = CROSS_WF.replace(
            "            crate: gdi-dataset-tool", "            pkg: gdi-dataset-tool"
        )
        problems = "\n".join(gate.check_cross_matrix(broken))
        self.assertIn("1", problems)
        self.assertIn("2", problems)

    def test_declared_row_count_counts_every_matrix_entry(self):
        self.assertEqual(2, gate.cross_matrix_declared_rows(CROSS_WF))
        self.assertEqual(5, gate.cross_matrix_declared_rows(gate.CI_YML.read_text()))

    def test_the_shipped_matrix_passes_the_guard(self):
        self.assertEqual([], gate.check_cross_matrix(gate.CI_YML.read_text()))

    def test_the_shipped_scheduled_yml_has_the_two_aarch64_rows(self):
        # The weekly `cross-linux-arm` job holds the aarch64-linux legs, and
        # `ci-local.sh cross-arm`, which `release` runs, reads them from here.
        rows = gate.cross_matrix_arm(gate.SCHEDULED_YML.read_text())
        self.assertEqual(2, len(rows))
        self.assertIn(
            ("aarch64-unknown-linux-gnu", "gdi-node-standalone", "full"), rows
        )
        self.assertIn(
            ("aarch64-unknown-linux-musl", "gdi-node-standalone", "full"), rows
        )

    def test_the_arm_declared_row_count_matches(self):
        self.assertEqual(
            2, gate.cross_arm_declared_rows(gate.SCHEDULED_YML.read_text())
        )

    def test_the_shipped_arm_matrix_passes_the_guard(self):
        self.assertEqual(
            [], gate.check_cross_matrix_arm(gate.SCHEDULED_YML.read_text())
        )

    def test_a_PARTIALLY_unparseable_arm_matrix_is_reported(self):
        # Same silent-shrink hazard as the x86_64 matrix: one broken row and cross-arm
        # build-verifies fewer aarch64 targets than release.yml ships, while passing.
        sched = gate.SCHEDULED_YML.read_text()
        broken = sched.replace(
            '            crate: gdi-node-standalone\n            features: "full"',
            "",
            1,
        )
        problems = "\n".join(gate.check_cross_matrix_arm(broken))
        self.assertIn("cross-linux-arm", problems)


class GateCoverage(unittest.TestCase):
    def test_a_fully_wired_workflow_passes(self):
        self.assertEqual([], gate.check_workflow(WORKFLOW, {"semver-checks"}))

    def test_a_job_missing_from_needs_is_reported(self):
        broken = WORKFLOW.replace("      - rust\n", "")
        problems = "\n".join(gate.check_workflow(broken, {"semver-checks"}))
        self.assertIn("rust", problems)
        self.assertIn("not a dependency of `ci-success`", problems)

    def test_a_stale_needs_entry_is_reported(self):
        broken = WORKFLOW.replace("      - rust\n", "      - rust\n      - ghost\n")
        problems = "\n".join(gate.check_workflow(broken, {"semver-checks"}))
        self.assertIn("ghost", problems)


class SilentGates(unittest.TestCase):
    def test_an_unexpected_job_level_if_is_reported(self):
        """`ci-success` tolerates `skipped`, so a new `if:` on a gate must be declared."""
        broken = WORKFLOW.replace(
            "  rust:\n    runs-on: ubuntu-latest\n",
            "  rust:\n    runs-on: ubuntu-latest\n    if: github.ref == 'refs/heads/main'\n",
        )
        problems = "\n".join(gate.check_workflow(broken, {"semver-checks"}))
        self.assertIn("rust", problems)
        self.assertIn("if:", problems)

    def test_an_unexpected_continue_on_error_is_reported(self):
        broken = WORKFLOW.replace(
            "  rust:\n    runs-on: ubuntu-latest\n",
            "  rust:\n    runs-on: ubuntu-latest\n    continue-on-error: true\n",
        )
        problems = "\n".join(gate.check_workflow(broken, {"semver-checks"}))
        self.assertIn("continue-on-error", problems)

    def test_a_stale_allowlist_entry_is_reported(self):
        """If semver-checks loses its `if:`, the allowlist entry must be removed."""
        fixed = WORKFLOW.replace("    if: github.event_name == 'pull_request'\n", "")
        problems = "\n".join(gate.check_workflow(fixed, {"semver-checks"}))
        self.assertIn("no longer", problems)

    def test_ci_success_without_always_is_reported(self):
        broken = WORKFLOW.replace(
            "  ci-success:\n    name: ci-success\n    if: always()\n",
            "  ci-success:\n    name: ci-success\n",
        )
        problems = "\n".join(gate.check_workflow(broken, {"semver-checks"}))
        self.assertIn("always()", problems)


class ToolchainCoherence(unittest.TestCase):
    """Only one direction is a defect: a declared MSRV above the toolchain CI builds with.

    `MSRV == pin` and `MSRV < pin` are both legitimate configurations, so a guard that
    rejected the second would block a policy change. `MSRV > pin` is broken: cargo refuses
    to build the package at all.
    """

    def test_msrv_equal_to_the_pin_passes(self):
        self.assertEqual(
            [], gate.check_toolchain('channel = "1.96.0"', 'rust-version = "1.96"')
        )

    def test_msrv_below_the_pin_passes(self):
        """The conservative policy: dev on 1.96, floor at 1.90, `msrv` job tests the floor."""
        self.assertEqual(
            [], gate.check_toolchain('channel = "1.96.0"', 'rust-version = "1.90"')
        )

    def test_msrv_above_the_pin_is_reported(self):
        """Unbuildable: cargo refuses a package whose rust-version exceeds the toolchain."""
        problems = "\n".join(
            gate.check_toolchain('channel = "1.96.0"', 'rust-version = "1.99"')
        )
        self.assertIn("1.99", problems)
        self.assertIn("1.96", problems)

    def test_a_patch_difference_is_fine(self):
        self.assertEqual(
            [], gate.check_toolchain('channel = "1.96.3"', 'rust-version = "1.96"')
        )

    def test_unparseable_input_is_reported(self):
        self.assertNotEqual([], gate.check_toolchain("", 'rust-version = "1.96"'))

    def test_the_msrv_job_is_a_tautology_only_when_they_are_equal(self):
        self.assertTrue(
            gate.msrv_job_is_degenerate('channel = "1.96.0"', 'rust-version = "1.96"')
        )
        self.assertFalse(
            gate.msrv_job_is_degenerate('channel = "1.96.0"', 'rust-version = "1.90"')
        )


class BuilderImageMatchesThePin(unittest.TestCase):
    """The Dockerfile's `FROM rust:<ver>` and `rust-toolchain.toml` are two copies of one
    fact that cannot be single-sourced, because a Dockerfile cannot read another file, so
    the agreement is asserted. Drift ships a binary built by a compiler no gate ever ran.
    """

    DOCKERFILE = "FROM rust:1.97.1-trixie@sha256:abc AS builder\nWORKDIR /build\n"

    def test_an_exact_match_passes(self):
        self.assertEqual(
            [], gate.check_builder_image('channel = "1.97.1"', self.DOCKERFILE)
        )

    def test_a_two_component_tag_matches_a_three_component_pin(self):
        """`rust:1.97-trixie` is a legitimate way to write the same minor series."""
        self.assertEqual(
            [],
            gate.check_builder_image(
                'channel = "1.97.1"', "FROM rust:1.97-trixie@sha256:abc AS builder\n"
            ),
        )

    def test_a_patch_difference_is_fine(self):
        """The digest beside the tag is what actually fixes the image."""
        self.assertEqual(
            [], gate.check_builder_image('channel = "1.97.0"', self.DOCKERFILE)
        )

    def test_a_minor_drift_is_reported(self):
        """The case this guard exists for: the pin moved, the Dockerfile did not."""
        problems = "\n".join(
            gate.check_builder_image(
                'channel = "1.97.1"', "FROM rust:1.96-trixie AS builder\n"
            )
        )
        self.assertIn("1.96", problems)
        self.assertIn("1.97.1", problems)

    def test_unparseable_input_is_reported(self):
        self.assertNotEqual([], gate.check_builder_image('channel = "1.97.1"', ""))
        self.assertNotEqual([], gate.check_builder_image("", self.DOCKERFILE))


class AboutTargetsMatchTheReleaseMatrix(unittest.TestCase):
    """`about.toml`'s `targets` is a second copy of the release matrix that cargo-about
    cannot derive, since it reads only its own config, so the agreement is asserted. Both
    directions matter: a missing target under-attributes a shipped artifact, and an extra
    one attributes a platform nobody receives.
    """

    RELEASE = """
jobs:
  build:
    strategy:
      matrix:
        include:
          - name: a
            target: x86_64-unknown-linux-gnu
          - name: b
            target: aarch64-apple-darwin
    steps:
      - uses: dtolnay/rust-toolchain@abc
        with:
          targets: ${{ matrix.target }}
"""
    ABOUT = 'accepted = [\n  "MIT",\n]\n\ntargets = [\n    "x86_64-unknown-linux-gnu",\n    "aarch64-apple-darwin",\n]\n'

    def test_matching_sets_pass(self):
        self.assertEqual([], gate.check_about_targets(self.RELEASE, self.ABOUT))

    def test_the_plural_toolchain_key_is_not_mistaken_for_a_matrix_target(self):
        """`targets: ${{ matrix.target }}` is an action input, not a shipped target."""
        self.assertEqual(
            {"x86_64-unknown-linux-gnu", "aarch64-apple-darwin"},
            gate._release_matrix_targets(self.RELEASE),
        )

    def test_a_shipped_target_missing_from_about_is_reported(self):
        """The licensing defect: an artifact ships whose crates were never resolved."""
        thin = self.ABOUT.replace('    "aarch64-apple-darwin",\n', "")
        problems = "\n".join(gate.check_about_targets(self.RELEASE, thin))
        self.assertIn("aarch64-apple-darwin", problems)
        self.assertIn("about.toml does not list it", problems)

    def test_a_dropped_platform_left_in_about_is_reported(self):
        """A platform dropped from the release matrix but left behind in about.toml."""
        stale = self.ABOUT.replace(
            "targets = [\n", 'targets = [\n    "x86_64-apple-darwin",\n'
        )
        problems = "\n".join(gate.check_about_targets(self.RELEASE, stale))
        self.assertIn("x86_64-apple-darwin", problems)
        self.assertIn("ships no such", problems)

    def test_the_accepted_licence_list_is_not_read_as_targets(self):
        """A looser array match would conflate `accepted = [...]` with `targets`."""
        self.assertEqual(
            {"x86_64-unknown-linux-gnu", "aarch64-apple-darwin"},
            gate._about_targets(self.ABOUT),
        )

    def test_unparseable_input_is_reported(self):
        self.assertNotEqual(
            [], gate.check_about_targets(self.RELEASE, "accepted = []\n")
        )
        self.assertNotEqual([], gate.check_about_targets("jobs:\n", self.ABOUT))


class ShippedFiles(unittest.TestCase):
    """The real ci.yml / rust-toolchain.toml / Cargo.toml must satisfy every check."""

    def test_the_repo_passes_its_own_gate_guard(self):
        self.assertEqual([], gate.main_problems())


SH = """\
need() {
  command -v "$1" >/dev/null 2>&1 || die "required tool '$1' not found. install with: $2"
}
pip_audit() {
  step "pip-audit (all features, private items)"
  need uv "https://docs.astral.sh/uv/"
}
deny() {
  need cargo-deny "https://example.org"
}
supply_chain() { deny; pip_audit; }
doc() {
  step "rustdoc; all features, private items"
  run env RUSTDOCFLAGS='-D warnings' cargo doc --all-features
}
all() { supply_chain; doc; }
dispatch() {
  case "$1" in
    supply-chain)      supply_chain ;;
    doc|doctests)      doc ;;
    all)               all ;;
  esac
}
"""

JOB_WITHOUT_UV = """
name: ci
on: [push]
jobs:
  supply-chain:
    runs-on: ubuntu-latest
    steps:
      - uses: taiki-e/install-action@aaaa
        with: { tool: cargo-deny@0.20.2 }
      - run: ./scripts/ci-local.sh supply-chain
"""

JOB_WITH_UV = JOB_WITHOUT_UV.replace(
    "      - run: ./scripts/ci-local.sh supply-chain",
    "      - uses: taiki-e/install-action@aaaa\n"
    "        with: { tool: uv }\n"
    "      - run: ./scripts/ci-local.sh supply-chain",
)


class LegToolProvisioningTest(unittest.TestCase):
    """The guard that would have caught `uv` missing from the supply-chain job."""

    def test_a_transitively_needed_tool_that_is_not_installed_is_reported(self):
        # `supply_chain` never says `uv`; it reaches it through `pip_audit`. That is the
        # whole point: the job installs what the leg's name suggests and misses the rest.
        problems = gate.check_leg_tool_provisioning([("ci.yml", JOB_WITHOUT_UV)], SH)
        self.assertTrue(any("`uv`" in p for p in problems), problems)
        self.assertFalse(any("cargo-deny" in p for p in problems), problems)

    def test_installing_the_tool_clears_it(self):
        self.assertEqual(
            gate.check_leg_tool_provisioning([("ci.yml", JOB_WITH_UV)], SH), []
        )

    def test_a_quoted_parenthesis_is_not_read_as_a_call_to_the_all_aggregate(self):
        # `doc`'s step banner contains "(all features, …)". Splitting on the parenthesis
        # made the word `all` look like a call to the run-everything aggregate, which
        # attributed every tool in the script to the `doctests` job.
        job = JOB_WITHOUT_UV.replace(
            "./scripts/ci-local.sh supply-chain", "./scripts/ci-local.sh doc"
        )
        self.assertEqual(gate.check_leg_tool_provisioning([("ci.yml", job)], SH), [])

    def test_a_word_in_a_comment_is_not_read_as_a_call(self):
        sh = SH.replace("doc() {", "doc() {\n  # see pip_audit for the uv rationale")
        job = JOB_WITHOUT_UV.replace(
            "./scripts/ci-local.sh supply-chain", "./scripts/ci-local.sh doc"
        )
        self.assertEqual(gate.check_leg_tool_provisioning([("ci.yml", job)], sh), [])

    def test_comparing_nothing_is_a_failure_not_a_pass(self):
        # The shape this guard could fail silently in: no step matches the invocation
        # pattern, every loop body is skipped, and an empty problem list reads as green.
        job = JOB_WITHOUT_UV.replace("./scripts/ci-local.sh supply-chain", "make test")
        problems = gate.check_leg_tool_provisioning([("ci.yml", job)], SH)
        self.assertTrue(any("matched zero" in p for p in problems), problems)

    def test_an_unparsable_script_is_a_failure_not_a_pass(self):
        problems = gate.check_leg_tool_provisioning([("ci.yml", JOB_WITH_UV)], "")
        self.assertTrue(any("vacuous" in p for p in problems), problems)

    def test_the_shipped_workflows_provision_every_tool_their_legs_need(self):
        texts = [
            (p.name, p.read_text(encoding="utf-8"))
            for p in (
                gate.CI_YML,
                gate.SCHEDULED_YML,
                gate.E2E_FULL_YML,
                gate.RELEASE_YML,
            )
            if p.is_file()
        ]
        sh = gate.CI_LOCAL_SH.read_text(encoding="utf-8")
        self.assertEqual(gate.check_leg_tool_provisioning(texts, sh), [])


SH_PIP = "PIP_AUDIT_VERSION='2.10.1'\n"

JOB_PINNED = """
name: ci
on: [push]
jobs:
  conformance:
    runs-on: ubuntu-latest
    steps:
      - run: |
          "$RUNNER_TEMP/audit-venv/bin/pip" install --upgrade pip 'pip-audit==2.10.1'
          "$RUNNER_TEMP/audit-venv/bin/pip-audit" --strict -r conformance/requirements.lock
"""


class PipAuditPinTest(unittest.TestCase):
    """A workflow cannot read `PIP_AUDIT_VERSION` out of ci-local.sh, so the pin is a real
    duplicate and only a check can hold the copies together."""

    def test_a_matching_pin_passes(self):
        self.assertEqual(gate.check_pip_audit_pin([("ci.yml", JOB_PINNED)], SH_PIP), [])

    def test_a_drifted_pin_names_both_versions(self):
        job = JOB_PINNED.replace("pip-audit==2.10.1", "pip-audit==9.9.9")
        problems = gate.check_pip_audit_pin([("ci.yml", job)], SH_PIP)
        self.assertTrue(any("9.9.9" in p and "2.10.1" in p for p in problems), problems)

    def test_an_unpinned_install_is_reported(self):
        job = JOB_PINNED.replace("'pip-audit==2.10.1'", "pip-audit")
        problems = gate.check_pip_audit_pin([("ci.yml", job)], SH_PIP)
        self.assertTrue(any("without a version" in p for p in problems), problems)

    def test_the_invocation_line_is_not_read_as_an_unpinned_install(self):
        # `bin/pip-audit` on the *run* line has no `==`; the lookbehind must keep it from
        # being reported, or the guard cries wolf on every correct workflow.
        self.assertEqual(gate.check_pip_audit_pin([("ci.yml", JOB_PINNED)], SH_PIP), [])

    def test_comparing_nothing_is_a_failure_not_a_pass(self):
        job = JOB_PINNED.replace("'pip-audit==2.10.1'", "wheel").replace(
            '"$RUNNER_TEMP/audit-venv/bin/pip-audit" --strict -r conformance/requirements.lock',
            "true",
        )
        problems = gate.check_pip_audit_pin([("ci.yml", job)], SH_PIP)
        self.assertTrue(any("compared nothing" in p for p in problems), problems)

    def test_an_unreadable_version_is_a_failure_not_a_pass(self):
        problems = gate.check_pip_audit_pin([("ci.yml", JOB_PINNED)], "")
        self.assertTrue(
            any("nothing to be compared against" in p for p in problems), problems
        )

    def test_the_shipped_workflows_agree_with_ci_local(self):
        texts = [
            (p.name, p.read_text(encoding="utf-8"))
            for p in (
                gate.CI_YML,
                gate.SCHEDULED_YML,
                gate.E2E_FULL_YML,
                gate.RELEASE_YML,
            )
            if p.is_file()
        ]
        self.assertEqual(
            gate.check_pip_audit_pin(
                texts, gate.CI_LOCAL_SH.read_text(encoding="utf-8")
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
