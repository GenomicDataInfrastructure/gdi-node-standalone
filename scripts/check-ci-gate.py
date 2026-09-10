#!/usr/bin/env python3
"""Guard the CI gate graphs themselves.

Two aggregate jobs decide whether anyone ever hears about a failure:

* ``ci-success`` in ``ci.yml``, the one required check for branch protection. It
  ``needs:`` every gate, runs ``if: always()``, and fails when a dependency reports
  ``failure``/``cancelled``.
* ``notify`` in ``scheduled.yml`` and ``e2e-full.yml``, which opens an assignable
  tracking issue when a cron run fails, because a scheduled-failure email is easy to miss
  and cannot be assigned.

Three ways a gate goes quiet without anything turning red, all three applying to both:

1. A new job is added and never wired into the aggregate's ``needs:``. It runs, it can
   fail, and nothing blocks the merge or opens the issue.
2. A gate gains a job-level ``if:``. On the path where the condition is false it reports
   ``skipped``, which the aggregate tolerates (``semver-checks`` is PR-only). A gate that
   stops matching its own condition stops enforcing.
3. A gate gains ``continue-on-error: true``. Its ``needs.*.result`` is then ``success``
   even when it fails.

The last two are escape hatches, and each carries an explicit allowlist checked for
staleness in both directions.

The skippable allowlist is not duplicated. ``ci-success`` needs it at runtime, so the
workflow owns it as the ``ALLOWED_SKIPS`` env value and this script reads it back. A guard
over two copies of one fact drifts with the fact.

It also asserts cross-file invariants: facts duplicated across files that no tool can
single-source.

* The declared ``rust-version`` must not exceed the ``rust-toolchain.toml`` pin. A
  toolchain file outranks ``rustup default`` (though not ``RUSTUP_TOOLCHAIN``), so the pin
  is what CI compiles with, and cargo refuses a package whose ``rust-version`` is above the
  active toolchain. An MSRV below the pin is the conservative configuration and is allowed.
* The Dockerfile's ``FROM rust:<ver>`` builder must match that pin. A Dockerfile cannot
  read a version out of another file, so this copy cannot be deleted. The pin governs every
  gated ``cargo`` invocation while the Dockerfile governs the shipped binary; drift means
  the release artifact was built by a compiler no gate ever ran.
* ``about.toml``'s ``targets`` list must equal the set of targets ``release.yml`` ships.
  cargo-about reads only its own config, so that list is a second copy of the release
  matrix. A mismatch either under-attributes a shipped artifact (a licensing problem) or
  attributes a platform nobody receives.
* Every ``-r <file>`` in a workflow must name the hash-locked ``.lock``, and every
  ``pip install`` of one must pass ``--require-hashes``. The ``.txt`` beside it has no
  artifact hashes, so installing from it resolves transitives live.
* Each ``conformance/requirements*.txt`` pin must appear in its ``.lock``. The workflows
  install the lock, so a bump that edits only the ``.txt`` would otherwise pass while
  having no effect. ``ci-local.sh`` checks this too, but only from ``ensure_venv``, which
  no workflow job calls.
* ``ci.yml`` must set ``C4GH_INTEROP_REQUIRED``. Without it a missing reference venv makes
  every crypt4gh interop test skip, and a skip passes, so the job's ``expected=7`` count
  guard is satisfied by seven tests that verified nothing.
* Every job that runs ``ci-local.sh <leg>`` must provision every tool that leg ``need``s,
  transitively. ``need`` is a hard ``die``, not a skip, and the dependency can be reached
  through a helper the job's name never mentions: ``supply-chain`` reaches ``uv`` via
  ``pip_audit``. The failure is invisible on a developer machine that has the tool on
  ``PATH`` and fails every run on a runner that does not.
* Every workflow ``pip-audit==<v>`` must equal ``ci-local.sh``'s ``PIP_AUDIT_VERSION``, and
  no job may install pip-audit unpinned. A workflow cannot read a shell variable out of
  that script, so this pin is genuinely duplicated.
* ``ci.yml``'s conformance ``min=<n>`` floor must stay readable, because
  ``scripts/ci-local.sh`` resolves it at runtime via ``--conformance-floor`` instead of
  keeping a second copy. The literal lives in the workflow and the local gate reads it
  back, the same shape as ``--glibc-floor``.

Pure stdlib (no PyYAML): the workflows' shape is fixed and line-oriented.
Exit: 0 = clean, 1 = problem, 2 = IO error.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CI_YML = ROOT / ".github/workflows/ci.yml"
SCHEDULED_YML = ROOT / ".github/workflows/scheduled.yml"
E2E_FULL_YML = ROOT / ".github/workflows/e2e-full.yml"
TOOLCHAIN_TOML = ROOT / "rust-toolchain.toml"
CARGO_TOML = ROOT / "Cargo.toml"
DOCKERFILE = ROOT / "Dockerfile"
RELEASE_YML = ROOT / ".github/workflows/release.yml"
ABOUT_TOML = ROOT / "about.toml"
DENY_TOML = ROOT / "deny.toml"

AGGREGATE = "ci-success"


def parse_allowed_skips(ci_text):
    """The `ALLOWED_SKIPS` allowlist declared by the `ci-success` step, or `None`.

    Single source: the workflow needs this list at runtime to decide which `skipped`
    results to tolerate, so the workflow owns it and this script reads it back. Widening
    the allowlist is one edit, in one place.
    """
    m = re.search(r'^\s*ALLOWED_SKIPS:\s*"([^"]*)"\s*$', ci_text, re.MULTILINE)
    return set(m.group(1).split()) if m else None


# Jobs permitted to carry `continue-on-error: true`: they report `success` to their
# aggregate even when they fail. Script-side, because nothing consumes them at runtime, so
# there is nothing to duplicate. One allowlist per workflow; every entry needs a reason.
CI_ADVISORY = {
    "semver-checks": "advisory: these crates have no external/versioned consumer yet, so a "
    "semver break is a review signal rather than a merge blocker",
}
SCHEDULED_ADVISORY = {
    "benches": "advisory microbenchmarks; they gate nothing and are noisy on shared runners",
    "coverage": "report-only; a coverage dip is a review signal, not a weekly failure",
}
E2E_SKIPPABLE = {
    "e2e-smoke-full": "runs on schedule/dispatch always, but on a PR only when it carries "
    "the `full-e2e` label",
    "chaos": "same gating as e2e-smoke-full: schedule/dispatch always, on a PR only with "
    "the `full-e2e` label",
}

# Cron workflows whose every job must be wired into a failure-surfacing `notify` job, with
# the silent-gate allowlists that apply to each: (path, aggregate, skippable, advisory).
NOTIFY_WORKFLOWS = (
    (SCHEDULED_YML, "notify", set(), SCHEDULED_ADVISORY),
    (E2E_FULL_YML, "notify", set(E2E_SKIPPABLE), {}),
)


@dataclass
class Job:
    """A top-level job and the two properties that can make it stop gating."""

    name: str
    conditional: bool  # carries a job-level `if:`
    advisory: bool  # carries `continue-on-error: true`


def workflow_jobs(text):
    """Every top-level job in a workflow, keyed by name.

    Jobs sit at exactly two spaces of indent under ``jobs:``; their own keys at four. A
    step-level ``if:`` lives deeper and must not be read as a job-level one.
    """
    jobs = {}
    in_jobs = False
    current = None
    for line in text.splitlines():
        if re.match(r"^jobs:\s*$", line):
            in_jobs = True
            continue
        if in_jobs and re.match(r"^\S", line):
            break
        if not in_jobs:
            continue
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if m:
            current = m.group(1)
            jobs[current] = Job(current, conditional=False, advisory=False)
            continue
        if current is None:
            continue
        if re.match(r"^    if:", line):
            jobs[current].conditional = True
        elif re.match(r"^    continue-on-error:\s*true\s*$", line):
            jobs[current].advisory = True
    return jobs


def _job_block(text, job):
    """The raw text of one job's body, or `None`."""
    marker = f"\n  {job}:\n"
    if marker not in text:
        return None
    block = text[text.index(marker) + len(marker) :]
    nxt = re.search(r"\n  [A-Za-z0-9_-]+:\n", block)
    return block[: nxt.start()] if nxt else block


def job_needs(text, job):
    """The job names a job depends on, in order.

    Handles both YAML forms this repo uses: the inline flow list
    (``needs: [fuzz, canary]``, as in ``scheduled.yml``) and the block list (``needs:``
    then ``- lint``, as in ``ci.yml``).
    """
    block = _job_block(text, job)
    if block is None or "needs:" not in block:
        return []
    after = block[block.index("needs:") + len("needs:") :]
    head = after.splitlines()[0].strip()
    if head.startswith("["):
        inner = head[1 : head.index("]")] if "]" in head else head[1:]
        return [x.strip() for x in inner.split(",") if x.strip()]
    out = []
    for line in after.splitlines()[1:]:
        m = re.match(r"^\s+- (\S+)\s*$", line)
        if m:
            out.append(m.group(1))
        elif line.strip():
            break
    return out


def ci_success_needs(text):
    """The job names listed under ``ci-success``'s ``needs:``, in order."""
    return job_needs(text, AGGREGATE)


def _coverage_problems(gates, needs, aggregate, workflow):
    """Jobs the aggregate does not depend on, and dependencies that are not jobs."""
    problems = []
    for missing in sorted(gates - needs):
        problems.append(
            f"UNGATED JOB: `{workflow}` job `{missing}` is not a dependency of "
            f"`{aggregate}`, so its failure is never surfaced. Add it to `{aggregate}`'s "
            "`needs:` list."
        )
    for ghost in sorted(needs - gates):
        problems.append(
            f"STALE NEEDS: `{workflow}` job `{aggregate}` depends on `{ghost}`, which is "
            "not a job in that workflow. Remove it."
        )
    return problems


def _silent_gate_problems(jobs, gates, aggregate, workflow, skippable, advisory):
    """Un-allowlisted `if:` / `continue-on-error` on a gate, plus stale allowlist entries."""
    problems = []
    for name in sorted(n for n in gates if jobs[n].conditional and n not in skippable):
        problems.append(
            f"SILENT GATE: `{workflow}` job `{name}` carries a job-level `if:`, so it can "
            f"report `skipped`, which `{aggregate}` tolerates. A gate that stops matching "
            "its own condition stops enforcing. Allowlist it if that is intended."
        )
    for name in sorted(n for n in gates if jobs[n].advisory and n not in advisory):
        problems.append(
            f"SILENT GATE: `{workflow}` job `{name}` carries `continue-on-error: true`, so "
            f"it reports `success` to `{aggregate}` even when it fails. Allowlist it "
            "with a reason if that is intended."
        )
    for name in sorted(skippable):
        if name in gates and not jobs[name].conditional:
            problems.append(
                f"STALE ALLOWLIST: `{workflow}` job `{name}` is allowlisted as skippable "
                "but no longer carries a job-level `if:`. Remove the entry so a future "
                "`if:` is caught."
            )
    for name in sorted(advisory):
        if name in gates and not jobs[name].advisory:
            problems.append(
                f"STALE ALLOWLIST: `{workflow}` job `{name}` is allowlisted as advisory but "
                "no longer carries `continue-on-error: true`. Remove the entry."
            )
    return problems


def check_workflow(text, skippable):
    """Every gate-integrity problem in `ci.yml`.

    `skippable` is read from the workflow itself (see :func:`parse_allowed_skips`), never
    duplicated here.
    """
    problems = []
    jobs = workflow_jobs(text)
    if AGGREGATE not in jobs:
        return [f"AGGREGATE MISSING: no `{AGGREGATE}` job in the workflow"]

    # The aggregate must run even when a dependency failed, or it cannot observe them.
    if not jobs[AGGREGATE].conditional:
        problems.append(
            f"AGGREGATE: `{AGGREGATE}` must carry `if: always()`, otherwise it is skipped "
            "whenever a dependency fails and the required check never goes red."
        )

    gates = {n for n in jobs if n != AGGREGATE}
    problems += _coverage_problems(
        gates, set(ci_success_needs(text)), AGGREGATE, "ci.yml"
    )
    problems += _silent_gate_problems(
        jobs, gates, AGGREGATE, "ci.yml", skippable, CI_ADVISORY
    )
    return problems


def check_notify_workflow(text, aggregate, workflow, skippable, advisory):
    """Coverage + silent-gate checks for a cron workflow's failure-surfacing `notify` job.

    An unwired job fails on its schedule and opens no tracking issue; a `continue-on-error`
    job reports `success` and never trips `notify` at all. Same defects as `ci.yml`, same
    consequence: a gate goes quiet and nobody is told.
    """
    jobs = workflow_jobs(text)
    if aggregate not in jobs:
        return [f"AGGREGATE MISSING: `{workflow}` has no `{aggregate}` job."]
    gates = {n for n in jobs if n != aggregate}
    return _coverage_problems(
        gates, set(job_needs(text, aggregate)), aggregate, workflow
    ) + _silent_gate_problems(jobs, gates, aggregate, workflow, skippable, advisory)


# A cross matrix row: name -> os -> target -> crate -> features, in that order. Shared by
# the per-PR `cross-compile` job (ci.yml) and the weekly `cross-linux-arm` job
# (scheduled.yml), so the guard and the two `ci-local.sh` legs read one parser, not copies.
_MATRIX_ROW_RE = re.compile(
    r"- name:\s*\S+\s*\n\s*os:\s*\S+\s*\n\s*target:\s*(\S+)\s*\n"
    r"\s*crate:\s*(\S+)\s*\n\s*features:\s*\"([^\"]*)\""
)


def _matrix_rows(block):
    """`(target, crate, features)` triples from a cross matrix job body, in order."""
    # The regex has exactly three capture groups, so `findall` already yields the triples.
    return _MATRIX_ROW_RE.findall(block)


def _declared_rows(block):
    """How many matrix rows a cross job body declares.

    A matrix row is a ``- name:`` immediately followed by ``os:``. That distinguishes it from
    a *step* ``- name:`` (``Install cross``, ``Build (cross…)``, ``glibc floor guard``), which
    would otherwise inflate the count and fire the parse-completeness check below on a
    perfectly good workflow.
    """
    return len(re.findall(r"- name:\s*\S+\s*\n\s*os:\s*\S+", block))


def _cross_block(ci_text):
    """The per-PR `cross-compile` job body, or `""`."""
    return _job_block(ci_text, "cross-compile") or ""


def _cross_arm_block(sched_text):
    """The weekly `cross-linux-arm` job body, or `""`."""
    return _job_block(sched_text, "cross-linux-arm") or ""


def cross_matrix(ci_text):
    """The per-PR `cross-compile` matrix as `(target, crate, features)` triples, in order.

    Single source for `ci-local.sh cross`. Rows copied into a shell script would drift
    from these, and the local build-verify would then cover a different set than CI does.
    """
    return _matrix_rows(_cross_block(ci_text))


def cross_matrix_arm(sched_text):
    """The weekly `cross-linux-arm` matrix (the aarch64-linux legs), as triples, in order.

    Single source for `ci-local.sh cross-arm`, which `release` runs so the local tag gate
    build-verifies the aarch64 targets the per-PR `cross-compile` matrix does not cover.
    """
    return _matrix_rows(_cross_arm_block(sched_text))


def cross_matrix_declared_rows(ci_text):
    """How many rows the per-PR `cross-compile` matrix declares."""
    return _declared_rows(_cross_block(ci_text))


def cross_arm_declared_rows(sched_text):
    """How many rows the weekly `cross-linux-arm` matrix declares."""
    return _declared_rows(_cross_arm_block(sched_text))


def glibc_floor(ci_text):
    """The maximum GLIBC symbol version the gnu artifacts may reference, from `ci.yml`.

    Single-sourced the same way: the `2.28` floor (RHEL/Rocky 8) lives in the workflow's
    guard and `ci-local.sh cross` reads it back.
    """
    m = re.search(r"printf '%s\\n([0-9.]+)\\n'", ci_text)
    return m.group(1) if m else None


def check_lock_tracks_pins():
    """Every `name==version` in a `conformance/requirements*.txt` must appear in its `.lock`.

    The two files are two representations of one fact: the `.lock` is compiled from the
    `.txt` by `uv pip compile`. The duplication cannot be deleted, only asserted.

    It is asserted here rather than only in `scripts/ci-local.sh`, whose equivalent check
    lives in `assert_lock_current` and runs from `ensure_venv`, which no workflow job calls
    (the conformance and crypt4gh jobs build their own venvs inline). Since those jobs
    install the `.lock`, a bump that edits only the `.txt` would install the old pins and
    still pass. This guard runs in both places, so it closes that.

    Mirrors `assert_lock_current`'s PyPI name normalisation (case-fold, `_`/`.` -> `-`).
    """
    problems = []
    for req in sorted(ROOT.glob("conformance/requirements*.txt")):
        lock = req.with_suffix(".lock")
        if not lock.is_file():
            problems.append(
                f"PYTHON PINS: {req.name} has no {lock.name} beside it, but the workflows "
                "install from the lock — regenerate with `uv pip compile --universal "
                f"--generate-hashes {req.name} -o {lock.name}`."
            )
            continue
        lock_text = lock.read_text().lower()
        for raw in req.read_text().splitlines():
            line = raw.split("#", 1)[0].strip()
            m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;]+)$", line)
            if not m:
                continue
            name = re.sub(r"[_.]", "-", m.group(1).lower())
            if not re.search(
                rf"^{re.escape(name)}=={re.escape(m.group(2).lower())}(?=[\s\\]|$)",
                lock_text,
                re.MULTILINE,
            ):
                problems.append(
                    f"PYTHON PINS: {req.name} pins {m.group(1)}=={m.group(2)} but "
                    f"{lock.name} does not. The workflows install the lock, so this bump "
                    "would have no effect in CI. Regenerate: `uv pip compile --universal "
                    f"--generate-hashes {req.name} -o {lock.name}`."
                )
    return problems


def conformance_floor(ci_text):
    """The minimum number of tests the conformance non-triviality suite must discover.

    Single-sourced the same way as :func:`glibc_floor`: the literal lives in the workflow's
    guard and `scripts/ci-local.sh` reads it back via `--conformance-floor`, so the two gates
    cannot disagree about what "enough tests ran" means.
    """
    m = re.search(r"^\s*min=([0-9]+)\s*$", ci_text, re.MULTILINE)
    return m.group(1) if m else None


def check_conformance_floor(ci_text):
    """The floor must stay readable, because `ci-local.sh` resolves it at runtime.

    If the `min=` line is renamed or deleted, the local leg's `$(… --conformance-floor)`
    yields an empty string and its `-ge` comparison would be comparing against nothing.
    Failing here turns that into a loud, early error in the gate that owns the fact.
    """
    if conformance_floor(ci_text) is None:
        return [
            (
                "CONFORMANCE FLOOR: could not read `min=<n>` from ci.yml's conformance "
                "non-triviality step. scripts/ci-local.sh reads that value back via "
                "`--conformance-floor`; without it the local leg has no floor to assert."
            )
        ]
    return []


def _matrix_completeness_problems(block, job, workflow, consumer):
    """Every declared row of a cross matrix `block` must parse, else `consumer` builds less.

    Non-empty is not enough. When a matrix is partly unparseable, some rows parse, the local
    leg loops over the smaller set, and it build-verifies fewer targets than CI while still
    passing. So the parsed count is compared against the declared `- name:` count.
    """
    parsed, declared = len(_matrix_rows(block)), _declared_rows(block)
    if declared == 0:
        return [
            (
                f"CROSS MATRIX: no rows declared in the `{job}` job in {workflow}. {consumer} "
                "reads its target list from there, so an unparseable matrix would make it "
                "build-verify nothing and pass."
            )
        ]
    if parsed != declared:
        return [
            (
                f"CROSS MATRIX: {declared} matrix rows are declared in the `{job}` job in "
                f"{workflow} but only {parsed} parse into (target, crate, features). {consumer} "
                "would silently build-verify the smaller set. Every row needs `name`, `os`, "
                "`target`, `crate` and `features`, in that order."
            )
        ]
    return []


def check_cross_matrix(ci_text):
    """The per-PR `cross-compile` matrix parses fully and the glibc floor is readable."""
    problems = _matrix_completeness_problems(
        _cross_block(ci_text), "cross-compile", "ci.yml", "`ci-local.sh cross`"
    )
    if glibc_floor(ci_text) is None:
        problems.append(
            "CROSS MATRIX: could not read the glibc floor from the `cross-compile` job's "
            "guard in ci.yml. `ci-local.sh cross` reads it from there."
        )
    return problems


def check_cross_matrix_arm(sched_text):
    """The weekly `cross-linux-arm` matrix parses fully. Its rows feed `ci-local.sh
    cross-arm`, which `release` runs, so a shrunken set would under-verify the aarch64
    release."""
    return _matrix_completeness_problems(
        _cross_arm_block(sched_text),
        "cross-linux-arm",
        "scheduled.yml",
        "`ci-local.sh cross-arm`",
    )


def _key(version):
    """`1.96.0` / `1.96` -> `(1, 96)`. The patch component is ignored."""
    parts = version.split(".")
    return tuple(int(p) for p in parts[:2])


def _versions(toolchain_text, cargo_text):
    chan = re.search(r'^\s*channel\s*=\s*"([0-9.]+)"', toolchain_text, re.MULTILINE)
    msrv = re.search(r'^\s*rust-version\s*=\s*"([0-9.]+)"', cargo_text, re.MULTILINE)
    return (chan.group(1) if chan else None, msrv.group(1) if msrv else None)


def check_toolchain(toolchain_text, cargo_text):
    """The declared MSRV must not exceed the toolchain CI actually builds with.

    Only one direction is a defect:

    * ``rust-version > channel`` is broken: cargo refuses the package outright ("rustc
      1.96.0 is not supported by the following package").
    * ``rust-version == channel`` is allowed, but it makes the ``msrv`` job a tautology
      (:func:`msrv_job_is_degenerate`). The floor is a ratchet that sits below the pin.
    * ``rust-version < channel`` is the conservative configuration and is healthy: the
      matrix builds on the newer pin while ``msrv`` verifies the floor. Lowering the MSRV
      below the pin is a legitimate policy change, so this guard allows it.
    """
    chan, msrv = _versions(toolchain_text, cargo_text)
    if not chan or not msrv:
        return [
            (
                "TOOLCHAIN: could not read `channel` from rust-toolchain.toml / `rust-version` "
                "from Cargo.toml"
            )
        ]
    if _key(msrv) > _key(chan):
        return [
            (
                f'TOOLCHAIN: Cargo.toml declares `rust-version = "{msrv}"` but '
                f"rust-toolchain.toml pins `{chan}`. The declared MSRV is above the toolchain "
                "CI builds with, and a rust-toolchain.toml outranks `rustup default`, so "
                "cargo refuses the package outright. Raise the pin, or lower `rust-version`."
            )
        ]
    return []


def check_builder_image(toolchain_text, dockerfile_text):
    """The Dockerfile's `FROM rust:<ver>` builder must match the `rust-toolchain.toml` pin.

    These are two copies of one fact, "the compiler this project builds with", and the
    duplication cannot be deleted: a Dockerfile has no way to read a version out of another
    file, and the tag is needed before any build step could compute one.

    `rust-toolchain.toml` governs every local and CI `cargo` invocation; the Dockerfile
    governs the shipped binary. If they drift, the image is built by a compiler no gate
    ever runs.

    Compared on (major, minor) only: the Dockerfile tag may legitimately be more precise
    (`1.97.1-trixie`) or less (`1.97-trixie`), and the digest pin beside it is what actually
    fixes the image.
    """
    chan = re.search(r'^\s*channel\s*=\s*"([0-9.]+)"', toolchain_text, re.MULTILINE)
    from_ = re.search(
        r"^FROM\s+rust:([0-9]+\.[0-9]+(?:\.[0-9]+)?)", dockerfile_text, re.MULTILINE
    )
    if not chan or not from_:
        return [
            (
                "BUILDER IMAGE: could not read `channel` from rust-toolchain.toml / "
                "`FROM rust:<version>` from the Dockerfile"
            )
        ]
    if _key(chan.group(1)) != _key(from_.group(1)):
        return [
            (
                f"BUILDER IMAGE: the Dockerfile builds with `rust:{from_.group(1)}` but "
                f"rust-toolchain.toml pins `{chan.group(1)}`. The shipped binary would be "
                "compiled by a toolchain no gate leg ever runs. Bump both together (and "
                "re-resolve the image digest beside the tag)."
            )
        ]
    return []


def _uncommented(text):
    """`text` with `#`-to-end-of-line stripped from every line.

    Both YAML comments and shell comments inside `run:` blocks use `#`, and this guard
    reads what the workflow executes, not what it says about itself. Without this, the prose
    "Pin lives in conformance/requirements-crypt4gh.txt" would trip the `-r` check below.
    """
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def check_python_installs(named_texts):
    """Every `-r <file>` in a workflow must name a hash-locked `.lock`, installed with hashes.

    `conformance/requirements*.txt` carries the reviewed top-level pins but no artifact
    hashes; the `.lock` beside it (`uv pip compile --universal --generate-hashes`) pins the
    full transitive closure by hash. Installing from the `.txt` resolves transitives live
    and accepts whatever the index serves, so the supply-chain property the lock provides
    is absent while the step still says "Install pinned deps".

    Two assertions, both scoped to executable text (comments stripped):
      * every `-r <file>` argument names a `.lock`, covering `pip install` and
        `pip-audit`, so the audited closure cannot drift from the installed one; and
      * every `pip install … -r …` also passes `--require-hashes`, since naming the lock
        without that flag re-admits unhashed dists.
    """
    problems = []
    for name, text in named_texts:
        for line in _uncommented(text).splitlines():
            # Scope to pip invocations: `read -r`, `jq -r` and `grep -r` use the same
            # flag, so a bare `-r` scan over the whole workflow is noise. Match `pip`
            # through an optional closing quote, because the workflows invoke it by
            # absolute path as `"$RUNNER_TEMP/fdp-venv/bin/pip" install …`, which a literal
            # `pip install` substring test would miss.
            is_install = re.search(r"""pip["']?\s+install""", line) is not None
            is_audit = "pip-audit" in line
            if not (is_install or is_audit):
                continue
            m = re.search(r"-r\s+(\S+)", line)
            if not m:
                continue
            target = m.group(1)
            if not target.endswith(".lock"):
                problems.append(
                    f"PYTHON PINS: {name} reads requirements from `{target}`, which must be "
                    "the hash-locked `.lock` (regenerate with `uv pip compile --universal "
                    "--generate-hashes <requirements> -o <lock>`). A `.txt` has no artifact "
                    "hashes, so the install resolves transitives live."
                )
            if is_install and "--require-hashes" not in line:
                problems.append(
                    f"PYTHON PINS: {name} has a `pip install … -r …` without "
                    "`--require-hashes`: pip would accept a dist whose hash is not pinned. "
                    f"Line: {line.strip()}"
                )
    return problems


def check_interop_required(ci_text):
    """ci.yml must set `C4GH_INTEROP_REQUIRED` on the crypt4gh interop job.

    `require_venv()` in crates/core/tests/crypt4gh_interop.rs skips when the reference venv
    is absent, and a skipped test passes, so the job's `expected=7` assertion would be
    satisfied by seven tests that ran no reference implementation. The test carries the
    assert that turns this into a hard failure; the flag arms it.

    The flag is asserted here rather than defaulted on, because the skip path is wanted for
    a developer without the venv (see that function's comment), which makes arming it a
    per-call-site decision that is easy to forget.
    """
    if not re.search(r'^\s*C4GH_INTEROP_REQUIRED:\s*"?1"?\s*$', ci_text, re.MULTILINE):
        return [
            (
                'CRYPT4GH GATE: ci.yml does not set `C4GH_INTEROP_REQUIRED: "1"`. Without '
                "it a missing reference venv makes every interop test skip, and a skip "
                "passes, so the `expected=7` count guard would be satisfied by seven tests "
                "that verified nothing."
            )
        ]
    return []


def _release_matrix_targets(release_text):
    """Every `target:` value in release.yml's build matrix.

    Matches the singular `target:` key only. The `targets:` (plural) input on the
    rust-toolchain action is a different thing and must not be picked up.
    """
    return set(re.findall(r"^\s+target:\s*(\S+)", release_text, re.MULTILINE))


def _about_targets(about_text):
    """The `targets = [...]` list from about.toml, or `None` if absent.

    Anchored on `targets` specifically: about.toml also carries an `accepted = [...]`
    licence list, and a looser array match would silently conflate the two.
    """
    m = re.search(r"^targets\s*=\s*\[(.*?)^\]", about_text, re.MULTILINE | re.DOTALL)
    return set(re.findall(r'"([^"]+)"', m.group(1))) if m else None


def _toml_string_list(text, key):
    """The `key = [...]` array of strings from a TOML text, or `None` if absent.

    Anchored on the key at line start so `allow`/`accepted` cannot match a similarly
    named key nested in another table.
    """
    m = re.search(
        rf"^{re.escape(key)}\s*=\s*\[(.*?)^\]", text, re.MULTILINE | re.DOTALL
    )
    return set(re.findall(r'"([^"]+)"', m.group(1))) if m else None


def check_licence_allowlists(deny_text, about_text):
    """`deny.toml`'s `[licenses].allow` and `about.toml`'s `accepted` must agree.

    They are two copies of one policy read by two different tools: `cargo deny` fails the
    build on a licence outside `allow`, while `cargo about` refuses to render a bundle
    containing one outside `accepted`.

    Divergence is silent until it is expensive, and asymmetric:

    * a licence in `allow` but not in `accepted` passes the supply-chain gate and then
      fails the `licenses` leg during a release, when the bundle cannot be rendered;
    * a licence in `accepted` but not in `allow` is worse: the attribution bundle documents
      a licence the project's own policy forbids shipping.

    Single-sourcing is not available (each tool reads only its own config), so assert.
    """
    allow = _toml_string_list(deny_text, "allow")
    accepted = _toml_string_list(about_text, "accepted")
    if allow is None:
        return ["LICENCE LISTS: could not read `allow = [...]` from deny.toml"]
    if accepted is None:
        return ["LICENCE LISTS: could not read `accepted = [...]` from about.toml"]
    problems = []
    for missing in sorted(allow - accepted):
        problems.append(
            f"LICENCE LISTS: deny.toml allows `{missing}` but about.toml does not accept "
            f"it, so a crate under it fails the release `licenses` leg when the "
            f"attribution bundle is rendered."
        )
    for extra in sorted(accepted - allow):
        problems.append(
            f"LICENCE LISTS: about.toml accepts `{extra}` but deny.toml does not allow "
            f"it, so the attribution bundle would document a licence this project's own "
            f"policy refuses to ship."
        )
    return problems


def check_about_targets(release_text, about_text):
    """about.toml's `targets` must equal the set of targets release.yml ships.

    That list is a second copy of the release matrix, and it cannot be single-sourced:
    cargo-about reads only its own config and has no way to see a workflow file.

    Both directions are defects, for different reasons:

    * a target in release.yml but not in about.toml ships an artifact whose
      platform-specific crates were never licence-resolved, so THIRD-PARTY-LICENSES.md
      under-attributes what is distributed, which is a legal problem;
    * a target in about.toml but not in release.yml inflates the bundle with attribution
      for something nobody receives, and is the fingerprint of a dropped platform whose
      config was left behind.
    """
    rel = _release_matrix_targets(release_text)
    about = _about_targets(about_text)
    if about is None:
        return [
            "ABOUT TARGETS: could not read a `targets = [...]` list from about.toml"
        ]
    if not rel:
        return [
            "ABOUT TARGETS: no `target:` entries found in release.yml's build matrix"
        ]
    problems = []
    for missing in sorted(rel - about):
        problems.append(
            f"ABOUT TARGETS: release.yml ships `{missing}` but about.toml does not list it, "
            "so THIRD-PARTY-LICENSES.md omits that platform's crates and the shipped "
            "artifact is under-attributed. Add it to `targets` in about.toml and regenerate "
            "(`scripts/ci-local.sh licenses`)."
        )
    for extra in sorted(about - rel):
        problems.append(
            f"ABOUT TARGETS: about.toml lists `{extra}` but release.yml ships no such "
            "target, so the attribution bundle covers a platform nobody receives, usually a "
            "dropped platform whose config was left behind. Remove it and regenerate "
            "(`scripts/ci-local.sh licenses`)."
        )
    return problems


def msrv_job_is_degenerate(toolchain_text, cargo_text):
    """True when the declared MSRV equals the dev pin, so `msrv` re-checks one compiler.

    Not a defect by itself, but under the ratchet policy the floor should sit below the
    pin. Surfaced so nobody reads a green `msrv` job as evidence that an older rustc still
    builds the workspace.
    """
    chan, msrv = _versions(toolchain_text, cargo_text)
    if not chan or not msrv:
        return False
    return _key(chan) == _key(msrv)


def _missing(path, consequence):
    """A required input that is absent.

    Reported as a problem, never skipped: behind an `is_file()` guard, deleting or
    renaming the artifact would remove its check while this script still printed ok. If an
    artifact is retired, retire its check here in the same change.
    """
    return f"MISSING: {path} does not exist, so its check did not run. {consequence}"


# Tools present on GitHub's `ubuntu-*` runner images with no install step. Anything else a
# leg `need`s must be provisioned by the job that invokes it. Deliberately short: the
# failure this guard exists for is a job that installs the tools it can see in the leg's
# name and misses one the leg reaches through a helper, so a generous builtin list would
# reintroduce exactly that blind spot.
RUNNER_BUILTIN_TOOLS = frozenset(
    {"bash", "curl", "docker", "git", "jq", "objdump", "python3", "rustup"}
)

CI_LOCAL_SH = ROOT / "scripts/ci-local.sh"


def _shell_functions(sh_text):
    """`name` -> body text, for every function defined at column 0 in ci-local.sh.

    Both shapes the script uses: a one-liner (`supply_chain() { deny; pip_audit; }`) and a
    block ending in a `}` on its own line. Missing the one-liner form would drop
    `supply_chain` itself, which is the aggregate this guard most needs to follow.
    """
    bodies, name, buf = {}, None, []
    for line in sh_text.splitlines():
        if name is None:
            m = re.match(r"^([a-z_][a-z0-9_]*)\(\)\s*\{(.*)$", line)
            if not m:
                continue
            rest = m.group(2)
            if rest.rstrip().endswith("}"):
                bodies[m.group(1)] = rest.rstrip()[:-1]
            else:
                name, buf = m.group(1), [rest]
            continue
        if line == "}":
            bodies[name], name, buf = "\n".join(buf), None, []
        else:
            buf.append(line)
    return bodies


def _leg_dispatch(sh_text):
    """CLI leg name -> shell function, read from ci-local.sh's own `case` dispatcher."""
    out = {}
    for m in re.finditer(
        r"^\s+([a-z0-9][a-z0-9|_-]*)\)\s+([a-z_][a-z0-9_]*)\s*;;", sh_text, re.MULTILINE
    ):
        for alias in m.group(1).split("|"):
            out[alias] = m.group(2)
    return out


def _called_names(body):
    """Identifiers in command position, so a word inside a comment is not read as a call.

    Comment lines are dropped, quoted spans are blanked, and each line is split on the
    shell's command separators; the first token of each fragment is the command.

    Both filters earn their place. Without the comment drop, the word "secrets" in prose
    pulls gitleaks into every leg that mentions it. Without blanking quotes, a `step`
    banner reading `"… (all features, private items)"` splits at the parenthesis and the
    word `all` is read as a call to the run-everything aggregate, which then attributes
    *every* tool in the script to that leg. Parentheses are therefore not separators here:
    in this script they appear inside message strings far more often than as syntax.
    """
    names = set()
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        stripped = re.sub(r"'[^']*'|\"[^\"]*\"", " ", stripped)
        for frag in re.split(r"[;&|]+", stripped):
            tok = frag.strip().split(" ", 1)[0]
            if re.fullmatch(r"[a-z_][a-z0-9_]*", tok):
                names.add(tok)
    return names


def _tools_for(func, bodies, seen=None):
    """Every tool `func` `need`s, following its calls to other functions in the script."""
    if seen is None:
        seen = set()
    if func in seen or func not in bodies:
        return set()
    seen.add(func)
    body = bodies[func]
    tools = set()
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        # Split on command separators first: a one-liner body such as
        # `quick() { need python3 <url>; fmt; clippy_lite; script_tests; }` is one line, so
        # matching only at its start would see at most the first `need`.
        for frag in re.split(r"[;&|]+", stripped):
            m = re.match(r"^need\s+([A-Za-z0-9_.-]+)", frag.strip())
            if m:
                tools.add(m.group(1))
    for callee in _called_names(body):
        if callee != func:
            tools |= _tools_for(callee, bodies, seen)
    return tools


def _provisioned_tools(job_block):
    """Tools a job installs, across the shapes this repo uses."""
    tools = set()
    # taiki-e/install-action, inline (`with: { tool: nextest@0.9.143 }`) and block form.
    for m in re.finditer(r"\btool:\s*\{?\s*([^\n}#]+)", job_block):
        for raw in m.group(1).split(","):
            item = raw.strip().strip("'\"")
            if item:
                tools.add(item.split("@", 1)[0])
    # `cargo install <tool> --version …` inside a run block.
    tools |= set(re.findall(r"\bcargo install\s+([A-Za-z0-9_-]+)", job_block))
    if "dtolnay/rust-toolchain" in job_block:
        tools |= {"rustup", "cargo"}
    # An explicit declaration, for a tool installed by a shell step this parser cannot
    # recognise: teaching it every install idiom would fail open on the next one invented.
    # The marker alone is not enough, though, or deleting the install step while leaving the
    # comment would still pass. The tool must also appear outside a comment in the same job.
    non_comment = "\n".join(
        line for line in job_block.splitlines() if not line.lstrip().startswith("#")
    )
    for decl in re.findall(r"#[ \t]*provides:[ \t]*([^\n]+)", job_block):
        for name in re.split(r"[,\s]+", decl.strip()):
            if name and re.search(
                rf"(?<![\w-]){re.escape(name)}(?![\w-])", non_comment
            ):
                tools.add(name)
    return tools


def check_pip_audit_pin(named_texts, sh_text):
    """Every workflow `pip-audit==<v>` must equal ci-local.sh's `PIP_AUDIT_VERSION`.

    A workflow cannot read a shell variable out of ci-local.sh, so this pin is genuinely
    duplicated and the copies can only be held together by a check. Unpinned, the jobs
    fetch and execute whatever PyPI serves that minute; pinned but drifted, CI audits with
    a different scanner than the local gate and the two disagree for no visible reason.
    """
    m = re.search(r"^PIP_AUDIT_VERSION='([^']+)'", sh_text, re.MULTILINE)
    if not m:
        return [
            (
                "PIP-AUDIT PIN: no `PIP_AUDIT_VERSION='…'` found in ci-local.sh, so the "
                "workflow pins have nothing to be compared against. Fix the parser "
                "rather than trusting this pass."
            )
        ]
    want = m.group(1)
    problems = []
    found = 0
    for name, text in named_texts:
        for line_no, line in enumerate(text.splitlines(), 1):
            for got in re.findall(r"pip-audit==([0-9][^'\"\s]*)", line):
                found += 1
                if got != want:
                    problems.append(
                        f"PIP-AUDIT PIN: {name}:{line_no} pins `pip-audit=={got}` but "
                        f"ci-local.sh's PIP_AUDIT_VERSION is `{want}`. CI would audit with "
                        f"a different scanner than the local gate."
                    )
            # Not `pip install …`: every call here goes through a venv path, so the
            # literal is `"$RUNNER_TEMP/audit-venv/bin/pip" install …`. The lookbehind
            # keeps `bin/pip-audit` (the *invocation* on the next line) from being read as
            # an unpinned install, and comment lines are skipped so the prose explaining
            # the pin does not trip the guard that enforces it.
            if (
                not line.lstrip().startswith("#")
                and "install" in line
                and re.search(r"(?<![/\w-])pip-audit\b(?!==)", line)
            ):
                problems.append(
                    f"PIP-AUDIT PIN: {name}:{line_no} installs pip-audit without a version. "
                    f"Pin it to `pip-audit=={want}`, matching ci-local.sh."
                )
    if found == 0 and not problems:
        problems.append(
            "PIP-AUDIT PIN: no workflow pins pip-audit at all, so this guard compared "
            "nothing. Either a job stopped auditing, or the install shape changed."
        )
    return problems


def check_leg_tool_provisioning(named_texts, sh_text):
    """A job that runs a gate leg must install every tool that leg `need`s.

    `need` is a hard `die`, not a skip, so a missing tool fails the job outright — and it
    fails it *late*, after the tools the job did install have already done their work. The
    failure is invisible locally, because a maintainer's machine has the tool on PATH; it
    surfaces only on a runner. It is also transitive: `supply-chain` reaches `uv` through
    `pip_audit`, which the job's name does not mention.
    """
    bodies = _shell_functions(sh_text)
    dispatch = _leg_dispatch(sh_text)
    if not bodies or not dispatch:
        return [
            (
                "LEG TOOLS: could not parse ci-local.sh's function bodies or its `case` "
                "dispatcher, so the provisioning comparison would be vacuous. Fix the "
                "parser rather than trusting this pass."
            )
        ]
    problems = []
    # Legs matched, not (leg, tool) pairs. A leg that legitimately needs no tool beyond the
    # runner's builtins contributes zero pairs, so a pair counter would call a correct
    # single-leg run vacuous. What this counter is really asserting is that the invocation
    # pattern still matches the workflows at all.
    legs_checked = 0
    for name, text in named_texts:
        for job in workflow_jobs(text):
            block = _job_block(text, job)
            if block is None:
                continue
            legs = []
            for m in re.finditer(r"\./scripts/ci-local\.sh\s+([^\n|&;]*)", block):
                for tok in m.group(1).split():
                    if tok in dispatch:
                        legs.append(tok)
                    else:
                        break
            if not legs:
                continue
            have = _provisioned_tools(block)
            for leg in legs:
                legs_checked += 1
                for tool in sorted(_tools_for(dispatch[leg], bodies)):
                    if tool in RUNNER_BUILTIN_TOOLS or tool in have:
                        continue
                    problems.append(
                        f"LEG TOOLS: {name} job `{job}` runs `ci-local.sh {leg}`, which "
                        f"`need`s `{tool}`, but the job provisions no `{tool}`. `need` "
                        f"dies rather than skipping, so this job fails on the runner while "
                        f"passing on any machine that happens to have `{tool}` installed. "
                        f"Add an install step, or add `{tool}` to RUNNER_BUILTIN_TOOLS if "
                        f"the runner image really ships it."
                    )
    if legs_checked == 0:
        problems.append(
            "LEG TOOLS: matched zero gate legs. No workflow step matched "
            "`./scripts/ci-local.sh <leg>`, so this guard checked nothing."
        )
    return problems


def main_problems():
    """Every problem across the shipped files."""
    ci_text = CI_YML.read_text()
    skippable = parse_allowed_skips(ci_text)
    if skippable is None:
        return [
            (
                'ALLOWLIST: no `ALLOWED_SKIPS: "…"` env value found in ci.yml. `ci-success` '
                "must declare which jobs may report `skipped`; this script reads it from there."
            )
        ]
    problems = check_workflow(ci_text, skippable)
    problems += check_cross_matrix(ci_text)
    problems += check_interop_required(ci_text)
    problems += check_conformance_floor(ci_text)
    problems += check_lock_tracks_pins()
    # Every workflow, not just ci.yml: a `-r requirements.txt` is just as unpinned in a
    # release or scheduled job, and those run with more privilege, not less.
    problems += check_python_installs(
        [
            (path.name, path.read_text())
            for path in (CI_YML, SCHEDULED_YML, E2E_FULL_YML, RELEASE_YML)
            if path.is_file()
        ]
    )
    if CI_LOCAL_SH.is_file():
        _workflow_texts = [
            (path.name, path.read_text())
            for path in (CI_YML, SCHEDULED_YML, E2E_FULL_YML, RELEASE_YML)
            if path.is_file()
        ]
        _sh = CI_LOCAL_SH.read_text()
        problems += check_pip_audit_pin(_workflow_texts, _sh)
        problems += check_leg_tool_provisioning(_workflow_texts, _sh)
    else:
        problems.append(
            _missing(
                CI_LOCAL_SH,
                "Gate-leg tool provisioning and the pip-audit pin are unverified.",
            )
        )
    if SCHEDULED_YML.is_file():
        problems += check_cross_matrix_arm(SCHEDULED_YML.read_text())
    else:
        problems.append(_missing(SCHEDULED_YML, "The ARM cross matrix is unverified."))
    problems += check_toolchain(TOOLCHAIN_TOML.read_text(), CARGO_TOML.read_text())
    if DOCKERFILE.is_file():
        problems += check_builder_image(
            TOOLCHAIN_TOML.read_text(), DOCKERFILE.read_text()
        )
    else:
        problems.append(
            _missing(
                DOCKERFILE, "The builder image is no longer pinned to the toolchain."
            )
        )
    if DENY_TOML.is_file() and ABOUT_TOML.is_file():
        problems += check_licence_allowlists(
            DENY_TOML.read_text(), ABOUT_TOML.read_text()
        )
    elif not DENY_TOML.is_file():
        problems.append(_missing(DENY_TOML, "Licence policy is unverified."))
    if RELEASE_YML.is_file() and ABOUT_TOML.is_file():
        problems += check_about_targets(RELEASE_YML.read_text(), ABOUT_TOML.read_text())
    else:
        for path in (RELEASE_YML, ABOUT_TOML):
            if not path.is_file():
                problems.append(
                    _missing(path, "Licence attribution targets are unverified.")
                )
    for path, aggregate, skips, advisory in NOTIFY_WORKFLOWS:
        if path.is_file():
            problems += check_notify_workflow(
                path.read_text(), aggregate, path.name, skips, advisory
            )
        else:
            problems.append(
                _missing(
                    path,
                    f"Its `{aggregate}` failure-notification wiring is unverified.",
                )
            )
    return problems


def main(argv=None):
    """No args: run the guard. `--cross-matrix` (per-PR ci.yml) / `--cross-matrix-arm` (weekly
    scheduled.yml) / `--glibc-floor`: emit a value for `scripts/ci-local.sh cross` /
    `cross-arm`, which must not keep their own copy of the matrix or the floor."""
    argv = sys.argv[1:] if argv is None else argv
    if argv:
        if not CI_YML.is_file():
            print(f"error: missing {CI_YML}", file=sys.stderr)
            return 2
        ci_text = CI_YML.read_text()
        if argv == ["--cross-matrix"]:
            for target, crate, features in cross_matrix(ci_text):
                print(f"{target} {crate} {features}")
            return 0
        if argv == ["--cross-matrix-arm"]:
            if not SCHEDULED_YML.is_file():
                print(f"error: missing {SCHEDULED_YML}", file=sys.stderr)
                return 2
            for target, crate, features in cross_matrix_arm(SCHEDULED_YML.read_text()):
                print(f"{target} {crate} {features}")
            return 0
        if argv == ["--glibc-floor"]:
            floor = glibc_floor(ci_text)
            if floor is None:
                print("error: no glibc floor in ci.yml", file=sys.stderr)
                return 2
            print(floor)
            return 0
        if argv == ["--conformance-floor"]:
            floor = conformance_floor(ci_text)
            if floor is None:
                print("error: no conformance floor in ci.yml", file=sys.stderr)
                return 2
            print(floor)
            return 0
        print(
            f"usage: {sys.argv[0]} [--cross-matrix | --cross-matrix-arm | --glibc-floor "
            "| --conformance-floor]",
            file=sys.stderr,
        )
        return 2

    for path in (CI_YML, TOOLCHAIN_TOML, CARGO_TOML):
        if not path.is_file():
            print(f"error: missing {path}", file=sys.stderr)
            return 2
    problems = main_problems()
    if problems:
        print("\n\n".join(problems), file=sys.stderr)
        return 1

    ci_text = CI_YML.read_text()
    jobs = workflow_jobs(ci_text)
    chan, msrv = _versions(TOOLCHAIN_TOML.read_text(), CARGO_TOML.read_text())
    notified = sum(
        len(workflow_jobs(p.read_text())) - 1
        for p, _, _, _ in NOTIFY_WORKFLOWS
        if p.is_file()
    )
    print(
        f"ok: all {len(jobs) - 1} ci.yml jobs are dependencies of `{AGGREGATE}`; "
        f"{notified} scheduled/e2e jobs are wired into their `notify`; "
        f"skippable allowlist single-sourced from the workflow "
        f"({sorted(parse_allowed_skips(ci_text) or [])}); "
        f"{len(cross_matrix(ci_text))} cross-compile rows; "
        f"declared MSRV {msrv} <= dev pin {chan}."
    )
    if msrv_job_is_degenerate(TOOLCHAIN_TOML.read_text(), CARGO_TOML.read_text()):
        print(
            f"note: the MSRV ({msrv}) equals the dev toolchain pin ({chan}), so the `msrv` "
            "job re-checks the same compiler every other job uses. It is not evidence "
            "that any older rustc still builds this workspace. The MSRV policy is a "
            "ratchet: the floor stays below the pin and rises only when a dependency "
            "forces it (CONTRIBUTING documents it), so the `msrv` job starts earning its "
            "keep as soon as the pin moves ahead of the floor."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
