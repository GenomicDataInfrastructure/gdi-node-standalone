#!/usr/bin/env bash
# Verify and refresh the vendored conformance inputs against their pinned upstream
# commit.
#
# Four sets are vendored verbatim (see each directory's VENDORED.md for the pin and the
# manual re-vendor procedure):
#   * conformance/shapes/gdi-metadata/               <- GenomicDataInfrastructure/gdi-metadata
#   * conformance/ga4gh-beacon-v2/                   <- ga4gh-beacon/beacon-v2 (framework/json)
#   * conformance/ga4gh-beacon-v2-default-model/     <- ga4gh-beacon/beacon-v2 (models/json/…)
#   * conformance/ga4gh-vrs-1.3/                     <- ga4gh/vrs, branch 1.3
#
# The two beacon-v2 sets share one upstream commit but pin different upstream paths, and
# a set is one repository plus one path, hence two directories, re-vendored together.
# `check_shared_commit` asserts the shared commit rather than only documenting it here.
# VRS is a third repository: the beacon default model $refs it by absolute URL and ships
# no copy.
#
# conformance/shapes/fdp/ is authored in-repo rather than vendored (see its
# PROVENANCE.md), so it is not covered here.
#
# The pin, repository / path / commit, is parsed from each set's VENDORED.md, which is the
# only place it is written. This script hard-codes no pin.
#
# Subcommands:
#   check          Fetch every local vendored file from its pinned upstream commit and
#                  assert it is byte-identical. Non-zero exit on any drift or fetch
#                  failure. Needs network access to github.com, so run it on demand or
#                  on a cadence rather than per commit.
#   verify         Local-only integrity guard, in two halves: (a) each set's on-disk payload
#                  file count matches its VENDORED.md `**Files:**` count, catching an added
#                  or deleted file; (b) every payload file matches its SHA256SUMS entry,
#                  catching an in-place edit, which the count alone cannot see. That is the
#                  dangerous direction: weakening a vendored shape or gutting a Beacon
#                  schema makes every downstream check pass more easily. No network, so
#                  this is the half of `check` that is safe in the per-commit
#                  `ci-local.sh all` gate.
#   sums           Regenerate each set's SHA256SUMS from what is on disk. A re-vendor step,
#                  not a verification step; `fetch` already does it for you.
#   fetch SET [REF]
#                  Re-download every local file of SET (substring match over the SETS
#                  paths below: `gdi-metadata`, `beacon`, which matches both beacon-v2
#                  sets because they share a commit, `default-model`, or `vrs`) from
#                  upstream at REF (default: the pinned commit) and overwrite it in
#                  place. This is the mechanical step of a re-vendor. Afterwards bump the
#                  commit in that set's VENDORED.md and the matching build constant
#                  (api_version / gdi_metadata_version) by hand, per VENDORED.md, then
#                  re-run `check`.
#   drift          Report whether upstream has moved. `check` cannot answer that, because
#                  it fetches each set at its immutable pinned commit and so stays green
#                  however far upstream advances. This compares the same files against
#                  the upstream branch (VENDORED.md `**Branch:**`). Exit 3 = upstream
#                  moved, which is news, not a defect. Network; not in `ci-local.sh all`.
#   pins           Assert each EXTERNAL_PINS entry below (the userportal's deployed
#                  CKAN-extension refs and gdi-metadata's declared HealthDCAT-AP release)
#                  still contains its expected token. `check` runs this too, so it needs
#                  no separate invocation there.
#
# Scope: `check` and `fetch` verify the fidelity of the files this repo does vendor. They
# do not detect that upstream has added a file worth having, because each set vendors a
# curated subset (beacon omits `examples*/`, for one), so picking up new files stays a
# re-vendor decision rather than drift. `pins` covers the opposite case: upstream files
# this repo does not vendor but silently depends on (harvest/profile version, metadata
# lineage), asserting a substring rather than byte-equality. `pins` makes one
# `api.github.com` call for the beacon-v2 release watch and one per distinct Action pin,
# against an unauthenticated budget of 60/h per IP. Set GITHUB_TOKEN to raise it;
# the token is sent to api.github.com only (see curl_to). A rate-limited 403 is reported
# as RATE-LIMITED rather than a bare UNREACHABLE, so the remedy is named where the
# failure is.
set -euo pipefail

RAW="https://raw.githubusercontent.com"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# The vendored sets, as local directories (each holds a VENDORED.md with the pin).
SETS=(
  "conformance/shapes/gdi-metadata"
  "conformance/ga4gh-beacon-v2"
  "conformance/ga4gh-beacon-v2-default-model"
  "conformance/ga4gh-vrs-1.3"
)

# External upstream references this repo does not vendor byte-for-byte, but which the
# node's conformance and harvest story silently depends on and must not drift unnoticed:
#   * the userportal's deployed CKAN-extension pins: the DCAT profile parser
#     (`ckanext-dcat`) that the check_ckanext.py hand-mirror tracks, and the FDP harvester
#     (`ckanext-fairdatapoint`) that crawls this node's FDP;
#   * the gdi-metadata model's declared HealthDCAT-AP release ("lineage"). The node tracks
#     gdi-metadata and the userportal profile, not the raw HealthDCAT-AP spec, so this
#     fires when the federation moves (Release 5 -> 6 or 7). That is the signal to
#     re-vendor the shapes and follow in lockstep, not to get ahead of it.
# Each entry asserts the remote file still contains an expected substring (a version tag
# or the declared release) rather than byte-diffing it: the upstream files change often
# for reasons that do not concern this repo, and only the pinned token matters.
# Format: "<owner>/<repo>/<git-ref>|<path>|<expected-substring>|<label>"
#   ...or "<full https URL>||<expected-substring>|<label>" for the release watches below.
#
# Release watches. Everything above tracks what the federation deploys; these track what
# the standard publishes. `check` fetches each set at its pinned commit, an immutable SHA,
# so it verifies that the local copy is faithful to the pin, never that upstream has stood
# still, and without a watch a new Beacon release passes unnoticed. A release is a tag, and
# tags are in no file the repo contains, so the watch reads the API: beacon-v2's own
# CHANGELOG tops out at `2.0.0` while the repo is tagged v2.2.0.
#
# The needle includes the JSON key, not just the bare version: `v2.2.0` alone also appears
# in a release's prose body, so a v2.3.0 announcement mentioning "since v2.2.0" would keep
# matching and report green. Keyed matching depends on GitHub's JSON spacing, which trades
# a possible false alarm (visible, one-line fix) for a false green (invisible), the right
# way round for a guard.
EXTERNAL_PINS=(
  "GenomicDataInfrastructure/gdi-userportal-ckan-docker/main|ckan/Dockerfile|gdi-userportal-ckanext-dcat.git@v2.4.2|userportal ckanext-dcat pin"
  "GenomicDataInfrastructure/gdi-userportal-ckan-docker/main|ckan/Dockerfile|gdi-userportal-ckanext-fairdatapoint.git@v1.6.12|userportal ckanext-fairdatapoint (FDP harvester) pin"
  "GenomicDataInfrastructure/gdi-metadata/main|README.md|HealthDCAT-AP Release 5|gdi-metadata HealthDCAT-AP lineage"
  "https://api.github.com/repos/ga4gh-beacon/beacon-v2/releases/latest||\"tag_name\": \"v2.2.0\"|GA4GH beacon-v2 latest RELEASE (bump with the vendored tag + [beacon].api_version)"
)

# Extract the value of a `- **Key:** `value`` line from a VENDORED.md.
md_field() { # <vendored.md> <key>
  # Single-quoted sed script: the backticks are literal, matching the markdown around
  # the value, and \1 is a sed backref, so shell expansion must not apply here.
  # shellcheck disable=SC2016
  grep -m1 -E "\*\*$2:\*\*" "$1" | sed -E 's/.*`([^`]*)`.*/\1/'
}

# Files relative to a set's local dir (the vendored payload; *.md is excluded).
set_files() { # <local_dir>
  ( cd "$1" && find . -type f \( -name '*.ttl' -o -name '*.json' \) \
      | sed 's#^\./##' | sort )
}

# The two beacon-v2 sets pin different paths of one upstream commit. A re-vendor that
# bumps one VENDORED.md and forgets the other leaves framework and model at different
# upstream commits while `check` and `verify` stay green, because each set is
# byte-identical to its own pin. Empty pins fail too: two absent `Commit:` lines compare
# equal and must not read as OK.
check_shared_commit() {
  local a b
  a="$(md_field "conformance/ga4gh-beacon-v2/VENDORED.md" Commit)"
  b="$(md_field "conformance/ga4gh-beacon-v2-default-model/VENDORED.md" Commit)"
  if [[ -z "$a" || -z "$b" || "$a" != "$b" ]]; then
    echo "SHARED-COMMIT MISMATCH: conformance/ga4gh-beacon-v2 pins '${a:-<none>}' but" >&2
    echo "conformance/ga4gh-beacon-v2-default-model pins '${b:-<none>}'. The two sets vendor" >&2
    echo "one upstream commit: bump both VENDORED.md files together ('fetch beacon' and" >&2
    echo "'fetch default-model' at the same ref)." >&2
    return 1
  fi
  echo "OK: both beacon-v2 sets pin upstream commit ${a:0:12}."
}

# The HTTP status of the last `curl_to`, when the server answered one. Read by the caller
# to tell a pinned path that is gone from a host that refused to serve the request.
CURL_HTTP_CODE=0

curl_to() { # <url> <out>  -> 0 on HTTP 200; sets CURL_HTTP_CODE and CURL_RATELIMITED
  local auth=()
  # The token goes to api.github.com only. That is the host with the 60/h unauthenticated
  # budget, and a bearer attached to every URL in EXTERNAL_PINS would hand it to whichever
  # host a future pin names.
  if [[ -n "${GITHUB_TOKEN:-}" && "$1" == https://api.github.com/* ]]; then
    auth=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
  fi
  # --retry-all-errors so a transient connection reset / 5xx is retried (a real 404
  # still ultimately fails after the retries, surfacing a bad pin).
  # `%header{}` needs curl >= 7.83 (2022-04); an older curl prints the token literally,
  # which the numeric test below reads as "unknown", never as "rate-limited".
  local out rc remaining
  out=$(curl -fsSL --retry 3 --retry-delay 2 --retry-all-errors "${auth[@]}" \
          -w '%{http_code} %header{x-ratelimit-remaining}' "$1" -o "$2")
  rc=$?
  CURL_HTTP_CODE=${out%% *}; CURL_HTTP_CODE=${CURL_HTTP_CODE:-0}
  remaining="${out#* }"
  # GitHub's rate-limit refusal is a 403 with the remaining budget at 0. Told apart from
  # every other 403 so the leg can print the GITHUB_TOKEN remedy instead of UNREACHABLE.
  CURL_RATELIMITED=0
  [[ "$CURL_HTTP_CODE" == 403 && "$remaining" == 0 ]] && CURL_RATELIMITED=1
  return $rc
}

# The deleted/added-file assertion, written once and used by `check` (post-fetch, network)
# and by `count` (local, network-free): compare a set's actual vendored-file count against
# the `**Files:**` count declared in its VENDORED.md. Returns 0 on match, and also when no
# count is declared, so an older VENDORED.md without the field does not block `check`.
# Prints the mismatch and the remedy and returns 1 otherwise.
check_file_count() { # <label> <actual> <expected>
  local label="$1" actual="$2" expected="$3"
  [[ -z "$expected" || "$actual" -eq "$expected" ]] && return 0
  echo "  FILE-COUNT MISMATCH: ${label}: ${actual} vendored file(s) present, VENDORED.md declares ${expected}" >&2
  echo "    (a vendored file was deleted or added locally; restore it, or re-vendor and bump the **Files:** count)" >&2
  return 1
}

# The upstream branch a set's `drift` comparison reads, from its VENDORED.md `**Branch:**`
# field. Defaults to `main` so an older VENDORED.md without the field still works.
upstream_branch() { # <local_dir>
  local b
  b="$(md_field "$1/VENDORED.md" Branch 2>/dev/null || true)"
  printf '%s' "${b:-main}"
}

# Verify or refresh one set. mode = check | fetch.
process_set() { # <mode> <local_dir> <ref-or-empty>
  local mode="$1" dir="$2" ref_override="${3:-}"
  local md="$dir/VENDORED.md"
  [[ -f "$md" ]] || { echo "ERROR: $md not found" >&2; return 1; }

  local repo path commit ref files_expected
  repo="$(md_field "$md" Repository)"
  path="$(md_field "$md" Path)"
  commit="$(md_field "$md" Commit)"
  files_expected="$(md_field "$md" Files)" # expected payload file count (deleted-file guard)
  path="${path%/}" # strip any trailing slash
  if [[ -z "$repo" || -z "$path" || -z "$commit" ]]; then
    echo "ERROR: could not parse repository/path/commit from $md" >&2
    return 1
  fi
  ref="${ref_override:-$commit}"

  echo "## ${dir}  <-  ${repo} @ ${ref}  (path: ${path})"
  local n_ok=0 n_diff=0 n_fail=0 rel url tmp
  while IFS= read -r rel; do
    [[ -n "$rel" ]] || continue
    url="${RAW}/${repo}/${ref}/${path}/${rel}"
    tmp="$(mktemp)"
    if ! curl_to "$url" "$tmp"; then
      echo "  FETCH-FAIL  ${rel}"
      n_fail=$((n_fail + 1)); rm -f "$tmp"; continue
    fi
    if diff -q "$dir/$rel" "$tmp" >/dev/null 2>&1; then
      n_ok=$((n_ok + 1))
    elif [[ "$mode" == fetch ]]; then
      cp "$tmp" "$dir/$rel"; echo "  UPDATED     ${rel}"; n_diff=$((n_diff + 1))
    else
      echo "  DRIFT       ${rel}"; n_diff=$((n_diff + 1))
    fi
    rm -f "$tmp"
  done < <(set_files "$dir")

  # Deleted/added-file guard: set_files enumerates only the local survivors, so a
  # vendored file deleted locally would otherwise pass, every survivor still matching
  # upstream. Compare the total against the count recorded in VENDORED.md's `**Files:**`
  # field. n_total is exact because every file goes through one of the three branches.
  local n_total=$((n_ok + n_diff + n_fail)) count_ok=1
  check_file_count "$dir" "$n_total" "$files_expected" || count_ok=0

  if [[ "$mode" == check ]]; then
    echo "  -> ${n_ok} identical, ${n_diff} drifted, ${n_fail} fetch-failure(s); ${n_total}/${files_expected:-?} files"
    [[ $n_diff -eq 0 && $n_fail -eq 0 && $count_ok -eq 1 ]]
  else
    echo "  -> ${n_ok} already current, ${n_diff} updated, ${n_fail} fetch-failure(s); ${n_total}/${files_expected:-?} files"
    [[ $n_fail -eq 0 && $count_ok -eq 1 ]]
  fi
}

# Assert each EXTERNAL_PINS entry's remote file still contains its expected token.
check_pins() {
  echo "## external pins  (userportal deploy refs + gdi-metadata lineage)"
  local n_ok=0 n_drift=0 n_fetchfail=0 entry ref path needle label url where tmp crc
  for entry in "${EXTERNAL_PINS[@]}"; do
    IFS='|' read -r ref path needle label <<<"$entry"
    # A pin is normally `<owner>/<repo>/<ref>` plus a path under raw.githubusercontent. An
    # entry whose first field is already a full URL is used verbatim, which is how the
    # release watches work: a new upstream version is a tag, and tags live in the API
    # rather than in any file the repo contains.
    if [[ "$ref" == https://* ]]; then
      url="$ref"
    else
      url="${RAW}/${ref}/${path}"
    fi
    where="${path:-$url}"
    tmp="$(mktemp)"
    crc=0; curl_to "$url" "$tmp" || crc=$?
    if [[ $crc -ne 0 ]]; then
      # Separate "the server said no" from "there was no server". curl exit 22 is
      # `--fail`'s HTTP >= 400, so the host was reached; everything else (6 could not
      # resolve, 7 could not connect, 28 timeout, 35 TLS) is this machine's network and
      # says nothing about the pin.
      #
      # Within exit 22, only 404 and 410 say the pin is wrong: 401 and 403 are
      # credentials, 429 is rate limiting, and 5xx is the host having a bad day. Counting
      # those as drift would fail the gate for a reason unrelated to the pin.
      if [[ $crc -eq 22 && ( $CURL_HTTP_CODE == 404 || $CURL_HTTP_CODE == 410 ) ]]; then
        echo "  GONE        ${label}  (HTTP ${CURL_HTTP_CODE} fetching ${where}; renamed or removed upstream?)"
        n_drift=$((n_drift + 1))
      elif [[ $crc -eq 22 && "${CURL_RATELIMITED:-0}" == 1 ]]; then
        echo "  RATE-LIMITED ${label}  (GitHub API x-ratelimit-remaining: 0; 60/h unauthenticated per IP; export GITHUB_TOKEN; ${url})"
        n_fetchfail=$((n_fetchfail + 1))
      elif [[ $crc -eq 22 ]]; then
        echo "  UNREACHABLE ${label}  (HTTP ${CURL_HTTP_CODE}; an auth or server error, which says nothing about the pin; ${url})"
        n_fetchfail=$((n_fetchfail + 1))
      else
        echo "  UNREACHABLE ${label}  (curl exit ${crc}; ${url})"
        n_fetchfail=$((n_fetchfail + 1))
      fi
      rm -f "$tmp"; continue
    fi
    if grep -qF -- "$needle" "$tmp"; then
      echo "  OK          ${label}  ('${needle}')"
      n_ok=$((n_ok + 1))
    else
      echo "  DRIFT       ${label}  (expected '${needle}' in ${where})"
      n_drift=$((n_drift + 1))
    fi
    rm -f "$tmp"
  done
  echo "  -> ${n_ok} pinned as expected, ${n_drift} drifted, ${n_fetchfail} unreachable"
  # Distinct exit codes, because the two failures mean opposite things to a caller that
  # runs this on every gate (`ci-local.sh pins`): DRIFT is a real finding and must fail
  # closed, whereas UNREACHABLE means this machine has no network, or GitHub is down, and
  # says nothing about the pins. Collapsed, an offline gate goes red for a non-finding.
  #   0 = every pin as expected
  #   1 = at least one real DRIFT (authoritative: every pin was actually fetched)
  #   2 = no drift seen, but at least one pin could not be fetched (verdict unknown)
  if [[ $n_drift -gt 0 ]]; then return 1; fi
  if [[ $n_fetchfail -gt 0 ]]; then return 2; fi
  return 0
}

# GitHub Action pins: assert each `uses: owner/repo@<sha> # <tag>` still means what it
# says.
#
# SHA-pinning buys immutability, not provenance. The comment beside the SHA is the only
# human-readable statement of which version is pinned, and it is what a reviewer checks a
# bump against, so a SHA that exists but is not that tag passes review in silence while
# running unreviewed code.
#
# The pins are enumerated from the workflows rather than listed here, because a hardcoded
# list silently exempts every action added after it was written.
# `test_action_pin_comments.py` is the network-free half: it asserts every pinned `uses:`
# carries a comment, so this check can never be handed a pin with nothing to compare
# against and report OK by vacuity.
#
# One call per pin. `/commits/{ref}` accepts a tag and returns the commit it points at,
# dereferencing annotated tags, so comparing its `sha` to the pin answers the whole
# question in a single request.
#
# A comment naming a branch (`stable`, `nightly`) is checked for existence only. A branch
# head moves, so a pin equal to today's head would be the anomaly, and demanding equality
# would report permanent false drift.
check_action_pins() {
  echo "## github action pins  (uses: owner/repo@sha # tag)"
  local n_ok=0 n_drift=0 n_fetchfail=0 n_branch=0
  local line spec repo sha tag url tmp crc got
  # `sort -u`: the same action is pinned at many sites; verify each distinct pin once.
  while read -r line; do
    [[ -n "$line" ]] || continue
    spec="${line%% *}"; tag="${line##* }"
    repo="${spec%@*}"; sha="${spec#*@}"
    # A version comment starts with a digit or `v`; anything else is a branch/alias.
    if [[ ! "$tag" =~ ^v?[0-9] ]]; then
      url="https://api.github.com/repos/${repo}/commits/${sha}"
      tmp="$(mktemp)"; crc=0; curl_to "$url" "$tmp" || crc=$?
      rm -f "$tmp"
      if [[ $crc -eq 0 ]]; then
        echo "  OK(branch)  ${repo}@${sha:0:12} (# ${tag}: branch alias, existence only)"
        n_branch=$((n_branch + 1))
      elif [[ $crc -eq 22 && ( $CURL_HTTP_CODE == 404 || $CURL_HTTP_CODE == 410 ) ]]; then
        echo "  GONE        ${repo}@${sha:0:12} (# ${tag}): commit does not exist upstream"
        n_drift=$((n_drift + 1))
      elif [[ "${CURL_RATELIMITED:-0}" == 1 ]]; then
        echo "  RATE-LIMITED ${repo} (# ${tag}): GitHub API x-ratelimit-remaining: 0; export GITHUB_TOKEN"
        n_fetchfail=$((n_fetchfail + 1))
      else
        echo "  UNREACHABLE ${repo} (# ${tag}) (HTTP ${CURL_HTTP_CODE:-?}, curl ${crc})"
        n_fetchfail=$((n_fetchfail + 1))
      fi
      continue
    fi
    url="https://api.github.com/repos/${repo}/commits/${tag}"
    tmp="$(mktemp)"; crc=0; curl_to "$url" "$tmp" || crc=$?
    if [[ $crc -ne 0 ]]; then
      # Same split as check_pins: 404 and 410 are a verdict about the pin, meaning the
      # tag the comment names is not there. Auth, rate-limit and 5xx say nothing about it.
      if [[ $crc -eq 22 && ( $CURL_HTTP_CODE == 404 || $CURL_HTTP_CODE == 410 ) ]]; then
        echo "  GONE        ${repo} (# ${tag}): no such tag upstream, renamed or deleted?"
        n_drift=$((n_drift + 1))
      elif [[ "${CURL_RATELIMITED:-0}" == 1 ]]; then
        echo "  RATE-LIMITED ${repo} (# ${tag}): GitHub API x-ratelimit-remaining: 0; export GITHUB_TOKEN"
        n_fetchfail=$((n_fetchfail + 1))
      else
        echo "  UNREACHABLE ${repo} (# ${tag}) (HTTP ${CURL_HTTP_CODE:-?}, curl ${crc})"
        n_fetchfail=$((n_fetchfail + 1))
      fi
      rm -f "$tmp"; continue
    fi
    # First 40-hex `"sha"` in the response is the commit's own.
    got="$(grep -o '"sha"[[:space:]]*:[[:space:]]*"[0-9a-f]\{40\}"' "$tmp" | head -1 | grep -o '[0-9a-f]\{40\}')"
    rm -f "$tmp"
    if [[ -z "$got" ]]; then
      echo "  UNREACHABLE ${repo} (# ${tag}): no commit sha in the API response"
      n_fetchfail=$((n_fetchfail + 1))
    elif [[ "$got" == "$sha" ]]; then
      echo "  OK          ${repo}@${sha:0:12} == ${tag}"
      n_ok=$((n_ok + 1))
    else
      echo "  DRIFT       ${repo} (# ${tag}) pins ${sha:0:12} but ${tag} is ${got:0:12}"
      n_drift=$((n_drift + 1))
    fi
  done < <(grep -rhoE 'uses: [A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40} +# +\S+' \
             .github/workflows/*.yml 2>/dev/null | sed 's/^uses: //; s/ \+# \+/ /' | sort -u)

  echo "  -> ${n_ok} pin(s) match their tag, ${n_branch} branch-alias, ${n_drift} drifted, ${n_fetchfail} unreachable"
  # A guard that enumerated nothing must not report success: if the workflows move or the
  # pin format changes, silence here would read exactly like "all pins are fine".
  if [[ $((n_ok + n_branch + n_drift + n_fetchfail)) -eq 0 ]]; then
    echo "  no action pins found, so the enumeration is broken: the workflows moved, or the pin format changed" >&2
    return 1
  fi
  if [[ $n_drift -gt 0 ]]; then return 1; fi
  if [[ $n_fetchfail -gt 0 ]]; then return 2; fi
  return 0
}

# Network-free deleted/added-file guard: assert each set's on-disk payload file count
# matches the `**Files:**` count declared in its VENDORED.md. This is the local half of
# the `check` file-count assertion, which otherwise runs only after fetching every file
# over the network, so `ci-local.sh` can run it per commit. `set_files` enumerates only
# the local survivors, so a vendored file deleted locally silently drops coverage, and
# this is what catches it.
count_files() {
  local rc=0 dir md files_expected n
  for dir in "${SETS[@]}"; do
    md="$dir/VENDORED.md"
    if [[ ! -f "$md" ]]; then
      echo "ERROR: $md not found" >&2; rc=1; continue
    fi
    files_expected="$(md_field "$md" Files)"
    if [[ -z "$files_expected" ]]; then
      echo "ERROR: $md has no **Files:** count to check against" >&2; rc=1; continue
    fi
    n="$(set_files "$dir" | wc -l | tr -d ' ')"
    if check_file_count "$dir" "$n" "$files_expected"; then
      echo "  OK  $dir: ${n} vendored file(s) match VENDORED.md **Files:**"
    else
      rc=1
    fi
  done
  if [[ $rc -ne 0 ]]; then
    echo "Vendored file-count drift: a vendored payload file was added or deleted locally." >&2
  fi
  return $rc
}

# The per-set content manifest: a plain `sha256sum` file rather than a table in
# VENDORED.md, because `sha256sum -c` is then the verifier and there is no bespoke parser
# to drift from the format it parses. Excluded from `set_files`, which matches only *.ttl
# and *.json, so adding it does not perturb the file-count guard.
sums_file() { printf '%s/SHA256SUMS' "$1"; }

# Regenerate a set's manifest from what is currently on disk. Called after `fetch` (a
# re-vendor legitimately changes content) and by the `sums` subcommand. Never called by
# `verify`: a guard that rewrites its own expectation checks nothing.
write_sums() { # <local_dir>
  local dir="$1" sums
  sums="$(sums_file "$dir")"
  # Same enumeration as `set_files` so the manifest and the count guard can never disagree
  # about what "a payload file" means.
  ( cd "$dir" && find . -type f \( -name '*.ttl' -o -name '*.json' \) \
      | sed 's#^\./##' | sort | xargs sha256sum > SHA256SUMS )
  echo "  wrote $sums ($(wc -l < "$sums" | tr -d ' ') entries)"
}

# Network-free content guard. The file-count check above proves nothing was added or
# deleted; this proves nothing was edited. Weakening an `sh:minCount` in a vendored shape,
# or deleting a `"required"` array from a Beacon schema, keeps the file count identical and
# makes the suite pass more easily, so no downstream test notices either.
#
# Also asserts the manifest covers every payload file, so a newly added file cannot sit
# unverified: `sha256sum -c` only checks the lines it is given.
verify_sums() {
  local rc=0 dir sums n_listed n_files
  for dir in "${SETS[@]}"; do
    sums="$(sums_file "$dir")"
    if [[ ! -f "$sums" ]]; then
      echo "ERROR: $sums not found; regenerate with: $0 sums" >&2; rc=1; continue
    fi
    n_listed="$(wc -l < "$sums" | tr -d ' ')"
    n_files="$(set_files "$dir" | wc -l | tr -d ' ')"
    if [[ "$n_listed" -ne "$n_files" ]]; then
      echo "ERROR: $sums lists $n_listed file(s) but $dir holds $n_files payload file(s);" >&2
      echo "       an unlisted file is an unverified file. Regenerate with: $0 sums" >&2
      rc=1; continue
    fi
    if ( cd "$dir" && sha256sum -c --quiet SHA256SUMS ); then
      echo "  OK  $dir: ${n_listed} vendored file(s) match SHA256SUMS"
    else
      rc=1
    fi
  done
  if [[ $rc -ne 0 ]]; then
    echo "Vendored content drift: a vendored file was edited in place. These files are" >&2
    echo "copies of upstream and must never be hand-edited: re-vendor with 'fetch' (which" >&2
    echo "regenerates SHA256SUMS), or revert the edit. If you meant to relax a shape, do it" >&2
    echo "in conformance/shapes/fdp/ (authored in-repo) instead." >&2
  fi
  return $rc
}

cmd="${1:-check}"
case "$cmd" in
  check)
    rc=0
    for s in "${SETS[@]}"; do process_set check "$s" "" || rc=1; done
    # The asymmetry with `ci-local.sh pins` is intended: there, an unreachable network
    # (exit 2) is a warning, so that a developer who is offline still gets a usable gate.
    # Here it is a failure, because `check` is the network job whose purpose is to reach
    # upstream: if it could not, it verified nothing. Both codes fold into rc=1.
    check_pins || rc=1
    # Byte-equality with upstream proves the files are right; this proves the manifest
    # still describes them, catching a re-vendor that updated the payload but not
    # SHA256SUMS, which would leave the offline `verify` gate red for everyone else.
    verify_sums || rc=1
    check_shared_commit || rc=1
    if [[ $rc -ne 0 ]]; then
      echo "Vendored drift detected: a vendored file or external pin no longer matches its" >&2
      echo "pinned upstream. If the change is intended, re-vendor with 'fetch' and bump" >&2
      echo "VENDORED.md, or update EXTERNAL_PINS and follow the federation. Else revert it." >&2
    else
      echo "OK: vendored files byte-identical to their pinned commit; external pins unchanged."
    fi
    exit $rc
    ;;
  verify)
    # The complete offline guard: nothing added or deleted (count), and nothing edited in
    # place (checksums). Run both before reporting, so one failure does not mask the other.
    rc=0
    count_files || rc=1
    verify_sums || rc=1
    check_shared_commit || rc=1
    if [[ $rc -eq 0 ]]; then
      echo "OK: every vendored set matches its VENDORED.md file count and its SHA256SUMS, and the two beacon-v2 sets share one commit."
      exit 0
    fi
    exit 1
    ;;
  drift)
    # Report whether upstream has moved, which `check` cannot answer because it fetches
    # each set at its immutable pinned commit. This fetches the same files at the upstream
    # branch instead, so a changed shape or schema shows up as DRIFT.
    #
    # Not part of `ci-local.sh all`: it is ~45 raw.githubusercontent GETs, and its answer
    # is news rather than a defect, since upstream moving is not a bug in this tree. Run
    # it on a cadence, or by hand when deciding whether to re-vendor. Exit 3 = upstream
    # has moved, which callers can treat as informational.
    #
    # Scope, same as `check`: this sees files that changed (drift) or were removed
    # upstream (fetch-fail or 404). A file upstream has added is invisible, because the
    # comparison enumerates the local payload, so picking up new files stays a re-vendor
    # decision.
    rc=0
    for s in "${SETS[@]}"; do
      process_set check "$s" "$(upstream_branch "$s")" || rc=1
    done
    if [[ $rc -eq 0 ]]; then
      echo "OK: every vendored file is still identical to its upstream branch head."
      exit 0
    fi
    echo
    echo "Upstream has moved: the vendored files differ from their upstream branch head." >&2
    echo "This is news, not a defect. The tree is pinned to a commit, and adopting an" >&2
    echo "upstream change is a decision to take rather than a reflex. To adopt this one:" >&2
    echo "'$0 fetch <set>' (which regenerates SHA256SUMS), then bump **Commit** and" >&2
    echo "the matching build constant in that set's VENDORED.md, review the diff, and run" >&2
    echo "'$0 check'. To stay put: do nothing." >&2
    exit 3
    ;;
  sums)
    # Regenerate the manifests. This is a re-vendor step, not a verification step: run it
    # only when you have changed the vendored payload, normally via `fetch`, which does it
    # for you. Then review the SHA256SUMS diff alongside the content diff.
    for s in "${SETS[@]}"; do write_sums "$s"; done
    echo "Manifests regenerated. Review the diff: a changed hash with no matching content"
    echo "change in the same commit means the manifest, not the payload, was tampered with."
    exit 0
    ;;
  pins)
    # `set -e` would abort on a non-zero, so capture each code explicitly. The two checks
    # answer independent questions, one about what the federation deploys and one about
    # what an action SHA means, so both always run rather than one short-circuiting the
    # other, and each keeps its own verdict for the remedy message below.
    erc=0; check_pins || erc=$?
    arc=0; check_action_pins || arc=$?
    # Worst code wins: DRIFT (1) outranks UNREACHABLE (2), because 1 is an authoritative
    # finding about a pin and 2 only means this machine could not reach the network.
    rc=0
    if [[ $erc -eq 2 || $arc -eq 2 ]]; then rc=2; fi
    if [[ $erc -eq 1 || $arc -eq 1 ]]; then rc=1; fi
    if [[ $rc -eq 0 ]]; then
      echo "OK: external upstream pins unchanged; action pins match their tags."
      exit 0
    fi
    if [[ $rc -eq 2 ]]; then
      echo "Pins unreachable: at least one pin could not be fetched, and no drift was seen" >&2
      echo "in the ones that were. This is a network verdict, not a pin verdict. Either this" >&2
      echo "machine is offline, or raw.githubusercontent is down, or, if the lines above say" >&2
      echo "RATE-LIMITED, the unauthenticated GitHub API budget of 60/h per IP is spent:" >&2
      echo "export GITHUB_TOKEN. Re-run when connected. Callers tell this from drift by the" >&2
      echo "exit code: 2 = unreachable, 1 = drift." >&2
      exit 2
    fi
    # Name the remedy for the check that actually drifted. The two have different fixes,
    # and printing the federation remedy for an action-pin drift sends the reader to
    # EXTERNAL_PINS to find nothing wrong.
    if [[ $arc -eq 1 ]]; then
      echo "GitHub Action pin drift: a 'uses: owner/repo@<sha> # <tag>' comment no longer" >&2
      echo "names the version that SHA is. Either the pin was written wrong, so fix the SHA," >&2
      echo "or upstream moved the tag, in which case the SHA is still the reviewed code:" >&2
      echo "update the comment and say so. See the DRIFT lines above for both values." >&2
    fi
    if [[ $erc -eq 1 ]]; then
      echo "External pin drift: the userportal deploy refs, or gdi-metadata's declared" >&2
      echo "HealthDCAT-AP release, changed. If the federation moved, follow in lockstep:" >&2
      echo "re-vendor the gdi-metadata shapes and bump the pin in EXTERNAL_PINS and in" >&2
      echo "conformance/requirements.txt. Do not get ahead of it." >&2
    fi
    exit 1
    ;;
  fetch)
    target="${2:-}"; ref="${3:-}"
    if [[ -z "$target" ]]; then
      echo "usage: $0 fetch <set> [ref]   (set: gdi-metadata | beacon | default-model | vrs)" >&2
      exit 2
    fi
    matched=0 rc=0
    for s in "${SETS[@]}"; do
      if [[ "$s" == *"$target"* ]]; then
        matched=1
        process_set fetch "$s" "$ref" || rc=1
      fi
    done
    if [[ $matched -eq 0 ]]; then
      echo "no vendored set matches '$target' (expected gdi-metadata, beacon, default-model or vrs)" >&2
      exit 2
    fi
    # A re-vendor legitimately changes content, so the manifest must move with it.
    # Otherwise every later offline `verify` fails, and the tempting fix is to delete the
    # guard.
    for s in "${SETS[@]}"; do
      [[ "$s" == *"$target"* ]] && write_sums "$s"
    done
    echo
    echo "Re-fetch done. Now, per the set's VENDORED.md: bump its **Commit** (and Tag,"
    echo "if any), bump the matching build constant (api_version / gdi_metadata_version),"
    echo "review the diff, then run: $0 check"
    exit $rc
    ;;
  *)
    echo "usage: $0 {check | drift | verify | sums | fetch <set> [ref] | pins}" >&2
    exit 2
    ;;
esac
