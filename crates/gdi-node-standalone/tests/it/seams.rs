//! Seam checks: facts that must agree between artifacts.
//!
//! Every other guard in this repo checks one artifact against itself, or against the code it
//! belongs to. These compare artifacts to each other: the code, the Dockerfile, the Compose
//! stacks and the operator-facing docs. They check that a config file named in a doc exists,
//! that the container's config path is the one the node reads, that a default quoted in the
//! docs is the default the code ships, that a repo path cited in prose is on disk, that no
//! doc advertises a release artifact before one exists, and that the shipped attribution bundle
//! is not HTML-escaped.
//!
//! Every expected value is derived from the code or the filesystem, never restated here.
//! Renaming `DEFAULT_CONFIG_PATH` re-aims these tests; a hand-maintained list of forbidden
//! strings would go stale instead.

#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use gdi_node_standalone_core::config::{DEFAULT_CONFIG_FILE, DEFAULT_CONFIG_PATH, ServiceConfig};

fn repo_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo_path(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// The service config's file name, read from the code rather than restated here.
fn service_config_file() -> &'static str {
    Path::new(DEFAULT_CONFIG_PATH)
        .file_name()
        .and_then(|n| n.to_str())
        .expect("DEFAULT_CONFIG_PATH has a file name")
}

/// The operator-facing surfaces. Excludes `CHANGELOG.md`, which records history rather than
/// instructing a reader, and Rust sources, where a mention of another file name explains a
/// rename rather than pointing at a file.
const DOC_SURFACES: &[&str] = &[
    "README.md",
    "node.example.toml",
    "node.quickstart.toml",
    "tool.example.toml",
    "docs/operating.md",
    "docs/deployment.md",
    "docs/api.md",
    "docs/architecture.md",
    "docs/gdi-dataset-tool.md",
    "docs/package-format.md",
];

/// Every `*.toml` name an operator may legitimately meet: the two code-declared config
/// defaults, plus every `.toml` that exists in the repo (the shipped templates and the
/// Compose configs).
fn legitimate_toml_names() -> BTreeMap<String, &'static str> {
    let mut ok: BTreeMap<String, &'static str> = BTreeMap::new();
    ok.insert(
        service_config_file().to_owned(),
        "the service config default",
    );
    ok.insert(DEFAULT_CONFIG_FILE.to_owned(), "the tool config default");

    // Anything that exists on disk is a real file a doc may name.
    for dir in ["", "compose"] {
        let Ok(entries) = std::fs::read_dir(repo_path(dir)) else {
            continue;
        };
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if Path::new(&name)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("toml"))
            {
                ok.insert(name, "a file that exists in the repo");
            }
        }
    }
    ok
}

/// Whether a `.toml` token pulled from a doc is satisfied by the legitimate set.
///
/// A literal name must be present outright. A token carrying `*` is a glob, so a doc may
/// point at a set (`compose/node.*.toml`) without naming each member. A glob is satisfied
/// only when it matches at least one real name, which keeps the guard's teeth instead of
/// skipping anything with a star. This also absorbs markdown emphasis (`**node.toml**`),
/// where `*` matches the empty string.
fn toml_name_is_legitimate(name: &str, legitimate: &BTreeMap<String, &'static str>) -> bool {
    if !name.contains('*') {
        return legitimate.contains_key(name);
    }
    legitimate.keys().any(|real| glob_matches(name, real))
}

/// Match a `*` glob against a literal name, where `*` stands for any run of characters
/// (including none). The patterns are filenames rather than paths, so there is no `**` or
/// separator semantics to honour and no glob crate to justify.
fn glob_matches(pattern: &str, name: &str) -> bool {
    let mut segments = pattern.split('*');
    let first = segments.next().unwrap_or("");
    let Some(mut rest) = name.strip_prefix(first) else {
        return false;
    };
    let tail: Vec<&str> = segments.collect();
    // No `*` at all: the prefix had to consume the whole name.
    let Some((last, middle)) = tail.split_last() else {
        return rest.is_empty();
    };
    for seg in middle {
        let Some(at) = rest.find(seg) else {
            return false;
        };
        rest = &rest[at + seg.len()..];
    }
    rest.len() >= last.len() && rest.ends_with(last)
}

/// Pull every `foo.toml` token out of a line (bare or inside backticks/paths).
fn toml_names_in(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (i, _) in line.match_indices(".toml") {
        // Walk back over the file-name characters preceding `.toml`.
        // `*` counts as a name character so a glob (`compose/node.*.toml`) survives whole
        // instead of truncating at the star to a meaningless bare `.toml`.
        let start = line[..i]
            .rfind(|c: char| {
                !(c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' || c == '*')
            })
            .map_or(0, |p| p + 1);
        let name = &line[start..i + ".toml".len()];
        // A path (`compose/node.s3.toml`, `/etc/gdi-node-standalone/node.toml`) is judged on its
        // final component, which is what the `legitimate` set holds.
        if let Some(base) = name.rsplit('/').next()
            && !base.is_empty()
        {
            out.push(base.to_owned());
        }
    }
    out
}

/// Seam: no operator-facing file may name a config file that does not exist.
///
/// Derived, not banned: the legitimate set is the two code-declared defaults plus every
/// `.toml` on disk. `config.toml` fails because it is neither a default nor a real file, and
/// a future rename re-aims this test for free.
#[test]
fn no_doc_names_a_config_file_that_does_not_exist() {
    let legitimate = legitimate_toml_names();
    let mut bad: Vec<String> = Vec::new();
    let mut checked = 0_usize;

    for rel in DOC_SURFACES {
        let Ok(text) = std::fs::read_to_string(repo_path(rel)) else {
            continue; // an optional doc; absence is not this test's business
        };
        for (n, line) in text.lines().enumerate() {
            for name in toml_names_in(line) {
                checked += 1;
                if !toml_name_is_legitimate(&name, &legitimate) {
                    bad.push(format!(
                        "{rel}:{}: names `{name}`, which is neither a code-declared config \
                         default ({} / {}) nor a file in the repo",
                        n + 1,
                        service_config_file(),
                        DEFAULT_CONFIG_FILE,
                    ));
                }
            }
        }
    }

    // Same bound as `docs_quote_the_real_defaults`: this guard scans and then asserts it
    // found nothing wrong, so a scanner that stops matching reports success having checked
    // nothing. A doc rename, or a change in how `*.toml` is written, would do it.
    assert!(
        checked > 0,
        "the scanner matched no `*.toml` names at all, so it has stopped checking anything; \
         the doc phrasing may have changed"
    );
    assert!(
        bad.is_empty(),
        "operator-facing docs name config files that do not exist:\n  {}\n\n\
         Every `*.toml` an operator is told to create or pass must be a real file or a \
         code-declared default. A stale name here sends them to a path nothing reads.",
        bad.join("\n  ")
    );
}

/// A `*` glob token must survive tokenization intact, not truncate to a bare `.toml`.
///
/// A doc may cite a set of files as `compose/node.*.toml`. If tokenization stops at the star
/// the token becomes a bare `.toml`, which matches no legitimate name, and the guard rejects
/// correct prose.
#[test]
fn toml_names_in_keeps_a_glob_token_whole() {
    assert_eq!(
        toml_names_in("the shipped `compose/node.*.toml` all set it"),
        vec!["node.*.toml".to_owned()],
    );
}

/// A glob is legitimate when it matches at least one real file and illegitimate when it
/// matches none, so the guard keeps its teeth instead of skipping every glob.
#[test]
fn a_glob_is_legitimate_only_when_it_matches_a_real_file() {
    let legitimate = legitimate_toml_names();
    assert!(
        toml_name_is_legitimate("node.*.toml", &legitimate),
        "compose/node.{{full,minimal,s3}}.toml exist, so this glob must be accepted",
    );
    assert!(
        !toml_name_is_legitimate("nonexistent.*.toml", &legitimate),
        "a glob matching nothing must still be reported",
    );
}

/// Seam: the container's config path must be the one the node reads.
///
/// `Dockerfile`'s `ENV GDI_CONFIG` and every Compose mount of a `compose/node.*.toml` must
/// land on [`DEFAULT_CONFIG_PATH`]. A mount and an `ENV` that disagree are each valid on
/// their own; the stack then dies at boot with "config file not found".
#[test]
fn dockerfile_and_compose_mount_the_config_where_the_node_reads_it() {
    let mut bad: Vec<String> = Vec::new();
    // The Dockerfile half `.expect()`s its ENV line, so it cannot pass vacuously. The
    // Compose half is a scan, and a change to how mounts are written (or a compose file
    // rename) would leave it matching nothing and reporting success.
    let mut mounts_checked = 0_usize;

    // 1. The image's GDI_CONFIG.
    let dockerfile = read("Dockerfile");
    let env_line = dockerfile
        .lines()
        .find(|l| l.trim_start().starts_with("ENV GDI_CONFIG="))
        .expect("Dockerfile sets ENV GDI_CONFIG");
    let env_path = env_line.split('=').nth(1).unwrap().trim();
    if env_path != DEFAULT_CONFIG_PATH {
        bad.push(format!(
            "Dockerfile: ENV GDI_CONFIG={env_path}, but the service reads {DEFAULT_CONFIG_PATH}"
        ));
    }

    // 2. Every Compose stack's mount of a shipped compose config.
    for entry in std::fs::read_dir(repo_path(""))
        .expect("read repo root")
        .flatten()
    {
        let name = entry.file_name().to_string_lossy().into_owned();
        let is_compose = name.starts_with("docker-compose")
            && Path::new(&name)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("yml"));
        if !is_compose {
            continue;
        }
        let text = read(&name);
        for (n, line) in text.lines().enumerate() {
            // `- ./compose/node.s3.toml:/etc/gdi-node-standalone/node.toml:ro`
            let Some(rest) = line.split_once("./compose/node.").map(|(_, r)| r) else {
                continue;
            };
            let Some((_, after_colon)) = rest.split_once(':') else {
                continue;
            };
            let target = after_colon.split(':').next().unwrap_or_default().trim();
            mounts_checked += 1;
            if target != DEFAULT_CONFIG_PATH {
                bad.push(format!(
                    "{name}:{}: mounts the node config at {target}, but the node reads \
                     {DEFAULT_CONFIG_PATH} (the stack would fail to boot)",
                    n + 1
                ));
            }
        }
    }

    assert!(
        mounts_checked > 0,
        "no compose stack mounts a `./compose/node.*` file; the scan matched nothing, so \
         this guard is no longer checking the mount seam"
    );
    assert!(
        bad.is_empty(),
        "container config-path seam is broken:\n  {}",
        bad.join("\n  ")
    );
}

/// Seam: a default quoted in the docs must be the default the code ships.
///
/// `config_example_documents_real_defaults` pins this for `node.example.toml`; this extends
/// the same comparison to the markdown, which that guard does not read. A doc that quotes
/// the wrong default sends an operator to a listener the node never binds.
///
/// Scope: a claim is checked only when one line carries both a `[section].field` reference
/// and a ``default `value` ``, and the value is a literal (no `<placeholder>`). The scope is
/// narrow because this is a seam check, not a prose grader.
#[test]
fn docs_quote_the_real_defaults() {
    let default_json =
        serde_json::to_value(ServiceConfig::default()).expect("serialize default config");
    let mut defaults: BTreeMap<String, String> = BTreeMap::new();
    flatten(&String::new(), &default_json, &mut defaults);

    let mut bad: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for rel in DOC_SURFACES {
        let Ok(text) = std::fs::read_to_string(repo_path(rel)) else {
            continue;
        };
        for (n, line) in text.lines().enumerate() {
            for (field, claimed) in default_claims_in(line) {
                // Non-literal defaults (`<config-dir>/keys/...`) are illustrative, not values.
                if claimed.contains('<') {
                    continue;
                }
                let Some(actual) = defaults.get(&field) else {
                    continue; // not a ServiceConfig field (e.g. a tool-config knob)
                };
                checked += 1;
                if &claimed != actual {
                    let (section, name) = field.split_once('.').unwrap_or(("", &field));
                    bad.push(format!(
                        "{rel}:{}: says `[{section}].{name}` defaults to `{claimed}`; it is \
                         `{actual}`",
                        n + 1,
                    ));
                }
            }
        }
    }

    // Ratchet, not a floor of one: a `> 0` floor would let coverage rot to a single claim
    // and still pass. Lower it only alongside a real removal of claims.
    assert!(
        checked >= 8,
        "the scanner matched only {checked} default-claims (expected >= 8), so it has \
         largely stopped checking; the doc phrasing may have changed"
    );
    assert!(
        bad.is_empty(),
        "docs quote defaults the code does not ship:\n  {}\n\n\
         An operator configures from these numbers. Quote the real default, or drop the claim.",
        bad.join("\n  ")
    );
}

/// Every `(field, claimed-default)` pair a line actually asserts.
///
/// Mis-pairing is worse than missing a claim, so the extractor is conservative. Two traps:
///
/// * the word "default" occurs inside a field name (`[beacon].default_page_limit`), so a
///   naive scan reads the next backtick as its "value";
/// * a claim can belong to a field on the previous line (`api.md` wraps
///   ``(default `…`) and `[beacon].sensitive_base_path` (default``), so the first field on
///   the line is not the one being described.
///
/// Rules: a `default` token counts only outside backticks and on a word boundary, its value
/// is the next backticked span, and it is attributed to the nearest field reference before
/// it on the same line. No preceding field on the line means the claim is skipped.
fn default_claims_in(line: &str) -> Vec<(String, String)> {
    // Backtick spans, so we can tell "inside code" from "prose".
    let ticks: Vec<usize> = line.match_indices('`').map(|(i, _)| i).collect();
    let inside_code = |pos: usize| ticks.iter().take_while(|&&t| t < pos).count() % 2 == 1;

    // Field references and where they start: `[section].field`
    let mut fields: Vec<(usize, String)> = Vec::new();
    for (start, _) in line.match_indices("`[") {
        let rest = &line[start + 2..];
        let Some(close) = rest.find(']') else {
            continue;
        };
        let section = &rest[..close];
        let Some(after) = rest.get(close + 1..).and_then(|a| a.strip_prefix('.')) else {
            continue;
        };
        let end = after
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(after.len());
        let field = &after[..end];
        if !section.is_empty() && !field.is_empty() {
            fields.push((start, format!("{section}.{field}")));
        }
    }

    let lower = line.to_ascii_lowercase();
    let mut out = Vec::new();
    for (at, _) in lower.match_indices("default") {
        // "default_page_limit" is an identifier, not a claim, and a `default` inside
        // backticks is part of a name rather than prose about one.
        let next = line[at + "default".len()..].chars().next();
        if next.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') || inside_code(at) {
            continue;
        }
        // The claimed value: the next backticked span after the word.
        let rest = &line[at..];
        let Some(open) = rest.find('`') else { continue };
        let after = &rest[open + 1..];
        let Some(close) = after.find('`') else {
            continue;
        };
        let value = after[..close].trim();
        if value.is_empty() {
            continue;
        }
        // Attribute it to the nearest field mentioned before it on this line.
        let Some((_, field)) = fields.iter().rfind(|(pos, _)| *pos < at) else {
            continue; // the claim belongs to a field on another line — too ambiguous to judge
        };
        out.push((field.clone(), value.to_owned()));
    }
    out
}

/// Flatten the serialized config to dotted leaf paths, stringifying scalars the way a doc
/// would quote them.
fn flatten(prefix: &String, v: &serde_json::Value, out: &mut BTreeMap<String, String>) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, vv) in map {
                let p = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten(&p, vv, out);
            }
        }
        serde_json::Value::String(s) => {
            out.insert(prefix.clone(), s.clone());
        }
        serde_json::Value::Null | serde_json::Value::Array(_) => {}
        other => {
            out.insert(prefix.clone(), other.to_string());
        }
    }
}

/// The doc surfaces that make CI and release claims a reader acts on. Includes
/// `CHANGELOG.md` and `CONTRIBUTING.md`, which [`DOC_SURFACES`] omits.
const CI_CLAIM_SURFACES: &[&str] = &[
    "README.md",
    "CONTRIBUTING.md",
    "CHANGELOG.md",
    "docs/operating.md",
    "docs/deployment.md",
    "docs/testing.md",
    "docs/api.md",
    "docs/architecture.md",
    "docs/gdi-dataset-tool.md",
    "docs/package-format.md",
    "conformance/README.md",
];

/// Phrase groups that assert a *released artifact* as accomplished fact. Each inner slice is
/// a conjunction: every lowercased substring must appear on one line for it to count.
///
/// Claims about CI are deliberately absent. The workflows are real and the docs describe them
/// in the present tense on purpose; what remains untrue until a `v*` tag is pushed is the
/// existence of a release, an asset, or a published image. The list stays narrow, so
/// phrasings with honest uses ("the release job will publish") are not in it.
const CI_CLAIM_MARKERS: &[&[&str]] = &[
    &["attached to each release"],
    &["attached to every release"],
    &["download it from the releases page"],
    &["pull the published image"],
];

/// Tokens that make a CI or release mention honest instead of misleading: the caveat that CI
/// does not run here. A claim standing within two lines of one of these passes.
const CI_CLAIM_DISCLAIMERS: &[&str] = &[
    "no git remote",
    "never run",
    "never ran",
    "has never",
    "no hosted ci",
    "false here",
    "not a mirror",
    "run it yourself",
    "is the gate",
    "none gates",
    "advisory",
    "continue-on-error",
    "not a gate",
    "not a merge blocker",
];

/// Whether any `v*` release tag exists. This is the premise of the guard below: once a tag
/// is pushed the release, its assets and its image exist, so the claims become true and the
/// guard steps aside. A missing `git`, or no work tree, counts as no tag, which fails toward
/// enforcement.
fn has_release_tag() -> bool {
    std::process::Command::new("git")
        .arg("-C")
        .arg(repo_path(""))
        .args(["tag", "--list", "v*"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .is_some_and(|o| !String::from_utf8_lossy(&o.stdout).trim().is_empty())
}

/// Seam: no doc may advertise a release artifact before one exists.
///
/// No `v*` tag has been pushed, so there is no GitHub Release, no `SHA256SUMS`, no
/// attestation and no `ghcr.io/…` image. A doc that tells a reader to download an asset
/// "attached to each release" sends them hunting for something that is not there.
///
/// It does not police claims about CI. The workflows are real and the docs describe them in
/// the present tense deliberately; the release is what is still untrue, so the release is
/// what this checks.
///
/// The fact cannot be single-sourced, because what it prevents is a new claim written into
/// prose, which only a guard can catch. So the phrase list is small and curated rather than a
/// prose grader, and a claim within two lines of a disclaimer passes. Extend
/// [`CI_CLAIM_MARKERS`] when a new framing appears; the guard stands aside once a `v*` tag
/// exists, because from that moment the claims are true.
#[test]
fn docs_do_not_advertise_releases_that_do_not_exist() {
    if has_release_tag() {
        return; // premise gone: a release exists, so the claims may hold.
    }

    let mut bad: Vec<String> = Vec::new();
    // Unlike the other scanning guards, finding zero claims here is a correct outcome:
    // there may be none to disclaim. What must not pass silently is reading no files, since
    // renaming every surface away leaves the guard scanning nothing while reporting success.
    // So the floor is on surfaces read, not on claims matched.
    let mut surfaces_read = 0_usize;
    for rel in CI_CLAIM_SURFACES {
        // Skip a renamed or removed surface rather than crash: the claim class matters, not
        // this exact file list.
        let Ok(text) = std::fs::read_to_string(repo_path(rel)) else {
            continue;
        };
        surfaces_read += 1;
        let orig: Vec<&str> = text.lines().collect();
        let lower: Vec<String> = orig.iter().map(|l| l.to_ascii_lowercase()).collect();
        for (n, line) in lower.iter().enumerate() {
            let is_claim = CI_CLAIM_MARKERS
                .iter()
                .any(|group| group.iter().all(|m| line.contains(m)));
            if !is_claim {
                continue;
            }
            // Honest if the caveat sits on this line or within two lines either side.
            let lo = n.saturating_sub(2);
            let hi = (n + 2).min(lower.len() - 1);
            let disclaimed =
                (lo..=hi).any(|i| CI_CLAIM_DISCLAIMERS.iter().any(|d| lower[i].contains(d)));
            if !disclaimed {
                bad.push(format!("{rel}:{}: {}", n + 1, orig[n].trim()));
            }
        }
    }

    assert!(
        surfaces_read > 0,
        "none of CI_CLAIM_SURFACES could be read: every doc this guard watches has been \
         renamed or removed, so it is scanning nothing"
    );
    assert!(
        bad.is_empty(),
        "docs advertise a release artifact that does not exist — no `v*` tag has been \
         pushed, so there is no Release, no SHA256SUMS, no attestation and no image:\n  \
         {}\n\nReword to the future form (\"the release job will publish\"), or keep the \
         caveat (\"no release has been cut\") within two lines of the claim. Once a `v*` tag \
         exists this guard stands aside on its own.",
        bad.join("\n  ")
    );
}

/// The shipped K8s base must carry the `startupProbe` its own runbook prescribes.
///
/// The management listener is not bound from process start, so during hydration both probes
/// get connection-refused rather than a 503. Without a `startupProbe`, `livenessProbe` runs
/// on its default budget of initialDelay 10 plus period 10 times failureThreshold 3, which
/// is shorter than one Vault connect-and-request timeout. A populated node can then be
/// `SIGKILL`ed mid-hydrate on every restart.
#[test]
fn k8s_deployment_declares_the_startup_probe_the_runbook_prescribes() {
    let manifest = std::fs::read_to_string(repo_path("deploy/kubernetes/base/deployment.yaml"))
        .expect("read deploy/kubernetes/base/deployment.yaml");
    assert!(
        manifest.contains("startupProbe:"),
        "the shipped base must declare a startupProbe (operating.md §1 prescribes one); \
         without it liveness can SIGKILL a node that is still hydrating"
    );
    // It must gate on readiness, not liveness: /health/live answers as soon as the listener
    // binds, so a startupProbe pointed at it succeeds before the hydration it covers has
    // finished.
    let after = manifest
        .split_once("startupProbe:")
        .expect("startupProbe present")
        .1;
    // Wide enough to span the block plus its comments, narrow enough not to reach the
    // sibling probes below (which have their own failureThreshold).
    let block: String = after.lines().take(10).collect::<Vec<_>>().join("\n");
    assert!(
        block.contains("/health/ready"),
        "the startupProbe must probe /health/ready, not /health/live: {block}"
    );
    assert!(
        block.contains("failureThreshold"),
        "the startupProbe must set an explicit failureThreshold — the default (3) is far \
         below the Vault + store-self-test window it exists to cover: {block}"
    );
}

/// A cited path may legitimately be absent from a clean checkout when it is gitignored,
/// developer-local material. Keep this list tiny and justified: every entry is a hole in the
/// guard below.
///
/// * `.cargo/config.toml`: the gitignored `mold` opt-in `scripts/dev-setup.sh` offers to
///   write. `CONTRIBUTING.md` tells you to create it, so a clean checkout lacks it.
/// * `compose/keys/`: dev crypt4gh key material minted by hand (`.gitignore` keeps only the
///   `.gitkeep`). `scripts/dev-reset.sh --keys` deletes it again.
/// * `target/`: build output. `target/.gate-ok` exists only after a green gate run, so
///   including it would tie this guard's verdict to whether you had built yet.
const CITED_BUT_NOT_IN_TREE: &[&str] = &[".cargo/", "compose/keys/", "target/"];

/// Extensions that make a token a file citation rather than dotted member access. Needed
/// only for the Rust scan: prose does not write `module.function`.
const FILE_EXTENSIONS: &[&str] = &[
    "rs", "md", "toml", "py", "sh", "yml", "yaml", "json", "lock", "hbs", "txt", "ttl", "example",
    "gz", "tsv", "vcf", "c4gh", "parquet", "tar", "pub", "sec",
];

/// Punctuation a citation may be wrapped in when backticks do not delimit it: a trailing
/// full stop, a parenthesised aside, a quoted TOML value.
const TRIM_AROUND_CITATION: &[char] = &['.', ',', ';', ':', '!', '?', ')', '(', '"', '\'', '`'];

/// The candidate path citations on one line of `rel`.
///
/// Markdown delimits a citation with backticks, so only backticked spans are scanned there.
/// Prose names files loosely ("see the deployment doc") and a whitespace scan would chase
/// every sentence. A `.toml` template has no such convention: its citations sit bare in `#`
/// comments and inside quoted values, so there the unit is the whitespace-separated token,
/// filtered by the same three tests the caller applies (contains `/`, first segment is a real
/// top-level entry, last segment carries an extension). Those filters keep the whitespace
/// scan from turning into noise: `http://…`, `<data_dir>/overrides` and `[[s3.buckets]]` all
/// fall out on their own.
fn citation_spans<'a>(rel: &str, line: &'a str) -> Vec<&'a str> {
    let is_toml = Path::new(rel)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("toml"));
    if is_toml {
        line.split([' ', '\t', '"', '\'', '`', '=', '[', ']', ','])
            .collect()
    } else {
        line.split('`').skip(1).step_by(2).collect()
    }
}

/// Seam: a repo path cited in prose must be a path that exists.
///
/// This walks `docs/` from the filesystem rather than [`DOC_SURFACES`], for two reasons.
/// [`DOC_SURFACES`] omits some docs, and a doc added tomorrow is covered the day it lands
/// rather than whenever someone remembers to extend a list.
///
/// Scope: a backticked span counts as a citation only when it contains a `/`, its first
/// segment is a real top-level entry of the repo, and its last segment carries an extension.
/// `<placeholder>` and glob spans are patterns rather than paths, and are skipped.
#[test]
fn docs_cite_repo_paths_that_exist() {
    let top: std::collections::BTreeSet<String> = std::fs::read_dir(repo_path("."))
        .expect("read repo root")
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();

    // Every markdown doc, discovered rather than listed, plus the two root guides.
    let mut targets: Vec<String> = std::fs::read_dir(repo_path("docs"))
        .expect("read docs/")
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| {
            Path::new(n)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("md"))
        })
        .map(|n| format!("docs/{n}"))
        .collect();
    targets.sort();
    targets.push("README.md".to_owned());
    targets.push("CONTRIBUTING.md".to_owned());
    // The two annotated config templates are operator-facing prose as much as the markdown
    // is: their comments explain each knob and cite the files that set it. So they are
    // scanned alongside the docs.
    targets.push("node.example.toml".to_owned());
    targets.push("tool.example.toml".to_owned());

    let mut checked = 0usize;
    let mut bad: Vec<String> = Vec::new();

    for rel in &targets {
        let text = read(rel);
        for (n, line) in text.lines().enumerate() {
            for span in citation_spans(rel, line) {
                let cited = span.trim().trim_matches(TRIM_AROUND_CITATION);
                if !cited.contains('/')
                    || cited.contains(['<', '>', '*', '$', ' '])
                    || CITED_BUT_NOT_IN_TREE.iter().any(|p| cited.starts_with(p))
                {
                    continue;
                }
                let Some((first, _)) = cited.split_once('/') else {
                    continue;
                };
                if !top.contains(first) {
                    continue; // not a repo-relative path (a URL fragment, a glob, prose)
                }
                let last = cited.rsplit('/').next().unwrap_or_default();
                if !last.contains('.') {
                    continue; // a directory reference, not a file citation
                }
                checked += 1;
                if !repo_path(cited).exists() {
                    bad.push(format!("{rel}:{}: cites `{cited}`: no such file", n + 1));
                }
            }
        }
    }

    // Ratchet, not a floor of one: a `> 0` floor would let coverage rot to a single line and
    // still pass. Lower it only alongside a real removal of citations.
    assert!(
        checked >= 100,
        "only {checked} path citations matched (expected >= 100), so the scanner has \
         stopped seeing most of the docs"
    );
    assert!(
        bad.is_empty(),
        "docs cite repo paths that do not exist:\n  {}\n\n\
         Fix the citation (or add a justified entry to CITED_BUT_NOT_IN_TREE if the path is \
         gitignored developer-local material).",
        bad.join("\n  ")
    );
}

/// Seam: a repo path cited in a Rust comment must be a path that exists.
///
/// The sibling test above scans prose; this one scans `crates/**/*.rs`. A file that becomes
/// a directory module leaves every citation of it pointing at nothing, and nothing else
/// notices.
///
/// Comment lines only: a path in a string literal is a fixture or an argument, not a claim
/// about the tree.
///
/// A cited `foo.rs` whose `foo/` exists is reported as stale rather than missing, because
/// that names the cause.
#[test]
fn rust_comments_cite_repo_paths_that_exist() {
    fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                // `target/` holds generated sources that cite generated paths.
                if path.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                rust_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    let top: std::collections::BTreeSet<String> = std::fs::read_dir(repo_path("."))
        .expect("read repo root")
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();

    let mut files = Vec::new();
    rust_files(&repo_path("crates"), &mut files);
    files.sort();
    assert!(
        files.len() >= 100,
        "only {} Rust files found under crates/, so this scan is not seeing the tree",
        files.len()
    );

    let mut checked = 0usize;
    let mut bad: Vec<String> = Vec::new();

    for path in &files {
        let rel = path
            .strip_prefix(repo_path("."))
            .unwrap_or(path)
            .to_string_lossy()
            .into_owned();
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for (n, line) in text.lines().enumerate() {
            if !line.trim_start().starts_with("//") {
                continue;
            }
            for span in citation_spans(&rel, line) {
                let cited = span.trim().trim_matches(TRIM_AROUND_CITATION);
                if !cited.contains('/')
                    || cited.contains(['<', '>', '*', '$', ' '])
                    || CITED_BUT_NOT_IN_TREE.iter().any(|p| cited.starts_with(p))
                {
                    continue;
                }
                let Some((first, _)) = cited.split_once('/') else {
                    continue;
                };
                if !top.contains(first) {
                    continue;
                }
                // Two shapes appear in Rust comments but not in prose, and both look like
                // a path with an extension. `foo.rs::some_test` names an item inside a
                // file, so the path is everything before the `::`. `_helpers.strip_test_
                // modules` is dotted member access, where the "extension" is a function
                // name; requiring a real file extension is what separates the two.
                let cited = cited.split("::").next().unwrap_or(cited);
                let last = cited.rsplit('/').next().unwrap_or_default();
                let Some((_, ext)) = last.rsplit_once('.') else {
                    continue;
                };
                if !FILE_EXTENSIONS.contains(&ext) {
                    continue;
                }
                checked += 1;
                if repo_path(cited).exists() {
                    continue;
                }
                let stem = cited.strip_suffix(".rs").filter(|s| repo_path(s).is_dir());
                match stem {
                    Some(dir) => bad.push(format!(
                        "{rel}:{}: cites `{cited}`: stale, `{dir}/` is a directory module now",
                        n + 1
                    )),
                    None => bad.push(format!("{rel}:{}: cites `{cited}`: no such file", n + 1)),
                }
            }
        }
    }

    // Ratchet, as above: a `> 0` floor would let coverage rot to one line and still pass.
    assert!(
        checked >= 100,
        "only {checked} path citations matched in Rust comments (expected >= 100), so the \
         scanner has stopped seeing most of them"
    );
    assert!(
        bad.is_empty(),
        "Rust comments cite repo paths that do not exist:\n  {}\n\n\
         Fix the citation, or add a justified entry to CITED_BUT_NOT_IN_TREE if the path is \
         gitignored developer-local material.",
        bad.join("\n  ")
    );
}

/// `about.hbs` renders the third-party attribution bundle. Handlebars' double-brace
/// interpolation HTML-escapes its value; the triple-brace form emits it raw. The licence
/// bodies land inside a fenced code block, where Markdown does not decode entities, so an
/// escaping interpolation ships a literal `&quot;Licensor&quot;` to every consumer and
/// mangles attribution lines such as `Sean McArthur &amp; Hyper Contributors`.
///
/// The `licenses` leg cannot catch this: it re-renders with the same template and diffs the
/// result against the committed file, so both sides carry the identical corruption and agree.
/// It verifies freshness, not fidelity. This test reads the shipped artifact instead.
#[test]
fn third_party_licences_are_verbatim_not_html_escaped() {
    // The escaped forms only. A licence text may contain a bare `&` ("AT&T"); it must never
    // contain `&amp;`.
    const ENTITIES: &[&str] = &["&quot;", "&#x27;", "&lt;", "&gt;", "&amp;", "&#x3D;"];
    let rel = "THIRD-PARTY-LICENSES.md";
    let text =
        std::fs::read_to_string(repo_path(rel)).unwrap_or_else(|e| panic!("reading {rel}: {e}"));

    let found: Vec<String> = ENTITIES
        .iter()
        .filter_map(|entity| match text.matches(entity).count() {
            0 => None,
            n => Some(format!("{entity} x{n}")),
        })
        .collect();

    assert!(
        found.is_empty(),
        "{rel} carries HTML entity escapes ({}) — the shipped licence texts are not \
         verbatim, which breaks the attribution/notice obligation they exist to discharge.\n\
         Cause: an escaping double-brace interpolation in about.hbs. Use the raw \
         triple-brace form for `text` and `name`, then regenerate:\n  \
         cargo about generate about.hbs -o {rel}",
        found.join(", ")
    );
}
