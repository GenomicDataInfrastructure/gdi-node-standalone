//! Config-drift guard: the shipped, hand-maintained example configs are pinned to the
//! typed config definitions in code.
//!
//! The `compose/` configs boot the dev stack unedited, so they must parse into the typed
//! [`ServiceConfig`] and pass the same `preflight` the live service runs. The two annotated
//! templates, `node.example.toml` and `node.quickstart.toml`, carry `<SET ME: …>`
//! placeholders for the fields an operator supplies, so they hold the stricter contract of
//! [`assert_placeheld_template`]: parse always, fail preflight while a placeholder stands,
//! preflight cleanly once filled. The provider config `tool.example.toml` must parse into
//! [`ToolConfig`]. A field renamed, removed or retyped in code, or a new cross-field
//! preflight rule, breaks the examples here instead of leaving a stale example behind. Both
//! config structs `deny_unknown_fields`, so a stale key in an example also fails here.
//!
//! `ServiceConfig::preflight` is feature-independent (the `--features full` gating
//! of `[vault]`/`[s3]`/`[[s3.buckets]]` is the service binary's own startup check),
//! so the full-stack example preflights under the default (lite) test build too.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use gdi_node_standalone_core::config::{S3Bucket, ServiceConfig, ToolConfig, VaultConfig};

/// The workspace root, relative to this crate's manifest dir.
fn repo_path(rel: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

/// Parse + preflight one shipped service config, relative to the workspace root.
fn parse_and_preflight(rel: &str) {
    let path = repo_path(rel);
    let toml = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    let cfg = ServiceConfig::from_toml_str(&toml)
        .unwrap_or_else(|e| panic!("{rel} no longer parses into ServiceConfig: {e}"));
    cfg.preflight()
        .unwrap_or_else(|e| panic!("{rel} fails preflight: {e}"));
}

/// The `compose/` configs boot the dev stack unedited, so they must be valid as shipped. The
/// two annotated templates are not, and are covered by [`assert_placeheld_template`].
#[test]
fn shipped_compose_configs_parse_and_preflight() {
    // Enumerated from disk rather than listed here, so a config added to `compose/` is
    // covered the moment it lands. A hand-written list only covers what someone remembered
    // to add to it.
    let compose = repo_path("compose");
    let mut found = 0usize;
    let mut entries: Vec<_> = std::fs::read_dir(&compose)
        .unwrap_or_else(|e| panic!("reading {}: {e}", compose.display()))
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        // The `node.` prefix is the discriminator, not decoration: `compose/` also holds
        // `garage.toml`, an S3-server config that is not a `ServiceConfig` and must not be
        // parsed as one. Naming every node config `node.*` is what makes "is this ours?"
        // answerable from the file name alone.
        .filter(|n| {
            n.starts_with("node.")
                && Path::new(n)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"))
        })
        .collect();
    entries.sort();
    for name in entries {
        parse_and_preflight(&format!("compose/{name}"));
        found += 1;
    }
    // A guard that scans nothing reports success. Pin the floor so an empty/renamed
    // directory fails loudly instead of passing vacuously.
    assert!(
        found >= 3,
        "expected at least 3 shipped compose configs, found {found} — did compose/ move, \
         or were its `node.*.toml` configs renamed out from under this scan?"
    );
}

/// The full contract for a shipped template that carries `<SET ME: …>` placeholders.
///
/// The template parses, so a renamed, removed or retyped field breaks here via
/// `deny_unknown_fields`. It fails preflight while a placeholder stands, which is the
/// fail-fast `check-config` relies on: a half-edited copy cannot boot with a placeholder
/// identity or a literal `<…>` where a credential belongs. Once the hints are substituted it
/// preflights cleanly, which pins that the hints are usable values and that no new required
/// field has left a filled-in copy invalid.
fn assert_placeheld_template(rel: &str) {
    let path = repo_path(rel);
    let toml = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));

    let cfg = ServiceConfig::from_toml_str(&toml)
        .unwrap_or_else(|e| panic!("{rel} must parse into ServiceConfig: {e}"));
    let err = cfg
        .preflight()
        .expect_err(&format!(
            "{rel} must fail preflight while it holds <SET ME> placeholders"
        ))
        .to_string();
    assert!(
        err.contains("placeholder"),
        "{rel} preflight failure should be the placeholder error: {err}"
    );

    let filled = fill_placeholders(&toml);
    assert!(
        !filled.contains("<SET ME"),
        "filling {rel} left a placeholder in a non-`<SET ME: hint>` form; fix the marker:\n{filled}"
    );
    let cfg = ServiceConfig::from_toml_str(&filled)
        .unwrap_or_else(|e| panic!("filled {rel} must parse into ServiceConfig: {e}"));
    cfg.preflight().unwrap_or_else(|e| {
        panic!("{rel} must preflight once its <SET ME> hints are filled in: {e}")
    });
}

#[test]
fn quickstart_parses_but_fails_preflight_until_filled() {
    assert_placeheld_template("node.quickstart.toml");
}

/// The Kubernetes example carries a template too: `deploy/kubernetes/base/node.toml`, the
/// input to the `configMapGenerator` in that directory's kustomization. It is the one config
/// in this repo an operator applies to a live cluster.
///
/// It is held to the same contract as the other two because its failure mode is worse. At one
/// replica under `strategy: Recreate`, a config preflight rejects is not a failed apply. It
/// is a crash-loop with no previous pod still serving, on a distroless image that cannot be
/// shelled into to ask why. Filling the hints and preflighting is what makes "these
/// placeholders are usable values" a checked claim.
#[test]
fn k8s_example_parses_but_fails_preflight_until_filled() {
    assert_placeheld_template("deploy/kubernetes/base/node.toml");
}

/// `node.example.toml` is the annotated reference an operator copies. Its S3 and Vault
/// credential fields are `<SET ME: …>` for the same reason the quickstart's are: without them
/// `check-config` reports OK on a config whose access key is still placeholder text, so the
/// pre-deploy gate passes and the node takes S3 403s and Vault auth failures at first ingest.
#[test]
fn example_parses_but_fails_preflight_until_filled() {
    assert_placeheld_template("node.example.toml");
}

/// Replace every `<SET ME: hint>` marker with its `hint` text, the substitution an operator
/// makes by hand when filling in a shipped template.
fn fill_placeholders(toml: &str) -> String {
    const OPEN: &str = "<SET ME: ";
    let mut out = String::with_capacity(toml.len());
    let mut rest = toml;
    while let Some(start) = rest.find(OPEN) {
        out.push_str(&rest[..start]);
        let after = &rest[start + OPEN.len()..];
        if let Some(end) = after.find('>') {
            out.push_str(after[..end].trim());
            rest = &after[end + 1..];
        } else {
            // A malformed marker with no closing `>` leaves the tail untouched, so the
            // residual `<SET ME` assertion in the test fails loudly.
            out.push_str(after);
            rest = "";
        }
    }
    out.push_str(rest);
    out
}

#[test]
fn shipped_tool_example_config_parses() {
    // The provider-side example parses into the typed `ToolConfig`, which
    // `deny_unknown_fields`, so a stale or mistyped key fails here.
    let path = repo_path("tool.example.toml");
    // Assert existence first. `ToolConfig::load` goes through figment's `Toml::file`, which
    // treats a missing file as an empty document and hands back a default `ToolConfig`, so
    // without this the test would report success having parsed nothing, and stay green with
    // `tool.example.toml` deleted or renamed. It is the only guard on that file.
    assert!(
        path.exists(),
        "tool.example.toml is missing at {} — this guard parses nothing when the file is \
         absent, so its absence must fail loudly here",
        path.display()
    );
    ToolConfig::load(Some(&path))
        .unwrap_or_else(|e| panic!("tool.example.toml no longer parses into ToolConfig: {e}"));
}

/// Path prefixes `node.example.toml` populates with required or illustrative deployment
/// values rather than built-in defaults: node identity and URLs, the catalog list, FDP
/// descriptive metadata, and the S3 and Vault wiring.
///
/// The `[s3]` and `[vault]` sections are `Option`, so they are `None` in the default config
/// and every leaf under them necessarily differs. Their own internal defaults are guarded by
/// their type's `Default`. Any leaf outside these prefixes, meaning the tuning knobs in
/// `[service]`, `[beacon.configuration]`, `[keys]` and `[audit]`, must equal
/// `ServiceConfig::default()`.
const EXAMPLE_OVERRIDE_PREFIXES: &[&str] = &[
    "catalogs",
    "fairdp",
    "s3",
    "vault",
    "keys.identities",
    "beacon.id",
    "beacon.name",
    "beacon.documentation_url",
    "beacon.organization",
    "service.base_url",
    "service.data_dir",
    "service.inbox",
    // Shown at `true` against a built-in default of `false`; the key's annotation in
    // `node.example.toml` explains why. This is the one knob where the built-in default and
    // the value an operator should copy differ. The default is permissive so a fresh node
    // with no override store still boots, while any node that has recorded a suppression
    // wants the assertion on. Flipping the default would make existing store-less nodes
    // refuse to boot on upgrade, so the example carries the deployment value instead.
    "service.require_override_store",
];

/// Flatten a `serde_json` value tree into `dotted.path -> scalar` leaves.
fn flatten_leaves(prefix: &str, v: &serde_json::Value, out: &mut BTreeMap<String, String>) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, vv) in map {
                let p = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten_leaves(&p, vv, out);
            }
        }
        serde_json::Value::Array(items) => {
            for (i, vv) in items.iter().enumerate() {
                flatten_leaves(&format!("{prefix}[{i}]"), vv, out);
            }
        }
        scalar => {
            out.insert(prefix.to_owned(), scalar.to_string());
        }
    }
}

/// `node.example.toml` is the exhaustive annotated reference, so every tuning knob it lists
/// shows the built-in default. An operator who copies it, or reads it to learn a default, is
/// then not misled.
///
/// Parse the example into `ServiceConfig`, compare every leaf against
/// `ServiceConfig::default()`, and require a match except for the required and illustrative
/// values under `EXAMPLE_OVERRIDE_PREFIXES`. A field whose example value drifts from its
/// default fails here until it is corrected or covered by a prefix.
#[test]
fn config_example_documents_real_defaults() {
    let toml =
        std::fs::read_to_string(repo_path("node.example.toml")).expect("read node.example.toml");
    let example = serde_json::to_value(
        ServiceConfig::from_toml_str(&toml).expect("node.example.toml parses"),
    )
    .expect("serialize parsed example");
    let default = serde_json::to_value(ServiceConfig::default()).expect("serialize default config");

    let mut ex = BTreeMap::new();
    let mut de = BTreeMap::new();
    flatten_leaves("", &example, &mut ex);
    flatten_leaves("", &default, &mut de);

    let matches = |path: &str, prefix: &str| {
        path == prefix
            || path
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('.') || rest.starts_with('['))
    };
    let is_override = |path: &str| EXAMPLE_OVERRIDE_PREFIXES.iter().any(|p| matches(path, p));

    let differs: BTreeSet<&str> = ex
        .iter()
        .filter(|(k, v)| de.get(*k) != Some(*v))
        .map(|(k, _)| k.as_str())
        .collect();

    let unexpected: Vec<String> = differs
        .iter()
        .copied()
        .filter(|&k| !is_override(k))
        .map(|k| {
            let def = de.get(k).map_or("<absent>", |v| v.as_str());
            format!("  - {k} = {} (built-in default: {def})", ex[k])
        })
        .collect();
    assert!(
        unexpected.is_empty(),
        "node.example.toml sets these tuning knobs to a NON-default value — correct \
         them to the built-in default so the reference does not mislead (this is the \
         `strict_key_perms` drift class), or if the example must show a non-default, \
         extend EXAMPLE_OVERRIDE_PREFIXES:\n{}",
        unexpected.join("\n")
    );

    let unused: Vec<&str> = EXAMPLE_OVERRIDE_PREFIXES
        .iter()
        .copied()
        .filter(|&p| !differs.iter().any(|&k| matches(k, p)))
        .collect();
    assert!(
        unused.is_empty(),
        "EXAMPLE_OVERRIDE_PREFIXES has entries that match no deviation (remove them): \
         {unused:?}"
    );
}

/// Whether the example documents `leaf` as a commented-out assignment (`# key = <example>`).
///
/// A knob shown that way is an opt-in feature illustrated rather than activated, such as the
/// `otel` knobs. It still counts as documented. Only a knob with neither an active nor a
/// commented assignment is undocumented.
fn commented_leaf_in(toml_text: &str, leaf: &str) -> bool {
    toml_text.lines().any(|line| {
        line.trim_start()
            .strip_prefix('#')
            .map(str::trim_start)
            .and_then(|rest| rest.strip_prefix(leaf))
            .is_some_and(|rest| rest.trim_start().starts_with('='))
    })
}

/// Completeness guard: every tuning knob `ServiceConfig::default()` carries appears in
/// `node.example.toml`.
///
/// [`config_example_documents_real_defaults`] checks only the value of knobs the example
/// already lists. A knob left out is filled with its default on parse and then matches it, so
/// the "exhaustive annotated reference" claim erodes without this. Parsing the raw example
/// TOML, whose absent keys are genuinely absent, and requiring every non-override default leaf
/// to appear closes that.
#[test]
fn config_example_documents_every_tuning_knob() {
    let toml_text =
        std::fs::read_to_string(repo_path("node.example.toml")).expect("read node.example.toml");
    let raw: serde_json::Value =
        toml::from_str(&toml_text).expect("node.example.toml is valid TOML");
    let default = serde_json::to_value(ServiceConfig::default()).expect("serialize default config");

    let mut present = BTreeMap::new();
    let mut de = BTreeMap::new();
    flatten_leaves("", &raw, &mut present);
    flatten_leaves("", &default, &mut de);
    let present_keys: BTreeSet<&str> = present.keys().map(String::as_str).collect();

    let matches = |path: &str, prefix: &str| {
        path == prefix
            || path
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('.') || rest.starts_with('['))
    };
    let is_override = |path: &str| EXAMPLE_OVERRIDE_PREFIXES.iter().any(|p| matches(path, p));

    // A knob shown commented out, such as the `otel` knobs, still documents it. Only a knob
    // with neither an active nor a commented assignment is undocumented.
    let commented_leaf = |leaf: &str| commented_leaf_in(&toml_text, leaf);

    let missing: Vec<String> = de
        .keys()
        .map(String::as_str)
        .filter(|k| !is_override(k))
        .filter(|k| !present_keys.contains(k))
        .filter(|k| !commented_leaf(k.rsplit('.').next().unwrap_or(k)))
        .map(|k| format!("  - {k} (built-in default: {})", de[k]))
        .collect();
    assert!(
        missing.is_empty(),
        "node.example.toml omits these tuning knobs that ServiceConfig::default() has \
         — add each (set to its built-in default, with a comment) so the annotated \
         reference stays exhaustive, or if it is a required/illustrative field extend \
         EXAMPLE_OVERRIDE_PREFIXES:\n{}",
        missing.join("\n")
    );
}

/// Complements [`config_example_documents_real_defaults`] for the optional sections.
///
/// `[s3]` and `[vault]` are `Option`, so they are `None` in `ServiceConfig::default()` and the
/// main test cannot reach their internal knob defaults. This compares the example's populated
/// section against the section type's own `Default` instead. Content and illustrative fields
/// are skipped: endpoints, credentials, and `path_style`, which the example sets to `true`
/// for the non-AWS case its comment documents while stating the `false` default. The
/// remaining knobs, namely the Vault mounts and timeouts, the bucket poll intervals,
/// `allow_http` and `write_status`, must equal the default.
#[test]
fn config_example_documents_section_defaults() {
    fn assert_section_knobs(
        label: &str,
        example_section: Option<&serde_json::Value>,
        default_section: &serde_json::Value,
        skip: &[&str],
    ) {
        let section = example_section.unwrap_or_else(|| {
            panic!("node.example.toml is missing the [{label}] section this guard checks")
        });
        let mut ex = BTreeMap::new();
        let mut de = BTreeMap::new();
        flatten_leaves("", section, &mut ex);
        flatten_leaves("", default_section, &mut de);
        let mismatched: Vec<String> = ex
            .iter()
            .filter(|(k, _)| !skip.contains(&k.as_str()))
            .filter(|(k, v)| de.get(*k) != Some(*v))
            .map(|(k, v)| {
                let def = de.get(k).map_or("<absent>", |d| d.as_str());
                format!("  - {label}.{k} = {v} (built-in default: {def})")
            })
            .collect();
        assert!(
            mismatched.is_empty(),
            "node.example.toml documents non-default values for these [{label}] knobs \
             — correct them to the type's built-in default:\n{}",
            mismatched.join("\n")
        );
    }

    let toml =
        std::fs::read_to_string(repo_path("node.example.toml")).expect("read node.example.toml");
    let example = serde_json::to_value(
        ServiceConfig::from_toml_str(&toml).expect("node.example.toml parses"),
    )
    .expect("serialize parsed example");

    assert_section_knobs(
        "vault",
        example.get("vault"),
        &serde_json::to_value(VaultConfig::default()).expect("serialize VaultConfig::default"),
        &["address", "token", "kv_path", "s3_path"],
    );

    let bucket0 = example
        .get("s3")
        .and_then(|s3| s3.get("buckets"))
        .and_then(|buckets| buckets.get(0));
    assert_section_knobs(
        "s3.buckets[0]",
        bucket0,
        &serde_json::to_value(S3Bucket::default()).expect("serialize S3Bucket::default"),
        &[
            "name",
            "endpoint",
            "bucket",
            "region",
            "access_key_id",
            "secret_access_key",
            "path_style",
        ],
    );
}

/// Completeness for the optional sections, which
/// [`config_example_documents_section_defaults`] cannot see.
///
/// That guard parses the example into `ServiceConfig` first, so a key deleted from `[vault]`
/// or `[[s3.buckets]]` is serde-default-filled on parse and then matches the default it is
/// compared against. The gap is absence, not wrongness. `ServiceConfig::default()` cannot
/// close it either: both sections are `Option` and therefore `None` there, so they contribute
/// no leaves for [`config_example_documents_every_tuning_knob`] to find missing, and both are
/// listed in `EXAMPLE_OVERRIDE_PREFIXES`.
///
/// Comparing the raw TOML against the section type's own `Default` closes it. A new `S3Bucket`
/// or `VaultConfig` field then fails here until the reference documents it. `[fairdp]` is
/// absent because it has no `Default`: its fields are required deployment metadata rather
/// than defaulted knobs.
#[test]
fn config_example_documents_every_optional_section_knob() {
    let toml_text =
        std::fs::read_to_string(repo_path("node.example.toml")).expect("read node.example.toml");
    let raw: serde_json::Value =
        toml::from_str(&toml_text).expect("node.example.toml is valid TOML");

    let assert_documents_every_field_of =
        |label: &str,
         raw_section: Option<&serde_json::Value>,
         default_section: &serde_json::Value| {
            let section = raw_section.unwrap_or_else(|| {
                panic!(
                    "node.example.toml has no [{label}] section — this guard reads the RAW TOML, \
                 so the section must be present and populated for it to mean anything"
                )
            });
            let mut present = BTreeMap::new();
            let mut de = BTreeMap::new();
            flatten_leaves("", section, &mut present);
            flatten_leaves("", default_section, &mut de);

            let missing: Vec<String> = de
                .keys()
                .filter(|k| !present.contains_key(*k))
                .filter(|k| !commented_leaf_in(&toml_text, k.rsplit('.').next().unwrap_or(k)))
                .map(|k| format!("  - {label}.{k} (built-in default: {})", de[k]))
                .collect();
            assert!(
                missing.is_empty(),
                "node.example.toml OMITS these [{label}] knobs that the section type's Default \
             carries. The example claims to be exhaustive, and the value guard cannot catch \
             an omission (an absent key is default-filled on parse and then matches). Add \
             each with its built-in default and a comment:\n{}",
                missing.join("\n")
            );
        };

    assert_documents_every_field_of(
        "vault",
        raw.get("vault"),
        &serde_json::to_value(VaultConfig::default()).expect("serialize VaultConfig::default"),
    );
    assert_documents_every_field_of(
        "s3.buckets[0]",
        raw.get("s3")
            .and_then(|s3| s3.get("buckets"))
            .and_then(|buckets| buckets.get(0)),
        &serde_json::to_value(S3Bucket::default()).expect("serialize S3Bucket::default"),
    );
}

/// The literal right after `Default: ` in a template comment, or `None` when the claim is
/// prose rather than a value. A quoted claim keeps its quotes so it parses as a JSON string;
/// a bare token is taken up to the first space or comma, with the sentence's trailing `.`
/// stripped (`Default: 30.` -> `30`, `Default: 3600 (1 h).` -> `3600`).
fn claimed_literal(comment: &str) -> Option<String> {
    let rest = comment.split_once("Default: ")?.1.trim_start();
    if let Some(body) = rest.strip_prefix('"') {
        let end = body.find('"')?;
        return Some(format!("\"{}\"", &body[..end]));
    }
    let end = rest
        .find(|c: char| c.is_whitespace() || c == ',')
        .unwrap_or(rest.len());
    Some(rest[..end].trim_end_matches('.').to_owned())
}

/// The prose half of the reference is true too: every `# … Default: X.` comment states the
/// value the code has.
///
/// [`config_example_documents_real_defaults`] compares parsed values and never reads a
/// comment, and `seams::docs_quote_the_real_defaults` lists this file in `DOC_SURFACES` but
/// its `default_claims_in` fires only on a markdown shape the templates never use. Without
/// this test, a comment claiming `Default: 99999.` beside an assignment of the true `30`
/// keeps every guard green, and an operator reading a knob's default to decide whether to
/// override it is misled.
///
/// A claim is judged only when the claimed token is a JSON scalar: a number, a bool, or a
/// quoted string. Prose defaults such as `none`, `[]` or `"<data_dir>/overrides"` describe a
/// shape rather than a literal, and are skipped rather than guessed at.
#[test]
fn config_example_default_comments_match_the_code() {
    let toml_text =
        std::fs::read_to_string(repo_path("node.example.toml")).expect("read node.example.toml");

    // The dotted-path -> default-value map, assembled from the same three types the
    // value guards use, so this cannot disagree with them.
    let mut defaults = BTreeMap::new();
    flatten_leaves(
        "",
        &serde_json::to_value(ServiceConfig::default()).expect("serialize ServiceConfig::default"),
        &mut defaults,
    );
    flatten_leaves(
        "vault",
        &serde_json::to_value(VaultConfig::default()).expect("serialize VaultConfig::default"),
        &mut defaults,
    );
    flatten_leaves(
        "s3.buckets[0]",
        &serde_json::to_value(S3Bucket::default()).expect("serialize S3Bucket::default"),
        &mut defaults,
    );

    let mut section = String::new();
    let mut pending: Option<String> = None;
    let mut judged = 0_usize;
    let mut wrong: Vec<String> = Vec::new();

    for line in toml_text.lines() {
        let t = line.trim();
        if let Some(header) = t.strip_prefix("[[").and_then(|h| h.strip_suffix("]]")) {
            // An array-of-tables: the example populates exactly one, as index 0.
            section = format!("{header}[0]");
            pending = None;
            continue;
        }
        if let Some(header) = t.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
            section = header.to_owned();
            pending = None;
            continue;
        }
        if t.starts_with('#') && t.contains("Default: ") {
            pending = claimed_literal(t);
        }
        // Do not `continue` on a comment line: a commented-out knob (`# key = <example>`)
        // still documents it, so it has to reach the assignment match below.
        let assignment = t.trim_start_matches('#').trim_start();
        let Some((key, _)) = assignment.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        let Some(claim) = pending.take() else {
            continue;
        };
        let path = if section.is_empty() {
            key.to_owned()
        } else {
            format!("{section}.{key}")
        };
        // Only a JSON scalar is comparable; prose ("none", "[]") describes a shape.
        let Ok(parsed) = claim.parse::<serde_json::Value>() else {
            continue;
        };
        let Some(actual) = defaults.get(&path) else {
            continue; // a field with no built-in default (required deployment metadata)
        };
        judged += 1;
        if &parsed.to_string() != actual {
            wrong.push(format!(
                "  - {path}: comment claims `{claim}`, code default is `{actual}`"
            ));
        }
    }

    // A ratchet rather than a floor of one, because a guard that stops seeing claims reports
    // success. Most `Default:` claims in the file are comparable literals; the rest are prose
    // such as `none` or `[]`, or name a field with no built-in default at all. Lower this only
    // when documented defaults are intentionally removed.
    assert!(
        judged >= 50,
        "only {judged} `Default:` claims were judged (expected >= 50) — the scanner has \
         stopped seeing them, which is indistinguishable from every claim being correct"
    );
    assert!(
        wrong.is_empty(),
        "node.example.toml's `Default:` comments contradict the code — the prose is what an \
         operator reads to decide whether to override a knob:\n{}",
        wrong.join("\n")
    );
}

/// Every `[section]` in `node.example.toml` must carry a `TIER:` marker within the
/// next three lines.
///
/// The file is an exhaustive per-field reference, which is the right shape for looking a
/// field up and the wrong shape for deciding what to set. The `TIER:` markers make it
/// navigable: each section says up front whether an operator has to touch it (`REQUIRED`),
/// should make a decision about it (`RECOMMENDED`), or can leave it alone (`ADVANCED`),
/// matching the index at the top of the file.
///
/// This is a completeness check over one artifact, not a second copy of a fact: it asserts a
/// marker is present, never what tier it names.
#[test]
fn config_example_tiers_every_section() {
    let text = std::fs::read_to_string(repo_path("node.example.toml"))
        .expect("node.example.toml is readable");
    let lines: Vec<&str> = text.lines().collect();
    let mut untiered = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        // A section header at column 0: `[service]`, `[beacon.organization]`,
        // `[[s3.buckets]]`. Commented-out examples are indented or prefixed with `#`.
        let trimmed = line.trim_end();
        if !trimmed.starts_with('[') || !trimmed.ends_with(']') {
            continue;
        }
        let tiered = lines
            .iter()
            .skip(i + 1)
            .take(3)
            .any(|l| l.contains("TIER:"));
        if !tiered {
            untiered.push(format!("  line {}: {trimmed}", i + 1));
        }
    }
    assert!(
        untiered.is_empty(),
        "node.example.toml section(s) with no `TIER:` marker in the following 3 lines \
         — say whether an operator must set this block (REQUIRED), should decide about it \
         (RECOMMENDED), or can leave it alone (ADVANCED), and mirror it in the START HERE \
         index:\n{}",
        untiered.join("\n")
    );
}

/// A `data_dir` or `inbox` that exists but is a regular file fails preflight, while one that
/// is merely absent passes.
///
/// Both halves matter, and they pull in opposite directions. `check-config` is a pre-deploy
/// gate, run on machines that have none of the node's storage mounted, so requiring the
/// directory to exist would fail every such run. That is why preflight does not check
/// existence or writability. But a path that exists and is a file can never become a data dir
/// on any host, and answering `config check OK` for it is the one verdict a pre-deploy gate
/// must not give. A container mount landing a file where a directory was meant reaches it the
/// ordinary way.
#[test]
fn preflight_rejects_a_data_dir_that_is_a_file_but_tolerates_an_absent_one() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let file = tmp.path().join("i-am-a-file");
    std::fs::write(&file, b"not a directory").expect("write");

    let base = std::fs::read_to_string(repo_path("compose/node.minimal.toml")).expect("read");

    // Absent: passes. This is the pre-deploy case.
    let absent = tmp.path().join("not/yet/mounted");
    let ok = base.replace(
        "data_dir = \"/var/lib/gdi-node-standalone/datasets\"",
        &format!("data_dir = \"{}\"", absent.display()),
    );
    ServiceConfig::from_toml_str(&ok)
        .expect("parses")
        .preflight()
        .expect("an absent data_dir must not fail a pre-deploy check");

    // Exists as a file: fails, and names the field.
    let bad = base.replace(
        "data_dir = \"/var/lib/gdi-node-standalone/datasets\"",
        &format!("data_dir = \"{}\"", file.display()),
    );
    let err = ServiceConfig::from_toml_str(&bad)
        .expect("parses")
        .preflight()
        .expect_err("a data_dir that is a regular file cannot serve and must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("service.data_dir") && msg.contains("not a directory"),
        "the error must name the field and the reason; got: {msg}"
    );

    // The same rule covers the inbox, which is the other configured directory.
    let bad_inbox = base.replace(
        "inbox = \"/var/lib/gdi-node-standalone/inbox\"",
        &format!("inbox = \"{}\"", file.display()),
    );
    let err = ServiceConfig::from_toml_str(&bad_inbox)
        .expect("parses")
        .preflight()
        .expect_err("an inbox that is a regular file must be refused too");
    assert!(
        err.to_string().contains("service.inbox"),
        "the error must name the inbox field; got: {err}"
    );
}
