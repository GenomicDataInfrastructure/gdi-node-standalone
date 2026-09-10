//! Binds every `gdi-node-standalone …` invocation in `docs/operating.md` to clap: each
//! documented subcommand path must parse, with `--help` appended, against the built binary.
//!
//! The runbook exists to be copy-pasted, so a verb it names that the binary does not have
//! makes every recipe exit 2. This binds the subcommand path (verb and sub-verb), which is
//! what a renamed or removed verb breaks. The dataset tool's flags are bound separately, by
//! its own `cli_docs.rs`.
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

/// Every code span and fenced-code line in `doc`. Prose is excluded, because the runbook's
/// title (`gdi-node-standalone operator runbook`) is not a command.
fn code_text(doc: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_fence = false;
    for line in doc.lines() {
        if line.trim_start().starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            out.push(line.to_owned());
            continue;
        }
        let mut rest = line;
        while let Some(open) = rest.find('`') {
            let Some(len) = rest[open + 1..].find('`') else {
                break;
            };
            out.push(rest[open + 1..open + 1 + len].to_owned());
            rest = &rest[open + 1 + len + 1..];
        }
    }
    out
}

/// The subcommand path an invocation names: the tokens after `gdi-node-standalone`, skipping
/// the global `--config <PATH>`, taking the leading lowercase-dash words up to two levels. A
/// subcommand is never capitalised, never a placeholder and never a flag. The CLI is
/// noun-verb, so a third lowercase token is a positional such as a channel name.
fn subcommand_path(after: &str) -> Vec<String> {
    let mut path = Vec::new();
    let mut tokens = after.split_whitespace();
    while let Some(tok) = tokens.next() {
        if tok == "--config" {
            tokens.next();
            continue;
        }
        if tok.starts_with("--config=") {
            continue;
        }
        let is_word = tok
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            && tok.starts_with(|c: char| c.is_ascii_lowercase());
        if !is_word || path.len() == 2 {
            break;
        }
        path.push(tok.to_owned());
    }
    path
}

/// Every documented invocation, as its subcommand path. Duplicates are kept, because the
/// count is the vacuity floor.
fn documented_invocations(doc: &str) -> Vec<Vec<String>> {
    const BIN: &str = "gdi-node-standalone ";
    let mut out = Vec::new();
    for text in code_text(doc) {
        let mut rest = text.as_str();
        while let Some(at) = rest.find(BIN) {
            // The binary name, not a prefix of a longer word (`gdi-node-standalone-core`).
            let after = &rest[at + BIN.len()..];
            if at == 0 || !rest.as_bytes()[at - 1].is_ascii_alphanumeric() {
                // A line continuation puts the verb on the next line, which this reads as no
                // verb at all: an empty path that runs `--help` and passes. Refuse it rather
                // than let the runbook's shape un-guard a recipe.
                assert!(
                    !after.trim_start().starts_with('\\'),
                    "docs/operating.md writes `gdi-node-standalone \\` with a line continuation, \
                     which this guard cannot follow — keep each documented invocation on one line"
                );
                out.push(subcommand_path(after));
            }
            rest = after;
        }
    }
    out
}

#[test]
fn every_documented_node_invocation_parses() {
    let doc = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/operating.md"),
    )
    .expect("read docs/operating.md");

    let invocations = documented_invocations(&doc);
    // The floor counts invocations that carry a verb. An unparsed prefix yields an empty
    // path, which runs `--help` and passes, so counting empties toward the floor would let
    // every recipe degrade to `[]` with the floor still met. A bare `gdi-node-standalone
    // --help` is the one legitimate empty path in the runbook.
    let with_verb = invocations.iter().filter(|p| !p.is_empty()).count();
    assert!(
        with_verb >= 20,
        "only {with_verb} `gdi-node-standalone <verb> …` invocations found in \
         docs/operating.md (expected >= 20; {} in total) — the extractor has stopped seeing \
         the runbook's verbs.",
        invocations.len()
    );

    let unique: BTreeSet<&Vec<String>> = invocations.iter().collect();
    let mut failures = Vec::new();
    for path in unique {
        let out = Command::new(env!("CARGO_BIN_EXE_gdi-node-standalone"))
            .args(path)
            .arg("--help")
            .output()
            .unwrap();
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            failures.push(format!(
                "gdi-node-standalone {} --help -> exit {:?}: {}",
                path.join(" "),
                out.status.code(),
                stderr.lines().next().unwrap_or_default()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "docs/operating.md documents invocations the binary does not parse:\n  {}",
        failures.join("\n  ")
    );
}

#[test]
fn the_extractor_reads_paths_the_way_the_runbook_writes_them() {
    let doc = "# gdi-node-standalone operator runbook\n\n\
        Run `gdi-node-standalone --config node.toml identity init --ensure` first.\n\
        ```bash\n\
        gdi-node-standalone --config /etc/gdi/node.toml dataset hide DATASET_ID --reason T-1 2>&1 | tee x\n\
        gdi-node-standalone verify > verify.out\n\
        gdi-node-standalone --help\n\
        ```\n\
        See `gdi-node-standalone-core` (a crate, not a command) and `gdi-node-standalone doctor`.\n";
    let paths = documented_invocations(doc);
    assert_eq!(
        paths,
        vec![
            vec!["identity".to_owned(), "init".to_owned()],
            vec!["dataset".to_owned(), "hide".to_owned()],
            vec!["verify".to_owned()],
            vec![],
            vec!["doctor".to_owned()],
        ],
        "the title is prose (excluded); the crate name is not the binary"
    );
}
