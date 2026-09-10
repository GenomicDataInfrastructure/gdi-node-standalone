//! Seam: every flag the CLI accepts must appear in the provider-facing doc.
//!
//! `docs/README.md` scopes `docs/gdi-dataset-tool.md` to data providers and says it covers
//! every command, so a flag missing from it is a flag providers cannot find. Documenting a
//! provider-run flag only in `docs/operating.md`, the operator runbook, does not count: a
//! provider who re-keys without `rekey --as`, for instance, mints a fresh ephemeral writer
//! key that a `writer_policy = enforce` node rejects.
//!
//! The ground truth is `clap` itself via [`CommandFactory`], not a parse of the source: a
//! regex over `#[arg(...)]` misses `visible_alias` and mis-attributes flattened args.

use std::path::Path;

use clap::CommandFactory;
use gdi_dataset_tool::cli::Cli;

/// `doc` mentions `--flag` as a whole word — `--out` must not be satisfied by `--output`.
fn mentions(doc: &str, flag: &str) -> bool {
    let needle = format!("--{flag}");
    doc.match_indices(&needle).any(|(i, _)| {
        doc[i + needle.len()..]
            .chars()
            .next()
            .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
    })
}

/// Walk `cmd` and its nested subcommands, collecting `(path, long-flag)` for every visible
/// argument. Hidden commands and args are out of scope: they are not part of the
/// documented surface.
fn visible_long_flags(cmd: &clap::Command, path: &str, out: &mut Vec<(String, String)>) {
    for arg in cmd.get_arguments() {
        if arg.is_hide_set() {
            continue;
        }
        if let Some(long) = arg.get_long() {
            // clap synthesises these; they are not part of any doc's flag tables.
            if long == "help" || long == "version" {
                continue;
            }
            out.push((path.to_owned(), long.to_owned()));
        }
    }
    for sub in cmd.get_subcommands() {
        if sub.is_hide_set() {
            continue;
        }
        let child = if path.is_empty() {
            sub.get_name().to_owned()
        } else {
            format!("{path} {}", sub.get_name())
        };
        visible_long_flags(sub, &child, out);
    }
}

#[test]
fn every_cli_flag_appears_in_the_provider_doc() {
    let doc_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/gdi-dataset-tool.md");
    let doc = std::fs::read_to_string(&doc_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", doc_path.display()));

    let cmd = Cli::command();
    let mut flags = Vec::new();
    visible_long_flags(&cmd, "", &mut flags);

    let missing: Vec<String> = flags
        .iter()
        .filter(|(_, long)| !mentions(&doc, long))
        .map(|(path, long)| {
            if path.is_empty() {
                format!("--{long} (global)")
            } else {
                format!("{path} --{long}")
            }
        })
        .collect();

    // Ratchet, not a floor of one: a `> 0` floor would let this rot to a single flag and
    // still pass. Lower it only alongside a deliberate removal of flags.
    assert!(
        flags.len() >= 35,
        "only {} visible long flags found (expected >= 35) — the walk has stopped seeing \
         most of the CLI. A guard that cannot see is worse than none.",
        flags.len()
    );
    assert!(
        missing.is_empty(),
        "these flags exist but docs/gdi-dataset-tool.md never mentions them:\n  {}\n\n\
         That doc is the data provider's reference and claims to cover every command. \
         Document the flag there (documenting it only in docs/operating.md reaches \
         operators, not the providers who run this tool), or hide the flag.",
        missing.join("\n  ")
    );
}
