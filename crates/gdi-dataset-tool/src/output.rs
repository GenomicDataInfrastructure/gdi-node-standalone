//! Shared CLI result output for the state-changing verbs.
//!
//! Every mutating verb (`build`, `pack`, `package`, `upload`, `deploy`,
//! `publish`/`unpublish`, `delete`, `rekey`) computes its result once and prints it
//! through [`emit_result`], as either the human line (default) or a single JSON
//! object. Both go to stdout, so the result is the last stdout line in either mode
//! and an orchestrator can read the minted `datasetId`, output path or resolved
//! channel without scraping prose.

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use crate::cli::OutputFormat;

/// Whether a machine-readable object has already been written to stdout this run.
static RESULT_EMITTED: AtomicBool = AtomicBool::new(false);

/// Print one JSON value to stdout as this run's machine-readable output, recording that
/// something parseable was emitted.
///
/// Every `--format json` result and report goes through here, so that a verb which fails
/// before printing its object never exits non-zero with empty stdout: `main` emits an error
/// envelope instead. `main` can only do that if it knows whether anything reached stdout,
/// and a per-verb `println!` is unobservable. One function makes that a knowable fact.
pub fn emit_json(value: &serde_json::Value) {
    RESULT_EMITTED.store(true, Ordering::Relaxed);
    println!(
        "{}",
        serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".to_owned())
    );
}

/// Record that machine-readable output reached stdout by a route [`emit_json`] cannot serve.
///
/// There is one such route: `inspect --manifest` streams the package's `manifest.json`
/// bytes through verbatim, with no re-serialization, so a consumer gets the provider's own
/// formatting byte for byte. Handing those bytes to [`emit_json`] would parse and
/// pretty-print them, rewriting what the flag exists to reproduce exactly.
///
/// Kept separate from `emit_json` so the exception is named and greppable. A second caller
/// would mean the raw-passthrough case wants a real abstraction.
pub fn mark_result_emitted() {
    RESULT_EMITTED.store(true, Ordering::Relaxed);
}

/// Whether [`emit_json`] has already run. `main`'s guard against a second object.
#[must_use]
pub fn result_was_emitted() -> bool {
    RESULT_EMITTED.load(Ordering::Relaxed)
}

/// Emit a verb's result: the human-readable `text` line in text mode, or `json`
/// pretty-printed as one object in JSON mode. Always stdout.
///
/// The JSON object is the machine-readable contract; by convention every caller
/// includes a `"status": "ok"` and an `"action"` field plus the result fields an
/// orchestrator needs (ids, paths, channels).
pub fn emit_result(format: OutputFormat, text: &str, json: &serde_json::Value) {
    match format {
        OutputFormat::Text => println!("{text}"),
        OutputFormat::Json => emit_json(json),
    }
}

/// Merge a leading `"schemaVersion": 1` into a report verb's serialized payload, turning
/// a typed report struct into the same versioned envelope the action verbs emit, without
/// hand-listing the struct's fields. Every report payload serializes to a JSON object; a
/// non-object value is returned unchanged. Callers pretty-print the result to stdout.
///
/// The `1` matches the action verbs' `schemaVersion`, so a consumer can version-gate every
/// `--format json` output, report and action alike.
///
/// # Errors
///
/// Returns the underlying [`serde_json::Error`] if the report cannot be serialized.
pub fn versioned_value(
    report: &impl serde::Serialize,
) -> Result<serde_json::Value, serde_json::Error> {
    let mut value = serde_json::to_value(report)?;
    if let serde_json::Value::Object(map) = &mut value {
        map.insert("schemaVersion".to_owned(), serde_json::json!(1));
    }
    Ok(value)
}

/// Every key at or below `value` that is not `camelCase` (one containing `_`, or starting
/// uppercase), path-qualified so a failure names where it lives.
///
/// Lives here because [`versioned_value`] is the chokepoint: it stamps `schemaVersion` onto
/// payloads authored both in this crate and in `core`, and a payload without `rename_all`
/// leaks Rust field names into that same object. One shared checker each report verb's test
/// calls, rather than the invariant restated per verb.
///
/// Only struct field names are in scope. `rename_all` does not touch map keys and must not:
/// a report keyed by population label (`EE_F`) or variant type (`SNP`) carries data there.
/// Remove such subtrees before calling this, or they register as false positives.
#[cfg(test)]
pub(crate) fn non_camel_keys(value: &serde_json::Value) -> Vec<String> {
    fn walk(v: &serde_json::Value, path: &str, out: &mut Vec<String>) {
        match v {
            serde_json::Value::Object(map) => {
                for (key, inner) in map {
                    if key.contains('_') || key.chars().next().is_some_and(char::is_uppercase) {
                        out.push(format!("{path}{key}"));
                    }
                    walk(inner, &format!("{path}{key}."), out);
                }
            }
            serde_json::Value::Array(items) => {
                for inner in items {
                    walk(inner, path, out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(value, "", &mut out);
    out
}

/// Neutralise terminal control characters in a string that came from provider-controlled
/// input (a package manifest field, a parquet `POPULATION` or variant-type label, a VCF
/// INFO field name, a bucket status object) before it is printed to the operator's
/// terminal. Each [`char::is_control`] character becomes a space, so columns keep their
/// width.
///
/// Without this a crafted value injects ANSI escape sequences that clear the screen, spoof
/// a "clean" report, or hide output. This is the shared sanitizer every human-readable
/// render of untrusted text routes through (`lint`, `status`, the catalog reader).
/// `--format json` output is not sanitized here: JSON string escaping already neutralizes
/// control bytes, and a machine consumer wants the raw value.
#[must_use]
pub fn sanitize_terminal(s: &str) -> String {
    // Delegates, so the filter predicate lives in one place: `Untrusted`'s `Display`.
    // Two copies of "what counts as renderable" would drift apart.
    Untrusted(s).to_string()
}

/// Join untrusted items with `, `, rendering each through [`Untrusted`].
///
/// The one place a list of untrusted strings becomes safe to print. Population labels are
/// raw VCF header text, rendered both by `preview`'s report and by the wizard's disclosure
/// gate. The gate is where an injected label does the most damage, because the operator
/// answers "Publish these populations?" against it. Sharing the join keeps that screen from
/// being a second, unsanitized code path.
#[must_use]
pub fn join_untrusted(items: &[String]) -> String {
    items
        .iter()
        .map(|s| Untrusted(s).to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The single stderr line for a fatal error: `error: <message>`.
///
/// Every [`ToolError`](crate::ToolError) reaches the terminal through this line
/// (`main.rs`), and the message folds provider-controlled text: `pack` quotes a manifest's
/// `datasetId`, `build` a source path. It is therefore rendered through [`Untrusted`]. The
/// `--format json` envelope carries the raw message; JSON escaping neutralises it there.
#[must_use]
pub fn error_line(message: &str) -> String {
    format!("error: {}", Untrusted(message))
}

/// Untrusted text, safe to `{}` into any human-readable render.
///
/// Prefer this to [`sanitize_terminal`]: a function is one a new print site can fail to
/// call, whereas `{}` of an `Untrusted` cannot render a control byte, because no code path
/// does.
///
/// A control byte becomes a space rather than being dropped. Dropping it is equally safe
/// and produces a wrong message: the text either side closes up, so a multi-line diagnostic
/// folded into a single-line `error:` welds one line's number onto the previous line's
/// value and reports a token that is nowhere in the input.
///
/// Use it wherever untrusted text reaches a human: VCF header ids, dataset titles, tar
/// member names, diagnostic messages. `--format json` is not routed through here, because
/// JSON string escaping already neutralizes control bytes and a machine consumer wants the
/// raw value.
#[derive(Debug, Clone, Copy)]
pub struct Untrusted<'a>(pub &'a str);

impl std::fmt::Display for Untrusted<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::fmt::Write as _;
        for c in self.0.chars() {
            // A space, not a deletion: see the type's docs. A space cannot start an
            // escape sequence, so the injection guard is unaffected.
            f.write_char(if c.is_control() { ' ' } else { c })?;
        }
        Ok(())
    }
}

/// CLI verbosity, set once at startup from `-q` / `-v`. Ordered: a higher
/// level shows everything a lower one does, plus more.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verbosity {
    /// `-q`: only the result (stdout) + warnings + errors (stderr). No progress/notes.
    Quiet = 0,
    /// Default: the result + per-step progress + warnings + errors.
    Normal = 1,
    /// `-v` (or more): also diagnostic notes (resolved profile, build stages, timings).
    /// Repeating `-v` past one does not add detail; this is the highest level.
    Verbose = 2,
}

impl Verbosity {
    /// Resolve the level from the repeated `-v` count and the `-q` flag (`-q` wins).
    #[must_use]
    pub fn from_flags(verbose: u8, quiet: bool) -> Self {
        if quiet {
            Self::Quiet
        } else {
            match verbose {
                0 => Self::Normal,
                _ => Self::Verbose,
            }
        }
    }
}

/// The process-global verbosity. A CLI is single-shot: `run` sets this once and the gated
/// stderr helpers read it, including from the convert worker threads, hence an atomic.
static LEVEL: AtomicU8 = AtomicU8::new(Verbosity::Normal as u8);

/// Set the global verbosity. Call once at startup, before any gated output.
pub fn set_verbosity(level: Verbosity) {
    LEVEL.store(level as u8, Ordering::Relaxed);
}

/// The current global verbosity.
#[must_use]
pub fn verbosity() -> Verbosity {
    match LEVEL.load(Ordering::Relaxed) {
        0 => Verbosity::Quiet,
        2 => Verbosity::Verbose,
        _ => Verbosity::Normal,
    }
}

/// Whether `-v` (or more) is in effect. Guard before building an expensive note, so the
/// default path never pays to format one it would not print.
#[must_use]
pub fn is_verbose() -> bool {
    verbosity() >= Verbosity::Verbose
}

/// Paint a leading severity token for the terminal: `error:` red, `warning:` yellow,
/// `note:` and `hint:` cyan, a leading `ok:` green; bold in every case.
///
/// Only the token is styled, never the message body, which may fold provider-controlled
/// text (see [`Untrusted`]). Styling applies only when stderr is a terminal that wants
/// color: [`console::colors_enabled_stderr`] is the gate the dialoguer prompts use, and it
/// honors `NO_COLOR`. Off a terminal the input is returned unchanged, so log scrapers and
/// the `--format json` contract never see an escape byte.
#[must_use]
pub fn stylize(msg: &str) -> String {
    if !console::colors_enabled_stderr() {
        return msg.to_owned();
    }
    // `.for_stderr()`: a `StyledObject` renders against stdout's color gate by default,
    // and these lines go to stderr, so without it no style is applied.
    let paint = |token: &str, style: console::Style| {
        msg.strip_prefix(token)
            .map(|rest| format!("{}{rest}", style.for_stderr().apply_to(token)))
    };
    paint("error:", console::Style::new().red().bold())
        .or_else(|| paint("warning:", console::Style::new().yellow().bold()))
        .or_else(|| paint("note:", console::Style::new().cyan().bold()))
        .or_else(|| paint("hint:", console::Style::new().cyan().bold()))
        .or_else(|| paint("ok:", console::Style::new().green().bold()))
        .unwrap_or_else(|| msg.to_owned())
}

/// The terminal's width in columns, or a comfortable default when there is no terminal
/// to ask (piped output, CI).
fn terminal_width() -> usize {
    let cols = usize::from(console::Term::stderr().size().1);
    if cols == 0 { 100 } else { cols }
}

/// Build a `<lead> <label> <fill><fill>…` rule that ends one column short of `width`.
///
/// Pure, so the arithmetic is unit-tested without a terminal. One column short because a
/// line of exactly `width` characters followed by a newline leaves the cursor in the
/// deferred-wrap state on most terminals, which shows up as a phantom blank row.
///
/// A label too long for the width degrades to `<lead> <label>` with no fill rather than
/// wrapping, so a narrow terminal loses the rule but never the heading.
fn rule(lead: &str, label: &str, fill: char, width: usize) -> String {
    let head = format!("{lead} {label} ");
    let budget = width.saturating_sub(1);
    let pad = budget.saturating_sub(head.chars().count());
    if pad == 0 {
        return format!("{lead} {label}");
    }
    let mut out = head;
    out.extend(std::iter::repeat_n(fill, pad));
    out
}

/// Whether the next [`section_caption`] is the first of its stage.
///
/// The one piece of layout state this module keeps. A caption is separated from what
/// precedes it by a blank line, except directly under a [`stage_banner`], which has already
/// supplied the separation. Without this, a stage rule and its first section rule stack
/// against each other.
static CAPTION_IS_FIRST: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// A wizard stage banner: blank line, then a heavy full-width rule, bold.
///
/// The heaviest thing the wizard prints, so that the transcript's structure stands out
/// against the many green `✔` answer lines between banners.
///
/// `step`/`total` come from [`crate::cli::Stage`], never from literals.
pub fn stage_banner(step: usize, total: usize, title: &str) {
    let line = rule(
        "==",
        &format!("[{step}/{total}] {title}"),
        '=',
        terminal_width(),
    );
    let line = if console::colors_enabled_stderr() {
        console::Style::new()
            .bold()
            .for_stderr()
            .apply_to(line)
            .to_string()
    } else {
        line
    };
    eprintln!();
    eprintln!("{line}");
    CAPTION_IS_FIRST.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// A section caption inside a stage: a light full-width rule, dim, preceded by a blank
/// line unless it is the first of its stage.
///
/// Same shape as [`stage_banner`] but lighter in both weight and colour, so the two read as
/// a hierarchy rather than as competing dividers. The separation, not the decoration, is
/// what makes a section findable.
pub fn section_caption(title: &str) {
    if !CAPTION_IS_FIRST.swap(false, std::sync::atomic::Ordering::Relaxed) {
        eprintln!();
    }
    let line = rule("--", title, '-', terminal_width());
    let line = if console::colors_enabled_stderr() {
        console::Style::new()
            .dim()
            .for_stderr()
            .apply_to(line)
            .to_string()
    } else {
        line
    };
    eprintln!("{line}");
}

/// Colourize one line of the wizard's rendered `package.yaml`.
///
/// Hand-rolled rather than pulling in a highlighter: the input is not arbitrary YAML but
/// this tool's own emitter output (plain keys, quoted scalars, bare numbers, `- ` list
/// items and `{}`), so a tokenizer for that subset is a dozen lines and no dependency.
///
/// The line is sanitized first ([`Untrusted`] blanks control bytes, `ESC` among them) and
/// only then styled, so an operator-supplied title cannot smuggle its own escape sequence
/// into the block. Never slices; a line that does not match any shape is returned plain.
fn highlight_yaml_line(line: &str) -> String {
    let clean = Untrusted(line).to_string();
    if !console::colors_enabled_stderr() {
        return clean;
    }
    let key_style = console::Style::new().cyan().for_stderr();
    let str_style = console::Style::new().green().for_stderr();
    let dim = console::Style::new().dim().for_stderr();

    let indent: String = clean.chars().take_while(|c| c.is_whitespace()).collect();
    let body = clean.trim_start();

    // A comment is dim, whole-line.
    if body.starts_with('#') {
        return format!("{indent}{}", dim.apply_to(body));
    }
    // A list item: everything after the dash is a value. Checked before the key split,
    // because a list item is often a URL and `split_once(':')` would cut it at `http:`.
    if let Some(rest) = body.strip_prefix("- ") {
        return format!("{indent}{} {}", dim.apply_to("-"), str_style.apply_to(rest));
    }
    // `key:` or `key: value`. The first colon separates them, so a colon inside the
    // value (a URL) is never mistaken for the separator.
    if let Some((key, rest)) = body.split_once(':') {
        let value = rest.trim_start();
        // The separator's own whitespace, rebuilt rather than sliced: `str` indexing is
        // banned here (it panics on a multibyte boundary).
        let gap: String = rest.chars().take_while(|c| c.is_whitespace()).collect();
        let painted = if value.is_empty() {
            String::new()
        } else if value.starts_with('"') {
            str_style.apply_to(value).to_string()
        } else if value == "{}" || value == "[]" {
            dim.apply_to(value).to_string()
        } else {
            value.to_owned()
        };
        return format!(
            "{indent}{}{}{gap}{painted}",
            key_style.apply_to(key),
            dim.apply_to(":")
        );
    }
    clean
}

/// Print a rendered document as a delimited, syntax-highlighted block, to stderr.
///
/// The caption above the block and the closing rule below it delimit the document, so a
/// ~30-line `package.yaml` does not read as more wizard output; the colour is what makes
/// its structure scannable.
///
/// Not verbosity-gated. Its one caller shows the document the operator is about to be asked
/// to write, and what a prompt asks about must reach the operator at every verbosity,
/// including `-q`. Otherwise the operator approves against an empty screen.
pub fn yaml_block(text: &str) {
    let mut err = std::io::stderr().lock();
    yaml_block_to(&mut err, text);
}

/// [`yaml_block`] to a caller-supplied sink: the seam through which a test reads what the
/// operator would see, verbosity and all.
pub fn yaml_block_to(out: &mut dyn std::io::Write, text: &str) {
    for line in text.lines() {
        // Best-effort, like `eprintln!`: a closed stderr is not a reason to fail a write.
        let _ = writeln!(out, "  {}", highlight_yaml_line(line));
    }
    block_end_to(out);
}

/// A bare dim rule closing a block opened by [`section_caption`].
pub fn block_end() {
    let mut err = std::io::stderr().lock();
    block_end_to(&mut err);
}

/// [`block_end`] to a caller-supplied sink.
pub fn block_end_to(out: &mut dyn std::io::Write) {
    // Not `rule()`: that formats a labelled rule, and an empty label leaves a gap in it.
    let line: String = std::iter::repeat_n('-', terminal_width().saturating_sub(1)).collect();
    let line = if console::colors_enabled_stderr() {
        console::Style::new()
            .dim()
            .for_stderr()
            .apply_to(line)
            .to_string()
    } else {
        line
    };
    let _ = writeln!(out, "{line}");
}

/// Emit a per-step progress line to stderr, shown at `Normal` and above and suppressed by
/// `-q`. Stderr only, so the stdout result and `--format json` contract are undisturbed.
pub fn progress(msg: &str) {
    if verbosity() >= Verbosity::Normal {
        eprintln!("{}", stylize(msg));
    }
}

/// Emit a diagnostic note to stderr, shown at `Verbose` and above (`-v`). Stderr only.
/// Callers pass fingerprints, paths and counts, never secret material.
pub fn note(msg: &str) {
    if verbosity() >= Verbosity::Verbose {
        eprintln!("{}", stylize(msg));
    }
}

/// Emit a warning to stderr, shown at every verbosity including `-q`, because a warning
/// signals a degraded-but-continued outcome the operator has to see (a catalog sync that
/// did not complete, a fallback path taken). Stderr only, so the stdout result and
/// `--format json` contract are untouched.
pub fn warn(msg: &str) {
    eprintln!("{}", stylize(msg));
}

/// Emit a line to stderr at every verbosity: the channel for output that is the result of
/// the run rather than commentary on it, such as the wizard's final summary and stage
/// banners, a conversion's per-source `populations emitted` echo, and the diagnostics a
/// provider must see even under `-q`. Distinct from [`warn`] only in intent (greppable at
/// the call site); both print unconditionally.
pub fn always(msg: &str) {
    eprintln!("{}", stylize(msg));
}

#[cfg(test)]
mod tests {

    /// The YAML highlighter must not mistake a colon inside a value for the key
    /// separator, and must never let operator text carry its own escape sequences.
    #[test]
    fn the_yaml_highlighter_handles_urls_and_strips_control_bytes() {
        // Colours are off in tests (not a terminal), so this asserts the sanitized text.
        // A list item that is a URL: the `http:` colon must not split it into a key.
        let item = highlight_yaml_line("    - \"http://data.europa.eu/eli/reg/2025/327/oj\"");
        assert_eq!(item, "    - \"http://data.europa.eu/eli/reg/2025/327/oj\"");
        // A key whose value is a URL keeps both halves intact.
        let kv = highlight_yaml_line("  license: \"http://example.org/a:b\"");
        assert_eq!(kv, "  license: \"http://example.org/a:b\"");
        // An ESC smuggled in through a title is dropped before any styling happens.
        let hostile = highlight_yaml_line("  title: \"pwn\u{1b}[31mred\"");
        assert!(!hostile.contains('\u{1b}'), "{hostile:?}");
        // The ESC byte becomes a space, so the text either side is not glued into a
        // token that was never in the file (see `Untrusted`), and the harmless leftover
        // stays visible instead of being silently rewritten.
        assert_eq!(hostile, "  title: \"pwn [31mred\"");
        // Shapes with no key at all pass through unchanged.
        assert_eq!(highlight_yaml_line("metadata:"), "metadata:");
        assert_eq!(highlight_yaml_line(""), "");
    }

    /// The rule ends one column short of the terminal width. A line of exactly `width`
    /// characters plus a newline parks the cursor in deferred wrap, which renders as a
    /// phantom blank row.
    #[test]
    fn a_rule_stops_one_column_short_and_never_wraps() {
        for width in [40_usize, 80, 100, 200] {
            let line = rule("==", "[2/5] Author", '=', width);
            assert_eq!(
                line.chars().count(),
                width - 1,
                "a rule with room to fill must reach exactly width-1 at {width}"
            );
        }
        // Whatever the width, the rule never exceeds width-1 while the label still fits.
        let long = "[2/5] Author: describe the dataset (package.yaml)";
        for width in [60_usize, 80, 100] {
            let line = rule("==", long, '=', width);
            assert!(
                line.chars().count() < width,
                "{width}: {} chars; a full-width line parks the cursor in deferred wrap",
                line.chars().count()
            );
        }
        // A label wider than the terminal keeps the heading and drops the fill, rather
        // than wrapping into a second row that the redraw would not account for.
        let narrow = rule(
            "--",
            "Catalog entry: published via the node's FAIR Data Point",
            '-',
            20,
        );
        assert!(
            narrow.chars().count() > 20,
            "the heading itself is not truncated"
        );
        assert!(
            !narrow.ends_with('-'),
            "no fill when there is no room: {narrow}"
        );
    }
    use super::*;

    #[test]
    fn untrusted_display_and_sanitize_terminal_cannot_disagree() {
        // The two entry points must apply the same rule. `sanitize_terminal` delegates to
        // `Untrusted`'s `Display` so there is one predicate; re-implementing the filter in
        // either of them fails here.
        for s in [
            "GDI-EE-UTARTU-1",
            "AF_\u{1b}[2J\u{1b}[H evil",
            "line\nbreak\tand\0nul",
            "",
            "plain",
        ] {
            assert_eq!(
                sanitize_terminal(s),
                Untrusted(s).to_string(),
                "the sanitizer and the newtype disagreed on {s:?}"
            );
        }
    }

    /// The fatal-error line is a sink for provider-controlled text (a manifest's
    /// `datasetId`, a VCF INFO id folded into a message), so it renders through
    /// `Untrusted`: a message carrying a terminal clear-screen sequence must not reach the
    /// terminal with that sequence intact.
    #[test]
    fn error_line_renders_the_message_as_untrusted() {
        let hostile = "staging dir name X does not match the datasetId \u{1b}[2J\u{1b}[Hspoofed";
        let line = error_line(hostile);
        assert!(line.starts_with("error: "), "{line:?}");
        assert!(
            !line.chars().any(char::is_control),
            "error_line rendered a control byte: {line:?}"
        );
        assert!(line.ends_with("datasetId  [2J [Hspoofed"), "{line:?}");
    }

    #[test]
    fn stylize_paints_only_the_severity_token_and_only_on_a_color_terminal() {
        // Off a terminal (this test harness) stylize is the identity: no escape byte may
        // reach a pipe, a log, or the JSON contract.
        for msg in [
            "warning: x",
            "note: y",
            "error: z",
            "ok: done",
            "plain line",
        ] {
            assert_eq!(stylize(msg), msg, "off-terminal stylize must be identity");
        }
        // Force colors on (console's global override): the token is painted, the body is
        // not, and a line with no severity token is untouched.
        console::set_colors_enabled_stderr(true);
        let painted = stylize("warning: body stays plain");
        console::set_colors_enabled_stderr(false);
        assert!(
            painted.contains("\u{1b}[") && painted.contains("warning:"),
            "token must be styled: {painted:?}"
        );
        assert!(
            painted.ends_with(" body stays plain"),
            "the body must carry no styling: {painted:?}"
        );
        console::set_colors_enabled_stderr(true);
        let plain = stylize("no token here");
        console::set_colors_enabled_stderr(false);
        assert_eq!(plain, "no token here");
    }

    #[test]
    fn untrusted_display_removes_control_bytes() {
        // The property the type exists to enforce: `{}` of untrusted text cannot emit a
        // control byte, because no code path renders one.
        let hostile = "AF_\u{1b}[2J\u{1b}[Hspoofed";
        let rendered = format!("{}", Untrusted(hostile));
        assert!(
            !rendered.chars().any(char::is_control),
            "Untrusted rendered a control byte: {rendered:?}"
        );
        assert_eq!(rendered, "AF_ [2J [Hspoofed");
    }

    /// A control character becomes a space, so text either side of it is never glued.
    ///
    /// Asserted on the separation rather than on a golden string, so it fails for the
    /// reason it exists: tokens that were on different lines must not become one token.
    #[test]
    fn untrusted_display_does_not_glue_text_across_a_control_char() {
        let multiline = "prefix: GDI\n3 |   org: UTARTU";
        let rendered = format!("{}", Untrusted(multiline));
        assert!(
            !rendered.chars().any(char::is_control),
            "still no control bytes: {rendered:?}"
        );
        assert!(
            !rendered.contains("GDI3"),
            "the line number was glued onto the value: {rendered:?}"
        );
        assert!(
            rendered.contains("GDI 3"),
            "the two lines must stay separated: {rendered:?}"
        );
        // Tabs and carriage returns glue just as badly as newlines.
        assert_eq!(Untrusted("a\tb\rc").to_string(), "a b c");
    }

    #[test]
    fn sanitize_terminal_strips_control_and_escape_bytes() {
        // An ANSI screen-clear + a spoofed "clean" line must be neutered to inert text.
        let hostile = "GDI-\x1b[2J\x1b[Hall checks passed\r";
        let clean = sanitize_terminal(hostile);
        assert!(!clean.contains('\x1b'), "ESC removed: {clean:?}");
        assert!(!clean.contains('\r'), "CR removed: {clean:?}");
        // Printable content survives.
        assert!(clean.contains("all checks passed"));
        // Ordinary text is unchanged.
        assert_eq!(sanitize_terminal("GDI-EE-UTARTU-1"), "GDI-EE-UTARTU-1");
    }

    #[test]
    fn versioned_value_merges_schema_version_into_object() {
        // A report object gains a `schemaVersion: 1` while keeping its own fields.
        let v = versioned_value(&serde_json::json!({ "a": 1, "b": "x" })).expect("serializes");
        assert_eq!(v["schemaVersion"], 1);
        assert_eq!(v["a"], 1);
        assert_eq!(v["b"], "x");
    }

    #[test]
    fn versioned_value_leaves_non_object_unchanged() {
        // A non-object payload (never emitted by a report verb) is passed through as-is.
        let v = versioned_value(&serde_json::json!([1, 2, 3])).expect("serializes");
        assert_eq!(v, serde_json::json!([1, 2, 3]));
    }

    #[test]
    fn from_flags_maps_and_orders_levels() {
        assert_eq!(Verbosity::from_flags(0, false), Verbosity::Normal);
        assert_eq!(Verbosity::from_flags(1, false), Verbosity::Verbose);
        // Repeating -v past one saturates: there is no level above Verbose.
        assert_eq!(Verbosity::from_flags(2, false), Verbosity::Verbose);
        assert_eq!(Verbosity::from_flags(9, false), Verbosity::Verbose);
        // -q wins over any -v count.
        assert_eq!(Verbosity::from_flags(0, true), Verbosity::Quiet);
        assert_eq!(Verbosity::from_flags(3, true), Verbosity::Quiet);
        // The ladder is ordered.
        assert!(Verbosity::Quiet < Verbosity::Normal);
        assert!(Verbosity::Normal < Verbosity::Verbose);
    }

    /// The review block reaches the operator under `-q`: it precedes "Write package.yaml?",
    /// and the operator must be able to see what the prompt asks about.
    #[test]
    fn the_yaml_block_is_printed_even_when_quiet() {
        set_verbosity(Verbosity::Quiet);
        let mut out = Vec::new();
        yaml_block_to(
            &mut out,
            "title: Synthetic AF dataset\nkeywords:\n  - covid\n",
        );
        set_verbosity(Verbosity::Normal);
        let shown = String::from_utf8(out).expect("utf-8");
        assert!(
            shown.contains("Synthetic AF dataset") && shown.contains("covid"),
            "the document must reach the operator under -q; got: {shown:?}"
        );
        assert!(
            shown.contains("----"),
            "the closing rule delimits the block: {shown:?}"
        );
    }
}
