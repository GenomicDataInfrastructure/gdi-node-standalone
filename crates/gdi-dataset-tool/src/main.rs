//! `gdi-dataset-tool` entry point: parse args, run, and map the result to the
//! documented exit codes. User-fixable errors print a single line with no stack
//! trace.
#![cfg_attr(
    test,
    allow(
        clippy::disallowed_methods,
        reason = "test code writes plain files; durability is not under test"
    )
)]

use std::process::ExitCode;

use clap::Parser as _;
use gdi_dataset_tool::{
    cli::{Cli, OutputFormat},
    output, run,
};

/// Install a process-level panic hook that suppresses the raw panic text for a
/// panic `gdi-node-standalone-core`'s decode paths already catch and convert into
/// a clean [`gdi_dataset_tool::ToolError`] — e.g. `arrow`/`parquet` panicking on a
/// crafted malformed parquet footer. Without the hook, `validate`/`build`/`deploy`
/// against such a file print a raw Rust panic message (Rust's own hook fires before
/// the `catch_unwind` inside core ever sees the unwind) ahead of the tool's clean
/// `error: invalid parquet: parquet decode panicked ... (malformed file)` line.
///
/// While the panic is inside one of those guarded decode calls
/// (`gdi_node_standalone_core::panic_guard::handled_decode_in_progress`), this
/// downgrades to a `-v` diagnostic note (message + location): invisible by default,
/// and never the raw panic formatting when it does show. Any other panic — a real
/// bug, not a handled decode — falls through to Rust's default hook unchanged, so a
/// genuine crash still gets full output.
fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if !gdi_node_standalone_core::panic_guard::handled_decode_in_progress() {
            default_hook(info);
            return;
        }
        let payload = info.payload();
        let message = payload
            .downcast_ref::<&str>()
            .map(|s| (*s).to_string())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "panic".to_owned());
        let location = info.location().map_or_else(
            || "unknown".to_owned(),
            |l| format!("{}:{}:{}", l.file(), l.line(), l.column()),
        );
        output::note(&format!(
            "note: panic in a handled decode path (caught; not a crash): {message} at {location}"
        ));
    }));
}

fn main() -> ExitCode {
    // Install first, before any argument parsing or work — matching the service
    // binary's `logging::install_panic_hook` ordering, so a panic anywhere during
    // this process's life goes through the same hook.
    install_panic_hook();
    let cli = Cli::parse();
    // Captured before dispatch: `run` consumes the parsed CLI, and the error path below
    // needs to know whether the caller asked for machine-readable output.
    let format = cli.command.requested_format();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // A `--format json` run that fails before printing its own object would otherwise
            // exit non-zero with empty stdout — the one shape a machine consumer cannot act
            // on, since `jq` receives no input and "the tool broke" is indistinguishable from
            // "your data is bad". Emit the error as the same versioned envelope every other
            // JSON output uses.
            //
            // Guarded on `result_was_emitted` so a verb that already printed a parseable
            // object and then returned `Err` — `validate` with `valid:false`, `doctor` with a
            // failed check, `check` with a mismatch — is not followed by a second, contradictory
            // object. Every JSON emission routes through `output::emit_json`, so the guard
            // lives at this one site instead of being a rule each verb must remember.
            if format == Some(OutputFormat::Json) && !output::result_was_emitted() {
                output::emit_json(&serde_json::json!({
                    "schemaVersion": 1,
                    "status": "error",
                    "reason": err.message,
                    "exitCode": err.exit_code,
                }));
            }
            // Single-line message, no stack trace; rendered as untrusted text, because the
            // message can quote a manifest's `datasetId` or a VCF header id verbatim.
            eprintln!("{}", output::stylize(&output::error_line(&err.message)));
            ExitCode::from(u8::try_from(err.exit_code).unwrap_or(1))
        }
    }
}
