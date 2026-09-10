//! `gdi-dataset-tool completions <shell>` — print a shell-completion script.
//!
//! Generated from the same clap [`Cli`] command tree the binary parses, so the
//! completions never drift from the actual flags/subcommands.

use std::io;

use clap::CommandFactory as _;
use clap_complete::{Shell, generate};

use crate::cli::Cli;

/// Write the completion script for `shell` to stdout.
///
/// Infallible: `clap_complete::generate` writes directly to the handle. Shell-script
/// output only — no filesystem or network access.
pub fn run(shell: Shell) {
    let mut cmd = Cli::command();
    let bin = cmd.get_name().to_string();
    generate(shell, &mut cmd, bin, &mut io::stdout());
}
