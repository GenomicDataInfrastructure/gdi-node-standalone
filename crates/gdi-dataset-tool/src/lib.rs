//! Library surface for `gdi-dataset-tool`, so integration tests can construct
//! the clap [`cli::Cli`] and drive [`run`] directly. The binary's `main` is a
//! thin wrapper that maps the result to the documented exit codes.
#![deny(
    clippy::expect_used,
    clippy::string_slice,
    reason = "a panic in production code is a crash, and `str` byte-slicing panics on a \
              multibyte boundary. `print_stdout`/`print_stderr` are absent here because a \
              CLI legitimately writes to stdout and stderr. `allow-expect-in-tests` in \
              clippy.toml needs a literal `#[cfg(test)]`, so a module gated on \
              `cfg(all(test, feature = ...))` needs its own attribute"
)]
#![cfg_attr(
    test,
    allow(
        clippy::string_slice,
        reason = "test code slices literals it owns; the multibyte hazard is a property \
                  of runtime input, which a test fixture is not"
    )
)]
#![cfg_attr(
    test,
    allow(
        clippy::disallowed_methods,
        reason = "unit tests write plain files: durability and atomicity are not \
                  properties under test"
    )
)]
#![warn(missing_docs)]

pub mod catalogs;
pub mod check;
pub mod cli;
pub mod commands;
pub mod output;
pub mod pkgio;
pub mod profile;
pub mod progress;
pub mod recipient;
pub mod runtime;
pub mod s3;
pub mod scratch;
pub mod state;
pub mod status;
pub mod wizard;

use cli::{Cli, Command};

/// Exit code for a user-fixable error (the default). Distinct from clap's own exit
/// `2` for argument-parse errors, which this scheme reserves.
pub const EXIT_USER: i32 = 1;
/// Exit code for a transient backend failure that retrying may fix.
pub const EXIT_TRANSIENT: i32 = 3;
/// Exit code for an authentication / authorization failure.
pub const EXIT_AUTH: i32 = 4;
/// Exit code for a `build --strict` failure: the build was well-formed and the tool
/// worked, but a `warning:` was emitted. Distinct from [`EXIT_USER`] so CI can tell "your
/// data has problems" from "the tool broke".
pub const EXIT_STRICT: i32 = 5;

/// A tool error carrying the process exit code to use.
///
/// The exit-code mapping lets a script branch on the failure class: user-fixable
/// errors exit [`EXIT_USER`] (`1`), a transient backend failure exits
/// [`EXIT_TRANSIENT`] (`3`), and an auth failure exits [`EXIT_AUTH`] (`4`); exit `2`
/// is reserved for clap's argument-parse errors. Errors print a single-line message
/// with no stack trace; the binary inspects [`ToolError::exit_code`] and prints
/// [`ToolError::message`]. Classification is applied only at the boundary mappers
/// that can actually distinguish the cause (network/auth sites); everything else
/// stays [`ToolError::user`].
#[derive(Debug)]
pub struct ToolError {
    /// The single-line, user-facing message (no stack trace).
    pub message: String,
    /// The process exit code.
    pub exit_code: i32,
}

impl ToolError {
    /// A user-fixable error (exit [`EXIT_USER`]).
    #[must_use]
    pub fn user(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: EXIT_USER,
        }
    }

    /// A `--strict` failure (exit [`EXIT_STRICT`]): warnings were emitted.
    #[must_use]
    pub fn strict(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: EXIT_STRICT,
        }
    }

    /// A transient backend error (exit [`EXIT_TRANSIENT`]): a failure that retrying
    /// may fix (e.g. a throttled or retry-exhausted S3 request).
    #[must_use]
    pub fn transient(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: EXIT_TRANSIENT,
        }
    }

    /// An authentication / authorization error (exit [`EXIT_AUTH`]): the credentials
    /// are missing, invalid, or lack permission for the operation.
    #[must_use]
    pub fn auth(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: EXIT_AUTH,
        }
    }
}

impl std::fmt::Display for ToolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ToolError {}

/// Convert a core [`gdi_node_standalone_core::error::CoreError`] into a user-facing
/// [`ToolError`] (exit 1), single-sourcing the adapter rather than copy-pasting it across
/// command modules.
impl From<&gdi_node_standalone_core::error::CoreError> for ToolError {
    fn from(e: &gdi_node_standalone_core::error::CoreError) -> Self {
        Self::user(e.to_string())
    }
}

impl ToolError {
    /// Present a core error raised while reading/converting a **VCF**.
    ///
    /// The conversion validators live in the same module as the parquet ones and raise
    /// `CoreError::InvalidParquet`, whose `Display` is `invalid parquet: …`. On this path
    /// no parquet exists yet, so that prefix sends providers looking for a corrupt output
    /// file instead of the input line the remediation text names, e.g. `invalid parquet:
    /// AF 0.35 is inconsistent with AC 100 / AN 8000`.
    ///
    /// Relabelled at presentation rather than by adding a `CoreError` variant: the error
    /// class is a documented closed set published on the node's dataset-state oracle, and
    /// a VCF never reaches the node — it only ever converts parquet — so widening that
    /// contract would add a value the node can never emit.
    #[must_use]
    pub fn from_vcf_stage(e: &gdi_node_standalone_core::error::CoreError) -> Self {
        let rendered = e.to_string();
        Self::user(
            rendered
                .strip_prefix("invalid parquet: ")
                .map_or(rendered.clone(), |detail| format!("invalid VCF: {detail}")),
        )
    }
}

#[cfg(test)]
mod vcf_stage_tests {
    use super::ToolError;
    use gdi_node_standalone_core::error::CoreError;

    /// A VCF-stage failure must not claim the parquet is invalid.
    #[test]
    fn a_vcf_stage_error_is_relabelled_but_its_detail_is_untouched() {
        let e = CoreError::InvalidParquet {
            detail: "AF 0.35 is inconsistent with AC 100 / AN 8000 at 3:100".to_owned(),
        };
        let msg = ToolError::from_vcf_stage(&e).message;
        assert!(
            msg.starts_with("invalid VCF: "),
            "the user supplied a VCF and no parquet exists yet: {msg}"
        );
        assert!(
            msg.contains("AF 0.35 is inconsistent with AC 100 / AN 8000 at 3:100"),
            "the remediation detail (which is good) must survive verbatim: {msg}"
        );
        assert!(
            !msg.contains("invalid parquet"),
            "the misleading prefix must be gone: {msg}"
        );
    }

    /// Any other class passes through untouched — this relabels one prefix, it does not
    /// rewrite errors generally.
    #[test]
    fn a_non_parquet_error_passes_through_unchanged() {
        let e = CoreError::InvalidManifest {
            detail: "missing datasetId".to_owned(),
        };
        assert_eq!(
            ToolError::from_vcf_stage(&e).message,
            ToolError::from(&e).message,
            "only the invalid-parquet prefix is stage-specific"
        );
    }
}

/// The canonical dataset-package manifest file name — the first tar member of a
/// `.tar.c4gh` and the manifest in a staging directory.
///
/// Re-exported from `core` rather than declared here: `core::ingest` needs the same
/// literal for `read_manifest_bytes` (the reader every verb routes through), and the
/// package-format name is a core contract the node reads too, so it is defined once.
pub use gdi_node_standalone_core::ingest::MANIFEST_FILE as MANIFEST_NAME;

/// Run the parsed CLI, returning a [`ToolError`] (with its exit code) on failure.
///
/// # Errors
///
/// Returns a [`ToolError`] when the command fails; the message is safe to print
/// verbatim (single line, no stack trace).
pub fn run(cli: Cli) -> Result<(), ToolError> {
    output::set_verbosity(output::Verbosity::from_flags(cli.verbose, cli.quiet));
    // The two global selectors every command module takes, resolved once.
    let profile = cli.profile.as_deref();
    let config = cli.config.as_deref();
    // An explicit `--config` that does not exist is a typo, not an empty config.
    //
    // The loader merges a missing TOML as empty, which is how an env-only load works and
    // how the setup wizard inspects a config path before writing one. Without this check
    // `--config /nonexistent.toml profiles` would print "no profiles configured" and exit
    // 0, and every later failure would blame config content rather than the path. The node
    // binary errors on a missing config too; checking here, at the CLI boundary, matches
    // that without changing the library contract the wizard depends on.
    //
    // `config init` and the `wizard` are exempt: they author the file, so a path that does
    // not exist yet is their normal input, not a typo.
    let authors_config = matches!(cli.command, Command::Config(_) | Command::Wizard(_));
    if let Some(path) = config
        && !path.exists()
        && !authors_config
    {
        return Err(ToolError::user(format!(
            "--config {} does not exist (check the path; omit --config to use <config-dir>/tool.toml)",
            path.display()
        )));
    }
    // An explicit `--profile` naming no configured profile is the same class of typo, and
    // it belongs at this boundary rather than in each verb. Most verbs error on their own,
    // but the two read-only ones cannot: `profiles` selects best-effort because it reports
    // state rather than acting, and `keys show` resolves the node recipient "never fatal"
    // so it stays usable offline. Without this check both absorb the unknown name and exit
    // 0, `profiles` printing "active profile: (none; pass --profile or set
    // default_profile)", which reads as "you set no default" rather than "that profile
    // does not exist" — on the one command documented for confirming which profile a run
    // would pick.
    //
    // Exempt for the same reason as `--config`: `config init` and the wizard author the
    // profile, so `wizard setup --profile ee_prod` legitimately names one that does not
    // exist yet.
    if let Some(name) = profile
        && !authors_config
    {
        profile::ensure_exists(config, name)?;
    }
    match cli.command {
        Command::Build(args) => commands::cmd_build::run(&args, profile, config),
        Command::Validate(args) => commands::cmd_validate::run(&args, profile, config),
        Command::Lint(args) => commands::cmd_lint::run(&args, config),
        Command::Diff(args) => commands::cmd_diff::run(&args, config),
        Command::Init(args) => commands::cmd_init::run(&args, profile, config),
        Command::Keys(args) => commands::cmd_keys::run(&args, profile, config),
        Command::Pack(args) => commands::cmd_pack::run(&args, profile, config),
        Command::Package(args) => commands::cmd_pack::run_package(&args, profile, config),
        Command::Rekey(args) => commands::cmd_rekey::run(&args, profile, config),
        Command::Upload(args) => commands::cmd_upload::run(&args, profile, config),
        Command::Download(args) => commands::cmd_download::run(&args, profile, config),
        Command::List(args) => commands::cmd_list::run(&args, profile, config),
        Command::Deploy(args) => commands::cmd_deploy::run(&args, profile, config),
        Command::Unpack(args) => commands::cmd_unpack::run(&args, profile, config),
        Command::Inspect(args) => commands::cmd_inspect::run(&args, config),
        Command::Publish(args) => commands::cmd_publish::run(&args, true, profile, config),
        Command::Unpublish(args) => commands::cmd_publish::run(&args, false, profile, config),
        Command::Delete(args) => commands::cmd_delete::run(&args, profile, config),
        Command::Status(args) => commands::cmd_status::run(&args, profile, config),
        Command::Catalogs(args) => commands::cmd_catalogs::run(&args, profile, config),
        Command::Check(args) => commands::cmd_check::run(&args, profile, config),
        Command::Doctor(args) => commands::cmd_doctor::run(&args, profile, config),
        Command::Preview(args) => commands::cmd_preview::run(&args),
        Command::Profiles(args) => commands::cmd_profiles::run(&args, profile, config),
        Command::Completions(args) => {
            commands::cmd_completions::run(args.shell);
            Ok(())
        }
        Command::Config(args) => commands::cmd_config::run(&args, config),
        Command::Wizard(args) => {
            wizard::prompts::require_tty()?;
            let outcome = wizard::run(&wizard::prompts::DialoguerPrompter, &args, profile, config);
            // Unconditionally, on the way out: a menu aborted part-way (Ctrl-C) never runs
            // dialoguer's own per-menu restore, and the operator's shell then keeps an
            // invisible cursor until they run `reset`.
            wizard::prompts::restore_cursor();
            outcome
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_classify_by_failure_kind() {
        assert_eq!(ToolError::user("x").exit_code, EXIT_USER);
        assert_eq!(ToolError::user("x").exit_code, 1);
        assert_eq!(ToolError::transient("x").exit_code, EXIT_TRANSIENT);
        assert_eq!(ToolError::transient("x").exit_code, 3);
        assert_eq!(ToolError::auth("x").exit_code, EXIT_AUTH);
        assert_eq!(ToolError::auth("x").exit_code, 4);
        assert_eq!(ToolError::transient("boom").message, "boom");
    }

    #[test]
    fn exit_two_is_reserved_for_clap() {
        // clap exits 2 on an argument-parse error; none of our classes may collide.
        assert_ne!(EXIT_USER, 2);
        assert_ne!(EXIT_TRANSIENT, 2);
        assert_ne!(EXIT_AUTH, 2);
    }
}
