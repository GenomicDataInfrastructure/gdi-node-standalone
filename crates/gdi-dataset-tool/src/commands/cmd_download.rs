//! The `download` command: GET a `{id}.tar.c4gh` package from the active
//! profile's S3 bucket to a local path (for backup, transfer, etc.). S3-only —
//! no local analog.
//!
//! The op logic lives in [`crate::s3`]; this is the thin clap wrapper.

use std::path::{Path, PathBuf};

use crate::cli::DownloadArgs;
use crate::s3::TAR_C4GH_SUFFIX;
use crate::{ToolError, profile, runtime, s3};

/// Run `download`.
///
/// # Errors
///
/// Returns a [`ToolError`] when the profile has no `[s3]` block, the output
/// exists without `--force`, the package is absent, or the id is malformed
/// (all exit 1). Any S3 GET / write failure exits 1, except an auth /
/// permission failure (exit 4) or a transient / throttled failure (exit 3),
/// matching [`s3::download_package_to_path`].
pub fn run(
    args: &DownloadArgs,
    profile_name: Option<&str>,
    config_path: Option<&Path>,
) -> Result<(), ToolError> {
    // Validate the dataset id up front, like every other id-taking command, so a malformed
    // id fails clearly instead of deriving the output path from unvalidated input and
    // surfacing a confusing store error.
    if !gdi_node_standalone_core::id::is_valid_dataset_id(&args.id) {
        return Err(ToolError::user(format!(
            "invalid dataset id '{}': not a well-formed GDI dataset id",
            args.id
        )));
    }
    let active = profile::load_active(config_path, profile_name)?;
    // The package body client: unbounded, so a multi-GB `.tar.c4gh` is never cut off
    // mid-stream by a request timeout. `download` makes no metadata request of its own.
    let store = s3::open_package_store(&active, "download")?;
    let source = active.s3.as_ref().map(crate::s3::target_label);
    run_with_store(args, &store, source.as_deref())
}

/// `download` against an already-opened store — the same code path [`run`] takes, minus
/// profile resolution. See [`crate::commands::cmd_upload::run_with_store`] for the rationale.
///
/// [`run`] validates the id before the profile is touched, so this entry point does not
/// repeat that guard. A caller reaching it directly already holds a store, which is past the
/// point the guard protects.
///
/// # Errors
///
/// Returns a [`ToolError`] when the output exists without `--force`, the package is absent,
/// or any S3 GET / write fails.
pub fn run_with_store(
    args: &DownloadArgs,
    store: &s3::PackageStore,
    source: Option<&str>,
) -> Result<(), ToolError> {
    let started = std::time::Instant::now();
    let file_name = format!("{}{TAR_C4GH_SUFFIX}", args.id);
    let output = match args.output.clone() {
        // A directory means "put it in here", the way `cp` reads it. Taken as the literal
        // output path instead, `-o downloads/` would report "output already exists" and
        // `--force` would then fail with a raw `Is a directory`.
        Some(path) if path.is_dir() => path.join(&file_name),
        Some(path) => path,
        None => PathBuf::from(&file_name),
    };
    if output.exists() && !args.force {
        return Err(ToolError::user(format!(
            "output already exists: {} (use --force to overwrite)",
            output.display()
        )));
    }

    crate::output::note(&format!("downloading {} -> {}", args.id, output.display()));
    if let Some(label) = source {
        crate::output::note(&format!("source: {label}"));
    }

    runtime::block_on(s3::download_package_to_path(
        store,
        &args.id,
        &output,
        args.max_size,
    ))?;
    if let Ok(meta) = std::fs::metadata(&output) {
        crate::output::note(&format!("downloaded {} bytes", meta.len()));
    }
    crate::output::note(&format!("download complete in {:.1?}", started.elapsed()));
    crate::output::emit_result(
        args.format,
        &format!("downloaded {} -> {}", args.id, output.display()),
        &serde_json::json!({
            "schemaVersion": 1,
            "status": "ok",
            "action": "download",
            "datasetId": args.id,
            "path": output.display().to_string(),
        }),
    );
    Ok(())
}
