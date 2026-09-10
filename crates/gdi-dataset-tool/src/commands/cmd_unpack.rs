//! The `unpack` command: decrypt, validate, and extract a `.tar.c4gh` package to
//! an arbitrary directory (for inspection or manual transfer).
//!
//! Distinct from `deploy`, which installs a package into a node's inbox: `unpack` only
//! materialises a package's plaintext contents for the operator. It decrypts with the
//! provider's own identity (packages are encrypted to the node recipient **plus** the
//! provider's own recipient, so the provider can always decrypt its own packages),
//! safe-extracts the TAR into `--output`, and re-runs the structural gates so the extracted
//! directory is known-valid.
//!
//! The op's logic lives in the CLI-independent [`unpack_package`] library
//! function; the CLI is a thin wrapper.

use std::fs;
use std::path::{Path, PathBuf};

use gdi_node_standalone_core::extract::{ExtractBounds, extract_tar_safely};

use super::cmd_validate;
use crate::cli::UnpackArgs;
use crate::{ToolError, pkgio};

/// Run `unpack`, printing a success line.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) if the package cannot be decrypted, the
/// output directory is non-empty without `--force`, extraction fails, or the
/// extracted dataset fails the structural gates.
pub fn run(
    args: &UnpackArgs,
    profile_name: Option<&str>,
    config_path: Option<&Path>,
) -> Result<(), ToolError> {
    unpack_package(
        &args.package,
        &args.output,
        args.force,
        profile_name,
        config_path,
    )?;
    println!(
        "unpacked {} -> {}",
        args.package.display(),
        args.output.display()
    );
    Ok(())
}

/// Decrypt `package` with the provider identity, safe-extract it into `output`,
/// and re-validate the extracted dataset.
///
/// `output` is created if missing; an existing non-empty directory is refused
/// unless `force`.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) on a decrypt failure, a non-empty output
/// without `force`, an extraction failure, or a structural-gate failure.
pub fn unpack_package(
    package: &Path,
    output: &Path,
    force: bool,
    profile_name: Option<&str>,
    config_path: Option<&Path>,
) -> Result<(), ToolError> {
    let started = std::time::Instant::now();
    prepare_output_dir(output, force)?;
    crate::output::note(&format!(
        "unpacking {} -> {}",
        package.display(),
        output.display()
    ));

    // Diagnostic only: report which provider identities (by public-key fingerprint —
    // never key bytes) are tried to decrypt. Best-effort + verbose-gated, so a config
    // failure here can never change the decrypt path's own canonical error.
    if crate::output::is_verbose()
        && let Ok(identities) = pkgio::provider_identities(config_path)
    {
        let fingerprints: Vec<String> = identities
            .iter()
            .map(|sk| gdi_node_standalone_core::crypt4gh::public_key_fingerprint(&sk.public_key()))
            .collect();
        crate::output::note(&format!(
            "decrypting with {} provider identit{} ({})",
            fingerprints.len(),
            if fingerprints.len() == 1 { "y" } else { "ies" },
            fingerprints.join(", ")
        ));
    }

    // Stream the crypt4gh decrypt straight into the safe extractor over an in-process
    // pipe, so the whole plaintext TAR is never staged to scratch disk (that would be a
    // full extra dataset-sized copy beside the extracted output). The decrypt runs on a
    // worker thread feeding the pipe; this thread reads + extracts the other end.
    let (reader, mut writer) = std::io::pipe()
        .map_err(|e| ToolError::user(format!("cannot create pipe for unpack: {e}")))?;
    let package_owned = package.to_path_buf();
    let config_owned = config_path.map(Path::to_path_buf);
    let decrypt_thread = std::thread::spawn(move || {
        pkgio::decrypt_package_to_writer(&package_owned, &mut writer, config_owned.as_deref())
    });

    // Live byte progress over the decrypt→extract stream. Sized to the `.tar.c4gh`
    // ciphertext length (the plaintext TAR consumed is marginally smaller — crypt4gh adds
    // a small per-block tag — so the bar tops out just shy of 100% before it is cleared).
    let total = fs::metadata(package).map_or(0, |m| m.len());
    let sp = crate::progress::StreamProgress::new(total, "unpacking", crate::progress::active());

    // If extraction fails it drops `reader`, releasing a decrypter blocked on a full pipe
    // (no deadlock). On extract error the worker's write gets `BrokenPipe`, which
    // `decrypt_package_to_writer` maps to `Ok`.
    sp.note(&format!(
        "decrypting + extracting {} -> {}",
        package.display(),
        output.display()
    ));
    let extract_result =
        extract_tar_safely(sp.wrap_read(reader), output, &ExtractBounds::default())
            .map_err(|e| ToolError::from(&e));
    let decrypt_result = decrypt_thread
        .join()
        .unwrap_or_else(|_| Err(ToolError::user("decrypt thread panicked while unpacking")));
    sp.finish();
    // A genuine decrypt failure (e.g. wrong identity) is the root cause — surface it over
    // an extract error that is only the truncated-stream symptom.
    decrypt_result?;
    extract_result?;

    // Per-member visibility: the safe extractor is opaque (no per-member hook), so walk
    // the materialized tree afterward for a `tar -v`-style member list + a count. Skipped
    // entirely under `-q` (nothing would print, so don't pay for the walk).
    if crate::output::verbosity() >= crate::output::Verbosity::Normal {
        let extracted = collect_extracted_files(output);
        for (path, size) in &extracted {
            let rel = path.strip_prefix(output).unwrap_or(path);
            crate::output::progress(&format!("extracted {} ({size} byte(s))", rel.display()));
        }
        crate::output::note(&format!("extracted {} member(s)", extracted.len()));
    }

    // Re-validate the extracted dataset so the output is known-good, using the active
    // profile's catalog allow-list (threaded via --profile). `validate_target` collects all
    // problems rather than failing fast, so turn a non-empty error set into a hard failure
    // here.
    let outcome = cmd_validate::validate_target(output, profile_name, config_path)?;
    if !outcome.is_valid() {
        return Err(ToolError::user(format!(
            "unpacked dataset failed validation ({} error(s)): {}",
            outcome.errors.len(),
            outcome.errors.join("; ")
        )));
    }
    crate::output::note(&format!("unpack complete in {:.1?}", started.elapsed()));
    Ok(())
}

/// Recursively collect every extracted file's path + size, for the post-extraction
/// per-member progress + count (the safe extractor is opaque — no per-member hook — so
/// the materialized tree is walked after the fact). Read errors are skipped: this feeds
/// diagnostics only and must never fail the unpack.
fn collect_extracted_files(root: &Path) -> Vec<(PathBuf, u64)> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() {
                let size = entry.metadata().map_or(0, |m| m.len());
                files.push((path, size));
            }
        }
    }
    // Deterministic listing regardless of read_dir order.
    files.sort();
    files
}

/// Create the output directory, refusing a non-empty existing one without `force`.
#[expect(
    clippy::disallowed_methods,
    reason = "operator-chosen extraction directory on the operator's own machine"
)]
fn prepare_output_dir(output: &Path, force: bool) -> Result<(), ToolError> {
    if output.exists() {
        if !output.is_dir() {
            return Err(ToolError::user(format!(
                "output exists and is not a directory: {}",
                output.display()
            )));
        }
        let non_empty = fs::read_dir(output)
            .map_err(|e| ToolError::user(format!("cannot read {}: {e}", output.display())))?
            .next()
            .is_some();
        if non_empty && !force {
            return Err(ToolError::user(format!(
                "output directory is not empty: {} (use --force to extract into it)",
                output.display()
            )));
        }
        return Ok(());
    }
    fs::create_dir_all(output)
        .map_err(|e| ToolError::user(format!("cannot create {}: {e}", output.display())))
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;

    #[test]
    fn non_empty_output_refused_without_force() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("out");
        fs::create_dir_all(&out).unwrap();
        fs::write(out.join("existing"), b"x").unwrap();
        let err = prepare_output_dir(&out, false).unwrap_err();
        assert_eq!(err.exit_code, 1);
        assert!(err.message.contains("not empty"));
        // --force is accepted.
        prepare_output_dir(&out, true).unwrap();
    }

    #[test]
    fn fresh_output_created() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("a/b/c");
        prepare_output_dir(&out, false).unwrap();
        assert!(out.is_dir());
    }
}
