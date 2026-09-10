//! A tiny block-on helper so the synchronous CLI commands can drive the async
//! S3 (`object_store`) and HTTP (`reqwest`) calls.
//!
//! The tool's CLI core stays synchronous (the local provider commands have no
//! async work); only the networked ops (e.g. `upload`/`download`/`list`/
//! `status`/`publish`/`deploy`) need a runtime, so each builds a small
//! current-thread Tokio runtime and `block_on`s its future rather than the
//! whole `main` being `#[tokio::main]`.

use crate::ToolError;

/// Run `fut` to completion on a fresh current-thread Tokio runtime.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) if the runtime cannot be constructed (a
/// resource exhaustion the user can act on); otherwise returns the future's
/// own `Result`.
pub fn block_on<F, T>(fut: F) -> Result<T, ToolError>
where
    F: std::future::Future<Output = Result<T, ToolError>>,
{
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| ToolError::user(format!("cannot start the async runtime: {e}")))?;
    rt.block_on(fut)
}
