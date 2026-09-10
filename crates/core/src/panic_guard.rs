//! Marks the window in which the current thread is inside a decode wrapped in
//! [`std::panic::catch_unwind`], so a process-level panic hook can tell an expected panic
//! from a genuine bug.
//!
//! `arrow` and `parquet` panic rather than return an error on some crafted parquet, so
//! `crate::validate_parquet` and `crate::parquet_io` wrap every decode call in
//! `catch_unwind`: a malformed provider file becomes a clean
//! [`crate::error::CoreError::InvalidParquet`] instead of aborting the process. A
//! `std::panic::set_hook` callback runs before unwinding starts, so on its own it cannot
//! tell a panic that is about to be caught a few frames up from one that will escape.
//! This flag is what lets a hook tell the two apart.

use crate::error::{CoreError, CoreResult};
use std::cell::Cell;
use std::marker::PhantomData;

thread_local! {
    /// A depth counter rather than a flag, because guarded decodes can nest. "In
    /// progress" is `depth > 0`: each [`HandledDecodeGuard`] increments on construction
    /// and decrements on [`Drop`], so only the outermost guard's drop returns it to zero.
    /// A `bool` would let an inner region's drop clear it while an outer region is still
    /// active. Thread-local rather than a shared atomic, because the window is a property
    /// of one thread's call stack and concurrent decodes must not see each other.
    static HANDLED_DECODE_DEPTH: Cell<u32> = const { Cell::new(0) };
}

/// True while the current thread is inside one or more decodes wrapped in
/// [`std::panic::catch_unwind`] that convert any panic into a clean
/// [`crate::error::CoreError::InvalidParquet`]. A panic firing now is about to be handled.
///
/// Both binaries' panic hooks consult this to downgrade their output to a `debug` line for
/// this window, instead of the raw panic text a hook normally writes.
#[must_use]
pub fn handled_decode_in_progress() -> bool {
    HANDLED_DECODE_DEPTH.with(|depth| depth.get() > 0)
}

/// RAII guard marking the current thread as inside a handled-decode window.
///
/// Increments the thread's depth counter on construction and decrements it on [`Drop`],
/// including when the scope ends in an unwinding panic. Unwinding runs the `Drop` impls of
/// locals still in scope, and this guard is such a local, so its increment cannot outlive
/// the `catch_unwind` boundary it was created inside. The same ordering is what makes it a
/// usable signal: a panic hook runs at the panic site, before any unwinding and therefore
/// before any `Drop`, so the counter still reflects every guard live at panic time.
///
/// # Nesting
///
/// Constructing a guard while another is live on the same thread adds to the depth, and
/// [`handled_decode_in_progress`] stays true until every live guard has dropped. A hook
/// firing after an inner guard unwound but before an outer one dropped still sees the
/// window as open.
///
/// # Examples
/// ```
/// use gdi_node_standalone_core::panic_guard::{HandledDecodeGuard, handled_decode_in_progress};
///
/// let outcome = std::panic::catch_unwind(|| {
///     let _guard = HandledDecodeGuard::new();
///     assert!(handled_decode_in_progress());
///     // ... the guarded decode call goes here ...
/// });
/// assert!(outcome.is_ok());
/// assert!(!handled_decode_in_progress());
/// ```
#[must_use = "the depth counter is decremented as soon as this guard drops; bind it to a \
              named variable, since binding to `_` drops it immediately and guards nothing"]
pub struct HandledDecodeGuard {
    // Makes the guard `!Send` and `!Sync`. The depth counter is thread-local, so a guard
    // moved to another thread and dropped there would decrement that thread's counter and
    // leave its own stuck above zero. Pinning the guard to its constructing thread turns
    // the miscount into a compile error.
    _not_send: PhantomData<*const ()>,
}

impl HandledDecodeGuard {
    /// Marks the current thread as inside a handled-decode window until the
    /// returned guard is dropped. Safe to nest with another live guard on the
    /// same thread — see "Nesting" above.
    pub fn new() -> Self {
        HANDLED_DECODE_DEPTH.with(|depth| depth.set(depth.get() + 1));
        Self {
            _not_send: PhantomData,
        }
    }
}

impl Default for HandledDecodeGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for HandledDecodeGuard {
    fn drop(&mut self) {
        // Saturating rather than `- 1`: this runs while a panic unwinds, so an underflow
        // that correct `new`/`drop` pairing cannot produce must still not panic in drop
        // and abort the process.
        HANDLED_DECODE_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

/// Run `f` under [`HandledDecodeGuard`], turning a panic into the error `on_panic` builds.
/// `f` decodes untrusted provider bytes, which the arrow and parquet stack may panic on.
///
/// This is the only panic boundary for decodes in this crate. A boundary written without
/// the guard would let the process-level hook print raw panic text for every malformed
/// file, so `every_catch_unwind_goes_through_here` below fails on any `catch_unwind`
/// elsewhere in `src/`.
///
/// `AssertUnwindSafe` holds because every caller's closure returns a `Result` and leaves
/// only its own locals broken on unwind, or a caller-supplied sink whose partial state the
/// caller discards. Each call site states its own reasoning.
pub(crate) fn catch_decode_panic<T, F>(f: F, on_panic: impl FnOnce() -> CoreError) -> CoreResult<T>
where
    F: FnOnce() -> CoreResult<T>,
{
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = HandledDecodeGuard::new();
        f()
    })) {
        Ok(result) => result,
        Err(_) => Err(on_panic()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_outside_any_guard() {
        assert!(!handled_decode_in_progress());
    }

    #[test]
    fn set_for_the_life_of_the_guard_then_cleared() {
        assert!(!handled_decode_in_progress());
        {
            let _guard = HandledDecodeGuard::new();
            assert!(handled_decode_in_progress());
        }
        assert!(!handled_decode_in_progress());
    }

    #[test]
    fn cleared_even_when_the_guarded_call_panics() {
        assert!(!handled_decode_in_progress());
        let result = std::panic::catch_unwind(|| {
            let _guard = HandledDecodeGuard::new();
            assert!(handled_decode_in_progress());
            panic!("synthetic panic under the guard");
        });
        assert!(result.is_err());
        assert!(
            !handled_decode_in_progress(),
            "the flag leaked past an unwind through the guard's scope"
        );
    }

    #[test]
    fn nested_guards_only_clear_the_flag_once_the_outermost_drops() {
        // With a bool flag the inner guard's drop would clear it while the outer guard is
        // still live, so a panic in the rest of the outer region would read as unhandled.
        assert!(!handled_decode_in_progress());
        let outer = HandledDecodeGuard::new();
        assert!(handled_decode_in_progress());
        {
            let inner = HandledDecodeGuard::new();
            assert!(handled_decode_in_progress());
            drop(inner);
            assert!(
                handled_decode_in_progress(),
                "the inner guard's drop cleared the flag while the outer guard was still active"
            );
        }
        assert!(
            handled_decode_in_progress(),
            "the outer guard is still live after the inner guard's scope closed"
        );
        drop(outer);
        assert!(!handled_decode_in_progress());
    }

    #[test]
    fn a_panic_inside_a_nested_guard_leaves_the_outer_guard_correctly_counted() {
        assert!(!handled_decode_in_progress());
        let outer = HandledDecodeGuard::new();
        let result = std::panic::catch_unwind(|| {
            let _inner = HandledDecodeGuard::new();
            assert!(handled_decode_in_progress());
            panic!("synthetic panic inside the nested guard");
        });
        assert!(result.is_err());
        assert!(
            handled_decode_in_progress(),
            "the outer guard must still be counted after the inner guard unwound and dropped"
        );
        drop(outer);
        assert!(
            !handled_decode_in_progress(),
            "the depth must return to zero once the outermost guard drops"
        );
    }

    /// Every `catch_unwind` in this crate's production code goes through
    /// [`catch_decode_panic`], so no decode boundary can be written without the guard.
    /// `test_util::production_text` cuts test modules out: a test that arms a panic and
    /// catches it is exercising the hook, not decoding.
    #[test]
    fn every_catch_unwind_goes_through_here() {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).expect("read_dir") {
                let path = entry.expect("entry").path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        walk(&src, &mut files);
        assert!(files.len() >= 20, "the walk broke: {} files", files.len());
        let mut offenders = Vec::new();
        for file in files {
            if file.ends_with("panic_guard.rs") {
                continue;
            }
            // Production code only: a test that arms a panic, such as faults.rs's
            // `arm_panic_panics`, catches it legitimately and is not a decode boundary.
            let text = test_util::production_text(&std::fs::read_to_string(&file).expect("read"));
            for (i, line) in text.lines().enumerate() {
                if line.contains("catch_unwind(") && !line.trim_start().starts_with("//") {
                    offenders.push(format!("{}:{}", file.display(), i + 1));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "catch_unwind outside panic_guard.rs; route it through catch_decode_panic so \
             the HandledDecodeGuard cannot be forgotten: {offenders:?}"
        );
    }
}
