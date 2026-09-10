//! Fuzz the parquet schema/value validator.
//!
//! The input bytes are written under a well-formed data-file name and read as a
//! provider-supplied `allele-freq.*.parquet`. `validate_parquet_dir` checks its schema, the
//! decompression-bomb caps (read from row-group metadata before any decode) and the per-row
//! value rules. The same code runs on the node's ingest path, so its input is untrusted.
//!
//! It must return `Ok` or `Err` and never panic. A crash is reachable from any package a
//! provider uploads.
//!
//! # Panics that the product already handles must not read as crashes
//!
//! `arrow-ipc`'s metadata schema decoder (`fb_to_schema`) panics rather than returning an
//! error on some crafted parquet. A malformed embedded `ARROW:schema` flatbuffer whose `Int`
//! field declares a bit width of 0, or one whose schema has no `fields` at all, both do it.
//!
//! The product turns that into a clean error. `validate_parquet_dir` runs the read inside
//! `core::validate_parquet::catch_parquet_panic`, so under the normal panic-unwind build a
//! malformed file yields `Err(CoreError::InvalidParquet)` and never a process abort. The
//! fixtures under `crates/core/tests/fixtures/malformed/` pin that in the `core` unit suite.
//!
//! `libfuzzer-sys`'s default panic hook prints the panic and calls `process::abort()`
//! synchronously at the panic site, before unwinding starts and therefore before
//! `catch_parquet_panic` can catch anything. Left alone it makes this target abort on exactly
//! the inputs the product handles, which is noise rather than a real defect.
//!
//! [`install_handled_decode_aware_hook`] replaces that hook once with one that consults
//! `gdi_node_standalone_core::panic_guard::handled_decode_in_progress`, the same thread-local
//! the node's own panic hooks consult. While a guarded decode is in progress the panic is
//! silenced and unwinds normally, so the product's `catch_unwind` catches it and the target
//! matches production. Outside a guarded region the original libfuzzer-sys hook still runs and
//! aborts at the panic site, which is what preserves full stack frames for triage, so a
//! genuinely uncaught panic is still reported as a crash with its message intact.
#![no_main]

use std::fs;
use std::sync::Once;

use libfuzzer_sys::fuzz_target;

use gdi_node_standalone_core::panic_guard::handled_decode_in_progress;
use gdi_node_standalone_core::validate_parquet::{validate_parquet_dir, ParquetCaps};

/// See the module-level doc comment. Idempotent and cheap, so it is called at the top of every
/// iteration rather than through `fuzz_target!`'s `init:` clause, which keeps this file a
/// single closure. The `Once` is what makes that free.
fn install_handled_decode_aware_hook() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // Captures libfuzzer-sys's own hook, installed by `LLVMFuzzerInitialize`, which the
        // libFuzzer runtime calls before this ever runs: print, then abort at the panic
        // site. It is delegated to unchanged for an uncaught panic, and silenced only
        // inside a guarded region.
        let libfuzzer_abort_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |panic_info| {
            if handled_decode_in_progress() {
                // A guarded decode's own `catch_unwind` is about to catch this
                // a few frames up on this same thread: no print, no abort.
                return;
            }
            libfuzzer_abort_hook(panic_info);
        }));
    });
}

fuzz_target!(|data: &[u8]| {
    install_handled_decode_aware_hook();

    // A fresh tempdir per iteration. If the environment cannot provide one, skip rather than
    // mask parser panics.
    let Ok(dir) = tempfile::tempdir() else {
        return;
    };
    // A name `collect_data_files` and `group_by_chr_block` recognise, so the fuzzer exercises
    // the per-file and per-group path rather than only the directory scan.
    let file = dir
        .path()
        .join("allele-freq.chr1.0.br10000000.0123456789abcdef.parquet");
    if fs::write(&file, data).is_err() {
        return;
    }

    // Must return (Ok or Err), never panic, on any byte stream.
    let _ = validate_parquet_dir(dir.path(), &ParquetCaps::default());
});
