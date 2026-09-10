//! Fuzz the safe TAR extractor.
//!
//! The input bytes are a provider-supplied TAR stream, the inner `.tar` of a `.tar.c4gh`.
//! `extract_tar_safely` unpacks it into a destination directory under member-type,
//! path-containment and size/count bounds.
//!
//! It must return `Ok` or `Err`, never panic, and never write outside the destination. A crash
//! or an escape is reachable from any package a provider uploads.
//!
//! # Containment differential
//!
//! A path traversal or symlink escape does not panic. It succeeds and writes outside `dest`,
//! which a crash-only oracle cannot see. Every successful extraction is therefore cross-checked
//! with [`check_staging_dir`], an independent filesystem-side walk that uses
//! `symlink_metadata`, so it detects links rather than following them, and rejects any
//! symlink, hardlink or special member and any path escaping the root.
//!
//! `extract_tar_safely` claiming success while that walk finds an escape is a containment bug.
//! The two paths must agree.
#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;

use gdi_node_standalone_core::extract::{check_staging_dir, extract_tar_safely, ExtractBounds};

fuzz_target!(|data: &[u8]| {
    // A fresh destination per iteration. If the tempdir cannot be created, skip rather than
    // mask parser panics.
    let Ok(dest) = tempfile::tempdir() else {
        return;
    };
    // Must return (Ok or Err), never panic, on any byte stream.
    if extract_tar_safely(Cursor::new(data), dest.path(), &ExtractBounds::default()).is_ok() {
        // Extraction claimed success, so an independent walk must agree that nothing
        // escaped. The bounds are generous, so only the containment and member-type
        // invariants are cross-checked. A member or byte count differing from the caps
        // `extract_tar_safely` already enforced would be a false positive.
        let containment_only = ExtractBounds {
            max_members: usize::MAX,
            max_total_bytes: u64::MAX,
        };
        check_staging_dir(dest.path(), &containment_only).expect(
            "extract_tar_safely returned Ok but the staging dir failed the independent \
             containment check (symlink/hardlink/special member or path escape)",
        );
    }
});
