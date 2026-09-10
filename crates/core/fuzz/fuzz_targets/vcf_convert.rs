//! Fuzz the aggregated VCF -> Parquet converter.
//!
//! The input bytes are written to a temporary `.vcf` and read as a provider-supplied VCF, the
//! largest untrusted input on the build path, through `noodles-vcf` and the per-record
//! allele-frequency value validation.
//!
//! `convert_vcf` must return `Ok` or `Err` and never panic. A crash is reachable from any VCF
//! a provider hands the tool.
#![no_main]

use std::fs;

use libfuzzer_sys::fuzz_target;

use gdi_node_standalone_core::convert::{convert_vcf, ConvertOptions};

fuzz_target!(|data: &[u8]| {
    // A fresh tempdir per iteration. If the environment cannot provide one, skip rather than
    // extract into an unknown directory and mask parser panics.
    let Ok(dir) = tempfile::tempdir() else {
        return;
    };
    let vcf_path = dir.path().join("input.vcf");
    let out_dir = dir.path().join("out");
    if fs::write(&vcf_path, data).is_err() || fs::create_dir_all(&out_dir).is_err() {
        return;
    }

    let opts = ConvertOptions {
        assembly: "GRCh38".to_owned(),
        block_range: 10_000_000,
        min_allele_count: 0,
    };

    // Must return (Ok or Err), never panic, on any byte stream.
    let _ = convert_vcf(&vcf_path, &out_dir, &opts);
});
