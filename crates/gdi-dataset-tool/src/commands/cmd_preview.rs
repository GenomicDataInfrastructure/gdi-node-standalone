//! `gdi-dataset-tool preview <vcf>` — a read-only dry run over a VCF.
//!
//! Reports the recognized populations / AF-AC fields, the record + row counts, and
//! any warnings (ignored INFO fields, populations with no AF) without writing a
//! staging directory — so a provider can sanity-check what `build` would produce
//! before committing to a full conversion. Honours bgzipped (`.vcf.gz`) input.

use gdi_node_standalone_core::convert::{
    ConvertOptions, MAX_POPULATIONS, PreviewReport, Severity, preview_vcf_with_progress,
};

use crate::ToolError;
use crate::cli::{OutputFormat, PreviewArgs};

/// Run `preview`: convert-validate the VCF in memory and print the report as text or
/// JSON. Writes nothing to disk.
///
/// # Errors
///
/// Returns a [`ToolError`] if the VCF cannot be read / parsed or violates a hard
/// conversion rule. (`--format` is validated by clap before this runs.)
pub fn run(args: &PreviewArgs) -> Result<(), ToolError> {
    let opts = ConvertOptions {
        assembly: args.assembly.clone(),
        block_range: args.block_range,
        min_allele_count: args.min_allele_count,
    };
    crate::output::note(&format!(
        "previewing VCF {} (assembly {}, block range {}, min allele count {})",
        args.vcf.display(),
        opts.assembly,
        opts.block_range,
        opts.min_allele_count
    ));
    // The scan is the whole command's runtime, so without a bar a multi-minute preview
    // reads as a hang. `ConvertProgress` is the same byte bar `build` draws (and the same
    // non-TTY heartbeat), sized from the file itself.
    let prog = crate::progress::ConvertProgress::for_paths(
        std::slice::from_ref(&args.vcf),
        crate::progress::active(),
    );
    let report = preview_vcf_with_progress(&args.vcf, &opts, &|n| prog.inc(0, n)).map_err(|e| {
        // VCF stage: `ToolError::from_vcf_stage` relabels `invalid parquet:`. The user
        // supplied a VCF and no parquet exists.
        let e = ToolError::from_vcf_stage(&e);
        ToolError::user(format!("preview of {}: {}", args.vcf.display(), e.message))
    });
    prog.finish();
    let report = report?;
    crate::output::note(&format!(
        "resolved {} header population(s), {} emitted, {} recognized AF/AC field(s); {} distinct record(s), {} row(s) emitted",
        report.populations_recognized.len(),
        report.populations_emitted.len(),
        report.recognized_fields.len(),
        report.number_of_records,
        report.rows_emitted
    ));

    // `--floor-impact`: convert once more with no floor, so the delta shows what the
    // configured floor actually costs. Providers otherwise choose a number blind.
    let impact = if args.floor_impact {
        Some(compute_floor_impact(&args.vcf, &opts, &report)?)
    } else {
        None
    };

    match args.format {
        OutputFormat::Json => {
            let mut value = crate::output::versioned_value(&report)
                .map_err(|e| ToolError::user(format!("serializing preview report: {e}")))?;
            if let (Some(impact), Some(map)) = (&impact, value.as_object_mut()) {
                map.insert(
                    "floorImpact".to_owned(),
                    serde_json::to_value(impact)
                        .map_err(|e| ToolError::user(format!("serializing floor impact: {e}")))?,
                );
            }
            crate::output::emit_json(&value);
        }
        OutputFormat::Text => {
            print_text(&report);
            if let Some(impact) = &impact {
                print_floor_impact(impact);
            }
        }
    }
    Ok(())
}

/// Re-run the preview with no floor and diff it against `floored`.
///
/// # Errors
///
/// Returns a [`ToolError`] when the baseline conversion fails (it cannot, in practice: the
/// floored pass already parsed the same VCF).
fn compute_floor_impact(
    vcf: &std::path::Path,
    opts: &ConvertOptions,
    floored: &PreviewReport,
) -> Result<FloorImpact, ToolError> {
    // With no floor the baseline is the floored pass. Converting the VCF a second time to
    // report a row of zeros would double the work of a `--floor-impact` run on a large VCF.
    if opts.min_allele_count == 0 {
        return Ok(floor_impact_at(0, floored, floored));
    }
    let baseline_opts = ConvertOptions {
        min_allele_count: 0,
        ..opts.clone()
    };
    // A second full scan of the same VCF: it needs the bar as much as the first, or
    // `--floor-impact` goes silent for exactly as long again.
    let prog = crate::progress::ConvertProgress::for_paths(
        &[vcf.to_path_buf()],
        crate::progress::active(),
    );
    let baseline =
        preview_vcf_with_progress(vcf, &baseline_opts, &|n| prog.inc(0, n)).map_err(|e| {
            let e = ToolError::from_vcf_stage(&e);
            ToolError::user(format!(
                "floor-impact baseline of {}: {}",
                vcf.display(),
                e.message
            ))
        });
    prog.finish();
    let baseline = baseline?;
    Ok(floor_impact_at(opts.min_allele_count, &baseline, floored))
}

/// Render the floor impact for a human.
fn print_floor_impact(i: &FloorImpact) {
    if i.min_allele_count == 0 {
        println!("floor impact: minAlleleCount is 0, so no rows are withheld at build time");
        return;
    }
    println!(
        "floor impact (minAlleleCount {}): {} of {} row(s) withheld ({:.1}%), {} kept",
        i.min_allele_count, i.rows_withheld, i.rows_baseline, i.percent_withheld, i.rows_kept
    );
    println!(
        "populations erased entirely by the floor ({}): {}",
        i.populations_lost.len(),
        join_or_none(&i.populations_lost)
    );
}

/// What a `minAlleleCount` floor would withhold from this VCF, measured by converting it
/// twice: once with no floor, once with the configured one.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FloorImpact {
    /// The floor the comparison was run at.
    pub min_allele_count: u32,
    /// Rows the VCF would emit with no floor.
    pub rows_baseline: u64,
    /// Rows that survive the floor.
    pub rows_kept: u64,
    /// Rows the floor withholds — below it, plus the siblings its collapse removes.
    pub rows_withheld: u64,
    /// Percentage of baseline rows withheld, at full precision; the text renderer
    /// rounds it to one decimal for display.
    pub percent_withheld: f64,
    /// Populations the floor erases from the dataset entirely. A population far above the
    /// floor can appear here: the coherence collapse removes a withheld row's siblings.
    pub populations_lost: Vec<String>,
}

/// Compare an unfloored preview against a floored one.
fn floor_impact_at(floor: u32, baseline: &PreviewReport, floored: &PreviewReport) -> FloorImpact {
    let rows_withheld = baseline.rows_emitted.saturating_sub(floored.rows_emitted);
    #[expect(
        clippy::cast_precision_loss,
        reason = "row counts far below 2^53; the value is a display percentage"
    )]
    let percent_withheld = if baseline.rows_emitted == 0 {
        0.0
    } else {
        (rows_withheld as f64 / baseline.rows_emitted as f64) * 100.0
    };
    let populations_lost: Vec<String> = baseline
        .populations_emitted
        .iter()
        .filter(|p| !floored.populations_emitted.contains(p))
        .cloned()
        .collect();
    FloorImpact {
        min_allele_count: floor,
        rows_baseline: baseline.rows_emitted,
        rows_kept: floored.rows_emitted,
        rows_withheld,
        percent_withheld,
        populations_lost,
    }
}

/// Render the report as a concise human-readable summary.
fn print_text(report: &PreviewReport) {
    println!(
        "populations recognized in the header ({}): {}",
        report.populations_recognized.len(),
        join_or_none(&report.populations_recognized)
    );
    // The header set is what the VCF declares; under a `min_allele_count` floor it can
    // be a strict superset of what reaches parquet. Print both, so "3 populations" is
    // never read as a promise that three will be served.
    println!(
        "populations actually emitted ({}): {}",
        report.populations_emitted.len(),
        join_or_none(&report.populations_emitted)
    );
    println!(
        "populations counted toward the cap: {} of {} max (those with an AF field){}",
        report.af_population_count,
        MAX_POPULATIONS,
        if report.af_population_count > MAX_POPULATIONS {
            "; over the cap, so build will reject this dataset"
        } else {
            ""
        }
    );
    println!(
        "recognized AF/AC fields ({}): {}",
        report.recognized_fields.len(),
        join_or_none(&report.recognized_fields)
    );
    // Both are structured data on the report, not merely prose in a diagnostic: a
    // population with no AF emits nothing, and an ignored field is a silently dropped
    // column. Naming them is the difference between "one population" and "why one?".
    println!(
        "ignored INFO fields ({}): {}",
        report.ignored_info_fields.len(),
        join_or_none(&report.ignored_info_fields)
    );
    println!(
        "populations with no AF ({}, emit no rows): {}",
        report.populations_without_af.len(),
        join_or_none(&report.populations_without_af)
    );
    println!("distinct records: {}", report.number_of_records);
    println!("rows that would be emitted: {}", report.rows_emitted);
    println!(
        "input records: {} read, {} dropped ({} non-primary contig, {} no supported ALT), \
         {} non-PASS FILTER (kept)",
        report.drops.input_records,
        report.drops.total_dropped(),
        report.drops.dropped_unsupported_contig,
        report.drops.dropped_no_supported_alt,
        report.drops.non_pass_records,
    );
    // Alleles lost from records that were published — invisible in the drop counts above,
    // since those records survived on another ALT.
    println!(
        "ALT alleles discarded from surviving records: {}",
        report.drops.alleles_discarded
    );
    println!(
        "k-anonymity suppression: {} row(s) below the floor, {} row(s) removed by \
         collapsing {} variant(s) to Total",
        report.suppression.rows_below_floor,
        report.suppression.rows_collapsed_to_total,
        report.suppression.variants_collapsed_to_total,
    );
    // The VCF's own cohort size, when it carries `NS`: the value the provider is otherwise
    // left to count by hand for the recommended `numberOfUniqueIndividuals`.
    if let Some(peak) = report.drops.ns_peak {
        println!(
            "NS peak: {peak} (samples with data at the best-covered site, the value the VCF \
             suggests for metadata.numberOfUniqueIndividuals)"
        );
    }
    if report.diagnostics.is_empty() {
        println!("diagnostics: none");
    } else {
        println!("diagnostics ({}):", report.diagnostics.len());
        for d in &report.diagnostics {
            // Diagnostic messages fold the same raw header ids in (convert.rs builds them
            // from the ignored-field set), so they need the same treatment.
            println!(
                "  - [{}] {}",
                severity_label(d.severity),
                crate::output::Untrusted(&d.message)
            );
        }
    }
}

/// The CLI prefix for a diagnostic's severity. A `note` is an expected consequence of
/// declared configuration; a `warning` is a probable mistake (and fails `build --strict`).
fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Warning => "warning",
        Severity::Note => "note",
    }
}

/// Join a list with `, `, or `(none)` when empty, sanitizing each item for terminal
/// control sequences.
///
/// The sanitization is part of the contract, not an implementation detail: every list this
/// report renders is raw VCF header text, and this is where it becomes safe to print. A
/// caller that formats a list some other way is not covered.
fn join_or_none(items: &[String]) -> String {
    if items.is_empty() {
        "(none)".to_owned()
    } else {
        // Every list on this report is raw VCF header text: `convert` keeps any id with an
        // underscore-separated `AF`/`AC`/`AN` token, so `AF_<ESC>[2J` qualifies on its first
        // token. This screen is also the wizard's disclosure gate, where the operator
        // answers "Publish these populations?" — so an injected escape could repaint the
        // list being confirmed. `output::join_untrusted` is shared with that gate, so both
        // renders sanitize with the same code rather than the same intention.
        crate::output::join_untrusted(items)
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
mod tests {
    use super::*;
    use gdi_node_standalone_core::convert::preview_vcf;
    use std::io::Write as _;

    /// Three populations; `FI` has AC=2 and falls below a floor of 5.
    const THREE_POP: &str = "##fileformat=VCFv4.2\n\
##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
##INFO=<ID=AC,Number=A,Type=Integer,Description=\"ac\">\n\
##INFO=<ID=AN,Number=1,Type=Integer,Description=\"an\">\n\
##INFO=<ID=AF_EE,Number=A,Type=Float,Description=\"ee\">\n\
##INFO=<ID=AC_EE,Number=A,Type=Integer,Description=\"ee\">\n\
##INFO=<ID=AF_FI,Number=A,Type=Float,Description=\"fi\">\n\
##INFO=<ID=AC_FI,Number=A,Type=Integer,Description=\"fi\">\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n\
1\t100\t.\tA\tG\t.\tPASS\tAF=0.25;AC=250;AN=1000;AF_EE=0.4;AC_EE=248;AF_FI=0.01;AC_FI=2\n";

    fn report_at(dir: &std::path::Path, floor: u32) -> PreviewReport {
        let vcf = dir.join("in.vcf");
        let mut f = std::fs::File::create(&vcf).unwrap();
        f.write_all(THREE_POP.as_bytes()).unwrap();
        preview_vcf(
            &vcf,
            &ConvertOptions {
                assembly: "GRCh38".into(),
                block_range: 10_000_000,
                min_allele_count: floor,
            },
        )
        .unwrap()
    }

    #[test]
    fn floor_impact_names_the_populations_a_floor_would_erase() {
        // Picking a floor is otherwise blind. `EE` has AC=248 — far above 5 — yet is lost
        // as collateral of the coherence collapse. That is the surprising part.
        let dir = tempfile::tempdir().unwrap();
        let baseline = report_at(dir.path(), 0);
        let floored = report_at(dir.path(), 5);
        let impact = floor_impact_at(5, &baseline, &floored);

        assert_eq!(impact.rows_baseline, 3);
        assert_eq!(impact.rows_kept, 1);
        assert_eq!(impact.rows_withheld, 2);
        assert_eq!(impact.populations_lost, ["EE", "FI"]);
    }

    #[test]
    fn a_zero_floor_withholds_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let baseline = report_at(dir.path(), 0);
        let impact = floor_impact_at(0, &baseline, &baseline);
        assert_eq!(impact.rows_withheld, 0);
        assert!(impact.populations_lost.is_empty());
    }

    /// Every key of `preview --format json` is `camelCase`, at every depth.
    ///
    /// This contract spans two crates: the payload is [`PreviewReport`] from `core`, while
    /// `schemaVersion` and `floorImpact` are added here — so a missing `rename_all` on
    /// either half would put `rows_emitted` next to `floorImpact` in one object.
    ///
    /// Asserting the rendered value rather than the structs is what makes this bind: a new
    /// field, a newly nested type, or a fourth report merged into this envelope fails here
    /// without anyone having to remember the convention. The checker lives on
    /// [`crate::output`] beside the envelope, so the sibling verb `lint` asserts the same
    /// contract with the same code.
    #[test]
    fn the_json_report_is_camel_case_at_every_depth() {
        let dir = tempfile::tempdir().unwrap();
        let floored = report_at(dir.path(), 5);
        let baseline = report_at(dir.path(), 0);
        let impact = floor_impact_at(5, &baseline, &floored);
        let mut value = crate::output::versioned_value(&floored).unwrap();
        value.as_object_mut().unwrap().insert(
            "floorImpact".to_owned(),
            serde_json::to_value(&impact).unwrap(),
        );

        let offenders = crate::output::non_camel_keys(&value);
        assert!(
            offenders.is_empty(),
            "non-camelCase keys in `preview --format json`: {offenders:?}"
        );

        // Anti-vacuity: an empty offender list proves nothing unless the walk actually
        // descended into the nested objects, which is where the snake_case keys were.
        assert!(
            value
                .get("drops")
                .and_then(|d| d.get("inputRecords"))
                .is_some(),
            "the walk never reached `drops`, so a green result here is vacuous"
        );
    }
}
