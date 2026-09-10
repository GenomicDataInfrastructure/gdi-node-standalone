//! Aggregated VCF -> Parquet conversion.
//!
//! Implements the schema and processing rules for chromosome/position/REF-ALT/
//! variant handling, multiple VCFs, Parquet file partitioning, Parquet options,
//! and aggregated mode (allele frequencies).
//!
//! The conversion is single-pass over the records, streaming each
//! `(chr, POS / block_range)` partition to its parquet file. The records' guaranteed
//! monotonic `(chr, POS)` ordering, enforced by `enforce_chr_pos_order`, makes a partition's
//! rows contiguous, so the batcher ships a partition when its key advances, and also
//! whenever the `MAX_BATCH_BYTES` budget is reached. That second flush is deferred to the
//! next `POS` boundary, so a `POS` group is never split across two batches. A worker keeps
//! the partition's writer open across its batches, appending each as a row group. Peak
//! memory is therefore the constant `pool_size × (WORKER_QUEUE_DEPTH + 1) ×
//! MAX_BATCH_BYTES`, independent of `block_range`, chromosome length and line width.
//!
//! Each partition's rows are sorted by `(POS, REF, ALT, POPULATION)` and written to one
//! `allele-freq.chr{CHR}.{group}.br{block_range}.{vcfid}.parquet` file. `vcfid` is the
//! first 16 hex chars of the source VCF's SHA-256, folded out of the conversion read
//! (files are written under a placeholder and renamed once it finalizes).
//! `number_of_records` counts the distinct `(chr, POS, REF, ALT)` keys that produced at
//! least one row; the build recounts it from the written parquet.

use std::{
    cell::RefCell,
    collections::{BTreeSet, HashMap},
    fs::File,
    path::{Path, PathBuf},
    rc::Rc,
    sync::atomic::{AtomicUsize, Ordering},
    sync::mpsc::{Receiver, SyncSender, sync_channel},
    sync::{Arc, Mutex, PoisonError},
};

use arrow_array::{
    ArrayRef, RecordBatch,
    builder::{Float32Builder, Int32Builder, StringBuilder},
};
use arrow_schema::SchemaRef;
use noodles_vcf::{
    self as vcf, header::record::value::map::info::Number, variant::record::AlternateBases as _,
};
use parquet::{arrow::arrow_writer::ArrowWriter, file::properties::WriterProperties};
use sha2::{Digest as _, Sha256};

use crate::{
    chrom::normalize_contig,
    error::{CoreError, CoreResult, invalid_parquet},
    parquet_io::{allele_freq_schema, writer_properties},
    popfield::{Metric, RejectReason, TOTAL_POPULATION, parse_info_field, rejection_reason},
    subcounts,
    variant::{
        alt_is_supported, classify_vt, is_left_trimmable, normalize_allele, right_trim_alleles,
    },
};

/// Maximum number of distinct populations permitted per dataset.
///
/// Enforced authoritatively in the record-merge path (only populations that emit rows
/// count); [`read_header_populations`] lets a caller reject an over-cap dataset up front
/// from the header alone, and `preview`/`lint` surface the headroom.
pub const MAX_POPULATIONS: usize = 512;

/// Maximum population-label length, in characters. Also the ingest-side
/// `ParquetCaps::max_population_len` bound (pinned equal by
/// `population_len_cap_matches_producer`), so producer and consumer agree.
pub(crate) const MAX_POPULATION_LABEL_LEN: usize = 16;

/// Length, in hex chars, of the `vcfid` prefix taken from the source VCF's SHA-256.
const VCFID_HEX_LEN: usize = 16;

/// A distinct variant key: `(chr, POS, REF, ALT)`. The string components are `Arc<str>` so
/// the emit path hands keys over as refcount bumps rather than fresh allocations; the keys
/// are only counted for `numberOfRecords` and never serialized. Per-record scratch only,
/// never accumulated: see [`DistinctKeyCounter`].
pub(crate) type RecordKey = (Arc<str>, i32, Arc<str>, Arc<str>);

/// Counts distinct `(chr, POS, REF, ALT)` keys in memory proportional to the alleles at one
/// `POS`, rather than retaining every key.
///
/// Retaining them costs a couple of hundred bytes per distinct variant to produce a single
/// `u64`, which reaches hundreds of gigabytes on a whole-genome input.
/// [`enforce_chr_pos_order`] rejects a decreasing position, so keys arrive with
/// non-decreasing `POS` within a chromosome and a chromosome never reappears. Two keys can
/// therefore only collide when they share a `POS`, which makes a dedup window scoped to the
/// current `(chr, POS)` equivalent to a set over the whole scan.
#[derive(Default)]
struct DistinctKeyCounter {
    count: u64,
    /// The `(chr, POS)` the window is currently open on.
    at: Option<(Arc<str>, i32)>,
    /// `(REF, ALT)` already seen at that coordinate. Cleared when the coordinate advances.
    seen: BTreeSet<(Arc<str>, Arc<str>)>,
}

impl DistinctKeyCounter {
    /// Offer one emitted allele's key. Counts it unless the same key was already seen at
    /// this `(chr, POS)`.
    fn add(&mut self, key: &RecordKey) {
        let (chr, pos, ref_, alt) = key;
        if !matches!(&self.at, Some((c, p)) if c == chr && p == pos) {
            self.seen.clear();
            self.at = Some((Arc::clone(chr), *pos));
        }
        if self.seen.insert((Arc::clone(ref_), Arc::clone(alt))) {
            self.count += 1;
        }
    }
}

/// Options controlling an aggregated conversion.
#[derive(Debug, Clone)]
pub struct ConvertOptions {
    /// Dataset assembly (`GRCh37` / `GRCh38`), used to cross-check accessions.
    pub assembly: String,
    /// Position block size; a row's partition group is `POS / block_range`
    /// (group `0` when `block_range` is `0`).
    pub block_range: u32,
    /// Build-time minimum allele count: rows whose `AC` is below this are
    /// dropped (rows with no `AC` are exempt). `0` disables the floor.
    pub min_allele_count: u32,
}

/// How much a [`Diagnostic`] should alarm the provider.
///
/// One rule decides it, and `build --strict` depends on it: a [`Severity::Note`] reports a
/// consequence of behaviour the `package.yaml` declares. The `min_allele_count` floor
/// withholds rows because `config.minAlleleCount` asked it to; an aggregated-mode build
/// drops symbolic ALTs because `mode: aggregated` says the dataset carries allele
/// frequencies. A [`Severity::Warning`] says the tool saw something the provider probably
/// did not intend, and nothing in the package asked for it.
///
/// Collapsing the two would make strict mode useless: the floor's tally fires on any real
/// dataset with a non-zero floor, so treating it as a warning would mean a strict build
/// could never enable the floor, which is the main privacy control.
///
/// The same rule makes an ungated `FILTER` a warning rather than a note: no `package.yaml`
/// field declares an intent to publish non-`PASS` calls. A provider whose export
/// accidentally carried VQSR-failed or `AC0` variants would otherwise publish those allele
/// frequencies as authoritative with only an informational line, and `--strict` would pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// An informational tally. Never fails a strict build.
    Note,
    /// A probable mistake. Fails a strict build.
    Warning,
}

/// One non-fatal message from a conversion or preview, tagged with its [`Severity`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Diagnostic {
    /// Whether this is an expected tally or a probable mistake.
    pub severity: Severity,
    /// The human-readable message, rendered by the CLI behind a `note:` / `warning:` prefix.
    pub message: String,
}

impl Diagnostic {
    /// An informational tally — an expected consequence of declared configuration.
    #[must_use]
    pub fn note(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Note,
            message: message.into(),
        }
    }

    /// A probable mistake, worth failing a strict build over.
    #[must_use]
    pub fn warning(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            message: message.into(),
        }
    }
}

/// Record- and allele-level tallies from one VCF scan.
///
/// A drop is a whole input record discarded by where its coordinates or alleles fell. The
/// counts are surfaced so a provider sees "kept N, dropped M" at build and preview time
/// rather than an unexplained shrink; a gVCF or SV-heavy VCF can legitimately lose the large
/// majority of its records. `input_records` is the denominator, and
/// [`Self::dropped_unsupported_contig`], [`Self::dropped_no_supported_alt`],
/// [`Self::dropped_all_rows_withheld`] and [`Self::dropped_no_af`] sum into
/// [`Self::total_dropped`].
///
/// The struct also carries tallies that are not drops ([`Self::non_pass_records`],
/// [`Self::gvcf_reference_blocks`], [`Self::alleles_discarded`],
/// [`Self::total_af_zero_variants`]) and one hint, [`Self::ns_peak`], because they come from
/// the same scan. Per-population no-AF cases are reported separately.
#[derive(Debug, Clone, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DropCounts {
    /// Input records read from the VCF — the denominator for the drop counts.
    pub input_records: u64,
    /// Records dropped because the contig is not a primary assembly contig
    /// (`normalize_contig` skipped it): an unplaced, alt, patch or decoy contig outside
    /// the canonical set.
    pub dropped_unsupported_contig: u64,
    /// Records dropped because no supported ALT remained after filtering: a record
    /// whose ALTs are all symbolic (`<DEL>`, gVCF `<NON_REF>`, …), breakends, `*`
    /// (spanning-deletion), missing, or a literal ALT identical to REF (a
    /// non-variant). The dominant silent-loss class for SV / gVCF input.
    pub dropped_no_supported_alt: u64,
    /// Records carrying a gVCF `<NON_REF>` reference-block ALT (a subset of
    /// [`Self::dropped_no_supported_alt`]). A non-zero value means the input is a
    /// gVCF, not a sites/allele-frequency VCF — the actionable signal that an
    /// otherwise-baffling near-empty output is expected, not a bug.
    pub gvcf_reference_blocks: u64,
    /// Input records whose `FILTER` column is neither `PASS` nor missing (`.`).
    ///
    /// Not a drop, and not part of [`Self::total_dropped`]: the converter never gates on
    /// `FILTER`, so these records are converted like any other. Counted, and surfaced as a
    /// [`Severity::Warning`], so a provider who expected a site-filtered VCF learns that
    /// unfiltered calls were published and `build --strict` refuses to ship them.
    pub non_pass_records: u64,
    /// Split alleles (`(chr, POS, REF, ALT)` variants) whose `Total` row was emitted with
    /// `AF = 0` — the cohort carries no copy of the alternate allele at all.
    ///
    /// Not a drop, and not part of [`Self::total_dropped`]: the row is stored and served
    /// like any other, as a variant present with frequency `0`. Counted, and surfaced as a
    /// [`Severity::Note`], because an export that never removed the sites that became
    /// monomorphic under sample QC publishes every one of them as a found answer and nothing
    /// else in the build says so. Written by stage B, like [`Self::records_emitted`], because
    /// only the emit knows which rows survived.
    pub total_af_zero_variants: u64,
    /// The largest `NS` (samples with data) any converted record carried, when the input
    /// has the field: the number of individuals the VCF observed at its best-covered site.
    ///
    /// A hint, not a statistic of the output: `metadata.numberOfUniqueIndividuals` is a
    /// recommended field the provider must supply, and this is the value the VCF itself
    /// suggests for it when every sample is a distinct individual.
    pub ns_peak: Option<u64>,
    /// ALT alleles discarded from records that survived: symbolic (`<DEL>`), breakend,
    /// `*` spanning-deletion, or a literal ALT equal to REF, on a line that kept at least
    /// one supported ALT.
    ///
    /// Not a drop class, and not part of [`Self::total_dropped`]: the record was published.
    /// A record whose ALTs are all unsupported is counted whole as
    /// [`Self::dropped_no_supported_alt`] and contributes nothing here, and one dropped for
    /// its contig never reaches ALT parsing, so the counters cannot double-count a loss.
    ///
    /// Emits no [`Diagnostic`]: `*` spanning deletions make this non-zero on most real
    /// population VCFs, so warning on it would be noise on every build.
    pub alleles_discarded: u64,
    /// Split alleles that remain non-minimal after [`right_trim_alleles`] because reaching
    /// minimal representation would advance `POS` (a shared leading base with >1 base on
    /// each side).
    ///
    /// Not a drop: the allele is published, in a non-canonical representation, so an
    /// exact-match Beacon query in canonical form misses it. The converter does not
    /// left-trim, because that would move the row out of sorted-`POS` order and possibly
    /// across a `blockRange` boundary. It warns instead, pointing at `bcftools norm`.
    pub alleles_not_left_trimmed: u64,
    /// Records that survived the contig + ALT filters but emitted **no row at all** because
    /// the k-anonymity floor withheld every one of them.
    ///
    /// A drop class, and the one that is otherwise invisible. Without it a manifest can show
    /// an input count, every `discarded.*` at zero, and a smaller output count, with nothing
    /// to account for the difference. The build's own self-check cannot catch that either,
    /// because both sides of that cross-check count outputs.
    ///
    /// Floor-attributable only. A record that emitted nothing because its input carried no
    /// allele frequency is [`Self::dropped_no_af`], not this. Merging the two would report
    /// records as withheld by the floor even on a dataset converted with the floor off,
    /// blaming disclosure control for a gap in the provider's export and pointing them at a
    /// knob that was not involved.
    pub dropped_all_rows_withheld: u64,
    /// Records that survived the contig + ALT filters but emitted **no row at all** because
    /// no population had an allele frequency to emit — the input carried no usable `AF`
    /// (gnomAD, for one, omits `AF`/`AF_XX`/`AF_XY` entirely at its `AN = 0` sites).
    ///
    /// Split from [`Self::dropped_all_rows_withheld`] because the two have opposite
    /// remedies: this one is fixed upstream in the provider's export, that one by changing
    /// `min_allele_count`. A provider cannot tell them apart from a merged total.
    pub dropped_no_af: u64,
    /// Records that emitted at least one row. The complement of the four drop classes.
    pub records_emitted: u64,
}

impl DropCounts {
    /// Total records dropped (sum of all drop classes).
    #[must_use]
    pub fn total_dropped(&self) -> u64 {
        self.dropped_unsupported_contig
            .saturating_add(self.dropped_no_supported_alt)
            .saturating_add(self.dropped_all_rows_withheld)
            .saturating_add(self.dropped_no_af)
    }

    /// The record-level accounting identity: every input record is either dropped by one of
    /// the four drop classes, or it emitted rows.
    ///
    /// This is the invariant that makes silent record loss impossible to ship. It is stated
    /// at record level, because no identity can link [`Self::input_records`] to
    /// `number_of_records`: that counts distinct `(chr, POS, REF, ALT)` alleles, which
    /// multi-allelic splitting inflates and shared loci across a dataset's VCFs deflate.
    #[must_use]
    pub fn accounting_holds(&self) -> bool {
        self.total_dropped().saturating_add(self.records_emitted) == self.input_records
    }

    /// Record a whole input record dropped for having no supported ALT, together with the
    /// gVCF reference-block tally the same record contributes. One call, because a record
    /// counted in the drop class but not in the gVCF hint, or the reverse, is the
    /// unexplained-shrink shape these counters exist to make visible.
    fn drop_no_supported_alt(&mut self, has_non_ref: bool) {
        self.dropped_no_supported_alt += 1;
        self.gvcf_reference_blocks += u64::from(has_non_ref);
    }
}

/// Row-level losses inflicted by the build-time k-anonymity floor.
///
/// Kept out of [`DropCounts`]: a drop discards a whole input record by its coordinates or
/// alleles, whereas suppression withholds individual population rows of a record that is
/// otherwise published. Folding them together would corrupt
/// [`DropCounts::total_dropped`] and the "dropped N of M input records" denominator.
///
/// Both counters matter independently. `rows_below_floor` is the loss the provider asked
/// for. [`Self::rows_collapsed_to_total`] is the one they did not: a population far above
/// the floor is still withheld when a sibling falls below it, because a partial marginal set
/// would let `Total - sum(survivors)` recover the withheld cell.
#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SuppressionCounts {
    /// Population rows never emitted because their `AC` was below `min_allele_count`.
    /// Rows carrying no `AC` are exempt from the floor and are not counted here.
    pub rows_below_floor: u64,
    /// Further population rows removed by the coherence collapse — siblings of a
    /// withheld row, discarded regardless of their own `AC`. Zero when no variant
    /// collapsed. These rows are the non-obvious cost of a non-zero floor.
    pub rows_collapsed_to_total: u64,
    /// Variant/allele groups that lost at least one row to the collapse. A group whose
    /// only surviving row was already `Total` is not counted: nothing was removed.
    pub variants_collapsed_to_total: u64,
}

/// Which drop class a record that emitted **no rows** belongs to: `true` when the
/// k-anonymity floor is what removed them, `false` when the input had no allele frequency
/// to emit in the first place.
///
/// Discriminated on the floor's own per-record tally alone. `rows_below_floor` is
/// incremented only by the floor branch, while `rows_collapsed_to_total` is incremented by
/// the coherence collapse, which the no-AF branch triggers just as the floor does, since a
/// population without `AF` is a partial marginal set. A record emptied by a no-AF collapse
/// with the floor off therefore carries a collapse tally and no floor tally, and belongs to
/// the no-AF class; counting the collapse as the floor's would send the provider to lower a
/// floor that was not on. When the floor took at least one row, the floor is what emptied
/// the record even if a no-AF sibling collapsed too.
///
/// The partition worker and the sequential preview scan both produce this count, and they
/// must agree, or `preview` and `build` report different drop classes for the same input.
/// Both call this function rather than repeating the test.
const fn floor_emptied_the_record(s: &SuppressionCounts) -> bool {
    s.rows_below_floor > 0
}

impl SuppressionCounts {
    /// Fold another tally into this one (per-partition results into the scan total).
    fn add(&mut self, other: Self) {
        self.rows_below_floor = self.rows_below_floor.saturating_add(other.rows_below_floor);
        self.rows_collapsed_to_total = self
            .rows_collapsed_to_total
            .saturating_add(other.rows_collapsed_to_total);
        self.variants_collapsed_to_total = self
            .variants_collapsed_to_total
            .saturating_add(other.variants_collapsed_to_total);
    }
}

/// The result of converting one VCF file.
#[derive(Debug, Clone)]
pub struct ConvertOutput {
    /// Paths of the parquet files written (one per partition), joined onto the
    /// caller-supplied `out_dir`; absolute only if `out_dir` itself is absolute.
    pub parquet_files: Vec<PathBuf>,
    /// Count of distinct `(chr, POS, REF, ALT)` keys in this VCF that produced >=1 row.
    ///
    /// For a multi-VCF dataset this is not the dataset total: a per-population or
    /// per-country split shares loci across files, so summing per-VCF counts double-counts
    /// and the union is not recoverable from the summands. The dataset total is recounted
    /// from the written parquet by [`crate::validate_parquet::validate_parquet_dir`], whose
    /// `(chr, block)` streaming merge is exact in bounded memory. These per-VCF counts then
    /// bound it, `max(per_vcf) <= dataset <= sum(per_vcf)`, with equality on both sides in
    /// the single-VCF case, which keeps the build's cross-check independent of the parquet it
    /// is checking.
    pub number_of_records: u64,
    /// Non-fatal diagnostics (ignored INFO fields, populations with no AF, tallies).
    pub diagnostics: Vec<Diagnostic>,
    /// Per-record drop tally for this VCF (silent-data-loss visibility).
    pub drops: DropCounts,
    /// Row-level k-anonymity losses for this VCF.
    pub suppression: SuppressionCounts,
    /// Total output rows written across every partition of this VCF.
    pub rows_emitted: u64,
    /// Distinct population labels the header declared, sorted — a superset of
    /// [`Self::populations_emitted`] whenever a floor or an absent `AF` withheld rows.
    pub populations_recognized: Vec<String>,
    /// Raw INFO field IDs that looked like AF/AC/AN metrics but did not match the
    /// population grammar, sorted. Not derivable from any counter.
    pub ignored_info_fields: Vec<String>,
    /// Populations carrying `AC`/`AN` but no `AF`, sorted. They emit no rows, and are the
    /// only explanation for a `Total`-collapse when the floor is zero.
    pub populations_without_af: Vec<String>,
    /// The distinct population labels that reached parquet, sorted. Under a non-zero floor
    /// this is a subset of the header's populations, so it, rather than the header, is what
    /// `build` echoes back to the provider.
    pub populations_emitted: Vec<String>,
    /// First 16 hex chars of the source VCF's SHA-256.
    pub vcfid: String,
    /// Full 64-hex SHA-256 of the source VCF — the same digest the manifest records
    /// for the file ([`Self::vcfid`] is its first 16 chars). Surfaced so the build
    /// orchestrator can reuse it for the manifest instead of hashing the file again.
    pub source_sha256: String,
    /// Byte length of the source VCF (the manifest's `size` for the file), returned
    /// alongside [`Self::source_sha256`] so it, too, need not be recomputed.
    pub source_size: u64,
}

/// Which per-population metric a header INFO field carries, joined with its
/// population key (the parsed [`crate::popfield::InfoField`] plus the raw ID).
struct PopField {
    /// The raw INFO field ID as it appears in the VCF (e.g. `AF_FI_M`).
    id: String,
    /// The statistic this field contributes.
    metric: Metric,
    /// The population key (`Total`, `FI`, `FI_M`, ...), interned as `Arc<str>` so each
    /// emitted row clones the refcount rather than re-allocating the label.
    population: Arc<str>,
    /// The header-declared `Number` for this field, captured once at header-parse time so
    /// the per-record value lookup needs no header-map lookup. That lookup runs dozens of
    /// times per variant.
    number: Number,
}

/// A single emitted output row, before partitioning and sorting. `chr` is not stored: a row
/// exists only inside its `(chr, block)` partition, and the chromosome lives in the file
/// name rather than in the parquet data, so the partition is keyed off the [`Extracted`]
/// record.
///
/// The string fields are `Arc<str>`, so a variant's per-population rows share one allocation
/// each for `ref_` and `alt`, and `population` is interned from the scan-stable [`PopField`]
/// set: a refcount bump per row instead of a fresh `String`.
struct OutRow {
    pos: i32,
    ref_: Arc<str>,
    alt: Arc<str>,
    vt: &'static str,
    population: Arc<str>,
    af: f32,
    ac: Option<i32>,
    ac_hom: Option<i32>,
    ac_het: Option<i32>,
    ac_hemi: Option<i32>,
    an: Option<i32>,
}

/// Per-(allele, population) accumulator while scanning one record's INFO fields.
#[derive(Default)]
struct Stats {
    af: Option<f32>,
    ac: Option<i32>,
    ac_hom: Option<i32>,
    ac_het: Option<i32>,
    ac_hemi: Option<i32>,
    an: Option<i32>,
}

/// Convert an aggregated VCF file to partitioned parquet under `out_dir`.
///
/// Implements every aggregated-mode processing rule: header `Number` validation,
/// contig normalization, multi-allelic splitting indexed by the ALT's original
/// line index, the ALT-filter-before-POS-check ordering, per-record value
/// validation (`AF <= 1`, `AC <= AN`, non-negativity, list-length), the
/// no-AF-synthesis rule, the build-time `min_allele_count` floor, and the
/// population bounds. Each split allele is stored uppercased, whitespace-trimmed, and
/// right-trimmed to its `POS`-preserving minimal form (see
/// [`crate::variant::right_trim_alleles`]).
///
/// # Errors
///
/// Returns [`CoreError::InvalidParquet`] when the VCF violates a hard rule
/// (no `AF` in header, a `Number` mismatch, a malformed/out-of-domain value,
/// `POS = 0` with a literal ALT, an unknown contig, a re-appearing chromosome,
/// a decreasing position, or exceeding the population cap), and
/// [`CoreError::Io`] for I/O failures.
pub fn convert_vcf(
    path: &Path,
    out_dir: &Path,
    opts: &ConvertOptions,
) -> CoreResult<ConvertOutput> {
    convert_vcf_with_worker_pool(path, out_dir, opts, worker_pool_size())
}

/// Like [`convert_vcf`], but with an explicit worker-pool size — a thin single-VCF
/// shortcut over [`convert_vcf_group`].
///
/// The whole conversion runs on `worker_pool` worker threads: the cheap stage A
/// (contig/POS normalize + ordering + batching) on the calling thread, then the heavy
/// stage-B emit + sort + parquet (Arrow + zstd) encode + write across the pool, per
/// independent partition. [`convert_vcf`] passes one worker per CPU. `worker_pool` is
/// clamped to at least 1.
///
/// # Errors
///
/// Same as [`convert_vcf`].
pub fn convert_vcf_with_worker_pool(
    path: &Path,
    out_dir: &Path,
    opts: &ConvertOptions,
    worker_pool: usize,
) -> CoreResult<ConvertOutput> {
    let sources = [path.to_path_buf()];
    convert_vcf_group(&sources, out_dir, opts, worker_pool, &|_| {}, &|_, _| {})?
        .pop()
        .unwrap_or_else(|| {
            // Unreachable: one source always yields exactly one result.
            Err(CoreError::InternalError {
                detail: "convert_vcf_group returned no result for one source".to_string(),
            })
        })
}

/// Convert a group of VCFs through one shared worker pool spanning the whole build, so a
/// finished VCF's share of the cores is reused by the others. A per-VCF pool, or a static
/// split of cores between jobs, idles cores when the VCFs are unequal in size.
///
/// A few producer threads work-steal the source list. Each reads a VCF and runs stage A,
/// stamping every partition batch with the VCF's index and context and feeding the shared
/// pool of `pool_size` workers. Worker results are merged per VCF, and one result is
/// returned per source, in source order. `on_start(idx)` fires as each VCF is picked up, and
/// `on_bytes(idx, n)` reports `n` freshly-read compressed on-disk bytes of VCF `idx` as its
/// conversion streams. `on_bytes` is called from the producer threads, so it must be cheap
/// and `Sync`. It covers the conversion read only, not the separate source-digest pass.
///
/// # Errors
///
/// Returns [`CoreError`] only for build-wide setup failures (output dir / parquet writer
/// config). Per-VCF failures are the inner `CoreResult`s.
pub fn convert_vcf_group(
    sources: &[PathBuf],
    out_dir: &Path,
    opts: &ConvertOptions,
    pool_size: usize,
    on_start: &(dyn Fn(usize) + Sync),
    on_bytes: &(dyn Fn(usize, u64) + Sync),
) -> CoreResult<Vec<CoreResult<ConvertOutput>>> {
    #[expect(
        clippy::disallowed_methods,
        reason = "operator-chosen output directory for converted parquet; the tool runs as the operator"
    )]
    std::fs::create_dir_all(out_dir)?;
    let schema = allele_freq_schema();
    let props = writer_properties()
        .map_err(|e| invalid_parquet(format!("parquet writer setup failed: {e}")))?;
    let n = sources.len();
    let pool_size = pool_size.max(1);
    // A few producers overlap the per-VCF digest + read while the pool stays fed; they
    // are mostly I/O / back-pressure bound, so they need not match the worker count.
    let producer_count = n.min(pool_size).max(1);
    // One channel per worker rather than one shared behind a mutex: a partition arrives as
    // several byte-bounded batches that must all reach the same worker, which owns that
    // partition's open `ArrowWriter`. `route_partition` pins the mapping, and a private FIFO
    // channel keeps a partition's batches in order without locking the writer.
    let (txs, rxs): (Vec<_>, Vec<_>) = (0..pool_size)
        .map(|_| sync_channel::<PartitionBatch>(WORKER_QUEUE_DEPTH))
        .unzip();
    let block_range = opts.block_range;
    let next = AtomicUsize::new(0);
    let metas: Vec<ProducerSlot> = (0..n).map(|_| Mutex::new(None)).collect();
    // Group the two progress callbacks so the producer plumbing passes one value (keeping
    // the per-thread helper under clippy's argument-count limit); both stay `Sync`.
    let progress = ProgressHooks { on_start, on_bytes };

    let (all_results, worker_panicked) = std::thread::scope(
        |scope| -> (Vec<(usize, usize, CoreResult<PartitionOutput>)>, bool) {
            // Borrow the shared writer config once: each worker closure is `move` (it owns
            // its receiver), so capturing `schema`/`props` by value would move them N times.
            let writer_cfg = WriterConfig {
                out_dir,
                block_range,
                schema: &schema,
                props: &props,
            };
            let workers: Vec<_> = rxs
                .into_iter()
                .map(|rx| scope.spawn(move || process_partitions(&rx, opts, writer_cfg)))
                .collect();
            // Capture shared references (Copy) so each producer closure borrows the
            // work-stealing index + result slots rather than trying to move them.
            let next = &next;
            let metas = &metas[..];
            let producers: Vec<_> = (0..producer_count)
                .map(|_| {
                    let txs = txs.clone();
                    scope.spawn(move || {
                        producer_loop(next, sources, opts, block_range, metas, progress, txs);
                    })
                })
                .collect();
            drop(txs);
            for p in producers {
                let _ = p.join();
            }
            // All producers done -> every sender dropped -> the pool drains and ends.
            let mut all = Vec::new();
            let mut panicked = false;
            for w in workers {
                match w.join() {
                    Ok(mut part) => all.append(&mut part),
                    Err(_) => panicked = true,
                }
            }
            (all, panicked)
        },
    );

    if worker_panicked {
        return Ok((0..n)
            .map(|_| {
                Err(CoreError::InternalError {
                    detail: "parquet worker thread panicked".to_string(),
                })
            })
            .collect());
    }

    // Route worker results to their VCF, then merge each VCF independently.
    let mut grouped: Vec<Vec<(usize, CoreResult<PartitionOutput>)>> =
        (0..n).map(|_| Vec::new()).collect();
    for (vcf_idx, seq, result) in all_results {
        grouped[vcf_idx].push((seq, result));
    }
    let mut outputs = Vec::with_capacity(n);
    for (i, slot) in metas.into_iter().enumerate() {
        let result = match slot.into_inner().unwrap_or_else(PoisonError::into_inner) {
            Some(Ok((data, scan_err))) => {
                merge_partitions(std::mem::take(&mut grouped[i]), scan_err).and_then(
                    |mut merged| {
                        // The workers wrote this VCF's files under the placeholder vcfid,
                        // because the real one is not known until the digest finalizes. Both
                        // the paths and the real vcfid are in hand here, so rename the files
                        // into their final names before the output, and the caller's
                        // self-check that globs those names, sees them.
                        rename_partition_files(
                            &mut merged.parquet_files,
                            &placeholder_vcfid(i),
                            &data.vcfid,
                        )?;
                        Ok(assemble_convert_output(data, merged))
                    },
                )
            }
            Some(Err(setup_err)) => Err(setup_err),
            None => Err(CoreError::InternalError {
                detail: "VCF was never produced".to_string(),
            }),
        };
        outputs.push(result);
    }
    Ok(outputs)
}

/// A per-VCF producer outcome slot. `Err` is a setup failure, raised before any batch was
/// sent; `Ok((data, scan_err))` carries the per-VCF metadata and the producer-side scan
/// error. Written by the producer that handled the VCF, read by the per-VCF merge.
type ProducerSlot = Mutex<Option<CoreResult<(ProducerData, Option<CoreError>)>>>;

/// The producer-thread progress callbacks, grouped so the per-producer plumbing forwards one
/// `Copy` value. Both are invoked from producer threads, so both must be cheap and `Sync`:
/// `on_start(idx)` as a VCF is picked up, `on_bytes(idx, n)` per `n` freshly-read compressed
/// bytes of source `idx`.
#[derive(Clone, Copy)]
struct ProgressHooks<'a> {
    on_start: &'a (dyn Fn(usize) + Sync),
    on_bytes: &'a (dyn Fn(usize, u64) + Sync),
}

/// One producer thread: work-steal VCFs off `next` and convert each via
/// [`produce_one_vcf`], recording the outcome in its slot.
fn producer_loop(
    next: &AtomicUsize,
    sources: &[PathBuf],
    opts: &ConvertOptions,
    block_range: u32,
    metas: &[ProducerSlot],
    progress: ProgressHooks<'_>,
    txs: Vec<SyncSender<PartitionBatch>>,
) {
    loop {
        let i = next.fetch_add(1, Ordering::Relaxed);
        if i >= sources.len() {
            break;
        }
        (progress.on_start)(i);
        let outcome = produce_one_vcf(&sources[i], i, opts, block_range, progress.on_bytes, &txs);
        *metas[i].lock().unwrap_or_else(PoisonError::into_inner) = Some(outcome);
    }
    // Drop this producer's sender clones so that, once every producer finishes, each
    // worker's channel closes and the pool drains and exits. `txs` is taken by value
    // because this is where it is consumed.
    drop(txs);
}

/// The producer-side per-VCF state the merge needs but the workers do not compute: the
/// source digest, the vcfid, the header warnings, and the drop tally.
struct ProducerData {
    source_sha256: String,
    source_size: u64,
    vcfid: String,
    header_diagnostics: Vec<Diagnostic>,
    drops: DropCounts,
    /// Raw INFO IDs that looked like AF/AC/AN fields but did not parse.
    ignored_info_fields: Vec<String>,
    /// Distinct population labels the header declared (incl. AC/AN-only ones).
    populations_recognized: Vec<String>,
}

/// A [`std::io::Read`] adapter that reports the byte count of every non-empty read to a
/// callback, driving byte-level conversion progress. Wrapping the file below the optional
/// bgzf decoder means the callback observes compressed on-disk bytes, which is what a
/// percentage-of-file-size progress bar needs. The final EOF read does not fire the callback.
struct CountingReader<R, F> {
    inner: R,
    on_read: F,
}

impl<R, F> CountingReader<R, F> {
    fn new(inner: R, on_read: F) -> Self {
        Self { inner, on_read }
    }
}

impl<R: std::io::Read, F: FnMut(u64)> std::io::Read for CountingReader<R, F> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            (self.on_read)(n as u64);
        }
        Ok(n)
    }
}

/// The running SHA-256 of a source VCF, folded into the conversion read so the file is not
/// hashed in a second pass. Shared through `Rc<RefCell<…>>` between the [`DigestingReader`]
/// in the reader stack and the producer that finalizes it. The read is single-threaded per
/// VCF, so no lock is needed.
struct DigestState {
    hasher: Sha256,
    bytes: u64,
}

/// A [`std::io::Read`] adapter that folds every byte into a shared [`DigestState`] as it is
/// read, so the source VCF's SHA-256 (its `vcfid` and manifest digest) comes for free from
/// the conversion read instead of a separate full-file pass.
///
/// Sits at the bottom of the reader stack, wrapping the raw `File` below the bgzf decoder,
/// so it hashes the compressed on-disk bytes. The reader consumes the whole file, since its
/// final buffer refill reads to EOF, and the producer still drains any unread tail before
/// finalizing, so the digest covers the file even if a future reader stops short.
struct DigestingReader<R> {
    inner: R,
    state: Rc<RefCell<DigestState>>,
}

impl<R: std::io::Read> std::io::Read for DigestingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            let mut s = self.state.borrow_mut();
            s.hasher.update(&buf[..n]);
            s.bytes += n as u64;
        }
        Ok(n)
    }
}

/// Finalize a [`DigestState`] to a 64-char lowercase hex string, guaranteeing it covered the
/// whole file: if the reader stopped before EOF, the unread tail is read and hashed here.
///
/// # Errors
///
/// Returns [`CoreError::Io`] if the tail cannot be read.
fn finalize_source_digest(
    source: &Path,
    state: Rc<RefCell<DigestState>>,
    source_size: u64,
) -> CoreResult<(String, u64)> {
    let mut state = Rc::try_unwrap(state)
        .map_or_else(|rc| rc.borrow().clone_for_finalize(), RefCell::into_inner);
    if state.bytes < source_size {
        // Safety net: the reader left a tail unread. Hash it directly from the file.
        use std::io::{Read as _, Seek as _, SeekFrom};
        let mut f = File::open(source)?;
        f.seek(SeekFrom::Start(state.bytes))?;
        let mut buf = vec![0u8; 128 * 1024];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            state.hasher.update(&buf[..n]);
            state.bytes += n as u64;
        }
    }
    Ok((crate::util::sha256_hex(state.hasher), state.bytes))
}

impl DigestState {
    /// Clone the running hash so the caller can finalize it while another `Rc` clone (the
    /// reader, not yet dropped) still holds the shared state. Only used on the cold path.
    fn clone_for_finalize(&self) -> Self {
        Self {
            hasher: self.hasher.clone(),
            bytes: self.bytes,
        }
    }
}

/// The compression `vcf::io::reader::Builder::build_from_path` selects for `source`: by
/// extension, `gz` and `bgz` mean bgzf and everything else is uncompressed. Spelled out here
/// so [`open_reader`] can wrap the file in a [`CountingReader`] and still pick the same
/// codec. `preflight_vcf_format` has already rejected an extension and content mismatch.
fn vcf_compression_for(source: &Path) -> vcf::io::CompressionMethod {
    match source.extension().and_then(|e| e.to_str()) {
        Some("gz" | "bgz") => vcf::io::CompressionMethod::Bgzf,
        _ => vcf::io::CompressionMethod::None,
    }
}

/// Open a VCF reader that counts every compressed on-disk byte read, for progress, and, when
/// `digest` is `Some`, folds those same bytes into a running SHA-256 below the bgzf decoder,
/// so a producer gets the source digest without a separate full-file pass. `digest = None`
/// gives a plain counting reader.
///
/// Every underlying file read is reported to `on_read` as compressed on-disk bytes; see
/// [`CountingReader`]. Equivalent to building the reader from the path, except that the
/// compression is selected explicitly so a wrapped reader can be used.
///
/// # Errors
///
/// Returns [`CoreError`] if the file cannot be opened or the reader cannot be built.
fn open_reader<'a>(
    source: &Path,
    on_read: impl FnMut(u64) + 'a,
    digest: Option<Rc<RefCell<DigestState>>>,
) -> CoreResult<vcf::io::Reader<Box<dyn std::io::BufRead + 'a>>> {
    let file = File::open(source)?;
    let builder = vcf::io::reader::Builder::default().set_compression_method(
        // Detect compression before the file is wrapped: `vcf_compression_for` reads the
        // path, which the digesting wrapper would otherwise obscure.
        vcf_compression_for(source),
    );
    let reader = match digest {
        Some(state) => {
            let digesting = DigestingReader { inner: file, state };
            builder.build_from_reader(CountingReader::new(digesting, on_read))?
        }
        None => builder.build_from_reader(CountingReader::new(file, on_read))?,
    };
    Ok(reader)
}

/// Read one VCF on the calling producer thread: preflight, digest, header, recognized
/// fields, then stage A over every record, batching survivors into the shared pool through a
/// clone of `tx` tagged with `vcf_idx`. Returns the per-VCF [`ProducerData`] plus the
/// producer-side scan error, if any. An `Err` is a setup failure raised before any batch was
/// sent.
#[expect(
    clippy::string_slice,
    reason = "a SHA-256 hex digest is ASCII, so every byte offset is a char boundary"
)]
fn produce_one_vcf(
    source: &Path,
    vcf_idx: usize,
    opts: &ConvertOptions,
    block_range: u32,
    on_bytes: &(dyn Fn(usize, u64) + Sync),
    txs: &[SyncSender<PartitionBatch>],
) -> CoreResult<(ProducerData, Option<CoreError>)> {
    preflight_vcf_format(source)?;
    // The source digest is folded into the conversion read below, so the file is not hashed
    // in a second pass. Its first 16 hex characters are the `vcfid` embedded in every
    // partition file name, and those are not known until the read completes. The files are
    // written under a per-VCF placeholder vcfid and renamed once the digest finalizes, in
    // `convert_vcf_group`, where both the paths and the digest are in hand.
    let source_size = std::fs::metadata(source)?.len();
    let placeholder = placeholder_vcfid(vcf_idx);
    let digest = Rc::new(RefCell::new(DigestState {
        hasher: Sha256::new(),
        bytes: 0,
    }));
    let mut reader = open_reader(source, |n| on_bytes(vcf_idx, n), Some(Rc::clone(&digest)))?;
    let header = reader.read_header()?;
    let mut header_diagnostics = Vec::new();
    let scan = build_pop_fields(&header, &mut header_diagnostics)?;
    let populations_recognized = recognized_populations(&scan.pop_fields);
    let ignored_info_fields = scan.ignored_info_fields;
    let pop_fields = scan.pop_fields;
    let ctx = Arc::new(VcfContext {
        pop_fields,
        vcfid: placeholder,
    });
    let mut batcher =
        PartitionBatcher::new(vcf_idx, ctx, block_range, MAX_BATCH_BYTES, txs.to_vec());
    let mut drops = DropCounts::default();
    let scan_err = produce_vcf_partitions(&mut reader, opts, &mut batcher, &mut drops);
    drop(batcher);
    // Drop the reader first, so its `Rc` clone of the digest state is released, then
    // finalize, draining any unread tail so the digest covers the whole file.
    drop(reader);
    let (source_sha256, source_size) = finalize_source_digest(source, digest, source_size)?;
    let vcfid = source_sha256[..VCFID_HEX_LEN].to_owned();
    Ok((
        ProducerData {
            source_sha256,
            source_size,
            vcfid,
            header_diagnostics,
            drops,
            ignored_info_fields,
            populations_recognized,
        },
        scan_err,
    ))
}

/// The per-VCF placeholder `vcfid` a partition file is written under, before the source
/// digest is known. Sixteen chars (matching a real `vcfid`'s length), unique per VCF, and
/// distinguishable from any real hex digest by its `pending` prefix.
fn placeholder_vcfid(vcf_idx: usize) -> String {
    format!("pending{vcf_idx:09x}")
}

/// Drive the shared per-record extraction over `reader`: read each VCF record, run
/// `extract_record` (contig/POS-order enforcement + drop accounting), and hand each
/// surviving [`Extracted`] record to `on_record`.
///
/// Shared by the build producer ([`produce_vcf_partitions`]) and the [`preview_vcf`] dry
/// run. They differ only in the per-record action: the build pushes into a partition batch,
/// while preview emits into a reused scratch and counts. Keeping the action a callback means
/// preview is not coupled to the writing pipeline. Stops at the first error.
///
/// # Errors
/// Propagates a read error, an `extract_record` error, or an `on_record` error.
fn drive_records<R, F>(
    reader: &mut vcf::io::Reader<R>,
    opts: &ConvertOptions,
    pop_fields: &[PopField],
    drops: &mut DropCounts,
    mut on_record: F,
) -> CoreResult<()>
where
    R: std::io::BufRead,
    F: FnMut(Extracted) -> CoreResult<()>,
{
    let mut current_chr: Option<String> = None;
    let mut last_pos_in_chr: Option<i32> = None;
    let mut seen_chrs: BTreeSet<String> = BTreeSet::new();
    // One record buffer for the whole scan. `extract_record` borrows it and copies out only
    // what survives, so the read buffer is reused instead of allocated per line.
    let mut record = vcf::Record::default();
    loop {
        if reader.read_record(&mut record)? == 0 {
            break;
        }
        if let Some(ex) = extract_record(
            &record,
            opts,
            pop_fields,
            &mut current_chr,
            &mut last_pos_in_chr,
            &mut seen_chrs,
            drops,
        )? {
            on_record(ex)?;
        }
    }
    Ok(())
}

/// Stage A over one VCF: read every record, extract survivors, and batch them by
/// partition into `batcher` (which feeds the worker pool). The per-VCF ordering state is
/// local. Returns the first producer-side error (a stage-A validation error or a read
/// error), if any; the open partition is always flushed first so an earlier (lower-seq)
/// validation error in it is not lost.
fn produce_vcf_partitions<R: std::io::BufRead>(
    reader: &mut vcf::io::Reader<R>,
    opts: &ConvertOptions,
    batcher: &mut PartitionBatcher,
    drops: &mut DropCounts,
) -> Option<CoreError> {
    let pop_fields = Arc::clone(&batcher.ctx);
    let mut scan_err = drive_records(reader, opts, &pop_fields.pop_fields, drops, |ex| {
        batcher.push(ex)
    })
    .err();
    if let Err(e) = batcher.flush() {
        scan_err.get_or_insert(e);
    }
    scan_err
}

/// Build a [`ConvertOutput`] from the producer's per-VCF data and the merged partition
/// results: the header warnings first, then the no-AF and drop warnings.
fn assemble_convert_output(data: ProducerData, merged: MergedPartitions) -> ConvertOutput {
    let mut diagnostics = data.header_diagnostics;
    let mut drops = data.drops;
    finish_scan_diagnostics(
        &mut diagnostics,
        &mut drops,
        &StageBTallies {
            records_emitted: merged.records_emitted,
            records_all_rows_withheld: merged.records_all_rows_withheld,
            records_no_af: merged.records_no_af,
            number_of_records: merged.number_of_records,
            total_af_zero_variants: merged.total_af_zero_variants,
        },
        &merged.suppression,
        &merged.no_af,
    );
    let populations_without_af: Vec<String> = merged.no_af.iter().cloned().collect();
    ConvertOutput {
        parquet_files: merged.parquet_files,
        number_of_records: merged.number_of_records,
        diagnostics,
        drops,
        suppression: merged.suppression,
        rows_emitted: merged.rows_emitted,
        populations_recognized: data.populations_recognized,
        ignored_info_fields: data.ignored_info_fields,
        populations_without_af,
        populations_emitted: sorted_labels(merged.populations_emitted),
        vcfid: data.vcfid,
        source_sha256: data.source_sha256,
        source_size: data.source_size,
    }
}

/// The merged result of the worker pool: the ordered file list plus the scan-wide
/// accumulators, which are computed per partition rather than by the producer.
struct MergedPartitions {
    parquet_files: Vec<PathBuf>,
    number_of_records: u64,

    no_af: BTreeSet<String>,
    /// Scan-wide k-anon losses, folded from every partition.
    suppression: SuppressionCounts,
    /// Total rows written across every partition.
    rows_emitted: u64,
    /// Distinct populations that reached parquet, gathered for the cap check.
    populations_emitted: BTreeSet<Arc<str>>,
    /// Records that emitted >=1 row, across every partition.
    records_emitted: u64,
    /// Records whose every population row was withheld by the floor, across every partition.
    records_all_rows_withheld: u64,
    /// Records that emitted nothing for want of an allele frequency, across every partition.
    records_no_af: u64,
    /// Variants whose `Total` row carries `AF = 0`, across every partition.
    total_af_zero_variants: u64,
}

/// Fold the workers' per-partition results into the final output, in partition (`seq`)
/// order so the lowest-positioned error wins and the per-dataset population cap fires
/// at the same partition it would sequentially. A producer (`scan_err`) error is at the
/// highest position (after every dispatched partition), so it is reported only when no
/// partition itself failed.
fn merge_partitions(
    mut results: Vec<(usize, CoreResult<PartitionOutput>)>,
    scan_err: Option<CoreError>,
) -> CoreResult<MergedPartitions> {
    results.sort_by_key(|(seq, _)| *seq);
    let mut files: Vec<(String, u64, PathBuf)> = Vec::new();
    let mut distinct_variants: u64 = 0;
    let mut populations_seen: BTreeSet<Arc<str>> = BTreeSet::new();
    let mut no_af: BTreeSet<String> = BTreeSet::new();
    let mut suppression = SuppressionCounts::default();
    let mut rows_emitted: u64 = 0;
    let mut records_emitted: u64 = 0;
    let mut records_all_rows_withheld: u64 = 0;
    let mut records_no_af: u64 = 0;
    let mut total_af_zero_variants: u64 = 0;
    for (_, result) in results {
        let out = result?;
        // Partitions are disjoint by `(chr, POS-block)`, and two equal keys share a POS, so
        // a key lives in exactly one partition and summing cannot double-count.
        distinct_variants = distinct_variants.saturating_add(out.distinct_variants);
        no_af.extend(out.no_af);
        suppression.add(out.suppression);
        rows_emitted = rows_emitted.saturating_add(out.rows_written);
        records_emitted = records_emitted.saturating_add(out.records_emitted);
        records_all_rows_withheld =
            records_all_rows_withheld.saturating_add(out.records_all_rows_withheld);
        records_no_af = records_no_af.saturating_add(out.records_no_af);
        total_af_zero_variants = total_af_zero_variants.saturating_add(out.total_af_zero_variants);
        for pop in out.pops {
            record_population(&mut populations_seen, pop)?;
        }
        if let Some(path) = out.path {
            files.push((out.chr, out.group, path));
        }
    }
    // A producer-side error outranks nothing that was dispatched, so it is reported last.
    if let Some(e) = scan_err {
        return Err(e);
    }
    // Deterministic (chr, group) order; encode-completion order is irrelevant.
    files.sort_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1)));
    Ok(MergedPartitions {
        number_of_records: distinct_variants,
        parquet_files: files.into_iter().map(|(_, _, path)| path).collect(),
        no_af,
        suppression,
        rows_emitted,
        populations_emitted: populations_seen,
        records_emitted,
        records_all_rows_withheld,
        records_no_af,
        total_af_zero_variants,
    })
}

/// Record one emitted population label in a scan-wide set, enforcing the per-dataset
/// [`MAX_POPULATIONS`] cap as each new label is first seen. Shared by the converter's
/// partition merge and the [`preview_vcf`] dry run so both fail at the same point with the
/// same message.
///
/// # Errors
///
/// Returns [`CoreError::InvalidParquet`] when `pop` is the label that exceeds the cap.
fn record_population(seen: &mut BTreeSet<Arc<str>>, pop: Arc<str>) -> CoreResult<()> {
    if seen.insert(pop) && seen.len() > MAX_POPULATIONS {
        return Err(invalid_parquet(format!(
            "dataset exceeds the {MAX_POPULATIONS}-population cap"
        )));
    }
    Ok(())
}

/// Complete a scan's record-level accounting, then push everything it diagnoses, in the
/// order both the build ([`assemble_convert_output`]) and the [`preview_vcf`] dry run report
/// it, so the two cannot drift apart.
///
/// The stage-B-only tallies are written here rather than by the caller, because only stage B
/// knows whether a surviving record emitted a row: the producer's tally is incomplete until
/// now, and every diagnostic below reads `drops`.
fn finish_scan_diagnostics(
    diags: &mut Vec<Diagnostic>,
    drops: &mut DropCounts,
    tallies: &StageBTallies,
    suppression: &SuppressionCounts,
    no_af: &BTreeSet<String>,
) {
    drops.records_emitted = tallies.records_emitted;
    drops.dropped_all_rows_withheld = tallies.records_all_rows_withheld;
    drops.dropped_no_af = tallies.records_no_af;
    drops.total_af_zero_variants = tallies.total_af_zero_variants;
    debug_assert!(
        drops.accounting_holds(),
        "record accounting broken: {drops:?}"
    );
    for pop in no_af {
        diags.push(Diagnostic::warning(format!(
            "population {pop} has AC/AN but no AF; no rows emitted for it"
        )));
    }
    push_suppression_diagnostics(diags, suppression);
    push_non_pass_diagnostic(diags, drops);
    push_total_af_zero_diagnostic(diags, drops, tallies.number_of_records);
    push_left_trim_diagnostic(diags, drops);
    push_drop_diagnostics(diags, drops);
}

/// The scan-wide counts only stage B can produce — folded from every partition by the
/// build, accumulated by the sequential [`preview_vcf`] dry run — handed to
/// [`finish_scan_diagnostics`] as one named value so the two callers cannot pass the same
/// five counters in two different orders.
struct StageBTallies {
    /// Records that emitted at least one row.
    records_emitted: u64,
    /// Records whose every population row the k-anonymity floor withheld.
    records_all_rows_withheld: u64,
    /// Records that emitted nothing for want of an allele frequency.
    records_no_af: u64,
    /// Distinct `(chr, POS, REF, ALT)` keys that emitted a row: the denominator of the
    /// `Total AF = 0` note.
    number_of_records: u64,
    /// Variants whose `Total` row carries `AF = 0`.
    total_af_zero_variants: u64,
}

/// Push the k-anonymity suppression tally onto `diags` as [`Severity::Note`]s. The floor is
/// what the provider configured, so it must never fail a strict build. Two messages, because
/// the two losses have different causes and remedies: the floor is what the provider asked
/// for, the collapse is the coherence cost they did not. No-op when the floor withheld
/// nothing.
fn push_suppression_diagnostics(diags: &mut Vec<Diagnostic>, sup: &SuppressionCounts) {
    if sup.rows_below_floor > 0 {
        diags.push(Diagnostic::note(format!(
            "the min_allele_count floor suppressed {} population row(s) whose AC was below it",
            sup.rows_below_floor,
        )));
    }
    if sup.variants_collapsed_to_total > 0 {
        diags.push(Diagnostic::note(format!(
            "k-anonymity coherence collapsed {} variant(s) to their Total row only, \
             removing {} further population row(s) regardless of their own AC: \
             a withheld population forces its siblings to be withheld too",
            sup.variants_collapsed_to_total, sup.rows_collapsed_to_total,
        )));
    }
}

/// Push the non-minimal-allele tally onto `diags` as a [`Severity::Warning`] when any split
/// allele still shares a leading base after the right-trim.
///
/// A warning rather than a note: no package field declares an intent to publish alleles in a
/// non-canonical representation, and the consequence is a Beacon false negative. An
/// exact-match query in canonical `referenceBases` and `alternateBases` form returns no
/// variant rather than an error, so nobody downstream notices. No-op for a left-aligned VCF,
/// so a conforming provider never sees it.
fn push_left_trim_diagnostic(diags: &mut Vec<Diagnostic>, drops: &DropCounts) {
    if drops.alleles_not_left_trimmed == 0 {
        return;
    }
    diags.push(Diagnostic::warning(format!(
        "{} allele(s) are not left-aligned: REF and ALT still share a leading base, so the \
         stored representation is not minimal and an exact-match Beacon query will miss them; \
         run `bcftools norm -m -any -f <reference.fa>` on the VCF before building \
         (the converter right-trims split alleles, but left-trimming would advance POS)",
        drops.alleles_not_left_trimmed,
    )));
}

/// Push the non-PASS `FILTER` tally onto `diags` as a [`Severity::Warning`] when any input
/// record carried a filter label: the records are kept, and nothing in the package asked for
/// that. Separate from [`push_drop_diagnostics`], because the count is a quality signal
/// rather than a loss report and must surface even for a VCF that dropped nothing.
///
/// No-op for a wholly `PASS` or `.` input, which is every well-formed aggregated export, so
/// the warning costs a conforming provider nothing. See [`Severity`] for why it is not a
/// note: a note never fails a strict build, and publishing allele frequencies for calls the
/// provider's own pipeline rejected is what `--strict` exists to catch.
fn push_non_pass_diagnostic(diags: &mut Vec<Diagnostic>, drops: &DropCounts) {
    if drops.non_pass_records == 0 {
        return;
    }
    diags.push(Diagnostic::warning(format!(
        "{} of {} input records have a FILTER other than PASS and were converted anyway: \
         the converter does not gate on FILTER; pre-filter the VCF if that is not intended",
        drops.non_pass_records, drops.input_records,
    )));
}

/// Push the `Total AF = 0` tally onto `diags` as a [`Severity::Note`] when any emitted
/// variant has no carrier in the whole cohort; `variants` is the distinct-variant count it
/// is measured against.
///
/// A note, not a warning: the export states the fact explicitly as `AC = 0` and `AF = 0`,
/// the converter stores it faithfully, and a site that became monomorphic under sample QC is
/// a true statement about the cohort. It is surfaced because the consequence is easy to
/// miss, since the node answers such a site as a variant that is present with frequency `0`,
/// and because the remedy is one filter upstream of `build`. No-op when every variant has a
/// carrier.
fn push_total_af_zero_diagnostic(diags: &mut Vec<Diagnostic>, drops: &DropCounts, variants: u64) {
    if drops.total_af_zero_variants == 0 {
        return;
    }
    diags.push(Diagnostic::note(format!(
        "{} of {variants} emitted variant(s) have Total AF=0: no copy of the alternate \
         allele in the whole cohort, and are stored and served like any other row, as a \
         variant present with frequency 0; remove monomorphic sites before building \
         (`bcftools view -c 1`) if that is not intended",
        drops.total_af_zero_variants,
    )));
}

/// Push the kept-and-dropped summary onto `diags` as a [`Severity::Note`], plus a
/// [`Severity::Warning`] when the input is a gVCF, so the CLI text output and the build log
/// show silent data loss without reading the structured [`DropCounts`]. No-op when nothing
/// was dropped.
fn push_drop_diagnostics(diags: &mut Vec<Diagnostic>, drops: &DropCounts) {
    let dropped = drops.total_dropped();
    if dropped == 0 {
        return;
    }
    diags.push(Diagnostic::note(format!(
        "dropped {dropped} of {} input records ({} non-primary contig, {} no supported ALT; \
         symbolic/SV/gVCF/missing, {} no allele frequency in the input, {} every population \
         row withheld by the k-anonymity floor)",
        drops.input_records,
        drops.dropped_unsupported_contig,
        drops.dropped_no_supported_alt,
        drops.dropped_no_af,
        drops.dropped_all_rows_withheld,
    )));
    // A `<NON_REF>` ALT only appears in a gVCF, so a non-zero count means the input is a
    // gVCF of per-sample reference blocks rather than a sites or allele-frequency VCF. That
    // is the actionable reason a near-empty output is expected.
    if drops.gvcf_reference_blocks > 0 {
        diags.push(Diagnostic::warning(format!(
            "input appears to be a gVCF: {} reference-block (<NON_REF>) records were skipped; \
             convert it to a sites/allele-frequency VCF before building",
            drops.gvcf_reference_blocks,
        )));
    }
}

/// A read-only preview of what converting a VCF would produce: the recognized populations
/// and AF/AC fields, the record and row counts, and any warnings, without writing a staging
/// dir. Powers the tool's `preview` dry run.
///
/// Serialized `camelCase`, because this type is emitted verbatim into `preview --format
/// json`, whose envelope and every sibling report verb use camelCase. Without the rename a
/// single object would mix Rust field names with the contract's own.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewReport {
    /// Distinct population keys recognized from the header (`Total`, `FI`, ...), including
    /// those carrying only `AC`/`AN`. A superset of [`Self::populations_emitted`].
    pub populations_recognized: Vec<String>,
    /// Distinct populations carrying an `AF` field: the count measured against the
    /// [`MAX_POPULATIONS`] cap. A population with only `AC` or `AN` emits nothing, so it is
    /// excluded here even though it appears in [`Self::populations_recognized`].
    pub af_population_count: usize,
    /// The raw INFO field IDs recognized as per-population AF/AC metrics.
    pub recognized_fields: Vec<String>,
    /// Distinct `(chr, POS, REF, ALT)` keys that would emit at least one row.
    pub number_of_records: u64,
    /// Total output rows that would be written across all partitions.
    pub rows_emitted: u64,
    /// Per-record drop tally (records that would produce no output row).
    pub drops: DropCounts,
    /// Row-level k-anonymity losses (the `min_allele_count` floor and its collapse).
    pub suppression: SuppressionCounts,
    /// The population labels that would actually reach parquet, sorted. A subset of
    /// [`Self::populations_recognized`] whenever a floor or an absent `AF` withholds rows.
    pub populations_emitted: Vec<String>,
    /// Raw INFO field IDs that looked like AF/AC/AN metrics but did not match the grammar.
    pub ignored_info_fields: Vec<String>,
    /// Populations carrying `AC`/`AN` but no `AF`; they emit no rows.
    pub populations_without_af: Vec<String>,
    /// Non-fatal diagnostics (ignored INFO fields, populations with AC/AN but no AF, tallies).
    pub diagnostics: Vec<Diagnostic>,
}

/// Read only a VCF's header and return its distinct AF-bearing population labels.
///
/// Runs the same header validation as [`convert_vcf`] and [`preview_vcf`], so a missing `AF`
/// field, an over-long population label or a bad `Number=` fails here with the same
/// [`CoreError`]. It reads no records, so it is cheap enough to run as a preflight over
/// every source VCF and let `build` fail before writing any parquet. Only populations
/// carrying an `AF` field are returned: those are the ones that emit rows and count toward
/// the [`MAX_POPULATIONS`] cap.
///
/// # Errors
///
/// Returns the header-validation [`CoreError`] variants of [`convert_vcf`], or
/// [`CoreError::Io`] on an I/O failure.
pub fn read_header_populations(path: &Path) -> CoreResult<Vec<String>> {
    preflight_vcf_format(path)?;
    let mut reader = vcf::io::reader::Builder::default().build_from_path(path)?;
    let header = reader.read_header()?;
    let mut diags = Vec::new();
    let scan = build_pop_fields(&header, &mut diags)?;
    Ok(sorted_labels(
        scan.pop_fields
            .iter()
            .filter(|f| f.metric == Metric::Af)
            .map(|f| &f.population),
    ))
}

/// What a VCF's header (and its first record) say about the questions the wizard asks
/// before any conversion runs: which assembly the file was called against, and which
/// contig it starts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderHints {
    /// `GRCh37` or `GRCh38` when the header decides it, from a `##contig` line for
    /// chromosome 1 carrying that assembly's length, or failing that a `##reference=` line
    /// naming the build. `None` otherwise. A hint, never an answer: a lifted-over VCF can
    /// still carry its source header.
    pub assembly: Option<&'static str>,
    /// The `CHROM` of the first data record, verbatim; `None` for a header-only file.
    pub first_contig: Option<String>,
    /// How many sample columns the `#CHROM` line declares: the identifier-bearing surface a
    /// `with-identifiers` header policy would ship. `0` for a sites-only VCF.
    pub samples: usize,
}

/// Chromosome-1 lengths that identify an assembly from a `##contig` line.
const CHR1_LENGTHS: [(usize, &str); 2] = [(249_250_621, "GRCh37"), (248_956_422, "GRCh38")];

/// Read a VCF's header plus its first record and return the [`HeaderHints`].
///
/// Reads no further than the first record, so it is cheap enough to run on every source
/// at the prompt. The format preflight is the converter's own, so a file the reader would
/// reject fails here with the same error.
///
/// # Errors
///
/// Returns [`CoreError::Io`] on an I/O failure or an unreadable header/first record, or the
/// format-preflight error of [`convert_vcf`].
pub fn read_header_hints(path: &Path) -> CoreResult<HeaderHints> {
    preflight_vcf_format(path)?;
    let mut reader = vcf::io::reader::Builder::default().build_from_path(path)?;
    let header = reader.read_header()?;
    let assembly = assembly_from_contigs(&header).or_else(|| assembly_from_reference_line(&header));
    let samples = header.sample_names().len();
    let first_contig = match reader.records().next() {
        Some(record) => Some(record?.reference_sequence_name().to_owned()),
        None => None,
    };
    Ok(HeaderHints {
        assembly,
        first_contig,
        samples,
    })
}

/// The assembly named by a chromosome-1 `##contig` length, if the header carries one.
fn assembly_from_contigs(header: &vcf::Header) -> Option<&'static str> {
    header.contigs().iter().find_map(|(name, contig)| {
        let bare = name.strip_prefix("chr").unwrap_or(name);
        if bare != "1" {
            return None;
        }
        let length = contig.length()?;
        CHR1_LENGTHS
            .iter()
            .find(|(known, _)| *known == length)
            .map(|(_, assembly)| *assembly)
    })
}

/// The assembly a `##reference=` line names, if it names one the tool knows.
fn assembly_from_reference_line(header: &vcf::Header) -> Option<&'static str> {
    use vcf::header::record::value::Collection;
    header
        .other_records()
        .iter()
        .filter(|(key, _)| key.as_ref() == "reference")
        .find_map(|(_, value)| {
            let Collection::Unstructured(values) = value else {
                return None;
            };
            values.iter().find_map(|v| assembly_named_in(v))
        })
}

/// `GRCh37`/`GRCh38` when `text` mentions a build by any of its common spellings.
fn assembly_named_in(text: &str) -> Option<&'static str> {
    let lower = text.to_ascii_lowercase();
    if lower.contains("grch38") || lower.contains("hg38") {
        Some("GRCh38")
    } else if lower.contains("grch37") || lower.contains("hg19") || lower.contains("b37") {
        Some("GRCh37")
    } else {
        None
    }
}

/// Preview an aggregated VCF without writing parquet.
///
/// Runs the same header parse and per-record validation as [`convert_vcf`], so a VCF that
/// would fail conversion fails here with the same error, but accumulates only the recognized
/// fields, the record and row counts, and the warnings. Nothing is written to disk.
/// Bgzipped input is auto-detected by the same reader the converter uses.
///
/// # Errors
///
/// Returns the same [`CoreError`] variants as [`convert_vcf`] for a VCF that
/// violates a hard rule, or [`CoreError::Io`] on an I/O failure.
pub fn preview_vcf(path: &Path, opts: &ConvertOptions) -> CoreResult<PreviewReport> {
    preview_vcf_with_progress(path, opts, &|_| {})
}

/// [`preview_vcf`], reporting freshly-read **compressed on-disk bytes** to `on_bytes` as
/// the scan streams.
///
/// Previewing a whole-chromosome VCF is minutes of pure CPU with nothing to show between
/// the opening line and the report, which is indistinguishable from a hang. This is the same
/// signal [`convert_vcf_group`] reports through its own `on_bytes`, so `preview` drives an
/// identical byte bar rather than a second, divergent one.
///
/// # Errors
///
/// As [`preview_vcf`].
pub fn preview_vcf_with_progress(
    path: &Path,
    opts: &ConvertOptions,
    on_bytes: &dyn Fn(u64),
) -> CoreResult<PreviewReport> {
    preflight_vcf_format(path)?;
    // `open_reader` rather than building from the path, so the byte counter wraps the file
    // read as the converter's producer does and the bar measures the same quantity in both
    // commands.
    let mut reader = open_reader(path, on_bytes, None)?;
    let header = reader.read_header()?;

    let mut diagnostics = Vec::new();
    let scan = build_pop_fields(&header, &mut diagnostics)?;
    let pop_fields = scan.pop_fields;
    let ignored_info_fields = scan.ignored_info_fields;
    let populations_recognized = recognized_populations(&pop_fields);
    let recognized_fields = sorted_labels(pop_fields.iter().map(|f| &f.id));
    let af_population_count = pop_fields
        .iter()
        .filter(|f| f.metric == Metric::Af)
        .map(|f| &f.population)
        .collect::<BTreeSet<_>>()
        .len();

    // Run the same stage-A and stage-B path as the converter, sequentially, but only count
    // the rows: each record's rows are emitted into the reused `emit` scratch, counted, then
    // discarded, so preview stays proportional to the distinct keys, not to all rows.
    let mut distinct = DistinctKeyCounter::default();
    let mut populations_seen: BTreeSet<Arc<str>> = BTreeSet::new();
    let mut no_af_pops: BTreeSet<String> = BTreeSet::new();
    let mut drops = DropCounts::default();
    let mut by_pop: HashMap<Arc<str>, Stats> = HashMap::new();
    let mut emit = RecordEmit::default();
    let mut rows_emitted: u64 = 0;
    let mut records_emitted: u64 = 0;
    let mut records_all_rows_withheld: u64 = 0;
    let mut records_no_af: u64 = 0;
    let mut total_af_zero_variants: u64 = 0;
    let mut suppression = SuppressionCounts::default();

    // The same read and extract loop as the converter, through `drive_records`. The
    // per-record action here emits into the reused `emit` scratch and counts, instead of
    // pushing into a partition batch.
    drive_records(&mut reader, opts, &pop_fields, &mut drops, |ex| {
        emit_extracted(&ex, &pop_fields, opts, &mut by_pop, &mut emit)?;
        if emit.rows.is_empty() {
            if floor_emptied_the_record(&emit.suppression) {
                records_all_rows_withheld += 1;
            } else {
                records_no_af += 1;
            }
        } else {
            records_emitted += 1;
        }
        rows_emitted += emit.rows.len() as u64;
        suppression.add(emit.suppression);
        total_af_zero_variants += emit.total_af_zero;
        // Per-dataset population cap, enforced as distinct labels are first seen (the same
        // point the converter's merge enforces it).
        for row in &emit.rows {
            record_population(&mut populations_seen, Arc::clone(&row.population))?;
            // Run the same AC/AF/AN coherence check `build` enforces on the written parquet
            // here on the in-memory rows, so `preview` cannot pass a row that `build`
            // rejects. Gated on both values being present, as the write-path check is.
            if let (Some(ac), Some(an)) = (row.ac, row.an) {
                crate::validate_parquet::check_ac_an_af(ac, an, row.af)?;
            }
        }
        for key in emit.keys.drain(..) {
            distinct.add(&key);
        }
        for pop in emit.no_af.drain(..) {
            no_af_pops.insert(pop.to_string());
        }
        Ok(())
    })?;

    finish_scan_diagnostics(
        &mut diagnostics,
        &mut drops,
        &StageBTallies {
            records_emitted,
            records_all_rows_withheld,
            records_no_af,
            number_of_records: distinct.count,
            total_af_zero_variants,
        },
        &suppression,
        &no_af_pops,
    );

    Ok(PreviewReport {
        populations_recognized,
        af_population_count,
        recognized_fields,
        number_of_records: distinct.count,
        rows_emitted,
        drops,
        suppression,
        populations_emitted: sorted_labels(populations_seen),
        ignored_info_fields,
        populations_without_af: no_af_pops.iter().cloned().collect(),
        diagnostics,
    })
}

/// Render labels, whether interned populations or raw INFO field IDs, as a sorted,
/// de-duplicated `Vec<String>` for reporting.
fn sorted_labels(labels: impl IntoIterator<Item = impl AsRef<str>>) -> Vec<String> {
    labels
        .into_iter()
        .map(|label| label.as_ref().to_owned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Rename a VCF's partition files from the write-time `placeholder` vcfid to the real
/// `vcfid`, which is known only after the source digest finalizes, updating `paths` in place.
///
/// The vcfid appears exactly once in each name, as `.{vcfid}.parquet`, so a targeted
/// replace of that segment cannot touch the chr/group/blockRange fields. `fs::rename` within
/// one directory is atomic and cheap. On failure the caller's `StagingGuard` removes the
/// whole partial staging dir, so a half-renamed set never escapes.
///
/// # Errors
///
/// Returns [`CoreError::Io`] if a rename fails or a path has no file name.
fn rename_partition_files(paths: &mut [PathBuf], placeholder: &str, vcfid: &str) -> CoreResult<()> {
    let from = format!(".{placeholder}.parquet");
    let to = format!(".{vcfid}.parquet");
    for path in paths {
        let name = path.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
            invalid_parquet(format!(
                "partition path has no file name: {}",
                path.display()
            ))
        })?;
        let renamed = name.replace(&from, &to);
        let new_path = path.with_file_name(renamed);
        std::fs::rename(&*path, &new_path)?;
        *path = new_path;
    }
    Ok(())
}

/// The header scan's result: the parsed per-population metric fields, plus the raw IDs that
/// looked like allele-frequency fields but did not match the grammar. The ignored IDs are
/// returned as data, not only as a [`Diagnostic`], so the manifest can record which columns
/// the projection dropped.
struct HeaderScan {
    pop_fields: Vec<PopField>,
    ignored_info_fields: Vec<String>,
}

/// Build the population-field set from the header INFO definitions, validating the `Number`
/// requirements all-or-nothing and requiring at least one `AF`.
///
/// # Errors
///
/// Returns [`CoreError::InvalidParquet`] when a metric field declares the wrong `Number`,
/// when the AN-family fields disagree, or when no `AF` field is present.
fn build_pop_fields(header: &vcf::Header, diags: &mut Vec<Diagnostic>) -> CoreResult<HeaderScan> {
    let mut pop_fields = Vec::new();
    let mut ignored = Vec::new();
    let mut has_af = false;

    // AN-family Number agreement: None until the first AN field fixes it.
    let mut an_is_array: Option<bool> = None;

    for (id, map) in header.infos() {
        let Some(parsed) = parse_info_field(id) else {
            // Not a population-stratified statistic field. Only fields that look like
            // population fields but do not conform are reported; ordinary INFO fields such
            // as DP, MQ, AA, NS, VT and MULTI_ALLELIC are skipped silently.
            if looks_like_pop_metric(id) {
                ignored.push(id.clone());
            }
            continue;
        };

        let number = map.number();
        match parsed.metric {
            Metric::Af | Metric::Ac | Metric::AcHom | Metric::AcHet | Metric::AcHemi => {
                if number != Number::AlternateBases {
                    return Err(invalid_parquet(format!(
                        "INFO {id} must be Number=A for an aggregated metric, found {number:?}"
                    )));
                }
                if matches!(parsed.metric, Metric::Af) {
                    has_af = true;
                }
            }
            Metric::An => {
                let this_is_array = match number {
                    Number::AlternateBases => true,
                    Number::Count(1) => false,
                    other => {
                        return Err(invalid_parquet(format!(
                            "AN-family INFO {id} must be Number=1 or Number=A, found {other:?}"
                        )));
                    }
                };
                match an_is_array {
                    None => an_is_array = Some(this_is_array),
                    Some(prev) if prev != this_is_array => {
                        return Err(invalid_parquet(format!(
                            "AN-family Number is inconsistent: {id} disagrees with earlier AN fields"
                        )));
                    }
                    Some(_) => {}
                }
            }
        }

        // Validate the population label length once per distinct field, where the interned
        // `Arc` is built, rather than on every emitted row. A backstop: `parse_info_field`
        // already bounds a label to a country and sex join, or "Total", so this never fires
        // on grammar-valid input. It guards against a future change to that grammar.
        let population: Arc<str> = Arc::from(parsed.population);
        if population.chars().count() > MAX_POPULATION_LABEL_LEN {
            return Err(invalid_parquet(format!(
                "population label {population:?} exceeds {MAX_POPULATION_LABEL_LEN} chars"
            )));
        }
        pop_fields.push(PopField {
            id: id.clone(),
            metric: parsed.metric,
            population,
            number,
        });
    }

    if !has_af {
        return Err(invalid_parquet("No AF INFO fields found".to_string()));
    }

    if !ignored.is_empty() {
        diags.push(Diagnostic::warning(format!(
            "ignored non-conforming INFO fields: {}; {}",
            ignored.join(", "),
            describe_rejections(&ignored)
        )));
    }
    ignored.sort_unstable();

    // Two different header IDs can decode to one (metric, population) slot: the population
    // grammar is permutation-invariant, so `AC_Hom_EE` and `AC_EE_Hom` are the same slot and
    // whichever the header yields last wins. That makes the served value depend on header
    // iteration order, and only the provider can say which field is right.
    //
    // Answered here because it is header-determined and knowable once, rather than inside
    // `apply_metric_value`, which runs per record, allele and field. Reported as a
    // `Diagnostic` rather than through `tracing`: the tool installs no subscriber, so a
    // `tracing::warn!` would reach the provider as silence while `--strict` still exits 0.
    // Keyed on the metric's debug form, so the grouping needs no `Ord` on `Metric`.
    let mut by_slot: std::collections::BTreeMap<(String, &str), Vec<&str>> =
        std::collections::BTreeMap::new();
    for f in &pop_fields {
        by_slot
            .entry((format!("{:?}", f.metric), f.population.as_ref()))
            .or_default()
            .push(f.id.as_str());
    }
    for ((metric, population), ids) in by_slot.iter().filter(|(_, ids)| ids.len() > 1) {
        diags.push(Diagnostic::warning(format!(
            "{} INFO fields decode to the same (metric, population) slot ({metric}, \
             {population}): {}; the last one in header order wins. Rename or remove all \
             but one so the served value is not chosen by header order.",
            ids.len(),
            ids.join(", ")
        )));
    }

    Ok(HeaderScan {
        pop_fields,
        ignored_info_fields: ignored,
    })
}

/// The distinct population labels a header declares, sorted, including populations that
/// carry only `AC` or `AN` and therefore emit no rows.
fn recognized_populations(pop_fields: &[PopField]) -> Vec<String> {
    sorted_labels(pop_fields.iter().map(|f| &f.population))
}

/// Whether `id` carries a metric token (`AF`, `AC` or `AN`) in any underscore-separated
/// position, which makes a failed parse worth warning about. Unrelated INFO fields such as
/// DP, MQ and AA are skipped silently.
///
/// Every position is checked, not just the first, because the two dominant public
/// conventions put the metric on opposite sides: gnomAD prefixes it as `AF_nfe`, and 1000
/// Genomes suffixes it as `EUR_AF`. Matching only the prefix would let a whole
/// suffix-convention header pass unremarked, leaving the provider with a `Total`-only
/// dataset.
fn looks_like_pop_metric(id: &str) -> bool {
    id.split('_').any(|tok| matches!(tok, "AF" | "AC" | "AN"))
}

/// The tail of the ignored-fields warning: the rejected IDs grouped by the rule each broke,
/// most common rule first, each with up to three example IDs, so a provider whose whole
/// stratification was dropped reads why in one line instead of reverse-engineering the
/// grammar from a list of names.
fn describe_rejections(ignored: &[String]) -> String {
    let mut by_reason: std::collections::BTreeMap<RejectReason, Vec<&str>> =
        std::collections::BTreeMap::new();
    for id in ignored {
        by_reason
            .entry(rejection_reason(id).unwrap_or(RejectReason::UnknownToken))
            .or_default()
            .push(id);
    }
    let mut groups: Vec<(RejectReason, Vec<&str>)> = by_reason.into_iter().collect();
    groups.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(&b.0)));
    groups
        .iter()
        .map(|(reason, ids)| {
            let examples = ids.iter().take(3).copied().collect::<Vec<_>>().join(", ");
            let more = if ids.len() > 3 { ", ..." } else { "" };
            format!(
                "{} because of {} (e.g. {examples}{more})",
                ids.len(),
                reason.describe()
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// One parsed INFO value, already converted to the column type its metric stores.
///
/// Parsing in stage A is what lets [`Extracted`] drop the VCF record entirely. The variant
/// is chosen by the field's [`Metric`], so the pair can never disagree.
#[derive(Debug, Clone, Copy, PartialEq)]
enum MetricValue {
    /// An `AF`-family value: a finite `f32` in `[0, 1]`.
    Af(f32),
    /// An `AC`/`AC_Hom`/`AC_Het`/`AC_Hemi`/`AN` value: a non-negative `i32`.
    Count(i32),
}

/// One split alternate allele of a record, already reduced to its `POS`-preserving minimal
/// representation by [`right_trim_alleles`].
///
/// REF is per-allele, not per-record: right-trimming `AT -> ATT,A` yields `(A, AT)` and
/// `(AT, A)`, which no longer share a REF. When an allele needs no trim, which is every
/// allele of an already-bi-allelic VCF, the record's interned REF `Arc` is cloned, so the
/// common path allocates nothing extra.
struct SplitAllele {
    ref_: Arc<str>,
    alt: Arc<str>,
}

/// One surviving record's stage-A result: everything stage B needs, and nothing else.
///
/// It does not own the [`vcf::Record`]. Holding it would make the partition buffer scale
/// with the source line width rather than with the data actually read: on a genotype-bearing
/// VCF the INFO column, the only part this converter looks at, is around one percent of the
/// line, and the genotype columns the projection never touches are the rest.
///
/// Carrying the INFO text instead would fix that shape but not a sites-only VCF's, where the
/// line is almost entirely INFO. So stage A parses INFO down to the values the emit needs:
/// `values` holds `pop_fields.len()` entries per supported allele, allele-major, in one flat
/// allocation per record, which is tens of bytes in place of thousands.
///
/// The cost is that INFO parsing moves from the worker pool onto the single producer thread.
struct Extracted {
    chr: Arc<str>,
    pos0: i32,
    pos_1based: usize,
    /// The supported ALTs, each carrying its own right-trimmed REF.
    supported_alts: Vec<SplitAllele>,
    /// Parsed INFO values, allele-major: `pop_fields.len()` entries per entry of
    /// `supported_alts`, in `pop_fields` order. `None` = the field was absent or `.`.
    values: Vec<Option<MetricValue>>,
}

impl Extracted {
    /// Approximate heap footprint, for the batcher's byte budget. Counts the per-allele
    /// strings and the parsed values; `chr` is interned across the whole VCF, so its bytes
    /// are attributed to no record.
    fn approx_bytes(&self) -> usize {
        let alleles: usize = self
            .supported_alts
            .iter()
            .map(|a| a.ref_.len() + a.alt.len() + 2 * size_of::<Arc<str>>())
            .sum();
        size_of::<Self>() + alleles + self.values.len() * size_of::<Option<MetricValue>>()
    }
}

/// Stage A for one record: contig, REF, ALT-filter and POS normalization,
/// position-ordering enforcement, and drop accounting. Sequential and ordering-critical, so
/// it runs on the producer thread. Returns the owned [`Extracted`] when the record survives
/// with at least one supported ALT, or `None` when it is dropped. The heavy stage B, the
/// INFO parse and emit, runs later on a worker, so this stage costs little more than the
/// bare record read.
fn extract_record(
    record: &vcf::Record,
    opts: &ConvertOptions,
    pop_fields: &[PopField],
    current_chr: &mut Option<String>,
    last_pos_in_chr: &mut Option<i32>,
    seen_chrs: &mut BTreeSet<String>,
    drops: &mut DropCounts,
) -> CoreResult<Option<Extracted>> {
    drops.input_records += 1;

    // 0. FILTER is not a gate: a non-PASS record converts like any other. Count it so the
    //    provider learns that unfiltered calls were published rather than inferring it from
    //    a site count. The tally surfaces as a warning, so a strict build refuses to ship
    //    them. `PASS` and the missing value are clean.
    let filters = record.filters();
    if !matches!(AsRef::<str>::as_ref(&filters), "PASS" | "." | "") {
        drops.non_pass_records += 1;
    }

    // 1. Contig normalization (skip Ok(None), error on Err).
    let Some(chr) = normalize_contig(record.reference_sequence_name(), &opts.assembly)? else {
        drops.dropped_unsupported_contig += 1;
        return Ok(None);
    };

    // 2. Collect the line's ALTs with their original indices, then drop unsupported ALTs.
    //    The ALT filter runs before the POS check.
    let Some(ref_norm) = normalize_allele(record.reference_bases()) else {
        return Err(invalid_parquet(format!("empty REF allele on contig {chr}")));
    };

    let mut alt_count = 0usize;
    // `(original ALT index, right-trimmed REF, right-trimmed ALT)`. The original index binds
    // the allele to its slot in a `Number=A` INFO list, so trimming never disturbs the
    // lookup. It is consumed below and does not survive into `Extracted`.
    let mut alts: Vec<(usize, Arc<str>, Arc<str>)> = Vec::new();
    // The record's REF, interned once. Every allele that needs no right-trim, which is all
    // of them for an already-bi-allelic VCF, clones this refcount rather than allocating.
    let ref_arc: Arc<str> = Arc::from(&*ref_norm);
    // The gVCF reference-block marker (`<NON_REF>`): a non-zero count means the input is
    // a gVCF, surfaced as a dataset-level hint.
    let mut has_non_ref = false;
    for alt_result in record.alternate_bases().iter() {
        let alt_raw = alt_result?;
        if alt_raw == "<NON_REF>" || alt_raw == "<*>" {
            has_non_ref = true;
        }
        let idx = alt_count;
        alt_count += 1;
        let Some(alt_norm) = normalize_allele(alt_raw) else {
            continue;
        };
        // A literal ALT identical to REF is not a variant: VCF requires ALT ≠ REF. Skip it
        // so it never becomes a beacon row or reaches `classify_vt`, whose five-way
        // vocabulary has no label for a non-variant.
        if !alt_is_supported(&alt_norm) || alt_norm.as_ref() == ref_norm.as_ref() {
            continue;
        }
        // Reduce the pair this split just authored to its POS-preserving minimal form.
        // Splitting `AT -> ATT,A` invents `(AT, ATT)`; the canonical variant is `(A, AT)`.
        let (ref_trim, alt_trim) = right_trim_alleles(&ref_norm, &alt_norm);
        if is_left_trimmable(ref_trim, alt_trim) {
            drops.alleles_not_left_trimmed += 1;
        }
        let ref_: Arc<str> = if ref_trim.len() == ref_norm.len() {
            Arc::clone(&ref_arc)
        } else {
            Arc::from(ref_trim)
        };
        alts.push((idx, ref_, Arc::from(alt_trim)));
    }

    // 3. POS check (after the ALT filter).
    let Some(pos_result) = record.variant_start() else {
        if alts.is_empty() {
            drops.drop_no_supported_alt(has_non_ref);
            return Ok(None);
        }
        return Err(invalid_parquet(format!(
            "POS=0 with a literal ALT on contig {chr} cannot map to a 0-based coordinate"
        )));
    };
    // Name the field and the contig rather than letting the parser's error through raw. A
    // bare "invalid digit found in string" names no field, no contig and no file position,
    // which leaves the provider guessing which of millions of records it meant, while POS=0
    // on the same path gets the message above.
    let pos_1based = pos_result.map_err(|e| {
        invalid_parquet(format!(
            "POS on contig {chr} is not a valid 1-based position: {e}. VCF POS is a positive \
             integer, so a negative or non-numeric value cannot be converted; check that \
             record (and `bcftools view` the file if it may be malformed more widely)"
        ))
    })?;
    let pos0 = i32::try_from(usize::from(pos_1based) - 1).map_err(|_| {
        invalid_parquet(format!(
            "position {} on contig {chr} exceeds int32",
            usize::from(pos_1based)
        ))
    })?;

    // 4. Position ordering and chromosome reappearance, advanced even for an
    //    all-unsupported-ALT record so it still occupies its coordinate.
    enforce_chr_pos_order(&chr, pos0, current_chr, last_pos_in_chr, seen_chrs)?;

    if alts.is_empty() {
        drops.drop_no_supported_alt(has_non_ref);
        return Ok(None);
    }

    // Only reached when at least one ALT survived, so these alleles were lost from a
    // published record. The all-unsupported case returned above and is already counted as a
    // whole record; counting its alleles here too would double-report the same loss.
    drops.alleles_discarded += (alt_count - alts.len()) as u64;

    // 5. Parse the INFO column down to the values the emit needs, so the record itself is
    //    never buffered. Done after the ordering and POS gates, so a dropped record never
    //    pays for the parse and a malformed INFO on a mis-ordered line still reports the
    //    ordering error first.
    let info = record.info();
    let info_map = parse_info_map(info.as_ref());
    // `NS`, samples with data, is not a served statistic, but its peak over the file is the
    // individual count the VCF itself suggests for `numberOfUniqueIndividuals`. One map
    // lookup per published record; a malformed value is simply not a hint.
    if let Some(ns) = info_map
        .get("NS")
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        drops.ns_peak = Some(drops.ns_peak.map_or(ns, |peak| peak.max(ns)));
    }
    let mut values = Vec::with_capacity(alts.len() * pop_fields.len());
    for (orig_idx, _, _) in &alts {
        for field in pop_fields {
            let parsed = lookup_value(&info_map, field.number, &field.id, *orig_idx, alt_count)?
                .map(|token| parse_metric(field.metric, token, &field.id))
                .transpose()?;
            values.push(parsed);
        }
    }

    Ok(Some(Extracted {
        chr: Arc::from(&*chr),
        pos0,
        pos_1based: usize::from(pos_1based),
        supported_alts: alts
            .into_iter()
            .map(|(_, ref_, alt)| SplitAllele { ref_, alt })
            .collect(),
        values,
    }))
}

/// The per-record locus context shared across a line's split alleles. `chr` is interned once
/// per variant, so the per-population rows clone the refcount. REF is not here: it is
/// per-allele after the right-trim, on [`SplitAllele`].
struct Locus {
    chr: Arc<str>,
    pos0: i32,
    pos_1based: usize,
}

/// One record's emitted output: its rows, its distinct `(chr, POS, REF, ALT)` keys, and the
/// populations for which it has AC or AN but no AF. The per-dataset population cap is
/// enforced later, when partition results are merged, because the distinct set is scan-wide.
#[derive(Default)]
struct RecordEmit {
    rows: Vec<OutRow>,
    keys: Vec<RecordKey>,
    no_af: Vec<Arc<str>>,
    /// Rows this record lost to the k-anonymity floor or its collapse. Reset per record like
    /// the other fields; each caller folds it into its own scan-wide tally.
    suppression: SuppressionCounts,
    /// Split alleles of this record whose `Total` row was emitted with `AF = 0`. Reset per
    /// record; each caller folds it into its own scan-wide tally.
    total_af_zero: u64,
}

/// Stage B, the heavy half, which runs on a worker: emit one extracted record's rows into
/// `emit`, which is reset first. Tokenizes the record's INFO column once, then emits per
/// supported allele.
fn emit_extracted(
    ex: &Extracted,
    pop_fields: &[PopField],
    opts: &ConvertOptions,
    by_pop: &mut HashMap<Arc<str>, Stats>,
    emit: &mut RecordEmit,
) -> CoreResult<()> {
    emit.rows.clear();
    emit.keys.clear();
    emit.no_af.clear();
    emit.suppression = SuppressionCounts::default();
    emit.total_af_zero = 0;
    let loc = Locus {
        chr: Arc::clone(&ex.chr),
        pos0: ex.pos0,
        pos_1based: ex.pos_1based,
    };
    // `values` is allele-major with `pop_fields.len()` entries per allele, so the chunks line
    // up one-to-one with `supported_alts`. An empty `pop_fields` cannot reach here, because
    // `build_pop_fields` rejects a header with no `AF`.
    if pop_fields.is_empty() {
        return Ok(());
    }
    for (allele, values) in ex
        .supported_alts
        .iter()
        .zip(ex.values.chunks_exact(pop_fields.len()))
    {
        emit_allele_rows(values, pop_fields, opts, &loc, allele, emit, by_pop)?;
    }
    Ok(())
}

/// Population-hierarchy coherence across one allele's populations.
///
/// `check_subcounts` verifies that one population's genotype cells partition its own `AC`.
/// This verifies that the populations partition each other the way the label grammar says,
/// with `FI_M` inside `FI` inside `Total`. Both are hard errors: each reports a set of
/// numbers that cannot describe any cohort, so the producer's INFO fields disagree with
/// themselves.
///
/// Runs before the per-population drain, which consumes the map.
fn check_population_hierarchy(
    by_pop: &HashMap<Arc<str>, Stats>,
    loc: &Locus,
) -> Result<(), CoreError> {
    let counts: std::collections::BTreeMap<String, crate::hierarchy::PopCounts> = by_pop
        .iter()
        .map(|(pop, st)| {
            (
                pop.to_string(),
                crate::hierarchy::PopCounts {
                    ac: st.ac.map(i64::from),
                    an: st.an.map(i64::from),
                },
            )
        })
        .collect();
    crate::hierarchy::check_hierarchy(&counts)
        .map_err(|e| invalid_parquet(format!("{e} at {}:{}", loc.chr, loc.pos_1based)))
}

/// Gather per-population stats for one allele and append its output rows to `emit`.
fn emit_allele_rows(
    values: &[Option<MetricValue>],
    pop_fields: &[PopField],
    opts: &ConvertOptions,
    loc: &Locus,
    allele: &SplitAllele,
    emit: &mut RecordEmit,
    by_pop: &mut HashMap<Arc<str>, Stats>,
) -> CoreResult<()> {
    // Population to accumulated stats for this allele, keyed by the scan-stable
    // `PopField::population` as an `Arc<str>`, which is a refcount bump rather than a
    // `String` allocation. The same `Arc` is moved into the emitted row, so the label is
    // never re-allocated. The map is reused across alleles and records, cleared here and
    // drained below, so its backing allocation is made once for the whole conversion.
    by_pop.clear();
    for (field, value) in pop_fields.iter().zip(values) {
        let Some(value) = value else {
            continue; // missing field / '.' -> null
        };
        let stats = by_pop.entry(Arc::clone(&field.population)).or_default();
        apply_metric_value(field, *value, stats);
    }

    // Classify from the right-trimmed pair. `classify_vt` trims both affixes for its label,
    // and trimming is idempotent, so the five-way VT vocabulary is unchanged by the trim.
    let vt = classify_vt(&allele.ref_, &allele.alt).as_str();
    // First row of this allele within the record-wide `emit.rows`; the k-anonymity collapse
    // below is scoped to `start..`.
    let start = emit.rows.len();
    // Set when any population of this variant is withheld, whether floor-dropped or omitted
    // with a count but no AF. That is a partial marginal set, which must collapse to `Total`.
    let mut suppressed_any = false;

    check_population_hierarchy(by_pop, loc)?;

    for (population, stats) in by_pop.drain() {
        // AC <= AN coherence holds whenever both are present, independent of AF;
        // per-field non-negativity and the AF bound are already checked. This runs before
        // the no-AF early return below, so an incoherent AC > AN is rejected even for a
        // population that has AC and AN but no AF, which otherwise emits no row.
        if let (Some(ac), Some(an)) = (stats.ac, stats.an)
            && ac > an
        {
            return Err(invalid_parquet(format!(
                "AC ({ac}) exceeds AN ({an}) for population {population} at {}:{}",
                loc.chr, loc.pos_1based
            )));
        }

        // The genotype sub-counts partition AC, counting alleles rather than individuals, so
        // an incoherent set means the producer's INFO fields disagree with themselves.
        // Checked before the no-AF early return for the same reason AC > AN is: a population
        // with counts but no AF emits no row yet must still be well-formed.
        // `validate_parquet` re-checks it at ingest from the same predicate, because the
        // node does not trust the producer.
        if let Err(e) = subcounts::check_subcounts(
            stats.ac.map(i64::from),
            stats.ac_hom.map(i64::from),
            stats.ac_het.map(i64::from),
            stats.ac_hemi.map(i64::from),
        ) {
            return Err(invalid_parquet(format!(
                "{e} for population {population} at {}:{}",
                loc.chr, loc.pos_1based
            )));
        }

        // No AF for this (allele, population). Two very different causes:
        //
        // 1. `AN == 0`: the population has no called genotypes here, so AF is undefined,
        //    not withheld. There is no cell to recover: `Total - sum(present siblings)`
        //    yields 0, which `AN = 0` already publishes. Treating it as a withheld cell
        //    collapses the variant to `Total` and discards the siblings' valid rows, and
        //    when `Total` itself has `AN = 0` the whole variant disappears. gnomAD emits
        //    exactly this shape: at an `AN_XX = 0` site it omits `AF_XX` entirely.
        // 2. `AN > 0` (or absent) with a count present: a genuinely partial marginal set,
        //    since `Total - sum(present)` recovers the omitted cell. Warn and collapse.
        let Some(af) = stats.af else {
            if stats.an == Some(0) {
                continue;
            }
            if stats.ac.is_some() || stats.an.is_some() {
                emit.no_af.push(population);
                suppressed_any = true;
            }
            continue;
        };

        // Build-time min_allele_count, through the shared row rule in `core::kanon`, which
        // is the same rule the serve-time floor applies, so the two cannot drift. Comparing
        // only an explicit `AC` would exempt a group derivable from `AF x AN`, and the
        // complement tail: a near-fixed row whose reference-carrier group is below the floor
        // while its own AC is above it.
        //
        // `Uncountable` is kept rather than dropped, and that is the one place the two
        // callers legitimately differ. `AF` is the only required frequency field, so an
        // AF-only dataset is a supported shape, and failing closed here would permanently
        // delete every row of one built with any floor above zero, at the one moment the
        // data still exists. Serve time fails such a row closed per response, which is
        // reversible; this is not. See `kanon::RowVerdict::Uncountable`.
        //
        // A dropped sibling leaves a partial marginal set, so it triggers the collapse below.
        if opts.min_allele_count > 0
            && crate::kanon::classify_row(stats.ac, stats.an, af, i64::from(opts.min_allele_count))
                == crate::kanon::RowVerdict::Suppress
        {
            suppressed_any = true;
            emit.suppression.rows_below_floor += 1;
            continue;
        }

        // `af` is non-negative, enforced by `parse_af`, so `<= 0.0` means `AF == 0` without
        // a float equality: no carrier in this population. Only `Total` says that of the
        // whole cohort; a per-population zero is an ordinary stratum with no carrier.
        if population.as_ref() == TOTAL_POPULATION && af <= 0.0 {
            emit.total_af_zero += 1;
        }

        emit.rows.push(OutRow {
            pos: loc.pos0,
            ref_: Arc::clone(&allele.ref_),
            alt: Arc::clone(&allele.alt),
            vt,
            population,
            af,
            ac: stats.ac,
            ac_hom: stats.ac_hom,
            ac_het: stats.ac_het,
            ac_hemi: stats.ac_hemi,
            an: stats.an,
        });
    }

    // Build-time k-anonymity coherence, mirroring the serve-time collapse. The emitted
    // marginals sum to `Total`, so a partial set, with some siblings withheld above, would
    // let `Total - sum(present siblings)` recover a withheld below-floor cell. When any
    // population of this variant was withheld, keep only the `Total` row, and keep nothing
    // if `Total` itself was withheld. That makes the build-time drop coherent with the serve
    // gate, which sees a complete set or `Total` alone and never a partial one, closing the
    // differencing vector a naive per-population drop would reintroduce.
    if suppressed_any {
        let this_variant = emit.rows.split_off(start);
        let before = this_variant.len() as u64;
        emit.rows.extend(
            this_variant
                .into_iter()
                .filter(|r| r.population.as_ref() == TOTAL_POPULATION),
        );
        // Meter only what the collapse removed. A group whose sole survivor was already
        // `Total` loses nothing here: its cell was counted at the floor instead, and
        // counting it twice would overstate the collapse's cost.
        let removed = before - (emit.rows.len() - start) as u64;
        if removed > 0 {
            emit.suppression.rows_collapsed_to_total += removed;
            emit.suppression.variants_collapsed_to_total += 1;
        }
    }

    if emit.rows.len() > start {
        // Reuse the already-interned `Arc<str>` values, which are refcount bumps rather than
        // three fresh `String` allocations. These keys are only counted, for
        // `numberOfRecords`, never serialized, and `Arc<str>` orders by its `str`, so the
        // dedup and ordering are unchanged.
        emit.keys.push((
            Arc::clone(&loc.chr),
            loc.pos0,
            Arc::clone(&allele.ref_),
            Arc::clone(&allele.alt),
        ));
    }

    Ok(())
}

/// Catch a BGZF, plain-text or plain-gzip format mismatch before record parsing, so a
/// mis-named or wrongly compressed file fails with a clear message instead of garbled records
/// or a confusing mid-stream error.
///
/// The reader selects the bgzf decompressor by file extension, so gzip magic without a
/// `.gz`-family extension, or a `.gz` name that is not gzip, is misread. A `.gz` that is
/// gzip but plain rather than blocked fails deep in the reader with an opaque buffer error.
/// Reads the 18-byte BGZF block header, enough to see the FEXTRA flag and the `BC` subfield.
fn preflight_vcf_format(path: &Path) -> CoreResult<()> {
    use std::io::Read as _;
    // 18 bytes = the canonical BGZF header through the `BC` extra subfield's BSIZE.
    let mut magic = [0u8; 18];
    let mut filled = 0;
    let mut f = std::fs::File::open(path)?;
    while filled < magic.len() {
        match f.read(&mut magic[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    let is_gzip = filled >= 2 && magic[0..2] == [0x1f, 0x8b];
    // BGZF is gzip with the FEXTRA flag (FLG bit 0x04) carrying a `BC` subfield (SI1 'B'
    // 0x42, SI2 'C' 0x43), which is the block structure the reader needs for indexed access.
    // Plain gzip output has the same magic but never sets FEXTRA and never carries `BC`.
    let is_bgzf =
        is_gzip && filled >= 14 && (magic[3] & 0x04) != 0 && magic[12] == 0x42 && magic[13] == 0x43;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    // Case-insensitive bgzip-family extension check, so a mis-cased `.GZ` still counts.
    let gz_ext = path.extension().is_some_and(|e| {
        e.eq_ignore_ascii_case("gz")
            || e.eq_ignore_ascii_case("bgz")
            || e.eq_ignore_ascii_case("bgzf")
    });
    if is_gzip && !gz_ext {
        return Err(invalid_parquet(format!(
            "{name} is BGZF/gzip-compressed but its name has no .gz extension; the reader \
                 selects the decompressor by extension, so rename it to .vcf.gz (or decompress it) \
                 before building"
        )));
    }
    if !is_gzip && gz_ext {
        return Err(invalid_parquet(format!(
            "{name} is named like a bgzip VCF (.gz) but is not gzip-compressed; if it is plain \
                 text rename it to .vcf, or compress it with `bgzip`"
        )));
    }
    if is_gzip && gz_ext && !is_bgzf {
        // The plain-gzip case: the same magic and `.gz` name as bgzip, so both guards above
        // pass, but the bgzf reader needs the block structure `bgzip` adds and otherwise
        // fails with an opaque buffer error. Name the fix.
        return Err(CoreError::InvalidParquet {
            detail: format!(
                "{name} is plain gzip, not BGZF (blocked gzip). A VCF may be plain-gzipped, but \
                 the reader needs bgzip's block structure (for indexed access), so re-compress it: \
                 `gunzip -c {name} | bgzip > {name}` (or `bcftools view {name} -Oz -o {name}`)"
            ),
        });
    }
    if !is_gzip && filled > 0 {
        reject_leading_junk(name, &magic[..filled])?;
    }
    Ok(())
}

/// Reject anything before the mandatory `##fileformat` line of an uncompressed VCF, naming
/// what is actually there.
///
/// The reader reports every such file as empty input whatever its size, including a small
/// file with a valid header and a record. That message names the one thing that is not
/// wrong, so a provider goes looking at a file they will find is fine. Two realistic inputs
/// land here:
///
/// * a UTF-8 byte-order mark, which a Windows editor or an Excel round-trip adds silently
///   and which is invisible in every viewer;
/// * leading blank lines, from a copy-paste or a shell heredoc.
///
/// Scoped to the uncompressed case: the gzip families are diagnosed above, and the first
/// bytes of a compressed file are magic, not text.
///
/// # Errors
/// Returns [`CoreError::InvalidParquet`] naming the offending prefix and the fix.
fn reject_leading_junk(name: &str, head: &[u8]) -> CoreResult<()> {
    const BOM: &[u8] = &[0xEF, 0xBB, 0xBF];
    if head.starts_with(BOM) {
        return Err(invalid_parquet(format!(
            "{name} starts with a UTF-8 byte-order mark (BOM) before `##fileformat`, so the \
             reader sees no header and reports the file as empty. A BOM is invisible in most \
             editors and is usually added by a Windows editor or an Excel round-trip. Strip \
             it: `sed -i '1s/^\\xEF\\xBB\\xBF//' {name}`"
        )));
    }
    // A VCF's first line must be `##fileformat`, so nothing may legitimately precede it.
    // Anything here is the reader's empty-input report in disguise.
    if head.first().is_some_and(u8::is_ascii_whitespace) {
        return Err(invalid_parquet(format!(
            "{name} begins with blank or whitespace lines before `##fileformat`, so the \
             reader sees no header and reports the file as empty. A VCF's first line must be \
             `##fileformat=VCFv4.x`; delete the leading blank lines"
        )));
    }
    if !head.starts_with(b"##") {
        return Err(invalid_parquet(format!(
            "{name} does not begin with `##fileformat` (a VCF's mandatory first line), so the \
             reader sees no header and reports the file as empty. Check that this really is a \
             VCF and that nothing precedes its header"
        )));
    }
    Ok(())
}

/// Enforce non-decreasing POS within a chromosome, and that a chromosome cannot reappear
/// after a different chromosome has started. This is the sorted-input invariant the
/// downstream row-group `POS` prune and the cross-file uniqueness scan rely on.
fn enforce_chr_pos_order(
    chr: &str,
    pos0: i32,
    current_chr: &mut Option<String>,
    last_pos_in_chr: &mut Option<i32>,
    seen_chrs: &mut BTreeSet<String>,
) -> CoreResult<()> {
    match current_chr {
        Some(cur) if cur == chr => {
            if let Some(last) = *last_pos_in_chr
                && pos0 < last
            {
                return Err(invalid_parquet(format!(
                    "position {pos0} on contig {chr} is before the previous position {last}; \
                         the VCF must be coordinate-sorted; run `bcftools sort` (and `bgzip` if \
                         compressed) before building"
                )));
            }
            *last_pos_in_chr = Some(pos0);
        }
        _ => {
            // Switching to a chromosome, possibly one not seen before.
            if let Some(prev) = current_chr.take() {
                seen_chrs.insert(prev);
            }
            if seen_chrs.contains(chr) {
                return Err(invalid_parquet(format!(
                    "contig {chr} reappears after it was already written; the VCF must be \
                         grouped and coordinate-sorted by contig; run `bcftools sort` before building"
                )));
            }
            *current_chr = Some(chr.to_string());
            *last_pos_in_chr = Some(pos0);
        }
    }
    Ok(())
}

/// Look up the raw value token for INFO field `id` bound to `alt_idx` (the ALT's
/// original line index), validating the `Number=A` list length and the
/// scalar-only rule.
///
/// `info_map` is the record's INFO column pre-tokenized by [`parse_info_map`].
/// Returns `Ok(None)` when the field is absent, a bare flag, or the value is `.`
/// (missing). The returned token is borrowed from the INFO string the map indexes.
fn lookup_value<'a>(
    info_map: &HashMap<&str, &'a str>,
    number: Number,
    id: &str,
    alt_idx: usize,
    alt_count: usize,
) -> CoreResult<Option<&'a str>> {
    // The map gives the raw value, and the list length, scalar-versus-A and missing-value
    // rules are applied here, so they stay explicit and independent of how the VCF library
    // maps `Number` to its own value variants. `number` is the field's header-declared
    // `Number`, captured once on the `PopField`, so there is no per-call header lookup.
    let Some(value_part) = info_map.get(id).copied() else {
        return Ok(None);
    };

    let token = match number {
        Number::AlternateBases => {
            // Count the comma-separated values and pick the `alt_idx`-th in one pass,
            // rather than splitting twice.
            let mut count = 0usize;
            let mut picked = "";
            for (i, part) in value_part.split(',').enumerate() {
                if i == alt_idx {
                    picked = part;
                }
                count += 1;
            }
            if count != alt_count {
                return Err(invalid_parquet(format!(
                    "INFO {id} has {count} values but the line has {alt_count} ALT(s)"
                )));
            }
            picked
        }
        Number::Count(1) => {
            // A scalar value must be a single token, with no comma list. A scalar AN is
            // repeated on every split row, bound to each allele as-is even on a
            // multi-allelic line. A comma list under Number=1 is malformed; the values are
            // counted only on that error path.
            if value_part.contains(',') {
                let count = value_part.split(',').count();
                return Err(invalid_parquet(format!(
                    "scalar INFO {id} has {count} comma-separated values"
                )));
            }
            value_part
        }
        other => {
            return Err(invalid_parquet(format!(
                "INFO {id} has unsupported Number {other:?}"
            )));
        }
    };

    let token = token.trim();
    if token == "." || token.is_empty() {
        Ok(None)
    } else {
        Ok(Some(token))
    }
}

/// Tokenize a record's `;`-delimited INFO column into a key-to-value map once, so each field
/// is a constant-time lookup instead of a re-scan of the whole INFO string per
/// `(allele, population)` pair, which is quadratic in the field count. Bare flags, a key with
/// no `=`, carry no value and are skipped, and on a duplicate key the first occurrence wins.
/// An aggregated metric is never a flag.
///
/// Pre-sized from a single `;` count, so the per-field inserts never rehash.
fn parse_info_map(info: &str) -> HashMap<&str, &str> {
    if info.is_empty() || info == "." {
        return HashMap::new();
    }
    let fields = info.bytes().filter(|&b| b == b';').count() + 1;
    let mut map = HashMap::with_capacity(fields);
    for field in info.split(';') {
        if let Some((key, value)) = field.split_once('=') {
            map.entry(key).or_insert(value);
        }
    }
    map
}

/// Parse one raw INFO token to the column type `metric` stores, applying the domain checks
/// (non-negative everywhere; `AF <= 1`). Runs in stage A, on the producer thread.
///
/// # Errors
///
/// Returns [`CoreError::InvalidParquet`] when the token is not a number, is negative or
/// non-finite, or (for `AF`) exceeds `1.0`.
fn parse_metric(metric: Metric, token: &str, id: &str) -> CoreResult<MetricValue> {
    Ok(match metric {
        Metric::Af => MetricValue::Af(parse_af(token, id)?),
        Metric::Ac | Metric::AcHom | Metric::AcHet | Metric::AcHemi | Metric::An => {
            MetricValue::Count(parse_count(token, id)?)
        }
    })
}

/// Fold one field's already-parsed value into the per-population accumulator.
///
/// Infallible: [`parse_metric`] chose the [`MetricValue`] variant from the same
/// [`PopField::metric`], so the pair cannot disagree. The mismatched arms are unreachable
/// and assert in debug builds rather than silently writing nothing.
fn apply_metric_value(field: &PopField, value: MetricValue, stats: &mut Stats) {
    // A (metric, population) slot collision is header-determined and reported once by
    // `build_pop_fields`, through the `Diagnostic` channel the provider receives.
    match (field.metric, value) {
        (Metric::Af, MetricValue::Af(af)) => stats.af = Some(af),
        (Metric::Ac, MetricValue::Count(n)) => stats.ac = Some(n),
        (Metric::AcHom, MetricValue::Count(n)) => stats.ac_hom = Some(n),
        (Metric::AcHet, MetricValue::Count(n)) => stats.ac_het = Some(n),
        (Metric::AcHemi, MetricValue::Count(n)) => stats.ac_hemi = Some(n),
        (Metric::An, MetricValue::Count(n)) => stats.an = Some(n),
        (metric, value) => debug_assert!(
            false,
            "metric {metric:?} cannot carry value {value:?}; parse_metric builds both"
        ),
    }
}

/// Parse an `AF` token: a finite `f32` in `[0, 1]`.
fn parse_af(token: &str, id: &str) -> CoreResult<f32> {
    let af: f32 = token
        .parse()
        .map_err(|_| invalid_parquet(format!("INFO {id} AF {token:?} is not a number")))?;
    if !af.is_finite() || af < 0.0 {
        return Err(invalid_parquet(format!(
            "INFO {id} AF {af} is negative or non-finite"
        )));
    }
    if af > 1.0 {
        return Err(invalid_parquet(format!("INFO {id} AF {af} exceeds 1.0")));
    }
    Ok(af)
}

/// Parse a count token (`AC`/`AC_*`/`AN`): a non-negative `i32`.
fn parse_count(token: &str, id: &str) -> CoreResult<i32> {
    let n: i32 = token.parse().map_err(|_| {
        invalid_parquet(format!(
            "INFO {id} count {token:?} is not a non-negative integer"
        ))
    })?;
    if n < 0 {
        return Err(invalid_parquet(format!("INFO {id} count {n} is negative")));
    }
    Ok(n)
}

/// Per-VCF context the worker pool needs to convert any of that VCF's partitions: the
/// recognized population fields and the vcfid embedded in each partition file name. Shared
/// through an `Arc` across all of a VCF's batches, so one pool can interleave partitions from
/// several VCFs and a finished VCF's cores are reused by the others.
struct VcfContext {
    pop_fields: Vec<PopField>,
    vcfid: String,
}

/// One chunk of a partition handed to a worker.
///
/// A partition may arrive as several batches, because the batcher ships one whenever its byte
/// budget is reached, so the worker keeps the parquet writer open across them and closes it
/// on `is_final`. Every batch of a partition carries the same `(vcf_idx, chr, group)` key and
/// the same `seq`, and is routed to the same worker, so they arrive in order.
struct PartitionBatch {
    /// Routes the result back to its VCF (one shared pool serves the whole build).
    vcf_idx: usize,
    /// The per-VCF partition index, not the batch index. Used to report the
    /// lowest-positioned validation error deterministically when several partitions fail.
    seq: usize,
    chr: Arc<str>,
    group: u64,
    /// Extracted records in record order. May be empty on a final batch whose partition was
    /// already fully shipped by a byte-budget flush.
    records: Vec<Extracted>,
    /// This VCF's shared context: the population fields and the vcfid.
    ctx: Arc<VcfContext>,
    /// Last batch of this partition: close the writer and emit the [`PartitionOutput`].
    is_final: bool,
}

/// Bytes of extracted records the batcher buffers before shipping a batch.
///
/// This is what makes peak memory a function of a constant rather than of the input. Shipping
/// a partition only when the `(chr, block)` key advances makes peak memory
/// `in_flight_partitions x blockRange x variant_density`, and `blockRange: 0`, which the
/// `init` template offers as one file per chromosome, buffers an entire chromosome.
///
/// A constant, not a function of `pool_size`. Batch boundaries become parquet row-group
/// boundaries, so deriving them from the core count would make the written bytes, and each
/// file's manifest `sha256`, differ between a one-job and a four-job build on the same input.
/// `parallel_build_matches_sequential_build` pins that they do not.
///
/// Pool-wide in-flight memory is therefore
/// `pool_size x (WORKER_QUEUE_DEPTH + 1) x MAX_BATCH_BYTES`, which scales with the machine's
/// cores, chosen by the operator, and never with the size of the VCF.
const MAX_BATCH_BYTES: usize = 32 * 1024 * 1024;

/// Per-worker channel depth. One slack batch lets a producer stay a step ahead of a worker
/// without blocking; more would only raise the in-flight bound.
const WORKER_QUEUE_DEPTH: usize = 1;

/// Route a partition to a worker so every batch of it lands on the same one, since that worker
/// owns the partition's open `ArrowWriter`. A plain FNV-1a over the key: balance matters less
/// than affinity, because partitions are many and similar in size.
fn route_partition(vcf_idx: usize, chr: &str, group: u64, pool_size: usize) -> usize {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut mix = |bytes: &[u8]| {
        for b in bytes {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    mix(&vcf_idx.to_le_bytes());
    mix(chr.as_bytes());
    mix(&group.to_le_bytes());
    usize::try_from(h % pool_size.max(1) as u64).unwrap_or(0)
}

/// A worker's result for one fully-converted partition: the written file plus the
/// scan-wide contributions the merge folds together.
struct PartitionOutput {
    chr: String,
    group: u64,
    /// The partition's parquet file, or `None` when every row the partition would have
    /// held was withheld and no file was kept (see [`close_partition`]).
    path: Option<PathBuf>,
    /// Distinct `(chr, POS, REF, ALT)` keys that produced at least one row in this
    /// partition, counted while streaming. Disjoint across partitions, so the per-VCF total
    /// is their sum.
    distinct_variants: u64,
    /// Distinct populations emitted (unioned for the per-dataset population cap).
    pops: BTreeSet<Arc<str>>,
    /// Populations with AC/AN but no AF (unioned for the warning).
    no_af: BTreeSet<String>,
    /// Rows this partition lost to the k-anonymity floor or its collapse, summed across
    /// partitions.
    suppression: SuppressionCounts,
    /// Rows written to this partition's parquet file (summed for `rows_emitted`).
    rows_written: u64,
    /// Records in this partition that emitted at least one row, summed into `DropCounts`.
    records_emitted: u64,
    /// Records in this partition whose every population row the floor withheld, summed into
    /// `DropCounts::dropped_all_rows_withheld`. Only stage B can see this, because stage A
    /// does not know whether a surviving record will produce a row.
    records_all_rows_withheld: u64,
    /// Records in this partition that emitted nothing because the input carried no allele
    /// frequency, summed into `DropCounts::dropped_no_af`. Both producing sites share the
    /// `floor_emptied_the_record` discriminator.
    records_no_af: u64,
    /// Variants in this partition whose `Total` row carries `AF = 0`, summed into
    /// `DropCounts::total_af_zero_variants`.
    total_af_zero_variants: u64,
}

/// Number of concurrent partition-worker threads. Each worker runs a whole partition's heavy
/// path: the stage-B INFO parse and emit, the sort, and the Arrow and zstd parquet encode and
/// write. Together those dwarf the producer's sequential scan and stage-A extract. The
/// partition files are independent, so there is one worker per logical CPU.
fn worker_pool_size() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
}

/// Routes a `(chr, POS/block_range)` partition's extracted records to the worker pool, in
/// batches bounded by a byte budget rather than by the partition boundary.
///
/// Records arrive in monotonic `(chr, POS)` order, enforced upstream by
/// [`enforce_chr_pos_order`], so a partition's records are contiguous in the stream. The
/// batcher ships a batch whenever [`MAX_BATCH_BYTES`] is reached, and a final one when the
/// `(chr, group)` key advances or the VCF ends. Peak memory is therefore
/// `pool_size x (WORKER_QUEUE_DEPTH + 1) x MAX_BATCH_BYTES`, a constant times the core count,
/// instead of `in_flight_partitions x blockRange x density`, which `blockRange: 0` drives to
/// a whole chromosome.
///
/// A byte-triggered flush is deferred to the next `POS` boundary. Each batch is sorted
/// independently by `(POS, REF, ALT, POPULATION)` before being appended, and the parquet
/// footer declares the file sorted on those columns, which `validate_parquet`'s uniqueness
/// scan relies on to find duplicates adjacent. Splitting one `POS` group across two
/// independently sorted batches would break both. A `POS` group is bounded by the alleles at
/// a single coordinate, so deferring overshoots the budget only slightly.
struct PartitionBatcher {
    /// Index of the VCF being read, so the shared pool can route results back.
    vcf_idx: usize,
    /// This VCF's shared context, the population fields and vcfid, stamped onto every batch.
    ctx: Arc<VcfContext>,
    /// Position block size. The group is `POS / block_range`, or `0` when `block_range` is 0.
    block_range: u32,
    /// The open partition's `(chr, group)` key, or `None` before the first record.
    current: Option<(Arc<str>, u64)>,
    /// Buffered records for the open batch (moved out on every ship).
    buf: Vec<Extracted>,
    /// `approx_bytes` of everything in `buf`.
    buf_bytes: usize,
    /// Ship once `buf_bytes` reaches this.
    max_batch_bytes: usize,
    /// The `POS` of the last buffered record, so a deferred flush can wait for it to advance.
    last_pos: Option<i32>,
    /// The budget was reached; ship as soon as `POS` advances.
    pending_flush: bool,
    /// Monotonic per-VCF partition index, so a worker's error can be ordered by partition.
    seq: usize,
    /// One channel per worker; a partition is pinned to `route_partition`'s worker so its
    /// open `ArrowWriter` is owned by exactly one thread and needs no lock.
    txs: Vec<SyncSender<PartitionBatch>>,
}

/// The partition group for a 0-based position under `block_range` (group `0` when
/// `block_range == 0`).
///
/// The `(chr, POS/block_range)` partitioning is defined here alone. The convert batcher
/// routes each row to its file by this value, and the parquet validator
/// ([`crate::validate_parquet`]) re-derives it to prove every `allele-freq.*` file's rows
/// fall in the block its filename names. Keeping both sides on one function makes them
/// unable to drift.
pub(crate) fn partition_group(pos0: i32, block_range: u32) -> u64 {
    if block_range == 0 {
        0
    } else {
        // POS is always >= 0 (a 0-based position from a 1-based VCF POS >= 1).
        u64::try_from(pos0).unwrap_or(0) / u64::from(block_range)
    }
}

impl PartitionBatcher {
    /// A batcher for one VCF, with no partition open and nothing buffered yet.
    fn new(
        vcf_idx: usize,
        ctx: Arc<VcfContext>,
        block_range: u32,
        max_batch_bytes: usize,
        txs: Vec<SyncSender<PartitionBatch>>,
    ) -> Self {
        Self {
            vcf_idx,
            ctx,
            block_range,
            max_batch_bytes,
            txs,
            current: None,
            buf: Vec::new(),
            buf_bytes: 0,
            last_pos: None,
            pending_flush: false,
            seq: 0,
        }
    }

    /// The partition group for a 0-based position; `0` when `block_range` is 0.
    fn group_of(&self, pos: i32) -> u64 {
        partition_group(pos, self.block_range)
    }

    /// Buffer one extracted record, shipping a batch first when the partition key advances
    /// or when the byte budget was reached and `POS` has moved on.
    fn push(&mut self, ex: Extracted) -> CoreResult<()> {
        let group = self.group_of(ex.pos0);
        let same = matches!(&self.current, Some((chr, g)) if *chr == ex.chr && *g == group);
        if same {
            // Deferred budget flush, only ever between POS groups; see the struct docs.
            if self.pending_flush && self.last_pos != Some(ex.pos0) {
                self.ship(false)?;
            }
        } else {
            self.flush()?;
            self.current = Some((Arc::clone(&ex.chr), group));
            self.seq += 1;
            self.last_pos = None;
            self.pending_flush = false;
        }
        self.last_pos = Some(ex.pos0);
        self.buf_bytes += ex.approx_bytes();
        self.buf.push(ex);
        if self.buf_bytes >= self.max_batch_bytes {
            self.pending_flush = true;
        }
        Ok(())
    }

    /// Ship the buffered records as one batch of the open partition.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InternalError`] if the routed worker has stopped, for instance
    /// after a write error. The caller then joins the pool to surface the root cause.
    fn ship(&mut self, is_final: bool) -> CoreResult<()> {
        let Some((chr, group)) = self.current.clone() else {
            return Ok(());
        };
        // A non-final batch with nothing buffered carries no information. A final one must
        // still reach the worker, to close a writer an earlier batch opened.
        if self.buf.is_empty() && !is_final {
            return Ok(());
        }
        let records = std::mem::take(&mut self.buf);
        self.buf_bytes = 0;
        self.pending_flush = false;
        let worker = route_partition(self.vcf_idx, &chr, group, self.txs.len());
        self.txs[worker]
            .send(PartitionBatch {
                vcf_idx: self.vcf_idx,
                seq: self.seq,
                chr,
                group,
                records,
                ctx: Arc::clone(&self.ctx),
                is_final,
            })
            .map_err(|_| CoreError::InternalError {
                detail: "parquet worker pool stopped before a partition was sent".to_string(),
            })
    }

    /// Close the open partition: ship its final batch (possibly empty, to close a writer an
    /// earlier byte-budget batch opened) and reset. A no-op when no partition is open.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InternalError`] if the routed worker has already stopped, for
    /// instance after a write error. The caller then joins the pool to surface the root cause.
    fn flush(&mut self) -> CoreResult<()> {
        if self.current.is_none() {
            return Ok(());
        }
        self.ship(true)?;
        self.current = None;
        self.last_pos = None;
        Ok(())
    }
}

/// A partition whose parquet writer stays open across several batches.
///
/// The batcher ships a partition in byte-bounded chunks, so a worker accumulates the
/// partition's scan-wide contributions here and appends each batch's rows as a row group.
/// `ArrowWriter::write` appends and closes row groups by size, and every batch's rows are
/// sorted and strictly after the previous batch's, because records arrive POS-ordered and a
/// batch boundary never splits a POS group. The file's declared
/// `(POS, REF, ALT, POPULATION)` sort therefore holds across the whole file.
struct OpenPartition {
    writer: ArrowWriter<File>,
    path: PathBuf,
    chr: String,
    group: u64,
    distinct: DistinctKeyCounter,
    pops: BTreeSet<Arc<str>>,
    no_af: BTreeSet<String>,
    suppression: SuppressionCounts,
    rows_written: u64,
    records_emitted: u64,
    records_all_rows_withheld: u64,
    records_no_af: u64,
    total_af_zero_variants: u64,
}

/// The key identifying a partition across the batches that make it up.
type PartitionKey = (usize, Arc<str>, u64);

/// The write-side configuration shared by every partition of a build: where the files go, the
/// `blockRange` their names carry, and the pinned Arrow schema and parquet writer properties.
/// Borrowed as one `Copy` value, because the four travel together from [`convert_vcf_group`]
/// through each worker to [`create_partition_writer`].
#[derive(Clone, Copy)]
struct WriterConfig<'a> {
    out_dir: &'a Path,
    block_range: u32,
    schema: &'a SchemaRef,
    props: &'a WriterProperties,
}

/// One worker: drain its own receiver and convert each batch — stage-B emit, sort, parquet
/// encode and append — concurrently with the other workers and the producers' scans.
///
/// Each worker owns a private channel rather than sharing one behind a mutex, because a
/// partition is delivered as several batches that must all reach the same worker. That worker
/// holds the partition's open `ArrowWriter`, so appending needs no lock, and FIFO delivery
/// keeps the batches in order. [`route_partition`] pins the mapping.
///
/// Returns each partition's `(vcf_idx, seq, result)` and does not stop on a per-partition
/// error, because it must keep draining or a producer stalls. The caller picks the
/// lowest-`seq` error.
///
/// A per-batch panic is caught and turned into an error result rather than killing the
/// worker: a producer blocks on `send` until its worker drains, so a dead worker would
/// deadlock it. The partition's writer is dropped, leaving a partial file that the failed
/// build removes with its staging dir, and its remaining batches are skipped.
fn process_partitions(
    rx: &Receiver<PartitionBatch>,
    opts: &ConvertOptions,
    writer_cfg: WriterConfig<'_>,
) -> Vec<(usize, usize, CoreResult<PartitionOutput>)> {
    // Per-worker reused emit scratch: one allocation for this worker's whole lifetime.
    let mut by_pop: HashMap<Arc<str>, Stats> = HashMap::new();
    let mut emit = RecordEmit::default();
    let mut open: HashMap<PartitionKey, OpenPartition> = HashMap::new();
    let mut failed: BTreeSet<PartitionKey> = BTreeSet::new();
    let mut results = Vec::new();

    // `recv` errors once every sender is dropped: the scan is finished and this worker ends.
    while let Ok(batch) = rx.recv() {
        let key: PartitionKey = (batch.vcf_idx, Arc::clone(&batch.chr), batch.group);
        if failed.contains(&key) {
            // An earlier batch of this partition already reported its error.
            if batch.is_final {
                failed.remove(&key);
            }
            continue;
        }
        // `by_pop` and `emit` are cleared at the start of every reuse, so a partial state
        // left by a panic is harmless, which is the unwind safety `catch_decode_panic`
        // asserts. Routed through that chokepoint rather than a bare `catch_unwind`, so the
        // process-level hook knows the panic is expected and does not print it raw.
        let outcome = crate::panic_guard::catch_decode_panic(
            || {
                absorb_batch(
                    &mut open,
                    &key,
                    &batch,
                    opts,
                    writer_cfg,
                    &mut by_pop,
                    &mut emit,
                )
            },
            || CoreError::InternalError {
                detail: format!(
                    "panic while converting partition chr{}.{}",
                    batch.chr, batch.group
                ),
            },
        );

        match outcome {
            Err(e) => {
                open.remove(&key);
                if !batch.is_final {
                    failed.insert(key);
                }
                results.push((batch.vcf_idx, batch.seq, Err(e)));
            }
            Ok(()) if batch.is_final => {
                let finished = open.remove(&key).map_or_else(
                    || {
                        Err(CoreError::InternalError {
                            detail: "final partition batch with no open writer".to_string(),
                        })
                    },
                    close_partition,
                );
                results.push((batch.vcf_idx, batch.seq, finished));
            }
            Ok(()) => {}
        }
    }
    results
}

/// Emit one batch's rows into its partition's open writer, opening the writer on the first
/// batch. Folds the batch's tallies into the partition's running totals.
fn absorb_batch(
    open: &mut HashMap<PartitionKey, OpenPartition>,
    key: &PartitionKey,
    batch: &PartitionBatch,
    opts: &ConvertOptions,
    writer_cfg: WriterConfig<'_>,
    by_pop: &mut HashMap<Arc<str>, Stats>,
    emit: &mut RecordEmit,
) -> CoreResult<()> {
    let mut rows: Vec<OutRow> = Vec::new();
    let mut distinct_keys: Vec<RecordKey> = Vec::new();
    let mut no_af: BTreeSet<String> = BTreeSet::new();
    let mut suppression = SuppressionCounts::default();
    let mut records_emitted = 0u64;
    let mut records_all_rows_withheld = 0u64;
    let mut records_no_af = 0u64;
    let mut total_af_zero_variants = 0u64;
    for ex in &batch.records {
        emit_extracted(ex, &batch.ctx.pop_fields, opts, by_pop, emit)?;
        // Read before the drain below empties `emit.rows`.
        if emit.rows.is_empty() {
            if floor_emptied_the_record(&emit.suppression) {
                records_all_rows_withheld += 1;
            } else {
                records_no_af += 1;
            }
        } else {
            records_emitted += 1;
        }
        rows.append(&mut emit.rows);
        suppression.add(emit.suppression);
        total_af_zero_variants += emit.total_af_zero;
        distinct_keys.append(&mut emit.keys);
        for pop in emit.no_af.drain(..) {
            no_af.insert(pop.to_string());
        }
    }
    // A total, stable order, so the parquet bytes and the manifest's per-file sha256 are
    // reproducible: rows sharing a POS are otherwise in the `by_pop` map's arbitrary order.
    // `chr` is constant within a partition, so the key is (POS, REF, ALT, POPULATION).
    // Sorting per batch gives a file-wide order, because a batch boundary never splits a POS
    // group.
    rows.sort_by(|a, b| {
        (a.pos, &a.ref_, &a.alt, &a.population).cmp(&(b.pos, &b.ref_, &b.alt, &b.population))
    });

    let partition = match open.entry(key.clone()) {
        std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
        std::collections::hash_map::Entry::Vacant(e) => {
            let (writer, path) =
                create_partition_writer(writer_cfg, &batch.ctx.vcfid, &batch.chr, batch.group)?;
            e.insert(OpenPartition {
                writer,
                path,
                chr: batch.chr.to_string(),
                group: batch.group,
                distinct: DistinctKeyCounter::default(),
                pops: BTreeSet::new(),
                no_af: BTreeSet::new(),
                suppression: SuppressionCounts::default(),
                rows_written: 0,
                records_emitted: 0,
                records_all_rows_withheld: 0,
                records_no_af: 0,
                total_af_zero_variants: 0,
            })
        }
    };

    for k in &distinct_keys {
        partition.distinct.add(k);
    }
    partition
        .pops
        .extend(rows.iter().map(|r| Arc::clone(&r.population)));
    partition.no_af.extend(no_af);
    partition.suppression.add(suppression);
    partition.rows_written += rows.len() as u64;
    partition.records_emitted += records_emitted;
    partition.records_all_rows_withheld += records_all_rows_withheld;
    partition.records_no_af += records_no_af;
    partition.total_af_zero_variants += total_af_zero_variants;

    if !rows.is_empty() {
        let arrow_batch = build_batch(writer_cfg.schema, &rows)?;
        partition
            .writer
            .write(&arrow_batch)
            .map_err(|e| invalid_parquet(format!("parquet write failed: {e}")))?;
    }
    Ok(())
}

/// Close a partition's writer and turn its running totals into a [`PartitionOutput`].
///
/// # Errors
///
/// Returns [`CoreError::InvalidParquet`] if the parquet footer cannot be written.
fn close_partition(partition: OpenPartition) -> CoreResult<PartitionOutput> {
    let OpenPartition {
        writer,
        path,
        chr,
        group,
        distinct,
        pops,
        no_af,
        suppression,
        rows_written,
        records_emitted,
        records_all_rows_withheld,
        records_no_af,
        total_af_zero_variants,
    } = partition;
    writer
        .close()
        .map_err(|e| invalid_parquet(format!("parquet close failed: {e}")))?;
    // The writer opens on a partition's first batch, before anyone knows whether the floor
    // will leave that partition any rows. Close it with none written and you get a parquet
    // with zero row groups, hence no offset index, which every ingest-path reader rejects
    // (`enforce_page_size_caps` fails closed on a missing index), so the build's own
    // validation would reject the file the build just wrote. The rows are already in the
    // drop counts; the file is not part of the dataset.
    let path = if rows_written == 0 {
        std::fs::remove_file(&path)?;
        None
    } else {
        Some(path)
    };
    Ok(PartitionOutput {
        chr,
        group,
        path,
        distinct_variants: distinct.count,
        pops,
        no_af,
        suppression,
        rows_written,
        records_emitted,
        records_all_rows_withheld,
        records_no_af,
        total_af_zero_variants,
    })
}

/// The file name holding one `(chr, group)` partition of the source VCF `vcfid`.
///
/// The single producer of the data-file naming contract. [`partition_block_key`] is its
/// inverse for the block half, and `partition_file_name_round_trips_through_its_block_key`
/// pins the two together, so a name format cannot change in one place and be read in another.
pub(crate) fn partition_file_name(chr: &str, group: u64, block_range: u32, vcfid: &str) -> String {
    format!("allele-freq.chr{chr}.{group}.br{block_range}.{vcfid}.parquet")
}

/// The block a partition file belongs to: its name with the per-VCF `{vcfid}` removed, or
/// `None` if `file_name` is not a partition file.
///
/// Two files sharing a block key came from different source VCFs covering the same
/// positions: the per-population split shape, which the serving node cannot stream and must
/// buffer whole. The build uses this to say so at the one moment the provider can still
/// choose a different layout.
#[must_use]
pub fn partition_block_key(file_name: &str) -> Option<String> {
    // `allele-freq . chr{chr} . {group} . br{block_range} . {vcfid} . parquet`
    let rest = file_name
        .strip_prefix("allele-freq.")?
        .strip_suffix(".parquet")?;
    let (block, vcfid) = rest.rsplit_once('.')?;
    // A vcfid is a hex digest prefix; anything else means the name is not this tool's.
    if vcfid.is_empty() || !vcfid.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    // chr, group and br must all be present, or this is some other `allele-freq.*` file.
    if block.split('.').count() != 3 {
        return None;
    }
    Some(block.to_owned())
}

/// Create a partition's parquet file and its `ArrowWriter`, returning both.
#[expect(
    clippy::disallowed_methods,
    reason = "the staging directory is packaged or renamed as a whole, so a torn file is never served"
)]
fn create_partition_writer(
    writer_cfg: WriterConfig<'_>,
    vcfid: &str,
    chr: &str,
    group: u64,
) -> CoreResult<(ArrowWriter<File>, PathBuf)> {
    let block_range = writer_cfg.block_range;
    let file_name = partition_file_name(chr, group, block_range, vcfid);
    let path = writer_cfg.out_dir.join(&file_name);
    let file = File::create(&path)?;
    let writer = ArrowWriter::try_new(
        file,
        Arc::clone(writer_cfg.schema),
        Some(writer_cfg.props.clone()),
    )
    .map_err(|e| invalid_parquet(format!("parquet writer creation failed: {e}")))?;
    Ok((writer, path))
}

/// Build an Arrow [`RecordBatch`] for one partition's rows.
fn build_batch(schema: &SchemaRef, rows: &[OutRow]) -> CoreResult<RecordBatch> {
    let mut pos = Int32Builder::with_capacity(rows.len());
    // Pre-size the string builders as the numeric ones already are: a capacity hint per
    // column avoids the regrow-and-copy as rows append. The byte estimates are small,
    // because REF, ALT, VT and POPULATION are short tokens.
    let mut ref_ = StringBuilder::with_capacity(rows.len(), rows.len() * 4);
    let mut alt = StringBuilder::with_capacity(rows.len(), rows.len() * 4);
    let mut vt = StringBuilder::with_capacity(rows.len(), rows.len() * 3);
    let mut population = StringBuilder::with_capacity(rows.len(), rows.len() * 8);
    let mut af = Float32Builder::with_capacity(rows.len());
    let mut ac = Int32Builder::with_capacity(rows.len());
    let mut ac_hom = Int32Builder::with_capacity(rows.len());
    let mut ac_het = Int32Builder::with_capacity(rows.len());
    let mut ac_hemi = Int32Builder::with_capacity(rows.len());
    let mut an = Int32Builder::with_capacity(rows.len());

    for row in rows {
        pos.append_value(row.pos);
        ref_.append_value(row.ref_.as_ref());
        alt.append_value(row.alt.as_ref());
        vt.append_value(row.vt);
        population.append_value(row.population.as_ref());
        af.append_value(row.af);
        ac.append_option(row.ac);
        ac_hom.append_option(row.ac_hom);
        ac_het.append_option(row.ac_het);
        ac_hemi.append_option(row.ac_hemi);
        an.append_option(row.an);
    }

    let columns: Vec<ArrayRef> = vec![
        Arc::new(pos.finish()),
        Arc::new(ref_.finish()),
        Arc::new(alt.finish()),
        Arc::new(vt.finish()),
        Arc::new(population.finish()),
        Arc::new(af.finish()),
        Arc::new(ac.finish()),
        Arc::new(ac_hom.finish()),
        Arc::new(ac_het.finish()),
        Arc::new(ac_hemi.finish()),
        Arc::new(an.finish()),
    ];

    RecordBatch::try_new(Arc::clone(schema), columns)
        .map_err(|e| invalid_parquet(format!("record batch assembly failed: {e}")))
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use std::io::Write as _;

    use arrow_array::Array as _;
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    use super::*;

    #[test]
    fn parse_af_enforces_the_closed_unit_interval() {
        // AF is a served allele frequency, so its [0, 1] domain must be exact. The
        // endpoints 0.0 and 1.0 are valid; a negative, greater-than-one, non-finite or
        // non-numeric AF is rejected.
        assert!(
            parse_af("0", "AF").unwrap().abs() < 1e-6,
            "AF 0 must parse to 0.0"
        );
        assert!(
            (parse_af("1", "AF").unwrap() - 1.0).abs() < 1e-6,
            "AF 1 must parse to 1.0"
        );
        assert!((parse_af("0.077", "AF").unwrap() - 0.077).abs() < 1e-6);
        assert!(
            parse_af("-0.5", "AF").is_err(),
            "negative AF must be rejected"
        );
        assert!(parse_af("1.5", "AF").is_err(), "AF > 1 must be rejected");
        assert!(
            parse_af("nan", "AF").is_err(),
            "non-finite AF must be rejected"
        );
        assert!(
            parse_af("x", "AF").is_err(),
            "non-numeric AF must be rejected"
        );
    }

    #[test]
    fn parse_info_map_parses_real_fields_not_just_the_dot_sentinel() {
        // The early return covers only the empty and `.` sentinels; a real INFO string must
        // yield its key-to-value map. Inverting that condition would return an empty map for
        // every real INFO and parse no metrics at all.
        let m = parse_info_map("AC=5;AF=0.1;AN=100");
        assert_eq!(m.get("AC"), Some(&"5"));
        assert_eq!(m.get("AF"), Some(&"0.1"));
        assert_eq!(m.get("AN"), Some(&"100"));
        assert!(parse_info_map(".").is_empty());
        assert!(parse_info_map("").is_empty());
    }

    /// Write `contents` to a `*.vcf` in `dir` and return its path.
    fn write_vcf(dir: &Path, contents: &str) -> PathBuf {
        let path = dir.join("in.vcf");
        let mut f = File::create(&path).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        path
    }

    /// Write `contents` bgzf-compressed to a `*.vcf.gz` in `dir` and return its path.
    fn write_bgzf_vcf(dir: &Path, contents: &str) -> PathBuf {
        let path = dir.join("in.vcf.gz");
        let mut w = noodles_bgzf::io::Writer::new(File::create(&path).unwrap());
        w.write_all(contents.as_bytes()).unwrap();
        w.finish().unwrap();
        path
    }

    /// Consume a whole VCF through the counting reader and return the compressed on-disk
    /// bytes the callback observed.
    fn count_full_read(path: &Path) -> u64 {
        let count = std::cell::Cell::new(0u64);
        {
            let mut reader = open_reader(path, |n| count.set(count.get() + n), None).unwrap();
            let _header = reader.read_header().unwrap();
            let mut record = vcf::Record::default();
            while reader.read_record(&mut record).unwrap() != 0 {}
        }
        count.get()
    }

    #[test]
    fn open_reader_counts_whole_file_plain_and_bgzf() {
        let dir = tempfile::tempdir().unwrap();
        let vcf = "##fileformat=VCFv4.2\n##contig=<ID=chr1>\n\
                   #CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";

        // Plain `.vcf`: counter sits on the raw file, so it must equal the file size.
        let plain = write_vcf(dir.path(), vcf);
        let plain_size = std::fs::metadata(&plain).unwrap().len();
        assert_eq!(count_full_read(&plain), plain_size);

        // bgzf `.vcf.gz`: the counter sits below the bgzf decoder, so it must equal the
        // compressed file size, since the whole compressed stream is consumed to reach EOF.
        let gz = write_bgzf_vcf(dir.path(), vcf);
        let gz_size = std::fs::metadata(&gz).unwrap().len();
        assert_eq!(count_full_read(&gz), gz_size);
    }

    #[test]
    fn counting_reader_reports_each_read_and_passes_bytes_through() {
        use std::io::Read as _;
        let data = b"hello, counting reader \x00\xff payload";
        let count = std::cell::Cell::new(0u64);
        let mut out = Vec::new();
        {
            let mut reader = CountingReader::new(&data[..], |n| count.set(count.get() + n));
            // A tiny buffer forces several non-empty reads plus a final EOF read, which
            // must not fire the callback, so the total still equals the byte count.
            let mut buf = [0u8; 7];
            loop {
                let n = reader.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n]);
            }
        }
        assert_eq!(out, data, "bytes must pass through unchanged");
        assert_eq!(
            count.get(),
            data.len() as u64,
            "callback total == bytes read"
        );
    }

    /// The canonical 18-byte BGZF block header: gzip magic, deflate, the FEXTRA flag, then
    /// the `BC` extra subfield carrying the block size. That is what the reader needs; a
    /// plain-gzip VCF has the same magic but no FEXTRA flag and no `BC` subfield.
    const BGZF_HEADER: [u8; 18] = [
        0x1f, 0x8b, 0x08, 0x04, // magic, CM=deflate, FLG=FEXTRA
        0x00, 0x00, 0x00, 0x00, // MTIME
        0x00, 0xff, // XFL, OS
        0x06, 0x00, // XLEN = 6
        0x42, 0x43, // SI1='B', SI2='C'
        0x02, 0x00, // SLEN = 2
        0x1b, 0x00, // BSIZE
    ];

    #[test]
    fn preflight_rejects_format_extension_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        // Plain text named `.vcf.gz` → rejected (would fail mid-stream otherwise).
        let p1 = dir.path().join("a.vcf.gz");
        File::create(&p1)
            .unwrap()
            .write_all(b"##fileformat=VCFv4.2\n")
            .unwrap();
        let err = preflight_vcf_format(&p1).unwrap_err();
        assert!(format!("{err}").contains("not gzip-compressed"), "{err}");
        // Gzip magic named `.vcf` → rejected (the reader would read it as plain text).
        let p2 = dir.path().join("b.vcf");
        File::create(&p2).unwrap().write_all(&BGZF_HEADER).unwrap();
        let err = preflight_vcf_format(&p2).unwrap_err();
        assert!(format!("{err}").contains("no .gz extension"), "{err}");
        // Matching plain-text `.vcf` passes.
        let p3 = dir.path().join("c.vcf");
        File::create(&p3)
            .unwrap()
            .write_all(b"##fileformat=VCFv4.2\n")
            .unwrap();
        preflight_vcf_format(&p3).unwrap();
    }

    /// Anything before `##fileformat` is named for what it is, rather than reported as an
    /// empty file.
    ///
    /// The reader answers with an empty-input error for every such input whatever its size,
    /// including a small file with a valid header and a record. That names the one thing
    /// which is not wrong, so a provider inspects a file they will find is fine. Both inputs
    /// here are ordinary: a byte-order mark from a Windows editor or an Excel round-trip,
    /// invisible in most viewers, and blank lines from a copy-paste or a heredoc.
    #[test]
    fn preflight_names_leading_junk_instead_of_calling_the_file_empty() {
        let dir = tempfile::tempdir().unwrap();
        let header = b"##fileformat=VCFv4.2\n#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";

        // A UTF-8 BOM before the header.
        let bom = dir.path().join("bom.vcf");
        let mut f = File::create(&bom).unwrap();
        f.write_all(&[0xEF, 0xBB, 0xBF]).unwrap();
        f.write_all(header).unwrap();
        let err = format!("{}", preflight_vcf_format(&bom).unwrap_err());
        assert!(err.contains("byte-order mark"), "must name the BOM: {err}");
        assert!(
            err.contains("Strip it"),
            "must name the fix, not just the diagnosis: {err}"
        );

        // Leading blank lines before the header.
        let blank = dir.path().join("blank.vcf");
        let mut f = File::create(&blank).unwrap();
        f.write_all(b"\n\n").unwrap();
        f.write_all(header).unwrap();
        let err = format!("{}", preflight_vcf_format(&blank).unwrap_err());
        assert!(
            err.contains("blank or whitespace lines"),
            "must name the blank lines: {err}"
        );

        // A well-formed header still passes: the guard must not reject real VCFs.
        let good = dir.path().join("good.vcf");
        File::create(&good).unwrap().write_all(header).unwrap();
        preflight_vcf_format(&good).unwrap();
    }

    #[test]
    fn preflight_rejects_plain_gzip_with_an_actionable_bgzip_message() {
        // A plain `gzip file.vcf` produces a file with the same magic and `.vcf.gz` name as
        // bgzip, so it passes both extension guards and reaches the bgzf reader, which fails
        // with an opaque buffer error. Plain gzip sets no FEXTRA flag and carries no `BC`
        // subfield, so it is caught here with a message naming `bgzip`.
        let dir = tempfile::tempdir().unwrap();
        // `gzip` default output: FLG has FNAME (0x08), never FEXTRA (0x04).
        let plain_gzip = [0x1f, 0x8b, 0x08, 0x08, 0x00, 0x00, 0x00, 0x00];
        for ext in ["p.vcf.gz", "p.vcf.bgz"] {
            let p = dir.path().join(ext);
            File::create(&p).unwrap().write_all(&plain_gzip).unwrap();
            let err = preflight_vcf_format(&p).unwrap_err();
            let msg = format!("{err}");
            assert!(
                msg.contains("bgzip") && msg.to_lowercase().contains("bgzf"),
                "{ext}: a plain-gzip VCF must be named as such and point at bgzip: {msg}"
            );
        }
    }

    #[test]
    fn preflight_accepts_bgzip_family_extensions() {
        // The bgzip-family extension set is `gz`, `bgz` or `bgzf`. Regrouping those
        // alternatives collapses the set to `gz` alone, which would wrongly reject a real
        // `.bgz` or `.bgzf` VCF as having no `.gz` extension.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.vcf.bgz");
        File::create(&p).unwrap().write_all(&BGZF_HEADER).unwrap();
        preflight_vcf_format(&p).expect("a BGZF .vcf.bgz must be accepted");
    }

    /// Convert with the default GRCh38/10Mb/no-floor options.
    fn convert(dir: &Path, vcf: &Path, min_allele_count: u32) -> CoreResult<ConvertOutput> {
        let out = dir.join("out");
        convert_vcf(
            vcf,
            &out,
            &ConvertOptions {
                assembly: "GRCh38".into(),
                block_range: 10_000_000,
                min_allele_count,
            },
        )
    }

    /// The digest folded into the conversion read must be byte-identical to an independent
    /// full-file SHA-256. The `vcfid` is that digest's prefix and is embedded in every
    /// partition filename and in the manifest, so any divergence corrupts the package. Also
    /// asserts the write-time placeholder was renamed away.
    #[test]
    fn folded_source_digest_equals_a_standalone_hash_and_leaves_no_placeholder() {
        let dir = tempfile::tempdir().unwrap();
        let vcf = write_vcf(
            dir.path(),
            &format!(
                "{HDR_AF_A}3\t100\t.\tA\tG\t.\t.\tAF=0.5;AC=5;AN=10\n\
3\t15000000\t.\tA\tG\t.\t.\tAF=0.3;AC=3;AN=10\n"
            ),
        );
        let out = convert(dir.path(), &vcf, 0).unwrap();

        let (independent, size) =
            crate::util::sha256_hex_reader(std::fs::File::open(&vcf).unwrap()).unwrap();
        assert_eq!(
            out.source_sha256, independent,
            "read-folded digest must equal a standalone full-file hash"
        );
        assert_eq!(out.source_size, size);
        // The vcfid is the digest's 16-character prefix, checked without a `str` slice,
        // which the crate lints against.
        assert_eq!(out.vcfid.len(), VCFID_HEX_LEN);
        assert!(independent.starts_with(&out.vcfid));

        for path in &out.parquet_files {
            let name = path.file_name().unwrap().to_str().unwrap();
            assert!(
                name.contains(&out.vcfid),
                "file not renamed to vcfid: {name}"
            );
            assert!(!name.contains("pending"), "placeholder leaked: {name}");
        }
    }

    /// The digest's whole-file guarantee must not depend on the reader consuming to EOF:
    /// `finalize_source_digest` drains any unread tail. Simulates a reader that stopped after
    /// the first few bytes and asserts the finalized digest still equals the whole file's.
    #[test]
    fn finalize_source_digest_drains_an_unread_tail() {
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("src.bin");
        let bytes: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        std::fs::File::create(&path)
            .unwrap()
            .write_all(&bytes)
            .unwrap();

        // A state that hashed only the first 10 bytes, as if the reader stopped early.
        let mut hasher = Sha256::new();
        hasher.update(&bytes[..10]);
        let state = Rc::new(RefCell::new(DigestState { hasher, bytes: 10 }));

        let (hex, size) = finalize_source_digest(&path, state, bytes.len() as u64).unwrap();
        let (want, want_size) =
            crate::util::sha256_hex_reader(std::fs::File::open(&path).unwrap()).unwrap();
        assert_eq!(size, want_size);
        assert_eq!(hex, want, "the drain must recover the whole-file digest");
    }

    /// Read every (POS, REF, ALT, POPULATION, AF, AC) tuple from the output.
    fn read_rows(files: &[PathBuf]) -> Vec<(i32, String, String, String, f32, Option<i32>)> {
        let mut out = Vec::new();
        for path in files {
            let file = File::open(path).unwrap();
            #[expect(
                clippy::disallowed_methods,
                reason = "test fixture: this reads a parquet the test itself just wrote, so the Pages-vs-Values distinction the ban exists for cannot arise; the ban targets production readers of UNTRUSTED parquet"
            )]
            let reader = ParquetRecordBatchReaderBuilder::try_new(file)
                .unwrap()
                .build()
                .unwrap();
            for batch in reader {
                let batch = batch.unwrap();
                let pos = batch
                    .column_by_name("POS")
                    .unwrap()
                    .as_any()
                    .downcast_ref::<arrow_array::Int32Array>()
                    .unwrap();
                let r = batch
                    .column_by_name("REF")
                    .unwrap()
                    .as_any()
                    .downcast_ref::<arrow_array::StringArray>()
                    .unwrap();
                let a = batch
                    .column_by_name("ALT")
                    .unwrap()
                    .as_any()
                    .downcast_ref::<arrow_array::StringArray>()
                    .unwrap();
                let p = batch
                    .column_by_name("POPULATION")
                    .unwrap()
                    .as_any()
                    .downcast_ref::<arrow_array::StringArray>()
                    .unwrap();
                let af = batch
                    .column_by_name("AF")
                    .unwrap()
                    .as_any()
                    .downcast_ref::<arrow_array::Float32Array>()
                    .unwrap();
                let ac = batch
                    .column_by_name("AC")
                    .unwrap()
                    .as_any()
                    .downcast_ref::<arrow_array::Int32Array>()
                    .unwrap();
                for i in 0..batch.num_rows() {
                    out.push((
                        pos.value(i),
                        r.value(i).to_string(),
                        a.value(i).to_string(),
                        p.value(i).to_string(),
                        af.value(i),
                        if ac.is_null(i) {
                            None
                        } else {
                            Some(ac.value(i))
                        },
                    ));
                }
            }
        }
        out
    }

    /// Read `(REF, ALT, VT)` for every emitted row, keyed by POS.
    fn read_vt_by_pos(
        files: &[PathBuf],
    ) -> std::collections::BTreeMap<i32, (String, String, String)> {
        let mut by_pos = std::collections::BTreeMap::new();
        for path in files {
            let file = File::open(path).unwrap();
            #[expect(
                clippy::disallowed_methods,
                reason = "test fixture: this reads a parquet the test itself just wrote, so the Pages-vs-Values distinction the ban exists for cannot arise; the ban targets production readers of UNTRUSTED parquet"
            )]
            let reader = ParquetRecordBatchReaderBuilder::try_new(file)
                .unwrap()
                .build()
                .unwrap();
            for batch in reader {
                let batch = batch.unwrap();
                let str_col = |name: &str| {
                    batch
                        .column_by_name(name)
                        .unwrap()
                        .as_any()
                        .downcast_ref::<arrow_array::StringArray>()
                        .unwrap()
                        .clone()
                };
                let pos = batch
                    .column_by_name("POS")
                    .unwrap()
                    .as_any()
                    .downcast_ref::<arrow_array::Int32Array>()
                    .unwrap()
                    .clone();
                let (r, a, vt) = (str_col("REF"), str_col("ALT"), str_col("VT"));
                for i in 0..batch.num_rows() {
                    by_pos.insert(
                        pos.value(i),
                        (
                            r.value(i).to_string(),
                            a.value(i).to_string(),
                            vt.value(i).to_string(),
                        ),
                    );
                }
            }
        }
        by_pos
    }

    const HDR_AF_A: &str = "##fileformat=VCFv4.1\n##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n##INFO=<ID=AC,Number=A,Type=Integer,Description=\"ac\">\n##INFO=<ID=AN,Number=1,Type=Integer,Description=\"an\">\n##contig=<ID=3>\n#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";

    #[test]
    fn convert_vcf_group_reports_bytes_read_per_source() {
        use std::sync::atomic::AtomicU64;
        let dir = tempfile::tempdir().unwrap();
        // Two plain VCFs of different sizes, so per-index attribution is observable. Each is
        // fully consumed by conversion, so its on_bytes total must equal its size on disk.
        let write = |name: &str, rows: u32| -> PathBuf {
            let mut body = String::new();
            for i in 0..rows {
                let pos = i * 100 + 1;
                let _ = std::fmt::Write::write_fmt(
                    &mut body,
                    format_args!("3\t{pos}\t.\tA\tG\t.\t.\tAF=0.50\n"),
                );
            }
            let path = dir.path().join(name);
            File::create(&path)
                .unwrap()
                .write_all(format!("{HDR_AF_A}{body}").as_bytes())
                .unwrap();
            path
        };
        let small = write("small.vcf", 5);
        let large = write("large.vcf", 200);
        let sources = vec![small.clone(), large.clone()];
        let opts = ConvertOptions {
            assembly: "GRCh38".into(),
            block_range: 10_000_000,
            min_allele_count: 0,
        };
        let totals = [AtomicU64::new(0), AtomicU64::new(0)];

        let results = convert_vcf_group(
            &sources,
            &dir.path().join("out"),
            &opts,
            2,
            &|_| {},
            &|i, n| {
                totals[i].fetch_add(n, Ordering::Relaxed);
            },
        )
        .unwrap();

        assert!(results.iter().all(Result::is_ok), "both VCFs convert");
        assert_eq!(
            totals[0].load(Ordering::Relaxed),
            std::fs::metadata(&small).unwrap().len(),
            "small VCF byte total == file size"
        );
        assert_eq!(
            totals[1].load(Ordering::Relaxed),
            std::fs::metadata(&large).unwrap().len(),
            "large VCF byte total == file size"
        );
    }

    /// The dry run reports the same bytes the converter does.
    ///
    /// The scan is the whole runtime of a `preview`, and on a whole-chromosome VCF that is
    /// minutes of silence unless it reports progress. This test keeps the byte hook: a
    /// refactor that stops calling `on_bytes`, or that wires the reader back to a
    /// build-from-path reader with nothing to count, still passes every other preview test.
    /// Asserting the total equals the file size also catches a hook that fires for only part
    /// of the stream, which would draw a bar that stalls short of the end.
    #[test]
    fn preview_vcf_reports_every_byte_it_reads() {
        let dir = tempfile::tempdir().unwrap();
        let mut body = String::new();
        for i in 0..200_u32 {
            let pos = i * 100 + 1;
            let _ = std::fmt::Write::write_fmt(
                &mut body,
                format_args!("3\t{pos}\t.\tA\tG\t.\t.\tAF=0.50\n"),
            );
        }
        let path = dir.path().join("preview-bytes.vcf");
        File::create(&path)
            .unwrap()
            .write_all(format!("{HDR_AF_A}{body}").as_bytes())
            .unwrap();

        let opts = ConvertOptions {
            assembly: "GRCh38".into(),
            block_range: 10_000_000,
            min_allele_count: 0,
        };
        let total = std::cell::Cell::new(0_u64);
        let report =
            preview_vcf_with_progress(&path, &opts, &|n| total.set(total.get() + n)).unwrap();

        assert_eq!(report.number_of_records, 200, "every record previewed");
        assert_eq!(
            total.get(),
            std::fs::metadata(&path).unwrap().len(),
            "preview byte total == file size"
        );
    }

    /// The worker pool emits, sorts and encodes the independent partition files
    /// concurrently and in nondeterministic order, and the result must still be
    /// byte-identical across runs. Per-file bytes depend only on the stably sorted rows, and
    /// the file list is re-sorted by `(chr, group)`. Builds a VCF spanning several
    /// `(chr, block)` partitions, converts it twice, and asserts the parquet files match
    /// name for name and byte for byte.
    #[test]
    fn parallel_pool_is_deterministic_across_runs() {
        let dir = tempfile::tempdir().unwrap();
        let hdr = "##fileformat=VCFv4.1\n\
##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
##INFO=<ID=AF_FI,Number=A,Type=Float,Description=\"af fi\">\n\
##INFO=<ID=AF_NL,Number=A,Type=Float,Description=\"af nl\">\n\
##contig=<ID=3>\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";
        let mut body = String::new();
        // 1000 ascending variants straddling several 10 Mb blocks, so there are many
        // partition files and the worker pool fans out. Each carries three populations.
        for i in 0..1000u32 {
            let pos = i * 30_000 + 1;
            let af = 0.1 + f64::from(i % 7) * 0.01;
            let _ = std::fmt::Write::write_fmt(
                &mut body,
                format_args!("3\t{pos}\t.\tA\tG\t.\t.\tAF={af:.2};AF_FI={af:.2};AF_NL={af:.2}\n"),
            );
        }
        let vcf = write_vcf(dir.path(), &format!("{hdr}{body}"));
        let opts = ConvertOptions {
            assembly: "GRCh38".into(),
            block_range: 10_000_000,
            min_allele_count: 0,
        };

        let a = convert_vcf(&vcf, &dir.path().join("a"), &opts).unwrap();
        let b = convert_vcf(&vcf, &dir.path().join("b"), &opts).unwrap();
        assert_eq!(a.number_of_records, b.number_of_records);
        assert_eq!(a.number_of_records, 1000);

        let files = |d: &Path| -> std::collections::BTreeMap<String, Vec<u8>> {
            std::fs::read_dir(d)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|e| e.path().extension().is_some_and(|x| x == "parquet"))
                .map(|e| {
                    (
                        e.file_name().to_string_lossy().into_owned(),
                        std::fs::read(e.path()).unwrap(),
                    )
                })
                .collect()
        };
        let fa = files(&dir.path().join("a"));
        let fb = files(&dir.path().join("b"));
        assert!(
            fa.len() > 1,
            "expected several partition files, got {}",
            fa.len()
        );
        assert_eq!(
            fa, fb,
            "the parallel worker pool must produce byte-identical parquet across runs"
        );
    }

    /// The streaming writer flushes a partition when the `(chr, POS/block_range)` key
    /// advances, both across a block boundary within a chromosome and across a chromosome
    /// change. This exercises that boundary with two contigs and a within-contig block jump,
    /// asserting the full set of partition files is written and every file's rows are
    /// completely and stably sorted, which is the reproducibility invariant.
    #[test]
    fn streams_partitions_on_chr_and_block_boundaries() {
        let dir = tempfile::tempdir().unwrap();
        let hdr = "##fileformat=VCFv4.1\n\
##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
##INFO=<ID=AF_FI,Number=A,Type=Float,Description=\"af fi\">\n\
##contig=<ID=3>\n##contig=<ID=7>\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";
        // chr3 block 0 (POS 100, 200), chr3 block 1 (POS 15_000_000), chr7 block 0
        // (POS 100) → three (chr, block) partitions. Each record emits Total + FI.
        let body = "3\t100\t.\tT\tC\t.\t.\tAF=0.5;AF_FI=0.4\n\
3\t200\t.\tA\tG\t.\t.\tAF=0.6;AF_FI=0.55\n\
3\t15000000\t.\tA\tG\t.\t.\tAF=0.3;AF_FI=0.2\n\
7\t100\t.\tT\tC\t.\t.\tAF=0.1;AF_FI=0.05\n";
        let vcf = write_vcf(dir.path(), &format!("{hdr}{body}"));
        let out = convert(dir.path(), &vcf, 0).unwrap();

        // One file per (chr, block) partition.
        assert_eq!(
            out.parquet_files.len(),
            3,
            "one parquet file per (chr, block) partition: {:?}",
            out.parquet_files
        );
        // 4 records × 2 populations (Total, FI) = 8 rows total across all partitions.
        let rows = read_rows(&out.parquet_files);
        assert_eq!(rows.len(), 8);
        // 4 distinct (chr, POS, REF, ALT) keys.
        assert_eq!(out.number_of_records, 4);

        // Each partition file's rows are totally ordered by (POS, REF, ALT, POPULATION).
        for path in &out.parquet_files {
            let file_rows = read_rows(std::slice::from_ref(path));
            let mut sorted = file_rows.clone();
            sorted.sort_by(|a, b| (a.0, &a.1, &a.2, &a.3).cmp(&(b.0, &b.1, &b.2, &b.3)));
            assert_eq!(
                file_rows,
                sorted,
                "rows within a partition file must be stably sorted: {}",
                path.display()
            );
        }
    }

    /// Build a `PartitionBatcher` wired to one worker channel, for the two tests below.
    fn test_batcher(
        block_range: u32,
        max_batch_bytes: usize,
    ) -> (PartitionBatcher, Receiver<PartitionBatch>) {
        let (txs, rxs): (Vec<_>, Vec<_>) =
            (0..1).map(|_| sync_channel::<PartitionBatch>(4096)).unzip();
        let ctx = Arc::new(VcfContext {
            pop_fields: Vec::new(),
            vcfid: "testvcfid".to_owned(),
        });
        let batcher = PartitionBatcher::new(0, ctx, block_range, max_batch_bytes, txs);
        (batcher, rxs.into_iter().next().unwrap())
    }

    /// A minimal `Extracted` at `(chr, pos0)`; only chr/pos0 drive partitioning.
    fn test_extracted(chr: &str, pos0: i32) -> Extracted {
        Extracted {
            chr: Arc::from(chr),
            pos0,
            pos_1based: usize::try_from(pos0).unwrap() + 1,
            supported_alts: vec![SplitAllele {
                ref_: Arc::from("A"),
                alt: Arc::from("G"),
            }],
            values: Vec::new(),
        }
    }

    /// Each `(chr, group)` partition is closed with exactly one `is_final` batch, so a worker
    /// knows when to close that partition's parquet writer.
    #[test]
    fn batcher_closes_each_partition_with_one_final_batch() {
        let (mut batcher, rx) = test_batcher(10, usize::MAX);
        // chr1 block0 = 3, chr1 block1 = 2, chr2 block0 = 1, chr2 block3 = 4.
        for (chr, pos0) in [
            ("1", 0),
            ("1", 1),
            ("1", 2),
            ("1", 10),
            ("1", 11),
            ("2", 0),
            ("2", 30),
            ("2", 31),
            ("2", 32),
            ("2", 33),
        ] {
            batcher.push(test_extracted(chr, pos0)).unwrap();
        }
        batcher.flush().unwrap();
        drop(batcher); // drops the senders so `rx` terminates

        let sent: Vec<PartitionBatch> = rx.into_iter().collect();
        assert_eq!(sent.len(), 4, "one batch per (chr, group) partition");
        assert!(sent.iter().all(|b| b.is_final), "each closes its partition");
        let counts: Vec<usize> = sent.iter().map(|b| b.records.len()).collect();
        assert_eq!(counts, vec![3, 2, 1, 4]);
        // Every partition gets its own seq, so the merge can order errors by position.
        let seqs: Vec<usize> = sent.iter().map(|b| b.seq).collect();
        assert_eq!(seqs, vec![1, 2, 3, 4]);
    }

    /// Peak memory must be a constant, not `blockRange x density`, so the batcher ships on a
    /// byte budget and splits a partition across several batches.
    ///
    /// `block_range: 0`, the value `init` offers as one file per chromosome, is the case a
    /// flush-on-key-change batcher cannot handle: every record lands in group 0, so nothing
    /// flushes until EOF and the whole chromosome buffers.
    ///
    /// The split must never fall inside a POS group. Each batch is sorted independently and
    /// appended as its own row group, while the parquet footer declares the whole file sorted
    /// on `(POS, REF, ALT, POPULATION)`, and `validate_parquet`'s uniqueness scan relies on
    /// duplicates being adjacent. Splitting a POS group would break both.
    #[test]
    fn byte_budget_splits_a_partition_but_never_a_pos_group() {
        // Budget of 1 byte: every record trips the budget, so a flush happens at each POS
        // boundary and nowhere else.
        let (mut batcher, rx) = test_batcher(0, 1);
        // Three POS groups on one chromosome, of sizes 3, 2 and 1.
        let records = [
            ("1", 100),
            ("1", 100),
            ("1", 100),
            ("1", 200),
            ("1", 200),
            ("1", 300),
        ];
        let mut peak_bytes = 0usize;
        for (chr, pos0) in records {
            batcher.push(test_extracted(chr, pos0)).unwrap();
            peak_bytes = peak_bytes.max(batcher.buf_bytes);
        }
        batcher.flush().unwrap();
        drop(batcher);

        let sent: Vec<PartitionBatch> = rx.into_iter().collect();
        assert!(
            sent.len() > 1,
            "the byte budget must split the single blockRange=0 partition"
        );
        // Exactly one final batch: all of these are the same partition.
        assert_eq!(sent.iter().filter(|b| b.is_final).count(), 1);
        assert!(sent.last().unwrap().is_final);
        assert!(sent.iter().all(|b| b.seq == 1), "one partition, one seq");

        // No POS appears in two batches — the sort-order invariant.
        let mut seen_pos: BTreeSet<i32> = BTreeSet::new();
        for batch in &sent {
            let batch_pos: BTreeSet<i32> = batch.records.iter().map(|e| e.pos0).collect();
            for pos in &batch_pos {
                assert!(
                    seen_pos.insert(*pos),
                    "POS {pos} straddles two independently-sorted batches"
                );
            }
        }
        assert_eq!(seen_pos.len(), 3, "all three POS groups shipped");
        // Every record arrived exactly once.
        let total: usize = sent.iter().map(|b| b.records.len()).sum();
        assert_eq!(total, records.len());

        // The buffer only ever held one POS group beyond the budget, a bound set by the
        // alleles at a single coordinate rather than by the chromosome.
        let one_record = test_extracted("1", 1).approx_bytes();
        assert!(
            peak_bytes <= 3 * one_record,
            "buffered {peak_bytes} bytes; a POS group of 3 is the bound"
        );
    }

    /// Batch boundaries become parquet row-group boundaries. If the budget were derived from
    /// `pool_size`, a one-job build and a four-job build of the same VCF would write
    /// different bytes and different per-file digests, which
    /// `parallel_build_matches_sequential_build` forbids. The batcher must therefore read a
    /// constant, and every batcher in a build must agree on it.
    #[test]
    fn batch_budget_does_not_depend_on_the_core_count() {
        for pool in [1usize, 2, 4, 8, 16, 64] {
            let (txs, _rxs): (Vec<_>, Vec<_>) =
                (0..pool).map(|_| sync_channel::<PartitionBatch>(1)).unzip();
            let (batcher, _rx) = test_batcher(0, MAX_BATCH_BYTES);
            drop(txs);
            assert_eq!(
                batcher.max_batch_bytes, MAX_BATCH_BYTES,
                "pool {pool} must not change the batch budget"
            );
        }
    }

    #[test]
    fn preview_reports_fields_records_and_rows_without_writing() {
        let dir = tempfile::tempdir().unwrap();
        let vcf = write_vcf(
            dir.path(),
            &format!("{HDR_AF_A}3\t100\t.\tT\tC\t.\t.\tAF=0.5;AC=5;AN=10\n"),
        );
        let report = preview_vcf(
            &vcf,
            &ConvertOptions {
                assembly: "GRCh38".into(),
                block_range: 10_000_000,
                min_allele_count: 0,
            },
        )
        .unwrap();
        assert!(
            report.populations_recognized.contains(&"Total".to_owned()),
            "populations: {:?}",
            report.populations_recognized
        );
        assert!(
            report.recognized_fields.contains(&"AF".to_owned()),
            "recognized: {:?}",
            report.recognized_fields
        );
        assert_eq!(report.number_of_records, 1);
        assert_eq!(report.rows_emitted, 1);
        // Preview writes nothing: the temp dir still holds only the input VCF.
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.path())
            .collect();
        assert_eq!(entries, vec![vcf], "preview must not write any output");
    }

    #[test]
    fn preview_rejects_an_af_ac_an_incoherent_row_like_build() {
        // `preview` is record validation positioned before `build`, so it must run the same
        // AC/AF/AN coherence check. Without it `AF=0.9;AC=100;AN=1000`, where 0.9 of 1000 is
        // 900 rather than 100, previews clean and then hard-fails at build.
        let dir = tempfile::tempdir().unwrap();
        let vcf = write_vcf(
            dir.path(),
            &format!("{HDR_AF_A}3\t100\t.\tT\tC\t.\t.\tAF=0.9;AC=100;AN=1000\n"),
        );
        let err = preview_vcf(
            &vcf,
            &ConvertOptions {
                assembly: "GRCh38".into(),
                block_range: 10_000_000,
                min_allele_count: 0,
            },
        )
        .expect_err("an AF/AC/AN-incoherent VCF must fail preview, as it fails build");
        assert!(
            format!("{err}").contains("inconsistent with AC"),
            "the preview error must name the AC/AF/AN incoherence: {err}"
        );
    }

    #[test]
    fn drop_counts_track_unsupported_contig_and_symbolic_alts() {
        let dir = tempfile::tempdir().unwrap();
        let hdr = "##fileformat=VCFv4.1\n\
##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
##contig=<ID=3>\n##contig=<ID=hs37d5>\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";
        let vcf = write_vcf(
            dir.path(),
            &format!(
                "{hdr}3\t100\t.\tT\tC\t.\t.\tAF=0.5\n\
3\t200\t.\tT\t<DEL>\t.\t.\tAF=0.5\n\
hs37d5\t50\t.\tA\tG\t.\t.\tAF=0.5\n"
            ),
        );
        let report = preview_vcf(
            &vcf,
            &ConvertOptions {
                assembly: "GRCh38".into(),
                block_range: 10_000_000,
                min_allele_count: 0,
            },
        )
        .unwrap();
        assert_eq!(report.drops.input_records, 3, "three records were read");
        assert_eq!(
            report.drops.dropped_unsupported_contig, 1,
            "the hs37d5 decoy contig record is dropped"
        );
        assert_eq!(
            report.drops.dropped_no_supported_alt, 1,
            "the <DEL> symbolic-only record has no supported ALT"
        );
        assert_eq!(report.drops.total_dropped(), 2);
        // Only the one literal-ALT record on a primary contig produced a row.
        assert_eq!(report.number_of_records, 1);
        // The kept-and-dropped summary is surfaced through the diagnostics channel, so the
        // CLI text output shows it without reading the structured counts.
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.message.contains("dropped 2 of 3 input records")),
            "drop summary warning missing: {:?}",
            report.diagnostics
        );
        // No gVCF marker in this input, so no gVCF hint.
        assert_eq!(report.drops.gvcf_reference_blocks, 0);
    }

    #[test]
    fn suffix_style_population_fields_are_reported_as_ignored() {
        // 1000 Genomes names its per-population AFs with the metric as a suffix, `EUR_AF`,
        // while gnomAD uses a prefix, `AF_nfe`. Neither conforms to the `AF[_CC][_SEX]`
        // grammar, so both are dropped, and both forms must be reported, or a
        // suffix-convention VCF silently yields a `Total`-only dataset.
        let dir = tempfile::tempdir().unwrap();
        let hdr = "##fileformat=VCFv4.2\n\
##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
##INFO=<ID=EUR_AF,Number=A,Type=Float,Description=\"eur af\">\n\
##INFO=<ID=EAS_AF,Number=A,Type=Float,Description=\"eas af\">\n\
##INFO=<ID=DP,Number=1,Type=Integer,Description=\"depth\">\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";
        let vcf = write_vcf(
            dir.path(),
            &format!("{hdr}1\t100\t.\tA\tG\t.\tPASS\tAF=0.25;EUR_AF=0.4;EAS_AF=0.1;DP=30\n"),
        );
        let report = preview_vcf(
            &vcf,
            &ConvertOptions {
                assembly: "GRCh38".into(),
                block_range: 10_000_000,
                min_allele_count: 0,
            },
        )
        .unwrap();
        let ignored = &report
            .diagnostics
            .iter()
            .find(|d| d.message.starts_with("ignored non-conforming INFO fields"))
            .unwrap_or_else(|| panic!("no ignored-fields warning: {:?}", report.diagnostics))
            .message;
        assert!(
            ignored.contains("EUR_AF") && ignored.contains("EAS_AF"),
            "suffix-convention population fields must be named: {ignored}"
        );
        // ...and the rule they broke, so the provider need not reverse-engineer the grammar.
        assert!(
            ignored.contains("2 because of the metric is not the first token"),
            "the warning must group the rejected fields by reason: {ignored}"
        );
        // `DP` carries no AF, AC or AN token, so it is not an allele-frequency look-alike
        // and must not be reported, or the warning becomes noise on every VCF.
        assert!(
            !ignored.contains("DP"),
            "a plain INFO field must not be flagged: {ignored}"
        );
    }

    #[test]
    fn two_info_fields_decoding_to_one_slot_are_reported_to_the_provider() {
        // The population grammar is permutation-invariant, so `AC_Hom_EE` and `AC_EE_Hom`
        // decode to the same (AcHom, "EE") slot and the later one wins, making the served
        // value depend on header iteration order.
        //
        // Reported through the `Diagnostic` channel rather than `tracing`: the tool installs
        // no subscriber, so a warn would be a no-op for the only binary that runs the
        // converter, and the provider would see nothing while `--strict` exited 0. The
        // question is header-determined, so it is answered once in the header scan rather
        // than per record, allele and field.
        let dir = tempfile::tempdir().unwrap();
        let hdr = "##fileformat=VCFv4.2\n\
##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
##INFO=<ID=AC_Hom_EE,Number=A,Type=Integer,Description=\"hom\">\n\
##INFO=<ID=AC_EE_Hom,Number=A,Type=Integer,Description=\"hom again\">\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";
        let vcf = write_vcf(
            dir.path(),
            &format!("{hdr}1\t100\t.\tA\tG\t.\tPASS\tAF=0.25;AC_Hom_EE=3;AC_EE_Hom=4\n"),
        );
        let report = preview_vcf(
            &vcf,
            &ConvertOptions {
                assembly: "GRCh38".into(),
                block_range: 10_000_000,
                min_allele_count: 0,
            },
        )
        .unwrap();
        let collision = report
            .diagnostics
            .iter()
            .find(|d| d.message.contains("same (metric, population)"))
            .unwrap_or_else(|| panic!("no collision diagnostic: {:?}", report.diagnostics));
        assert!(
            collision.message.contains("AC_Hom_EE") && collision.message.contains("AC_EE_Hom"),
            "both colliding header IDs must be named so the provider can pick one: {}",
            collision.message
        );
    }

    /// A VCF header and `#CHROM` line declaring a single `AF` field, for the FILTER tests.
    fn af_only_header() -> &'static str {
        "##fileformat=VCFv4.2\n\
##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n"
    }

    #[test]
    fn non_pass_filter_records_are_counted_and_warned() {
        // FILTER is never read by the converter: a `q10` record is converted like a `PASS`
        // one. That is a data-quality decision the provider must make knowingly, so the
        // count is surfaced rather than left implicit.
        let dir = tempfile::tempdir().unwrap();
        let vcf = write_vcf(
            dir.path(),
            &format!(
                "{}1\t100\t.\tA\tG\t.\tPASS\tAF=0.1\n\
1\t200\t.\tA\tG\t.\tq10\tAF=0.2\n\
1\t300\t.\tA\tG\t.\t.\tAF=0.3\n\
1\t400\t.\tA\tG\t.\tq10;s50\tAF=0.4\n",
                af_only_header()
            ),
        );
        let report = preview_vcf(
            &vcf,
            &ConvertOptions {
                assembly: "GRCh38".into(),
                block_range: 10_000_000,
                min_allele_count: 0,
            },
        )
        .unwrap();
        assert_eq!(report.drops.input_records, 4);
        assert_eq!(
            report.drops.non_pass_records, 2,
            "only `q10` and `q10;s50` are non-PASS; `PASS` and the missing `.` are not"
        );
        // The records are kept, so this is a quality signal rather than a drop.
        assert_eq!(report.drops.total_dropped(), 0);
        assert_eq!(report.number_of_records, 4);
        assert!(
            report.diagnostics.iter().any(|d| d
                .message
                .contains("2 of 4 input records have a FILTER other than PASS")),
            "non-PASS warning missing: {:?}",
            report.diagnostics
        );
    }

    #[test]
    fn all_pass_or_missing_filter_emits_no_filter_warning() {
        let dir = tempfile::tempdir().unwrap();
        let vcf = write_vcf(
            dir.path(),
            &format!(
                "{}1\t100\t.\tA\tG\t.\tPASS\tAF=0.1\n1\t200\t.\tA\tG\t.\t.\tAF=0.2\n",
                af_only_header()
            ),
        );
        let report = preview_vcf(
            &vcf,
            &ConvertOptions {
                assembly: "GRCh38".into(),
                block_range: 10_000_000,
                min_allele_count: 0,
            },
        )
        .unwrap();
        assert_eq!(report.drops.non_pass_records, 0);
        assert!(
            !report
                .diagnostics
                .iter()
                .any(|d| d.message.contains("FILTER")),
            "a clean VCF must not warn about FILTER: {:?}",
            report.diagnostics
        );
    }

    /// A variant whose `Total` row is `AF = 0` has no carrier in the cohort, yet it is stored
    /// and served like any other row. Both `preview` and `build` count exactly those and say
    /// so in a note, since nothing else in the build would. A per-population zero under a
    /// non-zero `Total` is an ordinary stratum and is not counted.
    #[test]
    fn total_af_zero_variants_are_counted_and_noted_by_preview_and_build() {
        let dir = tempfile::tempdir().unwrap();
        let vcf = write_vcf(
            dir.path(),
            "##fileformat=VCFv4.2\n\
##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
##INFO=<ID=AC,Number=A,Type=Integer,Description=\"ac\">\n\
##INFO=<ID=AN,Number=1,Type=Integer,Description=\"an\">\n\
##INFO=<ID=AF_FI,Number=A,Type=Float,Description=\"af fi\">\n\
##contig=<ID=1>\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n\
1\t100\t.\tA\tG\t.\tPASS\tAF=0;AC=0;AN=100;AF_FI=0\n\
1\t200\t.\tA\tG\t.\tPASS\tAF=0.5;AC=50;AN=100;AF_FI=0\n\
1\t300\t.\tA\tG\t.\tPASS\tAF=0.1;AC=10;AN=100;AF_FI=0.2\n",
        );
        let opts = opts_with_floor(0);
        let report = preview_vcf(&vcf, &opts).unwrap();
        assert_eq!(report.drops.total_af_zero_variants, 1);
        assert_eq!(report.number_of_records, 3);
        assert_eq!(report.drops.ns_peak, None, "no NS field, no hint");
        let note = report
            .diagnostics
            .iter()
            .find(|d| d.message.contains("Total AF=0"))
            .unwrap_or_else(|| panic!("the Total AF=0 note is missing: {:?}", report.diagnostics));
        assert_eq!(note.severity, Severity::Note);
        assert!(
            note.message
                .starts_with("1 of 3 emitted variant(s) have Total AF=0"),
            "{}",
            note.message
        );
        // `build` reports the same tally through the same diagnostic.
        let out = convert(dir.path(), &vcf, 0).unwrap();
        assert_eq!(out.drops.total_af_zero_variants, 1);
        assert!(
            out.diagnostics.iter().any(|d| d
                .message
                .starts_with("1 of 3 emitted variant(s) have Total AF=0")),
            "{:?}",
            out.diagnostics
        );
        // With no such variant there is no note at all.
        let clean = write_vcf(
            dir.path(),
            &format!("{}1\t100\t.\tA\tG\t.\tPASS\tAF=0.1\n", af_only_header()),
        );
        let clean = preview_vcf(&clean, &opts).unwrap();
        assert_eq!(clean.drops.total_af_zero_variants, 0);
        assert!(
            !clean.diagnostics.iter().any(|d| d.message.contains("AF=0")),
            "{:?}",
            clean.diagnostics
        );
    }

    /// `NS` is not served, but its peak is the individual count the VCF itself suggests for
    /// `numberOfUniqueIndividuals`: the largest value over the records that were converted,
    /// so a dropped record contributes nothing. A malformed value is ignored, and a VCF
    /// without the field yields no hint. `preview` and `build` agree.
    #[test]
    fn ns_peak_is_the_largest_ns_of_the_converted_records() {
        let dir = tempfile::tempdir().unwrap();
        let vcf = write_vcf(
            dir.path(),
            "##fileformat=VCFv4.2\n\
##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
##INFO=<ID=NS,Number=1,Type=Integer,Description=\"samples with data\">\n\
##contig=<ID=1>\n##contig=<ID=hs37d5>\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n\
1\t100\t.\tA\tG\t.\tPASS\tAF=0.1;NS=10\n\
1\t200\t.\tA\tG\t.\tPASS\tNS=36428;AF=0.2\n\
1\t300\t.\tA\tG\t.\tPASS\tAF=0.3\n\
1\t400\t.\tA\tG\t.\tPASS\tAF=0.4;NS=abc\n\
hs37d5\t100\t.\tA\tG\t.\tPASS\tAF=0.5;NS=99999\n",
        );
        let opts = opts_with_floor(0);
        let report = preview_vcf(&vcf, &opts).unwrap();
        assert_eq!(report.drops.ns_peak, Some(36_428));
        assert_eq!(report.drops.dropped_unsupported_contig, 1);
        let out = convert(dir.path(), &vcf, 0).unwrap();
        assert_eq!(out.drops.ns_peak, Some(36_428));
    }

    /// [`ConvertOptions`] for `GRCh38` at the default block range, with an explicit floor.
    fn opts_with_floor(min_allele_count: u32) -> ConvertOptions {
        ConvertOptions {
            assembly: "GRCh38".into(),
            block_range: 10_000_000,
            min_allele_count,
        }
    }

    #[test]
    fn suppression_is_a_note_but_a_bad_info_field_is_a_warning() {
        // The floor firing is an expected consequence of declared configuration, so it must
        // not be a warning, or `build --strict` could never be used with a floor, which is
        // the main privacy control.
        let dir = tempfile::tempdir().unwrap();
        let vcf = three_population_vcf(dir.path());
        let report = preview_vcf(&vcf, &opts_with_floor(5)).unwrap();
        let floor = report
            .diagnostics
            .iter()
            .find(|d| d.message.contains("min_allele_count floor suppressed"))
            .unwrap_or_else(|| panic!("no floor diagnostic: {:?}", report.diagnostics));
        assert_eq!(floor.severity, Severity::Note);
        assert!(
            !report
                .diagnostics
                .iter()
                .any(|d| d.severity == Severity::Warning),
            "a floor-only build must emit zero warnings: {:?}",
            report.diagnostics
        );
    }

    #[test]
    fn drops_are_notes_while_gvcf_non_pass_and_af_less_populations_are_warnings() {
        // Pins the full severity table against the rule in `Severity`'s docs: a note reports
        // a consequence of behaviour `package.yaml` declares. `mode: aggregated` declares
        // that symbolic and decoy records are dropped, so that is a tally. Nothing declares a
        // gVCF input, an AF-less population, or publishing non-PASS calls, so those are
        // warnings.
        let dir = tempfile::tempdir().unwrap();
        let hdr = "##fileformat=VCFv4.2\n\
##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
##INFO=<ID=AC_NO,Number=A,Type=Integer,Description=\"no ac\">\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";
        let vcf = write_vcf(
            dir.path(),
            &format!(
                "{hdr}1\t100\t.\tA\tG\t.\tq10\tAF=0.25;AC_NO=5\n\
1\t200\t.\tA\t<NON_REF>\t.\tPASS\tAF=0.1\n\
hs37d5\t50\t.\tA\tG\t.\tPASS\tAF=0.5\n"
            ),
        );
        let report = preview_vcf(&vcf, &opts_with_floor(0)).unwrap();
        let sev = |needle: &str| {
            report
                .diagnostics
                .iter()
                .find(|d| d.message.contains(needle))
                .unwrap_or_else(|| panic!("missing {needle}: {:?}", report.diagnostics))
                .severity
        };
        assert_eq!(sev("appears to be a gVCF"), Severity::Warning);
        assert_eq!(sev("has AC/AN but no AF"), Severity::Warning);
        assert_eq!(sev("dropped 2 of 3"), Severity::Note);
        // No `package.yaml` field declares an intent to publish non-PASS calls, so a strict
        // build must refuse them. Demoting this to a note would let a provider ship allele
        // frequencies for variants their own pipeline rejected, with a green `--strict`.
        assert_eq!(sev("FILTER other than PASS"), Severity::Warning);
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.severity == Severity::Warning)
        );
    }

    /// The streaming counter must agree with a whole-scan set on every stream the converter
    /// can produce: `POS` non-decreasing within a chromosome, and a chromosome never
    /// reappearing, both enforced by `enforce_chr_pos_order`. Equal keys can therefore only
    /// be adjacent, which is what lets the dedup window cover one coordinate instead of the
    /// whole scan, saving a couple of hundred resident bytes per distinct variant.
    #[test]
    fn distinct_key_counter_matches_a_full_set_on_ordered_streams() {
        let k = |chr: &str, pos: i32, r: &str, a: &str| -> RecordKey {
            (Arc::from(chr), pos, Arc::from(r), Arc::from(a))
        };
        let stream = vec![
            k("1", 100, "A", "G"),
            k("1", 100, "A", "T"),  // same POS, different ALT -> distinct
            k("1", 100, "A", "G"),  // exact repeat at the same POS -> deduped
            k("1", 100, "AT", "A"), // same POS, different REF -> distinct
            k("1", 200, "A", "G"),  // POS advances; `A>G` here is a different variant
            k("2", 100, "A", "G"),  // chromosome advances; POS resets
            k("2", 100, "A", "G"),  // repeat -> deduped
        ];

        let mut counter = DistinctKeyCounter::default();
        for key in &stream {
            counter.add(key);
        }
        let full: BTreeSet<RecordKey> = stream.iter().cloned().collect();
        assert_eq!(counter.count, full.len() as u64);
        assert_eq!(counter.count, 5);
        assert_eq!(
            counter.seen.len(),
            1,
            "the window must hold only the current coordinate, never the whole scan"
        );
    }

    /// The floor-attributable half of the split: when the floor is what emptied a record, it
    /// must land in `dropped_all_rows_withheld`, not in `dropped_no_af`.
    ///
    /// The companion to the assertion that a record emptied with the floor off lands in
    /// `dropped_no_af`. Without this one, always reporting `no_af` would satisfy that
    /// assertion and the split would be a rename rather than an attribution.
    #[test]
    fn a_record_emptied_by_the_floor_is_not_reported_as_missing_af() {
        let dir = tempfile::tempdir().unwrap();
        let hdr = "##fileformat=VCFv4.2\n\
##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
##INFO=<ID=AC,Number=A,Type=Integer,Description=\"ac\">\n\
##INFO=<ID=AN,Number=1,Type=Integer,Description=\"an\">\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";
        // AF is present and well-formed, but AC=1 is below a floor of 5, so the only row
        // this record could emit is withheld.
        let vcf = write_vcf(
            dir.path(),
            &format!("{hdr}1\t100\t.\tA\tG\t.\tPASS\tAF=0.01;AC=1;AN=100\n"),
        );
        let out = convert(dir.path(), &vcf, 5).unwrap();

        assert_eq!(
            out.drops.records_emitted, 0,
            "the floor withheld the only row"
        );
        assert_eq!(
            out.drops.dropped_all_rows_withheld, 1,
            "a record the FLOOR emptied belongs to the floor class: {:?}",
            out.drops
        );
        assert_eq!(
            out.drops.dropped_no_af, 0,
            "the input carried a perfectly good AF; blaming a missing AF would send the \
             provider to fix an export that is not broken: {:?}",
            out.drops
        );
        assert!(out.drops.accounting_holds(), "{:?}", out.drops);
    }

    /// `AN = 0` means a population has no called genotypes at this site, so its AF is
    /// undefined rather than withheld. Treating it as withheld triggers the k-anonymity
    /// collapse, which throws away the siblings' valid rows to close a differencing channel
    /// that does not exist: `Total - sum(present)` recovers 0, and `AN = 0` already publishes
    /// that.
    ///
    /// gnomAD emits exactly this shape: at an `AN_XX = 0` site it omits `AF_XX` entirely.
    /// On the gnomAD chr21 slice, treating it as withheld removes 353 valid sibling rows.
    #[test]
    fn an_zero_population_is_undefined_not_withheld() {
        let dir = tempfile::tempdir().unwrap();
        let hdr = "##fileformat=VCFv4.2\n\
##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
##INFO=<ID=AN,Number=1,Type=Integer,Description=\"an\">\n\
##INFO=<ID=AF_EE,Number=A,Type=Float,Description=\"af ee\">\n\
##INFO=<ID=AN_EE,Number=1,Type=Integer,Description=\"an ee\">\n\
##INFO=<ID=AF_FI,Number=A,Type=Float,Description=\"af fi\">\n\
##INFO=<ID=AN_FI,Number=1,Type=Integer,Description=\"an fi\">\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";
        // EE has no called genotypes (AN_EE=0, AF_EE omitted). FI and Total are fine.
        let vcf = write_vcf(
            dir.path(),
            &format!("{hdr}1\t100\t.\tA\tG\t.\tPASS\tAF=0.5;AN=100;AN_EE=0;AF_FI=0.3;AN_FI=50\n"),
        );
        let out = convert(dir.path(), &vcf, 0).unwrap();

        let mut pops: Vec<String> = read_rows(&out.parquet_files)
            .into_iter()
            .map(|(_, _, _, pop, _, _)| pop)
            .collect();
        pops.sort();
        assert_eq!(
            pops,
            vec!["FI".to_owned(), "Total".to_owned()],
            "FI's valid row must survive EE being undefined"
        );
        assert_eq!(out.suppression.variants_collapsed_to_total, 0);
        assert_eq!(out.suppression.rows_collapsed_to_total, 0);
        assert!(
            out.populations_without_af.is_empty(),
            "AN=0 is undefined, not an AF-less population: {:?}",
            out.populations_without_af
        );
        assert_eq!(out.drops.records_emitted, 1);
        assert_eq!(out.drops.dropped_all_rows_withheld, 0);
        assert!(out.drops.accounting_holds());
    }

    /// A record emptied by the no-AF collapse with the floor off belongs to `dropped_no_af`.
    ///
    /// `Total` carries `AC`/`AN` but no `AF`, so it is a partial marginal set and the
    /// coherence collapse removes the AF-bearing sibling; nothing is left, and the floor
    /// (0) took nothing. `rows_collapsed_to_total > 0` alone must not read as
    /// floor-attributable: the collapse fires for the no-AF cause too, so reading it as the
    /// floor's would blame a floor that is off. With the floor on and the sibling below it,
    /// the floor is what emptied the record, and the class flips.
    #[test]
    fn a_record_emptied_by_a_no_af_collapse_is_not_blamed_on_the_floor() {
        let hdr = "##fileformat=VCFv4.2\n\
##INFO=<ID=AC,Number=A,Type=Integer,Description=\"ac\">\n\
##INFO=<ID=AN,Number=1,Type=Integer,Description=\"an\">\n\
##INFO=<ID=AF_EE,Number=A,Type=Float,Description=\"af ee\">\n\
##INFO=<ID=AC_EE,Number=A,Type=Integer,Description=\"ac ee\">\n\
##INFO=<ID=AN_EE,Number=1,Type=Integer,Description=\"an ee\">\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";
        let record =
            format!("{hdr}1\t100\t.\tA\tG\t.\tPASS\tAC=10;AN=100;AF_EE=0.1;AC_EE=1;AN_EE=10\n");

        // Floor off: only the no-AF branch can have collapsed this record.
        let dir = tempfile::tempdir().unwrap();
        let vcf = write_vcf(dir.path(), &record);
        let out = convert(dir.path(), &vcf, 0).unwrap();
        assert_eq!(out.drops.records_emitted, 0, "{:?}", out.drops);
        assert_eq!(
            out.drops.dropped_no_af, 1,
            "with the floor off, a record the no-AF collapse emptied belongs to the no-AF \
             class: {:?}",
            out.drops
        );
        assert_eq!(
            out.drops.dropped_all_rows_withheld, 0,
            "the floor was off and took nothing; blaming it sends the provider to lower a \
             floor that is not on: {:?}",
            out.drops
        );
        assert!(out.drops.accounting_holds(), "{:?}", out.drops);

        // Floor on at 5: EE's AC=1 is withheld by the floor, so the floor emptied it.
        let dir = tempfile::tempdir().unwrap();
        let vcf = write_vcf(dir.path(), &record);
        let out = convert(dir.path(), &vcf, 5).unwrap();
        assert_eq!(out.drops.dropped_all_rows_withheld, 1, "{:?}", out.drops);
        assert_eq!(out.drops.dropped_no_af, 0, "{:?}", out.drops);
        assert!(out.drops.accounting_holds(), "{:?}", out.drops);
    }

    /// A record whose every population is undefined emits nothing. Without a drop class for
    /// it that loss is invisible: the manifest publishes `input.records` > `output.records`
    /// with every `discarded.*` at zero, and the record identity does not close.
    ///
    /// The class is `dropped_no_af`: this record carries `AN = 0` and no `AF`, and the floor
    /// here is 0 so it cannot have withheld anything. Asserting the class, and not only the
    /// count, keeps the loss attributed to the provider's export rather than to the floor.
    #[test]
    fn record_with_every_population_undefined_is_counted_not_silently_lost() {
        let dir = tempfile::tempdir().unwrap();
        let hdr = "##fileformat=VCFv4.2\n\
##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
##INFO=<ID=AN,Number=1,Type=Integer,Description=\"an\">\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";
        let vcf = write_vcf(
            dir.path(),
            &format!(
                "{hdr}1\t100\t.\tA\tG\t.\tPASS\tAF=0.5;AN=100\n\
1\t200\t.\tA\tG\t.\tPASS\tAN=0\n"
            ),
        );
        let out = convert(dir.path(), &vcf, 0).unwrap();
        assert_eq!(out.drops.input_records, 2);
        assert_eq!(out.drops.records_emitted, 1);
        assert_eq!(out.drops.dropped_no_af, 1);
        assert_eq!(out.drops.dropped_all_rows_withheld, 0);
        assert_eq!(out.number_of_records, 1);
        assert!(
            out.drops.accounting_holds(),
            "input must equal dropped + emitted: {:?}",
            out.drops
        );
        let note = out
            .diagnostics
            .iter()
            .find(|d| d.message.contains("no allele frequency in the input"))
            .unwrap_or_else(|| panic!("loss not reported: {:?}", out.diagnostics));
        assert_eq!(note.severity, Severity::Note);
    }

    /// The identity must hold across every drop class at once, not just in isolation.
    #[test]
    fn record_accounting_identity_holds_across_all_drop_classes() {
        let dir = tempfile::tempdir().unwrap();
        let hdr = "##fileformat=VCFv4.2\n\
##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
##INFO=<ID=AN,Number=1,Type=Integer,Description=\"an\">\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";
        let vcf = write_vcf(
            dir.path(),
            &format!(
                "{hdr}1\t100\t.\tA\tG\t.\tPASS\tAF=0.5;AN=100\n\
1\t150\t.\tA\t<DEL>\t.\tPASS\tAF=0.2;AN=100\n\
1\t200\t.\tA\tG\t.\tPASS\tAN=0\n\
hs37d5\t50\t.\tA\tG\t.\tPASS\tAF=0.5;AN=100\n"
            ),
        );
        let out = convert(dir.path(), &vcf, 0).unwrap();
        let d = &out.drops;
        assert_eq!(d.input_records, 4);
        assert_eq!(d.dropped_unsupported_contig, 1);
        assert_eq!(d.dropped_no_supported_alt, 1);
        // The `AN=0` record: no AF in the input, and the floor is 0 here so it withheld
        // nothing. Both classes are asserted so the identity cannot close by accident with
        // the count sitting in the wrong bucket.
        assert_eq!(d.dropped_no_af, 1);
        assert_eq!(d.dropped_all_rows_withheld, 0);
        assert_eq!(d.records_emitted, 1);
        assert!(d.accounting_holds(), "{d:?}");
        assert_eq!(d.total_dropped(), 3);
    }

    const HDR_SUBCOUNTS: &str = "##fileformat=VCFv4.1\n\
##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
##INFO=<ID=AC,Number=A,Type=Integer,Description=\"ac\">\n\
##INFO=<ID=AC_Hom,Number=A,Type=Integer,Description=\"hom\">\n\
##INFO=<ID=AC_Het,Number=A,Type=Integer,Description=\"het\">\n\
##INFO=<ID=AC_Hemi,Number=A,Type=Integer,Description=\"hemi\">\n\
##INFO=<ID=AN,Number=1,Type=Integer,Description=\"an\">\n\
##contig=<ID=3>\n#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";

    /// The build gate rejects genotype sub-counts that do not partition `AC` (they count
    /// alleles, so every alternate allele lies in exactly one class — see `core::subcounts`).
    /// The node re-checks this independently at ingest; here we pin the producer side.
    #[test]
    fn build_rejects_incoherent_genotype_subcounts() {
        let dir = tempfile::tempdir().unwrap();

        // Coherent: 2 homozygous + 1 heterozygous + 1 hemizygous allele == AC 4.
        let vcf = write_vcf(
            dir.path(),
            &format!(
                "{HDR_SUBCOUNTS}3\t100\t.\tT\tC\t.\t.\tAF=0.4;AC=4;AC_Hom=2;AC_Het=1;AC_Hemi=1;AN=10\n"
            ),
        );
        convert(dir.path(), &vcf, 0).expect("a coherent sub-count set must convert");

        // Short by one: an alternate allele in no genotype class.
        let dir2 = tempfile::tempdir().unwrap();
        let vcf = write_vcf(
            dir2.path(),
            &format!(
                "{HDR_SUBCOUNTS}3\t100\t.\tT\tC\t.\t.\tAF=0.4;AC=4;AC_Hom=2;AC_Het=1;AC_Hemi=0;AN=10\n"
            ),
        );
        let err = convert(dir2.path(), &vcf, 0)
            .expect_err("sub-counts that do not partition AC must be rejected");
        assert!(
            format!("{err}").contains("does not equal AC"),
            "expected a partition error, got: {err}"
        );

        // A single sub-count larger than AC.
        let dir3 = tempfile::tempdir().unwrap();
        let vcf = write_vcf(
            dir3.path(),
            &format!("{HDR_SUBCOUNTS}3\t100\t.\tT\tC\t.\t.\tAF=0.4;AC=4;AC_Hom=5;AN=10\n"),
        );
        let err =
            convert(dir3.path(), &vcf, 0).expect_err("a sub-count exceeding AC must be rejected");
        assert!(
            format!("{err}").contains("exceeds AC"),
            "expected an exceeds error, got: {err}"
        );
    }

    /// The converter splits multi-allelic lines, so the `(REF, ALT)` pairs it stores are
    /// pairs it authored: the provider never wrote them. Storing the union REF verbatim
    /// makes them non-minimal, and `beacon::request` matches `referenceBases`/
    /// `alternateBases` exactly, so a client querying the canonical form gets a false
    /// negative ("no variant") rather than an error. Both lines below are real 1000 Genomes
    /// phase-3 chr21 records.
    #[test]
    fn multi_allelic_split_stores_minimal_alleles_not_the_union_ref() {
        let dir = tempfile::tempdir().unwrap();
        let hdr = "##fileformat=VCFv4.2\n\
##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";
        let vcf = write_vcf(
            dir.path(),
            &format!(
                "{hdr}21\t100\t.\tAT\tATT,A\t.\tPASS\tAF=0.1,0.2\n\
21\t200\t.\tGATGAAATGAA\tGATGAA,G\t.\tPASS\tAF=0.3,0.4\n"
            ),
        );
        let out = convert(dir.path(), &vcf, 0).unwrap();
        let mut pairs: Vec<(i32, String, String)> = read_rows(&out.parquet_files)
            .into_iter()
            .map(|(pos, r, a, _pop, _af, _ac)| (pos, r, a))
            .collect();
        pairs.sort();
        assert_eq!(
            pairs,
            vec![
                // `AT>ATT` is a 1-base insertion: the canonical pair is `A>AT`.
                (99, "A".to_owned(), "AT".to_owned()),
                // `AT>A` was already minimal.
                (99, "AT".to_owned(), "A".to_owned()),
                // `GATGAAATGAA>GATGAA` is a 5-base deletion: canonical is `GATGAA>G`.
                (199, "GATGAA".to_owned(), "G".to_owned()),
                // `GATGAAATGAA>G` deletes 10 bases and was already minimal.
                (199, "GATGAAATGAA".to_owned(), "G".to_owned()),
            ],
            "split alleles must be stored in minimal representation"
        );
        assert_eq!(out.drops.alleles_not_left_trimmed, 0);
        assert!(
            !out.diagnostics
                .iter()
                .any(|d| d.severity == Severity::Warning),
            "a left-aligned VCF must trim silently: {:?}",
            out.diagnostics
        );
        // Four distinct minimal alleles, still four keys — the trim must not collide them.
        assert_eq!(out.number_of_records, 4);
    }

    /// Right-trimming cannot canonicalise an allele that still shares a leading base:
    /// finishing the job would advance POS, pushing the row out of the sorted-POS order
    /// `enforce_chr_pos_order` guarantees and possibly across a `blockRange` boundary into
    /// a file whose name no longer describes it. The converter warns instead of rewriting.
    #[test]
    fn left_trimmable_allele_warns_and_is_stored_untrimmed() {
        let dir = tempfile::tempdir().unwrap();
        let hdr = "##fileformat=VCFv4.2\n\
##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";
        // 21:15713994 REF=TT ALT=TTG,T — allele `TT>TTG` needs a POS-advancing left-trim.
        let vcf = write_vcf(
            dir.path(),
            &format!("{hdr}21\t100\t.\tTT\tTTG,T\t.\tPASS\tAF=0.1,0.2\n"),
        );
        let out = convert(dir.path(), &vcf, 0).unwrap();
        assert_eq!(out.drops.alleles_not_left_trimmed, 1);
        let warn = out
            .diagnostics
            .iter()
            .find(|d| d.message.contains("not left-aligned"))
            .unwrap_or_else(|| panic!("no left-trim warning: {:?}", out.diagnostics));
        assert_eq!(warn.severity, Severity::Warning);
        assert!(warn.message.contains("bcftools norm"));

        // Stored verbatim: POS never moves.
        let mut pairs: Vec<(i32, String, String)> = read_rows(&out.parquet_files)
            .into_iter()
            .map(|(pos, r, a, _pop, _af, _ac)| (pos, r, a))
            .collect();
        pairs.sort();
        assert_eq!(
            pairs,
            vec![
                (99, "TT".to_owned(), "T".to_owned()),
                (99, "TT".to_owned(), "TTG".to_owned()),
            ]
        );
    }

    #[test]
    fn ignored_info_fields_and_populations_without_af_are_data_not_prose() {
        // Both losses live only inside warning strings today. A manifest consumer cannot
        // parse prose, and `populations_without_af` is the only explanation for a
        // Total-collapse when the floor is 0.
        let dir = tempfile::tempdir().unwrap();
        let hdr = "##fileformat=VCFv4.2\n\
##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
##INFO=<ID=EUR_AF,Number=A,Type=Float,Description=\"eur\">\n\
##INFO=<ID=AC_NO,Number=A,Type=Integer,Description=\"no ac\">\n\
##INFO=<ID=AN_NO,Number=A,Type=Integer,Description=\"no an\">\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";
        let vcf = write_vcf(
            dir.path(),
            &format!("{hdr}1\t100\t.\tA\tG\t.\tPASS\tAF=0.25;EUR_AF=0.4;AC_NO=5;AN_NO=10\n"),
        );
        let report = preview_vcf(&vcf, &opts_with_floor(0)).unwrap();
        assert_eq!(report.ignored_info_fields, vec!["EUR_AF"]);
        assert_eq!(report.populations_without_af, vec!["NO"]);
        assert_eq!(report.populations_recognized, vec!["NO", "Total"]);
        assert_eq!(report.populations_emitted, vec!["Total"]);
    }

    #[test]
    fn convert_output_exposes_rows_emitted_and_the_header_population_set() {
        let dir = tempfile::tempdir().unwrap();
        let vcf = three_population_vcf(dir.path());
        let out = tempfile::tempdir().unwrap();
        let output = convert_vcf(&vcf, out.path(), &opts_with_floor(0)).unwrap();
        assert_eq!(output.rows_emitted, 3);
        assert_eq!(output.populations_recognized, vec!["EE", "FI", "Total"]);
        assert!(output.ignored_info_fields.is_empty());
        assert!(output.populations_without_af.is_empty());
    }

    #[test]
    fn suppressed_rows_plus_emitted_rows_equal_the_unfloored_row_count() {
        // The invariant the manifest's `suppressed` block must satisfy: nothing vanishes
        // unaccounted for between floor=0 and floor=5.
        let dir = tempfile::tempdir().unwrap();
        let vcf = three_population_vcf(dir.path());
        let out0 = tempfile::tempdir().unwrap();
        let out5 = tempfile::tempdir().unwrap();
        let unfloored = convert_vcf(&vcf, out0.path(), &opts_with_floor(0)).unwrap();
        let floored = convert_vcf(&vcf, out5.path(), &opts_with_floor(5)).unwrap();
        assert_eq!(
            floored.rows_emitted
                + floored.suppression.rows_below_floor
                + floored.suppression.rows_collapsed_to_total,
            unfloored.rows_emitted
        );
    }

    #[test]
    fn alleles_discarded_counts_alts_lost_from_surviving_records() {
        // 3 records, 7 declared ALTs, 4 literal ACGTN. Every record survives on its `G`,
        // so `total_dropped()` is 0 and the 3 lost alleles would otherwise be invisible.
        let dir = tempfile::tempdir().unwrap();
        let vcf = write_vcf(
            dir.path(),
            &format!(
                "{}1\t100\t.\tA\tG,*\t.\tPASS\tAF=0.25,0.10\n\
1\t200\t.\tA\tG,<DEL>\t.\tPASS\tAF=0.30,0.05\n\
1\t300\t.\tA\tG,T,*\t.\tPASS\tAF=0.1,0.2,0.3\n",
                af_only_header()
            ),
        );
        let report = preview_vcf(&vcf, &opts_with_floor(0)).unwrap();
        assert_eq!(report.drops.input_records, 3);
        assert_eq!(
            report.drops.total_dropped(),
            0,
            "every record kept a literal ALT"
        );
        assert_eq!(
            report.drops.alleles_discarded, 3,
            "one `*`, one `<DEL>`, one `*`"
        );
    }

    #[test]
    fn an_all_unsupported_record_is_counted_once_and_not_as_alleles() {
        // The record is already counted whole as `dropped_no_supported_alt`; also counting
        // its alleles would double-report the same loss.
        let dir = tempfile::tempdir().unwrap();
        let vcf = write_vcf(
            dir.path(),
            &format!(
                "{}1\t100\t.\tA\t<DEL>,*\t.\tPASS\tAF=0.1,0.2\n",
                af_only_header()
            ),
        );
        let report = preview_vcf(&vcf, &opts_with_floor(0)).unwrap();
        assert_eq!(report.drops.dropped_no_supported_alt, 1);
        assert_eq!(report.drops.alleles_discarded, 0);
    }

    /// An AF-only dataset must survive a build-time floor with its rows intact.
    ///
    /// `AF` is the only required frequency field, since `AC` and `AN` are both optional, so
    /// an AF-only VCF is a supported shape. Serve time fails such a row closed, and applying
    /// that at build time would permanently delete every row of the dataset at the one
    /// moment the data still exists. That is data destruction, not disclosure control, and
    /// the serve-time floor already withholds these rows on every response.
    ///
    /// This is the consequence half of
    /// `kanon::tests::an_uncountable_row_is_classified_as_such_not_suppressed`: that one
    /// pins the verdict, this one pins what the verdict costs if it flips.
    #[test]
    fn an_af_only_dataset_is_not_emptied_by_the_build_time_floor() {
        let dir = tempfile::tempdir().unwrap();
        // No AC and no AN anywhere: nothing is derivable, so every row is Uncountable.
        let hdr = "##fileformat=VCFv4.2\n\
##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
##INFO=<ID=AF_EE,Number=A,Type=Float,Description=\"ee af\">\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";
        let vcf = write_vcf(
            dir.path(),
            &format!("{hdr}1\t100\t.\tA\tG\t.\tPASS\tAF=0.25;AF_EE=0.4\n"),
        );

        let out = tempfile::tempdir().unwrap();
        let floored = convert_vcf(&vcf, out.path(), &opts_with_floor(5)).unwrap();
        assert!(
            floored.rows_emitted > 0,
            "a high floor emptied an AF-only dataset: the build-time floor must KEEP an \
             uncountable row; deleting it here is irreversible and buys nothing serve time \
             does not already do per response"
        );
        assert_eq!(
            floored.suppression.rows_below_floor, 0,
            "no row here has a derivable count, so none can be below the floor"
        );
    }

    /// The build-time floor must apply the same row rule the serve-time floor does.
    ///
    /// Comparing only an explicit `AC` leaves two gaps with no rationale: a group whose
    /// count is derivable from `AF x AN` but has no `AC` field, and the complement tail, a
    /// near-fixed row whose reference-carrier group `AN - AC` is below the floor while its
    /// own `AC` sits comfortably above it. Both are the same disclosure the provider asked
    /// to withhold when they set `minAlleleCount`.
    ///
    /// Uncountable rows (`AF` present, no `AC`, no `AN`) are not dropped here:
    /// see `core::kanon::RowVerdict::Uncountable`.
    #[test]
    fn the_build_time_floor_applies_the_shared_row_rule() {
        let dir = tempfile::tempdir().unwrap();
        // Total is near-fixed: AC 998 of AN 1000, so refc = 2 — a complement tail below a
        // floor of 5, with an AC far above it. EE has no AC field but AF x AN = 2 is
        // derivable and below the floor.
        let hdr = "##fileformat=VCFv4.2\n\
##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
##INFO=<ID=AC,Number=A,Type=Integer,Description=\"ac\">\n\
##INFO=<ID=AN,Number=1,Type=Integer,Description=\"an\">\n\
##INFO=<ID=AF_EE,Number=A,Type=Float,Description=\"ee af\">\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";
        let vcf = write_vcf(
            dir.path(),
            &format!("{hdr}1\t100\t.\tA\tG\t.\tPASS\tAF=0.998;AC=998;AN=1000;AF_EE=0.002\n"),
        );

        let out = tempfile::tempdir().unwrap();
        let floored = convert_vcf(&vcf, out.path(), &opts_with_floor(5)).unwrap();

        assert!(
            floored.suppression.rows_below_floor > 0,
            "the build-time floor must withhold the complement tail and the AF x AN-derivable \
             group; it withheld nothing, so it is still comparing only an explicit AC"
        );
        // Nothing vanishes unaccounted for: the same invariant the sibling test asserts.
        let unfloored_dir = tempfile::tempdir().unwrap();
        let unfloored = convert_vcf(&vcf, unfloored_dir.path(), &opts_with_floor(0)).unwrap();
        assert_eq!(
            floored.rows_emitted
                + floored.suppression.rows_below_floor
                + floored.suppression.rows_collapsed_to_total,
            unfloored.rows_emitted,
            "rows must be accounted for across the floor"
        );
    }

    /// A three-population header (`Total`, `EE`, `FI`) carrying AF + AC, for the
    /// suppression-metering tests.
    fn three_population_vcf(dir: &Path) -> PathBuf {
        let hdr = "##fileformat=VCFv4.2\n\
##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
##INFO=<ID=AC,Number=A,Type=Integer,Description=\"ac\">\n\
##INFO=<ID=AN,Number=1,Type=Integer,Description=\"an\">\n\
##INFO=<ID=AF_EE,Number=A,Type=Float,Description=\"ee af\">\n\
##INFO=<ID=AC_EE,Number=A,Type=Integer,Description=\"ee ac\">\n\
##INFO=<ID=AF_FI,Number=A,Type=Float,Description=\"fi af\">\n\
##INFO=<ID=AC_FI,Number=A,Type=Integer,Description=\"fi ac\">\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";
        write_vcf(
            dir,
            &format!(
                "{hdr}1\t100\t.\tA\tG\t.\tPASS\tAF=0.25;AC=250;AN=1000;AF_EE=0.4;AC_EE=248;AF_FI=0.01;AC_FI=2\n"
            ),
        )
    }

    #[test]
    fn floor_suppressed_rows_and_the_total_collapse_are_counted() {
        // `FI` (AC=2) falls below the floor of 5 and is withheld. The coherence collapse
        // then removes `EE` too, even though AC=248 is far above the floor, because a
        // partial marginal set would let `Total - EE` recover the withheld `FI` cell.
        // Both losses must be metered: the collateral one is the surprising one.
        let dir = tempfile::tempdir().unwrap();
        let vcf = three_population_vcf(dir.path());
        let report = preview_vcf(
            &vcf,
            &ConvertOptions {
                assembly: "GRCh38".into(),
                block_range: 10_000_000,
                min_allele_count: 5,
            },
        )
        .unwrap();

        assert_eq!(report.rows_emitted, 1, "only the Total row survives");
        assert_eq!(
            report.suppression.rows_below_floor, 1,
            "FI (AC=2) is below the floor of 5"
        );
        assert_eq!(
            report.suppression.rows_collapsed_to_total, 1,
            "EE (AC=248) is removed as collateral of the coherence collapse"
        );
        assert_eq!(report.suppression.variants_collapsed_to_total, 1);
        // Suppression is row-level, so it must not be mistaken for a record drop.
        assert_eq!(report.drops.total_dropped(), 0);

        assert!(
            report.diagnostics.iter().any(|d| d
                .message
                .contains("min_allele_count floor suppressed 1 population row")),
            "floor warning missing: {:?}",
            report.diagnostics
        );
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.message.contains("collapsed 1 variant")
                    && d.message.contains("removing 1 further population row")),
            "collapse warning missing: {:?}",
            report.diagnostics
        );
    }

    #[test]
    fn no_floor_suppresses_nothing_and_warns_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let vcf = three_population_vcf(dir.path());
        let report = preview_vcf(
            &vcf,
            &ConvertOptions {
                assembly: "GRCh38".into(),
                block_range: 10_000_000,
                min_allele_count: 0,
            },
        )
        .unwrap();
        assert_eq!(report.rows_emitted, 3, "Total + EE + FI");
        assert_eq!(report.suppression.rows_below_floor, 0);
        assert_eq!(report.suppression.rows_collapsed_to_total, 0);
        assert_eq!(report.suppression.variants_collapsed_to_total, 0);
        assert!(
            !report
                .diagnostics
                .iter()
                .any(|d| d.message.contains("suppressed")),
            "no suppression warning without a floor: {:?}",
            report.diagnostics
        );
    }

    #[test]
    fn preview_separates_recognized_populations_from_emitted_ones() {
        // The header declares three populations; under a floor only `Total` survives.
        // Reporting only the header-derived set advertises data the build will not emit.
        let dir = tempfile::tempdir().unwrap();
        let vcf = three_population_vcf(dir.path());
        let report = preview_vcf(
            &vcf,
            &ConvertOptions {
                assembly: "GRCh38".into(),
                block_range: 10_000_000,
                min_allele_count: 5,
            },
        )
        .unwrap();
        assert_eq!(report.populations_recognized, vec!["EE", "FI", "Total"]);
        assert_eq!(
            report.populations_emitted,
            vec!["Total"],
            "only populations that actually reach parquet"
        );
    }

    #[test]
    fn convert_reports_the_emitted_population_set() {
        // `build` echoes this so a provider who expected five populations and sees one
        // learns it at build time rather than from a beacon query weeks later.
        let dir = tempfile::tempdir().unwrap();
        let vcf = three_population_vcf(dir.path());
        let out = tempfile::tempdir().unwrap();
        let output = convert_vcf(
            &vcf,
            out.path(),
            &ConvertOptions {
                assembly: "GRCh38".into(),
                block_range: 10_000_000,
                min_allele_count: 0,
            },
        )
        .unwrap();
        assert_eq!(output.populations_emitted, vec!["EE", "FI", "Total"]);
    }

    #[test]
    fn convert_meters_suppression_on_the_parallel_path() {
        // The worker path folds its per-partition suppression counts, exactly as the
        // sequential preview path does.
        let dir = tempfile::tempdir().unwrap();
        let vcf = three_population_vcf(dir.path());
        let out = tempfile::tempdir().unwrap();
        let output = convert_vcf(
            &vcf,
            out.path(),
            &ConvertOptions {
                assembly: "GRCh38".into(),
                block_range: 10_000_000,
                min_allele_count: 5,
            },
        )
        .unwrap();
        assert_eq!(output.suppression.rows_below_floor, 1);
        assert_eq!(output.suppression.rows_collapsed_to_total, 1);
        assert_eq!(output.suppression.variants_collapsed_to_total, 1);
        assert_eq!(output.populations_emitted, vec!["Total"]);
    }

    #[test]
    fn classifies_each_variant_class_end_to_end() {
        // Each supported ALT class flows through convert → parquet with its canonical
        // VT label (classify_vt is unit-tested; this pins the end-to-end wiring).
        let dir = tempfile::tempdir().unwrap();
        let vcf = write_vcf(
            dir.path(),
            &format!(
                "{HDR_AF_A}\
3\t100\t.\tT\tC\t.\t.\tAF=0.5\n\
3\t200\t.\tAC\tA\t.\t.\tAF=0.5\n\
3\t300\t.\tA\tAC\t.\t.\tAF=0.5\n\
3\t400\t.\tAT\tGC\t.\t.\tAF=0.5\n\
3\t500\t.\tAT\tGCC\t.\t.\tAF=0.5\n"
            ),
        );
        let out = convert(dir.path(), &vcf, 0).unwrap();
        let by_pos = read_vt_by_pos(&out.parquet_files);
        // Stored POS is 0-based (VCF POS − 1).
        assert_eq!(by_pos[&99], ("T".into(), "C".into(), "SNP".into()));
        assert_eq!(by_pos[&199], ("AC".into(), "A".into(), "DEL".into())); // deletion
        assert_eq!(by_pos[&299], ("A".into(), "AC".into(), "INS".into())); // insertion
        assert_eq!(by_pos[&399], ("AT".into(), "GC".into(), "MNP".into())); // block sub
        assert_eq!(by_pos[&499], ("AT".into(), "GCC".into(), "DELINS".into())); // complex
        assert_eq!(out.number_of_records, 5);
    }

    #[test]
    fn ref_equals_alt_allele_is_dropped_as_non_variant() {
        // A literal ALT identical to REF is not a variant (VCF requires ALT ≠ REF):
        // as the sole ALT the record is dropped and counted; alongside a real ALT the
        // non-variant allele is skipped and the real one is kept.
        let dir = tempfile::tempdir().unwrap();
        let vcf = write_vcf(
            dir.path(),
            &format!(
                "{HDR_AF_A}\
3\t100\t.\tA\tA\t.\t.\tAF=0.5\n\
3\t200\t.\tG\tG,T\t.\t.\tAF=0,0.5\n"
            ),
        );
        let out = convert(dir.path(), &vcf, 0).unwrap();
        let by_pos = read_vt_by_pos(&out.parquet_files);
        // The sole-ALT non-variant emits no row and is counted as a drop (stored POS
        // is 0-based, so VCF POS 100 would be key 99).
        assert!(
            !by_pos.contains_key(&99),
            "a REF==ALT record must not emit a row"
        );
        assert_eq!(out.drops.dropped_no_supported_alt, 1);
        // The multiallelic record keeps its real G>T SNP (the G>G allele is skipped).
        assert_eq!(by_pos[&199], ("G".into(), "T".into(), "SNP".into()));
        assert_eq!(out.number_of_records, 1);
    }

    #[test]
    fn gvcf_reference_blocks_are_counted_and_hinted() {
        // A gVCF carries `<NON_REF>` reference-block records; they are dropped as
        // unsupported symbolic ALTs and counted, and the dataset-level warning
        // tells the provider the input is a gVCF (not a bug).
        let dir = tempfile::tempdir().unwrap();
        let hdr = "##fileformat=VCFv4.2\n\
##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
##ALT=<ID=NON_REF,Description=\"Represents any possible alternative allele\">\n\
##contig=<ID=3>\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";
        let vcf = write_vcf(
            dir.path(),
            &format!(
                "{hdr}3\t100\t.\tT\tC,<NON_REF>\t.\t.\tAF=0.5,0\n\
3\t200\t.\tA\t<NON_REF>\t.\t.\tAF=0\n\
3\t300\t.\tG\t<NON_REF>\t.\t.\tAF=0\n"
            ),
        );
        let report = preview_vcf(
            &vcf,
            &ConvertOptions {
                assembly: "GRCh38".into(),
                block_range: 10_000_000,
                min_allele_count: 0,
            },
        )
        .unwrap();
        // Records 2 and 3 are <NON_REF>-only → dropped reference blocks; record 1
        // has a real `C` ALT so it is kept (its trailing <NON_REF> is ignored).
        assert_eq!(report.drops.gvcf_reference_blocks, 2);
        assert_eq!(report.drops.dropped_no_supported_alt, 2);
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.message.contains("input appears to be a gVCF")),
            "gVCF hint warning missing: {:?}",
            report.diagnostics
        );
    }

    #[test]
    fn rejects_when_no_af_in_header() {
        let dir = tempfile::tempdir().unwrap();
        let vcf = write_vcf(
            dir.path(),
            "##fileformat=VCFv4.1\n##INFO=<ID=AC,Number=A,Type=Integer,Description=\"ac\">\n##contig=<ID=3>\n#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n3\t100\t.\tT\tC\t.\t.\tAC=5\n",
        );
        let err = convert(dir.path(), &vcf, 0).unwrap_err();
        std::assert_matches!(err, CoreError::InvalidParquet { .. });
        assert!(format!("{err}").contains("No AF INFO fields found"));
    }

    #[test]
    fn rejects_af_above_one() {
        let dir = tempfile::tempdir().unwrap();
        let vcf = write_vcf(
            dir.path(),
            &format!("{HDR_AF_A}3\t100\t.\tT\tC\t.\t.\tAF=1.5;AC=5;AN=10\n"),
        );
        let err = convert(dir.path(), &vcf, 0).unwrap_err();
        assert!(format!("{err}").contains("exceeds 1.0"));
    }

    #[test]
    fn rejects_ac_exceeding_an() {
        let dir = tempfile::tempdir().unwrap();
        let vcf = write_vcf(
            dir.path(),
            &format!("{HDR_AF_A}3\t100\t.\tT\tC\t.\t.\tAF=0.5;AC=20;AN=10\n"),
        );
        let err = convert(dir.path(), &vcf, 0).unwrap_err();
        assert!(format!("{err}").contains("exceeds AN"));
    }

    /// A mis-stratified breakdown must be rejected, not converted silently.
    ///
    /// `AN_EE_M + AN_EE_F == AN_EE` exactly, so the two sexes provably partition EE, yet
    /// they report 510 carriers inside a parent of 10. Without this check `preview`,
    /// `build`, `validate`, `lint` and the node's ingest all report `diagnostics: none`
    /// and the beacon serves the impossible breakdown, so a swapped sex label or a subgroup
    /// computed on the wrong cohort reaches consumers as authoritative.
    #[test]
    fn rejects_an_incoherent_population_hierarchy() {
        let dir = tempfile::tempdir().unwrap();
        let hdr = "##fileformat=VCFv4.1\n\
##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
##INFO=<ID=AC,Number=A,Type=Integer,Description=\"ac\">\n\
##INFO=<ID=AN,Number=1,Type=Integer,Description=\"an\">\n\
##INFO=<ID=AC_EE,Number=A,Type=Integer,Description=\"ac\">\n\
##INFO=<ID=AN_EE,Number=1,Type=Integer,Description=\"an\">\n\
##INFO=<ID=AF_EE,Number=A,Type=Float,Description=\"af\">\n\
##INFO=<ID=AC_EE_M,Number=A,Type=Integer,Description=\"ac\">\n\
##INFO=<ID=AN_EE_M,Number=1,Type=Integer,Description=\"an\">\n\
##INFO=<ID=AF_EE_M,Number=A,Type=Float,Description=\"af\">\n\
##INFO=<ID=AC_EE_F,Number=A,Type=Integer,Description=\"ac\">\n\
##INFO=<ID=AN_EE_F,Number=1,Type=Integer,Description=\"an\">\n\
##INFO=<ID=AF_EE_F,Number=A,Type=Float,Description=\"af\">\n\
##contig=<ID=3>\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";
        let body = "3\t100\t.\tT\tC\t.\t.\t\
AF=0.00125;AC=10;AN=8000;\
AF_EE=0.0025;AC_EE=10;AN_EE=4000;\
AF_EE_M=0.25;AC_EE_M=500;AN_EE_M=2000;\
AF_EE_F=0.005;AC_EE_F=10;AN_EE_F=2000\n";
        let vcf = write_vcf(dir.path(), &format!("{hdr}{body}"));
        let err = convert(dir.path(), &vcf, 0).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("EE_M") && msg.contains("EE"),
            "the error must name the offending child and its parent: {msg}"
        );
    }

    #[test]
    fn rejects_number_a_violation_on_af() {
        let dir = tempfile::tempdir().unwrap();
        let vcf = write_vcf(
            dir.path(),
            "##fileformat=VCFv4.1\n##INFO=<ID=AF,Number=1,Type=Float,Description=\"af\">\n##contig=<ID=3>\n#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n3\t100\t.\tT\tC\t.\t.\tAF=0.5\n",
        );
        let err = convert(dir.path(), &vcf, 0).unwrap_err();
        assert!(format!("{err}").contains("must be Number=A"));
    }

    #[test]
    fn rejects_pos_zero_with_literal_alt() {
        let dir = tempfile::tempdir().unwrap();
        let vcf = write_vcf(
            dir.path(),
            &format!("{HDR_AF_A}3\t0\t.\tT\tC\t.\t.\tAF=0.5;AC=5;AN=10\n"),
        );
        let err = convert(dir.path(), &vcf, 0).unwrap_err();
        assert!(format!("{err}").contains("POS=0"));
    }

    #[test]
    fn pos_zero_with_symbolic_alt_is_skipped() {
        // POS=0 with only a symbolic ALT: the ALT filter drops it before the POS
        // check, so it is skipped (no rows, no error).
        let dir = tempfile::tempdir().unwrap();
        let vcf = write_vcf(
            dir.path(),
            &format!("{HDR_AF_A}3\t0\t.\tT\t<DEL>\t.\t.\tAF=0.5;AC=5;AN=10\n"),
        );
        let out = convert(dir.path(), &vcf, 0).unwrap();
        assert_eq!(out.number_of_records, 0);
        assert!(out.parquet_files.is_empty());
    }

    #[test]
    fn multiallelic_indexes_by_original_alt_position() {
        // ALTs: <DEL> (idx 0, dropped), G (idx 1), A (idx 2). The Number=A lists
        // must be indexed by the original index, so G binds list[1] and A binds
        // list[2] even though <DEL> was dropped.
        let dir = tempfile::tempdir().unwrap();
        let vcf = write_vcf(
            dir.path(),
            &format!("{HDR_AF_A}3\t100\t.\tT\t<DEL>,G,A\t.\t.\tAF=0.1,0.2,0.3;AC=1,2,3;AN=10\n"),
        );
        let out = convert(dir.path(), &vcf, 0).unwrap();
        let rows = read_rows(&out.parquet_files);
        // Two emitted alleles (G, A); <DEL> dropped.
        assert_eq!(out.number_of_records, 2);
        let g = rows.iter().find(|r| r.2 == "G").unwrap();
        assert!((g.4 - 0.2).abs() < 1e-6);
        assert_eq!(g.5, Some(2));
        let a = rows.iter().find(|r| r.2 == "A").unwrap();
        assert!((a.4 - 0.3).abs() < 1e-6);
        assert_eq!(a.5, Some(3));
    }

    #[test]
    fn min_allele_count_drops_low_ac_rows_before_counting() {
        // AC=3 is below the floor of 5 and is dropped; with no rows left the
        // record is not counted.
        let dir = tempfile::tempdir().unwrap();
        let vcf = write_vcf(
            dir.path(),
            &format!("{HDR_AF_A}3\t100\t.\tT\tC\t.\t.\tAF=0.5;AC=3;AN=10\n"),
        );
        let out = convert(dir.path(), &vcf, 5).unwrap();
        assert_eq!(out.number_of_records, 0);
    }

    /// A partition whose every row the floor withholds must leave no file behind. The writer
    /// opens on the partition's first batch, so without this the build wrote a parquet with
    /// no row groups and no offset index, then rejected it itself with "parquet has no page
    /// (offset) index". That happens on exactly the input a provider gets by choosing a
    /// floor on a small cohort.
    #[test]
    fn a_partition_emptied_by_the_floor_leaves_no_parquet_file() {
        use parquet::arrow::arrow_reader::{ArrowReaderOptions, ParquetRecordBatchReaderBuilder};
        use parquet::file::metadata::PageIndexPolicy;
        let dir = tempfile::tempdir().unwrap();
        // Two records in different 10 M blocks: the first below the floor, the second above
        // it on both alleles (the floor also bounds the reference count, AN - AC).
        let vcf = write_vcf(
            dir.path(),
            &format!(
                "{HDR_AF_A}3\t100\t.\tT\tC\t.\t.\tAF=0.3;AC=3;AN=10\n\
                 3\t15000000\t.\tA\tG\t.\t.\tAF=0.4;AC=8;AN=20\n"
            ),
        );
        let out = convert(dir.path(), &vcf, 5).unwrap();
        assert_eq!(
            out.number_of_records, 1,
            "only the record above the floor is counted"
        );
        assert_eq!(
            out.parquet_files.len(),
            1,
            "the emptied partition must not be listed: {:?}",
            out.parquet_files
        );
        let on_disk: Vec<_> = std::fs::read_dir(dir.path().join("out"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "parquet"))
            .collect();
        assert_eq!(
            on_disk.len(),
            1,
            "and must not be on disk either: {on_disk:?}"
        );
        for path in &out.parquet_files {
            // The reader every ingest-path validator uses: a file with no page index fails
            // to open here, which is what the build's validation tripped over.
            let opened = ParquetRecordBatchReaderBuilder::try_new_with_options(
                File::open(path).unwrap(),
                ArrowReaderOptions::new().with_page_index_policy(PageIndexPolicy::Required),
            );
            assert!(
                opened.is_ok(),
                "{} must carry a page index: {:?}",
                path.display(),
                opened.err()
            );
        }
    }

    #[test]
    fn min_allele_count_keeps_a_row_exactly_at_the_floor() {
        // The floor drops rows with AC strictly below it; AC == floor is at-or-above
        // and must be kept. A `<`→`<=` off-by-one would drop the boundary row — a
        // k-anon-relevant defect, since this is the build-time disclosure floor.
        let dir = tempfile::tempdir().unwrap();
        let vcf = write_vcf(
            dir.path(),
            &format!("{HDR_AF_A}3\t100\t.\tT\tC\t.\t.\tAF=0.5;AC=5;AN=10\n"),
        );
        let out = convert(dir.path(), &vcf, 5).unwrap();
        assert_eq!(
            out.number_of_records, 1,
            "AC == floor must be kept, not dropped"
        );
        let rows = read_rows(&out.parquet_files);
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].5,
            Some(5),
            "the at-floor AC must survive to the output"
        );
    }

    #[test]
    fn rejects_decreasing_position_within_chromosome() {
        let dir = tempfile::tempdir().unwrap();
        let vcf = write_vcf(
            dir.path(),
            &format!(
                "{HDR_AF_A}3\t200\t.\tT\tC\t.\t.\tAF=0.5;AC=5;AN=10\n3\t100\t.\tT\tC\t.\t.\tAF=0.5;AC=5;AN=10\n"
            ),
        );
        let err = convert(dir.path(), &vcf, 0).unwrap_err();
        assert!(format!("{err}").contains("before the previous position"));
    }

    #[test]
    fn does_not_synthesize_af_from_ac_an() {
        // A population (FI) with AC/AN but no AF emits no rows and a warning.
        let dir = tempfile::tempdir().unwrap();
        let hdr = "##fileformat=VCFv4.1\n##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n##INFO=<ID=AC_FI,Number=A,Type=Integer,Description=\"ac fi\">\n##INFO=<ID=AN_FI,Number=1,Type=Integer,Description=\"an fi\">\n##contig=<ID=3>\n#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";
        let vcf = write_vcf(
            dir.path(),
            &format!("{hdr}3\t100\t.\tT\tC\t.\t.\tAF=0.5;AC_FI=5;AN_FI=10\n"),
        );
        let out = convert(dir.path(), &vcf, 0).unwrap();
        let rows = read_rows(&out.parquet_files);
        // Only the Total population (which has AF) is emitted; FI is not.
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].3, "Total");
        assert!(out.diagnostics.iter().any(|d| d.message.contains("FI")));
    }

    /// A header with `Total` + two country siblings (`FI`, `NL`), each with AF/AC/AN.
    const HDR_3POP: &str = "##fileformat=VCFv4.1\n\
##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
##INFO=<ID=AC,Number=A,Type=Integer,Description=\"ac\">\n\
##INFO=<ID=AN,Number=1,Type=Integer,Description=\"an\">\n\
##INFO=<ID=AF_FI,Number=A,Type=Float,Description=\"af fi\">\n\
##INFO=<ID=AC_FI,Number=A,Type=Integer,Description=\"ac fi\">\n\
##INFO=<ID=AN_FI,Number=1,Type=Integer,Description=\"an fi\">\n\
##INFO=<ID=AF_NL,Number=A,Type=Float,Description=\"af nl\">\n\
##INFO=<ID=AC_NL,Number=A,Type=Integer,Description=\"ac nl\">\n\
##INFO=<ID=AN_NL,Number=1,Type=Integer,Description=\"an nl\">\n\
##contig=<ID=3>\n#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";

    fn pops_of(out: &ConvertOutput) -> Vec<String> {
        let mut pops: Vec<String> = read_rows(&out.parquet_files)
            .into_iter()
            .map(|(_, _, _, pop, _, _)| pop)
            .collect();
        pops.sort();
        pops
    }

    #[test]
    fn build_floor_collapses_a_partial_marginal_set_to_total_only() {
        // K-anonymity coherence: build-time min_allele_count suppression must mirror the
        // serve-time `emittable_rows` collapse. Total + two siblings where one is below the
        // floor: dropping only the below-floor sibling would leave a partial set
        // (Total + surviving sibling), letting `Total - survivor` recover the dropped cell.
        // The build must keep only Total. Total AC=10; FI AC=9 (>=5); NL AC=1 (<5).
        let dir = tempfile::tempdir().unwrap();
        let body = "3\t100\t.\tA\tG\t.\t.\tAF=0.01;AC=10;AN=1000;AF_FI=0.018;AC_FI=9;AN_FI=500;AF_NL=0.002;AC_NL=1;AN_NL=500\n";
        let vcf = write_vcf(dir.path(), &format!("{HDR_3POP}{body}"));
        let out = convert(dir.path(), &vcf, 5).unwrap();
        assert_eq!(
            pops_of(&out),
            vec!["Total".to_string()],
            "a below-floor sibling must collapse the variant to Total-only"
        );
    }

    #[test]
    fn build_floor_keeps_the_full_marginal_set_when_none_are_below_floor() {
        // No sibling below the floor -> the complete marginal set is emitted (no collapse,
        // no over-suppression). All AC >= 5.
        let dir = tempfile::tempdir().unwrap();
        let body = "3\t100\t.\tA\tG\t.\t.\tAF=0.02;AC=20;AN=1000;AF_FI=0.018;AC_FI=9;AN_FI=500;AF_NL=0.022;AC_NL=11;AN_NL=500\n";
        let vcf = write_vcf(dir.path(), &format!("{HDR_3POP}{body}"));
        let out = convert(dir.path(), &vcf, 5).unwrap();
        assert_eq!(
            pops_of(&out),
            vec!["FI".to_string(), "NL".to_string(), "Total".to_string()]
        );
    }

    #[test]
    fn no_af_sibling_with_counts_collapses_the_variant_to_total_only() {
        // A sibling carrying AC/AN but no AF emits no row, leaving a partial set that
        // `Total - sum(present)` could recover. It must collapse to Total. Here NL has
        // AC/AN but the data line omits AF_NL; FI keeps its AF. Floor 0 (no floor drop).
        let dir = tempfile::tempdir().unwrap();
        let body = "3\t100\t.\tA\tG\t.\t.\tAF=0.01;AC=10;AN=1000;AF_FI=0.018;AC_FI=9;AN_FI=500;AC_NL=1;AN_NL=500\n";
        let vcf = write_vcf(dir.path(), &format!("{HDR_3POP}{body}"));
        let out = convert(dir.path(), &vcf, 0).unwrap();
        assert_eq!(
            pops_of(&out),
            vec!["Total".to_string()],
            "an omitted no-AF sibling with counts must collapse the variant to Total-only"
        );
        assert!(out.diagnostics.iter().any(|d| d.message.contains("NL")));
    }

    #[test]
    fn rejects_ac_exceeding_an_even_without_af() {
        // AC > AN is incoherent and must be rejected even when the population has
        // no AF: the coherence check runs before the no-AF early return, because a
        // no-AF population emits no row and would otherwise never be checked.
        let dir = tempfile::tempdir().unwrap();
        let vcf = write_vcf(
            dir.path(),
            &format!("{HDR_AF_A}3\t100\t.\tT\tC\t.\t.\tAC=20;AN=10\n"),
        );
        let err = convert(dir.path(), &vcf, 0).unwrap_err();
        assert!(
            format!("{err}").contains("exceeds AN"),
            "expected an AC>AN rejection, got: {err}"
        );
    }

    #[test]
    fn accepts_ac_equal_to_an_a_fixed_variant() {
        // AC == AN (every allele is the ALT — a valid fully-fixed variant) is not
        // "AC exceeds AN": it must be accepted and emitted. A `>`→`>=` off-by-one on
        // the `ac > an` coherence check would wrongly reject this boundary.
        let dir = tempfile::tempdir().unwrap();
        let vcf = write_vcf(
            dir.path(),
            &format!("{HDR_AF_A}3\t100\t.\tT\tC\t.\t.\tAF=1.0;AC=10;AN=10\n"),
        );
        let out = convert(dir.path(), &vcf, 0)
            .expect("AC == AN is a valid fixed variant, not an AC>AN error");
        let rows = read_rows(&out.parquet_files);
        assert_eq!(rows.len(), 1, "the fixed variant must be emitted");
        assert_eq!(rows[0].5, Some(10), "AC preserved");
    }

    // ── Regression tests for rules that are implemented but easily un-exercised ──

    /// Build a VCF header + one record that declares `n` distinct population AF
    /// fields (`AF_AA`, `AF_AB`, …) each with `Number=A` and a single value of
    /// `0.01`. The contig `3` and one ALT `C` (REF `T`) are used throughout.
    ///
    /// The returned string is a complete, parseable VCF.
    fn vcf_with_n_populations(n: usize) -> String {
        use std::fmt::Write as _;

        // Enumerate enough 2-letter uppercase codes to cover n populations: the `Total`
        // population (plain `AF`) first, then `AF_AA`, `AF_AB`, ..., cycling through
        // A..=Z × A..=Z.
        let mut header = String::from("##fileformat=VCFv4.1\n##contig=<ID=3>\n");
        let mut info_values: Vec<String> = Vec::with_capacity(n);

        // First population: Total (plain AF).
        header.push_str("##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n");
        info_values.push("AF=0.01".to_string());

        // Remaining populations: `AF_AA`, `AF_AB`, ..., up to n total.
        let mut remaining = n.saturating_sub(1);
        'outer: for c1 in b'A'..=b'Z' {
            for c2 in b'A'..=b'Z' {
                if remaining == 0 {
                    break 'outer;
                }
                let code = format!("{}{}", c1 as char, c2 as char);
                let _ = writeln!(
                    header,
                    "##INFO=<ID=AF_{code},Number=A,Type=Float,Description=\"af {code}\">"
                );
                info_values.push(format!("AF_{code}=0.01"));
                remaining -= 1;
            }
        }

        header.push_str("#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n");
        let info_str = info_values.join(";");
        format!("{header}3\t100\t.\tT\tC\t.\t.\t{info_str}\n")
    }

    /// A VCF whose header declares more than 512 distinct populations is rejected, by the
    /// `MAX_POPULATIONS` guard in `record_population`.
    #[test]
    fn rejects_more_than_512_populations() {
        let dir = tempfile::tempdir().unwrap();
        // 513 populations: Total + AA..ZZ (first 512 two-letter codes) = 513 total.
        let vcf_str = vcf_with_n_populations(513);
        let vcf = write_vcf(dir.path(), &vcf_str);
        let err = convert(dir.path(), &vcf, 0).unwrap_err();
        std::assert_matches!(
            err,
            CoreError::InvalidParquet { .. },
            "expected InvalidParquet, got {err:?}"
        );
        assert!(
            format!("{err}").contains("512"),
            "error message should mention the cap, got: {err}"
        );
    }

    /// Population labels stay within the 16-char cap. The popfield grammar — a base
    /// (`AF`/`AC`/`AN`), an optional `Hom`/`Het`/`Hemi`, an optional 2-letter
    /// country code, and an optional `M`/`F` — cannot produce a key longer than the
    /// cap, so the label-length guard never fires on conforming input. Asserts the
    /// cap invariant on the produced labels rather than pinning one literal length.
    #[test]
    fn population_labels_stay_within_the_length_cap() {
        let dir = tempfile::tempdir().unwrap();
        let vcf = write_vcf(
            dir.path(),
            &format!("{HDR_AF_A}3\t100\t.\tT\tC\t.\t.\tAF=0.2;AC=1;AN=10\n"),
        );
        let out = convert(dir.path(), &vcf, 0).unwrap();
        let rows = read_rows(&out.parquet_files);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].3, "Total");
        assert!(
            rows.iter().all(|r| r.3.chars().count() <= 16),
            "every grammar-produced population label must be within the 16-char cap"
        );
    }

    /// A contig cannot reappear within one VCF: records on chr1, then chr2, then chr1
    /// again are rejected by the `seen_chrs.contains(chr)` guard in
    /// `enforce_chr_pos_order`.
    #[test]
    fn rejects_contig_reappearing_after_different_contig() {
        let dir = tempfile::tempdir().unwrap();
        let hdr = "##fileformat=VCFv4.1\n\
                   ##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
                   ##contig=<ID=1>\n\
                   ##contig=<ID=2>\n\
                   #CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";
        // chr1 at 100, chr2 at 200, chr1 at 300 — chr1 reappears after chr2.
        let vcf = write_vcf(
            dir.path(),
            &format!(
                "{hdr}\
                 1\t100\t.\tT\tC\t.\t.\tAF=0.1\n\
                 2\t200\t.\tT\tC\t.\t.\tAF=0.1\n\
                 1\t300\t.\tT\tC\t.\t.\tAF=0.1\n"
            ),
        );
        let err = convert(dir.path(), &vcf, 0).unwrap_err();
        std::assert_matches!(
            err,
            CoreError::InvalidParquet { .. },
            "expected InvalidParquet, got {err:?}"
        );
        assert!(
            format!("{err}").contains("reappears"),
            "error message should mention contig reappearance, got: {err}"
        );
    }

    /// A `Number=A` list length must equal the line's ALT count: a record with two ALTs
    /// but one value in the `AF` list is rejected by the `count != alt_count` guard in
    /// `lookup_value`.
    #[test]
    fn rejects_number_a_list_length_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        // Two ALTs (C, G) but AF only has one value → mismatch.
        let vcf = write_vcf(
            dir.path(),
            &format!("{HDR_AF_A}3\t100\t.\tT\tC,G\t.\t.\tAF=0.1;AC=1,2;AN=10\n"),
        );
        let err = convert(dir.path(), &vcf, 0).unwrap_err();
        std::assert_matches!(
            err,
            CoreError::InvalidParquet { .. },
            "expected InvalidParquet, got {err:?}"
        );
        let msg = format!("{err}");
        assert!(
            msg.contains("1 values") && msg.contains("2 ALT"),
            "error message should report the count mismatch, got: {msg}"
        );
    }

    /// Two records at the same POS on one contig are legal, for instance a SNP and an
    /// indel emitted on separate lines by `bcftools sort`. The non-decreasing guard in
    /// `enforce_chr_pos_order` is `pos0 < last`, so equal positions are accepted; a
    /// `<`→`<=` off-by-one would wrongly reject the second same-POS record. Both loci
    /// must be emitted.
    #[test]
    fn accepts_two_records_at_the_same_position() {
        let dir = tempfile::tempdir().unwrap();
        let vcf = write_vcf(
            dir.path(),
            &format!(
                "{HDR_AF_A}3\t100\t.\tT\tC\t.\t.\tAF=0.5;AC=5;AN=10\n3\t100\t.\tG\tA\t.\t.\tAF=0.5;AC=5;AN=10\n"
            ),
        );
        let out = convert(dir.path(), &vcf, 0)
            .expect("two records at the same POS are legal and must be accepted");
        assert_eq!(out.number_of_records, 2, "both same-POS records must count");
        let rows = read_rows(&out.parquet_files);
        // Stored POS is 0-based (VCF POS − 1), so both loci sit at key 99.
        assert!(
            rows.iter().any(|r| r.0 == 99 && r.1 == "T" && r.2 == "C"),
            "the first same-POS locus (T>C) must be emitted: {rows:?}"
        );
        assert!(
            rows.iter().any(|r| r.0 == 99 && r.1 == "G" && r.2 == "A"),
            "the second same-POS locus (G>A) must be emitted: {rows:?}"
        );
    }

    /// A `.` (missing) INFO value maps to a NULL column, not to the literal token `"."`.
    /// `AC=.` on a real record yields a NULL AC, and the row survives on its present AF,
    /// rather than reaching `parse_count(".")`, which would error. A `||`→`&&` slip in
    /// `lookup_value`'s `token == "." || token.is_empty()` guard would return `Some(".")`
    /// and fail the conversion.
    #[test]
    fn missing_info_value_dot_maps_to_null_not_the_dot_token() {
        let dir = tempfile::tempdir().unwrap();
        let vcf = write_vcf(
            dir.path(),
            &format!("{HDR_AF_A}3\t100\t.\tT\tC\t.\t.\tAF=0.5;AC=.;AN=10\n"),
        );
        let out = convert(dir.path(), &vcf, 0)
            .expect("a `.` INFO value must map to NULL, not fail parsing");
        let rows = read_rows(&out.parquet_files);
        assert_eq!(
            rows.len(),
            1,
            "the record with AF present must emit one row"
        );
        assert!((rows[0].4 - 0.5).abs() < 1e-6, "AF preserved");
        assert_eq!(
            rows[0].5, None,
            "the `.` AC must be a NULL column, not Some(\".\")"
        );
    }

    /// The name formatter and the block-key reader are inverses, and the key ignores the
    /// per-VCF half — which is the whole point: two VCFs covering the same positions must
    /// produce the same key, and that equality is what the build warns on.
    #[test]
    fn partition_file_name_round_trips_through_its_block_key() {
        let a = partition_file_name("21", 5, 1000, "0af7651916cd43dd");
        let b = partition_file_name("21", 5, 1000, "b7ad6b7169203331");
        assert_eq!(a, "allele-freq.chr21.5.br1000.0af7651916cd43dd.parquet");
        assert_eq!(
            partition_block_key(&a).as_deref(),
            Some("chr21.5.br1000"),
            "the key is the name minus the vcfid"
        );
        assert_eq!(
            partition_block_key(&a),
            partition_block_key(&b),
            "two source VCFs writing into one block share a key"
        );
        assert_ne!(
            partition_block_key(&a),
            partition_block_key(&partition_file_name("21", 6, 1000, "0af7651916cd43dd")),
            "a different block is a different key"
        );

        // Not ours to read: other staged files, and a name whose block half is truncated.
        for other in [
            "manifest.json",
            "allele-freq.parquet",
            "allele-freq.chr21.5.0af7651916cd43dd.parquet",
            "allele-freq.chr21.5.br1000.not-hex.parquet",
        ] {
            assert_eq!(partition_block_key(other), None, "{other}");
        }
    }

    /// The wizard's assembly hint comes from the chromosome-1 `##contig` length first,
    /// then from a `##reference=` line; a header that says neither yields no hint. The
    /// first record's contig rides along, and a header-only file has none.
    #[test]
    fn header_hints_read_the_assembly_and_the_first_contig() {
        let dir = tempfile::tempdir().unwrap();
        let record = "3\t100\t.\tT\tC\t.\t.\tAF=0.1;AC=1;AN=10\n";

        // A chr1 contig length decides it, whatever `##reference` says.
        let grch37 = write_vcf(
            dir.path(),
            &format!(
                "##fileformat=VCFv4.1\n##reference=hg38\n##INFO=<ID=AF,Number=A,Type=Float,\
                 Description=\"af\">\n##contig=<ID=chr1,length=249250621>\n##contig=<ID=3>\n\
                 #CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n{record}"
            ),
        );
        let hints = read_header_hints(&grch37).unwrap();
        assert_eq!(hints.assembly, Some("GRCh37"));
        assert_eq!(hints.first_contig.as_deref(), Some("3"));

        // No chr1 length: the `##reference` line is consulted.
        let by_reference = write_vcf(
            dir.path(),
            &format!(
                "##fileformat=VCFv4.1\n##reference=file:///ref/GRCh38_full_analysis_set.fa\n\
                 ##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n##contig=<ID=3>\n\
                 #CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n{record}"
            ),
        );
        assert_eq!(
            read_header_hints(&by_reference).unwrap().assembly,
            Some("GRCh38")
        );

        // Neither: no hint, and a header-only file has no first contig.
        let silent = write_vcf(dir.path(), HDR_AF_A);
        let hints = read_header_hints(&silent).unwrap();
        assert_eq!(hints.assembly, None);
        assert_eq!(hints.first_contig, None);

        // An unknown length is not a hint either — the table is exact, not approximate.
        let odd = write_vcf(
            dir.path(),
            &format!(
                "##fileformat=VCFv4.1\n##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
                 ##contig=<ID=1,length=248387328>\n\
                 #CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n{record}"
            ),
        );
        assert_eq!(read_header_hints(&odd).unwrap().assembly, None);
    }

    #[test]
    fn assembly_named_in_recognises_the_common_spellings() {
        assert_eq!(assembly_named_in("GRCh38"), Some("GRCh38"));
        assert_eq!(assembly_named_in("hg38.fa"), Some("GRCh38"));
        assert_eq!(assembly_named_in("human_g1k_v37 (b37)"), Some("GRCh37"));
        assert_eq!(assembly_named_in("ucsc.hg19.fasta"), Some("GRCh37"));
        assert_eq!(assembly_named_in("T2T-CHM13"), None);
    }
}
