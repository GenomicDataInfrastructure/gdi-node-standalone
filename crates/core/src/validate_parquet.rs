//! Parquet schema/value validation and per-dataset `(POS, REF, ALT, population)`
//! uniqueness.
//!
//! The same checks run in the tool's `build`/`validate` post-conversion self-check and on
//! the service's ingest path, so the logic lives once here in `core`.
//!
//! The decompression-bomb guard reads row group by row group, never materialising the whole
//! file, and rejects before decoding on both halves of the declared expansion: the
//! row-group metadata's uncompressed sizes here, and each page header's own
//! `uncompressed_page_size` in [`crate::parquet_pages`]. A crafted high-ratio parquet is
//! caught as a fast [`CoreError::InvalidParquet`] rather than an OOM.

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use arrow_array::{Array, Int32Array, RecordBatch};
use parquet::arrow::ProjectionMask;
use parquet::arrow::arrow_reader::{
    ArrowReaderOptions, ParquetRecordBatchReader, ParquetRecordBatchReaderBuilder,
};
use parquet::file::metadata::{PageIndexPolicy, ParquetMetaData};
use parquet::file::page_index::column_index::ColumnIndexMetaData;
use parquet::file::statistics::Statistics;

use crate::{
    error::{CoreError, CoreResult, invalid_parquet},
    parquet_io::allele_freq_schema,
    subcounts::check_subcounts,
};

/// Resource caps for parquet validation.
///
/// Defaults follow the spec (`[service]` defaults): 1 GiB on-disk per file,
/// 4 GiB decompressed working set per file, 256 MiB decompressed per row group,
/// and a 10 000 bp `REF` length cap (the range-query lookback window).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParquetCaps {
    /// Reject any on-disk parquet data file larger than this many bytes.
    pub max_parquet_file_bytes: u64,
    /// Reject any file whose total declared uncompressed working set exceeds this.
    pub max_parquet_decompressed_bytes: u64,
    /// Reject any single row group whose declared uncompressed size exceeds this.
    pub max_parquet_row_group_bytes: u64,
    /// Reject any `REF` allele longer than this many bases (the lookback cap).
    pub max_ref_len: usize,
    /// Reject any `ALT` allele longer than this many bases. Unlike `max_ref_len`
    /// (a query-mechanics lookback bound), this is purely an anti-amplification cap:
    /// `ALT` is stored verbatim and served as `alternateBases`, so an unbounded ALT
    /// cell would bloat both the stored parquet and every Beacon response that
    /// returns it. Generous for any real allele (even sequence-resolved insertions),
    /// far below the megabyte-scale cell an attacker would need to amplify a response.
    pub max_alt_len: usize,
    /// Reject a `(chr, block)` group whose number of distinct `(REF, ALT,
    /// population)` rows sharing a single `POS` exceeds this. The per-row-group /
    /// per-file decompression caps are POS-independent and do not bound this
    /// cross-file working set, so a crafted parquet could otherwise pile an
    /// unbounded number of rows onto one locus. Real loci carry a handful of
    /// populations, so this is far above any legitimate value.
    pub max_distinct_keys_per_pos: usize,
    /// Reject a `(chr, block)` group whose cumulative `REF`/`ALT`/`POPULATION` byte
    /// size of the distinct rows sharing a single `POS` exceeds this. Complements the
    /// count bound `max_distinct_keys_per_pos`: each key owns up to `max_ref_len` plus
    /// `max_alt_len` plus population-label bytes, so a few-but-very-large keys could
    /// otherwise pile tens of GB onto one locus (about `max_distinct_keys_per_pos`
    /// times the per-key bytes) before the count cap trips. Far above any legitimate
    /// locus (a handful of short-labelled populations at short alleles).
    pub max_pos_key_bytes: u64,
    /// Reject a beacon query whose cumulative matching-row count for a single dataset
    /// exceeds this. The per-file byte caps bound one file's decode, but a wide `Range`
    /// query over a dense region spans many files and accumulates every matching
    /// `AlleleRow` into one `Vec` before grouping. Query breadth is the caller's lever, so
    /// this fails such a query closed instead of letting the heap grow unbounded. Far above
    /// any legitimate dataset's matches for a real query.
    pub max_query_rows: usize,
    /// Reject any `POPULATION` label longer than this many characters. Like
    /// `max_alt_len`, this is an anti-amplification cap: `POPULATION` is stored
    /// verbatim and served in every `frequencyInPopulations[].population`, so an
    /// unbounded cell would bloat both the stored parquet and every Beacon response.
    /// Pinned to the trusted producer's `convert::MAX_POPULATION_LABEL_LEN` (16
    /// chars) so a hand-assembled parquet that bypasses `convert` faces the same
    /// bound the tool applies (counted in `char`s, not bytes, to match the producer).
    pub max_population_len: usize,
    /// Reject a `(chr, block)` group holding more than this many parquet files. The
    /// uniqueness merge opens one file descriptor + reader per group member up front,
    /// and the group key is only `(chr, block)`, so files differing solely by their
    /// `vcfid` all land in one group — an attacker could otherwise force tens of
    /// thousands of concurrent open descriptors (EMFILE) on the ingest worker. A real
    /// `(chr, block)` group carries a handful of files, so this is far above any
    /// legitimate value while bounding the fan-out.
    pub max_files_per_group: usize,
}

impl Default for ParquetCaps {
    fn default() -> Self {
        Self {
            max_parquet_file_bytes: 1024 * 1024 * 1024,
            max_parquet_decompressed_bytes: 4 * 1024 * 1024 * 1024,
            max_parquet_row_group_bytes: 256 * 1024 * 1024,
            max_ref_len: 10_000,
            max_alt_len: 10_000,
            max_distinct_keys_per_pos: 1_000_000,
            // 256 MiB cumulative per-POS key bytes — same scale as the row-group cap;
            // bounds the cross-file per-locus working set the count cap leaves open.
            max_pos_key_bytes: 256 * 1024 * 1024,
            // ~10M AlleleRows ≈ 2 GiB resident at the common short-allele shape
            // (224 B/row by `AlleleRow::scan_weight_bytes`); bounds a wide-range scan.
            max_query_rows: 10_000_000,
            // Matches `convert::MAX_POPULATION_LABEL_LEN`; pinned by
            // `population_len_cap_matches_producer`.
            max_population_len: 16,
            // A real `(chr, block)` group has ~1 file per VCF group; 1024 is far above
            // any legitimate fan-out while bounding concurrent open descriptors.
            max_files_per_group: 1024,
        }
    }
}
/// What a full validating scan of a dataset's parquet observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParquetScan {
    /// Distinct `(chr, POS, REF, ALT)` variants, counting a variant reported for several
    /// populations once. This is the quantity `manifest.metadata.numberOfRecords` declares.
    pub distinct_variants: u64,
    /// The distinct `POPULATION` labels present, sorted. This is the quantity
    /// `manifest.metadata.populations` declares, and the node advertises on `/datasets`.
    pub populations: BTreeSet<String>,
}

/// Validate every `allele-freq.*.parquet` data file in `dir`.
///
/// Each file is checked in this order, from the footer metadata and before any row group
/// is decoded: the on-disk size cap, the exact schema, the per-row-group and per-file
/// decompressed working set, the per-page declared expansion, and the declared `POS`
/// statistics against the rows they claim to bound.
///
/// The per-row value rules then run on every decoded row: `POS` non-negative and
/// non-decreasing; `REF` and `ALT` in `ACGTN` and within their length caps; `POPULATION`
/// within its length cap; `VT` in `{SNP, MNP, INS, DEL, DELINS}`; `AF` finite and within
/// `[0, 1]`; every present count non-negative; `AC <= AN` and `AF` consistent with
/// `AC / AN` when both are present; the genotype sub-counts partitioning `AC`; and the
/// population hierarchy coherent.
///
/// Across the whole dataset it enforces `(POS, REF, ALT, population)`
/// uniqueness: no tuple may occur more than once within a single file, nor
/// across the files of a `(chr, block)` group (files are POS-sorted, so the
/// check is a bounded-memory streaming merge).
///
/// Returns a [`ParquetScan`]: the distinct `(chr, POS, REF, ALT)` variant count, counting a
/// variant reported for several populations once, and the distinct `POPULATION` labels.
/// Both are by-products of the per-`(chr, block)` uniqueness scan, so they add no extra
/// pass, and both are claims the manifest declares and the node cross-checks against the
/// data.
///
/// # Errors
///
/// Returns [`CoreError::InvalidParquet`] on any schema, cap, value, or
/// uniqueness violation, or [`CoreError::Io`] on a filesystem error.
pub fn validate_parquet_dir(dir: &Path, caps: &ParquetCaps) -> CoreResult<ParquetScan> {
    let mut files = collect_data_files(dir)?;
    // Deterministic order keeps any error reporting stable across runs.
    files.sort();

    // Single decode pass: group by (chr, block), then run each group's uniqueness scan,
    // which also applies the per-file schema/cap/value checks as it decodes each file once
    // (folded into `RowCursor::open`/`refill`). Every file lands in exactly one group
    // (`group_by_chr_block` isolates an unparseable name under its own key), so no file
    // skips validation. The panic boundary below still covers a decode or schema panic
    // during a cursor open.
    //
    // Groups partition the data by (chr, POS-block), so a given (chr, POS, REF, ALT)
    // lives in exactly one group — summing the distinct-variant counts is exact and
    // never double-counts.
    let groups = group_by_chr_block(&files);
    let mut distinct_variants: u64 = 0;
    let mut populations: BTreeSet<String> = BTreeSet::new();
    for group_files in groups.values() {
        let first = group_files.first().map_or(dir, |p| p.as_path());
        // `check_group_uniqueness` returns its label set rather than filling one through
        // the panic boundary: a `&mut BTreeSet` is not `UnwindSafe`.
        let (variants, group_populations) =
            catch_parquet_panic(first, || check_group_uniqueness(group_files, caps))?;
        distinct_variants += variants;
        populations.extend(group_populations);
        // The dataset-wide cap, which is what `convert::MAX_POPULATIONS` and
        // `docs/gdi-dataset-tool.md` promise: at most N distinct populations per dataset.
        // `check_group_uniqueness` bounds only its own (chr, block) group, so without this a
        // package split into N groups, each just under the cap, passes with up to N times
        // the cap. Checked as each group folds in, so a crafted package fails on the group
        // that crosses the line rather than after scanning every one.
        check_population_cap(populations.len())?;
    }

    Ok(ParquetScan {
        distinct_variants,
        populations,
    })
}

/// Run a parquet-reading closure under a panic boundary, converting any panic
/// into a [`CoreError::InvalidParquet`].
///
/// The `arrow`/`parquet` decode path panics, rather than erroring, on some crafted inputs.
/// A malicious `ARROW:schema` flatbuffer in the parquet key-value metadata makes
/// `arrow-ipc`'s schema converter panic (`Int type with bit width of 0 ... not supported`).
/// Parquet data files are untrusted provider input on both the tool self-check and the node
/// ingest path, and the contract is to treat a malformed file as an error, never a panic.
/// The closure's borrowed inputs (`&Path`, `&[Path]`, `&ParquetCaps`) are
/// [`std::panic::RefUnwindSafe`], so no `AssertUnwindSafe` wrapper is needed.
///
/// Wrapped in a [`crate::panic_guard::HandledDecodeGuard`] for the duration of `f`. A panic
/// here is expected and about to become the clean error below, so the process-level panic
/// hook, which fires before this `catch_unwind` sees the unwind, can downgrade its output
/// instead of writing raw panic text to the log for every malformed provider file.
fn catch_parquet_panic<F, T>(path: &Path, f: F) -> CoreResult<T>
where
    F: FnOnce() -> CoreResult<T> + std::panic::UnwindSafe,
{
    crate::panic_guard::catch_decode_panic(f, || {
        invalid_parquet(format!(
            "parquet decode panicked on {} (malformed file)",
            path.display()
        ))
    })
}

/// Collect the `allele-freq.*.parquet` data files directly under `dir`.
fn collect_data_files(dir: &Path) -> CoreResult<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if crate::s3_layout::is_data_file_name(name) {
            files.push(path);
        }
    }
    Ok(files)
}

/// Group data files by their `(chr, block)` filename component.
///
/// The filename layout is
/// `allele-freq.chr{CHR}.{block}.br{block_range}.{vcfid}.parquet`; neither
/// `{CHR}` nor `{vcfid}` contains a dot, so splitting on `.` is unambiguous.
/// Files that do not match the pattern are placed in their own singleton group
/// keyed by the whole filename (their value checks still ran above; they cannot
/// false-share a uniqueness key with a well-formed file).
fn group_by_chr_block(files: &[PathBuf]) -> std::collections::BTreeMap<String, Vec<PathBuf>> {
    let mut groups: std::collections::BTreeMap<String, Vec<PathBuf>> =
        std::collections::BTreeMap::new();
    for path in files {
        let key = chr_block_key(path);
        groups.entry(key).or_default().push(path.clone());
    }
    groups
}

/// Derive the `(chr, block)` group key from a data-file path.
fn chr_block_key(path: &Path) -> String {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    let parts: Vec<&str> = name.split('.').collect();
    // ["allele-freq", "chr{CHR}", "{block}", "br{range}", "{vcfid}", "parquet"]
    if parts.len() >= 4 && parts[0] == "allele-freq" {
        format!("{}.{}", parts[1], parts[2])
    } else {
        // Unrecognised name: keep it isolated so it cannot collide with a
        // well-formed group's keys.
        name.to_string()
    }
}

/// Parse the `(block, block_range)` a data-file name declares, or `None` for any name
/// that is not `allele-freq.chr{CHR}.{block}.br{range}.{vcfid}.parquet` with a numeric
/// `{block}` and `{range}`.
///
/// Used to prove each file's rows fall in the block its name claims. The Beacon serve path
/// (`beacon::query::select_files`) resolves a file purely by the
/// `allele-freq.chr{chr}.{block}.br{block_range}.` prefix it builds from the dataset's
/// configured `blockRange`, so a file whose POS values map to a different block would be
/// unqueryable. Names that do not parse are left unchecked here: they are already isolated
/// in their own uniqueness group and cannot be resolved by the serve path either.
// `pub` because the serve path selects files through this same parser, so the
// ingest/validate gate and the serve path cannot diverge on the `(block, range)` filename
// grammar. A file one accepts and the other cannot resolve would advertise as visible yet
// answer nothing.
#[must_use]
pub fn parse_block_and_range(name: &str) -> Option<(u64, u32)> {
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() != 6 || parts[0] != "allele-freq" || parts[5] != "parquet" {
        return None;
    }
    let block = parts[2].parse::<u64>().ok()?;
    let range = parts[3].strip_prefix("br")?.parse::<u32>().ok()?;
    Some((block, range))
}

/// Verify every `allele-freq.*.parquet` data file in `dir` declares the `block_range` the
/// manifest configures.
///
/// The Beacon serve path resolves a stored file purely by the
/// `allele-freq.chr{chr}.{block}.br{block_range}.` prefix it builds from the dataset's
/// configured `blockRange`. A file whose name declares a different `br{N}`, or a name so
/// malformed the block and range cannot be read, is unreachable, so the dataset would
/// advertise as visible yet answer no queries. Both the node ingest gate and the tool's
/// `build`/`validate` self-check call this, so the tool rejects the same package the node
/// would.
///
/// [`validate_parquet_dir`] additionally proves each row's POS falls in the block its name
/// declares. This pins the name itself to the manifest's `blockRange` and, through the
/// shared `parse_block_and_range`, rejects a name the per-row check can only skip.
///
/// # Errors
///
/// [`CoreError::InvalidManifest`] if any file declares a `br{N}` differing from
/// `block_range`, or a name that is not a well-formed data-file name; [`CoreError::Io`]
/// on a filesystem error reading `dir`.
pub fn check_data_file_block_range(dir: &Path, block_range: u32) -> CoreResult<()> {
    for path in collect_data_files(dir)? {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        match parse_block_and_range(name) {
            // The name parses AND its declared range matches the manifest's.
            Some((_block, range)) if range == block_range => {}
            Some((_block, range)) => {
                return Err(CoreError::InvalidManifest {
                    detail: format!(
                        "data file {name:?} declares blockRange {range} but manifest \
                         config.blockRange is {block_range}"
                    ),
                });
            }
            None => {
                return Err(CoreError::InvalidManifest {
                    detail: format!(
                        "data file {name:?} is not a well-formed \
                         allele-freq.chr{{CHR}}.{{block}}.br{{range}}.{{vcfid}}.parquet name"
                    ),
                });
            }
        }
    }
    Ok(())
}

/// Verify the file's Arrow schema matches [`allele_freq_schema`] exactly.
fn check_schema(actual: &arrow_schema::SchemaRef) -> CoreResult<()> {
    let expected = allele_freq_schema();
    let exp_fields = expected.fields();
    let act_fields = actual.fields();
    if exp_fields.len() != act_fields.len() {
        return Err(invalid_parquet(format!(
            "schema has {} columns, expected {}",
            act_fields.len(),
            exp_fields.len()
        )));
    }
    for (exp, act) in exp_fields.iter().zip(act_fields.iter()) {
        if exp.name() != act.name() {
            return Err(invalid_parquet(format!(
                "schema column name mismatch: found {:?}, expected {:?}",
                act.name(),
                exp.name()
            )));
        }
        if exp.data_type() != act.data_type() {
            return Err(invalid_parquet(format!(
                "schema type mismatch on column {:?}: found {:?}, expected {:?}",
                act.name(),
                act.data_type(),
                exp.data_type()
            )));
        }
        if exp.is_nullable() != act.is_nullable() {
            return Err(invalid_parquet(format!(
                "schema nullability mismatch on column {:?}",
                act.name()
            )));
        }
    }

    Ok(())
}

/// Whether a declared row-group `POS` statistic `[dmin, dmax]` actually bounds the
/// group's observed `[omin, omax]`.
fn pos_stat_bounds_observed(dmin: i32, dmax: i32, omin: i32, omax: i32) -> bool {
    dmin <= omin && dmax >= omax
}

/// Grow a running observed `[min, max]` to include `pos` (seeding it on the first row).
fn widen_bounds(bounds: &mut Option<(i32, i32)>, pos: i32) {
    *bounds = Some(match *bounds {
        Some((min, max)) => (min.min(pos), max.max(pos)),
        None => (pos, pos),
    });
}

/// Reject a parquet whose declared per-row-group `POS` statistics do not bound its
/// actual rows (forged / stale statistics).
///
/// The serve path prunes row groups, and pages, on producer-supplied `POS` footer
/// statistics without decoding the pruned rows
/// ([`crate::parquet_io::read_matching_rows`]). A producer that writes real, sorted,
/// block-consistent rows but forges a row group's `POS` statistics to a narrower range
/// therefore makes those rows unqueryable, returning `exists:false` for data the node
/// holds. The rest of ingest validation decodes every row but never reads statistics, so
/// this requires `declared_min <= observed_min` and `declared_max >= observed_max` per row
/// group. A group with absent or non-`Int32` statistics is accepted: the serve path then
/// decodes it without pruning, so it cannot under-disclose.
///
/// Reads the `POS` column once (projected) and attributes rows to groups by the declared
/// per-group row counts, so it does not assume record batches respect row-group
/// boundaries.
fn verify_pos_statistics(path: &Path, meta: &ParquetMetaData) -> CoreResult<()> {
    let file = fs::File::open(path)?;
    // `Required`, like every other reader of an untrusted parquet in this module: every
    // ingest-path reader opens the file in one page-traversal mode, where a bare `try_new`
    // would inherit `PageIndexPolicy::Skip`. The property that matters is symmetry. This
    // function checks the declared per-page and per-group POS statistics against the rows
    // they claim to bound, so it must decode the same rows the value checks and the PME
    // re-encode do. A `Pages` reader and a `Values` walk can otherwise disagree on a file
    // with a truncated `compressed_size`. `enforce_page_size_caps`, called by
    // `RowCursor::open` before any of this runs, requires the index to tile the chunk
    // exactly and rejects every such shape. See `parquet_io::encrypt_parquet_file_inner`
    // for the full argument.
    let builder = ParquetRecordBatchReaderBuilder::try_new_with_options(
        file,
        ArrowReaderOptions::new().with_page_index_policy(PageIndexPolicy::Required),
    )
    .map_err(|e| invalid_parquet(format!("cannot open parquet metadata: {e}")))?;
    // POS is leaf column 0 of the canonical schema.
    let mask = ProjectionMask::leaves(builder.parquet_schema(), [0]);
    let reader = builder
        .with_projection(mask)
        .build()
        .map_err(|e| invalid_parquet(format!("cannot build POS-column reader: {e}")))?;

    let counts: Vec<usize> = (0..meta.num_row_groups())
        .map(|i| usize::try_from(meta.row_group(i).num_rows().max(0)).unwrap_or(0))
        .collect();
    let mut observed: Vec<Option<(i32, i32)>> = vec![None; counts.len()];
    // Per row group: the page-level observed bounds, keyed by page, alongside the row index
    // within the group at which each page starts, so a row can be attributed to the page
    // whose declared bounds must contain it. Both come from the same `OffsetIndex` lookup,
    // and a group without one contributes no pages.
    //
    // The serve path prunes at page granularity from the column index
    // (`parquet_io::pos_row_selection`), so these are the numbers pruning uses. Verifying
    // only the row-group statistics would leave them unchecked, and a provider could declare
    // page bounds excluding a page that holds real variants.
    //
    // Page boundaries come from `parquet_io::page_row_ranges`, the same derivation the serve
    // path prunes with, rather than being re-read here. Anchoring on raw `first_row_index`
    // would `partition_point` a slice never proved sorted, mis-attributing rows to pages on a
    // non-monotonic index, while the serve path builds an inverted range from the same
    // numbers and panics on it. Rejecting the file here keeps a malformed index out of the
    // store.
    let mut page_starts: Vec<Vec<usize>> = Vec::with_capacity(counts.len());
    let mut page_observed: Vec<Vec<Option<(i32, i32)>>> = Vec::with_capacity(counts.len());
    for (rg, &group_rows) in counts.iter().enumerate() {
        let ranges = match meta
            .offset_index()
            .and_then(|idx| idx.get(rg))
            .and_then(|cols| cols.first())
        {
            Some(col) => crate::parquet_io::page_row_ranges(col, group_rows).ok_or_else(|| {
                invalid_parquet(format!(
                    "row group {rg} has a malformed page index: first_row_index is not a \
                     non-decreasing partition of the group's {group_rows} rows"
                ))
            })?,
            // No page index for this group: nothing to attribute rows to, as before.
            None => Vec::new(),
        };
        page_observed.push(vec![None; ranges.len()]);
        page_starts.push(ranges.into_iter().map(|r| r.start).collect());
    }
    let mut group = 0usize;
    let mut in_group = 0usize;
    for batch in reader {
        let batch = batch.map_err(|e| invalid_parquet(format!("cannot decode POS column: {e}")))?;
        let pos = downcast_i32(&batch, "POS")?;
        for r in 0..batch.num_rows() {
            // Advance past any fully-consumed (or zero-row) groups.
            while group < counts.len() && in_group >= counts[group] {
                group += 1;
                in_group = 0;
            }
            if group >= counts.len() {
                break;
            }
            let p = pos.value(r);
            widen_bounds(&mut observed[group], p);
            // Attribute this row to its page: the last page whose start is <= in_group.
            if let Some(starts) = page_starts.get(group)
                && !starts.is_empty()
            {
                let page = starts.partition_point(|&start| start <= in_group).max(1) - 1;
                if let Some(slot) = page_observed.get_mut(group).and_then(|g| g.get_mut(page)) {
                    widen_bounds(slot, p);
                }
            }
            in_group += 1;
        }
    }

    for (i, obs) in observed.iter().enumerate() {
        let Some((omin, omax)) = *obs else { continue };
        let Some(Statistics::Int32(s)) = meta.row_group(i).column(0).statistics() else {
            continue;
        };
        let (Some(&dmin), Some(&dmax)) = (s.min_opt(), s.max_opt()) else {
            continue;
        };
        if !pos_stat_bounds_observed(dmin, dmax, omin, omax) {
            return Err(invalid_parquet(format!(
                "row group {i} POS statistics [{dmin}, {dmax}] do not bound its rows \
                     [{omin}, {omax}]: forged or stale statistics would let the serve path \
                     prune (hide) stored variants"
            )));
        }
    }
    verify_page_pos_statistics(meta, &page_observed)?;
    Ok(())
}

/// Verify each page's declared POS bounds against the rows it holds.
///
/// Split out of [`verify_pos_statistics`] so each granularity reads on its own. The serve
/// path prunes per page (`parquet_io::pos_row_selection`), so these are the numbers that
/// decide what a query can see.
fn verify_page_pos_statistics(
    meta: &ParquetMetaData,
    page_observed: &[Vec<Option<(i32, i32)>>],
) -> CoreResult<()> {
    // The same check at page granularity, against the column index the serve path prunes
    // with. A page whose declared bounds do not contain its own rows would make
    // `pos_row_selection` skip it, so stored variants would never be served.
    if let Some(column_index) = meta.column_index() {
        for (rg, pages) in page_observed.iter().enumerate() {
            let Some(ColumnIndexMetaData::INT32(idx)) =
                column_index.get(rg).and_then(|cols| cols.first())
            else {
                continue; // no (or non-INT32) page index: the serve path keeps the group
            };
            let mins: Vec<Option<&i32>> = idx.min_values_iter().collect();
            let maxs: Vec<Option<&i32>> = idx.max_values_iter().collect();
            for (page, obs) in pages.iter().enumerate() {
                let Some((omin, omax)) = *obs else { continue };
                let (Some(Some(&dmin)), Some(Some(&dmax))) =
                    (mins.get(page).copied(), maxs.get(page).copied())
                else {
                    continue; // a page with no declared bounds is never pruned
                };
                if !pos_stat_bounds_observed(dmin, dmax, omin, omax) {
                    return Err(invalid_parquet(format!(
                        "row group {rg} page {page} POS statistics [{dmin}, {dmax}] do not \
                             bound its rows [{omin}, {omax}]: the serve path prunes at page \
                             granularity, so forged page bounds would hide stored variants"
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Whether every allele-frequency parquet in `dir` is "AF-only": no row in any file
/// carries an `AC` or an `AN` value (both null throughout).
///
/// Such a dataset is entirely withheld at query time under a positive k-anonymity floor,
/// because the beacon query path's `row_survives` fail-closes an AF-only row. The node
/// therefore warns at ingest when this holds and a floor is configured; otherwise the
/// operator sees only empty query results. Reads just the projected `AC`/`AN` columns and
/// short-circuits on the first present value.
///
/// Takes the dataset's [`crate::parquet_io::DatasetDecryptor`] because the store it scans
/// may be PME-encrypted. A bare reader fails the footer parse on every `PARE` file, so on a
/// PME node the check would return no answer and the warning would never be emitted. Every
/// sibling reader of a stored file takes a decryptor for the same reason.
///
/// # Errors
///
/// Returns [`CoreError`] if a file cannot be read/decoded.
pub fn dir_af_only(
    dir: &Path,
    caps: &ParquetCaps,
    decryptor: &crate::parquet_io::DatasetDecryptor,
) -> CoreResult<bool> {
    let mut files: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        let is_af_file = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(crate::s3_layout::is_data_file_name);
        if is_af_file {
            files.push(path);
        }
    }
    for path in files {
        if fs::metadata(&path)?.len() > caps.max_parquet_file_bytes {
            // A too-large file is rejected by validation elsewhere; here, do not claim
            // AF-only for a file we decline to scan (fail toward "has counts").
            return Ok(false);
        }
        let file = fs::File::open(&path)?;
        // PME-aware: decrypts the footer on a `PARE` file, plain open otherwise.
        let builder = crate::parquet_io::open_reader_builder(file, decryptor, &path)?;
        // AC is leaf column 6, AN is leaf column 10 of the canonical allele-freq schema.
        let mask = ProjectionMask::leaves(builder.parquet_schema(), [6, 10]);
        let reader = builder
            .with_projection(mask)
            .build()
            .map_err(|e| invalid_parquet(format!("cannot build AC/AN reader: {e}")))?;
        for batch in reader {
            let batch =
                batch.map_err(|e| invalid_parquet(format!("cannot decode AC/AN columns: {e}")))?;
            let ac = downcast_i32(&batch, "AC")?;
            let an = downcast_i32(&batch, "AN")?;
            for i in 0..batch.num_rows() {
                if !ac.is_null(i) || !an.is_null(i) {
                    return Ok(false); // a count is present -> not AF-only
                }
            }
        }
    }
    Ok(true)
}

/// The AF-consistency tolerance, in alleles, for a population of `an` alleles.
///
/// `AF` reaches the parquet through a VCF that printed it with about six significant
/// digits, the precision common VCF writers use, so the value can sit up to `5e-7` from the
/// exact `AC / AN`, and `f32` storage adds at most half an ULP (`3e-8` below `1.0`).
/// `round(AF × AN)` therefore lands within `AN × 5.3e-7 + 0.5` of `AC`, which
/// `max(1, ceil(AN × 6e-7))` bounds from above at every `AN`. Below 1 666 667 alleles the
/// tolerance is one allele; at 4 M alleles it is 3, at 10 M it is 6. A
/// different-denominator `AF` (`popmax`, `faf`, an imputed frequency) diverges by orders of
/// magnitude more, so the check keeps its purpose without failing a cohort whose only
/// deviation is its size.
pub(crate) fn af_tolerance_alleles(an: i32) -> u32 {
    // ceil(an × 6e-7) in integers: (6·an) / 10^7, rounded up; `an` is non-negative here.
    let an = i64::from(an.max(0));
    let tolerance = (an * 6 + 9_999_999) / 10_000_000;
    u32::try_from(tolerance).unwrap_or(u32::MAX).max(1)
}

/// Per-row AC/AN/AF domain coherence, checked when AC and AN are both present (the caller
/// gates on that).
///
/// - `AC <= AN`: a (sub-)population's alternate count cannot exceed its allele number.
/// - `round(AF*AN) == AC` within [`af_tolerance_alleles`]: the served AF must be the
///   client-derivable `AC/AN`. AF is copied from the source, never recomputed, so a
///   fabricated or mis-derived AF would be served verbatim and would desync the
///   k-anonymity carrier reconstruction, which reads carriers as `round(AF*AN)` when the AC
///   column is absent (`beacon::query::alt_carriers`). The tolerance is the allele
///   granularity a six-significant-digit `AF` stored as `f32` can lose at this `AN`, so a
///   consistent printed AF passes at any cohort size.
///
/// # Errors
///
/// [`CoreError::InvalidParquet`] when AC exceeds AN, or AF is inconsistent with AC/AN.
pub(crate) fn check_ac_an_af(ac: i32, an: i32, af: f32) -> CoreResult<()> {
    if ac > an {
        return Err(invalid_parquet(format!("AC {ac} exceeds AN {an}")));
    }
    let derived = (f64::from(af) * f64::from(an)).round();
    let tolerance = af_tolerance_alleles(an);
    if (derived - f64::from(ac)).abs() > f64::from(tolerance) {
        return Err(invalid_parquet(format!(
            "AF {af} is inconsistent with AC {ac} / AN {an}: round(AF*AN) = {derived}, \
                 expected AC {ac} within {tolerance} allele(s), the slack a \
                 six-significant-digit AF has at this AN, so this AF is not this \
                 population's own AC/AN"
        )));
    }
    Ok(())
}

/// Accumulates one variant's per-population counts across record batches so the node can
/// re-check population-hierarchy coherence independently of the producer.
///
/// `convert` enforces the hierarchy at build time, but a hand-assembled parquet never
/// passed through it. The check needs every population of one `(POS, REF, ALT)`, which the
/// per-row loop cannot see, so the group is accumulated here and closed when the key
/// changes.
///
/// Safe to fold across batches because the writer sorts every partition by
/// `(POS, REF, ALT, POPULATION)`, so a group's rows are contiguous. That order is only
/// advertised (`sorting_columns`), never trusted: a key that goes backwards ends the group
/// early, which can make this check weaker but never wrong, and the non-decreasing POS rule
/// beside it rejects genuinely unsorted files.
#[derive(Default)]
struct HierarchyAcc {
    /// The open group's key, or `None` before the first row.
    key: Option<(i32, String, String)>,
    /// Per-population counts within the open group.
    counts: std::collections::BTreeMap<String, crate::hierarchy::PopCounts>,
}

impl HierarchyAcc {
    /// Close the open group (if any) and validate it.
    fn flush(&mut self) -> CoreResult<()> {
        let counts = std::mem::take(&mut self.counts);
        self.key = None;
        if counts.len() < 2 {
            return Ok(()); // one population cannot contradict another
        }
        crate::hierarchy::check_hierarchy(&counts).map_err(|e| invalid_parquet(e.to_string()))
    }

    /// Add one row, flushing first when it opens a new `(POS, REF, ALT)` group.
    fn push(
        &mut self,
        pos: i32,
        ref_: &str,
        alt: &str,
        population: &str,
        ac: Option<i64>,
        an: Option<i64>,
    ) -> CoreResult<()> {
        let key = (pos, ref_.to_owned(), alt.to_owned());
        if self.key.as_ref() != Some(&key) {
            self.flush()?;
            self.key = Some(key);
        }
        self.counts.insert(
            population.to_owned(),
            crate::hierarchy::PopCounts { ac, an },
        );
        Ok(())
    }
}

/// Apply the per-row value rules to one record batch.
///
/// `prev_pos` carries the last seen POS across batches and row groups, so the
/// non-decreasing check spans the whole file.
fn check_batch_values(
    batch: &RecordBatch,
    caps: &ParquetCaps,
    prev_pos: &mut Option<i32>,
    hierarchy: &mut HierarchyAcc,
) -> CoreResult<()> {
    let pos = downcast_i32(batch, "POS")?;
    let ref_ = downcast_str(batch, "REF")?;
    let alt = downcast_str(batch, "ALT")?;
    let vt = downcast_str(batch, "VT")?;
    let af = downcast_f32(batch, "AF")?;
    let ac = downcast_i32(batch, "AC")?;
    let ac_hom = downcast_i32(batch, "AC_HOM")?;
    let ac_het = downcast_i32(batch, "AC_HET")?;
    let ac_hemi = downcast_i32(batch, "AC_HEMI")?;
    let an = downcast_i32(batch, "AN")?;
    let population = downcast_str(batch, "POPULATION")?;

    for i in 0..batch.num_rows() {
        let p = pos.value(i);
        if p < 0 {
            return Err(invalid_parquet(format!("POS {p} is negative")));
        }
        if let Some(prev) = *prev_pos
            && p < prev
        {
            return Err(invalid_parquet(format!(
                "POS {p} is before the previous position {prev}"
            )));
        }
        *prev_pos = Some(p);

        let r = ref_.value(i);
        check_bases("REF", r)?;
        if r.len() > caps.max_ref_len {
            return Err(invalid_parquet(format!(
                "REF length {} exceeds max_ref_len {}",
                r.len(),
                caps.max_ref_len
            )));
        }
        let alt_str = alt.value(i);
        check_bases("ALT", alt_str)?;
        if alt_str.len() > caps.max_alt_len {
            return Err(invalid_parquet(format!(
                "ALT length {} exceeds max_alt_len {}",
                alt_str.len(),
                caps.max_alt_len
            )));
        }

        // POPULATION is served verbatim in every `frequencyInPopulations[].population`, so
        // cap its length in chars, matching the producer. A hand-assembled parquet that
        // bypasses `convert` then cannot amplify a small query into a multi-megabyte
        // response or bloat the stored file.
        let pop = population.value(i);
        let pop_chars = pop.chars().count();
        if pop_chars > caps.max_population_len {
            return Err(invalid_parquet(format!(
                "POPULATION length {pop_chars} exceeds max_population_len {}",
                caps.max_population_len
            )));
        }

        // The storable VT vocabulary is defined once, on the enum the read path decodes
        // into; a second copy of the label list here would be free to drift from it.
        let v = vt.value(i);
        if crate::variant::Vt::parse(v).is_none() {
            return Err(invalid_parquet(format!(
                "VT {v:?} is not one of SNP/MNP/INS/DEL/DELINS"
            )));
        }

        // AF is a served public statistic, so it must be a finite number in the closed
        // interval [0, 1]. A value outside it is a percentage-vs-fraction or mis-summed-AF
        // artifact, and NaN or infinity would serialize to a non-numeric wire value. The
        // trusted convert path enforces this too; mirroring it here stops a crafted parquet
        // bypassing the domain. A bare `> 1.0` check catches neither `NaN` nor `-0.5`.
        let f = af.value(i);
        if !f.is_finite() || !(0.0..=1.0).contains(&f) {
            return Err(invalid_parquet(format!(
                "AF {f} is outside [0, 1] or non-finite"
            )));
        }

        // Every served allele count must be non-negative.
        for (name, col) in [
            ("AC", ac),
            ("AC_HOM", ac_hom),
            ("AC_HET", ac_het),
            ("AC_HEMI", ac_hemi),
            ("AN", an),
        ] {
            if !col.is_null(i) && col.value(i) < 0 {
                return Err(invalid_parquet(format!(
                    "{name} {} is negative",
                    col.value(i)
                )));
            }
        }
        if !ac.is_null(i) && !an.is_null(i) {
            check_ac_an_af(ac.value(i), an.value(i), f)?;
        }

        // The genotype sub-counts count alleles and partition AC. `convert` enforces this
        // producer-side; re-checking it here from the same predicate covers a
        // hand-assembled parquet. An incoherent set would otherwise be served verbatim as
        // `alleleCountHomozygous` and its siblings, and the k-anonymity sub-count gate
        // reasons about these values relative to the floor.
        let count = |col: &Int32Array| (!col.is_null(i)).then(|| i64::from(col.value(i)));
        check_subcounts(count(ac), count(ac_hom), count(ac_het), count(ac_hemi)).map_err(|e| {
            invalid_parquet(format!("{e} for population {:?}", population.value(i)))
        })?;

        // The populations' coherence with each other (`FI_M` inside `FI` inside `Total`),
        // the level above `check_subcounts`. Same reasoning: `convert` enforces it, and a
        // hand-assembled parquet never went through `convert`.
        hierarchy.push(
            p,
            ref_.value(i),
            alt.value(i),
            population.value(i),
            count(ac),
            count(an),
        )?;
    }
    Ok(())
}

/// Verify `s` contains only the uppercase bases `ACGTN`.
fn check_bases(col: &str, s: &str) -> CoreResult<()> {
    if s.is_empty()
        || !s
            .bytes()
            .all(|b| matches!(b, b'A' | b'C' | b'G' | b'T' | b'N'))
    {
        return Err(invalid_parquet(format!(
            "{col} {s:?} contains non-ACGTN characters"
        )));
    }
    Ok(())
}

/// Reject a population-label count above [`crate::convert::MAX_POPULATIONS`].
///
/// The cap is expressed once here, shared by the per-(chr, block)-group scan and the
/// dataset-wide union in [`validate_parquet_dir`]. A second copy would let the two drift,
/// and the dataset-wide bound is the one the constant's own doc and
/// `docs/gdi-dataset-tool.md` promise.
fn check_population_cap(count: usize) -> CoreResult<()> {
    if count > crate::convert::MAX_POPULATIONS {
        return Err(invalid_parquet(format!(
            "dataset declares more than {} populations (exceeds MAX_POPULATIONS)",
            crate::convert::MAX_POPULATIONS
        )));
    }
    Ok(())
}

/// Rows per decoded batch a [`RowCursor`] buffers.
///
/// Named here rather than inherited from parquet's `DEFAULT_BATCH_SIZE`. The k-way merge
/// holds one fully-decoded batch per open cursor at once, so this is a multiplicand of the
/// ingest memory peak. Taking it from a dependency would let a parquet bump move the node's
/// memory ceiling with no line changing here.
pub(crate) const ROW_CURSOR_BATCH_ROWS: usize = 1024;

/// Ceiling on the bytes the primed k-way merge may hold across every cursor of one
/// `(chr, block)` group.
///
/// `max_files_per_group` bounds open descriptors, not the product of descriptors and
/// buffered batch. `min_front_pos` primes every cursor before any is drained, so without
/// this ceiling the peak at the caps is about 20 GiB live (1024 files × 1024 rows ×
/// ~20 KB/row, the worst case `worst_case_row_bytes` derives from the caps). The ingest
/// worker is a `spawn_blocking` task in the node process, so that
/// is an allocator abort, which `catch_parquet_panic` cannot intercept, or an OOM-kill
/// taking the Beacon and FDP listeners with it before any quarantine decision is reached.
/// The package would then stay in the channel and the boot rescan would re-queue it, giving
/// a crash loop from one uploaded package.
pub(crate) const MAX_GROUP_WORKING_SET_BYTES: usize = 256 * 1024 * 1024;

/// Per-buffered-row byte cost, upper-bounded from the caps alone.
///
/// A [`URow`] owns three `String`s; 24 bytes of header each is the allocation overhead the
/// contents sit on top of.
pub(crate) fn worst_case_row_bytes(caps: &ParquetCaps) -> usize {
    const STRING_HEADER_BYTES: usize = 24;
    caps.max_ref_len
        .saturating_add(caps.max_alt_len)
        .saturating_add(caps.max_population_len)
        .saturating_add(3 * STRING_HEADER_BYTES)
        .max(1)
}

/// The batch size that keeps `files` primed cursors inside [`MAX_GROUP_WORKING_SET_BYTES`].
///
/// Shrinks the buffered working set rather than the descriptor count, because the working
/// set is what allocates. Never below one row: the merge must still make progress, and one
/// row per cursor is the degenerate but correct shape.
pub(crate) fn group_batch_rows(files: usize, caps: &ParquetCaps) -> usize {
    let budget = MAX_GROUP_WORKING_SET_BYTES / files.max(1) / worst_case_row_bytes(caps);
    budget.clamp(1, ROW_CURSOR_BATCH_ROWS)
}

/// Streaming uniqueness merge across a `(chr, block)` group's files.
///
/// Each file is POS-sorted, so a per-file streaming scan catches adjacent in-file
/// duplicates, and a k-way merge across the group's files catches a
/// `(POS, REF, ALT, population)` tuple shared between two VCFs. Both run in bounded memory:
/// one front row per file, plus the rows sharing the current minimum POS.
fn check_group_uniqueness(
    files: &[PathBuf],
    caps: &ParquetCaps,
) -> CoreResult<(u64, BTreeSet<String>)> {
    let mut populations: BTreeSet<String> = BTreeSet::new();
    // Bound the fan-out before opening anything: the k-way merge holds one open descriptor
    // and reader per group member at once, and the group key is only `(chr, block)`, so
    // files differing solely by `vcfid` all pile into one group. Without this cap a crafted
    // package could force tens of thousands of concurrent open descriptors on the ingest
    // worker. A real group has a handful of files, so this fails closed well before
    // exhausting the descriptor table.
    if files.len() > caps.max_files_per_group {
        return Err(invalid_parquet(format!(
            "{} files in a single (chr, block) group exceeds max_files_per_group {}",
            files.len(),
            caps.max_files_per_group
        )));
    }
    // Cursors: one streaming row iterator per file, each buffering a batch sized so that all
    // of them primed together stay inside `MAX_GROUP_WORKING_SET_BYTES`. The cap above
    // bounds descriptors; this bounds the bytes those descriptors hold, which is the term
    // that OOMs.
    let batch_rows = group_batch_rows(files.len(), caps);
    let mut cursors: Vec<RowCursor> = Vec::with_capacity(files.len());
    for path in files {
        cursors.push(RowCursor::open(path, caps, batch_rows)?);
    }
    // Distinct `(POS, REF, ALT)` variants in this group, populations collapsed: the group's
    // contribution to `numberOfRecords`.
    let mut distinct_variants: u64 = 0;

    // Process locus-by-locus across all files, ascending by POS. For each
    // minimum POS, gather every row at that POS from every file into a small
    // working set, then assert no duplicate (POS, REF, ALT, population) key.
    while let Some(pos) = min_front_pos(&mut cursors)? {
        let keys = keys_at_pos(&mut cursors, pos, caps, &mut populations)?;
        // Distinct variants at this POS are the distinct (REF, ALT) pairs: a variant
        // reported for N populations is one record. Projected from the already-built
        // per-POS key set, so the hot scan gains no per-row allocation.
        distinct_variants += keys
            .iter()
            .map(|(r, a, _)| (r.as_str(), a.as_str()))
            .collect::<std::collections::HashSet<_>>()
            .len() as u64;
    }

    Ok((distinct_variants, populations))
}

/// The smallest POS at the front of any cursor, or `None` once every cursor is exhausted.
///
/// Priming each cursor's look-ahead is what drives the per-file decode, and therefore the
/// per-batch value checks folded into [`RowCursor::refill`].
///
/// # Errors
///
/// Whatever decoding the next batch of any cursor reports (schema, cap, or value
/// violations).
fn min_front_pos(cursors: &mut [RowCursor]) -> CoreResult<Option<i32>> {
    let mut min_pos: Option<i32> = None;
    for c in cursors {
        if let Some(row) = c.peek()? {
            min_pos = Some(min_pos.map_or(row.pos, |m| m.min(row.pos)));
        }
    }
    Ok(min_pos)
}

/// Drain every row at `pos` from every cursor, returning the locus's distinct
/// `(REF, ALT, population)` keys and extending `populations` with the labels seen.
///
/// This is the per-locus working set the two per-POS caps bound: the cursors are
/// POS-sorted, so it holds only the rows sharing the current minimum POS.
///
/// # Errors
///
/// [`CoreError::InvalidParquet`] on a repeated `(POS, REF, ALT, population)` key, on more
/// than `convert::MAX_POPULATIONS` distinct labels, or when the locus exceeds either
/// per-POS working-set cap — `max_distinct_keys_per_pos` (count) or `max_pos_key_bytes`
/// (size).
fn keys_at_pos(
    cursors: &mut [RowCursor],
    pos: i32,
    caps: &ParquetCaps,
    populations: &mut BTreeSet<String>,
) -> CoreResult<std::collections::HashSet<(String, String, String)>> {
    let mut keys: std::collections::HashSet<(String, String, String)> =
        std::collections::HashSet::new();
    // Cumulative REF+ALT+POPULATION bytes of the distinct keys at this POS: bounds the
    // working set by size, which `max_distinct_keys_per_pos`, a count, does not.
    let mut pos_bytes: u64 = 0;
    for c in cursors {
        while c.peek()?.is_some_and(|r| r.pos == pos) {
            let row = c.next_row()?;
            // The distinct label set is what the node advertises as the dataset's
            // populations, so it is collected from the data rather than trusted. Costs a
            // lookup per row and a clone only for a label never seen before.
            if !populations.contains(&row.population) {
                populations.insert(row.population.clone());
                // Enforce the population-count cap at ingest, not only producer-side: the
                // `MAX_POPULATIONS` cap in `convert` bounds the trusted build path, but a
                // hand-crafted parquet can declare far more.
                //
                // This arm bounds one (chr, block) group, which is what keeps this scan's
                // memory bounded. The dataset-wide guarantee lives at the union in
                // `validate_parquet_dir`, since N groups each just under the cap sum to N
                // times it. Both call `check_population_cap`, so the bound and its message
                // have one definition.
                check_population_cap(populations.len())?;
            }
            let key = (row.r#ref, row.alt, row.population);
            let key_bytes = (key.0.len() + key.1.len() + key.2.len()) as u64;
            if !keys.insert(key) {
                // Name the offending locus. POS is `Copy`, so this adds no per-row cost on
                // the ingest validation path; REF, ALT and population would each need a
                // clone per row and are omitted.
                return Err(invalid_parquet(format!(
                    "duplicate variant+population at POS {pos} within the dataset"
                )));
            }
            // Bound the per-POS working set by count: the decompression caps are
            // POS-independent and do not cover this cross-file set, so a crafted parquet
            // could otherwise pile unbounded rows onto one locus.
            if keys.len() > caps.max_distinct_keys_per_pos {
                return Err(invalid_parquet(format!(
                    "more than {} distinct rows at a single POS (exceeds max_distinct_keys_per_pos)",
                    caps.max_distinct_keys_per_pos
                )));
            }
            // ...and by bytes: a few keys each carrying a huge REF/ALT/POPULATION would
            // evade the count cap while still exhausting memory at one locus.
            pos_bytes = pos_bytes.saturating_add(key_bytes);
            if pos_bytes > caps.max_pos_key_bytes {
                return Err(invalid_parquet(format!(
                    "distinct rows at POS {pos} exceed the {}-byte per-POS working-set cap (max_pos_key_bytes)",
                    caps.max_pos_key_bytes
                )));
            }
        }
    }
    Ok(keys)
}

/// One decoded uniqueness-relevant row: POS plus the three string keys.
#[derive(Debug, Clone)]
struct URow {
    pos: i32,
    r#ref: String,
    alt: String,
    population: String,
}

/// A streaming, peekable row cursor over one parquet file's data files,
/// reading one row group (and one batch) at a time.
struct RowCursor {
    /// Persistent reader over the whole file's row groups, opened once. It yields one
    /// batch at a time lazily, so the cursor buffers a single batch without reopening
    /// and re-parsing the footer per row group.
    reader: ParquetRecordBatchReader,
    /// Buffered rows from the current batch, consumed front-to-back.
    buffer: std::collections::VecDeque<URow>,
    /// One-row look-ahead, populated by [`RowCursor::peek`].
    lookahead: Option<URow>,
    /// The validation caps, applied to every decoded batch's value checks.
    caps: ParquetCaps,
    /// The last-seen POS in this file, threading the non-decreasing check across batches
    /// and row groups. It is a per-file property.
    prev_pos: Option<i32>,
    /// Cross-batch accumulator for the population-hierarchy re-check.
    hierarchy: HierarchyAcc,
    /// The `(block, block_range)` this file's name declares, or `None` for a name that is
    /// not a well-formed data-file name. When set, every decoded row's POS must map to
    /// `block` under `block_range`, proving the file's content matches the block the serve
    /// path would resolve it as.
    block_check: Option<(u64, u32)>,
}

impl RowCursor {
    /// Open a cursor over `path`: one file open and footer parse for the whole file, then
    /// the per-file pre-decode guards, so the file is decoded once for both value
    /// validation and the uniqueness scan. The guards are the on-disk size cap, the
    /// exact-schema check and the decompression-bomb row-group caps, all before any data is
    /// decoded.
    ///
    /// `batch_rows` bounds the rows this cursor buffers at once. It is a parameter rather
    /// than a default because only the caller knows the fan-out: the merge holds one such
    /// batch per cursor at once, so the safe size depends on how many cursors will exist.
    /// See [`group_batch_rows`].
    fn open(path: &Path, caps: &ParquetCaps, batch_rows: usize) -> CoreResult<Self> {
        let on_disk = fs::metadata(path)?.len();
        if on_disk > caps.max_parquet_file_bytes {
            return Err(invalid_parquet(format!(
                "parquet file size {on_disk} exceeds max_parquet_file_bytes {}",
                caps.max_parquet_file_bytes
            )));
        }
        let file = fs::File::open(path)?;
        // Load the page index with the footer: `enforce_page_size_caps` below needs the
        // per-page offsets. Without it the metadata carries none, which that check reads as
        // "cannot be bounded".
        let builder = ParquetRecordBatchReaderBuilder::try_new_with_options(
            file,
            ArrowReaderOptions::new().with_page_index_policy(PageIndexPolicy::Required),
        )
        .map_err(|e| invalid_parquet(format!("cannot open parquet metadata: {e}")))?;
        check_schema(builder.schema())?;
        // Decompression-size caps from row-group metadata, before decoding any data, so a
        // decompression bomb is rejected without expanding it.
        let meta = builder.metadata().clone();
        let mut total_decompressed: u64 = 0;
        for i in 0..meta.num_row_groups() {
            enforce_row_group_caps(
                meta.row_group(i).total_byte_size(),
                caps,
                &mut total_decompressed,
            )?;
        }
        // The other half of the bomb defence. The caps above read `total_byte_size`, which
        // the producer writes and the decoder never consults; the bytes allocated come from
        // each page header's `uncompressed_page_size`. Bound every page by its row group's
        // already-capped total, so a page cannot be widened without widening the row group
        // the caps above reject.
        crate::parquet_pages::enforce_page_size_caps(path, &meta)?;
        // Forged/stale per-row-group POS statistics would let the serve path prune (hide)
        // stored rows without decoding them; reject a file whose declared POS stats do not
        // bound its actual rows before it is served.
        verify_pos_statistics(path, &meta)?;
        let reader = builder
            .with_batch_size(batch_rows)
            .build()
            .map_err(|e| invalid_parquet(format!("cannot build parquet reader: {e}")))?;
        let block_check = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(parse_block_and_range);
        Ok(Self {
            reader,
            buffer: std::collections::VecDeque::new(),
            lookahead: None,
            caps: *caps,
            prev_pos: None,
            hierarchy: HierarchyAcc::default(),
            block_check,
        })
    }

    /// Fill `buffer` from the next non-empty batch, if any.
    fn refill(&mut self) -> CoreResult<()> {
        while self.buffer.is_empty() {
            let Some(batch) = self.reader.next() else {
                // Reader exhausted: close the last open variant group, which no later key
                // change will close for us.
                self.hierarchy.flush()?;
                break;
            };
            let batch =
                batch.map_err(|e| invalid_parquet(format!("cannot decode parquet batch: {e}")))?;
            // Per-row value checks folded in (POS ordering and value ranges), so this one
            // decode both validates the file and feeds the uniqueness scan.
            check_batch_values(&batch, &self.caps, &mut self.prev_pos, &mut self.hierarchy)?;
            let pos = downcast_i32(&batch, "POS")?;
            let ref_ = downcast_str(&batch, "REF")?;
            let alt = downcast_str(&batch, "ALT")?;
            let population = downcast_str(&batch, "POPULATION")?;
            for i in 0..batch.num_rows() {
                let pos_i = pos.value(i);
                // The file's rows must fall in the block its name declares, using the same
                // `partition_group` formula the convert batcher routed them by. The serve
                // path resolves a file purely by its named `(block, block_range)`, so
                // otherwise rows would be unqueryable.
                if let Some((block, range)) = self.block_check {
                    let actual = crate::convert::partition_group(pos_i, range);
                    if actual != block {
                        return Err(invalid_parquet(format!(
                            "POS {pos_i} maps to block {actual} but the file is named for \
                                 block {block} (blockRange {range})"
                        )));
                    }
                }
                self.buffer.push_back(URow {
                    pos: pos_i,
                    r#ref: ref_.value(i).to_string(),
                    alt: alt.value(i).to_string(),
                    population: population.value(i).to_string(),
                });
            }
        }
        Ok(())
    }

    /// Look at the next row without consuming it, lazily reading the next row
    /// group if needed. Returns `Ok(None)` once the cursor is exhausted.
    fn peek(&mut self) -> CoreResult<Option<&URow>> {
        if self.lookahead.is_none() {
            if self.buffer.is_empty() {
                self.refill()?;
            }
            self.lookahead = self.buffer.pop_front();
        }
        Ok(self.lookahead.as_ref())
    }

    /// Consume and return the next row. Returns an error only if called past the
    /// end of the cursor (the caller observes the end via [`RowCursor::peek`]).
    fn next_row(&mut self) -> CoreResult<URow> {
        self.peek()?;
        match self.lookahead.take() {
            Some(row) => Ok(row),
            None => Err(invalid_parquet(
                "internal: next_row past end of cursor".to_string(),
            )),
        }
    }
}

// The column-downcast helpers are single-sourced in `parquet_io`, the read half of the same
// defence, and re-exported here under the local `downcast_*` names so the two modules
// cannot drift on the error text.
use crate::parquet_io::{
    col_f32 as downcast_f32, col_i32 as downcast_i32, col_str as downcast_str,
};

/// Enforce the per-row-group and cumulative decompressed-size caps against a row
/// group's self-reported `total_byte_size` (bytes), advancing `total_decompressed`.
///
/// Single-sources the pre-decode decompression-bomb guard shared by the validate
/// path here and the read path in [`crate::parquet_io`], so a future tightening of
/// the bomb bounds applies to both halves of the defence.
///
/// # Errors
/// [`CoreError::InvalidParquet`] if this group's size exceeds
/// `max_parquet_row_group_bytes`, or the running total exceeds
/// `max_parquet_decompressed_bytes`.
pub(crate) fn enforce_row_group_caps(
    rg_total_byte_size: i64,
    caps: &ParquetCaps,
    total_decompressed: &mut u64,
) -> CoreResult<()> {
    let rg_uncompressed = u64::try_from(rg_total_byte_size).unwrap_or(u64::MAX);
    if rg_uncompressed > caps.max_parquet_row_group_bytes {
        return Err(invalid_parquet(format!(
            "row group decompressed size {rg_uncompressed} exceeds \
                 max_parquet_row_group_bytes {}",
            caps.max_parquet_row_group_bytes
        )));
    }
    *total_decompressed = total_decompressed.saturating_add(rg_uncompressed);
    if *total_decompressed > caps.max_parquet_decompressed_bytes {
        return Err(invalid_parquet(format!(
            "file decompressed size {} exceeds max_parquet_decompressed_bytes {}",
            *total_decompressed, caps.max_parquet_decompressed_bytes
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use std::path::Path;
    use std::sync::Arc;

    use arrow_array::{Float32Array, Int32Array, RecordBatch, StringArray};
    use parquet::arrow::arrow_writer::ArrowWriter;
    use parquet::file::properties::WriterProperties;
    use proptest::prelude::*;

    use super::*;
    use crate::convert::{ConvertOptions, convert_vcf};
    use crate::error::ErrorClass;

    /// A hand-built fixture row (`ac`/`an` are written non-null). `ac_hom` is
    /// written into the `AC_HOM` column; `row()` defaults it to 0.
    struct TestRow {
        pos: i32,
        r#ref: String,
        alt: String,
        vt: String,
        population: String,
        af: f32,
        ac: i32,
        an: i32,
        ac_hom: i32,
    }

    /// Construct a [`TestRow`] tersely (`ac_hom` defaults to 0; set it via struct
    /// update syntax `TestRow { ac_hom: -1, ..row(..) }` when a test needs it).
    #[expect(
        clippy::too_many_arguments,
        reason = "test-fixture row constructor; named struct fields are clearer than a builder here"
    )]
    fn row(
        pos: i32,
        r#ref: &str,
        alt: &str,
        vt: &str,
        population: &str,
        af: f32,
        ac: i32,
        an: i32,
    ) -> TestRow {
        TestRow {
            pos,
            r#ref: r#ref.to_string(),
            alt: alt.to_string(),
            vt: vt.to_string(),
            population: population.to_string(),
            af,
            ac,
            an,
            ac_hom: 0,
        }
    }

    /// Write one parquet file with the canonical schema and the given rows.
    fn write_parquet(path: &Path, rows: &[TestRow]) {
        write_parquet_with_props(path, rows, None);
    }

    fn write_parquet_with_props(
        path: &Path,
        rows: &[TestRow],
        props: Option<parquet::file::properties::WriterProperties>,
    ) {
        let schema = allele_freq_schema();
        let pos = Int32Array::from(rows.iter().map(|r| r.pos).collect::<Vec<_>>());
        let ref_ = StringArray::from(rows.iter().map(|r| r.r#ref.as_str()).collect::<Vec<_>>());
        let alt = StringArray::from(rows.iter().map(|r| r.alt.as_str()).collect::<Vec<_>>());
        let vt = StringArray::from(rows.iter().map(|r| r.vt.as_str()).collect::<Vec<_>>());
        let population = StringArray::from(
            rows.iter()
                .map(|r| r.population.as_str())
                .collect::<Vec<_>>(),
        );
        let af = Float32Array::from(rows.iter().map(|r| r.af).collect::<Vec<_>>());
        let ac = Int32Array::from(rows.iter().map(|r| Some(r.ac)).collect::<Vec<_>>());
        let ac_hom = Int32Array::from(rows.iter().map(|r| Some(r.ac_hom)).collect::<Vec<_>>());
        // AC_HET / AC_HEMI are NULL, i.e. *not reported* — these rows exercise POS/REF/ALT/
        // AF/AC/AN, not the genotype classes. Writing `Some(0)` here would instead assert
        // that every alternate allele lies in no genotype class, which `check_subcounts`
        // correctly rejects for any `AC > 0`.
        let unreported = Int32Array::from(vec![None::<i32>; rows.len()]);
        let an = Int32Array::from(rows.iter().map(|r| Some(r.an)).collect::<Vec<_>>());
        let batch = RecordBatch::try_new(
            Arc::clone(&schema),
            vec![
                Arc::new(pos),
                Arc::new(ref_),
                Arc::new(alt),
                Arc::new(vt),
                Arc::new(population),
                Arc::new(af),
                Arc::new(ac),
                Arc::new(ac_hom),
                Arc::new(unreported.clone()),
                Arc::new(unreported),
                Arc::new(an),
            ],
        )
        .unwrap();
        let file = std::fs::File::create(path).unwrap();
        let mut writer = ArrowWriter::try_new(file, schema, props).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
    }

    /// Validate a one-row parquet built from a single [`TestRow`]; returns the
    /// validation result so a test can assert pass/fail.
    fn validate_one_row(row: TestRow) -> CoreResult<()> {
        let dir = tempfile::tempdir().unwrap();
        let file = dir
            .path()
            .join("allele-freq.chr3.0.br10000000.0123456789abcdef.parquet");
        write_parquet(&file, &[row]);
        validate_parquet_dir(dir.path(), &ParquetCaps::default()).map(|_| ())
    }

    /// Write a single-row parquet whose `AN` column is NULL (with the given `AC`),
    /// which the shared `write_parquet` helper cannot express, and validate it.
    fn validate_one_row_null_an(ac: i32) -> CoreResult<()> {
        let dir = tempfile::tempdir().unwrap();
        let file = dir
            .path()
            .join("allele-freq.chr3.0.br10000000.0123456789abcdef.parquet");
        let schema = allele_freq_schema();
        // The genotype sub-counts are NULL (not reported): this row is about the AC/AN
        // gate, and a reported all-zero set under `AC > 0` is independently incoherent.
        let unreported = || Int32Array::from(vec![None::<i32>]);
        let batch = RecordBatch::try_new(
            Arc::clone(&schema),
            vec![
                Arc::new(Int32Array::from(vec![Some(100)])),   // POS
                Arc::new(StringArray::from(vec!["T"])),        // REF
                Arc::new(StringArray::from(vec!["C"])),        // ALT
                Arc::new(StringArray::from(vec!["SNP"])),      // VT
                Arc::new(StringArray::from(vec!["Total"])),    // population
                Arc::new(Float32Array::from(vec![0.5f32])),    // AF
                Arc::new(Int32Array::from(vec![Some(ac)])),    // AC
                Arc::new(unreported()),                        // AC_HOM
                Arc::new(unreported()),                        // AC_HET
                Arc::new(unreported()),                        // AC_HEMI
                Arc::new(Int32Array::from(vec![None::<i32>])), // AN (null)
            ],
        )
        .unwrap();
        let f = std::fs::File::create(&file).unwrap();
        let mut w = ArrowWriter::try_new(f, schema, None).unwrap();
        w.write(&batch).unwrap();
        w.close().unwrap();
        validate_parquet_dir(dir.path(), &ParquetCaps::default()).map(|_| ())
    }

    /// Write a single-row parquet with explicit genotype sub-counts (`None` = the column
    /// is NULL, i.e. the class was not reported) and validate the directory.
    fn validate_one_row_subcounts(
        ac: i32,
        hom: Option<i32>,
        het: Option<i32>,
        hemi: Option<i32>,
    ) -> CoreResult<()> {
        let dir = tempfile::tempdir().unwrap();
        let file = dir
            .path()
            .join("allele-freq.chr3.0.br10000000.0123456789abcdef.parquet");
        let schema = allele_freq_schema();
        let batch = RecordBatch::try_new(
            Arc::clone(&schema),
            vec![
                Arc::new(Int32Array::from(vec![Some(100)])), // POS
                Arc::new(StringArray::from(vec!["T"])),      // REF
                Arc::new(StringArray::from(vec!["C"])),      // ALT
                Arc::new(StringArray::from(vec!["SNP"])),    // VT
                Arc::new(StringArray::from(vec!["Total"])),  // population
                Arc::new(Float32Array::from(vec![0.5f32])),  // AF
                Arc::new(Int32Array::from(vec![Some(ac)])),  // AC
                Arc::new(Int32Array::from(vec![hom])),       // AC_HOM
                Arc::new(Int32Array::from(vec![het])),       // AC_HET
                Arc::new(Int32Array::from(vec![hemi])),      // AC_HEMI
                Arc::new(Int32Array::from(vec![Some(8)])),   // AN
            ],
        )
        .unwrap();
        let f = std::fs::File::create(&file).unwrap();
        let mut w = ArrowWriter::try_new(f, schema, None).unwrap();
        w.write(&batch).unwrap();
        w.close().unwrap();
        validate_parquet_dir(dir.path(), &ParquetCaps::default()).map(|_| ())
    }

    #[test]
    fn non_acgtn_bases_are_rejected() {
        // The REF/ALT base-character gate must reject an empty string and any byte outside
        // ACGTN, so a crafted parquet cannot serve non-conforming referenceBases or
        // alternateBases verbatim into RDF. Both halves of
        // `s.is_empty() || !all_acgtn(s)` are covered.
        for (col, r, a) in [("REF", "X", "C"), ("ALT", "A", "Z"), ("empty-REF", "", "C")] {
            let err = validate_one_row(row(100, r, a, "SNP", "Total", 0.1, 1, 10)).unwrap_err();
            assert_eq!(
                err.class(),
                ErrorClass::InvalidParquetSchema,
                "{col}: non-ACGTN/empty base must be rejected"
            );
        }
        // Canonical bases still pass.
        validate_one_row(row(100, "T", "C", "SNP", "Total", 0.1, 1, 10)).unwrap();
    }

    #[test]
    fn ac_exceeding_an_is_rejected() {
        // AC must never exceed AN: that is an impossible allele count, so a mis-summed or
        // crafted statistic. Covers the comparison and the non-null gate reaching it.
        let err = validate_one_row(row(100, "T", "C", "SNP", "Total", 0.5, 100, 10)).unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidParquetSchema);
    }

    #[test]
    fn ac_equal_to_an_is_accepted() {
        // AC == AN (every allele is the ALT, AF = 1.0) is valid, so the comparison must be
        // `>` rather than `>=`.
        validate_one_row(row(100, "T", "C", "SNP", "Total", 1.0, 10, 10))
            .expect("AC == AN is a valid row");
    }

    #[test]
    fn ac_with_null_an_is_accepted() {
        // When AN is NULL the AC-vs-AN comparison must be skipped, not run against a null
        // read as 0, which would false-reject a valid AC.
        validate_one_row_null_an(5).expect("AC with a null AN must be accepted");
    }

    /// The ingest gate rejects a row whose AF is inconsistent with AC/AN. AF is a served
    /// public statistic, and the k-anonymity floor derives carriers as `round(AF*AN)` when
    /// AC is absent, so a fabricated AF is both a disclosure and a suppression-desync risk.
    /// The check is the identity `round(AF*AN) == AC` within `af_tolerance_alleles`.
    #[test]
    fn af_inconsistent_with_ac_over_an_is_rejected_at_ingest() {
        // AF=0.5 of AN=8000 implies ~4000 carriers, but AC=1: round(0.5*8000)=4000 != 1.
        let err = validate_one_row(row(100, "T", "C", "SNP", "Total", 0.5, 1, 8000))
            .expect_err("an AF grossly inconsistent with AC/AN must be rejected");
        assert!(
            err.to_string().contains("inconsistent with AC"),
            "expected an AF-consistency error, got: {err}"
        );

        // The consistent AF for the same AC/AN (1/8000) is accepted — the check discriminates.
        validate_one_row(row(100, "T", "C", "SNP", "Total", 0.000_125, 1, 8000))
            .expect("an AF equal to AC/AN must be accepted");

        // A one-allele discrepancy is the whole tolerance at AN 8000, which f32 precision
        // and a lightly-rounded AF can produce: round(0.000_03*8000) = 0, one allele from
        // AC = 1.
        validate_one_row(row(100, "T", "C", "SNP", "Total", 0.000_03, 1, 8000))
            .expect("an AF within one allele of AC/AN must be accepted");
    }

    /// A six-significant-digit `AF`, the precision VCF writers print, sits up to `5e-7`
    /// from `AC / AN`, which is more than one allele once `AN` passes about 2 M. The
    /// tolerance scales with `AN`, so a large cohort's faithfully printed `AF` passes while
    /// a value beyond it still fails.
    #[test]
    fn a_six_digit_af_passes_at_any_cohort_size_and_a_wrong_denominator_still_fails() {
        // 0.308642 is what a writer prints for AC/AN pairs whose exact quotient is
        // 0.30864175…: the printed value lands 2 alleles off at 4 M and 5 off at 10 M.
        for (ac, an) in [
            (308_643, 1_000_000),
            (1_234_570, 4_000_000),
            (3_086_425, 10_000_000),
        ] {
            validate_one_row(row(100, "T", "C", "SNP", "Total", 0.308_642, ac, an))
                .unwrap_or_else(|e| panic!("a six-digit AF must be accepted at AN {an}: {e}"));
        }
        // Beyond the tolerance (3 alleles at 4 M) the row is still rejected, and the error
        // names the tolerance it applied.
        let err = validate_one_row(row(
            100, "T", "C", "SNP", "Total", 0.308_642, 1_234_572, 4_000_000,
        ))
        .expect_err("4 alleles off at AN 4 M exceeds the 3-allele tolerance");
        assert!(err.to_string().contains("within 3 allele(s)"), "{err}");
        // A different-denominator AF is ~1.9 M alleles off: rejected at any cohort size.
        validate_one_row(row(
            100, "T", "C", "SNP", "Total", 0.5, 3_086_425, 10_000_000,
        ))
        .expect_err("a wrong-denominator AF must still be rejected");
    }

    /// The tolerance must cover the worst case a six-significant-digit `AF` stored as `f32`
    /// can produce at every `AN`: `round` of an error of at most `AN × 5.3e-7`. Checked
    /// exhaustively up to 20 M alleles, in integer arithmetic so the bound carries no float
    /// rounding of its own.
    #[test]
    fn af_tolerance_covers_a_six_digit_af_at_every_an() {
        for an in 1..=20_000_000_i64 {
            // floor(5.3e-7 × an + 0.5) = (53·an + 5·10^7) / 10^8 — the largest allele
            // distance a faithfully printed AF can round to.
            let worst = (53 * an + 50_000_000) / 100_000_000;
            let tolerance = i64::from(af_tolerance_alleles(i32::try_from(an).unwrap()));
            assert!(
                tolerance >= worst.max(1),
                "AN {an}: tolerance {tolerance} < worst case {worst}"
            );
        }
        assert_eq!(af_tolerance_alleles(0), 1);
        assert_eq!(af_tolerance_alleles(1_000_000), 1);
        assert_eq!(af_tolerance_alleles(2_000_000), 2);
        assert_eq!(af_tolerance_alleles(4_000_000), 3);
        assert_eq!(af_tolerance_alleles(10_000_000), 6);
    }

    /// The ingest gate re-checks genotype sub-count coherence from `core::subcounts`,
    /// independently of the producer, because a hand-assembled parquet never ran through
    /// `convert`. Drives the wiring through `validate_parquet_dir`, not the predicate alone.
    #[test]
    fn incoherent_genotype_subcounts_are_rejected_at_ingest() {
        // AC = 4 but the reported classes account for 3 alleles: one alternate allele
        // would lie in no genotype class at all.
        let err = validate_one_row_subcounts(4, Some(2), Some(1), Some(0))
            .expect_err("an incoherent sub-count set must be rejected");
        let detail = err.to_string();
        assert!(
            detail.contains("does not equal AC"),
            "expected a partition error, got: {detail}"
        );

        // A sub-count larger than AC alone.
        let err = validate_one_row_subcounts(4, Some(5), None, None)
            .expect_err("a sub-count exceeding AC must be rejected");
        assert!(
            err.to_string().contains("exceeds AC"),
            "expected an exceeds error, got: {err}"
        );

        // The coherent partition of the same AC is accepted, so the test discriminates.
        validate_one_row_subcounts(4, Some(2), Some(1), Some(1))
            .expect("a coherent sub-count set must be accepted");
        // Unreported classes only have to not exceed AC.
        validate_one_row_subcounts(4, Some(2), None, None)
            .expect("unreported sub-counts must be accepted");
    }

    #[test]
    fn malformed_short_data_file_name_groups_without_panic() {
        // A data file with too few dot-parts (`allele-freq.parquet`) must land in its own
        // isolated group rather than being indexed through `parts[2]`.
        // `validate_parquet_dir` returns an `Err` because the file is not valid parquet.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("allele-freq.parquet"),
            b"not a parquet file",
        )
        .unwrap();
        assert!(
            validate_parquet_dir(dir.path(), &ParquetCaps::default()).is_err(),
            "a malformed short data-file name must yield an Err, not a panic"
        );
    }

    #[test]
    fn short_data_file_name_block_range_check_is_graceful() {
        // A data file name with five dot-parts, missing the vcfid segment, must yield a
        // clean `InvalidManifest` from `check_data_file_block_range`.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("allele-freq.chr3.0.br10000000.parquet"),
            b"x",
        )
        .unwrap();
        std::assert_matches!(
            check_data_file_block_range(dir.path(), 10_000_000),
            Err(CoreError::InvalidManifest { .. }),
            "a 5-part data-file name must be a clean InvalidManifest, not a panic"
        );
    }

    #[test]
    fn pos_stat_bounds_observed_accepts_containing_rejects_narrower() {
        // The forge-detection decision: declared stats must contain the observed rows.
        assert!(pos_stat_bounds_observed(0, 1000, 500, 502)); // declared wider -> ok
        assert!(pos_stat_bounds_observed(500, 502, 500, 502)); // exact -> ok
        assert!(!pos_stat_bounds_observed(0, 0, 500, 502)); // forged-narrow max -> reject
        assert!(!pos_stat_bounds_observed(501, 1000, 500, 502)); // forged-narrow min -> reject
    }

    #[test]
    fn verify_pos_statistics_rejects_stats_that_do_not_bound_rows() {
        // A producer that writes real rows but forges narrow POS statistics would let the
        // serve path prune them. `ArrowWriter` computes statistics from the data, so a
        // format-level forge cannot be written directly; instead pair one file's real rows
        // with another, narrower file's declared metadata. That is the
        // "declared does not bound observed" condition `verify_pos_statistics` rejects.
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.parquet");
        let narrow = dir.path().join("narrow.parquet");
        // Real rows at POS 500..=502 (honest stats would be [500, 502]).
        write_parquet(
            &real,
            &[
                row(500, "A", "T", "SNP", "Total", 0.1, 1, 10),
                row(501, "A", "T", "SNP", "Total", 0.1, 1, 10),
                row(502, "A", "T", "SNP", "Total", 0.1, 1, 10),
            ],
        );
        // Same shape (one row group, three rows), but its honest stats are the narrow
        // [0, 0]: the forged claim a real file could carry over the 500..502 rows.
        write_parquet(
            &narrow,
            &[
                row(0, "A", "T", "SNP", "Total", 0.1, 1, 10),
                row(0, "A", "T", "SNP", "Total", 0.1, 1, 10),
                row(0, "A", "T", "SNP", "Total", 0.1, 1, 10),
            ],
        );
        #[expect(
            clippy::disallowed_methods,
            reason = "test fixture: this reads a parquet the test itself just wrote, so the Pages-vs-Values distinction the ban exists for cannot arise; the ban targets production readers of UNTRUSTED parquet"
        )]
        let meta = |p: &Path| {
            ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(p).unwrap())
                .unwrap()
                .metadata()
                .clone()
        };
        // Real rows against the narrow, forged declared stats: rejected.
        let err = verify_pos_statistics(&real, &meta(&narrow)).unwrap_err();
        std::assert_matches!(err, CoreError::InvalidParquet { .. }, "got {err:?}");
        assert!(err.to_string().contains("do not bound"), "{err}");
        // Real rows against their own honest stats: accepted, so there is no false reject.
        verify_pos_statistics(&real, &meta(&real)).unwrap();
    }

    /// The file's metadata with the page (offset and column) index loaded: the page offsets
    /// and page statistics the pre-decode checks read.
    fn metadata_with_page_index(path: &Path) -> Arc<ParquetMetaData> {
        ParquetRecordBatchReaderBuilder::try_new_with_options(
            std::fs::File::open(path).expect("open"),
            ArrowReaderOptions::new().with_page_index_policy(PageIndexPolicy::Required),
        )
        .expect("metadata")
        .metadata()
        .clone()
    }

    /// Rewrite field 2 (`uncompressed_page_size`) of the page header at `page_offset` to
    /// claim `i32::MAX` bytes: the bomb a page can hide from the row-group caps.
    ///
    /// The field is a zigzag varint, so a wider value shifts the bytes after it and corrupts
    /// the page body. That is harmless here because the size check runs before any decode.
    fn patch_page_to_claim_i32_max(path: &Path, page_offset: usize) {
        let mut bytes = std::fs::read(path).expect("read");
        // Header layout at `page_offset`: field 1 (the page type, a field header plus a
        // small zigzag value), then field 2 (uncompressed size).
        let f2_at = page_offset + 2;
        bytes[f2_at] = 0x15; // id delta 1 -> field 2, type 5 (i32)
        let mut varint = Vec::new();
        let mut v: u64 = u64::from(i32::MAX.unsigned_abs()) << 1; // zigzag(i32::MAX)
        loop {
            let b = u8::try_from(v & 0x7f).expect("7 bits");
            v >>= 7;
            if v == 0 {
                varint.push(b);
                break;
            }
            varint.push(b | 0x80);
        }
        bytes.splice(f2_at + 1..f2_at + 1 + varint.len(), varint.iter().copied());
        std::fs::write(path, &bytes).expect("write");
    }

    /// A real file whose first page header is patched to claim an enormous expansion: the
    /// decompression bomb the row-group caps cannot see.
    ///
    /// The caps read `total_byte_size`, which the producer writes and this leaves untouched,
    /// while the decoder allocates from the page header's `uncompressed_page_size`. Patching
    /// only the latter builds a file that passes every cap and then asks
    /// `Vec::with_capacity` for about 2 GiB.
    #[test]
    fn a_page_claiming_more_than_its_row_group_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bomb.parquet");
        write_parquet(&path, &[row(100, "T", "C", "SNP", "Total", 0.1, 1, 10)]);

        // Sanity: the honest file passes.
        assert!(
            RowCursor::open(&path, &ParquetCaps::default(), ROW_CURSOR_BATCH_ROWS).is_ok(),
            "an honest file validates"
        );

        // The first data page's offset comes from the `OffsetIndex`.
        let offset = metadata_with_page_index(&path)
            .offset_index()
            .expect("page index")
            .first()
            .and_then(|cols| cols.first())
            .and_then(|c| c.page_locations().first())
            .map(|p| usize::try_from(p.offset).expect("offset fits"))
            .expect("at least one page");
        patch_page_to_claim_i32_max(&path, offset);

        let msg = match RowCursor::open(&path, &ParquetCaps::default(), ROW_CURSOR_BATCH_ROWS) {
            Ok(_) => panic!("a page claiming more than its row group must be rejected"),
            Err(e) => e.to_string(),
        };
        assert!(
            msg.contains("uncompressed") || msg.contains("bounded"),
            "the rejection must name the page-size problem: {msg}"
        );
    }

    /// `parquet_pages::chunk_start` must equal the library's own `byte_range().0` under
    /// both encodings, with and without a declared dictionary page. That equivalence is what
    /// makes probing the chunk start cover every page origin.
    ///
    /// It is computed rather than delegated because `byte_range()` asserts on a negative
    /// offset, panicking on provider-supplied metadata. This test is what stops the two
    /// definitions drifting apart.
    #[test]
    fn chunk_start_matches_byte_range_under_both_encodings() {
        for (label, props) in [
            ("dictionary-encoded", None),
            (
                "dictionary-disabled",
                Some(
                    parquet::file::properties::WriterProperties::builder()
                        .set_dictionary_enabled(false)
                        .build(),
                ),
            ),
        ] {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("chunk-start.parquet");
            write_parquet_with_props(
                &path,
                &[row(100, "T", "C", "SNP", "Total", 0.1, 1, 10)],
                props,
            );
            let meta = metadata_with_page_index(&path);
            let rg = meta.row_group(0);
            for col in rg.columns() {
                let want = i64::try_from(col.byte_range().0).expect("start fits i64");
                assert_eq!(
                    crate::parquet_pages::chunk_start(col),
                    want,
                    "{label}: chunk_start must mirror byte_range().0"
                );
            }
        }
    }

    /// The dictionary-page sibling of the test above.
    ///
    /// The dictionary page is not listed in the `OffsetIndex`, so the data-page walk never
    /// sees it and its `uncompressed_page_size` must be probed from the column chunk's
    /// `dictionary_page_offset`. Dictionary encoding is on by default, so a bomb here is the
    /// common case. Patch field 2 of the dictionary page header to `i32::MAX` and require a
    /// rejection: an edit that drops the dictionary probe fails here.
    #[test]
    fn a_dictionary_page_claiming_more_than_its_row_group_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("dict-bomb.parquet");
        write_parquet(&path, &[row(100, "T", "C", "SNP", "Total", 0.1, 1, 10)]);

        assert!(
            RowCursor::open(&path, &ParquetCaps::default(), ROW_CURSOR_BATCH_ROWS).is_ok(),
            "an honest file validates"
        );

        // The dictionary page's offset lives in the column chunk, not the `OffsetIndex`.
        // Its header has the same shape as a data page's, so it is patched the same way.
        let dict_offset = metadata_with_page_index(&path)
            .row_group(0)
            .columns()
            .iter()
            .find_map(parquet::file::metadata::ColumnChunkMetaData::dictionary_page_offset)
            .map(|o| usize::try_from(o).expect("offset fits"))
            .expect("a dictionary page must exist (dictionary encoding is on by default)");
        patch_page_to_claim_i32_max(&path, dict_offset);

        let msg = match RowCursor::open(&path, &ParquetCaps::default(), ROW_CURSOR_BATCH_ROWS) {
            Ok(_) => panic!("a dictionary page claiming more than its row group must be rejected"),
            Err(e) => e.to_string(),
        };
        assert!(
            msg.contains("dictionary") || msg.contains("uncompressed") || msg.contains("bounded"),
            "the rejection must name the page-size problem: {msg}"
        );
    }

    /// As [`write_parquet`], but with one row per page so page-granularity behaviour is
    /// observable. A single-page file cannot distinguish page checks from row-group ones.
    fn write_parquet_paged(path: &Path, rows: &[TestRow]) {
        use parquet::file::properties::WriterProperties;
        let props = WriterProperties::builder()
            .set_data_page_row_count_limit(1)
            .set_write_batch_size(1)
            .build();
        write_parquet_with_props(path, rows, Some(props));
    }

    /// A page whose declared bounds do not contain its own rows must be rejected even when
    /// the row group's bounds are honest.
    ///
    /// The serve path prunes at page granularity from the column index
    /// (`parquet_io::pos_row_selection`). A file can carry an honest row-group range, which
    /// passes the group-level check, while a page declares bounds excluding rows it holds;
    /// the serve path would then skip that page and never serve those variants.
    ///
    /// Built with the suite's forging technique, since `ArrowWriter` always computes honest
    /// stats: real rows are paired with another file's metadata, one row per page and a wide
    /// row-group span, so only the page check can fire.
    #[test]
    fn verify_pos_statistics_rejects_page_stats_that_do_not_bound_their_page() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.parquet");
        let decoy = dir.path().join("decoy.parquet");

        // Real rows sit at 500 and 501, one per page.
        write_parquet_paged(
            &real,
            &[
                row(500, "A", "T", "SNP", "Total", 0.1, 1, 10),
                row(501, "A", "T", "SNP", "Total", 0.1, 1, 10),
            ],
        );
        // The decoy spans [0, 1000] at row-group level, which bounds 500 and 501 honestly
        // so the group check passes, while its pages declare [0, 0] and [1000, 1000].
        write_parquet_paged(
            &decoy,
            &[
                row(0, "A", "T", "SNP", "Total", 0.1, 1, 10),
                row(1000, "A", "T", "SNP", "Total", 0.1, 1, 10),
            ],
        );

        let decoy_meta = metadata_with_page_index(&decoy);

        let err = verify_pos_statistics(&real, &decoy_meta)
            .expect_err("page bounds that exclude their own rows must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("page"),
            "the rejection must name the PAGE-level fault, not the row group: {msg}"
        );
    }

    /// Write one allele-freq parquet whose rows carry AF but null AC, AN and genotype
    /// sub-counts: the "AF-only" dataset shape.
    fn write_parquet_af_only(path: &Path, rows: &[(i32, f32)]) {
        let schema = allele_freq_schema();
        let n = rows.len();
        let s = |v: &str| StringArray::from(vec![v; n]);
        let null_i32 = Int32Array::from(vec![None::<i32>; n]);
        let batch = RecordBatch::try_new(
            Arc::clone(&schema),
            vec![
                Arc::new(Int32Array::from(
                    rows.iter().map(|r| r.0).collect::<Vec<_>>(),
                )),
                Arc::new(s("A")),
                Arc::new(s("T")),
                Arc::new(s("SNP")),
                Arc::new(s("Total")),
                Arc::new(Float32Array::from(
                    rows.iter().map(|r| r.1).collect::<Vec<_>>(),
                )),
                Arc::new(null_i32.clone()), // AC
                Arc::new(null_i32.clone()), // AC_HOM
                Arc::new(null_i32.clone()), // AC_HET
                Arc::new(null_i32.clone()), // AC_HEMI
                Arc::new(null_i32),         // AN
            ],
        )
        .unwrap();
        let file = std::fs::File::create(path).unwrap();
        let mut writer = ArrowWriter::try_new(file, schema, None).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
    }

    #[test]
    fn dir_af_only_detects_missing_and_present_counts() {
        let caps = ParquetCaps::default();
        // A dataset whose rows carry AC/AN is not AF-only.
        let with_counts = tempfile::tempdir().unwrap();
        write_parquet(
            &with_counts
                .path()
                .join("allele-freq.chr1.0.br10000000.abc.parquet"),
            &[row(100, "A", "T", "SNP", "Total", 0.1, 1, 10)],
        );
        assert!(
            !dir_af_only(
                with_counts.path(),
                &caps,
                &crate::parquet_io::DatasetDecryptor::plaintext()
            )
            .unwrap()
        );

        // A dataset whose rows have null AC and null AN, carrying only AF, is AF-only.
        let af_only = tempfile::tempdir().unwrap();
        write_parquet_af_only(
            &af_only
                .path()
                .join("allele-freq.chr1.0.br10000000.abc.parquet"),
            &[(100, 0.1), (200, 0.2)],
        );
        assert!(
            dir_af_only(
                af_only.path(),
                &caps,
                &crate::parquet_io::DatasetDecryptor::plaintext()
            )
            .unwrap()
        );
    }

    #[test]
    fn out_of_domain_af_is_rejected() {
        // The untrusted-ingest parquet gate must reject an AF outside the closed interval
        // [0, 1] and a non-finite AF, so a crafted parquet cannot serve a domain-violating
        // allele frequency verbatim. `NaN > 1.0` and `-0.5 > 1.0` are both false, so a
        // `> 1.0` comparison alone would let them through.
        for (label, af) in [
            ("NaN", f32::NAN),
            ("negative", -0.5),
            ("+inf", f32::INFINITY),
            (">1", 1.5),
        ] {
            let err = validate_one_row(row(100, "T", "C", "SNP", "Total", af, 1, 10)).unwrap_err();
            assert_eq!(
                err.class(),
                ErrorClass::InvalidParquetSchema,
                "AF {label} must be rejected"
            );
        }
        // A valid in-domain AF still passes.
        validate_one_row(row(100, "T", "C", "SNP", "Total", 0.085, 1, 10))
            .expect("an in-[0,1] finite AF validates");
    }

    #[test]
    fn negative_allele_counts_are_rejected() {
        // AC and AN are served statistics (alleleCount, alleleNumber), so a negative value
        // is out of domain and must be rejected on the untrusted path.
        let err = validate_one_row(row(100, "T", "C", "SNP", "Total", 0.1, -1, 10)).unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidParquetSchema, "negative AC");
        let err = validate_one_row(row(100, "T", "C", "SNP", "Total", 0.1, 1, -10)).unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidParquetSchema, "negative AN");
        // A negative count in one of the hom/het/hemi columns is likewise rejected.
        let err = validate_one_row(TestRow {
            ac_hom: -3,
            ..row(100, "T", "C", "SNP", "Total", 0.1, 1, 10)
        })
        .unwrap_err();
        assert_eq!(
            err.class(),
            ErrorClass::InvalidParquetSchema,
            "negative AC_HOM"
        );
    }

    #[test]
    fn per_pos_working_set_is_bounded() {
        // Three distinct (REF, ALT, population) rows at one POS: no duplicate, so only the
        // per-POS size bound can reject them. With a cap of 2 it must, and under the default
        // cap the same file validates.
        let dir = tempfile::tempdir().unwrap();
        let file = dir
            .path()
            .join("allele-freq.chr3.0.br10000000.0123456789abcdef.parquet");
        write_parquet(
            &file,
            &[
                row(100, "T", "C", "SNP", "P1", 0.1, 1, 10),
                row(100, "T", "C", "SNP", "P2", 0.1, 1, 10),
                row(100, "T", "C", "SNP", "P3", 0.1, 1, 10),
            ],
        );
        let capped = ParquetCaps {
            max_distinct_keys_per_pos: 2,
            ..ParquetCaps::default()
        };
        let err = validate_parquet_dir(dir.path(), &capped).unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidParquetSchema);
        assert!(
            format!("{err}").contains("max_distinct_keys_per_pos"),
            "expected the per-POS bound, got: {err}"
        );
        validate_parquet_dir(dir.path(), &ParquetCaps::default())
            .expect("the same file validates under the default cap");
    }

    #[test]
    fn per_pos_working_set_is_byte_bounded() {
        // `max_distinct_keys_per_pos` bounds the per-POS working set by key count, but each
        // key owns REF+ALT+POPULATION bytes, so a crafted parquet with few but huge keys at
        // one POS could pile tens of gigabytes onto one locus before the count cap trips.
        // `max_pos_key_bytes` bounds the cumulative byte size independently. Three distinct
        // short rows at one POS (12 key-bytes) must be rejected under an 8-byte cap, and the
        // same file validates under the default byte cap.
        let dir = tempfile::tempdir().unwrap();
        let file = dir
            .path()
            .join("allele-freq.chr3.0.br10000000.0123456789abcdef.parquet");
        write_parquet(
            &file,
            &[
                row(100, "T", "C", "SNP", "P1", 0.1, 1, 10),
                row(100, "T", "C", "SNP", "P2", 0.1, 1, 10),
                row(100, "T", "C", "SNP", "P3", 0.1, 1, 10),
            ],
        );
        let capped = ParquetCaps {
            max_pos_key_bytes: 8,
            ..ParquetCaps::default()
        };
        let err = validate_parquet_dir(dir.path(), &capped).unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidParquetSchema);
        assert!(
            format!("{err}").contains("max_pos_key_bytes"),
            "expected the per-POS byte bound, got: {err}"
        );
        validate_parquet_dir(dir.path(), &ParquetCaps::default())
            .expect("the same file validates under the default byte cap");
    }

    #[test]
    fn good_dataset_passes_and_duplicates_rejected() {
        // The `convert_vcf` output of the COVID fixture passes validation.
        let dir = tempfile::tempdir().unwrap();
        let vcf = test_util::covid_vcf_path();
        convert_vcf(
            &vcf,
            dir.path(),
            &ConvertOptions {
                assembly: "GRCh38".into(),
                block_range: 10_000_000,
                min_allele_count: 0,
            },
        )
        .unwrap();
        validate_parquet_dir(dir.path(), &ParquetCaps::default()).expect("good dataset validates");

        // A directory whose parquet repeats (POS, REF, ALT, POPULATION) fails with an
        // `InvalidParquetSchema` class and a "duplicate" detail.
        let bad = tempfile::tempdir().unwrap();
        // The filename must match the data-file pattern so the (chr, block) grouping
        // applies and the value checks run.
        let bad_file = bad
            .path()
            .join("allele-freq.chr3.0.br10000000.0123456789abcdef.parquet");
        write_parquet(
            &bad_file,
            &[
                row(100, "T", "C", "SNP", "Total", 0.1, 1, 10),
                // identical POS/REF/ALT/POPULATION -> duplicate
                row(100, "T", "C", "SNP", "Total", 0.1, 1, 10),
            ],
        );
        let err = validate_parquet_dir(bad.path(), &ParquetCaps::default()).unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidParquetSchema);
        assert!(
            format!("{err}").contains("duplicate"),
            "expected duplicate detail, got {err}"
        );
    }

    #[test]
    fn duplicate_across_two_files_in_group_rejected() {
        let dir = tempfile::tempdir().unwrap();
        // Two files in the same (chr, block) group, differing only by vcfid, that share a
        // (POS, REF, ALT, population) tuple.
        write_parquet(
            &dir.path()
                .join("allele-freq.chr3.0.br10000000.aaaaaaaaaaaaaaaa.parquet"),
            &[row(100, "T", "C", "SNP", "FI_M", 0.1, 1, 10)],
        );
        write_parquet(
            &dir.path()
                .join("allele-freq.chr3.0.br10000000.bbbbbbbbbbbbbbbb.parquet"),
            &[row(100, "T", "C", "SNP", "FI_M", 0.2, 2, 10)],
        );
        let err = validate_parquet_dir(dir.path(), &ParquetCaps::default()).unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidParquetSchema);
        assert!(format!("{err}").contains("duplicate"));
    }

    #[test]
    fn distinct_population_across_files_passes() {
        // Per-population split: same variant, different populations -> OK.
        let dir = tempfile::tempdir().unwrap();
        write_parquet(
            &dir.path()
                .join("allele-freq.chr3.0.br10000000.aaaaaaaaaaaaaaaa.parquet"),
            &[row(100, "T", "C", "SNP", "FI_M", 0.1, 1, 10)],
        );
        write_parquet(
            &dir.path()
                .join("allele-freq.chr3.0.br10000000.bbbbbbbbbbbbbbbb.parquet"),
            &[row(100, "T", "C", "SNP", "EE_M", 0.2, 2, 10)],
        );
        validate_parquet_dir(dir.path(), &ParquetCaps::default()).unwrap();
    }

    /// A hand-assembled parquet with an incoherent population hierarchy must be rejected at
    /// ingest, not only at build.
    ///
    /// `convert` enforces this producer-side, but a parquet crafted directly never passed
    /// through it. Here `AN_EE_M + AN_EE_F == AN_EE` exactly, so the two sexes partition EE,
    /// yet they report more carriers than EE holds.
    #[test]
    fn validate_parquet_dir_rejects_an_incoherent_population_hierarchy() {
        let dir = tempfile::tempdir().unwrap();
        write_parquet(
            &dir.path()
                .join("allele-freq.chr3.0.br10000000.aaaaaaaaaaaaaaaa.parquet"),
            &[
                // Rows are written in the (POS, REF, ALT, POPULATION) order the writer
                // guarantees, so the accumulator sees one contiguous group.
                row(100, "T", "C", "SNP", "EE", 0.0025, 10, 4000),
                row(100, "T", "C", "SNP", "EE_F", 0.005, 10, 2000),
                row(100, "T", "C", "SNP", "EE_M", 0.25, 500, 2000),
            ],
        );
        let err = validate_parquet_dir(dir.path(), &ParquetCaps::default())
            .expect_err("an impossible breakdown must not validate");
        let msg = format!("{err}");
        assert!(
            msg.contains("EE_M") && msg.contains("EE"),
            "the error must name the offending child and its parent: {msg}"
        );
    }

    /// The coherent shape must still validate — otherwise the check would reject real
    /// data rather than the pipeline bugs it targets.
    #[test]
    fn validate_parquet_dir_accepts_a_coherent_population_hierarchy() {
        let dir = tempfile::tempdir().unwrap();
        write_parquet(
            &dir.path()
                .join("allele-freq.chr3.0.br10000000.aaaaaaaaaaaaaaaa.parquet"),
            &[
                row(100, "T", "C", "SNP", "EE", 0.0025, 10, 4000),
                row(100, "T", "C", "SNP", "EE_F", 0.0015, 3, 2000),
                row(100, "T", "C", "SNP", "EE_M", 0.0035, 7, 2000),
            ],
        );
        validate_parquet_dir(dir.path(), &ParquetCaps::default())
            .expect("a coherent breakdown must validate");
    }

    #[test]
    fn validate_parquet_dir_counts_distinct_variants_collapsing_populations() {
        // The returned count is distinct (POS, REF, ALT) variants: a variant reported for
        // several populations counts once. This is the value verified against the manifest's
        // `numberOfRecords` at ingest.
        let dir = tempfile::tempdir().unwrap();
        write_parquet(
            &dir.path()
                .join("allele-freq.chr3.0.br10000000.aaaaaaaaaaaaaaaa.parquet"),
            &[
                // variant 1 (POS 100, T>C) reported for two populations: one record
                row(100, "T", "C", "SNP", "EE_M", 0.1, 1, 10),
                row(100, "T", "C", "SNP", "FI_M", 0.2, 2, 10),
                // variant 2: same POS, different ALT -> a distinct record
                row(100, "T", "G", "SNP", "FI_M", 0.1, 1, 10),
                // variant 3: a later POS
                row(200, "A", "G", "SNP", "FI_M", 0.3, 3, 10),
            ],
        );
        let scan = validate_parquet_dir(dir.path(), &ParquetCaps::default())
            .expect("valid dataset validates");
        assert_eq!(
            scan.distinct_variants, 3,
            "3 distinct (POS,REF,ALT) variants across 4 rows (two populations share one)"
        );
        // The same pass observes the label set the node will advertise.
        assert_eq!(
            scan.populations
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["EE_M", "FI_M"]
        );
    }

    #[test]
    fn ingest_rejects_more_than_max_populations() {
        use crate::convert::MAX_POPULATIONS;
        // A hand-crafted parquet can declare far more populations than the trusted convert
        // path; the ingest scan must reject `> MAX_POPULATIONS`, not advertise them all.
        let write = |n: usize, dir: &Path| {
            let rows: Vec<TestRow> = (0..n)
                .map(|i| row(100, "T", "C", "SNP", &format!("P{i:04}"), 0.1, 1, 10))
                .collect();
            write_parquet(
                &dir.join("allele-freq.chr3.0.br10000000.aaaaaaaaaaaaaaaa.parquet"),
                &rows,
            );
        };
        // Exactly MAX_POPULATIONS is allowed.
        let ok = tempfile::tempdir().unwrap();
        write(MAX_POPULATIONS, ok.path());
        validate_parquet_dir(ok.path(), &ParquetCaps::default())
            .expect("exactly MAX_POPULATIONS populations validates");
        // One over the cap is rejected.
        let bad = tempfile::tempdir().unwrap();
        write(MAX_POPULATIONS + 1, bad.path());
        let err = validate_parquet_dir(bad.path(), &ParquetCaps::default()).unwrap_err();
        assert!(
            err.to_string().contains("MAX_POPULATIONS"),
            "must reject exceeding the population cap: {err}"
        );

        // ...and the cap is dataset-wide, not per (chr, block) group.
        //
        // The single-file fixture above cannot reach this case. A per-group check alone lets
        // two groups, each just under the cap, sum to about twice it, while
        // `MAX_POPULATIONS` and `docs/gdi-dataset-tool.md` both say "per dataset". Splitting
        // by chromosome keeps each file a separate group without needing distinct POS
        // blocks.
        let split = tempfile::tempdir().unwrap();
        let half = MAX_POPULATIONS / 2 + 1; // 2 × half > MAX_POPULATIONS
        for (chr, offset) in [("chr3", 0), ("chr4", half)] {
            let rows: Vec<TestRow> = (0..half)
                .map(|i| {
                    row(
                        100,
                        "T",
                        "C",
                        "SNP",
                        &format!("P{:04}", i + offset),
                        0.1,
                        1,
                        10,
                    )
                })
                .collect();
            write_parquet(
                &split.path().join(format!(
                    "allele-freq.{chr}.0.br10000000.aaaaaaaaaaaaaaaa.parquet"
                )),
                &rows,
            );
        }
        let err = validate_parquet_dir(split.path(), &ParquetCaps::default()).expect_err(
            "populations spread across several (chr, block) groups must still hit the \
             DATASET-wide cap",
        );
        assert!(
            err.to_string().contains("MAX_POPULATIONS"),
            "must reject a cross-group population set over the cap: {err}"
        );
    }

    /// The cap is documented and enforced producer-side as a per-dataset limit, so the
    /// ingest gate must apply it to the union of the per-group sets, not per
    /// `(chr, block)` group.
    ///
    /// Otherwise a package with G groups carries `G × MAX_POPULATIONS` distinct labels, and
    /// with `blockRange = 1` each file is its own group. The node would advertise every one
    /// on `/datasets` and in the FDP records, and the dataset-level `BTreeSet<String>` would
    /// be unbounded input-driven allocation on the ingest worker.
    #[test]
    fn ingest_rejects_more_than_max_populations_across_groups() {
        use crate::convert::MAX_POPULATIONS;
        let dir = tempfile::tempdir().unwrap();
        // Two different `(chr, block)` groups, each within the per-group cap on its own.
        for (chr, offset) in [("chr3", 0), ("chr4", MAX_POPULATIONS)] {
            let rows: Vec<TestRow> = (0..MAX_POPULATIONS)
                .map(|i| {
                    row(
                        100,
                        "T",
                        "C",
                        "SNP",
                        &format!("P{:05}", i + offset),
                        0.1,
                        1,
                        10,
                    )
                })
                .collect();
            write_parquet(
                &dir.path().join(format!(
                    "allele-freq.{chr}.0.br10000000.aaaaaaaaaaaaaaaa.parquet"
                )),
                &rows,
            );
        }

        let err = validate_parquet_dir(dir.path(), &ParquetCaps::default())
            .expect_err("the dataset-wide union exceeds the cap and must be rejected");
        assert!(
            err.to_string().contains("MAX_POPULATIONS"),
            "must reject on the dataset-wide population union: {err}"
        );
    }

    #[test]
    fn row_outside_named_block_is_rejected() {
        // A file named for (chr3, block 4, blockRange 10_000_000) whose row falls in block
        // 3 (0-based 30_000_000 / 10_000_000) is unqueryable on the serve path, which
        // resolves files by their named `(block, block_range)` prefix, so the ingest and
        // self-check gates must reject it.
        let dir = tempfile::tempdir().unwrap();
        let file = dir
            .path()
            .join("allele-freq.chr3.4.br10000000.0123456789abcdef.parquet");
        write_parquet(
            &file,
            &[row(30_000_000, "T", "C", "SNP", "Total", 0.1, 1, 10)],
        );
        let err = validate_parquet_dir(dir.path(), &ParquetCaps::default()).unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidParquetSchema);
        assert!(
            format!("{err}").contains("maps to block"),
            "expected the block-membership detail, got {err}"
        );
    }

    #[test]
    fn row_inside_named_block_passes() {
        // The complement of the above: POS 45_000_000 / 10_000_000 = 4 matches the named
        // block 4, so the otherwise valid file validates. Guards against the block check
        // rejecting correctly-placed rows.
        let dir = tempfile::tempdir().unwrap();
        let file = dir
            .path()
            .join("allele-freq.chr3.4.br10000000.0123456789abcdef.parquet");
        write_parquet(
            &file,
            &[row(45_000_000, "T", "C", "SNP", "Total", 0.1, 1, 10)],
        );
        validate_parquet_dir(dir.path(), &ParquetCaps::default())
            .expect("a row inside its named block validates");
    }

    #[test]
    fn data_file_blockrange_mismatch_is_rejected() {
        // A data file whose filename blockRange disagrees with the manifest's configured
        // blockRange is rejected: it would be unreachable on the serve path, which globs by
        // the configured blockRange. The node ingest gate and the tool's `build`/`validate`
        // both run this check.
        let dir = tempfile::tempdir().unwrap();
        write_parquet(
            &dir.path()
                .join("allele-freq.chr3.0.br5000000.0123456789abcdef.parquet"),
            &[row(100, "T", "C", "SNP", "Total", 0.1, 1, 10)],
        );
        let err = check_data_file_block_range(dir.path(), 10_000_000).unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidManifest);
        assert!(
            format!("{err}").contains("config.blockRange"),
            "expected the blockRange mismatch detail, got {err}"
        );
        // The matching blockRange passes.
        check_data_file_block_range(dir.path(), 5_000_000)
            .expect("a file whose br matches the configured blockRange validates");
    }

    #[test]
    fn malformed_data_file_name_rejected_by_blockrange_check() {
        // A name whose block or range cannot be read, here a non-numeric block, is
        // unreachable on the serve path, and the per-row block check can only skip it. The
        // blockRange gate rejects it instead, through the same `parse_block_and_range`.
        let dir = tempfile::tempdir().unwrap();
        write_parquet(
            &dir.path()
                .join("allele-freq.chr3.X.br10000000.0123456789abcdef.parquet"),
            &[row(100, "T", "C", "SNP", "Total", 0.1, 1, 10)],
        );
        let err = check_data_file_block_range(dir.path(), 10_000_000).unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidManifest);
        assert!(
            format!("{err}").contains("well-formed"),
            "expected the malformed-name detail, got {err}"
        );
    }

    #[test]
    fn schema_mismatch_rejected() {
        // A parquet with a wholly different schema is rejected on the schema check.
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("allele-freq.chr3.0.br10000000.cccccccccccccccc.parquet");
        let schema = Arc::new(arrow_schema::Schema::new(vec![arrow_schema::Field::new(
            "POS",
            arrow_schema::DataType::Int64,
            false,
        )]));
        let batch = RecordBatch::try_new(
            Arc::clone(&schema),
            vec![Arc::new(arrow_array::Int64Array::from(vec![1_i64]))],
        )
        .unwrap();
        let file = std::fs::File::create(&path).unwrap();
        let mut writer = ArrowWriter::try_new(file, schema, None).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();

        let err = validate_parquet_dir(dir.path(), &ParquetCaps::default()).unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidParquetSchema);
    }

    #[test]
    fn over_cap_ref_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("allele-freq.chr3.0.br10000000.dddddddddddddddd.parquet");
        let long_ref = "A".repeat(20);
        write_parquet(
            &path,
            &[row(100, &long_ref, "C", "DELINS", "Total", 0.1, 1, 10)],
        );
        let caps = ParquetCaps {
            max_ref_len: 10,
            ..ParquetCaps::default()
        };
        let err = validate_parquet_dir(dir.path(), &caps).unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidParquetSchema);
        assert!(format!("{err}").contains("REF length"));
    }

    #[test]
    fn over_cap_alt_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("allele-freq.chr3.0.br10000000.ffffffffffffffff.parquet");
        let long_alt = "A".repeat(20);
        write_parquet(
            &path,
            &[row(100, "T", &long_alt, "INS", "Total", 0.1, 1, 10)],
        );
        let caps = ParquetCaps {
            max_alt_len: 10,
            ..ParquetCaps::default()
        };
        let err = validate_parquet_dir(dir.path(), &caps).unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidParquetSchema);
        assert!(format!("{err}").contains("ALT length"));
    }

    #[test]
    fn over_cap_population_rejected() {
        // POPULATION is served verbatim in every response; a hand-assembled parquet
        // that bypasses `convert` must not smuggle an oversized label past ingest.
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("allele-freq.chr3.0.br10000000.aaaaaaaaaaaaaaaa.parquet");
        let long_pop = "P".repeat(20);
        write_parquet(&path, &[row(100, "T", "C", "SNP", &long_pop, 0.1, 1, 10)]);
        let caps = ParquetCaps {
            max_population_len: 16,
            ..ParquetCaps::default()
        };
        let err = validate_parquet_dir(dir.path(), &caps).unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidParquetSchema);
        assert!(
            format!("{err}").contains("POPULATION length"),
            "expected the POPULATION length detail, got {err}"
        );
    }

    #[test]
    fn population_len_cap_matches_producer() {
        // Producer (`convert`) and consumer (ingest) must apply the same population-label
        // bound, or the tool would emit labels the node rejects, or the reverse.
        assert_eq!(
            ParquetCaps::default().max_population_len,
            crate::convert::MAX_POPULATION_LABEL_LEN,
            "the ingest POPULATION cap must equal the producer's label cap"
        );
    }

    #[test]
    fn over_cap_files_per_group_rejected() {
        // A (chr, block) group with more files than `max_files_per_group` is rejected
        // before the uniqueness merge opens one descriptor per file.
        let dir = tempfile::tempdir().unwrap();
        for (i, hex) in ["1111111111111111", "2222222222222222", "3333333333333333"]
            .iter()
            .enumerate()
        {
            let path = dir
                .path()
                .join(format!("allele-freq.chr1.0.br10000000.{hex}.parquet"));
            // Distinct POS within block 0 (POS < 10_000_000), so without the cap these
            // files would validate cleanly and the cap must be what fires.
            let pos = 100 + i32::try_from(i).unwrap();
            write_parquet(&path, &[row(pos, "T", "C", "SNP", "Total", 0.5, 1, 10)]);
        }
        let caps = ParquetCaps {
            max_files_per_group: 2,
            ..ParquetCaps::default()
        };
        let err = validate_parquet_dir(dir.path(), &caps).unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidParquetSchema);
        assert!(
            format!("{err}").contains("max_files_per_group"),
            "expected the fan-out cap detail, got {err}"
        );
    }

    #[test]
    fn over_cap_file_size_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("allele-freq.chr3.0.br10000000.eeeeeeeeeeeeeeee.parquet");
        write_parquet(&path, &[row(100, "T", "C", "SNP", "Total", 0.1, 1, 10)]);
        let caps = ParquetCaps {
            max_parquet_file_bytes: 1,
            ..ParquetCaps::default()
        };
        let err = validate_parquet_dir(dir.path(), &caps).unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidParquetSchema);
        assert!(format!("{err}").contains("file size"));
    }

    #[test]
    fn malformed_arrow_schema_metadata_is_error_not_panic() {
        // The fixture is a valid parquet whose embedded `ARROW:schema` flatbuffer holds an
        // `Int` field with bitWidth 0, on which `arrow-ipc`'s `fb_to_schema` panics
        // ("Int type with bit width of 0 ... not supported"). Under a panic=unwind build
        // the boundary must turn that third-party panic into a clean `InvalidParquet` error
        // rather than let it abort the process. The file carries the canonical data-file
        // name so `collect_data_files` picks it up and the full per-file path runs.
        let dir = tempfile::tempdir().unwrap();
        let dest = dir
            .path()
            .join("allele-freq.chr1.0.br10000000.0123456789abcdef.parquet");
        std::fs::copy("tests/fixtures/malformed/arrow_schema_panic.parquet", &dest).unwrap();
        let err = validate_parquet_dir(dir.path(), &ParquetCaps::default())
            .expect_err("malformed parquet metadata must be an error, not a panic");
        assert_eq!(err.class(), ErrorClass::InvalidParquetSchema);
        assert!(
            format!("{err}").contains("panicked"),
            "expected the panic-boundary detail, got {err}"
        );
    }

    #[test]
    #[serial_test::serial(panic_hook)]
    fn handled_decode_flag_is_set_when_a_process_panic_hook_would_see_it() {
        // `HandledDecodeGuard` exists so a `std::panic::set_hook` callback, which fires
        // before `catch_unwind` below sees the unwind, can consult
        // `panic_guard::handled_decode_in_progress()` and tell "about to be handled" apart
        // from "a real bug" instead of printing the raw panic. This installs a real hook
        // that records whether the flag was set when it fired, drives a panic through
        // `catch_parquet_panic`, then asserts both halves: the hook saw the flag set, and
        // the public result is still the `parquet decode panicked ... (malformed file)`
        // error.
        use std::sync::Mutex;
        use std::sync::OnceLock;

        static HOOK_OBSERVATIONS: OnceLock<Mutex<Vec<bool>>> = OnceLock::new();
        let observations = HOOK_OBSERVATIONS.get_or_init(|| Mutex::new(Vec::new()));
        observations.lock().unwrap().clear();

        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_info| {
            let observations = HOOK_OBSERVATIONS.get_or_init(|| Mutex::new(Vec::new()));
            observations
                .lock()
                .unwrap()
                .push(crate::panic_guard::handled_decode_in_progress());
        }));

        let result = catch_parquet_panic(Path::new("synthetic.parquet"), || -> CoreResult<()> {
            panic!("synthetic decode panic for the handled-decode flag test")
        });

        std::panic::set_hook(previous);

        let seen = observations.lock().unwrap().clone();
        assert_eq!(
            seen,
            vec![true],
            "the panic hook must fire exactly once and see the flag SET \
             (a real hook uses this to suppress its raw-panic output)"
        );
        assert!(
            !crate::panic_guard::handled_decode_in_progress(),
            "the flag must be cleared again once catch_parquet_panic has returned"
        );
        match result {
            Err(err) => {
                assert_eq!(err.class(), ErrorClass::InvalidParquetSchema);
                let msg = format!("{err}");
                assert!(
                    msg.contains("parquet decode panicked on synthetic.parquet (malformed file)"),
                    "expected the existing panic-boundary error text, got {msg}"
                );
            }
            Ok(()) => panic!("expected the synthetic panic to surface as Err"),
        }
    }

    #[test]
    fn fuzz_crash_artifacts_are_errors_not_panics() {
        // Replays the cargo-fuzz `parquet_validate` crash reproducers through the real
        // `validate_parquet_dir`: each must become a clean `Err`, never a panic or abort
        // that escapes the `catch_parquet_panic` net. Fuzzer artifacts are gitignored under
        // `fuzz/artifacts/`, so each minimized reproducer is promoted into this tracked
        // fixtures directory.
        //
        // `fuzz_crash_fc0ea292.parquet` is a crafted footer whose embedded Arrow IPC schema
        // has no `fields`: the same `fb_to_schema` panic family as the other two fixtures,
        // and the reason the fuzz target mirrors production's `catch_unwind` boundary (see
        // `crates/core/fuzz/fuzz_targets/parquet_validate.rs`).
        for name in [
            "fuzz_minimized_cb9351a9.parquet",
            "fuzz_crash_82778894.parquet",
            "fuzz_crash_fc0ea292.parquet",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let dest = dir
                .path()
                .join("allele-freq.chr1.0.br10000000.0123456789abcdef.parquet");
            std::fs::copy(format!("tests/fixtures/malformed/{name}"), &dest).unwrap();
            // `expect_err` is the assertion: had validation panicked instead of returning
            // `Err`, the test process would unwind here. The class is not pinned, because
            // the guarantee is no-panic and different reproducers surface different parquet
            // error classes.
            validate_parquet_dir(dir.path(), &ParquetCaps::default())
                .expect_err("a fuzz crash artifact must be an error, not a panic");
        }
    }

    #[test]
    fn over_cap_row_group_decompressed_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("allele-freq.chr3.0.br10000000.ffffffffffffffff.parquet");
        write_parquet(&path, &[row(100, "T", "C", "SNP", "Total", 0.1, 1, 10)]);
        let caps = ParquetCaps {
            max_parquet_row_group_bytes: 1,
            ..ParquetCaps::default()
        };
        let err = validate_parquet_dir(dir.path(), &caps).unwrap_err();
        assert_eq!(err.class(), ErrorClass::InvalidParquetSchema);
        assert!(format!("{err}").contains("row group decompressed size"));
    }

    #[test]
    fn cumulative_decompressed_cap_enforced_and_equal_accepted() {
        // The cumulative decompression-bomb cap is distinct from the per-group cap. Each
        // group here is under `max_parquet_row_group_bytes` (1000), so only the running
        // total can reject: 50 + 60 = 110 exceeds the cumulative cap of 100. The comparison
        // must be `>`, since 110 is not equal to 100.
        let caps = ParquetCaps {
            max_parquet_row_group_bytes: 1000,
            max_parquet_decompressed_bytes: 100,
            ..ParquetCaps::default()
        };
        let mut total = 0u64;
        enforce_row_group_caps(50, &caps, &mut total).expect("first group under both caps");
        let err = enforce_row_group_caps(60, &caps, &mut total)
            .expect_err("running total 110 exceeds the cumulative cap 100");
        assert_eq!(err.class(), ErrorClass::InvalidParquetSchema);
        assert!(
            format!("{err}").contains("max_parquet_decompressed_bytes"),
            "expected the cumulative-cap detail, got: {err}"
        );

        // A running total exactly equal to the cap is accepted.
        let mut total_eq = 0u64;
        enforce_row_group_caps(100, &caps, &mut total_eq)
            .expect("a cumulative total exactly equal to the cap is accepted");
    }

    #[test]
    fn distinct_chr_groups_are_not_cross_group_duplicates() {
        // `chr_block_key` derives a per-(chr, block) group key. A constant key would
        // collapse every data file into one uniqueness group, turning identical variants on
        // different chromosomes into a false duplicate. Two files keyed to chr3 and chr7,
        // both block 0, each holding the same (POS, REF, ALT, population) tuple are distinct
        // groups: validation passes and the distinct-variant count is 2.
        let dir = tempfile::tempdir().unwrap();
        write_parquet(
            &dir.path()
                .join("allele-freq.chr3.0.br10000000.aaaaaaaaaaaaaaaa.parquet"),
            &[row(100, "T", "C", "SNP", "Total", 0.1, 1, 10)],
        );
        write_parquet(
            &dir.path()
                .join("allele-freq.chr7.0.br10000000.bbbbbbbbbbbbbbbb.parquet"),
            &[row(100, "T", "C", "SNP", "Total", 0.1, 1, 10)],
        );
        let scan = validate_parquet_dir(dir.path(), &ParquetCaps::default())
            .expect("identical variants in different chr groups are not duplicates");
        assert_eq!(
            scan.distinct_variants, 2,
            "each distinct (chr,block) group contributes one variant"
        );
    }

    // ── Property test: the cross-file ordering and duplicate gate ────────────────
    // The streaming k-way `RowCursor` merge across a group's files is what prevents
    // double-counted allele frequencies on the public beacon. A group is accepted exactly
    // when every file is POS-non-decreasing and no `(POS, REF, ALT, population)` key repeats
    // across the group. Every other validity dimension is held valid by construction, so
    // only ordering and duplication decide the verdict. Files are written with a tiny
    // row-group cap, so a multi-row file spans more than one row group and exercises the
    // streaming path.

    const PROP_BASES: [&str; 4] = ["A", "C", "G", "T"];
    const PROP_POPS: [&str; 3] = ["Total", "FI", "FI_M"];

    #[derive(Clone, Debug)]
    struct GenRow {
        pos: i32,
        ref_: &'static str,
        alt: &'static str,
        pop: &'static str,
        file_b: bool,
    }

    fn gen_row() -> impl Strategy<Value = GenRow> {
        (0i32..6, 0usize..4, 1usize..4, 0usize..3, any::<bool>()).prop_map(
            |(pos, r, alt_off, p, file_b)| GenRow {
                pos,
                ref_: PROP_BASES[r],
                // `+ alt_off` (1..4) guarantees ALT != REF (a real variant).
                alt: PROP_BASES[(r + alt_off) % 4],
                pop: PROP_POPS[p],
                file_b,
            },
        )
    }

    /// Write `rows` (in order) to one parquet with a 2-row row-group cap, so a file
    /// with >2 rows spans multiple row groups.
    fn write_grouped(path: &Path, rows: &[&GenRow]) {
        let schema = allele_freq_schema();
        let n = rows.len();
        let batch = RecordBatch::try_new(
            Arc::clone(&schema),
            vec![
                Arc::new(Int32Array::from(
                    rows.iter().map(|r| r.pos).collect::<Vec<_>>(),
                )),
                Arc::new(StringArray::from(
                    rows.iter().map(|r| r.ref_).collect::<Vec<_>>(),
                )),
                Arc::new(StringArray::from(
                    rows.iter().map(|r| r.alt).collect::<Vec<_>>(),
                )),
                Arc::new(StringArray::from(vec!["SNP"; n])),
                Arc::new(StringArray::from(
                    rows.iter().map(|r| r.pop).collect::<Vec<_>>(),
                )),
                // AF must equal AC/AN (1/10) so the ingest gate's AF-consistency check
                // accepts the row. This property is about sort order, not the AF value.
                Arc::new(Float32Array::from(vec![0.1f32; n])),
                Arc::new(Int32Array::from(vec![Some(1); n])), // AC
                // The single alternate allele is one heterozygote, so the genotype
                // sub-counts partition AC (see `core::subcounts`). This property is about
                // sort order and cross-file duplicates, but the rows must still be valid.
                Arc::new(Int32Array::from(vec![Some(0); n])), // AC_HOM
                Arc::new(Int32Array::from(vec![Some(1); n])), // AC_HET
                Arc::new(Int32Array::from(vec![Some(0); n])), // AC_HEMI
                Arc::new(Int32Array::from(vec![Some(10); n])), // AN
            ],
        )
        .unwrap();
        let props = WriterProperties::builder()
            .set_max_row_group_row_count(Some(2))
            .build();
        let file = std::fs::File::create(path).unwrap();
        let mut writer = ArrowWriter::try_new(file, schema, Some(props)).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]
        #[test]
        fn accepts_iff_sorted_and_no_cross_file_duplicate(
            rows in prop::collection::vec(gen_row(), 1..10)
        ) {
            let dir = tempfile::tempdir().unwrap();
            let file_a: Vec<&GenRow> = rows.iter().filter(|r| !r.file_b).collect();
            let file_b: Vec<&GenRow> = rows.iter().filter(|r| r.file_b).collect();
            // Two files in the same (chr3, block4) group, with distinct vcfids. An empty
            // file is skipped: an empty parquet is not what this gate is about.
            if !file_a.is_empty() {
                write_grouped(
                    &dir.path().join("allele-freq.chr3.0.br10000000.aaaaaaaaaaaaaaaa.parquet"),
                    &file_a,
                );
            }
            if !file_b.is_empty() {
                write_grouped(
                    &dir.path().join("allele-freq.chr3.0.br10000000.bbbbbbbbbbbbbbbb.parquet"),
                    &file_b,
                );
            }

            let nondecreasing = |f: &[&GenRow]| f.windows(2).all(|w| w[0].pos <= w[1].pos);
            let sorted = nondecreasing(&file_a) && nondecreasing(&file_b);
            let mut seen = std::collections::HashSet::new();
            let no_dup = rows
                .iter()
                .all(|r| seen.insert((r.pos, r.ref_, r.alt, r.pop)));
            let expected_ok = sorted && no_dup;

            let actual_ok = validate_parquet_dir(dir.path(), &ParquetCaps::default()).is_ok();
            prop_assert_eq!(
                actual_ok, expected_ok,
                "sorted={} no_dup={} rows={:?}", sorted, no_dup, rows
            );
        }
    }

    #[test]
    fn the_primed_merge_working_set_is_bounded_by_the_caps_alone() {
        // The binding for the ingest memory peak, computed from `ParquetCaps` with no
        // fixture. Raising any factor, whether files per group, batch rows, or the
        // REF/ALT/POPULATION lengths, fails here rather than in an OOM-killed process.
        //
        // `max_files_per_group` bounds open descriptors; this bounds what those descriptors
        // hold. `min_front_pos` primes every cursor before any is drained, so the peak is
        // the product of the two.
        let caps = ParquetCaps::default();
        for files in [1usize, 8, 64, caps.max_files_per_group] {
            let rows = group_batch_rows(files, &caps);
            assert!(
                rows >= 1,
                "the merge must still make progress at {files} files"
            );
            assert!(
                rows <= ROW_CURSOR_BATCH_ROWS,
                "batch size must never EXCEED the nominal at {files} files"
            );
            let peak = files
                .saturating_mul(rows)
                .saturating_mul(worst_case_row_bytes(&caps));
            assert!(
                peak <= MAX_GROUP_WORKING_SET_BYTES,
                "primed working set for {files} files is {peak} B, over the \
                 {MAX_GROUP_WORKING_SET_BYTES} B ceiling"
            );
        }

        // At the descriptor cap the nominal batch size would exceed the ceiling, so the
        // bound has to bite rather than coincide with it.
        let unbounded = caps
            .max_files_per_group
            .saturating_mul(ROW_CURSOR_BATCH_ROWS)
            .saturating_mul(worst_case_row_bytes(&caps));
        assert!(
            unbounded > MAX_GROUP_WORKING_SET_BYTES,
            "if the nominal batch already fits, this test proves nothing — re-derive it"
        );
    }
}
