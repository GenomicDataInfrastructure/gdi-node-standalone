//! `g_variants` Parquet file selection, scan, and response assembly.
//!
//! Given a classified [`QueryKind`], [`select_files`] computes the
//! block span and globs the dataset directory for the candidate
//! `allele-freq.*.parquet` files, and [`scan_dataset`] reads each
//! with a row-group `POS` prune (via [`read_matching_rows_budgeted`]) and applies the
//! exact Sequence / Range / Bracket predicate to every decoded row.
//!
//! This module also owns the response assembly ([`assemble`]),
//! granularity / `includeResultsetResponses` shaping, the `beaconResponseMeta`
//! and received-request echo helpers, and the `datasets` collections response,
//! including the k-anonymity suppression logic.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use gdi_node_standalone_core::{
    cache::DatasetEntry,
    chrom::accession_for,
    error::{CoreResult, IoResultExt},
    model::{LocalizedText, ManifestConfig},
    parquet_io::{
        AlleleRow, DatasetDecryptor, PosWindow, ScanBudgets, read_matching_rows_budgeted,
    },
    popfield::{PopulationAxis, TOTAL_POPULATION, population_axis},
    validate_parquet::ParquetCaps,
    variant::Vt,
};

use crate::BeaconParams;
use sha2::{Digest as _, Sha256};

use crate::model::{
    BeaconCollectionsResponse, BeaconResponse, BeaconResponseMeta, Collection, CollectionsBody,
    Frequency, FrequencyInPopulations, GdiDatasetInfo, Identifiers, Pagination,
    ReceivedRequestSummary, ResponseSummary, ResultEntry, ResultSet, ResultSetsBody, Schema,
    SequenceInterval, SequenceLocation, Variation,
};
use crate::request::{IncludeResultsetResponses, Predicates, QueryKind, RequestParams};
use serde_json::Value;

/// The maximum number of storage blocks a single query may enumerate in
/// [`select_files`]. A coordinate-span ceiling, independent of the provider-controlled
/// `block_range`, so a hostile `blockRange` such as `1` cannot turn one request into an
/// arbitrarily wide scan of the shared serving process.
///
/// It bounds the span, not an allocation. `select_files` allocates nothing per block:
/// `first_block` and `last_block` are two scalars used for an O(1) `contains` test, and
/// `out` grows only with files that exist on disk.
///
/// Far above any legitimate query: at the default `blockRange = 10_000_000` reaching it
/// would need a span on the order of 1e12 bp, beyond any chromosome.
pub const MAX_QUERY_BLOCKS: i64 = 100_000;

/// Select the candidate `allele-freq.chr{chr}.{block}.br{block_range}.*.parquet`
/// files in `dir` for `kind`.
///
/// The candidate variant **start** is bounded by `lo`/`hi` (derived from `kind`:
/// Sequence `lo = hi = pos`; Range `lo = start`, `hi = end`; Bracket
/// `lo = s_min`, `hi = min(s_max, e_max)`). For a **range** query the lower bound is widened by
/// a lookback of `caps.max_ref_len` bp: a range's overlap predicate
/// (`v_start < end AND v_end > start`) can match a long variant whose `POS`
/// precedes the window, so the preceding blocks within one maximum-length REF must
/// be scanned. Deriving the lookback from `caps.max_ref_len` (rather than a
/// standalone constant) keeps it in lock-step with the ingest length cap and the
/// row-group pruning window, so raising the cap cannot silently leave a
/// long-variant block unselected. Sequence/bracket queries need no lookback (`0`).
///
/// The block span is the inclusive range `max(0, lo − lookback) / br ..= max(0, hi)
/// / br` — `hi` (not `hi − 1`) so the span is a superset that never misses a
/// block-boundary variant. When `block_range == 0` the single block `0` is used.
/// [`QueryKind::Empty`] selects nothing. Only existing files matching the glob are
/// returned, ordered by **parsed storage block** (then filename) — so the order is
/// POS-ascending across blocks, which [`scan_dataset_counts`] depends on. Sorting the
/// filenames instead would not be: the block is written unpadded, so `…chr1.10.…` sorts
/// before `…chr1.9.…`.
///
/// This orders blocks, not rows. When several source VCFs contribute a file to the same
/// block (a multi-VCF package, each file carrying its own `vcfid`), those files cover
/// overlapping `POS` spans and no ordering of whole files makes the concatenated row
/// stream monotonic. [`scan_dataset_counts`] fails closed on that rather than miscounting.
///
/// # Errors
/// [`CoreError::Io`] if the dataset directory cannot be read (perms, stale
/// mount, in-progress ingest swap). It is not swallowed to an empty list: an unreadable
/// published dataset must surface as a 500, not a truthful-looking `exists:false` false
/// negative.
///
/// [`CoreError::QueryTooLarge`] if the query's coordinate span divided by the dataset's
/// `block_range` would enumerate more than [`MAX_QUERY_BLOCKS`] storage blocks. That is a
/// fail-closed guard against a provider-controlled `block_range` driving an arbitrarily
/// wide scan, mapped to HTTP 400 by the caller. See [`MAX_QUERY_BLOCKS`] for what it does
/// and does not bound.
///
/// [`CoreError::Io`]: gdi_node_standalone_core::error::CoreError::Io
/// [`CoreError::QueryTooLarge`]: gdi_node_standalone_core::error::CoreError::QueryTooLarge
pub fn select_files(
    dir: &Path,
    chr: &str,
    block_range: u32,
    kind: &QueryKind,
    caps: &ParquetCaps,
) -> CoreResult<Vec<BlockFiles>> {
    let range_lookback = usize_i64(caps.max_ref_len);
    let (lo, hi, lookback) = match kind {
        QueryKind::Sequence { pos, .. } => (*pos, *pos, 0),
        QueryKind::Range { start, end, .. } => (*start, *end, range_lookback),
        // Bracket: the scan upper bound is min(s_max, e_max), not s_max. A Bracket match
        // requires v_end <= e_max and v_end >= v_start, so any row with POS (v_start) >
        // e_max can never match; clamping here bounds block enumeration by the
        // span-capped e_max even when s_max is pushed to i32::MAX (span-cap-bypass DoS).
        QueryKind::Bracket {
            s_min,
            s_max,
            e_max,
            ..
        } => (*s_min, (*s_max).min(*e_max), 0),
        QueryKind::Empty => return Ok(Vec::new()),
    };

    // Defence in depth: clamp the coordinates into the `i32` `POS` storage range before
    // deriving the block span. The request layer (`request::check_coord_bounds`) already
    // rejects out-of-range coordinates, but `select_files` is public, so this keeps the
    // derived span finite regardless of `max_query_span_bp`. A coordinate outside
    // `[0, i32::MAX]` can never match a stored `POS`, so clamping loses no real block.
    //
    // Both ends, not just the ceiling. `lo` is used as `lo - lookback` below, where a
    // sufficiently negative `lo` would overflow `i64` and panic, in a `pub fn` whose
    // callers may construct `QueryKind` directly (its variants carry public fields).
    let max_coord = i64::from(i32::MAX);
    let (lo, hi) = (lo.clamp(0, max_coord), hi.clamp(0, max_coord));

    let (first_block, last_block): (u64, u64) = if block_range == 0 {
        (0, 0)
    } else {
        let br = i64::from(block_range);
        let first = (lo - lookback).max(0) / br;
        let last = hi.max(0) / br;
        // Bound the block span independently of `block_range`, which is the provider's
        // `manifest.config.blockRange` taken verbatim with no lower bound at ingest. A
        // dataset shipping `blockRange = 1` turns one wide query into a ~2.1-billion-block
        // span, so fail the query closed (mapped to HTTP 400) rather than scan an
        // attacker-sized range. Legitimate datasets never approach this: at the default
        // `blockRange = 10_000_000` even a whole-chromosome span is a few dozen blocks.
        let count = last - first + 1;
        if count > MAX_QUERY_BLOCKS {
            return Err(gdi_node_standalone_core::error::CoreError::QueryTooLarge {
                detail: format!(
                    "query spans {count} storage blocks (blockRange {block_range}); \
                     exceeds the {MAX_QUERY_BLOCKS}-block limit; narrow the position range"
                ),
            });
        }
        // `first <= last` because `lo <= hi` and `lookback >= 0`; both are non-negative
        // after `.max(0)` and division by a positive `br`.
        #[expect(
            clippy::cast_sign_loss,
            reason = "first/last are non-negative after max(0) and division by a positive br"
        )]
        (first as u64, last as u64)
    };

    // Select each stored file in O(1) via the shared filename parser
    // (`validate_parquet::parse_block_and_range`, the grammar ingest and validate enforce),
    // range-checking its block against `[first_block, last_block]`. Parsing each name once
    // is O(dir-entries), independent of the queried span. Matching one filename prefix per
    // block against every directory entry would instead be O(dir-entries × blocks), and
    // both factors are provider-controlled: a tiny `blockRange` inflates the block count,
    // a flood of files the entry count.
    let chr_segment = format!("chr{chr}");
    // Keyed by the parsed block, so the sort below is numeric. The writer emits the block
    // unpadded (`…chr1.9.…` beside `…chr1.10.…`), so sorting the names would put block 10
    // before block 9 and hand `scan_dataset_counts` a row stream whose POS goes backwards
    // at a file boundary. That fold fails closed on it, turning a legitimate
    // `count`/`boolean` query straddling a digit boundary into a 500.
    let mut out: Vec<(u64, PathBuf)> = Vec::new();
    let entries = std::fs::read_dir(dir).io_ctx("read_dir", dir)?;
    for entry in entries {
        // Propagate a per-entry `readdir(3)` error instead of dropping it with `.flatten()`:
        // an unreadable published dataset dir must surface as a 500, not a truthful-looking
        // `exists:false` false negative (see this fn's contract above).
        let entry = entry.io_ctx("read_dir_entry", dir)?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // The parser fixes `allele-freq.chr{CHR}.{block}.br{range}.{vcfid}.parquet` and yields
        // `(block, range)`; a name it rejects is not a resolvable data file. The `chr` segment
        // (`parts[1]`) is matched separately against the queried chromosome.
        let Some((block, range)) =
            gdi_node_standalone_core::validate_parquet::parse_block_and_range(name)
        else {
            continue;
        };
        if range == block_range
            && (first_block..=last_block).contains(&block)
            && name.split('.').nth(1) == Some(chr_segment.as_str())
        {
            out.push((block, path));
        }
    }
    // `(block, path)` orders numerically by block, then by name to keep several files in
    // one block deterministic.
    out.sort();
    // Coalesce into per-block groups. The sort above already made equal blocks adjacent.
    let mut blocks: Vec<BlockFiles> = Vec::new();
    for (block, path) in out {
        match blocks.last_mut() {
            Some(last) if last.block == block => last.files.push(path),
            _ => blocks.push(BlockFiles {
                block,
                files: vec![path],
            }),
        }
    }
    Ok(blocks)
}

/// The stored parquet files of one storage block, in filename order.
///
/// Grouped rather than flat because a block can hold more than one file, and a flat list
/// invites the assumption that reading the files in order yields ascending `POS`. That
/// holds only when every block holds exactly one file. A package built from several source
/// VCFs stamps each file with its own `vcfid` (`core::convert::convert_vcf_group`), and a
/// per-population split (several VCFs over the same loci, each carrying different
/// populations) is a supported shape whose files cover the same `POS` span and interleave.
/// Grouping shows a consumer that needs ordered rows that it must merge within the group.
#[derive(Debug, Clone)]
pub struct BlockFiles {
    /// The storage block (`POS / block_range`) these files belong to.
    pub block: u64,
    /// Its files, sorted by name for determinism. Usually exactly one.
    pub files: Vec<PathBuf>,
}

/// What a completed `(POS, REF, ALT)` group is used for.
///
/// The fold below owns when a group is complete: the key change, the order guard, the final
/// flush. What happens to a completed group is the only thing the `count` and `record`
/// paths disagree about, so it is the only thing they implement separately. One tallies the
/// group, the other keeps it when it falls inside the requested page. Which groups exist,
/// and in what order, is shared, so the two cannot drift into disagreeing about the answer,
/// only about how much of it they retain.
trait GroupSink {
    /// Take a completed group. Called once per group, in ascending `(POS, REF, ALT)`.
    ///
    /// `retention` is the caller's process-wide budget. A sink that keeps a group charges
    /// it here: what a scan retains has to be visible to `max_total_query_bytes`, or the
    /// ceiling stops seeing the memory the read path holds.
    ///
    /// # Errors
    ///
    /// [`CoreError::ResourceExhausted`] when `retention` refuses the charge.
    ///
    /// [`CoreError::ResourceExhausted`]: gdi_node_standalone_core::error::CoreError::ResourceExhausted
    fn close(&mut self, group: VariantGroup, retention: &mut dyn RetentionSink) -> CoreResult<()>;
}

/// The streaming `(POS, REF, ALT)` group fold shared by [`scan_dataset_counts`] and
/// [`scan_dataset_page`].
///
/// Holds exactly one open group, bounded by the dataset's population count, so the memory
/// it needs is independent of the match-set size. The single-file (streamed) and multi-file
/// (merged) arms share this one definition of closing a group, so they cannot drift into
/// disagreeing about group boundaries.
struct GroupFold<S: GroupSink> {
    pending: Option<VariantGroup>,
    sink: S,
}

/// [`GroupSink`] that tallies surviving groups for a `boolean`/`count` answer.
struct CountSink {
    counts: DatasetCounts,
    floor: u32,
}

impl GroupSink for CountSink {
    /// Counting retains nothing beyond the open group, so there is nothing to charge.
    fn close(&mut self, group: VariantGroup, _retention: &mut dyn RetentionSink) -> CoreResult<()> {
        if group_survives(&group, self.floor) {
            self.counts.exists = true;
            self.counts.surviving = self.counts.surviving.saturating_add(1);
        }
        Ok(())
    }
}

/// [`GroupSink`] that keeps only the groups inside the requested page.
///
/// This is what makes `record` retention independent of the match-set size. A group that
/// survives the floor is counted whatever the window, so `results_count` is the true total
/// rather than the page length, but it is kept only when its ordinal falls in
/// `[skip, skip + limit)`. Everything outside the window is dropped as soon as it is
/// closed, so the rows of a million-variant match set never coexist.
struct PageSink {
    floor: u32,
    skip: u64,
    limit: u64,
    /// Surviving groups seen so far — the ordinal the window is applied to.
    total: u64,
    kept: Vec<VariantGroup>,
}

impl GroupSink for PageSink {
    fn close(&mut self, group: VariantGroup, retention: &mut dyn RetentionSink) -> CoreResult<()> {
        if !group_survives(&group, self.floor) {
            return Ok(());
        }
        let ordinal = self.total;
        self.total = self.total.saturating_add(1);
        // `limit == 0` is Beacon's "unbounded" sentinel, already clamped to the configured
        // page cap before it reaches here, so a zero limit means an empty page rather than
        // an unbounded one.
        let end = self.skip.saturating_add(self.limit);
        if ordinal < self.skip || ordinal >= end {
            return Ok(());
        }
        // Keeping this group makes it resident until the response is written, so charge it
        // before storing it: a saturated node then sheds the scan about to hold the memory
        // rather than the next request to arrive. Groups outside the window were dropped
        // above and cost nothing.
        let weight = group
            .rows
            .iter()
            .map(AlleleRow::scan_weight_bytes)
            .sum::<u64>();
        retention.charge(weight).map_err(|r| {
            gdi_node_standalone_core::error::CoreError::ResourceExhausted { detail: r.detail }
        })?;
        self.kept.push(group);
        Ok(())
    }
}

impl<S: GroupSink> GroupFold<S> {
    fn new(sink: S) -> Self {
        Self {
            pending: None,
            sink,
        }
    }

    /// Feed one row. Rows must arrive in ascending `(POS, REF, ALT)`. `source` names where
    /// they came from, for the guard's diagnostic.
    ///
    /// # Errors
    /// [`CoreError::InvalidParquet`] if the key goes backwards.
    ///
    /// [`CoreError::InvalidParquet`]: gdi_node_standalone_core::error::CoreError::InvalidParquet
    fn push(
        &mut self,
        row: AlleleRow,
        source: &str,
        retention: &mut dyn RetentionSink,
    ) -> CoreResult<()> {
        let same = self
            .pending
            .as_ref()
            .is_some_and(|g| g.pos == row.pos && g.ref_ == row.ref_ && g.alt == row.alt);
        if same {
            // `same` proved it is `Some`.
            if let Some(group) = self.pending.as_mut() {
                group.rows.push(row);
            }
            return Ok(());
        }
        if let Some(group) = self.pending.take() {
            // Order guard: the new key must not precede the one just closed, or a completed
            // group could still receive rows and be counted twice.
            //
            // Cross-file order cannot trip this: blocks are POS-disjoint and enumerated in
            // ascending block order, and a block holding several files is merged before it
            // is folded. A violation therefore means the rows inside one file are unsorted,
            // which no supported writer produces, and the message names the file.
            if (row.pos, &row.ref_, &row.alt) < (group.pos, &group.ref_, &group.alt) {
                return Err(gdi_node_standalone_core::error::CoreError::InvalidParquet {
                    detail: format!(
                        "rows within {source} are not ordered by (POS, REF, ALT): POS {} \
                             came after POS {}. Every partition is written sorted by \
                             (POS, REF, ALT, POPULATION), so these rows were not produced by \
                             a supported writer",
                        row.pos, group.pos
                    ),
                });
            }
            self.sink.close(group, retention)?;
        }
        self.pending = Some(VariantGroup {
            pos: row.pos,
            ref_: row.ref_.clone(),
            alt: row.alt.clone(),
            vt: row.vt,
            rows: vec![row],
        });
        Ok(())
    }

    /// Close the final group (it never sees a key change) and yield the sink.
    ///
    /// # Errors
    ///
    /// As [`GroupSink::close`].
    fn finish(mut self, retention: &mut dyn RetentionSink) -> CoreResult<S> {
        if let Some(group) = self.pending.take() {
            self.sink.close(group, retention)?;
        }
        Ok(self.sink)
    }
}

/// Answer a `boolean`/`count` query for one dataset without retaining its rows.
///
/// The record path materialises every matching row so `assemble_dataset` can group and page
/// them. A `boolean`/`count` response needs neither: only `exists` and the surviving-group
/// count reach the wire. Folding as the rows stream past holds one variant group at a time,
/// bounded by the dataset's population count, rather than the whole match set. That takes
/// both the match-set size and the population multiplier out of the memory cost of a wide
/// query, turning gigabytes into kilobytes.
///
/// Counting rather than short-circuiting on the first hit keeps the audit line honest: it
/// records the true `exists` and count before granularity shaping drops them from the
/// response. The count is O(1) memory either way, so only an early exit is given up.
///
/// # Memory
///
/// Streaming requires globally ascending `(POS, REF, ALT)`. That holds across blocks, which
/// are POS-disjoint and returned in ascending block order by [`select_files`], but not
/// across the files within one block: a package built from several source VCFs stores one
/// file per `vcfid` over the same `POS` span, so concatenating them makes `POS` jump
/// backwards. A per-population split is the supported shape that produces this.
///
/// Such a block is merged before it is folded: its matching rows are read from every file,
/// sorted, and then streamed through the same fold. A block holding a single file, the
/// common shape, still streams row by row.
///
/// Known limitation: for a multi-file block, peak memory scales with that block's whole
/// matching row set rather than with one group, and neither the requested granularity nor
/// the page window reduces it. The buffer exists to order the rows at all, before any sink
/// decides what to keep, so `boolean`/`count` costs what `record` costs, and `skip`/`limit`
/// are applied downstream by [`PageSpec`]. The bound is `caps.max_query_rows` and
/// `max_query_bytes`: the buffer is charged to the retention budget, so a ceiling turns an
/// oversized multi-file block into a refused query rather than an out-of-memory kill. While
/// the merge reads its next file, that file's parquet page-decode buffer is resident on top
/// of the bytes already merged, so the peak reaches `block_bytes + page_bytes`. That
/// over-shoot is bounded by exactly one page buffer; size RAM with that much headroom above
/// the ceiling. `docs/deployment.md` states the operator-facing sizing consequence.
///
/// The structural fix is a k-way merge across the block's already-sorted files, which would
/// stream this arm like the other and trade the whole-block buffer for `files × row_group`.
/// The parquet read seam is push-based (`for_each_matching_batch` takes a callback) and a
/// k-way merge needs pull-based per-file iterators, so it is a change to that seam rather
/// than to this function.
///
/// # Errors
/// The same decode and cap errors as [`scan_dataset`], plus a fail-closed error when the
/// rows inside one file are not sorted by `(POS, REF, ALT)`, from the fold's order guard.
pub fn scan_dataset_counts(
    dir: &Path,
    chr: &str,
    block_range: u32,
    kind: &QueryKind,
    caps: &ParquetCaps,
    decryptor: &DatasetDecryptor,
    aggregate: AggregateScan<'_>,
) -> CoreResult<DatasetCounts> {
    let blocks = select_files(dir, chr, block_range, kind, caps)?;
    let window = pos_window(kind, caps);
    let predicate = |row_pos: i32, row_ref: &str, row_alt: &str, vt: &str| {
        row_matches(kind, row_pos, row_ref, row_alt, vt)
    };

    // Destructured up front: the `budgets` closure captures `max_query_bytes` immutably
    // while the merge loop needs `sink` mutably, and both live on the same struct.
    let AggregateScan {
        max_query_bytes: agg_max_bytes,
        floor: agg_floor,
        sink,
    } = aggregate;
    let mut fold = GroupFold::new(CountSink {
        counts: DatasetCounts {
            exists: false,
            surviving: 0,
        },
        floor: agg_floor,
    });
    fold_matching_rows(
        &blocks,
        window,
        &predicate,
        caps,
        decryptor,
        agg_max_bytes,
        sink,
        &mut fold,
    )?;
    Ok(fold.finish(sink)?.counts)
}

/// Stream every row of `blocks` matching `predicate` through `fold`, in ascending
/// `(POS, REF, ALT)`.
///
/// The single definition of how a dataset's rows reach a fold, shared by the
/// `boolean`/`count` path ([`scan_dataset_counts`]) and the `record` path
/// ([`scan_dataset_page`]). Both must see the same rows in the same order. If they could
/// drift, a `count` answer would disagree with the `record` answer for the same query,
/// giving a wrong `numTotalResults` rather than a visible failure. [`row_matches`] is
/// single-sourced for the same reason.
///
/// # Memory
///
/// Holds one block's merge buffer at most, and only for a block several source VCFs
/// contributed to; the common single-file block streams row by row. The buffer is charged
/// to `sink` before it is allocated and credited back once folded, so two blocks' buffers
/// are never both outstanding.
///
/// # Errors
///
/// Decode/cap errors from the reader, [`CoreError::ResourceExhausted`] if `sink` refuses a
/// merge buffer, and [`CoreError::InvalidParquet`] if rows within one file are unsorted.
///
/// [`CoreError::ResourceExhausted`]: gdi_node_standalone_core::error::CoreError::ResourceExhausted
/// [`CoreError::InvalidParquet`]: gdi_node_standalone_core::error::CoreError::InvalidParquet
#[expect(
    clippy::too_many_arguments,
    reason = "every parameter is a distinct axis of one read: where to read, what to match, \
              what to charge, and where to fold. Bundling them would only move the list into \
              a struct literal at the two call sites that already differ in exactly one of them"
)]
fn fold_matching_rows<S: GroupSink>(
    blocks: &[BlockFiles],
    window: PosWindow,
    predicate: &impl Fn(i32, &str, &str, &str) -> bool,
    caps: &ParquetCaps,
    decryptor: &DatasetDecryptor,
    max_query_bytes: u64,
    sink: &mut dyn RetentionSink,
    fold: &mut GroupFold<S>,
) -> CoreResult<()> {
    let agg_max_bytes = max_query_bytes;
    let mut scanned_rows: usize = 0;
    // Bytes this scan retains right now, meaning the multi-file merge buffer below.
    // Streamed rows are not retained and are not counted. This rises as a block's buffer
    // fills and falls when the fold consumes it, so it tracks what is resident rather than
    // what has passed through: two blocks' buffers never coexist, and a ceiling that summed
    // them would shed a many-block dataset far below its true peak.
    let mut retained_bytes: u64 = 0;
    // The remaining global row and byte allowance, evaluated per file: the budgeted read
    // fails closed mid-file once that file alone would carry the cumulative total past a cap.
    //
    // Both axes are cumulative, because the ceiling is per dataset, not per file. Holding
    // `bytes` constant and decrementing only `rows` would give every file in a block a fresh
    // full `max_query_bytes` allowance while the merge buffer accumulates across all of
    // them, so an F-file block could retain F times the ceiling the operator sized RAM from.
    let budgets = |scanned: usize, retained: u64| ScanBudgets {
        rows: Some(caps.max_query_rows.saturating_sub(scanned)),
        bytes: Some(agg_max_bytes.saturating_sub(retained)),
    };

    for block in blocks {
        if let [file] = block.files.as_slice() {
            // The common shape: one file, already sorted, so stream it row-by-row and hold
            // only the open group.
            let label = file
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("this parquet file")
                .to_owned();
            let file_budgets = budgets(scanned_rows, retained_bytes);
            gdi_node_standalone_core::parquet_io::for_each_matching_batch(
                file,
                caps,
                window,
                &predicate,
                decryptor,
                file_budgets,
                |batch| {
                    scanned_rows = scanned_rows.saturating_add(batch.len());
                    for row in batch.drain(..) {
                        fold.push(row, &label, sink)?;
                    }
                    Ok(())
                },
            )?;
        } else {
            // Several source VCFs contributed a file to this block (a per-population split),
            // so their POS spans overlap and concatenation is not ascending. Merge the block
            // first — see this function's `# Memory` note for the bound that buys.
            // Report the shape before allocating for it, so a scan the ceiling then sheds
            // still tells the operator which block did it.
            sink.note_merged_block(block.files.len());
            let mut rows: Vec<AlleleRow> = Vec::new();
            // What this block's buffer holds, so it can be credited back once folded.
            let mut block_bytes: u64 = 0;
            for file in &block.files {
                let mut part = read_matching_rows_budgeted(
                    file,
                    caps,
                    window,
                    &predicate,
                    decryptor,
                    budgets(scanned_rows, retained_bytes),
                )?;
                scanned_rows = scanned_rows.saturating_add(part.len());
                // The merge buffer is what this arm retains, so charge it before appending,
                // against both the cumulative per-dataset budget and the caller's
                // process-wide sink. A saturated node then sheds the scan about to allocate
                // rather than the next request to arrive.
                let weight = part.iter().map(AlleleRow::scan_weight_bytes).sum::<u64>();
                retained_bytes = retained_bytes.saturating_add(weight);
                block_bytes = block_bytes.saturating_add(weight);
                sink.charge(weight).map_err(|r| {
                    gdi_node_standalone_core::error::CoreError::ResourceExhausted {
                        detail: r.detail,
                    }
                })?;
                rows.append(&mut part);
            }
            rows.sort_by(|a, b| (a.pos, &a.ref_, &a.alt).cmp(&(b.pos, &b.ref_, &b.alt)));
            let label = format!("block {}", block.block);
            for row in rows {
                fold.push(row, &label, sink)?;
            }
            // The fold above consumed `rows`, so the buffer this block charged for is gone:
            // credit it back on both ceilings before the next block allocates its own. An
            // early `?` skips this because the scan is unwinding and the caller's guard
            // reclaims the whole charge at once.
            retained_bytes = retained_bytes.saturating_sub(block_bytes);
            sink.release(block_bytes);
        }
    }

    Ok(())
}

/// Which groups a `record` scan keeps: the disclosure floor, and the page window.
///
/// These three travel together through the scan, the fold and the sink, and `skip` and
/// `limit` are same-typed neighbours: passing one where the other belongs compiles silently
/// and yields a plausible wrong page. Naming them makes that transposition unwritable.
#[derive(Debug, Clone, Copy)]
pub struct PageSpec {
    /// Minimum allele count a population must reach to be disclosed.
    pub floor: u32,
    /// Surviving groups to skip before the page starts.
    pub skip: u64,
    /// Surviving groups to keep. `0` means an empty page, not an unbounded one: Beacon's
    /// "unbounded" sentinel is clamped to the configured cap before it reaches here.
    pub limit: u64,
}

impl PageSpec {
    /// Every surviving group, suppressing nothing, which is the shape `scan_dataset` wants.
    #[must_use]
    pub const fn everything() -> Self {
        Self {
            floor: 0,
            skip: 0,
            limit: u64::MAX,
        }
    }
}

/// One dataset's `record` answer: the requested page, plus the true surviving total.
#[derive(Debug, Default)]
pub struct DatasetPage {
    /// The surviving variant groups inside `[skip, skip + limit)`, ascending.
    pub groups: Vec<VariantGroup>,
    /// Surviving groups across the whole match set, independent of the page.
    pub total: u64,
    /// The disclosure floor this page was built with.
    ///
    /// The floor decides which groups survive, and therefore both `total` and the page
    /// ordinals. Assembly derives its own floor from config (`assemble_dataset`), so a page
    /// built under a lower floor is re-suppressed rather than served, in `results[]` and in
    /// `resultsCount`/`exists` alike: the scan's `total` is trusted only when this floor is
    /// at least the configured one. Otherwise the count falls back to the in-window
    /// survivors under the configured floor, a lower bound that never discloses a
    /// below-floor variant's existence. The ordinals remain the scan's, so a caller that
    /// wants them right passes `effective_floor` to both.
    pub floor: u32,
}

impl DatasetPage {
    /// Build a page from rows already in memory.
    ///
    /// Goes through the same `GroupFold` and `PageSink` the scan uses, so a page built this
    /// way and a page built by [`scan_dataset_page`] cannot disagree about grouping,
    /// survival or the window. Rows are sorted first, so an unordered caller is safe here.
    /// The streaming scan cannot afford that sort and guards the order instead.
    ///
    /// # Errors
    ///
    /// The fold's order guard cannot trip on rows this function has just sorted, so this
    /// returns `Err` only if that guard changes. The signature mirrors the scan's so the
    /// two stay interchangeable.
    pub fn from_rows(mut rows: Vec<AlleleRow>, page: PageSpec) -> CoreResult<Self> {
        rows.sort_by(|a, b| (a.pos, &a.ref_, &a.alt).cmp(&(b.pos, &b.ref_, &b.alt)));
        let mut fold = GroupFold::new(PageSink {
            floor: page.floor,
            skip: page.skip,
            limit: page.limit,
            total: 0,
            kept: Vec::new(),
        });
        for row in rows {
            fold.push(row, "an in-memory row set", &mut UnboundedRetention)?;
        }
        let PageSink { total, kept, .. } = fold.finish(&mut UnboundedRetention)?;
        Ok(Self {
            groups: kept,
            total,
            floor: page.floor,
        })
    }

    /// Retained-row bytes this page holds, for the caller's cross-dataset ceiling.
    #[must_use]
    pub fn retained_bytes(&self) -> u64 {
        self.groups
            .iter()
            .flat_map(|g| &g.rows)
            .map(AlleleRow::scan_weight_bytes)
            .sum()
    }
}

/// Answer a `record` query for one dataset, retaining only the requested page.
///
/// Inclusion is decided as groups close, so what is retained is the page plus one open
/// group. Materialising every matching row and leaving grouping, suppression and paging to
/// `assemble_dataset` would make `limit` no bound on memory at all: a query matching a
/// million variants would retain a million variants' rows in order to return ten.
///
/// The floor is applied here rather than at assembly because whether a group survives
/// decides whether it counts toward the page ordinal. It is the same `group_survives` the
/// count path uses, so the two agree by construction.
///
/// # Errors
///
/// As the shared scan loop: any [`CoreError`] from reading or decoding a selected parquet
/// file, and [`CoreError::ResourceExhausted`] when a retention sink refuses the page.
///
/// [`CoreError`]: gdi_node_standalone_core::error::CoreError
/// [`CoreError::ResourceExhausted`]: gdi_node_standalone_core::error::CoreError::ResourceExhausted
#[expect(
    clippy::too_many_arguments,
    reason = "the floor and window are already grouped into `PageSpec`; the rest are the \
              dataset's location, the read caps, the decryptor and the two independent byte \
              ceilings, none of which co-vary"
)]
pub fn scan_dataset_page(
    dir: &Path,
    chr: &str,
    block_range: u32,
    kind: &QueryKind,
    caps: &ParquetCaps,
    decryptor: &DatasetDecryptor,
    max_query_bytes: u64,
    page: PageSpec,
    sink: &mut dyn RetentionSink,
) -> CoreResult<DatasetPage> {
    let blocks = select_files(dir, chr, block_range, kind, caps)?;
    let window = pos_window(kind, caps);
    let predicate = |row_pos: i32, row_ref: &str, row_alt: &str, vt: &str| {
        row_matches(kind, row_pos, row_ref, row_alt, vt)
    };
    let mut fold = GroupFold::new(PageSink {
        floor: page.floor,
        skip: page.skip,
        limit: page.limit,
        total: 0,
        kept: Vec::new(),
    });
    fold_matching_rows(
        &blocks,
        window,
        &predicate,
        caps,
        decryptor,
        max_query_bytes,
        sink,
        &mut fold,
    )?;
    let PageSink { total, kept, .. } = fold.finish(sink)?;
    Ok(DatasetPage {
        groups: kept,
        total,
        floor: page.floor,
    })
}

/// Does one decoded row satisfy `kind`?
///
/// The single definition of a row match, shared by the record path ([`scan_dataset`]) and
/// the aggregate path ([`scan_dataset_counts`]). Single-sourcing it is what keeps a
/// `boolean`/`count` answer from disagreeing with the `record` answer for the same query.
fn row_matches(kind: &QueryKind, row_pos: i32, row_ref: &str, row_alt: &str, vt: &str) -> bool {
    match kind {
        QueryKind::Sequence {
            pos,
            ref_,
            alt,
            predicates,
        } => {
            i64::from(row_pos) == *pos
                && row_ref == ref_
                && row_alt == alt
                && matches_predicates(predicates, row_ref, row_alt, vt)
        }
        QueryKind::Range {
            start,
            end,
            predicates,
        } => {
            let v_start = i64::from(row_pos);
            let v_end = v_start + len_i64(row_ref);
            v_start < *end && v_end > *start && matches_predicates(predicates, row_ref, row_alt, vt)
        }
        QueryKind::Bracket {
            s_min,
            s_max,
            e_min,
            e_max,
            predicates,
        } => {
            let v_start = i64::from(row_pos);
            let v_end = v_start + len_i64(row_ref);
            *s_min <= v_start
                && v_start <= *s_max
                && *e_min <= v_end
                && v_end <= *e_max
                && matches_predicates(predicates, row_ref, row_alt, vt)
        }
        QueryKind::Empty => false,
    }
}

/// The aggregate answer for one dataset: everything a `boolean` or `count` response needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatasetCounts {
    /// Did any variant group survive the disclosure floor?
    pub exists: bool,
    /// How many groups survived — the resultSet's `resultsCount`.
    pub surviving: u64,
}

/// The per-dataset inputs unique to an aggregate scan, grouped to keep
/// [`scan_dataset_counts`] within the argument limit.
// No `Copy`/`Clone`/`Debug`: the sink is a unique mutable borrow, because two copies of a
// scan's accounting handle would each charge the same bytes.
pub struct AggregateScan<'a> {
    /// Per-dataset retained-row byte ceiling (`[service].max_query_bytes`).
    pub max_query_bytes: u64,
    /// The disclosure floor to apply, from `effective_floor`.
    pub floor: u32,
    /// Charged as the multi-file block buffer grows. This struct has no `Default`, so a new
    /// call site cannot skip the accounting by omission; pass [`UnboundedRetention`] to opt
    /// out explicitly.
    pub sink: &'a mut dyn RetentionSink,
}

/// A sink that accounts for bytes a scan retains, charged as they accumulate.
///
/// A sink rather than a return value, because weighing the rows after the scan hands them
/// back leaves a dataset's peak already resident before anything is charged. Concurrent
/// scans, each free to reach `max_query_bytes`, could then pass the process-wide ceiling
/// several times over before the first debit lands, shedding the next request rather than
/// the current spike. Charging inside the accumulation loop is what makes the ceiling a
/// bound rather than a report.
///
/// The engine knows nothing about where the ceiling comes from: implementors hold whatever
/// process-wide state they like and answer one question.
pub trait RetentionSink {
    /// Account for `bytes` about to be retained.
    ///
    /// # Errors
    ///
    /// [`RetentionRejected`] when the ceiling is full. The scan aborts and the caller maps
    /// it to [`CoreError::ResourceExhausted`], a 5xx meaning the server is saturated, never
    /// the 4xx that [`CoreError::QueryTooLarge`] carries, which means the request is too
    /// broad.
    ///
    /// [`CoreError::ResourceExhausted`]: gdi_node_standalone_core::error::CoreError::ResourceExhausted
    /// [`CoreError::QueryTooLarge`]: gdi_node_standalone_core::error::CoreError::QueryTooLarge
    fn charge(&mut self, bytes: u64) -> Result<(), RetentionRejected>;

    /// Credit back `bytes` of an earlier [`charge`](Self::charge) whose buffer the scan has
    /// freed.
    ///
    /// The aggregate path drops each multi-file block's merge buffer as soon as it is
    /// folded, so what a dataset holds at once is the largest block's buffer, not the sum
    /// over blocks. Without this credit the ceiling would bound that sum: a many-block
    /// dataset would trip it at a fraction of its true peak and shed legitimate queries.
    ///
    /// A scan that fails mid-flight does not credit back what it already charged.
    /// Reclaiming that remainder belongs to whoever owns the sink; the node ties it to the
    /// request's lifetime with a drop guard. Implementations must clamp the credit to what
    /// is outstanding, so an accounting slip cannot hand back another scan's charge.
    fn release(&mut self, bytes: u64);

    /// Report that a block was buffered and sorted whole because `files` source files (a
    /// per-population split) contributed overlapping `POS` spans to it, so the scan could
    /// not stream it. Called once per such block, immediately before its first charge.
    ///
    /// This arm is the one shape whose peak is bounded by neither granularity nor `limit`,
    /// and it follows from how the package was built, which no operator-facing surface
    /// otherwise reveals. The engine reports it and holds no opinion; implementors decide
    /// whether anyone is listening.
    ///
    /// Required rather than defaulted: a sink that does not care writes an empty body,
    /// which is a visible decision, where a default would let the signal be lost by
    /// omission.
    fn note_merged_block(&mut self, files: usize);
}

/// A retention charge the sink refused.
#[derive(Debug, Clone)]
pub struct RetentionRejected {
    /// Non-sensitive description of which ceiling was hit.
    pub detail: String,
}

/// A sink that admits everything — for benches, property tests, and any caller with no
/// process-wide ceiling to enforce.
///
/// Not the default: a scan takes its sink explicitly, so charging nothing is a visible
/// choice at the call site rather than the absence of one.
#[derive(Debug, Default)]
pub struct UnboundedRetention;

impl RetentionSink for UnboundedRetention {
    fn charge(&mut self, _bytes: u64) -> Result<(), RetentionRejected> {
        Ok(())
    }

    fn release(&mut self, _bytes: u64) {}

    /// Nothing observes a bench or property-test scan.
    fn note_merged_block(&mut self, _files: usize) {}
}

/// Select and scan a dataset directory, returning every [`AlleleRow`] that
/// matches `kind`'s exact predicate.
///
/// Files are chosen by [`select_files`]; each is read with [`read_matching_rows_budgeted`]
/// using a [`PosWindow`] superset for row-group pruning and a closure
/// implementing the exact predicate:
///
/// * **Sequence** — `POS == pos AND REF == ref AND ALT == alt`.
/// * **Range** — half-open overlap `v_start < end AND v_end > start` (where
///   `v_start = POS`, `v_end = POS + len(REF)`), plus the optional
///   [`Predicates`].
/// * **Bracket** — `s_min ≤ v_start ≤ s_max AND e_min ≤ v_end ≤ e_max`, plus the
///   optional [`Predicates`].
///
/// The returned rows are the predicate matches and nothing else: pruning is a superset
/// filter, and the closure re-checks `POS` so a row in a partially overlapping row group
/// cannot leak through.
///
/// # Errors
///
/// Propagates any [`gdi_node_standalone_core::error::CoreError`] from reading or
/// decoding a selected parquet file.
#[expect(
    clippy::too_many_arguments,
    reason = "the retention sink is the 8th; bundling it into a struct would hide the \
              one parameter a new call site must not forget"
)]
pub fn scan_dataset(
    dir: &Path,
    chr: &str,
    block_range: u32,
    kind: &QueryKind,
    caps: &ParquetCaps,
    decryptor: &DatasetDecryptor,
    max_query_bytes: u64,
    sink: &mut dyn RetentionSink,
) -> CoreResult<Vec<AlleleRow>> {
    // Floor 0 suppresses nothing, so every non-empty group survives, and an unbounded
    // window keeps every one of them: the result is every matching row, in ascending
    // (POS, REF, ALT) rather than file order. Expressed through the paged scan so there is
    // one definition of which rows match rather than two that could drift.
    //
    // The serving path does not use this. It calls `scan_dataset_page` with the request's
    // real floor and window and never materialises the whole match set. This shape is for
    // tests, benches and the PME round-trip, which want the rows themselves.
    let page = scan_dataset_page(
        dir,
        chr,
        block_range,
        kind,
        caps,
        decryptor,
        max_query_bytes,
        PageSpec::everything(),
        sink,
    )?;
    Ok(page.groups.into_iter().flat_map(|g| g.rows).collect())
}

/// The inclusive `POS` superset window for row-group pruning.
///
/// Sequence: `[pos, pos]`. Range: `[start − max_ref_len, end − 1]` — the lower
/// bound subtracts the longest indexable `REF` so a long variant starting before
/// the window is not pruned; the upper bound is `end − 1` because the overlap
/// predicate requires `v_start < end`. Bracket: `[s_min, min(s_max, e_max)]` — a match
/// needs `v_end <= e_max` and `v_end >= v_start`, so `POS > e_max` never matches;
/// clamping to `e_max` keeps the prune window inside the span cap even when `s_max` is
/// unbounded. [`QueryKind::Empty`] yields an empty window `[1, 0]` (it selects no files
/// anyway).
fn pos_window(kind: &QueryKind, caps: &ParquetCaps) -> PosWindow {
    match kind {
        QueryKind::Sequence { pos, .. } => PosWindow { lo: *pos, hi: *pos },
        QueryKind::Range { start, end, .. } => PosWindow {
            lo: start - usize_i64(caps.max_ref_len),
            hi: end - 1,
        },
        QueryKind::Bracket {
            s_min,
            s_max,
            e_max,
            ..
        } => PosWindow {
            lo: *s_min,
            // min(s_max, e_max): POS > e_max can never match (v_end >= v_start and
            // v_end <= e_max), so an unbounded s_max must not disable row-group pruning
            // (span-cap-bypass DoS).
            hi: (*s_max).min(*e_max),
        },
        QueryKind::Empty => PosWindow { lo: 1, hi: 0 },
    }
}

/// Apply the optional range/bracket [`Predicates`] to one decoded row.
///
/// A present `ref_`/`alt` is an equality check and a present `variant_type` is a
/// set-membership check (the row's `vt` must be one of the selected labels); a
/// present `min_len`/`max_len` bounds the alternate-allele length `len(ALT)` (matching the
/// GDI reference beacon beacon2-pi-api, which maps the length filter to `alternateBases`).
fn matches_predicates(p: &Predicates, row_ref: &str, row_alt: &str, vt: &str) -> bool {
    if let Some(want) = &p.ref_
        && row_ref != want
    {
        return false;
    }
    if let Some(want) = &p.alt
        && row_alt != want
    {
        return false;
    }
    if let Some(wanted) = &p.variant_type
        && !wanted.iter().any(|w| w == vt)
    {
        return false;
    }
    // An SNV has `len(ALT) == 1`, so `variantMinLength=1` includes it.
    let alt_len = len_i64(row_alt);
    if let Some(min) = p.min_len
        && alt_len < min
    {
        return false;
    }
    if let Some(max) = p.max_len
        && alt_len > max
    {
        return false;
    }
    true
}

/// Length of `s` as an `i64`, saturating at [`i64::MAX`].
///
/// Allele lengths are tiny (ingest caps `len(REF)` at 10 000), so saturation
/// never occurs in practice; it only keeps the conversion total and lint-clean.
fn len_i64(s: &str) -> i64 {
    i64::try_from(s.len()).unwrap_or(i64::MAX)
}

/// A `usize` cap as an `i64`, saturating at [`i64::MAX`].
fn usize_i64(n: usize) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

/// The `defaultSchema.json` URL for a Beacon v2 default-model entry directory
/// (`model_dir`, e.g. `genomicVariations`) at the served `api_version`.
///
/// Single-sources the `ga4gh-beacon/beacon-v2` template shared by the per-entry
/// schema-URL helpers; the node emits these URLs but never fetches them.
fn model_schema_url(api_version: &str, model_dir: &str) -> String {
    format!(
        "https://raw.githubusercontent.com/ga4gh-beacon/beacon-v2/{api_version}/models/json/beacon-v2-default-model/{model_dir}/defaultSchema.json"
    )
}

/// The genomicVariant default-schema URL for `api_version`, named in `returnedSchemas`.
///
/// Points into the `ga4gh-beacon/beacon-v2` repository at the served API version tag (e.g.
/// `v2.2.0`).
fn genomic_variant_schema_url(api_version: &str) -> String {
    model_schema_url(api_version, "genomicVariations")
}

/// Build a [`BeaconResponseMeta`] with the node's fixed envelope shaping: top-level
/// `returnedGranularity` is always `"record"` (the node serves up to record; the
/// per-request ceiling is applied later by [`shape_for_granularity`]), and the echoed
/// `receivedRequestSummary` always carries `testMode: false`, an empty
/// `requestedSchemas`, and `includeResultsetResponses: HIT` (the HTTP layer overlays the
/// real values afterwards via [`echo_received_request`]). Callers supply the
/// `returnedSchemas` (the called entry type's default schema), the echoed
/// `requestedGranularity`, and the applied `pagination`. Single-sources the meta shape
/// shared by [`error_response_meta`], [`assemble`] and [`collections_meta`].
fn response_meta(
    beacon_cfg: &BeaconParams,
    returned_schemas: Vec<Schema>,
    requested_granularity: &str,
    pagination: Pagination,
) -> BeaconResponseMeta {
    BeaconResponseMeta {
        beacon_id: beacon_cfg.id.clone(),
        api_version: beacon_cfg.api_version.clone(),
        returned_granularity: "record".to_owned(),
        returned_schemas,
        received_request_summary: ReceivedRequestSummary {
            api_version: beacon_cfg.api_version.clone(),
            requested_granularity: requested_granularity.to_owned(),
            test_mode: false,
            // Like `test_mode`, the shipped default that `echo_received_request` overlays
            // on the success path. A `beaconErrorResponse` keeps it: a request rejected
            // before its envelope was read has no applied shaping to report, and `HIT` is
            // what the node would have applied had it answered.
            include_resultset_responses: IncludeResultsetResponses::Hit,
            requested_schemas: Vec::new(),
            pagination,
            // Set by the HTTP layer only on the path that assumed an assembly (see
            // `ReceivedRequestSummary::assumed_assembly_id`); absent everywhere else.
            assumed_assembly_id: None,
        },
    }
}

/// Build the fully-populated [`BeaconResponseMeta`] used by a `beaconErrorResponse`.
///
/// The error envelope must carry the **same** `meta` shape as a success response:
/// `returnedSchemas` naming the genomicVariant default
/// schema and a `receivedRequestSummary` with the applied pagination. A rejected
/// request may not have been parsed far enough to echo the real requested values,
/// so the granularity defaults to `"record"`, pagination to the node default, and
/// `includeResultsetResponses` to the `HIT` the request would have been shaped with;
/// the schema only constrains the *shape*, which this satisfies. The service
/// binary's HTTP handlers call this to render rejects (the model types are
/// `#[non_exhaustive]`, so this is the supported construction path).
///
/// # Examples
///
/// ```
/// use gdi_node_standalone_beacon::BeaconParams;
/// use gdi_node_standalone_beacon::query::error_response_meta;
///
/// let cfg = BeaconParams::default();
/// let meta = error_response_meta(&cfg, "genomicVariant");
///
/// // A rejected request defaults granularity to "record" and echoes the served
/// // API version + the node's default page limit in the request summary.
/// assert_eq!(meta.returned_granularity, "record");
/// assert_eq!(meta.api_version, cfg.api_version);
/// assert_eq!(meta.received_request_summary.pagination.limit, cfg.default_page_limit);
/// // Exactly one returnedSchemas entry, naming the genomicVariant entry type.
/// assert_eq!(meta.returned_schemas.len(), 1);
/// assert_eq!(meta.returned_schemas[0].entry_type, "genomicVariant");
/// ```
#[must_use]
pub fn error_response_meta(beacon_cfg: &BeaconParams, entry_type: &str) -> BeaconResponseMeta {
    let schema = entry_schema(entry_type, &beacon_cfg.api_version);
    response_meta(
        beacon_cfg,
        vec![schema],
        "record",
        Pagination::new(0, beacon_cfg.default_page_limit),
    )
}

/// The response `meta` for a request that matched **no route** — an empty
/// `returnedSchemas`.
///
/// Distinct from [`error_response_meta`], which names the entry type it interpreted the
/// request as. That is right for a `400`: the route was found, the request was for a known
/// entity, and it was rejected on its contents. It is a false claim for a path that matched
/// nothing, where the node interpreted the request as no entity at all.
///
/// The field's own vendored description says it "indicates that the request has been
/// interpreted for the indicated entity" and exists "to disambiguate between negative
/// responses due to e.g. no hit on a well understood request and failures to interpret …
/// the request". A route miss is the second case, so the honest value is the empty list.
/// `ListOfSchemas` sets no `minItems`, so an empty array stays conformant, and
/// `returnedSchemas` remains present as the schema's `required` demands.
///
/// ```
/// use gdi_node_standalone_beacon::BeaconParams;
/// use gdi_node_standalone_beacon::query::route_miss_response_meta;
///
/// let cfg = BeaconParams::default();
/// let meta = route_miss_response_meta(&cfg);
/// assert!(meta.returned_schemas.is_empty());
/// assert_eq!(meta.api_version, cfg.api_version);
/// ```
#[must_use]
pub fn route_miss_response_meta(beacon_cfg: &BeaconParams) -> BeaconResponseMeta {
    response_meta(
        beacon_cfg,
        Vec::new(),
        "record",
        Pagination::new(0, beacon_cfg.default_page_limit),
    )
}

/// The `(filters, requestedSchemas)` a request submitted: the two array-valued echo
/// candidates, each empty when the key is absent or not an array, never a panic or a
/// reflected scalar. The summary's other echoes (`testMode`,
/// `includeResultsetResponses`) are scalars read directly by [`echo_received_request`].
///
/// `requestedSchemas` elements are kept only when they are JSON objects. The value is
/// wholly client-supplied and is echoed onto the wire, where the vendored schema types it
/// as `ListOfSchemas` → `SchemasPerEntity` (`"type": "object"`). Echoing it verbatim would
/// let a client submit `requestedSchemas: [42, "x"]` and make the node emit a response that
/// fails its own `beacon_schema_conformance` gate, the same hazard `requestParameters` is
/// not echoed for (see [`crate::model::ReceivedRequestSummary`]). Filtering here, at the
/// one chokepoint both the aggregated and sensitive planes call, keeps the two from
/// drifting apart. A scalar in that position carries no recoverable meaning, so dropping it
/// costs the client nothing.
///
/// `filters` are returned verbatim, because no caller puts them on the wire and the
/// decision belongs to the caller. `g_variants` and `datasets` reject a non-empty `filters`
/// upstream with a `400` (see [`crate::request::reject_unsupported_filters`]) and
/// [`echo_received_request`] discards this half of the tuple. The `/individuals`
/// placeholder accepts a `filters` list as a no-op and reflects nothing: the vendored
/// `Filters` def types items as `"type": "string"` (CURIEs), while the Beacon v2
/// ontology-filter shape real clients send is an object (`{"id": "NCIT:C20197"}`), so
/// reflecting one yields a response that fails the node's own conformance gate. Filtering
/// those elements to strings would misreport what the client submitted, which is the
/// opposite of what an echo is for.
#[must_use]
pub fn submitted_request_echo(params: &RequestParams) -> (Vec<Value>, Vec<Value>) {
    let arr = |key: &str| {
        params
            .get(key)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    let objects_only = |key: &str| {
        params
            .get(key)
            .and_then(Value::as_array)
            .map(|items| items.iter().filter(|v| v.is_object()).cloned().collect())
            .unwrap_or_default()
    };
    (arr("filters"), objects_only("requestedSchemas"))
}

/// Echo the submitted `requestedSchemas` and `testMode`, and the applied
/// `includeResultsetResponses`, into an already-built `meta.receivedRequestSummary` —
/// Beacon v2's transparency mechanism so a client can see how the server interpreted its
/// request. `requestedSchemas` is echoed but not honoured (the node serves a single
/// default schema). `includeResultsetResponses` is honoured, so it echoes the applied
/// value rather than the submitted one. `filters` are never echoed: a submitted
/// `filters` selector is rejected upstream with a 400 (`reject_unsupported_filters`) and
/// `ReceivedRequestSummary` has no filters field.
///
/// Applied by the HTTP layer **after** assembly so the pure response builders stay
/// request-agnostic. A golden snapshot that submits none of these stays byte-identical
/// under this overlay: `requestedSchemas` defaults to an empty array, `testMode` to
/// `false`, `filters` is never echoed, and `includeResultsetResponses` overlays the same
/// `HIT` that the meta builder already seeded.
pub fn echo_received_request(meta: &mut BeaconResponseMeta, params: &RequestParams) {
    let (_filters, requested_schemas) = submitted_request_echo(params);
    // `filters` are not echoed: this beacon rejects a submitted `filters` selector with
    // a 400 (see `reject_unsupported_filters`), so a request that reaches here carried
    // none.
    meta.received_request_summary.requested_schemas = requested_schemas;
    // Echo `testMode` (the request has already been validated as boolean by
    // `check_envelope`, so a parse error here degrades to the `false` default).
    meta.received_request_summary.test_mode = crate::request::testmode_flag(params.get("testMode"))
        .ok()
        .flatten()
        .unwrap_or(false);
    // Echo the applied `includeResultsetResponses` so a client can see which shaping it
    // got, including the `HIT` it gets by saying nothing. `check_envelope` has already
    // rejected an out-of-enum value with a 400, so the parse cannot fail on a request that
    // reaches here, and the fallback is the same `HIT` the answer was shaped with rather
    // than a value the response did not use.
    meta.received_request_summary.include_resultset_responses =
        crate::request::parse_include_resultset_responses(params)
            .unwrap_or(IncludeResultsetResponses::Hit);
}

/// Map a nullable `i32` count to the wire `Option<u64>` (negative → `None`).
///
/// Counts are non-negative by construction (ingest validation), so a negative
/// value is treated as absent rather than panicking or wrapping.
fn count_u64(v: Option<i32>) -> Option<u64> {
    v.and_then(|n| u64::try_from(n).ok())
}

/// The three genotype sub-counts (`AC_Hom`/`AC_Het`/`AC_Hemi`), suppressed coherently: if
/// a below-floor genotype cell is derivable at all, all three are withheld, or the withheld
/// one would be recoverable from `AC` and the survivors (`hom = (AC - het)/2`). Empty cells
/// (`v == 0`) never trigger suppression, and `floor <= 0` (the default) passes every value
/// through unchanged.
///
/// `ac` is the *client-derivable* alt-carrier count from [`alt_carriers`] (the exact `AC`
/// when present, else `round(AF*AN)`) — not the `AC` column — because the residual arm of
/// [`genotype_cell_in_danger`] is arithmetic the client can do with either.
fn gate_subcounts(
    ac: Option<i64>,
    hom: Option<i32>,
    het: Option<i32>,
    hemi: Option<i32>,
    floor: i64,
) -> (Option<u64>, Option<u64>, Option<u64>) {
    if genotype_cell_in_danger(ac, hom, het, hemi, floor) {
        return (None, None, None);
    }
    (count_u64(hom), count_u64(het), count_u64(hemi))
}

/// Whether a single nullable genotype count is a non-empty group below the floor
/// (`1 <= v < floor`). Empty cells (`0`) and `floor <= 0` (the default) never trigger.
fn count_in_danger(v: Option<i32>, floor: i64) -> bool {
    matches!(v, Some(x) if (1..floor).contains(&i64::from(x)))
}

/// Whether a below-floor genotype cell is derivable from one row's sub-counts. The single
/// definition shared by the per-row gate ([`gate_subcounts`]) and the cross-population
/// collapse trigger ([`subcount_in_danger`]), so the two cannot drift. The same reason
/// makes [`axis_remainder_reidentifying`] shared across the `AC` and sub-count planes.
///
/// Two ways a cell becomes derivable:
///
/// * **Present and small** — a reported sub-count is itself in `1..floor`.
/// * **Absent, with a small residual** — the three sub-counts partition `AC` exactly
///   (`core::subcounts`: they count alleles, so a reported triple sums to `AC`). When one or
///   more is absent, `residual = AC - Σ(present)` is the withheld remainder, and the client
///   computes it with the same arithmetic. With exactly one absent the residual is that
///   cell; with two or three absent it is their sum, and a below-floor sum bounds each of
///   them below the floor too, so withholding is correct either way. Ingest permits the
///   partial shape (`check_subcounts` requires exact equality only when all three are
///   present, and `sum <= AC` otherwise), so this is a reachable input, not a malformed one.
///
/// Withholding all three removes the client's ability to evaluate the residual at all: `AC`
/// alone says nothing about the split.
fn genotype_cell_in_danger(
    ac: Option<i64>,
    hom: Option<i32>,
    het: Option<i32>,
    hemi: Option<i32>,
    floor: i64,
) -> bool {
    if count_in_danger(hom, floor) || count_in_danger(het, floor) || count_in_danger(hemi, floor) {
        return true;
    }
    // A complete triple leaves no remainder to recover, and `floor <= 0` disables the floor.
    if floor <= 0 || (hom.is_some() && het.is_some() && hemi.is_some()) {
        return false;
    }
    let Some(ac) = ac else {
        // No derivable carrier count: the client cannot form the residual either.
        return false;
    };
    let present =
        i64::from(hom.unwrap_or(0)) + i64::from(het.unwrap_or(0)) + i64::from(hemi.unwrap_or(0));
    (1..floor).contains(&(ac - present))
}

/// Whether a row exposes a below-floor genotype cell — see [`genotype_cell_in_danger`].
/// This is the trigger for the cross-partition sub-count coherence step in
/// [`frequencies_for`]: the sub-counts are sex/country marginals of `Total` exactly as `AC`
/// is, so a withheld below-floor sub-count in one population is otherwise recoverable by
/// subtracting the surviving siblings from `Total` (e.g. `F.Hom = Total.Hom - M.Hom`).
fn subcount_in_danger(row: &AlleleRow, floor: i64) -> bool {
    genotype_cell_in_danger(
        alt_carriers(row),
        row.ac_hom,
        row.ac_het,
        row.ac_hemi,
        floor,
    )
}

/// A `(POS, REF, ALT)` group of [`AlleleRow`]s for one dataset.
///
/// Public because [`DatasetPage`] hands completed groups to the assembly path: the scan
/// decides grouping, suppression and paging, so what crosses that boundary is groups rather
/// than loose rows. The fields stay crate-private, because a consumer renders a group and
/// does not construct one.
#[derive(Debug)]
pub struct VariantGroup {
    pos: i32,
    ref_: String,
    alt: String,
    vt: Vt,
    rows: Vec<AlleleRow>,
}

/// The alt-allele carrier count `AC` for the low-tail check, or `None` when it cannot be
/// established.
///
/// Thin adapter over [`gdi_node_standalone_core::kanon::alt_carriers`], which owns the rule
/// so the build-time floor in `core::convert` applies the identical derivation. This exists
/// only to keep the `&AlleleRow` call shape at the serve-time sites.
fn alt_carriers(row: &AlleleRow) -> Option<i64> {
    gdi_node_standalone_core::kanon::alt_carriers(row.ac, row.an, row.af)
}

/// The reference-allele carrier count `refc = AN - AC` for the complement-tail check, or
/// `None` when it cannot be established.
///
/// Thin adapter over [`gdi_node_standalone_core::kanon::reference_carriers`] — see
/// [`alt_carriers`].
fn reference_carriers(row: &AlleleRow) -> Option<i64> {
    gdi_node_standalone_core::kanon::reference_carriers(row.ac, row.an, row.af)
}

/// Whether a group row is emitted, applying the `min_allele_count` floor as a
/// *symmetric, non-empty* k-anonymity threshold.
///
/// With `floor == 0` (the default) every row survives. Otherwise a row is
/// withheld when it would expose a **non-empty** group smaller than the floor on
/// either tail:
///
/// * **low tail** — a rare *alt*-carrier group: `1 <= AC < floor`. `AC` is taken
///   from [`alt_carriers`], so a row that omits the `AC` field but still ships
///   `AF`+`AN` is checked against its client-derivable `AC = round(AF*AN)` and is
///   not exempt.
/// * **complement tail** — a rare *reference*-carrier group `refc = AN - AC`:
///   `1 <= refc < floor`. `AF` is always on the wire and equals `AC/AN`, so
///   `refc` is client-derivable even when the `AN` field is withheld; the check
///   therefore reconstructs `AN` from `AC/AF` when needed (see
///   [`reference_carriers`]).
///
/// Empty groups (`AC == 0`, or `refc == 0` for a fully-fixed variant) are never
/// re-identifiable and always survive. An uncountable row, meaning `AF > 0` so the variant
/// is present but neither `AC` nor `AN` is there to derive a carrier count from, fails
/// closed under a floor and is suppressed: the floor cannot prove the group is
/// non-identifying, and `exists:true` would otherwise confirm a possible singleton. The rule
/// is defined once here and applied by both [`group_survives`] (the count pass) and
/// [`frequencies_for`] (materialization), so `resultsCount` cannot drift from the emitted
/// `results[]`.
fn row_survives(row: &AlleleRow, floor: i64) -> bool {
    use gdi_node_standalone_core::kanon::RowVerdict;
    match gdi_node_standalone_core::kanon::classify_row(row.ac, row.an, row.af, floor) {
        RowVerdict::Serve => true,
        // Both withheld here for different reasons, merged only because the answer this
        // caller gives happens to coincide.
        //
        // `Suppress` is a proven below-floor group. `Uncountable` is a group that cannot be
        // proven to be at or above the floor, so a boolean/exists query would otherwise
        // confirm a possible below-floor singleton. Serve time can afford to fail closed
        // because it is reversible: the operator lowers the floor and the data is still in
        // the store. The build-time caller maps `Uncountable` the other way for that reason,
        // and the two mappings change independently. See `RowVerdict::Uncountable`.
        RowVerdict::Suppress | RowVerdict::Uncountable => false,
    }
}

/// Sanitize a served allele frequency.
///
/// Ingest already rejects a non-finite or out-of-`[0,1]` `AF` (see `validate_parquet`), so
/// this bites only an out-of-band parquet. `serde_json` renders a non-finite `f32` as JSON
/// `null`, which violates the required `alleleFrequency` number and breaks the whole
/// response for a strict consumer. Clamping to `[0, 1]` is a no-op for a valid in-range
/// value, so the shortest round-trip is preserved. `f32::clamp` returns `NaN` for `NaN`, so
/// that case maps to `0.0`; `±∞` clamp to the bounds. Like the serve-time re-application of
/// the `min_allele_count` floor, a value that must never leave the node is re-checked at
/// emit rather than trusted from ingest.
fn finite_af(af: f32) -> f32 {
    if af.is_nan() { 0.0 } else { af.clamp(0.0, 1.0) }
}

/// Which of a group's population rows are emitted after the `min_allele_count` floor,
/// including the k-anonymity cross-partition coherence step.
///
/// [`row_survives`] is a per-population threshold: applied alone it drops each below-floor
/// cell independently. That is insufficient, because the node emits redundant marginals, a
/// `Total` plus a per-sex, per-country and country×sex breakdown that sum to it, so a
/// suppressed `[1, floor)` cell is recoverable by subtraction from the surviving siblings
/// and the `Total` (`F = Total - M`). This step closes that: if the floor suppresses any
/// population in the group, only the aggregate `Total` is emitted, and no surviving sibling
/// remains to subtract against.
///
/// The same collapse fires when nothing is suppressed here but the surviving set is an
/// incomplete partition: an axis whose present members' exact `AC` leaves a remainder
/// `Total - Σ ∈ 1..floor`, meaning a below-floor sibling was withheld before the data
/// reached this node. That extends the same defence to datasets built without the
/// build-time collapse (see [`marginal_set_incomplete`]).
///
/// It mirrors [`gate_subcounts`], which withholds Hom/Het/Hemi as a set rather than one
/// cell, for the same reason: a withheld value must not be recoverable from the survivors.
/// The rule is blunt. It favours privacy over sub-group utility and does not compute the
/// NP-hard minimal complementary-cell suppression. A group with a suppressed cell but no
/// `Total` row is dropped entirely, because a finer partition (country×sex summing to a
/// surviving sex total) could otherwise reconstruct the suppressed cell, so no non-`Total`
/// survivor is safe to serve alone. The residual multi-variant differencing attack over a
/// linear system is out of scope; differential privacy is the complete defence.
/// `floor <= 0` (the default) passes every row through.
///
/// Defined once here and used by both the count pass ([`group_survives`]) and
/// materialization ([`frequencies_for`]), so `resultsCount` can never drift from the emitted
/// `results[]`.
fn emittable_rows(group: &VariantGroup, floor: i64) -> Vec<&AlleleRow> {
    if floor <= 0 {
        return group.rows.iter().collect();
    }
    let mut survived: Vec<&AlleleRow> = Vec::with_capacity(group.rows.len());
    let mut suppressed_any = false;
    for row in &group.rows {
        if row_survives(row, floor) {
            survived.push(row);
        } else {
            suppressed_any = true;
        }
    }
    if suppressed_any {
        // A below-floor cell was withheld: keep only the aggregate so no surviving
        // sibling can reconstruct it by subtraction. Empties the group when there is no
        // `Total` (see the doc note).
        survived.retain(|row| row.population == TOTAL_POPULATION);
    } else if marginal_set_incomplete(&survived, floor) {
        // Defence in depth: even with nothing suppressed here, a partition axis whose
        // present members leave a below-floor remainder means a sibling was withheld before
        // the data reached this node. `Total - sum(present)` would then recover a
        // below-floor cell, so collapse to `Total` only, as a suppression does.
        survived.retain(|row| row.population == TOTAL_POPULATION);
    }
    survived
}

/// Whether the surviving marginals form an incomplete partition whose missing part is
/// re-identifying: a partition axis (per-sex, per-country, or country×sex) whose present
/// members' carrier counts leave a remainder `Total - sum` in `1..floor`. That remainder is
/// a below-floor cell withheld before the data reached this node, which `Total -
/// sum(present)` recovers, so the caller collapses to `Total` only.
///
/// Counts rows with [`alt_carriers`], the exact `AC` when present and the client's own
/// `round(AF * AN)` otherwise, never the `AC` column alone. This gate stops a client
/// subtracting a withheld sibling out of the marginals, and that subtraction does not need
/// the column: [`row_survives`] treats an `AF` + `AN` row as countable by this same
/// derivation. Anchoring on the column would let a sibling shipping `AF` + `AN` but no `AC`
/// disable the gate for its whole axis while leaving the client's arithmetic intact.
///
/// A survivor whose `AF` is `0` is an empty alt group and contributes `0`. A survivor with
/// `AF > 0` and no derivable count cannot reach here: [`row_survives`] suppresses it as
/// uncountable, which sets `suppressed_any`, and the caller collapses before consulting
/// this function.
///
/// An axis with no members, or whose remainder is `0` (complete) or `>= floor` (a
/// k-anon-safe unreported aggregate), is not flagged, so a legitimately partial breakdown is
/// not over-collapsed. `round(AF * AN)` costs no utility here: where `AF` was written as
/// `f32(AC / AN)`, the derivation recovers `AC` exactly for every `AN` up to `2^24`
/// (`16_777_216`, an `f32` mantissa's worth, pinned by `alt_carriers_recovers_ac_exactly`),
/// so a complete `AF`-only axis leaves remainder `0` and is emitted in full, as an
/// `AC`-bearing one is.
///
/// A remainder below `0`, an axis summing above `Total`, therefore does not mean rounding.
/// It means the marginals are incoherent, which honest data cannot be. Such an axis is not
/// flagged, and that is safe: a client subtracting the same emitted numbers gets the same
/// nonsense, and because this is an `any()` across axes, one incoherent axis cannot mask an
/// honest one that would flag. Incoherent marginals are refused at the ingest gate, beside
/// `AC <= AN` and the genotype sub-count partition, not here, where the data has already
/// been accepted.
fn marginal_set_incomplete(survived: &[&AlleleRow], floor: i64) -> bool {
    // Both tails, because `row_survives` suppresses on both: a rare non-carrier is as
    // re-identifying as a rare carrier, so an axis may be complete on the alt plane while
    // its complement remainder still recovers a below-floor group.
    axis_remainder_reidentifying(survived, floor, alt_carriers)
        || axis_remainder_reidentifying(survived, floor, reference_carriers)
}

/// Whether the present members of any partition axis leave a re-identifying remainder
/// against `Total`, for the single plane of counts selected by `value`.
///
/// This is the single source of the incomplete-partition rule, applied to the `AC` plane by
/// [`marginal_set_incomplete`] and to each genotype sub-count plane by
/// [`subcount_partition_incomplete`]. Both are marginals of the same `Total`, so both are
/// recoverable by the same subtraction, and a rule stated for only one of them leaves the
/// other open. Keep the planes sharing this function rather than restating the arithmetic
/// per plane, so neither can drift from the other.
///
/// A row whose value is absent contributes `0`, which is what makes the remainder visible:
/// an absent sibling is precisely the withheld cell a client recovers by subtraction.
fn axis_remainder_reidentifying(
    survived: &[&AlleleRow],
    floor: i64,
    value: impl Fn(&AlleleRow) -> Option<i64>,
) -> bool {
    // (1) Anchored: each axis (Sex, Country, CountrySex) partitions the same cohort, so an
    //     axis whose present members leave a `1..floor` remainder against a known cohort
    //     total recovers a withheld sibling.
    //
    //     The anchor is derived rather than looked up. Anchoring solely on the served
    //     `Total` row short-circuits the whole rule whenever `Total` carries no value for
    //     this plane, and nothing requires a `Total` row to carry sub-counts when its
    //     children do: `core::subcounts` is strictly per-row, `check_hierarchy` reads only
    //     AC/AN, and `convert` reads each population's sub-count fields independently. A
    //     complete axis is itself the cohort total, so every present axis's sum is also an
    //     anchor. With `Total.Hom` null, Sex summing to 100 and Country to 98, the withheld
    //     `EE_Hom = 2` is recoverable by subtraction, and only a cross-axis comparison sees
    //     it.
    let mut sum = [0i64; PopulationAxis::COUNT];
    let mut present = [false; PopulationAxis::COUNT];
    for row in survived {
        if let Some(axis) = population_axis(&row.population) {
            let axis = axis.index();
            present[axis] = true;
            sum[axis] = sum[axis].saturating_add(value(row).unwrap_or(0));
        }
    }
    // `saturating_sub` for the same reason the accumulation above saturates:
    // `reference_carriers` is documented to saturate to `i64::MAX` for a pathologically tiny
    // AF with AN absent, and this workspace leaves `overflow-checks` off in release, so a
    // plain `-` would panic in dev and test builds and wrap in release, deciding a k-anon
    // collapse on a wrapped value.
    let leaves_remainder = |anchor: i64| {
        (0..PopulationAxis::COUNT)
            .any(|a| present[a] && (1..floor).contains(&anchor.saturating_sub(sum[a])))
    };
    let total_anchored = survived
        .iter()
        .find(|r| r.population == TOTAL_POPULATION)
        .and_then(|r| value(r))
        .is_some_and(&leaves_remainder)
        || (0..PopulationAxis::COUNT).any(|b| present[b] && leaves_remainder(sum[b]));
    // (2) Nested: a `CountrySex` cell partitions not only `Total` but its parent Sex and
    //     Country marginals too, so `FI_M = M - sum(present *_M)` (or `FI - sum(present FI_*)`)
    //     recovers a withheld cell the Total anchor never sees. Checked unconditionally (it
    //     needs no `Total`).
    total_anchored || nested_remainder_reidentifying(survived, floor, &value)
}

/// The nested companion to [`axis_remainder_reidentifying`]'s Total anchor. A `CountrySex`
/// cell (`CC_S`) partitions not only [`TOTAL_POPULATION`] but also its parent Sex marginal
/// `S` and parent Country marginal `CC`, so a withheld `FI_M` is recovered by `M -
/// sum(present *_M)` or by `FI - sum(present FI_*)`. The Total anchor cannot see that
/// subtraction, because the `CountrySex`-against-`Total` remainder can be safely large while
/// a per-parent remainder is re-identifying. `EE_M = M - FI_M` is the differencing this
/// closes.
///
/// Anchor each present, derivable Sex or Country marginal against the sum of its present
/// `CountrySex` children, flagging the same `1..floor` remainder
/// [`axis_remainder_reidentifying`] uses, so the two rules cannot drift. A parent that is
/// absent or underivable is no anchor, because a client cannot subtract from a number it
/// never received. A child with no derivable value on this plane contributes `0`, as an
/// absent sibling does, which is what makes the withheld mass visible. Sex tokens are one
/// byte and country codes two, so a child's suffix (`M`) and prefix (`FI`) key onto the same
/// label namespace as their parent marginals without collision.
fn nested_remainder_reidentifying<F: Fn(&AlleleRow) -> Option<i64>>(
    survived: &[&AlleleRow],
    floor: i64,
    value: &F,
) -> bool {
    // Cheap exit for the common unstratified / sex-or-country-only shape: no `CountrySex` cell
    // means no nesting to check, and no allocation on the serving hot path.
    if !survived
        .iter()
        .any(|r| population_axis(&r.population) == Some(PopulationAxis::CountrySex))
    {
        return false;
    }
    // Parent label -> its present, derivable marginal value (the client's subtraction anchor).
    let mut parent: BTreeMap<&str, i64> = BTreeMap::new();
    // Parent label -> sum of its present `CountrySex` children's values (0 for an underivable
    // child; a key present here means "at least one child seen for this parent").
    let mut child_sum: BTreeMap<&str, i64> = BTreeMap::new();
    for row in survived {
        match population_axis(&row.population) {
            Some(PopulationAxis::Sex | PopulationAxis::Country) => {
                if let Some(v) = value(row) {
                    parent.insert(row.population.as_str(), v);
                }
            }
            Some(PopulationAxis::CountrySex) => {
                if let Some((cc, sx)) = row.population.split_once('_') {
                    let v = value(row).unwrap_or(0);
                    // `saturating_add`, matching the Total anchor's accumulation above. The
                    // values summed here are the ones the crate documents as saturating to
                    // `i64::MAX`, so a plain `+=` is the one arithmetic in this gate that
                    // could wrap. A wrapped `child_sum` lands `m - s` inside the `1..floor`
                    // window from the wrong side, flipping a withheld cell to not
                    // re-identifying and failing the gate open. Saturating keeps the
                    // remainder large, which fails closed.
                    let sx_sum = child_sum.entry(sx).or_insert(0);
                    *sx_sum = sx_sum.saturating_add(v);
                    let cc_sum = child_sum.entry(cc).or_insert(0);
                    *cc_sum = cc_sum.saturating_add(v);
                }
            }
            None => {}
        }
    }
    parent.iter().any(|(label, &m)| {
        child_sum
            .get(label)
            .is_some_and(|&s| (1..floor).contains(&m.saturating_sub(s)))
    })
}

/// Whether any genotype sub-count plane leaves a re-identifying remainder on some axis.
///
/// The companion to [`subcount_in_danger`], covering the case that predicate cannot see: it
/// fires only on a present value in `1..floor`, so a sibling whose sub-count is absent reads
/// as safe while `Total.Hom - sum(present siblings)` still recovers it. This is the
/// sub-count analogue of [`marginal_set_incomplete`], sharing its arithmetic.
fn subcount_partition_incomplete(survived: &[&AlleleRow], floor: i64) -> bool {
    axis_remainder_reidentifying(survived, floor, |r| r.ac_hom.map(i64::from))
        || axis_remainder_reidentifying(survived, floor, |r| r.ac_het.map(i64::from))
        || axis_remainder_reidentifying(survived, floor, |r| r.ac_hemi.map(i64::from))
}

/// Whether the group yields any emitted population after the floor and the k-anonymity
/// collapse, meaning whether [`frequencies_for`] would return `Some`. Used for the
/// `resultsCount` pass, so a group outside the requested `(skip, limit)` page window is
/// counted without allocating and sorting a `Vec<Frequency>` that would be discarded.
/// Delegates to [`emittable_rows`] so the count can never disagree with materialization.
fn group_survives(group: &VariantGroup, floor: u32) -> bool {
    !emittable_rows(group, i64::from(floor)).is_empty()
}

/// Build the per-population [`Frequency`] list for a group, applying the
/// `min_allele_count` floor.
///
/// A population is dropped when its alt-carrier count — the exact `AC`, or the
/// client-derivable `round(AF*AN)` when the `AC` field is absent — is a non-empty
/// group below `floor` (when `floor > 0`), on either the low or complement tail
/// (see [`row_survives`]/[`alt_carriers`]). A population with `AC == None` and no
/// derivable count (no `AN`) is kept only when `AF == 0` (empty group) or the floor is off:
/// an `AF > 0` uncountable row fails closed under a floor. If the floor suppresses any
/// population the group collapses to `Total` only, the k-anonymity cross-partition coherence
/// step in [`emittable_rows`]. Returns `None` when nothing survives, and the caller then
/// drops the whole variant group rather than emit an empty `frequencies[]` (schema
/// `minItems: 1`).
///
/// Genotype sub-counts (`AC_Hom`/`AC_Het`/`AC_Hemi`) are suppressed coherently on two axes.
/// Within a row (see [`gate_subcounts`]): if any one is a non-empty group below the floor,
/// all three are withheld, so none is recoverable from `AC` and the other two. Across the
/// group ([`subcount_in_danger`]): if any emitted population's sub-count is below the floor,
/// the sub-counts of every non-`Total` row are withheld, so a suppressed cell cannot be
/// reconstructed as `Total` minus the surviving siblings (`F.Hom = Total.Hom - M.Hom`). That
/// is the sub-count analogue of the AC-plane collapse in [`emittable_rows`]. `AC`, `AN` and
/// `AF` still serve the frequency in every case.
fn frequencies_for(group: &VariantGroup, floor: u32) -> Option<Vec<Frequency>> {
    let floor = i64::from(floor);
    let rows = emittable_rows(group, floor);
    if rows.is_empty() {
        return None;
    }
    // Cross-partition coherence for genotype sub-counts. `gate_subcounts` alone
    // withholds a below-floor Hom/Het/Hemi only within its own row, but the sub-counts
    // are sex/country marginals of `Total` just as `AC` is, so a withheld cell is
    // recoverable from `Total` minus the surviving siblings (`F.Hom = Total.Hom - M.Hom`).
    // If any emitted population exposes a below-floor sub-count, withhold the sub-counts of
    // every non-`Total` row so no sibling remains to subtract against. `Total`'s own
    // sub-counts stay, still subject to the per-row `gate_subcounts`, because a lone
    // aggregate has nothing to difference against. Mirrors the `emittable_rows` AC-plane
    // collapse, one level down.
    let subcount_collapse = rows.iter().any(|row| subcount_in_danger(row, floor))
        || subcount_partition_incomplete(&rows, floor);
    let mut out: Vec<Frequency> = Vec::with_capacity(rows.len());
    for row in rows {
        let (hom, het, hemi) = if subcount_collapse && row.population != TOTAL_POPULATION {
            (None, None, None)
        } else {
            gate_subcounts(
                alt_carriers(row),
                row.ac_hom,
                row.ac_het,
                row.ac_hemi,
                floor,
            )
        };
        out.push(Frequency {
            population: row.population.clone(),
            // `row.af` is already `f32` (the VCF/BCF native width); emit it directly
            // so the wire carries the shortest round-tripping decimal, not the noise
            // tail a `f32 -> f64` widening would add. `finite_af` is a no-op for a valid
            // in-range AF and only rewrites a non-finite / out-of-range out-of-band value
            // so it never serializes as JSON `null` for the required field.
            allele_frequency: finite_af(row.af),
            allele_count: count_u64(row.ac),
            allele_number: count_u64(row.an),
            allele_count_homozygous: hom,
            allele_count_heterozygous: het,
            allele_count_hemizygous: hemi,
        });
    }
    // Sort by population key for a deterministic wire order (the parquet scan does
    // not guarantee a stable population order across files/row groups). `out` is
    // non-empty here: `emittable_rows` returned at least one row.
    out.sort_by(|a, b| a.population.cmp(&b.population));
    Some(out)
}

/// Render the public HGVS id for a group, or `None` when the accession is unknown.
///
/// `POS` is 0-based, so `start = POS + 1` is the 1-based coordinate of `REF[0]`. The form
/// mirrors the GDI production loader `beacon2-ri-tools-v2` (its `genomicVariations_vcf.py`
/// HGVS builder) so a federated `genomicHGVSId` is consistent across GDI nodes. Multi-base
/// deletions therefore use a range, and an insertion strips the anchor base:
///
/// * **SNV** (`len(REF) == len(ALT) == 1`) → `{acc}:g.{start}{REF}>{ALT}`.
/// * **Deletion** (`len(REF) > len(ALT)`):
///   * suffix-anchored (`REF` ends with `ALT[0]`) → `{acc}:g.{start}_{start+len(REF)-2}del`;
///   * single-base (`len(REF) - len(ALT) == 1`, not suffix-anchored) → `{acc}:g.{start+1}del`;
///   * multi-base (otherwise) → `{acc}:g.{start}_{start+len(REF)-1}delins{ALT}`.
/// * **Insertion** (`len(ALT) > len(REF)`):
///   * multi-base `REF` → `{acc}:g.{start}_{start+len(REF)-1}delins{ALT}`;
///   * prefix-anchored (`REF[0] == ALT[0]`) → `{acc}:g.{start}_{start+1}ins{ALT[1..]}`;
///   * otherwise → `{acc}:g.{start}delins{ALT}`.
/// * **MNV** (equal-length multi-base) → `{acc}:g.{start}{REF}>{ALT}`.
///
/// The `inv` and `dup` shorthands the loader also derives are not reproduced: its `inv`
/// branch is unreachable (`reversed(ref) == alt` can never hold in Python), and its `dup`
/// detection is a fragile heuristic. Those cases fall through to the equivalent `delins` or
/// `ins` form.
///
/// # Standards note
///
/// This is faithful to the GDI production reference rather than to strict HGVS
/// nomenclature. `genomicHGVSId` feeds the cross-node `variantInternalId` hash and is
/// queried verbatim by `beacon2-pi-api`, so federated consistency with that implementation's
/// exact output is chosen over canonical HGVS. The known deviations from HGVS: no
/// 3′-shifting or repeat-normalization, where HGVS mandates the most-3′ position; an
/// equal-length multi-base substitution (MNV) renders `…{REF}>{ALT}`, where HGVS requires
/// `delins`; a multi-base left-anchored deletion renders `delins` rather than the minimal
/// `del`. Consumers must treat the value as an opaque, instance-stable id, not a parseable
/// canonical HGVS expression. Adopting true HGVS or VRS normalization would be a coordinated
/// GDI-network change rather than a unilateral one here.
#[expect(
    clippy::string_slice,
    reason = "ALT is validated ACGTN (ASCII) at ingest, so byte 1 is a char boundary"
)]
fn genomic_hgvs_id(accession: &str, pos: i32, ref_: &str, alt: &str) -> String {
    let start = i64::from(pos) + 1; // 1-based position of REF[0]
    let rl = len_i64(ref_);
    let al = len_i64(alt);
    let prefix = format!("{accession}:g.");
    let ref_first = ref_.as_bytes().first().copied();
    let ref_last = ref_.as_bytes().last().copied();
    let alt_first = alt.as_bytes().first().copied();

    if rl == 1 && al == 1 {
        // SNV substitution.
        format!("{prefix}{start}{ref_}>{alt}")
    } else if rl > al {
        // Deletion (REF longer than ALT).
        if ref_last == alt_first {
            // Suffix-anchored: a range over the deleted prefix before the shared base.
            format!("{prefix}{start}_{}del", start + rl - 2)
        } else if rl - al > 1 {
            // Multi-base, not suffix-anchored: a delins over the whole REF span.
            format!("{prefix}{start}_{}delins{alt}", start + rl - 1)
        } else {
            // Single-base deletion: the one base after the anchor.
            format!("{prefix}{}del", start + 1)
        }
    } else if al > rl {
        // Insertion (ALT longer than REF).
        if rl > 1 {
            // Multi-base REF: a delins over the whole REF span.
            format!("{prefix}{start}_{}delins{alt}", start + rl - 1)
        } else if ref_first == alt_first {
            // Prefix-anchored: insert ALT minus the anchor between start and start+1.
            format!("{prefix}{start}_{}ins{}", start + 1, &alt[1..])
        } else {
            // Unanchored: a delins of the whole ALT at the single REF base.
            format!("{prefix}{start}delins{alt}")
        }
    } else {
        // Equal-length multi-nucleotide substitution (MNV): a span substitution.
        format!("{prefix}{start}{ref_}>{alt}")
    }
}

/// Lowercase hex of `sha256(dataset_id || suffix)` — the opaque,
/// beacon-instance-local `variantInternalId`.
///
/// `suffix` is the group's `genomicHGVSId`, which every served group has: the accession is
/// resolved once per dataset in [`assemble_dataset`], which serves the dataset as a miss if
/// it cannot be. The id is therefore deterministic and collision-free within the node.
fn variant_internal_id(dataset_id: &str, suffix: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(dataset_id.as_bytes());
    hasher.update(suffix.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        // Writing to a String never fails.
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// The effective `min_allele_count` floor a dataset's answers are served under:
/// `max(node [beacon].min_allele_count, the dataset's declared config floor)`.
///
/// The single source for the served floor. The suppression in `assemble_dataset`, the
/// `gdiDatasetInfo` disclosure on each `g_variants` resultSet, and the `/datasets`
/// `collection_for` disclosure all read it, so the floor applied and the floor disclosed on
/// either endpoint can never drift.
///
/// Public so the aggregate (`boolean`/`count`) scan path applies the same floor as the
/// record path: a suppressed cell must be suppressed identically at every granularity.
#[must_use]
pub fn effective_floor(cfg: &ManifestConfig, beacon_cfg: &BeaconParams) -> u32 {
    beacon_cfg.min_allele_count.max(cfg.min_allele_count)
}

/// The per-dataset inputs [`assemble`] feeds one at a time to `assemble_dataset`:
/// `(dataset_id, manifest config, served populations, chromosome, scanned rows)`.
/// Factored into a named type so the pub `assemble` signature and the service handler
/// stay legible (and to satisfy clippy's `type_complexity` / `too_many_arguments`).
pub type DatasetScan<'a> = (
    String,
    &'a ManifestConfig,
    Option<&'a [String]>,
    &'a str,
    DatasetPage,
);

/// The single `ResultSet` construction `assemble_dataset` returns, from either of its
/// exits: the assembled answer (`surviving` groups with the page in `results`) and the
/// fail-closed miss (`0`, empty `results`).
///
/// A dataset with zero surviving groups is a per-dataset miss (`exists:false`, empty
/// `results[]`) rather than an omission: it names a dataset that was consulted, so an
/// `ALL` or `MISS` query can account for a `0`. A dataset with survivors but an empty page
/// slice keeps the true count with an empty `results[]`. The `includeResultsetResponses`
/// filter decides which of these reach the wire.
///
/// One construction rather than two, so the fail-closed miss cannot drift from the
/// zero-survivors miss: `exists` is derived from `surviving` at a single site, and the
/// `gdiDatasetInfo` disclosure is built identically on both paths.
fn dataset_result_set(
    dataset_id: String,
    cfg: &ManifestConfig,
    populations: Option<&[String]>,
    beacon_cfg: &BeaconParams,
    floor: u32,
    surviving: u64,
    results: Vec<ResultEntry>,
) -> ResultSet {
    ResultSet {
        beacon_id: beacon_cfg.id.clone(),
        id: dataset_id,
        set_type: "dataset".to_owned(),
        exists: surviving > 0,
        results_count: surviving,
        results,
        // Disclose the floor the caller applied, so a client can bound a `0`. Built from
        // the same `floor` the suppression used, so the disclosure can never understate the
        // suppression it reports.
        gdi_dataset_info: GdiDatasetInfo {
            assembly: cfg.assembly.reference.clone(),
            populations: populations.map(<[String]>::to_vec),
            min_allele_count: floor,
        },
    }
}

fn assemble_dataset(scan: DatasetScan<'_>, beacon_cfg: &BeaconParams, base_url: &str) -> ResultSet {
    let (dataset_id, cfg, populations, chr, page) = scan;
    // The floor is derived from config here, not read back from the page. `page.floor`
    // records what the scan applied, which decided survival, `total` and the ordinals, but
    // suppression at assembly must not depend on a value a caller could have built the page
    // with: `DatasetPage::from_rows(rows, PageSpec::everything())` carries floor 0, and a
    // `debug_assert_eq!` on the two is compiled out of the release binary. Every production
    // scan calls `effective_floor` too, so the applied floor and the `gdiDatasetInfo`
    // disclosure below cannot drift from each other.
    let floor = effective_floor(cfg, beacon_cfg);
    let source = cfg
        .af_source
        .clone()
        .unwrap_or_else(|| beacon_cfg.name.clone());
    let source_reference = cfg
        .af_source_reference
        .clone()
        .unwrap_or_else(|| base_url.to_owned());
    // Total on every reachable input: ingest admits only GRCh37 and GRCh38 and only the 25
    // canonical contigs (`chrom::normalize_contig`), and a dataset is scanned only for the
    // known assembly the request selected. A `None` here means the store disagrees with its
    // manifest. Fail closed for this dataset alone: serve it as a miss and log at `error`,
    // never a location without its reference sequence and never a fabricated CURIE.
    let Some(accession) = accession_for(chr, &cfg.assembly.reference) else {
        tracing::error!(
            dataset = %dataset_id,
            chr,
            assembly = %cfg.assembly.reference,
            "no reference accession for a stored dataset's assembly/contig: the store \
             disagrees with its manifest; serving the dataset as a miss"
        );
        return dataset_result_set(
            dataset_id,
            cfg,
            populations,
            beacon_cfg,
            floor,
            0,
            Vec::new(),
        );
    };

    // Survival, grouping and paging all happened in the scan, which keeps retained memory
    // proportional to the page rather than to the match set. What is left here is
    // rendering: the HGVS text, the `variantInternalId` SHA-256, the frequency list, and
    // that work is done only for groups in the `(skip, limit)` window.
    //
    // Suppression at assembly covers the count too. `page.total` was computed under the
    // scan's floor, and a page built under a lower one (`PageSpec::everything()`, floor 0)
    // holds nothing about its out-of-window groups, so its total can be bounded but not
    // corrected. When the scan's floor is at least the configured one the total stands.
    // Otherwise `resultsCount` and `exists` come from the in-window survivors under the
    // configured floor, a lower bound. Re-suppressing `results[]` alone would answer
    // `exists: true, resultsCount: 1, results: []` for a below-floor page, disclosing the
    // existence the floor is there to withhold. Every production scan passes
    // `effective_floor` to both, so in the node this branch is never the lower bound.
    let trusted_total = page.floor >= floor;
    let mut in_window_survivors: u64 = 0;
    let mut paged: Vec<ResultEntry> = Vec::with_capacity(page.groups.len());
    for group in page.groups {
        // `PageSink` kept only the groups that survived the scan's floor; under the
        // configured floor this may still be `None`.
        let Some(frequencies) = frequencies_for(&group, floor) else {
            continue;
        };
        in_window_survivors += 1;

        let sequence_id = format!("refseq:{accession}");
        let hgvs = genomic_hgvs_id(accession, group.pos, &group.ref_, &group.alt);
        // The `variantInternalId` hashes the HGVS text. There is no
        // `{chr}:{pos}:{ref}:{alt}` fallback, because the accession is always resolved
        // above.
        let hash_suffix = hgvs.clone();
        let identifiers = Identifiers {
            genomic_hgvs_id: hgvs,
        };

        paged.push(ResultEntry {
            variant_internal_id: variant_internal_id(&dataset_id, &hash_suffix),
            variation: Variation {
                location: SequenceLocation::new(
                    sequence_id,
                    SequenceInterval::new(
                        i64::from(group.pos),
                        i64::from(group.pos) + len_i64(&group.ref_),
                    ),
                ),
                reference_bases: group.ref_,
                alternate_bases: group.alt,
                variant_type: group.vt.as_str().to_owned(),
            },
            identifiers,
            frequency_in_populations: vec![FrequencyInPopulations {
                source: source.clone(),
                source_reference: source_reference.clone(),
                frequencies,
            }],
        });
    }

    let surviving = if trusted_total {
        page.total
    } else {
        in_window_survivors
    };
    dataset_result_set(
        dataset_id,
        cfg,
        populations,
        beacon_cfg,
        floor,
        surviving,
        paged,
    )
}

/// Assemble scanned rows into a Beacon v2 [`BeaconResponse`].
///
/// Each [`DatasetScan`] tuple becomes one [`ResultSet`]: the scan's `(POS, REF, ALT)`
/// groups each yield one `frequencyInPopulations` entry. The `min_allele_count` floor is
/// `max(beacon_cfg.min_allele_count, cfg.min_allele_count)`; a population whose `AC`
/// is below the floor is dropped (a population with no `AC` field is not exempt: it is
/// checked against its client-derivable `round(AF*AN)`, and an uncountable `AF>0` row with
/// no `AC`/`AN` fails closed — see the `row_survives` helper), and if any
/// population is suppressed the group collapses to the aggregate `Total` only (k-anonymity
/// cross-partition coherence, via the `emittable_rows` helper). A group with no surviving
/// population is omitted (never an empty `frequencies[]`). `source`/`sourceReference`
/// fall back to `beacon_cfg.name` / `base_url` when the manifest leaves them unset.
///
/// `resultsCount` is the true number of surviving groups per dataset, unaffected by
/// paging, and `results[]` carries the page the scan already selected. Assembly does not
/// slice: [`scan_dataset_page`] applied the window while folding, so the rows outside it
/// were never retained. `pagination` is taken here only to echo back into
/// `meta.receivedRequestSummary`, so changing it without re-scanning changes the echo and
/// nothing else. Datasets with zero surviving groups become `exists:false` misses, still
/// emitted so an `ALL` or `MISS` query can account for them; the
/// `includeResultsetResponses` filter drops them for a `Hit` query. The `meta` and
/// `responseSummary` blocks are populated per the schema (`returnedSchemas`,
/// `receivedRequestSummary`, `exists`, `numTotalResults`).
///
/// `requested_granularity` is the case-folded value the request carried
/// (`boolean` | `count` | `record`, defaulted from `[beacon.configuration]` when omitted),
/// echoed verbatim into `meta.receivedRequestSummary`. The aggregated path always serves
/// record-level detail, so `returnedGranularity` stays `"record"`; the spec permits serving
/// only record.
#[must_use]
pub fn assemble(
    datasets: Vec<DatasetScan<'_>>,
    pagination: &Pagination,
    beacon_cfg: &BeaconParams,
    base_url: &str,
    requested_granularity: &str,
) -> BeaconResponse {
    let mut result_sets: Vec<ResultSet> = Vec::new();
    // Owned `Vec` consumed by value: each dataset's row vector moves into
    // `assemble_dataset` exactly once, with no per-dataset clone on the response path.
    for scan in datasets {
        // Every considered dataset becomes a resultSet: a hit (`exists:true`) or a
        // per-dataset miss (`exists:false`, empty). Emitting the miss rather than dropping
        // it is what lets an `ALL` or `MISS` query account for a `0`, because the miss
        // names the dataset that was consulted. `apply_include_resultset_responses` later
        // drops the misses for a `HIT` query, so the default wire is unchanged.
        result_sets.push(assemble_dataset(scan, beacon_cfg, base_url));
    }

    // `exists` and `numTotalResults` are the true aggregate over every considered dataset,
    // independent of the `includeResultsetResponses` view filter: a miss contributes
    // `false` and `0`, so neither the `any` hit nor the count sum changes when misses are
    // materialized.
    let exists = result_sets.iter().any(|rs| rs.exists);
    let num_total_results = Some(result_sets.iter().map(|rs| rs.results_count).sum::<u64>());

    let schema = Schema {
        entry_type: "genomicVariant".to_owned(),
        schema: genomic_variant_schema_url(&beacon_cfg.api_version),
    };
    // The aggregated path always serves record-level detail, and the spec permits serving
    // only record, so `returnedGranularity` stays "record", fixed inside `response_meta`.
    // The request's granularity is echoed in `receivedRequestSummary`.
    let meta = response_meta(beacon_cfg, vec![schema], requested_granularity, *pagination);

    BeaconResponse {
        meta,
        response_summary: ResponseSummary {
            exists,
            num_total_results,
        },
        response: Some(ResultSetsBody { result_sets }),
    }
}

/// Build the `boolean`/`count` response from folded per-dataset totals, without ever
/// materialising rows or resultSets.
///
/// Safe because [`shape_for_granularity`] sets `response.response = None` for both of those
/// granularities. The per-dataset resultSets body never reaches the wire, so the only
/// observable outputs are `responseSummary.exists` and, for `count`, `numTotalResults`,
/// which is what [`scan_dataset_counts`] returns. `meta` is built by the same
/// `response_meta` call [`assemble`] uses, so the envelope is identical.
///
/// The empty resultSets body below is a value discarded before serialization rather than a
/// lossy shortcut. Call this only for `boolean` and `count`: at `record` granularity the
/// body is the answer, and this would serve an empty one.
#[must_use]
pub fn assemble_counts(
    totals: DatasetCounts,
    pagination: &Pagination,
    beacon_cfg: &BeaconParams,
    requested_granularity: &str,
) -> BeaconResponse {
    let schema = Schema {
        entry_type: "genomicVariant".to_owned(),
        schema: genomic_variant_schema_url(&beacon_cfg.api_version),
    };
    let meta = response_meta(beacon_cfg, vec![schema], requested_granularity, *pagination);
    BeaconResponse {
        meta,
        response_summary: ResponseSummary {
            exists: totals.exists,
            // Carried even for `boolean`, where shaping drops it: the audit trail reads
            // the true count from here before shaping, so withholding it would blind the
            // audit rather than the client.
            num_total_results: Some(totals.surviving),
        },
        response: Some(ResultSetsBody {
            result_sets: Vec::new(),
        }),
    }
}

/// Shape an assembled [`BeaconResponse`] for the request's
/// `includeResultsetResponses`.
///
/// `meta` and `responseSummary` are left untouched in every case, so the summary still
/// reflects the true aggregate match; only the per-dataset `resultSets` view is filtered.
/// [`assemble`] materializes one resultSet per considered dataset, a hit (`exists:true`) or
/// a miss (`exists:false`), so all four selectors are honoured:
///
/// * [`IncludeResultsetResponses::All`] — every considered dataset, hits and misses.
/// * [`IncludeResultsetResponses::Hit`] (the default) — only the matching datasets.
/// * [`IncludeResultsetResponses::Miss`] — only the non-matching datasets, so a client
///   can enumerate which datasets returned nothing and, with `gdiDatasetInfo`, bound
///   what a `0` could hide.
/// * [`IncludeResultsetResponses::None`] — no resultSets, but the `response` member is
///   kept and empty. `beaconResultsetsResponse` requires it, so dropping it would serve a
///   schema-non-conformant body at `record` granularity.
#[must_use]
pub fn apply_include_resultset_responses(
    mut response: BeaconResponse,
    include: IncludeResultsetResponses,
) -> BeaconResponse {
    let Some(body) = response.response.as_mut() else {
        return response;
    };
    match include {
        IncludeResultsetResponses::All => {}
        IncludeResultsetResponses::Hit => body.result_sets.retain(|rs| rs.exists),
        IncludeResultsetResponses::Miss => body.result_sets.retain(|rs| !rs.exists),
        IncludeResultsetResponses::None => body.result_sets = Vec::new(),
    }
    response
}

/// Shape an assembled [`BeaconResponse`] for the request's `requestedGranularity`,
/// treating the granularity as a disclosure ceiling (GA4GH Beacon v2). The node can serve
/// up to `record`, so it serves the requested level and no more. A `boolean` or `count`
/// request does not receive the record-level `frequencyInPopulations` payload:
///
/// * `boolean` — the `response` body is dropped and `numTotalResults` is withheld, leaving
///   only `responseSummary.exists`, so the count is not disclosed.
/// * `count` — the `response` body is dropped, leaving `meta` and `responseSummary`
///   (`exists` and `numTotalResults`).
/// * `record` — the full per-population body.
///
/// `returnedGranularity` is set to the level served. An unrecognized value is treated as
/// `record`, defensively: `parse_request` only ever produces the three folded values
/// `boolean`, `count` and `record`.
#[must_use]
pub fn shape_for_granularity(mut response: BeaconResponse, granularity: &str) -> BeaconResponse {
    // The node can serve up to `record`, so the served level is exactly the requested
    // one; an unrecognized value (unreachable after `fold_granularity`) is `record`.
    let served = match granularity {
        "boolean" | "count" => granularity,
        _ => "record",
    };
    served.clone_into(&mut response.meta.returned_granularity);
    match served {
        "boolean" => {
            response.response = None;
            response.response_summary.num_total_results = None;
        }
        "count" => response.response = None,
        // "record": serve the full record-level body unchanged.
        _ => {}
    }
    response
}

/// The `individual` default-schema URL for `api_version` (the `returnedSchemas`
/// entry naming the `individual` endpoint's schema in the response `meta`).
///
/// Points into the `ga4gh-beacon/beacon-v2` repository at the served API version tag,
/// mirroring [`genomic_variant_schema_url`] but naming the `individual` entry type.
fn individual_schema_url(api_version: &str) -> String {
    model_schema_url(api_version, "individuals")
}

/// The `returnedSchemas` [`Schema`] for a beacon entry type.
///
/// Maps the three served entry types (`genomicVariant` / `dataset` / `individual`) to
/// their default-schema URL so an error envelope names the schema of the endpoint that
/// was called rather than a request-agnostic default. An unrecognised value falls back
/// to `genomicVariant` (the node's primary entry type).
#[must_use]
pub fn entry_schema(entry_type: &str, api_version: &str) -> Schema {
    let schema = match entry_type {
        "dataset" => dataset_schema_url(api_version),
        "individual" => individual_schema_url(api_version),
        _ => genomic_variant_schema_url(api_version),
    };
    Schema {
        entry_type: entry_type.to_owned(),
        schema,
    }
}

fn dataset_schema_url(api_version: &str) -> String {
    model_schema_url(api_version, "datasets")
}

/// Pick a single representative literal from a [`LocalizedText`].
///
/// A `Plain` value is taken verbatim. For a language `Map`, the `en` entry is
/// preferred (the Beacon `name`/`description` fields are plain strings, not
/// language-tagged), falling back to the first entry by key order
/// (`BTreeMap`-deterministic) so the choice is stable across runs. An empty map
/// yields `None`.
fn representative_literal(text: &LocalizedText) -> Option<String> {
    match text {
        LocalizedText::Plain(value) => Some(value.clone()),
        LocalizedText::Map(map) => map
            .get("en")
            .or_else(|| map.values().next())
            .map(ToOwned::to_owned),
    }
}

/// Build one [`Collection`] for a visible dataset.
///
/// `id` is the dataset's `datasetId`, `name` the representative `title` literal,
/// `description` the representative `description` literal when present. The
/// create/update times are derived from the dataset id's timestamp tail (matching
/// the FDP `dct:issued`/`dct:modified`): `createDateTime` from the id, and
/// `updateDateTime` from an applied metadata overlay (`metadata_modified`) falling
/// back to the id time. A foreign id with no parseable timestamp leaves both `None`.
fn collection_for(entry: &DatasetEntry, beacon_cfg: &BeaconParams) -> Collection {
    let name = representative_literal(&entry.metadata.title).unwrap_or_default();
    let description = entry
        .metadata
        .description
        .as_ref()
        .and_then(representative_literal);
    let created = gdi_node_standalone_core::datetime::dataset_datetime(&entry.id);
    let updated = entry.metadata_modified.clone().or_else(|| created.clone());
    // The floor a client must reason about is the one actually applied at query time —
    // via the same `effective_floor` the g_variants path uses, so the two disclosures agree.
    let min_allele_count = effective_floor(&entry.config, beacon_cfg);
    Collection {
        id: entry.id.clone(),
        name,
        description,
        create_date_time: created,
        update_date_time: updated,
        gdi_dataset_info: GdiDatasetInfo {
            assembly: entry.config.assembly.reference.clone(),
            populations: entry.metadata.populations.clone(),
            min_allele_count,
        },
    }
}

/// Build the `beaconCollectionsResponse` `meta` (naming the `dataset` schema).
///
/// Mirrors the `g_variants` [`assemble`] `meta` exactly except that
/// `returnedSchemas` names the `dataset` default schema (not `genomicVariant`),
/// so the two envelopes report `meta` (and the applied pagination) identically.
fn collections_meta(pagination: &Pagination, beacon_cfg: &BeaconParams) -> BeaconResponseMeta {
    let schema = Schema {
        entry_type: "dataset".to_owned(),
        schema: dataset_schema_url(&beacon_cfg.api_version),
    };
    response_meta(beacon_cfg, vec![schema], "record", *pagination)
}

/// Assemble the visible datasets into a Beacon v2 [`BeaconCollectionsResponse`].
///
/// One [`Collection`] per visible dataset; the caller passes the already
/// visibility-filtered slice, so hidden, error and processing datasets are excluded.
/// `responseSummary.numTotalResults` is the true visible count, unaffected by paging, and
/// `exists` is `count > 0`. `response.collections[]` carries only the `pagination`-limited
/// (`skip` and `limit`) slice. The `meta` names the `dataset` schema and echoes the applied
/// pagination, as the `g_variants` [`assemble`] `meta` does.
#[must_use]
pub fn datasets_response(
    visible: &[&DatasetEntry],
    pagination: &Pagination,
    beacon_cfg: &BeaconParams,
) -> BeaconCollectionsResponse {
    let num_total_results = u64::try_from(visible.len()).unwrap_or(u64::MAX);
    let exists = !visible.is_empty();

    let skip = usize::try_from(pagination.skip).unwrap_or(usize::MAX);
    let limit = usize::try_from(pagination.limit).unwrap_or(usize::MAX);
    let collections: Vec<Collection> = visible
        .iter()
        .skip(skip)
        .take(limit)
        .map(|entry| collection_for(entry, beacon_cfg))
        .collect();

    BeaconCollectionsResponse {
        meta: collections_meta(pagination, beacon_cfg),
        response_summary: ResponseSummary {
            exists,
            num_total_results: Some(num_total_results),
        },
        response: CollectionsBody { collections },
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use std::path::Path;

    use gdi_node_standalone_core::convert::{ConvertOptions, convert_vcf};
    use gdi_node_standalone_core::model::DatasetMode;
    use test_util::covid;

    use super::*;

    /// Convert the COVID fixture into a fresh tempdir and return it.
    fn covid_dataset() -> tempfile::TempDir {
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
        dir
    }

    /// Header for a minimal contig-3 aggregate VCF (AF/AC `Number=A`, AN scalar).
    const VCF_HDR_CHR3: &str = "##fileformat=VCFv4.1\n\
##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
##INFO=<ID=AC,Number=A,Type=Integer,Description=\"ac\">\n\
##INFO=<ID=AN,Number=1,Type=Integer,Description=\"an\">\n\
##contig=<ID=3>\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";

    /// Convert an inline (coordinate-sorted) VCF `body` on contig 3 into a fresh
    /// tempdir dataset and return it.
    fn dataset_from_vcf(body: &str) -> tempfile::TempDir {
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let vcf = dir.path().join("in.vcf");
        std::fs::File::create(&vcf)
            .unwrap()
            .write_all(format!("{VCF_HDR_CHR3}{body}").as_bytes())
            .unwrap();
        let out = tempfile::tempdir().unwrap();
        convert_vcf(
            &vcf,
            out.path(),
            &ConvertOptions {
                assembly: "GRCh38".into(),
                block_range: 10_000_000,
                min_allele_count: 0,
            },
        )
        .unwrap();
        out
    }

    /// A sink that records what it was charged and credited, and can be made to refuse once
    /// its outstanding charge exceeds a cap. Outstanding rather than cumulative, because
    /// that is what a real ceiling bounds: a buffer already credited back is not resident.
    struct CountingSink {
        charged: u64,
        released: u64,
        calls: usize,
        refuse_after: Option<u64>,
        /// One entry per block the scan had to buffer whole, holding its file count.
        merged_blocks: Vec<usize>,
    }

    impl CountingSink {
        fn new(refuse_after: Option<u64>) -> Self {
            Self {
                charged: 0,
                released: 0,
                calls: 0,
                refuse_after,
                merged_blocks: Vec::new(),
            }
        }

        fn outstanding(&self) -> u64 {
            self.charged - self.released
        }
    }

    impl RetentionSink for CountingSink {
        fn charge(&mut self, bytes: u64) -> Result<(), RetentionRejected> {
            self.calls += 1;
            self.charged += bytes;
            if self
                .refuse_after
                .is_some_and(|cap| self.outstanding() > cap)
            {
                return Err(RetentionRejected {
                    detail: "test ceiling".to_owned(),
                });
            }
            Ok(())
        }

        fn note_merged_block(&mut self, files: usize) {
            self.merged_blocks.push(files);
        }

        fn release(&mut self, bytes: u64) {
            self.released += bytes;
            assert!(
                self.released <= self.charged,
                "a sink must never be credited more than it was charged (released {} > charged {})",
                self.released,
                self.charged
            );
        }
    }

    #[test]
    fn both_scan_paths_actually_charge_their_sink_and_honour_a_refusal() {
        // Every other caller in this crate passes `UnboundedRetention`, which admits
        // everything. Without one test that observes a real sink, the accounting could be
        // deleted outright and the whole suite would stay green.
        let dir = covid_dataset();
        let kind = QueryKind::Sequence {
            pos: 45_823_239,
            ref_: "T".into(),
            alt: "C".into(),
            predicates: Predicates::default(),
        };
        let caps = ParquetCaps::default();
        let dec = DatasetDecryptor::plaintext();

        // 1. The record path charges, and the total is non-zero.
        let mut sink = CountingSink::new(None);
        let rows = scan_dataset(
            dir.path(),
            "3",
            10_000_000,
            &kind,
            &caps,
            &dec,
            u64::MAX,
            &mut sink,
        )
        .expect("scan");
        assert!(
            !rows.is_empty(),
            "fixture must match rows for this to mean anything"
        );
        assert!(sink.calls > 0, "scan_dataset never charged its sink");
        assert!(
            sink.charged > 0,
            "scan_dataset charged zero bytes for a non-empty scan"
        );

        // 2. A refusal aborts the scan and surfaces as ResourceExhausted (5xx), never as
        //    QueryTooLarge (4xx): a saturated server must not tell a client its query
        //    was bad.
        let mut refusing = CountingSink::new(Some(0));
        let err = scan_dataset(
            dir.path(),
            "3",
            10_000_000,
            &kind,
            &caps,
            &dec,
            u64::MAX,
            &mut refusing,
        )
        .expect_err("a refusing sink must abort the scan");
        assert_eq!(
            err.class(),
            gdi_node_standalone_core::error::ErrorClass::ResourceExhausted,
            "a refused charge must be ResourceExhausted, not {:?}",
            err.class()
        );

        // 3. The aggregate path charges only what it retains. On a single-file block it
        //    streams row by row and holds nothing, so it must charge nothing: a charge here
        //    would bill the budget for memory that never existed and shed healthy requests.
        //    Its charging arm is the multi-file block merge buffer, built by
        //    `aggregate_fold_agrees_with_the_record_path_on_a_per_population_split`.
        let mut agg_sink = CountingSink::new(None);
        scan_dataset_counts(
            dir.path(),
            "3",
            10_000_000,
            &kind,
            &caps,
            &dec,
            AggregateScan {
                sink: &mut agg_sink,
                max_query_bytes: u64::MAX,
                floor: 0,
            },
        )
        .expect("aggregate scan");
        assert_eq!(
            agg_sink.charged, 0,
            "the streaming (single-file block) arm retains nothing and must charge nothing"
        );
    }

    #[test]
    fn sequence_scan_applies_variant_type_and_length_predicates() {
        // A `variantType` or length bound submitted alongside an exact-allele (Sequence)
        // query is honoured, as it is for the Range and Bracket shapes. The COVID variant
        // is a T>C SNP.
        let dir = covid_dataset();
        let scan = |predicates: Predicates| {
            scan_dataset(
                dir.path(),
                "3",
                10_000_000,
                &QueryKind::Sequence {
                    pos: 45_823_239,
                    ref_: "T".into(),
                    alt: "C".into(),
                    predicates,
                },
                &ParquetCaps::default(),
                &DatasetDecryptor::plaintext(),
                u64::MAX,
                &mut UnboundedRetention,
            )
            .unwrap()
        };

        // Matching variantType (the stored VT is SNP) still returns rows.
        assert!(
            !scan(Predicates {
                variant_type: Some(vec!["SNP".to_owned()]),
                ..Predicates::default()
            })
            .is_empty(),
            "variantType=SNP must still match the SNP"
        );
        // A contradicting variantType filters the row out.
        assert!(
            scan(Predicates {
                variant_type: Some(vec!["DEL".to_owned()]),
                ..Predicates::default()
            })
            .is_empty(),
            "variantType=DEL must filter out the T>C SNP on the exact-allele path"
        );
        // Under alt-allele-length semantics (matching the reference beacon) an SNV has
        // len(ALT)=1, so variantMinLength=1 includes it. An indel-size delta of 0 would
        // wrongly exclude every SNV a federated peer would have returned.
        assert!(
            !scan(Predicates {
                min_len: Some(1),
                ..Predicates::default()
            })
            .is_empty(),
            "variantMinLength=1 must include the SNV (len(ALT)=1 >= 1)"
        );
        // variantMinLength=2 still excludes the SNV (len(ALT)=1 < 2).
        assert!(
            scan(Predicates {
                min_len: Some(2),
                ..Predicates::default()
            })
            .is_empty(),
            "variantMinLength=2 must filter out the SNV (len(ALT)=1 < 2)"
        );
    }

    /// The aggregate fold must produce what the record path counts, exactly.
    ///
    /// The fold counts as it streams rather than materialising, grouping and then counting,
    /// and its failure mode is not a crash but a wrong `numTotalResults`, which a federated
    /// aggregator would propagate as fact. It is therefore checked differentially against
    /// the record path across several query shapes and several floors. The floor decides
    /// which groups survive, so it must not shift the two paths apart.
    #[test]
    fn aggregate_fold_counts_agree_with_the_record_path() {
        let dir = covid_dataset();
        let caps = ParquetCaps::default();
        let dec = DatasetDecryptor::plaintext();

        let kinds = vec![
            (
                "exact SNV",
                QueryKind::Sequence {
                    pos: 45_823_239,
                    ref_: "T".into(),
                    alt: "C".into(),
                    predicates: Predicates::default(),
                },
            ),
            (
                "wide range",
                QueryKind::Range {
                    start: 0,
                    end: 100_000_000,
                    predicates: Predicates::default(),
                },
            ),
            (
                "narrow range",
                QueryKind::Range {
                    start: 45_823_000,
                    end: 45_824_000,
                    predicates: Predicates::default(),
                },
            ),
            (
                "range matching nothing",
                QueryKind::Range {
                    start: 1,
                    end: 2,
                    predicates: Predicates::default(),
                },
            ),
        ];

        for (label, kind) in kinds {
            for floor in [0u32, 1, 5, 50, 10_000] {
                // The record path: materialise, group, then count survivors, which is what
                // `assemble_dataset` does to produce `resultsCount`.
                let rows = scan_dataset(
                    dir.path(),
                    "3",
                    10_000_000,
                    &kind,
                    &caps,
                    &dec,
                    u64::MAX,
                    &mut UnboundedRetention,
                )
                .expect("record scan");
                let expected: u64 = DatasetPage::from_rows(
                    rows,
                    PageSpec {
                        floor,
                        ..PageSpec::everything()
                    },
                )
                .expect("group the scanned rows")
                .total;

                let got = scan_dataset_counts(
                    dir.path(),
                    "3",
                    10_000_000,
                    &kind,
                    &caps,
                    &dec,
                    AggregateScan {
                        sink: &mut UnboundedRetention,
                        max_query_bytes: u64::MAX,
                        floor,
                    },
                )
                .expect("aggregate scan");

                assert_eq!(
                    got.surviving, expected,
                    "{label} @ floor {floor}: fold counted {} surviving groups, record path {expected}",
                    got.surviving
                );
                assert_eq!(
                    got.exists,
                    expected > 0,
                    "{label} @ floor {floor}: exists must agree with a non-zero count"
                );
            }
        }
    }

    /// The multi-file companion to `aggregate_fold_counts_agree_with_the_record_path`.
    ///
    /// That test runs on the COVID fixture, which holds one variant and emits a single data
    /// file, so every query it makes selects one file and it cannot exercise the fold across
    /// a file boundary. This builds a per-population split: several source VCFs over the
    /// same loci carrying different populations, converted together by `convert_vcf_group`.
    /// That is a supported packaging shape (the dataset-tool's `build_e2e` packages it, and
    /// `validate_parquet` admits "same variant, different populations"), and it puts several
    /// files in one block whose `POS` spans fully overlap.
    ///
    /// Concatenating those files makes `POS` jump backwards at every boundary, which the
    /// aggregate fold fails closed on. Without the per-block merge, a `count` or `boolean`
    /// query against a valid package would return a 500 while the same query at `record`
    /// granularity succeeded.
    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "an inline two-VCF fixture; splitting it would move the shape under test away from the assertion that reads it"
    )]
    fn aggregate_fold_agrees_with_the_record_path_on_a_per_population_split() {
        use std::io::Write as _;

        const HDR_TOTAL: &str = "##fileformat=VCFv4.1\n\
##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
##INFO=<ID=AC,Number=A,Type=Integer,Description=\"ac\">\n\
##INFO=<ID=AN,Number=1,Type=Integer,Description=\"an\">\n\
##contig=<ID=3>\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";
        const HDR_NL: &str = "##fileformat=VCFv4.1\n\
##INFO=<ID=AF_NL,Number=A,Type=Float,Description=\"af nl\">\n\
##INFO=<ID=AC_NL,Number=A,Type=Integer,Description=\"ac nl\">\n\
##INFO=<ID=AN_NL,Number=1,Type=Integer,Description=\"an nl\">\n\
##contig=<ID=3>\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";

        let src = tempfile::tempdir().unwrap();
        let write = |name: &str, text: &str| -> std::path::PathBuf {
            let p = src.path().join(name);
            std::fs::File::create(&p)
                .unwrap()
                .write_all(text.as_bytes())
                .unwrap();
            p
        };
        // Shared loci (100, 200, 300) with distinct populations, so the (variant,
        // population) pairs stay unique while the (POS, REF, ALT) keys overlap across the
        // two files.
        let a = write(
            "total.vcf",
            &format!(
                "{HDR_TOTAL}3\t100\t.\tA\tG\t.\t.\tAF=0.10;AC=10;AN=100\n\
                 3\t200\t.\tC\tT\t.\t.\tAF=0.20;AC=20;AN=100\n\
                 3\t300\t.\tG\tA\t.\t.\tAF=0.30;AC=30;AN=100\n"
            ),
        );
        let b = write(
            "nl.vcf",
            &format!(
                "{HDR_NL}3\t100\t.\tA\tG\t.\t.\tAF_NL=0.11;AC_NL=11;AN_NL=100\n\
                 3\t200\t.\tC\tT\t.\t.\tAF_NL=0.21;AC_NL=21;AN_NL=100\n\
                 3\t300\t.\tG\tA\t.\t.\tAF_NL=0.31;AC_NL=31;AN_NL=100\n"
            ),
        );

        let out = tempfile::tempdir().unwrap();
        let results = gdi_node_standalone_core::convert::convert_vcf_group(
            &[a, b],
            out.path(),
            &ConvertOptions {
                assembly: "GRCh38".into(),
                block_range: 10_000_000,
                min_allele_count: 0,
            },
            2,
            &|_| {},
            &|_, _| {},
        )
        .expect("build-wide setup");
        for r in results {
            r.expect("each VCF converts");
        }

        let kind = QueryKind::Range {
            start: 0,
            end: 1_000,
            predicates: Predicates::default(),
        };
        let caps = ParquetCaps::default();
        let dec = DatasetDecryptor::plaintext();

        // Non-vacuity: the fixture must put more than one file in one block, or this test
        // proves nothing about the merge.
        let blocks = select_files(out.path(), "3", 10_000_000, &kind, &caps).unwrap();
        assert!(
            blocks.iter().any(|b| b.files.len() > 1),
            "the per-population split must leave several files in one block, got {:?}",
            blocks
                .iter()
                .map(|b| (b.block, b.files.len()))
                .collect::<Vec<_>>()
        );

        let rows = scan_dataset(
            out.path(),
            "3",
            10_000_000,
            &kind,
            &caps,
            &dec,
            u64::MAX,
            &mut UnboundedRetention,
        )
        .expect("record scan");
        let expected = DatasetPage::from_rows(rows, PageSpec::everything())
            .expect("group the scanned rows")
            .total;
        assert_eq!(expected, 3, "three shared loci, one group each");

        let got = scan_dataset_counts(
            out.path(),
            "3",
            10_000_000,
            &kind,
            &caps,
            &dec,
            AggregateScan {
                sink: &mut UnboundedRetention,
                max_query_bytes: u64::MAX,
                floor: 0,
            },
        )
        .expect("the aggregate fold must not fail on a valid per-population split");

        assert_eq!(
            got.surviving, expected,
            "the merged fold must count each shared locus once, not once per source file"
        );
        assert!(got.exists);
    }

    /// A per-population split spanning two blocks, so an aggregate scan over it builds and
    /// then drops one merge buffer per block. Query the returned dir with `block_range =
    /// 1000` over `POS` 0..2000 to select both.
    fn two_block_population_split() -> tempfile::TempDir {
        use std::io::Write as _;

        const HDR_TOTAL: &str = "##fileformat=VCFv4.1\n\
##INFO=<ID=AF,Number=A,Type=Float,Description=\"af\">\n\
##INFO=<ID=AC,Number=A,Type=Integer,Description=\"ac\">\n\
##INFO=<ID=AN,Number=1,Type=Integer,Description=\"an\">\n\
##contig=<ID=3>\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";
        const HDR_NL: &str = "##fileformat=VCFv4.1\n\
##INFO=<ID=AF_NL,Number=A,Type=Float,Description=\"af nl\">\n\
##INFO=<ID=AC_NL,Number=A,Type=Integer,Description=\"ac nl\">\n\
##INFO=<ID=AN_NL,Number=1,Type=Integer,Description=\"an nl\">\n\
##contig=<ID=3>\n\
#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";

        let src = tempfile::tempdir().unwrap();
        let write = |name: &str, text: &str| -> std::path::PathBuf {
            let p = src.path().join(name);
            std::fs::File::create(&p)
                .unwrap()
                .write_all(text.as_bytes())
                .unwrap();
            p
        };
        // Two blocks under `block_range = 1000` (a row's group is `POS / block_range`),
        // each carrying the same three loci in both populations, so the blocks' merge
        // buffers are the same size and a per-block charge can be compared with its sibling.
        let a = write(
            "total.vcf",
            &format!(
                "{HDR_TOTAL}3\t100\t.\tA\tG\t.\t.\tAF=0.10;AC=10;AN=100\n\
                 3\t200\t.\tC\tT\t.\t.\tAF=0.20;AC=20;AN=100\n\
                 3\t300\t.\tG\tA\t.\t.\tAF=0.30;AC=30;AN=100\n\
                 3\t1100\t.\tA\tG\t.\t.\tAF=0.10;AC=10;AN=100\n\
                 3\t1200\t.\tC\tT\t.\t.\tAF=0.20;AC=20;AN=100\n\
                 3\t1300\t.\tG\tA\t.\t.\tAF=0.30;AC=30;AN=100\n"
            ),
        );
        let b = write(
            "nl.vcf",
            &format!(
                "{HDR_NL}3\t100\t.\tA\tG\t.\t.\tAF_NL=0.11;AC_NL=11;AN_NL=100\n\
                 3\t200\t.\tC\tT\t.\t.\tAF_NL=0.21;AC_NL=21;AN_NL=100\n\
                 3\t300\t.\tG\tA\t.\t.\tAF_NL=0.31;AC_NL=31;AN_NL=100\n\
                 3\t1100\t.\tA\tG\t.\t.\tAF_NL=0.11;AC_NL=11;AN_NL=100\n\
                 3\t1200\t.\tC\tT\t.\t.\tAF_NL=0.21;AC_NL=21;AN_NL=100\n\
                 3\t1300\t.\tG\tA\t.\t.\tAF_NL=0.31;AC_NL=31;AN_NL=100\n"
            ),
        );

        let out = tempfile::tempdir().unwrap();
        let results = gdi_node_standalone_core::convert::convert_vcf_group(
            &[a, b],
            out.path(),
            &ConvertOptions {
                assembly: "GRCh38".into(),
                block_range: 1000,
                min_allele_count: 0,
            },
            2,
            &|_| {},
            &|_, _| {},
        )
        .expect("build-wide setup");
        for r in results {
            r.expect("each VCF converts");
        }
        out
    }

    #[test]
    fn the_aggregate_path_credits_back_each_block_buffer_it_has_folded() {
        // The fold consumes the merge buffer at the end of every block, so a dataset holds
        // the largest block's buffer at once, never the sum over blocks. Charging without
        // crediting makes the ceiling bound that sum: a many-block dataset then trips
        // `max_query_bytes`, and the process-wide pool behind it, at a fraction of its true
        // peak, shedding legitimate queries with a 503 while the node sits far below the
        // memory the operator sized it for.
        let dir = two_block_population_split();
        let kind = QueryKind::Range {
            start: 0,
            end: 2_000,
            predicates: Predicates::default(),
        };
        let caps = ParquetCaps::default();
        let dec = DatasetDecryptor::plaintext();

        // Non-vacuity: the fixture must yield more than one block, each holding more than
        // one file. With one block, or one file per block, this test says nothing about
        // crediting between blocks.
        let blocks = select_files(dir.path(), "3", 1000, &kind, &caps).unwrap();
        let merged = blocks.iter().filter(|b| b.files.len() > 1).count();
        assert!(
            merged >= 2,
            "the fixture must produce at least two multi-file blocks, got {:?}",
            blocks
                .iter()
                .map(|b| (b.block, b.files.len()))
                .collect::<Vec<_>>()
        );

        let mut sink = CountingSink::new(None);
        scan_dataset_counts(
            dir.path(),
            "3",
            1000,
            &kind,
            &caps,
            &dec,
            AggregateScan {
                sink: &mut sink,
                max_query_bytes: u64::MAX,
                floor: 0,
            },
        )
        .expect("aggregate scan");

        assert!(
            sink.charged > 0,
            "the merge arm must charge what it buffers"
        );
        // The shape is reported, not just paid for: one note per multi-file block, each
        // carrying that block's file count. This is the only signal an operator gets that a
        // package was built in the expensive shape.
        assert_eq!(
            sink.merged_blocks.len(),
            merged,
            "one note per merged block (got {:?} for {merged} multi-file blocks)",
            sink.merged_blocks
        );
        assert!(
            sink.merged_blocks.iter().all(|&files| files > 1),
            "a note's file count is the block's, which is >1 by definition: {:?}",
            sink.merged_blocks
        );
        assert_eq!(
            sink.outstanding(),
            0,
            "every block buffer is dropped once folded, so a scan that ran to completion must \
             have credited back everything it charged (charged {}, released {})",
            sink.charged,
            sink.released
        );

        // The bound that matters, and the one that fails without the credit: a ceiling
        // sized for one block's buffer must admit a scan over N such blocks, because only
        // one is ever resident. `refuse_after` caps the outstanding charge, which is what a
        // real ceiling measures.
        let one_block = sink.charged / u64::try_from(merged).unwrap();
        let mut capped = CountingSink::new(Some(one_block));
        scan_dataset_counts(
            dir.path(),
            "3",
            1000,
            &kind,
            &caps,
            &dec,
            AggregateScan {
                sink: &mut capped,
                max_query_bytes: u64::MAX,
                floor: 0,
            },
        )
        .expect(
            "a ceiling the size of one block's merge buffer must admit a multi-block scan: \
             the buffers do not coexist",
        );
    }

    /// The record path over a per-population split: one group per locus, ascending, and the
    /// page window counted over merged groups.
    ///
    /// This is the shape the merge arm of `fold_matching_rows` exists for. The files carry
    /// the same loci in different populations, so their `POS` spans overlap and
    /// concatenating them is not ascending. Everything the fold does downstream, the order
    /// guard, the key-change group close and the page ordinal, is correct only if that arm
    /// re-sorts. A regression there still compiles and does not trip the count path's
    /// accounting assertions; it emits each locus twice and pages over the duplicates.
    #[test]
    fn the_record_path_merges_a_population_split_block_into_ordered_groups() {
        let dir = two_block_population_split();
        let kind = QueryKind::Range {
            start: 0,
            end: 2_000,
            predicates: Predicates::default(),
        };
        let caps = ParquetCaps::default();
        let dec = DatasetDecryptor::plaintext();

        // Non-vacuity: without a multi-file block this test is about the streaming arm and
        // says nothing about the merge.
        let blocks = select_files(dir.path(), "3", 1000, &kind, &caps).unwrap();
        let merged = blocks.iter().filter(|b| b.files.len() > 1).count();
        assert!(
            merged >= 2,
            "the fixture must produce at least two multi-file blocks, got {:?}",
            blocks
                .iter()
                .map(|b| (b.block, b.files.len()))
                .collect::<Vec<_>>()
        );

        let page = scan_dataset_page(
            dir.path(),
            "3",
            1000,
            &kind,
            &caps,
            &dec,
            u64::MAX,
            PageSpec::everything(),
            &mut UnboundedRetention,
        )
        .expect("the record path must not fail on a valid per-population split");

        // The fixture is three loci per block over two blocks, each locus present in both
        // source files. Six groups, not twelve: a lost merge shows up here first.
        let keys: Vec<i32> = page.groups.iter().map(|g| g.pos).collect();
        assert_eq!(
            keys,
            // 0-based storage POS: the VCF's 1-based 100 is stored as 99.
            vec![99, 199, 299, 1099, 1199, 1299],
            "each locus must appear once, in ascending POS, across both files of its block"
        );
        assert_eq!(
            page.total, 6,
            "the true surviving total counts merged groups"
        );

        // Each group must carry both files' populations. This is the assertion that
        // distinguishes a real merge from a coincidence of ordering: `Total` comes from
        // total.vcf and `NL` from nl.vcf, so a group holding both proves rows from two
        // different files were folded into one group.
        for g in &page.groups {
            let mut pops: Vec<&str> = g.rows.iter().map(|r| r.population.as_str()).collect();
            pops.sort_unstable();
            assert_eq!(
                pops,
                vec!["NL", "Total"],
                "locus {} must merge both source files' populations",
                g.pos
            );
        }

        // The page ordinal is counted over merged groups: the window is applied while
        // folding, not as a slice of an already-merged vector.
        let windowed = scan_dataset_page(
            dir.path(),
            "3",
            1000,
            &kind,
            &caps,
            &dec,
            u64::MAX,
            PageSpec {
                floor: 0,
                skip: 2,
                limit: 2,
            },
            &mut UnboundedRetention,
        )
        .expect("windowed record scan");
        assert_eq!(
            windowed.groups.iter().map(|g| g.pos).collect::<Vec<_>>(),
            vec![299, 1099],
            "skip/limit must index merged groups — indexing raw rows would land mid-locus \
             and indexing per-file would repeat one"
        );
        assert_eq!(
            windowed.total, 6,
            "the surviving total is independent of the window"
        );

        // The count path folds the same blocks without materialising, so the two paths must
        // agree about how many groups survive over this shape.
        let mut sink = CountingSink::new(None);
        let counts = scan_dataset_counts(
            dir.path(),
            "3",
            1000,
            &kind,
            &caps,
            &dec,
            AggregateScan {
                sink: &mut sink,
                max_query_bytes: u64::MAX,
                floor: 0,
            },
        )
        .expect("aggregate scan");
        assert_eq!(
            counts.surviving, page.total,
            "the count and record paths must agree over a multi-file block"
        );
    }

    #[test]
    fn sequence_scan_returns_exact_population_rows() {
        let dir = covid_dataset();
        let kind = QueryKind::Sequence {
            pos: 45_823_239,
            ref_: "T".into(),
            alt: "C".into(),
            predicates: Predicates::default(),
        };
        let rows = scan_dataset(
            dir.path(),
            "3",
            10_000_000,
            &kind,
            &ParquetCaps::default(),
            &DatasetDecryptor::plaintext(),
            u64::MAX,
            &mut UnboundedRetention,
        )
        .unwrap();

        // Every returned row must be the exact variant.
        assert!(!rows.is_empty(), "expected at least the Total/FI_M rows");
        for r in &rows {
            assert_eq!(r.pos, 45_823_239);
            assert_eq!(r.ref_, "T");
            assert_eq!(r.alt, "C");
        }

        let total = rows
            .iter()
            .find(|r| r.population == "Total")
            .expect("Total population row present");
        assert!(
            (total.af - 0.077_25).abs() < 1e-4,
            "Total AF {} not ≈ 0.07725",
            total.af
        );
        assert_eq!(total.ac, Some(i32::try_from(covid::TOTAL_AC).unwrap()));
        assert_eq!(total.an, Some(i32::try_from(covid::TOTAL_AN).unwrap()));

        let fi_m = rows
            .iter()
            .find(|r| r.population == "FI_M")
            .expect("FI_M population row present");
        assert!(
            (f64::from(fi_m.af) - covid::FI_M_AF).abs() < 1e-4,
            "FI_M AF {} not ≈ 0.085",
            fi_m.af
        );
        assert_eq!(fi_m.ac, Some(i32::try_from(covid::FI_M_AC).unwrap()));
        assert_eq!(fi_m.an, Some(1400));
    }

    /// A query whose cumulative matching rows for one dataset exceed
    /// `caps.max_query_rows` fails closed (bounding heap), while the same query under
    /// the default cap succeeds.
    #[test]
    fn scan_rejects_query_exceeding_max_query_rows() {
        let dir = covid_dataset();
        let kind = QueryKind::Sequence {
            pos: 45_823_239,
            ref_: "T".into(),
            alt: "C".into(),
            predicates: Predicates::default(),
        };
        let tight = ParquetCaps {
            max_query_rows: 0,
            ..ParquetCaps::default()
        };
        let err = scan_dataset(
            dir.path(),
            "3",
            10_000_000,
            &kind,
            &tight,
            &DatasetDecryptor::plaintext(),
            u64::MAX,
            &mut UnboundedRetention,
        )
        .unwrap_err();
        assert!(
            format!("{err}").contains("narrow the position range"),
            "expected a query-too-broad rejection, got: {err}"
        );
        // It must classify as a client error, which drives the beacon HTTP 400
        // query-too-broad reject, not as a server fault. See beacon_http's scan error
        // dispatch.
        assert_eq!(
            err.class(),
            gdi_node_standalone_core::error::ErrorClass::QueryTooLarge,
            "the row cap is a client error, not invalid-parquet-schema"
        );

        // The same query under the default cap returns its rows.
        let ok = scan_dataset(
            dir.path(),
            "3",
            10_000_000,
            &kind,
            &ParquetCaps::default(),
            &DatasetDecryptor::plaintext(),
            u64::MAX,
            &mut UnboundedRetention,
        )
        .unwrap();
        assert!(!ok.is_empty(), "default cap must not reject a point query");
    }

    #[test]
    fn non_matching_sequence_returns_empty() {
        let dir = covid_dataset();
        let kind = QueryKind::Sequence {
            pos: 1,
            ref_: "T".into(),
            alt: "C".into(),
            predicates: Predicates::default(),
        };
        let rows = scan_dataset(
            dir.path(),
            "3",
            10_000_000,
            &kind,
            &ParquetCaps::default(),
            &DatasetDecryptor::plaintext(),
            u64::MAX,
            &mut UnboundedRetention,
        )
        .unwrap();
        assert!(rows.is_empty(), "non-matching sequence must return no rows");
    }

    /// A minimal `ManifestConfig` with the given serving floor.
    fn manifest_cfg(min_allele_count: u32) -> ManifestConfig {
        ManifestConfig {
            mode: DatasetMode::Aggregated,
            block_range: 10_000_000,
            af_source: None,
            af_source_reference: None,
            min_allele_count,
            hide_lower_counts: None,
            assembly: gdi_node_standalone_core::model::Assembly {
                reference: "GRCh38".to_owned(),
            },
            manifest_version: 1,
            generated_by: "test".to_owned(),
        }
    }

    /// One `AlleleRow` for population `pop` at `pos` (REF T / ALT C), `AC = ac`.
    fn arow(pos: i32, pop: &str, ac: i32) -> AlleleRow {
        AlleleRow {
            pos,
            ref_: "T".to_owned(),
            alt: "C".to_owned(),
            vt: Vt::Snp,
            population: pop.to_owned(),
            af: 0.1,
            ac: Some(ac),
            ac_hom: None,
            ac_het: None,
            ac_hemi: None,
            an: Some(1000),
        }
    }

    /// An `AlleleRow` with explicit `AC` / `AN` / `AF` for the suppression tests.
    fn krow(pop: &str, ac: Option<i32>, an: Option<i32>, af: f32) -> AlleleRow {
        AlleleRow {
            pos: 100,
            ref_: "T".to_owned(),
            alt: "C".to_owned(),
            vt: Vt::Snp,
            population: pop.to_owned(),
            af,
            ac,
            ac_hom: None,
            ac_het: None,
            ac_hemi: None,
            an,
        }
    }

    /// `round(AF * AN)` recovers `AC` exactly, which is what makes the `AF`-only fallback
    /// in [`alt_carriers`] cost no utility: a complete `AF`-only axis leaves
    /// [`marginal_set_incomplete`] a remainder of `0`, as an `AC`-bearing one does. For
    /// `AF = f32(AC / AN)`, `round(f64(AF) * f64(AN)) == AC` for every `AC` at every `AN` up
    /// to the bound checked here, and up to `2^24`. Past `2^24` the `f32` mantissa runs out
    /// and the identity breaks, at an `AN` no real cohort reaches.
    #[test]
    fn alt_carriers_recovers_ac_exactly() {
        for an in 1..=512i32 {
            for ac in 0..=an {
                #[expect(
                    clippy::cast_precision_loss,
                    reason = "AF is stored as f32, so the lossy cast is the production path this test covers"
                )]
                let af = ac as f32 / an as f32;
                let row = AlleleRow {
                    ac: None,
                    af,
                    an: Some(an),
                    ..arow(100, "M", 0)
                };
                let derived = alt_carriers(&row);
                if ac == 0 {
                    // `af == 0` is an empty alt group: `alt_carriers` reports no count.
                    assert_eq!(derived, None, "AC=0 AN={an}");
                } else {
                    assert_eq!(
                        derived,
                        Some(i64::from(ac)),
                        "round(AF*AN) must recover AC exactly: AC={ac} AN={an} AF={af}"
                    );
                }
            }
        }
    }

    fn gtrow(pop: &str, ac: i32, hom: i32, het: i32) -> AlleleRow {
        AlleleRow {
            pos: 100,
            ref_: "T".to_owned(),
            alt: "C".to_owned(),
            vt: Vt::Snp,
            population: pop.to_owned(),
            af: 0.03,
            ac: Some(ac),
            ac_hom: Some(hom),
            ac_het: Some(het),
            ac_hemi: None,
            an: Some(1000),
        }
    }

    fn gtgroup(rows: Vec<AlleleRow>) -> VariantGroup {
        VariantGroup {
            pos: 100,
            ref_: "T".to_owned(),
            alt: "C".to_owned(),
            vt: Vt::Snp,
            rows,
        }
    }

    #[test]
    fn subcount_in_danger_fires_on_exactly_one_below_floor_subcount() {
        // `subcount_in_danger` is `hom || het || hemi` in danger, so each sub-count below
        // the floor alone must trigger it. A `&&` in place of the `||` would need all three
        // below the floor.
        // hom below floor, het safe, hemi absent.
        assert!(
            subcount_in_danger(&gtrow("F", 5, 2, 20), 5),
            "hom-only below floor"
        );
        // het below floor, hom safe, hemi absent.
        assert!(
            subcount_in_danger(&gtrow("F", 5, 20, 3), 5),
            "het-only below floor"
        );
        // hemi below floor, hom/het safe.
        let mut hemi_row = gtrow("F", 5, 20, 20);
        hemi_row.ac_hemi = Some(2);
        assert!(subcount_in_danger(&hemi_row, 5), "hemi-only below floor");
        // All three safe (or absent) -> not in danger.
        assert!(!subcount_in_danger(&gtrow("F", 30, 20, 20), 5), "all safe");
    }

    #[test]
    fn subcount_partition_incomplete_fires_on_exactly_one_incomplete_axis() {
        // `subcount_partition_incomplete` is `hom || het || hemi` incomplete across the
        // group; a `&&` in place of the `||` would need all three axes incomplete. The
        // survived set below leaves a re-identifying Total-remainder on the hom axis only:
        // Total.hom=30, M.hom=27 gives remainder 3 (in 1..5, incomplete); Total.het=30,
        // M.het=15 gives remainder 15 (complete); hemi is absent, so it has no anchor.
        let total = gtrow("Total", 30, 30, 30);
        let m = gtrow("M", 27, 27, 15);
        let survived: Vec<&AlleleRow> = vec![&total, &m];
        assert!(
            subcount_partition_incomplete(&survived, 5),
            "a single incomplete axis (hom) must trigger suppression"
        );
        // A group where no axis is incomplete must not trigger.
        let total_ok = gtrow("Total", 30, 30, 30);
        let m_ok = gtrow("M", 15, 15, 15);
        let survived_ok: Vec<&AlleleRow> = vec![&total_ok, &m_ok];
        assert!(
            !subcount_partition_incomplete(&survived_ok, 5),
            "all-complete axes must not trigger"
        );
    }

    #[test]
    fn a_null_total_subcount_does_not_disable_the_partition_rule() {
        // Looking the anchor up on the served `Total` row would short-circuit the whole
        // rule to "safe" whenever `Total` carries no value for a plane, even with two axes
        // disagreeing by a below-floor amount. Nothing requires a `Total` row to carry
        // sub-counts when its children do: `core::subcounts` is strictly per-row,
        // `check_hierarchy` reads only AC/AN, and `convert` reads each population's
        // sub-count fields independently.
        //
        // Floor 5, all ingest predicates satisfied, no row individually suppressed:
        //   Sex axis     hom: M 50 + F 50            = 100
        //   Country axis hom: FI 98 + EE (withheld)  =  98
        // The client subtracts to recover EE.hom = 2, one homozygous individual in Estonia,
        // which is what the floor exists to hide. Only a cross-axis comparison sees it: the
        // `Total` anchor is null on this plane.
        let total = AlleleRow {
            ac_hom: None,
            ac_het: None,
            ac_hemi: None,
            ..gtrow("Total", 200, 0, 0)
        };
        let m = gtrow("M", 100, 50, 50);
        let f = gtrow("F", 100, 50, 50);
        // het is kept consistent across both axes (100 vs 100) so only the hom plane is
        // re-identifying, and the assertion cannot pass for the wrong reason.
        let fi = gtrow("FI", 190, 98, 90);
        let ee = AlleleRow {
            ac_hom: None,
            ..gtrow("EE", 10, 0, 10)
        };
        let survived: Vec<&AlleleRow> = vec![&total, &m, &f, &fi, &ee];
        assert!(
            subcount_partition_incomplete(&survived, 5),
            "a cross-axis hom remainder of 2 must collapse the group even though Total.hom \
             carries no value"
        );
    }

    #[test]
    fn frequencies_for_collapses_subcounts_group_wide_against_differencing() {
        // Every population's AC clears the floor, so the AC plane does not collapse, but
        // F's genotype sub-counts are below the floor. Without group-wide coherence F.Hom
        // is withheld per row yet recoverable as Total.Hom - M.Hom.
        let group = gtgroup(vec![
            gtrow("Total", 30, 10, 20),
            gtrow("M", 25, 9, 18),
            gtrow("F", 5, 1, 2),
        ]);
        let freqs = frequencies_for(&group, 5).expect("group has surviving rows");
        // All three rows are still served (AC 30/25/5 all >= floor 5), so AC and AF utility
        // is preserved.
        assert_eq!(freqs.len(), 3);
        for f in &freqs {
            assert!(f.allele_count.is_some() && f.allele_number.is_some());
            if f.population == "Total" {
                // The lone aggregate keeps its sub-counts: nothing to difference against.
                assert_eq!(f.allele_count_homozygous, Some(10));
                assert_eq!(f.allele_count_heterozygous, Some(20));
            } else {
                // Every non-Total sibling is stripped, so Total - M and Total - F cannot
                // reconstruct the below-floor F cell.
                assert_eq!(
                    f.allele_count_homozygous, None,
                    "{} hom leaked",
                    f.population
                );
                assert_eq!(
                    f.allele_count_heterozygous, None,
                    "{} het leaked",
                    f.population
                );
            }
        }
    }

    #[test]
    fn frequencies_for_collapses_when_only_het_below_floor() {
        // A differencing variant the coherence gate must catch: only F's Het is below the
        // floor, because its Hom clears it. The trigger fires on any below-floor sub-count
        // independently (Hom, Het or Hemi), or F.Het would be recoverable as
        // Total.Het - M.Het. The collapse test above has F.Hom below the floor too, so it
        // cannot detect a gate that fires only when Hom and Het are both in danger.
        let group = gtgroup(vec![
            gtrow("Total", 30, 10, 20),
            gtrow("M", 25, 8, 17),
            gtrow("F", 10, 8, 2), // Hom 8 clears floor 5; only Het 2 is below it.
        ]);
        let freqs = frequencies_for(&group, 5).expect("group has surviving rows");
        assert_eq!(freqs.len(), 3, "all AC (30/25/10) clear floor 5");
        for f in &freqs {
            if f.population == "Total" {
                assert_eq!(f.allele_count_heterozygous, Some(20));
            } else {
                assert_eq!(
                    f.allele_count_heterozygous, None,
                    "{} het leaked (recoverable as Total.Het - sibling)",
                    f.population
                );
                assert_eq!(
                    f.allele_count_homozygous, None,
                    "{} hom leaked",
                    f.population
                );
            }
        }
    }

    #[test]
    fn frequencies_for_collapses_subcounts_when_a_sibling_subcount_is_absent() {
        // The incomplete-partition attack on a sub-count plane. `marginal_set_incomplete`
        // catches a sibling withheld before ingest on the AC plane, and `subcount_in_danger`
        // cannot stand in for it here: it fires only on a present value in `1..floor`, and
        // an absent sibling is `None`, which it reads as safe.
        //
        // Every other guard declines to fire on this input: all three ACs clear the floor,
        // the AC axis is complete (25 + 5 == 30) so neither the AC collapse nor
        // `marginal_set_incomplete` triggers, and every present sub-count clears the floor.
        // Yet `Total.Hom - M.Hom == 2` hands the client a below-floor cell by subtraction.
        let mut f = gtrow("F", 5, 0, 0);
        f.ac_hom = None;
        f.ac_het = None;
        let group = gtgroup(vec![gtrow("Total", 30, 10, 20), gtrow("M", 25, 8, 18), f]);
        let freqs = frequencies_for(&group, 5).expect("group has surviving rows");
        assert_eq!(
            freqs.len(),
            3,
            "AC/AF utility is preserved; only sub-counts collapse"
        );
        for fr in &freqs {
            if fr.population == TOTAL_POPULATION {
                continue; // the lone aggregate has nothing to difference against
            }
            assert_eq!(
                fr.allele_count_homozygous, None,
                "{} hom leaked: Total.Hom - M.Hom recovers the absent cell",
                fr.population
            );
        }
    }

    #[test]
    fn frequencies_for_keeps_subcounts_when_all_clear_floor() {
        // No population's sub-count is below the floor, so nothing collapses and every
        // sub-count is served.
        let group = gtgroup(vec![
            gtrow("Total", 30, 10, 20),
            gtrow("M", 25, 6, 14),
            gtrow("F", 15, 8, 7),
        ]);
        let freqs = frequencies_for(&group, 5).expect("surviving rows");
        for f in &freqs {
            assert!(f.allele_count_homozygous.is_some(), "{} hom", f.population);
            assert!(
                f.allele_count_heterozygous.is_some(),
                "{} het",
                f.population
            );
        }
    }

    #[test]
    fn subcount_coherence_invariant_no_nontotal_leak_when_any_below_floor() {
        // A sweep over the whole input space rather than a proptest, since this suite takes
        // no proptest dependency: whenever any emitted population has a Hom count in
        // `1..floor`, no non-Total row exposes its Hom, so subtracting the siblings from
        // Total cannot recover the withheld cell. AC and AN keep every row above the
        // AC-plane floor.
        let floor: u32 = 5;
        let floor_i32: i32 = 5;
        for f_hom in 0..12i32 {
            for m_hom in 0..12i32 {
                let group = gtgroup(vec![
                    gtrow("Total", 60, f_hom + m_hom, 6),
                    gtrow("M", 30, m_hom, 6),
                    gtrow("F", 30, f_hom, 6),
                ]);
                let freqs = frequencies_for(&group, floor).expect("rows survive");
                let any_below = [f_hom, m_hom, f_hom + m_hom]
                    .iter()
                    .any(|&v| (1..floor_i32).contains(&v));
                if any_below {
                    for f in freqs.iter().filter(|f| f.population != "Total") {
                        assert_eq!(
                            f.allele_count_homozygous, None,
                            "leak: {} hom served with f_hom={f_hom} m_hom={m_hom}",
                            f.population
                        );
                    }
                }
            }
        }
    }

    /// Serve time is the backstop for the one rule the build-time floor exempts.
    ///
    /// The floor is applied at two points, both through one implementation
    /// (`core::kanon::classify_row`), so the low tail and the complement tail cannot drift.
    /// One arm is mapped differently: `Uncountable`. Serve time fails it closed, and build
    /// time keeps it, because `AF` is the only required frequency field and dropping the row
    /// at build time would permanently delete every row of an AF-only dataset.
    ///
    /// This test pins that asymmetry, and pins that the effective floor is
    /// `max(build, serve)` with serve time re-applying its rules to every response. Without
    /// it, skipping the serve-time floor because the build already applied one would read as
    /// a speedup rather than a disclosure regression.
    #[test]
    fn the_shared_row_rule_diverges_only_on_the_uncountable_arm() {
        const FLOOR: i64 = 5;

        // (a) No AC, but AF+AN make the carrier count client-derivable. Both floors derive
        //     round(AF*AN) = 2 and suppress.
        let derivable = krow("NoAcButDerivable", None, Some(1000), 0.002);
        assert!(
            !row_survives(&derivable, FLOOR),
            "a below-floor group derivable from AF*AN must be suppressed"
        );

        // (b) No AC and no AN: nothing is derivable, so the group cannot be shown to be at
        //     or above the floor. Build time exempts it; serve time fails closed.
        let uncountable = krow("Uncountable", None, None, 0.01);
        assert!(
            !row_survives(&uncountable, FLOOR),
            "an uncountable row must fail closed at serve time; this is the one arm the \
             build-time floor maps the other way"
        );

        // (c) AC is comfortably above the floor, but the reference carriers (AN - AC = 2)
        //     are below it. Both floors check this.
        let complement = krow("NearFixed", Some(998), Some(1000), 0.998);
        assert!(
            !row_survives(&complement, FLOOR),
            "a rare reference-carrier group must be suppressed even though its AC is above \
             the floor"
        );

        // And the composition itself: a row that both rules accept is served.
        let ordinary = krow("Common", Some(50), Some(1000), 0.05);
        assert!(row_survives(&ordinary, FLOOR));
    }

    #[test]
    fn row_survives_low_tail_suppresses_only_nonempty_groups() {
        // floor 5: a non-empty alt-carrier group below the floor is re-identifiable.
        assert!(!row_survives(&krow("P", Some(4), Some(1000), 0.004), 5));
        assert!(!row_survives(&krow("P", Some(1), Some(1000), 0.001), 5));
        // AC == floor is served (the bound is exclusive).
        assert!(row_survives(&krow("P", Some(5), Some(1000), 0.005), 5));
        // AC == 0 is an empty alt group and survives.
        assert!(row_survives(&krow("P", Some(0), Some(1000), 0.0), 5));
        // AC field absent with AF == 0 (no derivable count) survives.
        assert!(row_survives(&krow("P", None, Some(1000), 0.0), 5));
        // floor 0 => suppression off.
        assert!(row_survives(&krow("P", Some(1), Some(1000), 0.001), 0));
    }

    #[test]
    fn row_survives_reconstructs_ac_from_af_an_when_ac_field_absent() {
        // A population that omits the AC field but still ships AF+AN is not exempt from
        // the floor, because a client can recover a below-floor singleton via
        // AC ≈ round(AF*AN). The floor checks the reconstructed count.
        //
        // round(0.002*1000) = 2 (< 5) -> suppressed.
        assert!(!row_survives(&krow("P", None, Some(1000), 0.002), 5));
        // round(0.02*1000) = 20 (>= 5) -> served.
        assert!(row_survives(&krow("P", None, Some(1000), 0.02), 5));
        // Complement tail also applies to a reconstructed AC: round(0.998*1000) = 998,
        // refc = 1000 - 998 = 2 (< 5) -> a near-fixed variant is suppressed too.
        assert!(!row_survives(&krow("P", None, Some(1000), 0.998), 5));
        // No AN to reconstruct from -> no derivable integer count. Under a floor this fails
        // closed: an AF-only present variant is suppressed, not served.
        assert!(!row_survives(&krow("P", None, None, 0.002), 5));
        // floor 0 => suppression off even for a reconstructable below-floor count.
        assert!(row_survives(&krow("P", None, Some(1000), 0.002), 0));
    }

    #[test]
    fn a_derived_carrier_count_that_rounds_to_zero_is_not_an_empty_group() {
        // The reconstruction `round(AF*AN)` can round down to 0 while `AF > 0` says the
        // variant is present. Reading that 0 as an empty group, which never suppresses,
        // would serve the row.
        //
        // AF = 1.0e-4 with AN = 2000 gives round(0.2) = 0, so a group of exactly one carrier
        // would be published under a floor of 5, and a client reading the emitted AF and AN
        // knows it cannot be zero. That is the existence-channel disclosure the fail-closed
        // arm exists to stop, defeated by a derivation that produces a provably wrong zero.
        assert!(
            !row_survives(&krow("P", None, Some(2000), 1.0e-4), 5),
            "a positive AF cannot describe an empty group: the derived 0 is lost resolution"
        );

        // A genuine empty group, an explicit `AC = 0`, must survive untouched: the derived
        // zero and the reported one are discriminated.
        assert!(
            row_survives(&krow("P", Some(0), Some(2000), 0.0), 5),
            "an explicitly reported AC = 0 is a real empty group and stays served"
        );

        // An explicit AC = 0 that incoherently ships a positive AF still takes the
        // reported-count path rather than the derivation.
        assert!(row_survives(&krow("P", Some(0), Some(2000), 1.0e-4), 5));
    }

    #[test]
    fn af_only_row_fails_closed_under_floor() {
        // An AF-only row has AF present, so the variant exists, but neither AC nor AN, so
        // there is no derivable carrier count and the floor cannot prove the group is at or
        // above it. Under a floor it fails closed and is suppressed, or a boolean/exists
        // query would still confirm a possible singleton. It is served only when suppression
        // is off (floor 0).
        assert!(!row_survives(&krow("P", None, None, 0.001), 5));
        assert!(!row_survives(&krow("P", None, None, 0.5), 1));
        // floor 0 => suppression off, so the uncountable row is served.
        assert!(row_survives(&krow("P", None, None, 0.001), 0));
        // An AF == 0 uncountable row is an empty alt group rather than a present variant.
        // It is never re-identifying and survives, via the `af > 0` guard.
        assert!(row_survives(&krow("P", None, None, 0.0), 5));
    }

    #[test]
    fn alt_carriers_prefers_exact_then_reconstructs_round() {
        // Exact AC wins.
        assert_eq!(
            alt_carriers(&krow("P", Some(7), Some(1000), 0.007)),
            Some(7)
        );
        // AC absent, AF+AN present -> round(AF*AN) to nearest.
        assert_eq!(alt_carriers(&krow("P", None, Some(1000), 0.002)), Some(2));
        assert_eq!(alt_carriers(&krow("P", None, Some(1000), 0.02)), Some(20));
        // AC absent, AF == 0 -> no derivable count.
        assert_eq!(alt_carriers(&krow("P", None, Some(1000), 0.0)), None);
        // AC absent, AN absent -> no derivable count.
        assert_eq!(alt_carriers(&krow("P", None, None, 0.5)), None);
    }

    #[test]
    fn row_survives_complement_tail_suppresses_near_fixed_variants() {
        // refc = AN - AC, floor 5.
        // refc == 2 (998/1000): a re-identifiable reference-carrier group -> dropped.
        assert!(!row_survives(&krow("P", Some(998), Some(1000), 0.998), 5));
        // refc == 5: served (exclusive bound).
        assert!(row_survives(&krow("P", Some(995), Some(1000), 0.995), 5));
        // refc == 0 (fully-fixed, AC == AN): empty reference group -> survives.
        assert!(row_survives(&krow("P", Some(1000), Some(1000), 1.0), 5));
    }

    #[test]
    fn row_survives_reconstructs_complement_from_af_when_an_absent() {
        // AN withheld: refc is still derivable from AC/AF (AF = AC/AN), so the check runs.
        // AF 0.98, AC 100 -> AN ~= 102 -> refc ~= 2 (< 5) -> dropped.
        assert!(!row_survives(&krow("P", Some(100), None, 0.98), 5));
        // AF 0.90, AC 100 -> AN ~= 111 -> refc ~= 11 (>= 5) -> served.
        assert!(row_survives(&krow("P", Some(100), None, 0.90), 5));
    }

    #[test]
    fn row_survives_rounds_reconstructed_an_so_a_true_single_ref_carrier_is_suppressed() {
        // With AN absent, the reconstructed AN rounds to nearest, matching the client's
        // own round(AC/AF), rather than flooring. Row: AC=99, AN omitted, AF=f32(0.99),
        // which widens to 0.99000001. The true AN is 100, so the reference-carrier group is
        // a single re-identifiable individual (refc=1). floor(99/0.99000001) = 99 gives
        // refc=0, which would survive; rounding gives 100, so refc=1 is in 1..5 and the row
        // is suppressed.
        assert_eq!(
            reference_carriers(&krow("Total", Some(99), None, 0.99)),
            Some(1)
        );
        assert!(!row_survives(&krow("Total", Some(99), None, 0.99), 5));
    }

    #[test]
    fn row_survives_suppresses_af_only_positive_rows_fail_closed() {
        // A row with only AF (no AC, no AN) has no derivable integer count, but a positive
        // AF still discloses the variant's presence and rarity, so under a positive floor it
        // is suppressed fail-closed.
        assert!(!row_survives(&krow("P", None, None, 0.0002), 5));
        // A zero-AF no-count row discloses nothing, because the variant does not occur, so
        // it survives.
        assert!(row_survives(&krow("P", None, None, 0.0), 5));
        // With the floor off (the default), AF-only rows survive.
        assert!(row_survives(&krow("P", None, None, 0.0002), 0));
    }

    #[test]
    fn reference_carriers_prefers_an_then_reconstructs() {
        // Exact AN.
        assert_eq!(
            reference_carriers(&krow("P", Some(12), Some(1000), 0.012)),
            Some(988)
        );
        // AC == AN -> empty reference group.
        assert_eq!(
            reference_carriers(&krow("P", Some(1000), Some(1000), 1.0)),
            Some(0)
        );
        // Malformed AN < AC clamps to 0 (never negative).
        assert_eq!(
            reference_carriers(&krow("P", Some(10), Some(4), 1.0)),
            Some(0)
        );
        // AN absent, AC > 0 -> reconstructed from AC/AF (round to nearest): 100/0.98 ~= 102 -> 2.
        assert_eq!(
            reference_carriers(&krow("P", Some(100), None, 0.98)),
            Some(2)
        );
        // AC == 0 with AN present -> Some(AN): the AN-present branch runs before the ac>0 guard.
        assert_eq!(
            reference_carriers(&krow("P", Some(0), Some(1000), 0.0)),
            Some(1000)
        );
        // AC == 0 with AN absent -> None (reference group is the whole cohort; AF == 0).
        assert_eq!(reference_carriers(&krow("P", Some(0), None, 0.0)), None);
        // AC absent with AN present and AF == 0 -> Some(AN), the same answer as the
        // `AC == 0` twin above. `AF == 0` with `AN` present means `AC == 0` unambiguously,
        // so the reference group is the whole cohort and the complement tail is answerable.
        // Answering `None` here would leave the complement tail unreachable for this shape
        // and serve a below-floor reference cohort, while the identical wire content with
        // `AC` spelled `0` was suppressed.
        assert_eq!(
            reference_carriers(&krow("P", None, Some(1000), 0.0)),
            Some(1000)
        );
    }

    #[test]
    fn reference_carriers_none_when_an_absent_and_ac_or_af_degenerate() {
        // AN absent and AC == 0 with a positive AF: no valid complement to reconstruct,
        // via the `ac_i32 > 0` guard. A `>=` there would enter the branch and emit Some(0)
        // instead of None. The AC==0 case above uses AF==0, which the `af > 0.0` guard
        // rejects first, so it cannot distinguish that.
        assert_eq!(reference_carriers(&krow("P", Some(0), None, 0.5)), None);
        // AN absent and AC > 0 with AF == 0: AN = AC/AF is not reconstructable, via the
        // `af > 0.0` guard. A `>=` there would divide by zero and emit a saturated
        // i64::MAX-derived count instead of None.
        assert_eq!(reference_carriers(&krow("P", Some(10), None, 0.0)), None);
    }

    #[test]
    fn pos_window_is_the_exact_pruning_superset() {
        // The row-group pruning window is a correctness-adjacent contract. A wider window
        // is still correct, so the differential scan proptest cannot observe a loosened one,
        // but a narrower window would prune real matches. Pin the exact bounds so an
        // arithmetic slip (`-` becoming `+` or `/`) is caught.
        let caps = ParquetCaps {
            max_ref_len: 5,
            ..Default::default()
        };
        let seq = pos_window(
            &QueryKind::Sequence {
                pos: 100,
                ref_: "A".to_owned(),
                alt: "T".to_owned(),
                predicates: Predicates::default(),
            },
            &caps,
        );
        assert_eq!((seq.lo, seq.hi), (100, 100));

        // lo = start - max_ref_len (long-REF lookback); hi = end - 1 (half-open).
        let range = pos_window(
            &QueryKind::Range {
                start: 100,
                end: 200,
                predicates: Predicates::default(),
            },
            &caps,
        );
        assert_eq!((range.lo, range.hi), (95, 199));

        let bracket = pos_window(
            &QueryKind::Bracket {
                s_min: 100,
                s_max: 150,
                e_min: 160,
                e_max: 200,
                predicates: Predicates::default(),
            },
            &caps,
        );
        assert_eq!((bracket.lo, bracket.hi), (100, 150));

        let empty = pos_window(&QueryKind::Empty, &caps);
        assert_eq!((empty.lo, empty.hi), (1, 0));
    }

    #[test]
    fn bracket_pos_window_clamps_scan_to_e_max_not_s_max() {
        // Span-cap bypass: a Bracket with a tiny measured span (e_max near s_min) but
        // s_max pushed to i32::MAX must not yield a prune window spanning all POS, which
        // would disable row-group pruning and force a full decode and decrypt. The
        // scan upper bound is min(s_max, e_max) because a match needs v_end <= e_max and
        // v_end >= v_start, so POS > e_max can never match.
        let caps = ParquetCaps::default();
        let w = pos_window(
            &QueryKind::Bracket {
                s_min: 100,
                s_max: i64::from(i32::MAX),
                e_min: 100,
                e_max: 200,
                predicates: Predicates::default(),
            },
            &caps,
        );
        assert_eq!((w.lo, w.hi), (100, 200), "clamped to e_max, not s_max");
    }

    /// The count pass (`group_survives`) must agree with materialization
    /// (`frequencies_for`) at every floor, or `resultsCount`, driven by the former, drifts
    /// from `results[]`, driven by the latter. Out-of-window groups are never materialized,
    /// so nothing else compares the two.
    #[test]
    fn group_survives_agrees_with_frequencies_for() {
        let group = VariantGroup {
            pos: 100,
            ref_: "T".to_owned(),
            alt: "C".to_owned(),
            vt: Vt::Snp,
            // Two populations: AC 3 and AC 12.
            rows: vec![arow(100, "FIN", 3), arow(100, "Total", 12)],
        };
        for floor in [0u32, 1, 3, 4, 12, 13, 100] {
            assert_eq!(
                group_survives(&group, floor),
                frequencies_for(&group, floor).is_some(),
                "survival/count pass disagrees with materialization at floor {floor}"
            );
        }
    }

    /// The count pass and materialization must still agree once the complement tail
    /// and `AC == 0` (1b) rows are in play — otherwise `resultsCount` drifts from
    /// `results[]`.
    #[test]
    fn survival_agreement_holds_for_complement_and_empty_tails() {
        let group = VariantGroup {
            pos: 100,
            ref_: "T".to_owned(),
            alt: "C".to_owned(),
            vt: Vt::Snp,
            rows: vec![
                krow("Rare", Some(2), Some(1000), 0.002),        // low tail
                krow("NearFixed", Some(998), Some(1000), 0.998), // complement tail
                krow("Absent", Some(0), Some(1000), 0.0),        // empty alt group, kept
                krow("Common", Some(50), Some(1000), 0.05),      // clearly served
            ],
        };
        for floor in [0u32, 1, 3, 5, 50, 51, 1000] {
            assert_eq!(
                group_survives(&group, floor),
                frequencies_for(&group, floor).is_some(),
                "count pass disagrees with materialization at floor {floor}"
            );
        }
        // At floor 5, Rare (AC 2) and NearFixed (refc 2) are suppressed. A population was
        // suppressed and this group carries no aggregate `Total` to fall back to, so the
        // cross-partition collapse drops the whole group: no surviving sibling (Absent
        // or Common) may be served alongside a suppressed cell, because a finer partition
        // could reconstruct it. Materialization is None and the count pass agrees. The
        // tail-suppression logic itself is covered by the `row_survives_*` unit tests.
        assert!(
            frequencies_for(&group, 5).is_none(),
            "a suppressed cell with no Total anchor collapses the group"
        );
        assert!(!group_survives(&group, 5));
    }

    #[test]
    fn emittable_rows_collapses_a_partial_marginal_set_with_below_floor_remainder() {
        // Defence in depth for a dataset built without the build-time collapse: a variant
        // whose per-sex axis is missing `F` (Total=14, M=13) lets a client recover
        // `F = 14 - 13 = 1`, a below-floor singleton, even though every present row clears
        // the floor. The gate must collapse to `Total` only.
        let group = gtgroup(vec![arow(100, "Total", 14), arow(100, "M", 13)]);
        let pops: Vec<&str> = emittable_rows(&group, 5)
            .iter()
            .map(|r| r.population.as_str())
            .collect();
        assert_eq!(pops, vec!["Total"]);
    }

    #[test]
    fn emittable_rows_collapses_a_partial_marginal_set_on_the_complement_tail() {
        // The same defence on the complement tail. `row_survives` suppresses a below-floor
        // reference-carrier group (`AN - AC`) as it does a below-floor alt group, because a
        // rare non-carrier is as re-identifying as a rare carrier, so the
        // incomplete-partition check must cover both planes.
        //
        // Total: refc = 100 - 50 = 50. M: refc = 60 - 12 = 48. The alt remainder is
        // 50 - 12 = 38, safely above the floor, so the alt-plane check stays silent, while
        // the complement remainder is 50 - 48 = 2, a below-floor non-carrier group the
        // client recovers by subtraction.
        let group = gtgroup(vec![
            krow("Total", Some(50), Some(100), 0.5),
            krow("M", Some(12), Some(60), 0.2),
        ]);
        let pops: Vec<&str> = emittable_rows(&group, 5)
            .iter()
            .map(|r| r.population.as_str())
            .collect();
        assert_eq!(pops, vec!["Total"]);
    }

    #[test]
    fn emittable_rows_keeps_a_complete_marginal_set() {
        // A complete axis (`M + F == Total`) leaves no recoverable remainder, so nothing
        // collapses.
        let group = gtgroup(vec![
            arow(100, "Total", 20),
            arow(100, "M", 13),
            arow(100, "F", 7),
        ]);
        let mut pops: Vec<&str> = emittable_rows(&group, 5)
            .iter()
            .map(|r| r.population.as_str())
            .collect();
        pops.sort_unstable();
        assert_eq!(pops, vec!["F", "M", "Total"]);
    }

    #[test]
    fn emittable_rows_collapses_a_nested_countrysex_leak_against_the_sex_marginal() {
        // The CountrySex cells partition their parent Sex marginal, not just Total. Here
        // `Total = 100`, `M = 10`, `EE_M = 8`, and `FI_M` is withheld as below-floor. Every
        // axis sums far below Total (remainder ~90, safe), so the Total anchor stays
        // silent, but `M - EE_M = 2` recovers the withheld `FI_M` in one query. The nested
        // anchor must catch it and collapse to Total.
        let group = gtgroup(vec![
            arow(100, "Total", 100),
            arow(100, "M", 10),
            arow(100, "EE_M", 8),
        ]);
        let pops: Vec<&str> = emittable_rows(&group, 5)
            .iter()
            .map(|r| r.population.as_str())
            .collect();
        assert_eq!(
            pops,
            vec!["Total"],
            "M - EE_M = 2 recovers a below-floor FI_M; the nested gate must collapse"
        );
    }

    #[test]
    fn emittable_rows_collapses_a_nested_countrysex_leak_against_the_country_marginal() {
        // The mirror on the Country axis: `FI = 10`, `FI_M = 8` present, `FI_F` withheld.
        // `FI - FI_M = 2` recovers the below-floor `FI_F`. No Sex marginal is present, so
        // only the Country parent anchors, exercising that half of the nesting on its own.
        let group = gtgroup(vec![
            arow(100, "Total", 100),
            arow(100, "FI", 10),
            arow(100, "FI_M", 8),
        ]);
        let pops: Vec<&str> = emittable_rows(&group, 5)
            .iter()
            .map(|r| r.population.as_str())
            .collect();
        assert_eq!(
            pops,
            vec!["Total"],
            "FI - FI_M = 2 recovers a below-floor FI_F"
        );
    }

    #[test]
    fn emittable_rows_keeps_a_complete_nested_breakdown() {
        // A CountrySex breakdown that fully accounts for its parent Sex marginal
        // (`M = EE_M + FI_M = 12`) leaves remainder 0 and must not be over-collapsed. Total
        // is large enough that no axis trips the Total anchor either.
        let group = gtgroup(vec![
            arow(100, "Total", 100),
            arow(100, "M", 12),
            arow(100, "EE_M", 6),
            arow(100, "FI_M", 6),
        ]);
        let mut pops: Vec<&str> = emittable_rows(&group, 5)
            .iter()
            .map(|r| r.population.as_str())
            .collect();
        pops.sort_unstable();
        assert_eq!(
            pops,
            vec!["EE_M", "FI_M", "M", "Total"],
            "a complete nested set discloses no remainder and must survive"
        );
    }

    #[test]
    fn emittable_rows_keeps_a_partial_breakdown_with_a_safe_remainder() {
        // A partial breakdown whose unreported remainder is itself at or above the floor
        // (Total=100, FI=40, remainder 60) discloses only a k-anon-safe aggregate, so it
        // must not be over-collapsed.
        let group = gtgroup(vec![arow(100, "Total", 100), arow(100, "FI", 40)]);
        let mut pops: Vec<&str> = emittable_rows(&group, 5)
            .iter()
            .map(|r| r.population.as_str())
            .collect();
        pops.sort_unstable();
        assert_eq!(pops, vec!["FI", "Total"]);
    }

    /// Cross-partition differencing: the node emits a `Total` plus a per-sex and
    /// per-country breakdown that sums to it, and [`row_survives`] drops each below-floor
    /// cell independently. That leaks: with `Total` (6) and `M` (5) served while `F` (1)
    /// is suppressed, a client recovers `F = Total - M = 1`. When the floor suppresses any
    /// population, the group collapses to `Total` only.
    #[test]
    fn frequencies_for_collapses_to_total_when_a_sibling_is_suppressed() {
        let group = VariantGroup {
            pos: 100,
            ref_: "T".to_owned(),
            alt: "C".to_owned(),
            vt: Vt::Snp,
            rows: vec![
                krow("Total", Some(6), Some(200), 0.03),
                krow("M", Some(5), Some(100), 0.05),
                krow("F", Some(1), Some(100), 0.01), // singleton: suppressed at floor 5
            ],
        };
        let freqs = frequencies_for(&group, 5).expect("Total survives, so the group is served");
        let pops: Vec<&str> = freqs.iter().map(|f| f.population.as_str()).collect();
        assert_eq!(
            pops,
            vec!["Total"],
            "a suppressed sibling (F=1) must collapse the group to Total, else F = Total(6) - M(5)"
        );
    }

    /// The collapse must not over-fire: when no population is below the floor, the full
    /// breakdown is served unchanged.
    #[test]
    fn frequencies_for_keeps_full_breakdown_when_none_suppressed() {
        let group = VariantGroup {
            pos: 100,
            ref_: "T".to_owned(),
            alt: "C".to_owned(),
            vt: Vt::Snp,
            rows: vec![
                krow("Total", Some(20), Some(200), 0.10),
                krow("M", Some(12), Some(100), 0.12),
                krow("F", Some(8), Some(100), 0.08),
            ],
        };
        let freqs = frequencies_for(&group, 5).expect("all populations clear the floor");
        let pops: Vec<&str> = freqs.iter().map(|f| f.population.as_str()).collect();
        assert_eq!(
            pops,
            vec!["F", "M", "Total"],
            "no over-suppression when nothing is below floor"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1024))]

        /// The single-group k-anonymity differencing invariant, generalising the two
        /// `frequencies_for_*` example tests above. For any variant group of a `Total` plus
        /// marginal sub-populations that partition it, so that their AC and AN sum to the
        /// `Total`, at any floor, the served frequencies must never let a client recover a
        /// below-floor cell by subtracting the served siblings from the served `Total`:
        ///
        ///   (a) every served cell is itself at or above the floor on both tails, and
        ///   (b) if any population was dropped, only `Total` remains, so no sibling is left
        ///       to subtract against. That is the `emittable_rows` collapse to `Total`.
        ///
        /// Scope: the single-group attack. The residual multi-variant differencing over a
        /// linear system is out of scope on `emittable_rows`, where differential privacy is
        /// the intended complete defence, and is not asserted here. `PROPTEST_CASES` raises
        /// the case count; the property is cheap, because `frequencies_for` is pure.
        #[test]
        fn no_single_group_differencing_recovers_a_below_floor_cell(
            floor in 2u32..8,
            marginals in prop::collection::vec(0i32..12, 2..=4),
            an_per in 200i32..2000,
        ) {
            // Fixed marginal names: `format!` is unavailable inside `proptest!`.
            const NAMES: [&str; 4] = ["P0", "P1", "P2", "P3"];
            // Marginals partition one cohort, so Total is their sum in both AC and AN,
            // which makes the subtraction attack `Pi = Total - Σ(other Pj)` real. The
            // suppression path ignores `af` when AC and AN are both present, reading the
            // exact AC and AN, so a constant placeholder is fine.
            let total_ac: i32 = marginals.iter().sum();
            let count = i32::try_from(marginals.len()).unwrap_or(1);
            let total_an: i32 = an_per * count;
            let mut rows = vec![krow("Total", Some(total_ac), Some(total_an), 0.01)];
            for (i, &ac) in marginals.iter().enumerate() {
                rows.push(krow(NAMES[i], Some(ac), Some(an_per), 0.01));
            }
            let group = VariantGroup {
                pos: 100,
                ref_: "T".to_owned(),
                alt: "C".to_owned(),
                vt: Vt::Snp,
                rows,
            };

            if let Some(freqs) = frequencies_for(&group, floor) {
                let fl = i64::from(floor);
                // (a) No served cell is a below-floor singleton on either tail.
                for f in &freqs {
                    if let (Some(ac), Some(an)) = (f.allele_count, f.allele_number) {
                        let ac = i64::try_from(ac).unwrap_or(i64::MAX);
                        let an = i64::try_from(an).unwrap_or(i64::MAX);
                        prop_assert!(
                            !(1..fl).contains(&ac),
                            "served a below-floor alt cell: AC={} floor={}",
                            ac, floor
                        );
                        prop_assert!(
                            !(1..fl).contains(&(an - ac)),
                            "served a below-floor ref cell: refc={} floor={}",
                            an - ac, floor
                        );
                    }
                }
                // (b) Collapse coherence: a dropped population leaves only `Total`.
                let emitted: std::collections::HashSet<&str> =
                    freqs.iter().map(|f| f.population.as_str()).collect();
                let dropped_any = group
                    .rows
                    .iter()
                    .any(|r| !emitted.contains(r.population.as_str()));
                if dropped_any {
                    prop_assert!(
                        emitted.iter().all(|&p| p == TOTAL_POPULATION),
                        "a cell was dropped but non-Total siblings remain (differencing risk)"
                    );
                }
            }
        }
    }

    /// `resultsCount` is the full surviving-group count, independent of paging. The
    /// `results[]` slice is the `(skip, limit)` window. A dataset with survivors but an
    /// empty page is still present; a dataset with zero survivors is a miss.
    #[test]
    fn assemble_paginates_without_changing_results_count() {
        let cfg = manifest_cfg(0);
        let beacon = BeaconParams {
            id: "b".to_owned(),
            name: "n".to_owned(),
            ..BeaconParams::default()
        };
        // Three distinct variant groups (POS 100/200/300), each a single population.
        let rows = || {
            vec![
                arow(100, "Total", 10),
                arow(200, "Total", 10),
                arow(300, "Total", 10),
            ]
        };
        // The scan applies the page window, so the test builds the page with it.
        let assemble = |skip: u64, limit: u64| {
            let floor = effective_floor(&cfg, &beacon);
            let page =
                DatasetPage::from_rows(rows(), PageSpec { floor, skip, limit }).expect("page");
            assemble_dataset(
                ("ds".to_owned(), &cfg, None, "3", page),
                &beacon,
                "http://x",
            )
        };

        // Full page: all three groups returned, count == 3.
        let rs = assemble(0, 10);
        assert!(rs.exists);
        assert_eq!(rs.results_count, 3);
        assert_eq!(rs.results.len(), 3);

        // skip=1, limit=1: count still 3, one entry, and it is the second group (start
        // 200), because groups are ordered by (POS, REF, ALT).
        let rs = assemble(1, 1);
        assert_eq!(
            rs.results_count, 3,
            "count must not depend on the page window"
        );
        assert_eq!(rs.results.len(), 1);
        assert_eq!(rs.results[0].variation.location.interval.start.value, 200);

        // skip past the end: the dataset is still present with the true count, empty page.
        let rs = assemble(5, 10);
        assert_eq!(rs.results_count, 3);
        assert!(rs.results.is_empty());

        // Every population suppressed by the floor gives zero survivors, so the dataset is
        // a per-dataset miss (`exists:false`, count 0) rather than an omission: it is still
        // named, so an `ALL` or `MISS` query can account for it.
        let high = manifest_cfg(1000);
        let high_floor = effective_floor(&high, &beacon);
        let miss_page = DatasetPage::from_rows(
            rows(),
            PageSpec {
                floor: high_floor,
                skip: 0,
                limit: 10,
            },
        )
        .expect("page");
        let miss = assemble_dataset(
            ("ds".to_owned(), &high, None, "3", miss_page),
            &beacon,
            "http://x",
        );
        assert!(
            !miss.exists,
            "a dataset with zero survivors is exists:false"
        );
        assert_eq!(miss.results_count, 0);
        assert!(miss.results.is_empty());
    }

    /// Assembly suppresses under the configured floor, not the floor the page happens to
    /// carry: a page built with `PageSpec::everything()` (floor 0) against a manifest floor
    /// of 5 must not emit its below-floor row. A `debug_assert_eq!` on `page.floor` would
    /// not cover this, because the release binary compiles it out.
    #[test]
    fn assembly_applies_the_configured_floor_not_the_pages() {
        let cfg = manifest_cfg(5);
        let beacon = BeaconParams {
            id: "b".to_owned(),
            name: "n".to_owned(),
            ..BeaconParams::default()
        };
        let page = DatasetPage::from_rows(vec![arow(100, "Total", 1)], PageSpec::everything())
            .expect("page");
        assert_eq!(page.floor, 0, "this page is built under no floor");

        let rs = assemble_dataset(
            ("ds".to_owned(), &cfg, None, "3", page),
            &beacon,
            "http://x",
        );
        assert!(
            rs.results.is_empty(),
            "AC=1 is below the configured floor of 5 and must not be served whatever floor \
             the page carries; got {} result(s)",
            rs.results.len()
        );
        // The count and the existence bit are suppressed with it. Asserting on `results`
        // alone would pass for an answer of `exists: true, resultsCount: 1, results: []`,
        // which discloses that a below-floor variant exists at the locus.
        assert_eq!(
            rs.results_count, 0,
            "resultsCount must respect the configured floor"
        );
        assert!(!rs.exists, "exists must respect the configured floor");

        // A low-floor page whose window holds a genuine survivor still counts it: the
        // fallback is the in-window survivors under the configured floor, not zero.
        let mixed = DatasetPage::from_rows(
            vec![arow(100, "Total", 1), arow(200, "Total", 10)],
            PageSpec::everything(),
        )
        .expect("page");
        let rs = assemble_dataset(
            ("ds".to_owned(), &cfg, None, "3", mixed),
            &beacon,
            "http://x",
        );
        assert_eq!(rs.results.len(), 1, "AC=10 survives the floor of 5");
        assert_eq!(rs.results_count, 1);
        assert!(rs.exists);
    }

    /// A dataset whose stored assembly has no reference accession is served as a miss,
    /// never as a location without its reference sequence.
    ///
    /// Unreachable by construction: ingest admits only `GRCh37` and `GRCh38` and only
    /// canonical contigs, and a dataset is scanned only for the known assembly the request
    /// selected.
    /// If it ever fires, the store disagrees with its manifest. Fail closed for that
    /// dataset alone: serve it as a miss and log at `error`, rather than emit a VRS location
    /// whose `sequence_id` is missing or fabricated.
    #[test]
    fn a_dataset_whose_assembly_has_no_accession_is_served_as_a_miss_not_a_bare_location() {
        // `DatasetScan` carries `&ManifestConfig`, so the invariant is broken on the owned
        // config the scan borrows, rather than through a test-only setter on the scan.
        let mut cfg = manifest_cfg(0);
        cfg.assembly.reference = "T2T-CHM13".to_owned();
        let beacon = BeaconParams {
            id: "b".to_owned(),
            name: "n".to_owned(),
            ..BeaconParams::default()
        };
        let floor = effective_floor(&cfg, &beacon);
        let page = DatasetPage::from_rows(
            vec![arow(100, "Total", 10)],
            PageSpec {
                floor,
                skip: 0,
                limit: 10,
            },
        )
        .expect("page");
        assert_eq!(
            page.total, 1,
            "the group survives the floor: only the accession is missing"
        );

        let rs = assemble_dataset(
            ("ds".to_owned(), &cfg, None, "3", page),
            &beacon,
            "http://x",
        );

        assert!(!rs.exists, "an accession-less dataset must not claim a hit");
        assert!(
            rs.results.is_empty(),
            "no entry may be built without a sequence_id; got {} result(s)",
            rs.results.len()
        );
        assert_eq!(rs.results_count, 0);
        // The miss still names the dataset, as the zero-survivors miss does, so an `ALL` or
        // `MISS` query can account for it.
        assert_eq!(rs.id, "ds");
        assert_eq!(rs.set_type, "dataset");
        assert_eq!(rs.gdi_dataset_info.assembly, "T2T-CHM13");
        assert_eq!(rs.gdi_dataset_info.min_allele_count, floor);
    }

    /// The selected files as a flat, ordered name list. `select_files` returns them grouped
    /// per block; these tests assert on the resulting order and membership.
    fn selected_names(blocks: &[BlockFiles]) -> Vec<String> {
        blocks
            .iter()
            .flat_map(|b| &b.files)
            .map(|p| p.file_name().unwrap().to_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn select_files_groups_several_files_of_one_block_together() {
        // A per-population split puts more than one file in a block, since each VCF stamps
        // its own vcfid. The grouping is what tells `scan_dataset_counts` it must merge
        // before folding, so pin it: one entry per block, ascending, with the block's files
        // inside it.
        let dir = tempfile::tempdir().unwrap();
        for name in [
            "allele-freq.chr3.9.br10000000.bbbb000000000000.parquet",
            "allele-freq.chr3.9.br10000000.aaaa000000000000.parquet",
            "allele-freq.chr3.10.br10000000.cccc000000000000.parquet",
        ] {
            std::fs::File::create(dir.path().join(name)).unwrap();
        }
        let kind = QueryKind::Range {
            start: 0,
            end: 2_000_000_000,
            predicates: Predicates::default(),
        };
        let blocks =
            select_files(dir.path(), "3", 10_000_000, &kind, &ParquetCaps::default()).unwrap();

        let shape: Vec<(u64, usize)> = blocks.iter().map(|b| (b.block, b.files.len())).collect();
        assert_eq!(
            shape,
            vec![(9, 2), (10, 1)],
            "blocks must be ascending (9 before 10, not lexicographic) and a block's files \
             grouped under it"
        );
        // Within a block the order is still deterministic (by name).
        assert_eq!(
            selected_names(&blocks)[0],
            "allele-freq.chr3.9.br10000000.aaaa000000000000.parquet"
        );
    }

    #[test]
    fn select_files_finds_block_for_sequence() {
        let dir = covid_dataset();
        let kind = QueryKind::Sequence {
            pos: 45_823_239,
            ref_: "T".into(),
            alt: "C".into(),
            predicates: Predicates::default(),
        };
        let caps = ParquetCaps::default();
        let names =
            selected_names(&select_files(dir.path(), "3", 10_000_000, &kind, &caps).unwrap());
        assert!(!names.is_empty(), "expected the chr3 block-4 file");
        for name in &names {
            assert!(
                name.starts_with("allele-freq.chr3.4.br10000000."),
                "unexpected file {name}"
            );
        }
        // A different chromosome selects nothing.
        assert!(
            select_files(dir.path(), "1", 10_000_000, &kind, &caps)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn select_files_bracket_clamps_block_enumeration_to_e_max() {
        // Span-cap bypass on the block-enumeration side: a Bracket with s_max at i32::MAX
        // but a small e_max must enumerate blocks only up to e_max, not every block of the
        // chromosome, which would select every file for a full decode. POS > e_max can
        // never match. Empty files suffice, because select_files matches on name only.
        let dir = tempfile::tempdir().unwrap();
        let br = 100u32;
        for block in [0u64, 5] {
            std::fs::write(
                dir.path()
                    .join(format!("allele-freq.chr1.{block}.br{br}.abc.parquet")),
                b"",
            )
            .unwrap();
        }
        let kind = QueryKind::Bracket {
            s_min: 0,
            s_max: i64::from(i32::MAX),
            e_min: 0,
            e_max: 50, // within block 0 (POS 0..99); block 5 (POS 500..599) is past e_max
            predicates: Predicates::default(),
        };
        let caps = ParquetCaps::default();
        let names = selected_names(&select_files(dir.path(), "1", br, &kind, &caps).unwrap());
        assert_eq!(
            names,
            vec!["allele-freq.chr1.0.br100.abc.parquet".to_owned()],
            "only block 0 (<= e_max) is enumerated, not block 5: {names:?}"
        );
    }

    #[test]
    fn select_files_errors_on_unreadable_dir() {
        // A `read_dir` failure, here a non-existent directory, must surface as a
        // `CoreError::Io` rather than be swallowed into an empty file list. Otherwise an
        // infrastructure fault such as bad permissions or a stale mount on a published
        // dataset would answer `exists:false` with a 200 instead of the expected 500.
        let kind = QueryKind::Sequence {
            pos: 100,
            ref_: "T".into(),
            alt: "C".into(),
            predicates: Predicates::default(),
        };
        let caps = ParquetCaps::default();
        let missing = Path::new("/nonexistent-gdi-node-standalone-dataset-dir");
        let err = select_files(missing, "1", 10_000_000, &kind, &caps)
            .expect_err("an unreadable dataset dir must be an error, not an empty list");
        std::assert_matches!(
            err,
            gdi_node_standalone_core::error::CoreError::Io(_),
            "expected CoreError::Io, got {err:?}"
        );
    }

    #[test]
    fn select_files_rejects_excessive_block_span() {
        // A provider-controlled `block_range = 1` plus a wide coordinate span would
        // enumerate about 2.1e9 blocks. `select_files` fails closed with `QueryTooLarge`
        // (HTTP 400) before enumerating them. The error returns before `read_dir`, so an
        // empty directory is fine here.
        let dir = tempfile::tempdir().unwrap();
        let kind = QueryKind::Range {
            start: 0,
            end: i64::from(i32::MAX),
            predicates: Predicates::default(),
        };
        let caps = ParquetCaps::default();
        let err = select_files(dir.path(), "1", 1, &kind, &caps)
            .expect_err("a pathological blockRange=1 wide query must be rejected, not OOM");
        assert_eq!(
            err.class(),
            gdi_node_standalone_core::error::ErrorClass::QueryTooLarge,
            "expected QueryTooLarge (400), got {err:?}"
        );
        assert!(
            format!("{err}").contains("storage blocks"),
            "expected the block-span detail, got {err}"
        );

        // A legitimate wide query at the default block_range enumerates a few blocks and is
        // unaffected by the ceiling.
        select_files(dir.path(), "1", 10_000_000, &kind, &caps)
            .expect("a normal blockRange must not trip the ceiling");
    }

    #[test]
    fn range_lookback_scales_with_max_ref_len() {
        // The Range lookback is `caps.max_ref_len`, not a fixed constant. A range
        // starting just inside block 1 must also select block 0 once the cap is
        // large enough that a long variant could start in block 0 and overlap.
        let dir = covid_dataset();
        // Touch empty block-0 and block-1 files so selection can return them. The file
        // content is irrelevant: select_files only does block math and name matching.
        let br: u32 = 1_000_000;
        for block in [0_u64, 1] {
            let name = format!("allele-freq.chr3.{block}.br{br}.deadbeef.parquet");
            std::fs::write(dir.path().join(name), b"").unwrap();
        }
        // A range starting 50_000 bp into block 1 (beyond the default 10_000 bp
        // lookback, so the default cap stays within block 1).
        let kind = QueryKind::Range {
            start: i64::from(br) + 50_000,
            end: i64::from(br) + 50_100,
            predicates: Predicates::default(),
        };

        // Default cap (10_000 bp lookback): 50_000 bp into the block does not reach block
        // 0, so only block 1 is selected.
        let small = ParquetCaps::default();
        let blocks_small =
            selected_names(&select_files(dir.path(), "3", br, &kind, &small).unwrap());
        assert!(blocks_small.iter().any(|n| n.contains(".1.")));
        assert!(
            !blocks_small.iter().any(|n| n.contains(".0.")),
            "default lookback must not reach block 0: {blocks_small:?}"
        );

        // Raised cap (100_000 bp lookback, past the 50_000 bp offset): block 0 is selected,
        // so the lookback tracks `max_ref_len`.
        let big = ParquetCaps {
            max_ref_len: 100_000,
            ..ParquetCaps::default()
        };
        let blocks_big = selected_names(&select_files(dir.path(), "3", br, &kind, &big).unwrap());
        assert!(
            blocks_big.iter().any(|n| n.contains(".0.")),
            "raised max_ref_len must widen the lookback to block 0: {blocks_big:?}"
        );
    }

    #[test]
    fn range_scan_excludes_variants_abutting_the_half_open_boundaries() {
        // The Range overlap test is `v_start < end && v_end > start` for the half-open
        // interval `[start, end)`. A variant whose span abuts a boundary without entering
        // the interval is excluded:
        //   * left-abutting  (v_end == start): entirely left of `[start, end)`
        //   * right-abutting (v_start == end): starts exactly at the excluded upper bound
        // Both sit inside the row-group `pos_window` prune band (lo = start − max_ref_len,
        // hi = end − 1) alongside an interior variant, so the whole group is kept and the
        // `keep` predicate rather than pruning is what excludes them. That catches a `<`
        // loosened to `<=` or `==` and a `>` loosened to `>=` or `==`, either of which would
        // return an abutting variant, while the interior variant is the positive control.
        //
        // Stored POS is 0-based (VCF POS − 1); REF length 1 ⇒ v_end = v_start + 1.
        // Query `[start, end) = [1000, 2000)`:
        //   VCF 1000 → pos 999,  v_end 1000 == start  (left-abutting, excluded)
        //   VCF 1501 → pos 1500, inside              (interior, returned)
        //   VCF 2001 → pos 2000 == end               (right-abutting, excluded)
        let dir = dataset_from_vcf(
            "3\t1000\t.\tA\tG\t.\t.\tAF=0.5;AC=5;AN=10\n\
3\t1501\t.\tA\tG\t.\t.\tAF=0.5;AC=5;AN=10\n\
3\t2001\t.\tA\tG\t.\t.\tAF=0.5;AC=5;AN=10\n",
        );
        let rows = scan_dataset(
            dir.path(),
            "3",
            10_000_000,
            &QueryKind::Range {
                start: 1000,
                end: 2000,
                predicates: Predicates::default(),
            },
            &ParquetCaps::default(),
            &DatasetDecryptor::plaintext(),
            u64::MAX,
            &mut UnboundedRetention,
        )
        .unwrap();
        let positions: std::collections::BTreeSet<i32> = rows.iter().map(|r| r.pos).collect();
        assert!(
            positions.contains(&1500),
            "the interior variant (pos 1500) must be returned: {positions:?}"
        );
        assert!(
            !positions.contains(&999),
            "the left-abutting variant (pos 999, v_end == start) must be excluded: {positions:?}"
        );
        assert!(
            !positions.contains(&2000),
            "the right-abutting variant (pos 2000, v_start == end) must be excluded: {positions:?}"
        );
    }

    #[test]
    #[expect(
        clippy::float_cmp,
        reason = "finite_af returns exact sentinels (0.0/1.0) or bit-preserved clamp values, so exact equality is intended"
    )]
    fn finite_af_sanitizes_non_finite_and_out_of_range() {
        // A valid in-range AF is preserved bit-exactly.
        assert_eq!(finite_af(0.42_f32), 0.42_f32);
        assert_eq!(finite_af(0.0_f32), 0.0_f32);
        assert_eq!(finite_af(1.0_f32), 1.0_f32);
        // Non-finite maps to 0.0, or serde_json would emit `null` for the required field.
        assert_eq!(finite_af(f32::NAN), 0.0_f32);
        assert_eq!(finite_af(f32::INFINITY), 1.0_f32);
        assert_eq!(finite_af(f32::NEG_INFINITY), 0.0_f32);
        // Out-of-range clamped.
        assert_eq!(finite_af(-0.5_f32), 0.0_f32);
        assert_eq!(finite_af(1.5_f32), 1.0_f32);
    }

    #[test]
    fn predicate_min_len_bound_is_inclusive() {
        // Bound is on len(ALT) (the alternate-allele length), inclusive.
        let p = Predicates {
            ref_: None,
            alt: None,
            variant_type: None,
            min_len: Some(2),
            max_len: None,
        };
        assert!(matches_predicates(&p, "A", "AA", "SNP")); // len(ALT) 2 == min -> passes
        assert!(matches_predicates(&p, "A", "AAA", "SNP")); // len(ALT) 3 > min
        assert!(!matches_predicates(&p, "A", "T", "SNP")); // len(ALT) 1 < min
    }

    #[test]
    fn predicate_max_len_bound_is_inclusive() {
        let p = Predicates {
            ref_: None,
            alt: None,
            variant_type: None,
            min_len: None,
            max_len: Some(2),
        };
        assert!(matches_predicates(&p, "A", "AA", "SNP")); // len(ALT) 2 == max -> passes
        assert!(matches_predicates(&p, "A", "T", "SNP")); // len(ALT) 1 < max
        assert!(!matches_predicates(&p, "A", "AAA", "SNP")); // len(ALT) 3 > max
    }

    #[test]
    fn predicate_field_equality_and_window() {
        // Inclusive window [2, 2] on len(ALT): only len(ALT) == 2 survives.
        let window = Predicates {
            ref_: None,
            alt: None,
            variant_type: None,
            min_len: Some(2),
            max_len: Some(2),
        };
        assert!(matches_predicates(&window, "A", "AA", "SNP"));
        assert!(!matches_predicates(&window, "A", "T", "SNP"));
        assert!(!matches_predicates(&window, "A", "AAA", "SNP"));

        // ref/alt are exact-equality and variant_type is set-membership; None = no
        // constraint. A single-label set is a plain equality check.
        let exact = Predicates {
            ref_: Some("A".to_owned()),
            alt: Some("T".to_owned()),
            variant_type: Some(vec!["SNP".to_owned()]),
            min_len: None,
            max_len: None,
        };
        assert!(matches_predicates(&exact, "A", "T", "SNP"));
        assert!(!matches_predicates(&exact, "A", "C", "SNP")); // alt mismatch
        assert!(!matches_predicates(&exact, "G", "T", "SNP")); // ref mismatch
        assert!(!matches_predicates(&exact, "A", "T", "DEL")); // vt mismatch

        // The indel umbrella set matches any length-changing type but not a substitution.
        let indel = Predicates {
            variant_type: Some(vec![
                "INS".to_owned(),
                "DEL".to_owned(),
                "DELINS".to_owned(),
            ]),
            ..Predicates::default()
        };
        assert!(matches_predicates(&indel, "A", "AC", "INS"));
        assert!(matches_predicates(&indel, "AC", "A", "DEL"));
        assert!(matches_predicates(&indel, "AT", "GCC", "DELINS"));
        assert!(!matches_predicates(&indel, "A", "T", "SNP"));

        // An all-None predicate matches anything.
        let any = Predicates {
            ref_: None,
            alt: None,
            variant_type: None,
            min_len: None,
            max_len: None,
        };
        assert!(matches_predicates(&any, "ACGT", "N", "DELINS"));
    }

    #[test]
    fn genomic_hgvs_id_matches_production_format() {
        // Exact strings, mirroring beacon2-ri-tools-v2's HGVS builder. `pos` is the
        // 0-based POS; `start = pos + 1`.
        let acc = "NC_000003.12";
        // SNV.
        assert_eq!(genomic_hgvs_id(acc, 99, "T", "C"), "NC_000003.12:g.100T>C");
        // Single-base left-anchored deletion (REF=AC, ALT=A): delete C at start+1.
        assert_eq!(genomic_hgvs_id(acc, 99, "AC", "A"), "NC_000003.12:g.101del");
        // Suffix-anchored deletion (REF=CTA, ALT=A): a range over the deleted prefix.
        assert_eq!(
            genomic_hgvs_id(acc, 99, "CTA", "A"),
            "NC_000003.12:g.100_101del"
        );
        // Multi-base left-anchored deletion (REF=ATGC, ALT=A): rendered as delins
        // (mirrors ri-tools, which does not minimise the left anchor here).
        assert_eq!(
            genomic_hgvs_id(acc, 99, "ATGC", "A"),
            "NC_000003.12:g.100_103delinsA"
        );
        // Prefix-anchored insertion (REF=A, ALT=ACGT): insert CGT between start, start+1.
        assert_eq!(
            genomic_hgvs_id(acc, 99, "A", "ACGT"),
            "NC_000003.12:g.100_101insCGT"
        );
        // Unanchored insertion (REF=A, ALT=CGT): a delins of the whole ALT.
        assert_eq!(
            genomic_hgvs_id(acc, 99, "A", "CGT"),
            "NC_000003.12:g.100delinsCGT"
        );
        // Multi-base REF insertion (REF=AT, ALT=ACGT): delins over the REF span.
        assert_eq!(
            genomic_hgvs_id(acc, 99, "AT", "ACGT"),
            "NC_000003.12:g.100_101delinsACGT"
        );
        // Equal-length MNV (REF=AT, ALT=GC): a span substitution.
        assert_eq!(
            genomic_hgvs_id(acc, 99, "AT", "GC"),
            "NC_000003.12:g.100AT>GC"
        );
    }

    #[test]
    fn gate_subcounts_off_passes_through() {
        assert_eq!(
            gate_subcounts(Some(6), Some(1), Some(2), Some(3), 0),
            (Some(1), Some(2), Some(3))
        );
    }

    #[test]
    fn gate_subcounts_withholds_all_three_when_any_is_a_small_group() {
        // het == 2 is a re-identifiable group at floor 5, so all three are withheld,
        // including the empty (0) and safe (20) cells, and none is recoverable from AC.
        assert_eq!(
            gate_subcounts(Some(22), Some(0), Some(2), Some(20), 5),
            (None, None, None)
        );
        // A None cell alongside a small one still forces all-None.
        assert_eq!(
            gate_subcounts(Some(30), None, Some(2), None, 5),
            (None, None, None)
        );
    }

    #[test]
    fn gate_subcounts_emits_all_when_none_is_a_small_group() {
        // floor 5: 5 (== floor, served), 0 (empty group, safe), 10 (safe) -> all emitted.
        assert_eq!(
            gate_subcounts(Some(15), Some(5), Some(0), Some(10), 5),
            (Some(5), Some(0), Some(10))
        );
        // None cells stay None; a safe present value is emitted. `AC == het` leaves a zero
        // residual, so the absent pair is empty rather than a withheld small group.
        assert_eq!(
            gate_subcounts(Some(6), None, Some(6), None, 5),
            (None, Some(6), None)
        );
        // All-None inputs -> all-None (nothing present to trigger, nothing to emit).
        assert_eq!(
            gate_subcounts(None, None, None, None, 5),
            (None, None, None)
        );
    }

    #[test]
    fn gate_subcounts_withholds_when_the_absent_cell_is_a_small_residual() {
        // The three sub-counts partition `AC` exactly, so an absent one is
        // `AC - Σ(present)`, arithmetic the client does itself. A chrX dataset whose
        // producer VCF carries AC, AC_Hom and AC_Het but no AC_Hemi:
        //   AC=50, hom=20, het=28  =>  hemi = 50 - 48 = 2, a below-floor group at floor 10.
        // Ingest accepts this shape, because `check_subcounts` demands an exact partition
        // only when all three are present, and every present value clears the floor. Without
        // this check both sub-counts reach the wire beside AC and the client subtracts.
        assert_eq!(
            gate_subcounts(Some(50), Some(20), Some(28), None, 10),
            (None, None, None)
        );
        // Two absent: the residual is their sum, and a below-floor sum bounds each below
        // the floor too, so the same collapse applies.
        assert_eq!(
            gate_subcounts(Some(30), Some(27), None, None, 10),
            (None, None, None)
        );
        // A residual at or above the floor is a legitimately unreported group, so nothing
        // collapses.
        assert_eq!(
            gate_subcounts(Some(50), Some(20), Some(15), None, 10),
            (Some(20), Some(15), None)
        );
        // A zero residual (the complete-but-for-an-empty-cell case) is not a group at all.
        assert_eq!(
            gate_subcounts(Some(48), Some(20), Some(28), None, 10),
            (Some(20), Some(28), None)
        );
        // Floor off: never collapse, whatever the residual.
        assert_eq!(
            gate_subcounts(Some(50), Some(20), Some(28), None, 0),
            (Some(20), Some(28), None)
        );
    }

    #[test]
    fn count_u64_maps_negative_to_none() {
        assert_eq!(count_u64(Some(7)), Some(7));
        assert_eq!(count_u64(Some(0)), Some(0));
        assert_eq!(count_u64(None), None);
        // Negative is treated as absent (counts are non-negative by construction).
        assert_eq!(count_u64(Some(-1)), None);
        assert_eq!(count_u64(Some(i32::MIN)), None);
    }

    use proptest::prelude::*;

    /// A 1..12-base ACGTN allele (mirrors the `query_proptest` `acgtn` helper).
    fn acgtn_str() -> impl Strategy<Value = String> {
        proptest::collection::vec(prop::sample::select(vec!['A', 'C', 'G', 'T', 'N']), 1..12)
            .prop_map(|v| v.into_iter().collect())
    }

    /// An ACGTN allele of length 0..64, covering the empty and long-indel lengths, for
    /// adversarial panic testing of `genomic_hgvs_id`'s index and length arithmetic.
    fn acgtn_adversarial() -> impl Strategy<Value = String> {
        proptest::collection::vec(prop::sample::select(vec!['A', 'C', 'G', 'T', 'N']), 0..64)
            .prop_map(|v| v.into_iter().collect())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// The rendered HGVS id is well-formed across every branch: it carries the
        /// `{acc}:g.` prefix; the `>` substitution marker appears if and only if REF and ALT
        /// are equal length (SNV or MNV); a deletion (`len(REF) > len(ALT)`) always carries
        /// `del`; an insertion (`len(ALT) > len(REF)`) always carries `ins`. The exact
        /// production-matching strings are pinned in
        /// `genomic_hgvs_id_matches_production_format`. Built by string concatenation,
        /// because `format!` is unavailable inside `proptest!`.
        #[test]
        fn genomic_hgvs_id_is_well_formed(
            pos in 0i32..2_000_000_000,
            ref_ in acgtn_str(),
            alt in acgtn_str(),
        ) {
            let acc = "NC_000003.12";
            let id = genomic_hgvs_id(acc, pos, &ref_, &alt);
            prop_assert!(id.starts_with(&(String::from(acc) + ":g.")));

            let (rl, al) = (ref_.len(), alt.len());
            // `>` marks a same-length substitution (SNV or MNV), never an indel.
            prop_assert_eq!(id.contains('>'), rl == al);
            if rl > al {
                prop_assert!(id.contains("del"), "deletion must carry `del`: {}", id);
            }
            if al > rl {
                prop_assert!(id.contains("ins"), "insertion must carry `ins`: {}", id);
            }
        }

        /// `genomic_hgvs_id`'s index and length arithmetic must not panic for any `i32`
        /// pos, including `i32::MAX` and `i32::MIN`, or any ACGTN allele length, including
        /// empty and long indels. `pos + 1` and the span arithmetic run in `i64`, and the
        /// sole string slice `alt[1..]` is reached only when `len(alt) >= 2` on ASCII bytes.
        #[test]
        fn genomic_hgvs_id_never_panics_on_adversarial_pos_and_lengths(
            pos in any::<i32>(),
            ref_ in acgtn_adversarial(),
            alt in acgtn_adversarial(),
        ) {
            let acc = "NC_000003.12";
            let id = genomic_hgvs_id(acc, pos, &ref_, &alt);
            prop_assert!(id.starts_with(&(String::from(acc) + ":g.")));
        }
    }

    /// Deterministic companion to the adversarial proptest: exercise the reachable
    /// coordinate ceiling (`i32::MAX`, a real stored `POS`) and the empty and indel allele
    /// shapes, showing no `i32` overflow, since `pos + 1` is `i64`, and no out-of-range
    /// slice.
    #[test]
    fn genomic_hgvs_id_boundary_positions_do_not_panic() {
        for pos in [i32::MIN, -1, 0, 1, i32::MAX] {
            for (r, a) in [
                ("A", "T"),
                ("A", "ACGT"),
                ("ACGT", "A"),
                ("AC", "GT"),
                ("", ""),
                ("A", ""),
                ("", "T"),
            ] {
                let id = genomic_hgvs_id("NC_000003.12", pos, r, a);
                assert!(
                    id.starts_with("NC_000003.12:g."),
                    "pos={pos} ref={r:?} alt={a:?} -> {id}"
                );
            }
        }
    }
}
