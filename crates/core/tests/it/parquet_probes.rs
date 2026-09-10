//! Probes over Parquet page-index behaviour and the memory the ingest path holds resident.
//!
//! Two ingest properties turn on how the `parquet` crate traverses a file rather than on code
//! in this crate, so they are settled by building a file and measuring it. One is whether the
//! two page-traversal modes decode the same rows over the same bytes. A split there would let
//! one reader validate rows that a second re-encrypts into the served store. The other is
//! what the k-way duplicate check holds resident once every cursor is primed, which is the
//! quantity an ingest memory ceiling has to bound.
//!
//! Most of these are `#[ignore]`d diagnostics that print a result for a human to read, and
//! one allocates gigabytes. Run them explicitly:
//!
//! ```text
//! cargo test -p gdi-node-standalone-core --test it --all-features -- --ignored --nocapture parquet_probes
//! ```
//!
//! The two that assert run with the ordinary suite. Both pin that `enforce_page_size_caps`
//! rejects an index that does not describe the whole column chunk, which is what keeps the
//! two traversal modes from ever seeing different rows.

use std::sync::Arc;

use arrow_array::{Array, ArrayRef, RecordBatch, StringArray};
use parquet::arrow::ArrowWriter;
use parquet::arrow::arrow_reader::{ArrowReaderMetadata, ArrowReaderOptions};
use parquet::file::metadata::{PageIndexPolicy, ParquetMetaDataBuilder};
use parquet::file::page_index::offset_index::{OffsetIndexMetaData, PageLocation};
use parquet::file::properties::WriterProperties;

/// Resident set size in bytes, from `/proc/self/statm` (Linux only).
///
/// Field 2 is the resident page count. Read directly rather than through a crate: RSS is the
/// number that decides whether a workload is OOM-killed, and measuring it should not cost a
/// dependency.
#[cfg(target_os = "linux")]
fn rss_bytes() -> u64 {
    let Ok(text) = std::fs::read_to_string("/proc/self/statm") else {
        return 0;
    };
    let pages: u64 = text
        .split_whitespace()
        .nth(1)
        .and_then(|f| f.parse().ok())
        .unwrap_or(0);
    pages * 4096
}

#[cfg(not(target_os = "linux"))]
fn rss_bytes() -> u64 {
    0
}

/// Write a single-column parquet whose column chunk holds `pages` data pages, each with
/// `rows_per_page` rows of `value_len`-byte strings.
///
/// `set_data_page_row_count_limit` forces the page split. Without it the writer emits one
/// page and the two traversal modes have nothing to disagree about.
fn write_multi_page(path: &std::path::Path, pages: usize, rows_per_page: usize, value_len: usize) {
    let props = WriterProperties::builder()
        .set_data_page_row_count_limit(rows_per_page)
        .set_write_batch_size(rows_per_page)
        // Plain and uncompressed, so page boundaries in the file sit exactly where the
        // index says they do. These probes are about index-versus-bytes disagreement, not
        // about codec behaviour.
        .set_dictionary_enabled(false)
        .set_compression(parquet::basic::Compression::UNCOMPRESSED)
        .build();

    let total = pages * rows_per_page;
    let values: Vec<String> = (0..total).map(|i| format!("{i:0value_len$}")).collect();
    let col: ArrayRef = Arc::new(StringArray::from(values));
    let batch = RecordBatch::try_from_iter(vec![("v", col)]).expect("batch");

    let file = std::fs::File::create(path).expect("create parquet");
    let mut writer = ArrowWriter::try_new(file, batch.schema(), Some(props)).expect("writer");
    writer.write(&batch).expect("write");
    writer.close().expect("close");
}

/// Decode every value of column 0 through a given reader configuration.
fn read_all(
    path: &std::path::Path,
    metadata: Option<ArrowReaderMetadata>,
    policy: parquet::arrow::arrow_reader::ArrowReaderOptions,
) -> Vec<String> {
    let file = std::fs::File::open(path).expect("open");
    let builder = match metadata {
        Some(md) => {
            parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::new_with_metadata(
                file, md,
            )
        }
        None => {
            parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new_with_options(
                file, policy,
            )
            .expect("builder")
        }
    };
    let reader = builder.build().expect("reader");
    let mut out = Vec::new();
    for batch in reader {
        let batch = batch.expect("batch");
        let col = batch
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("string column");
        for i in 0..col.len() {
            out.push(col.value(i).to_owned());
        }
    }
    out
}

/// An `OffsetIndex` that omits a physically present page does not, by itself, make the two
/// page-traversal modes decode different rows.
///
/// This matters because the ingest path checks a file's values with one reader and
/// re-encrypts the same file with another. If those two could decode different rows, values
/// that never met `check_batch_values` would reach the served store. The modes differ by
/// page-index policy: `Required` gives `Pages`, `Skip` gives `Values`.
///
/// Absent a `RowSelection` neither mode locates pages through the index. Both walk the column
/// chunk's byte range, so a two-page file whose index lists only the second page still decodes
/// all 128 rows either way. The index steers decoding only once a selection is derived from
/// it, which is the serve path (`pos_row_selection`).
///
/// This is the weaker of two constructions. The stronger one also shrinks the chunk's
/// `compressed_size`, and that one does split the readers. It is built and settled in
/// `page_index_residual_shrunk_chunk_is_rejected_before_it_can_diverge`.
#[test]
#[ignore = "diagnostic probe; run explicitly with --ignored"]
fn probe_page_discovery_divergence() {
    const PAGES: usize = 2;
    const ROWS_PER_PAGE: usize = 64;
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("two_pages.parquet");
    write_multi_page(&path, PAGES, ROWS_PER_PAGE, 8);

    // Ground truth: the real file, read with the page index loaded.
    let file = std::fs::File::open(&path).expect("open");
    let real = ArrowReaderMetadata::load(
        &file,
        ArrowReaderOptions::new().with_page_index_policy(PageIndexPolicy::Required),
    )
    .expect("load metadata with page index");
    let md = real.metadata();

    let offset_index = md.offset_index().expect("offset index present");
    let locations = &offset_index[0][0].page_locations;
    println!("--- page-discovery probe: an index that omits a present page ---");
    println!("pages listed in the real OffsetIndex : {}", locations.len());
    for (i, p) in locations.iter().enumerate() {
        println!(
            "  page {i}: offset={} compressed_page_size={} first_row_index={}",
            p.offset, p.compressed_page_size, p.first_row_index
        );
    }
    if locations.len() < 2 {
        println!(
            "INCONCLUSIVE: the writer emitted {} page(s); the probe needs >= 2 to omit one.",
            locations.len()
        );
        return;
    }

    let all_rows = md.row_group(0).num_rows();
    // The crafted index lists only the second page and claims it covers every row of the
    // group. Page 0 is still physically there, before it, inside the chunk.
    let patched_locations = vec![PageLocation {
        offset: locations[1].offset,
        compressed_page_size: locations[1].compressed_page_size,
        first_row_index: 0,
    }];
    let patched_index = vec![vec![OffsetIndexMetaData {
        page_locations: patched_locations,
        unencoded_byte_array_data_bytes: None,
    }]];
    let patched_md = Arc::new(
        ParquetMetaDataBuilder::new_from_metadata(md.as_ref().clone())
            .set_offset_index(Some(patched_index))
            .build(),
    );
    let patched = ArrowReaderMetadata::try_new(
        patched_md,
        ArrowReaderOptions::new().with_page_index_policy(PageIndexPolicy::Required),
    )
    .expect("patched metadata");

    let pages_mode = read_all(&path, Some(patched), ArrowReaderOptions::new());
    let values_mode = read_all(
        &path,
        None,
        ArrowReaderOptions::new().with_page_index_policy(PageIndexPolicy::Skip),
    );

    println!("group rows declared                  : {all_rows}");
    println!(
        "rows decoded via Pages (patched idx) : {}",
        pages_mode.len()
    );
    println!(
        "rows decoded via Values (sequential) : {}",
        values_mode.len()
    );
    if pages_mode == values_mode {
        println!(
            "the two modes agree even with an index that omits a physically present \
             page: omitting a page is not by itself a validation bypass."
        );
    } else {
        println!(
            "the two modes disagree: the rows a validating reader checks are not the \
             rows a Values-mode reader re-encodes into the store. First divergence at \
             index {}.",
            pages_mode
                .iter()
                .zip(values_mode.iter())
                .position(|(a, b)| a != b)
                .map_or_else(|| "len".to_owned(), |i| i.to_string())
        );
    }
}

/// The ingest duplicate check holds one fully decoded batch per open file, so its resident
/// cost scales with the number of files in a `(chr, block)` group.
///
/// `check_group_uniqueness` opens one `RowCursor` per file in the group, and `min_front_pos`
/// primes every cursor before any is drained. The peak is therefore files times batch rows
/// times row bytes. `max_files_per_group` bounds descriptors, which is a different quantity
/// and leaves that product unbounded, so `MAX_GROUP_WORKING_SET_BYTES` bounds the buffered
/// working set instead.
///
/// The bound is what keeps a single uploaded package from becoming a crash loop. The ingest
/// worker runs inside the node process, so exhausting memory there is an allocator abort,
/// which `catch_parquet_panic` cannot intercept, or an OOM-kill that takes the Beacon and FDP
/// listeners with it. Either happens before a quarantine decision is reached, so the package
/// stays in the channel and the boot rescan re-queues it.
///
/// `GDI_PROBE_FILES` sets the file count (default 64). The peak is linear in it, so the
/// printed per-file figure is the number that carries to the cap.
#[test]
#[ignore = "diagnostic probe; allocates GBs; run explicitly with --ignored"]
#[expect(
    clippy::cast_precision_loss,
    reason = "the GiB conversions feed a human-readable print; byte counts this small lose \
              nothing"
)]
fn probe_ingest_group_working_set() {
    let files: usize = std::env::var("GDI_PROBE_FILES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(64);
    // The ingest caps: 1024 rows per decoded batch, 10 000-byte REF and ALT.
    let rows_per_page: usize = 1024;
    let value_len: usize = 10_000;

    let tmp = tempfile::tempdir().expect("tempdir");
    println!("--- ingest working-set probe: one primed cursor per file ---");
    println!("files={files} rows_per_batch={rows_per_page} value_len={value_len}");

    let baseline = rss_bytes();
    let mut paths = Vec::with_capacity(files);
    for i in 0..files {
        let p = tmp.path().join(format!("part-{i:04}.parquet"));
        write_multi_page(&p, 1, rows_per_page, value_len);
        paths.push(p);
    }
    let after_write = rss_bytes();

    // Prime one reader per file without draining any, the shape `min_front_pos` creates.
    // The descriptor cap bounds the readers, not the decoded batch each one holds.
    let mut readers = Vec::with_capacity(files);
    for p in &paths {
        let f = std::fs::File::open(p).expect("open");
        let mut r = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(f)
            .expect("builder")
            .build()
            .expect("reader");
        // Pull one batch and hold it, as a primed cursor does.
        if let Some(batch) = r.next() {
            readers.push((r, batch.expect("batch")));
        }
    }
    let primed = rss_bytes();

    let held: usize = readers.iter().map(|(_, b)| b.get_array_memory_size()).sum();
    println!("RSS baseline            : {baseline:>12} B");
    println!("RSS after writing files : {after_write:>12} B");
    println!("RSS with all cursors primed: {primed:>9} B");
    println!(
        "delta attributable to priming: {:>7} B ({:.2} GiB)",
        primed.saturating_sub(after_write),
        (primed.saturating_sub(after_write)) as f64 / (1024.0 * 1024.0 * 1024.0)
    );
    println!(
        "sum of held arrow batches   : {:>10} B ({:.2} GiB)",
        held,
        held as f64 / (1024.0 * 1024.0 * 1024.0)
    );
    let per_file = held as f64 / files.max(1) as f64;
    println!(
        "per-file held               : {:>10.0} B  => at max_files_per_group: {:.2} GiB",
        per_file,
        per_file * 1024.0 / (1024.0 * 1024.0 * 1024.0)
    );
    // Keep the readers alive to the end so the measurement is not optimised away.
    drop(readers);
}

/// A `RowSelection` maps positionally over the row group, so a malformed page index cannot
/// steer which rows the serve path returns.
///
/// The probe above establishes that the two traversal modes agree when no selection is
/// applied, because neither locates pages through the index in that case. That leaves the
/// serve path, which does derive a `RowSelection` from the index (`pos_row_selection` ->
/// `page_row_ranges`), so an index misdescribing the page-to-row mapping could in principle
/// steer which rows are decoded.
///
/// It does not. Selecting the first 64 of 128 rows returns the positional first half: a
/// `RowSelection` indexes rows of the group, not pages named by the index.
#[test]
#[ignore = "diagnostic probe; run explicitly with --ignored"]
fn probe_selection_path_with_a_malformed_index() {
    const ROWS_PER_PAGE: usize = 64;
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("sel.parquet");
    write_multi_page(&path, 2, ROWS_PER_PAGE, 8);

    let truth = read_all(&path, None, ArrowReaderOptions::new());

    let file = std::fs::File::open(&path).expect("open");
    let builder =
        parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new_with_options(
            file,
            ArrowReaderOptions::new().with_page_index_policy(PageIndexPolicy::Required),
        )
        .expect("builder");
    let selection = parquet::arrow::arrow_reader::RowSelection::from(vec![
        parquet::arrow::arrow_reader::RowSelector::select(ROWS_PER_PAGE),
        parquet::arrow::arrow_reader::RowSelector::skip(ROWS_PER_PAGE),
    ]);
    let reader = builder
        .with_row_selection(selection)
        .build()
        .expect("reader");
    let mut selected: Vec<String> = Vec::new();
    for batch in reader {
        let batch = batch.expect("batch");
        let col = batch
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("string column");
        for i in 0..col.len() {
            selected.push(col.value(i).to_owned());
        }
    }

    println!("--- page-discovery probe: the row-selection path ---");
    println!("total rows            : {}", truth.len());
    println!("rows under selection  : {}", selected.len());
    let expected_first_half = &truth[..ROWS_PER_PAGE.min(truth.len())];
    if selected == expected_first_half {
        println!(
            "a row selection maps positionally over the real rows: the index's page and \
             row claims do not redirect it."
        );
    } else {
        println!(
            "the selection returned different rows than the positional truth, so a \
             malformed index steers the serve path."
        );
    }
}

/// The page-size caps must cover bytes the index does not list, not merely the pages it does.
///
/// `enforce_page_size_caps` builds its probe set from the chunk start plus every
/// OffsetIndex-listed offset. A page that is physically present but absent from the index sits
/// in no probe origin, so nothing bounds its `uncompressed_page_size`, while a sequential
/// reader still walks it and allocates from that header. The caps therefore require the index
/// to account for the whole chunk.
///
/// The probe calls the cap directly with a real index and then with one that omits a page, so
/// the two lines it prints distinguish "the cap ran" from "the cap looked at every byte the
/// decoder can reach". A change that drops the anchoring turns the second line back into `Ok`
/// without failing anything, which is why
/// `page_size_caps_reject_an_index_that_does_not_tile_the_chunk` asserts the same shape.
#[test]
#[ignore = "diagnostic probe; run explicitly with --ignored"]
fn probe_page_size_cap_coverage_of_an_unlisted_page() {
    const ROWS_PER_PAGE: usize = 64;
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("bomb_shape.parquet");
    write_multi_page(&path, 2, ROWS_PER_PAGE, 8);

    let file = std::fs::File::open(&path).expect("open");
    let real = ArrowReaderMetadata::load(
        &file,
        ArrowReaderOptions::new().with_page_index_policy(PageIndexPolicy::Required),
    )
    .expect("load metadata");
    let md = real.metadata();
    let locations = &md.offset_index().expect("offset index")[0][0].page_locations;
    println!("--- page-size cap probe: coverage of an unlisted page ---");
    println!("pages physically present / listed: 2 / {}", locations.len());

    let full = gdi_node_standalone_core::parquet_pages::enforce_page_size_caps(&path, md);
    println!("caps over the full index     : {:?}", full.map(|()| "ok"));

    let patched_index = vec![vec![OffsetIndexMetaData {
        page_locations: vec![PageLocation {
            offset: locations[1].offset,
            compressed_page_size: locations[1].compressed_page_size,
            first_row_index: 0,
        }],
        unencoded_byte_array_data_bytes: None,
    }]];
    let patched = ParquetMetaDataBuilder::new_from_metadata(md.as_ref().clone())
        .set_offset_index(Some(patched_index))
        .build();
    let partial = gdi_node_standalone_core::parquet_pages::enforce_page_size_caps(&path, &patched);
    println!(
        "caps over the omitting index : {:?}",
        partial.map(|()| "ok")
    );
    println!(
        "the omitting index must be rejected: an unlisted page sits in no probe origin, so \
         nothing bounds the size it declares. Two `ok` lines mean the cap looked only at the \
         pages the producer chose to list."
    );
}

/// `enforce_page_size_caps` anchors the listed run of pages to the column chunk at three
/// points, and each anchor rejects the omission it exists for while a real index passes.
///
/// The anchors are that the first listed page starts at `data_page_offset`, that consecutive
/// pages abut, and that the last page ends at the chunk end. Together they require the index
/// to tile the chunk exactly, which leaves no page outside the byte range a sequential reader
/// covers.
///
/// One page is omitted per case, so each case can only be satisfied by the anchor it names:
/// the tail arithmetic balances when the first page is missing, and the first-page anchor is
/// blind to a gap in the middle or at the end.
#[test]
fn page_size_caps_reject_an_index_that_does_not_tile_the_chunk() {
    const ROWS_PER_PAGE: usize = 64;
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("three_pages.parquet");
    write_multi_page(&path, 3, ROWS_PER_PAGE, 8);

    let file = std::fs::File::open(&path).expect("open");
    let real = ArrowReaderMetadata::load(
        &file,
        ArrowReaderOptions::new().with_page_index_policy(PageIndexPolicy::Required),
    )
    .expect("load metadata");
    let md = real.metadata();
    let locations = md.offset_index().expect("offset index")[0][0]
        .page_locations
        .clone();
    assert_eq!(
        locations.len(),
        3,
        "the fixture must list three pages, or an omission below omits nothing"
    );

    gdi_node_standalone_core::parquet_pages::enforce_page_size_caps(&path, md)
        .expect("the producer's own index tiles the chunk exactly and must pass");

    let listing_only = |keep: &[usize]| {
        let index = vec![vec![OffsetIndexMetaData {
            page_locations: keep.iter().map(|&i| locations[i].clone()).collect(),
            unencoded_byte_array_data_bytes: None,
        }]];
        ParquetMetaDataBuilder::new_from_metadata(md.as_ref().clone())
            .set_offset_index(Some(index))
            .build()
    };
    for (anchor, keep, names) in [
        (
            "first-page (page 0 omitted)",
            &[1, 2][..],
            "declares its data pages begin at",
        ),
        (
            "contiguity (page 1 omitted)",
            &[0, 2][..],
            "does not describe a contiguous run of pages",
        ),
        (
            "tail (page 2 omitted)",
            &[0, 1][..],
            "while the column chunk ends at",
        ),
    ] {
        let err = gdi_node_standalone_core::parquet_pages::enforce_page_size_caps(
            &path,
            &listing_only(keep),
        )
        .expect_err(anchor);
        assert!(
            err.to_string().contains(names),
            "{anchor}: the rejection must come from that anchor, not another: {err}"
        );
    }
}

/// Rebuild `md` with row-group 0 / column 0's `total_compressed_size` set to
/// `new_compressed_size` and its `OffsetIndex` replaced by `offset_index`.
///
/// Pass `None` to clear the index. That is the only faithful way to model a `Values`-mode
/// reader, because `PageIndexPolicy::Skip` does not strip an index already present in supplied
/// metadata.
///
/// This models the footer an attacker writes without forging thrift page headers: the physical
/// pages already exist in the file, and only the metadata describing them is patched.
fn patch_chunk(
    md: &parquet::file::metadata::ParquetMetaData,
    new_compressed_size: i64,
    offset_index: Option<Vec<Vec<OffsetIndexMetaData>>>,
) -> Arc<parquet::file::metadata::ParquetMetaData> {
    let mut builder = ParquetMetaDataBuilder::new_from_metadata(md.clone());
    let mut rgs = builder.take_row_groups();
    let rg0 = rgs.remove(0);
    let mut rgb = rg0.into_builder();
    let mut cols = rgb.take_columns();
    let patched_col = cols
        .remove(0)
        .into_builder()
        .set_total_compressed_size(new_compressed_size)
        .build()
        .expect("rebuild column");
    cols.insert(0, patched_col);
    let rg0 = rgb
        .set_column_metadata(cols)
        .build()
        .expect("rebuild row group");
    rgs.insert(0, rg0);
    Arc::new(
        builder
            .set_row_groups(rgs)
            .set_offset_index(offset_index)
            .build(),
    )
}

/// Decode column 0 through a reader handed exactly `md`, and return the row count.
fn decode_row_count(
    path: &std::path::Path,
    md: Arc<parquet::file::metadata::ParquetMetaData>,
    policy: PageIndexPolicy,
) -> usize {
    let file = std::fs::File::open(path).expect("open");
    let arm =
        ArrowReaderMetadata::try_new(md, ArrowReaderOptions::new().with_page_index_policy(policy))
            .expect("metadata");
    let reader =
        parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::new_with_metadata(file, arm)
            .build()
            .expect("reader");
    let mut rows = 0usize;
    for batch in reader {
        rows += batch.expect("batch").num_rows();
    }
    rows
}

/// A truncated `compressed_size` genuinely splits the two page-traversal modes, and the ingest
/// gate rejects every representation of that split before anything is stored.
///
/// Shrinking the column chunk's `compressed_size` stops a `Values`-mode sequential walk early,
/// while a `Pages` reader follows the `OffsetIndex` to pages beyond the truncated bound. Over
/// a three-page file the two decode 64 rows and 192 rows. One reader would then validate 64
/// rows while another stored 192, and the rows in between would reach the served store having
/// met no value check.
///
/// What closes that is `enforce_page_size_caps`, which `validate_parquet::RowCursor::open`
/// runs before the store. It rejects each shape the split can take:
///
/// * an index listing a page past the shrunk chunk end, through the tail anchor;
/// * a listed page beyond a gap, through the contiguity anchor;
/// * no index at all, by failing closed.
///
/// An index that does tile the chunk leaves no page outside the `Values` byte range, so the
/// two modes then decode the same pages. Keeping both ingest readers in `Pages` mode, which
/// the `clippy.toml` ban on `try_new` enforces, is a second line rather than the guarantee.
///
/// The test pins both halves, so a refactor cannot make the rejection vacuous: the
/// construction must still split the readers, and the gate must still reject every form of it.
///
/// Only the metadata is patched. The physical file carries real page headers at every listed
/// offset, so `ParquetMetaDataBuilder` alone builds the whole construction.
#[test]
fn page_index_residual_shrunk_chunk_is_rejected_before_it_can_diverge() {
    use gdi_node_standalone_core::parquet_pages::enforce_page_size_caps;

    const ROWS_PER_PAGE: usize = 64;
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("residual.parquet");
    write_multi_page(&path, 3, ROWS_PER_PAGE, 8);

    let file = std::fs::File::open(&path).expect("open");
    let real = ArrowReaderMetadata::load(
        &file,
        ArrowReaderOptions::new().with_page_index_policy(PageIndexPolicy::Required),
    )
    .expect("load metadata with page index");
    let md = real.metadata();
    let locations = md.offset_index().expect("offset index")[0][0]
        .page_locations
        .clone();
    assert_eq!(locations.len(), 3, "fixture must list three pages");
    let total_rows = 3 * ROWS_PER_PAGE;
    let real_cs = md.row_group(0).column(0).compressed_size();
    let full_index = |locs: Vec<PageLocation>| {
        vec![vec![OffsetIndexMetaData {
            page_locations: locs,
            unencoded_byte_array_data_bytes: None,
        }]]
    };

    // Baseline: a well-formed, chunk-tiling index. The gate passes and the two readers agree.
    // Pages over the real index and a Values walk over the full chunk decode the same rows.
    enforce_page_size_caps(&path, md).expect("the producer's own tiling index must pass");
    let real_pages = decode_row_count(
        &path,
        Arc::new(md.as_ref().clone()),
        PageIndexPolicy::Required,
    );
    let real_values =
        decode_row_count(&path, patch_chunk(md, real_cs, None), PageIndexPolicy::Skip);
    assert_eq!(
        real_pages, total_rows,
        "Pages reads every row of a tiling file"
    );
    assert_eq!(
        real_values, real_pages,
        "a tiling index leaves no page outside the Values byte range, so the modes agree"
    );

    // The residual: shrink compressed_size so the chunk "ends" after page 0 only.
    let shrunk = i64::from(locations[0].compressed_page_size);

    // (i) The split is real. A Values walk stops at the shrunk bound, while a Pages reader
    // over the same bytes follows the OffsetIndex to pages 1 and 2, both beyond it.
    let values_rows = decode_row_count(&path, patch_chunk(md, shrunk, None), PageIndexPolicy::Skip);
    let pages_rows = decode_row_count(
        &path,
        patch_chunk(md, shrunk, Some(full_index(locations.clone()))),
        PageIndexPolicy::Required,
    );
    assert_eq!(
        values_rows, ROWS_PER_PAGE,
        "Values walk stops at the shrunk compressed_size"
    );
    assert_eq!(
        pages_rows, total_rows,
        "Pages follows the index past the shrunk bound"
    );
    assert_ne!(
        values_rows, pages_rows,
        "the residual must genuinely split the readers, or the rejection below is vacuous"
    );

    // (ii) The gate rejects every representation of that split, before the store.
    let tail_err = enforce_page_size_caps(
        &path,
        &patch_chunk(md, shrunk, Some(full_index(locations.clone()))),
    )
    .expect_err("an index whose pages run past the shrunk chunk end must be rejected");
    assert!(
        tail_err
            .to_string()
            .contains("while the column chunk ends at"),
        "the Pages representation must fail the tail anchor: {tail_err}"
    );

    let gap_index = full_index(vec![locations[0].clone(), locations[2].clone()]);
    let gap_err = enforce_page_size_caps(&path, &patch_chunk(md, shrunk, Some(gap_index)))
        .expect_err("a listed page beyond a gap must be rejected");
    assert!(
        gap_err
            .to_string()
            .contains("does not describe a contiguous run"),
        "the non-contiguous representation must fail the contiguity anchor: {gap_err}"
    );

    let noindex_err = enforce_page_size_caps(&path, &patch_chunk(md, shrunk, None))
        .expect_err("a shrunk chunk with no index at all must be rejected");
    assert!(
        noindex_err.to_string().contains("no page (offset) index"),
        "the Values representation must fail closed on the absent index: {noindex_err}"
    );
}
