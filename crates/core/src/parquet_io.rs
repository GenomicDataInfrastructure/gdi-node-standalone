//! Parquet writer properties and the aggregated allele-frequency schema.
//!
//! The schema is the eleven columns
//! `POS`/`REF`/`ALT`/`VT`/`POPULATION`/`AF` (all required) plus the five
//! nullable counts `AC`/`AC_HOM`/`AC_HET`/`AC_HEMI`/`AN`.

use std::{
    path::Path,
    sync::{Arc, OnceLock},
};

use arrow_array::{Array, Float32Array, Int32Array, StringArray};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use parquet::{
    arrow::arrow_reader::{ArrowReaderOptions, ParquetRecordBatchReaderBuilder, RowSelection},
    basic::{Compression, Encoding, ZstdLevel},
    errors::ParquetError,
    file::{
        metadata::{PageIndexPolicy, ParquetMetaData, SortingColumn},
        page_index::column_index::ColumnIndexMetaData,
        properties::{EnabledStatistics, WriterProperties, WriterPropertiesBuilder},
        statistics::Statistics,
    },
    schema::types::ColumnPath,
};

#[cfg(feature = "pme")]
use parquet::encryption::{decrypt::FileDecryptionProperties, encrypt::FileEncryptionProperties};
#[cfg(feature = "pme")]
use zeroize::Zeroizing;

use crate::{
    error::{CoreError, CoreResult, invalid_parquet},
    validate_parquet::ParquetCaps,
    variant::Vt,
};

/// The raw byte length of a Parquet Modular Encryption footer key (AES-256-GCM).
///
/// Vault's `transit/datakey/plaintext/<key>` with `bits=256` mints exactly this
/// many bytes; a key of any other length is a configuration / Transit-key-type
/// error and is rejected before it reaches the parquet writer/reader.
#[cfg(feature = "pme")]
pub const PME_KEY_LEN: usize = 32;

/// Mints a per-file data-encryption key (DEK) for Parquet Modular Encryption.
///
/// The seam that keeps `core`'s parquet write path Vault-agnostic: the service
/// implements this over the Vault Transit `datakey/plaintext` primitive,
/// returning the raw footer key
/// plus the self-describing `key_metadata` blob that the reader's
/// [`parquet::encryption::decrypt::KeyRetriever`] parses back. `core` only ever
/// sees opaque bytes: it never knows the wrapping scheme.
///
/// Implementations are `Send + Sync` so the minter can be threaded through the
/// `spawn_blocking` ingest store from a shared service handle.
#[cfg(feature = "pme")]
pub trait DekMinter: Send + Sync {
    /// Mint a fresh 256-bit footer key and its `key_metadata`.
    ///
    /// Returns `(key_bytes, key_metadata)` where `key_bytes` is exactly
    /// [`PME_KEY_LEN`] bytes held in a [`Zeroizing`] buffer (wiped on drop) and
    /// `key_metadata` is the opaque self-describing record stored as the parquet
    /// `key_metadata`.
    ///
    /// # Errors
    ///
    /// Returns a [`CoreError`] when the DEK cannot be minted (e.g. a Vault Transit
    /// failure). The caller classifies a transient mint failure as retryable.
    fn mint(&self) -> CoreResult<(Zeroizing<Vec<u8>>, Vec<u8>)>;
}

/// Re-export the parquet crate's key-retriever trait so the service implements it
/// directly (its `retrieve_key(&[u8]) -> Result<Vec<u8>>` signature is exactly the
/// PME read seam — parse `key_metadata`, unwrap the DEK, return raw key bytes).
#[cfg(feature = "pme")]
pub use parquet::encryption::decrypt::KeyRetriever;

/// Re-export the parquet error type so the service's `KeyRetriever` impl can name
/// its return type without a direct `parquet` dependency (the service crate does
/// not link `parquet` itself; it goes through `core`).
#[cfg(feature = "pme")]
pub use parquet::errors::ParquetError as PmeError;

/// The optional PME read context threaded through [`read_matching_rows`] and the beacon
/// scan. Its shape is the same in every feature build, so the call sites stay
/// feature-agnostic.
///
/// * Under the `pme` feature it optionally carries a `KeyRetriever`. A `PARE` (encrypted)
///   file is decrypted through it; a `PAR1` (plaintext) file ignores it, because parquet
///   self-describes its encryption via the file magic, so a mixed store reads correctly.
/// * Without `pme` it is a zero-sized marker and the plaintext read path is unaffected.
///
/// [`DatasetDecryptor::plaintext`] is the always-available constructor with no retriever.
/// The service builds the PME variant when a `[vault].transit_key` is configured.
#[derive(Clone, Default)]
pub struct DatasetDecryptor {
    #[cfg(feature = "pme")]
    retriever: Option<Arc<dyn KeyRetriever>>,
}

impl DatasetDecryptor {
    /// The plaintext read context: no key retriever. Available in every build.
    #[must_use]
    pub fn plaintext() -> Self {
        Self::default()
    }

    /// The PME read context wrapping a [`KeyRetriever`] used to unwrap each
    /// encrypted file's DEK from its stored `key_metadata`.
    #[cfg(feature = "pme")]
    #[must_use]
    pub fn with_retriever(retriever: Arc<dyn KeyRetriever>) -> Self {
        Self {
            retriever: Some(retriever),
        }
    }

    /// The decryption properties for this context, if a retriever is present.
    #[cfg(feature = "pme")]
    fn decryption(&self) -> Result<Option<Arc<FileDecryptionProperties>>, ParquetError> {
        match &self.retriever {
            Some(r) => decryption_properties(Arc::clone(r)).map(Some),
            None => Ok(None),
        }
    }
}

impl std::fmt::Debug for DatasetDecryptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never reveal key material; just whether a retriever is configured.
        #[cfg(feature = "pme")]
        let has = self.retriever.is_some();
        #[cfg(not(feature = "pme"))]
        let has = false;
        f.debug_struct("DatasetDecryptor")
            .field("has_retriever", &has)
            .finish()
    }
}

/// The write-side mirror of [`DatasetDecryptor`], threaded through the ingest store. Its
/// shape is the same in every feature build, so the ingest call sites stay
/// feature-agnostic.
///
/// * Under the `pme` feature it optionally carries a `DekMinter`. When one is present the
///   store re-encodes each plaintext staging parquet into a `PARE` file via
///   `encrypt_parquet_file`, minting a fresh per-file DEK. When absent it writes
///   plaintext with `fs::copy`.
/// * Without `pme` it is a zero-sized marker and the store path is unaffected.
///
/// [`DatasetEncryptor::plaintext`] is the always-available constructor with no minter.
/// The service builds the PME variant when a `[vault].transit_key` is configured.
#[derive(Clone, Default)]
pub struct DatasetEncryptor {
    #[cfg(feature = "pme")]
    minter: Option<Arc<dyn DekMinter>>,
}

impl DatasetEncryptor {
    /// The plaintext write context: no minter. Available in every build.
    #[must_use]
    pub fn plaintext() -> Self {
        Self::default()
    }

    /// The PME write context wrapping a [`DekMinter`] used to mint a fresh DEK +
    /// `key_metadata` per parquet file at store time.
    #[cfg(feature = "pme")]
    #[must_use]
    pub fn with_minter(minter: Arc<dyn DekMinter>) -> Self {
        Self {
            minter: Some(minter),
        }
    }

    /// The configured minter, if any (PME builds only).
    #[cfg(feature = "pme")]
    #[must_use]
    fn minter(&self) -> Option<&Arc<dyn DekMinter>> {
        self.minter.as_ref()
    }

    /// Whether this context writes plaintext parquet, i.e. carries no PME minter.
    ///
    /// Only plaintext at-rest bytes warrant a stored content digest. PME (`PARE`) files
    /// already carry per-segment AEAD tamper detection, and re-hashing their plaintext
    /// would force a per-file Vault DEK fetch for no added integrity.
    #[must_use]
    // Without `pme` there is no minter field to consult and the answer is unconditionally
    // `true`, so `self` goes unused in that build alone. It stays a method because the pme
    // build genuinely depends on the receiver.
    #[cfg_attr(
        not(feature = "pme"),
        expect(
            clippy::unused_self,
            reason = "no minter field exists without `pme`; the pme build uses `self`"
        )
    )]
    pub(crate) fn writes_plaintext(&self) -> bool {
        #[cfg(feature = "pme")]
        {
            self.minter.is_none()
        }
        #[cfg(not(feature = "pme"))]
        {
            true
        }
    }
}

impl std::fmt::Debug for DatasetEncryptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(feature = "pme")]
        let has = self.minter.is_some();
        #[cfg(not(feature = "pme"))]
        let has = false;
        f.debug_struct("DatasetEncryptor")
            .field("has_minter", &has)
            .finish()
    }
}

/// zstd compression level used for all aggregated parquet output.
const ZSTD_LEVEL: i32 = 19;

/// Maximum rows per row group in aggregated parquet output.
///
/// `convert` writes one [`arrow_array::RecordBatch`] per (chromosome, position block), so
/// without a cap a dense block becomes a single multi-hundred-thousand-row group.
/// Row-group statistics are the coarsest prune granularity, so a query against such a
/// block must decode the whole group. Capping the group at 64Ki rows lets min/max-`POS`
/// pruning skip all but the group whose `POS` range covers the lookup. Applied to both
/// the plaintext and the PME writer so encrypted-at-rest files prune identically.
const MAX_ROW_GROUP_SIZE: usize = 64 * 1024;

/// Rows per data page (`data_page_row_count_limit`), overriding the parquet default of
/// 20 000.
///
/// A data page is the finest granularity the page index can prune, and
/// [`read_matching_rows`] builds a `POS` [`RowSelection`] from that index, so a sparse
/// point or Sequence query decodes only the pages whose `POS` range covers it rather than
/// the whole 64Ki-row group. 4 096 rows per page is the point-query knee: several times
/// faster than the un-paged read, while the wide-range scan and the per-page compression
/// cost stay modest. It also guarantees multiple pages for the small sparse-block
/// partitions that a single 20 000-row page would leave un-prunable. Applied to both the
/// plaintext and the PME writer so encrypted-at-rest files prune identically.
const DATA_PAGE_ROWS: usize = 4096;

/// Build the Arrow schema for an `allele-freq.*.parquet` file.
///
/// `POS` is `int32` (0-based); `REF`/`ALT`/`VT`/`POPULATION` are UTF-8 strings;
/// `AF` is `float32`; the five count columns (`AC`, `AC_HOM`, `AC_HET`,
/// `AC_HEMI`, `AN`) are nullable `int32`. Every other column is non-nullable.
#[must_use]
pub fn allele_freq_schema() -> SchemaRef {
    // The schema is a compile-time-constant shape; build it (and its 11 `Field`s) once
    // and hand back a cheap `Arc` clone — it is requested per validated file and on every
    // read/write path.
    static SCHEMA: OnceLock<SchemaRef> = OnceLock::new();
    SCHEMA
        .get_or_init(|| {
            Arc::new(Schema::new(vec![
                Field::new("POS", DataType::Int32, false),
                Field::new("REF", DataType::Utf8, false),
                Field::new("ALT", DataType::Utf8, false),
                Field::new("VT", DataType::Utf8, false),
                Field::new("POPULATION", DataType::Utf8, false),
                Field::new("AF", DataType::Float32, false),
                Field::new("AC", DataType::Int32, true),
                Field::new("AC_HOM", DataType::Int32, true),
                Field::new("AC_HET", DataType::Int32, true),
                Field::new("AC_HEMI", DataType::Int32, true),
                Field::new("AN", DataType::Int32, true),
            ]))
        })
        .clone()
}

/// The physical row order stamped into every row group's `sorting_columns` footer
/// metadata: `(POS, REF, ALT, POPULATION)`, all ascending. This is the key
/// `convert::process_partition` sorts each partition by. The indices are the schema leaf
/// positions (`POS` = 0, `REF` = 1, `ALT` = 2, `POPULATION` = 4).
///
/// This only *advertises* the ordering to external Parquet readers; the node's own
/// reader prunes on `POS` statistics directly and does not consult it.
fn physical_sort_columns() -> Vec<SortingColumn> {
    [0, 1, 2, 4]
        .into_iter()
        .map(|column_idx| SortingColumn {
            column_idx,
            descending: false,
            nulls_first: false,
        })
        .collect()
}

/// The settings shared by the plaintext and the PME writer: zstd level 19, page-level
/// statistics, and the `DATA_PAGE_ROWS` data-page row limit (so the page index is
/// fine-grained enough for [`read_matching_rows`]'s `POS` `RowSelection`).
///
/// Page-level statistics enable the column (page) index; the offset index is
/// always written. There is no `set_write_page_index` boolean in the `parquet`
/// crate — page-index emission follows from page statistics being enabled.
///
/// `POS` is written `DELTA_BINARY_PACKED` with dictionary encoding disabled for it: the
/// column is physically sorted ascending, so delta beats the dictionary/PLAIN default
/// (dictionary would otherwise remain the primary encoding and delta a never-used
/// fallback). The physical sort order is recorded in each row group's `sorting_columns`
/// footer metadata via `physical_sort_columns`. Neither affects the node's `POS`
/// pruning, which reads statistics/page-index and is encoding-agnostic.
///
/// Both writers build from here rather than repeating the chain, so an encrypted file
/// cannot drift from the plaintext one on compression, statistics, or pruning geometry.
///
/// # Errors
///
/// Returns [`ParquetError`] if the zstd level is rejected by the codec (it is a
/// fixed in-range constant, so this does not happen in practice).
fn base_writer_properties() -> Result<WriterPropertiesBuilder, ParquetError> {
    let level = ZstdLevel::try_new(ZSTD_LEVEL)?;
    Ok(WriterProperties::builder()
        .set_compression(Compression::ZSTD(level))
        .set_statistics_enabled(EnabledStatistics::Page)
        .set_max_row_group_row_count(Some(MAX_ROW_GROUP_SIZE))
        .set_data_page_row_count_limit(DATA_PAGE_ROWS)
        .set_column_dictionary_enabled(ColumnPath::from("POS"), false)
        .set_column_encoding(ColumnPath::from("POS"), Encoding::DELTA_BINARY_PACKED)
        .set_sorting_columns(Some(physical_sort_columns())))
}

/// Build the writer properties for a plaintext parquet: exactly the shared
/// `base_writer_properties`, with no encryption.
///
/// # Errors
///
/// Returns [`ParquetError`] if the zstd level is rejected by the codec (it is a
/// fixed in-range constant, so this does not happen in practice).
pub fn writer_properties() -> Result<WriterProperties, ParquetError> {
    Ok(base_writer_properties()?.build())
}

/// Build writer properties that additionally encrypt the file with Parquet
/// Modular Encryption (uniform encryption, single footer key, encrypted footer).
///
/// Built from the same `base_writer_properties` as [`writer_properties`]. PME encrypts
/// within the parquet structure, so the column index and offset index are preserved, and
/// with them row-group pruning and the page-index `RowSelection`; only the bytes are
/// ciphertext. `footer_key` is the raw 32-byte DEK, held in a zeroize buffer by the
/// caller and taken by value as a `Vec<u8>` by the parquet API. `key_metadata` is the
/// self-describing blob stored so the reader's [`KeyRetriever`] can recover the key.
///
/// Uniform encryption, with no per-column keys, encrypts every page, every column chunk
/// and the footer with the one footer key. The single-reader aggregated tier needs no
/// column-level access control. The footer is encrypted, the default, not
/// plaintext-signed.
///
/// # Errors
///
/// Returns [`ParquetError`] if the zstd level is rejected (a fixed in-range
/// constant — does not happen in practice) or the encryption properties cannot be
/// built.
#[cfg(feature = "pme")]
pub fn writer_properties_encrypted(
    footer_key: Vec<u8>,
    key_metadata: Vec<u8>,
) -> Result<WriterProperties, ParquetError> {
    let base = base_writer_properties()?;
    // Uniform encryption + encrypted footer (both defaults of the builder): no
    // `with_column_key`, no `with_plaintext_footer`.
    let enc = FileEncryptionProperties::builder(footer_key)
        .with_footer_key_metadata(key_metadata)
        .build()?;
    Ok(base.with_file_encryption_properties(enc).build())
}

/// Build [`FileDecryptionProperties`] driven by a [`KeyRetriever`], for reading a
/// PME-encrypted (`PARE`) file.
///
/// The retriever is handed each file's stored `key_metadata` and returns the raw
/// footer key. Used by [`read_matching_rows`] when a retriever is supplied; a
/// plaintext (`PAR1`) file ignores it (parquet self-describes its encryption).
///
/// # Errors
///
/// Returns [`ParquetError`] if the decryption properties cannot be built.
#[cfg(feature = "pme")]
fn decryption_properties(
    retriever: Arc<dyn KeyRetriever>,
) -> Result<Arc<FileDecryptionProperties>, ParquetError> {
    FileDecryptionProperties::with_key_retriever(retriever).build()
}

/// One fully decoded allele-frequency row from an `allele-freq.*.parquet` file.
///
/// The six required columns map to non-`Option` fields; the five count columns
/// (`AC`, `AC_HOM`, `AC_HET`, `AC_HEMI`, `AN`) are `Option<i32>` because they are
/// nullable in the schema (a null decodes to `None`).
#[derive(Debug, Clone, PartialEq)]
pub struct AlleleRow {
    /// 0-based position (`POS`).
    pub pos: i32,
    /// Reference allele (`REF`).
    pub ref_: String,
    /// Alternate allele (`ALT`).
    pub alt: String,
    /// Variant type (`VT`). Held as the enum rather than the stored label: the vocabulary
    /// is closed and five-valued, so an owned `String` would cost 24 bytes of struct plus
    /// its own heap block per retained row to carry at most six bytes.
    pub vt: Vt,
    /// Population key (`POPULATION`).
    pub population: String,
    /// Allele frequency (`AF`).
    pub af: f32,
    /// Allele count (`AC`), `None` when null.
    pub ac: Option<i32>,
    /// Homozygous allele count (`AC_HOM`), `None` when null.
    pub ac_hom: Option<i32>,
    /// Heterozygous allele count (`AC_HET`), `None` when null.
    pub ac_het: Option<i32>,
    /// Hemizygous allele count (`AC_HEMI`), `None` when null.
    pub ac_hemi: Option<i32>,
    /// Allele number (`AN`), `None` when null.
    pub an: Option<i32>,
}

impl AlleleRow {
    /// A conservative estimate of this row's retained heap and stack footprint, for the
    /// Beacon read path's aggregate scan budget.
    ///
    /// Both terms matter, and counting both is what lets one byte ceiling bound two failure
    /// modes. The fixed struct size dominates for the many-rows, short-alleles shape. The
    /// three owned strings dominate for the long-allele shape that ingest admits up to
    /// `max_ref_len` / `max_alt_len` (10 000 bases each), where a single row is about 20 KB
    /// rather than the ~100 B a row-count cap assumes. The weight is defined only here; the
    /// budget check in `beacon` reads it.
    ///
    /// Each string is charged its allocation, not its length: a non-empty one costs at
    /// least the allocator's minimum block, whatever `len()` says. A ceiling denominated in
    /// `len()` units does not bound RSS. The result is still a lower bound on process
    /// footprint, because it is per-row and excludes the container the rows are collected
    /// into and the parquet decode working set.
    #[must_use]
    pub fn scan_weight_bytes(&self) -> u64 {
        // `vt` is a `Copy` enum inside `size_of::<Self>()` — it owns no allocation.
        let strings = string_alloc_bytes(self.ref_.len())
            + string_alloc_bytes(self.alt.len())
            + string_alloc_bytes(self.population.len());
        (std::mem::size_of::<Self>() + strings) as u64
    }
}

/// The smallest heap block a non-empty `String` actually occupies.
///
/// Each of an [`AlleleRow`]'s three strings is its own heap allocation, and no allocator
/// hands back a block as small as a one-base allele: glibc's minimum chunk is 32 bytes.
/// Charging `len()` therefore under-counts the dominant short-allele shape by more than an
/// order of magnitude, which is why a `max_query_bytes` ceiling in those units does not
/// bound RSS.
const MIN_STRING_ALLOC_BYTES: usize = 32;

/// Heap bytes a `String` of `len` really costs: its own allocation, floored at the
/// allocator's minimum block. An empty `String` does not allocate, so it costs nothing.
const fn string_alloc_bytes(len: usize) -> usize {
    if len == 0 {
        0
    } else if len < MIN_STRING_ALLOC_BYTES {
        MIN_STRING_ALLOC_BYTES
    } else {
        len
    }
}

/// An inclusive `POS` window `[lo, hi]` used to prune row groups.
///
/// It is a superset of the matching positions: a row group is skipped only when
/// its `[min POS, max POS]` lies entirely outside this window, so pruning can
/// never drop a row that the predicate would match. The exact predicate then
/// runs over every decoded row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PosWindow {
    /// Inclusive lower bound (a `POS` below this cannot match).
    pub lo: i64,
    /// Inclusive upper bound (a `POS` above this cannot match).
    pub hi: i64,
}

/// Read the rows of one `allele-freq.*.parquet` file matching `keep`, pruning by
/// `POS` row-group statistics against `window`.
///
/// Processing is row-group-at-a-time (the file is never materialised whole),
/// reusing the same decompression-bomb guards as
/// [`crate::validate_parquet::validate_parquet_dir`]: the on-disk file size, the
/// per-row-group declared uncompressed size, and the per-file declared
/// uncompressed working set are all checked against `caps` from the footer
/// metadata before any row group is decoded.
///
/// Pruning uses the `POS` column's footer row-group statistics: a row group whose
/// `[min, max]` lies entirely outside `window` is skipped. When statistics are
/// absent the group is read (correctness over pruning). `keep(pos, ref, alt, vt)`
/// is then applied to every decoded row; matching rows are collected as full
/// [`AlleleRow`]s with nullable counts mapped to `None`.
///
/// On top of the row-group prune, a page-index [`RowSelection`] narrows decoding to
/// only the `POS` pages whose `[min, max]` can intersect `window` (see
/// `pos_row_selection`), so a sparse point or Sequence query decodes a few thousand
/// rows instead of the whole 64Ki-row group. The selection is a superset of the
/// matching rows (page granularity), so `keep` still runs as the exact final filter and
/// the result is identical to a full scan; when the page index is absent the selection
/// is skipped and every row of each kept group is decoded (correctness over pruning).
///
/// # Errors
///
/// Returns [`CoreError::InvalidParquet`] when the file cannot be opened/decoded
/// or exceeds a `caps` bound, [`CoreError::Transient`] when a PME key-retriever
/// reports a transient Vault failure (see [`PME_TRANSIENT_MARKER`]), or
/// [`CoreError::Io`] on a filesystem error.
pub fn read_matching_rows<F: Fn(i32, &str, &str, &str) -> bool>(
    path: &Path,
    caps: &ParquetCaps,
    window: PosWindow,
    keep: &F,
    decryptor: &DatasetDecryptor,
) -> CoreResult<Vec<AlleleRow>> {
    read_matching_rows_budgeted(
        path,
        caps,
        window,
        keep,
        decryptor,
        ScanBudgets::unbounded(),
    )
}

/// Like [`read_matching_rows`], but fails closed with [`CoreError::QueryTooLarge`] as
/// soon as this file's accumulated match set exceeds `budgets.rows` rows — checked after
/// each decoded batch, so a single dense file cannot decode its entire match set into
/// memory before the caller's cumulative cap trips. Pass `None` for the unbounded read
/// (the tool `lint` and bench paths). The beacon serve path passes
/// `Some(caps.max_query_rows - already_collected)`, so a wide `Range` or `Bracket` query
/// fails mid-file at the remaining allowance instead of overshooting the heap cap by a
/// whole file.
///
/// # Errors
///
/// [`CoreError::QueryTooLarge`] when the budget is exceeded, plus every error
/// [`read_matching_rows`] can return (decode / IO / cap violations).
pub fn read_matching_rows_budgeted<F: Fn(i32, &str, &str, &str) -> bool>(
    path: &Path,
    caps: &ParquetCaps,
    window: PosWindow,
    keep: &F,
    decryptor: &DatasetDecryptor,
    budgets: ScanBudgets,
) -> CoreResult<Vec<AlleleRow>> {
    // The panic boundary that turns a decoder panic into `InvalidParquet` lives in
    // `for_each_matching_batch`; this path only collects the batches it yields.
    let mut rows: Vec<AlleleRow> = Vec::new();
    for_each_matching_batch(path, caps, window, keep, decryptor, budgets, |batch| {
        rows.append(batch);
        Ok(())
    })?;
    Ok(rows)
}

/// The cumulative fail-closed ceilings applied while scanning one file, checked after every
/// decoded batch so a dense file cannot materialise its whole match set first.
///
/// There is no `Default` impl: an omitted budget would mean unbounded, so every caller
/// states both fields. `unbounded()` exists for the offline callers (tool `lint`, benches)
/// that have no ceiling.
#[derive(Debug, Clone, Copy)]
pub struct ScanBudgets {
    /// Max cumulative matched rows for this file, or `None` for unbounded.
    pub rows: Option<usize>,
    /// Max cumulative matched-row weight in bytes for this file, or `None` for unbounded.
    pub bytes: Option<u64>,
}

impl ScanBudgets {
    /// No ceiling on either axis — for offline callers with no request behind them.
    #[must_use]
    pub fn unbounded() -> Self {
        Self {
            rows: None,
            bytes: None,
        }
    }
}

/// Stream a file's matching rows to `on_batch` one decoded batch at a time, instead of
/// accumulating them into a `Vec`.
///
/// This is the seam an aggregate query folds over. A `boolean` or `count` answer needs only
/// `exists` and a surviving-group count, so retaining the row set is pure cost, and on a
/// wide query that cost runs to gigabytes. The sink receives the batch by `&mut` and may
/// drain it; it is cleared before each refill either way.
///
/// The cumulative [`ScanBudgets`] are enforced across batches exactly as for
/// the `Vec`-returning path, so a streaming caller gets the same fail-closed behaviour.
///
/// # Errors
/// Propagates the sink's error, and the same decode/cap errors as
/// [`read_matching_rows_budgeted`].
pub fn for_each_matching_batch<F, G>(
    path: &Path,
    caps: &ParquetCaps,
    window: PosWindow,
    keep: &F,
    decryptor: &DatasetDecryptor,
    budgets: ScanBudgets,
    on_batch: G,
) -> CoreResult<()>
where
    F: Fn(i32, &str, &str, &str) -> bool,
    G: FnMut(&mut Vec<AlleleRow>) -> CoreResult<()>,
{
    // arrow/parquet panic rather than erroring on some crafted inputs, so the decode runs
    // under a panic boundary that reports a clean `InvalidParquet`. The boundary covers the
    // caller-supplied sink too: an unwind through it leaves only its own locals broken. The
    // guard also tells the process-level panic hook that this panic is expected and handled,
    // so the hook downgrades its output instead of logging raw panic text.
    crate::panic_guard::catch_decode_panic(
        || read_matching_rows_inner(path, caps, window, keep, decryptor, budgets, on_batch),
        || {
            invalid_parquet(format!(
                "parquet decode panicked on {} (malformed file)",
                path.display()
            ))
        },
    )
}

/// Marker embedded in a PME key-retriever error when the underlying Vault failure is
/// transient, so [`read_matching_rows`] can re-surface the transient class instead of
/// misclassifying a Vault outage as corrupt parquet. The service's `core_to_parquet` maps
/// a `CoreError::Transient` into a `ParquetError` carrying this marker, and the decode path
/// here checks for it.
pub const PME_TRANSIENT_MARKER: &str = "PME DEK unwrap failed (transient)";

/// Classify a parquet build or decode error for the read path. A PME key-retriever
/// transient, which carries [`PME_TRANSIENT_MARKER`], becomes `CoreError::Transient`, so
/// the caller degrades that dataset and an operator chases the Vault outage rather than
/// phantom corruption. Anything else is untrusted-file corruption (`InvalidParquet`).
fn classify_parquet_decode_error(msg: &str, path: &Path) -> CoreError {
    if msg.contains(PME_TRANSIENT_MARKER) {
        CoreError::Transient {
            detail: format!(
                "PME key unavailable while reading {}: {msg}",
                path.display()
            ),
        }
    } else {
        invalid_parquet(format!("cannot decode {}: {msg}", path.display()))
    }
}

fn read_matching_rows_inner<F, G>(
    path: &Path,
    caps: &ParquetCaps,
    window: PosWindow,
    keep: &F,
    decryptor: &DatasetDecryptor,
    budgets: ScanBudgets,
    mut on_batch: G,
) -> CoreResult<()>
where
    F: Fn(i32, &str, &str, &str) -> bool,
    G: FnMut(&mut Vec<AlleleRow>) -> CoreResult<()>,
{
    let on_disk = std::fs::metadata(path)?.len();
    if on_disk > caps.max_parquet_file_bytes {
        return Err(invalid_parquet(format!(
            "parquet file size {on_disk} exceeds max_parquet_file_bytes {}",
            caps.max_parquet_file_bytes
        )));
    }

    let file = std::fs::File::open(path)?;
    let builder = open_reader_builder(file, decryptor, path)?;
    let meta = builder.metadata().clone();

    // One pass over the row-group metadata, in memory and without decoding: enforce the
    // decompressed-size caps and collect the kept indices. POS is column 0, and a row group
    // is kept only when its `[min, max]` can intersect the window; absent statistics fall
    // through and the group is read. Every group's caps are checked before any decode,
    // since this loop completes before the reader is built, and an over-cap group still
    // short-circuits. One reader over the kept set reuses the already-parsed and decrypted
    // footer instead of re-opening the file per surviving group.
    let mut total_decompressed: u64 = 0;
    let mut kept: Vec<usize> = Vec::with_capacity(meta.num_row_groups());
    for i in 0..meta.num_row_groups() {
        let rg = meta.row_group(i);
        // Shared pre-decode decompression-bomb guard; the validate half lives in
        // `validate_parquet`. The per-page half (`parquet_pages::enforce_page_size_caps`)
        // is not repeated here. It runs once at ingest, on provider-supplied bytes, which
        // is where the trust boundary sits. Everything read here is node-owned data that
        // already passed that gate, so re-checking every page on every query would only
        // guard against someone who can already write to `data_dir`, at hot-path cost.
        crate::validate_parquet::enforce_row_group_caps(
            rg.total_byte_size(),
            caps,
            &mut total_decompressed,
        )?;
        if !pos_outside_window(rg.column(0).statistics(), window) {
            kept.push(i);
        }
    }

    let mut out: Vec<AlleleRow> = Vec::new();
    if !kept.is_empty() {
        // Page-index POS prune across the kept groups (None when the page index is
        // absent — then decode every row of each kept group, as before). Built before
        // `with_row_groups` moves `kept`.
        let selection = pos_row_selection(&meta, &kept, window);
        let builder = builder.with_row_groups(kept);
        let builder = match selection {
            Some(sel) => builder.with_row_selection(sel),
            None => builder,
        };
        let reader = builder
            .build()
            .map_err(|e| classify_parquet_decode_error(&e.to_string(), path))?;
        let mut out_bytes: u64 = 0;
        let mut out_rows: usize = 0;
        for batch in reader {
            let batch = batch.map_err(|e| classify_parquet_decode_error(&e.to_string(), path))?;
            out.clear();
            collect_matching(&batch, keep, &mut out)?;
            out_rows = out_rows.saturating_add(out.len());
            // Fail closed as soon as this file's decoded match set exceeds the budget,
            // before decoding the rest of the file, so a single dense file cannot grow the
            // heap by its whole match set before the caller's cumulative cap trips.
            if let Some(budget) = budgets.rows
                && out_rows > budget
            {
                return Err(CoreError::QueryTooLarge {
                    detail: format!(
                        "query matches more than {} rows for one dataset; narrow the position range",
                        caps.max_query_rows
                    ),
                });
            }
            // The same fail-closed check by weight. A row count is a poor proxy for heap:
            // a 10 000-base REF/ALT row weighs about 20 KB against the ~100 B a count
            // assumes, so a match set far under `budgets.rows` can still be gigabytes.
            if let Some(budget) = budgets.bytes {
                out_bytes = out_bytes
                    .saturating_add(out.iter().map(AlleleRow::scan_weight_bytes).sum::<u64>());
                if out_bytes > budget {
                    return Err(CoreError::QueryTooLarge {
                        detail: format!(
                            "query retained more than {budget} bytes of matching rows for one \
                             dataset; narrow the position range"
                        ),
                    });
                }
            }
            on_batch(&mut out)?;
        }
    }
    Ok(())
}
/// The per-page row ranges of one row group, or `None` when the page index is malformed.
///
/// The single derivation of page boundaries from an `OffsetIndex`. Both the serve-time
/// pruner ([`pos_row_selection`]) and the ingest gate's page-bounds verifier read them from
/// here, so neither indexes pages by a raw `first_row_index` it has not validated.
///
/// `first_row_index` is provider-controlled. A non-monotonic index, where a page declares a
/// smaller start than its predecessor, yields an inverted range, and
/// `RowSelection::from_consecutive_ranges` then panics on the `usize` subtraction (or, in a
/// release build with overflow checks off, moments later on a wrapped length). Every Beacon
/// query touching the dataset would fail from then on, for a package that passed the whole
/// ingest gate.
///
/// Returns `None`, never a partial or best-effort list, when the boundaries are not usable,
/// for any of four reasons: the pages do not partition the group from row 0, because a page
/// starts anywhere but where the previous one ended; a page reaches past `group_rows`; the
/// last page ends before `group_rows`; or a group that has rows lists no pages at all. A
/// well-formed writer satisfies all four, so this costs nothing on real data.
///
/// Callers must fail closed on `None`: the serve path by declining to prune and decoding the
/// whole group, which is always correct, and the ingest path by rejecting the file.
pub(crate) fn page_row_ranges(
    off_col: &parquet::file::page_index::offset_index::OffsetIndexMetaData,
    group_rows: usize,
) -> Option<Vec<std::ops::Range<usize>>> {
    let pages = off_col.page_locations();
    let mut out: Vec<std::ops::Range<usize>> = Vec::with_capacity(pages.len());
    let mut prev_end = 0usize;
    for (j, page) in pages.iter().enumerate() {
        let first = usize::try_from(page.first_row_index).ok()?;
        // The first page must start the group; each later page must start exactly where the
        // previous ended (the pages partition the group's rows).
        if first != prev_end {
            return None;
        }
        let last = match pages.get(j + 1) {
            Some(next) => usize::try_from(next.first_row_index).ok()?,
            None => group_rows,
        };
        if last < first || last > group_rows {
            return None;
        }
        out.push(first..last);
        prev_end = last;
    }
    // A complete page list must cover the group exactly.
    if !out.is_empty() && prev_end != group_rows {
        return None;
    }
    // A row group that has rows but lists no pages is malformed, not "nothing to prune".
    // Answering `Some(vec![])` would make `pos_row_selection` push no ranges while still
    // advancing `base` by `group_rows`, so the selection would skip the whole group and the
    // reader would fail every request touching that block. A genuinely empty group
    // (`group_rows == 0`) still yields `Some(vec![])`.
    if out.is_empty() && group_rows > 0 {
        return None;
    }
    Some(out)
}

/// Build a `POS` [`RowSelection`] over the `kept` row groups (in the order they are
/// passed to `with_row_groups`) from the page (column + offset) index: a data page is
/// kept iff its `POS` `[min, max]` can intersect `window`. The returned selection's row
/// indices are relative to the concatenation of the kept groups, as the reader expects.
///
/// Returns `None` when the page index is not loaded (no column/offset index), so the
/// caller falls back to decoding every row of the kept groups. A kept group whose `POS`
/// column index is missing or non-`INT32` selects all of that group's rows (correctness
/// over pruning). The selection is always a superset of the matching rows, and the exact
/// predicate is still applied to every decoded row, so the result is identical to a full
/// scan.
fn pos_row_selection(
    meta: &ParquetMetaData,
    kept: &[usize],
    window: PosWindow,
) -> Option<RowSelection> {
    let column_index = meta.column_index()?;
    let offset_index = meta.offset_index()?;

    let mut ranges: Vec<std::ops::Range<usize>> = Vec::new();
    // Running row offset across the concatenated kept groups.
    let mut base: usize = 0;
    for &rg in kept {
        let group_rows = usize::try_from(meta.row_group(rg).num_rows()).unwrap_or(0);
        // `num_rows` is provider-declared and `base` accumulates it across every kept
        // group, so the running offset is attacker-influenced. In release an overflowing
        // `base + group_rows` wraps silently into a `RowSelection` whose ranges are
        // nonsense, and the reader then decodes the wrong rows or panics. Fail closed the
        // same way a malformed page index does: `None` means decode every row of the kept
        // groups, which is always correct, merely unpruned.
        let group_end = base.checked_add(group_rows)?;
        // POS is column 0. A missing page index for this group (or a non-INT32 POS
        // column index, which never happens for our schema) keeps the whole group.
        match (
            offset_index.get(rg).and_then(|cols| cols.first()),
            column_index.get(rg).and_then(|cols| cols.first()),
        ) {
            (Some(off_col), Some(ColumnIndexMetaData::INT32(pos_idx))) => {
                // Fail closed on a malformed page index: keep the whole group, always
                // correct and merely unpruned, rather than building a range the reader
                // would panic on.
                let Some(page_ranges) = page_row_ranges(off_col, group_rows) else {
                    ranges.push(base..group_end);
                    base = group_end;
                    continue;
                };
                let mins: Vec<Option<&i32>> = pos_idx.min_values_iter().collect();
                let maxs: Vec<Option<&i32>> = pos_idx.max_values_iter().collect();
                for (j, page) in page_ranges.iter().enumerate() {
                    let keep_page = match (
                        mins.get(j).copied().flatten(),
                        maxs.get(j).copied().flatten(),
                    ) {
                        (Some(&mn), Some(&mx)) => {
                            i64::from(mx) >= window.lo && i64::from(mn) <= window.hi
                        }
                        // Missing per-page stats: keep the page (correctness over pruning).
                        _ => true,
                    };
                    if keep_page {
                        // Bounded by `group_end`: `page_row_ranges` returns a partition that
                        // covers the group exactly (it rejects any other shape), so
                        // `page.end <= group_rows` and these sums cannot overflow now that
                        // `base + group_rows` is known to fit.
                        ranges.push((base + page.start)..(base + page.end));
                    }
                }
            }
            _ => ranges.push(base..group_end),
        }
        base = group_end;
    }

    Some(RowSelection::from_consecutive_ranges(
        ranges.into_iter(),
        base,
    ))
}

/// Open a [`ParquetRecordBatchReaderBuilder`] for `file`, decrypting via the
/// `decryptor`'s key retriever when one is present (a `PARE` file) and reading the
/// plaintext path otherwise (a `PAR1` file, or any no-PME build).
///
/// A PME-decrypting open uses [`ParquetRecordBatchReaderBuilder::try_new_with_options`]
/// with `ArrowReaderOptions::with_file_decryption_properties` (that type is only in
/// scope under the `pme` parquet-encryption feature, so it stays a plain code span
/// rather than an intra-doc link), which decrypts the footer so the row-group
/// statistics (and page index) stay usable for pruning.
pub(crate) fn open_reader_builder(
    file: std::fs::File,
    decryptor: &DatasetDecryptor,
    path: &std::path::Path,
) -> CoreResult<ParquetRecordBatchReaderBuilder<std::fs::File>> {
    // Load the page (column + offset) index so `read_matching_rows` can build a `POS`
    // `RowSelection` from it. `Optional` loads it when present (every file this node
    // writes enables page statistics) and silently degrades to row-group-only pruning if
    // a file somehow lacks it — never a hard error.
    #[cfg(feature = "pme")]
    {
        if let Some(props) = decryptor.decryption().map_err(|e| {
            // Route through the classifier so a Vault-transient key failure while building
            // the decryption properties surfaces as `Transient`, not as corrupt parquet.
            classify_parquet_decode_error(
                &format!("cannot build parquet decryption properties: {e}"),
                path,
            )
        })? {
            let opts = ArrowReaderOptions::new()
                .with_page_index_policy(PageIndexPolicy::Optional)
                .with_file_decryption_properties(props);
            // The key retriever runs here first, to decrypt the footer, so a transient Vault
            // outage during footer decryption must be classified as `Transient` rather than
            // `InvalidParquet`. The build and iterate classifiers below never see this error.
            return ParquetRecordBatchReaderBuilder::try_new_with_options(file, opts)
                .map_err(|e| classify_parquet_decode_error(&e.to_string(), path));
        }
    }
    #[cfg(not(feature = "pme"))]
    let _ = (decryptor, path);
    let opts = ArrowReaderOptions::new().with_page_index_policy(PageIndexPolicy::Optional);
    ParquetRecordBatchReaderBuilder::try_new_with_options(file, opts)
        .map_err(|e| invalid_parquet(format!("cannot open parquet: {e}")))
}

/// Probe that every `allele-freq.*.parquet` data file in `dataset_dir` can be opened
/// and its footer read through `decryptor` — a cheap startup "can I read/decrypt my
/// own store" check.
///
/// For a `PARE` (PME) file this decrypts the footer, so a loaded key that cannot decrypt
/// the existing store fails at startup with a clear readiness signal, instead of erroring
/// per query later and silently serving `error` datasets. For a plaintext store it
/// confirms the footer is intact. A dataset directory with no data file is a no-op `Ok`.
///
/// # Errors
///
/// Returns [`CoreError::InvalidParquet`] when the data file cannot be opened or its
/// footer decrypted, or when the parquet decoder *panics* on a malformed file (the
/// panic is caught and mapped to `InvalidParquet` — this function never itself
/// panics on file content), or [`CoreError::Io`] on a filesystem error.
pub fn probe_dataset_readable(
    dataset_dir: &std::path::Path,
    decryptor: &DatasetDecryptor,
) -> CoreResult<()> {
    // Probe every `allele-freq.*.parquet`, not just the first. A dataset holds one file
    // per chromosome and block range, so probing only the first would leave corruption,
    // truncation or a wrong per-file DEK on the rest invisible to the boot self-test and
    // the periodic sweep, both of which run this at `Footer` depth. Sorting makes the
    // failure deterministic: the first bad file by name.
    let mut data_files: Vec<std::path::PathBuf> = Vec::new();
    for entry in std::fs::read_dir(dataset_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if name
            .to_str()
            .is_some_and(crate::s3_layout::is_data_file_name)
        {
            data_files.push(entry.path());
        }
    }
    data_files.sort();
    for path in data_files {
        let file = std::fs::File::open(&path)?;
        // Building the reader reads the footer, decrypts it under PME, and parses the
        // page, column and offset index. The arrow/parquet decoder panics rather than
        // erroring on some crafted inputs, so the call is bounded here and a panic becomes
        // an `Err`. That upholds `scrub_dataset`'s never-panics contract: the probe runs on
        // the readiness self-test's `spawn_blocking` task, where an escaped panic becomes a
        // `JoinError` that latches `/health/ready` to 503 for the process lifetime. On
        // panic the half-built reader is dropped and only an `Err` crosses the boundary, so
        // no partially-mutated state is observed. The guard also marks the panic expected,
        // so the process-level hook downgrades its output instead of logging raw panic text.
        crate::panic_guard::catch_decode_panic(
            || open_reader_builder(file, decryptor, path.as_ref()).map(|_| ()),
            || {
                invalid_parquet(format!(
                    "parquet footer probe panicked on {} (malformed file)",
                    path.display()
                ))
            },
        )?;
    }
    Ok(())
}

/// Re-encode the plaintext parquet at `src` into a PME-encrypted parquet at `dst`,
/// minting a fresh per-file DEK + `key_metadata` via `minter`.
///
/// The store step calls this instead of `fs::copy` when PME is active: it streams
/// `src` row-group-at-a-time (constant memory, like the read path), re-writing
/// each batch through an [`ArrowWriter`](parquet::arrow::arrow_writer::ArrowWriter) configured with
/// [`writer_properties_encrypted`]. The schema is the canonical
/// [`allele_freq_schema`] read from `src` (already validated). The result file
/// carries the `PARE` magic and is self-describing.
///
/// # Errors
///
/// Returns [`CoreError::InvalidParquet`] if `src` cannot be read/decoded or the
/// encrypted writer cannot be built, the typed [`CoreError`] from
/// [`DekMinter::mint`], or [`CoreError::Io`] on a filesystem error.
#[cfg(feature = "pme")]
pub(crate) fn encrypt_parquet_file(
    src: &Path,
    dst: &Path,
    minter: &dyn DekMinter,
) -> CoreResult<()> {
    let (key, key_metadata) = minter.mint()?;
    if key.len() != PME_KEY_LEN {
        return Err(invalid_parquet(format!(
            "minted PME key is {} bytes, expected {PME_KEY_LEN}",
            key.len()
        )));
    }
    let props = writer_properties_encrypted(key.to_vec(), key_metadata).map_err(|e| {
        invalid_parquet(format!(
            "cannot build encrypted parquet writer properties: {e}"
        ))
    })?;

    // Isolate the arrow/parquet decode: the decoder panics rather than erroring on crafted
    // inputs, and this path re-encodes the same untrusted producer parquet that
    // `read_matching_rows` and `probe_dataset_readable` already guard. Without the boundary
    // a crafted package that passes validation would surface as an opaque "ingest task
    // panicked" `JoinError` instead of an `InvalidParquet` naming the file. The inner body
    // can already return `Err` mid-loop, leaving a partial `dst` the caller cleans up, so
    // mapping a panic to `Err` adds no new partial-output case. The guard also marks the
    // panic expected, so the process-level hook downgrades its output.
    crate::panic_guard::catch_decode_panic(
        || encrypt_parquet_file_inner(src, dst, props),
        || {
            invalid_parquet(format!(
                "parquet decode panicked while re-encrypting {} (malformed file)",
                src.display()
            ))
        },
    )
}

/// The decode + re-encrypt body of [`encrypt_parquet_file`], split out so the arrow
/// decode can run under [`std::panic::catch_unwind`] (the decoder panics on crafted
/// inputs). Constant memory (row-group-at-a-time).
#[cfg(feature = "pme")]
#[expect(
    clippy::disallowed_methods,
    reason = "writes into the ingest staging directory that store_atomically renames into place"
)]
fn encrypt_parquet_file_inner(src: &Path, dst: &Path, props: WriterProperties) -> CoreResult<()> {
    use parquet::arrow::arrow_writer::ArrowWriter;

    let in_file = std::fs::File::open(src)?;
    // `PageIndexPolicy::Required`, matching `validate_parquet`'s reader. This is a security
    // boundary, not a tuning knob.
    //
    // The policy selects the page-traversal mode: with the index loaded
    // `SerializedPageReader` runs in `Pages` mode, without it (the `Skip` default a bare
    // `try_new` inherits) in `Values` mode. The validating scan and this re-encode must run
    // in the same mode, because a page decoded here that the scan never decoded would reach
    // the served PARE file without meeting `check_batch_values`, `check_subcounts`, the POS
    // ordering check or the block check. Nothing downstream re-validates a PME store, whose
    // scrub is footer-only, so this is the last gate.
    //
    // The two modes can decode different rows: a `Pages` reader follows the OffsetIndex's
    // listed offsets, while a `Values` walk is bounded by the chunk's `compressed_size`. A
    // truncated `compressed_size` is the sharpest case, where the `Values` walk stops at
    // the shrunk chunk end and a `Pages` reader follows a listed offset beyond it. Two
    // things close that gap: `enforce_page_size_caps` runs on this same ingest path before
    // the store and requires the index to tile the chunk exactly (first page at
    // `data_page_offset`, contiguous, ending at the chunk end), failing closed when the
    // index is absent; and the `clippy.toml` ban on
    // `ParquetRecordBatchReaderBuilder::try_new` keeps both readers on one mode.
    //
    // What matters is the match with `validate_parquet`, not the strictness of `Required`,
    // which is weaker than its name suggests: it errors on a declared but unreadable index
    // and accepts a file that declares none at all. The symmetry is what holds, since both
    // readers run `Pages`/`Pages` on an indexed file and `Values`/`Values` on an index-less
    // one, so the encode can never decode a row the validating scan did not.
    //
    // The Beacon serve path is a third reader over the stored, already-validated parquet,
    // opened under `PageIndexPolicy::Optional` on bytes this gate has passed.
    let builder = ParquetRecordBatchReaderBuilder::try_new_with_options(
        in_file,
        ArrowReaderOptions::new().with_page_index_policy(PageIndexPolicy::Required),
    )
    .map_err(|e| invalid_parquet(format!("cannot open source parquet for encryption: {e}")))?;
    let schema = builder.schema().clone();
    let reader = builder
        .build()
        .map_err(|e| invalid_parquet(format!("cannot build source parquet reader: {e}")))?;

    let out_file = std::fs::File::create(dst)?;
    let mut writer = ArrowWriter::try_new(out_file, schema, Some(props))
        .map_err(|e| invalid_parquet(format!("cannot create encrypted parquet writer: {e}")))?;
    for batch in reader {
        let batch = batch
            .map_err(|e| invalid_parquet(format!("cannot decode source parquet batch: {e}")))?;
        writer
            .write(&batch)
            .map_err(|e| invalid_parquet(format!("cannot write encrypted parquet batch: {e}")))?;
    }
    let file = writer
        .into_inner()
        .map_err(|e| invalid_parquet(format!("cannot finalize encrypted parquet: {e}")))?;
    file.sync_all()?;
    Ok(())
}

/// Store one validated plaintext parquet from `src` into `dst`, encrypting with a
/// freshly-minted DEK when the `encryptor` carries a `DekMinter` (PME on), else
/// copying plaintext verbatim.
///
/// This is the single store-time hook the ingest pipeline calls per parquet file. PME is
/// additive and `Option`-gated through [`DatasetEncryptor`], so the plaintext path is an
/// ordinary `fs::copy`. On the PME path the file is re-encoded via `encrypt_parquet_file`,
/// row-group-at-a-time in constant memory, and lands as a `PARE` file.
///
/// Returns whether the file was encrypted (so the caller can log it); the result
/// is otherwise informational.
///
/// # Errors
///
/// Returns the typed [`CoreError`] from `encrypt_parquet_file` (PME path) or
/// [`CoreError::Io`] on a copy failure.
pub fn store_parquet_file(
    src: &Path,
    dst: &Path,
    encryptor: &DatasetEncryptor,
) -> CoreResult<bool> {
    #[cfg(feature = "pme")]
    {
        if let Some(minter) = encryptor.minter() {
            encrypt_parquet_file(src, dst, minter.as_ref())?;
            return Ok(true);
        }
    }
    #[cfg(not(feature = "pme"))]
    let _ = encryptor;
    #[expect(
        clippy::disallowed_methods,
        reason = "`dst` is in the fresh ingest staging directory, where no symlink can be planted"
    )]
    std::fs::copy(src, dst)?;
    Ok(false)
}

/// True when a row group's `POS` `[min, max]` lies entirely outside `window`.
///
/// Returns `false` (do not prune) when statistics are absent or are not the
/// expected `Int32` variant, or either bound is missing — correctness over
/// pruning.
fn pos_outside_window(stats: Option<&Statistics>, window: PosWindow) -> bool {
    let Some(Statistics::Int32(s)) = stats else {
        return false;
    };
    let (Some(&min), Some(&max)) = (s.min_opt(), s.max_opt()) else {
        return false;
    };
    let (min, max) = (i64::from(min), i64::from(max));
    max < window.lo || min > window.hi
}

/// Apply `keep` to every row of `batch`, pushing full [`AlleleRow`]s for matches.
fn collect_matching<F: Fn(i32, &str, &str, &str) -> bool>(
    batch: &arrow_array::RecordBatch,
    keep: &F,
    out: &mut Vec<AlleleRow>,
) -> CoreResult<()> {
    let pos = col_i32(batch, "POS")?;
    let ref_ = col_str(batch, "REF")?;
    let alt = col_str(batch, "ALT")?;
    let vt = col_str(batch, "VT")?;
    let population = col_str(batch, "POPULATION")?;
    let af = col_f32(batch, "AF")?;
    let ac = col_i32(batch, "AC")?;
    let ac_hom = col_i32(batch, "AC_HOM")?;
    let ac_het = col_i32(batch, "AC_HET")?;
    let ac_hemi = col_i32(batch, "AC_HEMI")?;
    let an = col_i32(batch, "AN")?;

    for i in 0..batch.num_rows() {
        let p = pos.value(i);
        let r = ref_.value(i);
        let a = alt.value(i);
        let v = vt.value(i);
        if !keep(p, r, a, v) {
            continue;
        }
        out.push(AlleleRow {
            pos: p,
            ref_: r.to_string(),
            alt: a.to_string(),
            vt: Vt::parse(v).ok_or_else(|| {
                invalid_parquet(format!("VT {v:?} is not one of SNP/MNP/INS/DEL/DELINS"))
            })?,
            population: population.value(i).to_string(),
            af: af.value(i),
            ac: opt_i32(ac, i),
            ac_hom: opt_i32(ac_hom, i),
            ac_het: opt_i32(ac_het, i),
            ac_hemi: opt_i32(ac_hemi, i),
            an: opt_i32(an, i),
        });
    }
    Ok(())
}

/// Read a nullable `Int32` cell as `Option<i32>`.
fn opt_i32(col: &Int32Array, i: usize) -> Option<i32> {
    if col.is_null(i) {
        None
    } else {
        Some(col.value(i))
    }
}

/// Downcast a column to `Int32Array`.
pub(crate) fn col_i32<'a>(
    batch: &'a arrow_array::RecordBatch,
    name: &str,
) -> CoreResult<&'a Int32Array> {
    batch
        .column_by_name(name)
        .and_then(|c| c.as_any().downcast_ref::<Int32Array>())
        .ok_or_else(|| invalid_parquet(format!("column {name} is not Int32")))
}

/// Downcast a column to `Float32Array`.
pub(crate) fn col_f32<'a>(
    batch: &'a arrow_array::RecordBatch,
    name: &str,
) -> CoreResult<&'a Float32Array> {
    batch
        .column_by_name(name)
        .and_then(|c| c.as_any().downcast_ref::<Float32Array>())
        .ok_or_else(|| invalid_parquet(format!("column {name} is not Float32")))
}

/// Downcast a column to `StringArray`.
pub(crate) fn col_str<'a>(
    batch: &'a arrow_array::RecordBatch,
    name: &str,
) -> CoreResult<&'a StringArray> {
    batch
        .column_by_name(name)
        .and_then(|c| c.as_any().downcast_ref::<StringArray>())
        .ok_or_else(|| invalid_parquet(format!("column {name} is not Utf8")))
}

#[cfg(test)]
mod page_index_tests {
    //! `page_row_ranges` is the fail-closed boundary derivation both the serve pruner and
    //! the ingest gate read. These pin the malformed shapes that must not reach
    //! `RowSelection::from_consecutive_ranges` as an inverted range, which panics every
    //! query touching the dataset.
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use parquet::file::page_index::offset_index::{OffsetIndexMetaData, PageLocation};

    /// Build an `OffsetIndexMetaData` from the given `first_row_index` values.
    fn off_index(firsts: &[i64]) -> OffsetIndexMetaData {
        let locations = firsts
            .iter()
            .map(|&first_row_index| PageLocation {
                offset: 0,
                compressed_page_size: 0,
                first_row_index,
            })
            .collect();
        OffsetIndexMetaData {
            page_locations: locations,
            unencoded_byte_array_data_bytes: None,
        }
    }

    #[test]
    fn a_well_formed_page_index_partitions_the_group() {
        let ranges = super::page_row_ranges(&off_index(&[0, 400, 700]), 1000).unwrap();
        assert_eq!(ranges, vec![0..400, 400..700, 700..1000]);
    }

    #[test]
    fn a_non_monotonic_page_index_is_rejected() {
        // The crafted shape: page 0 declares 500, page 1 declares 100 => `500..100`.
        assert!(super::page_row_ranges(&off_index(&[500, 100]), 1000).is_none());
    }

    #[test]
    fn a_page_index_not_starting_at_zero_is_rejected() {
        assert!(super::page_row_ranges(&off_index(&[7, 400]), 1000).is_none());
    }

    #[test]
    fn a_page_index_reaching_past_the_group_is_rejected() {
        assert!(super::page_row_ranges(&off_index(&[0, 400]), 300).is_none());
    }

    #[test]
    fn an_empty_page_list_for_a_group_with_rows_is_rejected() {
        // A row group declaring rows while listing no pages is malformed. Answering
        // `Some(vec![])`, meaning "prunes nothing", would make `pos_row_selection` emit a
        // skip over the whole group, which the reader rejects and every query touching the
        // block fails. Both consumers fail closed on `None`: the serve path decodes the
        // whole group, the ingest gate rejects the file.
        assert!(super::page_row_ranges(&off_index(&[]), 1000).is_none());
    }

    #[test]
    fn an_empty_page_list_for_an_empty_group_prunes_nothing() {
        // The legitimate empty case must stay `Some(vec![])`: there is nothing to select.
        assert_eq!(super::page_row_ranges(&off_index(&[]), 0), Some(vec![]));
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;

    #[test]
    fn scan_weight_bytes_counts_the_struct_plus_owned_strings() {
        // The weight must include both the fixed struct footprint, dominant for the
        // many-rows short-allele shape, and the three owned strings, dominant for the
        // 10 000-base-allele shape. Counting only the strings would let tens of millions of
        // one-character rows slip under a byte cap while consuming gigabytes.
        let base = std::mem::size_of::<AlleleRow>() as u64;
        let short = AlleleRow {
            pos: 1,
            ref_: "A".to_owned(),
            alt: "T".to_owned(),
            vt: Vt::Snp,
            population: "Total".to_owned(),
            af: 0.1,
            ac: Some(1),
            ac_hom: None,
            ac_het: None,
            ac_hemi: None,
            an: Some(10),
        };
        // Each string is charged its allocation, not its length: three separate heap blocks,
        // each floored at the allocator minimum. Charging (1 + 1 + 5) = 7 B would let a byte
        // ceiling pass far more rows than it believes.
        assert_eq!(
            short.scan_weight_bytes(),
            base + 3 * MIN_STRING_ALLOC_BYTES as u64,
            "three owned strings: ref_, alt, population (vt is a Copy enum in the struct)"
        );

        // A long-allele row is far heavier: the case a row-count cap misses.
        let long = AlleleRow {
            ref_: "A".repeat(10_000),
            alt: "C".repeat(10_000),
            ..short
        };
        // Past the allocator floor a string costs its length, so the ~20 KB row dominates.
        assert_eq!(
            long.scan_weight_bytes(),
            base + 10_000 + 10_000 + MIN_STRING_ALLOC_BYTES as u64
        );
        assert!(
            long.scan_weight_bytes() > 20_000,
            "a 10k-base row weighs ~20 KB, not the ~100 B a row count assumes"
        );
    }

    #[test]
    fn scan_weight_never_charges_a_string_less_than_it_allocates() {
        // Every non-empty string must be charged at least one allocator block, whatever its
        // length; an empty one allocates nothing and must stay free. Charging `len()` would
        // put a one-base SNP row's strings at 10 B against roughly 96 B of real heap, and a
        // ceiling in those units cannot bound RSS: the process can be several times heavier
        // per row than the budget believes, so a `max_total_query_bytes` set well under the
        // container limit still ends in an OOM kill rather than a shed.
        let row = AlleleRow {
            pos: 1,
            ref_: "A".to_owned(),
            alt: "T".to_owned(),
            vt: Vt::Snp,
            population: "EE".to_owned(),
            af: 0.1,
            ac: Some(1),
            ac_hom: None,
            ac_het: None,
            ac_hemi: None,
            an: Some(10),
        };
        let base = std::mem::size_of::<AlleleRow>() as u64;
        let charged_for_strings = row.scan_weight_bytes() - base;
        assert!(
            charged_for_strings >= 3 * MIN_STRING_ALLOC_BYTES as u64,
            "three short strings are three separate heap blocks, not \
             {charged_for_strings} bytes"
        );

        assert_eq!(
            string_alloc_bytes(0),
            0,
            "an empty String does not allocate"
        );
        assert_eq!(string_alloc_bytes(1), MIN_STRING_ALLOC_BYTES);
        assert_eq!(
            string_alloc_bytes(MIN_STRING_ALLOC_BYTES),
            MIN_STRING_ALLOC_BYTES
        );
        assert_eq!(
            string_alloc_bytes(10_000),
            10_000,
            "past the floor, len wins"
        );

        // The weight must stay monotonic in allele length, or the long-allele bound the
        // two-term design exists for is lost.
        let long = AlleleRow {
            ref_: "A".repeat(10_000),
            ..row
        };
        assert!(long.scan_weight_bytes() > 10_000);
    }

    #[test]
    fn read_matching_rows_isolates_a_malformed_file_panic() {
        // A decode panic on the read path, here a malformed `ARROW:schema` flatbuffer,
        // must become a clean `InvalidParquet` error rather than abort: the tool `lint`
        // path has no request-level unwind isolation. Reuses the validate panic fixture.
        let path = std::path::Path::new("tests/fixtures/malformed/arrow_schema_panic.parquet");
        let dec = DatasetDecryptor::plaintext();
        let err = read_matching_rows(
            path,
            &ParquetCaps::default(),
            PosWindow {
                lo: 0,
                hi: i64::MAX,
            },
            &|_, _, _, _| true,
            &dec,
        )
        .expect_err("a malformed parquet must be an error, not a panic");
        std::assert_matches!(
            err,
            CoreError::InvalidParquet { .. },
            "expected InvalidParquet, got {err:?}"
        );
        assert!(
            format!("{err}").contains("panicked"),
            "expected the panic-boundary detail: {err}"
        );
    }

    #[test]
    fn pme_transient_decode_error_is_reclassified_transient() {
        // A Vault transient carried via `PME_TRANSIENT_MARKER` re-surfaces as `Transient`,
        // so operators chase the Vault outage rather than phantom corruption, while any
        // other decode error stays `InvalidParquet` (untrusted-file corruption).
        let p = std::path::Path::new("allele-freq.chr1.0.br1.x.parquet");
        let transient =
            classify_parquet_decode_error(&format!("{PME_TRANSIENT_MARKER}: vault down"), p);
        std::assert_matches!(transient, CoreError::Transient { .. }, "got {transient:?}");
        let corrupt = classify_parquet_decode_error("malformed flatbuffer", p);
        std::assert_matches!(corrupt, CoreError::InvalidParquet { .. }, "got {corrupt:?}");
    }

    #[test]
    fn schema_has_eleven_columns_with_expected_nullability() {
        let schema = allele_freq_schema();
        let fields = schema.fields();
        assert_eq!(fields.len(), 11);

        let names: Vec<&str> = fields.iter().map(|f| f.name().as_str()).collect();
        assert_eq!(
            names,
            [
                "POS",
                "REF",
                "ALT",
                "VT",
                "POPULATION",
                "AF",
                "AC",
                "AC_HOM",
                "AC_HET",
                "AC_HEMI",
                "AN",
            ]
        );

        // POS/REF/ALT/VT/POPULATION/AF are required; the five counts are nullable.
        for name in ["POS", "REF", "ALT", "VT", "POPULATION", "AF"] {
            let f = schema.field_with_name(name).unwrap();
            assert!(!f.is_nullable(), "{name} must be non-nullable");
        }
        for name in ["AC", "AC_HOM", "AC_HET", "AC_HEMI", "AN"] {
            let f = schema.field_with_name(name).unwrap();
            assert!(f.is_nullable(), "{name} must be nullable");
        }
    }

    /// Doc-drift guard: the parquet column list in `docs/gdi-dataset-tool.md` must match
    /// the schema's field names, in order. The expected list is built from
    /// `allele_freq_schema()` rather than hand-copied, so a column rename, reorder or
    /// addition fails here. An ordered comma list cannot be satisfied by incidental prose.
    #[test]
    fn doc_parquet_column_list_matches_the_schema() {
        let joined = allele_freq_schema()
            .fields()
            .iter()
            .map(|f| f.name().as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let doc = include_str!("../../../docs/gdi-dataset-tool.md");
        // Match a whole line rather than a substring: `contains` would be satisfied by a
        // renamed trailing column, since `…AN` is a prefix of `…ANX`. A whole line pins
        // names, order and completeness.
        assert!(
            doc.lines().any(|l| l.trim() == joined),
            "docs/gdi-dataset-tool.md must have the exact parquet column list on one line \
             (\"{joined}\") — it has drifted from allele_freq_schema()"
        );
    }

    #[test]
    fn writer_properties_build() {
        let props = writer_properties().unwrap();
        assert_eq!(
            props.compression(&"AF".into()),
            Compression::ZSTD(ZstdLevel::try_new(ZSTD_LEVEL).unwrap())
        );
        assert_eq!(
            props.statistics_enabled(&"AF".into()),
            EnabledStatistics::Page
        );
        assert_eq!(
            props.max_row_group_row_count(),
            Some(MAX_ROW_GROUP_SIZE),
            "row-group size must be capped so POS pruning is sub-block granular"
        );
        assert_eq!(
            props.data_page_row_count_limit(),
            DATA_PAGE_ROWS,
            "data-page row count drives page-index POS RowSelection granularity"
        );
    }

    /// Write a tiny POS-sorted allele-freq file (POS 0..99) with the production
    /// [`writer_properties`], returning the tempdir (kept alive by the caller) and the
    /// file path.
    fn write_small_allele_file() -> (tempfile::TempDir, std::path::PathBuf) {
        let pos: Vec<i32> = (0..100).collect();
        write_allele_file(
            &pos,
            &vec![Some(1); pos.len()],
            writer_properties().unwrap(),
        )
    }

    #[test]
    fn writer_delta_encodes_the_pos_column() {
        // POS is physically sorted ascending — the ideal case for DELTA_BINARY_PACKED,
        // which beats the dictionary/PLAIN default. Dictionary must be disabled on POS
        // or it stays the primary encoding and delta is only a never-used fallback.
        let (_dir, path) = write_small_allele_file();
        #[expect(
            clippy::disallowed_methods,
            reason = "test fixture: reads a parquet this test just wrote, not untrusted input"
        )]
        let builder =
            ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(&path).unwrap()).unwrap();
        let encodings: Vec<parquet::basic::Encoding> = builder
            .metadata()
            .row_group(0)
            .column(0)
            .encodings()
            .collect();
        assert!(
            encodings.contains(&parquet::basic::Encoding::DELTA_BINARY_PACKED),
            "POS must be delta-encoded, got {encodings:?}"
        );
        assert!(
            !encodings.contains(&parquet::basic::Encoding::RLE_DICTIONARY)
                && !encodings.contains(&parquet::basic::Encoding::PLAIN_DICTIONARY),
            "POS dictionary encoding must be disabled, got {encodings:?}"
        );
    }

    #[test]
    fn writer_records_the_physical_sort_order_in_the_footer() {
        // The rows are physically sorted (POS, REF, ALT, POPULATION); the footer's
        // sorting_columns must advertise exactly that so external readers can trust it.
        let (_dir, path) = write_small_allele_file();
        #[expect(
            clippy::disallowed_methods,
            reason = "test fixture: reads a parquet this test just wrote, not untrusted input"
        )]
        let builder =
            ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(&path).unwrap()).unwrap();
        let md = builder.metadata();
        let sorting = md
            .row_group(0)
            .sorting_columns()
            .expect("sorting_columns must be written to the footer");
        let idxs: Vec<i32> = sorting.iter().map(|s| s.column_idx).collect();
        assert_eq!(
            idxs,
            vec![0, 1, 2, 4],
            "sort key is (POS, REF, ALT, POPULATION)"
        );
        assert!(
            sorting.iter().all(|s| !s.descending),
            "all columns ascending"
        );
    }

    #[test]
    fn writer_caps_row_groups_so_a_large_batch_splits() {
        use parquet::arrow::arrow_writer::ArrowWriter;

        // A single batch larger than the cap (one (chr,block) RecordBatch in the
        // real convert path) must be written as more than one row group, so the
        // min/max-POS row-group statistics prune at sub-batch granularity rather
        // than forcing a whole-block decode for a point query.
        let n = MAX_ROW_GROUP_SIZE + 1_000;
        let schema = Arc::new(Schema::new(vec![Field::new("POS", DataType::Int32, false)]));
        let col = Int32Array::from_iter_values(0..i32::try_from(n).unwrap());
        let batch =
            arrow_array::RecordBatch::try_new(Arc::clone(&schema), vec![Arc::new(col)]).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rowgroups.parquet");
        let file = std::fs::File::create(&path).unwrap();
        let mut writer =
            ArrowWriter::try_new(file, schema, Some(writer_properties().unwrap())).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();

        let in_file = std::fs::File::open(&path).unwrap();
        #[expect(
            clippy::disallowed_methods,
            reason = "test fixture: reads a parquet this test just wrote, not untrusted input"
        )]
        let builder = ParquetRecordBatchReaderBuilder::try_new(in_file).unwrap();
        assert!(
            builder.metadata().num_row_groups() > 1,
            "a {n}-row batch must span >1 row group at cap {MAX_ROW_GROUP_SIZE}"
        );
    }

    #[test]
    fn page_index_row_selection_matches_full_scan() {
        // 12 000 ascending-POS rows (POS == row index) in small row groups of 4 000 and
        // small pages of 1 000: 3 row groups of 4 pages each. A query that keeps several
        // row groups and skips pages within them stresses the page-index `RowSelection`
        // and its per-kept-group base offset. The selection is a page-granular superset,
        // so the exact predicate must yield the same rows as a brute-force scan.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pages.parquet");
        write_multipage_pos_fixture(&path, 12_000);

        // Sanity: the fixture really is multi-row-group and multi-page, or the test
        // exercises nothing.
        let probe = ParquetRecordBatchReaderBuilder::try_new_with_options(
            std::fs::File::open(&path).unwrap(),
            ArrowReaderOptions::new().with_page_index_policy(PageIndexPolicy::Required),
        )
        .unwrap();
        assert!(probe.metadata().num_row_groups() >= 3);
        assert!(
            probe.metadata().offset_index().is_some(),
            "page index loaded"
        );

        let caps = ParquetCaps::default();
        let dec = DatasetDecryptor::plaintext();
        let read = |lo: i64, hi: i64, keep: &dyn Fn(i32) -> bool| -> Vec<i32> {
            read_matching_rows(
                &path,
                &caps,
                PosWindow { lo, hi },
                &|p, _, _, _| keep(p),
                &dec,
            )
            .unwrap()
            .iter()
            .map(|r| r.pos)
            .collect()
        };

        // Point query for a POS outside the first page of its row group, so a real page
        // is skipped: exactly one row, the matching POS.
        assert_eq!(read(7_777, 7_777, &|p| p == 7_777), vec![7_777]);

        // A range spanning several row groups, with page-skipped ends in the first and
        // last kept groups, must equal the brute-force scan.
        let want: Vec<i32> = (3_500..=9_500).collect();
        assert_eq!(read(3_500, 9_500, &|p| (3_500..=9_500).contains(&p)), want);

        // A window past every row prunes to nothing.
        assert!(read(1_000_000, 2_000_000, &|_| true).is_empty());
    }

    #[test]
    fn read_matching_rows_budgeted_trips_mid_file() {
        // One dense file must fail closed at the row budget rather than accumulate its
        // entire match set first. A 10 000-row file of 3 row groups read with a budget of
        // 10 returns `QueryTooLarge` after the first decoded batch (4 000 rows > 10) and
        // never decodes groups 2 and 3. The unbudgeted read of the same file still returns
        // every row, for the tool `lint` and bench callers.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allele-freq.chr1.0.br10000000.0.parquet");
        write_multipage_pos_fixture(&path, 10_000);
        let caps = ParquetCaps::default();
        let dec = DatasetDecryptor::plaintext();
        let window = PosWindow {
            lo: i64::MIN,
            hi: i64::MAX,
        };

        let err = read_matching_rows_budgeted(
            &path,
            &caps,
            window,
            &|_, _, _, _| true,
            &dec,
            ScanBudgets {
                rows: Some(10),
                bytes: None,
            },
        )
        .unwrap_err();
        std::assert_matches!(
            err,
            CoreError::QueryTooLarge { .. },
            "a single file exceeding the budget must be QueryTooLarge, got {err:?}"
        );

        let all = read_matching_rows(&path, &caps, window, &|_, _, _, _| true, &dec).unwrap();
        assert_eq!(
            all.len(),
            10_000,
            "the unbudgeted read still returns every row"
        );
    }

    /// The streaming seam must be row-for-row identical to the `Vec` path.
    ///
    /// `read_matching_rows_budgeted` is implemented on top of `for_each_matching_batch`, so
    /// a divergence here means the aggregate query path, which folds over the stream, and
    /// the record path, which collects it, disagree about what a query matched. That
    /// produces a wrong `numTotalResults` rather than a visible failure. Pins order and
    /// content, not just count.
    #[test]
    fn for_each_matching_batch_streams_exactly_the_vec_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allele-freq.chr1.0.br10000000.0.parquet");
        // 10 000 rows over 3 row groups and several pages, so the sink is invoked many
        // times and a dropped or double-counted batch shows up.
        write_multipage_pos_fixture(&path, 10_000);
        let caps = ParquetCaps::default();
        let dec = DatasetDecryptor::plaintext();
        let window = PosWindow {
            lo: i64::MIN,
            hi: i64::MAX,
        };

        let collected = read_matching_rows_budgeted(
            &path,
            &caps,
            window,
            &|_, _, _, _| true,
            &dec,
            ScanBudgets::unbounded(),
        )
        .unwrap();

        let mut streamed: Vec<AlleleRow> = Vec::new();
        let mut batches = 0usize;
        for_each_matching_batch(
            &path,
            &caps,
            window,
            &|_, _, _, _| true,
            &dec,
            ScanBudgets::unbounded(),
            |batch| {
                batches += 1;
                streamed.append(batch);
                Ok(())
            },
        )
        .unwrap();

        assert!(
            batches > 1,
            "fixture must span several batches for this to test anything (got {batches})"
        );
        assert_eq!(
            streamed.len(),
            collected.len(),
            "streamed and collected row counts must match"
        );
        assert!(
            streamed
                .iter()
                .zip(collected.iter())
                .all(|(a, b)| a.pos == b.pos && a.ref_ == b.ref_ && a.alt == b.alt),
            "streamed rows must match the Vec path in ORDER, not just in count"
        );
    }

    /// An error returned by the sink must propagate out rather than being swallowed — the
    /// fold uses this to fail closed (e.g. on an out-of-order group key).
    #[test]
    fn for_each_matching_batch_propagates_a_sink_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allele-freq.chr1.0.br10000000.0.parquet");
        write_multipage_pos_fixture(&path, 10_000);
        let caps = ParquetCaps::default();
        let dec = DatasetDecryptor::plaintext();
        let window = PosWindow {
            lo: i64::MIN,
            hi: i64::MAX,
        };

        let err = for_each_matching_batch(
            &path,
            &caps,
            window,
            &|_, _, _, _| true,
            &dec,
            ScanBudgets::unbounded(),
            |_| {
                Err(CoreError::QueryTooLarge {
                    detail: "sink refused".to_owned(),
                })
            },
        )
        .unwrap_err();
        std::assert_matches!(
            err,
            CoreError::QueryTooLarge { .. },
            "the sink's error must reach the caller, got {err:?}"
        );
    }

    /// The byte ceiling must fail closed mid-file too, not only the row count.
    ///
    /// A row count is a poor proxy for heap: a long-allele row weighs about 20 KB against
    /// the ~100 B a count assumes, so a match set comfortably under `max_query_rows` can
    /// still be gigabytes. A byte ceiling checked only after a dataset's whole match set is
    /// materialised cannot prevent the allocation it exists to bound.
    #[test]
    fn read_matching_rows_budgeted_trips_mid_file_on_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allele-freq.chr1.0.br10000000.0.parquet");
        write_multipage_pos_fixture(&path, 10_000);
        let caps = ParquetCaps::default();
        let dec = DatasetDecryptor::plaintext();
        let window = PosWindow {
            lo: i64::MIN,
            hi: i64::MAX,
        };

        // A generous row budget with a tight byte budget: only the byte check can trip.
        let err = read_matching_rows_budgeted(
            &path,
            &caps,
            window,
            &|_, _, _, _| true,
            &dec,
            ScanBudgets {
                rows: Some(usize::MAX),
                bytes: Some(1024),
            },
        )
        .unwrap_err();
        std::assert_matches!(
            err,
            CoreError::QueryTooLarge { .. },
            "a file exceeding the BYTE budget must be QueryTooLarge, got {err:?}"
        );

        // The same read with a byte budget above the file's weight still returns everything,
        // so the check bounds without truncating a legitimate result.
        let all = read_matching_rows_budgeted(
            &path,
            &caps,
            window,
            &|_, _, _, _| true,
            &dec,
            ScanBudgets {
                rows: Some(usize::MAX),
                bytes: Some(u64::MAX),
            },
        )
        .unwrap();
        assert_eq!(
            all.len(),
            10_000,
            "a byte budget above the match set's weight must not drop rows"
        );
    }

    /// Write `n` ascending-POS rows (POS == row index) into a canonical-schema parquet with
    /// row groups of 4 000 and pages of 1 000: `n / 4 000` row groups of four pages each.
    /// This is the geometry every pruning test relies on.
    fn write_multipage_pos_fixture(path: &std::path::Path, n: i32) {
        let pos: Vec<i32> = (0..n).collect();
        let props = WriterProperties::builder()
            .set_statistics_enabled(EnabledStatistics::Page)
            .set_max_row_group_row_count(Some(4_000))
            .set_data_page_row_count_limit(1_000)
            .build();
        write_allele_file_at(path, &pos, &vec![Some(1); pos.len()], props);
    }

    #[test]
    fn pruning_decodes_only_surviving_pages_not_the_whole_file() {
        // `page_index_row_selection_matches_full_scan` proves the pruned read returns the
        // same rows as a full scan, but it would also pass if pruning stopped entirely and
        // every row group and page were kept: the exact `keep` predicate re-filters each
        // decoded row, so the result stays correct while only performance degrades. This
        // test guards the pruning invariant itself. `keep` is invoked once per decoded row,
        // so counting its calls measures decode work, and a narrow query must decode far
        // fewer rows than the file holds.
        let n: i32 = 12_000; // 3 row groups (4 000) × 4 pages (1 000)
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("pages.parquet");
        write_multipage_pos_fixture(&path, n);

        let caps = ParquetCaps::default();
        let dec = DatasetDecryptor::plaintext();
        // `keep` is called once per decoded row; count the calls to measure decode work.
        // Returns (rows_matched, rows_decoded).
        let read_counting = |lo: i64, hi: i64| -> (usize, usize) {
            let decoded = std::cell::Cell::new(0usize);
            let rows = read_matching_rows(
                &path,
                &caps,
                PosWindow { lo, hi },
                &|p, _, _, _| {
                    decoded.set(decoded.get() + 1);
                    lo <= i64::from(p) && i64::from(p) <= hi
                },
                &dec,
            )
            .unwrap();
            (rows.len(), decoded.get())
        };

        // Control: a whole-file query matches everything, so every row is decoded — this
        // proves the counter actually counts decode work, i.e. the small numbers below are
        // pruning, not a dead counter.
        let (matched, decoded) = read_counting(0, i64::from(n));
        assert_eq!(matched, 12_000);
        assert_eq!(decoded, 12_000, "a full-range query decodes every row");

        // Row-group pruning: a window past every row decodes nothing, because all three
        // row groups are pruned on their POS statistics before any decode. Without it all
        // 12 000 rows would be decoded and `keep` called 12 000 times.
        let (matched, decoded) = read_counting(1_000_000, 2_000_000);
        assert_eq!(matched, 0);
        assert_eq!(
            decoded, 0,
            "out-of-window: row-group pruning skips all decode"
        );

        // Page pruning: a point query decodes about one 1 000-row page, not the whole
        // surviving 4 000-row group and not the 12 000-row file, so the page-index prune
        // fires on top of the row-group prune. Without the page prune this would be ~4 000,
        // the whole kept group; without either, ~12 000.
        let (matched, decoded) = read_counting(7_777, 7_777);
        assert_eq!(matched, 1, "the one matching row");
        assert!(
            decoded <= 1_000,
            "page pruning should decode ~one 1 000-row page, decoded {decoded}"
        );
    }

    /// Write an allele-freq parquet at `path` under `props`, taking `POS` and `AC` from the
    /// given slices. The four other count columns mirror `AC`, and REF/ALT/VT/POPULATION/AF
    /// are placeholders. Every read-path test builds on this, so the canonical
    /// eleven-column batch is spelled out once.
    fn write_allele_file_at(
        path: &std::path::Path,
        pos: &[i32],
        ac: &[Option<i32>],
        props: WriterProperties,
    ) {
        use parquet::arrow::arrow_writer::ArrowWriter;
        let count = pos.len();
        let schema = allele_freq_schema();
        let s = |v: &str| StringArray::from(vec![v; count]);
        let ac_arr = Int32Array::from(ac.to_vec());
        let batch = arrow_array::RecordBatch::try_new(
            Arc::clone(&schema),
            vec![
                Arc::new(Int32Array::from(pos.to_vec())),
                Arc::new(s("A")),
                Arc::new(s("G")),
                Arc::new(s("SNP")),
                Arc::new(s("Total")),
                Arc::new(Float32Array::from(vec![0.1_f32; count])),
                Arc::new(ac_arr.clone()),
                Arc::new(ac_arr.clone()),
                Arc::new(ac_arr.clone()),
                Arc::new(ac_arr.clone()),
                Arc::new(ac_arr),
            ],
        )
        .unwrap();
        let file = std::fs::File::create(path).unwrap();
        let mut writer = ArrowWriter::try_new(file, schema, Some(props)).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
    }

    /// As [`write_allele_file_at`], into a fresh tempdir; returns the tempdir (kept alive
    /// by the caller) and the path.
    fn write_allele_file(
        pos: &[i32],
        ac: &[Option<i32>],
        props: WriterProperties,
    ) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allele.parquet");
        write_allele_file_at(&path, pos, ac, props);
        (dir, path)
    }

    #[test]
    fn read_decodes_nullable_counts_present_and_null() {
        // `opt_i32` decodes every nullable count on the non-pme read path: a present AC
        // must decode to `Some(n)` and an absent one to `None`. The other count-asserting
        // tests live in the `pme` submodule, which does not run in a lite build. Value 7,
        // which is none of 0, 1 or -1, plus the null row cover the mutants of `opt_i32`.
        let (_dir, path) = write_allele_file(
            &[10, 20],
            &[Some(7), None],
            WriterProperties::builder()
                .set_statistics_enabled(EnabledStatistics::Chunk)
                .build(),
        );
        let rows = read_matching_rows(
            &path,
            &ParquetCaps::default(),
            PosWindow { lo: 0, hi: 1000 },
            &|_, _, _, _| true,
            &DatasetDecryptor::plaintext(),
        )
        .unwrap();
        let present = rows.iter().find(|r| r.pos == 10).unwrap();
        assert_eq!(present.ac, Some(7), "a non-null AC must decode to Some(7)");
        let null = rows.iter().find(|r| r.pos == 20).unwrap();
        assert_eq!(null.ac, None, "a null AC must decode to None");
    }

    #[test]
    fn read_keeps_row_groups_touching_the_window_boundary() {
        // `pos_outside_window` prunes a row group only when it lies entirely outside the
        // window: `max < lo || min > hi`. A group whose max POS equals `lo`, or whose min
        // POS equals `hi`, still touches the boundary and must be kept. Chunk-only
        // statistics with no page index isolate the row-group prune, so a comparison that
        // prunes the abutting group drops the boundary row.
        //
        // 30 rows POS 0..29 in row groups of 10 → groups [0..9], [10..19], [20..29].
        // Query [9, 20]: group 0's max (9) == lo and group 2's min (20) == hi.
        let pos: Vec<i32> = (0..30).collect();
        let ac = vec![Some(1i32); 30];
        let (_dir, path) = write_allele_file(
            &pos,
            &ac,
            WriterProperties::builder()
                .set_statistics_enabled(EnabledStatistics::Chunk)
                .set_max_row_group_row_count(Some(10))
                .build(),
        );
        // Sanity: the fixture really is multiple row groups (else nothing is pruned).
        #[expect(
            clippy::disallowed_methods,
            reason = "test fixture: reads a parquet this test just wrote, not untrusted input"
        )]
        let probe =
            ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(&path).unwrap()).unwrap();
        assert!(
            probe.metadata().num_row_groups() >= 3,
            "fixture must be multi-row-group"
        );

        let rows = read_matching_rows(
            &path,
            &ParquetCaps::default(),
            PosWindow { lo: 9, hi: 20 },
            &|p, _, _, _| (9..=20).contains(&p),
            &DatasetDecryptor::plaintext(),
        )
        .unwrap();
        let got: Vec<i32> = rows.iter().map(|r| r.pos).collect();
        assert_eq!(
            got,
            (9..=20).collect::<Vec<i32>>(),
            "boundary rows (max==lo and min==hi) must not be pruned"
        );
    }

    #[test]
    fn read_rejects_a_file_over_the_size_cap() {
        // The on-disk file-size cap is `on_disk > max_parquet_file_bytes`. Every other read
        // test uses the 1 GiB default with tiny files, so the guard never fires there.
        // Setting the cap one byte below the real file size makes the strict `>` fire, and
        // an `==` comparison would wrongly accept the file.
        let (_dir, path) = write_small_allele_file();
        let on_disk = std::fs::metadata(&path).unwrap().len();
        assert!(on_disk > 1, "fixture must be larger than one byte");
        let caps = ParquetCaps {
            max_parquet_file_bytes: on_disk - 1,
            ..ParquetCaps::default()
        };
        let err = read_matching_rows(
            &path,
            &caps,
            PosWindow {
                lo: 0,
                hi: i64::MAX,
            },
            &|_, _, _, _| true,
            &DatasetDecryptor::plaintext(),
        )
        .expect_err("a file larger than max_parquet_file_bytes must be rejected");
        std::assert_matches!(
            err,
            CoreError::InvalidParquet { .. },
            "expected InvalidParquet, got {err:?}"
        );
        assert!(
            format!("{err}").contains("exceeds max_parquet_file_bytes"),
            "expected the size-cap detail, got: {err}"
        );
    }

    #[cfg(feature = "pme")]
    mod pme {
        use super::*;
        use std::sync::Mutex;

        use arrow_array::{Float32Array, Int32Array, RecordBatch, StringArray};
        use parquet::arrow::arrow_writer::ArrowWriter;
        use parquet::errors::ParquetError;

        /// A deterministic in-test DEK minter + matching retriever, modelling Vault
        /// Transit `datakey`/`decrypt` without a server: `mint` returns a fixed
        /// 32-byte key wrapped as a token recording the key bytes; `retrieve_key`
        /// parses the token back to the same bytes.
        ///
        /// The `key_metadata` is `b"wrap:" || hex(key)` (the analogue of the real
        /// `{s,m,k,w}` blob — here only the wrapped DEK matters for the unwrap).
        struct MockKeys {
            key: [u8; PME_KEY_LEN],
        }

        impl MockKeys {
            fn new(seed: u8) -> Self {
                Self {
                    key: [seed; PME_KEY_LEN],
                }
            }
        }

        impl DekMinter for MockKeys {
            fn mint(&self) -> CoreResult<(Zeroizing<Vec<u8>>, Vec<u8>)> {
                let mut meta = b"wrap:".to_vec();
                for b in self.key {
                    meta.push(b);
                }
                Ok((Zeroizing::new(self.key.to_vec()), meta))
            }
        }

        impl KeyRetriever for MockKeys {
            fn retrieve_key(&self, key_metadata: &[u8]) -> Result<Vec<u8>, ParquetError> {
                let raw = key_metadata.strip_prefix(b"wrap:").ok_or_else(|| {
                    ParquetError::General("key_metadata missing wrap: prefix".to_owned())
                })?;
                Ok(raw.to_vec())
            }
        }

        /// A retriever that returns the WRONG key bytes (decrypt must then fail).
        struct WrongKey;
        impl KeyRetriever for WrongKey {
            fn retrieve_key(&self, _meta: &[u8]) -> Result<Vec<u8>, ParquetError> {
                Ok(vec![0xFF; PME_KEY_LEN])
            }
        }

        /// A retriever that counts its `retrieve_key` calls (proves the read path
        /// invokes it), delegating to an inner [`MockKeys`].
        struct Counting {
            inner: MockKeys,
            calls: Mutex<usize>,
        }
        impl KeyRetriever for Counting {
            fn retrieve_key(&self, meta: &[u8]) -> Result<Vec<u8>, ParquetError> {
                *self.calls.lock().unwrap() += 1;
                self.inner.retrieve_key(meta)
            }
        }

        /// Write a small canonical-schema plaintext parquet with three rows.
        fn write_plaintext(path: &Path) {
            write_plaintext_with_props(path, writer_properties().unwrap());
        }

        /// [`write_plaintext`] with caller-chosen writer properties, so a test can produce
        /// a file the node's own writer would never emit: specifically one with the
        /// `OffsetIndex` omitted, which is what distinguishes a `Pages`-mode reader from a
        /// `Values`-mode one.
        fn write_plaintext_with_props(
            path: &Path,
            props: parquet::file::properties::WriterProperties,
        ) {
            let schema = allele_freq_schema();
            let pos = Int32Array::from(vec![100, 200, 300]);
            let ref_ = StringArray::from(vec!["T", "A", "G"]);
            let alt = StringArray::from(vec!["C", "G", "T"]);
            let vt = StringArray::from(vec!["SNP", "SNP", "SNP"]);
            let population = StringArray::from(vec!["Total", "Total", "Total"]);
            let af = Float32Array::from(vec![0.1_f32, 0.2, 0.3]);
            let ac = Int32Array::from(vec![Some(1), Some(2), Some(3)]);
            let zero = Int32Array::from(vec![Some(0), Some(0), Some(0)]);
            let an = Int32Array::from(vec![Some(10), Some(10), Some(10)]);
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
                    Arc::new(zero.clone()),
                    Arc::new(zero.clone()),
                    Arc::new(zero),
                    Arc::new(an),
                ],
            )
            .unwrap();
            let file = std::fs::File::create(path).unwrap();
            let mut writer = ArrowWriter::try_new(file, schema, Some(props)).unwrap();
            writer.write(&batch).unwrap();
            writer.close().unwrap();
        }

        /// The first four bytes (file magic) of a parquet file.
        fn magic(path: &Path) -> [u8; 4] {
            let bytes = std::fs::read(path).unwrap();
            [bytes[0], bytes[1], bytes[2], bytes[3]]
        }

        #[test]
        fn encrypted_file_has_pare_magic_and_round_trips() {
            let tmp = tempfile::tempdir().unwrap();
            let plain = tmp.path().join("plain.parquet");
            let enc = tmp.path().join("enc.parquet");
            write_plaintext(&plain);
            assert_eq!(&magic(&plain), b"PAR1", "plaintext file must be PAR1");

            let keys = MockKeys::new(7);
            encrypt_parquet_file(&plain, &enc, &keys).unwrap();
            // Encrypted-footer PME files carry the PARE magic.
            assert_eq!(&magic(&enc), b"PARE", "encrypted file must be PARE");

            // Reading the PARE file with a matching retriever returns the same rows.
            let retriever: Arc<dyn KeyRetriever> = Arc::new(MockKeys::new(7));
            let decryptor = DatasetDecryptor::with_retriever(retriever);
            let rows = read_matching_rows(
                &enc,
                &ParquetCaps::default(),
                PosWindow { lo: 0, hi: 1000 },
                &|_, _, _, _| true,
                &decryptor,
            )
            .unwrap();
            assert_eq!(rows.len(), 3);
            assert_eq!(rows[0].pos, 100);
            assert_eq!(rows[0].ac, Some(1));
            assert_eq!(rows[2].pos, 300);
        }

        /// `PageIndexPolicy::Required` does not reject a parquet with a wholly absent page
        /// index. It rejects one whose declared index is unreadable.
        ///
        /// A characterization test of the pinned `parquet` crate, kept because the security
        /// argument on `encrypt_parquet_file_inner` depends on this boundary and the policy
        /// name suggests otherwise. `Required` is enforced on the per-column path that
        /// parses a declared offset-index range: a range that is missing or unparseable
        /// errors, while a file that declares no index at all never reaches that code.
        ///
        /// That is still safe, because what the re-encode needs is symmetry with the
        /// validating scan, not strictness: indexed files are read `Pages`/`Pages` and
        /// index-less files `Values`/`Values`, so the encode never sees a page validation
        /// did not. This test cannot detect a revert to `try_new`, since the two modes
        /// coincide on every file that is not forged; the `clippy.toml` ban on
        /// `ParquetRecordBatchReaderBuilder::try_new` is what binds that.
        #[test]
        fn page_index_required_accepts_a_wholly_absent_index() {
            let tmp = tempfile::tempdir().unwrap();
            let plain = tmp.path().join("no-page-index.parquet");
            let enc = tmp.path().join("enc.parquet");
            // Both settings are needed. `set_offset_index_disabled(true)` alone is
            // overridden when the statistics level is `Page`, which `base_writer_properties`
            // sets: parquet resolves that combination to `DisabledOverridden` and writes the
            // index anyway. Lowering the level to `Chunk` is what omits it, and the
            // precondition below is what proves the fixture really lacks one.
            let props = base_writer_properties()
                .unwrap()
                .set_statistics_enabled(EnabledStatistics::Chunk)
                .set_offset_index_disabled(true)
                .build();
            write_plaintext_with_props(&plain, props);
            // Precondition: the file really lacks the index (otherwise this proves nothing).
            let probe = ParquetRecordBatchReaderBuilder::try_new_with_options(
                std::fs::File::open(&plain).unwrap(),
                ArrowReaderOptions::new().with_page_index_policy(PageIndexPolicy::Optional),
            )
            .unwrap();
            assert!(
                probe.metadata().offset_index().is_none(),
                "the fixture must carry no OffsetIndex, or this test cannot detect the bypass"
            );

            // The documented boundary: `Required` opens this file rather than refusing it.
            // If a future `parquet` bump makes this an `Err`, the comment on
            // `encrypt_parquet_file_inner` needs revisiting.
            let keys = MockKeys::new(7);
            encrypt_parquet_file(&plain, &enc, &keys).expect(
                "PageIndexPolicy::Required accepts a wholly absent index (it rejects only a \
                 declared-but-unreadable one); if this now fails, the pinned parquet changed \
                 semantics and the re-encode reader's doc comment must be re-checked",
            );
            assert_eq!(
                &magic(&enc),
                b"PARE",
                "the re-encode must still produce PARE"
            );
        }

        #[test]
        fn encrypt_parquet_file_rejects_malformed_source() {
            // The re-encrypt path is fed untrusted producer data, so a malformed parquet
            // must fail with a clean `InvalidParquet` and never crash the process. That is
            // the property the decode panic boundary guards.
            let tmp = tempfile::tempdir().unwrap();
            let bad = tmp.path().join("bad.parquet");
            let enc = tmp.path().join("enc.parquet");
            std::fs::write(&bad, b"not a parquet file at all").unwrap();

            let err = encrypt_parquet_file(&bad, &enc, &MockKeys::new(1)).unwrap_err();
            std::assert_matches!(
                err,
                CoreError::InvalidParquet { .. },
                "malformed source must yield InvalidParquet, got: {err:?}"
            );
        }

        #[test]
        fn plaintext_file_reads_with_retriever_present() {
            // The mixed-store invariant: a PAR1 file reads correctly even when a retriever
            // is configured, because parquet self-describes its encryption.
            let tmp = tempfile::tempdir().unwrap();
            let plain = tmp.path().join("plain.parquet");
            write_plaintext(&plain);

            let retriever: Arc<dyn KeyRetriever> = Arc::new(MockKeys::new(9));
            let decryptor = DatasetDecryptor::with_retriever(retriever);
            let rows = read_matching_rows(
                &plain,
                &ParquetCaps::default(),
                PosWindow { lo: 0, hi: 1000 },
                &|_, _, _, _| true,
                &decryptor,
            )
            .unwrap();
            assert_eq!(rows.len(), 3);
        }

        #[test]
        fn row_group_pruning_works_on_encrypted_file() {
            // The footer is encrypted but decrypted on open, so POS row-group statistics
            // still prune: a window past every row returns nothing.
            let tmp = tempfile::tempdir().unwrap();
            let plain = tmp.path().join("plain.parquet");
            let enc = tmp.path().join("enc.parquet");
            write_plaintext(&plain);
            let keys = MockKeys::new(3);
            encrypt_parquet_file(&plain, &enc, &keys).unwrap();

            let retriever: Arc<dyn KeyRetriever> = Arc::new(MockKeys::new(3));
            let decryptor = DatasetDecryptor::with_retriever(retriever);
            let rows = read_matching_rows(
                &enc,
                &ParquetCaps::default(),
                PosWindow {
                    lo: 10_000,
                    hi: 20_000,
                },
                &|_, _, _, _| true,
                &decryptor,
            )
            .unwrap();
            assert!(
                rows.is_empty(),
                "out-of-window pruning should yield no rows"
            );
        }

        #[test]
        fn wrong_key_fails_to_decrypt() {
            let tmp = tempfile::tempdir().unwrap();
            let plain = tmp.path().join("plain.parquet");
            let enc = tmp.path().join("enc.parquet");
            write_plaintext(&plain);
            encrypt_parquet_file(&plain, &enc, &MockKeys::new(1)).unwrap();

            let retriever: Arc<dyn KeyRetriever> = Arc::new(WrongKey);
            let decryptor = DatasetDecryptor::with_retriever(retriever);
            let err = read_matching_rows(
                &enc,
                &ParquetCaps::default(),
                PosWindow { lo: 0, hi: 1000 },
                &|_, _, _, _| true,
                &decryptor,
            )
            .unwrap_err();
            assert_eq!(err.class(), crate::error::ErrorClass::InvalidParquetSchema);
        }

        /// The read path must invoke the retriever. The service-level cache lives above
        /// this; this only asserts the call happens.
        #[test]
        fn retriever_is_invoked_on_encrypted_read() {
            let tmp = tempfile::tempdir().unwrap();
            let plain = tmp.path().join("plain.parquet");
            let enc = tmp.path().join("enc.parquet");
            write_plaintext(&plain);
            encrypt_parquet_file(&plain, &enc, &MockKeys::new(5)).unwrap();

            let counting = Arc::new(Counting {
                inner: MockKeys::new(5),
                calls: Mutex::new(0),
            });
            let retriever: Arc<dyn KeyRetriever> = counting.clone();
            let decryptor = DatasetDecryptor::with_retriever(retriever);
            let rows = read_matching_rows(
                &enc,
                &ParquetCaps::default(),
                PosWindow { lo: 0, hi: 1000 },
                &|_, _, _, _| true,
                &decryptor,
            )
            .unwrap();
            assert_eq!(rows.len(), 3);
            assert!(
                *counting.calls.lock().unwrap() >= 1,
                "retriever was invoked"
            );
        }
    }
}

#[cfg(test)]
mod probe_tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use std::sync::Arc;

    use arrow_array::{Float32Array, Int32Array, RecordBatch, StringArray};
    use parquet::arrow::arrow_writer::ArrowWriter;

    use super::{DatasetDecryptor, allele_freq_schema, probe_dataset_readable, writer_properties};

    /// Write a minimal valid one-row canonical-schema parquet at `path`.
    fn write_valid(path: &std::path::Path) {
        let schema = allele_freq_schema();
        let z = Int32Array::from(vec![Some(0)]);
        let batch = RecordBatch::try_new(
            Arc::clone(&schema),
            vec![
                Arc::new(Int32Array::from(vec![100])),
                Arc::new(StringArray::from(vec!["T"])),
                Arc::new(StringArray::from(vec!["C"])),
                Arc::new(StringArray::from(vec!["SNP"])),
                Arc::new(StringArray::from(vec!["Total"])),
                Arc::new(Float32Array::from(vec![0.1_f32])),
                Arc::new(z.clone()),
                Arc::new(z.clone()),
                Arc::new(z.clone()),
                Arc::new(z.clone()),
                Arc::new(z),
            ],
        )
        .unwrap();
        let file = std::fs::File::create(path).unwrap();
        let mut writer =
            ArrowWriter::try_new(file, schema, Some(writer_properties().unwrap())).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
    }

    #[test]
    fn probe_dataset_readable_ok_empty_and_corrupt() {
        // An empty dataset dir (nothing ingested yet) is a no-op Ok.
        let empty = tempfile::tempdir().unwrap();
        probe_dataset_readable(empty.path(), &DatasetDecryptor::plaintext()).unwrap();

        // A readable plaintext data file probes Ok.
        let good = tempfile::tempdir().unwrap();
        write_valid(
            &good
                .path()
                .join("allele-freq.chr3.0.br10000000.0123456789abcdef.parquet"),
        );
        probe_dataset_readable(good.path(), &DatasetDecryptor::plaintext()).unwrap();

        // A corrupt or unreadable data file fails the probe. This is the startup self-test
        // catching an unreadable store; under PME a wrong key fails the footer decrypt here.
        let bad = tempfile::tempdir().unwrap();
        std::fs::write(
            bad.path()
                .join("allele-freq.chr3.0.br10000000.0123456789abcdef.parquet"),
            b"this is not a parquet file",
        )
        .unwrap();
        assert!(probe_dataset_readable(bad.path(), &DatasetDecryptor::plaintext()).is_err());
    }

    #[test]
    fn probe_dataset_readable_checks_every_file_not_just_the_first() {
        // A dataset holds one parquet per chromosome and block range, and every file's
        // footer must be probed, not just the first enumerated. Otherwise corruption,
        // truncation or a wrong per-file DEK on the later files passes the boot self-test
        // and the periodic sweep undetected.
        let dir = tempfile::tempdir().unwrap();
        // A good file that sorts first, plus a corrupt file that sorts later.
        write_valid(
            &dir.path()
                .join("allele-freq.chr1.0.br10000000.0000000000000000.parquet"),
        );
        std::fs::write(
            dir.path()
                .join("allele-freq.chr2.0.br10000000.0000000000000001.parquet"),
            b"this is not a parquet file",
        )
        .unwrap();
        assert!(
            probe_dataset_readable(dir.path(), &DatasetDecryptor::plaintext()).is_err(),
            "a corrupt non-first data file must fail the probe"
        );
    }

    #[test]
    fn probe_dataset_readable_maps_decoder_panic_to_error() {
        // The readiness self-test's panic boundary: a parquet whose embedded
        // `ARROW:schema` flatbuffer panics the arrow-ipc decoder must come back as a clean
        // `Err` rather than unwind out of the probe. An escaped panic here becomes a
        // `spawn_blocking` `JoinError` that latches `/health/ready` to 503 for the process
        // lifetime, so one crafted dataset would take the node offline.
        let dir = tempfile::tempdir().unwrap();
        let dest = dir
            .path()
            .join("allele-freq.chr1.0.br10000000.0123456789abcdef.parquet");
        std::fs::copy("tests/fixtures/malformed/arrow_schema_panic.parquet", &dest).unwrap();
        let err = probe_dataset_readable(dir.path(), &DatasetDecryptor::plaintext())
            .expect_err("a decoder panic must surface as an error, not a panic");
        assert!(
            format!("{err}").contains("panicked"),
            "expected the panic-boundary detail, got {err}"
        );
    }
}
