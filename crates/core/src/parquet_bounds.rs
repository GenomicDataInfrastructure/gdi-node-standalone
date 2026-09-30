//! Checks a parquet file's Thrift metadata before `parquet` decodes it.
//!
//! `parquet` reserves a list's declared length before reading any of it, and that length is a
//! varint in the file, so a few bytes of footer can ask for hundreds of gigabytes. A failed
//! allocation aborts the process. The page index, which ingest loads, is read the same way.
//!
//! [`open_arrow_reader`] runs [`check_metadata_bounds`] first; `clippy.toml` bans the
//! `parquet` calls that would skip it. The check walks the footer and each page-index blob and
//! refuses a file when:
//!
//! - a field is not in the schema below, or has a different Thrift type;
//! - a list declares more elements than bytes remain or than [`MAX_LIST_ELEMENTS`], or a
//!   value runs past its blob;
//! - a schema element other than the root declares children, or the root declares more
//!   than the schema holds;
//! - the footer is over [`MAX_FOOTER_BYTES`], or a page-index entry is empty, outside the
//!   data, or adds up to more than [`MAX_PAGE_INDEX_BYTES`].
//!
//! The types matter because `parquet` reads a known field by its schema type and ignores the
//! type on the wire, so bytes we would skip as an `i32` can be a list header to it. When every
//! wire type matches, both readers meet the same list headers. `parquet` reserves under 128
//! bytes per list element, so the element cap holds a list to 128 MiB. It builds the schema
//! tree recursively; our writer's schema is flat, so only the root may have children. Real
//! metadata is small: the gnomAD chr21 corpus slice has 2.2 KB of footer and 1.5 KB of page
//! index, and a 1 GiB file from our writer has a few thousand row groups.
//!
//! The schema is the part of `parquet-format` that `parquet` 59 reads here, minus the
//! encryption fields and geospatial statistics, which plaintext files from our writer never
//! carry. Encrypted footers (`PARE`) are not walked: `parquet` reads them only with the node's
//! key, so only the node's own store gets that far.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use parquet::arrow::arrow_reader::{ArrowReaderOptions, ParquetRecordBatchReaderBuilder};
use parquet::errors::ParquetError;

use crate::error::{CoreError, CoreResult, invalid_parquet};

/// The largest footer accepted, in bytes.
pub(crate) const MAX_FOOTER_BYTES: u64 = 16 * 1024 * 1024;

/// The largest page index accepted, in bytes, both as a span and as the sum of its blobs:
/// column chunks can share a blob, and `parquet` decodes it once per chunk.
pub(crate) const MAX_PAGE_INDEX_BYTES: u64 = 64 * 1024 * 1024;

/// The most elements a list may declare. `parquet` reserves them all before reading one.
pub(crate) const MAX_LIST_ELEMENTS: u64 = 1 << 20;

/// The file ends with the footer length (a little-endian `u32`) and the magic.
const TAIL_BYTES: u64 = 8;
const MAGIC_PLAINTEXT_FOOTER: &[u8] = b"PAR1";

/// Opens `file` for Arrow reads once [`check_metadata_bounds`] has passed it.
///
/// `map_parquet_error` converts an error from `parquet` itself, so each caller keeps its own
/// message and error class.
///
/// # Errors
///
/// [`CoreError::InvalidParquet`] naming `path` for out-of-bounds metadata, [`CoreError::Io`]
/// when the file cannot be read, and whatever `map_parquet_error` returns.
pub(crate) fn open_arrow_reader(
    file: File,
    path: &Path,
    options: ArrowReaderOptions,
    map_parquet_error: impl FnOnce(ParquetError) -> CoreError,
) -> CoreResult<ParquetRecordBatchReaderBuilder<File>> {
    check_metadata_bounds(&file).map_err(|error| match error {
        CoreError::InvalidParquet { detail } => {
            invalid_parquet(format!("{}: {detail}", path.display()))
        }
        other => other,
    })?;
    #[expect(
        clippy::disallowed_methods,
        reason = "the chokepoint: the metadata was checked above"
    )]
    let builder = ParquetRecordBatchReaderBuilder::try_new_with_options(file, options);
    builder.map_err(map_parquet_error)
}

/// Checks `file`'s footer and page index; returns how many page-index blobs it walked.
///
/// # Errors
///
/// [`CoreError::InvalidParquet`] naming the first bound broken, and [`CoreError::Io`] when the
/// file cannot be read.
pub(crate) fn check_metadata_bounds(file: &File) -> CoreResult<usize> {
    let file_len = file.metadata()?.len();
    if file_len < TAIL_BYTES {
        return Ok(0);
    }
    let mut tail = [0u8; 8];
    read_exact_at(file, file_len - TAIL_BYTES, &mut tail)?;
    let (length, magic) = tail.split_at(4);
    // `parquet` rejects a bad magic from the tail alone, and an encrypted footer without the
    // node's key.
    if magic != MAGIC_PLAINTEXT_FOOTER {
        return Ok(0);
    }
    let footer_len = u64::from(u32::from_le_bytes([
        length[0], length[1], length[2], length[3],
    ]));
    if footer_len > MAX_FOOTER_BYTES {
        return Err(refused(format!(
            "the footer is {footer_len} bytes, over the {MAX_FOOTER_BYTES}-byte cap"
        )));
    }
    // Room for the leading magic, the footer and the tail.
    let footer_start = file_len
        .checked_sub(TAIL_BYTES + footer_len)
        .filter(|&start| start >= 4)
        .ok_or_else(|| {
            refused(format!(
                "a {footer_len}-byte footer does not fit a {file_len}-byte file"
            ))
        })?;
    let mut footer = vec![0u8; to_usize(footer_len)?];
    read_exact_at(file, footer_start, &mut footer)?;
    let mut blobs = Vec::new();
    Thrift::new(&footer).walk_struct(&FILE_META_DATA, &mut blobs)?;
    check_page_index(file, &blobs, footer_start)
}

/// Checks and walks the page-index blobs the footer names; returns how many it walked.
fn check_page_index(file: &File, blobs: &[IndexBlob], footer_start: u64) -> CoreResult<usize> {
    let mut spans = Vec::with_capacity(blobs.len());
    let mut total: u64 = 0;
    for &IndexBlob {
        shape,
        offset,
        length,
    } in blobs
    {
        let outside = || {
            refused(format!(
                "the {} at offset {offset}, length {length}, is outside the data",
                shape.name
            ))
        };
        let (Ok(start), Ok(len)) = (u64::try_from(offset), u64::try_from(length)) else {
            return Err(outside());
        };
        // `parquet` reads from the lowest start to the highest end over every entry, empty
        // ones included, and no writer produces an empty one.
        if len == 0 {
            return Err(refused(format!(
                "the {} at offset {offset} is empty",
                shape.name
            )));
        }
        let end = start
            .checked_add(len)
            .filter(|&end| start >= 4 && end <= footer_start)
            .ok_or_else(outside)?;
        total = total.saturating_add(len);
        spans.push((shape, start, end));
    }
    let (Some(first), Some(last)) = (
        spans.iter().map(|&(_, start, _)| start).min(),
        spans.iter().map(|&(_, _, end)| end).max(),
    ) else {
        return Ok(0);
    };
    let size = total.max(last - first);
    if size > MAX_PAGE_INDEX_BYTES {
        return Err(refused(format!(
            "the page index is {size} bytes, over the {MAX_PAGE_INDEX_BYTES}-byte cap"
        )));
    }
    let mut index = vec![0u8; to_usize(last - first)?];
    read_exact_at(file, first, &mut index)?;
    for &(shape, start, end) in &spans {
        let blob = &index[to_usize(start - first)?..to_usize(end - first)?];
        Thrift::new(blob).walk_struct(shape, &mut Vec::new())?;
    }
    Ok(spans.len())
}

fn read_exact_at(mut file: &File, offset: u64, buf: &mut [u8]) -> CoreResult<()> {
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(buf)?;
    Ok(())
}

fn to_usize(n: u64) -> CoreResult<usize> {
    usize::try_from(n).map_err(|_| refused(format!("a length of {n} bytes exceeds usize")))
}

/// Every refusal starts with this, which tells it apart from an error of `parquet`'s own.
fn refused(detail: impl std::fmt::Display) -> CoreError {
    invalid_parquet(format!(
        "parquet metadata refused before decoding: {detail}"
    ))
}

fn truncated() -> CoreError {
    refused("it is truncated")
}

/// A Thrift struct: its name, and the fields it may carry with their types.
struct Shape {
    name: &'static str,
    fields: &'static [(i16, Ty)],
}

/// A field's type.
#[derive(Clone, Copy)]
enum Ty {
    Bool,
    I8,
    I16,
    I32,
    I64,
    /// A Thrift `binary` or `string`.
    Binary,
    Struct(&'static Shape),
    List(Elem),
}

/// A list element's type.
#[derive(Clone, Copy)]
enum Elem {
    Bool,
    I32,
    I64,
    Binary,
    Struct(&'static Shape),
}

// Compact-protocol type codes. A boolean field carries its value in the type code; a boolean
// list element is one byte.
const BOOL_TRUE: u8 = 1;
const BOOL_FALSE: u8 = 2;
const BYTE: u8 = 3;
const I16: u8 = 4;
const I32: u8 = 5;
const I64: u8 = 6;
const BINARY: u8 = 8;
const LIST: u8 = 9;
const STRUCT: u8 = 12;

impl Ty {
    fn accepts(self, code: u8) -> bool {
        match self {
            Ty::Bool => matches!(code, BOOL_TRUE | BOOL_FALSE),
            Ty::I8 => code == BYTE,
            Ty::I16 => code == I16,
            Ty::I32 => code == I32,
            Ty::I64 => code == I64,
            Ty::Binary => code == BINARY,
            Ty::Struct(_) => code == STRUCT,
            Ty::List(_) => code == LIST,
        }
    }
}

impl Elem {
    fn accepts(self, code: u8) -> bool {
        match self {
            Elem::Bool => matches!(code, BOOL_TRUE | BOOL_FALSE),
            Elem::I32 => code == I32,
            Elem::I64 => code == I64,
            Elem::Binary => code == BINARY,
            Elem::Struct(_) => code == STRUCT,
        }
    }
}

// `parquet-format`'s schema as `parquet` 59 reads it on this path. Enums are `i32`.

static FILE_META_DATA: Shape = Shape {
    name: "FileMetaData",
    fields: &[
        (1, Ty::I32),
        (2, Ty::List(Elem::Struct(&SCHEMA_ELEMENT))),
        (3, Ty::I64),
        (4, Ty::List(Elem::Struct(&ROW_GROUP))),
        (5, Ty::List(Elem::Struct(&KEY_VALUE))),
        (6, Ty::Binary),
        (7, Ty::List(Elem::Struct(&COLUMN_ORDER))),
    ],
};

static SCHEMA_ELEMENT: Shape = Shape {
    name: "SchemaElement",
    fields: &[
        (1, Ty::I32),
        (2, Ty::I32),
        (3, Ty::I32),
        (4, Ty::Binary),
        (5, Ty::I32),
        (6, Ty::I32),
        (7, Ty::I32),
        (8, Ty::I32),
        (9, Ty::I32),
        (10, Ty::Struct(&LOGICAL_TYPE)),
    ],
};

/// A union: one member field is set. Members without a payload are empty structs.
static LOGICAL_TYPE: Shape = Shape {
    name: "LogicalType",
    fields: &[
        (1, Ty::Struct(&EMPTY)),
        (2, Ty::Struct(&EMPTY)),
        (3, Ty::Struct(&EMPTY)),
        (4, Ty::Struct(&EMPTY)),
        (5, Ty::Struct(&DECIMAL_TYPE)),
        (6, Ty::Struct(&EMPTY)),
        (7, Ty::Struct(&TIMESTAMP_TYPE)),
        (8, Ty::Struct(&TIMESTAMP_TYPE)),
        (10, Ty::Struct(&INT_TYPE)),
        (11, Ty::Struct(&EMPTY)),
        (12, Ty::Struct(&EMPTY)),
        (13, Ty::Struct(&EMPTY)),
        (14, Ty::Struct(&EMPTY)),
        (15, Ty::Struct(&EMPTY)),
        (16, Ty::Struct(&VARIANT_TYPE)),
        (17, Ty::Struct(&GEOMETRY_TYPE)),
        (18, Ty::Struct(&GEOGRAPHY_TYPE)),
    ],
};

static EMPTY: Shape = Shape {
    name: "an empty struct",
    fields: &[],
};

static DECIMAL_TYPE: Shape = Shape {
    name: "DecimalType",
    fields: &[(1, Ty::I32), (2, Ty::I32)],
};

/// `TimeType` has the same shape, and `parquet` reads it as this struct.
static TIMESTAMP_TYPE: Shape = Shape {
    name: "TimestampType",
    fields: &[(1, Ty::Bool), (2, Ty::Struct(&TIME_UNIT))],
};

/// A union of three empty members.
static TIME_UNIT: Shape = Shape {
    name: "TimeUnit",
    fields: &[
        (1, Ty::Struct(&EMPTY)),
        (2, Ty::Struct(&EMPTY)),
        (3, Ty::Struct(&EMPTY)),
    ],
};

static INT_TYPE: Shape = Shape {
    name: "IntType",
    fields: &[(1, Ty::I8), (2, Ty::Bool)],
};

static VARIANT_TYPE: Shape = Shape {
    name: "VariantType",
    fields: &[(1, Ty::I8)],
};

static GEOMETRY_TYPE: Shape = Shape {
    name: "GeometryType",
    fields: &[(1, Ty::Binary)],
};

static GEOGRAPHY_TYPE: Shape = Shape {
    name: "GeographyType",
    fields: &[(1, Ty::Binary), (2, Ty::I32)],
};

static ROW_GROUP: Shape = Shape {
    name: "RowGroup",
    fields: &[
        (1, Ty::List(Elem::Struct(&COLUMN_CHUNK))),
        (2, Ty::I64),
        (3, Ty::I64),
        (4, Ty::List(Elem::Struct(&SORTING_COLUMN))),
        (5, Ty::I64),
        (6, Ty::I64),
        (7, Ty::I16),
    ],
};

static SORTING_COLUMN: Shape = Shape {
    name: "SortingColumn",
    fields: &[(1, Ty::I32), (2, Ty::Bool), (3, Ty::Bool)],
};

/// Fields 4 to 7 locate the chunk's offset index and column index.
static COLUMN_CHUNK: Shape = Shape {
    name: "ColumnChunk",
    fields: &[
        (1, Ty::Binary),
        (2, Ty::I64),
        (3, Ty::Struct(&COLUMN_META_DATA)),
        (4, Ty::I64),
        (5, Ty::I32),
        (6, Ty::I64),
        (7, Ty::I32),
    ],
};

static COLUMN_META_DATA: Shape = Shape {
    name: "ColumnMetaData",
    fields: &[
        (1, Ty::I32),
        (2, Ty::List(Elem::I32)),
        (3, Ty::List(Elem::Binary)),
        (4, Ty::I32),
        (5, Ty::I64),
        (6, Ty::I64),
        (7, Ty::I64),
        (8, Ty::List(Elem::Struct(&KEY_VALUE))),
        (9, Ty::I64),
        (10, Ty::I64),
        (11, Ty::I64),
        (12, Ty::Struct(&STATISTICS)),
        (13, Ty::List(Elem::Struct(&PAGE_ENCODING_STATS))),
        (14, Ty::I64),
        (15, Ty::I32),
        (16, Ty::Struct(&SIZE_STATISTICS)),
    ],
};

static STATISTICS: Shape = Shape {
    name: "Statistics",
    fields: &[
        (1, Ty::Binary),
        (2, Ty::Binary),
        (3, Ty::I64),
        (4, Ty::I64),
        (5, Ty::Binary),
        (6, Ty::Binary),
        (7, Ty::Bool),
        (8, Ty::Bool),
    ],
};

static PAGE_ENCODING_STATS: Shape = Shape {
    name: "PageEncodingStats",
    fields: &[(1, Ty::I32), (2, Ty::I32), (3, Ty::I32)],
};

static SIZE_STATISTICS: Shape = Shape {
    name: "SizeStatistics",
    fields: &[
        (1, Ty::I64),
        (2, Ty::List(Elem::I64)),
        (3, Ty::List(Elem::I64)),
    ],
};

static KEY_VALUE: Shape = Shape {
    name: "KeyValue",
    fields: &[(1, Ty::Binary), (2, Ty::Binary)],
};

/// A union whose one member, `TYPE_ORDER`, is an empty struct.
static COLUMN_ORDER: Shape = Shape {
    name: "ColumnOrder",
    fields: &[(1, Ty::Struct(&EMPTY))],
};

static OFFSET_INDEX: Shape = Shape {
    name: "OffsetIndex",
    fields: &[
        (1, Ty::List(Elem::Struct(&PAGE_LOCATION))),
        (2, Ty::List(Elem::I64)),
    ],
};

static PAGE_LOCATION: Shape = Shape {
    name: "PageLocation",
    fields: &[(1, Ty::I64), (2, Ty::I32), (3, Ty::I64)],
};

static COLUMN_INDEX: Shape = Shape {
    name: "ColumnIndex",
    fields: &[
        (1, Ty::List(Elem::Bool)),
        (2, Ty::List(Elem::Binary)),
        (3, Ty::List(Elem::Binary)),
        (4, Ty::I32),
        (5, Ty::List(Elem::I64)),
        (6, Ty::List(Elem::I64)),
        (7, Ty::List(Elem::I64)),
    ],
};

/// A page-index blob a `ColumnChunk` names, as the file declares it.
#[derive(Clone, Copy)]
struct IndexBlob {
    shape: &'static Shape,
    offset: i64,
    length: i64,
}

/// A bounded reader over one Thrift compact-protocol blob.
struct Thrift<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Thrift<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn remaining(&self) -> u64 {
        u64::try_from(self.bytes.len() - self.pos).unwrap_or(u64::MAX)
    }

    fn byte(&mut self) -> CoreResult<u8> {
        let byte = *self.bytes.get(self.pos).ok_or_else(truncated)?;
        self.pos += 1;
        Ok(byte)
    }

    fn skip(&mut self, n: u64) -> CoreResult<()> {
        if n > self.remaining() {
            return Err(truncated());
        }
        self.pos += to_usize(n)?;
        Ok(())
    }

    fn varint(&mut self) -> CoreResult<u64> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = self.byte()?;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(refused("a varint is longer than ten bytes"))
    }

    fn zigzag(&mut self) -> CoreResult<i64> {
        let n = self.varint()?;
        let magnitude = i64::try_from(n >> 1).map_err(|_| truncated())?;
        Ok(if n & 1 == 0 { magnitude } else { !magnitude })
    }

    fn skip_binary(&mut self) -> CoreResult<()> {
        let len = self.varint()?;
        self.skip(len)
    }

    /// Walks one `shape` struct. A `ColumnChunk` adds the page-index blobs it names to `blobs`,
    /// and a `SchemaElement` returns its `num_children`.
    fn walk_struct(
        &mut self,
        shape: &'static Shape,
        blobs: &mut Vec<IndexBlob>,
    ) -> CoreResult<Option<i64>> {
        let mut last_id: i64 = 0;
        let mut index = [None; 4];
        let mut children = None;
        loop {
            let header = self.byte()?;
            if header == 0 {
                break;
            }
            let code = header & 0x0f;
            let id = match header >> 4 {
                0 => self.zigzag()?,
                delta => last_id.saturating_add(i64::from(delta)),
            };
            last_id = id;
            let Some(&(_, ty)) = shape
                .fields
                .iter()
                .find(|&&(field, _)| i64::from(field) == id)
            else {
                return Err(refused(format!("{} has unexpected field {id}", shape.name)));
            };
            if !ty.accepts(code) {
                return Err(refused(format!(
                    "{} field {id} has the wrong Thrift type ({code})",
                    shape.name
                )));
            }
            let value = self.walk_field(ty, blobs)?;
            if std::ptr::eq(shape, &raw const COLUMN_CHUNK) && (4..=7).contains(&id) {
                index[usize::try_from(id - 4).map_err(|_| truncated())?] = value;
            } else if std::ptr::eq(shape, &raw const SCHEMA_ELEMENT) && id == 5 {
                children = value;
            }
        }
        for (index_shape, offset, length) in [
            (&OFFSET_INDEX, index[0], index[1]),
            (&COLUMN_INDEX, index[2], index[3]),
        ] {
            if let (Some(offset), Some(length)) = (offset, length) {
                blobs.push(IndexBlob {
                    shape: index_shape,
                    offset,
                    length,
                });
            }
        }
        Ok(children)
    }

    /// Walks one field's value, and returns it if it is an integer.
    fn walk_field(&mut self, ty: Ty, blobs: &mut Vec<IndexBlob>) -> CoreResult<Option<i64>> {
        match ty {
            // The value is in the type code.
            Ty::Bool => {}
            Ty::I8 => self.skip(1)?,
            Ty::I16 | Ty::I32 | Ty::I64 => return self.zigzag().map(Some),
            Ty::Binary => self.skip_binary()?,
            Ty::Struct(shape) => {
                self.walk_struct(shape, blobs)?;
            }
            Ty::List(elem) => self.walk_list(elem, blobs)?,
        }
        Ok(None)
    }

    fn walk_list(&mut self, elem: Elem, blobs: &mut Vec<IndexBlob>) -> CoreResult<()> {
        let header = self.byte()?;
        let code = header & 0x0f;
        if !elem.accepts(code) {
            return Err(refused(format!(
                "a list has the wrong element type ({code})"
            )));
        }
        let count = match header >> 4 {
            15 => self.varint()?,
            short => u64::from(short),
        };
        // Every element type in the schema takes at least a byte.
        let remaining = self.remaining();
        if count > remaining {
            return Err(refused(format!(
                "a list declares {count} elements but only {remaining} bytes remain"
            )));
        }
        if count > MAX_LIST_ELEMENTS {
            return Err(refused(format!(
                "a list declares {count} elements, over the {MAX_LIST_ELEMENTS}-element cap"
            )));
        }
        for i in 0..count {
            match elem {
                Elem::Bool => self.skip(1)?,
                Elem::I32 | Elem::I64 => {
                    self.varint()?;
                }
                Elem::Binary => self.skip_binary()?,
                Elem::Struct(shape) => {
                    // Only a schema element has a child count; see the module doc.
                    if let Some(children) = self.walk_struct(shape, blobs)? {
                        let most = if i == 0 { count - 1 } else { 0 };
                        if !u64::try_from(children).is_ok_and(|c| c <= most) {
                            return Err(refused(format!(
                                "schema element {i} declares {children} children"
                            )));
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use std::io::Write;
    use std::sync::Arc;

    use arrow_array::{Int32Array, RecordBatch};
    use arrow_schema::{DataType, Field, Schema};
    use parquet::arrow::ArrowWriter;
    use parquet::file::properties::{EnabledStatistics, WriterProperties};

    use super::*;

    /// The leading magic, `body`, `footer`, then the tail.
    fn parquet_file(body: &[u8], footer: &[u8]) -> File {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(MAGIC_PLAINTEXT_FOOTER).unwrap();
        file.write_all(body).unwrap();
        file.write_all(footer).unwrap();
        let footer_len = u32::try_from(footer.len()).unwrap();
        file.write_all(&footer_len.to_le_bytes()).unwrap();
        file.write_all(MAGIC_PLAINTEXT_FOOTER).unwrap();
        file
    }

    fn varint(mut n: u64) -> Vec<u8> {
        let mut out = Vec::new();
        while n >= 0x80 {
            out.push(u8::try_from(n & 0x7f).unwrap() | 0x80);
            n >>= 7;
        }
        out.push(u8::try_from(n).unwrap());
        out
    }

    fn zigzag(n: i64) -> Vec<u8> {
        varint(u64::from_ne_bytes(((n << 1) ^ (n >> 63)).to_ne_bytes()))
    }

    /// A field header for field `id` (1 to 15) of type `code`, at the start of a struct.
    fn field(id: u8, code: u8) -> u8 {
        (id << 4) | code
    }

    fn list_header(code: u8, count: u64) -> Vec<u8> {
        match u8::try_from(count) {
            Ok(short) if short < 15 => vec![(short << 4) | code],
            _ => [vec![0xf0 | code], varint(count)].concat(),
        }
    }

    const I32_MAX: u64 = 2_147_483_647;

    /// A footer with one row group whose column chunks name offset indexes at `ranges`.
    fn footer_naming_offset_indexes(ranges: &[(i64, i64)]) -> Vec<u8> {
        let mut footer = vec![field(4, LIST)];
        footer.extend(list_header(STRUCT, 1));
        footer.push(field(1, LIST));
        footer.extend(list_header(STRUCT, u64::try_from(ranges.len()).unwrap()));
        for &(offset, length) in ranges {
            footer.push(field(4, I64));
            footer.extend(zigzag(offset));
            footer.push(field(1, I32));
            footer.extend(zigzag(length));
            footer.push(0);
        }
        footer.extend([0, 0]);
        footer
    }

    fn refusal(file: &File) -> String {
        let msg = check_metadata_bounds(file)
            .expect_err("the metadata must be refused")
            .to_string();
        assert!(msg.contains("refused before decoding"), "{msg}");
        msg
    }

    #[test]
    fn a_list_longer_than_its_bytes_is_refused() {
        // Field 4 is `row_groups`, field 5 `key_value_metadata`, the list the fuzz run's
        // input inflates.
        for id in [4, 5] {
            let footer = [vec![field(id, LIST)], list_header(STRUCT, I32_MAX), vec![0]].concat();
            let msg = refusal(&parquet_file(&[], &footer));
            assert!(msg.contains("declares 2147483647 elements"), "{msg}");
        }
    }

    #[test]
    fn a_field_that_differs_from_the_schema_is_refused() {
        // `parquet` reads field 5 as a list whatever its wire type, so to it these bytes are
        // `i32::MAX` key-value pairs. A 37-byte file built this way aborts `parquet` 59.
        let mistyped = [
            vec![field(5, I32)],
            vec![0xfc, 0xff, 0xff, 0xff, 0xff, 0x07],
            vec![0],
        ]
        .concat();
        let msg = refusal(&parquet_file(&[], &mistyped));
        assert!(
            msg.contains("FileMetaData field 5 has the wrong Thrift type"),
            "{msg}"
        );

        // Field 8, `encryption_algorithm`, is outside the schema.
        let unknown = [field(8, STRUCT), 0, 0];
        let msg = refusal(&parquet_file(&[], &unknown));
        assert!(msg.contains("FileMetaData has unexpected field 8"), "{msg}");
    }

    #[test]
    fn a_list_whose_elements_are_not_all_there_is_refused() {
        // Two schema elements fit the two bytes left, but the first never ends.
        let footer = [
            vec![field(2, LIST)],
            list_header(STRUCT, 2),
            vec![field(1, I32), 2],
        ]
        .concat();
        let msg = refusal(&parquet_file(&[], &footer));
        assert!(msg.contains("it is truncated"), "{msg}");
    }

    #[test]
    fn a_footer_over_the_cap_is_refused_before_it_is_read() {
        let mut file = tempfile::tempfile().unwrap();
        file.set_len(MAX_FOOTER_BYTES + 64).unwrap();
        file.seek(SeekFrom::End(-8)).unwrap();
        let declared = u32::try_from(MAX_FOOTER_BYTES + 1).unwrap();
        file.write_all(&declared.to_le_bytes()).unwrap();
        file.write_all(MAGIC_PLAINTEXT_FOOTER).unwrap();
        let msg = refusal(&file);
        assert!(msg.contains("over the 16777216-byte cap"), "{msg}");
    }

    #[test]
    fn a_page_index_outside_the_data_is_refused() {
        for range in [(1_000_000, 10), (4, -1), (2, 10)] {
            let file = parquet_file(&[0; 16], &footer_naming_offset_indexes(&[range]));
            let msg = refusal(&file);
            assert!(msg.contains("is outside the data"), "{range:?}: {msg}");
        }
    }

    #[test]
    fn an_empty_page_index_entry_is_refused() {
        // `parquet` still reads from its offset, which can stretch the span past the cap.
        let file = parquet_file(&[0; 16], &footer_naming_offset_indexes(&[(4, 0)]));
        let msg = refusal(&file);
        assert!(msg.contains("OffsetIndex at offset 4 is empty"), "{msg}");
    }

    #[test]
    fn a_list_over_the_element_cap_is_refused() {
        let count = MAX_LIST_ELEMENTS + 1;
        let empty_structs = vec![0; usize::try_from(count).unwrap() + 1];
        let footer = [
            vec![field(5, LIST)],
            list_header(STRUCT, count),
            empty_structs,
        ]
        .concat();
        let msg = refusal(&parquet_file(&[], &footer));
        assert!(msg.contains("-element cap"), "{msg}");
    }

    #[test]
    fn only_the_schema_root_may_have_children() {
        let schema = |children: &[i64]| {
            let mut footer = vec![field(2, LIST)];
            footer.extend(list_header(STRUCT, u64::try_from(children.len()).unwrap()));
            for &n in children {
                footer.push(field(5, I32));
                footer.extend(zigzag(n));
                footer.push(0);
            }
            footer.push(0);
            footer
        };
        assert!(check_metadata_bounds(&parquet_file(&[], &schema(&[1, 0]))).is_ok());
        for (children, expected) in [
            (&[2, 0][..], "schema element 0 declares 2 children"),
            (&[1, 1][..], "schema element 1 declares 1 children"),
        ] {
            let msg = refusal(&parquet_file(&[], &schema(children)));
            assert!(msg.contains(expected), "{msg}");
        }
    }

    #[test]
    fn malformed_thrift_is_refused() {
        let overlong_varint = [vec![field(1, I32)], vec![0x80; 10], vec![0]].concat();
        let wrong_element = [vec![field(2, LIST)], list_header(I32, 1), vec![0, 0]].concat();
        for (footer, expected) in [
            (overlong_varint, "longer than ten bytes"),
            (wrong_element, "wrong element type"),
        ] {
            let msg = refusal(&parquet_file(&[], &footer));
            assert!(msg.contains(expected), "{msg}");
        }
    }

    #[test]
    fn a_page_index_list_longer_than_its_bytes_is_refused() {
        let blob = [vec![field(1, LIST)], list_header(STRUCT, I32_MAX), vec![0]].concat();
        let length = i64::try_from(blob.len()).unwrap();
        let file = parquet_file(&blob, &footer_naming_offset_indexes(&[(4, length)]));
        let msg = refusal(&file);
        assert!(msg.contains("declares 2147483647 elements"), "{msg}");
    }

    #[test]
    fn a_page_index_over_the_cap_is_refused() {
        // 65 column chunks share one 1 MiB blob: the span is small, the total is not.
        let mib = 1024 * 1024;
        let chunks = vec![(4, mib); 65];
        let file = parquet_file(&vec![0; 1 << 20], &footer_naming_offset_indexes(&chunks));
        let msg = refusal(&file);
        assert!(msg.contains("is 68157440 bytes"), "{msg}");
    }

    #[test]
    fn a_written_file_passes_and_its_page_index_is_walked() {
        let schema = Arc::new(Schema::new(vec![Field::new("POS", DataType::Int32, false)]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![Arc::new(Int32Array::from_iter_values(0..10_000))],
        )
        .unwrap();
        let props = WriterProperties::builder()
            .set_statistics_enabled(EnabledStatistics::Page)
            .build();
        let file = tempfile::tempfile().unwrap();
        let mut writer =
            ArrowWriter::try_new(file.try_clone().unwrap(), schema, Some(props)).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();

        // The one column chunk's offset index and column index.
        assert_eq!(check_metadata_bounds(&file).unwrap(), 2);
        let rows: usize = open_arrow_reader(
            file,
            Path::new("written.parquet"),
            ArrowReaderOptions::new(),
            |e| invalid_parquet(e.to_string()),
        )
        .unwrap()
        .build()
        .unwrap()
        .map(|batch| batch.unwrap().num_rows())
        .sum();
        assert_eq!(rows, 10_000);
    }
}
