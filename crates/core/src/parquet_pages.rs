//! Pre-decode page-size validation: the half of the decompression-bomb defence that looks
//! at the number the decoder allocates from.
//!
//! The row-group caps in [`crate::validate_parquet`] bound
//! `RowGroupMetaData::total_byte_size()`, a thrift field the producer writes. The bytes
//! actually allocated come from each page header's own `uncompressed_page_size`, which
//! `parquet`'s `decode_page` feeds into `Vec::with_capacity` after checking only that it is
//! non-negative. The two numbers are independent, so a tiny row group can hold a page
//! claiming gigabytes.
//!
//! In well-formed Parquet a row group's `total_byte_size` is the sum of its pages'
//! uncompressed sizes, so no page may exceed it. That is the rule enforced here, and
//! because the row-group total is already capped it transitively bounds every allocation
//! the decoder makes.
//!
//! Two probe origins route through the same per-offset check. Data-page offsets come from
//! the `OffsetIndex`. The column chunk's own start is probed unconditionally: it is where
//! the decoder begins reading page headers, it is the dictionary page's offset when one is
//! declared, and otherwise it is `data_page_offset`, at which `SerializedPageReader`
//! synthesises a dictionary page whenever the first index location does not coincide with
//! it. Taking the origin from the chunk rather than from the producer-written index stops a
//! crafted file moving a header out from under the probe set.
//!
//! Only the leading fixed-width fields of a header are parsed. Nothing walks nested thrift
//! structures, and every read is bounds-checked against a short slice.

use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::Path;

use parquet::file::metadata::ParquetMetaData;

use crate::error::{CoreResult, invalid_parquet};

/// How many bytes of each page header to examine.
///
/// `PageHeader`'s first three fields (`type`, `uncompressed_page_size`,
/// `compressed_page_size`) are fixed-width thrift-compact integers written in ascending
/// field order, so they live in the first handful of bytes. This is generous slack over
/// that, and bounds every read below.
const HEADER_PROBE_BYTES: usize = 64;

/// A decoded LEB128 varint and the number of bytes it occupied.
fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    for (i, &byte) in buf.iter().enumerate() {
        if shift >= 64 {
            return None; // overlong: refuse rather than wrap
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
        shift += 7;
    }
    None // ran off the end of the probe
}

/// Thrift zigzag decoding.
fn zigzag(n: u64) -> i64 {
    #[expect(
        clippy::cast_possible_wrap,
        reason = "zigzag decoding is defined on the two's-complement bit pattern"
    )]
    let signed = (n >> 1) as i64;
    #[expect(
        clippy::cast_possible_wrap,
        reason = "zigzag decoding is defined on the two's-complement bit pattern"
    )]
    let sign = -((n & 1) as i64);
    signed ^ sign
}

/// The declared uncompressed size of the page whose header starts at `buf[0]`.
///
/// Returns `None` when the header is not the plain ascending-i32 shape a `PageHeader`
/// begins with. The caller treats that as a rejection, not as "unknown": a header whose
/// size cannot be read is a decode that cannot be bounded.
///
/// Thrift compact: each field is a header byte of `(id_delta << 4) | type`, with `type == 5`
/// for i32 and a zigzag varint payload; `id_delta == 0` means an explicit zigzag field id
/// follows. Field 2 is `uncompressed_page_size`.
fn declared_uncompressed_size(buf: &[u8]) -> Option<i32> {
    let mut pos = 0usize;
    let mut last_id: i16 = 0;
    while pos < buf.len() {
        let field_header = buf[pos];
        pos += 1;
        if field_header == 0 {
            return None; // stop field before field 2: not a shape we can bound
        }
        let field_type = field_header & 0x0f;
        let delta = i16::from(field_header >> 4);
        let id = if delta == 0 {
            let (raw, used) = read_varint(buf.get(pos..)?)?;
            pos += used;
            i16::try_from(zigzag(raw)).ok()?
        } else {
            last_id.checked_add(delta)?
        };
        last_id = id;

        // Only the leading fixed-width integers are understood. A nested struct, list or
        // binary means the walk has passed the size fields without finding field 2, so stop
        // and let the caller reject.
        if field_type != 5 {
            return None;
        }
        let (raw, used) = read_varint(buf.get(pos..)?)?;
        pos += used;
        let value = i32::try_from(zigzag(raw)).ok()?;
        if id == 2 {
            return Some(value);
        }
    }
    None
}

/// Reject any page that declares an uncompressed size larger than its row group's own
/// declared (and already capped) `total_byte_size`.
///
/// # Errors
///
/// [`CoreError::InvalidParquet`](crate::error::CoreError::InvalidParquet) when a page's
/// declared expansion exceeds its row group's, when a page header cannot be read as a
/// bounded size, or when the file carries no `OffsetIndex`. Absence fails closed: without
/// page offsets there is nothing to bound the decode with.
pub fn enforce_page_size_caps(path: &Path, meta: &ParquetMetaData) -> CoreResult<()> {
    let Some(offset_index) = meta.offset_index() else {
        return Err(invalid_parquet(
            "parquet has no page (offset) index, so its page sizes cannot be bounded \
                     before decoding; rebuild it with gdi-dataset-tool"
                .to_owned(),
        ));
    };

    let mut file = std::fs::File::open(path)?;
    let mut probe = [0u8; HEADER_PROBE_BYTES];

    for (rg, columns) in offset_index.iter().enumerate() {
        let row_group = meta.row_group(rg);
        // The row-group total is what the existing caps already bound, so it is the ceiling
        // that makes this check transitively bounding.
        let group_limit = row_group.total_byte_size().max(0);
        for (col, pages) in columns.iter().enumerate() {
            // Probe the column chunk's own start unconditionally: it is the one offset the
            // decoder always reads a page header from, and the only probe origin the
            // producer's `OffsetIndex` cannot move. With no dictionary offset declared the
            // chunk starts at `data_page_offset`, which the index need not list, and
            // `SerializedPageReader` synthesises a dictionary page there whenever the first
            // index location does not coincide with it.
            check_page_at_offset(
                &mut file,
                &mut probe,
                chunk_start(row_group.column(col)),
                group_limit,
                rg,
                "chunk-start",
            )?;
            for page in pages.page_locations() {
                check_page_at_offset(&mut file, &mut probe, page.offset, group_limit, rg, "data")?;
            }
            // The listed pages must account for the chunk's bytes. Every probe above comes
            // from the producer's `OffsetIndex`, so a page that is physically present but
            // unlisted is never bounded, while the sequential reader walks the chunk's byte
            // range and still allocates from its header. Rather than re-implement a thrift
            // page-header walk over hostile input, require the index to describe the whole
            // chunk: `PageLocation.compressed_page_size` includes the header, so listed
            // pages tile exactly and any unclaimed byte is one the decoder may read
            // unbounded.
            //
            // The run is anchored at both ends. The first listed page must start at
            // `data_page_offset`, so no unlisted page can sit ahead of it. The remaining
            // region, `[chunk_start, data_page_offset)`, is the dictionary page when one is
            // declared, and the chunk-start probe bounds it.
            let chunk = row_group.column(col);
            let chunk_end = chunk_start(chunk).saturating_add(chunk.compressed_size());
            if let Some(first) = pages.page_locations().first()
                && first.offset != chunk.data_page_offset()
            {
                return Err(invalid_parquet(format!(
                    "row group {rg} column {col} has an OffsetIndex whose first page starts at \
                     {} while the chunk declares its data pages begin at {}; the bytes between \
                     are reachable by the decoder and bounded by nothing",
                    first.offset,
                    chunk.data_page_offset()
                )));
            }
            let mut expected_next: Option<i64> = None;
            for page in pages.page_locations() {
                if let Some(prev_end) = expected_next
                    && page.offset != prev_end
                {
                    return Err(invalid_parquet(format!(
                        "row group {rg} column {col} has an OffsetIndex that does not describe \
                         a contiguous run of pages (a page starts at {}, the previous ended at \
                         {prev_end}); the unaccounted bytes are reachable by the decoder and \
                         bounded by nothing",
                        page.offset
                    )));
                }
                expected_next = Some(
                    page.offset
                        .saturating_add(i64::from(page.compressed_page_size)),
                );
            }
            if let Some(last_end) = expected_next
                && last_end != chunk_end
            {
                return Err(invalid_parquet(format!(
                    "row group {rg} column {col} has an OffsetIndex whose pages end at \
                     {last_end} while the column chunk ends at {chunk_end}; the unaccounted \
                     bytes are reachable by the decoder and bounded by nothing"
                )));
            }
        }
    }
    Ok(())
}

/// The byte offset a column chunk's decoder starts reading page headers at.
///
/// Mirrors `ColumnChunkMetaData::byte_range().0` rather than calling it: that method
/// asserts `col_start >= 0` and so panics on hostile metadata, and this code runs on
/// provider-supplied files. Computing it here routes a negative offset through
/// [`check_page_at_offset`]'s guard, which turns it into a clean `InvalidParquet`.
pub(crate) fn chunk_start(col: &parquet::file::metadata::ColumnChunkMetaData) -> i64 {
    col.dictionary_page_offset()
        .unwrap_or_else(|| col.data_page_offset())
}

/// Bound one page (data or dictionary) at `offset`: read its header, decode its declared
/// uncompressed size, and reject if it exceeds `group_limit`. Every offset routes through
/// this one check, so a page kind cannot be added that skips the bound.
///
/// # Errors
///
/// [`CoreError::InvalidParquet`](crate::error::CoreError::InvalidParquet) on a negative
/// offset, an unreadable header, or a declared expansion beyond the row group's own
/// (already capped) total.
fn check_page_at_offset(
    file: &mut std::fs::File,
    probe: &mut [u8; HEADER_PROBE_BYTES],
    offset: i64,
    group_limit: i64,
    rg: usize,
    kind: &str,
) -> CoreResult<()> {
    let Ok(offset) = u64::try_from(offset) else {
        return Err(invalid_parquet(format!(
            "row group {rg} has a {kind} page at a negative offset"
        )));
    };
    file.seek(SeekFrom::Start(offset))?;
    // A short read at the tail of the file is fine: the size fields are at the front of the
    // header, so a partial probe either resolves them or is rejected below.
    let read = read_up_to(file, probe)?;
    let Some(declared) = declared_uncompressed_size(&probe[..read]) else {
        return Err(invalid_parquet(format!(
            "row group {rg} has a {kind} page header whose declared sizes could not be \
                 read, so its decode cannot be bounded"
        )));
    };
    if i64::from(declared) > group_limit {
        return Err(invalid_parquet(format!(
            "row group {rg} has a {kind} page declaring {declared} uncompressed bytes, \
                 more than the row group's own declared total of {group_limit}; a page cannot \
                 expand beyond its row group, so this is a decompression bomb or a corrupt header"
        )));
    }
    Ok(())
}

/// Fill as much of `buf` as the file has left, returning how many bytes were read.
fn read_up_to(file: &mut std::fs::File, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0usize;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode an unsigned LEB128 varint (test-side mirror of the reader).
    fn varint(mut v: u64, out: &mut Vec<u8>) {
        loop {
            let byte = u8::try_from(v & 0x7f).expect("7 bits");
            v >>= 7;
            if v == 0 {
                out.push(byte);
                return;
            }
            out.push(byte | 0x80);
        }
    }

    /// Encode a thrift-compact i32 field (`id`, ascending from `prev_id`).
    fn i32_field(prev_id: i16, id: i16, value: i32, out: &mut Vec<u8>) {
        let delta = id - prev_id;
        assert!((1..=15).contains(&delta), "test helper writes short deltas");
        out.push((u8::try_from(delta).expect("delta fits") << 4) | 0x05);
        let zz = (u64::from(value.unsigned_abs()) << 1) ^ u64::from(value < 0);
        varint(zz, out);
    }

    /// A `PageHeader` prefix: type=field1, uncompressed=field2, compressed=field3.
    fn header(page_type: i32, uncompressed: i32, compressed: i32) -> Vec<u8> {
        let mut out = Vec::new();
        i32_field(0, 1, page_type, &mut out);
        i32_field(1, 2, uncompressed, &mut out);
        i32_field(2, 3, compressed, &mut out);
        out
    }

    #[test]
    fn reads_the_declared_uncompressed_size() {
        assert_eq!(
            declared_uncompressed_size(&header(0, 4096, 200)),
            Some(4096)
        );
        // The bomb: a tiny compressed page claiming an enormous expansion.
        assert_eq!(
            declared_uncompressed_size(&header(0, i32::MAX, 40)),
            Some(i32::MAX)
        );
    }

    #[test]
    fn a_truncated_header_is_not_readable() {
        // Refusing beats guessing: a size we cannot read is a decode we cannot bound.
        let full = header(0, 4096, 200);
        assert_eq!(declared_uncompressed_size(&full[..1]), None);
        assert_eq!(declared_uncompressed_size(&[]), None);
    }

    #[test]
    fn a_non_integer_field_before_the_size_is_rejected() {
        // A struct (type 12) where an i32 belongs means these are not the leading size
        // fields, so there is nothing to bound.
        let buf = vec![0x1c_u8, 0x00]; // field 1, type 12 (struct), then stop
        assert_eq!(declared_uncompressed_size(&buf), None);
    }

    #[test]
    fn a_stop_field_before_the_size_is_rejected() {
        assert_eq!(declared_uncompressed_size(&[0x00]), None);
    }

    #[test]
    fn an_explicit_field_id_is_honoured() {
        // `id_delta == 0` means the id follows as a zigzag varint; field 2 must still be
        // found that way.
        let mut buf = Vec::new();
        buf.push(0x05); // id_delta 0, type i32 -> the field id follows explicitly
        varint(2u64 << 1, &mut buf); // zigzag-encoded field id 2
        varint(1234u64 << 1, &mut buf); // zigzag-encoded value 1234
        assert_eq!(declared_uncompressed_size(&buf), Some(1234));
    }

    #[test]
    fn varint_refuses_an_overlong_encoding() {
        // Ten continuation bytes would overflow a u64; refuse rather than wrap.
        let overlong = [0x80u8; 12];
        assert_eq!(read_varint(&overlong), None);
    }
}
