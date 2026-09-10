//! Derive a dataset's creation `xsd:dateTime` from its `datasetId` timestamp tail.
//!
//! An id minted by this node ends in a 17-digit `YYYYMMDDHHMMSSmmm` UTC timestamp (see
//! [`crate::id`]); both `dct:issued`/`dct:modified` (FDP) and the Beacon collection
//! `createDateTime` are that creation time. A foreign ID (e.g. `GDI-FI-THL-1`)
//! carries no parseable timestamp; the caller supplies a fallback.
//!
//! Lives in `core` (not `fairdp`) so both the `fairdp` and `beacon` crates can
//! derive the same value without `beacon` depending on `fairdp`.

/// Convert a 17-digit `YYYYMMDDHHMMSSmmm` numeric tail into an `xsd:dateTime`
/// lexical value (`YYYY-MM-DDTHH:MM:SS.mmmZ`), or [`None`] if the `datasetId`
/// has no 17-digit timestamp tail or the tail is not a real UTC instant.
///
/// This is a pure lexical reshaping with full calendar validation: month
/// 01-12, hour 00-23, minute/second 00-59, and the day must be a real day of that
/// month accounting for Gregorian leap years (so Apr 31 and Feb 29 in a non-leap
/// year are rejected). It still never constructs a calendar type, so no time crate
/// is needed and it cannot panic. Returning [`None`] for an impossible date lets the
/// caller fall back to the preflight-validated `[fairdp].issued`, so the node never
/// emits an ill-typed `xsd:dateTime` literal a strict FDP/SHACL consumer rejects.
///
/// The heuristic is shape-only and provenance-blind. Any id whose final hyphen-segment is
/// 17 digits forming a real UTC instant is read as a creation time, whatever its prefix.
/// A foreign id whose opaque tail happens to have that shape (`GDI-FI-THL-20240101000000123`)
/// is reported as that instant rather than `None`. The node mints both `GOE-` and `GDI-`
/// ids with real 17-digit timestamp tails, so a prefix cannot distinguish a node-minted
/// timestamp from someone else's accession number. A foreign dataset whose true instant
/// differs from its id tail must carry it explicitly, for example in `metadata_modified`.
///
/// # Examples
///
/// ```
/// use gdi_node_standalone_core::datetime::dataset_datetime;
///
/// // The 17-digit timestamp tail becomes an xsd:dateTime lexical value.
/// assert_eq!(
///     dataset_datetime("GDI-EE-UTARTU-20260409143052837").as_deref(),
///     Some("2026-04-09T14:30:52.837Z")
/// );
/// // A foreign id with no parseable timestamp yields `None`.
/// assert_eq!(dataset_datetime("GDI-FI-THL-1"), None);
/// // An out-of-range field (month 13) is rejected.
/// assert_eq!(dataset_datetime("GDI-EE-UTARTU-20261309143052837"), None);
/// // A field-valid but calendar-impossible date (Apr 31) is rejected too.
/// assert_eq!(dataset_datetime("GDI-EE-UTARTU-20260431120000000"), None);
/// ```
#[must_use]
pub fn dataset_datetime(dataset_id: &str) -> Option<String> {
    // The numeric tail after the final `-`.
    let tail = dataset_id.rsplit('-').next()?;
    if tail.len() != 17 || !tail.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (year, rest) = tail.split_at(4);
    let (month, rest) = rest.split_at(2);
    let (day, rest) = rest.split_at(2);
    let (hour, rest) = rest.split_at(2);
    let (minute, rest) = rest.split_at(2);
    let (second, millis) = rest.split_at(2);

    if !in_range(month, 1, 12)
        || !in_range(hour, 0, 23)
        || !in_range(minute, 0, 59)
        || !in_range(second, 0, 59)
    {
        return None;
    }
    // Calendar-validate the day against the actual length of (year, month). The tail is
    // all ASCII digits and `year`/`month`/`day` are fixed-width slices, so every `parse`
    // here succeeds and the `?` is never taken.
    let y: u32 = year.parse().ok()?;
    let m: u32 = month.parse().ok()?;
    let d: u32 = day.parse().ok()?;
    // XSD 1.0 prohibits year 0000 in the `xsd:dateTime` lexical space, so it is rejected
    // alongside the calendar check. Otherwise a `…-00000101…` tail would emit
    // "0000-01-01T00:00:00.000Z", an ill-typed literal a strict FDP/SHACL consumer rejects.
    // The caller falls back to the preflight-validated `[fairdp].issued`.
    if y < 1 || d < 1 || d > days_in_month(y, m) {
        return None;
    }

    Some(format!(
        "{year}-{month}-{day}T{hour}:{minute}:{second}.{millis}Z"
    ))
}

/// A total, chronological ordering key for an `xsd:dateTime` / RFC-3339 instant
/// string — whole nanoseconds since the Unix epoch in UTC — or [`None`] if `value`
/// is not a parseable RFC-3339 instant.
///
/// [`dataset_datetime`] emits a canonical `…Z` form whose byte order already tracks
/// chronological order, but operator-supplied `[fairdp].issued` may carry a numeric
/// offset (`+03:00`) or omit sub-seconds, so a *lexical* max over a mix of the two
/// forms can report the chronologically-earlier value as the latest. Callers that
/// must order such a mix (e.g. the FDP `metadataModified`) compare on this key.
///
/// # Examples
///
/// ```
/// use gdi_node_standalone_core::datetime::rfc3339_instant_nanos;
///
/// // `12:00:00+03:00` (= 09:00Z) is earlier than `10:00:00.000Z`, even though it
/// // sorts lexically later. That is the bug this key exists to avoid.
/// let offset = rfc3339_instant_nanos("2025-06-01T12:00:00+03:00").unwrap();
/// let zulu = rfc3339_instant_nanos("2025-06-01T10:00:00.000Z").unwrap();
/// assert!(offset < zulu);
/// assert_eq!(rfc3339_instant_nanos("not-a-date"), None);
/// ```
#[must_use]
pub fn rfc3339_instant_nanos(value: &str) -> Option<i128> {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(time::OffsetDateTime::unix_timestamp_nanos)
}

/// Whether the 2-digit field parses into `[lo, hi]`.
fn in_range(field: &str, lo: u32, hi: u32) -> bool {
    field.parse::<u32>().is_ok_and(|v| (lo..=hi).contains(&v))
}

/// The number of days in `month` (1-12) of `year`, per the Gregorian calendar.
///
/// Returns `0` for a month outside 1-12 (unreachable — the caller range-checks the
/// month first), which makes any day fail the `d <= days_in_month` test.
fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// The Gregorian leap-year rule: divisible by 4, except centuries not divisible by 400.
fn is_leap_year(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

/// Re-serialize an RFC-3339 timestamp into the `xsd:dateTime` lexical space, or `None`
/// when it does not parse.
///
/// The one place this conversion happens: validity and canonicality are different
/// questions.
///
/// `time`'s RFC-3339 parser is lenient. It accepts any single byte as the date/time
/// separator and matches the zone case-insensitively, so `2027-01-01 00:00:00Z` and
/// `2027-01-01t00:00:00z` both parse while lying outside `xsd:dateTime`. Anything stamped
/// `^^xsd:dateTime` must therefore be re-serialized, not merely checked. One ill-typed
/// literal fails SHACL for the whole record at a conforming harvester, and
/// `fdp-o:metadataModified` on the FDP root is the max over datasets, so a bad value there
/// drops the root and every catalog record out of the harvest.
///
/// Both `[fairdp].issued` at config load and the operator-writable overlay `applied_at`
/// that feeds `dct:modified` come through here.
#[must_use]
pub fn to_xsd_datetime(value: &str) -> Option<String> {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::parse(value, &Rfc3339)
        .ok()
        .and_then(|dt| dt.format(&Rfc3339).ok())
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;

    #[test]
    fn parses_17_digit_timestamp() {
        assert_eq!(
            dataset_datetime("GDI-EE-UTARTU-20260409143052837").unwrap(),
            "2026-04-09T14:30:52.837Z"
        );
    }

    #[test]
    fn rejects_foreign_short_id() {
        assert!(dataset_datetime("GDI-FI-THL-1").is_none());
    }

    #[test]
    fn shape_heuristic_is_provenance_blind() {
        // The heuristic keys on the 17-digit-valid-date shape alone, never the prefix, so
        // a foreign id whose opaque tail coincidentally has that shape is read as a
        // creation time rather than `None`. A prefix cannot distinguish a node-minted
        // timestamp from a foreign accession number, since the node mints both `GOE-` and
        // `GDI-` ids with real timestamp tails. Pinned here so gating on provenance is a
        // conscious edit.
        assert_eq!(
            dataset_datetime("GDI-FI-THL-20240101000000123").as_deref(),
            Some("2024-01-01T00:00:00.123Z"),
            "a foreign date-shaped 17-digit tail is interpreted (provenance-blind)"
        );
        // A foreign tail that is not a 17-digit real instant yields None, so the caller
        // falls back to [fairdp].issued rather than emitting an ill-typed literal.
        assert!(
            dataset_datetime("GDI-FI-THL-20241301000000000").is_none(),
            "month 13 in a foreign tail is not a real instant -> None"
        );
    }

    #[test]
    fn rejects_out_of_range_month() {
        // 17 digits but month 13.
        assert!(dataset_datetime("GDI-EE-UTARTU-20261309143052837").is_none());
    }

    #[test]
    fn accepts_inclusive_field_boundaries() {
        // Upper bounds: month 12, day 31, hour 23, minute 59, second 59 (the
        // `..=hi` inclusive edge — an exclusive `..hi` off-by-one would reject).
        assert_eq!(
            dataset_datetime("X-20261231235959999").as_deref(),
            Some("2026-12-31T23:59:59.999Z")
        );
        // Lower bounds: month 01, day 01, hour/minute/second 00 (the `lo..=`
        // inclusive edge — a `(lo+1)..=` off-by-one would reject month 01).
        assert_eq!(
            dataset_datetime("X-20260101000000000").as_deref(),
            Some("2026-01-01T00:00:00.000Z")
        );
    }

    #[test]
    fn rejects_fields_just_outside_their_range() {
        assert!(dataset_datetime("X-20261232235959999").is_none()); // day 32
        assert!(dataset_datetime("X-20261231245959999").is_none()); // hour 24
        assert!(dataset_datetime("X-20261231236059999").is_none()); // minute 60
        assert!(dataset_datetime("X-20261231235960999").is_none()); // second 60
        assert!(dataset_datetime("X-20260001000000000").is_none()); // month 00
        assert!(dataset_datetime("X-20260100000000000").is_none()); // day 00
    }

    #[test]
    fn rejects_year_zero() {
        // XSD 1.0 prohibits year 0000 in the `xsd:dateTime` lexical space. A datasetId tail
        // yielding year 0000 must return None, so the caller falls back to the
        // preflight-validated `[fairdp].issued` rather than emitting
        // "0000-01-01T00:00:00.000Z", which a strict FDP/SHACL consumer rejects.
        assert!(
            dataset_datetime("X-00000101000000000").is_none(),
            "year 0000 is not a valid xsd:dateTime and must yield None"
        );
        // The lower bound is exactly 0000: year 0001 is a valid xsd:dateTime and is still
        // accepted (pins the guard to `< 1`, not an over-broad epoch floor).
        assert_eq!(
            dataset_datetime("X-00010101000000000").as_deref(),
            Some("0001-01-01T00:00:00.000Z")
        );
    }

    #[test]
    fn rejects_field_valid_but_calendar_impossible_dates() {
        // Each of these passes the per-field range checks (day <= 31) but is not a
        // real calendar day, so it would otherwise emit an ill-typed xsd:dateTime the
        // FDP/SHACL consumer rejects.
        assert!(dataset_datetime("X-20260431120000000").is_none()); // Apr 31 (30-day)
        assert!(dataset_datetime("X-20260631120000000").is_none()); // Jun 31 (30-day)
        assert!(dataset_datetime("X-20260229120000000").is_none()); // Feb 29, 2026 (non-leap)
        assert!(dataset_datetime("X-19000229120000000").is_none()); // Feb 29, 1900 (century, non-leap)
    }

    #[test]
    fn accepts_valid_non_leap_february_day() {
        // Feb 28 in a non-leap year (2026) is a real calendar day and must be accepted.
        // Deleting the `2 => 28` arm of `days_in_month` makes non-leap February fall
        // through to `_ => 0`, so `d > 0` rejects every day and this valid date would
        // wrongly yield `None` (the caller then silently falls back to `[fairdp].issued`).
        assert_eq!(
            dataset_datetime("X-20260228120000000").as_deref(),
            Some("2026-02-28T12:00:00.000Z")
        );
    }

    #[test]
    fn rfc3339_instant_nanos_orders_across_offset_and_zulu() {
        // A unit mirror of the doctest above, which nextest does not execute, so the
        // `-> None` and `Some(0/1/-1)` mutants of this key are challenged here.
        // `12:00:00+03:00` (= 09:00Z) is earlier than `10:00:00.000Z` yet sorts lexically
        // later, which is the bug this key defends against. The `.expect`s kill `-> None`;
        // the ordering and the `None` assertion kill the constant mutants.
        let offset = rfc3339_instant_nanos("2025-06-01T12:00:00+03:00")
            .expect("a valid offset RFC3339 instant parses");
        let zulu = rfc3339_instant_nanos("2025-06-01T10:00:00.000Z")
            .expect("a valid Zulu RFC3339 instant parses");
        assert!(
            offset < zulu,
            "a +03:00 instant must order before the same wall-clock time in Zulu: \
             {offset} vs {zulu}"
        );
        assert_eq!(
            rfc3339_instant_nanos("not-a-date"),
            None,
            "a non-RFC3339 input must yield None"
        );
    }

    #[test]
    fn accepts_real_leap_day() {
        // Feb 29 in a leap year (2024) and in a 400-divisible century (2000) is valid.
        assert_eq!(
            dataset_datetime("X-20240229120000000").as_deref(),
            Some("2024-02-29T12:00:00.000Z")
        );
        assert_eq!(
            dataset_datetime("X-20000229120000000").as_deref(),
            Some("2000-02-29T12:00:00.000Z")
        );
    }
}
