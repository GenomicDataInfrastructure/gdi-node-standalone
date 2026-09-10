//! Dataset ID generation and validation.
//!
//! Format: `(GOE|GDI)-CC-ORG-YYYYMMDDHHMMSSmmm`. Validation uses the broader gdi-metadata
//! SHACL pattern `^(GOE|GDI)-[A-Z]{2}-[A-Z]+-[0-9]+$` (the numeric part is "a unique number",
//! not necessarily a timestamp), plus a single overall 64-char cap. The numeric width is
//! not pinned, so foreign IDs such as `GDI-FI-THL-1` validate.

use crate::error::{CoreResult, invalid_manifest};
use regex::Regex;
use std::sync::OnceLock;
use time::OffsetDateTime;
use time::format_description::BorrowedFormatItem;
use time::macros::format_description;

/// Maximum overall dataset-ID length (bounds storage without constraining the numeric width).
const MAX_DATASET_ID_LEN: usize = 64;

/// Maximum length of the `ORG` institute abbreviation.
const MAX_ORG_LEN: usize = 16;

/// `YYYYMMDDHHMMSSmmm` (17 digits): date, time, then a 3-digit millisecond subsecond.
const TIMESTAMP_FORMAT: &[BorrowedFormatItem<'static>] =
    format_description!("[year][month][day][hour][minute][second][subsecond digits:3]");

/// The two dataset-ID prefixes.
///
/// The ID regex below, the mint-time check in [`generate_dataset_id`], `validate_pkg`'s
/// `metadata.prefix` enum and the tool wizard's pick-list all read this constant, so the
/// list exists in one place.
pub const DATASET_ID_PREFIXES: [&str; 2] = ["GOE", "GDI"];

/// The compiled, linear-time validation pattern (RE2-style automaton; no backtracking).
#[expect(
    clippy::expect_used,
    reason = "the pattern is a compile-time constant, so a failure is a build bug, not a runtime condition"
)]
fn pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(&format!(
            r"^({})-[A-Z]{{2}}-[A-Z]+-[0-9]+$",
            DATASET_ID_PREFIXES.join("|")
        ))
        .expect("static dataset-ID regex is valid")
    })
}

/// Validate a dataset ID (own or foreign), per the gdi-metadata SHACL pattern + 64-char cap.
///
/// Accepts any numeric width (e.g. the foreign `GDI-FI-THL-1`), not just the 17-digit
/// timestamp this crate's generator produces.
///
/// # Examples
///
/// ```
/// use gdi_node_standalone_core::id::is_valid_dataset_id;
///
/// // Our own 17-digit-timestamp form and a foreign short numeric both validate.
/// assert!(is_valid_dataset_id("GDI-EE-UTARTU-20260409143052837"));
/// assert!(is_valid_dataset_id("GDI-FI-THL-1"));
/// // The GOE (Genome of Europe) prefix is equally valid.
/// assert!(is_valid_dataset_id("GOE-EE-UTARTU-20260409143052837"));
/// // A lowercase prefix or a 3-letter country code is rejected.
/// assert!(!is_valid_dataset_id("gdi-EE-UTARTU-1"));
/// assert!(!is_valid_dataset_id("GDI-EST-UTARTU-1"));
/// ```
#[must_use]
pub fn is_valid_dataset_id(id: &str) -> bool {
    id.len() <= MAX_DATASET_ID_LEN && pattern().is_match(id)
}

/// Build a dataset ID from its parts.
///
/// `epoch_millis` is the creation timestamp in milliseconds since the Unix epoch; the caller
/// supplies it (the CLI passes the real wall clock) so this function stays pure and testable.
/// The timestamp is formatted as the 17-digit `YYYYMMDDHHMMSSmmm` form in UTC.
///
/// # Examples
///
/// ```
/// use gdi_node_standalone_core::id::{generate_dataset_id, is_valid_dataset_id};
///
/// # fn main() -> Result<(), gdi_node_standalone_core::error::CoreError> {
/// // 1_744_209_052_837 ms since the epoch = 2025-04-09T14:30:52.837Z (UTC).
/// let id = generate_dataset_id("GDI", "EE", "UTARTU", 1_744_209_052_837)?;
/// assert_eq!(id, "GDI-EE-UTARTU-20250409143052837");
/// assert!(is_valid_dataset_id(&id));
/// // A malformed part (a lowercase org) is rejected.
/// assert!(generate_dataset_id("GDI", "EE", "utartu", 0).is_err());
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns [`CoreError::InvalidManifest`](crate::error::CoreError::InvalidManifest) if any
/// part is malformed: `prefix` must be `GOE` or `GDI`; `cc` must be exactly two uppercase
/// ASCII letters; `org` must be 1..=16 uppercase ASCII letters; `epoch_millis` must be a
/// representable timestamp; and the assembled ID must satisfy [`is_valid_dataset_id`].
pub fn generate_dataset_id(
    prefix: &str,
    cc: &str,
    org: &str,
    epoch_millis: u64,
) -> CoreResult<String> {
    if !DATASET_ID_PREFIXES.contains(&prefix) {
        return Err(invalid_manifest("prefix must be GOE or GDI"));
    }
    if cc.len() != 2 || !cc.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(invalid_manifest(
            "country code must be two uppercase letters",
        ));
    }
    if org.is_empty() || org.len() > MAX_ORG_LEN || !org.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(invalid_manifest("org must be 1..=16 uppercase letters"));
    }

    let nanos = i128::from(epoch_millis) * 1_000_000;
    let ts = OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .map_err(|_| invalid_manifest("creation timestamp out of range"))?
        .format(&TIMESTAMP_FORMAT)
        .map_err(|_| invalid_manifest("failed to format creation timestamp"))?;

    let id = format!("{prefix}-{cc}-{org}-{ts}");
    if !is_valid_dataset_id(&id) {
        return Err(invalid_manifest("generated dataset ID failed validation"));
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;
    #[test]
    fn validates_generated_and_foreign_ids() {
        assert!(is_valid_dataset_id("GDI-EE-UTARTU-20260409143052837"));
        assert!(is_valid_dataset_id("GOE-EE-UTARTU-20260409143052837")); // GOE arm
        assert!(is_valid_dataset_id("GDI-FI-THL-1")); // foreign short numeric — must pass
        assert!(!is_valid_dataset_id("gdi-EE-UTARTU-1")); // lowercase prefix
        assert!(!is_valid_dataset_id("GDI-EST-UTARTU-1")); // 3-letter CC
        assert!(!is_valid_dataset_id(&format!(
            "GDI-EE-UTARTU-{}",
            "9".repeat(60)
        ))); // >64 chars
    }
    #[test]
    fn rejects_control_chars_and_trailing_newline() {
        // The path-injection guarantee rests on the regex `$` meaning end-of-haystack: the
        // `regex` crate with no `(?m)` flag, unlike PCRE, where `$` also matches before a
        // trailing newline. A newline, CR or NUL anywhere in an otherwise-valid id must be
        // rejected, so a `(?m)` flag or an engine swap that reopens a newline or NUL
        // injection into an audit line, an S3 key or a path join fails here.
        assert!(!is_valid_dataset_id("GDI-FI-THL-1\n"));
        assert!(!is_valid_dataset_id("GDI-FI-THL-1\r\n"));
        assert!(!is_valid_dataset_id("GDI-FI-THL-1\r"));
        assert!(!is_valid_dataset_id("GDI-FI-THL-1\0"));
        assert!(!is_valid_dataset_id("GDI-FI-THL\n-1"));
        assert!(!is_valid_dataset_id("\nGDI-FI-THL-1"));
    }

    #[test]
    fn generates_well_formed_id() {
        let id = generate_dataset_id("GDI", "EE", "UTARTU", 1_744_209_052_837).unwrap();
        assert!(id.starts_with("GDI-EE-UTARTU-"));
        assert!(is_valid_dataset_id(&id));
        // 1_744_209_052_837 ms = 2025-04-09T14:30:52.837Z (UTC), formatted as 17 digits.
        assert_eq!(id, "GDI-EE-UTARTU-20250409143052837");
    }

    #[test]
    fn rejects_malformed_parts() {
        // bad prefix, country code, and org are all rejected.
        assert!(generate_dataset_id("GOX", "EE", "UTARTU", 0).is_err());
        assert!(generate_dataset_id("GDI", "EST", "UTARTU", 0).is_err());
        assert!(generate_dataset_id("GDI", "ee", "UTARTU", 0).is_err());
        assert!(generate_dataset_id("GDI", "EE", "utartu", 0).is_err());
        assert!(generate_dataset_id("GDI", "EE", "", 0).is_err());
        assert!(generate_dataset_id("GDI", "EE", &"A".repeat(17), 0).is_err());
    }

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Self-consistency: any valid (prefix, cc, org, timestamp) generates an id
        /// that `is_valid_dataset_id` accepts, whose 17-digit numeric tail is exactly
        /// the UTC `YYYYMMDDHHMMSSmmm` of the timestamp. The epoch range is bounded to
        /// years 1970..=9999 so the tail is always exactly 17 digits.
        #[test]
        fn generate_then_validate_roundtrips(
            prefix in prop::sample::select(vec!["GOE".to_owned(), "GDI".to_owned()]),
            cc in "[A-Z]{2}",
            org in "[A-Z]{1,16}",
            epoch_millis in 0u64..=253_402_300_799_999u64,
        ) {
            let id = generate_dataset_id(&prefix, &cc, &org, epoch_millis).unwrap();
            prop_assert!(is_valid_dataset_id(&id));
            // id == prefix-cc-org-tail (format! is unavailable inside proptest!).
            let parts: Vec<&str> = id.splitn(4, '-').collect();
            prop_assert_eq!(parts.len(), 4);
            prop_assert_eq!(parts[0], prefix.as_str());
            prop_assert_eq!(parts[1], cc.as_str());
            prop_assert_eq!(parts[2], org.as_str());

            let tail = parts[3];
            prop_assert_eq!(tail.len(), 17);
            prop_assert!(tail.bytes().all(|b| b.is_ascii_digit()));

            // Recompute the tail independently from the same timestamp.
            let nanos = i128::from(epoch_millis) * 1_000_000;
            let want = OffsetDateTime::from_unix_timestamp_nanos(nanos)
                .unwrap()
                .format(&TIMESTAMP_FORMAT)
                .unwrap();
            prop_assert_eq!(tail, want.as_str());
        }

        /// A malformed part (bad prefix, non-2-letter cc, lowercase cc, lowercase
        /// org) always yields `Err`.
        #[test]
        fn malformed_parts_rejected(
            org in "[A-Z]{1,16}",
            ms in 0u64..=253_402_300_799_999u64,
            which in 0u8..4,
        ) {
            let res = match which {
                0 => generate_dataset_id("GOX", "EE", &org, ms),
                1 => generate_dataset_id("GDI", "EST", &org, ms),
                2 => generate_dataset_id("GDI", "ee", &org, ms),
                _ => generate_dataset_id("GDI", "EE", &org.to_lowercase(), ms),
            };
            prop_assert!(res.is_err());
        }
    }
}
