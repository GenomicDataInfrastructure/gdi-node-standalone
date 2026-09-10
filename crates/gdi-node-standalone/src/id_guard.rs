//! Boundary validation for id-bearing routes.
//!
//! Every id and catalog-name path parameter is parsed against its pattern at the API
//! boundary. A non-conforming value (a traversal-shaped `../…`, an embedded NUL, an
//! overlong string) is rejected with `400`/`404` before it can index the cache or build a
//! filesystem path. Lookups go through the in-memory cache and status index, never the
//! filesystem, so this is defence in depth: a route-level check guarantees a
//! traversal-shaped value can never reach a path join.
//!
//! * Dataset ids ([`is_safe_dataset_id`]) use the gdi-metadata SHACL pattern via
//!   [`gdi_node_standalone_core::id::is_valid_dataset_id`]:
//!   `^(GOE|GDI)-[A-Z]{2}-[A-Z]+-[0-9]+$` capped at 64 chars, which admits no `/`, `.`,
//!   NUL, or overlong value.
//! * Catalog names ([`is_safe_catalog_name`]) are config keys looked up in a map, so the
//!   boundary check covers traversal, NUL and length only: a non-empty, ≤64-char value of
//!   safe characters.

use gdi_node_standalone_core::id::is_valid_dataset_id;

/// Whether `id` is a syntactically valid dataset id safe to use as a lookup key.
///
/// Delegates to the canonical [`is_valid_dataset_id`]; the pattern admits no
/// traversal (`/`, `.`), NUL, or overlong value.
#[must_use]
pub fn is_safe_dataset_id(id: &str) -> bool {
    is_valid_dataset_id(id)
}

/// Whether `name` is a safe catalog name to use as a map lookup key.
///
/// Catalog names are operator-chosen config keys, not a fixed SHACL pattern, so this is the
/// data-safety guard only: non-empty, within the catalog-name length cap, and free of
/// path-traversal and control characters. An unknown but safe name still `404`s at the map
/// lookup; this rejects the shapes that must never reach a lookup or a path join.
#[must_use]
pub fn is_safe_catalog_name(name: &str) -> bool {
    // Delegates, as `is_safe_dataset_id` above does: the cap and the rule that applies it
    // live in core, so the two crates cannot disagree about either.
    gdi_node_standalone_core::validate_pkg::is_safe_catalog_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_dataset_id_accepts_valid_rejects_traversal() {
        assert!(is_safe_dataset_id("GDI-EE-UTARTU-20260409143052837"));
        assert!(is_safe_dataset_id("GDI-FI-THL-1"));
        // Traversal / separators / control shapes never match the pattern.
        assert!(!is_safe_dataset_id("../etc/passwd"));
        assert!(!is_safe_dataset_id("GDI-EE-UTARTU-1/../secret"));
        assert!(!is_safe_dataset_id("GDI-EE-UTARTU-1\0"));
        // The pattern is end-anchored, so a decoded `%0a`/`%0d` cannot smuggle a control
        // character into a lookup key or an audit line.
        assert!(!is_safe_dataset_id("GDI-EE-UTARTU-1\n"));
        assert!(!is_safe_dataset_id("GDI-EE-UTARTU-1\r\n"));
        assert!(!is_safe_dataset_id("GDI-EE-UTARTU\n-1"));
        assert!(!is_safe_dataset_id("not_an_id"));
        assert!(!is_safe_dataset_id(""));
    }

    #[test]
    fn safe_catalog_name_accepts_valid_rejects_traversal() {
        assert!(is_safe_catalog_name("gdi-aggregated"));
        assert!(is_safe_catalog_name("gdi_sensitive"));
        assert!(is_safe_catalog_name("cat.v2"));
        // Traversal / control / overlong / empty are rejected.
        assert!(!is_safe_catalog_name(""));
        assert!(!is_safe_catalog_name("../etc"));
        assert!(!is_safe_catalog_name("a/b"));
        assert!(!is_safe_catalog_name(".hidden"));
        assert!(!is_safe_catalog_name("a..b"));
        assert!(!is_safe_catalog_name("with space"));
        assert!(!is_safe_catalog_name("nul\0byte"));
        assert!(!is_safe_catalog_name(&"x".repeat(65)));
    }
}
