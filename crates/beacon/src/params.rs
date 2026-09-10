//! The minimal beacon configuration contract.
//!
//! The query/assembly ([`crate::query`]) and request parse/classify
//! ([`crate::request`]) APIs read only these eight fields — not the full ~20-field
//! service `[beacon]` configuration. Owning the contract here (rather than taking
//! `gdi_node_standalone_core::config::BeaconConfig`) keeps this crate a self-contained,
//! framework-agnostic library: a consumer maps its own configuration into
//! [`BeaconParams`] instead of being forced to construct the service's config shape.

/// The beacon parameters the query and request APIs read.
///
/// The `gdi-node-standalone` service maps its `[beacon]` config into this at each handler.
#[derive(Debug, Clone)]
pub struct BeaconParams {
    /// Beacon id (GA4GH `meta.beaconId`).
    pub id: String,
    /// Human-readable beacon name; also the fallback `af_source` when a dataset leaves
    /// it unset.
    pub name: String,
    /// GA4GH API version string (`meta.apiVersion`).
    pub api_version: String,
    /// Maximum queryable span in base pairs; a request wider than this is rejected.
    pub max_query_span_bp: u64,
    /// Default page size when the request omits `limit`.
    pub default_page_limit: u64,
    /// Maximum page size a request may ask for; every `limit` is clamped to this. Applied
    /// per dataset, so a query matching N datasets returns up to `N × limit` entries.
    pub max_page_limit: u64,
    /// The node-wide k-anonymity floor, `max`'d with each dataset's own. Counts alleles,
    /// not individuals: a homozygote contributes 2 to `AC`, so the effective
    /// individual-level anonymity is about `floor/2`. Use `2k` for k distinct people.
    pub min_allele_count: u32,
    /// Default response granularity (`boolean` | `count` | `record`) when the request
    /// omits `requestedGranularity`.
    pub default_granularity: String,
}

impl Default for BeaconParams {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            // GA4GH Beacon v2.2.0 — the spec version this crate implements (mirrors
            // `gdi_node_standalone_core::config::SUPPORTED_BEACON_API_VERSION`).
            api_version: "v2.2.0".to_owned(),
            max_query_span_bp: 10_000_000,
            default_page_limit: 10,
            // 1000 so a client that asks for a whole position range in one page, as the
            // GDI User Portal does, is served it rather than silently truncated. Peak RSS
            // grows with the page limit and with the dataset's population count (see
            // "Resource baseline" in `docs/deployment.md`), and the cost is per request and
            // per dataset, so a node sizes `max_concurrent_requests` against it.
            // `default_page_limit` stays 10, so only a client that asks for a big page
            // pays for one.
            max_page_limit: 1000,
            min_allele_count: 0,
            default_granularity: "record".to_owned(),
        }
    }
}
