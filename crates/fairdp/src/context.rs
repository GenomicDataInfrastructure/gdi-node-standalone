//! The rendering context: the node-invariant inputs (base URL, beacon path, FDP
//! node identity) plus the IRI builders the graph builder uses.

use gdi_node_standalone_core::config::FairdpConfig;
use oxrdf::Graph;

use crate::publish::{NO_EDITS, Publish, Record};

/// The node-invariant inputs threaded through graph construction.
///
/// Borrows everything: the caller owns the config and the strings. `base_url`
/// carries no trailing slash (the service config strips it on load) and
/// `beacon_aggregated_path` is the beacon `aggregated_base_path` (e.g.
/// `/beacon/v2`).
#[derive(Debug, Clone, Copy)]
pub struct FdpContext<'a> {
    /// Externally-reachable base URL, no trailing slash (e.g.
    /// `https://gdi-ee.example.org`).
    pub base_url: &'a str,
    /// Beacon aggregated mount path, leading slash, no trailing slash (e.g.
    /// `/beacon/v2`).
    pub beacon_aggregated_path: &'a str,
    /// The FAIR Data Point node identity (publisher / HDAB / theme / license).
    pub fairdp: &'a FairdpConfig,
    /// The compiled `[fairdp.publish]` edits every record builder applies last. No edits
    /// unless set with [`FdpContext::with_publish`].
    pub publish: &'a Publish,
}

impl<'a> FdpContext<'a> {
    /// Build a context from its parts.
    ///
    /// # Examples
    ///
    /// ```
    /// use gdi_node_standalone_fairdp::FdpContext;
    /// use gdi_node_standalone_core::config::FairdpConfig;
    ///
    /// let fairdp = FairdpConfig::default();
    /// let ctx = FdpContext::new("https://gdi-ee.example.org", "/beacon/v2", &fairdp);
    ///
    /// // The IRI builders compose the node base URL with the FDP path layout.
    /// assert_eq!(ctx.root_iri(), "https://gdi-ee.example.org/fairdp");
    /// assert_eq!(
    ///     ctx.dataset_iri("GDI-EE-UTARTU-20260409143052837"),
    ///     "https://gdi-ee.example.org/fairdp/dataset/GDI-EE-UTARTU-20260409143052837"
    /// );
    /// assert_eq!(ctx.beacon_endpoint_url(), "https://gdi-ee.example.org/beacon/v2");
    /// ```
    #[must_use]
    pub fn new(
        base_url: &'a str,
        beacon_aggregated_path: &'a str,
        fairdp: &'a FairdpConfig,
    ) -> Self {
        Self {
            base_url,
            beacon_aggregated_path,
            fairdp,
            publish: &NO_EDITS,
        }
    }

    /// This context with the compiled `[fairdp.publish]` edits.
    #[must_use]
    pub fn with_publish(self, publish: &'a Publish) -> Self {
        Self { publish, ..self }
    }

    /// Apply the `[fairdp.publish]` edits to a finished record graph whose subject is
    /// `subject` and whose id (for `$FDP_ID`) is `id`. Every record builder returns
    /// through this, so none can serve a record without the edits.
    pub(crate) fn published(
        &self,
        mut graph: Graph,
        record: Record,
        subject: &str,
        id: Option<&str>,
    ) -> Graph {
        self.publish
            .apply(&mut graph, record, subject, &self.root_iri(), id);
        graph
    }

    /// The FDP-root resource IRI: `{base_url}/fairdp`.
    #[must_use]
    pub fn root_iri(&self) -> String {
        format!("{}/fairdp", self.base_url)
    }

    /// The catalog resource IRI: `{base_url}/fairdp/catalog/{id}`.
    #[must_use]
    pub fn catalog_iri(&self, id: &str) -> String {
        format!("{}/fairdp/catalog/{id}", self.base_url)
    }

    /// The FDP-root profile marker IRI: `{base_url}/fairdp/profile/service`. An
    /// opaque, non-dereferenceable marker satisfying the cardinality-1
    /// `dct:conformsTo` requirement.
    #[must_use]
    pub fn root_profile_iri(&self) -> String {
        format!("{}/fairdp/profile/service", self.base_url)
    }

    /// The Catalog profile marker IRI: `{base_url}/fairdp/profile/catalog` (an
    /// opaque marker, as [`Self::root_profile_iri`]).
    #[must_use]
    pub fn catalog_profile_iri(&self) -> String {
        format!("{}/fairdp/profile/catalog", self.base_url)
    }

    /// The dataset resource IRI: `{base_url}/fairdp/dataset/{id}`.
    #[must_use]
    pub fn dataset_iri(&self, id: &str) -> String {
        format!("{}/fairdp/dataset/{id}", self.base_url)
    }

    /// The distribution resource IRI: `{base_url}/fairdp/distribution/{id}`.
    #[must_use]
    pub fn distribution_iri(&self, id: &str) -> String {
        format!("{}/fairdp/distribution/{id}", self.base_url)
    }

    /// The aggregated Beacon's base URL, `{base_url}{beacon_aggregated_path}`: the
    /// `dcat:endpointURL` of every distribution's data service.
    #[must_use]
    pub fn beacon_endpoint_url(&self) -> String {
        format!(
            "{}{}",
            self.base_url.trim_end_matches('/'),
            self.beacon_aggregated_path.trim_end_matches('/')
        )
    }
}
