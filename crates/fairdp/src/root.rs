//! Build the FDP-root and Catalog RDF records and their LDP navigation.
//!
//! These are the only two layers FDP v1.2 normatively constrains, so each carries
//! its full mandatory property set at the stated cardinality. All values are
//! service-generated from `[fairdp]` and `[catalogs]` config plus constants; none are
//! per-dataset. Two structural invariants the tests guard:
//!
//! * The root lists every configured catalog, including empty ones, with stable URIs,
//!   under both `ldp:contains` and `fdp-o:metadataCatalog`.
//! * A catalog lists only its visible datasets, under all three of `dct:hasPart`,
//!   `dcat:dataset` and `ldp:contains`. The caller does the visibility filtering; this
//!   module renders what it is given.
//!
//! `fdp-o:metadataModified` is data-derived and restart-stable: the latest dataset
//! change time (from each `datasetId` timestamp via [`crate::datetime`]), falling back
//! to `[fairdp].issued` when nothing is contained. It is never a wall-clock value.

use gdi_node_standalone_core::cache::DatasetEntry;
use oxrdf::{Graph, NamedNode, NamedOrBlankNode};

use crate::context::FdpContext;
use crate::datetime::rfc3339_instant_nanos;
use crate::graph::{GraphBuilder, add_contact_point_cfg, add_publisher, dataset_modified};
use crate::vocab;

/// One configured catalog as listed under the FDP root: its id, display title,
/// and its visible datasets (for the data-derived `fdp-o:metadataModified`).
///
/// Carries the visible datasets rather than a pre-computed timestamp, so the root
/// derives its own `metadataModified` (the latest across all catalogs) with the same
/// rule the catalog records use. An empty `visible_datasets` is a valid empty catalog:
/// stable URI, zero membership triples.
pub struct CatalogListing<'a> {
    /// The catalog id (the `[catalogs]` key; the resource-IRI slug).
    pub id: &'a str,
    /// The catalog display title (the `[catalogs]` value).
    pub title: &'a str,
    /// The catalog's visible datasets, already filtered by the caller.
    pub visible_datasets: Vec<&'a DatasetEntry>,
}

/// The data-derived metadata-modified time for a set of datasets: the latest
/// dataset change time, floored at (and falling back to) `[fairdp].issued`.
///
/// Each dataset's change time is its `dct:modified`, taken from [`dataset_modified`] so
/// the two cannot drift. The latest is the chronological maximum: dataset values are
/// canonical `…Z`, but the `issued` fallback is operator-supplied and may carry a numeric
/// offset (`+03:00`) or omit sub-seconds, so a byte-wise max over the mix could report the
/// earlier instant as the latest change. The comparison runs on the parsed instant and
/// returns the winner's original lexical form. The result is restart-stable: it depends
/// only on the contained ids and config, never on the wall clock.
///
/// Each dataset's `metadata_modified` is itself monotonic (the overlay store keeps a
/// durable high-water mark that survives a revert; see
/// [`gdi_node_standalone_core::overlay_store::read_modified_hwm`]), so a content edit or
/// revert never lowers this aggregate. It can still fall when the latest-modified dataset
/// leaves the visible set: an accepted limitation, since a harvester already sees that
/// change through the dropped `dcat:dataset` and `ldp:contains` triples.
fn metadata_modified(datasets: &[&DatasetEntry], issued: &str) -> String {
    datasets
        .iter()
        .map(|entry| dataset_modified(entry, issued))
        // Floored at `issued` by making it a participant rather than only a fallback: a
        // dataset's change time can predate the catalog's issue date (an id minted before
        // the node was configured, or an imported package), and `issued` is the earliest
        // instant this record can claim.
        .chain(std::iter::once(issued.to_owned()))
        // Values that fail to parse sort lowest (`None` < `Some`), so a real instant
        // always wins over an unparseable one.
        .max_by(|a, b| rfc3339_instant_nanos(a).cmp(&rfc3339_instant_nanos(b)))
        .unwrap_or_else(|| issued.to_owned())
}

/// The metadata-bookkeeping triplet plus the two conformance markers, shared by
/// the root and Catalog records (both FDP v1.2-mandatory at cardinality 1).
///
/// `metadata_identifier` is the record's own resource IRI; `conforms_to` is its
/// opaque profile marker IRI; `modified` is the data-derived value.
fn add_common_fdp_metadata(
    b: &mut GraphBuilder,
    subj: &NamedOrBlankNode,
    metadata_identifier: &str,
    conforms_to: &str,
    issued: &str,
    modified: &str,
) {
    b.add_iri(
        subj.clone(),
        vocab::FDP_O_CONFORMS_TO_FDP_SPEC,
        vocab::FDP_SPEC_V1_2,
    );
    b.add_iri(subj.clone(), vocab::DCT_CONFORMS_TO, conforms_to);
    b.add_iri(
        subj.clone(),
        vocab::FDP_O_METADATA_IDENTIFIER,
        metadata_identifier,
    );
    b.add_typed(
        subj.clone(),
        vocab::FDP_O_METADATA_ISSUED,
        issued,
        vocab::XSD_DATE_TIME,
    );
    b.add_typed(
        subj.clone(),
        vocab::FDP_O_METADATA_MODIFIED,
        modified,
        vocab::XSD_DATE_TIME,
    );
}

/// Build the **Catalog** record graph for one catalog.
///
/// `visible_datasets` are the catalog's already-filtered visible datasets; an
/// empty slice renders a valid empty `dcat:Catalog` (stable URI, mandatory props,
/// zero membership triples). Every visible dataset is emitted under all three
/// membership predicates `dct:hasPart`, `dcat:dataset` and `ldp:contains` (the FDP v1.2,
/// DCAT and harvester-navigation predicates).
///
/// The graph carries a `dct:publisher` blank node, so structural comparison must
/// be blank-node-aware (canonicalize first).
#[must_use]
pub fn catalog_graph(
    catalog_id: &str,
    title: &str,
    visible_datasets: &[&DatasetEntry],
    ctx: &FdpContext,
) -> Graph {
    let mut b = GraphBuilder::new();
    let iri = ctx.catalog_iri(catalog_id);
    let subj: NamedOrBlankNode = NamedNode::new_unchecked(&iri).into();
    let issued = &ctx.fairdp.issued;
    let modified = metadata_modified(visible_datasets, issued);

    b.add_type(subj.clone(), vocab::DCAT_CATALOG);
    add_common_fdp_metadata(
        &mut b,
        &subj,
        &iri,
        &ctx.catalog_profile_iri(),
        issued,
        &modified,
    );

    // Title; description always equals the title (CatalogShape mandates both).
    b.add_string(subj.clone(), vocab::DCT_TITLE, title);
    b.add_string(subj.clone(), vocab::DCT_DESCRIPTION, title);

    add_publisher(&mut b, &subj, vocab::DCT_PUBLISHER, ctx);
    b.add_iri(subj.clone(), vocab::DCT_LICENSE, &ctx.fairdp.license);
    b.add_iri(subj.clone(), vocab::DCT_LANGUAGE, &ctx.fairdp.language);
    b.add_iri(subj.clone(), vocab::DCT_IS_PART_OF, &ctx.root_iri());

    // themeTaxonomy: the SKOS ConceptScheme of the configured theme (bare IRI, no
    // local rdf:type). Omitted only if no theme is configured.
    if let Some(taxonomy) = ctx.fairdp.theme_taxonomy_iri() {
        b.add_iri(subj.clone(), vocab::DCAT_THEME_TAXONOMY, &taxonomy);
    }

    // CatalogShape-mandated node-level applicableLegislation (datasets carry their
    // own).
    b.add_iris(
        &subj,
        vocab::DCATAP_APPLICABLE_LEGISLATION,
        &ctx.fairdp.applicable_legislation,
    );

    // The three membership predicates, each -> every visible dataset IRI.
    for entry in visible_datasets {
        let dataset_iri = ctx.dataset_iri(&entry.id);
        b.add_iri(subj.clone(), vocab::DCT_HAS_PART, &dataset_iri);
        b.add_iri(subj.clone(), vocab::DCAT_DATASET_PRED, &dataset_iri);
        b.add_iri(subj.clone(), vocab::LDP_CONTAINS, &dataset_iri);
    }

    b.finish()
}

/// Build the **FDP-root** record graph (`/fairdp`) and its LDP navigation.
///
/// Lists every configured catalog in `catalogs`, including empty ones, with stable URIs,
/// under both `ldp:contains` and `fdp-o:metadataCatalog`. The root is typed all three of
/// `fdp-o:FAIRDataPoint`, `fdp-o:MetadataService` and `dcat:DataService`. The last makes
/// gdi-metadata's `DataServiceShape` target it, so the root carries `dcat:endpointURL`,
/// the canonical lowercase-`p` DCAT predicate that satisfies both the FDP-root shape and
/// `DataServiceShape`.
///
/// `fdp-o:metadataModified` is the latest change across every catalog's visible datasets,
/// falling back to `[fairdp].issued`.
///
/// The graph carries `dct:publisher` / `dcat:contactPoint` blank nodes, so
/// structural comparison must be blank-node-aware (canonicalize first).
#[must_use]
pub fn fdp_root_graph(catalogs: &[CatalogListing], ctx: &FdpContext) -> Graph {
    let mut b = GraphBuilder::new();
    let iri = ctx.root_iri();
    let subj: NamedOrBlankNode = NamedNode::new_unchecked(&iri).into();
    let issued = &ctx.fairdp.issued;

    // Latest change across every catalog's visible datasets.
    let all_datasets: Vec<&DatasetEntry> = catalogs
        .iter()
        .flat_map(|c| c.visible_datasets.iter().copied())
        .collect();
    let modified = metadata_modified(&all_datasets, issued);

    b.add_type(subj.clone(), vocab::FDP_O_FAIR_DATA_POINT);
    b.add_type(subj.clone(), vocab::FDP_O_METADATA_SERVICE);
    b.add_type(subj.clone(), vocab::DCAT_DATA_SERVICE);

    add_common_fdp_metadata(
        &mut b,
        &subj,
        &iri,
        &ctx.root_profile_iri(),
        issued,
        &modified,
    );

    b.add_string(subj.clone(), vocab::DCT_TITLE, &ctx.fairdp.title);
    add_publisher(&mut b, &subj, vocab::DCT_PUBLISHER, ctx);
    b.add_iri(subj.clone(), vocab::DCT_LICENSE, &ctx.fairdp.license);
    b.add_iri(subj.clone(), vocab::DCT_LANGUAGE, &ctx.fairdp.language);

    // The DCAT service endpoint: the canonical lowercase-`p` `dcat:endpointURL`,
    // satisfying both the FDP-root shape and gdi-metadata's DataServiceShape (the
    // `dcat:` namespace defines no capital-P `endPointURL`).
    b.add_iri(subj.clone(), vocab::DCAT_ENDPOINT_URL, &iri);

    // Optional description + contact point (the publisher contact point is required
    // config, so always present and emitted here too).
    if let Some(description) = &ctx.fairdp.description {
        b.add_string(subj.clone(), vocab::DCT_DESCRIPTION, description);
    }
    add_contact_point_cfg(
        &mut b,
        &subj,
        vocab::DCAT_CONTACT_POINT,
        &ctx.fairdp.publisher.contact_point,
    );

    // Every configured catalog, even empty ones, under both navigation predicates.
    for catalog in catalogs {
        let catalog_iri = ctx.catalog_iri(catalog.id);
        b.add_iri(subj.clone(), vocab::FDP_O_METADATA_CATALOG, &catalog_iri);
        b.add_iri(subj.clone(), vocab::LDP_CONTAINS, &catalog_iri);
    }

    b.finish()
}
