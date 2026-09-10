//! Build the FDP entity graphs (Dataset, Distribution + inline `DataService`) as a
//! single `oxrdf::Graph`. The Dataset record is driven by the static mapping table;
//! the Distribution (a hard-coded 1:1 child of the dataset) and its inline
//! `DataService` are built directly.
//!
//! The graph is the internal representation both serializers read, so Turtle and
//! JSON-LD never drift. Node construction uses the `*_unchecked` oxrdf constructors:
//! the IRIs are either node constants or values already validated at config preflight
//! or package ingest, so a second parse would only add cost.

use gdi_node_standalone_core::cache::DatasetEntry;
use gdi_node_standalone_core::config::ContactPointCfg;
use gdi_node_standalone_core::model::{Agent, ContactPoint, LocalizedText, OtherIdentifier};
use gdi_node_standalone_core::validate_pkg::canonical_bcp47;
use oxrdf::{BlankNode, Graph, Literal, NamedNode, NamedOrBlankNode, Term, Triple};

use crate::context::FdpContext;
use crate::datetime::dataset_datetime;
use crate::mapping::{DATASET_MAPPING, FieldMapping, MetaField};
use crate::vocab;

/// Thin builder over [`oxrdf::Graph`] with typed-add helpers for each RDF object
/// encoding (langString / typed literal / IRI / blank node). Subjects are passed as
/// owned [`NamedOrBlankNode`], so the same helpers serve the dataset record and its
/// nested blank nodes.
pub(crate) struct GraphBuilder {
    graph: Graph,
}

impl GraphBuilder {
    pub(crate) fn new() -> Self {
        Self {
            graph: Graph::new(),
        }
    }

    /// Consume the builder and return the assembled graph.
    pub(crate) fn finish(self) -> Graph {
        self.graph
    }

    /// Insert `subject predicate object`.
    pub(crate) fn add(&mut self, subject: NamedOrBlankNode, predicate: &str, object: Term) {
        let triple = Triple::new(subject, NamedNode::new_unchecked(predicate), object);
        self.graph.insert(&triple);
    }

    /// `subject rdf:type class`.
    pub(crate) fn add_type(&mut self, subject: NamedOrBlankNode, class: &str) {
        self.add(
            subject,
            vocab::RDF_TYPE,
            NamedNode::new_unchecked(class).into(),
        );
    }

    /// Attach a fresh, `rdf:type`d blank node under `parent`, i.e.
    /// `parent predicate [ a class ]`. Returns the new node's subject so the caller
    /// can hang the node's own properties off it.
    fn add_blank_node(
        &mut self,
        parent: &NamedOrBlankNode,
        predicate: &str,
        class: &str,
    ) -> NamedOrBlankNode {
        let node = BlankNode::default();
        let node_subj: NamedOrBlankNode = node.clone().into();
        self.add(parent.clone(), predicate, Term::BlankNode(node));
        self.add_type(node_subj.clone(), class);
        node_subj
    }

    /// `subject predicate <iri>`.
    pub(crate) fn add_iri(&mut self, subject: NamedOrBlankNode, predicate: &str, iri: &str) {
        self.add(subject, predicate, NamedNode::new_unchecked(iri).into());
    }

    /// `subject predicate <iri>` for each IRI in the list.
    pub(crate) fn add_iris<'i>(
        &mut self,
        subject: &NamedOrBlankNode,
        predicate: &str,
        iris: impl IntoIterator<Item = &'i String>,
    ) {
        for iri in iris {
            self.add_iri(subject.clone(), predicate, iri);
        }
    }

    /// `subject predicate "value"` for each plain-string literal in the list.
    fn add_strings<'i>(
        &mut self,
        subject: &NamedOrBlankNode,
        predicate: &str,
        values: impl IntoIterator<Item = &'i String>,
    ) {
        for value in values {
            self.add_string(subject.clone(), predicate, value);
        }
    }

    /// `subject predicate "n"^^datatype` for a non-negative integer value.
    fn add_typed_u64(
        &mut self,
        subject: NamedOrBlankNode,
        predicate: &str,
        n: u64,
        datatype: &str,
    ) {
        self.add_typed(subject, predicate, &n.to_string(), datatype);
    }

    /// `subject predicate "value"` (plain string literal, no datatype/lang).
    pub(crate) fn add_string(&mut self, subject: NamedOrBlankNode, predicate: &str, value: &str) {
        self.add(
            subject,
            predicate,
            Literal::new_simple_literal(value).into(),
        );
    }

    /// `subject predicate "value"^^datatype`.
    pub(crate) fn add_typed(
        &mut self,
        subject: NamedOrBlankNode,
        predicate: &str,
        value: &str,
        datatype: &str,
    ) {
        let lit = Literal::new_typed_literal(value, NamedNode::new_unchecked(datatype));
        self.add(subject, predicate, lit.into());
    }

    /// Localized field: one `"text"@lang` per map entry, or a single plain literal
    /// for an unkeyed string.
    ///
    /// The tag is emitted in canonical lowercase form, through the same
    /// [`canonical_bcp47`] that ingest uses as the `sh:uniqueLang` key. RDF 1.1 defines a
    /// langString's value space with the tag lowercased, so a map key such as `en-US`
    /// echoed verbatim would not survive its own re-parse. One definition of "the same
    /// language tag" keeps the emitter and the uniqueness gate in step.
    fn add_localized(&mut self, subject: NamedOrBlankNode, predicate: &str, text: &LocalizedText) {
        match text {
            LocalizedText::Plain(value) => self.add_string(subject, predicate, value),
            LocalizedText::Map(map) => {
                for (lang, value) in map {
                    // An ill-formed tag cannot reach here: package ingest and overlay
                    // apply both reject a tag with no canonical form. Emitting it
                    // unchanged is the inert fallback for a value that cannot occur.
                    let tag = canonical_bcp47(lang).unwrap_or_else(|| lang.clone());
                    let lit = Literal::new_language_tagged_literal_unchecked(value, tag);
                    self.add(subject.clone(), predicate, lit.into());
                }
            }
        }
    }
}

/// Build the **Dataset** record graph for `entry`.
///
/// Emits everything the gdi-metadata `DatasetShape` mandates, plus the service-generated
/// `dct:issued`/`dct:modified`, the node-config publisher / HDAB / theme, the
/// distribution link, and the constant `adms:status`.
///
/// The graph carries blank nodes (creator, publisher, HDAB, contact point,
/// `adms:Identifier`), so structural comparison must be blank-node-aware
/// (canonicalize first).
#[must_use]
pub fn dataset_graph(entry: &DatasetEntry, ctx: &FdpContext) -> Graph {
    let mut b = GraphBuilder::new();
    let subj: NamedOrBlankNode = NamedNode::new_unchecked(ctx.dataset_iri(&entry.id)).into();

    b.add_type(subj.clone(), vocab::DCAT_DATASET);
    for m in DATASET_MAPPING {
        add_dataset_field(&mut b, &subj, entry, ctx, m);
    }

    b.finish()
}

/// Emit the triples for one mapping-table row on the dataset record.
fn add_dataset_field(
    b: &mut GraphBuilder,
    subj: &NamedOrBlankNode,
    entry: &DatasetEntry,
    ctx: &FdpContext,
    m: &FieldMapping,
) {
    let meta = &entry.metadata;
    match m.field {
        MetaField::Identifier => {
            // The datasetId as an xsd:string literal (DatasetShape mandates the
            // literal; the IRI slug alone does not satisfy it).
            b.add_typed(subj.clone(), m.predicate, &entry.id, vocab::XSD_STRING);
        }
        MetaField::Title => b.add_localized(subj.clone(), m.predicate, &meta.title),
        MetaField::Description => {
            if let Some(desc) = &meta.description {
                b.add_localized(subj.clone(), m.predicate, desc);
            }
        }
        // `accessRights` is descriptive metadata: it classifies record-level access and
        // no serving path consults it. The k-anonymity floor and the dataset's visibility
        // state are the access controls, which is what makes a record-level NON_PUBLIC
        // dataset publishable as aggregate allele frequencies.
        MetaField::AccessRights => b.add_iri(subj.clone(), m.predicate, &meta.access_rights),
        MetaField::ApplicableLegislation => {
            b.add_iris(subj, m.predicate, &meta.applicable_legislation);
        }
        MetaField::License => b.add_iri(subj.clone(), m.predicate, &meta.license),
        MetaField::Creator => {
            for agent in &meta.creator {
                add_creator(b, subj, m.predicate, agent);
            }
        }
        MetaField::Publisher => add_publisher(b, subj, m.predicate, ctx),
        MetaField::Hdab => add_hdab(b, subj, m.predicate, ctx),
        MetaField::HealthCategory => b.add_iris(subj, m.predicate, &meta.health_category),
        MetaField::Keyword => b.add_strings(subj, m.predicate, meta.keywords.iter().flatten()),
        MetaField::NumberOfUniqueIndividuals => {
            if let Some(n) = meta.number_of_unique_individuals {
                b.add_typed_u64(
                    subj.clone(),
                    m.predicate,
                    n,
                    vocab::XSD_NON_NEGATIVE_INTEGER,
                );
            }
        }
        MetaField::NumberOfRecords => {
            if let Some(n) = meta.number_of_records {
                b.add_typed_u64(
                    subj.clone(),
                    m.predicate,
                    n,
                    vocab::XSD_NON_NEGATIVE_INTEGER,
                );
            }
        }
        MetaField::ConformsTo => b.add_iris(subj, m.predicate, meta.conforms_to.iter().flatten()),
        MetaField::Type => {
            if let Some(t) = &meta.type_ {
                b.add_iri(subj.clone(), m.predicate, t);
            }
        }
        MetaField::LegalBasis => b.add_iris(subj, m.predicate, meta.legal_basis.iter().flatten()),
        MetaField::IsReferencedBy => {
            b.add_iris(subj, m.predicate, meta.is_referenced_by.iter().flatten());
        }
        MetaField::OtherIdentifier => {
            for id in meta.other_identifier.iter().flatten() {
                add_other_identifier(b, subj, m.predicate, id);
            }
        }
        MetaField::ContactPoint => {
            if let Some(cp) = &meta.contact_point {
                add_contact_point(b, subj, m.predicate, cp);
            }
        }
        MetaField::Theme => b.add_iris(subj, m.predicate, &ctx.fairdp.theme),
        MetaField::Language => b.add_iri(subj.clone(), m.predicate, &ctx.fairdp.language),
        MetaField::Issued => {
            let dt = dataset_datetime(&entry.id).unwrap_or_else(|| ctx.fairdp.issued.clone());
            b.add_typed(subj.clone(), m.predicate, &dt, vocab::XSD_DATE_TIME);
        }
        MetaField::Modified => {
            let dt = dataset_modified(entry, &ctx.fairdp.issued);
            b.add_typed(subj.clone(), m.predicate, &dt, vocab::XSD_DATE_TIME);
        }
        MetaField::Distribution => {
            b.add_iri(subj.clone(), m.predicate, &ctx.distribution_iri(&entry.id));
        }
        MetaField::Status => {
            b.add_iri(subj.clone(), m.predicate, vocab::DATASET_STATUS_COMPLETED);
        }
    }
}

/// A dataset's `dct:modified` value: its recorded `metadata_modified`, else the
/// creation timestamp derived from its `datasetId`, else the `[fairdp].issued`
/// fallback.
///
/// Single-sourced here: [`crate::root`] derives the catalog and FDP-root
/// `fdp-o:metadataModified` as the latest of this value across the contained datasets,
/// so a record and its containers cannot disagree about a dataset's change time.
pub(crate) fn dataset_modified(entry: &DatasetEntry, issued: &str) -> String {
    entry
        .metadata_modified
        .clone()
        // The override comes from the operator-writable overlay file's `applied_at`, the
        // one source of this value not validated upstream. It is canonicalized rather than
        // only checked: `rfc3339_instant_nanos` accepts a space separator and a lowercase
        // `t`/`z`, both outside the `xsd:dateTime` lexical space. A value that does not
        // parse falls through to the next source, since one ill-typed literal fails SHACL
        // for the whole record and this value also feeds every catalog and the FDP root as
        // the max `fdp-o:metadataModified`.
        .and_then(|v| crate::datetime::to_xsd_datetime(&v))
        .or_else(|| dataset_datetime(&entry.id))
        .unwrap_or_else(|| issued.to_owned())
}

/// `dct:publisher`: the node-config Organization (`AgentHdabShape`), its optional
/// `foaf:homepage`, and always a `foaf:mbox`. The mbox is the configured
/// `[fairdp.publisher].mbox` when set, else the contact point's mandatory
/// `vcard:hasEmail`.
///
/// The mbox is unconditional for the reason [`add_hdab`] states: `ckanext-dcat`'s
/// `_agents_details` reads the address on the agent and never descends into
/// `dcat:contactPoint`, and a config with a contact point but no `mbox` preflights
/// clean.
pub(crate) fn add_publisher(
    b: &mut GraphBuilder,
    parent: &NamedOrBlankNode,
    predicate: &str,
    ctx: &FdpContext,
) {
    let pubr = &ctx.fairdp.publisher;
    let node = add_agent_hdab(b, parent, predicate, &pubr.name, &pubr.contact_point);
    if let Some(homepage) = &pubr.homepage {
        b.add_iri(node.clone(), vocab::FOAF_HOMEPAGE, homepage);
    }
    let mbox = pubr
        .mbox
        .as_deref()
        .unwrap_or(&pubr.contact_point.has_email);
    b.add_iri(node, vocab::FOAF_MBOX, mbox);
}

/// `healthdcatap:hdab`: the node-config Health Data Access Body (`AgentHdabShape`)
/// plus the `foaf:mbox` its contact point's `vcard:hasEmail` already states.
///
/// The address is duplicated because `ckanext-dcat`'s `_agents_details` reads
/// `foaf:mbox` on the agent and never descends into `dcat:contactPoint`, so an agent
/// carrying only the vCard harvests with an empty e-mail. The vCard stays because
/// `AgentHdabShape` mandates it.
///
/// Every HDAB agent goes through this one function, as the publisher goes through
/// [`add_publisher`], so no call site can emit the agent without its `foaf:mbox`.
pub(crate) fn add_hdab(
    b: &mut GraphBuilder,
    parent: &NamedOrBlankNode,
    predicate: &str,
    ctx: &FdpContext,
) {
    let hdab = &ctx.fairdp.hdab;
    let node = add_agent_hdab(b, parent, predicate, &hdab.name, &hdab.contact_point);
    b.add_iri(node, vocab::FOAF_MBOX, &hdab.contact_point.has_email);
}

/// Build the **Distribution** record graph for `entry`.
///
/// The distribution is the dataset's 1:1 generated child: its
/// `dcatap:applicableLegislation` and `dct:license` are inherited from the parent
/// dataset. `dcat:accessURL` and the inline `dcat:accessService` `dcat:DataService` both
/// point at the beacon `g_variants` endpoint.
#[must_use]
pub fn distribution_graph(entry: &DatasetEntry, ctx: &FdpContext) -> Graph {
    let mut b = GraphBuilder::new();
    let dist_iri = ctx.distribution_iri(&entry.id);
    let dataset_iri = ctx.dataset_iri(&entry.id);
    let g_variants = ctx.beacon_g_variants_url();
    let subj: NamedOrBlankNode = NamedNode::new_unchecked(&dist_iri).into();

    b.add_type(subj.clone(), vocab::DCAT_DISTRIBUTION);
    b.add_string(subj.clone(), vocab::DCT_TITLE, "Beacon distribution");
    b.add_iri(subj.clone(), vocab::DCAT_ACCESS_URL, &g_variants);
    // The distribution's response media type. `ckanext-dcat` maps `dcat:mediaType` into
    // the GDI User Portal's `res_format` facet; a Beacon endpoint answers `application/json`.
    b.add_iri(
        subj.clone(),
        vocab::DCAT_MEDIA_TYPE,
        vocab::IANA_MEDIA_TYPE_APPLICATION_JSON,
    );
    // The same fact as a format, the predicate that facet labels from (see
    // `vocab::EU_FILE_TYPE_JSON`). DCAT-AP 3 recommends emitting the pair.
    b.add_iri(subj.clone(), vocab::DCT_FORMAT, vocab::EU_FILE_TYPE_JSON);

    // Inherited from the parent dataset's own per-dataset values.
    for iri in &entry.metadata.applicable_legislation {
        b.add_iri(subj.clone(), vocab::DCATAP_APPLICABLE_LEGISLATION, iri);
    }
    b.add_iri(subj.clone(), vocab::DCT_LICENSE, &entry.metadata.license);

    // Inline DataService blank node under dcat:accessService.
    let service_subj =
        b.add_blank_node(&subj, vocab::DCAT_ACCESS_SERVICE, vocab::DCAT_DATA_SERVICE);
    // Lowercase `dcat:endpointURL` (the DataServiceShape predicate), not the capital-P
    // FDP v1.2 spelling: an inline DataService carries only this one.
    b.add_iri(service_subj.clone(), vocab::DCAT_ENDPOINT_URL, &g_variants);
    b.add_string(service_subj.clone(), vocab::DCT_TITLE, "GDI Beacon");
    b.add_iri(service_subj, vocab::DCAT_SERVES_DATASET, &dataset_iri);

    b.finish()
}

/// `dct:creator [ a foaf:Agent ; foaf:name "<name>" ]` (`AgentCreatorShape`).
fn add_creator(b: &mut GraphBuilder, parent: &NamedOrBlankNode, predicate: &str, agent: &Agent) {
    let node_subj = b.add_blank_node(parent, predicate, vocab::FOAF_AGENT);
    b.add_string(node_subj, vocab::FOAF_NAME, &agent.name);
}

/// An `AgentHdabShape` agent (`foaf:Agent` + `foaf:name` + a mandatory
/// `dcat:contactPoint` `vcard:Kind`). Used for both `dct:publisher` and
/// `healthdcatap:hdab` from node config. Returns the agent's blank-node subject
/// so the caller can attach agent-specific extras (e.g. the publisher's
/// `foaf:homepage`/`foaf:mbox`).
fn add_agent_hdab(
    b: &mut GraphBuilder,
    parent: &NamedOrBlankNode,
    predicate: &str,
    name: &str,
    contact: &ContactPointCfg,
) -> NamedOrBlankNode {
    let node_subj = b.add_blank_node(parent, predicate, vocab::FOAF_AGENT);
    b.add_string(node_subj.clone(), vocab::FOAF_NAME, name);
    add_contact_point_cfg(b, &node_subj, vocab::DCAT_CONTACT_POINT, contact);
    node_subj
}

/// `adms:identifier [ a adms:Identifier ; skos:notation … ; adms:schemaAgency … ;
/// foaf:name … ]` (`IdentifierShape` — all three string literals; only `notation`
/// is required).
fn add_other_identifier(
    b: &mut GraphBuilder,
    parent: &NamedOrBlankNode,
    predicate: &str,
    id: &OtherIdentifier,
) {
    let node_subj = b.add_blank_node(parent, predicate, vocab::ADMS_IDENTIFIER_CLASS);
    b.add_string(node_subj.clone(), vocab::SKOS_NOTATION, &id.notation);
    if let Some(agency) = &id.schema_agency {
        b.add_string(node_subj.clone(), vocab::ADMS_SCHEMA_AGENCY, agency);
    }
    if let Some(name) = &id.name {
        b.add_string(node_subj, vocab::FOAF_NAME, name);
    }
}

/// A per-dataset `dcat:contactPoint [ a vcard:Kind ; … ]` (`KindShape`). `fn` is a
/// literal; `hasEmail` (`mailto:` IRI) and `hasURL` are IRIs.
fn add_contact_point(
    b: &mut GraphBuilder,
    parent: &NamedOrBlankNode,
    predicate: &str,
    cp: &ContactPoint,
) {
    let node_subj = b.add_blank_node(parent, predicate, vocab::VCARD_KIND);
    if let Some(fn_) = &cp.fn_ {
        b.add_string(node_subj.clone(), vocab::VCARD_FN, fn_);
    }
    if let Some(email) = &cp.has_email {
        b.add_iri(node_subj.clone(), vocab::VCARD_HAS_EMAIL, email);
    }
    if let Some(url) = &cp.has_url {
        b.add_iri(node_subj, vocab::VCARD_HAS_URL, url);
    }
}

/// A node-config `vcard:Kind` contact point (publisher / HDAB / FDP root). The
/// config type makes `fn`/`hasEmail` mandatory (validated at preflight).
pub(crate) fn add_contact_point_cfg(
    b: &mut GraphBuilder,
    parent: &NamedOrBlankNode,
    predicate: &str,
    cp: &ContactPointCfg,
) {
    let node_subj = b.add_blank_node(parent, predicate, vocab::VCARD_KIND);
    b.add_string(node_subj.clone(), vocab::VCARD_FN, &cp.fn_);
    b.add_iri(node_subj.clone(), vocab::VCARD_HAS_EMAIL, &cp.has_email);
    if let Some(url) = &cp.has_url {
        b.add_iri(node_subj, vocab::VCARD_HAS_URL, url);
    }
}
