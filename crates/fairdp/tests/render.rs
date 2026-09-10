//! Integration tests for the FDP Dataset / Distribution / inline `DataService`
//! rendering: key-triple assertions, golden canonical-N-Triples snapshots,
//! JSON-LD <-> Turtle isomorphism, and the inline `DataService` blank-node
//! contract.
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::collections::BTreeMap;

use gdi_node_standalone_core::cache::DatasetEntry;
use gdi_node_standalone_core::config::{
    ContactPointCfg, FairdpConfig, FairdpHdab, FairdpPublisher,
};
use gdi_node_standalone_core::model::{
    Agent, Assembly, ContactPoint, DatasetMode, LocalizedText, ManifestConfig, ManifestMetadata,
    OtherIdentifier,
};
use gdi_node_standalone_core::state::DatasetState;

use gdi_node_standalone_fairdp::{
    CatalogListing, FdpContext, catalog_graph, dataset_graph, distribution_graph, fdp_root_graph,
    serialize_jsonld, serialize_turtle,
};

use oxrdf::dataset::CanonicalizationAlgorithm;
use oxrdf::{Graph, NamedNodeRef, NamedOrBlankNodeRef, TermRef};

const DATASET_ID: &str = "GDI-EE-UTARTU-20260409143052837";
const BASE_URL: &str = "https://gdi-ee.example.org";
const BEACON_PATH: &str = "/beacon/v2";
/// The fixture's `[fairdp].language`: Estonian, so it is distinguishable from the
/// built-in English default.
const LANGUAGE: &str = "http://publications.europa.eu/resource/authority/language/EST";

/// A representative COVID-derived dataset entry (the manifest.json fixture
/// fields), exercising every model branch: localized title/description as a
/// language map, lists, the otherIdentifier blank node, and a contact point.
fn covid_entry() -> DatasetEntry {
    let mut title = BTreeMap::new();
    title.insert("en".to_owned(), "GoE Estonia aggregated AFs".to_owned());
    title.insert("et".to_owned(), "GoE Eesti koondsagedused".to_owned());

    let metadata = ManifestMetadata {
        dataset_id: DATASET_ID.to_owned(),
        catalog: "gdi-aggregated".to_owned(),
        title: LocalizedText::Map(title),
        description: Some(LocalizedText::Plain(
            "Aggregated allele frequencies for the GoE Estonia cohort.".to_owned(),
        )),
        access_rights: "http://publications.europa.eu/resource/authority/access-right/PUBLIC"
            .to_owned(),
        applicable_legislation: vec!["http://data.europa.eu/eli/reg/2025/327/oj".to_owned()],
        license: "https://creativecommons.org/licenses/by/4.0/".to_owned(),
        creator: vec![Agent {
            name: "Genome of Europe - EE node".to_owned(),
        }],
        health_category: vec!["http://data.gdi.eu/core/p2/HealthCategoryHumanGenomic".to_owned()],
        keywords: Some(vec!["allele-frequency".to_owned(), "genomics".to_owned()]),
        number_of_unique_individuals: Some(1234),
        conforms_to: Some(vec!["http://data.gdi.eu/core/p2/1MGCompliant".to_owned()]),
        type_: None,
        legal_basis: Some(vec!["https://w3id.org/dpv#Consent".to_owned()]),
        is_referenced_by: Some(vec!["https://doi.org/10.1234/example".to_owned()]),
        other_identifier: Some(vec![OtherIdentifier {
            notation: "DOI-12345".to_owned(),
            schema_agency: Some("DataCite".to_owned()),
            name: Some("Example identifier".to_owned()),
        }]),
        contact_point: Some(ContactPoint {
            fn_: Some("Data team".to_owned()),
            has_email: Some("mailto:data@example.org".to_owned()),
            has_url: None,
        }),
        number_of_records: Some(123_456),
        populations: None,
    };

    let config = ManifestConfig {
        mode: DatasetMode::Aggregated,
        block_range: 10_000_000,
        af_source: Some("The Genome of Europe".to_owned()),
        af_source_reference: Some("https://genomeofeurope.eu/".to_owned()),
        min_allele_count: 0,
        hide_lower_counts: None,
        assembly: Assembly {
            reference: "GRCh38".to_owned(),
        },
        manifest_version: 1,
        generated_by: "gdi-dataset-tool v1.0.0".to_owned(),
    };

    DatasetEntry {
        id: DATASET_ID.to_owned(),
        metadata,
        config,
        state: DatasetState::Visible,
        metadata_modified: None,
    }
}

/// The node-identity FDP config (publisher + HDAB + theme + license).
fn fairdp_config() -> FairdpConfig {
    FairdpConfig {
        title: "GDI Estonia FAIR Data Point".to_owned(),
        description: Some("Aggregated genomic metadata for GDI Estonia".to_owned()),
        issued: "2026-01-01T00:00:00Z".to_owned(),
        license: "https://creativecommons.org/licenses/by/4.0/".to_owned(),
        // Not the built-in default (ENG): an emitter that hard-coded the default IRI
        // instead of reading config would render identically under an English fixture.
        language: LANGUAGE.to_owned(),
        theme: vec!["http://publications.europa.eu/resource/authority/data-theme/HEAL".to_owned()],
        theme_taxonomy: None,
        applicable_legislation: vec!["http://data.europa.eu/eli/reg/2025/327/oj".to_owned()],
        publisher: FairdpPublisher {
            name: "University of Tartu".to_owned(),
            homepage: Some("https://gdi.ut.ee".to_owned()),
            mbox: Some("mailto:gdi@example.org".to_owned()),
            contact_point: ContactPointCfg {
                fn_: "GDI Estonia".to_owned(),
                has_email: "mailto:gdi@example.org".to_owned(),
                // Distinct from publisher.homepage above: with one IRI in both,
                // foaf:homepage and vcard:hasURL render identically in the goldens, and
                // emitting one where the other belongs would be invisible.
                has_url: Some("https://gdi.ut.ee/contact".to_owned()),
            },
        },
        hdab: FairdpHdab {
            name: "Estonian HDAB".to_owned(),
            contact_point: ContactPointCfg {
                fn_: "Estonian HDAB".to_owned(),
                has_email: "mailto:hdab@example.org".to_owned(),
                has_url: None,
            },
        },
    }
}

/// Re-parse a Turtle document into a canonicalized graph.
fn parse_turtle(ttl: &str) -> Graph {
    let mut graph = Graph::new();
    for triple in oxttl::TurtleParser::new().for_slice(ttl.as_bytes()) {
        graph.insert(&triple.unwrap());
    }
    graph.canonicalize(CanonicalizationAlgorithm::Unstable);
    graph
}

/// Re-parse a JSON-LD document into a canonicalized graph.
fn parse_jsonld(jsonld: &str) -> Graph {
    let mut graph = Graph::new();
    for quad in oxjsonld::JsonLdParser::new().for_slice(jsonld.as_bytes()) {
        let quad = quad.unwrap();
        graph.insert(oxrdf::TripleRef::new(
            quad.subject.as_ref(),
            quad.predicate.as_ref(),
            quad.object.as_ref(),
        ));
    }
    graph.canonicalize(CanonicalizationAlgorithm::Unstable);
    graph
}

#[test]
fn dataset_turtle_contains_key_triples() {
    let fairdp = fairdp_config();
    let ctx = FdpContext::new(BASE_URL, BEACON_PATH, &fairdp);
    let graph = dataset_graph(&covid_entry(), &ctx);
    let ttl = serialize_turtle(&graph);

    let dataset_iri = format!("{BASE_URL}/fairdp/dataset/{DATASET_ID}");

    // The dataset resource is typed dcat:Dataset.
    assert!(ttl.contains("a dcat:Dataset") || ttl.contains("rdf:type dcat:Dataset"));

    // dct:identifier carrying the datasetId as a string literal — bound to the
    // dataset subject, not just present somewhere in the serialization.
    assert!(
        literals(&graph, &dataset_iri, &format!("{DCT}identifier"))
            .contains(&DATASET_ID.to_owned()),
        "dct:identifier literal not bound to dataset subject"
    );

    // The configured theme IRI emitted on the dataset subject under dcat:theme.
    assert!(
        iri_objects(&graph, &dataset_iri, &format!("{DCAT}theme")).contains(
            &"http://publications.europa.eu/resource/authority/data-theme/HEAL".to_owned()
        ),
        "theme IRI not bound to dataset subject under dcat:theme:\n{ttl}"
    );

    // numberOfRecords typed literal.
    assert!(
        ttl.contains("healthdcatap:numberOfRecords") && ttl.contains("123456"),
        "numberOfRecords missing:\n{ttl}"
    );

    // The distribution link to the generated distribution resource.
    assert!(
        iri_objects(&graph, &dataset_iri, &format!("{DCAT}distribution"))
            .contains(&format!("{BASE_URL}/fairdp/distribution/{DATASET_ID}")),
        "distribution link not bound to dataset subject:\n{ttl}"
    );

    // legalBasis under dpv:hasLegalBasis (DPV namespace), bound to the dataset subject.
    assert!(
        !iri_objects(&graph, &dataset_iri, "https://w3id.org/dpv#hasLegalBasis").is_empty(),
        "dpv:hasLegalBasis not found on dataset subject:\n{ttl}"
    );

    // Language-tagged title literals bound to the dataset subject under dct:title.
    let title_literals = literals(&graph, &dataset_iri, &format!("{DCT}title"));
    assert!(
        title_literals
            .iter()
            .any(|v| v == "GoE Estonia aggregated AFs"),
        "English title literal not found on dataset subject; got: {title_literals:?}"
    );
    assert!(
        title_literals
            .iter()
            .any(|v| v == "GoE Eesti koondsagedused"),
        "Estonian title literal not found on dataset subject; got: {title_literals:?}"
    );

    // The constant COMPLETED status.
    assert!(
        ttl.contains("http://publications.europa.eu/resource/authority/dataset-status/COMPLETED")
    );
}

/// A deterministic golden representation of a graph: canonicalize blank nodes, then emit
/// sorted N-Triples, one fully-qualified triple per line.
///
/// `oxrdf::Graph` iteration and the Turtle serializer's grouping are both hash-dependent,
/// so a Turtle snapshot would not be byte-stable across runs. The content-assertion tests
/// cover the human-readable Turtle form.
fn golden_ntriples(graph: &Graph) -> String {
    let mut canon = graph.clone();
    canon.canonicalize(CanonicalizationAlgorithm::Unstable);
    let mut lines: Vec<String> = canon.iter().map(|t| t.to_string()).collect();
    lines.sort();
    lines.join("\n")
}

#[test]
fn dataset_graph_golden_snapshot() {
    let fairdp = fairdp_config();
    let ctx = FdpContext::new(BASE_URL, BEACON_PATH, &fairdp);
    let nt = golden_ntriples(&dataset_graph(&covid_entry(), &ctx));
    insta::assert_snapshot!("dataset_ntriples", nt);
}

/// The distribution record, triple-for-triple.
///
/// This golden is the only cover for several of these triples, so a diff here is not
/// cosmetic. `dcat:mediaType` must stay the IANA `application/json` IRI: ckanext-dcat
/// parses it into the userportal's `res_format` facet, and without it this node's
/// datasets are invisible to that filter.
#[test]
fn distribution_graph_golden_snapshot() {
    let fairdp = fairdp_config();
    let ctx = FdpContext::new(BASE_URL, BEACON_PATH, &fairdp);
    let nt = golden_ntriples(&distribution_graph(&covid_entry(), &ctx));
    insta::assert_snapshot!("distribution_ntriples", nt);
}

#[test]
fn dataset_jsonld_value_objects_are_expanded() {
    let fairdp = fairdp_config();
    let ctx = FdpContext::new(BASE_URL, BEACON_PATH, &fairdp);
    let source_graph = dataset_graph(&covid_entry(), &ctx);
    let jsonld = serialize_jsonld(&source_graph);
    // Re-parse the JSON-LD into a graph; assertions below bind subject+predicate
    // rather than substring-matching the serialized JSON (which is brittle to
    // whitespace changes).
    let graph = parse_jsonld(&jsonld);

    // The dataset subject the assertions below bind to.
    let dataset_iri = format!("{BASE_URL}/fairdp/dataset/{DATASET_ID}");

    // dct:identifier carries the datasetId as a literal bound to the dataset subject.
    assert!(
        literals(&graph, &dataset_iri, &format!("{DCT}identifier"))
            .contains(&DATASET_ID.to_owned()),
        "dct:identifier literal not found on dataset subject in JSON-LD graph"
    );

    // dct:issued is a dateTime literal bound to the dataset subject.
    // DATASET_ID = "GDI-EE-UTARTU-20260409143052837" -> "2026-04-09T14:30:52.837Z"
    assert!(
        literals(&graph, &dataset_iri, &format!("{DCT}issued"))
            .contains(&"2026-04-09T14:30:52.837Z".to_owned()),
        "dct:issued dateTime literal not bound to dataset subject in JSON-LD graph"
    );

    // healthdcatap:numberOfRecords is a nonNegativeInteger literal.
    // The fixture sets number_of_records = 123_456.
    assert!(
        literals(
            &graph,
            &dataset_iri,
            "http://healthdataportal.eu/ns/health#numberOfRecords"
        )
        .contains(&"123456".to_owned()),
        "healthdcatap:numberOfRecords literal not bound to dataset subject in JSON-LD graph"
    );

    // Language-tagged title literals are bound to the dataset subject under dct:title.
    let title_literals = literals(&graph, &dataset_iri, &format!("{DCT}title"));
    assert!(
        title_literals
            .iter()
            .any(|v| v == "GoE Estonia aggregated AFs"),
        "English title not found on dataset subject in JSON-LD graph; got: {title_literals:?}"
    );
    assert!(
        title_literals
            .iter()
            .any(|v| v == "GoE Eesti koondsagedused"),
        "Estonian title not found on dataset subject in JSON-LD graph; got: {title_literals:?}"
    );

    // Guard against parse_jsonld silently swallowing content: the re-parsed graph must
    // carry as many triples as the source.
    assert_eq!(
        source_graph.len(),
        graph.len(),
        "JSON-LD graph has different triple count than source graph (serializer/parser asymmetry)"
    );
}

/// `dct:type` is emitted exactly when `meta.type_` is `Some(iri)`, and is absent
/// when `type_` is `None`. Every fixture in this file sets `type_: None` by default,
/// so the `Some` branch is exercised here explicitly.
#[test]
fn dct_type_emitted_only_when_set() {
    let fairdp = fairdp_config();
    let ctx = FdpContext::new(BASE_URL, BEACON_PATH, &fairdp);
    let dataset_iri = format!("{BASE_URL}/fairdp/dataset/{DATASET_ID}");
    let dct_type_pred = format!("{DCT}type");

    // Case A: type_ = None (the default fixture) — dct:type must be absent.
    let graph_none = dataset_graph(&covid_entry(), &ctx);
    assert!(
        iri_objects(&graph_none, &dataset_iri, &dct_type_pred).is_empty(),
        "dct:type must not be emitted when type_ is None"
    );

    // Case B: type_ = Some(iri) — dct:type must carry exactly that IRI.
    let type_iri = "http://www.w3.org/ns/dcat#Dataset";
    let mut entry = covid_entry();
    entry.metadata.type_ = Some(type_iri.to_owned());
    let graph_some = dataset_graph(&entry, &ctx);
    assert_eq!(
        iri_objects(&graph_some, &dataset_iri, &dct_type_pred),
        vec![type_iri.to_owned()],
        "dct:type must be emitted as the IRI set in type_ when Some"
    );
}

/// One representative dual-encoding round-trip: the Turtle and JSON-LD serializers must
/// emit the same triples for one graph, which catches an oxrdf encode/decode asymmetry.
/// Per-resource graph correctness is covered by the golden N-Triples snapshots and the
/// SHACL conformance suite.
#[test]
fn dataset_jsonld_turtle_isomorphic() {
    let fairdp = fairdp_config();
    let ctx = FdpContext::new(BASE_URL, BEACON_PATH, &fairdp);
    let graph = dataset_graph(&covid_entry(), &ctx);

    let from_ttl = parse_turtle(&serialize_turtle(&graph));
    let from_jsonld = parse_jsonld(&serialize_jsonld(&graph));
    assert_eq!(
        from_ttl, from_jsonld,
        "dataset Turtle and JSON-LD parse to non-isomorphic graphs"
    );
}

#[test]
fn inline_data_service_has_lowercase_endpoint_url_and_title() {
    let fairdp = fairdp_config();
    let ctx = FdpContext::new(BASE_URL, BEACON_PATH, &fairdp);
    let ttl = serialize_turtle(&distribution_graph(&covid_entry(), &ctx));

    let g_variants = format!("{BASE_URL}{BEACON_PATH}/g_variants");

    // The inline DataService is not type-only: it carries the lowercase
    // dcat:endpointURL pointing at g_variants.
    assert!(
        ttl.contains("dcat:endpointURL"),
        "lowercase dcat:endpointURL missing:\n{ttl}"
    );
    // The capital-P FDP v1.2 spelling must not appear on an inline DataService.
    assert!(
        !ttl.contains("endPointURL"),
        "inline DataService must not carry capital-P endPointURL:\n{ttl}"
    );
    // dct:title "GDI Beacon" on the service.
    assert!(
        ttl.contains("GDI Beacon"),
        "DataService title missing:\n{ttl}"
    );
    // Both accessURL and the service endpoint point at g_variants.
    assert!(ttl.contains(&g_variants), "g_variants URL missing:\n{ttl}");
    // servesDataset back to the dataset IRI.
    assert!(ttl.contains(&format!("{BASE_URL}/fairdp/dataset/{DATASET_ID}")));
    // dcat:accessService is present (the inline service link).
    assert!(ttl.contains("dcat:accessService"));
}

#[test]
fn distribution_inherits_dataset_license_and_legislation() {
    let fairdp = fairdp_config();
    let ctx = FdpContext::new(BASE_URL, BEACON_PATH, &fairdp);
    let graph = distribution_graph(&covid_entry(), &ctx);
    let ttl = serialize_turtle(&graph);

    // The covid_entry() fixture shares its license IRI with fairdp_config(), so these
    // assertions prove only that the triples sit on the distribution subject.
    // distribution_license_and_legislation_come_from_dataset_not_config uses distinct
    // values to prove the inheritance itself.
    let dist_iri = format!("{BASE_URL}/fairdp/distribution/{DATASET_ID}");

    // dct:license is bound to the distribution subject.
    assert!(
        iri_objects(&graph, &dist_iri, &format!("{DCT}license"))
            .contains(&"https://creativecommons.org/licenses/by/4.0/".to_owned()),
        "dct:license not bound to distribution subject:\n{ttl}"
    );

    // dcatap:applicableLegislation is bound to the distribution subject.
    assert!(
        iri_objects(&graph, &dist_iri, DCATAP_LEG)
            .contains(&"http://data.europa.eu/eli/reg/2025/327/oj".to_owned()),
        "dcatap:applicableLegislation not bound to distribution subject:\n{ttl}"
    );

    assert!(ttl.contains("a dcat:Distribution") || ttl.contains("rdf:type dcat:Distribution"));
}

/// The HDAB agent must carry `foaf:mbox`, not the vCard alone.
///
/// `ckanext-dcat`'s `_agents_details` reads `foaf:mbox` and `foaf:homepage` on the agent
/// and never descends into the agent's `dcat:contactPoint`, so an HDAB carrying only the
/// vCard harvests with an empty e-mail. The vCard stays, because the gdi-metadata
/// `AgentHdabShape` asks for `dcat:contactPoint`.
///
/// The fixture's HDAB e-mail differs from the publisher's, so reading the wrong agent's
/// address fails here rather than passing by coincidence.
#[test]
fn hdab_agent_carries_foaf_mbox_beside_its_vcard() {
    let fairdp = fairdp_config();
    let ctx = FdpContext::new(BASE_URL, BEACON_PATH, &fairdp);
    let graph = dataset_graph(&covid_entry(), &ctx);
    let dataset_iri = format!("{BASE_URL}/fairdp/dataset/{DATASET_ID}");

    let hdab = blank_object(
        &graph,
        NamedNodeRef::new_unchecked(&dataset_iri),
        HEALTHDCATAP_HDAB,
    );
    assert_eq!(
        iri_objects_of(&graph, hdab, FOAF_MBOX),
        vec!["mailto:hdab@example.org".to_owned()],
        "the HDAB agent must carry its own foaf:mbox: the consumer reads that, not the \
         nested vCard, and it must be the HDAB's address, not the publisher's"
    );

    // The vCard is not replaced: the shape mandates `dcat:contactPoint`, so both stand.
    let vcard = blank_object(&graph, hdab, DCAT_CONTACT_POINT);
    assert_eq!(
        iri_objects_of(&graph, vcard, VCARD_HAS_EMAIL),
        vec!["mailto:hdab@example.org".to_owned()],
        "the vCard contact point must survive alongside foaf:mbox"
    );
}

/// The publisher agent carries `foaf:mbox` even when `[fairdp.publisher].mbox` is unset,
/// derived from its contact point's mandatory `vcard:hasEmail` as the HDAB agent's is. A
/// config with `has_email` and no `mbox` preflights clean, so without this the publisher
/// would reach the root, every catalog and every dataset with no address the harvester
/// can read.
#[test]
fn publisher_agent_carries_foaf_mbox_from_its_contact_point_when_mbox_is_unset() {
    let mut fairdp = fairdp_config();
    fairdp.publisher.mbox = None;
    let ctx = FdpContext::new(BASE_URL, BEACON_PATH, &fairdp);
    let graph = dataset_graph(&covid_entry(), &ctx);
    let dataset_iri = format!("{BASE_URL}/fairdp/dataset/{DATASET_ID}");

    let publisher = blank_object(
        &graph,
        NamedNodeRef::new_unchecked(&dataset_iri),
        DCT_PUBLISHER_IRI,
    );
    assert_eq!(
        iri_objects_of(&graph, publisher, FOAF_MBOX),
        vec![fairdp.publisher.contact_point.has_email.clone()],
        "with no explicit mbox the publisher must still carry one, from its contact point"
    );

    // An explicit `mbox` still wins over the derived one.
    let graph = dataset_graph(
        &covid_entry(),
        &FdpContext::new(BASE_URL, BEACON_PATH, &fairdp_config()),
    );
    let publisher = blank_object(
        &graph,
        NamedNodeRef::new_unchecked(&dataset_iri),
        DCT_PUBLISHER_IRI,
    );
    assert_eq!(
        iri_objects_of(&graph, publisher, FOAF_MBOX),
        vec!["mailto:gdi@example.org".to_owned()]
    );
}

/// A distribution carries `dct:format` beside `dcat:mediaType`.
///
/// `ckanext-dcat`'s `_distribution_format` unwraps an authority IRI only from
/// `dct:format`. From `dcat:mediaType` it takes the string as a media type, fails to find
/// the IANA URL in `resource_formats.json` (whose keys are `application/json`), and leaves
/// the raw URL as the format, which the userportal's `res_format` facet then displays.
/// With the EU file-type IRI on `dct:format` the label resolver renders `JSON`. DCAT-AP 3
/// recommends emitting both.
#[test]
fn distribution_carries_dct_format_beside_dcat_media_type() {
    let fairdp = fairdp_config();
    let ctx = FdpContext::new(BASE_URL, BEACON_PATH, &fairdp);
    let graph = distribution_graph(&covid_entry(), &ctx);
    let dist_iri = format!("{BASE_URL}/fairdp/distribution/{DATASET_ID}");

    assert_eq!(
        iri_objects(&graph, &dist_iri, &format!("{DCT}format")),
        vec!["http://publications.europa.eu/resource/authority/file-type/JSON".to_owned()],
        "the distribution must carry the EU file-type IRI on dct:format"
    );
    assert_eq!(
        iri_objects(&graph, &dist_iri, &format!("{DCAT}mediaType")),
        vec!["https://www.iana.org/assignments/media-types/application/json".to_owned()],
        "dcat:mediaType must stay the IANA media-type IRI (the res_format facet reads it)"
    );
}

// --- FDP-root and Catalog records, LDP navigation ---

const DATASET_ID_2: &str = "GDI-EE-UTARTU-20260512090000000";
const CATALOG_ID: &str = "gdi-aggregated";
const CATALOG_TITLE: &str = "GoE aggregated catalog";

/// A second visible dataset (a later timestamp than [`covid_entry`]) so the
/// catalog/root `metadataModified` derivation has a clear latest.
fn second_entry() -> DatasetEntry {
    let mut entry = covid_entry();
    DATASET_ID_2.clone_into(&mut entry.id);
    DATASET_ID_2.clone_into(&mut entry.metadata.dataset_id);
    entry
}

/// Count how many of the graph's triples have `subject predicate <object-iri>`
/// for an IRI object — used to assert membership-predicate cardinality.
fn count_iri_objects(graph: &Graph, subject: &str, predicate: &str) -> usize {
    let subj = NamedOrBlankNodeRef::NamedNode(NamedNodeRef::new_unchecked(subject));
    let pred = NamedNodeRef::new_unchecked(predicate);
    graph
        .triples_for_subject(subj)
        .filter(|t| t.predicate == pred && matches!(t.object, TermRef::NamedNode(_)))
        .count()
}

/// Collect the IRI objects of `subject predicate ?o` as a sorted Vec.
fn iri_objects(graph: &Graph, subject: &str, predicate: &str) -> Vec<String> {
    let subj = NamedOrBlankNodeRef::NamedNode(NamedNodeRef::new_unchecked(subject));
    let pred = NamedNodeRef::new_unchecked(predicate);
    let mut out: Vec<String> = graph
        .triples_for_subject(subj)
        .filter(|t| t.predicate == pred)
        .filter_map(|t| match t.object {
            TermRef::NamedNode(n) => Some(n.as_str().to_owned()),
            _ => None,
        })
        .collect();
    out.sort();
    out
}

/// The blank-node object of `subject predicate ?b`, as a subject reference so the node's
/// own properties can be read. Panics when there is none — the caller is asserting the
/// nested node exists.
fn blank_object<'g>(
    graph: &'g Graph,
    subject: impl Into<NamedOrBlankNodeRef<'g>>,
    predicate: &str,
) -> NamedOrBlankNodeRef<'g> {
    let subj: NamedOrBlankNodeRef<'g> = subject.into();
    let pred = NamedNodeRef::new_unchecked(predicate);
    graph
        .triples_for_subject(subj)
        .filter(|t| t.predicate == pred)
        .find_map(|t| match t.object {
            TermRef::BlankNode(b) => Some(NamedOrBlankNodeRef::BlankNode(b)),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no blank-node object for <{subj}> <{predicate}>"))
}

/// [`iri_objects`] for any subject — an IRI or a blank node reached via [`blank_object`].
fn iri_objects_of<'g>(
    graph: &'g Graph,
    subject: impl Into<NamedOrBlankNodeRef<'g>>,
    predicate: &str,
) -> Vec<String> {
    let pred = NamedNodeRef::new_unchecked(predicate);
    let mut out: Vec<String> = graph
        .triples_for_subject(subject)
        .filter(|t| t.predicate == pred)
        .filter_map(|t| match t.object {
            TermRef::NamedNode(n) => Some(n.as_str().to_owned()),
            _ => None,
        })
        .collect();
    out.sort();
    out
}

/// Collect the literal (string) values of `subject predicate ?o` as a sorted Vec.
///
/// Returns the raw lexical value (no datatype or language tag). Useful for
/// asserting that a specific predicate carries the expected literal on a known
/// subject, rather than substring-searching the whole serialization.
fn literals(graph: &Graph, subject: &str, predicate: &str) -> Vec<String> {
    let subj = NamedOrBlankNodeRef::NamedNode(NamedNodeRef::new_unchecked(subject));
    let pred = NamedNodeRef::new_unchecked(predicate);
    let mut out: Vec<String> = graph
        .triples_for_subject(subj)
        .filter(|t| t.predicate == pred)
        .filter_map(|t| match t.object {
            TermRef::Literal(l) => Some(l.value().to_owned()),
            _ => None,
        })
        .collect();
    out.sort();
    out
}

/// Like [`literals`], but keeps the datatype IRI alongside the lexical value.
///
/// [`literals`] discards the datatype, so assertions built on it cannot see an ill-typed
/// literal: a `dct:modified` can carry a canonical `2027-01-01T00:00:00Z` and still be
/// stamped `xsd:string`, which SHACL rejects.
fn typed_literals(graph: &Graph, subject: &str, predicate: &str) -> Vec<(String, String)> {
    let subj = NamedOrBlankNodeRef::NamedNode(NamedNodeRef::new_unchecked(subject));
    let pred = NamedNodeRef::new_unchecked(predicate);
    let mut out: Vec<(String, String)> = graph
        .triples_for_subject(subj)
        .filter(|t| t.predicate == pred)
        .filter_map(|t| match t.object {
            TermRef::Literal(l) => Some((l.value().to_owned(), l.datatype().as_str().to_owned())),
            _ => None,
        })
        .collect();
    out.sort();
    out
}

const XSD_DATE_TIME: &str = "http://www.w3.org/2001/XMLSchema#dateTime";
const FDP_O: &str = "https://w3id.org/fdp/fdp-o#";
const DCT: &str = "http://purl.org/dc/terms/";
const DCAT: &str = "http://www.w3.org/ns/dcat#";
const LDP_CONTAINS: &str = "http://www.w3.org/ns/ldp#contains";
const DCATAP_LEG: &str = "http://data.europa.eu/r5r/applicableLegislation";
const HEALTHDCATAP_HDAB: &str = "http://healthdataportal.eu/ns/health#hdab";
const FOAF_MBOX: &str = "http://xmlns.com/foaf/0.1/mbox";
const DCT_PUBLISHER_IRI: &str = "http://purl.org/dc/terms/publisher";
const DCAT_CONTACT_POINT: &str = "http://www.w3.org/ns/dcat#contactPoint";
const VCARD_HAS_EMAIL: &str = "http://www.w3.org/2006/vcard/ns#hasEmail";

#[test]
fn catalog_three_membership_predicates_cover_every_visible_dataset() {
    let fairdp = fairdp_config();
    let ctx = FdpContext::new(BASE_URL, BEACON_PATH, &fairdp);
    let e1 = covid_entry();
    let e2 = second_entry();
    let visible = [&e1, &e2];
    let graph = catalog_graph(CATALOG_ID, CATALOG_TITLE, &visible, &ctx);

    let catalog_iri = format!("{BASE_URL}/fairdp/catalog/{CATALOG_ID}");
    let want: Vec<String> = vec![
        format!("{BASE_URL}/fairdp/dataset/{DATASET_ID}"),
        format!("{BASE_URL}/fairdp/dataset/{DATASET_ID_2}"),
    ];
    let mut want_sorted = want.clone();
    want_sorted.sort();

    // Every visible dataset appears under all three membership predicates, never a subset.
    for pred in [
        format!("{DCT}hasPart"),
        format!("{DCAT}dataset"),
        LDP_CONTAINS.to_owned(),
    ] {
        assert_eq!(
            iri_objects(&graph, &catalog_iri, &pred),
            want_sorted,
            "predicate {pred} does not cover exactly the visible datasets"
        );
    }

    // Mandatory Catalog props present (cardinality 1 each unless noted).
    let ttl = serialize_turtle(&graph);
    assert!(ttl.contains("a dcat:Catalog") || ttl.contains("rdf:type dcat:Catalog"));
    assert_eq!(
        count_iri_objects(&graph, &catalog_iri, &format!("{FDP_O}conformsToFdpSpec")),
        1
    );
    assert!(ttl.contains("https://specs.fairdatapoint.org/v1.2/fdp-specs-v1.2.html"));
    // conformsTo -> the opaque catalog profile marker IRI.
    assert!(ttl.contains(&format!("{BASE_URL}/fairdp/profile/catalog")));
    // metadataIdentifier -> the catalog's own IRI.
    assert_eq!(
        iri_objects(&graph, &catalog_iri, &format!("{FDP_O}metadataIdentifier")),
        vec![catalog_iri.clone()]
    );
    // isPartOf -> the root.
    assert_eq!(
        iri_objects(&graph, &catalog_iri, &format!("{DCT}isPartOf")),
        vec![format!("{BASE_URL}/fairdp")]
    );
    // themeTaxonomy derived from [fairdp].theme (the data-theme scheme, concept
    // minus its final segment).
    assert_eq!(
        iri_objects(&graph, &catalog_iri, &format!("{DCAT}themeTaxonomy")),
        vec!["http://publications.europa.eu/resource/authority/data-theme".to_owned()]
    );
    // CatalogShape-mandated node-level applicableLegislation, title, description.
    assert_eq!(count_iri_objects(&graph, &catalog_iri, DCATAP_LEG), 1);
    assert!(ttl.contains("dct:title") && ttl.contains("dct:description"));
    // publisher + license present.
    assert!(ttl.contains("dct:publisher") && ttl.contains("dct:license"));
}

#[test]
fn empty_catalog_is_valid_with_no_membership_triples() {
    let fairdp = fairdp_config();
    let ctx = FdpContext::new(BASE_URL, BEACON_PATH, &fairdp);
    let graph = catalog_graph(CATALOG_ID, CATALOG_TITLE, &[], &ctx);

    let catalog_iri = format!("{BASE_URL}/fairdp/catalog/{CATALOG_ID}");

    // Stable URI + mandatory props still present.
    let ttl = serialize_turtle(&graph);
    assert!(ttl.contains("a dcat:Catalog") || ttl.contains("rdf:type dcat:Catalog"));
    assert_eq!(
        count_iri_objects(&graph, &catalog_iri, &format!("{FDP_O}conformsToFdpSpec")),
        1
    );
    assert_eq!(
        count_iri_objects(&graph, &catalog_iri, &format!("{FDP_O}metadataIdentifier")),
        1
    );
    assert_eq!(count_iri_objects(&graph, &catalog_iri, DCATAP_LEG), 1);
    assert!(ttl.contains("dct:title") && ttl.contains("dct:description"));

    // Zero membership triples of any of the three predicates.
    for pred in [
        format!("{DCT}hasPart"),
        format!("{DCAT}dataset"),
        LDP_CONTAINS.to_owned(),
    ] {
        assert_eq!(
            count_iri_objects(&graph, &catalog_iri, &pred),
            0,
            "empty catalog must carry zero {pred} triples"
        );
    }
}

#[test]
fn root_lists_all_configured_catalogs_including_empty() {
    let fairdp = fairdp_config();
    let ctx = FdpContext::new(BASE_URL, BEACON_PATH, &fairdp);
    let e1 = covid_entry();
    let catalogs = vec![
        CatalogListing {
            id: "gdi-aggregated",
            title: "GoE aggregated catalog",
            visible_datasets: vec![&e1],
        },
        CatalogListing {
            id: "empty-cat",
            title: "Empty catalog",
            visible_datasets: vec![],
        },
    ];
    let graph = fdp_root_graph(&catalogs, &ctx);
    let root_iri = format!("{BASE_URL}/fairdp");

    let want_catalogs: Vec<String> = vec![
        format!("{BASE_URL}/fairdp/catalog/empty-cat"),
        format!("{BASE_URL}/fairdp/catalog/gdi-aggregated"),
    ];

    // Every configured catalog, including the empty one, under both ldp:contains and
    // fdp-o:metadataCatalog.
    assert_eq!(
        iri_objects(&graph, &root_iri, LDP_CONTAINS),
        want_catalogs,
        "ldp:contains must list every configured catalog"
    );
    assert_eq!(
        iri_objects(&graph, &root_iri, &format!("{FDP_O}metadataCatalog")),
        want_catalogs,
        "fdp-o:metadataCatalog must list every configured catalog"
    );

    // The canonical lowercase-`p` `dcat:endpointURL`, and only that spelling: the
    // `dcat:` namespace defines no capital-P `endPointURL`.
    assert_eq!(
        iri_objects(&graph, &root_iri, &format!("{DCAT}endpointURL")),
        vec![root_iri.clone()],
        "lowercase dcat:endpointURL missing"
    );
    assert!(
        iri_objects(&graph, &root_iri, &format!("{DCAT}endPointURL")).is_empty(),
        "the root must not carry the non-standard capital-P dcat:endPointURL"
    );

    // All three rdf:type values on the root.
    let types = iri_objects(
        &graph,
        &root_iri,
        "http://www.w3.org/1999/02/22-rdf-syntax-ns#type",
    );
    assert!(types.contains(&format!("{FDP_O}FAIRDataPoint")));
    assert!(types.contains(&format!("{FDP_O}MetadataService")));
    assert!(types.contains(&format!("{DCAT}DataService")));

    // The opaque service profile marker + the spec marker.
    let ttl = serialize_turtle(&graph);
    assert!(ttl.contains(&format!("{BASE_URL}/fairdp/profile/service")));
    assert!(ttl.contains("https://specs.fairdatapoint.org/v1.2/fdp-specs-v1.2.html"));
    // Optional description + the contact point (required publisher config).
    assert!(ttl.contains("dct:description"));
    assert!(ttl.contains("dcat:contactPoint"));
}

/// `[fairdp].language` is emitted as `dct:language` on the FDP root, on every catalog and
/// on every dataset. The userportal's DCAT profile reads it into the dataset's `language`
/// field. It is one node-level value; there is no per-dataset override.
///
/// All three subjects are asserted from one configured value: emitting it on the root
/// alone leaves the portal's dataset records with an empty `language`.
#[test]
fn configured_language_is_emitted_on_the_root_every_catalog_and_every_dataset() {
    let fairdp = fairdp_config();
    let ctx = FdpContext::new(BASE_URL, BEACON_PATH, &fairdp);
    let entry = covid_entry();
    let catalogs = vec![CatalogListing {
        id: CATALOG_ID,
        title: "GoE aggregated catalog",
        visible_datasets: vec![&entry],
    }];

    // The expected IRI is spelled out, not read back off the config the emitter was
    // given: an assertion whose subject is derived from the same value cannot fail when
    // that value is empty or wrong.
    let want = vec![LANGUAGE.to_owned()];
    assert_eq!(
        iri_objects(
            &fdp_root_graph(&catalogs, &ctx),
            &format!("{BASE_URL}/fairdp"),
            &format!("{DCT}language")
        ),
        want,
        "the FDP root must carry dct:language"
    );
    assert_eq!(
        iri_objects(
            &catalog_graph(CATALOG_ID, "GoE aggregated catalog", &[&entry], &ctx),
            &format!("{BASE_URL}/fairdp/catalog/{CATALOG_ID}"),
            &format!("{DCT}language")
        ),
        want,
        "every catalog must carry dct:language"
    );
    assert_eq!(
        iri_objects(
            &dataset_graph(&entry, &ctx),
            &format!("{BASE_URL}/fairdp/dataset/{DATASET_ID}"),
            &format!("{DCT}language")
        ),
        want,
        "every dataset must carry dct:language, the field the portal shows"
    );
}

#[test]
fn metadata_modified_is_data_derived_and_restart_stable() {
    let fairdp = fairdp_config();
    let ctx = FdpContext::new(BASE_URL, BEACON_PATH, &fairdp);
    let e1 = covid_entry();
    let e2 = second_entry();
    let visible = [&e1, &e2];

    let modified_pred = format!("{FDP_O}metadataModified");
    let modified = |graph: &Graph, subject: &str| -> String {
        let subj = NamedOrBlankNodeRef::NamedNode(NamedNodeRef::new_unchecked(subject));
        let pred = NamedNodeRef::new_unchecked(&modified_pred);
        graph
            .triples_for_subject(subj)
            .filter(|t| t.predicate == pred)
            .find_map(|t| match t.object {
                TermRef::Literal(l) => Some(l.value().to_owned()),
                _ => None,
            })
            .expect("metadataModified literal present")
    };

    let catalog_iri = format!("{BASE_URL}/fairdp/catalog/{CATALOG_ID}");

    // Rendering twice yields the same value (no wall-clock).
    let g1 = catalog_graph(CATALOG_ID, CATALOG_TITLE, &visible, &ctx);
    let g2 = catalog_graph(CATALOG_ID, CATALOG_TITLE, &visible, &ctx);
    let m1 = modified(&g1, &catalog_iri);
    let m2 = modified(&g2, &catalog_iri);
    assert_eq!(m1, m2, "metadataModified must be restart-stable");

    // It is the latest visible dataset's change time (the second, later id), derived
    // from its 17-digit timestamp, not the wall clock and not [fairdp].issued.
    assert_eq!(m1, "2026-05-12T09:00:00.000Z");

    // An empty catalog falls back to [fairdp].issued.
    let empty = catalog_graph(CATALOG_ID, CATALOG_TITLE, &[], &ctx);
    assert_eq!(modified(&empty, &catalog_iri), fairdp.issued);

    // The root derives the latest across every catalog's datasets, restart-stable.
    let catalogs = vec![CatalogListing {
        id: CATALOG_ID,
        title: CATALOG_TITLE,
        visible_datasets: vec![&e1, &e2],
    }];
    let r1 = fdp_root_graph(&catalogs, &ctx);
    let r2 = fdp_root_graph(&catalogs, &ctx);
    let root_iri = format!("{BASE_URL}/fairdp");
    assert_eq!(modified(&r1, &root_iri), modified(&r2, &root_iri));
    assert_eq!(modified(&r1, &root_iri), "2026-05-12T09:00:00.000Z");

    // An entirely-empty root falls back to [fairdp].issued.
    let empty_root = fdp_root_graph(&[], &ctx);
    assert_eq!(modified(&empty_root, &root_iri), fairdp.issued);
}

/// `metadataModified` must be the chronological max, not the lexical max.
///
/// A foreign-id dataset falls back to `[fairdp].issued`; written with a `+03:00` offset
/// (`11:00+03:00` = `08:00Z`) it sorts lexically later than a canonical-id dataset's
/// `09:00Z` change time but is chronologically earlier. The catalog's latest change must
/// be the dataset's `09:00Z`.
#[test]
fn metadata_modified_uses_chronological_not_lexical_max() {
    let mut fairdp = fairdp_config();
    fairdp.issued = "2026-05-12T11:00:00+03:00".to_owned(); // == 08:00:00Z
    let ctx = FdpContext::new(BASE_URL, BEACON_PATH, &fairdp);

    let dated = second_entry(); // canonical id → 2026-05-12T09:00:00.000Z
    let mut foreign = covid_entry();
    foreign.id = "GDI-FI-THL-1".to_owned(); // no timestamp tail → falls back to issued
    foreign.metadata_modified = None;
    let visible = [&dated, &foreign];

    let modified_pred = format!("{FDP_O}metadataModified");
    let catalog_iri = format!("{BASE_URL}/fairdp/catalog/{CATALOG_ID}");
    let g = catalog_graph(CATALOG_ID, CATALOG_TITLE, &visible, &ctx);
    let subj = NamedOrBlankNodeRef::NamedNode(NamedNodeRef::new_unchecked(&catalog_iri));
    let pred = NamedNodeRef::new_unchecked(&modified_pred);
    let value = g
        .triples_for_subject(subj)
        .filter(|t| t.predicate == pred)
        .find_map(|t| match t.object {
            TermRef::Literal(l) => Some(l.value().to_owned()),
            _ => None,
        })
        .expect("metadataModified literal present");
    assert_eq!(
        value, "2026-05-12T09:00:00.000Z",
        "chronological max must pick the later dataset value, not the lexically-larger offset issued"
    );
}

/// A malformed operator-supplied `metadata_modified` must not reach the RDF.
///
/// The override comes from the operator-writable overlay file's `applied_at`, unlike
/// `dataset_modified`'s other two sources, which are validated. One malformed typed
/// literal fails SHACL for the whole record at the harvester, not just that field, so a
/// hand-edited overlay would drop the dataset out of the harvest entirely.
#[test]
fn a_malformed_metadata_modified_override_falls_back_instead_of_emitting_garbage() {
    let fairdp = fairdp_config();
    let ctx = FdpContext::new(BASE_URL, BEACON_PATH, &fairdp);

    let mut entry = covid_entry();
    entry.metadata_modified = Some("not-a-datetime".to_owned());
    let g = dataset_graph(&entry, &ctx);

    let dataset_iri = format!("{BASE_URL}/fairdp/dataset/{DATASET_ID}");
    let emitted = literals(&g, &dataset_iri, &format!("{DCT}modified"));
    assert!(
        !emitted.iter().any(|v| v == "not-a-datetime"),
        "a malformed override must never be emitted as an xsd:dateTime: {emitted:?}"
    );
    // It falls back to the id-derived instant, which is well-formed.
    assert!(
        emitted
            .iter()
            .any(|v| gdi_node_standalone_core::datetime::rfc3339_instant_nanos(v).is_some()),
        "the emitted dct:modified must parse as an instant: {emitted:?}"
    );
}

/// A lenient but parseable override is canonicalized, not discarded.
///
/// `time`'s RFC-3339 parser accepts a space separator and a lowercase `t`/`z`. Those do
/// parse, so a validity filter alone passes them through, yet they sit outside the
/// `xsd:dateTime` lexical space and must not be stamped verbatim as a typed literal.
#[test]
fn a_lenient_metadata_modified_override_is_canonicalized_not_discarded() {
    // Both lenient spellings below denote the same instant, so the canonical output is
    // known exactly. Asserting that exact value is what separates canonicalization from a
    // renderer that rejects the override and falls back to the id-derived instant, which
    // is well-formed too. The instant lies outside the fixture's year, so the fallback
    // cannot produce it.
    const CANONICAL: &str = "2027-01-01T00:00:00Z";

    let fairdp = fairdp_config();
    let ctx = FdpContext::new(BASE_URL, BEACON_PATH, &fairdp);
    let dataset_iri = format!("{BASE_URL}/fairdp/dataset/{DATASET_ID}");

    for lenient in ["2027-01-01 00:00:00Z", "2027-01-01t00:00:00z"] {
        let mut entry = covid_entry();
        entry.metadata_modified = Some(lenient.to_owned());
        let g = dataset_graph(&entry, &ctx);
        let emitted = literals(&g, &dataset_iri, &format!("{DCT}modified"));
        assert!(
            emitted.iter().any(|v| v == CANONICAL),
            "{lenient:?} must be rewritten to {CANONICAL:?}, not emitted verbatim and not \
             dropped in favour of the id-derived fallback: {emitted:?}"
        );
        // It must also be typed: comparing lexical form alone cannot see a canonical
        // value stamped `xsd:string`, which SHACL rejects just as hard as a malformed one.
        let typed = typed_literals(&g, &dataset_iri, &format!("{DCT}modified"));
        assert!(
            typed
                .iter()
                .any(|(v, dt)| v == CANONICAL && dt == XSD_DATE_TIME),
            "the canonicalized value must be stamped ^^xsd:dateTime, not left untyped: \
             {typed:?}"
        );
    }

    // The blast radius: this value also propagates to every catalog, and from there to
    // the FDP root, as the max `fdp-o:metadataModified`, so one hand-edited overlay can
    // take the whole node out of a conforming harvest.
    let mut entry = covid_entry();
    entry.metadata_modified = Some("2027-01-01 00:00:00Z".to_owned());
    let visible = [&entry];
    let catalog = catalog_graph(CATALOG_ID, CATALOG_TITLE, &visible, &ctx);
    let catalog_iri = format!("{BASE_URL}/fairdp/catalog/{CATALOG_ID}");
    let aggregated = literals(&catalog, &catalog_iri, &format!("{FDP_O}metadataModified"));
    assert!(
        aggregated.iter().any(|v| v == CANONICAL),
        "the catalog aggregate must carry the canonicalized dataset value {CANONICAL:?}; \
         a lenient form reaching here is what breaks the harvest for the whole node: \
         {aggregated:?}"
    );
}

/// `fdp-o:metadataModified` must never precede `[fairdp].issued`.
///
/// The aggregate is the chronological max over the contained datasets, and a dataset's
/// own change time can predate the catalog's issue date, which would leave the record
/// claiming it was modified before it was issued.
#[test]
fn metadata_modified_is_floored_at_issued() {
    let mut fairdp = fairdp_config();
    // Issued after any dataset's derived time (the covid fixture's id tail is 2026-04-09).
    fairdp.issued = "2027-01-01T00:00:00Z".to_owned();
    let ctx = FdpContext::new(BASE_URL, BEACON_PATH, &fairdp);

    let entry = covid_entry();
    let visible = [&entry];
    let g = catalog_graph(CATALOG_ID, CATALOG_TITLE, &visible, &ctx);

    let catalog_iri = format!("{BASE_URL}/fairdp/catalog/{CATALOG_ID}");
    let subj = NamedOrBlankNodeRef::NamedNode(NamedNodeRef::new_unchecked(&catalog_iri));
    let modified_pred = format!("{FDP_O}metadataModified");
    let pred = NamedNodeRef::new_unchecked(&modified_pred);
    let value = g
        .triples_for_subject(subj)
        .filter(|t| t.predicate == pred)
        .find_map(|t| match t.object {
            TermRef::Literal(l) => Some(l.value().to_owned()),
            _ => None,
        })
        .expect("metadataModified literal present");

    let modified = gdi_node_standalone_core::datetime::rfc3339_instant_nanos(&value)
        .expect("emitted value parses");
    let issued = gdi_node_standalone_core::datetime::rfc3339_instant_nanos(&fairdp.issued)
        .expect("issued parses");
    assert!(
        modified >= issued,
        "a record cannot have been modified ({value}) before it was issued ({})",
        fairdp.issued
    );
}

/// The distribution's `dct:license` and `dcatap:applicableLegislation` are inherited from
/// the dataset, not read from node config.
///
/// `distribution_inherits_dataset_license_and_legislation` uses a fixture whose dataset
/// license equals the config license, so it cannot catch a source swap in the builder
/// (`&entry.metadata.license` -> `&ctx.fairdp.license`). This one uses distinct values.
#[test]
fn distribution_license_and_legislation_come_from_dataset_not_config() {
    const DATASET_LICENSE: &str = "https://creativecommons.org/publicdomain/zero/1.0/"; // CC0
    const DATASET_LEGISLATION: &str = "http://data.europa.eu/eli/reg/2016/679/oj"; // GDPR
    let fairdp = fairdp_config(); // config license = CC-BY-4.0; legislation = 2025/327
    let ctx = FdpContext::new(BASE_URL, BEACON_PATH, &fairdp);
    let mut entry = covid_entry();
    entry.metadata.license = DATASET_LICENSE.to_owned();
    entry.metadata.applicable_legislation = vec![DATASET_LEGISLATION.to_owned()];

    let graph = distribution_graph(&entry, &ctx);
    let dist_iri = format!("{BASE_URL}/fairdp/distribution/{DATASET_ID}");

    let licenses = iri_objects(&graph, &dist_iri, &format!("{DCT}license"));
    assert_eq!(
        licenses,
        vec![DATASET_LICENSE.to_owned()],
        "distribution dct:license must be the dataset license (CC0), not the config license"
    );
    assert!(
        !licenses.contains(&fairdp.license),
        "distribution must not carry the config license"
    );

    let legislation = iri_objects(&graph, &dist_iri, DCATAP_LEG);
    assert_eq!(
        legislation,
        vec![DATASET_LEGISLATION.to_owned()],
        "distribution applicableLegislation must be the dataset value (GDPR), not config"
    );
    assert!(
        !legislation
            .iter()
            .any(|l| fairdp.applicable_legislation.contains(l)),
        "distribution must not carry the config applicableLegislation"
    );
}

/// A foreign id (no 17-digit timestamp tail) with no `metadata_modified` override emits
/// both `dct:issued` and `dct:modified` as `[fairdp].issued`. This is the
/// `dataset_datetime(id).unwrap_or_else(issued)` fallback on the dataset record, which
/// `catalog_graph` alone does not exercise.
#[test]
fn dataset_graph_foreign_id_issued_and_modified_fall_back_to_config_issued() {
    let fairdp = fairdp_config(); // issued = "2026-01-01T00:00:00Z"
    let ctx = FdpContext::new(BASE_URL, BEACON_PATH, &fairdp);
    let mut entry = covid_entry();
    "GDI-FI-THL-1".clone_into(&mut entry.id);
    "GDI-FI-THL-1".clone_into(&mut entry.metadata.dataset_id);
    entry.metadata_modified = None;

    let graph = dataset_graph(&entry, &ctx);
    let dataset_iri = format!("{BASE_URL}/fairdp/dataset/GDI-FI-THL-1");
    assert_eq!(
        literals(&graph, &dataset_iri, &format!("{DCT}issued")),
        vec![fairdp.issued.clone()],
        "foreign-id dct:issued must fall back to [fairdp].issued"
    );
    assert_eq!(
        literals(&graph, &dataset_iri, &format!("{DCT}modified")),
        vec![fairdp.issued.clone()],
        "foreign-id dct:modified must fall back to [fairdp].issued"
    );
}

/// A visible dataset's `metadata_modified` override participates in the catalog and root
/// chronological-max aggregate.
#[test]
fn catalog_and_root_metadata_modified_include_a_dataset_override_in_the_max() {
    let fairdp = fairdp_config();
    let ctx = FdpContext::new(BASE_URL, BEACON_PATH, &fairdp);
    let base = second_entry(); // id-derived 2026-05-12T09:00:00.000Z
    let mut overridden = covid_entry(); // id-derived 2026-04-09T…
    let later = "2027-01-01T00:00:00Z".to_owned();
    overridden.metadata_modified = Some(later.clone());
    let visible = [&base, &overridden];
    let modified_pred = format!("{FDP_O}metadataModified");

    let catalog = catalog_graph(CATALOG_ID, CATALOG_TITLE, &visible, &ctx);
    let cat_iri = format!("{BASE_URL}/fairdp/catalog/{CATALOG_ID}");
    assert_eq!(
        literals(&catalog, &cat_iri, &modified_pred),
        vec![later.clone()],
        "catalog metadataModified must include the dataset override in its max"
    );

    let catalogs = vec![CatalogListing {
        id: CATALOG_ID,
        title: CATALOG_TITLE,
        visible_datasets: vec![&base, &overridden],
    }];
    let root = fdp_root_graph(&catalogs, &ctx);
    let root_iri = format!("{BASE_URL}/fairdp");
    assert_eq!(
        literals(&root, &root_iri, &modified_pred),
        vec![later],
        "root metadataModified must include the dataset override in its max"
    );
}

/// An earlier override must not win over a later-modified sibling: the aggregate is a
/// true chronological max.
#[test]
fn catalog_metadata_modified_prefers_a_later_sibling_over_an_earlier_override() {
    let fairdp = fairdp_config();
    let ctx = FdpContext::new(BASE_URL, BEACON_PATH, &fairdp);
    let sibling = second_entry(); // 2026-05-12T09:00:00.000Z
    let mut earlier = covid_entry();
    earlier.metadata_modified = Some("2020-01-01T00:00:00.000Z".to_owned());
    let visible = [&sibling, &earlier];
    let cat = catalog_graph(CATALOG_ID, CATALOG_TITLE, &visible, &ctx);
    let cat_iri = format!("{BASE_URL}/fairdp/catalog/{CATALOG_ID}");
    assert_eq!(
        literals(&cat, &cat_iri, &format!("{FDP_O}metadataModified")),
        vec!["2026-05-12T09:00:00.000Z".to_owned()],
        "an earlier override must not win over a later sibling's id-derived time"
    );
}

/// The serializer trust boundary for literal values: the Turtle serializer escapes them,
/// so a hostile string cannot inject triples. This test locks that half, plus re-parse
/// integrity.
///
/// Language tags are the other half. The render layer validates no tag; core's ingest
/// gate is the sole validator. It does normalise the tag through
/// `validate_pkg::canonical_bcp47`, because validity at ingest does not give canonical
/// form. See [`language_tags_are_emitted_in_canonical_lowercase_form`].
#[test]
fn serializer_escapes_hostile_literal_values_without_injecting_triples() {
    let mut title = BTreeMap::new();
    // A value packed with Turtle metacharacters that would inject a triple if emitted raw.
    title.insert(
        "en".to_owned(),
        "evil \" .\n<http://x/s> <http://x/p> \"pwned".to_owned(),
    );
    let fairdp = fairdp_config();
    let ctx = FdpContext::new(BASE_URL, BEACON_PATH, &fairdp);
    let mut entry = covid_entry();
    entry.metadata.title = LocalizedText::Map(title);

    let graph = dataset_graph(&entry, &ctx);
    let ttl = serialize_turtle(&graph);
    let reparsed = parse_turtle(&ttl);
    assert_eq!(
        reparsed.len(),
        graph.len(),
        "escaped serialization must not gain or lose triples on re-parse (no injection):\n{ttl}"
    );
    let dataset_iri = format!("{BASE_URL}/fairdp/dataset/{DATASET_ID}");
    assert!(
        literals(&reparsed, &dataset_iri, &format!("{DCT}title"))
            .iter()
            .any(|t| t.contains("pwned")),
        "the hostile value must round-trip as a single escaped literal:\n{ttl}"
    );
}

/// The HTTP layer renders an empty serialization as a 500, so a non-empty graph must
/// never serialize empty. Asserted for both formats, with a round-trip re-parse.
#[test]
fn serialize_of_a_nonempty_graph_is_nonempty_and_reparses() {
    let fairdp = fairdp_config();
    let ctx = FdpContext::new(BASE_URL, BEACON_PATH, &fairdp);
    let graph = dataset_graph(&covid_entry(), &ctx);
    assert!(
        !graph.is_empty(),
        "precondition: the dataset graph is non-empty"
    );

    let ttl = serialize_turtle(&graph);
    assert!(
        !ttl.is_empty(),
        "Turtle of a non-empty graph must not be empty"
    );
    assert!(
        !parse_turtle(&ttl).is_empty(),
        "serialized Turtle must re-parse to triples"
    );

    let jsonld = serialize_jsonld(&graph);
    assert!(
        !jsonld.is_empty(),
        "JSON-LD of a non-empty graph must not be empty"
    );
    assert!(
        !parse_jsonld(&jsonld).is_empty(),
        "serialized JSON-LD must re-parse to triples"
    );
}

/// Golden N-Triples snapshot of the FDP-root graph. It pins every emitted predicate and
/// value, so a change to the root's predicate set trips this snapshot, which is the cue
/// to check whether `conformance/shapes/fdp/fdp-root.ttl` needs the matching update (see
/// `conformance/shapes/fdp/PROVENANCE.md`).
#[test]
fn root_graph_golden_snapshot() {
    let fairdp = fairdp_config();
    let ctx = FdpContext::new(BASE_URL, BEACON_PATH, &fairdp);
    let e1 = covid_entry();
    let catalogs = vec![
        CatalogListing {
            id: "gdi-aggregated",
            title: "GoE aggregated catalog",
            visible_datasets: vec![&e1],
        },
        CatalogListing {
            id: "empty-cat",
            title: "Empty catalog",
            visible_datasets: vec![],
        },
    ];
    let nt = golden_ntriples(&fdp_root_graph(&catalogs, &ctx));
    insta::assert_snapshot!("root_ntriples", nt);
}

/// Golden N-Triples snapshot of the Catalog graph. As with the root snapshot, it pins
/// every emitted predicate and value, so a change to the catalog's predicate set trips it,
/// the cue to check whether `conformance/shapes/fdp/fdp-catalog.ttl` needs the matching
/// update (see `conformance/shapes/fdp/PROVENANCE.md`).
#[test]
fn catalog_graph_golden_snapshot() {
    let fairdp = fairdp_config();
    let ctx = FdpContext::new(BASE_URL, BEACON_PATH, &fairdp);
    let e1 = covid_entry();
    let e2 = second_entry();
    let visible = [&e1, &e2];
    let nt = golden_ntriples(&catalog_graph(CATALOG_ID, CATALOG_TITLE, &visible, &ctx));
    insta::assert_snapshot!("catalog_ntriples", nt);
}

#[test]
fn dataset_issued_and_modified_bind_to_the_right_predicates() {
    let fairdp = fairdp_config();
    let ctx = FdpContext::new(BASE_URL, BEACON_PATH, &fairdp);
    let mut entry = covid_entry(); // a Visible DatasetEntry
    entry.metadata_modified = Some("2026-06-18T09:30:00.000Z".to_owned());

    // Extract the literal object of `<dataset> <predicate> ?o`. Binding each datetime to
    // its predicate catches an issued/modified swap that a plain `ttl.contains(...)`
    // substring check, with both literals present, would miss.
    let dataset_iri = format!("{BASE_URL}/fairdp/dataset/{DATASET_ID}");
    let literal = |graph: &Graph, predicate: &str| -> Option<String> {
        let subj = NamedOrBlankNodeRef::NamedNode(NamedNodeRef::new_unchecked(&dataset_iri));
        let pred = NamedNodeRef::new_unchecked(predicate);
        graph
            .triples_for_subject(subj)
            .filter(|t| t.predicate == pred)
            .find_map(|t| match t.object {
                TermRef::Literal(l) => Some(l.value().to_owned()),
                _ => None,
            })
    };

    let graph = dataset_graph(&entry, &ctx);
    // dct:modified takes the override; dct:issued stays the id-derived creation time.
    // DATASET_ID = "GDI-EE-UTARTU-20260409143052837" -> "2026-04-09T14:30:52.837Z".
    // The override is canonicalized through `core::datetime::to_xsd_datetime` before it
    // is stamped `^^xsd:dateTime`, so an all-zero subsecond fraction is dropped:
    // `…09:30:00.000Z` and `…09:30:00Z` are the same instant, and the second is what the
    // serializer emits.
    assert_eq!(
        literal(&graph, &format!("{DCT}modified")).as_deref(),
        Some("2026-06-18T09:30:00Z"),
        "dct:modified must carry the override, in canonical xsd:dateTime form"
    );
    assert_eq!(
        literal(&graph, &format!("{DCT}issued")).as_deref(),
        Some("2026-04-09T14:30:52.837Z"),
        "dct:issued must remain the id-derived creation time, never the override"
    );

    // With no override, both predicates hold the id-derived creation time.
    entry.metadata_modified = None;
    let graph2 = dataset_graph(&entry, &ctx);
    // Asserted positively: `assert_ne!` against an `Option` would also hold if
    // `dct:modified` were omitted entirely (None != Some(_)), so it could not detect a
    // renderer that stopped emitting the predicate.
    assert_eq!(
        literal(&graph2, &format!("{DCT}modified")).as_deref(),
        Some("2026-04-09T14:30:52.837Z"),
        "without an override dct:modified falls back to the id-derived creation time, and \
         must still be present"
    );
    assert_eq!(
        literal(&graph2, &format!("{DCT}issued")).as_deref(),
        Some("2026-04-09T14:30:52.837Z"),
    );
}

/// Render a graph as sorted N-Triples. Comparing two `oxrdf::Graph` values with
/// `assert_eq!` dumps the whole string interner on failure, which is unreadable; a sorted
/// N-Triples string diffs line by line.
fn ntriples(graph: &Graph) -> String {
    let mut lines: Vec<String> = graph.iter().map(|t| t.to_string()).collect();
    lines.sort();
    lines.join("\n")
}

/// Values that would inject RDF structure if a serializer emitted them raw. Three
/// structurally distinct shapes: one aimed at Turtle's grammar, one at JSON-LD's object
/// nesting, and one at the control/bidi codepoints that a naive escaper drops or passes
/// through.
const HOSTILE_VALUES: &[(&str, &str)] = &[
    (
        "turtle-triple-injection",
        "evil \" .\n<http://x/s> <http://x/p> \"pwned",
    ),
    (
        "jsonld-object-break",
        "evil\"}],\"@id\":\"http://x/pwned\",\"z\":[{\"@value\":\"x",
    ),
    (
        "control-and-bidi",
        "bell\u{7}\u{1}\u{7f}safe\u{202e}elif.txt\u{202c}\r\nend",
    ),
];

/// Assert `graph` survives both serializations with its triple count intact and its
/// structure isomorphic. `what` labels the case in the failure message.
fn assert_round_trips_in_both_formats(mut graph: Graph, what: &str) {
    let expected_len = graph.len();
    graph.canonicalize(CanonicalizationAlgorithm::Unstable);

    let ttl = serialize_turtle(&graph);
    let ttl_reparsed = parse_turtle(&ttl);
    assert_eq!(
        ttl_reparsed.len(),
        expected_len,
        "{what}: Turtle re-parse changed the triple count; a value escaped its literal\n{ttl}"
    );
    assert_eq!(
        ntriples(&graph),
        ntriples(&ttl_reparsed),
        "{what}: Turtle round-trip is not isomorphic\n{ttl}"
    );

    let jsonld = serialize_jsonld(&graph);
    let jsonld_reparsed = parse_jsonld(&jsonld);
    assert_eq!(
        jsonld_reparsed.len(),
        expected_len,
        "{what}: JSON-LD re-parse changed the triple count; a value escaped its literal\n{jsonld}"
    );
    assert_eq!(
        ntriples(&graph),
        ntriples(&jsonld_reparsed),
        "{what}: JSON-LD round-trip is not isomorphic\n{jsonld}"
    );
}

/// A hostile value in any literal-bearing dataset field round-trips as one escaped
/// literal, in both serializations.
///
/// [`serializer_escapes_hostile_literal_values_without_injecting_triples`] covers `title`
/// in Turtle only. This test adds the two open axes: JSON-LD is a different serializer
/// (`oxjsonld`, with its own escaping rules), and the blank-node fields (creator,
/// `otherIdentifier`, contact point) reach the literal writer by another path.
#[test]
fn hostile_values_in_any_dataset_literal_field_round_trip_in_both_formats() {
    let fairdp = fairdp_config();
    let ctx = FdpContext::new(BASE_URL, BEACON_PATH, &fairdp);

    for (payload, evil) in HOSTILE_VALUES {
        // Direct dataset properties: a langString and a plain-literal list.
        let mut entry = covid_entry();
        let mut title = BTreeMap::new();
        title.insert("en".to_owned(), (*evil).to_owned());
        entry.metadata.title = LocalizedText::Map(title);
        entry.metadata.keywords = Some(vec![(*evil).to_owned()]);
        assert_round_trips_in_both_formats(
            dataset_graph(&entry, &ctx),
            &format!("dataset-properties/{payload}"),
        );

        // Every nested blank node that carries a string literal.
        let mut entry = covid_entry();
        entry.metadata.creator = vec![Agent {
            name: (*evil).to_owned(),
        }];
        entry.metadata.other_identifier = Some(vec![OtherIdentifier {
            notation: (*evil).to_owned(),
            schema_agency: Some((*evil).to_owned()),
            name: Some((*evil).to_owned()),
        }]);
        entry.metadata.contact_point = Some(ContactPoint {
            fn_: Some((*evil).to_owned()),
            has_email: Some("mailto:data@example.org".to_owned()),
            has_url: None,
        });
        assert_round_trips_in_both_formats(
            dataset_graph(&entry, &ctx),
            &format!("blank-nodes/{payload}"),
        );
    }
}

/// The same hostile values through the three graph builders the dataset tests never
/// reach, driven by the literals each one actually owns: the catalog title (which
/// becomes both `dct:title` and `dct:description`) and the `[fairdp]` node-identity
/// strings (which land on the root, every catalog and every dataset record via the
/// publisher / HDAB blank nodes).
#[test]
fn hostile_values_round_trip_through_the_catalog_root_and_distribution_builders() {
    for (payload, evil) in HOSTILE_VALUES {
        let mut fairdp = fairdp_config();
        fairdp.title = (*evil).to_owned();
        fairdp.description = Some((*evil).to_owned());
        fairdp.publisher.name = (*evil).to_owned();
        fairdp.publisher.contact_point.fn_ = (*evil).to_owned();
        fairdp.hdab.name = (*evil).to_owned();
        fairdp.hdab.contact_point.fn_ = (*evil).to_owned();
        let ctx = FdpContext::new(BASE_URL, BEACON_PATH, &fairdp);

        let entry = covid_entry();
        let entries = [&entry];

        assert_round_trips_in_both_formats(
            distribution_graph(&entry, &ctx),
            &format!("distribution/{payload}"),
        );
        assert_round_trips_in_both_formats(
            catalog_graph("gdi-aggregated", evil, &entries, &ctx),
            &format!("catalog/{payload}"),
        );
        assert_round_trips_in_both_formats(
            fdp_root_graph(
                &[CatalogListing {
                    id: "gdi-aggregated",
                    title: evil,
                    visible_datasets: vec![&entry],
                }],
                &ctx,
            ),
            &format!("root/{payload}"),
        );
        assert_round_trips_in_both_formats(
            dataset_graph(&entry, &ctx),
            &format!("dataset-node-identity/{payload}"),
        );
    }
}

/// A language tag is emitted in its RDF-canonical (lowercase) form, whatever case the
/// package used.
///
/// Ingest accepts `en-US`, the spelling RFC 5646 recommends for a region subtag, and
/// stores the language-map key verbatim. RDF 1.1 puts the lowercased tag in a
/// langString's value space, so a key emitted as-is yields a document that is legal but
/// no longer equal to its own re-parse, the property `dataset_jsonld_turtle_isomorphic`
/// and the round-trip proptest exist to hold.
#[test]
fn language_tags_are_emitted_in_canonical_lowercase_form() {
    let fairdp = fairdp_config();
    let ctx = FdpContext::new(BASE_URL, BEACON_PATH, &fairdp);

    for (given, canonical) in [
        ("en-US", "en-us"),
        ("EN", "en"),
        ("zh-CN", "zh-cn"),
        ("en", "en"),
    ] {
        let mut entry = covid_entry();
        let mut title = BTreeMap::new();
        title.insert(given.to_owned(), "A title".to_owned());
        entry.metadata.title = LocalizedText::Map(title);

        let mut graph = dataset_graph(&entry, &ctx);
        graph.canonicalize(CanonicalizationAlgorithm::Unstable);
        let ttl = serialize_turtle(&graph);

        assert!(
            ttl.contains(&format!("\"A title\"@{canonical}")),
            "language tag {given:?} must be emitted as @{canonical}:\n{ttl}"
        );

        // ...and the graph must therefore survive its own round-trip, in both formats.
        assert_eq!(
            ntriples(&graph),
            ntriples(&parse_turtle(&ttl)),
            "Turtle round-trip must be isomorphic for language tag {given:?}"
        );
        let jsonld = serialize_jsonld(&graph);
        assert_eq!(
            ntriples(&graph),
            ntriples(&parse_jsonld(&jsonld)),
            "JSON-LD round-trip must be isomorphic for language tag {given:?}"
        );
    }
}

mod proptests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use std::collections::BTreeMap;

    use gdi_node_standalone_core::model::LocalizedText;
    use gdi_node_standalone_fairdp::{
        FdpContext, dataset_graph, serialize_jsonld, serialize_turtle,
    };
    use oxrdf::dataset::CanonicalizationAlgorithm;
    use proptest::prelude::*;

    use super::{
        BASE_URL, BEACON_PATH, covid_entry, fairdp_config, ntriples, parse_jsonld, parse_turtle,
    };

    /// The language tags a title map may be keyed by, mixed case: ingest accepts `en-US`
    /// (the spelling RFC 5646 recommends), and generating it is what binds the emitter to
    /// canonicalise the tag. No two entries collapse to the same canonical tag, so no
    /// `sh:uniqueLang` collision is generated; ingest would reject such a package anyway.
    const LANGS: [&str; 6] = ["en", "et", "fi", "en-US", "zh-CN", "pt-BR"];

    /// Literal-text strategy: a curated charset covering the Turtle-significant
    /// characters (`"` `\` newline tab `<` `>` `&` `'`) plus unicode, rather than every
    /// control codepoint.
    fn text() -> impl Strategy<Value = String> {
        prop::string::string_regex("[a-zA-Z0-9 ._\"\\\\\n\t<>&'é\u{65e5}]{0,40}").unwrap()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        #[test]
        fn dataset_rdf_round_trips_isomorphic_in_both_formats(
            langs in prop::sample::subsequence(LANGS.to_vec(), 1..=3),
            title_texts in prop::collection::vec(text(), 3),
            description in prop::option::of(text()),
            keywords in prop::collection::vec(text(), 0..4),
        ) {
            let mut title = BTreeMap::new();
            for (lang, t) in langs.iter().zip(title_texts) {
                title.insert((*lang).to_owned(), t);
            }
            let mut entry = covid_entry();
            entry.metadata.title = LocalizedText::Map(title);
            entry.metadata.description = description.map(LocalizedText::Plain);
            entry.metadata.keywords = Some(keywords);

            let fairdp = fairdp_config();
            let ctx = FdpContext::new(BASE_URL, BEACON_PATH, &fairdp);
            let mut original = dataset_graph(&entry, &ctx);
            original.canonicalize(CanonicalizationAlgorithm::Unstable);

            // Both serializations render from this one graph, so both must round-trip;
            // covering JSON-LD here is what catches `oxjsonld` drifting from `oxttl`.
            let ttl = serialize_turtle(&original);
            prop_assert_eq!(
                ntriples(&original), ntriples(&parse_turtle(&ttl)),
                "dataset Turtle must round-trip isomorphically; ttl=\n{}", ttl
            );
            let jsonld = serialize_jsonld(&original);
            prop_assert_eq!(
                ntriples(&original), ntriples(&parse_jsonld(&jsonld)),
                "dataset JSON-LD must round-trip isomorphically; jsonld=\n{}", jsonld
            );
        }
    }
}
