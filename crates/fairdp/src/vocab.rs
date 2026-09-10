//! RDF vocabulary: namespace base IRIs, the bounded predicate set, the prefixes
//! registered on the serializers, and the constant authority IRIs the node emits.
//!
//! This is the single place the wire-level IRIs live. The predicate set is bounded by
//! what the `ckanext-dcat` `EuropeanHealthDCATAPProfile` parses plus the gdi-metadata
//! SHACL shapes. The serializer prefix registrations live next to the serializers in
//! [`crate::serialize`].

/// `rdf:type`.
pub(crate) const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";

// --- Class IRIs ---

/// `dcat:Dataset`.
pub(crate) const DCAT_DATASET: &str = "http://www.w3.org/ns/dcat#Dataset";
/// `dcat:Distribution`.
pub(crate) const DCAT_DISTRIBUTION: &str = "http://www.w3.org/ns/dcat#Distribution";
/// `dcat:DataService`.
pub(crate) const DCAT_DATA_SERVICE: &str = "http://www.w3.org/ns/dcat#DataService";
/// `dcat:Catalog`.
pub(crate) const DCAT_CATALOG: &str = "http://www.w3.org/ns/dcat#Catalog";
/// `fdp-o:FAIRDataPoint` (the FDP-root primary type).
pub(crate) const FDP_O_FAIR_DATA_POINT: &str = "https://w3id.org/fdp/fdp-o#FAIRDataPoint";
/// `fdp-o:MetadataService` (FDP-root secondary type).
pub(crate) const FDP_O_METADATA_SERVICE: &str = "https://w3id.org/fdp/fdp-o#MetadataService";
/// `foaf:Agent`.
pub(crate) const FOAF_AGENT: &str = "http://xmlns.com/foaf/0.1/Agent";
/// `adms:Identifier`.
pub(crate) const ADMS_IDENTIFIER_CLASS: &str = "http://www.w3.org/ns/adms#Identifier";
/// `vcard:Kind`.
pub(crate) const VCARD_KIND: &str = "http://www.w3.org/2006/vcard/ns#Kind";

// --- Predicate IRIs (the bounded set) ---

/// `dct:identifier`.
pub(crate) const DCT_IDENTIFIER: &str = "http://purl.org/dc/terms/identifier";
/// `dct:title`.
pub(crate) const DCT_TITLE: &str = "http://purl.org/dc/terms/title";
/// `dct:description`.
pub(crate) const DCT_DESCRIPTION: &str = "http://purl.org/dc/terms/description";
/// `dct:accessRights`.
pub(crate) const DCT_ACCESS_RIGHTS: &str = "http://purl.org/dc/terms/accessRights";
/// `dct:license`.
pub(crate) const DCT_LICENSE: &str = "http://purl.org/dc/terms/license";
/// `dct:creator`.
pub(crate) const DCT_CREATOR: &str = "http://purl.org/dc/terms/creator";
/// `dct:publisher`.
pub(crate) const DCT_PUBLISHER: &str = "http://purl.org/dc/terms/publisher";
/// `dct:conformsTo`.
pub(crate) const DCT_CONFORMS_TO: &str = "http://purl.org/dc/terms/conformsTo";
/// `dct:language` — the node-level `[fairdp].language` authority IRI, emitted on the
/// FDP root, every catalog and every dataset. Not in the gdi-metadata shapes; the
/// userportal's DCAT profile reads it.
pub(crate) const DCT_LANGUAGE: &str = "http://purl.org/dc/terms/language";
/// `dct:type`.
pub(crate) const DCT_TYPE: &str = "http://purl.org/dc/terms/type";
/// `dct:isReferencedBy`.
pub(crate) const DCT_IS_REFERENCED_BY: &str = "http://purl.org/dc/terms/isReferencedBy";
/// `dct:issued`.
pub(crate) const DCT_ISSUED: &str = "http://purl.org/dc/terms/issued";
/// `dct:modified`.
pub(crate) const DCT_MODIFIED: &str = "http://purl.org/dc/terms/modified";
/// `dct:isPartOf` (Catalog -> FDP-root).
pub(crate) const DCT_IS_PART_OF: &str = "http://purl.org/dc/terms/isPartOf";
/// `dct:hasPart` (Catalog -> each visible dataset; the FDP v1.2 membership
/// predicate).
pub(crate) const DCT_HAS_PART: &str = "http://purl.org/dc/terms/hasPart";

/// `dcat:keyword`.
pub(crate) const DCAT_KEYWORD: &str = "http://www.w3.org/ns/dcat#keyword";
/// `dcat:theme`.
pub(crate) const DCAT_THEME: &str = "http://www.w3.org/ns/dcat#theme";
/// `dcat:distribution`.
pub(crate) const DCAT_DISTRIBUTION_PRED: &str = "http://www.w3.org/ns/dcat#distribution";
/// `dcat:contactPoint`.
pub(crate) const DCAT_CONTACT_POINT: &str = "http://www.w3.org/ns/dcat#contactPoint";
/// `dcat:accessURL`.
pub(crate) const DCAT_ACCESS_URL: &str = "http://www.w3.org/ns/dcat#accessURL";
/// `dcat:mediaType`.
pub(crate) const DCAT_MEDIA_TYPE: &str = "http://www.w3.org/ns/dcat#mediaType";
/// `dct:format`.
pub(crate) const DCT_FORMAT: &str = "http://purl.org/dc/terms/format";
/// `dcat:accessService`.
pub(crate) const DCAT_ACCESS_SERVICE: &str = "http://www.w3.org/ns/dcat#accessService";

/// The IANA media-type IRI for `application/json` — the Beacon distribution's response
/// media type, advertised via [`DCAT_MEDIA_TYPE`]. `ckanext-dcat` parses this into the
/// GDI User Portal's `res_format` facet; without it the node's datasets are unfilterable
/// by format.
pub(crate) const IANA_MEDIA_TYPE_APPLICATION_JSON: &str =
    "https://www.iana.org/assignments/media-types/application/json";
/// The EU file-type authority IRI for JSON — the Beacon distribution's format,
/// advertised via [`DCT_FORMAT`] beside [`IANA_MEDIA_TYPE_APPLICATION_JSON`].
///
/// `ckanext-dcat`'s `_distribution_format` unwraps an authority IRI only from
/// `dct:format`. From `dcat:mediaType` it reads the IRI as a media-type string, misses it
/// in `resource_formats.json` (keyed by `application/json`) and leaves the raw URL as the
/// format, which the userportal's `res_format` facet shows verbatim. With this IRI the
/// harvester's label resolver renders `JSON`. DCAT-AP 3 recommends emitting both.
pub(crate) const EU_FILE_TYPE_JSON: &str =
    "http://publications.europa.eu/resource/authority/file-type/JSON";
/// `dcat:endpointURL` — the canonical lowercase-`p` DCAT predicate, read by DCAT-AP,
/// FDP-O and `ckanext-dcat`. The `dcat:` namespace defines only `endpointURL`, never the
/// capital-P `endPointURL`. The FDP root (a `dcat:DataService`) and every inline
/// `DataService` emit this one predicate.
pub(crate) const DCAT_ENDPOINT_URL: &str = "http://www.w3.org/ns/dcat#endpointURL";
/// `dcat:servesDataset`.
pub(crate) const DCAT_SERVES_DATASET: &str = "http://www.w3.org/ns/dcat#servesDataset";
/// `dcat:dataset` (Catalog -> each visible dataset; the DCAT membership
/// predicate).
pub(crate) const DCAT_DATASET_PRED: &str = "http://www.w3.org/ns/dcat#dataset";
/// `dcat:themeTaxonomy` (Catalog -> the SKOS `ConceptScheme` of the node theme).
pub(crate) const DCAT_THEME_TAXONOMY: &str = "http://www.w3.org/ns/dcat#themeTaxonomy";

/// `dcatap:applicableLegislation`.
pub(crate) const DCATAP_APPLICABLE_LEGISLATION: &str =
    "http://data.europa.eu/r5r/applicableLegislation";

/// `healthdcatap:healthCategory`.
pub(crate) const HEALTHDCATAP_HEALTH_CATEGORY: &str =
    "http://healthdataportal.eu/ns/health#healthCategory";
/// `healthdcatap:numberOfRecords`.
pub(crate) const HEALTHDCATAP_NUMBER_OF_RECORDS: &str =
    "http://healthdataportal.eu/ns/health#numberOfRecords";
/// `healthdcatap:numberOfUniqueIndividuals`.
pub(crate) const HEALTHDCATAP_NUMBER_OF_UNIQUE_INDIVIDUALS: &str =
    "http://healthdataportal.eu/ns/health#numberOfUniqueIndividuals";
/// `healthdcatap:hdab`.
pub(crate) const HEALTHDCATAP_HDAB: &str = "http://healthdataportal.eu/ns/health#hdab";

/// `dpv:hasLegalBasis` — `legalBasis` serialises here, in the DPV namespace, not under
/// `healthdcatap:`.
pub(crate) const DPV_HAS_LEGAL_BASIS: &str = "https://w3id.org/dpv#hasLegalBasis";

/// `adms:identifier`.
pub(crate) const ADMS_IDENTIFIER: &str = "http://www.w3.org/ns/adms#identifier";
/// `adms:status`.
pub(crate) const ADMS_STATUS: &str = "http://www.w3.org/ns/adms#status";
/// `adms:schemaAgency` (the gdi-metadata `IdentifierShape` spelling).
pub(crate) const ADMS_SCHEMA_AGENCY: &str = "http://www.w3.org/ns/adms#schemaAgency";

/// `skos:notation`.
pub(crate) const SKOS_NOTATION: &str = "http://www.w3.org/2004/02/skos/core#notation";

/// `foaf:name`.
pub(crate) const FOAF_NAME: &str = "http://xmlns.com/foaf/0.1/name";
/// `foaf:homepage`.
pub(crate) const FOAF_HOMEPAGE: &str = "http://xmlns.com/foaf/0.1/homepage";
/// `foaf:mbox`.
pub(crate) const FOAF_MBOX: &str = "http://xmlns.com/foaf/0.1/mbox";

/// `vcard:fn`.
pub(crate) const VCARD_FN: &str = "http://www.w3.org/2006/vcard/ns#fn";
/// `vcard:hasEmail` (`sh:nodeKind sh:IRI` — a `mailto:` IRI, not a literal).
pub(crate) const VCARD_HAS_EMAIL: &str = "http://www.w3.org/2006/vcard/ns#hasEmail";
/// `vcard:hasURL` (`sh:nodeKind sh:IRI`).
pub(crate) const VCARD_HAS_URL: &str = "http://www.w3.org/2006/vcard/ns#hasURL";

// --- FDP-O (FAIR Data Point Ontology) predicates ---

/// `fdp-o:conformsToFdpSpec` — the FDP-spec-version marker (constant value, see
/// [`FDP_SPEC_V1_2`]); mandatory on both the root and Catalog records.
pub(crate) const FDP_O_CONFORMS_TO_FDP_SPEC: &str = "https://w3id.org/fdp/fdp-o#conformsToFdpSpec";
/// `fdp-o:metadataIdentifier` — the record's own metadata-identifier IRI (the
/// resource IRI itself); part of the mandatory bookkeeping triplet.
pub(crate) const FDP_O_METADATA_IDENTIFIER: &str = "https://w3id.org/fdp/fdp-o#metadataIdentifier";
/// `fdp-o:metadataIssued` — the record's metadata-issued `xsd:dateTime`.
pub(crate) const FDP_O_METADATA_ISSUED: &str = "https://w3id.org/fdp/fdp-o#metadataIssued";
/// `fdp-o:metadataModified` — the record's data-derived, restart-stable
/// metadata-modified `xsd:dateTime`.
pub(crate) const FDP_O_METADATA_MODIFIED: &str = "https://w3id.org/fdp/fdp-o#metadataModified";
/// `fdp-o:metadataCatalog` — root -> each catalog IRI (alongside `ldp:contains`).
pub(crate) const FDP_O_METADATA_CATALOG: &str = "https://w3id.org/fdp/fdp-o#metadataCatalog";

// --- LDP (Linked Data Platform) predicates ---

/// `ldp:contains` — the harvester's navigation predicate (root -> catalogs,
/// catalog -> visible datasets).
pub(crate) const LDP_CONTAINS: &str = "http://www.w3.org/ns/ldp#contains";

// --- Constant authority IRIs ---

/// `fdp-o:conformsToFdpSpec` constant value: the resolvable FDP v1.2 spec URI. The
/// `/v1.2/` path is required, since the form without it `404`s and a dereferencing
/// validator would reject the marker. Emitted on both root and Catalog.
pub(crate) const FDP_SPEC_V1_2: &str = "https://specs.fairdatapoint.org/v1.2/fdp-specs-v1.2.html";

/// `adms:status` constant: the EU dataset-status `COMPLETED` authority value
/// (gdi-metadata's SHACL default, not derived from visible/hidden state).
pub(crate) const DATASET_STATUS_COMPLETED: &str =
    "http://publications.europa.eu/resource/authority/dataset-status/COMPLETED";

// --- XSD datatype IRIs ---

/// `xsd:string`.
pub(crate) const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
/// `xsd:dateTime`.
pub(crate) const XSD_DATE_TIME: &str = "http://www.w3.org/2001/XMLSchema#dateTime";
/// `xsd:nonNegativeInteger`.
pub(crate) const XSD_NON_NEGATIVE_INTEGER: &str =
    "http://www.w3.org/2001/XMLSchema#nonNegativeInteger";
