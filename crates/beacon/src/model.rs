//! The GA4GH Beacon v2.2.0 `g_variants` response wire model.
//!
//! These types are the contract a GDI consumer reads, down to the nesting
//! `response.resultSets[].results[].frequencyInPopulations[].frequencies[]`.
//!
//! All Beacon-level serialization is `camelCase`. The VRS 1.3 sub-graph under
//! `variation.location` ([`SequenceLocation`], [`SequenceInterval`], [`VrsNumber`]) is the
//! exception: it carries VRS's own keys, `sequence_id` and a constant `type` discriminator
//! per class, because the Beacon v2 default model `$ref`s VRS directly and validates
//! against its schema rather than Beacon's naming convention.
//!
//! Every optional field is `Option<…>` with
//! `#[serde(skip_serializing_if = "Option::is_none")]`, so an absent field omits the JSON
//! key entirely rather than emitting `null` or `""`. That matches the framework schema's
//! optionality and the reference's `response_model_exclude_none`.
//!
//! `source` and `source_reference` on [`FrequencyInPopulations`] are required by the GA4GH
//! schema and are therefore plain non-`Option` fields here. They are never omitted: a
//! missing value falls back to a node-level default upstream rather than dropping the key.

use serde::Serialize;
use serde_json::Value;

use crate::request::IncludeResultsetResponses;

/// One per-population allele-frequency record.
///
/// `population` and `allele_frequency` are the only GA4GH-standard fields, both required.
/// The `allele*` count fields are the GDI/`GoE` extension: permitted, but non-portable.
/// All count fields are optional and omitted when absent.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Frequency {
    /// Population key (`GoE` convention: `Total` / two-letter country code / `M`|`F`
    /// / `CC_SEX`).
    pub population: String,
    /// Allele frequency (`AF`).
    ///
    /// `f32` to match the source precision: VCF/BCF `Type=Float` is single-precision, so
    /// the provider's published `AF` is an `f32`. Serializing it as `f32` emits the
    /// shortest round-tripping decimal (`0.085`) rather than the tail a widening
    /// `f32 -> f64` produces (`0.0850000035…`).
    pub allele_frequency: f32,
    /// Allele count (`AC`); GDI/`GoE` extension.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allele_count: Option<u64>,
    /// Allele number (`AN`); GDI/`GoE` extension.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allele_number: Option<u64>,
    /// Homozygous allele count (`AC_Hom`); GDI/`GoE` extension.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allele_count_homozygous: Option<u64>,
    /// Heterozygous allele count (`AC_Het`); GDI/`GoE` extension.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allele_count_heterozygous: Option<u64>,
    /// Hemizygous allele count (`AC_Hemi`); GDI/`GoE` extension.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allele_count_hemizygous: Option<u64>,
}

/// A `frequencyInPopulations` entry: the per-source population frequency list.
///
/// `source` and `source_reference` are GA4GH-required and never omitted.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct FrequencyInPopulations {
    /// Frequency source label (e.g. `"The Genome of Europe"`); required.
    pub source: String,
    /// Frequency source reference URL; required.
    pub source_reference: String,
    /// Per-population frequencies (`minItems: 1` per the schema).
    pub frequencies: Vec<Frequency>,
}

/// A VRS 1.3 [`Number`]: an integer coordinate carried as a typed object rather than a
/// bare integer.
///
/// [`Number`]: https://w3id.org/ga4gh/schema/vrs/1.3/vrs.json
///
/// VRS 1.3 defines `SequenceInterval.start` and `.end` as
/// `oneOf [DefiniteRange, IndefiniteRange, Number]`. All three are objects, so a bare
/// integer conforms to none of them: a client generated from the schema cannot parse one,
/// and that failure takes down the whole response rather than one row.
///
/// `type` is a private field set only by [`VrsNumber::new`], so no construction site can
/// omit or misspell it. VRS `Number` declares `"required": ["type", "value"]` with
/// `additionalProperties: false`, which makes both failure modes fatal.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct VrsNumber {
    /// VRS class discriminator; always `"Number"`.
    #[serde(rename = "type")]
    type_: &'static str,
    /// The coordinate value.
    pub value: i64,
}

impl VrsNumber {
    /// A VRS `Number` carrying `value`.
    #[must_use]
    pub const fn new(value: i64) -> Self {
        Self {
            type_: "Number",
            value,
        }
    }
}

/// A VRS 1.3 `SequenceInterval`: a 0-based half-open coordinate span.
///
/// `type` is private and set only by [`SequenceInterval::new`]. VRS declares
/// `"required": ["end", "start", "type"]` with `additionalProperties: false`, so an
/// untyped interval matches neither `SequenceInterval` nor the deprecated
/// `SimpleInterval`, and the enclosing `SequenceLocation` then matches nothing either.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct SequenceInterval {
    /// VRS class discriminator; always `"SequenceInterval"`.
    #[serde(rename = "type")]
    type_: &'static str,
    /// Interval start (`POS`).
    pub start: VrsNumber,
    /// Interval end (`POS + len(REF)`).
    pub end: VrsNumber,
}

impl SequenceInterval {
    /// A VRS `SequenceInterval` over the 0-based half-open range `start..end`.
    #[must_use]
    pub const fn new(start: i64, end: i64) -> Self {
        Self {
            type_: "SequenceInterval",
            start: VrsNumber::new(start),
            end: VrsNumber::new(end),
        }
    }
}

/// A VRS 1.3 `SequenceLocation` with a coordinate interval and reference sequence.
///
/// `type` is private and set only by [`SequenceLocation::new`]; VRS declares
/// `"required": ["interval", "sequence_id", "type"]` with `additionalProperties: false`.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct SequenceLocation {
    /// VRS class discriminator; always `"SequenceLocation"`.
    #[serde(rename = "type")]
    type_: &'static str,
    /// Reference sequence CURIE (`refseq:{accession}`); `snake_case` is the VRS key.
    /// Always present: every stored dataset carries a `GRCh37` or `GRCh38` assembly and
    /// only canonical contigs, since ingest rejects anything else, so the accession lookup
    /// is total on every reachable `(assembly, chr)`. See `assemble_dataset` for the
    /// fail-closed posture of the arm that cannot be reached.
    #[serde(rename = "sequence_id")]
    pub sequence_id: String,
    /// The 0-based half-open coordinate interval.
    pub interval: SequenceInterval,
}

impl SequenceLocation {
    /// A VRS `SequenceLocation` on `sequence_id` over `interval`.
    #[must_use]
    pub fn new(sequence_id: String, interval: SequenceInterval) -> Self {
        Self {
            type_: "SequenceLocation",
            sequence_id,
            interval,
        }
    }
}

/// The `variation` object of a result entry.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Variation {
    /// VRS sequence location.
    pub location: SequenceLocation,
    /// Reference bases (`REF`).
    pub reference_bases: String,
    /// Alternate bases (`ALT`).
    pub alternate_bases: String,
    /// Variant type label (e.g. `SNP` / `DEL` / `DELINS`).
    pub variant_type: String,
}

/// Public/portable identifiers for a variant.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Identifiers {
    /// Public HGVS id (`{accession}:g.…`). Always present: it is rendered from the same
    /// accession as the location's `sequence_id`, which every served entry carries.
    ///
    /// The canonical GA4GH key is `genomicHGVSId` (capital `HGVS`), so this field
    /// carries an explicit rename rather than relying on the struct's `camelCase`
    /// (which would emit `genomicHgvsId`).
    #[serde(rename = "genomicHGVSId")]
    pub genomic_hgvs_id: String,
}

/// One `results[]` entry: a variant group with its population frequencies.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ResultEntry {
    /// Opaque, beacon-instance-local primary key (schema-required).
    pub variant_internal_id: String,
    /// The variant's VRS-style variation object.
    pub variation: Variation,
    /// Public identifiers.
    pub identifiers: Identifiers,
    /// Per-source population frequencies for this variant.
    pub frequency_in_populations: Vec<FrequencyInPopulations>,
}

/// One `resultSets[]` entry: a single visible dataset's matches.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ResultSet {
    /// The serving beacon id.
    pub beacon_id: String,
    /// The dataset id, which is how a client associates frequencies with datasets.
    pub id: String,
    /// Result-set type; always `"dataset"` for this node.
    pub set_type: String,
    /// Whether this dataset has any match.
    pub exists: bool,
    /// True count of matching variant groups (unaffected by paging).
    pub results_count: u64,
    /// The page-limited slice of variant groups.
    pub results: Vec<ResultEntry>,
    /// GDI disclosure facts about this dataset, carried on every resultSet, hit or
    /// `exists:false` miss, so a `0` is self-describing: the `minAlleleCount` floor bounds
    /// what an empty answer could hide (`{0} ∪ [1, floor)`), and `assembly` and
    /// `populations` say what the dataset could have matched. Identical to the
    /// [`Collection`] disclosure on `/datasets`, under a namespaced key a client that does
    /// not know it can ignore.
    pub gdi_dataset_info: GdiDatasetInfo,
}

/// The `response` body wrapping the result sets.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ResultSetsBody {
    /// One result set per matching dataset.
    pub result_sets: Vec<ResultSet>,
}

/// The `responseSummary` block.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ResponseSummary {
    /// Whether any result set matched.
    pub exists: bool,
    /// Sum of every result set's `resultsCount`.
    ///
    /// `None`, with the JSON key omitted, is the `boolean`-granularity shape, where the
    /// node discloses only `exists` and withholds the count. `count` and `record` carry
    /// `Some(total)`. `numTotalResults` is optional in the Beacon v2 `responseSummary`
    /// schema, so omitting it stays conformant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_total_results: Option<u64>,
}

/// A `ListOfSchemas` element: an entry type and the schema URL it conforms to.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Schema {
    /// The entry type the schema applies to, such as `genomicVariant`. Serialized as
    /// `entityType`, the field name the Beacon v2.2.0 `SchemasPerEntity` definition
    /// (`beaconCommonComponents.json`) uses for `returnedSchemas` items. The
    /// `#[serde(rename)]` overrides the struct-level camelCase, which would emit the
    /// non-spec `entryType`.
    #[serde(rename = "entityType")]
    pub entry_type: String,
    /// The schema URL. The node emits it and never fetches it.
    pub schema: String,
}

/// `pagination`: the applied skip and limit, after defaulting and clamping.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Pagination {
    /// Number of result groups to skip.
    pub skip: u64,
    /// Maximum number of result groups to return (after defaulting + clamping).
    pub limit: u64,
}

impl Pagination {
    /// Build an applied [`Pagination`] from already-resolved `skip`/`limit`.
    ///
    /// `request::apply_pagination` produces the defaulted and clamped values. This
    /// constructor exists so callers and tests can build the type even though it is
    /// `#[non_exhaustive]`.
    ///
    /// # Examples
    ///
    /// ```
    /// use gdi_node_standalone_beacon::model::Pagination;
    ///
    /// let p = Pagination::new(20, 50);
    /// assert_eq!((p.skip, p.limit), (20, 50));
    /// // Serializes to the camelCase wire keys a client reads.
    /// let v = serde_json::to_value(p).expect("serialize pagination");
    /// assert_eq!(v["skip"], 20);
    /// assert_eq!(v["limit"], 50);
    /// ```
    #[must_use]
    pub fn new(skip: u64, limit: u64) -> Self {
        Self { skip, limit }
    }
}

/// `receivedRequestSummary` (`beaconReceivedRequestSummary`).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ReceivedRequestSummary {
    /// Echo of the request API version.
    pub api_version: String,
    /// Echo of the (case-folded) requested granularity.
    pub requested_granularity: String,
    /// Echo of the submitted `testMode` (Beacon v2; default `false`). Always
    /// serialized. This all-public aggregate beacon holds no sensitive data, so
    /// `testMode` is answered as a normal query and reflected here for transparency.
    ///
    /// `filters` are not echoed: this beacon advertises no filtering terms and rejects a
    /// submitted `filters` selector with a 400, so there is nothing to echo.
    /// `requestParameters` are not echoed either. The vendored Beacon v2.2.0
    /// `requestParameters` schema is a placeholder requiring object-valued entries, which
    /// real scalar and array selectors (`referenceName`, `start`, …) violate, so an echo
    /// would fail the `beacon_schema_conformance` gate.
    pub test_mode: bool,
    /// Echo of the `includeResultsetResponses` shaping the node applied at `record`
    /// granularity: the submitted value, or `HIT` when the client submitted none. Always
    /// serialized. Under `boolean`/`count` the response is shaped by the granularity
    /// instead and this echoes the received value, which had no effect.
    ///
    /// The applied value rather than the literal submitted one, because the `$def` declares
    /// `default: "HIT"` and reads an absent field as that default. A client that sent
    /// nothing still had a shaping applied, and omitting the key here would leave it unable
    /// to tell the hit-only default apart from a beacon that ignored the field. This
    /// mirrors `pagination`, which also echoes the effective value.
    ///
    /// Typed as the enum rather than a `String`, so the four members are the only
    /// representable values and `null`, which the `$def`'s `enum` does not admit, is
    /// unrepresentable rather than avoided by convention.
    pub include_resultset_responses: IncludeResultsetResponses,
    /// Echo of the submitted `requestedSchemas`. The field is required with `minItems: 0`,
    /// so an empty array is valid and it is always serialized. The node serves its single
    /// default schema regardless of what is asked for, reported in
    /// [`BeaconResponseMeta::returned_schemas`].
    ///
    /// Not verbatim: `submitted_request_echo` keeps only the object-valued entries. The
    /// vendored `beaconRequestedSchema` types each item as an object, so echoing a client's
    /// `["foo"]` back would emit a response the node's own `beacon_schema_conformance` gate
    /// rejects, answering a malformed request with a malformed response. Non-object entries
    /// are dropped from the echo only; the answer never depended on them.
    pub requested_schemas: Vec<Value>,
    /// The applied pagination: the effective `skip` and `limit` after the
    /// `[beacon].max_page_limit` clamp, not the requested ones, so a client that asked for
    /// more than the cap can see it was capped rather than read a short page as "no more
    /// rows".
    pub pagination: Pagination,
    /// The assembly the node assumed for a variant query that named none, which is only
    /// possible when every visible dataset shares one. Absent, never `null`, when the
    /// client named an assembly itself, so its presence means the node filled it in.
    ///
    /// Not echoed under the standard `requestParameters` key. The vendored Beacon v2.2.0
    /// `requests/requestParameters.json` is a placeholder that types every entry as
    /// `{"type": "object"}`, so a string in `requestParameters: {"assemblyId": "GRCh38"}`
    /// makes the node's own `beacon_schema_conformance` gate reject the response, as
    /// `framework_request_parameters_placeholder_rejects_a_scalar_echo` pins. Upstream's
    /// own default model types `assemblyId` as a string, so the placeholder contradicts the
    /// model it defers to. Until that is fixed upstream, the assumed value rides on this
    /// sibling key, which the summary schema permits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assumed_assembly_id: Option<String>,
}

/// `meta` (`beaconResponseMeta`), reused verbatim by success and error envelopes.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct BeaconResponseMeta {
    /// The serving beacon id.
    pub beacon_id: String,
    /// The served API version.
    pub api_version: String,
    /// The granularity served (`boolean` | `count` | `record`), set by
    /// `shape_for_granularity` to the requested level, and `record` on the default path.
    pub returned_granularity: String,
    /// One-element list naming the default schema of the served entry type: the
    /// `genomicVariant` schema for a `g_variants` success, the `dataset` schema for a
    /// `/datasets` collections success, and, since error envelopes reuse this `meta`, the
    /// rejecting endpoint's entry type (`genomicVariant` | `dataset` | `individual`) for a
    /// `beaconErrorResponse`.
    pub returned_schemas: Vec<Schema>,
    /// The schema-constrained summary of the received request.
    pub received_request_summary: ReceivedRequestSummary,
}

/// A full `g_variants` success response.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct BeaconResponse {
    /// The fully-populated response meta.
    pub meta: BeaconResponseMeta,
    /// The summary (exists + total count).
    pub response_summary: ResponseSummary,
    /// The result-set body.
    ///
    /// `None`, with the JSON key omitted, is produced by `shape_for_granularity` for a
    /// `boolean` or `count` request, which drops the `response` member. `record`
    /// granularity keeps it `Some`. `includeResultsetResponses: NONE` does not drop it: it
    /// keeps `Some` with an empty `resultSets`. See `apply_include_resultset_responses`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<ResultSetsBody>,
}

/// One `response.collections[]` entry: a minimal Beacon v2 `dataset`.
///
/// Matches the beacon-v2 `datasets/defaultSchema.json`, a `Dataset` collection: `id` and
/// `name` are required, and `description`, `createDateTime` and `updateDateTime` are
/// optional and omitted when absent rather than emitted as `null` or `""`. The node serves
/// only these fields. The schema's `additionalProperties: true` permits richer entries
/// (`version`, `dataUseConditions`, …), which the node does not carry.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Collection {
    /// Unique dataset identifier (the dataset's `datasetId` / `dct:identifier`).
    pub id: String,
    /// Human-readable dataset name (the dataset's `title`).
    pub name: String,
    /// Dataset description; omitted when the manifest leaves it unset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Creation timestamp (ISO 8601); omitted when unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub create_date_time: Option<String>,
    /// Update timestamp (ISO 8601); omitted when unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_date_time: Option<String>,
    /// GDI-specific disclosure facts about this dataset. Carried under a namespaced key
    /// because the beacon-v2 `Dataset` schema defines none of them; its
    /// `additionalProperties: true` permits the extension without an `apiVersion` bump.
    pub gdi_dataset_info: GdiDatasetInfo,
}

/// What the node discloses about a dataset so a client can interpret its answers.
///
/// Without these three facts an empty result is ambiguous: a variant absent from a
/// population may have been suppressed rather than never observed, and a query against the
/// wrong assembly silently matches nothing. In both cases absence reads as zero.
///
/// Carried both on a `/datasets` [`Collection`] and on each `g_variants` [`ResultSet`],
/// hit or `exists:false` miss, so a client can bound a `0` from the query response itself
/// rather than cross-referencing `/datasets`.
///
/// This is a dataset-level disclosure, never a per-variant one: it rides on the resultSet,
/// which is the dataset, not on any `results[]` entry. Naming the floor says that
/// thresholds exist, while flagging an individual suppressed row would reveal which
/// variants have below-floor cells, the fact the `Total` collapse exists to hide. It is
/// query-independent, the same for every variant, so it adds no differencing surface:
/// suppressed and absent still assemble to a byte-identical `exists:false` resultSet.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct GdiDatasetInfo {
    /// The reference assembly this dataset is built on (`GRCh37` / `GRCh38`). A variant
    /// query naming any other assembly cannot match it.
    pub assembly: String,
    /// The population labels the dataset serves, sorted. Omitted rather than empty when the
    /// manifest carries no such field, so "unknown" is never rendered as "none".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub populations: Option<Vec<String>>,
    /// The effective allele-count floor applied to this dataset's answers:
    /// `max(node floor, dataset floor)`. `0` means no suppression. Disclosing only the
    /// dataset's own floor would understate the suppression a node-wide floor adds.
    pub min_allele_count: u32,
}

/// The `response` body of a `beaconCollectionsResponse`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct CollectionsBody {
    /// One collection per visible dataset (`minItems: 0`).
    pub collections: Vec<Collection>,
}

/// A Beacon v2 `beaconCollectionsResponse`, the `datasets` entry type's envelope.
///
/// Distinct from the `resultSets` shape `g_variants` uses: it wraps the same `meta`, a
/// [`BeaconResponseMeta`] naming the `dataset` schema, and [`ResponseSummary`] around a
/// `response.collections[]` list with one entry per visible dataset. Matches the beacon-v2
/// framework `beaconCollectionsResponse.json` (`required: [meta, responseSummary,
/// response]`, `response.required: [collections]`).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct BeaconCollectionsResponse {
    /// The fully-populated response meta (naming the `dataset` schema).
    pub meta: BeaconResponseMeta,
    /// The summary (`exists` + true total visible count).
    pub response_summary: ResponseSummary,
    /// The collections body.
    pub response: CollectionsBody,
}

/// The `error` block of a `beaconErrorResponse`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct BeaconError {
    /// The HTTP status code (e.g. `400`).
    pub error_code: u16,
    /// Human-readable message (never leaks internal detail).
    pub error_message: String,
}

/// A Beacon v2 `beaconErrorResponse`: the same `meta` as a success, plus `error`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct BeaconErrorResponse {
    /// The fully-populated response meta (same shape as success).
    pub meta: BeaconResponseMeta,
    /// The error block.
    pub error: BeaconError,
}

impl BeaconErrorResponse {
    /// Build a `beaconErrorResponse` from an already-built [`BeaconResponseMeta`], an HTTP
    /// status code and a public message.
    ///
    /// The `meta` is the same fully-populated shape a success response carries, built via
    /// [`crate::query::error_response_meta`], so the error envelope is schema-conformant.
    /// The types are `#[non_exhaustive]`, so this constructor is how an out-of-crate caller
    /// such as the service binary's HTTP handlers renders an error envelope.
    ///
    /// # Examples
    ///
    /// ```
    /// use gdi_node_standalone_beacon::model::BeaconErrorResponse;
    /// use gdi_node_standalone_beacon::query::error_response_meta;
    /// use gdi_node_standalone_beacon::BeaconParams;
    ///
    /// let cfg = BeaconParams::default();
    /// let meta = error_response_meta(&cfg, "genomicVariant");
    /// let resp = BeaconErrorResponse::new(meta, 400, "unsupported referenceName".to_owned());
    ///
    /// // The `error` block carries the status code and the public message.
    /// let v = serde_json::to_value(&resp).expect("serialize error response");
    /// assert_eq!(v["error"]["errorCode"], 400);
    /// assert_eq!(v["error"]["errorMessage"], "unsupported referenceName");
    /// // The same `meta` shape a success response carries is present.
    /// assert!(v["meta"]["returnedSchemas"].is_array());
    /// ```
    #[must_use]
    pub fn new(meta: BeaconResponseMeta, error_code: u16, error_message: String) -> Self {
        Self {
            meta,
            error: BeaconError {
                error_code,
                error_message,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frequency_in_populations_serializes_to_contract() {
        let f = FrequencyInPopulations {
            source: "The Genome of Europe".into(),
            source_reference: "https://genomeofeurope.eu/".into(),
            frequencies: vec![Frequency {
                population: "FI_M".into(),
                allele_frequency: 0.085,
                allele_count: Some(119),
                allele_number: Some(1400),
                allele_count_homozygous: Some(8),
                allele_count_heterozygous: Some(111),
                allele_count_hemizygous: Some(0),
            }],
        };
        insta::assert_json_snapshot!(f);
    }

    #[test]
    fn returned_schema_uses_spec_entity_type_key() {
        // Beacon v2.2.0 `SchemasPerEntity` (beaconCommonComponents.json) names the field
        // `entityType`, not `entryType`, and a strict client reads `entityType`.
        let s = Schema {
            entry_type: "genomicVariant".to_owned(),
            schema: "https://example.org/schema.json".to_owned(),
        };
        let v = serde_json::to_value(&s).expect("serialize schema");
        let obj = v.as_object().expect("schema is a JSON object");
        assert!(
            obj.contains_key("entityType"),
            "returnedSchemas item must use the spec `entityType` key"
        );
        assert!(
            !obj.contains_key("entryType"),
            "must not emit the non-spec `entryType` key"
        );
    }

    #[test]
    fn frequency_omits_absent_count_keys() {
        let f = Frequency {
            population: "Total".into(),
            allele_frequency: 0.5,
            allele_count: None,
            allele_number: None,
            allele_count_homozygous: None,
            allele_count_heterozygous: None,
            allele_count_hemizygous: None,
        };
        let v = serde_json::to_value(&f).expect("serialize frequency");
        let obj = v.as_object().expect("frequency is a JSON object");
        // Only the two GA4GH-standard keys remain; every count key is omitted.
        assert_eq!(obj.len(), 2);
        assert!(obj.contains_key("population"));
        assert!(obj.contains_key("alleleFrequency"));
        assert!(!obj.contains_key("alleleCount"));
        assert!(!obj.contains_key("alleleNumber"));
        assert!(!obj.contains_key("alleleCountHomozygous"));
        assert!(!obj.contains_key("alleleCountHeterozygous"));
        assert!(!obj.contains_key("alleleCountHemizygous"));
    }

    #[test]
    fn sequence_location_keeps_snake_case_sequence_id_and_always_emits_it() {
        // sequence_id is the VRS key, so it stays snake_case even though the sibling
        // response structs are renamed camelCase. VRS declares it required, and the field
        // is a plain `String` with no `skip_serializing_if`, so no location can reach the
        // wire without its reference sequence.
        let location = SequenceLocation::new(
            "refseq:NC_000011.10".into(),
            SequenceInterval::new(100, 101),
        );
        let v = serde_json::to_value(&location).expect("serialize location");
        let obj = v.as_object().expect("location is a JSON object");
        assert!(obj.contains_key("sequence_id")); // snake_case, not sequenceId
        assert!(!obj.contains_key("sequenceId"));
        assert!(obj.contains_key("interval"));
    }

    #[test]
    fn sequence_location_serializes_the_vrs_1_3_shape() {
        // The whole VRS 1.3 encoding, pinned at the crate boundary: a `type` on the
        // location and on the interval, and object coordinates rather than bare integers.
        // `beacon_schema_conformance.rs` binds this at the wire level by validating a real
        // `/g_variants` response against the vendored default-model and VRS schemas. This
        // is the unit-level check, so a break is visible without booting a node.
        let location = SequenceLocation::new(
            "refseq:NC_000003.12".into(),
            SequenceInterval::new(45_823_239, 45_823_240),
        );
        assert_eq!(
            serde_json::to_value(&location).expect("serialize location"),
            serde_json::json!({
                "type": "SequenceLocation",
                "sequence_id": "refseq:NC_000003.12",
                "interval": {
                    "type": "SequenceInterval",
                    "start": { "type": "Number", "value": 45_823_239 },
                    "end": { "type": "Number", "value": 45_823_240 },
                },
            })
        );
    }
}
