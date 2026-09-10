//! The generated `manifest.json` — JSON, machine-written and machine-read.
//!
//! Same four sections as `package.yaml`
//! (`metadata` / `files` / `internal` / `config`), but `metadata` carries the generated
//! `datasetId` + computed `numberOfRecords` (not `prefix`/`org`), `files` entries have all
//! checksums/sizes computed, and `config` adds `assembly`, `manifestVersion`, `generatedBy`.

use super::metadata::{
    Agent, Assembly, ContactPoint, DatasetMode, Internal, LocalizedText, OtherIdentifier,
};
use serde::{Deserialize, Serialize};

/// The full generated manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Manifest {
    /// FDP-public, per-dataset metadata.
    pub metadata: ManifestMetadata,
    /// Inventory of the provider's source inputs, the VCF and BAM files the dataset was
    /// built from, with their checksums and sizes. This is upstream provenance, not the
    /// Parquet payload the node serves. Non-public: the node strips this section at
    /// ingest, and only an integrating system's registry reads it.
    #[serde(default)]
    pub files: Vec<FileGroup>,
    /// Non-public bookkeeping (node-opaque).
    #[serde(default)]
    pub internal: Internal,
    /// Digests of the packaged payload: the TAR members the package carries.
    // Not a doc comment: schemars would publish it into docs/manifest.schema.json.
    //
    // `files` above is the provider's source inventory, the VCFs a dataset was built from.
    // This section records the bytes the package ships, so two packages built from
    // identical VCFs but with a different disclosure floor, column projection or converter
    // version are distinguishable at the manifest level. `files` is stripped by the node at
    // ingest and so cannot serve as an at-rest integrity record; this section is retained.
    //
    // Optional, and absent from a package built before it existed: a consumer must treat
    // `None` as "unknown", never as "no payload". Keyed by TAR member name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Payload>,
    /// Processing options.
    pub config: ManifestConfig,
}

/// The `payload` section: what the package ships, as opposed to what it was built from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Payload {
    /// Digest algorithm; `sha256` is the only value this tool writes or accepts.
    // The doc above is published into docs/manifest.schema.json as this field's
    // `description`, so it names the value literally rather than linking `Payload::SHA256`.
    // An intra-doc link means nothing to a schema consumer. Readers inside this workspace
    // must use `Payload::algorithm_supported` rather than this string.
    //
    // The value is encoded in the schema, not only described, so a document declaring
    // `algorithm: "sha-256"` fails validation instead of passing it and being rejected
    // later by ingest. The literal is duplicated from `Payload::SHA256` because a schemars
    // attribute takes no const expression, and
    // `the_published_schema_encodes_the_only_algorithm_this_build_accepts` binds the two.
    #[cfg_attr(feature = "schema", schemars(extend("enum" = ["sha256"])))]
    pub algorithm: String,
    /// Every packaged member except `manifest.json` itself, keyed by TAR member name
    /// (`headers/{vcfid}.vcf`, `allele-freq.*.parquet`) and sorted by key. These are the
    /// packaged bytes. The provider's source inventory is the manifest's top-level
    /// `files`.
    // The doc above is published into docs/manifest.schema.json as this field's
    // `description`, so it says what a schema consumer needs and nothing more. The name is
    // `members` rather than `files` because two `files` keys at different depths meaning
    // opposite things is an integrator trap.
    //
    // `payload_section` enumerates the staged dir with two globs, so a further member type
    // added to TAR assembly could ship undigested.
    // `a_built_manifest_records_its_payload_digest` asserts this map names every staged
    // member and nothing else, against the bytes on disk.
    pub members: std::collections::BTreeMap<String, PayloadEntry>,
}

impl Payload {
    /// The only digest algorithm this workspace writes or verifies.
    ///
    /// Three readers check it: node ingest, `pack`'s pre-sign verification and `diff`'s
    /// basis selection. Their failure modes differ, since ingest hard-fails while `diff`
    /// downgrades to the weaker source-inventory comparison, so adding a second algorithm
    /// and missing one reader would quietly stop `diff` comparing packaged bytes. Hence one
    /// constant.
    pub const SHA256: &'static str = "sha256";

    /// Whether this build can verify the declared digests.
    ///
    /// Readers must branch on this rather than comparing [`Self::algorithm`] themselves,
    /// so "which algorithms are understood" stays one fact.
    #[must_use]
    pub fn algorithm_supported(&self) -> bool {
        self.algorithm == Self::SHA256
    }
}

/// One packaged member's digest and size.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct PayloadEntry {
    /// SHA-256 of the member's bytes as packed (64 lowercase hex chars).
    // The pattern is what a validator can act on. As prose over a bare `type: string`, an
    // uppercase, truncated or non-hex digest passes validation and fails later, at the
    // comparison it was meant to make possible.
    #[cfg_attr(feature = "schema", schemars(regex(pattern = r"^[0-9a-f]{64}$")))]
    pub sha256: String,
    /// The member's size in bytes.
    pub size: u64,
}

/// The `metadata` section of a manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ManifestMetadata {
    /// Generated dataset ID (replaces `prefix`/`org`).
    pub dataset_id: String,
    /// Catalog name; must match a catalog defined in the service config.
    pub catalog: String,
    /// Dataset title (plain string or language map).
    pub title: LocalizedText,
    /// Free-text description (plain string or language map). Required.
    // Not a doc comment: schemars would publish it into docs/manifest.schema.json.
    //
    // `Option` in Rust but required on the wire, hence `schemars(required)`. Ingest rejects
    // a manifest without it, and the docs declare the schema authoritative, so the schema
    // must not list it as optional merely because the field is an `Option`.
    //
    // The Rust type stays `Option` because the field is absent from a package baseline that
    // a metadata overlay later supplies, so the struct must represent that intermediate
    // state. Marking it required also drops the `null` branch from the schema's `anyOf`, so
    // `"description": null` is not admissible.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(required))]
    pub description: Option<LocalizedText>,
    /// Access rights authority IRI (`PUBLIC` / `RESTRICTED` / `NON_PUBLIC`).
    pub access_rights: String,
    /// Legislation mandating the dataset (EU ELI IRIs, >= 1).
    pub applicable_legislation: Vec<String>,
    /// Reuse license for this dataset (IRI).
    pub license: String,
    /// Creating agents (>= 1).
    pub creator: Vec<Agent>,
    /// GDI health category IRIs (>= 1).
    pub health_category: Vec<String>,
    /// Tags for discovery (recommended).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keywords: Option<Vec<String>>,
    /// Distinct sequenced subjects across the whole dataset (recommended).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub number_of_unique_individuals: Option<u64>,
    /// Standards-compliance IRIs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conforms_to: Option<Vec<String>>,
    /// Dataset type IRI, set only for synthetic datasets.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    /// DPV legal basis IRIs (for real personal data).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legal_basis: Option<Vec<String>>,
    /// Publication DOI IRIs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_referenced_by: Option<Vec<String>>,
    /// Secondary identifiers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub other_identifier: Option<Vec<OtherIdentifier>>,
    /// Dataset-level contact point.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_point: Option<ContactPoint>,
    /// Computed: distinct `(chromosome, POS, REF, ALT)` variants the dataset serves.
    ///
    /// Optional in this schema, but required by the node at ingest. It is served verbatim
    /// in the public FDP and DCAT records and cross-checked against the parquet data, so a
    /// package that omits it or miscounts is rejected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub number_of_records: Option<u64>,
    /// Computed: the sorted population labels the dataset serves, the union of every source
    /// VCF's emitted set after the build-time `minAlleleCount` floor.
    ///
    /// It sits in `metadata` rather than `files` because the node strips `files` at ingest,
    /// so the per-VCF conversion statistics never reach serve time. Without this field a
    /// Beacon client can only union the labels that happen to come back from variant
    /// queries, which suppression can truncate.
    ///
    /// Absent on a manifest written before the field existed. The node then advertises no
    /// population set rather than an empty one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub populations: Option<Vec<String>>,
}

/// The `manifestVersion` this build of the workspace produces and accepts. The tool stamps
/// it into every generated `manifest.json` at `build` and the node rejects any other value
/// at ingest, both reading this one constant, so the emitted and the accepted version
/// cannot drift apart. Bumped only on a backwards-incompatible manifest/package change;
/// additive fields do not bump it.
pub const SUPPORTED_MANIFEST_VERSION: u32 = 1;

/// The `config` section of a manifest: the node-visible processing and provenance fields.
///
/// Unlike the rest of the manifest, `config` rejects unknown keys. It is a small,
/// controlled set of security-relevant knobs, notably `minAlleleCount`, so a mistyped key
/// such as `minAlleleCnt` fails loudly at ingest instead of dropping to the default. The
/// `metadata` and `files` sections stay lenient, so the DCAT-style `metadata` can grow
/// additive fields without an older node rejecting the package. An additive `config` field
/// requires a coordinated tool and node deploy.
// The tool and the node are one co-versioned workspace; see `SUPPORTED_MANIFEST_VERSION`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ManifestConfig {
    /// Data-content mode; `aggregated` = allele frequencies (the only mode implemented).
    pub mode: DatasetMode,
    /// Position-based block range in bases (0 = single file per chromosome).
    pub block_range: u32,
    /// Allele-frequency provenance source (free text).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub af_source: Option<String>,
    /// Allele-frequency provenance source reference (URL).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub af_source_reference: Option<String>,
    /// AC floor applied at build (0 = off). Counts alleles, not individuals: a homozygote
    /// contributes 2 to AC, so use about 2k for k distinct people, for example 10 for
    /// k = 5. It bounds singleton and small-cell re-identification only. No floor value
    /// prevents multi-variant membership inference, which operates on the common variants
    /// that always survive.
    #[serde(default)]
    pub min_allele_count: u32,
    /// Declared sensitive-tier individual-match-count floor (recorded, not applied here).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hide_lower_counts: Option<u32>,
    /// Dataset assembly the node reads (promoted from the VCF group).
    pub assembly: Assembly,
    /// Manifest schema version (bumped only on a backwards-incompatible change). This
    /// build of the tool writes, and this build of the node accepts, exactly the value the
    /// schema bounds it to.
    // The bound lives in the schema so a consumer that generates its model from it rejects
    // a later, incompatible manifest by version, naming the reason, rather than failing on
    // whichever shape difference it trips over first. Serde ingest and the published
    // schema read the same `SUPPORTED_MANIFEST_VERSION` constant.
    #[cfg_attr(
        feature = "schema",
        schemars(range(equal = SUPPORTED_MANIFEST_VERSION))
    )]
    pub manifest_version: u32,
    /// Tool identity that produced the manifest.
    pub generated_by: String,
}

/// A group of files of one category (e.g. `VCF`, `BAM`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct FileGroup {
    /// File category; `VCF` is the one reserved value (case-insensitive).
    pub category: String,
    /// Assembly build (required on the VCF group, optional otherwise).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// Patch-level provenance (not used for matching).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub precise_reference: Option<String>,
    /// The files in this group (manifest form: all checksums/sizes computed).
    pub files: Vec<FileEntry>,
}

/// A manifest file entry: always the object form, with `sha256` and `size` computed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct FileEntry {
    /// The source input's path, relative to the `package.yaml` directory, or the operator's
    /// declared string when the file lives outside it. This is not an in-package member
    /// name: the source files are never shipped in the package.
    pub path: String,
    /// SHA-256 checksum (64 hex chars).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// File size in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// What the VCF to parquet projection discarded when building from this file. Present
    /// only on entries the converter processed; a `BAM` group's entries omit it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversion: Option<ConversionStats>,
}

/// What `build` discarded when projecting one source VCF into the 11-column parquet
/// schema, ordered along the pipeline: input, then what the projection discarded, then
/// what disclosure control withheld, then output.
///
/// # Trust
///
/// This is an unverified provider claim. The source VCFs are not shipped in the package,
/// so the sibling `sha256` is already a digest of a file no consumer receives, and these
/// counters are the same trust class: a claim by the provider's own tool about a
/// transformation nobody downstream can re-run. The node strips the whole `files` section
/// at ingest, so it never influences serving.
///
// Modelled separately from `crate::convert::DropCounts` and
// `crate::convert::SuppressionCounts`: the manifest is an external contract, those are
// implementation details that also feed `preview`'s JSON. Coupling them would let an
// internal rename rewrite the manifest. Not a doc comment, because schemars would publish
// it to every schema consumer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ConversionStats {
    /// Observations about the VCF as read. Its records were kept.
    pub input: ConversionInput,
    /// What the projection threw away.
    pub discarded: ConversionDiscarded,
    /// What the `min_allele_count` floor and its coherence collapse withheld.
    pub suppressed: ConversionSuppressed,
    /// What reached parquet.
    pub output: ConversionOutput,
}

/// Facts about the source VCF. Nothing here was discarded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ConversionInput {
    /// Records read: the denominator for every drop count.
    pub records: u64,
    /// Records whose `FILTER` was neither `PASS` nor missing. They were converted anyway:
    /// the converter does not gate on `FILTER`.
    pub non_pass_records: u64,
    /// Records carrying a gVCF `<NON_REF>` reference block. Non-zero means the input was a
    /// gVCF rather than a sites or allele-frequency VCF. A subset of
    /// `discarded.recordsNoSupportedAlt`, not a peer of it.
    pub gvcf_reference_blocks: u64,
    /// Population labels the header declared, including `AC`/`AN`-only ones. A superset of
    /// `output.populations`.
    pub populations_recognized: Vec<String>,
}

/// What the projection discarded. Only the four `records_*` counts are whole records.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ConversionDiscarded {
    /// Records on a non-primary-assembly contig (decoy, `_alt`, `chrUn_`, `HLA-`).
    pub records_unsupported_contig: u64,
    /// Records with no supported ALT left (symbolic, breakend, `*`, or ALT == REF).
    pub records_no_supported_alt: u64,
    /// Records that survived both filters but emitted no row because the k-anonymity floor
    /// withheld every one of them (including its coherence collapse).
    ///
    /// Absent on a manifest written before this counter existed; such a manifest simply
    /// cannot close the record identity documented on `output`.
    ///
    /// Floor-attributable only. A record that emitted nothing because the input carried no
    /// allele frequency is counted in `recordsNoAf` instead, so a build with the floor
    /// switched off cannot report records here.
    #[serde(default)]
    pub records_all_rows_withheld: u64,
    /// Records that survived both filters but emitted no row because no population had an
    /// allele frequency to emit (the input carried no usable `AF`).
    ///
    /// Absent on a manifest written before this counter existed. On such a manifest these
    /// records are folded into `recordsAllRowsWithheld`, so the identity still closes, with
    /// the older and coarser attribution.
    #[serde(default)]
    pub records_no_af: u64,
    /// ALT alleles dropped from records that survived on another ALT. These are invisible
    /// in the two counts above, because those records were published.
    pub alleles: u64,
    /// INFO field IDs that looked like AF/AC/AN metrics but did not match the population
    /// grammar (`EUR_AF`, `AF_nfe`, …). Their columns are gone.
    pub ignored_info_fields: Vec<String>,
    /// Populations carrying `AC` and `AN` but no `AF`. They emit no rows, and are the only
    /// explanation for a non-zero `suppressed.variantsCollapsedToTotal` when the floor is
    /// zero.
    pub populations_without_af: Vec<String>,
}

/// What the k-anonymity floor withheld. The floor itself is recorded in `config`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ConversionSuppressed {
    /// Population rows whose `AC` was below `config.minAlleleCount`.
    pub rows_below_floor: u64,
    /// Further rows removed by the coherence collapse: siblings of a withheld row,
    /// discarded regardless of their own `AC`.
    pub rows_collapsed_to_total: u64,
    /// Variant/allele groups that lost at least one row to the collapse.
    pub variants_collapsed_to_total: u64,
}

/// What reached parquet. `rows + suppressed.rowsBelowFloor + suppressed.rowsCollapsedToTotal`
/// equals the rows that would exist at `minAlleleCount = 0`.
///
/// # The record identity
///
/// `output.recordsEmitted` closes the loop that `output.records` cannot:
///
/// ```text
/// input.records == discarded.recordsUnsupportedContig
///                + discarded.recordsNoSupportedAlt
///                + discarded.recordsAllRowsWithheld
///                + discarded.recordsNoAf
///                + output.recordsEmitted
/// ```
///
/// It is stated over records, not loci, because no identity can link `output.records` to
/// `input.records`. `output.records` counts distinct `(chr, POS, REF, ALT)` alleles, so
/// multi-allelic splitting inflates it, and loci shared across a dataset's VCFs deflate it.
/// Without the identity a manifest can report an input count, every `discarded` counter at
/// zero, and a smaller output count, losing real variants with nothing to account for them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ConversionOutput {
    /// Distinct `(chr, POS, REF, ALT)` loci this VCF produced.
    pub records: u64,
    /// Input records that emitted at least one row: the term that closes the record
    /// identity above. Absent on manifests written before it existed.
    #[serde(default)]
    pub records_emitted: u64,
    /// Total parquet rows written.
    pub rows: u64,
    /// Population labels that actually reached parquet.
    pub populations: Vec<String>,
}

impl From<&crate::convert::ConvertOutput> for ConversionStats {
    fn from(o: &crate::convert::ConvertOutput) -> Self {
        Self {
            input: ConversionInput {
                records: o.drops.input_records,
                non_pass_records: o.drops.non_pass_records,
                gvcf_reference_blocks: o.drops.gvcf_reference_blocks,
                populations_recognized: o.populations_recognized.clone(),
            },
            discarded: ConversionDiscarded {
                records_unsupported_contig: o.drops.dropped_unsupported_contig,
                records_no_supported_alt: o.drops.dropped_no_supported_alt,
                records_all_rows_withheld: o.drops.dropped_all_rows_withheld,
                records_no_af: o.drops.dropped_no_af,
                alleles: o.drops.alleles_discarded,
                ignored_info_fields: o.ignored_info_fields.clone(),
                populations_without_af: o.populations_without_af.clone(),
            },
            suppressed: ConversionSuppressed {
                rows_below_floor: o.suppression.rows_below_floor,
                rows_collapsed_to_total: o.suppression.rows_collapsed_to_total,
                variants_collapsed_to_total: o.suppression.variants_collapsed_to_total,
            },
            output: ConversionOutput {
                records: o.number_of_records,
                records_emitted: o.drops.records_emitted,
                rows: o.rows_emitted,
                populations: o.populations_emitted.clone(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::convert::{ConvertOutput, DropCounts, SuppressionCounts};

    /// A [`ConvertOutput`] whose every counter holds a distinct sentinel, so a `From` impl
    /// that reads the wrong source field (`alleles: o.drops.non_pass_records`) cannot pass.
    fn sentinel_output() -> ConvertOutput {
        ConvertOutput {
            parquet_files: Vec::new(),
            number_of_records: 32,
            diagnostics: Vec::new(),
            drops: DropCounts {
                input_records: 11,
                dropped_unsupported_contig: 12,
                dropped_no_supported_alt: 13,
                gvcf_reference_blocks: 14,
                non_pass_records: 15,
                alleles_discarded: 16,
                alleles_not_left_trimmed: 17,
                dropped_all_rows_withheld: 18,
                dropped_no_af: 20,
                records_emitted: 19,
                total_af_zero_variants: 41,
                ns_peak: Some(42),
            },
            suppression: SuppressionCounts {
                rows_below_floor: 21,
                rows_collapsed_to_total: 22,
                variants_collapsed_to_total: 23,
            },
            rows_emitted: 31,
            populations_recognized: vec!["NO".to_owned(), "Total".to_owned()],
            ignored_info_fields: vec!["EUR_AF".to_owned()],
            populations_without_af: vec!["NO".to_owned()],
            populations_emitted: vec!["Total".to_owned()],
            vcfid: "0123456789abcdef".to_owned(),
            source_sha256: "f".repeat(64),
            source_size: 99,
        }
    }

    #[test]
    fn conversion_stats_from_convert_output_maps_every_field() {
        let o = sentinel_output();
        let s = ConversionStats::from(&o);
        assert_eq!(s.input.records, 11);
        assert_eq!(s.input.non_pass_records, 15);
        assert_eq!(s.input.gvcf_reference_blocks, 14);
        assert_eq!(s.input.populations_recognized, ["NO", "Total"]);
        assert_eq!(s.discarded.records_unsupported_contig, 12);
        assert_eq!(s.discarded.records_no_supported_alt, 13);
        // These two counters are adjacent in meaning, so the sentinel gives every field a
        // distinct value: a mapping that read the other source field must fail here.
        assert_eq!(s.discarded.records_all_rows_withheld, 18);
        assert_eq!(s.discarded.records_no_af, 20);
        assert_eq!(s.discarded.alleles, 16);
        assert_eq!(s.discarded.ignored_info_fields, ["EUR_AF"]);
        assert_eq!(s.discarded.populations_without_af, ["NO"]);
        assert_eq!(s.suppressed.rows_below_floor, 21);
        assert_eq!(s.suppressed.rows_collapsed_to_total, 22);
        assert_eq!(s.suppressed.variants_collapsed_to_total, 23);
        assert_eq!(s.output.records, 32);
        assert_eq!(s.output.rows, 31);
        assert_eq!(s.output.populations, ["Total"]);
    }

    #[test]
    fn conversion_stats_serialize_with_the_documented_keys() {
        // The manifest is an external contract; these key names are the contract.
        let v =
            serde_json::to_value(ConversionStats::from(&sentinel_output())).expect("serializes");
        assert_eq!(v["input"]["records"], 11);
        assert_eq!(v["input"]["nonPassRecords"], 15);
        assert_eq!(v["input"]["gvcfReferenceBlocks"], 14);
        assert_eq!(v["input"]["populationsRecognized"][0], "NO");
        assert_eq!(v["discarded"]["recordsUnsupportedContig"], 12);
        assert_eq!(v["discarded"]["recordsNoSupportedAlt"], 13);
        assert_eq!(v["discarded"]["recordsAllRowsWithheld"], 18);
        assert_eq!(v["discarded"]["recordsNoAf"], 20);
        assert_eq!(v["discarded"]["alleles"], 16);
        assert_eq!(v["discarded"]["ignoredInfoFields"][0], "EUR_AF");
        assert_eq!(v["discarded"]["populationsWithoutAf"][0], "NO");
        assert_eq!(v["suppressed"]["rowsBelowFloor"], 21);
        assert_eq!(v["suppressed"]["rowsCollapsedToTotal"], 22);
        assert_eq!(v["suppressed"]["variantsCollapsedToTotal"], 23);
        assert_eq!(v["output"]["records"], 32);
        assert_eq!(v["output"]["rows"], 31);
        assert_eq!(v["output"]["populations"][0], "Total");
    }

    #[test]
    fn file_entry_omits_conversion_when_absent() {
        let e = FileEntry {
            path: "x.bam".to_owned(),
            sha256: None,
            size: None,
            conversion: None,
        };
        let v = serde_json::to_value(&e).expect("serializes");
        assert!(
            v.get("conversion").is_none(),
            "a non-VCF entry carries no conversion block"
        );
    }

    /// A typo'd or extra key in `config` must be rejected rather than dropped, so a
    /// provider's misspelled security-relevant field (`minAlleleCnt` for `minAlleleCount`)
    /// fails loud at ingest instead of losing its intent.
    #[test]
    fn manifest_config_rejects_unknown_field() {
        let json = r#"{
            "mode": "aggregated",
            "blockRange": 0,
            "minAlleleCnt": 5,
            "assembly": { "reference": "GRCh38" },
            "manifestVersion": 1,
            "generatedBy": "test"
        }"#;
        let err = serde_json::from_str::<ManifestConfig>(json)
            .expect_err("an unknown config field must be rejected");
        assert!(
            err.to_string().contains("unknown field"),
            "unexpected error: {err}"
        );
    }
}
