//! Shared metadata building blocks used by both `package.yaml` and `manifest.json`.
//!
//! Field names on the wire are camelCase (`hasEmail`, `accessRights`); the vCard `fn`
//! token is a Rust keyword and is mapped explicitly with `#[serde(rename = "fn")]`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Either a plain string or a BCP-47 language map (e.g. `{en: "...", et: "..."}`).
///
/// Used for the localized `title` and `description` fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum LocalizedText {
    /// Single untagged value.
    Plain(String),
    /// Language-tagged values, keyed by BCP-47 tag.
    Map(BTreeMap<String, String>),
}

/// An agent (creator / contributor). Maps to `foaf:Agent`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Agent {
    /// `foaf:name`.
    pub name: String,
}

/// A vCard-style contact point (`vcard:Kind`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ContactPoint {
    /// `vcard:fn` (required when a contact point is present).
    #[serde(rename = "fn", skip_serializing_if = "Option::is_none")]
    pub fn_: Option<String>,
    /// `vcard:hasEmail` (required when a contact point is present).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_email: Option<String>,
    /// `vcard:hasURL` (optional; recommended sub-field).
    #[serde(rename = "hasURL", skip_serializing_if = "Option::is_none")]
    pub has_url: Option<String>,
}

/// A secondary identifier (`adms:identifier`).
//
// No `deny_unknown_fields` here. Not a doc comment, because schemars would publish it as
// the type's `description`.
//
// This type tolerates unknown keys, as package-format.md requires. The node deserialises
// this shape out of a provider's `manifest.json`, so an older node must tolerate a field a
// newer package added rather than reject the package over a section it discards anyway.
// Denying unknown keys would make an older node reject an entire conformant package, losing
// a whole dataset, over one optional identifier field.
//
// A mistyped key is caught where it can be fixed, at the producer: `gdi-dataset-tool build`
// reports unrecognised keys as a warning and `build --strict` as an error. Strict on write,
// lenient on read.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct OtherIdentifier {
    /// `skos:notation` (required within the identifier).
    pub notation: String,
    /// `adms:schemaAgency` (recommended within the identifier).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_agency: Option<String>,
    /// Optional human-readable name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// The dataset assembly the node reads (`config.assembly`): just the build `reference`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Assembly {
    /// Assembly build, e.g. `GRCh38`.
    pub reference: String,
}

/// The kind of genomic data a dataset package carries (`config.mode`).
///
/// This is the data-content axis, distinct from the Beacon request granularity (boolean,
/// count or record) and from the `individuals` entry-type endpoint name. Only `aggregated`
/// is implemented. `individual` is reserved for the individual-level record tier, and both
/// package validation and ingest reject it.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum DatasetMode {
    /// Aggregated allele frequencies, or cohort summary statistics. The only mode built.
    Aggregated,
    /// Individual-level genotypes, one record per sample. Reserved, not yet supported.
    Individual,
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;

    #[test]
    fn dataset_mode_serializes_to_lowercase_wire_strings() {
        assert_eq!(
            serde_json::to_string(&DatasetMode::Aggregated).unwrap(),
            "\"aggregated\""
        );
        assert_eq!(
            serde_json::to_string(&DatasetMode::Individual).unwrap(),
            "\"individual\""
        );
    }

    #[test]
    fn dataset_mode_deserializes_from_wire_strings() {
        let agg: DatasetMode = serde_json::from_str("\"aggregated\"").unwrap();
        assert_eq!(agg, DatasetMode::Aggregated);
        let ind: DatasetMode = serde_json::from_str("\"individual\"").unwrap();
        assert_eq!(ind, DatasetMode::Individual);
    }

    #[test]
    fn dataset_mode_rejects_legacy_bool_and_unknown() {
        // Clean break: the legacy boolean `aggregated` form is no longer accepted,
        // and unrelated tokens are rejected rather than silently defaulted.
        assert!(serde_json::from_str::<DatasetMode>("true").is_err());
        assert!(serde_json::from_str::<DatasetMode>("\"genotype\"").is_err());
    }
}

/// What the packaged `headers/{vcfId}.vcf` members contain.
///
/// Recorded in the non-public `internal` section, which the node strips at ingest and an
/// integrating system reads, so a consumer knows what it holds without re-deriving it and a
/// package claiming a restrictive policy can be checked rather than trusted.
///
/// Every value names something checkable. There is no "mostly full" middle value: a
/// sanitiser whose output cannot be characterised is worse than none, because the consumer
/// cannot know what was removed and a reviewer cannot check the claim.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum HeaderPolicy {
    /// No `headers/` member at all (`--no-headers`).
    None,
    /// Structural keys only (`fileformat`, `INFO`, `FORMAT`, `FILTER`, `contig`,
    /// `reference`, `assembly`), with `#CHROM` truncated to the eight fixed columns.
    ///
    /// The default. An allow-list, not a deny-list: every mainstream toolchain stamps its
    /// own command line into the header (`##bcftools_viewCommand`, `##GATKCommandLine`,
    /// `##DRAGENCommandLine`, `##source`), each carrying whatever was on that command line,
    /// including sample identifiers and internal filesystem paths. A deny-list needs an
    /// entry per tool and fails open for the key nobody has invented yet.
    #[default]
    Minimal,
    /// `Minimal` plus the structured subject identifiers: the `#CHROM` sample columns and
    /// the `##SAMPLE` and `##PEDIGREE` lines. Free-text command lines are still dropped.
    ///
    /// Opt-in. Whether subject identifiers may travel in a package is a data-protection
    /// decision, not an engineering one.
    WithIdentifiers,
    /// The source header byte-for-byte, including command lines, filesystem paths and
    /// anything else the producing toolchain stamped in. Verifiable by comparing against
    /// the source; opt-in for the same reason as `WithIdentifiers`, and then some.
    Verbatim,
}

/// Non-public bookkeeping (node-opaque; stripped at ingest; read only by an integrating
/// system, if one is run).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Internal {
    /// Optional organisation-internal handle. The node assigns it no meaning; it travels in
    /// the non-public section for whoever consumes that section to interpret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal_id: Option<String>,
    /// Optional single dataset ID this one supersedes (immediate predecessor).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub past_version: Option<String>,
    /// What the packaged `headers/` members contain. Absent on packages built before the
    /// policy existed, which a consumer must treat as unknown rather than as any particular
    /// policy. Those packages were effectively `verbatim` apart from the `#CHROM` line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_policy: Option<HeaderPolicy>,
}
