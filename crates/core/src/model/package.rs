//! The human-authored `package.yaml` input model (deserialize only, via `serde-saphyr`).
//!
//! Mirrors the manifest's four sections but:
//! `metadata` carries `prefix`/`org` (not `datasetId`/`numberOfRecords`), `config` omits the
//! node-computed `assembly`/`manifestVersion`/`generatedBy`, and file entries may be a bare
//! path string OR a `{path, sha256?, size?}` object (sha256/size optional — computed if absent).

use super::metadata::{Agent, ContactPoint, DatasetMode, Internal, LocalizedText, OtherIdentifier};
use serde::{Deserialize, Serialize};

/// The full user-authored package input.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PackageYaml {
    /// FDP-public, per-dataset metadata.
    pub metadata: PackageMetadata,
    /// Content/provenance inventory (the VCF group drives parquet conversion).
    #[serde(default)]
    pub files: Vec<PackageFileGroup>,
    /// Non-public bookkeeping (node-opaque).
    #[serde(default)]
    pub internal: Internal,
    /// Processing options.
    pub config: PackageConfig,
}

/// The `metadata` section of a `package.yaml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PackageMetadata {
    /// `GOE` or `GDI` prefix for the dataset ID (replaced by `datasetId` in the manifest).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// Institute abbreviation for the dataset ID (e.g. `UTARTU`, `DKFZ`, `HRI`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    /// Catalog name; must match a catalog defined in the service config.
    pub catalog: String,
    /// Dataset title (plain string or language map).
    pub title: LocalizedText,
    /// Free-text description (plain string or language map).
    #[serde(skip_serializing_if = "Option::is_none")]
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
    /// Dataset type IRI — set only for synthetic datasets.
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
}

/// The `config` section of a `package.yaml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PackageConfig {
    /// Data-content mode; `aggregated` = allele frequencies (the only mode implemented).
    pub mode: DatasetMode,
    /// Position-based block range in bases (`0` = single file per chromosome).
    ///
    /// Defaults to 10 000 000 (10 Mb) when omitted — the sharding size that keeps a
    /// human chromosome to a handful of files while staying coarse enough to avoid
    /// fragmentation. Set explicitly (including `0`) to override.
    #[serde(default = "default_block_range")]
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
    ///
    /// This is the build-time floor. Rows below it are dropped from the package at
    /// `gdi-dataset-tool build` and never reach a node, so it is irreversible without
    /// rebuilding. It is a separate knob from the node's serve-time
    /// `[beacon].min_allele_count`, which applies to every response and can be retuned by
    /// restarting. The two compose: the effective floor is `max(build-time, serve-time)`,
    /// so leaving this at 0 is fine provided the node sets its own.
    #[serde(default)]
    pub min_allele_count: u32,
    /// Declared sensitive-tier individual-match-count floor (recorded, not applied here).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hide_lower_counts: Option<u32>,
}

/// Default `blockRange` (10 Mb) applied when a `package.yaml` omits it — see
/// [`PackageConfig::block_range`].
fn default_block_range() -> u32 {
    10_000_000
}

/// A group of files of one category in a `package.yaml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PackageFileGroup {
    /// File category; `VCF` is the one reserved value (case-insensitive).
    pub category: String,
    /// Assembly build (required on the VCF group, optional otherwise).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// Patch-level provenance (not used for matching).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub precise_reference: Option<String>,
    /// The files in this group; each entry is a bare path or a `{path, sha256?, size?}` object.
    pub files: Vec<PackageFileEntry>,
}

/// A `package.yaml` file entry: a bare path string, or an object with an optional checksum
/// and size.
///
/// `Serialize` stays derived (`untagged`), so a `Path` serializes as a bare string and a
/// `WithMeta` as a `{path, …}` map. `Deserialize` is implemented by hand rather than derived:
/// a derived `#[serde(untagged)]` enum cannot honour `deny_unknown_fields` on its struct
/// variant, because serde ignores it under `untagged` and `flatten`. A mistyped `sha256` or
/// `size` key would then be dropped and the "verified if provided" checksum guard skipped.
/// The manual impl rejects unknown keys on the map form, matching the strictness every other
/// `package.yaml` struct gets from `deny_unknown_fields`.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum PackageFileEntry {
    /// Bare path string (`sha256`/`size` computed at build).
    Path(String),
    /// Path with optionally-provided `sha256`/`size` (verified if present).
    WithMeta {
        /// File path (relative to the YAML or absolute).
        path: String,
        /// SHA-256 checksum, verified against the file if provided.
        #[serde(skip_serializing_if = "Option::is_none")]
        sha256: Option<String>,
        /// File size in bytes, verified against the file if provided.
        #[serde(skip_serializing_if = "Option::is_none")]
        size: Option<u64>,
    },
}

impl<'de> Deserialize<'de> for PackageFileEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct EntryVisitor;

        impl<'de> serde::de::Visitor<'de> for EntryVisitor {
            type Value = PackageFileEntry;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a file path string or a {path, sha256?, size?} map")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(PackageFileEntry::Path(v.to_owned()))
            }

            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(PackageFileEntry::Path(v))
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut path: Option<String> = None;
                let mut sha256: Option<String> = None;
                let mut size: Option<u64> = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "path" => {
                            if path.is_some() {
                                return Err(serde::de::Error::duplicate_field("path"));
                            }
                            path = Some(map.next_value()?);
                        }
                        "sha256" => {
                            if sha256.is_some() {
                                return Err(serde::de::Error::duplicate_field("sha256"));
                            }
                            sha256 = Some(map.next_value()?);
                        }
                        "size" => {
                            if size.is_some() {
                                return Err(serde::de::Error::duplicate_field("size"));
                            }
                            size = Some(map.next_value()?);
                        }
                        other => {
                            return Err(serde::de::Error::unknown_field(
                                other,
                                &["path", "sha256", "size"],
                            ));
                        }
                    }
                }
                let path = path.ok_or_else(|| serde::de::Error::missing_field("path"))?;
                Ok(PackageFileEntry::WithMeta { path, sha256, size })
            }
        }

        deserializer.deserialize_any(EntryVisitor)
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;

    #[test]
    fn block_range_defaults_to_ten_million_when_omitted() {
        // A `config` that omits `blockRange` must deserialize to the 10 Mb sharding
        // default, not 0 (unsharded) and not a missing-field error.
        let cfg: PackageConfig = serde_saphyr::from_str("mode: aggregated\n").unwrap();
        assert_eq!(cfg.block_range, 10_000_000);
    }

    #[test]
    fn block_range_honors_an_explicit_value() {
        let cfg: PackageConfig =
            serde_saphyr::from_str("mode: aggregated\nblockRange: 0\n").unwrap();
        assert_eq!(cfg.block_range, 0);
    }

    #[test]
    fn file_entry_rejects_unknown_key() {
        // A mistyped checksum key such as `sh256` must be a hard parse error rather than
        // being dropped. Otherwise a provider who pins a checksum but mistypes the key gets
        // `sha256 = None` and the documented "verified if provided" guard is skipped, while
        // every other typo in the same YAML hard-fails via `deny_unknown_fields`. The
        // file-entry map form must be equally strict.
        let err = serde_saphyr::from_str::<PackageFileEntry>("path: f.vcf\nsh256: deadbeef\n")
            .expect_err("an unknown key on a file entry must be rejected");
        let msg = format!("{err}").to_ascii_lowercase();
        assert!(
            msg.contains("sh256") || msg.contains("unknown"),
            "the error must flag the unknown field: {msg}"
        );
    }

    #[test]
    fn file_entry_accepts_bare_string_and_valid_map() {
        // A bare path string → `Path`; a well-formed `{path, sha256?, size?}` map →
        // `WithMeta` with the parsed fields (the two legitimate shapes still round-trip).
        let bare: PackageFileEntry = serde_saphyr::from_str("f.vcf").unwrap();
        std::assert_matches!(bare, PackageFileEntry::Path(p) if p == "f.vcf");

        let meta: PackageFileEntry =
            serde_saphyr::from_str("path: f.vcf\nsha256: abc123\nsize: 42\n").unwrap();
        match meta {
            PackageFileEntry::WithMeta { path, sha256, size } => {
                assert_eq!(path, "f.vcf");
                assert_eq!(sha256.as_deref(), Some("abc123"));
                assert_eq!(size, Some(42));
            }
            PackageFileEntry::Path(_) => panic!("a map form must deserialize to WithMeta"),
        }

        // A map with only `path` (no checksum/size) is still valid → WithMeta with Nones.
        let path_only: PackageFileEntry = serde_saphyr::from_str("path: g.vcf\n").unwrap();
        std::assert_matches!(
            path_only,
            PackageFileEntry::WithMeta {
                sha256: None,
                size: None,
                ..
            }
        );
    }
}
