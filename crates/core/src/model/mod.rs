//! Typed data models for the `package.yaml` input and the generated `manifest.json`.
//!
//! `package.yaml` carries four sections — `metadata` / `files` / `internal` / `config`;
//! the generated `manifest.json` carries those four plus `payload` (the digests of the
//! packaged bytes, added alongside ingest-time verification). Defined in [`metadata`]
//! (shared building blocks), [`package`] (input YAML) and [`manifest`] (generated output),
//! with [`overlay`] holding the operator-patch shape that edits a served manifest.

pub mod manifest;
pub mod metadata;
pub mod overlay;
pub mod package;

pub use manifest::{
    ConversionDiscarded, ConversionInput, ConversionOutput, ConversionStats, ConversionSuppressed,
    FileEntry, FileGroup, Manifest, ManifestConfig, ManifestMetadata, Payload, PayloadEntry,
    SUPPORTED_MANIFEST_VERSION,
};
pub use metadata::{
    Agent, Assembly, ContactPoint, DatasetMode, HeaderPolicy, Internal, LocalizedText,
    OtherIdentifier,
};
pub use overlay::MetadataOverlay;
pub use package::{
    PackageConfig, PackageFileEntry, PackageFileGroup, PackageMetadata, PackageYaml,
};

// The derived JSON Schemas for the manifest and handoff sidecars live in
// `crate::schema`, a single registry the freshness guard loops over.
