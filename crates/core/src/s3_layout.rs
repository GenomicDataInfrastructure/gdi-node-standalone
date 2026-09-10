//! The shared S3 object-name contract between `gdi-dataset-tool` (writer) and the
//! `gdi-node-standalone` service (reader).
//!
//! These constants are the wire contract of the flat S3 bucket layout. The tool writes
//! `{id}.tar.c4gh` packages and `{id}.state.json` visibility sidecars, and bumps
//! `_sync_marker.json`. The service reconciles the same names and writes
//! `_status/{id}.json` results. Both crates resolve the identical string from this module,
//! so a one-sided rename cannot break sync silently.
//!
//! This module is feature-free: the string constants and the sidecar wire shape, no client
//! logic. The S3 client code stays in each crate's own `s3` module.

use serde::{Deserialize, Serialize};

/// The encrypted-package suffix: a dataset package is stored as `{id}.tar.c4gh`.
pub const TAR_C4GH_SUFFIX: &str = ".tar.c4gh";

/// The operator metadata-overlay suffix: `{id}.metadata.json`.
///
/// The fifth bucket-root object name. It belongs here and in the pinning test below with
/// its siblings: a deleting client that cannot see the name orphans the object.
pub const OVERLAY_SUFFIX: &str = ".metadata.json";

/// Maximum size of a bucket control object: the small JSON sidecars
/// (`{id}.state.json`, `{id}.metadata.json`, `_status/{id}.json`, `_sync_marker.json`)
/// both binaries read before parsing.
///
/// A shared-bucket writer is a distinct principal from the node, since the trust boundary
/// is the bucket, so an oversized control object is a cheap memory-exhaustion lever against
/// whoever reads it. The node and the tool share this one constant so their limits cannot
/// drift apart.
pub const MAX_CONTROL_OBJECT_BYTES: u64 = 1024 * 1024;

/// The visibility-sidecar suffix: a dataset's served visibility is recorded in
/// `{id}.state.json` (`{"state":"visible"|"hidden"|"deleted"}`).
pub const STATE_SUFFIX: &str = ".state.json";

/// The change-detection marker object at the bucket root, bumped by the tool on
/// any mutation and `HeadObject`-polled by the service.
pub const MARKER_KEY: &str = "_sync_marker.json";

/// The reserved prefix for node-written status objects (`_status/{id}.json`),
/// ignored by the tool on `list` and by the service on reconcile.
pub const STATUS_PREFIX: &str = "_status/";

/// The maximum number of objects either crate will buffer or scan from a single bucket
/// listing before failing closed. A shared bucket is a co-tenant trust boundary, so an
/// unbounded `list` is an out-of-memory vector for both the long-running service and the
/// operator's CLI. Set here once so the reader and writer cannot diverge on the ceiling.
pub const MAX_BUCKET_OBJECTS: usize = 1_000_000;

/// Filename prefix of a per-`(chr, block)` allele-frequency data file inside a package or
/// staging directory (`allele-freq.chr{CHR}.{block}.br{range}.{vcfid}.parquet`).
pub const DATA_FILE_PREFIX: &str = "allele-freq.";

/// Filename suffix (extension) of a data file.
pub const DATA_FILE_SUFFIX: &str = ".parquet";

/// Whether `name` is a data-file name by the flat `allele-freq.*.parquet` convention.
///
/// This is the loose prefix/suffix membership test the store scans, the digest walk and the
/// packer use to select data files. It does not validate the full
/// `allele-freq.chr{CHR}.{block}.br{range}.{vcfid}.parquet` structure. That stricter check,
/// covering component count and recognized chromosome, lives in the ingest validator. The
/// two literals live here so they cannot drift across `core`, the service and the tool.
#[must_use]
pub fn is_data_file_name(name: &str) -> bool {
    name.starts_with(DATA_FILE_PREFIX) && name.ends_with(DATA_FILE_SUFFIX)
}

/// The parsed `{id}.state.json` visibility sidecar: the operator's declarative state
/// intent. It is the single model every reader shares, so the wire shape cannot drift
/// across the tool, which writes it and lists it from S3, and the service, which reads it
/// on S3 reconcile and inbox scan.
///
/// Parsed leniently, per the forward-compatibility contract: unknown keys are tolerated,
/// notably the writer's `schemaVersion` discriminator, and a missing `force` defaults to
/// `false`. Writers emit `{"schemaVersion":1,"state":"<state>"[,"force":true]}`. An
/// unrecognised `state` is the reader's concern, and every reader maps an unknown or absent
/// state to a fail-safe `hidden`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct StateSidecar {
    /// The declared served state: `visible` | `hidden` | `deleted`.
    pub state: String,
    /// For `deleted` only: bypass the visible-dataset delete guard. Absent means `false`,
    /// and the field is irrelevant for `visible` and `hidden`.
    #[serde(default)]
    pub force: bool,
    /// Optional W3C `traceparent`. When an orchestrator stamps its own trace context here,
    /// and the node is configured to trust inbound trace context, the node parents the
    /// package's `ingest_job` span under it, so a publish can be correlated with its ingest
    /// across the S3 handoff, which carries no HTTP headers. Absent means a fresh
    /// server-side root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traceparent: Option<String>,
}

/// The `schemaVersion` stamped on every `_status/{id}.json` writeback object.
pub const STATUS_SCHEMA_VERSION: u32 = 1;

/// The status-writeback object the service publishes at `_status/{id}.json` and the tool
/// reads back to detect drift.
///
/// One model is shared by the service, which writes it, and the tool, which reads it, so a
/// field rename on one side cannot silently deserialize to a default on the other and
/// defeat the tool's freshness check.
///
/// The read side is lenient: the tool consults only `state`, `source_signature` and
/// `error_message`, and the discriminator and provenance fields `schemaVersion`, `id` and
/// `updated_at` default when absent, so an older or partial object still parses. Only
/// `state` is required.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct StatusWriteback {
    /// Schema version of this writeback object; `1` today. Readers ignore it under the
    /// lenient parse, matching `manifestVersion`.
    #[serde(rename = "schemaVersion", default)]
    pub schema_version: u32,
    /// The dataset id.
    #[serde(default)]
    pub id: String,
    /// The node's reported state: `processing` | `visible` | `hidden` | `error` | `deleted`.
    pub state: String,
    /// Sanitized closed-class error message (present only on `error`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    /// The `ETag` of the `.tar.c4gh` this result describes: the freshness key a reader
    /// compares against the current package `ETag`. Absent only on `deleted`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_signature: Option<String>,
    /// RFC3339 write time.
    #[serde(default)]
    pub updated_at: String,
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;

    /// Pin the exact wire-contract literals. Consumers interpolate these symbols
    /// (`format!("{id}{TAR_C4GH_SUFFIX}")`), so a one-sided rename would break tool/service
    /// sync without any other test failing.
    #[test]
    fn wire_contract_literals_are_pinned() {
        // These literals name objects in the flat S3 bucket layout, the on-wire contract
        // shared by the tool (writer) and the service (reader). Changing one is a breaking
        // wire change: it orphans every object already written under the old name and
        // desyncs any orchestrator or doc that builds these keys.
        const WHY: &str = "S3 object-naming wire contract changed: this orphans objects \
            already written under the old name and desyncs the tool/orchestrator/docs; treat \
            it as a breaking change and migrate every reader together";
        assert_eq!(TAR_C4GH_SUFFIX, ".tar.c4gh", "{WHY}");
        assert_eq!(STATE_SUFFIX, ".state.json", "{WHY}");
        assert_eq!(MARKER_KEY, "_sync_marker.json", "{WHY}");
        assert_eq!(STATUS_PREFIX, "_status/", "{WHY}");
        assert_eq!(OVERLAY_SUFFIX, ".metadata.json", "{WHY}");
    }

    /// The control-object cap is a shared limit, not a per-crate preference: the node and
    /// the tool must refuse the same oversized sidecar, or one of them is the soft target.
    #[test]
    fn control_object_cap_is_one_mib() {
        assert_eq!(MAX_CONTROL_OBJECT_BYTES, 1024 * 1024);
    }

    /// The shared sidecar parses leniently: the writer's `schemaVersion` discriminator is
    /// tolerated, `force` defaults to `false`, and only `state` is required.
    #[test]
    fn state_sidecar_parses_leniently() {
        let visible: StateSidecar =
            serde_json::from_str(r#"{"schemaVersion":1,"state":"visible"}"#).unwrap();
        assert_eq!(visible.state, "visible");
        assert!(!visible.force);

        let deleted: StateSidecar =
            serde_json::from_str(r#"{"schemaVersion":1,"state":"deleted","force":true}"#).unwrap();
        assert_eq!(deleted.state, "deleted");
        assert!(deleted.force);

        // An optional `traceparent` is parsed when present and defaults to None, so a
        // sidecar without it is unaffected.
        assert_eq!(visible.traceparent, None);
        let traced: StateSidecar = serde_json::from_str(
            r#"{"state":"visible","traceparent":"00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"}"#,
        )
        .unwrap();
        assert_eq!(
            traced.traceparent.as_deref(),
            Some("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
        );
    }

    /// Pin the `_status/{id}.json` wire keys (the exact JSON the tool reads) and prove the
    /// shared struct round-trips, so a rename on the shared model is caught here rather than
    /// breaking the tool's freshness check. `error_message` and `source_signature` are
    /// omitted when absent; the rest are always present.
    #[test]
    fn status_writeback_wire_shape_is_pinned() {
        let obj = StatusWriteback {
            schema_version: STATUS_SCHEMA_VERSION,
            id: "GDI-1".to_owned(),
            state: "error".to_owned(),
            error_message: Some("decrypt-failed".to_owned()),
            source_signature: Some("etag-1".to_owned()),
            updated_at: "2026-07-06T00:00:00Z".to_owned(),
        };
        let v: serde_json::Value = serde_json::to_value(&obj).unwrap();
        let keys: std::collections::BTreeSet<&str> =
            v.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "schemaVersion",
                "id",
                "state",
                "error_message",
                "source_signature",
                "updated_at"
            ]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
            "_status writeback wire keys changed: {v}"
        );

        // omit-on-none: a deleted tombstone drops error_message + source_signature.
        let deleted = StatusWriteback {
            schema_version: STATUS_SCHEMA_VERSION,
            id: "GDI-1".to_owned(),
            state: "deleted".to_owned(),
            updated_at: "2026-07-06T00:00:00Z".to_owned(),
            ..StatusWriteback::default()
        };
        let dv: serde_json::Value = serde_json::to_value(&deleted).unwrap();
        assert!(dv.get("error_message").is_none(), "{dv}");
        assert!(dv.get("source_signature").is_none(), "{dv}");

        // Round-trips, and a minimal `{"state":...}` still parses (reader leniency).
        let back: StatusWriteback = serde_json::from_value(v).unwrap();
        assert_eq!(back.state, "error");
        assert_eq!(back.source_signature.as_deref(), Some("etag-1"));
        let minimal: StatusWriteback = serde_json::from_str(r#"{"state":"visible"}"#).unwrap();
        assert_eq!(minimal.state, "visible");
        assert_eq!(minimal.schema_version, 0);
    }
}
