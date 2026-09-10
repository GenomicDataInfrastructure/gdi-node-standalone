//! Core error types. Libraries use typed `thiserror` errors; binaries wrap with `anyhow`.
use thiserror::Error;

/// Why a package's writer cannot be vouched for by its channel: the reason a
/// `[ingest].writer_policy` decision withholds trust. Carried on
/// [`CoreError::WriterRejected`] so the runtime emits the right audit line, plaintext drop
/// against untrusted key, for a package the store-time gate rejected.
///
/// Lives here, beside the error variant that carries it, rather than in `ingest` where it is
/// produced. Nearly every module depends on `error`, so a field pointing back at `ingest`
/// would pull `error` into `ingest`'s dependency cycle and take most of the crate with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriterUnknownKind {
    /// A plaintext staging-dir drop: no crypt4gh envelope, so no writer key to allow-list.
    PlaintextDrop,
    /// A recovered-but-untrusted key (not on the channel allow-list) or an unparseable header
    /// — the recovered fingerprints, if any.
    UntrustedKey(Vec<String>),
}

/// Closed, path-free public error classification (safe for `GET /datasets/{id}/state`
/// and the beacon `errorMessage`).
///
/// The string returned by [`ErrorClass::as_str`] is a stable public contract. It must never
/// contain filesystem paths, hostnames or other sensitive context. That detail belongs only
/// in the structured log, via the `anyhow` cause chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorClass {
    /// Service configuration failed startup preflight.
    InvalidConfig,
    /// Manifest failed schema/required-field validation.
    InvalidManifest,
    /// Parquet failed schema or value validation.
    InvalidParquetSchema,
    /// TAR/staging member failed the safety checks.
    UnsafeArchive,
    /// Catalog not configured on the node.
    UnknownCatalog,
    /// crypt4gh decryption failed (keys present, none decrypted / corrupt).
    DecryptFailed,
    /// A client request asked for more than a configured limit (e.g. a beacon query
    /// matching more rows than `max_query_rows`) — a client error, not a server fault.
    QueryTooLarge,
    /// A request could not be admitted because a server-side resource ceiling is full, such
    /// as the process-wide beacon query-memory budget. Distinct from
    /// [`Self::QueryTooLarge`], which says the request is too broad and the caller must
    /// narrow it (4xx). This one says the request may be fine and the server is saturated,
    /// so the caller should retry later (5xx). Collapsing the two would tell a client its
    /// query was malformed when the node was simply busy.
    ResourceExhausted,
    /// A package's crypt4gh writer key is not in the channel's allow-list under an
    /// `enforce` [`writer_policy`](crate::config::WriterPolicy) — the package decrypted and
    /// validated, but its producer is not trusted for that channel, so it is not published.
    WriterRejected,
    /// A stored dataset failed the at-rest store scrub: a PME (`PARE`) parquet did not
    /// decrypt/authenticate, either because the at-rest bytes were tampered with or
    /// because the key material that wrote them is gone (a wiped/rotated Transit key).
    /// Distinct from [`DecryptFailed`](Self::DecryptFailed), which is the *package*
    /// crypt4gh envelope at ingest; this one is the node's own store, after install.
    ScrubFailed,
    /// Catch-all internal failure.
    InternalError,
}

impl ErrorClass {
    /// Stable, path-free public string.
    ///
    /// # Examples
    ///
    /// ```
    /// use gdi_node_standalone_core::error::ErrorClass;
    ///
    /// // The strings are a stable public contract (no paths/hosts/secrets).
    /// assert_eq!(ErrorClass::InvalidManifest.as_str(), "invalid-manifest");
    /// assert_eq!(ErrorClass::DecryptFailed.as_str(), "decrypt-failed");
    /// ```
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidConfig => "invalid-config",
            Self::InvalidManifest => "invalid-manifest",
            Self::InvalidParquetSchema => "invalid-parquet-schema",
            Self::UnsafeArchive => "unsafe-archive",
            Self::UnknownCatalog => "unknown-catalog",
            Self::DecryptFailed => "decrypt-failed",
            Self::QueryTooLarge => "query-too-large",
            Self::ResourceExhausted => "resource-exhausted",
            Self::WriterRejected => "writer-rejected",
            Self::ScrubFailed => "scrub-failed",
            Self::InternalError => "internal-error",
        }
    }

    /// Parse a public class string (as produced by [`as_str`](Self::as_str)) back into a
    /// variant, or `None` for an unrecognized string. The inverse of [`as_str`](Self::as_str);
    /// used to classify a persisted `error_message` on restart.
    #[must_use]
    pub(crate) fn from_public_str(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == s)
    }

    /// Whether an ingest `error` of this class is attributable to the node's own
    /// configuration or key state, which a restart or a config or Vault fix may have
    /// changed, rather than to the package bytes.
    ///
    /// The ingest runtime clears these at startup so a corrected node re-attempts them,
    /// instead of leaving a dataset branded by a fault the operator has since fixed. Adding
    /// a catalog clears `unknown-catalog`, and restoring a key clears a Vault-derived
    /// `internal-error` or `decrypt-failed`. Data faults, meaning a bad manifest, parquet or
    /// archive, are not retriable: they need a corrected package, so re-attempting them on
    /// every restart only repeats wasted work.
    #[must_use]
    pub(crate) fn is_node_retriable(self) -> bool {
        match self {
            // Node configuration / key material / infra — a restart may fix these.
            // `WriterRejected` is the writer-key allow-list (node config): adding the
            // producer's fingerprint to the channel's allow-list
            // (`[ingest].inbox_allowed_writer_fingerprints` for the inbox, or
            // `[[s3.buckets]].allowed_writer_fingerprints` for a bucket) and restarting
            // should re-admit a package the node rejected.
            Self::InvalidConfig
            | Self::UnknownCatalog
            | Self::DecryptFailed
            | Self::WriterRejected
            | Self::InternalError
            // `ResourceExhausted` belongs here: server saturation is the one shape in this
            // group that clears without a corrected package or a config change, since the
            // same request may succeed once in-flight work drains. `is_transient` agrees,
            // and the two predicates must not disagree about this variant.
            | Self::ResourceExhausted => true,
            // Intrinsic to the stored bytes: a restart cannot change what is on disk.
            //
            // `ScrubFailed` is here because the store-scrub sweep re-verifies the
            // quarantined set every pass and lifts the quarantine when it passes. Clearing
            // it at boot as well would clear it by assumption, ahead of that measurement,
            // and the node would re-serve data it has already proven corrupt. Restoring a
            // wiped or rotated Transit key needs no restart either: the next sweep passes
            // and lifts the quarantine on its own.
            Self::InvalidManifest
            | Self::InvalidParquetSchema
            | Self::UnsafeArchive
            | Self::ScrubFailed
            | Self::QueryTooLarge => false,
        }
    }

    /// Every [`ErrorClass`] variant, in declaration order.
    ///
    /// This is the published taxonomy: the [`as_str`](Self::as_str) strings of these
    /// entries are the closed set of public `error_class` metric labels and
    /// `GET /datasets/{id}/state` `error_message` values. Adding a variant to the
    /// enum forces the exhaustive `match` in [`as_str`](Self::as_str) /
    /// `is_node_retriable` (crate-internal) to fail to compile until it is
    /// updated, which in turn fails the taxonomy golden test — so the published list
    /// cannot silently drift. The `docs/operating.md` §4 taxonomy list is held in sync
    /// by the same golden test, which `include_str!`s the runbook and asserts every
    /// class string appears there.
    pub const ALL: [ErrorClass; 11] = [
        Self::InvalidConfig,
        Self::InvalidManifest,
        Self::InvalidParquetSchema,
        Self::UnsafeArchive,
        Self::UnknownCatalog,
        Self::DecryptFailed,
        Self::QueryTooLarge,
        Self::ResourceExhausted,
        Self::WriterRejected,
        Self::ScrubFailed,
        Self::InternalError,
    ];
}

/// Persisted and served as the stable [`as_str`](ErrorClass::as_str) string, so typing the
/// field changes no on-disk or wire bytes — only what the compiler will accept as a value.
impl serde::Serialize for ErrorClass {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(self.as_str())
    }
}

/// Deserialize a persisted `error_message` leniently: an unrecognized class becomes `None`
/// rather than failing the parse.
///
/// Two invariants meet here, and both require this to be lenient in exactly this way:
///
/// 1. [`crate::cache::StatusIndex::load`] is a strict `serde_json` parse over the whole
///    status index, so one unparseable entry would fail the entire load, dropping every
///    channel and resurrecting every `error` marker. A hand-edited index, or one written
///    by a newer node that knows a class this build does not, must cost at most the class
///    of one entry, never the index.
/// 2. `drain_retriable_errors` clears only faults it can positively identify as
///    node-retriable. Coarsening an unknown class to a *retriable* one (e.g.
///    [`ErrorClass::InternalError`]) would silently make unidentifiable faults drainable
///    and invert that conservatism, so an unknown class must carry no retriable claim.
///
/// The entry and its `error` state always survive; only the unrecognized class is dropped.
///
/// # Errors
///
/// Propagates a deserializer error only for a non-string, non-null value.
pub(crate) fn deserialize_lenient_error_class<'de, D>(de: D) -> Result<Option<ErrorClass>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;
    let raw = Option::<std::borrow::Cow<'_, str>>::deserialize(de)?;
    Ok(raw.and_then(|s| ErrorClass::from_public_str(&s)))
}

/// Library error type. `#[non_exhaustive]` so adding variants is non-breaking.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CoreError {
    /// Service configuration failed startup preflight (carries a non-sensitive
    /// description naming the offending key).
    #[error("invalid config: {detail}")]
    InvalidConfig {
        /// Non-sensitive description (config key + reason, not a path or secret).
        detail: String,
    },
    /// Manifest validation failure (carries a non-sensitive field name).
    #[error("invalid manifest: {detail}")]
    InvalidManifest {
        /// Non-sensitive description (field name, not a path).
        detail: String,
    },
    /// Parquet schema/value validation failure.
    #[error("invalid parquet: {detail}")]
    InvalidParquet {
        /// Non-sensitive description.
        detail: String,
    },
    /// Unsafe archive/staging member.
    #[error("unsafe archive: {detail}")]
    UnsafeArchive {
        /// Non-sensitive description.
        detail: String,
    },
    /// Catalog not configured on the node.
    #[error("unknown catalog: {name}")]
    UnknownCatalog {
        /// The offending catalog name (operator-known, non-sensitive).
        name: String,
    },
    /// crypt4gh decrypt failed.
    #[error("decrypt failed")]
    DecryptFailed,
    /// A client request exceeded a configured limit (e.g. a beacon query matching more
    /// than `max_query_rows` rows). A client error — the caller must narrow the request,
    /// retrying it unchanged cannot help — so it is mapped to a 4xx, not a 5xx.
    #[error("query too large: {detail}")]
    QueryTooLarge {
        /// Non-sensitive description (the limit + how to narrow the request).
        detail: String,
    },
    /// A server-side resource ceiling is full, so the request was not admitted.
    ///
    /// Raised from inside a scan when a retention charge is refused, by the beacon crate's
    /// `RetentionSink`. The process-wide beacon query-memory budget is the only current
    /// source. Transient by construction: nothing about the request is wrong, so the same
    /// request may succeed once in-flight work drains. Callers map it to 503, never 400.
    #[error("resource exhausted: {detail}")]
    ResourceExhausted {
        /// Non-sensitive description of which ceiling was hit.
        detail: String,
    },
    /// A package's crypt4gh writer key is not allow-listed for its channel under an
    /// `enforce` writer policy. Permanent: the package is valid but its producer is not
    /// trusted for that channel, so retrying it unchanged cannot help.
    #[error("writer rejected: {detail}")]
    WriterRejected {
        /// Why the writer could not be vouched for, plaintext drop against untrusted key, so
        /// the runtime emits the right audit line for a store-time-gated package.
        kind: WriterUnknownKind,
        /// Non-sensitive description (channel + that the key is not allow-listed).
        detail: String,
    },
    /// Catch-all internal failure (carries a non-sensitive description).
    #[error("internal error: {detail}")]
    InternalError {
        /// Non-sensitive description (no path or secret).
        detail: String,
    },
    /// A transient backend failure that retrying can fix (e.g. Vault
    /// unreachable while minting a PME data key on ingest). Distinct from the
    /// permanent variants so the ingest runtime can leave the dataset for the next
    /// reconcile rather than quarantining it. Publicly classified as
    /// [`ErrorClass::InternalError`] (the public state contract is path-free and
    /// does not expose a separate transient class).
    #[error("transient backend error: {detail}")]
    Transient {
        /// Non-sensitive description (no path or secret).
        detail: String,
    },
    /// I/O error (path stripped from the public class).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl CoreError {
    /// Whether this error is a transient backend condition that retrying can fix. The
    /// ingest runtime uses this to leave the dataset for the next reconcile instead of
    /// recording a permanent `error` and quarantining it.
    ///
    /// Three cases are transient:
    /// * [`CoreError::Transient`] — an explicit backend transient (e.g. Vault
    ///   unreachable while minting a PME data key).
    /// * [`CoreError::Io`] whose [`std::io::ErrorKind`] is a resource-exhaustion condition:
    ///   `StorageFull` (ENOSPC), `QuotaExceeded` (EDQUOT) or `OutOfMemory` (ENOMEM). A
    ///   scratch disk filling mid-ingest must keep the job `processing` and retry once space
    ///   is freed, rather than fail the dataset and quarantine its only copy. Permanent I/O,
    ///   such as permission denied, not found or read-only filesystem, stays permanent.
    /// * [`CoreError::ResourceExhausted`] — a server-side ceiling was full. Nothing about
    ///   the input is wrong and no operator action clears it, so it must never quarantine.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        match self {
            // `ResourceExhausted` is saturation, not a fault: the same work succeeds once
            // in-flight work drains. `ErrorClass::is_node_retriable` and the variant's own
            // doc both call it transient, and classifying it permanent here would quarantine
            // a dataset for a condition that clears by itself, with no operator action able
            // to lift it. Only the beacon scan path raises it today, so no ingest job reaches
            // this arm, but the next ceiling added on the write path would land here.
            Self::Transient { .. } | Self::ResourceExhausted { .. } => true,
            Self::Io(err) => matches!(
                err.kind(),
                std::io::ErrorKind::StorageFull
                    | std::io::ErrorKind::QuotaExceeded
                    | std::io::ErrorKind::OutOfMemory
            ),
            // Every remaining variant is a permanent, non-retryable fault. Listed explicitly
            // with no `_` wildcard, so adding a `CoreError` variant forces a
            // transient-versus-permanent decision here. The ingest runtime quarantines a
            // permanent error but retries a transient one, so a silent default is a
            // correctness hazard. Mirrors the exhaustive `class()` match.
            Self::InvalidConfig { .. }
            | Self::InvalidManifest { .. }
            | Self::InvalidParquet { .. }
            | Self::UnsafeArchive { .. }
            | Self::UnknownCatalog { .. }
            | Self::DecryptFailed
            | Self::QueryTooLarge { .. }
            | Self::WriterRejected { .. }
            | Self::InternalError { .. } => false,
        }
    }

    /// Whether this is an I/O not-found, meaning the target path vanished. The Beacon scan
    /// path uses it to tell a dataset directory removed mid-scan, a benign delete or
    /// reconcile race that skips the dataset and contributes no rows, from a genuine server
    /// fault that becomes a 500. A dataset that vanishes was in the visible snapshot and is
    /// being removed, never a hidden one, so skipping it is privacy-neutral.
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::Io(err) if err.kind() == std::io::ErrorKind::NotFound)
    }

    /// Map to the closed public class.
    ///
    /// The returned [`ErrorClass`] is path-free and safe to expose publicly.
    ///
    /// # Examples
    ///
    /// ```
    /// use gdi_node_standalone_core::error::{CoreError, ErrorClass};
    ///
    /// let err = CoreError::UnknownCatalog { name: "missing".to_string() };
    /// assert_eq!(err.class(), ErrorClass::UnknownCatalog);
    /// // The public class string carries no sensitive detail.
    /// assert_eq!(err.class().as_str(), "unknown-catalog");
    ///
    /// // A transient backend failure is publicly classified as `internal-error`.
    /// let transient = CoreError::Transient { detail: "vault unreachable".to_string() };
    /// assert!(transient.is_transient());
    /// assert_eq!(transient.class(), ErrorClass::InternalError);
    /// ```
    #[must_use]
    pub fn class(&self) -> ErrorClass {
        match self {
            Self::InvalidConfig { .. } => ErrorClass::InvalidConfig,
            Self::InvalidManifest { .. } => ErrorClass::InvalidManifest,
            Self::InvalidParquet { .. } => ErrorClass::InvalidParquetSchema,
            Self::UnsafeArchive { .. } => ErrorClass::UnsafeArchive,
            Self::UnknownCatalog { .. } => ErrorClass::UnknownCatalog,
            Self::DecryptFailed => ErrorClass::DecryptFailed,
            Self::QueryTooLarge { .. } => ErrorClass::QueryTooLarge,
            Self::ResourceExhausted { .. } => ErrorClass::ResourceExhausted,
            Self::WriterRejected { .. } => ErrorClass::WriterRejected,
            Self::InternalError { .. } | Self::Transient { .. } | Self::Io(_) => {
                ErrorClass::InternalError
            }
        }
    }
}

/// Convenience result alias for fallible `core` library functions.
pub type CoreResult<T> = Result<T, CoreError>;

/// Attach the failing operation and path to an [`std::io::Result`], turning it into a
/// [`CoreError::Io`] whose message names both. The operator-facing cause-chain log line then
/// says which `create_dir_all`, open, rename, copy or write failed, rather than a bare
/// `io error: <kind>`. I/O is the largest ingest fault class, and its log line is the one
/// the runbook cites for root-causing.
///
/// The original [`std::io::ErrorKind`] is preserved, so the transient classification
/// ([`CoreError::is_transient`]: ENOSPC/EDQUOT/ENOMEM) is unchanged and the public
/// [`ErrorClass`] stays `InternalError`. Additive: a bare `?` on an `io::Error` still works,
/// so use this at the filesystem sites worth naming.
pub trait IoResultExt<T> {
    /// Map an `io::Error` to a context-carrying [`CoreError::Io`].
    ///
    /// # Errors
    /// [`CoreError::Io`] naming `op` + `path`, preserving the source `ErrorKind`.
    fn io_ctx(self, op: &str, path: &std::path::Path) -> CoreResult<T>;
}

impl<T> IoResultExt<T> for std::io::Result<T> {
    fn io_ctx(self, op: &str, path: &std::path::Path) -> CoreResult<T> {
        self.map_err(|e| {
            CoreError::Io(std::io::Error::new(
                e.kind(),
                format!("{op} {}: {e}", path.display()),
            ))
        })
    }
}

/// Construct a [`CoreError::InvalidParquet`] from a detail string.
///
/// The single constructor for this variant, so every "invalid parquet" site across
/// `core` (the reader, the converter, and the page/statistics validators) builds it one
/// way instead of repeating the struct literal. `detail` is a non-sensitive description;
/// it becomes the `invalid parquet: {detail}` message.
pub(crate) fn invalid_parquet(detail: impl Into<String>) -> CoreError {
    CoreError::InvalidParquet {
        detail: detail.into(),
    }
}

/// Construct a [`CoreError::InvalidManifest`] from a detail string.
///
/// The single constructor for this variant, shared by `id.rs` and `ingest.rs` so the
/// wording cannot drift. `detail` is a non-sensitive field description, not a path.
pub(crate) fn invalid_manifest(detail: &str) -> CoreError {
    CoreError::InvalidManifest {
        detail: detail.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;

    #[test]
    fn is_not_found_only_for_io_notfound() {
        use std::io::{Error, ErrorKind};
        // A vanished path (dir removed mid-scan) is NotFound.
        assert!(CoreError::Io(Error::from(ErrorKind::NotFound)).is_not_found());
        // Other I/O faults are not "not found": they must stay 500 on the scan path.
        assert!(!CoreError::Io(Error::from(ErrorKind::PermissionDenied)).is_not_found());
        assert!(!CoreError::Io(Error::from(ErrorKind::StorageFull)).is_not_found());
        // Non-I/O errors are never "not found".
        assert!(
            !CoreError::Transient {
                detail: "vault".to_owned()
            }
            .is_not_found()
        );
    }

    #[test]
    fn io_ctx_names_op_and_path_while_preserving_kind_and_class() {
        use std::io::{Error, ErrorKind};
        use std::path::Path;

        // A permanent io error keeps its kind, so permission-denied stays permanent, and
        // names the op and path in its message.
        let denied: std::io::Result<()> = Err(Error::new(ErrorKind::PermissionDenied, "denied"));
        let err = denied
            .io_ctx("create_dir_all", Path::new("/data/.incoming/x"))
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("create_dir_all"), "op must be named: {msg}");
        assert!(
            msg.contains("/data/.incoming/x"),
            "path must be named: {msg}"
        );
        assert!(!err.is_transient(), "permission-denied must stay permanent");
        assert_eq!(
            err.class(),
            ErrorClass::InternalError,
            "class stays path-free"
        );

        // A resource-exhaustion kind is preserved, so it stays transient through the wrap.
        let full: std::io::Result<()> = Err(Error::from(ErrorKind::StorageFull));
        assert!(
            full.io_ctx("copy", Path::new("/data/y"))
                .unwrap_err()
                .is_transient(),
            "StorageFull must remain transient after io_ctx"
        );
    }

    #[test]
    fn error_class_is_closed_and_path_free() {
        let e = CoreError::UnknownCatalog { name: "x".into() };
        assert_eq!(e.class(), ErrorClass::UnknownCatalog);
        // Public class string never contains a path/host.
        assert_eq!(e.class().as_str(), "unknown-catalog");
    }

    #[test]
    fn scrub_failed_is_a_published_class_not_a_raw_string() {
        // `scrub-failed` must reach the wire through this enum, never as a hardcoded string
        // literal at the emitting site. The taxonomy golden test below, and the docs drift
        // guard it drives, can only see a class that is declared here; anything else is an
        // `error_message` value outside the closed set docs/api.md promises.
        assert_eq!(ErrorClass::ScrubFailed.as_str(), "scrub-failed");
        assert!(
            ErrorClass::ALL.contains(&ErrorClass::ScrubFailed),
            "ScrubFailed must be in the published taxonomy"
        );
        assert_eq!(
            ErrorClass::from_public_str("scrub-failed"),
            Some(ErrorClass::ScrubFailed)
        );
        // A scrub failure is a verdict about the bytes already on disk, so a restart cannot
        // change it and must not clear it. The quarantine is lifted by measurement instead:
        // the sweep re-verifies the quarantined set at `Digest` depth every pass and lifts
        // it on a pass. That also self-heals a wiped or rotated Transit key, without a
        // restart. Clearing it at boot would clear it ahead of the measurement, and the
        // first reconcile would re-serve bytes the node has already proven corrupt.
        assert!(!ErrorClass::ScrubFailed.is_node_retriable());
    }

    #[test]
    fn from_public_str_round_trips_as_str() {
        for class in ErrorClass::ALL {
            assert_eq!(ErrorClass::from_public_str(class.as_str()), Some(class));
        }
        assert_eq!(ErrorClass::from_public_str("not-a-real-class"), None);
        assert_eq!(ErrorClass::from_public_str(""), None);
    }

    #[test]
    fn node_retriable_splits_node_faults_from_data_faults() {
        // Node-side faults a restart / config fix / key restore may clear.
        assert!(ErrorClass::InvalidConfig.is_node_retriable());
        assert!(ErrorClass::UnknownCatalog.is_node_retriable());
        assert!(ErrorClass::DecryptFailed.is_node_retriable());
        assert!(ErrorClass::InternalError.is_node_retriable());
        // Data faults intrinsic to the package bytes — only a corrected package clears them.
        assert!(!ErrorClass::InvalidManifest.is_node_retriable());
        assert!(!ErrorClass::InvalidParquetSchema.is_node_retriable());
        assert!(!ErrorClass::UnsafeArchive.is_node_retriable());
    }

    #[test]
    fn error_class_taxonomy_is_complete_and_stable() {
        // The exhaustive `match` (no wildcard) forces a compile error the moment a
        // variant is added, and `ErrorClass::ALL`'s fixed length forces the array to
        // be updated too — together they keep the published `error_class` strings from
        // drifting. The docs/operating.md §4 taxonomy list is guarded separately, at the
        // end of this test.
        for class in ErrorClass::ALL {
            match class {
                ErrorClass::InvalidConfig
                | ErrorClass::InvalidManifest
                | ErrorClass::InvalidParquetSchema
                | ErrorClass::UnsafeArchive
                | ErrorClass::UnknownCatalog
                | ErrorClass::DecryptFailed
                | ErrorClass::QueryTooLarge
                | ErrorClass::ResourceExhausted
                | ErrorClass::WriterRejected
                | ErrorClass::ScrubFailed
                | ErrorClass::InternalError => {}
            }
        }

        // The string contract is exactly this golden list, in declaration order.
        let golden: [&str; 11] = [
            "invalid-config",
            "invalid-manifest",
            "invalid-parquet-schema",
            "unsafe-archive",
            "unknown-catalog",
            "decrypt-failed",
            "query-too-large",
            "resource-exhausted",
            "writer-rejected",
            "scrub-failed",
            "internal-error",
        ];
        let actual: Vec<&str> = ErrorClass::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(actual, golden, "published error_class taxonomy drifted");

        // Strings are unique and path-free.
        let mut seen = std::collections::HashSet::new();
        for s in golden {
            assert!(seen.insert(s), "duplicate error_class string: {s}");
            assert!(
                !s.chars().any(|c| matches!(c, '/' | '\\' | ' ' | ':')),
                "error_class string is not path-free: {s}"
            );
        }

        // Doc-side drift guard: the same taxonomy is enumerated for operators in
        // docs/operating.md §4 and for integrators in docs/api.md, which tells a client it
        // "may match on them exhaustively". `include_str!` embeds both at compile time, so a
        // moved or renamed file fails the build. The comparison is set equality in both
        // directions: a class missing from a doc fails, and so does a doc row for a class
        // the node can never emit. Only the enumerations are read, scoped by the text that
        // introduces each, so a sentence that happens to contain "internal-error" can
        // neither satisfy nor pollute the guard.
        let declared: std::collections::BTreeSet<&str> =
            ErrorClass::ALL.iter().map(|c| c.as_str()).collect();

        // docs/api.md: the `error_message` vocabulary table, reading the first backticked
        // cell of each row only. The Cause column quotes other identifiers such as
        // `manifest.json` and `numberOfRecords`, which are not classes.
        let api_md = include_str!("../../../docs/api.md");
        let (_, table) = api_md
            .split_once("| `error_message` | Cause |")
            .expect("docs/api.md lost its `error_message` vocabulary table");
        let table = table.split("\n\n").next().unwrap_or_default();
        let in_api: std::collections::BTreeSet<&str> = table
            .lines()
            .filter_map(|row| row.strip_prefix("| `"))
            .filter_map(|rest| rest.split('`').next())
            .collect();
        assert_eq!(
            declared, in_api,
            "docs/api.md's `error_message` vocabulary table disagrees with ErrorClass::ALL"
        );

        // docs/operating.md §4: the inline "full published set" list.
        let operating_md = include_str!("../../../docs/operating.md");
        let (_, list) = operating_md
            .split_once("closed, sanitized class** (one of")
            .expect("docs/operating.md §4 lost its `error_message` class list");
        let (list, _) = list
            .split_once("— the full published set")
            .expect("docs/operating.md §4's class list lost its closing phrase");
        let in_operating: std::collections::BTreeSet<&str> =
            list.split('`').skip(1).step_by(2).collect();
        assert_eq!(
            declared, in_operating,
            "docs/operating.md §4's `error_message` class list disagrees with ErrorClass::ALL"
        );
    }

    #[test]
    fn resource_exhaustion_io_errors_are_transient() {
        use std::io::{Error, ErrorKind};
        // A full scratch disk, an exceeded quota or an OOM during ingest is transient: the
        // ingest runtime must leave the job `processing` and retry, rather than record a
        // permanent `error` and quarantine the only copy of the package.
        assert!(CoreError::Io(Error::from(ErrorKind::StorageFull)).is_transient());
        assert!(CoreError::Io(Error::from(ErrorKind::QuotaExceeded)).is_transient());
        assert!(CoreError::Io(Error::from(ErrorKind::OutOfMemory)).is_transient());
        // ENOSPC arriving as a raw OS error is decoded to `StorageFull` by libstd
        // (Rust >= 1.83 `io_error_more`) and is likewise transient.
        assert!(CoreError::Io(Error::from_raw_os_error(28)).is_transient());
    }

    #[test]
    fn permanent_io_errors_are_not_transient() {
        use std::io::{Error, ErrorKind};
        // A genuinely permanent I/O condition that retrying cannot fix must stay
        // permanent (otherwise a misconfigured read-only mount would loop forever).
        assert!(!CoreError::Io(Error::from(ErrorKind::PermissionDenied)).is_transient());
        assert!(!CoreError::Io(Error::from(ErrorKind::NotFound)).is_transient());
        assert!(!CoreError::Io(Error::from(ErrorKind::ReadOnlyFilesystem)).is_transient());
    }

    #[test]
    fn explicit_transient_variant_is_transient() {
        assert!(
            CoreError::Transient {
                detail: "vault unreachable".to_owned()
            }
            .is_transient()
        );
        assert!(
            !CoreError::InternalError {
                detail: "boom".to_owned()
            }
            .is_transient()
        );
    }

    #[test]
    fn the_two_retry_predicates_agree_that_saturation_is_not_a_fault() {
        // These are different questions, so neither can answer the other. `is_transient`
        // asks whether to retry this in-flight attempt with backoff; `is_node_retriable`
        // asks whether to clear this recorded error at startup. For `ResourceExhausted`
        // they must still answer the same way. Permanent means quarantine, and no operator
        // action clears a quarantine imposed because the node was momentarily busy.
        let saturated = CoreError::ResourceExhausted {
            detail: "process-wide beacon query memory budget is full".to_owned(),
        };
        assert!(
            saturated.is_transient(),
            "saturation clears by itself, so the in-flight attempt must be retried"
        );
        assert!(
            saturated.class().is_node_retriable(),
            "and a recorded one must be cleared at startup, not left branded"
        );
    }
}
