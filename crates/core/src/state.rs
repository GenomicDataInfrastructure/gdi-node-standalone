//! The served state of a dataset: the node's public state contract.
//!
//! A dependency-free value type, kept out of [`crate::cache`] where it is produced and
//! stored, so a module that only needs to name a state does not depend on the whole cache.
//! [`crate::error::WriterUnknownKind`] is separated for the same reason.

use serde::{Deserialize, Serialize};

/// The served state of a dataset.
///
/// `deleted` is operator sidecar vocabulary, not a served state: a deleted dataset is
/// removed and then `404`s. See [`crate::cache::DELETED_SIDECAR_STATE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DatasetState {
    /// Public: all public metadata served; listed in catalogs/collections.
    Visible,
    /// Served as ID + state only; excluded from listings. The default when ingest
    /// succeeded but no governing `{id}.state.json` sidecar exists.
    Hidden,
    /// A permanent data/validation failure; served as ID + state + a sanitized,
    /// closed-class error message.
    Error,
    /// Queued or being ingested (including waiting to retry a transient failure).
    /// Ephemeral — never persisted to the status index.
    Processing,
}

/// Writes the same lowercase spelling as [`DatasetState::as_str`], so a log field written
/// with `%state` matches the API, the sidecar and the `gdi_dataset_state{state}` label.
/// Log sites must use `%state`, not `?state`: the `Debug` form spells the variant name.
impl std::fmt::Display for DatasetState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl DatasetState {
    /// The canonical lowercase JSON spelling of this state
    /// (`visible`/`hidden`/`error`/`processing`).
    ///
    /// Defines the published `state` string, matching the
    /// `#[serde(rename_all = "lowercase")]` encoding.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Visible => "visible",
            Self::Hidden => "hidden",
            Self::Error => "error",
            Self::Processing => "processing",
        }
    }

    /// Parse an operator-settable **served visibility** from a `.state.json`
    /// sidecar value.
    ///
    /// Only `visible`/`hidden` — the visibilities an operator may set — are
    /// accepted. Every other value yields `None`: the service-internal
    /// `error`/`processing` states are not operator-settable, and the `deleted`
    /// tombstone is handled on a separate path. Callers fail safe to `hidden`.
    #[must_use]
    pub fn from_visibility_str(value: &str) -> Option<Self> {
        match value {
            "visible" => Some(Self::Visible),
            "hidden" => Some(Self::Hidden),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dataset_state_string_round_trips() {
        // `as_str` defines the published `state` string and `from_visibility_str` parses
        // the operator-settable subset. A wrong spelling (`as_str` -> "" / "xyzzy") or a
        // dropped match arm would mis-serve visibility.
        assert_eq!(DatasetState::Visible.as_str(), "visible");
        assert_eq!(DatasetState::Hidden.as_str(), "hidden");
        assert_eq!(DatasetState::Error.as_str(), "error");
        assert_eq!(DatasetState::Processing.as_str(), "processing");

        // Only visible/hidden are operator-settable; every other value -> None.
        assert_eq!(
            DatasetState::from_visibility_str("visible"),
            Some(DatasetState::Visible)
        );
        assert_eq!(
            DatasetState::from_visibility_str("hidden"),
            Some(DatasetState::Hidden)
        );
        assert_eq!(DatasetState::from_visibility_str("error"), None);
        assert_eq!(DatasetState::from_visibility_str("deleted"), None);
        assert_eq!(DatasetState::from_visibility_str("nonsense"), None);

        // Round-trip for the two operator-settable states.
        assert_eq!(
            DatasetState::from_visibility_str(DatasetState::Visible.as_str()),
            Some(DatasetState::Visible)
        );
        assert_eq!(
            DatasetState::from_visibility_str(DatasetState::Hidden.as_str()),
            Some(DatasetState::Hidden)
        );
    }

    /// The serde encoding is the wire format and `as_str` must agree with it. A
    /// `rename_all` change that missed one would publish one string and parse another.
    #[test]
    fn serde_encoding_agrees_with_as_str() {
        for st in [
            DatasetState::Visible,
            DatasetState::Hidden,
            DatasetState::Error,
            DatasetState::Processing,
        ] {
            let json = serde_json::to_string(&st).expect("serialize");
            assert_eq!(json, format!("\"{}\"", st.as_str()), "encoding for {st:?}");
            let back: DatasetState = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, st);
        }
    }
}
