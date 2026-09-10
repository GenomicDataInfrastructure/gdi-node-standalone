//! The `status` data model: a dataset's resolved **node state**, its **sync
//! summary** relative to S3, and (with `--diff`) the granular file/`ETag`/state
//! difference between the bucket objects and the node's writeback.
//!
//! State resolution:
//! 1. the management plane `GET /datasets/{id}/state` when reachable (in-cluster /
//!    loopback) — the authoritative state + channel;
//! 2. else a **remote** tool reads `_status/{id}.json` from the bucket, matching
//!    its `source_signature` against the current `.tar.c4gh` `ETag` — reporting the
//!    published node state, **pending** (stale signature), or
//!    **unavailable** (no writeback — `write_status` off or not yet written);
//! 3. an inbox-owned (local) dataset has no remote, so its sync is `local`.
//!
//! Each routine is a CLI-independent library function; `cmd_status` is the wrapper.

use crate::state::Channel;

/// The node-state outcome for a dataset (the first half of a status report).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeStatus {
    /// A definite served state (`visible` / `hidden` / `processing` / `error`),
    /// with the sanitized `error_message` when in `error`.
    State {
        /// The served state string.
        state: String,
        /// The sanitized error message (error state only).
        error_message: Option<String>,
    },
    /// The node has not yet processed the latest upload: `_status/{id}.json` is
    /// present but its `source_signature` does not match the current package `ETag`.
    /// (An absent status object maps to [`Self::Unavailable`], not `Pending`.)
    Pending,
    /// No node state is available: the bucket has `write_status` off and the
    /// management plane is unreachable. Fall back to local `validate` / S3-derived
    /// visibility.
    Unavailable,
}

impl NodeStatus {
    /// A short human label for the outcome.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::State {
                state,
                error_message,
            } => match error_message {
                Some(msg) => format!("{state} ({msg})"),
                None => state.clone(),
            },
            Self::Pending => "pending".to_owned(),
            Self::Unavailable => "unavailable".to_owned(),
        }
    }

    /// A self-explaining label for the human text report. Identical to [`Self::label`]
    /// except `Unavailable` spells out why, so an operator does not read a benign
    /// `unavailable` next to `visibility: visible` as an alarm. JSON output keeps the
    /// bare [`Self::label`] for a clean machine value.
    #[must_use]
    pub fn display_label(&self) -> String {
        match self {
            Self::Unavailable => {
                "unavailable (no node writeback; write_status off or management plane unreachable)"
                    .to_owned()
            }
            _ => self.label(),
        }
    }
}

/// The sync summary of a dataset relative to its remote (S3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sync {
    /// The dataset is in sync with S3 (its package is present; state consistent).
    InSync,
    /// The dataset has drifted from S3 (a different `ETag` / state).
    Drifted,
    /// The dataset is missing from S3 (no package present).
    Missing,
    /// An inbox-owned (local) dataset has no remote to compare against.
    Local,
}

impl Sync {
    /// The `sync: <...>` label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::InSync => "in-sync",
            Self::Drifted => "drifted",
            Self::Missing => "missing",
            Self::Local => "local",
        }
    }
}

// The `_status/{id}.json` writeback shape is the shared `s3_layout::StatusWriteback`:
// the node (writer) serializes it and this tool (reader) deserializes the same struct, so
// the wire field names cannot drift between the two crates. Re-exported here so
// `status::StatusWriteback` stays the local name. The reader consults only
// `state` / `source_signature` / `error_message`; the other fields default on parse.
pub use gdi_node_standalone_core::s3_layout::StatusWriteback;

/// Parse a `_status/{id}.json` body, returning `None` on an unparseable body.
#[must_use]
pub fn parse_writeback(bytes: &[u8]) -> Option<StatusWriteback> {
    serde_json::from_slice(bytes).ok()
}

/// Replace each terminal control character with a space in an attacker-influenced bucket
/// object field (`_status/{id}.json`) before it reaches the operator's terminal.
///
/// Delegates to the one shared [`crate::output::sanitize_terminal`], so `status`, `lint` and
/// the catalog reader cannot drift on this rule.
fn strip_control(s: &str) -> String {
    crate::output::sanitize_terminal(s)
}

/// Resolve the **remote** node status from a writeback object and the current
/// package `ETag` (the no-management-plane path):
///
/// * a parsed writeback whose `source_signature` matches `current_etag` (or whose
///   signature/etag are absent) => the published [`NodeStatus::State`];
/// * a writeback whose signature is **stale** (≠ the current `ETag`) => [`NodeStatus::Pending`];
/// * no writeback object at all (`write_status` off for this bucket, or the node
///   has not written one yet) => [`NodeStatus::Unavailable`]. The tool cannot tell
///   those two apart without reading the bucket's `write_status` flag, so both map
///   to `Unavailable` (not `Pending`).
#[must_use]
pub fn remote_node_status(
    writeback: Option<&StatusWriteback>,
    current_etag: Option<&str>,
) -> NodeStatus {
    match writeback {
        Some(wb) => match (&wb.source_signature, current_etag) {
            // Both present and differing => the result is for an older upload.
            (Some(sig), Some(etag)) if sig != etag => NodeStatus::Pending,
            // Matching, or one side unknown => trust the published state. Strip terminal
            // control characters from the (attacker-influenceable) bucket-object fields so
            // a crafted writeback cannot inject ANSI escapes into the operator's terminal.
            _ => NodeStatus::State {
                state: strip_control(&wb.state),
                error_message: wb.error_message.as_deref().map(strip_control),
            },
        },
        // No writeback object at all: the node hasn't published a result we can read.
        None => NodeStatus::Unavailable,
    }
}

/// One granular difference line for `--diff` (file / `ETag` / state).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DiffLine {
    /// What differs (e.g. `package`, `state`, `_status`).
    pub aspect: String,
    /// The local-side value (or `<none>`).
    pub local: String,
    /// The remote (S3) value (or `<none>`).
    pub remote: String,
}

/// Decide the sync summary for an S3-owned dataset from package presence + an
/// `ETag`/state drift signal.
#[must_use]
pub const fn s3_sync(package_present: bool, drifted: bool) -> Sync {
    if !package_present {
        Sync::Missing
    } else if drifted {
        Sync::Drifted
    } else {
        Sync::InSync
    }
}

/// The sync summary for a dataset given its channel (an inbox dataset is `local`,
/// an S3 one defers to [`s3_sync`]).
#[must_use]
pub const fn channel_sync(channel: Channel, package_present: bool, drifted: bool) -> Sync {
    match channel {
        Channel::Inbox => Sync::Local,
        Channel::S3 => s3_sync(package_present, drifted),
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;

    #[test]
    fn remote_status_matching_signature_is_state() {
        let wb = StatusWriteback {
            state: "visible".to_owned(),
            error_message: None,
            source_signature: Some("etag-1".to_owned()),
            ..StatusWriteback::default()
        };
        let st = remote_node_status(Some(&wb), Some("etag-1"));
        assert_eq!(
            st,
            NodeStatus::State {
                state: "visible".to_owned(),
                error_message: None
            }
        );
        assert_eq!(st.label(), "visible");
    }

    #[test]
    fn remote_status_stale_signature_is_pending() {
        let wb = StatusWriteback {
            state: "error".to_owned(),
            error_message: Some("manifest invalid".to_owned()),
            source_signature: Some("old-etag".to_owned()),
            ..StatusWriteback::default()
        };
        let st = remote_node_status(Some(&wb), Some("new-etag"));
        assert_eq!(st, NodeStatus::Pending);
    }

    #[test]
    fn remote_status_error_carries_message() {
        let wb = StatusWriteback {
            state: "error".to_owned(),
            error_message: Some("bad parquet".to_owned()),
            source_signature: None,
            ..StatusWriteback::default()
        };
        let st = remote_node_status(Some(&wb), Some("etag"));
        assert_eq!(st.label(), "error (bad parquet)");
    }

    #[test]
    fn remote_status_strips_control_characters_from_bucket_fields() {
        // A shared/attacker-writable bucket object must not inject ANSI escapes into the
        // operator's terminal: control chars in state/error_message are stripped.
        let wb = StatusWriteback {
            state: "visible\u{1b}[2J".to_owned(),
            error_message: Some("boom\u{1b}]0;pwn\u{7}\nline2".to_owned()),
            source_signature: None,
            ..StatusWriteback::default()
        };
        let st = remote_node_status(Some(&wb), Some("etag"));
        let NodeStatus::State {
            state,
            error_message,
        } = st
        else {
            panic!("expected a State outcome");
        };
        assert_eq!(
            state, "visible [2J",
            "ESC must be neutralized in state (replaced by a space, not deleted)"
        );
        assert_eq!(
            error_message.as_deref(),
            Some("boom ]0;pwn  line2"),
            "ESC/BEL/newline must be neutralized in error_message — each becomes a space, \
             so `pwn` and `line2` cannot be glued into one token"
        );
        // And the rendered label carries no control byte.
        assert!(
            !NodeStatus::State {
                state,
                error_message,
            }
            .label()
            .chars()
            .any(char::is_control),
            "the printed label must contain no control characters"
        );
    }

    #[test]
    fn remote_status_no_writeback_is_unavailable() {
        let st = remote_node_status(None, Some("etag"));
        assert_eq!(st, NodeStatus::Unavailable);
        assert_eq!(st.label(), "unavailable");
    }

    #[test]
    fn parse_writeback_tolerates_extra_keys() {
        let body =
            br#"{"id":"x","state":"hidden","source_signature":"e1","updated_at":"t","extra":1}"#;
        let wb = parse_writeback(body).unwrap();
        assert_eq!(wb.state, "hidden");
        assert_eq!(wb.source_signature.as_deref(), Some("e1"));
        assert!(parse_writeback(b"not json").is_none());
    }

    #[test]
    fn sync_summaries() {
        assert_eq!(s3_sync(true, false), Sync::InSync);
        assert_eq!(s3_sync(true, true), Sync::Drifted);
        assert_eq!(s3_sync(false, false), Sync::Missing);
        assert_eq!(channel_sync(Channel::Inbox, true, true), Sync::Local);
        assert_eq!(channel_sync(Channel::S3, true, false), Sync::InSync);
        assert_eq!(Sync::Local.label(), "local");
    }
}
