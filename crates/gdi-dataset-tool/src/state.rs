//! Channel routing + the declarative `{id}.state.json` sidecar edit shared by the
//! lifecycle ops (`publish` / `unpublish` / `delete`).
//!
//! A lifecycle op routes by the dataset's channel (provenance). When the node's
//! management-plane `GET {management_url}/datasets/{id}/state` is reachable, the tool
//! reads the authoritative `{state, channel, error_message?}` there and writes that
//! channel's sidecar, so its routing matches the service's view and a sidecar write
//! cannot land on a channel the node does not own. A tool that cannot reach the
//! management plane determines ownership from whether the bucket holds the package,
//! plus the `--s3` / `--local` override.
//!
//! Each routine here is a CLI-independent library function over plain arguments and
//! an `Arc<dyn ObjectStore>`; the `cmd_publish` / `cmd_delete` wrappers resolve the
//! profile and call them.

use std::path::{Path, PathBuf};
use std::time::Duration;

use gdi_node_standalone_core::config::Profile;
use gdi_node_standalone_core::state::DatasetState;
use object_store::path::Path as ObjPath;
use object_store::{ObjectStoreExt, PutPayload};

use crate::s3::{self, OVERLAY_SUFFIX, STATE_SUFFIX, Store, TAR_C4GH_SUFFIX};
use crate::{ToolError, runtime};

/// Timeout for the management-plane `GET /datasets/{id}/state` probe. Shared with
/// `status --all`'s up-front reachability probe so the two can never disagree.
pub(crate) const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// The channel (provenance) a dataset is owned by: the bucket (S3) or the inbox.
///
/// The string `channel` the management endpoint returns is the bucket's configured
/// `name` (an S3 channel) or the literal `inbox` (a local dataset); the tool only
/// needs the two-way S3-vs-inbox routing, so it collapses any non-`inbox` channel
/// to [`Channel::S3`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    /// An S3-owned dataset: the bucket holds `{id}.tar.c4gh` + `{id}.state.json`.
    S3,
    /// A local (inbox-owned) dataset: the service reconciles the inbox sidecar.
    Inbox,
}

impl Channel {
    /// Map a management-endpoint `channel` string to a [`Channel`] (`inbox` =>
    /// [`Channel::Inbox`]; any configured bucket name => [`Channel::S3`]).
    #[must_use]
    pub fn from_endpoint(channel: &str) -> Self {
        if channel.eq_ignore_ascii_case("inbox") {
            Self::Inbox
        } else {
            Self::S3
        }
    }
}

/// The node's authoritative view of a dataset, parsed from `GET
/// /datasets/{id}/state`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeState {
    /// The served state: `visible` / `hidden` / `processing` / `error`.
    pub state: String,
    /// The owning channel (provenance), collapsed to the tool's S3-vs-inbox routing.
    pub channel: Channel,
    /// The node's raw channel name (a bucket `name`, or `inbox`), preserved for a
    /// cross-check against the active profile's declared channel. The collapsed
    /// [`Channel`] alone cannot distinguish one S3 bucket from another.
    pub raw_channel: String,
    /// The sanitized error message, present only in the `error` state.
    pub error_message: Option<String>,
    /// When the node last ignored a changed re-drop under this live, immutable id.
    ///
    /// A live dataset is immutable, so re-presenting a corrected package under the same id
    /// is quarantined and the existing entry is left `visible`. This stamp is the node's
    /// signal that the re-drop was not applied. Without it, `deploy --wait` sees the
    /// previous ingest's `visible` on its first poll and reports success for a package the
    /// node rejected while it keeps serving the old data.
    pub superseded_redrop_at: Option<String>,
    /// The opaque signature of the artifact the node last processed under this id: an S3
    /// `ETag`, or an inbox package's content hash.
    ///
    /// The discriminator `deploy --wait` needs, because it answers "has the node looked at
    /// this upload yet?", which comparing `error_message` strings cannot: a package
    /// re-rejected for the same reason carries an identical message, and the wait would
    /// read a terminal rejection as still in flight. Compare for equality only. It is
    /// opaque, not a digest of the dataset contents.
    pub last_seen_signature: Option<String>,
}

impl NodeState {
    /// Whether the dataset is currently live (installed and served): `visible` or
    /// `hidden`. A lifecycle edit (`publish`/`unpublish`) is refused unless it is.
    #[must_use]
    pub fn is_live(&self) -> bool {
        DatasetState::from_visibility_str(&self.state).is_some()
    }

    /// Whether the dataset is currently `hidden`, which is where `upload`/`deploy` leave
    /// a new dataset and the state a `publish` nudge is conditional on. One predicate
    /// rather than the wire literal at six call sites.
    #[must_use]
    pub fn is_hidden(&self) -> bool {
        DatasetState::from_visibility_str(&self.state) == Some(DatasetState::Hidden)
    }

    /// Whether the node rejected the dataset (`error`), with `error_message` set.
    #[must_use]
    pub fn is_error(&self) -> bool {
        self.state == DatasetState::Error.as_str()
    }

    /// Whether the dataset is currently `visible` (the `delete` visible-guard).
    #[must_use]
    pub fn is_visible(&self) -> bool {
        DatasetState::from_visibility_str(&self.state) == Some(DatasetState::Visible)
    }
}

/// The minimal shape of `GET /datasets/{id}/state`; only the fields the tool
/// routes on are read, extra keys tolerated.
#[derive(serde::Deserialize)]
struct StateResp {
    /// The served state.
    state: String,
    /// The owning channel string (bucket `name` or `inbox`).
    channel: String,
    /// The sanitized error message (error state only).
    #[serde(default)]
    error_message: Option<String>,
    /// RFC3339 stamp of the last ignored re-drop under this live id, if any.
    #[serde(default)]
    superseded_redrop_at: Option<String>,
    /// Opaque signature of the artifact the node last processed under this id.
    /// `#[serde(default)]`, so a node that does not send it yields `None` and the wait
    /// falls back to comparing messages for equality.
    #[serde(default)]
    last_seen_signature: Option<String>,
}

/// What the node's state oracle says about an id, without the lossy collapse
/// [`probe_node_state`] applies.
///
/// That function returns `Option<NodeState>`, whose `None` carries four meanings at once:
/// node unreachable, id unknown (`404`), unparseable body, and tombstoned id. This keeps
/// them apart for the one caller that must distinguish them.
#[derive(Debug)]
pub(crate) enum NodeProbe {
    /// The node answered `200` with a parseable state.
    Live(Box<NodeState>),
    /// The node answered `410 Gone`: the id existed, was deleted, and a tombstone stands
    /// that refuses any re-drop. Terminal, and carries the node's own reason.
    Gone(String),
    /// The oracle did not answer at all: connection refused, DNS, timeout. Distinct from
    /// [`Self::Unknown`] because it says nothing about the id. Reading it as "the node has
    /// never seen this id" tells the operator to re-install a dataset that is present.
    /// Callers that only need a verdict fold it into the same fallback as `Unknown`.
    Unreachable,
    /// No authoritative view of this id: a `404`, or an unusable body on a `2xx`. Callers
    /// fall back to S3-ownership routing.
    Unknown,
}

/// Probe the oracle, distinguishing a tombstoned id from every other no-view case.
///
/// [`probe_node_state`] is defined in terms of this and folds `Gone` back into `None`, so
/// only the caller that needs the distinction pays for it.
///
/// # Errors
///
/// Same as [`probe_node_state`]: a malformed base URL, an insecure transport, or a client
/// that cannot be built.
pub(crate) async fn probe_node_state_detailed(
    base: &str,
    id: &str,
) -> Result<NodeProbe, ToolError> {
    let url = format!("{}/datasets/{id}/state", base.trim_end_matches('/'));
    crate::recipient::require_secure_transport(
        &url,
        "a MITM could forge the node's authoritative channel/state and steer sidecar routing.",
    )?;
    let client = gdi_node_standalone_core::tls::https_client_builder()
        .timeout(PROBE_TIMEOUT)
        .build()
        .map_err(|e| ToolError::user(format!("cannot build HTTP client: {e}")))?;
    let Ok(resp) = client.get(&url).send().await else {
        return Ok(NodeProbe::Unreachable);
    };
    if resp.status() == reqwest::StatusCode::GONE {
        let reason = crate::catalogs::read_capped_body(resp, &url)
            .await
            .unwrap_or_default();
        let reason = reason.trim();
        return Ok(NodeProbe::Gone(if reason.is_empty() {
            "a `deleted` tombstone stands for this id".to_owned()
        } else {
            reason.to_owned()
        }));
    }
    Ok(match probe_parse(resp, &url).await {
        Some(state) => NodeProbe::Live(Box::new(state)),
        None => NodeProbe::Unknown,
    })
}

/// Probe `GET {base}/datasets/{id}/state`.
///
/// Returns the parsed [`NodeState`] on a `200`, or `None` when the node is unreachable,
/// the id is unknown (`404`), or the response is otherwise unusable. On `None` the caller
/// falls back to S3-ownership routing.
///
/// # Errors
///
/// Returns a [`ToolError`] for a config error the operator fixes: a malformed `base` URL,
/// a plaintext `http` base to a non-loopback host (both rejected by
/// `require_secure_transport`), or an HTTP client that cannot be built. Runtime failures
/// (connection, DNS or send errors, a non-2xx status including `404`, and oversized or
/// unparseable bodies) all map to `None`.
pub async fn probe_node_state(base: &str, id: &str) -> Result<Option<NodeState>, ToolError> {
    let url = format!("{}/datasets/{id}/state", base.trim_end_matches('/'));
    // A MITM over plaintext http could forge the node's authoritative channel and state
    // and steer sidecar routing, so require https for a non-loopback host. Loopback
    // development is exempt. This is a config error the operator fixes.
    crate::recipient::require_secure_transport(
        &url,
        "a MITM could forge the node's authoritative channel/state and steer sidecar routing.",
    )?;
    let client = gdi_node_standalone_core::tls::https_client_builder()
        .timeout(PROBE_TIMEOUT)
        .build()
        .map_err(|e| ToolError::user(format!("cannot build HTTP client: {e}")))?;

    // Unreachable node / DNS / connection error: fall back to S3 ownership.
    let Ok(resp) = client.get(&url).send().await else {
        return Ok(None);
    };
    if !resp.status().is_success() {
        // 404 (unknown id) or any other non-2xx: no authoritative view.
        return Ok(None);
    }
    Ok(probe_parse(resp, &url).await)
}

/// Read + parse a `200` state body into a [`NodeState`], or `None` when it is unusable.
///
/// The single definition shared by [`probe_node_state`] and
/// [`probe_node_state_detailed`], so the two cannot drift on what counts as a usable
/// answer. The body is capped, because a compromised or MITM'd node could otherwise
/// stream an unbounded JSON body into the provider host. An oversized or unparseable body
/// means no authoritative view, and the caller falls back to S3.
async fn probe_parse(resp: reqwest::Response, url: &str) -> Option<NodeState> {
    let body = crate::catalogs::read_capped_body(resp, url).await.ok()?;
    let parsed = serde_json::from_str::<StateResp>(&body).ok()?;
    Some(NodeState {
        channel: Channel::from_endpoint(&parsed.channel),
        raw_channel: parsed.channel,
        state: parsed.state,
        error_message: parsed.error_message,
        // Parsed here so both probes see it: the detailed probe must report an ignored
        // re-drop just as the plain one does.
        superseded_redrop_at: parsed.superseded_redrop_at,
        last_seen_signature: parsed.last_seen_signature,
    })
}

/// Probe the management-plane state, returning `None` when no base is available or the
/// node is unreachable / unknown. The base is `override_base` when the caller supplies one
/// (the `--management-url` flag), else the profile's
/// [`node_state_base`](Profile::node_state_base) (`management_url`, else `service_url`).
///
/// `override_base` exists so the profile-less `--inbox` path can still reach an oracle.
/// Without it those runs have no base at all, and every visibility guard keyed on this
/// silently does not run. See `cmd_delete::delete_refusal`.
///
/// Shared by the `publish` / `unpublish` / `delete` wrappers (the lifecycle ops
/// that route by channel) and by `status`'s per-dataset resolution, so they cannot
/// drift on which base is probed.
///
/// # Errors
///
/// Returns a [`ToolError`] if the probe runtime cannot be started.
pub(crate) fn resolve_node_state(
    active: &Profile,
    id: &str,
    override_base: Option<&str>,
) -> Result<Option<NodeState>, ToolError> {
    match override_base.or_else(|| active.node_state_base()) {
        Some(base) => runtime::block_on(probe_node_state(base, id)),
        None => Ok(None),
    }
}

/// Resolve the channel to write to: prefer the node's authoritative `channel`; on
/// no authoritative view fall back to the explicit `--s3` / `--local` override, or
/// (with neither) infer from the profile (S3 configured => S3, else inbox).
///
/// `force_s3` / `force_local` are mutually exclusive at the clap layer. Shared by
/// `publish` / `unpublish` / `delete`. (The read-only `status` command keeps its
/// own [`crate::commands::cmd_status`] inference: it never errors and adds a
/// local-package-present heuristic, neither of which a write should adopt.)
///
/// # Errors
///
/// Returns a [`ToolError`] when the node is unreachable, no override is given, and the
/// profile configures neither S3 nor an inbox. A write must not guess.
pub(crate) fn resolve_channel(
    node_state: Option<&NodeState>,
    active: &Profile,
    force_s3: bool,
    force_local: bool,
) -> Result<Channel, ToolError> {
    if let Some(ns) = node_state {
        return Ok(ns.channel);
    }
    if force_s3 {
        return Ok(Channel::S3);
    }
    if force_local {
        return Ok(Channel::Inbox);
    }
    // No authoritative view and no override: infer from the profile shape.
    if active.s3.is_some() {
        Ok(Channel::S3)
    } else if active.inbox.is_some() {
        Ok(Channel::Inbox)
    } else {
        Err(ToolError::user(
            "cannot determine the dataset's channel: the node is unreachable and the profile has \
             neither a [profiles.<name>.s3] bucket nor an inbox; pass --s3 or --local",
        ))
    }
}

/// The channel-mismatch warning message, if the active profile's declared S3 channel
/// (`[profiles.<name>.s3].channel`) disagrees with the node's authoritative owning channel.
///
/// Pure (no I/O) so the decision is unit-testable. Returns `None`, meaning nothing to warn
/// about, unless the node is reachable on an S3 channel and the profile declares a channel
/// that differs from the node's raw channel name.
fn channel_mismatch_message(node_state: Option<&NodeState>, active: &Profile) -> Option<String> {
    let ns = node_state?;
    let s3 = active.s3.as_ref()?;
    if ns.channel != Channel::S3 {
        return None;
    }
    let declared = s3.channel.as_deref()?;
    if declared == ns.raw_channel {
        return None;
    }
    Some(format!(
        "the node reports this dataset is owned by channel {node:?}, but the active profile \
         declares channel {declared:?}; the tool writes the sidecar to this profile's bucket, \
         which the node may not monitor for channel {node:?}, so the change could be a silent \
         no-op. Run the op from the profile that owns channel {node:?}.",
        node = ns.raw_channel,
    ))
}

/// Warn when the node's authoritative owning channel does not match the active profile's
/// declared S3 channel name (`[profiles.<name>.s3].channel`).
///
/// The tool writes the `.state.json` sidecar to the profile's single bucket, so on a
/// multi-bucket node an S3 lifecycle op (`publish` / `unpublish` / `delete`) run under a
/// profile whose bucket is not the dataset's owning channel is a silent no-op: the node
/// monitors the owning bucket and never sees the sidecar. This surfaces that mismatch; see
/// [`channel_mismatch_message`] for the condition. No-op unless the node is reachable on an
/// S3 channel and the profile declares its channel.
pub(crate) fn warn_channel_mismatch(node_state: Option<&NodeState>, active: &Profile) {
    if let Some(msg) = channel_mismatch_message(node_state, active) {
        crate::output::warn(&msg);
    }
}

/// Resolve the inbox directory from the active profile.
///
/// # Errors
///
/// Returns a [`ToolError`] when the dataset is inbox-owned but the profile has no
/// inbox configured.
pub(crate) fn resolve_inbox(active: &Profile) -> Result<PathBuf, ToolError> {
    active
        .inbox
        .as_deref()
        .map(PathBuf::from)
        .ok_or_else(|| ToolError::user("this dataset is inbox-owned but the profile has no inbox"))
}

// The `--inbox` escape hatch, shared by publish / unpublish / delete.
//
// `deploy --inbox <dir>` needs no profile: naming the directory fully specifies the
// target. The lifecycle verbs that follow it must not then demand one, or a profile-free
// deploy would report success and then point at a command that dies with "no profiles
// configured". These three helpers are shared so the three verbs cannot drift apart on
// what `--inbox` means.

/// Load the active profile for a channel-routed edit, letting an explicit `--inbox` stand
/// in for one entirely.
///
/// Without `--inbox` a profile is still required, because nothing else names the target.
/// With it, a missing profile map degrades to [`Profile::default`], whose fields are all
/// `None`, so the node-state probe finds no management base and the live guard degrades as
/// `deploy`'s does. A malformed config or an unknown `--profile` still hard-fails (see
/// [`crate::profile::load_active_optional`]).
///
/// # Errors
///
/// Returns a [`ToolError`] when the config cannot be loaded, or when no `--inbox` is given
/// and no profile can be selected.
pub(crate) fn load_profile_for_edit(
    inbox_flag: Option<&Path>,
    config_path: Option<&Path>,
    profile_name: Option<&str>,
) -> Result<Profile, ToolError> {
    if inbox_flag.is_some() {
        return Ok(
            crate::profile::load_active_optional(config_path, profile_name)?.unwrap_or_default(),
        );
    }
    crate::profile::load_active(config_path, profile_name)
}

/// The inbox to write the sidecar into: the explicit `--inbox`, else the profile's.
///
/// # Errors
///
/// Returns a [`ToolError`] when neither is set.
pub(crate) fn resolve_inbox_with_flag(
    inbox_flag: Option<&Path>,
    active: &Profile,
) -> Result<PathBuf, ToolError> {
    match inbox_flag {
        Some(dir) => Ok(dir.to_path_buf()),
        None => resolve_inbox(active),
    }
}

/// Refuse an `--inbox` edit for a dataset the node says lives on S3.
///
/// [`resolve_channel`] gives the node's authoritative view precedence over `--local`, so
/// without this guard `--inbox` could resolve to [`Channel::S3`] and write the sidecar to a
/// bucket, ignoring the directory the operator named. The reverse, writing an inbox sidecar
/// for an S3-owned dataset, is as bad: the node ignores it and the command reports success.
/// Refuse, and say which channel owns the dataset.
///
/// # Errors
///
/// Returns a [`ToolError`] when `--inbox` is set but the resolved channel is S3.
pub(crate) fn guard_inbox_flag_matches_channel(
    inbox_flag: Option<&Path>,
    channel: Channel,
    id: &str,
) -> Result<(), ToolError> {
    if inbox_flag.is_some() && channel == Channel::S3 {
        return Err(ToolError::user(format!(
            "--inbox names a local directory, but the node reports {id} is owned by the S3 \
             channel; an inbox sidecar there would be silently ignored. Drop --inbox to edit \
             it on its own channel."
        )));
    }
    Ok(())
}

/// Write `{id}.state.json` = `{"schemaVersion":1,"state":"<state>"}` into the **S3** bucket and
/// bump `_sync_marker.json` last (the write-order discipline). Used by
/// `publish`/`unpublish` for an S3-owned dataset.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) on any PUT failure.
pub async fn s3_set_state(store: &Store, id: &str, state: &str) -> Result<(), ToolError> {
    let key = ObjPath::from(format!("{id}{STATE_SUFFIX}"));
    let body = s3::state_sidecar_body(state, false);
    store
        .put(&key, PutPayload::from(body.into_bytes()))
        .await
        .map_err(|e| crate::s3::classify_object_store_error(&format!("writing {key}"), e))?;
    // The marker bump is last: the node only reacts once the sidecar is in place.
    s3::bump_marker(store).await?;
    Ok(())
}

/// Delete an **S3**-owned dataset: remove `{id}.tar.c4gh`, `{id}.state.json` and
/// `{id}.metadata.json`, then bump `_sync_marker.json` last. A missing object is not
/// an error (the delete is idempotent / partially-applied recovery).
///
/// The metadata overlay goes with the package because the keyspace is keyed by dataset
/// id and ids are reusable: an overlay left behind by a deleted dataset is silently
/// applied to whatever is uploaded under that id next, so a retraction would leave the
/// old dataset's governance metadata governing new data. Deleting all three is what
/// makes "delete" mean the id is free again.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) on a delete (other than `NotFound`) or the
/// marker bump failing.
pub async fn s3_delete(store: &Store, id: &str) -> Result<(), ToolError> {
    // Delete the package (the servable artifact) first. A failure to delete the package
    // itself returns early: nothing was removed, so there is nothing to signal.
    let pkg_key = ObjPath::from(format!("{id}{TAR_C4GH_SUFFIX}"));
    match store.delete(&pkg_key).await {
        Ok(()) => {}
        Err(e) if crate::s3::is_not_found_object_store(&e) => {}
        Err(e) => {
            return Err(crate::s3::classify_object_store_error(
                &format!("deleting {pkg_key}"),
                e,
            ));
        }
    }
    // The package is gone, so the node has to be signalled to evict it: bump the marker
    // even if the sidecar cleanup below errors. Removals are marker-gated, so a periodic
    // reconcile on an unchanged marker would keep serving the node's local copy of a
    // package that is no longer there. Capture the sidecar result without early-returning
    // on it, so the bump still happens.
    //
    // Both sidecars are swept: the state sidecar the node reconciles, and the operator
    // metadata overlay it applies to whatever holds this id. The first error is reported,
    // after the bump.
    let mut sidecar_result = Ok(());
    for suffix in [STATE_SUFFIX, OVERLAY_SUFFIX] {
        let sidecar_key = ObjPath::from(format!("{id}{suffix}"));
        match store.delete(&sidecar_key).await {
            Ok(()) => {}
            Err(e) if crate::s3::is_not_found_object_store(&e) => {}
            Err(e) => {
                if sidecar_result.is_ok() {
                    sidecar_result = Err(crate::s3::classify_object_store_error(
                        &format!("deleting {sidecar_key}"),
                        e,
                    ));
                }
            }
        }
    }
    // Marker last, per the write-order invariant. A bump failure matters more than a
    // sidecar cleanup error, because without it the node never reconciles the removal, so
    // it takes precedence.
    s3::bump_marker(store).await?;
    sidecar_result
}

/// Require `inbox` to be an existing directory, rather than creating it.
///
/// The inbox is the node's ingress and the node creates it at startup, so on any node that
/// has run it exists. An absent one means the path is wrong, or that node has never run
/// there. In both cases `mkdir -p` is the wrong answer.
///
/// Creating it turns `ENOENT`, the one signal a mistyped path gives, into a phantom inbox:
/// `deploy --inbox /srv/gdi/inbx` would create the tree, copy a full staging directory into
/// it and report success, and every later `publish` into the same typo would succeed too,
/// while the node reads the real inbox and sees nothing.
///
/// There is no `--create-inbox` escape hatch: staging an inbox before the node's first
/// start is unusual, and the message below names the one command that does it.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) when `inbox` does not exist, or exists but is not a
/// directory.
pub fn require_inbox(inbox: &Path) -> Result<(), ToolError> {
    match std::fs::metadata(inbox) {
        Ok(meta) if meta.is_dir() => Ok(()),
        Ok(_) => Err(ToolError::user(format!(
            "inbox {} exists but is not a directory",
            inbox.display()
        ))),
        Err(_) => Err(ToolError::user(format!(
            "inbox {} does not exist. The node creates its inbox at startup, so an absent \
             one means this is not that node's inbox path. Check the profile's `inbox` \
             or `--inbox` against the node's `[service].inbox`. If you are staging a drop \
             before the node's first start, create it first: mkdir -p {}",
            inbox.display(),
            inbox.display()
        ))),
    }
}

/// Write the **inbox** `{id}.state.json` sidecar = `body` (raw JSON). The service
/// reconciles it (the tool cannot write the node's data dir). Used for a local
/// (inbox-owned) lifecycle op.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) if the inbox is missing (see [`require_inbox`]) or the
/// sidecar cannot be written.
pub fn inbox_write_sidecar(inbox: &Path, id: &str, body: &str) -> Result<(), ToolError> {
    require_inbox(inbox)?;
    let path = inbox.join(format!("{id}{STATE_SUFFIX}"));
    // Durable atomic write (tmp -> fsync -> rename): the service's inbox scanner reads
    // this sidecar to drive reconciliation, so it must never observe a torn or zero-length
    // file mid-write, nor lose it to a crash after a non-atomic overwrite.
    #[expect(
        clippy::disallowed_methods,
        reason = "not secret: a lifecycle state sidecar the service scanner reads"
    )]
    gdi_node_standalone_core::util::write_durable_atomic(&path, body.as_bytes())
        .map_err(|e| ToolError::user(format!("cannot write {}: {e}", path.display())))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use std::sync::Arc;

    use async_trait::async_trait;
    use futures::stream::{BoxStream, StreamExt as _};
    use object_store::memory::InMemory;
    use object_store::{
        CopyOptions, GetOptions, GetResult, ListResult, ObjectMeta, ObjectStore,
        PutMultipartOptions, PutOptions, PutPayload, PutResult,
    };

    use super::*;

    fn id() -> &'static str {
        "GDI-EE-UTARTU-20260409143052837"
    }

    fn mem_store() -> Store {
        Arc::new(InMemory::new())
    }

    /// An `InMemory` store whose `delete` fails for keys ending in `fail_suffix`
    /// (everything else delegates), to drive `s3_delete`'s partial-delete path (package
    /// gone, sidecar cleanup errors) and the backend-specific spellings of "already
    /// absent".
    ///
    /// `InMemory` reports a missing key as the typed [`object_store::Error::NotFound`], so
    /// it cannot reproduce a real backend's `DeleteObjects` answer on its own; the
    /// injected error is what makes that shape testable.
    #[derive(Debug)]
    struct DeleteFailsSidecar {
        inner: InMemory,
        fail_suffix: &'static str,
        error: fn() -> object_store::Error,
    }

    impl DeleteFailsSidecar {
        fn injected() -> object_store::Error {
            object_store::Error::Generic {
                store: "DeleteFailsSidecar",
                source: "test: injected sidecar delete failure".into(),
            }
        }

        /// What Garage answers when `DeleteObjects` is asked to remove a key that is not
        /// there: a `200` multi-status carrying a per-key `NoSuchKey`, which
        /// `object_store` surfaces as `Generic`, never as `NotFound`. It embeds the object
        /// key, which is why the matcher keys on the error code rather than on a status
        /// number a dataset id could contain.
        fn garage_no_such_key() -> object_store::Error {
            object_store::Error::Generic {
                store: "S3",
                source: format!(
                    "DeleteObjects request failed for key {}{OVERLAY_SUFFIX}: Key not \
                     found (code: NoSuchKey)",
                    id()
                )
                .into(),
            }
        }
    }

    impl std::fmt::Display for DeleteFailsSidecar {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "DeleteFailsSidecar")
        }
    }

    #[async_trait]
    impl ObjectStore for DeleteFailsSidecar {
        async fn put_opts(
            &self,
            location: &ObjPath,
            payload: PutPayload,
            opts: PutOptions,
        ) -> object_store::Result<PutResult> {
            self.inner.put_opts(location, payload, opts).await
        }

        async fn put_multipart_opts(
            &self,
            location: &ObjPath,
            opts: PutMultipartOptions,
        ) -> object_store::Result<Box<dyn object_store::MultipartUpload>> {
            self.inner.put_multipart_opts(location, opts).await
        }

        async fn get_opts(
            &self,
            location: &ObjPath,
            options: GetOptions,
        ) -> object_store::Result<GetResult> {
            self.inner.get_opts(location, options).await
        }

        fn delete_stream(
            &self,
            locations: BoxStream<'static, object_store::Result<ObjPath>>,
        ) -> BoxStream<'static, object_store::Result<ObjPath>> {
            // `ObjectStoreExt::delete` drives this; inject an error for the selected
            // sidecar deletion, leaving the package deletion to succeed: the
            // partial-delete case.
            let (fail_suffix, error) = (self.fail_suffix, self.error);
            self.inner
                .delete_stream(locations)
                .map(move |res| match res {
                    Ok(path) if path.as_ref().ends_with(fail_suffix) => Err(error()),
                    other => other,
                })
                .boxed()
        }

        fn list(
            &self,
            prefix: Option<&ObjPath>,
        ) -> BoxStream<'static, object_store::Result<ObjectMeta>> {
            self.inner.list(prefix)
        }

        async fn list_with_delimiter(
            &self,
            prefix: Option<&ObjPath>,
        ) -> object_store::Result<ListResult> {
            self.inner.list_with_delimiter(prefix).await
        }

        async fn copy_opts(
            &self,
            from: &ObjPath,
            to: &ObjPath,
            options: CopyOptions,
        ) -> object_store::Result<()> {
            self.inner.copy_opts(from, to, options).await
        }
    }

    async fn get_str(store: &Store, key: &str) -> Option<String> {
        match store.get(&ObjPath::from(key)).await {
            Ok(r) => Some(String::from_utf8(r.bytes().await.unwrap().to_vec()).unwrap()),
            Err(object_store::Error::NotFound { .. }) => None,
            Err(e) => panic!("unexpected get error: {e}"),
        }
    }

    #[test]
    fn channel_maps_inbox_and_buckets() {
        assert_eq!(Channel::from_endpoint("inbox"), Channel::Inbox);
        assert_eq!(Channel::from_endpoint("INBOX"), Channel::Inbox);
        assert_eq!(Channel::from_endpoint("primary"), Channel::S3);
        assert_eq!(Channel::from_endpoint("eu-handoff"), Channel::S3);
    }

    #[test]
    fn node_state_live_and_visible() {
        let live = NodeState {
            state: "hidden".to_owned(),
            channel: Channel::S3,
            raw_channel: "primary".to_owned(),
            error_message: None,
            superseded_redrop_at: None,
            last_seen_signature: None,
        };
        assert!(live.is_live());
        assert!(!live.is_visible());

        let vis = NodeState {
            state: "visible".to_owned(),
            channel: Channel::Inbox,
            raw_channel: "inbox".to_owned(),
            error_message: None,
            superseded_redrop_at: None,
            last_seen_signature: None,
        };
        assert!(vis.is_live());
        assert!(vis.is_visible());

        let proc = NodeState {
            state: "processing".to_owned(),
            channel: Channel::S3,
            raw_channel: "primary".to_owned(),
            error_message: None,
            superseded_redrop_at: None,
            last_seen_signature: None,
        };
        assert!(!proc.is_live());
    }

    #[tokio::test]
    async fn s3_set_state_writes_sidecar_and_bumps_marker() {
        let store = mem_store();
        s3_set_state(&store, id(), "visible").await.unwrap();

        let sidecar = get_str(&store, &format!("{}{STATE_SUFFIX}", id()))
            .await
            .expect("sidecar written");
        assert!(sidecar.contains(r#""state":"visible""#), "{sidecar}");

        let marker = get_str(&store, s3::MARKER_KEY)
            .await
            .expect("marker bumped");
        assert!(marker.contains("last_modified"), "{marker}");
    }

    #[tokio::test]
    async fn s3_delete_removes_objects_and_bumps_marker() {
        let store = mem_store();
        // Seed a package + sidecar.
        s3::upload_package_bytes(
            &store,
            &s3::PackageStore::new(store.clone()),
            id(),
            b"PKG".to_vec(),
            false,
        )
        .await
        .unwrap();
        assert!(
            get_str(&store, &format!("{}{TAR_C4GH_SUFFIX}", id()))
                .await
                .is_some()
        );

        // An operator metadata overlay for the same id, which a re-upload would inherit.
        store
            .put(
                &ObjPath::from(format!("{}{OVERLAY_SUFFIX}", id())),
                object_store::PutPayload::from(b"{}".to_vec()),
            )
            .await
            .unwrap();

        s3_delete(&store, id()).await.unwrap();
        assert!(
            get_str(&store, &format!("{}{TAR_C4GH_SUFFIX}", id()))
                .await
                .is_none(),
            "package removed"
        );
        assert!(
            get_str(&store, &format!("{}{STATE_SUFFIX}", id()))
                .await
                .is_none(),
            "sidecar removed"
        );
        assert!(
            get_str(&store, &format!("{}{OVERLAY_SUFFIX}", id()))
                .await
                .is_none(),
            "metadata overlay removed; otherwise the next dataset uploaded under this id \
             inherits the deleted one's governance metadata"
        );
        let marker = get_str(&store, s3::MARKER_KEY)
            .await
            .expect("marker bumped");
        assert!(marker.contains("last_modified"), "{marker}");
    }

    #[tokio::test]
    async fn s3_delete_bumps_marker_even_if_sidecar_delete_errors() {
        // If the package delete succeeds but the state-sidecar delete errors, the marker
        // must still bump: the servable artifact is gone, and a marker-gated periodic
        // reconcile has to be signalled to evict it, or the node keeps serving its local
        // copy on an unchanged marker. The call still returns the sidecar error, after
        // bumping.
        let store: Store = Arc::new(DeleteFailsSidecar {
            inner: InMemory::new(),
            fail_suffix: STATE_SUFFIX,
            error: DeleteFailsSidecar::injected,
        });
        // Seed the package and sidecar directly, with no marker bump, so the marker is
        // absent until s3_delete's own bump and the assertion below isolates it.
        store
            .put(
                &ObjPath::from(format!("{}{TAR_C4GH_SUFFIX}", id())),
                b"PKG".to_vec().into(),
            )
            .await
            .unwrap();
        store
            .put(
                &ObjPath::from(format!("{}{STATE_SUFFIX}", id())),
                br#"{"state":"visible"}"#.to_vec().into(),
            )
            .await
            .unwrap();
        assert!(
            get_str(&store, s3::MARKER_KEY).await.is_none(),
            "no marker seeded"
        );

        let res = s3_delete(&store, id()).await;
        assert!(res.is_err(), "the sidecar delete error must still surface");
        assert!(
            get_str(&store, &format!("{}{TAR_C4GH_SUFFIX}", id()))
                .await
                .is_none(),
            "the package was removed"
        );
        assert!(
            get_str(&store, s3::MARKER_KEY).await.is_some(),
            "marker must bump when the package is gone, even if the sidecar delete errored"
        );
    }

    #[tokio::test]
    async fn s3_delete_tolerates_a_backend_that_spells_absent_as_generic() {
        // The `.metadata.json` overlay is optional, and absent for every dataset that never
        // had an operator correction, so removing it must be a no-op. `InMemory` spells
        // that absence as the typed `NotFound`, which is why the sibling
        // `s3_delete_is_idempotent_on_missing` cannot cover this case: Garage answers
        // `DeleteObjects` with a per-key `NoSuchKey` inside a `200`, which `object_store`
        // surfaces as `Generic`. A variant-only match reports a delete that fully
        // succeeded as a non-zero exit on this repo's default Compose backend.
        let store: Store = Arc::new(DeleteFailsSidecar {
            inner: InMemory::new(),
            fail_suffix: OVERLAY_SUFFIX,
            error: DeleteFailsSidecar::garage_no_such_key,
        });
        store
            .put(
                &ObjPath::from(format!("{}{TAR_C4GH_SUFFIX}", id())),
                b"PKG".to_vec().into(),
            )
            .await
            .unwrap();

        s3_delete(&store, id())
            .await
            .expect("an absent overlay is not a delete failure, however the backend spells it");

        assert!(
            get_str(&store, &format!("{}{TAR_C4GH_SUFFIX}", id()))
                .await
                .is_none(),
            "the package was removed"
        );
        assert!(
            get_str(&store, s3::MARKER_KEY).await.is_some(),
            "the marker still bumps, so the node reconciles the removal"
        );
    }

    #[tokio::test]
    async fn s3_delete_is_idempotent_on_missing() {
        let store = mem_store();
        // Nothing seeded; delete still succeeds (idempotent) and bumps the marker.
        s3_delete(&store, id()).await.unwrap();
        assert!(get_str(&store, s3::MARKER_KEY).await.is_some());
    }

    #[test]
    fn inbox_write_sidecar_creates_file() {
        let tmp = tempfile::tempdir().unwrap();
        let inbox = tmp.path().join("inbox");
        std::fs::create_dir_all(&inbox).unwrap();
        inbox_write_sidecar(&inbox, id(), r#"{"state":"deleted","force":true}"#).unwrap();
        let body = std::fs::read_to_string(inbox.join(format!("{}{STATE_SUFFIX}", id()))).unwrap();
        assert_eq!(body, r#"{"state":"deleted","force":true}"#);
    }

    fn profile_with(s3: bool, inbox: bool) -> Profile {
        Profile {
            s3: s3.then(gdi_node_standalone_core::config::ProfileS3::default),
            inbox: inbox.then(|| "/var/inbox".to_owned()),
            ..Profile::default()
        }
    }

    fn s3_profile_with_channel(channel: Option<&str>) -> Profile {
        Profile {
            s3: Some(gdi_node_standalone_core::config::ProfileS3 {
                channel: channel.map(str::to_owned),
                ..gdi_node_standalone_core::config::ProfileS3::default()
            }),
            ..Profile::default()
        }
    }

    fn s3_node_state(raw_channel: &str) -> NodeState {
        NodeState {
            state: "visible".to_owned(),
            channel: Channel::S3,
            raw_channel: raw_channel.to_owned(),
            error_message: None,
            superseded_redrop_at: None,
            last_seen_signature: None,
        }
    }

    #[test]
    fn channel_mismatch_warns_only_on_declared_disagreement() {
        // The warning fires only when the profile declares a channel that differs from
        // the node's authoritative owning channel.
        // Declared channel differs -> warn (the message names both channels).
        assert!(
            channel_mismatch_message(
                Some(&s3_node_state("primary")),
                &s3_profile_with_channel(Some("secondary")),
            )
            .is_some_and(|m| m.contains("primary") && m.contains("secondary")),
            "a declared-channel mismatch must warn"
        );
        // Declared channel matches -> no warning.
        assert!(
            channel_mismatch_message(
                Some(&s3_node_state("primary")),
                &s3_profile_with_channel(Some("primary")),
            )
            .is_none(),
            "a matching declared channel must not warn"
        );
        // No declared channel -> no warning.
        assert!(
            channel_mismatch_message(
                Some(&s3_node_state("primary")),
                &s3_profile_with_channel(None),
            )
            .is_none(),
            "an undeclared profile channel must not warn"
        );
        // Node unreachable -> no warning.
        assert!(
            channel_mismatch_message(None, &s3_profile_with_channel(Some("secondary"))).is_none(),
            "an unreachable node must not warn"
        );
        // Inbox-owned dataset -> not an S3 op, no warning even if a channel is declared.
        let inbox_ns = NodeState {
            state: "visible".to_owned(),
            channel: Channel::Inbox,
            raw_channel: "inbox".to_owned(),
            error_message: None,
            superseded_redrop_at: None,
            last_seen_signature: None,
        };
        assert!(
            channel_mismatch_message(Some(&inbox_ns), &s3_profile_with_channel(Some("secondary")))
                .is_none(),
            "an inbox-owned dataset must not warn on S3 channel mismatch"
        );
    }

    #[test]
    fn channel_prefers_node_authoritative_view() {
        let ns = NodeState {
            state: "hidden".to_owned(),
            channel: Channel::Inbox,
            raw_channel: "inbox".to_owned(),
            error_message: None,
            superseded_redrop_at: None,
            last_seen_signature: None,
        };
        // Even with S3 configured, the node's `inbox` channel wins.
        let ch = resolve_channel(Some(&ns), &profile_with(true, true), false, false).unwrap();
        assert_eq!(ch, Channel::Inbox);
    }

    #[test]
    fn channel_override_when_node_unreachable() {
        // Each override is tested against a profile whose inference disagrees with it, or
        // the early return is unfalsifiable: the fallback checks s3 first, so on a profile
        // with both, `--s3` matches what inference would answer anyway.
        //
        // `--s3` on an inbox-only profile: inference would say Inbox.
        let inbox_only = profile_with(false, true);
        assert_eq!(
            resolve_channel(None, &inbox_only, true, false).unwrap(),
            Channel::S3,
            "--s3 must override an inbox-only profile's inferred channel"
        );
        assert_eq!(
            resolve_channel(None, &inbox_only, false, false).unwrap(),
            Channel::Inbox,
            "the contrast: without the override, inference answers Inbox"
        );
        // `--local` on an s3-only profile: inference would say S3.
        let s3_only = profile_with(true, false);
        assert_eq!(
            resolve_channel(None, &s3_only, false, true).unwrap(),
            Channel::Inbox,
            "--local must override an s3-only profile's inferred channel"
        );
        assert_eq!(
            resolve_channel(None, &s3_only, false, false).unwrap(),
            Channel::S3,
            "the contrast: without the override, inference answers S3"
        );
    }

    #[test]
    fn channel_infers_from_profile_shape() {
        assert_eq!(
            resolve_channel(None, &profile_with(true, false), false, false).unwrap(),
            Channel::S3
        );
        assert_eq!(
            resolve_channel(None, &profile_with(false, true), false, false).unwrap(),
            Channel::Inbox
        );
        // Neither configured + no override + unreachable node => a clear error.
        assert!(resolve_channel(None, &profile_with(false, false), false, false).is_err());
    }
}

#[cfg(test)]
mod require_inbox_tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::require_inbox;

    /// An existing directory passes; an absent one and a file are both refused.
    ///
    /// The absent arm is the one that matters: `ENOENT` is the only signal a mistyped
    /// `--inbox` gives, so refusing must not create the path it refused.
    #[test]
    fn an_absent_or_non_directory_inbox_is_refused_and_nothing_is_created() {
        let tmp = tempfile::tempdir().unwrap();

        // A real inbox: accepted.
        require_inbox(tmp.path()).expect("an existing inbox directory must be accepted");

        // Absent: refused, and the message must point at the config, not just say "no".
        let missing = tmp.path().join("deep/nested/inbox");
        let err = require_inbox(&missing).expect_err("an absent inbox must be refused");
        assert!(
            err.message.contains("does not exist"),
            "must say what is wrong: {}",
            err.message
        );
        assert!(
            err.message.contains("[service].inbox"),
            "must point at the node's own setting so the operator can compare: {}",
            err.message
        );
        assert!(
            !missing.exists(),
            "refusing must not create the path it refused"
        );

        // A regular file: refused too, and distinguishably.
        let file = tmp.path().join("not-a-dir");
        std::fs::write(&file, b"x").unwrap();
        let err = require_inbox(&file).expect_err("a file cannot be an inbox");
        assert!(
            err.message.contains("not a directory"),
            "a file must be reported as a file, not as missing: {}",
            err.message
        );
    }
}
