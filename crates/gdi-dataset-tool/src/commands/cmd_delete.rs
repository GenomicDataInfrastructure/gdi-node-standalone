//! The `delete` command: remove an installed dataset from the node, routed by the
//! dataset's channel (provenance).
//!
//! Routing: an **S3**-owned id removes its `.tar.c4gh`, `.state.json` and
//! `.metadata.json` from the bucket and bumps `_sync_marker.json`; a **local
//! (inbox-owned)** id writes its inbox `{id}.state.json` = `{"state":"deleted"}`
//! (the service reconciles it and removes `datasets/{id}/`). It is **refused if the
//! dataset is currently visible** (checked via the state endpoint) — `unpublish`
//! first, or pass `--force`, which for an inbox dataset writes
//! `{"state":"deleted","force":true}`.
//!
//! It is also refused when visibility cannot be determined at all, with no oracle and no
//! sidecar: `delete` is irreversible, so it fails closed rather than skipping its own
//! precondition. `--management-url` gives the profile-less `--inbox` path an oracle to
//! consult. The rule lives in the private `delete_refusal` below.
//!
//! The routing + writes live in [`crate::state`]; this is the thin clap wrapper.

use std::path::Path;

use gdi_node_standalone_core::cache::DELETED_SIDECAR_STATE;
use gdi_node_standalone_core::id::is_valid_dataset_id;

use crate::cli::DeleteArgs;
use crate::state::{self, Channel, NodeState};
use crate::{ToolError, runtime, s3};

/// Run `delete`.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) on an invalid id, an unroutable channel, a
/// visible dataset without `--force`, or any S3 / filesystem failure.
pub fn run(
    args: &DeleteArgs,
    profile_name: Option<&str>,
    config_path: Option<&Path>,
) -> Result<(), ToolError> {
    let started = std::time::Instant::now();
    if !is_valid_dataset_id(&args.id) {
        return Err(ToolError::user(format!("invalid dataset id: {}", args.id)));
    }
    // `--inbox` stands in for a profile entirely; see `state::load_profile_for_edit`.
    let active = state::load_profile_for_edit(args.inbox.as_deref(), config_path, profile_name)?;

    let node_state = state::resolve_node_state(&active, &args.id, args.management_url.as_deref())?;
    // Warn if this profile's declared channel is not the node's owning channel: the delete
    // edits this profile's bucket, so a wrong-profile delete is a silent no-op.
    state::warn_channel_mismatch(node_state.as_ref(), &active);
    // `--inbox` names a filesystem target, so it implies the local channel.
    let local = args.local || args.inbox.is_some();
    let channel = state::resolve_channel(node_state.as_ref(), &active, args.s3, local)?;
    state::guard_inbox_flag_matches_channel(args.inbox.as_deref(), channel, &args.id)?;

    // For an S3-owned dataset, build the store once — reused by the visibility guard
    // (below) and the delete itself. Alongside it, resolve a human-readable `target`
    // (bucket/endpoint or inbox path) echoed in the output + dry-run, so a wrong or
    // forgotten `--profile` on this irreversible op is visible rather than silent.
    let (store, target) = match channel {
        Channel::S3 => {
            let s3_cfg = active.s3.as_ref().ok_or_else(|| {
                ToolError::user(
                    "this dataset is S3-owned but the active profile has no \
                     [profiles.<name>.s3] block",
                )
            })?;
            s3::install_crypto_provider();
            let target = crate::s3::target_label(s3_cfg);
            (Some(s3::build_object_store(s3_cfg)?), target)
        }
        Channel::Inbox => {
            let inbox = state::resolve_inbox_with_flag(args.inbox.as_deref(), &active)?;
            (None, format!("inbox {}", inbox.display()))
        }
    };

    // Refuse a currently-visible dataset unless --force (so a live, served dataset is
    // not yanked out from under queries by accident). Prefer the authoritative
    // management-plane state; if the node is unreachable, an S3-owned dataset's
    // visibility is still readable directly from the bucket `{id}.state.json`, so
    // enforce the guard from it rather than skipping it.
    let node_visible = node_state.as_ref().map(NodeState::is_visible);
    ensure_s3_package_exists(store.as_ref(), &args.id, node_state.is_some())?;
    let sidecar_visible = match (&node_state, &store) {
        (None, Some(s)) => {
            crate::output::note(&format!(
                "node unreachable; reading the S3 visibility sidecar for {} to enforce the \
                 visible-guard",
                args.id
            ));
            Some(runtime::block_on(s3::fetch_visibility(s, &args.id))? == s3::Visibility::Visible)
        }
        _ => None,
    };
    refusal_error(
        &args.id,
        delete_refusal(node_visible, sidecar_visible, args.force).as_ref(),
    )?;

    // `store` is `Some` exactly for the S3 channel, `None` for inbox — branch on it
    // directly (no re-derivation, no unreachable arm).
    let channel_label = if store.is_some() { "s3" } else { "inbox" };
    crate::output::note(&format!(
        "routing delete of {} to channel {channel_label} (target: {target}, force: {})",
        args.id, args.force
    ));

    // --dry-run: the channel routing + visibility guard above have already run, so the
    // preview reflects the real decision — but write nothing.
    if args.dry_run {
        crate::output::note(&format!(
            "dry-run: routing resolved, writing nothing for {}",
            args.id
        ));
        crate::output::emit_result(
            args.format,
            &format!(
                "dry run: {} would be deleted from {target}; nothing written",
                args.id
            ),
            &serde_json::json!({
                "schemaVersion": 1,
                "status": "ok",
                "action": "delete",
                "dryRun": true,
                "datasetId": args.id,
                "channel": channel_label,
                "target": target,
                "force": args.force,
            }),
        );
        return Ok(());
    }

    if let Some(store) = store {
        runtime::block_on(state::s3_delete(&store, &args.id))?;
    } else {
        let inbox = state::resolve_inbox_with_flag(args.inbox.as_deref(), &active)?;
        let body = crate::s3::state_sidecar_body(DELETED_SIDECAR_STATE, args.force);
        state::inbox_write_sidecar(&inbox, &args.id, &body)?;
    }

    crate::output::note(&format!("deleted {} in {:.1?}", args.id, started.elapsed()));
    crate::output::emit_result(
        args.format,
        &format!("deleted {} from {target}", args.id),
        &serde_json::json!({
            "schemaVersion": 1,
            "status": "ok",
            "action": "delete",
            "datasetId": args.id,
            "channel": channel_label,
            "target": target,
            "force": args.force,
        }),
    );
    Ok(())
}

/// Fail closed when an S3 delete targets an id with no package in the bucket.
///
/// A phantom or typo'd id, or the wrong profile, would otherwise be reported as a successful
/// "deleted" — `state::s3_delete` treats a `NotFound` as success — while the real dataset
/// stays live. Only checked when the node has no record of the dataset (`node_known ==
/// false`); the inbox channel (`store == None`) is not checkable from the tool and is
/// skipped, exactly as `cmd_publish`'s guard is.
///
/// # Errors
/// Returns a [`ToolError`] (exit 1) when the package check fails, or when no package
/// exists for `id` in the bucket.
fn ensure_s3_package_exists(
    store: Option<&s3::Store>,
    id: &str,
    node_known: bool,
) -> Result<(), ToolError> {
    if let Some(s) = store
        && !node_known
        && !runtime::block_on(async { s3::package_exists(s, id).await })?
    {
        return Err(ToolError::user(format!(
            "dataset {id} has no package in the bucket (typo'd id, wrong profile, or already \
             deleted); nothing to delete"
        )));
    }
    Ok(())
}

/// Turn a [`DeleteRefusal`] into the user-facing error, or `Ok(())` to proceed.
///
/// The two arms carry different remedies on purpose: a confirmed-visible dataset wants
/// `unpublish`, while an unconfirmable one wants an oracle (`--management-url`) — telling an
/// operator to `unpublish` a dataset whose state nobody can read is advice they cannot act
/// on.
///
/// # Errors
///
/// Returns a [`ToolError`] whenever `refusal` is `Some`.
fn refusal_error(id: &str, refusal: Option<&DeleteRefusal>) -> Result<(), ToolError> {
    match refusal {
        Some(DeleteRefusal::Visible) => Err(ToolError::user(format!(
            "dataset {id} reads as visible on the node's state oracle. If you just ran \
             `unpublish`, the node has not reconciled it yet (the oracle lags the sidecar \
             by a few seconds); wait briefly and retry, or pass --force. Otherwise \
             `unpublish` it first."
        ))),
        Some(DeleteRefusal::Unconfirmable) => Err(ToolError::user(format!(
            "cannot confirm whether dataset {id} is currently visible: no management-plane \
             state oracle is reachable, so the visible-guard cannot run. `delete` is \
             irreversible and this is the profile-less `--inbox` path, where there is no \
             `management_url` to consult; pass --management-url <URL> to enforce the \
             guard, `unpublish` first, or pass --force to delete without the check."
        ))),
        None => Ok(()),
    }
}

/// Why a delete was refused, or `None` to proceed.
#[derive(Debug, PartialEq, Eq)]
enum DeleteRefusal {
    /// The dataset is confirmed visible and `--force` was not given.
    Visible,
    /// Visibility could not be determined at all — no oracle, no sidecar.
    Unconfirmable,
}

/// Whether a delete must be refused, and why.
///
/// `node_visible` is the authoritative management-plane visibility when the node is
/// reachable; `sidecar_visible` is the bucket `{id}.state.json` visibility, consulted
/// **only** when the node is unreachable for an S3-owned dataset (so the guard is not
/// skipped just because the management plane is down).
///
/// Both `None` means the visibility is unconfirmable, and unconfirmable refuses. A
/// profile-less `delete <id> --inbox <dir>` has no `management_url` and no sidecar, so
/// treating unconfirmable as "proceed" would let it destroy a live, publicly-served dataset
/// at exit 0 with no `--force`.
///
/// Failing closed is the only safe default for an irreversible op whose precondition cannot
/// be checked. The three escape hatches are all explicit: `--management-url`, `unpublish`
/// first, or `--force`.
fn delete_refusal(
    node_visible: Option<bool>,
    sidecar_visible: Option<bool>,
    force: bool,
) -> Option<DeleteRefusal> {
    if force {
        return None;
    }
    match node_visible.or(sidecar_visible) {
        Some(true) => Some(DeleteRefusal::Visible),
        Some(false) => None,
        None => Some(DeleteRefusal::Unconfirmable),
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;
    use crate::cli::{DeleteArgs, OutputFormat};

    #[test]
    fn invalid_id_is_rejected_before_any_io() {
        let args = DeleteArgs {
            id: "bad id".to_owned(),
            management_url: None,
            force: false,
            dry_run: false,
            s3: false,
            local: false,
            inbox: None,
            format: OutputFormat::Text,
        };
        let err = run(&args, None, None).unwrap_err();
        assert!(
            err.message.contains("invalid dataset id"),
            "{}",
            err.message
        );
    }

    #[test]
    fn delete_guard_uses_sidecar_when_node_unreachable() {
        // --force always proceeds, from every state — including unconfirmable.
        assert_eq!(delete_refusal(Some(true), None, true), None);
        assert_eq!(delete_refusal(None, None, true), None);
        // Authoritative node says visible -> refused.
        assert_eq!(
            delete_refusal(Some(true), None, false),
            Some(DeleteRefusal::Visible)
        );
        assert_eq!(delete_refusal(Some(false), None, false), None);
        // Node unreachable: fall back to the S3 bucket sidecar.
        assert_eq!(
            delete_refusal(None, Some(true), false),
            Some(DeleteRefusal::Visible)
        );
        assert_eq!(delete_refusal(None, Some(false), false), None);
    }

    /// An unconfirmable delete must fail closed.
    ///
    /// Both `None` is the profile-less `--inbox` path: no `management_url`, so no oracle,
    /// and nothing to check. Proceeding there would destroy a live, publicly-served dataset
    /// at exit 0 with no `--force`.
    ///
    /// It is a distinct variant, not merely `Visible`, because the remedy differs: the user
    /// needs `--management-url` or `--force`, not `unpublish`.
    #[test]
    fn an_unconfirmable_delete_is_refused_rather_than_proceeding() {
        assert_eq!(
            delete_refusal(None, None, false),
            Some(DeleteRefusal::Unconfirmable),
            "no oracle and no sidecar means the visible-guard cannot run; an irreversible \
             op must fail closed"
        );
    }
}
