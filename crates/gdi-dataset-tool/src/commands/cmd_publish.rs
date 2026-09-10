//! The `publish` / `unpublish` commands: the declarative `{id}.state.json` edit
//! that makes a hidden dataset visible (or a visible one hidden), routed by the
//! dataset's channel (provenance).
//!
//! Both verbs are the **same** edit — only the target `state` string differs
//! (`visible` vs `hidden`). Routing: when the
//! node's management plane is reachable the tool reads the authoritative `channel`
//! there and writes that channel's sidecar (bucket for S3, inbox for a local
//! dataset); a remote tool falls back to S3 ownership + the `--s3` / `--local`
//! override. The edit is **refused unless the dataset is currently live**
//! (`visible`/`hidden`) per the state endpoint.
//!
//! The routing + sidecar writes live in [`crate::state`]; this is the thin clap
//! wrapper that resolves the profile, the channel, and the S3 store / inbox.

use std::path::Path;

use gdi_node_standalone_core::id::is_valid_dataset_id;

use crate::cli::PublishArgs;
use crate::state::{self, Channel};
use crate::{ToolError, runtime, s3};

/// Run `publish` (`visible`) or `unpublish` (`hidden`).
///
/// # Errors
///
/// Returns a [`ToolError`] on an invalid id, an unroutable channel, a not-live
/// dataset, or a filesystem failure (all exit 1). A failure writing the sidecar to
/// S3 is classified by kind (auth exits 4, transient exits 3, otherwise 1); any
/// failure in the S3 package-existence pre-check (used when the node is unreachable)
/// exits 1.
pub fn run(
    args: &PublishArgs,
    make_visible: bool,
    profile_name: Option<&str>,
    config_path: Option<&Path>,
) -> Result<(), ToolError> {
    let started = std::time::Instant::now();
    if !is_valid_dataset_id(&args.id) {
        return Err(ToolError::user(format!("invalid dataset id: {}", args.id)));
    }
    // `--inbox` stands in for a profile entirely; see `state::load_profile_for_edit`.
    let active = state::load_profile_for_edit(args.inbox.as_deref(), config_path, profile_name)?;

    // Resolve the authoritative node view (management plane), if reachable.
    let node_state = state::resolve_node_state(&active, &args.id, args.management_url.as_deref())?;
    // On a multi-bucket node, warn if this profile's declared channel is not the one the
    // node reports owning the dataset: the sidecar is written to this profile's bucket, so
    // a wrong-profile op would be silently ignored.
    state::warn_channel_mismatch(node_state.as_ref(), &active);

    // Refuse unless the dataset is currently live (visible/hidden). When the node
    // is unreachable, the live state cannot be confirmed, so the edit is allowed to
    // proceed (the node is the backstop — it ignores a sidecar for an unknown id).
    if let Some(ns) = &node_state
        && !ns.is_live()
    {
        return Err(ToolError::user(format!(
            "dataset {} is not live (state: {}); only a visible/hidden dataset can be \
                 published/unpublished",
            args.id, ns.state
        )));
    }

    // `--inbox` names a filesystem target, so it implies the local channel.
    let local = args.local || args.inbox.is_some();
    let channel = state::resolve_channel(node_state.as_ref(), &active, args.s3, local)?;
    state::guard_inbox_flag_matches_channel(args.inbox.as_deref(), channel, &args.id)?;
    let target_state = if make_visible { "visible" } else { "hidden" };
    let channel_label = match &channel {
        Channel::S3 => "s3",
        Channel::Inbox => "inbox",
    };
    crate::output::note(&format!(
        "setting {} to {target_state} on channel {channel_label}",
        args.id
    ));

    let target = match channel {
        Channel::S3 => {
            let s3_cfg = active.s3.as_ref().ok_or_else(|| {
                ToolError::user(
                    "this dataset is S3-owned but the active profile has no \
                     [profiles.<name>.s3] block",
                )
            })?;
            s3::install_crypto_provider();
            let store = s3::build_object_store(s3_cfg)?;
            // When the management plane was unreachable, liveness could not be confirmed
            // above. Before writing a sidecar for a phantom id, confirm the package is
            // actually in the bucket (mirroring delete's S3 fallback) — otherwise
            // `publish <typo'd / never-uploaded id>` prints success though the node
            // ignores the orphan sidecar.
            if node_state.is_none() {
                crate::output::note(&format!(
                    "node unreachable; confirming package {} exists in the bucket before writing a \
                     sidecar",
                    args.id
                ));
            }
            if node_state.is_none()
                && !runtime::block_on(async { s3::package_exists(&store, &args.id).await })?
            {
                return Err(ToolError::user(format!(
                    "dataset {} has no package in the bucket; upload it first (the node ignores \
                     a sidecar for an id it has no package for)",
                    args.id
                )));
            }
            crate::output::note(&format!(
                "writing the S3 state sidecar for {} = {target_state} and bumping the sync marker",
                args.id
            ));
            runtime::block_on(state::s3_set_state(&store, &args.id, target_state))?;
            crate::s3::target_label(s3_cfg)
        }
        Channel::Inbox => {
            let inbox = state::resolve_inbox_with_flag(args.inbox.as_deref(), &active)?;
            let body = crate::s3::state_sidecar_body(target_state, false);
            crate::output::note(&format!(
                "writing the inbox state sidecar for {} = {target_state} in {}",
                args.id,
                inbox.display()
            ));
            state::inbox_write_sidecar(&inbox, &args.id, &body)?;
            format!("inbox {}", inbox.display())
        }
    };

    let verb = if make_visible {
        "published"
    } else {
        "unpublished"
    };
    crate::output::note(&format!("{verb} {} in {:.1?}", args.id, started.elapsed()));
    let (text, payload) = publish_result(
        verb,
        &args.id,
        target_state,
        &target,
        channel_label,
        make_visible,
    );
    crate::output::emit_result(args.format, &text, &payload);
    Ok(())
}

/// The `publish` / `unpublish` result: the human line and the `--format json` payload.
///
/// Pure, and separate from [`run`], so the property that matters is testable without a
/// node behind it: this command writes a sidecar and **never observes the node applying
/// it**, so neither half may report `target_state` as an achieved fact. The node reads the
/// sidecar on its next scan (`[service].rescan_interval_seconds`, default 600 s), and
/// until then the state endpoint still reports the old state — which is why the text
/// points at that endpoint as the confirmation step rather than implying the flip already
/// happened.
fn publish_result(
    verb: &str,
    id: &str,
    target_state: &str,
    target: &str,
    channel_label: &str,
    make_visible: bool,
) -> (String, serde_json::Value) {
    // The confirmation pointer is the management-plane state oracle, not `status <id>`:
    // `--inbox` fully specifies the target for this command, so publish routinely runs with
    // no tool profile at all, and on that path `status` exits 1 with "no profiles
    // configured" even when handed `--management-url`. Naming a command that fails on the
    // path this message is most often printed from would be a worse pointer than none.
    let text = format!(
        "{verb} {id}: wrote the {target_state} sidecar on {target}. The node applies it on \
         its next scan; its management-plane /datasets/{id}/state reports when it has"
    );
    let payload = serde_json::json!({
        "schemaVersion": 1,
        "status": "ok",
        "action": if make_visible { "publish" } else { "unpublish" },
        "datasetId": id,
        // The state written to the sidecar, never one read back from the node. `applied`
        // says so explicitly, because `status: ok` + `state: visible` alone reads as "the
        // dataset is now visible" and is wrong for up to one rescan interval. `deploy`
        // carries the analogous `waited` flag for the same distinction.
        "state": target_state,
        "applied": false,
        "channel": channel_label,
        "target": target,
    });
    (text, payload)
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;
    use crate::cli::{OutputFormat, PublishArgs};

    #[test]
    fn invalid_id_is_rejected_before_any_io() {
        // The id guard fires before profile load / network, so config_path is unused.
        let args = PublishArgs {
            management_url: None,
            id: "not a valid id".to_owned(),
            format: OutputFormat::Text,
            s3: false,
            local: false,
            inbox: None,
        };
        let err = run(&args, true, None, None).unwrap_err();
        assert!(
            err.message.contains("invalid dataset id"),
            "{}",
            err.message
        );
    }

    /// Neither half of the result may present the written state as an observed one. The
    /// text says what was written and names the state endpoint as the confirmation; the
    /// payload carries `applied: false` beside `state`, so a machine consumer cannot read
    /// `status: ok` + `state: visible` as "the node is serving it".
    #[test]
    fn publish_result_reports_the_write_not_an_observed_state() {
        let (text, payload) = publish_result(
            "published",
            "GDI-EE-UTARTU-20260409143052837",
            "visible",
            "inbox /srv/gdi/inbox",
            "inbox",
            true,
        );

        assert_eq!(
            payload["applied"],
            serde_json::json!(false),
            "the sidecar write is not an observation: {payload}"
        );
        assert_eq!(payload["state"], "visible", "{payload}");
        assert!(
            text.contains("wrote the visible sidecar"),
            "the text names the write it performed: {text}"
        );
        assert!(
            text.contains("next scan"),
            "the text says the flip is still pending: {text}"
        );
        assert!(
            text.contains("/datasets/GDI-EE-UTARTU-20260409143052837/state"),
            "the text names the oracle that confirms it, which unlike `status` needs no \
             tool profile: {text}"
        );
    }

    /// `unpublish` is the same seam with the other target state, so the pending-ness is
    /// reported there too rather than only on the publish path.
    #[test]
    fn unpublish_result_reports_the_write_not_an_observed_state() {
        let (text, payload) = publish_result(
            "unpublished",
            "GDI-EE-UTARTU-20260409143052837",
            "hidden",
            "s3 bucket gdi-ee",
            "s3",
            false,
        );

        assert_eq!(payload["action"], "unpublish", "{payload}");
        assert_eq!(payload["applied"], serde_json::json!(false), "{payload}");
        assert!(
            text.contains("wrote the hidden sidecar") && text.contains("next scan"),
            "{text}"
        );
    }
}
