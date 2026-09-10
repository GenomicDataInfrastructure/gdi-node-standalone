//! The `upload` command: PUT a local `.tar.c4gh` package into the active
//! profile's S3 bucket in the spec write order (package, then `hidden` state
//! sidecar, then the `_sync_marker.json` bump last), hidden by default.
//!
//! Rejects an id already present in the bucket (a fast client-side guard against
//! an accidental sub-second id collision); `--replace` re-uploads on purpose — to
//! retry an `error`ed id with a fixed package. It does **not** overwrite a live
//! dataset: the node ignores a changed source for a `visible`/`hidden` id.
//!
//! The op logic lives in [`crate::s3`] (generic over `Arc<dyn ObjectStore>`); this
//! is the thin clap wrapper that resolves the profile + reads the package bytes.

use std::path::Path;

use crate::cli::UploadArgs;
use crate::{ToolError, pkgio, profile, runtime, s3};

/// Run `upload`.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) when the profile has no `[s3]` block, the
/// package is missing/misnamed, the id is already present without `--replace`, or
/// any S3 PUT/HEAD fails.
pub fn run(
    args: &UploadArgs,
    profile_name: Option<&str>,
    config_path: Option<&Path>,
) -> Result<(), ToolError> {
    run_with_credentials(args, profile_name, config_path, None)
}

/// [`run`], with credentials the wizard collected in this process filled into the
/// profile's `[s3]` block when the environment supplies none.
///
/// The wizard's setup writes the credentials to `secrets.env` for later runs, but the
/// process that asked cannot `source` that file into its own environment — and with neither
/// credential loaded the client is anonymous, so the same run's upload is refused after
/// build + pack. Environment credentials, when present, still win.
///
/// # Errors
///
/// As [`run`].
pub fn run_with_credentials(
    args: &UploadArgs,
    profile_name: Option<&str>,
    config_path: Option<&Path>,
    credentials: Option<&s3::S3Credentials>,
) -> Result<(), ToolError> {
    let mut active = profile::load_active(config_path, profile_name)?;
    apply_carried_credentials(&mut active, credentials);
    // Two clients: the bounded one for `upload`'s small requests (the exists-check HEAD,
    // the visibility sidecar, the marker bump — a stalled endpoint must not hang a CI
    // upload forever), and the unbounded one for the multipart package body (each part is
    // its own request, so a timeout there would abort a legitimate large upload).
    let store = s3::open_store(&active, "upload")?;
    let package_store = s3::open_package_store(&active, "upload")?;
    // Echo the resolved bucket/endpoint so a wrong/forgotten --profile is visible.
    let target = active
        .s3
        .as_ref()
        .map_or_else(|| "S3".to_owned(), crate::s3::target_label);

    // `--wait` resolves its oracle and captures the node's pre-upload view of this id
    // before the PUT. Both halves must happen first: resolving after would refuse a flag
    // the operator passed only once the bytes were already in the bucket, and a baseline
    // read after the upload could already reflect it — and that baseline is what tells "the
    // node has not looked yet" apart from "it looked and rejected this".
    let wait_base = args
        .management_url
        .as_deref()
        .or_else(|| active.node_state_base())
        .map(str::to_owned);
    let before = if args.wait {
        let base = wait_base.as_deref().ok_or_else(|| {
            ToolError::user(
                "--wait needs the node's management plane to poll the dataset-state oracle. \
                 Pass --management-url <URL>, or set management_url (or service_url) on the \
                 profile. (Or drop --wait and poll with `status <id>`.)",
            )
        })?;
        let id = pkgio::dataset_id_from_package(&args.package)?;
        runtime::block_on(crate::state::probe_node_state(base, &id))?
    } else {
        None
    };

    let visibility = run_with_store(args, &store, &package_store, &target)?;

    if args.wait {
        let id = pkgio::dataset_id_from_package(&args.package)?;
        // `wait_base` is proven `Some` on this path: the baseline probe above returns the
        // "--wait needs the management plane" error before the upload when it is `None`.
        let base = wait_base.as_deref().unwrap_or_default();
        // The result is built here and emitted only after the wait, so `run_with_store`
        // emits nothing under `--wait`. Emitting before the wait would put
        // `{"status":"ok"}` on stdout and then exit non-zero when the node rejects the
        // package, so a script reading stdout would see a success object for a failed
        // upload. `deploy --wait` orders it the same way.
        let outcome = super::cmd_deploy::wait_for_ingest(
            base,
            &id,
            std::time::Duration::from_secs(args.wait_timeout),
            before
                .as_ref()
                .and_then(|s| s.superseded_redrop_at.as_deref()),
            before.as_ref().and_then(|s| s.error_message.as_deref()),
            before
                .as_ref()
                .and_then(|s| s.last_seen_signature.as_deref()),
        );
        let (text, payload) = wait_outcome(
            &id,
            visibility,
            &target,
            args.replace,
            outcome.as_ref().map(|s| s.state.as_str()),
        );
        // One object on stdout for both outcomes. A rejection carries the node's reason
        // before the non-zero exit, so a pipeline branching on stdout sees the failure.
        crate::output::emit_result(args.format, &text, &payload);
        let state = outcome?;
        // stderr, unconditionally, as `deploy --wait` prints it. `output::note` would gate
        // it behind `-v`, and `run_with_store`'s own next-step line is suppressed under
        // `--wait`, so a default-verbosity `upload --wait` would say nothing at all.
        eprintln!(
            "note: ingest finished: {id} is {}. {}",
            state.state,
            if state.is_hidden() {
                format!("Run `publish {id}` to make it visible.")
            } else {
                "It is being served.".to_owned()
            }
        );
    }
    Ok(())
}

/// Fill `credentials` into the profile's `[s3]` block — only when the block exists and the
/// environment supplied neither credential, so a configured environment always wins and a
/// profile without S3 stays without it.
fn apply_carried_credentials(
    profile: &mut gdi_node_standalone_core::config::Profile,
    credentials: Option<&s3::S3Credentials>,
) {
    if let Some(carried) = credentials
        && let Some(block) = profile.s3.as_mut()
        && block.access_key_id.is_none()
        && block.secret_access_key.is_none()
    {
        block.access_key_id = Some(carried.access_key_id.clone());
        block.secret_access_key = Some(carried.secret_access_key.clone());
    }
}

/// Build what `upload` reports: the human result line and the JSON result object.
///
/// Pure, and separate from [`run_with_store`], so a test can assert the rendered strings
/// rather than only the value behind them. That matters because the visibility is computed
/// a layer down: asserting the returned value alone would leave an edit free to print a
/// hardcoded `hidden` beside a correct value without failing anything.
fn upload_result(
    id: &str,
    visibility: s3::Visibility,
    target: &str,
    replace: bool,
) -> (String, serde_json::Value) {
    let state = visibility.as_str();
    (
        format!("uploaded {id} ({state}) to {target}"),
        serde_json::json!({
            "schemaVersion": 1,
            "status": "ok",
            "action": "upload",
            "datasetId": id,
            "channel": "s3",
            "state": state,
            "target": target,
            "replace": replace,
        }),
    )
}

/// The result line and payload `--wait` emits, built from the node's verdict.
///
/// Pure, so it is testable without a bucket or an oracle. The text and the payload must
/// agree on the outcome: a payload rewritten to `status: "error"` beside a text line that
/// still reads `uploaded {id} (hidden) to …` would print a success line to stdout and then
/// exit non-zero. The bytes are in the bucket, so the rejected line still says where; it
/// just does not read as a success.
fn wait_outcome(
    id: &str,
    visibility: s3::Visibility,
    target: &str,
    replace: bool,
    outcome: Result<&str, &ToolError>,
) -> (String, serde_json::Value) {
    let (_, mut payload) = upload_result(id, visibility, target, replace);
    payload["waited"] = serde_json::Value::Bool(true);
    match outcome {
        Ok(state) => {
            payload["state"] = serde_json::Value::String(state.to_owned());
            (
                format!("uploaded {id} to {target}; the node ingested it ({state})"),
                payload,
            )
        }
        Err(e) => {
            payload["status"] = serde_json::Value::String("error".to_owned());
            payload["reason"] = serde_json::Value::String(e.to_string());
            (
                format!("upload of {id} to {target} rejected by the node: {e}"),
                payload,
            )
        }
    }
}

/// `upload` against an already-opened store — the same code path [`run`] takes, minus
/// profile resolution.
///
/// This is the seam that makes `upload` testable. Without it, everything below the store is
/// reachable only by constructing a real S3 client, so nothing drives the reporting layer
/// and a result line claiming a flat `hidden` could stand while `s3.rs` unit-tests the
/// opposite rule one layer below. Splitting profile resolution from the operation costs
/// nothing at runtime and lets a test inject `object_store::InMemory`.
///
/// Returns the [`s3::Visibility`] it reported — the same value rendered into the result line
/// and the JSON `state`, not a recomputation. `run` discards it; a test asserts it against
/// the sidecar, which is how the CLI substituting a different visibility for the one that
/// was written is caught without capturing stdout.
///
/// # Errors
///
/// Returns a [`ToolError`] when the package is missing/misnamed, the id is already present
/// without `--replace`, or any S3 PUT/HEAD fails.
pub fn run_with_store(
    args: &UploadArgs,
    store: &s3::Store,
    package_store: &s3::PackageStore,
    target: &str,
) -> Result<s3::Visibility, ToolError> {
    let started = std::time::Instant::now();
    let id = pkgio::dataset_id_from_package(&args.package)?;
    crate::output::note(&format!(
        "uploading {id} from {}{}",
        args.package.display(),
        if args.replace { " (replace)" } else { "" }
    ));
    crate::output::note(&format!("target: {target}"));

    // Stream the package straight from disk (never read it whole into memory; not
    // bounded by the single-PUT 5 GiB ceiling).
    //
    // The visibility is what `upload_package` actually wrote, not an assumption: a fresh
    // upload is `hidden`, but `--replace` preserves a live dataset's current value.
    // Reporting a flat `hidden` would contradict that guarantee on the one path it exists
    // for, and tell a provider to `publish` a dataset that may be hidden deliberately, such
    // as after a consent withdrawal or under a legal hold.
    let visibility = runtime::block_on(s3::upload_package(
        store,
        package_store,
        &id,
        &args.package,
        args.replace,
    ))?;
    crate::output::note(&format!("upload complete in {:.1?}", started.elapsed()));

    let (text, json) = upload_result(&id, visibility, target, args.replace);
    // Under `--wait` the caller emits instead, after the wait, so a rejected upload cannot
    // print a success object and then exit non-zero (see `run_with_credentials`). Same rule
    // `deploy` follows.
    if !args.wait {
        crate::output::emit_result(args.format, &text, &json);
    }
    // The node ingests asynchronously; nudge the next steps on stderr, so stdout stays a
    // clean result line. Unlike the inbox — which the node watches, so ingest starts within
    // milliseconds of a `deploy` — an S3 bucket is polled, and nothing happens for up to a
    // poll interval after this command returns success. Naming that gap is what keeps a
    // provider from reading it as a silent failure.
    //
    // The publish nudge is conditional on what was actually written: a `--replace` that
    // preserved `visible` needs no publish, and suggesting one anyway is the advice that
    // bites when a dataset is hidden on purpose (a consent withdrawal, a legal hold), where
    // `publish` would disclose it.
    let next_step = if visibility == s3::Visibility::Hidden {
        format!("then `publish {id}` to make it visible")
    } else {
        "no `publish` is needed; --replace preserved its current visibility".to_owned()
    };
    // One line, and only when the caller is not waiting. It fires on every upload, so it
    // carries just the two things a provider acts on — that the wait is expected, and what
    // to run next; the poll intervals they cannot change from here are documented in the
    // `upload` section of docs/gdi-dataset-tool.md. Under `--wait` it would be wrong: the
    // caller is about to be told the terminal state, so there is no gap to explain.
    if !args.wait {
        eprintln!(
            "note: the node polls its bucket, so {id} takes up to a few minutes to appear \
             (that gap is expected). Run `status {id}` to confirm, {next_step}. \
             Or re-run with `--wait` to block until the node has ingested it."
        );
    }
    Ok(visibility)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What is printed must carry the visibility that was written, in both formats.
    ///
    /// A literal `hidden` in either rendering would be invisible to an assertion on the
    /// value beside it, so this asserts the strings rather than the source variable.
    #[test]
    fn the_reported_result_carries_the_written_visibility() {
        let (text, json) = upload_result("GDI-EE-UTARTU-1", s3::Visibility::Visible, "buck", true);
        assert!(
            text.contains("(visible)"),
            "the result line must state the visibility that was written: {text}"
        );
        assert!(
            !text.contains("hidden"),
            "a preserved-visible upload must never print `hidden`: {text}"
        );
        assert_eq!(json["state"], "visible", "the JSON contract must agree");
        assert_eq!(json["replace"], true);

        let (text, json) = upload_result("GDI-EE-UTARTU-1", s3::Visibility::Hidden, "buck", false);
        assert!(text.contains("(hidden)"), "{text}");
        assert_eq!(json["state"], "hidden");
    }

    /// Carried credentials fill an empty `[s3]` block only: the environment's win, and a
    /// profile without S3 gains none.
    #[test]
    fn carried_credentials_fill_an_empty_s3_block_only() {
        use gdi_node_standalone_core::config::{Profile, ProfileS3};
        let carried = s3::S3Credentials {
            access_key_id: "A".into(),
            secret_access_key: "S".into(),
        };
        let key = |p: &Profile| p.s3.as_ref().and_then(|s| s.access_key_id.clone());

        let mut none = Profile::default();
        apply_carried_credentials(&mut none, Some(&carried));
        assert!(none.s3.is_none(), "no block, nothing to fill");

        let mut empty = Profile {
            s3: Some(ProfileS3::default()),
            ..Profile::default()
        };
        apply_carried_credentials(&mut empty, Some(&carried));
        assert_eq!(key(&empty).as_deref(), Some("A"));

        let mut from_env = Profile {
            s3: Some(ProfileS3 {
                access_key_id: Some("ENV".into()),
                secret_access_key: Some("ENV".into()),
                ..ProfileS3::default()
            }),
            ..Profile::default()
        };
        apply_carried_credentials(&mut from_env, Some(&carried));
        assert_eq!(
            key(&from_env).as_deref(),
            Some("ENV"),
            "the environment wins"
        );

        let mut untouched = Profile {
            s3: Some(ProfileS3::default()),
            ..Profile::default()
        };
        apply_carried_credentials(&mut untouched, None);
        assert_eq!(key(&untouched), None);
    }

    /// A rejected `--wait` must not leave a success line on stdout: text and payload
    /// agree, and the text names the rejection and its reason.
    #[test]
    fn a_rejected_wait_reports_the_rejection_in_text_and_payload() {
        let err = ToolError::user("the node rejected it: invalid parquet");
        let (text, payload) = wait_outcome(
            "GDI-EE-UTARTU-1",
            s3::Visibility::Hidden,
            "s3://b/p",
            false,
            Err(&err),
        );
        assert!(
            !text.starts_with("uploaded"),
            "a rejection must not read as a success line: {text}"
        );
        assert!(
            text.contains("rejected") && text.contains("invalid parquet"),
            "{text}"
        );
        assert_eq!(payload["status"], "error");
        assert_eq!(payload["waited"], true);
        assert!(
            payload["reason"]
                .as_str()
                .is_some_and(|r| r.contains("invalid parquet"))
        );
    }

    /// A finished `--wait` reports the node's terminal state in both, not the S3
    /// visibility the bytes were written with.
    #[test]
    fn a_finished_wait_reports_the_nodes_terminal_state() {
        let (text, payload) = wait_outcome(
            "GDI-EE-UTARTU-1",
            s3::Visibility::Hidden,
            "s3://b/p",
            true,
            Ok("visible"),
        );
        assert!(text.contains("visible"), "{text}");
        assert_eq!(payload["status"], "ok");
        assert_eq!(payload["state"], "visible");
        assert_eq!(payload["waited"], true);
        assert_eq!(payload["replace"], true);
    }
}
