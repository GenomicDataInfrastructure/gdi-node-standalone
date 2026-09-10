//! The `deploy` command: copy a `.tar.c4gh` package or a prepared staging
//! directory into the node's local **inbox** for ingestion (the no-S3 workflow);
//! the service then decrypts (for a `.tar.c4gh`), validates, and installs it.
//!
//! The drop is **atomic and durable**, mirroring the S3 write-order discipline: a file is
//! staged as `{name}.partial`, `fsync`ed, and `rename()`d into place; a staging dir is
//! staged as a dot-prefixed dir (each file `fsync`ed) and `rename()`d — then the inbox
//! itself is `fsync`ed. So the service's inbox scan (which ignores `*.partial` and
//! dot-prefixed entries) only ever sees a complete artifact, and a crash right after the
//! rename cannot leave a truncated package under the name the scanner ingests.
//!
//! Before deploying, when the node's management endpoint is reachable, it
//! **refuses an id already live** (`GET {management_url}/datasets/{id}/state` →
//! `visible`/`hidden`) unless `--replace` — which re-presents on purpose to retry
//! an `error`ed id, but cannot overwrite a live dataset (the node ignores a
//! changed source for a live id). If the endpoint is unreachable the deploy
//! proceeds (the node is the backstop).
//!
//! The op logic is CLI-independent ([`deploy_artifact`] takes plain paths); this
//! is the thin clap wrapper that resolves the profile + inbox + service URL.

use std::path::{Path, PathBuf};

use gdi_node_standalone_core::config::Profile;
use gdi_node_standalone_core::util::fsync_dir;

use crate::cli::DeployArgs;
use crate::pkgio::{self, TAR_C4GH_SUFFIX};
use crate::{ToolError, profile, runtime};

use crate::MANIFEST_NAME;

/// The kind of artifact being deployed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArtifactKind {
    /// A `{id}.tar.c4gh` package file.
    Package,
    /// A prepared staging directory (a `build/{id}/` dir with a `manifest.json`).
    StagingDir,
}

/// Wait for ingest, emitting the verdict in the requested format on both outcomes.
///
/// The verdict is emitted on both outcomes: a `--wait` that times out or is rejected must
/// not print nothing in `--format json` and then exit non-zero, which is the one shape a CI
/// pipeline cannot act on. The pre-drop baselines it passes through keep a re-dropped id
/// from being mistaken for the original ingest.
///
/// # Errors
///
/// Propagates the wait failure, after emitting the error verdict.
fn wait_and_emit_verdict(
    base: &str,
    args: &DeployArgs,
    result: &DeployResult,
    payload: &mut serde_json::Value,
    text: &str,
) -> Result<crate::state::NodeState, ToolError> {
    let waited = wait_for_ingest(
        base,
        &result.id,
        std::time::Duration::from_secs(args.wait_timeout),
        result.superseded_redrop_at_before.as_deref(),
        result.error_message_before.as_deref(),
        result.signature_before.as_deref(),
    );
    match waited {
        Ok(state) => {
            payload["waited"] = serde_json::Value::Bool(true);
            payload["state"] = serde_json::Value::String(state.state.clone());
            crate::output::emit_result(args.format, text, payload);
            Ok(state)
        }
        Err(e) => {
            payload["status"] = serde_json::Value::String("error".to_owned());
            payload["waited"] = serde_json::Value::Bool(true);
            payload["reason"] = serde_json::Value::String(e.to_string());
            crate::output::emit_result(args.format, text, payload);
            Err(e)
        }
    }
}

/// Run `deploy`.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) when the inbox is not configured, the artifact
/// is missing/unrecognized, the id is already live on the node without `--replace`,
/// or any filesystem step fails.
pub fn run(
    args: &DeployArgs,
    profile_name: Option<&str>,
    config_path: Option<&Path>,
) -> Result<(), ToolError> {
    let started = std::time::Instant::now();
    // `--inbox <dir>` fully specifies the local target, so it must not require a tool
    // profile — dropping a package into a directory needs nothing else, and demanding a
    // `[profiles.<name>]` block first was the single biggest friction on the local
    // (no-S3) path. Load the profile lazily: it is still consulted when present, for the
    // node management base behind the live-id guard, and `deploy_artifact` already
    // degrades gracefully to "no live-id guard" without one.
    let active = if args.inbox.is_some() {
        profile::load_active_optional(config_path, profile_name)?
    } else {
        Some(profile::load_active(config_path, profile_name)?)
    };
    let inbox = args
        .inbox
        .clone()
        .or_else(|| {
            active
                .as_ref()
                .and_then(|a| a.inbox.as_deref().map(PathBuf::from))
        })
        .ok_or_else(|| {
            ToolError::user(
                "no inbox configured: pass --inbox <dir> or set the profile's inbox path",
            )
        })?;
    crate::output::note(&format!("inbox: {}", inbox.display()));

    // Resolved once and passed to both the pre-drop baselines and the `--wait` poll, so
    // the two can never read different planes. If the baselines were taken from the profile
    // while the poll preferred `--management-url`, a wizard-authored profile (which
    // collects only `service_url`) would probe the public plane, which 404s
    // `/datasets/{id}/state`, and every baseline would come back `None` — enough for
    // `error_is_about_this_drop` to blame a previous ingest's error on this drop, and for
    // `drop_was_ignored` to advise taking a healthy dataset down.
    let state_base = args
        .management_url
        .as_deref()
        .or_else(|| active.as_ref().and_then(Profile::node_state_base));
    let result = deploy_artifact(&args.artifact, &inbox, state_base, args.replace)?;
    crate::output::note(&format!("deploy complete in {:.1?}", started.elapsed()));
    let text = if result.kind == "staging-dir" {
        format!(
            "deployed {} (staging dir) -> {}",
            result.id,
            result.path.display()
        )
    } else {
        format!("deployed {} -> {}", result.id, result.path.display())
    };
    // Built now, emitted once — after the wait when `--wait` is set. Emitting here and
    // then waiting would make `--wait --format json` pay for the poll and yield no
    // machine-readable verdict, and would put `"status":"ok"` on stdout beside exit 1 for
    // a rejected package, since `wait_for_ingest` returns `Err` on the `error` state.
    let mut payload = serde_json::json!({
        "schemaVersion": 1,
        "status": "ok",
        "action": "deploy",
        "datasetId": result.id,
        "kind": result.kind,
        "target": result.path.display().to_string(),
    });
    if !args.wait {
        crate::output::emit_result(args.format, &text, &payload);
    }
    if args.wait {
        // `--management-url` before the profile's: otherwise `--inbox --wait` would be
        // impossible without a profile, and `--inbox` exists precisely so the local path
        // needs none. `--inbox` says where to drop it; this says where to watch it land.
        // Resolved once above and reused here, so the pre-drop baselines and this poll can
        // never read different planes.
        let base = state_base.ok_or_else(|| {
            ToolError::user(
                "--wait needs the node's management plane to poll the dataset-state oracle. \
                     Pass --management-url <URL>, or configure a profile with management_url / \
                     service_url. (Or drop --wait and poll with `status <id>`.)",
            )
        })?;
        let state = wait_and_emit_verdict(base, args, &result, &mut payload, &text)?;
        eprintln!(
            "note: ingest finished: {id} is {state}. {next}",
            id = result.id,
            state = state.state,
            next = if state.is_hidden() {
                format!(
                    "Run `{}` to make it visible.",
                    publish_hint(args, &result.id)
                )
            } else {
                "It is being served.".to_owned()
            }
        );
        return Ok(());
    }
    // The node ingests asynchronously; nudge the next steps (stderr, so stdout stays a
    // clean result line).
    eprintln!(
        "note: the node ingests asynchronously; run `status {id}` / `check {id}` to confirm, \
         then `{publish}` to make it visible (or re-run with `--wait` to block until \
         ingest finishes)",
        id = result.id,
        publish = publish_hint(args, &result.id)
    );
    Ok(())
}

/// The exact `publish` invocation that will work from here.
///
/// A deploy driven by `--inbox` needs no profile — so telling that caller to run a bare
/// `publish <id>` hands them the very "no profiles configured" error the `--inbox` escape
/// hatch exists to avoid. Carry the flag through, so the suggested next step is one they
/// can actually paste.
fn publish_hint(args: &DeployArgs, id: &str) -> String {
    args.inbox.as_ref().map_or_else(
        || format!("publish {id}"),
        |dir| format!("publish {id} --inbox {}", dir.display()),
    )
}

/// How often `--wait` re-probes the node's dataset-state oracle.
const WAIT_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Whether the node has processed the bytes this drop wrote — the "has it looked at my
/// drop yet?" question, asked in one place.
///
/// `last_seen_signature` is the node's opaque id for the bytes it last processed (an S3
/// `ETag`, or an inbox package's content hash), so it changes exactly when the node has
/// looked at a different artifact under this id.
///
/// Every terminal arm of the wait loop needs it. Without it on the `is_live` arm, an
/// already-live id returns success on the first poll — milliseconds after the rename, long
/// before the node has hashed the package — so `deploy --replace --wait`, the sanctioned
/// correction flow, would report "It is being served" and exit 0 while the node quarantines
/// the corrected package as an immutable re-drop and keeps serving the old data. It also
/// keeps the `drop_was_ignored` arm reachable: that guard needs `superseded_redrop_at` to
/// be stamped, which requires the full package hash.
///
/// Pure and separate from the loop, so the truth table is testable without a stub node.
fn node_has_processed_this_drop(
    signature_before: Option<&str>,
    signature_now: Option<&str>,
) -> bool {
    match signature_now {
        // `last_seen_signature` changes exactly when the node has looked at a different
        // artifact under this id.
        Some(now) => signature_before != Some(now),
        // An older node that does not send the field: the question is unanswerable, so keep
        // the previous behaviour rather than waiting out the whole deadline. Weaker, and
        // visible here rather than implied by an arm that never asked.
        None => true,
    }
}

/// Whether an `error` state read now was caused by this drop, rather than being a terminal
/// error the id already carried before the upload.
///
/// With a `last_seen_signature` from the node the answer is
/// [`node_has_processed_this_drop`]; without one (an older node) it falls back to comparing
/// the error message against the pre-drop one — weaker, since an identical rejection of new
/// bytes reads as "unchanged", which is why the fallback is a visible arm rather than folded
/// into the signature one.
fn error_is_about_this_drop(
    signature_before: Option<&str>,
    signature_now: Option<&str>,
    error_before: Option<&str>,
    error_now: Option<&str>,
) -> bool {
    match signature_now {
        // The node has processed different bytes than it had before the drop: this error is
        // about our upload. Terminal.
        Some(_) => node_has_processed_this_drop(signature_before, signature_now),
        // No signature: an older node that does not send the field. Fall back to message
        // equality — weaker, and the reason this branch is kept rather than deleted.
        None => error_before.is_none_or(|before| before != error_now.unwrap_or_default()),
    }
}

/// Poll the node's dataset-state oracle until `id` reaches a terminal ingest state.
///
/// Ingest is asynchronous, so the alternative is a hand-rolled poll loop in the caller's
/// shell. This one is bounded and — the part a naive `until state == visible` loop gets
/// wrong — failure-aware: a package the node rejects lands in `error`, which a naive loop
/// waits out to the timeout and then reports as a timeout instead of the rejection reason.
///
/// `processing`, and an id the node has not seen yet (`None`), are the states worth waiting
/// on; `visible`/`hidden` are success; `error` is a hard failure carrying the node's reason.
///
/// The `*_before` parameters are the node's view of this id captured before the drop, so a
/// pre-existing terminal state is not blamed on this deploy. `signature_before` carries the
/// decision: `last_seen_signature` changes exactly when the node has processed different
/// bytes under this id, which distinguishes "has not looked at my upload yet" from "looked
/// at it and rejected it". `error_before` is the fallback for a node too old to send a
/// signature.
///
/// # Errors
///
/// Returns a [`ToolError`] if the node rejected the package (`error`), if `base` is
/// reachable but is not the node's management plane, if `base` is malformed or is plaintext
/// `http` to a non-loopback host, or if `timeout` elapses first. An oracle that is merely
/// unreachable is not an error here — it is probed as "not seen yet" and surfaces only as
/// that timeout.
///
/// Shared with `upload`: ingest is asynchronous on both install channels, and every
/// judgement this loop makes — a rejection is terminal, a pre-existing `error` is not this
/// drop's, a live id means the package was ignored — is a property of the node's oracle,
/// not of how the bytes arrived. The S3 channel differs only in being polled rather than
/// watched, which is latency, not semantics. Kept as one implementation because the
/// failure-awareness is the whole value; a second hand-rolled loop for the bucket path is
/// exactly the naive `until state == visible` loop this exists to replace.
pub(crate) fn wait_for_ingest(
    base: &str,
    id: &str,
    timeout: std::time::Duration,
    superseded_before: Option<&str>,
    error_before: Option<&str>,
    signature_before: Option<&str>,
) -> Result<crate::state::NodeState, ToolError> {
    // Establish that `base` is actually the management plane before polling it.
    //
    // The dataset-state oracle lives only on the management plane; the public plane 404s on
    // it, and `probe_node_state` maps every non-2xx to `None`, i.e. "the node has not seen
    // this id yet". Pointing `--wait` at a `service_url` — what `node_state_base` falls back
    // to, and all the wizard's setup collects — would poll a plane that can never answer,
    // burn the whole timeout, and then blame the node for a dataset that ingested seconds
    // ago. Fail fast, and name the actual mistake.
    ensure_management_plane(base)?;

    let deadline = std::time::Instant::now() + timeout;
    // Set on the poll that saw a pre-existing error and declined to blame this drop for it,
    // so the timeout can say which of the two ambiguous things happened instead of guessing.
    let mut stale_error = false;
    crate::output::note(&format!("waiting for the node to ingest {id}..."));
    loop {
        // One detailed probe per poll. The plain `probe_node_state` folds `410 Gone` into
        // the same `None` as "unreachable" and "not seen yet", which would keep `--wait`
        // polling an id the node has permanently refused and then blame a slow ingest.
        match runtime::block_on(crate::state::probe_node_state_detailed(base, id))? {
            // Tombstoned: terminal, and the node says why.
            crate::state::NodeProbe::Gone(reason) => {
                return Err(ToolError::user(format!(
                    "the node has deleted {id} and refuses this drop: {reason}"
                )));
            }
            crate::state::NodeProbe::Live(state) if state.is_error() => {
                // Distinguish this drop's rejection from one that was already there.
                //
                // Nothing on the inbox path writes `processing`; the only writer is the S3
                // write-back. A re-drop's first poll therefore sees whatever the previous
                // ingest left, and for the documented retry flow (`deploy --replace --wait`
                // after a rejection) that is `error`. Reporting it would exit 1 with the
                // stale reason while the node goes on to ingest the corrected package. The
                // `visible` arm compares against the same pre-drop baseline.
                if error_is_about_this_drop(
                    signature_before,
                    state.last_seen_signature.as_deref(),
                    error_before,
                    state.error_message.as_deref(),
                ) {
                    return Err(ToolError::user(format!(
                        "the node rejected {id}: {}",
                        state
                            .error_message
                            .as_deref()
                            .unwrap_or("no reason reported by the node")
                    )));
                }
                stale_error = true;
            }
            // The node ignored this drop: a live dataset is immutable, so a re-presented
            // (corrected) package under the same id is quarantined and the existing entry
            // stays `visible`. Without this arm the first poll would see that pre-existing
            // `visible` and report "it is being served" for a package the node rejected,
            // while it keeps serving the old data — the contract is that a rejected package
            // exits non-zero with the node's reason.
            //
            // Compared against the value observed before the drop rather than against the
            // tool's own clock: the stamp is node-generated, so a time comparison would
            // import provider/node clock skew into a correctness decision. A change is
            // unambiguous.
            crate::state::NodeProbe::Live(state)
                if drop_was_ignored(state.superseded_redrop_at.as_deref(), superseded_before) =>
            {
                return Err(ToolError::user(format!(
                    "the node ignored this drop of {id}: the dataset is already live and \
                     immutable, so the re-presented package was quarantined and the node \
                     keeps serving the previous data (superseded at {}). Take the dataset \
                     down and re-add it, or publish under a new id.",
                    state.superseded_redrop_at.as_deref().unwrap_or("unknown")
                )));
            }
            // `visible` / `hidden` — the node is done with it, one way or the other, and
            // it has processed the bytes just dropped. Without the second half this returns
            // success for a still-live previous package, the state every `--replace` starts
            // from.
            crate::state::NodeProbe::Live(state)
                if state.is_live()
                    && node_has_processed_this_drop(
                        signature_before,
                        state.last_seen_signature.as_deref(),
                    ) =>
            {
                return Ok(*state);
            }
            // `processing`, an id the node has not picked up yet, no authoritative view
            // of it (`Unknown`), or an oracle that did not answer this poll
            // (`Unreachable` — the node may be restarting): keep waiting.
            _ => {}
        }
        if std::time::Instant::now() >= deadline {
            if stale_error {
                // `stale_error` latches on the poll that observed it and is never cleared,
                // so it reports what was true at some poll, not necessarily the last one.
                // The message says "was still reporting" for that reason.
                //
                // The reason string comes from `error_before`, which reaching this branch
                // proves is `Some`: `stale_error` is only set on the fallback path, which
                // requires `error_before.is_some_and(..)` to have matched. A pre-existing
                // error with no message arrives as `Some("")` from the producer's own
                // `unwrap_or_default`, so match it explicitly rather than rendering "()".
                let reason = match error_before {
                    Some("") | None => "no reason reported by the node".to_owned(),
                    Some(r) => r.to_owned(),
                };
                return Err(ToolError::user(format!(
                    "timed out after {}s waiting for the node to ingest {id}. At the last \
                     poll that saw it, the node was still reporting the same error it \
                     reported before this drop ({reason}), so either it has not re-ingested \
                     yet or the new package failed the same way. Check with `status {id}`, \
                     or raise --wait-timeout.",
                    timeout.as_secs(),
                )));
            }
            return Err(ToolError::user(format!(
                "timed out after {}s waiting for the node to ingest {id}. It may still be \
                 processing. Check with `status {id}`, or raise --wait-timeout.",
                timeout.as_secs()
            )));
        }
        std::thread::sleep(WAIT_POLL_INTERVAL);
    }
}

/// Did the node ignore the drop `--wait` is watching?
///
/// `observed` is the node's `superseded_redrop_at` now; `before` is the value read just
/// before the artifact was dropped. A live dataset is immutable, so a re-presented package
/// is quarantined and the entry stays `visible` — meaning the current state alone cannot
/// distinguish "this drop landed" from "an earlier ingest is still live". A change in this
/// stamp can.
///
/// Compared by value, not against the tool's clock: the stamp is node-generated, so a time
/// comparison would import provider/node clock skew into a correctness decision.
fn drop_was_ignored(observed: Option<&str>, before: Option<&str>) -> bool {
    observed.is_some() && observed != before
}

/// Confirm `base` is the node's management plane before `--wait` polls it for state.
///
/// `GET /version` is served by the management router and by nothing else, so it is the
/// cheap discriminator: the public plane 404s on it exactly as it 404s on
/// `/datasets/{id}/state`. Without this check a `--wait` aimed at the public plane is
/// indistinguishable from a slow ingest, and only reveals itself as a timeout that blames
/// the node for the operator's wrong URL.
///
/// A node that is merely unreachable is not an error here — the poll loop below is the
/// right place to tolerate that (it may still be starting). Only a reachable endpoint that
/// answers `/version` with a non-2xx is proof of the wrong plane.
///
/// # Errors
///
/// Returns a [`ToolError`] when `base` is reachable but is not a management plane.
fn ensure_management_plane(base: &str) -> Result<(), ToolError> {
    let url = format!("{}/version", base.trim_end_matches('/'));
    let Ok(client) = gdi_node_standalone_core::tls::https_client_builder()
        .timeout(crate::state::PROBE_TIMEOUT)
        .build()
    else {
        return Ok(()); // cannot build a client; let the poll loop report the real failure
    };
    let probe = runtime::block_on(async {
        client
            .get(&url)
            .send()
            .await
            .map_err(|e| ToolError::user(format!("probing {url}: {e}")))
    });
    let Ok(resp) = probe else {
        return Ok(()); // unreachable: the node may still be coming up; let the loop wait
    };
    if resp.status().is_success() {
        return Ok(());
    }
    Err(ToolError::user(format!(
        "{base} answered, but it is not the node's management plane (GET /version -> {}). \
         The dataset-state oracle `--wait` polls lives only on the management plane \
         ([service].management_addr, default :9090); the public plane does not serve it, so \
         waiting here would poll forever. Point --management-url (or the profile's \
         management_url) at the management plane, or drop --wait and poll with `status`.",
        resp.status().as_u16()
    )))
}

/// What a successful [`deploy_artifact`] dropped into the inbox.
#[derive(Debug)]
pub struct DeployResult {
    /// The dataset id.
    pub id: String,
    /// `"package"` (a `.tar.c4gh`) or `"staging-dir"`.
    pub kind: &'static str,
    /// The final path written into the inbox.
    pub path: PathBuf,
    /// The node's `superseded_redrop_at` as observed before this drop, when a management
    /// base was configured. `--wait` compares against it: a change means the node ignored
    /// this drop, which is otherwise indistinguishable from an earlier ingest still being
    /// live. `None` when no base was configured or the node had no view of the id.
    pub superseded_redrop_at_before: Option<String>,
    /// The node's `error_message` for this id before the drop, when it was already in
    /// `error`. A retry (`deploy --replace --wait` after a rejection) is the documented
    /// flow, so this is the common case, not an edge one — see `wait_for_ingest`.
    pub error_message_before: Option<String>,
    /// The node's `last_seen_signature` for this id before the drop, if the node knew the
    /// id at all. The discriminator `wait_for_ingest` uses to tell "the node has not looked
    /// at my upload yet" from "the node looked and rejected it" — see that function.
    pub signature_before: Option<String>,
}

/// Deploy `artifact` into `inbox`, optionally guarded by the node's
/// management-plane state (`node_state_base` = the profile's `management_url`, else
/// `service_url`), atomically. CLI-independent (plain args).
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) on a missing/unrecognized artifact, a live-id
/// refusal, or any filesystem failure.
pub fn deploy_artifact(
    artifact: &Path,
    inbox: &Path,
    node_state_base: Option<&str>,
    replace: bool,
) -> Result<DeployResult, ToolError> {
    let (kind, id) = classify(artifact)?;
    crate::output::note(&format!(
        "artifact {} -> dataset {id} ({})",
        artifact.display(),
        match kind {
            ArtifactKind::Package => "package",
            ArtifactKind::StagingDir => "staging-dir",
        }
    ));

    // Probe the node's view once, before the drop, and use it for two things: the live-id
    // guard below, and the `superseded_redrop_at` baseline returned to `--wait`.
    //
    // The baseline is why this runs even under `--replace`. A live dataset is immutable,
    // so re-presenting a corrected package under the same id is quarantined and the existing
    // entry stays `visible` — and `--wait`, polling only the current state, would see that
    // pre-existing `visible` on its first poll and report success for a package the node
    // rejected. Comparing against the value observed before the drop is what distinguishes
    // "this drop landed" from "some earlier ingest is still live".
    let before = match node_state_base {
        Some(base) => runtime::block_on(crate::state::probe_node_state(base, &id))?,
        None => None,
    };

    // The management-plane guard: refuse a live id unless --replace. An unreachable
    // management plane (or no configured base) proceeds — the node is the backstop.
    if replace {
        crate::output::note("--replace set: skipping the live-id guard");
    } else if node_state_base.is_none() {
        crate::output::note("no node management base configured: skipping the live-id guard");
    }
    if !replace
        && let Some(node_state) = before.as_ref()
        && node_state.is_live()
    {
        return Err(ToolError::user(format!(
            "dataset {id} is already live on the node (state: {}); a live dataset \
                         cannot be overwritten (use --replace only to retry an error'ed id)",
            node_state.state
        )));
    }

    // Require the inbox rather than create it — see `state::require_inbox`. Creating it
    // would let a mistyped `--inbox` silently receive a full staging directory that the
    // node never reads.
    crate::state::require_inbox(inbox)?;

    let (kind_label, path) = match kind {
        ArtifactKind::Package => ("package", deploy_file(artifact, inbox, &id, replace)?),
        ArtifactKind::StagingDir => ("staging-dir", deploy_dir(artifact, inbox, &id, replace)?),
    };
    Ok(DeployResult {
        id,
        kind: kind_label,
        path,
        superseded_redrop_at_before: before.as_ref().and_then(|s| s.superseded_redrop_at.clone()),
        error_message_before: before.as_ref().and_then(|s| {
            s.is_error()
                .then(|| s.error_message.clone().unwrap_or_default())
        }),
        signature_before: before.as_ref().and_then(|s| s.last_seen_signature.clone()),
    })
}

/// Classify the artifact as a package or staging dir and derive its dataset id.
fn classify(artifact: &Path) -> Result<(ArtifactKind, String), ToolError> {
    if artifact.is_dir() {
        if !artifact.join(MANIFEST_NAME).is_file() {
            return Err(ToolError::user(format!(
                "staging directory has no {MANIFEST_NAME}: {}",
                artifact.display()
            )));
        }
        let id = staging_dir_id(artifact)?;
        Ok((ArtifactKind::StagingDir, id))
    } else if artifact.is_file() {
        let id = pkgio::dataset_id_from_package(artifact)?;
        Ok((ArtifactKind::Package, id))
    } else {
        Err(ToolError::user(format!(
            "artifact not found: {}",
            artifact.display()
        )))
    }
}

/// Derive the dataset id from a staging directory's name (`build/{id}/`).
fn staging_dir_id(dir: &Path) -> Result<String, ToolError> {
    let id = dir.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
        ToolError::user(format!(
            "cannot derive a dataset id from staging path {}",
            dir.display()
        ))
    })?;
    if !gdi_node_standalone_core::id::is_valid_dataset_id(id) {
        return Err(ToolError::user(format!(
            "staging directory name is not a valid dataset id: {}",
            dir.display()
        )));
    }
    Ok(id.to_owned())
}

/// Refuse an existing inbox target unless `replace`, and clear it when `replace`.
///
/// One policy for both local writers, which must not disagree: if `deploy_dir` refused an
/// existing target while `deploy_file` renamed straight over it, the same command would
/// silently replace a package awaiting ingest but reject the byte-equivalent staging-dir
/// operation. Threading the same parameter through both is what binds it — a writer that
/// omits it does not type-check against the dispatch site.
fn clear_or_refuse(
    final_path: &Path,
    id: &str,
    replace: bool,
    what: &str,
) -> Result<(), ToolError> {
    if !final_path.exists() {
        return Ok(());
    }
    if !replace {
        return Err(ToolError::user(format!(
            "inbox already holds a {what} for {id}: {}. It may be awaiting or retrying ingest. \
             Pass --replace to overwrite it, or remove it first.",
            final_path.display()
        )));
    }
    let cleared = if final_path.is_dir() {
        std::fs::remove_dir_all(final_path)
    } else {
        std::fs::remove_file(final_path)
    };
    cleared.map_err(|e| ToolError::user(format!("cannot replace {}: {e}", final_path.display())))
}

/// Atomically **and durably** drop a `.tar.c4gh` package: copy to
/// `{id}.tar.c4gh.partial`, `fsync` it, then `rename()` to `{id}.tar.c4gh` (same
/// filesystem) and `fsync` the inbox. The `*.partial` name is ignored by the inbox scan
/// until the rename completes.
///
/// The `fsync`s matter because the service ingests whatever appears under the final name:
/// a bare `rename` is atomic (visibility) but not durable, so a crash could publish a
/// zero-length or truncated package under the exact name the scanner picks up. Any failure
/// before the rename removes the partial rather than stranding it on the inbox volume.
fn deploy_file(
    package: &Path,
    inbox: &Path,
    id: &str,
    replace: bool,
) -> Result<PathBuf, ToolError> {
    let final_name = format!("{id}{TAR_C4GH_SUFFIX}");
    let final_path = inbox.join(&final_name);
    // Same policy the staging-dir writer applies. The `rename` below would otherwise
    // publish straight over a package already queued for ingest.
    clear_or_refuse(&final_path, id, replace, "package")?;
    let partial = inbox.join(format!("{final_name}.partial"));

    // Best-effort clean of a stale partial from a prior crashed deploy.
    let _ = std::fs::remove_file(&partial);
    // Progress over the stage copy: a cross-device inbox (network mount / different disk)
    // makes this a multi-GB, multi-second copy that would otherwise show a dead terminal.
    let total = std::fs::metadata(package).map_or(0, |m| m.len());
    let sp = crate::progress::StreamProgress::new(
        total,
        &format!("deploying {id}"),
        crate::progress::active(),
    );
    let staged = stage_package(package, &partial, &sp);
    sp.finish();
    // Every failure between creating and renaming the partial must clean it up: on a
    // space-constrained inbox that leak wastes the very space that caused the failure.
    if let Err(e) = staged {
        let _ = std::fs::remove_file(&partial);
        return Err(e);
    }
    std::fs::rename(&partial, &final_path).map_err(|e| {
        let _ = std::fs::remove_file(&partial);
        ToolError::user(format!(
            "cannot finalize {} -> {}: {e}",
            partial.display(),
            final_path.display()
        ))
    })?;
    // The rename published the scanned name; make that directory entry durable too.
    fsync_dir(inbox);
    Ok(final_path)
}

/// Copy `package` into `partial` and `fsync` it, so the bytes are on stable storage before
/// the caller's `rename` publishes them under the name the inbox scanner ingests.
#[expect(
    clippy::disallowed_methods,
    reason = "this is the durable write; `write_durable_atomic` cannot stream a large file"
)]
fn stage_package(
    package: &Path,
    partial: &Path,
    sp: &crate::progress::StreamProgress,
) -> Result<(), ToolError> {
    let stage_err = |e: std::io::Error| {
        ToolError::user(format!(
            "cannot stage {} -> {}: {e}",
            package.display(),
            partial.display()
        ))
    };
    let mut src = std::fs::File::open(package)
        .map_err(|e| ToolError::user(format!("cannot read {}: {e}", package.display())))?;
    let mut dst = std::fs::File::create(partial).map_err(stage_err)?;
    {
        let mut writer = sp.wrap_write(&mut dst);
        std::io::copy(&mut src, &mut writer).map_err(stage_err)?;
    }
    dst.sync_all()
        .map_err(|e| ToolError::user(format!("cannot flush {} to disk: {e}", partial.display())))
}

/// Atomically drop a staging directory: copy into a dot-prefixed temp dir then
/// `rename()` to `{id}` (same filesystem). The dot-prefixed name is ignored by the
/// inbox scan until the rename completes.
fn deploy_dir(staging: &Path, inbox: &Path, id: &str, replace: bool) -> Result<PathBuf, ToolError> {
    let final_path = inbox.join(id);
    clear_or_refuse(&final_path, id, replace, "staging dir")?;
    let temp = inbox.join(format!(".{id}.partial"));
    let _ = std::fs::remove_dir_all(&temp);
    // As in `deploy_file`: a failed copy must not strand the temp tree on the inbox volume.
    if let Err(e) = copy_dir_recursive(staging, &temp) {
        let _ = std::fs::remove_dir_all(&temp);
        return Err(e);
    }
    std::fs::rename(&temp, &final_path).map_err(|e| {
        let _ = std::fs::remove_dir_all(&temp);
        ToolError::user(format!(
            "cannot finalize {} -> {}: {e}",
            temp.display(),
            final_path.display()
        ))
    })?;
    // The rename published the scanned name; make that directory entry durable too.
    fsync_dir(inbox);
    Ok(final_path)
}

/// Recursively copy regular files + directories from `src` into `dst`. Symlinks /
/// special files are not expected in a `build` staging dir; if encountered they are
/// rejected (the service applies the same containment rules on ingest).
///
/// Each copied file is `fsync`ed and each populated directory entry-list is `fsync`ed, so
/// the caller's `rename` publishes a tree that is durable, not merely visible.
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), ToolError> {
    #[expect(
        clippy::disallowed_methods,
        reason = "a copy into the inbox ingress, whose mode is the operator's decision"
    )]
    std::fs::create_dir_all(dst)
        .map_err(|e| ToolError::user(format!("cannot create {}: {e}", dst.display())))?;
    let entries = std::fs::read_dir(src)
        .map_err(|e| ToolError::user(format!("cannot read {}: {e}", src.display())))?;
    for entry in entries {
        let entry =
            entry.map_err(|e| ToolError::user(format!("cannot read {}: {e}", src.display())))?;
        let file_type = entry
            .file_type()
            .map_err(|e| ToolError::user(format!("cannot stat {}: {e}", entry.path().display())))?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else if file_type.is_file() {
            #[expect(
                clippy::disallowed_methods,
                reason = "the walk classifies with DirEntry::file_type(), which does not \
                          follow symlinks, so `from` is a regular file the operator named"
            )]
            std::fs::copy(&from, &to).map_err(|e| {
                ToolError::user(format!(
                    "cannot copy {} -> {}: {e}",
                    from.display(),
                    to.display()
                ))
            })?;
            let copied = std::fs::File::open(&to)
                .map_err(|e| ToolError::user(format!("cannot reopen {}: {e}", to.display())))?;
            copied.sync_all().map_err(|e| {
                ToolError::user(format!("cannot flush {} to disk: {e}", to.display()))
            })?;
        } else {
            return Err(ToolError::user(format!(
                "refusing to deploy a non-regular file in the staging dir: {}",
                from.display()
            )));
        }
    }
    fsync_dir(dst);
    Ok(())
}

// The node-state probe (`GET {base}/datasets/{id}/state`) is single-sourced in
// `crate::state::probe_node_state`, which returns a typed `NodeState`. `run` above calls it
// directly, so `deploy` holds no private copy that could drift from it.

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
mod tests {
    use super::*;

    /// `--wait` must not report success for a drop the node ignored.
    ///
    /// Re-presenting a corrected package under a live, immutable id is quarantined and the
    /// existing entry stays `visible`. Polling only the current state would see that
    /// pre-existing `visible` on the first poll and report success while the node keeps
    /// serving the old data. The contract is the opposite: a rejected package exits
    /// non-zero with the node's reason. A change in `superseded_redrop_at` is what tells
    /// the two apart.
    #[test]
    fn an_ignored_redrop_is_distinguished_from_an_earlier_live_ingest() {
        // Nothing ignored before, something ignored now: this drop was the one ignored.
        assert!(
            drop_was_ignored(Some("2026-07-29T10:00:00Z"), None),
            "a stamp appearing after our drop means the node ignored it"
        );
        // A new ignore on top of an older one is still ours.
        assert!(
            drop_was_ignored(Some("2026-07-29T10:00:00Z"), Some("2026-07-28T09:00:00Z")),
            "a stamp that moved after our drop means the node ignored it"
        );

        // A pre-existing ignore that did not move says nothing about our drop — treating it
        // as ours would fail every subsequent deploy of an id that was ever re-dropped.
        assert!(
            !drop_was_ignored(Some("2026-07-28T09:00:00Z"), Some("2026-07-28T09:00:00Z")),
            "an unchanged stamp is not evidence about this drop"
        );
        // The ordinary path: the node never ignored anything.
        assert!(!drop_was_ignored(None, None));
        // Defensive: a stamp that vanished (id re-ingested, which clears it) is not an
        // ignore — that is the take-down-and-re-add recovery working.
        assert!(!drop_was_ignored(None, Some("2026-07-28T09:00:00Z")));
    }

    /// `--wait` aimed at the public plane must fail fast, not poll it to death.
    ///
    /// The public plane 404s on both `/version` and `/datasets/{id}/state`, and
    /// `probe_node_state` maps every non-2xx to `None`, meaning "not seen yet". Without this
    /// guard a `--wait` on the wrong plane burns the whole timeout and then blames the node
    /// for a dataset that ingested seconds earlier. A wizard-authored profile reaches it:
    /// setup collects only `service_url`, and `node_state_base` falls back to it. This binds
    /// the fast failure and that the message names the management plane.
    #[test]
    fn wait_against_a_non_management_plane_fails_fast() {
        use std::io::{Read as _, Write as _};

        // A stub that 404s everything — i.e. behaves like the public plane for /version.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind stub");
        let addr = listener.local_addr().expect("stub addr");
        std::thread::spawn(move || {
            for stream in listener.incoming().take(1) {
                let Ok(mut s) = stream else { continue };
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf);
                let _ = s.write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n");
            }
        });

        let err = ensure_management_plane(&format!("http://{addr}"))
            .expect_err("a plane that 404s /version is not the management plane");
        assert!(
            err.message.contains("not the node's management plane"),
            "must name the actual mistake: {}",
            err.message
        );
        assert!(
            err.message.contains("management_addr"),
            "must point at the knob that fixes it: {}",
            err.message
        );
    }

    /// The truth table the `--wait` loop hangs on.
    ///
    /// `error` is terminal, and the signature is what makes it decidable. Comparing
    /// `error_message` strings cannot: a package re-rejected for the same reason looks
    /// identical to the pre-existing error, so the wait would burn its whole timeout instead
    /// of exiting non-zero with the node's reason.
    #[test]
    fn a_re_rejection_is_terminal_when_the_node_has_seen_new_bytes() {
        // The hard case: same reason, but the node has processed a new artifact.
        assert!(
            error_is_about_this_drop(Some("etag-old"), Some("etag-new"), Some("bad"), Some("bad")),
            "a changed signature means the node looked at our upload; same message or not, \
             this rejection is ours and is terminal"
        );

        // The node has not picked up the drop yet: the error is the pre-existing one.
        assert!(
            !error_is_about_this_drop(Some("etag-old"), Some("etag-old"), Some("bad"), Some("bad")),
            "an unchanged signature means the node has not looked at this drop yet"
        );
        // ...and that holds even when the message differs, where message equality would
        // answer the other way.
        assert!(
            !error_is_about_this_drop(
                Some("etag-old"),
                Some("etag-old"),
                Some("bad"),
                Some("different")
            ),
            "the signature is authoritative: same bytes cannot be a new rejection"
        );

        // First sighting of an id the node had no state for: any error is about this drop.
        assert!(error_is_about_this_drop(
            None,
            Some("etag-new"),
            None,
            Some("bad")
        ));

        // Older node (no signature field): fall back to message equality rather than
        // treating every error as terminal.
        assert!(
            !error_is_about_this_drop(None, None, Some("bad"), Some("bad")),
            "without a signature the only evidence is the message, and it is unchanged"
        );
        assert!(
            error_is_about_this_drop(None, None, Some("bad"), Some("worse")),
            "a changed message is still the best available evidence on an older node"
        );
        assert!(
            error_is_about_this_drop(None, None, None, Some("bad")),
            "no pre-existing error at all means this one is ours"
        );
    }

    /// An unreachable base is not the same mistake: the node may simply still be starting, so
    /// the poll loop (which tolerates it) must get the chance to wait it out.
    #[test]
    fn wait_tolerates_an_unreachable_base_rather_than_prejudging_it() {
        // Port 1 on loopback: connection refused, not a 404.
        ensure_management_plane("http://127.0.0.1:1")
            .expect("an unreachable node must not be mistaken for the wrong plane");
    }

    const ID: &str = "GDI-EE-UTARTU-20260409143052837";

    /// The suggested next step must be one the caller can actually paste.
    ///
    /// A deploy driven by `--inbox` needs no profile, so a bare `publish <id>` hint would
    /// hand that caller the very "no profiles configured" error `--inbox` exists to avoid.
    /// The hint must carry the flag through.
    #[test]
    fn publish_hint_carries_the_inbox_flag_through() {
        let base = DeployArgs {
            artifact: PathBuf::from("x.tar.c4gh"),
            inbox: None,
            replace: false,
            wait: false,
            wait_timeout: 120,
            management_url: None,
            format: crate::cli::OutputFormat::Text,
        };
        assert_eq!(publish_hint(&base, ID), format!("publish {ID}"));

        let with_inbox = DeployArgs {
            inbox: Some(PathBuf::from("/var/lib/gdi-node-standalone/inbox")),
            ..base
        };
        assert_eq!(
            publish_hint(&with_inbox, ID),
            format!("publish {ID} --inbox /var/lib/gdi-node-standalone/inbox"),
            "a profile-free deploy must be told the profile-free publish"
        );
    }

    /// A copy that fails mid-stream (here: a "package" that opens but cannot be read)
    /// must not leave its `{id}.tar.c4gh.partial` behind — on a space-constrained inbox
    /// that leak wastes the very space that caused the failure.
    #[test]
    fn deploy_file_removes_the_partial_when_the_copy_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let inbox = tmp.path().join("inbox");
        std::fs::create_dir_all(&inbox).unwrap();
        // A directory opens as a File but returns EISDIR on read, so `io::copy` fails.
        let bogus = tmp.path().join("not-a-file");
        std::fs::create_dir_all(&bogus).unwrap();

        let err = deploy_file(&bogus, &inbox, ID, false).unwrap_err();

        assert_eq!(err.exit_code, 1);
        let partial = inbox.join(format!("{ID}{TAR_C4GH_SUFFIX}.partial"));
        assert!(
            !partial.exists(),
            "a failed stage copy must not leak {}",
            partial.display()
        );
    }

    /// The same for a staging dir: a rejected member aborts `copy_dir_recursive`, and the
    /// dot-prefixed temp dir must not survive it.
    #[cfg(unix)]
    #[test]
    fn deploy_dir_removes_the_temp_when_the_copy_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let inbox = tmp.path().join("inbox");
        std::fs::create_dir_all(&inbox).unwrap();
        let staging = tmp.path().join(ID);
        std::fs::create_dir_all(&staging).unwrap();
        // A symlink is a non-regular member: `copy_dir_recursive` refuses it.
        std::os::unix::fs::symlink("elsewhere", staging.join("link")).unwrap();

        let err = deploy_dir(&staging, &inbox, ID, false).unwrap_err();

        assert_eq!(err.exit_code, 1);
        let staged_dir = inbox.join(format!(".{ID}.partial"));
        assert!(
            !staged_dir.exists(),
            "a failed staging-dir copy must not leak {}",
            staged_dir.display()
        );
    }

    /// Both local writers must apply the same overwrite policy.
    ///
    /// If `deploy_file` renamed straight over whatever sat at the final name while
    /// `deploy_dir` refused it, one command with one artifact argument would silently
    /// replace a package awaiting (or retrying) ingest, yet reject the byte-equivalent
    /// staging-dir operation.
    #[test]
    fn both_local_writers_refuse_an_existing_target_without_replace() {
        let tmp = tempfile::tempdir().unwrap();
        let inbox = tmp.path().join("inbox");
        std::fs::create_dir_all(&inbox).unwrap();

        // A package already awaiting ingest.
        let existing = inbox.join(format!("{ID}{TAR_C4GH_SUFFIX}"));
        std::fs::write(&existing, b"awaiting-ingest").unwrap();
        let package = tmp.path().join(format!("{ID}{TAR_C4GH_SUFFIX}"));
        std::fs::write(&package, b"new-bytes").unwrap();

        let err = deploy_file(&package, &inbox, ID, false).unwrap_err();
        assert!(
            err.to_string().contains("--replace"),
            "the refusal must name the remedy: {err}"
        );
        assert_eq!(
            std::fs::read(&existing).unwrap(),
            b"awaiting-ingest",
            "the queued package must be untouched by a refused deploy"
        );

        // With --replace it goes through.
        deploy_file(&package, &inbox, ID, true).unwrap();
        assert_eq!(std::fs::read(&existing).unwrap(), b"new-bytes");
    }

    /// The happy path still publishes the artifact under its final, scanned name.
    #[test]
    fn deploy_file_publishes_the_package_and_leaves_no_partial() {
        let tmp = tempfile::tempdir().unwrap();
        let inbox = tmp.path().join("inbox");
        std::fs::create_dir_all(&inbox).unwrap();
        let package = tmp.path().join(format!("{ID}{TAR_C4GH_SUFFIX}"));
        std::fs::write(&package, b"crypt4gh-bytes").unwrap();

        let out = deploy_file(&package, &inbox, ID, false).unwrap();

        assert_eq!(out, inbox.join(format!("{ID}{TAR_C4GH_SUFFIX}")));
        assert_eq!(std::fs::read(&out).unwrap(), b"crypt4gh-bytes");
        assert!(
            !inbox
                .join(format!("{ID}{TAR_C4GH_SUFFIX}.partial"))
                .exists()
        );
    }
}
