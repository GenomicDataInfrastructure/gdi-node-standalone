//! The management-plane operator action endpoints, mounted under `[control].enabled`.
//!
//! `POST /reload` is `SIGHUP` over HTTP, for deployments that cannot send the signal. Under
//! Kubernetes the mounted `ConfigMap` file updates on its own. Applying it needs
//! `kubectl exec … kill -HUP 1`, and `pods/exec` is RBAC many clusters withhold; the only
//! other option is restarting the pod, a public Beacon outage at one replica.
//!
//! The route does not re-implement the reload. It invokes the same closure the `SIGHUP`
//! handler runs, installed once at boot ([`ReloadHook`]), and unlike a signal it reports
//! whether the config was applied or refused, and why. It takes no body, so it cannot
//! inject configuration; it only tells the node to re-read its own already-trusted file.

use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse as _, Response};
use serde::Serialize;

use crate::id_guard::is_safe_dataset_id;
use crate::state::{AppState, ReingestVerdict};

/// The reconcile action's future. Boxed because it is stored behind a `dyn Fn`.
pub type ReconcileFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// The reload action's future. Boxed for the same reason as [`ReconcileFuture`].
///
/// The reload is async because resolving a bucket's credential can require a round trip to
/// Vault: `[vault].s3_path` is read at boot, so a bucket the reload adds has no entry in that
/// snapshot and must be looked up now or refused.
pub type ReloadFuture = Pin<Box<dyn Future<Output = ReloadOutcome> + Send>>;

/// Why a reload attempt did not apply, as a closed set fit for the wire.
///
/// The node logs the underlying error in full. This does not carry it, because a config
/// parse or preflight failure names filesystem paths and this plane does not put those on
/// the wire, the same rule `GET /datasets`' `500` follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReloadRejection {
    /// The file could not be read or parsed as TOML.
    Unparsable,
    /// It parsed, but failed the same startup validation boot runs.
    Invalid,
}

impl ReloadRejection {
    /// The stable wire string, also used in the `reason` field of the response body.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unparsable => "unparsable",
            Self::Invalid => "invalid",
        }
    }
}

/// What one reload attempt did: the value both triggers produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadOutcome {
    /// The reloadable subset was swapped in, and any bucket changes applied.
    ///
    /// `restart_required` is `true` when the same file also changed something outside that
    /// subset, which was therefore not applied.
    Applied {
        /// Whether the same file also changed something outside the reloadable subset,
        /// which was therefore not applied.
        restart_required: bool,
    },
    /// The candidate config was refused; the running config is untouched.
    Rejected(ReloadRejection),
}

/// The reload action itself, installed by `main` once the pieces it needs exist.
///
/// A cell rather than a constructor argument because the management router is built before
/// the ingest runtime and the bucket-monitor set it reloads. It is the same filled-later
/// `Arc` the `SIGHUP` handler already holds for the monitors. Until it is installed the
/// route answers `503`: the node is still starting, which a caller should retry.
pub struct ReloadHook {
    /// The shared implementation. `None` until `main` installs it.
    action: Mutex<Option<Box<dyn Fn() -> ReloadFuture + Send + Sync>>>,
    /// When the last action was accepted, for the `[control].min_interval_seconds` pacing.
    /// A rate-limited request does not update it, so a caller cannot hold the window open
    /// by hammering.
    last_accepted: Mutex<Option<Instant>>,
}

impl std::fmt::Debug for ReloadHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The closure is not `Debug`; report whether one is installed, the only thing a
        // reader of this struct's debug output can act on.
        let installed = self
            .action
            .lock()
            .map_or_else(|e| e.into_inner().is_some(), |g| g.is_some());
        f.debug_struct("ReloadHook")
            .field("installed", &installed)
            .finish_non_exhaustive()
    }
}

impl Default for ReloadHook {
    fn default() -> Self {
        Self::new()
    }
}

impl ReloadHook {
    /// An empty hook, with no action installed yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            action: Mutex::new(None),
            last_accepted: Mutex::new(None),
        }
    }

    /// Install the action `POST /reload` invokes. Called once, at boot, by `main`.
    pub fn install(&self, action: Box<dyn Fn() -> ReloadFuture + Send + Sync>) {
        *self
            .action
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(action);
    }

    /// Build the reload future, or `None` when `main` has not installed the action yet.
    ///
    /// Returns the future rather than awaiting it, so the guard is released before the work
    /// starts: the reload awaits a Vault read, and a `std::sync::Mutex` guard must not be
    /// held across an `.await`. Same shape as [`ReconcileHook::make_future`].
    fn make_future(&self) -> Option<ReloadFuture> {
        let guard = self
            .action
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.as_ref().map(|action| action())
    }

    /// Whether an action may run now, given `min_interval`; stamps the clock when it may.
    /// Returns the stamp it replaced, for [`Self::release`].
    fn admit(&self, min_interval: Duration, now: Instant) -> Result<Option<Instant>, u64> {
        admit_against(&self.last_accepted, min_interval, now)
    }

    /// Hand the window back after an admitted request did no work. See [`release_admission`].
    fn release(&self, previous: Option<Instant>) {
        release_admission(&self.last_accepted, previous);
    }
}

/// The pacing rule every control endpoint shares.
///
/// Returns `Err(remaining)` with the whole seconds a caller should wait, for `Retry-After`.
/// Test-and-stamp happen under one lock: two concurrent requests must not both observe an
/// open window and both proceed. A refused call does not stamp, so a caller polling faster
/// than the interval cannot push its own next admission away.
///
/// Shared by all three endpoints rather than copied per hook, so there is one place where
/// the refusal path can get the stamping wrong.
fn admit_against(
    last_accepted: &Mutex<Option<Instant>>,
    min_interval: Duration,
    now: Instant,
) -> Result<Option<Instant>, u64> {
    let mut last = last_accepted
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(prev) = *last {
        let elapsed = now.saturating_duration_since(prev);
        if elapsed < min_interval {
            // Round up: a 0 in `Retry-After` would invite an immediate retry that is still
            // inside the window. `saturating_sub` cannot underflow here, since the branch
            // established `elapsed < min_interval`, and it keeps the clock arithmetic total
            // rather than relying on that invariant holding forever.
            let remaining = min_interval.saturating_sub(elapsed);
            let secs = remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0);
            return Err(secs.max(1));
        }
    }
    let previous = last.replace(now);
    Ok(previous)
}

/// Hand a consumed window back, for a request that was admitted and then did no work.
///
/// Only the `503` arm is entitled to this, where `main` has not installed the action yet.
/// That is a bounded startup transient, and without the hand-back a client polling
/// `/reload` through a rollout burns the window, so the first request after the node
/// finishes starting is refused with `429` for up to `min_interval_seconds`.
///
/// Not used for the `500` arms. Those attempt real work and can fail persistently
/// (`/log-level` on a process with no subscriber fails every time), so releasing there
/// would hand out an unpaced retry loop.
fn release_admission(last_accepted: &Mutex<Option<Instant>>, previous: Option<Instant>) {
    *last_accepted
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = previous;
}

/// The `429` a paced endpoint returns, carrying `Retry-After`.
fn rate_limited(retry_after: u64) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [("retry-after", retry_after.to_string())],
        "control actions are rate-limited; retry after the interval",
    )
        .into_response()
}

/// The `SIGUSR1` reconcile action, installed by `main` alongside the reload one.
///
/// Async where [`ReloadHook`] is synchronous, because the work is: reload the suppression and
/// overlay stores, drain the queued re-ingest markers, rescan the inbox, wake every bucket
/// monitor. `POST /reconcile` answers `202` and does not wait, because a full rescan is
/// unbounded work and holding an operator's HTTP request open across it would tie the answer
/// to the management plane's request timeout rather than to the reconcile.
pub struct ReconcileHook {
    /// The shared implementation. `None` until `main` installs it.
    action: Mutex<Option<Box<dyn Fn() -> ReconcileFuture + Send + Sync>>>,
    /// The rate-limit clock, shared with nothing: `/reconcile` is paced independently of
    /// `/reload` because they are different work with different costs.
    last_accepted: Mutex<Option<Instant>>,
}

impl std::fmt::Debug for ReconcileHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let installed = self
            .action
            .lock()
            .map_or_else(|e| e.into_inner().is_some(), |g| g.is_some());
        f.debug_struct("ReconcileHook")
            .field("installed", &installed)
            .finish_non_exhaustive()
    }
}

impl Default for ReconcileHook {
    fn default() -> Self {
        Self::new()
    }
}

impl ReconcileHook {
    /// An empty hook, with no action installed yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            action: Mutex::new(None),
            last_accepted: Mutex::new(None),
        }
    }

    /// Install the action `POST /reconcile` invokes. Called once, at boot, by `main`.
    pub fn install(&self, action: Box<dyn Fn() -> ReconcileFuture + Send + Sync>) {
        *self
            .action
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(action);
    }

    /// Build the reconcile future, or `None` when `main` has not installed the action yet.
    ///
    /// Returns the future rather than awaiting it, so the lock is released before the work
    /// starts; the guard must not be held across an `.await`.
    fn make_future(&self) -> Option<ReconcileFuture> {
        let guard = self
            .action
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.as_ref().map(|action| action())
    }

    /// Same pacing contract as [`ReloadHook::admit`].
    fn admit(&self, min_interval: Duration, now: Instant) -> Result<Option<Instant>, u64> {
        admit_against(&self.last_accepted, min_interval, now)
    }

    /// Hand the window back after an admitted request did no work. See [`release_admission`].
    fn release(&self, previous: Option<Instant>) {
        release_admission(&self.last_accepted, previous);
    }
}

/// The verbose-logging window behind `POST /log-level`.
///
/// Holds only this endpoint's rate-limit clock. The level and its generation both live in
/// [`crate::logging`], which owns the subscriber, so `SIGUSR2` bumps the generation too and a
/// pending auto-revert is superseded by any later level change rather than only by an HTTP
/// one.
#[derive(Debug, Default)]
pub struct LogLevelWindow {
    /// This endpoint's own rate-limit clock (see [`admit_against`]).
    last_accepted: Mutex<Option<Instant>>,
}

impl LogLevelWindow {
    /// A window with nothing armed.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            last_accepted: Mutex::new(None),
        }
    }

    /// Same pacing contract as [`ReloadHook::admit`]. Flipping the level is cheap, but
    /// flapping it is not, and one knob paces all three endpoints.
    fn admit(&self, min_interval: Duration, now: Instant) -> Result<Option<Instant>, u64> {
        admit_against(&self.last_accepted, min_interval, now)
    }
}

/// The `POST /reload` response body.
#[derive(Debug, Serialize)]
struct ReloadBody {
    /// Whether the candidate config was applied.
    applied: bool,
    /// Whether the same file also changed a restart-only setting, which was not applied.
    /// Absent on a refusal, where nothing was applied at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    restart_required: Option<bool>,
    /// The closed-set refusal reason; absent when `applied`.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    /// A human-readable summary of what the caller should do next.
    detail: &'static str,
}

/// `POST /reload` — re-read the config file, exactly as `SIGHUP` does.
///
/// `200` with `{"applied": true}` when the reloadable subset was swapped in; `200` with
/// `{"applied": false, "reason": …}` when the candidate config was refused and the running
/// one kept. A refusal is an answer, not a transport failure, and the node is healthy either
/// way. `429` while inside the `[control].min_interval_seconds` window, with `Retry-After`.
/// `503` before `main` has installed the action, while the node is still starting.
///
/// Idempotent: re-reading the same file twice applies the same subset twice, so the signal
/// is safe to coalesce and this is safe to retry.
pub(crate) async fn reload(State(state): State<AppState>) -> Response {
    let min_interval = Duration::from_secs(state.config.control.min_interval_seconds.max(1));
    let admitted = match state.reload_hook.admit(min_interval, Instant::now()) {
        Ok(previous) => previous,
        Err(retry_after) => return rate_limited(retry_after),
    };
    let Some(reload) = state.reload_hook.make_future() else {
        // No action installed: nothing ran, so the window is handed back.
        state.reload_hook.release(admitted);
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "the node is still starting; the reload action is not installed yet",
        )
            .into_response();
    };
    let outcome = reload.await;
    let body = match outcome {
        ReloadOutcome::Applied { restart_required } => ReloadBody {
            applied: true,
            restart_required: Some(restart_required),
            reason: None,
            detail: if restart_required {
                "reloaded [catalogs], the [ingest] writer allow-list, and any added or \
                 credential-changed [[s3.buckets]]. This file also changes a restart-only \
                 setting, which was not applied. Restart the node to pick it up"
            } else {
                "reloaded [catalogs], the [ingest] writer allow-list, and any added or \
                 credential-changed [[s3.buckets]]; nothing in this file needed a restart"
            },
        },
        ReloadOutcome::Rejected(reason) => ReloadBody {
            applied: false,
            restart_required: None,
            reason: Some(reason.as_str()),
            detail: "the candidate config was refused and the running config kept; the node \
                     logged the underlying error, which is not put on the wire because it \
                     can name filesystem paths",
        },
    };
    (StatusCode::OK, Json(body)).into_response()
}

/// The `POST /reconcile` response body.
#[derive(Debug, Serialize)]
struct ReconcileBody {
    /// Always `true`: the pass was started. Present so a caller parses one shape.
    started: bool,
    /// What to watch for the effect, since the work outlives this response.
    detail: &'static str,
}

/// `POST /reconcile` — run the `SIGUSR1` pass now: reload and enforce the operator
/// suppression store and the node-local overlay overrides, drain queued `dataset reingest`
/// markers, rescan the inbox, and wake every bucket monitor.
///
/// `202 Accepted`, not `200`: the pass is unbounded work, up to a full inbox rescan, so
/// waiting for it would tie the answer to this plane's request timeout rather than to the
/// reconcile. Poll `GET /datasets/{id}/state` for the effect.
///
/// This matters most for a withhold. `dataset hide` and `dataset take-down` write a
/// suppression file, the CLI sends no signal, and nothing applies it until the next periodic
/// reconcile, so without this endpoint an operator who cannot `exec` into the pod has no way
/// to make a take-down take effect promptly.
pub(crate) async fn reconcile(State(state): State<AppState>) -> Response {
    let min_interval = Duration::from_secs(state.config.control.min_interval_seconds.max(1));
    let admitted = match state.reconcile_hook.admit(min_interval, Instant::now()) {
        Ok(previous) => previous,
        Err(retry_after) => return rate_limited(retry_after),
    };
    let Some(pass) = state.reconcile_hook.make_future() else {
        // No action installed: nothing ran, so the window is handed back.
        state.reconcile_hook.release(admitted);
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "the node is still starting; the reconcile action is not installed yet",
        )
            .into_response();
    };
    // Detached, as the doc above says. The action `main` installs wraps the pass in the same
    // panic guard the signal handler uses, so a panicking pass cannot take the process down.
    tokio::spawn(pass);
    (
        StatusCode::ACCEPTED,
        Json(ReconcileBody {
            started: true,
            detail: "reconcile started: suppressions and overlays reloaded, queued reingest \
                     markers drained, inbox rescanned, bucket monitors woken. It runs \
                     asynchronously; poll GET /datasets/{id}/state for the effect",
        }),
    )
        .into_response()
}

/// The `POST /datasets/{id}/reingest` response body.
#[derive(Debug, Serialize)]
struct ReingestBody {
    /// Always `true`: the recorded signature was cleared. Present so a caller parses one
    /// shape.
    cleared: bool,
    /// Always `true`: the reconcile pass that re-presents the package was started.
    started: bool,
    /// What to watch for the effect, since the work outlives this response.
    detail: &'static str,
}

/// The `409` body: what a re-ingest can and cannot do, so the caller does not retry it.
const NOT_RETRIABLE: &str = "nothing to retry: only a bucket-owned dataset in `error` with a \
    recorded source signature is re-ingested by clearing it. A live dataset is already \
    served, an inbox dataset is restored with `dataset reingest <id>` on the host, and a \
    broken package needs a corrected re-upload";

/// `POST /datasets/{id}/reingest` — clear one dataset's recorded source signature and run
/// the reconcile pass now: the HTTP twin of `dataset reingest <id>` for a bucket-owned id.
///
/// A node-side ingest failure (a Vault blip, `internal-error`, a catalog added since) leaves
/// the id `error` with its signature recorded, and the S3 reconcile's same-ETag
/// short-circuit holds it there until a restart or an operator with a shell writes the CLI's
/// marker. The effect is applied in-process instead: the serving path never writes the
/// override store, whose replicas may mount it read-only, and the marker only exists to
/// carry a request from a separate process to this one.
///
/// `202` with `{"cleared": true, "started": true}`: the signature is gone and the shared
/// reconcile pass, the one `/reconcile` and `SIGUSR1` run, has been detached to wake the
/// bucket monitors. `400` for a malformed id. `404` for an id this node has no status entry
/// for. `409` for an entry clearing would not change: inbox-owned, live, or no signature
/// recorded. Those three are decided before admission, so a refusal never consumes the
/// pacing window. `429` with `Retry-After` on `/reconcile`'s clock, since this starts the
/// same pass and must not be a way around that endpoint's pacing. `503` before the pass is
/// installed; nothing is cleared then, because a cleared signature with no pass to act on
/// would sit until the next periodic reconcile.
pub(crate) async fn reingest(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    if !is_safe_dataset_id(&id) {
        return (StatusCode::BAD_REQUEST, "invalid dataset id").into_response();
    }
    // Both refusals are audited, like the state oracle's miss: they answer the existence
    // question for any id, on this unauthenticated plane, before the pacing window.
    match state.reingest_verdict(&id) {
        ReingestVerdict::Unknown => {
            crate::audit::reingest_refused(&state.config.audit, &id, "unknown");
            return (
                StatusCode::NOT_FOUND,
                "no dataset with this id has been seen by this node; there is no recorded \
                 signature to clear",
            )
                .into_response();
        }
        ReingestVerdict::NotRetriable => {
            crate::audit::reingest_refused(&state.config.audit, &id, "not_retriable");
            return (StatusCode::CONFLICT, NOT_RETRIABLE).into_response();
        }
        ReingestVerdict::Retriable => {}
    }
    let min_interval = Duration::from_secs(state.config.control.min_interval_seconds.max(1));
    let admitted = match state.reconcile_hook.admit(min_interval, Instant::now()) {
        Ok(previous) => previous,
        Err(retry_after) => return rate_limited(retry_after),
    };
    let Some(pass) = state.reconcile_hook.make_future() else {
        // No action installed: nothing ran, so the window is handed back.
        state.reconcile_hook.release(admitted);
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "the node is still starting; the reconcile action is not installed yet",
        )
            .into_response();
    };
    // The clear persists the status index (a durable write), so it leaves the executor.
    let clearing_state = state.clone();
    let clearing_id = id.clone();
    let cleared =
        tokio::task::spawn_blocking(move || clearing_state.clear_reingest_signature(&clearing_id))
            .await;
    match cleared {
        Ok(ReingestVerdict::Retriable) => {}
        Ok(_) => {
            // The entry changed between the verdict above and the clear (a self-heal to
            // `visible`, an erasure): nothing was touched, so the window is handed back.
            state.reconcile_hook.release(admitted);
            crate::audit::reingest_refused(&state.config.audit, &id, "not_retriable");
            return (StatusCode::CONFLICT, NOT_RETRIABLE).into_response();
        }
        Err(e) => {
            tracing::warn!(
                dataset = %id,
                error = %e,
                "POST /datasets/{{id}}/reingest: the clear task failed"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not clear the recorded signature; nothing was changed",
            )
                .into_response();
        }
    }
    crate::audit::reingest_requested(&state.config.audit, &id);
    // Detached, as in `reconcile`: the pass is unbounded work and the action `main`
    // installs carries the panic guard.
    tokio::spawn(pass);
    (
        StatusCode::ACCEPTED,
        Json(ReingestBody {
            cleared: true,
            started: true,
            detail: "recorded source signature cleared and the reconcile pass started, so the \
                     unchanged package is presented to ingest again. It runs asynchronously; \
                     poll GET /datasets/{id}/state",
        }),
    )
        .into_response()
}

/// The `POST /log-level` response body.
#[derive(Debug, Serialize)]
struct LogLevelBody {
    /// Whether diagnostic (`debug`) logging is on after this call.
    verbose: bool,
    /// The applied filter directives.
    filter: String,
    /// Seconds until verbosity reverts on its own; absent when turning it off.
    #[serde(skip_serializing_if = "Option::is_none")]
    reverts_in_seconds: Option<u64>,
    /// A human-readable summary of what just happened.
    detail: &'static str,
}

/// `POST /log-level` — flip diagnostic logging, exactly as `SIGUSR2` does, but on a timer.
///
/// Bodyless and a toggle, like the signal: on if it was off, off if it was on. Turning it on
/// also schedules a return to the boot level after `[control].log_level_revert_seconds`, so
/// `debug` cannot be left on in production forever.
///
/// The revert does not bound a log-flood denial of service. The window is re-armable: every
/// trigger bumps the generation, so a caller who can reach this plane calls it again after
/// each revert and holds `debug` on indefinitely. What the revert bounds is verbosity left on
/// by mistake, not an adversary. Bounding an adversary needs a cumulative budget of total
/// verbose seconds per interval, which does not exist; the control today is that
/// `[control].enabled` defaults to `false` and the management listener defaults to loopback.
///
/// The revert never overrides a later decision: `set_verbose` hands back the generation its
/// change produced, and a scheduled revert fires only while `logging::level_generation()` is
/// still that value. The counter lives in `logging`, so every trigger bumps it: turning
/// verbosity off by hand, re-arming the window, or flipping it with `SIGUSR2` all supersede a
/// pending revert.
pub(crate) async fn log_level(State(state): State<AppState>) -> Response {
    let min_interval = Duration::from_secs(state.config.control.min_interval_seconds.max(1));
    if let Err(retry_after) = state.log_level_window.admit(min_interval, Instant::now()) {
        return rate_limited(retry_after);
    }
    let want = !crate::logging::is_verbose();
    // The generation is this change's own, returned rather than re-read, so another trigger
    // landing in between cannot make the revert below think it owns a session it does not.
    let (filter, generation) = match crate::logging::set_verbose(want) {
        Ok(applied) => applied,
        Err(e) => {
            tracing::warn!(error = %e, "POST /log-level: could not change the log level");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not change the log level; it is unchanged",
            )
                .into_response();
        }
    };
    let revert_after = state.config.control.log_level_revert_seconds.max(1);
    if want {
        // The revert closes the diagnostic window, so it is audited too: an auditor needs
        // both edges of a verbose-logging session, and only the opening one is attributable
        // to a trigger.
        let revert_config = std::sync::Arc::clone(&state.config);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(revert_after)).await;
            if crate::logging::level_generation() != generation {
                return; // superseded by a later change, from any trigger
            }
            match crate::logging::set_verbose(false) {
                Ok((filter, _)) => {
                    tracing::info!(
                        filter = %filter,
                        "log-level auto-revert: diagnostic logging window elapsed"
                    );
                    crate::audit::log_level_changed(
                        &revert_config.audit,
                        "auto-revert",
                        false,
                        &filter,
                    );
                }
                Err(e) => tracing::warn!(error = %e, "log-level auto-revert failed"),
            }
        });
    }
    tracing::info!(filter = %filter, verbose = want, "POST /log-level: log level changed");
    crate::audit::log_level_changed(&state.config.audit, "http", want, &filter);
    (
        StatusCode::OK,
        Json(LogLevelBody {
            verbose: want,
            filter,
            reverts_in_seconds: want.then_some(revert_after),
            detail: if want {
                "diagnostic logging on; it reverts to the boot level on its own after the \
                 window unless re-armed, so it cannot be left on by accident"
            } else {
                "diagnostic logging off; the boot-time level is restored"
            },
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::{Duration, Instant, ReloadHook, ReloadOutcome, ReloadRejection};

    /// The window admits once, refuses inside it, and admits again after it.
    ///
    /// Driven by an injected clock rather than by sleeping: a test that slept would either be
    /// slow or flaky, and the thing under test is the arithmetic.
    #[test]
    fn the_rate_limit_admits_refuses_then_admits_again() {
        let hook = ReloadHook::new();
        let t0 = Instant::now();
        let window = Duration::from_secs(10);

        assert!(hook.admit(window, t0).is_ok(), "the first call is admitted");
        assert_eq!(
            hook.admit(window, t0 + Duration::from_secs(4)),
            Err(6),
            "inside the window, refused with the whole seconds remaining"
        );
        assert!(
            hook.admit(window, t0 + Duration::from_secs(10)).is_ok(),
            "the window has elapsed"
        );
    }

    /// A refused request must not restart the window.
    ///
    /// If it did, a caller polling faster than the interval would push the next legitimate
    /// action further away with every attempt, denying itself the endpoint under the very
    /// traffic the limit exists to handle.
    #[test]
    fn a_refused_request_does_not_extend_the_window() {
        let hook = ReloadHook::new();
        let t0 = Instant::now();
        let window = Duration::from_secs(10);

        assert!(hook.admit(window, t0).is_ok());
        for tick in 1..10 {
            assert!(hook.admit(window, t0 + Duration::from_secs(tick)).is_err());
        }
        assert!(
            hook.admit(window, t0 + Duration::from_secs(10)).is_ok(),
            "nine refusals in between must not have moved the deadline"
        );
    }

    /// `Retry-After` never reads `0`: a sub-second remainder rounds up to 1.
    #[test]
    fn retry_after_never_invites_an_immediate_retry() {
        let hook = ReloadHook::new();
        let t0 = Instant::now();
        let window = Duration::from_secs(10);
        assert!(hook.admit(window, t0).is_ok());
        assert_eq!(
            hook.admit(window, t0 + Duration::from_millis(9_500)),
            Err(1),
            "500ms left must round up to 1s, not truncate to 0"
        );
    }

    /// An uninstalled hook reports that rather than pretending the reload happened.
    #[tokio::test]
    async fn an_uninstalled_hook_invokes_nothing() {
        let hook = ReloadHook::new();
        assert!(hook.make_future().is_none());
        hook.install(Box::new(|| {
            Box::pin(async { ReloadOutcome::Rejected(ReloadRejection::Invalid) }) as _
        }));
        let outcome = hook.make_future().expect("installed").await;
        assert_eq!(outcome, ReloadOutcome::Rejected(ReloadRejection::Invalid));
    }
}
