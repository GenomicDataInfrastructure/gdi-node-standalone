//! `POST /reload` on the management plane, behind an opt-in flag.
//!
//! The rate-limit arithmetic is unit-tested next to the limiter in `control_http`. What is
//! asserted here is the wiring a unit test cannot reach: the route is absent when the flag is
//! off, it reports the shared action's outcome rather than inventing one, and a node whose
//! action is not installed says so instead of reporting a reload that never happened.
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use gdi_node_standalone::app::build_management_router;
use gdi_node_standalone::control_http::{ReloadOutcome, ReloadRejection};
use gdi_node_standalone::identities::NodeIdentities;
use gdi_node_standalone::state::AppState;
use gdi_node_standalone_core::cache::StatusIndex;
use gdi_node_standalone_core::config::ServiceConfig;
use tower::ServiceExt as _;

/// POST any control route and return `(status, body)`.
async fn post(state: &AppState, uri: &str) -> (StatusCode, String) {
    let resp = build_management_router(state.clone(), None)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// Every control route appears and disappears together, under one flag. The list is derived
/// from the router source, then bound to [`CONTROL_ROUTES`] in both directions.
///
/// Checked as a set rather than per route: the flag gates a capability ("this plane is an
/// operator API"), and a change that mounted two of three would otherwise pass every
/// single-route test. A restated list here would drift: a route can join the flag while
/// `check-config` goes on printing the old count. The constant is what the posture surfaces
/// print, so the parsed mount and the constant must be the same set.
#[tokio::test]
async fn every_control_route_is_gated_by_the_one_flag() {
    use gdi_node_standalone::app::CONTROL_ROUTES;
    const REINGEST: &str = "/datasets/GDI-EE-UTARTU-20260409143052837/reingest";

    let gated = crate::route_inventory::paths_gated_on("control");
    assert!(
        gated.len() >= 4,
        "parsed only {} control routes from app.rs — the parser broke and this guard would \
         pass by checking nothing",
        gated.len()
    );
    let parsed: std::collections::BTreeSet<&str> = gated.iter().map(String::as_str).collect();
    let declared: std::collections::BTreeSet<&str> = CONTROL_ROUTES.iter().copied().collect();
    assert_eq!(
        parsed, declared,
        "the routes mounted under `[control].enabled` and `app::CONTROL_ROUTES` (what \
         check-config and the boot opt-in notice print) must be the same set"
    );

    let (off, _t1) = state_with(false, 10);
    for path in CONTROL_ROUTES {
        let uri = crate::route_inventory::concretize(path);
        let (status, _) = post(&off, &uri).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{uri} must be absent when off"
        );
    }

    let (on, _t2) = state_with(true, 10);
    for path in CONTROL_ROUTES.iter().filter(|p| !p.contains("{id}")) {
        let (status, _) = post(&on, path).await;
        assert_ne!(
            status,
            StatusCode::NOT_FOUND,
            "{path} must be mounted when on"
        );
    }
    // The per-id route answers 404 for an id this empty index has never seen, so "mounted"
    // is proven the way the api_doc guard proves it: a registered path answers 405 to a
    // method no route allows.
    let resp = build_management_router(on.clone(), None)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(REINGEST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::METHOD_NOT_ALLOWED,
        "the per-id route must be mounted when on"
    );
}

/// `POST /reconcile` answers 202 and starts the shared pass; before `main` installs it, 503.
///
/// 202 rather than 200 is the contract: a full rescan is unbounded work, so the response
/// means started. Asserting the uninstalled case beside it is what makes the 202 meaningful —
/// a handler that always answered 202 would be indistinguishable otherwise.
#[tokio::test]
async fn reconcile_reports_started_and_503_before_the_action_exists() {
    let (state, _tmp) = state_with(true, 10);
    let (status, _) = post(&state, "/reconcile").await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "no action installed yet"
    );

    let (state, _tmp) = state_with(true, 10);
    let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = std::sync::Arc::clone(&ran);
    state.reconcile_hook.install(Box::new(move || {
        let flag = std::sync::Arc::clone(&flag);
        Box::pin(async move {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        }) as _
    }));
    let (status, body) = post(&state, "/reconcile").await;
    assert_eq!(status, StatusCode::ACCEPTED, "body: {body}");
    assert!(body.contains("\"started\":true"), "body: {body}");
    // The pass is detached, so yield until it has run rather than asserting immediately.
    for _ in 0..100 {
        if ran.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        ran.load(std::sync::atomic::Ordering::SeqCst),
        "202 must mean the shared pass was actually started, not just acknowledged"
    );
}

/// `POST /log-level` on a process with no logging subscriber reports the failure instead of
/// claiming the level changed.
///
/// This binary installs no global subscriber, so `set_verbose` genuinely cannot apply a
/// filter here — which makes it the honest test of the failure arm. The value being pinned is
/// that the route does not answer `200 {"verbose": true}` on a node where nothing changed: an
/// operator who believes they raised the level stops looking for why the logs are quiet. The
/// success path is exercised end-to-end against a real node by `scripts/e2e/run-full.sh`,
/// which is the only place a real subscriber exists.
#[tokio::test]
async fn log_level_reports_a_failed_change_instead_of_claiming_success() {
    let (state, _tmp) = state_with(true, 10);
    let (status, body) = post(&state, "/log-level").await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "no subscriber is installed, so the change cannot apply: {body}"
    );
    assert!(
        body.contains("unchanged"),
        "the body must say the level did NOT change: {body}"
    );
}

/// `[control].log_level_revert_seconds = 0` is refused at startup.
///
/// The bounded window is the control that makes `/log-level` safe to expose, so a zero-length
/// one is a contradiction rather than a way to switch the feature off.
#[test]
fn a_zero_length_log_level_window_is_refused_at_startup() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"

[control]
enabled = true
log_level_revert_seconds = 0

[catalogs]
gdi-aggregated = "GoE"

[beacon]
id = "org.test.beacon"
name = "Test Beacon"
"#,
        data_dir.display(),
    );
    let config = ServiceConfig::from_toml_str(&toml).unwrap();
    let err = config
        .preflight()
        .expect_err("log_level_revert_seconds = 0 must not boot");
    assert!(
        err.to_string().contains("log_level_revert_seconds"),
        "the error must name the field: {err}"
    );
}

fn state_with(control_enabled: bool, min_interval_seconds: u64) -> (AppState, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"

[control]
enabled = {control_enabled}
min_interval_seconds = {min_interval_seconds}

[catalogs]
gdi-aggregated = "GoE"

[beacon]
id = "org.test.beacon"
name = "Test Beacon"
"#,
        data_dir.display(),
    );
    let config = ServiceConfig::from_toml_str(&toml).unwrap();
    config.preflight().unwrap();
    let state = AppState::new(config, StatusIndex::new(), NodeIdentities::empty());
    (state, tmp)
}

async fn post_reload(state: &AppState) -> (StatusCode, Option<String>, String) {
    let resp = build_management_router(state.clone(), None)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/reload")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let retry_after = resp
        .headers()
        .get("retry-after")
        .map(|v| v.to_str().unwrap().to_owned());
    let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    (
        status,
        retry_after,
        String::from_utf8_lossy(&body).into_owned(),
    )
}

/// With the flag off the route is absent, like every other opt-in surface on this plane.
///
/// `/version` is the control: without it, a router that failed to build would pass too.
#[tokio::test]
async fn the_route_is_absent_when_the_flag_is_off() {
    let (state, _tmp) = state_with(false, 10);
    state.reload_hook.install(Box::new(|| {
        Box::pin(async {
            ReloadOutcome::Applied {
                restart_required: false,
            }
        }) as _
    }));

    let (status, _, _) = post_reload(&state).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "off means absent — and the installed action must not make it reachable"
    );

    let resp = build_management_router(state, None)
        .oneshot(
            Request::builder()
                .uri("/version")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "the plane is otherwise up");
}

/// The route reports the shared action's verdict, both of them, rather than assuming
/// success.
///
/// Asserting the applied case alone would pass against a handler that always answered
/// `applied: true`, which is the failure mode that matters: an operator who believes a
/// rejected config was applied stops looking.
#[tokio::test]
async fn the_response_reports_what_the_shared_action_actually_did() {
    let (applied_state, _t1) = state_with(true, 10);
    applied_state.reload_hook.install(Box::new(|| {
        Box::pin(async {
            ReloadOutcome::Applied {
                restart_required: false,
            }
        }) as _
    }));
    let (status, _, body) = post_reload(&applied_state).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("\"applied\":true"), "applied body: {body}");
    assert!(
        !body.contains("\"reason\""),
        "no refusal reason on success: {body}"
    );

    let (rejected_state, _t2) = state_with(true, 10);
    rejected_state.reload_hook.install(Box::new(|| {
        Box::pin(async { ReloadOutcome::Rejected(ReloadRejection::Unparsable) }) as _
    }));
    let (status, _, body) = post_reload(&rejected_state).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a refused config is an ANSWER, not a transport failure — the node is healthy"
    );
    assert!(body.contains("\"applied\":false"), "rejected body: {body}");
    assert!(
        body.contains("\"reason\":\"unparsable\""),
        "the closed-set reason reaches the caller: {body}"
    );
}

/// The response says whether the file also carried a restart-only change.
///
/// An operator editing a `ConfigMap` wants to know whether the change took effect, and
/// `applied: true` alone answers that wrongly for the commonest edit. Every opt-in flag
/// decides route mounting at boot, and every `endpoint`, `bucket` or `prefix` edit re-points a
/// keyspace, so all of them are restart-only: turning one on and posting to `/reload` would
/// otherwise report `applied: true` and change nothing observable.
#[tokio::test]
async fn the_response_says_when_a_restart_is_still_required() {
    let (plain, _t1) = state_with(true, 10);
    plain.reload_hook.install(Box::new(|| {
        Box::pin(async {
            ReloadOutcome::Applied {
                restart_required: false,
            }
        }) as _
    }));
    let (status, _, body) = post_reload(&plain).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("\"restart_required\":false"),
        "an ordinary reload reports that nothing needs a restart: {body}"
    );

    let (pending, _t2) = state_with(true, 10);
    pending.reload_hook.install(Box::new(|| {
        Box::pin(async {
            ReloadOutcome::Applied {
                restart_required: true,
            }
        }) as _
    }));
    let (status, _, body) = post_reload(&pending).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a partially-applied reload is still a successful answer"
    );
    assert!(
        body.contains("\"applied\":true") && body.contains("\"restart_required\":true"),
        "the caller must be told the file carried a change that was NOT applied: {body}"
    );
    assert!(
        body.contains("Restart the node"),
        "and the detail must say what to do about it: {body}"
    );
}

/// Before `main` installs the action the route says the node is starting, rather than
/// reporting a reload that did not happen.
#[tokio::test]
async fn an_uninstalled_action_is_503_not_a_silent_success() {
    let (state, _tmp) = state_with(true, 10);
    let (status, _, _) = post_reload(&state).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

/// The second call inside the window is refused with a `Retry-After`, and the action does
/// not run again.
#[tokio::test]
async fn a_second_call_inside_the_window_is_refused_and_does_not_run_the_action() {
    let (state, _tmp) = state_with(true, 3600);
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = std::sync::Arc::clone(&calls);
    state.reload_hook.install(Box::new(move || {
        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async {
            ReloadOutcome::Applied {
                restart_required: false,
            }
        }) as _
    }));

    let (first, _, _) = post_reload(&state).await;
    assert_eq!(first, StatusCode::OK);

    let (second, retry_after, _) = post_reload(&state).await;
    assert_eq!(second, StatusCode::TOO_MANY_REQUESTS);
    let retry_after = retry_after.expect("a 429 must say when to retry");
    assert!(
        retry_after.parse::<u64>().is_ok_and(|s| s > 0),
        "Retry-After must be a positive whole number of seconds, got {retry_after:?}"
    );
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the refused request must not have run the reload — otherwise the limit paces only \
         the RESPONSE, not the work"
    );
}

/// `[control].min_interval_seconds = 0` is refused at startup rather than silently clamped.
///
/// An operator who wrote `0` meant "no limit"; clamping would leave them believing they had
/// it while the node paced anyway.
#[test]
fn an_unpaced_control_endpoint_is_refused_at_startup() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let toml = format!(
        r#"
[service]
base_url = "https://test.example.org"
data_dir = "{}"

[control]
enabled = true
min_interval_seconds = 0

[catalogs]
gdi-aggregated = "GoE"

[beacon]
id = "org.test.beacon"
name = "Test Beacon"
"#,
        data_dir.display(),
    );
    let config = ServiceConfig::from_toml_str(&toml).unwrap();
    let err = config
        .preflight()
        .expect_err("min_interval_seconds = 0 must not boot");
    let msg = err.to_string();
    assert!(
        msg.contains("min_interval_seconds"),
        "the error must name the field: {msg}"
    );
    assert!(
        msg.contains("[control].enabled = false"),
        "and point at the switch that actually turns the endpoints off: {msg}"
    );
}
