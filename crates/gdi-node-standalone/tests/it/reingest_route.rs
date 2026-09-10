//! `POST /datasets/{id}/reingest` on the management plane: the per-id twin of
//! `dataset reingest <id>` for a bucket-owned id, behind the same `[control].enabled` flag and
//! the same pacing clock as `POST /reconcile`.
//!
//! What is asserted here is the wiring a unit test cannot reach: the signature is cleared in
//! the status index and nothing is written to the override store, the shared reconcile pass is
//! started rather than a private one, the pacing window is the reconcile's, and every refusal
//! arm leaves both the index and the window untouched.
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use gdi_node_standalone::app::build_management_router;
use gdi_node_standalone::identities::NodeIdentities;
use gdi_node_standalone::state::AppState;
use gdi_node_standalone_core::cache::{DatasetProvenance, StatusEntry, StatusIndex};
use gdi_node_standalone_core::config::ServiceConfig;
use gdi_node_standalone_core::reingest_request::requests_subdir;
use gdi_node_standalone_core::state::DatasetState;
use tower::ServiceExt as _;

/// A bucket-owned id in `error` with a recorded signature — the retriable shape.
const KNOWN: &str = "GDI-EE-UTARTU-20260409143052837";
/// A bucket-owned id that is being served — nothing to retry.
const LIVE: &str = "GDI-EE-UTARTU-20260409143052838";
/// A well-formed id the node has never seen.
const UNKNOWN: &str = "GDI-EE-UTARTU-20260409143052999";

fn entry(state: DatasetState) -> StatusEntry {
    StatusEntry {
        state,
        error_message: None,
        channel: "pins".to_owned(),
        last_seen_signature: Some("\"etag-1\"".to_owned()),
        provenance: DatasetProvenance::Plaintext,
    }
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
    let mut status = StatusIndex::new();
    status.insert(KNOWN.to_owned(), entry(DatasetState::Error));
    status.insert(LIVE.to_owned(), entry(DatasetState::Visible));
    let state = AppState::new(config, status, NodeIdentities::empty());
    (state, tmp)
}

/// Install a reconcile action that only counts how often it ran.
fn install_counting_pass(state: &AppState) -> Arc<AtomicUsize> {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    state.reconcile_hook.install(Box::new(move || {
        let counter = Arc::clone(&counter);
        Box::pin(async move {
            counter.fetch_add(1, Ordering::SeqCst);
        }) as _
    }));
    calls
}

/// POST `uri` and return `(status, retry-after, body)`.
async fn post(state: &AppState, uri: &str) -> (StatusCode, Option<String>, String) {
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

fn signature_of(state: &AppState, id: &str) -> Option<String> {
    state
        .status
        .lock()
        .unwrap()
        .get(id)
        .and_then(|e| e.last_seen_signature.clone())
}

fn marker_dir_exists(state: &AppState) -> bool {
    requests_subdir(&state.config.service.override_dir_resolved()).exists()
}

/// The pass is detached, so yield until it has run rather than asserting immediately.
async fn wait_for_calls(calls: &AtomicUsize, want: usize) {
    for _ in 0..100 {
        if calls.load(Ordering::SeqCst) >= want {
            return;
        }
        tokio::task::yield_now().await;
    }
}

/// A retriable id: the signature is gone, the shared pass ran, and nothing was written to
/// the override store — the effect is applied in-process, not by the CLI's marker.
#[tokio::test]
async fn a_known_errored_id_is_cleared_and_the_shared_pass_starts() {
    let (state, _tmp) = state_with(true, 10);
    let calls = install_counting_pass(&state);
    assert!(
        signature_of(&state, KNOWN).is_some(),
        "fixture: a signature is recorded"
    );

    let (status, _, body) = post(&state, &format!("/datasets/{KNOWN}/reingest")).await;

    assert_eq!(status, StatusCode::ACCEPTED, "body: {body}");
    assert!(body.contains("\"cleared\":true"), "body: {body}");
    assert!(body.contains("\"started\":true"), "body: {body}");
    assert!(
        signature_of(&state, KNOWN).is_none(),
        "the recorded signature must be cleared so the same-ETag short-circuit no longer pins \
         the id"
    );
    assert!(
        !marker_dir_exists(&state),
        "the serving path must not write the override store — the effect is in-process"
    );
    wait_for_calls(&calls, 1).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "202 must mean the shared reconcile pass was started, not a private drain"
    );
}

/// The three refusals are decided before admission: nothing is cleared, nothing is written,
/// and the pacing window is still open for the next real action.
#[tokio::test]
async fn a_malformed_unknown_or_live_id_is_refused_without_consuming_the_window() {
    let (state, _tmp) = state_with(true, 3600);
    let calls = install_counting_pass(&state);

    let (status, _, _) = post(&state, "/datasets/not-an-id/reingest").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _, _) = post(&state, &format!("/datasets/{UNKNOWN}/reingest")).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an id the node has no status entry for has no signature to clear"
    );
    let (status, _, body) = post(&state, &format!("/datasets/{LIVE}/reingest")).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a live id is already served: {body}"
    );
    assert!(body.contains("nothing to retry"), "body: {body}");
    assert!(
        signature_of(&state, LIVE).is_some(),
        "a refusal must leave the live entry untouched"
    );
    assert!(!marker_dir_exists(&state));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "no refusal may start the pass"
    );

    // None of the refusals consumed the pacing window: the next real action is admitted.
    let (status, _, _) = post(&state, "/reconcile").await;
    assert_eq!(status, StatusCode::ACCEPTED);
}

/// Before `main` installs the reconcile action the route says the node is starting and
/// clears nothing — a cleared signature with no pass to act on it would be a silent
/// half-action the caller was told succeeded.
#[tokio::test]
async fn it_is_503_before_the_pass_is_installed_and_clears_nothing() {
    let (state, _tmp) = state_with(true, 10);
    let (status, _, _) = post(&state, &format!("/datasets/{KNOWN}/reingest")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        signature_of(&state, KNOWN).is_some(),
        "nothing may be cleared on a 503"
    );
    assert!(!marker_dir_exists(&state));
}

/// The route is paced on `/reconcile`'s clock: a re-ingest starts the same pass, so it must
/// not be a way around that endpoint's `min_interval_seconds`.
#[tokio::test]
async fn it_shares_the_reconcile_window() {
    let (state, _tmp) = state_with(true, 3600);
    let calls = install_counting_pass(&state);

    let (status, _, _) = post(&state, &format!("/datasets/{KNOWN}/reingest")).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let (status, retry_after, _) = post(&state, "/reconcile").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    let retry_after = retry_after.expect("a 429 must say when to retry");
    assert!(
        retry_after.parse::<u64>().is_ok_and(|s| s > 0),
        "Retry-After must be a positive whole number of seconds, got {retry_after:?}"
    );

    wait_for_calls(&calls, 1).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the refused /reconcile must not have run the pass a second time"
    );
}

/// With the flag off the route is absent, like its three siblings; `/version` is the control.
#[tokio::test]
async fn it_is_absent_when_the_flag_is_off() {
    let (state, _tmp) = state_with(false, 10);
    install_counting_pass(&state);
    let (status, _, _) = post(&state, &format!("/datasets/{KNOWN}/reingest")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(signature_of(&state, KNOWN).is_some());

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

/// A refused re-ingest is audited on both arms, with the closed-set reason. The route answers
/// the existence question for any id on the unauthenticated plane, ahead of the pacing window,
/// as the state oracle does, and its miss is recorded for the same reason.
///
/// A plain `#[test]` over a current-thread runtime: `tracing::subscriber::with_default` is
/// thread-local, so the requests must run on the thread the capture is installed on.
#[test]
#[serial_test::serial(env)]
fn a_refused_reingest_is_audited_with_its_reason() {
    use tracing_subscriber::layer::SubscriberExt as _;

    crate::fixtures::ensure_capture_safe_tracing();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let (state, _tmp) = state_with(true, 10);
    let writer = test_util::CaptureWriter::new();
    let make = {
        let w = writer.clone();
        move || w.clone()
    };
    let subscriber = tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().json().with_writer(make));

    tracing::subscriber::with_default(subscriber, || {
        rt.block_on(async {
            for (id, expected) in [
                (UNKNOWN, StatusCode::NOT_FOUND),
                (LIVE, StatusCode::CONFLICT),
            ] {
                let resp = build_management_router(state.clone(), None)
                    .oneshot(
                        Request::builder()
                            .method("POST")
                            .uri(format!("/datasets/{id}/reingest"))
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(resp.status(), expected, "{id}");
            }
        });
    });

    let out = writer.contents();
    let refusals: Vec<serde_json::Value> = out
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["fields"]["event"] == "reingest_refused")
        .collect();
    assert_eq!(
        refusals.len(),
        2,
        "both refusal arms must leave an audit record; got {out}"
    );
    assert_eq!(refusals[0]["fields"]["dataset"], UNKNOWN, "{out}");
    assert_eq!(refusals[0]["fields"]["reason"], "unknown", "{out}");
    assert_eq!(refusals[1]["fields"]["dataset"], LIVE, "{out}");
    assert_eq!(refusals[1]["fields"]["reason"], "not_retriable", "{out}");
    assert!(
        !out.contains("reingest_requested"),
        "a refusal is not a request: {out}"
    );
}
