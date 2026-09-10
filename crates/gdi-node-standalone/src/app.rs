//! HTTP application wiring: build the axum [`Router`] and its resilience layers.
//!
//! The Beacon entry types are mounted under two configurable prefixes:
//! `[beacon].aggregated_base_path` (genomicVariant + dataset) and
//! `[beacon].sensitive_base_path` (the individual placeholder). When the two are equal the
//! node mounts once, as a combined beacon serving all three entry types; when distinct (the
//! default) it mounts an aggregated and a sensitive beacon, each with the full informational
//! set scoped to its entry types. The route table is built from a small entry-type helper, so
//! adding an entry type does not restructure the wiring.
//!
//! Layers applied, outermost first:
//! * [`tower_http::catch_panic::CatchPanicLayer`] → `500`;
//! * [`DefaultBodyLimit`] from `[service].max_request_body_bytes` → `413`;
//! * [`tower_http::timeout::TimeoutLayer`] from `[service].request_timeout_seconds`;
//! * [`tower::load_shed::LoadShedLayer`] + [`tower::limit::GlobalConcurrencyLimitLayer`]
//!   from `[service].max_concurrent_requests` → `503` on shed (one global limit, not
//!   per-route: see the `shared_concurrency_layer` helper).
//!
//! Every error those layers synthesize, and the `414` request-target cap, is rendered by one
//! layer, `render_synthesized_errors`, in the dialect of the surface the request was for: the
//! `beaconErrorResponse` envelope under a beacon prefix, bare text under the FDP mount,
//! neutral JSON elsewhere, matching the unmatched-path `404`.

use std::any::Any;
use std::time::Duration;

use axum::body::Body;
use axum::error_handling::HandleErrorLayer;
use axum::extract::{DefaultBodyLimit, MatchedPath, Request, State};
use axum::http::header::{
    ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_EXPOSE_HEADERS, CONTENT_LENGTH, CONTENT_TYPE,
    HeaderName, ORIGIN, VARY,
};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, get, post};
use axum::{BoxError, Router};
use tower::ServiceBuilder;
use tower::limit::GlobalConcurrencyLimitLayer;
use tower::load_shed::LoadShedLayer;
use tower::load_shed::error::Overloaded;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::request_id::{
    MakeRequestUuid, PropagateRequestIdLayer, RequestId, SetRequestIdLayer,
};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::beacon_http;
use crate::beacon_info::{self, MountScope};
use crate::catalogs_http;
use crate::control_http;
use crate::datasets_http;
use crate::fairdp_http;
use crate::health;
use crate::metrics;
use crate::state::AppState;
use crate::stats_http;

/// The request-id header carried in logs + echoed in the response. Lowercase per
/// the HTTP/2 header convention `tower_http` uses.
const REQUEST_ID_HEADER: &str = "x-request-id";

/// Longest caller-supplied `x-request-id` the management plane adopts.
///
/// Above every id an orchestrator mints (a UUID is 36 characters, a W3C trace-id 32, a
/// Kubernetes pod name at most 63) and far below the size at which copying the value into a
/// response header and every log line of the request becomes an amplification lever. Anything
/// longer is dropped for a server-minted UUID.
const MAX_INBOUND_REQUEST_ID_LEN: usize = 128;

/// Maximum request-target (path + query) length, in bytes, on the public plane.
///
/// The GET-side mirror of `[service].max_request_body_bytes`: a body cap does not bound a
/// long URI, so an over-long GET target is rejected with `414`, rendered in the surface's
/// dialect (see `ErrorDialect`). A constant rather than a config knob: 8 KiB is well above
/// any legitimate Beacon GET query and at or below common proxy URI limits, such as nginx's
/// default `large_client_header_buffers`.
const MAX_REQUEST_TARGET_BYTES: usize = 8 * 1024;

/// Upper bound on a JSON error body [`add_request_id_to_error_body`] will buffer to
/// inject `requestId`. The node's error envelopes are well under 1 KiB; a larger or
/// unknown-length body is passed through untouched rather than buffered.
const MAX_ERROR_BODY_REWRITE_BYTES: usize = 64 * 1024;

// The public plane's CORS origin policy.
//
// `Access-Control-Allow-Origin` leaves this node from three places, because two of them
// synthesize their response outside the routed mounts' `CorsLayer`:
//
//   1. the routed data planes' `CorsLayer` (`build_router`),
//   2. the unmatched-path fallback 404 (`public_not_found`),
//   3. the resilience-error responses, 408/413/414/500/503, in whichever dialect
//      `render_synthesized_errors` chose (`set_security_headers`).
//
// The policy is stated once, here: every site routes through `public_cors_origin_allowed`,
// including the `CorsLayer`, via `AllowOrigin::predicate` so `tower-http` does not run a
// second matcher. Change the rule here and all three change together.

/// Is the public plane wildcard-open? Empty (the default) or an explicit `"*"`.
///
/// `pub` rather than `pub(crate)` because the binary is a separate crate and its
/// `check-config` posture summary asks the same question; re-deriving it there would be a
/// second copy of the rule the router enforces.
#[must_use]
pub fn public_cors_is_wildcard(configured: &[String]) -> bool {
    configured.is_empty() || configured.iter().any(|o| o == "*")
}

/// The one origin matcher: may `origin` read the public plane under `configured`?
///
/// Exact byte equality against `[service].cors_allowed_origins`, the comparison a browser's
/// `Origin` header demands, which is why preflight forces each configured entry into
/// canonical origin form.
fn public_cors_origin_allowed(configured: &[String], origin: &HeaderValue) -> bool {
    public_cors_is_wildcard(configured)
        || origin
            .to_str()
            .is_ok_and(|o| configured.iter().any(|c| c == o))
}

/// The `Access-Control-Allow-Origin` value to send to a request carrying `origin`, or
/// `None` when that origin may not read the response (so no header is sent at all).
fn public_cors_acao(configured: &[String], origin: Option<&HeaderValue>) -> Option<HeaderValue> {
    if public_cors_is_wildcard(configured) {
        return Some(HeaderValue::from_static("*"));
    }
    let origin = origin?;
    if public_cors_origin_allowed(configured, origin) {
        Some(origin.clone())
    } else {
        None
    }
}

/// Stamp the public CORS headers onto a response synthesized outside the `CorsLayer` (sites
/// 2 and 3 above), so those envelopes carry the policy the routed planes do.
fn stamp_public_cors(configured: &[String], resp: &mut Response, origin: Option<&HeaderValue>) {
    let Some(acao) = public_cors_acao(configured, origin) else {
        return;
    };
    let restricted = !public_cors_is_wildcard(configured);
    let headers = resp.headers_mut();
    headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, acao);
    headers.insert(
        ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static(REQUEST_ID_HEADER),
    );
    // A restricted policy echoes the request origin, so the response varies by it: without
    // `Vary` a shared cache could hand one origin's `Allow-Origin` to another. The wildcard
    // is origin-independent and needs none.
    if restricted {
        headers.insert(VARY, HeaderValue::from_static("origin"));
    }
}

/// The [`AllowOrigin`] the routed mounts' `CorsLayer` enforces, driven by the same matcher as
/// the hand-stamped sites.
///
/// Wildcard keeps the literal `*`, which is origin-independent and cacheable; a restricted
/// list is enforced through [`public_cors_origin_allowed`], so `tower-http` echoes only an
/// allowed origin. Entries are validated at config preflight
/// ([`ServiceConfig::preflight`](gdi_node_standalone_core::config::ServiceConfig::preflight)).
fn cors_allow_origin(configured: &[String]) -> AllowOrigin {
    if public_cors_is_wildcard(configured) {
        return AllowOrigin::any();
    }
    let allowed: Vec<String> = configured.to_vec();
    AllowOrigin::predicate(move |origin, _parts| public_cors_origin_allowed(&allowed, origin))
}

/// Build the service's axum [`Router`] from the shared [`AppState`].
///
/// Mounts the Beacon entry types and the full informational endpoint set under the aggregated
/// and sensitive prefixes, as one combined mount when they are equal (see the module docs and
/// `beacon_router`), then wraps the whole router in the resilience layers. The returned router
/// is served by the bounded hyper accept loop `main::serve_bounded`, which bounds the
/// connection phase both planes share, never by `axum::serve`; tests drive it in-process with
/// `tower::ServiceExt::oneshot`.
pub fn build_router(state: AppState) -> Router {
    let cfg = &state.config;
    // The mount prefixes come from the same helper the synthesized-error renderer classifies
    // request paths with (`apply_resilience_layers`), so the two cannot disagree about where
    // a mount begins.
    let PublicMounts {
        aggregated: agg_prefix,
        sensitive: sens_prefix,
    } = public_mounts(cfg);

    // The config Arc the beacon mounts + the resilience layer stack share.
    let beacon_cfg = std::sync::Arc::clone(&state.config);

    // The public CORS layer, applied only to the browser-consumed public endpoints: the
    // aggregated beacon mount and the FDP. Not to the well-known crypt4gh recipient, which
    // the provider tool fetches rather than a browser, nor to the management plane or the
    // sensitive mount.
    //
    // The beacon entry types are queried by POST with `content-type: application/json`, which
    // is not a CORS "simple" request, so a cross-origin browser client sends an OPTIONS
    // preflight first. The layer must therefore allow the POST method and the `content-type`
    // request header, or browser POST queries are blocked despite the origin header;
    // `CorsLayer` answers the preflight itself once methods are set. GET and the FDP's
    // Accept-based content negotiation are simple requests and need no preflight. No
    // credentials are allowed on this unauthenticated tier, so a `*` origin is safe.
    // `[service].cors_allowed_origins` chooses the origins, empty meaning the wildcard this
    // public beacon defaults to; the method and header policy is independent of that choice.
    let public_cors = CorsLayer::new()
        .allow_origin(cors_allow_origin(&cfg.service.cors_allowed_origins))
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([CONTENT_TYPE])
        // Expose the correlation id to cross-origin browser clients. Without it the
        // `Access-Control-Expose-Headers` list omits `x-request-id`, a browser reading that
        // header cross-origin gets null, and the documented correlation contract is inert
        // for the clients the wildcard CORS exists to serve.
        .expose_headers([HeaderName::from_static(REQUEST_ID_HEADER)]);

    // Equal prefixes mount one combined beacon serving all three entry types with a combined
    // informational set; mounting both scopes there would double-register conflicting routes.
    // Distinct prefixes mount an aggregated and a sensitive beacon, each scoped to its entry
    // types.
    //
    // The wildcard CORS goes on the aggregated or combined beacon mount and the FDP only.
    // With distinct prefixes the sensitive mount is nested without the CORS layer, because
    // the stage-2 sensitive-beacon gate governs its CORS; with equal prefixes the combined
    // mount carries it, and the placeholder sensitive entry type emits only zeros.
    let mut app = Router::new();
    if agg_prefix == sens_prefix {
        app = app.nest(
            &agg_prefix,
            beacon_router(MountScope::Combined, std::sync::Arc::clone(&beacon_cfg))
                .layer(public_cors.clone()),
        );
    } else {
        app = app
            .nest(
                &agg_prefix,
                beacon_router(MountScope::Aggregated, std::sync::Arc::clone(&beacon_cfg))
                    .layer(public_cors.clone()),
            )
            .nest(
                &sens_prefix,
                beacon_router(MountScope::Sensitive, std::sync::Arc::clone(&beacon_cfg)),
            );
    }

    let app = app
        // The service directory at the origin root: the one place a human, or a client
        // handed only the host, can land and learn where the beacon and the FDP are.
        // Browser-readable discovery, so it carries the public CORS.
        .route(ROOT_PATH, get(root_index).layer(public_cors.clone()))
        // The FAIR Data Point surface, nested at an absolute prefix rather than under the
        // beacon prefix. Each handler returns 404 when `[fairdp]` is unconfigured, so the
        // routes are always present but inert on a beacon-only node. The nest carries its own
        // fallback (see `fairdp_router`), so an unknown FDP path answers in the FDP's
        // bare-text dialect rather than the Beacon envelope. The FDP is a public browser
        // endpoint and carries the wildcard CORS; both layers are applied before nesting, so
        // they cover that fallback too.
        .nest(
            FAIRDP_PREFIX,
            fairdp_router()
                .layer(public_cors.clone())
                // Instrument the FDP serving plane, mirroring the beacon mounts' own
                // per-entry-type metric. Outermost on this sub-router, so it observes the
                // final status after CORS.
                .layer(axum::middleware::from_fn(meter_fairdp)),
        )
        // The FDP root's trailing-slash form, the one exception to "a trailing slash is not
        // a route" (`docs/api.md`). It must live on the outer router: `Router::nest` routes
        // `{prefix}/` to neither the nested root nor the nested fallback, so a route inside
        // `fairdp_router` could not answer it. The path is derived from `FAIRDP_PREFIX`
        // rather than spelled again, so the mount and its slash form cannot drift. It carries
        // the same public CORS as the mount, since a browser client cannot follow a redirect
        // that drops it.
        .route(
            &format!("{FAIRDP_PREFIX}/"),
            get(fairdp_root_redirect).layer(public_cors),
        )
        // The node's crypt4gh recipient, mounted at the root rather than under the beacon
        // prefix, and 404 when keyless. The provider tool fetches it, not a browser, so it
        // carries no CORS header.
        .route(WELL_KNOWN_C4GH_PATH, get(beacon_info::c4gh_recipient))
        // Fallback for a path outside every mount, such as a mistyped prefix: a neutral JSON
        // 404 naming the public services, never the Beacon envelope. A miss under a mount
        // does not normally get here, because each beacon mount and the FDP nest carry their
        // own fallback in their own dialect; the exception is a beacon nest root with a
        // trailing slash, which `nest` hands to the outer router, so the handler classifies
        // the path and answers in that mount's dialect (see `public_not_found`). Stamped with
        // the public CORS the routed planes carry, so a cross-origin browser client can read
        // the request id. Not via `RESILIENCE_ERRORS`, which would also stamp CORS onto the
        // keyless well-known 404 that carries none.
        .fallback(public_not_found)
        // The management plane (health, dataset-state oracle, metrics) is not mounted here.
        // It is served on the separate `[service].management_addr` listener by
        // `build_management_router`, so misconfiguring the public Ingress cannot expose the
        // hidden-dataset oracle or metrics.
        .with_state(state);

    apply_resilience_layers(app, beacon_cfg)
}

/// The FAIR Data Point mount prefix: the nest path of [`fairdp_router`] and the `fairdp`
/// entry of [`service_directory`], stated once.
const FAIRDP_PREFIX: &str = "/fairdp";

/// The origin root, served by `root_index`.
const ROOT_PATH: &str = "/";

/// The node's crypt4gh recipient endpoint, mounted at the origin root (not under a
/// beacon prefix) because the provider tool fetches it by a well-known path.
const WELL_KNOWN_C4GH_PATH: &str = "/.well-known/c4gh-recipient";

/// The public-plane paths [`build_router`] registers at the origin root, and which a
/// beacon mount prefix therefore cannot take.
///
/// [`ROOT_PATH`] is absent: `normalize_prefix` maps a bare `/` to `/beacon` and
/// `preflight_base_path` rejects `/` outright, so no config reaches the router with the root
/// as its mount. Every entry is a path axum really conflicts on, which
/// `tests::every_reserved_public_path_really_conflicts` asserts by building the router at
/// each one.
const RESERVED_PUBLIC_PATHS: &[&str] = &[FAIRDP_PREFIX, WELL_KNOWN_C4GH_PATH];

/// The reserved public path a beacon mount at `prefix` would collide with, if any.
///
/// `prefix` is the raw configured value, normalized here as [`build_router`] normalizes it,
/// so the answer is about the mount that would be nested rather than about the spelling.
///
/// A collision is either spelling of the same mount point: equality, or one path being a
/// path-segment ancestor of the other. Equality makes `Router::nest` panic outright
/// ("Overlapping method route"); an ancestor relation is the quieter half, where the outer
/// mount swallows the inner path and the reserved endpoint stops answering. Both are
/// refusals, because a node that cannot serve its own well-known recipient is as broken as
/// one that will not start.
pub(crate) fn conflicting_reserved_path(prefix: &str) -> Option<&'static str> {
    let mount = normalize_prefix(prefix);
    RESERVED_PUBLIC_PATHS.iter().copied().find(|reserved| {
        mount == *reserved
            || reserved
                .strip_prefix(&mount)
                .is_some_and(|r| r.starts_with('/'))
            || mount
                .strip_prefix(*reserved)
                .is_some_and(|r| r.starts_with('/'))
    })
}

/// The public services this node serves, as `{name: path}`: the body of `GET /` and the
/// `services` of the neutral top-level `404`, built in one place so the two cannot disagree.
/// Names the aggregated beacon prefix and, when `[fairdp]` is configured, the FDP. Never the
/// sensitive prefix, since the listing exists for a mistyped public path and the sensitive
/// mount is not a browser-discoverable surface.
fn service_directory(cfg: &gdi_node_standalone_core::config::ServiceConfig) -> serde_json::Value {
    let mut services = serde_json::Map::new();
    services.insert(
        "beacon".to_owned(),
        serde_json::Value::from(public_mounts(cfg).aggregated),
    );
    if cfg.fairdp.is_some() {
        services.insert("fairdp".to_owned(), serde_json::Value::from(FAIRDP_PREFIX));
    }
    serde_json::Value::Object(services)
}

/// `GET /` — the service directory (see [`service_directory`]).
async fn root_index(State(state): State<AppState>) -> Response {
    axum::Json(serde_json::json!({ "services": service_directory(&state.config) })).into_response()
}

/// Fallback handler for a public path no route matched.
///
/// Outside every mount it renders a neutral JSON `404` carrying `status`, `message` and the
/// [`service_directory`] as `services`. The body stays JSON so
/// [`add_request_id_to_error_body`] can inject `requestId`, and it is stamped with the same
/// public CORS policy the routed planes carry ([`stamp_public_cors`], site 2), so a
/// cross-origin browser client that mistypes a prefix still gets a correlatable, readable
/// error. Under a restricted `[service].cors_allowed_origins` a disallowed origin gets no
/// `Allow-Origin` here either.
///
/// A miss under a beacon prefix or the FDP mount normally goes to that mount's own fallback,
/// in its own dialect. The exception is a beacon nest root with a trailing slash, which
/// `Router::nest` routes to neither the nested router's root nor its catch-all: this handler
/// classifies the path with the same [`error_dialect`] the synthesized errors use, so a
/// federated client that appends a slash gets the envelope it parses. The sensitive mount
/// carries no public CORS, since the stage-2 gate governs it, and that is mirrored here. The
/// FDP's own trailing-slash form is a real route ([`fairdp_root_redirect`]) and never
/// arrives.
async fn public_not_found(
    State(state): State<AppState>,
    uri: axum::http::Uri,
    headers: HeaderMap,
) -> Response {
    let mounts = public_mounts(&state.config);
    let dialect = error_dialect(&mounts, uri.path());
    let mut resp = match dialect {
        // The entry type is dropped here: this arm is the unmatched-path 404, and naming
        // an entity the node never interpreted the request as is the claim
        // `route_miss_response` exists to stop making. The resilience-envelope arm below
        // keeps its entry type, because those requests did match a mount.
        ErrorDialect::Beacon(_) => beacon_http::route_miss_response(
            &state.config.beacon,
            "no Beacon endpoint matches this path",
        ),
        ErrorDialect::Fdp => fairdp_http::not_found_fallback().await,
        ErrorDialect::Neutral => (
            StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({
                "status": 404,
                "message": "no route matches this path",
                "services": service_directory(&state.config),
            })),
        )
            .into_response(),
    };
    let sensitive_only = mounts.aggregated != mounts.sensitive
        && dialect == ErrorDialect::Beacon(MountScope::Sensitive.primary_entry_type());
    if !sensitive_only {
        stamp_public_cors(
            &state.config.service.cors_allowed_origins,
            &mut resp,
            headers.get(ORIGIN),
        );
    }
    resp
}

/// Apply the resilience layer stack to `router`: request-id correlation, trace span,
/// catch-panic → 500, body-limit → 413, timeout → 408, load-shed plus concurrency limit →
/// 503. The body, timeout and concurrency knobs come from `cfg.service`; the 500 and 503
/// envelopes are rendered from `cfg.beacon`.
///
/// Extracted from [`build_router`] and exposed so tests can wrap the real stack around a
/// router carrying panicking or blocking routes; the production router has none.
pub fn apply_resilience_layers(
    router: Router,
    cfg: std::sync::Arc<gdi_node_standalone_core::config::ServiceConfig>,
) -> Router {
    let body_limit = cfg.service.max_request_body_bytes;
    let request_timeout = Duration::from_secs(cfg.service.request_timeout_seconds);
    let max_concurrent = cfg.service.max_concurrent_requests;
    // Publish the concurrency limit as the constant capacity line for the
    // `gdi_http_inflight` saturation gauge (a no-op when metrics are disabled).
    metrics::record_http_max_concurrent(max_concurrent);
    // Every rejecting layer below synthesizes a bare, marked status (see
    // `SynthesizedError`); the single `render_synthesized_errors` layer above them renders it
    // in the dialect of the surface the request was for (see `ErrorDialect`).
    let mounts = std::sync::Arc::new(public_mounts(&cfg));
    let request_id_header = HeaderName::from_static(REQUEST_ID_HEADER);
    // Whether to adopt an inbound W3C `traceparent` as the request span's parent. Default
    // off, honoured only behind a trusted ingress and only in an `otel` build (see
    // `adopt_inbound_trace_context`).
    #[cfg(feature = "otel")]
    let trust_traceparent = cfg.service.trust_inbound_traceparent;
    router.layer(
        ServiceBuilder::new()
            // Outermost: the baseline security headers on every public response.
            // `X-Content-Type-Options: nosniff` stops content-type sniffing of the JSON, RDF
            // and PEM bodies; `Cache-Control: no-store` keeps a withheld or taken-down
            // dataset from being served out of an intermediary cache after the node itself
            // stopped serving it (see `set_security_headers`). X-Frame-Options and CSP add
            // nothing, because the node serves no HTML, and HSTS belongs at the TLS edge, so
            // both are omitted. The management plane has its own router and is unaffected.
            .layer(axum::middleware::from_fn({
                // The CORS half of this stamp reads `[service].cors_allowed_origins`, so the
                // middleware needs the config the routed `CorsLayer` was built from.
                let sec_cfg = std::sync::Arc::clone(&cfg);
                move |req, next| {
                    let cfg = std::sync::Arc::clone(&sec_cfg);
                    async move { set_security_headers(req, next, &cfg).await }
                }
            }))
            // Count requests rejected by an inner resilience layer: load-shed 503, timeout
            // 408, body-cap 413, URI-cap 414. Placed first, so it observes the final status
            // after those layers rendered it, including a 408 whose handler future the
            // timeout cancelled, which `gdi_beacon_requests_total` never recorded, and a 503
            // shed before any route ran. These are the load and attack signals the inner
            // per-route metric cannot see.
            .layer(axum::middleware::from_fn(meter_rejections))
            // Request-id correlation: generate a fresh UUID server-side and ignore any
            // inbound `X-Request-Id`. `SetRequestIdLayer` sets the header only when it is
            // absent, keeping a client-supplied one, so the inbound value must be stripped
            // first. Otherwise an unauthenticated caller controls the id on every audit and
            // access-log line, on the `x-request-id` response header and in the JSON error
            // body, which defeats forensic correlation. Placed immediately outside
            // `SetRequestIdLayer`, so the request reaches it header-less.
            .layer(axum::middleware::from_fn(strip_inbound_request_id))
            // Set the id, outermost after the strip, so the trace span and downstream
            // handlers see it, then propagate it into the response header so a request's logs
            // and its public error response correlate by `X-Request-Id`.
            .layer(SetRequestIdLayer::new(
                request_id_header.clone(),
                MakeRequestUuid,
            ))
            // Inject the correlation `requestId` into JSON error bodies. Inside
            // `SetRequestIdLayer`, so the id is on the request extensions, and outside the
            // resilience layers, so it also enriches their synthesized 408/413/414/500/503
            // envelopes. The client gets one id to quote, the same one on the `x-request-id`
            // response header.
            .layer(axum::middleware::from_fn(add_request_id_to_error_body))
            // A per-request trace span recording the method, path and request id, so every
            // log line emitted while handling the request carries them.
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(move |req: &Request<_>| {
                        let request_id = req
                            .headers()
                            .get(REQUEST_ID_HEADER)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("");
                        let route = req
                            .extensions()
                            .get::<MatchedPath>()
                            .map(MatchedPath::as_str);
                        let span =
                            public_request_span(req.method(), req.uri().path(), request_id, route);
                        // Distributed tracing: behind a trusted ingress, nest this span
                        // under the caller's inbound `traceparent`. When off, or without
                        // `otel`, the span is a fresh server-side root.
                        #[cfg(feature = "otel")]
                        if trust_traceparent {
                            adopt_inbound_trace_context(&span, req.headers());
                        }
                        span
                    })
                    // One access-log line per request, carrying the final response status
                    // and wall-clock latency. Emitted inside the `http_request` span, so it
                    // inherits `method`, `path` and `request_id` for correlation.
                    // tower-http's own `on_response` defaults to DEBUG, invisible at the
                    // shipped `info` level, and formats latency as a human string; this
                    // emits numeric fields a log aggregator can work with. On the outer
                    // layer stack, so it observes the final status of every request,
                    // including the resilience-layer 408/413/414/500/503 that never reach a
                    // route handler.
                    //
                    // Emitted on the `audit` target, like the beacon query audit trail, so
                    // `with_audit_floor` keeps it at info under an operational
                    // `GDI_LOG=warn`. It is the only per-request record for traffic the
                    // resilience layers reject, which produces no `beacon_query` audit line,
                    // so silencing it with the level knob would erase that traffic's only
                    // trace.
                    .on_response(
                        |response: &Response<_>, latency: Duration, span: &tracing::Span| {
                            let status = response.status().as_u16();
                            tracing::info!(
                                target: "audit",
                                event = "http_request",
                                event.action = "http.request",
                                status,
                                // Microseconds: a typical request is well under a
                                // millisecond, so whole milliseconds read `0` on nearly
                                // every line.
                                latency_us = u64::try_from(latency.as_micros()).unwrap_or(u64::MAX),
                                "request completed"
                            );
                            record_response_on_span(span, status);
                            // Whole public-plane RED metrics: every completed public
                            // request, including the beacon informational surface and the
                            // well-known recipient endpoint, which the per-entry-type beacon
                            // metric never saw. Content-free labels only.
                            crate::metrics::record_http_request(
                                crate::metrics::PLANE_PUBLIC,
                                status,
                                latency.as_secs_f64(),
                            );
                        },
                    ),
            )
            .layer(PropagateRequestIdLayer::new(request_id_header))
            // Within the request span: record the OTel trace and span ids onto it, so the
            // JSON log line carries `span.trace_id` and a log viewer can pivot from a line to
            // its trace. A no-op without the `otel` feature: the ids stay `Empty` and are
            // omitted.
            .layer(axum::middleware::from_fn(record_otel_ids))
            // Render every synthesized resilience error from the layers below (414, 408,
            // 503, 500) in the dialect of the surface the request was for: the beacon
            // envelope, the FDP's bare text, or neutral JSON, decided from the request path
            // (see `ErrorDialect`). Inside the request-id and trace layers, so the JSON
            // dialects gain `requestId` and every rejection still emits an access-log line;
            // outside every rejecting layer, and inside `meter_rejections`, so a rejection is
            // still counted.
            .layer(axum::middleware::from_fn(move |req, next| {
                let cfg = std::sync::Arc::clone(&cfg);
                let mounts = std::sync::Arc::clone(&mounts);
                async move { render_synthesized_errors(&cfg, &mounts, req, next).await }
            }))
            // Request-target length cap → 414, the GET-side mirror of the body cap. It
            // pre-empts routing and the handler, body and timeout layers below.
            .layer(axum::middleware::from_fn(reject_long_uri))
            // Panic isolation: a handler panic → 500.
            .layer(CatchPanicLayer::custom(panic_to_response))
            // Global body cap → 413. axum renders the `DefaultBodyLimit` rejection itself;
            // the beacon mounts re-render theirs as the envelope (see `beacon_router`).
            .layer(DefaultBodyLimit::max(body_limit))
            // Per-request timeout → a bare 408, which `render_synthesized_errors`
            // recognizes by status (tower's layer sets no marker; no handler emits 408).
            .layer(TimeoutLayer::with_status_code(
                StatusCode::REQUEST_TIMEOUT,
                request_timeout,
            ))
            // Load-shed maps an over-limit ConcurrencyLimit into an Overloaded error;
            // HandleErrorLayer turns that into a marked 503.
            .layer(HandleErrorLayer::new(|err: BoxError| async move {
                handle_layer_error(&err)
            }))
            .layer(LoadShedLayer::new())
            .layer(shared_concurrency_layer(max_concurrent))
            // Innermost: track in-flight requests. Inside the concurrency limit and the
            // load-shed, so the gauge counts only requests that acquired a permit and are
            // being served; it ranges over [0, max_concurrent] and is directly comparable to
            // the capacity line. The RAII guard decrements on drop, so a cancelled request
            // future still releases its count.
            .layer(axum::middleware::from_fn(track_in_flight)),
    )
}

/// Middleware that injects the correlation `requestId` into a JSON error response body
/// (status ≥ 400), so a client receiving an error can quote one id, the same one on the
/// `x-request-id` response header.
///
/// The id is the server-generated one from [`SetRequestIdLayer`], read from the request
/// extensions and never from an inbound header. Only a JSON error body under the buffering
/// cap is rewritten; a non-JSON body, or one whose declared `Content-Length` exceeds the cap,
/// is passed through untouched. A body with no `Content-Length` is buffered up to the cap and
/// rewritten. A `2xx` or `3xx` response is left as is.
async fn add_request_id_to_error_body(req: Request, next: Next) -> Response {
    let request_id = req
        .extensions()
        .get::<RequestId>()
        .and_then(|id| id.header_value().to_str().ok())
        .map(str::to_owned);
    let response = next.run(req).await;

    let Some(request_id) = request_id else {
        return response;
    };
    let status = response.status();
    if !status.is_client_error() && !status.is_server_error() {
        return response;
    }
    let headers = response.headers();
    let is_json = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/json"));
    // A `Content-Length` is usually absent here, because axum's `Json` leaves it for the
    // server to set at send time, so buffering is bounded by the `to_bytes` cap below rather
    // than by this header. Only a declared over-cap length is skipped up front, to avoid
    // reading a large body we would discard.
    let declared_over_cap = headers
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|n| n > MAX_ERROR_BODY_REWRITE_BYTES);
    if !is_json || declared_over_cap {
        return response;
    }

    let (mut parts, body) = response.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, MAX_ERROR_BODY_REWRITE_BYTES).await else {
        // Unreachable for a full sub-`Content-Length` body. If it happens the body is
        // already consumed, so return the status with an empty body rather than a torn one;
        // `Content-Length` is dropped so the server recomputes it.
        parts.headers.remove(CONTENT_LENGTH);
        return Response::from_parts(parts, Body::empty());
    };
    // Insert `requestId` only into a JSON object; any other JSON shape passes through
    // unchanged. `Content-Length` is dropped so the server recomputes it for the new body.
    match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(serde_json::Value::Object(mut map)) => {
            map.insert("requestId".to_owned(), serde_json::Value::from(request_id));
            let rendered = serde_json::to_vec(&serde_json::Value::Object(map))
                .unwrap_or_else(|_| bytes.to_vec());
            parts.headers.remove(CONTENT_LENGTH);
            Response::from_parts(parts, Body::from(rendered))
        }
        _ => Response::from_parts(parts, Body::from(bytes)),
    }
}

/// Build the router holding a mount's beacon routes, before nesting under its prefix.
///
/// The informational set is present on every mount; `configuration`, `entry_types` and `map`
/// are scoped to `scope`'s entry types, which the closures capture. The query routes are added
/// per entry type via [`mount_entry_type`], so the table extends in one line: `g_variants` and
/// `datasets` for an aggregated or combined mount, `individuals` for a sensitive or combined
/// one.
fn beacon_router(
    scope: MountScope,
    cfg: std::sync::Arc<gdi_node_standalone_core::config::ServiceConfig>,
) -> Router<AppState> {
    // Scope-aware informational handlers: wrapping the `(state, scope)` functions in closures
    // bakes the per-prefix entry-type scoping into the route. `scope` is `Copy`, so each
    // `move` closure captures its own.
    let mut router = Router::new()
        // Informational endpoints (shared across entry types under this prefix).
        .route("/", get(beacon_info::info))
        .route("/info", get(beacon_info::info))
        .route("/service-info", get(beacon_info::service_info))
        .route(
            "/configuration",
            get(
                move |axum::extract::State(state): axum::extract::State<AppState>| async move {
                    beacon_info::configuration(&state, scope)
                },
            ),
        )
        .route(
            "/entry_types",
            get(
                move |axum::extract::State(state): axum::extract::State<AppState>| async move {
                    beacon_info::entry_types(&state, scope)
                },
            ),
        )
        .route(
            "/map",
            get(
                move |axum::extract::State(state): axum::extract::State<AppState>| async move {
                    beacon_info::map(&state, scope)
                },
            ),
        )
        .route("/filtering_terms", get(beacon_info::filtering_terms));

    // Aggregated entry types: genomicVariant (`g_variants`) + dataset (`datasets`).
    if matches!(scope, MountScope::Aggregated | MountScope::Combined) {
        router = mount_entry_type(
            router,
            "g_variants",
            post(beacon_http::g_variants_post).get(beacon_http::g_variants_get),
        );
        router = mount_entry_type(
            router,
            "datasets",
            post(beacon_http::datasets_post).get(beacon_http::datasets_get),
        );
    }

    // Sensitive entry type: the individuals placeholder (`individuals`).
    if matches!(scope, MountScope::Sensitive | MountScope::Combined) {
        router = mount_entry_type(
            router,
            "individuals",
            post(beacon_http::individuals_post).get(beacon_http::individuals_get),
        );
    }

    // The mount's own unmatched-path fallback: an unknown path under a beacon prefix still
    // answers in the Beacon envelope, which a federated client pointed at this mount parses,
    // with a message saying what happened and an empty `returnedSchemas`. No route matched, so
    // no entity was interpreted, and that field names what the request has been interpreted
    // for. The resilience errors differ: they name the mount's own primary entry type (see
    // `error_dialect`), because their request did target the mount. Declared before the layer
    // below, so the mount's CORS and 413 map cover it. A miss outside every mount gets
    // `public_not_found`'s neutral JSON instead.
    let router = router.fallback(
        move |axum::extract::State(state): axum::extract::State<AppState>| async move {
            beacon_http::route_miss_response(
                &state.config.beacon,
                "no Beacon endpoint matches this path",
            )
        },
    );

    // Render a body-limit 413 as a `beaconErrorResponse` envelope rather than axum's
    // bare-text rejection: the global `DefaultBodyLimit` makes the `Json` extractor reject an
    // oversized body with a plain 413, and a federated aggregator parses the error body.
    // Scoped to the beacon mount, so FDP and management 413s are untouched.
    router.layer(axum::middleware::map_response(move |resp: Response| {
        let cfg = std::sync::Arc::clone(&cfg);
        async move {
            if resp.status() == StatusCode::PAYLOAD_TOO_LARGE {
                beacon_http::error_response(
                    &cfg.beacon,
                    413,
                    "request body exceeds the configured limit",
                )
            } else {
                resp
            }
        }
    }))
}

/// Build the FAIR Data Point router (the LDP resource hierarchy), nested at [`FAIRDP_PREFIX`]
/// by [`build_router`]; the paths here are relative to it.
///
/// The four dereferenceable resources, plus the mount's own fallback: anything else under the
/// prefix gets the bare `404` a real FDP miss returns ([`fairdp_http::not_found_fallback`]),
/// not the Beacon envelope. The profile resources are absent, their `dct:conformsTo` markers
/// being opaque and not served. Each handler self-gates on `[fairdp]` being configured.
fn fairdp_router() -> Router<AppState> {
    Router::new()
        .route("/", get(fairdp_http::root))
        .route("/catalog/{id}", get(fairdp_http::catalog))
        .route("/dataset/{id}", get(fairdp_http::dataset))
        .route("/distribution/{id}", get(fairdp_http::distribution))
        .fallback(fairdp_http::not_found_fallback)
}

/// `GET /fairdp/` — `308 Permanent Redirect` to the FDP root [`FAIRDP_PREFIX`].
///
/// The one exception to the node's "a trailing slash is not a route" rule, and a bounded one:
/// a harvest source URL written with the slash otherwise gets the FDP-dialect `404`, which
/// `ckanext-fairdatapoint` reads as an empty FDP, so the harvest completes with zero datasets
/// and no error for an operator to see.
///
/// `308` rather than `307`: the canonical IRI is the slash-less form permanently, and `308`
/// preserves the method, which a `301` may not. No other path gains a slash spelling, because
/// two spellings for a resource IRI is what an LDP containment graph must not have;
/// `not_found_shapes::every_other_trailing_slash_path_still_404s` pins that.
///
/// Not gated on `[fairdp]` being configured, matching the FDP routes themselves, which are
/// always mounted and each self-gating, so the redirect cannot be probed to learn whether the
/// block is present.
///
/// It sits on the outer router, since `nest` cannot route a nest root with a trailing slash,
/// so it carries `public_cors` but not `meter_fairdp`: such a hit is counted on the generic
/// HTTP series and not in the FDP serving metric. That costs one redirect per misconfigured
/// harvester, and the followed request lands inside the nest and is metered there.
async fn fairdp_root_redirect() -> Response {
    axum::response::Redirect::permanent(FAIRDP_PREFIX).into_response()
}

/// The unauthenticated action endpoints the management plane mounts under
/// `[control].enabled`, as route paths: the one list every posture surface prints
/// (`check-config`, the boot-time opt-in notice), so none of them can enumerate three of four.
/// The router mounts the same paths as literals (see the note inside
/// [`build_management_router`]); the `reload_route` guard binds the two.
pub const CONTROL_ROUTES: &[&str] = &[
    "/reload",
    "/reconcile",
    "/log-level",
    "/datasets/{id}/reingest",
];

/// Build the management-plane router, served on the separate `[service].management_addr`
/// listener and never on the public one. Keeping it off the public socket and Ingress means a
/// misconfigured public Ingress can expose only the data plane (beacon and FDP, visible-only),
/// never the non-visible-dataset existence and `channel` oracle or the operational metrics.
/// All consumers are in-cluster (kubelet probes, Prometheus, operator tooling); reach is
/// governed by network binding and `NetworkPolicy`, not by a subtractive allowlist.
///
/// Routes:
/// * `GET /health/live` — liveness (always `200`);
/// * `GET /health/ready` — readiness plus per-subsystem detail (`200`/`503`);
/// * `GET /version` — build and version info (JSON, always `200`);
/// * `GET /catalogs` — the configured catalogs (id and title) as plain JSON;
/// * `GET /datasets/{id}/state` — one dataset's serving status, for any id including hidden
///   and errored ones, which is why it must stay off the public surface;
/// * `GET /datasets` and `GET /datasets/suppressed` — the whole inventory and the withheld
///   inventory, present only under `[service].expose_dataset_list`;
/// * `GET /stats/queries` — per-dataset usage counters, present only under `[stats].enabled`;
/// * the action endpoints [`CONTROL_ROUTES`] — `POST /reload`, `POST /reconcile`,
///   `POST /log-level`, `POST /datasets/{id}/reingest` — present only under
///   `[control].enabled`, and unauthenticated like the rest of the plane;
/// * `GET /metrics` — Prometheus exposition, present only when a recorder was installed.
///
/// The `api_doc_routes` and `route_inventory` guards check the router source against
/// `docs/api.md`. This list is prose; the guards are the binding.
///
/// A handler panic is caught and rendered as a bare `500` on every route, the probes included:
/// this plane is not the beacon, so it carries no `beaconErrorResponse` envelope and no
/// wildcard CORS. Every route carries the request timeout. The probes do not carry admission
/// control, the load shed and the concurrency limit, so a saturated plane cannot make the
/// kubelet evict a node that is answering; see the comment on the layer stack below. The
/// high-frequency health probes are not traced.
pub fn build_management_router(
    state: AppState,
    metrics: Option<std::sync::Arc<metrics::MetricsHandle>>,
) -> Router {
    // The mount below restates these paths as literals rather than iterating this constant:
    // the route-inventory guards parse the path literals of the `Router::route` calls out of
    // this source, and an iterated mount would leave them nothing to read. The integration
    // guard `reload_route::every_control_route_is_gated_by_the_one_flag` asserts that the
    // parsed `[control].enabled` block equals this constant both ways, which keeps the
    // literals and the constant from drifting.
    let cfg = std::sync::Arc::clone(&state.config);
    let mut router = traced_management_router(&cfg);
    if let Some(handle) = metrics {
        router = router.merge(metrics::metrics_router(handle));
    }
    // The management plane gets the same resilience floor as the public one. It carries the
    // dataset-state oracle and must bind beyond loopback for an orchestrator to reach it, so
    // without a request timeout and a concurrency limit anything able to reach it could hold
    // connections open until the health probes starved and the node was evicted as unready.
    // Not the beacon error envelope: this plane speaks its own shapes, so the bare tower
    // statuses (408, 503) are correct here.
    let timeout = Duration::from_secs(cfg.service.request_timeout_seconds.max(1));
    let max_concurrent = cfg.service.max_concurrent_requests.max(1);

    // The probes are exempt from admission control, not from the safety layers. `Router::layer`
    // applies to the path router and the fallbacks alike, so a probe merged inside the shed and
    // the semaphore queues behind saturating traffic and answers 503; enough shed probes in a
    // row make the kubelet kill a node that is serving correctly. They keep panic-catching and
    // the request timeout: `health::ready` takes `channel_health` twice, and no route on either
    // plane should be unbounded.
    let safety = || {
        tower::ServiceBuilder::new()
            .layer(CatchPanicLayer::new())
            .layer(TimeoutLayer::with_status_code(
                StatusCode::REQUEST_TIMEOUT,
                timeout,
            ))
    };
    let limited = router.layer(
        tower::ServiceBuilder::new()
            .layer(safety())
            // The error is bound and logged, not discarded. This layer sees two different
            // things: `Overloaded` from the load-shed below, which is expected back-pressure
            // and already counted, and any other tower layer failure, which is not.
            // Flattening both to a silent 503 would make an inner failure on this plane
            // indistinguishable from shedding, with nothing written anywhere.
            //
            // The status discriminates too, as it does in the public plane's
            // `handle_layer_error`. The health router is merged outside `limited` below, so
            // what this covers is the dataset-state oracle and `/metrics`. For those, "I am
            // shedding, retry" and "something inside me failed" are different answers: an
            // orchestrator backs off on 503 and escalates on 500.
            .layer(HandleErrorLayer::new(|err: BoxError| async move {
                if err.is::<Overloaded>() {
                    // Expected back-pressure, already counted by the rejection metric.
                    StatusCode::SERVICE_UNAVAILABLE
                } else {
                    tracing::error!(
                        error = %err,
                        "unexpected tower layer error on the management plane; returning 500"
                    );
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            }))
            .layer(LoadShedLayer::new())
            .layer(shared_concurrency_layer(max_concurrent)),
    );
    limited
        .merge(management_health_router().layer(safety()))
        // Outermost, over both halves: the management plane's RED series. It sits here rather
        // than on the traced router's `TraceLayer`, which wraps only the oracle and control
        // routes; the health probes and `/metrics` are merged outside that layer and are most
        // of this plane's traffic.
        .layer(axum::middleware::from_fn(meter_management_request))
        .with_state(state)
}

/// Management-plane RED: one increment into `gdi_http_requests_total{plane="management"}` and
/// the duration histogram per completed request, on every management route, the traced oracle
/// routes, `/metrics` and the untraced health probes alike. A metric increment rather than a
/// span keeps the probes untraced (see [`management_health_router`]) while making a scraper or
/// kubelet hammering the plane visible without flooding the trace backend. It is the outermost
/// layer, so it sees the final status, including the resilience layers' 408 and 503.
async fn meter_management_request(req: Request, next: Next) -> Response {
    let started = std::time::Instant::now();
    let response = next.run(req).await;
    crate::metrics::record_http_request(
        crate::metrics::PLANE_MANAGEMENT,
        response.status().as_u16(),
        started.elapsed().as_secs_f64(),
    );
    response
}

/// The high-frequency liveness and readiness probes. Untraced: the kubelet hits these every
/// few seconds, so a span per probe would flood the trace backend for no diagnostic value,
/// the same reason `/metrics` is untraced.
fn management_health_router() -> Router<AppState> {
    Router::new()
        .route("/health/live", get(health::live))
        .route("/health/ready", get(health::ready))
}

/// The orchestrator-facing management routes (`/datasets/{id}/state`, `/version`,
/// `/catalogs`), traced only when the caller supplies an inbound `traceparent` and the node
/// trusts it (`[service].trust_inbound_traceparent`). That keeps the state-oracle call
/// correlatable with the orchestrator's own trace on demand, without an unparented span on
/// every unlabelled poll, which would flood the plane as tracing the health probes would.
fn traced_management_router(
    cfg: &gdi_node_standalone_core::config::ServiceConfig,
) -> Router<AppState> {
    // Copied out because the `make_span_with` closure below is `move` and outlives `cfg`.
    let trust_traceparent = cfg.service.trust_inbound_traceparent;
    let request_id_header = HeaderName::from_static(REQUEST_ID_HEADER);
    let mut router = Router::new()
        .route("/version", get(health::version))
        // Always mounted, like `/version`: the catalog table is already public on the FDP
        // root, so there is no disclosure to gate. This is the same table as plain JSON, for
        // an integrating system that should not have to parse the RDF.
        .route("/catalogs", get(catalogs_http::catalogs))
        .route("/datasets/{id}/state", get(datasets_http::dataset_state));
    // Opt-in: mounted only when the operator asked for it, so with the flag off the route is
    // absent rather than forbidden. That 404 is the one an older node gives, which keeps the
    // flag itself unprobeable.
    if cfg.service.expose_dataset_list {
        router = router
            .route("/datasets", get(datasets_http::dataset_list))
            // Same flag and same disclosure class: the withheld set is the one inventory
            // question the plain listing cannot answer (see `dataset_list_suppressed`).
            .route(
                "/datasets/suppressed",
                get(datasets_http::dataset_list_suppressed),
            );
    }
    // Opt-in on the same terms. This function takes the whole config rather than a bool per
    // flag: a growing bool list is both a lint (`fn_params_excessive_bools`) and a
    // positional-argument hazard.
    if cfg.stats.enabled {
        router = router.route("/stats/queries", get(stats_http::query_stats));
    }
    // Opt-in on the same terms, but these make the node act rather than answer a read. Same
    // absent-when-off shape.
    if cfg.control.enabled {
        router = router
            .route("/reload", post(control_http::reload))
            .route("/reconcile", post(control_http::reconcile))
            .route("/log-level", post(control_http::log_level))
            // The per-id twin of `/reconcile`: clears one dataset's recorded signature, as
            // `dataset reingest <id>` queues, and starts the same pass.
            .route("/datasets/{id}/reingest", post(control_http::reingest));
    }
    router.layer(
        ServiceBuilder::new()
            // Outermost: unlike the public plane, this one honours a caller-supplied
            // `x-request-id`, but only one fit to appear in a log line and a response
            // header. The value is bounded first, and an unusable one is dropped and
            // replaced below rather than rejected. See `bound_inbound_request_id` for why
            // honouring it is safe here and not there.
            .layer(axum::middleware::from_fn(bound_inbound_request_id))
            // `SetRequestIdLayer` sets the header only when it is absent, keeping an
            // existing one, so the caller's id survives to the span, the handlers and, via
            // propagation, the response. With no inbound id, or one the bound above dropped,
            // a fresh server-side UUID is minted, so every management response carries one.
            .layer(SetRequestIdLayer::new(
                request_id_header.clone(),
                MakeRequestUuid,
            ))
            // Echo it back: the response header is the correlation surface an orchestrator
            // reads, and the only one on a plane that does not log every poll.
            .layer(PropagateRequestIdLayer::new(request_id_header))
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(move |req: &Request<_>| {
                        // A span buys nothing on an unlabelled poll, such as a readiness
                        // check hitting `/version`, so one is created only when the caller
                        // asked to be correlated: by supplying a usable `x-request-id`, or
                        // by carrying a trace context this node trusts. A minted id alone is
                        // not enough, because nothing would correlate with it.
                        let caller_supplied =
                            req.extensions().get::<CallerSuppliedRequestId>().is_some();
                        if !(caller_supplied
                            || (trust_traceparent && req.headers().contains_key("traceparent")))
                        {
                            return tracing::Span::none();
                        }
                        let request_id = req
                            .headers()
                            .get(REQUEST_ID_HEADER)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("");
                        let route = req
                            .extensions()
                            .get::<MatchedPath>()
                            .map(MatchedPath::as_str);
                        let span = tracing::info_span!(
                            "mgmt_request",
                            method = %req.method(),
                            path = %req.uri().path(),
                            request_id = %request_id,
                            // Same shape as the public span (see `build_public_router`).
                            otel.name = %request_span_name(req.method(), route),
                            otel.kind = "server",
                            http.route = route.unwrap_or(""),
                            http.response.status_code = tracing::field::Empty,
                            otel.status_code = tracing::field::Empty,
                            trace_id = tracing::field::Empty,
                            span_id = tracing::field::Empty,
                        );
                        // Nest under the caller's inbound `traceparent`: otel builds only,
                        // and a no-op without an active OpenTelemetry layer.
                        #[cfg(feature = "otel")]
                        adopt_inbound_trace_context(&span, req.headers());
                        // After the adoption, which changes the ids. The public plane records
                        // them from a middleware, and this plane's routes run under no such
                        // layer.
                        record_span_ids(&span);
                        span
                    })
                    // The final status onto the span, where a 5xx marks it an OTel error, as
                    // on the public plane. No log line and no metric here: the access log
                    // stays off this plane, and `meter_management_request` counts the
                    // request.
                    .on_response(
                        |response: &Response<_>, _latency: Duration, span: &tracing::Span| {
                            record_response_on_span(span, response.status().as_u16());
                        },
                    ),
            ),
    )
}

/// Marker placed on a management request whose inbound `x-request-id` was accepted, so the
/// span builder can tell a caller's id from one this node minted moments later.
///
/// By the time `make_span_with` runs, `SetRequestIdLayer` has given every request an id and
/// the two are indistinguishable from the headers alone, yet only the first is worth a span.
#[derive(Clone, Copy)]
struct CallerSuppliedRequestId;

/// Accept a caller-supplied `x-request-id` on the management plane, bounded.
///
/// Kept when it is 1–[`MAX_INBOUND_REQUEST_ID_LEN`] bytes of visible ASCII; otherwise the
/// header is removed and [`SetRequestIdLayer`] mints a fresh server-side UUID. Dropping rather
/// than rejecting: a malformed correlation id is no reason to fail an operator's request, and
/// degrading to a server-minted id loses only the caller's own correlation.
///
/// The public plane strips inbound ids unconditionally ([`strip_inbound_request_id`]), because
/// an unauthenticated internet caller would otherwise choose the id on every audit line,
/// response header and error body, and correlation an attacker controls is worse than none.
/// The management listener is a different trust domain: it binds loopback by default, carries
/// no public routes, and its callers are the operator and the orchestrator that deployed the
/// node. For them a shared id is what lets one request be followed across the boundary.
///
/// The bound is not about CRLF, since a `HeaderValue` cannot hold control bytes and the JSON
/// formatter escapes. It is about a value copied into a response header and into every log
/// line the request emits: an unbounded id is log amplification.
async fn bound_inbound_request_id(mut req: Request, next: Next) -> Response {
    let acceptable = req
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|id| {
            !id.is_empty()
                && id.len() <= MAX_INBOUND_REQUEST_ID_LEN
                && id.bytes().all(|b| b.is_ascii_graphic())
        });
    if acceptable {
        req.extensions_mut().insert(CallerSuppliedRequestId);
    } else {
        req.headers_mut().remove(REQUEST_ID_HEADER);
    }
    next.run(req).await
}

/// Mount one entry type's query route at `{entry_type}` on the beacon router, wrapped in the
/// per-entry-type request metric.
///
/// Centralizing this keeps adding an entry type a one-line change. The `entry_type` is a
/// static, content-free label, the route name and never the query; the only labels on
/// `gdi_beacon_requests_total` and `gdi_beacon_request_duration_seconds` are it and the
/// response status class.
fn mount_entry_type(
    router: Router<AppState>,
    entry_type: &'static str,
    method_router: MethodRouter<AppState>,
) -> Router<AppState> {
    let instrumented = method_router.layer(axum::middleware::from_fn(
        move |req: Request, next: Next| async move {
            let started = std::time::Instant::now();
            let response = next.run(req).await;
            metrics::record_beacon_request(
                beacon_metric_entry_type(entry_type),
                response.status().as_u16(),
                started.elapsed().as_secs_f64(),
            );
            response
        },
    ));
    router.route(&format!("/{entry_type}"), instrumented)
}

/// The GA4GH entry-type label (`genomicVariant` / `dataset` / `individual`) for a
/// beacon route slug (`g_variants` / `datasets` / `individuals`).
///
/// The route path stays the Beacon-spec slug, but the metric `entry_type` label uses the
/// GA4GH entity name, so it matches the audit `entry_type` and the `/map` entity naming and a
/// consumer can correlate the metric and audit streams on one value.
fn beacon_metric_entry_type(route_slug: &str) -> &'static str {
    match route_slug {
        "g_variants" => "genomicVariant",
        "datasets" => "dataset",
        "individuals" => "individual",
        // An unmapped slug is a new entry-type route that forgot to extend this map:
        // surface it, panicking under test and debug and warning in production, rather than
        // silently metering and auditing it as genomicVariant.
        other => {
            debug_assert!(
                false,
                "unmapped beacon route slug {other:?}; add it to beacon_metric_entry_type"
            );
            tracing::warn!(
                route_slug = other,
                "unmapped beacon route slug metered as genomicVariant"
            );
            "genomicVariant"
        }
    }
}

/// Normalize a configured mount prefix for `Router::nest`.
///
/// `nest` requires a path that does not end in a slash, so a trailing slash is stripped and a
/// missing leading slash added. An effectively-root prefix becomes the bare beacon root path,
/// so the nest is always valid.
fn normalize_prefix(raw: &str) -> String {
    let trimmed = raw.trim_end_matches('/');
    if trimmed.is_empty() {
        return "/beacon".to_owned();
    }
    if trimmed.starts_with('/') {
        trimmed.to_owned()
    } else {
        format!("/{trimmed}")
    }
}

/// The public plane's beacon mount prefixes, normalized for `Router::nest`.
///
/// Computed once by [`public_mounts`] and read both by [`build_router`], which nests the
/// beacon routers at them, and by [`render_synthesized_errors`], which classifies a request
/// path by them, so the two cannot disagree about where a mount begins. The FDP prefix is the
/// constant [`FAIRDP_PREFIX`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct PublicMounts {
    /// `[beacon].aggregated_base_path`, normalized.
    aggregated: String,
    /// `[beacon].sensitive_base_path`, normalized (equal to `aggregated` on a combined mount).
    sensitive: String,
}

/// The [`PublicMounts`] a config mounts.
fn public_mounts(cfg: &gdi_node_standalone_core::config::ServiceConfig) -> PublicMounts {
    PublicMounts {
        aggregated: normalize_prefix(&cfg.beacon.aggregated_base_path),
        sensitive: normalize_prefix(&cfg.beacon.sensitive_base_path),
    }
}

/// Which surface a request was for: the dialect a synthesized error answers in. The same three
/// the unmatched-path `404` uses (`public_not_found` and the beacon and FDP fallbacks),
/// decided here from the path, because the resilience layers run outside the routed mounts and
/// never see a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorDialect {
    /// Under a beacon mount: the `beaconErrorResponse` envelope a federated client pointed at
    /// the mount parses. The carried entry type names the mount's primary one and is what the
    /// resilience errors report. The mount's own unmatched-path `404` does not come through
    /// here; it takes `beacon_http::route_miss_response` and carries an empty
    /// `returnedSchemas`.
    Beacon(&'static str),
    /// Under `/fairdp`: bare `text/plain`, like the FDP's own handler errors.
    Fdp,
    /// Outside every mount: the neutral JSON body.
    Neutral,
}

/// Classify `path` (a request path, not a route) against the mounts. A prefix matches at a
/// segment boundary only, so `/fairdpx` is not the FDP and `/beacon/v2x` is not the beacon.
/// When both beacon prefixes match, with a sensitive mount nested under the aggregated one,
/// the longest wins, as the router's own nesting resolves it.
fn error_dialect(mounts: &PublicMounts, path: &str) -> ErrorDialect {
    fn under(path: &str, prefix: &str) -> bool {
        path.strip_prefix(prefix)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    }
    if mounts.aggregated == mounts.sensitive {
        if under(path, &mounts.aggregated) {
            return ErrorDialect::Beacon(MountScope::Combined.primary_entry_type());
        }
    } else {
        let aggregated = under(path, &mounts.aggregated).then_some(mounts.aggregated.len());
        let sensitive = under(path, &mounts.sensitive).then_some(mounts.sensitive.len());
        match (aggregated, sensitive) {
            (Some(a), Some(s)) if s > a => {
                return ErrorDialect::Beacon(MountScope::Sensitive.primary_entry_type());
            }
            (Some(_), _) => {
                return ErrorDialect::Beacon(MountScope::Aggregated.primary_entry_type());
            }
            (None, Some(_)) => {
                return ErrorDialect::Beacon(MountScope::Sensitive.primary_entry_type());
            }
            (None, None) => {}
        }
    }
    if under(path, FAIRDP_PREFIX) {
        ErrorDialect::Fdp
    } else {
        ErrorDialect::Neutral
    }
}

/// Response-extension marker on every error a resilience layer synthesizes (the 414 URI cap,
/// the load-shed 503, an unexpected layer 500, a caught-panic 500), carrying the message
/// [`render_synthesized_errors`] renders. Only a marked response is re-rendered, so a
/// handler's own error passes through untouched whatever its status. The 408 is the one
/// unmarked case: tower's `TimeoutLayer` emits it and no handler does, so it is recognized by
/// status.
#[derive(Debug, Clone, Copy)]
struct SynthesizedError {
    message: &'static str,
}

/// A bare `status` carrying the [`SynthesizedError`] marker — what every rejecting layer
/// returns; the dialect renderer gives it a body.
fn synthesized(status: StatusCode, message: &'static str) -> Response {
    let mut resp = status.into_response();
    resp.extensions_mut().insert(SynthesizedError { message });
    resp
}

/// Render a marked synthesized error (or a bare 408) in the request's [`ErrorDialect`].
async fn render_synthesized_errors(
    cfg: &gdi_node_standalone_core::config::ServiceConfig,
    mounts: &PublicMounts,
    req: Request,
    next: Next,
) -> Response {
    let dialect = error_dialect(mounts, req.uri().path());
    let resp = next.run(req).await;
    let status = resp.status();
    let message = match resp.extensions().get::<SynthesizedError>() {
        Some(marker) => marker.message,
        None if status == StatusCode::REQUEST_TIMEOUT => "request timed out",
        None => return resp,
    };
    match dialect {
        ErrorDialect::Beacon(entry_type) => {
            beacon_http::error_response_typed(&cfg.beacon, status.as_u16(), message, entry_type)
        }
        ErrorDialect::Fdp => (status, message).into_response(),
        ErrorDialect::Neutral => (
            status,
            axum::Json(serde_json::json!({ "status": status.as_u16(), "message": message })),
        )
            .into_response(),
    }
}

/// A `CatchPanicLayer` responder: any caught panic → a marked `500` (see
/// [`SynthesizedError`]), rendered by [`render_synthesized_errors`].
fn panic_to_response(panic: Box<dyn Any + Send + 'static>) -> Response {
    // The global panic hook already renders the panic as a `target:"panic"` NDJSON line with
    // message and location, but that line is written outside the request span and carries no
    // `request_id`. This runs inside the `TraceLayer` span, so re-logging here makes the
    // caught handler panic correlatable by `span.request_id`. The public 500 body stays
    // generic.
    let message = match panic.downcast::<&str>() {
        Ok(s) => (*s).to_owned(),
        Err(panic) => match panic.downcast::<String>() {
            Ok(s) => *s,
            Err(_) => "panic".to_owned(),
        },
    };
    tracing::error!(
        alert = true,
        event.action = "http.panic",
        event.outcome = "failure",
        panic_message = %message,
        "handler panicked; returning 500"
    );
    // Count the panic 500 explicitly: it unwinds past the per-entry-type request metric and
    // `rejection_reason` maps 500 → None, so it would otherwise show up only in the logs.
    // This makes a panic-rate alert on `gdi_http_requests_rejected_total{reason="internal"}`
    // viable.
    metrics::record_request_rejected(metrics::REJECT_REASON_INTERNAL);
    synthesized(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
}

/// Outermost middleware: count a request rejected by an inner resilience layer.
///
/// A load-shed `503`, request-timeout `408`, body-cap `413` or URI-cap `414` is bumped onto
/// `gdi_http_requests_rejected_total{reason}`. Any other status is a handler response and is
/// left untouched here.
///
/// The status-to-reason inference is exact for `408`, `413` and `414`, and it is tested
/// (`scan_reject_too_large_maps_to_400_not_413`). It is not exact for `503`: a public-plane
/// handler emits one too, since `ScanReject::scan_pool_saturated` renders a `503` through
/// `error_response_typed` that passes outward through this layer, so a scan-pool shed is
/// counted as `reason="overloaded"` alongside genuine load-shed rejections. The remedies
/// differ: a scan shed trips on scans detached by request timeouts, so it calls for a longer
/// `request_timeout_seconds` or narrower queries, not a higher concurrency cap. Independent
/// telemetry distinguishes the two.
///
/// The management plane, where readiness legitimately returns `503`, runs on a separate router
/// without this stack.
async fn meter_rejections(req: Request, next: Next) -> Response {
    let response = next.run(req).await;
    if let Some(reason) = rejection_reason(response.status()) {
        metrics::record_request_rejected(reason);
    }
    response
}

/// Strip any client-supplied `X-Request-Id` from the request, so [`SetRequestIdLayer`] always
/// mints a fresh server-side id; it keeps an existing header otherwise. Without this an
/// unauthenticated caller controls the correlation id on every audit line, on the response
/// header and in the JSON error body. CRLF log forgery is impossible either way, because
/// `HeaderValue` rejects control bytes and the log formatter escapes; this is about
/// correlation integrity.
async fn strip_inbound_request_id(mut req: Request, next: Next) -> Response {
    req.headers_mut().remove(REQUEST_ID_HEADER);
    next.run(req).await
}

/// The process-wide in-flight concurrency limiter, shared across every route the layer wraps.
///
/// This must be [`GlobalConcurrencyLimitLayer`], never `ConcurrencyLimitLayer`:
/// `Router::layer` applies a layer per route, and `ConcurrencyLimitLayer::new` mints a fresh
/// semaphore on each `.layer()` call, so the effective cap becomes (routes × methods) × `max`
/// and load-shed never fires at the intended threshold. The saturation gauge, a global
/// numerator over a per-route capacity, would be meaningless too. The global variant shares
/// one `Arc<Semaphore>` across all clones, so `max` is the true ceiling for the whole plane.
/// Both planes build their limiter here, so they cannot diverge.
fn shared_concurrency_layer(max: usize) -> GlobalConcurrencyLimitLayer {
    GlobalConcurrencyLimitLayer::new(max)
}

/// Record the active request span's OpenTelemetry trace and span ids onto its declared
/// `trace_id` and `span_id` fields, so the JSON log line carries `span.trace_id` and a log
/// viewer can pivot from a line to its trace.
///
/// Runs inside the `http_request` span, being layered under the `TraceLayer`, so
/// `Span::current()` is that span and the `tracing-opentelemetry` layer has already assigned
/// it a trace context. Without the `otel` feature this is a pass-through: the `Empty` fields
/// stay unrecorded and are omitted from the line.
async fn record_otel_ids(req: Request, next: Next) -> Response {
    record_span_ids(&tracing::Span::current());
    next.run(req).await
}

/// The public plane's per-request span: the `tracing` name `http_request` for the log lines,
/// and the OpenTelemetry shape for the export, pinned by
/// `logging::otel_tests::an_exported_request_span_has_the_conventional_shape`.
pub(crate) fn public_request_span(
    method: &Method,
    path: &str,
    request_id: &str,
    route: Option<&str>,
) -> tracing::Span {
    tracing::info_span!(
        "http_request",
        method = %method,
        path,
        request_id,
        // The exported span's name and kind. `otel.name` is what a trace backend's search
        // and facets key on, and the route template keeps it bounded and free of ids, so
        // "latency by endpoint" stays answerable. `otel.kind` marks a server span, which
        // service graphs and RED-from-spans need.
        otel.name = %request_span_name(method, route),
        otel.kind = "server",
        http.route = route.unwrap_or(""),
        // Recorded by `record_response_on_span` in `on_response`: the final status, and the
        // OTel error status on a 5xx, so a trace query for errors finds it.
        http.response.status_code = tracing::field::Empty,
        otel.status_code = tracing::field::Empty,
        // Filled in by `record_otel_ids` once the OpenTelemetry layer has assigned this span
        // its trace context, in otel builds only. Declared `Empty`, so an unrecorded value is
        // omitted from the JSON line and the default wire schema is unchanged.
        trace_id = tracing::field::Empty,
        span_id = tracing::field::Empty,
    )
}

/// The exported name of a request span: `METHOD route-template`, the OpenTelemetry convention
/// for a server span. The template rather than the path, so the name stays a bounded set; a
/// request that matched no route is `METHOD unmatched`. Recorded as the `otel.name` span
/// field, which the tracing bridge turns into the span's name, while the `tracing` name stays
/// `http_request` or `mgmt_request` for the log lines.
pub(crate) fn request_span_name(method: &Method, route: Option<&str>) -> String {
    format!("{method} {}", route.unwrap_or("unmatched"))
}

/// Record a completed request's status onto its span: `http.response.status_code`
/// always, and `otel.status_code = "ERROR"` on a 5xx (a 4xx is the client's error, and
/// the OpenTelemetry convention leaves a server span unset for it). Both fields are
/// declared `Empty` at span creation. A `Span::none()` (an untraced management poll) takes
/// the records as a no-op.
pub(crate) fn record_response_on_span(span: &tracing::Span, status: u16) {
    span.record("http.response.status_code", status);
    if status >= 500 {
        span.record("otel.status_code", "ERROR");
    }
}

/// Record the OpenTelemetry trace/span ids onto `span`'s `trace_id`/`span_id` fields
/// (declared `Empty` by whoever created the span), so the ECS layer lifts them to
/// `trace.id`/`span.id` on every line emitted inside it. Shared by the request middleware
/// above and the ingest job (`ingest_runtime`), whose lines would otherwise carry no trace
/// id even though the `ingest_job` span is exported. Call it after any `adopt_traceparent`,
/// which re-parents the span and changes the ids. A no-op without `otel`, or when the span
/// has no valid context.
pub(crate) fn record_span_ids(span: &tracing::Span) {
    #[cfg(feature = "otel")]
    {
        use opentelemetry::trace::TraceContextExt as _;
        use tracing_opentelemetry::OpenTelemetrySpanExt as _;

        let context = span.context();
        let otel_span = context.span();
        let span_context = otel_span.span_context();
        if span_context.is_valid() {
            span.record("trace_id", span_context.trace_id().to_string().as_str());
            span.record("span_id", span_context.span_id().to_string().as_str());
        }
    }
    #[cfg(not(feature = "otel"))]
    {
        let _ = span;
    }
}

/// Adopt an inbound W3C `traceparent` as `span`'s parent, so this node's spans nest
/// under an upstream trace (distributed tracing). Called from the request-span factory
/// only when `[service].trust_inbound_traceparent` is set — the operator's assertion
/// that the node sits behind a trusted ingress that sets the header; on the open
/// internet an inbound trace context is caller-controlled, so it is ignored by default.
/// A missing or malformed header yields an invalid context and is ignored (the
/// server-side root stands). Uses the W3C propagator registered globally at otel init.
///
/// A valid header with the sampled flag clear is not harmless. Adopting a parent carries
/// its sampling decision, and under the default `ParentBased` sampler a `traceparent` ending
/// `-00` leaves the child unsampled, so that request exports no spans. A caller trusted for
/// this header can therefore erase a request's trace rather than merely mis-parent it, which
/// blinds the operator to the requests the caller chooses.
///
/// What holds it: `[service].trust_inbound_traceparent` defaults to `false`, and setting it
/// is the operator asserting a trusted ingress that strips client-supplied values. If that
/// assumption ever weakens, adopt only the trace/span ids while forcing the local decision.
/// Rebuild the `SpanContext` with `TraceFlags::SAMPLED`, or configure `Sampler::AlwaysOn`,
/// so a caller can join a trace but never erase one.
#[cfg(feature = "otel")]
fn adopt_inbound_trace_context(span: &tracing::Span, headers: &axum::http::HeaderMap) {
    use opentelemetry::trace::TraceContextExt as _;
    use tracing_opentelemetry::OpenTelemetrySpanExt as _;

    let parent = opentelemetry::global::get_text_map_propagator(|propagator| {
        propagator.extract(&HeaderExtractor(headers))
    });
    if parent.span().span_context().is_valid() {
        // Best-effort: a failed adoption (e.g. no active otel layer) just leaves the
        // server-side root — never fatal.
        let _ = span.set_parent(parent);
    }
}

/// Parent `span` under an inbound W3C `traceparent` given as a string: the `ingest_job`
/// span's parent arrives not in HTTP headers but in the `{id}.state.json` sidecar, so build a
/// one-entry header carrier and reuse [`adopt_inbound_trace_context`].
/// Best-effort — a malformed value is ignored, leaving a fresh server-side root.
#[cfg(feature = "otel")]
pub(crate) fn adopt_traceparent(span: &tracing::Span, traceparent: &str) {
    if let Ok(value) = axum::http::HeaderValue::from_str(traceparent) {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("traceparent", value);
        adopt_inbound_trace_context(span, &headers);
    }
}

/// An [`opentelemetry::propagation::Extractor`] over an HTTP header map — inline so
/// context extraction needs no extra dependency (`opentelemetry-http`).
#[cfg(feature = "otel")]
struct HeaderExtractor<'a>(&'a axum::http::HeaderMap);

#[cfg(feature = "otel")]
impl opentelemetry::propagation::Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(axum::http::HeaderName::as_str).collect()
    }
}

/// Add the baseline security headers (`X-Content-Type-Options: nosniff` and
/// `Cache-Control: no-store`) to every public-plane response, and stamp the public CORS
/// policy onto the resilience-layer error responses.
///
/// The resilience layers (timeout `408`, URI-cap `414`, body-cap `413`, panic `500`,
/// load-shed `503`) synthesize their envelopes outside the per-route `public_cors` layer, so
/// without this a cross-origin browser gets an opaque network error and cannot read the
/// envelope or the `x-request-id` correlation header, while a `200` or route error is
/// readable. [`stamp_public_cors`] (site 3) applies the same policy the routed planes
/// enforce, so a restricted `[service].cors_allowed_origins` is honoured here too: an
/// allowed origin is echoed, a disallowed one gets no `Allow-Origin`. The CORS stamp is
/// applied only when the header is absent, so a route that already ran `public_cors`, or a
/// non-CORS route's success response, is left untouched.
///
/// The two security headers behave differently: `nosniff` and `Cache-Control: no-store` are
/// written with an unconditional `insert`, so a route that set its own value is overridden.
/// `no-store` is a disclosure control rather than a performance hint, and a route must not be
/// able to opt a withheld dataset back into an intermediary cache.
///
/// Scoped to the public plane (only in `apply_resilience_layers`); the management plane
/// carries no such headers.
async fn set_security_headers(
    req: Request,
    next: Next,
    cfg: &gdi_node_standalone_core::config::ServiceConfig,
) -> Response {
    /// The resilience-layer rejection statuses whose envelopes bypass `public_cors`.
    const RESILIENCE_ERRORS: [StatusCode; 5] = [
        StatusCode::REQUEST_TIMEOUT,
        StatusCode::PAYLOAD_TOO_LARGE,
        StatusCode::URI_TOO_LONG,
        StatusCode::INTERNAL_SERVER_ERROR,
        StatusCode::SERVICE_UNAVAILABLE,
    ];
    // The request is consumed by `next.run`, so capture the caller's origin first.
    let origin = req.headers().get(ORIGIN).cloned();
    let mut resp = next.run(req).await;
    let status = resp.status();
    resp.headers_mut().insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    // `Cache-Control: no-store` on the whole public plane, the FDP catalog included.
    //
    // Every withhold this node has (`channel take-down`, the suppression store,
    // `{id}.state.json` tombstones, the visibility-staleness bound) stops the node from
    // serving a dataset, and none of them reach a response already held by a shared forward
    // proxy or a browser cache: without a directive, a cache may heuristically retain a `200`
    // that carries no explicit freshness (RFC 9111 §4.2.2). `no-cache` would not do, because
    // it permits storage and only forces revalidation. The FDP catalog needs the directive
    // most, being the plane that enumerates datasets, so a stale copy re-advertises a
    // retracted one. The cost is small: these are small documents. An operator who wants
    // edge caching of the public catalog can add it at the Ingress for that route.
    resp.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    if RESILIENCE_ERRORS.contains(&status)
        && !resp.headers().contains_key(ACCESS_CONTROL_ALLOW_ORIGIN)
    {
        stamp_public_cors(
            &cfg.service.cors_allowed_origins,
            &mut resp,
            origin.as_ref(),
        );
    }
    resp
}

/// Reject a request whose target (path + query) exceeds [`MAX_REQUEST_TARGET_BYTES`]
/// with a marked `414` (see [`SynthesizedError`]) — the GET-side mirror of the body-size cap.
///
/// Method-agnostic (a POST with a short URI is still body-capped separately). It
/// does not count the rejection itself: the outer [`meter_rejections`] layer counts
/// the `414` via [`rejection_reason`], exactly as the body cap's `413` is counted.
async fn reject_long_uri(req: Request, next: Next) -> Response {
    let uri = req.uri();
    let target_len = uri.path().len() + uri.query().map_or(0, |q| q.len() + 1);
    if target_len > MAX_REQUEST_TARGET_BYTES {
        return synthesized(
            StatusCode::URI_TOO_LONG,
            "request target exceeds the maximum length",
        );
    }
    next.run(req).await
}

/// Innermost middleware: hold the `gdi_http_inflight` gauge incremented while one
/// admitted request is served. The [`metrics::InFlightGuard`] is held across the
/// `.await` and decrements on drop, so a request future cancelled mid-handler
/// (client disconnect, shutdown drain) still releases its slot — a manual
/// post-`.await` decrement would leak on cancellation and ratchet the gauge up.
async fn track_in_flight(req: Request, next: Next) -> Response {
    let _in_flight = metrics::InFlightGuard::enter();
    next.run(req).await
}

/// Instrument one FAIR Data Point request: record `gdi_fairdp_requests_total{status_class}`
/// and its duration. The beacon mounts are instrumented per entry type; the FDP plane mirrors
/// that with a single content-free status-class label.
async fn meter_fairdp(req: Request, next: Next) -> Response {
    let started = std::time::Instant::now();
    let resource = fairdp_resource(&req);
    let response = next.run(req).await;
    metrics::record_fairdp_request(
        resource,
        response.status().as_u16(),
        started.elapsed().as_secs_f64(),
    );
    response
}

/// Derive the bounded FDP `resource_type` label (`root|catalog|dataset|distribution`)
/// from the request path prefix — so a slow catalog listing is distinguishable from a
/// slow dataset fetch, mirroring beacon's per-entry-type split. Only the path prefix is
/// matched, never the `{id}` segment, so the label stays a bounded, content-free closed set.
///
/// `meter_fairdp` is layered on the FDP router before it is nested at [`FAIRDP_PREFIX`], and
/// a nested router sees the request path with that prefix stripped, per axum's `nest`
/// semantics, so the prefixes matched here are `/catalog/…` rather than `/fairdp/catalog/…`.
/// It fronts the four FDP routes and the mount's fallback, so a non-match is the FDP
/// root or an unknown path under it (metered as `root`, keeping the set closed).
fn fairdp_resource(req: &Request) -> &'static str {
    let path = req.uri().path();
    if path.starts_with("/catalog/") {
        "catalog"
    } else if path.starts_with("/dataset/") {
        "dataset"
    } else if path.starts_with("/distribution/") {
        "distribution"
    } else {
        "root"
    }
}

/// Map a resilience-layer rejection status to its bounded `reason` label, or `None`
/// for any other status. Pure (no I/O) so the label mapping is unit-tested directly.
fn rejection_reason(status: StatusCode) -> Option<&'static str> {
    match status {
        StatusCode::SERVICE_UNAVAILABLE => Some(metrics::REJECT_REASON_OVERLOADED),
        StatusCode::REQUEST_TIMEOUT => Some(metrics::REJECT_REASON_TIMEOUT),
        StatusCode::PAYLOAD_TOO_LARGE => Some(metrics::REJECT_REASON_BODY_TOO_LARGE),
        StatusCode::URI_TOO_LONG => Some(metrics::REJECT_REASON_URI_TOO_LARGE),
        _ => None,
    }
}

/// Map a tower layer error (the load-shed `Overloaded`) to a marked bare status (see
/// [`SynthesizedError`]).
///
/// A shed request surfaces as [`Overloaded`] → `503`; any other layer error is a
/// `500`.
fn handle_layer_error(err: &BoxError) -> Response {
    if err.is::<Overloaded>() {
        // Expected back-pressure (load-shed). Not logged per-request — it is a normal,
        // high-frequency signal counted via `gdi_http_requests_rejected_total`
        // {reason="overloaded"} by the outermost `meter_rejections` layer (the
        // per-entry-type beacon metric never sees a shed request — it never reaches a
        // route).
        synthesized(StatusCode::SERVICE_UNAVAILABLE, "service overloaded")
    } else {
        // Any other layer error is unexpected; the generic 500 body hides its cause,
        // so log it (within the request span → carries `span.request_id`).
        tracing::error!(error = %err, "unexpected tower layer error; returning 500");
        // Same rationale as the panic 500: count it so an unexpected-layer-error 500
        // is not metric-invisible (see `REJECT_REASON_INTERNAL`).
        metrics::record_request_rejected(metrics::REJECT_REASON_INTERNAL);
        synthesized(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;

    /// The single public-CORS matcher, exercised directly. Every emitting site (the
    /// `CorsLayer` predicate, the fallback 404, the resilience-error stamp) routes through
    /// it, so pinning it here pins all three.
    #[test]
    fn public_cors_matcher_is_wildcard_by_default_and_exact_when_restricted() {
        let origin = |s: &str| HeaderValue::from_str(s).unwrap();

        // Default (empty) and an explicit "*" are both wildcard-open: every origin is
        // allowed and the response carries the literal `*`.
        for wildcard in [Vec::new(), vec!["*".to_owned()]] {
            assert!(public_cors_is_wildcard(&wildcard));
            assert!(public_cors_origin_allowed(
                &wildcard,
                &origin("https://anything.example")
            ));
            assert_eq!(
                public_cors_acao(&wildcard, Some(&origin("https://anything.example"))),
                Some(HeaderValue::from_static("*"))
            );
            // A wildcard needs no request `Origin` at all to answer.
            assert_eq!(
                public_cors_acao(&wildcard, None),
                Some(HeaderValue::from_static("*"))
            );
        }

        // A restricted list matches exactly, and echoes the caller's origin back.
        let restricted = vec![
            "https://portal.example.org".to_owned(),
            "http://localhost:5173".to_owned(),
        ];
        assert!(!public_cors_is_wildcard(&restricted));
        for allowed in ["https://portal.example.org", "http://localhost:5173"] {
            assert!(public_cors_origin_allowed(&restricted, &origin(allowed)));
            assert_eq!(
                public_cors_acao(&restricted, Some(&origin(allowed))),
                Some(origin(allowed)),
                "an allowed origin is echoed verbatim, never `*`"
            );
        }

        // Anything else is refused — including near-misses that a substring or
        // suffix match would wrongly admit, and a request carrying no `Origin`.
        for denied in [
            "https://evil.example",
            "https://portal.example.org.evil.example",
            "https://sub.portal.example.org",
            "http://portal.example.org",       // scheme differs
            "https://portal.example.org:8443", // port differs
        ] {
            assert!(!public_cors_origin_allowed(&restricted, &origin(denied)));
            assert_eq!(
                public_cors_acao(&restricted, Some(&origin(denied))),
                None,
                "a disallowed origin gets no Allow-Origin header"
            );
        }
        assert_eq!(public_cors_acao(&restricted, None), None);
    }

    /// A minimal, preflight-valid `ServiceConfig` for driving the layer stack.
    fn test_service_config() -> gdi_node_standalone_core::config::ServiceConfig {
        let toml = r#"
[service]
base_url = "https://test.example.org"
data_dir = "/tmp/gdi-node-standalone-applog-test"

[catalogs]
gdi-aggregated = "Genome of Europe Aggregated Data"

[beacon]
aggregated_base_path = "/beacon/v2"
id = "org.test.beacon"
name = "Test Beacon"
environment = "test"

[beacon.organization]
id = "ee.ut.gdi"
name = "University of Tartu"
"#;
        let cfg = gdi_node_standalone_core::config::ServiceConfig::from_toml_str(toml).unwrap();
        cfg.preflight().unwrap();
        cfg
    }

    #[test]
    fn access_log_line_emitted_at_info_with_status_and_latency() {
        use std::sync::Arc;

        use tower::ServiceExt as _; // for `oneshot`

        let cfg = Arc::new(test_service_config());
        // Drive one request through the full layer stack under the capturing subscriber.
        // A current-thread runtime keeps the on_response event on this thread, so the
        // thread-local subscriber records it.
        let ((), logs) = test_util::capture_json_logs_flat(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let router = apply_resilience_layers(
                Router::new().route("/ok", get(|| async { "ok" })),
                Arc::clone(&cfg),
            );
            let req = Request::builder().uri("/ok").body(Body::empty()).unwrap();
            let resp = rt.block_on(router.oneshot(req)).unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        });

        let line = logs
            .lines()
            .find(|l| l.contains("\"request completed\""))
            .unwrap_or_else(|| panic!("no access-log line in captured output:\n{logs}"));
        let v: serde_json::Value = serde_json::from_str(line).unwrap();

        // The access line carries numeric status + latency an aggregator can query...
        assert_eq!(v["message"], "request completed");
        assert_eq!(v["status"], 200);
        assert!(v["latency_us"].is_number(), "latency_us is numeric: {v}");
        // ...and is correlated with the per-request span (method / path / request_id).
        assert_eq!(v["span"]["method"], "GET");
        assert_eq!(v["span"]["path"], "/ok");
        assert!(
            v["span"]["request_id"]
                .as_str()
                .is_some_and(|s| !s.is_empty()),
            "carries a request_id: {v}"
        );
    }

    /// The single path-to-dialect rule the synthesized-error renderer applies. A prefix
    /// matches at a segment boundary only (`/fairdpx` is not the FDP), the sensitive mount
    /// names `individual`, and a combined mount is the aggregated dialect.
    #[test]
    fn error_dialect_follows_the_mount_prefixes() {
        let split = public_mounts(&test_service_config());
        assert_eq!(split.aggregated, "/beacon/v2");
        assert_eq!(split.sensitive, "/sensitive/beacon/v2");
        for (path, expected) in [
            ("/beacon/v2", ErrorDialect::Beacon("genomicVariant")),
            (
                "/beacon/v2/g_variants",
                ErrorDialect::Beacon("genomicVariant"),
            ),
            ("/beacon/v2x", ErrorDialect::Neutral),
            (
                "/sensitive/beacon/v2/individuals",
                ErrorDialect::Beacon("individual"),
            ),
            ("/fairdp", ErrorDialect::Fdp),
            ("/fairdp/catalog/x", ErrorDialect::Fdp),
            ("/fairdpx", ErrorDialect::Neutral),
            ("/", ErrorDialect::Neutral),
            ("/.well-known/c4gh-recipient", ErrorDialect::Neutral),
        ] {
            assert_eq!(error_dialect(&split, path), expected, "{path}");
        }

        let combined = PublicMounts {
            aggregated: "/beacon/v2".to_owned(),
            sensitive: "/beacon/v2".to_owned(),
        };
        assert_eq!(
            error_dialect(&combined, "/beacon/v2/individuals"),
            ErrorDialect::Beacon("genomicVariant"),
            "a combined mount answers in the aggregated dialect"
        );

        // A sensitive prefix nested under the aggregated one: the longest matching prefix
        // decides, or every sensitive-plane path would answer in the aggregated dialect.
        let nested = PublicMounts {
            aggregated: "/beacon/v2".to_owned(),
            sensitive: "/beacon/v2/sensitive".to_owned(),
        };
        assert_eq!(
            error_dialect(&nested, "/beacon/v2/sensitive/individuals"),
            ErrorDialect::Beacon("individual"),
            "a nested sensitive mount is classified by the longest prefix"
        );
        assert_eq!(
            error_dialect(&nested, "/beacon/v2/g_variants"),
            ErrorDialect::Beacon("genomicVariant")
        );
    }

    #[test]
    fn rejection_reason_maps_only_resilience_layer_statuses() {
        assert_eq!(
            rejection_reason(StatusCode::SERVICE_UNAVAILABLE),
            Some(metrics::REJECT_REASON_OVERLOADED)
        );
        assert_eq!(
            rejection_reason(StatusCode::REQUEST_TIMEOUT),
            Some(metrics::REJECT_REASON_TIMEOUT)
        );
        assert_eq!(
            rejection_reason(StatusCode::PAYLOAD_TOO_LARGE),
            Some(metrics::REJECT_REASON_BODY_TOO_LARGE)
        );
        assert_eq!(
            rejection_reason(StatusCode::URI_TOO_LONG),
            Some(metrics::REJECT_REASON_URI_TOO_LARGE)
        );
        // Handler-produced statuses (including the 500 catch-panic envelope and a
        // 4xx bad query) are not resilience-layer rejections and must not be
        // miscounted onto `gdi_http_requests_rejected_total`.
        for ok in [
            StatusCode::OK,
            StatusCode::BAD_REQUEST,
            StatusCode::NOT_FOUND,
            StatusCode::INTERNAL_SERVER_ERROR,
        ] {
            assert_eq!(rejection_reason(ok), None, "{ok} must not map to a reason");
        }
    }

    #[cfg(feature = "otel")]
    #[test]
    fn inbound_traceparent_extraction_gates_on_validity() {
        use opentelemetry::propagation::TextMapPropagator as _;
        use opentelemetry::trace::TraceContextExt as _;

        let propagator = opentelemetry_sdk::propagation::TraceContextPropagator::new();
        let is_valid = |h: &axum::http::HeaderMap| {
            propagator
                .extract(&super::HeaderExtractor(h))
                .span()
                .span_context()
                .is_valid()
        };

        // A valid W3C traceparent → a valid remote context the node would adopt.
        let mut ok = axum::http::HeaderMap::new();
        ok.insert(
            "traceparent",
            axum::http::HeaderValue::from_static(
                "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
            ),
        );
        assert!(is_valid(&ok));

        // Malformed → invalid → ignored (the server-side root stands).
        let mut bad = axum::http::HeaderMap::new();
        bad.insert(
            "traceparent",
            axum::http::HeaderValue::from_static("garbage"),
        );
        assert!(!is_valid(&bad));

        // Absent → invalid (a request with no traceparent keeps its server root).
        assert!(!is_valid(&axum::http::HeaderMap::new()));
    }

    /// A `ServiceConfig` whose aggregated beacon mounts at `prefix`.
    ///
    /// Does not run `preflight`: these tests are about configs preflight rejects, so the
    /// fixture must be able to build one.
    fn config_mounting(prefix: &str) -> gdi_node_standalone_core::config::ServiceConfig {
        let toml = format!(
            r#"
[service]
base_url = "https://test.example.org"
data_dir = "/tmp/gdi-node-standalone-mount-test"

[catalogs]
gdi-aggregated = "Genome of Europe Aggregated Data"

[beacon]
aggregated_base_path = "{prefix}"
id = "org.test.beacon"
name = "Test Beacon"
environment = "test"

[beacon.organization]
id = "ee.ut.gdi"
name = "University of Tartu"
"#
        );
        gdi_node_standalone_core::config::ServiceConfig::from_toml_str(&toml).unwrap()
    }

    /// Build the public router for a config mounting the beacon at `prefix`, reporting
    /// whether axum rejected the layout.
    ///
    /// `Router::nest` signals an overlap by panicking, so catching is the only way to ask.
    /// The panic hook is silenced for the duration: an expected panic printing a backtrace
    /// makes a passing test look like a failing one.
    fn router_panics_at(prefix: &str) -> bool {
        let cfg = config_mounting(prefix);
        let state = crate::state::AppState::new(
            cfg,
            gdi_node_standalone_core::cache::StatusIndex::new(),
            crate::identities::NodeIdentities::empty(),
        );
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = build_router(state);
        }));
        std::panic::set_hook(previous);
        outcome.is_err()
    }

    /// Every entry in [`RESERVED_PUBLIC_PATHS`] is a path the router really conflicts on.
    ///
    /// The list is a second copy of a fact axum owns, so it can rot in two directions:
    /// an entry that no longer conflicts would refuse a working config, and a root route
    /// added without an entry would let the router panic at build time. This pins the first
    /// direction by construction — mount the beacon at each reserved path and watch
    /// `build_router` panic — and the control case proves the probe can come back false.
    #[test]
    fn every_reserved_public_path_really_conflicts() {
        for reserved in RESERVED_PUBLIC_PATHS {
            assert!(
                router_panics_at(reserved),
                "{reserved} is in RESERVED_PUBLIC_PATHS but mounting the beacon there \
                 builds a working router — the entry is stale, remove it"
            );
        }
        assert!(
            !router_panics_at("/beacon/v2"),
            "the probe reports a panic for an ordinary mount, so it proves nothing above"
        );
    }

    /// The collision predicate covers both spellings of the same mount point, and does
    /// not fire on a path that merely shares a textual prefix.
    #[test]
    fn conflicting_reserved_path_matches_at_segment_boundaries() {
        for colliding in [
            "/fairdp",
            "/fairdp/",
            "/fairdp/beacon",
            "/.well-known",
            "/.well-known/c4gh-recipient",
        ] {
            assert!(
                conflicting_reserved_path(colliding).is_some(),
                "{colliding} takes a reserved mount point but was accepted"
            );
        }
        for fine in ["/beacon/v2", "/fairdpx", "/well-known", "/fair"] {
            assert_eq!(
                conflicting_reserved_path(fine),
                None,
                "{fine} collides with nothing but was refused"
            );
        }
    }

    /// The boot-time consumer refuses what the predicate flags, on either mount.
    ///
    /// Drives the whole preflight (`run_with`) rather than `check_mount_prefixes` alone: a
    /// rule nothing calls would still let a config pass preflight and then kill the node.
    /// Asserted first on the inner function so a failure says which half broke.
    #[test]
    fn preflight_refuses_a_beacon_mount_on_a_reserved_path() {
        let err = crate::preflight::check_mount_prefixes(&config_mounting("/fairdp"))
            .expect_err("a beacon mounted at /fairdp must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains("aggregated_base_path") && msg.contains("/fairdp"),
            "the refusal names the offending key and path: {msg}"
        );

        // The wiring: `check-config` and boot both run this pass, and it must reject.
        crate::preflight::run_with(&config_mounting("/fairdp"), false)
            .expect_err("the shared preflight must run the mount check, not just define it");

        let mut split = config_mounting("/beacon/v2");
        split.beacon.sensitive_base_path = WELL_KNOWN_C4GH_PATH.to_owned();
        assert!(
            crate::preflight::run_with(&split, false).is_err(),
            "the sensitive mount is checked too, not just the aggregated one"
        );

        crate::preflight::run_with(&config_mounting("/beacon/v2"), false)
            .expect("an ordinary mount is accepted");
    }
}
