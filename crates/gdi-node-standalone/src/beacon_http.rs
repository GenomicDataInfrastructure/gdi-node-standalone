//! Beacon HTTP handlers for the service binary.
//!
//! The `beacon` crate stays a pure, axum-free library (parse, classify, scan, assemble).
//! This module is the thin axum glue that turns an HTTP request into calls on those pure
//! functions and renders the result. Routing wiring lives in [`crate::app`].

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use axum::Json;
use axum::extract::{FromRequest, FromRequestParts, Query, Request, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use gdi_node_standalone_beacon::BeaconParams;
use gdi_node_standalone_beacon::model::{BeaconErrorResponse, BeaconResponse, Pagination};
use gdi_node_standalone_beacon::query::{
    AggregateScan, DatasetCounts, DatasetPage, DatasetScan, PageSpec,
    apply_include_resultset_responses, assemble, assemble_counts, datasets_response,
    echo_received_request, effective_floor, error_response_meta, scan_dataset_counts,
    scan_dataset_page, shape_for_granularity, submitted_request_echo,
};
use gdi_node_standalone_beacon::request::{
    BeaconReject, IncludeResultsetResponses, QueryKind, RequestParams, apply_pagination, classify,
    parse_dataset_ids, parse_include_resultset_responses, parse_request,
    reject_unsupported_filters, reject_unsupported_params,
};
use gdi_node_standalone_core::cache::DatasetEntry;
use gdi_node_standalone_core::config::{BeaconConfig, ServiceConfig};
use gdi_node_standalone_core::error::ErrorClass;
use gdi_node_standalone_core::query_stats::DatasetOutcome;
use gdi_node_standalone_core::validate_parquet::ParquetCaps;
use serde_json::{Map, Value, json};
use tokio::task::JoinSet;

use crate::audit::BeaconQueryAudit;
use crate::state::AppState;

/// Microseconds elapsed since `started`, saturating (never panics).
fn elapsed_us(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

/// Per-query context the answered-line audit needs and the assembled response does not
/// carry. Built by `run_g_variants` and threaded into [`ok_response`].
struct QueryAuditCtx<'a> {
    /// Queried assembly id (`None` for the empty / no-assembly early returns).
    assembly: Option<&'a str>,
    /// The consulted datasets and, per dataset, whether it matched; empty for the early
    /// returns. Carries the outcome rather than bare ids so the audit line and the usage
    /// counters name the same set: two parallel lists could let a dataset be audited as
    /// scanned but counted as unconsulted.
    outcomes: &'a [DatasetOutcome],
    /// Effective pagination skip.
    skip: u64,
    /// Effective pagination limit.
    limit: u64,
    /// Handler entry instant, for `elapsed_us`.
    started: Instant,
}

/// Render a [`BeaconReject`] as a Beacon v2 `beaconErrorResponse`, naming the entry
/// type of the endpoint that rejected it in the error `meta`.
fn render_reject(cfg: &BeaconConfig, reject: &BeaconReject, entry_type: &str) -> Response {
    error_response_typed(cfg, reject.code, &reject.message, entry_type)
}

/// Render a `beaconErrorResponse` from an explicit status + message.
///
/// Used where a beacon-mount error has no entry context, such as the extractor rejections
/// below and the mount's body-limit 413 map. Those name the `genomicVariant` entry type,
/// the node's primary one. The entry-specific reject paths use [`error_response_typed`] via
/// [`render_reject`], as does the resilience-layer renderer in `crate::app`, which names the
/// mount's own entry type.
pub(crate) fn error_response(cfg: &BeaconConfig, code: u16, message: &str) -> Response {
    error_response_typed(cfg, code, message, "genomicVariant")
}

/// Render a `beaconErrorResponse` whose error `meta` names `entry_type` (one of
/// `genomicVariant` / `dataset` / `individual`). The `meta` is the same
/// fully-populated shape a success carries (built by `beacon::query::error_response_meta`).
pub(crate) fn error_response_typed(
    cfg: &BeaconConfig,
    code: u16,
    message: &str,
    entry_type: &str,
) -> Response {
    let status = StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let envelope = BeaconErrorResponse::new(
        error_response_meta(&to_beacon_params(cfg), entry_type),
        code,
        message.to_owned(),
    );
    (status, Json(envelope)).into_response()
}

/// A `404` for a path that matched no Beacon route: the same envelope, with an empty
/// `returnedSchemas`.
///
/// Separate from [`error_response_typed`] because the entry type is the difference. A
/// rejected-but-routed request (a `400`) was interpreted as some entity and should say
/// which; a route miss was interpreted as none. See
/// [`gdi_node_standalone_beacon::query::route_miss_response_meta`].
pub(crate) fn route_miss_response(cfg: &BeaconConfig, message: &str) -> Response {
    let envelope = BeaconErrorResponse::new(
        gdi_node_standalone_beacon::query::route_miss_response_meta(&to_beacon_params(cfg)),
        404,
        message.to_owned(),
    );
    (StatusCode::NOT_FOUND, Json(envelope)).into_response()
}

/// Map the service's `[beacon]` config into the beacon library's minimal
/// [`BeaconParams`] contract (the fields the query/request APIs read), so those APIs
/// never depend on the full service config shape.
///
/// An exhaustive struct literal, with no `..Default::default()`. A field added to
/// [`BeaconParams`] fails to compile here until it is wired, so the two layers cannot
/// drift. Do not add a `..` fallback; it would turn that compile error into a field that
/// quietly defaults.
fn to_beacon_params(c: &BeaconConfig) -> BeaconParams {
    BeaconParams {
        id: c.id.clone(),
        name: c.name.clone(),
        api_version: c.api_version.clone(),
        max_query_span_bp: c.max_query_span_bp,
        default_page_limit: c.default_page_limit,
        max_page_limit: c.max_page_limit,
        min_allele_count: c.min_allele_count,
        default_granularity: c.configuration.default_granularity.clone(),
    }
}

/// A JSON request-body extractor that renders a rejection (malformed body → 400, missing
/// or wrong `Content-Type` → 415) as a conformant `beaconErrorResponse` instead of axum's
/// default plain-text error. Semantic request validation happens later in
/// `beacon::request::parse_request`, which returns a `400`. This node never emits `422`: a
/// client-side query error is always a `400`, matching the reference Beacon
/// implementations, which reserve `422` for server-side invalid data.
///
/// This keeps every error a federated aggregator might parse in the same envelope as the
/// success, 413, 503 and 500 paths (see [`error_response`]). The handlers use it in place
/// of a bare `Json<Value>` on the POST surface.
pub(crate) struct BeaconJson(pub(crate) Value);

impl FromRequest<AppState> for BeaconJson {
    type Rejection = Response;

    async fn from_request(req: Request, state: &AppState) -> Result<Self, Self::Rejection> {
        match Json::<Value>::from_request(req, state).await {
            Ok(Json(body)) => Ok(Self(body)),
            Err(rejection) => Err(error_response(
                &state.config.beacon,
                rejection.status().as_u16(),
                "malformed or unsupported request body",
            )),
        }
    }
}

/// A GET query-string extractor that renders a malformed query string (bad
/// percent-encoding, non-UTF-8) as a conformant `beaconErrorResponse` instead of axum's
/// default plain-text `Query` rejection.
///
/// The GET mirror of [`BeaconJson`], keeping the GET error surface in the envelope a
/// federated aggregator parses on the POST path. The handlers' own semantic `400`s (from
/// [`render_reject`]) are returned as a `Response` and are untouched; only an
/// extractor-level rejection is re-rendered.
pub(crate) struct BeaconQuery(pub(crate) BTreeMap<String, String>);

impl FromRequestParts<AppState> for BeaconQuery {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        match Query::<BTreeMap<String, String>>::from_request_parts(parts, state).await {
            Ok(Query(map)) => Ok(Self(map)),
            Err(rejection) => Err(error_response(
                &state.config.beacon,
                rejection.status().as_u16(),
                "malformed query string",
            )),
        }
    }
}

/// Build the [`ParquetCaps`] for the query path from the `[service]` config, single-sourced
/// on
/// [`ServiceSection::parquet_caps`](gdi_node_standalone_core::config::ServiceSection::parquet_caps)
/// so the query and ingest paths cannot drift from each other or from the tool.
fn parquet_caps(cfg: &ServiceConfig) -> ParquetCaps {
    cfg.service.parquet_caps()
}

/// Read pagination from the request params: the nested `pagination.skip` and
/// `pagination.limit` envelope keys and the flat GET `skip` and `limit` keys, numeric or
/// numeric-string. Returns `(skip, limit)` as `Option<u64>` so [`apply_pagination`] can
/// default them.
fn read_pagination(params: &RequestParams) -> (Option<u64>, Option<u64>) {
    // A tolerant best-effort read, so a wide range query can page if asked. POST carries a
    // nested `pagination` object; GET carries flat `skip` / `limit` query-string keys as
    // JSON strings. Accept either, else a paginated GET is silently dropped.
    let pag = params.get("pagination").and_then(Value::as_object);
    let skip = pag
        .and_then(|p| p.get("skip"))
        .or_else(|| params.get("skip"))
        .and_then(value_as_u64);
    let limit = pag
        .and_then(|p| p.get("limit"))
        .or_else(|| params.get("limit"))
        .and_then(value_as_u64);
    (skip, limit)
}

/// Parse a JSON value as `u64`, accepting a JSON number or a numeric string (GET
/// query-string values arrive as strings).
fn value_as_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
}

/// Meter and audit a rejected query for `entry_type`, then render its 4xx
/// `beaconErrorResponse`. The shared body of the per-plane `reject_*` wrappers below: the
/// metric label, the audit `entry_type` and the error `meta` entry type all come from the
/// single `entry_type` argument, so the three planes cannot drift in how a reject is
/// recorded.
fn reject_query(
    state: &AppState,
    params: &RequestParams,
    started: Instant,
    reject: &BeaconReject,
    entry_type: &'static str,
) -> Response {
    crate::metrics::record_beacon_query_rejected(entry_type, reject.code);
    crate::audit::beacon_query_rejected(
        &state.config.audit,
        entry_type,
        reject.code,
        &reject.message,
        elapsed_us(started),
        Some(params),
    );
    render_reject(&state.config.beacon, reject, entry_type)
}

/// Emit the reject audit line for a `genomicVariant` query, then render the 4xx
/// `beaconErrorResponse`. Extracted so the reject match arms in [`run_g_variants`] stay one
/// line each.
fn reject_g_variants(
    state: &AppState,
    params: &RequestParams,
    started: Instant,
    reject: &BeaconReject,
) -> Response {
    reject_query(state, params, started, reject, "genomicVariant")
}

/// Audit and meter a rejected `individuals` query, then render the 4xx. The
/// individuals-plane mirror of [`reject_g_variants`].
fn reject_individuals(
    state: &AppState,
    params: &RequestParams,
    started: Instant,
    reject: &BeaconReject,
) -> Response {
    reject_query(state, params, started, reject, "individual")
}

/// Build and render the empty (no datasets matched) `g_variants` `200` response, auditing
/// it as an answered query. Reached from the empty-query early return in
/// [`run_g_variants`].
fn empty_g_variants(
    state: &AppState,
    params: &RequestParams,
    pagination: &Pagination,
    granularity: &str,
    include: IncludeResultsetResponses,
    started: Instant,
) -> Response {
    let response = assemble(
        Vec::new(),
        pagination,
        &to_beacon_params(&state.config.beacon),
        &state.config.service.base_url,
        granularity,
    );
    ok_response(
        state,
        params,
        response,
        include,
        granularity,
        &QueryAuditCtx {
            assembly: None,
            outcomes: &[],
            skip: pagination.skip,
            limit: pagination.limit,
            started,
        },
    )
}

/// The whole assembly policy for a `g_variants` query, in one place: pick the visible
/// datasets to search and report which assembly was searched.
///
/// `query_assembly` is the request's assembly after `normalize_assembly`, and `None` when
/// the request named none. A name resolving to neither `GRCh37` nor `GRCh38` never gets
/// here; `parse_request` already rejected it with `unknown assemblyId`. Returns the selected
/// datasets and the assembly actually applied, `None` only when nothing is visible, or a
/// `400`.
///
/// A dataset is only ever searched under its own assembly: every returned dataset's
/// `config.assembly.reference` equals the returned assembly, and no case below widens the
/// selection past that filter, so a cross-assembly false hit stays impossible.
///
/// An unresolvable `assemblyId` is a `400` from `parse_request` and never reaches here. The
/// cases decided here:
///
/// 1. Absent, one assembly served: assume it and search everything visible. The assumption
///    cannot produce a cross-assembly hit, because there is no other assembly to confuse it
///    with.
/// 2. Absent, several served: `400` saying the request is ambiguous and listing them.
///    Defaulting would have to pick one and silently drop the rest of the node.
/// 3. A recognised assembly with no matching dataset: an empty selection, answered `200`
///    `exists:false`. "I hold no data for that assembly" is the Beacon semantic for a miss,
///    and no dataset is searched.
/// 4. Nothing visible: an empty selection whatever was asked, with no assembly to report.
///    "I do not hold this variant" is true whatever was asked.
fn select_datasets_for_assembly(
    state: &AppState,
    query_assembly: Option<&str>,
) -> Result<(Vec<Arc<DatasetEntry>>, Option<String>), BeaconReject> {
    let visible = state.fresh_visible_datasets();
    let mut served: Vec<&str> = visible
        .iter()
        .map(|d| d.config.assembly.reference.as_str())
        .collect();
    served.sort_unstable();
    served.dedup();

    let assembly = match query_assembly {
        Some(a) => a.to_owned(),
        // Case 4 before case 2: an empty node has nothing to be ambiguous about.
        None => match served.as_slice() {
            [] => return Ok((Vec::new(), None)),
            [only] => (*only).to_owned(),
            several => {
                return Err(BeaconReject::bad_request(format!(
                    "assemblyId is ambiguous: this node serves several assemblies ({}); \
                     name one in requestParameters.assemblyId",
                    several.join(", ")
                )));
            }
        },
    };

    let selected: Vec<Arc<DatasetEntry>> = visible
        .iter()
        .filter(|d| d.config.assembly.reference.eq_ignore_ascii_case(&assembly))
        .map(Arc::clone)
        .collect();
    Ok((selected, Some(assembly)))
}

/// Selects the visible datasets whose assembly matches the query, scans each dataset's
/// parquet under [`tokio::task::spawn_blocking`], since the scan is blocking and CPU-bound,
/// and assembles the Beacon response. Returns the JSON `Response` on success or a rendered
/// `beaconErrorResponse` on an internal scan failure.
async fn run_g_variants(state: &AppState, params: RequestParams) -> Response {
    let started = Instant::now();
    let cfg = &state.config;
    let beacon_params = to_beacon_params(&cfg.beacon);
    let beacon_cfg = &beacon_params;

    // Reject a submitted `filters` selector: this aggregated beacon advertises no filtering
    // terms, so it cannot honour one, and silently ignoring it would return an unfiltered
    // result the caller believes was narrowed. The sensitive `individuals` placeholder
    // serves no data and does not reject; it is where real filter handling would land.
    if let Err(reject) = reject_unsupported_filters(&params) {
        return reject_g_variants(state, &params, started, &reject);
    }

    let normalized = match parse_request(&params, beacon_cfg) {
        Ok(q) => q,
        Err(reject) => return reject_g_variants(state, &params, started, &reject),
    };
    let kind = match classify(&normalized, beacon_cfg) {
        Ok(k) => k,
        Err(reject) => return reject_g_variants(state, &params, started, &reject),
    };

    // The envelope enum is already validated by `classify` (via `check_envelope`);
    // re-parse it to drive the MISS/NONE response shaping below.
    let include =
        parse_include_resultset_responses(&params).unwrap_or(IncludeResultsetResponses::Hit);

    let (skip, limit) = read_pagination(&params);
    let pagination = apply_pagination(skip, limit, beacon_cfg);

    // Echo the request's (case-folded) granularity in `meta.receivedRequestSummary`
    // (defaulted from `[beacon.configuration]` when omitted, by `parse_request`).
    let granularity = normalized.requested_granularity;

    // Empty query → 200 with empty resultSets (not an error).
    if matches!(kind, QueryKind::Empty) {
        return empty_g_variants(state, &params, &pagination, &granularity, include, started);
    }

    let chr = normalized.reference_name.clone();
    // The parquet caps, data dir and PME read context are derived inside each answer
    // helper rather than here, so the two paths cannot be handed different scan inputs.

    // Pick the visible datasets to search, and the assembly they are searched under; the
    // synonyms are already normalized into NormalizedQuery::assembly_id.
    // `select_datasets_for_assembly` owns the policy for an absent, foreign or unserved
    // assembly, and its reject goes through the audited helper, so this envelope-level 400
    // leaves the same audit and metric trail as the parse/classify rejects.
    let (selected, applied_assembly) =
        match select_datasets_for_assembly(state, normalized.assembly_id.as_deref()) {
            Ok(picked) => picked,
            Err(reject) => return reject_g_variants(state, &params, started, &reject),
        };
    // Echo an assembly the node chose, never one the client supplied (see
    // `ReceivedRequestSummary::assumed_assembly_id`).
    let assumed_assembly = if normalized.assembly_id.is_none() {
        applied_assembly.clone()
    } else {
        None
    };

    // Honour `datasetIds`: scope the scan to the requested datasets. Scanning every visible
    // dataset instead would let a dataset-scoped existence query return a hit from an
    // out-of-scope dataset, a false "variant V exists in dataset D" when V is only in some
    // other dataset. An absent list means all visible datasets, and a requested id that is
    // not currently visible contributes no resultSet. Applied after the assembly selection,
    // so it can only narrow it: a `datasetIds` naming a dataset of another assembly cannot
    // pull it into the scan.
    //
    // `None` (absent) and `Some(vec![])` (submitted but resolving to no id) differ. Testing
    // `is_empty()` on a bare `Vec` merges them, so `datasetIds: []` widens the query back to
    // every visible dataset, invisibly at `boolean` and `count`, where the per-dataset
    // resultSets are dropped and only the OR-ed `exists` reaches the client.
    let selected: Vec<Arc<DatasetEntry>> = match parse_dataset_ids(&params) {
        None => selected,
        Some(requested) => {
            let want: std::collections::HashSet<&str> =
                requested.iter().map(String::as_str).collect();
            selected
                .into_iter()
                .filter(|d| want.contains(d.id.as_str()))
                .collect()
        }
    };

    // Two answer paths, one tail. `boolean`/`count` never put resultSets on the wire
    // (`shape_for_granularity` drops the whole body), so they are answered by a streaming
    // fold that retains no rows: orders of magnitude less memory on a wide query, and no
    // population multiplier to make a small dataset expensive. `record` still materialises
    // and groups, because there the body is the answer. Both funnel through the same
    // `ok_response` so metrics, the audit line and granularity shaping cannot diverge.
    let answered = if matches!(granularity.as_str(), "boolean" | "count") {
        aggregate_g_variants_answer(state, selected, &kind, &chr, &pagination, &granularity).await
    } else {
        record_g_variants_answer(state, selected, &kind, &chr, &pagination, &granularity).await
    };
    let (mut response, outcomes) = match answered {
        Ok(answered) => answered,
        Err(rej) => return reject_scan(state, &params, started, &rej),
    };
    response.meta.received_request_summary.assumed_assembly_id = assumed_assembly;
    ok_response(
        state,
        &params,
        response,
        include,
        &granularity,
        &QueryAuditCtx {
            assembly: applied_assembly.as_deref(),
            outcomes: &outcomes,
            skip: pagination.skip,
            limit: pagination.limit,
            started,
        },
    )
}

/// Answer a `record` `g_variants` query: scan, materialise, group and page.
///
/// Returns the assembled response and the per-dataset outcomes: the scanned ids for the
/// audit line, each with whether it matched, for the usage counters.
async fn record_g_variants_answer(
    state: &AppState,
    selected: Vec<Arc<DatasetEntry>>,
    kind: &QueryKind,
    chr: &str,
    pagination: &Pagination,
    granularity: &str,
) -> Result<(BeaconResponse, Vec<DatasetOutcome>), ScanReject> {
    let cfg = &state.config;
    let beacon_params = to_beacon_params(&cfg.beacon);
    // `_budget_guard` holds this query's charge against the process-wide retained-row
    // budget. It must stay in scope until `assemble` below has consumed the rows: dropping
    // it earlier would credit the bytes back while they are still resident, the accounting
    // hole `max_total_query_bytes` exists to close.
    let datasets = selected.len();
    let decryptor = state.dataset_decryptor();
    let scan = scan_selected_datasets(
        selected,
        &cfg.service.data_dir,
        kind,
        chr,
        &decryptor,
        &beacon_params,
        pagination,
        ScanExec {
            caps: parquet_caps(cfg),
            concurrency: cfg.service.query_concurrency(),
            inflight: Arc::clone(&state.query_scan_blocking),
            max_query_bytes: cfg.service.max_query_bytes,
            budget: Arc::clone(&state.query_memory_budget),
        },
    );
    // The fan-out as one `beacon_scan` child of the request span, with the per-dataset
    // `scan_dataset` spans under it: the part of a Beacon request that costs anything.
    // `datasets` is a count, never a query field.
    let (mut scanned, _budget_guard) = tracing::Instrument::instrument(
        scan,
        tracing::info_span!("beacon_scan", mode = "record", datasets),
    )
    .await?;

    // Build the tuples `assemble` consumes, moving each scanned row vector out with
    // `mem::take` rather than cloning it; `assemble` takes the `Vec` by value. The
    // `&dataset.config` and `&dataset.metadata.populations` borrows keep `scanned` alive for
    // the call, and the populations ride through to each resultSet's `gdiDatasetInfo` so a
    // `0` is self-describing.
    let datasets: Vec<DatasetScan<'_>> = scanned
        .iter_mut()
        .map(|(id, dataset, rows)| {
            (
                id.clone(),
                &dataset.config,
                dataset.metadata.populations.as_deref(),
                chr,
                std::mem::take(rows),
            )
        })
        .collect();

    let response = assemble(
        datasets,
        pagination,
        &beacon_params,
        &cfg.service.base_url,
        granularity,
    );

    // Read the outcomes back out of the assembled response rather than re-deriving them
    // from `scanned`. `assemble` emits one resultSet per consulted dataset, a hit or an
    // `exists:false` miss, and that `exists` is the post-suppression truth: a dataset whose
    // every group fell below its `min_allele_count` floor scanned rows but matched nothing.
    // Recomputing "did it match" from the scanned rows would report a hit the client was
    // never shown. Read here, before `apply_include_resultset_responses` in `ok_response`
    // drops the misses from the wire.
    let outcomes = response.response.as_ref().map_or_else(Vec::new, |body| {
        body.result_sets
            .iter()
            .map(|rs| DatasetOutcome {
                id: rs.id.clone(),
                hit: rs.exists,
            })
            .collect()
    });
    Ok((response, outcomes))
}

/// A `g_variants` scan failure: the HTTP status, a path-free `reason` for the audit
/// line, and the generic `public` body for the rendered `beaconErrorResponse`.
/// Returned by [`scan_selected_datasets`] so [`run_g_variants`] audits the failed
/// query before rendering it.
#[derive(Debug)]
struct ScanReject {
    /// HTTP status (`400` query-too-broad, `500` internal scan failure, `503` shed).
    code: u16,
    /// Path-free audit reason (the actionable 400 detail, or the error class for 500).
    reason: String,
    /// The public `beaconErrorResponse` message.
    public: String,
}

impl ScanReject {
    /// A generic internal-scan-failure (`500`) reject; `reason` is the path-free audit
    /// detail (an error class, or a fixed cause); the public body stays generic.
    fn internal(reason: &str) -> Self {
        Self {
            code: 500,
            reason: reason.to_owned(),
            public: "internal error scanning a dataset".to_owned(),
        }
    }

    /// A query-too-broad (`400`) reject; `detail` is the path-free actionable message, used
    /// as both the public body and the audit reason. `400` rather than `413` because this is
    /// about query breadth, not request-payload size. It matches the pre-scan span cap
    /// (`request::check_span`) and keeps `413` for the body-size limit, whose mount-wide
    /// envelope rewrite would otherwise clobber this message.
    fn too_large(detail: String) -> Self {
        Self {
            code: 400,
            reason: detail.clone(),
            public: detail,
        }
    }

    /// An overloaded-scan-pool (`503`) reject: too many blocking scans are already
    /// occupying the shared pool, so this request is shed rather than piling on.
    fn scan_pool_saturated() -> Self {
        Self {
            code: 503,
            reason: "scan pool saturated".to_owned(),
            public: "service is busy; retry shortly".to_owned(),
        }
    }

    /// A process-wide-query-memory (`503`) reject: this query's rows would push the node
    /// past `max_total_query_bytes`, summed over everything already in flight.
    ///
    /// `503`, not the `400` its per-request sibling returns. The query is not too broad, and
    /// the same request would succeed on an idle node, so telling the caller to narrow it
    /// would be wrong. This is a capacity condition, the same answer the scan-pool shed and
    /// the load-shed layer give.
    fn query_budget_exhausted() -> Self {
        Self {
            code: 503,
            reason: "process-wide query memory budget exhausted".to_owned(),
            public: "service is busy; retry shortly".to_owned(),
        }
    }
}

/// Audit an in-scan `g_variants` failure ([`ScanReject`]) and render its
/// `beaconErrorResponse`. The post-scan-error mirror of [`reject_g_variants`], so a
/// query that reached the scan still leaves an audit trail when it 400s or 500s.
fn reject_scan(
    state: &AppState,
    params: &RequestParams,
    started: Instant,
    rej: &ScanReject,
) -> Response {
    crate::metrics::record_beacon_query_rejected("genomicVariant", rej.code);
    crate::audit::beacon_query_rejected(
        &state.config.audit,
        "genomicVariant",
        rej.code,
        &rej.reason,
        elapsed_us(started),
        Some(params),
    );
    error_response(&state.config.beacon, rej.code, &rej.public)
}

/// The execution knobs for a batch of per-dataset scans, grouped to keep
/// [`scan_selected_datasets`] within the argument limit: the parquet decode `caps`, the
/// fan-out `concurrency` cap, and the shared `inflight` counter (sampled into
/// `gdi_beacon_scan_blocking_inflight`).
struct ScanExec {
    caps: ParquetCaps,
    concurrency: usize,
    inflight: Arc<AtomicUsize>,
    /// Aggregate retained-row byte ceiling for the whole fan-out, from
    /// `[service].max_query_bytes`. No `Default` and a struct literal at every site, so a
    /// new caller cannot omit it.
    max_query_bytes: u64,
    /// The process-wide retained-row budget this request charges against, shared by every
    /// in-flight query. The per-request `max_query_bytes` above cannot bound the total.
    budget: Arc<QueryMemoryBudget>,
}

/// Process-wide accounting of retained scan-row bytes, summed across every `g_variants`
/// query in flight at once (`[service].max_total_query_bytes`).
///
/// `max_query_bytes` bounds one request. Without an aggregate bound the exposure would be
/// that ceiling multiplied by `max_concurrent_requests`, since every concurrent request
/// carries its own full allowance. This is what stops N cheap-to-issue broad queries from
/// summing to an OOM.
pub struct QueryMemoryBudget {
    limit: u64,
    used: AtomicU64,
}

impl QueryMemoryBudget {
    /// A budget admitting at most `limit` bytes of retained rows across all in-flight scans.
    #[must_use]
    pub fn new(limit: u64) -> Self {
        Self {
            limit,
            used: AtomicU64::new(0),
        }
    }

    /// Currently-charged bytes across all in-flight scans.
    ///
    /// There is no dedicated gauge: a shed increments
    /// `gdi_beacon_query_rejected_total{code="503"}` through the normal reject path, which
    /// is the signal an operator alerts on. This accessor backs the shed log line and the
    /// tests asserting the charge/release balance.
    #[must_use]
    pub fn used_bytes(&self) -> u64 {
        self.used.load(Ordering::Relaxed)
    }

    /// The configured ceiling (`[service].max_total_query_bytes`).
    #[must_use]
    pub fn limit_bytes(&self) -> u64 {
        self.limit
    }

    /// Charge `bytes` against the budget, or refuse if that would exceed the limit.
    ///
    /// A CAS loop rather than `fetch_add`-then-check: `fetch_add` would momentarily charge
    /// past the limit and, with several requests racing, each could observe an
    /// over-limit total and all back off. Here a refusal never mutates the counter.
    fn try_charge(&self, bytes: u64) -> bool {
        let mut current = self.used.load(Ordering::Relaxed);
        loop {
            let next = current.saturating_add(bytes);
            if next > self.limit {
                return false;
            }
            match self.used.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    /// Return `bytes` to the budget. Saturating, so an accounting slip can never wrap the
    /// counter into a huge value that would wedge the node into permanent shedding.
    fn release(&self, bytes: u64) {
        let mut current = self.used.load(Ordering::Relaxed);
        loop {
            let next = current.saturating_sub(bytes);
            match self.used.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(actual) => current = actual,
            }
        }
    }
}

/// One request's charge against the [`QueryMemoryBudget`], released on drop.
///
/// Drop covers every exit path the scan has: the `?` on a rejected debit, a panicking
/// blocking task, and a request cancelled by `TimeoutLayer` mid-fan-out all unwind through
/// here, so a shed request cannot leak its charge and ratchet the node toward permanent
/// 503s.
struct QueryMemoryGuard {
    budget: Arc<QueryMemoryBudget>,
    charged: u64,
}

impl QueryMemoryGuard {
    fn new(budget: Arc<QueryMemoryBudget>) -> Self {
        Self { budget, charged: 0 }
    }

    /// Charge `bytes` for this request, or shed (503) when the process-wide budget is full.
    fn charge(&mut self, bytes: u64) -> Result<(), ScanReject> {
        if !self.budget.try_charge(bytes) {
            tracing::warn!(
                requested = bytes,
                used = self.budget.used_bytes(),
                limit = self.budget.limit_bytes(),
                "process-wide query memory budget exhausted; shedding"
            );
            return Err(ScanReject::query_budget_exhausted());
        }
        self.charged = self.charged.saturating_add(bytes);
        Ok(())
    }

    /// Return `bytes` this request charged for a buffer it has now freed.
    ///
    /// Clamped to what this guard holds, so a miscounted credit can only release this
    /// request's own charge, never another in-flight request's. `self.charged` stays the
    /// exact amount `Drop` must still return.
    fn release(&mut self, bytes: u64) {
        let credit = bytes.min(self.charged);
        self.charged -= credit;
        self.budget.release(credit);
    }
}

/// A [`QueryMemoryGuard`] shared across the concurrent scans of one request.
///
/// The charge must outlive the task that made it, because the rows travel back to the
/// fan-out and stay resident until the response is assembled, so a per-task guard would
/// credit the budget back while its memory is still held. One guard behind a mutex, cloned
/// into each task, ties release to the request's lifetime while letting every scan charge as
/// it accumulates. Contention is negligible: one lock per file read, never across an
/// `.await`.
#[derive(Clone)]
struct SharedRetention(Arc<std::sync::Mutex<QueryMemoryGuard>>);

impl gdi_node_standalone_beacon::query::RetentionSink for SharedRetention {
    fn charge(
        &mut self,
        bytes: u64,
    ) -> Result<(), gdi_node_standalone_beacon::query::RetentionRejected> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .charge(bytes)
            .map_err(|_| gdi_node_standalone_beacon::query::RetentionRejected {
                detail: "process-wide beacon query memory budget is full".to_owned(),
            })
    }

    fn release(&mut self, bytes: u64) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .release(bytes);
    }

    /// Publish the split-block shape: the scan is about to hold a whole block, which an
    /// operator could otherwise learn only by listing the store's parquet files.
    fn note_merged_block(&mut self, files: usize) {
        crate::metrics::beacon_merged_block(files);
    }
}

impl Drop for QueryMemoryGuard {
    fn drop(&mut self) {
        self.budget.release(self.charged);
    }
}

/// Increments the running-scan counter on construction and decrements it on drop. It lives
/// inside the `spawn_blocking` scan closure, so a scan detached by a request timeout stays
/// counted until it finishes; `spawn_blocking` cannot be cancelled mid-run. The read-path
/// sibling of ingest's `BlockingGuard`; its counter is sampled into the
/// `gdi_beacon_scan_blocking_inflight` gauge.
struct ScanBlockingGuard(Arc<AtomicUsize>);

impl ScanBlockingGuard {
    fn new(counter: Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self(counter)
    }
}

impl Drop for ScanBlockingGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The `(id, entry, rows)` tuples [`assemble`] consumes, one per scanned dataset.
type ScannedDatasets = Vec<(String, Arc<DatasetEntry>, DatasetPage)>;

/// How many times the per-request scan window a node may run globally before shedding.
/// Healthy concurrent traffic sits far below this; only scans detached by request timeouts,
/// which `spawn_blocking` cannot cancel, accumulate toward it.
const SCAN_POOL_MULTIPLIER: usize = 4;

/// Slack above [`SCAN_POOL_MULTIPLIER`] so a brief burst is absorbed rather than shed.
/// Mirrors `ingest_runtime`'s `DETACHED_HEADROOM`.
const SCAN_DETACHED_HEADROOM: usize = 16;

/// The number of concurrent blocking scans the pool admits for a given per-query fan-out
/// cap.
///
/// Exposed so the boot advisory can derive the transient parquet decode working set a
/// saturated pool holds, `scan_pool_cap x max_parquet_row_group_bytes`. That sits on top of
/// `max_total_query_bytes`, because the retention sink never charges it. Deriving it here
/// rather than restating the arithmetic at the advisory keeps the two from drifting.
///
/// It is not `scan_pool_cap x max_query_bytes`: retained rows are charged as they accumulate
/// and shed with a 503 from inside the scan, so that product is unreachable.
#[must_use]
pub fn scan_pool_cap(cap: usize) -> usize {
    cap.saturating_mul(SCAN_POOL_MULTIPLIER)
        .saturating_add(SCAN_DETACHED_HEADROOM)
}

/// Shed (503) when the shared blocking pool is already saturated by in-flight and detached
/// scans, so a new fan-out cannot deepen it. `TimeoutLayer` sits outside
/// `ConcurrencyLimitLayer`, so a timed-out request releases its permit while its
/// `spawn_blocking` scans keep running, and nothing else bounds their sum toward tokio's
/// blocking-pool ceiling. Sized as a mirror of the ingest pool, well above healthy
/// concurrent traffic, so only detached buildup trips it. 503 is the same answer the
/// load-shed layer gives.
///
/// # Errors
///
/// [`ScanReject`] with a 503 when the pool is already at [`scan_pool_cap`].
fn reject_if_scan_pool_saturated(inflight: &AtomicUsize, cap: usize) -> Result<(), ScanReject> {
    let pool_cap = scan_pool_cap(cap);
    let running = inflight.load(Ordering::Relaxed);
    if running >= pool_cap {
        tracing::warn!(
            running,
            pool_cap,
            "beacon scan pool saturated (detached scans included); shedding"
        );
        return Err(ScanReject::scan_pool_saturated());
    }
    Ok(())
}

/// Add a completed scan's retained-row weight to the per-request aggregate ceiling
/// (`max_query_bytes`, a 400 too-broad) across the datasets of one fan-out.
///
/// This is not the process-wide budget, and not the only place a byte ceiling is enforced:
/// the scans charge `max_total_query_bytes` through their `RetentionSink` as they
/// accumulate, which makes that ceiling a bound rather than a report. What this adds is the
/// cross-dataset sum, which no single scan can see, since each one knows only its own rows.
///
/// There is no second charge here to order against: the 503 shed happens inside the scan,
/// before these rows exist, so a genuinely too-broad query still gets its 400 from this
/// check.
fn debit_retained_bytes(
    retained: &mut u64,
    weight: u64,
    max_query_bytes: u64,
) -> Result<(), ScanReject> {
    *retained = retained.saturating_add(weight);
    if *retained > max_query_bytes {
        return Err(ScanReject::too_large(format!(
            "query retained more than {max_query_bytes} bytes of matching rows across the \
             selected datasets; narrow the position range or query fewer datasets"
        )));
    }
    Ok(())
}

/// Scan the selected datasets off the async executor into the `(id, entry, rows)`
/// tuples [`assemble`] consumes, running up to `concurrency` per-dataset blocking
/// scans at once.
///
/// Scans are dispatched through a rolling [`JoinSet`] window of `spawn_blocking` tasks,
/// capped at `concurrency`. The window is kept full by launching the next queued dataset as
/// soon as one finishes, so the blocking pool never idles waiting out a batch's slowest
/// scan, while the cap keeps a pathological dataset count from flooding it. Completion order
/// is nondeterministic, so the collected outcomes are sorted by dataset id before
/// classification and assembly, making both the resultSet order and which dataset a scan
/// error reports deterministic.
///
/// Returns a [`ScanReject`] on a scan failure or a non-completing (panicked) blocking task,
/// the first error by id winning. The real cause is logged first, inside the request span so
/// it carries `span.request_id`, while the public body stays generic; the caller renders the
/// response and emits the reject audit line.
#[expect(
    clippy::too_many_arguments,
    reason = "the scan applies the request's floor and page window itself; folding these into \
              a struct would hide what a new call site must supply"
)]
async fn scan_selected_datasets(
    selected: Vec<Arc<DatasetEntry>>,
    data_dir: &std::path::Path,
    kind: &QueryKind,
    chr: &str,
    decryptor: &gdi_node_standalone_core::parquet_io::DatasetDecryptor,
    beacon_params: &gdi_node_standalone_beacon::BeaconParams,
    pagination: &Pagination,
    exec: ScanExec,
) -> Result<(ScannedDatasets, Arc<std::sync::Mutex<QueryMemoryGuard>>), ScanReject> {
    type ScanOutcome = (
        Arc<DatasetEntry>,
        gdi_node_standalone_core::error::CoreResult<DatasetPage>,
    );

    let ScanExec {
        caps,
        concurrency,
        inflight,
        max_query_bytes,
        budget,
    } = exec;
    // Returned to the caller with the rows: the charge must stay held until the rows are
    // dropped, after `assemble`, not released when this function returns.
    let budget_guard = Arc::new(std::sync::Mutex::new(QueryMemoryGuard::new(budget)));
    let cap = concurrency.max(1);
    reject_if_scan_pool_saturated(&inflight, cap)?;

    let total = selected.len();
    let mut iter = selected.into_iter();
    let mut outcomes: Vec<ScanOutcome> = Vec::with_capacity(total);
    let mut set: JoinSet<ScanOutcome> = JoinSet::new();

    // Spawn one blocking scan for `dataset` into `set`. Each task returns its
    // `DatasetEntry` alongside the scan result so the caller can re-associate and sort by
    // id. `caps` is `Copy`; `kind`, `chr` and `decryptor` are cloned per task.
    let spawn_scan = |set: &mut JoinSet<ScanOutcome>, dataset: Arc<DatasetEntry>| {
        let dataset_dir = data_dir.join(&dataset.id);
        let block_range = dataset.config.block_range;
        // The floor and the page window are decided here, so the scan can drop everything
        // outside them instead of handing the whole match set to `assemble`. Only the three
        // resulting integers cross into the blocking closure.
        let page = PageSpec {
            floor: effective_floor(&dataset.config, beacon_params),
            skip: pagination.skip,
            limit: pagination.limit,
        };
        let kind = kind.clone();
        let chr = chr.to_owned();
        let decryptor = decryptor.clone();
        let scan_blocking = Arc::clone(&inflight);
        let mut sink = SharedRetention(Arc::clone(&budget_guard));
        // One child span per dataset scan, minted here and entered on the pool thread,
        // since `spawn_blocking` carries no span. The trace then shows which dataset took
        // how long instead of one flat `http_request` span. `dataset` is the same
        // administrative id the `ingest_job` span carries.
        let scan_span = tracing::info_span!("scan_dataset", dataset = %dataset.id);
        set.spawn_blocking(move || {
            let _scan_span = scan_span.entered();
            // Count this scan while it occupies a pool thread. The guard is constructed
            // inside the closure so a scan whose request has already timed out stays counted
            // until it truly finishes, and is decremented on the normal path or a panic
            // unwind.
            let _scan_guard = ScanBlockingGuard::new(scan_blocking);
            // The per-dataset byte ceiling. `max_query_bytes` is the per-request aggregate;
            // passing it here also fails one dataset closed mid-file, so a lowered ceiling
            // is enforced during the scan instead of after the whole match set is on the
            // heap. The cross-dataset sum is still enforced by `debit_retained_bytes` below.
            let page = scan_dataset_page(
                &dataset_dir,
                &chr,
                block_range,
                &kind,
                &caps,
                &decryptor,
                max_query_bytes,
                page,
                &mut sink,
            );
            (dataset, page)
        });
    };

    // Rolling window: keep up to `cap` blocking scans in flight at once. Prime the window,
    // then launch the next queued dataset the moment one finishes, so the blocking pool
    // never idles waiting out a batch's slowest task while `cap` still bounds concurrency.
    for _ in 0..cap {
        let Some(dataset) = iter.next() else { break };
        spawn_scan(&mut set, dataset);
    }
    // Aggregate retained-row bytes across every completed dataset: the per-dataset
    // `max_query_rows` cap bounds one dataset, but `outcomes` holds every dataset's rows at
    // once, and a long-allele row is ~20 KB not ~100 B. `debit_retained_bytes` fails closed
    // with a 400 too-broad once the request's retained set exceeds the ceiling, so neither
    // many datasets nor heavy alleles can drive the process to OOM.
    let mut retained_bytes: u64 = 0;
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok(outcome) => {
                if let Ok(page) = &outcome.1
                    && let Err(reject) = debit_retained_bytes(
                        &mut retained_bytes,
                        page.retained_bytes(),
                        max_query_bytes,
                    )
                {
                    set.abort_all();
                    return Err(reject);
                }
                outcomes.push(outcome);
                if let Some(dataset) = iter.next() {
                    spawn_scan(&mut set, dataset);
                }
            }
            Err(join) => {
                set.abort_all();
                tracing::warn!(
                    panicked = join.is_panic(),
                    "g_variants scan task did not complete; returning 500"
                );
                return Err(ScanReject::internal("scan task did not complete"));
            }
        }
    }

    let scanned = classify_scan_outcomes(outcomes)?;
    Ok((scanned, budget_guard))
}

/// Answer a `boolean`/`count` `g_variants` query without retaining rows.
///
/// Rederives the scan inputs from `state` rather than taking them as parameters, so the
/// argument list stays short and cannot drift from what the record path uses.
///
/// The returned outcomes name the datasets that were actually scanned, so a dataset deleted
/// mid-scan is absent here exactly as it is absent from the record path's resultSets. That
/// makes the audit line's `dataset_ids`, and the `consulted` counter built from the same
/// list, mean one thing at every granularity.
async fn aggregate_g_variants_answer(
    state: &AppState,
    selected: Vec<Arc<DatasetEntry>>,
    kind: &QueryKind,
    chr: &str,
    pagination: &Pagination,
    granularity: &str,
) -> Result<(BeaconResponse, Vec<DatasetOutcome>), ScanReject> {
    let cfg = &state.config;
    let beacon_params = to_beacon_params(&cfg.beacon);
    let datasets = selected.len();
    let decryptor = state.dataset_decryptor();
    let scan = scan_selected_dataset_counts(
        selected,
        &cfg.service.data_dir,
        kind,
        chr,
        &decryptor,
        ScanExec {
            caps: parquet_caps(cfg),
            concurrency: cfg.service.query_concurrency(),
            inflight: Arc::clone(&state.query_scan_blocking),
            max_query_bytes: cfg.service.max_query_bytes,
            budget: Arc::clone(&state.query_memory_budget),
        },
        &beacon_params,
    );
    // Same `beacon_scan` parent as the record path (see `record_g_variants_answer`).
    let (totals, outcomes) = tracing::Instrument::instrument(
        scan,
        tracing::info_span!("beacon_scan", mode = "aggregate", datasets),
    )
    .await?;
    Ok((
        assemble_counts(totals, pagination, &beacon_params, granularity),
        outcomes,
    ))
}

/// Scan the selected datasets for a `boolean`/`count` answer, folding each dataset's rows
/// into `(exists, surviving)` as they stream instead of retaining them.
///
/// The concurrency machinery mirrors [`scan_selected_datasets`]: the same rolling `JoinSet`
/// window, the same `ScanBlockingGuard` accounting, the same scan-pool shed, so the two
/// paths cannot diverge in how they load the blocking pool. What differs is what is
/// retained. This path returns folded counts, not rows, so the only thing it holds is the
/// per-block merge buffer a multi-file block needs, charged and credited back inside
/// [`scan_dataset_counts`] against the same per-request guard the record path uses.
async fn scan_selected_dataset_counts(
    selected: Vec<Arc<DatasetEntry>>,
    data_dir: &std::path::Path,
    kind: &QueryKind,
    chr: &str,
    decryptor: &gdi_node_standalone_core::parquet_io::DatasetDecryptor,
    exec: ScanExec,
    beacon_cfg: &BeaconParams,
) -> Result<(DatasetCounts, Vec<DatasetOutcome>), ScanReject> {
    type CountOutcome = (
        Arc<DatasetEntry>,
        gdi_node_standalone_core::error::CoreResult<DatasetCounts>,
    );

    // The aggregate path returns folded counts, not rows, so there is nothing here to weigh
    // after the fact the way the record path weighs its returned `Vec<AlleleRow>`. The
    // retention it does perform, the multi-file block merge buffer, is charged inside
    // `scan_dataset_counts` as the buffer fills and credited back as the fold consumes it,
    // against both the per-dataset `max_query_bytes` and the process-wide pool below.
    //
    // The per-dataset budget is cumulative across the files of a block, since re-arming it
    // per file would let an F-file block hold F x the ceiling. The process-wide charge is
    // held by `agg_budget` for the whole request, so concurrent aggregate queries shed each
    // other exactly as concurrent record queries do.
    let ScanExec {
        caps,
        concurrency,
        inflight,
        max_query_bytes,
        budget,
    } = exec;
    // One guard per request, shared by its concurrent scans, the same shape the record path
    // uses. Held until this function returns, when every folded count is in hand, so a
    // scan's charge is released only when its rows are genuinely gone.
    let agg_budget = Arc::new(std::sync::Mutex::new(QueryMemoryGuard::new(budget)));
    let cap = concurrency.max(1);
    reject_if_scan_pool_saturated(&inflight, cap)?;

    let total = selected.len();
    let mut iter = selected.into_iter();
    let mut outcomes: Vec<CountOutcome> = Vec::with_capacity(total);
    let mut set: JoinSet<CountOutcome> = JoinSet::new();

    let spawn_scan = |set: &mut JoinSet<CountOutcome>, dataset: Arc<DatasetEntry>| {
        let dataset_dir = data_dir.join(&dataset.id);
        let block_range = dataset.config.block_range;
        // The floor the record path applies for this dataset, from the same
        // `effective_floor` source, so a suppressed cell is suppressed identically whether
        // the client asked for `record` or `boolean`.
        let floor = effective_floor(&dataset.config, beacon_cfg);
        let kind = kind.clone();
        let chr = chr.to_owned();
        let decryptor = decryptor.clone();
        let scan_blocking = Arc::clone(&inflight);
        let mut sink = SharedRetention(Arc::clone(&agg_budget));
        // Same per-dataset child span as the record path (see `scan_selected_datasets`).
        let scan_span = tracing::info_span!("scan_dataset", dataset = %dataset.id);
        set.spawn_blocking(move || {
            let _scan_span = scan_span.entered();
            let _scan_guard = ScanBlockingGuard::new(scan_blocking);
            let counts = scan_dataset_counts(
                &dataset_dir,
                &chr,
                block_range,
                &kind,
                &caps,
                &decryptor,
                AggregateScan {
                    sink: &mut sink,
                    max_query_bytes,
                    floor,
                },
            );
            (dataset, counts)
        });
    };

    for _ in 0..cap {
        let Some(dataset) = iter.next() else { break };
        spawn_scan(&mut set, dataset);
    }
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok(outcome) => {
                outcomes.push(outcome);
                if let Some(dataset) = iter.next() {
                    spawn_scan(&mut set, dataset);
                }
            }
            Err(join) => {
                set.abort_all();
                tracing::warn!(
                    panicked = join.is_panic(),
                    "g_variants count scan task did not complete; returning 500"
                );
                return Err(ScanReject::internal("scan task did not complete"));
            }
        }
    }

    sum_count_outcomes(outcomes)
}

/// Sum the per-dataset folded counts, applying the same error classification the record
/// path uses: a dataset that vanished mid-scan is skipped, a too-broad query still 400s,
/// anything else is a 500.
///
/// Returns the summed totals and each dataset's own outcome. The per-dataset `exists` is
/// otherwise folded away here and never reaches the wire at this granularity, where only the
/// OR-ed answer does, so this is the single place it can be observed. That is why the `hit`
/// counter is threaded out from here rather than reconstructed from the response.
///
/// The outcomes are sorted by dataset id: completion order is not deterministic, and this
/// list is also what the audit line's `dataset_ids` is built from.
fn sum_count_outcomes(
    outcomes: Vec<(
        Arc<DatasetEntry>,
        gdi_node_standalone_core::error::CoreResult<DatasetCounts>,
    )>,
) -> Result<(DatasetCounts, Vec<DatasetOutcome>), ScanReject> {
    let mut totals = DatasetCounts {
        exists: false,
        surviving: 0,
    };
    let mut per_dataset: Vec<DatasetOutcome> = Vec::with_capacity(outcomes.len());
    for (dataset, counts) in outcomes {
        match counts {
            Ok(c) => {
                totals.exists |= c.exists;
                totals.surviving = totals.surviving.saturating_add(c.surviving);
                per_dataset.push(DatasetOutcome {
                    id: dataset.id.clone(),
                    hit: c.exists,
                });
            }
            Err(e) => {
                if e.is_not_found() {
                    tracing::info!(
                        dataset = %dataset.id,
                        "dataset removed mid-scan; skipping (no rows)"
                    );
                    continue;
                }
                if e.class() == ErrorClass::QueryTooLarge {
                    tracing::info!(
                        dataset = %dataset.id,
                        "g_variants query too broad; returning 400"
                    );
                    return Err(ScanReject::too_large(e.to_string()));
                }
                // A retention refusal is backpressure, not a fault: the node is healthy and
                // the request is well-formed, there is no memory budget right now.
                // `docs/api.md` and `ErrorClass::ResourceExhausted` both promise 503, and a
                // client cannot tell "retry shortly" from "this node is broken" on a 500.
                if e.class() == ErrorClass::ResourceExhausted {
                    tracing::info!(
                        dataset = %dataset.id,
                        "beacon query memory budget exhausted; returning 503"
                    );
                    return Err(ScanReject::query_budget_exhausted());
                }
                tracing::warn!(
                    dataset = %dataset.id,
                    error_class = %e.class().as_str(),
                    error = %e,
                    "g_variants count scan failed; returning 500"
                );
                return Err(ScanReject::internal(e.class().as_str()));
            }
        }
    }
    // Deterministic order regardless of completion order, the same normalization
    // `classify_scan_outcomes` applies on the record path.
    per_dataset.sort_by(|a, b| a.id.cmp(&b.id));
    Ok((totals, per_dataset))
}

/// Turn the completed per-dataset scan outcomes into the `(id, entry, rows)` tuples
/// [`assemble`] consumes, sorting by dataset id first so both the resultSet order and which
/// dataset a scan error reports are deterministic; completion order is not.
fn classify_scan_outcomes(
    mut outcomes: Vec<(
        Arc<DatasetEntry>,
        gdi_node_standalone_core::error::CoreResult<DatasetPage>,
    )>,
) -> Result<ScannedDatasets, ScanReject> {
    // Deterministic order regardless of completion order.
    outcomes.sort_by(|a, b| a.0.id.cmp(&b.0.id));

    let mut scanned: ScannedDatasets = Vec::with_capacity(outcomes.len());
    for (dataset, rows) in outcomes {
        let rows = match rows {
            Ok(rows) => rows,
            Err(e) => {
                // The dataset directory vanished mid-scan, a concurrent delete or reconcile
                // eviction of a dataset that was in the visible snapshot: skip it and
                // contribute no rows rather than failing the whole query with a 500. It is
                // genuinely gone, never a hidden dataset, so this is privacy-neutral, and
                // the next request's snapshot already excludes it.
                if e.is_not_found() {
                    tracing::info!(
                        dataset = %dataset.id,
                        "dataset removed mid-scan; skipping (no rows)"
                    );
                    continue;
                }
                // A query matching more than `max_query_rows` is a client error, a
                // too-broad range, so 400 with the actionable path-free detail forwarded;
                // any other scan failure is a server fault, so 500 with a generic message.
                if e.class() == ErrorClass::QueryTooLarge {
                    tracing::info!(
                        dataset = %dataset.id,
                        "g_variants query too broad; returning 400"
                    );
                    return Err(ScanReject::too_large(e.to_string()));
                }
                // The sibling of the arm in `sum_count_outcomes`. Both paths raise
                // `ResourceExhausted` from the same shared `RetentionSink`, so both map it
                // to backpressure rather than to an internal error.
                if e.class() == ErrorClass::ResourceExhausted {
                    tracing::info!(
                        dataset = %dataset.id,
                        "beacon query memory budget exhausted; returning 503"
                    );
                    return Err(ScanReject::query_budget_exhausted());
                }
                tracing::warn!(
                    dataset = %dataset.id,
                    error_class = %e.class().as_str(),
                    error = %e,
                    "g_variants scan failed; returning 500"
                );
                return Err(ScanReject::internal(e.class().as_str()));
            }
        };
        scanned.push((dataset.id.clone(), dataset, rows));
    }
    Ok(scanned)
}

/// Render an assembled [`BeaconResponse`] as a `200`, honouring the request's
/// `requestedGranularity` as a disclosure ceiling and, at `record` granularity, the
/// `includeResultsetResponses` MISS/NONE shaping.
///
/// `boolean`/`count` requests are downgraded via [`shape_for_granularity`] (the
/// per-population `frequencyInPopulations` body is dropped, and `boolean` also
/// withholds the count), so they do not carry the full record-level payload.
/// `includeResultsetResponses` only applies to the `record` body, so it is a no-op
/// for the downgraded shapes.
fn ok_response(
    state: &AppState,
    params: &RequestParams,
    mut response: BeaconResponse,
    include: IncludeResultsetResponses,
    granularity: &str,
    ctx: &QueryAuditCtx<'_>,
) -> Response {
    // Echo the submitted `requestedSchemas`, the validated `testMode` and the applied
    // `includeResultsetResponses` into
    // `receivedRequestSummary` (Beacon v2 transparency). One place covers every g_variants
    // path — empty, no-assembly, and the full scan all funnel through here. Not `filters`:
    // a non-empty one is a 400 upstream, so nothing legitimate reaches here to echo, and
    // `echo_received_request` discards them.
    echo_received_request(&mut response.meta, params);
    crate::metrics::record_beacon_query(
        "genomicVariant",
        granularity,
        response.response_summary.exists,
    );
    // The usage counters (`consulted` / `hit`), recorded from the same outcomes the audit
    // line below names. Both granularity paths funnel through here, so neither the counters
    // nor the audit can be right at one granularity and wrong at the other. A no-op unless
    // `[stats].enabled`. Synchronous, so its lock cannot be held across an `.await`.
    state.query_stats.record_query(ctx.outcomes);
    let dataset_ids: Vec<String> = ctx.outcomes.iter().map(|o| o.id.clone()).collect();
    // Audit the answered query. The true result (exists + count) is recorded here, read
    // before `shape_for_granularity` may drop the count from the wire at `boolean`
    // granularity, so the audit trail reflects what was found rather than what was
    // disclosed.
    crate::audit::beacon_query(
        &state.config.audit,
        &BeaconQueryAudit {
            entry_type: "genomicVariant",
            granularity,
            // Interpret testMode with the same bool-or-string parser the envelope
            // validation uses, so the audit does not misreport a GET `?testMode=…`.
            test_mode: gdi_node_standalone_beacon::request::testmode_flag(params.get("testMode"))
                .ok()
                .flatten()
                .unwrap_or(false),
            exists: response.response_summary.exists,
            num_results: response.response_summary.num_total_results.unwrap_or(0),
            assembly: ctx.assembly,
            dataset_ids: &dataset_ids,
            skip: ctx.skip,
            limit: ctx.limit,
            include: params
                .get("includeResultsetResponses")
                .and_then(Value::as_str),
            elapsed_us: elapsed_us(ctx.started),
            params: Some(params),
        },
    );
    let shaped = match granularity {
        "boolean" | "count" => shape_for_granularity(response, granularity),
        _ => apply_include_resultset_responses(response, include),
    };
    (StatusCode::OK, Json(shaped)).into_response()
}

/// `POST {prefix}/g_variants` — read the `query` envelope (merging its
/// `requestParameters` with the `query.*` siblings) and run the query.
pub(crate) async fn g_variants_post(
    State(state): State<AppState>,
    BeaconJson(body): BeaconJson,
) -> Response {
    if let Err(reject) = reject_malformed_envelope(&body) {
        let started = Instant::now();
        let params = request_params_from_body(&body);
        return reject_g_variants(&state, &params, started, &reject);
    }
    let params = request_params_from_body(&body);
    run_g_variants(&state, params).await
}

/// Reject an obviously-malformed request envelope (`400`) rather than parsing it
/// leniently into a misleading empty-query `200`.
///
/// Two shapes are rejected: a bare top-level `requestParameters` with no `query`
/// wrapper (the spec nests it under `query`), and a non-null `query` that is present but not
/// an object (a `null` `query` is treated as empty). A genuinely empty query stays a valid
/// `200` — `{}`, `{"query":{}}` and `{"query":{"requestParameters":{}}}` all qualify — as
/// does a body the lenient JSON parse cannot map at all.
///
/// # Errors
///
/// Returns a `400` [`BeaconReject`] for the two misplaced-envelope shapes above.
fn reject_malformed_envelope(body: &Value) -> Result<(), BeaconReject> {
    if let Some(obj) = body.as_object() {
        if obj.contains_key("requestParameters") && !obj.contains_key("query") {
            return Err(BeaconReject::bad_request(
                "requestParameters must be nested under `query`",
            ));
        }
        if let Some(q) = obj.get("query")
            && !q.is_object()
            && !q.is_null()
        {
            return Err(BeaconReject::bad_request("`query` must be an object"));
        }
        // The field this guard exists to protect. Without this arm a non-object value
        // survives, `as_object()` yields None, the params map comes out empty, and the
        // handler answers 200 `exists:false`, reporting "I do not hold this variant" for a
        // variant the node may hold, which a federated aggregator then records.
        // Absent and explicitly-null stay lenient: an empty query is a legitimate 200.
        if let Some(rp) = obj.get("query").and_then(|q| q.get("requestParameters"))
            && !rp.is_object()
            && !rp.is_null()
        {
            return Err(BeaconReject::bad_request(
                "`query.requestParameters` must be an object",
            ));
        }
    }
    Ok(())
}

/// `GET {prefix}/g_variants` — read the query string into the same params map.
pub(crate) async fn g_variants_get(
    State(state): State<AppState>,
    BeaconQuery(params): BeaconQuery,
) -> Response {
    let params = request_params_from_query(&params);
    run_g_variants(&state, params).await
}

/// Flatten a Beacon v2 POST `query` into the single params map the handlers read.
///
/// Clients send `{"query": {"requestParameters": {...}, ...}}`. The GA4GH variant
/// parameters live in `query.requestParameters`, but the Beacon v2 request envelope
/// fields (`includeResultsetResponses`, `requestedGranularity`,
/// `testMode`, `pagination`, `filters`) are siblings of `requestParameters` under `query`,
/// which is where the reference client (`BeaconRequestQuery`) and the framework schema place
/// them. This merges both into one flat map so envelope validation and handling, such as
/// rejecting `testMode:true` and honouring `includeResultsetResponses`, granularity and
/// pagination, sees them.
///
/// A body that omits the nesting (a bare `requestParameters`, or an empty body) is
/// handled leniently: missing → an empty map (an empty query → 200 empty results).
/// A sibling overrides a same-named key nested inside `requestParameters` (the
/// sibling is the canonical location); a client that only nests still works.
fn request_params_from_body(body: &Value) -> RequestParams {
    let query = body.get("query");
    // Base: the GA4GH variant parameters.
    let mut map = query
        .and_then(|q| q.get("requestParameters"))
        .or_else(|| body.get("requestParameters"))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    // Overlay the envelope fields from `query.*` (the canonical location).
    if let Some(q) = query.and_then(Value::as_object) {
        for key in [
            "includeResultsetResponses",
            "requestedGranularity",
            "testMode",
            "pagination",
            "filters",
            "requestedSchemas",
            "datasetIds",
        ] {
            if let Some(value) = q.get(key) {
                map.insert((*key).to_owned(), value.clone());
            }
        }
    }
    // A `filters` selector at the top level, a sibling of `query` rather than inside it, is
    // non-conformant, but `reject_unsupported_filters` must still reject it rather than
    // ignore it, or a client believes a filter narrowed the result when it did not. Fall
    // back to a top-level `filters` when the canonical `query.filters` is absent.
    if !map.contains_key("filters")
        && let Some(f) = body.get("filters")
    {
        map.insert("filters".to_owned(), f.clone());
    }
    map
}

/// Map GET query-string pairs into a [`RequestParams`] map.
///
/// Scalar values are kept as JSON strings — `parse_request` already accepts a
/// comma-separated string for `start`/`end` and folds string scalars, so the GET
/// surface behaves the same as POST without bespoke per-key coercion.
fn request_params_from_query(params: &BTreeMap<String, String>) -> RequestParams {
    let mut map = Map::new();
    for (k, v) in params {
        map.insert(k.clone(), Value::String(v.clone()));
    }
    map
}

/// Audit + meter a rejected `datasets` query, then render the 4xx. The datasets-plane
/// mirror of [`reject_g_variants`] / [`reject_individuals`].
fn reject_datasets(
    state: &AppState,
    params: &RequestParams,
    started: Instant,
    reject: &BeaconReject,
) -> Response {
    reject_query(state, params, started, reject, "dataset")
}

/// Execute a `datasets` query: render the visible datasets as a
/// `beaconCollectionsResponse`.
///
/// One `collections[]` entry per visible dataset (the cache's
/// `visible_datasets()` already excludes hidden / error / processing), paged by the
/// requested `skip` / `limit` under the same `[beacon]` bound as `g_variants`. The
/// true visible count is reported in `responseSummary.numTotalResults` regardless of
/// paging.
fn run_datasets(
    state: &AppState,
    skip: Option<u64>,
    limit: Option<u64>,
    params: Option<&RequestParams>,
) -> Response {
    let started = Instant::now();
    // Reject a submitted `filters` selector or an unsupported variant selector
    // (`geneId`, …): this aggregated collections endpoint advertises no filtering
    // terms and serves no variant query, so silently ignoring one would return a list the
    // caller believes was narrowed. Mirrors g_variants for consistency.
    if let Some(params) = params
        && let Err(reject) = reject_unsupported_filters(params)
            .and_then(|()| reject_unsupported_params(params))
            // The shared envelope checks (`testMode`, `includeResultsetResponses`,
            // `requestedGranularity`) the variant entry types get via `check_envelope`.
            // Without them `/datasets` would answer 200 to values its siblings reject with
            // 400, and echo a granularity the client had not asked for.
            .and_then(|()| gdi_node_standalone_beacon::request::check_envelope_params(params))
    {
        return reject_datasets(state, params, started, &reject);
    }
    let beacon_params = to_beacon_params(&state.config.beacon);
    let beacon_cfg = &beacon_params;
    let pagination = apply_pagination(skip, limit, beacon_cfg);

    // Order deterministically by id so the paged slice is stable across requests
    // (the cache is a HashMap, whose iteration order is not).
    let mut visible = state.fresh_visible_datasets();
    visible.sort_by(|a, b| a.id.cmp(&b.id));
    let refs: Vec<&DatasetEntry> = visible.iter().map(AsRef::as_ref).collect();

    let mut response = datasets_response(&refs, &pagination, beacon_cfg);
    // Echo the submitted envelope fields. `requestedSchemas` is POST-body only, since a GET
    // listing carries none, but `includeResultsetResponses` reaches here on both surfaces:
    // `datasets_get` builds its params from the query string so that it does. Not `filters`,
    // which `/datasets` rejects when non-empty upstream, as `g_variants` does.
    if let Some(params) = params {
        echo_received_request(&mut response.meta, params);
        // Echo the requested granularity so receivedRequestSummary reflects what the client
        // asked (collections_meta defaults it to "record"). returnedGranularity stays
        // "record": /datasets serves record-level public registry metadata regardless of the
        // requested granularity, so there is no disclosure ceiling to lower here.
        if let Some(g) = params
            .get("requestedGranularity")
            .and_then(Value::as_str)
            .and_then(gdi_node_standalone_beacon::request::fold_granularity)
        {
            response.meta.received_request_summary.requested_granularity = g;
        }
    }
    crate::metrics::record_beacon_query("dataset", "n/a", response.response_summary.exists);
    // The served page, read back out of the assembled response rather than re-sliced here:
    // `datasets_response` applies `skip`/`take` internally, so a second slice at this call
    // site would be a copy of that arithmetic and would drift from it. `refs` above is the
    // full visible set, not what was listed.
    //
    // It feeds the `listed` counter (a dataset on page 3 of a listing that served page 1 was
    // not listed) and the audit line's `dataset_ids`, so this line names the datasets it
    // touched like every other answered-query line.
    let served: Vec<String> = response
        .response
        .collections
        .iter()
        .map(|c| c.id.clone())
        .collect();
    state.query_stats.record_listing(&served);
    // No sensitive query content for a dataset listing, so no detail params.
    crate::audit::beacon_query(
        &state.config.audit,
        &BeaconQueryAudit {
            entry_type: "dataset",
            granularity: "n/a",
            // Same bool-or-string testMode parser as the envelope validation (the
            // datasets endpoint has no envelope check, so a GET `?testMode=true` is
            // reachable and must not be misrecorded as false).
            test_mode: gdi_node_standalone_beacon::request::testmode_flag(
                params.and_then(|p| p.get("testMode")),
            )
            .ok()
            .flatten()
            .unwrap_or(false),
            exists: response.response_summary.exists,
            num_results: response.response_summary.num_total_results.unwrap_or(0),
            assembly: None,
            dataset_ids: &served,
            skip: pagination.skip,
            limit: pagination.limit,
            include: params
                .and_then(|p| p.get("includeResultsetResponses"))
                .and_then(Value::as_str),
            elapsed_us: elapsed_us(started),
            params: None,
        },
    );
    (StatusCode::OK, Json(response)).into_response()
}

/// `POST {prefix}/datasets` — render the visible datasets as a collections response.
///
/// Pagination is read from the Beacon request body, tolerant of either the
/// top-level `pagination` (the Beacon v2 placement) or a `pagination` nested under
/// `query.requestParameters` (matching the `g_variants` read).
pub(crate) async fn datasets_post(
    State(state): State<AppState>,
    BeaconJson(body): BeaconJson,
) -> Response {
    let params = request_params_from_body(&body);
    let (mut skip, mut limit) = read_pagination(&params);
    // Fall back to the top-level `pagination` (Beacon v2's request placement).
    if skip.is_none() && limit.is_none() {
        let (top_skip, top_limit) = read_top_level_pagination(&body);
        skip = top_skip;
        limit = top_limit;
    }
    run_datasets(&state, skip, limit, Some(&params))
}

/// `GET {prefix}/datasets` — same as the POST, reading `skip`/`limit` from the
/// query string.
pub(crate) async fn datasets_get(
    State(state): State<AppState>,
    BeaconQuery(params): BeaconQuery,
) -> Response {
    let skip = params.get("skip").and_then(|v| v.parse::<u64>().ok());
    let limit = params.get("limit").and_then(|v| v.parse::<u64>().ok());
    // Build RequestParams from the GET query so a GET `?testMode=true` /
    // `?includeResultsetResponses=…` is recorded in the audit trail and echoed in
    // receivedRequestSummary, and a submitted `filters` is rejected rather than silently
    // ignored. `filters` are the exception to the echo half: a non-empty one is a 400
    // upstream, so none survives to echo. Passing `None` here drops all three.
    let params = request_params_from_query(&params);
    run_datasets(&state, skip, limit, Some(&params))
}

/// Read a top-level `pagination` object (`skip`/`limit`) from a Beacon request body.
fn read_top_level_pagination(body: &Value) -> (Option<u64>, Option<u64>) {
    let pag = body.get("pagination").and_then(Value::as_object);
    let skip = pag.and_then(|p| p.get("skip")).and_then(Value::as_u64);
    let limit = pag.and_then(|p| p.get("limit")).and_then(Value::as_u64);
    (skip, limit)
}

// ---- Sensitive beacon: individuals placeholder ----

/// Validate an `individuals` request envelope and return a schema-valid zero result
/// honouring `requestedGranularity`.
///
/// The placeholder serves no data: it validates the Beacon v2 envelope exactly as
/// `g_variants` does (granularity, the full `includeResultsetResponses` enum
/// `{ALL, HIT, MISS, NONE}`, pagination, `testMode` accepted as a no-op, structural
/// `filters` and `requestParameters`) and then returns a zero result by construction.
/// No code path scans real individual data and no config toggle enables one, which is the
/// structural deployment gate. A structurally-valid `filters` list is accepted without a
/// semantic check and matches nothing.
///
/// Granularity shaping of the zero result:
/// * `boolean` → `responseSummary.exists: false` (no `resultSets` member);
/// * `count` → `responseSummary.numTotalResults: 0` (no `resultSets` member);
/// * `record` → empty `resultSets`.
fn run_individuals(state: &AppState, params: &RequestParams) -> Response {
    let started = Instant::now();
    let beacon_params = to_beacon_params(&state.config.beacon);
    let beacon_cfg = &beacon_params;

    // Validate the envelope exactly like g_variants (reuse parse + classify). The
    // placeholder never scans data, so the classified QueryKind is discarded — only
    // its validation effect (rejecting malformed input) is wanted.
    let normalized = match parse_request(params, beacon_cfg) {
        Ok(q) => q,
        Err(reject) => return reject_individuals(state, params, started, &reject),
    };
    if let Err(reject) = classify(&normalized, beacon_cfg) {
        return reject_individuals(state, params, started, &reject);
    }

    // Honour the (case-folded) requested granularity for the zero-shape; the applied
    // pagination, `includeResultsetResponses` and `testMode` are echoed in `meta`
    // exactly as g_variants does.
    let granularity = normalized.requested_granularity;
    let (skip, limit) = read_pagination(params);
    let pagination = apply_pagination(skip, limit, beacon_cfg);
    // `filters` are not echoed. See `individuals_zero`.
    let (_filters, requested_schemas) = submitted_request_echo(params);
    // `classify` above already rejected an out-of-enum value with a 400, so the parse
    // cannot fail here; the fallback is the `HIT` default the request would carry anyway.
    let include =
        parse_include_resultset_responses(params).unwrap_or(IncludeResultsetResponses::Hit);
    // Read `testMode` once and feed both the wire echo and the audit line below. Two reads
    // of the same request field are two chances to disagree, and the audit line and the wire
    // echo must report the same submitted value. Uses the same bool-or-string parser the
    // g_variants and datasets handlers use, so a GET `?testMode=true` — which arrives as a
    // JSON string, not a bool — is not misread.
    let test_mode = gdi_node_standalone_beacon::request::testmode_flag(params.get("testMode"))
        .ok()
        .flatten()
        .unwrap_or(false);
    let response = individuals_zero(
        beacon_cfg,
        &granularity,
        &pagination,
        &requested_schemas,
        include,
        test_mode,
    );
    crate::metrics::record_beacon_query("individual", &granularity, false);
    // The sensitive beacon is a zeros-only placeholder: exists is always false.
    crate::audit::beacon_query(
        &state.config.audit,
        &BeaconQueryAudit {
            entry_type: "individual",
            granularity: &granularity,
            // The same value the response echoed — read once above, precisely so the audit
            // line and the wire cannot disagree about what the client sent.
            test_mode,
            exists: false,
            num_results: 0,
            assembly: None,
            dataset_ids: &[],
            skip: pagination.skip,
            limit: pagination.limit,
            include: params
                .get("includeResultsetResponses")
                .and_then(Value::as_str),
            elapsed_us: elapsed_us(started),
            params: Some(params),
        },
    );
    (StatusCode::OK, Json(response)).into_response()
}

/// The `beacon-v2-default-model` base URL for `api_version`. Shared by the query
/// zero-response shaping here and the informational entry-type definitions in
/// [`crate::beacon_info`].
pub(crate) fn default_model_base(api_version: &str) -> String {
    format!(
        "https://raw.githubusercontent.com/ga4gh-beacon/beacon-v2/{api_version}/models/json/beacon-v2-default-model"
    )
}

/// Build the schema-valid zero `individuals` response for a granularity.
///
/// The `meta` is the same fully-populated shape `g_variants`/errors use; only
/// `returnedSchemas`/`returnedGranularity` differ, naming the `individual` entry type and
/// the requested granularity. Every summary field carries what the typed path would carry.
///
/// That parity has to be maintained by hand: this is the one summary in the tree built as
/// raw JSON instead of
/// [`ReceivedRequestSummary`](gdi_node_standalone_beacon::model::ReceivedRequestSummary),
/// so a field added to that struct reaches `g_variants`, `datasets` and every error
/// envelope on its own and reaches this endpoint only when it is added here too. The
/// cross-endpoint test `individuals_summary_key_set_matches_g_variants` is what makes an
/// omission fail rather than ship. The zero result is granularity-shaped per
/// [`run_individuals`].
fn individuals_zero(
    cfg: &BeaconParams,
    granularity: &str,
    pagination: &Pagination,
    requested_schemas: &[Value],
    include: IncludeResultsetResponses,
    test_mode: bool,
) -> Value {
    let base = default_model_base(&cfg.api_version);
    let schema = json!({
        // `entityType` is the Beacon v2.2.0 `SchemasPerEntity` field name (matches the
        // typed `Schema` struct on the g_variants/datasets path).
        "entityType": "individual",
        "schema": format!("{base}/individuals/defaultSchema.json")
    });
    // Echo the submitted request fields (Beacon v2 transparency), matching the typed
    // g_variants/datasets path: `requestedSchemas` is always present (required),
    // `testMode` is the submitted flag, and `includeResultsetResponses` carries the
    // applied value.
    //
    // `filters` are not echoed, and this endpoint is the only one that ever could. It
    // accepts a structural `filters` list as a no-op (`reject_unsupported_filters` is
    // applied only on `g_variants`), so reflecting one verbatim is possible here and
    // nowhere else. The vendored `beaconReceivedRequestSummary` types that field as
    // `Filters`, whose items are `"type": "string"`; the Beacon v2 ontology-filter shape
    // real clients send is an object (`{"id": "NCIT:C20197"}`), so echoing it would let any
    // client force a response that fails the node's own `beacon_schema_conformance` gate.
    // `filters` is an optional summary field, so omitting it is conformant, and it matches
    // `g_variants` and `datasets`, which never echo one either. Acceptance is unaffected: a
    // `200` with zeros, see `structurally_valid_filters_are_accepted_and_match_nothing`.
    // Only the reflection is dropped.
    let received = json!({
        "apiVersion": cfg.api_version,
        "requestedGranularity": granularity,
        // The submitted `testMode`. It changes nothing here, since the placeholder serves
        // no data and a testMode request returns the same zeros, but the summary field is
        // defined as "indicating that a request was received in a test context", which is a
        // claim about the request. Hard-coding `false` would make this endpoint deny having
        // received a flag its own audit line recorded.
        "testMode": test_mode,
        // The applied `includeResultsetResponses`, echoed as the typed path does. Moot
        // here in the same sense `testMode` is, since this endpoint has no resultSets to
        // shape, but omitting it would make the endpoint disagree with itself: a rejected
        // `individuals` request answers through the typed `error_response_meta`, which
        // carries the key, so a 400 would advertise a field its own 200 did not.
        "includeResultsetResponses": include,
        "requestedSchemas": Value::Array(requested_schemas.to_vec()),
        "pagination": { "skip": pagination.skip, "limit": pagination.limit }
    });
    let meta = json!({
        "beaconId": cfg.id,
        "apiVersion": cfg.api_version,
        "returnedGranularity": granularity,
        "returnedSchemas": [schema],
        "receivedRequestSummary": received
    });

    // Every granularity reports the same zero (no datasets matched):
    // boolean → exists:false; count → numTotalResults:0; record → empty resultSets.
    match granularity {
        "boolean" => json!({
            "meta": meta,
            "responseSummary": { "exists": false }
        }),
        "count" => json!({
            "meta": meta,
            "responseSummary": { "exists": false, "numTotalResults": 0 }
        }),
        // "record" (and any other folded value — only the three are reachable).
        _ => json!({
            "meta": meta,
            "responseSummary": { "exists": false, "numTotalResults": 0 },
            "response": { "resultSets": [] }
        }),
    }
}

/// `POST {sensitive_prefix}/individuals` — sensitive-beacon placeholder.
///
/// Reads `query.requestParameters`, validates the envelope and returns a
/// granularity-shaped zero result. A bearer `Authorization` header is accepted and
/// ignored: every endpoint in this build is public, and the handler takes no token
/// state.
pub(crate) async fn individuals_post(
    State(state): State<AppState>,
    BeaconJson(body): BeaconJson,
) -> Response {
    let params = request_params_from_body(&body);
    run_individuals(&state, &params)
}

/// `GET {sensitive_prefix}/individuals` — same as POST, reading the query string.
pub(crate) async fn individuals_get(
    State(state): State<AppState>,
    BeaconQuery(params): BeaconQuery,
) -> Response {
    let params = request_params_from_query(&params);
    run_individuals(&state, &params)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A present-but-non-object `query.requestParameters` must be rejected, not read as an
    /// empty query.
    ///
    /// The guard also rejects a top-level `requestParameters` with no `query` wrapper and a
    /// `query` that is not an object. Without this arm,
    /// `{"query":{"requestParameters":[...]}}` passes, `as_object()` yields `None`, the base
    /// map comes out empty, and the handler renders 200 `exists:false`. A client that
    /// serialized `requestParameters` as a one-element array would be told the node does not
    /// hold a variant it does hold, and a federated aggregator would record the negative.
    #[test]
    fn a_non_object_request_parameters_is_rejected_not_read_as_an_empty_query() {
        for bad in [
            serde_json::json!({"query": {"requestParameters": [{"referenceName": "1"}]}}),
            serde_json::json!({"query": {"requestParameters": "referenceName=1"}}),
            serde_json::json!({"query": {"requestParameters": 7}}),
        ] {
            let err = reject_malformed_envelope(&bad)
                .expect_err("a non-object requestParameters must be a 400");
            assert!(
                format!("{err:?}").contains("requestParameters"),
                "the rejection must name the field: {err:?}"
            );
        }

        // Absent and explicitly-null stay lenient: an empty query is a legitimate 200, and
        // the flattener accepts a missing envelope.
        for ok in [
            serde_json::json!({"query": {}}),
            serde_json::json!({"query": {"requestParameters": null}}),
            serde_json::json!({"query": {"requestParameters": {"referenceName": "1"}}}),
        ] {
            reject_malformed_envelope(&ok).expect("valid shapes must still pass");
        }
    }

    /// The global scan ceiling sheds instead of piling on when detached scans have already
    /// filled the pool.
    ///
    /// `TimeoutLayer` sits outside `ConcurrencyLimitLayer`, so a timed-out request releases
    /// its concurrency permit while its `spawn_blocking` scans keep running, since
    /// `spawn_blocking` cannot be cancelled. The per-request rolling window bounds one
    /// request and the request limit bounds the rest, but neither bounds their sum, so scans
    /// would accumulate toward tokio's blocking-pool ceiling, each holding scan memory. This
    /// pins that a saturated pool is shed as 503 rather than deepened.
    #[tokio::test]
    async fn a_saturated_scan_pool_sheds_instead_of_piling_on() {
        let inflight = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let concurrency = 4usize;
        let cap = concurrency
            .saturating_mul(SCAN_POOL_MULTIPLIER)
            .saturating_add(SCAN_DETACHED_HEADROOM);

        // Model scans detached by earlier timed-out requests: still occupying pool threads,
        // no longer attached to any live request.
        inflight.store(cap, std::sync::atomic::Ordering::Relaxed);

        let tmp = tempfile::tempdir().expect("tempdir");
        let err = scan_selected_datasets(
            Vec::new(),
            tmp.path(),
            &QueryKind::Sequence {
                pos: 0,
                ref_: String::new(),
                alt: String::new(),
                predicates: gdi_node_standalone_beacon::request::Predicates::default(),
            },
            "chr1",
            &gdi_node_standalone_core::parquet_io::DatasetDecryptor::plaintext(),
            &to_beacon_params(&BeaconConfig::default()),
            &Pagination::new(0, 10),
            ScanExec {
                caps: ParquetCaps::default(),
                concurrency,
                inflight: std::sync::Arc::clone(&inflight),
                max_query_bytes: u64::MAX,
                budget: std::sync::Arc::new(QueryMemoryBudget::new(u64::MAX)),
            },
        )
        .await
        .map(|(rows, _guard)| rows)
        .expect_err("a saturated pool must shed");
        assert_eq!(
            err.code, 503,
            "shedding is a 503, as the load-shed layer gives"
        );

        // Below the ceiling the same call proceeds (an empty selection scans nothing).
        inflight.store(cap - 1, std::sync::atomic::Ordering::Relaxed);
        assert!(
            scan_selected_datasets(
                Vec::new(),
                tmp.path(),
                &QueryKind::Sequence {
                    pos: 0,
                    ref_: String::new(),
                    alt: String::new(),
                    predicates: gdi_node_standalone_beacon::request::Predicates::default(),
                },
                "chr1",
                &gdi_node_standalone_core::parquet_io::DatasetDecryptor::plaintext(),
                &to_beacon_params(&BeaconConfig::default()),
                &Pagination::new(0, 10),
                ScanExec {
                    caps: ParquetCaps::default(),
                    concurrency,
                    inflight: std::sync::Arc::clone(&inflight),
                    max_query_bytes: u64::MAX,
                    budget: std::sync::Arc::new(QueryMemoryBudget::new(u64::MAX)),
                },
            )
            .await
            .is_ok(),
            "below the ceiling the scan must proceed"
        );
    }

    /// The scan-inflight counter (sampled into `gdi_beacon_scan_blocking_inflight`) must
    /// increment while a scan holds a pool thread and return to zero once it finishes —
    /// including a scan that unwinds. Pins the RAII balance the gauge relies on; a guard
    /// that failed to decrement (or over-decremented) would drift the pool-pressure signal.
    #[test]
    fn scan_blocking_guard_increments_then_balances_to_zero() {
        let counter = Arc::new(AtomicUsize::new(0));
        {
            let _a = ScanBlockingGuard::new(Arc::clone(&counter));
            assert_eq!(counter.load(Ordering::Relaxed), 1, "one scan running");
            let _b = ScanBlockingGuard::new(Arc::clone(&counter));
            assert_eq!(counter.load(Ordering::Relaxed), 2, "two scans running");
        }
        assert_eq!(
            counter.load(Ordering::Relaxed),
            0,
            "both guards decrement on drop"
        );

        // A guard dropped during a panic unwind still decrements (the closure runs to
        // completion whether the scan returns Ok, Err, or panics).
        let counter2 = Arc::new(AtomicUsize::new(0));
        let c2 = Arc::clone(&counter2);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = ScanBlockingGuard::new(c2);
            assert_eq!(counter2.load(Ordering::Relaxed), 1);
            panic!("scan blew up");
        }));
        assert_eq!(
            counter2.load(Ordering::Relaxed),
            0,
            "guard decrements on panic unwind"
        );
    }

    /// The process-wide budget must refuse a charge that would cross the limit without
    /// mutating the counter. A refusal that consumed budget would leave it permanently
    /// depleted and ratchet the node into shedding everything.
    #[test]
    fn query_memory_budget_refuses_over_limit_without_consuming() {
        let budget = QueryMemoryBudget::new(1000);
        assert!(budget.try_charge(600), "under the limit is admitted");
        assert_eq!(budget.used_bytes(), 600);
        assert!(!budget.try_charge(500), "600 + 500 > 1000 is refused");
        assert_eq!(
            budget.used_bytes(),
            600,
            "a refused charge must leave the counter untouched"
        );
        assert!(budget.try_charge(400), "exactly at the limit is admitted");
        assert_eq!(budget.used_bytes(), 1000);
        assert!(!budget.try_charge(1), "one byte over is refused");
    }

    /// Over-releasing must saturate at zero rather than wrap. A wrapped counter would read
    /// as ~18 EiB used and wedge the node into permanent 503s — a worse failure than the
    /// leak it would come from.
    #[test]
    fn query_memory_budget_release_saturates_at_zero() {
        let budget = QueryMemoryBudget::new(1000);
        assert!(budget.try_charge(100));
        budget.release(500);
        assert_eq!(budget.used_bytes(), 0, "release saturates, never wraps");
        assert!(
            budget.try_charge(1000),
            "the budget is still fully usable after an over-release"
        );
    }

    /// The RAII balance the shed depends on: a guard returns its charge on drop, including
    /// when it is dropped by a panic unwind (a panicking blocking scan) or by the early
    /// `return` a rejected debit takes. Without this, every shed or failed query would
    /// permanently consume budget.
    #[test]
    fn query_memory_guard_returns_its_charge_on_drop_and_unwind() {
        let budget = Arc::new(QueryMemoryBudget::new(1000));
        {
            let mut guard = QueryMemoryGuard::new(Arc::clone(&budget));
            guard.charge(300).expect("under the limit");
            guard.charge(200).expect("still under the limit");
            assert_eq!(budget.used_bytes(), 500, "charges accumulate");
        }
        assert_eq!(budget.used_bytes(), 0, "drop returns the whole charge");

        let b2 = Arc::clone(&budget);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut guard = QueryMemoryGuard::new(b2);
            guard.charge(700).expect("under the limit");
            panic!("scan blew up mid-fan-out");
        }));
        assert_eq!(
            budget.used_bytes(),
            0,
            "an unwinding request must not leak its charge"
        );

        // A guard whose charge is refused still releases what it had already taken.
        let mut guard = QueryMemoryGuard::new(Arc::clone(&budget));
        guard.charge(900).expect("under the limit");
        let rejected = guard.charge(200).expect_err("900 + 200 > 1000 sheds");
        assert_eq!(
            rejected.code, 503,
            "a full budget is a capacity 503, not a 400"
        );
        drop(guard);
        assert_eq!(
            budget.used_bytes(),
            0,
            "the pre-refusal charge is returned too"
        );
    }

    /// Two concurrent requests must not each get the full per-request allowance: that
    /// multiplication (`max_query_bytes` x `max_concurrent_requests`) is the exposure the
    /// process-wide budget exists to close.
    #[test]
    fn query_memory_budget_is_shared_across_concurrent_requests() {
        let budget = Arc::new(QueryMemoryBudget::new(1000));
        let mut first = QueryMemoryGuard::new(Arc::clone(&budget));
        first.charge(800).expect("the first request fits");

        let mut second = QueryMemoryGuard::new(Arc::clone(&budget));
        let rejected = second
            .charge(800)
            .expect_err("the second must NOT get its own full allowance");
        assert_eq!(rejected.code, 503);

        // Once the first finishes, the second-sized query fits again.
        drop(first);
        let mut third = QueryMemoryGuard::new(Arc::clone(&budget));
        third
            .charge(800)
            .expect("budget is reusable once the first request releases");
    }

    #[test]
    fn body_params_merge_envelope_siblings_from_query() {
        // The Beacon v2 schema and real clients put includeResultsetResponses,
        // requestedGranularity, testMode, pagination and filters as siblings of
        // requestParameters under `query`, not inside it. They must reach the flat params
        // map the handlers and validation read, or testMode:true is never rejected and
        // granularity, include and pagination are silently ignored.
        let body = json!({
            "query": {
                "requestParameters": { "referenceName": "3", "start": 45_823_239 },
                "includeResultsetResponses": "NONE",
                "requestedGranularity": "boolean",
                "testMode": true,
                "pagination": { "skip": 2, "limit": 5 },
                "filters": []
            }
        });
        let params = request_params_from_body(&body);
        // The GA4GH variant params (requestParameters) are still present.
        assert_eq!(
            params.get("referenceName").and_then(Value::as_str),
            Some("3")
        );
        // The envelope siblings are merged in.
        assert_eq!(
            params
                .get("includeResultsetResponses")
                .and_then(Value::as_str),
            Some("NONE")
        );
        assert_eq!(
            params.get("requestedGranularity").and_then(Value::as_str),
            Some("boolean")
        );
        assert_eq!(params.get("testMode").and_then(Value::as_bool), Some(true));
        assert!(
            params
                .get("pagination")
                .and_then(Value::as_object)
                .is_some()
        );
        assert!(params.get("filters").is_some());
    }

    #[test]
    fn scan_reject_too_large_maps_to_400_not_413() {
        // A query too broad to serve (the `max_query_rows` cap tripping mid-scan) is a
        // client error about query breadth, the same class as the pre-scan span cap, which
        // already returns 400 (`request::check_span`). It must not be 413: 413 is reserved
        // for the request-body-size limit, and conflating the two would clobber this
        // reject's actionable "narrow the range" body under the mount-wide body-limit 413
        // rewrite and pollute the body_too_large counter.
        let reject = ScanReject::too_large("narrow the position range".to_owned());
        assert_eq!(reject.code, 400, "row-cap rejection must be 400, not 413");
        // The actionable detail is still forwarded as the public body + audit reason.
        assert_eq!(reject.public, "narrow the position range");
        assert_eq!(reject.reason, "narrow the position range");
    }

    #[test]
    fn body_params_keep_envelope_nested_in_request_parameters() {
        // Backward-compat: a client that (incorrectly) nests the envelope inside
        // requestParameters still works — the base map carries those keys, and a
        // query.* sibling only overlays when present.
        let body = json!({
            "query": {
                "requestParameters": { "testMode": true, "requestedGranularity": "count" }
            }
        });
        let params = request_params_from_body(&body);
        assert_eq!(params.get("testMode").and_then(Value::as_bool), Some(true));
        assert_eq!(
            params.get("requestedGranularity").and_then(Value::as_str),
            Some("count")
        );
    }

    #[test]
    fn body_params_sibling_overrides_request_parameters() {
        // The canonical sibling location wins over a duplicate inside
        // requestParameters.
        let body = json!({
            "query": {
                "requestParameters": { "requestedGranularity": "record" },
                "requestedGranularity": "boolean"
            }
        });
        let params = request_params_from_body(&body);
        assert_eq!(
            params.get("requestedGranularity").and_then(Value::as_str),
            Some("boolean")
        );
    }

    #[test]
    fn pagination_reads_nested_object_and_flat_get_keys() {
        // POST carries a nested `pagination` object.
        let mut post = Map::new();
        post.insert("pagination".to_owned(), json!({ "skip": 3, "limit": 7 }));
        assert_eq!(read_pagination(&post), (Some(3), Some(7)));

        // GET carries flat `skip` / `limit` query-string keys (JSON strings); they
        // must page too, rather than being silently dropped.
        let mut get = Map::new();
        get.insert("skip".to_owned(), Value::String("4".to_owned()));
        get.insert("limit".to_owned(), Value::String("9".to_owned()));
        assert_eq!(read_pagination(&get), (Some(4), Some(9)));
    }
}
