//! The management-plane dataset-state endpoint.
//!
//! `GET /datasets/{id}/state` reports a single dataset's current serving state to a trusted
//! in-cluster caller: the orchestrator on the `ClusterIP`, or a co-located tool on loopback.
//! The public Ingress does not route it, because telling a known id (`200`, with `channel`
//! and a sanitized `error_message`) from an unknown one (`404`) would be an existence,
//! channel and error oracle for non-visible datasets.
//!
//! The response shape:
//!
//! ```json
//! {
//!   "id": "GDI-EE-UTARTU-20260409143052837", "state": "visible", "channel": "primary",
//!   "provenance": {"kind": "recovered", "fingerprints": ["sha256:…"]}
//! }
//! ```
//!
//! Those four fields are on every `200`; `provenance` is the crypt4gh writer-key provenance
//! recorded at ingest. Every other field is added only when it applies, and omitted rather
//! than null when it does not: `error_message`, a sanitized closed-class string such as
//! `"manifest schema validation failed at field X"`, on `error`; a `suppression` object,
//! `{"mode": "hide", "at": "…"}`, while an operator override (`dataset hide`/`take-down`) is
//! active on the id; and the overlay, sidecar, re-drop, staleness and signature fields the
//! response struct below documents one by one.
//!
//! The state comes from two stores. The status index is the source of `channel` and of the
//! persisted `error` message; the in-memory cache carries the live
//! `visible`/`hidden`/`processing` state of an ingested and loaded dataset. An id known only
//! to the index, such as an `error` whose directory was never written, is served from the
//! index alone; an id absent from both is `404`. The `{id}` path parameter is validated
//! against the dataset-id pattern ([`crate::id_guard`]) before any lookup.

use axum::Json;
use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use gdi_node_standalone_core::cache::DatasetProvenance;
use gdi_node_standalone_core::state::DatasetState;
use serde::Serialize;

use crate::id_guard::is_safe_dataset_id;
use crate::state::AppState;

/// The `GET /datasets/{id}/state` response body.
///
/// `channel` is always present for a known id. `error_message` is present exactly when the
/// dataset's ingest errored: normally alongside `state: "error"`, but under an active
/// suppression the override masks the state to `hidden` and `source_state: "error"` says why
/// the error class is still there. `state` serializes as the lowercase served-state name
/// (`visible` / `hidden` / `processing` / `error`).
#[derive(Debug, Clone, Serialize)]
struct StateBody {
    /// The dataset id (echoed back).
    id: String,
    /// The effective served state: the declared state with any active operator suppression
    /// composed over it ([`gdi_node_standalone_core::suppression::compose_state`]), so it
    /// can never contradict the `suppression` field beside it. The cache arm gets this for
    /// free, because the withhold is applied to the cache itself; the index-only arm
    /// composes explicitly, because the index keeps the source-declared state.
    state: DatasetState,
    /// The recorded provenance: the owning bucket's configured `name`, `inbox`, or the
    /// `unknown` sentinel for a cache-loaded dataset with no status-index entry, such as one
    /// restored by a disk rehydrate.
    channel: String,
    /// The sanitized, closed-class public error message, present only on `error`.
    ///
    /// Typed as [`ErrorClass`](gdi_node_standalone_core::error::ErrorClass) rather than
    /// `String`, so a producer cannot widen the closed set documented in `docs/api.md` with
    /// a raw literal. It serializes to the same string, so the wire shape is unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    error_message: Option<gdi_node_standalone_core::error::ErrorClass>,
    /// The crypt4gh writer-key provenance recorded at ingest ([`DatasetProvenance`]):
    /// `{"kind": "recovered", "fingerprints": [...]}`, or a bare `{"kind": ...}` for the
    /// plaintext, recovery-failed and unknown cases.
    ///
    /// Proof of possession only, not an authenticated producer identity: anyone holding the
    /// node's public recipient key can author a package under a fresh writer key. Nothing
    /// gates on it.
    provenance: DatasetProvenance,
    /// The node-stamped apply time of the current operator metadata overlay
    /// (`dct:modified`), present when one is applied: the orchestrator's confirmation that a
    /// `{id}.metadata.json` correction landed.
    #[serde(skip_serializing_if = "Option::is_none")]
    overlay_applied_at: Option<String>,
    /// The closed-set reason (`fetch` | `parse` | `validate`) the last overlay attempt was
    /// rejected, present only while a rejected `{id}.metadata.json` stands, so a silently
    /// dropped correction is distinguishable from an applied one. Cleared when an overlay
    /// applies or reverts.
    #[serde(skip_serializing_if = "Option::is_none")]
    overlay_error: Option<String>,
    /// The closed-set reason (`unreadable` | `unrecognized`) the last visibility sidecar
    /// (`{id}.state.json`) was rejected, present only while a rejected one stands. Cleared
    /// when a sidecar for this id parses cleanly.
    ///
    /// The counterpart of `overlay_error` for visibility. A rejected sidecar fails safe to
    /// `hidden`, so without this field a dataset withdrawn from the public plane by a
    /// truncated sidecar write reads the same as one an operator chose to hide.
    #[serde(skip_serializing_if = "Option::is_none")]
    state_sidecar_error: Option<String>,
    /// When a changed re-drop under this live, immutable id was last ignored (RFC3339), if
    /// any. A corrected re-upload under a live id is quarantined and the entry stays
    /// `visible`, so this field is what distinguishes a silently ignored correction, or a
    /// same-millisecond id collision, from a landed one. Cleared when the id is re-ingested,
    /// by take-down and re-add, or erased.
    #[serde(skip_serializing_if = "Option::is_none")]
    superseded_redrop_at: Option<String>,
    /// `true` when this `visible` dataset is withheld from the public plane by the
    /// visibility-staleness gate: its owning bucket reconciled and then went dark past
    /// `[service].max_visibility_staleness_seconds`, so nobody is told "served" while
    /// collections are `0`. Omitted when false, and always so when the bound is unset.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    stale: bool,
    /// The active operator suppression override on this id, if any: a `hide` or `remove`
    /// written via `dataset hide|take-down` withholds the dataset whatever the source
    /// dictates. `None` when unsuppressed.
    #[serde(skip_serializing_if = "Option::is_none")]
    suppression: Option<SuppressionView>,
    /// The opaque signature of the artifact this state was last computed from: an S3
    /// `ETag`, or an inbox package's content hash. It changes exactly when the node has
    /// processed different bytes under this id.
    ///
    /// Exposed so a client can tell "the node has not looked at my upload yet" from "the
    /// node looked at my upload and rejected it". Comparing `error_message` cannot do that,
    /// because a package re-rejected for the same reason is indistinguishable from the
    /// error already recorded, which leaves `deploy --wait` polling out its timeout instead
    /// of exiting with the node's reason.
    ///
    /// Opaque by contract: compare it for equality, never parse it. It is not a digest of
    /// the dataset contents and must not be used as one.
    #[serde(skip_serializing_if = "Option::is_none")]
    last_seen_signature: Option<String>,
    /// The declared state an active suppression is masking, present only when an override
    /// changed the answer, and omitted rather than `null` otherwise. Mirrors
    /// `list_datasets::ListedDataset::source_state`: composing the override into `state`
    /// must not destroy the fact it masks, because an errored-and-withheld dataset still has
    /// to read as errored for triage.
    #[serde(skip_serializing_if = "Option::is_none")]
    source_state: Option<DatasetState>,
}

/// The `suppression` field of [`StateBody`]: the operator override active on this id.
#[derive(Debug, Clone, Serialize)]
struct SuppressionView {
    /// `"hide"` or `"remove"`, from
    /// [`SuppressMode::as_str`](gdi_node_standalone_core::suppression::SuppressMode::as_str).
    /// A plain string rather than the enum, so the wire shape does not follow the enum's own
    /// `serde` representation.
    mode: String,
    /// The operator-supplied timestamp of when the override was authored.
    at: String,
}

/// `GET /datasets` — the node's whole dataset inventory (management plane).
///
/// Mounted only when `[service].expose_dataset_list` is set; otherwise the route does not
/// exist and the plane answers `404`, indistinguishable from a node too old to serve it. It
/// does not gate `GET /datasets/{id}/state`, which stays available either way.
///
/// The body is the same JSON `dataset list --format json` prints, because both call
/// [`crate::list_datasets::collect`]. Unfiltered: the filters are a CLI affordance over a
/// listing an operator already has in full, and a query-parameter surface here would be a
/// second, drift-prone spelling of them for no new capability.
///
/// Reads the on-disk status index rather than the live cache, as the CLI does, so it may lag
/// a `visible`↔`hidden` flip by at most one reconcile; `GET /datasets/{id}/state` resolves a
/// single id against the cache instead. Neither is a live oracle for an operator override:
/// both compose in `AppState::suppressions`, an in-memory set refreshed on reload (SIGUSR1
/// and the periodic override reconcile) and never re-read from the store per request. The
/// same set gates what the Beacon serves, so a fresher reader would report a withhold the
/// node is not yet applying. A read failure is a `500` with a generic body, because the
/// underlying error can name a filesystem path.
pub(crate) async fn dataset_list(
    State(state): State<AppState>,
    RawQuery(query): RawQuery,
) -> Response {
    if let Some(rejected) = reject_any_query(query.as_deref()) {
        return rejected;
    }
    serve_inventory(
        state,
        crate::list_datasets::DatasetsFilter::default(),
        "/datasets",
    )
    .await
}

/// `GET /datasets/suppressed` — the datasets an operator is withholding (management plane).
///
/// Mounted under the same `[service].expose_dataset_list` flag as `GET /datasets`: the same
/// disclosure class, the same collector, the same audit.
///
/// The unfiltered listing structurally cannot answer this question. A `take-down` (`Remove`)
/// erases the local copy and purges the status entry, so the dataset survives only as an
/// override, and `collect` synthesizes rows for override-only ids only when
/// `DatasetsFilter::suppressed` is set, so that a completed GDPR erasure cannot leak into the
/// plain listing as merely "hidden". Without this route, an operator or DPO asking over HTTP
/// what has been withheld gets `[]`, an answer that reads as authoritative and is not.
///
/// A separate path rather than a `?suppressed=true` parameter on the listing: one route with
/// one meaning adds no query vocabulary that can drift from the CLI's filters.
pub(crate) async fn dataset_list_suppressed(
    State(state): State<AppState>,
    RawQuery(query): RawQuery,
) -> Response {
    if let Some(rejected) = reject_any_query(query.as_deref()) {
        return rejected;
    }
    let filter = crate::list_datasets::DatasetsFilter {
        suppressed: true,
        ..Default::default()
    };
    serve_inventory(state, filter, "/datasets/suppressed").await
}

/// Refuse any query string on the inventory routes, rather than ignoring it.
///
/// Neither route takes parameters, and axum drops unrecognized ones silently. Here that is
/// the wrong default: the obvious guess for the withheld set is a `suppressed=true` parameter
/// on the listing, and answering it `200 []` would tell the caller, with a success status,
/// that nothing is withheld. The refusal names the route that does answer the question.
fn reject_any_query(query: Option<&str>) -> Option<Response> {
    if query.is_none_or(str::is_empty) {
        return None;
    }
    Some(
        (
            StatusCode::BAD_REQUEST,
            "this route takes no query parameters; for the withheld inventory use \
             GET /datasets/suppressed",
        )
            .into_response(),
    )
}

/// Collect and serve one inventory listing, shared by both inventory routes. `route` names
/// which one, for the audit and log lines: the two routes disclose different sets, so a
/// record that cannot say which was pulled is not a record.
async fn serve_inventory(
    state: AppState,
    filter: crate::list_datasets::DatasetsFilter,
    route: &'static str,
) -> Response {
    // Blocking file reads (status index + override store) go off the async reactor: the poll
    // loops and the ingest queue share this runtime, and a slow or contended disk must not
    // stall them.
    let config = std::sync::Arc::clone(&state.config);
    // The live channel set, so a bucket a reload added is declared here as it is for the
    // hydrate projection and the per-id oracle.
    let reloadable = state.reloadable();
    let listed = tokio::task::spawn_blocking(move || {
        crate::list_datasets::collect(&config, &filter, &reloadable)
    })
    .await;
    match listed {
        Ok(Ok(rows)) => {
            // Audited like every other per-dataset disclosure on this plane, and only for
            // a served listing: a read that failed disclosed nothing.
            let ids: Vec<String> = rows.iter().map(|r| r.id.clone()).collect();
            crate::audit::dataset_inventory_read(&state.config.audit, route, rows.len(), &ids);
            Json(rows).into_response()
        }
        Ok(Err(e)) => {
            tracing::warn!(route, error = %e, "could not read the dataset inventory");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not read the dataset inventory",
            )
                .into_response()
        }
        Err(e) => {
            tracing::warn!(route, error = %e, "the dataset inventory read panicked");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not read the dataset inventory",
            )
                .into_response()
        }
    }
}

/// `GET /datasets/{id}/state` — one dataset's serving status (management-plane).
///
/// Validates `{id}` at the boundary, then resolves state from the status index +
/// cache: `200` with `{id, state, channel, provenance, error_message?,
/// overlay_applied_at?, overlay_error?, suppression?, source_state?}` for a known id, `404`
/// for an id the node has never ingested (distinct from `processing`).
pub(crate) async fn dataset_state(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    // Reject a malformed or traversal-shaped id before any lookup, as defence in depth: the
    // lookup is cache/index-based and never a path join. A malformed id is a client error
    // (`400`), distinct from the `404` an unknown but valid id gets.
    if !is_safe_dataset_id(&id) {
        return (StatusCode::BAD_REQUEST, "invalid dataset id").into_response();
    }

    // The status index is authoritative for the channel and the persisted error message,
    // and it survives a restart even for an inbox dataset whose package was consumed. Short,
    // non-await critical section.
    let indexed = {
        let guard = state
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.get(&id).cloned()
    };

    // The in-memory cache carries the live state of an ingested and loaded dataset: the
    // index may lag a `visible`<->`hidden` flip, and never holds `processing`.
    let cached = state.cache.get(&id);

    // The last overlay-reject reason, if the current `{id}.metadata.json` was dropped. Read
    // before `id` is moved into the body, and only meaningful for a cached dataset, since an
    // overlay applies only to an ingested one.
    let overlay_error = state.overlay_error(&id);

    // The last state-sidecar reject reason, read on the same terms: the only per-id signal
    // that a dataset is `hidden` because its `{id}.state.json` could not be read, rather
    // than because anyone chose to hide it.
    let state_sidecar_error = state.state_sidecar_error(&id);

    // When a changed re-drop under this live id was last ignored. Resolved once here and set
    // uniformly after the match, like `suppression`.
    let superseded_redrop_at = state.superseded_redrop_at(&id);

    // The active operator suppression override, if any. It is meaningful for both the
    // cache-hit and index-only arms below, since a suppression can name an id the node has
    // not yet ingested, so it is resolved once here. Short, non-`await` critical section.
    let suppression = {
        let guard = state
            .suppressions
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // The most restrictive of the id-level and channel-level overrides: the record
        // `effective_full` picks, which is what `list_datasets::collect` composes for the
        // listing and what `enforce_suppressions` acts on, where a `Remove` erases. Taking
        // the id-level record first would let this oracle answer `hide` for an id a channel
        // take-down is erasing, understating an irreversible action and disagreeing with the
        // listing at the same instant. A cache hit with no index entry has no channel to
        // judge; `unknown` is a name `is_valid_channel_name` reserves, so no channel override
        // can carry it. Best effort, the same stance the orphan axis below takes.
        let channel = indexed.as_ref().map_or("unknown", |e| e.channel.as_str());
        guard.effective_full(&id, channel).map(|s| SuppressionView {
            mode: s.mode.as_str().to_owned(),
            at: s.at.clone(),
        })
    };

    // The index's source-declared state, captured before the match consumes `indexed`: the
    // input to `source_state` below, for both arms. The cache arm's final state is the
    // already-withheld cache value, so the masked declared value survives only here.
    let declared = indexed.as_ref().map(|e| e.state);

    // The orphan axis (see `list_datasets::collect`): the hydrate projection withholds a
    // bucket channel the live configuration does not declare, and that withhold lives in the
    // cache only. The index-only arm below, and the reload→apply window of the cache arm,
    // must compose it here or answer the declared state for a dataset the node is
    // withholding. One predicate over the live reloadable set keeps this oracle and the
    // projection in agreement. A cache hit with no index entry has no channel to judge
    // (`unknown`) and so reads as not orphaned, best effort as above.
    let orphaned = indexed
        .as_ref()
        .is_some_and(|e| state.channel_is_orphaned(&e.channel));

    let mut body = match (cached, indexed) {
        // Loaded in the cache: the cache state is authoritative. The channel comes from the
        // index when present, else the `unknown` sentinel; a cache hit with no index entry
        // is reachable after a disk rehydrate, and an empty string would violate the
        // documented `inbox`-or-bucket-name provenance contract.
        //
        // The suppression is composed here even though `apply_suppressions_to_cache` usually
        // makes it a no-op: the store reload and the cache apply are two steps, and a read
        // landing between them would otherwise see `state: "visible"` beside a `suppression`
        // object. A lift is unaffected, since the cache stays `Hidden` until the next
        // reconcile re-derives the source state.
        (Some(entry), index) => StateBody {
            id,
            state: gdi_node_standalone_core::suppression::compose_state(
                entry.state,
                suppression.is_some() || orphaned,
            ),
            channel: index
                .as_ref()
                .map_or_else(|| "unknown".to_owned(), |e| e.channel.clone()),
            error_message: error_message_for(entry.state, index.as_ref()),
            // Like `channel`, provenance lives only in the index; a cache hit without an
            // index entry has none recorded and reports `Unknown`.
            provenance: index
                .as_ref()
                .map_or(DatasetProvenance::Unknown, |e| e.provenance.clone()),
            overlay_applied_at: entry.metadata_modified,
            overlay_error,
            state_sidecar_error,
            superseded_redrop_at: None, // set below, uniformly for both arms
            stale: false,               // set below, uniformly for both arms
            suppression: None,          // set below, uniformly for both arms
            source_state: None,         // set below, uniformly for both arms
            // Like `channel` and `provenance`, the signature lives only in the index.
            last_seen_signature: index.as_ref().and_then(|e| e.last_seen_signature.clone()),
        },
        // Known only to the status index, such as an `error` with no on-disk dataset or a
        // processing entry not yet loaded: serve from the index. An overlay requires a
        // cached dataset, so neither overlay field applies here.
        //
        // The composition below carries the withhold, unlike in the cache arm:
        // `apply_suppressions_to_cache` withholds by mutating the cache, which never reached
        // an id that is not in it, so the index value here is the declared state rather than
        // the effective one. `error_message` stays keyed to the source state, because the
        // composition masks visibility, not the fact that ingest failed; `source_state`, set
        // below, tells the reader why an error class rides on a `hidden` body.
        (None, Some(index)) => StateBody {
            id,
            state: gdi_node_standalone_core::suppression::compose_state(
                index.state,
                suppression.is_some() || orphaned,
            ),
            channel: index.channel.clone(),
            error_message: error_message_for(index.state, Some(&index)),
            provenance: index.provenance.clone(),
            overlay_applied_at: None,
            overlay_error: None,
            // Unlike `overlay_error` above, this is not pinned to `None`: an overlay applies
            // only to an ingested dataset, but a visibility sidecar is read for the ids this
            // arm covers too, and a rejected one is why such an id may sit at `hidden`.
            state_sidecar_error,
            superseded_redrop_at: None, // set below, uniformly for both arms
            stale: false,               // set below, uniformly for both arms
            suppression: None,          // set below, uniformly for both arms
            source_state: None,         // set below, uniformly for both arms
            last_seen_signature: index.last_seen_signature.clone(),
        },
        // In neither the cache nor the index: split out so the happy path stays inside
        // clippy's function-length budget.
        (None, None) => return unknown_id_response(&state, &id),
    };
    body.superseded_redrop_at = superseded_redrop_at;
    // Whether this visible dataset is currently withheld from the public plane by the
    // staleness gate. Resolved from the final state and channel, so it agrees with the
    // serve-time gate `fresh_visible_datasets` applies.
    body.stale = state.public_visibility_stale(body.state, &body.channel);
    body.suppression = suppression;
    // The masked declared state, only when an override actually changed the answer. Gated on
    // the override rather than on a bare `declared != state`, so a transient cache/index
    // divergence with no suppression in force cannot surface a spurious field.
    if body.suppression.is_some() || orphaned {
        body.source_state = declared.filter(|&s| s != body.state);
    }

    // Audit the resolved oracle read: the protected hidden-dataset existence, channel and
    // error surface.
    crate::audit::dataset_state_read(
        &state.config.audit,
        &body.id,
        true,
        body.state.as_str(),
        &body.channel,
    );
    (StatusCode::OK, Json(body)).into_response()
}

/// The `(None, None)` arm of [`dataset_state`]: an id in neither the cache nor the index.
/// Answers `410` for a tombstoned id and `404` for one never ingested, so a client can tell
/// a permanent refusal from an upload the node has not picked up yet.
fn unknown_id_response(state: &AppState, id: &str) -> Response {
    // Audit the oracle read even on a miss, so a scan probing for ids is visible. The reads
    // are uncorrelated: the management plane carries no request id.
    crate::audit::dataset_state_read(&state.config.audit, id, false, "", "");
    // Deleted and tombstoned: the id existed, was erased, and is refused while the
    // operator's `deleted` sidecar stands. `410 Gone` says that, and is a status code rather
    // than a new `state` value because a tombstone is not a serving state; widening the
    // documented `visible|hidden|processing|error` set would ripple through `DatasetState`,
    // `docs/api.md` and every consumer matching on it.
    let tombstoned = state
        .tombstoned
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .contains(id);
    if tombstoned {
        return (
            StatusCode::GONE,
            "dataset deleted; a `deleted` or unreadable tombstone sidecar for this id \
             stands in the inbox and suppresses any re-drop. Repair or remove the sidecar \
             to release the id; that also un-suppresses any package still in the inbox",
        )
            .into_response();
    }
    // Never ingested: 404, distinct from `processing`, which is a known id.
    StatusCode::NOT_FOUND.into_response()
}

/// The sanitized error message to surface for a state: only on `error`, taken from the
/// status index's persisted, closed-class value and never re-derived.
fn error_message_for(
    state: DatasetState,
    index: Option<&gdi_node_standalone_core::cache::StatusEntry>,
) -> Option<gdi_node_standalone_core::error::ErrorClass> {
    if state == DatasetState::Error {
        index.and_then(|e| e.error_message)
    } else {
        None
    }
}
