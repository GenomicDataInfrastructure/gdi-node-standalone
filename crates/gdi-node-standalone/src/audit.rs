//! Privacy-aware audit log of answered Beacon data-discovery queries.
//!
//! Emits one structured `audit`-target line per answered query (`g_variants`, `datasets` or
//! `individuals`). On by default. The query content, meaning coordinates and filters, is
//! withheld unless `[audit].query_detail` is set, so the default is privacy-preserving (see
//! [`gdi_node_standalone_core::config::AuditConfig`]). The line is emitted inside the
//! per-request `http_request` span, so it carries that span's `request_id`, the join key to
//! the fronting proxy's access log.

use gdi_node_standalone_beacon::request::RequestParams;
use gdi_node_standalone_core::config::{AuditConfig, WriterPolicy};
use gdi_node_standalone_core::ingest::WriterProvenance;
use gdi_node_standalone_core::state::DatasetState;
use gdi_node_standalone_core::suppression::SuppressMode;

/// The closed `event` vocabulary stamped on every audit line.
///
/// Audit is a compliance surface: an operator's log pipeline filters and alerts on these
/// names, and the runbook enumerates them. Both couplings are guarded.
/// `audit_event_catalogue_covers_every_emit_site` pins this list against the crate's emit
/// sites, and `audit_event_catalogue_matches_the_runbook` pins it against the
/// `audit-event-names` block in `docs/operating.md`, so adding an event without listing it
/// here, or listing one the runbook does not document, fails the build.
///
/// Keep sorted. Test-only: each emit site names its own event inline, as `tracing` requires,
/// so nothing reads this list at runtime.
#[cfg(test)]
const AUDIT_EVENTS: &[&str] = &[
    "beacon_query",
    "beacon_query_rejected",
    "channel_suppressed",
    "channel_unsuppressed",
    "config_reloaded",
    "dataset_inventory_read",
    "dataset_state_change",
    "dataset_state_read",
    "dataset_suppressed",
    "dataset_unsuppressed",
    "fairdp_read",
    "http_request",
    "identity_backed_up",
    "identity_initialized",
    "identity_listed",
    "identity_restored",
    "identity_retired",
    "identity_rotated",
    "ingest_provenance",
    "ingest_provenance_absent",
    "keyless_degraded",
    "log_level_changed",
    "metadata_overlay_applied",
    "metadata_overlay_cleared",
    "metadata_overlay_set",
    "override_store_reloaded",
    "overrides_imported",
    "plaintext_drop_not_allowed",
    "pme_at_rest_unverifiable",
    "pme_cache_flushed",
    "pme_master_key_mismatch",
    "pme_sentinel_resealed",
    "purge_rejected",
    "query_stats_read",
    "reconcile_requested",
    "reingest_refused",
    "reingest_requested",
    "writer_key_not_allowed",
];

/// The closed `actor` vocabulary stamped on every audit line: which class of process
/// produced it. It states which lines an automated process produced, rather than leaving
/// that to be inferred from a missing `request_id`, and gives every line a stable actor tag.
/// Each value is a fixed literal chosen per emit site, never a user-supplied string, so it
/// cannot carry injected or sensitive content.
///
/// The set is small and content-free:
/// * `beacon-client`: a public Beacon-plane caller, answered or rejected. Currently
///   unauthenticated; once an auth layer lands, the authenticated subject rides alongside
///   this on the request span rather than replacing it.
/// * `fairdp-client`: a FAIR-Data-Point-plane caller (a `/fairdp` read; see [`fairdp_read`]),
///   also unauthenticated.
/// * `management-client`: a management-plane caller, such as the `GET /datasets/{id}/state`
///   oracle read.
/// * `system`: an automated node process, such as the background reconcile or ingest
///   pipeline reaching a terminal dataset outcome.
/// * `operator`: an operator-invoked administrative CLI action, covering the crypt4gh
///   identity lifecycle and the dataset-suppression file-write verbs. Its trust equals
///   config-file-write trust; it is not an authenticated identity (see
///   [`dataset_suppressed`]).
const ACTOR_BEACON_CLIENT: &str = "beacon-client";
const ACTOR_FAIRDP_CLIENT: &str = "fairdp-client";
const ACTOR_MANAGEMENT_CLIENT: &str = "management-client";
pub(crate) const ACTOR_SYSTEM: &str = "system";
/// Operator CLI actions, such as the key-lifecycle flows. Not Vault-gated: a plain build
/// links `identity init` for a file-backed identity (`crate::init_identity_file`), which
/// emits `identity_initialized` as this same actor.
pub(crate) const ACTOR_OPERATOR: &str = "operator";

/// All fields of one answered-query audit line.
///
/// Bundled into a borrowed struct so [`beacon_query`] can grow detail fields without a long
/// positional signature. Every field is recorded unconditionally under `[audit].enabled`
/// except `params`, which is logged as a compact JSON `query` field only when
/// `[audit].query_detail` is set.
pub(crate) struct BeaconQueryAudit<'a> {
    /// GA4GH entry type (`genomicVariant` / `dataset` / `individual`).
    pub entry_type: &'a str,
    /// Served granularity (`boolean` / `count` / `record`, or `n/a` for the listing).
    pub granularity: &'a str,
    /// Submitted `testMode` flag. Always `false` on an answered line, since `testMode:true`
    /// is rejected upstream, but recorded anyway.
    pub test_mode: bool,
    /// Whether any result matched (recorded even when the wire withholds it).
    pub exists: bool,
    /// True total result count (recorded even when withheld at `boolean`).
    pub num_results: u64,
    /// Queried assembly id (`g_variants`); `None` for datasets/individuals.
    pub assembly: Option<&'a str>,
    /// Dataset ids the query scanned (assembly-matched); logged in full.
    pub dataset_ids: &'a [String],
    /// Effective (defaulted + clamped) pagination skip.
    pub skip: u64,
    /// Effective (defaulted + clamped) pagination limit.
    pub limit: u64,
    /// Submitted `includeResultsetResponses` level, if any.
    ///
    /// The submitted value, distinct from the applied one the wire echoes in
    /// `meta.receivedRequestSummary.includeResultsetResponses`: absent here is `None`, absent
    /// there is the `HIT` default. An operator correlating a log line with a captured
    /// response therefore sees an empty `include` beside a wire `"HIT"` for the same request.
    /// This field answers what the client asked for, which a defaulted echo would erase.
    pub include: Option<&'a str>,
    /// Wall time from handler entry to this audit emit, in microseconds.
    pub elapsed_us: u64,
    /// Raw request params, logged only with `[audit].query_detail`. `None` where there is no
    /// sensitive query, such as the dataset listing.
    pub params: Option<&'a RequestParams>,
}

/// Emit the audit line for one answered beacon query.
///
/// Records the query shape and operational detail unconditionally under `[audit].enabled`.
/// The raw request params are logged only when `[audit].query_detail` is set. Emitted inside
/// the per-request `http_request` span, so the line carries that span's `request_id`.
pub(crate) fn beacon_query(cfg: &AuditConfig, rec: &BeaconQueryAudit<'_>) {
    if !cfg.enabled {
        return;
    }
    // Comma-joined rather than a JSON array inside a string: `tracing` fields cannot carry
    // an array, and a keyword holding `["a","b"]` cannot be aggregated per dataset, while a
    // log query can split per-id terms out of this form.
    let dataset_ids = rec.dataset_ids.join(",");
    if let Some(p) = rec.params.filter(|_| cfg.query_detail) {
        tracing::info!(
            target: "audit",
            event = "beacon_query",
            event.action = "beacon.query",
            actor = ACTOR_BEACON_CLIENT,
            entry_type = rec.entry_type,
            granularity = rec.granularity,
            test_mode = rec.test_mode.then_some(true),
            exists = rec.exists,
            num_results = rec.num_results,
            assembly = rec.assembly.unwrap_or(""),
            datasets_scanned = rec.dataset_ids.len() as u64,
            dataset_ids = (!dataset_ids.is_empty()).then_some(dataset_ids.as_str()),
            skip = rec.skip,
            limit = rec.limit,
            include = rec.include,
            elapsed_us = rec.elapsed_us,
            query = %serde_json::to_string(p).unwrap_or_default(),
            "beacon query"
        );
    } else {
        tracing::info!(
            target: "audit",
            event = "beacon_query",
            event.action = "beacon.query",
            actor = ACTOR_BEACON_CLIENT,
            entry_type = rec.entry_type,
            granularity = rec.granularity,
            test_mode = rec.test_mode.then_some(true),
            exists = rec.exists,
            num_results = rec.num_results,
            assembly = rec.assembly.unwrap_or(""),
            datasets_scanned = rec.dataset_ids.len() as u64,
            dataset_ids = (!dataset_ids.is_empty()).then_some(dataset_ids.as_str()),
            skip = rec.skip,
            limit = rec.limit,
            include = rec.include,
            elapsed_us = rec.elapsed_us,
            "beacon query"
        );
    }
}

/// Emit the audit line for a rejected beacon query: a 4xx from envelope or coordinate
/// validation that the answered-query path ([`beacon_query`]) never sees, so that a probing
/// scan of malformed queries still leaves a trail.
///
/// `reason` is the [`BeaconReject`](gdi_node_standalone_beacon::request::BeaconReject)
/// message, a closed set of path-free strings naming the offending field rather than the
/// queried value, so it is recorded unconditionally. The raw request `params` are logged only
/// with `[audit].query_detail`, mirroring [`beacon_query`].
pub(crate) fn beacon_query_rejected(
    cfg: &AuditConfig,
    entry_type: &str,
    code: u16,
    reason: &str,
    elapsed_us: u64,
    params: Option<&RequestParams>,
) {
    if !cfg.enabled {
        return;
    }
    if let Some(p) = params.filter(|_| cfg.query_detail) {
        tracing::info!(
            target: "audit",
            event = "beacon_query_rejected",
            event.action = "beacon.query.reject",
            actor = ACTOR_BEACON_CLIENT,
            entry_type,
            code,
            reason,
            elapsed_us,
            query = %serde_json::to_string(p).unwrap_or_default(),
            "beacon query rejected"
        );
    } else {
        tracing::info!(
            target: "audit",
            event = "beacon_query_rejected",
            event.action = "beacon.query.reject",
            actor = ACTOR_BEACON_CLIENT,
            entry_type,
            code,
            reason,
            elapsed_us,
            "beacon query rejected"
        );
    }
}

/// Emit the audit line for a dataset reaching a terminal ingest outcome (published
/// or permanently errored).
///
/// Unlike [`beacon_query`] this records a node mutation rather than a read, so the audit
/// trail covers ingest as well as discovery: a controlled-access node that audited only
/// queries would leave who published what, and what was rejected, unaccountable. There is no
/// sensitive query content, so the line is gated only on `cfg.enabled` and carries the
/// dataset id, channel, resulting `state` and a path-free `cause`, never manifest contents or
/// secret material. Emitted inside the per-job context, so it shares any active
/// `request_id`.
pub(crate) fn dataset_state_change(
    cfg: &AuditConfig,
    dataset: &str,
    channel: &str,
    state: &str,
    cause: &str,
) {
    if !cfg.enabled {
        return;
    }
    tracing::info!(
        target: "audit",
        event = "dataset_state_change",
        event.action = "dataset.state.change",
        actor = ACTOR_SYSTEM,
        dataset,
        channel,
        state,
        cause,
        "dataset state change"
    );
}

/// Emit the record for a visibility transition driven by a `{id}.state.json` sidecar: the
/// audit line, plus an alarm line when the sidecar released the dataset.
///
/// Both sites that apply a sidecar transition, bucket and inbox, call this, so recording the
/// change and raising the alarm is one call rather than a pairing each site has to remember.
///
/// The release direction alarms because a `.tar.c4gh` package is authenticated, while the
/// sidecar beside it is not. Under a non-`off` `[ingest].writer_policy` the node recovers the
/// package's writer key and refuses one that is not allow-listed for the channel; the sidecar
/// carries no writer identity, so anything that can write the channel can flip any dataset in
/// it to `visible`, including one another party withheld. This line is the only evidence
/// tying such a flip to the sidecar, so it is tagged for a person rather than merely
/// retained. The withhold direction is not tagged, because failing closed is the safe
/// direction and the audit line still records it.
///
/// Expect one line per publication. The node cannot distinguish a legitimate publish from a
/// hostile one, so this is a detection control that someone correlates against their own
/// record of intended publishes; preventing it would need a signed sidecar. It fires for
/// every channel including the inbox, because the node cannot know which of its channels is
/// shared.
pub(crate) fn sidecar_state_change(
    cfg: &AuditConfig,
    dataset: &str,
    channel: &str,
    state: DatasetState,
) {
    if state == DatasetState::Visible {
        // Not gated on `cfg.enabled`: an operator who turned the audit stream off has opted
        // out of the governance record, not out of being told that something published a
        // dataset. The other tagged sites are plain `warn!`s for the same reason.
        tracing::warn!(
            alert = true,
            event.action = "dataset.sidecar.release",
            event.outcome = "success",
            dataset,
            channel,
            "a visibility sidecar published this dataset; sidecars carry no writer identity, \
             so confirm this publication was intended"
        );
    }
    dataset_state_change(
        cfg,
        dataset,
        channel,
        &format!("{state:?}"),
        "sidecar-state-change",
    );
}

/// Emit the audit line for a live `SIGHUP` reload of the reloadable config subset:
/// `[catalogs]` and the `[ingest]` writer allow-list, which is the node's only
/// publication-auth control.
///
/// A live enforcement change, such as `warn` to `enforce` or an allow-list edit, is a
/// security-posture change that must leave a durable trail. The plain module-target `info!`
/// the reload logs can be dropped by a `GDI_LOG` or `RUST_LOG` level, whereas this rides the
/// `target: "audit"` floor no env-filter directive can silence (see `crate::logging`). It
/// records the policy enum and the allow-list and catalog sizes, never a fingerprint or a
/// secret. The exhaustive `match` binds the enum, so a new `WriterPolicy` variant cannot be
/// added without naming it here. Gated on `cfg.enabled` like the other mutation lines.
///
/// `trigger` names what caused the reload (`sighup` or `http`), so the one record that
/// survives log filtering can tell an operator's signal from a POST to the action endpoint.
pub(crate) fn config_reloaded(
    cfg: &AuditConfig,
    trigger: &'static str,
    writer_policy: WriterPolicy,
    inbox_allowlist_size: usize,
    catalogs: usize,
) {
    if !cfg.enabled {
        return;
    }
    let writer_policy = match writer_policy {
        WriterPolicy::Off => "off",
        WriterPolicy::Warn => "warn",
        WriterPolicy::Enforce => "enforce",
    };
    tracing::info!(
        target: "audit",
        event = "config_reloaded",
        event.action = "config.reload",
        actor = ACTOR_SYSTEM,
        trigger,
        writer_policy,
        inbox_allowlist_size,
        catalogs,
        "config reload applied ([catalogs] + [ingest] writer allow-list)"
    );
}

/// Emit the audit line for an operator dataset-suppression override taking effect
/// (`dataset hide` / `dataset take-down` writing or refreshing
/// `<override_dir>/suppressions/{id}.json`).
///
/// The actor is the file writer, whoever ran the CLI process that wrote the override file,
/// not an authenticated identity. Its trust equals config-file-write trust, the same posture
/// as every other `operator`-actor line here (see the `ACTOR_OPERATOR` doc above). The line
/// is emitted from the CLI (`suppress_cmd::hide` and `take_down`) at the point the file write
/// succeeds, not from the node's later apply, so it exists even if the node is down or is
/// never told to reconcile; the durable file stays authoritative either way. See
/// [`dataset_state_change`] for the separate line the node emits when a `Remove` override
/// erases the local copy. Records the closed-set `mode`, never dataset content and never the
/// operator's free-text justification. Gated on `cfg.enabled`.
///
/// The `reason` is not a parameter. It is operator-authored free text that in practice names
/// the person the withholding was for, and `target: "audit"` reaches stderr as JSON, the
/// node's most widely replicated and longest retained surface, outside the retention policy
/// that governs the override file. It is withheld from the JSON surfaces for the same reason
/// (`list_datasets::ListedDataset::reason` is `#[serde(skip_serializing)]`), and
/// [`overrides_imported`] and [`metadata_overlay_set`] withhold entry bodies and patch
/// content on the same basis.
///
/// Dropping it from the signature rather than from the macro binds the rule: re-adding it
/// means re-threading a parameter through every call site. `dataset` and `mode` still
/// correlate this line with `<override_dir>/suppressions/{id}.json`, which remains the
/// durable record of why.
pub(crate) fn dataset_suppressed(cfg: &AuditConfig, dataset: &str, mode: SuppressMode) {
    if !cfg.enabled {
        return;
    }
    let mode = mode.as_str();
    tracing::info!(
        target: "audit",
        event = "dataset_suppressed",
        event.action = "dataset.suppress",
        actor = ACTOR_OPERATOR,
        dataset,
        mode,
        "operator dataset suppression override written"
    );
}

/// Emit the audit line for a suppression-store reload that changed the withhold set
/// out-of-band: the node adopting `<override_dir>/suppressions/` on `SIGUSR1` or a periodic
/// reconcile, diffed against what it held.
///
/// The per-write audit (`dataset_suppressed` and `dataset_unsuppressed`) fires in the CLI
/// writer process, so a direct `rm` or a hand-written suppression file leaves no record of
/// who withheld what and when. This is the node's own record of what it adopted: `added`
/// carries `id=mode` for a new or mode-changed withhold, and `removed` carries the ids whose
/// withhold vanished. Both are path-free dataset ids or `channel:<name>` scopes, never file
/// contents. The actor is `system`, because this is the node reconciling on-disk state rather
/// than an operator command. A no-change reload emits nothing. Gated on `cfg.enabled`.
///
/// This does not authenticate the change, since the store carries no signature. It makes the
/// change visible in the audit stream, where it would otherwise leave no trace.
pub(crate) fn override_store_reloaded(cfg: &AuditConfig, added: &[String], removed: &[String]) {
    if !cfg.enabled || (added.is_empty() && removed.is_empty()) {
        return;
    }
    tracing::info!(
        target: "audit",
        event = "override_store_reloaded",
        event.action = "override_store.reload",
        actor = ACTOR_SYSTEM,
        added = %added.join(","),
        removed = %removed.join(","),
        "suppression store reload adopted an out-of-band change to the withhold set"
    );
}

/// Emit the audit line for an operator lifting a dataset-suppression override
/// (`dataset unhide`, alias `show`), which removes
/// `<override_dir>/suppressions/{id}.json` if present.
///
/// Emitted on every `dataset unhide` call, including a no-op on an id that carried no
/// override, so a probing lift and a real one both leave a trail. Same file-writer actor
/// caveat as [`dataset_suppressed`]. Gated on `cfg.enabled`.
///
/// The operator-supplied `--reason` is not a field here, by the rule [`dataset_suppressed`]
/// states. The lift's justification lives durably in the [`crate::lift_record`] the verb
/// writes beside the override store, and this line correlates with that record by id.
pub(crate) fn dataset_unsuppressed(cfg: &AuditConfig, dataset: &str) {
    if !cfg.enabled {
        return;
    }
    tracing::info!(
        target: "audit",
        event = "dataset_unsuppressed",
        event.action = "dataset.unsuppress",
        actor = ACTOR_OPERATOR,
        dataset,
        "operator dataset suppression override lifted"
    );
}

/// Emit the audit line for an operator channel-suppression override taking effect
/// (`channel hide` or `channel take-down` writing or refreshing
/// `<override_dir>/suppressions/channel-{name}.json`). It is the channel-scoped sibling of
/// [`dataset_suppressed`]: it withholds every dataset of the channel and pauses its ingest.
///
/// The event name is distinct from [`dataset_suppressed`] rather than shared with a
/// dataset-versus-channel field, so an auditor filtering for a channel-wide governance action
/// never has to tell a channel name from a dataset id in the same stream. Same file-writer
/// actor caveat as [`dataset_suppressed`]. Gated on `cfg.enabled`.
///
/// It carries no `reason`, for the reason [`dataset_suppressed`] states: a channel
/// justification is the same operator free text about the same data subjects, and a
/// channel-wide withhold is more likely still to name an incident, a person or a legal
/// instruction.
pub(crate) fn channel_suppressed(cfg: &AuditConfig, channel: &str, mode: SuppressMode) {
    if !cfg.enabled {
        return;
    }
    let mode = mode.as_str();
    tracing::info!(
        target: "audit",
        event = "channel_suppressed",
        event.action = "channel.suppress",
        actor = ACTOR_OPERATOR,
        channel,
        mode,
        "operator channel suppression override written"
    );
}

/// Emit the audit line for an operator lifting a channel-suppression override, which
/// removes `<override_dir>/suppressions/channel-{name}.json` if present. Emitted on every
/// `channel unhide` call, including a no-op on a channel that carried no override. Mirrors
/// [`dataset_unsuppressed`], including sending the `--reason` to the durable
/// [`crate::lift_record`] instead of here. Gated on `cfg.enabled`.
pub(crate) fn channel_unsuppressed(cfg: &AuditConfig, channel: &str) {
    if !cfg.enabled {
        return;
    }
    tracing::info!(
        target: "audit",
        event = "channel_unsuppressed",
        event.action = "channel.unsuppress",
        actor = ACTOR_OPERATOR,
        channel,
        "operator channel suppression override lifted"
    );
}

/// Emit the audit line for an operator node-local metadata-overlay override taking effect
/// (`dataset correct` writing or refreshing `<override_dir>/overlays/{id}.json`), the
/// metadata-correction sibling of [`dataset_suppressed`].
///
/// Same file-writer actor caveat as [`dataset_suppressed`]. Emitted from the CLI
/// (`correct_cmd::correct`) at the point the file write succeeds, not from the node's later
/// apply; see [`dataset_state_change`] for the separate `"OverlayApplied"` and
/// `"OverlayReverted"` line the node emits when the override lands on served metadata.
/// Records only the dataset id, never the patch content, which may carry free-text
/// corrections; the durable override file is the record of what changed. Gated on
/// `cfg.enabled`.
///
/// # The `reason` is kept here, where [`dataset_suppressed`] drops it
///
/// A `dataset correct --reason` records why a metadata field was corrected ("fixed the
/// license IRI", "narrowed `accessRights`"), and the operator convention this node is
/// documented under is that a correction reason states the metadata change, not anything
/// about a data subject. Under that convention it is not personal data, and it is useful in
/// the trail.
///
/// The asymmetry with [`dataset_suppressed`] rests on two facts:
/// 1. A suppression or take-down reason routinely is about a subject, such as an erasure
///    request or a withdrawn consent, so it is treated as personal data and kept off the log
///    stream.
/// 2. A suppression reason has somewhere else to live: the override file persists
///    `suppression::Suppression::reason`, so dropping it from the log relocates it. A
///    correction reason does not, because `overlay_override::write_file` serialises a bare
///    [`MetadataOverlay`](gdi_node_standalone_core::model::MetadataOverlay), the served
///    patch, so moving the reason there would publish it as dataset metadata. Removing the
///    field from the log would delete the record rather than move it.
///
/// If correction reasons ever start carrying subject data, relocate the field rather than
/// drop it: give the overlay store an envelope `{reason, at, patch}` beside the served patch,
/// mirroring the suppression store, so the intent record survives. That is a file-format
/// change.
pub(crate) fn metadata_overlay_set(cfg: &AuditConfig, dataset: &str, reason: Option<&str>) {
    if !cfg.enabled {
        return;
    }
    // The operator-supplied `--reason`, an empty string when omitted, so the field is
    // always present for an auditor to grep rather than conditionally absent.
    tracing::info!(
        target: "audit",
        event = "metadata_overlay_set",
        event.action = "metadata_overlay.set",
        actor = ACTOR_OPERATOR,
        dataset,
        reason = reason.unwrap_or(""),
        "operator node-local metadata overlay override written"
    );
}

/// Emit the audit line for a metadata correction taking effect on served metadata, the
/// node-side companion to [`metadata_overlay_set`], which records only the operator's intent
/// at file-write time.
///
/// This is the one point where the pre-correction state still exists. `dataset correct`
/// overwrites `<override_dir>/overlays/{id}.json` in place, so by the time a second
/// correction is authored the previous patch is gone, and the node's durable applied-overlay
/// record is the last surviving copy, replaced by this apply.
///
/// Records the names of the changed fields, plus the before and after of `access_rights` and
/// nothing else. See [`OverlayChange`] for why other values are omitted: the rest of the
/// overlay is DCAT metadata the FDP already publishes, so copying it here would add a second
/// copy of record rather than evidence, and [`metadata_overlay_set`] keeps patch content out
/// of the log stream. `access_rights` is the exception, because its value is a disclosure
/// control rather than descriptive text.
///
/// A no-op when nothing changed, so the idempotent per-poll reconcile cannot flood the trail.
/// Gated on `cfg.enabled`.
///
/// [`OverlayChange`]: gdi_node_standalone_core::overlay_store::OverlayChange
pub(crate) fn metadata_overlay_applied(
    cfg: &AuditConfig,
    dataset: &str,
    change: &gdi_node_standalone_core::overlay_store::OverlayChange,
    actor: &str,
) {
    if !cfg.enabled || change.changed_fields.is_empty() {
        return;
    }
    // Empty strings rather than absent fields when `access_rights` did not move, so the
    // shape is stable for an auditor grepping the stream.
    tracing::info!(
        target: "audit",
        event = "metadata_overlay_applied",
        event.action = "metadata_overlay.apply",
        actor,
        dataset,
        fields = change.changed_fields.join(","),
        access_rights_before = change.access_rights_before.as_deref().unwrap_or(""),
        access_rights_after = change.access_rights_after.as_deref().unwrap_or(""),
        "operator metadata correction applied to served metadata"
    );
}

/// Record that an operator resealed the at-rest key sentinel (`pme reseal`).
///
/// This is the single point at which the evidence of a master-key change is overwritten, so
/// an auditor reconstructing an at-rest incident needs to see who cleared the marker, when,
/// against which Transit mount and key, and which stored dataset was proved readable first.
/// `probed` is empty when the store held no encrypted dataset to prove against, which is
/// itself worth recording.
// Only a `pme` build can emit this: the sole caller is `pme_cmd::run_reseal`'s pme arm, and a
// node without at-rest encryption has no sentinel to reseal.
#[cfg(feature = "pme")]
pub(crate) fn pme_sentinel_resealed(
    cfg: &AuditConfig,
    transit_mount: &str,
    transit_key: &str,
    probed: Option<&std::path::Path>,
) {
    if !cfg.enabled {
        return;
    }
    tracing::info!(
        target: "audit",
        event = "pme_sentinel_resealed",
        event.action = "pme.sentinel.reseal",
        actor = ACTOR_OPERATOR,
        transit_mount,
        transit_key,
        probed_dataset = probed.map(|p| p.display().to_string()).unwrap_or_default(),
        "at-rest key sentinel resealed against the currently configured Transit key"
    );
}

/// Emit the audit line for an operator removing a node-local metadata-overlay
/// override (`dataset correct <id> --reset`).
///
/// Emitted on every `--reset` call, including a no-op on an id that carried no override, so
/// a probing reset and a real one both leave a trail. Same file-writer actor caveat as
/// [`dataset_suppressed`]. Gated on `cfg.enabled`.
pub(crate) fn metadata_overlay_cleared(cfg: &AuditConfig, dataset: &str) {
    if !cfg.enabled {
        return;
    }
    tracing::info!(
        target: "audit",
        event = "metadata_overlay_cleared",
        event.action = "metadata_overlay.clear",
        actor = ACTOR_OPERATOR,
        dataset,
        "operator node-local metadata overlay override removed"
    );
}

/// Emit the audit line for an operator `dataset purge-rejected` run erasing
/// `inbox/.rejected/` entries on demand. It is independent of the automatic
/// `[service].rejected_retention_hours` GC, whose removals go through
/// [`dataset_state_change`] instead, one line per id with the `system` actor.
///
/// One line per purge invocation rather than per entry: the operator ran a single command, so
/// `count`, the number of entries removed, is the fact worth recording. Emitted only after a
/// real purge completes, including a `count = 0` run, so a miss leaves a trail too. A
/// `--dry-run` preview removes nothing and emits nothing. Same file-writer actor caveat as
/// [`dataset_suppressed`]. Gated on `cfg.enabled`.
pub(crate) fn purge_rejected(cfg: &AuditConfig, count: usize, older_than_secs: Option<u64>) {
    if !cfg.enabled {
        return;
    }
    tracing::info!(
        target: "audit",
        event = "purge_rejected",
        event.action = "quarantine.purge",
        actor = ACTOR_OPERATOR,
        count,
        older_than_secs,
        "operator purged inbox/.rejected entries on demand"
    );
}

/// Emit the ingest-provenance audit line for a just-published package.
///
/// The node does not gate on the writer key here, because decrypting with the public
/// recipient key does not authenticate the producer, so this line is the accountability
/// record of who wrote the package and makes a later producer-key mismatch auditable.
///
/// Every successful ingest emits exactly one line, and an empty fingerprint list is not
/// silent. Silence would make two different facts identical on the wire: a plaintext
/// staging-dir path, which has no envelope and is normal on an inbox drop, and a `.tar.c4gh`
/// whose header could not be parsed, which is anomalous. `Plaintext` and `Unrecoverable`
/// therefore emit a distinct `ingest_provenance_absent` event carrying a closed-class
/// `reason`, at `warn` for the anomalous case.
///
/// Gated on `cfg.enabled`. Carries the id, channel, public fingerprints and a closed-class
/// `reason` field, never secret material. The `Unrecoverable` detail goes in the human
/// message rather than a structured field, so consumers key on `reason`.
pub(crate) fn ingest_provenance(
    cfg: &AuditConfig,
    dataset: &str,
    channel: &str,
    provenance: &WriterProvenance,
) {
    if !cfg.enabled {
        return;
    }
    match provenance {
        WriterProvenance::Recovered(writers) => {
            let writer_fingerprints = writers.join(",");
            tracing::info!(
                target: "audit",
                event = "ingest_provenance",
                event.action = "ingest.provenance",
                actor = ACTOR_SYSTEM,
                dataset,
                channel,
                writer_fingerprints = %writer_fingerprints,
                "ingest provenance: recovered package writer key(s)"
            );
        }
        // Expected on every inbox staging-dir drop: there is no crypt4gh envelope to read.
        // Recorded, not silent, so "no provenance" is a positive statement in the trail
        // rather than the absence of one.
        WriterProvenance::Plaintext => {
            tracing::info!(
                target: "audit",
                event = "ingest_provenance_absent",
                event.action = "ingest.provenance.absent",
                actor = ACTOR_SYSTEM,
                dataset,
                channel,
                reason = "plaintext",
                "ingest provenance: none (plaintext staging dir carries no crypt4gh header)"
            );
        }
        // Anomalous: the body decrypted and the package published, but the header would not
        // yield a writer key, so warn.
        WriterProvenance::Unrecoverable(detail) => {
            tracing::warn!(
                target: "audit",
                event = "ingest_provenance_absent",
                event.action = "ingest.provenance.absent",
                actor = ACTOR_SYSTEM,
                dataset,
                channel,
                reason = "recovery_failed",
                "ingest provenance: package header decrypted but yielded no writer key: {detail}"
            );
        }
    }
}

/// Emit the audit line for a package whose writer key is not allow-listed for its channel
/// under a non-`off` `[ingest].writer_policy`.
///
/// `enforced` distinguishes `enforce` (the package was quarantined, not published) from
/// `warn` (published anyway, recorded for allow-list discovery). Carries the closed-class
/// `policy` decision and the offending fingerprints (public), never key material. Gated on
/// `cfg.enabled`; emitted at `warn` because an un-trusted producer reaching ingest is an
/// operator-relevant event in both modes.
pub(crate) fn writer_key_not_allowed(
    cfg: &AuditConfig,
    dataset: &str,
    channel: &str,
    fingerprints: &[String],
    enforced: bool,
) {
    if !cfg.enabled {
        return;
    }
    let writer_fingerprints = fingerprints.join(",");
    tracing::warn!(
        target: "audit",
        event = "writer_key_not_allowed",
        event.action = "ingest.writer.reject",
        actor = ACTOR_SYSTEM,
        dataset,
        channel,
        decision = if enforced { "quarantined" } else { "published_warn" },
        writer_fingerprints = %writer_fingerprints,
        "ingest: package writer key is not in the channel allow-list"
    );
}

/// Emit the audit line for a plaintext drop, meaning a staging dir, reaching a channel under
/// a non-`off` `[ingest].writer_policy`.
///
/// A plaintext artifact carries no crypt4gh envelope and so no writer key, and can never
/// appear on the channel's allow-list. Under `enforce` it is quarantined, since it would
/// otherwise be the one input path that bypasses the configured allow-list; under `warn` it
/// is published and recorded, which is what discovery mode is for. Distinct from
/// [`writer_key_not_allowed`], because there is no offending fingerprint to report: the
/// writer is unidentified.
pub(crate) fn plaintext_drop_not_allowed(
    cfg: &AuditConfig,
    dataset: &str,
    channel: &str,
    enforced: bool,
) {
    if !cfg.enabled {
        return;
    }
    tracing::warn!(
        target: "audit",
        event = "plaintext_drop_not_allowed",
        event.action = "ingest.plaintext.reject",
        actor = ACTOR_SYSTEM,
        dataset,
        channel,
        decision = if enforced { "quarantined" } else { "published_warn" },
        "ingest: plaintext drop carries no writer key, so it cannot be allow-listed"
    );
}

/// Emit the audit line for a read of the management-plane dataset-state oracle
/// (`GET /datasets/{id}/state`).
///
/// That endpoint is the protected oracle for hidden-dataset existence, channel and error
/// class, and the most sensitive discovery surface the node exposes, so its reads need an
/// access trail just as [`beacon_query`] and [`dataset_state_change`] do. `found` is whether
/// the id resolved, so a `404` is recorded as `found=false` and a probing scan of ids is
/// visible while this line is on. Records the id, `found`, the resolved `state` or empty, and
/// `channel`, never manifest contents.
///
/// The management plane carries no request-id or tracing layer, so this line is uncorrelated
/// and has no `request_id` field. Gated on both `cfg.enabled` and `cfg.management_reads`,
/// which defaults to off: an orchestrator polls this route every tick, so the trail does not
/// carry it unless `[audit].management_reads` is turned on for id-probe visibility.
pub(crate) fn dataset_state_read(
    cfg: &AuditConfig,
    dataset: &str,
    found: bool,
    state: &str,
    channel: &str,
) {
    // The management plane's own polling, off by default via `[audit].management_reads`.
    if !cfg.enabled || !cfg.management_reads {
        return;
    }
    tracing::info!(
        target: "audit",
        event = "dataset_state_read",
        event.action = "dataset.state.read",
        actor = ACTOR_MANAGEMENT_CLIENT,
        dataset,
        found,
        state,
        channel,
        "dataset state read"
    );
}

/// Emit the audit line for a read of the whole dataset inventory (`GET /datasets`).
///
/// The node audits every other per-dataset disclosure: one id on the state oracle
/// ([`dataset_state_read`]), an FDP record ([`fairdp_read`]), the datasets a query touched
/// ([`beacon_query`]), even a read-only `identity list`. This route discloses more than any
/// of them, since it returns every dataset the node holds, hidden ones included, in one
/// unauthenticated request, so it needs a record of whether and when the inventory was
/// pulled.
///
/// Records the `route`, either `/datasets` or `/datasets/suppressed`, which disclose
/// different sets and would otherwise be indistinguishable, and the number of rows served.
/// The dataset ids follow only under `[audit].query_detail`, reusing the knob that already
/// means "record the fact, withhold the content" for beacon query coordinates. They are
/// comma-joined, the shape every `dataset_ids` field here uses, because a JSON array inside a
/// string cannot be aggregated per id by a log store. Emitted only under
/// `[audit].management_reads`, which defaults to off, because an orchestrator polls this
/// route every tick and that volume would bury the disclosures the trail exists for.
pub(crate) fn dataset_inventory_read(
    cfg: &AuditConfig,
    route: &'static str,
    count: usize,
    ids: &[String],
) {
    if !cfg.enabled || !cfg.management_reads {
        return;
    }
    let dataset_ids: &[String] = if cfg.query_detail { ids } else { &[] };
    tracing::info!(
        target: "audit",
        event = "dataset_inventory_read",
        event.action = "dataset.inventory.read",
        actor = ACTOR_MANAGEMENT_CLIENT,
        route,
        count,
        dataset_ids = %dataset_ids.join(","),
        "dataset inventory read"
    );
}

/// Emit the audit line for a read of the per-dataset query counters (`GET /stats/queries`).
///
/// Same reasoning and disclosure class as [`dataset_inventory_read`]: the counters are keyed
/// by dataset id, hidden ones included, so a caller learns the node's full inventory from
/// this route too. Records how many datasets the snapshot named; the ids follow only under
/// `[audit].query_detail`.
pub(crate) fn query_stats_read(cfg: &AuditConfig, count: usize, ids: &[String]) {
    if !cfg.enabled || !cfg.management_reads {
        return;
    }
    let dataset_ids: &[String] = if cfg.query_detail { ids } else { &[] };
    tracing::info!(
        target: "audit",
        event = "query_stats_read",
        event.action = "stats.read",
        actor = ACTOR_MANAGEMENT_CLIENT,
        count,
        dataset_ids = %dataset_ids.join(","),
        "query statistics read"
    );
}

/// Emit the audit line for a FAIR Data Point read (`/fairdp` root / catalog / dataset /
/// distribution).
///
/// The FDP plane serves the same visible catalog the beacon `datasets` endpoint does, so a
/// harvester enumerating it leaves the same access trail [`beacon_query`] leaves. Otherwise
/// the whole dataset and distribution inventory could be pulled over the RDF surface with no
/// record. Records the `resource` kind (`root`, `catalog`, `dataset` or `distribution`), the
/// target `id` (a catalog or dataset id, empty for the root) and the number of records
/// served, never metadata contents. Emitted inside the `http_request` span, so it correlates
/// to the client through that span's `request_id`. Gated on `cfg.enabled`.
pub(crate) fn fairdp_read(cfg: &AuditConfig, resource: &str, id: &str, count: usize) {
    if !cfg.enabled {
        return;
    }
    tracing::info!(
        target: "audit",
        event = "fairdp_read",
        event.action = "fairdp.read",
        actor = ACTOR_FAIRDP_CLIENT,
        resource,
        // The root has no id: omit the field rather than emit `id: ""` on every crawl.
        id = (!id.is_empty()).then_some(id),
        count,
        "fair data point read"
    );
}

/// Emit the audit line for the node entering degraded keyless mode at startup.
///
/// A node configured with `[vault]` that cannot load its key material at boot, because Vault
/// is unreachable or its token lapsed, runs keyless: encrypted-package ingest is skipped and
/// `/health/ready` stays `503`. That is a security-relevant operational state, since the node
/// stops ingesting new controlled data, so it belongs in the audit trail alongside the
/// `gdi_keyless_degraded` metric. Identities load once, so recovery is a restart and this
/// boot-time entry is the only transition. Records no key material and carries the `system`
/// actor.
///
/// Takes the `degraded` latch, like the [`crate::metrics::keyless_degraded`] gauge, and emits
/// only when it is set and only under `cfg.enabled`, so a healthy boot records nothing. It is
/// `pub` because the latch is computed in the binary's startup path.
pub fn keyless_degraded(cfg: &AuditConfig, degraded: bool) {
    if !degraded || !cfg.enabled {
        return;
    }
    tracing::info!(
        target: "audit",
        event = "keyless_degraded",
        event.action = "vault.keyless_degraded",
        actor = ACTOR_SYSTEM,
        "node started in degraded keyless mode: encrypted-package ingest skipped, readiness 503 until a restart with reachable Vault"
    );
}

/// How many replaced-entry keys one `overrides_imported` line may carry.
///
/// A cap, not a sample: `replaced_total` on the same line reports the true number, so a
/// truncated list is visibly truncated. Chosen so the common case (a handful of corrections)
/// is recorded whole while a full-store restore cannot produce an unbounded log line.
pub const MAX_AUDITED_REPLACEMENTS: usize = 20;

/// Emit the audit line for a bulk operator-override import.
///
/// Records the counts, the store root and the keys of the in-force entries this import
/// replaced, never entry bodies, since a suppression carries an operator `reason` that is
/// free text about a data subject. The keys are `<store>/<file>`, meaning dataset ids, which
/// the audit stream already records for every sibling verb.
///
/// The names are what makes the record answerable. Counts alone cannot say which withholds an
/// import replaced, which would leave a `remove` take-down becoming a `hide`, the reversal of
/// a consent-withdrawal erasure, indistinguishable from a no-op re-import.
///
/// Bounded at [`MAX_AUDITED_REPLACEMENTS`], because a bundle can carry thousands of entries
/// and an audit line must not. `replaced_total` always reports the true count, so a truncated
/// list is visibly truncated rather than silently short.
pub fn overrides_imported(
    cfg: &AuditConfig,
    root: &str,
    written: usize,
    forced: bool,
    replaced: &[String],
    replaced_total: usize,
) {
    if !cfg.enabled {
        return;
    }
    tracing::info!(
        target: "audit",
        event = "overrides_imported",
        event.action = "overrides.import",
        // The operator actor, not the system one: `overrides import` is an operator CLI
        // invocation, and this event exists to record who replaced the in-force withhold set.
        actor = ACTOR_OPERATOR,
        override_dir = %root,
        entries = written,
        force = forced,
        replaced_total,
        replaced = %replaced.join(","),
        "operator-override bundle imported: the in-force suppression/overlay set was written in bulk"
    );
}

/// Emit the audit line for an at-rest master-key mismatch: the configured PME master key no
/// longer unwraps the sentinel this node wrote, so existing at-rest data is undecryptable.
///
/// This is the one at-rest key incident the node can detect, and it is an audit event rather
/// than a plain `error!` because the operator's remedy is `pme reseal`, which emits
/// `pme_sentinel_resealed` and overwrites the key-provenance evidence. Without this line the
/// stream records the overwrite and not the incident that prompted it, so an auditor cannot
/// reconstruct why the sentinel was rewritten. Records a key-material-free detail string
/// naming which check failed, and carries the `system` actor like its siblings.
pub fn pme_master_key_mismatch(cfg: &AuditConfig, detail: &str) {
    if !cfg.enabled {
        return;
    }
    tracing::error!(
        target: "audit",
        event = "pme_master_key_mismatch",
        event.action = "pme.master_key.mismatch",
        actor = ACTOR_SYSTEM,
        detail = %detail,
        "at-rest master key does not unwrap this node's sentinel: existing PME data is undecryptable until the correct key is restored"
    );
}

/// Emit the audit line for an at-rest key check that could not be completed from local
/// state: the sentinel is unreadable, unparseable, or names a scheme this build does not
/// know.
///
/// A separate event from [`pme_master_key_mismatch`], because the two are different facts.
/// One says the key is wrong, the other says the node could not tell, and recording a
/// mismatch for a check that never ran would put a claim in the stream the node did not
/// establish. Both are in the stream for the same reason: the remedy for either is
/// `pme reseal`, which emits `pme_sentinel_resealed` and overwrites key provenance.
///
/// The gauge and the readiness flip that accompany this verdict are ephemeral, since a gauge
/// is a level rather than a record and `/health/ready` forgets on restart, so this is the only
/// durable trace. It matters most for a restored data volume whose Transit key was replaced,
/// which presents as a local fault rather than a mismatch. Records the key-material-free
/// detail string and carries the `system` actor.
pub fn pme_at_rest_unverifiable(cfg: &AuditConfig, detail: &str) {
    if !cfg.enabled {
        return;
    }
    tracing::error!(
        target: "audit",
        event = "pme_at_rest_unverifiable",
        event.action = "pme.at_rest.unverifiable",
        actor = ACTOR_SYSTEM,
        detail = %detail,
        "at-rest key check could not be completed from local state: the sentinel is unreadable, unparseable, or names an unknown scheme"
    );
}

/// Emit the audit line for a node crypt4gh identity rotation (a key-lifecycle
/// mutation).
///
/// Records the new published key `field` and the count of `retained` identities, never key
/// material, public or secret. Gated on `cfg.enabled`.
///
/// Compiled only with the `vault` feature, since the rotation flow that calls it is
/// Vault-only.
#[cfg(feature = "vault")]
pub(crate) fn identity_rotated(cfg: &AuditConfig, field: &str, retained: usize) {
    if !cfg.enabled {
        return;
    }
    tracing::info!(
        target: "audit",
        event = "identity_rotated",
        event.action = "identity.rotate",
        actor = ACTOR_OPERATOR,
        field,
        retained,
        "node identity rotated"
    );
}

/// Emit a key-lifecycle audit line for an `identity retire` run: the retired field name and
/// how many identities remain, never key material. Vault-only.
#[cfg(feature = "vault")]
pub(crate) fn identity_retired(
    cfg: &AuditConfig,
    field: &str,
    remaining: usize,
    forced: bool,
    orphaned: usize,
) {
    if !cfg.enabled {
        return;
    }
    // `forced` and `orphaned` are why this line exists. A `--force` retire that knowingly
    // leaves packages undecryptable must not emit a record identical to a safe one, and the
    // orphan names exist only here on the success path.
    tracing::info!(
        target: "audit",
        event = "identity_retired",
        event.action = "identity.retire",
        actor = ACTOR_OPERATOR,
        field,
        remaining,
        forced,
        orphaned,
        "node identity retired"
    );
}

/// Emit a key-lifecycle audit line for `identity init`: the key `field` and whether it was
/// imported or freshly minted, never key material.
///
/// Emitted by both identity postures, so it is not feature-gated. `field` is the Vault KV
/// field for a `[vault]` node (`crate::init_identity`, a plain code span because a lite
/// rustdoc has nothing to link) and the key-file path for a `[keys]` one
/// ([`crate::init_identity_file`]).
pub(crate) fn identity_initialized(cfg: &AuditConfig, field: &str, imported: bool) {
    if !cfg.enabled {
        return;
    }
    tracing::info!(
        target: "audit",
        event = "identity_initialized",
        event.action = "identity.init",
        actor = ACTOR_OPERATOR,
        field,
        imported,
        "node identity initialized"
    );
}

/// Emit a key-lifecycle audit line for `identity backup`: how many identity `fields` were
/// exported and to how many operator `recipients`, never key material, paths or the
/// destination. Vault-only.
#[cfg(feature = "vault")]
pub(crate) fn identity_backed_up(cfg: &AuditConfig, fields: usize, recipients: usize) {
    if !cfg.enabled {
        return;
    }
    tracing::info!(
        target: "audit",
        event = "identity_backed_up",
        event.action = "identity.backup",
        actor = ACTOR_OPERATOR,
        fields,
        recipients,
        "node identity backed up"
    );
}

/// Emit a key-lifecycle audit line for `identity list`: how many identity `fields` were
/// read from Vault.
///
/// Reading the identity inventory reveals which key fields exist and which is the published
/// recipient, a sensitive read and the identity-plane counterpart to [`dataset_state_read`].
/// Without it the identity plane's audit trail is mutation-only, so an inventory read through
/// a leaked serving token would leave no record. Records only the count, never key material
/// or fingerprints.
///
/// Emitted by both identity postures, so it is not feature-gated, exactly as
/// `identity_initialized` is: `identity list` has a file-backed twin (`list_identity_file`)
/// that a `vault` gate would stop from calling this, and the verb is documented as working on
/// any build and either posture.
pub(crate) fn identity_listed(cfg: &AuditConfig, fields: usize) {
    if !cfg.enabled {
        return;
    }
    tracing::info!(
        target: "audit",
        event = "identity_listed",
        event.action = "identity.list",
        actor = ACTOR_OPERATOR,
        fields,
        "node identity inventory listed"
    );
}

/// Emit an audit line for a reconcile pass, naming which trigger started it.
///
/// `POST /reconcile` makes the node reload suppressions and overlays, drain queued reingest
/// markers, rescan the inbox and wake every bucket monitor, and it sits on a management plane
/// that authenticates nothing, so the operator action most able to change what the node
/// serves needs a record. Emitted from inside `reconcile_pass`, the single implementation
/// both triggers share, so the signal and HTTP paths cannot drift.
///
/// The actor is `ACTOR_SYSTEM` rather than `ACTOR_OPERATOR`, because on the HTTP trigger the
/// node cannot attribute the request to a person; `trigger` carries what set it off. Both
/// actor constants are code spans rather than intra-doc links, since they are `pub(crate)`
/// and this item is `pub`.
///
/// It is `pub` because `reconcile_pass` lives in the binary crate, separate from this
/// library.
pub fn reconcile_requested(cfg: &AuditConfig, trigger: &'static str) {
    if !cfg.enabled {
        return;
    }
    tracing::info!(
        target: "audit",
        event = "reconcile_requested",
        event.action = "reconcile.request",
        actor = ACTOR_SYSTEM,
        trigger,
        "reconcile pass started (suppressions + overlays reloaded, reingest markers drained, \
         inbox rescanned, bucket monitors woken)"
    );
}

/// Emit the audit line for a re-ingest requested over HTTP (`POST /datasets/{id}/reingest`).
///
/// The same actor as every other management-plane call: a caller on that plane is a network
/// position, not an authenticated identity (see [`dataset_state_read`]). The dataset id is
/// the request, so it is recorded, and the reconcile pass that follows audits itself as
/// `reconcile_requested`, so an auditor sees both the ask and the act.
pub(crate) fn reingest_requested(cfg: &AuditConfig, dataset: &str) {
    if !cfg.enabled {
        return;
    }
    tracing::info!(
        target: "audit",
        event = "reingest_requested",
        event.action = "reingest.request",
        actor = ACTOR_MANAGEMENT_CLIENT,
        dataset,
        "reingest requested: the recorded source signature is cleared so the unchanged \
         package is presented to ingest again on the reconcile pass that follows"
    );
}

/// The closed set of reasons [`reingest_refused`] records.
///
/// `unknown` means no status entry (`404`). `not_retriable` means clearing the entry would
/// change nothing (`409`): it is inbox-owned, live, or has no recorded signature, including
/// when the entry changes between the verdict and the clear.
pub(crate) const REINGEST_REFUSAL_REASONS: [&str; 2] = ["unknown", "not_retriable"];

/// Emit the audit line for a re-ingest refused over HTTP (`POST /datasets/{id}/reingest`
/// answering `404` or `409`).
///
/// The sibling oracle `GET /datasets/{id}/state` audits a miss so that a scan probing for ids
/// is visible. This route asks the same existence question on the same unauthenticated plane
/// and outside the pacing window, so an unrecorded refusal would make it an unaudited,
/// unpaced existence oracle. `reason` is one of [`REINGEST_REFUSAL_REASONS`].
pub(crate) fn reingest_refused(cfg: &AuditConfig, dataset: &str, reason: &'static str) {
    debug_assert!(REINGEST_REFUSAL_REASONS.contains(&reason));
    if !cfg.enabled {
        return;
    }
    tracing::info!(
        target: "audit",
        event = "reingest_refused",
        event.action = "reingest.refuse",
        actor = ACTOR_MANAGEMENT_CLIENT,
        dataset,
        reason,
        "reingest refused: nothing was cleared"
    );
}

/// Emit an audit line for a runtime diagnostic-logging change.
///
/// Raising verbosity changes what this node writes about every request it serves, and
/// `POST /log-level` can do it unauthenticated. That is a change to the evidence trail
/// itself, so it belongs in that trail. Records the resulting state and the applied filter,
/// never the request that asked for it.
///
/// `trigger` distinguishes `sigusr2`, an operator with shell access, from `http`. The actor
/// is `ACTOR_SYSTEM` for the same reason as [`reconcile_requested`].
///
/// It is `pub` because the `SIGUSR2` handler that calls it lives in the binary crate,
/// separate from this library.
pub fn log_level_changed(cfg: &AuditConfig, trigger: &'static str, verbose: bool, filter: &str) {
    if !cfg.enabled {
        return;
    }
    tracing::info!(
        target: "audit",
        event = "log_level_changed",
        event.action = "log.level.change",
        actor = ACTOR_SYSTEM,
        trigger,
        verbose,
        filter,
        "runtime diagnostic logging changed"
    );
}

/// Emit an audit line for a PME DEK-cache flush, naming which trigger caused it.
///
/// The flush propagates a Vault-side key revocation, a bumped Transit
/// `min_decryption_version`, into the running node by dropping every cached data-encryption
/// key. The audit trail has to show when a revocation was applied to a given node, and the
/// flush otherwise lands only in the general `info` log, invisible to a pipeline filtering
/// `target: "audit"`. Records no key material. It is `pub` because the `SIGHUP` handler that
/// calls it lives in the binary's startup path, like [`keyless_degraded`].
///
/// `trigger` mirrors `config_reloaded`'s, because the flush has the same two triggers and
/// they are not equally attributable: `SIGHUP` is an operator with shell access, while
/// `POST /reload` is whoever can reach the management listener, which authenticates nothing.
/// The actor is therefore `ACTOR_SYSTEM`, the node applying a revocation, with `trigger`
/// carrying what set it off.
#[cfg(feature = "pme")]
pub fn pme_cache_flushed(cfg: &AuditConfig, trigger: &'static str) {
    if !cfg.enabled {
        return;
    }
    tracing::info!(
        target: "audit",
        event = "pme_cache_flushed",
        event.action = "pme.cache.flush",
        actor = ACTOR_SYSTEM,
        trigger,
        "PME DEK cache flushed (key-revocation propagation)"
    );
}

/// Emit a key-lifecycle audit line for `identity restore`: how many identity `fields` were
/// restored into Vault, never key material, paths or the operator key. A restore provisions
/// the irreplaceable node secret onto a fresh node, so it leaves the same trail as
/// `identity init`. Vault-only.
#[cfg(feature = "vault")]
pub(crate) fn identity_restored(cfg: &AuditConfig, fields: usize) {
    if !cfg.enabled {
        return;
    }
    tracing::info!(
        target: "audit",
        event = "identity_restored",
        event.action = "identity.restore",
        actor = ACTOR_OPERATOR,
        fields,
        "node identity restored"
    );
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    /// The operator runbook, whose audit-event block must equal the catalogue.
    const OPERATING_MD: &str = include_str!("../../../docs/operating.md");
    const DOC_START: &str = "<!-- audit-event-names:start -->";
    const DOC_END: &str = "<!-- audit-event-names:end -->";

    /// Every `event` field literal emitted in `src`, scanning code lines only.
    ///
    /// Comment lines are skipped. A scan over raw text would be satisfiable, and breakable,
    /// by prose: a doc comment naming the field pattern would register as an emit site, and
    /// this guard would then pass or fail for the wrong reason.
    fn events_in_source(src: &str) -> BTreeSet<&str> {
        const NEEDLE: &str = "event = \"";
        let mut found = BTreeSet::new();
        for line in src.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            let mut rest = line;
            while let Some(i) = rest.find(NEEDLE) {
                rest = &rest[i + NEEDLE.len()..];
                if let Some(j) = rest.find('"') {
                    found.insert(&rest[..j]);
                    rest = &rest[j..];
                } else {
                    break;
                }
            }
        }
        found
    }

    /// Backticked names inside the runbook's machine-checked block.
    fn events_in_runbook() -> BTreeSet<&'static str> {
        let start = OPERATING_MD
            .find(DOC_START)
            .expect("docs/operating.md lost its `audit-event-names:start` marker")
            + DOC_START.len();
        let end = OPERATING_MD
            .find(DOC_END)
            .expect("docs/operating.md lost its `audit-event-names:end` marker");
        OPERATING_MD[start..end]
            .split('`')
            .skip(1)
            .step_by(2)
            .collect()
    }

    /// Every event literal in the crate, excluding each file's trailing `#[cfg(test)]`
    /// module, where fixtures emit fake events.
    ///
    /// Walks `src/` at test time rather than `include_str!`-ing a fixed list, so a new file
    /// that starts emitting audit events cannot escape the catalogue by not being named
    /// here.
    fn events_in_crate() -> BTreeSet<String> {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }
        let mut files = Vec::new();
        walk(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut files,
        );
        assert!(
            !files.is_empty(),
            "found no crate sources — the walker is broken"
        );

        let mut found = BTreeSet::new();
        for file in files {
            let Ok(text) = std::fs::read_to_string(&file) else {
                continue;
            };
            // Cut the trailing test module, so fixture emits do not count as production
            // sites. Keyed on `#[cfg(test)]` immediately followed by `mod`, not on any
            // `#[cfg(test)]`: this file puts one on `AUDIT_EVENTS`, and cutting there would
            // drop every real emit while the scan still looked as though it had run.
            let production = text
                .find("#[cfg(test)]\nmod ")
                .map_or(text.as_str(), |i| &text[..i]);
            for name in events_in_source(production) {
                found.insert(name.to_owned());
            }
        }
        found
    }

    /// The catalogue must name exactly the events the crate emits, no more and no fewer, so
    /// an unlisted one fails here rather than reaching an operator's log pipeline
    /// unannounced.
    ///
    /// The scan covers the whole crate, not just this file: `app.rs` also emits on the
    /// `audit` target, and a one-file scan cannot enforce a crate-wide claim.
    #[test]
    fn audit_event_catalogue_covers_every_emit_site() {
        let emitted = events_in_crate();
        assert!(
            !emitted.is_empty(),
            "the emit-site scan found nothing — the scanner is broken, not the catalogue"
        );
        let declared: BTreeSet<String> = AUDIT_EVENTS.iter().map(|s| (*s).to_owned()).collect();
        assert_eq!(
            emitted, declared,
            "AUDIT_EVENTS disagrees with the `event = \"…\"` literals in the crate"
        );
        let mut sorted: Vec<&str> = AUDIT_EVENTS.to_vec();
        sorted.sort_unstable();
        assert_eq!(AUDIT_EVENTS, sorted.as_slice(), "keep AUDIT_EVENTS sorted");
    }

    /// Audit is a compliance surface, so the runbook's catalogue is pinned to the code and
    /// scoped to the marker block: a name mentioned in prose elsewhere in the runbook must
    /// not satisfy this check.
    #[test]
    fn audit_event_catalogue_matches_the_runbook() {
        let documented = events_in_runbook();
        let declared: BTreeSet<&str> = AUDIT_EVENTS.iter().copied().collect();
        assert_eq!(
            declared, documented,
            "docs/operating.md's `audit-event-names` block disagrees with AUDIT_EVENTS"
        );
    }

    fn capture(cfg: &AuditConfig) -> String {
        let mut params = serde_json::Map::new();
        params.insert(
            "referenceName".to_owned(),
            serde_json::Value::String("3".to_owned()),
        );
        params.insert("start".to_owned(), serde_json::json!([45_823_239]));
        let dataset_ids = vec!["GDI-EE-UTARTU-1".to_owned(), "GDI-EE-UTARTU-2".to_owned()];
        test_util::capture_json_logs(|| {
            beacon_query(
                cfg,
                &BeaconQueryAudit {
                    entry_type: "genomicVariant",
                    granularity: "count",
                    test_mode: false,
                    exists: true,
                    num_results: 1,
                    assembly: Some("GRCh38"),
                    dataset_ids: &dataset_ids,
                    skip: 0,
                    limit: 10,
                    include: Some("HIT"),
                    elapsed_us: 3,
                    params: Some(&params),
                },
            );
        })
        .1
    }

    #[test]
    fn detail_off_withholds_query_content() {
        let out = capture(&AuditConfig {
            enabled: true,
            query_detail: false,
            management_reads: true,
        });
        assert!(
            out.contains("beacon query"),
            "the audit line is emitted: {out}"
        );
        assert!(out.contains("genomicVariant"), "{out}");
        assert!(
            !out.contains("referenceName"),
            "query content must be withheld by default: {out}"
        );
    }

    #[test]
    fn detail_on_includes_query_content() {
        let out = capture(&AuditConfig {
            enabled: true,
            query_detail: true,
            management_reads: true,
        });
        assert!(
            out.contains("referenceName"),
            "query_detail logs the request parameters: {out}"
        );
    }

    #[test]
    fn always_on_detail_present_without_query_detail() {
        let out = capture(&AuditConfig {
            enabled: true,
            query_detail: false,
            management_reads: true,
        });
        for needle in [
            "GRCh38",
            "datasets_scanned",
            "GDI-EE-UTARTU-1",
            "\"skip\":0",
            "\"limit\":10",
            "\"include\":\"HIT\"",
            "elapsed_us",
            // A public query is stamped with the `beacon-client` actor.
            "\"actor\":\"beacon-client\"",
        ] {
            assert!(out.contains(needle), "missing {needle}: {out}");
        }
        // Raw coordinates are still withheld without query_detail.
        assert!(!out.contains("referenceName"), "query withheld: {out}");
    }

    #[test]
    fn answered_line_carries_event_tag() {
        // The answered line carries a stable, machine-filterable event tag, matching the
        // rejected line, so a pipeline can classify the whole `audit` stream by a structured
        // field rather than by the message string.
        let out = capture(&AuditConfig {
            enabled: true,
            query_detail: false,
            management_reads: true,
        });
        assert!(
            out.contains("\"event\":\"beacon_query\""),
            "answered line tagged with event=beacon_query: {out}"
        );
    }

    #[test]
    fn rejected_query_records_code_and_reason() {
        let cfg = AuditConfig {
            enabled: true,
            query_detail: false,
            management_reads: true,
        };
        let mut params = serde_json::Map::new();
        params.insert(
            "referenceName".to_owned(),
            serde_json::Value::String("3".to_owned()),
        );
        let out = capture_with(|| {
            beacon_query_rejected(
                &cfg,
                "genomicVariant",
                400,
                "unsupported referenceName",
                2,
                Some(&params),
            );
        });
        assert!(out.contains("beacon_query_rejected"), "event: {out}");
        assert!(
            out.contains("\"actor\":\"beacon-client\""),
            "rejected query stamped with the beacon-client actor: {out}"
        );
        assert!(out.contains("genomicVariant"), "{out}");
        assert!(out.contains("\"code\":400"), "code: {out}");
        assert!(out.contains("unsupported referenceName"), "reason: {out}");
        // The raw `query` field is withheld without `query_detail`: the reason names the
        // parameter, but the params object itself is not logged.
        assert!(!out.contains("\"query\""), "params withheld: {out}");
    }

    #[test]
    fn rejected_query_detail_includes_params() {
        let cfg = AuditConfig {
            enabled: true,
            query_detail: true,
            management_reads: true,
        };
        let mut params = serde_json::Map::new();
        params.insert("start".to_owned(), serde_json::json!([45_823_239]));
        let out = capture_with(|| {
            beacon_query_rejected(&cfg, "genomicVariant", 400, "bad", 1, Some(&params));
        });
        assert!(out.contains("45823239"), "params logged with detail: {out}");
    }

    #[test]
    fn rejected_query_disabled_emits_nothing() {
        let out = capture_with(|| {
            beacon_query_rejected(
                &AuditConfig {
                    enabled: false,
                    query_detail: false,
                    management_reads: true,
                },
                "genomicVariant",
                400,
                "bad",
                1,
                None,
            );
        });
        assert!(out.is_empty(), "disabled emits nothing: {out:?}");
    }

    /// Capture JSON audit output produced by `f`.
    fn capture_lines(f: impl FnOnce()) -> String {
        test_util::capture_json_logs(f).1
    }

    #[test]
    fn dataset_state_read_audits_hit_and_miss() {
        let cfg = AuditConfig {
            enabled: true,
            query_detail: false,
            management_reads: true,
        };
        let out = capture_lines(|| {
            dataset_state_read(
                &cfg,
                "GDI-EE-UTARTU-20260409143052837",
                true,
                "hidden",
                "inbox",
            );
            dataset_state_read(&cfg, "does-not-exist", false, "", "");
        });
        assert!(out.contains("dataset_state_read"), "event emitted: {out}");
        assert!(
            out.contains("\"actor\":\"management-client\""),
            "a management-plane read is stamped with the management-client actor: {out}"
        );
        assert!(out.contains("hidden"), "resolved state recorded: {out}");
        // The miss is recorded too (a probing scan stays visible).
        assert!(out.contains("does-not-exist"), "miss recorded: {out}");
    }

    /// Both refusal arms of `POST /datasets/{id}/reingest` leave a record, with the
    /// closed-set reason, on the same terms as the state oracle's miss.
    #[test]
    fn reingest_refused_records_the_dataset_and_a_closed_set_reason() {
        // `management_reads` is off here: a refused action is not a management read, so
        // that knob must not swallow it.
        let cfg = AuditConfig {
            enabled: true,
            query_detail: false,
            management_reads: false,
        };
        let out = capture_lines(|| {
            reingest_refused(&cfg, "GDI-EE-UTARTU-20260409143052999", "unknown");
            reingest_refused(&cfg, "GDI-EE-UTARTU-20260409143052838", "not_retriable");
        });
        let lines: Vec<serde_json::Value> = out
            .lines()
            .map(|l| serde_json::from_str(l).expect("json log line"))
            .collect();
        assert_eq!(lines.len(), 2, "one line per refusal: {out}");
        for (line, dataset, reason) in [
            (&lines[0], "GDI-EE-UTARTU-20260409143052999", "unknown"),
            (
                &lines[1],
                "GDI-EE-UTARTU-20260409143052838",
                "not_retriable",
            ),
        ] {
            assert_eq!(line["fields"]["event"], "reingest_refused", "{line}");
            assert_eq!(line["fields"]["actor"], ACTOR_MANAGEMENT_CLIENT, "{line}");
            assert_eq!(line["fields"]["dataset"], dataset, "{line}");
            assert_eq!(line["fields"]["reason"], reason, "{line}");
            let recorded = line["fields"]["reason"]
                .as_str()
                .expect("reason is a string field");
            assert!(
                REINGEST_REFUSAL_REASONS.contains(&recorded),
                "the reason is one of the closed set: {line}"
            );
        }
        let silent = capture_lines(|| {
            reingest_refused(
                &AuditConfig {
                    enabled: false,
                    query_detail: false,
                    management_reads: false,
                },
                "x",
                "unknown",
            );
        });
        assert!(
            silent.is_empty(),
            "disabled audit emits nothing: {silent:?}"
        );
    }

    #[test]
    fn management_reads_default_off_suppresses_the_three_read_lines() {
        // The default (`management_reads: false`) exempts the orchestrator's own
        // reconciliation polling; a deployment that wants the trail sets it true.
        let cfg = AuditConfig {
            enabled: true,
            query_detail: false,
            management_reads: false,
        };
        let out = capture_lines(|| {
            dataset_state_read(&cfg, "x", true, "visible", "inbox");
            dataset_inventory_read(&cfg, "/datasets", 3, &["a".to_owned()]);
            query_stats_read(&cfg, 3, &["a".to_owned()]);
        });
        assert!(
            out.is_empty(),
            "management reads suppressed by default: {out:?}"
        );
    }

    #[test]
    fn dataset_state_read_disabled_emits_nothing() {
        let out = capture_lines(|| {
            dataset_state_read(
                &AuditConfig {
                    enabled: false,
                    query_detail: false,
                    management_reads: true,
                },
                "x",
                true,
                "visible",
                "inbox",
            );
        });
        assert!(out.is_empty(), "disabled audit emits nothing: {out:?}");
    }

    #[test]
    fn disabled_emits_nothing() {
        let out = capture(&AuditConfig {
            enabled: false,
            query_detail: true,
            management_reads: true,
        });
        assert!(out.is_empty(), "disabled audit must emit no line: {out}");
    }

    #[test]
    fn override_store_reloaded_audits_the_out_of_band_diff() {
        let cfg = AuditConfig {
            enabled: true,
            query_detail: false,
            management_reads: true,
        };
        let out = capture_lines(|| {
            override_store_reloaded(
                &cfg,
                &["GDI-EE-UTARTU-forged=hide".to_owned()],
                &["GDI-EE-UTARTU-lifted".to_owned()],
            );
        });
        assert!(
            out.contains("override_store_reloaded"),
            "the event fires: {out}"
        );
        assert!(
            out.contains("system"),
            "actor is the node, not an operator: {out}"
        );
        assert!(
            out.contains("GDI-EE-UTARTU-forged=hide"),
            "the added withhold is recorded: {out}"
        );
        assert!(
            out.contains("GDI-EE-UTARTU-lifted"),
            "the removed withhold is recorded: {out}"
        );
    }

    #[test]
    fn override_store_reloaded_is_silent_on_a_no_change_reload() {
        // A reload that changed nothing must not spam the audit stream.
        let out = capture_lines(|| {
            override_store_reloaded(
                &AuditConfig {
                    enabled: true,
                    query_detail: false,
                    management_reads: true,
                },
                &[],
                &[],
            );
        });
        assert!(out.is_empty(), "an unchanged reload emits nothing: {out:?}");
    }

    /// Capture the `audit`-target JSON emitted while running `f`.
    fn capture_with(f: impl FnOnce()) -> String {
        test_util::capture_json_logs(f).1
    }

    /// A sidecar release is alarmed as well as recorded; a sidecar withhold is only
    /// recorded.
    ///
    /// Publishing is the direction a missing writer identity can be abused in, and failing
    /// closed is the safe one. Both directions still leave the audit line, so the alarm
    /// cannot be mistaken for the record.
    #[test]
    fn a_sidecar_release_is_alarmed_and_a_withhold_is_only_recorded() {
        let cfg = AuditConfig {
            enabled: true,
            query_detail: false,
            // Inert here: `sidecar_state_change` is a state-change event gated on `enabled`,
            // not a management-plane read.
            management_reads: false,
        };

        let released =
            capture_with(|| sidecar_state_change(&cfg, "ds-1", "primary", DatasetState::Visible));
        assert!(
            released.contains("dataset.sidecar.release"),
            "a release names the action a ticket is routed on: {released}"
        );
        assert!(
            released.contains("\"alert\":true"),
            "a release asks for the Alert tag: {released}"
        );
        assert!(
            released.contains("dataset_state_change") && released.contains("sidecar-state-change"),
            "the audit line is still emitted beside the alarm: {released}"
        );

        let withheld =
            capture_with(|| sidecar_state_change(&cfg, "ds-1", "primary", DatasetState::Hidden));
        assert!(
            !withheld.contains("dataset.sidecar.release"),
            "failing closed is not an alarm: {withheld}"
        );
        assert!(
            withheld.contains("sidecar-state-change"),
            "...but it is still recorded: {withheld}"
        );
    }

    /// Turning the audit stream off drops the record, never the alarm.
    #[test]
    fn a_sidecar_release_alarms_even_with_the_audit_stream_disabled() {
        let off = AuditConfig {
            enabled: false,
            query_detail: false,
            // Inert here: `sidecar_state_change` is a state-change event gated on `enabled`,
            // not a management-plane read.
            management_reads: false,
        };
        let out =
            capture_with(|| sidecar_state_change(&off, "ds-1", "primary", DatasetState::Visible));
        assert!(
            out.contains("dataset.sidecar.release"),
            "opting out of the audit record is not opting out of being told: {out}"
        );
        assert!(
            !out.contains("dataset_state_change"),
            "the audit line stays gated on [audit].enabled: {out}"
        );
    }

    #[test]
    fn dataset_state_change_records_id_state_and_cause() {
        let cfg = AuditConfig {
            enabled: true,
            query_detail: false,
            management_reads: true,
        };
        let out =
            capture_with(|| dataset_state_change(&cfg, "ds-1", "inbox", "Published", "ingested"));
        assert!(
            out.contains("dataset_state_change"),
            "event tag present: {out}"
        );
        assert!(
            out.contains("\"actor\":\"system\""),
            "an automated ingest outcome is stamped with the system actor: {out}"
        );
        assert!(out.contains("ds-1"), "{out}");
        assert!(out.contains("Published"), "{out}");
        assert!(out.contains("ingested"), "{out}");
    }

    /// The line carries the closed-set facts an auditor needs, and not the operator's
    /// free-text justification.
    ///
    /// The `reason` is personal data about the subject the withholding was for, and
    /// `target: "audit"` renders to stderr, which reaches the log aggregator and its backups,
    /// outside the retention policy that governs the override file.
    ///
    /// `dataset` and `mode` still correlate the line with the override file, which remains
    /// the durable record of why.
    #[test]
    fn dataset_suppressed_records_actor_and_mode_but_never_the_reason() {
        let cfg = AuditConfig {
            enabled: true,
            query_detail: false,
            management_reads: true,
        };
        let out = capture_with(|| {
            dataset_suppressed(&cfg, "ds-1", SuppressMode::Hide);
        });
        assert!(
            out.contains("\"event\":\"dataset_suppressed\""),
            "event tag present: {out}"
        );
        assert!(
            out.contains("\"actor\":\"operator\""),
            "the file-writer is stamped with the operator actor: {out}"
        );
        assert!(out.contains("ds-1"), "{out}");
        assert!(out.contains("\"mode\":\"hide\""), "{out}");
        assert!(
            !out.contains("\"reason\""),
            "the operator justification is personal data and must never reach the log \
             stream: {out}"
        );
    }

    #[test]
    fn dataset_suppressed_records_remove_mode() {
        let out = capture_with(|| {
            dataset_suppressed(&enabled_audit(), "ds-2", SuppressMode::Remove);
        });
        assert!(out.contains("\"mode\":\"remove\""), "{out}");
    }

    #[test]
    fn dataset_suppressed_disabled_emits_nothing() {
        let cfg = AuditConfig {
            enabled: false,
            query_detail: false,
            management_reads: true,
        };
        let out = capture_with(|| dataset_suppressed(&cfg, "ds-1", SuppressMode::Hide));
        assert!(out.is_empty(), "disabled audit must emit no line: {out}");
    }

    #[test]
    fn dataset_unsuppressed_records_actor_and_id() {
        let out = capture_with(|| {
            dataset_unsuppressed(&enabled_audit(), "ds-1");
        });
        assert!(
            out.contains("\"event\":\"dataset_unsuppressed\""),
            "event tag present: {out}"
        );
        assert!(
            out.contains("\"actor\":\"operator\""),
            "the file-writer is stamped with the operator actor: {out}"
        );
        assert!(out.contains("ds-1"), "{out}");
        assert!(
            !out.contains("reason"),
            "the lift justification is personal data and lives in the lift record, never \
             this stream — the same rule dataset_suppressed applies: {out}"
        );
    }

    #[test]
    fn dataset_unsuppressed_disabled_emits_nothing() {
        let cfg = AuditConfig {
            enabled: false,
            query_detail: false,
            management_reads: true,
        };
        let out = capture_with(|| dataset_unsuppressed(&cfg, "ds-1"));
        assert!(out.is_empty(), "disabled audit must emit no line: {out}");
    }

    /// The channel twin of `dataset_suppressed_records_actor_and_mode_but_never_the_reason`.
    /// A channel-wide justification is the same operator free text about the same data
    /// subjects, so it must not reach the log stream either.
    #[test]
    fn channel_suppressed_records_actor_channel_and_mode_but_never_the_reason() {
        let out = capture_with(|| {
            channel_suppressed(&enabled_audit(), "primary", SuppressMode::Remove);
        });
        assert!(
            out.contains("\"event\":\"channel_suppressed\""),
            "event tag present: {out}"
        );
        assert!(
            out.contains("\"actor\":\"operator\""),
            "the file-writer is stamped with the operator actor: {out}"
        );
        assert!(out.contains("primary"), "{out}");
        assert!(out.contains("\"mode\":\"remove\""), "{out}");
        assert!(
            !out.contains("\"reason\""),
            "the operator justification is personal data and must never reach the log \
             stream: {out}"
        );
    }

    #[test]
    fn channel_suppressed_disabled_emits_nothing() {
        let cfg = AuditConfig {
            enabled: false,
            query_detail: false,
            management_reads: true,
        };
        let out = capture_with(|| channel_suppressed(&cfg, "primary", SuppressMode::Hide));
        assert!(out.is_empty(), "disabled audit must emit no line: {out}");
    }

    #[test]
    fn channel_unsuppressed_records_actor_and_channel() {
        let out = capture_with(|| channel_unsuppressed(&enabled_audit(), "primary"));
        assert!(
            out.contains("\"event\":\"channel_unsuppressed\""),
            "event tag present: {out}"
        );
        assert!(
            out.contains("\"actor\":\"operator\""),
            "the file-writer is stamped with the operator actor: {out}"
        );
        assert!(out.contains("primary"), "{out}");
        assert!(
            !out.contains("reason"),
            "the lift justification lives in the lift record, never this stream: {out}"
        );
    }

    #[test]
    fn channel_unsuppressed_disabled_emits_nothing() {
        let cfg = AuditConfig {
            enabled: false,
            query_detail: false,
            management_reads: true,
        };
        let out = capture_with(|| channel_unsuppressed(&cfg, "primary"));
        assert!(out.is_empty(), "disabled audit must emit no line: {out}");
    }

    #[test]
    fn dataset_state_change_disabled_emits_nothing() {
        let cfg = AuditConfig {
            enabled: false,
            query_detail: false,
            management_reads: true,
        };
        let out =
            capture_with(|| dataset_state_change(&cfg, "ds-1", "inbox", "error", "decrypt-failed"));
        assert!(out.is_empty(), "disabled audit must emit no line: {out}");
    }

    #[test]
    fn keyless_degraded_records_system_actor() {
        let cfg = AuditConfig {
            enabled: true,
            query_detail: false,
            management_reads: true,
        };
        let out = capture_with(|| keyless_degraded(&cfg, true));
        assert!(
            out.contains("\"event\":\"keyless_degraded\""),
            "event tag present: {out}"
        );
        // A boot-time automated node process, not an operator action.
        assert!(
            out.contains("\"actor\":\"system\""),
            "the degrade is stamped with the system actor: {out}"
        );
    }

    #[test]
    fn keyless_degraded_healthy_boot_emits_nothing() {
        // A healthy boot records nothing; only the degraded transition is audited.
        let cfg = AuditConfig {
            enabled: true,
            query_detail: false,
            management_reads: true,
        };
        let out = capture_with(|| keyless_degraded(&cfg, false));
        assert!(out.is_empty(), "a healthy boot emits no line: {out:?}");
    }

    #[test]
    fn keyless_degraded_disabled_emits_nothing() {
        let out = capture_with(|| {
            keyless_degraded(
                &AuditConfig {
                    enabled: false,
                    query_detail: false,
                    management_reads: true,
                },
                true,
            );
        });
        assert!(out.is_empty(), "disabled audit must emit no line: {out:?}");
    }

    #[cfg(feature = "vault")]
    #[test]
    fn identity_rotated_records_field_and_count_only() {
        let cfg = AuditConfig {
            enabled: true,
            query_detail: false,
            management_reads: true,
        };
        let out = capture_with(|| identity_rotated(&cfg, "c4gh-0000000000000002", 2));
        assert!(out.contains("identity_rotated"), "event tag present: {out}");
        assert!(
            out.contains("\"actor\":\"operator\""),
            "an operator CLI action is stamped with the operator actor: {out}"
        );
        assert!(
            out.contains("c4gh-0000000000000002"),
            "new field recorded: {out}"
        );
        assert!(
            out.contains("\"retained\":2"),
            "retained count recorded: {out}"
        );
    }

    #[cfg(feature = "vault")]
    #[test]
    fn identity_retired_distinguishes_a_forced_retire_from_a_safe_one() {
        let cfg = AuditConfig {
            enabled: true,
            query_detail: false,
            management_reads: true,
        };
        let out = capture_with(|| identity_retired(&cfg, "c4gh-0000000000000001", 1, false, 0));
        assert!(out.contains("identity_retired"), "event tag present: {out}");
        assert!(
            out.contains("c4gh-0000000000000001"),
            "retired field recorded: {out}"
        );
        assert!(
            out.contains("\"remaining\":1"),
            "remaining count recorded: {out}"
        );

        // A `--force` retire that knowingly orphans packages must not emit a line identical
        // to the safe one above, or the most consequential operator action the node supports
        // would be indistinguishable from a routine one.
        let forced = capture_with(|| identity_retired(&cfg, "c4gh-0000000000000001", 1, true, 3));
        assert!(
            forced.contains("\"forced\":true") && forced.contains("\"orphaned\":3"),
            "a forced retire must be distinguishable and carry the orphan count: {forced}"
        );
        assert_ne!(
            out, forced,
            "the two outcomes must not produce the same audit record"
        );
    }

    #[cfg(feature = "vault")]
    #[test]
    fn identity_initialized_records_field_and_source() {
        let cfg = AuditConfig {
            enabled: true,
            query_detail: false,
            management_reads: true,
        };
        let out = capture_with(|| identity_initialized(&cfg, "c4gh-0000000000000001", false));
        assert!(
            out.contains("identity_initialized"),
            "event tag present: {out}"
        );
        assert!(
            out.contains("c4gh-0000000000000001"),
            "minted field recorded: {out}"
        );
        assert!(
            out.contains("\"imported\":false"),
            "source flag recorded: {out}"
        );
    }

    #[cfg(feature = "vault")]
    #[test]
    fn identity_backed_up_records_counts_only() {
        let cfg = AuditConfig {
            enabled: true,
            query_detail: false,
            management_reads: true,
        };
        let out = capture_with(|| identity_backed_up(&cfg, 3, 2));
        assert!(
            out.contains("identity_backed_up"),
            "event tag present: {out}"
        );
        assert!(out.contains("\"fields\":3"), "fields count recorded: {out}");
        assert!(
            out.contains("\"recipients\":2"),
            "recipients count recorded: {out}"
        );
    }

    #[cfg(feature = "vault")]
    #[test]
    fn identity_restored_records_count_only() {
        let cfg = AuditConfig {
            enabled: true,
            query_detail: false,
            management_reads: true,
        };
        let out = capture_with(|| identity_restored(&cfg, 3));
        assert!(
            out.contains("identity_restored"),
            "event tag present: {out}"
        );
        assert!(
            out.contains("\"actor\":\"operator\""),
            "an operator CLI action is stamped with the operator actor: {out}"
        );
        assert!(
            out.contains("\"fields\":3"),
            "restored field count recorded: {out}"
        );
    }

    #[cfg(feature = "vault")]
    #[test]
    fn identity_rotated_disabled_emits_nothing() {
        let cfg = AuditConfig {
            enabled: false,
            query_detail: false,
            management_reads: true,
        };
        let out = capture_with(|| identity_rotated(&cfg, "c4gh-0000000000000002", 2));
        assert!(out.is_empty(), "disabled audit must emit no line: {out}");
    }

    fn enabled_audit() -> AuditConfig {
        AuditConfig {
            enabled: true,
            query_detail: false,
            management_reads: true,
        }
    }

    #[test]
    fn recovered_writer_key_emits_the_provenance_line() {
        let provenance = WriterProvenance::Recovered(vec!["sha256:aa".to_owned()]);
        let out =
            capture_with(|| ingest_provenance(&enabled_audit(), "GDI-1", "inbox", &provenance));
        assert!(
            out.contains("\"event\":\"ingest_provenance\""),
            "a recovered writer key emits the provenance event: {out}"
        );
        assert!(
            out.contains("sha256:aa"),
            "the fingerprint is on the line: {out}"
        );
    }

    #[test]
    fn multiple_recovered_writer_keys_are_comma_joined() {
        let provenance =
            WriterProvenance::Recovered(vec!["sha256:aa".to_owned(), "sha256:bb".to_owned()]);
        let out =
            capture_with(|| ingest_provenance(&enabled_audit(), "GDI-1", "inbox", &provenance));
        assert!(
            out.contains("sha256:aa,sha256:bb"),
            "multi-recipient packages join fingerprints with a comma: {out}"
        );
    }

    #[test]
    fn plaintext_ingest_emits_an_absent_line_not_silence() {
        // An empty fingerprint list must not return silently: a routine inbox drop and an
        // unreadable crypt4gh header would then be the same absent line on the wire. Both
        // are positively recorded.
        let out = capture_with(|| {
            ingest_provenance(
                &enabled_audit(),
                "GDI-1",
                "inbox",
                &WriterProvenance::Plaintext,
            );
        });
        assert!(
            out.contains("\"event\":\"ingest_provenance_absent\""),
            "a plaintext staging dir emits the absent event, not nothing: {out}"
        );
        assert!(
            out.contains("\"reason\":\"plaintext\""),
            "the closed-class reason distinguishes it from a failed recovery: {out}"
        );
    }

    /// The correction audit line must name the principal that actually authored the change.
    ///
    /// `metadata_overlay_applied` fires for provider-authored inbox and bucket sidecars as
    /// well as operator corrections, so a hard-coded operator actor would record a data
    /// provider broadening `access_rights` as an administrator action. The actor comes from
    /// `OverlaySource`, which also picks the provenance tag, so the two cannot disagree.
    #[test]
    fn overlay_correction_names_the_authoring_principal() {
        use crate::state::OverlaySource;
        let change = gdi_node_standalone_core::overlay_store::OverlayChange {
            changed_fields: vec!["access_rights"],
            access_rights_before: Some("RESTRICTED".to_owned()),
            access_rights_after: Some("PUBLIC".to_owned()),
        };

        let operator = capture_with(|| {
            metadata_overlay_applied(
                &enabled_audit(),
                "GDI-1",
                &change,
                OverlaySource::OperatorOverride.actor(),
            );
        });
        assert!(
            operator.contains("\"actor\":\"operator\""),
            "a node-local `dataset correct` is an operator action: {operator}"
        );

        for source in [OverlaySource::InboxSidecar, OverlaySource::Bucket] {
            let out = capture_with(|| {
                metadata_overlay_applied(&enabled_audit(), "GDI-1", &change, source.actor());
            });
            assert!(
                out.contains("\"actor\":\"system\""),
                "a provider-authored {source:?} overlay is applied by the background \
                 reconcile, not by an operator: {out}"
            );
            assert!(
                out.contains("\"access_rights_before\":\"RESTRICTED\"")
                    && out.contains("\"access_rights_after\":\"PUBLIC\""),
                "the disclosure-relevant before/after must survive regardless of actor: {out}"
            );
        }
    }

    #[test]
    fn unrecoverable_header_emits_a_distinct_warn_reason() {
        let provenance = WriterProvenance::Unrecoverable("decryption failed".to_owned());
        let out = capture_with(|| ingest_provenance(&enabled_audit(), "GDI-1", "bkt", &provenance));
        assert!(
            out.contains("\"event\":\"ingest_provenance_absent\""),
            "an unreadable header emits the absent event: {out}"
        );
        assert!(
            out.contains("\"reason\":\"recovery_failed\""),
            "its reason is distinguishable from the plaintext path — this is the field an \
             alert keys on: {out}"
        );
        assert!(
            out.contains("\"level\":\"WARN\""),
            "an unreadable header is anomalous and warns, unlike the plaintext path: {out}"
        );
    }

    #[test]
    fn every_provenance_variant_emits_exactly_one_line() {
        // A successful ingest always leaves exactly one provenance record, so the absence
        // of both events is itself a signal.
        for provenance in [
            WriterProvenance::Recovered(vec!["sha256:aa".to_owned()]),
            WriterProvenance::Plaintext,
            WriterProvenance::Unrecoverable("boom".to_owned()),
        ] {
            let out =
                capture_with(|| ingest_provenance(&enabled_audit(), "GDI-1", "inbox", &provenance));
            assert_eq!(
                out.lines().filter(|l| !l.trim().is_empty()).count(),
                1,
                "exactly one audit line per ingest for {provenance:?}: {out}"
            );
        }
    }

    #[test]
    fn provenance_is_silent_when_the_audit_trail_is_disabled() {
        let cfg = AuditConfig {
            enabled: false,
            query_detail: false,
            management_reads: true,
        };
        for provenance in [
            WriterProvenance::Recovered(vec!["sha256:aa".to_owned()]),
            WriterProvenance::Plaintext,
            WriterProvenance::Unrecoverable("boom".to_owned()),
        ] {
            let out = capture_with(|| ingest_provenance(&cfg, "GDI-1", "inbox", &provenance));
            assert!(out.is_empty(), "disabled audit emits nothing: {out}");
        }
    }

    /// The two inventory routes disclose different sets, so their lines say which was
    /// pulled. `dataset_ids` renders comma-joined, the shape every `dataset_ids` field here
    /// uses, because a log store gets per-id terms from it while a JSON array inside a string
    /// or a `Debug` dump gives none.
    #[test]
    fn inventory_read_names_its_route_and_renders_ids_comma_joined() {
        let ids = vec![
            "GDI-EE-UTARTU-20260409143052837".to_owned(),
            "GDI-EE-UTARTU-20260409143052838".to_owned(),
        ];
        let detailed = AuditConfig {
            management_reads: true,
            enabled: true,
            query_detail: true,
        };
        let out = capture_lines(|| {
            dataset_inventory_read(&detailed, "/datasets", 2, &ids);
            dataset_inventory_read(&detailed, "/datasets/suppressed", 1, &ids[..1]);
            query_stats_read(&detailed, 2, &ids);
        });
        let lines: Vec<serde_json::Value> = out
            .lines()
            .map(|l| serde_json::from_str(l).expect("json log line"))
            .collect();
        assert_eq!(lines.len(), 3, "{out}");
        assert_eq!(lines[0]["fields"]["route"], "/datasets", "{}", lines[0]);
        assert_eq!(
            lines[1]["fields"]["route"], "/datasets/suppressed",
            "{}",
            lines[1]
        );
        for (line, expected) in [
            (&lines[0], &ids[..]),
            (&lines[1], &ids[..1]),
            (&lines[2], &ids[..]),
        ] {
            let raw = line["fields"]["dataset_ids"]
                .as_str()
                .unwrap_or_else(|| panic!("dataset_ids is a string field: {line}"));
            let parsed: Vec<&str> = raw.split(',').collect();
            let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
            assert_eq!(parsed, expected, "{line}");
        }
        // Without `query_detail` the ids are withheld as an empty string, in the same shape.
        let terse = capture_lines(|| {
            dataset_inventory_read(
                &AuditConfig {
                    enabled: true,
                    query_detail: false,
                    management_reads: true,
                },
                "/datasets",
                2,
                &ids,
            );
        });
        let line: serde_json::Value =
            serde_json::from_str(terse.trim()).expect("one json log line");
        assert_eq!(line["fields"]["dataset_ids"], "", "{line}");
        assert_eq!(line["fields"]["count"], 2, "{line}");
    }
}
