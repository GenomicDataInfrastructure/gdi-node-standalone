//! The `status` command: a dataset's resolved node state + sync summary (and,
//! with `--diff`, the granular file/`ETag`/state difference).
//!
//! State resolution prefers the management plane `GET /datasets/{id}/state` (the
//! authoritative state + channel); a **remote** tool that cannot reach it reads
//! `_status/{id}.json` from the bucket, matching `source_signature` to the current
//! `.tar.c4gh` `ETag` (the published node state, `pending`, or `unavailable`). The
//! sync summary is S3-relative (`in-sync`/`drifted`/`missing`); an inbox-owned
//! dataset reports `sync: local`.
//!
//! The data model lives in [`crate::status`]; this is the orchestrating wrapper.

use std::path::Path;

use gdi_node_standalone_core::config::Profile;
use gdi_node_standalone_core::id::is_valid_dataset_id;

use crate::cli::{OutputFormat, StatusArgs};
use crate::s3::{Store, Visibility};
use crate::state::{self, Channel};
use crate::status::{self, DiffLine, NodeStatus, Sync};
use crate::{ToolError, catalogs, profile, runtime, s3};

/// Run `status`.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) on an invalid id, a missing S3 bucket where
/// one is required, or any S3 / HTTP failure that is not gracefully degraded.
pub fn run(
    args: &StatusArgs,
    profile_name: Option<&str>,
    config_path: Option<&Path>,
) -> Result<(), ToolError> {
    let started = std::time::Instant::now();
    let active = profile::load_active(config_path, profile_name)?;
    s3::install_crypto_provider();
    // The store is built lazily — a no-S3 (inbox-only) profile still runs `status`.
    let store = match active.s3.as_ref() {
        Some(cfg) => Some(s3::build_object_store(cfg)?),
        None => None,
    };
    crate::output::note(&format!(
        "node state base: {}",
        active.node_state_base().unwrap_or("<none configured>")
    ));
    match active.s3.as_ref().and_then(|c| c.bucket.as_deref()) {
        Some(bucket) => crate::output::note(&format!("S3 bucket: {bucket}")),
        None => crate::output::note("no S3 bucket configured (inbox-only profile)"),
    }

    if args.all {
        return run_all(
            &active,
            store.as_ref(),
            args.format,
            args.management_url.as_deref(),
        );
    }

    let id = args
        .id
        .as_deref()
        .ok_or_else(|| ToolError::user("status needs a dataset id (or --all)"))?;
    if !is_valid_dataset_id(id) {
        return Err(ToolError::user(format!("invalid dataset id: {id}")));
    }
    crate::output::note(&format!("resolving status of {id}"));

    // A single id pays at most one probe timeout, so always probe (no up-front gate).
    if let Some(summary) = report_one(
        &active,
        store.as_ref(),
        id,
        args.diff,
        args.format,
        true,
        args.management_url.as_deref(),
    )? {
        emit_one(&summary)?;
    }
    crate::output::note(&format!(
        "status of {id} resolved in {:.1?}",
        started.elapsed()
    ));
    Ok(())
}

/// The machine-readable `status --format json` summary for one dataset.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusSummary {
    /// The dataset id.
    id: String,
    /// The resolved node state (`visible`/`hidden`/`error`/`pending`/`unavailable`/…).
    state: String,
    /// Where `state` came from: `"node"` (the authoritative management-plane oracle) or
    /// `"sidecar"` (a possibly-stale S3 `_status` echo, used when the management plane is
    /// unreachable/unconfigured) — so a script can tell an authoritative read from a
    /// non-authoritative one rather than treating the byte-identical `state` the same.
    /// (Serialized as `stateSource` by the struct-level `rename_all = "camelCase"`.)
    state_source: &'static str,
    /// The sanitized error message (present only in the `error` state).
    #[serde(skip_serializing_if = "Option::is_none")]
    error_message: Option<String>,
    /// The owning channel (`s3` / `inbox`).
    channel: String,
    /// The S3-relative sync summary (`in-sync`/`drifted`/`missing`/`local`).
    sync: String,
    /// The S3-derived served visibility, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    visibility: Option<String>,
    /// The current `.tar.c4gh` `ETag`, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    etag: Option<String>,
    /// The granular diff (only with `--diff`; empty for a remote-less dataset).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    diff: Vec<DiffLine>,
}

/// The channel's short label (`s3` / `inbox`).
fn channel_label(channel: Channel) -> &'static str {
    match channel {
        Channel::S3 => "s3",
        Channel::Inbox => "inbox",
    }
}

/// The S3-derived served visibility (the `{id}.state.json` sidecar), or `None` when it is
/// not knowable: no bucket configured, an inbox-owned dataset, or no package in the bucket.
///
/// One place, so the text report, the JSON summary and `--diff` cannot disagree on when a
/// visibility exists. A single-object GET (fail-safe `Hidden`): `run_all` calls this once
/// per dataset, where a full-bucket `list_datasets` per id would cost O(n) LISTs and O(n²)
/// sidecar GETs.
fn s3_visibility(
    store: Option<&Store>,
    channel: Channel,
    id: &str,
    etag: Option<&str>,
) -> Result<Option<Visibility>, ToolError> {
    match (store, channel) {
        (Some(s), Channel::S3) if etag.is_some() => {
            Ok(Some(runtime::block_on(s3::fetch_visibility(s, id))?))
        }
        _ => Ok(None),
    }
}

/// Report on a single dataset id. In `text` mode prints the report (returning
/// `None`); in `json` mode builds and returns the [`StatusSummary`] for the caller
/// to emit (so `--all` can aggregate them into one JSON array).
fn report_one(
    active: &Profile,
    store: Option<&Store>,
    id: &str,
    diff: bool,
    format: OutputFormat,
    probe_node: bool,
    override_base: Option<&str>,
) -> Result<Option<StatusSummary>, ToolError> {
    // 1. Prefer the authoritative management-plane state (state + channel), reached via
    //    management_url (else service_url). `probe_node` is the up-front reachability
    //    verdict: `--all` sets it false when the state base is down, so this skips a
    //    per-dataset 5s timeout that would only resolve to `None` anyway (the S3 path).
    let node_state = if probe_node {
        state::resolve_node_state(active, id, override_base)?
    } else {
        None
    };
    // The provenance of the `state` value reported below: the authoritative node oracle,
    // or the S3-derived (non-authoritative) fallback.
    let state_source = if node_state.is_some() {
        "node"
    } else {
        "sidecar"
    };
    // 2. Resolve the S3-side facts (package presence + ETag + writeback) once.
    let (package_present, etag, writeback) = match store {
        Some(s) => {
            let etag = runtime::block_on(s3::package_etag(s, id))?;
            let wb_bytes = runtime::block_on(s3::read_status_object(s, id))?;
            let wb = wb_bytes.as_deref().and_then(status::parse_writeback);
            (etag.is_some(), etag, wb)
        }
        None => (false, None, None),
    };
    if crate::output::is_verbose() {
        crate::output::note(&format!(
            "{id}: S3 package {}, etag {}",
            if package_present { "present" } else { "absent" },
            etag.as_deref().unwrap_or("<none>")
        ));
    }

    // 3. The node-state outcome: management plane wins, else the remote writeback.
    let (node_status, channel) = if let Some(ns) = &node_state {
        (
            NodeStatus::State {
                state: ns.state.clone(),
                error_message: ns.error_message.clone(),
            },
            ns.channel,
        )
    } else {
        let st = status::remote_node_status(writeback.as_ref(), etag.as_deref());
        // No authoritative channel: infer S3 if the bucket holds it, else by profile.
        let ch = infer_channel(active, package_present);
        (st, ch)
    };

    // 4. The sync summary (S3-relative; inbox => local). Reuses the `writeback`
    //    already fetched above (no second `_status` GET, and the printed state +
    //    drift verdict come from the same read).
    let drifted = is_drifted(&node_status, writeback.as_ref(), etag.as_deref());
    let sync = status::channel_sync(channel, package_present, drifted);

    if format == OutputFormat::Text {
        print_report(id, &node_status, channel, sync, store, etag.as_deref())?;
        if diff {
            print_diff(
                id,
                channel,
                &node_status,
                package_present,
                etag.as_deref(),
                store,
            )?;
        }
        return Ok(None);
    }

    // JSON mode: build the summary (the visibility fetch + diff computation mirror
    // what the text path's `print_report`/`print_diff` compute).
    let visibility =
        s3_visibility(store, channel, id, etag.as_deref())?.map(|v| v.as_str().to_owned());
    let diff_lines = if diff {
        compute_diff(
            id,
            channel,
            &node_status,
            package_present,
            etag.as_deref(),
            store,
        )?
    } else {
        Vec::new()
    };
    // Clean structured fields: `state` is the bare state, `errorMessage` separate
    // (the text `label()` bundles them as `state (msg)` — not wanted in JSON).
    let (state, error_message) = match &node_status {
        NodeStatus::State {
            state,
            error_message,
        } => (state.clone(), error_message.clone()),
        other => (other.label(), None),
    };
    Ok(Some(StatusSummary {
        id: id.to_owned(),
        state,
        state_source,
        error_message,
        channel: channel_label(channel).to_owned(),
        sync: sync.label().to_owned(),
        visibility,
        etag,
        diff: diff_lines,
    }))
}

/// Print the one-line status report.
fn print_report(
    id: &str,
    node_status: &NodeStatus,
    channel: Channel,
    sync: Sync,
    store: Option<&Store>,
    etag: Option<&str>,
) -> Result<(), ToolError> {
    // The S3-derived served visibility (the sidecar) is a useful metadata summary.
    let vis_label = s3_visibility(store, channel, id, etag)?
        .map_or_else(String::new, |v| format!("\tvisibility: {}", v.as_str()));
    println!(
        "{id}\tstate: {}\tchannel: {}\tsync: {}{vis_label}",
        node_status.display_label(),
        channel_label(channel),
        sync.label()
    );
    Ok(())
}

/// Whether the dataset is drifted: the node's served state disagrees with the S3
/// writeback's freshness (a stale `source_signature` ⇒ the node has not caught up
/// with the latest upload, i.e. drift between local-intended and node-served).
fn is_drifted(
    node_status: &NodeStatus,
    writeback: Option<&status::StatusWriteback>,
    etag: Option<&str>,
) -> bool {
    // A `pending` remote status means the node's published result is for an older
    // package ETag than the one currently in the bucket — that is drift.
    if matches!(node_status, NodeStatus::Pending) {
        return true;
    }
    // Otherwise compare the (already-fetched) writeback signature against the
    // current ETag. Reusing the caller's `writeback` avoids a second `_status` GET
    // and keeps the printed state and this verdict consistent (one read, not two).
    if let (Some(wb), Some(current)) = (writeback, etag)
        && let Some(sig) = wb.source_signature.as_deref()
    {
        return sig != current;
    }
    // Nothing left to compare, and the node has published a state (a genuinely
    // never-processed package reports `Pending`, handled above). A missing writeback object
    // means writeback is not in use, not that the node is behind, so this is not drift.
    false
}

/// Print the granular `--diff` lines. S3-only: a local (inbox) dataset has no
/// remote to diff and says so.
fn print_diff(
    id: &str,
    channel: Channel,
    node_status: &NodeStatus,
    package_present: bool,
    etag: Option<&str>,
    store: Option<&Store>,
) -> Result<(), ToolError> {
    if channel == Channel::Inbox {
        println!("  diff: (local dataset; no S3 remote to diff)");
        return Ok(());
    }
    if store.is_none() {
        println!("  diff: (no S3 bucket configured; nothing to diff)");
        return Ok(());
    }
    for l in &compute_diff(id, channel, node_status, package_present, etag, store)? {
        println!(
            "  diff {:<8} local={} remote={}",
            l.aspect, l.local, l.remote
        );
    }
    Ok(())
}

/// Compute the granular `--diff` lines for an S3-owned dataset (package presence +
/// `ETag`, sidecar-vs-node state, `_status` freshness). A remote-less dataset
/// (inbox channel, or no bucket configured) has no remote to diff, so this returns
/// an empty list. Shared by the text [`print_diff`] and the JSON summary.
fn compute_diff(
    id: &str,
    channel: Channel,
    node_status: &NodeStatus,
    package_present: bool,
    etag: Option<&str>,
    store: Option<&Store>,
) -> Result<Vec<DiffLine>, ToolError> {
    if channel == Channel::Inbox {
        return Ok(Vec::new());
    }
    let Some(s) = store else {
        return Ok(Vec::new());
    };

    let mut lines: Vec<DiffLine> = Vec::new();

    // package presence + ETag.
    lines.push(DiffLine {
        aspect: "package".to_owned(),
        local: if package_present { "present" } else { "<none>" }.to_owned(),
        remote: etag_label(etag),
    });

    // The bucket-sidecar served state vs the node's writeback state. A dataset with no
    // package in the bucket reports `Hidden` (the fail-safe default); only when the package
    // is present does the sidecar's actual visibility surface — which is exactly when
    // `s3_visibility` yields one.
    let sidecar = s3_visibility(store, channel, id, etag)?.unwrap_or(Visibility::Hidden);
    let node_state_str = match node_status {
        NodeStatus::State { state, .. } => state.clone(),
        NodeStatus::Pending => "pending".to_owned(),
        NodeStatus::Unavailable => "unavailable".to_owned(),
    };
    lines.push(DiffLine {
        aspect: "state".to_owned(),
        local: sidecar.as_str().to_owned(),
        remote: node_state_str,
    });

    // _status freshness: the bucket's current package (its ETag — the bucket/intent
    // side, like the `state` line's sidecar under `local`) vs the signature the node
    // last processed (the node side, under `remote`). Both values are package ETags,
    // so they are labelled (`etag …` / `processed …`) — a bare ETag under `local=`
    // otherwise reads as if it were a local-disk fact.
    if let Some(bytes) = runtime::block_on(s3::read_status_object(s, id))? {
        // A present-but-unparseable `_status` object states no freshness fact, so it
        // contributes no line at all (unlike an absent one, which reports `<none>`).
        if let Some(wb) = status::parse_writeback(&bytes) {
            lines.push(DiffLine {
                aspect: "_status".to_owned(),
                local: etag_label(etag),
                remote: wb
                    .source_signature
                    .map_or_else(|| "<none>".to_owned(), |s| format!("processed {s}")),
            });
        }
    } else {
        lines.push(DiffLine {
            aspect: "_status".to_owned(),
            local: etag_label(etag),
            remote: "<none>".to_owned(),
        });
    }

    Ok(lines)
}

/// A package `ETag` as a `--diff` value (`etag <e>`), or `<none>` when absent.
fn etag_label(etag: Option<&str>) -> String {
    etag.map_or_else(|| "<none>".to_owned(), |e| format!("etag {e}"))
}

/// `status --all`: report on every dataset in [`all_dataset_ids`]. In `json` mode the
/// per-dataset summaries are aggregated under a `datasets` array inside a single
/// versioned object (`{"schemaVersion":1,"datasets":[ ... ]}`).
fn run_all(
    active: &Profile,
    store: Option<&Store>,
    format: OutputFormat,
    override_base: Option<&str>,
) -> Result<(), ToolError> {
    // One up-front reachability check of the state base: if it is configured but down,
    // skip the per-dataset node-state probe entirely (each would just hit the full 5s
    // timeout → `None`), turning an N×5s stall into a single check. A reachable node is
    // probed per id (those return fast). No state base configured ⇒ never probe.
    let started = std::time::Instant::now();
    let probe_node = match override_base.or_else(|| active.node_state_base()) {
        Some(base) => runtime::block_on(node_state_reachable(base))?,
        None => false,
    };
    crate::output::note(&format!(
        "node state base {} is {}",
        override_base
            .or_else(|| active.node_state_base())
            .unwrap_or("<none>"),
        if probe_node {
            "reachable; probing per dataset"
        } else {
            "down/unconfigured; using S3 sidecars"
        }
    ));

    let ids = all_dataset_ids(active, store, format)?;
    let total = ids.len();
    // Discrete per-dataset count bar — live only in JSON mode (Text mode prints each
    // status during the loop; off-TTY `step` keeps the plain `status N/total` line).
    let cp = crate::progress::CountProgress::new(
        "status",
        total as u64,
        crate::progress::active() && format == OutputFormat::Json,
    );
    let mut summaries: Vec<StatusSummary> = Vec::new();
    for id in &ids {
        cp.step(id);
        if let Some(summary) =
            report_one(active, store, id, false, format, probe_node, override_base)?
        {
            summaries.push(summary);
        }
    }
    cp.finish();
    if format == OutputFormat::Json {
        emit_all(&summaries);
    }
    crate::output::note(&format!(
        "status --all of {total} dataset(s) in {:.1?}",
        started.elapsed()
    ));
    Ok(())
}

/// The id set `--all` reports on: the S3 listing when a bucket is configured, else (on
/// no-S3) the FDP-visible datasets over the public plane, plus any ids the operator named
/// (none here — the operator names ids on the per-id form).
///
/// # Errors
///
/// Returns a [`ToolError`] when the listing / enumeration fails, or when the profile
/// configures neither a bucket nor a `service_url` to enumerate from.
fn all_dataset_ids(
    active: &Profile,
    store: Option<&Store>,
    format: OutputFormat,
) -> Result<Vec<String>, ToolError> {
    if let Some(s) = store {
        let datasets = runtime::block_on(s3::list_datasets(s))?;
        if datasets.is_empty() && format == OutputFormat::Text {
            println!("(no datasets in the bucket)");
        }
        crate::output::note(&format!(
            "comparing {} dataset(s) from the bucket",
            datasets.len()
        ));
        return Ok(datasets.into_iter().map(|d| d.id).collect());
    }

    // No-S3 node: enumerate the FDP-visible datasets via the public plane.
    let base = active.service_url.as_deref().ok_or_else(|| {
        ToolError::user(
            "status --all needs either a [profiles.<name>.s3] bucket or a reachable \
             `service_url` to enumerate datasets",
        )
    })?;
    crate::output::note(&format!("enumerating FDP-visible datasets via {base}"));
    let ids = runtime::block_on(fetch_visible_dataset_ids(base))?;
    if ids.is_empty() && format == OutputFormat::Text {
        println!("(no FDP-visible datasets)");
    }
    crate::output::note(&format!("comparing {} FDP-visible dataset(s)", ids.len()));
    Ok(ids)
}

/// One up-front reachability probe of the management/state `base`, so `--all` does not
/// pay the full per-dataset probe timeout N times when the node is simply down. Returns
/// `true` if the base answers any HTTP response (even a `404`/`400` for the sentinel id),
/// `false` on a connection / timeout / DNS failure.
///
/// This must agree with the per-id [`crate::state::probe_node_state`] it gates, on both
/// counts: it uses the same [`crate::state::PROBE_TIMEOUT`] (a shorter one would class a
/// merely-slow node as down and silently downgrade every dataset to a possibly-stale S3
/// sidecar read), and it applies the same secure-transport gate up front (otherwise a
/// plaintext non-loopback base is reported "reachable" here and then aborts the whole run
/// on the first per-dataset probe).
async fn node_state_reachable(base: &str) -> Result<bool, ToolError> {
    let url = format!(
        "{}/datasets/_reachability-probe_/state",
        base.trim_end_matches('/')
    );
    crate::recipient::require_secure_transport(
        &url,
        "a MITM could forge the node's authoritative channel/state and steer sidecar routing.",
    )?;
    let Ok(client) = gdi_node_standalone_core::tls::https_client_builder()
        .timeout(crate::state::PROBE_TIMEOUT)
        .build()
    else {
        return Ok(false);
    };
    // Any HTTP response ⇒ reachable; a transport error ⇒ unreachable.
    Ok(client.get(&url).send().await.is_ok())
}

/// Emit one dataset's status as `{"schemaVersion":1, ...StatusSummary fields...}` —
/// the versioned report envelope (`schemaVersion` merged in front of the summary's
/// own fields) so a single-id `status --format json` is version-gateable like the
/// action verbs.
fn emit_one(summary: &StatusSummary) -> Result<(), ToolError> {
    let value = crate::output::versioned_value(summary)
        .map_err(|e| ToolError::user(format!("serializing report: {e}")))?;
    crate::output::emit_json(&value);
    Ok(())
}

/// Emit the `--all` summaries as `{"schemaVersion":1,"datasets":[ ... ]}` — the
/// bare array is nested under `datasets` so the top-level payload is a versioned
/// object.
fn emit_all(summaries: &[StatusSummary]) {
    let out = serde_json::json!({ "schemaVersion": 1, "datasets": summaries });
    crate::output::emit_json(&out);
}

/// Fetch the FDP-visible dataset ids from the node's catalogs (the public-plane
/// enumeration the no-S3 `--all` uses). Each catalog record lists its visible
/// datasets as `…/fairdp/dataset/{id}` IRIs.
async fn fetch_visible_dataset_ids(service_url: &str) -> Result<Vec<String>, ToolError> {
    let cats = catalogs::fetch_node_catalogs(service_url).await?;
    let base = service_url.trim_end_matches('/');
    let mut ids: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let client = catalogs::fdp_client()?;
    for cat in &cats {
        let url = format!("{base}/fairdp/catalog/{cat}");
        let Ok(resp) = client
            .get(&url)
            .header(reqwest::header::ACCEPT, "text/turtle")
            .send()
            .await
        else {
            continue;
        };
        if !resp.status().is_success() {
            continue;
        }
        // Cap each per-catalog body (https already enforced transitively by the root
        // fetch above) so a hostile/MITM'd node cannot force an unbounded allocation.
        if let Ok(body) = catalogs::read_capped_body(resp, &url).await {
            for id in catalogs::dataset_ids_from_graph(&body) {
                ids.insert(id);
            }
        }
    }
    Ok(ids.into_iter().collect())
}

/// Infer the channel without an authoritative view: S3 when the bucket holds the
/// package or the profile configures S3, else the inbox if the profile has one,
/// else default to S3.
///
/// This is not [`crate::state::resolve_channel`], which the lifecycle writers use.
/// `status` is read-only reporting, so it never errors on an ambiguous profile and
/// defaults to S3 for the sync display, and it adds the local `package_present` heuristic.
/// A write must adopt neither.
fn infer_channel(active: &Profile, package_present: bool) -> Channel {
    if package_present || active.s3.is_some() {
        Channel::S3
    } else if active.inbox.is_some() {
        Channel::Inbox
    } else {
        Channel::S3
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;

    /// `--all`'s up-front reachability probe must apply the same transport gate as the
    /// per-id `probe_node_state`. Otherwise it reports the node "reachable" over plaintext
    /// http and the first per-dataset probe then aborts the whole run with exit 1.
    #[test]
    fn reachability_probe_refuses_a_plaintext_non_loopback_base() {
        let err = crate::runtime::block_on(node_state_reachable("http://node.invalid"))
            .expect_err("a plaintext non-loopback base must be refused up front");
        assert!(
            err.message.contains("plaintext http"),
            "expected the secure-transport refusal; got: {}",
            err.message
        );
    }

    /// Loopback stays exempt (local development): an unreachable loopback port is simply
    /// "not reachable", never an error.
    #[test]
    fn reachability_probe_allows_a_loopback_plaintext_base() {
        let reachable = crate::runtime::block_on(node_state_reachable("http://127.0.0.1:1"))
            .expect("loopback plaintext is exempt from the transport gate");
        assert!(!reachable, "a refused connection means unreachable");
    }

    /// A loopback HTTP server that answers every request with the same turtle body.
    /// Enough to drive `fetch_visible_dataset_ids`: the `/fairdp` root lists the
    /// catalogs, each `/fairdp/catalog/{c}` reply lists the dataset IRIs, and the
    /// ids dedup across catalogs.
    fn serve_loop(body: &'static str) -> String {
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/turtle\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
        });
        format!("http://{addr}")
    }

    #[test]
    fn fetch_visible_collects_and_dedups_dataset_ids() {
        // One turtle carrying both catalog IRIs (for the root listing) and dataset
        // IRIs (for each per-catalog crawl). The same body answers every request, so
        // the two catalogs yield the same ids, which must dedup into a sorted set.
        const TTL: &str = "\
@prefix ldp: <http://www.w3.org/ns/ldp#> .
<https://node.example/fairdp> ldp:contains
  <https://node.example/fairdp/catalog/gdi-aggregated> ,
  <https://node.example/fairdp/catalog/synthetic-data> ,
  <https://node.example/fairdp/dataset/GDI-EE-UTARTU-20260409143052837> ,
  <https://node.example/fairdp/dataset/GDI-EE-UTARTU-20260409143052838> .
";
        let base = serve_loop(TTL);
        let ids = runtime::block_on(fetch_visible_dataset_ids(&base)).unwrap();
        assert_eq!(
            ids,
            vec![
                "GDI-EE-UTARTU-20260409143052837".to_owned(),
                "GDI-EE-UTARTU-20260409143052838".to_owned(),
            ]
        );
    }

    /// Like `serve_loop` but routes by request path: the FDP root + the `good`
    /// catalog answer 200 with their turtle; the `bad` catalog answers 500.
    fn serve_routed(
        root_ttl: &'static str,
        good_ttl: &'static str,
        good: &'static str,
        bad: &'static str,
    ) -> String {
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut buf = [0u8; 1024];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                // The request target is the 2nd whitespace token of the first line.
                let target = req
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("");
                let (status, body) = if target.contains(bad) {
                    ("500 Internal Server Error", "")
                } else if target.contains(good) {
                    ("200 OK", good_ttl)
                } else {
                    ("200 OK", root_ttl)
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: text/turtle\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
        });
        format!("http://{addr}")
    }

    #[test]
    fn fetch_visible_skips_a_failing_catalog() {
        // Two catalogs; `synthetic-data` returns 500, so its crawl is skipped (the
        // `!resp.status().is_success()` continue arm) and only the healthy catalog's
        // ids are collected.
        const ROOT: &str = "\
@prefix ldp: <http://www.w3.org/ns/ldp#> .
<https://node.example/fairdp> ldp:contains
  <https://node.example/fairdp/catalog/gdi-aggregated> ,
  <https://node.example/fairdp/catalog/synthetic-data> .
";
        const GOOD: &str = "\
@prefix ldp: <http://www.w3.org/ns/ldp#> .
<https://node.example/fairdp/catalog/gdi-aggregated> ldp:contains
  <https://node.example/fairdp/dataset/GDI-EE-UTARTU-20260409143052837> .
";
        let base = serve_routed(ROOT, GOOD, "gdi-aggregated", "synthetic-data");
        let ids = runtime::block_on(fetch_visible_dataset_ids(&base)).unwrap();
        assert_eq!(ids, vec!["GDI-EE-UTARTU-20260409143052837".to_owned()]);
    }

    // `infer_channel` covers all three distinct branches.
    #[test]
    fn infer_channel_package_present_returns_s3() {
        // Branch 1: package_present=true → S3 even when the profile points at an inbox.
        //
        // The fixture must be one where the other arms disagree. `Profile::default()` (no
        // s3, no inbox) falls through to the final `else { S3 }`, so it answers S3 whether
        // or not `package_present` is consulted. An inbox-only profile answers Inbox without
        // the `package_present ||` term, so the fixture binds that term.
        let active = Profile {
            inbox: Some("/tmp/inbox".into()),
            ..Profile::default()
        };
        assert_eq!(
            infer_channel(&active, true),
            Channel::S3,
            "a present local package must force S3 even on an inbox profile"
        );
        // The contrast: same profile, no package -> the inbox arm wins.
        assert_eq!(
            infer_channel(&active, false),
            Channel::Inbox,
            "without a package the inbox profile reports Inbox"
        );
    }

    #[test]
    fn infer_channel_s3_configured_returns_s3() {
        // Branch 2: package_present=false but s3 is configured → S3.
        use gdi_node_standalone_core::config::ProfileS3;
        let active = Profile {
            s3: Some(ProfileS3::default()),
            ..Profile::default()
        };
        assert_eq!(infer_channel(&active, false), Channel::S3);
    }

    #[test]
    fn infer_channel_inbox_only_returns_inbox() {
        // Branch 3: package_present=false, no s3, inbox present → Inbox.
        let active = Profile {
            inbox: Some("/var/gdi/inbox".to_owned()),
            ..Profile::default()
        };
        assert_eq!(infer_channel(&active, false), Channel::Inbox);
    }

    #[test]
    fn infer_channel_no_s3_no_inbox_fallback_returns_s3() {
        // Fallback: package_present=false, no s3, no inbox → S3 (default).
        let active = Profile::default();
        assert_eq!(infer_channel(&active, false), Channel::S3);
    }

    #[test]
    fn is_drifted_reuses_writeback_without_refetch() {
        use status::StatusWriteback;
        let visible = NodeStatus::State {
            state: "visible".to_owned(),
            error_message: None,
        };
        let wb = |sig: &str| StatusWriteback {
            state: "visible".to_owned(),
            error_message: None,
            source_signature: Some(sig.to_owned()),
            ..StatusWriteback::default()
        };
        // Pending is always drift.
        assert!(is_drifted(&NodeStatus::Pending, None, None));
        // A stale writeback signature (!= current ETag) is drift.
        assert!(is_drifted(
            &visible,
            Some(&wb("old-etag")),
            Some("new-etag")
        ));
        // A matching signature is not drift.
        assert!(!is_drifted(&visible, Some(&wb("etag-1")), Some("etag-1")));
        // No writeback / no etag (non-pending) is not drift.
        assert!(!is_drifted(&visible, None, Some("etag-1")));
    }
}
