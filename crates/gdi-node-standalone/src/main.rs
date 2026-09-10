//! The `gdi-node-standalone` service binary.
//!
//! Startup: load + preflight the service config, load the persistent status index,
//! reap any stale `data_dir/.incoming/` working dirs left by a crash, run a
//! startup inbox scan, then start the bounded ingest worker pool and an inbox
//! filesystem watcher (plus a periodic rescan timer as the safety net). It then
//! serves the public beacon/FDP plane and the separate management plane until a
//! signal starts the bounded drain.
#![cfg_attr(
    test,
    allow(
        clippy::disallowed_methods,
        reason = "unit tests write plain files: durability and atomicity are not properties under test"
    )
)]

use std::path::Path;
use std::sync::Arc;
#[cfg(feature = "s3")]
use std::sync::PoisonError;
use std::time::Duration;

use anyhow::{Context as _, Result};
use clap::{Parser, Subcommand};
use gdi_node_standalone::app::build_router;
use gdi_node_standalone::audit;
use gdi_node_standalone::control_http::ReloadOutcome;
use gdi_node_standalone::ingest_runtime::IngestRuntime;
use gdi_node_standalone::logging;
use gdi_node_standalone::metrics;
use gdi_node_standalone::preflight;
use gdi_node_standalone::scrub;
use gdi_node_standalone::state::{AppState, ReloadTrigger};
use gdi_node_standalone_core::GDI_METADATA_VERSION;
use gdi_node_standalone_core::cache::StatusIndex;
use gdi_node_standalone_core::config::{ServiceConfig, WriterPolicy};
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use notify::{RecommendedWatcher, RecursiveMode, Watcher as _};
use tokio::sync::Notify;
use tokio::sync::Semaphore;
use tracing::{Instrument as _, debug, info, info_span, warn};

mod bootstrap;
use bootstrap::{LoadedSecrets, load_identities};

/// Warn when the beacon advertises an access tier this binary cannot enforce.
///
/// `[beacon.configuration].security_level` is published verbatim on `/configuration` and in
/// `/info`'s `securityAttributes`, and preflight accepts all three GA4GH values. This node
/// authenticates nothing on any plane, so `REGISTERED` and `CONTROLLED` advertise a control
/// that does not exist, while a harvester or registry may read them as "requests are gated".
///
/// A warning rather than a preflight refusal: the field is a registry-facing label, and an
/// operator may be required to publish a tier that a fronting gateway enforces. Refusing to
/// boot would break that topology.
fn warn_advertised_security_level(config: &ServiceConfig) {
    if config.beacon.configuration.security_level != "PUBLIC" {
        warn!(
            security_level = %config.beacon.configuration.security_level,
            "beacon.configuration.security_level advertises a gated access tier on \
             /configuration and /info, but this node performs no authentication on any plane: \
             every beacon route is open to anyone who can reach the port. Set it to PUBLIC, or \
             ensure an authenticating gateway in front of this node actually enforces the tier \
             you advertise"
        );
    }
}

/// The floor under a fully-saturated scan pool's transient parquet decode working set:
/// `(scan_pool_cap, scan_pool_cap x max_parquet_row_group_bytes)`.
///
/// Pure, and separate from the `warn!` that consumes it, so the threshold is testable
/// without capturing a tracing subscriber.
fn decode_working_set_floor(config: &ServiceConfig) -> (usize, u64) {
    let pool_cap =
        gdi_node_standalone::beacon_http::scan_pool_cap(config.service.query_concurrency());
    let floor = (pool_cap as u64).saturating_mul(config.service.max_parquet_row_group_bytes);
    (pool_cap, floor)
}

/// Warn about OTLP configuration that is easy to set and easy to miss being inert: an
/// endpoint in a binary built without the `otel` feature; auth headers or a metrics
/// push interval with no endpoint to send to; a traceparent-trust flag with no export
/// configured. All are silent no-ops — say so, or they are mistaken for active.
fn warn_inert_otel_config(config: &ServiceConfig) {
    // Under `otel` this check compiles away.
    #[cfg(not(feature = "otel"))]
    if config.service.otlp_endpoint.is_some() {
        warn!(
            otlp_endpoint = %config.service.otlp_endpoint.as_deref().unwrap_or_default(),
            "[service].otlp_endpoint is set but this binary was built without the `otel` \
             feature, so OTLP export is disabled (rebuild with --features otel to enable)"
        );
    }
    if (config.service.otlp_headers.is_some()
        || config.service.otlp_metrics_interval_seconds.is_some()
        || config.service.otlp_trace_sample_ratio.is_some())
        && config.service.otlp_endpoint.is_none()
    {
        warn!(
            event.action = "config.posture",
            otlp_headers = config.service.otlp_headers.is_some(),
            otlp_metrics_interval_seconds = config.service.otlp_metrics_interval_seconds,
            otlp_trace_sample_ratio = config.service.otlp_trace_sample_ratio,
            "[service].otlp_headers / otlp_metrics_interval_seconds / otlp_trace_sample_ratio \
             is set but [service].otlp_endpoint is not; there is no export to attach them \
             to, so they are ignored"
        );
    }
    // Both trace-trust flags, not just the inbound one. An operator who enables sidecar
    // trust so that publishes correlate is the one most likely to need this warning.
    if (config.service.trust_inbound_traceparent || config.service.trust_sidecar_traceparent)
        && config.service.otlp_endpoint.is_none()
    {
        warn!(
            trust_inbound_traceparent = config.service.trust_inbound_traceparent,
            trust_sidecar_traceparent = config.service.trust_sidecar_traceparent,
            "a [service] traceparent-trust flag is set but [service].otlp_endpoint is not; \
             with no trace export configured, traceparent adoption is inert"
        );
    }
}

/// Emit startup warnings for risky-but-valid deployment posture (not hard errors).
///
/// The management plane (health, the dataset-state oracle, metrics) must be reachable by
/// in-cluster scrapers and probes, so a wildcard bind is normal under Kubernetes. It then
/// relies on a `NetworkPolicy` or a host firewall to stay off the public network. Binding
/// loopback is not the fix: it breaks the probes and the scrape. Warn so an un-firewalled
/// deploy does not silently expose the hidden-dataset oracle.
fn warn_deployment_posture(config: &ServiceConfig) {
    let mgmt = config.service.management_addr.as_str();
    // Decided on the parsed address, not a string prefix. `is_loopback` covers every
    // spelling (127.0.0.1, 127.0.0.53, ::1) and also catches an explicit routable address
    // such as `10.0.0.7:9090`, which a wildcard-prefix test misses. An unparseable value
    // warns too: `preflight_service_bind` already requires `management_addr` to parse, so
    // that arm is only reachable by a config that is being rejected anyway.
    let exposed = mgmt
        .parse::<std::net::SocketAddr>()
        .ok()
        .is_none_or(|addr| !addr.ip().is_loopback());
    // INFO, not WARN: binding the pod interface is the documented deployment, so a warning
    // would fire on every correct production boot. Selectable by `event.action`.
    if exposed {
        info!(
            event.action = "config.posture",
            management_addr = %mgmt,
            "management plane is not bound to loopback; it serves /health, /metrics, and the \
             dataset-state oracle on that interface. Ensure a NetworkPolicy or host firewall \
             restricts it to in-cluster scrapers/probes"
        );
    }

    note_opt_in_surfaces(config, mgmt);

    // Re-identification posture (min_allele_count == 0) is warned centrally by
    // `suppression_disabled_warning`, fired from `ServiceConfig::preflight` in every
    // environment, so it is not duplicated here.

    warn_advertised_security_level(config);

    // Writer-authentication posture: with the shipped default (`writer_policy = off`) any
    // package that decrypts to this node's recipient key is published, and its writer
    // fingerprint is recorded but never checked. That is the `recovered` provenance kind.
    // A warning, because an operator should not have to infer that their publishers are
    // unauthenticated from a provenance string.
    if config.ingest.writer_policy == WriterPolicy::Off {
        warn!(
            event.action = "config.posture",
            writer_policy = "off",
            "ingest writer authentication is off: any package that decrypts to this node's key \
             is published, and its writer key is recorded but not verified (provenance \
             `recovered`). Set [ingest].writer_policy = \"warn\" to discover which fingerprints \
             arrive, then \"enforce\" with a per-channel allow-list"
        );
    }

    // The query-memory term an operator cannot derive from any single knob.
    //
    // Retained rows are already bounded: `max_total_query_bytes` is charged by each scan's
    // `RetentionSink` as rows accumulate, and the scan sheds with a 503 from inside itself,
    // so retained rows never reach `scan_pool_cap x max_query_bytes`.
    //
    // What the retention sink does not charge is the transient decode working set. To
    // produce rows at all, each admitted scan materialises a parquet row group, and that
    // allocation is live before any row is charged. The floor under a fully-saturated pool
    // is therefore `scan_pool_cap x max_parquet_row_group_bytes`, on top of whatever is
    // retained. At the shipped defaults that equals `max_total_query_bytes` exactly, so a
    // stock node is silent here. It fires when an operator raises
    // `max_parquet_row_group_bytes` or `query_concurrency` past what the shed budget
    // absorbs, which is the case that needs sizing attention.
    let (pool_cap, decode_floor) = decode_working_set_floor(config);
    // Bound once: the value is both a structured field and interpolated into the message,
    // so reading it twice could print the same number in two notations.
    let max_total = config.service.max_total_query_bytes;
    if decode_floor > max_total {
        warn!(
            scan_pool_cap = pool_cap,
            max_parquet_row_group_bytes = config.service.max_parquet_row_group_bytes,
            decode_floor_bytes = decode_floor,
            max_total_query_bytes = max_total,
            "beacon query memory: a saturated scan pool ({pool_cap}) decodes up to \
             {decode_floor} bytes of parquet row groups at once, which exceeds \
             [service].max_total_query_bytes ({max_total}). That decode working set is not \
             charged against the total, which bounds retained rows and sheds them with a 503, \
             so it adds on top of the total and an OOM kill becomes the failure mode instead \
             of a shed request. Lower [service].max_parquet_row_group_bytes or \
             [service].query_concurrency, or provision for the sum"
        );
    }

    // Audit existence posture, which outranks the content posture below. `enabled = false`
    // short-circuits every emit site in `audit.rs` before `tracing` is reached, so it
    // bypasses the `with_audit_floor` protection that stops `GDI_LOG`/`RUST_LOG` from
    // silencing the trail, and it is settable from the process environment
    // (`GDI_NODE__AUDIT__ENABLED=false`).
    //
    // It gates every event, not just queries: identity rotate/retire/init/restore, dataset
    // and channel suppression, metadata overlays, PME reseal and cache flush, keyless
    // degrade, override-store reload, purge-rejected. An operator who sets it to quieten
    // query logging also loses the record of `identity retire --force` and
    // `dataset take-down`.
    if !config.audit.enabled {
        warn!(
            "[audit].enabled is false, so the audit trail is off entirely: not just \
             per-query lines, but every operator action (identity rotate and retire, dataset \
             and channel take-down, metadata overrides, PME reseal). This bypasses the audit \
             log-level floor, so nothing else will record them. Set it true unless your DPIA \
             and retention policy explicitly cover running without an audit trail"
        );
    }

    // Audit content posture: `query_detail = true` widens the audit trail to record a
    // request's genomic coordinates, not just that a query occurred. Legitimate for a
    // controlled deployment, but the operator should opt into it knowingly, so warn when
    // auditing is on.
    if config.audit.enabled && config.audit.query_detail {
        warn!(
            "[audit].query_detail is true: the audit trail records beacon query parameters \
             (genomic coordinates), not only that a query occurred. Confirm this matches your \
             disclosure and retention posture"
        );
    }

    warn_inert_otel_config(config);

    // A [service] Parquet cap set below gdi-dataset-tool's frozen default lets the node
    // reject a package the tool validated and produced (the producer checks against
    // `ParquetCaps::default()`). Raising a cap only widens acceptance; lowering one below
    // the tool floor is a silent ingest-rejection footgun, so warn. The default agreement
    // is pinned by core's `service_default_caps_match_tool_default` test.
    let tool = gdi_node_standalone_core::validate_parquet::ParquetCaps::default();
    let s = &config.service;
    warn_if_cap_below_tool(
        "max_parquet_file_bytes",
        s.max_parquet_file_bytes,
        tool.max_parquet_file_bytes,
    );
    warn_if_cap_below_tool(
        "max_parquet_decompressed_bytes",
        s.max_parquet_decompressed_bytes,
        tool.max_parquet_decompressed_bytes,
    );
    warn_if_cap_below_tool(
        "max_parquet_row_group_bytes",
        s.max_parquet_row_group_bytes,
        tool.max_parquet_row_group_bytes,
    );
}

/// Warn when a `[service]` Parquet cap is configured below `gdi-dataset-tool`'s
/// frozen `ParquetCaps::default()` value — the node would then reject packages the
/// tool validated and produced. Raising a cap is safe (it only widens what the node
/// accepts); only a below-the-tool-floor value is the footgun.
fn warn_if_cap_below_tool(cap: &str, configured: u64, tool_default: u64) {
    if configured < tool_default {
        warn!(
            cap,
            configured,
            tool_default,
            "[service] Parquet cap is set below the gdi-dataset-tool default; the node may \
             reject packages the tool validated and produced. Raise it to at least the tool \
             default unless you intend to refuse larger packages"
        );
    }
}

/// Run `fut` to completion under panic isolation: a panic is caught in a child task,
/// logged and counted (`gdi_background_task_panics_total`), and does not propagate.
/// Wrapping a daemon loop's per-iteration work in this keeps one panicking iteration from
/// silently killing the loop.
async fn guarded(task: &'static str, fut: impl std::future::Future<Output = ()> + Send + 'static) {
    if let Err(e) = tokio::spawn(fut.instrument(info_span!("daemon", task))).await
        && e.is_panic()
    {
        warn!(task, "background task iteration panicked; continuing");
        metrics::background_task_panic();
    }
}

/// Spawn a self-restarting daemon: run `make()` to completion and, if it panics or
/// returns, log, count, back off and restart. For a loop whose body cannot be wrapped
/// per-iteration (an internal `run()` loop, such as the S3 bucket monitor).
///
/// `stop` is the retirement predicate. While it is false a clean return is an anomaly and
/// the task is restarted; once it is true the supervisor stops instead. That is what makes
/// a monitor replacement a replacement rather than a duplication. Aborting the supervisor
/// would not: `tokio::spawn` detaches, so dropping the inner task's `JoinHandle` leaves two
/// live monitors on one channel.
#[cfg(feature = "s3")]
fn spawn_supervised<F, Fut, S>(task: &'static str, instance: String, stop: S, make: F)
where
    F: Fn() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
    S: Fn() -> bool + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            if stop() {
                info!(task, instance = %instance, "background task retired; supervisor stopping");
                break;
            }
            // Stamp the per-instance identity (the bucket name) on the supervision span so
            // several instances of one `task` are distinguishable in a trace, not only in
            // the log body. Rebuilt each iteration so a restart gets a fresh span.
            let span = info_span!("daemon", task, instance = %instance);
            match tokio::spawn(make().instrument(span)).await {
                Ok(()) if stop() => {
                    // Retired while it ran: the task returned because it was stood down,
                    // so this is the expected exit, not the anomaly below. Re-checked here
                    // rather than only at the top of the loop, so retirement raised during
                    // a poll costs no restart.
                    info!(task, instance = %instance, "background task retired; supervisor stopping");
                    break;
                }
                Ok(()) => {
                    // A poll loop should never return; a clean return means it exited its
                    // own internal loop, a permanent condition. Back off before restarting,
                    // by the same delay as the panic arm, so a task that returns
                    // immediately cannot hot-spin the supervisor.
                    warn!(task, instance = %instance, "background task returned unexpectedly; backing off before restart");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Err(e) if e.is_panic() => {
                    warn!(
                        alert = true,
                        event.action = "task.panic",
                        event.outcome = "failure",
                        task,
                        instance = %instance,
                        "background task panicked; restarting after backoff"
                    );
                    metrics::background_task_panic();
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                // The join failed for a non-panic reason (the runtime is shutting down and
                // cancelled the child), so stop supervising.
                Err(_) => break,
            }
        }
    });
}

/// Add verify-specific guidance to a data-dir lock failure.
///
/// `verify` takes the writer lock, so on a running node it fails with the generic
/// single-writer message and writes nothing to stdout. That is correct fail-closed
/// behaviour, but a re-key runbook that pipes `verify` into `awk` then sees an empty
/// work-list and, without `set -o pipefail`, exit 0. Naming the fix here makes a manual
/// `verify` against a live node actionable.
fn contextualize_lock_error(err: anyhow::Error, is_verify: bool) -> anyhow::Error {
    if is_verify {
        err.context(
            "`verify` needs exclusive access to the data dir and a node is holding it. Stop \
             the node first, or run `verify` against a copy of the data dir. Do not treat this \
             run's empty output as \"all datasets healthy\": it verified nothing. In a script, \
             use `set -o pipefail` and assert a non-empty result.",
        )
    } else {
        err
    }
}

/// Whether the data-dir root needs tightening: `true` if any group or other permission bit
/// is set. An already owner-only dir (`0o700` or stricter) needs no chmod, which lets a
/// pre-tightened tmpfs, `emptyDir` or PV chowned to the node's run uid boot untouched. Mode
/// is half the question; [`check_data_dir_owner`] decides the other half, because an
/// owner-only dir the node does not own is one it cannot write.
#[cfg(unix)]
fn data_dir_needs_tightening(mode: u32) -> bool {
    mode & 0o077 != 0
}

/// This process's effective uid, or `None` when it cannot be determined.
///
/// Read from `/proc/self/status` — the `Uid:` line is `real effective saved fs`, so field 1
/// (0-indexed) is the effective uid, which is the one the kernel's DAC checks use and
/// therefore the one that must match the data dir's owner.
///
/// `None` on a Unix without procfs (macOS, or a container built without `/proc` mounted).
/// Callers treat that as "cannot judge ownership" and accept the dir: this check may only
/// add refusals it can justify, and the node's deployment target is Linux.
#[cfg(unix)]
fn effective_uid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|line| {
        let rest = line.strip_prefix("Uid:")?;
        rest.split_whitespace().nth(1)?.parse::<u32>().ok()
    })
}

/// Refuse an already-owner-only `data_dir` whose owner is not this process.
///
/// [`data_dir_needs_tightening`] answers on mode alone, so a root-owned `0o700` dir passes
/// it while an unprivileged node cannot open the dir at all. Without this check the failure
/// surfaces later as an opaque `EPERM` on the first write, far from the volume that caused
/// it. `fsGroup` produces exactly that shape: `chown -1:<gid>` leaves the owner root.
/// Refuse at boot instead, naming both uids.
///
/// Root (`euid == 0`) is exempt: it bypasses the kernel's DAC checks, so a dir it does not
/// own is still readable and writable, and the refusal's remedy would be to chown the
/// volume to uid 0, which breaks the unprivileged node the shipped image runs as.
///
/// # Errors
///
/// Returns an error when `owner` differs from a non-zero `euid`.
#[cfg(unix)]
fn check_data_dir_owner(data_dir: &Path, owner: u32, euid: u32) -> Result<()> {
    if owner == euid || euid == 0 {
        return Ok(());
    }
    Err(anyhow::anyhow!(
        "data dir {} is owned by uid {owner}, but this node runs as uid {euid}. The dir is \
         already owner-only (0o700), so there is nothing for the node to tighten, but \
         an owner-only dir owned by somebody else is one an unprivileged uid can neither read \
         nor write (root would bypass this, and is exempt from the check), and without it the \
         failure would surface later as an opaque EPERM on the first write. \
         chown the volume to uid {euid} (on Kubernetes: a root init container \
         (`deploy/kubernetes` ships one), a storage class that sets ownership, or a \
         pre-provisioned PV), or use a named volume, which the image pre-creates owned by the \
         run uid. `fsGroup` does not do this: it chowns the group only and leaves the owner \
         unchanged.",
        data_dir.display()
    ))
}

/// Tighten the data-dir root to owner-only (`0o700`) if it is not already, naming ownership
/// rather than the chmod when it cannot.
///
/// An unconditional chmod fails on a root-owned tmpfs, fresh `emptyDir` or PV, because chmod
/// needs ownership. So when the dir is already owner-only there is nothing to chmod and the
/// only question left is whether the node owns it ([`check_data_dir_owner`]); otherwise
/// chmod, and on failure explain that the node needs a data dir it owns, or one
/// pre-tightened by that uid. It never serves from a co-tenant-traversable dir.
///
/// # Errors
///
/// Fails to `stat` the dir, refuses an owner-only dir owned by another uid (unless running as
/// root, which is exempt), or cannot tighten a group/other-accessible dir it does not own.
#[cfg(unix)]
fn tighten_data_dir_root(data_dir: &Path) -> Result<()> {
    tighten_data_dir_root_as(data_dir, effective_uid())
}

/// The uid-injectable core of [`tighten_data_dir_root`]: `euid` is the effective uid to
/// judge ownership against, `None` when it could not be determined (ownership is then not
/// judged).
///
/// Split out so the refusal path is testable. Building a real foreign-owned directory needs
/// `chown`, so a test gated on that would skip wherever the runner is not root. Handing the
/// check a uid that is not the dir's owner exercises the same path everywhere.
///
/// # Errors
///
/// As [`tighten_data_dir_root`].
#[cfg(unix)]
fn tighten_data_dir_root_as(data_dir: &Path, euid: Option<u32>) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::PermissionsExt as _;
    let meta = std::fs::metadata(data_dir)
        .with_context(|| format!("stat data dir {}", data_dir.display()))?;
    let mode = meta.permissions().mode();
    if !data_dir_needs_tightening(mode) {
        // Already owner-only, so nothing to tighten. Whether it is usable depends on who
        // the owner is, which the mode cannot say; an unknown euid cannot judge it, so
        // accept.
        return match euid {
            Some(euid) => check_data_dir_owner(data_dir, meta.uid(), euid),
            None => Ok(()),
        };
    }
    std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
        anyhow::anyhow!(
            "cannot tighten data dir {} to owner-only (0o700): {e}. The node needs a data dir \
             it owns, or one already 0o700 and owned by its run uid, so a shared-volume \
             co-tenant cannot read the decrypted store. A root-owned tmpfs, fresh emptyDir or \
             PV is neither. chown the volume to the node's run uid, or pre-create it 0o700 as \
             that uid, which a named volume does. Pre-tightening alone is not enough: a 0o700 \
             dir owned by somebody else is refused too. The node refuses rather than serve \
             from a group- or other-traversable dir.",
            data_dir.display()
        )
    })
}

/// Acquire the single-writer advisory lock on `<data_dir>/.lock`, returning the held
/// [`std::fs::File`] (the lock releases when it drops, so on process exit). A node runs
/// exactly one writer per `data_dir`: every boot reaps `.incoming/*` and `.status.json` is
/// a whole-file last-writer-wins overwrite, so a second concurrent writer silently corrupts
/// a peer's in-flight ingest. This makes that fail fast.
///
/// # Errors
///
/// Returns an error if the lock file cannot be opened, or if another process already
/// holds the lock (run one writer per `data_dir` — see docs/operating.md §18).
fn acquire_data_dir_lock(data_dir: &Path) -> Result<std::fs::File> {
    use std::fs::TryLockError;
    let lock_path = data_dir.join(".lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .with_context(|| format!("opening data-dir lock {}", lock_path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => anyhow::bail!(
            "another gdi-node-standalone process already holds the data-dir lock {}; a node is \
             single-writer per data_dir (concurrent writers corrupt in-flight ingest). Run one \
             writer per volume: on k8s use an RWO PVC with `Recreate` (or RollingUpdate \
             maxSurge:0), or give each replica its own data volume (see \
             docs/operating.md section 18).",
            lock_path.display()
        ),
        Err(TryLockError::Error(e)) => {
            Err(anyhow::Error::from(e).context(format!("locking {}", lock_path.display())))
        }
    }
}

/// Run the serving preflight: config-shape validation, build-feature cross-checks and
/// deployment-posture warnings. Skipped for an offline-safe identity subcommand, which
/// never serves and must run on a box with no serving config (see [`IdentityCommand`]).
/// The preflight error names the resolved config path, so a missing or mistyped `--config`
/// is diagnosable rather than surfacing as a pathless `service.base_url is required`.
fn serving_preflight(
    command: Option<&Command>,
    config: &ServiceConfig,
    config_path: &Path,
) -> Result<()> {
    if matches!(command, Some(Command::Identity(_))) {
        return Ok(());
    }
    preflight::run(config).with_context(|| {
        format!(
            "service config failed startup preflight (config: {})",
            config_path.display()
        )
    })?;
    warn_deployment_posture(config);
    Ok(())
}

/// Process entry: parse the CLI, run, and turn the outcome into an exit status.
///
/// The split exists so that a refused start is a log event rather than a terminal message.
/// When serving, stderr is a log stream, and a refusal (an unreadable config, an override
/// store that is not intact, an identity that will not load) is the one fatal class no
/// metric rule can see: the process is gone before `/metrics` exists.
/// `logging::report_fatal` renders it as one structured, `Alert`-tagged line, keeping the
/// panic hook's "all stderr is NDJSON" promise, so a log rule raises the alarm with the
/// cause. A subcommand is an operator at a terminal, so its failure keeps the plain
/// `Error:` report.
#[tokio::main]
async fn main() -> std::process::ExitCode {
    // Parse the CLI surface once up front. `clap::Parser::parse` handles `--help` (usage
    // to stdout, exit 0) and an unrecognized or misdirected argument (usage to stderr,
    // exit 2) before any work runs, so neither silently boots the node on the
    // `GDI_CONFIG`/default config fallback.
    let cli = Cli::parse();
    // `serve` is the explicit spelling of the default: both are the serving process,
    // whose refusal is a log event (below), not a terminal message.
    let serving = matches!(cli.command, None | Some(Command::Serve));
    match run(cli).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) if serving => {
            logging::report_fatal(&error);
            std::process::ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("Error: {error:?}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "a linear startup orchestration reads better as one flow than split across helpers threading the same state"
)]
async fn run(cli: Cli) -> Result<()> {
    // Handle `--version` / `-V` (and its `version` subcommand spelling) before doing
    // any work: print the binary version and the pinned gdi-metadata model version (a
    // build-time constant, not a runtime config field), then exit.
    if cli.version || matches!(cli.command, Some(Command::Version)) {
        print_version();
        return Ok(());
    }

    // `config dump-defaults`: render the code's own defaults and exit. It reads no
    // config file and touches no data dir, so it is dispatched before the config load
    // below — it must work on a box with nothing deployed yet.
    if let Some(Command::Config(command)) = &cli.command {
        return run_config_command(command);
    }

    // Install the process-level panic hook first, so every panic — caught, escaping, from
    // spawn_blocking or from startup — is one JSON line and all of stderr stays valid
    // NDJSON for a line-based collector. It writes JSON directly rather than through the
    // subscriber, so it works before the subscriber is installed. That happens after config
    // load, so the optional OTLP trace exporter can read [service].otlp_endpoint.
    logging::install_panic_hook();

    // Install the process-wide rustls crypto provider (`ring`) before any TLS is
    // exercised. Compiled only when a TLS-using feature (`s3`/`vault`) is on; the
    // lite build links no rustls/ring at all.
    #[cfg(feature = "tls")]
    preflight::install_crypto_provider();

    // Config path precedence (highest first): the `--config` flag, the `GDI_CONFIG`
    // env var, then the default `/etc/gdi-node-standalone/node.toml` — `ServiceConfig::load`
    // applies that fallback when handed `None` for the flag.
    let cli_config = cli.config.as_deref();

    // `check-config` is a dry run: it runs the same load and preflight pass the live boot
    // uses, prints a human-readable result, and exits without serving — 0 on success,
    // non-zero on failure. Preflight validates config content only. It does not check that
    // [keys] files exist, that data_dir is writable, or that listen ports are bindable, so
    // a green check does not guarantee a clean boot; those are verified at startup.
    if matches!(cli.command, Some(Command::CheckConfig)) {
        return check_config(cli_config);
    }

    // `healthcheck`: the container HEALTHCHECK. Probe the management plane on
    // loopback and map ready/not-ready to the process exit code, then exit without
    // serving. Kept before logging/preflight so it stays a cheap, side-effect-free probe.
    if matches!(cli.command, Some(Command::Healthcheck)) {
        return run_healthcheck(cli_config);
    }

    // Load + preflight the config. `preflight::run` runs the feature-independent
    // ServiceConfig::preflight then the build-feature cross-checks (a config section
    // whose Cargo feature is not compiled in is rejected with a "rebuild with
    // --features …" error).
    let config_path = ServiceConfig::resolve_path(cli_config);
    let config =
        ServiceConfig::load(cli_config).map_err(|e| anyhow::anyhow!("loading config: {e}"))?;

    // Initialize structured logging now that config is loaded, wiring the optional OTLP
    // trace exporter from [service].otlp_endpoint (a no-op when unset or when the `otel`
    // feature is not compiled in). Held for the process lifetime so batched spans flush on
    // exit through `TelemetryGuard`'s `Drop`, including on the early-return identity
    // subcommands below. The panic hook is already installed above.
    let telemetry = init_logging(&config);
    // The first line, before any I/O: which binary this is, with its version and commit.
    //
    // Serving path only. The event is `service.start`, so emitting it from a one-shot would
    // say something untrue about what the process is doing — `dataset list` would announce
    // a service start and then print a table. The operator subcommands report themselves;
    // only `serve`, and its implicit spelling, starts a service.
    let serving = matches!(cli.command, None | Some(Command::Serve));
    if serving {
        info!(
            event.action = "service.start",
            version = env!("CARGO_PKG_VERSION"),
            git_sha = gdi_build_info::GIT_SHA,
            features = %LINKED_FEATURES.join(","),
            config_path = %config_path.display(),
            "service starting"
        );
    }

    // Install the metrics recorder before `load_identities` below.
    //
    // `metrics::` is a no-op until a recorder exists, so a write before this line lands on
    // nothing and the series is silently absent for the process lifetime. The subtle case
    // is transitive: `load_identities` writes Vault metrics (`gdi_vault_token_ttl_seconds`,
    // the `record_vault_call` histograms) from `vault.rs`, which
    // `test_metrics_recorder_ordering.py` cannot see because it reads only this file. On a
    // `[vault]`-without-`transit_key` node the liveness probe that would re-write the TTL
    // is `#[cfg(feature = "pme")]` and returns early, so that boot-time write is the only
    // one. Installing here covers the whole class; the config-derived series, which need
    // `&state`, are seeded after `AppState::new` below.
    let metrics_handle = metrics::install_recorder(telemetry.otel_mirror()).map(Arc::new);
    metrics::record_build_info();

    // Read-only one-shots (`doctor` and the `dataset` / `channel` verbs), dispatched before
    // the serving preflight and the data-dir writer lock, so they run while the node is
    // serving and stay usable even if a serving-only config section is misconfigured. Each
    // verb's positional and required flags are guaranteed by its args type.
    if let Some(command) = &cli.command
        && let Some(result) = run_lockfree_command(command, &config)
    {
        return result;
    }

    serving_preflight(cli.command.as_ref(), &config, &config_path)?;

    // One-shot identity subcommands (init / rotate / retire / list / backup / restore):
    // operator steps that provision or recover the node identity and exit.
    if let Some(Command::Identity(command)) = &cli.command {
        return run_identity_subcommand(command, &config).await;
    }

    // Also a one-shot that must run before the serve path touches the data dir: `pme
    // reseal` operates on a node that is currently refusing to serve.
    if let Some(Command::Pme(PmeCommand::Reseal(args))) = &cli.command {
        return gdi_node_standalone::pme_cmd::run_reseal(&config, args.yes).await;
    }

    // Operator-override presence assertion, before any dir is created, hydrated or served.
    // Reached only on the serve path: every one-shot operator subcommand above has already
    // returned, so a node whose store vanished can still be repaired with `dataset unhide`
    // or `dataset hide` while refusing to serve. Serving with a destroyed store would
    // silently re-disclose every withheld dataset (docs/operating.md §17), which is why
    // this is fatal rather than a warning.
    let override_root = config.service.override_dir_resolved();
    gdi_node_standalone_core::override_store::ensure_present(
        &override_root,
        config.service.require_override_store,
    )?;
    // The data dir, created before the used-marker sync below writes into it: the marker
    // lives on the data volume, so on a first boot the write would otherwise ENOENT and the
    // content assertion would run one boot late. The override-store assertion above stays
    // ahead of this because it must be a pure function of a filesystem the node has not
    // touched, and `data_dir` is a different directory.
    let data_dir = config.service.data_dir.clone();
    gdi_node_standalone_core::util::create_private_dir(&data_dir)
        .with_context(|| format!("creating data dir {}", data_dir.display()))?;
    // `create_private_dir` sets 0o700 only on components it creates, so a pre-existing
    // mounted `data_dir` keeps its prior, possibly world-traversable, mode. Tighten the root
    // explicitly on Unix so a shared-volume co-tenant cannot traverse into the decrypted
    // data tree. This makes the whole data tree owner-only, so a separate-uid reader (a
    // co-located backup, or a system consuming the decrypted store rather than the
    // .tar.c4gh packages) must run as the same uid or be granted an explicit ACL.
    #[cfg(unix)]
    tighten_data_dir_root(&data_dir)?;

    // The content half of the same assertion. `ensure_present` checks the store's
    // structure, which an empty-but-intact tree satisfies — the shape a structure-only
    // restore produces, and one that can resurrect an erased dataset. The used marker on
    // the data volume records that overrides have existed, so empty-after-use is
    // distinguishable from never-used and refuses here.
    gdi_node_standalone::override_marker::sync_and_assert(
        &config,
        config.service.require_override_store,
    )?;

    // An override subdirectory that exists but cannot be read is a refuse-to-start
    // condition on every posture, including the default one. At runtime an unreadable store
    // is survivable because the loaders keep their last-good set; at boot there is no
    // last-good set, so serving would mean serving with an unknowable withhold set. That is
    // the outcome this store exists to prevent, and it is unambiguous in a way absence is
    // not, which is why absence stays tolerated here and is governed by
    // `require_override_store` instead.
    for sub in [
        gdi_node_standalone_core::suppression::suppressions_subdir(&override_root),
        gdi_node_standalone_core::overlay_override::overlays_subdir(&override_root),
    ] {
        gdi_node_standalone_core::override_store::readable_or_absent(&sub).with_context(|| {
            format!(
                "operator-override directory {} exists but cannot be read; refusing to start \
                 rather than serve with an unknowable withhold set (fix the mount or its \
                 permissions)",
                sub.display()
            )
        })?;
    }

    // The converse, and the reason the assertion above is worth opting into: a node that
    // has overrides but has not declared them required is the state that loses them
    // silently. Nothing else on the node would say so, because an absent store reads as the
    // empty set and the loss surfaces as a clean recovery. Advisory, never fatal: the
    // operator may be mid-migration, and refusing to serve would be worse than the failure
    // being warned about.
    if !config.service.require_override_store
        && gdi_node_standalone_core::override_store::is_populated(&override_root)
    {
        warn!(
            override_dir = %override_root.display(),
            "operator overrides are recorded but service.require_override_store is not set: \
             this store is the one part of the data volume that re-ingest cannot rebuild, so \
             losing it would silently re-serve every withheld dataset with no error. Put it \
             on separately-backed storage and set service.require_override_store = true (see \
             docs/operating.md section 17)"
        );
    }

    // Single-writer guard, held for the process lifetime. Acquired before the `.incoming/`
    // reap and any ingest, so a second concurrent writer on the same `data_dir` fails fast
    // rather than silently corrupting in-flight ingest (the node has no other lock; see the
    // fn doc and docs/operating.md §18). On the serving path it is released by
    // `exit_serving` after the ingest quiesce; every other path drops it on return.
    //
    // `verify` also takes this lock, at the dispatch below, so on a running node it fails
    // here and writes nothing to stdout; `contextualize_lock_error` adds the guidance that
    // makes that empty result actionable.
    let data_dir_lock = acquire_data_dir_lock(&data_dir).map_err(|e| {
        contextualize_lock_error(e, matches!(cli.command, Some(Command::Verify(_))))
    })?;

    // Reap any stale .incoming/ working dirs; none of them is ever wanted.
    reap_incoming(&data_dir);

    // Complete any dataset erasure a crash interrupted (status purged, `data_dir/{id}/`
    // not yet removed). Runs before hydrate, so a purged-but-unremoved dataset is erased
    // and can never be re-served.
    let reaped =
        gdi_node_standalone_core::util::reap_deleting(&data_dir, config.service.inbox.as_deref());
    if !reaped.is_empty() {
        tracing::info!(
            count = reaped.len(),
            "completed interrupted dataset erasures on boot"
        );
    }

    // Load the persistent status index.
    let mut status =
        StatusIndex::load(&data_dir.join(".status.json")).context("loading .status.json")?;

    // Purge the status entries of the ids just reaped above.
    //
    // Erasing `data_dir/{id}/` without this leaves the entry and its `last_seen_signature`
    // behind. The cache evicts the id because its directory is gone, so `live` is false,
    // and the S3 reconcile's non-live branch then short-circuits on `last_seen == etag` for
    // the unchanged source object and never re-ingests it. The dataset would stay silently
    // absent until the provider modified the object or an operator intervened. Dropping the
    // entry restores the new-id path, which is what a completed erasure means. The inbox
    // path is unaffected: its signature short-circuit sits inside the `live` branch.
    for id in &reaped {
        if status.remove(id).is_some() {
            tracing::info!(
                dataset = %id,
                "purged the status entry of a reaped dataset so it can be re-ingested"
            );
        }
    }

    // Restore any `Unknown` provenance from the on-disk `provenance.json` sidecars: the
    // status index is the fast copy, the sidecars are the durable copy next to the data.
    // This heals an index whose provenance was lost or never recorded (e.g. a partially
    // rebuilt index) without a re-ingest. Non-fatal — the in-memory value is correct for
    // this run either way; a persist failure just retries next boot.
    let recovered = status.backfill_provenance_from_sidecars(&data_dir);
    if recovered > 0 {
        info!(
            recovered,
            "restored writer provenance from on-disk sidecars"
        );
        if let Err(e) = status.store(&data_dir.join(".status.json")) {
            warn!(error = %e, "failed to persist provenance backfill; will retry next boot");
        }
    }

    // Clear persisted `error` states whose class is node-retriable: a config, key or infra
    // fault a restart may have fixed, such as `unknown-catalog` cleared by adding the
    // catalog, or a Vault-derived `internal-error` cleared by restoring the key. A cleared
    // entry looks never-seen to the first reconcile and is re-ingested from its source, so
    // an operator who fixed the node is not left with a dataset branded by the fixed fault.
    // Data-fault errors (bad manifest, parquet or archive) are kept, because they need a
    // corrected package rather than a restart. Persist the pruned index immediately so the
    // cleared state is durable before the reconcile runs.
    let retried = status.drain_retriable_errors();
    if !retried.is_empty() {
        tracing::info!(
            count = retried.len(),
            datasets = ?retried,
            "cleared node-retriable ingest errors at startup; they will be re-attempted \
             from their source on the first reconcile"
        );
        status
            .store(&data_dir.join(".status.json"))
            .context("persisting the status index after clearing retriable errors")?;
    }

    // Load the node's crypt4gh identities. With `[vault]` configured and the `vault`
    // feature compiled, Vault is the source and takes precedence over the inline `[keys]`
    // files; otherwise identities come from `[keys].identities`, and an empty list means
    // keyless (plaintext only). The Vault path also yields the per-bucket S3 credential
    // overrides applied to the bucket monitors below. A transient Vault failure at startup
    // does not crash the node: it starts in a degraded keyless mode (encrypted packages
    // skipped, readiness 503, `gdi_keyless_degraded=1`). Identities are set once here, so
    // recovery is a restart once Vault is reachable, not an in-place retry.
    let LoadedSecrets {
        identities,
        s3_overrides,
        #[cfg(feature = "vault")]
        vault,
        pme,
        key_material_ok,
        vault_ok,
    } = load_identities(&config).await?;
    // A `vault`-without-`s3` build has no bucket credentials to refresh, so the retained
    // client has no consumer there.
    #[cfg(all(feature = "vault", not(feature = "s3")))]
    let _ = &vault;

    log_startup_summary(&config, &config_path, vault_ok);
    // Name each bucket's effective credential source. Vault overrides the config values
    // only when [vault].s3_path is set; otherwise a stale env var silently stays in force,
    // and the only other way to find out is a failing request.
    #[cfg(feature = "s3")]
    gdi_node_standalone::s3::log_credential_sources(&config, &s3_overrides);

    // A node that booted with `[vault]` configured but Vault unreachable runs in degraded
    // keyless mode: encrypted-package ingest is skipped, and it does not self-heal because
    // identities load once. Captured before `config` moves into the state, and surfaced as
    // an alertable latch just after the recorder is installed.
    let keyless_degraded = config.has_vault() && !key_material_ok;

    let state = AppState::new(config, status, identities);
    // Seed the readiness view from the startup secret-load outcome. `key_material` is
    // ready for a successful load or for the valid keyless mode; `vault` reflects whether
    // the client connected, and is consulted only when `[vault]` is configured. The S3 and
    // initial-reconcile flags are set later.
    state.readiness.set_key_material_ok(key_material_ok);
    state.readiness.set_vault_ok(vault_ok);
    // Attach the PME runtime (Vault-minted DEK + cached key retriever) when active;
    // a no-op when PME is off (the handle is `None`). The query path then decrypts
    // `PARE` files and ingest encrypts new writes.
    #[cfg(feature = "pme")]
    let state = state.with_pme(pme);
    #[cfg(not(feature = "pme"))]
    let _ = pme;

    // Config-derived metric series (bucket, channel and inbox label sets) and the sampler
    // need `&state`, so they run here, after `AppState::new`. The recorder itself is
    // installed before `load_identities`; see the note there. `install_recorder` returns
    // `None` only when a recorder is already installed, in which case there is nothing to
    // seed. `test_metrics_recorder_ordering.py` pins the ordering.
    if let Some(handle) = &metrics_handle {
        seed_config_series(&state);
        metrics::spawn_sampler(state.clone(), (**handle).clone());
    }

    // At-rest key check: prove the configured Transit master key still unwraps a DEK this
    // node already wrote. Runs once, here, because the alternative is discovering a
    // replaced key one dataset at a time as `error` or `scrub-failed`, which reads like
    // data corruption rather than a key incident.
    #[cfg(feature = "pme")]
    verify_at_rest_key(&state).await;

    // Re-hydrate the in-memory metadata cache from the already-published `datasets/{id}/`
    // directories before the inbox scan and S3 reconcile, so their sidecar reads can update
    // existing entries. The cache is the query-time source of truth and is never persisted,
    // so a restart whose data dir is already populated must reload it here or every
    // previously-ingested dataset vanishes from Beacon/FDP until its source is re-presented.
    //
    // Off the reactor via spawn_blocking, like the periodic `full_reload` path: the
    // O(datasets) manifest walk holds the cache write lock and issues blocking fs reads, so
    // running it on the async main task would park a reactor worker during cold start.
    let state_for_hydrate = state.clone();
    let hydrated = tokio::task::spawn_blocking(move || state_for_hydrate.hydrate_cache_from_disk())
        .await
        .unwrap_or_default();
    let rehydrated = hydrated.loaded;
    if rehydrated > 0 {
        info!(
            event.action = "cache.rehydrate",
            rehydrated, "re-hydrated dataset cache from disk"
        );
    }

    // Register every channel the status index still owns datasets for, not only the ones
    // the config currently declares. The staleness roster is otherwise seeded from
    // `[[s3.buckets]]` alone, so a provider whose entry was deleted — the documented
    // offboarding step — drops out of the roster entirely, with nothing measuring its
    // staleness and no `gdi_s3_*{channel=...}` series left to notice it. Registering it
    // seeds `false`, which puts it under the staleness bound and surfaces it as `degraded`
    // on a node that still declares at least one bucket, since `/health/ready` consults the
    // s3 rollup only when `has_s3_buckets`. A node with no bucket left reports the orphan
    // through the gauge and the warning below, not through readiness.
    //
    // The local inbox is excluded by name: it has no poll loop, so registering it would
    // withhold every inbox dataset one bound after boot.
    //
    // The block yields the orphaned channel names; their gauge is set below, after the
    // recorder exists, because a `metrics::` write before that lands on nothing. The
    // withhold itself must stay here, before the listener binds.
    let orphaned_channels: Vec<String> = {
        let owned: std::collections::BTreeMap<String, usize> = state
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entries()
            .values()
            .filter(|e| e.channel != gdi_node_standalone::health::INBOX_CHANNEL)
            .fold(std::collections::BTreeMap::new(), |mut acc, e| {
                *acc.entry(e.channel.clone()).or_default() += 1;
                acc
            });
        if !owned.is_empty() {
            state
                .readiness
                .register_configured_channels(owned.keys().map(String::as_str));
        }

        // Of those, the ones the config no longer declares are orphaned: no monitor is
        // built for them, so nothing polls their bucket and the provider deleting their
        // package, the documented retraction verb, has no effect on this node.
        //
        // They are already withheld. The hydrate above applies the orphan rule inside its
        // projection (`channel_is_orphaned`, over the live channel set), and every later
        // rescan re-applies it, so re-declaring the `[[s3.buckets]]` entry restores serving
        // on the next hydrate. The staleness bound cannot carry this alone: an orphan never
        // reconciles, so its staleness age measures from process start and every restart
        // hands the departed provider a fresh serving window. The immediate withhold needs
        // no clock. The registration above stays for the persistent `degraded` rollup on
        // `/health/ready`; this block only reports.
        let orphaned = state.orphaned_channels();
        if !orphaned.is_empty() {
            let summary: Vec<String> = orphaned
                .iter()
                .map(|(channel, count)| format!("{channel} ({count} dataset(s))"))
                .collect();
            warn!(
                channels = %summary.join(", "),
                "these channels own datasets but are no longer declared in [[s3.buckets]]: \
                 nothing polls them, so a provider deleting their package has no effect \
                 here. Their datasets are withheld from this boot; the local copies remain \
                 and nothing is erased. Re-add the [[s3.buckets]] entry to resume serving \
                 them, or erase them with `channel take-down <name>`"
            );
        }
        orphaned.into_iter().map(|(channel, _)| channel).collect()
    };

    // `verify` subcommand: offline store scrub, then exit, serving nothing. Runs after the
    // cache is hydrated so it sees every published dataset, but before any listener or
    // ingest starts, so it never touches the serve or readiness path.
    //
    // `hydrated.skipped` is handed over because `verify` enumerates the cache. A dataset
    // whose manifest.json is present but corrupt never entered it, so a report over what
    // was scrubbed alone would exit 0 while passing over the datasets whose integrity is
    // already known bad.
    if let Some(Command::Verify(args)) = &cli.command {
        return verify_store(&state, args, hydrated.skipped).await; // offline scrub then exit
    }

    // Enforce operator suppressions on the freshly-hydrated cache before the inbox scan and
    // S3 reconcile: force every Hide/Remove-suppressed dataset hidden, and erase every
    // `Remove` id. `hydrate` above seeds visibility from the status index, which a `Hide`
    // never touches, so a dataset an operator suppressed while the node was down would
    // otherwise be re-disclosed on this boot until the first SIGUSR1. The ingest gate then
    // keeps the subsequent scan and reconcile from re-ingesting a suppressed id. Placed
    // after the read-only `verify` return so a store scrub never triggers an erase.
    state.enforce_suppressions().await;
    // Same rationale for the node-local metadata-overlay override: a correction, or a
    // `--reset`, authored while the node was down must land on this boot rather than wait
    // for the first SIGUSR1. `hydrate` above already merged whatever durable overlay was
    // last written to disk, so this re-establishes precedence (operator over source) when
    // the node-local override and the durable file have diverged.
    state.enforce_local_overlays();
    // Bind the separate management-plane listener (health, dataset-state, metrics) before
    // the potentially slow store self-test, so `/health/live` answers 200 and
    // `/health/ready` answers 503 from this point rather than connection-refused. On a
    // populated PME node the self-test can take many seconds, because footer decrypts bridge
    // to Vault, so binding first keeps liveness probeable and avoids a startup-window
    // CrashLoop. `/health/ready` stays 503 throughout startup regardless, because
    // `initial_reconcile` is not marked done until data visibility is established below.
    //
    // The orphaned-channel gauge for the channels the block above withheld sits beside the
    // keyless latch: both are boot-outcome levels, and reading them together is how an
    // operator triages a degraded boot.
    for channel in &orphaned_channels {
        gdi_node_standalone::metrics::s3_channel_orphaned(channel, true);
    }
    // The catalog counterpart, evaluated here for the same triage reason. Reporting only:
    // unlike the channel case above, nothing is withheld.
    report_orphaned_catalogs(&state);
    // Flip the degraded-mode latch (a no-op when the node booted healthy, or if the
    // recorder failed to install).
    metrics::keyless_degraded(keyless_degraded);
    // Audit the boot-time entry into degraded keyless mode (a no-op on a healthy boot).
    audit::keyless_degraded(&state.config.audit, keyless_degraded);
    // Arm the SIGTERM/SIGINT handlers before the first listener binds. The call installs
    // them, not the returned future, so from this line on a signal is buffered and honoured
    // by the drain instead of killing the process outright (see the fn doc).
    //
    // Here and not earlier: everything above, including the disk cache re-hydrate that is
    // the slow part on a populated store, still runs with SIGTERM's default disposition,
    // and must. The offline `verify` subcommand returns before this line, and arming
    // earlier would install a handler nothing awaits, so a long `verify --full --digest`
    // would ignore Ctrl-C. Nothing is served in that stretch and the store is crash-safe.
    //
    // Installation is process-wide and permanent: tokio does not restore the default
    // disposition when the `Signal` is dropped. On the `?` paths between here and the serve
    // call — a management bind that fails, an inbox dir that cannot be created — a signal
    // is neither fatal nor observed by anything, and those paths exit on their own error.
    let shutdown = shutdown_signal();
    // The bind is a hard requirement: a failure aborts startup. The management server keeps
    // accepting until `mgmt_shutdown` fires, after the public drain below.
    let mgmt_shutdown = Arc::new(Notify::new());
    let mgmt_handle =
        serve_management(state.clone(), metrics_handle, Arc::clone(&mgmt_shutdown)).await?;

    // Probe store readability (off the async reactor — see the fn doc) and degrade
    // readiness if the loaded key material cannot read the existing store. Runs after the
    // management listener is bound, so health stays probeable while it runs.
    self_test_store_readable(state.clone()).await;

    let runtime = IngestRuntime::start(state.clone());

    // Signal handlers: SIGHUP (config reload, PME DEK-cache flush, bucket-monitor reload)
    // and SIGUSR1 (on-demand rescan). The monitor set is created here empty and filled by
    // `start_s3_monitors` below. The handler holds the same `Arc`, so a SIGHUP that lands
    // before the monitors start finds an empty set and treats every configured bucket as an
    // addition, which is what it is.
    #[cfg(feature = "s3")]
    let running_monitors: RunningMonitors = Arc::default();
    #[cfg(feature = "s3")]
    let s3_overrides = Arc::new(std::sync::RwLock::new(s3_overrides));
    #[cfg(feature = "s3")]
    let s3_reload = S3ReloadContext {
        inner: Some(S3ReloadInner {
            runtime: runtime.clone(),
            overrides: Arc::clone(&s3_overrides),
            running: Arc::clone(&running_monitors),
            #[cfg(feature = "vault")]
            vault,
        }),
    };
    #[cfg(not(feature = "s3"))]
    let s3_reload = S3ReloadContext::none();
    // Give `POST /reload` the same action the signal handler runs. Installed here rather
    // than passed to the router, because the management listener binds before the ingest
    // runtime and monitor set exist. Until this line the route answers 503, which is the
    // truth about a node that has not finished starting.
    {
        let hook_state = state.clone();
        let hook_path = config_path.clone();
        let hook_s3 = s3_reload.clone();
        state.reload_hook.install(Box::new(move || {
            let state = hook_state.clone();
            let path = hook_path.clone();
            let s3 = hook_s3.clone();
            Box::pin(
                async move { apply_config_reload(&state, &path, &s3, ReloadTrigger::Http).await },
            ) as _
        }));
    }
    // The same for `POST /reconcile`. Both hooks are futures; the difference is that the
    // route awaits the reload, because it reports the outcome, and detaches the reconcile,
    // which is unbounded work and answers 202.
    {
        let hook_state = state.clone();
        let hook_runtime = runtime.clone();
        state.reconcile_hook.install(Box::new(move || {
            let state = hook_state.clone();
            let runtime = hook_runtime.clone();
            Box::pin(reconcile_pass(state, runtime, "http")) as _
        }));
    }
    spawn_signal_handlers(&state, &runtime, &config_path, s3_reload);

    // Startup scan.
    runtime.scan_once().await;

    // Inbox watcher + periodic rescan, if an inbox is configured.
    if let Some(inbox) = state.config.service.inbox.clone() {
        // The inbox is an operator-provisioned ingress a provider drops into, so it keeps
        // its configured permissions. Unlike the rest of the data path, it is not forced
        // 0o700.
        #[expect(
            clippy::disallowed_methods,
            reason = "the inbox is an operator-provisioned ingress that keeps its configured permissions"
        )]
        std::fs::create_dir_all(&inbox)
            .with_context(|| format!("creating inbox {}", inbox.display()))?;
        // An inbox writable by more than its owner is a multi-tenant plaintext inbox, an
        // unsupported topology: a co-tenant can swap a just-validated staging file for a
        // symlink to another tenant's plaintext parquet between validation and the store
        // copy, a TOCTOU this plaintext path does not defend against. Warn rather than
        // carry a symlink-safe fd-verified copy for a posture no operator should run.
        //
        // The condition is the mode, not whether the node holds keys: `ingest_runtime`
        // accepts plaintext staging dirs on any node, so a keyed node is exposed exactly
        // like a keyless one. `ingest_runtime::copy_path_recursive` bounds the residual.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if let Ok(meta) = std::fs::metadata(&inbox) {
                let mode = meta.permissions().mode() & 0o777;
                if mode & 0o022 != 0 {
                    warn!(
                        event.action = "config.posture",
                        inbox = %inbox.display(),
                        mode = format!("{mode:o}"),
                        "UNSUPPORTED: a group/other-writable inbox is a multi-tenant plaintext \
                         inbox: a co-tenant can hijack an in-flight ingest via a symlink swap \
                         (TOCTOU), because plaintext staging dirs are accepted whether or not \
                         this node holds keys. Run a single-tenant 0700 inbox."
                    );
                }
                // Readability is a separate exposure: the inbox holds decrypted staging
                // dirs (allele-frequency parquet and VCF headers, both genotype-derived)
                // until ingest moves them, and rejected drops linger under `.rejected/`
                // for `rejected_retention_hours`. A 0o755 inbox, the umask default, lets
                // any local account read all of it next to a store kept at 0o700.
                if mode & 0o044 != 0 {
                    warn!(
                        event.action = "config.posture",
                        inbox = %inbox.display(),
                        mode = format!("{mode:o}"),
                        "a group- or other-readable inbox exposes decrypted dataset content: \
                         staging dirs hold allele-frequency parquet and VCF headers in \
                         plaintext until ingest completes, and rejected drops persist under \
                         .rejected/. The served store is 0700; the inbox should not be more \
                         permissive than what it feeds. Restrict it to the node's uid (0700), \
                         or to a single provider group (0750) if a separate account drops here."
                    );
                }
            }
        }
        spawn_watcher(runtime.clone(), &inbox);
        spawn_rescan_timer(
            runtime.clone(),
            state.config.service.rescan_interval_seconds,
        );
        info!(
            event.action = "inbox.start",
            "inbox ingestion runtime started"
        );
    } else {
        // A node with no ingest channel at all — no inbox and no `[[s3.buckets]]` — is
        // almost certainly a misconfiguration, and it reports `ready: true` while serving
        // whatever its data dir already holds, which is nothing on a fresh volume. The
        // shipped Kubernetes example has that shape until an operator adds a source, so the
        // signal has to be one an alert or a `grep -i warn` can see.
        //
        // With a bucket configured, "no inbox" is a normal posture and stays INFO.
        if state.config.has_s3_buckets() {
            info!("no inbox configured; ingestion runtime idle");
        } else {
            warn!(
                event.action = "config.posture",
                "no ingest channel configured: neither [service].inbox nor [[s3.buckets]]. \
                 This node can only serve what its data dir already holds; nothing will \
                 ever arrive. Configure a source (docs/deployment.md, \"Running against \
                 your own backends\") or run it as a read-only replica."
            );
        }
        // `spawn_rescan_timer` above, which also re-reads the operator override stores via
        // `IngestRuntime::full_reload`, is spawned only in the `Some(inbox)` arm. Without an
        // inbox nothing would periodically re-read a `dataset hide`, `take-down` or
        // `correct` written against this live node, because a bucket-owned dataset's S3 poll
        // loop never touches the override stores. So start the lighter override-only timer
        // here instead. It is mutually exclusive with `spawn_rescan_timer`'s reload and
        // enforce, so exactly one periodic path per override store exists on any node.
        spawn_override_reconcile_timer(state.clone(), state.config.service.rescan_interval_seconds);
    }

    // S3 bucket monitoring, only when the `s3` feature is compiled and `[[s3.buckets]]` is
    // configured. Each bucket runs a full startup reconcile for readiness, then its own
    // marker and full poll loop, feeding the one queue. `s3_overrides` carries any
    // Vault-backed per-bucket credentials, which take precedence over the inline values.
    #[cfg(feature = "s3")]
    {
        // Cloned into a local first: the read guard must not survive into the `.await`.
        let boot_overrides = s3_overrides
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        start_s3_monitors(&state, &runtime, &boot_overrides, &running_monitors).await;
    }
    #[cfg(not(feature = "s3"))]
    let _ = &s3_overrides;

    // The initial-reconcile gate. `initial_reconcile: done` means the node has established
    // data visibility, so `/health/ready` may report ready. That holds when there is no S3
    // to reconcile, or a restart re-hydrated datasets from disk and can serve them
    // regardless of S3, or at least one bucket's startup reconcile just succeeded
    // (`start_s3_monitors` awaited it above, so bucket health is current). A fresh S3 node
    // whose every bucket failed at boot is blind, and marking it done would let it answer
    // `exists:false` for data it should hold, so the gate stays pending and self-heals when
    // a later poll succeeds (see `BucketMonitor::reconcile`).
    let visibility_established =
        !state.config.has_s3_buckets() || rehydrated > 0 || state.readiness.any_bucket_ok();
    if visibility_established {
        state.readiness.mark_initial_reconcile_done();
    } else {
        warn!(
            "startup S3 reconcile established no data visibility (every bucket failed and no \
             datasets on disk); /health/ready stays not-ready until a bucket poll succeeds"
        );
    }

    // Detached periodic full store-readability sweep, off the readiness-gating critical
    // path, complementing the bounded boot self-test above by checking every dataset and
    // updating `gdi_store_scrub_failed`. Periodic rather than one-shot, because post-boot
    // corruption is the case the alert exists for.
    spawn_store_scrub_sweep(state.clone(), state.config.service.rescan_interval_seconds);

    // Periodic Vault token-liveness probe feeding `/health/ready`. Without it `vault_ok`
    // would be a boot-only snapshot, so a post-boot token expiry or revocation would leave
    // readiness green while encrypted datasets fail. Active only under PME, the runtime
    // Vault-token consumer; a no-op otherwise.
    #[cfg(feature = "pme")]
    spawn_vault_liveness_probe(state.clone());

    // The datasets-loaded count, logged at the point it is known: after the startup inbox
    // scan and every bucket's initial reconcile have populated the cache.
    info!(
        event.action = "cache.load",
        datasets_loaded = state.cache.len(),
        "initial dataset load complete"
    );

    // Serve the public plane until a bounded graceful drain, then tear down the
    // management listener (kept up throughout the drain — see the fn).
    let ingest_quiesce_budget =
        Duration::from_secs(state.config.service.shutdown_drain_seconds.max(1));
    let result =
        serve_public_then_stop_management(state, mgmt_shutdown, mgmt_handle, shutdown).await;

    let teardown_started = std::time::Instant::now();

    // After the public plane has drained, give any in-flight ingest blocking task a
    // bounded window to finish before the data-dir lock is released, so the single-writer
    // flock outlives the common-case writers. That includes a detached, non-cancellable
    // timed-out ingest still writing `datasets/{id}/`. It returns immediately when idle. If
    // the budget elapses the ingest is abandoned and not awaited by the runtime drop: the
    // process exits, terminating the write mid-flight. That is what `serve_http`'s doc and
    // operating.md §14 promise ("awaited, then abandoned"), and it is crash-safe — atomic
    // writes, the `.incoming` reap, and the re-hydrate on next boot — so the job re-queues
    // on the next startup.
    wait_for_quiescent(ingest_quiesce_budget, || runtime.inflight_blocking_count()).await;
    exit_serving(result, telemetry, data_dir_lock, teardown_started)
}

/// Best-effort wait for a non-zero `count` to drain to zero before the data-dir lock is
/// released on shutdown. Returns immediately when `count()` is already `0`; otherwise
/// polls it, bounded by `budget`. If the budget elapses the still-running work is
/// abandoned exactly as on a hard crash (crash-safe + re-queued on next boot), so the
/// caller proceeds to exit either way.
///
/// Takes a `count` getter rather than the runtime directly so the drain + timeout logic
/// is unit-testable with a controllable counter (mirroring `ingest_runtime`'s
/// `await_with_timeout`); `main` passes `|| runtime.inflight_blocking_count()`.
async fn wait_for_quiescent(budget: Duration, count: impl Fn() -> usize) {
    if count() == 0 {
        return;
    }
    info!("draining in-flight ingest before releasing the data-dir lock");
    let drained = tokio::time::timeout(budget, async {
        while count() > 0 {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    if drained.is_err() {
        warn!(
            "ingest still in flight after the drain budget; releasing the data-dir lock and \
             exiting (in-flight ingest is abandoned safely and re-queues on next startup)"
        );
    }
}

/// The serving process's exit: flush telemetry, release the data-dir lock, log the stop
/// with how long the post-drain teardown took, and leave without dropping the tokio
/// runtime.
///
/// Returning from `run` instead would let `#[tokio::main]` drop the runtime, which waits
/// for every started `spawn_blocking` closure to finish — the detached store-scrub sweep's
/// periodic pass, or an in-flight ingest that outlived `wait_for_quiescent`'s budget above.
/// A long closure would then be charged to the pod's grace period after `service.drained`,
/// with nothing logged. Exiting explicitly bounds shutdown regardless of what a blocking
/// closure is doing.
///
/// Everything that must survive the exit already has: every durable write is eager and
/// atomic, the OTLP batch is flushed here explicitly, and the kernel releases the flock and
/// zeroes freed pages. What is skipped is destructors — the sweep's own bookkeeping, a
/// gauge the next boot recomputes, and the identity map's zeroize, whose pages are freed to
/// the kernel rather than to another process — and any `spawn_blocking` closure still
/// running. So an ingest that outlived the quiesce budget is terminated mid-write rather
/// than awaited. That is crash-safe: it staged under `.incoming/`, `processing` was never
/// persisted, and the job re-queues on the next boot.
///
/// `teardown_ms` is the ingest quiesce plus this function up to the log call. It excludes
/// the telemetry flush below it, which must run after the event is emitted. The `Err` arm
/// reports through [`logging::report_fatal`] and carries no timing: a node that failed
/// mid-serve logs the cause, not a teardown duration.
fn exit_serving(
    result: Result<()>,
    mut telemetry: logging::TelemetryGuard,
    data_dir_lock: std::fs::File,
    teardown_started: std::time::Instant,
) -> ! {
    let teardown_ms = u64::try_from(teardown_started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let code = match result {
        Ok(()) => {
            info!(
                event.action = "service.stopped",
                teardown_ms, "shutdown complete; exiting"
            );
            0
        }
        Err(error) => {
            logging::report_fatal(&error);
            1
        }
    };
    telemetry.shutdown();
    drop(data_dir_lock);
    std::process::exit(code)
}

/// Serve the public data plane until its bounded graceful drain completes, then stop the
/// management listener.
///
/// The ordering matters: the management plane (`/health/ready` → `503` while draining,
/// `/health/live` → `200`, `/metrics`) stays up for the whole public drain, so probes and
/// scrapes keep getting real responses instead of connection-refused. Otherwise a pod still
/// finishing in-flight requests could be `SIGKILL`ed. The management drain is best-effort
/// time-bounded, so process exit never hangs on it.
///
/// `shutdown` is threaded in rather than created here because it must be armed before any
/// listener binds — see [`shutdown_signal`].
async fn serve_public_then_stop_management(
    state: AppState,
    mgmt_shutdown: Arc<Notify>,
    mgmt_handle: tokio::task::JoinHandle<()>,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> Result<()> {
    let result = serve_http(state, shutdown).await;
    mgmt_shutdown.notify_one();
    let _ = tokio::time::timeout(Duration::from_secs(2), mgmt_handle).await;
    result
}

/// Store-readability and key self-test: probe a bounded sample of the re-hydrated datasets'
/// parquet through the configured decryptor ([`SELF_TEST_SAMPLE`]). For a PME store this
/// decrypts the footer, so a loaded key that cannot decrypt the existing store fails
/// readiness here with a clear error rather than the node coming up and serving `error`
/// datasets per query. A plaintext store is confirmed readable, a light corruption check; a
/// fresh node with no data is a no-op.
///
/// The blocking probe runs under [`tokio::task::spawn_blocking`]. Under PME a cold-cache
/// footer decrypt bridges to Vault via `Handle::block_on`, which panics on a runtime worker
/// thread, so it must run on a blocking-pool thread, as the ingest and beacon probe sites
/// do. A panic inside the probe degrades readiness rather than aborting startup.
async fn self_test_store_readable(state: AppState) {
    let probe = state.clone();
    if tokio::task::spawn_blocking(move || self_test_probe(&probe))
        .await
        .is_err()
    {
        tracing::error!(
            "store-readability self-test panicked; reporting not ready (key material may not match the store)"
        );
        state.readiness.set_key_material_ok(false);
    }
}

/// The bounded sample the boot self-test probes on the critical path. The full store is
/// swept off-path by [`spawn_store_scrub_sweep`]; probing every dataset here would hold
/// `/health/ready` at 503 for a cold Vault round trip per distinct DEK, for a check whose
/// verdict is a global key-material question that a sample answers.
///
/// The unwraps are not serialised behind a process-wide lock: [`gdi_node_standalone::pme`]
/// uses per-key single-flight guards so unrelated reads do not queue, and the real bound is
/// the blocking pool's width. A DEK is minted per parquet file, so this constant caps
/// datasets while the probe iterates files; the two are not the same quantity.
const SELF_TEST_SAMPLE: usize = 24;

/// The opt-in management surfaces that are on, as one boot notice. The loopback notice
/// names only the read surfaces every node serves; these are the ones an operator chose,
/// and the one that acts (`[control]`) is unauthenticated like the rest of the plane. Named
/// from the same list `check-config` prints, so neither can enumerate a different set. INFO,
/// because the operator opted in: it repeats a decision, not a fault.
fn note_opt_in_surfaces(config: &ServiceConfig, mgmt: &str) {
    let mut opt_in: Vec<String> = Vec::new();
    if config.service.expose_dataset_list {
        opt_in.push(
            "GET /datasets + /datasets/suppressed (the whole inventory, hidden datasets included)"
                .to_owned(),
        );
    }
    if config.stats.enabled {
        opt_in
            .push("GET /stats/queries (per-dataset counters, hidden datasets included)".to_owned());
    }
    if config.control.enabled {
        opt_in.push(format!(
            "POST {} (operator ACTIONS, unauthenticated)",
            gdi_node_standalone::app::CONTROL_ROUTES.join(", ")
        ));
    }
    if !opt_in.is_empty() {
        info!(
            event.action = "config.posture",
            management_addr = mgmt,
            surfaces = %opt_in.join("; "),
            "opt-in management-plane surfaces are ON; the plane authenticates nothing, so \
             the bind address and a NetworkPolicy are the only controls on who reaches them"
        );
    }
}

/// The optional subsystems this binary was built with, for the `service.start` line, so the
/// first line of a log says which shape of node is starting.
const LINKED_FEATURES: &[&str] = &[
    #[cfg(feature = "s3")]
    "s3",
    #[cfg(feature = "vault")]
    "vault",
    #[cfg(feature = "pme")]
    "pme",
    #[cfg(feature = "otel")]
    "otel",
];

/// The blocking body of [`self_test_store_readable`] — must run off the async
/// reactor (see that function's doc).
fn self_test_probe(state: &AppState) {
    let ids: Vec<String> = state
        .cache
        .ids()
        .into_iter()
        .take(SELF_TEST_SAMPLE)
        .collect();
    if ids.is_empty() {
        return;
    }
    let sampled = ids.len();
    let mut failures = 0usize;
    for id in &ids {
        let r = scrub::scrub_dataset(state, id, scrub::ScrubDepth::Footer);
        if !r.ok {
            failures += 1;
            warn!(dataset = %id, detail = %r.detail, "store self-test: a sampled dataset is not readable with the loaded key material");
        }
    }
    // Flip readiness to not-ready only when every sampled dataset failed, which is a global
    // key-material mismatch. A single corrupt dataset is a per-dataset matter, surfaced by
    // the background sweep gauge `gdi_store_scrub_failed`, and must not 503 the whole node.
    if failures == sampled {
        tracing::error!(
            sampled,
            "store self-test: every sampled dataset is unreadable; reporting not ready (the loaded key material likely does not match the store)"
        );
        state.readiness.set_key_material_ok(false);
    } else if failures > 0 {
        warn!(
            sampled,
            failures,
            "store self-test: some sampled datasets unreadable; node stays ready (see gdi_store_scrub_failed)"
        );
    }
}

/// Log the one-line consolidated startup summary: the resolved config-file path, listen
/// address, base URL, catalog count, and S3 and Vault connection status. The
/// datasets-loaded count is not known yet, because the initial reconcile has not run, and
/// is logged separately once the cache is populated. Only non-secret fields are logged.
fn log_startup_summary(config: &ServiceConfig, config_path: &Path, vault_ok: bool) {
    // "configured", not "starting": the `service.start` line at the top of `run` is the
    // one that says which binary is starting; this one says what it resolved to.
    info!(
        event.action = "service.configure",
        config_path = %config_path.display(),
        listen = %config.service.listen,
        base_url = %config.service.base_url,
        catalogs = config.catalogs.len(),
        s3 = s3_status(config),
        vault = vault_status(config, vault_ok),
        "service configured"
    );
    for (audience, url) in registration_urls(
        &config.service.base_url,
        &config.beacon.aggregated_base_path,
        &config.beacon.sensitive_base_path,
        config.fairdp.is_some(),
    ) {
        info!(
            event.action = "service.registration_url",
            audience,
            url = %url,
            "public registration URL (forward to the federation)"
        );
    }
}

/// The public URLs a node operator forwards for federation enrollment, labelled by
/// audience.
///
/// The node does not self-register: an operator hands the beacon URL to the Beacon Network
/// aggregator and the `fairdp` URL to the FDP harvester. The aggregated and sensitive beacon
/// collapse to one URL when the node mounts them combined, which is the default; the FDP URL
/// is present only when `[fairdp]` is configured. Each is `base_url` plus the mount path,
/// and must equal what the operator forwards, because the node mints these same IRIs into
/// its FDP output and a mismatched URL breaks the harvester's crawl.
fn registration_urls(
    base_url: &str,
    aggregated_path: &str,
    sensitive_path: &str,
    has_fairdp: bool,
) -> Vec<(&'static str, String)> {
    let base = base_url.trim_end_matches('/');
    let mut urls = Vec::new();
    if aggregated_path == sensitive_path {
        urls.push((
            "beacon (aggregated + sensitive)",
            format!("{base}{aggregated_path}"),
        ));
    } else {
        urls.push(("beacon (aggregated)", format!("{base}{aggregated_path}")));
        urls.push(("beacon (sensitive)", format!("{base}{sensitive_path}")));
    }
    if has_fairdp {
        urls.push(("fairdp", format!("{base}/fairdp")));
    }
    urls
}

/// Spawn a detached, periodic full store-readability sweep (footer depth, every dataset)
/// that quarantines any unreadable dataset — state `Error`, evicted from the served view —
/// and updates the `gdi_store_scrub_failed` gauge. It is the complete check the bounded boot
/// self-test cannot afford on the readiness-gating critical path, and it never gates
/// readiness.
///
/// Runs shortly after startup and then every `[service].rescan_interval_seconds`. Periodic,
/// because on-disk corruption is not a boot-time event: bit-rot, a failing volume or an
/// out-of-band write all happen while the node serves, and a one-shot sweep would pin
/// `gdi_store_scrub_failed` to its boot value for the process lifetime. The cadence reuses
/// `rescan_interval_seconds`, the periodic safety-net knob the override reconcile timer also
/// uses, rather than adding a knob. Cost is bounded: footer depth for every dataset plus a
/// rotating hash-only digest slice on the periodic passes ([`scrub::ScrubPass`]; the first,
/// immediate tick skips the slice). The DEK cache absorbs the per-dataset Vault fetch after
/// the first pass, so steady-state cost is disk reads, off the request path in
/// `spawn_blocking`.
///
/// The count is self-correcting rather than latched: a quarantined dataset stays in
/// `cache.ids()`, so it is re-scrubbed and re-counted each pass and the gauge holds while
/// the corruption does. Repairing the file clears the alert on the next sweep, while the
/// dataset stays quarantined in `Error` until re-ingested. The gauge tracks corruption, not
/// quarantine.
///
/// It takes no shutdown signal: the serving process exits explicitly after the ingest
/// quiesce ([`exit_serving`]), so an in-flight pass is abandoned with the process.
fn spawn_store_scrub_sweep(state: AppState, interval_seconds: u64) {
    // `0` would make `interval` panic; floor to the same 1s minimum the other timers use.
    let period = Duration::from_secs(interval_seconds.max(1));
    tokio::spawn(
        async move {
            let mut ticker = tokio::time::interval(period);
            // A sweep that overruns the period must not queue up burst ticks behind it.
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // The immediate first tick is the startup sweep; it leaves out the rotating
            // digest slice — see [`scrub::ScrubPass`].
            let mut pass = scrub::ScrubPass::Boot;
            loop {
                ticker.tick().await;
                let scan = state.clone();
                let this_pass = pass;
                match tokio::task::spawn_blocking(move || scrub::run_scrub_sweep(&scan, this_pass))
                    .await
                {
                    Ok(failed) => {
                        gdi_node_standalone::metrics::record_store_scrub(failed);
                        if failed > 0 {
                            warn!(
                                failed,
                                "store sweep complete: some datasets are not readable"
                            );
                        } else {
                            // DEBUG: this fires every `rescan_interval_seconds` and says
                            // nothing happened, so at INFO it would dominate an idle log.
                            // The failure arm stays WARN, and `gdi_store_scrub_failed`
                            // carries the state either way.
                            debug!("store sweep complete: all datasets readable");
                        }
                    }
                    // Keep sweeping: a panic in one pass must not freeze the gauge, and
                    // with it the alert, for the rest of the process lifetime.
                    Err(e) => warn!(error = %e, "store sweep task panicked"),
                }
                pass = scrub::ScrubPass::Periodic;
            }
        }
        .instrument(info_span!("daemon", task = "store_scrub_sweep")),
    );
}

/// Interval between Vault token-liveness probes. Once a minute is frequent enough to catch
/// a token expiry or revocation promptly and cheap enough that one `transit/datakey` mint
/// per minute is negligible; the mint is stateless and non-destructive. See
/// [`gdi_node_standalone::pme::Pme::probe_vault`], which exercises the transit capability
/// rather than the cheaper `lookup-self`, because `lookup-self` stays green while the
/// transit mount is denied.
#[cfg(feature = "pme")]
const VAULT_LIVENESS_INTERVAL: Duration = Duration::from_mins(1);

/// Check the at-rest master key against the sentinel and record the verdict.
///
/// Complements the periodic liveness probe, which neither subsumes nor is subsumed by this.
/// The probe mints a datakey, proving the transit capability, which a brand-new key created
/// under the same name satisfies identically. Only unwrapping a previously wrapped DEK
/// proves the key is the one that encrypted the existing store.
#[cfg(feature = "pme")]
async fn verify_at_rest_key(state: &AppState) {
    use gdi_node_standalone::health::AtRestHealth;
    use gdi_node_standalone::pme::SentinelVerdict;

    let Some(pme) = state.pme.clone() else {
        // PME configured but inactive (Vault unreachable at boot) is already warned about
        // by `build_pme_runtime`; there is no key to check and nothing to latch.
        return;
    };
    let data_dir = state.config.service.data_dir.clone();
    match pme.verify_or_create_sentinel(&data_dir).await {
        SentinelVerdict::Verified => {
            state.readiness.set_at_rest(AtRestHealth::Ok);
            metrics::pme_master_key_mismatch(false);
        }
        SentinelVerdict::Created => {
            info!("at-rest key sentinel created; future boots will verify against it");
            state.readiness.set_at_rest(AtRestHealth::Ok);
            metrics::pme_master_key_mismatch(false);
        }
        SentinelVerdict::Mismatch(detail) => {
            // One line, not one per dataset.
            tracing::error!(
                detail = %detail,
                sentinel = %data_dir.join(gdi_node_standalone::pme::SENTINEL_FILE).display(),
                "the configured Transit master key cannot decrypt data written by this node: \
                 the key was replaced or the secrets backend was reset. PME data at rest is \
                 undecryptable and the node will not serve. See docs/operating.md \
                 section 17 (Disaster recovery). If you have already completed the recovery \
                 (or a section 10 key rotation's re-ingest) and the store is readable under \
                 the new key, clear this latch with \
                 `gdi-node-standalone pme reseal --yes`; it re-proves the store against the \
                 current key before rewriting the sentinel, and refuses if the mismatch is real"
            );
            state.readiness.set_at_rest(AtRestHealth::Mismatch);
            metrics::pme_master_key_mismatch(true);
            // The metric and the readiness flip are both ephemeral: a gauge is a level, not
            // a record, and `/health/ready` forgets on restart. The audit line is durable,
            // and it is what makes a later `pme_sentinel_resealed` legible — that event
            // records an overwrite of key provenance, and without this the WORM stream would
            // show the overwrite and never the incident that prompted it.
            audit::pme_master_key_mismatch(&state.config.audit, &detail);
        }
        SentinelVerdict::Unverifiable(detail) => {
            // A local fault: the sentinel is unreadable, unparseable, or names an unknown
            // scheme. Unlike an unreachable backend this does not heal on its own, and it is
            // the shape of a restored data volume whose Transit key was replaced, the
            // incident this check exists to catch. Report `at_rest: "unavailable"` rather
            // than "ok", and hold the mismatch metric at false: nothing here says the key is
            // wrong, only that it cannot be told. `pme reseal --yes` is the operator path for
            // a damaged sentinel; it re-proves the store against the current key before
            // rewriting, and refuses outright when the scheme is one this build does not
            // know, where the step is a newer binary instead.
            //
            // The metric is written here, to `false`, rather than skipped: a gauge is a
            // level, so leaving it unwritten would let a stale `true` stand.
            tracing::error!(
                detail = %detail,
                "at-rest key check could not be completed from local state (sentinel \
                 unreadable, unparseable, or an unknown scheme); reporting at_rest \
                 unavailable. Run \
                 `gdi-node-standalone pme reseal --yes` after confirming the store is intact"
            );
            state.readiness.set_at_rest(AtRestHealth::Unverifiable);
            metrics::pme_master_key_mismatch(false);
            // The durable record. `/health/ready` renders this verdict as
            // `at_rest: "unverifiable"` and a real key incident as `"mismatch"`, so the two
            // are distinguishable there too, but the probe forgets on restart and the audit
            // line does not.
            audit::pme_at_rest_unverifiable(&state.config.audit, &detail);
        }
        SentinelVerdict::Indeterminate(detail) => {
            // Says nothing about the key: an unreachable Vault, or a corrupt sentinel.
            // Latching a mismatch here would take a healthy node out of rotation over a
            // network blip, and the latch needs a restart to clear. The `vault_ok` and
            // keyless handling already cover an unreachable backend.
            warn!(
                detail = %detail,
                "at-rest key check inconclusive; not latching a mismatch"
            );
            state.readiness.set_at_rest(AtRestHealth::Ok);
            metrics::pme_master_key_mismatch(false);
        }
    }
}

/// Periodically re-validate Vault token liveness during serving and feed it into
/// `/health/ready`.
///
/// `vault_ok` is otherwise a boot-only snapshot, so a post-boot token expiry, revocation or
/// failed re-auth would leave readiness green while the next cache-miss `transit/decrypt`
/// returns 403 and encrypted datasets degrade. This flips `vault_ok` false on a probe
/// failure, so the orchestrator drains the wedged node, and back true on recovery. Spawned
/// only when PME is active, the sole runtime Vault-token consumer; a keyless node, or one
/// with Vault but no PME, has no live token to lapse after boot.
#[cfg(feature = "pme")]
fn spawn_vault_liveness_probe(state: AppState) {
    let Some(pme) = state.pme.clone() else {
        return;
    };
    // One alarm per excursion. The probe runs every minute, so re-raising the
    // `Alert`-tagged line on every tick would open one ticket a minute for as long as Vault
    // is down, and say nothing when it comes back. The transitions are what a person needs;
    // the steady state is on `gdi_health_ready{component="vault"}`.
    let vault_was_ok = Arc::new(std::sync::atomic::AtomicBool::new(true));
    tokio::spawn(
        async move {
            let mut ticker = tokio::time::interval(VAULT_LIVENESS_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // Consume the immediate first tick — boot already set the initial `vault_ok`.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                // Guarded so a panic in `probe_vault` cannot kill the loop and freeze
                // `vault_ok`, possibly at true, which would leave `/health/ready` green
                // after a token lapse and defeat the drain.
                guarded("vault_liveness", {
                    let pme = pme.clone();
                    let readiness = state.readiness.clone();
                    let vault_was_ok = Arc::clone(&vault_was_ok);
                    async move {
                        match pme.probe_vault().await {
                            Ok(()) => {
                                readiness.set_vault_ok(true);
                                if !vault_was_ok.swap(true, std::sync::atomic::Ordering::AcqRel) {
                                    info!(
                                        event.action = "vault.token.probe",
                                        event.outcome = "success",
                                        "vault token-liveness probe recovered; vault ready again"
                                    );
                                }
                            }
                            Err(e) => {
                                readiness.set_vault_ok(false);
                                if vault_was_ok.swap(false, std::sync::atomic::Ordering::AcqRel) {
                                    warn!(
                                        alert = true,
                                        event.action = "vault.token.probe",
                                        event.outcome = "failure",
                                        error = %e,
                                        "vault token-liveness probe failed; marking vault not ready"
                                    );
                                } else {
                                    debug!(error = %e, "vault token-liveness probe still failing");
                                }
                            }
                        }
                    }
                })
                .await;
            }
        }
        .instrument(info_span!("daemon", task = "vault_liveness")),
    );
}

/// The offline `verify` store scrub: scrub every loaded dataset at `depth` with
/// bounded concurrency, print a per-dataset report, and return an error (non-zero
/// exit) if any dataset fails. Binds no listener and starts no ingest.
async fn verify_store(state: &AppState, args: &VerifyArgs, unreadable: usize) -> Result<()> {
    // The two flags are independent, not a ladder: `--digest` verifies the at-rest sidecar
    // (hash only), `--full` validates every row, and asking for both runs both.
    let depth = match (args.full, args.digest) {
        (true, true) => scrub::ScrubDepth::FullDigest,
        (false, true) => scrub::ScrubDepth::Digest,
        (true, false) => scrub::ScrubDepth::Full,
        (false, false) => scrub::ScrubDepth::Footer,
    };
    let concurrency = args.concurrency;
    let ids: Vec<String> = state.cache.ids();
    let total = ids.len();
    if total == 0 {
        println!("verify: no datasets in the store");
        // An empty cache is not nothing to report: every dataset on disk may have been
        // skipped for an unreadable manifest, which is the worst store this command can be
        // pointed at.
        if unreadable > 0 {
            println!(
                "FAIL  (whole store)  {unreadable} dataset dir(s) skipped: manifest.json \
                 present but unreadable or corrupt"
            );
            anyhow::bail!(
                "{unreadable} dataset dir(s) could not be loaded (corrupt or unreadable \
                 manifest.json) and were not verified"
            );
        }
        return Ok(());
    }
    // Bound the per-dataset parallelism: process `limit` datasets at a time.
    //
    // This bounds Vault concurrency, not only disk and CPU. The DEK unwraps are not
    // serialised behind a process-wide lock — per-key single-flight guards keep unrelated
    // reads from queueing — so `limit` datasets can issue `limit` simultaneous
    // `transit/decrypt` calls. Keep it modest when Vault is shared with a live node, which
    // the runbook contemplates. A chunked join keeps this dependency-free.
    let limit = if concurrency == 0 { 4 } else { concurrency }.max(1);
    let owned = state.clone();
    let mut results: Vec<scrub::ScrubResult> = Vec::with_capacity(total);
    for chunk in ids.chunks(limit) {
        let mut handles = Vec::with_capacity(chunk.len());
        for id in chunk {
            let state = owned.clone();
            let id = id.clone();
            handles.push(tokio::task::spawn_blocking(move || {
                scrub::scrub_dataset(&state, &id, depth)
            }));
        }
        for h in handles {
            results.push(h.await.unwrap_or_else(|e| scrub::ScrubResult {
                id: String::new(),
                ok: false,
                // A panicked scrub task says nothing about the data, but `verify` reports
                // rather than quarantines, so this stays a plain failure.
                transient: false,
                detail: format!("scrub task panicked: {e}"),
            }));
        }
    }
    results.sort_by(|a, b| a.id.cmp(&b.id));

    let mut failed = 0usize;
    for r in &results {
        if r.ok {
            println!("ok    {}  {}", r.id, r.detail);
        } else {
            failed += 1;
            println!("FAIL  {}  {}", r.id, r.detail);
        }
    }
    // A dataset whose manifest.json is corrupt never entered the cache, so it is absent
    // from `ids` and was never scrubbed. Printed in the same `FAIL  ` shape the runbook's
    // `awk '/^FAIL/'` recipe greps for, so an existing pipeline picks it up.
    if unreadable > 0 {
        println!(
            "FAIL  (not loaded)  {unreadable} dataset dir(s) skipped: manifest.json present \
             but unreadable or corrupt; not verified"
        );
    }
    println!(
        "verify: {total} dataset(s), {failed} failed, {unreadable} not loaded \
         (depth: {depth:?}, concurrency: {limit})"
    );
    if failed > 0 || unreadable > 0 {
        anyhow::bail!(
            "{failed} of {total} dataset(s) failed verification, and {unreadable} could not \
             be loaded to be verified at all"
        );
    }
    Ok(())
}

/// Max concurrent accepted connections on one listener. Both planes serve through
/// [`serve_bounded`], so the public and management listeners each get this cap.
///
/// Bounds the file descriptors and per-connection tasks a connection flood can create. The
/// request-concurrency limit (`[service].max_concurrent_requests`) caps in-flight requests,
/// not open connections, so a slowloris or idle-keep-alive flood would otherwise accumulate
/// unbounded before any request-layer control engages. Excess connections are closed at
/// accept. Generous for a node behind an ingress, which pools upstream connections; pair it
/// with an ingress connection cap for direct internet exposure.
const MAX_PUBLIC_CONNECTIONS: usize = 2048;

/// Max time to read a request's headers before the connection is dropped.
///
/// Kills slowloris-style slow-header attacks, which the request-layer `TimeoutLayer` never
/// sees: it bounds only the body and handler phase, after hyper has read the head. Generous
/// for a legitimate client, far below any slow-drip dwell time. Keep-alive idle time between
/// requests is unaffected; this bounds only the header read.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);

/// Back-off applied after a failed `accept()` before retrying. A persistent accept error,
/// such as `EMFILE` under file-descriptor exhaustion, returns immediately and repeatedly;
/// without a yield the accept loop would hot-spin, pinning a core and flooding the log.
/// Short enough to recover promptly once descriptors free up.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(10);

/// Bind the public HTTP listener and serve the beacon + FDP + informational routes
/// (the public data plane only — the management plane is a separate listener; see
/// [`serve_management`]), shutting down gracefully on SIGINT / SIGTERM.
///
/// On SIGTERM or SIGINT it stops accepting new connections and drains in-flight HTTP
/// requests, bounded by `shutdown_drain_seconds` so the process cannot block past the grace
/// period. An in-flight request is already capped by `request_timeout_seconds`, which
/// preflight pins at or below this; the bound here is the backstop for a stuck connection or
/// an abandoned-but-not-yet-returned ingest. In-flight ingest is awaited, then abandoned:
/// `wait_for_quiescent` spends a second `shutdown_drain_seconds` on it after this drain
/// returns, and whatever is still running when that closes is dropped safely, since the
/// store uses atomic renames and `processing` is never persisted, so it re-queues next
/// startup. The total ceiling is therefore `2 x shutdown_drain_seconds + 2s`, not one drain;
/// see operating.md §14. SIGHUP is handled elsewhere.
///
/// `shutdown` is the caller's already-armed signal future ([`shutdown_signal`]), not one
/// created here: the handlers must be installed before this fn binds its listener, or the
/// bind-to-first-poll stretch has no handler at all.
///
/// # Errors
///
/// Returns an error if the listener cannot bind or the server fails while serving.
async fn serve_http(
    state: AppState,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> Result<()> {
    let listen = state.config.service.listen.clone();
    let listener = bind_listener(&listen, "HTTP listener", "listen").await?;
    let bound = listener
        .local_addr()
        .map_or_else(|_| listen.clone(), |a| a.to_string());
    info!(
        plane = gdi_node_standalone::metrics::PLANE_PUBLIC,
        event.action = "service.listen",
        addr = %bound,
        "HTTP server listening"
    );

    let drain = Duration::from_secs(state.config.service.shutdown_drain_seconds.max(1));
    // A readiness handle for the shutdown branch (build_router consumes `state`).
    let readiness = state.readiness.clone();
    let router = build_router(state);
    serve_bounded(
        listener,
        router,
        drain,
        Some(readiness),
        gdi_node_standalone::metrics::PLANE_PUBLIC,
        shutdown,
    )
    .await
}

/// The shared bounded serve loop for both planes, parameterised on the `shutdown` future so
/// it is unit-testable with an injected signal (production passes [`shutdown_signal`]).
///
/// Serves via a manual hyper accept loop rather than `axum::serve`, so the pre-service
/// connection phase is bounded: `http1_header_read_timeout` kills slow-header connections
/// and a [`Semaphore`] caps concurrent sockets. `axum::serve` exposes neither, so the
/// management plane — the sole liveness target — runs through this too. axum's `Router` is
/// `Service<Request<B>>` generic over the body, so a per-connection `router.clone()` serves
/// hyper's `Incoming` directly, with no `into_make_service`. On `shutdown` it stops
/// accepting and drains in-flight connections, bounded by `drain`.
///
/// `readiness` is `Some` only for the public plane: on shutdown it flips `/health/ready` to
/// `503` before draining, closing the endpoint-removal race. The management plane passes
/// `None`, because it must keep answering probes throughout the public drain and shuts down
/// on its own later signal.
///
/// # Errors
///
/// Infallible after the caller's successful bind — returns `Ok` on graceful exit; the
/// `Result` matches [`serve_http`]'s signature.
async fn serve_bounded(
    listener: tokio::net::TcpListener,
    router: axum::Router,
    drain: Duration,
    readiness: Option<gdi_node_standalone::health::Readiness>,
    plane: &'static str,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    let mut http = http1::Builder::new();
    // `header_read_timeout` requires a timer on the builder, or hyper panics
    // ("timeout set, but no timer set") on the first connection.
    http.timer(TokioTimer::new());
    http.header_read_timeout(Some(HEADER_READ_TIMEOUT));
    let graceful = GracefulShutdown::new();
    let connections = Arc::new(Semaphore::new(MAX_PUBLIC_CONNECTIONS));

    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _addr) = match accepted {
                    Ok(pair) => pair,
                    // A transient accept error, such as EMFILE under load, must not kill
                    // the serve loop. Back off briefly so a persistent error cannot
                    // hot-spin the loop, pinning a core and flooding the log.
                    Err(e) => {
                        warn!(error = %e, "accept failed; backing off briefly and continuing");
                        tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                        continue;
                    }
                };
                // Cap concurrent connections: close the excess rather than let a flood
                // accumulate descriptors and tasks. The permit is held for the connection's
                // whole life by the spawned task, so it releases on close. Dropped
                // connections are not logged per drop, because a flood would amplify the
                // log, but they are counted: a counter carries no per-connection detail, so
                // it cannot be amplified, and without it the cap would be unobservable. On
                // the management plane this sits below the health-probe exemption, so a
                // saturated listener can get the node SIGKILLed by the kubelet, and the
                // counter is the only operator-visible signal.
                let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
                    drop(stream);
                    gdi_node_standalone::metrics::record_connection_rejected(plane);
                    continue;
                };
                let service = TowerToHyperService::new(router.clone());
                let conn = http.serve_connection(TokioIo::new(stream), service);
                let watched = graceful.watch(conn);
                tokio::spawn(async move {
                    let _permit = permit;
                    // A per-connection error (client reset, header-read timeout, protocol
                    // error) is benign and self-contained.
                    let _ = watched.await;
                });
            }
            () = &mut shutdown => {
                // Flip `/health/ready` to 503 before the drain begins, so the orchestrator
                // removes this pod from rotation while in-flight requests finish, closing
                // the endpoint-removal race (see the preStop guidance in
                // docs/operating.md). Only the public plane carries a `readiness`; the
                // management plane must keep serving probes through the public drain.
                if let Some(r) = &readiness {
                    r.begin_shutdown();
                }
                break;
            }
        }
    }

    // Stop accepting, then drain in-flight connections, bounded by the drain budget.
    drop(listener);
    // `plane`: both listeners run this drain, so without it these lines would appear twice
    // with nothing saying which was which.
    info!(
        plane,
        event.action = "service.drain",
        "shutdown signal received; draining in-flight connections"
    );
    tokio::select! {
        () = graceful.shutdown() => {
            info!(plane, event.action = "service.drained", "in-flight requests drained; exiting");
        }
        () = tokio::time::sleep(drain) => {
            warn!(
                plane,
                event.action = "service.drain_timeout",
                drain_seconds = drain.as_secs(),
                "shutdown drain budget elapsed with connections still in flight; exiting (in-flight ingest is abandoned safely and re-queues on next startup)"
            );
        }
    }

    Ok(())
}

/// Type alias for the per-bucket Vault S3-credential overrides
/// (`bucket name -> (access_key_id, secret_access_key)`).
type S3Overrides = std::collections::BTreeMap<String, (String, String)>;

/// The `gdi-node-standalone` command-line surface.
///
/// The binary is both the node and the operator toolbox: with no command it serves, with a
/// command it runs that one thing and exits. `ServiceConfig::load` owns all real
/// configuration, so this surface stays small.
///
/// Every command's flags live on that command's own args type, so a flag can only be passed
/// to the command that owns it. Mutual exclusion, foreign-flag rejection and positional
/// arity are properties of these types rather than of a runtime validation pass.
#[derive(Debug, Parser)]
#[command(
    name = "gdi-node-standalone",
    about = "standalone GDI node (GA4GH Beacon v2 + FAIR Data Point)",
    long_about = "\
gdi-node-standalone: standalone GDI node (GA4GH Beacon v2 + FAIR Data Point)

Run with no command to serve the node; run with a command to do that one thing and
exit. Commands are grouped noun-verb (`identity ...`, `dataset ...`, `channel ...`,
`config ...`); node-level actions are bare verbs. Each command's flags apply only to it.

The `dataset`, `channel` and `overrides` groups and `doctor` are lock-free: they never take
the data-dir writer lock, so they are safe to run while the node is serving. `verify` and
the `identity` group are offline/Vault operations."
)]
struct Cli {
    /// Config-file path (highest precedence over `$GDI_CONFIG` and the default
    /// `/etc/gdi-node-standalone/node.toml`).
    ///
    /// A bare `--config` with no value leaves the path unset, so the `$GDI_CONFIG` /
    /// default fallback applies.
    #[arg(long, global = true, value_name = "PATH", num_args = 0..=1, help_heading = "Global options")]
    config: Option<std::path::PathBuf>,

    /// Print the version line and exit.
    #[arg(short = 'V', long, global = true, help_heading = "Global options")]
    version: bool,

    /// The command to run; omitted, the node serves.
    #[command(subcommand)]
    command: Option<Command>,
}

/// The commands. Every one but `serve` runs once and exits instead of serving.
#[derive(Debug, Subcommand)]
enum Command {
    /// Run the node (the default when no command is given).
    Serve,
    /// Load and preflight the config, print a redacted effective-config summary, then
    /// exit: the pre-deploy gate.
    CheckConfig,
    /// Probe the management-plane /health/ready on loopback and exit 0 (ready) or
    /// non-zero (not ready).
    ///
    /// This is the container HEALTHCHECK: the shipped image is distroless, so it carries
    /// no shell and no curl to probe with.
    Healthcheck,
    /// Print the version line and exit (the same output as `--version`).
    Version,
    /// Read-only preflight posture report (config, keys, k-anon floor, writer policy,
    /// subsystems, registry). Lock-free.
    Doctor(DoctorArgs),
    /// Offline store scrub: validate every dataset against the loaded key material,
    /// then exit. Non-zero if any dataset fails.
    Verify(VerifyArgs),
    /// Dataset-level operator commands: list, unhide, hide, take-down, reingest,
    /// purge-rejected, correct.
    #[command(subcommand)]
    Dataset(DatasetCommand),
    /// Channel-level operator commands: the channel-granularity sibling of the
    /// `dataset` verbs. They act on every dataset of one bucket or `inbox` at once.
    #[command(subcommand)]
    Channel(ChannelCommand),
    /// Back up and restore the operator-override store, the only state on the data volume
    /// that a re-ingest cannot rebuild.
    ///
    /// `overrides export` writes a readable JSON bundle; `overrides import` restores one.
    #[command(subcommand)]
    Overrides(OverridesCommand),
    /// Node crypt4gh identity lifecycle. `identity init` works on any build; the rest are
    /// Vault-only.
    #[command(subcommand)]
    Identity(IdentityCommand),
    /// Configuration helpers that need no config file of their own.
    #[command(subcommand)]
    Config(ConfigCommand),
    /// At-rest (PME) key operations.
    #[command(subcommand)]
    Pme(PmeCommand),
}

/// The `pme <verb>` group — at-rest master-key operations.
#[derive(Debug, Subcommand)]
enum PmeCommand {
    /// Reseal `<data_dir>/.pme-sentinel.json` against the currently configured Transit key.
    ///
    /// The documented exit from a latched `gdi_pme_master_key_mismatch` once the at-rest
    /// recovery is complete (docs/operating.md §17) or a key rotation's re-ingest has
    /// finished (§10). Without it the sentinel, written once and stored beside the data it
    /// vouches for, survives the recovery too and leaves a healthy node permanently
    /// `ready: false`.
    ///
    /// Refuses unless the configured key can still read the existing encrypted store, so it
    /// cannot be used to silence a genuine key mismatch.
    Reseal(ResealArgs),
}

/// Arguments for `pme reseal`.
#[derive(Debug, clap::Args)]
struct ResealArgs {
    /// Required to proceed: without it the command explains what it would reseal and exits
    /// non-zero. There is no interactive prompt, because the shipped image is distroless and
    /// this runs unattended, so the flag is the confirmation.
    #[arg(long)]
    yes: bool,
}

/// Arguments for `doctor`.
#[derive(Debug, clap::Args)]
struct DoctorArgs {
    /// Output format.
    #[arg(long, value_name = "text|json", value_parser = parse_output_format, default_value = "text")]
    format: gdi_node_standalone::list_datasets::OutputFormat,
    /// Exit non-zero on any WARN, not only on a hard FAIL.
    #[arg(long)]
    strict: bool,
}

/// Arguments for `verify`.
#[derive(Debug, clap::Args)]
struct VerifyArgs {
    /// Also run full parquet schema/value validation (plaintext stores; PME stores stay
    /// footer-only).
    #[arg(long)]
    full: bool,
    /// Also verify the at-rest `parquet-digests.json` sidecar (hash-only; combine with
    /// --full for row validation too).
    #[arg(long)]
    digest: bool,
    /// Bound per-dataset parallelism (0 = the default of 4). This also bounds concurrent
    /// Vault DEK unwraps — they are single-flighted per key, not serialised process-wide.
    #[arg(long, value_name = "N", default_value_t = 0)]
    concurrency: usize,
}

/// The `dataset <verb>` group: node-side operator actions on one dataset. All are
/// lock-free, so they are safe to run while the node is serving.
#[derive(Debug, Subcommand)]
enum DatasetCommand {
    /// Read-only listing of the persistent status index (id, state, channel, provenance,
    /// suppressed), with operator filters.
    List(DatasetListArgs),
    /// Lift an operator-authored withhold on ID, if any (never force-serves a dataset its
    /// source marked hidden). Requires --reason: re-exposing data is a governance act, and
    /// the withhold record says why data was withheld, not why it came back.
    ///
    /// Also spelled `show`, the pair to `hide`. `unhide` is the primary spelling because
    /// this group's read-only verb is `list`, so a `show` typed to inspect a dataset would
    /// silently lift a live withhold.
    #[command(name = "unhide", visible_alias = "show")]
    Show(DatasetShowArgs),
    /// Withhold ID from disclosure; the underlying data is untouched (reversible via
    /// `dataset unhide`).
    Hide(DatasetHideArgs),
    /// Withhold ID and mark it for eviction. Irreversible from the node's perspective:
    /// the node erases its local copy.
    TakeDown(DatasetTakeDownArgs),
    /// Retry ingest for ID after fixing its cause: restores a quarantined
    /// inbox/.rejected artifact for the inbox channel; otherwise queues a node-side
    /// reingest-request marker that clears ID's recorded signature so a same-ETag bucket
    /// package re-ingests. Applied on the node's next reconcile; the command prints how
    /// to apply it immediately.
    Reingest(DatasetIdArgs),
    /// Erase inbox/.rejected/ quarantine entries on demand (they can hold plaintext,
    /// genotype-derived data — a GDPR / disk-pressure lever). Requires [service].inbox.
    PurgeRejected(PurgeRejectedArgs),
    /// Author (or, with --reset, remove) a node-local metadata-overlay override for ID,
    /// applied through the existing overlay engine — it works for a bucket-owned dataset
    /// with no bucket write, and takes precedence over any bucket/inbox
    /// {id}.metadata.json sidecar. datasetId/catalog/numberOfRecords/populations are
    /// protected and always rejected.
    Correct(CorrectArgs),
}

/// A single dataset id — the positional `dataset reingest` takes.
#[derive(Debug, clap::Args)]
struct DatasetIdArgs {
    /// The dataset id.
    #[arg(value_name = "ID")]
    id: String,
}

/// Arguments for `dataset show` / `dataset unhide`.
///
/// Split out of [`DatasetIdArgs`], which `dataset reingest` still uses, rather than adding
/// an optional `--reason` there: the justification is mandatory here and meaningless on a
/// re-ingest, and one shared struct would make it optional for both.
#[derive(Debug, clap::Args)]
struct DatasetShowArgs {
    /// The dataset id whose withhold to lift.
    #[arg(value_name = "ID")]
    id: String,
    /// Required justification, recorded in a durable lift record under
    /// `<override_dir>/lifted/` rather than the log stream, which is why the
    /// `dataset_unsuppressed` audit line does not carry it. Keep it to a case or ticket
    /// reference, not a person's name or personal identity code.
    #[arg(long, value_name = "TEXT", value_parser = parse_reason)]
    reason: String,
}

/// Arguments for `dataset hide`.
#[derive(Debug, clap::Args)]
struct DatasetHideArgs {
    /// The dataset id to withhold.
    #[arg(value_name = "ID")]
    id: String,
    /// Required justification, carried into the suppression file's `reason` field rather
    /// than the log stream. That file is backed up out of band, so keep this to a case or
    /// ticket reference, not a person's name or personal identity code.
    #[arg(long, value_name = "TEXT", value_parser = parse_reason)]
    reason: String,
}

/// Arguments for `dataset take-down`.
#[derive(Debug, clap::Args)]
struct DatasetTakeDownArgs {
    /// The dataset id to withhold and evict.
    #[arg(value_name = "ID")]
    id: String,
    /// Required justification, carried into the suppression file's `reason` field rather
    /// than the log stream. That file is backed up out of band, so keep this to a case or
    /// ticket reference, not a person's name or personal identity code.
    #[arg(long, value_name = "TEXT", value_parser = parse_reason)]
    reason: String,
    /// Preview the take-down without writing anything.
    #[arg(long)]
    dry_run: bool,
    /// Confirm the irreversible eviction so it applies. Without --yes or --dry-run,
    /// `dataset take-down` refuses and tells you to pick one.
    #[arg(long)]
    yes: bool,
}

/// Arguments for `dataset purge-rejected`.
#[derive(Debug, clap::Args)]
struct PurgeRejectedArgs {
    /// Only purge entries whose mtime is older than this duration (an integer followed by
    /// one of s/m/h/d/w, such as 72h or 7d). Omitted, every entry is purged.
    ///
    /// A value is mandatory when the flag is given, because `older_than = None` is what
    /// means "purge everything": an unset shell variable must not be swallowed into it.
    #[arg(long, value_name = "DUR", value_parser = parse_older_than)]
    older_than: Option<std::time::Duration>,
    /// List what would be purged and remove nothing.
    #[arg(long)]
    dry_run: bool,
}

/// Arguments for `dataset correct`.
///
/// Exactly one mode is required: `--reset` removes the override, `--field` or `--patch`
/// writes one. `--field` and `--patch` are mutually exclusive, so the patch source is
/// unambiguous, and `--reset` cannot combine with either because it is a different action.
/// The `mode` arg group is that rule.
#[derive(Debug, clap::Args)]
#[command(group(clap::ArgGroup::new("mode").required(true).args(["field", "patch", "reset"])))]
struct CorrectArgs {
    /// The dataset id to correct.
    #[arg(value_name = "ID")]
    id: String,
    /// One field of the metadata-overlay patch (repeatable; a dotted KEY sets a
    /// nested/localized field, e.g. `title.en=…`). VALUE is parsed as JSON when possible
    /// (numbers, arrays), else taken as a bare string.
    #[arg(long, value_name = "KEY=VALUE")]
    field: Vec<String>,
    /// Read the metadata-overlay patch from a JSON file instead of --field.
    #[arg(long, value_name = "PATH")]
    patch: Option<std::path::PathBuf>,
    /// Remove ID's node-local metadata-overlay override, reverting to the package
    /// baseline (or resuming a source {id}.metadata.json, if one is present) on the
    /// node's next reconcile.
    #[arg(long)]
    reset: bool,
    /// Justification for the correction, recorded in the `metadata_overlay_set` audit line
    /// so an auditor can recover why a field was changed. Optional, and ignored with
    /// `--reset`.
    #[arg(long, value_name = "TEXT", value_parser = parse_reason)]
    reason: Option<String>,
}

/// Arguments for `dataset list`. Every filter must hold (logical AND across the flags);
/// `--state` matches if any one of its values does (logical OR within the flag).
#[derive(Debug, clap::Args)]
struct DatasetListArgs {
    /// Keep only datasets in this state (repeatable): visible, hidden, error, processing.
    ///
    /// `processing` is accepted but matches nothing on a node-managed store: this listing
    /// reads the persisted status index, and an in-flight ingest is never written there.
    /// Ask `GET /datasets/{id}/state` for the live state instead.
    #[arg(long = "state", value_name = "STATE")]
    states: Vec<String>,
    /// Sugar for `--state error`.
    #[arg(long)]
    errors: bool,
    /// Keep only this source channel (a bucket's logical name, or `inbox`).
    #[arg(long, value_name = "NAME")]
    channel: Option<String>,
    /// Keep only this provenance kind: recovered, plaintext, `recovery_failed`, unknown.
    #[arg(long, value_name = "KIND")]
    provenance: Option<String>,
    /// Keep only datasets a matching writer fingerprint published.
    #[arg(long, value_name = "FP-SUBSTR")]
    writer: Option<String>,
    /// Keep only ids containing this substring.
    #[arg(long = "id", value_name = "SUBSTR")]
    id_substring: Option<String>,
    /// Keep only datasets whose provenance is not `recovered` (no writer key of any kind).
    #[arg(long)]
    unverified: bool,
    /// Keep only datasets carrying an active operator hide/take-down override.
    #[arg(long)]
    suppressed: bool,
    /// Output format.
    #[arg(long, value_name = "text|json", value_parser = parse_output_format, default_value = "text")]
    format: gdi_node_standalone::list_datasets::OutputFormat,
}

impl DatasetListArgs {
    /// Assemble the [`gdi_node_standalone::list_datasets::DatasetsFilter`] these flags
    /// describe. `--errors` is sugar that appends `error` to the `--state` set (it is
    /// applied last, so it never displaces an explicit `--state`).
    fn filter(&self) -> gdi_node_standalone::list_datasets::DatasetsFilter {
        let mut states = self.states.clone();
        if self.errors {
            states.push("error".to_owned());
        }
        gdi_node_standalone::list_datasets::DatasetsFilter {
            states,
            channel: self.channel.clone(),
            provenance: self.provenance.clone(),
            writer: self.writer.clone(),
            id_substring: self.id_substring.clone(),
            unverified: self.unverified,
            suppressed: self.suppressed,
        }
    }
}

/// The `channel <verb>` group: the channel-granularity sibling of the `dataset` verbs.
/// Withhold every dataset of a whole bucket or `inbox` at once and pause its ingest. All
/// are lock-free.
#[derive(Debug, Subcommand)]
enum ChannelCommand {
    /// Read-only listing of every configured channel (each [[s3.buckets]] name, plus
    /// `inbox` if configured) with its current suppression state.
    List(ChannelListArgs),
    /// Lift an operator-authored withhold on channel NAME, if any, and resume its ingest.
    /// Requires --reason, for the same governance reason `dataset unhide` does.
    ///
    /// Also spelled `show` — see [`DatasetCommand::Show`] for why `unhide` is primary.
    #[command(name = "unhide", visible_alias = "show")]
    Show(ChannelShowArgs),
    /// Withhold every dataset of channel NAME from disclosure and pause its ingest, so no
    /// further poll or download runs. The underlying data is untouched, and it is reversible
    /// with `channel unhide`.
    Hide(ChannelHideArgs),
    /// Withhold every dataset of channel NAME, mark each for eviction, and pause its
    /// ingest. Irreversible from the node's perspective: it erases each dataset's local
    /// copy.
    TakeDown(ChannelTakeDownArgs),
}

/// `overrides` subcommands.
#[derive(Debug, clap::Subcommand)]
enum OverridesCommand {
    /// Write the operator-override store to a JSON bundle (stdout unless `--output`).
    ///
    /// Fails rather than emitting an empty bundle when the store cannot be read: a
    /// backup that silently captured nothing is worse than no backup.
    Export(OverridesExportArgs),
    /// Restore an override store from a bundle written by `overrides export`.
    ///
    /// Refuses when the target store already holds overrides unless `--force`.
    Import(OverridesImportArgs),
    /// Remove reingest-request markers this node can no longer act on.
    ///
    /// Processing keeps a marker (so a shared store fans out to every replica), so they
    /// accumulate. Removes only markers whose dataset the node has no trace of, unless
    /// `--all`.
    PruneReingest(OverridesPruneReingestArgs),
    /// Create an empty operator-override store when absent; attest an emptied one (--yes).
    ///
    /// Only needed on a node that sets `service.require_override_store` before it has ever
    /// recorded an override: the boot assertion refuses an absent or incomplete store and
    /// does not create one, because a check that creates what it tests cannot tell "never
    /// used" from "the volume was lost". Any `dataset hide`, `channel take-down` or
    /// `dataset correct` materialises the store on its own.
    ///
    /// While this node's used marker records that the store has held overrides — absent
    /// now, or present and empty — that shape is a lost volume until proven otherwise, so
    /// `init` refuses without `--yes` and names `overrides import` as the answer. With
    /// `--yes` it creates the store if absent, attests it as intentionally empty and clears
    /// the marker. An intact store is a no-op that writes nothing, so it is safe on every
    /// start; `deploy/kubernetes` runs it as an init container.
    Init(OverridesInitArgs),
}

/// Arguments for `overrides init`.
#[derive(Debug, clap::Args)]
struct OverridesInitArgs {
    /// Attest that an emptied store is intentionally empty: clears this node's used marker
    /// so it boots, creating the store first if it is absent. Required whenever the marker
    /// stands, and never needed on a node that has never held an override.
    #[arg(long)]
    yes: bool,
}

/// Arguments for `overrides prune-reingest`.
#[derive(Debug, clap::Args)]
struct OverridesPruneReingestArgs {
    /// Remove every pending marker, including ones for datasets this node still knows.
    ///
    /// Withdraws the requests outright. Another replica that has not yet observed a removed
    /// marker never will, so this is an operator decision, not a cleanup default.
    #[arg(long)]
    all: bool,
    /// Print what would be removed and change nothing.
    #[arg(long)]
    dry_run: bool,
}

/// Arguments for `overrides export`.
#[derive(Debug, clap::Args)]
struct OverridesExportArgs {
    /// Write the bundle here instead of stdout.
    #[arg(long, short = 'o', value_name = "PATH")]
    output: Option<std::path::PathBuf>,
}

/// Arguments for `overrides import`.
#[derive(Debug, clap::Args)]
struct OverridesImportArgs {
    /// The bundle to restore.
    #[arg(value_name = "BUNDLE")]
    bundle: std::path::PathBuf,
    /// Import even though the target store already holds overrides. Same-named entries
    /// are overwritten; extras are kept. Never deletes, so it cannot lift a withhold.
    #[arg(long)]
    force: bool,
}

/// Arguments for `channel list`.
#[derive(Debug, clap::Args)]
struct ChannelListArgs {
    /// Output format. `json` for scripting, matching `dataset list` and `doctor`, the
    /// read-only verbs this command is grouped with.
    #[arg(long, value_name = "text|json", value_parser = parse_output_format, default_value = "text")]
    format: gdi_node_standalone::list_datasets::OutputFormat,
}

/// Arguments for `channel show` / `channel unhide`.
#[derive(Debug, clap::Args)]
struct ChannelShowArgs {
    /// The channel name (a configured [[s3.buckets]].name, or `inbox`).
    #[arg(value_name = "NAME")]
    name: String,
    /// Required justification, recorded in a durable lift record under
    /// `<override_dir>/lifted/` rather than the log stream, which is why the
    /// `channel_unsuppressed` audit line does not carry it. Keep it to a case or ticket
    /// reference, not a person's name or personal identity code.
    #[arg(long, value_name = "TEXT", value_parser = parse_reason)]
    reason: String,
}

/// Arguments for `channel hide`.
#[derive(Debug, clap::Args)]
struct ChannelHideArgs {
    /// The channel name (a configured [[s3.buckets]].name, or `inbox`).
    #[arg(value_name = "NAME")]
    name: String,
    /// Required justification, carried into the suppression file's `reason` field rather
    /// than the log stream. That file is backed up out of band, so keep this to a case or
    /// ticket reference, not a person's name or personal identity code.
    #[arg(long, value_name = "TEXT", value_parser = parse_reason)]
    reason: String,
}

/// Arguments for `channel take-down`.
#[derive(Debug, clap::Args)]
struct ChannelTakeDownArgs {
    /// Confirm the irreversible eviction so it applies. Without --yes or --dry-run,
    /// `channel take-down` refuses and tells you to pick one.
    #[arg(long)]
    yes: bool,
    /// The channel name (a configured [[s3.buckets]].name, or `inbox`).
    #[arg(value_name = "NAME")]
    name: String,
    /// Required justification, carried into the suppression file's `reason` field rather
    /// than the log stream. That file is backed up out of band, so keep this to a case or
    /// ticket reference, not a person's name or personal identity code.
    #[arg(long, value_name = "TEXT", value_parser = parse_reason)]
    reason: String,
    /// Preview the take-down without writing anything.
    #[arg(long)]
    dry_run: bool,
}

/// The `identity <verb>` group — the node crypt4gh identity lifecycle. Offline-safe
/// maintenance one-shots that act on Vault/keys and never serve, so the boot path skips
/// the serving preflight for them.
#[derive(Debug, Subcommand)]
enum IdentityCommand {
    /// Mint the node crypt4gh identity, or import one with --from. It is written wherever
    /// the config says the node will read it from: Vault when [vault] is set, otherwise the
    /// first [keys].identities entry, the published recipient. Use --file <PATH> to name the
    /// key file explicitly. Create-only.
    Init(IdentityInitArgs),
    /// Mint a new identity beside the existing one(s); the new key becomes the published
    /// recipient, prior keys are retained for decryption.
    Rotate,
    /// Remove the oldest retained identity, keeping the published recipient and newer keys;
    /// run again to prune the next-oldest. Destructive: --yes applies, --dry-run previews,
    /// and it refuses if given neither.
    Retire(IdentityRetireArgs),
    /// Read-only: print the current identity state (fields, count, age, public-key
    /// fingerprint) without revealing secret key material. Safe with the read-only serving
    /// token.
    List,
    /// Export the node identity from Vault, crypt4gh-encrypted to one or more operator
    /// recipients: disaster recovery for the one irreplaceable secret.
    Backup(IdentityBackupArgs),
    /// Decrypt a backup with an operator secret key and write it into Vault create-only.
    Restore(IdentityRestoreArgs),
}

/// Arguments for `identity init`.
#[derive(Debug, clap::Args)]
struct IdentityInitArgs {
    /// Treat an already-provisioned path as a success no-op (idempotent re-runs) instead
    /// of erroring.
    #[arg(long)]
    ensure: bool,
    /// Replace an existing file-backed identity (the previous one is copied to a .bak-<epoch>
    /// sibling first). A Vault identity is create-only and rejects this.
    #[arg(long)]
    force: bool,
    /// Import an existing crypt4gh secret-key PEM from this file instead of minting a fresh
    /// keypair. For a Vault node it is read and validated in memory and never read again;
    /// for a file-backed node it is validated and installed at the target.
    #[arg(long, value_name = "PATH")]
    from: Option<std::path::PathBuf>,
    /// Write the identity to this key file instead of Vault: the non-Vault ([keys])
    /// posture. Omitted, a node with no [vault] writes to the first [keys].identities entry,
    /// the published recipient, so the key lands where the node will read it.
    #[arg(long, value_name = "PATH")]
    file: Option<std::path::PathBuf>,
}

/// Arguments for `identity retire`.
#[derive(Debug, clap::Args)]
struct IdentityRetireArgs {
    /// Preview the removal: read Vault and print the field that would go, writing nothing.
    #[arg(long)]
    dry_run: bool,
    /// Confirm the destructive removal so it applies. Without --yes or --dry-run,
    /// `identity retire` refuses and tells you to pick one.
    #[arg(long)]
    yes: bool,
    /// Retire even when packages would be orphaned, that is openable only with the retiring
    /// key. Off by default: the openability guard refuses and lists them.
    #[arg(long)]
    force: bool,
}

/// Arguments for `identity backup`.
#[derive(Debug, clap::Args)]
struct IdentityBackupArgs {
    /// Operator crypt4gh public key the backup is encrypted to. May be repeated: the backup
    /// is then encrypted to every recipient and any one of their secrets can restore it,
    /// giving redundancy against a lost operator key.
    #[arg(long = "recipient", value_name = "PATH")]
    recipients: Vec<std::path::PathBuf>,
    /// Where the encrypted blob is written.
    #[arg(long, value_name = "PATH")]
    out: Option<std::path::PathBuf>,
}

/// Arguments for `identity restore`.
#[derive(Debug, clap::Args)]
struct IdentityRestoreArgs {
    /// The encrypted backup to read.
    #[arg(long = "in", value_name = "PATH")]
    input: Option<std::path::PathBuf>,
    /// Operator crypt4gh secret key that decrypts the backup.
    #[arg(long, value_name = "PATH")]
    identity: Option<std::path::PathBuf>,
    /// Verify the backup (decrypt, parse and validate) without writing it to Vault, to
    /// confirm it is restorable.
    #[arg(long)]
    dry_run: bool,
}

/// The `config <verb>` group — configuration helpers. They read no config file and
/// touch no data dir, so they work on a box with nothing deployed yet.
#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Print the generated default configuration as TOML — the answer to "what does this
    /// node do if I set nothing?", generated from the code rather than hand-maintained.
    ///
    /// It is a defaults reference, not a runnable config: the deployment-specific fields
    /// (`[service].data_dir`, the bind addresses, `[beacon].base_url`) print as their empty
    /// defaults. Diff it against your config to see what you have overridden.
    DumpDefaults,
}

/// Parse a `--format` value (for `dataset list` / `doctor`) into an [`OutputFormat`], or a
/// usage error.
fn parse_output_format(
    value: &str,
) -> Result<gdi_node_standalone::list_datasets::OutputFormat, String> {
    use gdi_node_standalone::list_datasets::OutputFormat;
    match value {
        "text" => Ok(OutputFormat::Text),
        "json" => Ok(OutputFormat::Json),
        other => Err(format!(
            "invalid --format `{other}`; expected `text` or `json`"
        )),
    }
}

/// Parse a `--older-than` value (for `dataset purge-rejected`) into a [`Duration`]: a bare
/// positive integer followed by exactly one of `s`/`m`/`h`/`d`/`w`, such as `72h` or `7d`.
/// It does not accept combined units (`1d12h`) or fractional values.
fn parse_older_than(value: &str) -> Result<std::time::Duration, String> {
    let bad = || {
        format!(
            "invalid --older-than value `{value}`; expected an integer followed by \
             s/m/h/d/w, e.g. 72h or 7d"
        )
    };
    let unit = value.chars().next_back().ok_or_else(bad)?;
    let digits = &value[..value.len() - unit.len_utf8()];
    if digits.is_empty() {
        return Err(bad());
    }
    let n: u64 = digits.parse().map_err(|_| bad())?;
    let multiplier: u64 = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86400,
        'w' => 604_800,
        _ => return Err(bad()),
    };
    let secs = n
        .checked_mul(multiplier)
        .ok_or_else(|| format!("--older-than value `{value}` overflows"))?;
    Ok(std::time::Duration::from_secs(secs))
}

/// Run the lock-free, read-only one-shots — the `dataset` / `channel` verbs and
/// `doctor`. Returns `Some(result)` when one ran (the binary exits with it), or `None`
/// for a command that is not one of these (`serve`, `verify`, the `identity` group),
/// which the boot path continues past.
///
/// They are dispatched before the serving preflight and the data-dir writer lock, so they
/// run while the node is serving and stay usable even if a serving-only config section is
/// misconfigured.
fn run_lockfree_command(command: &Command, config: &ServiceConfig) -> Option<Result<()>> {
    match command {
        Command::Doctor(args) => Some(gdi_node_standalone::doctor::run(
            config,
            args.format,
            args.strict,
        )),
        Command::Dataset(cmd) => Some(run_dataset_command(cmd, config)),
        Command::Channel(cmd) => Some(run_channel_command(cmd, config)),
        Command::Overrides(cmd) => Some(run_overrides_command(cmd, config)),
        // Listed rather than caught by a wildcard, so a new command must be placed here or
        // in one of the boot path's later stages instead of silently falling through to
        // serve.
        Command::Serve
        | Command::CheckConfig
        | Command::Healthcheck
        | Command::Version
        | Command::Verify(_)
        | Command::Identity(_)
        | Command::Config(_)
        | Command::Pme(_) => None,
    }
}

/// Dispatch one `dataset <verb>`: drive the status-index listing, or the operator
/// suppression / metadata-overlay / reingest-request override the running node
/// reconciles. Lock-free — none of these touches `data_dir` directly.
///
/// # Errors
///
/// Returns whatever the selected verb returns (a missing inbox, an unwritable override
/// store, an unknown id, a rejected correction, …).
fn run_dataset_command(command: &DatasetCommand, config: &ServiceConfig) -> Result<()> {
    match command {
        DatasetCommand::List(args) => {
            gdi_node_standalone::list_datasets::run(config, &args.filter(), args.format)
        }
        DatasetCommand::Show(args) => {
            gdi_node_standalone::suppress_cmd::show(config, &args.id, &args.reason)
        }
        DatasetCommand::Hide(args) => {
            gdi_node_standalone::suppress_cmd::hide(config, &args.id, &args.reason)
        }
        DatasetCommand::TakeDown(args) => {
            confirm_take_down("dataset", args.dry_run, args.yes)?;
            gdi_node_standalone::suppress_cmd::take_down(
                config,
                &args.id,
                &args.reason,
                args.dry_run,
            )
        }
        DatasetCommand::Reingest(args) => {
            gdi_node_standalone::dataset_cmd::reingest(config, &args.id)
        }
        // A direct, synchronous filesystem operation on the configured `[service].inbox`'s
        // `.rejected/` dir: no operator-override store and no SIGUSR1 nudge, unlike the
        // suppression verbs above.
        DatasetCommand::PurgeRejected(args) => {
            gdi_node_standalone::dataset_cmd::purge_rejected(config, args.older_than, args.dry_run)
        }
        DatasetCommand::Correct(args) => run_dataset_correct(args, config),
    }
}

/// Run `dataset correct`: author (or, with `--reset`, remove) the node-local
/// metadata-overlay override. The `mode` arg group already guarantees exactly one of
/// `--reset` / `--patch` / `--field` is present.
///
/// # Errors
///
/// Returns an error if the patch file cannot be read/parsed, a `--field` is malformed or
/// targets a protected key, or the override cannot be written.
fn run_dataset_correct(args: &CorrectArgs, config: &ServiceConfig) -> Result<()> {
    if args.reset {
        return gdi_node_standalone::correct_cmd::reset(config, &args.id);
    }
    let overlay = if let Some(patch) = &args.patch {
        gdi_node_standalone::correct_cmd::overlay_from_patch_file(patch)?
    } else {
        gdi_node_standalone::correct_cmd::overlay_from_fields(&args.field)?
    };
    gdi_node_standalone::correct_cmd::correct(config, &args.id, &overlay, args.reason.as_deref())
}

/// Dispatch one `channel <verb>`: the channel-granularity sibling of
/// [`run_dataset_command`], withholding every dataset of a whole bucket or `inbox` at once
/// and pausing its ingest. Lock-free, same rationale.
///
/// # Errors
///
/// Returns whatever the selected verb returns (an unknown channel name, an unwritable
/// override store, …).
fn run_channel_command(command: &ChannelCommand, config: &ServiceConfig) -> Result<()> {
    match command {
        ChannelCommand::List(args) => gdi_node_standalone::channel_cmd::list(config, args.format),
        ChannelCommand::Show(args) => {
            gdi_node_standalone::channel_cmd::show(config, &args.name, &args.reason)
        }
        ChannelCommand::Hide(args) => {
            gdi_node_standalone::channel_cmd::hide(config, &args.name, &args.reason)
        }
        ChannelCommand::TakeDown(args) => {
            confirm_take_down("channel", args.dry_run, args.yes)?;
            gdi_node_standalone::channel_cmd::take_down(
                config,
                &args.name,
                &args.reason,
                args.dry_run,
            )
        }
    }
}

/// The confirmation gate the two irreversible `take-down` verbs share.
///
/// `take-down` withholds and evicts: the node erases its local copy, and nothing in the
/// node puts it back. So it takes the shape `identity retire` uses for the only other
/// irreversible verb — `--dry-run` previews, `--yes` applies, and giving neither is a
/// refusal rather than a silent default.
///
/// One function rather than a copy per verb, so a third take-down verb added later inherits
/// the gate by calling this.
fn confirm_take_down(what: &str, dry_run: bool, yes: bool) -> Result<()> {
    if dry_run || yes {
        return Ok(());
    }
    anyhow::bail!(
        "{what} take-down IRREVERSIBLY evicts the node's local copy of the data. Re-run with \
         --dry-run to preview exactly what would be removed, or --yes to confirm and apply."
    )
}

/// `--reason` on the governance verbs: a justification that is empty or whitespace is no
/// justification, and the flag is mandatory. One parser serves every `reason` argument, and
/// `every_reason_flag_rejects_an_empty_justification` walks the CLI so a verb added without
/// it is caught.
fn parse_reason(value: &str) -> Result<String, String> {
    if value.trim().is_empty() {
        return Err(
            "a justification is required; --reason must not be empty or whitespace".to_owned(),
        );
    }
    Ok(value.to_owned())
}

/// Dispatch an `overrides` subcommand.
///
/// # Errors
///
/// Propagates the export/import failure.
fn run_overrides_command(command: &OverridesCommand, config: &ServiceConfig) -> Result<()> {
    match command {
        OverridesCommand::Export(args) => {
            gdi_node_standalone::overrides_cmd::export(config, args.output.as_deref())
        }
        OverridesCommand::Import(args) => {
            gdi_node_standalone::overrides_cmd::import(config, &args.bundle, args.force)
        }
        OverridesCommand::PruneReingest(args) => {
            gdi_node_standalone::overrides_cmd::prune_reingest(config, args.all, args.dry_run)
        }
        OverridesCommand::Init(args) => gdi_node_standalone::overrides_cmd::init(config, args.yes),
    }
}

/// Run `config dump-defaults`: print the generated default config TOML to stdout.
///
/// In the no-network, no-data-dir class: it renders the code's own `Default` and reads
/// nothing, so it works before any config file exists.
///
/// # Errors
///
/// Returns an error if the default config cannot be rendered as TOML (see
/// [`gdi_node_standalone_core::config::defaults_toml`]).
fn run_config_command(command: &ConfigCommand) -> Result<()> {
    match command {
        ConfigCommand::DumpDefaults => {
            let toml = gdi_node_standalone_core::config::defaults_toml()
                .map_err(|e| anyhow::anyhow!("rendering the default config: {e}"))?;
            print!("{toml}");
            Ok(())
        }
    }
}

/// Run `healthcheck`: probe the management-plane `/health/ready` on loopback and
/// return `Ok(())` iff it answers `200`. The result maps to the process exit code
/// (0 ready / non-zero not), which is what the container `HEALTHCHECK` consumes.
///
/// Loads the same config the serving path loads and probes the management `/health/ready`
/// over the loopback matching the bind's address family. The bind may be a wildcard
/// (`0.0.0.0:9090` or `[::]:9090`), which is not itself connectable, so the probe dials
/// `127.0.0.1` or `::1` accordingly; the healthcheck runs in the server's own network
/// namespace. It uses blocking `std::net` and no tokio I/O — a one-shot probe that exits
/// immediately, bounded by connect, read and write timeouts — so it links in every feature
/// build, including the lite binary, whose tokio feature set omits `io-util`.
///
/// # Errors
///
/// Returns an error (→ non-zero exit) if the config cannot be loaded, the management
/// port cannot be parsed, the probe times out, or the endpoint is not `200`.
fn run_healthcheck(cli_config: Option<&Path>) -> Result<()> {
    let config =
        ServiceConfig::load(cli_config).map_err(|e| anyhow::anyhow!("loading config: {e}"))?;
    health_probe_ready(&config.service.management_addr)
}

/// The loopback addresses to probe for a given management bind, ordered by the
/// bind's address family.
///
/// A wildcard or literal IPv6 bind (`[::]:9090` / `[::1]:9090`) is reached on the
/// IPv6 loopback `::1`; an IPv4, wildcard-IPv4, or hostname bind (`0.0.0.0:9090`,
/// `127.0.0.1:9090`, `localhost:9090`) on `127.0.0.1`. The other family is kept as a
/// fallback so a dual-stack (IPv4-mapped) listener — or a `localhost` that resolves
/// to only one family — still answers when the preferred loopback is unreachable.
fn loopback_candidates(management_addr: &str) -> [std::net::IpAddr; 2] {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    let v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
    // A bracketed host (`[::]`, `[::1]`, `[fe80::1]`) is the only IPv6 spelling in a
    // `host:port` bind string; everything else is IPv4 or a hostname.
    if management_addr.trim_start().starts_with('[') {
        [v6, v4]
    } else {
        [v4, v6]
    }
}

/// Probe `GET /health/ready` on a loopback chosen to match `management_addr`'s
/// address family (see [`loopback_candidates`]) over a blocking TCP connection,
/// returning `Ok(())` iff the HTTP status line is `200`. Falls back to the other
/// loopback only when the preferred one cannot be connected (wrong family / nothing
/// listening), never when it answers a non-`200` status — a reachable-but-not-ready
/// management plane is a definitive negative.
///
/// # Errors
///
/// Returns an error if `management_addr` carries no parseable port, no loopback
/// candidate accepts a connection, an I/O step fails or times out, or the endpoint
/// answers a non-`200` status.
fn health_probe_ready(management_addr: &str) -> Result<()> {
    use std::io::{Read as _, Write as _};
    use std::net::{SocketAddr, TcpStream};

    let port: u16 = management_addr
        .rsplit(':')
        .next()
        .and_then(|p| p.parse().ok())
        .ok_or_else(|| {
            anyhow::anyhow!("cannot parse a port from management_addr {management_addr:?}")
        })?;

    let timeout = Duration::from_secs(5);
    let mut connect_err: Option<anyhow::Error> = None;
    for ip in loopback_candidates(management_addr) {
        let addr = SocketAddr::new(ip, port);
        let mut stream = match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => stream,
            Err(e) => {
                // Wrong address family, or nothing on this loopback: remember the failure
                // and try the other loopback before giving up.
                connect_err = Some(anyhow::anyhow!("connecting to {addr}: {e}"));
                continue;
            }
        };
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        stream.write_all(
            b"GET /health/ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )?;
        // The status line is in the first bytes of the response; a small read suffices.
        let mut chunk = [0u8; 512];
        let n = stream.read(&mut chunk)?;
        let head = String::from_utf8_lossy(&chunk[..n]);
        let status_line = head.lines().next().unwrap_or_default();
        return if status_line.contains(" 200") {
            Ok(())
        } else {
            anyhow::bail!("management /health/ready not ready (status line: {status_line:?})")
        };
    }
    Err(connect_err.unwrap_or_else(|| anyhow::anyhow!("no loopback candidate available to probe")))
}

/// Bring up structured logging and the optional OTLP trace exporter from the loaded config,
/// returning the [`logging::TelemetryGuard`] the caller must hold for the process lifetime;
/// its `Drop` flushes batched spans on exit. The deployment environment
/// (`[beacon].environment`) rides along as ECS `service.environment`.
fn init_logging(config: &ServiceConfig) -> logging::TelemetryGuard {
    logging::init(
        config.service.otlp_endpoint.as_deref(),
        config.service.otlp_headers.as_ref().map(|h| &h.0),
        &config.beacon.environment,
        config
            .service
            .otlp_metrics_interval_seconds
            .map(std::time::Duration::from_secs),
        config.service.otlp_trace_sample_ratio.unwrap_or(1.0),
    )
}

/// Run the `check-config` dry run: resolve the config path, run the same load and preflight
/// pass the live boot uses ([`ServiceConfig::load`] then [`preflight::run`]), print a
/// human-readable result, and return — exit 0 on success, a non-zero error on failure. It
/// never binds a listener or starts the runtime.
///
/// # Errors
///
/// Returns an error (mapped to a non-zero exit) if the config fails to load or
/// fails the startup preflight.
fn check_config(cli_config: Option<&Path>) -> Result<()> {
    // A dry run still emits preflight warnings, so bring up logging: with no trace export,
    // because a config check must not spin up an OTLP exporter, and no environment, because
    // the config is not loaded yet. Held until return.
    let _telemetry = logging::init(None, None, "", None, 1.0);
    let path = ServiceConfig::resolve_path(cli_config);
    let config = match ServiceConfig::load(cli_config) {
        Ok(config) => config,
        Err(e) => {
            println!("config check FAILED ({}): {e}", path.display());
            return Err(anyhow::anyhow!("loading config: {e}"));
        }
    };
    match preflight::run(&config) {
        Ok(()) => {
            println!("config check OK ({})", path.display());
            print_effective_config_summary(&config);
            Ok(())
        }
        Err(e) => {
            println!("config check FAILED ({}): {e}", path.display());
            Err(anyhow::Error::new(e).context("service config failed startup preflight"))
        }
    }
}

/// Print a redacted, resolved-config summary for a successful `check-config`, turning the
/// dry run from a bare OK/FAIL into an explanation of the effective config over the layered
/// file and `GDI_NODE__*` env model.
///
/// Only non-secret, operator-relevant fields: the resolved `listen`, management address,
/// `base_url` and `data_dir`, the beacon mount prefixes and whether they are combined or
/// split, the catalog count, and which optional subsystems (FDP, S3, Vault, PME, OTLP) are
/// both configured and compiled into this binary. Never a token, credential or transit key.
fn print_effective_config_summary(config: &ServiceConfig) {
    let b = &config.beacon;
    let beacon_mode = if b.aggregated_base_path == b.sensitive_base_path {
        "combined"
    } else {
        "split"
    };
    println!("  listen          = {}", config.service.listen);
    println!("  management_addr = {}", config.service.management_addr);
    println!("  base_url        = {}", config.service.base_url);
    println!("  data_dir        = {}", config.service.data_dir.display());
    println!(
        "  beacon_prefix   = {} (aggregated), {} (sensitive) [{beacon_mode}]",
        b.aggregated_base_path, b.sensitive_base_path
    );
    println!("  catalogs        = {}", config.catalogs.len());
    println!(
        "  fairdp          = {}",
        if config.fairdp.is_some() {
            "configured"
        } else {
            "not-configured"
        }
    );
    println!("  s3              = {}", s3_status(config));
    print_s3_bucket_summary(config);
    println!("  vault           = {}", vault_config_status(config));
    println!("  pme             = {}", pme_config_status(config));
    println!("  otlp_export     = {}", otlp_config_status(config));
    println!("  otlp_metrics    = {}", otlp_metrics_status(config));
    // Writer-auth posture: `check-config` does not run `warn_deployment_posture`, because
    // it never serves, so without this line a dry run would be silent about publishers being
    // unauthenticated — the thing a first-run operator is checking for.
    println!("  writer_auth     = {}", writer_policy_status(config));
    println!("  public_cors     = {}", public_cors_status(config));
    // Log and audit posture. It is otherwise env-only (LOG_FORMAT, GDI_LOG, RUST_LOG) and
    // config-only ([audit]), so a dry run would show neither a stale GDI_LOG shadowing
    // RUST_LOG nor an unintended query_detail.
    let (log_format, log_filter) = gdi_node_standalone::logging::effective_log_summary();
    println!("  log_format      = {log_format}");
    println!("  log_filter      = {log_filter}");
    println!(
        "  audit           = {} (query_detail={})",
        if config.audit.enabled {
            "enabled"
        } else {
            "disabled"
        },
        config.audit.query_detail
    );
    // Management-plane surface: which opt-in routes this config mounts. Without these lines
    // `check-config` would be byte-identical between a node with every opt-in off and one
    // mounting the whole inventory, hidden datasets included, plus three unauthenticated
    // action endpoints — and it is the documented pre-deploy gate. The k-anon floor joins
    // them for the same reason: its only other signal is the absence of a warning.
    println!(
        "  mgmt_inventory  = {}",
        if config.service.expose_dataset_list {
            "EXPOSED (GET /datasets + /datasets/suppressed enumerate every dataset, hidden ones included)"
        } else {
            "off (per-id state oracle only)"
        }
    );
    println!(
        "  mgmt_stats      = {}",
        if config.stats.enabled {
            "enabled (GET /stats/queries, per-dataset counters, hidden datasets included)"
        } else {
            "off"
        }
    );
    println!(
        "  mgmt_control    = {}",
        if config.control.enabled {
            format!(
                "ENABLED (POST {}, UNAUTHENTICATED; the bind address and a NetworkPolicy \
                 are the only controls)",
                gdi_node_standalone::app::CONTROL_ROUTES.join(", ")
            )
        } else {
            "off".to_owned()
        }
    );
    println!(
        "  k_anon_floor    = {}",
        if config.beacon.min_allele_count == 0 {
            "0, small-count suppression DISABLED (alleles, not individuals)".to_owned()
        } else {
            format!(
                "{} alleles (>= {} individuals per served cell)",
                config.beacon.min_allele_count,
                config.beacon.min_allele_count.div_ceil(2)
            )
        }
    );
    println!("  registration URLs (forward these to the federation; must match base_url):");
    for (audience, url) in registration_urls(
        &config.service.base_url,
        &b.aggregated_base_path,
        &b.sensitive_base_path,
        config.fairdp.is_some(),
    ) {
        println!("    {audience:<32} {url}");
    }
    print!(
        "{}",
        smoke_test_curl(&config.service.base_url, &b.aggregated_base_path)
    );
}

/// A ready-to-run `g_variants` query against this config's aggregated beacon.
///
/// The beacon does not live at a fixed path: `aggregated_base_path` defaults to
/// `/aggregated/beacon/v2`, while the Compose stacks override both mounts to `/beacon/v2`.
/// A curl in a README is therefore right for one of those and 404s on the other, and a 404
/// right after a long first install reads as "the node is broken" rather than "the path
/// moved". Emitting the URL from the config keeps the printed command true.
fn smoke_test_curl(base_url: &str, aggregated_path: &str) -> String {
    let base = base_url.trim_end_matches('/');
    format!(
        "  smoke test 1: is the beacon path right? (works on any node, data or not)\n\
         \x20   curl {base}{aggregated_path}/info\n\
         \x20   expect: 200 and a beaconId. A 404 means the path is wrong, not the node.\n\
         \x20 smoke test 2: is a dataset being served? (the bundled COVID fixture)\n\
         \x20   curl -X POST {base}{aggregated_path}/g_variants \\\n\
         \x20     -H 'content-type: application/json' \\\n\
         \x20     -d '{{\"query\":{{\"requestParameters\":{{\"referenceName\":\"3\",\
         \"start\":[45823239],\"referenceBases\":\"T\",\"alternateBases\":\"C\",\
         \"assemblyId\":\"GRCh38\",\"requestedGranularity\":\"RECORD\"}}}}}}'\n\
         \x20   expect: 200. `\"exists\": false` until you ingest that fixture; on a fresh\n\
         \x20   node that is the correct answer, not a failure.\n"
    )
}

/// Format a config section's status for the `check-config` and startup summaries from
/// whether it is `configured` (present in the config) and whether the feature that acts
/// on it is `compiled` into this binary: `not-configured`, `configured`, or the
/// `configured-but-not-compiled` mismatch. The three-state vocabulary is defined here alone,
/// so the per-subsystem status helpers below cannot drift apart.
fn feature_status(configured: bool, compiled: bool) -> &'static str {
    if !configured {
        "not-configured"
    } else if compiled {
        "configured"
    } else {
        "configured-but-not-compiled"
    }
}

/// Vault status for `check-config` (no connection attempted): whether `[vault]`
/// is configured and whether the `vault` feature is compiled in. Distinct from
/// [`vault_status`], which also reflects the live startup connect outcome.
fn vault_config_status(config: &ServiceConfig) -> &'static str {
    feature_status(config.has_vault(), cfg!(feature = "vault"))
}

/// Browser-origin posture of the public plane for `check-config`.
///
/// `[service].cors_allowed_origins` defaults to empty, which means the wildcard: any site a
/// browser visits may read this node's beacon and FDP. That is the right default for a
/// public, internet-facing beacon, whose data is unauthenticated anyway, and the wrong one
/// for a node whose data plane is intranet- or VPN-only, where the wildcard turns any user's
/// browser into a read-proxy for the node. The knob exists to close that, so the posture
/// belongs in the dry run next to the others. It reuses
/// [`app::public_cors_is_wildcard`], the single origin rule, rather than restating it.
fn public_cors_status(config: &ServiceConfig) -> String {
    let configured = &config.service.cors_allowed_origins;
    if gdi_node_standalone::app::public_cors_is_wildcard(configured) {
        return "wildcard (ANY browser origin may read the public plane)".to_owned();
    }
    format!("allow-list ({} origin(s))", configured.len())
}

/// Writer-authentication status for `check-config`.
///
/// `off` is the shipped default, so this line is what tells a first-run operator that
/// publishers are unauthenticated — the `recovered` provenance kind — rather than leaving
/// them to infer it. Mirrors the `doctor` writer-policy report for a node that is not
/// running yet.
fn writer_policy_status(config: &ServiceConfig) -> &'static str {
    match config.ingest.writer_policy {
        WriterPolicy::Off => "off (UNAUTHENTICATED: writer key recorded, never verified)",
        WriterPolicy::Warn => "warn (un-allow-listed writers recorded + counted, still published)",
        // Name plaintext drops too: a plaintext staging dir carries no writer key, so it
        // can never be allow-listed and `enforce` quarantines it. An operator who deploys
        // staging dirs and then hardens to `enforce` would otherwise watch every drop vanish
        // into quarantine with nothing here hinting why.
        WriterPolicy::Enforce => {
            "enforce (un-allow-listed writers and unidentified plaintext drops quarantined)"
        }
    }
}

/// PME (Parquet-modular-encryption at rest) status for `check-config`: active
/// when `[vault].transit_key` is set to a non-empty value, gated on the `pme`
/// feature. Never prints the key itself.
fn pme_config_status(config: &ServiceConfig) -> &'static str {
    let transit_set = config
        .vault
        .as_ref()
        .and_then(|v| v.transit_key.as_deref())
        .is_some_and(|k| !k.is_empty());
    feature_status(transit_set, cfg!(feature = "pme"))
}

/// OTLP trace-export status for `check-config`: whether `[service].otlp_endpoint`
/// is set, gated on the `otel` feature.
fn otlp_config_status(config: &ServiceConfig) -> &'static str {
    feature_status(
        config.service.otlp_endpoint.is_some(),
        cfg!(feature = "otel"),
    )
}

/// The OTLP metrics-push status for the `check-config` summary: off, the interval it
/// pushes at, or one of the two inert shapes an operator would otherwise mistake for
/// working (no endpoint to push to; a binary without the `otel` feature).
fn otlp_metrics_status(config: &ServiceConfig) -> String {
    match (
        config.service.otlp_metrics_interval_seconds,
        config.service.otlp_endpoint.is_some(),
        cfg!(feature = "otel"),
    ) {
        (None, _, _) => "off".to_owned(),
        (Some(_), false, _) => "configured-without-endpoint (inert)".to_owned(),
        (Some(seconds), true, true) => format!("every {seconds}s"),
        (Some(_), true, false) => "configured-but-not-compiled".to_owned(),
    }
}

/// Per-bucket detail for the `check-config` summary: name, endpoint, and where each
/// bucket's credentials come from.
///
/// `s3 = configured` alone says nothing an operator can act on, and it hides a precedence
/// trap: a bucket with no inline keys resolves to an anonymous client, so a mistyped
/// `GDI_NODE__S3__BUCKETS__0__ACCESS_KEY_ID` passes the gate and only shows up as a failing
/// request later. The live boot logs this as `s3 credential source`.
///
/// Vault is not consulted, because `check-config` makes no network calls, so a bucket that
/// Vault would supply is reported by its local source with the override called out
/// separately. It names the source, never a key.
#[cfg(feature = "s3")]
fn print_s3_bucket_summary(config: &gdi_node_standalone_core::config::ServiceConfig) {
    let Some(s3) = config.s3.as_ref() else {
        return;
    };
    let vault_supplies = config.vault.as_ref().is_some_and(|v| v.s3_path.is_some());
    for bucket in &s3.buckets {
        // Empty overrides: this is the offline view. `credential_source` is the function
        // the live boot uses, so the two cannot disagree about what "config" or "anonymous"
        // means.
        let local =
            gdi_node_standalone::s3::credential_source(bucket, &std::collections::BTreeMap::new());
        let note = if vault_supplies {
            " (vault.s3_path is set: Vault may override this at boot)"
        } else {
            ""
        };
        // The prefix decides which objects this channel addresses, and it is invisible
        // everywhere else a pre-deploy check looks, so a prefix set on the node and not on
        // the writer, or the reverse, reads as "the bucket is empty" with nothing naming the
        // cause. Printed as `bucket/prefix`, matching `gdi-dataset-tool`'s `target_label`,
        // so the two sides can be compared by eye.
        let target = if bucket.prefix.is_empty() {
            bucket
                .bucket
                .clone()
                .unwrap_or_else(|| "<unset>".to_owned())
        } else {
            format!(
                "{}/{}",
                bucket.bucket.as_deref().unwrap_or("<unset>"),
                bucket.prefix.trim_end_matches('/')
            )
        };
        println!(
            "    channel {name:<19} target={target} endpoint={endpoint} credentials={local}{note}",
            name = bucket.name,
            endpoint = bucket.endpoint.as_deref().unwrap_or("<unset>"),
        );
    }
}

/// No-op without the `s3` feature: a lite build cannot carry buckets at all.
#[cfg(not(feature = "s3"))]
fn print_s3_bucket_summary(_config: &gdi_node_standalone_core::config::ServiceConfig) {}

/// The S3 connection status for the startup log block: whether `[[s3.buckets]]` is
/// configured, and whether the `s3` feature is compiled into this binary. The
/// `configured-but-not-compiled` state is defensive, since preflight rejects that mismatch
/// before this point, but the branch stays honest. Never logs any credential.
fn s3_status(config: &ServiceConfig) -> &'static str {
    feature_status(config.has_s3_buckets(), cfg!(feature = "s3"))
}

/// The Vault connection status for the startup log block: not-configured, connected, or
/// unreachable-at-startup, in which case the node degrades to keyless. Never logs the token.
/// `vault_ok` is the startup connect outcome.
fn vault_status(config: &ServiceConfig, vault_ok: bool) -> &'static str {
    if !config.has_vault() {
        "not-configured"
    } else if !cfg!(feature = "vault") {
        // Preflight rejects this before we get here, but keep the branch honest.
        "configured-but-not-compiled"
    } else if vault_ok {
        "connected"
    } else {
        "unreachable-at-startup (keyless)"
    }
}

/// Dispatch one `identity <verb>` (init / rotate / retire / list / backup / restore) —
/// the binary exits with what it returns. Keeps `main` small.
///
/// # Errors
///
/// Returns whatever the selected verb returns (a missing `[vault]` section, a build
/// without the `vault` feature, an unreachable Vault, a missing required flag, …).
async fn run_identity_subcommand(command: &IdentityCommand, config: &ServiceConfig) -> Result<()> {
    match command {
        IdentityCommand::Init(args) => {
            run_init_identity(
                config,
                args.ensure,
                args.force,
                args.from.as_deref(),
                args.file.as_deref(),
            )
            .await
        }
        IdentityCommand::Rotate => run_rotate_identity(config).await,
        IdentityCommand::Retire(args) => {
            run_retire_identity(config, args.dry_run, args.yes, args.force).await
        }
        IdentityCommand::List => run_list_identity(config).await,
        IdentityCommand::Backup(args) => {
            run_backup_identity(config, &args.recipients, args.out.as_deref()).await
        }
        IdentityCommand::Restore(args) => {
            run_restore_identity(
                config,
                args.input.as_deref(),
                args.identity.as_deref(),
                args.dry_run,
            )
            .await
        }
    }
}

/// Run the `identity init` one-shot: provision the node's crypt4gh identity and
/// exit, instead of serving. With a `[vault]` block (and the `vault` feature) it
/// creates the identity in Vault (create-only); otherwise — or with `--file` — it
/// writes a key file to the `[keys].identities` path. Minted fresh, or imported
/// from an existing PEM when `from` is set. `ensure` turns an already-provisioned
/// path into a success no-op (idempotent re-runs).
///
/// # Errors
///
/// Returns an error when `[vault]` is configured but the `vault` feature is not
/// compiled in (and no `--file` is given), when the resolved key file already
/// exists without `--ensure`/`--force`, when `from` is not a readable crypt4gh
/// key, or when provisioning otherwise fails (Vault unreachable, a create-only
/// conflict with an existing Vault identity, or a failed write — see
/// [`gdi_node_standalone::init_identity::run`] and
/// [`gdi_node_standalone::init_identity_file::run`]). With no `[vault]` section it mints
/// a file identity instead of erroring.
#[cfg_attr(
    not(feature = "vault"),
    expect(
        clippy::unused_async,
        reason = "only the vault build awaits; without it the body has nothing to await"
    )
)]
async fn run_init_identity(
    config: &ServiceConfig,
    ensure: bool,
    force: bool,
    from: Option<&Path>,
    file: Option<&Path>,
) -> Result<()> {
    // The identity goes wherever the config says the node will read it from: Vault when
    // `[vault]` is set, otherwise the `[keys]` key file. An explicit `--file` selects the
    // file posture regardless, so an operator can mint a key file on a Vault-configured
    // node without editing the config first, and a no-Vault node need not reach for the
    // provider's `gdi-dataset-tool` to mint the node's own key.
    if file.is_some() || !config.has_vault() {
        return gdi_node_standalone::init_identity_file::run(config, ensure, force, from, file);
    }

    #[cfg(feature = "vault")]
    {
        let Some(vault_cfg) = config.vault.as_ref() else {
            anyhow::bail!(
                "identity init requires a [vault] section (the identity is written to Vault KV)"
            );
        };
        if force {
            anyhow::bail!(
                "--force replaces a file-backed identity; a Vault identity is create-only \
                 (add a new key with `identity rotate`, drop an old one with `identity retire`)"
            );
        }
        gdi_node_standalone::init_identity::run(
            vault_cfg,
            &config.audit,
            &config.service.data_dir,
            ensure,
            from,
        )
        .await
    }
    #[cfg(not(feature = "vault"))]
    {
        // `[vault]` is configured but this build cannot talk to it. A build without the
        // feature still mints a file identity above; that path needs no Vault client.
        let _ = (config, ensure, force, from);
        anyhow::bail!(
            "this config has a [vault] section but the binary was built without the `vault` \
             feature; rebuild with --features vault (or full), or mint a file-backed \
             identity with `identity init --file <PATH>`"
        )
    }
}

/// Run the `identity rotate` one-shot: mint a new node crypt4gh identity and add it
/// to Vault beside the existing one(s), then exit. The new key becomes the published
/// recipient; prior keys are retained for decryption. Generated in memory, never on
/// disk.
///
/// # Errors
///
/// Returns an error when the `vault` feature is not compiled in, `[vault]` is absent
/// from the config, no identity exists yet, or the check-and-set write is rejected
/// (see [`gdi_node_standalone::rotate_identity::run`]).
#[cfg_attr(
    not(feature = "vault"),
    expect(
        clippy::unused_async,
        reason = "only the vault build awaits; without it the body has nothing to await"
    )
)]
async fn run_rotate_identity(config: &ServiceConfig) -> Result<()> {
    #[cfg(feature = "vault")]
    {
        let Some(vault_cfg) = config.vault.as_ref() else {
            // A file-backed node is not misconfigured here: this verb does not apply to it,
            // and there is a procedure. Name it, rather than leaving an operator whose
            // `identity list` just worked to conclude the config is wrong.
            anyhow::bail!(
                "identity rotate is Vault-only: it rewrites the identity set in Vault KV, and \
                 this config has no [vault] section. A file-backed node rotates by minting \
                 the new key (`identity init --file <new>`), putting it first in \
                 [keys].identities with the old key kept after it, then restarting. See \
                 docs/operating.md section 9 (\"Rotating a file-backed identity\"). \
                 `identity list` shows the result."
            );
        };
        gdi_node_standalone::rotate_identity::run(vault_cfg, &config.audit).await
    }
    #[cfg(not(feature = "vault"))]
    {
        let _ = config;
        anyhow::bail!(
            "identity rotate requires the `vault` feature; rebuild with --features vault (or full)"
        )
    }
}

/// Run the `identity retire` one-shot: remove the oldest retained node crypt4gh
/// identity from Vault (keeping the published recipient + newer keys) and exit.
///
/// This op is destructive, so it requires an explicit choice: `--dry-run` previews
/// what would be removed (reads Vault, writes nothing); `--yes` applies it; neither
/// refuses with guidance (so an operator's universal "safe preview" reflex never
/// performs the real removal by accident).
///
/// # Errors
///
/// Returns an error when the `vault` feature is not compiled in, `[vault]` is absent,
/// neither `--dry-run` nor `--yes` was given, only one identity remains (nothing safe
/// to retire), or the write is rejected (see [`gdi_node_standalone::retire_identity::run`]).
#[cfg_attr(
    not(feature = "vault"),
    expect(
        clippy::unused_async,
        reason = "only the vault build awaits; without it the body has nothing to await"
    )
)]
async fn run_retire_identity(
    config: &ServiceConfig,
    dry_run: bool,
    yes: bool,
    force: bool,
) -> Result<()> {
    #[cfg(feature = "vault")]
    {
        if config.vault.is_none() {
            anyhow::bail!(
                "identity retire requires a [vault] section (the identity lives in Vault KV)"
            );
        }
        if !dry_run && !yes {
            anyhow::bail!(
                "identity retire PERMANENTLY removes the oldest node key from Vault. Re-run with \
                 --dry-run to preview exactly what would be removed, or --yes to confirm and apply."
            );
        }
        gdi_node_standalone::retire_identity::run(config, &config.audit, dry_run, force).await
    }
    #[cfg(not(feature = "vault"))]
    {
        let _ = (config, dry_run, yes, force);
        anyhow::bail!(
            "identity retire requires the `vault` feature; rebuild with --features vault (or full)"
        )
    }
}

/// Run `identity list`: print the current node identity state (read-only) from Vault,
/// without dumping secret key material (see [`gdi_node_standalone::list_identity::run`]).
///
/// # Errors
///
/// Returns an error (non-zero exit) when `[vault]` is absent, Vault is unreachable,
/// or no identity exists. Requires the `vault` feature.
#[cfg_attr(
    not(feature = "vault"),
    expect(
        clippy::unused_async,
        reason = "only the vault build awaits; without it the body has nothing to await"
    )
)]
async fn run_list_identity(config: &ServiceConfig) -> Result<()> {
    // Same rule as `identity init` (see `run_init_identity`): report on whichever store
    // the config says the node reads its identity from. A no-Vault node reads key files, so
    // it gets the file-backed listing; that posture is what the quickstart, s3 and minimal
    // configs ship.
    if !config.has_vault() {
        return gdi_node_standalone::list_identity_file::run(config);
    }

    #[cfg(feature = "vault")]
    {
        let Some(vault_cfg) = config.vault.as_ref() else {
            anyhow::bail!(
                "identity list requires a [vault] section (the identity lives in Vault KV)"
            );
        };
        gdi_node_standalone::list_identity::run(vault_cfg, &config.audit).await
    }
    #[cfg(not(feature = "vault"))]
    {
        // `[vault]` is configured but this build cannot talk to it. The key files (if
        // any) are still inspectable, and saying so beats a bare "rebuild with vault".
        anyhow::bail!(
            "identity list: [vault] is configured but this build lacks the `vault` feature; \
             rebuild with --features vault (or full). To inspect the file-backed \
             [keys].identities on this build instead, remove [vault] from the config you \
             pass with --config."
        )
    }
}

/// Run `identity backup`: export the node identity from Vault, crypt4gh-encrypted to
/// the operator recipient at `--recipient`, written to `--out`, then exit.
///
/// # Errors
///
/// Returns an error when the `vault` feature is not compiled in, `[vault]` is
/// absent, `--recipient`/`--out` are missing, or the backup fails (see
/// [`gdi_node_standalone::identity_backup::run_backup`]).
#[cfg_attr(
    not(feature = "vault"),
    expect(
        clippy::unused_async,
        reason = "only the vault build awaits; without it the body has nothing to await"
    )
)]
async fn run_backup_identity(
    config: &ServiceConfig,
    recipients: &[std::path::PathBuf],
    out: Option<&Path>,
) -> Result<()> {
    #[cfg(feature = "vault")]
    {
        let Some(vault_cfg) = config.vault.as_ref() else {
            anyhow::bail!(
                "identity backup is Vault-only: it exports the identity out of Vault KV, \
                 crypt4gh-encrypted, because in that posture the key is not a file. This \
                 config has no [vault] section, so the key is already a file; back it up by \
                 copying it (`install -m 0600 <key> <destination>`). See docs/operating.md \
                 section 9 (\"Backing up a file-backed identity\"); `identity list` names \
                 the files."
            );
        };
        if recipients.is_empty() {
            anyhow::bail!(
                "identity backup requires at least one --recipient <operator-public-key.pem>"
            );
        }
        let out = out.context("identity backup requires --out <file>")?;
        gdi_node_standalone::identity_backup::run_backup(vault_cfg, &config.audit, recipients, out)
            .await
    }
    #[cfg(not(feature = "vault"))]
    {
        let _ = (config, recipients, out);
        anyhow::bail!(
            "identity backup requires the `vault` feature; rebuild with --features vault (or full)"
        )
    }
}

/// Run `identity restore`: decrypt the backup at `--in` with the operator secret at
/// `--identity` and write it into Vault create-only, then exit. With `--dry-run`,
/// only verify the backup decrypts and parses (no Vault write, and no `[vault]` section
/// required — safe on an offline machine where the operator secret is held).
///
/// # Errors
///
/// Returns an error when the `vault` feature is not compiled in, `--in`/`--identity`
/// are missing, `[vault]` is absent (real restore only), or the restore/verify fails
/// (wrong key, an identity already present, etc. — see
/// [`gdi_node_standalone::identity_backup::run_restore`] /
/// [`gdi_node_standalone::identity_backup::verify_backup`]).
#[cfg_attr(
    not(feature = "vault"),
    expect(
        clippy::unused_async,
        reason = "only the vault build awaits; without it the body has nothing to await"
    )
)]
async fn run_restore_identity(
    config: &ServiceConfig,
    input: Option<&Path>,
    identity: Option<&Path>,
    dry_run: bool,
) -> Result<()> {
    #[cfg(feature = "vault")]
    {
        let input = input.context("identity restore requires --in <backup-file>")?;
        let identity =
            identity.context("identity restore requires --identity <operator-secret-key.pem>")?;
        if dry_run {
            // Verify-only: a purely local decrypt + parse, no Vault I/O — so it needs
            // no [vault] section and is safe to run wherever the operator secret lives.
            return gdi_node_standalone::identity_backup::verify_backup(input, identity);
        }
        let Some(vault_cfg) = config.vault.as_ref() else {
            anyhow::bail!(
                "identity restore requires a [vault] section (the identity lives in Vault KV)"
            );
        };
        gdi_node_standalone::identity_backup::run_restore(vault_cfg, &config.audit, input, identity)
            .await
    }
    #[cfg(not(feature = "vault"))]
    {
        let _ = (config, input, identity, dry_run);
        anyhow::bail!(
            "identity restore requires the `vault` feature; rebuild with --features vault (or full)"
        )
    }
}

/// The service version line: the crate version plus the pinned `gdi_metadata_version`
/// build constant (the gdi-metadata SHACL model tag the node's emitted FDP graph
/// conforms to).
///
/// Rendered here rather than via [`gdi_build_info::version_provenance`] because the
/// service interleaves `gdi_metadata_version`, which the tool has no equivalent of.
/// The provenance *substrings* must still match the tool's — see the test below.
fn version_line() -> String {
    format!(
        "{} {} (git {}, gdi_metadata_version {GDI_METADATA_VERSION}, build_epoch {})",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        gdi_build_info::GIT_SHA,
        gdi_build_info::BUILD_EPOCH,
    )
}

/// Print the service version line.
fn print_version() {
    println!("{}", version_line());
}

/// Seed the config-derived metric series (the per-channel and inbox label sets).
///
/// The `{channel}` label set is known only from config, so
/// `install_recorder`'s static `seed_always_present` cannot seed them. Without a baseline a
/// series is born at its first non-zero value and the `increase()>0` alerts miss the first
/// event. Called after `AppState::new`; the recorder is installed earlier (see `run`).
fn seed_config_series(state: &AppState) {
    // The per-channel error counters. A series born at 1 and left flat yields
    // `increase() = 0`, so without this baseline the channel alerts miss a first error.
    if let Some(s3) = state.config.s3.as_ref() {
        let names: Vec<&str> = s3.buckets.iter().map(|b| b.name.as_str()).collect();
        metrics::seed_s3_channel_series(&names);
    }
    // `gdi_channel_suppressed{channel}`, for every configured channel: the bucket names
    // plus `inbox`.
    let mut channel_names: Vec<&str> = state
        .config
        .s3
        .as_ref()
        .map(|s3| s3.buckets.iter().map(|b| b.name.as_str()).collect())
        .unwrap_or_default();
    if state.config.service.inbox.is_some() {
        channel_names.push("inbox");
        // Only with an inbox configured: the staleness alert over this gauge cannot fire on
        // an absent series, so an inbox unreadable from boot would be invisible to it.
        metrics::seed_inbox_series();
    }
    if state.config.fairdp.is_some() {
        // Only with the FDP mounted, for the same reason: it seeds the `2xx` and `5xx`
        // cells of the request counter, so the FDP panels read a flat zero on a fresh node.
        metrics::seed_fairdp_series();
    }
    metrics::seed_channel_series(&channel_names);
}

/// Bind the management listener, mapping a bind failure to a contextual error.
///
/// Separated from [`serve_management`] so the hard-requirement contract (a bind failure is
/// an `Err` the caller propagates to abort startup, never swallowed) is unit-testable
/// without spawning the server.
///
/// # Errors
///
/// Returns an error if `addr` cannot be bound (in use, bad address, permission).
async fn bind_management_listener(addr: &str) -> Result<tokio::net::TcpListener> {
    bind_listener(addr, "required management listener", "management_addr").await
}

/// Bind a TCP listener, turning `EADDRINUSE` into an error the operator can act on.
///
/// Both planes default to fixed ports (`8080` and `9090`), so a second node on the host,
/// or any unrelated process holding the port, collides. A bare `Address already in use
/// (os error 98)` names neither the knob to turn nor the squatter to find; name both.
/// `key` is the `[service]` field to retune.
///
/// # Errors
///
/// Returns an error if `addr` cannot be bound (in use, malformed, permission denied).
async fn bind_listener(addr: &str, role: &str, key: &str) -> Result<tokio::net::TcpListener> {
    match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => Ok(listener),
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            // `rsplit` always yields at least one item, so this is the port when `addr`
            // is `host:port` and the whole string otherwise.
            let port = addr.rsplit(':').next().unwrap_or(addr);
            Err(anyhow::Error::new(e).context(format!(
                "binding the {role} on {addr}: the address is already in use. Set \
                 `[service].{key}` to a free port, or stop whatever already holds it \
                 (`ss -ltnp | grep :{port}`)."
            )))
        }
        Err(e) => Err(anyhow::Error::new(e).context(format!("binding the {role} on {addr}"))),
    }
}

/// Bind the separate management-plane listener (`[service].management_addr`) and spawn
/// its server (health + dataset-state oracle + `/metrics`).
///
/// The bind is a hard startup requirement: a bind failure aborts startup so the node never
/// comes up with an unprobeable or unscrapeable management plane (unlike the public
/// listener, the kubelet's liveness target lives only here). It binds early, before the
/// ingest runtime, so liveness answers `200` and readiness `503` throughout startup.
/// Returns the spawned server's
/// [`JoinHandle`]; the server keeps accepting until the caller-supplied `shutdown`
/// [`Notify`] fires, which `run` does only after the public plane has drained, so probes
/// stay answerable throughout the drain. It is not the shared SIGTERM, which would defeat
/// the readiness drain.
///
/// [`JoinHandle`]: tokio::task::JoinHandle
///
/// # Errors
///
/// Returns an error if the management listener cannot bind.
async fn serve_management(
    state: AppState,
    metrics_handle: Option<Arc<metrics::MetricsHandle>>,
    shutdown: Arc<Notify>,
) -> Result<tokio::task::JoinHandle<()>> {
    let addr = state.config.service.management_addr.clone();
    let listener = bind_management_listener(&addr).await?;
    let bound = listener
        .local_addr()
        .map_or_else(|_| addr.clone(), |a| a.to_string());
    info!(
        plane = gdi_node_standalone::metrics::PLANE_MANAGEMENT,
        event.action = "service.listen",
        addr = %bound,
        "management plane listening (health, dataset-state, metrics)"
    );
    let router = gdi_node_standalone::app::build_management_router(state.clone(), metrics_handle);
    // Serve the management plane through the same bounded accept loop the public plane
    // uses (`serve_bounded`), so its pre-service connection phase is bounded too by a
    // header-read timeout and a connection cap. `axum::serve` has neither, which would leave
    // the sole liveness target open to a slowloris or connection flood. `readiness` is
    // `None`: the management plane must not flip `/health/ready`, because it keeps answering
    // probes throughout the public drain.
    //
    // It still drains on its own `shutdown` signal, fired only after the public plane has
    // finished draining, rather than on the shared SIGTERM or SIGINT. Otherwise the
    // `/health/ready` 503 drain would be defeated: fresh probes and scrapes would get
    // connection-refused for the whole drain window, and repeated liveness failures could
    // SIGKILL a pod still draining in-flight beacon requests.
    let drain = Duration::from_secs(state.config.service.shutdown_drain_seconds.max(1));
    let handle = tokio::spawn(async move {
        if let Err(e) = serve_bounded(
            listener,
            router,
            drain,
            None,
            gdi_node_standalone::metrics::PLANE_MANAGEMENT,
            async move {
                shutdown.notified().await;
            },
        )
        .await
        {
            warn!(error = %e, "management server exited with error");
        }
    });
    Ok(handle)
}

/// Remove every entry under `data_dir/.incoming/` (orphaned per-job working dirs).
fn reap_incoming(data_dir: &Path) {
    let incoming = data_dir.join(".incoming");
    let Ok(entries) = std::fs::read_dir(&incoming) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        let removed = if path.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        if let Err(e) = removed {
            warn!(path = %path.display(), error = %e, "could not reap stale .incoming entry");
        }
    }
}

/// Whether a watcher event is one the node's own inbox scan produces, and must therefore
/// not wake another scan.
///
/// `scan_once` only reads the inbox: it `read_dir`s the directory and opens the sidecars it
/// finds. On Linux that raises `IN_OPEN`, which `notify` reports as `Access(Open(..))`, the
/// event kind that closes a scan-to-scan loop. `Read` and `Close(Read)` are filtered on the
/// same grounds, since a reader produces them; they are not in `notify`'s default mask
/// today, so those arms are future-proofing rather than a live path.
///
/// Everything else stays a wake. `Close(Write)` is a finished write, and the documented
/// atomic drop (`*.partial` then `rename`) arrives as `Modify(Name(To))` or `Create`. None
/// of those is produced by reading, so filtering here cannot delay a real drop.
///
/// The node also moves entries within the inbox when quarantining to `.rejected/`, and that
/// legitimately wakes a scan. It is self-limiting, because the entry leaves the scanned set,
/// unlike an open, which would recur on every pass.
const fn is_self_inflicted(kind: notify::EventKind) -> bool {
    use notify::event::{AccessKind, AccessMode, EventKind};
    matches!(
        kind,
        EventKind::Access(
            AccessKind::Open(_) | AccessKind::Read | AccessKind::Close(AccessMode::Read)
        )
    )
}

/// Spawn a filesystem watcher on the inbox that triggers a rescan on any event.
///
/// Debouncing is deliberately plain: events fire a [`Notify`], and a draining task coalesces
/// a burst into a single `scan_once`, with a short settle delay collapsing a multi-file drop
/// into one scan. Correctness rests on `scan_once`'s idempotence, not on watcher
/// sophistication.
///
/// The scan must not be able to wake itself. `scan_once` opens the inbox directory and its
/// sidecars on every pass, and `notify`'s inotify backend arms the watch with `OPEN`, so a
/// wake-on-any-event callback closes a loop: scan, `IN_OPEN`, permit, settle, scan. That
/// loop is also silent, because `gdi_inbox_scan_last_success_timestamp_seconds` advancing
/// constantly looks maximally healthy and `InboxScanWedged` only catches a dead watcher.
/// [`is_self_inflicted`] filters exactly the read-only access kinds a scan produces, so
/// every real drop signal — create, write-close, rename-in, remove, attribute change —
/// still wakes it immediately, with no added latency and no debounce floor.
fn spawn_watcher(runtime: IngestRuntime, inbox: &Path) {
    let notify = Arc::new(Notify::new());
    let notify_for_cb = Arc::clone(&notify);

    // The watcher callback runs on notify's own thread and only wakes the async draining
    // task; it does no async work itself.
    let watcher = RecommendedWatcher::new(
        move |res: notify::Result<notify::Event>| match res {
            Ok(ev) if is_self_inflicted(ev.kind) => {}
            Ok(_) => notify_for_cb.notify_one(),
            Err(e) => {
                // A watcher-level error signals a degraded watcher: count it so an operator
                // sees a flaky watcher before pickups stop, with the periodic rescan as the
                // safety net. The counter is content-free.
                metrics::inbox_watcher_restart();
                warn!(error = %e, "inbox watcher error");
            }
        },
        notify::Config::default(),
    );
    let mut watcher = match watcher {
        Ok(w) => w,
        Err(e) => {
            metrics::inbox_watcher_restart();
            warn!(error = %e, "could not create inbox watcher; relying on the periodic rescan");
            return;
        }
    };
    if let Err(e) = watcher.watch(inbox, RecursiveMode::NonRecursive) {
        metrics::inbox_watcher_restart();
        warn!(error = %e, "could not watch inbox; relying on the periodic rescan");
        return;
    }

    tokio::spawn(async move {
        // Keep the watcher alive for the task's lifetime.
        let _watcher = watcher;
        loop {
            notify.notified().await;
            // Coalesce a burst: wait a short settle window, then scan once. Guarded so a
            // panicking scan does not kill the watcher loop, which would stop pickups until
            // the next restart.
            tokio::time::sleep(Duration::from_millis(250)).await;
            guarded("inbox_watcher", {
                let r = runtime.clone();
                async move { r.scan_once().await }
            })
            .await;
        }
    });
}

/// How many buckets' startup reconciles run at once. A sliding window rather than rigid
/// waves: as each bucket finishes, the next starts. Bounds the boot-time fan-out
/// (connection pools, sidecar fetches) for a large fleet; worst-case boot for an
/// all-unreachable fleet is `ceil(buckets / this) × startup_reconcile_timeout_seconds`.
#[cfg(feature = "s3")]
const STARTUP_RECONCILE_CONCURRENCY: usize = 16;

/// One live bucket monitor, as a config reload sees it.
#[cfg(feature = "s3")]
struct RunningMonitor {
    /// The descriptor this monitor was built from, after any Vault override, so a reload
    /// diffs like against like. Compared by `PartialEq` rather than by the `Debug` string
    /// other config diffs use: that redacts `secret_access_key`, and a rotated credential is
    /// what an add-only reload would silently ignore.
    descriptor: gdi_node_standalone_core::config::S3Bucket,
    /// Stands this monitor and its supervisor down together.
    retire: Arc<gdi_node_standalone::s3::RetireSignal>,
    /// This monitor's in-flight (`ingesting`) set, so a reload that replaces the monitor can
    /// hand it to the successor. Carrying it keeps an id still ingesting under the retired
    /// monitor visible to the replacement's `apply_removed`, so a package deleted at source
    /// mid-ingest is still published `Hidden` rather than briefly served `Visible`.
    ingesting: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
}

/// The live monitor set, keyed by channel name.
///
/// A `std::sync::Mutex` rather than a `tokio` one: every holder does a map lookup and
/// nothing else, so the guard is never held across an `.await`.
#[cfg(feature = "s3")]
type RunningMonitors = Arc<std::sync::Mutex<std::collections::HashMap<String, RunningMonitor>>>;

/// What the `SIGHUP` handler needs in order to apply the bucket half of a reload.
///
/// A struct rather than three parameters, so the handler's signature is the same on a build
/// without the `s3` feature, where this is an empty type and [`Self::apply`] is a no-op.
/// The `#[cfg]` then lives at one definition instead of at every use.
#[cfg(feature = "s3")]
#[derive(Clone, Default)]
struct S3ReloadContext {
    /// `None` where there is nothing to reload — the signal-handler tests, which install
    /// the handler without a live ingest runtime behind it.
    inner: Option<S3ReloadInner>,
}

/// The live pieces an `s3` build's reload needs.
#[cfg(feature = "s3")]
#[derive(Clone)]
struct S3ReloadInner {
    runtime: IngestRuntime,
    /// The per-bucket Vault credential map, behind an `RwLock` because a reload refreshes it
    /// (see [`S3ReloadContext::refresh_vault_overrides`]). A boot-time snapshot would leave a
    /// bucket added later with no credential, so its add would have to be refused.
    overrides: Arc<std::sync::RwLock<S3Overrides>>,
    running: RunningMonitors,
    /// The connected Vault client, retained past boot so the refresh above can happen.
    /// `None` without `[vault]`, or when the startup connection failed transiently.
    #[cfg(feature = "vault")]
    vault: Option<gdi_node_standalone::vault::VaultClient>,
}

/// The no-`s3` build's stand-in: a reload has no buckets to apply.
#[cfg(not(feature = "s3"))]
#[derive(Clone)]
struct S3ReloadContext;

impl S3ReloadContext {
    /// A context with no buckets to reload. On an `s3` build only the tests want it, since
    /// `main` always has a live runtime to hand.
    ///
    /// It is defined under both feature sets so that a caller which does not care about S3
    /// needs no `#[cfg]` of its own. The two bodies differ because without the feature this
    /// type is a unit struct, and calling `default()` on one is itself a lint.
    #[cfg(all(test, feature = "s3"))]
    fn none() -> Self {
        Self { inner: None }
    }

    /// A context with no buckets to reload: the only shape a build without the `s3` feature
    /// has. See the `s3` build's twin above.
    #[cfg(not(feature = "s3"))]
    fn none() -> Self {
        Self
    }

    /// Re-read `[vault].s3_path` for `new_config`'s bucket set, replacing the credential map
    /// the next [`Self::apply`] will use.
    ///
    /// The map is built once at boot, keyed by the buckets the boot config declared, so a
    /// bucket a reload adds has no credential in it: it would fall back to inline keys the
    /// deployment forbids, and poll anonymously. `reload_s3_monitors` refuses that add
    /// rather than starting a doomed channel, which is the right fallback but a poor default
    /// when the credential is one Vault read away.
    ///
    /// Best-effort: on any Vault error the existing map is kept and the add is refused as
    /// before, with the cause logged. A reload must not fail, and must never widen access,
    /// because a secret store was briefly unreachable.
    #[cfg(feature = "s3")]
    #[cfg_attr(
        not(feature = "vault"),
        expect(
            clippy::unused_async,
            reason = "only the vault build awaits; without it the body has nothing to await"
        )
    )]
    async fn refresh_vault_overrides(&self, new_config: &ServiceConfig) {
        #[cfg(feature = "vault")]
        {
            let Some(inner) = self.inner.as_ref() else {
                return;
            };
            let (Some(client), Some(vault_cfg)) = (inner.vault.as_ref(), new_config.vault.as_ref())
            else {
                return;
            };
            match gdi_node_standalone::secrets::load_s3_overrides(client, vault_cfg, new_config)
                .await
            {
                Ok(fresh) => {
                    let count = fresh.len();
                    *inner
                        .overrides
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = fresh;
                    info!(
                        buckets = count,
                        "config reload re-read the per-bucket S3 credentials from [vault].s3_path"
                    );
                }
                Err(e) => warn!(
                    error = %e,
                    "config reload could not re-read [vault].s3_path; keeping the credentials \
                     loaded at boot. A bucket this reload adds therefore has no credential and \
                     will not be started. Restart once Vault is reachable"
                ),
            }
        }
        #[cfg(not(feature = "vault"))]
        let _ = new_config;
    }

    /// No-op: without the `s3` feature there are no bucket credentials to refresh.
    #[cfg(not(feature = "s3"))]
    #[expect(
        clippy::unused_async,
        reason = "signature parity with the `s3` build's method"
    )]
    async fn refresh_vault_overrides(&self, _new_config: &ServiceConfig) {}

    /// Apply `new_config`'s buckets to the live monitor set.
    #[cfg(feature = "s3")]
    fn apply(&self, state: &AppState, new_config: &ServiceConfig) {
        let Some(inner) = self.inner.as_ref() else {
            return;
        };
        let overrides = inner
            .overrides
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        reload_s3_monitors(
            state,
            &inner.runtime,
            &overrides,
            &inner.running,
            new_config,
        );
    }

    /// No-op: without the `s3` feature a config carrying `[[s3.buckets]]` was already
    /// rejected at boot by `preflight::check_features`, so there is nothing to reload.
    #[cfg(not(feature = "s3"))]
    #[expect(
        clippy::unused_self,
        reason = "signature parity with the `s3` build's method"
    )]
    fn apply(&self, _state: &AppState, _new_config: &ServiceConfig) {}
}

/// Build a [`gdi_node_standalone::s3::BucketMonitor`] per configured bucket, run each
/// one's startup reconcile (readiness: listing + bounded sidecar-content fetch +
/// metadata load), then spawn its poll loop. Background ingest of new/changed
/// packages proceeds afterwards via the shared queue.
///
/// Readiness is realised here by awaiting each bucket's startup reconcile before the
/// listener binds, so already-present visible datasets read `visible` rather than the
/// `hidden` default by the time the service serves traffic.
#[cfg(feature = "s3")]
async fn start_s3_monitors(
    state: &AppState,
    runtime: &IngestRuntime,
    s3_overrides: &S3Overrides,
    running: &RunningMonitors,
) {
    use gdi_node_standalone::s3::BucketMonitor;

    let Some(s3) = state.config.s3.as_ref() else {
        return;
    };
    if s3.buckets.is_empty() {
        return;
    }

    // Register the configured channel set before building any client, so a bucket whose
    // client fails to build below is reported unhealthy rather than silently absent from
    // `/health/ready`: its `s3` rollup is `all(..)` over registered channels, and vacuous
    // when a channel never registers. Each flips to healthy on its first reconcile.
    state
        .readiness
        .register_configured_channels(s3.buckets.iter().map(|b| b.name.as_str()));

    let mut monitors = Vec::with_capacity(s3.buckets.len());
    for bucket in &s3.buckets {
        // Idempotent over the running set. A `SIGHUP` or `POST /reload` that lands before
        // boot reaches this point can already have started this channel through the reload's
        // add arm, and building a second monitor here would have `spawn_monitor`'s insert
        // replace its record, leaving the first monitor polling with no `RetireSignal`
        // anyone holds and unretirable by any later reload.
        let already_running = running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(&bucket.name);
        if already_running {
            info!(
                channel = %bucket.name,
                "monitor already running (started by a reload before boot reached this \
                 point); not starting a second one"
            );
            continue;
        }
        // Apply any Vault-backed credential override (Vault takes precedence over
        // the inline `[[s3.buckets]]` access/secret keys). A no-op under a
        // non-vault build / when no override exists for this bucket.
        let bucket = apply_bucket_override(bucket, s3_overrides);
        match BucketMonitor::new(bucket.clone(), state.clone(), runtime.clone()) {
            Ok(monitor) => monitors.push(monitor),
            Err(e) => {
                // The channel stays registered `false` from the seeding above, so this is a
                // degraded but visible bucket, not a disappeared one.
                warn!(channel = %bucket.name, error = %e, "could not build S3 client; bucket disabled (reported unhealthy on /health/ready)");
            }
        }
    }

    // Enumerate the resolved bucket set up front, so a misconfiguration among many buckets
    // — a missing or mistyped endpoint, or a bucket that failed to build a client above —
    // is visible at boot rather than only when a poll fails. Never logs credentials.
    for bucket in &s3.buckets {
        info!(
            event.action = "s3.bucket.configure",
            channel = %bucket.name,
            endpoint = bucket.endpoint.as_deref().unwrap_or("<default>"),
            object_bucket = bucket.bucket.as_deref().unwrap_or("<none>"),
            "configured S3 bucket"
        );
    }

    // Readiness: run every bucket's startup reconcile concurrently, each under a hard
    // per-bucket timeout, before serving. A hung or slow provider bucket is marked unhealthy
    // and skipped rather than blocking the whole node, and every other provider, from
    // binding.
    let timeout = Duration::from_secs(
        state
            .config
            .service
            .startup_reconcile_timeout_seconds
            .max(1),
    );
    BucketMonitor::reconcile_all_for_readiness(&monitors, timeout, STARTUP_RECONCILE_CONCURRENCY)
        .await;

    // Then spawn each bucket's independent poll loop, supervised so a panic in the
    // loop restarts it (with backoff) rather than silently stopping that bucket.
    for monitor in monitors {
        spawn_monitor(&monitor, running);
    }
    info!(
        event.action = "s3.monitors.start",
        buckets = s3.buckets.len(),
        "S3 bucket monitors started"
    );
}

/// Whether `bucket` has a credential this reload can resolve.
///
/// The question every monitor-construction path must ask, in one place. Asked on the add
/// path alone, a reload that rebuilt an existing monitor without a resolvable credential
/// would produce an anonymous client, which succeeds silently against a bucket with
/// anonymous GET and LIST.
///
/// `s3_overrides` is the map this reload just re-read from `[vault].s3_path`, so a miss
/// means Vault holds nothing for this bucket rather than that the node is looking at a
/// stale snapshot. Narrow: it applies only when Vault is the credential source.
/// An inline- or env-credentialled deployment is untouched.
#[cfg(feature = "s3")]
fn bucket_credential_is_resolvable(
    bucket: &gdi_node_standalone_core::config::S3Bucket,
    s3_overrides: &S3Overrides,
    vault_supplies_credentials: bool,
) -> bool {
    !vault_supplies_credentials
        || s3_overrides.contains_key(&bucket.name)
        || bucket.access_key_id.is_some()
}

/// Whether rebuilding `bucket`'s monitor would produce an anonymous client — and, if so,
/// say why at WARN and leave the caller to keep the old monitor running.
///
/// Split out so the reload's decision table stays a table: the arm is one line, and the
/// reason lives with the predicate rather than inside the `match`.
#[cfg(feature = "s3")]
fn would_rebuild_anonymous(
    bucket: &gdi_node_standalone_core::config::S3Bucket,
    s3_overrides: &S3Overrides,
    vault_supplies_credentials: bool,
) -> bool {
    if bucket_credential_is_resolvable(bucket, s3_overrides, vault_supplies_credentials) {
        return false;
    }
    warn!(
        channel = %bucket.name,
        "config reload changed this bucket, but [vault].s3_path now holds no credential \
         for it (this reload re-read that path) and the file supplies no inline one. \
         Rebuilding the monitor would poll anonymously, which succeeds silently against a \
         public bucket, so the monitor keeps running on its previous credential. Add \
         {}_access_key_id and {}_secret_access_key under [vault].s3_path and reload again. \
         `vault kv put` replaces the secret, so it must carry every channel's keys, not \
         only the one you are rotating",
        bucket.name,
        bucket.name
    );
    true
}

/// Whether a bucket the reload adds may start a monitor now, warning and returning
/// `false` when it may not.
///
/// Two refusals sharing one shape: a reload that cannot do the thing correctly says so
/// rather than doing a broken version of it, as bucket removal and a keyspace re-point
/// already do. Extracted from [`reload_s3_monitors`] because both cases answer the same
/// question: is this add safe to apply live, or is it restart-only?
#[cfg(feature = "s3")]
fn added_bucket_may_start(
    bucket: &gdi_node_standalone_core::config::S3Bucket,
    configured: &[gdi_node_standalone_core::config::S3Bucket],
    running: &RunningMonitors,
    s3_overrides: &S3Overrides,
    vault_supplies_credentials: bool,
) -> bool {
    // A rename is a removal plus an addition, and removal is restart-only, so the old
    // name's monitor is still polling. Starting this one would put two monitors on one
    // keyspace, the old one unremovable until a restart, both writing `_status/` and
    // counting removals independently.
    //
    // Detected by the keyspace, not the name: an add whose endpoint, bucket and prefix match
    // a still-running channel the reloaded file no longer declares is a rename in progress.
    // Two channels sharing a bucket under different prefixes address distinct keyspaces and
    // still start.
    let renamed_from = running
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .find(|(name, m)| {
            !configured.iter().any(|b| b.name == **name)
                && !m
                    .descriptor
                    .addresses_different_keyspace_than_ignoring_name(bucket)
        })
        .map(|(name, _)| name.clone());
    if let Some(old_name) = renamed_from {
        warn!(
            channel = %bucket.name,
            previous = %old_name,
            "config reload renamed this channel, which is a removal plus an \
             addition, and removal is restart-only, so {old_name}'s monitor is \
             still polling this same keyspace. The new channel is not started, \
             because two monitors on one keyspace race each other's writebacks \
             and the old one cannot be retired until a restart. Restart the node \
             to complete the rename"
        );
        return false;
    }
    // `s3_overrides` here is the map the reload just re-read from `[vault].s3_path` for
    // this config's bucket set, so reaching this branch means Vault holds no credential for
    // this bucket rather than that the node is looking at a stale snapshot. With no inline
    // key either, `build_object_store` would take its both-or-neither anonymous arm and the
    // channel would 403 on every poll.
    //
    // So the add is refused rather than half-applied, for the same reason removal and a
    // keyspace re-point are. Starting the monitor anyway would leave the node permanently
    // `degraded` on a channel that can never succeed, and against a public bucket the
    // anonymous client would succeed, ingesting with no authentication at all.
    //
    // The remedy is not a restart, which re-reads the same Vault path and finds the same
    // nothing. It is to put the credential where the node is already looking and reload
    // again, which onboards the bucket live.
    //
    // Narrow: only when Vault is the credential source, it has no entry for this
    // bucket, and the file supplies none either. An inline- or env-credentialled add is
    // untouched, as is every non-Vault deployment.
    if !bucket_credential_is_resolvable(bucket, s3_overrides, vault_supplies_credentials) {
        warn!(
            channel = %bucket.name,
            "config reload added this [[s3.buckets]] entry, but [vault].s3_path \
             holds no credential for it (this reload re-read that path) and the \
             file supplies no inline one, so starting it would poll anonymously. \
             The channel is not started. Add {}_access_key_id / \
             {}_secret_access_key under [vault].s3_path and reload again; a \
             restart is not needed and would find the same nothing",
            bucket.name,
            bucket.name
        );
        return false;
    }
    true
}

/// The reload-time WARN for a `[[s3.buckets]]` entry the operator just deleted.
#[cfg(feature = "s3")]
fn warn_bucket_removed(channel: &str) {
    warn!(
        channel = %channel,
        "config reload removed this [[s3.buckets]] entry, but bucket removal is \
         restart-only: the monitor keeps running against the old descriptor and its \
         datasets stay served. A restart does not erase them; it stops polling the \
         bucket and puts the channel under the visibility-staleness bound, which \
         withholds its datasets once that bound elapses (and never, if \
         [service].max_visibility_staleness_seconds is 0). To erase them, use \
         `channel take-down` before restarting"
    );
}

/// Apply a reloaded config's `[[s3.buckets]]` to the live monitor set.
///
/// Four cases, and the asymmetry between them is the design:
///
/// * **Added** — start a monitor. Purely additive; nothing existing is disturbed.
/// * **Modified, access or behaviour only** — retire the running monitor and start its
///   replacement. The credentials, `region`, addressing and `write_status` are held by the
///   monitor from boot, so an add-only reload would keep using a rotated credential's stale
///   value until someone restarted the node, silently, since the config on disk would look
///   applied. It is also the safe half: the channel still addresses the same objects, so
///   restarting its monitor evicts nothing.
/// * **Modified identity (`endpoint`, `bucket`, `prefix`, `name`)** — warn loudly and change
///   nothing until restart, as for removal. These decide which objects the channel can see,
///   so applying one live points the monitor at a keyspace that legitimately lists nothing,
///   which the reconcile cannot distinguish from a mass deletion. The restart it defers to
///   is covered by the keyspace-witness gate (`BucketMonitor::removals_authorized`), which
///   refuses removal processing after the re-point until the channel's data is present at
///   the new keyspace or has been erased. See
///   [`S3Bucket::addresses_different_keyspace_than`].
/// * **Removed** — warn loudly and change nothing until restart. A vanished bucket is
///   indistinguishable from a total mass removal and collides with the cross-poll removal
///   confirmation guard, and offboarding is planned and rare, so a restart is proportionate.
///
/// The two restart-only cases are the same hazard reached by different edits, which is why
/// they give the same answer.
///
/// The startup reconcile is not re-run for the readiness barrier here: the node is already
/// serving, so a new bucket must not be able to hold up or 503 a live listener. Its first
/// poll does the same work moments later, and until then the channel is registered and
/// reports unhealthy, which is the honest state.
#[cfg(feature = "s3")]
#[expect(
    clippy::too_many_lines,
    reason = "one match arm per reload change-class; splitting them hides the classification they share"
)]
fn reload_s3_monitors(
    state: &AppState,
    runtime: &IngestRuntime,
    s3_overrides: &S3Overrides,
    running: &RunningMonitors,
    new_config: &ServiceConfig,
) {
    use gdi_node_standalone::s3::BucketMonitor;

    let configured: Vec<_> = new_config
        .s3
        .as_ref()
        .map(|s3| s3.buckets.clone())
        .unwrap_or_default();
    // Whether this deployment expects Vault to supply per-bucket S3 credentials at all. Only
    // then is "no override for this bucket" a diagnosis rather than the ordinary inline
    // path.
    let vault_supplies_credentials = new_config
        .vault
        .as_ref()
        .is_some_and(|v| v.s3_path.as_deref().is_some_and(|p| !p.is_empty()));

    // A bucket the reloaded file no longer declares. Loud, and per bucket: this half of the
    // reload is not applied, so it must not read as an applied change.
    let known: Vec<String> = running
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .keys()
        .cloned()
        .collect();
    for channel in known {
        if !configured.iter().any(|b| b.name == channel) {
            warn_bucket_removed(&channel);
        }
    }

    for bucket in &configured {
        let bucket = apply_bucket_override(bucket, s3_overrides);
        // Take the decision under the lock and act outside it: `spawn_monitor` re-locks to
        // record the replacement, and the guard must not be held across that.
        let existing = running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&bucket.name)
            .map(|m| m.descriptor.clone());
        // Carried across a monitor swap; `None` for an add or a refused arm.
        let mut carried_ingesting: Option<
            Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
        > = None;

        match existing {
            Some(descriptor) if descriptor == bucket => continue,
            // A change to `endpoint`, `bucket` or `prefix` re-points the channel at a
            // different keyspace. Applying that live retires the monitor and starts its
            // replacement against a bucket that legitimately lists nothing, which the
            // reconcile cannot tell from "the provider deleted everything". It would evict
            // every dataset the channel owns and delete it from `data_dir` while
            // `/health/ready` still reported the channel `ok`. That is a prefix migration
            // turning into data destruction.
            //
            // So it joins removal as the restart-only half, for the same reason, and the
            // monitor is left alone: still polling the old keyspace, still serving, until a
            // restart.
            Some(descriptor) if descriptor.addresses_different_keyspace_than(&bucket) => {
                warn!(
                    channel = %bucket.name,
                    "config reload changed this bucket's endpoint, bucket or prefix, which is \
                     the keyspace the channel addresses, and that is restart-only: applying \
                     it live would point the monitor at an empty keyspace, which the \
                     reconcile cannot tell from a mass deletion and would evict every dataset \
                     this channel owns. The monitor keeps running against the previous \
                     descriptor and its datasets stay served. Restart the node to apply the \
                     new one; after the restart the keyspace gate refuses removal processing \
                     (only that) until the channel's datasets are present at the new keyspace \
                     or erased, so the restart cannot become that same mass eviction"
                );
                continue;
            }
            // A modification that leaves the channel with no resolvable credential would
            // rebuild it as an anonymous client, which `added_bucket_may_start` refuses on
            // the add path. That predicate is called from the add arm only, so without this
            // arm the invariant would hold at one of three monitor-construction sites.
            //
            // The way in is the node's own remedy message, which tells the operator to put
            // the credential under `[vault].s3_path` and reload. `vault kv put` replaces a
            // secret rather than patching it, and `s3_overrides_from_kv` omits buckets
            // absent from the result, so one such write drops every other bucket's
            // credential. `S3Bucket`'s `PartialEq` includes credentials, so each of those
            // buckets lands here as a modification. On a private bucket that is loud: 403
            // per poll, bucket unhealthy. On a bucket with anonymous GET and LIST, a common
            // Ceph, Garage and MinIO default, the node would keep listing, downloading and
            // ingesting with no authentication, and the only operator-visible line would
            // read like a successful rotation.
            //
            // So it joins removal and the keyspace re-point as a refused half-application:
            // the monitor is left alone on its old descriptor, still authenticated, still
            // serving.
            Some(_)
                if would_rebuild_anonymous(&bucket, s3_overrides, vault_supplies_credentials) =>
            {
                continue;
            }
            Some(_) => {
                // Retire before building the replacement: the outgoing monitor returns
                // between polls, so at worst the channel is briefly unpolled, never briefly
                // polled by two monitors racing each other's writebacks. Capture the
                // outgoing monitor's in-flight set while retiring it, to hand to the
                // replacement below: its ingest tasks are still running in the shared
                // runtime and prune and record through this same `Arc`.
                carried_ingesting = {
                    let guard = running.lock().unwrap_or_else(PoisonError::into_inner);
                    guard.get(&bucket.name).map(|m| {
                        m.retire.retire();
                        Arc::clone(&m.ingesting)
                    })
                };
                // Nothing polls this channel from here until the replacement's first
                // successful reconcile, so say so. `set_channel_health` is otherwise called
                // only by a monitor, so a channel whose monitor stops would keep its last
                // `true` forever and read ready while half-blind, the shape
                // `register_configured_channels` seeds `false` to avoid at boot. A rotation
                // therefore reads `degraded` for one poll, which is the honest state.
                state.readiness.set_channel_health(&bucket.name, false);
                // Reached only for an access or behaviour change — credentials, region,
                // addressing, poll intervals, `write_status` — so the same objects with a
                // new client. A mistake in any of them fails loudly rather than emptying the
                // listing, so restarting the monitor evicts nothing.
                info!(channel = %bucket.name, "config reload changed this channel's credentials or poll behaviour; restarting its monitor");
            }
            None => {
                if !added_bucket_may_start(
                    &bucket,
                    &configured,
                    running,
                    s3_overrides,
                    vault_supplies_credentials,
                ) {
                    continue;
                }
                // The series a boot-time bucket gets, seeded here for a bucket added live.
                // Without them a bucket whose endpoint is dead from the moment it was added
                // is no data for `S3PollerWedged`, which is the alert condition, and the
                // first error on every `increase(...) > 0` bucket counter is missed: a
                // series born at 1 and left flat yields 0.
                gdi_node_standalone::metrics::seed_s3_channel_series(&[bucket.name.as_str()]);
                gdi_node_standalone::metrics::seed_channel_series(&[bucket.name.as_str()]);
                info!(channel = %bucket.name, "config reload added this channel; starting its monitor");
                state
                    .readiness
                    .register_configured_channels(std::iter::once(bucket.name.as_str()));
                // If this channel was orphaned at boot — datasets on disk, no config entry
                // — it is orphaned no longer, so clear the gauge and let the alert stand
                // down with the condition. The withhold heals by itself: the reloadable
                // snapshot now declares the channel, so the next hydrate's projection serves
                // its datasets again and this monitor's first reconcile re-derives their
                // visibility from the bucket's sidecars. The cache needs no touch here.
                gdi_node_standalone::metrics::s3_channel_orphaned(&bucket.name, false);
            }
        }
        // A replacement `BucketMonitor` built with a fresh per-monitor `ingesting` set
        // would not see an id mid-ingest under the retired monitor, so if that id's
        // `.tar.c4gh` vanished at source in the same window, `apply_removed` would not mark
        // the removal and `on_success` would publish the finished dataset Visible. The
        // retired monitor's set is therefore shared into the replacement — the same `Arc`,
        // not a copy, since the retired monitor's ingest tasks still write to it.
        match BucketMonitor::new(bucket.clone(), state.clone(), runtime.clone()) {
            Ok(mut monitor) => {
                // The replacement adopts the retired monitor's in-flight set, so an id still
                // ingesting across the swap stays visible to `apply_removed` and a package
                // deleted mid-ingest is published Hidden rather than briefly served Visible.
                // Done before `spawn_monitor` clones the monitor, so every clone shares it.
                if let Some(ingesting) = carried_ingesting {
                    monitor.adopt_ingesting(ingesting);
                }
                spawn_monitor(&monitor, running);
            }
            Err(e) => {
                // The old monitor is already retired at this point, so say so plainly: this
                // channel is down until the config is fixed and reloaded again. Silence here
                // would read as a successful restart.
                warn!(
                    channel = %bucket.name,
                    error = %e,
                    "config reload could not build an S3 client for this bucket; the channel \
                     is now stopped (reported unhealthy on /health/ready) until a further \
                     reload or restart fixes it"
                );
                // Make the message above true. The outgoing monitor is retired and no
                // replacement exists, so nothing would write this channel's health again,
                // and the channel would keep its last `ok` forever.
                state.readiness.set_channel_health(&bucket.name, false);
                running
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .remove(&bucket.name);
            }
        }
    }
}

/// Spawn one bucket monitor under supervision and record it in `running`.
///
/// The descriptor recorded is the one the monitor was built from, after any Vault credential
/// override, so a later reload diffs like against like.
#[cfg(feature = "s3")]
fn spawn_monitor(monitor: &gdi_node_standalone::s3::BucketMonitor, running: &RunningMonitors) {
    let channel = monitor.channel().to_owned();
    let retire = monitor.retire_signal();
    running
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(
            channel.clone(),
            RunningMonitor {
                descriptor: monitor.descriptor().clone(),
                retire: Arc::clone(&retire),
                ingesting: monitor.ingesting_handle(),
            },
        );
    let monitor = monitor.clone();
    let stop = Arc::clone(&retire);
    spawn_supervised(
        "s3_monitor",
        channel,
        move || stop.is_retired(),
        move || monitor.clone().run(),
    );
}

/// Apply a Vault S3-credential override to a bucket; Vault takes precedence over the inline
/// credentials. With the `vault` feature compiled this delegates to
/// [`gdi_node_standalone::secrets::apply_s3_override`]; without it the overrides map is
/// always empty, so the bucket is returned unchanged.
#[cfg(all(feature = "s3", feature = "vault"))]
fn apply_bucket_override(
    bucket: &gdi_node_standalone_core::config::S3Bucket,
    overrides: &S3Overrides,
) -> gdi_node_standalone_core::config::S3Bucket {
    gdi_node_standalone::secrets::apply_s3_override(bucket, overrides)
}

/// S3-only build (no Vault): no overrides exist, so return the bucket unchanged.
#[cfg(all(feature = "s3", not(feature = "vault")))]
fn apply_bucket_override(
    bucket: &gdi_node_standalone_core::config::S3Bucket,
    _overrides: &S3Overrides,
) -> gdi_node_standalone_core::config::S3Bucket {
    bucket.clone()
}

/// Spawn the periodic safety-net rescan timer.
fn spawn_rescan_timer(runtime: IngestRuntime, interval_seconds: u64) {
    let interval = Duration::from_secs(interval_seconds.max(1));
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // Skip the immediate first tick (startup scan + hydration already ran).
        ticker.tick().await;
        loop {
            ticker.tick().await;
            // Full reload (cache re-hydrate) plus inbox rescan: the safety net. Guarded so
            // a panicking reload does not kill the last-resort timer.
            guarded("rescan", {
                let r = runtime.clone();
                async move { r.full_reload().await }
            })
            .await;
        }
    });
}

/// Spawn the periodic override-reconcile timer: re-read and re-project both operator
/// override stores (suppressions, node-local metadata overlays) on an interval, via
/// [`AppState::reload_and_enforce_overrides`].
///
/// Spawned by the caller only when no `[service].inbox` is configured; see the call site.
/// On an inbox-configured node this responsibility belongs to [`spawn_rescan_timer`]'s
/// `full_reload`, which does the same reload and enforce for both stores interleaved with
/// its own cache re-hydrate and inbox scan. The two timers are mutually exclusive, so
/// exactly one periodic reload-and-enforce path exists per override store.
///
/// Reuses `[service].rescan_interval_seconds`, the cadence `full_reload` runs on, rather
/// than adding a second interval knob for the same safety net without an inbox to rescan.
fn spawn_override_reconcile_timer(state: AppState, interval_seconds: u64) {
    let interval = Duration::from_secs(interval_seconds.max(1));
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // Skip the immediate first tick: boot already ran `enforce_suppressions` and
        // `enforce_local_overlays` against the inline-loaded stores (see `run`).
        ticker.tick().await;
        loop {
            ticker.tick().await;
            // Guarded so a panicking reload does not kill the timer, as in
            // `spawn_rescan_timer`.
            guarded("override_reconcile", {
                let s = state.clone();
                async move { s.reload_and_enforce_overrides().await }
            })
            .await;
        }
    });
}

/// Run one reconcile pass: reload + enforce the operator suppression store and the
/// node-local overlay overrides, drain queued `dataset reingest` markers, rescan the inbox,
/// and wake every bucket monitor.
///
/// The single implementation behind both triggers, `SIGUSR1` and `POST /reconcile`, for the
/// same reason [`apply_config_reload`] is one function.
///
/// Panic-guarded here rather than at the call sites, so both triggers get the guard. A
/// panicking pass must not kill the operator's self-heal trigger, and the HTTP caller
/// detaches this onto its own task, where an unguarded panic would be doubly invisible.
async fn reconcile_pass(state: AppState, runtime: IngestRuntime, trigger: &'static str) {
    guarded("reconcile_pass", async move {
        // Audited from inside the shared implementation rather than from each trigger's
        // call site, so the signal and HTTP paths cannot drift apart. Emitted before the
        // work rather than after: the record must exist even if a step below fails, since
        // "a reconcile was started" is itself the governance-relevant fact.
        crate::audit::reconcile_requested(&state.config.audit, trigger);
        state.reload_suppressions();
        state.enforce_suppressions().await;
        state.reload_local_overlays();
        state.enforce_local_overlays();
        state.process_reingest_requests().await;
        runtime.scan_once().await;
        state.reconcile_trigger.notify_waiters();
    })
    .await;
}

/// Report catalogs that visible datasets still declare but `[catalogs]` no longer
/// configures, as a warning plus the
/// [`CATALOG_ORPHANED`](gdi_node_standalone::metrics::CATALOG_ORPHANED) gauge. Called at
/// boot and after every applied config reload, the two moments the set can change.
///
/// Reporting only: the datasets keep serving. See `AppState::orphaned_catalogs` for why this
/// is not the catalog analogue of the boot-time channel withhold.
///
/// Every configured catalog is set to `0` on each pass, which stands the alert down when an
/// operator re-adds the entry. The other way an orphan can end — its last visible dataset
/// going away while the catalog stays unconfigured — leaves the gauge at `1` until the next
/// boot, because a gauge keyed on a label set that is absent from the config has nothing to
/// enumerate. That residual errs toward an alert outliving its cause rather than a silent
/// de-listing.
fn report_orphaned_catalogs(state: &AppState) {
    for catalog in state.reloadable().catalogs.keys() {
        gdi_node_standalone::metrics::catalog_orphaned(catalog, false);
    }
    let orphaned = state.orphaned_catalogs();
    if orphaned.is_empty() {
        return;
    }
    let summary: Vec<String> = orphaned
        .iter()
        .map(|(catalog, count)| format!("{catalog} ({count} visible dataset(s))"))
        .collect();
    warn!(
        catalogs = %summary.join(", "),
        "these catalogs are declared by visible datasets but are no longer in [catalogs]: \
         those datasets are still served on both planes, but they have dropped out of the \
         FDP root's ldp:contains, so nothing can reach them by crawling, which is what a \
         FAIR Data Point is for. Re-add the [catalogs] entry to restore discovery. Removing \
         a catalog is not a retraction; use `dataset take-down` if that was the intent"
    );
    for (catalog, _) in &orphaned {
        gdi_node_standalone::metrics::catalog_orphaned(catalog, true);
    }
}

/// Apply one config reload: swap the reloadable subset, then apply the bucket half.
///
/// The single implementation behind both triggers, `SIGHUP` and `POST /reload`. Two copies
/// would drift, and the copy an operator reaches for in an outage would be the one that had
/// diverged.
///
/// Both halves run against one parse of the file: `reload_config_from` hands back the config
/// it just validated, so the monitors can never be reloaded from bytes the reloadable-subset
/// swap rejected, nor from a second, different read of a file that changed in between.
async fn apply_config_reload(
    state: &AppState,
    config_path: &Path,
    s3_reload: &S3ReloadContext,
    trigger: ReloadTrigger,
) -> ReloadOutcome {
    // One reload at a time, across both triggers. `min_interval_seconds` paces HTTP callers
    // against each other and does not touch the signal path, so a `SIGHUP` landing while a
    // `POST /reload` runs could interleave inside `reload_s3_monitors`, which reads, retires
    // and re-inserts in three separate critical sections. Both would see the old descriptor,
    // both would retire, both would build, and the second insert would overwrite the first's
    // `RunningMonitor`, leaving a live monitor nobody holds a `RetireSignal` for: unretirable
    // by any later reload, polling one channel alongside its replacement.
    //
    // A tokio mutex, not a `std` one: this function awaits a Vault read, and holding a
    // `std::sync::MutexGuard` across an `.await` is both non-`Send` and a deadlock risk on a
    // multi-threaded runtime.
    static RELOAD_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _serialised = RELOAD_LOCK.lock().await;

    let outcome = match state.reload_config_from(config_path, trigger) {
        Ok(applied) => {
            let new_config = applied.config;
            // Refresh the Vault S3-credential map for the config just validated, before
            // the monitors are reloaded from it. `[vault].s3_path` is otherwise read once at
            // boot, so a bucket this reload adds would have no credential and be refused.
            // That stays the fallback when Vault is unreachable, but it is a poor default
            // when the credential is one read away.
            s3_reload.refresh_vault_overrides(&new_config).await;
            s3_reload.apply(state, &new_config);
            // Re-evaluate after the swap: `[catalogs]` is part of the reloadable subset, so
            // this reload is when a catalog can be removed out from under datasets that are
            // already visible. It is also the trigger an operator reaches for while editing
            // catalogs, so the warning lands next to the change that caused it.
            report_orphaned_catalogs(state);
            ReloadOutcome::Applied {
                restart_required: applied.restart_required,
            }
        }
        Err(reason) => ReloadOutcome::Rejected(reason),
    };
    // The PME DEK-cache flush, subsumed into `SIGHUP`'s broader "re-read external state".
    // It lives here rather than in the signal loop because `POST /reload` is the same
    // handler, and an operator who cannot `kubectl exec` is the one who needs it: revoking
    // an at-rest key — re-key every PME file, raise the Transit `min_decryption_version` —
    // is applied to this node by dropping every cached plaintext DEK, which bounds the
    // revocation latency to the trigger rather than to the cache TTL.
    //
    // Unconditional, like the signal: a rejected config must not withhold a revocation. The
    // two effects are independent, and both are idempotent.
    #[cfg(feature = "pme")]
    if let Some(pme) = state.pme.as_ref() {
        tracing::info!(trigger = trigger.as_str(), "flushing the PME DEK cache");
        pme.flush_cache();
        // Audit the revocation propagation: the flush applies a Vault-side key revocation to
        // this node, which must be reconstructable from the audit stream, not only the log.
        crate::audit::pme_cache_flushed(&state.config.audit, trigger.as_str());
    } else {
        tracing::info!(
            trigger = trigger.as_str(),
            "PME inactive: no DEK cache to flush (no-op)"
        );
    }
    outcome
}

/// Install the `SIGHUP` handler.
///
/// `SIGHUP` means "re-read external state". It reloads the reloadable config subset
/// (`[catalogs]` and the `[ingest]` writer-key allow-list, via
/// [`AppState::reload_config_from`]) and flushes the PME DEK cache. Both halves live in
/// [`apply_config_reload`], which `POST /reload` also calls, so this handler is one trigger
/// of a shared action rather than an implementation.
///
/// An operator revoking an at-rest key, after re-keying every PME file and raising the
/// Transit `min_decryption_version`, sends `SIGHUP` to drop every cached plaintext DEK at
/// once, bounding the revocation latency to the signal rather than the cache TTL. When PME
/// is inactive there is nothing to flush and that half is a no-op. Both effects are
/// idempotent, so a coalesced signal delivery repeats either safely.
///
/// The signal stream is installed unconditionally on unix: on a build without the `pme`
/// feature, and on a `pme` build whose PME runtime is inactive. Creating the `tokio::signal`
/// stream is what moves `SIGHUP` off its default Unix disposition, which is terminate.
/// Returning early before creating it would leave `kill -HUP` killing the node on the
/// default `lite` build and on any `full` build without `[vault].transit_key`, while
/// docs/operating.md §14 and §10 promise a no-op and §10 tells the operator to send exactly
/// that signal. So the PME check lives inside the receive loop, never before it.
/// `spawn_sigusr1_rescan` and `spawn_sigusr2_log_toggle` are unconditional for the same
/// reason; keep this one so.
fn spawn_sighup_flush(state: &AppState, config_path: &Path, s3_reload: S3ReloadContext) {
    #[cfg(unix)]
    {
        let state_for_reload = state.clone();
        let config_path = config_path.to_path_buf();
        // No separate PME or audit captures: the DEK-cache flush lives in
        // `apply_config_reload`, so this handler holds exactly what that call needs and the
        // two triggers cannot drift in what a reload means.

        tokio::spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            let mut hup = match signal(SignalKind::hangup()) {
                Ok(s) => s,
                Err(e) => {
                    // The disposition stays at the default, so SIGHUP terminates the node.
                    warn!(error = %e, "cannot install SIGHUP handler; SIGHUP will terminate this process");
                    return;
                }
            };
            while hup.recv().await.is_some() {
                info!(
                    event.action = "config.reload.signal",
                    config = %config_path.display(),
                    "SIGHUP received; reloading [catalogs], the [ingest] writer allow-list, \
                     and any added/modified [[s3.buckets]]"
                );
                // Guarded like the SIGUSR1 rescan, so a panic mid-reload cannot kill the
                // operator's reload trigger for good. A bad config file is already handled
                // as an ordinary `Err`; this guards the unexpected.
                guarded("sighup_config_reload", {
                    let state = state_for_reload.clone();
                    let config_path = config_path.clone();
                    let s3_reload = s3_reload.clone();
                    async move {
                        // The shared reload: the same call `POST /reload` makes. One
                        // implementation, two triggers; the signal discards the outcome it
                        // has no way to report.
                        let _outcome = apply_config_reload(
                            &state,
                            &config_path,
                            &s3_reload,
                            ReloadTrigger::Signal,
                        )
                        .await;
                    }
                })
                .await;
            }
        }
        .instrument(info_span!("daemon", task = "sighup")));
    }
    #[cfg(not(unix))]
    {
        let _ = state;
        let _ = config_path;
    }
}

/// Spawn a `SIGUSR2` handler that toggles diagnostic (verbose) logging on/off
/// ([`logging::toggle_verbose`]).
///
/// Lets an operator raise the node's own crates to `debug` to trace a live issue, such as a
/// wedged ingest, then toggle it back without a restart, which would drop in-flight ingests
/// and force a full re-reconcile. A signal rather than an env var, because a running process
/// cannot have its environment changed from outside. A no-op on non-unix.
fn spawn_sigusr2_log_toggle(audit_config: std::sync::Arc<ServiceConfig>) {
    #[cfg(not(unix))]
    let _ = audit_config;
    #[cfg(unix)]
    tokio::spawn(
        async move {
            use tokio::signal::unix::{SignalKind, signal};
            let mut usr2 = match signal(SignalKind::user_defined2()) {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "cannot install SIGUSR2 handler; runtime log-level toggle disabled");
                    return;
                }
            };
            while usr2.recv().await.is_some() {
                match logging::toggle_verbose() {
                    Ok(spec) => {
                        info!(
                            event.action = "log.level.toggle",
                            filter = %spec,
                            "SIGUSR2: toggled diagnostic logging"
                        );
                        crate::audit::log_level_changed(
                            &audit_config.audit,
                            "sigusr2",
                            logging::is_verbose(),
                            &spec,
                        );
                    }
                    Err(e) => {
                        warn!(error = %e, "SIGUSR2: log-level toggle failed; level unchanged");
                    }
                }
            }
        }
        .instrument(info_span!("daemon", task = "sigusr2_log_toggle")),
    );
}

/// Install the process signal handlers: SIGHUP (config reload + PME DEK-cache flush, a
/// no-op flush when PME is inactive), SIGUSR1 (on-demand inbox rescan), and SIGUSR2
/// (runtime diagnostic-log toggle). Grouped so `main` stays small.
///
/// All three are installed on every unix build. A handler that is only conditionally
/// registered leaves its signal at the default disposition — terminate for SIGHUP, SIGUSR1
/// and SIGUSR2 alike — which turns a documented no-op into an outage.
///
/// `config_path` is the resolved boot config path (`ServiceConfig::resolve_path`'s result,
/// the path `run` already loaded from), threaded through so `SIGHUP` re-parses the file the
/// node booted from rather than re-resolving `--config` and `$GDI_CONFIG` precedence, which
/// could have changed independently of the file's content.
fn spawn_signal_handlers(
    state: &AppState,
    runtime: &IngestRuntime,
    config_path: &Path,
    s3_reload: S3ReloadContext,
) {
    spawn_sighup_flush(state, config_path, s3_reload);
    spawn_sigusr1_rescan(state, runtime);
    spawn_sigusr2_log_toggle(std::sync::Arc::clone(&state.config));
}

/// Spawn a SIGUSR1 handler that reloads operator suppressions + metadata-overlay
/// overrides and runs an on-demand reconcile of every ingestion path.
///
/// Lets an operator force an immediate self-heal after a corrective fix — a fresh
/// `suppressions/*.json` or `overlays/*.json` override, or a restored package — instead of
/// waiting out `rescan_interval` or the S3 poll interval, or restarting. On each SIGUSR1
/// the node, in order:
/// 1. re-reads the suppression store ([`AppState::reload_suppressions`]);
/// 2. enforces it ([`AppState::enforce_suppressions`]) — force every Hide/Remove-suppressed
///    dataset Hidden immediately, then erase every `Remove` id (evict + purge +
///    `rm data_dir/{id}`);
/// 3. re-reads the node-local metadata-overlay override store
///    ([`AppState::reload_local_overlays`]) and applies it
///    ([`AppState::enforce_local_overlays`]) through the existing overlay engine, before
///    the reconcile below, so its precedence check (operator over source) sees the fresh
///    override set;
/// 4. processes every pending reingest-request marker
///    ([`AppState::process_reingest_requests`]), the targeted bucket retry: it clears
///    `last_seen_signature` for each id whose marker carries a stamp this process has not
///    acted on, so the S3 reconcile's same-ETag short-circuit no longer pins it. The marker
///    is kept, so every node reading the store sees the same request;
/// 5. runs the inbox rescan ([`IngestRuntime::scan_once`]) — whose ingest gate refuses to
///    re-ingest a still-present suppressed package (so a `Remove` erase is not undone),
///    and whose overlay reconcile skips any id with a node-local override;
/// 6. wakes every S3 bucket monitor to reconcile now ([`AppState::reconcile_trigger`]), so
///    the same gate / lift-restore / overlay precedence / unpinned reingest reaches
///    S3-owned datasets without a poll-interval wait.
///
/// Every step is idempotent and a no-op on a node with no inbox, no buckets or no
/// overrides, so this is a safe blanket trigger that takes no dataset id. It is not a per-id
/// re-ingest endpoint: `dataset reingest <id>`'s targeted bucket path is queued via the
/// marker step 4 processes, not driven directly by this handler.
fn spawn_sigusr1_rescan(state: &AppState, runtime: &IngestRuntime) {
    #[cfg(unix)]
    {
        let state = state.clone();
        let runtime = runtime.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            let mut usr1 = match signal(SignalKind::user_defined1()) {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "cannot install SIGUSR1 handler; on-demand rescan disabled");
                    return;
                }
            };
            while usr1.recv().await.is_some() {
                info!(
                    event.action = "reconcile.signal",
                    "SIGUSR1 received; reloading operator suppressions/metadata overrides and \
                     running an on-demand reconcile"
                );
                // Guarded like the inbox watcher and rescan timer, so a panicking pass does
                // not kill the operator's on-demand self-heal trigger. The shared pass: the
                // same one `POST /reconcile` runs.
                reconcile_pass(state.clone(), runtime.clone(), "sigusr1").await;
            }
        }
        .instrument(info_span!("daemon", task = "sigusr1_rescan")));
    }
    #[cfg(not(unix))]
    {
        let _ = state;
        let _ = runtime;
    }
}

/// The process shutdown signal — SIGTERM or SIGINT (Ctrl-C) — as a future to await.
///
/// Not an `async fn`. `tokio::signal::unix::signal` registers the OS handler when it is
/// called, while an `async fn`'s body does not run until the future it returns is first
/// polled. Registering from inside the future would leave the process running with SIGTERM's
/// default disposition for the whole stretch before the serve loop's first poll — both
/// binds, the store self-test, the ingest runtime and S3 monitor start, the initial
/// reconcile gate — and a signal arriving there kills the process outright: exit 143, no
/// drain, no `service.stopped`, in-flight requests cut. Called from [`run`] after the secret
/// load and the disk cache hydrate but before any listener binds, the `Signal`s exist from
/// that point on and tokio buffers a delivery until the future is polled, so a SIGTERM at
/// any later moment reaches the bounded drain.
///
/// A SIGTERM that arrives after arming but before the serve loop starts is honoured as soon
/// as it does: the node finishes booting and drains immediately. It does not cut startup
/// short.
///
/// Earlier than the arming line — config and secret load, the disk cache re-hydrate — a
/// signal keeps its default disposition and the process dies at once. That is correct for
/// those phases, since nothing is served yet and the store is crash-safe, and it is required
/// by the offline `verify` subcommand, which returns before the call site and must stay
/// Ctrl-C-killable: arming ahead of it would install a handler nothing awaits.
///
/// The future is `Send + 'static` so `run` can create it once, ahead of the binds, and
/// thread it through [`serve_public_then_stop_management`] into [`serve_bounded`].
fn shutdown_signal() -> impl std::future::Future<Output = ()> + Send + 'static {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        // Both handlers are installed here, by this call, not by the returned future.
        let term = signal(SignalKind::terminate());
        let int = signal(SignalKind::interrupt());
        async move {
            match (term, int) {
                (Ok(mut term), Ok(mut int)) => {
                    tokio::select! {
                        _ = term.recv() => {}
                        _ = int.recv() => {}
                    }
                }
                // One of the two could not be installed: wait on the other rather than lose
                // shutdown handling entirely. The two cases are separate arms so the message
                // names which signal is still armed and which is left at the kernel's
                // default disposition. Otherwise an operator cannot tell whether Ctrl-C or a
                // SIGTERM is the one that will now kill the node ungracefully.
                (Ok(mut term), Err(e)) => {
                    warn!(error = %e, armed = "SIGTERM", failed = "SIGINT", "cannot install one of the shutdown signal handlers; waiting on the other only");
                    term.recv().await;
                }
                (Err(e), Ok(mut int)) => {
                    warn!(error = %e, armed = "SIGINT", failed = "SIGTERM", "cannot install one of the shutdown signal handlers; waiting on the other only");
                    int.recv().await;
                }
                // Neither could be installed. `tokio::signal::ctrl_c()` is not a fallback:
                // on unix it is `signal(SignalKind::interrupt())`, the call that just
                // failed, so it fails again and, with its error discarded, resolves
                // immediately — draining a healthy node the moment it starts serving.
                // Waiting forever is the honest answer: nothing installed a handler, so both
                // signals keep their default disposition and still terminate the process
                // ungracefully with exit 143, as does SIGKILL. Both errors are logged
                // because the two calls can fail for different reasons.
                (Err(term_error), Err(int_error)) => {
                    warn!(
                        sigterm_error = %term_error,
                        sigint_error = %int_error,
                        "cannot install the SIGTERM or SIGINT handler; this process cannot shut down gracefully on a signal; a SIGTERM will terminate it outright, without draining"
                    );
                    std::future::pending::<()>().await;
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        async {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The supervisor stops restarting a task once it is retired.
    ///
    /// This is the half of the retirement handshake the monitor cannot assert about itself.
    /// Wrong in one direction, a retired monitor is restarted at once: two monitors on one
    /// channel after every bucket edit, the older one polling a superseded descriptor. Wrong
    /// in the other, the supervisor hot-spins on a task that returns immediately, which the
    /// 1 s backoff exists to bound.
    ///
    /// Asserted by counting invocations rather than by watching for a stop, because "has not
    /// restarted yet" and "will never restart" look identical at any single instant.
    #[cfg(feature = "s3")]
    #[tokio::test]
    async fn a_retired_task_is_not_restarted() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let runs = Arc::new(AtomicUsize::new(0));
        let retired = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let (runs_for_task, retired_for_task) = (Arc::clone(&runs), Arc::clone(&retired));
        let retired_for_stop = Arc::clone(&retired);
        spawn_supervised(
            "test_task",
            "one".to_owned(),
            move || retired_for_stop.load(Ordering::SeqCst),
            move || {
                // Returns immediately — the shape a retiring monitor takes, and the shape
                // that hot-spins a supervisor that does not know to stop.
                let runs = Arc::clone(&runs_for_task);
                let retired = Arc::clone(&retired_for_task);
                async move {
                    runs.fetch_add(1, Ordering::SeqCst);
                    // Retire from inside the first run, so the supervisor meets the flag on
                    // the `Ok(())` arm rather than at the top of its loop — the path a real
                    // reload takes, since retirement lands while the monitor is running.
                    retired.store(true, Ordering::SeqCst);
                }
            },
        );

        // Comfortably longer than the supervisor's 1 s restart backoff: had it restarted,
        // the count would have advanced by now.
        tokio::time::sleep(Duration::from_millis(2_500)).await;
        assert_eq!(
            runs.load(Ordering::SeqCst),
            1,
            "a retired task must run exactly once and never be restarted"
        );
    }

    /// The control: a task nobody retired, returning, is still restarted.
    ///
    /// Without it, the test above is satisfied by a supervisor that never restarts anything,
    /// which would turn every panicking bucket monitor into a dead channel.
    #[cfg(feature = "s3")]
    #[tokio::test]
    async fn an_unretired_task_that_returns_is_restarted() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let runs = Arc::new(AtomicUsize::new(0));
        let runs_for_task = Arc::clone(&runs);
        spawn_supervised(
            "test_task",
            "two".to_owned(),
            || false,
            move || {
                let runs = Arc::clone(&runs_for_task);
                async move {
                    runs.fetch_add(1, Ordering::SeqCst);
                }
            },
        );

        tokio::time::sleep(Duration::from_millis(2_500)).await;
        assert!(
            runs.load(Ordering::SeqCst) > 1,
            "a task that returns without being retired must be restarted after backoff"
        );
    }

    /// The service and the tool must report the same provenance.
    ///
    /// `gdi_build_info` holds the constants in one place, but not the rendering: the tool calls
    /// [`gdi_build_info::version_provenance`] while the service renders its own line so it
    /// can carry `gdi_metadata_version`. Nothing else holds the two together, so change the
    /// helper's shape and this line would not follow. Bind the substance rather than the
    /// exact format: both must carry the same `git …` and `build_epoch …` fragments.
    #[test]
    fn the_service_version_line_carries_the_same_provenance_as_the_tool() {
        let service = version_line();
        let tool = gdi_build_info::version_provenance(env!("CARGO_PKG_VERSION"));

        for fragment in [
            format!("git {}", gdi_build_info::GIT_SHA),
            format!("build_epoch {}", gdi_build_info::BUILD_EPOCH),
        ] {
            assert!(
                service.contains(&fragment),
                "the service line dropped `{fragment}`; got: {service}"
            );
            assert!(
                tool.contains(&fragment),
                "the tool line dropped `{fragment}`; got: {tool}"
            );
        }

        // The service prepends its own name (it does not go through clap's `version`),
        // so unlike the tool's value this one is expected to carry it.
        assert!(
            service.starts_with(concat!(env!("CARGO_PKG_NAME"), " ")),
            "got: {service}"
        );
        assert!(
            service.contains(GDI_METADATA_VERSION),
            "the service line must carry gdi_metadata_version; got: {service}"
        );
    }

    /// The lock-free command set the docs promise must be the one `run` dispatches.
    ///
    /// "Lock-free" is an operational promise — safe to run while the node is serving — made
    /// in two prose locations (`Cli`'s `long_about`, printed by `--help`, and
    /// `docs/operating.md` §0b) and implemented in one (`run_lockfree_command`). Without
    /// this, the three drift: an operator reading `--help` would stop a healthy node to take
    /// an override backup.
    ///
    /// `run_lockfree_command`'s exhaustive match already forces a new command to be placed
    /// explicitly in code. This pins that placement against what the operator is told. It
    /// asserts the exact set both ways, so prose that merely mentions a group cannot satisfy
    /// it, and a group moved between the arms fails here.
    #[test]
    fn documented_lock_free_groups_are_exactly_the_ones_dispatched_lock_free() {
        use clap::CommandFactory as _;

        // One instance per top-level `Command` variant. Constructing them, rather than
        // enumerating clap's subcommand names, is what makes this the real dispatch
        // question: it calls the function `run` calls, on the values `run` passes.
        let every_command = [
            Command::Serve,
            Command::CheckConfig,
            Command::Healthcheck,
            Command::Version,
            Command::Doctor(DoctorArgs {
                format: gdi_node_standalone::list_datasets::OutputFormat::Text,
                strict: false,
            }),
            Command::Verify(VerifyArgs {
                full: false,
                digest: false,
                concurrency: 0,
            }),
            Command::Dataset(DatasetCommand::Show(DatasetShowArgs {
                id: "GDI-EE-UTARTU-20260409143052837".to_owned(),
                reason: "r".to_owned(),
            })),
            Command::Channel(ChannelCommand::Show(ChannelShowArgs {
                name: "inbox".to_owned(),
                reason: "r".to_owned(),
            })),
            Command::Overrides(OverridesCommand::Export(OverridesExportArgs {
                output: None,
            })),
            Command::Identity(IdentityCommand::List),
            Command::Config(ConfigCommand::DumpDefaults),
            Command::Pme(PmeCommand::Reseal(ResealArgs { yes: false })),
        ];

        // The config is irrelevant to the routing question, but `run_lockfree_command` runs
        // the verb it selects, so use a throwaway data dir rather than a real one.
        let tmp = tempfile::tempdir().expect("tempdir");
        let toml = format!(
            "[service]\nbase_url=\"https://n.example.org/\"\ndata_dir=\"{}\"\n\
             [catalogs]\ngdi-aggregated=\"GoE\"\n\
             [beacon]\nid=\"o.n\"\nname=\"N\"\nenvironment=\"test\"\n",
            tmp.path().display()
        );
        let config = ServiceConfig::from_toml_str(&toml).expect("config parses");

        let dispatched: std::collections::BTreeSet<&str> = every_command
            .iter()
            .filter(|c| run_lockfree_command(c, &config).is_some())
            .map(group_name)
            .collect();

        let long_about = Cli::command()
            .get_long_about()
            .map(ToString::to_string)
            .expect("Cli carries a long_about");
        let runbook = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/operating.md"),
        )
        .expect("docs/operating.md is readable");

        for (source, text) in [
            ("--help long_about", lock_free_claim(&long_about)),
            ("docs/operating.md §0b", lock_free_claim(&runbook)),
        ] {
            assert!(
                text.contains("lock") || !text.is_empty(),
                "{source} no longer states a lock-free set — this guard would pass vacuously"
            );
            let claimed: std::collections::BTreeSet<&str> = ALL_GROUPS
                .iter()
                .copied()
                .filter(|group| text.contains(&format!("`{group}`")))
                .collect();
            assert_eq!(
                claimed, dispatched,
                "{source} names lock-free groups {claimed:?}, but `run_lockfree_command` \
                 dispatches {dispatched:?} lock-free. Update whichever is wrong — this promise \
                 is what tells an operator they need not stop the node."
            );
        }
    }

    /// The claim sentence a prose source uses to state the lock-free set: everything from
    /// the preceding paragraph break up to the phrase "lock-free".
    ///
    /// Extracting rather than scanning the whole document matters: both sources go on to
    /// name `verify` and the `identity` group as the offline ones in the next sentence, and
    /// a whole-text scan would count those as lock-free claims.
    fn lock_free_claim(text: &str) -> String {
        let head = text
            .split("lock-free")
            .next()
            .expect("split always yields a first element");
        head.rsplit_once("\n\n")
            .map_or_else(|| head.to_owned(), |(_, claim)| claim.to_owned())
    }

    /// Every top-level command group name, as spelled on the CLI. The vocabulary the
    /// lock-free seam matches prose against.
    const ALL_GROUPS: &[&str] = &[
        "serve",
        "check-config",
        "healthcheck",
        "version",
        "doctor",
        "verify",
        "dataset",
        "channel",
        "overrides",
        "identity",
        "config",
        "pme",
    ];

    /// The CLI spelling of a command's top-level group.
    const fn group_name(command: &Command) -> &'static str {
        match command {
            Command::Serve => "serve",
            Command::CheckConfig => "check-config",
            Command::Healthcheck => "healthcheck",
            Command::Version => "version",
            Command::Doctor(_) => "doctor",
            Command::Verify(_) => "verify",
            Command::Dataset(_) => "dataset",
            Command::Channel(_) => "channel",
            Command::Overrides(_) => "overrides",
            Command::Identity(_) => "identity",
            Command::Config(_) => "config",
            Command::Pme(_) => "pme",
        }
    }

    /// `--reason` is mandatory on the governance verbs because a withhold or a re-exposure
    /// needs a justification, and an empty or whitespace value is none. Walks every
    /// subcommand that carries a `--reason`, so a verb added later is covered without being
    /// listed here, and asserts clap refuses `""` and whitespace for it.
    #[test]
    fn every_reason_flag_rejects_an_empty_justification() {
        use clap::CommandFactory as _;
        use clap::Parser as _;

        fn walk(cmd: &clap::Command, path: &[String], out: &mut Vec<(Vec<String>, usize)>) {
            if cmd.get_arguments().any(|a| a.get_long() == Some("reason")) {
                out.push((path.to_vec(), cmd.get_positionals().count()));
            }
            for sub in cmd.get_subcommands() {
                let mut child = path.to_vec();
                child.push(sub.get_name().to_owned());
                walk(sub, &child, out);
            }
        }
        let mut verbs = Vec::new();
        walk(&Cli::command(), &[], &mut verbs);
        assert!(
            verbs.len() >= 7,
            "only {} verbs carry --reason (expected >= 7) — the walk has stopped seeing the CLI",
            verbs.len()
        );

        for (path, positionals) in &verbs {
            let argv = |reason: &str| -> Vec<String> {
                let mut argv = vec!["gdi-node-standalone".to_owned()];
                argv.extend(path.iter().cloned());
                argv.extend(std::iter::repeat_n(
                    "GDI-EE-UTARTU-20260409143052837".to_owned(),
                    *positionals,
                ));
                argv.push("--reason".to_owned());
                argv.push(reason.to_owned());
                argv
            };
            for blank in ["", "   ", "\t"] {
                let err = Cli::try_parse_from(argv(blank)).err().unwrap_or_else(|| {
                    panic!("{} --reason {blank:?} must be refused", path.join(" "))
                });
                let msg = err.to_string();
                assert!(
                    err.kind() == clap::error::ErrorKind::ValueValidation
                        && msg.contains("reason")
                        && msg.contains("empty"),
                    "{}: the refusal must be the value parser's, naming the flag and the \
                     cause: {msg}",
                    path.join(" ")
                );
            }
            // A real justification is not what the parser refuses: other requirements of
            // the verb may still fail the parse (`correct` needs a mode), but never as a
            // value-validation error.
            if let Err(err) = Cli::try_parse_from(argv("TICKET-123")) {
                assert_ne!(
                    err.kind(),
                    clap::error::ErrorKind::ValueValidation,
                    "{}: a non-empty --reason must be accepted: {err}",
                    path.join(" ")
                );
            }
        }
    }

    /// Every flag the node accepts must appear in the operator runbook.
    ///
    /// The sibling of `gdi-dataset-tool`'s `cli_docs` guard. Ground truth is `clap` itself
    /// via [`CommandFactory`], not a regex over `#[arg(...)]`: a regex misses
    /// `visible_alias` and mis-attributes flattened args.
    ///
    /// Lives in `main.rs` because `Cli` is defined in the binary, not the library, so an
    /// integration test cannot construct it.
    #[test]
    fn every_node_flag_appears_in_the_operator_runbook() {
        use clap::CommandFactory as _;

        fn walk(cmd: &clap::Command, path: &str, out: &mut Vec<(String, String)>) {
            for arg in cmd.get_arguments() {
                if arg.is_hide_set() {
                    continue;
                }
                if let Some(long) = arg.get_long() {
                    // clap synthesises these; no doc lists them as flags.
                    if long != "help" && long != "version" {
                        out.push((path.to_owned(), long.to_owned()));
                    }
                }
            }
            for sub in cmd.get_subcommands() {
                if sub.is_hide_set() {
                    continue;
                }
                let child = if path.is_empty() {
                    sub.get_name().to_owned()
                } else {
                    format!("{path} {}", sub.get_name())
                };
                walk(sub, &child, out);
            }
        }

        /// `doc` mentions `--flag` as a whole word — `--out` must not be satisfied by
        /// `--output`.
        fn mentions(doc: &str, flag: &str) -> bool {
            let needle = format!("--{flag}");
            doc.match_indices(&needle).any(|(i, _)| {
                doc[i + needle.len()..]
                    .chars()
                    .next()
                    .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
            })
        }

        let doc = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/operating.md"
        ))
        .expect("read docs/operating.md");

        let mut flags = Vec::new();
        walk(&Cli::command(), "", &mut flags);

        let missing: Vec<String> = flags
            .iter()
            .filter(|(_, long)| !mentions(&doc, long))
            .map(|(path, long)| {
                if path.is_empty() {
                    format!("--{long} (global)")
                } else {
                    format!("{path} --{long}")
                }
            })
            .collect();

        // A ratchet, not a floor of one: lower it only alongside an intentional removal.
        assert!(
            flags.len() >= 25,
            "only {} visible long flags found (expected >= 25): the walk has stopped seeing \
             most of the CLI, so this guard is checking almost nothing.",
            flags.len()
        );
        assert!(
            missing.is_empty(),
            "these node flags exist but docs/operating.md never mentions them:\n  {}\n\n\
             That runbook is the operator's reference for this binary. Document the flag \
             there, or hide it.",
            missing.join("\n  ")
        );
    }

    #[test]
    fn registration_urls_combined_beacon_with_fairdp() {
        // Default (aggregated == sensitive) collapses to one beacon URL; a trailing
        // slash on base_url is stripped so the joined URL never doubles the `/`.
        let urls = registration_urls("https://n.example.org/", "/beacon/v2", "/beacon/v2", true);
        assert_eq!(
            urls,
            vec![
                (
                    "beacon (aggregated + sensitive)",
                    "https://n.example.org/beacon/v2".to_owned()
                ),
                ("fairdp", "https://n.example.org/fairdp".to_owned()),
            ]
        );
    }

    #[test]
    fn registration_urls_split_beacon_without_fairdp() {
        // Distinct mounts yield two beacon URLs; no `[fairdp]` yields no FDP URL.
        let urls = registration_urls(
            "https://n.example.org",
            "/beacon/agg",
            "/beacon/sens",
            false,
        );
        assert_eq!(
            urls,
            vec![
                (
                    "beacon (aggregated)",
                    "https://n.example.org/beacon/agg".to_owned()
                ),
                (
                    "beacon (sensitive)",
                    "https://n.example.org/beacon/sens".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn data_dir_lock_is_exclusive_and_releases_on_drop() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // The first acquisition succeeds and holds the lock for as long as the File lives.
        let held = acquire_data_dir_lock(tmp.path()).expect("first acquire succeeds");
        // A second writer on the same data_dir fails fast: `flock` is per-open-description,
        // so even a same-process second open is denied while the first handle holds it.
        let err = acquire_data_dir_lock(tmp.path()).expect_err("second acquire is refused");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("already holds the data-dir lock"),
            "the refusal must name the single-writer reason: {msg}"
        );
        // Releasing the holder makes the lock re-acquirable.
        drop(held);
        acquire_data_dir_lock(tmp.path()).expect("re-acquire after release");
    }

    #[cfg(unix)]
    #[test]
    fn data_dir_tightening_skips_an_already_owner_only_dir_and_tightens_a_loose_one() {
        use std::os::unix::fs::PermissionsExt as _;
        // The decision: only a group/other-accessible dir needs tightening.
        assert!(
            !data_dir_needs_tightening(0o700),
            "already owner-only: skip"
        );
        assert!(!data_dir_needs_tightening(0o600), "stricter: skip");
        assert!(
            data_dir_needs_tightening(0o755),
            "group/other-readable: tighten"
        );
        assert!(data_dir_needs_tightening(0o777), "world-writable: tighten");

        // A loose dir this process owns is tightened to 0o700.
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o755))
            .expect("chmod");
        tighten_data_dir_root(tmp.path()).expect("owned loose dir tightens");
        assert_eq!(
            std::fs::metadata(tmp.path())
                .expect("stat")
                .permissions()
                .mode()
                & 0o777,
            0o700,
            "a loose owned data dir must be tightened to 0o700"
        );

        // An already-0o700 dir this process owns is left as is, with no chmod attempted.
        // Ownership is the other half of that path; the tests below assert it.
        let tmp2 = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(tmp2.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod");
        tighten_data_dir_root(tmp2.path()).expect("owned already-tight dir is a no-op");
    }

    /// The refusal half of the skip path, exercised as a pure decision: building a
    /// foreign-owned directory needs `chown`, so the uids are supplied directly here and
    /// injected into the real `tighten_data_dir_root_as` further down. Both run anywhere,
    /// with neither gated on privileges the runner may not have.
    #[cfg(unix)]
    #[test]
    fn an_owner_only_data_dir_owned_by_another_uid_is_refused_by_name() {
        let dir = Path::new("/mnt/gdi-data");
        check_data_dir_owner(dir, 65532, 65532).expect("the running uid owns it — accepted");
        let err = check_data_dir_owner(dir, 0, 65532)
            .expect_err("a root-owned 0o700 dir under a non-root node must be refused");
        let msg = format!("{err:#}");
        for needle in [
            "owned by uid 0",
            "runs as uid 65532",
            "/mnt/gdi-data",
            "chown",
            "named volume",
            "fsGroup",
        ] {
            assert!(
                msg.contains(needle),
                "the refusal must name `{needle}` so the operator knows whose dir it is and \
                 what to do: {msg}"
            );
        }
    }

    /// Root is exempt from the ownership refusal: it bypasses the kernel's DAC checks, so a
    /// dir it does not own is still readable and writable, and the refusal's remedy — chown
    /// the volume to uid 0 — would break the unprivileged node the shipped image runs as.
    /// Non-vacuous whoever runs it: the two uids differ, so only the exemption makes it
    /// `Ok`.
    #[cfg(unix)]
    #[test]
    fn a_root_node_is_exempt_from_the_data_dir_ownership_refusal() {
        let dir = Path::new("/mnt/gdi-data");
        check_data_dir_owner(dir, 65532, 0)
            .expect("root bypasses DAC, so a dir it does not own is still usable");
    }

    /// `effective_uid` is the subject of that refusal, so a version that always returned
    /// `None`, or read the wrong field of the `Uid:` line, would delete every refusal while
    /// both arms above still passed. Bind it to the filesystem's own answer: a directory
    /// this process just created is owned by its effective uid.
    #[cfg(unix)]
    #[test]
    fn effective_uid_matches_the_owner_of_a_directory_this_process_creates() {
        use std::os::unix::fs::MetadataExt as _;
        let tmp = tempfile::tempdir().expect("tempdir");
        let owner = std::fs::metadata(tmp.path()).expect("stat").uid();
        assert_eq!(
            effective_uid(),
            Some(owner),
            "a directory this process just created is owned by its effective uid — if these \
             disagree, the data-dir ownership check is judging the wrong uid"
        );
    }

    /// End-to-end over a real directory: the wiring, not only the decision function. A
    /// foreign-owned `0o700` dir cannot be built without `chown`, so the euid is injected
    /// instead: the same path, and it runs anywhere. Asserts all four arms of the
    /// already-owner-only branch — the owner boots, root boots, an unknown euid does not
    /// invent a refusal, and a stranger is refused.
    #[cfg(unix)]
    #[test]
    fn tighten_refuses_an_owner_only_data_dir_this_uid_does_not_own() {
        use std::os::unix::fs::MetadataExt as _;
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod 0700");
        let owner = std::fs::metadata(tmp.path()).expect("stat").uid();

        tighten_data_dir_root_as(tmp.path(), Some(owner)).expect("the owner's own dir boots");
        tighten_data_dir_root_as(tmp.path(), None)
            .expect("an undeterminable euid must not invent a refusal");
        tighten_data_dir_root_as(tmp.path(), Some(0))
            .expect("root is exempt — it bypasses DAC on a dir it does not own");

        let stranger = owner.wrapping_add(1);
        let err = tighten_data_dir_root_as(tmp.path(), Some(stranger))
            .expect_err("an owner-only data dir this uid does not own must be refused at boot");
        let msg = format!("{err:#}");
        assert!(
            msg.contains(&format!("owned by uid {owner}"))
                && msg.contains(&format!("runs as uid {stranger}")),
            "the refusal must name both uids: {msg}"
        );
    }

    #[test]
    fn verify_lock_failure_names_the_stop_the_node_fix() {
        // On a running node `verify` fails on this lock with empty stdout, and a naive
        // pipeline reads that as "0 FAILs, all healthy". The verify-cased error must name
        // the fix, so a manual run is actionable and never mistaken for a clean bill.
        let base =
            anyhow::anyhow!("another gdi-node-standalone process already holds the data-dir lock");

        let verify_err = format!("{:#}", contextualize_lock_error(base, true));
        assert!(
            verify_err.contains("Stop the node") && verify_err.contains("verified nothing"),
            "verify's lock failure must name the fix and warn the empty result is not health: \
             {verify_err}"
        );

        // A non-verify command (serve) keeps the plain single-writer message.
        let serve_err = format!(
            "{:#}",
            contextualize_lock_error(
                anyhow::anyhow!(
                    "another gdi-node-standalone process already holds the data-dir lock"
                ),
                false,
            )
        );
        assert!(
            !serve_err.contains("verified nothing"),
            "a non-verify lock failure must not carry the verify hint: {serve_err}"
        );
    }

    /// Spawn a one-shot blocking loopback listener (a real OS thread, so the blocking
    /// probe and the server make progress independently) that reads a request then
    /// writes `response`, returning the bound port. Stands in for the management plane.
    fn stub_listener(response: &'static [u8]) -> u16 {
        stub_listener_on("127.0.0.1", response).expect("bind loopback")
    }

    /// As [`stub_listener`], but binds an explicit loopback (`"127.0.0.1"` / `"::1"`),
    /// returning `None` when that family cannot be bound (e.g. a sandbox without an
    /// IPv6 loopback) so the caller can skip rather than fail.
    fn stub_listener_on(bind: &str, response: &'static [u8]) -> Option<u16> {
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind((bind, 0)).ok()?;
        let port = listener.local_addr().expect("local addr").port();
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 256];
                let _ = sock.read(&mut buf);
                let _ = sock.write_all(response);
            }
        });
        Some(port)
    }

    #[test]
    fn healthcheck_probe_ok_on_200() {
        let port = stub_listener(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        health_probe_ready(&format!("127.0.0.1:{port}")).expect("200 maps to ready");
    }

    #[test]
    fn healthcheck_probe_errors_on_503() {
        let port = stub_listener(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n");
        assert!(
            health_probe_ready(&format!("127.0.0.1:{port}")).is_err(),
            "503 maps to not-ready"
        );
    }

    /// An IPv6 management bind (`[::1]`) is probed on the IPv6 loopback `::1`, not
    /// IPv4 `127.0.0.1`. Skips on hosts without an IPv6 loopback (some minimal CI
    /// sandboxes), where the stub listener cannot be bound at all.
    #[test]
    fn healthcheck_probe_reaches_ipv6_loopback_bind() {
        let Some(port) = stub_listener_on("::1", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        else {
            eprintln!("skipping healthcheck_probe_reaches_ipv6_loopback_bind: no IPv6 loopback");
            return;
        };
        health_probe_ready(&format!("[::1]:{port}")).expect("an IPv6 bind must be probed on ::1");
    }

    /// For an IPv6 wildcard bind whose `::1` loopback is unreachable, the probe falls
    /// back to the IPv4 loopback rather than reporting unhealthy — so a dual-stack
    /// (IPv4-mapped) listener still passes. Runs on IPv4-only hosts.
    #[test]
    fn healthcheck_probe_falls_back_to_ipv4_loopback() {
        let port = stub_listener(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        // `[::]` orders `::1` first; with no IPv6 listener the probe must fall back
        // to `127.0.0.1`, where the stub is listening.
        health_probe_ready(&format!("[::]:{port}"))
            .expect("must fall back to the IPv4 loopback when ::1 is unreachable");
    }

    /// Loopback probe order follows the bind's address family: an IPv6 bind
    /// (`[::]`/`[::1]`) tries `::1` first, an IPv4 / wildcard / hostname bind tries
    /// `127.0.0.1` first; each keeps the other family as a fallback.
    #[test]
    fn loopback_candidates_orders_by_family() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        let v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);

        assert_eq!(loopback_candidates("0.0.0.0:9090"), [v4, v6]);
        assert_eq!(loopback_candidates("127.0.0.1:9090"), [v4, v6]);
        assert_eq!(loopback_candidates("localhost:9090"), [v4, v6]);
        assert_eq!(loopback_candidates("[::]:9090"), [v6, v4]);
        assert_eq!(loopback_candidates("[::1]:9090"), [v6, v4]);
    }

    /// The management listener bind is a hard startup requirement: a free address binds, but
    /// an address already in use yields a contextual `Err`, which `serve_management`
    /// propagates to abort startup, rather than a swallowed log line.
    #[tokio::test]
    async fn management_bind_failure_is_propagated() {
        let held = bind_management_listener("127.0.0.1:0")
            .await
            .expect("a free port binds");
        let addr = held.local_addr().expect("bound addr").to_string();

        let err = bind_management_listener(&addr)
            .await
            .expect_err("binding an in-use management address must fail, not be swallowed");
        assert!(
            err.to_string().contains("management listener"),
            "the error must name the management listener: {err}"
        );
        // A bare `Address already in use` leaves a first-run operator with nothing to do.
        // The message must name both the knob to turn and how to find the squatter.
        let msg = err.to_string();
        assert!(
            msg.contains("[service].management_addr"),
            "EADDRINUSE must name the config key to retune: {err}"
        );
        assert!(
            msg.contains("ss -ltnp"),
            "EADDRINUSE must say how to find the process holding the port: {err}"
        );
    }

    /// The smoke-test curl must be built from the configured mount, never a hardcoded one.
    ///
    /// The default is `/aggregated/beacon/v2`, the Compose stacks override both mounts to
    /// `/beacon/v2`, and a hardcoded curl is therefore wrong for one of them, reintroducing
    /// the 404 this exists to prevent.
    #[test]
    fn smoke_test_curl_follows_the_configured_beacon_mount() {
        let default_mount = smoke_test_curl("http://localhost:8080", "/aggregated/beacon/v2");
        assert!(
            default_mount.contains("http://localhost:8080/aggregated/beacon/v2/g_variants"),
            "must use the default split mount: {default_mount}"
        );

        // The Compose override: both planes collapsed onto /beacon/v2.
        let overridden = smoke_test_curl("https://node.example.org/", "/beacon/v2");
        assert!(
            overridden.contains("https://node.example.org/beacon/v2/g_variants"),
            "must follow an overridden mount (and not double the slash): {overridden}"
        );
        assert!(
            !overridden.contains("/aggregated/"),
            "must not leak the default path into an overridden config: {overridden}"
        );

        // Both probes, and the expected answer for each. A single fixture-data curl is
        // ambiguous on the node that runs it most — a fresh one, with nothing ingested,
        // where it returns `exists: false` at HTTP 200, which reads to a newcomer like a
        // broken install. The `/info` probe answers on any node, so it separates "wrong
        // path" (404) from "right path, no data yet".
        assert!(
            default_mount.contains("/aggregated/beacon/v2/info"),
            "must offer a data-independent path probe: {default_mount}"
        );
        assert!(
            default_mount.contains("beaconId"),
            "the path probe must say what a good answer looks like: {default_mount}"
        );
        assert!(
            default_mount.contains("exists"),
            "the data probe must name `exists: false` as the correct fresh-node answer: \
             {default_mount}"
        );
    }

    /// A node on shipped defaults must boot without the query-memory warning.
    ///
    /// Comparing `scan_pool_cap x max_query_bytes` against `max_total_query_bytes` would
    /// fire on every stock install, for a ceiling the node cannot reach:
    /// `max_total_query_bytes` is charged incrementally by each scan's `RetentionSink` and
    /// sheds with a 503 from inside the scan. A warning that appears on every install is one
    /// operators learn to skip.
    ///
    /// The defaults sit exactly at the boundary, which is why this asserts equality rather
    /// than a comfortable margin: if either default moves, the test says so instead of
    /// silently gaining or losing headroom.
    #[test]
    fn a_default_node_does_not_warn_about_query_memory() {
        let config = ServiceConfig::default();
        let (pool_cap, floor) = decode_working_set_floor(&config);
        assert_eq!(pool_cap, 32, "scan pool at default query_concurrency");
        assert_eq!(
            floor,
            config.service.max_total_query_bytes,
            "the shipped defaults sit exactly on the boundary: {} x {} vs {}",
            pool_cap,
            config.service.max_parquet_row_group_bytes,
            config.service.max_total_query_bytes
        );
        assert!(
            floor <= config.service.max_total_query_bytes,
            "a stock node must boot clean"
        );
    }

    /// It must still fire when an operator raises the knob that grows the unbounded term.
    /// Without this, "never warn" would satisfy the test above.
    #[test]
    fn raising_the_row_group_cap_warns_about_query_memory() {
        let mut config = ServiceConfig::default();
        config.service.max_parquet_row_group_bytes *= 2;
        let (_, floor) = decode_working_set_floor(&config);
        assert!(
            floor > config.service.max_total_query_bytes,
            "doubling max_parquet_row_group_bytes must cross the threshold: {floor} vs {}",
            config.service.max_total_query_bytes
        );

        // The other input to the product, so the check is not accidentally single-knob.
        let mut wider = ServiceConfig::default();
        wider.service.query_concurrency = Some(64);
        let (pool_cap, floor) = decode_working_set_floor(&wider);
        assert!(pool_cap > 32, "a raised query_concurrency widens the pool");
        assert!(
            floor > wider.service.max_total_query_bytes,
            "a wider pool must cross the threshold too: {floor}"
        );
    }

    /// The public plane's browser-origin posture must be visible in the dry run.
    ///
    /// `cors_allowed_origins` defaults to empty, which means the wildcard, and on an
    /// intranet- or VPN-only node that turns any user's browser into a read-proxy for the
    /// beacon. `check-config` reports every other posture (s3, vault, pme, `writer_auth`,
    /// audit), so this one belongs beside them.
    #[test]
    fn public_cors_status_names_the_wildcard_default() {
        let mut config = ServiceConfig::default();
        assert!(
            config.service.cors_allowed_origins.is_empty(),
            "the shipped default must remain empty for this test to mean anything"
        );
        let wildcard = public_cors_status(&config);
        assert!(
            wildcard.contains("wildcard") && wildcard.contains("ANY browser origin"),
            "the default posture must be spelled out, not glossed: {wildcard}"
        );

        config.service.cors_allowed_origins = vec!["https://portal.example.org".to_owned()];
        let allow_list = public_cors_status(&config);
        assert!(
            allow_list.contains("allow-list") && !allow_list.contains("wildcard"),
            "a configured allow-list must not still report a wildcard: {allow_list}"
        );
    }

    /// `writer_policy` ships as `off`, so a first-run node ingests packages whose writer key
    /// is recorded but never verified. `check-config` never calls `warn_deployment_posture`,
    /// because it does not serve, so this summary line is the only place a dry run can say
    /// so, and it must not be quietly reassuring.
    #[test]
    fn writer_policy_status_says_unauthenticated_when_off() {
        let mut config = ServiceConfig::default();
        assert_eq!(
            config.ingest.writer_policy,
            WriterPolicy::Off,
            "the shipped default must remain `off` for this test to mean anything"
        );
        let off = writer_policy_status(&config);
        assert!(
            off.contains("UNAUTHENTICATED"),
            "the default posture must be spelled out, not glossed: {off}"
        );

        config.ingest.writer_policy = WriterPolicy::Enforce;
        assert!(
            !writer_policy_status(&config).contains("UNAUTHENTICATED"),
            "enforce must not claim to be unauthenticated"
        );
    }

    /// The public listener gets the same actionable `EADDRINUSE` treatment as the
    /// management one: it defaults to a fixed `8080`, so it collides just as easily.
    #[tokio::test]
    async fn public_bind_in_use_names_the_config_key() {
        let held = bind_listener("127.0.0.1:0", "HTTP listener", "listen")
            .await
            .expect("a free port binds");
        let addr = held.local_addr().expect("bound addr").to_string();

        let err = bind_listener(&addr, "HTTP listener", "listen")
            .await
            .expect_err("binding an in-use public address must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("[service].listen") && msg.contains("already in use"),
            "EADDRINUSE on the public plane must name `[service].listen`: {err}"
        );
    }

    /// An idle shutdown must early-return after a single count check, never wait out the
    /// budget in the common case where no ingest is in flight.
    #[tokio::test]
    async fn wait_for_quiescent_returns_immediately_when_already_idle() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let polls = AtomicUsize::new(0);
        wait_for_quiescent(Duration::from_hours(1), || {
            polls.fetch_add(1, Ordering::Relaxed);
            0
        })
        .await;
        assert_eq!(
            polls.load(Ordering::Relaxed),
            1,
            "an idle shutdown must early-return after one count check, not enter the poll loop"
        );
    }

    /// When work is in flight but then drains, the wait returns as soon as the count reaches
    /// zero, well within the budget, releasing the data-dir lock.
    #[tokio::test]
    async fn wait_for_quiescent_drains_then_returns() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        // Non-zero for the first three reads (the early check + two poll iterations),
        // then zero: the loop exits on the read that observes zero.
        let reads = AtomicUsize::new(0);
        wait_for_quiescent(Duration::from_hours(1), || {
            usize::from(reads.fetch_add(1, Ordering::Relaxed) < 3)
        })
        .await;
        assert!(
            reads.load(Ordering::Relaxed) >= 4,
            "must poll until the count drains to zero, then return"
        );
    }

    /// Work that never drains must not hang shutdown: the wait is bounded by the budget,
    /// after which the caller proceeds to exit, abandoning the in-flight ingest, which is
    /// crash-safe and re-queues on the next boot.
    #[tokio::test]
    async fn wait_for_quiescent_is_bounded_by_the_budget() {
        let budget = Duration::from_millis(200);
        let start = std::time::Instant::now();
        wait_for_quiescent(budget, || 1).await;
        assert!(
            start.elapsed() >= budget,
            "a never-draining count must return only after the budget elapses, not hang"
        );
    }

    /// The manual public serve loop serves a real HTTP request over a real socket, through
    /// the hyper builder with the header-read-timeout timer that panics hyper on the first
    /// connection when unset, and returns cleanly once the injected shutdown fires. It uses
    /// a trivial router, so it exercises the serve machinery — loop, timer, connection cap,
    /// graceful drain — rather than axum routing.
    #[tokio::test]
    async fn serve_bounded_serves_a_request_then_drains_on_shutdown() {
        use axum::routing::get;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let router = axum::Router::new().route("/", get(|| async { "ok" }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().expect("bound addr");
        let readiness = gdi_node_standalone::health::Readiness::new();

        let shutdown = Arc::new(Notify::new());
        let shutdown_wait = {
            let s = Arc::clone(&shutdown);
            async move { s.notified().await }
        };
        let server = tokio::spawn(serve_bounded(
            listener,
            router,
            Duration::from_secs(5),
            Some(readiness.clone()),
            gdi_node_standalone::metrics::PLANE_PUBLIC,
            shutdown_wait,
        ));

        // A real HTTP/1.1 request must get a 200 (Connection: close so the server closes
        // after the response and `read_to_end` returns).
        let mut sock = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect to the served port");
        sock.write_all(b"GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
            .await
            .expect("write request");
        let mut resp = Vec::new();
        sock.read_to_end(&mut resp).await.expect("read response");
        let head = String::from_utf8_lossy(&resp);
        assert!(
            head.starts_with("HTTP/1.1 200"),
            "expected 200, got: {head}"
        );

        // Firing the injected shutdown drains and returns Ok within the drain budget.
        shutdown.notify_one();
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("serve_bounded must return after shutdown")
            .expect("serve_bounded task must not panic")
            .expect("serve_bounded returns Ok on graceful shutdown");

        // The public plane (`Some(readiness)`) must flip readiness to shutting down before
        // draining, so the endpoint-removal race stays closed.
        assert!(
            readiness.is_shutting_down(),
            "a Some(readiness) plane must flip /health/ready to 503 on shutdown"
        );
    }

    /// The management-plane call shape: `serve_bounded` with `readiness = None` serves a
    /// request and drains cleanly without a `Readiness`. It must keep answering probes
    /// through the public drain, so it must not flip readiness.
    #[tokio::test]
    async fn serve_bounded_with_no_readiness_drains() {
        use axum::routing::get;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let router = axum::Router::new().route("/", get(|| async { "ok" }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().expect("bound addr");

        let shutdown = Arc::new(Notify::new());
        let shutdown_wait = {
            let s = Arc::clone(&shutdown);
            async move { s.notified().await }
        };
        let server = tokio::spawn(serve_bounded(
            listener,
            router,
            Duration::from_secs(5),
            None,
            gdi_node_standalone::metrics::PLANE_MANAGEMENT,
            shutdown_wait,
        ));

        let mut sock = tokio::net::TcpStream::connect(addr).await.expect("connect");
        sock.write_all(b"GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
            .await
            .expect("write request");
        let mut resp = Vec::new();
        sock.read_to_end(&mut resp).await.expect("read response");
        assert!(
            String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 200"),
            "the None-readiness (management) shape must still serve"
        );

        shutdown.notify_one();
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("serve_bounded(None) must return after shutdown")
            .expect("task must not panic")
            .expect("serve_bounded(None) returns Ok on graceful shutdown");
    }

    /// Parse an argv the way `main` does, prepending the `argv[0]` clap expects. The tests
    /// below drive the real clap surface, so what they assert is what the operator gets.
    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("gdi-node-standalone").chain(args.iter().copied()))
    }

    /// Parse and unwrap to the selected [`Command`] — for the cases that pin one.
    fn command(args: &[&str]) -> Command {
        parse(args)
            .unwrap_or_else(|e| panic!("{args:?} must parse: {e}"))
            .command
            .unwrap_or_else(|| panic!("{args:?} must select a command"))
    }

    /// `--config` (split form) and `check-config` parse together; `--version`
    /// stays unset when not given.
    #[test]
    fn cli_parses_split_config_and_check_config() {
        let cli =
            parse(&["check-config", "--config", "/etc/x.toml"]).expect("recognized args parse");
        std::assert_matches!(cli.command, Some(Command::CheckConfig));
        assert!(!cli.version);
        assert_eq!(cli.config.as_deref(), Some(Path::new("/etc/x.toml")));
    }

    /// The joined `--config=<path>` form and the `-V` version alias both parse, and the
    /// `version` subcommand spelling selects the same one-shot.
    #[test]
    fn cli_parses_joined_config_and_version_alias() {
        let cli = parse(&["--config=/tmp/c.toml", "-V"]).expect("recognized args parse");
        assert_eq!(cli.config.as_deref(), Some(Path::new("/tmp/c.toml")));
        assert!(cli.version);
        assert!(cli.command.is_none());
        std::assert_matches!(command(&["version"]), Command::Version);
    }

    /// `--help` and `-h` short-circuit parsing: clap prints the usage itself and the process
    /// exits 0, which surfaces as the `DisplayHelp` error kind.
    #[test]
    fn cli_parses_help() {
        for flag in ["--help", "-h"] {
            let err = parse(&[flag]).expect_err("help short-circuits parsing");
            assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp, "{flag}");
            assert_eq!(err.exit_code(), 0, "{flag} exits 0");
        }
    }

    /// `config dump-defaults` parses as a bare, config-free one-shot (it takes no
    /// positional and no flags of its own).
    #[test]
    fn cli_parses_config_dump_defaults() {
        std::assert_matches!(
            command(&["config", "dump-defaults"]),
            Command::Config(ConfigCommand::DumpDefaults)
        );
        assert!(
            parse(&["config"]).is_err(),
            "`config` requires a subcommand"
        );
        assert!(
            parse(&["config", "dump-defaults", "x"]).is_err(),
            "no positional"
        );
    }

    #[test]
    fn cli_parses_identity_init_file_target() {
        // The file-backed (non-Vault) posture: `--file` names the key file, and `--force`
        // is accepted here (it replaces a file identity) as well as by retire.
        let Command::Identity(IdentityCommand::Init(args)) =
            command(&["identity", "init", "--file", "keys/node.c4gh"])
        else {
            panic!("identity init must parse to the init verb");
        };
        assert_eq!(args.file.as_deref(), Some(Path::new("keys/node.c4gh")));
        assert!(!args.force);

        let Command::Identity(IdentityCommand::Init(args)) =
            command(&["identity", "init", "--file=keys/node.c4gh", "--force"])
        else {
            panic!("--file=<v> and --force must parse");
        };
        assert_eq!(args.file.as_deref(), Some(Path::new("keys/node.c4gh")));
        assert!(args.force);

        // Misdirected flags stay a usage error, not a silent no-op.
        assert!(
            parse(&["doctor", "--file", "keys/node.c4gh"]).is_err(),
            "--file belongs to `identity init`"
        );
    }

    #[test]
    fn cli_parses_identity_group_verbs() {
        std::assert_matches!(
            command(&["identity", "list"]),
            Command::Identity(IdentityCommand::List)
        );
        std::assert_matches!(
            command(&["identity", "rotate"]),
            Command::Identity(IdentityCommand::Rotate)
        );
        // A bare `identity` with no verb, or an unknown verb, is a usage error.
        assert!(parse(&["identity"]).is_err());
        assert!(parse(&["identity", "frobnicate"]).is_err());
    }

    #[test]
    fn cli_parses_dataset_list_with_filters() {
        let Command::Dataset(DatasetCommand::List(args)) = command(&[
            "dataset",
            "list",
            "--state",
            "visible",
            "--state",
            "error",
            "--errors",
            "--channel",
            "egv-bucket",
            "--provenance",
            "recovery_failed",
            "--writer",
            "sha256:aa",
            "--id",
            "GDI-EE",
            "--unverified",
            "--suppressed",
            "--format",
            "json",
        ]) else {
            panic!("dataset list flags must parse");
        };
        let f = args.filter();
        assert_eq!(f.states, ["visible", "error", "error"]); // --errors appends "error"
        assert_eq!(f.channel.as_deref(), Some("egv-bucket"));
        assert_eq!(f.provenance.as_deref(), Some("recovery_failed"));
        assert_eq!(f.writer.as_deref(), Some("sha256:aa"));
        assert_eq!(f.id_substring.as_deref(), Some("GDI-EE"));
        assert!(f.unverified);
        assert!(f.suppressed);
        assert_eq!(
            args.format,
            gdi_node_standalone::list_datasets::OutputFormat::Json
        );
    }

    #[test]
    fn cli_parses_dataset_list_suppressed_alone() {
        // `--suppressed` alone (no other filter) must both parse and reach the filter
        // (it is the whole predicate, so a dropped flag would list everything).
        let Command::Dataset(DatasetCommand::List(args)) =
            command(&["dataset", "list", "--suppressed"])
        else {
            panic!("dataset list --suppressed must parse");
        };
        assert!(args.filter().suppressed);
        assert_ne!(
            args.filter(),
            gdi_node_standalone::list_datasets::DatasetsFilter::default(),
            "--suppressed alone must register as a set dataset-list filter"
        );
        // Given to a different command, it is a usage error (mirrors --unverified below).
        assert!(parse(&["doctor", "--suppressed"]).is_err());
    }

    #[test]
    fn cli_parses_dataset_verbs_with_positionals() {
        let Command::Dataset(DatasetCommand::Reingest(args)) =
            command(&["dataset", "reingest", "GDI-EE-UTARTU-20260409143052837"])
        else {
            panic!("reingest must parse");
        };
        assert_eq!(args.id, "GDI-EE-UTARTU-20260409143052837");
        // An unknown `dataset` verb is a usage error.
        assert!(parse(&["dataset", "purge", "X"]).is_err());
        // Including a two-positional shape: no `dataset` verb takes a state argument.
        assert!(parse(&["dataset", "set-state", "X", "hidden"]).is_err());
    }

    /// `dataset purge-rejected` parses bare, with `--older-than` (both `--flag value`
    /// and `--flag=value` forms) and `--dry-run`. It takes no positional id, unlike every
    /// other `dataset` verb above.
    #[test]
    fn cli_parses_dataset_purge_rejected() {
        let Command::Dataset(DatasetCommand::PurgeRejected(bare)) =
            command(&["dataset", "purge-rejected"])
        else {
            panic!("bare purge-rejected must parse");
        };
        assert!(bare.older_than.is_none());
        assert!(!bare.dry_run);

        let Command::Dataset(DatasetCommand::PurgeRejected(args)) =
            command(&["dataset", "purge-rejected", "--older-than", "7d"])
        else {
            panic!("--older-than must parse");
        };
        assert_eq!(
            args.older_than,
            Some(std::time::Duration::from_hours(7 * 24))
        );

        let Command::Dataset(DatasetCommand::PurgeRejected(args)) =
            command(&["dataset", "purge-rejected", "--older-than=72h"])
        else {
            panic!("--older-than=<v> must parse");
        };
        assert_eq!(args.older_than, Some(std::time::Duration::from_hours(72)));

        let Command::Dataset(DatasetCommand::PurgeRejected(args)) =
            command(&["dataset", "purge-rejected", "--dry-run"])
        else {
            panic!("--dry-run must parse");
        };
        assert!(args.dry_run);

        // A stray positional is a usage error — this verb takes none.
        assert!(
            parse(&[
                "dataset",
                "purge-rejected",
                "GDI-EE-UTARTU-20260409143052837"
            ])
            .is_err(),
            "purge-rejected takes no positional id"
        );
        // A malformed --older-than value is a usage error.
        assert!(parse(&["dataset", "purge-rejected", "--older-than", "abc"]).is_err());
        assert!(parse(&["dataset", "purge-rejected", "--older-than", "7"]).is_err());
        assert!(parse(&["dataset", "purge-rejected", "--older-than", "7x"]).is_err());
        // A bare, value-less --older-than (e.g. from an unset shell variable —
        // `--older-than $RETENTION` with `$RETENTION` empty) must not silently parse
        // as "unset", which would mean "purge everything": it must be a usage error.
        assert!(parse(&["dataset", "purge-rejected", "--older-than"]).is_err());
        // --older-than / --dry-run given to a foreign command is a usage error.
        assert!(parse(&["dataset", "reingest", "X", "--older-than", "7d"]).is_err());
        assert!(parse(&["doctor", "--dry-run"]).is_err());
    }

    /// `dataset hide|take-down|show` parse, with `--reason` required on all three, and a
    /// verb outside that set is a hard usage error.
    #[test]
    fn dataset_hide_takedown_show_parse() {
        const ID: &str = "GDI-EE-UTARTU-20260409143052837";

        let Command::Dataset(DatasetCommand::Hide(args)) =
            command(&["dataset", "hide", ID, "--reason", "r"])
        else {
            panic!("hide must parse");
        };
        assert_eq!(args.id, ID);
        assert_eq!(args.reason, "r");

        let Command::Dataset(DatasetCommand::TakeDown(args)) =
            command(&["dataset", "take-down", ID, "--reason", "r"])
        else {
            panic!("take-down must parse");
        };
        assert_eq!(args.id, ID);
        assert_eq!(args.reason, "r");
        assert!(!args.dry_run);

        let Command::Dataset(DatasetCommand::TakeDown(args)) =
            command(&["dataset", "take-down", ID, "--reason", "r", "--dry-run"])
        else {
            panic!("take-down --dry-run must parse");
        };
        assert!(args.dry_run);

        let Command::Dataset(DatasetCommand::Show(args)) =
            command(&["dataset", "unhide", ID, "--reason", "r"])
        else {
            panic!("unhide must parse");
        };
        assert_eq!(args.id, ID);
        assert_eq!(args.reason, "r");

        // `show` is the visible alias for `unhide`, the pair to `hide`.
        let Command::Dataset(DatasetCommand::Show(args)) =
            command(&["dataset", "show", ID, "--reason", "r"])
        else {
            panic!("show must parse as the unhide alias");
        };
        assert_eq!(args.id, ID);

        assert!(
            parse(&["dataset", "hide", ID]).is_err(),
            "reason required on hide"
        );
        assert!(
            parse(&["dataset", "take-down", ID]).is_err(),
            "reason required on take-down"
        );
        assert!(
            parse(&["dataset", "show", ID]).is_err(),
            "reason required on show: re-exposing data is a governance act too"
        );
        assert!(
            parse(&["dataset", "hide", ID, "--reason", "r", "--dry-run"]).is_err(),
            "--dry-run does not belong to hide"
        );
        assert!(
            parse(&["dataset", "set-state", ID, "hidden"]).is_err(),
            "a verb outside hide/take-down/unhide is refused"
        );
    }

    /// `channel list|show|hide|take-down` parse, with `--reason` required on every verb but
    /// `list`: the channel-granularity mirror of `dataset_hide_takedown_show_parse` above.
    #[test]
    fn channel_list_show_hide_takedown_parse() {
        const NAME: &str = "primary";

        std::assert_matches!(
            command(&["channel", "list"]),
            Command::Channel(ChannelCommand::List(_))
        );

        let Command::Channel(ChannelCommand::Hide(args)) =
            command(&["channel", "hide", NAME, "--reason", "r"])
        else {
            panic!("hide must parse");
        };
        assert_eq!(args.name, NAME);
        assert_eq!(args.reason, "r");

        let Command::Channel(ChannelCommand::TakeDown(args)) =
            command(&["channel", "take-down", NAME, "--reason", "r"])
        else {
            panic!("take-down must parse");
        };
        assert_eq!(args.name, NAME);
        assert_eq!(args.reason, "r");
        assert!(!args.dry_run);

        let Command::Channel(ChannelCommand::TakeDown(args)) =
            command(&["channel", "take-down", NAME, "--reason", "r", "--dry-run"])
        else {
            panic!("take-down --dry-run must parse");
        };
        assert!(args.dry_run);

        let Command::Channel(ChannelCommand::Show(args)) =
            command(&["channel", "unhide", NAME, "--reason", "r"])
        else {
            panic!("unhide must parse");
        };
        assert_eq!(args.name, NAME);
        assert_eq!(args.reason, "r");

        let Command::Channel(ChannelCommand::Show(args)) =
            command(&["channel", "show", NAME, "--reason", "r"])
        else {
            panic!("show must parse as the unhide alias");
        };
        assert_eq!(args.name, NAME);

        assert!(
            parse(&["channel", "hide", NAME]).is_err(),
            "reason required on hide"
        );
        assert!(
            parse(&["channel", "take-down", NAME]).is_err(),
            "reason required on take-down"
        );
        assert!(
            parse(&["channel", "show", NAME]).is_err(),
            "reason required on show: re-exposing a whole channel is a governance act too"
        );
        assert!(
            parse(&["channel", "list", "--reason", "r"]).is_err(),
            "--reason does not belong to list"
        );
        assert!(
            parse(&["channel", "hide", NAME, "--reason", "r", "--dry-run"]).is_err(),
            "--dry-run does not belong to hide"
        );
        assert!(
            parse(&["channel", "hide"]).is_err(),
            "missing positional name"
        );
        assert!(
            parse(&["channel", "list", NAME]).is_err(),
            "list takes no positional"
        );
        assert!(
            parse(&["channel", "frobnicate"]).is_err(),
            "unknown channel subcommand"
        );
        assert!(
            parse(&["channel"]).is_err(),
            "channel requires a subcommand"
        );
        assert!(
            parse(&["channel", "hide", NAME, "--reason", "r", "extra"]).is_err(),
            "a stray extra positional is a usage error"
        );
    }

    /// `dataset correct <id> --field k=v… | --patch <file> | --reset` parses, with the
    /// three modes mutually exclusive and the id positional required.
    #[test]
    fn cli_parses_dataset_correct_verb() {
        const ID: &str = "GDI-EE-UTARTU-20260409143052837";

        let Command::Dataset(DatasetCommand::Correct(args)) = command(&[
            "dataset",
            "correct",
            ID,
            "--field",
            "title=Corrected",
            "--field",
            "license=https://example.org",
        ]) else {
            panic!("--field (repeatable) must parse");
        };
        assert_eq!(args.id, ID);
        assert_eq!(
            args.field,
            ["title=Corrected", "license=https://example.org"]
        );
        assert!(args.patch.is_none());
        assert!(!args.reset);

        let Command::Dataset(DatasetCommand::Correct(args)) =
            command(&["dataset", "correct", ID, "--patch", "/tmp/p.json"])
        else {
            panic!("--patch must parse");
        };
        assert_eq!(args.patch.as_deref(), Some(Path::new("/tmp/p.json")));

        let Command::Dataset(DatasetCommand::Correct(args)) =
            command(&["dataset", "correct", ID, "--patch=/tmp/q.json"])
        else {
            panic!("--patch=<path> must parse");
        };
        assert_eq!(args.patch.as_deref(), Some(Path::new("/tmp/q.json")));

        let Command::Dataset(DatasetCommand::Correct(args)) =
            command(&["dataset", "correct", ID, "--field=title=X"])
        else {
            panic!("--field=<k=v> must parse");
        };
        assert_eq!(args.field, ["title=X"]);

        let Command::Dataset(DatasetCommand::Correct(args)) =
            command(&["dataset", "correct", ID, "--reset"])
        else {
            panic!("--reset must parse");
        };
        assert!(args.reset);
        assert!(args.field.is_empty());
        assert!(args.patch.is_none());

        // Exactly one mode is required (the `mode` arg group).
        assert!(
            parse(&["dataset", "correct", ID]).is_err(),
            "no --field/--patch/--reset is a usage error"
        );
        assert!(
            parse(&["dataset", "correct", ID, "--field", "title=X", "--reset"]).is_err(),
            "--reset cannot combine with --field"
        );
        assert!(
            parse(&["dataset", "correct", ID, "--patch", "p.json", "--reset"]).is_err(),
            "--reset cannot combine with --patch"
        );
        assert!(
            parse(&[
                "dataset", "correct", ID, "--field", "title=X", "--patch", "p.json"
            ])
            .is_err(),
            "--field and --patch are mutually exclusive"
        );
        assert!(
            parse(&["dataset", "correct", "--reset"]).is_err(),
            "missing id"
        );
        // `--reason` is accepted on `dataset correct`: it records the justification in the
        // audit line. It parses both alone and with `--reset`, where it is ignored.
        assert!(
            parse(&[
                "dataset", "correct", ID, "--field", "title=X", "--reason", "typo fix"
            ])
            .is_ok(),
            "--reason is a valid dataset correct flag"
        );
    }

    #[test]
    fn cli_datasets_accepts_joined_value_forms_and_rejects_bad_format() {
        let Command::Dataset(DatasetCommand::List(args)) =
            command(&["dataset", "list", "--channel=inbox"])
        else {
            panic!("--channel=inbox must parse");
        };
        assert_eq!(args.filter().channel.as_deref(), Some("inbox"));
        let err = parse(&["dataset", "list", "--format", "yaml"])
            .expect_err("an unknown --format value is a usage error");
        assert!(
            err.to_string().contains("expected `text` or `json`"),
            "the format parser's message survives: {err}"
        );
    }

    /// The irreversible verb refuses to run on a bare command line.
    ///
    /// `--reason` alone parses, because it is a governance field rather than a confirmation,
    /// so the gate cannot live in the grammar. It is [`confirm_take_down`], and this asserts
    /// the refusal directly: `take-down` erases the local copy, so it must demand at least
    /// as much as the reversible `hide` beside it.
    #[test]
    fn take_down_refuses_without_yes_or_dry_run() {
        let err = confirm_take_down("dataset", false, false)
            .expect_err("neither --yes nor --dry-run must refuse");
        let msg = err.to_string();
        assert!(
            msg.contains("--dry-run") && msg.contains("--yes"),
            "the refusal names BOTH ways forward: {msg}"
        );
        assert!(
            msg.contains("IRREVERSIBLY"),
            "and says why it is asking: {msg}"
        );

        confirm_take_down("dataset", false, true).expect("--yes applies");
        confirm_take_down("dataset", true, false).expect("--dry-run previews");
        confirm_take_down("channel", true, false).expect("the channel verb shares the gate");
    }

    /// Two commands at once are rejected: clap treats the second as an unexpected argument
    /// of the first. The "choose exactly one" rule is the grammar, so only the rejection is
    /// asserted, not its wording.
    #[test]
    fn cli_rejects_two_commands() {
        assert!(parse(&["dataset", "list", "verify"]).is_err());
        assert!(parse(&["doctor", "check-config"]).is_err());
    }

    /// A known flag that belongs to a different command is rejected. Each flag lives on its
    /// owning command's args type, so this is clap's "unexpected argument".
    #[test]
    fn cli_rejects_a_flag_that_belongs_to_another_command() {
        assert!(
            parse(&["doctor", "--channel", "x"]).is_err(),
            "a dataset-list filter on doctor must error"
        );
        assert!(
            parse(&["dataset", "list", "--force"]).is_err(),
            "--force is an identity retire/init flag"
        );
        assert!(
            parse(&["dataset", "list", "--dry-run"]).is_err(),
            "--dry-run belongs to identity retire/restore/dataset take-down only"
        );
        assert!(
            parse(&["dataset", "list", "--reason", "r"]).is_err(),
            "--reason belongs to dataset hide/take-down only"
        );
        // `--yes` belongs to the irreversible verbs — `identity retire` and both
        // `take-down`s — and to nothing else. It is not shared with `--dry-run`'s wider
        // owner set: `identity restore` has no confirm gate to bypass.
        parse(&[
            "dataset",
            "take-down",
            "GDI-EE-UTARTU-20260409143052837",
            "--reason",
            "r",
            "--yes",
        ])
        .expect("--yes confirms the irreversible dataset take-down");
        parse(&["channel", "take-down", "primary", "--reason", "r", "--yes"])
            .expect("--yes confirms the irreversible channel take-down");
        assert!(
            parse(&[
                "identity",
                "restore",
                "--in",
                "/b.c4gh",
                "--identity",
                "/op.sec",
                "--yes"
            ])
            .is_err(),
            "--yes does not belong to identity restore"
        );
        // --format is shared by dataset list and doctor.
        parse(&["doctor", "--format", "json"]).expect("doctor --format json is valid");
        parse(&["doctor", "--strict"]).expect("doctor --strict is valid");
        assert!(
            parse(&["verify", "--strict"]).is_err(),
            "--strict is a doctor flag"
        );
    }

    #[test]
    fn cli_rejects_wrong_positional_count() {
        assert!(
            parse(&["dataset", "hide", "--reason", "r"]).is_err(),
            "missing id"
        );
        assert!(parse(&["dataset", "reingest"]).is_err(), "missing id");
        assert!(
            parse(&["verify", "GDI-EE-UTARTU-20260409143052837"]).is_err(),
            "verify takes no positional"
        );
    }

    #[test]
    fn cli_accepts_a_command_with_only_its_own_flags() {
        parse(&[
            "dataset",
            "list",
            "--unverified",
            "--format",
            "json",
            "--channel",
            "egv",
        ])
        .expect("a dataset list with only its flags is valid");
        parse(&["verify", "--full", "--digest", "--concurrency", "8"])
            .expect("verify with only verify flags is valid");
        parse(&[
            "dataset",
            "take-down",
            "GDI-EE-UTARTU-20260409143052837",
            "--reason",
            "consent withdrawn",
            "--dry-run",
        ])
        .expect("dataset take-down with its own flags is valid");
        // Serve mode (no command, or explicit `serve`) with only the global --config is valid.
        let implicit = parse(&["--config", "/etc/x.toml"]).expect("implicit serve parses");
        assert!(implicit.command.is_none(), "no command means serve");
        std::assert_matches!(
            command(&["serve", "--config", "/etc/x.toml"]),
            Command::Serve
        );
    }

    #[test]
    fn cli_never_swallows_a_following_flag_as_a_value() {
        // `--config --version` must not set config = "--version" and silently drop the
        // version request. clap never takes a `--`-prefixed token as an option's value, so
        // the request parses with the version flag honoured and the path left unset.
        let cli = parse(&["--config", "--version"]).expect("clap does not swallow the flag");
        assert!(cli.config.is_none(), "the flag was not taken as a value");
        assert!(cli.version, "the version request survives");
        // The normal split form still works.
        let ok = parse(&["--config", "/etc/gdi/config.toml"]).expect("--config <path> parses");
        assert_eq!(
            ok.config.as_deref(),
            Some(Path::new("/etc/gdi/config.toml"))
        );
    }

    #[test]
    fn cli_parses_verify_with_flags() {
        let Command::Verify(args) =
            command(&["verify", "--full", "--digest", "--concurrency", "8"])
        else {
            panic!("verify must parse");
        };
        assert!(args.full);
        assert!(args.digest);
        assert_eq!(args.concurrency, 8);

        // Joined form + footer-only default.
        let Command::Verify(args) = command(&["verify", "--concurrency=16"]) else {
            panic!("verify --concurrency= must parse");
        };
        assert_eq!(args.concurrency, 16);
        assert!(!args.full && !args.digest);

        // A non-numeric concurrency is a hard error.
        assert!(parse(&["verify", "--concurrency", "x"]).is_err());
    }

    /// `identity backup` collects a repeated `--recipient` (split and joined forms)
    /// into the recipients list, in order, alongside `--out`.
    #[test]
    fn cli_parses_backup_identity_with_repeated_recipients() {
        let Command::Identity(IdentityCommand::Backup(args)) = command(&[
            "identity",
            "backup",
            "--recipient",
            "/a.pub",
            "--recipient=/b.pub",
            "--out",
            "/backup.c4gh",
        ]) else {
            panic!("identity backup must parse");
        };
        let recipients: Vec<&Path> = args
            .recipients
            .iter()
            .map(std::path::PathBuf::as_path)
            .collect();
        assert_eq!(recipients, vec![Path::new("/a.pub"), Path::new("/b.pub")]);
        assert_eq!(args.out.as_deref(), Some(Path::new("/backup.c4gh")));
    }

    /// `identity restore --dry-run` parses the verify-only flag alongside `--in` /
    /// `--identity`.
    #[test]
    fn cli_parses_restore_identity_dry_run() {
        let Command::Identity(IdentityCommand::Restore(args)) = command(&[
            "identity",
            "restore",
            "--in",
            "/b.c4gh",
            "--identity",
            "/op.sec",
            "--dry-run",
        ]) else {
            panic!("identity restore must parse");
        };
        assert!(args.dry_run);
        assert_eq!(args.input.as_deref(), Some(Path::new("/b.c4gh")));
        assert_eq!(args.identity.as_deref(), Some(Path::new("/op.sec")));
    }

    /// An unrecognized argument — a mistyped flag, a wrong-case flag, or a stray positional
    /// — is a hard error naming the offending token, rather than being ignored, which would
    /// boot the node on the config fallback with no diagnostic.
    #[test]
    fn cli_rejects_unknown_arguments() {
        let err = parse(&["--nonsense"]).expect_err("unknown flag errors");
        assert!(
            err.to_string().contains("--nonsense"),
            "error names the token: {err}"
        );

        // Wrong-case `--Config` must not be mistaken for `--config`.
        assert!(parse(&["--Config", "/etc/x.toml"]).is_err());

        // A stray positional is also rejected.
        assert!(parse(&["positional"]).is_err());
    }

    /// A bare trailing `--config` with no value is accepted and leaves the path unset
    /// (the env/default config fallback then applies).
    #[test]
    fn cli_handles_valueless_config() {
        let trailing = parse(&["--config"]).expect("valueless --config is ok");
        assert!(trailing.config.is_none());
    }

    /// A minimal [`AppState`] with PME inactive (`pme` is `None`): the shape of a default
    /// `lite` build, and of a `full` build with no `[vault].transit_key`. Also writes the
    /// same TOML to `dir/config.toml` (see [`pme_inactive_config_path`]) so a `SIGHUP`
    /// handler under test has a real, re-parsable file to reload from.
    #[cfg(unix)]
    fn pme_inactive_state(dir: &std::path::Path) -> AppState {
        let toml = pme_inactive_toml(dir);
        std::fs::write(pme_inactive_config_path(dir), &toml).expect("write config.toml");
        let config = gdi_node_standalone_core::config::ServiceConfig::from_toml_str(&toml)
            .expect("minimal config must parse");
        AppState::new(
            config,
            StatusIndex::new(),
            gdi_node_standalone::identities::NodeIdentities::empty(),
        )
    }

    /// The minimal TOML [`pme_inactive_state`] both parses in memory and writes to
    /// [`pme_inactive_config_path`].
    #[cfg(unix)]
    fn pme_inactive_toml(dir: &std::path::Path) -> String {
        format!(
            r#"
[service]
base_url = "https://x.example"
data_dir = "{}"

[beacon]
id = "org.x.beacon"
name = "X"
"#,
            dir.display()
        )
    }

    /// Where [`pme_inactive_state`] writes its config file — the path a `SIGHUP` handler
    /// under test reloads from.
    #[cfg(unix)]
    fn pme_inactive_config_path(dir: &std::path::Path) -> std::path::PathBuf {
        dir.join("config.toml")
    }

    /// `SIGHUP` must be a genuine no-op when PME is inactive, as the runbook promises.
    ///
    /// Creating the `tokio::signal` stream is what moves `SIGHUP` off its default Unix
    /// disposition, terminate. A handler that returns early before creating it would let
    /// `kill -HUP` kill the node on the two most common shapes — a default `lite` build and
    /// a `full` build without `[vault].transit_key` — while docs/operating.md §14 and §10
    /// promise a no-op and §10 instructs `kill -HUP <pid>`.
    ///
    /// If this regresses the test does not merely fail: the signal kills the test process.
    #[cfg(unix)]
    #[tokio::test]
    #[serial_test::serial(signals)]
    async fn sighup_is_a_noop_when_pme_is_inactive() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = pme_inactive_state(dir.path());
        let config_path = pme_inactive_config_path(dir.path());
        let pid = std::process::id();

        spawn_sighup_flush(&state, &config_path, S3ReloadContext::none());
        // Yield so the spawned task reaches `signal(SignalKind::hangup())` and installs the
        // process-wide handler before the signal is raised.
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;

        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("kill -HUP {pid}"))
            .status()
            .expect("raise SIGHUP");
        assert!(status.success(), "`kill -HUP` did not run");

        // With no handler installed the process is already gone. Reaching this line is the
        // real assertion; comparing the pid makes that explicit rather than implicit.
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        assert_eq!(std::process::id(), pid, "the node survived SIGHUP");
    }

    /// A reload triggered over HTTP reaches the PME half, not only the config half.
    ///
    /// `POST /reload` is the same handler as `SIGHUP`, and three docs say so. If the
    /// DEK-cache flush sat in the signal loop, the endpoint would reload config and skip the
    /// revocation half, and an operator who cannot `kubectl exec` — the reason the endpoint
    /// exists — would believe a key revocation had propagated.
    ///
    /// Asserted on the PME-inactive branch because it is reachable without Vault: the line
    /// is emitted only from inside `apply_config_reload`'s flush block, so seeing it under
    /// `trigger=http` proves that block runs on the HTTP path.
    ///
    /// Feature-gated because the flush block is: a build without `pme` has no DEK cache to
    /// reason about.
    #[cfg(feature = "pme")]
    #[test]
    fn a_reload_over_http_reaches_the_pme_flush_half() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = pme_inactive_state(dir.path());
        let config_path = pme_inactive_config_path(dir.path());

        // The reload is async, because it may re-read Vault, so the capture drives it to
        // completion on a current-thread runtime built inside the closure:
        // `capture_json_logs` installs a thread-local subscriber and cannot span an
        // `.await`, and a plain `#[test]` avoids nesting this inside an outer runtime. It
        // uses `tokio` rather than `futures::executor`, because `futures` is not a
        // dependency of this binary on every feature profile.
        let outcome = std::cell::RefCell::new(None);
        let logs = test_util::capture_json_logs(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("current-thread runtime");
            *outcome.borrow_mut() = Some(rt.block_on(apply_config_reload(
                &state,
                &config_path,
                &S3ReloadContext::none(),
                ReloadTrigger::Http,
            )));
        })
        .1;
        assert_eq!(
            outcome.into_inner(),
            Some(ReloadOutcome::Applied {
                restart_required: false
            })
        );

        assert!(
            logs.contains("no DEK cache to flush"),
            "the HTTP trigger must run the flush half of a reload: {logs}"
        );
        assert!(
            logs.contains("\"trigger\":\"http\""),
            "and the line must be attributed to the HTTP trigger: {logs}"
        );
    }

    /// The scan must not be able to wake itself.
    ///
    /// `notify`'s inotify mask includes `OPEN`, and `scan_once` opens the inbox on every
    /// pass, so treating every event as a wake closes a scan-to-scan loop that spins forever
    /// on an idle node with an empty inbox. Nothing observes it: a scan-success gauge
    /// advancing constantly is indistinguishable from health.
    #[test]
    fn read_only_access_events_do_not_wake_a_scan() {
        use notify::event::{
            AccessKind, AccessMode, CreateKind, EventKind, ModifyKind, RenameMode,
        };

        // What a read produces, the loop's fuel. It must be filtered.
        assert!(is_self_inflicted(EventKind::Access(AccessKind::Open(
            AccessMode::Any
        ))));
        assert!(is_self_inflicted(EventKind::Access(AccessKind::Open(
            AccessMode::Read
        ))));
        assert!(is_self_inflicted(EventKind::Access(AccessKind::Read)));
        // Closing a file opened for reading is what a reader produces too.
        assert!(is_self_inflicted(EventKind::Access(AccessKind::Close(
            AccessMode::Read
        ))));

        // What a real drop produces. Every one must still wake the scan, or the watcher
        // stops being a watcher and the periodic rescan becomes the only pickup path.
        for kind in [
            EventKind::Create(CreateKind::File),
            EventKind::Create(CreateKind::Folder),
            // The documented atomic drop: `*.partial` then rename into place.
            EventKind::Modify(ModifyKind::Name(RenameMode::To)),
            EventKind::Modify(ModifyKind::Any),
            // A finished write, which is an Access kind but not a read.
            EventKind::Access(AccessKind::Close(AccessMode::Write)),
            EventKind::Remove(notify::event::RemoveKind::File),
        ] {
            assert!(
                !is_self_inflicted(kind),
                "{kind:?} is a real drop signal and must still wake a scan"
            );
        }
    }

    /// The boot posture notice names every opt-in management surface that is on, taking the
    /// action endpoints from the list the router is bound to, and stays silent when none is.
    /// It is INFO because the operator opted in, so it repeats a decision rather than
    /// reporting a fault. The loopback warning names only the read surfaces every node
    /// serves, so without this a `[control].enabled` node would boot with no line saying its
    /// plane accepts unauthenticated actions.
    #[test]
    fn deployment_posture_names_every_opt_in_surface_that_is_on() {
        let config_with = |on: bool| {
            let dir = tempfile::tempdir().expect("tempdir");
            let toml = format!(
                r#"
[service]
base_url = "https://x.example"
data_dir = "{}"
expose_dataset_list = {on}

[beacon]
id = "org.x.beacon"
name = "X"

[stats]
enabled = {on}

[control]
enabled = {on}
"#,
                dir.path().display()
            );
            (
                ServiceConfig::from_toml_str(&toml).expect("config parses"),
                dir,
            )
        };

        let (on, _d1) = config_with(true);
        let logs = test_util::capture_json_logs(|| warn_deployment_posture(&on)).1;
        let line = logs
            .lines()
            .find(|l| l.contains("opt-in management-plane surfaces are ON"))
            .unwrap_or_else(|| panic!("the opt-in notice must fire with every surface on: {logs}"));
        for needle in ["/datasets/suppressed", "/stats/queries"] {
            assert!(line.contains(needle), "the notice names {needle}: {line}");
        }
        for route in gdi_node_standalone::app::CONTROL_ROUTES {
            assert!(line.contains(route), "the notice names {route}: {line}");
        }

        let (off, _d2) = config_with(false);
        let logs = test_util::capture_json_logs(|| warn_deployment_posture(&off)).1;
        assert!(
            !logs.contains("opt-in management-plane surfaces are ON"),
            "no opt-in surface on, no notice: {logs}"
        );
    }

    /// A boot config over `dir` declaring `buckets` (each at a dead loopback endpoint, so a
    /// monitor built from it fails its polls quickly rather than hanging).
    #[cfg(feature = "s3")]
    fn s3_config(dir: &std::path::Path, buckets: &[&str]) -> ServiceConfig {
        use std::fmt::Write as _;
        let mut toml = format!(
            r#"
[service]
base_url = "https://x.example"
data_dir = "{}"
startup_reconcile_timeout_seconds = 1

[beacon]
id = "org.x.beacon"
name = "X"
"#,
            dir.display()
        );
        for name in buckets {
            write!(
                toml,
                "\n[[s3.buckets]]\nname = \"{name}\"\nendpoint = \"http://127.0.0.1:1\"\nbucket = \"b-{name}\"\nallow_http = true\n"
            )
            .expect("writing to a String cannot fail");
        }
        ServiceConfig::from_toml_str(&toml).expect("config parses")
    }

    /// A bucket a config reload adds gets the same seeded series a boot-time bucket gets.
    /// Seeded only at boot, a bucket whose endpoint is dead from the moment it is added is
    /// no data for `S3PollerWedged`, which is the alert condition, and the first error on
    /// every `increase(...) > 0` bucket counter is missed: a series born at 1 and left flat
    /// yields `increase() = 0`.
    #[cfg(feature = "s3")]
    #[test]
    fn a_reload_added_bucket_gets_its_series_seeded() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = AppState::new(
            s3_config(dir.path(), &[]),
            StatusIndex::new(),
            gdi_node_standalone::identities::NodeIdentities::empty(),
        );
        let new_config = s3_config(dir.path(), &["added"]);
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime");
        rt.block_on(async {
            let runtime = IngestRuntime::start(state.clone());
            let running: RunningMonitors = Arc::default();
            ::metrics::with_local_recorder(&recorder, || {
                reload_s3_monitors(
                    &state,
                    &runtime,
                    &S3Overrides::default(),
                    &running,
                    &new_config,
                );
            });
            assert!(
                running
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .contains_key("added"),
                "precondition: the reload started the added bucket's monitor"
            );
        });

        let render = handle.render();
        for (series, label) in [
            (
                gdi_node_standalone::metrics::S3_DELETED_SIDECAR_IGNORED_TOTAL,
                "channel=\"added\"",
            ),
            (
                gdi_node_standalone::metrics::CHANNEL_SUPPRESSED,
                "channel=\"added\"",
            ),
        ] {
            assert!(
                render
                    .lines()
                    .any(|l| l.starts_with(series) && l.contains(label) && l.ends_with(" 0")),
                "a reload-added bucket must have {series}{{{label}}} seeded to 0, as a \
                 boot-time bucket does:\n{render}"
            );
        }
        assert!(
            render.lines().any(|l| {
                l.starts_with(gdi_node_standalone::metrics::S3_POLL_LAST_SUCCESS_TIMESTAMP_SECONDS)
                    && l.contains("channel=\"added\"")
            }),
            "the staleness clock must exist from the moment the bucket is added:\n{render}"
        );
    }

    /// `start_s3_monitors` is idempotent over the running set. A `SIGHUP` or `POST /reload`
    /// that lands before boot reaches it can already have started a channel's monitor, and a
    /// second start would build another whose `spawn_monitor` insert replaces the record,
    /// leaving the first monitor polling with no `RetireSignal` anyone holds and unretirable
    /// by any later reload.
    #[cfg(feature = "s3")]
    #[test]
    fn start_s3_monitors_leaves_a_channel_that_is_already_running_alone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = s3_config(dir.path(), &["b1"]);
        let descriptor = config
            .s3
            .as_ref()
            .and_then(|s3| s3.buckets.first().cloned())
            .expect("one bucket");
        let state = AppState::new(
            config,
            StatusIndex::new(),
            gdi_node_standalone::identities::NodeIdentities::empty(),
        );

        let running: RunningMonitors = Arc::default();
        let retire = Arc::new(gdi_node_standalone::s3::RetireSignal::default());
        running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                "b1".to_owned(),
                RunningMonitor {
                    descriptor,
                    retire: Arc::clone(&retire),
                    ingesting: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
                },
            );

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime");
        rt.block_on(async {
            let runtime = IngestRuntime::start(state.clone());
            start_s3_monitors(&state, &runtime, &S3Overrides::default(), &running).await;
        });

        let map = running.lock().unwrap_or_else(PoisonError::into_inner);
        assert_eq!(map.len(), 1, "no second record for a running channel");
        assert!(
            Arc::ptr_eq(&map["b1"].retire, &retire),
            "the running monitor's record must be left alone — a replacement orphans the \
             first monitor with no signal anyone can retire it with"
        );
    }
}
