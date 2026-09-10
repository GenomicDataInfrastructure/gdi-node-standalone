//! Structured logging setup.
//!
//! The node defaults to single-line JSON on stderr, which a log collector tails and parses
//! one document per line. The format is overridable with `LOG_FORMAT=text|json|ecs`, and the
//! level with `RUST_LOG`, or `GDI_LOG`, which takes precedence; the default is `info`.
//! `SIGUSR2` raises the level to diagnostic verbosity at runtime without a restart (see
//! [`toggle_verbose`]).
//!
//! The wire schema, built by `json_event_layer`: event fields are flattened to the top level
//! (`message`, `dataset`, `error_class`, …) so a consumer queries them directly rather than
//! under a `fields` envelope. Span fields are the exception: `request_id`, `method` and
//! `path` stay under `span`, the innermost enclosing span, with no ancestor list, so
//! correlate a request's lines by `span.request_id` (see `docs/operating.md`). The panic
//! line ([`render_panic_json`]) uses the same `timestamp`, `level` and `message` keys, so
//! panics and structured lines index under one schema.
//!
//! Two properties keep the log pipeline robust:
//! * All stderr is valid NDJSON, including panics. `CatchPanicLayer` turns a handler panic
//!   into a `500`, but a panic in `spawn_blocking` work, during startup, or any abort would
//!   otherwise hit the default panic hook and write an unstructured multi-line message that
//!   a line-based collector splits into bogus documents. [`install_panic_hook`] renders
//!   every panic as one JSON line.
//! * One field name maps to one JSON type: a `tracing` discipline, where identifiers stay
//!   strings and counts and durations stay numbers, rather than extra code here.
//!
//! Sensitive-data filtering is call-site discipline, not a type-level guarantee:
//!
//! * `zeroize::Zeroizing<Z>` derives `Debug`, which forwards to the inner type, so `{:?}` on
//!   a `Zeroizing<String>` prints the string. It also implements `serde::Serialize`.
//!   `Zeroizing` guarantees the memory is wiped on drop and nothing about formatting.
//! * Not every secret is wrapped: the S3 credential overrides are a plain
//!   `BTreeMap<String, (String, String)>`.
//!
//! So a log site in this crate can format a secret, and review is what stops it. The
//! type-level version would be a `Redacted<T>` newtype whose `Debug` prints `***`, the shape
//! `OtlpHeaders` uses in `core::config::service`, applied to every secret-bearing field.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use serde_json::{Map, Value};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Record};
use tracing::{Event, Id, Subscriber};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer as _;
use tracing_subscriber::Registry;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::Context;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::reload;
use tracing_subscriber::util::SubscriberInitExt as _;

/// The `tracing` target carrying beacon audit records, which may include the full query
/// when `[audit].query_detail` is on. It is the one content-bearing target, and OTLP trace
/// export excludes it (see [`init`]) so a trace backend never becomes a "who queried what"
/// store, the same content-free discipline `/metrics` follows.
///
/// Referenced in every build: `with_audit_floor` uses it to floor the audit target at `info`
/// in the level filter, so the trail cannot be silenced by `GDI_LOG`, and the `otel` export
/// path uses it for the trace-export exclusion.
const AUDIT_TARGET: &str = "audit";

/// Whether a `tracing` target may be exported as OTLP trace data. Excludes the
/// content-bearing [`AUDIT_TARGET`]; everything else is administrative span and event
/// metadata. Always compiled under `test`, so the content-free guarantee is unit-tested even
/// in a non-`otel` build.
#[cfg(any(test, feature = "otel"))]
#[must_use]
pub(crate) fn export_target_allowed(target: &str) -> bool {
    target != AUDIT_TARGET
}

/// The name of the supervision spans: `daemon{task, instance}` around every background
/// loop, and `daemon{task}` around each guarded iteration. They stamp `task` and `instance`
/// onto the log lines emitted inside them. Exported, they take one of two bad shapes — a
/// one-span root trace per tick, as `rescan` does every `rescan_interval_seconds`, or a
/// parent that never closes and collects one child per tick for the life of the process, as
/// `vault_liveness` does — and any work span created inside one, such as an `ingest_job`
/// with no sidecar parent, joins that trace.
#[cfg(any(test, feature = "otel"))]
pub(crate) const SUPERVISION_SPAN: &str = "daemon";

/// Whether a span or event may reach the OTLP export layer: the content-free target rule
/// ([`export_target_allowed`]), plus the supervision spans above kept out, so the work spans
/// they wrap (`ingest_job`, `http_request`) export as their own roots. Events keep passing;
/// they attach to their enclosing exported span, or to nothing.
#[cfg(any(test, feature = "otel"))]
#[must_use]
pub(crate) fn export_allowed(meta: &tracing::Metadata<'_>) -> bool {
    export_target_allowed(meta.target()) && !(meta.is_span() && meta.name() == SUPERVISION_SPAN)
}

/// The deployment environment (`[beacon].environment`: `dev`, `test`, `staging`, `prod`)
/// stamped onto structured log output as ECS `service.environment`. Set once by [`init`]
/// after config load, and read by the panic hook, which is installed before config load and
/// so must read the value lazily at panic time. Empty or unset means the field is omitted.
static LOG_ENVIRONMENT: OnceLock<String> = OnceLock::new();

/// The deployment environment recorded by [`init`], or `None` if unset/empty.
fn log_environment() -> Option<&'static str> {
    LOG_ENVIRONMENT
        .get()
        .map(String::as_str)
        .filter(|s| !s.is_empty())
}

/// The log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogFormat {
    /// Single-line JSON (the gdi-node-standalone default; ELK-ingestible).
    Json,
    /// Human-readable plain text.
    Text,
    /// Single-line ECS (Elastic Common Schema) JSON — `LOG_FORMAT=ecs`. Emits ECS
    /// field names (`@timestamp`, `log.level`, `message`, `service.name`, …) so logs
    /// land in Elasticsearch with no ingest pipeline.
    Ecs,
}

impl LogFormat {
    /// Resolve the format from `LOG_FORMAT` (`text`/`ecs`, case-insensitive); any
    /// other value (including `json`, or unset) defaults to JSON for the service.
    fn from_env() -> Self {
        match std::env::var("LOG_FORMAT").ok().as_deref() {
            Some(v) if v.eq_ignore_ascii_case("text") => Self::Text,
            Some(v) if v.eq_ignore_ascii_case("ecs") => Self::Ecs,
            _ => Self::Json,
        }
    }
}

/// Process-global handle to the reloadable level [`EnvFilter`], set once by [`init`]. Lets
/// `SIGUSR2` toggle diagnostic logging at runtime via [`toggle_verbose`] without a restart.
/// The audit-target OTLP exclusion is a separate static per-layer filter (see
/// `otel::build_layer`) that this handle does not reach, so a reload cannot re-open the
/// audit-export leak.
static RELOAD_HANDLE: OnceLock<reload::Handle<EnvFilter, Registry>> = OnceLock::new();

/// The filter when neither `GDI_LOG` nor `RUST_LOG` is set.
pub(crate) const DEFAULT_LOG_SPEC: &str = "info";

/// Third-party targets whose routine chatter is capped below the operator's level unless
/// the operator names them. The `object_store` crate logs every retry backoff at INFO, two
/// lines per S3 call, which during an S3 outage is most of the node's log; the shipped
/// compose sets `RUST_LOG=info`, so a default alone would not reach it. Applied like the
/// audit floor, inside [`audit_floored_filter`], so it holds for the boot filter and every
/// `SIGUSR2` reload. A spec that mentions the target keeps its own directive, because
/// `EnvFilter` resolves by specificity, so an operator's `object_store=debug` wins.
const THIRD_PARTY_CEILINGS: &[(&str, &str)] = &[("object_store", "warn")];

/// Build the [`EnvFilter`] from `GDI_LOG` (preferred) then `RUST_LOG`, defaulting to
/// [`DEFAULT_LOG_SPEC`]. `GDI_LOG` lets a deployment set the node's level without disturbing
/// a `RUST_LOG` that other co-located tooling reads.
fn build_filter() -> EnvFilter {
    // A valid `GDI_LOG` wins, else a valid `RUST_LOG`, else `info`. `invalid_log_spec`
    // mirrors this precedence and warns about whichever was discarded.
    let spec = std::env::var("GDI_LOG")
        .ok()
        .filter(|s| EnvFilter::try_new(s).is_ok())
        .or_else(|| {
            std::env::var("RUST_LOG")
                .ok()
                .filter(|s| EnvFilter::try_new(s).is_ok())
        })
        .unwrap_or_else(|| DEFAULT_LOG_SPEC.to_owned());
    audit_floored_filter(&spec)
}

/// Parse `spec` into an [`EnvFilter`] that always admits the audit target.
///
/// Split out of [`build_filter`] so the floor is testable against a spec string directly,
/// rather than only through process environment variables.
fn audit_floored_filter(spec: &str) -> EnvFilter {
    let sanitized = with_third_party_ceilings(&strip_audit_directives(spec));
    let base = EnvFilter::try_new(&sanitized).unwrap_or_else(|_| EnvFilter::new("info"));
    with_audit_floor(base)
}

/// Append each [`THIRD_PARTY_CEILINGS`] directive the operator's spec does not already
/// name. Specificity, not order, decides per event, so a bare level in `spec` never
/// out-ranks the appended `target=level`, while an operator's own `target=…` is left alone.
fn with_third_party_ceilings(spec: &str) -> String {
    let mut out = spec.to_owned();
    for (target, level) in THIRD_PARTY_CEILINGS {
        let named = spec.split(',').any(|directive| {
            let head = directive.split('=').next().unwrap_or_default();
            head.split('[').next().unwrap_or_default().trim() == *target
        });
        if !named {
            out.push(',');
            out.push_str(target);
            out.push('=');
            out.push_str(level);
        }
    }
    out
}

/// Drop every operator-supplied directive aimed at [`AUDIT_TARGET`], leaving the rest of
/// the spec untouched.
///
/// [`with_audit_floor`] adds a bare `audit=info` last, which beats another bare `audit`
/// directive. But `EnvFilter` resolves per event by specificity rather than by order, and a
/// field-qualified `audit[{event}]=off` is strictly more specific than the floor. Every
/// audit emit carries an `event` field, so that one directive would silence the whole
/// compliance trail while the floor looked applied, and `invalid_log_spec` would stay quiet
/// because the directive is valid. Ordering cannot win that race, so the operator's audit
/// directives are removed from the spec instead: the floor is then the only directive aimed
/// at the target, and no level knob can erase the audit trail.
fn strip_audit_directives(spec: &str) -> String {
    let kept: Vec<&str> = spec
        .split(',')
        .filter(|directive| !directive_targets_audit(directive))
        .collect();
    // An operator whose whole spec was an audit silencer is left with the default level
    // rather than an empty, and therefore meaningless, filter.
    if kept.iter().all(|d| d.trim().is_empty()) {
        return "info".to_owned();
    }
    kept.join(",")
}

/// Whether one comma-separated `EnvFilter` directive aims at [`AUDIT_TARGET`], with or
/// without a `[{field}]` qualifier (`audit=off`, `audit[{event}]=off`, …).
fn directive_targets_audit(directive: &str) -> bool {
    let head = directive.split('=').next().unwrap_or_default();
    let target = head.split('[').next().unwrap_or_default().trim();
    target == AUDIT_TARGET
}

/// Floor the dedicated [`AUDIT_TARGET`] at `info` regardless of the operational level knob.
/// The audit trail is compliance state, not operational noise, so it must not be silenceable
/// by lowering `GDI_LOG` or `RUST_LOG`. Applied inside [`build_filter`], so both the boot
/// filter and every `SIGUSR2` reload, which rebuilds from `build_filter`, admit
/// `audit`-target events. This is orthogonal to the audit-target OTLP export exclusion, a
/// separate static per-layer filter (see `otel::build_layer`): flooring the level filter
/// admits audit to the stderr sink without leaking it into exported traces.
fn with_audit_floor(filter: EnvFilter) -> EnvFilter {
    // A target-specific `audit=info` directive. `EnvFilter` matches the most specific
    // directive per event target, so this admits `target = "audit"` events at info even
    // under a lower global default, and, added last, overrides an operator's attempt to
    // silence it with `GDI_LOG=warn,audit=off`. The literal is a compile-time constant of
    // valid directive form; fall back to the unfloored filter rather than panic if it fails
    // to parse.
    match format!("{AUDIT_TARGET}=info").parse::<tracing_subscriber::filter::Directive>() {
        Ok(directive) => filter.add_directive(directive),
        Err(_) => filter,
    }
}

/// If a set `GDI_LOG` or `RUST_LOG` is unparseable, return the offending variable and value
/// so [`init`] can emit a one-time startup warning. `build_filter` falls back to the default
/// on a bad directive, so without this a typo such as `GDI_LOG=debg` leaves the node at
/// `info` during an incident with no signal that verbosity was ignored. Mirrors
/// `build_filter`'s precedence: `GDI_LOG` wins, and a valid `GDI_LOG` suppresses the
/// `RUST_LOG` check, because it is what took effect.
fn invalid_log_spec() -> Option<(&'static str, String)> {
    invalid_log_spec_from(
        std::env::var("GDI_LOG").ok(),
        std::env::var("RUST_LOG").ok(),
    )
}

/// Pure core of [`invalid_log_spec`]. The env read is split out so this precedence logic is
/// unit-testable without mutating the process environment; the crate forbids `unsafe`, so
/// `set_var` is not an option.
fn invalid_log_spec_from(
    gdi_log: Option<String>,
    rust_log: Option<String>,
) -> Option<(&'static str, String)> {
    if let Some(spec) = gdi_log {
        return EnvFilter::try_new(&spec).err().map(|_| ("GDI_LOG", spec));
    }
    if let Some(spec) = rust_log {
        return EnvFilter::try_new(&spec).err().map(|_| ("RUST_LOG", spec));
    }
    None
}

/// The resolved log format (`json`, `text` or `ecs`) and the effective filter directive
/// string, for the `check-config` posture summary. A pre-deploy dry run then shows the log
/// posture — a stale `GDI_LOG` shadowing `RUST_LOG`, an unexpected format — which is
/// otherwise env-only and invisible.
#[must_use]
pub fn effective_log_summary() -> (&'static str, String) {
    let format = match LogFormat::from_env() {
        LogFormat::Json => "json",
        LogFormat::Text => "text",
        LogFormat::Ecs => "ecs",
    };
    (format, build_filter().to_string())
}

/// Whether diagnostic (verbose) logging is currently toggled on. Flipped by
/// [`toggle_verbose`] on each `SIGUSR2`.
static VERBOSE: AtomicBool = AtomicBool::new(false);

/// The extra `EnvFilter` directives layered on top of the boot filter when diagnostic
/// logging is toggled on — every one of the node's own crates to `debug`, leaving
/// dependency noise at the boot level.
const DIAGNOSTIC_DIRECTIVES: &str = "gdi_node_standalone=debug,gdi_node_standalone_core=debug,gdi_node_standalone_beacon=debug,gdi_node_standalone_fairdp=debug";

/// Compose the diagnostic filter spec: the boot directives plus [`DIAGNOSTIC_DIRECTIVES`]
/// (later directives win per-target, so the node crates are raised to `debug`).
fn diagnostic_spec(base: &str) -> String {
    format!("{base},{DIAGNOSTIC_DIRECTIVES}")
}

/// Toggle diagnostic logging (the node's own crates at `debug`) on or off, returning the
/// applied filter directives. Driven by `SIGUSR2`, so an operator can raise verbosity to
/// trace a live issue such as a wedged ingest without a restart, which would drop in-flight
/// ingests and force a full re-reconcile, then toggle it back.
///
/// The base level is the boot-time `GDI_LOG`/`RUST_LOG` filter. `build_filter` is
/// deterministic — a process cannot change its own environment, so re-reading it
/// reconstructs the boot filter — and toggling off restores exactly that. The audit-target
/// OTLP exclusion is a separate static per-layer filter (see `otel::build_layer`) that this
/// never touches, so a toggle cannot re-open the leak.
///
/// # Errors
/// Returns `Err` if [`init`] has not run (no subscriber installed), the composed spec
/// fails to parse, or the subscriber has since been dropped.
pub fn toggle_verbose() -> Result<String, String> {
    set_verbose(!VERBOSE.load(Ordering::Relaxed)).map(|(filter, _generation)| filter)
}

/// Whether diagnostic logging is currently on.
///
/// `POST /log-level` reads it to decide which way its bodyless call flips, and its
/// auto-revert reads it to leave alone an operator who already turned verbosity off.
#[must_use]
pub fn is_verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

/// Monotonic counter of applied log-level changes — the identity of the current "session".
///
/// Lives here, beside `VERBOSE`, rather than next to the endpoint that reads it, so that
/// every level change bumps it by construction: `POST /log-level`, its own auto-revert, and
/// `SIGUSR2`. Kept beside the endpoint, only the HTTP path would bump it, so a `SIGUSR2`
/// would not supersede a pending revert and an operator who armed the window and then
/// flipped verbosity by signal would have it switched off under them when the timer fired.
static LEVEL_GENERATION: AtomicU64 = AtomicU64::new(0);

/// The current log-level generation. A caller that scheduled work against a level it set
/// compares this before acting, and does nothing if anything has changed the level since.
#[must_use]
pub fn level_generation() -> u64 {
    LEVEL_GENERATION.load(Ordering::SeqCst)
}

/// Set diagnostic logging to `want`, returning the applied filter directives and the
/// generation this change produced.
///
/// The implementation behind both triggers: `SIGUSR2`, via [`toggle_verbose`], and
/// `POST /log-level`. Idempotent, which the HTTP side needs and the signal does not: an
/// auto-revert that fires after the operator has already flipped verbosity off must leave it
/// off, where a second toggle would turn it back on.
///
/// The returned generation is this call's own. A scheduled revert carries it and does nothing
/// once [`level_generation`] has moved past it, so a revert can never override a later
/// decision — whichever trigger made it.
///
/// # Errors
/// Returns `Err` if [`init`] has not run (no subscriber installed), the composed spec
/// fails to parse, or the subscriber has since been dropped.
pub fn set_verbose(want: bool) -> Result<(String, u64), String> {
    let handle = RELOAD_HANDLE
        .get()
        .ok_or_else(|| "logging subscriber not initialised".to_owned())?;
    let now_verbose = want;
    let base = build_filter().to_string();
    let spec = if now_verbose {
        diagnostic_spec(&base)
    } else {
        base
    };
    let filter = EnvFilter::try_new(&spec).map_err(|e| e.to_string())?;
    let rendered = filter.to_string();
    handle.reload(filter).map_err(|e| e.to_string())?;
    VERBOSE.store(now_verbose, Ordering::Relaxed);
    // Bumped after the level is applied, and returned rather than re-read, so the caller
    // holds its own generation even if another trigger lands in between.
    let generation = LEVEL_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
    Ok((rendered, generation))
}

/// A `tracing` guard returned by [`init`]. Holds the OpenTelemetry tracer provider when
/// trace export is active, and flushes and shuts it down on drop, so batched spans are
/// delivered before the process exits. A no-op when the `otel` feature is off or no
/// `[service].otlp_endpoint` was configured: it then carries nothing and `Drop` does
/// nothing. The caller holds it for the process lifetime.
#[derive(Default)]
pub struct TelemetryGuard {
    #[cfg(feature = "otel")]
    provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
    /// The metrics-push provider (`[service].otlp_metrics_interval_seconds`), whose
    /// periodic reader owns the export thread; `shutdown` flushes its last push.
    #[cfg(feature = "otel")]
    meter_provider: Option<opentelemetry_sdk::metrics::SdkMeterProvider>,
    /// The meter the OTLP mirror records into — handed to `metrics::install_recorder`
    /// through [`Self::otel_mirror`].
    #[cfg(feature = "otel")]
    meter: Option<opentelemetry::metrics::Meter>,
}

impl TelemetryGuard {
    /// Flush and shut down trace and metrics export. Best-effort and idempotent: a second
    /// call, or `Drop` after an explicit call, is a no-op. An empty function when `otel` is
    /// off.
    pub fn shutdown(&mut self) {
        #[cfg(feature = "otel")]
        {
            if let Some(provider) = self.provider.take() {
                // Best-effort: a failed flush must not abort shutdown. The blocking OTLP
                // exporter runs on the batch processor's own thread, so this completes
                // during runtime teardown without a live tokio reactor.
                let _ = provider.shutdown();
            }
            if let Some(provider) = self.meter_provider.take() {
                // Same shape: the periodic reader's thread pushes the final collection.
                let _ = provider.shutdown();
            }
        }
    }

    /// The OTLP metrics mirror to fan the Prometheus recorder out to. `Some` only in an
    /// `otel` build with `[service].otlp_metrics_interval_seconds` set, and with
    /// `otlp_endpoint`, which that interval requires. Without the feature it is a `None` of
    /// an uninhabited type, so the call site reads the same in both builds.
    #[must_use]
    pub fn otel_mirror(&self) -> Option<crate::metrics::OtelMirror> {
        #[cfg(feature = "otel")]
        {
            self.meter.as_ref().map(|meter| {
                std::sync::Arc::new(crate::metrics_otel::OtelRecorder::new(
                    meter.clone(),
                    crate::metrics::HISTOGRAM_BUCKETS,
                ))
            })
        }
        #[cfg(not(feature = "otel"))]
        {
            None
        }
    }
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// A boxed `tracing` layer over the registry: the uniform element type of the composed
/// layer set, which is the JSON or text fmt layer plus the optional otel layer.
type BoxedLayer = Box<dyn tracing_subscriber::Layer<Registry> + Send + Sync>;

/// Build the optional OTLP export layer and its [`TelemetryGuard`]. Split by feature
/// so neither build carries a dead `mut`: the `otel` arm mutates the guard, the lite
/// arm does nothing. Returns `(layer, guard, setup-error-to-log-after-init)`.
#[cfg(feature = "otel")]
fn build_otel(
    otlp_endpoint: Option<&str>,
    otlp_headers: Option<&BTreeMap<String, String>>,
    environment: &str,
    otlp_metrics_interval: Option<std::time::Duration>,
    trace_sample_ratio: f64,
) -> (Option<BoxedLayer>, TelemetryGuard, Vec<String>) {
    let mut guard = TelemetryGuard::default();
    let mut failures = Vec::new();
    let Some(endpoint) = otlp_endpoint.filter(|e| !e.is_empty()) else {
        return (None, guard, failures);
    };
    // The two halves are attempted independently and each failure is named on its own.
    // Reported together, a trace-exporter fault would take the metrics push down with it
    // and the line would not say which half failed.
    let layer = match otel::build_layer(endpoint, otlp_headers, environment, trace_sample_ratio) {
        Ok((layer, provider)) => {
            guard.provider = Some(provider);
            Some(layer)
        }
        // Export setup is never fatal: report it (after init) and run trace-less.
        Err(e) => {
            failures.push(format!("OTLP trace export disabled: {e}"));
            None
        }
    };
    // The metrics push shares the endpoint, headers and identity; its own failure is
    // reported the same way and leaves traces running (and vice versa).
    if let Some(interval) = otlp_metrics_interval {
        match otel::build_meter_provider(endpoint, otlp_headers, environment, interval) {
            Ok((provider, meter)) => {
                guard.meter_provider = Some(provider);
                guard.meter = Some(meter);
            }
            Err(e) => failures.push(format!("OTLP metrics export disabled: {e}")),
        }
    }
    (layer, guard, failures)
}

/// Lite build: no OTLP export. Returns an empty layer set + no-op guard so [`init`]
/// composes identically without `mut`/`cfg` noise at the call site.
#[cfg(not(feature = "otel"))]
fn build_otel(
    _otlp_endpoint: Option<&str>,
    _otlp_headers: Option<&BTreeMap<String, String>>,
    _environment: &str,
    _otlp_metrics_interval: Option<std::time::Duration>,
    _trace_sample_ratio: f64,
) -> (Option<BoxedLayer>, TelemetryGuard, Vec<String>) {
    (None, TelemetryGuard::default(), Vec::new())
}

/// Initialize the global tracing subscriber: a JSON (default) or text fmt layer over an
/// [`EnvFilter`] on stderr. When `otlp_endpoint` is `Some(non-empty)` and the `otel` feature
/// is compiled in, it adds an OpenTelemetry layer that exports spans over OTLP, and with
/// `otlp_metrics_interval` the periodic OTLP metrics push, whose recorder is fanned in by
/// `metrics::install_recorder` from [`TelemetryGuard::otel_mirror`]. Returns a
/// [`TelemetryGuard`] that flushes export on drop, and is a no-op otherwise; the caller must
/// hold it until exit.
///
/// Export setup is never fatal: an exporter build failure is logged once and the node runs
/// without that signal. Idempotent via `try_init`, so a second call is a no-op and a test
/// may call it, passing `None` to skip export.
pub fn init(
    otlp_endpoint: Option<&str>,
    otlp_headers: Option<&BTreeMap<String, String>>,
    environment: &str,
    otlp_metrics_interval: Option<std::time::Duration>,
    trace_sample_ratio: f64,
) -> TelemetryGuard {
    // Record the deployment environment for the ECS layer and the panic hook. Idempotent:
    // a second init keeps the first value, matching `try_init`.
    let _ = LOG_ENVIRONMENT.set(environment.to_owned());

    // Build the optional OTLP export first. A setup failure is surfaced after the
    // subscriber is installed, below, and is never fatal.
    let (otel_layer, guard, otel_failures) = build_otel(
        otlp_endpoint,
        otlp_headers,
        environment,
        otlp_metrics_interval,
        trace_sample_ratio,
    );

    // The fmt layer carries no level filter of its own: the reloadable filter below gates
    // the whole layer set. The optional otel layer brings only its audit-exclusion filter.
    let fmt_layer: BoxedLayer = match LogFormat::from_env() {
        LogFormat::Json => json_event_layer(std::io::stderr).boxed(),
        // Colour only when stderr is a terminal. tracing-subscriber does not detect one, so
        // `LOG_FORMAT=text 2> node.log`, the documented local-run shape, would otherwise
        // fill the file with escape codes, as would journald or a container runtime.
        LogFormat::Text => text_layer(
            std::io::stderr,
            std::io::IsTerminal::is_terminal(&std::io::stderr()),
        )
        .boxed(),
        LogFormat::Ecs => EcsLayer::new(std::io::stderr, environment.to_owned()).boxed(),
    };

    let mut layers: Vec<BoxedLayer> = vec![fmt_layer];
    if let Some(layer) = otel_layer {
        layers.push(layer);
    }

    // The node-wide level is a single `EnvFilter`, wrapped in a `reload::Layer` so
    // `SIGUSR2` can toggle diagnostic verbosity (see [`toggle_verbose`]) without a restart.
    // It is applied as one per-layer filter over the whole boxed layer set, so a level
    // change gates every layer uniformly: the stderr fmt layer and the otel export layer.
    // The audit-target OTLP exclusion is a separate static per-layer filter inside the otel
    // layer (see `otel::build_layer`) that this reload never touches, so a toggle cannot
    // re-open the audit-export leak.
    let (level_filter, reload_handle) = reload::Layer::new(build_filter());
    // First init wins, mirroring `try_init` and `LOG_ENVIRONMENT`: a second call keeps the
    // first handle.
    let _ = RELOAD_HANDLE.set(reload_handle);

    let _ = tracing_subscriber::registry()
        .with(layers.with_filter(level_filter))
        .try_init();

    // The subscriber is now installed, so surface each export-setup failure through it,
    // once, as a warning. Traces and metrics are attempted independently, and the node keeps
    // running without either signal.
    for failure in otel_failures {
        tracing::warn!(error = %failure, "OTLP exporter setup failed; running without that signal");
    }

    // Surface a set-but-unparseable log directive. `build_filter` fell back to the default,
    // so warn once, now that the subscriber exists, rather than leave a mistyped verbosity
    // change quietly ineffective.
    if let Some((var, value)) = invalid_log_spec() {
        tracing::warn!(
            var,
            value = %value,
            "ignoring unparseable {var}; using the fallback log filter (check the EnvFilter directive syntax)"
        );
    }

    guard
}

/// The JSON event layer: the structured wire schema, defined once here and shared by
/// [`init`] and the schema-pinning test (`build_json_subscriber`).
///
/// `flatten_event(true)` hoists event fields (`message`, `dataset`, `error`, `error_class`,
/// …) to the top level instead of nesting them under `fields`, so a consumer queries
/// `message` and `error_class` directly. Span fields (`request_id`, `method`, `path`) are
/// not flattened: they stay under `span`, the innermost enclosing span, so correlate by
/// `span.request_id`.
///
/// `with_span_list(false)` drops `spans`, the whole ancestor chain, which the formatter
/// emits by default on every line. For a request line the chain is one span, so `spans`
/// repeats `span` verbatim and accounts for most of the line's bytes, and nothing documented
/// reads it. An ingest line keeps `dataset` and `channel` on its own `span`; a line inside a
/// supervised loop keeps `daemon{task}` there.
///
/// A new structured field must never reuse a reserved top-level key (`timestamp`, `level`,
/// `target`, `message`, `span`), or it would collide after flattening.
fn json_event_layer<S, W>(make_writer: W) -> impl tracing_subscriber::Layer<S>
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    W: for<'a> fmt::MakeWriter<'a> + Send + Sync + 'static,
{
    fmt::layer()
        .json()
        .flatten_event(true)
        .with_span_list(false)
        .with_writer(make_writer)
}

/// The human-readable text layer (`LOG_FORMAT=text`). `ansi` decides whether the line
/// carries colour escapes; [`init`] passes whether stderr is a terminal, so a run
/// redirected to a file or captured by a runtime gets plain text (pinned by
/// `text_format_colours_only_when_asked`).
fn text_layer<S, W>(make_writer: W, ansi: bool) -> impl tracing_subscriber::Layer<S>
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    W: for<'a> fmt::MakeWriter<'a> + Send + Sync + 'static,
{
    fmt::layer().with_ansi(ansi).with_writer(make_writer)
}

/// A `tracing` field visitor that records fields into a JSON map: identifiers stay strings,
/// counts and durations stay numbers, and `?` or `%` fields land as their formatted string.
/// Shared by the ECS event layer for both span and event fields.
struct JsonVisitor<'a>(&'a mut Map<String, Value>);

impl Visit for JsonVisitor<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_owned(), Value::from(value));
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.insert(field.name().to_owned(), Value::from(value));
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.0.insert(field.name().to_owned(), Value::from(value));
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().to_owned(), Value::from(value));
    }
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.0.insert(field.name().to_owned(), Value::from(value));
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0
            .insert(field.name().to_owned(), Value::from(format!("{value:?}")));
    }
}

/// One span's recorded fields as JSON, kept in the span's extensions so
/// [`EcsLayer::on_event`] can fold the active scope's fields into the event line.
struct EcsSpanFields(Map<String, Value>);

/// The ECS-native HTTP fields for the lines inside a request span.
///
/// Left under `labels.*`, the request span's `method`, `path` and `request_id` and the
/// access-log event's `status` and `latency_us` are invisible to HTTP views, APM correlation
/// and an ECS component template. They are lifted to the ECS names on every line the span
/// encloses, and only there (`in_request_span`): outside it a `path` is a filesystem path —
/// an ingest working dir, a sidecar, an override file — and stays under `labels.path`, as
/// the table in docs/operating.md §15 says. `status` and the duration are lifted only on the
/// access-log line itself (`event = "http_request"`), the one event that carries them.
/// `event.duration` is nanoseconds in ECS.
fn lift_http_fields(
    labels: &mut Map<String, Value>,
    in_request_span: bool,
) -> Vec<(&'static str, Value)> {
    let mut lifted: Vec<(&'static str, Value)> = Vec::new();
    if in_request_span {
        for (from, to) in [
            ("method", "http.request.method"),
            ("path", "url.path"),
            ("request_id", "http.request.id"),
        ] {
            if let Some(v) = labels.remove(from) {
                lifted.push((to, v));
            }
        }
    }
    if labels.get("event").and_then(Value::as_str) == Some("http_request") {
        if let Some(v) = labels.remove("status") {
            lifted.push(("http.response.status_code", v));
        }
        if let Some(us) = labels.remove("latency_us").and_then(|v| v.as_u64()) {
            lifted.push(("event.duration", Value::from(us.saturating_mul(1000))));
        }
    }
    lifted
}

/// Fold one span or event field into the ECS output. The OTLP-populated `trace_id` and
/// `span_id`, which are empty outside an `otel` build, lift to ECS `trace.id` and `span.id`
/// so logs correlate to APM traces. Everything else goes under `labels.*`, a keyword bag, so
/// arbitrary fields never explode the index mapping.
fn fold_ecs_field(
    labels: &mut Map<String, Value>,
    trace_id: &mut Option<String>,
    span_id: &mut Option<String>,
    key: &str,
    value: &Value,
) {
    match key {
        "trace_id" => {
            if let Value::String(s) = value
                && !s.is_empty()
            {
                *trace_id = Some(s.clone());
            }
        }
        "span_id" => {
            if let Value::String(s) = value
                && !s.is_empty()
            {
                *span_id = Some(s.clone());
            }
        }
        // `otel.name`, `otel.kind` and `otel.status_code` steer the trace export — the
        // span's exported name, kind and status. They are not log content, and the request
        // span's `http.route` already says what `otel.name` says.
        k if k.starts_with("otel.") => {}
        _ => {
            labels.insert(key.to_owned(), value.clone());
        }
    }
}

/// A `tracing` layer that writes each event as one line of ECS (Elastic Common Schema) JSON
/// to its writer. Selected by `LOG_FORMAT=ecs`, so logs land with ECS field names and an ECS
/// dashboard works without an ingest pipeline. Dotted ECS keys (`log.level`, `service.name`,
/// …) are emitted directly, and the store expands the dots. Event and span fields go under
/// `labels.*`. Same call-site secret-free contract as the other layers.
struct EcsLayer<W> {
    make_writer: W,
    /// Deployment environment emitted as ECS `service.environment`; omitted when empty.
    environment: String,
}

impl<W> EcsLayer<W> {
    fn new(make_writer: W, environment: String) -> Self {
        Self {
            make_writer,
            environment,
        }
    }
}

impl<S, W> tracing_subscriber::Layer<S> for EcsLayer<W>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    W: for<'a> fmt::MakeWriter<'a> + 'static,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let mut fields = Map::new();
        attrs.record(&mut JsonVisitor(&mut fields));
        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(EcsSpanFields(fields));
        }
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            let mut ext = span.extensions_mut();
            if let Some(EcsSpanFields(map)) = ext.get_mut::<EcsSpanFields>() {
                values.record(&mut JsonVisitor(map));
            }
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let meta = event.metadata();
        let mut event_fields = Map::new();
        event.record(&mut JsonVisitor(&mut event_fields));
        let message = match event_fields.remove("message") {
            Some(Value::String(s)) => s,
            Some(other) => other.to_string(),
            None => String::new(),
        };
        // A call site that needs a human says `alert = true`, and the line carries
        // `tags: ["Alert"]`, the field a log rule routes on, beside the `event.action` and
        // `event.outcome` the site names. Those are ECS core fields, so they sit at the top
        // level rather than under `labels.*`. Read from the event's own fields only: a
        // span-level `alert` would tag every line inside it. The tagged conditions are
        // listed in docs/operating.md §15 and bound to the sites by
        // scripts/tests/test_alert_tag_shape.py.
        let alert = event_fields
            .get("alert")
            .is_some_and(|v| *v == Value::Bool(true));
        if alert {
            event_fields.remove("alert");
        }
        let event_action = event_fields.remove("event.action");
        let event_outcome = event_fields.remove("event.outcome");

        // Fold the active scope's span fields, root to leaf, then the event fields, into
        // ECS `labels.*`, lifting any OTLP trace and span ids to correlation fields.
        let mut labels = Map::new();
        let mut trace_id: Option<String> = None;
        let mut span_id: Option<String> = None;
        // Whether this line sits inside the HTTP request span, the one whose `method`,
        // `path` and `request_id` are HTTP facts. Decided by the span, not by field name:
        // many non-HTTP sites log `path = %some_path.display()`, and lifting by name would
        // put a filesystem path under ECS `url.path` on every one of them.
        let mut in_request_span = false;
        if let Some(scope) = ctx.event_scope(event) {
            for span in scope.from_root() {
                if span.name() == "http_request" {
                    in_request_span = true;
                }
                if let Some(fields) = span.extensions().get::<EcsSpanFields>() {
                    for (k, v) in &fields.0 {
                        fold_ecs_field(&mut labels, &mut trace_id, &mut span_id, k, v);
                    }
                }
            }
        }
        for (k, v) in &event_fields {
            fold_ecs_field(&mut labels, &mut trace_id, &mut span_id, k, v);
        }

        let lifted = lift_http_fields(&mut labels, in_request_span);

        let mut obj = Map::new();
        obj.insert(
            "@timestamp".to_owned(),
            Value::from(gdi_node_standalone_core::util::now_rfc3339_nanos()),
        );
        obj.insert(
            "log.level".to_owned(),
            Value::from(meta.level().as_str().to_ascii_lowercase()),
        );
        obj.insert("message".to_owned(), Value::from(message));
        obj.insert("ecs.version".to_owned(), Value::from("8.11.0"));
        obj.insert(
            "service.name".to_owned(),
            Value::from(env!("CARGO_PKG_NAME")),
        );
        obj.insert(
            "service.version".to_owned(),
            Value::from(env!("CARGO_PKG_VERSION")),
        );
        if !self.environment.is_empty() {
            obj.insert(
                "service.environment".to_owned(),
                Value::from(self.environment.as_str()),
            );
        }
        obj.insert("log.logger".to_owned(), Value::from(meta.target()));
        if let Some(action) = event_action {
            obj.insert("event.action".to_owned(), action);
        }
        if let Some(outcome) = event_outcome {
            obj.insert("event.outcome".to_owned(), outcome);
        }
        if alert {
            obj.insert("tags".to_owned(), Value::from(vec!["Alert"]));
        }
        if let Some(t) = trace_id {
            obj.insert("trace.id".to_owned(), Value::from(t));
        }
        if let Some(s) = span_id {
            obj.insert("span.id".to_owned(), Value::from(s));
        }
        for (key, value) in lifted {
            obj.insert(key.to_owned(), value);
        }
        if !labels.is_empty() {
            obj.insert("labels".to_owned(), Value::Object(labels));
        }

        // serde_json never emits an interior newline for these values, so this is one
        // NDJSON line.
        let mut writer = self.make_writer.make_writer();
        let _ = writeln!(writer, "{}", Value::Object(obj));
    }
}

/// Build the JSON subscriber for the schema-pinning test: [`json_event_layer`] over an
/// [`EnvFilter`] on the registry.
#[cfg(test)]
fn build_json_subscriber<W>(make_writer: W) -> impl tracing::Subscriber + Send + Sync
where
    W: for<'a> fmt::MakeWriter<'a> + Send + Sync + 'static,
{
    tracing_subscriber::registry()
        .with(build_filter())
        .with(json_event_layer(make_writer))
}

/// OpenTelemetry export wiring for the `otel` feature: the trace layer and the metrics
/// push. In its own module, so a non-otel build compiles none of it.
#[cfg(feature = "otel")]
pub(crate) mod otel {
    use opentelemetry::metrics::MeterProvider as _;
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::WithExportConfig as _;
    use opentelemetry_otlp::WithHttpConfig as _;
    use opentelemetry_sdk::Resource;
    use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
    use opentelemetry_sdk::trace::SdkTracerProvider;
    use tracing_subscriber::Layer as _;
    use tracing_subscriber::Registry;

    /// `[service].otlp_endpoint` is the collector base, such as `http://collector:4318`.
    /// `with_endpoint` treats its argument as the signal-specific URL and uses it as is: the
    /// `/v1/<signal>` suffix is appended only when the endpoint comes from the OTLP
    /// environment variable, never from the programmatic setter. So the signal path is
    /// appended here; otherwise the export POSTs to the collector root and 404s silently,
    /// because export errors are best-effort and swallowed. Idempotent if the operator
    /// already included the path.
    fn signal_url(endpoint: &str, path: &str) -> String {
        let base = endpoint.trim_end_matches('/');
        if base.ends_with(path) {
            base.to_owned()
        } else {
            format!("{base}{path}")
        }
    }

    /// Optional per-request headers, such as an `Authorization` API key for a
    /// token-protected collector, in the shape the exporter builders take. Over `https://`,
    /// which any build carrying the `tls` feature group speaks, the header is protected in
    /// transit; preflight warns about a secret over plaintext `http://` in production.
    fn header_map(
        headers: Option<&std::collections::BTreeMap<String, String>>,
    ) -> std::collections::HashMap<String, String> {
        headers
            .map(|h| h.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default()
    }

    /// Transition-only health of one OTLP export path.
    ///
    /// The SDK swallows export errors (see `signal_url`), so a dead collector leaves no
    /// local signal. The alert for a dark signal is the receiving side's absence rule, such
    /// as `NodeMetricsAbsent`, because a node that cannot export cannot alert through the
    /// path that is down. So this is a WARN rather than `alert = true`: it delivers the
    /// cause over the log pipeline, which is separate from the OTLP push in the deployed
    /// shape.
    ///
    /// Transition-only, because an alarm-adjacent line must not repeat per tick: one WARN
    /// when the path starts failing, one INFO when it recovers, nothing in between.
    #[derive(Debug)]
    pub(super) struct ExportHealth {
        signal: &'static str,
        failing: std::sync::atomic::AtomicBool,
    }

    impl ExportHealth {
        pub(super) fn new(signal: &'static str) -> Self {
            Self {
                signal,
                failing: std::sync::atomic::AtomicBool::new(false),
            }
        }

        /// Record one export outcome; log only the transitions.
        pub(super) fn observe(&self, result: &opentelemetry_sdk::error::OTelSdkResult) {
            use std::sync::atomic::Ordering;
            match result {
                Err(error) => {
                    if !self.failing.swap(true, Ordering::Relaxed) {
                        tracing::warn!(
                            event.action = "otlp.export",
                            event.outcome = "failure",
                            signal = self.signal,
                            error = %error,
                            "OTLP export failing; this signal is not reaching the \
                             collector (logged once per outage; recovery is logged)"
                        );
                    }
                }
                Ok(()) => {
                    if self.failing.swap(false, Ordering::Relaxed) {
                        tracing::info!(
                            event.action = "otlp.export",
                            event.outcome = "success",
                            signal = self.signal,
                            "OTLP export recovered"
                        );
                    }
                }
            }
        }
    }

    /// [`opentelemetry_sdk::metrics::exporter::PushMetricExporter`] wrapper that runs every
    /// export outcome through [`ExportHealth`]. Pure forwarding otherwise.
    pub(super) struct WatchedMetricExporter<E> {
        pub(super) inner: E,
        pub(super) health: ExportHealth,
    }

    impl<E: opentelemetry_sdk::metrics::exporter::PushMetricExporter>
        opentelemetry_sdk::metrics::exporter::PushMetricExporter for WatchedMetricExporter<E>
    {
        async fn export(
            &self,
            metrics: &opentelemetry_sdk::metrics::data::ResourceMetrics,
        ) -> opentelemetry_sdk::error::OTelSdkResult {
            let result = self.inner.export(metrics).await;
            self.health.observe(&result);
            result
        }

        fn force_flush(&self) -> opentelemetry_sdk::error::OTelSdkResult {
            self.inner.force_flush()
        }

        fn shutdown_with_timeout(
            &self,
            timeout: std::time::Duration,
        ) -> opentelemetry_sdk::error::OTelSdkResult {
            self.inner.shutdown_with_timeout(timeout)
        }

        fn temporality(&self) -> opentelemetry_sdk::metrics::Temporality {
            self.inner.temporality()
        }
    }

    /// [`opentelemetry_sdk::trace::SpanExporter`] wrapper, with the same contract as
    /// [`WatchedMetricExporter`]. `set_resource` must forward, or the OTLP exporter would
    /// encode spans with an empty resource and no `service.name`.
    #[derive(Debug)]
    pub(super) struct WatchedSpanExporter<E> {
        pub(super) inner: E,
        pub(super) health: ExportHealth,
    }

    impl<E: opentelemetry_sdk::trace::SpanExporter> opentelemetry_sdk::trace::SpanExporter
        for WatchedSpanExporter<E>
    {
        async fn export(
            &self,
            batch: Vec<opentelemetry_sdk::trace::SpanData>,
        ) -> opentelemetry_sdk::error::OTelSdkResult {
            let result = self.inner.export(batch).await;
            self.health.observe(&result);
            result
        }

        fn shutdown_with_timeout(
            &self,
            timeout: std::time::Duration,
        ) -> opentelemetry_sdk::error::OTelSdkResult {
            self.inner.shutdown_with_timeout(timeout)
        }

        fn force_flush(&self) -> opentelemetry_sdk::error::OTelSdkResult {
            self.inner.force_flush()
        }

        fn set_resource(&mut self, resource: &Resource) {
            self.inner.set_resource(resource);
        }
    }

    /// The Resource both signals carry: the service name, version and build SHA, and, when
    /// set, the deployment environment under the OpenTelemetry semantic convention
    /// `deployment.environment`, so a backend can filter and group by environment as the ECS
    /// logs do. `service.version` mirrors the ECS log layer's value, keeping log, trace and
    /// metric identity consistent, and the git SHA makes side-by-side rolling-upgrade builds
    /// distinguishable. `service.instance.id` defaults to the hostname, which in Kubernetes
    /// is the pod name, unless `OTEL_RESOURCE_ATTRIBUTES` sets one; see
    /// `default_instance_id`.
    fn resource(environment: &str) -> Resource {
        let mut resource = Resource::builder()
            .with_service_name(env!("CARGO_PKG_NAME"))
            .with_attribute(opentelemetry::KeyValue::new(
                "service.version",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_attribute(opentelemetry::KeyValue::new(
                "service.build.git_sha",
                gdi_build_info::GIT_SHA,
            ));
        if !environment.is_empty() {
            resource = resource.with_attribute(opentelemetry::KeyValue::new(
                "deployment.environment",
                environment.to_owned(),
            ));
        }
        // A stable per-replica `service.instance.id` — the hostname, which in Kubernetes is
        // the pod name — so two replicas' pushed series stay distinguishable. Only when the
        // operator's `OTEL_RESOURCE_ATTRIBUTES` has not set one: the builder's env detector
        // has already read that variable into the base resource, and a `with_attribute` here
        // would override it, the wrong direction for an operator knob.
        if let Some(id) = default_instance_id(
            std::env::var("OTEL_RESOURCE_ATTRIBUTES").ok().as_deref(),
            host_name(),
        ) {
            resource =
                resource.with_attribute(opentelemetry::KeyValue::new("service.instance.id", id));
        }
        resource.build()
    }

    /// The instance id to add, or `None` when the operator environment already names one,
    /// whose value must win, or when no hostname is known. Never invents an id.
    pub(super) fn default_instance_id(
        env_attributes: Option<&str>,
        hostname: Option<String>,
    ) -> Option<String> {
        let env_has_one = env_attributes.is_some_and(|value| {
            value
                .split(',')
                .any(|pair| pair.split('=').next().map(str::trim) == Some("service.instance.id"))
        });
        if env_has_one { None } else { hostname }
    }

    /// The hostname, from the `HOSTNAME` environment variable, which containers and most
    /// shells set, falling back to `/proc/sys/kernel/hostname`. Both are dependency-free.
    fn host_name() -> Option<String> {
        let trimmed_nonempty = |raw: String| {
            let value = raw.trim().to_owned();
            (!value.is_empty()).then_some(value)
        };
        std::env::var("HOSTNAME")
            .ok()
            .and_then(trimmed_nonempty)
            .or_else(|| {
                std::fs::read_to_string("/proc/sys/kernel/hostname")
                    .ok()
                    .and_then(trimmed_nonempty)
            })
    }

    /// Build the OTLP/HTTP protobuf metric exporter behind a periodic reader, on its own
    /// thread because the reqwest client is blocking, as for the span exporter, plus the
    /// [`SdkMeterProvider`] that owns it. Returns the provider, whose `shutdown` pushes the
    /// final collection, and the meter the `metrics_otel` mirror records into.
    ///
    /// # Errors
    /// The exporter could not be built (a malformed endpoint or header).
    pub(crate) fn build_meter_provider(
        endpoint: &str,
        headers: Option<&std::collections::BTreeMap<String, String>>,
        environment: &str,
        interval: std::time::Duration,
    ) -> anyhow::Result<(SdkMeterProvider, opentelemetry::metrics::Meter)> {
        let exporter = opentelemetry_otlp::MetricExporter::builder()
            .with_http()
            .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
            .with_endpoint(signal_url(endpoint, "/v1/metrics"))
            .with_headers(header_map(headers))
            .build()?;
        // The SDK swallows export errors; the wrapper logs the transitions.
        let exporter = WatchedMetricExporter {
            inner: exporter,
            health: ExportHealth::new("metrics"),
        };
        let reader = PeriodicReader::builder(exporter)
            .with_interval(interval)
            .build();
        let provider = SdkMeterProvider::builder()
            .with_reader(reader)
            .with_resource(resource(environment))
            .build();
        let meter = provider.meter(env!("CARGO_PKG_NAME"));
        Ok((provider, meter))
    }

    /// Build the OTLP/HTTP protobuf span exporter, a batch [`SdkTracerProvider`], and the
    /// `tracing-opentelemetry` layer carrying the content-free filter. That is the only
    /// filter on this layer: a hard exclusion of [`super::AUDIT_TARGET`], the one site that
    /// can carry beacon query detail. The node-wide level `EnvFilter` is not attached here;
    /// [`super::init`] applies it over the whole layer set. Returns the boxed layer and the
    /// provider, whose `shutdown` flushes batched spans on exit.
    pub(super) fn build_layer(
        endpoint: &str,
        headers: Option<&std::collections::BTreeMap<String, String>>,
        environment: &str,
        trace_sample_ratio: f64,
    ) -> anyhow::Result<(
        Box<dyn tracing_subscriber::Layer<Registry> + Send + Sync>,
        SdkTracerProvider,
    )> {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
            .with_endpoint(signal_url(endpoint, "/v1/traces"))
            .with_headers(header_map(headers))
            .build()?;
        // The same transition-only export-failure signal as the metrics path.
        let exporter = WatchedSpanExporter {
            inner: exporter,
            health: ExportHealth::new("traces"),
        };

        // `[service].otlp_trace_sample_ratio` is parent-based, so a request carrying a
        // trusted upstream `traceparent` follows its parent's decision and a sampled
        // upstream trace is never cut off here, while a root trace is kept with the
        // configured probability. The default `1.0` is the SDK's always-on shape, spelled
        // out so the ratio path is the only one and there is no second path to test.
        let sampler = opentelemetry_sdk::trace::Sampler::ParentBased(Box::new(
            opentelemetry_sdk::trace::Sampler::TraceIdRatioBased(
                trace_sample_ratio.clamp(0.0, 1.0),
            ),
        ));
        let provider = SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_sampler(sampler)
            .with_resource(resource(environment))
            .build();

        // Register the W3C trace-context propagator globally so the node can adopt an
        // inbound `traceparent` as a span's parent when
        // `[service].trust_inbound_traceparent` is set. Harmless when the flag is off,
        // because nothing calls `extract`. It activates together with the export layer, so
        // trace ingestion is only ever live alongside export.
        opentelemetry::global::set_text_map_propagator(
            opentelemetry_sdk::propagation::TraceContextPropagator::new(),
        );

        let tracer = provider.tracer(env!("CARGO_PKG_NAME"));

        // Content-free by construction: never export the `audit` target. This is the only
        // filter on the export layer, because the node-wide level filter is the global
        // reloadable `EnvFilter` in [`super::init`], so a `SIGUSR2` verbosity toggle cannot
        // touch, and therefore cannot re-open, this exclusion. A typo here would re-open the
        // leak, so the constant is shared with the log path and unit-tested.
        let layer = tracing_layer(tracer)
            .with_filter(tracing_subscriber::filter::filter_fn(super::export_allowed))
            .boxed();
        Ok((layer, provider))
    }

    /// The `tracing`-to-OpenTelemetry bridge, configured. The bridge's defaults stamp
    /// `code.file.path`, `code.module.name`, `code.line.number`, `thread.id`, `thread.name`,
    /// `busy_ns` and `idle_ns` on every span — eight attributes that say the same thing on
    /// every one of the node's spans, and most of what an exported `http_request` would
    /// carry. They are off; the span's own fields are what an operator reads. Shared with
    /// the span-shape test, so what the test exercises is what ships.
    pub(super) fn tracing_layer<S>(
        tracer: opentelemetry_sdk::trace::SdkTracer,
    ) -> tracing_opentelemetry::OpenTelemetryLayer<S, opentelemetry_sdk::trace::SdkTracer>
    where
        S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    {
        tracing_opentelemetry::layer()
            .with_tracer(tracer)
            .with_location(false)
            .with_threads(false)
            .with_tracked_inactivity(false)
    }
}

/// Install a process-level panic hook that renders every panic — caught or escaping, from
/// any thread, from `spawn_blocking`, or from startup — as a single structured JSON line on
/// stderr, so all of stderr stays valid NDJSON for a line-based collector.
///
/// The line carries the panic message and location only, never a captured value: the payload
/// is a `&str` or `String` message, not a formatted secret-bearing struct. It is written
/// directly rather than through `tracing`, so it works even if a panic happens before the
/// subscriber is installed, and it is one self-contained document.
///
/// One exception: while
/// [`gdi_node_standalone_core::panic_guard::handled_decode_in_progress`] is true on the
/// panicking thread, this does not write the raw panic line. A panic hook fires before
/// `catch_unwind` sees the unwind, so without the check every malformed provider parquet —
/// a case `core`'s decode paths catch and turn into a clean `InvalidParquet` — would write a
/// full stderr line indistinguishable at a glance from a real crash. It is downgraded to a
/// `tracing` `debug` event with the message and location only: visible with `RUST_LOG=debug`
/// and invisible at the default level. It goes through `tracing` rather than direct stderr
/// because by the time a decode panic can happen, during ingest rather than startup, the
/// subscriber is initialized.
pub fn install_panic_hook() {
    let ecs = matches!(LogFormat::from_env(), LogFormat::Ecs);
    std::panic::set_hook(Box::new(move |info| {
        let payload = info.payload();
        let message = payload
            .downcast_ref::<&str>()
            .map(|s| (*s).to_owned())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "panic".to_owned());
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()));

        if gdi_node_standalone_core::panic_guard::handled_decode_in_progress() {
            tracing::debug!(
                message = %message,
                location = location.as_deref().unwrap_or("unknown"),
                "panic in a handled decode path (caught by catch_unwind; not a crash)"
            );
            return;
        }

        let line = if ecs {
            // Read the environment lazily: the hook is installed before config load, so
            // `init` may not have recorded it at install time.
            render_panic_ecs(&message, location.as_deref(), log_environment())
        } else {
            render_panic_json(&message, location.as_deref())
        };
        // Best-effort: a single write of one line to stderr.
        let mut stderr = std::io::stderr().lock();
        let _ = stderr.write_all(line.as_bytes());
        let _ = stderr.write_all(b"\n");
        let _ = stderr.flush();
    }));
}

/// Render a panic as one JSON document whose core field schema matches the `tracing` JSON
/// layer (`timestamp`, `level`, `target`, `message`), plus a panic-only `location` and the
/// `service.name` and `service.version` provenance fields, and `service.environment` when
/// the deployment environment is set. Those last three are not emitted by the plain
/// `tracing` JSON layer. A line-based collector then indexes panic and structured lines
/// under the same `timestamp`, `message` and `level` fields. Kept pure so a test can assert
/// it is single-line valid JSON without installing a process hook.
#[must_use]
pub fn render_panic_json(message: &str, location: Option<&str>) -> String {
    let timestamp = gdi_node_standalone_core::util::now_rfc3339_nanos();
    let mut obj = serde_json::Map::new();
    obj.insert("timestamp".to_owned(), serde_json::Value::String(timestamp));
    obj.insert(
        "level".to_owned(),
        serde_json::Value::String("ERROR".to_owned()),
    );
    obj.insert(
        "target".to_owned(),
        serde_json::Value::String("panic".to_owned()),
    );
    obj.insert(
        "message".to_owned(),
        serde_json::Value::String(message.to_owned()),
    );
    if let Some(loc) = location {
        obj.insert(
            "location".to_owned(),
            serde_json::Value::String(loc.to_owned()),
        );
    }
    // Provenance: stamp the node name and version, and the environment when set, so a
    // crash line is attributable to a build and a deployment. A panic is when an operator
    // needs to know which version and environment crashed without cross-referencing the boot
    // line. The ECS panic renderer carries the same fields.
    obj.insert(
        "service.name".to_owned(),
        serde_json::Value::String(env!("CARGO_PKG_NAME").to_owned()),
    );
    obj.insert(
        "service.version".to_owned(),
        serde_json::Value::String(env!("CARGO_PKG_VERSION").to_owned()),
    );
    if let Some(env) = log_environment() {
        obj.insert(
            "service.environment".to_owned(),
            serde_json::Value::String(env.to_owned()),
        );
    }
    // serde_json never emits an interior newline for these scalar values, so this is
    // single-line.
    serde_json::Value::Object(obj).to_string()
}

/// Render a panic as one ECS JSON document, the counterpart of [`render_panic_json`], so
/// under `LOG_FORMAT=ecs` panic lines share the structured lines' ECS schema. Message and
/// location only, never a captured value. A non-empty `environment` is emitted as ECS
/// `service.environment`, matching the `EcsLayer`'s structured lines.
#[must_use]
pub fn render_panic_ecs(
    message: &str,
    location: Option<&str>,
    environment: Option<&str>,
) -> String {
    let mut obj = Map::new();
    obj.insert(
        "@timestamp".to_owned(),
        Value::from(gdi_node_standalone_core::util::now_rfc3339_nanos()),
    );
    obj.insert("log.level".to_owned(), Value::from("error"));
    obj.insert("message".to_owned(), Value::from(message));
    obj.insert("ecs.version".to_owned(), Value::from("8.11.0"));
    obj.insert(
        "service.name".to_owned(),
        Value::from(env!("CARGO_PKG_NAME")),
    );
    // Emit `service.version` too, so the panic-path envelope matches the normal ECS log
    // layer's (`on_event`). Otherwise an operator's index template has to accept two
    // different ECS shapes.
    obj.insert(
        "service.version".to_owned(),
        Value::from(env!("CARGO_PKG_VERSION")),
    );
    if let Some(env) = environment.filter(|e| !e.is_empty()) {
        obj.insert("service.environment".to_owned(), Value::from(env));
    }
    obj.insert("log.logger".to_owned(), Value::from("panic"));
    if let Some(loc) = location {
        let mut labels = Map::new();
        labels.insert("location".to_owned(), Value::from(loc));
        obj.insert("labels".to_owned(), Value::Object(labels));
    }
    Value::Object(obj).to_string()
}

/// The `target`, `log.logger` and `event.action` of a refused start. `message` is the
/// top-level error and the chain beside it is the full `context` chain (`a: b: c`), so the
/// line names the operator-facing reason first and keeps the detail next to it.
const FATAL_TARGET: &str = "startup";

/// Render a refused start as one JSON line in the `LogFormat::Json` shape, keyed like
/// [`render_panic_json`] so a collector indexes it beside the structured lines. It carries
/// `event.action = "startup"`, `event.outcome = "failure"` and `tags = ["Alert"]`, which
/// makes the one fatal class a metric rule cannot see — the process is gone before
/// `/metrics` exists — routable by a log rule, with its reason. Kept pure so a test can
/// assert it is single-line valid JSON.
#[must_use]
pub fn render_fatal_json(message: &str, chain: &str) -> String {
    let mut obj = serde_json::Map::new();
    obj.insert(
        "timestamp".to_owned(),
        Value::from(gdi_node_standalone_core::util::now_rfc3339_nanos()),
    );
    obj.insert("level".to_owned(), Value::from("ERROR"));
    obj.insert("target".to_owned(), Value::from(FATAL_TARGET));
    obj.insert("message".to_owned(), Value::from(message));
    obj.insert("error".to_owned(), Value::from(chain));
    obj.insert("event.action".to_owned(), Value::from(FATAL_TARGET));
    obj.insert("event.outcome".to_owned(), Value::from("failure"));
    obj.insert("tags".to_owned(), Value::from(vec!["Alert"]));
    obj.insert(
        "service.name".to_owned(),
        Value::from(env!("CARGO_PKG_NAME")),
    );
    obj.insert(
        "service.version".to_owned(),
        Value::from(env!("CARGO_PKG_VERSION")),
    );
    if let Some(env) = log_environment() {
        obj.insert("service.environment".to_owned(), Value::from(env));
    }
    Value::Object(obj).to_string()
}

/// The ECS counterpart of [`render_fatal_json`], for `LOG_FORMAT=ecs`: the same facts in
/// the `EcsLayer` envelope, as `log.level`, `error.message`, `event.action`,
/// `event.outcome` and `tags`.
#[must_use]
pub fn render_fatal_ecs(message: &str, chain: &str, environment: Option<&str>) -> String {
    let mut obj = Map::new();
    obj.insert(
        "@timestamp".to_owned(),
        Value::from(gdi_node_standalone_core::util::now_rfc3339_nanos()),
    );
    obj.insert("log.level".to_owned(), Value::from("error"));
    obj.insert("message".to_owned(), Value::from(message));
    obj.insert("ecs.version".to_owned(), Value::from("8.11.0"));
    obj.insert(
        "service.name".to_owned(),
        Value::from(env!("CARGO_PKG_NAME")),
    );
    obj.insert(
        "service.version".to_owned(),
        Value::from(env!("CARGO_PKG_VERSION")),
    );
    if let Some(env) = environment.filter(|e| !e.is_empty()) {
        obj.insert("service.environment".to_owned(), Value::from(env));
    }
    obj.insert("log.logger".to_owned(), Value::from(FATAL_TARGET));
    obj.insert("error.message".to_owned(), Value::from(chain));
    obj.insert("event.action".to_owned(), Value::from(FATAL_TARGET));
    obj.insert("event.outcome".to_owned(), Value::from("failure"));
    obj.insert("tags".to_owned(), Value::from(vec!["Alert"]));
    Value::Object(obj).to_string()
}

/// The human counterpart of [`render_fatal_json`], for `LOG_FORMAT=text`: the reason on one
/// line, in the single-line shape the text layer emits for every other record.
///
/// `text` is the format a person selects when a person is reading, and a refused start is
/// the one message a first-run operator is guaranteed to meet. Folded into the JSON
/// renderer, that operator would get a machine envelope for "your config file is missing",
/// with the reason quoted twice inside it.
///
/// The alarm contract is unaffected: routing keys on `tags: ["Alert"]`, which only the
/// `json` and `ecs` renderers emit, and a deployment that routes alarms runs one of those.
/// `text` is the local and interactive format (see the `LOG_FORMAT` note in
/// docs/operating.md §15), so there is nothing here for a collector to lose.
///
/// The full cause chain is kept, being the diagnostic value of the line, and the bare
/// `message` is dropped, because `{error:#}` already opens with it.
#[must_use]
pub fn render_fatal_text(chain: &str) -> String {
    format!("ERROR {FATAL_TARGET}: {chain}")
}

/// Write a refused start to stderr as one structured line in the configured `LOG_FORMAT`,
/// then return; the caller sets the exit status. Written directly, like the panic hook,
/// because most refusals happen before the subscriber exists: an unreadable config fails
/// before `init` runs. Best-effort, since a write failure on stderr has nowhere to report
/// to.
pub fn report_fatal(error: &anyhow::Error) {
    let message = error.to_string();
    let chain = format!("{error:#}");
    let line = match LogFormat::from_env() {
        LogFormat::Ecs => render_fatal_ecs(&message, &chain, log_environment()),
        LogFormat::Text => render_fatal_text(&chain),
        LogFormat::Json => render_fatal_json(&message, &chain),
    };
    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_all(line.as_bytes());
    let _ = stderr.write_all(b"\n");
    let _ = stderr.flush();
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;

    /// A refused start renders as one JSON line carrying the alarm tag and the cause chain,
    /// the shape a log rule routes on.
    #[test]
    fn fatal_json_is_single_line_and_alert_tagged() {
        let line = render_fatal_json(
            "loading config: /etc/x.toml",
            "loading config: /etc/x.toml: No such file \"or\" directory\n",
        );
        assert!(!line.contains('\n'), "must be one line: {line}");
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["level"], "ERROR");
        assert_eq!(v["target"], "startup");
        assert_eq!(v["event.action"], "startup");
        assert_eq!(v["event.outcome"], "failure");
        assert_eq!(v["tags"], serde_json::json!(["Alert"]));
        assert_eq!(v["message"], "loading config: /etc/x.toml");
        assert!(v["error"].as_str().unwrap().contains("No such file"));
        assert_eq!(v["service.name"], env!("CARGO_PKG_NAME"));
    }

    #[test]
    fn fatal_ecs_has_ecs_shape_and_optional_environment() {
        let with = render_fatal_ecs("refused", "refused: because", Some("prod"));
        let v: serde_json::Value = serde_json::from_str(&with).unwrap();
        assert_eq!(v["log.level"], "error");
        assert_eq!(v["ecs.version"], "8.11.0");
        assert_eq!(v["log.logger"], "startup");
        assert_eq!(v["error.message"], "refused: because");
        assert_eq!(v["event.action"], "startup");
        assert_eq!(v["event.outcome"], "failure");
        assert_eq!(v["tags"], serde_json::json!(["Alert"]));
        assert_eq!(v["service.environment"], "prod");
        let without = render_fatal_ecs("refused", "refused", None);
        let v: serde_json::Value = serde_json::from_str(&without).unwrap();
        assert!(v.get("service.environment").is_none());
    }

    /// `LOG_FORMAT=text` renders the refusal for a person: one line, the cause chain, and no
    /// JSON envelope.
    ///
    /// Bound as a test because the failure is silent and lands on a first impression:
    /// sharing the `Json` arm would give a developer running the node in a terminal with the
    /// documented human format a machine envelope for "your config file is missing".
    /// Asserting the absence of `{` is what fails if the arm is folded back.
    #[test]
    fn fatal_text_is_one_human_line_without_a_json_envelope() {
        let line = render_fatal_text(
            "loading config: config file not found: /etc/x.toml: No such file or directory",
        );
        assert!(!line.contains('\n'), "must be one line: {line}");
        assert!(
            !line.contains('{'),
            "text must not carry a JSON envelope: {line}"
        );
        assert!(line.starts_with("ERROR startup: "), "got: {line}");
        assert!(
            line.contains("No such file or directory"),
            "the cause chain is the whole diagnostic value: {line}"
        );
    }

    /// A failed log-level change must not consume a generation.
    ///
    /// The generation is what a scheduled auto-revert compares itself against, so bumping it
    /// on a failed change would cancel a legitimate pending revert and leave `debug` on for
    /// the rest of the process, the outcome the bounded window exists to prevent. Here the
    /// subscriber is not installed, because this test binary never calls `init`, so
    /// `set_verbose` genuinely cannot apply a filter.
    ///
    /// The other half of the invariant — that `SIGUSR2` supersedes a pending revert too — is
    /// structural rather than asserted: the counter lives beside `VERBOSE` and `set_verbose`
    /// is its only writer, so every trigger that changes the level bumps it by construction.
    /// It cannot be exercised in-process because `RELOAD_HANDLE` is a process-wide `OnceLock`
    /// only `init` fills; `scripts/e2e/run-full.sh` drives the real subscriber.
    #[test]
    fn a_failed_level_change_does_not_consume_a_generation() {
        let before = level_generation();
        assert!(
            set_verbose(true).is_err(),
            "no subscriber is installed in this test binary"
        );
        assert_eq!(
            level_generation(),
            before,
            "a level change that did not apply must not invalidate a pending auto-revert"
        );
    }

    #[test]
    fn panic_json_is_single_line_valid_json() {
        let line = render_panic_json("boom", Some("src/x.rs:1:2"));
        assert!(!line.contains('\n'), "panic line must be single-line");
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["level"], "ERROR");
        assert_eq!(v["target"], "panic");
        assert_eq!(v["message"], "boom");
        assert_eq!(v["location"], "src/x.rs:1:2");
        // Provenance: a crash line must carry the build name and version so it is
        // attributable without cross-referencing the boot line.
        assert_eq!(v["service.name"], env!("CARGO_PKG_NAME"));
        assert_eq!(v["service.version"], env!("CARGO_PKG_VERSION"));
        // The time field is `timestamp`, matching the tracing JSON layer, never `ts`, so
        // the store indexes one parseable date field across panic and normal lines.
        assert!(
            v.get("ts").is_none(),
            "the time field is `timestamp`, never `ts`"
        );
        assert!(
            v["timestamp"]
                .as_str()
                .is_some_and(|t| t.contains('T') && t.ends_with('Z')),
            "`timestamp` must be RFC3339, was {:?}",
            v.get("timestamp")
        );
    }

    #[test]
    fn panic_json_handles_special_chars() {
        // CR, LF or quotes in a panic message must stay inside one JSON string, so the
        // line cannot be forged or split.
        let line = render_panic_json("a\nb\"c\r", None);
        assert!(!line.contains('\n'));
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["message"], "a\nb\"c\r");
        assert!(v.get("location").is_none());
    }

    #[test]
    fn init_is_idempotent() {
        // Two inits in one process must not panic (try_init swallows the second).
        // `None` skips trace export (no OTLP endpoint in the test env).
        let _g1 = init(None, None, "test", None, 1.0);
        let _g2 = init(None, None, "test", None, 1.0);
    }

    /// Run `emit` under an [`EcsLayer`] capturing to a buffer; return the line(s) written.
    fn capture_ecs(emit: impl FnOnce()) -> String {
        use tracing_subscriber::layer::SubscriberExt as _;

        let writer = test_util::CaptureWriter::new();
        let subscriber = tracing_subscriber::registry().with(EcsLayer::new(
            {
                let w = writer.clone();
                move || w.clone()
            },
            "test".to_owned(),
        ));
        tracing::subscriber::with_default(subscriber, emit);
        writer.contents()
    }

    /// `LOG_FORMAT=text` colours a line only when asked. `init` asks exactly when stderr is
    /// a terminal, so a run redirected to a file, the documented local shape, is plain.
    #[test]
    fn text_format_colours_only_when_asked() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let capture = |ansi: bool| {
            let writer = test_util::CaptureWriter::new();
            let subscriber = tracing_subscriber::registry().with(text_layer(
                {
                    let w = writer.clone();
                    move || w.clone()
                },
                ansi,
            ));
            tracing::subscriber::with_default(subscriber, || {
                tracing::warn!(dataset = "GDI-1", "scan failed");
            });
            writer.contents()
        };
        let plain = capture(false);
        assert!(
            plain.contains("scan failed") && plain.contains("GDI-1"),
            "{plain}"
        );
        assert!(
            !plain.contains('\x1b'),
            "escape codes in a non-terminal text line: {plain:?}"
        );
        assert!(
            capture(true).contains('\x1b'),
            "a terminal still gets colour"
        );
    }

    #[test]
    fn ecs_schema_is_pinned() {
        let line = capture_ecs(|| {
            let span = tracing::info_span!("http_request", request_id = "abc-123");
            span.in_scope(|| tracing::warn!(dataset = "GDI-1", "scan failed"));
        });
        assert!(!line.trim().contains('\n'), "one NDJSON line: {line}");
        let v: serde_json::Value = serde_json::from_str(line.trim()).unwrap();

        // Pin the exact top-level envelope, so any added, removed or renamed key — a silent
        // ECS schema drift — breaks this test. Dotted keys are literal map keys, and the
        // store expands the dots. `trace.id` and `span.id` are otel-populated and absent
        // here, as are `event.action`, `event.outcome` and `tags`, which come from
        // `alert = true` sites; see `ecs_lifts_alert_and_event_fields_from_the_event`.
        let keys: std::collections::BTreeSet<&str> =
            v.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "@timestamp",
                "ecs.version",
                // The request span's `request_id` is lifted to the ECS correlation
                // field; `method` / `path` would lift the same way (see
                // `ecs_access_log_uses_the_http_fields`).
                "http.request.id",
                "labels",
                "log.level",
                "log.logger",
                "message",
                "service.environment",
                "service.name",
                "service.version",
            ]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
            "ECS top-level envelope changed: {line}"
        );

        // Field placement and values. Pin the ECS schema-version value, not only its key:
        // bumping it without updating the operator's index template and ECS mappings is the
        // drift this string exists to signal.
        assert_eq!(
            v["ecs.version"], "8.11.0",
            "ECS schema version changed — also update the operator's Elasticsearch index \
             template / Kibana ECS mappings (external, not in this repo) before bumping this pin"
        );
        assert_eq!(v["log.level"], "warn");
        assert_eq!(v["message"], "scan failed");
        assert_eq!(v["service.name"], env!("CARGO_PKG_NAME"));
        // `capture_ecs` configures environment = "test".
        assert_eq!(v["service.environment"], "test");
        assert_eq!(v["log.logger"], "gdi_node_standalone::logging::tests");
        // Event and span fields land under labels.*, and nothing leaks to a reserved key.
        // The request id is the exception: it is an ECS field (`http.request.id`), so it is
        // lifted out of `labels` and must not also stay there.
        assert_eq!(v["labels"]["dataset"], "GDI-1");
        assert_eq!(v["http.request.id"], "abc-123");
        assert!(v["labels"].get("request_id").is_none(), "{line}");
        assert!(v.get("dataset").is_none(), "{line}");
    }

    /// A `path` logged outside the request span is a filesystem path and stays under
    /// `labels.path`. Lifting by field name would put ingest working directories under ECS
    /// `url.path`, where `url.path`-scoped rules and HTTP views read them as requests.
    #[test]
    fn ecs_does_not_lift_a_filesystem_path_outside_the_request_span() {
        let line = capture_ecs(|| {
            tracing::warn!(
                path = "/var/lib/gdi-node-standalone/datasets/.incoming/x.tmp",
                "could not remove the working directory"
            );
        });
        let v: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert!(
            v.get("url.path").is_none(),
            "a filesystem path was lifted to url.path: {line}"
        );
        assert_eq!(
            v["labels"]["path"], "/var/lib/gdi-node-standalone/datasets/.incoming/x.tmp",
            "the path must stay under labels.*: {line}"
        );
    }

    /// The access-log line and everything inside a request span use ECS's own HTTP fields
    /// rather than `labels.*` copies: `http.request.method`, `url.path`, `http.request.id`,
    /// and, on the `request completed` line only, `http.response.status_code` and
    /// `event.duration` in nanoseconds. Under `labels.*` an HTTP view sees none of them, and
    /// a millisecond duration reads `0` on nearly every request.
    #[test]
    fn ecs_access_log_uses_the_http_fields() {
        let line = capture_ecs(|| {
            let span = tracing::info_span!(
                "http_request",
                method = "POST",
                path = "/beacon/v2/g_variants",
                request_id = "req-9"
            );
            span.in_scope(|| {
                tracing::info!(
                    target: "audit",
                    event = "http_request",
                    status = 503_u16,
                    latency_us = 750_u64,
                    "request completed"
                );
            });
        });
        let v: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(v["http.request.method"], "POST");
        assert_eq!(v["url.path"], "/beacon/v2/g_variants");
        assert_eq!(v["http.request.id"], "req-9");
        assert_eq!(v["http.response.status_code"], 503);
        assert_eq!(v["event.duration"], 750_000);
        let labels = v["labels"].as_object().unwrap();
        for lifted in ["method", "path", "request_id", "status", "latency_us"] {
            assert!(
                !labels.contains_key(lifted),
                "{lifted} left under labels: {line}"
            );
        }
        assert_eq!(labels["event"], "http_request");

        // A non-access-log line inside the span lifts the span's fields but has no status
        // or duration to lift, and a `status` of its own is not an HTTP status.
        let other = capture_ecs(|| {
            let span = tracing::info_span!("http_request", request_id = "req-10");
            span.in_scope(|| tracing::info!(status = "queued", "not an access log"));
        });
        let v: serde_json::Value = serde_json::from_str(other.trim()).unwrap();
        assert_eq!(v["http.request.id"], "req-10");
        assert_eq!(v["labels"]["status"], "queued");
        assert!(v.get("http.response.status_code").is_none(), "{other}");
    }

    #[test]
    fn ecs_lifts_alert_and_event_fields_from_the_event() {
        let line = capture_ecs(|| {
            tracing::warn!(
                alert = true,
                event.action = "vault.token.reauth",
                event.outcome = "failure",
                error = "boom",
                "renewal failed"
            );
        });
        let v: serde_json::Value = serde_json::from_str(line.trim()).expect("one json line");
        assert_eq!(v["tags"], serde_json::json!(["Alert"]), "{line}");
        assert_eq!(v["event.action"], "vault.token.reauth", "{line}");
        assert_eq!(v["event.outcome"], "failure", "{line}");
        // Lifted, not duplicated: none of the three stays under labels.*.
        let labels = v["labels"].as_object().expect("labels object");
        assert!(labels.get("alert").is_none(), "{line}");
        assert!(labels.get("event.action").is_none(), "{line}");
        assert_eq!(labels["error"], "boom", "{line}");
    }

    #[test]
    fn ecs_tags_nothing_without_the_alert_field() {
        let line = capture_ecs(|| tracing::warn!(dataset = "GDI-1", "scan failed"));
        let v: serde_json::Value = serde_json::from_str(line.trim()).expect("one json line");
        assert!(v.get("tags").is_none(), "{line}");
        assert!(v.get("event.action").is_none(), "{line}");
        assert!(v.get("event.outcome").is_none(), "{line}");
    }

    #[test]
    fn ecs_ignores_a_span_level_alert() {
        // Only the event's own `alert` tags the line: a span carrying it would tag every
        // line emitted inside it, which is not what any site means.
        let line = capture_ecs(|| {
            let span = tracing::info_span!("job", alert = true);
            span.in_scope(|| tracing::warn!("inside"));
        });
        let v: serde_json::Value = serde_json::from_str(line.trim()).expect("one json line");
        assert!(v.get("tags").is_none(), "{line}");
    }

    #[test]
    fn ecs_lifts_trace_ids_out_of_labels() {
        // Simulate what the otel layer records onto the request span: trace and span ids.
        // They must surface as ECS `trace.id` and `span.id`, so a viewer links a log line to
        // its trace, and must not be duplicated under `labels.*`.
        let line = capture_ecs(|| {
            let span = tracing::info_span!(
                "http_request",
                trace_id = "0af7651916cd43dd8448eb211c80319c",
                span_id = "b7ad6b7169203331",
                request_id = "r1",
            );
            span.in_scope(|| tracing::info!("served"));
        });
        let v: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(v["trace.id"], "0af7651916cd43dd8448eb211c80319c");
        assert_eq!(v["span.id"], "b7ad6b7169203331");
        assert!(v["labels"].get("trace_id").is_none(), "{line}");
        assert!(v["labels"].get("span_id").is_none(), "{line}");
        // The request id is lifted to its ECS field too; see
        // `ecs_access_log_uses_the_http_fields`.
        assert_eq!(v["http.request.id"], "r1");
    }

    #[test]
    fn render_panic_ecs_has_ecs_shape() {
        let v: serde_json::Value =
            serde_json::from_str(&render_panic_ecs("boom", Some("f.rs:1:2"), Some("prod")))
                .unwrap();

        // Exhaustive top-level envelope (location + environment present), mirroring the
        // `on_event` pin in `ecs_schema_is_pinned` so the panic-path ECS shape cannot
        // silently drift from the normal-log shape. `trace.id`/`span.id` never apply here.
        let keys: std::collections::BTreeSet<&str> =
            v.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "@timestamp",
                "ecs.version",
                "labels",
                "log.level",
                "log.logger",
                "message",
                "service.environment",
                "service.name",
                "service.version",
            ]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
            "panic-path ECS envelope changed: {v}"
        );
        assert_eq!(
            v["ecs.version"], "8.11.0",
            "ECS schema version changed — also update the operator's Elasticsearch index \
             template / Kibana ECS mappings (external, not in this repo) before bumping this pin"
        );
        assert_eq!(v["service.version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(v["log.level"], "error");
        assert_eq!(v["message"], "boom");
        assert_eq!(v["log.logger"], "panic");
        assert_eq!(v["labels"]["location"], "f.rs:1:2");
        // The deployment environment rides along as ECS `service.environment`.
        assert_eq!(v["service.environment"], "prod");
    }

    #[test]
    fn render_panic_ecs_omits_empty_environment() {
        // An unset/empty environment must not emit an empty `service.environment`.
        let v: serde_json::Value =
            serde_json::from_str(&render_panic_ecs("boom", None, None)).unwrap();
        assert!(v.get("service.environment").is_none(), "{v}");
        let v2: serde_json::Value =
            serde_json::from_str(&render_panic_ecs("boom", None, Some(""))).unwrap();
        assert!(v2.get("service.environment").is_none(), "{v2}");
    }

    #[test]
    fn supervision_spans_are_excluded_from_trace_export_but_work_spans_and_events_pass() {
        let registry = tracing_subscriber::registry();
        tracing::subscriber::with_default(registry, || {
            let supervision = tracing::info_span!("daemon", task = "rescan");
            let work = tracing::info_span!("ingest_job", dataset = "x");
            assert!(!export_allowed(
                supervision.metadata().expect("enabled span")
            ));
            assert!(export_allowed(work.metadata().expect("enabled span")));
        });
        // Only spans called `daemon` are dropped; the target rule is unchanged.
        assert!(export_target_allowed("gdi_node_standalone::ingest_runtime"));
        assert!(!export_target_allowed(AUDIT_TARGET));
    }

    #[test]
    fn object_store_retry_chatter_is_capped_under_the_default_and_under_an_operator_info() {
        for spec in [DEFAULT_LOG_SPEC, "info", "debug,gdi_node_standalone=trace"] {
            let subscriber = tracing_subscriber::registry().with(audit_floored_filter(spec));
            tracing::subscriber::with_default(subscriber, || {
                assert!(
                    !tracing::enabled!(target: "object_store::client::retry", tracing::Level::INFO),
                    "{spec}"
                );
                assert!(
                    tracing::enabled!(target: "object_store::client::retry", tracing::Level::WARN)
                );
                assert!(tracing::enabled!(target: "gdi_node_standalone::s3", tracing::Level::INFO));
                assert!(tracing::enabled!(target: "audit", tracing::Level::INFO));
            });
        }
    }

    #[test]
    fn an_operator_who_names_object_store_keeps_their_own_directive() {
        let subscriber =
            tracing_subscriber::registry().with(audit_floored_filter("info,object_store=debug"));
        tracing::subscriber::with_default(subscriber, || {
            assert!(
                tracing::enabled!(target: "object_store::client::retry", tracing::Level::DEBUG)
            );
        });
        assert_eq!(with_third_party_ceilings("info"), "info,object_store=warn");
        assert_eq!(
            with_third_party_ceilings("info,object_store[{x}]=trace"),
            "info,object_store[{x}]=trace"
        );
    }

    #[test]
    fn audit_target_excluded_from_trace_export() {
        // The privacy tripwire: the `audit` target (the only site that can carry
        // beacon query detail) must never be exported as trace data, while ordinary
        // administrative targets are allowed. A regression here re-opens the leak.
        assert!(!export_target_allowed(AUDIT_TARGET));
        assert!(!export_target_allowed("audit"));
        assert!(export_target_allowed("gdi_node_standalone::app"));
        assert!(export_target_allowed("gdi_node_standalone::beacon_http"));
    }

    /// Wire-level proof of the content-free guarantee: build the real OTLP export layer
    /// against a mock collector, emit a request span carrying an `audit`-target event with a
    /// secret marker, flush, and assert the marker never appears in the bytes sent, while
    /// the administrative span does — so the absence is a real exclusion rather than an
    /// empty or failed export. This exercises the whole path, `build_layer` to batch export
    /// to `/v1/traces`, unlike the predicate test above.
    #[cfg(feature = "otel")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn otlp_export_omits_audit_query_content() {
        use tracing_subscriber::layer::SubscriberExt as _;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // A distinctive, contiguous marker standing in for queried coordinates. It would
        // appear verbatim in the OTLP protobuf if the `audit` event leaked.
        const SECRET_QUERY: &str = "SECRETchr1pos12345refAaltT";

        // Mock OTLP/HTTP collector: 200 every POST, record the bodies.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/traces"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        // The OTLP exporter builds a reqwest client, and under a `tls`-enabled build the
        // unified `rustls-no-provider` reqwest needs a process crypto provider first.
        // Production installs it at startup; this test drives `build_layer` directly, so it
        // installs it here too.
        #[cfg(feature = "tls")]
        crate::preflight::install_crypto_provider();

        // Real export layer and provider against the mock. ERROR level so the span and
        // event survive any ambient `RUST_LOG`, as in the JSON subscriber test; the audit
        // exclusion is by target, not by level.
        let (layer, provider) = super::otel::build_layer(&server.uri(), None, "test", 1.0).unwrap();
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::error_span!(
                "http_request",
                method = "POST",
                path = "/beacon/v2/g_variants"
            );
            let _entered = span.enter();
            // The one content-bearing site, mirroring audit.rs: target = "audit".
            tracing::error!(target: "audit", query = SECRET_QUERY, "beacon query");
            // The span closes (and is enqueued for export) when this closure ends.
        });

        // Flush off the runtime workers: the blocking exporter runs on the batch
        // processor's own thread, so block there rather than on a worker that must also
        // serve the mock.
        tokio::task::spawn_blocking(move || {
            let _ = provider.shutdown();
        })
        .await
        .unwrap();

        let requests = server.received_requests().await.unwrap();
        assert!(
            !requests.is_empty(),
            "the exporter must POST at least one OTLP batch to /v1/traces"
        );
        let bodies: String = requests
            .iter()
            .map(|r| String::from_utf8_lossy(&r.body).into_owned())
            .collect();
        assert!(
            bodies.contains("http_request"),
            "the administrative span must be present in the exported payload (sanity)"
        );
        assert!(
            !bodies.contains(SECRET_QUERY),
            "audit query content leaked into exported OTLP traces"
        );
    }

    #[test]
    fn reload_handle_hot_swaps_the_level() {
        use tracing_subscriber::Layer as _;
        use tracing_subscriber::layer::SubscriberExt as _;

        let writer = test_util::CaptureWriter::new();
        // Start at `info`, so a `debug` event is filtered out. This is the mechanism
        // `toggle_verbose` drives on SIGUSR2: a reloadable `EnvFilter` applied as a
        // per-layer filter. Only the directive source differs, since `toggle_verbose`
        // composes the boot filter with the diagnostic directives rather than a literal.
        let (level, handle) = reload::Layer::new(EnvFilter::new("info"));
        let subscriber = tracing_subscriber::registry().with(
            fmt::layer()
                .with_writer({
                    let w = writer.clone();
                    move || w.clone()
                })
                .with_filter(level),
        );

        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!("before-reload");
            handle.reload(EnvFilter::new("debug")).unwrap();
            tracing::debug!("after-reload");
        });

        let out = writer.contents();
        assert!(
            !out.contains("before-reload"),
            "an `info` filter must drop the pre-reload `debug` line: {out}"
        );
        assert!(
            out.contains("after-reload"),
            "reloading to `debug` must admit the post-reload `debug` line: {out}"
        );
    }

    /// Emit one audit event under `spec`, floored exactly as `build_filter` floors it, and
    /// return what reached the sink.
    fn audit_line_under(spec: &str) -> String {
        use tracing_subscriber::Layer as _;
        use tracing_subscriber::layer::SubscriberExt as _;

        let writer = test_util::CaptureWriter::new();
        let subscriber = tracing_subscriber::registry().with(
            fmt::layer()
                .with_writer({
                    let w = writer.clone();
                    move || w.clone()
                })
                .with_filter(audit_floored_filter(spec)),
        );
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "audit", event = "beacon_query", "audited-line");
        });
        writer.contents()
    }

    /// The audit floor must beat a field-qualified silencer, not only an equal-specificity
    /// one. `EnvFilter` picks the most specific directive per event, and `audit[{event}]` is
    /// strictly more specific than the floor's bare `audit`, so an operator, or a compromised
    /// deployment environment, could erase the whole compliance trail with a directive
    /// `invalid_log_spec` accepts as valid while `with_audit_floor` still looked applied.
    /// Every audit emit carries an `event` field, so that silences all of them.
    #[test]
    fn audit_target_survives_a_field_qualified_silencer() {
        for spec in [
            "off,audit[{event}]=off",
            "info,audit[{event}]=off",
            "warn,audit[{event=beacon_query}]=off",
            "off,audit=off",
        ] {
            let out = audit_line_under(spec);
            assert!(
                out.contains("audited-line"),
                "GDI_LOG={spec:?} silenced the audit trail: {out:?}"
            );
        }
    }

    #[test]
    fn audit_target_is_floored_above_the_level_knob() {
        use tracing_subscriber::Layer as _;
        use tracing_subscriber::layer::SubscriberExt as _;

        let writer = test_util::CaptureWriter::new();
        // Simulate `GDI_LOG=warn`, an operator quieting routine noise, then apply the audit
        // floor exactly as `build_filter` does. An `info`-level `audit` event must survive
        // it while a normal `info` event is dropped.
        let filter = with_audit_floor(EnvFilter::new("warn"));
        let subscriber = tracing_subscriber::registry().with(
            fmt::layer()
                .with_writer({
                    let w = writer.clone();
                    move || w.clone()
                })
                .with_filter(filter),
        );

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "audit", event = "beacon_query", "audited-line");
            tracing::info!("routine-noise-line");
        });

        let out = writer.contents();
        assert!(
            out.contains("audited-line"),
            "an info-level `audit` event must survive a `warn` base level: {out}"
        );
        assert!(
            !out.contains("routine-noise-line"),
            "a normal info event must still be dropped at a `warn` base level: {out}"
        );
    }

    #[test]
    fn invalid_log_spec_flags_a_set_but_unparseable_directive() {
        let bad = "gdi=supertrace".to_owned(); // an invalid level → unparseable directive
        let good = "info,gdi_node_standalone=debug".to_owned();

        // Nothing set → nothing to flag.
        assert_eq!(invalid_log_spec_from(None, None), None);
        // A valid GDI_LOG is what took effect → not flagged.
        assert_eq!(invalid_log_spec_from(Some(good.clone()), None), None);
        // A set-but-unparseable GDI_LOG is flagged (it was silently ignored).
        assert_eq!(
            invalid_log_spec_from(Some(bad.clone()), None),
            Some(("GDI_LOG", bad.clone()))
        );
        // A valid GDI_LOG suppresses the RUST_LOG check — GDI_LOG is what applied.
        assert_eq!(invalid_log_spec_from(Some(good), Some(bad.clone())), None);
        // With GDI_LOG unset, a garbage RUST_LOG is flagged.
        assert_eq!(
            invalid_log_spec_from(None, Some(bad.clone())),
            Some(("RUST_LOG", bad))
        );
    }

    #[test]
    fn diagnostic_spec_raises_node_crates_over_the_base() {
        let spec = diagnostic_spec("info");
        // The base level is preserved first, then the node's own crates are layered on at
        // `debug`; later directives win per target.
        assert!(spec.starts_with("info,"), "base level kept first: {spec}");
        assert!(spec.contains("gdi_node_standalone=debug"), "{spec}");
        assert!(spec.contains("gdi_node_standalone_core=debug"), "{spec}");
        assert!(spec.contains("gdi_node_standalone_beacon=debug"), "{spec}");
        assert!(spec.contains("gdi_node_standalone_fairdp=debug"), "{spec}");
        // The composed spec must parse as an `EnvFilter` — `toggle_verbose` relies on it.
        EnvFilter::try_new(&spec).expect("diagnostic spec must be a valid EnvFilter");
    }

    #[test]
    fn json_subscriber_flattens_event_fields_and_keeps_span_nested() {
        let writer = test_util::CaptureWriter::new();
        let subscriber = build_json_subscriber({
            let w = writer.clone();
            move || w.clone()
        });

        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::error_span!("http_request", request_id = "REQ-1");
            let _guard = span.enter();
            // ERROR level so it survives any default RUST_LOG in the test env.
            tracing::error!(
                dataset = "GDI-1",
                error_class = "invalid-parquet",
                "scan failed"
            );
        });

        let out = writer.contents();
        let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();

        // Event fields are flattened to the top level rather than nested under `fields`, so
        // a query reads `message` and `error_class` directly.
        assert_eq!(v["message"], "scan failed");
        assert_eq!(v["dataset"], "GDI-1");
        assert_eq!(v["error_class"], "invalid-parquet");
        assert!(
            v.get("fields").is_none(),
            "flatten_event must hoist event fields out of `fields`, got {v}"
        );
        // The request id stays a span field, which is why correlation queries
        // `span.request_id` rather than a top-level `request_id`.
        assert_eq!(v["span"]["request_id"], "REQ-1");
        assert!(v.get("request_id").is_none(), "request_id is a span field");
    }
}

/// The export-failure signal and the instance-id default, from the `otel` module.
#[cfg(all(test, feature = "otel"))]
mod otel_export_tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

    use std::sync::atomic::{AtomicBool, Ordering};

    use opentelemetry_sdk::error::{OTelSdkError, OTelSdkResult};
    use opentelemetry_sdk::trace::{SpanData, SpanExporter as _};

    use super::otel::{ExportHealth, WatchedSpanExporter, default_instance_id};

    #[test]
    fn export_health_logs_only_the_transitions() {
        let health = ExportHealth::new("metrics");
        let err: OTelSdkResult = Err(OTelSdkError::InternalFailure("connection refused".into()));
        let ok: OTelSdkResult = Ok(());
        let ((), out) = test_util::capture_json_logs_flat(|| {
            health.observe(&err);
            health.observe(&err);
            health.observe(&err);
            health.observe(&ok);
            health.observe(&ok);
            health.observe(&err);
        });
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3, "transitions only, never per batch: {out}");
        assert!(
            lines[0].contains("\"WARN\"")
                && lines[0].contains("otlp.export")
                && lines[0].contains("failure")
                && lines[0].contains("connection refused"),
            "the first failure carries the cause: {}",
            lines[0]
        );
        assert!(
            lines[1].contains("\"INFO\"") && lines[1].contains("recovered"),
            "recovery is announced once: {}",
            lines[1]
        );
        assert!(
            lines[2].contains("\"WARN\""),
            "a new outage logs again: {}",
            lines[2]
        );
    }

    /// A span exporter whose verdict is switchable, standing in for a collector that goes
    /// away and comes back.
    #[derive(Debug)]
    struct Flaky(AtomicBool);

    impl opentelemetry_sdk::trace::SpanExporter for Flaky {
        fn export(
            &self,
            _batch: Vec<SpanData>,
        ) -> impl std::future::Future<Output = OTelSdkResult> + Send {
            let fail = self.0.load(Ordering::Relaxed);
            async move {
                if fail {
                    Err(OTelSdkError::InternalFailure("intake said 503".into()))
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Collects every exported span, so a test can look at the shape that leaves the node.
    #[derive(Clone, Default, Debug)]
    struct Capture(std::sync::Arc<std::sync::Mutex<Vec<SpanData>>>);

    impl opentelemetry_sdk::trace::SpanExporter for Capture {
        fn export(
            &self,
            batch: Vec<SpanData>,
        ) -> impl std::future::Future<Output = OTelSdkResult> + Send {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend(batch);
            async { Ok(()) }
        }
    }

    /// What a request span looks like when it leaves the node: named `METHOD route`, kind
    /// server, an error status on a 5xx with the status code as an attribute, the route
    /// template attached, and none of the bridge's `code.*`, `thread.*`, `busy_ns` or
    /// `idle_ns` boilerplate. Built through the same `tracing_layer` and
    /// `public_request_span` the node uses, so this is the shipped shape, not a copy.
    #[test]
    fn an_exported_request_span_has_the_conventional_shape() {
        use opentelemetry::trace::TracerProvider as _;
        use tracing_subscriber::layer::SubscriberExt as _;

        let capture = Capture::default();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(capture.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(super::otel::tracing_layer(provider.tracer("test")));
        tracing::subscriber::with_default(subscriber, || {
            let span = crate::app::public_request_span(
                &axum::http::Method::POST,
                "/beacon/v2/g_variants",
                "req-1",
                Some("/beacon/v2/g_variants"),
            );
            let _entered = span.enter();
            crate::app::record_response_on_span(&span, 503);
        });
        provider.force_flush().expect("flush");

        let spans = capture
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let span = spans
            .iter()
            .find(|s| s.name == "POST /beacon/v2/g_variants")
            .unwrap_or_else(|| {
                panic!(
                    "no span named `POST /beacon/v2/g_variants` was exported; names: {:?}",
                    spans.iter().map(|s| s.name.clone()).collect::<Vec<_>>()
                )
            });
        assert_eq!(span.span_kind, opentelemetry::trace::SpanKind::Server);
        assert!(
            matches!(span.status, opentelemetry::trace::Status::Error { .. }),
            "a 503 must export as an error span, got {:?}",
            span.status
        );
        let attrs: std::collections::BTreeMap<String, String> = span
            .attributes
            .iter()
            .map(|kv| (kv.key.to_string(), kv.value.to_string()))
            .collect();
        assert_eq!(
            attrs.get("http.response.status_code").map(String::as_str),
            Some("503")
        );
        assert_eq!(
            attrs.get("http.route").map(String::as_str),
            Some("/beacon/v2/g_variants")
        );
        assert_eq!(attrs.get("method").map(String::as_str), Some("POST"));
        let boilerplate: Vec<&String> = attrs
            .keys()
            .filter(|k| {
                k.starts_with("code.")
                    || k.starts_with("thread.")
                    || *k == "busy_ns"
                    || *k == "idle_ns"
            })
            .collect();
        assert!(
            boilerplate.is_empty(),
            "bridge boilerplate on the span: {boilerplate:?}"
        );
    }

    #[test]
    fn the_watched_span_exporter_signals_through_the_real_trait() {
        let exporter = WatchedSpanExporter {
            inner: Flaky(AtomicBool::new(true)),
            health: ExportHealth::new("traces"),
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let ((), out) = test_util::capture_json_logs_flat(|| {
            runtime.block_on(async {
                // The error still propagates: observing must not swallow it.
                assert!(exporter.export(vec![]).await.is_err());
                assert!(exporter.export(vec![]).await.is_err());
                exporter.inner.0.store(false, Ordering::Relaxed);
                assert!(exporter.export(vec![]).await.is_ok());
            });
        });
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2, "one WARN + one recovery INFO: {out}");
        assert!(lines[0].contains("intake said 503"), "{out}");
        assert!(lines[1].contains("recovered"), "{out}");
    }

    #[test]
    fn the_instance_id_defaults_only_when_the_env_has_not_set_one() {
        let host = || Some("pod-7".to_owned());
        assert_eq!(default_instance_id(None, host()), host());
        assert_eq!(
            default_instance_id(Some("deployment.environment=prod"), host()),
            host(),
            "an env var naming other attributes does not suppress the default"
        );
        assert_eq!(
            default_instance_id(Some("service.instance.id=pod-x"), host()),
            None,
            "the operator's id must win — supply nothing"
        );
        assert_eq!(
            default_instance_id(Some("a=b, service.instance.id =pod-x"), host()),
            None,
            "spaces around the key are the operator's, not a different key"
        );
        assert_eq!(default_instance_id(None, None), None, "never invent an id");
    }
}
