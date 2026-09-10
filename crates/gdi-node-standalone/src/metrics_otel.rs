//! The OTLP metrics push (the `otel` feature): a second `metrics::Recorder` that mirrors
//! every counter, gauge and histogram the node records into OpenTelemetry instruments,
//! installed *beside* the Prometheus recorder through [`Fanout`].
//!
//! `/metrics` stays authoritative: the Prometheus recorder still renders the scrape. The
//! fan-out is one recorder to the `metrics` facade, so a series added anywhere in the node
//! crosses over without touching its call site. Names travel verbatim (`gdi_ingest_total`
//! stays `gdi_ingest_total`), because the names are the contract the alert rules and
//! dashboards are written against, and a store that speaks OTLP but not Prometheus should
//! show the same names an operator sees on `/metrics`. Labels become attributes one-to-one,
//! which keeps the content-free invariant (`metrics.rs`) intact: nothing here adds a label.
//!
//! Semantics that differ between the two facades, resolved here:
//!
//! * a `metrics` counter's `absolute(v)` sets the counter to `v`; an OpenTelemetry counter
//!   is a monotonic sum, so the mirror adds the delta since the last absolute value;
//! * a `metrics` gauge is relative (`increment`/`decrement`) as well as absolute (`set`);
//!   an OpenTelemetry gauge records values, so the mirror keeps the current value;
//! * histogram bucket boundaries are the same table the Prometheus recorder uses
//!   ([`crate::metrics::HISTOGRAM_BUCKETS`]), so a quantile reads the same in both stores.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use metrics::{
    Counter, CounterFn, Gauge, GaugeFn, Histogram, HistogramFn, Key, KeyName, Metadata, Recorder,
    SharedString, Unit,
};
use opentelemetry::KeyValue;
use opentelemetry::metrics::Meter;

/// A histogram bucket table: `(metric name, upper bounds)`, shared with the Prometheus
/// recorder so both stores bucket a series identically.
pub type BucketTable = &'static [(&'static str, &'static [f64])];

/// What a `describe_*` call recorded for a series, applied when its instrument is built.
struct Description {
    unit: Option<Unit>,
    text: SharedString,
}

/// The OpenTelemetry mirror of the `metrics` facade. One instrument per series name, built
/// on first registration, so a preceding `describe_*` lands on the instrument.
pub struct OtelRecorder {
    meter: Meter,
    buckets: BucketTable,
    descriptions: Mutex<HashMap<String, Description>>,
    counters: Mutex<HashMap<String, opentelemetry::metrics::Counter<u64>>>,
    gauges: Mutex<HashMap<String, opentelemetry::metrics::Gauge<f64>>>,
    histograms: Mutex<HashMap<String, opentelemetry::metrics::Histogram<f64>>>,
    /// One handle per `Key` (name + labels), shared by every registration of that key.
    /// `metrics 0.24`'s `counter!`/`gauge!` macros re-register on every invocation, which is
    /// the form every production call site uses, so per-handle state (the last `absolute`
    /// value, the current gauge value) must live here, keyed like the Prometheus exporter's
    /// registry. Held per call instead, each invocation would start from zero: a gauge would
    /// read `1` after three increments, and an absolute counter would sum its readings.
    counter_handles: Mutex<HashMap<Key, Arc<OtelCounter>>>,
    gauge_handles: Mutex<HashMap<Key, Arc<OtelGauge>>>,
}

impl OtelRecorder {
    /// Mirror onto `meter`, bucketing histograms per `buckets`.
    #[must_use]
    pub fn new(meter: Meter, buckets: BucketTable) -> Self {
        Self {
            meter,
            buckets,
            descriptions: Mutex::new(HashMap::new()),
            counters: Mutex::new(HashMap::new()),
            gauges: Mutex::new(HashMap::new()),
            histograms: Mutex::new(HashMap::new()),
            counter_handles: Mutex::new(HashMap::new()),
            gauge_handles: Mutex::new(HashMap::new()),
        }
    }

    /// Lock one of the instrument maps, tolerating a poisoned mutex: the maps hold
    /// nothing a panic could leave half-written (an insert is a single operation), so
    /// the value inside a poisoned lock is still the right one.
    fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn describe(&self, name: &str, unit: Option<Unit>, description: SharedString) {
        Self::lock(&self.descriptions).insert(
            name.to_owned(),
            Description {
                unit,
                text: description,
            },
        );
    }

    /// The `(unit, description)` a series was described with, if it was.
    fn described(&self, name: &str) -> (Option<&'static str>, String) {
        let descriptions = Self::lock(&self.descriptions);
        match descriptions.get(name) {
            Some(d) => (
                d.unit.as_ref().map(Unit::as_canonical_label),
                d.text.to_string(),
            ),
            None => (None, String::new()),
        }
    }

    fn counter(&self, name: &str) -> opentelemetry::metrics::Counter<u64> {
        if let Some(existing) = Self::lock(&self.counters).get(name) {
            return existing.clone();
        }
        let (unit, description) = self.described(name);
        let mut builder = self
            .meter
            .u64_counter(name.to_owned())
            .with_description(description);
        if let Some(unit) = unit {
            builder = builder.with_unit(unit);
        }
        let instrument = builder.build();
        Self::lock(&self.counters)
            .entry(name.to_owned())
            .or_insert(instrument)
            .clone()
    }

    fn gauge(&self, name: &str) -> opentelemetry::metrics::Gauge<f64> {
        if let Some(existing) = Self::lock(&self.gauges).get(name) {
            return existing.clone();
        }
        let (unit, description) = self.described(name);
        let mut builder = self
            .meter
            .f64_gauge(name.to_owned())
            .with_description(description);
        if let Some(unit) = unit {
            builder = builder.with_unit(unit);
        }
        let instrument = builder.build();
        Self::lock(&self.gauges)
            .entry(name.to_owned())
            .or_insert(instrument)
            .clone()
    }

    fn histogram(&self, name: &str) -> opentelemetry::metrics::Histogram<f64> {
        if let Some(existing) = Self::lock(&self.histograms).get(name) {
            return existing.clone();
        }
        let (unit, description) = self.described(name);
        let mut builder = self
            .meter
            .f64_histogram(name.to_owned())
            .with_description(description);
        if let Some(unit) = unit {
            builder = builder.with_unit(unit);
        }
        if let Some((_, bounds)) = self.buckets.iter().find(|(metric, _)| *metric == name) {
            builder = builder.with_boundaries(bounds.to_vec());
        }
        let instrument = builder.build();
        Self::lock(&self.histograms)
            .entry(name.to_owned())
            .or_insert(instrument)
            .clone()
    }
}

/// A `metrics` key's labels as OpenTelemetry attributes, one-to-one.
fn attributes(key: &Key) -> Vec<KeyValue> {
    key.labels()
        .map(|label| KeyValue::new(label.key().to_owned(), label.value().to_owned()))
        .collect()
}

struct OtelCounter {
    instrument: opentelemetry::metrics::Counter<u64>,
    attributes: Vec<KeyValue>,
    /// The last value `absolute` set, so the next one can be turned into a delta.
    last_absolute: AtomicU64,
}

impl CounterFn for OtelCounter {
    fn increment(&self, value: u64) {
        self.instrument.add(value, &self.attributes);
    }

    fn absolute(&self, value: u64) {
        let previous = self.last_absolute.swap(value, Ordering::AcqRel);
        if value > previous {
            self.instrument.add(value - previous, &self.attributes);
        }
    }
}

struct OtelGauge {
    instrument: opentelemetry::metrics::Gauge<f64>,
    attributes: Vec<KeyValue>,
    /// The current value as `f64` bits, so `increment`/`decrement` have a base.
    current: AtomicU64,
}

impl OtelGauge {
    fn apply(&self, update: impl Fn(f64) -> f64) {
        let mut next = 0.0;
        // `fetch_update` retries on contention; the closure is pure, so re-running it is
        // harmless, and it cannot fail because the closure always returns `Some`.
        let _ = self
            .current
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |bits| {
                next = update(f64::from_bits(bits));
                Some(next.to_bits())
            });
        self.instrument.record(next, &self.attributes);
    }
}

impl GaugeFn for OtelGauge {
    fn increment(&self, value: f64) {
        self.apply(|current| current + value);
    }

    fn decrement(&self, value: f64) {
        self.apply(|current| current - value);
    }

    fn set(&self, value: f64) {
        self.apply(|_| value);
    }
}

struct OtelHistogram {
    instrument: opentelemetry::metrics::Histogram<f64>,
    attributes: Vec<KeyValue>,
}

impl HistogramFn for OtelHistogram {
    fn record(&self, value: f64) {
        self.instrument.record(value, &self.attributes);
    }
}

impl Recorder for OtelRecorder {
    fn describe_counter(&self, key: KeyName, unit: Option<Unit>, description: SharedString) {
        self.describe(key.as_str(), unit, description);
    }

    fn describe_gauge(&self, key: KeyName, unit: Option<Unit>, description: SharedString) {
        self.describe(key.as_str(), unit, description);
    }

    fn describe_histogram(&self, key: KeyName, unit: Option<Unit>, description: SharedString) {
        self.describe(key.as_str(), unit, description);
    }

    fn register_counter(&self, key: &Key, _metadata: &Metadata<'_>) -> Counter {
        let mut handles = Self::lock(&self.counter_handles);
        if let Some(handle) = handles.get(key) {
            return Counter::from_arc(Arc::clone(handle));
        }
        let handle = Arc::new(OtelCounter {
            instrument: self.counter(key.name()),
            attributes: attributes(key),
            last_absolute: AtomicU64::new(0),
        });
        handles.insert(key.clone(), Arc::clone(&handle));
        Counter::from_arc(handle)
    }

    fn register_gauge(&self, key: &Key, _metadata: &Metadata<'_>) -> Gauge {
        let mut handles = Self::lock(&self.gauge_handles);
        if let Some(handle) = handles.get(key) {
            return Gauge::from_arc(Arc::clone(handle));
        }
        let handle = Arc::new(OtelGauge {
            instrument: self.gauge(key.name()),
            attributes: attributes(key),
            current: AtomicU64::new(0.0_f64.to_bits()),
        });
        handles.insert(key.clone(), Arc::clone(&handle));
        Gauge::from_arc(handle)
    }

    fn register_histogram(&self, key: &Key, _metadata: &Metadata<'_>) -> Histogram {
        Histogram::from_arc(Arc::new(OtelHistogram {
            instrument: self.histogram(key.name()),
            attributes: attributes(key),
        }))
    }
}

/// One recorder to the `metrics` facade that drives two: the Prometheus recorder that
/// renders `/metrics`, and the OpenTelemetry mirror. Every describe and register goes to
/// both; every handle returned is a pair, so a single `increment` lands in both stores.
pub struct Fanout<P> {
    prometheus: P,
    otel: Arc<OtelRecorder>,
}

impl<P: Recorder> Fanout<P> {
    /// Drive `prometheus` and `otel` together.
    pub fn new(prometheus: P, otel: Arc<OtelRecorder>) -> Self {
        Self { prometheus, otel }
    }
}

struct PairCounter(Counter, Counter);

impl CounterFn for PairCounter {
    fn increment(&self, value: u64) {
        self.0.increment(value);
        self.1.increment(value);
    }

    fn absolute(&self, value: u64) {
        self.0.absolute(value);
        self.1.absolute(value);
    }
}

struct PairGauge(Gauge, Gauge);

impl GaugeFn for PairGauge {
    fn increment(&self, value: f64) {
        self.0.increment(value);
        self.1.increment(value);
    }

    fn decrement(&self, value: f64) {
        self.0.decrement(value);
        self.1.decrement(value);
    }

    fn set(&self, value: f64) {
        self.0.set(value);
        self.1.set(value);
    }
}

struct PairHistogram(Histogram, Histogram);

impl HistogramFn for PairHistogram {
    fn record(&self, value: f64) {
        self.0.record(value);
        self.1.record(value);
    }
}

impl<P: Recorder> Recorder for Fanout<P> {
    fn describe_counter(&self, key: KeyName, unit: Option<Unit>, description: SharedString) {
        self.prometheus
            .describe_counter(key.clone(), unit, description.clone());
        self.otel.describe_counter(key, unit, description);
    }

    fn describe_gauge(&self, key: KeyName, unit: Option<Unit>, description: SharedString) {
        self.prometheus
            .describe_gauge(key.clone(), unit, description.clone());
        self.otel.describe_gauge(key, unit, description);
    }

    fn describe_histogram(&self, key: KeyName, unit: Option<Unit>, description: SharedString) {
        self.prometheus
            .describe_histogram(key.clone(), unit, description.clone());
        self.otel.describe_histogram(key, unit, description);
    }

    fn register_counter(&self, key: &Key, metadata: &Metadata<'_>) -> Counter {
        Counter::from_arc(Arc::new(PairCounter(
            self.prometheus.register_counter(key, metadata),
            self.otel.register_counter(key, metadata),
        )))
    }

    fn register_gauge(&self, key: &Key, metadata: &Metadata<'_>) -> Gauge {
        Gauge::from_arc(Arc::new(PairGauge(
            self.prometheus.register_gauge(key, metadata),
            self.otel.register_gauge(key, metadata),
        )))
    }

    fn register_histogram(&self, key: &Key, metadata: &Metadata<'_>) -> Histogram {
        Histogram::from_arc(Arc::new(PairHistogram(
            self.prometheus.register_histogram(key, metadata),
            self.otel.register_histogram(key, metadata),
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use metrics_exporter_prometheus::PrometheusBuilder;
    use opentelemetry::metrics::MeterProvider as _;
    use opentelemetry_sdk::error::OTelSdkResult;
    use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData, ResourceMetrics};
    use opentelemetry_sdk::metrics::exporter::PushMetricExporter;
    use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider, Temporality};

    use super::*;
    use crate::metrics::HISTOGRAM_BUCKETS;

    /// What one export delivered, flattened to what the assertions need.
    #[derive(Debug, Clone, PartialEq)]
    enum Point {
        Sum(f64),
        Gauge(f64),
        Histogram {
            count: u64,
            sum: f64,
            bounds: Vec<f64>,
        },
    }

    #[derive(Debug, Clone)]
    struct Captured {
        name: String,
        description: String,
        unit: String,
        attributes: Vec<(String, String)>,
        point: Point,
    }

    /// A push exporter that keeps every data point in memory. The SDK's own in-memory
    /// exporter sits behind its `testing` feature.
    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<Captured>>>);

    impl Capture {
        fn points(&self) -> Vec<Captured> {
            self.0.lock().expect("capture lock").clone()
        }

        fn push(
            &self,
            name: &str,
            description: &str,
            unit: &str,
            attrs: &[KeyValue],
            point: Point,
        ) {
            self.0.lock().expect("capture lock").push(Captured {
                name: name.to_owned(),
                description: description.to_owned(),
                unit: unit.to_owned(),
                attributes: attrs
                    .iter()
                    .map(|kv| (kv.key.as_str().to_owned(), kv.value.to_string()))
                    .collect(),
                point,
            });
        }
    }

    impl PushMetricExporter for Capture {
        fn export(&self, metrics: &ResourceMetrics) -> impl Future<Output = OTelSdkResult> + Send {
            for scope in metrics.scope_metrics() {
                for metric in scope.metrics() {
                    let (name, description, unit) =
                        (metric.name(), metric.description(), metric.unit());
                    match metric.data() {
                        AggregatedMetrics::U64(MetricData::Sum(sum)) => {
                            for dp in sum.data_points() {
                                #[expect(
                                    clippy::cast_precision_loss,
                                    reason = "test values are tiny"
                                )]
                                let value = dp.value() as f64;
                                self.push(
                                    name,
                                    description,
                                    unit,
                                    &dp.attributes().cloned().collect::<Vec<_>>(),
                                    Point::Sum(value),
                                );
                            }
                        }
                        AggregatedMetrics::F64(MetricData::Gauge(gauge)) => {
                            for dp in gauge.data_points() {
                                self.push(
                                    name,
                                    description,
                                    unit,
                                    &dp.attributes().cloned().collect::<Vec<_>>(),
                                    Point::Gauge(dp.value()),
                                );
                            }
                        }
                        AggregatedMetrics::F64(MetricData::Histogram(histogram)) => {
                            for dp in histogram.data_points() {
                                self.push(
                                    name,
                                    description,
                                    unit,
                                    &dp.attributes().cloned().collect::<Vec<_>>(),
                                    Point::Histogram {
                                        count: dp.count(),
                                        sum: dp.sum(),
                                        bounds: dp.bounds().collect(),
                                    },
                                );
                            }
                        }
                        _ => {}
                    }
                }
            }
            std::future::ready(Ok(()))
        }

        fn force_flush(&self) -> OTelSdkResult {
            Ok(())
        }

        fn shutdown_with_timeout(&self, _timeout: Duration) -> OTelSdkResult {
            Ok(())
        }

        fn temporality(&self) -> Temporality {
            Temporality::Cumulative
        }
    }

    /// A provider whose only reader pushes into `capture` on `force_flush`.
    fn provider(capture: &Capture) -> SdkMeterProvider {
        let reader = PeriodicReader::builder(capture.clone())
            .with_interval(Duration::from_secs(3600))
            .build();
        SdkMeterProvider::builder().with_reader(reader).build()
    }

    fn recorder(provider: &SdkMeterProvider) -> OtelRecorder {
        OtelRecorder::new(provider.meter("test"), HISTOGRAM_BUCKETS)
    }

    fn find<'a>(points: &'a [Captured], name: &str) -> &'a Captured {
        points
            .iter()
            .find(|p| p.name == name)
            .unwrap_or_else(|| panic!("{name} was not exported; got {points:?}"))
    }

    #[test]
    fn counters_keep_their_name_labels_and_delta_semantics() {
        let capture = Capture::default();
        let provider = provider(&capture);
        let recorder = recorder(&provider);

        metrics::with_local_recorder(&recorder, || {
            let handle = metrics::counter!("gdi_t_events_total", "outcome" => "ok");
            handle.increment(2);
            handle.increment(3);
            // `absolute` sets the Prometheus counter; the mirror must add only the delta.
            let absolute = metrics::counter!("gdi_t_seen_total");
            absolute.absolute(10);
            absolute.absolute(15);
            absolute.absolute(15);
        });
        provider.force_flush().expect("flush");

        let points = capture.points();
        let events = find(&points, "gdi_t_events_total");
        assert_eq!(events.point, Point::Sum(5.0));
        assert_eq!(
            events.attributes,
            vec![("outcome".to_owned(), "ok".to_owned())]
        );
        assert_eq!(find(&points, "gdi_t_seen_total").point, Point::Sum(15.0));
        provider.shutdown().expect("shutdown");
    }

    #[test]
    fn gauges_track_relative_and_absolute_updates() {
        let capture = Capture::default();
        let provider = provider(&capture);
        let recorder = recorder(&provider);

        metrics::with_local_recorder(&recorder, || {
            let depth = metrics::gauge!("gdi_t_queue_depth");
            depth.set(4.0);
            depth.increment(3.0);
            depth.decrement(1.0);
        });
        provider.force_flush().expect("flush");

        assert_eq!(
            find(&capture.points(), "gdi_t_queue_depth").point,
            Point::Gauge(6.0)
        );
        provider.shutdown().expect("shutdown");
    }

    /// The shape every production call site uses: a fresh `gauge!`/`counter!` macro
    /// invocation per update, never a kept handle.
    #[test]
    fn fresh_macro_handles_share_state_per_key() {
        let capture = Capture::default();
        let provider = provider(&capture);
        let recorder = recorder(&provider);

        metrics::with_local_recorder(&recorder, || {
            metrics::gauge!("gdi_t_inflight").increment(1.0);
            metrics::gauge!("gdi_t_inflight").increment(1.0);
            metrics::gauge!("gdi_t_inflight").increment(1.0);
            metrics::gauge!("gdi_t_inflight").decrement(1.0);
            metrics::counter!("gdi_t_cpu_total").absolute(5);
            metrics::counter!("gdi_t_cpu_total").absolute(6);
            metrics::counter!("gdi_t_cpu_total").absolute(7);
            // A different label set is a different series with its own state.
            metrics::gauge!("gdi_t_inflight", "plane" => "public").set(4.0);
            metrics::gauge!("gdi_t_inflight", "plane" => "public").decrement(1.0);
        });
        provider.force_flush().expect("flush");

        let points = capture.points();
        let unlabelled = points
            .iter()
            .find(|p| p.name == "gdi_t_inflight" && p.attributes.is_empty())
            .expect("unlabelled gauge point");
        assert_eq!(unlabelled.point, Point::Gauge(2.0));
        let labelled = points
            .iter()
            .find(|p| p.name == "gdi_t_inflight" && !p.attributes.is_empty())
            .expect("labelled gauge point");
        assert_eq!(labelled.point, Point::Gauge(3.0));
        assert_eq!(find(&points, "gdi_t_cpu_total").point, Point::Sum(7.0));
        provider.shutdown().expect("shutdown");
    }

    #[test]
    fn histograms_use_the_prometheus_bucket_table() {
        let capture = Capture::default();
        let provider = provider(&capture);
        let recorder = recorder(&provider);
        let (name, bounds) = HISTOGRAM_BUCKETS[0];

        metrics::with_local_recorder(&recorder, || {
            let h = metrics::histogram!(name);
            h.record(0.2);
            h.record(2.0);
        });
        provider.force_flush().expect("flush");

        assert_eq!(
            find(&capture.points(), name).point,
            Point::Histogram {
                count: 2,
                sum: 2.2,
                bounds: bounds.to_vec(),
            }
        );
        provider.shutdown().expect("shutdown");
    }

    #[test]
    fn descriptions_and_units_land_on_the_instrument() {
        let capture = Capture::default();
        let provider = provider(&capture);
        let recorder = recorder(&provider);

        metrics::with_local_recorder(&recorder, || {
            metrics::describe_histogram!(
                "gdi_t_wait_seconds",
                metrics::Unit::Seconds,
                "how long a thing waited"
            );
            metrics::histogram!("gdi_t_wait_seconds").record(1.0);
        });
        provider.force_flush().expect("flush");

        let points = capture.points();
        let wait = find(&points, "gdi_t_wait_seconds");
        assert_eq!(wait.description, "how long a thing waited");
        assert_eq!(wait.unit, "s");
        provider.shutdown().expect("shutdown");
    }

    #[test]
    fn the_fanout_lands_one_increment_in_both_stores() {
        let capture = Capture::default();
        let provider = provider(&capture);
        let prometheus = PrometheusBuilder::new().build_recorder();
        let rendered = prometheus.handle();
        let fanout = Fanout::new(prometheus, Arc::new(recorder(&provider)));

        metrics::with_local_recorder(&fanout, || {
            metrics::describe_counter!("gdi_t_both_total", "in both");
            metrics::counter!("gdi_t_both_total", "k" => "v").increment(7);
            metrics::gauge!("gdi_t_both_level").set(1.5);
            metrics::histogram!("gdi_t_both_seconds").record(0.5);
        });
        provider.force_flush().expect("flush");

        let text = rendered.render();
        assert!(
            text.contains("gdi_t_both_total{k=\"v\"} 7"),
            "the Prometheus side must still render the series: {text}"
        );
        assert!(text.contains("gdi_t_both_level 1.5"), "{text}");
        let points = capture.points();
        let both = find(&points, "gdi_t_both_total");
        assert_eq!(both.point, Point::Sum(7.0));
        assert_eq!(both.description, "in both");
        assert_eq!(find(&points, "gdi_t_both_level").point, Point::Gauge(1.5));
        assert!(matches!(
            find(&points, "gdi_t_both_seconds").point,
            Point::Histogram { count: 1, .. }
        ));
        provider.shutdown().expect("shutdown");
    }

    /// Wire level: the OTLP metrics exporter posts the mirrored series, by name, to
    /// `/v1/metrics`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn otlp_metrics_push_posts_the_series_by_name() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/metrics"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        #[cfg(feature = "tls")]
        crate::preflight::install_crypto_provider();

        let (provider, meter) = crate::logging::otel::build_meter_provider(
            &server.uri(),
            None,
            "test",
            Duration::from_secs(3600),
        )
        .expect("the meter provider builds against a mock collector");
        let recorder = OtelRecorder::new(meter, HISTOGRAM_BUCKETS);
        metrics::with_local_recorder(&recorder, || {
            metrics::counter!("gdi_t_wire_total", "plane" => "public").increment(1);
        });
        // Flush off the runtime workers: the blocking exporter runs on the reader's own
        // thread, so block there rather than on a worker that must also serve the mock.
        tokio::task::spawn_blocking(move || {
            let _ = provider.shutdown();
        })
        .await
        .expect("the flush thread joins");

        let requests = server
            .received_requests()
            .await
            .expect("the mock records requests");
        assert!(
            !requests.is_empty(),
            "the exporter must POST at least one OTLP batch to /v1/metrics"
        );
        let bodies: String = requests
            .iter()
            .map(|r| String::from_utf8_lossy(&r.body).into_owned())
            .collect();
        assert!(
            bodies.contains("gdi_t_wire_total"),
            "the series name must travel verbatim in the exported payload"
        );
        assert!(
            bodies.contains("public"),
            "the label value must travel as an attribute"
        );
    }
}
