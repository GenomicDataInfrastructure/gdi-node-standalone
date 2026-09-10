//! Per-source exponential backoff for transient ingest failures.
//!
//! A transient ingest error (Vault unreachable while minting a PME data key, an S3 hiccup)
//! is not quarantined and records no signature, so the next reconcile re-ingests the source.
//! Without pacing that becomes a hot retry loop under a fast reconcile trigger (a filesystem
//! watcher, `SIGUSR1`, an S3-poll storm), burning CPU, backend calls and log volume. This
//! paces the retry with capped exponential backoff keyed by dataset id, cleared per id on
//! the first successful ingest.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Base backoff window, applied from the second consecutive failure onward. The first
/// failure retries immediately; the window doubles on each subsequent failure.
const BASE: Duration = Duration::from_secs(5);
/// Ceiling on the backoff window, so a long outage still picks recovery up promptly once the
/// backend returns.
const CEILING: Duration = Duration::from_mins(10);

/// The backoff window after `attempts` consecutive transient failures (1-based).
///
/// The first failure retries immediately (`Duration::ZERO`), so a one-off blip recovers on the
/// next reconcile. From the second failure the window is
/// `min(BASE · 2^(attempts-2), CEILING)`. Overflow-safe for any `attempts`.
#[must_use]
pub fn backoff_delay(attempts: u32) -> Duration {
    if attempts <= 1 {
        return Duration::ZERO;
    }
    let shift = attempts.saturating_sub(2);
    let factor = 1u32.checked_shl(shift).unwrap_or(u32::MAX);
    BASE.checked_mul(factor).unwrap_or(CEILING).min(CEILING)
}

struct Entry {
    attempts: u32,
    next_eligible: Instant,
}

/// A shared map of `datasetId → backoff state`. It holds every id tracked as failing, from its
/// first transient failure until its first success, not only those currently inside a backoff
/// window. Cleared per id on the first successful ingest.
#[derive(Default)]
pub struct RetryBackoff {
    inner: Mutex<HashMap<String, Entry>>,
}

impl RetryBackoff {
    /// An empty backoff map (no id is backing off).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Publish the tracked-source count to the `gdi_ingest_transient_backoff` gauge.
    ///
    /// Every mutator calls this under the map's lock. Published after the lock is dropped,
    /// two racing mutators could set their lengths in the opposite order to their mutations
    /// and leave the gauge stale.
    fn publish_gauge(len: usize) {
        #[expect(
            clippy::cast_precision_loss,
            reason = "the count of backing-off sources is small; f64 for the gauge is exact"
        )]
        ::metrics::gauge!(crate::metrics::INGEST_TRANSIENT_BACKOFF).set(len as f64);
    }

    /// Record a transient failure for `id` at `now`, extending its backoff window, and
    /// return the new 1-based consecutive-failure count for an escalating caller warning.
    pub fn record_failure(&self, id: &str, now: Instant) -> u32 {
        let mut m = self.lock();
        let attempts = {
            let e = m.entry(id.to_owned()).or_insert(Entry {
                attempts: 0,
                next_eligible: now,
            });
            e.attempts = e.attempts.saturating_add(1);
            e.next_eligible = now.checked_add(backoff_delay(e.attempts)).unwrap_or(now);
            e.attempts
        };
        Self::publish_gauge(m.len());
        attempts
    }

    /// Whether `id` is still inside its backoff window at `now` (so a reconcile skips it).
    #[must_use]
    pub fn is_backing_off(&self, id: &str, now: Instant) -> bool {
        self.lock().get(id).is_some_and(|e| e.next_eligible > now)
    }

    /// Forget any backoff for `id`. Called on a successful ingest, an erase and a delete.
    pub fn clear(&self, id: &str) {
        let mut m = self.lock();
        m.remove(id);
        Self::publish_gauge(m.len());
    }

    /// The number of sources currently tracked as failing, which is the value
    /// [`Self::publish_gauge`] reports. A sustained non-zero count means a persistently
    /// failing backend. Test-only; production reads the gauge.
    #[cfg(test)]
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delay_is_free_on_the_first_failure_then_grows_and_caps() {
        // A one-off blip retries immediately; only repeated failures are paced.
        assert_eq!(backoff_delay(1), Duration::ZERO);
        assert_eq!(backoff_delay(2), Duration::from_secs(5));
        assert_eq!(backoff_delay(3), Duration::from_secs(10));
        assert_eq!(backoff_delay(4), Duration::from_secs(20));
        assert_eq!(backoff_delay(8), Duration::from_secs(320));
        assert_eq!(
            backoff_delay(100),
            Duration::from_mins(10),
            "caps at the ceiling"
        );
        // Never panics / overflows on a pathological attempt count.
        assert_eq!(backoff_delay(u32::MAX), Duration::from_mins(10));
    }

    #[test]
    fn records_paces_repeated_failures_and_clears_per_id() {
        let b = RetryBackoff::new();
        let t0 = Instant::now();
        assert!(!b.is_backing_off("x", t0));
        assert_eq!(b.active_count(), 0);
        // The first failure retries immediately but is still tracked, so the gauge shows a
        // source in a failing state.
        assert_eq!(b.record_failure("x", t0), 1);
        assert_eq!(
            b.active_count(),
            1,
            "a failing source is tracked for the gauge"
        );
        assert!(
            !b.is_backing_off("x", t0),
            "the first transient failure opens no backoff window"
        );
        // A second consecutive failure opens the backoff window (base 5s).
        assert_eq!(b.record_failure("x", t0), 2);
        assert!(b.is_backing_off("x", t0));
        assert!(b.is_backing_off("x", t0 + Duration::from_secs(4)));
        // Eligible again once the window elapses.
        assert!(!b.is_backing_off("x", t0 + Duration::from_secs(6)));
        // Backoff is per-id: a different id is unaffected.
        assert!(!b.is_backing_off("y", t0));
        // A success clears it.
        b.clear("x");
        assert!(!b.is_backing_off("x", t0));
    }
}
