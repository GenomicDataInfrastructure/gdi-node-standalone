//! Test-only deterministic fault injection at the process's durable-write and
//! ingest-publish chokepoints.
//!
//! This module is the single seam that lets the test suite exercise the node's
//! behaviour under conditions that are otherwise impossible to reproduce
//! deterministically: a full disk (`ENOSPC`) partway through a write, and a
//! crash (panic) partway through publishing a dataset. Every data-directory write
//! in the node goes straight to `std::fs`, so there is no filesystem layer to
//! decorate — instead the wired chokepoints ([`crate::util::write_durable_atomic`]
//! and the ingest atomic-store path) call [`guard`] with a [`FaultPoint`] and a
//! per-call key (a dataset id or path), and a test arms that point for a
//! matching key to fail or panic on its next call.
//!
//! # Zero-cost in production
//!
//! [`guard`] compiles to an inlined `Ok(())` unless the crate is built with the
//! `fault-injection` feature. That feature is enabled only through
//! dev-dependencies (the `gdi-node-standalone` node crate's integration suite and the
//! `gdi-dataset-tool` crate's tests), never a regular dependency, so no shipped
//! binary contains the arming registry or any fault check — the release build's
//! `guard` is a no-op the optimizer removes.
//!
//! # Isolation between parallel tests
//!
//! The arming registry is a single process-global map and the integration binary
//! runs tests in parallel, so an unscoped fault would fire on a concurrent test's
//! ingest. Every arm therefore carries a key substring: [`guard`] fires only
//! when the call-site key (the dataset id, or the durable-write path) contains it,
//! and a non-matching call passes through without consuming a fire. Tests use a
//! unique id/filename so their fault can never contaminate a sibling. Arming still
//! serializes (`#[serial(faults)]`) and returns a `FaultGuard` whose `Drop`
//! disarms the point, so a fault never leaks past the test that set it.
//!
//! `FaultGuard` is spelled as plain code rather than an intra-doc link. It lives in the
//! `fault-injection`-gated backend, so a link would fail a `-D warnings` doc build of this
//! crate without that feature.

/// A named point in the node's write path that a test can arm with a fault.
///
/// Passed to [`guard`] at each wired chokepoint. Kept a small closed enum (not a
/// free-form string) so a typo is a compile error and the set of wired points is
/// discoverable from one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FaultPoint {
    /// Every durable control-file write — the shared body behind all three crash-safe
    /// writers: [`crate::util::write_durable_atomic`] (the status index, lifecycle
    /// sidecars, metadata overlays, the identity-backup blob, and tool config),
    /// [`crate::util::write_secret_durable`] (crypt4gh private-key material, `0600`), and
    /// [`crate::util::write_durable_atomic_private`] (owner-only data-path control files).
    /// The [`guard`] key is the target path.
    DurableWrite,
    /// The ingest atomic-store path, just before the working dataset directory is
    /// fsynced and renamed into place. Arming an error here models a write that
    /// fails partway through publishing (the working dir is cleaned up and the
    /// dataset errors); arming a panic models a crash mid-publish (the working dir
    /// is left under `.incoming/` for the next boot to reap). The [`guard`] key is
    /// the dataset id.
    IngestStore,
    /// The S3 package download path, before the transient `.incoming/*.download`
    /// file is written. Models a disk-full (or other I/O failure) at the *download*
    /// stage — before ingest — which is transient: the download aborts, the partial
    /// is unlinked, and the next poll retries. The [`guard`] key is the dataset id.
    S3Download,
    /// The ingest atomic-store path, immediately after the working dataset directory has
    /// been renamed into place but before the caller (`on_success`) records the status.
    /// This is the torn cross-store window: arming a panic here models a crash after the
    /// atomic publish committed the dataset dir to disk but before the `.status.json`
    /// entry was written, so a restart finds a complete, valid dataset dir with no
    /// matching status entry, or a stale `Error` one. [`FaultPoint::IngestStore`] fires on
    /// the safe side, before the rename, so this point is the only way to reach that
    /// recovery path. The [`guard`] key is the dataset id.
    PostRename,
    /// The dataset delete path, immediately after the status entry has been purged, and
    /// the cache entry removed, but before the `data_dir/{id}/` directory is removed.
    /// This is the torn window of the two-store erasure: arming a panic here models a
    /// crash that leaves the dataset dir on disk with no status entry (un-erased data
    /// that a restart could re-serve). A durable `.deleting/{id}` intent marker written
    /// before the purge makes it recoverable — the next boot's `reap_deleting` finishes
    /// the erasure. The [`guard`] key is the dataset id.
    PostStatusPurge,
}

#[cfg(not(feature = "fault-injection"))]
mod backend {
    use super::FaultPoint;

    /// Fault-check hook — a no-op in every build without the `fault-injection`
    /// feature (i.e. every shipped binary). Always returns `Ok(())`.
    ///
    /// # Errors
    /// Never, in this build; the signature matches the `fault-injection` build so
    /// the wired call sites are identical.
    #[inline]
    pub fn guard(_point: FaultPoint, _key: &str) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(feature = "fault-injection")]
mod backend {
    use super::FaultPoint;
    use std::collections::HashMap;
    use std::io;
    use std::sync::{Mutex, OnceLock, PoisonError};

    #[derive(Clone, Copy)]
    enum Action {
        Io(io::ErrorKind),
        Panic,
        Delay(std::time::Duration),
    }

    struct Armed {
        action: Action,
        remaining: usize,
        key_match: String,
    }

    fn registry() -> &'static Mutex<HashMap<FaultPoint, Armed>> {
        static REGISTRY: OnceLock<Mutex<HashMap<FaultPoint, Armed>>> = OnceLock::new();
        REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
    }

    /// Fault-check hook wired into each write chokepoint. If `point` is armed, has
    /// fires remaining, and `key` contains the armed key substring, consumes one
    /// fire and either returns a simulated I/O error (out-of-space by default, or
    /// the kind armed via [`arm_io`]), panics, or — when armed via [`arm_delay`] —
    /// blocks for the delay and then returns `Ok(())`; a non-matching or unarmed
    /// call returns `Ok(())` without consuming a fire.
    ///
    /// # Errors
    /// Returns an [`io::Error`] of kind [`io::ErrorKind::StorageFull`] when `point`
    /// is armed via [`arm_enospc`] for a matching `key`.
    ///
    /// # Panics
    /// Panics when `point` is armed via [`arm_panic`] for a matching `key`.
    pub fn guard(point: FaultPoint, key: &str) -> io::Result<()> {
        let action = {
            let mut reg = registry().lock().unwrap_or_else(PoisonError::into_inner);
            match reg.get_mut(&point) {
                Some(armed) if armed.remaining > 0 && key.contains(&armed.key_match) => {
                    armed.remaining -= 1;
                    let action = armed.action;
                    if armed.remaining == 0 {
                        reg.remove(&point);
                    }
                    action
                }
                _ => return Ok(()),
            }
        };
        match action {
            Action::Io(kind) => Err(io::Error::new(
                kind,
                "fault-injection: simulated I/O failure",
            )),
            Action::Panic => panic!("fault-injection: simulated crash at {point:?}"),
            // Block this thread for `d` then proceed. The registry lock was released
            // above (the `let action` block), so the sleep never blocks a concurrent
            // `guard` call. Used to force an operation to overrun a deadline — e.g. a
            // blocking-thread `IngestStore` guard sleeping past `ingest_timeout_seconds`
            // so the ingest detaches, exercising the detached-task accounting.
            Action::Delay(d) => {
                std::thread::sleep(d);
                Ok(())
            }
        }
    }

    /// Test handle that disarms its [`FaultPoint`] when dropped, so a fault can
    /// never leak past the test that armed it.
    #[must_use = "binding the returned guard keeps the fault armed; dropping it disarms the point"]
    pub struct FaultGuard {
        point: FaultPoint,
    }

    impl Drop for FaultGuard {
        fn drop(&mut self) {
            let mut reg = registry().lock().unwrap_or_else(PoisonError::into_inner);
            reg.remove(&self.point);
        }
    }

    fn arm(point: FaultPoint, action: Action, key_match: &str, times: usize) -> FaultGuard {
        let mut reg = registry().lock().unwrap_or_else(PoisonError::into_inner);
        reg.insert(
            point,
            Armed {
                action,
                remaining: times,
                key_match: key_match.to_owned(),
            },
        );
        FaultGuard { point }
    }

    /// Arm `point` to return a simulated `ENOSPC` (disk full — a transient
    /// resource-exhaustion error) on each of its next `times` [`guard`] calls whose
    /// key contains `key_match`, then pass through.
    pub fn arm_enospc(point: FaultPoint, key_match: &str, times: usize) -> FaultGuard {
        arm(
            point,
            Action::Io(io::ErrorKind::StorageFull),
            key_match,
            times,
        )
    }

    /// Arm `point` to return an [`io::Error`] of the given `kind` on each of its next
    /// `times` [`guard`] calls whose key contains `key_match`, then pass through.
    ///
    /// Use for I/O failures other than ENOSPC, such as a permanent
    /// [`io::ErrorKind::ReadOnlyFilesystem`] to exercise the quarantine (not retry)
    /// classification path.
    pub fn arm_io(
        point: FaultPoint,
        key_match: &str,
        kind: io::ErrorKind,
        times: usize,
    ) -> FaultGuard {
        arm(point, Action::Io(kind), key_match, times)
    }

    /// Arm `point` to panic on each of its next `times` [`guard`] calls whose key
    /// contains `key_match` (models a crash mid-write), then pass through.
    pub fn arm_panic(point: FaultPoint, key_match: &str, times: usize) -> FaultGuard {
        arm(point, Action::Panic, key_match, times)
    }

    /// Arm `point` to block for `delay` on each of its next `times` [`guard`] calls whose
    /// key contains `key_match`, then proceed (returning `Ok`).
    ///
    /// Models a slow/hung operation. Firing at a chokepoint that runs on a blocking
    /// thread (e.g. [`FaultPoint::IngestStore`]) with a `delay` longer than the caller's
    /// deadline forces that deadline to elapse deterministically — used to exercise the
    /// ingest detached-timeout accounting without relying on wall-clock flakiness.
    pub fn arm_delay(
        point: FaultPoint,
        key_match: &str,
        delay: std::time::Duration,
        times: usize,
    ) -> FaultGuard {
        arm(point, Action::Delay(delay), key_match, times)
    }
}

pub use backend::*;

#[cfg(all(test, feature = "fault-injection"))]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;
    use serial_test::serial;
    use std::io::ErrorKind;
    use std::time::{Duration, Instant};

    #[test]
    #[serial(faults)]
    fn arm_delay_blocks_for_the_delay_then_proceeds_and_disarms() {
        let _g = arm_delay(
            FaultPoint::IngestStore,
            "slow",
            Duration::from_millis(80),
            1,
        );
        let start = Instant::now();
        assert!(guard(FaultPoint::IngestStore, "slow-ds").is_ok());
        assert!(
            start.elapsed() >= Duration::from_millis(70),
            "the guard must block for ~the armed delay before proceeding"
        );
        // Fired once (times == 1) => disarmed: the next call does not delay.
        let start2 = Instant::now();
        assert!(guard(FaultPoint::IngestStore, "slow-ds").is_ok());
        assert!(
            start2.elapsed() < Duration::from_millis(40),
            "a disarmed delay point must not block"
        );
    }

    #[test]
    #[serial(faults)]
    fn unarmed_guard_is_ok() {
        assert!(guard(FaultPoint::DurableWrite, "anything").is_ok());
    }

    #[test]
    #[serial(faults)]
    fn arm_enospc_fires_once_then_clears() {
        let _g = arm_enospc(FaultPoint::DurableWrite, "probe", 1);
        let err = guard(FaultPoint::DurableWrite, "probe").unwrap_err();
        assert_eq!(err.kind(), ErrorKind::StorageFull);
        // Fired once (times == 1); the point is now disarmed.
        assert!(guard(FaultPoint::DurableWrite, "probe").is_ok());
    }

    #[test]
    #[serial(faults)]
    fn arm_io_injects_the_requested_kind() {
        // A permanent kind (unlike ENOSPC) drives the quarantine-not-retry path.
        let _g = arm_io(
            FaultPoint::IngestStore,
            "ds",
            ErrorKind::ReadOnlyFilesystem,
            1,
        );
        let err = guard(FaultPoint::IngestStore, "ds").unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ReadOnlyFilesystem);
    }

    #[test]
    #[serial(faults)]
    fn arm_enospc_fires_the_requested_number_of_times() {
        let _g = arm_enospc(FaultPoint::DurableWrite, "probe", 2);
        assert!(guard(FaultPoint::DurableWrite, "probe").is_err());
        assert!(guard(FaultPoint::DurableWrite, "probe").is_err());
        assert!(guard(FaultPoint::DurableWrite, "probe").is_ok());
    }

    #[test]
    #[serial(faults)]
    fn fault_only_fires_for_a_matching_key() {
        let _g = arm_enospc(FaultPoint::IngestStore, "alpha", 1);
        // A non-matching key passes through without consuming the fire, so it cannot
        // contaminate a concurrent sibling test.
        assert!(
            guard(FaultPoint::IngestStore, "beta-dataset").is_ok(),
            "a non-matching key must not fire"
        );
        // The matching key still fires (the fire was not consumed above).
        assert!(
            guard(FaultPoint::IngestStore, "alpha-dataset").is_err(),
            "a matching key fires"
        );
        // And is now consumed.
        assert!(guard(FaultPoint::IngestStore, "alpha-dataset").is_ok());
    }

    #[test]
    #[serial(faults)]
    fn arm_panic_panics() {
        let _g = arm_panic(FaultPoint::IngestStore, "boom", 1);
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            guard(FaultPoint::IngestStore, "boom-ds")
        }));
        std::panic::set_hook(prev);
        assert!(result.is_err(), "an armed panic point must panic");
    }

    #[test]
    #[serial(faults)]
    fn guard_dropping_disarms() {
        {
            let _g = arm_enospc(FaultPoint::DurableWrite, "probe", 5);
        } // dropped here, well before the 5 fires are consumed
        assert!(
            guard(FaultPoint::DurableWrite, "probe").is_ok(),
            "dropping the guard disarms the point"
        );
    }

    #[test]
    #[serial(faults)]
    fn faults_are_keyed_by_point() {
        let _g = arm_enospc(FaultPoint::DurableWrite, "probe", 1);
        // A different point is unaffected by the arming.
        assert!(guard(FaultPoint::IngestStore, "probe").is_ok());
        // The armed point still fires.
        assert!(guard(FaultPoint::DurableWrite, "probe").is_err());
    }
}
