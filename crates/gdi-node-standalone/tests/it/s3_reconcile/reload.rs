//! Standing a bucket monitor down so a config reload can replace it.
//!
//! The reload decision itself, which buckets were added, modified or removed, lives in the
//! binary. What lives here is the half it depends on: a retired monitor stops promptly of its
//! own accord. Otherwise a `SIGHUP` that changes a bucket leaves two monitors on one channel,
//! the older one still polling with the superseded descriptor, and the symptoms of that are
//! remote from the cause.
use super::*;

/// A retired monitor returns, and does so at once rather than after a poll interval.
///
/// The timeout is the assertion, not a safety net: `marker_poll_interval` defaults to 30 s,
/// so a retirement that only set the flag — without the wake that `RetireSignal::retire`
/// pairs with it — would still return eventually and pass a test that merely awaited the
/// task. Bounding the wait well under one interval is what distinguishes the two.
#[tokio::test]
async fn a_retired_monitor_stands_down_promptly() {
    let rig = Rig::standard();
    let retire = rig.monitor.retire_signal();
    assert!(!retire.is_retired(), "a fresh monitor is not retired");

    let running = tokio::spawn(rig.monitor.clone().run());
    // Let the monitor reach its wake point (seed HeadObject, then the select).
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !running.is_finished(),
        "the monitor must poll until retired"
    );

    retire.retire();
    assert!(
        retire.is_retired(),
        "retirement is observable to the supervisor"
    );

    let stopped = tokio::time::timeout(Duration::from_secs(5), running).await;
    assert!(
        stopped.is_ok(),
        "a retired monitor must return well within one {}s poll interval, not merely \
         eventually — the supervisor is holding its channel until it does",
        rig.monitor.descriptor().marker_poll_interval
    );
    stopped
        .expect("bounded")
        .expect("the monitor task must not panic");
}

/// Retirement raised while the monitor is busy is still honoured.
///
/// `Notify::notify_one` stores a permit for a task that is not yet waiting, which is why
/// `retire` uses it: a reload lands whenever it lands, and most of a monitor's wall-clock is
/// spent reconciling rather than parked in the select. Retiring before the loop ever reaches
/// its wake point is the sharpest version of that case.
#[tokio::test]
async fn retirement_raised_before_the_first_wake_is_not_missed() {
    let rig = Rig::standard();
    let id = "GDI-EE-UTARTU-20260409143052904";
    rig.seed_package(id, Some("visible")).await;

    // Retired before `run` is even spawned: no waiter exists yet to receive the notify.
    rig.monitor.retire_signal().retire();

    let running = tokio::spawn(rig.monitor.clone().run());
    let stopped = tokio::time::timeout(Duration::from_secs(5), running).await;
    assert!(
        stopped.is_ok(),
        "a retirement raised before the monitor waits must still be seen at its first wake"
    );
    stopped
        .expect("bounded")
        .expect("the monitor task must not panic");
}

/// A monitor that is not retired keeps polling. This is the control for the two tests above.
///
/// Without it they are satisfied by a monitor that returns immediately for any reason at
/// all, which is the shape that would take a channel down silently.
#[tokio::test]
async fn an_unretired_monitor_keeps_running() {
    let rig = Rig::standard();
    let running = tokio::spawn(rig.monitor.clone().run());

    let stopped = tokio::time::timeout(Duration::from_millis(750), running).await;
    assert!(
        stopped.is_err(),
        "a monitor nobody retired must still be polling"
    );
}
