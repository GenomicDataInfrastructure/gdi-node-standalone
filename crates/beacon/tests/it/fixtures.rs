//! Fixtures shared across the `beacon` integration suites.

use gdi_node_standalone_beacon::BeaconParams;

/// The node identity the golden snapshots pin.
///
/// `response_meta` keeps its own `org.test.beacon` identity instead: it asserts on `meta`
/// contents rather than on a golden, so its values are its own business.
pub(crate) fn beacon_cfg() -> BeaconParams {
    BeaconParams {
        id: "ee.ut.af-beacon.production".to_owned(),
        name: "GDI Estonia Beacon".to_owned(),
        ..BeaconParams::default()
    }
}
