//! Derive a dataset's `dct:issued` / `dct:modified` `xsd:dateTime` from its
//! `datasetId` timestamp tail.
//!
//! The implementation lives in [`gdi_node_standalone_core::datetime`] so the `beacon`
//! crate can derive the same value (its Beacon collection `createDateTime`) without
//! depending on `fairdp`. It is re-exported here for the `crate::datetime::…` call
//! sites in `graph` and `root`.

pub use gdi_node_standalone_core::datetime::{
    dataset_datetime, rfc3339_instant_nanos, to_xsd_datetime,
};
