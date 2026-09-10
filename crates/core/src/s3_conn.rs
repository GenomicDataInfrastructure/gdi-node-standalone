//! Shared S3 client construction.
//!
//! The service (`[[s3.buckets]]`) and the tool (a profile's `s3` block) both build
//! an `object_store` S3 client against the same Ceph/Garage/minio endpoint, and
//! they must agree on region, path-style vs virtual-hosted addressing, `allow_http`,
//! and the both-or-neither credential / request-signing rule. Otherwise the two
//! binaries can read the same bucket differently. This module holds that
//! `AmazonS3Builder` configuration in one place (the connection-contract analog of
//! [`crate::s3_layout`]'s object-name contract). Each crate maps its own config
//! struct into [`S3ConnParams`] and calls [`build_object_store`].
//!
//! Available only under the `s3` feature: the tool always links it, and the
//! service links it under its `s3` feature (the default lite build, which has no
//! S3, does not).

use std::sync::Arc;

use object_store::ObjectStore;
use object_store::aws::AmazonS3Builder;

/// Endpoint + addressing + optional credentials for one S3 bucket connection.
///
/// `endpoint` and `bucket` are already-resolved (each crate validates its own
/// required-field errors); the remaining fields carry the drift-prone knobs.
///
/// Not `Debug`, like the other secret-bearing config structs: it holds the inline S3
/// `access_key_id` and `secret_access_key` in cleartext, so it must never be formattable.
/// A `debug!(?params)` would otherwise write the S3 credentials to the logs.
#[derive(Clone, Copy)]
pub struct S3ConnParams<'a> {
    /// The S3 endpoint URL (custom endpoint for Ceph/Garage/minio).
    pub endpoint: &'a str,
    /// The bucket name on the endpoint.
    pub bucket: &'a str,
    /// Key prefix the client is confined to within `bucket`; `""` addresses the whole
    /// bucket.
    ///
    /// Part of the connection contract rather than of each call site: it decides which
    /// keyspace this client addresses, as `bucket` does. Every store is built from these
    /// params, so a caller cannot acquire an S3 client without stating its prefix.
    /// Prefixing at the call sites instead would leave every place that formats a key free
    /// to forget, and reading the bucket root would go unnoticed.
    pub prefix: &'a str,
    /// Region; defaults to `us-east-1` (the placeholder Ceph/Garage/minio accept).
    pub region: Option<&'a str>,
    /// Path-style addressing (Ceph/Garage/minio) vs virtual-hosted.
    pub path_style: bool,
    /// Allow plain-HTTP endpoints (local dev only).
    pub allow_http: bool,
    /// Inline access key id (paired with `secret_access_key`).
    pub access_key_id: Option<&'a str>,
    /// Inline secret access key (paired with `access_key_id`).
    pub secret_access_key: Option<&'a str>,
}

/// Error from [`build_object_store`].
#[derive(Debug, thiserror::Error)]
pub enum S3ConnError {
    /// Exactly one of `access_key_id` / `secret_access_key` was set.
    #[error("set both access_key_id and secret_access_key, or neither")]
    HalfCredentials,
    /// The `object_store` builder failed.
    #[error("building the S3 client: {0}")]
    Build(#[from] object_store::Error),
}

/// Build an `object_store` S3 client from [`S3ConnParams`].
///
/// Both inline credentials present ⇒ SigV4-signed; neither ⇒ anonymous
/// (`skip_signature`, for a public bucket); exactly one ⇒ [`S3ConnError::HalfCredentials`].
///
/// # Errors
///
/// Returns [`S3ConnError::HalfCredentials`] for a half credential, or
/// [`S3ConnError::Build`] if the underlying client cannot be constructed.
pub fn build_object_store(params: &S3ConnParams) -> Result<Arc<dyn ObjectStore>, S3ConnError> {
    build_inner(
        params,
        crate::tls::s3_client_options(),
        object_store::RetryConfig::default(),
    )
}

/// Build an `object_store` S3 client for **metadata** operations — listings, the
/// `_sync_marker.json` `HeadObject`, and the small `.state.json` / overlay /
/// `_status` objects — as opposed to the package body.
///
/// Identical to [`build_object_store`] except for two bounds that only make sense
/// for small, latency-bounded requests:
///
/// * a per-request timeout ([`crate::tls::S3_METADATA_TIMEOUT`]). The package store runs
///   with `with_timeout_disabled()` so a legitimately slow multi-GB body is never cut
///   off. That also means an endpoint which accepts the TCP connection and then never
///   answers hangs forever: the connect timeout is already satisfied, and
///   `crate::tls::S3_BODY_READ_TIMEOUT` bounds only the gap between body reads, which
///   never begin. A poll loop awaiting such a request wedges with no self-recovery.
///   Metadata responses are small and prompt, so bounding them turns that permanent wedge
///   into a transient poll error that retries on the next cadence.
/// * a small retry budget (`METADATA_RETRY`). The bucket poll loop is the real retry
///   loop, coming back every `marker_poll_interval`, so exhausting `object_store`'s
///   default of 10 in-request retries only delays the inevitable. At startup it also
///   holds the boot reconcile in backoff before it can mark a refusing bucket unhealthy
///   and let the node come ready.
///
/// # Errors
///
/// As [`build_object_store`].
pub fn build_metadata_object_store(
    params: &S3ConnParams,
) -> Result<Arc<dyn ObjectStore>, S3ConnError> {
    build_metadata_object_store_with(params, crate::tls::S3_METADATA_TIMEOUT)
}

/// [`build_metadata_object_store`] with an explicit per-request bound.
///
/// Exists so a test can prove the bounding mechanism in milliseconds rather than waiting
/// out the production bound. Such a test establishes that a stalled endpoint surfaces as
/// an error instead of hanging; the bound's numeric value is not part of that claim.
///
/// [`crate::tls::S3_METADATA_TIMEOUT`] stays the production bound:
/// [`build_metadata_object_store`] is a one-line delegation, so the only way to unbound
/// production is to edit that line against its own doc comment.
///
/// `no_test_waits_out_the_s3_metadata_timeout` (in `test-util`) keeps tests off the
/// constant, so a third caller cannot go back to sleeping for the full bound.
///
/// # Errors
///
/// As [`build_object_store`].
pub fn build_metadata_object_store_with(
    params: &S3ConnParams,
    request_timeout: std::time::Duration,
) -> Result<Arc<dyn ObjectStore>, S3ConnError> {
    build_inner(
        params,
        crate::tls::s3_metadata_client_options_with(request_timeout),
        METADATA_RETRY,
    )
}

/// Retry budget for metadata requests, far below `object_store`'s default of 10 retries
/// over 180 s. A definitively-failing endpoint (connection refused, DNS failure) does not
/// become reachable by retrying harder inside one request, and the poll loop already
/// retries on its own cadence. Failing fast is what lets a node with one dead provider
/// bucket reach `ready` promptly instead of sitting in the startup reconcile.
const METADATA_RETRY: object_store::RetryConfig = object_store::RetryConfig {
    backoff: object_store::BackoffConfig {
        init_backoff: std::time::Duration::from_millis(100),
        max_backoff: std::time::Duration::from_secs(1),
        base: 2.0,
    },
    max_retries: 2,
    retry_timeout: std::time::Duration::from_secs(10),
};

/// Shared `AmazonS3Builder` wiring for [`build_object_store`] and
/// [`build_metadata_object_store`]: the whole connection contract in one place (region,
/// addressing, `allow_http`, the both-or-neither credential rule). The two public builders
/// differ only in the client options and retry budget they pass in.
fn build_inner(
    params: &S3ConnParams,
    client_options: object_store::ClientOptions,
    retry: object_store::RetryConfig,
) -> Result<Arc<dyn ObjectStore>, S3ConnError> {
    let builder = AmazonS3Builder::new()
        .with_endpoint(params.endpoint)
        .with_bucket_name(params.bucket)
        .with_region(params.region.unwrap_or("us-east-1"))
        .with_virtual_hosted_style_request(!params.path_style)
        // Bundled Mozilla roots (merged with the host store) so S3-over-HTTPS verifies
        // on a musl/scratch/HPC node with no system CA bundle. See `crate::tls`.
        //
        // Order matters. `with_client_options` replaces the builder's whole
        // `ClientOptions`, whose `allow_http` defaults to false, so it must come before
        // `with_allow_http`. Reversed, the caller's `allow_http` is clobbered back to
        // false and every plaintext-HTTP S3 endpoint breaks.
        .with_client_options(client_options)
        .with_allow_http(params.allow_http)
        .with_retry(retry);

    // Both-or-neither: both inline creds ⇒ SigV4-signed, neither ⇒ anonymous.
    let builder = match (params.access_key_id, params.secret_access_key) {
        (Some(key), Some(secret)) => builder
            .with_access_key_id(key)
            .with_secret_access_key(secret),
        // No inline creds: anonymous read of a public bucket (no request signing).
        (None, None) => builder.with_skip_signature(true),
        _ => return Err(S3ConnError::HalfCredentials),
    };

    Ok(scope_to_prefix(Arc::new(builder.build()?), params.prefix))
}

/// Confine `store` to `prefix`: every key it is asked for is resolved under the prefix,
/// and every key it reports (listings, `GetResult` metadata) has the prefix stripped
/// back off — so callers keep addressing the flat `{id}.tar.c4gh` / `_sync_marker.json`
/// contract of [`crate::s3_layout`] and the prefix stays a deployment fact.
///
/// An empty `prefix` returns `store` unchanged, so an unprefixed deployment pays nothing.
///
/// Public because it is also the seam a test uses to build the store a prefixed bucket
/// would get over an `InMemory`, so the test exercises the wrapper production uses.
#[must_use]
pub fn scope_to_prefix(store: Arc<dyn ObjectStore>, prefix: &str) -> Arc<dyn ObjectStore> {
    if prefix.is_empty() {
        return store;
    }
    Arc::new(object_store::prefix::PrefixStore::new(store, prefix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::ObjectStoreExt as _;

    fn params<'a>(
        access_key_id: Option<&'a str>,
        secret_access_key: Option<&'a str>,
    ) -> S3ConnParams<'a> {
        S3ConnParams {
            endpoint: "http://localhost:9000",
            bucket: "b",
            prefix: "",
            region: None,
            path_style: true,
            allow_http: true,
            access_key_id,
            secret_access_key,
        }
    }

    fn stalled_params(endpoint: &str) -> S3ConnParams<'_> {
        S3ConnParams {
            endpoint,
            bucket: "b",
            prefix: "",
            region: None,
            path_style: true,
            allow_http: true,
            access_key_id: Some("k"),
            secret_access_key: Some("s"),
        }
    }

    #[tokio::test]
    async fn metadata_store_bounds_a_stalled_response() {
        // The wedge: a provider endpoint that accepts TCP but never answers the marker
        // HeadObject. With no per-request timeout the poll loop awaits it forever and that
        // bucket's monitor never recovers. The metadata store must bound it, so the poll
        // fails transiently and retries on the next cadence.
        //
        // The bound is injected at 200 ms rather than waiting out the production value.
        // This establishes that a stall surfaces as an error rather than hanging; the
        // bound's numeric value is not part of that claim. `S3_METADATA_TIMEOUT` remains
        // the production value, and `s3_metadata_client_options()` is a one-line
        // delegation to the constructor this calls.
        const BOUND: std::time::Duration = std::time::Duration::from_millis(200);
        let endpoint = test_util::stalling_endpoint();
        let store = build_inner(
            &stalled_params(&endpoint),
            crate::tls::s3_metadata_client_options_with(BOUND),
            METADATA_RETRY,
        )
        .expect("build");

        // `METADATA_RETRY` allows 2 retries with ~100-300 ms backoff, so the whole call is
        // about 3 x BOUND plus backoff. The outer 10 s is slack, not the thing under test:
        // an unbounded request timeout would hang the head(), fire this outer timeout, and
        // fail the `is_ok()` assertion below.
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            store.head(&object_store::path::Path::from("_sync_marker.json")),
        )
        .await;

        assert!(
            res.is_ok(),
            "a stalled endpoint must make the metadata request FAIL, not hang forever"
        );
        assert!(
            res.expect("bounded").is_err(),
            "the stalled request must surface as an error the poll loop can retry"
        );
    }

    #[tokio::test]
    async fn package_store_stays_unbounded_for_large_bodies() {
        // The complement, and the reason metadata needs its own store: the package store
        // must not bound a request, or a legitimately slow multi-GB .tar.c4gh download
        // would be cut off mid-body. Against a stalling endpoint it is therefore still
        // waiting, which is correct here and a wedge anywhere else.
        let endpoint = test_util::stalling_endpoint();
        let store = build_object_store(&stalled_params(&endpoint)).expect("build");

        let res = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            store.head(&object_store::path::Path::from("_sync_marker.json")),
        )
        .await;

        assert!(
            res.is_err(),
            "the package store must remain unbounded (still awaiting), so that a slow \
             large body is never truncated -- metadata ops must not share it"
        );
    }

    /// The package-body store must carry a per-read stall bound.
    ///
    /// It has no total-request timeout, so a multi-GB body is never truncated. That leaves
    /// the "endpoint answers `200`, then blackholes the connection" case bounded by
    /// nothing: connect has already succeeded, the running-byte cap never trips because no
    /// bytes arrive, and `download_package` is awaited inline from the bucket reconcile, so
    /// that bucket's poll loop parks until the process restarts. A read timeout resets
    /// after each successful read, so it bounds the stall without bounding the transfer.
    ///
    /// Asserting the option is configured, rather than its rendered value, is what makes
    /// this fail if the `with_read_timeout` call is dropped.
    #[test]
    fn package_body_store_bounds_a_stalled_body() {
        let opts = crate::tls::s3_client_options();
        assert!(
            opts.get_config_value(&object_store::ClientConfigKey::ReadTimeout)
                .is_some(),
            "the package-body store must set a per-read stall timeout"
        );
    }

    /// The prefix wrapper is the whole of the key scoping. A caller that keeps writing the
    /// flat `s3_layout` names must reach objects under the prefix, must see listings with
    /// the prefix stripped (or every `key.strip_suffix(".tar.c4gh")` in the reconcile stops
    /// matching), and must not see a sibling prefix's objects at all.
    #[tokio::test]
    async fn scoping_to_a_prefix_hides_the_rest_of_the_bucket() {
        let inner: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let scoped = scope_to_prefix(Arc::clone(&inner), "gdi-node-storage/");

        // Written through the scoped store under the flat name the reconcile uses...
        scoped
            .put(
                &object_store::path::Path::from("GDI-1.tar.c4gh"),
                object_store::PutPayload::from_static(b"pkg"),
            )
            .await
            .expect("put");
        // ...lands under the prefix in the real bucket.
        assert!(
            inner
                .head(&object_store::path::Path::from(
                    "gdi-node-storage/GDI-1.tar.c4gh"
                ))
                .await
                .is_ok(),
            "the object must be written under the configured prefix"
        );

        // A co-tenant object outside the prefix, such as another tenant's backups.
        inner
            .put(
                &object_store::path::Path::from("backups/wal.gz"),
                object_store::PutPayload::from_static(b"secret"),
            )
            .await
            .expect("put");

        let listed = scoped.list_with_delimiter(None).await.expect("list");
        assert_eq!(
            listed
                .objects
                .iter()
                .map(|m| m.location.to_string())
                .collect::<Vec<_>>(),
            vec!["GDI-1.tar.c4gh".to_owned()],
            "the scoped listing must be prefix-STRIPPED and must not reach outside the prefix"
        );
        assert!(
            listed.common_prefixes.is_empty(),
            "the co-tenant `backups/` prefix must not appear in the scoped listing: {:?}",
            listed.common_prefixes
        );
        assert!(
            scoped
                .head(&object_store::path::Path::from("backups/wal.gz"))
                .await
                .is_err(),
            "a key outside the prefix must not be reachable through the scoped store"
        );

        // The unprefixed deployment is untouched, asserted as identity rather than
        // behaviour: a wrapper with an empty prefix resolves every key the same way and
        // would pass any behavioural check.
        let unscoped = scope_to_prefix(Arc::clone(&inner), "");
        assert!(
            Arc::ptr_eq(&inner, &unscoped),
            "an empty prefix must return the store itself, not wrap it"
        );
    }

    #[test]
    fn credentials_must_be_both_or_neither() {
        // Both set (signed) and neither set (anonymous) build a client.
        assert!(build_object_store(&params(Some("k"), Some("s"))).is_ok());
        assert!(build_object_store(&params(None, None)).is_ok());
        // Exactly one set is rejected before building.
        std::assert_matches!(
            build_object_store(&params(Some("k"), None)),
            Err(S3ConnError::HalfCredentials)
        );
        std::assert_matches!(
            build_object_store(&params(None, Some("s"))),
            Err(S3ConnError::HalfCredentials)
        );
    }
}
