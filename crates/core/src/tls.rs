//! Shared TLS trust-anchor policy for the networked binaries.
//!
//! The service and tool ship as self-contained binaries run in wildly different
//! places — a distroless container, a bare-metal glibc host, or a fully static
//! `musl`/`scratch`/HPC node with no system CA bundle at all. To keep the "download
//! one binary, it verifies public TLS anywhere" guarantee, each binary bundles the Mozilla
//! CA roots ([`webpki_root_certs`]) and merges them on top of the host's platform trust
//! store, rather than relying on the OS store alone.
//!
//! reqwest 0.13 dropped its bundled-`webpki-roots` feature in favour of the OS
//! `rustls-platform-verifier`; [`reqwest::ClientBuilder::tls_certs_merge`] layers the
//! bundled roots onto that verifier (internally `Verifier::new_with_extra_roots`),
//! which never errors on an empty OS store. `object_store`'s client takes the same
//! roots via [`object_store::ClientOptions::with_root_certificate`]. Both mean:
//! platform and enterprise roots on macOS, Windows and ordinary Linux, plus the Mozilla
//! bundle as a fallback that carries the handshake on a host with no system trust store.
//!
//! This is the single place the trust policy is defined, so it stays consistent
//! across the tool, the service, and `object_store`'s internal S3 client.

/// The bundled Mozilla server-authentication roots, as DER byte slices.
#[cfg(any(feature = "http", feature = "s3"))]
fn bundled_roots_der() -> impl Iterator<Item = &'static [u8]> {
    webpki_root_certs::TLS_SERVER_ROOT_CERTS
        .iter()
        .map(AsRef::as_ref)
}

/// Install `ring` as the process-wide rustls [`CryptoProvider`] default, once.
///
/// reqwest's `rustls-no-provider` and `object_store`'s client both refuse to `build()`
/// until a process default provider is installed. Calling this at the single point
/// where TLS clients are constructed guarantees it regardless of binary startup
/// ordering (the tool/service also install it at startup; `install_default` is
/// idempotent — a second call returns `Err` and is ignored).
///
/// [`CryptoProvider`]: rustls::crypto::CryptoProvider
#[cfg(any(feature = "http", feature = "s3"))]
fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// A [`reqwest::ClientBuilder`] pre-seeded with the platform trust store and the bundled
/// Mozilla roots, so HTTPS verifies even on a host with no system CA bundle, and with
/// [`secure_redirect_policy`] already applied.
///
/// Every networked reqwest client in the tool and service is built from this, so the
/// trust policy lives in exactly one place. Callers add their own timeouts, headers,
/// etc. and then `.build()`.
///
/// The redirect policy is applied here rather than by each caller, because reqwest's
/// default follows up to 10 hops with no re-validation. A caller that checks its URL with
/// [`transport_reason`] and then forgets `.redirect()` has validated hop 0 and nothing
/// else. A caller wanting a stricter policy overrides it afterwards, which is the safe
/// direction. `reqwest::Client::builder` is banned in `clippy.toml`, so a new call site
/// cannot start from a bare builder and inherit the permissive default.
#[cfg(feature = "http")]
pub fn https_client_builder() -> reqwest::ClientBuilder {
    ensure_crypto_provider();
    // `Certificate::from_der` only wraps the DER here; a malformed root (there are
    // none in the pinned bundle) would surface later at `ClientBuilder::build()`, so
    // dropping an unparseable entry cannot silently weaken a good build.
    let extra = bundled_roots_der().filter_map(|der| reqwest::tls::Certificate::from_der(der).ok());
    #[expect(
        clippy::disallowed_methods,
        reason = "the one permitted call: this IS the shared constructor the ban redirects every other site to"
    )]
    let builder = reqwest::Client::builder();
    builder
        .tls_certs_merge(extra)
        .redirect(secure_redirect_policy())
}

/// The single rule deciding whether a URL's transport is allowed, returning the human
/// reason it is refused or `None` when it is fine.
///
/// `https` anywhere is fine; `http` only to loopback. Every other scheme (`file:`, `ftp:`,
/// `data:`, …) is an unsupported scheme rather than plaintext http, since a check that
/// special-cases only `https` mislabels `file:///etc/passwd` as plaintext http.
/// Holding the rule here lets [`secure_redirect_policy`] re-apply the same check on every
/// redirect hop, so an `https` URL cannot redirect into a plaintext, link-local or `file:`
/// target. The initial check alone cannot stop that.
#[cfg(feature = "http")]
#[must_use]
pub fn transport_reason(url: &reqwest::Url) -> Option<String> {
    match url.scheme() {
        "https" => return None,
        "http" => {}
        other => {
            return Some(format!(
                "{url} uses unsupported URL scheme `{other}:`; only https (any host) and \
                 http (loopback only) are allowed."
            ));
        }
    }
    let host = url.host_str().unwrap_or("");
    // `host_str` brackets an IPv6 literal (`[::1]`); strip them before parsing.
    let bare = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    let is_loopback = bare.eq_ignore_ascii_case("localhost")
        || bare
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if is_loopback {
        return None;
    }
    Some(format!(
        "{url} is plaintext http to a non-loopback host: Use https, or a loopback address \
         for local development."
    ))
}

/// Maximum redirects a fetch will follow. Kept small: the fetches in this workspace target
/// single well-known paths, so a long redirect chain is anomalous.
#[cfg(feature = "http")]
pub const MAX_REDIRECTS: usize = 5;

/// A [`reqwest::redirect::Policy`] that re-applies [`transport_reason`] to every hop, so a
/// redirect cannot escape the transport rule the initial URL was checked against, an SSRF
/// bypass. A disallowed hop, or one past [`MAX_REDIRECTS`], fails the request loudly rather
/// than being followed.
///
/// Applied by default in [`https_client_builder`]; callers do not need to opt in.
#[cfg(feature = "http")]
#[must_use]
pub fn secure_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= MAX_REDIRECTS {
            return attempt.error(format!("too many redirects (> {MAX_REDIRECTS})"));
        }
        match transport_reason(attempt.url()) {
            None => attempt.follow(),
            Some(reason) => attempt.error(format!("refused redirect: {reason}")),
        }
    })
}

/// Connect (DNS + TCP + TLS handshake) timeout for the S3 client.
///
/// Bounds the most common S3 hang — an unreachable / blackholed / DNS-failing bucket
/// endpoint — so a steady-state reconcile cannot wedge indefinitely on it (the
/// connect attempt fails, which the monitor treats as a transient poll error, marks
/// the bucket unhealthy, and retries next cycle). This mirrors the `connect_timeout`
/// the Vault client already sets (`vault.rs`), closing an asymmetry.
///
/// A connect timeout, not a total-request one: a total timeout would also bound the
/// response body stream, aborting a legitimately large or slow multi-GB package download.
/// The residual "connection established, body stalls mid-stream" case is covered by
/// [`S3_BODY_READ_TIMEOUT`], which bounds the gap between reads without bounding the
/// transfer as a whole.
///
/// This connect timeout is paired with an explicit `.with_timeout_disabled()` in
/// [`s3_client_options`]. `object_store::ClientOptions::default()` sets a 30-second
/// total-request `timeout`, which left in place caps every package transfer at 30 s, about
/// a 375 MB body at 100 Mbps. The tool download, `status` streaming and the service
/// reconcile all share this one `ClientOptions`. Setting `with_connect_timeout` alone does
/// not clear that default, so the total timeout must be disabled explicitly.
#[cfg(feature = "s3")]
const S3_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Total-request timeout for S3 **metadata** requests (listings, the marker
/// `HeadObject`, the small `.state.json` / overlay / `_status` objects) — see
/// [`s3_metadata_client_options`] and `crate::s3_conn::build_metadata_object_store`.
///
/// This is the bound `S3_CONNECT_TIMEOUT` cannot provide. A connect timeout covers only
/// DNS, TCP and TLS. Once an endpoint has accepted the connection and then stalls, the
/// request waits forever, because the package-body store runs with
/// `with_timeout_disabled()` so a multi-GB download is never cut off. A bucket poll
/// awaiting such a request wedges permanently, with no self-recovery short of a restart.
/// The body store's own stall bound is [`S3_BODY_READ_TIMEOUT`]; this total-request bound
/// is the right shape for small, prompt metadata calls.
///
/// Metadata responses are small and prompt, so a total-request bound costs them nothing
/// and converts that permanent wedge into a transient poll error the monitor retries on
/// its normal cadence.
///
/// Paired with `S3_CONNECT_TIMEOUT` at connect ≤ 15 s and request ≤ 15 s. A single
/// `ListObjectsV2` page (≤ 1000 keys), a `HeadObject` or a few-KB `.state.json` returns in
/// well under a second even from a loaded endpoint, so this leaves about three orders of
/// magnitude of headroom. It bounds a wedge rather than expressing a latency target, and a
/// request that does exceed it is retried on the next poll rather than lost.
#[cfg(feature = "s3")]
pub const S3_METADATA_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Per-read stall timeout for the S3 **package body** store.
///
/// `object_store::ClientOptions::with_read_timeout` bounds the gap between successive
/// reads and resets after each successful one, so unlike a total-request `timeout` it never
/// truncates a legitimately large or slow transfer. A multi-GB download that keeps
/// delivering bytes is unaffected however long it runs. What it does bound is the case no
/// other timeout reaches: an endpoint or middlebox that answers `GET {id}.tar.c4gh` with
/// `200` and then blackholes the connection. Connect has already succeeded, the body cap
/// never trips because no bytes arrive, and `download_package`'s
/// `while let Some(chunk) = stream.next().await` is awaited inline from the bucket
/// reconcile, so that bucket's entire poll loop, metadata included, parks until the process
/// restarts, with nothing logged and no error metric moving.
///
/// One minute is generous for a slow link, since any live transfer delivers a chunk far
/// sooner, and far below a wedge.
#[cfg(feature = "s3")]
pub const S3_BODY_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(1);

/// The one [`object_store::ClientOptions`] constructor: bundled Mozilla roots merged on
/// top of the system store, which `object_store` forwards to its internal reqwest via
/// `tls_certs_merge`, plus [`S3_CONNECT_TIMEOUT`]. It is parameterized by the single knob
/// that differs between an S3 metadata request and a package body, `request_timeout`.
///
/// `None` disables the total-request timeout (clearing `object_store`'s 30-second
/// default, which would otherwise abort any package download longer than 30 s);
/// `Some(d)` bounds every request at `d`. Building both variants here keeps the trust store
/// and connect timeout from drifting between them.
///
/// # Known gap: this client is outside the redirect chokepoint
///
/// `clippy.toml` bans `reqwest::Client::builder`, `ClientBuilder::new` and `reqwest::get`,
/// so every hand-built HTTP client goes through [`https_client_builder`] and inherits its
/// redirect policy. That ban cannot reach here. `object_store` constructs its own `reqwest`
/// client internally and `ClientOptions` exposes no redirect knob, so the S3 stores inherit
/// `reqwest`'s default of following up to 10 redirects, including cross-host ones. The
/// absence of a redirect setting below does not mean the chokepoint covers it.
///
/// The residual exposure is blind SSRF, where the node issues a request to an
/// attacker-chosen host. It is not credential disclosure: `reqwest` strips `Authorization`
/// on a cross-host redirect, so the `SigV4` header does not travel. Bounding it needs
/// either a pre-built client passed through `object_store`'s `HttpConnector` seam or an
/// egress policy at the network layer.
#[cfg(feature = "s3")]
fn s3_options(request_timeout: Option<std::time::Duration>) -> object_store::ClientOptions {
    ensure_crypto_provider();
    // The per-read stall bound applies to both stores: it resets after every successful
    // read, so it cannot truncate a large body, and the metadata store's own total-request
    // bound is stricter anyway. Setting it here rather than only on the body path means a
    // third store cannot be added without it.
    let base = object_store::ClientOptions::new()
        .with_connect_timeout(S3_CONNECT_TIMEOUT)
        .with_read_timeout(S3_BODY_READ_TIMEOUT);
    let base = match request_timeout {
        Some(timeout) => base.with_timeout(timeout),
        None => base.with_timeout_disabled(),
    };
    bundled_roots_der()
        .filter_map(|der| object_store::Certificate::from_der(der).ok())
        .fold(base, object_store::ClientOptions::with_root_certificate)
}

/// Client options for the **package body** store: no total-request timeout, so a
/// legitimately large or slow multi-GB `.tar.c4gh` download is never cut off. Applied
/// by [`crate::s3_conn::build_object_store`].
///
/// Because this is unbounded, it must not be used for the small metadata requests a poll
/// loop awaits: an endpoint that accepts the connection and then stalls would wedge that
/// loop forever. Those use [`s3_metadata_client_options`].
#[cfg(feature = "s3")]
#[must_use]
pub fn s3_client_options() -> object_store::ClientOptions {
    s3_options(None)
}

/// Client options for the **metadata** store: every request bounded by
/// [`S3_METADATA_TIMEOUT`], so a stalled endpoint surfaces as a retryable error
/// instead of hanging the bucket poll loop forever. Applied by
/// [`crate::s3_conn::build_metadata_object_store`].
#[cfg(feature = "s3")]
#[must_use]
pub fn s3_metadata_client_options() -> object_store::ClientOptions {
    s3_metadata_client_options_with(S3_METADATA_TIMEOUT)
}

/// [`s3_metadata_client_options`] with an explicit bound.
///
/// The only caller that passes anything other than [`S3_METADATA_TIMEOUT`] is the test
/// proving that a stalled endpoint fails rather than hangs. What that test verifies is the
/// bounding mechanism, which a 200 ms bound demonstrates as well as the production value
/// and far faster. Splitting the bound from the constant keeps both: the mechanism is
/// proved in milliseconds, and the constant stays the production value.
#[cfg(feature = "s3")]
#[must_use]
pub(crate) fn s3_metadata_client_options_with(
    request_timeout: std::time::Duration,
) -> object_store::ClientOptions {
    s3_options(Some(request_timeout))
}

// Split rather than `cfg(all(test, …))`: clippy's `allow-expect-in-tests` only recognises a
// literal `cfg(test)` attribute, and folding it into an `all(…)` silently loses the exemption.
#[cfg(test)]
#[cfg(feature = "http")]
mod tests {
    use std::io::{Read as _, Write as _};

    /// Serve exactly one request on loopback, answering `302` to `location`.
    ///
    /// Returns the bound base URL. The thread exits after the single response.
    fn spawn_redirector(location: &'static str) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0_u8; 1024];
                let _ = sock.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 302 Found\r\nLocation: {location}\r\n\
                     Content-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = sock.write_all(resp.as_bytes());
            }
        });
        format!("http://{addr}")
    }

    /// The shared builder must apply the transport rule to every redirect hop, not just
    /// to the URL the caller passed. The initial hop here is loopback `http` (allowed);
    /// the redirect target is plaintext `http` to a non-loopback host (refused).
    ///
    /// Without the policy on the builder, reqwest follows the hop and the request fails
    /// later with a DNS/connect error — `is_redirect()` is what distinguishes a refused hop
    /// from a followed one whose target happened not to resolve.
    #[tokio::test]
    async fn builder_refuses_a_redirect_that_escapes_the_transport_rule() {
        let base = spawn_redirector("http://invalid.invalid/");
        let client = super::https_client_builder().build().expect("build client");

        let err = client
            .get(&base)
            .send()
            .await
            .expect_err("a redirect off the transport rule must not be followed");

        assert!(
            err.is_redirect(),
            "expected the redirect policy to refuse the hop, got: {err:?}"
        );
        assert!(
            format!("{err:?}").contains("refused redirect"),
            "the error must name the refusal, got: {err:?}"
        );
    }
}
