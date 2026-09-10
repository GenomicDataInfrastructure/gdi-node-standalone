//! Network smoke test (ignored by default) for the bundled-CA-roots guarantee.
//!
//! Proves that [`gdi_node_standalone_core::tls::https_client_builder`] verifies public TLS
//! using the compiled-in Mozilla roots (`webpki-root-certs`) merged onto the host
//! platform-verifier — so the self-contained tool/service binaries verify HTTPS on
//! any host, including a musl/`scratch`/HPC node with no system CA bundle.
//!
//! Needs network egress, so it is `#[ignore]`d (the offline gate skips it). Run it:
//! ```text
//! # Normal host (OS trust store present, plus the bundled roots):
//! cargo test -p gdi-dataset-tool --test tls_roots -- --ignored
//!
//! # Simulate a cert-less host (musl/scratch/HPC): the OS store loads nothing, so
//! # only the compiled-in Mozilla roots can carry the handshake. A bare
//! # `reqwest::Client::builder()` fails here; the shared builder does not.
//! SSL_CERT_FILE=/nonexistent SSL_CERT_DIR=/nonexistent \
//!     cargo test -p gdi-dataset-tool --test tls_roots -- --ignored
//! ```
//! The env is set by the invoker (not the test) because editing the process
//! environment is `unsafe` under edition 2024 and this workspace `forbid`s unsafe.

#[test]
#[ignore = "needs network egress; run explicitly with --ignored"]
fn bundled_roots_verify_public_tls() {
    // reqwest's `rustls-no-provider` installs no CryptoProvider, so do it here (as the
    // tool/service do at startup) before building any client.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime");

    rt.block_on(async {
        let client = gdi_node_standalone_core::tls::https_client_builder()
            .build()
            .expect("HTTPS client builds (ring provider + bundled roots)");

        let resp = client
            .get("https://www.rust-lang.org/")
            .send()
            .await
            .expect("TLS handshake verified via the bundled Mozilla roots");

        assert!(
            resp.status().is_success() || resp.status().is_redirection(),
            "unexpected status: {}",
            resp.status()
        );
    });
}
