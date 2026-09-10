//! Service-side startup preflight: the build-feature cross-checks and the rustls
//! crypto-provider install.
//!
//! [`gdi_node_standalone_core::config::ServiceConfig::preflight`] runs the
//! feature-independent validation (URLs, contact points, the timeout, drain and
//! metrics-addr rules). This module adds the checks that need the Cargo
//! `cfg!(feature = …)` flags in scope, which `core` does not have: a config section whose
//! feature is not compiled in is rejected with a path-free "rebuild with `--features …`"
//! error rather than silently ignored.
//!
//! It also adds the checks that need the router in scope rather than the config alone. A
//! beacon mount prefix that would collide with a path the public router serves at the origin
//! root (`/fairdp`, `/.well-known/c4gh-recipient`) is refused here, because `core`'s
//! base-path validation sees only the string.
//!
//! Finally it installs `ring` as the process-wide rustls `CryptoProvider` when a TLS-using
//! feature (`s3` or `vault`, via the internal `tls` group) is compiled.

use gdi_node_standalone_core::config::ServiceConfig;
use gdi_node_standalone_core::error::{CoreError, CoreResult};

/// Reject a config that references a Cargo feature this binary was not built with.
///
/// The three cross-checks:
/// - `[[s3.buckets]]` present but the `s3` feature is not compiled in;
/// - `[vault]` present but the `vault` feature is not compiled in;
/// - `[vault].transit_key` set but the `pme` feature is not compiled in.
///
/// Each failure is a [`CoreError::InvalidConfig`] in the same closed, path-free vocabulary
/// as the rest of the preflight, naming the offending section and the `--features …` to
/// rebuild with, so a misconfiguration is a boot error rather than a silent degradation.
/// A no-op on the full build and on a lite build whose config touches none of these
/// sections.
///
/// # Errors
///
/// Returns [`CoreError::InvalidConfig`] on the first section whose feature is
/// absent.
pub fn check_features(config: &ServiceConfig) -> CoreResult<()> {
    if config.has_s3_buckets() && !cfg!(feature = "s3") {
        return Err(CoreError::InvalidConfig {
            detail: "config has [[s3.buckets]] but this binary was built without S3 support; \
                     rebuild with --features s3 (or --features full)"
                .to_owned(),
        });
    }
    if config.has_vault() && !cfg!(feature = "vault") {
        return Err(CoreError::InvalidConfig {
            detail: "config has [vault] but this binary was built without Vault support; \
                     rebuild with --features vault (or --features full)"
                .to_owned(),
        });
    }
    if config.has_transit_key() && !cfg!(feature = "pme") {
        return Err(CoreError::InvalidConfig {
            detail: "config sets [vault].transit_key (at-rest PME) but this binary was built \
                     without PME support; rebuild with --features pme (or --features full)"
                .to_owned(),
        });
    }
    Ok(())
}

/// Reject a beacon mount prefix that collides with a path the public router already
/// serves at the origin root.
///
/// [`ServiceConfig::preflight`] validates a base path's shape (leading slash, no empty
/// segment, IRI-safe characters) but knows nothing about the router, so a value such as
/// `aggregated_base_path = "/fairdp"` clears it and would panic in `build_router` after both
/// listeners had bound. The router's reserved paths live in
/// `app::conflicting_reserved_path` (crate-private, so a code span rather than a link);
/// this is the boot-time consumer.
///
/// Both mounts are checked: on a split deployment either one can be the offender.
///
/// # Errors
///
/// Returns [`CoreError::InvalidConfig`] naming the offending key and the path it takes.
pub fn check_mount_prefixes(config: &ServiceConfig) -> CoreResult<()> {
    for (field, prefix) in [
        (
            "[beacon].aggregated_base_path",
            &config.beacon.aggregated_base_path,
        ),
        (
            "[beacon].sensitive_base_path",
            &config.beacon.sensitive_base_path,
        ),
    ] {
        if let Some(reserved) = crate::app::conflicting_reserved_path(prefix) {
            return Err(CoreError::InvalidConfig {
                detail: format!(
                    "{field} = {prefix:?} collides with `{reserved}`, which this node serves \
                     at the origin root; choose a mount that is not `{reserved}`, above it, \
                     or under it (e.g. /beacon/v2)"
                ),
            });
        }
    }
    Ok(())
}

/// Run the full service-side startup preflight: the feature-independent
/// [`ServiceConfig::preflight`], the build-feature cross-checks ([`check_features`]),
/// then the router-collision check ([`check_mount_prefixes`]).
///
/// Callers run this before binding the listener. `check-config` runs this same pass and
/// then exits, so it shares the live boot's code path.
///
/// # Errors
///
/// Returns the first [`CoreError`] from either pass.
pub fn run(config: &ServiceConfig) -> CoreResult<()> {
    run_with(config, true)
}

/// As [`run`], but `emit_advisories` gates the boot-time posture warnings (k-anon floor,
/// blocking-pool pressure). Pass `false` for a `SIGHUP` config reload: the advisories
/// describe restart-only settings, so re-firing them on a candidate config the reload will
/// not apply raises a false incident on a node whose floor never changed. Boot and
/// `check-config` pass `true`.
///
/// # Errors
///
/// Propagates any [`ServiceConfig::preflight`] or feature-availability error.
pub fn run_with(config: &ServiceConfig, emit_advisories: bool) -> CoreResult<()> {
    config.preflight()?;
    check_features(config)?;
    check_mount_prefixes(config)?;
    if emit_advisories {
        config.emit_startup_advisories();
    }
    Ok(())
}

/// Install `ring` as the process-wide rustls [`rustls::crypto::CryptoProvider`] default, once.
///
/// Compiled and called only when the internal `tls` feature is on (enabled by `s3` or
/// `vault`). rustls is built with `custom-provider`, which disables the implicit built-in
/// provider, so a provider has to be installed explicitly before any TLS handshake;
/// `object_store` installs none of its own and honours this default. PME needs `ring` but
/// not TLS, so this install is gated on `tls` rather than on `ring`.
///
/// Idempotent: [`rustls::crypto::CryptoProvider::install_default`] returns `Err` when a
/// provider is already set, which is not a failure here.
#[cfg(feature = "tls")]
pub fn install_crypto_provider() {
    // `install_default` returns `Err` when a provider is already installed, which is fine
    // for an idempotent startup, so the result is discarded.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal config that passes the feature-independent preflight, to layer
    /// feature-requiring sections onto.
    const BASE: &str = r#"
[service]
base_url = "https://gdi-ee.example.org"
data_dir = "/data"

[beacon]
id = "ee.ut.af-beacon.production"
name = "GDI Estonia Beacon"
"#;

    fn cfg(extra: &str) -> ServiceConfig {
        ServiceConfig::from_toml_str(&format!("{BASE}{extra}"))
            .expect("test TOML parses into ServiceConfig")
    }

    #[test]
    fn no_feature_sections_passes_on_any_profile() {
        // A lite-style config touches none of the gated sections, so the feature check is
        // a no-op whichever features are compiled.
        assert!(check_features(&cfg("")).is_ok());
        assert!(run(&cfg("")).is_ok());
    }

    /// Capture the JSON `tracing` output emitted on this thread while `f` runs.
    fn capture(f: impl FnOnce()) -> String {
        test_util::capture_json_logs(f).1
    }

    #[test]
    fn k_anon_disabled_advisory_fires_at_boot_but_not_on_reload() {
        // The k-anonymity warning is a boot posture advisory for a restart-only floor. On
        // a `SIGHUP` reload the preflight runs on the candidate config and then rejects any
        // floor change, so re-firing the alarm would be a false incident.
        // `min_allele_count` defaults to 0 here, so the advisory applies.
        let config = cfg("");

        // The boot and `check-config` path (`emit_advisories = true`) warns.
        let at_boot = capture(|| run_with(&config, true).expect("valid config"));
        assert!(
            at_boot.contains("k-anonymity suppression is disabled")
                || at_boot.contains("min_allele_count is 0"),
            "boot must surface the disabled-floor advisory: {at_boot}"
        );

        // The reload path (`emit_advisories = false`) validates without warning.
        let on_reload = capture(|| run_with(&config, false).expect("valid config"));
        assert!(
            !on_reload.contains("k-anonymity suppression is disabled")
                && !on_reload.contains("min_allele_count is 0"),
            "a SIGHUP reload must NOT re-raise the disabled-floor alarm: {on_reload}"
        );
    }

    #[test]
    fn s3_buckets_gated_on_s3_feature() {
        let config = cfg(r#"
[[s3.buckets]]
name = "ee-utartu"
endpoint = "https://s3.example.org"
bucket = "gdi-ee"
path_style = true
"#);
        assert!(config.has_s3_buckets());
        let result = check_features(&config);
        if cfg!(feature = "s3") {
            assert!(result.is_ok(), "s3 compiled in: must accept [[s3.buckets]]");
        } else {
            let err = result.expect_err("s3 absent: must reject [[s3.buckets]]");
            assert_eq!(
                err.class(),
                gdi_node_standalone_core::error::ErrorClass::InvalidConfig
            );
            let msg = err.to_string();
            assert!(msg.contains("s3.buckets"), "names the section: {msg}");
            assert!(
                msg.contains("--features s3"),
                "names the rebuild flag: {msg}"
            );
        }
    }

    #[test]
    fn vault_gated_on_vault_feature() {
        let config = cfg(r"
[vault]
");
        assert!(config.has_vault());
        let result = check_features(&config);
        if cfg!(feature = "vault") {
            assert!(result.is_ok(), "vault compiled in: must accept [vault]");
        } else {
            let err = result.expect_err("vault absent: must reject [vault]");
            let msg = err.to_string();
            assert!(msg.contains("[vault]"), "names the section: {msg}");
            assert!(
                msg.contains("--features vault"),
                "names the rebuild flag: {msg}"
            );
        }
    }

    #[test]
    fn transit_key_gated_on_pme_feature() {
        let config = cfg(r#"
[vault]
transit_key = "gdi-node-at-rest"
"#);
        assert!(config.has_transit_key());
        let result = check_features(&config);
        if cfg!(feature = "pme") {
            assert!(result.is_ok(), "pme compiled in: must accept transit_key");
        } else if cfg!(feature = "vault") {
            // vault present but pme absent: the transit_key check fires.
            let err = result.expect_err("pme absent: must reject transit_key");
            let msg = err.to_string();
            assert!(msg.contains("transit_key"), "names the key: {msg}");
            assert!(
                msg.contains("--features pme"),
                "names the rebuild flag: {msg}"
            );
        } else {
            // Neither vault nor pme: the [vault] check fires first.
            let err = result.expect_err("vault absent: must reject [vault]/transit_key");
            assert!(
                err.to_string().contains("--features"),
                "names a rebuild flag"
            );
        }
    }
}
