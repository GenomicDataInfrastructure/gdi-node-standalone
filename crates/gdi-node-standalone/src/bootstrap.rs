//! Startup secret/identity orchestration, split out of `main` to keep the
//! entrypoint focused on process lifecycle.
//!
//! Resolves the node's crypt4gh identities (Vault-backed when the `vault` feature and
//! `[vault]` are configured, else from `[keys]` files), the per-bucket S3 credential
//! overrides, the optional PME runtime, and the `/health/ready` facts, across every
//! combination of the `vault` and `pme` features.

use anyhow::{Context as _, Result};
use gdi_node_standalone::identities::NodeIdentities;
use gdi_node_standalone_core::config::ServiceConfig;

use crate::S3Overrides;

/// The optional PME runtime handle attached to `AppState`, present only under the `pme`
/// feature with a configured and reachable `[vault].transit_key`. A unit placeholder
/// otherwise, so the call site stays feature-agnostic.
#[cfg(feature = "pme")]
type PmeHandle = Option<std::sync::Arc<gdi_node_standalone::pme::PmeRuntime>>;
#[cfg(not(feature = "pme"))]
type PmeHandle = Option<()>;

/// What `load_identities` resolves: the crypt4gh identities, the per-bucket S3
/// credential overrides, the optional PME runtime, and the readiness facts (did the
/// configured key material load, did the Vault client connect) the `/health/ready`
/// probe needs.
pub(crate) struct LoadedSecrets {
    /// The node's crypt4gh identities (possibly empty/keyless).
    pub(crate) identities: NodeIdentities,
    /// The per-bucket Vault S3-credential overrides (empty on the no-Vault path).
    pub(crate) s3_overrides: S3Overrides,
    /// The connected Vault client, retained past boot so a later config reload can re-read
    /// `[vault].s3_path` for a bucket the boot config did not declare. `None` without the
    /// `vault` feature, without `[vault]`, or when the startup connection failed
    /// transiently. In that last case a reload falls back to the boot override map, which
    /// refuses the add rather than starting an uncredentialled channel. Cheap to clone,
    /// because the client is a handle rather than a connection.
    #[cfg(feature = "vault")]
    pub(crate) vault: Option<gdi_node_standalone::vault::VaultClient>,
    /// The optional PME runtime handle.
    pub(crate) pme: PmeHandle,
    /// Whether the configured key material loaded. `true` for a successful Vault or file
    /// load and for the valid keyless mode; `false` only when a configured Vault load
    /// failed transiently, so the node degraded to keyless rather than being configured
    /// that way. A `[keys]`-file load failure aborts startup instead. Drives
    /// `/health/ready`'s `key_material` subsystem.
    pub(crate) key_material_ok: bool,
    /// Whether the Vault client connected with a usable token; `false` when `[vault]` is
    /// unconfigured or unreachable at startup. Drives `/health/ready`'s `vault` subsystem,
    /// which is consulted only when `[vault]` is set.
    pub(crate) vault_ok: bool,
}

/// Load the node's crypt4gh identities and (under Vault) the per-bucket S3
/// credential overrides.
///
/// On the Vault path (`vault` feature with `[vault]` configured) Vault is the secret source
/// and takes precedence over the inline `[keys]` and `[[s3.buckets]]` values. A transient
/// Vault failure at startup, such as an unreachable server or a lapsed token, is logged and
/// the node starts keyless-degraded: encrypted-package ingest is skipped, `/health/ready`
/// stays `503`, and `gdi_keyless_degraded` latches to `1`. Identities are resolved once
/// here, so recovery is a restart once Vault returns, not an in-place retry. A permanent
/// Vault fault (a malformed or absent secret) fails startup. Without Vault, identities load
/// from `[keys]` files and the overrides map is empty.
///
/// # Errors
///
/// Returns an error only on a permanent fault: a `[keys]`-file load failure, or a
/// permanent Vault error (malformed / absent required secret).
#[cfg(feature = "vault")]
pub(crate) async fn load_identities(config: &ServiceConfig) -> Result<LoadedSecrets> {
    use gdi_node_standalone::secrets;
    use gdi_node_standalone::vault::VaultError;

    if config.has_vault() {
        match secrets::resolve(config).await {
            Ok(resolved) => {
                let pme = build_pme_runtime(config, resolved.vault.as_ref());
                Ok(LoadedSecrets {
                    identities: resolved.identities,
                    s3_overrides: resolved.s3_overrides,
                    vault: resolved.vault,
                    pme,
                    key_material_ok: true,
                    vault_ok: true,
                })
            }
            Err(VaultError::Transient(msg)) => {
                tracing::warn!(
                    error = %msg,
                    "Vault key material did not load at startup; the failure is transient, so \
                     the server was unreachable, the token lapsed or was denied, or the node's \
                     policy lacks read on the configured kv_path. See `error` for the status. \
                     The node started in degraded keyless mode: encrypted-package ingest is \
                     skipped and /health/ready stays 503. If [vault].transit_key is configured \
                     for at-rest encryption, plaintext staging-dir ingest is also parked while \
                     PME is inactive, so no dataset is written unencrypted at rest. This does \
                     not self-heal. Resolve the Vault condition, verifying that the AppRole or \
                     token policy grants read on [vault].kv_path if the server is reachable, \
                     then restart the node (gdi_keyless_degraded=1 while degraded)"
                );
                // The configured Vault key material did not load, so readiness reports
                // key_material and vault as unavailable. Identities are set once at
                // startup, so recovery is a restart rather than a retry.
                Ok(LoadedSecrets {
                    identities: NodeIdentities::empty(),
                    s3_overrides: S3Overrides::new(),
                    vault: None,
                    pme: None,
                    key_material_ok: false,
                    vault_ok: false,
                })
            }
            Err(VaultError::Permanent(msg)) => {
                Err(anyhow::anyhow!("Vault secret load failed: {msg}"))
            }
            // `VaultError` is `#[non_exhaustive]`, so treat an unknown variant as
            // transient rather than crashing at startup.
            Err(other) => {
                tracing::warn!(
                    alert = true,
                    event.action = "vault.secret.load",
                    event.outcome = "failure",
                    error = %other,
                    "Vault secret load failed and is treated as transient; the node started \
                     in degraded keyless mode, encrypted-package ingest is skipped, and \
                     recovery requires a restart once Vault is reachable \
                     (gdi_keyless_degraded=1)"
                );
                Ok(LoadedSecrets {
                    identities: NodeIdentities::empty(),
                    s3_overrides: S3Overrides::new(),
                    vault: None,
                    pme: None,
                    key_material_ok: false,
                    vault_ok: false,
                })
            }
        }
    } else {
        let identities = NodeIdentities::load(config)
            .context("loading crypt4gh identities ([keys].identities)")?;
        // No `[vault]`: file-loaded or keyless identities are ready, and Vault is not a
        // dependency.
        Ok(LoadedSecrets {
            identities,
            s3_overrides: S3Overrides::new(),
            #[cfg(feature = "vault")]
            vault: None,
            pme: None,
            key_material_ok: true,
            vault_ok: false,
        })
    }
}

/// Build the PME runtime (a Vault-minted DEK and the cached key retriever) when PME is
/// active: the `pme` feature is compiled, a `[vault].transit_key` is configured, and a Vault
/// client connected. Returns `None` otherwise, leaving at-rest protection volume-level only
/// and reads and writes in plaintext.
///
/// A `transit_key` set without a connected client yields `None`, and ingest then fails
/// closed for that window rather than degrading to plaintext:
/// `AppState::at_rest_encryption_required_but_inactive` is true, and
/// `IngestRuntime::scan_once` parks every plaintext staging dir in the inbox rather than
/// writing parquet unencrypted, which would be permanent, since datasets are immutable. The
/// node still boots and picks the work up once Vault returns.
#[cfg(all(feature = "vault", feature = "pme"))]
fn build_pme_runtime(
    config: &ServiceConfig,
    vault: Option<&gdi_node_standalone::vault::VaultClient>,
) -> Option<std::sync::Arc<gdi_node_standalone::pme::PmeRuntime>> {
    // No `[vault]` block or no `transit_key` means PME is not configured, and at-rest
    // protection stays volume-level. A silent "meant to enable PME but it is off" boot is
    // unreachable: `deny_unknown_fields` rejects a mistyped key name at load, and
    // `preflight_vault` rejects a present-but-empty `transit_key`.
    let vault_cfg = config.vault.as_ref()?;
    let transit_key = vault_cfg.transit_key.as_deref().filter(|k| !k.is_empty())?;
    // A `transit_key` is configured, so PME is intended. Warn when the Vault client is not
    // connected, so the plaintext-at-rest fallback does not pass unnoticed. Ingest still
    // degrades for this window and re-mints once Vault returns.
    let Some(client) = vault else {
        tracing::warn!(
            transit_key,
            "[vault].transit_key is set (PME intended) but the Vault client is unavailable, \
             so PME is inactive and ingest is parked: plaintext staging dirs are left in the \
             inbox rather than written unencrypted at rest, and are picked up once Vault is \
             reachable. No dataset is ingested in the meantime."
        );
        return None;
    };
    tracing::info!(
        transit_mount = %vault_cfg.transit_mount(),
        transit_key,
        "PME active: parquet payload encrypted at rest with a Vault-minted DEK"
    );
    Some(std::sync::Arc::new(
        gdi_node_standalone::pme::PmeRuntime::new(
            client.clone(),
            vault_cfg.transit_mount().to_owned(),
            transit_key.to_owned(),
        ),
    ))
}

/// No-op PME builder for a `vault`-without-`pme` build. There is no `PmeRuntime` type, so
/// this returns nothing and ingest and query stay plaintext.
#[cfg(all(feature = "vault", not(feature = "pme")))]
fn build_pme_runtime(
    _config: &ServiceConfig,
    _vault: Option<&gdi_node_standalone::vault::VaultClient>,
) -> Option<()> {
    None
}

/// Load the node's crypt4gh identities from `[keys]` files, on a build where the `vault`
/// feature is not compiled. The S3 overrides map is always empty here.
///
/// # Errors
///
/// Returns an error if a `[keys]` identity file cannot be read or parsed.
#[cfg(not(feature = "vault"))]
// `async` without an `.await` so this shares one call site with the `vault`-enabled
// variant, which does await.
pub(crate) async fn load_identities(config: &ServiceConfig) -> Result<LoadedSecrets> {
    let identities =
        NodeIdentities::load(config).context("loading crypt4gh identities ([keys].identities)")?;
    // No `vault` feature means no PME, since `pme` implies `vault`, so the PME handle is
    // always `None` and Vault is never a dependency. File-loaded or keyless identities are
    // ready key material.
    Ok(LoadedSecrets {
        identities,
        s3_overrides: S3Overrides::new(),
        pme: None,
        key_material_ok: true,
        vault_ok: false,
    })
}

// Asserts the Vault-branch readiness-fact mapping for `/health/ready`'s `key_material` and
// `vault` facts: healthy maps to ok, a transient fault to a keyless degrade rather than a
// crash, and a permanent fault to an abort. `load_identities` is binary-crate-private, so
// these live inline rather than in `tests/it/`, and they mock Vault with wiremock.
#[cfg(all(test, feature = "vault"))]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    // `allow-expect-in-tests` needs a literal `#[cfg(test)]`, and this module is gated on
    // `cfg(all(test, feature = "vault"))`, so the `clippy.toml` exemption does not reach it.
    #![expect(clippy::expect_used, reason = "expect is permitted in test code")]

    use gdi_node_standalone_core::config::ServiceConfig;
    use gdi_node_standalone_core::crypt4gh::{generate_keypair, serialize_secret_key};
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::{LoadedSecrets, load_identities};

    /// A fresh unencrypted crypt4gh secret-key PEM.
    fn fresh_identity_pem() -> String {
        let (sk, _pk) = generate_keypair();
        serialize_secret_key(&sk)
    }

    /// A `[vault]`-configured service config pointing at `address`. The static token means
    /// `connect` issues no HTTP, so the only request is the KV identity read.
    fn vault_config(address: &str) -> ServiceConfig {
        let toml = format!(
            r#"
[service]
base_url = "https://gdi-ee.example.org"
data_dir = "/tmp/gdi-bootstrap-readiness-test"

[beacon]
id = "ee.ut.af-beacon.production"
name = "GDI Estonia Beacon"

[vault]
address = "{address}"
token = "hvs.test"
kv_path = "gdi/c4gh"
"#
        );
        ServiceConfig::from_toml_str(&toml).expect("config parses")
    }

    /// Healthy Vault: the configured key material loads and the client connects,
    /// so both readiness facts are true.
    #[tokio::test]
    async fn healthy_vault_yields_ok_readiness_facts() {
        let server = MockServer::start().await;
        let vault_pem = fresh_identity_pem();
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/gdi/c4gh"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "data": { "c4gh-0000000000000001": vault_pem }, "metadata": { "version": 1 } }
            })))
            .mount(&server)
            .await;

        let config = vault_config(&server.uri());
        let LoadedSecrets {
            identities,
            key_material_ok,
            vault_ok,
            ..
        } = load_identities(&config).await.expect("healthy vault loads");

        assert!(key_material_ok, "configured key material loaded");
        assert!(vault_ok, "vault client connected");
        assert!(identities.is_enabled(), "the Vault identity is present");
    }

    /// A transient Vault fault (5xx) on the required secret degrades the node to keyless,
    /// with both facts false, and returns no error: a Vault blip must not take the node
    /// down.
    #[tokio::test]
    async fn vault_5xx_degrades_keyless_not_a_crash() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/gdi/c4gh"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let config = vault_config(&server.uri());
        let LoadedSecrets {
            identities,
            s3_overrides,
            key_material_ok,
            vault_ok,
            ..
        } = load_identities(&config)
            .await
            .expect("a transient Vault fault must degrade keyless, not error");

        assert!(!key_material_ok, "configured key material did not load");
        assert!(!vault_ok, "vault unavailable");
        assert!(!identities.is_enabled(), "node started keyless");
        assert!(s3_overrides.is_empty(), "no overrides on the keyless path");
    }

    /// Permanent Vault fault (404 on the required identity secret): startup aborts
    /// with an error rather than silently running without the configured keys.
    #[tokio::test]
    async fn vault_missing_required_secret_aborts_startup() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/gdi/c4gh"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({ "errors": [] })))
            .mount(&server)
            .await;

        let config = vault_config(&server.uri());
        // `LoadedSecrets` is not `Debug`, so bind the error directly instead of using
        // `expect_err`, which would require `Debug` on the `Ok` value.
        let Err(err) = load_identities(&config).await else {
            panic!("a permanent Vault fault must fail startup");
        };
        assert!(
            err.to_string().contains("Vault secret load failed"),
            "unexpected error: {err}"
        );
    }

    #[derive(Clone)]
    struct LogBuf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for LogBuf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A transient Vault fault degrades to keyless with a warning, and neither that warning
    /// nor the connect and resolve logs may carry the Vault token.
    #[tokio::test]
    async fn vault_transient_degrade_logs_no_token() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/gdi/c4gh"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let config = vault_config(&server.uri()); // token "hvs.test"

        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let subscriber = {
            use tracing_subscriber::layer::SubscriberExt as _;
            let w = LogBuf(std::sync::Arc::clone(&buf));
            tracing_subscriber::registry().with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_writer(move || w.clone()),
            )
        };
        // `set_default` keeps the subscriber installed across the `.await`, because the
        // current-thread test runtime keeps this task on one thread.
        let guard = tracing::subscriber::set_default(subscriber);
        let loaded = load_identities(&config).await;
        drop(guard);

        assert!(
            loaded.is_ok(),
            "a transient Vault fault must degrade keyless"
        );
        let logs = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(
            !logs.contains("hvs.test"),
            "the Vault token must not be logged: {logs}"
        );
    }
}
