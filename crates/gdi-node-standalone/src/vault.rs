//! Hand-rolled Vault KV v2 + Transit client (compiled only under the `vault` feature).
//!
//! A small async client over the workspace's `reqwest`/rustls stack, using the same `ring`
//! provider the S3 `object_store` connector installs as the process default (see
//! [`crate::preflight::install_crypto_provider`]). It pulls in no external Vault crate.
//! HashiCorp Vault and OpenBao speak the same KV v2 + Transit HTTP API, so one code path
//! serves either server, chosen by config alone.
//!
//! The surface is what the node needs:
//!
//! * Auth and token lifecycle: a static token (`[vault].token` / `VAULT_TOKEN`) used as-is;
//!   `AppRole` (`role_id` + `secret_id`) exchanged for a token at startup; or
//!   `[vault].token_file`, a token an external agent writes and keeps refreshed. An AppRole
//!   token is renewed before its lease expires, and the client re-authenticates if renewal
//!   fails. A static or file-sourced token is non-renewable here, and a `token_file` is
//!   re-read when its mtime changes. A fetch that fails because the token lapsed is
//!   transient ([`VaultError::Transient`]): the caller retries and readiness reports Vault
//!   as `unavailable`, never a permanent dataset `error`.
//! * KV v2 read ([`VaultClient::kv_get`]): the crypt4gh identity (`[vault].kv_path`) and the
//!   per-bucket S3 credentials (`[vault].s3_path`).
//! * Transit `datakey` and `decrypt` ([`VaultClient::transit_datakey`],
//!   [`VaultClient::transit_decrypt`]): `datakey/plaintext` mints and wraps each file's DEK,
//!   and `decrypt` unwraps it.
//!
//! The long-lived secret holders (the token, the AppRole secret-id, minted DEKs) are
//! `zeroize`-backed ([`zeroize::Zeroizing`]) and never `Debug`-formatted. Transient
//! serialization intermediates, such as a KV-write body carrying a secret, are not wiped.
//!
//! Least-privilege capabilities: a serving node only reads KV and POSTs to Transit, so it
//! needs `read` on `[vault].kv_path` and `[vault].s3_path` plus `update` on
//! `transit/datakey/*` and `transit/decrypt/*`, and no KV write. The operator-run
//! provisioning commands [`crate::init_identity`] and [`crate::rotate_identity`] are the
//! exceptions; they write the identity path with a separate write-capable credential,
//! `create` for the create-only bootstrap plus `update` for rotation's check-and-set.
//! Neither deletes or overwrites a key, so give the running service the read-only credential
//! and run provisioning from a distinct one. To hold no static credential at all, use
//! `[vault].token_file` with an agent sidecar: the agent authenticates by whatever method
//! the server supports, and this client only reads the token it writes.
#![expect(
    clippy::doc_markdown,
    reason = "docs use proper nouns (Vault, OpenBao, HashiCorp, AppRole, KMS) as prose, not code"
)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use gdi_node_standalone_core::config::VaultConfig;

use crate::metrics;

/// Whether the Vault client feature is compiled into this binary. Always `true` here, since
/// this module exists only under `#[cfg(feature = "vault")]`. Used by the startup feature
/// preflight log line.
#[must_use]
pub const fn compiled() -> bool {
    true
}

/// Renew a renewable token once it is within this fraction of its lease elapsed
/// (i.e. renew at ~2/3 of the lease, leaving headroom before expiry).
const RENEW_AT_FRACTION: f64 = 2.0 / 3.0;

/// Floor for a renewable lease's renew threshold so a very short lease still
/// triggers a renew with a little headroom.
const MIN_RENEW_HEADROOM: Duration = Duration::from_secs(10);

/// Maximum Vault/OpenBao response body. KV and Transit responses are a few KiB at most, so
/// 1 MiB is far above any real value and bounds an endpoint that streams an unbounded body
/// into the node; reqwest imposes no default limit. Mirrors the tool's `MAX_FDP_BODY_BYTES`.
const MAX_VAULT_BODY_BYTES: u64 = 1024 * 1024;

/// A KV identity map whose secret-key PEMs are wiped on drop.
///
/// The return type of [`VaultClient::kv_get`] / [`VaultClient::kv_get_versioned`], so the
/// client cannot hand out an unwiped map of the node's irreplaceable secret PEMs and no
/// caller has to remember to wipe one.
///
/// `Drop` closes it on every exit, including an early `?`, a `bail!` or a panic, which an
/// end-of-function `zeroize()` would miss. Field names such as `c4gh-<millis>` are not
/// secret. This is defence in depth against freed heap; there is no live, disk or log
/// exposure.
#[derive(Default)]
pub struct ZeroizingIdentityMap(pub(crate) std::collections::BTreeMap<String, String>);

impl Drop for ZeroizingIdentityMap {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        for pem in self.0.values_mut() {
            pem.zeroize();
        }
    }
}

impl std::ops::Deref for ZeroizingIdentityMap {
    type Target = std::collections::BTreeMap<String, String>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// `rotate` edits the fetched map before writing it back; mutating through the wrapper keeps
/// the wipe-on-drop guarantee a plain `BTreeMap` would lose.
impl std::ops::DerefMut for ZeroizingIdentityMap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// A Vault client error, classified transient or permanent so the ingest pipeline can treat
/// a lapsed token or unreachable server as a retryable backend condition rather than a
/// sticky dataset `error`, and a malformed request or missing secret as a permanent fault.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VaultError {
    /// A retryable backend condition: the server is unreachable, the token has lapsed or
    /// been denied (`401`/`403`), or the server returned a `5xx`. The caller retries and
    /// surfaces Vault as `unavailable` on readiness.
    #[error("vault transient error: {0}")]
    Transient(String),
    /// A permanent fault that retrying cannot fix: a malformed request, an absent secret or
    /// key path (`404`), a bad payload, or an unparseable response.
    #[error("vault permanent error: {0}")]
    Permanent(String),
}

/// Result alias for the Vault client.
pub type VaultResult<T> = Result<T, VaultError>;

/// The configured authentication method.
#[derive(Clone)]
enum Auth {
    /// A static token used as-is (may be non-renewable).
    Token(Zeroizing<String>),
    /// `AppRole`: `role_id` + `secret_id`, exchanged for a token at login and
    /// re-exchanged when a renewal fails.
    AppRole {
        /// The `AppRole` role id.
        role_id: String,
        /// The `AppRole` secret id (the out-of-band bootstrap credential).
        secret_id: Zeroizing<String>,
    },
    /// A token supplied by an external agent through a file, re-read when the file's mtime
    /// changes.
    ///
    /// The agent, a Vault Agent or Secrets Operator sidecar, owns authentication and
    /// renewal, so this token is treated as non-renewable here and the node never calls
    /// `renew-self` for it.
    TokenFile {
        /// The file holding the current token. The path is not secret; the contents are.
        path: std::path::PathBuf,
    },
}

/// Read a Vault token from `path`, trimming surrounding whitespace.
///
/// Agents commonly write a trailing newline, and a token carrying a stray `\n` fails
/// authentication in a way that reads like a permissions problem, so the trim is required.
///
/// # Errors
///
/// [`VaultError::Permanent`] when the file cannot be read or is empty. Both are deployment
/// faults that retrying cannot fix. The error names the path, never the contents.
fn read_token_file(path: &std::path::Path) -> VaultResult<Zeroizing<String>> {
    let raw = Zeroizing::new(std::fs::read_to_string(path).map_err(|e| {
        metrics::vault_token_file_read_error();
        VaultError::Permanent(format!("reading vault.token_file {}: {e}", path.display()))
    })?);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Ok(meta) = std::fs::metadata(path)
            && meta.permissions().mode() & 0o077 != 0
        {
            // Warn rather than reject, unlike `[service].strict_key_perms`, which refuses
            // to start on a group- or other-readable crypt4gh identity. An agent sink
            // commonly writes 0640, so failing closed here would break the credential-free
            // deployment shape `token_file` exists to enable, and this token is short-lived
            // and re-mintable while the crypt4gh identity is irreplaceable.
            warn!(
                path = %path.display(),
                "vault.token_file is group/other-readable; recommend chmod 0400/0600"
            );
        }
    }
    let token = Zeroizing::new(raw.trim().to_owned());
    if token.is_empty() {
        metrics::vault_token_file_read_error();
        return Err(VaultError::Permanent(format!(
            "vault.token_file {} is empty",
            path.display()
        )));
    }
    Ok(token)
}

/// The token file's mtime, or `None` when it cannot be read.
///
/// `None` is treated as "unchanged" by the freshness check so a transient `stat`
/// failure cannot cause a re-read storm on every request.
fn token_file_mtime(path: &std::path::Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// The current token and its renewal bookkeeping, held behind an async lock.
///
/// The token string lives in a [`Zeroizing`] buffer so it is wiped on
/// replacement / drop, and the holder never derives `Debug`.
struct TokenState {
    /// The active client token (zeroized on replace/drop).
    token: Zeroizing<String>,
    /// When the lease was obtained; `None` for a static, non-lease token.
    obtained_at: Option<Instant>,
    /// The lease duration; `None`/zero for a static, non-renewable token.
    lease: Option<Duration>,
    /// Whether the current token is renewable (server-reported on login).
    renewable: bool,
    /// Last observed mtime of `Auth::TokenFile`'s file, used to detect an agent rotation.
    /// `None` until the first read, and for every other auth method.
    ///
    /// Held beside the token it describes rather than in its own lock: the two are one fact.
    /// Published separately, two concurrent `ensure_token` callers could commit one caller's
    /// token with the other's mtime, after which the mtime comparison, the only refresh
    /// trigger for a file token, reports "unchanged" forever against a superseded token.
    seen_token_file_mtime: Option<std::time::SystemTime>,
}

impl TokenState {
    /// Whether the token is due for renewal (renewable and past the renew
    /// threshold of its lease). A static / non-renewable token never renews.
    fn needs_renew(&self) -> bool {
        if !self.renewable {
            return false;
        }
        let (Some(obtained), Some(lease)) = (self.obtained_at, self.lease) else {
            return false;
        };
        if lease.is_zero() {
            return false;
        }
        let threshold = renew_threshold(lease);
        obtained.elapsed() >= threshold
    }
}

/// The renew threshold for a lease: the elapsed time at which a renewable token is
/// renewed.
///
/// A lease at or below [`MIN_RENEW_HEADROOM`] is renewed eagerly, at threshold `0`, because
/// there is no useful window to wait out. A longer lease renews at [`RENEW_AT_FRACTION`] of
/// it, leaving headroom before expiry.
fn renew_threshold(lease: Duration) -> Duration {
    if lease <= MIN_RENEW_HEADROOM {
        return Duration::ZERO;
    }
    lease.mul_f64(RENEW_AT_FRACTION).min(lease)
}

/// A small async Vault / OpenBao client over the shared `reqwest`/rustls stack.
///
/// Cheaply cloneable (the HTTP client and token holder are `Arc`-backed), so it
/// can be shared by the identity/S3-cred loaders and (under PME) the parquet key
/// retriever.
#[derive(Clone)]
pub struct VaultClient {
    http: Client,
    /// Base URL with no trailing slash (e.g. `https://vault.example.org`).
    address: String,
    /// Optional `X-Vault-Namespace` header (HCP / Enterprise).
    namespace: Option<String>,
    /// KV v2 mount (default `secret`).
    kv_mount: String,
    /// Transit mount (default `transit`).
    transit_mount: String,
    auth: Auth,
    token: Arc<RwLock<TokenState>>,
    /// Serialises the reactive re-authentication in [`VaultClient::send_authed`], so a burst
    /// of concurrent requests meeting the same revoked token performs one login rather than
    /// a thundering herd against `auth/approle/login`.
    reauth_lock: Arc<tokio::sync::Mutex<()>>,
}

/// The KV v2 read response envelope: `{ "data": { "data": { ... } } }`.
///
/// Not `Debug`, and nor is [`KvReadInner`]: `.data` carries the secret map of crypt4gh
/// private-key PEMs and S3 access keys, so these envelopes must never be formattable.
#[derive(Deserialize)]
struct KvReadResponse {
    data: KvReadInner,
}

/// The inner `data` object of a KV v2 read: the secret map under `.data`, plus `.metadata`,
/// of which only `version` is consumed, for the rotation cas write.
#[derive(Deserialize)]
struct KvReadInner {
    data: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    metadata: KvMetadata,
}

/// The KV v2 read `metadata` sub-object; only `version` is read, for the
/// check-and-set on an additive rotation write ([`VaultClient::kv_put_cas`]).
#[derive(Debug, Default, Deserialize)]
struct KvMetadata {
    #[serde(default)]
    version: u64,
}

/// The AppRole / token-renew auth response: `{ "auth": { "client_token", ... } }`.
///
/// Not `Debug`, and nor is [`AuthInner`]: `client_token` is the live Vault token, a
/// credential that must never reach a log line through a stray `debug!(?resp)`.
#[derive(Deserialize)]
struct AuthResponse {
    auth: AuthInner,
}

/// The inner `auth` object: the client token + its lease metadata.
#[derive(Deserialize)]
struct AuthInner {
    client_token: String,
    #[serde(default)]
    lease_duration: u64,
    #[serde(default)]
    renewable: bool,
}

/// The Transit `datakey/plaintext` response: `{ "data": { "plaintext", "ciphertext" } }`.
///
/// Not `Debug`, and nor is [`DatakeyInner`]: `plaintext` is the unwrapped base64 DEK, the
/// same class of secret as the crypt4gh keys, so it must never be formattable.
#[derive(Deserialize)]
struct DatakeyResponse {
    data: DatakeyInner,
}

/// The inner Transit `datakey` data: base64 plaintext DEK + its wrapped form.
#[derive(Deserialize)]
struct DatakeyInner {
    plaintext: String,
    ciphertext: String,
}

/// The Transit `decrypt` response: `{ "data": { "plaintext" } }` (base64).
///
/// Not `Debug`, and nor is [`DecryptInner`]: `plaintext` is the unwrapped DEK, so these
/// envelopes must never be formattable.
#[derive(Deserialize)]
struct DecryptResponse {
    data: DecryptInner,
}

/// The inner Transit `decrypt` data: the unwrapped base64 plaintext.
#[derive(Deserialize)]
struct DecryptInner {
    plaintext: String,
}

impl VaultClient {
    /// Build a client from `[vault]` config and log in (resolving an `AppRole`
    /// exchange or adopting the static token).
    ///
    /// `token` / `secret_id` are taken from the config, into which figment has already
    /// overlaid `VAULT_TOKEN` / `GDI_NODE__VAULT__SECRET_ID`. The bare `VAULT_TOKEN` env var
    /// is also honoured when neither is set in config.
    ///
    /// # Errors
    ///
    /// [`VaultError::Permanent`] when the config declares no auth method, or a
    /// [`VaultError`] from the initial [`VaultClient::login`], which is transient when the
    /// server is unreachable.
    pub async fn connect(config: &VaultConfig) -> VaultResult<Self> {
        let address = config.address.trim_end_matches('/').to_owned();
        // A non-https Vault address sends the client token, the AppRole secret_id and the
        // Transit DEKs over an unencrypted channel, which hands the node identity and the
        // at-rest keys to a network MITM. Warn rather than reject: an in-cluster or
        // loopback dev backend is a legitimate http use. Production needs https.
        if !address.starts_with("https://") {
            warn!(
                event.action = "config.posture",
                address = %address,
                "vault: address is not https, so the client token, AppRole secret_id and \
                 Transit DEKs travel in cleartext; use https in production, and http only \
                 for an in-cluster or loopback dev backend"
            );
        }
        let auth = resolve_auth(config)?;

        // Bound connect and total request time so a dead or wedged Vault endpoint fails as
        // a transient error in seconds rather than waiting out the OS default while pinning
        // a blocking-pool thread. `0` on either knob disables the bound.
        //
        // Never follow redirects: the KV and Transit APIs never legitimately 3xx, and
        // reqwest strips only the four well-known auth headers on a cross-host redirect, so
        // following one would re-send `X-Vault-Token` and the AppRole `secret_id` body to
        // another host. Any redirect surfaces as an error.
        let mut builder = gdi_node_standalone_core::tls::https_client_builder()
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("gdi-node-standalone/", env!("CARGO_PKG_VERSION")));
        if config.connect_timeout_seconds > 0 {
            builder = builder.connect_timeout(std::time::Duration::from_secs(
                config.connect_timeout_seconds,
            ));
        }
        if config.request_timeout_seconds > 0 {
            builder = builder.timeout(std::time::Duration::from_secs(
                config.request_timeout_seconds,
            ));
        }
        let http = builder
            .build()
            .map_err(|e| VaultError::Permanent(format!("building HTTP client: {e}")))?;

        let client = Self {
            http,
            address,
            namespace: config.namespace.clone().filter(|n| !n.is_empty()),
            kv_mount: config.kv_mount().to_owned(),
            transit_mount: config.transit_mount().to_owned(),
            auth,
            reauth_lock: Arc::new(tokio::sync::Mutex::new(())),
            token: Arc::new(RwLock::new(TokenState {
                token: Zeroizing::new(String::new()),
                obtained_at: None,
                lease: None,
                renewable: false,
                seen_token_file_mtime: None,
            })),
        };
        client.login().await?;
        Ok(client)
    }

    /// Authenticate: adopt the static token, or exchange the `AppRole` `role_id`/`secret_id`
    /// for a fresh client token. Stores the token and its lease.
    ///
    /// # Errors
    ///
    /// [`VaultError::Transient`] when the server is unreachable or returns `401`/`403`/`5xx`;
    /// [`VaultError::Permanent`] on a `4xx` other than auth, such as a malformed `AppRole`
    /// request, or an unparseable response.
    pub async fn login(&self) -> VaultResult<()> {
        match &self.auth {
            Auth::Token(tok) => {
                // A static token is used as-is and treated as non-renewable: there is no
                // background renewal for it, so it lapses at its own TTL. Supply a token
                // whose TTL outlives the process, or use AppRole for auto-renewal; a
                // shorter-lived static token expires silently.
                let mut state = self.token.write().await;
                state.token.clone_from(tok);
                state.obtained_at = None;
                state.lease = None;
                state.renewable = false;
                // A static token has no lease to report: TTL gauge stays 0.
                metrics::vault_token_ttl(0.0);
                debug!("vault: using static token");
                Ok(())
            }
            Auth::TokenFile { path } => {
                // The agent owns authentication and renewal; the node only reads what it
                // wrote. Same posture as a static token, non-renewable and leaseless, so
                // `needs_renew` never fires and an mtime change is the only thing that
                // refreshes this token.
                //
                // Stat before read, and publish both together. Reading first pairs an old
                // token with a new mtime whenever the agent rewrites the file in between,
                // leaving the node on the superseded token until a third distinct mtime
                // appears. Stat'ing first inverts that into a new token with an older
                // mtime, which self-heals on the next `ensure_token` for one redundant
                // re-read.
                let mtime = token_file_mtime(path);
                let tok = read_token_file(path)?;
                {
                    let mut state = self.token.write().await;
                    state.token = tok;
                    state.obtained_at = None;
                    state.lease = None;
                    state.renewable = false;
                    state.seen_token_file_mtime = mtime;
                }
                // No lease to report: the TTL gauge stays 0, so `VaultTokenLeaseTooShort`
                // is inert for this mode as it is for a static token. Freshness is watched
                // via `gdi_vault_token_file_age_seconds` instead.
                metrics::vault_token_ttl(0.0);
                metrics::vault_token_file_reload();
                info!(path = %path.display(), "vault: loaded token from file");
                Ok(())
            }
            Auth::AppRole { role_id, secret_id } => {
                let url = format!("{}/v1/auth/approle/login", self.address);
                let body = json!({ "role_id": role_id, "secret_id": &**secret_id });
                let resp = self.send_unauthed(&url, &body).await?;
                let auth: AuthResponse = parse_json(resp).await?;
                let renewable = auth.auth.renewable;
                self.apply_token(auth.auth).await;
                info!(renewable, "vault: AppRole login succeeded");
                Ok(())
            }
        }
    }

    /// Apply a freshly-obtained auth result to the token holder (zeroizing the old
    /// token on replace).
    async fn apply_token(&self, auth: AuthInner) {
        let mut state = self.token.write().await;
        state.token = Zeroizing::new(auth.client_token);
        state.lease = (auth.lease_duration > 0).then(|| Duration::from_secs(auth.lease_duration));
        state.obtained_at = state.lease.map(|_| Instant::now());
        state.renewable = auth.renewable;
        // Publish the token TTL as of this login or renew: the lease, or 0 for a token with
        // none. It is a step value that resets to the full lease on every renew, not a live
        // countdown, so `gdi_vault_token_ttl_seconds` is not "seconds until expiry"; pair it
        // with the renewal and error counters. Content-free.
        metrics::vault_token_ttl(state.lease.map_or(0.0, |l| l.as_secs_f64()));
    }

    /// Ensure the token is fresh before a request: if it is renewable and past its
    /// renew threshold, renew via `auth/token/renew-self`; if that fails, re-login.
    /// A static (non-renewable) token is left as-is.
    ///
    /// # Errors
    ///
    /// [`VaultError`] if a required re-login fails (transient when the server is
    /// unreachable).
    async fn ensure_token(&self) -> VaultResult<()> {
        // A file-sourced token is refreshed by an external agent. Detect a rotation by
        // mtime and re-read.
        //
        // This runs before the renew check and cannot live inside it: `needs_renew`
        // short-circuits on `!renewable` and a file token is never renewable. Without this
        // branch a rotated file would never be re-read and the node would present a stale
        // token until restart. A local `stat` is negligible against the network round-trip
        // that follows.
        if let Auth::TokenFile { path } = &self.auth {
            let current = token_file_mtime(path);
            if let Some(mtime) = current
                && let Ok(age) = mtime.elapsed()
            {
                metrics::vault_token_file_age(age.as_secs_f64());
            }
            // `None` (stat failed) compares equal to a previous `None` and counts as
            // unchanged, so a transient stat failure cannot trigger a re-read per request.
            let changed = { self.token.read().await.seen_token_file_mtime != current };
            if changed {
                debug!("vault: token file changed on disk; re-reading");
                return self.login().await;
            }
            return Ok(());
        }
        let needs = { self.token.read().await.needs_renew() };
        if !needs {
            return Ok(());
        }
        match self.renew_self().await {
            Ok(()) => {
                debug!("vault: token renewed");
                Ok(())
            }
            Err(e) => {
                // Count the renewal failure before falling back to a re-login, so an
                // operator sees renewals failing even when re-auth masks the symptom.
                // Content-free counter.
                metrics::vault_renewal_failure();
                // No `alert = true`: a renewal failure on its own is expected. A renewable
                // token cannot be renewed past `token_max_ttl`, so reaching that ceiling
                // always fails one renewal and then re-logs in successfully, and alerting
                // would route a ticket once per max-TTL on a healthy node. The structured
                // fields stay, so the event is still searchable.
                warn!(
                    event.action = "vault.token.renew",
                    event.outcome = "failure",
                    error = %e,
                    "vault: token renewal failed; re-authenticating"
                );
                // The fallback's outcome is the signal that matters.
                let relogin = self.login().await;
                match &relogin {
                    Ok(()) => {
                        debug!("vault: re-authenticated after a failed renewal");
                        metrics::vault_reauth("recovered");
                    }
                    Err(e) => {
                        // The alarm: the renewal failed and the re-login could not recover
                        // it, so the credential is unusable and the node runs on borrowed
                        // time until its current token lapses.
                        warn!(
                            alert = true,
                            event.action = "vault.token.reauth",
                            event.outcome = "failure",
                            error = %e,
                            "vault: re-authentication after a failed renewal also failed; the credential is not usable"
                        );
                        metrics::vault_reauth("failed");
                    }
                }
                relogin
            }
        }
    }

    /// Renew the current token via `POST /v1/auth/token/renew-self`.
    ///
    /// # Errors
    ///
    /// [`VaultError`] when the renew request fails or the response is unparseable. A `403`,
    /// meaning the token already lapsed, is transient and the caller falls back to
    /// [`VaultClient::login`].
    async fn renew_self(&self) -> VaultResult<()> {
        let url = format!("{}/v1/auth/token/renew-self", self.address);
        let token = { self.token.read().await.token.clone() };
        let resp = self
            .http
            .post(&url)
            .header("X-Vault-Token", &*token)
            .headers(self.extra_headers())
            .json(&json!({}))
            .send()
            .await
            .map_err(|e| transient_send(&e))?;
        let resp = check_status(resp)?;
        let auth: AuthResponse = parse_json(resp).await?;
        self.apply_token(auth.auth).await;
        Ok(())
    }

    /// KV v2 read: `GET /v1/{kv_mount}/data/{path}` → the secret map under
    /// `.data.data`.
    ///
    /// # Errors
    ///
    /// [`VaultError::Transient`] on an unreachable server, a lapsed token (`403`) or a
    /// `5xx`; [`VaultError::Permanent`] when the path is absent (`404`) or the response is
    /// malformed.
    pub async fn kv_get(&self, path: &str) -> VaultResult<ZeroizingIdentityMap> {
        Ok(self.kv_get_versioned(path).await?.0)
    }

    /// Like [`VaultClient::kv_get`] but also returns the KV v2 secret version, so a caller
    /// can add a field with a check-and-set that will not clobber a concurrent writer (see
    /// [`VaultClient::kv_put_cas`], used by `identity rotate`).
    ///
    /// # Errors
    ///
    /// As [`VaultClient::kv_get`].
    pub async fn kv_get_versioned(&self, path: &str) -> VaultResult<(ZeroizingIdentityMap, u64)> {
        timed_call("kv_read", async {
            self.ensure_token().await?;
            let url = format!(
                "{}/v1/{}/data/{}",
                self.address,
                self.kv_mount,
                path.trim_start_matches('/')
            );
            let resp = self.authed_get(&url).await?;
            let parsed: KvReadResponse = parse_json(resp).await?;
            Ok((
                ZeroizingIdentityMap(parsed.data.data),
                parsed.data.metadata.version,
            ))
        })
        .await
    }

    /// KV v2 create-only write: `POST /v1/{kv_mount}/data/{path}` with `options.cas = 0`.
    ///
    /// The server honours `cas = 0` as "write only if this secret has never been written",
    /// so a pre-existing secret is rejected with HTTP `400` rather than overwritten. This is
    /// the atomic guard `identity init` relies on to mint the node identity exactly once;
    /// overwriting an identity orphans existing crypt4gh and PME data.
    ///
    /// # Errors
    ///
    /// [`VaultError::Transient`] on an unreachable server, a lapsed token (`403`) or a
    /// `5xx`; [`VaultError::Permanent`] when the secret already exists, since the `cas`
    /// mismatch is a `400`, or the request is otherwise rejected.
    pub async fn kv_put_create(
        &self,
        path: &str,
        data: &std::collections::BTreeMap<String, String>,
    ) -> VaultResult<()> {
        self.kv_put_cas(path, data, 0).await
    }

    /// KV v2 check-and-set write: `POST …/data/{path}` with `options.cas = <cas>`. The
    /// server writes only if the secret's current version equals `cas`.
    ///
    /// This is the optimistic-concurrency primitive for an additive update: read the current
    /// map and version ([`VaultClient::kv_get_versioned`]), add a field, then write the
    /// merged map back at that version, so a racing writer cannot be silently clobbered.
    /// `cas = 0` is the "create only if never written" case [`VaultClient::kv_put_create`]
    /// uses.
    ///
    /// # Errors
    ///
    /// [`VaultError::Transient`] on an unreachable server, a lapsed token (`403`) or a
    /// `5xx`; [`VaultError::Permanent`] on a `cas` mismatch (`400`) or another rejection.
    pub async fn kv_put_cas(
        &self,
        path: &str,
        data: &std::collections::BTreeMap<String, String>,
        cas: u64,
    ) -> VaultResult<()> {
        timed_call("kv_write", async {
            self.ensure_token().await?;
            let url = format!(
                "{}/v1/{}/data/{}",
                self.address,
                self.kv_mount,
                path.trim_start_matches('/')
            );
            let body = json!({ "data": data, "options": { "cas": cas } });
            self.authed_post(&url, &body).await?;
            Ok(())
        })
        .await
    }

    /// Transit `datakey/plaintext`: `POST /v1/{transit_mount}/datakey/plaintext/{key}`
    /// `{bits:256}` → `(plaintext_b64, ciphertext)`.
    ///
    /// `plaintext` is the base64-encoded fresh 256-bit DEK and `ciphertext` is its
    /// Vault-wrapped form (`vault:vN:…`). The master key never leaves Vault. The caller
    /// decodes the base64 and holds it in a zeroize-backed buffer.
    ///
    /// # Errors
    ///
    /// [`VaultError::Transient`] on an unreachable server, a lapsed token or a `5xx`;
    /// [`VaultError::Permanent`] when the key is absent or of the wrong type, since a
    /// signing key fails `datakey`.
    pub async fn transit_datakey(&self, key: &str) -> VaultResult<(Zeroizing<String>, String)> {
        timed_call("transit_datakey", async {
            self.ensure_token().await?;
            let url = format!(
                "{}/v1/{}/datakey/plaintext/{}",
                self.address, self.transit_mount, key
            );
            let resp = self.authed_post(&url, &json!({ "bits": 256 })).await?;
            let parsed: DatakeyResponse = parse_json(resp).await?;
            // The base64 plaintext reconstructs the full DEK just as the decoded bytes do,
            // so it is held in a zeroize-on-drop buffer too. The ciphertext is the wrapped
            // form and safe to return bare.
            Ok((
                Zeroizing::new(parsed.data.plaintext),
                parsed.data.ciphertext,
            ))
        })
        .await
    }

    /// Transit `decrypt`: `POST /v1/{transit_mount}/decrypt/{key}` `{ciphertext}` →
    /// the unwrapped base64 plaintext (`.data.plaintext`).
    ///
    /// # Errors
    ///
    /// [`VaultError::Transient`] on an unreachable server, a lapsed token or a `5xx`;
    /// [`VaultError::Permanent`] when the ciphertext is malformed or the key is absent.
    pub async fn transit_decrypt(
        &self,
        key: &str,
        ciphertext: &str,
    ) -> VaultResult<Zeroizing<String>> {
        timed_call("transit_decrypt", async {
            self.ensure_token().await?;
            let url = format!("{}/v1/{}/decrypt/{}", self.address, self.transit_mount, key);
            let resp = self
                .authed_post(&url, &json!({ "ciphertext": ciphertext }))
                .await?;
            let parsed: DecryptResponse = parse_json(resp).await?;
            // Zeroize-on-drop: the base64 plaintext reconstructs the unwrapped DEK.
            Ok(Zeroizing::new(parsed.data.plaintext))
        })
        .await
    }

    /// Decode a base64 Transit plaintext (a DEK or decrypted payload) into a
    /// zeroize-backed buffer.
    ///
    /// # Errors
    ///
    /// [`VaultError::Permanent`] when the value is not valid base64.
    pub fn decode_b64(value: &str) -> VaultResult<Zeroizing<Vec<u8>>> {
        BASE64
            .decode(value)
            .map(Zeroizing::new)
            .map_err(|e| VaultError::Permanent(format!("decoding base64 secret: {e}")))
    }

    // ---- HTTP helpers ----

    /// The extra per-request headers (currently the optional namespace).
    fn extra_headers(&self) -> reqwest::header::HeaderMap {
        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(ns) = &self.namespace
            && let Ok(v) = reqwest::header::HeaderValue::from_str(ns)
        {
            headers.insert("X-Vault-Namespace", v);
        }
        headers
    }

    /// POST an unauthenticated body (the AppRole login) and check status.
    async fn send_unauthed(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> VaultResult<reqwest::Response> {
        let resp = self
            .http
            .post(url)
            .headers(self.extra_headers())
            .json(body)
            .send()
            .await
            .map_err(|e| transient_send(&e))?;
        check_status(resp)
    }

    /// GET an authenticated endpoint (KV read) and check status.
    async fn authed_get(&self, url: &str) -> VaultResult<reqwest::Response> {
        self.send_authed(|token| {
            self.http
                .get(url)
                .header("X-Vault-Token", token)
                .headers(self.extra_headers())
        })
        .await
    }

    /// Whether this auth method can mint a fresh credential unattended.
    ///
    /// `AppRole` re-exchanges its `role_id`/`secret_id`, and a token file is re-read from
    /// disk because an external agent owns the rotation. A static token has nothing to
    /// re-mint, since re-presenting the same string would meet the same rejection, so
    /// re-auth is not attempted and the `403` surfaces unchanged.
    fn can_reauthenticate(&self) -> bool {
        matches!(self.auth, Auth::AppRole { .. } | Auth::TokenFile { .. })
    }

    /// Send an authenticated request, re-authenticating once on an auth rejection.
    ///
    /// Vault answers a revoked or expired token with `401`/`403`. Without this path the only
    /// post-boot route to [`Self::login`] for `AppRole` is `needs_renew()`, which requires a
    /// renewable token past ~2/3 of its lease, so a role issuing batch or non-renewable
    /// tokens would have no recovery short of a process restart.
    ///
    /// Retried at most once. A permissions failure, as opposed to a revocation, answers the
    /// re-authenticated request with the same `403`, and retrying further would hot-loop
    /// against a Vault that is already refusing. The second rejection is returned as-is and
    /// stays [`VaultError::Transient`].
    ///
    /// The re-login is single-flighted behind [`Self::reauth_lock`], so a burst of
    /// concurrent requests meeting the same dead token performs one login. A waiter that
    /// finds the token already changed skips its own login and retries.
    async fn send_authed<F>(&self, build: F) -> VaultResult<reqwest::Response>
    where
        F: Fn(&str) -> reqwest::RequestBuilder,
    {
        let token = { self.token.read().await.token.clone() };
        let resp = build(&token).send().await.map_err(|e| transient_send(&e))?;
        let status = resp.status();
        let rejected = status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN;
        if !rejected || !self.can_reauthenticate() {
            return check_status(resp);
        }

        {
            let _guard = self.reauth_lock.lock().await;
            // Someone else may have re-authenticated while we waited: if the token has
            // moved on, theirs is the one login this burst needed.
            let current = { self.token.read().await.token.clone() };
            if *current == *token {
                warn!(
                    status = status.as_u16(),
                    "vault: request rejected as unauthenticated; re-authenticating once"
                );
                self.login().await?;
            }
        }

        let token = { self.token.read().await.token.clone() };
        let resp = build(&token).send().await.map_err(|e| transient_send(&e))?;
        check_status(resp)
    }

    /// POST an authenticated body (Transit) and check status.
    async fn authed_post(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> VaultResult<reqwest::Response> {
        self.send_authed(|token| {
            self.http
                .post(url)
                .header("X-Vault-Token", token)
                .headers(self.extra_headers())
                .json(body)
        })
        .await
    }
}

/// Resolve the auth method from config, honouring the bare `VAULT_TOKEN` env var
/// as a final fallback when neither config token nor AppRole is set.
fn resolve_auth(config: &VaultConfig) -> VaultResult<Auth> {
    if let Some(token) = config.token.as_deref().filter(|t| !t.is_empty()) {
        return Ok(Auth::Token(Zeroizing::new(token.to_owned())));
    }
    if let Some(path) = config.token_file.as_ref() {
        return Ok(Auth::TokenFile { path: path.clone() });
    }
    let role_id = config.role_id.as_deref().filter(|r| !r.is_empty());
    let secret_id = config.secret_id.as_deref().filter(|s| !s.is_empty());
    if let (Some(role_id), Some(secret_id)) = (role_id, secret_id) {
        return Ok(Auth::AppRole {
            role_id: role_id.to_owned(),
            secret_id: Zeroizing::new(secret_id.to_owned()),
        });
    }
    if let Ok(token) = std::env::var("VAULT_TOKEN")
        && !token.is_empty()
    {
        return Ok(Auth::Token(Zeroizing::new(token)));
    }
    Err(VaultError::Permanent(
        "vault has no usable auth (set token / VAULT_TOKEN or role_id + secret_id)".to_owned(),
    ))
}

/// Map a `reqwest` send error (connect / timeout / DNS) to a transient error.
///
/// The raw error is not formatted: a `reqwest::Error` Display embeds the request URL, which
/// for a Vault request is the KV path or the Transit mount and key name. Those are not
/// secret (the token rides a header, never the URL), but they should not reach logs,
/// matching `check_status`, which omits the response body for the same reason. A category
/// label is enough to classify the transient.
fn transient_send(e: &reqwest::Error) -> VaultError {
    let category = if e.is_timeout() {
        "timeout"
    } else if e.is_connect() {
        "connection failure"
    } else {
        "request error"
    };
    VaultError::Transient(format!("vault request failed ({category})"))
}

/// Classify an HTTP response by status: `2xx` passes through, `401`/`403`/`429` and `5xx`
/// are transient, and other `4xx` are permanent. The response body is left out of the
/// error, since it may echo a secret path.
fn check_status(resp: reqwest::Response) -> VaultResult<reqwest::Response> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    let code = status.as_u16();
    if status == StatusCode::UNAUTHORIZED
        || status == StatusCode::FORBIDDEN
        || status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
    {
        Err(VaultError::Transient(format!(
            "vault returned status {code}"
        )))
    } else {
        Err(VaultError::Permanent(format!(
            "vault returned status {code}"
        )))
    }
}

/// Parse a JSON body, mapping a decode failure to a permanent error (a malformed
/// response is not made better by retrying).
async fn parse_json<T: serde::de::DeserializeOwned>(mut resp: reqwest::Response) -> VaultResult<T> {
    // Cap the body: a compromised or MITM'd Vault/OpenBao (the http case dev tolerates)
    // could stream an unbounded body into memory and OOM the node. Reject an oversized
    // Content-Length up front, then bound the accumulated chunks (a lying/absent length).
    if resp
        .content_length()
        .is_some_and(|len| len > MAX_VAULT_BODY_BYTES)
    {
        return Err(VaultError::Transient(
            "vault response body exceeds the size cap".to_owned(),
        ));
    }
    // This accumulation buffer holds the raw response bytes, which for a secret read
    // (private-key PEMs, S3 creds, the Transit DEK, the client token) are secret, and it is
    // dropped un-zeroized. Zeroizing `buf` alone would not close the window: the same bytes
    // live in the reqwest/hyper receive buffers behind `resp.chunk()`, which this code
    // cannot scrub. The HTTP read path is an accepted non-wiped intermediate, defence in
    // depth against core dumps and swap rather than a hard guarantee. The parsed return
    // values are wrapped in `Zeroizing` at each caller.
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|_| {
        // Do not interpolate the reqwest error: its Display can embed the request URL,
        // which for a Vault request is the KV secret path or the Transit mount and key
        // name. Mirror `transient_send` and `check_status`, which emit a fixed category
        // label rather than echoing the URL into operator logs.
        VaultError::Transient("reading vault response body failed".to_owned())
    })? {
        if u64::try_from(buf.len().saturating_add(chunk.len())).unwrap_or(u64::MAX)
            > MAX_VAULT_BODY_BYTES
        {
            return Err(VaultError::Transient(
                "vault response body exceeds the size cap".to_owned(),
            ));
        }
        buf.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&buf)
        .map_err(|e| VaultError::Permanent(format!("parsing vault response: {e}")))
}

/// Time a Vault HTTP call and record its latency and error status under `label`, the
/// `record_vault_call` metric label, so each request method carries only its own URL and
/// parse body rather than a repeated timing wrapper.
async fn timed_call<T>(
    label: &'static str,
    fut: impl std::future::Future<Output = VaultResult<T>>,
) -> VaultResult<T> {
    let started = std::time::Instant::now();
    // A `vault_call{operation}` child span under whatever is running (an `ingest_job`, a
    // Beacon `scan_dataset`), so a slow Vault is not read as a slow ingest or query.
    let result =
        tracing::Instrument::instrument(fut, tracing::info_span!("vault_call", operation = label))
            .await;
    crate::metrics::record_vault_call(label, started.elapsed().as_secs_f64(), result.is_err());
    result
}

#[cfg(test)]
mod tests {

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use serde_json::{Value, json};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    use super::*;

    /// A static-token vault config pointing at `address`.
    fn token_config(address: &str) -> VaultConfig {
        VaultConfig {
            address: address.to_owned(),
            token: Some("hvs.test-token".to_owned()),
            kv_path: Some("gdi-node-standalone/c4gh-identities".to_owned()),
            ..VaultConfig::default()
        }
    }

    /// An AppRole vault config pointing at `address`.
    fn approle_config(address: &str) -> VaultConfig {
        VaultConfig {
            address: address.to_owned(),
            role_id: Some("role-123".to_owned()),
            secret_id: Some("secret-456".to_owned()),
            kv_path: Some("gdi-node-standalone/c4gh-identities".to_owned()),
            ..VaultConfig::default()
        }
    }

    /// A KV v2 read body wrapping `data`.
    fn kv_body(data: &Value) -> Value {
        json!({ "data": { "data": data, "metadata": { "version": 1 } } })
    }

    /// An auth body (AppRole login / renew-self) with a token + lease.
    fn auth_body(token: &str, lease: u64, renewable: bool) -> Value {
        json!({ "auth": { "client_token": token, "lease_duration": lease, "renewable": renewable } })
    }

    #[tokio::test]
    async fn approle_login_then_kv_read_parses_inner_data() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/auth/approle/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(auth_body(
                "s.approle-token",
                3600,
                true,
            )))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/v1/secret/data/gdi-node-standalone/c4gh-identities"))
            .respond_with(ResponseTemplate::new(200).set_body_json(kv_body(&json!({
                "node": "-----BEGIN CRYPT4GH PRIVATE KEY-----\nAAAA\n-----END CRYPT4GH PRIVATE KEY-----", // gitleaks:allow - fixture PEM
                "node-prev": "-----BEGIN CRYPT4GH PRIVATE KEY-----\nBBBB\n-----END CRYPT4GH PRIVATE KEY-----"
            }))))
            .expect(1)
            .mount(&server)
            .await;

        let client = VaultClient::connect(&approle_config(&server.uri()))
            .await
            .expect("connect + AppRole login");
        let secret = client
            .kv_get("gdi-node-standalone/c4gh-identities")
            .await
            .expect("kv read");
        assert_eq!(secret.len(), 2);
        assert!(secret["node"].contains("CRYPT4GH PRIVATE KEY"));
        assert!(secret.contains_key("node-prev"));
    }

    #[tokio::test]
    async fn static_token_kv_read_sends_token_header() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/secret/data/s3-creds"))
            .and(wiremock::matchers::header(
                "X-Vault-Token",
                "hvs.test-token",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(kv_body(&json!({
                "primary_access_key_id": "AKIA",
                "primary_secret_access_key": "shhh"
            }))))
            .expect(1)
            .mount(&server)
            .await;

        let client = VaultClient::connect(&token_config(&server.uri()))
            .await
            .expect("connect with static token");
        let creds = client.kv_get("s3-creds").await.expect("kv read");
        assert_eq!(creds["primary_access_key_id"], "AKIA");
        assert_eq!(creds["primary_secret_access_key"], "shhh");
    }

    #[tokio::test]
    async fn kv_read_does_not_follow_a_redirect() {
        // `X-Vault-Token` is a custom header reqwest does not strip on a cross-host
        // redirect, and Vault's API never redirects, so the client must not follow a 3xx. A
        // KV read answered with a 302 must fail closed and never request the redirect
        // target, which would re-send the token to another host.
        let server = MockServer::start().await;

        // The KV read is answered with a 302 pointing at a sibling path. No `.expect(...)`,
        // since the client may retry the failing read; the invariant is asserted below.
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/s3-creds"))
            .respond_with(ResponseTemplate::new(302).insert_header("Location", "/leaked"))
            .mount(&server)
            .await;

        // The redirect target must never be requested; that would mean the token was re-sent.
        Mock::given(method("GET"))
            .and(path("/leaked"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(kv_body(&json!({ "stolen": "token" }))),
            )
            .expect(0)
            .mount(&server)
            .await;

        let client = VaultClient::connect(&token_config(&server.uri()))
            .await
            .expect("connect with static token");
        // Fails closed (a 302 is not a valid KV response) rather than following the redirect.
        assert!(
            client.kv_get("s3-creds").await.is_err(),
            "a redirected KV read must fail closed, not follow the redirect"
        );
        // `/leaked`'s `.expect(0)` is verified when `server` drops: the token was not re-sent.
    }

    #[tokio::test]
    async fn kv_put_create_sends_cas_zero() {
        use wiremock::matchers::body_partial_json;

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/secret/data/gdi-node-standalone/c4gh-identities"))
            // The create-only write must carry options.cas = 0 and the secret data.
            .and(body_partial_json(
                json!({ "options": { "cas": 0 }, "data": { "node": "PEM" } }),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "version": 1 }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = VaultClient::connect(&token_config(&server.uri()))
            .await
            .expect("connect");
        let mut data = std::collections::BTreeMap::new();
        data.insert("node".to_owned(), "PEM".to_owned());
        client
            .kv_put_create("gdi-node-standalone/c4gh-identities", &data)
            .await
            .expect("create");
    }

    #[tokio::test]
    async fn kv_put_create_cas_conflict_is_permanent() {
        let server = MockServer::start().await;
        // A pre-existing secret makes Vault reject cas=0 with a 400 -> permanent.
        Mock::given(method("POST"))
            .and(path("/v1/secret/data/p"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "errors": ["check-and-set parameter did not match the current version"]
            })))
            .mount(&server)
            .await;

        let client = VaultClient::connect(&token_config(&server.uri()))
            .await
            .expect("connect");
        let mut data = std::collections::BTreeMap::new();
        data.insert("node".to_owned(), "PEM".to_owned());
        let err = client
            .kv_put_create("p", &data)
            .await
            .expect_err("cas conflict should error");
        std::assert_matches!(err, VaultError::Permanent(_), "got {err:?}");
    }

    #[tokio::test]
    async fn transit_datakey_and_decrypt_round_trip() {
        let server = MockServer::start().await;
        // 256-bit DEK, base64.
        let dek_plain = BASE64.encode([7u8; 32]);
        let dek_wrapped = "vault:v1:AAAAdatakey";

        Mock::given(method("POST"))
            .and(path("/v1/transit/datakey/plaintext/gdi-at-rest"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "plaintext": dek_plain, "ciphertext": dek_wrapped }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let dek_plain_for_decrypt = dek_plain.clone();
        Mock::given(method("POST"))
            .and(path("/v1/transit/decrypt/gdi-at-rest"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "plaintext": dek_plain_for_decrypt }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = VaultClient::connect(&token_config(&server.uri()))
            .await
            .expect("connect");
        let (plain, wrapped) = client
            .transit_datakey("gdi-at-rest")
            .await
            .expect("datakey");
        assert_eq!(*plain, dek_plain);
        assert_eq!(wrapped, dek_wrapped);

        let unwrapped = client
            .transit_decrypt("gdi-at-rest", wrapped.as_str())
            .await
            .expect("decrypt");
        assert_eq!(*unwrapped, dek_plain);

        // The decoded DEK round-trips back to the raw 32 bytes.
        let raw = VaultClient::decode_b64(&unwrapped).expect("decode");
        assert_eq!(&raw[..], &[7u8; 32]);
    }

    /// A `token_file` config pointing at `path`.
    fn token_file_config(address: &str, path: &std::path::Path) -> VaultConfig {
        VaultConfig {
            address: address.to_owned(),
            token_file: Some(path.to_path_buf()),
            kv_path: Some("gdi-node-standalone/c4gh-identities".to_owned()),
            ..VaultConfig::default()
        }
    }

    /// Set a file's mtime, so a test can control the only rotation signal this auth mode
    /// has.
    fn set_mtime(path: &std::path::Path, mtime: std::time::SystemTime) {
        let file = std::fs::File::options()
            .write(true)
            .open(path)
            .expect("open for mtime");
        file.set_modified(mtime).expect("set mtime");
    }

    /// An agent that rotates the token file is picked up on the next call, and a rotation
    /// that does not move the mtime is invisible.
    ///
    /// `Auth::TokenFile` is the one auth mode with no lease and no renewal: `needs_renew` is
    /// structurally false, so the mtime comparison in `ensure_token` is the only thing that
    /// can refresh the token. Both halves matter:
    ///
    ///  * mtime moved -> re-read. Without it the node presents a revoked token until someone
    ///    restarts it, and the failure looks like "Vault started rejecting us".
    ///  * mtime unchanged -> not re-read. An agent that rewrites the file within the
    ///    filesystem's mtime granularity, or that preserves mtime, is missed. Pinning it
    ///    means anyone who adds content hashing or inode checks is told they changed the
    ///    contract.
    #[tokio::test]
    async fn token_file_rotation_is_seen_by_mtime_and_only_by_mtime() {
        let server = MockServer::start().await;
        let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen_resp = Arc::clone(&seen);
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/p"))
            .respond_with(move |req: &Request| {
                let tok = req
                    .headers
                    .get("X-Vault-Token")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("<missing>")
                    .to_owned();
                seen_resp.lock().expect("not poisoned").push(tok);
                ResponseTemplate::new(200).set_body_json(kv_body(&json!({ "k": "v" })))
            })
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().expect("tempdir");
        let token_path = dir.path().join("token");
        std::fs::write(&token_path, "hvs.first\n").expect("write token");
        let old_mtime = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000);
        set_mtime(&token_path, old_mtime);

        let client = VaultClient::connect(&token_file_config(&server.uri(), &token_path))
            .await
            .expect("connect");
        client.kv_get("p").await.expect("first read");

        // The agent rotates the token and the mtime moves: the next call must re-read.
        std::fs::write(&token_path, "hvs.rotated\n").expect("rotate token");
        set_mtime(&token_path, old_mtime + std::time::Duration::from_mins(1));
        client.kv_get("p").await.expect("read after rotation");

        // The agent rotates again but the mtime does not move, so the change is invisible.
        std::fs::write(&token_path, "hvs.third\n").expect("rotate token again");
        set_mtime(&token_path, old_mtime + std::time::Duration::from_mins(1));
        client
            .kv_get("p")
            .await
            .expect("read after silent rotation");

        let seen = seen.lock().expect("not poisoned").clone();
        assert_eq!(
            seen,
            vec![
                "hvs.first".to_owned(),
                "hvs.rotated".to_owned(),
                "hvs.rotated".to_owned(),
            ],
            "a moved mtime must re-read the file; an unmoved one must not (the third \
             call still presents the second token, never `hvs.third`)"
        );
    }

    #[tokio::test]
    async fn near_expiry_lease_triggers_renew_self() {
        let server = MockServer::start().await;

        // AppRole login returns a short renewable lease so the next request renews.
        Mock::given(method("POST"))
            .and(path("/v1/auth/approle/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(auth_body(
                "s.first-token",
                1,
                true,
            )))
            .expect(1)
            .mount(&server)
            .await;

        let renew_calls = Arc::new(AtomicUsize::new(0));
        let renew_calls_resp = Arc::clone(&renew_calls);
        Mock::given(method("POST"))
            .and(path("/v1/auth/token/renew-self"))
            .respond_with(move |_req: &Request| {
                renew_calls_resp.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(200).set_body_json(auth_body("s.renewed-token", 3600, true))
            })
            .expect(1)
            .mount(&server)
            .await;

        // The KV read must arrive with the renewed token, proving renew ran first.
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/p"))
            .and(wiremock::matchers::header(
                "X-Vault-Token",
                "s.renewed-token",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(kv_body(&json!({ "k": "v" }))))
            .expect(1)
            .mount(&server)
            .await;

        let client = VaultClient::connect(&approle_config(&server.uri()))
            .await
            .expect("connect");
        // The 1s lease is already past its renew threshold (it floors to a tiny
        // value), so the next call renews first.
        let secret = client.kv_get("p").await.expect("kv read after renew");
        assert_eq!(secret["k"], "v");
        assert_eq!(renew_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn renew_failure_triggers_relogin() {
        let server = MockServer::start().await;

        // Two AppRole logins expected: the initial one + the re-login after the
        // renew fails. The first yields a short lease; the second a long one.
        let login_calls = Arc::new(AtomicUsize::new(0));
        let login_resp = Arc::clone(&login_calls);
        Mock::given(method("POST"))
            .and(path("/v1/auth/approle/login"))
            .respond_with(move |_req: &Request| {
                let n = login_resp.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    ResponseTemplate::new(200).set_body_json(auth_body("s.first", 1, true))
                } else {
                    ResponseTemplate::new(200).set_body_json(auth_body("s.second", 3600, true))
                }
            })
            .expect(2)
            .mount(&server)
            .await;

        // renew-self fails with 403 (token already lapsed) -> re-login.
        Mock::given(method("POST"))
            .and(path("/v1/auth/token/renew-self"))
            .respond_with(
                ResponseTemplate::new(403)
                    .set_body_json(json!({ "errors": ["permission denied"] })),
            )
            .expect(1)
            .mount(&server)
            .await;

        // The KV read arrives with the re-logged-in token.
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/p"))
            .and(wiremock::matchers::header("X-Vault-Token", "s.second"))
            .respond_with(ResponseTemplate::new(200).set_body_json(kv_body(&json!({ "k": "v" }))))
            .expect(1)
            .mount(&server)
            .await;

        let client = VaultClient::connect(&approle_config(&server.uri()))
            .await
            .expect("connect");
        let secret = client.kv_get("p").await.expect("kv read after re-login");
        assert_eq!(secret["k"], "v");
        assert_eq!(login_calls.load(Ordering::SeqCst), 2);
    }

    /// An out-of-band token revocation must self-heal on the next request, not at the renew
    /// threshold.
    ///
    /// Vault answers a revoked token with 403. Without the re-auth path the only post-boot
    /// route to `login()` for AppRole is `needs_renew()`, which requires a renewable token
    /// past ~2/3 of its lease, so a role issuing batch or non-renewable tokens would have no
    /// recovery short of a process restart, and even a renewable role would draw
    /// PME_TRANSIENT and hold `/health/ready` at 503 until the renew threshold.
    #[tokio::test]
    async fn revoked_token_403_triggers_one_relogin_and_retry() {
        let server = MockServer::start().await;

        // Two logins: the initial connect, then the re-auth after the 403.
        let login_calls = Arc::new(AtomicUsize::new(0));
        let login_resp = Arc::clone(&login_calls);
        Mock::given(method("POST"))
            .and(path("/v1/auth/approle/login"))
            .respond_with(move |_req: &Request| {
                let n = login_resp.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    // Long lease and renewable, so `needs_renew` never fires: the only way
                    // to reach a second login is the 403 path under test.
                    ResponseTemplate::new(200).set_body_json(auth_body("s.revoked", 3600, true))
                } else {
                    ResponseTemplate::new(200).set_body_json(auth_body("s.fresh", 3600, true))
                }
            })
            .expect(2)
            .mount(&server)
            .await;

        // The revoked token is rejected...
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/p"))
            .and(wiremock::matchers::header("X-Vault-Token", "s.revoked"))
            .respond_with(
                ResponseTemplate::new(403)
                    .set_body_json(json!({ "errors": ["permission denied"] })),
            )
            .expect(1)
            .mount(&server)
            .await;

        // ...and the retry with the freshly minted token succeeds.
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/p"))
            .and(wiremock::matchers::header("X-Vault-Token", "s.fresh"))
            .respond_with(ResponseTemplate::new(200).set_body_json(kv_body(&json!({ "k": "v" }))))
            .expect(1)
            .mount(&server)
            .await;

        let client = VaultClient::connect(&approle_config(&server.uri()))
            .await
            .expect("connect");
        let secret = client.kv_get("p").await.expect("kv read after re-auth");
        assert_eq!(secret["k"], "v");
        assert_eq!(
            login_calls.load(Ordering::SeqCst),
            2,
            "exactly one re-login"
        );
    }

    #[tokio::test]
    async fn expired_token_403_on_kv_is_transient() {
        let server = MockServer::start().await;

        // Static token (non-renewable), so no renew runs; the KV read just 403s.
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/p"))
            .respond_with(
                ResponseTemplate::new(403)
                    .set_body_json(json!({ "errors": ["permission denied"] })),
            )
            .mount(&server)
            .await;

        let client = VaultClient::connect(&token_config(&server.uri()))
            .await
            .expect("connect");
        // `ZeroizingIdentityMap` is not `Debug` (it holds secret PEMs), so match rather
        // than `expect_err`, as `retire_identity` does for `SecretKey`.
        let Err(err) = client.kv_get("p").await else {
            panic!("403 should error");
        };
        std::assert_matches!(err, VaultError::Transient(_), "got {err:?}");
    }

    #[tokio::test]
    async fn missing_secret_404_is_permanent() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/secret/data/absent"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({ "errors": [] })))
            .mount(&server)
            .await;

        let client = VaultClient::connect(&token_config(&server.uri()))
            .await
            .expect("connect");
        // `ZeroizingIdentityMap` is not `Debug` (it holds secret PEMs), so match rather
        // than `expect_err`, as `retire_identity` does for `SecretKey`.
        let Err(err) = client.kv_get("absent").await else {
            panic!("404 should error");
        };
        std::assert_matches!(err, VaultError::Permanent(_), "got {err:?}");
    }

    #[tokio::test]
    async fn server_5xx_is_transient() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/p"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let client = VaultClient::connect(&token_config(&server.uri()))
            .await
            .expect("connect");
        // `ZeroizingIdentityMap` is not `Debug` (it holds secret PEMs), so match rather
        // than `expect_err`, as `retire_identity` does for `SecretKey`.
        let Err(err) = client.kv_get("p").await else {
            panic!("503 should error");
        };
        std::assert_matches!(err, VaultError::Transient(_), "got {err:?}");
    }

    #[tokio::test]
    async fn unreachable_server_login_is_transient() {
        // A port nothing listens on: AppRole login connect fails -> transient.
        // `VaultClient` holds no Debug (secrets), so match the err side directly.
        let cfg = approle_config("http://127.0.0.1:1");
        match VaultClient::connect(&cfg).await {
            Ok(_) => panic!("connect to dead server should fail"),
            Err(e) => std::assert_matches!(e, VaultError::Transient(_), "got {e:?}"),
        }
    }

    #[tokio::test]
    async fn approle_login_4xx_other_than_auth_is_permanent() {
        let server = MockServer::start().await;
        // 400 Bad Request on the login (malformed approle) -> permanent.
        Mock::given(method("POST"))
            .and(path("/v1/auth/approle/login"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({ "errors": ["bad"] })))
            .mount(&server)
            .await;
        match VaultClient::connect(&approle_config(&server.uri())).await {
            Ok(_) => panic!("400 login should fail"),
            Err(e) => std::assert_matches!(e, VaultError::Permanent(_), "got {e:?}"),
        }
    }

    #[test]
    #[serial_test::serial(env)]
    fn no_auth_config_is_permanent() {
        let cfg = VaultConfig {
            address: "https://vault.example.org".to_owned(),
            kv_path: Some("p".to_owned()),
            ..VaultConfig::default()
        };
        // Ensure no ambient VAULT_TOKEN leaks in. `Auth` holds no Debug, so match the err
        // side directly rather than `expect_err`. `EnvGuard` restores on `Drop`, so an
        // unwind from `resolve_auth` or from the assertions below still restores it.
        let _restore = test_util::EnvGuard::remove("VAULT_TOKEN");
        match resolve_auth(&cfg) {
            Ok(_) => panic!("no auth should be permanent"),
            Err(e) => std::assert_matches!(e, VaultError::Permanent(_), "got {e:?}"),
        }
    }

    #[test]
    fn renew_threshold_leaves_headroom() {
        // A 1h lease renews at ~2/3 (40min), not at the very end.
        let t = renew_threshold(Duration::from_hours(1));
        assert!(t >= Duration::from_mins(40) && t < Duration::from_hours(1));
        // A 5s lease is below MIN_RENEW_HEADROOM, so it renews almost immediately.
        let short = renew_threshold(Duration::from_secs(5));
        assert!(short <= Duration::from_secs(5));
    }

    /// A response that asserts the namespace header is forwarded.
    struct NamespaceAsserter;
    impl Respond for NamespaceAsserter {
        fn respond(&self, req: &Request) -> ResponseTemplate {
            let ns = req
                .headers
                .get("X-Vault-Namespace")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            ResponseTemplate::new(200).set_body_json(kv_body(&json!({ "ns": ns })))
        }
    }

    #[tokio::test]
    async fn namespace_header_is_forwarded() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/p"))
            .respond_with(NamespaceAsserter)
            .mount(&server)
            .await;

        let cfg = VaultConfig {
            namespace: Some("admin/gdi".to_owned()),
            ..token_config(&server.uri())
        };
        let client = VaultClient::connect(&cfg).await.expect("connect");
        let secret = client.kv_get("p").await.expect("kv read");
        assert_eq!(secret["ns"], "admin/gdi");
    }
}
