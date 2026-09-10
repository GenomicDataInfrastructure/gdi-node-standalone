//! Vault precedence integration tests (gated on the `vault` feature): with
//! `[vault]` configured, the loaded crypt4gh identity and per-bucket S3 creds come
//! from Vault, overriding the inline `[keys]` / `[[s3.buckets]]` values.
//!
//! Uses a wiremock mock Vault (no Docker).
#![cfg(feature = "vault")]
#![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

use gdi_node_standalone::secrets;
use gdi_node_standalone_core::config::ServiceConfig;
use gdi_node_standalone_core::crypt4gh::{
    generate_keypair, parse_secret_key, serialize_public_key, serialize_secret_key,
};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A fresh unencrypted crypt4gh secret-key PEM + its recipient PEM.
fn fresh_identity() -> (String, String) {
    let (sk, pk) = generate_keypair();
    (serialize_secret_key(&sk), serialize_public_key(&pk))
}

/// Build a service config whose `[vault]` points at `address`, with a different
/// inline `[keys]` identity and inline S3 creds we expect Vault to override.
fn config_with_vault_and_inline(address: &str, inline_key_file: &str) -> ServiceConfig {
    let toml = format!(
        r#"
[service]
base_url = "https://gdi-ee.example.org"
data_dir = "/tmp/gdi-vault-precedence-test"

[beacon]
id = "ee.ut.af-beacon.production"
name = "GDI Estonia Beacon"

[keys]
identities = ["{inline_key_file}"]

[[s3.buckets]]
name = "primary"
endpoint = "https://s3.example.org"
bucket = "gdi-ee"
path_style = true
access_key_id = "INLINE-ACCESS"
secret_access_key = "inline-secret"

[vault]
address = "{address}"
token = "hvs.test"
kv_path = "gdi/c4gh"
s3_path = "gdi/s3"
"#
    );
    ServiceConfig::from_toml_str(&toml).expect("config parses")
}

#[tokio::test]
async fn vault_identity_and_s3_creds_take_precedence_over_inline() {
    let server = MockServer::start().await;

    // The Vault-held identity, different from the inline one.
    let (vault_pem, vault_recipient) = fresh_identity();
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/gdi/c4gh"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "c4gh-0000000000000001": vault_pem }, "metadata": { "version": 1 } }
        })))
        .mount(&server)
        .await;

    // The Vault-held S3 credentials for bucket "primary", different from the inline ones.
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/gdi/s3"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": {
                "primary_access_key_id": "VAULT-ACCESS",
                "primary_secret_access_key": "vault-secret"
            }, "metadata": { "version": 1 } }
        })))
        .mount(&server)
        .await;

    // Write a different inline key file on disk, so the test can show Vault wins.
    let dir = tempfile::tempdir().unwrap();
    let inline_key_path = dir.path().join("inline.c4gh");
    let (inline_pem, inline_recipient) = fresh_identity();
    std::fs::write(&inline_key_path, &inline_pem).unwrap();
    assert_ne!(vault_recipient, inline_recipient, "fixtures must differ");

    let config = config_with_vault_and_inline(&server.uri(), inline_key_path.to_str().unwrap());

    let resolved = secrets::resolve(&config).await.expect("resolve secrets");

    // Identity precedence: the recipient is the Vault identity, not the inline one.
    assert!(resolved.identities.is_enabled());
    assert_eq!(
        resolved.identities.recipient_pem(),
        Some(vault_recipient),
        "Vault identity must take precedence over the inline [keys] file"
    );
    assert_ne!(resolved.identities.recipient_pem(), Some(inline_recipient));

    // S3-cred precedence: the override map carries the Vault creds for "primary".
    let (access, secret) = resolved
        .s3_overrides
        .get("primary")
        .expect("vault override for primary");
    assert_eq!(access, "VAULT-ACCESS");
    assert_eq!(secret, "vault-secret");

    // And applying the override replaces the inline values on the bucket.
    let bucket = &config.s3.as_ref().unwrap().buckets[0];
    assert_eq!(bucket.access_key_id.as_deref(), Some("INLINE-ACCESS"));
    let overridden = secrets::apply_s3_override(bucket, &resolved.s3_overrides);
    assert_eq!(overridden.access_key_id.as_deref(), Some("VAULT-ACCESS"));
    assert_eq!(
        overridden.secret_access_key.as_deref(),
        Some("vault-secret")
    );

    // The Vault identity actually parses (sanity: it is a usable key).
    assert!(parse_secret_key(&inline_pem).is_ok());
}

#[tokio::test]
async fn no_vault_block_falls_back_to_inline_keys() {
    // No [vault] block: identities load from [keys] files, no S3 overrides.
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("node.c4gh");
    let (pem, recipient) = fresh_identity();
    std::fs::write(&key_path, &pem).unwrap();
    // `strict_key_perms` defaults to `true`, fail-closed, so a group- or other-readable
    // identity key refuses to load. Set the 0600 permissions a real operator uses, so the
    // fallback path rather than the permissions gate is what is tested.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let toml = format!(
        r#"
[service]
base_url = "https://gdi-ee.example.org"
data_dir = "/tmp/gdi-no-vault-test"

[beacon]
id = "ee.ut.af-beacon.production"
name = "GDI Estonia Beacon"

[keys]
identities = ["{}"]
"#,
        key_path.to_str().unwrap()
    );
    let config = ServiceConfig::from_toml_str(&toml).unwrap();

    let resolved = secrets::resolve(&config).await.expect("resolve no-vault");
    assert!(resolved.vault.is_none());
    assert!(resolved.s3_overrides.is_empty());
    assert_eq!(resolved.identities.recipient_pem(), Some(recipient));
}

#[tokio::test]
async fn vault_unreachable_is_transient_not_a_crash() {
    use gdi_node_standalone::vault::VaultError;
    // Point at a dead port: connect fails transiently (the node would start
    // keyless rather than crash).
    let toml = r#"
[service]
base_url = "https://gdi-ee.example.org"
data_dir = "/tmp/gdi-vault-down-test"

[beacon]
id = "ee.ut.af-beacon.production"
name = "GDI Estonia Beacon"

[vault]
address = "http://127.0.0.1:1"
token = "hvs.test"
kv_path = "gdi/c4gh"
"#;
    let config = ServiceConfig::from_toml_str(toml).unwrap();
    match secrets::resolve(&config).await {
        Ok(_) => panic!("unreachable Vault should not resolve"),
        Err(e) => std::assert_matches!(e, VaultError::Transient(_), "got {e:?}"),
    }
}

/// Optional real-server smoke test (OpenBao / HashiCorp Vault dev), `#[ignore]`
/// by default and skipped unless `GDI_TEST_VAULT_ADDR` is set. The mock-server
/// coverage above is the default; this exercises the same code path against an
/// actual KV v2 + Transit engine.
///
/// The maintained route is `scripts/e2e/run-full.sh` (`ci-local.sh e2e-full`): it boots
/// the backends, exports every var below, and sets `GDI_TEST_REQUIRED=1` so a missing
/// one panics instead of skipping to a green. The snippet below is the by-hand route.
///
/// Run an OpenBao (or Vault) dev server, enable a transit key, then:
/// ```text
/// docker run -d --name openbao --cap-add=IPC_LOCK -p 8200:8200 \
///   -e BAO_DEV_ROOT_TOKEN_ID=root openbao/openbao server -dev \
///   -dev-listen-address=0.0.0.0:8200
/// export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root
/// bao secrets enable transit && bao write -f transit/keys/gdi-at-rest type=aes256-gcm96
/// bao kv put secret/gdi/c4gh c4gh-0000000000000001="$(cat node.c4gh)"
/// GDI_TEST_VAULT_ADDR=http://127.0.0.1:8200 GDI_TEST_VAULT_TOKEN=root \
/// GDI_TEST_TRANSIT_KEY=gdi-at-rest \
///   cargo test --features vault --test it -- --ignored real_vault
/// ```
#[tokio::test]
#[ignore = "requires a real OpenBao/Vault dev server via GDI_TEST_VAULT_ADDR"]
#[expect(
    clippy::doc_markdown,
    reason = "docs use proper nouns (OpenBao, Vault, HashiCorp) as prose, not code"
)]
async fn real_vault_kv_and_transit_round_trip() {
    use gdi_node_standalone::vault::VaultClient;
    use gdi_node_standalone_core::config::VaultConfig;

    let Some(addr) = test_util::endpoint_env("GDI_TEST_VAULT_ADDR") else {
        return;
    };
    // Install the ring rustls provider (no-op if already installed) so an https
    // endpoint handshakes; harmless for http.
    gdi_node_standalone::preflight::install_crypto_provider();

    let token = std::env::var("GDI_TEST_VAULT_TOKEN").unwrap_or_else(|_| "root".to_owned());
    // Overridable: the KV path holding the node identity is deployment-specific. The
    // Compose stack uses `gdi-node-standalone/c4gh-identities` (compose/node.full.toml),
    // not the `gdi/c4gh` a hand-rolled dev server gets from the snippet above.
    let kv_path = std::env::var("GDI_TEST_VAULT_KV_PATH").unwrap_or_else(|_| "gdi/c4gh".to_owned());
    let cfg = VaultConfig {
        address: addr,
        token: Some(token),
        kv_path: Some(kv_path.clone()),
        ..VaultConfig::default()
    };
    let client = VaultClient::connect(&cfg)
        .await
        .expect("connect real vault");

    // KV v2 read (the operator seeded this path above).
    let secret = client.kv_get(&kv_path).await.expect("kv read");
    assert!(!secret.is_empty(), "seeded KV secret should be non-empty");

    // Transit datakey + decrypt round-trip (when a transit key is provisioned).
    if let Some(key) = test_util::endpoint_env("GDI_TEST_TRANSIT_KEY") {
        let (plaintext, ciphertext) = client.transit_datakey(&key).await.expect("datakey");
        assert!(ciphertext.starts_with("vault:"), "wrapped DEK form");
        let unwrapped = client
            .transit_decrypt(&key, &ciphertext)
            .await
            .expect("decrypt");
        assert_eq!(plaintext, unwrapped, "datakey/decrypt round-trip");
        let raw = VaultClient::decode_b64(&unwrapped).expect("decode");
        assert_eq!(raw.len(), 32, "256-bit DEK");
    }
}

// --- [vault].token_file: the agent-sidecar auth shape ------------------------
//
// These exercise the real `VaultClient` against a mock Vault that matches on the token
// header, so an assertion failure means the node presented the wrong credential, not
// merely that some call happened.

/// A `[vault]`-only config whose token comes from `token_file`.
fn vault_config_with_token_file(address: &str, token_path: &std::path::Path) -> VaultConfigAlias {
    VaultConfigAlias {
        address: address.to_owned(),
        token: None,
        token_file: Some(token_path.to_path_buf()),
        kv_path: Some("gdi/c4gh".to_owned()),
        ..VaultConfigAlias::default()
    }
}

use gdi_node_standalone_core::config::VaultConfig as VaultConfigAlias;
use wiremock::matchers::header;

#[tokio::test]
async fn token_file_is_read_trimmed_and_presented_to_vault() {
    use gdi_node_standalone::vault::VaultClient;

    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let token_path = dir.path().join("token");
    // Agents commonly write a trailing newline; an untrimmed token authenticates as
    // a different, invalid credential, which reads like a permissions problem.
    std::fs::write(&token_path, "  s.from-file  \n").unwrap();

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/gdi/c4gh"))
        .and(header("X-Vault-Token", "s.from-file"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "k": "v" }, "metadata": { "version": 1 } }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let cfg = vault_config_with_token_file(&server.uri(), &token_path);
    let client = VaultClient::connect(&cfg).await.expect("connect");
    let secret = client.kv_get("gdi/c4gh").await.expect("kv read");
    assert_eq!(secret.get("k").map(String::as_str), Some("v"));
    // The mock's `.expect(1)` header match is the real assertion: it is only
    // satisfied if the trimmed token was presented.
}

#[tokio::test]
async fn rotated_token_file_is_picked_up_without_restart() {
    use gdi_node_standalone::vault::VaultClient;

    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let token_path = dir.path().join("token");
    std::fs::write(&token_path, "s.first").unwrap();

    // Only the first token is accepted on this route...
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/gdi/first"))
        .and(header("X-Vault-Token", "s.first"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "which": "first" }, "metadata": { "version": 1 } }
        })))
        .mount(&server)
        .await;
    // ...and only the second on this one, so a stale token cannot satisfy it.
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/gdi/second"))
        .and(header("X-Vault-Token", "s.second"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "which": "second" }, "metadata": { "version": 1 } }
        })))
        .mount(&server)
        .await;

    let cfg = vault_config_with_token_file(&server.uri(), &token_path);
    let client = VaultClient::connect(&cfg).await.expect("connect");
    assert_eq!(
        client
            .kv_get("gdi/first")
            .await
            .expect("first read")
            .get("which"),
        Some(&"first".to_owned())
    );

    // The agent rotates the token. Sleep past the filesystem's mtime resolution: a
    // same-instant rewrite can land on an identical timestamp, which would make this
    // test pass for the wrong reason (no rotation actually detected).
    std::thread::sleep(std::time::Duration::from_millis(1100));
    std::fs::write(&token_path, "s.second").unwrap();

    // No restart, no explicit re-login: the next request must observe the new file.
    let got = client.kv_get("gdi/second").await.expect("second read");
    assert_eq!(
        got.get("which"),
        Some(&"second".to_owned()),
        "a rotated token file must be re-read on the next request"
    );
}

#[tokio::test]
async fn missing_token_file_is_a_permanent_error_naming_the_path() {
    use gdi_node_standalone::vault::VaultClient;

    let server = MockServer::start().await;
    let missing = std::path::Path::new("/nonexistent/gdi-vault-token");
    let cfg = vault_config_with_token_file(&server.uri(), missing);

    let err = VaultClient::connect(&cfg)
        .await
        .err()
        .expect("connect must fail when the token file is absent");
    let msg = err.to_string();
    assert!(
        msg.contains("/nonexistent/gdi-vault-token"),
        "the error must name the path so the operator can find it: {msg}"
    );
    assert!(
        msg.contains("permanent"),
        "an absent token file is a deployment fault, not a retryable one: {msg}"
    );
}

#[tokio::test]
async fn empty_token_file_is_rejected_rather_than_sent() {
    use gdi_node_standalone::vault::VaultClient;

    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let token_path = dir.path().join("token");
    // A half-written file from an agent mid-rotation. Sending an empty token would
    // surface as a confusing 403 from Vault instead of a clear local fault.
    std::fs::write(&token_path, "   \n").unwrap();

    let cfg = vault_config_with_token_file(&server.uri(), &token_path);
    let err = VaultClient::connect(&cfg)
        .await
        .err()
        .expect("an empty token file must fail");
    assert!(err.to_string().contains("empty"), "got: {err}");
}

#[tokio::test]
async fn a_world_readable_token_file_warns_but_still_starts() {
    use gdi_node_standalone::vault::VaultClient;

    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let token_path = dir.path().join("token");
    std::fs::write(&token_path, "s.loose").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    // Loose permissions are not fatal here, unlike `[service].strict_key_perms`, which
    // refuses to start on a group- or other-readable crypt4gh identity. Agent sinks commonly
    // write 0640, and failing closed would break the credential-free pattern `token_file`
    // exists to enable. This test is what stops the warning being hardened into a rejection.
    let cfg = vault_config_with_token_file(&server.uri(), &token_path);
    VaultClient::connect(&cfg)
        .await
        .expect("a loose-permission token file must still start (warn, not reject)");
}
