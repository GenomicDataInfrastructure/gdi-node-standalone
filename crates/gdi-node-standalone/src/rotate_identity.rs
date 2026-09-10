//! The `identity rotate` one-shot: mint a new node crypt4gh identity and add it to Vault KV
//! beside the existing one(s) (compiled only under the `vault` feature).
//!
//! Like [`crate::init_identity`] this is an operator-run step that mints a keypair in memory
//! and writes it straight to `[vault].kv_path`. Where `init` is create-only, `rotate` is
//! additive: it requires an existing identity, generates a fresh keypair, and writes the
//! merged set back, so the new key becomes the published recipient while every prior key is
//! retained for decryption across the re-key window. It never deletes a key; retiring an old
//! one is a separate step.
//!
//! Two guarantees:
//! * The new key wins regardless of clock skew. The field name is the larger of the wall
//!   clock and `current_max + 1` millis (see [`crate::init_identity`]'s `field_name`), so it
//!   sorts strictly after every existing field, and [`crate::secrets`] reads newest-first.
//! * No lost update. The write is a KV v2 check-and-set at the version read, so a racing
//!   writer is rejected and the caller re-runs, rather than being silently clobbered.
//!
//! Run it with the same write-capable credential as `identity init`, distinct from the
//! serving token (see [`crate::vault`]).

use anyhow::{Result, bail};

use gdi_node_standalone_core::config::{AuditConfig, VaultConfig};
use gdi_node_standalone_core::crypt4gh::{
    generate_keypair, public_key_fingerprint, serialize_public_key, serialize_secret_key,
};
use zeroize::Zeroizing;

use crate::init_identity::{field_name, now_millis, parse_field_millis};
use crate::vault::{VaultClient, VaultError};

/// Add a new node identity to Vault KV at `[vault].kv_path`, keeping the existing
/// one(s). Requires an identity to already exist (run `identity init` first).
///
/// # Errors
///
/// Returns an error, which `main` maps to a non-zero exit, when `kv_path` is unset, when
/// Vault is unreachable or the token is denied, when no identity exists yet, or when the
/// check-and-set write is rejected because of a concurrent change, in which case re-run it.
///
/// On success it emits a key-lifecycle line to the `audit` target, gated on
/// `audit_cfg.enabled`, recording the new published key field and the retained-key count,
/// never key material.
pub async fn run(vault_cfg: &VaultConfig, audit_cfg: &AuditConfig) -> Result<()> {
    let Some(kv_path) = vault_cfg.kv_path.as_deref().filter(|p| !p.is_empty()) else {
        bail!(
            "identity rotate is Vault-only: it requires a [vault].kv_path (the KV path the \
             node reads its identity from). In the file-based / no-Vault profile, rotate by \
             prepending the new key file as the first [keys].identities entry and restarting \
             (see docs/operating.md section 9)."
        );
    };

    let client = VaultClient::connect(vault_cfg)
        .await
        .map_err(|e| anyhow::anyhow!("connecting to Vault: {e}"))?;

    // Rotation is additive: it requires an existing identity to add a key beside.
    // Read the current map + version for the check-and-set.
    let (current, version) = match client.kv_get_versioned(kv_path).await {
        Ok((map, v)) if !map.is_empty() => (map, v),
        // Present but empty, or absent (a KV v2 404 is permanent): nothing to rotate.
        Ok(_) | Err(VaultError::Permanent(_)) => bail!(
            "no node identity at {}/{kv_path} to rotate; run `identity init` first \
             (rotate adds a new key beside the existing one)",
            vault_cfg.kv_mount()
        ),
        Err(VaultError::Transient(e)) => {
            bail!("cannot reach Vault to read the current identity: {e}")
        }
    };

    // Name the new field so it sorts strictly after every existing one, by taking
    // max(now, current_max + 1). The loader treats the greatest-millis field as the
    // published recipient, so the new key wins even if the wall clock lags an earlier mint.
    let new_millis = match current.keys().filter_map(|k| parse_field_millis(k)).max() {
        Some(max) => now_millis().max(max.saturating_add(1)),
        None => now_millis(),
    };
    let new_field = field_name(new_millis);
    if current.contains_key(&new_field) {
        // Unreachable, since `new_millis` exceeds every parsed field, but never
        // silently overwrite a key.
        bail!("computed field name {new_field} already exists; refusing to overwrite a key");
    }

    // Mint the new keypair in memory (never on disk).
    let (secret_key, public_key) = generate_keypair();
    let secret_pem = Zeroizing::new(serialize_secret_key(&secret_key));
    let recipient_pem = serialize_public_key(&public_key);

    // Additive write: keep every existing identity, add the new one, and check-and-set on
    // the version read so a concurrent writer cannot be clobbered.
    let mut merged = current;
    merged.insert(new_field.clone(), secret_pem.to_string());
    let retained = merged.len();

    client
        .kv_put_cas(kv_path, &merged, version)
        .await
        .map_err(|e| match e {
            VaultError::Permanent(msg) => anyhow::anyhow!(
                "rotation write rejected; a concurrent change moved the secret version; re-run: {msg}"
            ),
            VaultError::Transient(msg) => anyhow::anyhow!("rotation write failed: {msg}"),
        })?;

    // Mutation audit trail: record the rotation (new published field + retained count),
    // never the key material.
    crate::audit::identity_rotated(audit_cfg, &new_field, retained);

    println!(
        "rotated node crypt4gh identity at {}/{kv_path}: added field `{new_field}` (now the \
         published recipient); {retained} identities retained for decryption",
        vault_cfg.kv_mount()
    );
    println!("new node recipient:");
    print!("{recipient_pem}");
    println!(
        "recipient fingerprint: {}",
        public_key_fingerprint(&public_key)
    );
    // The published recipient just changed, so an earlier `identity backup` export no
    // longer captures the current key, and a stale backup is how an irreplaceable identity
    // is lost. The advisory goes to stderr so it cannot corrupt a captured PEM on stdout.
    eprintln!(
        "warning: the node identity changed, so a previous `identity backup` export no longer \
         contains this new key. Re-run `identity backup` to capture it."
    );
    // A running node loads its identities once at startup and has no reload path.
    eprintln!(
        "note: restart the running node for this rotation to take effect. It loaded its \
         identities at startup and keeps publishing the previous recipient until restarted."
    );
    Ok(())
}

#[cfg(test)]
mod tests {

    use serde_json::json;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn cfg(address: &str) -> VaultConfig {
        VaultConfig {
            address: address.to_owned(),
            token: Some("hvs.test-token".to_owned()),
            kv_path: Some("gdi-node-standalone/c4gh-identities".to_owned()),
            ..VaultConfig::default()
        }
    }

    #[tokio::test]
    async fn adds_key_retaining_existing_with_cas_version() {
        let server = MockServer::start().await;
        // An existing identity at version 3.
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/gdi-node-standalone/c4gh-identities"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "data": { "c4gh-0000000000000001": "-----BEGIN CRYPT4GH PRIVATE KEY-----\nOLD\n-----END CRYPT4GH PRIVATE KEY-----" }, // gitleaks:allow - fixture PEM
                    "metadata": { "version": 3 }
                }
            })))
            .mount(&server)
            .await;
        // The rotation write check-and-sets on the read version (3) and keeps the old field.
        Mock::given(method("POST"))
            .and(path("/v1/secret/data/gdi-node-standalone/c4gh-identities"))
            .and(body_partial_json(json!({
                "options": { "cas": 3 },
                "data": { "c4gh-0000000000000001": "-----BEGIN CRYPT4GH PRIVATE KEY-----\nOLD\n-----END CRYPT4GH PRIVATE KEY-----" }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "version": 4 }
            })))
            .expect(1)
            .mount(&server)
            .await;

        run(&cfg(&server.uri()), &AuditConfig::default())
            .await
            .expect("rotate adds a key");
    }

    #[tokio::test]
    async fn refuses_when_no_identity_yet() {
        let server = MockServer::start().await;
        // Absent path: KV v2 returns 404, which is permanent, so there is nothing to rotate.
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/gdi-node-standalone/c4gh-identities"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({ "errors": [] })))
            .mount(&server)
            .await;

        let err = run(&cfg(&server.uri()), &AuditConfig::default())
            .await
            .expect_err("rotation with no existing identity should error");
        assert!(
            err.to_string().contains("identity init"),
            "error should point at identity init: {err}"
        );
    }

    #[tokio::test]
    async fn errors_without_kv_path() {
        let vault_cfg = VaultConfig {
            address: "https://vault.example.org".to_owned(),
            token: Some("hvs.test".to_owned()),
            kv_path: None,
            ..VaultConfig::default()
        };
        let err = run(&vault_cfg, &AuditConfig::default())
            .await
            .expect_err("missing kv_path");
        assert!(err.to_string().contains("kv_path"), "got {err}");
    }

    /// With a far-future existing field (`c4gh-9999999999999999`) the wall clock is always
    /// smaller, so `max(now, existing_max + 1)` selects `existing_max + 1` and the new field
    /// sorts strictly after the existing one.
    #[tokio::test]
    async fn new_field_uses_existing_max_plus_one_when_clock_would_lose() {
        let server = MockServer::start().await;
        let far_future_field = "c4gh-9999999999999999";
        let far_future_millis: u128 = 9_999_999_999_999_999;
        let expected_millis = far_future_millis + 1; // existing_max + 1

        Mock::given(method("GET"))
            .and(path("/v1/secret/data/gdi-node-standalone/c4gh-identities"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "data": {
                        far_future_field: "-----BEGIN CRYPT4GH PRIVATE KEY-----\nOLD\n-----END CRYPT4GH PRIVATE KEY-----" // gitleaks:allow - fixture PEM
                    },
                    "metadata": { "version": 1 }
                }
            })))
            .mount(&server)
            .await;

        // Mount the POST mock (captures the write body for assertion below).
        Mock::given(method("POST"))
            .and(path("/v1/secret/data/gdi-node-standalone/c4gh-identities"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "version": 2 }
            })))
            .expect(1)
            .mount(&server)
            .await;

        run(&cfg(&server.uri()), &AuditConfig::default())
            .await
            .expect("rotate must succeed");

        let requests = server
            .received_requests()
            .await
            .expect("requests available");
        let post = requests
            .iter()
            .find(|r| r.method == wiremock::http::Method::POST)
            .expect("a POST was made");
        let body: serde_json::Value = serde_json::from_slice(&post.body).expect("valid JSON body");
        let data = body["data"].as_object().expect("data is a JSON object");

        // The old field must be retained.
        assert!(
            data.contains_key(far_future_field),
            "old field must be retained in the rotation write; got keys: {:?}",
            data.keys().collect::<Vec<_>>()
        );

        // There must be exactly one new field (besides the retained old one).
        let new_field = data
            .keys()
            .find(|k| k.as_str() != far_future_field)
            .expect("a new field must be present");

        // The new field's epoch-millis must be existing_max + 1.
        let parsed = parse_field_millis(new_field).unwrap_or_else(|| {
            panic!("new field {new_field:?} does not parse as a c4gh-<millis> name")
        });
        assert_eq!(
            parsed, expected_millis,
            "new field millis must be existing_max+1 ({expected_millis}) to beat the far-future clock; got {parsed}"
        );
    }

    /// When no existing field follows the `c4gh-<millis>` convention, `parse_field_millis`
    /// yields `None` for every key and `max()` returns `None`, so the code falls through to
    /// `now_millis()` and the new field is a well-formed `c4gh-<millis>` with millis >= 1.
    #[tokio::test]
    async fn new_field_falls_back_to_now_when_no_parseable_existing_field() {
        let server = MockServer::start().await;
        // A non-conventional field name, for which `parse_field_millis` returns `None`.
        let unparseable_field = "node";

        Mock::given(method("GET"))
            .and(path("/v1/secret/data/gdi-node-standalone/c4gh-identities"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "data": {
                        unparseable_field: "-----BEGIN CRYPT4GH PRIVATE KEY-----\nOLD\n-----END CRYPT4GH PRIVATE KEY-----"
                    },
                    "metadata": { "version": 1 }
                }
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/v1/secret/data/gdi-node-standalone/c4gh-identities"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "version": 2 }
            })))
            .expect(1)
            .mount(&server)
            .await;

        run(&cfg(&server.uri()), &AuditConfig::default())
            .await
            .expect("rotate must succeed when no parseable field exists");

        let requests = server
            .received_requests()
            .await
            .expect("requests available");
        let post = requests
            .iter()
            .find(|r| r.method == wiremock::http::Method::POST)
            .expect("a POST was made");
        let body: serde_json::Value = serde_json::from_slice(&post.body).expect("valid JSON body");
        let data = body["data"].as_object().expect("data is a JSON object");

        // The new field must be a valid `c4gh-<millis>` name with millis >= 1, since
        // `now_millis()` is the Unix epoch in milliseconds.
        let new_field = data
            .keys()
            .find(|k| k.as_str() != unparseable_field)
            .expect("a new field must be present alongside the retained unparseable one");
        let parsed = parse_field_millis(new_field).unwrap_or_else(|| {
            panic!("new field {new_field:?} does not parse as a c4gh-<millis> name")
        });
        assert!(
            parsed >= 1,
            "fallback new field millis must come from now_millis() (>= 1); got {parsed}"
        );
    }
}
