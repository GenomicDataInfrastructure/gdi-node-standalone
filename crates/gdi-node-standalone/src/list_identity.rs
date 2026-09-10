//! The `identity list` one-shot: read-only inspection of the node's crypt4gh identity state
//! in Vault KV (compiled only under the `vault` feature).
//!
//! It prints, per stored field, its name, its role (published recipient or decrypt-only),
//! its age (derived from the `c4gh-<epoch-millis>` field name), and a non-secret SHA-256
//! fingerprint of the public key. Secret key material is never printed, so the command is
//! safe to run with the read-only serving token. The rest of the lifecycle is mint
//! ([`crate::init_identity`]), add ([`crate::rotate_identity`]), remove
//! ([`crate::retire_identity`]) and disaster recovery ([`crate::identity_backup`]).
//! Vault-profile only (see [`crate::vault`]).

use anyhow::{Result, bail};

use gdi_node_standalone_core::config::{AuditConfig, VaultConfig};
use gdi_node_standalone_core::crypt4gh::{parse_secret_key, public_key_fingerprint};

use crate::init_identity::{now_millis, parse_field_millis, published_field};
use crate::vault::{VaultClient, VaultError};

/// Print the current node identity state at `[vault].kv_path`: field names, count, age and a
/// non-secret public-key fingerprint, without revealing key material.
///
/// # Errors
///
/// Returns an error (mapped to a non-zero exit by `main`) when: `kv_path` is unset;
/// Vault is unreachable / the token is denied; or no identity exists at the path.
pub async fn run(vault_cfg: &VaultConfig, audit_cfg: &AuditConfig) -> Result<()> {
    let Some(kv_path) = vault_cfg.kv_path.as_deref().filter(|p| !p.is_empty()) else {
        // Only reachable with `[vault]` present but `kv_path` unset: a config without
        // `[vault]` at all is routed to the file-backed lister before reaching here.
        bail!(
            "identity list: [vault] is configured but [vault].kv_path is unset, so there is \
             no KV path to read the identity from. Set kv_path, or, if this node is \
             actually file-backed, remove the [vault] section and this command will list \
             the [keys].identities files instead (see docs/operating.md section 9)."
        );
    };

    let client = VaultClient::connect(vault_cfg)
        .await
        .map_err(|e| anyhow::anyhow!("connecting to Vault: {e}"))?;

    let map = match client.kv_get(kv_path).await {
        Ok(m) if !m.is_empty() => m,
        Ok(_) | Err(VaultError::Permanent(_)) => bail!(
            "no node identity at {}/{kv_path}; run `identity init` first",
            vault_cfg.kv_mount()
        ),
        Err(VaultError::Transient(e)) => {
            bail!("cannot reach Vault to read the current identity: {e}")
        }
    };

    print!(
        "{}",
        render_listing(vault_cfg.kv_mount(), kv_path, &map, now_millis())
    );
    // Audit the inventory read (which fields exist, which is published) so the identity
    // plane's audit trail is not mutation-only.
    crate::audit::identity_listed(audit_cfg, map.len());
    Ok(())
}

/// The exact text `identity list` emits, as a string.
///
/// Split out of [`run`] so a test can assert on the emitted text and hold the
/// no-secret-material guarantee, mirroring the `run` / `run_rendered` split in
/// [`crate::list_datasets`].
///
/// `now` is a parameter rather than a `now_millis()` call so the rendered ages are
/// deterministic.
fn render_listing(
    mount: &str,
    kv_path: &str,
    map: &crate::vault::ZeroizingIdentityMap,
    now: u128,
) -> String {
    use std::fmt::Write as _;

    // The published recipient is the `c4gh-<millis>` field with the greatest parsed millis,
    // matching what `crate::secrets` serves. Raw `BTreeMap` key order would mislabel a
    // non-`c4gh-` field as the recipient. A map of only non-conforming fields has none.
    let published = published_field(map.keys());
    let mut out = format!(
        "node crypt4gh identity at {mount}/{kv_path}: {} field(s)\n",
        map.len()
    );
    for (field, pem) in map.iter() {
        let role = if Some(field.as_str()) == published {
            "published recipient"
        } else {
            "decrypt-only"
        };
        let age = match parse_field_millis(field) {
            Some(millis) => format!("{}d", now.saturating_sub(millis) / 86_400_000),
            None => "age unknown".to_owned(),
        };
        let fingerprint =
            fingerprint_of_secret_pem(pem).unwrap_or_else(|| "fingerprint unavailable".to_owned());
        // `write!` to a String is infallible, so the `Result` is discarded.
        let _ = writeln!(out, "  {field}  [{role}]  age {age}  {fingerprint}");
    }
    out
}

/// SHA-256 fingerprint of the public key derived from a stored crypt4gh secret-key PEM,
/// rendered `sha256:<hex>` (via [`public_key_fingerprint`]). Returns `None` when the PEM
/// does not parse; the secret material is never printed either way.
fn fingerprint_of_secret_pem(pem: &str) -> Option<String> {
    Some(public_key_fingerprint(
        &parse_secret_key(pem).ok()?.public_key(),
    ))
}

#[cfg(test)]
mod tests {

    use serde_json::json;
    use wiremock::matchers::{method, path};
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

    /// A real crypt4gh secret-key PEM (so `parse_secret_key` succeeds and a real
    /// fingerprint is produced).
    fn real_pem() -> String {
        let (sk, _pk) = gdi_node_standalone_core::crypt4gh::generate_keypair();
        gdi_node_standalone_core::crypt4gh::serialize_secret_key(&sk)
    }

    #[tokio::test]
    async fn lists_fields_without_dumping_secrets() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/gdi-node-standalone/c4gh-identities"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "data": {
                        "c4gh-0000000000000001": real_pem(),
                        "c4gh-0000000000000002": real_pem()
                    },
                    "metadata": { "version": 3 }
                }
            })))
            .mount(&server)
            .await;
        // No POST mock: any write would 404 and fail, which proves this is read-only.
        run(&cfg(&server.uri()), &AuditConfig::default())
            .await
            .expect("identity list reads the identity state");

        // Assert on the text the command emits, not on a PEM fingerprinted here: only the
        // emitted text can show that no secret material reaches the output.
        let pem = real_pem();
        let map = crate::vault::ZeroizingIdentityMap(std::collections::BTreeMap::from([
            ("c4gh-0000000000000001".to_owned(), pem.clone()),
            ("c4gh-0000000000000002".to_owned(), pem.clone()),
        ]));
        let rendered = render_listing("secret", "gdi-node-standalone/c4gh-identities", &map, 0);

        // No secret material reaches the output.
        assert!(
            !rendered.contains("PRIVATE KEY"),
            "listing must not print PEM key material:\n{rendered}"
        );
        for line in pem
            .lines()
            .filter(|l| !l.starts_with("-----") && !l.is_empty())
        {
            assert!(
                !rendered.contains(line),
                "listing leaked a PEM body line:\n{rendered}"
            );
        }
        // ...and it does print the non-secret substitute, per field.
        assert_eq!(
            rendered.matches("sha256:").count(),
            2,
            "one public-key fingerprint per stored field:\n{rendered}"
        );
        assert!(
            rendered.contains("[published recipient]") && rendered.contains("[decrypt-only]"),
            "roles rendered:\n{rendered}"
        );
    }

    #[tokio::test]
    async fn errors_when_no_identity() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/gdi-node-standalone/c4gh-identities"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({ "errors": [] })))
            .mount(&server)
            .await;
        let err = run(&cfg(&server.uri()), &AuditConfig::default())
            .await
            .expect_err("absent identity must error");
        assert!(
            err.to_string().contains("no node identity"),
            "explains the absence: {err}"
        );
    }

    #[tokio::test]
    async fn errors_without_kv_path() {
        let vault_cfg = VaultConfig {
            address: "http://127.0.0.1:0".to_owned(),
            token: Some("hvs.test".to_owned()),
            kv_path: None,
            ..VaultConfig::default()
        };
        let err = run(&vault_cfg, &AuditConfig::default())
            .await
            .expect_err("missing kv_path must error");
        assert!(err.to_string().contains("kv_path"), "names kv_path: {err}");
    }

    #[test]
    fn fingerprint_of_invalid_pem_is_none() {
        assert!(fingerprint_of_secret_pem("not a pem").is_none());
    }
}
