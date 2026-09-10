//! The `identity init` one-shot: mint the node's crypt4gh identity straight into
//! Vault (compiled only under the `vault` feature).
//!
//! This is an operator-run provisioning step, not part of the serve path. It generates a
//! fresh crypt4gh keypair in memory and writes the secret key to the KV path the service
//! reads its identity from (`[vault].kv_path`), under a field named `c4gh-<epoch-millis>`
//! (see `field_name`). Field names sort by recency, and [`crate::secrets`] treats the newest
//! as the published recipient. The secret is held in a `zeroize`-backed buffer and never
//! touches local disk; the transient PEM text and the Vault request body it is serialized
//! into are short-lived rather than separately wiped.
//!
//! It is create-only. A node identity is the one irreplaceable piece of state, since losing
//! or replacing it makes existing `.tar.c4gh` and PME data undecryptable, so this refuses to
//! overwrite an existing identity. The write uses KV v2 check-and-set (`cas = 0`), so a
//! concurrent second run cannot clobber the first. Adding a new key is the separate
//! [`crate::rotate_identity`] command, which adds a field beside the existing ones without
//! deleting them. Pass `--ensure` to make an already-provisioned path a success no-op for
//! idempotent re-runs, and `--from <pem>` to import an existing crypt4gh secret-key PEM
//! instead of minting a fresh keypair.
//!
//! Run it with a write-capable credential distinct from the serving token. The serving node
//! is read-only on KV (see [`crate::vault`]), so `create` on `[vault].kv_path` is not
//! granted to the running service. Prefer a one-shot provisioning credential over a
//! long-lived static token; in dev the root token covers both.
//!
//! The recipient (public key) is printed for the operator to publish and verify, and the
//! running node also serves it at `/.well-known/c4gh-recipient`.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, bail};

use gdi_node_standalone_core::config::{AuditConfig, VaultConfig};
use gdi_node_standalone_core::crypt4gh::{
    generate_keypair, parse_public_key, parse_secret_key, public_key_fingerprint,
    serialize_public_key, serialize_secret_key,
};
use zeroize::Zeroizing;

use crate::vault::{VaultClient, VaultError};

/// The KV field-name prefix for a node crypt4gh identity. Each identity is stored
/// under `c4gh-<epoch-millis>`; [`crate::secrets`] reads the fields newest-first and
/// treats the newest (greatest name) as the published recipient.
pub(crate) const FIELD_PREFIX: &str = "c4gh-";

/// Zero-pad width for the epoch-millis component, so lexicographic field-name order
/// equals chronological order. 16 digits stays fixed-width past the year 300000.
pub(crate) const FIELD_MILLIS_WIDTH: usize = 16;

/// Build the KV field name for an identity minted at `epoch_millis`:
/// `c4gh-` followed by the millis zero-padded to `FIELD_MILLIS_WIDTH` digits.
pub(crate) fn field_name(epoch_millis: u128) -> String {
    let width = FIELD_MILLIS_WIDTH;
    format!("{FIELD_PREFIX}{epoch_millis:0width$}")
}

/// Parse the epoch-millis component out of a `c4gh-<epoch-millis>` field name, or
/// `None` for a name that does not follow the convention.
pub(crate) fn parse_field_millis(field: &str) -> Option<u128> {
    field.strip_prefix(FIELD_PREFIX)?.parse().ok()
}

/// The published-recipient field among a KV identity map's field names: the `c4gh-<millis>`
/// field with the greatest parsed millis, matching the serving loader (`crate::secrets`).
/// Fields that do not follow the convention are ignored. Raw `BTreeMap` key order is not
/// used, because a `node…`-style field would lexicographically outrank every identity and be
/// mislabelled as the recipient. Returns `None` if no field follows the convention.
pub(crate) fn published_field<'a, I: IntoIterator<Item = &'a String>>(
    fields: I,
) -> Option<&'a str> {
    fields
        .into_iter()
        .filter_map(|f| Some((parse_field_millis(f)?, f.as_str())))
        .max_by_key(|&(millis, _)| millis)
        .map(|(_, field)| field)
}

/// The oldest identity field, the `c4gh-<millis>` field with the least parsed millis, which
/// is the rotation-retire target. Uses the same parsed-millis ordering as
/// [`published_field`]. Returns `None` if no field follows the convention.
pub(crate) fn oldest_field<'a, I: IntoIterator<Item = &'a String>>(fields: I) -> Option<&'a str> {
    fields
        .into_iter()
        .filter_map(|f| Some((parse_field_millis(f)?, f.as_str())))
        .min_by_key(|&(millis, _)| millis)
        .map(|(_, field)| field)
}

/// Wall-clock epoch milliseconds, the time component of a fresh field name. A clock before
/// the Unix epoch falls back to 0, so the write still succeeds, and `identity rotate`
/// independently guarantees a new field sorts after the existing ones.
pub(crate) fn now_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis())
}

/// Provision the node identity into Vault KV at `[vault].kv_path`, refusing if one already
/// exists. `ensure` turns "already provisioned" into a success no-op. With `from` set the
/// identity is imported from an existing crypt4gh secret-key PEM; otherwise a fresh keypair
/// is minted in memory, and if `data_dir` already holds published datasets that mint warns
/// on stderr, since it may be re-minting over data the previous identity encrypted.
///
/// # Errors
///
/// Returns an error, which `main` maps to a non-zero exit, when `kv_path` is unset, when
/// `from` is set but the file is unreadable or not a valid crypt4gh secret key, when Vault
/// is unreachable or the token is denied, when a secret already exists at the path and
/// `ensure` is false, or when the write is rejected.
pub async fn run(
    vault_cfg: &VaultConfig,
    audit_cfg: &AuditConfig,
    data_dir: &Path,
    ensure: bool,
    from: Option<&Path>,
) -> Result<()> {
    let Some(kv_path) = vault_cfg.kv_path.as_deref().filter(|p| !p.is_empty()) else {
        bail!(
            "identity init requires [vault].kv_path (the KV path the node reads its identity from)"
        );
    };

    let client = VaultClient::connect(vault_cfg)
        .await
        .map_err(|e| anyhow::anyhow!("connecting to Vault: {e}"))?;

    // Refuse to overwrite. Read first so the common "already provisioned" case gets a clear
    // message, or a clean no-op exit under `--ensure`. The write below still uses `cas=0`,
    // so a racing writer between this read and the write cannot slip past create-only.
    match client.kv_get(kv_path).await {
        Ok(map) if !map.is_empty() => {
            if ensure {
                println!(
                    "node crypt4gh identity already present at {}/{kv_path}; nothing to do (--ensure)",
                    vault_cfg.kv_mount()
                );
                return Ok(());
            }
            bail!(
                "a secret already exists at {}/{kv_path}; refusing to overwrite the node identity \
                 (add a new key with `identity rotate`, or pass --ensure to no-op)",
                vault_cfg.kv_mount()
            )
        }
        // A transient failure leaves it unknown whether an identity exists, and minting a
        // second one would be unsafe, so abort.
        Err(VaultError::Transient(e)) => {
            bail!("cannot reach Vault to check for an existing identity: {e}")
        }
        // No identity to clobber: the path is present but empty, or absent, since KV v2
        // returns a permanent 404 for a path never written. Both proceed to the write.
        Ok(_) | Err(VaultError::Permanent(_)) => {}
    }

    // Obtain the identity: import an existing PEM, or mint a fresh keypair. Either way the
    // secret lives in a zeroize-backed buffer. The mint path never touches local disk, and
    // the import path reads the operator's file once and validates that it parses.
    let (secret_pem, recipient_pem) = if let Some(path) = from {
        let pem = Zeroizing::new(
            std::fs::read_to_string(path)
                .with_context(|| format!("reading identity PEM from {}", path.display()))?,
        );
        let secret_key = parse_secret_key(&pem).map_err(|e| {
            anyhow::anyhow!("{} is not a valid crypt4gh secret key: {e}", path.display())
        })?;
        (pem, serialize_public_key(&secret_key.public_key()))
    } else {
        crate::init_identity_file::warn_if_datasets_predate_new_identity(data_dir);
        let (secret_key, public_key) = generate_keypair();
        (
            Zeroizing::new(serialize_secret_key(&secret_key)),
            serialize_public_key(&public_key),
        )
    };

    let field = field_name(now_millis());
    let mut data = BTreeMap::new();
    data.insert(field.clone(), secret_pem.to_string());

    client
        .kv_put_create(kv_path, &data)
        .await
        .map_err(|e| match e {
            VaultError::Permanent(msg) => anyhow::anyhow!(
                "writing the node identity failed; it may have been created concurrently: {msg}"
            ),
            VaultError::Transient(msg) => {
                anyhow::anyhow!("writing the node identity failed: {msg}")
            }
        })?;

    // Key-lifecycle audit trail: the node's first identity now exists, minted or imported,
    // recorded by field name only and never by key material.
    crate::audit::identity_initialized(audit_cfg, &field, from.is_some());

    // The recipient is public, so print it for the operator to publish and verify.
    if let Some(path) = from {
        println!(
            "imported node crypt4gh identity from {} into Vault at {}/{kv_path} (field `{field}`)",
            path.display(),
            vault_cfg.kv_mount()
        );
    } else {
        println!(
            "minted node crypt4gh identity into Vault at {}/{kv_path} (field `{field}`)",
            vault_cfg.kv_mount()
        );
    }
    println!("node recipient:");
    print!("{recipient_pem}");
    if let Ok(pk) = parse_public_key(&recipient_pem) {
        println!("recipient fingerprint: {}", public_key_fingerprint(&pk));
    }
    // The one irreplaceable node secret now exists only in Vault. The advisory goes to
    // stderr so it cannot corrupt a captured recipient PEM on stdout.
    eprintln!(
        "next: run `identity backup --recipient <operator.pub> --out <file>` to make a \
         disaster-recovery copy of this identity. It is the one irreplaceable node secret."
    );
    Ok(())
}

#[cfg(test)]
mod tests {

    use serde_json::json;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    #[test]
    fn published_and_oldest_fields_order_by_parsed_millis_ignoring_non_c4gh() {
        // `node-legacy` sorts lexically after `c4gh-` and would hijack the recipient slot
        // under raw key order. The parsed-millis selection ignores it and picks `c4gh-2` as
        // published and `c4gh-1` as oldest, matching the loader.
        let fields: Vec<String> = [
            "c4gh-0000000000000001",
            "c4gh-0000000000000002",
            "node-legacy",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        assert_eq!(
            published_field(fields.iter()),
            Some("c4gh-0000000000000002")
        );
        assert_eq!(oldest_field(fields.iter()), Some("c4gh-0000000000000001"));
        // A map of only non-conforming fields has neither.
        let only_legacy = ["node-legacy".to_owned()];
        assert_eq!(published_field(only_legacy.iter()), None);
        assert_eq!(oldest_field(only_legacy.iter()), None);
    }

    /// A static-token vault config pointing at `address`.
    fn cfg(address: &str) -> VaultConfig {
        VaultConfig {
            address: address.to_owned(),
            token: Some("hvs.test-token".to_owned()),
            kv_path: Some("gdi-node-standalone/c4gh-identities".to_owned()),
            ..VaultConfig::default()
        }
    }

    #[tokio::test]
    async fn mints_identity_when_absent() {
        let server = MockServer::start().await;
        // Existence check: the path is absent (404).
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/gdi-node-standalone/c4gh-identities"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({ "errors": [] })))
            .mount(&server)
            .await;
        // Create-only write: must carry cas=0; succeeds.
        Mock::given(method("POST"))
            .and(path("/v1/secret/data/gdi-node-standalone/c4gh-identities"))
            .and(body_partial_json(json!({ "options": { "cas": 0 } })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "version": 1 }
            })))
            .expect(1)
            .mount(&server)
            .await;

        run(
            &cfg(&server.uri()),
            &AuditConfig::default(),
            Path::new(""),
            false,
            None,
        )
        .await
        .expect("mint identity");

        // Assert the write body carries the generated secret key in `data`.
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
        // Exactly one field, named `c4gh-<16-digit-millis>`.
        assert_eq!(
            data.len(),
            1,
            "data must contain exactly one field; got: {:?}",
            data.keys().collect::<Vec<_>>()
        );
        let (field_name_str, field_value) = data.iter().next().expect("one field present");
        // Validate the field name matches `c4gh-<FIELD_MILLIS_WIDTH digits>`.
        let parsed_millis = parse_field_millis(field_name_str);
        assert!(
            parsed_millis.is_some(),
            "field name must match c4gh-<{FIELD_MILLIS_WIDTH} digit millis>; got {field_name_str:?}"
        );
        let suffix = field_name_str
            .strip_prefix(FIELD_PREFIX)
            .expect("field name starts with FIELD_PREFIX");
        assert_eq!(
            suffix.len(),
            FIELD_MILLIS_WIDTH,
            "field name millis component must be exactly {FIELD_MILLIS_WIDTH} digits wide; got {field_name_str:?}"
        );
        let pem_text = field_value.as_str().expect("field value must be a string");
        assert!(
            pem_text.starts_with("-----BEGIN CRYPT4GH PRIVATE KEY-----"),
            "field value must start with crypt4gh PEM header; got {pem_text:?}"
        );
    }

    #[tokio::test]
    async fn imports_pem_when_from_given() {
        let server = MockServer::start().await;
        // Absent path (404), then a create-only write of the imported key succeeds.
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/gdi-node-standalone/c4gh-identities"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({ "errors": [] })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/secret/data/gdi-node-standalone/c4gh-identities"))
            .and(body_partial_json(json!({ "options": { "cas": 0 } })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "data": { "version": 1 } })),
            )
            .expect(1)
            .mount(&server)
            .await;

        // A valid crypt4gh secret-key PEM in a temp file is imported as-is.
        let (sk, _pk) = generate_keypair();
        let pem = serialize_secret_key(&sk);
        let file = tempfile::NamedTempFile::new().expect("temp file");
        std::fs::write(file.path(), pem.as_bytes()).expect("write pem");

        run(
            &cfg(&server.uri()),
            &AuditConfig::default(),
            Path::new(""),
            false,
            Some(file.path()),
        )
        .await
        .expect("import identity");

        // Assert the write body's `data` value byte-equals the imported PEM (BYOK).
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
        assert_eq!(
            data.len(),
            1,
            "data must contain exactly one field; got: {:?}",
            data.keys().collect::<Vec<_>>()
        );
        let stored_pem = data
            .values()
            .next()
            .and_then(|v| v.as_str())
            .expect("field value must be a string");
        assert_eq!(
            stored_pem, pem,
            "stored PEM must byte-equal the imported PEM (verbatim BYOK)"
        );
    }

    #[tokio::test]
    async fn from_invalid_pem_errors() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/gdi-node-standalone/c4gh-identities"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({ "errors": [] })))
            .mount(&server)
            .await;

        let file = tempfile::NamedTempFile::new().expect("temp file");
        std::fs::write(file.path(), b"not a crypt4gh key").expect("write garbage");

        let err = run(
            &cfg(&server.uri()),
            &AuditConfig::default(),
            Path::new(""),
            false,
            Some(file.path()),
        )
        .await
        .expect_err("invalid pem should error");
        assert!(
            err.to_string().contains("not a valid crypt4gh secret key"),
            "got {err}"
        );
    }

    #[tokio::test]
    async fn refuses_when_identity_present() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/gdi-node-standalone/c4gh-identities"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "data": { "c4gh-0000000000000001": "-----BEGIN CRYPT4GH PRIVATE KEY-----\nAAAA\n-----END CRYPT4GH PRIVATE KEY-----" },
                    "metadata": { "version": 1 }
                }
            })))
            .mount(&server)
            .await;

        let err = run(
            &cfg(&server.uri()),
            &AuditConfig::default(),
            Path::new(""),
            false,
            None,
        )
        .await
        .expect_err("should refuse to overwrite");
        assert!(
            err.to_string().contains("already exists"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn ensure_noops_when_identity_present() {
        let server = MockServer::start().await;
        // A present identity. With `--ensure` this is a clean no-op and no write is issued;
        // no POST mock is mounted, so a stray write would 404 and fail the run.
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/gdi-node-standalone/c4gh-identities"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "data": { "c4gh-0000000000000001": "-----BEGIN CRYPT4GH PRIVATE KEY-----\nAAAA\n-----END CRYPT4GH PRIVATE KEY-----" },
                    "metadata": { "version": 1 }
                }
            })))
            .mount(&server)
            .await;

        run(
            &cfg(&server.uri()),
            &AuditConfig::default(),
            Path::new(""),
            true,
            None,
        )
        .await
        .expect("--ensure should no-op when an identity already exists");
    }

    #[tokio::test]
    async fn aborts_when_vault_unreachable() {
        // Point at a dead port so VaultClient::connect yields a transient error.
        // No GET mock is mounted; there is no server at all, so the connection fails.
        let err = run(
            &cfg("http://127.0.0.1:1"),
            &AuditConfig::default(),
            Path::new(""),
            false,
            None,
        )
        .await
        .expect_err("unreachable vault should error");
        // A `connect()` failure maps to "connecting to Vault: …", so the message names
        // Vault and an operator can see which component failed.
        let msg = err.to_string();
        assert!(
            msg.contains("Vault") || msg.contains("vault"),
            "error must name the unreachable Vault; got: {msg}"
        );
        // The message must also name a connection problem, not an unrelated parse error.
        assert!(
            msg.contains("connecting") || msg.contains("reach") || msg.contains("connect"),
            "error must describe a connection failure; got: {msg}"
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
        let err = run(
            &vault_cfg,
            &AuditConfig::default(),
            Path::new(""),
            false,
            None,
        )
        .await
        .expect_err("missing kv_path");
        assert!(err.to_string().contains("kv_path"), "got {err}");
    }

    #[test]
    fn field_names_are_fixed_width_sortable_and_parse() {
        // A fixed width makes lexicographic order equal chronological order.
        let a = field_name(1);
        let b = field_name(2);
        let c = field_name(1_780_000_000_000);
        assert_eq!(a, "c4gh-0000000000000001");
        assert!(a < b, "{a} should sort before {b}");
        assert!(b < c, "{b} should sort before {c}");
        assert_eq!(a.len(), b.len(), "field names must be fixed width");
        assert_eq!(a.len(), c.len(), "field names must be fixed width");
        // Round-trip the millis back out.
        assert_eq!(parse_field_millis(&c), Some(1_780_000_000_000));
        assert_eq!(parse_field_millis("node"), None);
        assert_eq!(parse_field_millis("c4gh-notanumber"), None);
    }
}
