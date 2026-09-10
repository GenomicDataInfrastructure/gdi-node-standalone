//! Secret-source precedence: Vault over inline config (compiled only under the
//! `vault` feature).
//!
//! When `[vault]` is configured, Vault is the source for every secret the service
//! consumes, and the inline `[keys]` / `[[s3.buckets]]` values become the no-Vault
//! fallback:
//!
//! * the node's crypt4gh identities come from the KV secret at `[vault].kv_path`
//!   (one PEM per field, named `c4gh-<epoch-millis>`; the newest is the published
//!   recipient, the rest decrypt-only), overriding `[keys].identities`;
//! * each bucket's S3 access/secret keys come from the KV secret at
//!   `[vault].s3_path`, keyed by the bucket `name`, overriding the inline
//!   `[[s3.buckets]].access_key_id` / `secret_access_key`.
//!
//! Vault being unreachable or the token lapsed at load is transient
//! ([`VaultError::Transient`]): the node stays up, ingest retries and readiness
//! reports Vault as `unavailable`. A permanent fault, such as a malformed secret or
//! an absent required path, is surfaced so the operator fixes the config.
//!
//! Without a `[vault]` block, identities load from `[keys]` files and S3 credentials
//! stay inline.

use std::collections::BTreeMap;

use gdi_node_standalone_core::config::{S3Bucket, ServiceConfig};
use tracing::{info, warn};

use crate::identities::NodeIdentities;
use crate::vault::{VaultClient, VaultError, VaultResult};

/// The KV-secret key suffix for a bucket's access-key id, joined to the bucket
/// `name` (e.g. `primary_access_key_id`).
const S3_ACCESS_KEY_SUFFIX: &str = "_access_key_id";
/// The KV-secret key suffix for a bucket's secret access key.
const S3_SECRET_KEY_SUFFIX: &str = "_secret_access_key";

/// The resolved secret sources for the service: the loaded crypt4gh identities and
/// the optional Vault client (kept for the per-bucket S3-cred override and, under
/// PME, the Transit key retriever).
pub struct ResolvedSecrets {
    /// The node's crypt4gh identities (Vault-backed when configured, else
    /// `[keys]` files).
    pub identities: NodeIdentities,
    /// The connected Vault client when `[vault]` is configured (else `None`).
    pub vault: Option<VaultClient>,
    /// Per-bucket S3 credential overrides from Vault (`name -> (access, secret)`),
    /// applied over the inline `[[s3.buckets]]` values. Empty when no Vault or no
    /// `s3_path` is configured.
    pub s3_overrides: BTreeMap<String, (String, String)>,
}

/// Resolve the service's secrets with Vault precedence.
///
/// With `[vault]` present this connects the Vault client, loads the identities from
/// `kv_path`, and reads the per-bucket S3 overrides when `s3_path` is set and S3
/// buckets exist. Otherwise it falls back to `[keys]` files and leaves the S3
/// overrides empty.
///
/// # Errors
///
/// [`VaultError::Transient`] when the server is unreachable or the token lapsed; the
/// caller retries and the node still serves already-ingested datasets.
/// [`VaultError::Permanent`] on a malformed or absent secret, and for a `[keys]`-file
/// load error, which is a local config fault rather than a retryable one.
pub async fn resolve(config: &ServiceConfig) -> VaultResult<ResolvedSecrets> {
    let Some(vault_cfg) = config.vault.as_ref() else {
        // No-Vault path: identities from [keys] files, no S3 overrides.
        let identities = NodeIdentities::load(config)
            .map_err(|e| VaultError::Permanent(format!("loading [keys] identities: {e}")))?;
        return Ok(ResolvedSecrets {
            identities,
            vault: None,
            s3_overrides: BTreeMap::new(),
        });
    };

    info!(address = %vault_cfg.address, "connecting to Vault for secrets; Vault takes precedence over inline config");
    let client = VaultClient::connect(vault_cfg).await?;

    // Identities from kv_path (required; the preflight enforces kv_path presence).
    let identities = match vault_cfg.kv_path.as_deref() {
        Some(path) if !path.is_empty() => {
            // `kv_get` returns a self-wiping `ZeroizingIdentityMap`, so the raw
            // secret-key PEMs cannot linger in freed heap after this scope, however it
            // exits.
            let secret = client.kv_get(path).await?;
            identities_from_kv(&secret)?
        }
        _ => {
            return Err(VaultError::Permanent(
                "vault is configured without kv_path; cannot load the node identity".to_owned(),
            ));
        }
    };

    // Per-bucket S3 overrides from s3_path (optional).
    let s3_overrides = load_s3_overrides(&client, vault_cfg, config).await?;

    Ok(ResolvedSecrets {
        identities,
        vault: Some(client),
        s3_overrides,
    })
}

/// Read the per-bucket S3 credential overrides from `[vault].s3_path`, keyed by bucket
/// name, using an already-connected client. Empty when `s3_path` is unset or empty, or
/// when no buckets are configured.
///
/// Shared by boot ([`resolve`]), the openability scan in [`crate::retire_identity`] and
/// the SIGHUP / `POST /reload` config reload. The reload re-reads it so a bucket it adds
/// gets the credential Vault holds for it, and the retire scan reaches a Vault-backed
/// bucket with the same credentials serve-time uses rather than the inline placeholder.
///
/// # Errors
///
/// Propagates a [`VaultError`] from the KV read.
pub async fn load_s3_overrides(
    client: &VaultClient,
    vault_cfg: &gdi_node_standalone_core::config::VaultConfig,
    config: &ServiceConfig,
) -> VaultResult<BTreeMap<String, (String, String)>> {
    match vault_cfg.s3_path.as_deref() {
        Some(path) if !path.is_empty() && config.has_s3_buckets() => {
            // The fetch buffer wipes itself; the returned map keeps its own copies for
            // the process lifetime.
            let secret = client.kv_get(path).await?;
            Ok(s3_overrides_from_kv(&secret, s3_buckets(config)))
        }
        _ => Ok(BTreeMap::new()),
    }
}

/// Parse the KV identity secret into [`NodeIdentities`], newest first: field names follow
/// the `c4gh-<epoch-millis>` convention (see [`crate::init_identity`]), and
/// [`NodeIdentities`] treats the first entry as the published recipient with the rest as
/// decrypt-only fallbacks retained across a rotation's re-key window.
///
/// Ordering is by parsed millis, greatest first, not by raw `BTreeMap` key order: under
/// raw order a non-`c4gh-` field sorting after `c4gh-` would outrank every identity and
/// hijack the recipient slot. Fields that do not match `c4gh-<millis>` are kept as
/// decrypt-only fallbacks after the identities, so no key material is lost, but they are
/// never the published recipient. A secret with fields but no conforming identity fails
/// closed rather than promote a fallback.
fn identities_from_kv(secret: &BTreeMap<String, String>) -> VaultResult<NodeIdentities> {
    // Share `parse_field_millis` with the writer (init_identity mints, rotates and lists
    // these fields) so the two cannot drift over the prefix or the millis encoding.
    let mut identities: Vec<(u128, &str)> = Vec::new();
    let mut fallbacks: Vec<&str> = Vec::new();
    for (field, pem) in secret {
        if let Some(millis) = crate::init_identity::parse_field_millis(field) {
            identities.push((millis, pem.as_str()));
        } else {
            warn!(
                field = %field,
                "vault identity field is not `c4gh-<millis>`; kept as a decrypt-only \
                 fallback, never the published recipient"
            );
            fallbacks.push(pem.as_str());
        }
    }
    // Fail closed when the secret has fields but none is a conforming `c4gh-<millis>`
    // identity: otherwise `pems[0]` is a fallback promoted to the published recipient. An
    // entirely empty secret stays the valid keyless case.
    if identities.is_empty() && !fallbacks.is_empty() {
        return Err(VaultError::Permanent(format!(
            "vault identity secret has {} field(s) but none is a `c4gh-<millis>` identity; \
             refusing to promote a non-identity fallback to the published recipient",
            fallbacks.len()
        )));
    }
    // Newest (greatest millis) first; ties broken by PEM for a deterministic order.
    identities.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(b.1)));
    let pems: Vec<&str> = identities
        .into_iter()
        .map(|(_, pem)| pem)
        .chain(fallbacks)
        .collect();
    if pems.is_empty() {
        warn!(
            alert = true,
            event.action = "vault.secret.load",
            event.outcome = "failure",
            "vault identity secret is empty; node will be keyless"
        );
    }
    NodeIdentities::from_pems(pems)
        .map_err(|e| VaultError::Permanent(format!("parsing Vault crypt4gh identities: {e}")))
}

/// Build the per-bucket S3 override map from the KV S3-credentials secret.
///
/// For each configured bucket `name`, looks up `{name}_access_key_id` +
/// `{name}_secret_access_key`. A bucket present in the secret with both keys gets an
/// override; a bucket with only one of the pair keeps its inline value and logs a
/// warning, so a half-populated secret is visible; a bucket entirely absent from the
/// secret keeps its inline value silently.
fn s3_overrides_from_kv<'a, I>(
    secret: &BTreeMap<String, String>,
    buckets: I,
) -> BTreeMap<String, (String, String)>
where
    I: IntoIterator<Item = &'a S3Bucket>,
{
    let mut out = BTreeMap::new();
    for bucket in buckets {
        let access = secret.get(&format!("{}{S3_ACCESS_KEY_SUFFIX}", bucket.name));
        let key = secret.get(&format!("{}{S3_SECRET_KEY_SUFFIX}", bucket.name));
        match (access, key) {
            (Some(a), Some(s)) => {
                out.insert(bucket.name.clone(), (a.clone(), s.clone()));
            }
            (None, None) => {
                // No Vault creds for this bucket: keep the inline fallback silently.
            }
            _ => {
                warn!(
                    channel = %bucket.name,
                    "vault s3 secret has only one of {{name}}_access_key_id / {{name}}_secret_access_key; keeping inline creds for this bucket"
                );
            }
        }
    }
    out
}

/// The configured S3 buckets (empty slice when no `[s3]` block).
fn s3_buckets(config: &ServiceConfig) -> &[S3Bucket] {
    config.s3.as_ref().map_or(&[], |s3| s3.buckets.as_slice())
}

/// Apply the Vault S3 overrides to a bucket's inline creds, returning a bucket
/// whose `access_key_id` / `secret_access_key` are the Vault values when present.
///
/// Used by the S3 monitor wiring so [`crate::s3::build_object_store`] sees the
/// Vault-backed credentials (Vault takes precedence over the inline values).
#[must_use]
pub fn apply_s3_override(
    bucket: &S3Bucket,
    overrides: &BTreeMap<String, (String, String)>,
) -> S3Bucket {
    let mut bucket = bucket.clone();
    if let Some((access, secret)) = overrides.get(&bucket.name) {
        bucket.access_key_id = Some(access.clone());
        bucket.secret_access_key = Some(secret.clone());
    }
    bucket
}

#[cfg(test)]
mod tests {

    use super::*;
    use gdi_node_standalone_core::config::S3Config;

    /// A fresh, unencrypted crypt4gh secret-key PEM (round-trips through the codec).
    fn fresh_identity_pem() -> String {
        let (sk, _pk) = gdi_node_standalone_core::crypt4gh::generate_keypair();
        gdi_node_standalone_core::crypt4gh::serialize_secret_key(&sk)
    }

    fn bucket(name: &str) -> S3Bucket {
        S3Bucket {
            name: name.to_owned(),
            access_key_id: Some("inline-access".to_owned()),
            secret_access_key: Some("inline-secret".to_owned()),
            ..S3Bucket::default()
        }
    }

    #[test]
    fn identities_from_kv_selects_newest_as_recipient() {
        let pem_old = fresh_identity_pem();
        let pem_new = fresh_identity_pem();
        let mut secret = BTreeMap::new();
        // `c4gh-<epoch-millis>` field names: the greater (newer) is the recipient, the
        // rest are decrypt-only fallbacks. Insertion order is irrelevant.
        secret.insert("c4gh-0000000000000001".to_owned(), pem_old);
        secret.insert("c4gh-0000000000000002".to_owned(), pem_new.clone());
        let ids = identities_from_kv(&secret).expect("parse identities");
        assert!(ids.is_enabled());
        // The recipient derives from the newest entry.
        let expected = {
            let sk = gdi_node_standalone_core::crypt4gh::parse_secret_key(&pem_new)
                .expect("parse pem_new");
            gdi_node_standalone_core::crypt4gh::serialize_public_key(&sk.public_key())
        };
        assert_eq!(ids.recipient_pem(), Some(expected));
    }

    #[test]
    fn identities_from_kv_empty_is_keyless() {
        let ids = identities_from_kv(&BTreeMap::new()).expect("empty ok");
        assert!(!ids.is_enabled());
    }

    #[test]
    fn identities_from_kv_bad_pem_is_permanent() {
        let mut secret = BTreeMap::new();
        secret.insert("k".to_owned(), "not a pem".to_owned());
        // `NodeIdentities` holds no Debug (key material), so match the err side.
        match identities_from_kv(&secret) {
            Ok(_) => panic!("bad pem should not parse"),
            Err(e) => std::assert_matches!(e, VaultError::Permanent(_), "got {e:?}"),
        }
    }

    #[test]
    fn identities_from_kv_all_fallback_fails_closed() {
        // A secret with fields but no conforming `c4gh-<millis>` identity must fail closed
        // rather than promote the first fallback to published recipient. The fallback PEM
        // here is valid, so this exercises the promotion path, not a parse error.
        let mut secret = BTreeMap::new();
        secret.insert("legacy-node".to_owned(), fresh_identity_pem());
        match identities_from_kv(&secret) {
            Ok(_) => panic!("an all-fallback secret must not promote a published recipient"),
            Err(VaultError::Permanent(msg)) => {
                assert!(msg.contains("none is a"), "got: {msg}");
            }
            Err(e) => panic!("expected Permanent, got {e:?}"),
        }
    }

    #[test]
    fn s3_overrides_keyed_by_bucket_name() {
        let mut secret = BTreeMap::new();
        secret.insert(
            "primary_access_key_id".to_owned(),
            "vault-access".to_owned(),
        );
        secret.insert(
            "primary_secret_access_key".to_owned(),
            "vault-secret".to_owned(),
        );
        // A second bucket has no Vault creds (keeps inline).
        let buckets = [bucket("primary"), bucket("secondary")];
        let overrides = s3_overrides_from_kv(&secret, &buckets);
        assert_eq!(overrides.len(), 1);
        assert_eq!(
            overrides["primary"],
            ("vault-access".to_owned(), "vault-secret".to_owned())
        );
        assert!(!overrides.contains_key("secondary"));
    }

    #[test]
    fn apply_s3_override_replaces_inline_creds() {
        let mut overrides = BTreeMap::new();
        overrides.insert(
            "primary".to_owned(),
            ("vault-access".to_owned(), "vault-secret".to_owned()),
        );
        let resolved = apply_s3_override(&bucket("primary"), &overrides);
        assert_eq!(resolved.access_key_id.as_deref(), Some("vault-access"));
        assert_eq!(resolved.secret_access_key.as_deref(), Some("vault-secret"));

        // A bucket not in the overrides keeps its inline creds.
        let untouched = apply_s3_override(&bucket("other"), &overrides);
        assert_eq!(untouched.access_key_id.as_deref(), Some("inline-access"));
        assert_eq!(
            untouched.secret_access_key.as_deref(),
            Some("inline-secret")
        );
    }

    #[test]
    fn s3_buckets_empty_without_section() {
        let cfg = ServiceConfig::default();
        assert!(s3_buckets(&cfg).is_empty());
        let cfg = ServiceConfig {
            s3: Some(S3Config {
                buckets: vec![bucket("primary")],
            }),
            ..ServiceConfig::default()
        };
        assert_eq!(s3_buckets(&cfg).len(), 1);
    }
}
