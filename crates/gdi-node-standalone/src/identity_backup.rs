//! `identity backup` / `identity restore`: export the node crypt4gh identity from
//! Vault KV encrypted to an operator's crypt4gh recipient, and restore it onto a
//! fresh node. Compiled only under the `vault` feature.
//!
//! The node identity is the one irreplaceable secret: lose it and every inbound
//! `.tar.c4gh`, plus all PME-at-rest parquet, becomes permanently undecryptable.
//! `identity init` and `identity rotate` write it into Vault, and this pair gets it
//! back out for safekeeping:
//!
//! * `identity backup --recipient <operator.pub> --out <file>` reads the whole KV
//!   map at `[vault].kv_path` (every `c4gh-*` field, including rotated keys),
//!   serializes it, and crypt4gh-encrypts the blob to one or more operator public
//!   keys. `--recipient` may be **repeated**: the blob then carries a header packet
//!   per recipient and **any one** of those operator secrets can restore it — so a
//!   single lost operator key does not lose the backup. The recipients are
//!   offline-held, so the blob is useless without an operator secret.
//! * `identity restore --in <file> --identity <operator.sec>` decrypts the blob
//!   with the operator secret and writes the fields back **create-only** (KV v2
//!   `cas=0` via [`crate::vault::VaultClient::kv_put_create`]), so a restore can
//!   never clobber a live identity. Pass `--dry-run` to **verify** a backup instead
//!   of writing it ([`verify_backup`]): it decrypts + parses the blob and checks
//!   every field is a valid crypt4gh secret key, touching neither Vault nor the
//!   live identity — so an operator can confirm a backup is restorable before it is
//!   ever needed.
//!
//! The Vault **Transit** master key (PME) is not covered: Transit keys are
//! non-exportable, and their recovery is the Vault operator's responsibility through
//! cluster snapshots or HA. Making the key exportable just to back it up would weaken
//! the at-rest guarantee.

use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::Path;

use anyhow::{Context, Result, bail};
use gdi_node_standalone_core::config::{AuditConfig, VaultConfig};
use gdi_node_standalone_core::crypt4gh::{
    decrypt, encrypt, generate_keypair, parse_public_key, parse_secret_key, public_key_fingerprint,
};
use zeroize::Zeroizing;

use crate::vault::{VaultClient, VaultError, ZeroizingIdentityMap};

/// Back up the node identity at `[vault].kv_path`, crypt4gh-encrypted to the
/// operator recipient PEM(s) at `recipient_paths`, written to `out_path`.
///
/// At least one recipient is required; passing several embeds one header packet per
/// recipient, so **any one** of those operator secrets can restore the blob (the
/// redundancy guard against a single lost operator key — there is no threshold /
/// quorum, it is plain OR-decryption).
///
/// # Errors
///
/// Returns an error when `recipient_paths` is empty, `kv_path` is unset, a recipient
/// PEM is unreadable or invalid, Vault is unreachable / holds no identity, encryption
/// fails, or the output file cannot be written.
pub async fn run_backup(
    vault_cfg: &VaultConfig,
    audit_cfg: &AuditConfig,
    recipient_paths: &[std::path::PathBuf],
    out_path: &Path,
) -> Result<()> {
    let Some(kv_path) = vault_cfg.kv_path.as_deref().filter(|p| !p.is_empty()) else {
        bail!("identity backup requires [vault].kv_path (the KV path the node identity lives at)");
    };
    if recipient_paths.is_empty() {
        bail!("identity backup requires at least one --recipient <operator-public-key.pem>");
    }

    // Parse every recipient up front, so a bad PEM fails before Vault is touched.
    let mut recipients = Vec::with_capacity(recipient_paths.len());
    for recipient_path in recipient_paths {
        let recipient_pem = std::fs::read_to_string(recipient_path).with_context(|| {
            format!(
                "reading the operator recipient from {}",
                recipient_path.display()
            )
        })?;
        let recipient = parse_public_key(&recipient_pem).map_err(|e| {
            anyhow::anyhow!(
                "{} is not a valid crypt4gh public key: {e}",
                recipient_path.display()
            )
        })?;
        recipients.push(recipient);
    }

    let client = VaultClient::connect(vault_cfg)
        .await
        .map_err(|e| anyhow::anyhow!("connecting to Vault: {e}"))?;
    let map = match client.kv_get(kv_path).await {
        // Wrap so the fetched secret-key PEMs are wiped on drop, not left in freed heap
        // after the backup completes.
        Ok(m) if !m.is_empty() => m,
        // Empty, or an absent path (KV v2 404 → Permanent): nothing to back up.
        Ok(_) | Err(VaultError::Permanent(_)) => bail!(
            "no node identity at {}/{kv_path} to back up",
            vault_cfg.kv_mount()
        ),
        Err(VaultError::Transient(e)) => {
            bail!("cannot reach Vault to read the node identity: {e}")
        }
    };

    // The serialized map carries the secret-key PEMs — keep it in a zeroize buffer.
    let plaintext =
        Zeroizing::new(serde_json::to_vec(&*map).context("serializing the identity map")?);

    // crypt4gh-encrypt the blob to every operator recipient (ephemeral sender keypair).
    let (sender_sk, _sender_pk) = generate_keypair();
    let mut blob = Vec::new();
    encrypt(
        &mut Cursor::new(plaintext.as_slice()),
        &mut blob,
        &recipients,
        &sender_sk,
    )
    .map_err(|e| anyhow::anyhow!("encrypting the identity backup: {e}"))?;

    // Durable atomic write (tmp -> fsync -> rename -> dir fsync): this is the
    // irreplaceable DR copy of the node identity secret keys, so an interrupted
    // re-backup must never truncate or clobber a previously-good blob at out_path.
    //
    // Owner-only (0o600) as well. The blob is crypt4gh ciphertext, so confidentiality does
    // not rest on the mode, but the plain writer applies `0o666 & ~umask`, typically 0o644,
    // which would land the recovery copy of every node secret key world-readable. An offline
    // attack on the operator recipients' keys should not be handed the ciphertext for
    // free.
    gdi_node_standalone_core::util::write_durable_atomic_private(out_path, &blob)
        .with_context(|| format!("writing the backup to {}", out_path.display()))?;
    println!(
        "backed up {} node-identity field(s) from {}/{kv_path} to {} (encrypted to {} recipient(s))",
        map.len(),
        vault_cfg.kv_mount(),
        out_path.display(),
        recipients.len()
    );
    // Key-lifecycle audit trail: a copy of the node identity was exported. The audit line
    // carries counts only, never key material, the destination path, or recipient
    // identities. That is a property of the audit sink alone; the operator-facing `println!`
    // three lines up does print the destination path and the recipient count.
    crate::audit::identity_backed_up(audit_cfg, map.len(), recipients.len());
    Ok(())
}

/// Decrypt + parse a backup blob at `blob_path` with the operator secret PEM at
/// `identity_path` into the field→PEM identity map. Shared by [`run_restore`] (which
/// then writes it to Vault) and [`verify_backup`] (which only validates it). Performs
/// no Vault I/O.
///
/// # Errors
///
/// Returns an error when the operator key / blob is unreadable, decryption fails
/// (wrong key or corrupt blob), the blob is not a valid identity map, or it is empty.
fn decrypt_backup(blob_path: &Path, identity_path: &Path) -> Result<ZeroizingIdentityMap> {
    let operator_pem =
        Zeroizing::new(std::fs::read_to_string(identity_path).with_context(|| {
            format!(
                "reading the operator secret key from {}",
                identity_path.display()
            )
        })?);
    let operator_sk = parse_secret_key(&operator_pem).map_err(|e| {
        anyhow::anyhow!(
            "{} is not a valid crypt4gh secret key: {e}",
            identity_path.display()
        )
    })?;
    let blob = std::fs::read(blob_path)
        .with_context(|| format!("reading the backup from {}", blob_path.display()))?;

    let mut plaintext = Zeroizing::new(Vec::new());
    decrypt(
        &mut Cursor::new(blob.as_slice()),
        &mut *plaintext,
        std::slice::from_ref(&operator_sk),
    )
    .map_err(|e| anyhow::anyhow!("decrypting the identity backup (wrong operator key?): {e}"))?;
    let map: BTreeMap<String, String> = serde_json::from_slice(&plaintext)
        .context("the decrypted backup is not a valid node-identity map")?;
    if map.is_empty() {
        bail!("the backup contains no identity fields");
    }
    // Every field must parse as a crypt4gh secret key before this map is written to the
    // create-only Vault slot in `run_restore`. A backup that decrypts but holds a
    // valid-JSON-but-non-key field would otherwise occupy that create-only path with an
    // unusable identity, failing the next start (`from_pems` fails closed) and refusing a
    // subsequent good restore until the slot is manually cleared. This mirrors the per-field
    // check `verify_backup` applies under `--dry-run`, so the real restore path is no weaker
    // than the dry run.
    for (field, pem) in &map {
        parse_secret_key(pem).map_err(|e| {
            anyhow::anyhow!("backup field `{field}` is not a valid crypt4gh secret key: {e}")
        })?;
    }
    Ok(ZeroizingIdentityMap(map))
}

/// Verify a node-identity backup at `blob_path` is restorable, **without** writing it
/// to Vault (the `identity restore --dry-run` path): decrypt it with the operator
/// secret PEM at `identity_path`, parse the identity map, and confirm every field is
/// a valid crypt4gh secret key. Touches neither Vault nor the live identity, so it
/// needs no `[vault]` section and is safe to run on an offline machine where the
/// operator secret is held.
///
/// # Errors
///
/// Returns an error when the operator key / blob is unreadable, decryption fails
/// (wrong key or corrupt blob), the blob is not a valid identity map, it is empty, or
/// any field is not a parseable crypt4gh secret key.
pub fn verify_backup(blob_path: &Path, identity_path: &Path) -> Result<()> {
    let map = decrypt_backup(blob_path, identity_path)?;
    // Every value must parse as a crypt4gh secret key: a backup that decrypts but holds a
    // corrupt field would fail during a real restore. Capture each field's recipient
    // fingerprint so the operator can match the backup against `identity list` and spot a
    // stale blob, one taken before the latest rotation and missing the newest key.
    // `--dry-run` does no Vault I/O, so it cannot confirm currency on its own.
    let mut lines = Vec::with_capacity(map.len());
    for (field, pem) in map.iter() {
        let sk = parse_secret_key(pem).map_err(|e| {
            anyhow::anyhow!("backup field `{field}` is not a valid crypt4gh secret key: {e}")
        })?;
        lines.push(format!(
            "  {field}  {}",
            public_key_fingerprint(&sk.public_key())
        ));
    }
    println!(
        "backup at {} verified: {} identity field(s) decrypt with the operator key and parse as \
         valid crypt4gh secret keys; not written to Vault (--dry-run).",
        blob_path.display(),
        map.len()
    );
    println!(
        "fields (field name + recipient fingerprint, compare against `identity list` to confirm \
         the backup is CURRENT, not stale):"
    );
    for line in &lines {
        println!("{line}");
    }
    Ok(())
}

/// Restore a node-identity backup at `blob_path`, decrypted with the operator
/// secret PEM at `identity_path`, into `[vault].kv_path` (create-only).
///
/// On success emits a key-lifecycle audit line (gated on `audit_cfg.enabled`)
/// recording only the number of restored fields — never key material. A restore
/// provisions the irreplaceable node secret, so it leaves the same trail as the
/// other identity-lifecycle flows.
///
/// # Errors
///
/// Returns an error when `kv_path` is unset, the operator key / blob is unreadable,
/// decryption fails (wrong key or corrupt blob), the blob is not an identity map,
/// Vault is unreachable, an identity already exists at the path, or the write fails.
pub async fn run_restore(
    vault_cfg: &VaultConfig,
    audit_cfg: &AuditConfig,
    blob_path: &Path,
    identity_path: &Path,
) -> Result<()> {
    let Some(kv_path) = vault_cfg.kv_path.as_deref().filter(|p| !p.is_empty()) else {
        bail!("identity restore requires [vault].kv_path (the KV path to restore into)");
    };

    let map = decrypt_backup(blob_path, identity_path)?;

    let client = VaultClient::connect(vault_cfg)
        .await
        .map_err(|e| anyhow::anyhow!("connecting to Vault: {e}"))?;
    // Create-only: never clobber a live identity (the same guard as identity init).
    match client.kv_get(kv_path).await {
        Ok(m) if !m.is_empty() => bail!(
            "a node identity already exists at {}/{kv_path}; restore only onto a fresh path, \
             clearing the existing one first",
            vault_cfg.kv_mount()
        ),
        Err(VaultError::Transient(e)) => {
            bail!("cannot reach Vault to check for an existing identity: {e}")
        }
        Ok(_) | Err(VaultError::Permanent(_)) => {}
    }
    client
        .kv_put_create(kv_path, &map)
        .await
        .map_err(|e| anyhow::anyhow!("writing the restored identity: {e}"))?;
    println!(
        "restored {} node-identity field(s) into {}/{kv_path}",
        map.len(),
        vault_cfg.kv_mount()
    );
    // Key-lifecycle audit trail: the node identity was provisioned onto this node.
    // Field count only — never key material, the source path, or the operator key.
    crate::audit::identity_restored(audit_cfg, map.len());
    Ok(())
}

#[cfg(test)]
mod tests {

    use gdi_node_standalone_core::crypt4gh::{
        generate_keypair, serialize_public_key, serialize_secret_key,
    };
    use serde_json::json;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const KV: &str = "gdi-node-standalone/c4gh-identities";
    const FIELD: &str = "c4gh-0000000000000001";

    fn cfg(address: &str) -> VaultConfig {
        VaultConfig {
            address: address.to_owned(),
            token: Some("hvs.test-token".to_owned()),
            kv_path: Some(KV.to_owned()),
            ..VaultConfig::default()
        }
    }

    /// Write an operator keypair to temp PEM files named `<stem>.pub` / `<stem>.sec`;
    /// return (`recipient_pub`, secret). Distinct stems let one test hold several
    /// operator keypairs in the same dir (multi-recipient).
    fn operator_keypair_named(dir: &Path, stem: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let (sk, pk) = generate_keypair();
        let pub_path = dir.join(format!("{stem}.pub"));
        let sec_path = dir.join(format!("{stem}.sec"));
        std::fs::write(&pub_path, serialize_public_key(&pk)).expect("write pub");
        std::fs::write(&sec_path, serialize_secret_key(&sk).as_bytes()).expect("write sec");
        (pub_path, sec_path)
    }

    /// Write a single operator keypair (`operator.pub` / `operator.sec`).
    fn operator_keypair(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
        operator_keypair_named(dir, "operator")
    }

    /// A representative stored node identity (a real secret-key PEM under `FIELD`).
    fn node_identity_pem() -> String {
        let (sk, _pk) = generate_keypair();
        serialize_secret_key(&sk)
    }

    /// A Vault GET response whose KV-v2 `data.data` is the given field->PEM map.
    fn kv_present(field: &str, pem: &str) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { field: pem }, "metadata": { "version": 1 } }
        }))
    }

    /// A Vault GET for a present but empty KV-v2 secret (`data.data == {}`), a distinct
    /// state from an absent path (404). The backup guard treats it as "nothing to back up";
    /// the create-only restore guard treats it as a fresh path.
    fn kv_empty() -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": {}, "metadata": { "version": 1 } }
        }))
    }

    #[tokio::test]
    async fn backup_then_restore_round_trips() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (pub_path, sec_path) = operator_keypair(tmp.path());
        let blob = tmp.path().join("identity.c4gh");
        let pem = node_identity_pem();

        // Backup: Vault holds one identity field; run_backup encrypts it to the operator.
        let backup_srv = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/secret/data/{KV}")))
            .respond_with(kv_present(FIELD, &pem))
            .mount(&backup_srv)
            .await;
        run_backup(
            &cfg(&backup_srv.uri()),
            &AuditConfig::default(),
            std::slice::from_ref(&pub_path),
            &blob,
        )
        .await
        .expect("backup");
        assert!(blob.is_file(), "backup wrote the encrypted blob");

        // Restore: fresh path (404), then the create-only write must carry the same field
        // and PEM, proving the round-trip preserved the secret, with cas=0.
        let restore_srv = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/secret/data/{KV}")))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({ "errors": [] })))
            .mount(&restore_srv)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("/v1/secret/data/{KV}")))
            .and(body_partial_json(
                json!({ "options": { "cas": 0 }, "data": { FIELD: pem } }),
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "data": { "version": 1 } })),
            )
            .expect(1)
            .mount(&restore_srv)
            .await;
        run_restore(
            &cfg(&restore_srv.uri()),
            &AuditConfig::default(),
            &blob,
            &sec_path,
        )
        .await
        .expect("restore");
    }

    #[tokio::test]
    #[serial_test::serial(faults)]
    async fn backup_fails_closed_when_the_durable_write_fails() {
        // The identity backup is the irreplaceable recovery copy of the node's secret
        // keys, so a failed final durable write, disk full for instance, must fail closed.
        // `run_backup` propagates the error, so the operator gets a non-zero exit and knows
        // the backup did not complete, and leaves no partial or torn blob at out_path. It
        // must never return Ok having written nothing usable. Arm the durable-write fault on
        // the unique out_path so no sibling test's write can match.
        let tmp = tempfile::tempdir().expect("tempdir");
        let (pub_path, _sec) = operator_keypair(tmp.path());
        let blob = tmp.path().join("identity.c4gh");
        let arm_key = blob.to_string_lossy().into_owned();
        let pem = node_identity_pem();

        // Vault holds a real identity to back up — so run_backup reaches the write stage.
        let srv = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/secret/data/{KV}")))
            .respond_with(kv_present(FIELD, &pem))
            .mount(&srv)
            .await;

        let _g = gdi_node_standalone_core::faults::arm_enospc(
            gdi_node_standalone_core::faults::FaultPoint::DurableWrite,
            &arm_key,
            1,
        );
        let err = run_backup(
            &cfg(&srv.uri()),
            &AuditConfig::default(),
            std::slice::from_ref(&pub_path),
            &blob,
        )
        .await
        .expect_err("a failed durable write must make run_backup fail closed");
        // The error chain surfaces the write stage, not a silent success.
        assert!(
            format!("{err:#}").contains("writing the backup"),
            "error must surface the durable-write failure: {err:#}"
        );
        // Fail-closed: no partial blob, and no torn temp sibling (the guard fires before
        // any I/O, so nothing is created).
        assert!(
            !blob.exists(),
            "a failed backup must leave no blob at out_path"
        );
        assert!(
            !tmp.path().join("identity.c4gh.tmp").exists(),
            "a failed backup must leave no torn temp sibling"
        );
    }

    #[tokio::test]
    async fn backup_refuses_a_present_but_empty_identity() {
        // A present-but-empty KV path is "nothing to back up": run_backup must bail via
        // the `!m.is_empty()` guard, not silently write an empty backup blob.
        let tmp = tempfile::tempdir().expect("tempdir");
        let (pub_path, _sec) = operator_keypair(tmp.path());
        let blob = tmp.path().join("identity.c4gh");
        let srv = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/secret/data/{KV}")))
            .respond_with(kv_empty())
            .mount(&srv)
            .await;
        let err = run_backup(
            &cfg(&srv.uri()),
            &AuditConfig::default(),
            std::slice::from_ref(&pub_path),
            &blob,
        )
        .await
        .expect_err("an empty identity must not be backed up");
        assert!(err.to_string().contains("no node identity"), "got {err}");
        assert!(
            !blob.exists(),
            "no backup blob should be written for an empty identity"
        );
    }

    #[tokio::test]
    async fn restore_proceeds_onto_a_present_but_empty_path() {
        // The create-only guard must treat a present-but-empty path as fresh and proceed;
        // refusing with "already exists" is only for a non-empty identity. Mirrors the
        // round-trip test, but the restore-target GET is empty rather than 404.
        let tmp = tempfile::tempdir().expect("tempdir");
        let (pub_path, sec_path) = operator_keypair(tmp.path());
        let blob = tmp.path().join("identity.c4gh");
        let pem = node_identity_pem();

        let backup_srv = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/secret/data/{KV}")))
            .respond_with(kv_present(FIELD, &pem))
            .mount(&backup_srv)
            .await;
        run_backup(
            &cfg(&backup_srv.uri()),
            &AuditConfig::default(),
            std::slice::from_ref(&pub_path),
            &blob,
        )
        .await
        .expect("backup");

        let restore_srv = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/secret/data/{KV}")))
            .respond_with(kv_empty())
            .mount(&restore_srv)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("/v1/secret/data/{KV}")))
            .and(body_partial_json(
                json!({ "options": { "cas": 0 }, "data": { FIELD: pem } }),
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "data": { "version": 1 } })),
            )
            .expect(1)
            .mount(&restore_srv)
            .await;
        run_restore(
            &cfg(&restore_srv.uri()),
            &AuditConfig::default(),
            &blob,
            &sec_path,
        )
        .await
        .expect("restore onto a present-but-empty path must succeed");
    }

    #[tokio::test]
    async fn restore_with_wrong_operator_key_fails() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (pub_path, _sec_path) = operator_keypair(tmp.path());
        // A different operator secret cannot decrypt a backup made for the first.
        let other_sec = tmp.path().join("other.sec");
        let (osk, _opk) = generate_keypair();
        std::fs::write(&other_sec, serialize_secret_key(&osk).as_bytes()).expect("write other sec");
        let blob = tmp.path().join("identity.c4gh");

        let backup_srv = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/secret/data/{KV}")))
            .respond_with(kv_present(FIELD, &node_identity_pem()))
            .mount(&backup_srv)
            .await;
        run_backup(
            &cfg(&backup_srv.uri()),
            &AuditConfig::default(),
            std::slice::from_ref(&pub_path),
            &blob,
        )
        .await
        .expect("backup");

        let err = run_restore(
            &cfg("http://127.0.0.1:1"),
            &AuditConfig::default(),
            &blob,
            &other_sec,
        )
        .await
        .expect_err("wrong key must fail before Vault is touched");
        assert!(err.to_string().contains("decrypting"), "got {err}");
    }

    #[tokio::test]
    async fn backup_errors_when_no_identity() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (pub_path, _sec) = operator_keypair(tmp.path());
        let srv = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/secret/data/{KV}")))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({ "errors": [] })))
            .mount(&srv)
            .await;
        let err = run_backup(
            &cfg(&srv.uri()),
            &AuditConfig::default(),
            std::slice::from_ref(&pub_path),
            &tmp.path().join("b.c4gh"),
        )
        .await
        .expect_err("nothing to back up");
        assert!(err.to_string().contains("no node identity"), "got {err}");
    }

    #[tokio::test]
    async fn restore_refuses_when_identity_present() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (pub_path, sec_path) = operator_keypair(tmp.path());
        let blob = tmp.path().join("identity.c4gh");
        let backup_srv = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/secret/data/{KV}")))
            .respond_with(kv_present(FIELD, &node_identity_pem()))
            .mount(&backup_srv)
            .await;
        run_backup(
            &cfg(&backup_srv.uri()),
            &AuditConfig::default(),
            std::slice::from_ref(&pub_path),
            &blob,
        )
        .await
        .expect("backup");

        // Restore target already has an identity -> refuse (no POST mock; a stray
        // write would 404 and fail).
        let restore_srv = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/secret/data/{KV}")))
            .respond_with(kv_present(FIELD, &node_identity_pem()))
            .mount(&restore_srv)
            .await;
        let err = run_restore(
            &cfg(&restore_srv.uri()),
            &AuditConfig::default(),
            &blob,
            &sec_path,
        )
        .await
        .expect_err("must refuse to clobber");
        assert!(err.to_string().contains("already exists"), "got {err}");
    }

    #[tokio::test]
    async fn errors_without_kv_path() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (pub_path, sec_path) = operator_keypair(tmp.path());
        let vault_cfg = VaultConfig {
            address: "https://vault.example.org".to_owned(),
            token: Some("hvs.test".to_owned()),
            kv_path: None,
            ..VaultConfig::default()
        };
        let err = run_backup(
            &vault_cfg,
            &AuditConfig::default(),
            std::slice::from_ref(&pub_path),
            &tmp.path().join("b.c4gh"),
        )
        .await
        .expect_err("missing kv_path");
        assert!(err.to_string().contains("kv_path"), "got {err}");
        // run_restore checks kv_path before reading the blob or operator key, so the blob
        // path need not exist here.
        let err = run_restore(
            &vault_cfg,
            &AuditConfig::default(),
            &tmp.path().join("b.c4gh"),
            &sec_path,
        )
        .await
        .expect_err("missing kv_path");
        assert!(err.to_string().contains("kv_path"), "got {err}");
    }

    #[tokio::test]
    async fn backup_to_multiple_recipients_each_can_restore() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (pub_a, sec_a) = operator_keypair_named(tmp.path(), "a");
        let (pub_b, sec_b) = operator_keypair_named(tmp.path(), "b");
        let blob = tmp.path().join("identity.c4gh");

        let backup_srv = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/secret/data/{KV}")))
            .respond_with(kv_present(FIELD, &node_identity_pem()))
            .mount(&backup_srv)
            .await;
        // One blob encrypted to both operator recipients.
        run_backup(
            &cfg(&backup_srv.uri()),
            &AuditConfig::default(),
            &[pub_a, pub_b],
            &blob,
        )
        .await
        .expect("backup to two recipients");

        // Either operator secret alone can decrypt the same blob, so losing one operator
        // key does not lose the backup.
        verify_backup(&blob, &sec_a).expect("operator A can restore");
        verify_backup(&blob, &sec_b).expect("operator B can restore");
    }

    #[tokio::test]
    async fn verify_backup_accepts_good_and_rejects_wrong_key() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (pub_path, sec_path) = operator_keypair(tmp.path());
        let blob = tmp.path().join("identity.c4gh");

        let backup_srv = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/secret/data/{KV}")))
            .respond_with(kv_present(FIELD, &node_identity_pem()))
            .mount(&backup_srv)
            .await;
        run_backup(
            &cfg(&backup_srv.uri()),
            &AuditConfig::default(),
            std::slice::from_ref(&pub_path),
            &blob,
        )
        .await
        .expect("backup");

        // The correct operator key verifies the backup with no Vault contact (the
        // dry-run path touches neither Vault nor the live identity).
        verify_backup(&blob, &sec_path).expect("verify a good backup");

        // A different operator secret cannot decrypt it -> fails at the decrypt step.
        let (osk, _opk) = generate_keypair();
        let other_sec = tmp.path().join("other.sec");
        std::fs::write(&other_sec, serialize_secret_key(&osk).as_bytes()).expect("write other sec");
        let err = verify_backup(&blob, &other_sec).expect_err("wrong key must fail");
        assert!(err.to_string().contains("decrypting"), "got {err}");
    }

    #[test]
    fn decrypt_backup_rejects_non_key_field() {
        // Restore-path parity with `--dry-run`: a backup that decrypts but whose plaintext
        // map holds a valid-JSON-but-non-key field must be rejected by `decrypt_backup`,
        // which `run_restore` uses, before the create-only Vault write, and not only by the
        // optional `verify_backup` dry run.
        let tmp = tempfile::tempdir().expect("tempdir");
        let (pub_path, sec_path) = operator_keypair(tmp.path());

        // Valid JSON, but the field value is not a crypt4gh secret key.
        let bad_map: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::from([(FIELD.to_owned(), "not-a-crypt4gh-key".to_owned())]);
        let plaintext = serde_json::to_vec(&bad_map).expect("serialize map");

        let recipient_pem = std::fs::read_to_string(&pub_path).expect("read operator pub");
        let recipient = gdi_node_standalone_core::crypt4gh::parse_public_key(&recipient_pem)
            .expect("parse pub");
        let (sender_sk, _pk) = generate_keypair();
        let mut blob = Vec::new();
        gdi_node_standalone_core::crypt4gh::encrypt(
            &mut std::io::Cursor::new(plaintext.as_slice()),
            &mut blob,
            std::slice::from_ref(&recipient),
            &sender_sk,
        )
        .expect("encrypt bad backup");
        let blob_path = tmp.path().join("bad.c4gh");
        std::fs::write(&blob_path, &blob).expect("write blob");

        // NB: `ZeroizingIdentityMap` (the Ok type) is intentionally not `Debug`, so use a
        // let-else rather than `expect_err` (which would require `Debug` on the Ok variant).
        let Err(err) = super::decrypt_backup(&blob_path, &sec_path) else {
            panic!("a non-key field must be rejected before restore");
        };
        assert!(
            err.to_string().contains("not a valid crypt4gh secret key"),
            "expected the per-field validation error, got {err}"
        );
    }
}
