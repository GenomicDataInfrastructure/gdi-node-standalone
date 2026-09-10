//! The `identity retire` one-shot: remove the oldest retained node crypt4gh identity from
//! Vault KV (compiled only under the `vault` feature).
//!
//! [`crate::rotate_identity`] is purely additive: it adds a new key beside the existing
//! one(s) and never deletes, so every superseded key stays a live trial-decrypt key in Vault.
//! `retire` prunes one, removing the oldest field (the smallest, by the fixed-width sortable
//! name), so an operator can wind down the re-key window once providers have re-encrypted to
//! the current recipient, without hand-editing Vault during an incident (see
//! `docs/operating.md` §9).
//!
//! Two guarantees:
//! * The published recipient is never retired. The greatest-millis field is the served
//!   recipient ([`crate::secrets`] reads newest-first), so retiring the oldest cannot touch
//!   it, and the command refuses outright when only one key remains: retiring it would leave
//!   the node unable to decrypt anything.
//! * No lost update. The write is a KV v2 check-and-set at the version read, so a racing
//!   writer is rejected (re-run) rather than silently clobbered.
//!
//! Run it with the same write-capable, serving-token-distinct credential as `identity init`
//! and `identity rotate` (see [`crate::vault`]). It retires one key per invocation, so it is
//! incremental and least-destructive; run it again to prune the next-oldest.

use anyhow::{Result, bail};

use gdi_node_standalone_core::config::{AuditConfig, ServiceConfig};
use gdi_node_standalone_core::crypt4gh::{self, SecretKey};

use crate::vault::{VaultClient, VaultError};

/// Bytes fetched from the front of each package to check header openability. A crypt4gh
/// header for a handful of recipients is well under 1 KiB; 64 KiB is a generous bound that
/// still avoids downloading a multi-GB body.
const HEADER_PROBE_BYTES: u64 = 64 * 1024;

/// The buckets the openability scan connects to, with Vault-backed credentials applied. Pure,
/// so credential resolution is unit-tested without a live bucket: the scan must use the Vault
/// credentials, never the inline placeholder.
#[cfg(feature = "s3")]
fn scan_buckets(
    config: &ServiceConfig,
    s3_overrides: &std::collections::BTreeMap<String, (String, String)>,
) -> Vec<gdi_node_standalone_core::config::S3Bucket> {
    config.s3.as_ref().map_or_else(Vec::new, |s3| {
        s3.buckets
            .iter()
            .map(|b| crate::secrets::apply_s3_override(b, s3_overrides))
            .collect()
    })
}

/// Scan every configured source (the local inbox and each S3 bucket) for `.tar.c4gh`
/// packages whose crypt4gh header opens with none of the `surviving` identities: packages
/// that would become permanently undecryptable if the retiring identity were removed.
/// Returns their human-readable locations, sorted. A package that cannot be read or parsed is
/// conservatively reported, because its safety cannot be confirmed.
// The only `.await` in this body is the s3-gated bucket scan, so a build without `s3` has an
// await-free `async fn`. The signature stays `async` either way, so neither it nor its call
// site changes shape per feature. Scoped to `not(s3)` so an await-free body under `s3` still
// trips the lint.
#[cfg_attr(
    not(feature = "s3"),
    expect(
        clippy::unused_async,
        reason = "the sole await is the s3-gated bucket scan; the signature stays uniform across features"
    )
)]
async fn find_orphaned_packages(
    config: &ServiceConfig,
    surviving: &[SecretKey],
    // `expect`, not `allow`: it self-expires once the s3-gated use below goes away.
    #[cfg_attr(
        not(feature = "s3"),
        expect(
            unused_variables,
            reason = "the sole use is the s3-gated bucket scan; the signature stays uniform across features"
        )
    )]
    s3_overrides: &std::collections::BTreeMap<String, (String, String)>,
) -> Vec<String> {
    let mut orphans = Vec::new();

    // Inbox: read each `{id}.tar.c4gh`'s leading bytes off disk.
    //
    // Absent and unreadable are different answers and must not collapse into the same empty
    // iterator. This gate stands in front of an irreversible key deletion, so "could not
    // look" blocks it exactly as a failed bucket listing does below: an EACCES must not read
    // as a pass on the failure that hides packages openable only by the key about to be
    // destroyed. A directory that does not exist yet is genuinely nothing to check.
    if let Some(inbox) = config.service.inbox.as_deref() {
        let entries = match std::fs::read_dir(inbox) {
            Ok(entries) => Some(entries),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                orphans.push(format!("inbox:{} (unlistable: {e})", inbox.display()));
                None
            }
        };
        for entry in entries.into_iter().flatten() {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    orphans.push(format!("inbox:{} (unreadable entry: {e})", inbox.display()));
                    continue;
                }
            };
            let name = entry.file_name();
            // A name that cannot be read is the "cannot classify" case, not a skip: every
            // other failure in this loop pushes to `orphans`. On Linux a filename is
            // arbitrary bytes, so a provider drop or a restored archive can produce one.
            let Some(name) = name.to_str() else {
                // Name the entry (lossily), not just the directory: the operator has to
                // find and remove or rename it before the retire can proceed.
                orphans.push(format!(
                    "inbox:{}/{} (entry with a non-UTF-8 name: cannot be classified, so its \
                     openability cannot be proven)",
                    inbox.display(),
                    name.to_string_lossy()
                ));
                continue;
            };
            // The constant, as the S3 half of this scan already uses via
            // `strip_suffix(TAR_C4GH_SUFFIX)`. This predicate decides which files the gate in
            // front of an irreversible key deletion looks at, so a literal drifting from the
            // const would shrink the proof silently: no orphans reported, key deleted anyway.
            if !name.ends_with(gdi_node_standalone_core::s3_layout::TAR_C4GH_SUFFIX) {
                continue;
            }
            probe_inbox_artifact(
                &entry.path(),
                &format!("inbox:{name}"),
                surviving,
                &mut orphans,
            );
        }

        // Quarantine. `IngestRuntime::quarantine` renames a rejected artifact to
        // `inbox/.rejected/{id}` with the `.tar.c4gh` suffix stripped, so it is invisible to
        // the scan above on both counts: one directory deeper, and no longer matching the
        // suffix filter.
        //
        // These are the artifacts most likely to be orphaned: a package quarantined because
        // the key it was wrapped to was not loaded is one an operator intends to fix and
        // `dataset reingest`. Retiring that key while the guard reports "no orphans" makes
        // them permanently undecryptable, audited as a safe retire and requiring no
        // `--force`.
        let rejected = inbox.join(".rejected");
        match std::fs::read_dir(&rejected) {
            Ok(entries) => {
                for entry in entries {
                    // The same fail-closed posture as the inbox loop above:
                    // `entries.flatten()` would discard every per-entry error, so an EACCES
                    // on one quarantined package would read as "nothing here".
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(e) => {
                            orphans.push(format!(
                                "inbox:{} (unreadable entry: {e})",
                                rejected.display()
                            ));
                            continue;
                        }
                    };
                    let name = entry.file_name();
                    let Some(name) = name.to_str() else { continue };
                    // A quarantine entry is either a `.tar.c4gh` file (a packaged drop,
                    // suffix stripped by `quarantine`) or a staging directory (an inbox
                    // drop); see `RejectedEntry`. Only the file form can be probed for the
                    // key it was wrapped to, so the other two cases are reported instead:
                    // "could not look" blocks here exactly as an unlistable directory
                    // does.
                    match entry.file_type() {
                        Ok(t) if t.is_file() => probe_inbox_artifact(
                            &entry.path(),
                            &format!("inbox:.rejected/{name}"),
                            surviving,
                            &mut orphans,
                        ),
                        Ok(_) => orphans.push(format!(
                            "inbox:.rejected/{name} (quarantined staging directory: its \
                             recipient key cannot be probed; purge it with `dataset \
                             purge-rejected` or retire with --force)"
                        )),
                        Err(e) => orphans.push(format!(
                            "inbox:.rejected/{name} (entry type unreadable: {e})"
                        )),
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            // Wording distinct from the inbox scan's verdict above: a chmod of the inbox
            // trips both, since it also blocks traversal into `.rejected/`, and the two must
            // stay distinguishable to an assertion matching on the message.
            Err(e) => orphans.push(format!(
                "inbox:{} (quarantine unlistable: {e})",
                rejected.display()
            )),
        }
    }

    // S3 buckets: fetch each package's leading bytes with a ranged GET, using the
    // Vault-backed credentials rather than the inline placeholder.
    #[cfg(feature = "s3")]
    {
        for bucket in scan_buckets(config, s3_overrides) {
            match scan_bucket_for_orphans(&bucket, surviving).await {
                Ok(mut found) => orphans.append(&mut found),
                Err(e) => orphans.push(format!("{} (scan failed: {e})", bucket.name)),
            }
        }
    }

    orphans.sort();
    orphans
}

/// Print the orphaned-package locations (if any) to stderr — the operator-visible detail
/// behind the openability guard.
fn report_orphans(orphans: &[String]) {
    if orphans.is_empty() {
        return;
    }
    eprintln!(
        "{} package(s) would be orphaned (open only with the key being retired):",
        orphans.len()
    );
    for o in orphans {
        eprintln!("  - {o}");
    }
}

/// Probe one on-disk artifact and record it as an orphan if no surviving key opens it.
///
/// Shared by the top-level inbox scan and the `.rejected/` quarantine scan so the two cannot
/// drift: the quarantine sweep is easy to omit, and a second copy of this three-line
/// verdict is how it gets omitted.
fn probe_inbox_artifact(
    path: &std::path::Path,
    label: &str,
    surviving: &[gdi_node_standalone_core::crypt4gh::SecretKey],
    orphans: &mut Vec<String>,
) {
    let opens = read_inbox_header(path)
        .map(|buf| crypt4gh::header_opens_with(&mut &buf[..], surviving).unwrap_or(false));
    match opens {
        Ok(true) => {}
        Ok(false) => orphans.push(label.to_owned()),
        Err(e) => orphans.push(format!("{label} (unverifiable: {e})")),
    }
}

/// Read up to [`HEADER_PROBE_BYTES`] from the front of an inbox package file.
fn read_inbox_header(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    let mut buf = Vec::new();
    std::fs::File::open(path)?
        .take(HEADER_PROBE_BYTES)
        .read_to_end(&mut buf)?;
    Ok(buf)
}

/// How many package-header probes are in flight at once during the openability scan.
///
/// The scan issues one small ranged GET per `.tar.c4gh` in the bucket, so a sequential pass
/// over a few thousand packages costs one full round-trip each, and `identity retire`, even
/// with `--dry-run`, says nothing until they finish. The probes are independent, so they
/// pipeline. Bounded rather than unbounded: this runs against a provider's bucket on the
/// shared bounded client, and an unbounded fan-out would turn a safety pre-check into a
/// self-inflicted request flood.
#[cfg(feature = "s3")]
const ORPHAN_SCAN_CONCURRENCY: usize = 16;

/// What one bucket key is to the openability scan.
#[cfg(feature = "s3")]
#[derive(Debug, PartialEq, Eq)]
enum BucketKey<'a> {
    /// Not a package at all (a sidecar, a marker, a `_status/` object): genuinely nothing
    /// to prove openable.
    NotPackage,
    /// `{valid-id}.tar.c4gh` — a candidate whose header must be probed.
    Package(&'a str),
    /// A package-shaped object under a malformed id. The node would never have ingested
    /// it, but the bucket is provider-writable and the operator may intend to fix the id and
    /// re-upload after the key is gone. Skipping it would leave a real `.tar.c4gh`, possibly
    /// encrypted to the key being retired, outside the openability proof, while every other
    /// failure in the scan is conservative and reports an unreadable object as
    /// "unverifiable". It is reported, never skipped.
    MalformedPackage(&'a str),
}

/// Classify one bucket key for [`scan_bucket_for_orphans`] — split out so the rule that
/// decides what the gate in front of an irreversible key deletion even looks at can be
/// tested without a bucket.
#[cfg(feature = "s3")]
fn classify_bucket_key(key: &str) -> BucketKey<'_> {
    use gdi_node_standalone_core::s3_layout::TAR_C4GH_SUFFIX;
    let Some(id) = key.strip_suffix(TAR_C4GH_SUFFIX) else {
        return BucketKey::NotPackage;
    };
    if gdi_node_standalone_core::id::is_valid_dataset_id(id) {
        BucketKey::Package(id)
    } else {
        BucketKey::MalformedPackage(id)
    }
}

/// Ranged-scan one S3 bucket's `.tar.c4gh` packages for headers no surviving identity opens.
///
/// Lists first, then probes the candidates' headers with bounded concurrency
/// ([`ORPHAN_SCAN_CONCURRENCY`]). Completion order is not preserved — the caller sorts the
/// combined result — and every candidate is still probed: this is the safety gate for a
/// destructive, irreversible operation, so it trades latency for completeness, never
/// coverage for speed.
#[cfg(feature = "s3")]
async fn scan_bucket_for_orphans(
    bucket: &gdi_node_standalone_core::config::S3Bucket,
    surviving: &[SecretKey],
) -> Result<Vec<String>> {
    use futures::StreamExt as _;

    // The bounded client. This scan is all small requests, a listing plus a ranged read of
    // each package's crypt4gh header, so it must not run on the unbounded package-body
    // client, where a bucket endpoint that accepts the connection and then stalls would hang
    // `identity retire` forever. Retire is destructive and this scan is its safety
    // pre-check, so it has to be able to fail rather than hang.
    let store = crate::s3::build_object_store(bucket)?;

    // Pass 1 — enumerate candidates (listing only; no per-object request yet).
    let mut candidates = Vec::new();
    // Package-shaped objects this pass could not classify. Carried separately because
    // `orphans` does not exist until the probe stream below, and folded in at the end so
    // they refuse the retire exactly as an unreadable object does.
    let mut unclassifiable: Vec<String> = Vec::new();
    let mut stream = store.list(None);
    while let Some(meta) = stream.next().await {
        let meta = meta?;
        let key = meta.location.as_ref();
        match classify_bucket_key(key) {
            BucketKey::NotPackage => continue,
            BucketKey::MalformedPackage(_) => {
                unclassifiable.push(format!(
                    "{}:{key} (unclassifiable: not a valid dataset id, so its openability \
                     was not proven)",
                    bucket.name
                ));
                continue;
            }
            BucketKey::Package(_) => {}
        }
        candidates.push(meta);
    }

    // Pass 2 — probe each candidate's header, up to `ORPHAN_SCAN_CONCURRENCY` at a time.
    let store = &store;
    let mut orphans: Vec<String> = futures::stream::iter(candidates)
        .map(|meta| async move {
            let key = meta.location.as_ref();
            let end = meta.size.min(HEADER_PROBE_BYTES);
            match store
                .get_ranges(&meta.location, std::slice::from_ref(&(0..end)))
                .await
            {
                Ok(chunks) => {
                    let opens = chunks.first().is_some_and(|bytes| {
                        crypt4gh::header_opens_with(&mut bytes.as_ref(), surviving).unwrap_or(false)
                    });
                    // Only a package no surviving identity opens is an orphan.
                    (!opens).then(|| format!("{}:{key}", bucket.name))
                }
                // A package that cannot be read is conservatively reported: its safety
                // cannot be confirmed, and this gate must not fail open.
                Err(e) => Some(format!("{}:{key} (unverifiable: {e})", bucket.name)),
            }
        })
        .buffer_unordered(ORPHAN_SCAN_CONCURRENCY)
        .filter_map(|found| async move { found })
        .collect()
        .await;
    orphans.extend(unclassifiable);
    Ok(orphans)
}

/// Warn that the running node may still be publishing the key about to be removed.
///
/// `published` is the newest field in Vault. The node loads its identities once at startup
/// and has no reload path, so a node that has not been restarted since the last `identity
/// rotate` still advertises whatever was newest at its own boot. On a node that booted with
/// a single key and has since been rotated once, that is the retire target. Providers fetch
/// `/.well-known/c4gh-recipient` to decide what to encrypt to, so they would be encrypting
/// to the key this command is about to delete, and the openability scan cannot see those
/// packages because they do not exist yet.
///
/// Not machine-checked: proving it needs the node's live published recipient, which this
/// command fetches from neither Vault nor S3. Stated at the destructive step instead, with
/// the check the operator can run in one command.
fn warn_possible_stale_published_recipient(base_url: &str, oldest: &str, published: &str) {
    eprintln!(
        "warning: verify the running node is not still publishing `{oldest}` before continuing. \
         A node that has not been restarted since the last `identity rotate` keeps advertising \
         the recipient it loaded at boot, and providers encrypt to whatever \
         /.well-known/c4gh-recipient returns. Check that it matches the newest field \
         (`{published}`):  curl -s {}/.well-known/c4gh-recipient  If it does not, restart the \
         node and re-run. Packages uploaded against a stale recipient are created after the \
         openability scan and cannot be detected by it.",
        base_url.trim_end_matches('/')
    );
}

/// Record the packages a `--force` retire just made permanently undecryptable.
///
/// On the success path `report_orphans` is never reached — it runs only on the refusal
/// branch — so without this the names existed nowhere: they lived in a `Vec` that was
/// dropped, while the audit line was byte-identical to a safe retire's.
fn warn_forced_orphans(force: bool, orphans: &[String]) {
    if force && !orphans.is_empty() {
        tracing::warn!(
            orphaned = orphans.len(),
            packages = %orphans.join(", "),
            "--force retired an identity that was the only key for these packages; they are \
             no longer decryptable from their source"
        );
    }
}

/// Remove the oldest retained node identity from Vault KV at `[vault].kv_path`,
/// keeping the published recipient and every newer key.
///
/// When `dry_run` is set, Vault is read and the candidate retirement is printed, but
/// nothing is written (and no audit line is emitted) — a safe preview.
///
/// # Errors
///
/// Returns an error (mapped to a non-zero exit by `main`) when: `kv_path` is unset;
/// Vault is unreachable / the token is denied; no identity exists; only one key
/// remains (nothing safe to retire); or the check-and-set write is rejected (a
/// concurrent change — re-run).
///
/// On success, emits a key-lifecycle line to the `audit` target (gated on
/// `audit_cfg.enabled`) recording the retired field name, the remaining count, and
/// whether the retire was forced over a non-empty orphan list. Never any key material.
pub async fn run(
    config: &ServiceConfig,
    audit_cfg: &AuditConfig,
    dry_run: bool,
    force: bool,
) -> Result<()> {
    let Some(vault_cfg) = config.vault.as_ref() else {
        bail!("retire-identity requires a [vault] section (the identity lives in Vault KV)");
    };
    let Some(kv_path) = vault_cfg.kv_path.as_deref().filter(|p| !p.is_empty()) else {
        bail!(
            "identity retire is Vault-only: it requires a [vault].kv_path (the KV path the \
             node reads its identity from). In the file-based / no-Vault profile, retire by \
             removing the old key file from the [keys].identities list and restarting \
             (see docs/operating.md section 9)."
        );
    };

    let client = VaultClient::connect(vault_cfg)
        .await
        .map_err(|e| anyhow::anyhow!("connecting to Vault: {e}"))?;

    // Read the current map + version for the check-and-set.
    let (current, version) = match client.kv_get_versioned(kv_path).await {
        Ok((map, v)) if !map.is_empty() => (map, v),
        Ok(_) | Err(VaultError::Permanent(_)) => bail!(
            "no node identity at {}/{kv_path} to retire; run `identity init` first",
            vault_cfg.kv_mount()
        ),
        Err(VaultError::Transient(e)) => {
            bail!("cannot reach Vault to read the current identity: {e}")
        }
    };

    // Safety: never retire the sole/published key. The greatest-millis field is the served
    // recipient; retiring the only key would leave the node unable to decrypt.
    if current.len() <= 1 {
        bail!(
            "only one node identity remains at {}/{kv_path} (the published recipient); refusing \
             to retire it: that would leave the node unable to decrypt. Rotate in a new key \
             first if you are replacing it.",
            vault_cfg.kv_mount()
        );
    }

    // Select the oldest identity (the retire target) and the published recipient by parsed
    // `c4gh-<millis>`, matching what `crate::secrets` serves, rather than by raw `BTreeMap`
    // key order. Under key order a non-`c4gh-` field could be picked as "oldest" and deleted
    // while the real re-key window is never wound down. A map with no conforming field has
    // nothing to retire.
    let (Some(oldest), Some(published)) = (
        crate::init_identity::oldest_field(current.keys()).map(str::to_owned),
        crate::init_identity::published_field(current.keys()).map(str::to_owned),
    ) else {
        bail!("node identity map has no `c4gh-<millis>` identity field to retire");
    };
    // Belt-and-suspenders: never remove the published recipient.
    if oldest == published {
        bail!("refusing to retire the published recipient `{published}`");
    }

    // Openability guard: retiring the oldest key must not leave any package decryptable
    // only by that key, which would make it unrecoverable from its source, a loss that
    // surfaces only on a store-wipe recovery. Parse the surviving identities (the map minus
    // the retire target) and scan every configured source for a package whose header opens
    // with none of them. The node already holds the bucket credentials, and this is a header
    // read rather than a body decrypt.
    let surviving: Vec<SecretKey> = current
        .iter()
        .filter(|(field, _)| *field != &oldest)
        .filter_map(|(_, pem)| crypt4gh::parse_secret_key(pem).ok())
        .collect();
    // Load the Vault-backed per-bucket S3 credentials through the client already held, so
    // the openability scan reaches a Vault-backed bucket with the same credentials the serve
    // path uses rather than the `inline-fallback` placeholder. A read failure leaves the map
    // empty, and the scan then fails safe (unscannable means orphaned means refuse) rather
    // than aborting a retire that is otherwise valid.
    let s3_overrides = crate::secrets::load_s3_overrides(&client, vault_cfg, config)
        .await
        .unwrap_or_default();
    let orphans = find_orphaned_packages(config, &surviving, &s3_overrides).await;

    // `--dry-run`: report exactly what would be removed (read-only — Vault was read
    // above, nothing is written) and stop, so an operator's "safe preview" reflex never
    // performs the real removal.
    if dry_run {
        let remaining = current.len() - 1;
        println!(
            "dry-run: would retire node crypt4gh identity field `{oldest}` at {}/{kv_path}; \
             {remaining} identities would remain (published recipient `{published}` untouched). \
             Re-run with --yes to apply.",
            vault_cfg.kv_mount()
        );
        report_orphans(&orphans);
        return Ok(());
    }

    // Refuse (unless --force) when packages would be orphaned by the retirement.
    if !orphans.is_empty() && !force {
        report_orphans(&orphans);
        bail!(
            "refusing to retire `{oldest}`: {} package(s) open only with the key being retired \
             and would become undecryptable. Re-key them to a current recipient first \
             (`gdi-dataset-tool rekey`), or re-run with --force to retire anyway (the listed \
             packages will be unrecoverable from their source).",
            orphans.len()
        );
    }

    // See the function for why this is a warning and not a refusal.
    warn_possible_stale_published_recipient(&config.service.base_url, &oldest, &published);

    let mut reduced = current;
    reduced.remove(&oldest);
    let remaining = reduced.len();

    client
        .kv_put_cas(kv_path, &reduced, version)
        .await
        .map_err(|e| match e {
            VaultError::Permanent(msg) => anyhow::anyhow!(
                "retire write rejected; a concurrent change moved the secret version; re-run: {msg}"
            ),
            VaultError::Transient(msg) => anyhow::anyhow!("retire write failed: {msg}"),
        })?;

    // Mutation audit trail: record the retirement (retired field, remaining count, and
    // whether it was forced over a non-empty orphan list), never the key material.
    crate::audit::identity_retired(audit_cfg, &oldest, remaining, force, orphans.len());
    warn_forced_orphans(force, &orphans);

    println!(
        "retired node crypt4gh identity field `{oldest}` at {}/{kv_path}; {remaining} \
         identities retained (published recipient `{published}` untouched)",
        vault_cfg.kv_mount()
    );
    // A running node loaded its identities once at startup and has no reload path, so the
    // retired key stays live in memory, and still usable for decryption, until the node is
    // restarted. Make the take-effect requirement explicit.
    eprintln!(
        "note: restart the running node for this retirement to take effect. It loaded its \
         identities at startup and will keep the retired key live in memory until restarted."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    #![expect(
        clippy::similar_names,
        reason = "retiring/surviving sk/pk are the clearest crypto naming"
    )]

    use gdi_node_standalone_core::config::VaultConfig;
    use serde_json::json;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    #[tokio::test]
    async fn openability_scan_flags_a_package_no_surviving_key_opens() {
        use gdi_node_standalone_core::crypt4gh::{encrypt, generate_keypair};

        let (retiring_sk, retiring_pk) = generate_keypair();
        let (surviving_sk, _surviving_pk) = generate_keypair();
        let (sender_sk, _sender_pk) = generate_keypair();

        // An inbox holding one package wrapped only to the key being retired.
        let inbox = tempfile::tempdir().unwrap();
        let mut package = Vec::new();
        encrypt(
            &mut &b"payload"[..],
            &mut package,
            &[retiring_pk],
            &sender_sk,
        )
        .unwrap();
        std::fs::write(
            inbox
                .path()
                .join("GDI-EE-UTARTU-20260409143052999.tar.c4gh"),
            &package,
        )
        .unwrap();

        let mut config = ServiceConfig::default();
        config.service.inbox = Some(inbox.path().to_path_buf());

        // With only the surviving key, the package is orphaned (opens with neither it).
        let orphans =
            find_orphaned_packages(&config, &[surviving_sk], &std::collections::BTreeMap::new())
                .await;
        assert_eq!(
            orphans.len(),
            1,
            "package opening no surviving key is flagged"
        );
        assert!(orphans[0].contains("GDI-EE-UTARTU-20260409143052999"));

        // If the retiring key is counterfactually still among the survivors, the same
        // package opens and is not flagged.
        let orphans =
            find_orphaned_packages(&config, &[retiring_sk], &std::collections::BTreeMap::new())
                .await;
        assert!(
            orphans.is_empty(),
            "a package the surviving set opens is not flagged"
        );
    }

    /// On Linux a filename is arbitrary bytes, and a provider drop or a restored archive
    /// can produce one the scan cannot read as UTF-8. That is the "cannot classify" case,
    /// so it fails the gate closed, and the report must name the entry rather than only the
    /// directory, or the operator cannot find what to fix.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_non_utf8_inbox_name_is_an_orphan_that_names_the_entry() {
        use gdi_node_standalone_core::crypt4gh::generate_keypair;
        use std::os::unix::ffi::OsStrExt as _;
        let (surviving_sk, _pk) = generate_keypair();

        let inbox = tempfile::tempdir().unwrap();
        let name = std::ffi::OsStr::from_bytes(b"GDI-EE-UTARTU-2026\xff\xfe.tar.c4gh");
        std::fs::write(inbox.path().join(name), b"not a package").unwrap();
        let mut config = ServiceConfig::default();
        config.service.inbox = Some(inbox.path().to_path_buf());

        let orphans =
            find_orphaned_packages(&config, &[surviving_sk], &std::collections::BTreeMap::new())
                .await;
        assert_eq!(
            orphans.len(),
            1,
            "the unreadable name refuses the retire: {orphans:?}"
        );
        assert!(orphans[0].contains("non-UTF-8"), "{orphans:?}");
        assert!(
            orphans[0].contains("GDI-EE-UTARTU-2026"),
            "the report names the entry, not only the directory: {orphans:?}"
        );
    }

    /// The bucket half of the same classification: a package-shaped key under a malformed
    /// id is reported and never skipped, a sidecar or marker is not a package, and a valid
    /// package is a candidate. This rule decides what the gate in front of an irreversible
    /// key deletion looks at.
    #[cfg(feature = "s3")]
    #[test]
    fn a_package_shaped_key_under_a_malformed_id_is_reported_not_skipped() {
        assert_eq!(
            classify_bucket_key("GDI-EE-UTARTU-20260409143052837.tar.c4gh"),
            BucketKey::Package("GDI-EE-UTARTU-20260409143052837")
        );
        for malformed in [
            "ds-1.tar.c4gh",
            "gdi-ee-utartu-20260409143052837.tar.c4gh",
            ".tar.c4gh",
        ] {
            std::assert_matches!(
                classify_bucket_key(malformed),
                BucketKey::MalformedPackage(_),
                "{malformed}"
            );
        }
        for not_a_package in [
            "GDI-EE-UTARTU-20260409143052837.state.json",
            "GDI-EE-UTARTU-20260409143052837.metadata.json",
            "_status/GDI-EE-UTARTU-20260409143052837.json",
            "_sync_marker.json",
            "GDI-EE-UTARTU-20260409143052837.tar.c4gh.partial",
        ] {
            assert_eq!(
                classify_bucket_key(not_a_package),
                BucketKey::NotPackage,
                "{not_a_package}"
            );
        }
    }

    /// An inbox that cannot be listed must fail the gate closed.
    ///
    /// This gate stands in front of an irreversible key deletion. Swallowing the `read_dir`
    /// error and every per-entry error would collapse "directory unlistable" into "no
    /// orphans found", a silent pass on the I/O failure that hides packages
    /// openable only by the key about to be destroyed. Every sibling branch is fail-closed:
    /// an unreadable package, an unparseable header, and a failed bucket listing all push
    /// into `orphans`.
    #[tokio::test]
    async fn an_unlistable_inbox_is_an_orphan_not_an_empty_scan() {
        use gdi_node_standalone_core::crypt4gh::generate_keypair;
        let (surviving_sk, _pk) = generate_keypair();

        let inbox = tempfile::tempdir().expect("tempdir");
        let path = inbox.path().to_path_buf();
        // Drop the execute/read bits so `read_dir` fails with EACCES.
        let mut perms = std::fs::metadata(&path).expect("metadata").permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o000);
        std::fs::set_permissions(&path, perms).expect("chmod 000");

        let mut config = ServiceConfig::default();
        config.service.inbox = Some(path.clone());

        let orphans =
            find_orphaned_packages(&config, &[surviving_sk], &std::collections::BTreeMap::new())
                .await;

        // Restore so the tempdir can be cleaned up.
        let mut perms = std::fs::metadata(&path).expect("metadata").permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o700);
        let _ = std::fs::set_permissions(&path, perms);

        // Both scans trip on this chmod, since blocking traversal into the inbox also
        // blocks `inbox/.rejected`, so match the inbox scan's own verdict rather than a bare
        // "unlistable" both could produce. Shared wording would let the assertion pass if
        // either scan failed, leaving a regression that drops the inbox scan's fail-closed
        // arm green on the quarantine scan alone.
        assert!(
            orphans
                .iter()
                .any(|o| o.contains(&format!("inbox:{} (unlistable", path.display()))),
            "an unreadable inbox must block the retire, not pass it: {orphans:?}"
        );
        assert!(
            orphans.iter().any(|o| o.contains("(quarantine unlistable")),
            "and the quarantine sweep must report its own failure separately: {orphans:?}"
        );
    }

    /// A quarantined staging directory must block the retire.
    ///
    /// `quarantine` moves a rejected artifact to `inbox/.rejected/{id}` keeping its on-disk
    /// form, so an entry there is a `.tar.c4gh` file or a staging directory, as
    /// `RejectedEntry` says. A sweep filtered to `is_file()` would not see the directory
    /// form, and a quarantined package the guard cannot see lets `identity retire` report
    /// "no orphans", demand no `--force`, and audit the retire as safe while making that
    /// package permanently undecryptable.
    #[tokio::test]
    async fn a_quarantined_staging_directory_blocks_the_retire() {
        use gdi_node_standalone_core::crypt4gh::generate_keypair;
        let (surviving_sk, _pk) = generate_keypair();

        let inbox = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(
            inbox
                .path()
                .join(".rejected")
                .join("GDI-EE-UTARTU-20260409143052837"),
        )
        .expect("quarantined staging dir");

        let mut config = ServiceConfig::default();
        config.service.inbox = Some(inbox.path().to_path_buf());

        let orphans =
            find_orphaned_packages(&config, &[surviving_sk], &std::collections::BTreeMap::new())
                .await;
        assert!(
            orphans.iter().any(|o| {
                o.contains("GDI-EE-UTARTU-20260409143052837") && o.contains("staging directory")
            }),
            "a directory-form quarantine entry must be reported, not skipped: {orphans:?}"
        );
    }

    /// An inbox that does not exist yet is not an orphan: there is nothing to check, and
    /// conflating it with "unreadable" would block every retire on a node whose inbox has
    /// not been created.
    #[tokio::test]
    async fn an_absent_inbox_is_not_an_orphan() {
        use gdi_node_standalone_core::crypt4gh::generate_keypair;
        let (surviving_sk, _pk) = generate_keypair();
        let mut config = ServiceConfig::default();
        config.service.inbox = Some(std::path::PathBuf::from("/nonexistent-gdi-inbox-xyz"));

        let orphans =
            find_orphaned_packages(&config, &[surviving_sk], &std::collections::BTreeMap::new())
                .await;
        assert!(
            orphans.is_empty(),
            "absent inbox must not block: {orphans:?}"
        );
    }

    #[cfg(feature = "s3")]
    #[test]
    fn scan_buckets_apply_the_vault_credentials_not_the_inline_placeholder() {
        // Built from the raw bucket config, the openability scan's S3 client would use
        // `inline-fallback` on the full stack and get a 403. It must apply the same
        // Vault-backed override the serve path does.
        use gdi_node_standalone_core::config::{S3Bucket, S3Config};
        let config = ServiceConfig {
            s3: Some(S3Config {
                buckets: vec![S3Bucket {
                    name: "primary".to_owned(),
                    access_key_id: Some("inline-fallback".to_owned()),
                    secret_access_key: Some("inline-fallback".to_owned()),
                    ..S3Bucket::default()
                }],
            }),
            ..ServiceConfig::default()
        };
        let mut overrides = std::collections::BTreeMap::new();
        overrides.insert(
            "primary".to_owned(),
            ("vault-access".to_owned(), "vault-secret".to_owned()),
        );

        let prepared = scan_buckets(&config, &overrides);
        assert_eq!(prepared.len(), 1);
        assert_eq!(
            prepared[0].access_key_id.as_deref(),
            Some("vault-access"),
            "the scan must use the Vault access key, not inline-fallback"
        );
        assert_eq!(
            prepared[0].secret_access_key.as_deref(),
            Some("vault-secret")
        );

        // With no override for the bucket, the inline creds are kept (unchanged behaviour).
        let prepared_none = scan_buckets(&config, &std::collections::BTreeMap::new());
        assert_eq!(
            prepared_none[0].access_key_id.as_deref(),
            Some("inline-fallback")
        );
    }

    fn cfg(address: &str) -> ServiceConfig {
        // A minimal service config carrying only the Vault section under test. With no
        // inbox and no S3 buckets, the openability scan finds nothing to check, so
        // these Vault-focused tests exercise the retirement flow unchanged.
        ServiceConfig {
            vault: Some(VaultConfig {
                address: address.to_owned(),
                token: Some("hvs.test-token".to_owned()),
                kv_path: Some("gdi-node-standalone/c4gh-identities".to_owned()),
                ..VaultConfig::default()
            }),
            ..ServiceConfig::default()
        }
    }

    #[tokio::test]
    async fn removes_oldest_keeps_published_with_cas_version() {
        let server = MockServer::start().await;
        // Two identities at version 7: the oldest (…0001) must be removed, the
        // newest/published (…0002) kept.
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/gdi-node-standalone/c4gh-identities"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "data": {
                        "c4gh-0000000000000001": "-----BEGIN CRYPT4GH PRIVATE KEY-----\nOLD\n-----END CRYPT4GH PRIVATE KEY-----", // gitleaks:allow - fixture PEM
                        "c4gh-0000000000000002": "-----BEGIN CRYPT4GH PRIVATE KEY-----\nNEW\n-----END CRYPT4GH PRIVATE KEY-----"
                    },
                    "metadata": { "version": 7 }
                }
            })))
            .mount(&server)
            .await;
        // The write must cas on version 7, keep …0002, and drop …0001.
        Mock::given(method("POST"))
            .and(path("/v1/secret/data/gdi-node-standalone/c4gh-identities"))
            .and(body_partial_json(json!({
                "options": { "cas": 7 },
                "data": { "c4gh-0000000000000002": "-----BEGIN CRYPT4GH PRIVATE KEY-----\nNEW\n-----END CRYPT4GH PRIVATE KEY-----" }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "version": 8 }
            })))
            .expect(1)
            .mount(&server)
            .await;

        run(&cfg(&server.uri()), &AuditConfig::default(), false, false)
            .await
            .expect("retire removes the oldest key");
    }

    #[tokio::test]
    async fn dry_run_reads_but_never_writes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/gdi-node-standalone/c4gh-identities"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "data": {
                        "c4gh-0000000000000001": "-----BEGIN CRYPT4GH PRIVATE KEY-----\nOLD\n-----END CRYPT4GH PRIVATE KEY-----", // gitleaks:allow - fixture PEM
                        "c4gh-0000000000000002": "-----BEGIN CRYPT4GH PRIVATE KEY-----\nNEW\n-----END CRYPT4GH PRIVATE KEY-----"
                    },
                    "metadata": { "version": 7 }
                }
            })))
            .mount(&server)
            .await;
        // A POST would be a real write — mounting it with expect(0) makes the test fail
        // if `--dry-run` ever issues the mutation.
        Mock::given(method("POST"))
            .and(path("/v1/secret/data/gdi-node-standalone/c4gh-identities"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        run(&cfg(&server.uri()), &AuditConfig::default(), true, false)
            .await
            .expect("dry-run succeeds");
    }

    #[tokio::test]
    async fn refuses_to_retire_the_sole_key() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/gdi-node-standalone/c4gh-identities"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "data": { "c4gh-0000000000000001": "-----BEGIN CRYPT4GH PRIVATE KEY-----\nONLY\n-----END CRYPT4GH PRIVATE KEY-----" },
                    "metadata": { "version": 1 }
                }
            })))
            .mount(&server)
            .await;
        // No POST expected — the command must refuse before writing.
        let err = run(&cfg(&server.uri()), &AuditConfig::default(), false, false)
            .await
            .expect_err("retiring the sole key must fail");
        assert!(
            err.to_string().contains("only one node identity"),
            "explains the refusal: {err}"
        );
    }
}
