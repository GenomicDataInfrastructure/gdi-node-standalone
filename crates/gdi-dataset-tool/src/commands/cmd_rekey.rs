//! The `rekey` command: re-wrap a `.tar.c4gh` package's crypt4gh header to a new
//! node recipient, leaving the (large) encrypted body unchanged.
//!
//! Rotating a node identity does not re-encrypt the payload. The owner decrypts the
//! existing header with one of the provider's identities to recover the data (session) key,
//! re-wraps that same key to the new recipient set, and writes the package back as the new
//! header plus the byte-for-byte original body. `--as <provider-key>` re-signs the header as
//! that key, giving a stable writer fingerprint instead of a fresh ephemeral one; that is
//! required to rekey for a `writer_policy = enforce` node, which rejects the ephemeral
//! default.
//!
//! The old identity is retired *after* the re-wrap (an operator step — see
//! docs/operating.md), once every package has been re-keyed.
//!
//! The new recipient set **replaces** the old one — retiring the old node recipient is the
//! point of rotation. The new set is `{new node recipient, provider's own recipient}`, so
//! the provider can still decrypt its own re-keyed packages, mirroring `pack`.

use std::fs;
use std::path::Path;

use gdi_node_standalone_core::crypt4gh::{
    PublicKey, SecretKey, public_key_fingerprint, rewrap_header_as,
};

use super::cmd_pack;
use crate::cli::RekeyArgs;
use crate::scratch::{Scratch, create_scratch_file};
use crate::{ToolError, pkgio};

/// Run `rekey`, printing a success line.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) if the package cannot be decrypted with any
/// provider identity, the new node recipient cannot be resolved, the output
/// already exists without `--force`, or any filesystem/crypto step fails.
pub fn run(
    args: &RekeyArgs,
    profile_name: Option<&str>,
    config_path: Option<&Path>,
) -> Result<(), ToolError> {
    let started = std::time::Instant::now();
    // Enforce the `{id}.tar.c4gh` naming contract (like `upload`/`deploy`): a
    // package is named by its dataset id. `rekey` does not re-derive an id, but it
    // should not silently rewrite an arbitrarily-named file in place.
    let id = pkgio::dataset_id_from_package(&args.package)?;
    crate::output::note(&format!(
        "re-keying dataset {id} ({})",
        args.package.display()
    ));

    // The new recipient set: {new node recipient, provider's own recipient},
    // resolved exactly like `pack` (so `--recipient <file>` / profile precedence
    // and the always-present provider recipient match).
    let new_recipients = cmd_pack::resolve_recipients_readonly(
        args.recipient.as_deref(),
        profile_name,
        config_path,
    )?;

    // Surface the recipient fingerprints the package will be re-wrapped to (node first,
    // then the provider's own recipient) so a wrong/stale `--recipient` or fetched node
    // key is visible here, not later as a failed node ingest.
    let recipient_fps: Vec<String> = new_recipients.iter().map(public_key_fingerprint).collect();
    crate::output::note(&format!(
        "new recipient set ({}): {}",
        recipient_fps.len(),
        recipient_fps.join(", ")
    ));

    // The provider identities that can decrypt the existing header (the rotation
    // list, tried in order, so a package addressed to a now-retired key still
    // opens — same source `unpack`/`validate` use).
    let identities = pkgio::provider_identities(config_path)?;
    crate::output::note(&format!(
        "{} provider identity/identities available to decrypt the existing header",
        identities.len()
    ));

    // `--as <key>`: re-sign the header as this writer, so the recovered writer fingerprint
    // is stable and allow-listable (required to rekey for a `writer_policy = enforce` node;
    // a plain rekey mints a fresh ephemeral writer the node rejects). Announce the resulting
    // fingerprint so the operator can confirm it is the one on the node's allow-list.
    let writer_sk = match args.as_writer.as_deref() {
        Some(path) => Some(crate::commands::cmd_keys::load_identity_at(path)?),
        None => None,
    };
    let writer_fp = writer_sk
        .as_ref()
        .map(|sk| public_key_fingerprint(&sk.public_key()));
    match &writer_fp {
        Some(fp) => crate::output::note(&format!(
            "signing the re-wrapped header as writer {fp} (stable; add it to the node's \
             allowed_writer_fingerprints for a writer_policy=enforce node)"
        )),
        // `warn`, not `note`, for the same reason `cmd_pack` uses it on its
        // trust-on-first-use line: `note` is suppressed at default verbosity, so a plain
        // re-key would print only "re-keyed ... (recipients: ...)" and be indistinguishable
        // from an `--as` one. What that hides is not small — a `writer_policy = enforce`
        // node rejects every package signed by a fresh ephemeral writer, fleet-wide, with
        // fingerprints the operator cannot know in advance. Phrased conditionally because
        // the tool cannot read the node's policy, and on a `warn`/`off` node the plain form
        // is fine.
        None => crate::output::warn(
            "warning: signing the re-wrapped header with a fresh ephemeral writer key. A \
             node with `writer_policy = enforce` will reject this package \
             (error/writer-rejected); re-run with `--as <your-provider-key>` to keep the \
             writer fingerprint stable and allow-listable. On a `warn`/`off` node no action \
             is needed.",
        ),
    }

    // The output: explicit `-o`, else overwrite the input in place.
    let output = args.out.as_deref().unwrap_or(&args.package);
    crate::output::note(&format!(
        "re-wrapping header {} -> {} (encrypted body copied unchanged)",
        args.package.display(),
        output.display()
    ));
    rekey_package(
        &args.package,
        output,
        args.force,
        &identities,
        &new_recipients,
        writer_sk.as_ref(),
    )?;
    crate::output::note(&format!("re-key complete in {:.1?}", started.elapsed()));

    crate::output::emit_result(
        args.format,
        &format!(
            "re-keyed {} -> {} (recipients: {})",
            args.package.display(),
            output.display(),
            recipient_fps.join(", ")
        ),
        &serde_json::json!({
            "schemaVersion": 1,
            "status": "ok",
            "action": "rekey",
            "datasetId": id,
            "input": args.package.display().to_string(),
            "path": output.display().to_string(),
            "recipients": recipient_fps,
            "writerFingerprint": writer_fp,
        }),
    );
    Ok(())
}

/// Re-wrap `package`'s header to `new_recipients` and write the result to
/// `output`, copying the body unchanged.
///
/// The re-wrap is written to a scratch file beside the output and `rename()`d
/// into place, so an in-place re-key (`output == package`) reads the whole input
/// before the original is replaced, and a partial write never leaves a truncated
/// package.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) if `output` exists without `force`, the
/// package cannot be read/decrypted, the header cannot be re-wrapped, or the
/// scratch file cannot be written / renamed into place.
fn rekey_package(
    package: &Path,
    output: &Path,
    force: bool,
    identities: &[SecretKey],
    new_recipients: &[PublicKey],
    writer_sk: Option<&SecretKey>,
) -> Result<(), ToolError> {
    if !package.is_file() {
        return Err(ToolError::user(format!(
            "package not found: {}",
            package.display()
        )));
    }
    if output.exists() && !force {
        return Err(ToolError::user(format!(
            "output already exists: {} (use --force to overwrite)",
            output.display()
        )));
    }

    // Scratch dir beside the output, on the same filesystem, so the final rename
    // is atomic. The scratch (holding a re-wrapped — still encrypted — package) is
    // removed on every exit.
    let scratch = Scratch::new(output)?;
    let scratch_pkg = scratch.path().join("rekeyed.tar.c4gh");

    {
        let file = fs::File::open(package).map_err(|e| {
            ToolError::user(format!("cannot read package {}: {e}", package.display()))
        })?;
        // Live progress: rekey streams the whole (multi-GB) encrypted body byte-for-byte
        // to scratch (only the header changes), so on a large package this is a lengthy
        // disk-to-disk pass. Size the bar from the package length, TTY-gated.
        let total = fs::metadata(package).map_or(0, |m| m.len());
        let sp =
            crate::progress::StreamProgress::new(total, "re-keying", crate::progress::active());
        let mut reader = sp.wrap_read(file);
        let mut writer = create_scratch_file(&scratch_pkg)?;
        rewrap_header_as(
            &mut reader,
            &mut writer,
            identities,
            new_recipients,
            writer_sk,
        )
        .map_err(|e| {
            ToolError::user(format!(
                "cannot re-key {} with the provider identities: {e}",
                package.display()
            ))
        })?;
        writer
            .sync_all()
            .map_err(|e| ToolError::user(format!("cannot flush {}: {e}", scratch_pkg.display())))?;
        sp.finish();
    }

    fs::rename(&scratch_pkg, output).map_err(|e| {
        ToolError::user(format!(
            "cannot move re-keyed package into place {}: {e}",
            output.display()
        ))
    })?;
    // Make the rename durable (see `cmd_pack` / `deploy_file`): fsync the parent dir so
    // the re-keyed package name survives a power loss. Best-effort; the ciphertext was
    // already `sync_all`'d above.
    if let Some(parent) = output.parent() {
        gdi_node_standalone_core::util::fsync_dir(parent);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    #![expect(
        clippy::similar_names,
        reason = "node/provider sk/pk are the standard, clearest crypto naming"
    )]
    use super::*;
    use gdi_node_standalone_core::crypt4gh::{decrypt, encrypt, generate_keypair};

    /// End-to-end re-key over a real on-disk package, with no profile/config: the
    /// new node recipient comes straight from the resolved recipient list, so this
    /// drives `rekey_package` directly.
    #[test]
    fn rekey_package_rotates_recipient_in_place() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg = tmp.path().join("DS.tar.c4gh");

        // Provider identity (always a recipient) and the old node identity.
        let (provider_sk, provider_pk) = generate_keypair();
        let (old_node_sk, old_node_pk) = generate_keypair();
        let (sender_sk, _sender_pk) = generate_keypair();
        let payload = b"a packaged tar standing in for the real body".to_vec();

        // Encrypt to {old node, provider}, as `pack` would.
        {
            let mut writer = fs::File::create(&pkg).unwrap();
            encrypt(
                &mut &payload[..],
                &mut writer,
                &[old_node_pk, provider_pk.clone()],
                &sender_sk,
            )
            .unwrap();
        }

        // The new node identity to rotate to.
        let (new_node_sk, new_node_pk) = generate_keypair();

        // Re-key in place to {new node, provider}, decrypting with the provider id.
        rekey_package(
            &pkg,
            &pkg,
            true,
            std::slice::from_ref(&provider_sk),
            &[new_node_pk, provider_pk],
            None,
        )
        .unwrap();

        // The new node identity decrypts to the original payload.
        let mut out = Vec::new();
        {
            let mut reader = fs::File::open(&pkg).unwrap();
            decrypt(&mut reader, &mut out, &[new_node_sk]).unwrap();
        }
        assert_eq!(out, payload);

        // The provider can still decrypt its own re-keyed package.
        let mut out2 = Vec::new();
        {
            let mut reader = fs::File::open(&pkg).unwrap();
            decrypt(&mut reader, &mut out2, &[provider_sk]).unwrap();
        }
        assert_eq!(out2, payload);

        // Rotation property: the old node identity can no longer decrypt.
        let mut out3 = Vec::new();
        let mut reader = fs::File::open(&pkg).unwrap();
        assert!(decrypt(&mut reader, &mut out3, &[old_node_sk]).is_err());
    }

    #[test]
    fn rekey_as_stamps_the_provider_writer_so_enforce_would_accept() {
        // `rekey --as <provider-key>` re-signs the header as the provider's own key, so the
        // writer fingerprint the node checks against `writer_policy = enforce` is the
        // provider's: stable and already allow-listed, not a fresh ephemeral one.
        use gdi_node_standalone_core::crypt4gh::{decrypt, encrypt, recover_writer_keys};
        let tmp = tempfile::tempdir().unwrap();
        let pkg = tmp.path().join("DS.tar.c4gh");
        let out = tmp.path().join("OUT.tar.c4gh");
        let (provider_sk, provider_pk) = generate_keypair();
        let (old_node_sk, old_node_pk) = generate_keypair();
        let (new_node_sk, new_node_pk) = generate_keypair();
        let (sender_sk, _pk) = generate_keypair();
        let payload = b"payload-bytes";
        {
            let mut w = fs::File::create(&pkg).unwrap();
            encrypt(
                &mut &payload[..],
                &mut w,
                &[old_node_pk, provider_pk.clone()],
                &sender_sk,
            )
            .unwrap();
        }

        rekey_package(
            &pkg,
            &out,
            true,
            std::slice::from_ref(&provider_sk),
            &[new_node_pk, provider_pk.clone()],
            Some(&provider_sk), // --as the provider key
        )
        .unwrap();

        // The new node still decrypts (correctness), and the recovered writer key is the
        // provider's — the fingerprint an enforce node's allow-list already carries.
        let mut got = Vec::new();
        {
            let mut r = fs::File::open(&out).unwrap();
            decrypt(&mut r, &mut got, std::slice::from_ref(&new_node_sk)).unwrap();
        }
        assert_eq!(got, payload);
        let mut r = fs::File::open(&out).unwrap();
        let writers = recover_writer_keys(&mut r, std::slice::from_ref(&new_node_sk)).unwrap();
        assert!(
            writers
                .iter()
                .any(|w| w.as_bytes() == provider_pk.as_bytes()),
            "the rekeyed writer must be the provider key (allow-listable)"
        );
        let _ = old_node_sk;
    }

    #[test]
    fn rekey_refuses_existing_output_without_force() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg = tmp.path().join("DS.tar.c4gh");
        let out = tmp.path().join("OUT.tar.c4gh");
        let (provider_sk, _provider_pk) = generate_keypair();
        let (_node_sk, node_pk) = generate_keypair();
        let (sender_sk, _pk) = generate_keypair();
        {
            let mut writer = fs::File::create(&pkg).unwrap();
            encrypt(&mut &b"x"[..], &mut writer, &[node_pk], &sender_sk).unwrap();
        }
        fs::write(&out, b"existing").unwrap();
        let (_n2_sk, n2_pk) = generate_keypair();
        // The existing-output guard fires before any decryption is attempted.
        let err = rekey_package(&pkg, &out, false, &[provider_sk], &[n2_pk], None).unwrap_err();
        assert_eq!(err.exit_code, 1);
        assert!(err.message.contains("already exists"));
    }

    #[test]
    fn rekey_missing_package_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("nope.tar.c4gh");
        let out = tmp.path().join("out.tar.c4gh");
        let (sk, _pk) = generate_keypair();
        let (_n_sk, n_pk) = generate_keypair();
        let err = rekey_package(&missing, &out, true, &[sk], &[n_pk], None).unwrap_err();
        assert!(err.message.contains("not found"));
    }
}
