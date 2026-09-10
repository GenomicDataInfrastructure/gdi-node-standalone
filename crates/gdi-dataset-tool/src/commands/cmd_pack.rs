//! The `pack` and `package` commands: assemble a staging directory into an
//! uncompressed TAR in the spec member order, then crypt4gh-encrypt it to the
//! node recipient plus the provider's own recipient.
//!
//! Member order is a small metadata prefix followed by the bulk payload:
//! `manifest.json` first, then every `headers/{vcfid}.vcf` (sorted), then the
//! `allele-freq.*` parquet files (sorted). The TAR is uncompressed; every member
//! is a regular file with normalized permissions (`0o644`) and cleared
//! ownership (uid=0, gid=0, uname="", gname=""). The assembled TAR is streamed
//! straight into the crypt4gh encrypter over an in-process pipe (built on a worker
//! thread), so the whole uncompressed package is never materialized on scratch disk.

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufWriter, Write as _};
use std::path::{Path, PathBuf};

use gdi_node_standalone_core::crypt4gh::{PublicKey, SecretKey, encrypt, public_key_fingerprint};
use gdi_node_standalone_core::extract::{ExtractBounds, check_staging_dir};
use gdi_node_standalone_core::s3_layout::{DATA_FILE_PREFIX, DATA_FILE_SUFFIX, is_data_file_name};

use super::{cmd_build, cmd_keys};
use crate::cli::{BuildArgs, PackArgs, PackageArgs};
use crate::scratch::{Scratch, create_scratch_file};
use crate::{ToolError, profile, recipient, runtime};

use crate::MANIFEST_NAME;
/// The headers subdirectory.
const HEADERS_DIR: &str = "headers";

/// Run `pack`: encrypt an existing staging directory into `{datasetId}.tar.c4gh`.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) if the staging dir is missing/malformed, the
/// node recipient cannot be resolved, the output already exists without
/// `--force`, or any filesystem/crypto step fails.
pub fn run(
    args: &PackArgs,
    profile_name: Option<&str>,
    config_path: Option<&Path>,
) -> Result<(), ToolError> {
    let started = std::time::Instant::now();
    let dataset_id = dataset_id_from_staging(&args.staging)?;
    let output = resolve_output(args.out.as_deref(), &dataset_id);
    crate::output::note(&format!(
        "packing {dataset_id}: {} -> {}",
        args.staging.display(),
        output.display()
    ));
    let recipients = resolve_recipients(args.recipient.as_deref(), profile_name, config_path)?;
    let sender = cmd_keys::load_or_generate_provider_secret(config_path)?;

    pack_staging_dir(&args.staging, &output, args.force, &recipients, &sender)?;
    crate::output::note(&format!("pack complete in {:.1?}", started.elapsed()));
    crate::output::emit_result(
        args.format,
        &format!("packed {} -> {}", dataset_id, output.display()),
        &serde_json::json!({
            "schemaVersion": 1,
            "status": "ok",
            "action": "pack",
            "datasetId": dataset_id,
            "path": output.display().to_string(),
        }),
    );
    Ok(())
}

/// Run `package`: `build` the staging dir, then `pack` it in one step.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) on any build or pack failure.
pub fn run_package(
    args: &PackageArgs,
    profile_name: Option<&str>,
    config_path: Option<&Path>,
) -> Result<(), ToolError> {
    let started = std::time::Instant::now();
    // 1. Build the staging dir (reuse the build logic, no duplicate code path).
    let build_args = BuildArgs {
        package: args.package.clone(),
        country_code: args.country_code.clone(),
        out: args.build_out.clone(),
        force: args.force,
        no_headers: args.no_headers,
        header_policy: args.header_policy,
        strict: false,
        dry_run: false,
        build_epoch: None,
        jobs: args.jobs,
        // Forward `--refresh-catalogs` to the build phase (live catalog fetch with a
        // pinned fallback); the node re-validates catalogs at ingest regardless.
        refresh_catalogs: args.refresh_catalogs,
        // `build_staging_dir` emits no result line, so this is inert; carry the
        // package verb's format for consistency.
        format: args.format,
    };
    let built = cmd_build::build_staging_dir(&build_args, profile_name, config_path)?;
    crate::output::note(&format!(
        "staging built: {} -> {}",
        built.dataset_id,
        built.staging.display()
    ));

    // 2. Pack the freshly built staging dir.
    let output = resolve_output(args.out.as_deref(), &built.dataset_id);
    crate::output::note(&format!(
        "packing {} -> {}",
        built.dataset_id,
        output.display()
    ));
    let recipients = resolve_recipients(args.recipient.as_deref(), profile_name, config_path)?;
    let sender = cmd_keys::load_or_generate_provider_secret(config_path)?;

    pack_or_retain_plaintext(&built.staging, &output, args.force, &recipients, &sender)?;
    crate::output::note(&format!("package complete in {:.1?}", started.elapsed()));
    crate::output::emit_result(
        args.format,
        &format!("packaged {} -> {}", built.dataset_id, output.display()),
        &serde_json::json!({
            "schemaVersion": 1,
            "status": "ok",
            "action": "package",
            "datasetId": built.dataset_id,
            "path": output.display().to_string(),
        }),
    );

    // 3. The pack succeeded: delete the staging dir (it holds plaintext
    //    genotype-derived intermediates) unless `--keep` retains it. Best-effort —
    //    a removal failure is a warning, not a command failure.
    if args.keep {
        crate::output::note(&format!(
            "kept staging dir {} (--keep)",
            built.staging.display()
        ));
    } else if let Err(e) = fs::remove_dir_all(&built.staging) {
        eprintln!(
            "warning: could not delete the staging directory {} (it holds \
                 plaintext intermediates; remove it manually): {e}",
            built.staging.display()
        );
    } else {
        crate::output::note(&format!(
            "deleted staging dir {} (plaintext intermediates)",
            built.staging.display()
        ));
    }
    Ok(())
}

/// Derive the dataset ID from the staging directory's name, validating it and reconciling
/// it against the `datasetId` the directory's `manifest.json` declares.
///
/// The dir name keys both the output filename (`{id}.tar.c4gh`) and the emitted
/// `datasetId`, while the manifest is what the node actually registers — so a
/// valid-but-divergent dir name must not silently ship a package whose filename id
/// disagrees with its contents. The two sibling derivations,
/// [`crate::pkgio::dataset_id_from_package`] and deploy's `staging_dir_id`, validate the
/// same way.
fn dataset_id_from_staging(staging: &Path) -> Result<String, ToolError> {
    if !staging.is_dir() {
        return Err(ToolError::user(format!(
            "staging directory not found: {}",
            staging.display()
        )));
    }
    let id = staging
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| {
            ToolError::user(format!(
                "cannot derive a dataset id from staging path {}",
                staging.display()
            ))
        })?;
    if !gdi_node_standalone_core::id::is_valid_dataset_id(id) {
        return Err(ToolError::user(format!(
            "staging directory name is not a valid dataset id: {}",
            staging.display()
        )));
    }
    let declared = manifest_dataset_id(staging)?;
    if declared != id {
        return Err(ToolError::user(format!(
            "staging dir name {id} does not match the datasetId {declared} declared in \
             {}: rename the directory or fix the manifest",
            staging.join(MANIFEST_NAME).display()
        )));
    }
    Ok(id.to_owned())
}

/// Read the `metadata.datasetId` a staging dir's `manifest.json` declares.
fn manifest_dataset_id(staging: &Path) -> Result<String, ToolError> {
    let path = staging.join(MANIFEST_NAME);
    if !path.is_file() {
        return Err(ToolError::user(format!(
            "staging dir has no {MANIFEST_NAME}: {}",
            staging.display()
        )));
    }
    let raw = fs::read_to_string(&path)
        .map_err(|e| ToolError::user(format!("cannot read {}: {e}", path.display())))?;
    let doc: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| ToolError::user(format!("cannot parse {}: {e}", path.display())))?;
    doc.pointer("/metadata/datasetId")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            ToolError::user(format!("{} declares no metadata.datasetId", path.display()))
        })
}

/// Resolve the output path: an explicit `-o` — used verbatim as the output file,
/// except an existing directory receives the package inside it as
/// `{datasetId}.tar.c4gh` — else `{datasetId}.tar.c4gh` in the current working directory.
fn resolve_output(out_flag: Option<&Path>, dataset_id: &str) -> PathBuf {
    let file_name = format!("{dataset_id}.tar.c4gh");
    match out_flag {
        // An existing directory means "write the package into here" — the same noun
        // `build -o <dir>` takes, and what the flag's "defaults to the cwd" contract
        // already implies. Taking it verbatim instead would name the package after the
        // directory, which then trips the exists-check and reports the misleading
        // "output already exists: . (use --force to overwrite)" — where --force would go
        // on to try to overwrite the directory itself.
        Some(dir) if dir.is_dir() => dir.join(file_name),
        // Any other path is the literal output file.
        Some(path) => path.to_path_buf(),
        None => PathBuf::from(file_name),
    }
}

/// Resolve the encryption recipients: the node recipient (mandatory) followed by
/// the provider's own recipient (so the provider can decrypt its own packages).
///
/// The active profile is only loaded when needed (i.e. when `--recipient` is not
/// given), so `pack --recipient <file>` works with no profile configured. Reused
/// by `rekey` to build the new recipient set for a header re-wrap.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) if the node recipient cannot be resolved
/// (no `--recipient`, no `node_recipient_url`/`service_url`, no
/// `node_recipient_file`, or the online fetch fails) or the provider's own
/// recipient cannot be derived.
pub fn resolve_recipients(
    recipient_flag: Option<&Path>,
    profile_name: Option<&str>,
    config_path: Option<&Path>,
) -> Result<Vec<PublicKey>, ToolError> {
    let node = resolve_node_recipient(recipient_flag, profile_name, config_path)?;
    let provider = cmd_keys::provider_recipient(config_path)?;
    Ok(vec![node, provider])
}

/// As [`resolve_recipients`], but never mints a provider identity.
///
/// For verbs that also decrypt with the provider identities (`rekey`): minting one there is
/// always wrong — a key created a moment ago cannot open the package — and it writes a
/// stray unencrypted `0o600` secret plus its directories into whatever config dir happened
/// to resolve, replacing the "wrong config dir" diagnostic with an opaque crypto error.
///
/// # Errors
///
/// Propagates node-recipient resolution failures, and the absent-provider-key error from
/// [`cmd_keys::provider_recipient_readonly`].
pub fn resolve_recipients_readonly(
    recipient_flag: Option<&Path>,
    profile_name: Option<&str>,
    config_path: Option<&Path>,
) -> Result<Vec<PublicKey>, ToolError> {
    let node = resolve_node_recipient(recipient_flag, profile_name, config_path)?;
    let provider = cmd_keys::provider_recipient_readonly(config_path)?;
    Ok(vec![node, provider])
}

/// Resolve the node recipient with the spec precedence (mirrored from
/// `cmd_doctor::check_node_recipient`): explicit `--recipient <file>`
/// wins; else the active profile's `node_recipient_url` (online primary, defaulting
/// to `{service_url}/.well-known/c4gh-recipient`) is fetched; else the offline
/// `node_recipient_file`. An online-fetch failure when a URL is configured is a hard error
/// — never a silent fall-through to a possibly-stale local file.
///
/// `--recipient` short-circuits before the profile is loaded, so it works with no
/// profile configured.
fn resolve_node_recipient(
    recipient_flag: Option<&Path>,
    profile_name: Option<&str>,
    config_path: Option<&Path>,
) -> Result<PublicKey, ToolError> {
    if let Some(flag) = recipient_flag {
        return recipient::read_node_recipient_file(flag);
    }
    // The profile is only a means of finding the node's recipient here — `--recipient`
    // is the other, and it needs no profile at all. So a profile-resolution failure must
    // name that escape hatch; the bare "no profiles configured" tells a first-time
    // provider nothing about what to do next.
    let active = profile::load_active(config_path, profile_name).map_err(|e| {
        ToolError::user(format!(
            "{}; encrypting needs the node's crypt4gh recipient. Either pass \
             `--recipient <file>` (the public key the node operator gave you) or \
             configure a profile that names the node (`gdi-dataset-tool wizard setup`)",
            e.message
        ))
    })?;
    if let Some(url) = recipient::node_recipient_url(&active) {
        let configured = active.node_recipient_path(config_path);
        let default_pin = recipient::recipient_pin_path_for_read(&active, config_path);
        let fetched = match runtime::block_on(recipient::fetch_node_recipient(&url)) {
            Ok(pk) => pk,
            // The node being down must not strand a provider whose trust anchor is
            // already local: a successful fetch would be verified against the pin
            // (`enforce_recipient_trust` below), so encrypting to the pin directly is
            // security-neutral. Without this fallback every wizard-made offline profile is
            // un-packable — setup makes `service_url` mandatory and derives the recipient
            // URL from it, so the fetch is always attempted.
            Err(fetch_err) => {
                return match recipient::offline_pin_fallback(
                    configured.as_deref(),
                    default_pin.as_deref(),
                ) {
                    Some(Ok((pk, pin))) => {
                        // `warn`, not `note`: skipping the online fetch skips rotation
                        // detection for this run, which the operator should see at
                        // every verbosity.
                        crate::output::warn(&format!(
                            "warning: node not reachable ({url}); encrypting to the \
                             pinned recipient {}",
                            pin.display()
                        ));
                        Ok(pk)
                    }
                    // A configured pin that is missing or invalid stays a hard error.
                    Some(Err(pin_err)) => Err(pin_err),
                    None => Err(ToolError::user(format!(
                        "{}; pass --recipient <file> or set the profile's \
                         node_recipient_file for an offline recipient",
                        fetch_err.message
                    ))),
                };
            }
        };
        // The online fetch is what encryption uses. An explicitly-configured
        // `node_recipient_file` pin is authoritative: the fetched key must match it.
        // Otherwise the key is pinned trust-on-first-use at the conventional per-profile
        // path, the same location the wizard and `keys pin-recipient` write to. A later
        // MITM, DNS spoof or compromised endpoint then cannot silently substitute the
        // recipient. The first pack records the key; every later pack verifies it.
        let outcome = recipient::enforce_recipient_trust(
            &fetched,
            configured.as_deref(),
            default_pin.as_deref(),
        );
        // Fail-closed: an unverified fetch — `Unpinned`, or a first-use pin that could not
        // be written — is refused rather than trusted blindly. A verified/pinned key
        // proceeds, emitting the trust-on-first-use note. See `resolve_trust_decision`.
        if let Some(note) =
            resolve_trust_decision(outcome, default_pin.as_deref(), configured.is_some())?
        {
            // `warn`, not `note`: a trust-on-first-use pin is the one unverified trust
            // decision in the encryption path, and `note` is suppressed at default
            // verbosity, so adopting whatever key the endpoint served would show up as a
            // bare "packed ..." line. `warn` prints at every verbosity including `-q`, which
            // is the contract for a degraded-but-continued outcome.
            crate::output::warn(&note);
        }
        return Ok(fetched);
    }
    // Fully offline: no URL/service_url configured -> the local file is required.
    match active.node_recipient_path(config_path) {
        Some(file) => recipient::read_node_recipient_file(&file),
        None => Err(ToolError::user(
            "no node recipient: pass --recipient <file>, set the profile's \
             node_recipient_url (or service_url), or set node_recipient_file",
        )),
    }
}

/// Fail-closed recipient-trust decision for an online fetch (the `--recipient` path
/// short-circuits earlier, so it never reaches here). Returns `Ok(Some(note))` / `Ok(None)`
/// when the fetched key may be used to encrypt (with an optional user note), or `Err` when
/// it must be refused.
///
/// A fetch with no trust anchor is refused: `Unpinned` (no configured pin and no resolvable
/// config directory to pin into) and a first-use pin that could not be written both leave
/// the fetched key unverified. Encrypting a dataset to a recipient nothing vouches for is
/// exactly the window a MITM / rogue endpoint exploits, so the operator must establish trust
/// explicitly — pass `--recipient <file>` with an out-of-band copy of the node key, or set
/// `node_recipient_file` / run `setup` to pin it. A genuine mismatch against an existing pin
/// (a rotation or a MITM) propagates the original error unchanged.
fn resolve_trust_decision(
    outcome: Result<recipient::TrustOutcome, ToolError>,
    pin_path: Option<&Path>,
    configured: bool,
) -> Result<Option<String>, ToolError> {
    match outcome {
        Ok(recipient::TrustOutcome::PinnedOnFirstUse) => Ok(pin_path.map(|p| {
            format!(
                "pinned node recipient (trust-on-first-use) at {}; a later substitution will be \
                 rejected; re-pin with `keys pin-recipient --force` after a legitimate rotation.",
                p.display()
            )
        })),
        Ok(recipient::TrustOutcome::VerifiedConfigured | recipient::TrustOutcome::VerifiedTofu) => {
            Ok(None)
        }
        Ok(recipient::TrustOutcome::Unpinned) => Err(ToolError::user(
            "refusing to encrypt to an unverified node recipient: the key was fetched with no \
             trust anchor (no resolvable config directory to pin it, and no node_recipient_file \
             configured). Establish trust explicitly: pass --recipient <file> with an \
             out-of-band copy of the node's public key, or set node_recipient_file / run `setup` \
             to pin it, instead of trusting the endpoint blindly.",
        )),
        // A first-use pin write failed (e.g. a read-only config dir): no anchor was
        // established, so fail closed — the same exposure as Unpinned.
        Err(e) if !configured && pin_path.is_some_and(|p| !p.exists()) => {
            Err(ToolError::user(format!(
                "refusing to encrypt to an unverified node recipient: could not pin the fetched \
                 key ({}). Pass --recipient <file> or set node_recipient_file to establish trust \
                 explicitly.",
                e.message
            )))
        }
        // A genuine mismatch against an existing pin (configured or TOFU): propagate.
        Err(e) => Err(e),
    }
}

/// Pack the staging dir, annotating a failure with the plaintext dir it leaves behind.
///
/// The success path deletes the staging dir (unless `--keep`) and says so, because it
/// holds plaintext genotype-derived intermediates. A failure must not be quieter about
/// the same plaintext, so the dir is retained and the error names it. A failed pack is
/// worth re-trying, and deleting the dir would destroy an expensive build and the evidence
/// of what went wrong.
///
/// # Errors
///
/// Returns whatever [`pack_staging_dir`] returned, with the retained path appended.
fn pack_or_retain_plaintext(
    staging: &Path,
    output: &Path,
    force: bool,
    recipients: &[PublicKey],
    sender: &SecretKey,
) -> Result<(), ToolError> {
    pack_staging_dir(staging, output, force, recipients, sender).map_err(|e| ToolError {
        message: format!(
            "{}\nnote: the staging directory {} was kept for re-try; it holds \
             plaintext intermediates, so remove it once you no longer need it",
            e.message,
            staging.display()
        ),
        exit_code: e.exit_code,
    })
}

/// Assemble + encrypt: stream the uncompressed TAR through crypt4gh into a scratch file
/// beside `output`, then `rename` it into place once both the builder and the encrypter
/// have succeeded. The scratch dir is removed on every exit.
fn pack_staging_dir(
    staging: &Path,
    output: &Path,
    force: bool,
    recipients: &[PublicKey],
    sender: &SecretKey,
) -> Result<(), ToolError> {
    // Member safety before anything is read or written — the same call `validate` and the
    // node's own extract path make, so the producer applies exactly the rule every consumer
    // of its output applies. Without it a symlinked member is followed and its target's
    // bytes ship inside the encrypted package, so a staging dir assembled by a script, or
    // unpacked from an untrusted archive, could exfiltrate a file from outside the dataset.
    check_staging_dir(staging, &ExtractBounds::default()).map_err(|e| ToolError::from(&e))?;

    // `-o <dir>` never reaches here as a directory: `resolve_output` has already placed
    // the package inside it as `<dir>/{id}.tar.c4gh`.
    if output.exists() && !force {
        return Err(ToolError::user(format!(
            "output already exists: {} (use --force to overwrite)",
            output.display()
        )));
    }

    crate::output::note(&format!(
        "encrypting to {} recipient(s) (crypt4gh)",
        recipients.len()
    ));
    if crate::output::is_verbose() {
        for r in recipients {
            crate::output::note(&format!(
                "recipient fingerprint: {}",
                public_key_fingerprint(r)
            ));
        }
    }

    // Stream the assembled TAR straight into crypt4gh-encrypt over an in-process pipe so
    // the whole uncompressed package is never materialized on scratch disk. Writing it to
    // scratch first would roughly double the scratch free-space needed (plaintext TAR +
    // ciphertext output coexisting) and add a full extra dataset-sized write + read. The
    // TAR is built on a worker thread feeding the pipe's write end; this thread reads the
    // other end and encrypts it. A `Vec`-backed builder would buffer the whole dataset in
    // RAM, trading the disk cost for a worse one.
    // Live byte progress over the (plaintext) TAR streamed into the encrypter. Sized to
    // the member set's on-disk bytes (TAR header/padding overhead is negligible). The bar
    // is advanced by wrapping the pipe writer the builder thread writes through; a clone
    // drives the per-member milestone lines from that thread.
    let total = tar_total_bytes(staging);
    let sp = crate::progress::StreamProgress::new(total, "packing", crate::progress::active());

    // Encrypt into a scratch file beside `output`, on the same filesystem, so the final
    // `rename` is atomic — mirroring `rekey`. Writing the ciphertext straight into
    // `output` would truncate a prior good package the moment `--force` was passed, before
    // any encryption had succeeded.
    let scratch = Scratch::new(output)?;
    let staged = scratch.path().join("packed.tar.c4gh");

    let (reader, pipe_writer) = std::io::pipe()
        .map_err(|e| ToolError::user(format!("cannot create pipe for packing: {e}")))?;
    let wrapped = sp.wrap_write(pipe_writer);
    let staging_owned = staging.to_path_buf();
    let sp_builder = sp.clone();
    let builder = std::thread::spawn(move || write_tar_to(&staging_owned, wrapped, &sp_builder));

    // `encrypt_to_file_from` owns `reader` and drops it on every return path, so if the
    // encrypt side fails early the builder thread's next write gets `BrokenPipe` and exits
    // — `join` below can never deadlock on a builder blocked writing to a full pipe.
    let encrypt_result = encrypt_to_file_from(reader, &staged, recipients, sender);

    // Always join the builder: a builder error (a truncated TAR) must not be masked by a
    // "successful" encrypt of the partial stream — `encrypt` sees the dropped pipe writer
    // as a clean EOF and would happily produce a valid crypt4gh file of a truncated TAR.
    let build_result = builder
        .join()
        .unwrap_or_else(|_| Err(ToolError::user("tar builder thread panicked while packing")));
    sp.finish();

    // Publish only once both sides succeeded. On any failure `output` is never touched, so
    // a `--force` pack over an existing package cannot destroy it; the scratch dir (and the
    // partial ciphertext inside it) is removed by `Scratch`'s `Drop`.
    match (encrypt_result, build_result) {
        (Ok(()), Ok(())) => {}
        (Err(e), _) | (Ok(()), Err(e)) => return Err(e),
    }
    fs::rename(&staged, output).map_err(|e| {
        ToolError::user(format!(
            "cannot move the packed package into place {}: {e}",
            output.display()
        ))
    })?;
    // Make the rename durable so a power loss can't lose the just-published package
    // name, mirroring `deploy_file`/`write_durable_atomic`. Best-effort (dir fsync is
    // unsupported on some filesystems); the ciphertext itself was already `sync_all`'d.
    if let Some(parent) = output.parent() {
        gdi_node_standalone_core::util::fsync_dir(parent);
    }
    Ok(())
}

/// Sum the on-disk bytes of the TAR member set (`manifest.json` + `headers/*` + the
/// `allele-freq.*` parquet files) — the progress-bar total for [`pack_staging_dir`]. TAR
/// header/padding overhead is intentionally ignored (negligible beside multi-GB parquet);
/// a stat failure for any member contributes 0 rather than aborting the pack.
fn tar_total_bytes(staging: &Path) -> u64 {
    let mut total = fs::metadata(staging.join(MANIFEST_NAME)).map_or(0, |m| m.len());
    let headers_dir = staging.join(HEADERS_DIR);
    if headers_dir.is_dir()
        && let Ok(headers) = list_files(&headers_dir)
    {
        total += headers
            .iter()
            .map(|h| fs::metadata(h).map_or(0, |m| m.len()))
            .sum::<u64>();
    }
    if let Ok(parquet) = list_parquet_files(staging) {
        total += parquet
            .iter()
            .map(|p| fs::metadata(p).map_or(0, |m| m.len()))
            .sum::<u64>();
    }
    total
}

/// Build the uncompressed TAR from `staging` into `writer`, in the spec member order
/// with normalized perms/ownership. Streams every member from disk (no whole-dataset
/// buffering), so it can pipe the TAR straight into the encrypter without a scratch file.
fn write_tar_to<W: std::io::Write>(
    staging: &Path,
    writer: W,
    sp: &crate::progress::StreamProgress,
) -> Result<(), ToolError> {
    // Buffer the writer: `tar::Builder` emits a 512-byte header per member with its own
    // `write_all`, so without buffering a many-file dataset costs one syscall per header
    // (the member bodies already go through `io::copy`'s buffer).
    let mut builder = tar::Builder::new(BufWriter::new(writer));

    // 1. manifest.json — always first.
    let manifest = staging.join(MANIFEST_NAME);
    if !manifest.is_file() {
        return Err(ToolError::user(format!(
            "staging dir has no {MANIFEST_NAME}: {}",
            staging.display()
        )));
    }
    append_file(&mut builder, &manifest, MANIFEST_NAME)?;

    // 2. headers/{vcfid}.vcf — sorted, after the manifest.
    let headers_dir = staging.join(HEADERS_DIR);
    if headers_dir.is_dir() {
        let mut headers = list_files(&headers_dir)?;
        headers.sort();
        sp.detail(&format!("tar: {} header file(s)", headers.len()));
        for h in &headers {
            let name = h.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
                ToolError::user(format!("non-UTF-8 header file name: {}", h.display()))
            })?;
            append_file(&mut builder, h, &format!("{HEADERS_DIR}/{name}"))?;
        }
    }

    // 3. allele-freq.*.parquet — sorted, the bulk payload, last.
    let mut parquet = list_parquet_files(staging)?;
    // A dataset with no data files is not a dataset. `build` refuses to produce one ("the
    // VCF group produced no rows; the dataset would be empty"), but `pack` takes its staging
    // dir from the filesystem, where the parquet can go missing after the build — an
    // interrupted `rsync`/`cp`, an ENOSPC that truncated only the bulk members, a
    // hand-pruned directory. Such a dir would otherwise pack into a valid, signed
    // `.tar.c4gh` holding nothing but `manifest.json`, whose `numberOfRecords` and per-file
    // digests still describe the missing data, so the emptiness stays invisible until
    // ingest.
    if parquet.is_empty() {
        return Err(ToolError::user(format!(
            "staging dir {} contains no {DATA_FILE_PREFIX}*{DATA_FILE_SUFFIX} data file; \
             refusing to pack an empty dataset (its manifest still declares the records the \
             missing files hold; a partially-copied or interrupted build is the usual cause)",
            staging.display()
        )));
    }
    // Verify the staged bytes against the digest `build` recorded, before signing them
    // into a `.tar.c4gh`. The check above catches a staging dir whose parquet vanished
    // entirely; it cannot see one file replaced, truncated, or added — an interrupted
    // `rsync` that copied 9 of 10 files, an ENOSPC that truncated the last one, a
    // hand-edited directory — each of which would otherwise pack into a valid, signed
    // package whose manifest describes bytes it does not carry.
    //
    // Skipped when the manifest records no `payload`: a missing digest is unknown, not
    // "verified empty", and refusing would make `pack` unable to re-pack such a dir.
    verify_staged_payload(staging)?;

    parquet.sort();
    sp.detail(&format!("tar: {} parquet file(s)", parquet.len()));
    let total = parquet.len();
    for (i, p) in parquet.iter().enumerate() {
        let name = p.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
            ToolError::user(format!("non-UTF-8 parquet file name: {}", p.display()))
        })?;
        sp.note(&format!("packing parquet {}/{total}: {name}", i + 1));
        append_file(&mut builder, p, name)?;
    }

    let mut buffered = builder
        .into_inner()
        .map_err(|e| ToolError::user(format!("cannot finalize tar: {e}")))?;
    // Flush the buffered writer; the underlying pipe writer is then dropped (on return),
    // signalling EOF to the encrypter reading the other end.
    buffered
        .flush()
        .map_err(|e| ToolError::user(format!("cannot flush tar: {e}")))?;
    Ok(())
}

/// Append one file as a TAR member named `tar_name`, with normalized metadata.
///
/// The member is streamed from disk (size taken from the file's metadata, content
/// copied by `append_data`) rather than slurped into a `Vec` first, so a multi-GB
/// parquet member adds no in-memory spike. The emitted bytes are unchanged.
fn append_file<W: std::io::Write>(
    builder: &mut tar::Builder<W>,
    source: &Path,
    tar_name: &str,
) -> Result<(), ToolError> {
    let len = fs::metadata(source)
        .map_err(|e| ToolError::user(format!("cannot stat {}: {e}", source.display())))?
        .len();
    let mut header = tar::Header::new_gnu();
    header.set_size(len);
    header.set_entry_type(tar::EntryType::Regular);
    // Normalized perms + cleared ownership (see TAR creation).
    header.set_mode(0o644);
    header.set_uid(0);
    header.set_gid(0);
    header
        .set_username("")
        .map_err(|e| ToolError::user(format!("cannot set tar username: {e}")))?;
    header
        .set_groupname("")
        .map_err(|e| ToolError::user(format!("cannot set tar groupname: {e}")))?;
    // Fixed mtime keeps output reproducible and avoids leaking build wall-clock.
    header.set_mtime(0);
    // `append_data` sets the member path on the header, recomputes the checksum, and
    // copies exactly `len` bytes from the reader.
    let file = fs::File::open(source)
        .map_err(|e| ToolError::user(format!("cannot read {}: {e}", source.display())))?;
    builder
        .append_data(&mut header, tar_name, file)
        .map_err(|e| ToolError::user(format!("cannot append {tar_name} to tar: {e}")))
}

/// crypt4gh-encrypt the TAR bytes streamed from `reader` into the scratch file `staged`.
///
/// The caller renames `staged` over the real output only once the tar builder has also
/// succeeded, so a half-encrypted or truncated stream never becomes a published package.
fn encrypt_to_file_from<R: std::io::Read>(
    mut reader: R,
    staged: &Path,
    recipients: &[PublicKey],
    sender: &SecretKey,
) -> Result<(), ToolError> {
    let file = create_scratch_file(staged)?;
    // Buffer the writer: `encrypt` emits a tiny 12-byte nonce then a ~64 KiB cipher
    // segment per block, so an unbuffered file would issue an extra syscall per
    // segment for the nonce. `into_inner` flushes before the durability fsync.
    let mut writer = BufWriter::new(file);
    encrypt(&mut reader, &mut writer, recipients, sender)
        .map_err(|e| ToolError::user(format!("crypt4gh encryption failed: {e}")))?;
    let file = writer
        .into_inner()
        .map_err(|e| ToolError::user(format!("cannot flush {}: {e}", staged.display())))?;
    file.sync_all()
        .map_err(|e| ToolError::user(format!("cannot sync {} to disk: {e}", staged.display())))?;
    Ok(())
}

/// Collect the regular files directly under `dir`.
fn list_files(dir: &Path) -> Result<Vec<PathBuf>, ToolError> {
    let mut out = Vec::new();
    let entries = fs::read_dir(dir)
        .map_err(|e| ToolError::user(format!("cannot read {}: {e}", dir.display())))?;
    for entry in entries {
        let entry =
            entry.map_err(|e| ToolError::user(format!("cannot read {}: {e}", dir.display())))?;
        let path = entry.path();
        if path.is_file() {
            out.push(path);
        }
    }
    Ok(out)
}

/// The `payload` section alone, for [`verify_staged_payload`].
///
/// Deserializing the whole [`gdi_node_standalone_core::model::Manifest`] would make this
/// check fail on a manifest that is merely incomplete — a question it does not ask, and
/// which `lint`/`check`/ingest already answer.
#[derive(serde::Deserialize)]
struct PayloadOnly {
    #[serde(default)]
    payload: Option<gdi_node_standalone_core::model::Payload>,
}

/// Refuse to pack a staging dir whose bytes no longer match its manifest's `payload`.
///
/// A no-op when the manifest records no `payload`: a manifest without that section records
/// no digests, which is unknown rather than a mismatch.
///
/// # Errors
///
/// Returns a [`ToolError`] if the manifest cannot be read or digested, or if any member
/// was added, removed, or modified since `build` wrote the manifest.
fn verify_staged_payload(staging: &Path) -> Result<(), ToolError> {
    let raw = fs::read(staging.join(MANIFEST_NAME))
        .map_err(|e| ToolError::user(format!("reading {MANIFEST_NAME} for payload check: {e}")))?;
    // Read only the `payload` section, not the whole `Manifest`. This check is about
    // whether the staged bytes still match what was recorded; whether the rest of the
    // manifest is well-formed is `lint`/`check`/ingest's job, and hard-failing here would
    // make `pack` reject a directory for a reason it does not actually care about.
    let manifest: PayloadOnly = serde_json::from_slice(&raw).map_err(|e| {
        ToolError::user(format!(
            "parsing the payload section of {MANIFEST_NAME}: {e}"
        ))
    })?;
    let Some(recorded) = manifest.payload.as_ref() else {
        return Ok(());
    };
    if !recorded.algorithm_supported() {
        return Err(ToolError::user(format!(
            "{MANIFEST_NAME} declares payload algorithm {:?}; this build only understands \
             \"sha256\" and will not pack a payload it cannot verify",
            recorded.algorithm
        )));
    }
    let actual = payload_digests(staging)?;

    let mut problems: Vec<String> = Vec::new();
    for (name, want) in &recorded.members {
        match actual.get(name) {
            None => problems.push(format!("{name}: recorded in the manifest but missing")),
            // Size is compared, not merely printed: the message below reports both, and
            // `ingest::verify_declared_payload` compares the same pair on the node side.
            Some(got) if got.sha256 != want.sha256 || got.size != want.size => {
                problems.push(format!(
                    "{name}: changed since build (recorded {} bytes / {}, on disk {} / {})",
                    want.size, want.sha256, got.size, got.sha256
                ));
            }
            Some(_) => {}
        }
    }
    for name in actual.keys() {
        if !recorded.members.contains_key(name) {
            problems.push(format!("{name}: present on disk but not in the manifest"));
        }
    }
    if problems.is_empty() {
        return Ok(());
    }
    Err(ToolError::user(format!(
        "staging dir {} no longer matches the payload its {MANIFEST_NAME} records, so \
         packing it would sign a package whose manifest describes bytes it does not \
         carry:\n  {}\nRe-run `build` rather than packing this directory.",
        staging.display(),
        problems.join("\n  ")
    )))
}

/// The whole `payload` section for a fully-staged directory.
///
/// # Errors
///
/// Returns a [`ToolError`] if any staged member cannot be listed, read, or digested.
pub(crate) fn payload_section(
    staging: &Path,
) -> Result<gdi_node_standalone_core::model::Payload, ToolError> {
    Ok(gdi_node_standalone_core::model::Payload {
        algorithm: gdi_node_standalone_core::model::Payload::SHA256.to_owned(),
        members: payload_digests(staging)?,
    })
}

/// Digest every member `write_tar_to` will pack except `manifest.json` itself.
///
/// Single-sourced here, in the module that owns the TAR member layout, so the digest
/// `build` records and the set `pack` writes cannot drift: a member added to
/// [`write_tar_to`] without being added here would be shipped undigested.
///
/// `manifest.json` is excluded for the obvious reason — it is where the result is stored,
/// so including it would be self-referential.
///
/// # Errors
///
/// Returns a [`ToolError`] if the staging dir cannot be listed, a member cannot be read,
/// or a file name is not UTF-8 (the same names `write_tar_to` requires).
pub(crate) fn payload_digests(
    staging: &Path,
) -> Result<BTreeMap<String, gdi_node_standalone_core::model::PayloadEntry>, ToolError> {
    use gdi_node_standalone_core::model::PayloadEntry;

    let mut out = BTreeMap::new();
    let mut digest = |path: &Path, name: String| -> Result<(), ToolError> {
        let file = std::fs::File::open(path)
            .map_err(|e| ToolError::user(format!("reading {} for digest: {e}", path.display())))?;
        let (sha256, size) =
            gdi_node_standalone_core::util::sha256_hex_reader(std::io::BufReader::new(file))
                .map_err(|e| ToolError::user(format!("digesting {}: {e}", path.display())))?;
        out.insert(name, PayloadEntry { sha256, size });
        Ok(())
    };

    let headers_dir = staging.join(HEADERS_DIR);
    if headers_dir.is_dir() {
        for h in list_files(&headers_dir)? {
            let name = h.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
                ToolError::user(format!("non-UTF-8 header file name: {}", h.display()))
            })?;
            let member = format!("{HEADERS_DIR}/{name}");
            digest(&h, member)?;
        }
    }
    for pq in list_parquet_files(staging)? {
        let name = pq
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| {
                ToolError::user(format!("non-UTF-8 parquet file name: {}", pq.display()))
            })?
            .to_owned();
        digest(&pq, name)?;
    }
    Ok(out)
}

/// Collect the `allele-freq.*.parquet` files directly under `dir`.
fn list_parquet_files(dir: &Path) -> Result<Vec<PathBuf>, ToolError> {
    let mut out = Vec::new();
    for path in list_files(dir)? {
        if let Some(name) = path.file_name().and_then(|n| n.to_str())
            && is_data_file_name(name)
        {
            out.push(path);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;

    const ID: &str = "GDI-EE-UTARTU-20260409143052837";

    /// An unreachable node must not strand a profile whose `node_recipient_file` pin is
    /// already local. Setup makes `service_url` mandatory and derives the recipient URL
    /// from it, so treating the fetch failure as a hard error would tell the operator to
    /// set the very key they had set and leave every offline profile un-packable. The pin
    /// is what a successful fetch is verified against, so encrypting to it directly is
    /// security-neutral.
    #[test]
    #[serial_test::serial(env)]
    fn resolve_node_recipient_falls_back_to_the_configured_pin_when_the_fetch_fails() {
        use gdi_node_standalone_core::config::{Profile, ToolConfig};
        use gdi_node_standalone_core::crypt4gh::generate_keypair;
        let dir = tempfile::tempdir().unwrap();
        // Pin the config dir so the default TOFU pin path resolves inside the tempdir,
        // never against the host's real ~/.config/gdi.
        let _guard = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path());
        let (_sk, pk) = generate_keypair();
        let pin = dir.path().join("node.pub");
        recipient::write_pinned_recipient(&pk, &pin, false).unwrap();

        // Port 1 refuses connections: the derived recipient URL cannot be fetched.
        let profile = |recipient_file: Option<String>| ToolConfig {
            profiles: std::collections::BTreeMap::from([(
                "default".to_owned(),
                Profile {
                    service_url: Some("https://127.0.0.1:1".to_owned()),
                    node_recipient_file: recipient_file,
                    ..Profile::default()
                },
            )]),
            ..ToolConfig::default()
        };

        let cfg_path = dir.path().join("tool.toml");
        gdi_node_standalone_core::config::write(
            &profile(Some(pin.to_string_lossy().into_owned())),
            &cfg_path,
        )
        .unwrap();
        let key = resolve_node_recipient(None, None, Some(&cfg_path))
            .expect("the configured pin must carry an offline pack");
        assert_eq!(key.as_bytes(), pk.as_bytes());

        // Without any pin the fetch failure stays fatal and names both remedies.
        gdi_node_standalone_core::config::write(&profile(None), &cfg_path).unwrap();
        let err =
            resolve_node_recipient(None, None, Some(&cfg_path)).expect_err("no pin, no fallback");
        assert!(
            err.message.contains("--recipient") && err.message.contains("node_recipient_file"),
            "got: {}",
            err.message
        );
    }

    /// A failed pack must name the plaintext staging dir it leaves behind.
    #[test]
    fn pack_failure_names_the_retained_plaintext_staging_dir() {
        // On the success path `package` deletes the staging dir and says so, because it
        // holds plaintext genotype-derived intermediates. The failure path keeps the dir
        // for a re-try, so the error has to name it — otherwise the operator sees only
        // "output already exists" and never learns plaintext was left, or where. Simplest
        // trigger: pack onto an existing output without --force, which fails before any
        // key is used.
        let tmp = tempfile::tempdir().expect("tempdir");
        let staging = tmp.path().join("GDI-EE-UTARTU-20260101000000001");
        std::fs::create_dir_all(&staging).expect("staging");
        let output = tmp.path().join("taken.tar.c4gh");
        std::fs::write(&output, b"in the way").expect("output");

        let (sender, _) = gdi_node_standalone_core::crypt4gh::generate_keypair();
        let (_, recipient) = gdi_node_standalone_core::crypt4gh::generate_keypair();

        let err = pack_or_retain_plaintext(&staging, &output, false, &[recipient], &sender)
            .expect_err("packing onto an existing output without --force must fail");

        assert!(
            err.message.contains(&staging.display().to_string()),
            "the failure must name the staging dir that was left behind: {}",
            err.message
        );
        assert!(
            err.message.contains("plaintext"),
            "the failure must say why the retained dir matters: {}",
            err.message
        );
        assert!(
            staging.is_dir(),
            "the dir must be retained, not deleted; a failed pack is worth re-trying"
        );
    }

    /// `-o <dir>` means "write the package into this directory", not "name the package
    /// after the directory", so `pack <staging> -o .` resolves to a file inside `.`.
    #[test]
    fn output_flag_pointing_at_a_directory_places_the_package_inside_it() {
        let dir = tempfile::tempdir().unwrap();

        // An existing directory => the package lands inside it.
        assert_eq!(
            resolve_output(Some(dir.path()), ID),
            dir.path().join(format!("{ID}.tar.c4gh")),
        );

        // `-o .` — taken verbatim this would report "output already exists: .".
        assert_eq!(
            resolve_output(Some(Path::new(".")), ID),
            Path::new(".").join(format!("{ID}.tar.c4gh")),
        );

        // A non-directory path is still taken verbatim as the output file.
        let explicit = dir.path().join("custom-name.tar.c4gh");
        assert_eq!(resolve_output(Some(&explicit), ID), explicit);

        // Omitted => `{datasetId}.tar.c4gh` in the cwd (unchanged contract).
        assert_eq!(
            resolve_output(None, ID),
            PathBuf::from(format!("{ID}.tar.c4gh")),
        );
    }

    /// With neither `--recipient` nor a profile, the error must name `--recipient`. A bare
    /// "no profiles configured" leaves a first-time provider with no next step, and
    /// `pack --recipient <file>` needs no profile at all.
    #[test]
    #[serial_test::serial(env)]
    fn missing_profile_error_names_the_recipient_escape_hatch() {
        // Jail the config dir: without `--config` the default path is still read, so an
        // unjailed run picks up whatever profile the host machine has configured and can
        // resolve a recipient from it.
        let tmp = tempfile::tempdir().unwrap();
        let _guard = test_util::EnvGuard::set("GDI_CONFIG_DIR", tmp.path());
        let err = resolve_node_recipient(None, None, None)
            .expect_err("no profile and no --recipient cannot resolve a recipient");
        assert!(
            err.message.contains("--recipient"),
            "the error must point at `--recipient`; got: {}",
            err.message
        );
        assert!(
            err.message.contains("recipient"),
            "the error must say what is actually missing; got: {}",
            err.message
        );
    }

    /// A staging dir named `id` whose `manifest.json` declares `manifest_id`.
    fn staging_with_manifest(root: &Path, id: &str, manifest_id: &str) -> PathBuf {
        let staging = root.join(id);
        fs::create_dir_all(&staging).unwrap();
        fs::write(
            staging.join(MANIFEST_NAME),
            serde_json::json!({ "metadata": { "datasetId": manifest_id } }).to_string(),
        )
        .unwrap();
        staging
    }

    /// Add one data-file member, so the dir is something `pack` will accept.
    ///
    /// The content is not parquet and does not need to be: `pack` selects members by the
    /// `allele-freq.*.parquet` name rule (`is_data_file_name`) and streams their bytes —
    /// only `build` and the node's ingest validator parse them.
    fn with_data_file(staging: &Path) {
        fs::write(
            staging.join("allele-freq.chr1.0.br0-1000.in.parquet"),
            b"not-really-parquet",
        )
        .unwrap();
    }

    /// Record a `payload` section in the staging manifest matching what is on disk now.
    fn with_recorded_payload(staging: &Path) {
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(staging.join(MANIFEST_NAME)).unwrap()).unwrap();
        manifest["payload"] = serde_json::json!({
            "algorithm": "sha256",
            "members": payload_digests(staging).unwrap(),
        });
        fs::write(staging.join(MANIFEST_NAME), manifest.to_string()).unwrap();
    }

    /// A staging dir mutated after `build` must not be signed into a package.
    ///
    /// `packing_a_staging_dir_with_no_data_files_is_refused` catches only total emptiness.
    /// The realistic damage is partial — an `rsync` that copied 9 of 10 files, an ENOSPC
    /// that truncated the last one, a hand-pruned directory — and each would otherwise pack
    /// into a valid, signed `.tar.c4gh` whose manifest describes bytes it does not carry.
    /// Each row mutates the staged set in a different direction; all must be refused, and
    /// none may leave a package behind.
    #[test]
    fn packing_a_staging_dir_that_drifted_since_build_is_refused() {
        for (case, mutate) in [
            (
                "truncated",
                (|s: &Path| {
                    fs::write(s.join("allele-freq.chr1.0.br0-1000.in.parquet"), b"trunc").unwrap();
                }) as fn(&Path),
            ),
            ("deleted", |s: &Path| {
                fs::remove_file(s.join("allele-freq.chr1.0.br0-1000.in.parquet")).unwrap();
                fs::write(s.join("allele-freq.chr2.0.br0-1000.in.parquet"), b"other").unwrap();
            }),
            ("added", |s: &Path| {
                fs::write(s.join("allele-freq.chr9.0.br0-1000.in.parquet"), b"extra").unwrap();
            }),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let staging = staging_with_manifest(tmp.path(), ID, ID);
            with_data_file(&staging);
            with_recorded_payload(&staging);
            mutate(&staging);

            let output = tmp.path().join(format!("{ID}.tar.c4gh"));
            let (sender, _) = gdi_node_standalone_core::crypt4gh::generate_keypair();
            let (_, recipient) = gdi_node_standalone_core::crypt4gh::generate_keypair();
            let err =
                pack_staging_dir(&staging, &output, false, &[recipient], &sender).unwrap_err();

            assert!(
                err.message.contains("no longer matches the payload"),
                "[{case}] the refusal must say the staged bytes drifted; got: {}",
                err.message
            );
            assert!(
                !output.exists(),
                "[{case}] no package may be published from a drifted staging dir"
            );
        }
    }

    /// The verification is skipped, not failed, for a manifest with no `payload`.
    ///
    /// A manifest without that section records no digests: unknown, not "verified empty".
    /// Refusing would make `pack` unable to re-pack such a staging dir at all.
    #[test]
    fn a_manifest_without_a_payload_section_still_packs() {
        let tmp = tempfile::tempdir().unwrap();
        let staging = staging_with_manifest(tmp.path(), ID, ID);
        with_data_file(&staging);
        // No `with_recorded_payload`: that is what this test covers.
        let output = tmp.path().join(format!("{ID}.tar.c4gh"));
        let (sender, _) = gdi_node_standalone_core::crypt4gh::generate_keypair();
        let (_, recipient) = gdi_node_standalone_core::crypt4gh::generate_keypair();
        pack_staging_dir(&staging, &output, false, &[recipient], &sender).unwrap();
        assert!(output.is_file());
    }

    /// `--force` must never destroy a prior good package before the new one is complete:
    /// the write is staged and renamed, so a failed pack leaves the old package intact.
    #[test]
    fn a_failed_pack_preserves_the_existing_package() {
        let tmp = tempfile::tempdir().unwrap();
        // A staging dir with no manifest.json makes the tar builder fail.
        let staging = tmp.path().join(ID);
        fs::create_dir_all(&staging).unwrap();
        let output = tmp.path().join(format!("{ID}.tar.c4gh"));
        fs::write(&output, b"OLD-GOOD-PACKAGE").unwrap();

        let (sender, _) = gdi_node_standalone_core::crypt4gh::generate_keypair();
        let (_, recipient) = gdi_node_standalone_core::crypt4gh::generate_keypair();
        let err = pack_staging_dir(&staging, &output, true, &[recipient], &sender).unwrap_err();

        assert_eq!(err.exit_code, 1);
        assert_eq!(
            fs::read(&output).unwrap(),
            b"OLD-GOOD-PACKAGE",
            "a failed pack must leave the prior package byte-for-byte intact"
        );
    }

    /// A staging dir whose data files are gone is a packaging failure, not a small package.
    ///
    /// The manifest survives an interrupted copy far more often than the multi-GB parquet
    /// beside it (it is written last and is a few KiB), so "manifest only" is the shape a
    /// truncated transfer leaves behind — and it would otherwise pack into a valid, signed
    /// `.tar.c4gh` still advertising every record the missing files held. `build` refuses
    /// the equivalent input ("the dataset would be empty"); this is the same gate on the
    /// path that takes its input from the filesystem instead of from a VCF.
    #[test]
    fn packing_a_staging_dir_with_no_data_files_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let staging = staging_with_manifest(tmp.path(), ID, ID);
        let output = tmp.path().join(format!("{ID}.tar.c4gh"));

        let (sender, _) = gdi_node_standalone_core::crypt4gh::generate_keypair();
        let (_, recipient) = gdi_node_standalone_core::crypt4gh::generate_keypair();
        let err = pack_staging_dir(&staging, &output, false, &[recipient], &sender).unwrap_err();

        assert!(
            err.message.contains("no allele-freq")
                && err.message.contains(".parquet")
                && err.message.contains("empty dataset"),
            "the refusal must name the missing member class and why it matters; got: {}",
            err.message
        );
        assert!(
            !output.exists(),
            "no package may be published for an empty staging dir"
        );
    }

    /// The happy path still publishes a real crypt4gh package and leaves no scratch behind.
    #[test]
    fn a_successful_pack_publishes_a_crypt4gh_package() {
        let tmp = tempfile::tempdir().unwrap();
        let staging = staging_with_manifest(tmp.path(), ID, ID);
        // A payload member is required, see
        // `packing_a_staging_dir_with_no_data_files_is_refused`, so the fixture carries one
        // rather than packing a manifest-only dir.
        with_data_file(&staging);
        let output = tmp.path().join(format!("{ID}.tar.c4gh"));

        let (sender, _) = gdi_node_standalone_core::crypt4gh::generate_keypair();
        let (_, recipient) = gdi_node_standalone_core::crypt4gh::generate_keypair();
        pack_staging_dir(&staging, &output, false, &[recipient], &sender).unwrap();

        let bytes = fs::read(&output).unwrap();
        assert_eq!(
            &bytes[..8],
            b"crypt4gh",
            "output must be a crypt4gh package"
        );
        // Staging through `create_scratch_file` + `rename` means the published package
        // inherits the scratch file's `0o600`, matching `rekey`. Pinned so any change here
        // is deliberate.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(&output).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "packed package mode; got {mode:o}");
        }
        let leftovers: Vec<_> = fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(
            leftovers.is_empty(),
            "scratch must not survive a successful pack"
        );
    }

    /// The dir-derived id must be a valid dataset id, like its two sibling derivations
    /// (`pkgio::dataset_id_from_package`, deploy's `staging_dir_id`).
    #[test]
    fn dataset_id_from_staging_rejects_an_invalid_id() {
        let tmp = tempfile::tempdir().unwrap();
        let staging = staging_with_manifest(tmp.path(), "mydata", "mydata");

        let err = dataset_id_from_staging(&staging).unwrap_err();

        assert!(
            err.message.contains("valid dataset id"),
            "expected an id-validation error; got: {}",
            err.message
        );
    }

    /// A valid-but-mismatched dir name must not silently key the package under a different
    /// id than the manifest the node will register.
    #[test]
    fn dataset_id_from_staging_rejects_a_manifest_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let staging = staging_with_manifest(tmp.path(), ID, "GDI-EE-UTARTU-20260409143052999");

        let err = dataset_id_from_staging(&staging).unwrap_err();

        assert!(
            err.message.contains("does not match"),
            "expected a dir-vs-manifest mismatch error; got: {}",
            err.message
        );
    }

    #[test]
    fn dataset_id_from_staging_accepts_a_matching_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let staging = staging_with_manifest(tmp.path(), ID, ID);

        assert_eq!(dataset_id_from_staging(&staging).unwrap(), ID);
    }

    #[test]
    fn trust_decision_fails_closed_on_unpinned() {
        // Unpinned = fetched with no anchor (no --recipient, no configured pin, no config
        // dir to pin into). Fail closed rather than encrypt to an unverified recipient.
        let d = resolve_trust_decision(Ok(recipient::TrustOutcome::Unpinned), None, false);
        let err = d.expect_err("an unpinned recipient must be refused");
        assert!(
            err.message.contains("--recipient"),
            "the refusal must point the operator at an explicit-trust escape hatch: {}",
            err.message
        );
    }

    #[test]
    fn trust_decision_fails_closed_when_pin_write_failed() {
        // A first-use pin that could not be written (e.g. read-only config dir) leaves no
        // anchor — same exposure as Unpinned — so refuse rather than trust blindly.
        let missing = Path::new("/nonexistent-dir-xyz/does-not-exist.pub");
        let d = resolve_trust_decision(Err(ToolError::user("read-only fs")), Some(missing), false);
        let err = d.expect_err("a fetch we could not pin must be refused");
        assert!(
            err.message.contains("could not pin"),
            "message should explain the pin write failed: {}",
            err.message
        );
    }

    #[test]
    fn trust_decision_propagates_a_real_pin_mismatch() {
        // The pin exists and the fetched key differs (rotation / MITM): propagate the
        // original mismatch error unchanged (it tells the operator to re-pin with --force).
        let existing = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let d = resolve_trust_decision(
            Err(ToolError::user("recipient key changed since it was pinned")),
            Some(&existing),
            false,
        );
        let err = d.expect_err("a mismatch is an error");
        assert!(
            err.message.contains("recipient key changed"),
            "the original mismatch error must be propagated verbatim: {}",
            err.message
        );
    }

    #[test]
    fn trust_decision_accepts_verified_and_pinned() {
        // Verified keys proceed silently; a first-use pin proceeds with a note.
        std::assert_matches!(
            resolve_trust_decision(Ok(recipient::TrustOutcome::VerifiedConfigured), None, true),
            Ok(None)
        );
        std::assert_matches!(
            resolve_trust_decision(Ok(recipient::TrustOutcome::VerifiedTofu), None, false),
            Ok(None)
        );
        let pin = Path::new("/cfg/recipients/p.pub");
        std::assert_matches!(
            resolve_trust_decision(
                Ok(recipient::TrustOutcome::PinnedOnFirstUse),
                Some(pin),
                false
            ),
            Ok(Some(_)),
            "a first-use pin returns a user note"
        );
    }

    /// A loopback HTTP/1.1 server serving each `(pem, times)` pair of `script` in order,
    /// 200 per request, and returning its base URL. Loopback is exempt from the HTTPS
    /// requirement, so the fetch path runs against `http://127.0.0.1:<port>`.
    ///
    /// A substitution test needs one stable URL whose key changes — the pin is keyed on the
    /// node's recipient URL, so spinning a second listener for the second key models a
    /// different node (new loopback port) and correctly does not trip the mismatch. That is
    /// the behaviour, not a gap: a moved endpoint TOFU-pins afresh, exactly as a first
    /// contact does.
    fn serve_recipient_sequence(script: &[(String, usize)]) -> String {
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let script: Vec<(String, usize)> = script.to_vec();
        std::thread::spawn(move || {
            for (pem, times) in script {
                for _ in 0..times {
                    if let Ok((mut s, _)) = listener.accept() {
                        let mut buf = [0u8; 2048];
                        let _ = s.read(&mut buf);
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{pem}",
                            pem.len()
                        );
                        let _ = s.write_all(resp.as_bytes());
                        let _ = s.flush();
                    }
                }
            }
        });
        format!("http://{addr}")
    }

    /// End-to-end: with no configured `node_recipient_file`, the online fetch is pinned
    /// trust-on-first-use at the conventional per-profile path, and a later substituted key
    /// is rejected. Exercises the wiring the pure-fn unit test cannot: `load_active_named` +
    /// `default_recipient_pin_path` + the outcome handling.
    #[test]
    #[serial_test::serial(env)]
    fn resolve_node_recipient_pins_on_first_use_then_enforces() {
        use gdi_node_standalone_core::config::{Profile, ToolConfig};
        use gdi_node_standalone_core::crypt4gh::{generate_keypair, serialize_public_key};

        let (_sk1, pk1) = generate_keypair();
        let (_sk2, pk2) = generate_keypair();

        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");
        // The pin is keyed on the node (its recipient URL), not the profile name, so the
        // filename is derived rather than spelled here — restating the rule would just be a
        // second copy of it. Exactly one pin must exist, and it must be the same file across
        // fetches: that is what makes a substitution detectable at all.
        let recipients_dir = dir.path().join("recipients");
        let sole_pin = || -> Option<std::path::PathBuf> {
            let mut found: Vec<_> = std::fs::read_dir(&recipients_dir)
                .ok()?
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "pub"))
                .collect();
            found.sort();
            match found.len() {
                1 => found.pop(),
                n => panic!("expected exactly one TOFU pin, found {n}: {found:?}"),
            }
        };

        // GDI_CONFIG_DIR governs where the conventional TOFU pin lands.
        let _prev = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path());

        let write_cfg = |url: &str| {
            let cfg = ToolConfig {
                profiles: std::collections::BTreeMap::from([(
                    "test".to_owned(),
                    Profile {
                        node_recipient_url: Some(url.to_owned()),
                        ..Profile::default()
                    },
                )]),
                ..ToolConfig::default()
            };
            gdi_node_standalone_core::config::write(&cfg, &cfg_path).unwrap();
        };

        // One endpoint for all three fetches: it serves the legitimate key twice, then the
        // substituted one. The pin is keyed on the node's recipient URL, so a second
        // listener would be a second node (new loopback port) and would correctly TOFU-pin
        // afresh rather than report a mismatch.
        let base = serve_recipient_sequence(&[
            (serialize_public_key(&pk1), 2),
            (serialize_public_key(&pk2), 1),
        ]);
        write_cfg(&base);
        let got1 = resolve_node_recipient(None, Some("test"), Some(&cfg_path)).unwrap();
        assert_eq!(got1.as_bytes(), pk1.as_bytes());
        let pin = sole_pin().expect("first use must write the conventional TOFU pin");

        // (2) The same endpoint key on a later fetch -> verified against the pin.
        let got2 = resolve_node_recipient(None, Some("test"), Some(&cfg_path)).unwrap();
        assert_eq!(got2.as_bytes(), pk1.as_bytes());

        // (3) A substituted key from the same endpoint -> rejected (MITM / rotation).
        let err = resolve_node_recipient(None, Some("test"), Some(&cfg_path)).unwrap_err();
        assert!(
            err.message.contains("differs"),
            "a substituted recipient must be rejected; got: {}",
            err.message
        );
        assert_eq!(
            sole_pin().expect("the pin survives"),
            pin,
            "a rejected substitution must not re-pin"
        );
    }
}
