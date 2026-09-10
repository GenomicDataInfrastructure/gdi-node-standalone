//! The `keys` command: manage the provider's own crypt4gh identity(ies).
//!
//! The provider keypair is the second crypt4gh recipient on every package (so
//! the provider can always decrypt their own packages). It is stored
//! **unencrypted**; file permissions (`0o600`) plus volume-level encryption are
//! the protection, not an in-file passphrase.
//!
//! The provider may configure a rotation list under `[keys].identities` (paths
//! relative to the config dir, or absolute), tried in order when decrypting. The
//! **first** is primary: its recipient is the derived 2nd encryption recipient,
//! and it is auto-generated `0o600` if missing. An empty/absent list resolves to
//! the single implicit `keys/provider.c4gh` default.
//!
//! * `keys generate` creates the primary identity; `--force` backs the existing
//!   one up to a timestamped `.bak-<ts>` sibling, then replaces it (never silently
//!   destroying the only key that can decrypt/re-key prior packages).
//! * `keys show` prints the primary recipient + path, the active profile's node
//!   recipient, and any additional configured identities' paths/recipients.

use std::fs;
use std::path::{Path, PathBuf};

use gdi_node_standalone_core::config::ToolConfig;
use gdi_node_standalone_core::crypt4gh::{
    PublicKey, SecretKey, generate_keypair, parse_secret_key, public_key_fingerprint,
    serialize_public_key, serialize_secret_key,
};

use zeroize::Zeroizing;

use crate::cli::{KeysArgs, KeysCommand, KeysGenerateArgs, KeysPinRecipientArgs};
use crate::{ToolError, profile, recipient, runtime};

/// The default provider secret-key file name (within `<config_dir>/keys/`).
const PROVIDER_SECRET_FILE: &str = "provider.c4gh";
/// The `.pub` suffix appended to a secret-key path to derive its recipient file.
const PUBLIC_SUFFIX: &str = ".pub";

/// Run `keys`.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1, single-line message) if the config
/// directory cannot be resolved or created, if `keys generate` would overwrite
/// the primary identity without `--force`, on any filesystem error, or if
/// `keys show` cannot load/derive a recipient.
pub fn run(
    args: &KeysArgs,
    profile_name: Option<&str>,
    config_path: Option<&Path>,
) -> Result<(), ToolError> {
    match &args.command {
        KeysCommand::Generate(g) => generate(g, config_path),
        KeysCommand::Show => show(profile_name, config_path),
        KeysCommand::PinRecipient(p) => pin_recipient(p, profile_name, config_path),
    }
}

/// The directory relative `[keys].identities` paths resolve against: the parent of the
/// resolved config file when `--config` is set, else the gdi config dir. Core's one rule
/// (`config_base_dir`), mapping the unresolved case to a tool error.
fn identities_base_dir(config_path: Option<&Path>) -> Result<PathBuf, ToolError> {
    gdi_node_standalone_core::config::config_base_dir(config_path).ok_or_else(|| {
        ToolError::user(
            "cannot resolve the gdi config directory: pass --config, or set \
             $GDI_CONFIG_DIR, $XDG_CONFIG_HOME, or $HOME",
        )
    })
}

/// Resolve the ordered list of provider identity secret-key paths from
/// `[keys].identities`: absolute entries verbatim, relative entries joined to the
/// config dir. An empty/absent list resolves to the single implicit
/// `<config_dir>/keys/provider.c4gh` default.
///
/// # Errors
///
/// Returns a [`ToolError`] if the tool config cannot be loaded or the config
/// directory cannot be resolved.
pub(crate) fn resolve_identities(config_path: Option<&Path>) -> Result<Vec<PathBuf>, ToolError> {
    let cfg = ToolConfig::load(config_path)
        .map_err(|e| ToolError::user(format!("loading tool config: {e}")))?;
    let base = identities_base_dir(config_path)?;
    if cfg.keys.identities.is_empty() {
        return Ok(vec![base.join("keys").join(PROVIDER_SECRET_FILE)]);
    }
    Ok(cfg
        .keys
        .identities
        .iter()
        .map(|id| {
            if id.is_absolute() {
                id.clone()
            } else {
                base.join(id)
            }
        })
        .collect())
}

/// The `.pub` recipient file path for a secret-key path (`<secret>.pub`).
fn public_path_for(secret: &Path) -> PathBuf {
    let mut name = secret.as_os_str().to_owned();
    name.push(PUBLIC_SUFFIX);
    PathBuf::from(name)
}

/// Write the secret `contents` to `path` atomically and durably, `0o600` on Unix.
///
/// The provider identity is irreplaceable, so this writer must never truncate or overwrite
/// in place: a crash between a truncate and the write would leave a zero-length
/// `provider.c4gh`, which blocks `keys generate` (it refuses without `--force`) and
/// hard-errors every `pack`/`show` with "cannot parse provider identity".
/// `write_secret_durable` stages to a `0o600` temp, fsyncs, and renames, so the key file
/// always holds either the complete old or the complete new contents, and is never even
/// transiently group/other-readable.
fn write_secret_file(path: &Path, contents: &str) -> Result<(), ToolError> {
    gdi_node_standalone_core::util::write_secret_durable(path, contents.as_bytes())
        .map_err(|e| ToolError::user(format!("cannot write {}: {e}", path.display())))
}

/// Generate a fresh keypair at `secret_path` (`0o600`) + its `.pub` recipient,
/// creating the parent directory.
fn generate_identity_at(secret_path: &Path) -> Result<SecretKey, ToolError> {
    if let Some(parent) = secret_path.parent()
        && !parent.as_os_str().is_empty()
    {
        #[expect(
            clippy::disallowed_methods,
            reason = "operator-chosen key directory; the key file itself is written 0600"
        )]
        fs::create_dir_all(parent)
            .map_err(|e| ToolError::user(format!("cannot create {}: {e}", parent.display())))?;
    }
    let (sk, pk) = generate_keypair();
    // Hold the serialized secret PEM in a zeroized buffer, as its own doc requires, so the
    // base64 X25519 secret does not linger in freed heap.
    write_secret_file(secret_path, &Zeroizing::new(serialize_secret_key(&sk)))?;
    let public_path = public_path_for(secret_path);
    // The secret went out durably via `write_secret_file`; a half-written public key beside
    // it would silently mis-identify this provider to the node, so write it the same way.
    #[expect(
        clippy::disallowed_methods,
        reason = "not secret: the public half; the secret half uses write_secret_file"
    )]
    gdi_node_standalone_core::util::write_durable_atomic(
        &public_path,
        serialize_public_key(&pk).as_bytes(),
    )
    .map_err(|e| ToolError::user(format!("cannot write {}: {e}", public_path.display())))?;
    Ok(sk)
}

/// The warning owed for a provider secret key readable beyond its owner, if any.
///
/// The module doc states the protection plainly — the key is stored unencrypted, and file
/// permissions (`0o600`) plus volume-level encryption are all that guard it — so every read
/// path checks the mode. The node binds the identical invariant on its own keys and refuses
/// startup (`identities.rs`, `strict_key_perms`, fail-closed by default).
///
/// This warns rather than refuses: unlike the node, the tool runs interactively on an
/// operator's own workstation, and a hard failure here would lock someone out of their
/// packages over a mode bit with no way to override it. The warning uses the rung that is
/// visible at every verbosity, including `-q`.
fn loose_permission_warning(path: &Path) -> Option<String> {
    gdi_node_standalone_core::util::loose_secret_mode(path).map(|mode| {
        format!(
            "warning: the provider secret key {} is readable beyond its owner (mode {mode:o}); \
             file permissions are its only protection; run `chmod 600 {}`",
            path.display(),
            path.display()
        )
    })
}

/// Load and parse a provider secret key from `path`, warning about a loose file mode.
///
/// # Errors
///
/// Returns a [`ToolError`] when the file cannot be read or is not a crypt4gh secret key.
pub(crate) fn load_identity_at(path: &Path) -> Result<SecretKey, ToolError> {
    if let Some(warning) = loose_permission_warning(path) {
        crate::output::warn(&warning);
    }
    // Zeroize the secret PEM on drop after parsing.
    let pem = Zeroizing::new(
        fs::read_to_string(path)
            .map_err(|e| ToolError::user(format!("cannot read {}: {e}", path.display())))?,
    );
    parse_secret_key(&pem).map_err(|e| {
        ToolError::user(format!(
            "cannot parse provider identity {}: {e}",
            path.display()
        ))
    })
}

/// Append `.<suffix>` to a path (filename + the suffix), e.g.
/// `keys/provider.c4gh` + `bak-1700000000` → `keys/provider.c4gh.bak-1700000000`.
/// Mirrors [`public_path_for`]'s `OsString` handling so it is encoding-safe.
fn sibling_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".");
    name.push(suffix);
    PathBuf::from(name)
}

/// A filesystem-safe backup suffix derived from the wall clock
/// (`bak-<unix-seconds>`), falling back to `bak-0` only if the clock predates the
/// epoch (it never does in practice).
fn backup_suffix() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    format!("bak-{secs}")
}

/// Move an existing primary identity (secret **and**, if present, its `.pub`
/// recipient) aside to a timestamped `.bak-<ts>` sibling before a `--force`
/// regenerate, so the only key able to decrypt/re-key prior packages is never
/// destroyed. `rename` preserves the original `0o600` mode and is atomic on the
/// same filesystem. Returns the secret-key backup path for the operator warning.
///
/// # Errors
///
/// Returns a [`ToolError`] if the secret key cannot be moved aside — in which case
/// nothing is overwritten. A failure to move the *public* recipient is non-fatal
/// (the secret, the irreplaceable half, is already safe) and only warns.
fn back_up_existing_identity(secret_path: &Path, public_path: &Path) -> Result<PathBuf, ToolError> {
    let mut suffix = backup_suffix();
    if sibling_with_suffix(secret_path, &suffix).exists() {
        // A second `--force` within the same wall-clock second: disambiguate with
        // sub-second precision so an earlier backup is never clobbered.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or_default();
        suffix = format!("{suffix}-{nanos}");
    }
    let secret_bak = sibling_with_suffix(secret_path, &suffix);
    fs::rename(secret_path, &secret_bak).map_err(|e| {
        ToolError::user(format!(
            "cannot back up the existing provider identity {} to {}: {e}",
            secret_path.display(),
            secret_bak.display()
        ))
    })?;
    if public_path.exists() {
        let public_bak = sibling_with_suffix(public_path, &suffix);
        if let Err(e) = fs::rename(public_path, &public_bak) {
            eprintln!(
                "warning: backed up the secret key to {} but could not move its public \
                 recipient {} aside: {e}",
                secret_bak.display(),
                public_path.display()
            );
        }
    }
    Ok(secret_bak)
}

/// `keys generate`: create the primary identity (secret `0o600` + public). With
/// `--force`, the existing identity is first backed up to a timestamped
/// `.bak-<ts>` sibling (never silently destroyed) and a warning is printed.
fn generate(args: &KeysGenerateArgs, config_path: Option<&Path>) -> Result<(), ToolError> {
    let identities = resolve_identities(config_path)?;
    let secret_path = primary(&identities)?;
    let public_path = public_path_for(secret_path);
    crate::output::note(&format!(
        "keys generate: primary identity {} (recipient {}, force: {})",
        secret_path.display(),
        public_path.display(),
        args.force
    ));

    if secret_path.exists() {
        if !args.force {
            return Err(ToolError::user(format!(
                "provider identity already exists at {}. Replacing it makes every package \
                 already wrapped to its recipient impossible to decrypt or re-key. To rotate \
                 without losing access, add a new key as the first entry in [keys].identities \
                 and keep this one after it. To replace anyway (the old key is backed up \
                 first), pass --force.",
                secret_path.display()
            )));
        }
        let backup = back_up_existing_identity(secret_path, &public_path)?;
        eprintln!(
            "warning: --force replaced the existing provider identity; the previous key was \
             moved to {}. Packages already wrapped to the old recipient can be decrypted or \
             re-keyed only with that backup, so keep it. To rotate without replacing next \
             time, add the new key as the first [keys].identities entry and keep the old one \
             after it.",
            backup.display()
        );
    }

    let sk = generate_identity_at(secret_path)?;
    crate::output::note(&format!(
        "minted provider keypair; recipient fingerprint: {}",
        public_key_fingerprint(&sk.public_key())
    ));
    println!("wrote provider identity to {}", secret_path.display());
    println!("wrote provider recipient to {}", public_path.display());
    // The secret is written without a passphrase (crypt4gh PEM, mode 0o600). That posture is
    // documented in this module's header and in the key model, but a first-run operator
    // handling health data reads this output rather than either — so say it at the moment
    // the key hits the disk.
    eprintln!(
        "warning: {} is an unencrypted secret key (no passphrase, mode 0600). Anyone who can \
         read the file can decrypt every package wrapped to its recipient; filesystem \
         permissions plus volume-level encryption are its only protection. Back it up: losing \
         it makes those packages permanently undecryptable.",
        secret_path.display()
    );
    Ok(())
}

/// `keys show`: load (or auto-generate) the primary identity and print its recipient and
/// path, plus the active profile's node recipient (best-effort), plus any additional
/// configured identities' paths and recipients.
fn show(profile_name: Option<&str>, config_path: Option<&Path>) -> Result<(), ToolError> {
    let identities = resolve_identities(config_path)?;
    let primary_path = primary(&identities)?;
    crate::output::note(&format!(
        "keys show: primary identity {} ({} configured identit(ies))",
        primary_path.display(),
        identities.len()
    ));
    let sk = load_or_generate_provider_secret(config_path)?;
    let pk = sk.public_key();
    println!("provider identity: {}", primary_path.display());
    print!("{}", serialize_public_key(&pk));
    println!("fingerprint: {}", public_key_fingerprint(&pk));

    // Additional configured identities (rotation list): one line each, best-effort.
    for extra in identities.iter().skip(1) {
        match load_identity_at(extra) {
            Ok(sk) => println!(
                "additional identity: {} {}",
                extra.display(),
                recipient_oneline(&sk.public_key())
            ),
            Err(e) => println!(
                "additional identity: {} <unavailable: {}>",
                extra.display(),
                e.message
            ),
        }
    }

    // The active profile's node recipient (best-effort, never fatal).
    crate::output::note("resolving the active profile's node recipient (best-effort)");
    let mut substituted = false;
    match resolve_node_recipient(profile_name, config_path) {
        Ok((node, trust)) => {
            substituted = matches!(trust, Some(recipient::ReadonlyTrust::Substituted(_)));
            println!("node recipient:");
            print!("{}", serialize_public_key(&node));
            println!("fingerprint: {}", public_key_fingerprint(&node));
            // Tell the operator whether the fingerprint they are eyeballing is anchored:
            // an online key that merely parses is not authoritative under a MITM.
            println!(
                "trust: {}",
                match trust {
                    Some(recipient::ReadonlyTrust::VerifiedConfigured) =>
                        "VERIFIED (configured node_recipient_file pin)",
                    Some(recipient::ReadonlyTrust::VerifiedTofu) =>
                        "VERIFIED (trust-on-first-use pin)",
                    Some(recipient::ReadonlyTrust::Substituted(_)) =>
                        "SUBSTITUTED (the served key does not match its established pin; \
                         man-in-the-middle or an unannounced rotation; `pack` will refuse)",
                    Some(recipient::ReadonlyTrust::Unpinned) =>
                        "UNVERIFIED (fetched online, not yet pinned; `pack` pins on first use)",
                    Some(recipient::ReadonlyTrust::Unpinnable) =>
                        "UNVERIFIED (fetched online, and not pinnable: no node_recipient_file \
                         and no resolvable config directory; `pack` will refuse)",
                    None => "local file (out-of-band trusted)",
                }
            );
        }
        Err(e) => println!("node recipient: <unavailable: {}>", e.message),
    }
    // A detected substitution must not exit 0: rendering it as `<unavailable: …>` would be
    // indistinguishable from the node being down, and a wrapper script or a human skimming
    // the exit code would learn nothing. The fingerprint above is still printed — an
    // operator comparing it out-of-band is exactly who needs to see it.
    if substituted {
        return Err(ToolError::user(
            "the node recipient does not match its established pin (see `trust:` above). \
             Verify the new key out-of-band before trusting it; if the rotation is \
             legitimate, re-pin with `keys pin-recipient --force`.",
        ));
    }
    Ok(())
}

/// A single-line crypt4gh recipient (the PEM body, newlines collapsed) for the
/// additional-identity listing.
fn recipient_oneline(pk: &PublicKey) -> String {
    serialize_public_key(pk)
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("")
}

/// Resolve the active profile's node recipient the way `pack`/`doctor` do:
/// `node_recipient_url` (online primary, defaulting to
/// `{service_url}/.well-known/c4gh-recipient`) if configured, else the offline
/// `node_recipient_file`. Returns an error (rendered by [`show`] as an
/// unconditional `node recipient: <unavailable: …>` stdout line) when neither is
/// configured or the online fetch fails.
fn resolve_node_recipient(
    profile_name: Option<&str>,
    config_path: Option<&Path>,
) -> Result<(PublicKey, Option<recipient::ReadonlyTrust>), ToolError> {
    let active = profile::load_active(config_path, profile_name)?;
    if let Some(url) = recipient::node_recipient_url(&active) {
        let fetched = runtime::block_on(recipient::fetch_node_recipient(&url))?;
        // Verify the online-fetched key against its pin read-only (never write one from
        // `show`): a mismatch against an existing pin is the MITM/substitution condition,
        // so it errors here rather than presenting an attacker-substituted fingerprint as
        // authoritative. The trust status annotates the printed key.
        let configured = active.node_recipient_path(config_path);
        let default_pin = recipient::recipient_pin_path_for_read(&active, config_path);
        let trust = recipient::verify_fetched_readonly(
            &fetched,
            configured.as_deref(),
            default_pin.as_deref(),
        )?;
        return Ok((fetched, Some(trust)));
    }
    match active.node_recipient_path(config_path) {
        // A local file recipient is out-of-band-trusted; no online trust check applies.
        Some(file) => Ok((recipient::read_node_recipient_file(&file)?, None)),
        None => Err(ToolError::user(
            "no node_recipient_url (or service_url) and no node_recipient_file configured",
        )),
    }
}

/// The primary (first) identity path; the resolver never returns an empty list.
fn primary(identities: &[PathBuf]) -> Result<&PathBuf, ToolError> {
    identities
        .first()
        .ok_or_else(|| ToolError::user("no provider identity configured"))
}

/// Load the primary provider secret identity, auto-generating it (`0o600`) if missing.
/// This is the entry point `pack`/`package` use to obtain the sender key and the provider's
/// own (derived) recipient.
///
/// # Errors
///
/// Returns a [`ToolError`] if the config cannot be resolved, the existing primary
/// key cannot be read/parsed, or a newly generated key cannot be written.
pub fn load_or_generate_provider_secret(
    config_path: Option<&Path>,
) -> Result<SecretKey, ToolError> {
    let identities = resolve_identities(config_path)?;
    let secret_path = primary(&identities)?;
    if secret_path.exists() {
        return load_identity_at(secret_path);
    }
    // Auto-generate only the primary on first use.
    let sk = generate_identity_at(secret_path)?;
    // A mint is announced, never silent. This key is the package's crypt4gh writer
    // provenance — the value `[ingest].writer_policy = enforce` gates on — so minting one
    // resets who the node believes authored every package built from here on. It happens
    // whenever the resolved config dir holds no identity, which a `--config` typo or a
    // fresh checkout produces just as easily as a genuine first run.
    crate::output::warn(&minted_identity_warning(
        secret_path,
        &public_key_fingerprint(&sk.public_key()),
    ));
    Ok(sk)
}

/// The warning owed when a provider identity is minted rather than loaded.
///
/// Carries the fingerprint because that is the actionable part: it is what an operator must
/// add to the node's `allowed_writer_fingerprints` for packages signed with this key to be
/// accepted under `writer_policy = enforce`.
fn minted_identity_warning(path: &Path, fingerprint: &str) -> String {
    format!(
        "warning: no provider identity at {}; generated a new one ({fingerprint}). This key \
         is the crypt4gh writer provenance of every package built from here on; a node with \
         [ingest].writer_policy = enforce will reject them until this fingerprint is \
         allow-listed. If you expected an existing key, check --config / GDI_CONFIG_DIR \
         before packaging.",
        path.display()
    )
}

/// Load **all** existing provider identities in order, for decryption (so a
/// package encrypted to a now-retired key still decrypts).
///
/// This is a **read-only** path and it never generates a key. A freshly minted random
/// keypair cannot decrypt a package wrapped to somebody else's recipient, so generating one
/// here buys nothing and costs plenty: it would write a secret key into whatever config dir
/// resolved, then fail the decrypt anyway with a message about "the configured identity" —
/// an identity the tool had just invented. Running `pack` without `--config` and `inspect`
/// with it resolves two different config dirs, and the failure would read as "the provider
/// cannot decrypt its own package".
///
/// Minting stays where it is useful and intentional: [`load_or_generate_provider_secret`],
/// the `pack`/`package` sender path, which genuinely needs *a* key and does not care which.
///
/// # Errors
///
/// Returns a [`ToolError`] if the config cannot be resolved, or any configured identity file
/// is missing or cannot be read/parsed.
pub fn load_all_provider_secrets(config_path: Option<&Path>) -> Result<Vec<SecretKey>, ToolError> {
    let identities = resolve_identities(config_path)?;
    let mut out = Vec::with_capacity(identities.len());
    for (i, path) in identities.iter().enumerate() {
        if !path.exists() {
            // The primary and a retired key fail for different reasons, so say which.
            return Err(ToolError::user(if i == 0 {
                format!(
                    "no provider identity at {}; decrypting needs the key the package was \
                     wrapped to, and minting a new one here could not decrypt anything. Run \
                     `gdi-dataset-tool keys generate` if you have no identity yet, or point \
                     [keys].identities at the key it was wrapped to. Identities resolve under \
                     the config directory, so `--config` can select a different key set than \
                     the default.",
                    path.display()
                )
            } else {
                format!(
                    "configured provider identity is missing: {} (it is a retired key in \
                     [keys].identities; restore it or remove it from the list)",
                    path.display()
                )
            }));
        }
        out.push(load_identity_at(path)?);
    }
    Ok(out)
}

/// The provider's own recipient (public key) derived from the primary identity.
///
/// # Errors
///
/// Propagates any failure from [`load_or_generate_provider_secret`].
pub fn provider_recipient(config_path: Option<&Path>) -> Result<PublicKey, ToolError> {
    Ok(load_or_generate_provider_secret(config_path)?.public_key())
}

/// The provider's own recipient (public key) without minting one.
///
/// The variant every verb that also decrypts must use. `rekey` resolves recipients before
/// loading the identities it decrypts with, so reaching [`provider_recipient`] there would
/// run the minting path first and create the very file the absent-key diagnostic exists to
/// complain about.
///
/// # Errors
///
/// Propagates any failure from [`load_provider_secret_readonly`], including the absent-key
/// diagnostic that names the resolved path.
pub fn provider_recipient_readonly(config_path: Option<&Path>) -> Result<PublicKey, ToolError> {
    Ok(load_provider_secret_readonly(config_path)?.public_key())
}

/// Load the primary provider secret identity **without** generating it (the
/// read-only path `doctor` uses, which must stay side-effect-free).
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) if the config cannot be resolved, the primary
/// key file is absent, or it cannot be read / parsed.
pub fn load_provider_secret_readonly(config_path: Option<&Path>) -> Result<SecretKey, ToolError> {
    Ok(load_provider_secret_readonly_at(config_path)?.0)
}

/// As [`load_provider_secret_readonly`], but also reports the PATH the key was loaded
/// from.
///
/// The path is what makes the key's on-disk posture observable to a caller. The loader
/// itself only warns about a group/world-readable key, on stderr, where no `--format json`
/// consumer sees it — and `doctor`, whose job is to certify the setup, must not report
/// `"ok": true` for a condition the node refuses to start under (`identities.rs`,
/// `strict_key_perms`). Handing back the path lets the certifier re-stat and grade it
/// instead of inheriting the loader's rung.
///
/// # Errors
///
/// Identical to [`load_provider_secret_readonly`].
pub fn load_provider_secret_readonly_at(
    config_path: Option<&Path>,
) -> Result<(SecretKey, PathBuf), ToolError> {
    let identities = resolve_identities(config_path)?;
    let secret_path = primary(&identities)?;
    if !secret_path.exists() {
        return Err(ToolError::user(format!(
            "no provider identity at {} (run `keys generate`)",
            secret_path.display()
        )));
    }
    Ok((load_identity_at(secret_path)?, secret_path.clone()))
}

/// `keys pin-recipient`: resolve the node recipient (explicit `--file` or `--url`, else
/// the active profile's online URL, else its offline file) and pin it to a local file
/// with trust-on-first-use change-detection.
///
/// `--file` is the air-gapped path for a rotated node key handed over on removable media.
/// `wizard setup --recipient` refuses a differing pin and has no `--force`, so without
/// `--file` there is no way to install one.
///
/// The active profile is loaded lazily — only when `--url` or `--output` are not
/// both explicitly supplied — so a fully self-contained invocation (both flags
/// provided) does not require a profile to be configured.
fn pin_recipient(
    args: &KeysPinRecipientArgs,
    profile_name: Option<&str>,
    config_path: Option<&Path>,
) -> Result<(), ToolError> {
    // Resolve the recipient public key.
    let pk = if let Some(file) = args.file.as_deref() {
        recipient::read_node_recipient_file(file)?
    } else if let Some(url) = args.url.as_deref() {
        runtime::block_on(recipient::fetch_node_recipient(url))?
    } else {
        // Need the profile to know the URL or the offline file.
        let active = profile::load_active(config_path, profile_name)?;
        if let Some(url) = recipient::node_recipient_url(&active) {
            runtime::block_on(recipient::fetch_node_recipient(&url))?
        } else if let Some(file) = active.node_recipient_path(config_path) {
            recipient::read_node_recipient_file(&file)?
        } else {
            return Err(ToolError::user(
                "no recipient source: pass --url, or set the profile's service_url / \
                 node_recipient_url / node_recipient_file",
            ));
        }
    };
    // Resolve the output path: --output, else the profile's node_recipient_file,
    // else the URL-keyed pin path <config_dir>/recipients/<host>.<hash>.pub.
    let out = if let Some(p) = args.output.clone() {
        p
    } else {
        // Need the profile to know the output path.
        let active = profile::load_active(config_path, profile_name)?;
        // Through the resolver, not `PathBuf::from(raw)`: a relative `node_recipient_file`
        // is config-dir-relative for every reader (`pack`, `doctor`, `keys show`), so
        // resolving it against the CWD would write the pin where nothing looks. `pack` would
        // then fail closed telling the operator to run the command that had just
        // "succeeded", and after a real rotation `--force` would keep writing a fresh CWD
        // file while the stale pin still governed.
        if let Some(file) = active.node_recipient_path(config_path) {
            file
        } else {
            // The same rule the verifier reads, not a second spelling of it: the pin is
            // keyed on the node's recipient URL. Writing a profile-name-keyed file here
            // would put a pin somewhere `verify_fetched_readonly` never looks — a pin that
            // exists and anchors nothing is worse than no pin, because `keys show` would
            // report the key as pinned.
            recipient::default_recipient_pin_path(&active, config_path).ok_or_else(|| {
                ToolError::user(
                    "cannot place a trust-on-first-use pin: the profile has no service_url \
                     or node_recipient_url to key it on, and no --output was given. Pass \
                     --output <PATH>, or set node_recipient_file.",
                )
            })?
        }
    };

    crate::output::progress(&format!(
        "recipient fingerprint: {}",
        public_key_fingerprint(&pk)
    ));
    match recipient::write_pinned_recipient(&pk, &out, args.force)? {
        recipient::PinOutcome::Created => {
            println!("pinned node recipient to {}", out.display());
        }
        recipient::PinOutcome::Unchanged => {
            println!(
                "node recipient already pinned at {} (unchanged)",
                out.display()
            );
        }
        recipient::PinOutcome::Replaced => {
            println!("replaced pinned node recipient at {}", out.display());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

    #[test]
    fn minting_a_provider_identity_is_announced_with_its_fingerprint() {
        // `pack`/`package` mint a fresh sender key whenever the resolved config dir holds
        // no identity — which a `--config` typo or a fresh checkout produces just as easily
        // as a genuine first run. That key is the package's crypt4gh writer provenance, the
        // value `[ingest].writer_policy = enforce` gates on, so a silent mint would silently
        // change who the node believes authored every package built afterwards.
        let msg = minted_identity_warning(
            std::path::Path::new("/cfg/identities/provider.pem"),
            "sha256:abc123",
        );
        assert!(msg.contains("/cfg/identities/provider.pem"), "{msg}");
        assert!(
            msg.contains("sha256:abc123"),
            "the fingerprint is the actionable part; it is what gets allow-listed: {msg}"
        );
        assert!(
            msg.contains("writer_policy"),
            "say why it matters, not just that a key was made: {msg}"
        );
        assert!(
            msg.contains("--config"),
            "name the usual cause so the operator can check it before packaging: {msg}"
        );
    }

    #[test]
    fn a_first_use_mint_actually_creates_the_key_and_a_reload_does_not_re_mint() {
        // The mint path must remain a genuine first-use-only path: a second call loads.
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = dir.path().join("config.toml");
        std::fs::write(&cfg, "").expect("write config");

        let first = load_or_generate_provider_secret(Some(&cfg)).expect("mints on first use");
        let second = load_or_generate_provider_secret(Some(&cfg)).expect("loads on second use");
        assert_eq!(
            public_key_fingerprint(&first.public_key()),
            public_key_fingerprint(&second.public_key()),
            "a second call must load the minted key, not mint another; a changed writer \
             fingerprint between two packages of the same run would be undetectable"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_world_readable_provider_key_is_reported_on_every_read() {
        // The module doc calls 0o600 the protection, so every read path must verify it:
        // pack, package, rekey, unpack, inspect, validate, check and doctor all funnel
        // through `load_identity_at`. The node refuses startup on exactly this condition.
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("provider.pem");
        std::fs::write(&path, b"unused").expect("write");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        assert!(
            loose_permission_warning(&path).is_none(),
            "the intended posture must not warn"
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let msg = loose_permission_warning(&path).expect("0o644 must be reported");
        assert!(msg.contains("644"), "name the actual mode: {msg}");
        assert!(msg.contains("chmod 600"), "give the remedy: {msg}");
    }

    use super::*;
    use gdi_node_standalone_core::faults::{FaultPoint, arm_enospc};
    use serial_test::serial;

    /// The non-minting recipient accessor must not create a key, and must say which path
    /// it looked at.
    ///
    /// `rekey` resolves recipients before loading the identities it decrypts with, so the
    /// minting variant here would run first: with `[keys].identities` pointing at an
    /// unmounted encrypted volume it would `create_dir_all` the bare mountpoint, mint a
    /// shadow key there, and then fail with an opaque crypto error instead of the config-dir
    /// diagnostic.
    #[test]
    fn readonly_recipient_does_not_mint_a_provider_key() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("tool.toml");
        let keys = dir.path().join("keys");
        std::fs::write(
            &cfg,
            format!(
                "[keys]\nidentities = [\"{}\"]\n",
                keys.join("provider.c4gh").display()
            ),
        )
        .unwrap();

        let err = provider_recipient_readonly(Some(&cfg))
            .expect_err("no provider key exists, so this must fail rather than mint one");

        assert!(
            !keys.exists(),
            "the read-only path must not create the identities directory"
        );
        assert!(
            err.to_string().contains("provider.c4gh"),
            "the error should name the path it looked at: {err}"
        );

        // The discriminator: the minting variant, in the identical setup, creates the key
        // and the directories under it. That difference is the whole point — without it
        // this test would pass against a mere rename of the minting path.
        provider_recipient(Some(&cfg)).expect("the minting variant mints");
        assert!(
            keys.join("provider.c4gh").exists(),
            "provider_recipient must mint, so the two paths genuinely differ"
        );
    }

    /// A crash (here an injected `ENOSPC`) while writing the `.pub` recipient must be
    /// surfaced as an error — proving the recipient goes through the durable atomic
    /// writer (which the fault seam guards) rather than a plain `fs::write` (which the
    /// seam cannot see, so an in-flight failure would be silently swallowed leaving a
    /// durable secret beside a torn/absent `.pub`). Keyed on `.pub` so the fault fires
    /// on the public write, never the secret write that precedes it.
    #[test]
    #[serial(faults)]
    fn public_recipient_write_is_durable() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("id.key");
        let _fault = arm_enospc(FaultPoint::DurableWrite, ".pub", 1);
        // `SecretKey` is not `Debug` (secret material), so match rather than `expect_err`.
        assert!(
            generate_identity_at(&secret).is_err(),
            "an ENOSPC on the .pub write must fail generate_identity_at, not be swallowed"
        );
        // The secret is written durably first (its path holds no `.pub`, so the armed
        // fault did not fire on it); only the recipient write hit the fault.
        assert!(
            secret.exists(),
            "the secret key should have been written before the faulted .pub write"
        );
    }
}
