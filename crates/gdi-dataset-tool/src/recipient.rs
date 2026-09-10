//! Resolving the node's crypt4gh recipient, and the trust-on-first-use pinning that
//! anchors it.
//!
//! Online the recipient is fetched from the profile's `node_recipient_url` (which
//! defaults to `{service_url}/.well-known/c4gh-recipient`); offline it is read from
//! the local `node_recipient_file` (or a `--recipient` override). A fetched key is
//! checked against a pin before anything is encrypted to it, and the enforcing path
//! fails closed on any mismatch.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use gdi_node_standalone_core::config::Profile;
use gdi_node_standalone_core::crypt4gh::{PublicKey, parse_public_key, serialize_public_key};

use crate::ToolError;

/// Timeout for the node-recipient URL fetch.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// The default node-recipient path appended to `service_url`.
const WELL_KNOWN_RECIPIENT: &str = "/.well-known/c4gh-recipient";

/// Resolve the node-recipient **URL** for a profile: the explicit
/// `node_recipient_url`, else `{service_url}/.well-known/c4gh-recipient`.
#[must_use]
pub fn node_recipient_url(active: &Profile) -> Option<String> {
    if let Some(url) = active.node_recipient_url.as_deref() {
        return Some(url.to_owned());
    }
    active
        .service_url
        .as_deref()
        .map(|base| format!("{}{WELL_KNOWN_RECIPIENT}", base.trim_end_matches('/')))
}

/// Maximum node-recipient response body. A crypt4gh recipient PEM is ~100-200
/// bytes; 64 KiB is far above any real value and bounds a misbehaving or hostile
/// `node_recipient_url` that streams an unbounded body into the provider host.
const MAX_RECIPIENT_BYTES: usize = 64 * 1024;

/// Error if `total` bytes would exceed [`MAX_RECIPIENT_BYTES`] for `url`.
fn check_recipient_len(url: &str, total: usize) -> Result<(), ToolError> {
    if total > MAX_RECIPIENT_BYTES {
        return Err(ToolError::user(format!(
            "node recipient {url} body exceeds {MAX_RECIPIENT_BYTES} bytes"
        )));
    }
    Ok(())
}

/// Fetch + parse the node recipient from a URL.
///
/// # Errors
///
/// Returns a [`ToolError`] when the client cannot be built, the URL is unreachable /
/// non-2xx, or the body is not a valid crypt4gh recipient. A 401/403 response is an auth
/// failure (exit 4, `EXIT_AUTH`); every other failure is a user error (exit 1, `EXIT_USER`).
pub async fn fetch_node_recipient(url: &str) -> Result<PublicKey, ToolError> {
    require_secure_transport(
        url,
        "a MITM could substitute the recipient key so the dataset is encrypted to an attacker.",
    )?;
    let client = gdi_node_standalone_core::tls::https_client_builder()
        .timeout(FETCH_TIMEOUT)
        .build()
        .map_err(|e| ToolError::user(format!("cannot build HTTP client: {e}")))?;
    let mut resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| ToolError::user(format!("cannot fetch node recipient {url}: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let msg = format!("node recipient {url} returned {status}");
        let is_auth_failure =
            status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN;
        return Err(if is_auth_failure {
            ToolError::auth(msg)
        } else {
            ToolError::user(msg)
        });
    }
    // Read the body with a hard cap (streaming, so a hostile node cannot allocate
    // an unbounded body): reject an oversized Content-Length up front, then bound
    // the accumulated chunks.
    if let Some(len) = resp.content_length() {
        check_recipient_len(url, usize::try_from(len).unwrap_or(usize::MAX))?;
    }
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| ToolError::user(format!("cannot read node recipient body: {e}")))?
    {
        check_recipient_len(url, body.len().saturating_add(chunk.len()))?;
        body.extend_from_slice(&chunk);
    }
    let pem = String::from_utf8(body)
        .map_err(|e| ToolError::user(format!("node recipient {url} body is not UTF-8: {e}")))?;
    parse_public_key(&pem).map_err(|e| {
        ToolError::user(format!(
            "node recipient {url} is not a valid recipient: {e}"
        ))
    })
}

/// Require HTTPS for a remote fetch URL, exempting loopback.
///
/// Data fetched from the node over plaintext HTTP can be substituted by a MITM /
/// DNS-spoof / compromised endpoint. HTTPS is therefore required for a non-loopback
/// host; a loopback URL (`localhost` / `127.0.0.0/8` / `::1`, the local-development
/// case) is exempt. An in-cluster service reached over the pod network is not loopback,
/// so use https there. `mitm_hint` names the concrete consequence for the caller's payload
/// (recipient-key substitution, forged catalog list) and is appended to the error.
///
/// # Errors
///
/// Returns a [`ToolError`] when `url` is unparseable, or is plaintext `http` to a
/// non-loopback host.
pub(crate) fn require_secure_transport(url: &str, mitm_hint: &str) -> Result<(), ToolError> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|e| ToolError::user(format!("url {url} is not a valid URL: {e}")))?;
    match gdi_node_standalone_core::tls::transport_reason(&parsed) {
        None => Ok(()),
        Some(reason) => Err(ToolError::user(format!("{reason} {mitm_hint}"))),
    }
}

/// Verify a freshly-fetched node recipient against a trust-on-first-use pin file, if one
/// exists.
///
/// The pin, written by `keys pin-recipient` or the setup wizard into
/// `node_recipient_file`, is the operator's trusted node key. Encryption uses the online
/// fetch, so the fetched key must match the pin whenever one is present, or a MITM,
/// DNS-spoof or compromised endpoint could substitute the recipient. A missing pin file is
/// a no-op: there is nothing to verify against.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) when the pin exists and holds a different key, or
/// cannot be read or parsed.
pub fn verify_fetched_against_pin(fetched: &PublicKey, pin_path: &Path) -> Result<(), ToolError> {
    if !pin_path.exists() {
        return Ok(());
    }
    let pinned = read_node_recipient_file(pin_path)?;
    if pinned.as_bytes() != fetched.as_bytes() {
        return Err(ToolError::user(format!(
            "fetched node recipient differs from the pinned key at {} (rotation, or a \
             man-in-the-middle). After verifying the new key out-of-band, re-pin with \
             `gdi-dataset-tool keys pin-recipient --force`.",
            pin_path.display()
        )));
    }
    Ok(())
}

/// Fail closed when an explicitly-configured `node_recipient_file` pin is absent.
///
/// A configured pin is the authoritative node-recipient trust anchor, so a missing file is
/// a misconfiguration, not the benign "nothing to verify against" no-op that
/// [`verify_fetched_against_pin`] applies to the trust-on-first-use default path. Without
/// this check a configured-but-absent pin would accept the fetched key unverified and
/// unpinned, and would bypass any working default pin, because the configured branch
/// returns before the default in [`enforce_recipient_trust`] and
/// [`verify_fetched_readonly`].
///
/// # Errors
/// Returns a [`ToolError`] (exit 1) when `pin` does not exist.
fn require_configured_pin_exists(pin: &Path) -> Result<(), ToolError> {
    if pin.exists() {
        return Ok(());
    }
    Err(ToolError::user(format!(
        "configured node_recipient_file {} does not exist; a configured pin is the \
         authoritative node-recipient trust anchor and must be present. Create it with \
         `gdi-dataset-tool keys pin-recipient`, or remove node_recipient_file from the \
         profile to fall back to trust-on-first-use.",
        pin.display()
    )))
}

/// The offline fallback for a failed online recipient fetch: the profile's configured
/// `node_recipient_file` pin, else an existing trust-on-first-use pin.
///
/// Encrypting to the pin is what a successful fetch would have been verified against
/// anyway, since [`enforce_recipient_trust`] requires fetched == pin, so this fallback
/// cannot weaken trust. The worst case is a key the node rotated away from while
/// unreachable, which fails at ingest, never at disclosure. Without the fallback, a
/// wizard-made offline profile could not pack at all: setup makes `service_url`
/// mandatory, the recipient URL derives from it, and a fetch failure would be a hard
/// error telling the operator to set the `node_recipient_file` they already set.
///
/// Returns `None` when no pin exists to fall back to, in which case the caller keeps its
/// fetch error; `Some(Ok((key, pin_path)))` on a usable pin; and `Some(Err(_))` when a pin
/// is configured but unusable. A configured pin is the authoritative trust anchor, so a
/// missing or invalid file stays a hard error rather than falling through to the
/// trust-on-first-use path.
#[must_use]
pub fn offline_pin_fallback(
    configured: Option<&Path>,
    default_pin: Option<&Path>,
) -> Option<Result<(PublicKey, PathBuf), ToolError>> {
    if let Some(pin) = configured {
        return Some(
            require_configured_pin_exists(pin)
                .and_then(|()| read_node_recipient_file(pin))
                .map(|pk| (pk, pin.to_path_buf())),
        );
    }
    let pin = default_pin?;
    pin.exists()
        .then(|| read_node_recipient_file(pin).map(|pk| (pk, pin.to_path_buf())))
}

/// Read + parse the node recipient from a local file.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) when the file cannot be read or is not a valid
/// crypt4gh recipient.
pub fn read_node_recipient_file(path: &Path) -> Result<PublicKey, ToolError> {
    let pem = std::fs::read_to_string(path)
        .map_err(|e| ToolError::user(format!("cannot read recipient {}: {e}", path.display())))?;
    parse_public_key(&pem)
        .map_err(|e| ToolError::user(format!("invalid recipient {}: {e}", path.display())))
}

/// The result of pinning a node recipient to a local file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinOutcome {
    /// No pin existed; the recipient was written.
    Created,
    /// A pin with the identical key already existed; nothing changed.
    Unchanged,
    /// A pin with a different key existed and `--force` replaced it.
    Replaced,
}

/// Write `pk` as a crypt4gh recipient PEM to `out`, with trust-on-first-use
/// change-detection.
///
/// If `out` does not exist, the key is written ([`PinOutcome::Created`]). If it exists and
/// holds the same key, this is a no-op ([`PinOutcome::Unchanged`]). If it holds a different
/// key, the write is refused unless `force` is set, because a changed node key is either a
/// legitimate rotation or a man-in-the-middle and the operator must opt in; with `force` it
/// is overwritten ([`PinOutcome::Replaced`]).
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) when an existing pin differs and `force` is false, when
/// an existing pin cannot be read or parsed, or on a filesystem error.
pub fn write_pinned_recipient(
    pk: &PublicKey,
    out: &Path,
    force: bool,
) -> Result<PinOutcome, ToolError> {
    let outcome = if out.exists() {
        let existing = read_node_recipient_file(out)?;
        if existing.as_bytes() == pk.as_bytes() {
            return Ok(PinOutcome::Unchanged);
        }
        if !force {
            return Err(ToolError::user(format!(
                "pinned node recipient at {} differs from the key presented (rotation, or \
                 a man-in-the-middle). If the rotation is genuine, replace the pin with \
                 `keys pin-recipient --force`; add `--file <PATH>` for a key handed over \
                 offline.",
                out.display()
            )));
        }
        PinOutcome::Replaced
    } else {
        PinOutcome::Created
    };
    if let Some(parent) = out.parent()
        && !parent.as_os_str().is_empty()
    {
        #[expect(
            clippy::disallowed_methods,
            reason = "operator-chosen key directory; the key file itself is written 0600"
        )]
        fs::create_dir_all(parent)
            .map_err(|e| ToolError::user(format!("cannot create {}: {e}", parent.display())))?;
    }
    // The pin is a trust anchor: `pack` fails closed against it. A torn or half-written
    // pin is a trust failure, not a lost convenience file, so write it durably.
    #[expect(
        clippy::disallowed_methods,
        reason = "not secret: a serialized PUBLIC recipient key, which is meant to be shared"
    )]
    gdi_node_standalone_core::util::write_durable_atomic(out, serialize_public_key(pk).as_bytes())
        .map_err(|e| ToolError::user(format!("cannot write {}: {e}", out.display())))?;
    Ok(outcome)
}

/// The result of applying the node-recipient trust policy on an online fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustOutcome {
    /// The fetched key matched an explicitly-configured `node_recipient_file` pin.
    VerifiedConfigured,
    /// No pin existed at the conventional path; the key was recorded there
    /// (trust-on-first-use).
    PinnedOnFirstUse,
    /// The fetched key matched an existing trust-on-first-use pin.
    VerifiedTofu,
    /// No configured pin and no conventional pin path available: unverified.
    Unpinned,
}

/// Apply the node-recipient trust policy to a freshly-fetched key.
///
/// An explicitly-configured `configured_pin` is authoritative and the fetched key must
/// match it. Otherwise, when a conventional `default_pin` path is available, the key is
/// pinned trust-on-first-use there: the first fetch records it and every later fetch must
/// match, so an endpoint compromised later cannot substitute the recipient on a subsequent
/// `pack` or `build`. With neither pin the fetched key is unverified
/// ([`TrustOutcome::Unpinned`]), which happens for a profile with only a `service_url` and
/// no resolvable config directory. `cmd_pack::resolve_trust_decision` then fails closed on
/// that outcome rather than encrypting to an unanchored key.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) when the fetched key differs from a configured pin, or
/// from an existing trust-on-first-use pin. That is either a legitimate rotation or a
/// man-in-the-middle, and the operator must re-pin out-of-band with
/// `keys pin-recipient --force`.
pub fn enforce_recipient_trust(
    fetched: &PublicKey,
    configured_pin: Option<&Path>,
    default_pin: Option<&Path>,
) -> Result<TrustOutcome, ToolError> {
    if let Some(pin) = configured_pin {
        require_configured_pin_exists(pin)?;
        verify_fetched_against_pin(fetched, pin)?;
        return Ok(TrustOutcome::VerifiedConfigured);
    }
    if let Some(pin) = default_pin {
        return Ok(match write_pinned_recipient(fetched, pin, false)? {
            PinOutcome::Created => TrustOutcome::PinnedOnFirstUse,
            // `force` is false, so `Replaced` is unreachable; a matching key is
            // `Unchanged`, a differing key already returned `Err` above.
            PinOutcome::Unchanged | PinOutcome::Replaced => TrustOutcome::VerifiedTofu,
        });
    }
    Ok(TrustOutcome::Unpinned)
}

/// The conventional trust-on-first-use pin path for a node:
/// `<config_dir>/recipients/<host>.<hash>.pub`, keyed on the node's recipient URL (see
/// [`pin_file_name`]). This is the location `keys pin-recipient` defaults to and that
/// [`enforce_recipient_trust`] pins into. `None` when the profile carries no recipient URL
/// to key on, or no config directory can be resolved.
///
/// The setup wizard writes a profile-named file instead, but records it as the profile's
/// `node_recipient_file`, which makes it a configured pin, found by the configured branch
/// rather than by this path.
#[must_use]
pub(crate) fn default_recipient_pin_path(
    active: &Profile,
    config_path: Option<&Path>,
) -> Option<PathBuf> {
    let url = node_recipient_url(active)?;
    gdi_node_standalone_core::config::config_base_dir(config_path)
        .map(|d| d.join("recipients").join(pin_file_name(&url)))
}

/// The pin location for a run with no `--config`: `<config_dir>/recipients/…`, resolved
/// from the environment alone rather than from the config file's own directory.
///
/// `None` when it would be the same path [`default_recipient_pin_path`] returns, so a run
/// with no `--config` (the common case) has no second location at all.
#[must_use]
fn legacy_recipient_pin_path(active: &Profile, config_path: Option<&Path>) -> Option<PathBuf> {
    let canonical = default_recipient_pin_path(active, config_path)?;
    let url = node_recipient_url(active)?;
    #[expect(
        clippy::disallowed_methods,
        reason = "the legacy location is the environment default by definition: this is the \
                  one reader of pins written before `--config` resolved beside the file"
    )]
    let legacy = gdi_node_standalone_core::config::config_dir()
        .map(|d| d.join("recipients").join(pin_file_name(&url)))?;
    (legacy != canonical).then_some(legacy)
}

/// The pin path to read for trust verification: the canonical one, or, when only a pin in
/// the environment-default config directory exists, that one, with a warning naming both.
///
/// The fallback exists because the alternative is silent and fails open. An unfound pin is
/// not an error, it is trust-on-first-use, so moving the store without reading the old
/// location would let the next `pack` re-pin whatever key the node then serves: the
/// substitution the pin defends against. The old pin keeps governing until it is moved, and
/// the warning says how.
///
/// Writers ([`crate::commands::cmd_keys`]'s `pin-recipient`) do not use this: a new pin
/// belongs at the canonical path, so re-pinning migrates the store.
#[must_use]
pub(crate) fn recipient_pin_path_for_read(
    active: &Profile,
    config_path: Option<&Path>,
) -> Option<PathBuf> {
    let canonical = default_recipient_pin_path(active, config_path)?;
    if canonical.exists() {
        return Some(canonical);
    }
    match legacy_recipient_pin_path(active, config_path) {
        Some(legacy) if legacy.exists() => {
            crate::output::warn(&format!(
                "reading the node-recipient pin from the default config directory {}. Under \
                 `--config` it resolves beside the config file, at {}. Re-run \
                 `keys pin-recipient` after confirming the fingerprint out-of-band, or move \
                 the file, so one invocation keeps its key material in one place.",
                legacy.display(),
                canonical.display()
            ));
            Some(legacy)
        }
        _ => Some(canonical),
    }
}

/// The pin filename for a node-recipient URL: `{host}.{16 hex}.pub`.
///
/// Keyed on the URL, which is the node's identity and therefore what the pin anchors.
/// Keying on the profile name is wrong in both directions: two configs both naming
/// `default` for different nodes collide, surfacing as a false MITM whose documented remedy
/// is `--force`, which trains an operator to wave past a real substitution; and one node
/// reached under two profile names gets two independent pins, so a substitution detected
/// under one name is invisible under the other.
///
/// The URL is normalised by trimming a trailing `/` so one node cannot acquire two pins on
/// a spelling difference. The host prefix is for the operator reading `ls recipients/`; the
/// hash is what distinguishes, so the prefix is sanitized rather than trusted.
fn pin_file_name(url: &str) -> String {
    let normalised = url.trim_end_matches('/');
    // core's shared hasher: the tool declares no `sha2` dependency of its own, and adding
    // one just to name a file would be a new crate for no new capability.
    let (hex, _) = gdi_node_standalone_core::util::sha256_hex_reader(normalised.as_bytes())
        .unwrap_or_else(|_| (String::new(), 0));
    let hash: String = hex.chars().take(16).collect();

    // Host, for legibility only: between "://" and the next "/", with anything outside a
    // conservative filename set folded to `_` so a hostile URL cannot escape the directory.
    let host: String = normalised
        .split_once("://")
        .map_or(normalised, |(_, rest)| rest)
        .split('/')
        .next()
        .unwrap_or("node")
        .chars()
        .take(40)
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let host = if host.is_empty() || host.starts_with('.') {
        "node".to_owned()
    } else {
        host
    };
    format!("{host}.{hash}.pub")
}

/// The read-only trust status of a fetched node recipient, for the diagnostic/display
/// commands (`doctor`, `keys show`) that must not write a pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReadonlyTrust {
    /// Matched an explicitly-configured `node_recipient_file` pin.
    VerifiedConfigured,
    /// Matched an existing trust-on-first-use pin.
    VerifiedTofu,
    /// No pin anchors the key yet, but one can: a later `pack` pins it on first use.
    Unpinned,
    /// A pin exists and the fetched key disagrees with it: the substitution or MITM
    /// condition, and the strongest signal this tool can produce.
    ///
    /// Carried as a value rather than an `Err` so the diagnostic commands cannot render it
    /// as "something went wrong". Collapsing it into an error would render `keys show` as
    /// `<unavailable: …>`, the same shape as an unreachable node, a 404 or a 500, and exit
    /// 0, leaving the worse case with no `trust:` line while the milder `Unpinned` gets one.
    ///
    /// The enforcing path (`enforce_recipient_trust`, used by `pack`) still fails closed;
    /// only the read-only diagnostic view classifies instead of erroring.
    Substituted(String),
    /// No pin can be established at all: no configured `node_recipient_file` and no
    /// resolvable config directory to hold a trust-on-first-use pin.
    ///
    /// Distinct from [`ReadonlyTrust::Unpinned`] because the two lead to opposite outcomes
    /// at `pack`: `Unpinned` pins on first use and proceeds, while this state makes `pack`
    /// refuse to encrypt ("no trust anchor ... no resolvable config directory to pin it").
    /// A diagnostic that reports them alike green-lights a setup that cannot pack.
    Unpinnable,
}

/// Verify a freshly-fetched node recipient against whatever pin anchors it, without
/// writing one, unlike [`enforce_recipient_trust`], which pins on first use. For the
/// diagnostic and display commands, which must not mutate the pin store: a configured pin
/// is authoritative, else an existing trust-on-first-use pin is checked. With neither, the
/// key is [`ReadonlyTrust::Unpinned`] when a pin path exists to anchor it later, and
/// [`ReadonlyTrust::Unpinnable`] when none does, which is the state `pack` refuses.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) when the fetched key differs from a configured pin or
/// an existing trust-on-first-use pin: the substitution condition `pack` refuses.
pub(crate) fn verify_fetched_readonly(
    fetched: &PublicKey,
    configured_pin: Option<&Path>,
    default_pin: Option<&Path>,
) -> Result<ReadonlyTrust, ToolError> {
    if let Some(pin) = configured_pin {
        require_configured_pin_exists(pin)?;
        return match verify_fetched_against_pin(fetched, pin) {
            Ok(()) => Ok(ReadonlyTrust::VerifiedConfigured),
            Err(e) => Ok(ReadonlyTrust::Substituted(e.message)),
        };
    }
    if let Some(pin) = default_pin.filter(|p| p.exists()) {
        // Classify the mismatch rather than propagating it: see `ReadonlyTrust::Substituted`.
        // A failure to read the pin is a different thing and still propagates.
        return match verify_fetched_against_pin(fetched, pin) {
            Ok(()) => Ok(ReadonlyTrust::VerifiedTofu),
            Err(e) => Ok(ReadonlyTrust::Substituted(e.message)),
        };
    }
    match default_pin {
        Some(_) => Ok(ReadonlyTrust::Unpinned),
        None => Ok(ReadonlyTrust::Unpinnable),
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
mod tests {
    use std::io::Write as _;
    use std::net::TcpListener;

    use gdi_node_standalone_core::tls::transport_reason;

    use super::*;

    #[test]
    #[serial_test::serial(env)]
    fn the_tofu_pin_is_keyed_on_the_node_not_the_profile_name() {
        // The pin anchors a node, so it is keyed on the node's recipient URL, never on
        // the profile name. A profile-keyed pin is wrong in both directions:
        //
        //   * two configs both naming `default` for different nodes collide, and the
        //     collision surfaces as a false MITM whose documented remedy is `--force` —
        //     training an operator to wave past the one signal that means a real
        //     substitution;
        //   * the same node reached under two profile names gets two independent pins, so
        //     a substitution seen under one name is invisible under the other.
        let dir = tempfile::tempdir().unwrap();
        let _prev = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path());

        let node_a = Profile {
            service_url: Some("https://node-a.example.org".to_owned()),
            ..Profile::default()
        };
        let node_a_again = Profile {
            service_url: Some("https://node-a.example.org/".to_owned()),
            ..Profile::default()
        };
        let node_b = Profile {
            service_url: Some("https://node-b.example.org".to_owned()),
            ..Profile::default()
        };

        let a = default_recipient_pin_path(&node_a, None).expect("a resolvable pin path");
        let a2 = default_recipient_pin_path(&node_a_again, None).expect("a resolvable pin path");
        let b = default_recipient_pin_path(&node_b, None).expect("a resolvable pin path");

        assert_eq!(
            a, a2,
            "one node must have ONE pin however its URL is spelled — otherwise a \
             substitution detected under one profile is invisible under another"
        );
        assert_ne!(a, b, "different nodes must never share a pin");

        // An explicit node_recipient_url is the identity when set: it is what is fetched.
        let explicit = Profile {
            service_url: Some("https://node-b.example.org".to_owned()),
            node_recipient_url: Some(
                "https://node-a.example.org/.well-known/c4gh-recipient".to_owned(),
            ),
            ..Profile::default()
        };
        assert_eq!(
            default_recipient_pin_path(&explicit, None).expect("path"),
            a,
            "the pin follows the URL actually fetched, not the service_url beside it"
        );

        // A profile with nothing to fetch has nothing to pin.
        assert!(default_recipient_pin_path(&Profile::default(), None).is_none());
    }

    #[test]
    fn enforce_recipient_trust_pins_on_first_use_and_detects_change() {
        use gdi_node_standalone_core::crypt4gh::generate_keypair;
        let dir = tempfile::tempdir().unwrap();
        let (_ska, pk_a) = generate_keypair();
        let (_skb, pk_b) = generate_keypair();
        // A nested path the helper must create on first pin.
        let default_pin = dir.path().join("recipients").join("default.pub");

        // No configured pin and no existing default pin -> trust-on-first-use.
        assert_eq!(
            enforce_recipient_trust(&pk_a, None, Some(&default_pin)).unwrap(),
            TrustOutcome::PinnedOnFirstUse
        );
        assert!(
            default_pin.exists(),
            "first use must write the conventional pin"
        );

        // The same endpoint key on a later fetch -> verified against the TOFU pin.
        assert_eq!(
            enforce_recipient_trust(&pk_a, None, Some(&default_pin)).unwrap(),
            TrustOutcome::VerifiedTofu
        );

        // A substituted key on a later fetch -> rejected (MITM / rotation).
        let err = enforce_recipient_trust(&pk_b, None, Some(&default_pin)).unwrap_err();
        assert!(err.message.contains("differs"), "got: {}", err.message);

        // An explicitly-configured pin is authoritative and takes precedence.
        let configured = dir.path().join("configured.pub");
        write_pinned_recipient(&pk_b, &configured, false).unwrap();
        assert_eq!(
            enforce_recipient_trust(&pk_b, Some(&configured), Some(&default_pin)).unwrap(),
            TrustOutcome::VerifiedConfigured
        );

        // Neither pin -> unverified; `cmd_pack` refuses to encrypt on this outcome.
        assert_eq!(
            enforce_recipient_trust(&pk_a, None, None).unwrap(),
            TrustOutcome::Unpinned
        );
    }

    #[test]
    fn configured_but_absent_pin_fails_closed() {
        // A configured `node_recipient_file` that does not exist must be a hard error,
        // never a silent no-op that accepts the fetched key unverified and unpinned. The
        // configured branch returns before the trust-on-first-use default, so an absent
        // configured pin must not silently bypass a working TOFU pin either. Both the
        // enforcing (pack/build) and read-only (doctor / keys show) paths fail closed.
        use gdi_node_standalone_core::crypt4gh::generate_keypair;
        let dir = tempfile::tempdir().unwrap();
        let (_sk, pk) = generate_keypair();
        let absent = dir.path().join("configured-but-missing.pub");
        // A working TOFU default pin also exists — the configured-absent case must still
        // fail closed rather than fall through to (or bypass) it.
        let default_pin = dir.path().join("recipients").join("default.pub");
        write_pinned_recipient(&pk, &default_pin, false).unwrap();

        let err = enforce_recipient_trust(&pk, Some(&absent), Some(&default_pin)).unwrap_err();
        assert!(
            err.message.contains("node_recipient_file") && err.message.contains("does not exist"),
            "enforce: a configured-but-absent pin must fail closed naming the file: {}",
            err.message
        );
        let err = verify_fetched_readonly(&pk, Some(&absent), Some(&default_pin)).unwrap_err();
        assert!(
            err.message.contains("node_recipient_file") && err.message.contains("does not exist"),
            "readonly: a configured-but-absent pin must fail closed naming the file: {}",
            err.message
        );
    }

    #[test]
    fn offline_pin_fallback_prefers_the_configured_pin_and_fails_closed_without_it() {
        // The fallback exists so a wizard-made offline profile can pack while the node
        // is down; it must keep the fail-closed rule for a configured-but-absent pin and
        // never invent trust when no pin exists at all.
        use gdi_node_standalone_core::crypt4gh::generate_keypair;
        let dir = tempfile::tempdir().unwrap();
        let (_sk, pk) = generate_keypair();
        let configured = dir.path().join("configured.pub");
        write_pinned_recipient(&pk, &configured, false).unwrap();
        let default_pin = dir.path().join("recipients").join("default.pub");

        // A configured pin is used, and named, even when no default pin exists.
        let (key, path) = offline_pin_fallback(Some(&configured), Some(&default_pin))
            .expect("a configured pin is a fallback")
            .expect("a valid configured pin resolves");
        assert_eq!(key.as_bytes(), pk.as_bytes());
        assert_eq!(path, configured);

        // A configured-but-absent pin stays a hard error, even with a working default
        // pin right beside it.
        write_pinned_recipient(&pk, &default_pin, false).unwrap();
        let absent = dir.path().join("missing.pub");
        let err = offline_pin_fallback(Some(&absent), Some(&default_pin))
            .expect("a configured pin always answers")
            .expect_err("a configured-but-absent pin must fail closed");
        assert!(
            err.message.contains("does not exist"),
            "got: {}",
            err.message
        );

        // No configured pin: an existing trust-on-first-use pin is used.
        let (key, path) = offline_pin_fallback(None, Some(&default_pin))
            .expect("an existing TOFU pin is a fallback")
            .expect("a valid TOFU pin resolves");
        assert_eq!(key.as_bytes(), pk.as_bytes());
        assert_eq!(path, default_pin);

        // No pin anywhere: nothing to fall back to — the caller keeps its fetch error.
        assert!(offline_pin_fallback(None, Some(&dir.path().join("never-pinned.pub"))).is_none());
        assert!(offline_pin_fallback(None, None).is_none());
    }

    #[test]
    fn verify_fetched_readonly_separates_not_yet_pinned_from_unpinnable() {
        // Two states must stay distinct, because they lead to opposite outcomes at
        // `pack`:
        //   * a pin path exists but no pin file yet -> `pack` pins on first use (fine);
        //   * no pin path at all (no resolvable config dir) -> `pack` refuses, with
        //     "no trust anchor ... no resolvable config directory to pin it".
        // Reporting them alike green-lights a setup that cannot pack, so the distinction
        // lives in the type rather than being re-derived per caller.
        use gdi_node_standalone_core::crypt4gh::generate_keypair;
        let dir = tempfile::tempdir().unwrap();
        let (_sk, pk) = generate_keypair();

        let pinnable = dir.path().join("recipients").join("default.pub");
        assert_eq!(
            verify_fetched_readonly(&pk, None, Some(&pinnable)).unwrap(),
            ReadonlyTrust::Unpinned,
            "a resolvable-but-absent pin path is pinnable on first use"
        );
        assert_eq!(
            verify_fetched_readonly(&pk, None, None).unwrap(),
            ReadonlyTrust::Unpinnable,
            "no pin path at all is the state `pack` refuses outright"
        );
    }

    #[test]
    fn verify_fetched_readonly_checks_pins_without_writing_and_rejects_mismatch() {
        // The `doctor` / `keys show` read-only trust check: it must verify against an
        // existing pin and reject a substituted key, but never write a pin itself.
        use gdi_node_standalone_core::crypt4gh::generate_keypair;
        let dir = tempfile::tempdir().unwrap();
        let (_ska, pk_a) = generate_keypair();
        let (_skb, pk_b) = generate_keypair();
        let default_pin = dir.path().join("recipients").join("default.pub");

        // No pin yet -> Unpinned, and (unlike enforce_recipient_trust) it must not create
        // a pin as a side effect.
        assert_eq!(
            verify_fetched_readonly(&pk_a, None, Some(&default_pin)).unwrap(),
            ReadonlyTrust::Unpinned
        );
        assert!(
            !default_pin.exists(),
            "read-only verification must never write a trust-on-first-use pin"
        );

        // With an existing TOFU pin, the matching key verifies against it.
        write_pinned_recipient(&pk_a, &default_pin, false).unwrap();
        assert_eq!(
            verify_fetched_readonly(&pk_a, None, Some(&default_pin)).unwrap(),
            ReadonlyTrust::VerifiedTofu
        );
        // A substituted key against the TOFU pin is classified, not collapsed into a
        // generic error: an `Err` here renders in `keys show` as `<unavailable: …>`, the
        // same shape as "the node is down", and exits 0. A detected key substitution is
        // the strongest signal this tool can produce and must read as one.
        match verify_fetched_readonly(&pk_b, None, Some(&default_pin)) {
            Ok(ReadonlyTrust::Substituted(detail)) => {
                assert!(
                    detail.contains("pinned"),
                    "the detail must still name what disagreed: {detail}"
                );
            }
            other => panic!("a pin mismatch must be reported as Substituted, got {other:?}"),
        }

        // A configured pin is authoritative and takes precedence over the TOFU pin.
        let configured = dir.path().join("configured.pub");
        write_pinned_recipient(&pk_b, &configured, false).unwrap();
        assert_eq!(
            verify_fetched_readonly(&pk_b, Some(&configured), Some(&default_pin)).unwrap(),
            ReadonlyTrust::VerifiedConfigured
        );
        // A key mismatching the configured pin is reported as a substitution even though
        // the TOFU pin holds pk_a — the configured pin is checked first and is
        // authoritative. Classified, not `Err`, for the same reason as the TOFU case above.
        std::assert_matches!(
            verify_fetched_readonly(&pk_a, Some(&configured), Some(&default_pin)),
            Ok(ReadonlyTrust::Substituted(_))
        );
    }

    /// Spin up a one-shot loopback HTTP/1.1 server that replies with `status`
    /// and `body`, returning the base URL.
    fn serve_once(status: u16, body: &[u8]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body = body.to_vec();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = std::io::Read::read(&mut stream, &mut buf);
                let header = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len(),
                    reason = if status == 200 { "OK" } else { "Error" }
                );
                let _ = stream.write_all(header.as_bytes());
                let _ = stream.write_all(&body);
                let _ = stream.flush();
            }
        });
        format!("http://{addr}")
    }

    /// Drive `fetch_node_recipient` with a fresh tokio runtime (same pattern as
    /// `runtime::block_on`).
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }

    /// A 500 response → error mentioning the HTTP status code.
    #[test]
    fn fetch_node_recipient_500_errors_with_status() {
        let base = serve_once(500, b"internal error");
        let url = format!("{base}/.well-known/c4gh-recipient");
        let err = block_on(fetch_node_recipient(&url)).unwrap_err();
        assert!(
            err.message.contains("500"),
            "error must mention HTTP 500; got: {}",
            err.message
        );
        // 500 is a generic server error, not auth — stays exit 1.
        assert_eq!(err.exit_code, crate::EXIT_USER);
    }

    #[test]
    fn fetch_node_recipient_401_403_classify_as_auth() {
        for status in [401u16, 403] {
            let base = serve_once(status, b"nope");
            let url = format!("{base}/.well-known/c4gh-recipient");
            let err = block_on(fetch_node_recipient(&url)).unwrap_err();
            assert_eq!(
                err.exit_code,
                crate::EXIT_AUTH,
                "HTTP {status} must classify as an auth failure (exit 4); got {}",
                err.exit_code
            );
        }
    }

    /// A non-UTF-8 body on a 200 → error mentioning the parse failure (UTF-8 or
    /// invalid recipient).
    #[test]
    fn fetch_node_recipient_non_utf8_body_errors() {
        // 0xFF 0xFE is not valid UTF-8.
        let base = serve_once(200, &[0xFF, 0xFE, 0x00, 0xAA]);
        let url = format!("{base}/.well-known/c4gh-recipient");
        let err = block_on(fetch_node_recipient(&url)).unwrap_err();
        // Either "not UTF-8" or "not a valid recipient" is acceptable — the
        // body is garbage so it will fail at one of those two checks.
        let msg = &err.message;
        assert!(
            msg.contains("UTF-8") || msg.contains("not a valid recipient"),
            "error must mention UTF-8 or invalid recipient; got: {msg}"
        );
    }

    #[test]
    fn recipient_body_cap_rejects_oversized() {
        // At or under the cap is accepted; one byte over is rejected.
        assert!(check_recipient_len("https://node/x", MAX_RECIPIENT_BYTES).is_ok());
        assert!(check_recipient_len("https://node/x", MAX_RECIPIENT_BYTES + 1).is_err());
    }

    #[test]
    fn url_defaults_to_well_known() {
        let active = Profile {
            service_url: Some("https://node.example".to_owned()),
            ..Profile::default()
        };
        assert_eq!(
            node_recipient_url(&active).as_deref(),
            Some("https://node.example/.well-known/c4gh-recipient")
        );
    }

    #[test]
    fn explicit_url_overrides_default() {
        let active = Profile {
            service_url: Some("https://node.example".to_owned()),
            node_recipient_url: Some("https://recip.example/key".to_owned()),
            ..Profile::default()
        };
        assert_eq!(
            node_recipient_url(&active).as_deref(),
            Some("https://recip.example/key")
        );
    }

    #[test]
    fn no_url_when_neither_set() {
        assert!(node_recipient_url(&Profile::default()).is_none());
    }

    #[test]
    fn secure_transport_required_for_remote_http() {
        // https anywhere is fine; plaintext http is allowed only to loopback.
        let hint = "test hint.";
        assert!(
            require_secure_transport("https://node.example/.well-known/c4gh-recipient", hint)
                .is_ok()
        );
        assert!(require_secure_transport("http://127.0.0.1:8000/x", hint).is_ok());
        assert!(require_secure_transport("http://localhost:8000/x", hint).is_ok());
        assert!(require_secure_transport("http://[::1]:8000/x", hint).is_ok());
        // Plaintext http to a non-loopback host is rejected (MITM substitution).
        let err = require_secure_transport("http://node.example/x", hint).unwrap_err();
        assert!(
            err.message.contains("plaintext http"),
            "got: {}",
            err.message
        );
    }

    #[test]
    fn a_non_http_scheme_is_rejected_as_unsupported_not_as_plaintext_http() {
        // A non-http scheme must be named as an unsupported scheme, not as plaintext
        // http, so the diagnostic is truthful. `file:`, `ftp:` and `data:` are refused.
        let hint = "test hint.";
        for url in ["file:///etc/passwd", "ftp://host/x", "data:text/plain,hi"] {
            let err = require_secure_transport(url, hint).expect_err("must be rejected");
            assert!(
                err.message.contains("scheme") && !err.message.contains("plaintext http"),
                "{url} must be rejected as an unsupported scheme, got: {}",
                err.message
            );
        }
    }

    #[test]
    fn redirect_target_reuses_the_same_transport_rule() {
        // The redirect policy re-applies the same rule per hop, so an https URL cannot
        // 30x-redirect into a plaintext/link-local/file target (classic SSRF bypass). The
        // rule is single-sourced in `transport_reason`, so testing it there binds both the
        // direct check and every redirect hop.
        assert!(transport_reason(&reqwest::Url::parse("https://ok.example/x").unwrap()).is_none());
        assert!(transport_reason(&reqwest::Url::parse("http://127.0.0.1/x").unwrap()).is_none());
        assert!(
            transport_reason(&reqwest::Url::parse("http://169.254.169.254/latest").unwrap())
                .is_some(),
            "a redirect to cloud-metadata over plaintext http must be refused"
        );
        assert!(
            transport_reason(&reqwest::Url::parse("file:///etc/passwd").unwrap()).is_some(),
            "a redirect to a file: URL must be refused"
        );
    }

    #[test]
    fn pin_verification_matches_and_detects_substitution() {
        use gdi_node_standalone_core::crypt4gh::generate_keypair;
        let dir = tempfile::tempdir().unwrap();
        let (_sk_a, pk_a) = generate_keypair();
        let (_sk_b, pk_b) = generate_keypair();

        // No pin file means nothing to verify against, so this is a no-op.
        verify_fetched_against_pin(&pk_a, &dir.path().join("absent.pub")).unwrap();

        // Pin pk_a; a fetch of pk_a passes, a fetch of the attacker's pk_b is rejected.
        let pin = dir.path().join("node.pub");
        write_pinned_recipient(&pk_a, &pin, false).unwrap();
        verify_fetched_against_pin(&pk_a, &pin).unwrap();
        let err = verify_fetched_against_pin(&pk_b, &pin).unwrap_err();
        assert!(
            err.message.contains("differs from the pinned key"),
            "got: {}",
            err.message
        );
    }

    #[test]
    fn pin_creates_then_detects_change() {
        use gdi_node_standalone_core::crypt4gh::generate_keypair;
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("node.pub");
        let (sk_a, pk_a) = generate_keypair();
        let _ = sk_a;
        let (_sk_b, pk_b) = generate_keypair();

        // First pin: Created.
        std::assert_matches!(
            write_pinned_recipient(&pk_a, &out, false).unwrap(),
            PinOutcome::Created
        );
        // Same key again: Unchanged (idempotent).
        std::assert_matches!(
            write_pinned_recipient(&pk_a, &out, false).unwrap(),
            PinOutcome::Unchanged
        );
        // A different key without --force: refused.
        let err = write_pinned_recipient(&pk_b, &out, false).unwrap_err();
        assert_eq!(err.exit_code, crate::EXIT_USER);
        assert!(err.message.contains("differs"), "{}", err.message);
        // With --force: Replaced, and the file now holds key B.
        std::assert_matches!(
            write_pinned_recipient(&pk_b, &out, true).unwrap(),
            PinOutcome::Replaced
        );
        let pinned = read_node_recipient_file(&out).unwrap();
        assert_eq!(pinned.as_bytes(), pk_b.as_bytes());
    }
}
