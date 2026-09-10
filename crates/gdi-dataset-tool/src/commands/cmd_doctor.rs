//! The `doctor` command: a mostly read-only preflight of the active
//! profile + a node's reachability — the client analog of the service's
//! `check-config`.
//!
//! It validates the active profile loads, the **provider identity** loads (without
//! generating it) and its recipient derives, and the resolved **node recipient**
//! (an explicit `--recipient` overrides in either mode; otherwise
//! `node_recipient_url` online or `node_recipient_file` offline) is a usable
//! crypt4gh recipient. **Online** it additionally checks the FDP root
//! responds, the catalog list is fetchable, and the S3 bucket is writable (a probe
//! PUT/DELETE on a reserved key). It does not probe `/health/ready`, which is on the
//! management plane and not reachable from the provider side. **Offline** it checks the
//! local recipient file and the `catalogs` allow-list.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

use gdi_node_standalone_core::config::Profile;

use super::cmd_keys;
use crate::cli::{DoctorArgs, OutputFormat};
use crate::{ToolError, catalogs, profile, recipient, runtime, s3};

/// One preflight check result.
#[derive(serde::Serialize)]
struct Check {
    /// What was checked.
    name: String,
    /// Whether it passed.
    ok: bool,
    /// The failure class — `"ok"` when it passed, else `"user"` / `"transient"` /
    /// `"auth"` (mirroring the tool's 1/3/4 exit codes). Lets a script branch on why a
    /// check failed, and drives `doctor`'s overall exit code.
    class: &'static str,
    /// A short detail (the value on success, the reason on failure).
    detail: String,
}

impl Check {
    /// A passing check.
    fn pass(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.to_owned(),
            ok: true,
            class: "ok",
            detail: detail.into(),
        }
    }
    /// A failed check carrying the underlying [`ToolError`]'s class.
    fn fail(name: &str, e: &ToolError) -> Self {
        Self {
            name: name.to_owned(),
            ok: false,
            class: class_of(e.exit_code),
            detail: e.message.clone(),
        }
    }
    /// A failed check from a literal config/usage reason (the `user` class).
    fn fail_msg(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.to_owned(),
            ok: false,
            class: "user",
            detail: detail.into(),
        }
    }
}

/// The class label for a tool exit code (`4` → auth, `3` → transient, else user).
fn class_of(exit_code: i32) -> &'static str {
    match exit_code {
        4 => "auth",
        3 => "transient",
        _ => "user",
    }
}

/// The exit code for a class label (inverse of [`class_of`]).
fn code_of(class: &str) -> i32 {
    match class {
        "auth" => 4,
        "transient" => 3,
        _ => 1,
    }
}

/// The overall exit code for a doctor run: the **worst** failed check's class
/// (auth `4` > transient `3` > user `1`), so a script can branch on why doctor failed.
/// Falls back to `1` if (unexpectedly) called with no failed checks.
fn worst_exit_code(checks: &[Check]) -> i32 {
    checks
        .iter()
        .filter(|c| !c.ok)
        .map(|c| code_of(c.class))
        .max()
        .unwrap_or(1)
}

/// The machine-readable `doctor --format json` report.
#[derive(serde::Serialize)]
struct DoctorReport<'a> {
    /// Whether every check passed.
    ok: bool,
    /// The names of the failed checks (empty on success).
    failed: &'a [&'a str],
    /// Every check's result.
    checks: &'a [Check],
}

/// Run `doctor`.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) if the profile cannot be loaded, or — if any
/// preflight check failed (after printing every check's result) — with the worst
/// failed check's class as its exit code (user `1`, transient `3`, or auth `4`;
/// see `worst_exit_code`).
pub fn run(
    args: &DoctorArgs,
    profile_name: Option<&str>,
    config_path: Option<&Path>,
) -> Result<(), ToolError> {
    // Tolerate a missing profile: an air-gapped `doctor --offline --recipient <file>`
    // supplies every input on the CLI, so a missing profile file must not wall it off with
    // "no profiles configured". Falls back to a default (empty) profile only when none are
    // configured and no `--profile` was requested.
    let (_active_name, active) = profile::load_active_named_or_default(config_path, profile_name)?;
    let online = !args.offline && active.service_url.is_some();
    crate::output::note(&format!(
        "running doctor in {} mode",
        if online { "online" } else { "offline" }
    ));

    let mut checks: Vec<Check> = Vec::new();
    crate::output::note("checking active profile");
    checks.push(check_profile(&active));
    crate::output::note("checking build-readiness (country code)");
    checks.push(check_build_readiness(config_path));
    crate::output::note("checking provider identity (read-only)");
    checks.push(check_provider_identity(config_path));
    let recipient_src = if args.recipient.is_some() {
        "--recipient file"
    } else if online {
        "node_recipient_url"
    } else {
        "node_recipient_file"
    };
    crate::output::note(&format!("checking node recipient via {recipient_src}"));
    checks.push(check_node_recipient(&active, args, online, config_path));

    if online {
        s3::install_crypto_provider();
        if let Some(base) = active.service_url.as_deref() {
            crate::output::note(&format!("checking node FDP root reachability at {base}"));
        }
        // Fetch the node's catalogs once and reuse the result for both the FDP-root
        // reachability probe and the catalogs check, rather than issuing two identical
        // GETs of the FDP root per run.
        let catalogs_fetch = active
            .service_url
            .as_deref()
            .map(|base| runtime::block_on(catalogs::fetch_node_catalogs(base)));
        checks.push(check_fdp_root(&active, catalogs_fetch.as_ref()));
        crate::output::note("probing the beacon registration URL");
        // Only reached online, and `check_beacon_url` answers "no service_url" itself before
        // the probe result matters — so the result is a plain `bool`, not an `Option` whose
        // `None` arm no caller could reach.
        let beacon_responds = active.service_url.as_deref().is_some_and(|base| {
            let url = format!("{}/aggregated/beacon/v2", base.trim_end_matches('/'));
            // A probe failure is "the guess does not hold", never a doctor failure.
            runtime::block_on(default_beacon_mount_responds(&url)).unwrap_or(false)
        });
        checks.push(check_beacon_url(&active, beacon_responds));
        crate::output::note("checking the node's catalog list");
        checks.push(check_catalogs(&active, catalogs_fetch.as_ref()));
        if active.s3.is_some() {
            crate::output::note("checking the S3 bucket is writable (probe PUT/DELETE)");
            checks.push(check_s3_writable(&active));
        }
    } else {
        crate::output::note("checking the offline catalogs allow-list");
        checks.push(check_catalogs_offline(&active));
    }

    let failed: Vec<&str> = checks
        .iter()
        .filter(|c| !c.ok)
        .map(|c| c.name.as_str())
        .collect();

    // Read-only diagnostics go to stdout for piping.
    match args.format {
        OutputFormat::Json => {
            let report = DoctorReport {
                ok: failed.is_empty(),
                failed: &failed,
                checks: &checks,
            };
            let value = crate::output::versioned_value(&report)
                .map_err(|e| ToolError::user(format!("serializing report: {e}")))?;
            crate::output::emit_json(&value);
        }
        OutputFormat::Text => {
            // The same marker column `gdi-node-standalone doctor` prints: padded and
            // uppercase, so the two doctors an operator runs side by side render one shape
            // and the check names line up.
            for c in &checks {
                let mark = if c.ok { "OK  " } else { "FAIL" };
                println!("[{mark}] {}: {}", c.name, c.detail);
            }
            if failed.is_empty() {
                println!("doctor: all checks passed");
            }
        }
    }

    if failed.is_empty() {
        Ok(())
    } else {
        Err(ToolError {
            message: format!(
                "doctor: {} check(s) failed: {}",
                failed.len(),
                failed.join(", ")
            ),
            exit_code: worst_exit_code(&checks),
        })
    }
}

/// The active profile loaded (already done by the caller; report its shape).
fn check_profile(active: &Profile) -> Check {
    let mode = if active.s3.is_some() {
        "S3"
    } else if active.inbox.is_some() {
        "inbox"
    } else {
        "no install channel"
    };
    Check::pass("profile", format!("loaded ({mode})"))
}

/// Advisory (never a failure): surface whether the country code — the first thing a build
/// needs — is resolvable, so a clean `doctor` does not hide that `build`/`package` will
/// immediately fail without `--cc`. The country code is a build-time concern rather than a
/// profile/node one, so an absent one is a note, not a doctor failure.
fn check_build_readiness(config_path: Option<&Path>) -> Check {
    let cc = gdi_node_standalone_core::config::ToolConfig::load(config_path)
        .ok()
        .and_then(|cfg| cfg.resolve_country_code(None));
    match cc {
        Some(cc) => Check::pass(
            "build-readiness",
            format!("country code resolved ({cc}); a package.yaml is still required to build"),
        ),
        None => Check::pass(
            "build-readiness",
            "country code not set; build/package will require --cc (or set \
             country_code / GDI_TOOL__COUNTRY_CODE)",
        ),
    }
}

/// The provider identity loads (read-only — does not generate), its recipient derives,
/// and it is not readable beyond its owner.
///
/// The permission bits are graded here, not just warned about. The shared read path
/// (`cmd_keys::load_identity_at`) prints a stderr warning and returns the key anyway, so a
/// mode bit cannot lock an operator out of their own packages — but that warning is
/// invisible to `--format json` and to any script reading the exit code. The tool's module
/// doc calls `0o600` the only protection the unencrypted key has, and the node fails closed
/// on the identical condition (`identities.rs`, `strict_key_perms`), so a green `doctor`
/// here would certify a setup the node refuses. It fails on the `user` class (exit 1) — the
/// operator fixes it with one `chmod`.
fn check_provider_identity(config_path: Option<&Path>) -> Check {
    match cmd_keys::load_provider_secret_readonly_at(config_path) {
        Ok((sk, path)) => {
            let _ = sk.public_key(); // the recipient derives.
            // Re-stat rather than trust the loader's rung: the same predicate the node and
            // the tool's read path use, so the three cannot grade the same file differently.
            match gdi_node_standalone_core::util::loose_secret_mode(&path) {
                Some(mode) => Check::fail_msg(
                    "provider-identity",
                    format!(
                        "loaded, but {} is readable beyond its owner (mode {mode:o}); file \
                         permissions are its only protection; run `chmod 600 {}`",
                        path.display(),
                        path.display()
                    ),
                ),
                None => Check::pass("provider-identity", "loaded; recipient derives"),
            }
        }
        Err(e) => Check::fail("provider-identity", &e),
    }
}

/// The node recipient resolves to a usable crypt4gh recipient, and — for an online
/// fetch — matches its trust pin (read-only; `doctor` never writes a pin).
fn check_node_recipient(
    active: &Profile,
    args: &DoctorArgs,
    online: bool,
    config_path: Option<&Path>,
) -> Check {
    // A keyless profile encrypts nothing, so it has no node recipient, and an explicit
    // `--recipient` would be meaningless. Reporting "no recipient" as a fault here would
    // tell the operator to fix a profile that is already correct.
    if active.keyless && args.recipient.is_none() {
        return Check::pass(
            "node-recipient",
            "not required: keyless profile (packages are not encrypted; the staging dir is \
             deployed to the node's inbox)",
        );
    }
    let result = if let Some(path) = args.recipient.as_deref() {
        recipient::read_node_recipient_file(path)
    } else if online {
        match recipient::node_recipient_url(active) {
            Some(url) => runtime::block_on(recipient::fetch_node_recipient(&url)),
            None => Err(ToolError::user(
                "no node_recipient_url and no service_url".to_owned(),
            )),
        }
    } else {
        // Offline: the local recipient file is required.
        match active.node_recipient_path(config_path) {
            Some(file) => recipient::read_node_recipient_file(&file),
            None => Err(ToolError::user(
                "no node_recipient_file configured (offline needs a local recipient)".to_owned(),
            )),
        }
    };
    let fetched = match result {
        Ok(pk) => pk,
        Err(e) => {
            // Mirror pack's offline fallback: with a usable local pin, a failed fetch
            // does not block encryption — pack encrypts to the pin — so the check
            // reports that degraded-but-working state instead of failing a node that
            // is simply not up yet.
            if online && args.recipient.is_none() {
                let configured = active.node_recipient_path(config_path);
                let default_pin = recipient::recipient_pin_path_for_read(active, config_path);
                if let Some(Ok((_, pin))) =
                    recipient::offline_pin_fallback(configured.as_deref(), default_pin.as_deref())
                {
                    return Check::pass(
                        "node-recipient",
                        format!(
                            "fetch failed ({}); pack encrypts to the pinned recipient {}",
                            e.message,
                            pin.display()
                        ),
                    );
                }
            }
            return Check::fail("node-recipient", &e);
        }
    };
    // For an online fetch (no explicit --recipient file), verify the key against its pin
    // read-only: a mismatch is the MITM/substitution condition `pack` refuses, so `doctor`
    // surfaces it rather than green-lighting any key that merely parses.
    if online && args.recipient.is_none() {
        let configured = active.node_recipient_path(config_path);
        let default_pin = recipient::recipient_pin_path_for_read(active, config_path);
        return match recipient::verify_fetched_readonly(
            &fetched,
            configured.as_deref(),
            default_pin.as_deref(),
        ) {
            Ok(recipient::ReadonlyTrust::VerifiedConfigured) => Check::pass(
                "node-recipient",
                "verified against the configured node_recipient_file pin",
            ),
            Ok(recipient::ReadonlyTrust::VerifiedTofu) => Check::pass(
                "node-recipient",
                "verified against the trust-on-first-use pin",
            ),
            // Explicit, and named for what it is: not "a check errored" with a raw message,
            // but a key substitution against an established pin.
            Ok(recipient::ReadonlyTrust::Substituted(detail)) => Check::fail_msg(
                "node-recipient",
                format!(
                    "SUBSTITUTED: the key this node serves does not match its established \
                     pin. This is the man-in-the-middle / key-rotation condition `pack` \
                     refuses. {detail}"
                ),
            ),
            Ok(recipient::ReadonlyTrust::Unpinned) => Check::pass(
                "node-recipient",
                "resolves, but is not yet pinned; `pack` will pin it on first use",
            ),
            // Not a pass: with no configured pin and no resolvable config directory there
            // is nowhere to anchor the key, and `pack` refuses to encrypt to an unverified
            // recipient. Reporting this as healthy certifies a setup that cannot package.
            Ok(recipient::ReadonlyTrust::Unpinnable) => Check::fail_msg(
                "node-recipient",
                "resolves, but nothing can anchor it: no node_recipient_file is configured \
                 and no config directory resolves for a trust-on-first-use pin, so `pack` \
                 will refuse to encrypt. Set node_recipient_file, run `setup`, or pass \
                 --recipient <file> with an out-of-band copy of the node's public key.",
            ),
            Err(e) => Check::fail("node-recipient", &e),
        };
    }
    Check::pass("node-recipient", "resolves to a usable recipient")
}

/// The FDP root responds (online).
fn check_fdp_root(active: &Profile, fetched: Option<&Result<Vec<String>, ToolError>>) -> Check {
    let Some(base) = active.service_url.as_deref() else {
        return Check::fail_msg("fdp-root", "no service_url");
    };
    // Reuse the single catalogs fetch (from `run`) as the FDP-root reachability probe.
    match fetched {
        Some(Ok(_)) => Check::pass(
            "fdp-root",
            format!("{}/fairdp responds", base.trim_end_matches('/')),
        ),
        Some(Err(e)) => Check::fail("fdp-root", e),
        None => Check::fail_msg("fdp-root", "no service_url"),
    }
}

/// Whether the default aggregated beacon mount answers at `base`.
///
/// One cheap GET, reusing the same client the FDP probe uses. A non-2xx or an unreachable
/// endpoint is simply `false`: this is a "does the guess hold" question, never a
/// reachability verdict (the FDP-root check owns that).
async fn default_beacon_mount_responds(url: &str) -> Result<bool, ToolError> {
    let client = catalogs::fdp_client()?;
    Ok(matches!(client.get(url).send().await, Ok(r) if r.status().is_success()))
}

/// Report the node's beacon registration URL, probed when online.
///
/// The tool config carries only the node base URL, not the beacon mount path, so the URL is
/// a guess at the default `/aggregated/beacon/v2` mount. On a node with a custom
/// `[beacon].aggregated_base_path`, reporting it without fetching it would hand the operator
/// a URL that 404s — a dead endpoint registered with the Beacon Network, which is exactly
/// the class `doctor` exists to catch.
///
/// A custom mount still never fails the check: that would turn a legitimate configuration
/// into a non-zero exit, and the tool cannot know the node's prefix. It reports what it
/// found, so the operator is told to go and get the real URL rather than handed a broken one
/// with a green tick.
fn check_beacon_url(active: &Profile, responds: bool) -> Check {
    let Some(base) = active.service_url.as_deref() else {
        return Check::fail_msg("beacon-url", "no service_url");
    };
    let url = format!("{}/aggregated/beacon/v2", base.trim_end_matches('/'));
    if responds {
        Check::pass(
            "beacon-url",
            format!("{url} responds; forward this to the Beacon Network"),
        )
    } else {
        Check::pass(
            "beacon-url",
            format!(
                "custom [beacon].aggregated_base_path; the default-shaped {url} does not \
                 answer here. Do not register it; take the exact URL from the node's \
                 `gdi-node-standalone check-config` output"
            ),
        )
    }
}

/// The catalog list is fetchable (online).
fn check_catalogs(active: &Profile, fetched: Option<&Result<Vec<String>, ToolError>>) -> Check {
    match fetched {
        Some(Ok(names)) => {
            let mut detail = format!("{} catalog(s): {}", names.len(), names.join(", "));
            // Advisory: when the profile also carries an offline `catalogs` allow-list,
            // diff it against what the node actually serves so a stale hint is visible.
            // The allow-list is an optional fail-fast hint (cosmetic title only) — the
            // node re-validates catalogs at ingest — so a mismatch is a note, not a
            // failure (`ok` stays true).
            if !active.catalogs.is_empty() {
                let served: BTreeSet<&str> = names.iter().map(String::as_str).collect();
                let listed: BTreeSet<&str> = active.catalogs.keys().map(String::as_str).collect();
                let node_only: Vec<&str> = served.difference(&listed).copied().collect();
                let profile_only: Vec<&str> = listed.difference(&served).copied().collect();
                if !node_only.is_empty() || !profile_only.is_empty() {
                    // Writing to a String is infallible; the Result is intentionally dropped.
                    let _ = write!(
                        detail,
                        "; note: differs from the profile `catalogs` allow-list \
                         (node-only: [{}]; profile-only: [{}]). The allow-list is an optional \
                         hint, the node re-validates at ingest",
                        node_only.join(", "),
                        profile_only.join(", "),
                    );
                }
            }
            Check::pass("catalogs", detail)
        }
        Some(Err(e)) => Check::fail("catalogs", e),
        None => Check::fail_msg("catalogs", "no service_url"),
    }
}

/// The offline `catalogs` allow-list is present.
fn check_catalogs_offline(active: &Profile) -> Check {
    if active.catalogs.is_empty() {
        // An absent offline allow-list is a legitimate minimal posture, such as the
        // air-gapped `doctor --offline --recipient` flow: catalog names are then not
        // validated offline, which `build` and `validate` allow. Report it, do not fail.
        Check::pass(
            "catalogs",
            "no offline `catalogs` allow-list configured; catalog names are not validated \
             offline (configure one to gate them)",
        )
    } else {
        let names: Vec<&str> = active.catalogs.keys().map(String::as_str).collect();
        Check::pass(
            "catalogs",
            format!("{} allow-listed: {}", names.len(), names.join(", ")),
        )
    }
}

/// The S3 bucket is writable (online; a reserved probe PUT/DELETE).
fn check_s3_writable(active: &Profile) -> Check {
    let Some(cfg) = active.s3.as_ref() else {
        return Check::fail_msg("s3-writable", "no [profiles.<name>.s3] block");
    };
    let result =
        s3::build_object_store(cfg).and_then(|store| runtime::block_on(s3::probe_writable(&store)));
    match result {
        // Name the target, not just the outcome. A probe PUT/DELETE succeeds just as happily
        // in the wrong keyspace, so "writable" alone cannot tell a correct prefix from a
        // well-formed wrong one — and a wrong one presents as an empty listing on a node that
        // is serving fine. Printed in the same `bucket/prefix` shape the node's `doctor` and
        // `check-config` use, so the two sides can be compared by eye.
        Ok(()) => Check::pass(
            "s3-writable",
            format!(
                "{} accepts a probe PUT/DELETE (this must match the node's [[s3.buckets]].prefix \
                 for this channel)",
                s3::target_label(cfg)
            ),
        ),
        Err(e) => Check::fail("s3-writable", &e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_catalogs_is_informational_not_a_hard_fail_when_empty() {
        // The air-gapped `doctor --offline --recipient` flow has no catalogs allow-list,
        // and that must not fail doctor: catalog names are then not validated offline.
        let empty = Profile::default();
        let check = check_catalogs_offline(&empty);
        assert!(
            check.ok,
            "an empty offline catalogs allow-list must be informational"
        );
        // A configured allow-list still passes and lists the names.
        let mut with_cat = Profile::default();
        with_cat
            .catalogs
            .insert("gdi-aggregated".to_owned(), "GoE".to_owned());
        assert!(check_catalogs_offline(&with_cat).ok);
    }

    /// A keyless profile encrypts nothing, so it has no node recipient. `doctor` must not
    /// report that as a fault — it would send the operator off to fix a profile that is
    /// already correct. (An explicit `--recipient` still overrides and is checked.)
    #[test]
    fn doctor_does_not_demand_a_recipient_from_a_keyless_profile() {
        let keyless = Profile {
            keyless: true,
            service_url: Some("http://127.0.0.1:8080".into()),
            inbox: Some("/var/lib/gdi-node-standalone/inbox".into()),
            ..Profile::default()
        };
        let args = DoctorArgs {
            offline: true,
            recipient: None,
            format: OutputFormat::Text,
        };
        let check = check_node_recipient(&keyless, &args, false, None);
        assert!(
            check.ok,
            "a keyless profile must pass the recipient check: {}",
            check.detail
        );
        assert!(
            check.detail.contains("keyless"),
            "the check must say why no recipient is needed: {}",
            check.detail
        );

        // The same profile without the keyless flag still needs one (the check is not
        // simply disabled).
        let keyed = Profile {
            keyless: false,
            ..keyless
        };
        assert!(
            !check_node_recipient(&keyed, &args, false, None).ok,
            "a non-keyless profile with no recipient must still fail"
        );
    }

    #[test]
    fn class_code_round_trips() {
        assert_eq!((class_of(4), code_of("auth")), ("auth", 4));
        assert_eq!((class_of(3), code_of("transient")), ("transient", 3));
        assert_eq!((class_of(1), code_of("user")), ("user", 1));
        // An unknown / "ok" class maps to the user floor.
        assert_eq!(code_of("ok"), 1);
    }

    #[test]
    fn worst_exit_code_picks_the_highest_failed_class() {
        let auth = ToolError::auth("denied");
        let transient = ToolError::transient("503");
        let user = ToolError::user("bad");
        // auth(4) dominates transient(3) and user(1); passing checks are ignored.
        let mixed = vec![
            Check::pass("p", "ok"),
            Check::fail("u", &user),
            Check::fail("t", &transient),
            Check::fail("a", &auth),
        ];
        assert_eq!(worst_exit_code(&mixed), 4);
        // transient dominates user.
        assert_eq!(
            worst_exit_code(&[Check::fail("u", &user), Check::fail("t", &transient)]),
            3
        );
        // a lone user-class failure is exit 1.
        assert_eq!(worst_exit_code(&[Check::fail("u", &user)]), 1);
    }
}
