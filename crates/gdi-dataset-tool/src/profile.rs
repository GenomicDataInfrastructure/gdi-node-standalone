//! Active-profile resolution for the networked commands.
//!
//! `--profile <name>` selects the node deployment to act on: its `service_url`, its
//! `[profiles.<name>.s3]` bucket, its recipient, and its `catalogs` switch together.
//! The config models a `[profiles.<name>]` map; selection honours `--profile`, then
//! `default_profile`, then a sole configured profile, so a typo cannot silently target
//! the wrong node (an unknown name is a clear error).

use std::path::Path;

use gdi_node_standalone_core::config::{Profile, ToolConfig};

use crate::ToolError;

/// Load the active [`Profile`] from the tool config, honouring `--profile`.
///
/// Selection order:
/// 1. an explicit `--profile <name>` is looked up in `[profiles.<name>]`
///    (unknown name → error listing the available names);
/// 2. else `default_profile`, if set (error if it names a missing profile);
/// 3. else, if exactly one profile is configured, that one;
/// 4. else an error asking for `--profile` or `default_profile` (or
///    "no profiles configured" when the map is empty).
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) if the config cannot be loaded or no single
/// profile can be selected (unknown / missing default / ambiguous / empty).
pub fn load_active(config_path: Option<&Path>, name: Option<&str>) -> Result<Profile, ToolError> {
    load_active_named(config_path, name).map(|(_, profile)| profile)
}

/// Like [`load_active`] but also returns the resolved profile name. The name is guaranteed
/// to key into `cfg.profiles`.
///
/// Crate-visible so a run can tell the operator which profile it targets. The name must be
/// the resolved one: the wizard's setup prompt accepts whatever name is announced, so
/// announcing a hard-coded `"default"` would write a second profile, leaving a config with
/// two profiles, no `default_profile`, and every later command failing "no profile
/// selected".
///
/// Do not key paths on it. The trust-on-first-use recipient pin is keyed on the node's
/// recipient URL instead (`recipient::default_recipient_pin_path`), because a profile name
/// collides across configs that name the same profile for different nodes, and splits one
/// node into two pins when it is reached under two names.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) if the config cannot be loaded or no single profile
/// can be selected (unknown / missing default / ambiguous / empty).
pub(crate) fn load_active_named(
    config_path: Option<&Path>,
    name: Option<&str>,
) -> Result<(String, Profile), ToolError> {
    let cfg = ToolConfig::load(config_path)
        .map_err(|e| ToolError::user(format!("loading tool config: {e}")))?;
    warn_phantom_profile_twins(&cfg);
    let active_name = select_active_name(&cfg, name)?;
    let active = select_profile(&cfg, name).cloned()?;
    if crate::output::is_verbose() {
        crate::output::note(&format!("active profile: {active_name}"));
    }
    Ok((active_name, active))
}

/// Like [`load_active`] but also returning the resolved name and, when no profiles are
/// configured and no `--profile` was requested, returning an empty profile named `default`
/// instead of erroring "no profiles configured".
///
/// A fully self-contained invocation (`doctor --offline --recipient <file>`, or the
/// air-gapped `keys generate` / `package --recipient` flow) has every input on the command
/// line, so requiring a profile file is purely structural: an empty `[profiles.airgap]`
/// block would satisfy it identically. An explicit `--profile <name>` against an empty
/// config still errors, because the operator asked for a profile that does not exist.
///
/// # Errors
///
/// Propagates a config-load error, or, when profiles are configured or a name is given,
/// the same selection error as [`load_active`].
pub fn load_active_named_or_default(
    config_path: Option<&Path>,
    name: Option<&str>,
) -> Result<(String, Profile), ToolError> {
    let cfg = ToolConfig::load(config_path)
        .map_err(|e| ToolError::user(format!("loading tool config: {e}")))?;
    if cfg.profiles.is_empty() && name.is_none() {
        return Ok(("default".to_owned(), Profile::default()));
    }
    warn_phantom_profile_twins(&cfg);
    let active_name = select_active_name(&cfg, name)?;
    let active = select_profile(&cfg, name).cloned()?;
    Ok((active_name, active))
}

/// Like [`load_active`], but tolerates a config that configures no profiles at all,
/// returning `Ok(None)` instead of the "no profiles configured" error.
///
/// A verb already fully specified on the command line needs nothing from a profile.
/// `deploy --inbox <dir>` is the case that matters: copying a package into a directory
/// should not demand a `[profiles.<name>]` block first.
///
/// Only the empty-map case degrades to `None`. A malformed config, an unknown `--profile`,
/// a `default_profile` naming a missing profile, and an ambiguous multi-profile selection
/// all still hard-fail, so a real misconfiguration is never silently ignored.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) if the config cannot be loaded, or if a profile was
/// named or implied but cannot be selected (unknown / missing default / ambiguous).
pub fn load_active_optional(
    config_path: Option<&Path>,
    name: Option<&str>,
) -> Result<Option<Profile>, ToolError> {
    let cfg = ToolConfig::load(config_path)
        .map_err(|e| ToolError::user(format!("loading tool config: {e}")))?;
    warn_phantom_profile_twins(&cfg);
    // An explicit `--profile` must still be honoured, and error if unknown, even when
    // the map is empty: the operator asked for a specific profile.
    if cfg.profiles.is_empty() && name.is_none() {
        return Ok(None);
    }
    select_profile(&cfg, name).cloned().map(Some)
}

/// Warn (to stderr) about hyphen/underscore profile twins. A hyphenated
/// `[profiles.ee-prod]` cannot be reached by `GDI_TOOL__PROFILES__EE_PROD__…`, so injected
/// credentials land in a separate `ee_prod` phantom profile and the real profile fails to
/// authenticate.
///
/// Called by [`load_active_named`] (every networked verb) and by the `profiles`
/// introspection command, which is where an operator looks when debugging why env-injected
/// credentials are not taking effect.
pub(crate) fn warn_phantom_profile_twins(cfg: &ToolConfig) {
    for (a, b) in cfg.phantom_profile_twins() {
        eprintln!(
            "warning: profiles '{a}' and '{b}' differ only by '-' vs '_'. The GDI_TOOL__PROFILES__ env \
             overlay can only spell '_', so a hyphenated profile name is unreachable by env and any \
             credentials injected for it land in the '_' twin instead. Rename your profile to use \
             '_' (e.g. '{}').",
            a.replace('-', "_")
        );
    }
}

/// Apply the selection order to an already-loaded config, returning a reference
/// to the chosen [`Profile`]. Split out from [`load_active`] so it is unit-testable
/// without touching the filesystem. Delegates name resolution to [`select_active_name`],
/// which defines the selection order in one place.
fn select_profile<'a>(cfg: &'a ToolConfig, name: Option<&str>) -> Result<&'a Profile, ToolError> {
    let active = select_active_name(cfg, name)?;
    cfg.profiles
        .get(&active)
        .ok_or_else(|| unknown_profile(cfg, &active))
}

/// Resolve the active profile name using the same selection order as
/// `select_profile` / [`load_active`], without cloning the profile.
///
/// Exposed so the `profiles` introspection command can report which profile is
/// active alongside the full list, and so any caller that only needs the name
/// avoids a clone. Every `Ok(name)` is guaranteed to key into `cfg.profiles`.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) when no single profile can be selected
/// (unknown `--profile`, a `default_profile` naming a missing profile, an ambiguous
/// multi-profile config with no selection, or an empty profile map).
pub fn select_active_name(cfg: &ToolConfig, name: Option<&str>) -> Result<String, ToolError> {
    if let Some(name) = name {
        return if cfg.profiles.contains_key(name) {
            Ok(name.to_owned())
        } else {
            Err(unknown_profile(cfg, name))
        };
    }
    if let Some(default) = cfg.default_profile.as_deref() {
        return if cfg.profiles.contains_key(default) {
            Ok(default.to_owned())
        } else {
            Err(ToolError::user(format!(
                "default_profile names a missing profile '{default}'; {}",
                available(cfg)
            )))
        };
    }
    let mut iter = cfg.profiles.keys();
    match (iter.next(), iter.next()) {
        (Some(only), None) => Ok(only.clone()),
        (None, _) => Err(ToolError::user("no profiles configured")),
        (Some(_), Some(_)) => Err(ToolError::user(
            "no profile selected: pass --profile or set default_profile",
        )),
    }
}

/// Error unless `name` is a configured `[profiles.<name>]`.
///
/// The CLI-boundary check behind an explicit `--profile`, so the documented global-flag
/// contract ("an unknown name errors and lists the available profiles") holds for every
/// verb rather than only for the ones that go on to *use* the profile. Read-only verbs
/// that select best-effort — `profiles`, `keys show` — otherwise report an unknown name as
/// "no active profile", which reads as a missing `default_profile`.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) if the config cannot be loaded, or if `name` is not a
/// configured profile; the message lists the available names.
pub fn ensure_exists(config_path: Option<&Path>, name: &str) -> Result<(), ToolError> {
    let cfg = ToolConfig::load(config_path)
        .map_err(|e| ToolError::user(format!("loading tool config: {e}")))?;
    if cfg.profiles.contains_key(name) {
        Ok(())
    } else {
        Err(unknown_profile(&cfg, name))
    }
}

/// The "unknown profile" error, listing the available names.
fn unknown_profile(cfg: &ToolConfig, name: &str) -> ToolError {
    ToolError::user(format!("unknown profile '{name}'; {}", available(cfg)))
}

/// A human-readable list of the configured profile names (or a note when none).
fn available(cfg: &ToolConfig) -> String {
    if cfg.profiles.is_empty() {
        "no profiles configured".to_owned()
    } else {
        let names: Vec<&str> = cfg.profiles.keys().map(String::as_str).collect();
        format!("available: {}", names.join(", "))
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use std::collections::BTreeMap;

    use super::*;

    /// A config with the given profile names (each with a distinguishing
    /// `service_url`) and an optional `default_profile`.
    fn cfg_with(profiles: &[&str], default: Option<&str>) -> ToolConfig {
        let mut cfg = ToolConfig::default();
        let mut map = BTreeMap::new();
        for name in profiles {
            map.insert(
                (*name).to_owned(),
                Profile {
                    service_url: Some(format!("https://{name}.example")),
                    ..Profile::default()
                },
            );
        }
        cfg.profiles = map;
        cfg.default_profile = default.map(str::to_owned);
        cfg
    }

    #[test]
    fn named_profile_is_selected() {
        let cfg = cfg_with(&["prod", "dev"], None);
        let p = select_profile(&cfg, Some("dev")).unwrap();
        assert_eq!(p.service_url.as_deref(), Some("https://dev.example"));
    }

    #[test]
    fn default_profile_is_used_without_flag() {
        let cfg = cfg_with(&["prod", "dev"], Some("prod"));
        let p = select_profile(&cfg, None).unwrap();
        assert_eq!(p.service_url.as_deref(), Some("https://prod.example"));
    }

    #[test]
    fn sole_profile_is_used_without_flag_or_default() {
        let cfg = cfg_with(&["only"], None);
        let p = select_profile(&cfg, None).unwrap();
        assert_eq!(p.service_url.as_deref(), Some("https://only.example"));
    }

    #[test]
    fn load_or_default_returns_a_default_profile_when_none_configured() {
        // A config with no `[profiles.*]` must yield an empty default profile for a
        // self-contained invocation (`doctor --offline --recipient`), not "no profiles
        // configured". A file with only a root key and no profiles exercises this.
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("tool.toml");
        std::fs::write(&cfg_path, "country_code = \"EE\"\n").unwrap();

        let (name, profile) = load_active_named_or_default(Some(&cfg_path), None)
            .expect("defaults without a profile");
        assert_eq!(name, "default");
        assert!(profile.service_url.is_none() && profile.catalogs.is_empty());

        // But an explicit --profile against an empty config still errors: the operator
        // asked for a named profile that does not exist.
        let err = load_active_named_or_default(Some(&cfg_path), Some("airgap")).unwrap_err();
        assert_eq!(err.exit_code, 1);
    }

    #[test]
    fn unknown_named_profile_errors_listing_available() {
        let cfg = cfg_with(&["prod", "dev"], None);
        let err = select_profile(&cfg, Some("staging")).unwrap_err();
        assert_eq!(err.exit_code, 1);
        assert!(
            err.message.contains("unknown profile 'staging'"),
            "{}",
            err.message
        );
        assert!(err.message.contains("dev"), "{}", err.message);
        assert!(err.message.contains("prod"), "{}", err.message);
    }

    #[test]
    fn missing_default_profile_errors() {
        let cfg = cfg_with(&["prod"], Some("nope"));
        let err = select_profile(&cfg, None).unwrap_err();
        assert_eq!(err.exit_code, 1);
        assert!(
            err.message
                .contains("default_profile names a missing profile 'nope'"),
            "{}",
            err.message
        );
    }

    #[test]
    fn ambiguous_without_flag_or_default_errors() {
        let cfg = cfg_with(&["prod", "dev"], None);
        let err = select_profile(&cfg, None).unwrap_err();
        assert_eq!(err.exit_code, 1);
        assert!(
            err.message.contains("no profile selected"),
            "{}",
            err.message
        );
    }

    #[test]
    fn empty_map_errors() {
        let cfg = ToolConfig::default();
        let err = select_profile(&cfg, None).unwrap_err();
        assert_eq!(err.exit_code, 1);
        assert!(
            err.message.contains("no profiles configured"),
            "{}",
            err.message
        );
    }
}
