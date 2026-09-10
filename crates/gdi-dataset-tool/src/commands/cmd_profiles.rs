//! `gdi-dataset-tool profiles` — show the configured profiles and which one is
//! active, with secrets redacted.
//!
//! A read-only introspection command (it never edits config): profile selection is
//! an otherwise-silent 4-step precedence (`--profile`, the `default_profile` key, a
//! sole profile) that picks which node deployment the networked verbs target —
//! bucket, URLs, recipient. `profiles` answers "which profile am I on, and what does
//! it resolve to?", removing a class of "uploaded to the wrong node" mistakes.
//!
//! Credentials are never printed: `access_key_id` and `secret_access_key` are shown
//! only as `set` / `unset` (the config's `Debug` reveals `access_key_id`, so this is
//! the safe surface for it).

use std::path::Path;

use gdi_node_standalone_core::config::{Profile, ProfileHeaderPolicy, ToolConfig};

use crate::ToolError;
use crate::cli::{OutputFormat, ProfilesArgs};
use crate::profile;

/// Run `profiles`: print every configured profile (resolved fields, secrets
/// redacted) and mark the active one.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) only if the tool config cannot be loaded. An
/// unselectable active profile (none configured, or ambiguous with no `--profile` /
/// default) is reported as "no active profile", not an error — the point is to
/// *show* that state so the operator knows they must pass `--profile`.
pub fn run(
    args: &ProfilesArgs,
    profile_flag: Option<&str>,
    config_path: Option<&Path>,
) -> Result<(), ToolError> {
    let cfg = ToolConfig::load(config_path)
        .map_err(|e| ToolError::user(format!("loading tool config: {e}")))?;
    // `profiles` resolves the active name directly (it reports state, it never acts), so it
    // bypasses `load_active_named` — and with it the hyphen/underscore twin warning. Emit it
    // here too: this is the command an operator runs to ask "why aren't my env creds taking
    // effect?", and the phantom twin is the answer.
    profile::warn_phantom_profile_twins(&cfg);
    // Name the resolved path in both branches. "the default location" is the one answer
    // this command cannot usefully give: `profiles` is what an operator runs to ask which
    // config is in force, and the default location is exactly what varies — it follows
    // `$GDI_CONFIG_DIR` / `$XDG_CONFIG_HOME` / `$HOME`, so the phrase names a different file
    // on every machine while reading as though it named one.
    match config_path {
        Some(p) => crate::output::note(&format!("loaded tool config from {}", p.display())),
        None => match gdi_node_standalone_core::config::default_config_path() {
            // `ToolConfig::load(None)` merges the default file only if it exists; say which.
            Some(p) if p.is_file() => crate::output::note(&format!(
                "loaded tool config from {} (the default location; override with --config)",
                p.display()
            )),
            Some(p) => crate::output::note(&format!(
                "no tool config file at {} (the default location; override with --config), so \
                 only the GDI_TOOL__ env overlay is in force",
                p.display()
            )),
            None => crate::output::note(
                "no tool config file: no config dir resolves (GDI_CONFIG_DIR, XDG_CONFIG_HOME \
                 and HOME are all unset), so only the GDI_TOOL__ env overlay is in force",
            ),
        },
    }
    crate::output::note(&format!(
        "{} profile(s) configured (credentials shown masked as set/unset)",
        cfg.profiles.len()
    ));
    // Best-effort: an ambiguous/empty selection is shown as "no active profile",
    // not surfaced as an error — `profiles` reports state, it does not act.
    let active = profile::select_active_name(&cfg, profile_flag).ok();

    match args.format {
        OutputFormat::Json => print_json(&cfg, active.as_deref()),
        OutputFormat::Text => print_text(&cfg, active.as_deref()),
    }
    Ok(())
}

/// Whether an optional secret is present, as a redacted `set`/`unset` token (never
/// the value itself).
fn presence(v: Option<&str>) -> &'static str {
    if v.is_some_and(|s| !s.is_empty()) {
        "set"
    } else {
        "unset"
    }
}

/// One profile as a JSON object (secrets redacted to `set`/`unset`).
fn profile_json(name: &str, p: &Profile, active: bool) -> serde_json::Value {
    let s3 = p.s3.as_ref().map(|s3| {
        serde_json::json!({
            "bucket": s3.bucket,
            // `prefix` and `channel` decide where in the bucket the tool writes and which
            // node channel it expects to own the result — the two facts an operator checks
            // when a publish "succeeded" and the node saw nothing.
            "prefix": s3.prefix,
            "channel": s3.channel,
            "endpoint": s3.endpoint,
            "region": s3.region,
            "access_key_id": presence(s3.access_key_id.as_deref()),
            "secret_access_key": presence(s3.secret_access_key.as_deref()),
        })
    });
    serde_json::json!({
        "name": name,
        "active": active,
        "service_url": p.service_url,
        "org": p.org,
        "management_url": p.management_url,
        "node_state_base": p.node_state_base(),
        "inbox": p.inbox,
        "node_recipient_url": p.node_recipient_url,
        "node_recipient_file": p.node_recipient_file,
        "s3": s3,
        "catalogs": p.catalogs.keys().collect::<Vec<_>>(),
        "header_policy": p.header_policy.map(ProfileHeaderPolicy::as_str),
    })
}

/// Print the machine-readable `{active, default_profile, profiles}` object.
fn print_json(cfg: &ToolConfig, active: Option<&str>) {
    let profiles: Vec<serde_json::Value> = cfg
        .profiles
        .iter()
        .map(|(name, p)| profile_json(name, p, Some(name.as_str()) == active))
        .collect();
    let out = serde_json::json!({
        "schemaVersion": 1,
        "active": active,
        "default_profile": cfg.default_profile,
        "profiles": profiles,
    });
    crate::output::emit_json(&out);
}

/// Print a concise human-readable listing, marking the active profile.
fn print_text(cfg: &ToolConfig, active: Option<&str>) {
    if cfg.profiles.is_empty() {
        println!("no profiles configured");
        return;
    }
    match active {
        Some(name) => println!("active profile: {name}"),
        None => {
            println!("active profile: (none; pass --profile or set default_profile)");
        }
    }
    if let Some(def) = &cfg.default_profile {
        println!("default_profile: {def}");
    }
    for (name, p) in &cfg.profiles {
        let marker = if Some(name.as_str()) == active {
            " (active)"
        } else {
            ""
        };
        println!("\n[{name}]{marker}");
        print_opt("  service_url        ", p.service_url.as_deref());
        print_opt("  org                ", p.org.as_deref());
        print_opt("  management_url     ", p.management_url.as_deref());
        print_opt("  inbox              ", p.inbox.as_deref());
        print_opt("  node_recipient_url ", p.node_recipient_url.as_deref());
        print_opt("  node_recipient_file", p.node_recipient_file.as_deref());
        if let Some(s3) = &p.s3 {
            print_opt("  s3.bucket          ", s3.bucket.as_deref());
            print_opt(
                "  s3.prefix          ",
                Some(s3.prefix.as_str()).filter(|prefix| !prefix.is_empty()),
            );
            print_opt("  s3.channel         ", s3.channel.as_deref());
            print_opt("  s3.endpoint        ", s3.endpoint.as_deref());
            print_opt("  s3.region          ", s3.region.as_deref());
            println!(
                "  s3.access_key_id    = {}",
                presence(s3.access_key_id.as_deref())
            );
            println!(
                "  s3.secret_access_key = {}",
                presence(s3.secret_access_key.as_deref())
            );
        } else {
            println!("  s3                 = (none; inbox-only)");
        }
        let cats = if p.catalogs.is_empty() {
            "(none)".to_owned()
        } else {
            p.catalogs.keys().cloned().collect::<Vec<_>>().join(", ")
        };
        println!("  catalogs ({}): {cats}", p.catalogs.len());
        println!(
            "  header_policy       = {}",
            p.header_policy
                .map_or("(unset; minimal)", ProfileHeaderPolicy::as_str)
        );
    }
}

/// Print `label = value`, rendering an absent value as `(unset)`.
fn print_opt(label: &str, v: Option<&str>) {
    println!("{label} = {}", v.unwrap_or("(unset)"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_json_reports_the_header_policy() {
        use gdi_node_standalone_core::config::ProfileHeaderPolicy;
        let unset = profile_json("a", &Profile::default(), false);
        assert_eq!(unset["header_policy"], serde_json::Value::Null);
        let set = profile_json(
            "b",
            &Profile {
                header_policy: Some(ProfileHeaderPolicy::WithIdentifiers),
                ..Profile::default()
            },
            false,
        );
        assert_eq!(set["header_policy"], "with-identifiers");
    }

    #[test]
    fn presence_redacts_to_set_or_unset() {
        assert_eq!(presence(Some("AKIAEXAMPLE")), "set");
        assert_eq!(presence(Some("")), "unset");
        assert_eq!(presence(None), "unset");
    }

    #[test]
    fn profile_json_never_emits_credential_values() {
        let mut p = Profile {
            service_url: Some("https://node.example".to_owned()),
            ..Profile::default()
        };
        p.s3 = Some(gdi_node_standalone_core::config::ProfileS3 {
            bucket: Some("gdi-ee".to_owned()),
            prefix: "gdi-node-storage/".to_owned(),
            channel: Some("primary".to_owned()),
            access_key_id: Some("AKIASECRETID".to_owned()),
            secret_access_key: Some("supersecret".to_owned()),
            ..gdi_node_standalone_core::config::ProfileS3::default()
        });
        let v = profile_json("prod", &p, true);
        let text = v.to_string();
        assert!(
            !text.contains("AKIASECRETID"),
            "access_key_id leaked: {text}"
        );
        assert!(!text.contains("supersecret"), "secret leaked: {text}");
        assert_eq!(v["s3"]["access_key_id"], "set");
        assert_eq!(v["s3"]["secret_access_key"], "set");
        assert_eq!(v["active"], true);
        assert_eq!(v["s3"]["bucket"], "gdi-ee");
        // The keyspace half of the S3 target: where in the bucket the tool writes, and the
        // node channel expected to own it — the pair an operator compares against the node's
        // `[[s3.buckets]]` when a publish went nowhere.
        assert_eq!(v["s3"]["prefix"], "gdi-node-storage/");
        assert_eq!(v["s3"]["channel"], "primary");
    }

    #[test]
    fn profile_json_reports_the_org() {
        let unset = profile_json("a", &Profile::default(), false);
        assert_eq!(unset["org"], serde_json::Value::Null);
        let set = profile_json(
            "b",
            &Profile {
                org: Some("UTARTU".into()),
                ..Profile::default()
            },
            false,
        );
        assert_eq!(set["org"], "UTARTU");
    }
}
