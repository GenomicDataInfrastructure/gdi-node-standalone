//! The `catalogs` command: list the catalog names this node accepts.
//!
//! Online (a `service_url` is configured and `--offline` is not set) the list
//! comes from the node's public FDP root; offline it comes from the profile's
//! `catalogs` allow-list. Used to validate `metadata.catalog` and to scaffold
//! `init`.
//!
//! The FDP parse lives in [`crate::catalogs`]; this is the thin clap wrapper.

use std::path::Path;

use gdi_node_standalone_core::config::{self, ToolConfig};

use crate::cli::{CatalogsArgs, OutputFormat};
use crate::{ToolError, catalogs, profile, runtime};

/// Run `catalogs`.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) when the FDP root is unreachable (online), or
/// when neither a `service_url` nor a `catalogs` allow-list is configured.
pub fn run(
    args: &CatalogsArgs,
    profile_name: Option<&str>,
    config_path: Option<&Path>,
) -> Result<(), ToolError> {
    let active = profile::load_active(config_path, profile_name)?;

    if args.sync {
        return sync_catalogs(profile_name, config_path, args.format, args.dry_run);
    }

    let online_base = if args.offline {
        None
    } else {
        active.service_url.as_deref()
    };

    if let Some(base) = online_base {
        crate::output::note(&format!(
            "reading catalogs from the node FDP root at {base} \
             (profile allow-list: {} entr(ies) used for titles)",
            active.catalogs.len()
        ));
    } else {
        crate::output::note(&format!(
            "reading catalogs from the offline profile allow-list ({} entr(ies))",
            active.catalogs.len()
        ));
    }

    // Collect (name, optional display title) pairs once, then render per format. The
    // title comes from the profile `catalogs` allow-list when known (online), or is
    // the allow-list (offline).
    let entries: Vec<(String, Option<String>)> = if let Some(base) = online_base {
        crate::s3::install_crypto_provider();
        runtime::block_on(catalogs::fetch_node_catalogs(base))?
            .into_iter()
            .map(|name| {
                let title = active.catalogs.get(&name).cloned();
                (name, title)
            })
            .collect()
    } else {
        // Offline: the profile's catalogs allow-list (name -> display title).
        if active.catalogs.is_empty() {
            return Err(ToolError::user(
                "no catalogs available: the active profile has no `catalogs` allow-list and no \
                 reachable `service_url` (configure one, or run online)",
            ));
        }
        active
            .catalogs
            .iter()
            .map(|(name, title)| (name.clone(), Some(title.clone())))
            .collect()
    };

    crate::output::note(&format!("resolved {} catalog(s)", entries.len()));

    match args.format {
        OutputFormat::Text => {
            if entries.is_empty() {
                println!("(node lists no catalogs)");
            }
            for (name, title) in &entries {
                match title {
                    Some(t) => println!("{name}\t{t}"),
                    None => println!("{name}"),
                }
            }
        }
        OutputFormat::Json => {
            let arr: Vec<_> = entries
                .iter()
                .map(|(name, title)| serde_json::json!({ "name": name, "title": title }))
                .collect();
            let out = serde_json::json!({ "schemaVersion": 1, "catalogs": arr });
            crate::output::emit_json(&out);
        }
    }
    Ok(())
}

/// `catalogs --sync`: fetch the node's catalogs and persist them into the active
/// profile's `catalogs` allow-list, atomically rewriting the config file.
///
/// # Errors
///
/// Returns a [`ToolError`] when no `service_url` is configured, the fetch fails,
/// the config path cannot be resolved, or the write fails.
pub(crate) fn sync_catalogs(
    profile_name: Option<&str>,
    config_path: Option<&Path>,
    format: OutputFormat,
    dry_run: bool,
) -> Result<(), ToolError> {
    let cfg = ToolConfig::load(config_path)
        .map_err(|e| ToolError::user(format!("loading tool config: {e}")))?;
    let name = profile::select_active_name(&cfg, profile_name)?;
    let base = cfg
        .profiles
        .get(&name)
        .and_then(|p| p.service_url.clone())
        .ok_or_else(|| {
            ToolError::user(format!(
                "profile '{name}' has no service_url; catalogs --sync needs an online node"
            ))
        })?;

    crate::s3::install_crypto_provider();
    let names = runtime::block_on(catalogs::fetch_node_catalogs(&base))?;
    crate::output::progress(&format!("fetched {} catalog(s) from {base}", names.len()));

    // Determine where to persist: the explicit --config, else the default file.
    let target = match config_path {
        Some(p) => p.to_path_buf(),
        None => config::default_config_path().ok_or_else(|| {
            ToolError::user(
                "cannot resolve the config path to write: pass --config or set \
                 $GDI_CONFIG_DIR / $XDG_CONFIG_HOME / $HOME",
            )
        })?,
    };

    // Build the write base from the file only (not the env-overlaid `cfg` above), so
    // `catalogs --sync` does not bake `GDI_TOOL__` env-overlay non-secret values into
    // config.toml — a later env change would otherwise be silently overridden by the frozen
    // file value. The env-overlaid `cfg` resolves only the profile name and service_url for
    // the live fetch.
    let mut write_cfg = if target.exists() {
        gdi_node_standalone_core::config::ToolConfig::load_file_only(&target).map_err(|e| {
            ToolError::user(format!("cannot read {} to update: {e}", target.display()))
        })?
    } else {
        gdi_node_standalone_core::config::ToolConfig::default()
    };
    // Reconcile the allow-list to the node's set while keeping the operator's titles. The
    // membership is the node's to decide; the title is the operator's, and nothing fetched
    // here supersedes it.
    //
    // A catalog the node still serves keeps its existing title, a newly-appeared one gets
    // the name as a placeholder the operator can edit, and a catalog the node dropped
    // disappears. The node's own `dct:title` is not consulted: that would need a fetch per
    // catalog and would put untrusted remote text into the operator's config file.
    let profile = write_cfg.profiles.entry(name.clone()).or_default();
    let previous = std::mem::take(&mut profile.catalogs);
    profile.catalogs = reconcile_catalogs(&previous, &names);

    // `config::write` decides whether a backup is taken, but the operator only benefits if
    // they are told. `--sync` rewrites the whole file, dropping comments and any inline
    // credentials, so name the byte-identical `<path>.bak` beside it. `keys generate
    // --force` names its backup the same way.
    let existed = target.exists();

    if dry_run {
        report_dry_run(&previous, &names, &name, &target, format);
        return Ok(());
    }

    config::write(&write_cfg, &target)
        .map_err(|e| ToolError::user(format!("cannot write {}: {e}", target.display())))?;
    let backup = existed.then(|| {
        let mut b = target.clone().into_os_string();
        b.push(".bak");
        std::path::PathBuf::from(b)
    });
    match format {
        OutputFormat::Json => {
            // A versioned envelope, so `--sync` is machine-consumable like the other
            // verbs rather than only printing a prose line.
            let out = serde_json::json!({
                "schemaVersion": 1,
                "action": "catalogs-sync",
                "profile": name,
                "path": target.display().to_string(),
                "catalogs": names,
                "backup": backup.as_ref().map(|b| b.display().to_string()),
            });
            crate::output::emit_json(&out);
        }
        OutputFormat::Text => {
            println!(
                "synced {} catalog(s) into profile '{name}' at {}",
                names.len(),
                target.display()
            );
            if let Some(backup) = &backup {
                println!(
                    "note: the previous config was copied to {} (this rewrite drops comments)",
                    backup.display()
                );
            }
        }
    }
    Ok(())
}

/// Report what `catalogs --sync` would change, writing nothing.
///
/// `--sync` rewrites the whole config file, dropping comments and any inline S3
/// credentials, so an operator wants to see the effect before committing to it.
fn report_dry_run(
    previous: &std::collections::BTreeMap<String, String>,
    names: &[String],
    profile: &str,
    target: &Path,
    format: OutputFormat,
) {
    let added: Vec<&String> = names
        .iter()
        .filter(|n| !previous.contains_key(*n))
        .collect();
    let removed: Vec<&String> = previous.keys().filter(|n| !names.contains(n)).collect();
    match format {
        OutputFormat::Json => {
            let out = serde_json::json!({
                "schemaVersion": 1,
                "action": "catalogs-sync",
                "dryRun": true,
                "profile": profile,
                "path": target.display().to_string(),
                "catalogs": names,
                "added": added,
                "removed": removed,
            });
            crate::output::emit_json(&out);
        }
        OutputFormat::Text => {
            println!(
                "dry run: {} catalog(s) would be synced into profile '{profile}' at {}; \
                 nothing written",
                names.len(),
                target.display()
            );
            for n in &added {
                println!("  + {n}");
            }
            for n in &removed {
                println!("  - {n}");
            }
            if added.is_empty() && removed.is_empty() {
                println!("  (no membership change; existing titles are kept)");
            }
        }
    }
}

/// Reconcile a profile's `catalogs` allow-list to the node's set, keeping existing titles.
///
/// Membership is the node's to decide; the display title is the operator's. A catalog the
/// node still serves keeps its configured title, a newly-appeared one gets its name as a
/// placeholder, and one the node no longer serves is dropped.
fn reconcile_catalogs(
    previous: &std::collections::BTreeMap<String, String>,
    names: &[String],
) -> std::collections::BTreeMap<String, String> {
    names
        .iter()
        .map(|n| {
            let title = previous.get(n).cloned().unwrap_or_else(|| n.clone());
            (n.clone(), title)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `catalogs --sync` must not overwrite curated titles.
    ///
    /// Writing `(name, name)` for every entry would replace the operator's display titles
    /// with placeholders on a command whose purpose is to make offline runs match the node.
    /// Membership is the node's call; the title is not.
    #[test]
    fn sync_keeps_existing_titles_and_only_reconciles_membership() {
        let previous: std::collections::BTreeMap<String, String> = [
            ("gdi-aggregated", "Genome of Europe Aggregated Data"),
            ("retired", "A catalog the node no longer serves"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();

        let names = vec!["gdi-aggregated".to_owned(), "brand-new".to_owned()];
        let got = reconcile_catalogs(&previous, &names);

        assert_eq!(
            got.get("gdi-aggregated").map(String::as_str),
            Some("Genome of Europe Aggregated Data"),
            "a still-served catalog must keep the operator's title"
        );
        assert_eq!(
            got.get("brand-new").map(String::as_str),
            Some("brand-new"),
            "a newly-appeared catalog gets its name as an editable placeholder"
        );
        assert!(
            !got.contains_key("retired"),
            "a catalog the node no longer serves is dropped"
        );
        assert_eq!(got.len(), 2);
    }
}
