//! The `config` command: scaffold the tool-configuration TOML.
//!
//! `config init` writes a commented `tool.toml` template — the non-interactive
//! twin of the wizard's setup, for CI/headless provisioning. It writes only
//! non-secret settings: S3 credentials go in the `GDI_TOOL__…` env overlay (or a
//! separate secrets file), never the config (see the wizard design).

use std::fs;
use std::path::{Path, PathBuf};

use crate::ToolError;
use crate::cli::{ConfigArgs, ConfigCommand, ConfigInitArgs};

/// The scaffolded `tool.toml` template: provider-wide root keys, one example
/// `[profiles.<name>]` with its `[.s3]` (non-secret fields only) and `[.catalogs]`,
/// and a comment block pointing at the `GDI_TOOL__…` env vars for the S3 credentials.
const TEMPLATE: &str = r#"# gdi-dataset-tool configuration.
#
# Precedence: a `--config <path>` file (or this default <config_dir>/tool.toml)
# is overlaid by the `GDI_TOOL__...` environment overlay, which wins. S3 CREDENTIALS ARE
# NEVER STORED HERE. Set them via env (or a sourced secrets file):
#   export GDI_TOOL__PROFILES__default__S3__ACCESS_KEY_ID=...
#   export GDI_TOOL__PROFILES__default__S3__SECRET_ACCESS_KEY=...

# Provider-wide root keys (before any [section]).
# Two-letter country code for dataset IDs (or set GDI_TOOL__COUNTRY_CODE / --cc).
# country_code = "EE"
# The profile used when --profile is omitted (defaults to the sole profile).
# default_profile = "default"

[profiles.default]
# The node's public base URL (FDP + /.well-known/c4gh-recipient).
service_url = "REPLACE: https://node.example"
# The institute abbreviation minted into every dataset id (the ORG in GDI-EE-<ORG>-...);
# `wizard setup` asks for it once, and the wizard's authoring stage then never does.
# org = "REPLACE: UTARTU"
# The node's management-plane base URL (state oracle for deploy/status); optional.
# management_url = "REPLACE: https://node.example:9090"
# Local inbox directory of a co-located node (the `deploy` drop target); optional.
# inbox = "REPLACE: /var/lib/gdi-node/inbox"
# Pinned node crypt4gh recipient (run `keys pin-recipient` to populate this).
# node_recipient_file = "recipients/default.pub"
# Where the recipient was fetched from (recorded by `keys pin-recipient`); optional.
# node_recipient_url = "REPLACE: https://node.example/.well-known/c4gh-recipient"
# A keyless node takes plaintext staging dirs in its inbox and needs no recipient.
# keyless = false
# VCF headers to ship in packages: none | minimal | with-identifiers (the node drops
# them at ingest; `--header-policy` on build/package overrides this per run).
# header_policy = "minimal"

[profiles.default.s3]
# Non-secret S3 settings only (credentials come from the GDI_TOOL__... env overlay).
# bucket = "REPLACE: my-bucket"
# Key prefix inside the bucket; must match the node's [[s3.buckets]].prefix for this
# channel, or the tool writes where the node does not look.
# prefix = "gdi-node-storage/"
# The node channel that monitors this bucket (catches wrong-bucket publishes).
# channel = "REPLACE: primary"
# endpoint = "REPLACE: https://s3.example"
# region = "us-east-1"
# path_style = true
# allow_http = false

[profiles.default.catalogs]
# Offline allow-list (catalog name -> display title); run `catalogs --sync` to
# populate it from the node.
# gdi-aggregated = "GoE aggregated"
"#;

/// Run `config`.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) if the output path cannot be resolved
/// (when neither `-o`/`--output` nor `--config` is given and the default config
/// directory is also unavailable), if the output exists without `--force`, or on
/// a filesystem error.
pub fn run(args: &ConfigArgs, config_path: Option<&Path>) -> Result<(), ToolError> {
    match &args.command {
        ConfigCommand::Init(init) => init_config(init, config_path),
    }
}

/// `config init`: write the template to the output path resolved in precedence
/// order: `-o`/`--output` flag → `--config` path → default `<config_dir>/tool.toml`.
fn init_config(args: &ConfigInitArgs, config_path: Option<&Path>) -> Result<(), ToolError> {
    let out: PathBuf = match args.output.clone() {
        Some(p) => p,
        None => match config_path {
            Some(p) => p.to_path_buf(),
            None => gdi_node_standalone_core::config::default_config_path().ok_or_else(|| {
                ToolError::user(
                    "cannot resolve the default config path: set $GDI_CONFIG_DIR, \
                     $XDG_CONFIG_HOME, or $HOME, or pass --output / --config",
                )
            })?,
        },
    };
    if out.exists() && !args.force {
        return Err(ToolError::user(format!(
            "output already exists: {} (use --force to overwrite)",
            out.display()
        )));
    }
    if let Some(parent) = out.parent()
        && !parent.as_os_str().is_empty()
    {
        #[expect(
            clippy::disallowed_methods,
            reason = "the operator's config directory; tool.toml itself is written 0600"
        )]
        fs::create_dir_all(parent)
            .map_err(|e| ToolError::user(format!("cannot create {}: {e}", parent.display())))?;
    }
    // Reaching here with the file present means `--force`, i.e. we are about to replace a
    // real, possibly hand-curated tool.toml with the placeholder template. Every other
    // writer of this same file backs it up first — `config::write` (used by the wizard and
    // by `catalogs --sync`) leaves a `.bak`, and `keys generate --force` names its backup —
    // so `init --force` was the one path that destroyed the operator's configuration with
    // no recourse and no mention of it. Owner-only, because the file it copies can carry
    // inline credentials.
    if out.exists() {
        let existing = fs::read(&out)
            .map_err(|e| ToolError::user(format!("cannot read {}: {e}", out.display())))?;
        let mut b = out.clone().into_os_string();
        b.push(".bak");
        let backup = PathBuf::from(b);
        gdi_node_standalone_core::util::write_durable_atomic_private(&backup, &existing).map_err(
            |e| {
                ToolError::user(format!(
                    "cannot back up {} to {}: {e}",
                    out.display(),
                    backup.display()
                ))
            },
        )?;
        println!("backed up existing config to {}", backup.display());
    }
    // Owner-only from the first write, through the same chokepoint as the backup above and
    // as `config::write`: the operator edits this file in place, and the credentials it may
    // then carry must not inherit a 0644 the scaffold chose for them.
    gdi_node_standalone_core::util::write_durable_atomic_private(&out, TEMPLATE.as_bytes())
        .map_err(|e| ToolError::user(format!("cannot write {}: {e}", out.display())))?;
    println!("wrote tool config template to {}", out.display());
    eprintln!(
        "next: edit {} (set [profiles.default].service_url + country_code), \
         run `gdi-dataset-tool keys pin-recipient` and `catalogs --sync`, then `doctor`",
        out.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_parses_as_tool_config_and_omits_secrets() {
        // The committed template must always deserialize (so a freshly scaffolded
        // config never fails to load).
        let cfg: gdi_node_standalone_core::config::ToolConfig =
            toml::from_str(TEMPLATE).expect("template parses as ToolConfig");
        assert!(cfg.profiles.contains_key("default"));
        assert!(!TEMPLATE.contains("secret_access_key ="));
        assert!(TEMPLATE.contains("GDI_TOOL__PROFILES__"));
    }

    /// The template's `# key = value` lines, uncommented, so the documented keys become real
    /// keys: parsing the result under `deny_unknown_fields` proves every documented key
    /// exists, and its key set is what the completeness check below compares.
    fn template_with_documented_keys_active() -> String {
        TEMPLATE
            .lines()
            .map(|line| {
                let documented = line.strip_prefix("# ").filter(|rest| {
                    rest.split_once(" = ").is_some_and(|(key, _)| {
                        !key.is_empty()
                            && key.bytes().all(|b| {
                                b.is_ascii_lowercase()
                                    || b.is_ascii_digit()
                                    || b == b'_'
                                    || b == b'-'
                            })
                    })
                });
                documented.unwrap_or(line)
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Every `Profile` and `ProfileS3` field the config can carry is documented in the
    /// template, active or commented out, and nothing documented is a key the structs
    /// reject. The expected set is derived from a fully-populated instance through serde,
    /// so a field added to either struct fails here until the template names it; the two
    /// credential fields are `skip_serializing` and therefore never in that set: they are
    /// documented as the env overlay instead.
    #[test]
    fn template_documents_every_profile_field() {
        use gdi_node_standalone_core::config::{
            Profile, ProfileHeaderPolicy, ProfileS3, ToolConfig,
        };
        use std::collections::BTreeSet;

        let active = template_with_documented_keys_active();
        let parsed: ToolConfig =
            toml::from_str(&active).expect("every documented key must exist on the structs");
        assert!(parsed.profiles.contains_key("default"));

        let doc: toml::Value = toml::from_str(&active).expect("template parses as TOML");
        let profile_table = &doc["profiles"]["default"];
        let documented: BTreeSet<String> = profile_table
            .as_table()
            .expect("[profiles.default] is a table")
            .keys()
            .cloned()
            .collect();
        let documented_s3: BTreeSet<String> = profile_table["s3"]
            .as_table()
            .expect("[profiles.default.s3] is a table")
            .keys()
            .cloned()
            .collect();

        let full = Profile {
            service_url: Some("x".to_owned()),
            org: Some("x".to_owned()),
            management_url: Some("x".to_owned()),
            inbox: Some("x".to_owned()),
            node_recipient_url: Some("x".to_owned()),
            node_recipient_file: Some("x".to_owned()),
            s3: Some(ProfileS3 {
                bucket: Some("x".to_owned()),
                prefix: "x".to_owned(),
                channel: Some("x".to_owned()),
                endpoint: Some("x".to_owned()),
                region: Some("x".to_owned()),
                path_style: true,
                allow_http: true,
                access_key_id: Some("x".to_owned()),
                secret_access_key: Some("x".to_owned()),
            }),
            catalogs: std::collections::BTreeMap::from([("x".to_owned(), "x".to_owned())]),
            keyless: true,
            header_policy: Some(ProfileHeaderPolicy::Minimal),
        };
        let serde_json::Value::Object(fields) = serde_json::to_value(&full).expect("serialise")
        else {
            panic!("Profile serialises to an object")
        };
        let expected: BTreeSet<String> = fields.keys().cloned().collect();
        let serde_json::Value::Object(s3_fields) = fields["s3"].clone() else {
            panic!("ProfileS3 serialises to an object")
        };
        let expected_s3: BTreeSet<String> = s3_fields.keys().cloned().collect();

        assert_eq!(
            documented, expected,
            "[profiles.default] in TEMPLATE must document every Profile field (commented \
             `# key = value` counts)"
        );
        assert_eq!(
            documented_s3, expected_s3,
            "[profiles.default.s3] in TEMPLATE must document every ProfileS3 field the \
             config file can carry"
        );
    }

    /// The scaffolded file is owner-only, like every other writer of `tool.toml`: the
    /// operator edits it in place, and the credentials it may then carry must not inherit a
    /// 0644 the scaffold chose. `--force` over an existing file keeps the mode too.
    #[cfg(unix)]
    #[test]
    fn init_writes_the_template_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("tool.toml");
        let mode = |path: &Path| {
            std::fs::metadata(path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777
        };

        init_config(
            &ConfigInitArgs {
                output: Some(out.clone()),
                force: false,
            },
            None,
        )
        .expect("config init");
        assert_eq!(mode(&out), 0o600, "a fresh tool.toml must start owner-only");

        init_config(
            &ConfigInitArgs {
                output: Some(out.clone()),
                force: true,
            },
            None,
        )
        .expect("config init");
        assert_eq!(mode(&out), 0o600, "--force must not widen the mode");
    }
}
