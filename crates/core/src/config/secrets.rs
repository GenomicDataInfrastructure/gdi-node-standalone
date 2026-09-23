//! `tool-secrets.toml`, where the tool keeps S3 credentials.
//!
//! Credentials never go in `tool.toml` ([`ToolConfig`] doesn't serialize them). They live in
//! this file next to it, and [`ToolConfig::load`] reads it on every run, so nothing has to be
//! loaded into the shell first. `GDI_TOOL__PROFILES__<NAME>__S3__…` variables override it.
//!
//! ```toml
//! [profiles.default.s3]
//! access_key_id = "…"
//! secret_access_key = "…"
//! ```
//!
//! Nothing else is allowed in the file, and an empty value counts as unset (so do the
//! placeholders `wizard setup` writes, until filled in). Credentials for a profile the config
//! doesn't define are skipped until it does, so a deleted `tool.toml` doesn't block
//! `wizard setup`. Credentials for a profile without an S3 block are an error: merging them
//! would invent the block.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{ToolConfig, config_base_dir};

/// The credentials file name.
///
/// Not `secrets.toml`: other projects use that name too, and with `--config` this file is
/// read, strictly, from whatever directory the config is in, so a stray one would break every
/// command. `tool.toml` is named for the same reason.
pub const SECRETS_FILE: &str = "tool-secrets.toml";

/// The access key field, as in `[profiles.<name>.s3]`.
const ACCESS_KEY_ID: &str = "access_key_id";
/// The secret key field, as in `[profiles.<name>.s3]`.
const SECRET_ACCESS_KEY: &str = "secret_access_key";

/// The top of a new file.
const HEADER: &str = "\
# S3 credentials for gdi-dataset-tool, one [profiles.<name>.s3] table per profile.
# GDI_TOOL__PROFILES__<NAME>__S3__... environment variables override them.
# Keep this file private: don't commit or share it.
";

/// The credentials file for a run: next to the `--config` file if one is given, else in the
/// gdi config dir, the same place as the keys and the recipient pin ([`config_base_dir`]).
/// `None` when neither resolves.
#[must_use]
pub fn secrets_path(config_path: Option<&Path>) -> Option<PathBuf> {
    config_base_dir(config_path).map(|dir| dir.join(SECRETS_FILE))
}

/// Set a profile's S3 credentials in the file at `path`, replacing any earlier pair and
/// leaving the rest of the file as it was. Written atomically, owner-only on Unix.
///
/// # Errors
///
/// An I/O error if `path` can't be read or written, or [`io::ErrorKind::InvalidData`] if it
/// isn't valid TOML or `profiles.<profile>.s3` isn't a table. The error doesn't include
/// `path`; the caller adds it.
pub fn set_s3_credentials(
    path: &Path,
    profile: &str,
    access_key_id: &str,
    secret_access_key: &str,
) -> io::Result<()> {
    let mut doc = read_document(path)?;
    let s3 = s3_table(&mut doc, profile)?;
    s3.insert(ACCESS_KEY_ID, toml_edit::value(access_key_id));
    s3.insert(SECRET_ACCESS_KEY, toml_edit::value(secret_access_key));
    crate::util::write_secret_durable(path, doc.to_string().as_bytes())
}

/// Add empty S3 credential placeholders for a profile, to be filled in by hand. Existing keys
/// are never replaced, and if both exist the file isn't rewritten, so re-running
/// `wizard setup` can't touch credentials typed into it.
///
/// # Errors
///
/// As [`set_s3_credentials`].
pub fn add_s3_credential_placeholders(path: &Path, profile: &str) -> io::Result<()> {
    let mut doc = read_document(path)?;
    let s3 = s3_table(&mut doc, profile)?;
    let mut added = false;
    for key in [ACCESS_KEY_ID, SECRET_ACCESS_KEY] {
        if !s3.contains_key(key) {
            s3.insert(key, toml_edit::value(""));
            added = true;
        }
    }
    if !added {
        return Ok(());
    }
    crate::util::write_secret_durable(path, doc.to_string().as_bytes())
}

/// The file at `path` as an editable document; a missing file is an empty one.
fn read_document(path: &Path) -> io::Result<toml_edit::DocumentMut> {
    match fs::read_to_string(path) {
        Ok(text) => text.parse().map_err(|e: toml_edit::TomlError| {
            // Not `Display`: it quotes the offending line, which here may hold a secret.
            invalid(&line_of(&text, e.span()), e.message())
        }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(toml_edit::DocumentMut::new()),
        Err(e) => Err(e),
    }
}

/// `profiles.<profile>.s3` in `doc`, created if missing. In a new file this table carries
/// the header.
fn s3_table<'a>(
    doc: &'a mut toml_edit::DocumentMut,
    profile: &str,
) -> io::Result<&'a mut toml_edit::Table> {
    let fresh = doc.as_table().is_empty();
    let profiles = child_table(doc.as_table_mut(), "profiles")?;
    let entry = child_table(profiles, profile)?;
    let s3 = child_table(entry, "s3")?;
    if fresh {
        s3.decor_mut().set_prefix(HEADER);
    }
    Ok(s3)
}

/// The table under `key` in `parent`, created if missing. New tables are implicit, so the
/// levels above `s3` print no header of their own.
fn child_table<'a>(
    parent: &'a mut toml_edit::Table,
    key: &str,
) -> io::Result<&'a mut toml_edit::Table> {
    parent
        .entry(key)
        .or_insert_with(|| {
            let mut table = toml_edit::Table::new();
            table.set_implicit(true);
            toml_edit::Item::Table(table)
        })
        .as_table_mut()
        .ok_or_else(|| invalid("", &format!("`{key}` is not a table")))
}

/// An `InvalidData` error reading `line` (empty or `"line N: "`) then `what`.
fn invalid(line: &str, what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("{line}{what}"))
}

/// `"line N: "` for where `span` starts in `text`, or empty without a span.
fn line_of(text: &str, span: Option<std::ops::Range<usize>>) -> String {
    span.and_then(|span| text.get(..span.start))
        .map(|before| format!("line {}: ", before.matches('\n').count() + 1))
        .unwrap_or_default()
}

/// What a `tool-secrets.toml` holds. [`ToolConfig::load`] merges it between the config file
/// and the environment.
///
/// Unknown fields are denied at every level, so the file can't turn into a second config. No
/// `Debug`, since it holds secrets.
#[derive(Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct Secrets {
    /// Per-profile credentials, keyed by profile name.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    profiles: BTreeMap<String, ProfileSecrets>,
}

/// One profile's table: only `s3`.
#[derive(Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ProfileSecrets {
    /// `[profiles.<name>.s3]`.
    #[serde(skip_serializing_if = "Option::is_none")]
    s3: Option<S3Secrets>,
}

/// One profile's two S3 credentials.
#[derive(Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct S3Secrets {
    /// The access key id.
    #[serde(skip_serializing_if = "Option::is_none")]
    access_key_id: Option<String>,
    /// The secret access key.
    #[serde(skip_serializing_if = "Option::is_none")]
    secret_access_key: Option<String>,
}

impl Secrets {
    /// The credentials in the file at `path`. `Ok(None)` if the file is missing or sets none
    /// (empty values count as unset).
    ///
    /// # Errors
    ///
    /// A message naming `path` if it can't be read, isn't valid TOML, or holds anything else.
    /// The message names keys, never values.
    pub(super) fn read(path: &Path) -> Result<Option<Self>, String> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        };
        let parsed: Self = toml::from_str(&text).map_err(|e| {
            // Not `Display`: it quotes the offending line, and a misspelled key's line still
            // holds the secret.
            format!(
                "{}: {}{}",
                path.display(),
                line_of(&text, e.span()),
                without_value(e.message())
            )
        })?;
        Ok(parsed.without_empty())
    }

    /// Drop empty values, then the tables they leave empty; `None` when nothing remains.
    fn without_empty(mut self) -> Option<Self> {
        let set = |value: Option<String>| value.filter(|v| !v.is_empty());
        self.profiles.retain(|_, profile| {
            profile.s3 = profile.s3.take().and_then(|s3| {
                let s3 = S3Secrets {
                    access_key_id: set(s3.access_key_id),
                    secret_access_key: set(s3.secret_access_key),
                };
                (s3.access_key_id.is_some() || s3.secret_access_key.is_some()).then_some(s3)
            });
            profile.s3.is_some()
        });
        (!self.profiles.is_empty()).then_some(self)
    }

    /// Fit these credentials to `config` (the config file and environment, without this
    /// file): skip profiles it doesn't define, and refuse one that has no S3 block. `None`
    /// when nothing is left.
    ///
    /// # Errors
    ///
    /// A message naming `path` and the first profile without an S3 block.
    pub(super) fn for_config(
        mut self,
        config: &ToolConfig,
        path: &Path,
    ) -> Result<Option<Self>, String> {
        self.profiles
            .retain(|name, _| config.profiles.contains_key(name));
        for name in self.profiles.keys() {
            if config.profiles.get(name).is_some_and(|p| p.s3.is_none()) {
                return Err(format!(
                    "{}: credentials for profile '{name}', but the tool config has no \
                     [profiles.{name}.s3] block; add the block or remove the credentials",
                    path.display()
                ));
            }
        }
        Ok((!self.profiles.is_empty()).then_some(self))
    }
}

/// A deserialization error `message` without the value it quotes. Serde puts the value in
/// type errors (``invalid type: integer `123`, expected a string``), and here it can be a
/// secret. The last ", expected" is the real one, in case the value itself contains one.
fn without_value(message: &str) -> String {
    let Some((_, expected)) = message
        .strip_prefix("invalid type: ")
        .and_then(|rest| rest.rsplit_once(", expected "))
    else {
        return message.to_owned();
    };
    let expected = if expected.starts_with("struct ") || expected == "a map" {
        "a table"
    } else {
        expected
    };
    format!("wrong type, expected {expected}")
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    #![expect(
        clippy::result_large_err,
        reason = "the figment::Jail::expect_with closure return type is fixed by the test API"
    )]

    use super::*;

    /// A `tool.toml` whose `default` profile has an S3 block and `inbox` has none.
    const CONFIG: &str = "\
[profiles.default.s3]
bucket = \"gdi-datasets\"
endpoint = \"https://s3.example.org\"

[profiles.inbox]
inbox = \"/var/lib/gdi/inbox\"
";

    fn creds(cfg: &ToolConfig, profile: &str) -> (Option<String>, Option<String>) {
        let s3 = cfg.profiles[profile].s3.as_ref().unwrap();
        (s3.access_key_id.clone(), s3.secret_access_key.clone())
    }

    fn some(a: &str, b: &str) -> (Option<String>, Option<String>) {
        (Some(a.to_owned()), Some(b.to_owned()))
    }

    /// What setup writes is what a later load reads, including quotes and backslashes.
    #[test]
    #[serial_test::serial(env)]
    fn written_credentials_are_what_a_later_load_reads() {
        figment::Jail::expect_with(|jail| {
            jail.create_file("tool.toml", CONFIG)?;
            let secrets = jail.directory().join(SECRETS_FILE);
            set_s3_credentials(&secrets, "default", "AKIA\"1", "it's/a\\secret=").unwrap();

            let cfg = ToolConfig::load(Some(&jail.directory().join("tool.toml"))).unwrap();
            assert_eq!(creds(&cfg, "default"), some("AKIA\"1", "it's/a\\secret="));
            Ok(())
        });
    }

    /// The environment beats this file, which beats a value in `tool.toml`, per credential.
    #[test]
    #[serial_test::serial(env)]
    fn the_environment_outranks_the_file_which_outranks_the_config() {
        figment::Jail::expect_with(|jail| {
            jail.create_file(
                "tool.toml",
                "[profiles.default.s3]\nbucket = \"b\"\naccess_key_id = \"INLINE\"\n\
                 secret_access_key = \"INLINE\"\n",
            )?;
            let secrets = jail.directory().join(SECRETS_FILE);
            set_s3_credentials(&secrets, "default", "FILE", "FILE").unwrap();
            let path = jail.directory().join("tool.toml");

            let cfg = ToolConfig::load(Some(&path)).unwrap();
            assert_eq!(
                creds(&cfg, "default"),
                some("FILE", "FILE"),
                "the file wins"
            );

            jail.set_env("GDI_TOOL__PROFILES__DEFAULT__S3__ACCESS_KEY_ID", "ENV");
            let cfg = ToolConfig::load(Some(&path)).unwrap();
            assert_eq!(
                creds(&cfg, "default"),
                some("ENV", "FILE"),
                "the environment wins, one credential at a time"
            );
            Ok(())
        });
    }

    /// Unfilled placeholders count as unset: no error, and no empty credentials.
    #[test]
    #[serial_test::serial(env)]
    fn empty_placeholders_are_unset() {
        figment::Jail::expect_with(|jail| {
            jail.create_file("tool.toml", CONFIG)?;
            let secrets = jail.directory().join(SECRETS_FILE);
            add_s3_credential_placeholders(&secrets, "default").unwrap();
            // Placeholders for a profile without S3 set nothing, so they're not an error.
            add_s3_credential_placeholders(&secrets, "inbox").unwrap();

            let cfg = ToolConfig::load(Some(&jail.directory().join("tool.toml"))).unwrap();
            assert_eq!(creds(&cfg, "default"), (None, None));
            assert!(
                cfg.profiles["inbox"].s3.is_none(),
                "no S3 block is invented for an inbox-only profile"
            );
            Ok(())
        });
    }

    /// Any other key is refused. The error names the file and line but never quotes it,
    /// since a misspelled key's line still holds the secret.
    #[test]
    #[serial_test::serial(env)]
    fn any_other_key_is_refused_without_quoting_the_file() {
        figment::Jail::expect_with(|jail| {
            jail.create_file("tool.toml", CONFIG)?;
            jail.create_file(
                SECRETS_FILE,
                "[profiles.default.s3]\nsecret_acess_key = \"TOPSECRETVALUE\"\n",
            )?;
            let err = ToolConfig::load(Some(&jail.directory().join("tool.toml")))
                .err()
                .unwrap()
                .to_string();
            assert!(err.contains(SECRETS_FILE), "names the file: {err}");
            assert!(err.contains("line 2"), "names the line: {err}");
            assert!(err.contains("secret_acess_key"), "names the key: {err}");
            assert!(
                !err.contains("TOPSECRETVALUE"),
                "never quotes the value: {err}"
            );

            jail.create_file(SECRETS_FILE, "[profiles.default.s3]\nbucket = \"other\"\n")?;
            let err = ToolConfig::load(Some(&jail.directory().join("tool.toml")))
                .err()
                .unwrap()
                .to_string();
            assert!(
                err.contains("unknown field `bucket`"),
                "not a second config: {err}"
            );
            Ok(())
        });
    }

    /// Credentials for a configured profile with no S3 block are refused: merging them would
    /// give an inbox-only profile an S3 channel.
    #[test]
    #[serial_test::serial(env)]
    fn credentials_for_a_profile_without_s3_are_refused() {
        figment::Jail::expect_with(|jail| {
            jail.create_file("tool.toml", CONFIG)?;
            set_s3_credentials(&jail.directory().join(SECRETS_FILE), "inbox", "A", "S").unwrap();
            let err = ToolConfig::load(Some(&jail.directory().join("tool.toml")))
                .err()
                .unwrap()
                .to_string();
            assert!(
                err.contains("profile 'inbox'") && err.contains("[profiles.inbox.s3]"),
                "{err}"
            );
            Ok(())
        });
    }

    /// Credentials for a profile the config doesn't define are skipped, not turned into a
    /// phantom profile, and apply again once the profile is back. This is what lets
    /// `wizard setup` run after `tool.toml` was deleted.
    #[test]
    #[serial_test::serial(env)]
    fn credentials_for_an_undefined_profile_wait_for_it() {
        figment::Jail::expect_with(|jail| {
            let path = jail.directory().join("tool.toml");
            set_s3_credentials(&jail.directory().join(SECRETS_FILE), "default", "A", "S").unwrap();

            let cfg = ToolConfig::load(Some(&path)).unwrap();
            assert!(cfg.profiles.is_empty(), "no phantom profile");

            jail.create_file("tool.toml", CONFIG)?;
            let cfg = ToolConfig::load(Some(&path)).unwrap();
            assert_eq!(creds(&cfg, "default"), some("A", "S"));
            Ok(())
        });
    }

    /// A value of the wrong type is refused without echoing it: an unquoted number, or a
    /// string where a table belongs.
    #[test]
    #[serial_test::serial(env)]
    fn a_wrong_type_is_refused_without_echoing_the_value() {
        figment::Jail::expect_with(|jail| {
            jail.create_file("tool.toml", CONFIG)?;
            let path = jail.directory().join("tool.toml");
            for (body, expected) in [
                (
                    "[profiles.default.s3]\nsecret_access_key = 98765432109876\n",
                    "expected a string",
                ),
                (
                    "[profiles.default]\ns3 = \"98765432109876\"\n",
                    "expected a table",
                ),
            ] {
                jail.create_file(SECRETS_FILE, body)?;
                let err = ToolConfig::load(Some(&path)).err().unwrap().to_string();
                assert!(
                    !err.contains("98765432109876"),
                    "the value is echoed: {err}"
                );
                assert!(err.contains("line 2") && err.contains(expected), "{err}");
            }
            Ok(())
        });
    }

    /// With `--config`, only the file next to it is read; without, the one in the config dir.
    #[test]
    #[serial_test::serial(env)]
    fn the_file_beside_the_config_is_the_only_one_read() {
        figment::Jail::expect_with(|jail| {
            let env_dir = jail.directory().join("env");
            let cfg_dir = jail.directory().join("cfg");
            std::fs::create_dir_all(&env_dir).unwrap();
            std::fs::create_dir_all(&cfg_dir).unwrap();
            std::fs::write(env_dir.join("tool.toml"), CONFIG).unwrap();
            std::fs::write(cfg_dir.join("tool.toml"), CONFIG).unwrap();
            set_s3_credentials(&env_dir.join(SECRETS_FILE), "default", "ENVDIR", "ENVDIR").unwrap();
            jail.set_env("GDI_CONFIG_DIR", env_dir.display().to_string());

            let beside = ToolConfig::load(Some(&cfg_dir.join("tool.toml"))).unwrap();
            assert_eq!(creds(&beside, "default"), (None, None));
            let default = ToolConfig::load(None).unwrap();
            assert_eq!(creds(&default, "default"), some("ENVDIR", "ENVDIR"));
            Ok(())
        });
    }

    /// Rewriting `tool.toml` never reads this file, so it can't copy a credential into it.
    #[test]
    #[serial_test::serial(env)]
    fn the_config_rewrite_path_never_reads_the_file() {
        figment::Jail::expect_with(|jail| {
            jail.create_file("tool.toml", CONFIG)?;
            let path = jail.directory().join("tool.toml");
            set_s3_credentials(&jail.directory().join(SECRETS_FILE), "default", "A", "S").unwrap();

            let on_disk = ToolConfig::load_file_only(&path).unwrap();
            assert_eq!(creds(&on_disk, "default"), (None, None));
            crate::config::write(&ToolConfig::load(Some(&path)).unwrap(), &path).unwrap();
            let rewritten = std::fs::read_to_string(&path).unwrap();
            assert!(!rewritten.contains("access_key_id"), "{rewritten}");
            Ok(())
        });
    }

    /// Setting credentials replaces the old pair and keeps other profiles.
    #[test]
    fn setting_replaces_the_pair_and_keeps_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(SECRETS_FILE);
        add_s3_credential_placeholders(&path, "other").unwrap();
        set_s3_credentials(&path, "default", "A1", "S1").unwrap();
        set_s3_credentials(&path, "default", "A2", "S2").unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with(HEADER), "{text}");
        assert!(text.contains("[profiles.other.s3]"), "{text}");
        assert!(!text.contains("A1") && !text.contains("S1"), "{text}");
        assert_eq!(text.matches("access_key_id").count(), 2, "{text}");
        let doc: toml::Table = toml::from_str(&text).unwrap();
        assert_eq!(
            doc["profiles"]["default"]["s3"]["access_key_id"].as_str(),
            Some("A2")
        );
        assert_eq!(
            doc["profiles"]["default"]["s3"]["secret_access_key"].as_str(),
            Some("S2")
        );
    }

    /// Placeholders never replace a value, and nothing is written when both keys exist.
    #[test]
    fn placeholders_never_replace_a_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(SECRETS_FILE);
        add_s3_credential_placeholders(&path, "default").unwrap();
        let filled = std::fs::read_to_string(&path).unwrap().replace(
            "access_key_id = \"\"",
            "access_key_id = \"FILLED\"  # typed by hand",
        );
        std::fs::write(&path, &filled).unwrap();

        add_s3_credential_placeholders(&path, "default").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), filled, "untouched");

        add_s3_credential_placeholders(&path, "second").unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains("access_key_id = \"FILLED\"  # typed by hand"),
            "{text}"
        );
        assert!(text.contains("[profiles.second.s3]"), "{text}");
    }

    /// A non-table where a table should be is an error, and the file is left alone.
    #[test]
    fn a_non_table_level_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(SECRETS_FILE);
        std::fs::write(&path, "profiles = 3\n").unwrap();
        let err = set_s3_credentials(&path, "default", "A", "S").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("`profiles` is not a table"),
            "{err}"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "profiles = 3\n");
    }

    /// The file is created owner-only.
    #[cfg(unix)]
    #[test]
    fn a_new_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        for (i, write) in [
            |p: &Path| add_s3_credential_placeholders(p, "default"),
            |p: &Path| set_s3_credentials(p, "default", "A", "S"),
        ]
        .into_iter()
        .enumerate()
        {
            let path = dir.path().join(format!("{i}-{SECRETS_FILE}"));
            write(&path).unwrap();
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
