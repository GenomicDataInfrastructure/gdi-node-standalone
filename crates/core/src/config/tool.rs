//! `gdi-dataset-tool` configuration ([`ToolConfig`]): provider-wide root settings,
//! `[keys]` crypt4gh identities, and named `[profiles.<name>]` target-node deployments.
//! Sibling of the service's [`super::ServiceConfig`]. The shared secret-`Debug` helper
//! [`super::redacted`] lives in the module root.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use figment::{
    Figment,
    providers::{Env, Format, Toml},
};
use serde::{Deserialize, Serialize};

use super::{KeysConfig, redacted};

/// Env var that overrides the gdi config directory (tests, custom layouts).
const CONFIG_DIR_ENV: &str = "GDI_CONFIG_DIR";
/// Standard XDG config-home env var.
const XDG_CONFIG_HOME_ENV: &str = "XDG_CONFIG_HOME";
/// The home-directory env var, the last config-dir anchor.
const HOME_ENV: &str = "HOME";
/// The default tool-config file name within the gdi config dir.
///
/// Not `config.toml`. The service config is also a TOML file an operator would naturally
/// call `config.toml`, and the two schemas are disjoint, so a shared name would have the
/// tool discover the node's config and fail on `unknown field: found 'beacon'`. Distinct
/// names make that collision impossible, and [`ToolConfig::load`] shape-detects a service
/// config for anyone who points `--config` at the wrong file.
pub const DEFAULT_CONFIG_FILE: &str = "tool.toml";

/// The gdi config directory: `$GDI_CONFIG_DIR`, else `$XDG_CONFIG_HOME/gdi`, else
/// `$HOME/.config/gdi`. Returns `None` when none of those env vars resolve.
///
/// The one resolution used both by the tool's `config init` / `keys` commands and by
/// [`ToolConfig::load`]'s default-file discovery, the `--config`-absent path.
///
/// An empty value counts as unset at every one of the three anchors, so `HOME=` falls
/// through rather than resolving a `.config/gdi` under the working directory. All three read
/// the environment through one helper rather than repeating the check.
#[must_use]
pub fn config_dir() -> Option<PathBuf> {
    if let Some(dir) = non_empty_env(CONFIG_DIR_ENV) {
        return Some(PathBuf::from(dir));
    }
    if let Some(xdg) = non_empty_env(XDG_CONFIG_HOME_ENV) {
        return Some(PathBuf::from(xdg).join("gdi"));
    }
    non_empty_env(HOME_ENV).map(|home| PathBuf::from(home).join(".config").join("gdi"))
}

/// `key`'s value from the environment, treating an empty value as unset.
///
/// Every anchor in [`config_dir`] reads the environment through here, and none reads it
/// directly, so the emptiness rule cannot be omitted at one of them.
///
/// An empty value must not be taken literally. It is what a shell hands over for `VAR=`,
/// or an unpopulated `env:` entry in a container spec, and using it makes every derived
/// path relative to the working directory: [`default_config_path`] becomes the bare
/// `tool.toml`, so the tool adopts any such file in the directory it was run from, and the
/// node-recipient pin store becomes `recipients/` beside it. A missing pin file is
/// trust-on-first-use, so `pack`
/// from a fresh directory would pin, and then encrypt to, a substituted node key without
/// reporting a mismatch. Returning `None` falls through to the next anchor, or to no config
/// dir at all.
fn non_empty_env(key: &str) -> Option<std::ffi::OsString> {
    std::env::var_os(key).filter(|value| !value.is_empty())
}

/// The default tool-config file path: `<config_dir>/tool.toml`, or `None` when
/// the config dir cannot be resolved (all of `$GDI_CONFIG_DIR`, `$XDG_CONFIG_HOME`,
/// and `$HOME` are unset).
#[must_use]
#[expect(
    clippy::disallowed_methods,
    reason = "the default config path is, by definition, the one under the environment's \
              config dir: there is no `--config` to resolve beside"
)]
pub fn default_config_path() -> Option<PathBuf> {
    Some(config_dir()?.join(DEFAULT_CONFIG_FILE))
}

/// The `gdi-dataset-tool` configuration.
///
/// Provider-wide root-level settings, the provider's own crypt4gh identities under
/// `[keys]`, and a map of named target-node deployments under `[profiles.<name>]`. The
/// active [`Profile`] is chosen by `--profile <name>`, the `default_profile` key, or a
/// sole configured profile. Country-code precedence (config < env < `--cc`) is applied by
/// the caller, which overlays the flag on top of [`ToolConfig::country_code`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ToolConfig {
    /// Two-letter country code for dataset IDs; invariant per provider.
    ///
    /// A root-level key, and the lowest-precedence source: overridden by the
    /// `GDI_TOOL__COUNTRY_CODE` env var and then by the `--cc` flag. No default.
    pub country_code: Option<String>,
    /// The profile used when no `--profile` flag is given (a root-level key).
    ///
    /// Selects one of the `[profiles.<name>]` keys. When unset, the active
    /// profile is the sole configured one (if exactly one exists), else the
    /// caller errors asking for a `--profile` or this key. Overridable via
    /// `GDI_TOOL__DEFAULT_PROFILE`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_profile: Option<String>,
    /// `[keys]`: the provider's own crypt4gh identities, tried in order when decrypting
    /// the provider's own packages. The first is primary, and its recipient is the second
    /// encryption recipient. Empty means the implicit single `keys/provider.c4gh` default,
    /// resolved by the caller.
    pub keys: KeysConfig,
    /// `[profiles.<name>]`: the named target-node deployments. Each holds one node's
    /// recipient settings, S3 bucket, and catalog allow-list.
    pub profiles: BTreeMap<String, Profile>,
}

/// One named target-node deployment (`[profiles.<name>]`).
///
/// `--profile <name>` switches an entire node deployment together: its
/// `service_url` (public plane) and `management_url` (management plane), its single
/// S3 bucket (`[profiles.<name>.s3]`), its `node_recipient_url`/`node_recipient_file`,
/// and its `catalogs` allow-list (the tool targets one node deployment).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Profile {
    /// The node's public base URL, used for the FDP and recipient reads (`catalogs`,
    /// `check`, `doctor`, `/.well-known/c4gh-recipient`). For a co-located no-S3 node this
    /// is the loopback address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_url: Option<String>,
    /// The node's management-plane base URL — its separate `management_addr` listener,
    /// carrying the authoritative `GET /datasets/{id}/state` oracle that `deploy`, `delete`
    /// and `status` read. The management plane is a distinct listener from the public one, so
    /// a single `service_url` cannot reach both. Set this to the management address, for
    /// example loopback `:9090` for a co-located node. When unset, the state probes fall back
    /// to `service_url`, which suits a deployment where both planes share one address. If
    /// neither reaches the management plane the probes degrade gracefully, and the node
    /// re-validates on ingest as the backstop.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub management_url: Option<String>,
    /// Local inbox directory of a co-located node: the `deploy` drop target, a local path
    /// the tool atomically renames its drop into. `deploy --inbox` overrides this.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inbox: Option<String>,
    /// URL the node publishes its crypt4gh recipient at (online convenience).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_recipient_url: Option<String>,
    /// Local file holding the node's crypt4gh recipient (offline fallback).
    ///
    /// Do not turn this into a path directly. It is stored verbatim, so writing the config
    /// back cannot rewrite the operator's text, and a relative entry resolves against the
    /// config directory rather than the process working directory. Call
    /// [`Profile::node_recipient_path`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_recipient_file: Option<String>,
    /// The single S3 bucket this profile's node uses (`[profiles.<name>.s3]`).
    /// The tool targets one bucket per profile; omit for an inbox-only (no-S3) node.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3: Option<ProfileS3>,
    /// Catalog allow-list: catalog name to display title. An optional fail-fast hint, and
    /// the title is cosmetic. The node decides, and re-validates catalogs at ingest, so this
    /// only lets the tool reject an obviously wrong catalog offline. `doctor`'s online path
    /// diffs it against what the node serves and notes any drift.
    pub catalogs: BTreeMap<String, String>,
    /// The institute abbreviation minted into every dataset id built under this profile:
    /// the `<ORG>` of `GDI-<CC>-<ORG>-<millis>`, 1 to 16 uppercase ASCII letters, the same
    /// rule as `crate::id`. It is the provider's identity rather than a per-dataset choice,
    /// so an integrating backend can bind it to the provider and refuse a package whose id
    /// carries any other. `wizard setup` asks for it once, and the authoring stage then
    /// never asks. When unset, authoring asks and offers to store the answer here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    /// This node is keyless: it holds no crypt4gh identity, so there is nothing to encrypt
    /// to. Default `false`. When set, the wizard skips `pack` entirely and deploys the
    /// plaintext staging directory into [`inbox`](Self::inbox); the node ingests it with
    /// `Plaintext` writer-provenance, an expected inbox drop.
    ///
    /// Legitimate only when the inbox is itself the trust boundary: a co-located node on a
    /// trusted filesystem, where the package never crosses an untrusted channel. For an S3
    /// bucket, or a node someone else runs, leave this `false`, or the dataset travels in
    /// the clear.
    #[serde(default, skip_serializing_if = "is_false")]
    pub keyless: bool,
    /// What `build`/`package` put in the packaged `headers/{vcfId}.vcf` members when the
    /// invocation passes neither `--header-policy` nor `--no-headers`; a flag always wins.
    /// Unset means the built-in `minimal`.
    ///
    /// A per-deployment decision, not a per-dataset one: the node drops these members at
    /// ingest and never serves them, so what they carry only matters to whoever reads the
    /// package's non-public sections on the receiving side. `wizard setup` asks for it once
    /// per profile rather than `build` asking per dataset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_policy: Option<ProfileHeaderPolicy>,
}

/// The `[profiles.<name>].header_policy` value: what `build`/`package` put in the packaged
/// `headers/{vcfId}.vcf` members when no flag says otherwise.
///
/// The profile-level subset of [`HeaderPolicy`](crate::model::HeaderPolicy): the three
/// values a deployment can stand behind as a standing default. `verbatim`, which carries
/// tool command lines and filesystem paths, is unrepresentable here. It stays a
/// per-invocation `--header-policy verbatim`, so no profile can make it the silent
/// default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProfileHeaderPolicy {
    /// Ship no `headers/` member at all.
    None,
    /// Structural keys only, with `#CHROM` truncated to the eight fixed columns and no
    /// sample identifiers. The built-in default when the key is unset.
    Minimal,
    /// `Minimal` plus the `#CHROM` sample columns and `##SAMPLE`/`##PEDIGREE` lines.
    WithIdentifiers,
}

impl ProfileHeaderPolicy {
    /// The value as it is spelled in `tool.toml` (and in the manifest's `internal`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Minimal => "minimal",
            Self::WithIdentifiers => "with-identifiers",
        }
    }
}

impl From<ProfileHeaderPolicy> for crate::model::HeaderPolicy {
    fn from(policy: ProfileHeaderPolicy) -> Self {
        match policy {
            ProfileHeaderPolicy::None => Self::None,
            ProfileHeaderPolicy::Minimal => Self::Minimal,
            ProfileHeaderPolicy::WithIdentifiers => Self::WithIdentifiers,
        }
    }
}

impl Profile {
    /// The resolved path of this profile's `node_recipient_file` pin, if configured.
    ///
    /// Relative entries resolve against the config directory — the parent of the resolved
    /// config file when `--config` was given, else `config_dir()` — exactly as
    /// `[keys].identities` does. Absolute entries are returned verbatim.
    ///
    /// The only correct way to turn the field into a path, for a security reason.
    /// `node_recipient_file` is the authoritative pin the fetched node key must match, the
    /// defence against a substituted key. Resolved against the process CWD instead, one
    /// config would anchor to a different trust root depending on the working directory,
    /// and dropping a `node.pub` into each directory to "fix" the resulting failure yields
    /// per-directory trust anchors.
    ///
    /// Returns `None` when the profile configures no pin.
    #[must_use]
    pub fn node_recipient_path(&self, config_path: Option<&Path>) -> Option<PathBuf> {
        let raw = self.node_recipient_file.as_deref()?;
        let path = Path::new(raw);
        if path.is_absolute() {
            return Some(path.to_path_buf());
        }
        Some(config_base_dir(config_path)?.join(path))
    }
}

/// The directory every config-relative artifact of one invocation resolves against: the
/// parent of the resolved config file when `--config` was given, else [`config_dir`].
///
/// One rule, in one place. It governs `[keys].identities`, `node_recipient_file` and the
/// trust-on-first-use pin store alike, and those must agree: they are all crypt4gh material
/// for the same profile, written and read by sibling subcommands of one run. If they
/// disagree, an invocation splits its key material across two roots, and because an unfound
/// pin is trust-on-first-use rather than an error, the next `pack` re-pins whatever key the
/// node then serves and loses the substitution defence with no message.
///
/// Returns `None` only when no `--config` was given and no config dir resolves.
#[must_use]
#[expect(
    clippy::disallowed_methods,
    reason = "the chokepoint itself: the environment default is its no-`--config` arm"
)]
pub fn config_base_dir(config_path: Option<&Path>) -> Option<PathBuf> {
    match config_path {
        Some(cfg) => Some(
            cfg.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .map_or_else(|| PathBuf::from("."), Path::to_path_buf),
        ),
        None => super::config_dir(),
    }
}

/// `skip_serializing_if` for a plain `bool`: keep a `false` flag out of a written config
/// (the `Option` fields above get this from `Option::is_none`).
#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if requires a by-reference predicate"
)]
fn is_false(b: &bool) -> bool {
    !*b
}

impl Profile {
    /// The base URL for the node's management-plane `GET /datasets/{id}/state`
    /// oracle: the explicit [`management_url`](Self::management_url) when set, else a
    /// fallback to [`service_url`](Self::service_url) (back-compat / shared-address),
    /// else `None`. Callers treat `None` (or an unreachable result) as "no
    /// authoritative node view" and fall back to the S3 sidecar / node backstop.
    #[must_use]
    pub fn node_state_base(&self) -> Option<&str> {
        self.management_url
            .as_deref()
            .or(self.service_url.as_deref())
    }
}

/// The active profile's S3 bucket (`[profiles.<name>.s3]`) for `upload`, `download` and
/// `list`.
///
/// Endpoint-agnostic through `endpoint`, `path_style` and `allow_http`, so Ceph, Garage and
/// minio are one code path differing only by config, as on the service's `S3Bucket`. The
/// tool's `object_store` client is built from these fields, and the credentials are never
/// serialized back into a written config.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProfileS3 {
    /// The bucket name on the endpoint. Required for any S3 op (the loader leaves
    /// it empty when omitted; the op surfaces a clear error).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
    /// Key prefix within `bucket` that this profile reads and writes; empty (the
    /// default) is the whole bucket.
    ///
    /// It must match the `prefix` on the node's `[[s3.buckets]]` entry for this channel.
    /// The two sides address one keyspace, which is why [`crate::s3_layout`] exists: a
    /// prefix set on only one of them makes `upload` write `{id}.tar.c4gh` where the node
    /// never lists, or makes `list` and `status` report an empty bucket the node is
    /// serving from.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub prefix: String,
    /// The logical channel name the node monitors this bucket under, its per-bucket
    /// `name`. Optional. When set, `publish`, `unpublish` and `delete` warn if the node
    /// reports the dataset owned by another channel. That guards against an S3 lifecycle
    /// operation run under the wrong profile on a multi-bucket node, which would write a
    /// sidecar to a bucket the node never observes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// The S3-compatible endpoint URL (custom endpoint for Ceph+Rook/Garage/minio).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// The S3 region. Unset resolves to `us-east-1`, the conventional placeholder Ceph and
    /// minio accept; Garage checks it against its configured `s3_region` (`garage` in the
    /// Compose stack) and rejects a mismatch with a 400. Must match the node's
    /// `[[s3.buckets]].region` for the same endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Path-style addressing (Ceph/Garage/minio) rather than virtual-hosted. Default
    /// `false`.
    pub path_style: bool,
    /// Allow plain HTTP endpoints, for local minio/Garage development. Default `false`.
    pub allow_http: bool,
    /// S3 access key id. Set both credentials or neither; neither means anonymous read of
    /// a public bucket, and writing or listing a private bucket needs both. Never
    /// serialized: credentials live in the `GDI_TOOL__…` env overlay or a separate secrets
    /// file, never in a written config.
    #[serde(skip_serializing)]
    pub access_key_id: Option<String>,
    /// S3 secret access key, paired with `access_key_id`. Never serialized. See
    /// [`Self::access_key_id`].
    #[serde(skip_serializing)]
    pub secret_access_key: Option<String>,
}

impl std::fmt::Debug for ProfileS3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProfileS3")
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .field("channel", &self.channel)
            .field("endpoint", &self.endpoint)
            .field("region", &self.region)
            .field("path_style", &self.path_style)
            .field("allow_http", &self.allow_http)
            .field("access_key_id", &self.access_key_id)
            .field(
                "secret_access_key",
                &redacted(self.secret_access_key.as_ref()),
            )
            .finish()
    }
}

impl ToolConfig {
    /// Load the tool config from a TOML file only, without applying the `GDI_TOOL__`
    /// environment overlay.
    ///
    /// The on-disk-only view of the config, for inspecting what is persisted, such as
    /// detecting inline credentials before a rewrite where env-injected values must not
    /// trigger a false warning.
    ///
    /// When `path` does not exist, figment's `Toml::file` provider treats it as
    /// empty, so this returns a default [`ToolConfig`] rather than an error.
    ///
    /// # Errors
    ///
    /// Returns a boxed [`figment::Error`] if the TOML is malformed or the data
    /// does not deserialize into [`ToolConfig`].
    pub fn load_file_only(path: &Path) -> Result<Self, Box<figment::Error>> {
        Figment::new()
            .merge(Toml::file(path))
            .extract()
            .map(Self::with_empty_s3_dropped)
            .map_err(Box::new)
    }

    /// Load the tool config from an optional TOML file plus the `GDI_TOOL__*`
    /// (and `GDI_TOOL__PROFILES__<NAME>__*`, `GDI_TOOL__KEYS__*`) env overlay.
    ///
    /// When `path` is [`Some`] and the file is missing, figment's `Toml::file`
    /// provider treats it as empty rather than erroring, so a config-less run
    /// still loads (env-only). The env layer wins over the file.
    ///
    /// When `path` is [`None`] (no `--config` flag), the loader attempts to
    /// discover a default `<config_dir>/tool.toml` via [`default_config_path`]
    /// and merges it at the lowest precedence if the file exists. The `GDI_TOOL__`
    /// env overlay is then layered on top, so env always wins regardless of
    /// whether a default file was found.
    ///
    /// # Errors
    ///
    /// Returns a boxed [`figment::Error`] if the TOML is malformed or the merged
    /// data does not deserialize into [`ToolConfig`]. The error is boxed because
    /// `figment::Error` is large.
    pub fn load(path: Option<&Path>) -> Result<Self, Box<figment::Error>> {
        let mut fig = Figment::new();
        // Remember the file merged, so a failure can be checked against the other
        // binary's schema and reported as a mix-up rather than a stray-key error.
        let mut merged: Option<PathBuf> = None;
        match path {
            Some(path) => {
                fig = fig.merge(Toml::file(path));
                merged = Some(path.to_path_buf());
            }
            None => {
                // Fallback: merge <config_dir>/tool.toml when present (lowest
                // precedence; the GDI_TOOL__ env overlay below still wins).
                if let Some(default) = default_config_path()
                    && default.exists()
                {
                    fig = fig.merge(Toml::file(&default));
                    merged = Some(default);
                }
            }
        }
        fig = fig.merge(Env::prefixed("GDI_TOOL__").split("__"));
        fig.extract().map(Self::with_empty_s3_dropped).map_err(|e| {
            if let Some(file) = merged.as_deref()
                && let Some(hint) = super::cross_config_hint(file, super::ConfigKind::Tool)
            {
                return Box::new(figment::Error::from(hint));
            }
            Box::new(e)
        })
    }

    /// Treat a `[profiles.<name>.s3]` table that sets nothing as the absent block it
    /// describes.
    ///
    /// `config init` scaffolds that section header with every key commented out, so a
    /// profile written for the inbox channel still deserializes to `Some(ProfileS3)` with
    /// every field at its default. Left as `Some`, the empty table reads as "this profile
    /// has an S3 channel" everywhere the option is tested: `doctor` labels the profile
    /// `S3` and runs a bucket probe that then fails for want of an endpoint, `profiles`
    /// prints the same wrong label, and `resolve_channel` infers the S3 channel for a
    /// lifecycle verb whose node is unreachable, routing an inbox-only `publish` at a
    /// bucket that does not exist.
    ///
    /// The test is equality with [`ProfileS3::default`] rather than an enumeration of the
    /// fields, so a field added later is covered without editing this. A table that sets
    /// *any* value is kept, so a half-filled block still reaches the operation's own
    /// "bucket is required" diagnostic rather than being reported as absent.
    #[must_use]
    fn with_empty_s3_dropped(mut self) -> Self {
        let empty = ProfileS3::default();
        for profile in self.profiles.values_mut() {
            if profile.s3.as_ref() == Some(&empty) {
                profile.s3 = None;
            }
        }
        self
    }

    /// Resolve the country code with the precedence config < env < flag.
    ///
    /// The config-file value and the env override are already merged into
    /// [`ToolConfig::country_code`] by [`ToolConfig::load`] (env wins over the
    /// file). This applies the highest-precedence `--cc` flag on top.
    #[must_use]
    pub fn resolve_country_code(&self, flag: Option<&str>) -> Option<String> {
        flag.map(str::to_owned)
            .or_else(|| self.country_code.clone())
    }

    /// Pairs of `[profiles.*]` names that look like hyphen/underscore twins: names that
    /// become equal once every `-` is treated as `_` but differ as written, such as a file
    /// `[profiles.ee-prod]` plus an env-injected `ee_prod`.
    ///
    /// The `GDI_TOOL__PROFILES__<NAME>__…` env overlay splits on `__` and can only spell
    /// `_`, so a hyphenated profile name is unreachable by env and any credentials injected
    /// for it land in a separate underscore phantom profile. That is nearly always a
    /// misconfiguration. Returns each twin pair once, the `-` member first, since
    /// [`profiles`](Self::profiles) is a `BTreeMap` and `-` sorts before `_`.
    #[must_use]
    pub fn phantom_profile_twins(&self) -> Vec<(String, String)> {
        let names: Vec<&String> = self.profiles.keys().collect();
        let mut twins = Vec::new();
        for (i, a) in names.iter().enumerate() {
            for b in &names[i + 1..] {
                if a != b && a.replace('-', "_") == b.replace('-', "_") {
                    twins.push(((*a).clone(), (*b).clone()));
                }
            }
        }
        twins
    }
}

/// The backup sibling for a config path: `<path>.bak`.
fn backup_sibling(path: &Path) -> PathBuf {
    let mut name: OsString = path.as_os_str().to_owned();
    name.push(".bak");
    PathBuf::from(name)
}

/// Write `cfg` to `path` as pretty TOML, atomically.
///
/// The contents are serialized, written to a `<path>.tmp` sibling, then renamed
/// over `path` (atomic on the same filesystem).
///
/// If `path` already exists, its prior contents are written to `<path>.bak` first,
/// unconditionally, through the same durable owner-only writer.
///
/// Both files are owner-only (`0o600`), and both go through the same writer for that
/// reason. Either may hold hand-written S3 credentials, which `merge_into_existing`
/// preserves. A plain durable write would apply `0o666 & ~umask`, and `fs::copy` would
/// carry the source's mode, so either would widen a config already at `0o600`.
///
/// # Errors
///
/// Returns an [`io::Error`] if the config cannot be serialized (mapped to
/// [`io::ErrorKind::InvalidData`]) or any filesystem step fails.
pub fn write(cfg: &ToolConfig, path: &Path) -> io::Result<()> {
    let body =
        toml::to_string_pretty(cfg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        #[expect(
            clippy::disallowed_methods,
            reason = "the operator's config directory; tool.toml itself is written 0600"
        )]
        fs::create_dir_all(parent)?;
    }
    // Update the operator's file in place when one exists, so comments, formatting and
    // anything the tool does not manage survive. Only a first write serialises from
    // scratch.
    let existing = match fs::read_to_string(path) {
        Ok(existing) => Some(existing),
        // No file yet, as for `config init`: the serialised form is the file.
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    let body = match &existing {
        Some(existing) => merge_into_existing(existing, &body)?,
        None => body,
    };
    // Preserve the operator's previous config before the atomic replace overwrites it,
    // through the same owner-only writer as the config itself. The backup may carry inline
    // S3 credentials, which `merge_into_existing` preserves, and `fs::copy` would carry the
    // source's mode: a config still at the pre-0600 default would land in a world-readable
    // `.bak`.
    if let Some(existing) = &existing {
        crate::util::write_durable_atomic_private(&backup_sibling(path), existing.as_bytes())?;
    }
    // Durable atomic replace (tmp -> fsync -> rename -> dir fsync): a crash right after
    // the rename cannot leave a zero-length or torn config with the prior file gone.
    crate::util::write_durable_atomic_private(path, body.as_bytes())
}

/// Apply the serialised config `new_body` onto the operator's `existing` file, preserving
/// everything the serialisation cannot express.
///
/// A whole-file rewrite loses two things, and both matter:
///
/// * comments and formatting, an operator's annotations on their own config;
/// * inline S3 credentials: `access_key_id` and `secret_access_key` are
///   `#[serde(skip_serializing)]`, so a re-serialisation drops a credential the operator
///   hand-wrote and turns their next S3 call into an anonymous client.
///
/// The policy is that the tool never authors a credential into a config. Leaving bytes it
/// never parsed as secrets untouched authors nothing, so preserving them keeps the policy.
///
/// Merge rule: every key the serialised form carries overwrites the existing one, and a key
/// present in the file but absent from the serialised form is removed, which is how a
/// catalog the node no longer serves disappears. The two credential keys are exempt from
/// the removal half: as `skip_serializing` fields their absence carries no operator
/// intent.
fn merge_into_existing(existing: &str, new_body: &str) -> io::Result<String> {
    let invalid = |e: toml_edit::TomlError| io::Error::new(io::ErrorKind::InvalidData, e);
    let mut doc: toml_edit::DocumentMut = existing.parse().map_err(invalid)?;
    let new_doc: toml_edit::DocumentMut = new_body.parse().map_err(invalid)?;
    merge_table(doc.as_table_mut(), new_doc.as_table());
    Ok(doc.to_string())
}

/// Keys that survive in the existing document even though they never appear in the
/// serialised form. See [`merge_into_existing`].
const NEVER_SERIALISED_KEYS: [&str; 2] = ["access_key_id", "secret_access_key"];

/// Recursively apply `new` onto `old`, in place.
fn merge_table(old: &mut toml_edit::Table, new: &toml_edit::Table) {
    // Drop keys the new config no longer carries (a removed catalog, a cleared field),
    // except the ones serialisation never emits in the first place.
    let stale: Vec<String> = old
        .iter()
        .map(|(k, _)| k.to_owned())
        .filter(|k| !new.contains_key(k) && !NEVER_SERIALISED_KEYS.contains(&k.as_str()))
        .collect();
    for key in stale {
        old.remove(&key);
    }
    for (key, new_item) in new {
        // Both sides are tables: recurse, so comments inside a table survive an edit to
        // one of its keys.
        if let (Some(toml_edit::Item::Table(old_sub)), toml_edit::Item::Table(new_sub)) =
            (old.get_mut(key), new_item)
        {
            merge_table(old_sub, new_sub);
            continue;
        }
        // Replacing a scalar replaces its decor too, and decor is where `toml_edit` keeps
        // the comments around a key, so a plain insert would delete the operator's
        // annotation on any value touched. Carry the old decor onto the new value.
        if let (Some(old_item), toml_edit::Item::Value(new_value)) = (old.get_mut(key), new_item)
            && let Some(old_value) = old_item.as_value_mut()
        {
            let decor = old_value.decor().clone();
            *old_value = new_value.clone();
            *old_value.decor_mut() = decor;
            continue;
        }
        // A new key, or a shape change between value and table: take it wholesale.
        old.insert(key, new_item.clone());
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    use super::{Profile, ProfileS3, ToolConfig};

    fn cfg_with_profiles(names: &[&str]) -> ToolConfig {
        let mut cfg = ToolConfig::default();
        let mut map = BTreeMap::new();
        for n in names {
            map.insert((*n).to_owned(), Profile::default());
        }
        cfg.profiles = map;
        cfg
    }

    #[test]
    fn detects_hyphen_underscore_profile_twins() {
        let cfg = cfg_with_profiles(&["ee-prod", "ee_prod", "se_prod"]);
        let twins = cfg.phantom_profile_twins();
        assert_eq!(twins.len(), 1, "exactly one twin pair, got {twins:?}");
        // BTreeMap key order: `-` sorts before `_`, so the hyphen form is first.
        assert_eq!(
            (twins[0].0.as_str(), twins[0].1.as_str()),
            ("ee-prod", "ee_prod")
        );
    }

    #[test]
    fn no_twins_when_names_are_distinct_or_underscore_safe() {
        let cfg = cfg_with_profiles(&["ee_prod", "ee_local", "se_prod"]);
        assert!(cfg.phantom_profile_twins().is_empty());
    }

    /// A `[profiles.<name>.s3]` header with every key commented out is not an S3 channel.
    ///
    /// This is the exact shape `config init` scaffolds, so an inbox-only provider who
    /// edits the template without deleting that header would otherwise be reported as
    /// S3-configured: `doctor` fails its bucket probe, `profiles` mislabels the channel,
    /// and an unreachable-node lifecycle verb infers S3 and writes to a bucket that is not
    /// there.
    #[test]
    fn an_s3_table_that_sets_nothing_is_not_an_s3_channel() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tool.toml");
        std::fs::write(
            &path,
            "[profiles.default]\nservice_url = \"http://127.0.0.1:8081\"\n\n\
             [profiles.default.s3]\n# bucket = \"REPLACE: my-bucket\"\n\
             # endpoint = \"REPLACE: https://s3.example\"\n",
        )
        .expect("write config");

        let cfg = ToolConfig::load_file_only(&path).expect("load");

        assert!(
            cfg.profiles["default"].s3.is_none(),
            "an empty [profiles.*.s3] table must read as no S3 channel"
        );
    }

    /// ...but a table that sets anything at all is kept, so a half-filled block still
    /// reaches the operation's own "bucket is required" diagnostic instead of being
    /// reported as a block the user never wrote.
    #[test]
    fn an_s3_table_that_sets_any_value_is_kept() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tool.toml");
        std::fs::write(
            &path,
            "[profiles.default.s3]\nendpoint = \"https://s3.example\"\n",
        )
        .expect("write config");

        let cfg = ToolConfig::load_file_only(&path).expect("load");

        assert_eq!(
            cfg.profiles["default"]
                .s3
                .as_ref()
                .and_then(|s3| s3.endpoint.as_deref()),
            Some("https://s3.example"),
            "a partially-filled S3 block is still an S3 block"
        );
        assert_ne!(
            cfg.profiles["default"].s3.as_ref(),
            Some(&ProfileS3::default()),
            "the kept block must differ from the default it is compared against"
        );
    }

    /// The `node_recipient_file` pin must resolve against the config directory, never the
    /// process CWD.
    ///
    /// It is the authoritative pin the fetched node key must match, so a CWD-relative
    /// resolution would anchor one config to a different trust root depending on where the
    /// tool is run from. Pins the base for a relative entry, and that absolute entries are
    /// left alone.
    #[test]
    fn node_recipient_path_resolves_against_the_config_dir_not_cwd() {
        let mut profile = Profile {
            node_recipient_file: Some("node.pub".to_owned()),
            ..Profile::default()
        };
        let cfg = Path::new("/etc/gdi/tool.toml");

        assert_eq!(
            profile.node_recipient_path(Some(cfg)),
            Some(PathBuf::from("/etc/gdi/node.pub")),
            "a relative pin resolves against the config file's directory"
        );

        // An absolute entry is returned verbatim.
        profile.node_recipient_file = Some("/opt/pins/node.pub".to_owned());
        assert_eq!(
            profile.node_recipient_path(Some(cfg)),
            Some(PathBuf::from("/opt/pins/node.pub")),
            "an absolute pin is not re-based"
        );

        // No pin configured -> nothing to resolve.
        profile.node_recipient_file = None;
        assert_eq!(profile.node_recipient_path(Some(cfg)), None);
    }

    #[test]
    fn write_round_trips_and_backs_up() {
        // The old and new country codes are named once each and asserted distinct. If they
        // were equal, the backup assertion below would hold whether `.bak` kept the old file
        // or a copy of the new one.
        const OLD_CC: &str = "EE";
        const NEW_CC: &str = "SE";
        assert_ne!(
            OLD_CC, NEW_CC,
            "the pre- and post-write values must differ, or 'the backup holds the previous \
             contents' cannot fail"
        );
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");

        // First write: no existing file, so no backup is made.
        let mut cfg = ToolConfig {
            country_code: Some(OLD_CC.to_owned()),
            ..Default::default()
        };
        cfg.profiles
            .insert("default".to_owned(), Profile::default());
        super::write(&cfg, &path).expect("first write");
        assert!(path.exists(), "config file written");
        assert!(
            !path.with_extension("toml.bak").exists() && !backup_path(&path).exists(),
            "no backup on first write"
        );

        // A re-load equals what was written.
        let loaded = ToolConfig::load(Some(&path)).expect("load written config");
        assert_eq!(loaded.country_code.as_deref(), Some(OLD_CC));
        assert!(loaded.profiles.contains_key("default"));

        // Second write: the prior file is preserved in `<path>.bak`.
        let mut cfg2 = cfg.clone();
        cfg2.country_code = Some(NEW_CC.to_owned());
        super::write(&cfg2, &path).expect("second write");
        let bak = backup_path(&path);
        assert!(
            bak.exists(),
            "backup created on overwrite: {}",
            bak.display()
        );
        let bak_body = std::fs::read_to_string(&bak).expect("read backup");
        assert!(
            bak_body.contains(OLD_CC) && !bak_body.contains(NEW_CC),
            "the backup holds the previous contents, not the new ones: {bak_body}"
        );
        let new_body = std::fs::read_to_string(&path).expect("read new");
        assert!(
            new_body.contains(NEW_CC)
                && !new_body.contains(&format!("country_code = \"{OLD_CC}\"")),
            "new file holds the new contents: {new_body}"
        );
    }

    /// `<path>` + ".bak" (matches the implementation's sibling-suffix rule).
    fn backup_path(path: &Path) -> std::path::PathBuf {
        let mut name = path.as_os_str().to_owned();
        name.push(".bak");
        std::path::PathBuf::from(name)
    }

    #[test]
    #[serial_test::serial(env)]
    #[expect(
        clippy::result_large_err,
        reason = "the figment::Jail::expect_with closure return type is fixed by the test API"
    )]
    fn load_picks_up_default_config_file_when_no_path() {
        figment::Jail::expect_with(|jail| {
            // Point GDI_CONFIG_DIR at the jail's temp dir and drop a `tool.toml` in it.
            jail.set_env("GDI_CONFIG_DIR", jail.directory().display().to_string());
            jail.create_file("tool.toml", "country_code = \"NL\"\n")?;

            let cfg = ToolConfig::load(None).expect("load with default discovery");
            assert_eq!(cfg.country_code.as_deref(), Some("NL"));
            let expected = jail.directory().join("tool.toml");
            assert_eq!(
                super::default_config_path().as_deref(),
                Some(expected.as_path())
            );
            Ok(())
        });
    }

    /// An empty `GDI_CONFIG_DIR` must be treated as unset, not as the current directory.
    ///
    /// `GDI_CONFIG_DIR=`, which is a shell assignment with no value or an unpopulated `env:`
    /// entry in a container spec, otherwise resolves to `PathBuf::from("")` and rebases
    /// every derived path onto the CWD: the config file becomes the bare `tool.toml`, and
    /// the node-recipient pin store becomes `recipients/` under whatever directory the tool
    /// ran in. Since a missing pin is trust-on-first-use, `pack` from a fresh directory
    /// would silently pin, and encrypt to, a substituted node key. The assertion is on the
    /// resolved anchor, not merely on "not empty".
    #[test]
    #[serial_test::serial(env)]
    #[expect(
        clippy::result_large_err,
        reason = "the figment::Jail::expect_with closure return type is fixed by the test API"
    )]
    #[expect(
        clippy::disallowed_methods,
        reason = "the resolver's own test reads the environment on purpose"
    )]
    fn an_empty_config_dir_env_falls_through_to_xdg() {
        figment::Jail::expect_with(|jail| {
            let xdg = jail.directory().join("xdg");
            jail.set_env("GDI_CONFIG_DIR", "");
            jail.set_env("XDG_CONFIG_HOME", xdg.display().to_string());

            assert_eq!(
                super::config_dir(),
                Some(xdg.join("gdi")),
                "an empty GDI_CONFIG_DIR must fall through to $XDG_CONFIG_HOME/gdi, exactly \
                 as an empty XDG_CONFIG_HOME falls through to $HOME"
            );
            let path = super::default_config_path().expect("XDG is set, so a path resolves");
            assert!(
                path.is_absolute(),
                "the default config path must never be CWD-relative; got {}",
                path.display()
            );
            Ok(())
        });
    }

    /// The same hazard at the last anchor: `HOME=` must not resolve to a `.config/gdi` under
    /// the working directory, which would reach the trust-on-first-use pin-store hazard the
    /// sibling test describes. All three anchors read the environment through
    /// `non_empty_env`.
    #[test]
    #[serial_test::serial(env)]
    #[expect(
        clippy::result_large_err,
        reason = "the figment::Jail::expect_with closure return type is fixed by the test API"
    )]
    #[expect(
        clippy::disallowed_methods,
        reason = "the resolver's own test reads the environment on purpose"
    )]
    fn an_empty_home_resolves_no_config_dir_rather_than_a_cwd_relative_one() {
        figment::Jail::expect_with(|jail| {
            jail.set_env("GDI_CONFIG_DIR", "");
            jail.set_env("XDG_CONFIG_HOME", "");
            jail.set_env("HOME", "");

            assert_eq!(
                super::config_dir(),
                None,
                "with every anchor empty there is no config dir; anything else is rooted at \
                 the CWD"
            );
            assert_eq!(
                super::default_config_path(),
                None,
                "and no default config file, rather than a bare `tool.toml` the tool would \
                 adopt from whatever directory it was run in"
            );

            // Control: a non-empty HOME still anchors, so this test cannot pass by making
            // the HOME anchor useless.
            let home = jail.directory().join("home");
            jail.set_env("HOME", home.display().to_string());
            assert_eq!(super::config_dir(), Some(home.join(".config").join("gdi")));
            Ok(())
        });
    }

    #[test]
    fn s3_secrets_are_never_serialized() {
        let mut cfg = ToolConfig::default();
        let p = Profile {
            s3: Some(ProfileS3 {
                bucket: Some("my-bucket".to_owned()),
                endpoint: Some("https://s3.example".to_owned()),
                access_key_id: Some("AKIAEXAMPLE".to_owned()),
                secret_access_key: Some("super-secret-value".to_owned()),
                ..ProfileS3::default()
            }),
            ..Profile::default()
        };
        cfg.profiles.insert("default".to_owned(), p);

        let out = toml::to_string(&cfg).expect("serialize tool config to TOML");
        // Non-secret S3 config is written.
        assert!(
            out.contains("my-bucket"),
            "bucket must serialize; got:\n{out}"
        );
        assert!(out.contains("s3.example"), "endpoint must serialize");
        // Credentials must not appear anywhere in the output.
        assert!(
            !out.contains("AKIAEXAMPLE"),
            "access_key_id must never serialize; got:\n{out}"
        );
        assert!(
            !out.contains("super-secret-value"),
            "secret_access_key must never serialize; got:\n{out}"
        );
    }

    /// `load_file_only` reads credentials from the TOML file and does not apply the
    /// `GDI_TOOL__` env overlay.
    #[test]
    #[serial_test::serial(env)]
    #[expect(
        clippy::result_large_err,
        reason = "the figment::Jail::expect_with closure return type is fixed by the test API"
    )]
    fn load_file_only_reads_file_without_env_overlay() {
        figment::Jail::expect_with(|jail| {
            // Write a config with an inline secret_access_key.
            jail.create_file(
                "cfg.toml",
                r#"
[profiles.x.s3]
access_key_id = "AKIAFILE"
secret_access_key = "file-secret"
"#,
            )?;
            let path = jail.directory().join("cfg.toml");

            // File-only load sees the inline credentials.
            let file_cfg =
                ToolConfig::load_file_only(&path).expect("load_file_only from disk config");
            let s3 = file_cfg.profiles["x"].s3.as_ref().expect("s3 section");
            assert_eq!(s3.access_key_id.as_deref(), Some("AKIAFILE"));
            assert_eq!(s3.secret_access_key.as_deref(), Some("file-secret"));

            // Set a GDI_TOOL__ env overlay that would override the profile if the env
            // layer were applied. `load_file_only` must ignore it.
            jail.set_env("GDI_TOOL__PROFILES__x__S3__ACCESS_KEY_ID", "ENV-KEY");
            jail.set_env("GDI_TOOL__PROFILES__x__S3__SECRET_ACCESS_KEY", "env-secret");

            let file_only = ToolConfig::load_file_only(&path).expect("load_file_only ignores env");
            let s3_only = file_only.profiles["x"].s3.as_ref().expect("s3 section");
            // Must still reflect the file, not the env var.
            assert_eq!(
                s3_only.access_key_id.as_deref(),
                Some("AKIAFILE"),
                "load_file_only must not apply env overlay"
            );
            assert_eq!(
                s3_only.secret_access_key.as_deref(),
                Some("file-secret"),
                "load_file_only must not apply env overlay"
            );

            Ok(())
        });
    }

    /// An operator's hand-written config must survive a `write`: comments, formatting and
    /// inline S3 credentials all stay.
    ///
    /// `ProfileS3`'s credential fields are `#[serde(skip_serializing)]`, so a whole-file
    /// re-serialisation would drop them and turn the operator's next S3 call into an
    /// anonymous client. The policy is that the tool never authors a credential into a
    /// config; leaving bytes it never parsed as secrets untouched authors nothing, so the
    /// in-place edit keeps the policy without damaging the file.
    #[test]
    fn write_preserves_comments_and_inline_credentials_in_place() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");

        std::fs::write(
            &path,
            r#"# The provider's own notes, which an in-place write must preserve.
country_code = "EE"

[profiles.default.s3]
bucket = "b"                      # trailing comment
access_key_id = "AKIAEXAMPLE"
secret_access_key = "super-secret-value"

[profiles.default.catalogs]
gdi-aggregated = "Genome of Europe Aggregated Data"
"#,
        )
        .expect("seed config");

        // Round-trip the way `catalogs --sync` does: load from file, write back.
        let cfg = ToolConfig::load_file_only(&path).expect("load");
        super::write(&cfg, &path).expect("write");

        let after = std::fs::read_to_string(&path).expect("rewritten config");
        assert!(
            after.contains("super-secret-value") && after.contains("AKIAEXAMPLE"),
            "inline credentials must survive an in-place write: {after}"
        );
        assert!(
            after.contains("# The provider's own notes"),
            "comments must survive: {after}"
        );
        assert!(
            after.contains("# trailing comment"),
            "trailing comments must survive: {after}"
        );
        assert!(
            after.contains("Genome of Europe Aggregated Data"),
            "curated catalog titles must survive: {after}"
        );

        // The backup is still taken, so the previous file is always recoverable.
        assert!(
            std::fs::read_to_string(dir.path().join("config.toml.bak"))
                .expect("backup exists")
                .contains("super-secret-value")
        );
    }

    /// The tool config is written owner-only, and a rewrite must not widen an existing one.
    ///
    /// `merge_into_existing` preserves what the serialisation cannot express, so an S3
    /// credential the operator wrote by hand survives every rewrite even though `ProfileS3`
    /// marks both credential fields `skip_serializing`. The plain durable writer applies
    /// `0o666 & ~umask`, typically 0644, which would reset a config the operator had
    /// already `chmod 600`-ed.
    #[cfg(unix)]
    #[test]
    fn the_written_config_is_owner_only_and_a_rewrite_does_not_widen_it() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("tool.toml");
        let cfg = ToolConfig::default();

        super::write(&cfg, &path).expect("write config");
        let mode = std::fs::metadata(&path)
            .expect("stat config")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "a fresh config must be owner-only; got {mode:o}"
        );

        // Widen it as an operator never would, then rewrite: the mode must come back down,
        // never up. That is the direction that matters, because the failure to catch is a
        // rewrite resetting a locked-down file to the umask default of 0o644. Setting 0o600
        // here would re-establish the mode the assertion above just proved, so the rewrite
        // would never be asked to narrow anything.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        super::write(&cfg, &path).expect("write config");
        let mode = std::fs::metadata(&path)
            .expect("stat config")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "a rewrite must not widen a config the operator locked down; got {mode:o}"
        );

        // The backup, not just the primary. The rewrite above ran against a 0644 file, the
        // one moment the backup is written from a world-readable source, and a plain
        // `fs::copy` would carry that mode across and publish any inline credential
        // `merge_into_existing` preserved.
        let backup = super::backup_sibling(&path);
        let mode = std::fs::metadata(&backup)
            .expect("stat backup")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "the backup may carry inline credentials and must be owner-only too; got {mode:o}"
        );
    }
}
