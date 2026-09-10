//! Configuration loaders (figment: TOML + env).
//!
//! This module hosts both [`ToolConfig`] for `gdi-dataset-tool` (in `tool`) and the
//! service's [`ServiceConfig`] (in `service`). Each loader layers a TOML file under a
//! `figment` env overlay, using only the `toml` and `env` providers. The two binaries use
//! distinct env prefixes so a variable meant for one never hard-fails the other's
//! `deny_unknown_fields` load: the service reads `GDI_NODE__SECTION__KEY`
//! (`Env::prefixed("GDI_NODE__").split("__")`) and the tool reads `GDI_TOOL__SECTION__KEY`
//! (`Env::prefixed("GDI_TOOL__")`). The two configs are disjoint, and neither consumer links
//! the other, so they live in sibling submodules, re-exported here to keep the public
//! `crate::config::*` paths stable.

mod service;
mod tool;

pub use service::*;
pub use tool::*;
// Named beside the glob so the `disallowed-methods` entry resolves: clippy matches a local
// crate's items by name and a glob import has none, so through `tool::*` alone the ban is
// silently inert (the lint_canary catches that as an unfulfilled expectation).
pub use tool::config_dir;

/// Which binary a TOML config belongs to.
///
/// The two schemas are disjoint, so pointing a binary at the other's file produces a
/// `deny_unknown_fields` error naming one stray key (`unknown field: found 'beacon'`),
/// which leaves the operator to work out that they fed the wrong file to the wrong binary.
/// The default names differ (`node.toml` and `tool.toml`), but an explicit `--config` can
/// point anywhere, so detect the mix-up and say it outright.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfigKind {
    /// The `gdi-node-standalone` service config (`node.toml`).
    Service,
    /// The `gdi-dataset-tool` provider config (`tool.toml`).
    Tool,
}

impl ConfigKind {
    /// Top-level tables and keys that appear only in this config's schema.
    ///
    /// `keys` is absent because both schemas have a `[keys]` table, so it discriminates
    /// nothing.
    const fn signature_keys(self) -> &'static [&'static str] {
        match self {
            Self::Service => &[
                "service", "beacon", "fairdp", "catalogs", "s3", "vault", "ingest", "audit",
            ],
            Self::Tool => &["country_code", "default_profile", "profiles"],
        }
    }

    /// The binary that reads this config, for the hint text.
    const fn binary(self) -> &'static str {
        match self {
            Self::Service => "gdi-node-standalone",
            Self::Tool => "gdi-dataset-tool",
        }
    }
}

/// If `path` parses as TOML and carries the other config's signature keys but none of
/// `expected`'s, return a message saying so. `None` when the file is absent, unparseable
/// or ambiguous. This only improves an error that is already being returned, so a false
/// negative leaves the original message in place.
pub(crate) fn cross_config_hint(path: &std::path::Path, expected: ConfigKind) -> Option<String> {
    let other = match expected {
        ConfigKind::Service => ConfigKind::Tool,
        ConfigKind::Tool => ConfigKind::Service,
    };
    let text = std::fs::read_to_string(path).ok()?;
    let table: toml::Table = text.parse().ok()?;

    let has = |kind: ConfigKind| kind.signature_keys().iter().any(|k| table.contains_key(*k));
    // Only claim a mix-up when the file looks unambiguously like the other one.
    if !has(other) || has(expected) {
        return None;
    }
    let found: Vec<&str> = other
        .signature_keys()
        .iter()
        .copied()
        .filter(|k| table.contains_key(*k))
        .collect();
    Some(format!(
        "{} looks like a {} config, not a {} config (it has: {}). \
         Each binary reads its own file: `{} --config <{}>`.",
        path.display(),
        other.binary(),
        expected.binary(),
        found.join(", "),
        other.binary(),
        if other == ConfigKind::Service {
            "node.toml"
        } else {
            "tool.toml"
        },
    ))
}

/// Serialize the default [`service::ServiceConfig`] as TOML.
///
/// The generated answer to "what does this node do if nothing is set?".
/// `node.example.toml` carries rationale, warnings and worked examples that cannot be
/// generated, so this does not replace it, but that file should not restate the default
/// values `Default for ServiceSection` and its siblings already declare. This gives an
/// operator, and the drift guard, a generated copy to diff against.
///
/// The required, deployment-specific fields (`[service].data_dir`, `[service].base_url` and
/// the `[beacon]` identity strings) serialize as their empty `Default`: this is a defaults
/// reference, not a runnable config. Use `config init` to get a working file.
///
/// # Errors
///
/// Returns [`crate::error::CoreError::InvalidConfig`] if the default config cannot be
/// rendered as TOML, which happens only if a field is added whose type has no TOML
/// representation.
pub fn defaults_toml() -> crate::error::CoreResult<String> {
    toml::to_string_pretty(&service::ServiceConfig::default()).map_err(|e| {
        crate::error::CoreError::InvalidConfig {
            detail: format!("cannot render the default config as TOML: {e}"),
        }
    })
}

/// Render a secret-bearing `Option<String>` field for `Debug`: `None` stays `None`, and any
/// present value is redacted to `Some("***")`. Used by the manual `Debug` impls on the
/// secret-bearing config structs in both submodules, so a `debug!(?config)` cannot leak a
/// credential. The secret value never reaches the formatter.
fn redacted(value: Option<&String>) -> impl std::fmt::Debug + use<> {
    value.map(|_| "***")
}

#[cfg(test)]
mod tests;
