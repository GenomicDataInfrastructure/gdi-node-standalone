//! The `pme reseal` one-shot: the documented exit from a latched at-rest key mismatch.
//!
//! `<data_dir>/.pme-sentinel.json` records a throwaway DEK wrapped by the configured Transit
//! master key. On every boot the node unwraps it to prove the key that encrypted the existing
//! store is still the key it is configured with; a *permanent* unwrap failure latches
//! `at_rest_ok = false`, so `/health/ready` reports not-ready and the node stays out of
//! rotation. That is the right behaviour for an unnoticed key replacement.
//!
//! Without this verb it is a one-way door. The sentinel is written once, when the file is
//! absent, and lives on the data volume, so it survives both the incident and the recovery.
//! An operator who follows `docs/operating.md` §17 (provision a new Transit key, re-ingest
//! every dataset) or §10 (rotate, re-ingest, then raise `min_decryption_version`) ends up
//! with a fully decryptable store and a sentinel that still refuses to unwrap: a healthy
//! node, permanently unready.
//!
//! `pme reseal` re-mints the sentinel only after proving the current key can still read a
//! real encrypted dataset. See `crate::pme::PmeRuntime::reseal_sentinel`, `pme`-gated and so
//! a plain code span rather than a link a lite rustdoc cannot resolve, for why that proof
//! matters and why the node does not reseal for itself at boot.

use anyhow::{Result, bail};
use gdi_node_standalone_core::config::ServiceConfig;

/// Run `pme reseal`.
///
/// # Errors
/// Returns an error when the binary was built without the `pme` feature, when `[vault]` /
/// `[vault].transit_key` is not configured, when Vault is unreachable, when the existing store
/// cannot be read under the current Transit key (the refusal that keeps a genuine mismatch
/// visible), or when the new sentinel cannot be written.
#[cfg(feature = "pme")]
pub async fn run_reseal(config: &ServiceConfig, assume_yes: bool) -> Result<()> {
    use anyhow::Context as _;

    use crate::pme::PmeRuntime;
    use crate::vault::VaultClient;

    let Some(vault_cfg) = config.vault.as_ref() else {
        bail!(
            "pme reseal: [vault] is not configured, so this node has no at-rest master key and \
             no sentinel to reseal."
        );
    };
    let Some(transit_key) = vault_cfg.transit_key.as_deref().filter(|k| !k.is_empty()) else {
        bail!(
            "pme reseal: [vault].transit_key is unset, so PME is not enabled on this node and \
             there is no at-rest sentinel to reseal."
        );
    };

    let data_dir = &config.service.data_dir;
    let sentinel = data_dir.join(crate::pme::SENTINEL_FILE);

    if !assume_yes {
        // Interactive by default: this overwrites the one artifact that proves the store's
        // key provenance, and doing so on a node whose store is genuinely undecryptable would
        // trade a loud, correct alarm for a quiet, wrong green.
        eprintln!(
            "About to reseal {} against Transit key {}/{}.\n\
             \n\
             This is safe only after the at-rest recovery is complete (operating.md section 17) or the\n\
             key rotation's re-ingest has finished (section 10). The current key must already be able\n\
             to read the existing store; that is checked below, and a failure aborts.\n\
             \n\
             Re-run with --yes to proceed.",
            sentinel.display(),
            vault_cfg.transit_mount(),
            transit_key,
        );
        bail!("pme reseal: refused without --yes");
    }

    let client = VaultClient::connect(vault_cfg)
        .await
        .map_err(|e| anyhow::anyhow!("connecting to Vault: {e}"))?;
    let pme = PmeRuntime::new(
        client,
        vault_cfg.transit_mount().to_owned(),
        transit_key.to_owned(),
    );

    let outcome = pme
        .reseal_sentinel(data_dir)
        .await
        .context("pme reseal failed")?;

    match &outcome.probed_dataset {
        Some(dir) => println!(
            "verified: the configured Transit key {}/{} still reads the existing encrypted \
             store (probed {})",
            vault_cfg.transit_mount(),
            transit_key,
            dir.display()
        ),
        None => println!(
            "note: this store holds no PME-encrypted dataset yet, so there was nothing to \
             verify the key against; resealing is unconditionally safe here"
        ),
    }
    println!("resealed: {}", outcome.sentinel.display());
    println!(
        "Restart the node (or wait for the next boot) to clear the latched \
         gdi_pme_master_key_mismatch and at_rest readiness signal."
    );

    crate::audit::pme_sentinel_resealed(
        &config.audit,
        vault_cfg.transit_mount(),
        transit_key,
        outcome.probed_dataset.as_deref(),
    );
    Ok(())
}

/// The `pme` verbs need the `pme` feature (which implies `vault`); a lite build has no
/// at-rest encryption, hence no sentinel.
///
/// # Errors
/// Always — this build cannot have an at-rest sentinel.
#[cfg(not(feature = "pme"))]
#[expect(
    clippy::unused_async,
    reason = "must match the `pme` signature so the single call site in main.rs awaits one shape"
)]
pub async fn run_reseal(_config: &ServiceConfig, _assume_yes: bool) -> Result<()> {
    bail!(
        "pme reseal: this binary was built without the `pme` feature, so it has no at-rest \
         encryption and no sentinel. Use a build with --features pme."
    );
}

#[cfg(test)]
#[cfg(feature = "pme")]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]

    use gdi_node_standalone_core::config::ServiceConfig;

    /// A config with the given `[vault]` stanza appended (empty string = no `[vault]`).
    fn config_with(vault_stanza: &str) -> ServiceConfig {
        let toml = format!(
            r#"
[service]
base_url = "https://n.example.org/"
data_dir = "/var/lib/gdi/datasets"

[catalogs]
gdi-aggregated = "GoE"

[beacon]
id = "org.n.beacon"
name = "N"
environment = "test"

[beacon.organization]
id = "ee.ut.gdi"
name = "University of Tartu"
{vault_stanza}
"#
        );
        ServiceConfig::from_toml_str(&toml).unwrap()
    }

    /// Every refusal below must name what to do about it. `pme reseal` is reached by an
    /// operator whose node is stuck not-ready, so a bare "error" costs an outage.
    #[tokio::test]
    async fn reseal_refuses_when_vault_is_not_configured() {
        let err = super::run_reseal(&config_with(""), true)
            .await
            .expect_err("no [vault] means no master key and no sentinel");
        let msg = format!("{err}");
        assert!(msg.contains("[vault] is not configured"), "{msg}");
    }

    #[tokio::test]
    async fn reseal_refuses_when_transit_key_is_unset() {
        let cfg = config_with("\n[vault]\naddress = \"http://vault.example.org:8200\"\n");
        let err = super::run_reseal(&cfg, true)
            .await
            .expect_err("no transit_key means PME is not enabled");
        let msg = format!("{err}");
        assert!(msg.contains("transit_key"), "{msg}");
    }

    /// The safety guard: without `--yes`, reseal refuses before touching anything.
    ///
    /// Resealing overwrites the one artifact proving the store's key provenance. Doing it on
    /// a node whose store is genuinely undecryptable trades a loud, correct alarm for a
    /// quiet, wrong green, so the confirmation is not cosmetic.
    ///
    /// This also pins that the refusal happens before the Vault connect: the config here
    /// points at an address nothing is listening on, so if the guard were removed this
    /// test would fail on a connection error instead — a different message, still caught.
    #[tokio::test]
    async fn reseal_refuses_without_yes_before_contacting_vault() {
        let cfg =
            config_with("\n[vault]\naddress = \"http://127.0.0.1:1\"\ntransit_key = \"gdi-dek\"\n");
        let err = super::run_reseal(&cfg, false)
            .await
            .expect_err("must refuse without --yes");
        let msg = format!("{err}");
        assert!(
            msg.contains("refused without --yes"),
            "the refusal must be the --yes guard, not a downstream Vault failure: {msg}"
        );
    }
}
