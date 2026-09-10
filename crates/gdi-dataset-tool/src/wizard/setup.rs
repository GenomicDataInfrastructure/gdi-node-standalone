//! Interactive profile and config setup.
//!
//! [`run_setup`] drives a terminal wizard that prompts for a profile name,
//! service URL, recipient TOFU, catalog sync, optional S3 config, and country
//! code; assembles a [`ToolConfig`]; and writes it to the config path. All
//! interactive I/O goes through the [`Prompter`] seam so the flow is
//! testable with a [`crate::wizard::prompts::ScriptedPrompter`] without a real terminal.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use gdi_node_standalone_core::config::{Profile, ProfileHeaderPolicy, ProfileS3, ToolConfig};

use crate::commands::cmd_keys;
use crate::s3::S3Credentials;
use crate::wizard::{fields, prompts::Prompter};
use crate::{ToolError, catalogs, recipient, runtime};

/// What `run_setup` produced: where it wrote, and what this run must carry in memory.
pub struct SetupOutcome {
    /// The written config file.
    pub config_path: PathBuf,
    /// The S3 credentials the operator typed, when they did. They are in `secrets.env` for
    /// later runs; this run's Publish stage takes them from here, because a process cannot
    /// `source` a file into its own environment.
    pub s3_credentials: Option<S3Credentials>,
}

impl std::fmt::Debug for SetupOutcome {
    /// Names whether credentials were collected, never what they are.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetupOutcome")
            .field("config_path", &self.config_path)
            .field(
                "s3_credentials",
                &self.s3_credentials.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Whether the active profile is complete enough to skip setup: it names some way to
/// reach a node recipient — a pinned file, an explicit recipient URL, or a `service_url`
/// to derive one from.
#[must_use]
pub fn profile_complete(profile: &Profile) -> bool {
    // A keyless profile has no recipient by design — nothing is encrypted, so there is
    // nothing to encrypt to. Demanding one here would report it as incomplete forever and
    // re-run `wizard setup` on every invocation. It is complete once it knows where to drop
    // the staging dir.
    if profile.keyless {
        return profile.inbox.is_some();
    }
    // Any one of the three is enough, because any one of them lets `pack` resolve a
    // recipient:
    //
    // * `node_recipient_file` — a local recipient is self-sufficient; a provider who
    //   packages for hand-off has no node URL to give.
    // * `node_recipient_url` / `service_url` — the recipient is fetched, with the URL
    //   derived from `service_url` when only that is set.
    //
    // This does not require `node_recipient_url` alongside `service_url`. The wizard never
    // writes `node_recipient_url` (it derives it), and `keys pin-recipient` records nothing
    // in the profile at all — its trust-on-first-use pin is keyed on the recipient URL, not
    // the profile. Demanding it would make the "Continue without one: pin it later" branch
    // permanently incomplete, restarting every later run at Setup with no route to Author,
    // on a profile `doctor` and `pack` both accept. Completeness matches what the rest of
    // the tool can do: an unreachable node fails at `pack` with a clear error, which is
    // recoverable, rather than locking the operator out of the wizard, which is not.
    profile.node_recipient_file.is_some()
        || profile.node_recipient_url.is_some()
        || profile.service_url.is_some()
}

/// Run the interactive setup wizard: prompt for profile/config settings,
/// assemble and write a [`ToolConfig`], and return the written config path together with
/// what this run must carry in memory (see [`SetupOutcome`]).
///
/// With `recipient_file`, the node recipient is read from that local file instead of
/// fetched over the network (offline/air-gapped setup); the catalog sync is best-effort
/// (a failure warns and leaves the allow-list empty rather than aborting), so with a
/// recipient file and sync declined the wizard needs no network at all.
///
/// # Errors
///
/// Returns a [`ToolError`] (exit 1) on I/O failure, user abort, a bad `recipient_file`
/// (the offline `--recipient` path) or a `service_url` from which no recipient URL can be
/// derived, or when the config directory cannot be resolved. An unreachable/invalid
/// recipient on the *online* fetch path is not fatal — it opens a recovery menu. A
/// catalog-sync failure is not an error.
#[expect(
    clippy::too_many_lines,
    reason = "wizard flow: the prompts are inherently sequential and cannot be split \
              further without losing readability"
)]
pub fn run_setup(
    p: &dyn Prompter,
    config_path: Option<&Path>,
    recipient_file: Option<&Path>,
    profile_name: Option<&str>,
    standalone: bool,
) -> Result<SetupOutcome, ToolError> {
    // Step 1: Profile name. Constrained to a lowercase identifier so (a) the
    // `GDI_TOOL__PROFILES__<NAME>__…` env overlay can actually address it (figment
    // lowercases env keys — a mixed-case/hyphenated name would silently never receive
    // its credentials) and (b) it is safe to interpolate into filesystem paths.
    // Default to the `--profile <name>` the rest of this run targets, and with no flag to
    // the profile that is already active. Setup fires exactly when `load_active` fails,
    // which is the case where the operator named a profile that does not exist yet: a
    // hard-coded "default" would write `[profiles.default]` while build, pack and publish
    // target the named one, aborting at pack with "unknown profile '<name>'". `wizard setup`
    // is also the advertised re-entry for rotation, so it runs against configs that already
    // have a profile; offering "default" there would make Enter fork the config into two
    // profiles with no `default_profile`, after which every command fails "no profile
    // selected" until someone hand-edits tool.toml.
    let active_name = (profile_name.is_none())
        .then(|| crate::profile::load_active_named(config_path, None).ok())
        .flatten()
        .map(|(name, _)| name);
    let default_name = profile_name.or(active_name.as_deref()).unwrap_or("default");
    let name = p.input_validated("Profile name", Some(default_name), &|s| {
        fields::resolve_profile_name(s).map(|_| ())
    })?;
    // `input_validated` returns the raw entry; normalize to the trimmed canonical form
    // used as the config key and in paths.
    let name = fields::resolve_profile_name(&name).unwrap_or(name);

    // What the file already records for this profile — read-only, and only so a re-run
    // pre-fills the answers it recorded last time. `wizard setup` is the advertised
    // re-entry for rotation, and a prompt that forgets the previous value silently narrows
    // a deliberate choice back to a default.
    let target = resolve_write_target(config_path)?;
    let existing: Profile = ToolConfig::load_file_only(&target)
        .ok()
        .and_then(|cfg| cfg.profiles.get(&name).cloned())
        .unwrap_or_default();

    // Step 2: Node service URL. Blank is a real answer: a provider who prepares packages
    // for hand-off has no node to name. Demanding a URL would make them invent one, after
    // which every pack takes the fetch-fails-then-fall-back-to-the-pin path (with its
    // warning) instead of the clean no-URL path.
    let service_url = {
        crate::output::progress(
            "  the node's public base URL. Blank if there is no node yet; you will hand \
             the package over instead.",
        );
        let answer =
            p.input_validated("Node service URL", existing.service_url.as_deref(), &|s| {
                if s.trim().is_empty() {
                    Ok(())
                } else {
                    fields::resolve_iri("service_url", s).map(|_| ())
                }
            })?;
        let trimmed = answer.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    };

    // Step 2b: management URL, optional. The authoritative dataset-state oracle lives on
    // the management plane (`GET /datasets/{id}/state`), which the public plane 404s:
    // without it `status` degrades to the sidecar, the already-live guard on deploy /
    // publish / delete is disarmed, and the wizard's own deploy cannot wait for ingest.
    // Only a co-located node's operator can reach that plane, so a blank answer is the
    // normal one — and it keeps whatever the profile already has.
    let management_url = {
        crate::output::progress(
            "  blank unless the node is co-located and you can reach its management plane \
             (typically http://127.0.0.1:9090).",
        );
        let answer = p.input_validated(
            "Node management URL",
            existing.management_url.as_deref(),
            &|s| {
                if s.trim().is_empty() {
                    Ok(())
                } else {
                    fields::resolve_iri("management_url", s).map(|_| ())
                }
            },
        )?;
        let trimmed = answer.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    };

    // Where this run's config-relative artifacts go: the recipient pin (step 3) and
    // `secrets.env` (step 5). Beside the config file under `--config`, else the gdi config
    // dir, which is the rule `[keys].identities`, `node_recipient_file` and the pin store
    // already follow (`config_base_dir`). Without it a `--config` run scatters its key material,
    // key beside the config and pin under `~/.config/gdi`. Absolute, because the pin path
    // is recorded in the profile verbatim and must not depend on the cwd a later `pack`
    // runs from.
    let base = gdi_node_standalone_core::config::config_base_dir(config_path).ok_or_else(|| {
        ToolError::user(
            "cannot resolve the gdi config directory: pass --config, or set \
             $GDI_CONFIG_DIR, $XDG_CONFIG_HOME, or $HOME",
        )
    })?;
    let config_d = std::path::absolute(&base).map_err(|e| {
        ToolError::user(format!(
            "cannot resolve {} to an absolute path: {e}",
            base.display()
        ))
    })?;

    // Step 3: Recipient. Offline path (`--recipient`): read a local recipient,
    // record its path, and skip both the network fetch and the trust prompt (the
    // operator explicitly chose the file). Otherwise: fetch it from the node, show the
    // fingerprint, and ask to pin it (trust-on-first-use) — recovering interactively when
    // the node cannot serve one yet, instead of aborting the whole wizard.
    let choice = match (recipient_file, service_url.as_deref()) {
        (Some(rf), _) => RecipientChoice::Pinned(record_recipient_file(rf, &config_d, &name)?),
        (None, Some(url)) => resolve_recipient_online(p, url, &name, &config_d)?,
        // No node URL to fetch from: the same menu the failed-fetch path shows, minus the
        // rows that need a URL — there is nothing to retry, and nothing to pin later.
        (None, None) => match recipient_recovery_menu(p, false, &config_d, &name)? {
            Recovery::Chose(choice) => choice,
            Recovery::Retry => RecipientChoice::Deferred,
        },
    };
    let keyless = matches!(choice, RecipientChoice::Keyless);
    let node_recipient_file = match choice {
        RecipientChoice::Pinned(path) => Some(path),
        RecipientChoice::Deferred | RecipientChoice::Keyless => None,
    };

    // Step 3b: a keyless node is fed by deploying the staging dir into its inbox (there is
    // no package to upload), so the inbox path is the one thing that setup must capture.
    let inbox = if keyless {
        Some(p.input_path(
            "Node inbox directory (where the staging dir is dropped; Tab completes)",
            Some("/var/lib/gdi-node-standalone/inbox"),
            &require_path,
        )?)
    } else {
        None
    };

    // Step 4: Catalogs. A sync failure is not fatal: the pinned catalogs are an
    // optional fail-fast hint (the node re-validates authoritatively at ingest), so a
    // flaky/absent FDP root must not abort setup — warn and continue with an empty
    // allow-list, which can be refreshed later with `catalogs --sync` or
    // `build --refresh-catalogs`.
    let catalogs_map: BTreeMap<String, String> = if let Some(url) = service_url.as_deref() {
        if p.confirm("Sync catalogs from the node?", true)? {
            match runtime::block_on(catalogs::fetch_node_catalogs(url)) {
                Ok(names) => names.into_iter().map(|n| (n.clone(), n)).collect(),
                Err(e) => {
                    crate::output::warn(&format!(
                        "warning: catalog sync failed ({}); continuing with no pinned \
                         catalogs; refresh later with `catalogs --sync`",
                        e.message
                    ));
                    BTreeMap::new()
                }
            }
        } else {
            BTreeMap::new()
        }
    } else {
        // No node to ask, so offer to type them. Optional on purpose, and blank is the
        // default answer: a non-empty allow-list is enforced (`error: unknown catalog: …`
        // at build), so a list typed wrong from memory blocks correct catalogs locally,
        // while an empty one is merely permissive and leaves the node to validate at
        // ingest. Whoever handed over the recipient file usually named the catalogs too,
        // and supplying them upgrades the authoring prompt from free text to a pick-list,
        // which is where a typo gets caught.
        prompt_offline_catalogs(p)?
    };

    // Step 5: S3 (optional).
    // Not asked for a keyless profile. The S3 channel carries packages, and a keyless node
    // produces none — the Publish stage says so and offers only the inbox drop, so asking
    // here would write an `[s3]` block into tool.toml that nothing can use, two prompts
    // after the keyless warning that says "never use it for an S3 bucket".
    if keyless {
        crate::output::progress(
            "  keyless profile: skipping S3: that channel carries packages, and this \
             node is fed by an inbox drop.",
        );
    }
    let (s3, s3_credentials) = if !keyless && p.confirm("Configure S3 upload?", false)? {
        // A re-run offers what the profile already records, as `prefix` and `channel` do:
        // `wizard setup` is the advertised rotation path, and making the operator retype
        // the bucket and endpoint from memory to change a credential invites a typo in the
        // two fields that decide where everything lands.
        let existing_s3 = existing.s3.as_ref();
        let bucket = p.input_validated(
            "S3 bucket name",
            existing_s3.and_then(|s3| s3.bucket.as_deref()),
            &|s| fields::resolve_nonempty("bucket", s).map(|_| ()),
        )?;
        let endpoint = p.input_validated(
            "S3 endpoint URL",
            existing_s3.and_then(|s3| s3.endpoint.as_deref()),
            &|s| fields::resolve_iri("endpoint", s).map(|_| ()),
        )?;
        // `allow_http` is derived below: it is a fact about the endpoint, not a preference.
        // The node's twin flag defaults off so a production misconfiguration cannot silently
        // drop TLS, so a non-loopback plaintext endpoint is called out before it is enabled.
        if let Some(host) = plaintext_non_loopback_host(&endpoint) {
            crate::output::warn(&format!(
                "warning: plaintext S3 endpoint ({host}); credentials and packages will \
                 cross the network unencrypted; use https:// in production"
            ));
        }
        // Some endpoints check the region rather than just recording it: Garage 400s a
        // request signed for anything but its configured `s3_region`, and the client's
        // unset default is `us-east-1`. So it is asked, and a first run offers no default,
        // because `us-east-1` is right for MinIO and Ceph but wrong for Garage and most AWS
        // buckets, and a wrong region only shows up at the wizard's own Publish stage.
        // Pressing Enter through a pre-filled value is exactly how it would get there. A
        // re-run offers the profile's value, like every other S3 field.
        let region = {
            let existing_region = existing_s3.and_then(|s3| s3.region.as_deref());
            crate::output::progress(
                "  the node's region: garage for Garage, us-east-1 for MinIO/Ceph, the \
                 bucket's own for AWS.",
            );
            let answer = p.input_validated("S3 region", existing_region, &|s| {
                fields::resolve_nonempty("region", s).map(|_| ())
            })?;
            answer.trim().to_owned()
        };
        // The prefix is half of the one keyspace both sides address. Set on one side only
        // it is a silent desync: uploads the node never lists. Validated with the node's own
        // spelling rule; a re-run offers the profile's current value. The prompt itself
        // stays short, because dialoguer redraws a finished prompt by clearing one line,
        // so a prompt that wraps leaves its first line behind on every terminal.
        let prefix = {
            let existing_prefix = existing
                .s3
                .as_ref()
                .map(|s3| s3.prefix.clone())
                .unwrap_or_default();
            crate::output::progress(
                "  must match the node's [[s3.buckets]].prefix exactly; a prefix on one side \
                 only is a silent desync.",
            );
            let answer = p.input_validated(
                "Key prefix in the bucket (blank = the whole bucket)",
                (!existing_prefix.is_empty()).then_some(existing_prefix.as_str()),
                &|s| {
                    gdi_node_standalone_core::config::validate_key_prefix(s.trim())
                        .map_err(|why| format!("invalid prefix: {why}"))
                },
            )?;
            answer.trim().to_owned()
        };

        let env_file = config_d.join("secrets.env");
        // `name` is a lowercase `[a-z0-9_]` identifier (validated in step 1), so its
        // upper-case is exactly the env-key segment figment lowercases back to `name`.
        let name_upper = name.to_uppercase();
        if let Some(parent) = env_file.parent() {
            #[expect(
                clippy::disallowed_methods,
                reason = "operator-chosen path; the files inside carry their own mode"
            )]
            std::fs::create_dir_all(parent)
                .map_err(|e| ToolError::user(format!("cannot create {}: {e}", parent.display())))?;
        }
        // Never truncate an existing secrets.env: a re-run only appends the stubs for
        // keys not already present, preserving credentials the operator filled in for
        // this or any other profile.
        //
        // The credentials themselves, hidden. Written to secrets.env for every later run and
        // carried in memory through this one: the process that asked cannot `source` a file
        // into its own environment, and with neither credential loaded the S3 client is
        // built anonymous, so the wizard's own "Upload to S3" fails after build + pack.
        let credentials = prompt_s3_credentials(p)?;
        if let Some(typed) = &credentials {
            write_secret_values(&env_file, &name, &name_upper, typed)?;
            crate::output::progress(&format!(
                "stored the S3 credentials in {} (owner-only); this run carries them, later \
                 runs need: source {}; verify the bucket with `gdi-dataset-tool doctor` \
                 (it does a probe PUT/DELETE)",
                env_file.display(),
                env_file.display()
            ));
        } else {
            write_secret_stub(&env_file, &name, &name_upper)?;
            crate::output::progress(&format!(
                "hint: fill in credentials in {} and run: source {}",
                env_file.display(),
                env_file.display()
            ));
        }

        // Ask for the node's channel name for this bucket — the node's
        // `[[s3.buckets]].name`, which arms the cross-channel guard:
        // `publish`/`delete` write the state sidecar to this profile's bucket, and the
        // mismatch warning (the only thing that catches a wrong-bucket lifecycle write,
        // otherwise a silent no-op reported as success) can only fire when the profile
        // declares the name the node reports. There is no default: the channel is a logical
        // label (conventionally "primary" for bucket "gdi-datasets"), so defaulting to the
        // bucket name would arm the guard with a wrong value and warn on every correct op.
        // Blank leaves the guard off; a re-run offers the profile's current value.
        let channel = {
            let existing_channel = existing.s3.as_ref().and_then(|s3| s3.channel.clone());
            crate::output::progress(
                "  the node's [[s3.buckets]].name for this bucket; ask the node operator.",
            );
            let answer = p.input_validated(
                "Channel name (blank leaves the wrong-bucket guard off)",
                existing_channel.as_deref(),
                &|_| Ok(()),
            )?;
            let trimmed = answer.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_owned())
        };

        // Addressing + scheme, derived rather than defaulted. `ProfileS3::default()` gives
        // `path_style = false` (virtual-hosted) and `allow_http = false`, and both are plain
        // `bool`s with no `skip_serializing_if`, so `config::write` persists those literals
        // into tool.toml. But this branch has made an endpoint mandatory, and a custom
        // endpoint is overwhelmingly a Ceph RGW / MinIO / Garage that speaks path style, so
        // inheriting the defaults would write a profile that looks complete and then fails
        // at the wizard's own Publish stage with a DNS failure or a 400.
        let path_style = p.confirm(
            "Path-style S3 URLs? (yes: RGW/MinIO/Garage; no: virtual-hosted)",
            true,
        )?;
        // Not prompted: this is a fact about the endpoint just entered, not a preference.
        // An `http://` endpoint is otherwise accepted here and then rejected by an
        // https-only client.
        let allow_http = endpoint.starts_with("http://");

        (
            Some(ProfileS3 {
                bucket: Some(bucket),
                endpoint: Some(endpoint),
                region: Some(region),
                prefix,
                channel,
                path_style,
                allow_http,
                ..ProfileS3::default()
            }),
            credentials,
        )
    } else {
        (None, None)
    };

    // Step 6: Ensure the provider keypair exists (auto-generates if missing).
    cmd_keys::load_or_generate_provider_secret(config_path)?;

    // Step 7: Country code — validated inline (2 uppercase letters) so a bad value is
    // caught here rather than failing late at the build stage.
    let cc_raw = p.input_validated("Two-letter country code (e.g. EE)", None, &|s| {
        fields::resolve_country_code(s).map(|_| ())
    })?;
    let cc = fields::resolve_country_code(&cc_raw).unwrap_or(cc_raw);

    // Step 7b: the institute abbreviation — the other identity half of every dataset id
    // (`GDI-<CC>-<ORG>-<millis>`), and like the country code a fact about the provider,
    // not about a dataset. Asked once here so the authoring stage never has to; an
    // integrating backend binds this value to the provider and refuses any other.
    crate::output::progress("  the ORG in GDI-EE-<ORG>-..., e.g. EXAMPLE.");
    let org_raw = p.input_validated(
        "Institute abbreviation for dataset ids",
        existing.org.as_deref(),
        &|s| fields::resolve_org(s).map(|_| ()),
    )?;
    let org = fields::resolve_org(&org_raw).unwrap_or(org_raw);

    // Step 8: Load any existing config so that a re-run preserves unrelated profiles,
    // `default_profile`, and keys rather than clobbering them. Loaded here, after step 6
    // may have touched the key material, not from the read-only snapshot taken above.
    let mut cfg = if target.exists() {
        gdi_node_standalone_core::config::ToolConfig::load_file_only(&target).map_err(|e| {
            ToolError::user(format!(
                "cannot read existing config {}: {e}",
                target.display()
            ))
        })?
    } else {
        ToolConfig::default()
    };
    cfg.country_code = Some(cc);
    // Merge into the existing profile rather than replacing it. `wizard setup` is advertised
    // as re-entry for credential and key rotation, so re-running it on a profile that
    // already exists is a first-class flow, and a wholesale `insert` would reset every field
    // setup never asks about. `management_url` is the costly one: it is the authoritative
    // dataset-state oracle, so losing it silently degrades `status` to the non-authoritative
    // sidecar, disarms the live-id guard on `deploy`/`publish`/`delete`, and makes
    // `deploy --wait` poll a plane that cannot answer. `node_recipient_url` is the same kind
    // of loss.
    //
    // The rule is: overwrite what the operator actually supplied, preserve what they were
    // never asked about — and treat a declined optional step as "leave it alone", not "erase
    // it". Declining the catalog sync must not wipe a pinned allow-list; declining S3 must
    // not discard a configured bucket; a deferred recipient must not drop an existing pin.
    let mut profile = cfg.profiles.remove(&name).unwrap_or_default();

    // Step 9: VCF header policy. A per-deployment decision, so it lives on the profile and
    // is asked here, once, rather than by `build` per dataset: the node drops `headers/` at
    // ingest and never serves them, so what the members carry only matters to whoever
    // reads the package's non-public sections on the receiving side. Asked after the
    // existing config is loaded so a re-run pre-selects the profile's current choice — the
    // advertised re-entry for key rotation must not silently narrow a deliberate
    // `with-identifiers` back to the built-in default.
    let labels: Vec<String> = HEADER_POLICY_CHOICES
        .iter()
        .map(|c| header_policy_label(*c).to_owned())
        .collect();
    crate::output::progress(
        "  the node drops these at ingest; `--header-policy` on build/package always \
         overrides the profile.",
    );
    let choice = p.select(
        "VCF headers to ship in packages",
        &labels,
        header_policy_default_index(profile.header_policy),
    )?;
    profile.header_policy = Some(*HEADER_POLICY_CHOICES.get(choice).ok_or_else(|| {
        ToolError::user(format!("header policy choice {choice} is out of range"))
    })?);

    if service_url.is_some() {
        profile.service_url = service_url;
    }
    profile.org = Some(org);
    if management_url.is_some() {
        profile.management_url = management_url;
    }
    profile.keyless = keyless;
    if node_recipient_file.is_some() {
        profile.node_recipient_file = node_recipient_file;
    }
    if !catalogs_map.is_empty() {
        profile.catalogs = catalogs_map;
    }
    if s3.is_some() {
        // Every S3 field is prompted, each defaulting to the profile's current value, so the
        // prompted block is the whole answer: a re-run (the documented credential-rotation
        // path) keeps whatever the operator pressed Enter on.
        profile.s3 = s3;
    }
    if inbox.is_some() {
        profile.inbox = inbox;
    }
    let profile_label = name.clone();
    cfg.profiles.insert(name, profile);
    // A config with several profiles and no `default_profile` selects nothing: every
    // profile-reading command fails "no profile selected: pass --profile or set
    // default_profile", and the only repair is hand-editing the file. Setup is the one
    // writer that adds a profile, so it is the one place that can prevent it, both for a
    // name typed here and for a second profile that arrived any other way.
    //
    // A choice, not a yes/no. Asking "make this one the default?" reads as "or keep the
    // one you had", but this branch only runs when there is no default to keep, so
    // declining wrote exactly the config the paragraph above describes. Every answer here
    // names a profile, so setup cannot leave a config that selects nothing. The one the
    // operator just configured comes first, so the pre-selected answer is the expected one.
    if cfg.profiles.len() > 1 && cfg.default_profile.is_none() {
        crate::output::warn(&format!(
            "warning: {} profiles are configured and none is the default, so every command \
             would need --profile",
            cfg.profiles.len()
        ));
        let mut names = vec![profile_label.clone()];
        names.extend(
            cfg.profiles
                .keys()
                .filter(|k| **k != profile_label)
                .cloned(),
        );
        let chosen = p.select("Which profile should be the default?", &names, 0)?;
        // `get` rather than an index: a prompter that returns an out-of-range choice must
        // not panic the wizard, and the profile just written is the safe fallback.
        cfg.default_profile = Some(names.get(chosen).unwrap_or(&profile_label).clone());
    }
    gdi_node_standalone_core::config::write(&cfg, &target)
        .map_err(|e| ToolError::user(format!("cannot write {}: {e}", target.display())))?;

    // Always printed, like the journey's own closing summary: after a dozen questions the
    // operator needs the path the profile landed at.
    crate::output::always(&format!(
        "ok: profile '{profile_label}' written to {}",
        target.display()
    ));
    // Only when setup was the whole run. Mid-journey this would tell the operator to run
    // the command they are already inside, one line before `[2/5] Author`.
    if standalone {
        crate::output::always(
            "  next      `gdi-dataset-tool wizard` to author and build a dataset \
             (`gdi-dataset-tool doctor` checks the node, keys and bucket)",
        );
    }

    Ok(SetupOutcome {
        config_path: target,
        s3_credentials,
    })
}

/// The config file setup writes: `--config`, else the default path in the gdi config dir.
///
/// # Errors
///
/// Returns a [`ToolError`] when no default path can be resolved.
fn resolve_write_target(config_path: Option<&Path>) -> Result<PathBuf, ToolError> {
    match config_path {
        Some(p) => Ok(p.to_path_buf()),
        None => gdi_node_standalone_core::config::default_config_path().ok_or_else(|| {
            ToolError::user(
                "cannot resolve the default config path: set $GDI_CONFIG_DIR, \
                 $XDG_CONFIG_HOME, or $HOME",
            )
        }),
    }
}

/// Persist `org` into the active profile — what the authoring stage offers when the
/// profile has none, so the question is asked once rather than per dataset. Returns the
/// written path.
///
/// # Errors
///
/// Returns a [`ToolError`] when the config path cannot be resolved, no profile can be
/// selected, or the write fails.
pub fn store_profile_org(
    config_path: Option<&Path>,
    profile_name: Option<&str>,
    org: &str,
) -> Result<PathBuf, ToolError> {
    let target = resolve_write_target(config_path)?;
    let mut cfg = if target.exists() {
        ToolConfig::load_file_only(&target).map_err(|e| {
            ToolError::user(format!(
                "cannot read existing config {}: {e}",
                target.display()
            ))
        })?
    } else {
        ToolConfig::default()
    };
    let name = crate::profile::select_active_name(&cfg, profile_name)?;
    cfg.profiles.entry(name).or_default().org = Some(org.to_owned());
    gdi_node_standalone_core::config::write(&cfg, &target)
        .map_err(|e| ToolError::user(format!("cannot write {}: {e}", target.display())))?;
    Ok(target)
}

/// Ask for the two S3 credentials, hidden. A blank access key skips both (the stub file
/// is written instead), and so does a blank secret — one credential alone is a
/// configuration the S3 client refuses.
fn prompt_s3_credentials(p: &dyn Prompter) -> Result<Option<S3Credentials>, ToolError> {
    let access_key_id = p
        .secret("S3 access key id (blank to skip; secrets.env can be filled in later)")?
        .trim()
        .to_owned();
    if access_key_id.is_empty() {
        return Ok(None);
    }
    let secret_access_key = p.secret("S3 secret access key")?.trim().to_owned();
    if secret_access_key.is_empty() {
        crate::output::warn(
            "warning: no secret access key entered. Both credentials are skipped; fill in \
             secrets.env",
        );
        return Ok(None);
    }
    Ok(Some(S3Credentials {
        access_key_id,
        secret_access_key,
    }))
}

/// Write this profile's two credential lines into `secrets.env`, replacing any earlier
/// lines for the same two keys and keeping every other line (other profiles' credentials
/// included). Atomic and owner-only like [`write_secret_file`]; the values are
/// single-quoted so `source` reads them verbatim.
fn write_secret_values(
    path: &Path,
    profile: &str,
    name_upper: &str,
    creds: &S3Credentials,
) -> Result<(), ToolError> {
    use std::fmt::Write as _;
    let access = format!("GDI_TOOL__PROFILES__{name_upper}__S3__ACCESS_KEY_ID");
    let secret = format!("GDI_TOOL__PROFILES__{name_upper}__S3__SECRET_ACCESS_KEY");
    let existing = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(ToolError::user(format!(
                "cannot read {}: {e}",
                path.display()
            )));
        }
    };
    let mut out = String::new();
    if existing.is_empty() {
        out.push_str("# GDI S3 credentials: source this file before running gdi-dataset-tool.\n");
    }
    // Drop this profile's own lines — its two keys and the comment that heads them —
    // because they are re-appended below. Keeping the comment would make every rotation
    // add another `# profile 'x'` above the same pair.
    let header = format!("# profile '{profile}'");
    for line in existing.lines() {
        let ours = line.trim_start().starts_with(&format!("{access}="))
            || line.trim_start().starts_with(&format!("{secret}="))
            || line.trim_end() == header;
        if !ours {
            out.push_str(line);
            out.push('\n');
        }
    }
    // Writing to a `String` via `fmt::Write` is infallible; discard the Result.
    let _ = writeln!(out, "{header}");
    let _ = writeln!(out, "{access}={}", shell_single_quote(&creds.access_key_id));
    let _ = writeln!(
        out,
        "{secret}={}",
        shell_single_quote(&creds.secret_access_key)
    );
    write_secret_file(path, &out)
}

/// `s` as a POSIX single-quoted word: verbatim except `'`, which becomes `'\''`.
fn shell_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// The `header_policy` choices `wizard setup` offers, in menu order. `minimal` comes first:
/// it is the pre-selected default for a fresh profile (index 0), the one that needs no
/// decision. `verbatim` is not offered — it is not a profile value at all.
const HEADER_POLICY_CHOICES: [ProfileHeaderPolicy; 3] = [
    ProfileHeaderPolicy::Minimal,
    ProfileHeaderPolicy::WithIdentifiers,
    ProfileHeaderPolicy::None,
];

/// The menu index to pre-select: the profile's existing choice on a re-run, else `minimal`.
fn header_policy_default_index(existing: Option<ProfileHeaderPolicy>) -> usize {
    existing
        .and_then(|e| HEADER_POLICY_CHOICES.iter().position(|c| *c == e))
        .unwrap_or(0)
}

/// The menu label for one header policy: the value as spelled in `tool.toml`, then what
/// it means for the sample identifiers — the fact the operator is deciding about.
fn header_policy_label(policy: ProfileHeaderPolicy) -> &'static str {
    match policy {
        ProfileHeaderPolicy::Minimal => {
            "minimal: structural keys only, no sample identifiers (default)"
        }
        ProfileHeaderPolicy::WithIdentifiers => {
            "with-identifiers: also the #CHROM sample columns and ##SAMPLE/##PEDIGREE lines"
        }
        ProfileHeaderPolicy::None => "none: ship no VCF headers at all",
    }
}

/// The host of a plaintext (`http://`) endpoint when it is not loopback — the case
/// worth a warning before `allow_http` is derived on. Loopback (`localhost`,
/// `127.0.0.1`, `::1`) is the ordinary local-dev shape and stays silent.
fn plaintext_non_loopback_host(endpoint: &str) -> Option<String> {
    let rest = endpoint.strip_prefix("http://")?;
    let authority = rest.split('/').next().unwrap_or(rest);
    // Strip the port: `[::1]:3900` keeps the bracketed host, `host:port` the host.
    let host = if let Some(bracketed) = authority.strip_prefix('[') {
        bracketed.split(']').next().unwrap_or(bracketed)
    } else {
        authority.split(':').next().unwrap_or(authority)
    };
    let loopback = host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1";
    (!loopback).then(|| host.to_owned())
}

/// The fetch failure's cause with the URL echoes stripped. The raw message embeds
/// `cannot fetch node recipient <url>: … for url (<url>)`, which would print the same URL
/// three times in one line.
fn terse_fetch_cause(url: &str, message: &str) -> String {
    message
        .strip_prefix(&format!("cannot fetch node recipient {url}: "))
        .unwrap_or(message)
        .replace(&format!(" for url ({url})"), "")
}

/// What the recipient step settled on.
#[derive(Debug)]
enum RecipientChoice {
    /// A recipient is available; the profile records this path.
    Pinned(String),
    /// No recipient yet — the node is simply not up. `pack` re-derives the recipient URL
    /// from `service_url` and fetches it at pack time; `keys pin-recipient` pins it.
    Deferred,
    /// The node holds no crypt4gh identity at all, so nothing is ever encrypted to it:
    /// the wizard deploys the plaintext staging dir into its inbox instead of packing.
    Keyless,
}

/// `input_validated` validator for a required filesystem path: reject a blank answer.
fn require_path(s: &str) -> Result<(), String> {
    if s.trim().is_empty() {
        Err("a path is required".to_owned())
    } else {
        Ok(())
    }
}

/// Ask for the node's catalog names when there is no node to ask.
///
/// Blank — the expected answer — yields an empty allow-list, i.e. exactly the behaviour
/// before this prompt existed. Names are trimmed and de-duplicated; the title is the name,
/// as a sync would record it (titles are cosmetic; the node is the source of truth).
///
/// # Errors
///
/// Propagates a prompt failure.
fn prompt_offline_catalogs(p: &dyn Prompter) -> Result<BTreeMap<String, String>, ToolError> {
    crate::output::progress(
        "  no node to ask, so these cannot be synced. Blank is fine: the node validates \
         at ingest either way; naming them here only catches a typo sooner.",
    );
    let raw = p.input(
        "Catalog names this node accepts (comma-separated; blank to skip)",
        None,
        true,
    )?;
    Ok(raw
        .split(',')
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(|n| (n.to_owned(), n.to_owned()))
        .collect())
}

/// Read a local recipient file, report its fingerprint, and return the absolute path to
/// record in the profile (so it resolves regardless of the cwd at build/pack time).
///
/// # Errors
///
/// Returns a [`ToolError`] when the file is missing or is not a valid crypt4gh recipient.
fn record_recipient_file(rf: &Path, config_d: &Path, name: &str) -> Result<String, ToolError> {
    let pk = recipient::read_node_recipient_file(rf)?;
    crate::output::progress(&format!(
        "recipient fingerprint: {} (from {})",
        gdi_node_standalone_core::crypt4gh::public_key_fingerprint(&pk),
        rf.display()
    ));
    // Copy it, exactly as the online path pins a fetched key — do not record where the
    // operator happened to be pointing. This is the air-gapped path, so that file arrives
    // on a USB stick, in /tmp, or in a downloads folder, and recording its original
    // location would make the profile depend on a path that is often gone by the next run:
    // the whole VCF conversion would run and `pack` fail at the very end with "cannot read
    // recipient …: No such file or directory", with `doctor` agreeing. It is a public key,
    // so copying it carries nothing sensitive.
    //
    // `force = false`, like the online path: an existing pin that differs is a rotation or
    // worse. Re-pinning it takes an explicit `keys pin-recipient --file <PATH> --force`,
    // the offline form of the verb, rather than a silent overwrite because someone pointed
    // the wizard at a new file.
    let pin_path = config_d.join("recipients").join(format!("{name}.pub"));
    recipient::write_pinned_recipient(&pk, &pin_path, false)?;
    Ok(pin_path.to_string_lossy().into_owned())
}

/// Fetch the node's recipient over the network and pin it (trust-on-first-use).
///
/// A node that cannot serve a recipient is not a fatal setup error. On a first
/// bring-up the node does not exist yet, so `{service_url}/.well-known/c4gh-recipient`
/// is a connection error or a 404 — aborting there strands the operator in a
/// chicken-and-egg (the wizard demands a running node; the node is what you are about to
/// stand up). So a fetch failure drops into a recovery menu instead.
///
/// Minting a node identity is not offered: the node's secret key belongs to the node and
/// must be generated there. The provider tool never holds it. It only ever learns the
/// node's public recipient, online or from a file handed over out-of-band.
///
/// Returns the pinned recipient path, or the operator's chosen alternative: defer (pin it
/// later, once the node is up) or keyless (this node has no identity, so never encrypt).
///
/// # Errors
///
/// Returns a [`ToolError`] when `service_url` yields no recipient URL, on a prompt I/O
/// failure, or when the operator explicitly aborts.
fn resolve_recipient_online(
    p: &dyn Prompter,
    service_url: &str,
    name: &str,
    config_d: &Path,
) -> Result<RecipientChoice, ToolError> {
    let tmp_profile = Profile {
        service_url: Some(service_url.to_owned()),
        ..Profile::default()
    };
    let recipient_url = recipient::node_recipient_url(&tmp_profile).ok_or_else(|| {
        ToolError::user("cannot derive recipient URL from service_url: service_url must be set")
    })?;

    loop {
        match runtime::block_on(recipient::fetch_node_recipient(&recipient_url)) {
            Ok(pk) => {
                crate::output::progress(&format!(
                    "recipient fingerprint: {}",
                    gdi_node_standalone_core::crypt4gh::public_key_fingerprint(&pk)
                ));
                if !p.confirm("Trust this recipient?", true)? {
                    return Ok(RecipientChoice::Deferred);
                }
                let pin_path = config_d.join("recipients").join(format!("{name}.pub"));
                recipient::write_pinned_recipient(&pk, &pin_path, false)?;
                return Ok(RecipientChoice::Pinned(
                    pin_path.to_string_lossy().into_owned(),
                ));
            }
            Err(e) => {
                crate::output::warn(&format!(
                    "warning: node not reachable at {recipient_url}: expected on a first \
                     bring-up ({})",
                    terse_fetch_cause(&recipient_url, &e.message)
                ));
                match recipient_recovery_menu(p, true, config_d, name)? {
                    Recovery::Chose(choice) => return Ok(choice),
                    Recovery::Retry => {}
                }
            }
        }
    }
}

/// What [`recipient_recovery_menu`] settled on.
#[derive(Debug)]
enum Recovery {
    /// A recipient decision was made.
    Chose(RecipientChoice),
    /// Try the fetch again (only reachable when a fetch exists to retry).
    Retry,
}

/// One row of [`recipient_recovery_menu`]. The menu is conditional, so rows are matched
/// by kind rather than by position.
#[derive(Clone, Copy)]
enum Row {
    /// Name a local recipient file.
    File,
    /// Re-attempt the fetch (URL-only).
    Retry,
    /// The node holds no identity; deploy plaintext to its inbox.
    Keyless,
    /// Proceed with no recipient and pin it later (URL-only).
    Defer,
    /// Give up on setup.
    Abort,
}

/// The "no node recipient" recovery menu, shared by the failed-fetch path and the
/// no-service-URL path so both offer the operator the same escape hatches.
///
/// `offer_retry` adds the retry row: with no URL configured there is nothing to retry,
/// and offering it would loop the menu forever.
///
/// # Errors
///
/// Returns a [`ToolError`] on a prompt failure, or when the operator aborts setup.
fn recipient_recovery_menu(
    p: &dyn Prompter,
    has_recipient_url: bool,
    config_d: &Path,
    name: &str,
) -> Result<Recovery, ToolError> {
    loop {
        // Rows are built as (label, kind) pairs and matched on the kind. Matching on the
        // index instead would make the optional retry row shift every row below it, so one
        // row added in the wrong place would silently re-point three choices.
        let mut rows = vec![(
            "Use a recipient file the node operator gave me (offline / air-gapped)".to_owned(),
            Row::File,
        )];
        // Both of these need a URL to mean anything: there is nothing to retry, and
        // nothing for `keys pin-recipient` to pin from, when none is configured. Offering
        // "pin it later" there would leave a profile whose advertised remedy answers
        // "error: no recipient source". One flag, so the two rows cannot drift apart.
        if has_recipient_url {
            rows.push((
                "Retry the fetch (the node may still be starting)".to_owned(),
                Row::Retry,
            ));
        }
        rows.push((
            "This node is KEYLESS: don't encrypt; deploy the staging dir to its inbox".to_owned(),
            Row::Keyless,
        ));
        if has_recipient_url {
            rows.push((
                "Continue without one: pin it later with `keys pin-recipient`".to_owned(),
                Row::Defer,
            ));
        }
        rows.push(("Abort setup".to_owned(), Row::Abort));
        let labels: Vec<String> = rows.iter().map(|(label, _)| label.clone()).collect();
        let chosen = p.select("No node recipient. How do you want to proceed?", &labels, 0)?;
        match rows.get(chosen).map(|(_, kind)| *kind) {
            Some(Row::File) => {
                // Blank returns to the menu. This row is the pre-selected one, so a
                // provider who has no file at all reaches it by pressing Enter, and a
                // validator that rejected blank would re-prompt forever, with no way back
                // to the rows that are the actual answer.
                crate::output::progress("  blank goes back to this menu; Tab completes.");
                let entered =
                    p.input_path("Path to the node's recipient file", None, &|_| Ok(()))?;
                let entered = entered.trim();
                if entered.is_empty() {
                    continue;
                }
                match record_recipient_file(Path::new(entered), config_d, name) {
                    Ok(path) => return Ok(Recovery::Chose(RecipientChoice::Pinned(path))),
                    // A bad path must not strand the operator: warn and re-offer the
                    // menu rather than aborting a half-finished setup.
                    Err(bad) => crate::output::warn(&format!("warning: {}", bad.message)),
                }
            }
            Some(Row::Retry) => return Ok(Recovery::Retry),
            Some(Row::Keyless) => {
                // A keyless node holds no identity, so there is no recipient to wait for
                // and nothing to encrypt to. Only safe when the inbox is the trust
                // boundary — say so, because the same choice on an S3 or third-party
                // node would ship the dataset in the clear.
                crate::output::warn(
                    "warning: keyless node: packages will NOT be encrypted; the plaintext \
                     staging dir is deployed into the node's inbox (the node records it as \
                     `Plaintext` provenance). This is safe ONLY when that inbox is itself \
                     the trust boundary, i.e. a co-located node on a filesystem you \
                     control. Never use it for an S3 bucket or a node someone else runs.",
                );
                return Ok(Recovery::Chose(RecipientChoice::Keyless));
            }
            Some(Row::Defer) => {
                crate::output::warn(
                    "warning: continuing with no pinned recipient: `pack`/`package` will \
                     fetch it from the node at pack time and refuse to encrypt while the \
                     node is unreachable. Once the node serves /.well-known/c4gh-recipient, \
                     run `gdi-dataset-tool keys pin-recipient` to pin it \
                     (trust-on-first-use).",
                );
                return Ok(Recovery::Chose(RecipientChoice::Deferred));
            }
            Some(Row::Abort) | None => {
                return Err(ToolError::user(
                    "setup aborted: no node recipient. Re-run `wizard setup` once the node \
                     is serving /.well-known/c4gh-recipient, or pass `--recipient <file>` \
                     to set up offline from a recipient the node operator sent you. To \
                     describe and build the dataset meanwhile, run `gdi-dataset-tool wizard \
                     --from author --to build`; only `pack` needs the node's key",
                ));
            }
        }
    }
}

/// Ensure `secrets.env` carries this profile's two S3 credential keys, without ever
/// truncating an existing file.
///
/// A fresh file is created (`0o600`) with a header and empty stubs. If the file already
/// exists, it is read and only the keys it does not already contain are appended under a
/// per-profile comment — so re-running `wizard setup` (to add a profile, fix a field, or
/// re-run S3 setup) preserves credentials the operator filled in, for this profile and
/// every other. Idempotent: when both keys are already present, nothing is written.
fn write_secret_stub(path: &Path, profile: &str, name_upper: &str) -> Result<(), ToolError> {
    use std::fmt::Write as _;
    let access = format!("GDI_TOOL__PROFILES__{name_upper}__S3__ACCESS_KEY_ID");
    let secret = format!("GDI_TOOL__PROFILES__{name_upper}__S3__SECRET_ACCESS_KEY");
    if !path.exists() {
        let content = format!(
            "# GDI S3 credentials: source this file before running gdi-dataset-tool.\n\
             # Fill in the values below; `wizard setup` only ever appends to this file.\n\
             # profile '{profile}'\n\
             {access}=\n\
             {secret}=\n"
        );
        return write_secret_file(path, &content);
    }

    let existing = fs::read_to_string(path)
        .map_err(|e| ToolError::user(format!("cannot read {}: {e}", path.display())))?;
    let has = |key: &str| {
        let prefix = format!("{key}=");
        existing
            .lines()
            .any(|l| l.trim_start().starts_with(&prefix))
    };
    let (has_access, has_secret) = (has(&access), has(&secret));
    if has_access && has_secret {
        return Ok(());
    }
    // Writing to a `String` via `fmt::Write` is infallible; discard the Result.
    let mut add = String::new();
    let _ = writeln!(add, "\n# GDI S3 credentials for profile '{profile}'");
    if !has_access {
        let _ = writeln!(add, "{access}=");
    }
    if !has_secret {
        let _ = writeln!(add, "{secret}=");
    }
    append_secret_file(path, &add)
}

/// Append `contents` to `path`, creating it `0o600` on Unix if absent. Unlike
/// [`write_secret_file`] this never truncates, so it cannot destroy existing secrets.
fn append_secret_file(path: &Path, contents: &str) -> Result<(), ToolError> {
    use std::io::Write as _;
    let cannot_write =
        |e: std::io::Error| ToolError::user(format!("cannot write {}: {e}", path.display()));
    let mut options = fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(cannot_write)?;
    file.write_all(contents.as_bytes()).map_err(cannot_write)
}

/// Write the credential `contents` to `path` atomically and durably, `0o600` on Unix —
/// the same shared secret writer `keys generate` uses.
fn write_secret_file(path: &Path, contents: &str) -> Result<(), ToolError> {
    gdi_node_standalone_core::util::write_secret_durable(path, contents.as_bytes())
        .map_err(|e| ToolError::user(format!("cannot write {}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;
    use crate::wizard::prompts::ScriptedPrompter;
    use gdi_node_standalone_core::config::{Profile, ToolConfig};

    /// The S3 step records a typed key prefix, and a blank channel answer leaves the field
    /// unset, so the wrong-bucket guard stays off. Arming it with the bucket name would be
    /// wrong: the node's channel (`[[s3.buckets]].name`) is conventionally "primary".
    #[test]
    #[serial_test::serial(env)]
    fn s3_setup_records_the_prefix_and_a_blank_channel_disarms_the_guard() {
        use gdi_node_standalone_core::crypt4gh::{generate_keypair, serialize_public_key};
        let (_sk, pk) = generate_keypair();
        let base = stub_node(&serialize_public_key(&pk));
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");
        let p = ScriptedPrompter::new()
            .with_inputs(vec![
                "default",
                &base,
                "", // management URL: none
                "gdi-bucket",
                "https://s3.example.org",
                "garage",            // region: the endpoint's, not the client's default
                "gdi-node-storage/", // key prefix: must match the node's entry
                "",                  // channel: blank — guard off
                "EE",
                "UTARTU",
            ])
            .with_confirms(vec![
                true,  /*trust*/
                false, /*catalogs*/
                true,  /*S3?*/
                true,  /*path-style*/
            ])
            .with_secrets(vec![""])
            .with_selects(vec![0]);
        let _prev = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path());

        run_setup(&p, Some(&cfg_path), None, None, true).unwrap();
        let cfg = ToolConfig::load(Some(&cfg_path)).unwrap();
        let s3 = cfg.profiles["default"].s3.as_ref().expect("s3 configured");
        assert_eq!(
            s3.prefix, "gdi-node-storage/",
            "the typed prefix must reach the profile — a one-sided prefix is the \
             silent-desync case the prompt exists to prevent"
        );
        assert_eq!(s3.channel, None, "blank leaves the wrong-bucket guard off");
        assert_eq!(
            s3.region.as_deref(),
            Some("garage"),
            "the typed region must reach the profile: Garage rejects the client's \
             `us-east-1` default with a 400 at the wizard's own Publish stage"
        );
    }

    /// Under `--config`, every artifact setup writes lands beside the config file, not in
    /// the environment's config dir: `secrets.env`, the recipient pin and the provider key.
    /// Splitting them was the defect: the key went beside the config (`[keys].identities`
    /// resolves there) while `secrets.env` and the pin went under `~/.config/gdi`, so the
    /// `source` hint named a file in a directory the operator never chose, and the pin sat
    /// where a later `--config` run only finds it through the legacy-location fallback.
    #[test]
    #[serial_test::serial(env)]
    fn setup_under_config_keeps_secrets_pin_and_key_beside_the_config_file() {
        use gdi_node_standalone_core::crypt4gh::{generate_keypair, serialize_public_key};
        let (_sk, pk) = generate_keypair();
        let base = stub_node(&serialize_public_key(&pk));
        let env_dir = tempfile::tempdir().unwrap();
        let cfg_dir = tempfile::tempdir().unwrap();
        let cfg_path = cfg_dir.path().join("tool.toml");
        let p = ScriptedPrompter::new()
            .with_inputs(vec![
                "default",
                &base,
                "", // management URL: none
                "gdi-bucket",
                "https://s3.example.org",
                "us-east-1", // region
                "",          // key prefix: whole bucket
                "primary",   // channel
                "EE",
                "UTARTU",
            ])
            .with_confirms(vec![
                true,  /*trust*/
                false, /*catalogs*/
                true,  /*S3?*/
                true,  /*path-style*/
            ])
            .with_secrets(vec![""]) // blank: the stub is written instead
            .with_selects(vec![0]);
        let _prev = test_util::EnvGuard::set("GDI_CONFIG_DIR", env_dir.path());

        run_setup(&p, Some(&cfg_path), None, None, true).unwrap();

        let beside = cfg_dir.path();
        assert!(
            beside.join("secrets.env").is_file(),
            "secrets.env goes beside the --config file"
        );
        assert!(
            beside.join("keys").join("provider.c4gh").is_file(),
            "the provider key goes beside the --config file"
        );
        let cfg = ToolConfig::load(Some(&cfg_path)).unwrap();
        let recorded = cfg.profiles["default"]
            .node_recipient_file
            .clone()
            .expect("recipient pinned");
        assert_eq!(
            std::path::Path::new(&recorded),
            beside.join("recipients").join("default.pub"),
            "the pin goes beside the --config file, recorded absolute"
        );
        assert!(
            !env_dir.path().join("secrets.env").exists()
                && !env_dir.path().join("recipients").exists()
                && !env_dir.path().join("keys").exists(),
            "nothing lands in the environment's config dir when --config names another"
        );
    }

    /// A first run offers no region default. `us-east-1` is right for minio and Ceph and
    /// wrong for Garage and most AWS buckets, and a wrong region fails only at the wizard's
    /// own Publish stage with a 400, so a blank answer is refused, naming the field, rather
    /// than filled in. (A re-run offers the profile's value; the re-run test covers that.)
    #[test]
    #[serial_test::serial(env)]
    fn a_first_run_refuses_a_blank_s3_region_rather_than_defaulting_it() {
        use gdi_node_standalone_core::crypt4gh::{generate_keypair, serialize_public_key};
        let (_sk, pk) = generate_keypair();
        let base = stub_node(&serialize_public_key(&pk));
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");
        let p = ScriptedPrompter::new()
            .with_inputs(vec![
                "default",
                &base,
                "", // management URL: none
                "gdi-bucket",
                "https://s3.example.org",
                "", // region: blank, and there is nothing to fall back to
            ])
            .with_confirms(vec![
                true,  /*trust*/
                false, /*catalogs*/
                true,  /*S3?*/
            ]);
        let _prev = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path());

        let err = run_setup(&p, Some(&cfg_path), None, None, true).unwrap_err();
        assert!(
            err.message.contains("region"),
            "the refusal must name the field; got: {}",
            err.message
        );
        assert!(
            !cfg_path.exists(),
            "nothing is written when setup stops at the region"
        );
    }

    /// A plaintext endpoint warns only off-loopback, so local dev stays quiet.
    #[test]
    fn plaintext_warning_fires_only_off_loopback() {
        assert_eq!(plaintext_non_loopback_host("https://s3.example.org"), None);
        assert_eq!(plaintext_non_loopback_host("http://127.0.0.1:8383"), None);
        assert_eq!(plaintext_non_loopback_host("http://localhost:9000/x"), None);
        assert_eq!(plaintext_non_loopback_host("http://[::1]:3900"), None);
        assert_eq!(
            plaintext_non_loopback_host("http://s3.hpc.example:3900/bucket").as_deref(),
            Some("s3.hpc.example")
        );
        assert_eq!(
            plaintext_non_loopback_host("http://10.0.0.7").as_deref(),
            Some("10.0.0.7")
        );
    }

    #[test]
    fn terse_fetch_cause_strips_the_url_echoes() {
        // The raw failure embeds the URL twice more than the warning's own prose.
        let url = "https://127.0.0.1:18080/.well-known/c4gh-recipient";
        let raw =
            format!("cannot fetch node recipient {url}: error sending request for url ({url})");
        assert_eq!(terse_fetch_cause(url, &raw), "error sending request");
        // A message in another shape passes through unshortened.
        assert_eq!(
            terse_fetch_cause(url, "connection refused"),
            "connection refused"
        );
    }

    #[test]
    fn profile_complete_needs_some_way_to_reach_a_recipient() {
        let mut prof = Profile::default();
        assert!(!profile_complete(&prof));
        prof.service_url = Some("https://node".into());
        prof.node_recipient_file = Some("r.pub".into());
        assert!(profile_complete(&prof));
    }

    /// A profile whose recipient is a local file is complete without any node URL: a
    /// provider packaging for hand-off has no node to name, and calling that profile
    /// incomplete would re-run the whole setup wizard on every invocation.
    #[test]
    fn a_local_recipient_alone_completes_a_profile() {
        let file_only = Profile {
            node_recipient_file: Some("node.pub".into()),
            ..Profile::default()
        };
        assert!(
            profile_complete(&file_only),
            "an offline, file-only profile must not re-trigger setup"
        );
        // A `service_url` alone also completes a profile: the recipient URL is derived
        // from it, so `pack` can resolve a recipient (fetch, then verify against any pin).
        // Requiring `node_recipient_url` on top — which the wizard never writes, and which
        // `keys pin-recipient` does not write either — would make the "pin it later" branch
        // permanently incomplete and restart setup on every run.
        let url_only = Profile {
            service_url: Some("https://node".into()),
            ..Profile::default()
        };
        assert!(
            profile_complete(&url_only),
            "a fetchable recipient is a resolvable recipient"
        );
        // Nothing at all to reach a recipient with is still incomplete.
        assert!(!profile_complete(&Profile::default()));
    }

    /// Setup completes with no service URL: the recovery menu (minus its retry row, there
    /// being no fetch to retry) offers the recipient file, and the resulting profile is
    /// complete, so the next wizard run goes straight to authoring.
    #[test]
    #[serial_test::serial(env)]
    fn setup_completes_offline_without_a_service_url() {
        use gdi_node_standalone_core::crypt4gh::{generate_keypair, serialize_public_key};
        let dir = tempfile::tempdir().unwrap();
        let (_sk, pk) = generate_keypair();
        let recipient = dir.path().join("node.pub");
        std::fs::write(&recipient, serialize_public_key(&pk)).unwrap();
        let cfg_path = dir.path().join("config.toml");

        // Ask order with no URL: profile name, service URL (blank), management URL,
        // [recovery menu select 0], recipient path, country code, org.
        let p = ScriptedPrompter::new()
            .with_inputs(vec![
                "default",
                "", // service URL: none — there is no node yet
                "", // management URL: none
                recipient.to_str().unwrap(),
                "", // catalogs: blank — offered because there is no node to sync from
                "EE",
                "UTARTU",
            ])
            .with_selects(vec![
                0, // recovery menu: use a recipient file
                0, // header policy: minimal
            ])
            // No catalog-sync confirm: there is no node to sync from — the names are
            // offered as free text instead, answered blank above.
            .with_confirms(vec![false /*S3?*/]);
        let _prev = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path());

        run_setup(&p, Some(&cfg_path), None, None, true).unwrap();
        let cfg = ToolConfig::load(Some(&cfg_path)).unwrap();
        let prof = &cfg.profiles["default"];
        assert_eq!(prof.service_url, None, "a blank answer records no URL");
        assert!(prof.node_recipient_file.is_some(), "the file was recorded");
        assert!(
            profile_complete(prof),
            "the offline profile setup just wrote must not send the next run back to setup"
        );
    }

    /// A keyless profile has no recipient by design. If `profile_complete` demanded one, the
    /// wizard's setup stage would consider the profile unfinished and re-run `wizard setup`
    /// on every single invocation.
    #[test]
    fn a_keyless_profile_is_complete_without_a_recipient() {
        let mut prof = Profile {
            keyless: true,
            service_url: Some("http://127.0.0.1:8080".into()),
            ..Profile::default()
        };
        assert!(
            !profile_complete(&prof),
            "a keyless profile with no inbox has no deploy target yet"
        );
        prof.inbox = Some("/var/lib/gdi-node-standalone/inbox".into());
        assert!(
            profile_complete(&prof),
            "a keyless profile needs an inbox, NOT a recipient — otherwise the wizard \
             re-runs setup forever"
        );
    }

    #[test]
    fn secret_stub_preserves_filled_values_and_is_idempotent() {
        // Re-running S3 setup must never truncate operator-filled credentials.
        let dir = tempfile::tempdir().unwrap();
        let env_file = dir.path().join("secrets.env");

        // First profile: fresh file with empty stubs.
        write_secret_stub(&env_file, "default", "DEFAULT").unwrap();
        // Operator fills in the access key.
        let filled = std::fs::read_to_string(&env_file).unwrap().replace(
            "GDI_TOOL__PROFILES__DEFAULT__S3__ACCESS_KEY_ID=",
            "GDI_TOOL__PROFILES__DEFAULT__S3__ACCESS_KEY_ID=AKIAFILLED",
        );
        std::fs::write(&env_file, &filled).unwrap();

        // Re-running for the same profile must not clobber the filled value (both keys
        // already present -> nothing written).
        write_secret_stub(&env_file, "default", "DEFAULT").unwrap();
        let after = std::fs::read_to_string(&env_file).unwrap();
        assert!(
            after.contains("GDI_TOOL__PROFILES__DEFAULT__S3__ACCESS_KEY_ID=AKIAFILLED"),
            "the operator-filled value must be preserved on a re-run:\n{after}"
        );

        // Adding a second profile appends its stubs and still preserves the first.
        write_secret_stub(&env_file, "other", "OTHER").unwrap();
        let after = std::fs::read_to_string(&env_file).unwrap();
        assert!(after.contains("GDI_TOOL__PROFILES__DEFAULT__S3__ACCESS_KEY_ID=AKIAFILLED"));
        assert!(after.contains("GDI_TOOL__PROFILES__OTHER__S3__ACCESS_KEY_ID="));
        assert!(after.contains("GDI_TOOL__PROFILES__OTHER__S3__SECRET_ACCESS_KEY="));
    }

    #[cfg(unix)]
    #[test]
    fn secret_stub_creates_file_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let env_file = dir.path().join("secrets.env");
        write_secret_stub(&env_file, "default", "DEFAULT").unwrap();
        let mode = std::fs::metadata(&env_file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "secrets.env must be created 0600");
    }

    #[test]
    #[serial_test::serial(env)]
    fn run_setup_writes_profile_and_pins_recipient() {
        use gdi_node_standalone_core::crypt4gh::{generate_keypair, serialize_public_key};
        // Stub a node: GET /.well-known/c4gh-recipient → PEM; GET /fairdp → catalogs TTL.
        let (_sk, pk) = generate_keypair();
        let pem = serialize_public_key(&pk);
        let base = stub_node(&pem); // helper below; serves recipient + FDP root

        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");
        // Scripted answers, in ask order: profile name, service_url, management URL,
        // [trust recipient?], [sync catalogs?], [configure S3?], country code, org.
        let p = ScriptedPrompter::new()
            .with_inputs(vec!["default", &base, "", "EE", "UTARTU"])
            .with_confirms(vec![
                true,  /*trust recipient*/
                true,  /*sync catalogs*/
                false, /*S3?*/
            ])
            .with_selects(vec![0]); // header policy: 0 = minimal

        // GDI_CONFIG_DIR so keypair + recipient pin land in the temp dir.
        let _prev = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path());

        let written = run_setup(&p, Some(&cfg_path), None, None, true)
            .unwrap()
            .config_path;
        assert_eq!(written, cfg_path);
        let cfg = ToolConfig::load(Some(&cfg_path)).unwrap();
        let prof = &cfg.profiles["default"];
        assert_eq!(prof.service_url.as_deref(), Some(base.as_str()));
        assert!(prof.node_recipient_file.is_some(), "recipient pinned");
        assert!(!prof.catalogs.is_empty(), "catalogs synced");
        assert_eq!(cfg.country_code.as_deref(), Some("EE"));
    }

    /// The header policy is a per-deployment decision, so setup asks once and records it
    /// on the profile; `build`/`package` then apply it whenever no flag is given.
    #[test]
    #[serial_test::serial(env)]
    fn run_setup_records_the_chosen_header_policy() {
        use gdi_node_standalone_core::config::ProfileHeaderPolicy;
        use gdi_node_standalone_core::crypt4gh::{generate_keypair, serialize_public_key};
        let (_sk, pk) = generate_keypair();
        let pem = serialize_public_key(&pk);
        let base = stub_node(&pem);

        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");
        let p = ScriptedPrompter::new()
            .with_inputs(vec!["default", &base, "", "EE", "UTARTU"])
            .with_confirms(vec![
                true,  /*trust recipient*/
                false, /*sync catalogs*/
                false, /*S3?*/
            ])
            .with_selects(vec![1]); // header policy: 1 = with-identifiers
        let _prev = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path());

        run_setup(&p, Some(&cfg_path), None, None, true).unwrap();
        let cfg = ToolConfig::load(Some(&cfg_path)).unwrap();
        assert_eq!(
            cfg.profiles["default"].header_policy,
            Some(ProfileHeaderPolicy::WithIdentifiers)
        );
    }

    /// Re-running setup on a profile that already chose `with-identifiers` must offer
    /// that as the default, not the built-in `minimal`: the advertised re-entry for key
    /// rotation would otherwise silently narrow a deliberate choice.
    #[test]
    fn header_policy_prompt_defaults_to_the_existing_profile_value() {
        use gdi_node_standalone_core::config::ProfileHeaderPolicy;
        assert_eq!(
            HEADER_POLICY_CHOICES[0],
            ProfileHeaderPolicy::Minimal,
            "minimal is the first choice, so it is also the default for a fresh profile"
        );
        assert_eq!(header_policy_default_index(None), 0);
        for (i, policy) in HEADER_POLICY_CHOICES.iter().enumerate() {
            assert_eq!(header_policy_default_index(Some(*policy)), i, "{policy:?}");
        }
    }

    /// Configuring S3 must record the node's channel for the bucket.
    ///
    /// The cross-channel mismatch warning is the only thing that tells an operator a
    /// lifecycle write went to the wrong bucket, and it can only fire when the profile
    /// declares `channel`. The config template comments the key out, so without this
    /// prompt a wrong-bucket publish is a silent no-op reported as success.
    #[test]
    #[serial_test::serial(env)]
    fn run_setup_records_the_s3_channel() {
        use gdi_node_standalone_core::crypt4gh::{generate_keypair, serialize_public_key};
        let (_sk, pk) = generate_keypair();
        let pem = serialize_public_key(&pk);
        let base = stub_node(&pem);

        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");
        // Ask order: profile name, service_url, management URL, bucket, endpoint, region,
        // key prefix, channel, country code, org.
        let p = ScriptedPrompter::new()
            .with_inputs(vec![
                "default",
                &base,
                "", // management URL: none
                "gdi-bucket",
                "https://s3.example.org",
                "us-east-1", // region: a first run offers no default
                "",          // key prefix: blank = whole bucket
                "primary",   // channel: the node's [[s3.buckets]].name
                "EE",
                "UTARTU",
            ])
            .with_confirms(vec![
                true, /*trust*/
                true, /*catalogs*/
                true, /*S3?*/
                true, /*path-style addressing*/
            ])
            .with_secrets(vec![""]) // access key id: blank -> credentials skipped, stub written
            .with_selects(vec![0]); // header policy: 0 = minimal

        let _prev = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path());

        run_setup(&p, Some(&cfg_path), None, None, true).unwrap();
        let cfg = ToolConfig::load(Some(&cfg_path)).unwrap();
        let s3 = cfg.profiles["default"].s3.as_ref().expect("s3 configured");
        assert_eq!(
            s3.channel.as_deref(),
            Some("primary"),
            "without a channel the wrong-bucket guard cannot fire"
        );
        // The wizard makes the endpoint mandatory, so `ProfileS3::default()`'s
        // virtual-hosted `path_style = false` would write a profile that looks complete
        // and then fails at the wizard's own Publish stage against a Ceph/MinIO/Garage
        // endpoint. Both fields are derived, not defaulted.
        assert!(
            s3.path_style,
            "a custom endpoint defaults to path-style addressing"
        );
        assert!(
            !s3.allow_http,
            "an https:// endpoint must not enable plaintext http"
        );
    }

    /// Re-running setup and accepting the S3 step must not delete `prefix` or `region`:
    /// both prompts default to the profile's current value, so Enter keeps them. A
    /// `ProfileS3` rebuilt from scratch would drop both from tool.toml, after which the tool
    /// addresses the bucket root while the node stays confined to its prefix, and `delete`
    /// reports success on a package that survives under it. The prompted fields still win.
    #[test]
    #[serial_test::serial(env)]
    fn re_running_setup_with_s3_accepted_keeps_the_prefix_and_region() {
        use gdi_node_standalone_core::crypt4gh::{generate_keypair, serialize_public_key};
        let (_sk, pk) = generate_keypair();
        let pem = serialize_public_key(&pk);
        let base = stub_node(&pem);

        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");
        let existing = ToolConfig {
            profiles: std::collections::BTreeMap::from([(
                "default".into(),
                Profile {
                    s3: Some(ProfileS3 {
                        bucket: Some("old-bucket".into()),
                        prefix: "gdi-node-storage/".into(),
                        region: Some("eu-central-1".into()),
                        ..ProfileS3::default()
                    }),
                    ..Profile::default()
                },
            )]),
            ..ToolConfig::default()
        };
        gdi_node_standalone_core::config::write(&existing, &cfg_path).unwrap();

        // Ask order: profile name, service_url, management URL, bucket, endpoint, region,
        // key prefix, channel, country code, org.
        let p = ScriptedPrompter::new()
            .with_inputs(vec![
                "default",
                &base,
                "", // management URL: none
                "new-bucket",
                "https://s3.example.org",
                "",        // region: Enter keeps the existing value (the default)
                "",        // key prefix: Enter keeps the existing value (the default)
                "primary", // channel
                "EE",
                "UTARTU",
            ])
            .with_confirms(vec![
                true,  /*trust*/
                false, /*catalogs*/
                true,  /*S3?*/
                true,  /*path-style addressing*/
            ])
            .with_secrets(vec![""]) // access key id: blank -> credentials skipped
            .with_selects(vec![0]); // header policy: 0 = minimal
        let _prev = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path());

        run_setup(&p, Some(&cfg_path), None, None, true).unwrap();

        let cfg = ToolConfig::load(Some(&cfg_path)).unwrap();
        let s3 = cfg.profiles["default"].s3.as_ref().expect("s3 configured");
        assert_eq!(
            s3.bucket.as_deref(),
            Some("new-bucket"),
            "the prompted bucket wins"
        );
        assert_eq!(
            s3.prefix, "gdi-node-storage/",
            "the prefix prompt defaults to the existing value, so Enter keeps it"
        );
        assert_eq!(
            s3.region.as_deref(),
            Some("eu-central-1"),
            "the region prompt defaults to the existing value, so Enter keeps it"
        );
    }

    /// `--profile <name>` must reach the profile-name prompt.
    ///
    /// Setup fires exactly when `load_active(config_path, profile_name)` fails — i.e.
    /// precisely when the operator named a profile that does not exist yet. With a
    /// hard-coded "default" in the prompt, pressing Enter (having already named the profile
    /// on the command line) would write `[profiles.default]` while Build/Pack/Publish keep
    /// targeting the named one, and the run would abort at Pack with
    /// `unknown profile 'ee_stage'; available: default`.
    #[test]
    #[serial_test::serial(env)]
    fn run_setup_defaults_the_prompt_to_the_requested_profile() {
        use gdi_node_standalone_core::crypt4gh::{generate_keypair, serialize_public_key};
        let (_sk, pk) = generate_keypair();
        let base = stub_node(&serialize_public_key(&pk));

        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");
        // Empty profile answer => the prompt's default is taken. Everything else is the
        // minimal happy path with S3 declined.
        let p = ScriptedPrompter::new()
            .with_inputs(vec!["", &base, "", "EE", "UTARTU"])
            .with_confirms(vec![
                true,  /*trust*/
                true,  /*catalogs*/
                false, /*S3?*/
            ])
            .with_selects(vec![0]); // header policy: 0 = minimal

        let _prev = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path());

        run_setup(&p, Some(&cfg_path), None, Some("ee_stage"), true).unwrap();
        let cfg = ToolConfig::load(Some(&cfg_path)).unwrap();

        assert!(
            cfg.profiles.contains_key("ee_stage"),
            "the profile the rest of the run targets must be the one written; got {:?}",
            cfg.profiles.keys().collect::<Vec<_>>()
        );
    }

    /// A re-run of `run_setup` for a new profile must preserve pre-existing profiles in the
    /// config file rather than clobbering them with a freshly-assembled struct.
    #[test]
    #[serial_test::serial(env)]
    fn run_setup_preserves_existing_profiles() {
        use gdi_node_standalone_core::crypt4gh::{generate_keypair, serialize_public_key};
        // The stored and answered country codes are named once each and asserted distinct.
        // If they were ever the same, the assertion below would pass even when the wizard
        // discards the operator's answer — and this is the only test of the merge-re-run
        // overwrite semantics. A comment cannot fail; `assert_ne!` can.
        const STORED_CC: &str = "EE";
        const ANSWERED_CC: &str = "SE";

        assert_ne!(
            STORED_CC, ANSWERED_CC,
            "the stored and answered country codes must DIFFER, or 'the answer overwrites \
             the stored value' is unfalsifiable"
        );
        let (_sk, pk) = generate_keypair();
        let pem = serialize_public_key(&pk);
        let base = stub_node(&pem);

        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");

        // Pre-populate the config with an existing "other" profile.
        let existing = ToolConfig {
            country_code: Some(STORED_CC.into()),
            default_profile: Some("other".into()),
            profiles: std::collections::BTreeMap::from([(
                "other".into(),
                Profile {
                    service_url: Some("https://other.node".into()),
                    ..Profile::default()
                },
            )]),
            ..ToolConfig::default()
        };
        gdi_node_standalone_core::config::write(&existing, &cfg_path).unwrap();

        let p = ScriptedPrompter::new()
            .with_inputs(vec!["default", &base, "", ANSWERED_CC, "UTARTU"])
            .with_confirms(vec![
                true,  // trust recipient
                true,  // sync catalogs
                false, // S3?
            ])
            .with_selects(vec![0]); // header policy: 0 = minimal
        let _prev = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path());

        run_setup(&p, Some(&cfg_path), None, None, true).unwrap();

        let cfg = ToolConfig::load(Some(&cfg_path)).unwrap();
        // The newly-added profile must be present.
        assert!(cfg.profiles.contains_key("default"), "new profile added");
        // The pre-existing "other" profile must be preserved.
        assert!(
            cfg.profiles.contains_key("other"),
            "pre-existing profile preserved"
        );
        assert_eq!(
            cfg.profiles["other"].service_url.as_deref(),
            Some("https://other.node"),
            "other profile unchanged"
        );
        // The answered country_code overwrites the stored one; default_profile is preserved.
        assert_eq!(
            cfg.country_code.as_deref(),
            Some(ANSWERED_CC),
            "the wizard must write the answered country code over the stored one"
        );
        assert_eq!(cfg.default_profile.as_deref(), Some("other"));
    }

    /// Adding a second profile must never leave the config with no default. A config with
    /// two profiles and no `default_profile` selects nothing: every profile-reading command
    /// fails "no profile selected: pass `--profile` or set `default_profile`", and the
    /// only repair is hand-editing the file. Setup is the one writer that adds a profile,
    /// so it is the one place that can prevent it. It has to prevent it, not merely offer
    /// to.
    #[test]
    #[serial_test::serial(env)]
    fn a_second_profile_always_leaves_a_default_selected() {
        use gdi_node_standalone_core::crypt4gh::{generate_keypair, serialize_public_key};
        let (_sk, pk) = generate_keypair();
        let base = stub_node(&serialize_public_key(&pk));
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");

        // The state an operator reaches by running setup once: one profile, and no
        // `default_profile` key, because a sole profile is selected without one.
        let existing = ToolConfig {
            country_code: Some("EE".into()),
            default_profile: None,
            profiles: std::collections::BTreeMap::from([(
                "first".into(),
                Profile {
                    service_url: Some("https://first.node".into()),
                    ..Profile::default()
                },
            )]),
            ..ToolConfig::default()
        };
        gdi_node_standalone_core::config::write(&existing, &cfg_path).unwrap();

        let p = ScriptedPrompter::new()
            .with_inputs(vec!["second", &base, "", "EE", "UTARTU"])
            .with_confirms(vec![
                true,  // trust recipient
                true,  // sync catalogs
                false, // S3?
            ])
            // header policy, then the default-profile choice: 1 = keep 'first'.
            .with_selects(vec![0, 1]);
        let _prev = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path());

        run_setup(&p, Some(&cfg_path), None, None, true).unwrap();

        let cfg = ToolConfig::load(Some(&cfg_path)).unwrap();
        assert_eq!(cfg.profiles.len(), 2, "both profiles are present");
        assert_eq!(
            cfg.default_profile.as_deref(),
            Some("first"),
            "the chosen profile must be recorded as the default; leaving it unset is the \
             defect this guards"
        );
        // The real subject: the config a later command loads must select something.
        let (name, _) = crate::profile::load_active_named(Some(&cfg_path), None)
            .expect("a config setup wrote must select a profile without --profile");
        assert_eq!(name, "first");
    }

    /// The same prompt, choosing the profile setup just created.
    #[test]
    #[serial_test::serial(env)]
    fn the_new_profile_can_be_made_the_default() {
        use gdi_node_standalone_core::crypt4gh::{generate_keypair, serialize_public_key};
        let (_sk, pk) = generate_keypair();
        let base = stub_node(&serialize_public_key(&pk));
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");
        let existing = ToolConfig {
            country_code: Some("EE".into()),
            default_profile: None,
            profiles: std::collections::BTreeMap::from([(
                "first".into(),
                Profile {
                    service_url: Some("https://first.node".into()),
                    ..Profile::default()
                },
            )]),
            ..ToolConfig::default()
        };
        gdi_node_standalone_core::config::write(&existing, &cfg_path).unwrap();

        let p = ScriptedPrompter::new()
            .with_inputs(vec!["second", &base, "", "EE", "UTARTU"])
            .with_confirms(vec![true, true, false])
            // header policy, then the default-profile choice: 0 = the new 'second'.
            .with_selects(vec![0, 0]);
        let _prev = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path());

        run_setup(&p, Some(&cfg_path), None, None, true).unwrap();

        let cfg = ToolConfig::load(Some(&cfg_path)).unwrap();
        assert_eq!(cfg.default_profile.as_deref(), Some("second"));
        let (name, _) = crate::profile::load_active_named(Some(&cfg_path), None).unwrap();
        assert_eq!(name, "second");
    }

    /// Re-entry must not silently strip the target profile's own settings.
    ///
    /// `wizard setup` is documented as re-entry for credential and key rotation, so
    /// re-running it against an existing profile is a first-class flow. Inserting a
    /// freshly-built `Profile` would reset every field the wizard never asks about.
    /// `management_url` is the expensive one: it is the authoritative dataset-state oracle,
    /// so losing it degrades `status` to the non-authoritative sidecar, disarms the live-id
    /// guard on `deploy`, `publish` and `delete`, and leaves `deploy --wait` polling a plane
    /// that cannot answer, all while the wizard reports success.
    ///
    /// The declined optional steps matter just as much: saying "no" to S3 or to the catalog
    /// sync means "I am not changing that", not "erase it".
    #[test]
    #[serial_test::serial(env)]
    fn re_running_setup_preserves_the_target_profiles_untouched_settings() {
        use gdi_node_standalone_core::crypt4gh::{generate_keypair, serialize_public_key};
        let (_sk, pk) = generate_keypair();
        let pem = serialize_public_key(&pk);
        let base = stub_node(&pem);

        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");

        // An existing `default` profile carrying settings the wizard never prompts for.
        let existing = ToolConfig {
            profiles: std::collections::BTreeMap::from([(
                "default".into(),
                Profile {
                    service_url: Some("https://old.node".into()),
                    management_url: Some("https://mgmt.node:8081".into()),
                    node_recipient_url: Some("https://old.node/.well-known/c4gh-recipient".into()),
                    inbox: Some("/var/lib/gdi/inbox".into()),
                    catalogs: std::collections::BTreeMap::from([(
                        "gdi-aggregated".into(),
                        "GDI Aggregated".into(),
                    )]),
                    s3: Some(ProfileS3 {
                        bucket: Some("keep-me".into()),
                        ..ProfileS3::default()
                    }),
                    ..Profile::default()
                },
            )]),
            ..ToolConfig::default()
        };
        gdi_node_standalone_core::config::write(&existing, &cfg_path).unwrap();

        let p = ScriptedPrompter::new()
            .with_inputs(vec!["default", &base, "", "EE", "UTARTU"])
            .with_confirms(vec![
                true,  // trust the recipient
                false, // DECLINE the catalog sync
                false, // DECLINE S3
            ])
            .with_selects(vec![0]); // header policy: 0 = minimal
        let _prev = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path());

        run_setup(&p, Some(&cfg_path), None, None, true).unwrap();

        let cfg = ToolConfig::load(Some(&cfg_path)).unwrap();
        let prof = &cfg.profiles["default"];
        // Answered: the new service URL wins.
        assert_eq!(prof.service_url.as_deref(), Some(&base[..]));
        // Never asked about: must survive verbatim.
        assert_eq!(
            prof.management_url.as_deref(),
            Some("https://mgmt.node:8081"),
            "management_url is the authoritative state oracle — losing it degrades status, \
             the live-id guard and --wait, all silently"
        );
        assert_eq!(
            prof.node_recipient_url.as_deref(),
            Some("https://old.node/.well-known/c4gh-recipient"),
            "node_recipient_url must survive a re-run"
        );
        assert_eq!(
            prof.inbox.as_deref(),
            Some("/var/lib/gdi/inbox"),
            "a non-keyless re-run must not discard the inbox"
        );
        // Declined steps preserve rather than erase.
        assert!(
            prof.catalogs.contains_key("gdi-aggregated"),
            "declining the catalog sync must not wipe a pinned allow-list"
        );
        assert_eq!(
            prof.s3.as_ref().and_then(|s| s.bucket.as_deref()),
            Some("keep-me"),
            "declining S3 must not discard a configured bucket"
        );
    }

    /// Re-running the wizard over a hand-written config must not damage it: the
    /// operator's comments, their formatting, and any inline S3 credentials all survive.
    ///
    /// `config::write` merges in place and has its own unit coverage, but only from a
    /// generated file. This is the operator-facing composition: the wizard round-trips
    /// through `load_file_only` -> mutate -> `write`, and it replaces the whole `Profile`
    /// it is (re)configuring. So it is the path where a regression in the merge, or a
    /// switch back to whole-file re-serialisation, silently eats an annotated file — and
    /// `[profiles.default.s3]` credentials are `#[serde(skip_serializing)]`, so the same
    /// regression would also strip the secret while leaving the config looking fine.
    #[test]
    #[serial_test::serial(env)]
    fn run_setup_preserves_an_annotated_config_file() {
        use gdi_node_standalone_core::crypt4gh::{generate_keypair, serialize_public_key};
        let (_sk, pk) = generate_keypair();
        let pem = serialize_public_key(&pk);
        let base = stub_node(&pem);

        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");
        // Hand-written, not round-tripped through `write`: the comments and the spacing
        // are the fixture. `archive` is a profile the wizard does not touch; its inline
        // credentials must be here afterwards too.
        std::fs::write(
            &cfg_path,
            r#"# Tartu node — operator notes. Do not reformat.
country_code = "EE"
default_profile = "archive"

[profiles.archive]
service_url = "https://archive.node"     # long-term store, not the wizard's target

[profiles.archive.s3]
bucket = "archive-bucket"
access_key_id = "AKIAARCHIVE"
secret_access_key = "archive-secret-value"
"#,
        )
        .unwrap();

        let p = ScriptedPrompter::new()
            .with_inputs(vec!["default", &base, "", "SE", "UTARTU"])
            .with_confirms(vec![
                true,  // trust recipient
                true,  // sync catalogs
                false, // S3?
            ])
            .with_selects(vec![0]); // header policy: 0 = minimal
        let _prev = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path());

        run_setup(&p, Some(&cfg_path), None, None, true).unwrap();

        let after = std::fs::read_to_string(&cfg_path).unwrap();
        assert!(
            after.contains("# Tartu node — operator notes. Do not reformat."),
            "the leading comment must survive a wizard re-run: {after}"
        );
        assert!(
            after.contains("# long-term store, not the wizard's target"),
            "a trailing comment on an untouched profile must survive: {after}"
        );
        assert!(
            after.contains("archive-secret-value") && after.contains("AKIAARCHIVE"),
            "inline credentials the wizard never asked about must survive: {after}"
        );
        // ...and the wizard's own work still landed.
        let cfg = ToolConfig::load(Some(&cfg_path)).unwrap();
        assert!(cfg.profiles.contains_key("default"), "new profile added");
        assert_eq!(
            cfg.country_code.as_deref(),
            Some("SE"),
            "the answered country code overwrites the annotated file's"
        );
    }

    /// A catalog-sync failure must not be fatal: the node serves the recipient but
    /// its FDP root errors (500). Setup completes; the recipient is still pinned and
    /// the catalogs allow-list is simply left empty.
    #[test]
    #[serial_test::serial(env)]
    fn run_setup_catalog_sync_failure_is_nonfatal() {
        use gdi_node_standalone_core::crypt4gh::{generate_keypair, serialize_public_key};
        let (_sk, pk) = generate_keypair();
        let pem = serialize_public_key(&pk);
        let base = stub_node_recipient_ok_fdp_fails(&pem);

        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");
        let p = ScriptedPrompter::new()
            .with_inputs(vec!["default", &base, "", "EE", "UTARTU"])
            .with_confirms(vec![
                true,  // trust recipient
                true,  // sync catalogs — the fetch will fail; must be non-fatal
                false, // S3?
            ])
            .with_selects(vec![0]); // header policy: 0 = minimal
        let _prev = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path());

        let written = run_setup(&p, Some(&cfg_path), None, None, true)
            .unwrap()
            .config_path;
        assert_eq!(written, cfg_path);
        let cfg = ToolConfig::load(Some(&cfg_path)).unwrap();
        let prof = &cfg.profiles["default"];
        assert!(prof.node_recipient_file.is_some(), "recipient still pinned");
        assert!(
            prof.catalogs.is_empty(),
            "a failed sync must leave catalogs empty, not abort setup"
        );
    }

    /// `--recipient` makes setup fully offline: the recipient is read from the
    /// local file (no fetch, no trust prompt) and the profile records that path. With
    /// catalog sync declined, no network call is made at all — even though
    /// `service_url` points at an unreachable address.
    #[test]
    #[serial_test::serial(env)]
    fn run_setup_uses_local_recipient_file_without_network() {
        use gdi_node_standalone_core::crypt4gh::{generate_keypair, serialize_public_key};
        let (_sk, pk) = generate_keypair();
        let pem = serialize_public_key(&pk);
        let dir = tempfile::tempdir().unwrap();
        let rf = dir.path().join("node.pub");
        std::fs::write(&rf, &pem).unwrap();
        let cfg_path = dir.path().join("config.toml");

        // No "Trust this recipient?" prompt when a file is supplied; only sync + S3.
        let p = ScriptedPrompter::new()
            .with_inputs(vec!["default", "http://127.0.0.1:1", "", "EE", "UTARTU"])
            .with_confirms(vec![
                false, // sync catalogs?
                false, // S3?
            ])
            .with_selects(vec![0]); // header policy: 0 = minimal
        let _prev = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path());

        let written = run_setup(&p, Some(&cfg_path), Some(&rf), None, true)
            .unwrap()
            .config_path;
        assert_eq!(written, cfg_path);
        let cfg = ToolConfig::load(Some(&cfg_path)).unwrap();
        let prof = &cfg.profiles["default"];
        let recorded = prof
            .node_recipient_file
            .as_deref()
            .expect("recipient set from the local file");
        // The profile points at a copy inside the config dir, not at wherever the operator
        // was pointing: that file arrives on a USB stick or in /tmp on the air-gapped path,
        // and recording its original location made `pack` fail at the very end of a run
        // once it moved. What matters is that the copy is the key that was handed over.
        assert_eq!(
            std::path::Path::new(recorded),
            dir.path().join("recipients").join("default.pub"),
            "the recipient must be pinned into the config dir; got: {recorded}"
        );
        assert_eq!(
            std::fs::read(recorded).unwrap(),
            std::fs::read(&rf).unwrap(),
            "the pinned copy must be byte-identical to the file handed over"
        );
        assert!(prof.catalogs.is_empty());
    }

    /// Write a valid recipient PEM to `dir/node.pub` and return its path.
    fn write_recipient_pem(dir: &Path) -> PathBuf {
        use gdi_node_standalone_core::crypt4gh::{generate_keypair, serialize_public_key};
        let (_sk, pk) = generate_keypair();
        let rf = dir.join("node.pub");
        std::fs::write(&rf, serialize_public_key(&pk)).unwrap();
        rf
    }

    /// An address with nothing listening: the recipient fetch fails, which is exactly the
    /// greenfield first-bring-up case (the node does not exist yet).
    const UNREACHABLE: &str = "http://127.0.0.1:1";

    /// A keyless profile is never asked about S3, and never gets an `[s3]` block.
    ///
    /// The S3 channel carries packages and a keyless node produces none — the Publish stage
    /// offers only the inbox drop — so the question would write a block into tool.toml that
    /// nothing can use, two prompts after the keyless warning that says "never use it for
    /// an S3 bucket". The prompter is queued with no S3 confirm on purpose: if the question
    /// comes back, it runs dry and this test fails rather than silently passing.
    #[test]
    #[serial_test::serial(env)]
    fn a_keyless_profile_is_not_asked_about_s3() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");
        let p = ScriptedPrompter::new()
            .with_inputs(vec![
                "default",
                "",                                   // service URL: none
                "",                                   // management URL: none
                "/var/lib/gdi-node-standalone/inbox", // the keyless inbox
                "",                                   // catalogs: blank
                "EE",
                "UTARTU",
            ])
            .with_selects(vec![
                1, // recovery menu with no URL: [file, KEYLESS, abort] -> keyless
                0, // header policy
            ])
            // No S3 confirm queued — asking would run the prompter dry.
            .with_confirms(vec![]);
        let _prev = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path());
        run_setup(&p, Some(&cfg_path), None, None, true).unwrap();

        let cfg = ToolConfig::load(Some(&cfg_path)).unwrap();
        let prof = &cfg.profiles["default"];
        assert!(prof.keyless, "the keyless choice must be recorded");
        assert!(
            prof.s3.is_none(),
            "a keyless profile must carry no [s3] block: {:?}",
            prof.s3
        );
        assert!(
            prof.inbox.is_some(),
            "the inbox is what feeds a keyless node"
        );
    }

    /// With no recipient URL there is nothing to retry and nothing for `keys
    /// pin-recipient` to pin from, so neither row may be offered. Offering "pin it later"
    /// there leaves a profile whose own advertised remedy answers "no recipient source".
    #[test]
    fn the_no_url_recipient_menu_omits_the_rows_that_need_a_url() {
        // Rows without a URL: file, keyless, abort. Pick the last.
        let dir = tempfile::tempdir().unwrap();
        let p = ScriptedPrompter::new().with_selects(vec![2]);
        let err = recipient_recovery_menu(&p, false, dir.path(), "default").unwrap_err();
        assert!(err.message.contains("setup aborted"), "{}", err.message);
        let seen = p.seen_prompts();
        assert!(
            seen.iter().any(|l| l.contains("KEYLESS")),
            "the keyless row needs no URL and must stay: {seen:?}"
        );
        assert!(
            !seen.iter().any(|l| l.contains("pin it later")),
            "nothing to pin from: {seen:?}"
        );
        assert!(
            !seen.iter().any(|l| l.contains("Retry the fetch")),
            "nothing to retry: {seen:?}"
        );
    }

    /// …and with a URL both rows are on offer, so the two are driven by the one flag.
    #[test]
    fn the_url_recipient_menu_offers_retry_and_defer() {
        // Rows with a URL: file, retry, keyless, defer, abort. Pick abort.
        let dir = tempfile::tempdir().unwrap();
        let p = ScriptedPrompter::new().with_selects(vec![4]);
        recipient_recovery_menu(&p, true, dir.path(), "default").unwrap_err();
        let seen = p.seen_prompts();
        assert!(
            seen.iter().any(|l| l.contains("Retry the fetch")),
            "{seen:?}"
        );
        assert!(seen.iter().any(|l| l.contains("pin it later")), "{seen:?}");
    }

    /// A blank recipient-file path returns to the menu. That row is pre-selected, so a
    /// provider with no file reaches it by pressing Enter, and a validator that rejected
    /// blank would re-prompt forever, with Ctrl-C (which discards the run) the only exit.
    #[test]
    fn a_blank_recipient_path_returns_to_the_menu() {
        let p = ScriptedPrompter::new()
            // menu: file → blank path → menu again: abort
            .with_selects(vec![0, 2])
            .with_inputs(vec![""]);
        let dir = tempfile::tempdir().unwrap();
        let err = recipient_recovery_menu(&p, false, dir.path(), "default").unwrap_err();
        assert!(err.message.contains("setup aborted"), "{}", err.message);
        assert_eq!(
            p.seen_prompts()
                .iter()
                .filter(|l| l.starts_with("No node recipient"))
                .count(),
            2,
            "the menu must be re-offered, not re-prompted for a path"
        );
    }

    /// `wizard setup` is the advertised re-entry for rotation, so it runs against configs
    /// that already have a profile. Offering "default" as the name there would make the
    /// obvious answer — Enter — write a second profile beside the real one, leaving the
    /// config with two profiles, no `default_profile`, and every command failing "no
    /// profile selected" until someone hand-edits tool.toml.
    #[test]
    #[serial_test::serial(env)]
    fn setup_re_entry_defaults_to_the_profile_that_is_already_active() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");
        let existing = ToolConfig {
            country_code: Some("EE".into()),
            profiles: [(
                "s3node".to_owned(),
                Profile {
                    service_url: Some(UNREACHABLE.into()),
                    ..Profile::default()
                },
            )]
            .into_iter()
            .collect(),
            ..ToolConfig::default()
        };
        gdi_node_standalone_core::config::write(&existing, &cfg_path).unwrap();

        let p = ScriptedPrompter::new()
            // name → enter (empty ⇒ the offered default), then service/management URL,
            // country, org.
            .with_inputs(vec!["", UNREACHABLE, "", "EE", "UTARTU"])
            .with_selects(vec![3, 0]) // recipient menu: defer; header policy
            // The third confirm is spare on purpose. With the fix there is one profile and
            // it is never asked; with the bug a second profile appears and the
            // "make it the default?" question fires — and without a queued answer the
            // prompter runs dry, so the test would fail on the harness and its assertions
            // would never run. Declining leaves the forked config intact for them to catch.
            .with_confirms(vec![
                false, /*sync catalogs*/
                false, /*S3?*/
                false, /*spare: see above*/
            ]);
        let _prev = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path());
        run_setup(&p, Some(&cfg_path), None, None, true).unwrap();

        let cfg = ToolConfig::load(Some(&cfg_path)).unwrap();
        assert!(
            cfg.profiles.contains_key("s3node"),
            "the active profile must be the one edited: {:?}",
            cfg.profiles.keys().collect::<Vec<_>>()
        );
        assert!(
            !cfg.profiles.contains_key("default"),
            "Enter must not fork the config into a second profile: {:?}",
            cfg.profiles.keys().collect::<Vec<_>>()
        );
    }

    /// A config with several profiles and no `default_profile` selects nothing — every
    /// command fails "no profile selected". Setup is the one writer that adds a profile, so
    /// it names the default rather than leaving the config unusable. This covers the arm
    /// that picks the profile just written; `a_second_profile_always_leaves_a_default_selected`
    /// covers picking the other one, which is the arm the old yes/no prompt got wrong.
    #[test]
    #[serial_test::serial(env)]
    fn setup_names_a_default_profile_when_it_would_leave_the_config_ambiguous() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");
        let existing = ToolConfig {
            country_code: Some("EE".into()),
            profiles: [(
                "staging".to_owned(),
                Profile {
                    service_url: Some(UNREACHABLE.into()),
                    ..Profile::default()
                },
            )]
            .into_iter()
            .collect(),
            ..ToolConfig::default()
        };
        gdi_node_standalone_core::config::write(&existing, &cfg_path).unwrap();

        let p = ScriptedPrompter::new()
            .with_inputs(vec!["prod", UNREACHABLE, "", "EE", "UTARTU"])
            // recovery menu, header policy, then the default-profile choice: 0 = 'prod',
            // the profile this run just wrote.
            .with_selects(vec![3, 0, 0])
            .with_confirms(vec![false /*sync catalogs*/, false /*S3?*/]);
        let _prev = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path());
        run_setup(&p, Some(&cfg_path), None, None, true).unwrap();

        let cfg = ToolConfig::load(Some(&cfg_path)).unwrap();
        assert_eq!(cfg.profiles.len(), 2);
        assert_eq!(
            cfg.default_profile.as_deref(),
            Some("prod"),
            "two profiles and no default is a config no command can use"
        );
    }

    /// An unreachable node must not abort setup on a first bring-up. The recovery menu
    /// offers a local recipient file, and choosing it completes setup offline.
    #[test]
    #[serial_test::serial(env)]
    fn unreachable_node_offers_local_recipient_file_instead_of_aborting() {
        let dir = tempfile::tempdir().unwrap();
        let rf = write_recipient_pem(dir.path());
        let cfg_path = dir.path().join("config.toml");

        let p = ScriptedPrompter::new()
            .with_inputs(vec![
                "default",
                UNREACHABLE,
                "",                   // management URL: none
                rf.to_str().unwrap(), // path to the node's recipient file
                "EE",
                "UTARTU",
            ])
            .with_selects(vec![0, 0]) // menu: use a local recipient file
            .with_confirms(vec![false /*sync catalogs*/, false /*S3?*/]);

        let _prev = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path());

        let written = run_setup(&p, Some(&cfg_path), None, None, true)
            .unwrap()
            .config_path;
        let cfg = ToolConfig::load(Some(&written)).unwrap();
        let prof = &cfg.profiles["default"];
        let recorded = prof
            .node_recipient_file
            .as_deref()
            .expect("the recipient chosen from the menu must be recorded");
        assert!(
            recorded.ends_with("recipients/default.pub"),
            "the menu's recipient must be pinned into the config dir; got {recorded}"
        );
    }

    /// Deferring: the operator may finish setup with no recipient at all. `service_url` is
    /// still recorded, so `pack` re-derives the recipient URL once the node is up.
    #[test]
    #[serial_test::serial(env)]
    fn unreachable_node_can_defer_the_recipient_and_still_write_the_profile() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");

        let p = ScriptedPrompter::new()
            .with_inputs(vec!["default", UNREACHABLE, "", "EE", "UTARTU"])
            .with_selects(vec![3, 0]) // menu: continue without a recipient
            .with_confirms(vec![false /*sync catalogs*/, false /*S3?*/]);

        let _prev = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path());

        let written = run_setup(&p, Some(&cfg_path), None, None, true)
            .unwrap()
            .config_path;
        let cfg = ToolConfig::load(Some(&written)).unwrap();
        let prof = &cfg.profiles["default"];
        assert!(
            prof.node_recipient_file.is_none(),
            "deferring must leave the recipient unpinned"
        );
        assert_eq!(
            prof.service_url.as_deref(),
            Some(UNREACHABLE),
            "service_url is still recorded, so pack can fetch the recipient later"
        );
        // …and because it can fetch later, the profile is complete. Calling it incomplete
        // would lock the operator out: every subsequent `wizard` run would restart at Setup
        // and never reach Author, on the branch offered precisely for a node that is not up
        // yet.
        assert!(
            profile_complete(prof),
            "a deferred profile can still fetch at pack time; re-running setup forever is \
             not a recovery path"
        );
    }

    /// A bad recipient path must re-offer the menu, not strand the operator in a
    /// half-finished setup.
    #[test]
    #[serial_test::serial(env)]
    fn bad_recipient_path_re_offers_the_menu() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");
        let missing = dir.path().join("does-not-exist.pub");

        let p = ScriptedPrompter::new()
            .with_inputs(vec![
                "default",
                UNREACHABLE,
                "",                        // management URL: none
                missing.to_str().unwrap(), // first attempt: bad path
                "EE",
                "UTARTU",
            ])
            // menu twice: (0) local file -> bad path -> menu again -> (3) defer
            .with_selects(vec![0, 3, 0])
            .with_confirms(vec![false /*sync catalogs*/, false /*S3?*/]);

        let _prev = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path());

        let written = run_setup(&p, Some(&cfg_path), None, None, true)
            .unwrap()
            .config_path;
        let cfg = ToolConfig::load(Some(&written)).unwrap();
        assert!(
            cfg.profiles["default"].node_recipient_file.is_none(),
            "after the bad path the operator deferred; no recipient is pinned"
        );
    }

    /// Keyless: a co-located node with no crypt4gh identity needs no recipient at all.
    /// Setup records `keyless` + the inbox, so the wizard can skip `pack` and deploy the
    /// plaintext staging dir instead.
    #[test]
    #[serial_test::serial(env)]
    fn keyless_node_records_the_inbox_and_needs_no_recipient() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");

        let p = ScriptedPrompter::new()
            .with_inputs(vec![
                "default",
                UNREACHABLE,
                "",                                   // management URL: none
                "/var/lib/gdi-node-standalone/inbox", // the inbox prompt the keyless branch adds
                "EE",
                "UTARTU",
            ])
            .with_selects(vec![2, 0]) // menu: this node is KEYLESS
            .with_confirms(vec![false /*sync catalogs*/, false /*S3?*/]);

        let _prev = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path());

        let written = run_setup(&p, Some(&cfg_path), None, None, true)
            .unwrap()
            .config_path;
        let cfg = ToolConfig::load(Some(&written)).unwrap();
        let prof = &cfg.profiles["default"];

        assert!(prof.keyless, "the keyless choice must be recorded");
        assert!(
            prof.node_recipient_file.is_none(),
            "a keyless node has no recipient to pin"
        );
        assert_eq!(
            prof.inbox.as_deref(),
            Some("/var/lib/gdi-node-standalone/inbox"),
            "the inbox is the keyless deploy target and must be captured"
        );
    }

    /// Aborting stays available and is still an error exit.
    #[test]
    #[serial_test::serial(env)]
    fn unreachable_node_abort_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");

        let p = ScriptedPrompter::new()
            .with_inputs(vec!["default", UNREACHABLE, ""])
            .with_selects(vec![4]); // menu: abort

        let _prev = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path());

        let err = run_setup(&p, Some(&cfg_path), None, None, true)
            .expect_err("aborting the recipient step must fail setup");
        assert!(
            err.message.contains("--recipient"),
            "the abort must name the offline escape hatch; got: {}",
            err.message
        );
        assert!(
            !cfg_path.exists(),
            "an aborted setup must not write a partial config"
        );
    }

    /// A loopback node that serves the recipient PEM on the c4gh-recipient path but
    /// returns HTTP 500 for the FDP root (`/fairdp`), so catalog sync fails.
    fn stub_node_recipient_ok_fdp_fails(pem: &str) -> String {
        use std::io::Write as _;
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let pem = pem.to_owned();
        std::thread::spawn(move || {
            for _ in 0..4 {
                if let Ok((mut s, _)) = listener.accept() {
                    let mut buf = [0u8; 2048];
                    let n = std::io::Read::read(&mut s, &mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let (status, body) = if req.contains("c4gh-recipient") {
                        ("200 OK", pem.clone())
                    } else {
                        ("500 Internal Server Error", "boom".to_owned())
                    };
                    let resp = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(resp.as_bytes());
                    let _ = s.flush();
                }
            }
        });
        format!("http://{addr}")
    }

    /// One-shot loopback server: replies to the recipient path with `pem`, and to
    /// any other path with a two-catalog FDP-root Turtle.
    fn stub_node(pem: &str) -> String {
        use std::io::Write as _;
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let pem = pem.to_owned();
        std::thread::spawn(move || {
            for _ in 0..4 {
                if let Ok((mut s, _)) = listener.accept() {
                    let mut buf = [0u8; 2048];
                    let n = std::io::Read::read(&mut s, &mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let body = if req.contains("c4gh-recipient") {
                        pem.clone()
                    } else {
                        "@prefix fdp-o: <https://w3id.org/fdp/fdp-o#> .\n\
                         @prefix ldp: <http://www.w3.org/ns/ldp#> .\n\
                         <x> a fdp-o:FAIRDataPoint ; ldp:contains \
                         <https://n/fairdp/catalog/gdi-aggregated> .\n"
                            .to_owned()
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(resp.as_bytes());
                    let _ = s.flush();
                }
            }
        });
        format!("http://{addr}")
    }

    /// Typed S3 credentials land in `secrets.env` (owner-only, single-quoted for `source`),
    /// never in the config file, and come back in the outcome for this run's Publish stage.
    #[test]
    #[serial_test::serial(env)]
    fn typed_s3_credentials_are_stored_owner_only_and_carried() {
        use gdi_node_standalone_core::crypt4gh::{generate_keypair, serialize_public_key};
        let (_sk, pk) = generate_keypair();
        let base = stub_node(&serialize_public_key(&pk));
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");
        let p = ScriptedPrompter::new()
            .with_inputs(vec![
                "default",
                &base,
                "", // management URL: none
                "gdi-bucket",
                "https://s3.example.org",
                "us-east-1", // region: a first run offers no default
                "",          // key prefix: blank = whole bucket
                "primary",   // channel: the node's [[s3.buckets]].name
                "EE",
                "UTARTU",
            ])
            .with_confirms(vec![
                true, /*trust*/
                true, /*catalogs*/
                true, /*S3?*/
                true, /*path-style*/
            ])
            .with_secrets(vec!["AKIAEXAMPLE", "it's/a+secret="])
            .with_selects(vec![0]); // header policy
        let _prev = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path());

        let outcome = run_setup(&p, Some(&cfg_path), None, None, true).unwrap();
        let carried = outcome
            .s3_credentials
            .expect("typed credentials are carried in the outcome");
        assert_eq!(carried.access_key_id, "AKIAEXAMPLE");
        assert_eq!(carried.secret_access_key, "it's/a+secret=");

        let env_file = dir.path().join("secrets.env");
        let text = std::fs::read_to_string(&env_file).unwrap();
        assert!(
            text.contains("GDI_TOOL__PROFILES__DEFAULT__S3__ACCESS_KEY_ID='AKIAEXAMPLE'"),
            "{text}"
        );
        assert!(
            text.contains(
                "GDI_TOOL__PROFILES__DEFAULT__S3__SECRET_ACCESS_KEY='it'\\''s/a+secret='"
            ),
            "the secret is single-quoted for `source`, with its own quote escaped: {text}"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&env_file).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "secrets.env must be owner-only");
        }
        let cfg_text = std::fs::read_to_string(&cfg_path).unwrap();
        assert!(
            !cfg_text.contains("AKIAEXAMPLE") && !cfg_text.contains("secret="),
            "the config file never carries a credential: {cfg_text}"
        );
        let cfg = ToolConfig::load(Some(&cfg_path)).unwrap();
        assert_eq!(cfg.profiles["default"].org.as_deref(), Some("UTARTU"));
    }

    #[test]
    fn secret_values_replace_this_profiles_lines_and_keep_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let env_file = dir.path().join("secrets.env");
        write_secret_stub(&env_file, "other", "OTHER").unwrap();
        let first = S3Credentials {
            access_key_id: "A1".into(),
            secret_access_key: "S1".into(),
        };
        write_secret_values(&env_file, "default", "DEFAULT", &first).unwrap();
        let rotated = S3Credentials {
            access_key_id: "A2".into(),
            secret_access_key: "S2".into(),
        };
        write_secret_values(&env_file, "default", "DEFAULT", &rotated).unwrap();
        let text = std::fs::read_to_string(&env_file).unwrap();
        assert!(
            text.contains("GDI_TOOL__PROFILES__OTHER__S3__ACCESS_KEY_ID="),
            "the other profile's stub is kept: {text}"
        );
        assert!(
            !text.contains("'A1'"),
            "an earlier value is replaced, not kept beside the new one: {text}"
        );
        assert_eq!(
            text.matches("GDI_TOOL__PROFILES__DEFAULT__S3__ACCESS_KEY_ID=")
                .count(),
            1,
            "{text}"
        );
        assert!(text.contains("GDI_TOOL__PROFILES__DEFAULT__S3__ACCESS_KEY_ID='A2'"));
        assert!(text.contains("GDI_TOOL__PROFILES__DEFAULT__S3__SECRET_ACCESS_KEY='S2'"));
    }

    #[test]
    fn shell_single_quote_escapes_only_the_quote() {
        assert_eq!(shell_single_quote("abc+/="), "'abc+/='");
        assert_eq!(shell_single_quote("it's"), "'it'\\''s'");
    }

    /// The management URL and the org are recorded, and a re-run that presses Enter keeps
    /// both — a blank answer means "as before", not "erase".
    #[test]
    #[serial_test::serial(env)]
    fn a_management_url_and_an_org_are_recorded_and_kept_on_a_re_run() {
        use gdi_node_standalone_core::crypt4gh::{generate_keypair, serialize_public_key};
        let (_sk, pk) = generate_keypair();
        let base = stub_node(&serialize_public_key(&pk));
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");
        let _prev = test_util::EnvGuard::set("GDI_CONFIG_DIR", dir.path());

        let p = ScriptedPrompter::new()
            .with_inputs(vec![
                "default",
                &base,
                "http://127.0.0.1:9090",
                "EE",
                "UTARTU",
            ])
            .with_confirms(vec![true, false, false])
            .with_selects(vec![0]);
        run_setup(&p, Some(&cfg_path), None, None, true).unwrap();
        let cfg = ToolConfig::load(Some(&cfg_path)).unwrap();
        assert_eq!(
            cfg.profiles["default"].management_url.as_deref(),
            Some("http://127.0.0.1:9090")
        );
        assert_eq!(cfg.profiles["default"].org.as_deref(), Some("UTARTU"));

        // Re-run: Enter through both prompts.
        let p = ScriptedPrompter::new()
            .with_inputs(vec!["default", &base, "", "EE", ""])
            .with_confirms(vec![true, false, false])
            .with_selects(vec![0]);
        run_setup(&p, Some(&cfg_path), None, None, true).unwrap();
        let cfg = ToolConfig::load(Some(&cfg_path)).unwrap();
        assert_eq!(
            cfg.profiles["default"].management_url.as_deref(),
            Some("http://127.0.0.1:9090"),
            "a blank re-run answer keeps the recorded management URL"
        );
        assert_eq!(
            cfg.profiles["default"].org.as_deref(),
            Some("UTARTU"),
            "a blank re-run answer keeps the recorded org"
        );
    }

    #[test]
    fn store_profile_org_writes_only_the_org() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("tool.toml");
        std::fs::write(
            &cfg_path,
            "country_code = \"EE\"\n\n[profiles.default]\nservice_url = \"https://node\"\n",
        )
        .unwrap();
        let written = store_profile_org(Some(&cfg_path), None, "UTARTU").unwrap();
        assert_eq!(written, cfg_path);
        let cfg = ToolConfig::load(Some(&cfg_path)).unwrap();
        assert_eq!(cfg.profiles["default"].org.as_deref(), Some("UTARTU"));
        assert_eq!(
            cfg.profiles["default"].service_url.as_deref(),
            Some("https://node"),
            "the other keys survive"
        );
        assert_eq!(cfg.country_code.as_deref(), Some("EE"));
    }
}
