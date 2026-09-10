//! The `doctor` one-shot subcommand: a read-only pre-flight posture report.
//!
//! `check-config` validates config shape and `verify` scrubs the store. `doctor` reports
//! the posture: it consolidates the config-preflight result with the security- and
//! operability-relevant state an operator confirms before going live, covering key
//! material, the k-anonymity floor, the writer-key policy, which subsystems are configured,
//! and a snapshot of the persisted registry.
//!
//! It is read-only and makes no network calls; runtime reachability of Vault and S3 is the
//! job of `/health/ready`. It reports what is knowable from the config and the on-disk
//! status index. It exits non-zero when any check reports FAIL, meaning a config that fails
//! preflight or, with `require_override_store` set, an absent override store, and under
//! `--strict` when any check reports WARN.

use anyhow::Result;

use crate::list_datasets::OutputFormat;
use gdi_node_standalone_core::cache::StatusIndex;
use gdi_node_standalone_core::config::{ServiceConfig, WriterPolicy};
use gdi_node_standalone_core::state::DatasetState;

/// The severity of one reported check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Level {
    Ok,
    Warn,
    Fail,
}

impl Level {
    const fn tag(self) -> &'static str {
        match self {
            Self::Ok => "OK  ",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }

    /// The lowercase level name for `--format json`.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

/// Run the posture report. Prints a human table (`OutputFormat::Text`) or a machine-readable
/// document (`OutputFormat::Json`).
///
/// # Errors
///
/// Returns an error, and so a non-zero exit, if any check is `FAIL`, or with `strict` if any
/// check is `WARN`. That lets a deployment gate veto a risky posture such as k-anon off,
/// keyless, or writer-policy off, which is otherwise only advisory.
pub fn run(config: &ServiceConfig, format: OutputFormat, strict: bool) -> Result<()> {
    let mut lines: Vec<(Level, String)> = Vec::new();

    // 1. Config preflight, the one hard gate. `preflight::run_with` is the composite check
    // the boot path, `check-config` and the SIGHUP reload use, and it adds the
    // feature-profile checks `config.preflight()` leaves out. `doctor` runs inside the same
    // binary, so it sees exactly what the boot path would reject: a `lite`-profile binary
    // carrying `[[s3.buckets]]`, or `[vault]` on a no-vault build, fails here.
    //
    // Advisories are suppressed: they are boot-posture warnings, and `doctor` renders its
    // own findings as `Level` lines rather than through `tracing`.
    match crate::preflight::run_with(config, false) {
        Ok(()) => lines.push((Level::Ok, "config: passes startup preflight".to_owned())),
        Err(e) => lines.push((Level::Fail, format!("config: preflight failed: {e}"))),
    }

    // 2. Key material posture.
    let identity_count = config.keys.identities.len();
    if config.has_vault() {
        lines.push((
            Level::Ok,
            "keys: Vault-sourced identity; encrypted .tar.c4gh ingest works while Vault is reachable".to_owned(),
        ));
    } else if identity_count > 0 {
        doctor_identity_files(config, &mut lines);
    } else {
        lines.push((
            Level::Warn,
            "keys: keyless; only plaintext staging-dir ingest works and encrypted .tar.c4gh packages are rejected".to_owned(),
        ));
    }

    // 3. k-anonymity floor posture, the disclosure-control decision.
    doctor_k_anon(config, &mut lines);

    // 4. Writer-key policy posture.
    doctor_writer_policy(config, &mut lines);
    doctor_public_cors(config, &mut lines);
    doctor_override_store(config, &mut lines);

    // 5. Configured subsystems (presence, not reachability).
    let buckets = config.s3.as_ref().map_or(0, |s3| s3.buckets.len());
    let inbox = if config.service.inbox.is_some() {
        "inbox: on"
    } else {
        "inbox: off"
    };
    lines.push((
        Level::Ok,
        format!(
            "subsystems: {inbox}, s3 buckets: {buckets}, vault: {}, fairdp: {}",
            yes_no(config.has_vault()),
            yes_no(config.fairdp.is_some()),
        ),
    ));
    // One line per channel naming the keyspace it addresses, in the `bucket/prefix` shape
    // `check-config` and `gdi-dataset-tool`'s target label use. The prefix decides which
    // objects a channel can see, and a prefix set on one side only presents as "the bucket
    // is empty", so both sides print it the same way and can be compared by eye.
    for bucket in config.s3.as_ref().map_or(&[][..], |s3| &s3.buckets) {
        let target = match (bucket.bucket.as_deref(), bucket.prefix.as_str()) {
            (Some(b), "") => b.to_owned(),
            (Some(b), p) => format!("{b}/{}", p.trim_end_matches('/')),
            (None, _) => "<unset>".to_owned(),
        };
        lines.push((
            Level::Ok,
            format!("channel {}: target={target}", bucket.name),
        ));
    }

    // 6. Registry snapshot from the persisted status index (read-only).
    doctor_registry(config, &mut lines);

    // 7. At-rest encryption form, when PME is configured.
    doctor_at_rest(config, &mut lines);

    // Decide the exit: a FAIL always fails; a WARN fails only under `strict`.
    let has_fail = lines.iter().any(|(l, _)| *l == Level::Fail);
    let has_warn = lines.iter().any(|(l, _)| *l == Level::Warn);
    let ok = !(has_fail || (strict && has_warn));

    match format {
        OutputFormat::Text => {
            for (level, msg) in &lines {
                println!("[{}] {msg}", level.tag());
            }
        }
        OutputFormat::Json => {
            let checks: Vec<serde_json::Value> = lines
                .iter()
                .map(|(level, msg)| serde_json::json!({ "level": level.as_str(), "message": msg }))
                .collect();
            let doc = serde_json::json!({ "ok": ok, "strict": strict, "checks": checks });
            println!(
                "{}",
                serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_owned())
            );
        }
    }

    if !ok {
        anyhow::bail!(if has_fail {
            "doctor: a hard check failed"
        } else {
            "doctor --strict: a warn-level check fired"
        });
    }
    Ok(())
}

/// Report the public plane's browser-origin posture.
///
/// `cors_allowed_origins` defaults to empty, which means the wildcard. That is correct for
/// an internet-facing beacon serving unauthenticated data, so it is reported at `Ok` and
/// there is no startup warning. It is still reported, because on a node whose data plane is
/// intranet or VPN-only the wildcard lets any site a user inside that network visits use
/// their browser as a read-proxy, and the operator needs to see which posture they are in.
///
/// Reuses [`crate::app::public_cors_is_wildcard`], the single origin rule, so the two
/// cannot drift.
fn doctor_public_cors(config: &ServiceConfig, lines: &mut Vec<(Level, String)>) {
    let configured = &config.service.cors_allowed_origins;
    if crate::app::public_cors_is_wildcard(configured) {
        lines.push((
            Level::Ok,
            "public-cors: wildcard; any browser origin may read the public plane. Correct for \
             an internet-facing beacon; on an intranet or VPN-only node set \
             [service].cors_allowed_origins to close it"
                .to_owned(),
        ));
    } else {
        lines.push((
            Level::Ok,
            format!(
                "public-cors: allow-list of {} origin(s); only these browser origins may \
                 read the public plane",
                configured.len()
            ),
        ));
    }
}

/// Report the posture of each configured `[keys].identities` file, by opening it.
///
/// Counting the configured paths without reading them would print `OK` for a missing,
/// unparseable or (under `strict_key_perms`) group-readable key, so `doctor --strict` would
/// exit 0 on a node that cannot boot.
///
/// Delegates to [`crate::list_identity_file::inspect`], the same predictor the loader uses,
/// so this report cannot drift from the real boot outcome.
fn doctor_identity_files(config: &ServiceConfig, lines: &mut Vec<(Level, String)>) {
    let mut healthy = 0usize;
    for (i, path) in config.keys.identities.iter().enumerate() {
        let entry =
            crate::list_identity_file::inspect(path, i == 0, config.service.strict_key_perms);
        if let Some(fatal) = entry.fatal {
            lines.push((Level::Fail, format!("keys: {}: {fatal}", entry.path)));
        } else {
            healthy += 1;
            if let Some(warning) = entry.warning {
                lines.push((Level::Warn, format!("keys: {}: {warning}", entry.path)));
            }
        }
    }
    if healthy == config.keys.identities.len() {
        lines.push((
            Level::Ok,
            format!("keys: {healthy} inline crypt4gh identity file(s) load"),
        ));
    }
}

/// The k-anonymity floor posture, the disclosure-control decision.
///
/// Both branches carry the membership-inference caveat that docs/threat-model.md requires,
/// and a unit test asserts it on each. Split out of `run` so that test can drive it
/// directly rather than scraping stdout.
fn doctor_k_anon(config: &ServiceConfig, lines: &mut Vec<(Level, String)>) {
    let floor = config.beacon.min_allele_count;
    if floor == 0 {
        lines.push((
            Level::Warn,
            "k-anon: [beacon].min_allele_count = 0, so node-level suppression is off and singletons are served unless a dataset sets its own floor. Even when set, a floor counts alleles rather than individuals and bounds singleton re-identification only; no floor value prevents multi-variant membership inference".to_owned(),
        ));
    } else {
        // `individuals_floor`, not an inlined `floor / 2`: the conversion is
        // `ceil(floor / 2)` because a homozygote contributes 2 to AC, and truncating gives
        // the wrong answer for every odd floor.
        lines.push((
            Level::Ok,
            format!(
                "k-anon: node floor min_allele_count = {floor} alleles, which guarantees at least {} individuals per served cell. A floor bounds singleton re-identification only; it does not prevent multi-variant membership inference (Homer) at any value. Use the authenticated tier or differential privacy for a membership-sensitive cohort",
                gdi_node_standalone_core::kanon::individuals_floor(floor)
            ),
        ));
    }
}

fn doctor_writer_policy(config: &ServiceConfig, lines: &mut Vec<(Level, String)>) {
    match config.ingest.writer_policy {
        WriterPolicy::Off => lines.push((
            Level::Warn,
            "writer-policy: off; writer keys are recorded but not enforced, so any package encrypted to the node's public key can publish".to_owned(),
        )),
        WriterPolicy::Warn => lines.push((
            Level::Ok,
            "writer-policy: warn; un-allow-listed writers are recorded and counted but still published, which is the allow-list discovery mode".to_owned(),
        )),
        WriterPolicy::Enforce => {
            // Note any channel with an empty list: enforce there admits no encrypted package.
            let mut empty: Vec<&str> = Vec::new();
            if config.service.inbox.is_some() && config.writer_allowlist_for("inbox").is_empty() {
                empty.push("inbox");
            }
            if let Some(s3) = &config.s3 {
                for b in &s3.buckets {
                    if config.writer_allowlist_for(&b.name).is_empty() {
                        empty.push(b.name.as_str());
                    }
                }
            }
            if empty.is_empty() {
                lines.push((Level::Ok, "writer-policy: enforce; every ingest channel has an allow-list, and un-allow-listed writers and unidentified plaintext staging-dir drops are quarantined".to_owned()));
            } else {
                lines.push((
                    Level::Warn,
                    format!(
                        "writer-policy: enforce with an empty allow-list on {}; no encrypted package is accepted there unless allow_any_writer_ack is set",
                        empty.join(", ")
                    ),
                ));
            }
        }
    }
}

/// Surface a mixed at-rest store when PME is configured.
///
/// Enabling PME (`[vault].transit_key`) does not migrate existing plaintext datasets: a
/// volume carried from a non-PME run keeps its `PAR1` (plaintext) parquet, served alongside
/// new `PARE` (encrypted) files. Without this line an operator who turned PME on to satisfy
/// an at-rest-encryption control would read "N visible" and believe the whole store is
/// encrypted. Runs only when PME is configured, and reads only the 4-byte magic of one
/// parquet per dataset directory.
///
/// The counts come from [`crate::scrub::at_rest_tally`], which reports each store as
/// plaintext, encrypted, or neither. "Neither" gets its own line: folded into "encrypted",
/// as a `total - plaintext` tally does, a store holding nothing but corrupt datasets would
/// report that all of them are encrypted. `Indeterminate` and `Unreadable` both land in
/// `indeterminate` here, because the question is what the store holds; they diverge on the
/// scrub path, where one is corruption and the other a transient fault.
fn doctor_at_rest(config: &ServiceConfig, lines: &mut Vec<(Level, String)>) {
    if !config.has_transit_key() {
        return; // no PME configured: at-rest form is expected to be plaintext, not a finding
    }
    // Shared with the `gdi_datasets_at_rest` gauge so this on-demand answer and the
    // standing signal cannot drift.
    let tally = crate::scrub::at_rest_tally(&config.service.data_dir);
    let total = tally.total();

    if tally.indeterminate > 0 {
        lines.push((
            Level::Warn,
            format!(
                "at-rest: {} of {total} dataset(s) have no readable parquet, so the at-rest \
                 form cannot be determined and they are not known to be encrypted. A \
                 published dataset always carries one, so the store is deleted, truncated \
                 or unreadable: run `verify --digest`, which fails on it and names the \
                 dataset",
                tally.indeterminate
            ),
        ));
    }

    if tally.plaintext > 0 {
        lines.push((
            Level::Warn,
            format!(
                "at-rest: PME is configured but {} of {total} dataset(s) are plaintext \
                 (PAR1) at rest; enabling PME does not migrate existing datasets. Re-ingest \
                 them, by delete and re-add or by re-upload from S3, to encrypt them; \
                 `verify --digest` shows the form per dataset",
                tally.plaintext
            ),
        ));
    } else if total == 0 {
        lines.push((
            Level::Ok,
            "at-rest: PME configured; the store holds no datasets yet".to_owned(),
        ));
    } else if tally.indeterminate == 0 {
        lines.push((
            Level::Ok,
            format!("at-rest: PME configured; all {total} dataset(s) are encrypted (PARE) at rest"),
        ));
    }
}

fn doctor_registry(config: &ServiceConfig, lines: &mut Vec<(Level, String)>) {
    let path = config.service.data_dir.join(".status.json");
    match StatusIndex::load(&path) {
        Ok(index) => {
            // Count by effective served state, not stored state: a dataset withheld by
            // `dataset hide`/`take-down` is not being served, so counting its stored
            // `visible`/`hidden` would under-count what is actually withheld. A degraded
            // suppression file fails closed to Hide in the running node, so it counts as
            // withheld here too. `load_or_report`, not `load`: an unreadable store yields
            // the empty set, and reporting that as `withheld = 0` states the opposite of
            // the truth on a disclosure-control surface.
            let suppressions = match gdi_node_standalone_core::suppression::load_or_report(
                &gdi_node_standalone_core::suppression::suppressions_subdir(
                    &config.service.override_dir_resolved(),
                ),
            ) {
                Ok(set) => set,
                Err(e) => {
                    lines.push((
                        Level::Fail,
                        format!(
                            "override store is unreadable ({e}); the withheld count cannot \
                             be computed and is not reported as zero. Every dataset an \
                             operator has hidden or taken down is invisible to this check"
                        ),
                    ));
                    return;
                }
            };
            // The orphan axis of the same effective-state rule: a bucket channel the
            // configuration does not declare is withheld by the serve path's hydrate
            // projection, and that withhold is in neither store this check reads. It is
            // composed here from the one shared predicate, over the channel set the config
            // file declares, since a one-shot command has no live snapshot.
            let reloadable = gdi_node_standalone_core::config::Reloadable::from_config(config);
            let orphaned = |channel: &str| crate::state::channel_is_orphaned(&reloadable, channel);
            let mut counts = [0u32; 4]; // visible, hidden, error, processing
            let mut withheld = 0u32;
            let mut orphan_counts: std::collections::BTreeMap<&str, u32> =
                std::collections::BTreeMap::new();
            for (id, entry) in index.entries() {
                let is_orphaned = orphaned(&entry.channel);
                if is_orphaned {
                    *orphan_counts.entry(entry.channel.as_str()).or_default() += 1;
                }
                let is_withheld =
                    is_orphaned || suppressions.effective(id, &entry.channel).is_some();
                if is_withheld {
                    withheld += 1;
                    // A withheld dataset is served as `hidden` whatever its source state,
                    // except that `error` is a health fact rather than a visibility one: no
                    // override produces it and withholding a broken dataset does not repair
                    // it, so it stays counted and keeps the summary at WARN, the same
                    // carve-out `dataset list --errors` makes. An errored-and-withheld
                    // dataset counts in both `error` and `withheld`.
                    if entry.state != DatasetState::Error {
                        continue;
                    }
                }
                let slot = match entry.state {
                    DatasetState::Visible => 0,
                    DatasetState::Hidden => 1,
                    DatasetState::Error => 2,
                    DatasetState::Processing => 3,
                };
                counts[slot] += 1;
            }
            let total = index.entries().len();
            let level = if counts[2] > 0 {
                Level::Warn
            } else {
                Level::Ok
            };
            // `withheld` is appended only when non-zero, so the common case keeps the plain
            // line and a non-zero count draws the eye.
            let withheld_clause = if withheld > 0 {
                format!(", {withheld} withheld")
            } else {
                String::new()
            };
            lines.push((
                level,
                format!(
                    "registry: {total} dataset(s): {} visible, {} hidden, {} error{withheld_clause}",
                    counts[0], counts[1], counts[2]
                ),
            ));
            // One WARN line per orphaned channel: the boot warning scrolls away and the
            // gauge needs a scraper, but `doctor` is what an operator runs by hand, and it
            // must not report a half-finished offboarding as a healthy registry.
            for (channel, n) in orphan_counts {
                lines.push((
                    Level::Warn,
                    format!(
                        "channel {channel}: orphaned; it owns {n} dataset(s) but no \
                         [[s3.buckets]] entry declares it. They are withheld rather than \
                         erased, and nothing polls the bucket. Re-add the entry to resume \
                         serving, or erase with `channel take-down {channel}`"
                    ),
                ));
            }
        }
        Err(e) => lines.push((
            Level::Warn,
            format!("registry: cannot read {}: {e}", path.display()),
        )),
    }
}

/// Report the durability posture of the operator-override store.
///
/// The store (`override_dir`: `suppressions/` + `overlays/`) is the only state on the data
/// volume that re-ingesting from the source cannot rebuild, because re-ingest restores each
/// dataset to the source-resolved state an override exists to countermand. An absent store
/// reads as "no overrides", so losing it re-serves every withheld dataset with no error
/// anywhere. `[service].require_override_store` converts that silence into a refusal to
/// serve, and this check tells an operator when they have not set it.
fn doctor_override_store(config: &ServiceConfig, lines: &mut Vec<(Level, String)>) {
    use gdi_node_standalone_core::override_store;

    let root = config.service.override_dir_resolved();
    let required = config.service.require_override_store;
    let present = override_store::is_present(&root);
    let populated = override_store::is_populated(&root);

    if required && !present {
        lines.push((
            Level::Fail,
            "override-store: require_override_store is set but the store is absent, so this \
             node would refuse to serve. Restore it from backup, or clear the flag if the \
             node genuinely holds no overrides"
                .to_owned(),
        ));
        return;
    }

    if !populated {
        lines.push((
            Level::Ok,
            format!(
                "override-store: no operator overrides recorded; require_override_store set: {}",
                yes_no(required)
            ),
        ));
        return;
    }

    if required {
        lines.push((
            Level::Ok,
            "override-store: overrides recorded and require_override_store is set, so a lost \
             store refuses to serve instead of re-serving withheld datasets"
                .to_owned(),
        ));
        return;
    }

    // Populated but unasserted: the finding. Naming a co-located store matters, because the
    // documented recovery discards and recreates that volume, so the advice is to move it
    // and assert it, not just to assert it.
    let colocated = root.starts_with(&config.service.data_dir);
    let where_it_lives = if colocated {
        " It currently lives inside data_dir, the volume disaster recovery replaces, so a \
         documented recovery would destroy it."
    } else {
        ""
    };
    lines.push((
        Level::Warn,
        format!(
            "override-store: operator overrides are recorded but require_override_store is not \
             set. They are the only state here that re-ingesting from the source cannot \
             rebuild, and an absent store reads as 'no overrides', so losing it re-serves \
             every withheld dataset.{where_it_lives} Put override_dir on separately-backed \
             storage and set require_override_store = true"
        ),
    ));
}

const fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "unwrap is permitted in test code")]
    use super::*;

    fn minimal_config() -> ServiceConfig {
        // A keyless node with the default k-anon floor (0) and writer-policy (off): this
        // config passes preflight but produces several WARN-level posture lines.
        let dir = tempfile::tempdir().unwrap();
        let toml = format!(
            r#"
[service]
base_url = "https://n.example.org/"
data_dir = "{}"

[catalogs]
gdi-aggregated = "GoE"

[beacon]
id = "org.n.beacon"
name = "N"
environment = "test"

[beacon.organization]
id = "ee.ut.gdi"
name = "University of Tartu"
"#,
            dir.path().display()
        );
        // Leak the tempdir so data_dir stays valid for the test's duration.
        std::mem::forget(dir);
        ServiceConfig::from_toml_str(&toml).unwrap()
    }

    #[test]
    fn warnings_pass_by_default_but_fail_under_strict() {
        let cfg = minimal_config();
        // Keyless + k-anon-off + writer-off are WARNs, not FAILs: default run is Ok.
        run(&cfg, OutputFormat::Text, false).expect("WARNs do not fail without --strict");
        // --strict promotes any WARN to a non-zero exit (a deployment gate can veto it).
        assert!(
            run(&cfg, OutputFormat::Text, true).is_err(),
            "a WARN must fail under --strict"
        );
    }

    /// `docs/threat-model.md` Residual risk 1 requires `doctor`'s k-anon line to keep its
    /// membership-inference caveat: a floor bounds singleton re-identification only and
    /// prevents multi-variant membership inference (Homer) at no value. Asserted on both
    /// the floor-off WARN and the floor-set OK branch, because the OK branch is the one an
    /// operator reads as "this is handled".
    #[test]
    fn the_k_anon_line_keeps_its_membership_inference_caveat_on_both_branches() {
        const CAVEAT: &str = "membership inference";

        let off = minimal_config();
        assert_eq!(off.beacon.min_allele_count, 0, "fixture must have it off");
        let line = k_anon_line(&off);
        assert!(
            line.contains(CAVEAT),
            "the floor-OFF k-anon line dropped the membership-inference caveat: {line}"
        );

        let mut on = minimal_config();
        on.beacon.min_allele_count = 10;
        let line = k_anon_line(&on);
        assert!(
            line.contains(CAVEAT),
            "the floor-SET k-anon line dropped the membership-inference caveat — this is the \
             branch an operator reads as 'handled': {line}"
        );
    }

    /// The k-anon posture line for `config`, whichever branch it takes.
    fn k_anon_line(config: &ServiceConfig) -> String {
        let mut lines: Vec<(Level, String)> = Vec::new();
        doctor_k_anon(config, &mut lines);
        lines
            .into_iter()
            .map(|(_, text)| text)
            .find(|text| text.starts_with("k-anon:"))
            .expect("doctor must always emit a k-anon posture line")
    }

    /// Build a config whose override store lives at `<tmp>/overrides`, optionally with an
    /// override already recorded and/or the presence assertion set.
    fn config_with_store(populated: bool, require: bool) -> (ServiceConfig, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("overrides");
        let toml = format!(
            r#"
[service]
base_url = "https://n.example.org/"
data_dir = "{}"
override_dir = "{}"
require_override_store = {require}

[catalogs]
gdi-aggregated = "GoE"

[beacon]
id = "org.n.beacon"
name = "N"
environment = "test"
"#,
            tmp.path().join("data").display(),
            root.display(),
        );
        let cfg = ServiceConfig::from_toml_str(&toml).unwrap();
        if populated {
            // A store that exists has both loader directories: the write path
            // (`override_store::create_store_dir`) and `overrides init` materialise both on
            // the first override of any kind. Boot creates nothing, so it can tell an empty
            // re-provisioned volume from a node that never recorded an override. Creating
            // only one here would model a half-destroyed store, which these tests are not
            // about.
            let sub = gdi_node_standalone_core::suppression::suppressions_subdir(&root);
            std::fs::create_dir_all(&sub).unwrap();
            std::fs::create_dir_all(gdi_node_standalone_core::overlay_override::overlays_subdir(
                &root,
            ))
            .unwrap();
            // A name the loader admits (`ds-1` is not a valid id, and a store holding
            // only what the loaders ignore is not populated).
            std::fs::write(sub.join("GDI-EE-UTARTU-20260409143052837.json"), b"{}").unwrap();
        }
        (cfg, tmp)
    }

    fn levels_of(cfg: &ServiceConfig) -> Vec<(Level, String)> {
        let mut lines = Vec::new();
        doctor_override_store(cfg, &mut lines);
        lines
    }

    #[test]
    fn at_rest_flags_a_plaintext_dataset_on_a_pme_node() {
        // PME configured but a plaintext (PAR1) dataset present -> WARN. A node with no PME
        // configured emits nothing, since plaintext is expected there.
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("data");
        // Two dataset dirs: one plaintext (PAR1), one encrypted (PARE).
        let plain = data_dir.join("GDI-EE-UTARTU-20260409143052837");
        let enc = data_dir.join("GDI-EE-UTARTU-20260409143052838");
        std::fs::create_dir_all(&plain).unwrap();
        std::fs::create_dir_all(&enc).unwrap();
        std::fs::write(plain.join("allele-freq.chr1.0.parquet"), b"PAR1....").unwrap();
        std::fs::write(enc.join("allele-freq.chr1.0.parquet"), b"PARE....").unwrap();

        let pme_toml = format!(
            "[service]\nbase_url=\"https://n.example.org/\"\ndata_dir=\"{}\"\n\
             [catalogs]\ngdi-aggregated=\"GoE\"\n[beacon]\nid=\"o.n\"\nname=\"N\"\nenvironment=\"test\"\n\
             [vault]\naddress=\"http://vault:8200\"\ntransit_key=\"gdi-dek\"\n",
            data_dir.display(),
        );
        let cfg = ServiceConfig::from_toml_str(&pme_toml).unwrap();
        let mut lines = Vec::new();
        doctor_at_rest(&cfg, &mut lines);
        assert!(
            lines
                .iter()
                .any(|(l, m)| *l == Level::Warn && m.contains("1 of 2") && m.contains("plaintext")),
            "a mixed store on a PME node must WARN; got {lines:?}"
        );

        // A store whose parquet is gone must never be reported as encrypted: under a
        // `total - plaintext` tally it would count as PARE, so a store holding nothing but
        // corrupt datasets would answer "all N are encrypted".
        let broken_dir = data_dir.join("GDI-EE-UTARTU-20260409143052839");
        std::fs::create_dir_all(&broken_dir).unwrap();
        let mut lines3 = Vec::new();
        doctor_at_rest(&cfg, &mut lines3);
        assert!(
            lines3
                .iter()
                .any(|(l, m)| *l == Level::Warn && m.contains("no readable parquet")),
            "an indeterminate store must be called out, not folded into `encrypted`; got {lines3:?}"
        );
        assert!(
            !lines3.iter().any(|(_, m)| m.contains("all 3")),
            "and it must not be counted toward an all-encrypted claim; got {lines3:?}"
        );

        // No PME configured: at-rest form is not a finding at all.
        let no_pme = format!(
            "[service]\nbase_url=\"https://n.example.org/\"\ndata_dir=\"{}\"\n\
             [catalogs]\ngdi-aggregated=\"GoE\"\n[beacon]\nid=\"o.n\"\nname=\"N\"\nenvironment=\"test\"\n",
            data_dir.display(),
        );
        let cfg2 = ServiceConfig::from_toml_str(&no_pme).unwrap();
        let mut lines2 = Vec::new();
        doctor_at_rest(&cfg2, &mut lines2);
        assert!(
            lines2.is_empty(),
            "no PME configured -> no at-rest finding: {lines2:?}"
        );
    }

    #[test]
    fn registry_counts_a_suppressed_dataset_as_withheld_not_visible() {
        // The registry summary counts by effective served state: a dataset withheld by
        // `dataset hide` must not show as "visible", or a successor operator under-counts
        // what is actually being served.
        use gdi_node_standalone_core::cache::{DatasetProvenance, StatusEntry, StatusIndex};
        use gdi_node_standalone_core::state::DatasetState;
        use gdi_node_standalone_core::suppression::{self, SuppressMode, Suppression};

        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("data");
        let root = tmp.path().join("overrides");
        std::fs::create_dir_all(&data_dir).unwrap();
        let toml = format!(
            "[service]\nbase_url=\"https://n.example.org/\"\ndata_dir=\"{}\"\noverride_dir=\"{}\"\n\
             [catalogs]\ngdi-aggregated=\"GoE\"\n[beacon]\nid=\"o.n\"\nname=\"N\"\nenvironment=\"test\"\n",
            data_dir.display(),
            root.display(),
        );
        let cfg = ServiceConfig::from_toml_str(&toml).unwrap();

        // Two stored-visible datasets; one of them is hidden by an operator override.
        let mut index = StatusIndex::new();
        for id in [
            "GDI-EE-UTARTU-20260409143052837",
            "GDI-EE-UTARTU-20260409143052838",
        ] {
            index.insert(
                id.to_owned(),
                StatusEntry {
                    state: DatasetState::Visible,
                    error_message: None,
                    channel: "inbox".to_owned(),
                    last_seen_signature: None,
                    provenance: DatasetProvenance::Unknown,
                },
            );
        }
        index.store(&data_dir.join(".status.json")).unwrap();

        let sub = suppression::suppressions_subdir(&cfg.service.override_dir_resolved());
        suppression::write_file(
            &sub,
            "GDI-EE-UTARTU-20260409143052838",
            &Suppression {
                mode: SuppressMode::Hide,
                reason: "embargo".to_owned(),
                at: String::new(),
            },
        )
        .unwrap();

        let mut lines = Vec::new();
        doctor_registry(&cfg, &mut lines);
        let registry = lines
            .iter()
            .find(|(_, m)| m.starts_with("registry:"))
            .map(|(_, m)| m.clone())
            .expect("a registry line");

        assert!(
            registry.contains("1 visible") && registry.contains("1 withheld"),
            "a hidden-by-override dataset must count as withheld, not visible; got {registry:?}"
        );
    }

    /// `error` is a health fact, not a visibility one: an errored dataset on an orphaned
    /// channel is withheld and still broken. The summary, whose level goes to WARN on any
    /// error, keeps counting it, or offboarding a provider would hide every failure their
    /// channel left behind.
    #[test]
    fn registry_keeps_counting_an_errored_dataset_that_is_also_withheld() {
        use gdi_node_standalone_core::cache::{DatasetProvenance, StatusEntry, StatusIndex};
        use gdi_node_standalone_core::state::DatasetState;

        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        let toml = format!(
            "[service]\nbase_url=\"https://n.example.org/\"\ndata_dir=\"{}\"\n\
             [catalogs]\ngdi-aggregated=\"GoE\"\n[beacon]\nid=\"o.n\"\nname=\"N\"\nenvironment=\"test\"\n",
            data_dir.display(),
        );
        let cfg = ServiceConfig::from_toml_str(&toml).unwrap();

        let mut index = StatusIndex::new();
        // A served inbox dataset, and an errored one on a channel no config declares.
        for (id, state, channel) in [
            (
                "GDI-EE-UTARTU-20260409143052837",
                DatasetState::Visible,
                "inbox",
            ),
            (
                "GDI-EE-UTARTU-20260409143052838",
                DatasetState::Error,
                "departed",
            ),
        ] {
            index.insert(
                id.to_owned(),
                StatusEntry {
                    state,
                    error_message: None,
                    channel: channel.to_owned(),
                    last_seen_signature: None,
                    provenance: DatasetProvenance::Unknown,
                },
            );
        }
        index.store(&data_dir.join(".status.json")).unwrap();

        let mut lines = Vec::new();
        doctor_registry(&cfg, &mut lines);
        let (level, registry) = lines
            .iter()
            .find(|(_, m)| m.starts_with("registry:"))
            .cloned()
            .expect("a registry line");

        assert!(
            registry.contains("1 visible")
                && registry.contains("1 error")
                && registry.contains("1 withheld"),
            "an errored dataset on an orphaned channel is withheld and still an error; got {registry:?}"
        );
        assert_eq!(
            level,
            Level::Warn,
            "an error keeps the summary at WARN: {registry:?}"
        );
    }

    #[test]
    fn override_store_warns_when_populated_but_not_asserted() {
        // The state the check exists for: real overrides on disk, with nothing declaring
        // they must survive.
        let (cfg, _tmp) = config_with_store(true, false);
        let lines = levels_of(&cfg);

        assert!(
            lines
                .iter()
                .any(|(l, m)| *l == Level::Warn && m.contains("require_override_store")),
            "expected a WARN naming the assertion, got {lines:?}"
        );
    }

    #[test]
    fn override_store_fails_when_asserted_but_absent() {
        // This node would refuse to start, so doctor must not call it merely risky.
        let (cfg, _tmp) = config_with_store(false, true);
        let lines = levels_of(&cfg);

        assert!(
            lines.iter().any(|(l, _)| *l == Level::Fail),
            "an asserted-but-absent store must FAIL, got {lines:?}"
        );
    }

    #[test]
    fn override_store_is_ok_when_asserted_and_present() {
        let (cfg, _tmp) = config_with_store(true, true);
        let lines = levels_of(&cfg);

        assert!(
            lines.iter().all(|(l, _)| *l == Level::Ok),
            "the protected posture must be clean, got {lines:?}"
        );
    }

    #[test]
    fn override_store_is_ok_on_a_node_that_records_no_overrides() {
        // A fresh node with no store is the normal case, not a finding.
        let (cfg, _tmp) = config_with_store(false, false);
        let lines = levels_of(&cfg);

        assert!(
            lines.iter().all(|(l, _)| *l == Level::Ok),
            "an empty store must not warn, got {lines:?}"
        );
    }

    #[test]
    fn json_format_runs_without_panicking() {
        // The JSON branch serializes the same checks; exercising it guards the render path.
        let cfg = minimal_config();
        run(&cfg, OutputFormat::Json, false).expect("json render is Ok when no check FAILs");
    }
}
