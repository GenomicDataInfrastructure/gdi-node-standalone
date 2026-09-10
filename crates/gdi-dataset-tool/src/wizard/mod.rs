//! The interactive `gdi-dataset-tool wizard`: a guided journey (setup → author →
//! preview → build/validate → pack → optional publish) over the existing handlers
//! and the scripted-twin primitives. `dialoguer` is confined to [`prompts`].

pub mod author;
pub mod fields;
pub mod prompts;
pub mod setup;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use gdi_node_standalone_core::config::Profile;
use gdi_node_standalone_core::convert::{read_header_hints, read_header_populations};
use gdi_node_standalone_core::model::HeaderPolicy;
use gdi_node_standalone_core::model::metadata::LocalizedText;
use gdi_node_standalone_core::model::package::PackageFileEntry;

use crate::ToolError;
use crate::cli::{
    BuildArgs, DeployArgs, OutputFormat, PackArgs, Stage, UploadArgs, WizardArgs, WizardCommand,
};
use crate::s3::S3Credentials;
use crate::wizard::prompts::Prompter;

/// Run the interactive wizard journey.
///
/// When [`WizardArgs::command`] is `Some(WizardCommand::Setup)`, only the
/// profile/config setup wizard runs. Otherwise, the staged journey executes
/// the stages between `args.from` and `args.to` (inclusive):
///
/// ```text
/// Setup → Author → Build → Pack → Publish
/// ```
///
/// The TTY guard ([`prompts::require_tty`]) lives in the dispatch arm in
/// [`crate::run`], so this function is prompter-agnostic and testable with a
/// [`prompts::ScriptedPrompter`] in integration tests without a real terminal.
///
/// # Errors
///
/// Returns a [`ToolError`] on any stage failure: a prompt abort, a file I/O
/// error, a build/validation failure, or a pack/upload/deploy error.
#[expect(
    clippy::too_many_lines,
    reason = "wizard orchestration: the five stages are inherently sequential and cannot be \
              split further without losing readability or introducing artificial indirection"
)]
#[expect(
    clippy::disallowed_methods,
    reason = "writes the user's edited `package.yaml` back during the interactive fixup loop"
)]
pub fn run(
    p: &dyn Prompter,
    args: &WizardArgs,
    profile_name: Option<&str>,
    config_path: Option<&Path>,
) -> Result<(), ToolError> {
    // If the user ran `wizard setup`, run only the setup wizard and return.
    if args.command == Some(WizardCommand::Setup) {
        setup::run_setup(
            p,
            config_path,
            args.recipient.as_deref(),
            profile_name,
            true,
        )?;
        return Ok(());
    }

    // Pack and Publish need the in-run `build_output`; resuming from them without a
    // prior Build step is not supported.
    if args.from > Stage::Build {
        return Err(ToolError::user(
            "--from must be one of setup|author|build (pack and publish always follow build in the same run)",
        ));
    }

    // An empty range (`--from build --to author`) is an operator mistake to name, not a
    // silent success.
    if args.from > args.to {
        let name = |s: Stage| {
            <Stage as clap::ValueEnum>::to_possible_value(&s)
                .map_or_else(|| format!("{s:?}"), |v| v.get_name().to_owned())
        };
        return Err(ToolError::user(format!(
            "--from {} comes after --to {}: no stage would run",
            name(args.from),
            name(args.to)
        )));
    }
    let in_range = |stage: Stage| args.from <= stage && stage <= args.to;
    // Carry the build output from the Build stage into Pack + Publish.
    let mut build_output: Option<crate::commands::cmd_build::BuildOutput> = None;
    // S3 credentials this run's setup collected, carried to the Publish stage in memory:
    // setup writes them to `secrets.env` for later runs, but nothing can `source` that file
    // into the process that is already running — and with neither credential loaded the S3
    // client is built anonymous, so the wizard's own upload fails after build + pack.
    let mut carried_s3: Option<S3Credentials> = None;
    // The package.yaml this run builds: `-o`, unless the Author stage authors a new one
    // at another path.
    let mut package_yaml: PathBuf = args.output.clone();
    // Facts for the final summary (printed whenever the Build stage ran): the packed
    // `.tar.c4gh`, whether the staging dir survived, what Publish did, and the one next
    // step the operator should take.
    let mut packed_package: Option<PathBuf> = None;
    let mut staging_kept: Option<PathBuf> = None;
    let mut summary_publish: Option<String> = None;
    let mut summary_next: Option<String> = None;

    // Setup
    if in_range(Stage::Setup) {
        // The resolved name, not `--profile`'s: this line tells the operator which node,
        // bucket and recipient the rest of the run targets, and the flag may be absent or
        // name a profile that does not exist yet. The banner prints whether or not setup
        // runs, so the journey always opens at `[1/5]` and this line has a heading to sit
        // under.
        banner(Stage::Setup, "Setup: profile & keys");
        match crate::profile::load_active_named(config_path, profile_name) {
            Ok((name, profile)) if setup::profile_complete(&profile) => {
                crate::output::progress(&format!("  using profile '{name}'"));
            }
            _ => {
                let outcome = setup::run_setup(
                    p,
                    config_path,
                    args.recipient.as_deref(),
                    profile_name,
                    false,
                )?;
                carried_s3 = outcome.s3_credentials;
            }
        }
    }

    // Author
    if in_range(Stage::Author) {
        banner(Stage::Author, "Author: describe the dataset (package.yaml)");
        let active = crate::profile::load_active(config_path, profile_name).ok();
        if package_yaml.exists() {
            let current = std::fs::read_to_string(&package_yaml).map_err(|e| {
                ToolError::user(format!("cannot read {}: {e}", package_yaml.display()))
            })?;
            if author::replace_markers(&current).is_empty() {
                loop {
                    match existing_package_choice(p, &package_yaml)? {
                        ExistingChoice::Rebuild => {}
                        ExistingChoice::EditThenRebuild => author::edit_existing(p, &package_yaml)?,
                        ExistingChoice::AuthorNew => {
                            // Blank goes back to the menu: this row commits the operator to
                            // naming a second file, and rejecting blank would leave Ctrl-C —
                            // which discards the whole run — as the only way back.
                            crate::output::progress(
                                "  blank goes back; .yaml is appended if missing.",
                            );
                            let new_out =
                                p.input_path("Path for the new package.yaml", None, &|s| {
                                    if s.trim().is_empty() {
                                        Ok(())
                                    } else {
                                        validate_new_output(s)
                                    }
                                })?;
                            if new_out.trim().is_empty() {
                                continue;
                            }
                            package_yaml = normalize_new_output(&new_out);
                            if package_yaml.as_os_str() != new_out.trim() {
                                crate::output::progress(&format!(
                                    "using {}",
                                    package_yaml.display()
                                ));
                            }
                            author_new(
                                p,
                                &package_yaml,
                                active.as_ref(),
                                profile_name,
                                config_path,
                            )?;
                        }
                    }
                    break;
                }
            } else {
                author::author_fixup(p, &package_yaml)?;
            }
        } else {
            author_new(p, &package_yaml, active.as_ref(), profile_name, config_path)?;
        }
    }

    // A keyless node holds no crypt4gh identity, so there is nothing to encrypt to: the
    // wizard skips `pack` and deploys the plaintext staging dir into the node's inbox.
    let active = crate::profile::load_active(config_path, profile_name).ok();
    let keyless = active.as_ref().is_some_and(|profile| profile.keyless);
    // `deploy --wait` polls the dataset-state oracle on the management plane. Only an
    // explicit `management_url` may turn it on: `Profile::node_state_base` falls back to the
    // public `service_url`, which 404s that route, so a wait against it returns a false
    // verdict — a stale `error` blamed on the new drop, and a destructive "take the dataset
    // down" suggestion with it.
    let wait_for_ingest = active
        .as_ref()
        .is_some_and(|profile| profile.management_url.is_some());

    // Build
    if in_range(Stage::Build) {
        banner(Stage::Build, "Build: convert & validate");
        // Disclosure preview first: which populations a dataset publishes is a
        // DPIA-relevant decision, but it is derived implicitly from the VCF's INFO-field
        // naming (`AC_EE_F` → an `EE_F` stratum), so a provider can publish country- and
        // sex-stratified marginals without ever having chosen to. Show it and require a
        // yes. This runs before the build so declining costs nothing: the preview reads
        // the VCF headers only and writes nothing.
        // The staging parent sits beside the package.yaml (`-o`'s directory): run
        // artifacts stay with their manifest instead of landing in whatever CWD the
        // wizard happened to run from.
        let staging_parent = manifest_dir(&package_yaml).join("build");
        let build_args = BuildArgs {
            package: package_yaml.clone(),
            country_code: None,
            out: staging_parent,
            force: true,
            no_headers: false,
            // No flag: the profile's `header_policy` (asked once, at setup) applies, else
            // the built-in `minimal`. The wizard never widens it on its own — the preview
            // below shows the effective value and, when identifiers ship, says so in the
            // one question the operator must answer.
            header_policy: None,
            strict: false,
            dry_run: false,
            build_epoch: None,
            jobs: 0,
            // The setup stage already synced (or pinned) the catalogs allow-list.
            refresh_catalogs: false,
            format: OutputFormat::Text,
        };
        preview_and_confirm(
            p,
            &mut std::io::stdout().lock(),
            &package_yaml,
            build_args.header_policy(active.as_ref()),
        )?;
        let mut attempt =
            crate::commands::cmd_build::build_staging_dir(&build_args, profile_name, config_path);
        let out = loop {
            match attempt {
                Ok(o) => break o,
                Err(build_err) => {
                    // The error itself comes first. Opening the menu without printing what
                    // failed would leave the operator choosing "Edit package.yaml" blind.
                    crate::output::warn(&format!(
                        "error: {}",
                        crate::output::Untrusted(&build_err.message)
                    ));
                    // The failure menu: edit-and-retry, plain retry (for a cause fixed
                    // outside package.yaml — a bcftools norm, a moved file), or abort.
                    // Loops until a build succeeds or the operator aborts.
                    match p.select(
                        "Build failed. What next?",
                        &[
                            "Edit package.yaml".into(),
                            "Retry the build".into(),
                            "Abort".into(),
                        ],
                        2,
                    )? {
                        0 => {
                            // Open the package.yaml in the user's editor (wires the
                            // Prompter::editor seam), write it back, then retry. This
                            // handles the marker-free failure case where author_fixup
                            // would be a no-op.
                            let current = std::fs::read_to_string(&package_yaml).map_err(|e| {
                                ToolError::user(format!(
                                    "cannot read {}: {e}",
                                    package_yaml.display()
                                ))
                            })?;
                            let edited = p.editor(
                                "Fix the package.yaml to resolve the build error",
                                &current,
                            )?;
                            std::fs::write(&package_yaml, &edited).map_err(|e| {
                                ToolError::user(format!(
                                    "cannot write {}: {e}",
                                    package_yaml.display()
                                ))
                            })?;
                            // The edit may have changed the source set, and the yes
                            // given above was for the old one — re-run the disclosure
                            // gate against the edited file before rebuilding.
                            preview_and_confirm(
                                p,
                                &mut std::io::stdout().lock(),
                                &package_yaml,
                                build_args.header_policy(active.as_ref()),
                            )?;
                        }
                        1 => {}
                        _ => return Err(build_err),
                    }
                    attempt = crate::commands::cmd_build::build_staging_dir(
                        &build_args,
                        profile_name,
                        config_path,
                    );
                }
            }
        };
        crate::output::progress(&format!(
            "built dataset {} -> {}",
            out.dataset_id,
            out.staging.display()
        ));
        build_output = Some(out);
    }

    // Pack
    if in_range(Stage::Pack) {
        banner(Stage::Pack, "Pack: encrypt into one package");
        let staging = build_output
            .as_ref()
            .ok_or_else(|| {
                ToolError::user("pack stage needs the build stage; use --from build or earlier")
            })?
            .staging
            .clone();
        if keyless {
            crate::output::progress(
                "keyless node: skipping pack: there is no node recipient to encrypt to, so the \
                 plaintext staging dir is deployed as-is",
            );
            staging_kept = Some(staging);
        } else {
            let pack_args = PackArgs {
                staging: staging.clone(),
                recipient: None,
                // Beside the package.yaml, like the staging dir, so `-o /data/x.yaml` does
                // not split one run's artifacts across two directories. `resolve_output`
                // joins the file name into an existing directory, and the manifest's own
                // directory always exists.
                out: Some(manifest_dir(&package_yaml)),
                force: true,
                format: OutputFormat::Text,
            };
            crate::commands::cmd_pack::run(&pack_args, profile_name, config_path)
                .map_err(|e| resume_hint(e, Some(&staging), None))?;
            if let Some(build) = build_output.as_ref() {
                packed_package = Some(package_path(&package_yaml, &build.dataset_id));
            }
            // The staging dir is now redundant — the package contains everything and a
            // rebuild recreates it from package.yaml + the VCFs. Offer to remove it
            // (default yes), matching `package`, which deletes its staging on success
            // for the same reason: it holds plaintext genotype-derived intermediates.
            crate::output::progress(&format!(
                "  {}; plaintext build output; the .tar.c4gh holds the same content \
                 encrypted, and a rebuild recreates it.",
                staging.display()
            ));
            if p.confirm("Remove the staging dir?", true)? {
                match std::fs::remove_dir_all(&staging) {
                    Ok(()) => {
                        // …and the `build/` parent the staging dir was the only occupant
                        // of: a cleanup the operator asked for should not leave an empty
                        // directory behind. `remove_dir` refuses a non-empty directory, so
                        // a second dataset's staging is safe.
                        if let Some(parent) = staging.parent() {
                            let _ = std::fs::remove_dir(parent);
                        }
                        crate::output::progress(&format!(
                            "removed the staging dir {}",
                            staging.display()
                        ));
                    }
                    Err(e) => {
                        crate::output::warn(&format!(
                            "warning: could not remove the staging dir {} ({e}); remove it \
                             yourself when convenient",
                            staging.display()
                        ));
                        staging_kept = Some(staging);
                    }
                }
            } else {
                staging_kept = Some(staging);
            }
        }
    }

    // A run that stops before Pack (`--to build`) leaves the staging dir as its
    // deliverable, so the summary must name it — `staging_kept` is otherwise only set
    // by the Pack stage, and a build-only run would name no artifact at all.
    if !in_range(Stage::Pack)
        && let Some(build) = build_output.as_ref()
    {
        staging_kept = Some(build.staging.clone());
    }

    // Publish (optional)
    if in_range(Stage::Publish) {
        banner(Stage::Publish, "Publish: send it to the node");
        let build = build_output.as_ref().ok_or_else(|| {
            ToolError::user(
                "publish needs the build stage to know the dataset id; \
                 use --from build or earlier",
            )
        })?;
        if keyless {
            // A keyless node produced no `.tar.c4gh`, so S3 upload is not on offer (the S3
            // channel carries packages, not staging dirs): the only route is a local inbox drop.
            let choice = p.select(
                // Not "Publish?": the `publish` verb means "make visible", while this
                // question only asks whether to hand the artifact to the node, which
                // lands it hidden. One word for two acts would teach operators the wrong
                // model of their own dataset's visibility.
                "Send the staging dir to the node now?",
                &[
                    "Deploy it to the node's inbox".into(),
                    "Skip: deploy it yourself".into(),
                ],
                0,
            )?;
            if choice == 0 {
                let deploy_args = wizard_deploy_args(build.staging.clone(), wait_for_ingest);
                crate::commands::cmd_deploy::run(&deploy_args, profile_name, config_path)
                    .map_err(|e| resume_hint(e, Some(&build.staging), None))?;
                // A deployed dataset lands hidden. The summary is the last thing on
                // screen, so it must not imply "live".
                summary_publish = Some(
                    "staging dir deployed to the node's inbox; the dataset lands hidden".to_owned(),
                );
                summary_next = Some(format!(
                    "run `gdi-dataset-tool status {id}` to confirm ingest, then \
                     `gdi-dataset-tool publish {id}` to make it visible",
                    id = build.dataset_id
                ));
            } else {
                summary_publish = Some("nothing sent to the node (your choice)".to_owned());
                summary_next =
                    Some("drop the staging dir into the node's inbox when ready".to_owned());
            }
        } else {
            let package = package_path(&package_yaml, &build.dataset_id);
            // The routes below move `package` into their args; the resume hint needs it
            // afterwards.
            let packed = package.clone();
            let routes = publish_routes(active.as_ref(), carried_s3.is_some());
            if routes.is_empty() {
                // One short warning — the operator must know nothing went anywhere —
                // and the next step lands in the summary, split by cause: an S3 block
                // with no credentials loaded wants `source secrets.env`, no publish
                // channel at all wants setup (or a hand-off to the node operator).
                crate::output::warn(
                    "warning: nothing was sent to the node: the profile has no loaded S3 \
                     credentials and no inbox",
                );
                summary_publish = Some("nothing sent to the node".to_owned());
                summary_next = Some(
                    if active.as_ref().is_some_and(|profile| profile.s3.is_some()) {
                        format!(
                            "load the credentials (`source <config-dir>/secrets.env`), then \
                             `gdi-dataset-tool upload {}`",
                            package.display()
                        )
                    } else {
                        format!(
                            "hand {} to the node operator, or configure S3/an inbox with \
                             `gdi-dataset-tool wizard setup`",
                            package.display()
                        )
                    },
                );
            } else {
                let mut labels: Vec<String> = routes
                    .iter()
                    .map(|route| route_label(*route, active.as_ref()))
                    .collect();
                labels.push("Skip: publish elsewhere".to_owned());
                // Default to the first route, the same as the keyless branch: an operator
                // who has just answered eight S3 questions and supplied credentials should
                // not ship nothing by pressing Enter. Both routes land the dataset hidden —
                // the review window is the hidden state, not the transfer — so neither
                // default risks disclosure.
                let choice = p.select("Send the package to the node now?", &labels, 0)?;
                match routes.get(choice) {
                    Some(PublishRoute::UploadS3) => {
                        // No `--wait` here: the wizard's own closing summary names the
                        // dataset id and the `status` / `publish` pair, and the S3 route is
                        // reached on profiles that need no `management_url` at all. Blocking
                        // a guided run on an oracle it was never asked to configure would
                        // turn a completed journey into a timeout.
                        let upload_args = UploadArgs {
                            package,
                            replace: false,
                            wait: false,
                            wait_timeout: 300,
                            management_url: None,
                            format: OutputFormat::Text,
                        };
                        let uploaded = crate::commands::cmd_upload::run_with_credentials(
                            &upload_args,
                            profile_name,
                            config_path,
                            carried_s3.as_ref(),
                        );
                        uploaded
                            .map_err(|e| resume_hint(e, staging_kept.as_deref(), Some(&packed)))?;
                        // The dataset lands hidden and the node only polls its bucket.
                        // The summary is the last thing on screen, so it repeats what
                        // upload's own note said.
                        summary_publish = Some(
                            "uploaded to the S3 bucket; the dataset lands hidden and \
                             the node polls (allow ~30 s before it even looks)"
                                .to_owned(),
                        );
                        summary_next = Some(format!(
                            "run `gdi-dataset-tool status {id}` to confirm ingest, then \
                             `gdi-dataset-tool publish {id}` to make it visible",
                            id = build.dataset_id
                        ));
                    }
                    Some(PublishRoute::DeployInbox) => {
                        let deploy_args = wizard_deploy_args(package, wait_for_ingest);
                        crate::commands::cmd_deploy::run(&deploy_args, profile_name, config_path)
                            .map_err(|e| resume_hint(e, staging_kept.as_deref(), Some(&packed)))?;
                        summary_publish = Some(
                            "deployed to the node's inbox; the dataset lands hidden".to_owned(),
                        );
                        summary_next = Some(format!(
                            "run `gdi-dataset-tool status {id}` to confirm ingest, then \
                             `gdi-dataset-tool publish {id}` to make it visible",
                            id = build.dataset_id
                        ));
                    }
                    None => {
                        summary_publish = Some("nothing sent to the node (your choice)".to_owned());
                        summary_next = Some("deploy the package when ready".to_owned());
                    }
                }
            }
        }
    }

    // Summary
    // Printed whenever a dataset was built, at every verbosity: this block is the
    // point of the run — the id, where each artifact lives, what happened at Publish,
    // and the one next step — not commentary on it. A journey that stopped before
    // Build (setup-only, author-only) has its outcome on screen already.
    if let Some(build) = &build_output {
        crate::output::always("");
        crate::output::always("ok: wizard finished");
        crate::output::always(&format!("    dataset   {}", build.dataset_id));
        if let Some(package) = &packed_package {
            crate::output::always(&format!("    package   {}", package.display()));
        }
        if let Some(staging) = &staging_kept {
            crate::output::always(&format!("    staging   {}", staging.display()));
        }
        crate::output::always(&format!(
            "    manifest  {} (re-run the wizard here to rebuild or edit)",
            package_yaml.display()
        ));
        if let Some(publish) = &summary_publish {
            // "shipped", not "publish": the wizard hands the artifact to the node and the
            // dataset lands hidden. Making it visible is the separate `publish` verb, which
            // the `next` row goes on to recommend, so naming this row after it would report
            // an act the wizard never performs.
            crate::output::always(&format!("    shipped   {publish}"));
        }
        if let Some(next) = &summary_next {
            crate::output::always(&format!("    next      {next}"));
        }
    }

    Ok(())
}

/// Print the stage banner, numbering it from the [`Stage`] enum.
///
/// Numbering from the enum keeps one copy of a fact a sixth stage would otherwise make
/// wrong in five places at once.
fn banner(stage: Stage, title: &str) {
    crate::output::stage_banner(stage.step(), Stage::count(), title);
}

/// The directory the run's artifacts live in: the `package.yaml`'s own directory, or
/// `.` when it was named without one.
///
/// One definition, because three call sites must agree on it — the staging parent, the
/// packed `.tar.c4gh`, and the path the Publish stage hands to `upload`/`deploy`. If they
/// disagree, `wizard -o /data/x.yaml` scatters one run's output across two directories and
/// the publish step looks for the package where it was never written.
fn manifest_dir(package_yaml: &Path) -> PathBuf {
    package_yaml
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

/// Where this run's `{datasetId}.tar.c4gh` is written — beside its `package.yaml`.
fn package_path(package_yaml: &Path, dataset_id: &str) -> PathBuf {
    manifest_dir(package_yaml).join(format!("{dataset_id}.tar.c4gh"))
}

/// Say how to continue from the artifacts this run already produced, then return the
/// error unchanged.
///
/// Ending a Pack- or Publish-stage failure with the bare error would leave re-running as
/// the only route, and that restarts at Author, where "Rebuild" re-converts every VCF and
/// mints a new dataset id. On a whole-genome set that is many minutes and a changed id to
/// recover from an unreachable node or a wrong credential. The staging dir, and the
/// package once packed, are intact and the plain verbs continue from exactly there,
/// so the wizard names the command instead of leaving the operator to know it.
fn resume_hint(e: ToolError, staging: Option<&Path>, package: Option<&Path>) -> ToolError {
    let resume = match (package, staging) {
        (Some(pkg), _) if pkg.exists() => Some(format!(
            "the package is built; retry just this step with `gdi-dataset-tool upload {pkg}` \
             (S3) or `gdi-dataset-tool deploy {pkg}` (inbox); no rebuild, same dataset id",
            pkg = pkg.display()
        )),
        (_, Some(dir)) if dir.exists() => Some(format!(
            "the build is intact; resume with `gdi-dataset-tool pack {dir}`; no rebuild, \
             same dataset id (re-running the wizard would mint a new one)",
            dir = dir.display()
        )),
        _ => None,
    };
    if let Some(resume) = resume {
        crate::output::warn(&format!("note: {resume}"));
    }
    e
}

/// Greenfield-author `out` with what the active profile knows (its catalog allow-list,
/// its `org`, and — when it names a node — a way to refresh the catalogs), then persist an
/// `org` the operator asked to have remembered.
fn author_new(
    p: &dyn Prompter,
    out: &Path,
    active: Option<&Profile>,
    profile_name: Option<&str>,
    config_path: Option<&Path>,
) -> Result<(), ToolError> {
    let refresh = || -> Result<BTreeMap<String, String>, ToolError> {
        crate::commands::cmd_catalogs::sync_catalogs(
            profile_name,
            config_path,
            OutputFormat::Text,
            false,
        )?;
        crate::profile::load_active(config_path, profile_name).map(|profile| profile.catalogs)
    };
    let refresh_ref: &dyn Fn() -> Result<BTreeMap<String, String>, ToolError> = &refresh;
    let can_refresh = active.is_some_and(|profile| profile.service_url.is_some());
    let ctx = author::AuthorContext {
        catalogs: active
            .map(|profile| profile.catalogs.clone())
            .unwrap_or_default(),
        org: active.and_then(|profile| profile.org.as_deref()),
        refresh_catalogs: can_refresh.then_some(refresh_ref),
        header_policy: active.and_then(|profile| profile.header_policy),
    };
    let result = author::author_greenfield(p, out, &ctx, false)?;
    if let Some(org) = result.org_to_store {
        match setup::store_profile_org(config_path, profile_name, &org) {
            Ok(path) => crate::output::progress(&format!(
                "remembered org {org} in {}: the wizard will not ask again",
                path.display()
            )),
            Err(e) => crate::output::warn(&format!(
                "warning: could not store the org in the profile ({}); you will be asked again \
                 next time",
                e.message
            )),
        }
    }
    Ok(())
}

/// What to do with a `package.yaml` that is already complete when the Author stage finds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExistingChoice {
    /// Build it again as it is — a new dataset id is minted.
    Rebuild,
    /// Open it in the editor first, then build.
    EditThenRebuild,
    /// Leave it alone and author another `package.yaml` at a path the operator names.
    AuthorNew,
}

/// Ask what an existing, complete `package.yaml` is for.
///
/// Passing such a file straight through into Build would mint a fresh, timestamped dataset
/// id, so `wizard` run in a directory that still holds the previous dataset's
/// `package.yaml` would republish that dataset under a new id, with the VCF path in the
/// disclosure preview as the only cue. Ids are immutable on the node and take-down is an
/// administrator's action. The default is the one that cannot produce a duplicate; an
/// intentional rebuild is `--from build`, which skips this question.
///
/// # Errors
///
/// Returns a [`ToolError`] on a prompt failure, or when the operator aborts.
fn existing_package_choice(p: &dyn Prompter, path: &Path) -> Result<ExistingChoice, ToolError> {
    crate::output::progress(&format!(
        "{} already exists and is complete; it describes {}",
        path.display(),
        describe_package(path)
    ));
    let labels = [
        "Rebuild it as it is (a new dataset id is minted)",
        "Edit it first, then rebuild",
        "Author a new package.yaml at another path",
        "Abort",
    ]
    .map(String::from);
    // Default to rebuild, the reason the operator re-ran the wizard in this directory.
    // Pre-selecting "Author a new package.yaml at another path" would make Enter open a
    // mandatory path prompt whose only exit is Ctrl-C.
    match p.select("What do you want to do with it?", &labels, 0)? {
        0 => Ok(ExistingChoice::Rebuild),
        1 => Ok(ExistingChoice::EditThenRebuild),
        2 => Ok(ExistingChoice::AuthorNew),
        _ => Err(ToolError::user(
            "aborted: package.yaml left as it is; `--from build` rebuilds from it, \
             `-o <path>` authors another",
        )),
    }
}

/// One line on what a `package.yaml` describes — its title and source VCF(s) — for the
/// existing-file question, or a generic phrase when it does not parse.
fn describe_package(path: &Path) -> String {
    let Ok(package) = crate::commands::cmd_build::load_package(path, false) else {
        return "a dataset (the file could not be parsed)".to_owned();
    };
    let title = match &package.metadata.title {
        LocalizedText::Plain(text) => text.clone(),
        LocalizedText::Map(by_language) => by_language
            .get("en")
            .or_else(|| by_language.values().next())
            .cloned()
            .unwrap_or_default(),
    };
    let vcfs: Vec<&str> = package
        .files
        .iter()
        .filter(|group| group.category.eq_ignore_ascii_case("VCF"))
        .flat_map(|group| group.files.iter())
        .map(|entry| match entry {
            PackageFileEntry::Path(rel) | PackageFileEntry::WithMeta { path: rel, .. } => {
                rel.as_str()
            }
        })
        .collect();
    let first = vcfs
        .first()
        .map(|vcf| format!(", first {}", crate::output::Untrusted(vcf)))
        .unwrap_or_default();
    format!(
        "\"{}\" with {} source VCF(s){first}",
        crate::output::Untrusted(&title),
        vcfs.len()
    )
}

/// The typed answer with a missing `.yaml`/`.yml` extension appended — nobody means to
/// author an extensionless "package2"; the caller echoes the resolved name.
fn normalize_new_output(s: &str) -> PathBuf {
    let path = PathBuf::from(s.trim());
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("yaml" | "yml") => path,
        _ => PathBuf::from(format!("{}.yaml", path.display())),
    }
}

/// The validator for the "author a new package.yaml" path: non-empty, and — after the
/// same `.yaml` normalization the caller applies — not a file that already exists (the
/// question was asked precisely because one did).
fn validate_new_output(s: &str) -> Result<(), String> {
    let t = s.trim();
    if t.is_empty() {
        return Err("a path is required".to_owned());
    }
    let resolved = normalize_new_output(t);
    if resolved.exists() {
        Err(format!(
            "{} already exists; name a path that does not",
            resolved.display()
        ))
    } else {
        Ok(())
    }
}

/// A way the wizard can hand a package to a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublishRoute {
    /// `upload` into the profile's S3 bucket.
    UploadS3,
    /// `deploy` into the profile's inbox directory.
    DeployInbox,
}

/// The publish routes this profile can actually take, in menu order.
///
/// A static menu would offer "Upload to S3" to a profile with no `[s3]` block and "Deploy
/// to inbox" to one with no inbox, and each fails after build and pack with an error naming
/// a flag the wizard does not have. S3 is offered only with credentials in hand, either the
/// environment's or the ones this run's setup collected. With neither, the client is built
/// anonymous and a private bucket refuses the PUT.
fn publish_routes(active: Option<&Profile>, carried_credentials: bool) -> Vec<PublishRoute> {
    let mut routes = Vec::new();
    let Some(profile) = active else {
        return routes;
    };
    if let Some(s3) = profile.s3.as_ref() {
        let has_credentials =
            carried_credentials || (s3.access_key_id.is_some() && s3.secret_access_key.is_some());
        if has_credentials {
            routes.push(PublishRoute::UploadS3);
        } else {
            crate::output::progress(
                "note: S3 is configured but no credentials are loaded (`source` secrets.env, or \
                 re-run `wizard setup`); upload is not offered",
            );
        }
    }
    if profile.inbox.is_some() {
        routes.push(PublishRoute::DeployInbox);
    }
    routes
}

/// The menu row for a route, naming where it goes.
fn route_label(route: PublishRoute, active: Option<&Profile>) -> String {
    match route {
        PublishRoute::UploadS3 => format!(
            "Upload to S3 ({})",
            active
                .and_then(|profile| profile.s3.as_ref())
                .map(crate::s3::target_label)
                .unwrap_or_default()
        ),
        PublishRoute::DeployInbox => format!(
            "Deploy to the node's inbox ({})",
            active
                .and_then(|profile| profile.inbox.as_deref())
                .unwrap_or_default()
        ),
    }
}

/// The `deploy` arguments the wizard uses for `artifact` — the single place both publish
/// routes (keyless staging dir, packed `.tar.c4gh`) get them from.
///
/// `wait` is on only when the profile names a `management_url`: the oracle it polls
/// (`GET /datasets/{id}/state`) lives on the management plane, and a poll against the
/// public plane's fallback cannot answer — it waits out the whole timeout and then reports
/// "may still be processing" about a dataset that ingested seconds earlier. `deploy` prints
/// the next step either way.
fn wizard_deploy_args(artifact: PathBuf, wait: bool) -> DeployArgs {
    DeployArgs {
        artifact,
        inbox: None,
        replace: false,
        wait,
        wait_timeout: 120,
        management_url: None,
        format: OutputFormat::Text,
    }
}

/// Print the disclosure preview for the authored `package.yaml` and require an explicit
/// yes before building.
///
/// Reports what the dataset will publish: the populations — including the `F`/`M` sex
/// marginals and country×sex cells the tool derives from INFO-field names. Nothing else on
/// the provider path makes the author look at that list, yet it is the most
/// disclosure-consequential property of the dataset: publish `Total` plus the country and
/// sex marginals and they can be differenced against each other. So the wizard shows it
/// and asks.
///
/// The list comes from the header ([`read_header_populations`]), not from a record scan.
/// The AF-bearing header labels are exactly the ones that emit rows, and the
/// `min_allele_count` floor can only remove labels from that set — so the header answer is
/// the conservative one, and the gate over-warns rather than under-warns. It is also
/// effectively free: a record scan would read every source in full, and `build` reads them
/// all again moments later to recompute the same thing (which it echoes as
/// `populations emitted (N)`). What the floor actually withholds is
/// `preview --floor-impact`'s question, asked when an operator wants it.
///
/// Runs before the build, so declining costs nothing. A `package.yaml` with no VCF group
/// has nothing to preview and passes through silently.
///
/// Every file in the group is previewed, not just the first. `build` converts them all
/// (`cmd_build` iterates `vcf_group.files`), and a group is routinely plural — a
/// per-chromosome or, more pointedly, a per-population split is a documented packaging
/// shape. Previewing only `files.first()` would show one file's populations while the
/// dataset published the union, so on a per-population split the operator could confirm
/// "Publish these populations?" against a single stratum and ship every one of them.
///
/// # Errors
///
/// Returns a [`ToolError`] if the `package.yaml` cannot be read or parsed, any preview
/// fails, or the operator declines the disclosure.
fn preview_and_confirm(
    p: &dyn Prompter,
    out: &mut dyn std::io::Write,
    package_yaml: &Path,
    header_policy: HeaderPolicy,
) -> Result<(), ToolError> {
    let package = crate::commands::cmd_build::load_package(package_yaml, false)?;
    // The first VCF group is the one that drives parquet conversion.
    let Some(group) = package
        .files
        .iter()
        .find(|g| g.category.eq_ignore_ascii_case("VCF"))
    else {
        return Ok(());
    };
    if group.files.is_empty() {
        return Ok(());
    }
    let total = group.files.len();
    // To `out` (stdout in the wizard), not through `output::progress`: that channel is
    // suppressed at `-q`, which would leave `gdi-dataset-tool -q wizard …` asking "Publish
    // these populations?" with the list being confirmed hidden. What the gate asks about
    // must be printed on every run.
    let mut say = |line: String| {
        writeln!(out, "{line}")
            .map_err(|e| ToolError::user(format!("cannot print the disclosure preview: {e}")))
    };
    say(format!(
        "disclosure preview: what this dataset will publish ({total} source VCF(s)):"
    ))?;
    // Per-source sample-column counts, read only when the effective policy would ship
    // them: the question below must not claim "sample identifiers" over sources that
    // have none (a sites-only aggregate VCF is the common case), and when some sources
    // carry them the operator should see which.
    let with_identifiers = matches!(
        header_policy,
        HeaderPolicy::WithIdentifiers | HeaderPolicy::Verbatim
    );
    let mut sample_counts: Vec<(String, usize)> = Vec::new();
    let mut published: BTreeSet<String> = BTreeSet::new();
    for (i, entry) in group.files.iter().enumerate() {
        let (PackageFileEntry::Path(rel) | PackageFileEntry::WithMeta { path: rel, .. }) = entry;
        // `package.yaml` paths are relative to the YAML's own directory (or absolute).
        let rel_path = Path::new(rel.as_str());
        let vcf = if rel_path.is_absolute() {
            rel_path.to_path_buf()
        } else {
            package_yaml
                .parent()
                .filter(|dir| !dir.as_os_str().is_empty())
                .map_or_else(|| rel_path.to_path_buf(), |dir| dir.join(rel_path))
        };
        // The header already fixes the disclosure surface: populations are derived from
        // INFO-field names, and `read_header_populations` returns exactly the AF-bearing
        // labels — the ones that emit rows. A `min_allele_count` floor can only ever remove
        // labels from that set, never add one, so the header list is the conservative answer
        // to "what can this publish": it over-warns and cannot under-warn. Narrowing it to
        // the post-floor set would cost a full scan of every source here and a second one in
        // `build`; `preview --floor-impact` is where an operator asks what the floor
        // withholds.
        let pops = read_header_populations(&vcf).map_err(|e| {
            let e = ToolError::from_vcf_stage(&e);
            ToolError::user(format!("preview of {}: {}", vcf.display(), e.message))
        })?;
        if with_identifiers {
            let hints = read_header_hints(&vcf).map_err(|e| {
                let e = ToolError::from_vcf_stage(&e);
                ToolError::user(format!("preview of {}: {}", vcf.display(), e.message))
            })?;
            sample_counts.push((rel.as_str().to_owned(), hints.samples));
        }
        // Printed for every source, single-file runs included: the commonest shape is one
        // VCF, and gating this on `total > 1` would show the operator a heading and then
        // nothing at all.
        say(format!(
            "  [{}/{total}] {}: {}",
            i + 1,
            crate::output::Untrusted(rel.as_str()),
            if pops.is_empty() {
                "(no population carries an AF field; this source emits no rows)".to_owned()
            } else {
                crate::output::join_untrusted(&pops)
            }
        ))?;
        published.extend(pops);
    }
    let all: Vec<String> = published.into_iter().collect();
    if total > 1 {
        // A per-population or per-chromosome split publishes the union, which no single
        // per-file line shows.
        say(format!(
            "  union across all {total} sources ({}): {}",
            all.len(),
            crate::output::join_untrusted(&all)
        ))?;
    }

    // The headers are part of the disclosure surface too: they are the one place a
    // package can carry subject identifiers, and the wizard's own flags cannot widen the
    // policy — only the profile can — so this is where the operator sees what applies.
    let ships_identifiers = sample_counts.iter().any(|(_, samples)| *samples > 0);
    say(format!(
        "  VCF headers: {}",
        header_policy_line(header_policy, &sample_counts)
    ))?;

    let question = disclosure_question(total, header_policy, ships_identifiers);
    if
    // Default no. This is the only thing on the provider path that forces an author to look
    // at the population list before genomic data becomes public, and a default yes would
    // make "hold Enter through the wizard" a passing answer to it.
    p.confirm(&question, false)? {
        Ok(())
    } else {
        Err(ToolError::user(
            "stopped at the disclosure preview. To change what the dataset exposes, either \
             drop or rename the population INFO fields in the VCF, or raise \
             `config.minAlleleCount` in package.yaml to suppress small counts. Then re-run \
             the wizard",
        ))
    }
}

/// One line on what the effective header policy ships, for the disclosure preview.
///
/// `with-identifiers` is content-aware: `sample_counts` (per source, from the `#CHROM`
/// line) decides whether the line claims identifiers ship, names which sources carry
/// them, or says plainly that none do — a policy-keyed claim over sites-only VCFs is
/// noise that trains operators to stop reading the gate.
fn header_policy_line(policy: HeaderPolicy, sample_counts: &[(String, usize)]) -> String {
    match policy {
        HeaderPolicy::None => "none: no header member ships".to_owned(),
        HeaderPolicy::Minimal => "minimal: structural keys only, no sample identifiers".to_owned(),
        HeaderPolicy::Verbatim => {
            "verbatim: the source header byte-for-byte, tool command lines included".to_owned()
        }
        HeaderPolicy::WithIdentifiers => {
            let carriers: Vec<String> = sample_counts
                .iter()
                .filter(|(_, samples)| *samples > 0)
                .map(|(name, samples)| {
                    format!(
                        "{} ships {samples} sample identifier(s)",
                        crate::output::Untrusted(name)
                    )
                })
                .collect();
            let sampleless = sample_counts.len() - carriers.len();
            if carriers.is_empty() {
                "with-identifiers (the profile's `header_policy`); but these sources \
                 carry no sample columns; nothing identifying ships"
                    .to_owned()
            } else if sampleless == 0 {
                format!(
                    "with-identifiers (the profile's `header_policy`); {}",
                    carriers.join("; ")
                )
            } else {
                format!(
                    "with-identifiers (the profile's `header_policy`); {}; {sampleless} \
                     source(s) carry none",
                    carriers.join("; ")
                )
            }
        }
    }
}

/// The single disclosure question. It names the sample identifiers exactly when the
/// effective policy would ship them and at least one source actually carries any, so
/// "yes" to the population list is never mistaken for consent to something the operator
/// was not shown — and never warns about identifiers that do not exist.
fn disclosure_question(total: usize, policy: HeaderPolicy, ships_identifiers: bool) -> String {
    let scope = if total > 1 {
        format!(" (across all {total} source VCFs)")
    } else {
        String::new()
    };
    match policy {
        HeaderPolicy::WithIdentifiers if ships_identifiers => {
            format!("Publish these populations{scope} and ship the sample identifiers?")
        }
        HeaderPolicy::Verbatim => {
            format!("Publish these populations{scope} and ship the headers verbatim?")
        }
        HeaderPolicy::None | HeaderPolicy::Minimal | HeaderPolicy::WithIdentifiers => {
            format!("Publish these populations{scope}?")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wizard::prompts::ScriptedPrompter;

    /// The one confirm that gates disclosure must name the sample identifiers exactly
    /// when the effective header policy ships them and a source actually carries any:
    /// otherwise "Publish these populations?" is answered without the operator ever
    /// seeing that subject identifiers go too, and a policy-keyed claim over sites-only
    /// VCFs (no sample columns anywhere) is noise that trains operators to stop reading.
    #[test]
    fn the_disclosure_question_names_sample_identifiers_only_when_they_ship() {
        assert_eq!(
            disclosure_question(1, HeaderPolicy::Minimal, false),
            "Publish these populations?"
        );
        assert_eq!(
            disclosure_question(3, HeaderPolicy::Minimal, false),
            "Publish these populations (across all 3 source VCFs)?"
        );
        assert_eq!(
            disclosure_question(1, HeaderPolicy::None, false),
            "Publish these populations?"
        );
        let q = disclosure_question(1, HeaderPolicy::WithIdentifiers, true);
        assert!(q.contains("sample identifiers"), "{q}");
        // with-identifiers over sources with no sample columns: the plain question.
        assert_eq!(
            disclosure_question(1, HeaderPolicy::WithIdentifiers, false),
            "Publish these populations?"
        );
        // verbatim ships the whole header (command lines included) regardless of
        // sample columns, so it is flagged either way.
        let q = disclosure_question(2, HeaderPolicy::Verbatim, false);
        assert!(q.contains("verbatim") && q.contains("across all 2"), "{q}");
    }

    /// The preview's header line is content-aware under with-identifiers: it names the
    /// carriers, counts the sample-less, and says plainly when nothing identifying ships.
    #[test]
    fn the_header_policy_line_reports_what_actually_ships() {
        let line = header_policy_line(HeaderPolicy::WithIdentifiers, &[]);
        assert!(line.contains("carry no sample columns"), "{line}");
        let counts = vec![("a.vcf".to_owned(), 0), ("b.vcf.gz".to_owned(), 11)];
        let line = header_policy_line(HeaderPolicy::WithIdentifiers, &counts);
        assert!(
            line.contains("b.vcf.gz ships 11 sample identifier(s)")
                && line.contains("1 source(s) carry none"),
            "{line}"
        );
        let line = header_policy_line(HeaderPolicy::Minimal, &counts);
        assert!(line.contains("no sample identifiers"), "{line}");
    }

    /// The disclosure gate must reach every VCF in the group, not just `files.first()`.
    ///
    /// `build` converts them all, and a per-population or per-chromosome split is a
    /// documented packaging shape — so previewing one file would let an operator confirm
    /// "Publish these populations?" against a strict subset of what is published.
    ///
    /// The contrast is behavioural and cannot pass vacuously: the second source is absent,
    /// so reaching it is an error and not reaching it is silent success.
    #[test]
    fn the_disclosure_preview_reaches_every_vcf_in_the_group() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pkg = test_util::write_covid_package(&tmp.path().join("pkg"));

        // Control: the canonical single-VCF package previews and the confirmation is honoured.
        let p = ScriptedPrompter::new().with_confirms(vec![true]);
        preview_and_confirm(&p, &mut Vec::new(), &pkg, HeaderPolicy::Minimal)
            .expect("a single valid VCF must preview cleanly");

        // Add a second source the group declares but which does not exist.
        let yaml = std::fs::read_to_string(&pkg).expect("read package.yaml");
        let patched = yaml.replace(
            "      - \"COVID.monogneic.aggregate.AFs.GRCh38.vcf\"",
            "      - \"COVID.monogneic.aggregate.AFs.GRCh38.vcf\"\n      - \"absent-second.vcf\"",
        );
        assert_ne!(
            patched, yaml,
            "the fixture's VCF entry must have been found"
        );
        std::fs::write(&pkg, patched).expect("write patched package.yaml");

        let p = ScriptedPrompter::new().with_confirms(vec![true]);
        let err = preview_and_confirm(&p, &mut Vec::new(), &pkg, HeaderPolicy::Minimal)
            .expect_err("a second, unreadable source VCF must be reached and reported");
        assert!(
            err.message.contains("absent-second.vcf"),
            "the failure must name the source it could not preview: {}",
            err.message
        );
    }

    /// `-q` must not hide the population list the operator is asked to confirm.
    ///
    /// The preview is written to the sink the caller passes (stdout in the wizard), not
    /// through the verbosity-gated `progress` channel: under `Quiet` that channel prints
    /// nothing, which would leave the operator answering "Publish these populations?"
    /// against an empty screen. The sink is a `Write`, so the test reads exactly what the
    /// operator would.
    #[test]
    fn the_disclosure_preview_is_printed_even_when_quiet() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pkg = test_util::write_covid_package(&tmp.path().join("pkg"));
        let p = ScriptedPrompter::new().with_confirms(vec![true]);

        crate::output::set_verbosity(crate::output::Verbosity::Quiet);
        let mut out = Vec::new();
        let result = preview_and_confirm(&p, &mut out, &pkg, HeaderPolicy::Minimal);
        crate::output::set_verbosity(crate::output::Verbosity::Normal);
        result.expect("a single valid VCF must preview cleanly");

        let shown = String::from_utf8(out).expect("utf-8");
        assert!(
            shown.contains("disclosure preview") && shown.contains("Total"),
            "the population list must reach the operator under -q; got: {shown:?}"
        );
        assert!(
            shown.contains("VCF headers: minimal"),
            "the header policy is part of what is confirmed; got: {shown:?}"
        );
    }

    /// A package with no VCF group has nothing to disclose and passes through silently —
    /// without consuming a confirmation the operator was never asked for.
    #[test]
    fn a_package_with_no_vcf_group_skips_the_gate() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pkg = test_util::write_covid_package(&tmp.path().join("pkg"));
        let yaml = std::fs::read_to_string(&pkg).expect("read package.yaml");
        let patched = yaml.replace("category: \"VCF\"", "category: \"BAM\"");
        std::fs::write(&pkg, patched).expect("write patched package.yaml");

        // No confirmations queued: a prompt here would fail the scripted prompter.
        let p = ScriptedPrompter::new();
        preview_and_confirm(&p, &mut Vec::new(), &pkg, HeaderPolicy::Minimal)
            .expect("no VCF group means nothing to confirm");
    }

    /// The Publish menu follows the profile: S3 only with credentials in hand (the
    /// environment's, or this run's), the inbox only when configured, nothing otherwise.
    #[test]
    fn publish_routes_follow_the_profile() {
        use gdi_node_standalone_core::config::ProfileS3;
        let s3 = |creds: bool| ProfileS3 {
            bucket: Some("wizard-bucket".into()),
            endpoint: Some("https://s3.example.org".into()),
            access_key_id: creds.then(|| "k".to_owned()),
            secret_access_key: creds.then(|| "s".to_owned()),
            ..ProfileS3::default()
        };
        assert!(publish_routes(None, false).is_empty());
        assert!(
            publish_routes(Some(&Profile::default()), false).is_empty(),
            "nothing configured, nothing offered"
        );
        let s3_no_creds = Profile {
            s3: Some(s3(false)),
            ..Profile::default()
        };
        assert!(
            publish_routes(Some(&s3_no_creds), false).is_empty(),
            "S3 without credentials would upload anonymously — not offered"
        );
        assert_eq!(
            publish_routes(Some(&s3_no_creds), true),
            [PublishRoute::UploadS3],
            "…unless this run carries them"
        );
        let s3_env = Profile {
            s3: Some(s3(true)),
            ..Profile::default()
        };
        assert_eq!(
            publish_routes(Some(&s3_env), false),
            [PublishRoute::UploadS3]
        );
        let both = Profile {
            s3: Some(s3(true)),
            inbox: Some("/var/lib/node/inbox".into()),
            ..Profile::default()
        };
        assert_eq!(
            publish_routes(Some(&both), false),
            [PublishRoute::UploadS3, PublishRoute::DeployInbox]
        );
        assert!(
            route_label(PublishRoute::DeployInbox, Some(&both)).contains("/var/lib/node/inbox")
        );
        assert!(route_label(PublishRoute::UploadS3, Some(&both)).contains("wizard-bucket"));
    }

    #[test]
    fn a_new_output_path_must_not_exist_yet() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let existing = test_util::write_covid_package(&tmp.path().join("pkg"));
        assert!(validate_new_output("").is_err());
        assert!(validate_new_output(existing.to_str().expect("utf-8")).is_err());
        assert!(validate_new_output(tmp.path().join("new.yaml").to_str().expect("utf-8")).is_ok());
        // The validator applies the same .yaml normalization the caller does: an
        // extensionless answer that resolves to an existing file is rejected too.
        let stem = existing.with_extension("");
        assert!(
            validate_new_output(stem.to_str().expect("utf-8")).is_err(),
            "the extensionless twin of an existing package.yaml must be rejected"
        );
    }

    #[test]
    fn a_new_output_path_gains_the_yaml_extension() {
        assert_eq!(normalize_new_output("second"), PathBuf::from("second.yaml"));
        assert_eq!(
            normalize_new_output(" second.yml "),
            PathBuf::from("second.yml")
        );
        assert_eq!(
            normalize_new_output("dir/pkg.v2"),
            PathBuf::from("dir/pkg.v2.yaml"),
            "an unrelated dot-suffix is appended to, not replaced"
        );
        assert_eq!(
            normalize_new_output("second.yaml"),
            PathBuf::from("second.yaml")
        );
    }

    #[test]
    fn describe_package_names_the_title_and_the_source() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pkg = test_util::write_covid_package(&tmp.path().join("pkg"));
        let described = describe_package(&pkg);
        assert!(
            described.contains("Genome of Europe Estonia aggregated allele frequencies"),
            "{described}"
        );
        assert!(
            described.contains("COVID.monogneic.aggregate.AFs.GRCh38.vcf"),
            "{described}"
        );
        assert!(describe_package(&tmp.path().join("missing.yaml")).contains("could not be parsed"));
    }

    /// The existing-file question: every row maps, and "Abort" says how to rebuild on
    /// purpose without being asked.
    #[test]
    fn an_existing_complete_package_is_asked_about() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let pkg = test_util::write_covid_package(&tmp.path().join("pkg"));
        for (index, expected) in [
            (0, ExistingChoice::Rebuild),
            (1, ExistingChoice::EditThenRebuild),
            (2, ExistingChoice::AuthorNew),
        ] {
            let p = ScriptedPrompter::new().with_selects(vec![index]);
            assert_eq!(
                existing_package_choice(&p, &pkg).expect("a choice"),
                expected
            );
        }
        let p = ScriptedPrompter::new().with_selects(vec![3]);
        let err = existing_package_choice(&p, &pkg).expect_err("abort is an error");
        assert!(err.message.contains("--from build"), "{}", err.message);
    }
}
